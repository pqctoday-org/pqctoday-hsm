//! K19 — the four KMIP 3.0 Baseline client-to-server operations from
//! Profiles v3.0 §5.1.2 item 9 that round 1 left advertised-only:
//!
//! - Get Usage Allocation §6.1.29 (op `0x11`) — grant an allocation
//!   against the object's tracked `Usage Limits Count`.
//! - Get Constraints      §6.1.28 (op `0x38`) — report the constraint
//!   table the server applies to object-creating operations.
//! - Set Defaults         §6.1.60 (op `0x36`) — store per-Object-Type
//!   default attributes applied beneath client templates on factory
//!   operations (Create / CreateKeyPair / Register).
//! - Set Endpoint Role    §6.1.61 (op `0x32`) — endpoint-role
//!   negotiation; see [`set_endpoint_role`] for the policy decision.
//!
//! Op codepoints verified against
//! `spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json` (`enums.Operation`).
//!
//! ## Plane mapping
//!
//! All four are Plane-2 only: they mutate / read server-side metadata
//! (store usage counters, Deps defaults state, static capability
//! tables) and never call into the PKCS#11 engine.

use crate::error::{KmipError, Result};
use crate::kmip30::{
    Attribute, Constraint, EndpointRole, GetConstraintsRequest, GetConstraintsResponse,
    GetUsageAllocationRequest, GetUsageAllocationResponse, KmipAlgorithm, ObjectType,
    SetConstraintsRequest, SetConstraintsResponse, SetDefaultsRequest, SetDefaultsResponse,
    SetEndpointRoleRequest, SetEndpointRoleResponse, State,
};

use super::deps::Deps;
use super::helpers::{emit_request, emit_success, fail_err};

// ── Get Usage Allocation (§6.1.29) ──────────────────────────────────────────

/// Handle a `Get Usage Allocation` request per KMIP 3.0 §6.1.29.
///
/// "This operation requests the server to obtain an allocation from
/// the current Usage Limits value … The server SHALL assume that the
/// entire allocated amount is going to be consumed." The grant is a
/// plain decrement against the tracked remaining budget — the same
/// counter the Encrypt path deducts bytes from (K11/CS-BC-M-7).
///
/// Error mapping per the §6.1.27.1 Table 331 error table:
/// - unknown UID                 → `Object Not Found (0x37)`
/// - no Usage Limits attribute   → `Attribute Not Found (0x21)`
/// - object not usable for protection (not Active)
///                               → `Permission Denied (0x0c)`
/// - non-positive count          → `Invalid Field (0x07)`
/// - count > remaining           → `Usage Limit Exceeded (0x1a)`
pub fn get_usage_allocation(
    deps: &Deps,
    req: GetUsageAllocationRequest,
    correlation_id: &str,
) -> Result<GetUsageAllocationResponse> {
    emit_request(
        deps,
        correlation_id,
        "GetUsageAllocation",
        format!("uid={} count={}", req.uid, req.usage_limits_count),
    );

    let mut obj = deps.store.get(&req.uid)?.ok_or_else(|| {
        fail_err(deps, correlation_id, "GetUsageAllocation", KmipError::object_not_found(&req.uid))
    })?;

    // §6.1.27 — "is only valid if the Managed Object has a Usage
    // Limits attribute. If the operation is requested for an object
    // that has no Usage Limits attribute … the server SHALL return an
    // error." Table 331 names `Attribute Not Found`.
    let Some(total) = obj.usage_limits_total else {
        return Err(fail_err(
            deps,
            correlation_id,
            "GetUsageAllocation",
            KmipError::attribute_not_found(format!(
                "UID {:?} has no Usage Limits attribute",
                req.uid
            )),
        ));
    };

    // §6.1.27 — "The operation SHALL only be requested during the
    // time that protection is enabled for these objects" (i.e. the
    // object must be usable for applying cryptographic protection).
    // Non-Active states cannot apply protection → Permission Denied.
    if obj.state != State::Active {
        return Err(fail_err(
            deps,
            correlation_id,
            "GetUsageAllocation",
            KmipError::permission_denied(format!(
                "UID {:?} is in {:?} — usage allocation requires an Active object",
                req.uid, obj.state
            )),
        ));
    }

    if req.usage_limits_count <= 0 {
        return Err(fail_err(
            deps,
            correlation_id,
            "GetUsageAllocation",
            KmipError::invalid_field(format!(
                "Usage Limits Count must be positive; got {}",
                req.usage_limits_count
            )),
        ));
    }

    // §6.1.27 — "If the requested amount is not available … the
    // server SHALL return an error" (Table 331: Usage Limit Exceeded).
    let remaining = obj.usage_limits_remaining.unwrap_or(total);
    if req.usage_limits_count > remaining {
        return Err(fail_err(
            deps,
            correlation_id,
            "GetUsageAllocation",
            KmipError::usage_limit_exceeded(format!(
                "requested {} Usage Limits Units; only {} remaining",
                req.usage_limits_count, remaining
            )),
        ));
    }

    // Grant: "The server SHALL assume that the entire allocated
    // amount is going to be consumed" — reserve it now.
    obj.usage_limits_remaining = Some(remaining - req.usage_limits_count);
    deps.store.update(obj)?;

    emit_success(deps, correlation_id, "GetUsageAllocation");
    Ok(GetUsageAllocationResponse { uid: req.uid })
}

// ── Get Constraints (§6.1.28) ───────────────────────────────────────────────

/// Handle a `Get Constraints` request per KMIP 3.0 §6.1.28 — "return
/// the constraints that are being applied to Managed Objects during
/// operations".
///
/// The table is static and reflects the engine's REAL algorithm
/// bounds (the same surface `softhsmrustv3`'s mechanism table
/// enforces on Create / CreateKeyPair): each §7.6 `Constraint` scopes
/// the object types an algorithm family creates and carries the
/// algorithm + its maximum accepted `Cryptographic Length`.
pub fn get_constraints(
    deps: &Deps,
    _req: GetConstraintsRequest,
    correlation_id: &str,
) -> Result<GetConstraintsResponse> {
    emit_request(deps, correlation_id, "GetConstraints", String::new());
    // Phase 3.2 — a client-set override (§6.1.57) wins; absent one,
    // report the real engine-bounds default.
    let constraints = deps
        .constraints
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .unwrap_or_else(server_constraints);
    let resp = GetConstraintsResponse { constraints };
    emit_success(deps, correlation_id, "GetConstraints");
    Ok(resp)
}

/// `Set Constraints` (KMIP 3.0 §6.1.59 / Table 427) — "set the
/// constraints that will be applied to Managed Objects during
/// operations." Replaces the stored set entirely; `Get Constraints`
/// (§6.1.28) reads it back. Genuinely mutable — before Phase 3.2 the
/// server always reported a hardcoded engine-bounds table regardless
/// of what a client tried to set.
pub fn set_constraints(
    deps: &Deps,
    req: SetConstraintsRequest,
    correlation_id: &str,
) -> Result<SetConstraintsResponse> {
    emit_request(
        deps,
        correlation_id,
        "SetConstraints",
        format!("constraints={}", req.constraints.len()),
    );
    *deps.constraints.lock().unwrap_or_else(|e| e.into_inner()) = Some(req.constraints);
    emit_success(deps, correlation_id, "SetConstraints");
    Ok(SetConstraintsResponse)
}

/// The engine-backed constraint table (§7.6 / §7.7). Lengths are the
/// MAXIMUM the engine accepts for the family; smaller spec-defined
/// sizes are also accepted (AES 128–256, RSA 2048–4096, EC P-256 to
/// P-521). PQC parameter sets are fixed per algorithm codepoint
/// (ML-DSA-44/65/87, ML-KEM-512/768/1024) so the largest of each
/// family is listed without a length attribute.
fn server_constraints() -> Vec<Constraint> {
    let key_pair = vec![ObjectType::PublicKey, ObjectType::PrivateKey];
    vec![
        Constraint {
            object_types: vec![ObjectType::SymmetricKey],
            attributes: vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes),
                Attribute::CryptographicLength(256), // engine: 16–32-byte AES keys
            ],
        },
        Constraint {
            object_types: key_pair.clone(),
            attributes: vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::Rsa),
                Attribute::CryptographicLength(4096), // engine: RSA-2048..4096
            ],
        },
        Constraint {
            object_types: key_pair.clone(),
            attributes: vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::Ecdsa),
                Attribute::CryptographicLength(521), // engine: P-256..P-521
            ],
        },
        Constraint {
            object_types: key_pair.clone(),
            attributes: vec![Attribute::CryptographicAlgorithm(KmipAlgorithm::MlDsa87)],
        },
        Constraint {
            object_types: key_pair,
            attributes: vec![Attribute::CryptographicAlgorithm(KmipAlgorithm::MlKem1024)],
        },
    ]
}

// ── Set Defaults (§6.1.60) ──────────────────────────────────────────────────

/// Handle a `Set Defaults` request per KMIP 3.0 §6.1.60 — "set the
/// default attributes that will be applied to Managed Objects during
/// factory operations if the client does not supply values".
///
/// Semantics per Table 428: the supplied `Defaults Information` is
/// "the set of Object Defaults to begin using" — it REPLACES the
/// stored set; an absent `Defaults Information` removes all Object
/// Defaults. The stored attributes are applied generically beneath
/// the client template (see [`apply_object_defaults`]) on Create /
/// CreateKeyPair / Register. Response payload is empty (Table 429).
pub fn set_defaults(
    deps: &Deps,
    req: SetDefaultsRequest,
    auth: &crate::server::auth::AuthContext,
    correlation_id: &str,
) -> Result<SetDefaultsResponse> {
    emit_request(
        deps,
        correlation_id,
        "SetDefaults",
        format!(
            "object_defaults={}",
            req.defaults_information.as_ref().map_or(0, |v| v.len())
        ),
    );

    // Part F §F7.5 — per-tenant: this Set Defaults replaces only the
    // CALLING tenant's bucket, leaving every other tenant's untouched.
    let requester = auth.identity.as_ref().map(|i| i.username.clone());
    let mut outer = deps.object_defaults.lock().unwrap();
    let mut map: std::collections::HashMap<ObjectType, Vec<Attribute>> =
        std::collections::HashMap::new();
    if let Some(object_defaults) = req.defaults_information {
        for od in object_defaults {
            for ot in &od.object_types {
                // A type listed in multiple Object Defaults structures
                // accumulates all of them (spec is silent; first-set
                // wins per attribute via the discriminant merge below).
                map.entry(*ot).or_default().extend(od.attributes.iter().cloned());
            }
        }
    }
    // Table 428 — a new set REPLACES the old one; an absent (or empty)
    // Defaults Information removes this tenant's defaults entirely
    // rather than leaving a dangling empty bucket in the shared map.
    if map.is_empty() {
        outer.remove(&requester);
    } else {
        outer.insert(requester, map);
    }
    drop(outer);

    emit_success(deps, correlation_id, "SetDefaults");
    Ok(SetDefaultsResponse)
}

/// Merge the stored §6.1.58 Object Defaults for `object_type` into
/// `template`, with client-template precedence: a default attribute is
/// appended only when no attribute of the same kind (same enum
/// variant) is already present in `template` or in any of the extra
/// `also_present` baskets (CreateKeyPair's `Common Attributes`).
///
/// Merge order is therefore: client template > Set Defaults > the
/// server's hardcoded fallbacks (which the existing handlers apply
/// only when the attribute is absent from the template).
pub fn apply_object_defaults(
    deps: &Deps,
    object_type: ObjectType,
    also_present: &[Attribute],
    template: &mut Vec<Attribute>,
    auth: &crate::server::auth::AuthContext,
) {
    // Part F §F7.5 — read only the CALLING tenant's own defaults.
    let requester = auth.identity.as_ref().map(|i| i.username.clone());
    let outer = deps.object_defaults.lock().unwrap();
    let Some(map) = outer.get(&requester) else { return };
    let Some(defaults) = map.get(&object_type) else { return };
    let missing: Vec<Attribute> = defaults
        .iter()
        .filter(|d| {
            let kind = std::mem::discriminant(*d);
            !template.iter().chain(also_present.iter()).any(|a| {
                std::mem::discriminant(a) == kind
            })
        })
        .cloned()
        .collect();
    template.extend(missing);
}

// ── Set Endpoint Role (§6.1.61) ─────────────────────────────────────────────

/// Handle a `Set Endpoint Role` request per KMIP 3.0 §6.1.61.
///
/// The request carries "the endpoint role for the server to apply"
/// (Table 431); "after successful completion of the operation the
/// server assumes the client role, and the client assumes the server
/// role" — i.e. requesting `Endpoint Role = Client` asks this server
/// to switch into the §6.2 server-to-client operation mode.
///
/// **K19 policy decision:** this implementation is a server and stays
/// one — it has no client-mode machinery for the §6.2 server-to-client
/// operations (Notify / Put / Query / Set Endpoint Role from the
/// server side). Therefore:
///
/// - `Endpoint Role = Server` — the identity request: the server
///   applies the role it already holds. Accepted; the response echoes
///   "the accepted endpoint role as applied by the server" (Table
///   432) = `Server`, and no roles change.
/// - `Endpoint Role = Client` — the role switch. Rejected with
///   `Operation Failed / Feature Not Supported (0x08)` from the
///   §6.1.61.1 Table 433 error table, naming the missing capability.
pub fn set_endpoint_role(
    deps: &Deps,
    req: SetEndpointRoleRequest,
    correlation_id: &str,
) -> Result<SetEndpointRoleResponse> {
    emit_request(
        deps,
        correlation_id,
        "SetEndpointRole",
        format!("endpoint_role={:?}", req.endpoint_role),
    );

    match req.endpoint_role {
        EndpointRole::Server => {
            // Identity request — the server keeps the Server role.
            emit_success(deps, correlation_id, "SetEndpointRole");
            Ok(SetEndpointRoleResponse { endpoint_role: EndpointRole::Server })
        }
        EndpointRole::Client => Err(fail_err(
            deps,
            correlation_id,
            "SetEndpointRole",
            KmipError::feature_not_supported(
                "endpoint role switching is not supported — this server has no \
                 client-mode machinery for KMIP 3.0 §6.2 server-to-client operations \
                 and always operates in the Server role",
            ),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditlog::{AuditSink, RingSink};
    use crate::error::ResultReason;
    use crate::kmip30::{ObjectDefaults, UsageMask};
    use crate::server::auth::AuthContext;
    use crate::policy::{load_from_str, Engine};
    use crate::store::{MemoryStore, ObjectRecord};
    use std::sync::Arc;
    use time::OffsetDateTime;

    fn deps() -> Deps {
        let ring = Arc::new(RingSink::new(64));
        let sink: Arc<dyn AuditSink> = ring;
        let engine = Engine::with_global_sink(sink.clone());
        engine.activate(load_from_str(
            "schema_version: 1\nmetadata: {name: t, description: t, authority: t, effective: always}\nrules: []\n",
            std::path::Path::new("<t>"),
        ).unwrap()).unwrap();
        Deps::new(engine, Arc::new(MemoryStore::new()), sink, super::super::deps::DepsConfig::default())
    }

    fn put_key(d: &Deps, uid: &str, state: State, limits: Option<(i64, i64)>) {
        d.store.put(ObjectRecord {
            uid: uid.into(),
            object_type: ObjectType::SymmetricKey,
            algorithm: KmipAlgorithm::Aes,
            cryptographic_length: 256,
            usage_mask: UsageMask::ENCRYPT,
            state,
            initial_date: OffsetDateTime::UNIX_EPOCH,
            usage_limits_total: limits.map(|(t, _)| t),
            usage_limits_remaining: limits.map(|(_, r)| r),
            usage_limits_unit: limits.map(|_| 0x01),
            ..ObjectRecord::default()
        }).unwrap();
    }

    // ── Get Usage Allocation ────────────────────────────────────────────

    #[test]
    fn usage_allocation_decrements_remaining() {
        let d = deps();
        put_key(&d, "u", State::Active, Some((100, 100)));
        let r = get_usage_allocation(&d, GetUsageAllocationRequest {
            uid: "u".into(), usage_limits_count: 30,
        }, "c").unwrap();
        assert_eq!(r.uid, "u");
        let rec = d.store.get("u").unwrap().unwrap();
        assert_eq!(rec.usage_limits_remaining, Some(70), "grant reserves the allocation");
        assert_eq!(rec.usage_limits_total, Some(100), "total is untouched");
        // A second allocation draws from the new remaining budget.
        get_usage_allocation(&d, GetUsageAllocationRequest {
            uid: "u".into(), usage_limits_count: 70,
        }, "c").unwrap();
        assert_eq!(d.store.get("u").unwrap().unwrap().usage_limits_remaining, Some(0));
    }

    #[test]
    fn usage_allocation_unknown_uid_is_object_not_found() {
        let d = deps();
        let err = get_usage_allocation(&d, GetUsageAllocationRequest {
            uid: "ghost".into(), usage_limits_count: 1,
        }, "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::ObjectNotFound);
    }

    /// §6.1.27 — "If the operation is requested for an object that has
    /// no Usage Limits attribute … the server SHALL return an error"
    /// (Table 331: Attribute Not Found).
    #[test]
    fn usage_allocation_without_usage_limits_is_attribute_not_found() {
        let d = deps();
        put_key(&d, "u", State::Active, None);
        let err = get_usage_allocation(&d, GetUsageAllocationRequest {
            uid: "u".into(), usage_limits_count: 1,
        }, "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::AttributeNotFound);
    }

    /// §6.1.27 — "If the requested amount is not available … the
    /// server SHALL return an error" (Table 331: Usage Limit Exceeded);
    /// the budget is NOT touched by the failed request.
    #[test]
    fn usage_allocation_over_budget_is_usage_limit_exceeded() {
        let d = deps();
        put_key(&d, "u", State::Active, Some((100, 10)));
        let err = get_usage_allocation(&d, GetUsageAllocationRequest {
            uid: "u".into(), usage_limits_count: 11,
        }, "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::UsageLimitExceeded);
        assert_eq!(d.store.get("u").unwrap().unwrap().usage_limits_remaining, Some(10));
    }

    /// §6.1.27 — allocation is only valid while protection is enabled;
    /// a PreActive object cannot apply protection.
    #[test]
    fn usage_allocation_non_active_is_permission_denied() {
        let d = deps();
        put_key(&d, "u", State::PreActive, Some((100, 100)));
        let err = get_usage_allocation(&d, GetUsageAllocationRequest {
            uid: "u".into(), usage_limits_count: 1,
        }, "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::PermissionDenied);
    }

    #[test]
    fn usage_allocation_non_positive_count_is_invalid_field() {
        let d = deps();
        put_key(&d, "u", State::Active, Some((100, 100)));
        for count in [0, -5] {
            let err = get_usage_allocation(&d, GetUsageAllocationRequest {
                uid: "u".into(), usage_limits_count: count,
            }, "c").unwrap_err();
            assert_eq!(err.result_reason(), ResultReason::InvalidField);
        }
    }

    // ── Get Constraints ─────────────────────────────────────────────────

    /// §6.1.26 Table 327 — the response carries the Constraints set;
    /// every Constraint reflects a real engine bound.
    #[test]
    fn get_constraints_reports_engine_bounds() {
        let d = deps();
        let r = get_constraints(&d, GetConstraintsRequest, "c").unwrap();
        assert!(!r.constraints.is_empty(), "Constraints REQUIRED per Table 327");
        // AES constraint scopes SymmetricKey and carries the max length.
        let aes = r.constraints.iter().find(|c| {
            c.attributes.contains(&Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes))
        }).expect("AES constraint present");
        assert_eq!(aes.object_types, vec![ObjectType::SymmetricKey]);
        assert!(aes.attributes.contains(&Attribute::CryptographicLength(256)));
        // Key-pair constraints scope both halves.
        let rsa = r.constraints.iter().find(|c| {
            c.attributes.contains(&Attribute::CryptographicAlgorithm(KmipAlgorithm::Rsa))
        }).expect("RSA constraint present");
        assert_eq!(rsa.object_types, vec![ObjectType::PublicKey, ObjectType::PrivateKey]);
        assert!(rsa.attributes.contains(&Attribute::CryptographicLength(4096)));
        // PQC families list the largest parameter set, no length.
        assert!(r.constraints.iter().any(|c| {
            c.attributes.contains(&Attribute::CryptographicAlgorithm(KmipAlgorithm::MlDsa87))
        }));
        assert!(r.constraints.iter().any(|c| {
            c.attributes.contains(&Attribute::CryptographicAlgorithm(KmipAlgorithm::MlKem1024))
        }));
    }

    // ── Set Constraints (Phase 3.2) ─────────────────────────────────────

    /// Set→Get round-trips: a client-set constraints list genuinely
    /// replaces the engine-bounds default, and Get reads it back
    /// exactly. Before Phase 3.2, `server_constraints()` was a hardcoded
    /// function — Set Constraints had no store to write into at all.
    #[test]
    fn set_constraints_then_get_round_trips() {
        let d = deps();
        let custom = vec![Constraint {
            object_types: vec![ObjectType::SymmetricKey],
            attributes: vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes),
                Attribute::CryptographicLength(128),
            ],
        }];
        set_constraints(&d, SetConstraintsRequest { constraints: custom.clone() }, "c").unwrap();
        let r = get_constraints(&d, GetConstraintsRequest, "c").unwrap();
        assert_eq!(r.constraints, custom);
    }

    /// An explicit empty Set Constraints is a real override ("no
    /// constraints"), distinct from never having called Set Constraints
    /// at all (which still reports the engine-bounds default).
    #[test]
    fn set_constraints_empty_list_overrides_the_default() {
        let d = deps();
        set_constraints(&d, SetConstraintsRequest { constraints: vec![] }, "c").unwrap();
        let r = get_constraints(&d, GetConstraintsRequest, "c").unwrap();
        assert!(r.constraints.is_empty());
    }

    /// A later Set Constraints replaces (not merges with) the earlier one.
    #[test]
    fn set_constraints_replaces_not_merges() {
        let d = deps();
        let first = vec![Constraint {
            object_types: vec![ObjectType::SymmetricKey],
            attributes: vec![Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes)],
        }];
        let second = vec![Constraint {
            object_types: vec![ObjectType::PublicKey, ObjectType::PrivateKey],
            attributes: vec![Attribute::CryptographicAlgorithm(KmipAlgorithm::Rsa)],
        }];
        set_constraints(&d, SetConstraintsRequest { constraints: first }, "c1").unwrap();
        set_constraints(&d, SetConstraintsRequest { constraints: second.clone() }, "c2").unwrap();
        let r = get_constraints(&d, GetConstraintsRequest, "c").unwrap();
        assert_eq!(r.constraints, second);
    }

    // ── Set Defaults ────────────────────────────────────────────────────

    fn defaults_req(ot: ObjectType, attrs: Vec<Attribute>) -> SetDefaultsRequest {
        SetDefaultsRequest {
            defaults_information: Some(vec![ObjectDefaults {
                object_types: vec![ot],
                attributes: attrs,
            }]),
        }
    }

    #[test]
    fn set_defaults_stores_and_replaces_the_set() {
        let d = deps();
        set_defaults(&d, defaults_req(
            ObjectType::SymmetricKey,
            vec![Attribute::CryptographicUsageMask(UsageMask::ENCRYPT | UsageMask::DECRYPT)],
        ), &AuthContext::open(), "c").unwrap();
        // One tenant bucket (the anonymous/open one), with one type in it.
        assert_eq!(d.object_defaults.lock().unwrap().len(), 1);
        assert!(d.object_defaults.lock().unwrap().get(&None).unwrap().contains_key(&ObjectType::SymmetricKey));
        // Table 428 — a new set REPLACES the old one…
        set_defaults(&d, defaults_req(
            ObjectType::SecretData,
            vec![Attribute::Description("dflt".into())],
        ), &AuthContext::open(), "c").unwrap();
        let outer = d.object_defaults.lock().unwrap();
        let map = outer.get(&None).unwrap();
        assert!(!map.contains_key(&ObjectType::SymmetricKey), "old set replaced");
        assert!(map.contains_key(&ObjectType::SecretData));
        drop(outer);
        // …and an absent Defaults Information removes all defaults (the
        // whole tenant bucket, so the shared outer map is empty again).
        set_defaults(&d, SetDefaultsRequest { defaults_information: None }, &AuthContext::open(), "c").unwrap();
        assert!(d.object_defaults.lock().unwrap().is_empty());
    }

    /// §7.23 — an Object Defaults entry naming several object types
    /// applies to each of them.
    #[test]
    fn set_defaults_object_types_structure_fans_out() {
        let d = deps();
        set_defaults(&d, SetDefaultsRequest {
            defaults_information: Some(vec![ObjectDefaults {
                object_types: vec![ObjectType::PublicKey, ObjectType::PrivateKey],
                attributes: vec![Attribute::Extractable(false)],
            }]),
        }, &AuthContext::open(), "c").unwrap();
        let outer = d.object_defaults.lock().unwrap();
        let map = outer.get(&None).unwrap();
        assert_eq!(map.get(&ObjectType::PublicKey), Some(&vec![Attribute::Extractable(false)]));
        assert_eq!(map.get(&ObjectType::PrivateKey), Some(&vec![Attribute::Extractable(false)]));
    }

    /// Merge precedence: client template > Set Defaults. The default
    /// fills the gap when the client omits the attribute and yields
    /// when the client (or the CreateKeyPair common basket) supplies it.
    #[test]
    fn apply_object_defaults_client_template_wins() {
        let d = deps();
        set_defaults(&d, defaults_req(
            ObjectType::SymmetricKey,
            vec![
                Attribute::CryptographicUsageMask(UsageMask::ENCRYPT),
                Attribute::Description("server default".into()),
            ],
        ), &AuthContext::open(), "c").unwrap();

        // Client omits both → both defaults applied.
        let mut t1 = vec![Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes)];
        apply_object_defaults(&d, ObjectType::SymmetricKey, &[], &mut t1, &AuthContext::open());
        assert!(t1.contains(&Attribute::CryptographicUsageMask(UsageMask::ENCRYPT)));
        assert!(t1.contains(&Attribute::Description("server default".into())));

        // Client supplies a mask → the default mask yields.
        let mut t2 = vec![Attribute::CryptographicUsageMask(UsageMask::SIGN)];
        apply_object_defaults(&d, ObjectType::SymmetricKey, &[], &mut t2, &AuthContext::open());
        assert!(t2.contains(&Attribute::CryptographicUsageMask(UsageMask::SIGN)));
        assert!(!t2.contains(&Attribute::CryptographicUsageMask(UsageMask::ENCRYPT)));

        // Attribute present in the `also_present` basket (CreateKeyPair
        // Common Attributes) also suppresses the default.
        let common = vec![Attribute::CryptographicUsageMask(UsageMask::VERIFY)];
        let mut t3 = Vec::new();
        apply_object_defaults(&d, ObjectType::SymmetricKey, &common, &mut t3, &AuthContext::open());
        assert!(!t3.iter().any(|a| matches!(a, Attribute::CryptographicUsageMask(_))));
        assert!(t3.contains(&Attribute::Description("server default".into())));

        // No defaults stored for the type → template untouched.
        let mut t4 = vec![Attribute::Sensitive(true)];
        apply_object_defaults(&d, ObjectType::Certificate, &[], &mut t4, &AuthContext::open());
        assert_eq!(t4, vec![Attribute::Sensitive(true)]);
    }

    // ── Set Endpoint Role ───────────────────────────────────────────────

    /// §6.1.59 — `Server` is the identity request: accepted, role
    /// echoed per Table 432, nothing changes.
    #[test]
    fn set_endpoint_role_server_is_acknowledged() {
        let d = deps();
        let r = set_endpoint_role(&d, SetEndpointRoleRequest {
            endpoint_role: EndpointRole::Server,
        }, "c").unwrap();
        assert_eq!(r.endpoint_role, EndpointRole::Server);
    }

    /// §6.1.59.1 Table 433 — the role switch (`Client`) is rejected
    /// with `Feature Not Supported (0x08)`: this server has no §6.2
    /// client-mode machinery (documented K19 policy decision).
    #[test]
    fn set_endpoint_role_client_is_feature_not_supported() {
        let d = deps();
        let err = set_endpoint_role(&d, SetEndpointRoleRequest {
            endpoint_role: EndpointRole::Client,
        }, "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::FeatureNotSupported);
    }

    #[test]
    fn endpoint_role_codepoints_match_oasis_extraction() {
        assert_eq!(EndpointRole::Client.to_wire_value(), 0x01);
        assert_eq!(EndpointRole::Server.to_wire_value(), 0x02);
        assert_eq!(EndpointRole::from_wire_value(0x02), Some(EndpointRole::Server));
        assert_eq!(EndpointRole::from_wire_value(0x03), None);
    }
}
