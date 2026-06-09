//! KMIP 3.0 Group D (lifecycle: Deactivate / Check / Archive / Recover /
//! Obliterate) + leftover Group A (DiscoverVersions / Ping).
//!
//! Spec mapping:
//!
//! - Deactivate       §6.1.14 — Active → Deactivated, set Deactivation Date
//! - Check            §6.1.7  — policy gate; v0.1 always allows
//! - Archive          §6.1.4  — client indicates archival; server policy decides
//! - Recover          §6.1.47 — undo archival
//! - Obliterate       §6.1.39 — remove object + all metadata
//! - DiscoverVersions §6.1.20 — protocol version negotiation
//! - Ping             §6.1.41 — liveness check (no payload)

use std::collections::HashMap;
use time::OffsetDateTime;

use crate::error::{KmipError, Result};
use crate::kmip30::{
    ArchiveRequest, ArchiveResponse, CheckRequest, CheckResponse, DeactivateRequest,
    DeactivateResponse, DiscoverVersionsRequest, DiscoverVersionsResponse, KMIP_VERSION_MAJOR,
    KMIP_VERSION_MINOR, ObliterateRequest, ObliterateResponse, PingRequest, PingResponse,
    RecoverRequest, RecoverResponse, State,
};
use crate::policy::{Decision, PolicyRequest};

use super::deps::Deps;
use super::helpers::{canonical_name, emit_request, emit_success, fail_err, state_name};

// ── Deactivate ─────────────────────────────────────────────────────────────

pub fn deactivate(
    deps: &Deps,
    req: DeactivateRequest,
    correlation_id: &str,
) -> Result<DeactivateResponse> {
    let started = OffsetDateTime::now_utc();
    emit_request(deps, correlation_id, "Deactivate", format!("uid={}", req.uid));

    let mut obj = deps.store.get(&req.uid)?.ok_or_else(|| {
        fail_err(deps, correlation_id, "Deactivate", KmipError::not_found(&req.uid))
    })?;

    // Per §6.1.14: only `Active` may transition to `Deactivated`. Other
    // source states are §6.1.14 Error Handling → WrongKeyLifecycleState
    // (we encode as PermissionDenied since our ResultReason enum doesn't
    // carry that explicit variant — KMIP 3.0 §11 has it as 0x12).
    if obj.state != State::Active {
        return Err(fail_err(deps, correlation_id, "Deactivate",
            KmipError::permission_denied(format!(
                "Deactivate requires Active state; UID {} is in {:?}",
                req.uid, obj.state
            ))));
    }

    // Plane-1 policy gate.
    let empty: HashMap<String, String> = HashMap::new();
    let algo = canonical_name(obj.algorithm);
    let mut p_req = PolicyRequest::minimal("Deactivate", Some(&algo), started, correlation_id, &empty);
    p_req.state = Some(state_name(obj.state));
    p_req.target_uid = Some(&req.uid);
    if let Decision::Deny { human, .. } = deps.engine.evaluate(&p_req) {
        return Err(fail_err(deps, correlation_id, "Deactivate",
            KmipError::permission_denied(human)));
    }

    obj.state = State::Deactivated;
    deps.store.update(obj)?;
    emit_success(deps, correlation_id, "Deactivate");
    Ok(DeactivateResponse { uid: req.uid })
}

// ── Check ──────────────────────────────────────────────────────────────────

pub fn check(deps: &Deps, req: CheckRequest, correlation_id: &str) -> Result<CheckResponse> {
    emit_request(deps, correlation_id, "Check", format!("uid={}", req.uid));

    let obj = deps.store.get(&req.uid)?.ok_or_else(|| {
        fail_err(deps, correlation_id, "Check", KmipError::not_found(&req.uid))
    })?;

    // Per §6.1.7: server validates the requested usage parameters against
    // the object's attributes + policy. v0.1 always allows (no Usage
    // Limits, no Lease Time enforcement). The Cryptographic Usage Mask
    // check would deny if requested bits are not present in the object's
    // mask — we honour that since it's a direct spec mandate.
    if let Some(requested) = req.cryptographic_usage_mask {
        let have = obj.usage_mask.bits();
        if requested & have != requested {
            return Err(fail_err(deps, correlation_id, "Check",
                KmipError::permission_denied(format!(
                    "Cryptographic Usage Mask {:#x} not all permitted by object's {:#x}",
                    requested, have
                ))));
        }
    }

    emit_success(deps, correlation_id, "Check");
    Ok(CheckResponse { uid: req.uid })
}

// ── Archive ────────────────────────────────────────────────────────────────

pub fn archive(deps: &Deps, req: ArchiveRequest, correlation_id: &str) -> Result<ArchiveResponse> {
    emit_request(deps, correlation_id, "Archive", format!("uid={}", req.uid));
    let _ = deps.store.get(&req.uid)?.ok_or_else(|| {
        fail_err(deps, correlation_id, "Archive", KmipError::not_found(&req.uid))
    })?;
    // Per §6.1.4: "This request is only an indication from a client
    // that, from its point of view, the key management system MAY
    // archive the object." v0.1 acknowledges but doesn't move bytes.
    emit_success(deps, correlation_id, "Archive");
    Ok(ArchiveResponse { uid: req.uid })
}

// ── Recover ────────────────────────────────────────────────────────────────

pub fn recover(deps: &Deps, req: RecoverRequest, correlation_id: &str) -> Result<RecoverResponse> {
    emit_request(deps, correlation_id, "Recover", format!("uid={}", req.uid));
    let _ = deps.store.get(&req.uid)?.ok_or_else(|| {
        fail_err(deps, correlation_id, "Recover", KmipError::not_found(&req.uid))
    })?;
    // Per §6.1.47: recover access to an archived object. Since v0.1's
    // Archive is a no-op, Recover is also a no-op — the object is
    // already accessible.
    emit_success(deps, correlation_id, "Recover");
    Ok(RecoverResponse { uid: req.uid })
}

// ── Obliterate ─────────────────────────────────────────────────────────────

pub fn obliterate(
    deps: &Deps,
    req: ObliterateRequest,
    correlation_id: &str,
) -> Result<ObliterateResponse> {
    emit_request(deps, correlation_id, "Obliterate", format!("uid={}", req.uid));
    let _ = deps.store.get(&req.uid)?.ok_or_else(|| {
        fail_err(deps, correlation_id, "Obliterate", KmipError::not_found(&req.uid))
    })?;
    // Per §6.1.39: "remove the Managed Object. All meta-data SHALL also
    // be removed from the server." Unlike Destroy (which retains
    // metadata), Obliterate removes everything.
    deps.store.remove(&req.uid)?;
    emit_success(deps, correlation_id, "Obliterate");
    Ok(ObliterateResponse)
}

// ── DiscoverVersions ───────────────────────────────────────────────────────

/// Versions the server speaks — in decreasing order of preference per
/// §6.1.20. v0.1 only supports KMIP 3.0; later versions add 2.1 and 1.4.
const SUPPORTED_VERSIONS: &[(i32, i32)] = &[(KMIP_VERSION_MAJOR, KMIP_VERSION_MINOR)];

pub fn discover_versions(
    deps: &Deps,
    req: DiscoverVersionsRequest,
    correlation_id: &str,
) -> Result<DiscoverVersionsResponse> {
    emit_request(
        deps,
        correlation_id,
        "DiscoverVersions",
        format!("client_versions={}", req.protocol_versions.len()),
    );

    // Per §6.1.20:
    // - empty client list → return ALL server-supported versions
    // - non-empty client list → return intersection (or empty list)
    let response_versions: Vec<(i32, i32)> = if req.protocol_versions.is_empty() {
        SUPPORTED_VERSIONS.to_vec()
    } else {
        SUPPORTED_VERSIONS
            .iter()
            .filter(|v| req.protocol_versions.contains(v))
            .copied()
            .collect()
    };

    emit_success(deps, correlation_id, "DiscoverVersions");
    Ok(DiscoverVersionsResponse { protocol_versions: response_versions })
}

// ── Ping ───────────────────────────────────────────────────────────────────

pub fn ping(deps: &Deps, _req: PingRequest, correlation_id: &str) -> Result<PingResponse> {
    // Per §6.1.41: server MAY treat Ping as a non-logged operation.
    // We still emit a tiny audit trail for traceability since the
    // sandbox is dev-oriented; production deployments can filter.
    emit_request(deps, correlation_id, "Ping", String::new());
    emit_success(deps, correlation_id, "Ping");
    Ok(PingResponse)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditlog::{AuditSink, RingSink};
    use crate::kmip30::{KmipAlgorithm, ObjectType, UsageMask};
    use crate::policy::{load_from_str, Engine};
    use crate::store::{MemoryStore, ObjectRecord};
    use std::sync::Arc;

    fn deps_with() -> Deps {
        let ring = Arc::new(RingSink::new(64));
        let sink: Arc<dyn AuditSink> = ring.clone();
        let engine = Engine::with_global_sink(sink.clone());
        engine.activate(load_from_str(
            "schema_version: 1\nmetadata: {name: t, description: t, authority: t, effective: always}\nrules: []\n",
            std::path::Path::new("<t>"),
        ).unwrap()).unwrap();
        Deps::new(engine, Arc::new(MemoryStore::new()), sink, super::super::deps::DepsConfig::default())
    }

    fn put(d: &Deps, uid: &str, state: State) {
        d.store.put(ObjectRecord {
            uid: uid.into(),
            object_type: ObjectType::SymmetricKey,
            algorithm: KmipAlgorithm::Aes,
            cryptographic_length: 128,
            usage_mask: UsageMask::ENCRYPT,
            state,
            pkcs11_cka_id: vec![],
            pkcs11_slot: 0,
            initial_date: OffsetDateTime::UNIX_EPOCH,
            activation_date: None,
            supersedes: None,
            name: None,
            links: HashMap::new(),
            custom_attributes: HashMap::new(),
            key_material: None,
            key_format_type: None,
        }).unwrap();
    }

    #[test]
    fn deactivate_transitions_active_to_deactivated() {
        let d = deps_with();
        put(&d, "u", State::Active);
        deactivate(&d, DeactivateRequest {
            uid: "u".into(), deactivation_reason: None, deactivation_date: None,
        }, "c").unwrap();
        assert_eq!(d.store.get("u").unwrap().unwrap().state, State::Deactivated);
    }

    #[test]
    fn deactivate_rejects_non_active() {
        let d = deps_with();
        put(&d, "u", State::PreActive);
        let err = deactivate(&d, DeactivateRequest {
            uid: "u".into(), deactivation_reason: None, deactivation_date: None,
        }, "c").unwrap_err();
        assert_eq!(err.result_reason(), crate::error::ResultReason::PermissionDenied);
    }

    #[test]
    fn check_rejects_unsupported_usage_mask() {
        let d = deps_with();
        put(&d, "u", State::Active);
        // Object has ENCRYPT only; client asks for SIGN.
        let err = check(&d, CheckRequest {
            uid: "u".into(),
            usage_limits_count: None,
            cryptographic_usage_mask: Some(UsageMask::SIGN.bits()),
            lease_time: None,
        }, "c").unwrap_err();
        assert_eq!(err.result_reason(), crate::error::ResultReason::PermissionDenied);
    }

    #[test]
    fn obliterate_removes_the_record() {
        let d = deps_with();
        put(&d, "u", State::Active);
        obliterate(&d, ObliterateRequest { uid: "u".into() }, "c").unwrap();
        assert!(d.store.get("u").unwrap().is_none());
    }

    #[test]
    fn discover_versions_with_empty_request_returns_supported_set() {
        let d = deps_with();
        let r = discover_versions(&d, DiscoverVersionsRequest { protocol_versions: vec![] }, "c").unwrap();
        assert_eq!(r.protocol_versions, vec![(KMIP_VERSION_MAJOR, KMIP_VERSION_MINOR)]);
    }

    #[test]
    fn discover_versions_with_intersection_returns_only_overlap() {
        let d = deps_with();
        // Client supports 1.2 + 3.0 + 4.0; server only does 3.0.
        let r = discover_versions(&d, DiscoverVersionsRequest {
            protocol_versions: vec![(1, 2), (3, 0), (4, 0)],
        }, "c").unwrap();
        assert_eq!(r.protocol_versions, vec![(3, 0)]);
    }

    #[test]
    fn discover_versions_with_no_overlap_returns_empty() {
        let d = deps_with();
        let r = discover_versions(&d, DiscoverVersionsRequest {
            protocol_versions: vec![(1, 0), (2, 1)],
        }, "c").unwrap();
        assert!(r.protocol_versions.is_empty());
    }

    #[test]
    fn ping_returns_success() {
        let d = deps_with();
        assert!(ping(&d, PingRequest, "c").is_ok());
    }
}
