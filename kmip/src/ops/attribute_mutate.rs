//! KMIP 3.0 attribute-mutation op handlers — Group B wave 2.
//!
//! Five ops are bundled in this module because they share semantics and
//! store-mutation logic:
//!
//! | Op              | Spec       | Pre-condition           | Effect               |
//! |-----------------|------------|-------------------------|----------------------|
//! | AddAttribute    | §6.1.2     | attribute MUST NOT exist | create attribute    |
//! | ModifyAttribute | §6.1.38    | attribute MUST exist     | change value         |
//! | DeleteAttribute | §6.1.17    | attribute MUST exist     | remove value         |
//! | SetAttribute    | §6.1.56    | (none)                   | create or modify    |
//! | AdjustAttribute | §6.1.3     | numeric / boolean attr   | apply delta / negate |
//!
//! Spec mandates per-op error result reasons; we honour the ones the
//! v0.1 store can detect (Attribute Single Valued, Attribute Not Found,
//! Read Only Attribute, Invalid Attribute, Object Not Found).
//!
//! Storage model: the in-memory and SQLite ObjectRecord shapes carry a
//! handful of typed fields (algorithm, length, state, usage_mask, …)
//! plus three free-form maps for everything else: `name`, `links`
//! (LinkType → target UID), `custom_attributes` (name → text value).
//! The handlers route each typed-tag attribute to the right slot.

use std::collections::HashMap;
use time::OffsetDateTime;

use crate::error::{KmipError, Result, ResultReason};
use crate::kmip30::{
    AddAttributeRequest, AddAttributeResponse,
    AdjustAttributeRequest, AdjustAttributeResponse, AdjustmentType,
    Attribute, DeleteAttributeRequest, DeleteAttributeResponse,
    ModifyAttributeRequest, ModifyAttributeResponse,
    SetAttributeRequest, SetAttributeResponse,
    UsageMask,
};
use crate::policy::{Decision, PolicyRequest};
use crate::store::ObjectRecord;

use super::deps::Deps;
use super::helpers::{canonical_name, emit_request, emit_success, fail_err, state_name};

// ── AddAttribute ───────────────────────────────────────────────────────────

pub fn add_attribute(
    deps: &Deps,
    req: AddAttributeRequest,
    auth: &crate::server::auth::AuthContext,
    correlation_id: &str,
) -> Result<AddAttributeResponse> {
    emit_request(deps, correlation_id, "AddAttribute",
                 format!("uid={} attr={:?}", req.uid, attribute_name(&req.new_attribute)));

    // Part F §F7.4 — owner-checked lookup (see get.rs for the pattern).
    let mut obj = super::helpers::authorize_object(deps, auth, &req.uid, || {
        KmipError::object_not_found(&req.uid)
    })
    .map_err(|e| fail_err(deps, correlation_id, "AddAttribute", e))?;
    policy_gate(deps, &obj, "AddAttribute", correlation_id)?;

    // KMIP 3.0 §6.1.48 + §11 — `Name` MUST be unique across the
    // server's managed objects; a duplicate (on ANY UID, including
    // the target itself) yields `NonUniqueNameAttribute` (0x35),
    // NOT the generic `InvalidField`. BL-M-8 msg #2 pins this
    // code: the test re-adds the same Name to the same object so
    // the comparator can verify the uniqueness rule.
    if let Attribute::Name(n) = &req.new_attribute {
        let dup = deps
            .store
            .find(&|r| r.name.as_deref() == Some(n.as_str()))
            .unwrap_or_default();
        if !dup.is_empty() {
            return Err(fail_err(
                deps,
                correlation_id,
                "AddAttribute",
                KmipError::non_unique_name_attribute(n),
            ));
        }
    }

    // Per §6.1.2: "Existing attribute values SHALL NOT be changed by this
    // operation". Reject if a value is already present for this
    // single-valued attribute. KMIP §11 ResultReason for this scenario
    // is `AttributeSingleValued` (0x23), NOT the generic `InvalidField`.
    // BL-M-5 step #4 pins this for a duplicate `Description` add.
    if attribute_present(&obj, &req.new_attribute) {
        return Err(fail_err(deps, correlation_id, "AddAttribute",
            KmipError::failed(
                ResultReason::AttributeSingleValued,
                format!("attribute {:?} already present on {}", attribute_name(&req.new_attribute), req.uid),
            )));
    }
    if attribute_is_read_only(&req.new_attribute) {
        return Err(fail_err(deps, correlation_id, "AddAttribute",
            KmipError::failed(
                ResultReason::InvalidField,
                format!("attribute {:?} is Read-Only and cannot be added", attribute_name(&req.new_attribute)),
            )));
    }

    check_circular_link(deps, "AddAttribute", &req.uid, &req.new_attribute, correlation_id)?;
    apply_attribute(&mut obj, &req.new_attribute);
    commit_mutation(deps, auth, correlation_id, obj)?;
    emit_success(deps, correlation_id, "AddAttribute");
    Ok(AddAttributeResponse { uid: req.uid })
}

// ── ModifyAttribute ────────────────────────────────────────────────────────

pub fn modify_attribute(
    deps: &Deps,
    req: ModifyAttributeRequest,
    auth: &crate::server::auth::AuthContext,
    correlation_id: &str,
) -> Result<ModifyAttributeResponse> {
    emit_request(deps, correlation_id, "ModifyAttribute",
                 format!("uid={} attr={:?}", req.uid, attribute_name(&req.new_attribute)));

    // Part F §F7.4 — owner-checked lookup (see get.rs for the pattern).
    let mut obj = super::helpers::authorize_object(deps, auth, &req.uid, || {
        KmipError::object_not_found(&req.uid)
    })
    .map_err(|e| fail_err(deps, correlation_id, "ModifyAttribute", e))?;
    policy_gate(deps, &obj, "ModifyAttribute", correlation_id)?;

    // Per KMIP 3.0 §6.1.38 + §11 attribute table — Read-Only attributes
    // (UniqueIdentifier, ObjectType, State, …) are server-owned and MUST
    // NOT be modified by clients. BL-M-7 step #2 pins the reason code as
    // `AttributeReadOnly` (0x22) not the generic `InvalidField`.
    if attribute_is_read_only(&req.new_attribute) {
        return Err(fail_err(deps, correlation_id, "ModifyAttribute",
            KmipError::attribute_read_only(attribute_name(&req.new_attribute))));
    }

    // Gap-remediation Phase B — §4.69 Table 90's guard condition:
    // Usage Limits stops being client-modifiable once Get Usage
    // Allocation has granted at least one allocation against it.
    if matches!(&req.new_attribute, Attribute::UsageLimits { .. }) && usage_limits_locked(&obj) {
        return Err(fail_err(deps, correlation_id, "ModifyAttribute",
            KmipError::failed(
                ResultReason::InvalidField,
                format!(
                    "UsageLimits on {} is no longer client-modifiable — Get Usage Allocation has already granted against it",
                    req.uid,
                ),
            )));
    }

    // Per KMIP 3.0 §11 attribute table — `Activation Date` is modifiable
    // only while the object is in `PreActive`. AKLC-M-3 + SKLC-M-3 step #4
    // both pin `WrongKeyLifecycleState` once the object is Active.
    if let Attribute::ActivationDate(_) = &req.new_attribute {
        if !matches!(obj.state, crate::kmip30::State::PreActive) {
            return Err(fail_err(deps, correlation_id, "ModifyAttribute",
                KmipError::failed(
                    ResultReason::WrongKeyLifecycleState,
                    format!("ActivationDate modifiable only in PreActive (object is in {})",
                        state_name(obj.state)),
                )));
        }
    }

    // Per §6.1.38: "Only existing attributes MAY be changed via this operation."
    if !attribute_present(&obj, &req.new_attribute) {
        return Err(fail_err(deps, correlation_id, "ModifyAttribute",
            KmipError::failed(
                ResultReason::ItemNotFound,
                format!("attribute {:?} not present on {} — Modify requires existing value", attribute_name(&req.new_attribute), req.uid),
            )));
    }
    // Per §6.1.38: "Specifying a Current Attribute for which there exists
    // no Attribute associated with the object SHALL result in an error."
    if let Some(current) = &req.current_attribute {
        if !attribute_present(&obj, current) {
            return Err(fail_err(deps, correlation_id, "ModifyAttribute",
                KmipError::failed(
                    ResultReason::ItemNotFound,
                    "Current Attribute does not match any existing value".to_string(),
                )));
        }
    }

    check_circular_link(deps, "ModifyAttribute", &req.uid, &req.new_attribute, correlation_id)?;
    apply_attribute(&mut obj, &req.new_attribute);
    commit_mutation(deps, auth, correlation_id, obj)?;
    emit_success(deps, correlation_id, "ModifyAttribute");
    Ok(ModifyAttributeResponse { uid: req.uid })
}

// ── DeleteAttribute ────────────────────────────────────────────────────────

pub fn delete_attribute(
    deps: &Deps,
    req: DeleteAttributeRequest,
    auth: &crate::server::auth::AuthContext,
    correlation_id: &str,
) -> Result<DeleteAttributeResponse> {
    emit_request(deps, correlation_id, "DeleteAttribute",
                 format!("uid={} ref={:?}", req.uid, req.attribute_reference));

    // Part F §F7.4 — owner-checked lookup (see get.rs for the pattern).
    let mut obj = super::helpers::authorize_object(deps, auth, &req.uid, || {
        KmipError::object_not_found(&req.uid)
    })
    .map_err(|e| fail_err(deps, correlation_id, "DeleteAttribute", e))?;
    policy_gate(deps, &obj, "DeleteAttribute", correlation_id)?;

    // Per §6.1.17:
    // - If `current_attribute` is given, delete that specific value.
    // - If only `attribute_reference` is given, delete all instances of
    //   the named attribute.
    // - Attempting to delete a non-existent attribute SHALL result in an
    //   error.
    // - Attributes always REQUIRED to have a value SHALL never be deleted.
    if let Some(current) = &req.current_attribute {
        if attribute_is_required(current) {
            return Err(fail_err(deps, correlation_id, "DeleteAttribute",
                KmipError::failed(
                    ResultReason::InvalidField,
                    format!("attribute {:?} is always REQUIRED", attribute_name(current)),
                )));
        }
        if !attribute_present(&obj, current) {
            return Err(fail_err(deps, correlation_id, "DeleteAttribute",
                KmipError::failed(
                    ResultReason::ItemNotFound,
                    "Current Attribute does not match any existing value".to_string(),
                )));
        }
        // Gap-remediation Phase B/T3 — §4.69 Table 90: "Deletable by
        // client: Yes, as long as Get Usage Allocation has not been
        // performed" — the same guard condition as Set/ModifyAttribute,
        // just phrased for Delete.
        if matches!(current, Attribute::UsageLimits { .. }) && usage_limits_locked(&obj) {
            return Err(fail_err(deps, correlation_id, "DeleteAttribute",
                KmipError::failed(
                    ResultReason::InvalidField,
                    format!(
                        "UsageLimits on {} is no longer client-deletable — Get Usage Allocation has already granted against it",
                        req.uid,
                    ),
                )));
        }
        remove_attribute_by_value(&mut obj, current);
    } else if let Some(name) = &req.attribute_reference {
        if attribute_name_is_required(name) {
            return Err(fail_err(deps, correlation_id, "DeleteAttribute",
                KmipError::failed(
                    ResultReason::InvalidField,
                    format!("attribute {name} is always REQUIRED"),
                )));
        }
        if !attribute_name_present(&obj, name) {
            return Err(fail_err(deps, correlation_id, "DeleteAttribute",
                KmipError::failed(
                    ResultReason::ItemNotFound,
                    format!("attribute {name} not present on {}", req.uid),
                )));
        }
        let canonical_name: String = name.chars().filter(|c| c.is_alphanumeric()).collect();
        if canonical_name == "UsageLimits" && usage_limits_locked(&obj) {
            return Err(fail_err(deps, correlation_id, "DeleteAttribute",
                KmipError::failed(
                    ResultReason::InvalidField,
                    format!(
                        "UsageLimits on {} is no longer client-deletable — Get Usage Allocation has already granted against it",
                        req.uid,
                    ),
                )));
        }
        remove_attribute_by_name(&mut obj, name);
    } else {
        return Err(fail_err(deps, correlation_id, "DeleteAttribute",
            KmipError::failed(
                ResultReason::MissingData,
                "must specify either Current Attribute or Attribute Reference".to_string(),
            )));
    }

    commit_mutation(deps, auth, correlation_id, obj)?;
    emit_success(deps, correlation_id, "DeleteAttribute");
    Ok(DeleteAttributeResponse { uid: req.uid })
}

// ── SetAttribute ───────────────────────────────────────────────────────────

pub fn set_attribute(
    deps: &Deps,
    req: SetAttributeRequest,
    auth: &crate::server::auth::AuthContext,
    correlation_id: &str,
) -> Result<SetAttributeResponse> {
    emit_request(deps, correlation_id, "SetAttribute",
                 format!("uid={} attr={:?}", req.uid, attribute_name(&req.new_attribute)));

    // Part F §F7.4 — owner-checked lookup (see get.rs for the pattern).
    let mut obj = super::helpers::authorize_object(deps, auth, &req.uid, || {
        KmipError::object_not_found(&req.uid)
    })
    .map_err(|e| fail_err(deps, correlation_id, "SetAttribute", e))?;
    policy_gate(deps, &obj, "SetAttribute", correlation_id)?;

    // Per §6.1.56: "Read-Only attributes SHALL NOT be added or modified
    // using this operation."
    if attribute_is_read_only(&req.new_attribute) {
        return Err(fail_err(deps, correlation_id, "SetAttribute",
            KmipError::failed(
                ResultReason::InvalidField,
                format!("attribute {:?} is Read-Only", attribute_name(&req.new_attribute)),
            )));
    }

    // Gap-remediation Phase B — §4.69 Table 90's guard condition:
    // Usage Limits stops being client-modifiable once Get Usage
    // Allocation has granted at least one allocation against it.
    if matches!(&req.new_attribute, Attribute::UsageLimits { .. }) && usage_limits_locked(&obj) {
        return Err(fail_err(deps, correlation_id, "SetAttribute",
            KmipError::failed(
                ResultReason::InvalidField,
                format!(
                    "UsageLimits on {} is no longer client-modifiable — Get Usage Allocation has already granted against it",
                    req.uid,
                ),
            )));
    }

    check_circular_link(deps, "SetAttribute", &req.uid, &req.new_attribute, correlation_id)?;
    apply_attribute(&mut obj, &req.new_attribute);
    commit_mutation(deps, auth, correlation_id, obj)?;
    emit_success(deps, correlation_id, "SetAttribute");
    Ok(SetAttributeResponse { uid: req.uid })
}

// ── AdjustAttribute ────────────────────────────────────────────────────────

pub fn adjust_attribute(
    deps: &Deps,
    req: AdjustAttributeRequest,
    auth: &crate::server::auth::AuthContext,
    correlation_id: &str,
) -> Result<AdjustAttributeResponse> {
    emit_request(deps, correlation_id, "AdjustAttribute",
                 format!("uid={} ref={:?} type={:?}", req.uid, req.attribute_reference, req.adjustment_type));

    // Part F §F7.4 — owner-checked lookup (see get.rs for the pattern).
    let mut obj = super::helpers::authorize_object(deps, auth, &req.uid, || {
        KmipError::object_not_found(&req.uid)
    })
    .map_err(|e| fail_err(deps, correlation_id, "AdjustAttribute", e))?;

    // K22 — §6.1.3.1 Error Handling – Adjust Attribute is the only
    // attribute-mutation error table that lists `Object Archived`
    // (0x0d): adjusting an archived object's attributes fails until
    // Recover. (Add/Modify/Delete/Set Attribute tables do not list
    // it, so those still work on archived objects.)
    if obj.archived {
        return Err(fail_err(deps, correlation_id, "AdjustAttribute",
            KmipError::object_archived(&req.uid)));
    }
    policy_gate(deps, &obj, "AdjustAttribute", correlation_id)?;

    // Per §6.1.3, the v0.1 store has very few numeric/boolean attributes
    // that can be adjusted; the spec applies broadly to attributes like
    // Cryptographic Usage Mask, Server Limit, Operation Policy. We honour
    // Cryptographic Usage Mask (bit operations) and CryptographicLength
    // for now; everything else returns OperationNotSupported.
    let canonical: String = req.attribute_reference.chars().filter(|c| c.is_alphanumeric()).collect();
    match canonical.as_str() {
        "CryptographicUsageMask" => {
            let delta = req.adjustment_value.unwrap_or(0) as u32;
            obj.usage_mask = match req.adjustment_type {
                AdjustmentType::Increment => obj.usage_mask | UsageMask::from_bits_truncate(delta),
                AdjustmentType::Decrement => obj.usage_mask & UsageMask::from_bits_truncate(!delta),
                AdjustmentType::Negate    => UsageMask::from_bits_truncate(!obj.usage_mask.bits()),
            };
        }
        "CryptographicLength" => {
            let prev = obj.cryptographic_length as i64;
            let delta = req.adjustment_value.unwrap_or(0);
            obj.cryptographic_length = match req.adjustment_type {
                AdjustmentType::Increment => (prev + delta).max(0) as u32,
                AdjustmentType::Decrement => (prev - delta).max(0) as u32,
                AdjustmentType::Negate    => 0,
            };
        }
        other => {
            return Err(fail_err(deps, correlation_id, "AdjustAttribute",
                KmipError::failed(
                    ResultReason::OperationNotSupported,
                    format!("AdjustAttribute on {other} not supported in v0.1"),
                )));
        }
    }

    commit_mutation(deps, auth, correlation_id, obj)?;
    emit_success(deps, correlation_id, "AdjustAttribute");
    Ok(AdjustAttributeResponse { uid: req.uid })
}

// ── Shared helpers ─────────────────────────────────────────────────────────

/// Shared commit path for all five mutation ops. KMIP 3.0 §11 — `Last
/// Change Date` is server-set and SHALL be updated whenever any
/// attribute of the managed object changes (K-13); stamping it here,
/// immediately before `store.update`, guarantees no mutation op can
/// forget it.
fn commit_mutation(
    deps: &Deps,
    auth: &crate::server::auth::AuthContext,
    correlation_id: &str,
    mut obj: ObjectRecord,
) -> Result<()> {
    obj.last_change_date = Some(OffsetDateTime::now_utc());
    refresh_engine_mechanism_whitelist(deps, auth, correlation_id, &obj);
    deps.store.update(obj)
}

/// PKCS#11 v3.2 §4.8 Table 13 — keep the engine-side `CKA_ALLOWED_MECHANISMS`
/// whitelist in sync with `CryptographicUsageMask` across every attribute
/// mutation (Add/Modify/Set/Adjust/Delete all funnel through
/// `commit_mutation`). Without this, widening usage post-creation left the
/// engine gate stuck at its original, narrower set (blocking a now-allowed
/// op), and narrowing it left the gate stuck at its original, wider set —
/// reopening the exact raw-PKCS#11 bypass this attribute exists to close.
/// Unconditional (not gated on which attribute changed) and unconditional on
/// the derived list being non-empty — unlike Create's skip-if-empty
/// posture, a mutation that narrows usage to nothing MUST actively write an
/// empty whitelist so `check_mechanism_allowed` locks the key down, not
/// leave a stale wider one in place. Scoped to key objects only — Certificate
/// records carry a sentinel `CryptographicAlgorithm` (never a real mechanism
/// family) and have no PKCS#11 concept of a mechanism whitelist. Best-effort,
/// same posture as key creation: a set_attribute failure here doesn't unwind
/// the already-decided KMIP-side mutation.
fn refresh_engine_mechanism_whitelist(
    deps: &Deps,
    auth: &crate::server::auth::AuthContext,
    correlation_id: &str,
    obj: &ObjectRecord,
) {
    use crate::kmip30::ObjectType;
    if !matches!(
        obj.object_type,
        ObjectType::PrivateKey | ObjectType::PublicKey | ObjectType::SymmetricKey
    ) {
        return;
    }
    // Part F §F7 — the mutated object's engine mirror lives in the
    // CALLING tenant's own token (ownership verified upstream by
    // authorize_object), so the whitelist refresh uses the caller's
    // resolved session.
    let Some(session) = deps.resolve_tenant_session(auth.identity.as_ref()).ok() else { return };
    let Ok(Some(handle)) =
        super::helpers::find_handle_for_object(session, &obj.pkcs11_cka_id, obj.object_type)
    else {
        return;
    };
    let mechs = obj.algorithm.usage_mask_to_allowed_mechanisms(obj.usage_mask);
    let packed: Vec<u8> = mechs.iter().flat_map(|m| m.to_le_bytes()).collect();
    let r = softhsmrustv3::native::set_attribute(
        session,
        handle,
        softhsmrustv3::constants::CKA_ALLOWED_MECHANISMS,
        packed,
    );
    super::helpers::emit_pkcs11_result(
        deps,
        correlation_id,
        "native::set_attribute(CKA_ALLOWED_MECHANISMS, refresh)",
        None,
        &r,
    );
}

fn policy_gate(deps: &Deps, obj: &ObjectRecord, op: &'static str, correlation_id: &str) -> Result<()> {
    let started = OffsetDateTime::now_utc();
    let empty: HashMap<String, String> = HashMap::new();
    let algo = canonical_name(obj.algorithm);
    let mut p_req = PolicyRequest::minimal(op, Some(&algo), started, correlation_id, &empty);
    p_req.state = Some(state_name(obj.state));
    p_req.target_uid = Some(&obj.uid);
    if let Decision::Deny { kmip_reason, human, .. } = deps.engine.evaluate(&p_req) {
        return Err(fail_err(deps, correlation_id, op, KmipError::failed(kmip_reason.to_result_reason(), human)));
    }
    Ok(())
}

/// Human-readable attribute tag name — used for diagnostics + reference lookup.
fn attribute_name(a: &Attribute) -> &'static str {
    match a {
        Attribute::CryptographicAlgorithm(_) => "CryptographicAlgorithm",
        Attribute::CryptographicLength(_)    => "CryptographicLength",
        Attribute::CryptographicUsageMask(_) => "CryptographicUsageMask",
        Attribute::ObjectType(_)             => "ObjectType",
        Attribute::State(_)                  => "State",
        Attribute::UniqueIdentifier(_)       => "UniqueIdentifier",
        Attribute::Name(_)                   => "Name",
        Attribute::Custom { .. }             => "Custom",
        // Baseline Server attributes — tag-form names matter only for
        // diagnostics here; the wire codec carries the real codepoints.
        _ => "Baseline",
    }
}

/// Per KMIP 3.0 §4 the listed attributes are always present on any
/// managed object and MUST NOT be deleted. The rest may be absent.
fn attribute_is_required(a: &Attribute) -> bool {
    matches!(a,
        Attribute::UniqueIdentifier(_) |
        Attribute::ObjectType(_) |
        Attribute::State(_) |
        Attribute::CryptographicAlgorithm(_)
    )
}

fn attribute_name_is_required(name: &str) -> bool {
    let canonical: String = name.chars().filter(|c| c.is_alphanumeric()).collect();
    matches!(canonical.as_str(),
        "UniqueIdentifier" | "ObjectType" | "State" | "CryptographicAlgorithm"
    )
}

/// Per KMIP 3.0 §11 attribute table these attributes are Read-Only —
/// server SHALL NOT honour client attempts to add or modify them. The
/// list below mirrors the spec's "Modifiable by client = No" column.
///
/// Gap-remediation Phase B — every entry below (past the original
/// v0.1 set) was verified directly against the spec's own
/// attribute-rules tables (`kmip-spec-v3.0.pdf` §4.x, "Modifiable by
/// client" row), not inferred from context — a first-pass draft of
/// this fix had 3 wrong entries (CryptographicDomainParameters,
/// ProtectionStorageMask, KeyFormatType belong here; the Link
/// sub-types and ProtectionLevel do NOT — see `apply_attribute`)
/// caught only by re-checking every attribute against the spec text
/// before implementing.
fn attribute_is_read_only(a: &Attribute) -> bool {
    matches!(a,
        Attribute::UniqueIdentifier(_) |
        Attribute::ObjectType(_) |
        Attribute::State(_) |
        // Initial Date / Last Change Date / Original Creation Date /
        // Short Unique Identifier are all server-set timestamps.
        Attribute::InitialDate(_) |
        Attribute::LastChangeDate(_) |
        Attribute::OriginalCreationDate(_) |
        Attribute::ShortUniqueIdentifier(_) |
        // Always Sensitive / Never Extractable are server-derived from
        // the Sensitive / Extractable history (§11).
        Attribute::AlwaysSensitive(_) |
        Attribute::NeverExtractable(_) |
        // Digest + RandomNumberGenerator structures are server-computed.
        Attribute::Digest(_) |
        Attribute::RandomNumberGenerator(_) |
        // Key Value Present mirrors the engine state.
        Attribute::KeyValuePresent(_) |
        // Certificate Length / Subject CN / Issuer / Subject are
        // server-extracted from the Certificate Value DER bytes at
        // Register time. BL-M-10 step #4 pins `CertificateLength`.
        Attribute::CertificateLength(_) |
        Attribute::CertificateSubjectCN(_) |
        Attribute::X509CertificateSubject(_) |
        Attribute::X509CertificateIssuer(_) |
        Attribute::X509CertificateIdentifier(_) |
        // §4.16 Table 89 — "Modifiable by client: No". Distinct from
        // `CryptographicParameters`, which IS client-modifiable
        // (Table 93) — see `apply_attribute`.
        Attribute::CryptographicDomainParameters { .. } |
        // §4.50 — "Modifiable by client: No". The server is the only
        // authority on which storage classes actually back an object.
        Attribute::ProtectionStorageMask(_) |
        // §4.29 — "Modifiable by client: No".
        Attribute::KeyFormatType(_) |
        // §4.25 — "Modifiable by client: No".
        Attribute::DigitalSignatureAlgorithm(_) |
        // §4.38 — "Modifiable by client: No".
        Attribute::NistKeyType(_) |
        // §4.53 — "Modifiable by client: No". Set by Revoke, not
        // client-editable afterward.
        Attribute::RevocationReasonCode(_) |
        // §4.21 — "Modifiable by client: No". Set by Deactivate.
        Attribute::DeactivationReasonCode(_) |
        // §4.7 — "Modifiable by client: No". Server-derived from the
        // Certificate Value DER at Register time, same posture as the
        // CertificateLength/SubjectCN/Issuer/Subject group above.
        Attribute::CertificateType(_) |
        Attribute::CertificateValue(_) |
        // §4.63-4.66 — all four Split Key attributes plus Key Part
        // Identifier are "Modifiable by client: No"; they describe the
        // share's own math (method/threshold/parts/index/polynomial),
        // fixed at Create Split Key time, not something to edit after
        // the fact.
        Attribute::SplitKeyMethod(_) |
        Attribute::SplitKeyParts(_) |
        Attribute::SplitKeyThreshold(_) |
        Attribute::KeyPartIdentifier(_) |
        Attribute::SplitKeyPolynomial(_)
    )
}

/// Gap-remediation Phase B — §4.69 Table 90: `Usage Limits` is
/// "Modifiable by client: Yes (Usage Limits Total and/or Usage Limits
/// Unit only, as long as Get Usage Allocation has not been performed)".
/// `usage_limits_remaining` starts `None` and only becomes `Some(_)`
/// once `GetUsageAllocation` grants the first allocation
/// (`ops/allocation_and_config.rs`) — exactly the signal the spec's
/// guard condition needs.
fn usage_limits_locked(obj: &ObjectRecord) -> bool {
    obj.usage_limits_remaining.is_some()
}

/// True if `obj` currently has a value for the attribute carried in `a`.
fn attribute_present(obj: &ObjectRecord, a: &Attribute) -> bool {
    match a {
        Attribute::Name(_)                   => obj.name.is_some(),
        Attribute::CryptographicAlgorithm(_) => true,  // always present (created with one)
        Attribute::CryptographicLength(_)    => obj.cryptographic_length > 0,
        Attribute::CryptographicUsageMask(_) => !obj.usage_mask.is_empty(),
        Attribute::ObjectType(_)             => true,
        Attribute::State(_)                  => true,
        Attribute::UniqueIdentifier(_)       => true,
        Attribute::Custom { name, .. }       => obj.custom_attributes.contains_key(name),
        Attribute::NextLink(_)               => obj.links.contains_key("NextLink"),
        Attribute::PreviousLink(_)           => obj.links.contains_key("PreviousLink"),
        Attribute::PublicKeyLink(_)          => obj.links.contains_key("PublicKeyLink"),
        Attribute::PrivateKeyLink(_)         => obj.links.contains_key("PrivateKeyLink"),
        // Gap-remediation Phase B/T3 — these 5 link types (the
        // pre-existing GroupLink plus the 4 newly-settable Derivation/
        // Replacement links) fell through to the `true` catch-all
        // below, which made `AddAttribute` on a *fresh* object (that
        // never had the link set) wrongly fail with
        // `AttributeSingleValued` instead of succeeding — harmless
        // while these were no-ops in `apply_attribute`, load-bearing
        // now that they're genuinely persisted.
        Attribute::GroupLink(_)                   => obj.links.contains_key("GroupLink"),
        Attribute::DerivationBaseObjectLink(_)    => obj.links.contains_key("DerivationBaseObjectLink"),
        Attribute::DerivedObjectLink(_)            => obj.links.contains_key("DerivedObjectLink"),
        Attribute::ReplacedObjectLink(_)           => obj.links.contains_key("ReplacedObjectLink"),
        Attribute::ReplacementObjectLink(_)        => obj.links.contains_key("ReplacementObjectLink"),
        // Same class of gap for the three attributes Phase B just made
        // genuinely settable.
        Attribute::ProtectionLevel(_)         => obj.protection_level.is_some(),
        Attribute::CryptographicParameters(_) => obj.cryptographic_parameters.is_some(),
        Attribute::UsageLimits { .. }         => obj.usage_limits_total.is_some(),
        // KMIP `Object Group` is multi-instance: "present" means THIS
        // exact membership already exists. AddAttribute may add further
        // distinct groups; re-adding the same one trips the §6.1.2
        // already-present guard.
        Attribute::ObjectGroup(g)            => obj.object_groups.iter().any(|x| x == g),
        // Baseline Server attributes — presence depends on the typed
        // field actually being populated on the record. AddAttribute
        // MUST succeed when none of these is yet set (BL-M-5 step #3
        // pins `AddAttribute Description` on a fresh OpaqueObject).
        Attribute::Description(_)            => obj.description.is_some(),
        Attribute::Comment(_)                => obj.comment.is_some(),
        Attribute::ContactInformation(_)     => obj.contact_information.is_some(),
        Attribute::AlternativeName { .. }    => obj.alternative_name.is_some(),
        Attribute::ObjectClass(_)            => obj.object_class.is_some(),
        Attribute::KeyValueLocation(_)       => obj.key_value_location.is_some(),
        Attribute::ActivationDate(_)         => obj.activation_date.is_some(),
        Attribute::DeactivationDate(_)       => obj.deactivation_date.is_some(),
        Attribute::DestroyDate(_)            => obj.destroy_date.is_some(),
        Attribute::CompromiseDate(_)         => obj.compromise_date.is_some(),
        Attribute::CompromiseOccurrenceDate(_) => obj.compromise_occurrence_date.is_some(),
        Attribute::ProcessStartDate(_)       => obj.process_start_date.is_some(),
        Attribute::ProtectStopDate(_)        => obj.protect_stop_date.is_some(),
        Attribute::RotateDate(_)             => obj.rotate_date.is_some(),
        Attribute::Sensitive(_)              => obj.sensitive.is_some(),
        Attribute::Extractable(_)            => obj.extractable.is_some(),
        Attribute::Fresh(_)                  => obj.fresh.is_some(),
        Attribute::QuantumSafe(_)            => obj.quantum_safe.is_some(),
        Attribute::LeaseTime(_)              => obj.lease_time.is_some(),
        Attribute::RotateName(_)             => obj.rotate_name.is_some(),
        // Conservative default: claim present for attrs we don't yet
        // route into a typed field. Tightens up over time as more
        // tests exercise them.
        _ => true,
    }
}

fn attribute_name_present(obj: &ObjectRecord, name: &str) -> bool {
    let canonical: String = name.chars().filter(|c| c.is_alphanumeric()).collect();
    match canonical.as_str() {
        "Name"                    => obj.name.is_some(),
        "CryptographicAlgorithm"  => true,
        "CryptographicLength"     => obj.cryptographic_length > 0,
        "CryptographicUsageMask"  => !obj.usage_mask.is_empty(),
        "ObjectType" | "State" | "UniqueIdentifier" => true,
        // Gap-remediation Phase B/T3 — same three attributes as
        // `attribute_present`'s corresponding fix.
        "ProtectionLevel"         => obj.protection_level.is_some(),
        "CryptographicParameters" => obj.cryptographic_parameters.is_some(),
        "UsageLimits"             => obj.usage_limits_total.is_some(),
        // Gap-remediation Phase B/T3 — the pre-existing catch-all
        // checked `obj.links.contains_key(name)` against the RAW
        // decoded reference (e.g. "Next Link", spec-cased with a
        // space per `tag_name_from_code`), never matching the
        // no-space keys `apply_attribute` actually writes
        // ("NextLink"). Every `DeleteAttribute` by name against any
        // Link attribute has always spuriously returned
        // `ItemNotFound` as a result. Match on `canonical` (already
        // space-stripped) instead, same as `remove_attribute_by_name`
        // below.
        _ => obj.custom_attributes.contains_key(name) || obj.links.contains_key(&canonical),
    }
}

/// P2.4 — extract `(canonical-link-key, target-UID)` for the Link
/// attribute variants, else `None`. The key matches the `obj.links`
/// map keys written by [`apply_attribute`].
fn link_target(a: &Attribute) -> Option<(&'static str, &str)> {
    match a {
        Attribute::NextLink(uid)       => Some(("NextLink", uid)),
        Attribute::PreviousLink(uid)   => Some(("PreviousLink", uid)),
        Attribute::PublicKeyLink(uid)  => Some(("PublicKeyLink", uid)),
        Attribute::PrivateKeyLink(uid) => Some(("PrivateKeyLink", uid)),
        Attribute::GroupLink(uid)      => Some(("GroupLink", uid)),
        // Gap-remediation Phase B — KMIP 3.0 Tables 136/138/160/162 all
        // say "Modifiable by client: Yes" for these four (verified
        // directly against the spec, not assumed), so `apply_attribute`
        // below now persists them for real. Wiring them into
        // `link_target` too means `check_circular_link` (already called
        // generically by Add/Modify/SetAttribute) actually protects
        // them — without this, making them settable would let a client
        // create a genuine circular link the way ReKey/DeriveKey's own
        // internal writes never could.
        Attribute::DerivationBaseObjectLink(uid) => Some(("DerivationBaseObjectLink", uid)),
        Attribute::DerivedObjectLink(uid)         => Some(("DerivedObjectLink", uid)),
        Attribute::ReplacedObjectLink(uid)         => Some(("ReplacedObjectLink", uid)),
        Attribute::ReplacementObjectLink(uid)      => Some(("ReplacementObjectLink", uid)),
        _ => None,
    }
}

/// KMIP §11 defines several link types as *inverse pairs* — the back
/// edge of a legitimate bidirectional relationship, NOT a cycle:
/// NextLink↔PreviousLink (rotation chain), PublicKeyLink↔PrivateKeyLink
/// (key-pair halves), ReplacedObjectLink↔ReplacementObjectLink (re-key),
/// DerivationBaseObjectLink↔DerivedObjectLink (derive). A reciprocal
/// link that uses the matching inverse type is spec-correct and must
/// NOT be flagged as a `Circular Link Error`. Returns the canonical
/// inverse key of `key`, if any.
fn inverse_link_key(key: &str) -> Option<&'static str> {
    Some(match key {
        "NextLink"                 => "PreviousLink",
        "PreviousLink"             => "NextLink",
        "PublicKeyLink"            => "PrivateKeyLink",
        "PrivateKeyLink"           => "PublicKeyLink",
        "ReplacedObjectLink"       => "ReplacementObjectLink",
        "ReplacementObjectLink"    => "ReplacedObjectLink",
        "DerivationBaseObjectLink" => "DerivedObjectLink",
        "DerivedObjectLink"        => "DerivationBaseObjectLink",
        _ => return None,
    })
}

/// P2.4 — detect link cycles before storing a Link attribute and emit
/// `Circular Link Error` (KMIP 3.0 §11, 0x4d) instead of silently
/// storing the cycle (the previous behaviour). Scope: the directly
/// cheap cases — a self-link (A→A) and an immediate reciprocal 2-cycle
/// (adding A→B while B already carries a link back to A). Deeper (N>2)
/// cycle detection would require a full link-graph walk across the
/// store and is left as future work.
///
/// P2.1 correction: a reciprocal link via the spec-defined *inverse*
/// link type (NextLink↔PreviousLink, PublicKeyLink↔PrivateKeyLink, …)
/// is the legitimate back edge of a bidirectional relationship, not a
/// cycle — the original P2.4 heuristic wrongly rejected it, breaking
/// AX-M-1/2 (which stitch a rotation chain with NextLink then the
/// reciprocal PreviousLink). Only a back-link via a NON-inverse type
/// (or the same type) is a true cycle.
fn check_circular_link(
    deps: &Deps,
    op: &str,
    src_uid: &str,
    a: &Attribute,
    correlation_id: &str,
) -> Result<()> {
    let Some((key, target)) = link_target(a) else { return Ok(()) };
    // Self-link: A → A.
    if target == src_uid {
        return Err(fail_err(deps, correlation_id, op,
            KmipError::circular_link_error(format!(
                "Link on {src_uid} targets itself ({target})"))));
    }
    // Direct reciprocal 2-cycle: target already links back to src via a
    // link type that is NOT the spec inverse of the one being added.
    let inverse = inverse_link_key(key);
    if let Ok(Some(target_obj)) = deps.store.get(target) {
        let true_cycle = target_obj
            .links
            .iter()
            .any(|(back_key, v)| v == src_uid && Some(back_key.as_str()) != inverse);
        if true_cycle {
            return Err(fail_err(deps, correlation_id, op,
                KmipError::circular_link_error(format!(
                    "Link {src_uid}→{target} closes a reciprocal cycle ({target} already links back to {src_uid})"))));
        }
    }
    Ok(())
}

/// Write the attribute value into the right slot on `obj`. Used by Add /
/// Modify / Set (which all converge on "the new value SHALL be stored").
fn apply_attribute(obj: &mut ObjectRecord, a: &Attribute) {
    match a {
        Attribute::Name(n)                   => obj.name = Some(n.clone()),
        Attribute::CryptographicAlgorithm(_) => {}  // Read-Only, guarded earlier
        Attribute::CryptographicLength(n)    => obj.cryptographic_length = *n,
        Attribute::CryptographicUsageMask(m) => obj.usage_mask = *m,
        Attribute::ObjectType(_)             => {}  // Read-Only
        Attribute::State(_)                  => {}  // Read-Only
        Attribute::UniqueIdentifier(_)       => {}  // Read-Only
        Attribute::Custom { name, value }    => {
            obj.custom_attributes.insert(name.clone(), value.clone());
        }
        // KMIP §11 Link attributes — UID references into the
        // record's `links` map keyed by canonical attribute name.
        // GetAttributes / GetAttributeList read back the same keys.
        Attribute::NextLink(uid)             => { obj.links.insert("NextLink".into(), uid.clone()); }
        Attribute::PreviousLink(uid)         => { obj.links.insert("PreviousLink".into(), uid.clone()); }
        Attribute::PublicKeyLink(uid)        => { obj.links.insert("PublicKeyLink".into(), uid.clone()); }
        Attribute::PrivateKeyLink(uid)       => { obj.links.insert("PrivateKeyLink".into(), uid.clone()); }
        Attribute::GroupLink(uid)            => { obj.links.insert("GroupLink".into(), uid.clone()); }
        // Gap-remediation Phase B — §4.19/§4.22/§4.51/§4.52 (Tables
        // 136/138/160/162): all "Modifiable by client: Yes", same
        // posture as the five link types just above. `link_target`
        // (used by `check_circular_link`, already called generically
        // by every caller of `apply_attribute`) now recognizes these
        // four too, so making them real doesn't also open a
        // circular-link hole.
        Attribute::DerivationBaseObjectLink(uid) => { obj.links.insert("DerivationBaseObjectLink".into(), uid.clone()); }
        Attribute::DerivedObjectLink(uid)         => { obj.links.insert("DerivedObjectLink".into(), uid.clone()); }
        Attribute::ReplacedObjectLink(uid)         => { obj.links.insert("ReplacedObjectLink".into(), uid.clone()); }
        Attribute::ReplacementObjectLink(uid)      => { obj.links.insert("ReplacementObjectLink".into(), uid.clone()); }
        // KMIP `Object Group` (0x420056) — multi-instance: AddAttribute
        // appends a fresh membership; SetAttribute reuses this path so a
        // repeated value is idempotent (deduped).
        Attribute::ObjectGroup(g)            => {
            if !obj.object_groups.contains(g) {
                obj.object_groups.push(g.clone());
            }
        }
        Attribute::ApplicationSpecificInformation { namespace, data } => {
            obj.application_specific_information = Some((namespace.clone(), data.clone()));
        }
        // ── Baseline Server attribute setters ──
        Attribute::ActivationDate(t)           => obj.activation_date = Some(time::OffsetDateTime::from_unix_timestamp(*t).unwrap_or(time::OffsetDateTime::UNIX_EPOCH)),
        Attribute::DeactivationDate(t)         => obj.deactivation_date = Some(time::OffsetDateTime::from_unix_timestamp(*t).unwrap_or(time::OffsetDateTime::UNIX_EPOCH)),
        Attribute::DestroyDate(t)              => obj.destroy_date = Some(time::OffsetDateTime::from_unix_timestamp(*t).unwrap_or(time::OffsetDateTime::UNIX_EPOCH)),
        Attribute::CompromiseDate(t)           => obj.compromise_date = Some(time::OffsetDateTime::from_unix_timestamp(*t).unwrap_or(time::OffsetDateTime::UNIX_EPOCH)),
        Attribute::CompromiseOccurrenceDate(t) => obj.compromise_occurrence_date = Some(time::OffsetDateTime::from_unix_timestamp(*t).unwrap_or(time::OffsetDateTime::UNIX_EPOCH)),
        Attribute::ProcessStartDate(t)         => obj.process_start_date = Some(time::OffsetDateTime::from_unix_timestamp(*t).unwrap_or(time::OffsetDateTime::UNIX_EPOCH)),
        Attribute::ProtectStopDate(t)          => obj.protect_stop_date = Some(time::OffsetDateTime::from_unix_timestamp(*t).unwrap_or(time::OffsetDateTime::UNIX_EPOCH)),
        Attribute::RotateDate(t)               => obj.rotate_date = Some(time::OffsetDateTime::from_unix_timestamp(*t).unwrap_or(time::OffsetDateTime::UNIX_EPOCH)),
        Attribute::Sensitive(b)                => obj.sensitive = Some(*b),
        Attribute::Extractable(b)              => obj.extractable = Some(*b),
        Attribute::Fresh(b)                    => obj.fresh = Some(*b),
        Attribute::QuantumSafe(b)              => obj.quantum_safe = Some(*b),
        Attribute::RotateAutomatic(b)          => obj.rotate_automatic = Some(*b),
        Attribute::AlternativeName { value, name_type } => {
            obj.alternative_name = Some(value.clone());
            obj.alternative_name_type = Some(*name_type);
        }
        Attribute::Comment(s)                  => obj.comment = Some(s.clone()),
        Attribute::Description(s)              => obj.description = Some(s.clone()),
        Attribute::ContactInformation(s)       => obj.contact_information = Some(s.clone()),
        Attribute::ObjectClass(s)              => obj.object_class = Some(s.clone()),
        Attribute::KeyValueLocation(s)         => obj.key_value_location = Some(s.clone()),
        Attribute::X509CertificateIdentifier(s) => obj.x509_certificate_identifier = Some(s.clone()),
        Attribute::X509CertificateIssuer(s)    => obj.x509_certificate_issuer = Some(s.clone()),
        Attribute::X509CertificateSubject(s)   => obj.x509_certificate_subject = Some(s.clone()),
        Attribute::RotateName(s)               => obj.rotate_name = Some(s.clone()),
        Attribute::LeaseTime(n)                => obj.lease_time = Some(*n),
        Attribute::ProtectionPeriod(n)         => obj.protection_period = Some(*n),
        Attribute::RotateInterval(n)           => obj.rotate_interval = Some(*n),
        Attribute::RotateOffset(n)             => obj.rotate_offset = Some(*n),
        Attribute::RotateGeneration(n)         => obj.rotate_generation = Some(*n),
        // §4.48 Table 148 — "Modifiable by client: Yes".
        Attribute::ProtectionLevel(n)          => obj.protection_level = Some(*n),
        // Gap-remediation Phase B — §4.18 Table 93: "Modifiable by
        // client: Yes", unconditionally (unlike UsageLimits below, no
        // guard condition). Distinct from `CryptographicDomainParameters`
        // (read-only, see `attribute_is_read_only`).
        Attribute::CryptographicParameters(cp) => obj.cryptographic_parameters = Some(cp.clone()),
        // Gap-remediation Phase B — §4.69 Table 90: "Modifiable by
        // client: Yes (Usage Limits Total and/or Usage Limits Unit
        // only, as long as Get Usage Allocation has not been
        // performed)". The guard condition is enforced by the callers
        // (`set_attribute`/`modify_attribute`, via `usage_limits_locked`)
        // before this ever runs; `count` (the remaining budget) is
        // deliberately NOT settable here — that's server-managed via
        // GetUsageAllocation, same as `extract_attrs`'s identical
        // Create/Register-time handling of this attribute.
        Attribute::UsageLimits { total, unit, .. } => {
            obj.usage_limits_total = Some(*total);
            obj.usage_limits_unit = *unit;
        }
        // Read-only or server-managed Baseline attributes (Initial Date,
        // Last Change Date, Original Creation Date, Short UID, Always/
        // Never Sensitive, Key Value Present, Certificate*, Split Key*,
        // etc.) — the server sets these; client AddAttribute is a no-op.
        // Every non-custom variant that reaches this arm is intentional:
        // it's either genuinely read-only (guarded by
        // `attribute_is_read_only` before `apply_attribute` is ever
        // called) or a vendor/forward-compat variant this store doesn't
        // yet route to a typed field.
        _ => {}
    }
}

fn remove_attribute_by_value(obj: &mut ObjectRecord, a: &Attribute) {
    match a {
        Attribute::Name(_)                   => obj.name = None,
        Attribute::CryptographicLength(_)    => obj.cryptographic_length = 0,
        Attribute::CryptographicUsageMask(_) => obj.usage_mask = UsageMask::empty(),
        Attribute::Custom { name, .. }       => { obj.custom_attributes.remove(name); }
        // KMIP `Object Group` multi-instance — drop just the named
        // membership, leaving the object in any other groups.
        Attribute::ObjectGroup(g)            => { obj.object_groups.retain(|x| x != g); }
        // Gap-remediation Phase B/T3 — `DeleteAttribute`'s
        // `current_attribute`-value path had no arms at all for any
        // Link type or for the three attributes Phase B just made
        // genuinely settable: `attribute_present`/`attribute_is_required`
        // would let the delete through, but this function then did
        // nothing, so the client got a `Success` while the value stayed
        // in the store. `UsageLimits`'s own guard (§4.69 Table 90:
        // "Deletable by client: Yes, as long as Get Usage Allocation has
        // not been performed") is enforced by the caller
        // (`delete_attribute`, via `usage_limits_locked`) before this
        // ever runs — mirrors the Set/ModifyAttribute guard exactly.
        Attribute::NextLink(_)                    => { obj.links.remove("NextLink"); }
        Attribute::PreviousLink(_)                => { obj.links.remove("PreviousLink"); }
        Attribute::PublicKeyLink(_)               => { obj.links.remove("PublicKeyLink"); }
        Attribute::PrivateKeyLink(_)              => { obj.links.remove("PrivateKeyLink"); }
        Attribute::GroupLink(_)                   => { obj.links.remove("GroupLink"); }
        Attribute::DerivationBaseObjectLink(_)    => { obj.links.remove("DerivationBaseObjectLink"); }
        Attribute::DerivedObjectLink(_)           => { obj.links.remove("DerivedObjectLink"); }
        Attribute::ReplacedObjectLink(_)          => { obj.links.remove("ReplacedObjectLink"); }
        Attribute::ReplacementObjectLink(_)       => { obj.links.remove("ReplacementObjectLink"); }
        Attribute::ProtectionLevel(_)             => { obj.protection_level = None; }
        Attribute::CryptographicParameters(_)     => { obj.cryptographic_parameters = None; }
        Attribute::UsageLimits { .. }             => {
            obj.usage_limits_total = None;
            obj.usage_limits_unit = None;
        }
        // Required / Read-Only attributes guarded earlier.
        _ => {}
    }
}

fn remove_attribute_by_name(obj: &mut ObjectRecord, name: &str) {
    let canonical: String = name.chars().filter(|c| c.is_alphanumeric()).collect();
    match canonical.as_str() {
        "Name"                   => obj.name = None,
        "CryptographicLength"    => obj.cryptographic_length = 0,
        "CryptographicUsageMask" => obj.usage_mask = UsageMask::empty(),
        // Gap-remediation Phase B/T3 — same three attributes as
        // `remove_attribute_by_value`'s corresponding fix; the generic
        // `other` arm below only clears `custom_attributes`/`links`, so
        // these three (stored in dedicated typed fields) need explicit
        // arms or a name-based Delete silently no-ops for them too.
        "ProtectionLevel"         => obj.protection_level = None,
        "CryptographicParameters" => obj.cryptographic_parameters = None,
        "UsageLimits"             => {
            obj.usage_limits_total = None;
            obj.usage_limits_unit = None;
        }
        other => {
            obj.custom_attributes.remove(other);
            obj.links.remove(other);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditlog::{AuditSink, RingSink};
    use crate::kmip30::{KmipAlgorithm, ObjectType, State, UsageMask};
    use crate::policy::{load_from_str, Engine};
    use crate::store::MemoryStore;
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

    fn put(d: &Deps, uid: &str) {
        d.store.put(ObjectRecord {
            uid: uid.into(),
            object_type: ObjectType::SymmetricKey,
            algorithm: KmipAlgorithm::Aes,
            cryptographic_length: 256,
            usage_mask: UsageMask::ENCRYPT,
            state: State::Active,
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
        ..ObjectRecord::default()
}).unwrap();
    }

    #[test]
    fn add_then_get_name_round_trips() {
        let d = deps_with();
        put(&d, "u");
        add_attribute(&d, AddAttributeRequest {
            uid: "u".into(),
            new_attribute: Attribute::Name("my-key".into()),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        assert_eq!(d.store.get("u").unwrap().unwrap().name.as_deref(), Some("my-key"));
    }

    #[test]
    fn add_existing_name_fails_single_valued() {
        let d = deps_with();
        put(&d, "u");
        // First add succeeds.
        add_attribute(&d, AddAttributeRequest {
            uid: "u".into(), new_attribute: Attribute::Name("x".into()),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        // Second add on same attribute must fail per §6.1.2 with
        // `AttributeSingleValued` (v0.1 carries only one Name per
        // record; multi-valued Name support would relax this).
        let err = add_attribute(&d, AddAttributeRequest {
            uid: "u".into(), new_attribute: Attribute::Name("y".into()),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::AttributeSingleValued);
    }

    #[test]
    fn add_read_only_attribute_fails() {
        let d = deps_with();
        put(&d, "u");
        let err = add_attribute(&d, AddAttributeRequest {
            uid: "u".into(),
            new_attribute: Attribute::ObjectType(ObjectType::SymmetricKey),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap_err();
        // §6.1.2 — Add against an always-present (single-valued)
        // attribute fails the presence check first → `AttributeSingleValued`.
        assert_eq!(err.result_reason(), ResultReason::AttributeSingleValued);
    }

    #[test]
    fn modify_name_changes_value() {
        let d = deps_with();
        put(&d, "u");
        add_attribute(&d, AddAttributeRequest {
            uid: "u".into(), new_attribute: Attribute::Name("v1".into()),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        modify_attribute(&d, ModifyAttributeRequest {
            uid: "u".into(), current_attribute: None,
            new_attribute: Attribute::Name("v2".into()),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        assert_eq!(d.store.get("u").unwrap().unwrap().name.as_deref(), Some("v2"));
    }

    /// KMIP 3.0 §6.1.38 + §11 attribute table — `State` is Read-Only
    /// (modifiable only by Activate/Revoke/Destroy state transitions).
    /// BL-M-7 step #2 pins `ResultReason = AttributeReadOnly` (0x22).
    #[test]
    fn modify_read_only_attribute_returns_attribute_read_only() {
        let d = deps_with();
        put(&d, "u");
        let err = modify_attribute(&d, ModifyAttributeRequest {
            uid: "u".into(),
            current_attribute: None,
            new_attribute: Attribute::State(crate::kmip30::State::Compromised),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::AttributeReadOnly);
    }

    /// KMIP 3.0 §11 attribute table — `Activation Date` is modifiable
    /// only while the managed object is in `PreActive`. Mutating it
    /// once the object has Activated returns `WrongKeyLifecycleState`
    /// (AKLC-M-3 step #4 + SKLC-M-3 step #4 both pin this code).
    #[test]
    fn modify_activation_date_after_active_returns_wrong_lifecycle_state() {
        let d = deps_with();
        // put() places the object directly in `Active` state.
        put(&d, "u");
        let err = modify_attribute(&d, ModifyAttributeRequest {
            uid: "u".into(),
            current_attribute: None,
            new_attribute: Attribute::ActivationDate(123_456_789),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::WrongKeyLifecycleState);
    }

    /// PreActive → modifying ActivationDate MUST succeed per §11.
    #[test]
    fn modify_activation_date_while_preactive_succeeds() {
        let d = deps_with();
        d.store.put(ObjectRecord {
            uid: "p".into(),
            object_type: ObjectType::SymmetricKey,
            algorithm: KmipAlgorithm::Aes,
            cryptographic_length: 256,
            usage_mask: UsageMask::ENCRYPT,
            state: State::PreActive,
            pkcs11_cka_id: vec![],
            pkcs11_slot: 0,
            initial_date: OffsetDateTime::UNIX_EPOCH,
            // KMIP §6.1.38 requires the attribute to ALREADY exist on
            // the object — seed an initial ActivationDate the modify
            // can then change. (SetAttribute is the right op when the
            // attribute is absent.)
            activation_date: Some(OffsetDateTime::UNIX_EPOCH),
            supersedes: None,
            name: None,
            links: HashMap::new(),
            custom_attributes: HashMap::new(),
            key_material: None,
            key_format_type: None,
            ..ObjectRecord::default()
        }).unwrap();
        modify_attribute(&d, ModifyAttributeRequest {
            uid: "p".into(),
            current_attribute: None,
            new_attribute: Attribute::ActivationDate(42),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        let rec = d.store.get("p").unwrap().unwrap();
        assert_eq!(rec.activation_date.unwrap().unix_timestamp(), 42);
    }

    #[test]
    fn modify_missing_attribute_fails() {
        let d = deps_with();
        put(&d, "u");
        // Name doesn't exist yet → Modify must fail per §6.1.38.
        let err = modify_attribute(&d, ModifyAttributeRequest {
            uid: "u".into(), current_attribute: None,
            new_attribute: Attribute::Name("v".into()),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::ItemNotFound);
    }

    #[test]
    fn delete_by_reference_removes_value() {
        let d = deps_with();
        put(&d, "u");
        add_attribute(&d, AddAttributeRequest {
            uid: "u".into(), new_attribute: Attribute::Name("x".into()),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        delete_attribute(&d, DeleteAttributeRequest {
            uid: "u".into(), current_attribute: None,
            attribute_reference: Some("Name".into()),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        assert!(d.store.get("u").unwrap().unwrap().name.is_none());
    }

    #[test]
    fn delete_required_attribute_fails() {
        let d = deps_with();
        put(&d, "u");
        let err = delete_attribute(&d, DeleteAttributeRequest {
            uid: "u".into(), current_attribute: None,
            attribute_reference: Some("CryptographicAlgorithm".into()),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::InvalidField);
    }

    #[test]
    fn set_acts_as_add_when_absent() {
        let d = deps_with();
        put(&d, "u");
        set_attribute(&d, SetAttributeRequest {
            uid: "u".into(), new_attribute: Attribute::Name("first".into()),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        assert_eq!(d.store.get("u").unwrap().unwrap().name.as_deref(), Some("first"));
    }

    #[test]
    fn set_acts_as_modify_when_present() {
        let d = deps_with();
        put(&d, "u");
        set_attribute(&d, SetAttributeRequest {
            uid: "u".into(), new_attribute: Attribute::Name("first".into()),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        set_attribute(&d, SetAttributeRequest {
            uid: "u".into(), new_attribute: Attribute::Name("second".into()),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        assert_eq!(d.store.get("u").unwrap().unwrap().name.as_deref(), Some("second"));
    }

    /// K-13 — KMIP 3.0 §11: `Last Change Date` SHALL be updated by
    /// every attribute-mutation op. The `put()` fixture stores
    /// `last_change_date: None`, so any `Some(_)` after the op proves
    /// the shared commit path stamped it.
    #[test]
    fn add_attribute_updates_last_change_date() {
        let d = deps_with();
        put(&d, "u");
        assert!(d.store.get("u").unwrap().unwrap().last_change_date.is_none());
        add_attribute(&d, AddAttributeRequest {
            uid: "u".into(), new_attribute: Attribute::Name("n".into()),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        assert!(d.store.get("u").unwrap().unwrap().last_change_date.is_some());
    }

    #[test]
    fn set_attribute_updates_last_change_date() {
        let d = deps_with();
        put(&d, "u");
        set_attribute(&d, SetAttributeRequest {
            uid: "u".into(), new_attribute: Attribute::Comment("c".into()),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        assert!(d.store.get("u").unwrap().unwrap().last_change_date.is_some());
    }

    #[test]
    fn modify_attribute_updates_last_change_date() {
        let d = deps_with();
        put(&d, "u");
        add_attribute(&d, AddAttributeRequest {
            uid: "u".into(), new_attribute: Attribute::Name("v1".into()),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        let after_add = d.store.get("u").unwrap().unwrap().last_change_date.unwrap();
        modify_attribute(&d, ModifyAttributeRequest {
            uid: "u".into(), current_attribute: None,
            new_attribute: Attribute::Name("v2".into()),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        let after_modify = d.store.get("u").unwrap().unwrap().last_change_date.unwrap();
        assert!(after_modify >= after_add);
    }

    #[test]
    fn delete_attribute_updates_last_change_date() {
        let d = deps_with();
        put(&d, "u");
        add_attribute(&d, AddAttributeRequest {
            uid: "u".into(), new_attribute: Attribute::Name("x".into()),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        delete_attribute(&d, DeleteAttributeRequest {
            uid: "u".into(), current_attribute: None,
            attribute_reference: Some("Name".into()),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        assert!(d.store.get("u").unwrap().unwrap().last_change_date.is_some());
    }

    #[test]
    fn adjust_attribute_updates_last_change_date() {
        let d = deps_with();
        put(&d, "u");
        adjust_attribute(&d, AdjustAttributeRequest {
            uid: "u".into(),
            attribute_reference: "Cryptographic Usage Mask".into(),
            adjustment_type: AdjustmentType::Increment,
            adjustment_value: Some(UsageMask::SIGN.bits() as i64),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        assert!(d.store.get("u").unwrap().unwrap().last_change_date.is_some());
    }

    #[test]
    fn adjust_usage_mask_increments_bits() {
        let d = deps_with();
        put(&d, "u");
        adjust_attribute(&d, AdjustAttributeRequest {
            uid: "u".into(),
            attribute_reference: "Cryptographic Usage Mask".into(),
            adjustment_type: AdjustmentType::Increment,
            adjustment_value: Some(UsageMask::SIGN.bits() as i64),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        let rec = d.store.get("u").unwrap().unwrap();
        assert!(rec.usage_mask.contains(UsageMask::ENCRYPT));
        assert!(rec.usage_mask.contains(UsageMask::SIGN));
    }

    // ── P2.4 — Circular Link Error (KMIP 3.0 §11, 0x4d) ─────────────

    /// A self-link (A → A) is the simplest cycle and must be rejected
    /// with `CircularLinkError`, not silently stored.
    #[test]
    fn add_self_link_returns_circular_link_error() {
        let d = deps_with();
        put(&d, "u");
        let err = add_attribute(&d, AddAttributeRequest {
            uid: "u".into(),
            new_attribute: Attribute::NextLink("u".into()),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::CircularLinkError);
        // The link must not have been committed.
        assert!(d.store.get("u").unwrap().unwrap().links.is_empty());
    }

    /// A direct reciprocal 2-cycle via a NON-inverse link type is a
    /// true cycle: B already NextLinks to A, so adding A NextLink B
    /// closes a same-relation loop → `CircularLinkError`.
    #[test]
    fn add_reciprocal_link_returns_circular_link_error() {
        let d = deps_with();
        put(&d, "a");
        put(&d, "b");
        // b → a via NextLink first (no cycle yet).
        add_attribute(&d, AddAttributeRequest {
            uid: "b".into(),
            new_attribute: Attribute::NextLink("a".into()),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        // a → b via NextLink now closes a same-type 2-cycle.
        let err = add_attribute(&d, AddAttributeRequest {
            uid: "a".into(),
            new_attribute: Attribute::NextLink("b".into()),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::CircularLinkError);
    }

    /// P2.1 correction: a reciprocal link via the spec INVERSE type is
    /// the legitimate back edge of a bidirectional relationship — NOT a
    /// cycle. This is the AX-M-1/2 pattern: A NextLink B, then B
    /// PreviousLink A. Both SHALL succeed (the original P2.4 heuristic
    /// wrongly rejected the second, breaking AX-M).
    #[test]
    fn add_inverse_reciprocal_link_pair_succeeds() {
        let d = deps_with();
        put(&d, "a");
        put(&d, "b");
        // a → b via NextLink (forward edge of the rotation chain).
        add_attribute(&d, AddAttributeRequest {
            uid: "a".into(),
            new_attribute: Attribute::NextLink("b".into()),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        // b → a via PreviousLink (the spec inverse — the back edge).
        add_attribute(&d, AddAttributeRequest {
            uid: "b".into(),
            new_attribute: Attribute::PreviousLink("a".into()),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        assert_eq!(
            d.store.get("b").unwrap().unwrap().links.get("PreviousLink").map(String::as_str),
            Some("a")
        );
        // PublicKeyLink ↔ PrivateKeyLink is likewise a valid inverse pair.
        put(&d, "pub");
        put(&d, "priv");
        add_attribute(&d, AddAttributeRequest {
            uid: "priv".into(),
            new_attribute: Attribute::PublicKeyLink("pub".into()),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        add_attribute(&d, AddAttributeRequest {
            uid: "pub".into(),
            new_attribute: Attribute::PrivateKeyLink("priv".into()),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
    }

    /// A non-cyclic link (A → B with no back-link) is accepted.
    #[test]
    fn add_acyclic_link_succeeds() {
        let d = deps_with();
        put(&d, "a");
        put(&d, "b");
        add_attribute(&d, AddAttributeRequest {
            uid: "a".into(),
            new_attribute: Attribute::NextLink("b".into()),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        assert_eq!(
            d.store.get("a").unwrap().unwrap().links.get("NextLink").map(String::as_str),
            Some("b")
        );
    }

    // ── Gap-remediation Phase B ─────────────────────────────────────────

    /// §4.18 Table 93 — `CryptographicParameters` is client-modifiable
    /// (unlike `CryptographicDomainParameters`, which is not). SetAttribute
    /// must persist it for real, not silently drop it.
    #[test]
    fn set_attribute_cryptographic_parameters_round_trips() {
        let d = deps_with();
        put(&d, "u");
        let cp = crate::kmip30::ops::CryptographicParameters {
            padding_method: Some(0x07), // OAEP
            ..Default::default()
        };
        set_attribute(&d, SetAttributeRequest {
            uid: "u".into(),
            new_attribute: Attribute::CryptographicParameters(cp.clone()),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        assert_eq!(
            d.store.get("u").unwrap().unwrap().cryptographic_parameters,
            Some(cp),
        );
    }

    /// §4.48 Table 148 — `ProtectionLevel` is client-modifiable.
    #[test]
    fn set_attribute_protection_level_round_trips() {
        let d = deps_with();
        put(&d, "u");
        set_attribute(&d, SetAttributeRequest {
            uid: "u".into(),
            new_attribute: Attribute::ProtectionLevel(1),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        assert_eq!(d.store.get("u").unwrap().unwrap().protection_level, Some(1));
    }

    /// §4.69 Table 90 — `UsageLimits` Total/Unit are client-modifiable
    /// *before* Get Usage Allocation has been performed.
    #[test]
    fn set_attribute_usage_limits_round_trips_before_allocation() {
        let d = deps_with();
        put(&d, "u");
        set_attribute(&d, SetAttributeRequest {
            uid: "u".into(),
            new_attribute: Attribute::UsageLimits { total: 500, count: None, unit: Some(1) },
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        let rec = d.store.get("u").unwrap().unwrap();
        assert_eq!(rec.usage_limits_total, Some(500));
        assert_eq!(rec.usage_limits_unit, Some(1));
    }

    /// §4.69 Table 90's guard condition — once Get Usage Allocation has
    /// granted at least one allocation, UsageLimits is no longer
    /// client-modifiable via SetAttribute or ModifyAttribute.
    #[test]
    fn set_and_modify_attribute_usage_limits_rejected_after_allocation() {
        let d = deps_with();
        put(&d, "u");
        let mut rec = d.store.get("u").unwrap().unwrap();
        rec.usage_limits_total = Some(1000);
        rec.usage_limits_remaining = Some(700); // Get Usage Allocation already ran.
        d.store.update(rec).unwrap();

        let err = set_attribute(&d, SetAttributeRequest {
            uid: "u".into(),
            new_attribute: Attribute::UsageLimits { total: 2000, count: None, unit: None },
        }, &crate::server::auth::AuthContext::open(), "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::InvalidField);

        let err = modify_attribute(&d, ModifyAttributeRequest {
            uid: "u".into(),
            current_attribute: None,
            new_attribute: Attribute::UsageLimits { total: 2000, count: None, unit: None },
        }, &crate::server::auth::AuthContext::open(), "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::InvalidField);

        // The stored value must be untouched by the rejected attempts.
        assert_eq!(d.store.get("u").unwrap().unwrap().usage_limits_total, Some(1000));
    }

    /// §4.16 Table 89 — `CryptographicDomainParameters` is Read-Only,
    /// distinct from the client-modifiable `CryptographicParameters`
    /// above; a first-pass draft of this fix conflated the two.
    #[test]
    fn set_attribute_cryptographic_domain_parameters_rejected_read_only() {
        let d = deps_with();
        put(&d, "u");
        let err = set_attribute(&d, SetAttributeRequest {
            uid: "u".into(),
            new_attribute: Attribute::CryptographicDomainParameters { qlength: None, recommended_curve: None },
        }, &crate::server::auth::AuthContext::open(), "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::InvalidField);
    }

    /// §4.50 — `ProtectionStorageMask` is Read-Only.
    #[test]
    fn set_attribute_protection_storage_mask_rejected_read_only() {
        let d = deps_with();
        put(&d, "u");
        let err = set_attribute(&d, SetAttributeRequest {
            uid: "u".into(),
            new_attribute: Attribute::ProtectionStorageMask(1),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::InvalidField);
    }

    /// §4.29 — `KeyFormatType` is Read-Only.
    #[test]
    fn set_attribute_key_format_type_rejected_read_only() {
        let d = deps_with();
        put(&d, "u");
        let err = set_attribute(&d, SetAttributeRequest {
            uid: "u".into(),
            new_attribute: Attribute::KeyFormatType(0x01), // Raw
        }, &crate::server::auth::AuthContext::open(), "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::InvalidField);
    }

    /// Tables 136/138/160/162 — the four Derivation/Replacement link
    /// types are client-modifiable, and (per `link_target`) still get
    /// real circular-link protection: a direct A→B / B→A cycle via the
    /// *same* link type (not the spec inverse) must be rejected.
    #[test]
    fn set_attribute_derivation_link_round_trips_and_detects_cycle() {
        let d = deps_with();
        put(&d, "a");
        put(&d, "b");
        set_attribute(&d, SetAttributeRequest {
            uid: "a".into(),
            new_attribute: Attribute::DerivationBaseObjectLink("b".into()),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        assert_eq!(
            d.store.get("a").unwrap().unwrap().links.get("DerivationBaseObjectLink").map(String::as_str),
            Some("b")
        );

        // b → a via the SAME (non-inverse) link type closes a true cycle.
        let err = set_attribute(&d, SetAttributeRequest {
            uid: "b".into(),
            new_attribute: Attribute::DerivationBaseObjectLink("a".into()),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::CircularLinkError);

        // b → a via the spec INVERSE (DerivedObjectLink) is the
        // legitimate back edge and must be accepted.
        set_attribute(&d, SetAttributeRequest {
            uid: "b".into(),
            new_attribute: Attribute::DerivedObjectLink("a".into()),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        assert_eq!(
            d.store.get("b").unwrap().unwrap().links.get("DerivedObjectLink").map(String::as_str),
            Some("a")
        );
    }

    // ── Gap-remediation Phase B/T3 — DeleteAttribute's independent path ─

    /// Before this fix, `attribute_present`'s catch-all unconditionally
    /// claimed `ProtectionLevel`/`CryptographicParameters`/`UsageLimits`
    /// were already present, so the very first `AddAttribute` for any of
    /// them wrongly failed with `AttributeSingleValued` on a fresh
    /// object that had never had the value set.
    #[test]
    fn add_attribute_protection_level_succeeds_on_fresh_object() {
        let d = deps_with();
        put(&d, "u");
        add_attribute(&d, AddAttributeRequest {
            uid: "u".into(),
            new_attribute: Attribute::ProtectionLevel(1),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        assert_eq!(d.store.get("u").unwrap().unwrap().protection_level, Some(1));
    }

    /// Same class of gap for a Link type's first-time `AddAttribute`.
    #[test]
    fn add_attribute_derivation_link_succeeds_on_fresh_object() {
        let d = deps_with();
        put(&d, "a");
        put(&d, "b");
        add_attribute(&d, AddAttributeRequest {
            uid: "a".into(),
            new_attribute: Attribute::DerivationBaseObjectLink("b".into()),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        assert_eq!(
            d.store.get("a").unwrap().unwrap().links.get("DerivationBaseObjectLink").map(String::as_str),
            Some("b")
        );
    }

    /// `DeleteAttribute` by `current_attribute` value must actually clear
    /// `ProtectionLevel`/`CryptographicParameters`/`UsageLimits` and every
    /// Link type — before this fix `remove_attribute_by_value` had no
    /// arms for any of them and silently no-op'd.
    #[test]
    fn delete_attribute_by_value_clears_settable_attributes_and_links() {
        let d = deps_with();
        put(&d, "u");
        set_attribute(&d, SetAttributeRequest {
            uid: "u".into(), new_attribute: Attribute::ProtectionLevel(2),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        delete_attribute(&d, DeleteAttributeRequest {
            uid: "u".into(),
            current_attribute: Some(Attribute::ProtectionLevel(2)),
            attribute_reference: None,
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        assert_eq!(d.store.get("u").unwrap().unwrap().protection_level, None);

        put(&d, "a");
        put(&d, "b");
        set_attribute(&d, SetAttributeRequest {
            uid: "a".into(), new_attribute: Attribute::NextLink("b".into()),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        delete_attribute(&d, DeleteAttributeRequest {
            uid: "a".into(),
            current_attribute: Some(Attribute::NextLink("b".into())),
            attribute_reference: None,
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        assert!(d.store.get("a").unwrap().unwrap().links.get("NextLink").is_none());
    }

    /// `DeleteAttribute` by `attribute_reference` name for a Link type —
    /// before this fix, `attribute_name_present`'s catch-all compared the
    /// raw decoded reference name (spec-cased with a space, e.g. "Next
    /// Link") against `obj.links`' no-space keys ("NextLink"), so this
    /// always spuriously returned `ItemNotFound`.
    #[test]
    fn delete_attribute_by_name_finds_and_clears_link() {
        let d = deps_with();
        put(&d, "a");
        put(&d, "b");
        set_attribute(&d, SetAttributeRequest {
            uid: "a".into(), new_attribute: Attribute::NextLink("b".into()),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        // Simulates the space-cased name `tag_name_from_code` decodes.
        delete_attribute(&d, DeleteAttributeRequest {
            uid: "a".into(),
            current_attribute: None,
            attribute_reference: Some("Next Link".into()),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        assert!(d.store.get("a").unwrap().unwrap().links.get("NextLink").is_none());
    }

    /// `DeleteAttribute` by `attribute_reference` name for `UsageLimits`
    /// — before this fix the generic fallback arm only cleared
    /// `custom_attributes`/`links`, so this silently no-op'd.
    #[test]
    fn delete_attribute_by_name_clears_usage_limits() {
        let d = deps_with();
        put(&d, "u");
        set_attribute(&d, SetAttributeRequest {
            uid: "u".into(),
            new_attribute: Attribute::UsageLimits { total: 100, count: None, unit: Some(1) },
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        delete_attribute(&d, DeleteAttributeRequest {
            uid: "u".into(),
            current_attribute: None,
            attribute_reference: Some("Usage Limits".into()),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        assert_eq!(d.store.get("u").unwrap().unwrap().usage_limits_total, None);
    }

    /// §4.69 Table 90 — "Deletable by client: Yes, as long as Get Usage
    /// Allocation has not been performed": once locked, DeleteAttribute
    /// must reject both the by-value and by-name forms.
    #[test]
    fn delete_attribute_usage_limits_rejected_after_allocation() {
        let d = deps_with();
        put(&d, "u");
        let mut rec = d.store.get("u").unwrap().unwrap();
        rec.usage_limits_total = Some(1000);
        rec.usage_limits_remaining = Some(700);
        d.store.update(rec).unwrap();

        let err = delete_attribute(&d, DeleteAttributeRequest {
            uid: "u".into(),
            current_attribute: Some(Attribute::UsageLimits { total: 1000, count: None, unit: None }),
            attribute_reference: None,
        }, &crate::server::auth::AuthContext::open(), "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::InvalidField);

        let err = delete_attribute(&d, DeleteAttributeRequest {
            uid: "u".into(),
            current_attribute: None,
            attribute_reference: Some("Usage Limits".into()),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::InvalidField);

        assert_eq!(d.store.get("u").unwrap().unwrap().usage_limits_total, Some(1000));
    }
}
