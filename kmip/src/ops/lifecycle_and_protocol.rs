//! KMIP 3.0 Group D (lifecycle: Deactivate / Check / Archive / Recover /
//! Obliterate) + leftover Group A (DiscoverVersions / Ping).
//!
//! Spec mapping:
//!
//! - Deactivate       §6.1.14 — Active → Deactivated, set Deactivation Date
//! - Check            §6.1.7  — policy gate; v0.1 always allows
//! - Archive          §6.1.4  — move object to Archival storage (K22: real)
//! - Recover          §6.1.47 — move object back On-line
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
        fail_err(deps, correlation_id, "Deactivate", KmipError::object_not_found(&req.uid))
    })?;

    // Per §6.1.14: only `Active` may transition to `Deactivated`. Other
    // source states are §6.1.14 Error Handling → `WrongKeyLifecycleState`
    // (0x43).
    if obj.state != State::Active {
        return Err(fail_err(deps, correlation_id, "Deactivate",
            super::helpers::non_active_state_error(&req.uid, obj.state)));
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

    // Per §6.1.14: Deactivation Date is set to the current date and
    // time. Last Change Date follows automatically per profile §5.1.2.
    let now = OffsetDateTime::now_utc();
    obj.state = State::Deactivated;
    obj.deactivation_date = Some(now);
    obj.last_change_date = Some(now);
    if let Some(code) = req.deactivation_reason.map(|r| r.to_wire_value()) {
        obj.deactivation_reason_code = Some(code);
    }
    deps.store.update(obj)?;
    emit_success(deps, correlation_id, "Deactivate");
    Ok(DeactivateResponse { uid: req.uid })
}

// ── Check ──────────────────────────────────────────────────────────────────

pub fn check(deps: &Deps, req: CheckRequest, correlation_id: &str) -> Result<CheckResponse> {
    emit_request(deps, correlation_id, "Check", format!("uid={}", req.uid));

    let obj = deps.store.get(&req.uid)?.ok_or_else(|| {
        fail_err(deps, correlation_id, "Check", KmipError::object_not_found(&req.uid))
    })?;

    // Per §6.1.7: server validates the requested usage parameters against
    // the object's attributes + policy. v0.1 always allows (no Usage
    // Limits, no Lease Time enforcement). The Cryptographic Usage Mask
    // check would deny if requested bits are not present in the object's
    // mask — we honour that since it's a direct spec mandate.
    if let Some(requested) = req.cryptographic_usage_mask {
        let have = obj.usage_mask.bits();
        if requested & have != requested {
            // KMIP 3.0 §11 — the spec-specific reason is
            // `IncompatibleCryptographicUsageMask` (0x29), distinct
            // from the generic `PermissionDenied`. OASIS BL-M-2 msg
            // #2 pins this code on the Check that triggers its Undo
            // wave.
            return Err(fail_err(deps, correlation_id, "Check",
                KmipError::failed(
                    crate::error::ResultReason::IncompatibleCryptographicUsageMask,
                    format!(
                        "Cryptographic Usage Mask {:#x} not all permitted by object's {:#x}",
                        requested, have
                    ),
                )));
        }
    }

    emit_success(deps, correlation_id, "Check");
    Ok(CheckResponse { uid: req.uid })
}

// ── Archive ────────────────────────────────────────────────────────────────

pub fn archive(deps: &Deps, req: ArchiveRequest, correlation_id: &str) -> Result<ArchiveResponse> {
    emit_request(deps, correlation_id, "Archive", format!("uid={}", req.uid));
    let mut obj = deps.store.get(&req.uid)?.ok_or_else(|| {
        fail_err(deps, correlation_id, "Archive", KmipError::object_not_found(&req.uid))
    })?;

    // §6.1.4.1 Error Handling – Archive lists `Object Archived` as a
    // returnable reason: archiving an already-archived object fails
    // with 0x0d (§11: "The object SHALL be recovered from the archive
    // before performing the operation"). NOT idempotent per the table.
    if obj.archived {
        return Err(fail_err(deps, correlation_id, "Archive",
            KmipError::object_archived(&req.uid)));
    }

    // Per §6.1.4: "This request is only an indication from a client
    // that, from its point of view, the key management system MAY
    // archive the object." K22: this server's policy is to honour the
    // indication immediately — the record moves to Archival storage
    // (§12.3 mask bit 0x02) and the material goes off-line until
    // Recover (§6.1.47). No lifecycle-state precondition: the
    // §6.1.4.1 error table lists neither `Object Destroyed` nor
    // `Wrong Key Lifecycle State`, so any stored object (including
    // Destroyed tombstones) may be archived.
    obj.archived = true;
    obj.last_change_date = Some(OffsetDateTime::now_utc());
    deps.store.update(obj)?;
    emit_success(deps, correlation_id, "Archive");
    Ok(ArchiveResponse { uid: req.uid })
}

// ── Recover ────────────────────────────────────────────────────────────────

pub fn recover(deps: &Deps, req: RecoverRequest, correlation_id: &str) -> Result<RecoverResponse> {
    emit_request(deps, correlation_id, "Recover", format!("uid={}", req.uid));
    let mut obj = deps.store.get(&req.uid)?.ok_or_else(|| {
        fail_err(deps, correlation_id, "Recover", KmipError::object_not_found(&req.uid))
    })?;

    // Per §6.1.47: "This operation is used to obtain access to a
    // Managed Object that has been archived. … Once the response is
    // received, the object is now on-line, and MAY be obtained (e.g.,
    // via a Get operation)." Recover of an already-on-line object is
    // idempotent success: the §6.1.47.1 error table lists no
    // applicable reason (only Object Not Found + generics), and the
    // postcondition — "the object is now on-line" — already holds.
    if obj.archived {
        obj.archived = false;
        obj.last_change_date = Some(OffsetDateTime::now_utc());
        deps.store.update(obj)?;
    }
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
        fail_err(deps, correlation_id, "Obliterate", KmipError::object_not_found(&req.uid))
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
        ..ObjectRecord::default()
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
        assert_eq!(err.result_reason(), crate::error::ResultReason::WrongKeyLifecycleState);
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
        // KMIP 3.0 §11: the spec-specific reason is
        // `IncompatibleCryptographicUsageMask` (0x29), not the
        // generic `PermissionDenied` — the original assertion was
        // wrong. OASIS BL-M-2 msg #2 pins the corrected behaviour.
        assert_eq!(
            err.result_reason(),
            crate::error::ResultReason::IncompatibleCryptographicUsageMask,
        );
    }

    /// K22 — §6.1.4: Archive moves the record to Archival storage and
    /// stamps Last Change Date.
    #[test]
    fn archive_marks_record_archival() {
        let d = deps_with();
        put(&d, "u", State::Active);
        let r = archive(&d, ArchiveRequest { uid: "u".into() }, "c").unwrap();
        assert_eq!(r.uid, "u");
        let rec = d.store.get("u").unwrap().unwrap();
        assert!(rec.archived);
        assert!(rec.last_change_date.is_some());
    }

    /// K22 — §6.1.4.1 error table lists `Object Archived`: archiving
    /// an already-archived object fails with 0x0d (not idempotent).
    #[test]
    fn archive_of_archived_object_fails_object_archived() {
        let d = deps_with();
        put(&d, "u", State::Active);
        archive(&d, ArchiveRequest { uid: "u".into() }, "c").unwrap();
        let err = archive(&d, ArchiveRequest { uid: "u".into() }, "c").unwrap_err();
        assert_eq!(err.result_reason(), crate::error::ResultReason::ObjectArchived);
    }

    /// K22 — §6.1.4.1 lists neither `Object Destroyed` nor `Wrong Key
    /// Lifecycle State`: Archive of a Destroyed tombstone succeeds.
    #[test]
    fn archive_of_destroyed_object_succeeds() {
        let d = deps_with();
        put(&d, "u", State::Destroyed);
        assert!(archive(&d, ArchiveRequest { uid: "u".into() }, "c").is_ok());
        assert!(d.store.get("u").unwrap().unwrap().archived);
    }

    /// K22 — §6.1.47: "Once the response is received, the object is
    /// now on-line" — Recover flips the record back.
    #[test]
    fn recover_restores_online_storage() {
        let d = deps_with();
        put(&d, "u", State::Active);
        archive(&d, ArchiveRequest { uid: "u".into() }, "c").unwrap();
        let r = recover(&d, RecoverRequest { uid: "u".into() }, "c").unwrap();
        assert_eq!(r.uid, "u");
        assert!(!d.store.get("u").unwrap().unwrap().archived);
    }

    /// K22 — §6.1.47.1 error table has no reason for "already
    /// on-line", and the postcondition already holds → idempotent
    /// success.
    #[test]
    fn recover_of_online_object_is_idempotent_success() {
        let d = deps_with();
        put(&d, "u", State::Active);
        assert!(recover(&d, RecoverRequest { uid: "u".into() }, "c").is_ok());
        assert!(!d.store.get("u").unwrap().unwrap().archived);
    }

    /// K2 — UID validation kept: Archive/Recover of a missing UID is
    /// `ObjectNotFound` per both error tables.
    #[test]
    fn archive_and_recover_unknown_uid_fail_object_not_found() {
        let d = deps_with();
        let e = archive(&d, ArchiveRequest { uid: "nope".into() }, "c").unwrap_err();
        assert_eq!(e.result_reason(), crate::error::ResultReason::ObjectNotFound);
        let e = recover(&d, RecoverRequest { uid: "nope".into() }, "c").unwrap_err();
        assert_eq!(e.result_reason(), crate::error::ResultReason::ObjectNotFound);
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
