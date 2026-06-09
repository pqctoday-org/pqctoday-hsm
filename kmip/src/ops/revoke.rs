//! KMIP 3.0 §6.1.49 **Revoke** operation.
//!
//! > "This operation requests the server to revoke a Managed Cryptographic
//! > Object or an Opaque Object."
//!
//! Op codepoint `0x13` (verified — `Revoke = 0x00000013` in
//! `kmip-spec-3.0-tags-enums.json`).
//!
//! ## Plane mapping
//!
//! - **Plane 1** — engine.evaluate; policies can deny Revoke on certain
//!   algorithm classes or require attribute predicates.
//! - **Plane 2** — lifecycle FSM (per `docs/IMPLEMENTATION_PLAN.md` §3.4):
//!   `Active → Deactivated` (default) or `Active → Compromised` (when
//!   `revocation_reason ∈ { KeyCompromise, CaCompromise }`). Other source
//!   states rejected with `PermissionDenied`.
//! - **Plane 3** — none. Revoke is a KMIP-only concept; PKCS#11 has no
//!   equivalent op.

use std::collections::HashMap;
use time::OffsetDateTime;

use crate::error::{KmipError, Result};
use crate::kmip30::{RevocationReason, RevokeRequest, RevokeResponse, State};
use crate::policy::{Decision, PolicyRequest};

use super::deps::Deps;
use super::helpers::{
    canonical_name, emit_request, emit_state_change, emit_success, fail_err, state_name,
};

pub fn revoke(deps: &Deps, req: RevokeRequest, correlation_id: &str) -> Result<RevokeResponse> {
    let started = OffsetDateTime::now_utc();
    emit_request(
        deps,
        correlation_id,
        "Revoke",
        format!("uid={} reason={:?}", req.uid, req.reason),
    );

    let mut obj = deps
        .store
        .get(&req.uid)?
        .ok_or_else(|| fail_err(deps, correlation_id, "Revoke", KmipError::not_found(&req.uid)))?;

    // KMIP 3.0 §3.x — Revoke is only valid from Active.
    if obj.state != State::Active {
        return Err(fail_err(
            deps,
            correlation_id,
            "Revoke",
            KmipError::permission_denied(format!(
                "Revoke requires Active; UID {} is in {:?}",
                req.uid, obj.state
            )),
        ));
    }

    // Plane-1 policy gate.
    let empty: HashMap<String, String> = HashMap::new();
    let algo = canonical_name(obj.algorithm);
    let mut p_req = PolicyRequest::minimal("Revoke", Some(&algo), started, correlation_id, &empty);
    p_req.state = Some(state_name(obj.state));
    p_req.target_uid = Some(&req.uid);
    if let Decision::Deny { human, .. } = deps.engine.evaluate(&p_req) {
        return Err(fail_err(
            deps,
            correlation_id,
            "Revoke",
            KmipError::permission_denied(human),
        ));
    }

    // Lifecycle transition. KeyCompromise / CaCompromise → Compromised;
    // every other RevocationReason → Deactivated.
    let target_state = match req.reason {
        RevocationReason::KeyCompromise | RevocationReason::CaCompromise => State::Compromised,
        _ => State::Deactivated,
    };
    let from_label = state_name(obj.state).to_string();
    let to_label = state_name(target_state).to_string();
    obj.state = target_state;
    // Per Baseline §5.1.2: Compromise Date / Compromise Occurrence Date
    // become attribute-visible when Revoke moves the object into the
    // Compromised state. Last Change Date follows any state change.
    let now = OffsetDateTime::now_utc();
    obj.last_change_date = Some(now);
    if target_state == State::Compromised {
        obj.compromise_date = Some(now);
        obj.compromise_occurrence_date = Some(now);
    }
    obj.revocation_reason_code = Some(req.reason.to_wire_value());
    deps.store.update(obj)?;

    emit_state_change(
        deps,
        correlation_id,
        &req.uid,
        &from_label,
        &to_label,
        &format!("KMIP Revoke op (reason {:?})", req.reason),
    );
    emit_success(deps, correlation_id, "Revoke");

    Ok(RevokeResponse {
        uid: req.uid,
        state: target_state,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditlog::{AuditSink, RingSink};
    use crate::kmip30::{KmipAlgorithm, ObjectType, UsageMask};
    use crate::policy::{load_from_str, Engine};
    use crate::store::{MemoryStore, ObjectRecord};
    use std::sync::Arc;

    fn deps_with(yaml: &str) -> Deps {
        let ring = Arc::new(RingSink::new(64));
        let sink: Arc<dyn AuditSink> = ring.clone();
        let engine = Engine::with_global_sink(sink.clone());
        engine.activate(load_from_str(yaml, std::path::Path::new("<t>")).unwrap()).unwrap();
        Deps::new(engine, Arc::new(MemoryStore::new()), sink, super::super::deps::DepsConfig::default())
    }

    fn active(deps: &Deps, uid: &str) {
        deps.store.put(ObjectRecord {
            uid: uid.into(),
            object_type: ObjectType::PrivateKey,
            algorithm: KmipAlgorithm::MlDsa87,
            cryptographic_length: 0,
            usage_mask: UsageMask::SIGN | UsageMask::VERIFY,
            state: State::Active,
            pkcs11_cka_id: vec![],
            pkcs11_slot: 0,
            initial_date: OffsetDateTime::UNIX_EPOCH,
            activation_date: Some(OffsetDateTime::UNIX_EPOCH),
            supersedes: None,
            name: None,

            links: std::collections::HashMap::new(),

            custom_attributes: std::collections::HashMap::new(),


            key_material: None,


            key_format_type: None,
        ..ObjectRecord::default()
}).unwrap();
    }

    const ALLOW: &str = "schema_version: 1\nmetadata: {name: t, description: t, authority: t, effective: always}\nrules: []\n";

    #[test]
    fn unspecified_reason_yields_deactivated() {
        let d = deps_with(ALLOW);
        active(&d, "u");
        let resp = revoke(&d, RevokeRequest { uid: "u".into(), reason: RevocationReason::Unspecified }, "c").unwrap();
        assert_eq!(resp.state, State::Deactivated);
    }

    #[test]
    fn key_compromise_yields_compromised() {
        let d = deps_with(ALLOW);
        active(&d, "u2");
        let resp = revoke(&d, RevokeRequest { uid: "u2".into(), reason: RevocationReason::KeyCompromise }, "c").unwrap();
        assert_eq!(resp.state, State::Compromised);
    }

    #[test]
    fn revoke_from_pre_active_rejected() {
        let d = deps_with(ALLOW);
        d.store.put(ObjectRecord {
            uid: "p".into(),
            object_type: ObjectType::PrivateKey,
            algorithm: KmipAlgorithm::MlDsa87,
            cryptographic_length: 0,
            usage_mask: UsageMask::SIGN,
            state: State::PreActive,
            pkcs11_cka_id: vec![],
            pkcs11_slot: 0,
            initial_date: OffsetDateTime::UNIX_EPOCH,
            activation_date: None,
            supersedes: None,
            name: None,

            links: std::collections::HashMap::new(),

            custom_attributes: std::collections::HashMap::new(),


            key_material: None,


            key_format_type: None,
        ..ObjectRecord::default()
}).unwrap();
        let err = revoke(&d, RevokeRequest { uid: "p".into(), reason: RevocationReason::Unspecified }, "c").unwrap_err();
        assert_eq!(err.result_reason(), crate::error::ResultReason::PermissionDenied);
    }
}
