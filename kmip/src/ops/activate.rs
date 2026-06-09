//! KMIP 3.0 §6.1.1 **Activate** operation.
//!
//! > "This operation requests the server to activate a Managed
//! > Cryptographic Object."
//!
//! Op codepoint `0x12` (verified — `Activate = 0x00000012` in
//! `kmip-spec-3.0-tags-enums.json`).
//!
//! ## Plane mapping
//!
//! - **Plane 1** — engine.evaluate with op=`"Activate"`. Policies typically
//!   do not gate Activate (no algorithm choice is being made), but the
//!   rule surface is available if needed.
//! - **Plane 2** — lifecycle FSM transition `PreActive → Active`
//!   (`docs/IMPLEMENTATION_PLAN.md` §3.4). Any other source state is
//!   rejected with `PermissionDenied`.
//! - **Plane 3** — none. Activation is a KMIP-only concept; PKCS#11
//!   has no equivalent op.

use std::collections::HashMap;
use time::OffsetDateTime;

use crate::error::{KmipError, Result};
use crate::kmip30::{ActivateRequest, ActivateResponse, State};
use crate::policy::{Decision, PolicyRequest};

use super::deps::Deps;
use super::helpers::{
    canonical_name, emit_request, emit_state_change, emit_success, fail_err, state_name,
};

pub fn activate(deps: &Deps, req: ActivateRequest, correlation_id: &str) -> Result<ActivateResponse> {
    let started = OffsetDateTime::now_utc();
    emit_request(deps, correlation_id, "Activate", format!("uid={}", req.uid));

    let mut obj = deps
        .store
        .get(&req.uid)?
        .ok_or_else(|| fail_err(deps, correlation_id, "Activate", KmipError::not_found(&req.uid)))?;

    // KMIP 3.0 §3.x — Activate is only valid from PreActive.
    if obj.state != State::PreActive {
        return Err(fail_err(
            deps,
            correlation_id,
            "Activate",
            KmipError::permission_denied(format!(
                "Activate requires PreActive; UID {} is in {:?}",
                req.uid, obj.state
            )),
        ));
    }

    // Plane-1 policy gate.
    let empty: HashMap<String, String> = HashMap::new();
    let algo = canonical_name(obj.algorithm);
    let mut p_req = PolicyRequest::minimal(
        "Activate",
        Some(&algo),
        started,
        correlation_id,
        &empty,
    );
    p_req.state = Some(state_name(obj.state));
    p_req.target_uid = Some(&req.uid);
    if let Decision::Deny { human, .. } = deps.engine.evaluate(&p_req) {
        return Err(fail_err(
            deps,
            correlation_id,
            "Activate",
            KmipError::permission_denied(human),
        ));
    }

    // Lifecycle transition. Last Change Date follows per Baseline §5.1.2.
    let now = OffsetDateTime::now_utc();
    obj.state = State::Active;
    obj.activation_date = Some(now);
    obj.last_change_date = Some(now);
    deps.store.update(obj.clone())?;
    emit_state_change(
        deps,
        correlation_id,
        &req.uid,
        "PreActive",
        "Active",
        "KMIP Activate op",
    );
    emit_success(deps, correlation_id, "Activate");

    Ok(ActivateResponse {
        uid: req.uid,
        state: State::Active,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditlog::{AuditSink, Plane, RingSink};
    use crate::kmip30::{KmipAlgorithm, ObjectType, UsageMask};
    use crate::policy::{load_from_str, Engine};
    use crate::store::{MemoryStore, ObjectRecord};
    use std::sync::Arc;

    fn deps_with(yaml: &str) -> (Arc<RingSink>, Deps) {
        let ring = Arc::new(RingSink::new(64));
        let sink: Arc<dyn AuditSink> = ring.clone();
        let engine = Engine::with_global_sink(sink.clone());
        engine.activate(load_from_str(yaml, std::path::Path::new("<t>")).unwrap()).unwrap();
        (
            ring,
            Deps::new(engine, Arc::new(MemoryStore::new()), sink, super::super::deps::DepsConfig::default()),
        )
    }

    fn pre_active(deps: &Deps, uid: &str) {
        deps.store.put(ObjectRecord {
            uid: uid.into(),
            object_type: ObjectType::PrivateKey,
            algorithm: KmipAlgorithm::MlDsa87,
            cryptographic_length: 0,
            usage_mask: UsageMask::SIGN | UsageMask::VERIFY,
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
    }

    const ALLOW_ALL: &str = "schema_version: 1\nmetadata: {name: t, description: t, authority: t, effective: always}\nrules: []\n";

    #[test]
    fn activates_pre_active_to_active() {
        let (ring, d) = deps_with(ALLOW_ALL);
        pre_active(&d, "urn:u");
        let resp = activate(&d, ActivateRequest { uid: "urn:u".into() }, "c").unwrap();
        assert_eq!(resp.state, State::Active);
        assert_eq!(d.store.get("urn:u").unwrap().unwrap().state, State::Active);
        // Audit: 1 ObjectStateChanged event recorded.
        let p2 = ring.filter_plane(Plane::Kmip);
        assert!(p2.iter().any(|e| matches!(e.event, crate::auditlog::EventPayload::KmipObjectStateChanged { .. })));
    }

    #[test]
    fn rejects_non_pre_active() {
        let (_ring, d) = deps_with(ALLOW_ALL);
        // Insert an already-Active record.
        d.store.put(ObjectRecord {
            uid: "urn:a".into(),
            object_type: ObjectType::PrivateKey,
            algorithm: KmipAlgorithm::MlDsa87,
            cryptographic_length: 0,
            usage_mask: UsageMask::SIGN,
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
        let err = activate(&d, ActivateRequest { uid: "urn:a".into() }, "c").unwrap_err();
        assert_eq!(err.result_reason(), crate::error::ResultReason::PermissionDenied);
    }

    #[test]
    fn missing_uid_returns_item_not_found() {
        let (_ring, d) = deps_with(ALLOW_ALL);
        let err = activate(&d, ActivateRequest { uid: "ghost".into() }, "c").unwrap_err();
        assert_eq!(err.result_reason(), crate::error::ResultReason::ItemNotFound);
    }
}
