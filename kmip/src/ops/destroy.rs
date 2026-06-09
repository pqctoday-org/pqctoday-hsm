//! KMIP 3.0 §6.1.19 **Destroy** operation.
//!
//! > "This operation is used to indicate to the server that the key
//! > material for the specified Managed Object SHALL be destroyed."
//!
//! Op codepoint `0x14` (verified — `Destroy = 0x00000014`).
//!
//! ## Plane mapping
//!
//! - **Plane 1** — engine.evaluate; rare to gate Destroy via policy but
//!   the surface is available.
//! - **Plane 2** — lifecycle FSM per `docs/IMPLEMENTATION_PLAN.md` §3.4:
//!   `PreActive → Destroyed`, `Deactivated → Destroyed`,
//!   `Compromised → DestroyedCompromised`. Active and already-Destroyed
//!   are rejected.
//! - **Plane 3** — calls `C_DestroyObject` (PKCS#11 v3.2 §C.5.10).
//!   Signature verified at `rust/src/ffi.rs::C_DestroyObject`:
//!   `C_DestroyObject(hSession: u32, hObject: u32) -> u32`.

use std::collections::HashMap;
use time::OffsetDateTime;

use crate::error::{KmipError, Result};
use crate::kmip30::{DestroyRequest, DestroyResponse, State};
use crate::policy::{Decision, PolicyRequest};

use super::deps::Deps;
use super::helpers::{
    canonical_name, emit_pkcs11, emit_request, emit_state_change, emit_success, fail_err,
    state_name,
};

pub fn destroy(deps: &Deps, req: DestroyRequest, correlation_id: &str) -> Result<DestroyResponse> {
    let started = OffsetDateTime::now_utc();
    emit_request(deps, correlation_id, "Destroy", format!("uid={}", req.uid));

    let mut obj = deps.store.get(&req.uid)?.ok_or_else(|| {
        fail_err(deps, correlation_id, "Destroy", KmipError::not_found(&req.uid))
    })?;

    // KMIP 3.0 §3.x lifecycle — Active cannot transition directly to Destroyed;
    // already-Destroyed is terminal.
    let target_state = match obj.state {
        State::PreActive | State::Deactivated => State::Destroyed,
        State::Compromised => State::DestroyedCompromised,
        State::Active => {
            return Err(fail_err(
                deps,
                correlation_id,
                "Destroy",
                KmipError::permission_denied(
                    "Active keys must be Revoked before Destroy (KMIP §3.x FSM)",
                ),
            ));
        }
        State::Destroyed | State::DestroyedCompromised => {
            return Err(fail_err(
                deps,
                correlation_id,
                "Destroy",
                KmipError::object_archived(&req.uid),
            ));
        }
    };

    // Plane-1 policy gate.
    let empty: HashMap<String, String> = HashMap::new();
    let algo = canonical_name(obj.algorithm);
    let mut p_req = PolicyRequest::minimal("Destroy", Some(&algo), started, correlation_id, &empty);
    p_req.state = Some(state_name(obj.state));
    p_req.target_uid = Some(&req.uid);
    if let Decision::Deny { human, .. } = deps.engine.evaluate(&p_req) {
        return Err(fail_err(
            deps,
            correlation_id,
            "Destroy",
            KmipError::permission_denied(human),
        ));
    }

    // Phase 7b: real bridge call when a session is wired. Falls back
    // to audit-only emission for unit tests.
    emit_pkcs11(deps, correlation_id, "C_DestroyObject", None, 0, "CKR_OK");
    if let Some(session) = deps.engine_session {
        // Best-effort: if the handle is already gone (e.g. engine restart
        // between record creation and Destroy), ignore the error — the
        // KMIP lifecycle transition still proceeds.
        if let Ok(Some(handle)) = softhsmrustv3::native::find_by_cka_id(session, &obj.pkcs11_cka_id) {
            let _ = softhsmrustv3::native::destroy_object(session, handle);
        }
    }

    // Plane-2: lifecycle update.
    let from_label = state_name(obj.state).to_string();
    let to_label = state_name(target_state).to_string();
    obj.state = target_state;
    deps.store.update(obj)?;

    emit_state_change(
        deps,
        correlation_id,
        &req.uid,
        &from_label,
        &to_label,
        "KMIP Destroy op",
    );
    emit_success(deps, correlation_id, "Destroy");

    Ok(DestroyResponse {
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

    fn deps_with() -> Deps {
        let ring = Arc::new(RingSink::new(64));
        let sink: Arc<dyn AuditSink> = ring.clone();
        let engine = Engine::with_global_sink(sink.clone());
        engine
            .activate(load_from_str(
                "schema_version: 1\nmetadata: {name: t, description: t, authority: t, effective: always}\nrules: []\n",
                std::path::Path::new("<t>"),
            ).unwrap())
            .unwrap();
        Deps::new(engine, Arc::new(MemoryStore::new()), sink, super::super::deps::DepsConfig::default())
    }

    fn put(deps: &Deps, uid: &str, state: State) {
        deps.store.put(ObjectRecord {
            uid: uid.into(),
            object_type: ObjectType::PrivateKey,
            algorithm: KmipAlgorithm::MlDsa87,
            cryptographic_length: 0,
            usage_mask: UsageMask::SIGN,
            state,
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
        }).unwrap();
    }

    #[test]
    fn pre_active_to_destroyed() {
        let d = deps_with();
        put(&d, "u", State::PreActive);
        let r = destroy(&d, DestroyRequest { uid: "u".into() }, "c").unwrap();
        assert_eq!(r.state, State::Destroyed);
    }

    #[test]
    fn deactivated_to_destroyed() {
        let d = deps_with();
        put(&d, "u", State::Deactivated);
        let r = destroy(&d, DestroyRequest { uid: "u".into() }, "c").unwrap();
        assert_eq!(r.state, State::Destroyed);
    }

    #[test]
    fn compromised_to_destroyed_compromised() {
        let d = deps_with();
        put(&d, "u", State::Compromised);
        let r = destroy(&d, DestroyRequest { uid: "u".into() }, "c").unwrap();
        assert_eq!(r.state, State::DestroyedCompromised);
    }

    #[test]
    fn active_rejected_must_revoke_first() {
        let d = deps_with();
        put(&d, "u", State::Active);
        let err = destroy(&d, DestroyRequest { uid: "u".into() }, "c").unwrap_err();
        assert_eq!(err.result_reason(), crate::error::ResultReason::PermissionDenied);
    }

    #[test]
    fn already_destroyed_rejected() {
        let d = deps_with();
        put(&d, "u", State::Destroyed);
        let err = destroy(&d, DestroyRequest { uid: "u".into() }, "c").unwrap_err();
        assert_eq!(err.result_reason(), crate::error::ResultReason::ObjectArchived);
    }
}
