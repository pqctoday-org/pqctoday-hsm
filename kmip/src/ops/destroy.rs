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
use zeroize::Zeroize;

use crate::error::{KmipError, Result};
use crate::kmip30::{DestroyRequest, DestroyResponse, State};
use crate::policy::{Decision, PolicyRequest};

use super::deps::Deps;
use super::helpers::{
    canonical_name, emit_request, emit_state_change, emit_success, fail_err,
    state_name,
};

pub fn destroy(deps: &Deps, req: DestroyRequest, correlation_id: &str) -> Result<DestroyResponse> {
    let started = OffsetDateTime::now_utc();
    emit_request(deps, correlation_id, "Destroy", format!("uid={}", req.uid));

    let mut obj = deps.store.get(&req.uid)?.ok_or_else(|| {
        fail_err(deps, correlation_id, "Destroy", KmipError::object_not_found(&req.uid))
    })?;

    // KMIP 3.0 §3.x lifecycle — Active cannot transition directly to Destroyed;
    // already-Destroyed is terminal.
    let target_state = match obj.state {
        State::PreActive | State::Deactivated => State::Destroyed,
        State::Compromised => State::DestroyedCompromised,
        State::Active => {
            // KMIP 3.0 §11 — `WrongKeyLifecycleState` (0x43) is the
            // spec-specific reason for an op rejected by the §3.x
            // FSM. AKLC-M-2 msg #5 pins this code. PermissionDenied
            // (0x0c) is reserved for policy-engine denials.
            return Err(fail_err(
                deps,
                correlation_id,
                "Destroy",
                super::helpers::non_active_state_error(&req.uid, obj.state),
            ));
        }
        State::Destroyed | State::DestroyedCompromised => {
            // KMIP 3.0 §11 — `ObjectDestroyed` (0x36) is the precise
            // reason for Destroy against an already-destroyed object.
            return Err(fail_err(
                deps,
                correlation_id,
                "Destroy",
                KmipError::object_destroyed(&req.uid),
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

    // Phase 7b: real bridge call when a session is wired. K15 — the
    // audit record is emitted after the call with its real rv; when no
    // engine call happens (no session / handle already gone) no
    // `Pkcs11Call` record is fabricated.
    if let Some(session) = deps.engine_session {
        // Best-effort: if the handle is already gone (e.g. engine restart
        // between record creation and Destroy), ignore the error — the
        // KMIP lifecycle transition still proceeds.
        if let Ok(Some(handle)) = softhsmrustv3::native::find_by_cka_id(session, &obj.pkcs11_cka_id) {
            let r = softhsmrustv3::native::destroy_object(session, handle);
            super::helpers::emit_pkcs11_result(
                deps,
                correlation_id,
                "native::destroy_object",
                None,
                &r,
            );
        }
    }

    // Plane-2: lifecycle update. Destroy Date set per Baseline §5.1.2.
    let from_label = state_name(obj.state).to_string();
    let to_label = state_name(target_state).to_string();
    let now = OffsetDateTime::now_utc();
    obj.state = target_state;
    obj.destroy_date = Some(now);
    obj.last_change_date = Some(now);

    // Gap-remediation Phase A — "the key material for the specified
    // Managed Object SHALL be destroyed" (§6.1.19) means destroyed, not
    // "state flipped while the plaintext sits in the store forever."
    // For Register/Import'd objects the raw bytes live in
    // `ObjectRecord.key_material` (there is no engine handle for them
    // to destroy above); zeroize the backing buffer before dropping it
    // rather than a bare `= None`, matching the `.zeroize()` discipline
    // `rust/src/ffi.rs` already uses for sensitive buffers. `Export`'s
    // own `key_material` filter for Destroyed objects becomes
    // redundant-but-harmless defense in depth after this, not load-
    // bearing — left in place.
    if let Some(mut material) = obj.key_material.take() {
        material.zeroize();
    }

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
        ..ObjectRecord::default()
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
        // KMIP 3.0 §11 — the FSM rejection reason is
        // `WrongKeyLifecycleState` (0x43), not the generic
        // `PermissionDenied`. AKLC-M-2 msg #5 pins this code.
        assert_eq!(
            err.result_reason(),
            crate::error::ResultReason::WrongKeyLifecycleState,
        );
    }

    #[test]
    fn already_destroyed_rejected() {
        let d = deps_with();
        put(&d, "u", State::Destroyed);
        let err = destroy(&d, DestroyRequest { uid: "u".into() }, "c").unwrap_err();
        assert_eq!(err.result_reason(), crate::error::ResultReason::ObjectDestroyed);
    }

    /// Gap-remediation Phase A — a Register/Import'd object's raw key
    /// bytes live in `ObjectRecord.key_material` (no engine handle to
    /// destroy). Destroy must scrub that field for real, not just flip
    /// the lifecycle state and leave the plaintext sitting in the
    /// store. Also confirms the pre-existing Export-side suppression
    /// (§6.1.22: Destroyed objects never return key material) still
    /// holds — that check becomes redundant-but-harmless defense in
    /// depth after this fix, not the only thing standing between a
    /// client and a "destroyed" key's plaintext.
    #[test]
    fn destroy_scrubs_key_material_for_registered_objects() {
        use crate::kmip30::ExportRequest;
        use crate::ops::register_import_export::export;

        let d = deps_with();
        d.store
            .put(ObjectRecord {
                uid: "u".into(),
                object_type: ObjectType::SecretData,
                algorithm: KmipAlgorithm::Aes,
                cryptographic_length: 256,
                usage_mask: UsageMask::ENCRYPT,
                state: State::PreActive,
                pkcs11_cka_id: vec![],
                pkcs11_slot: 0,
                initial_date: OffsetDateTime::UNIX_EPOCH,
                activation_date: None,
                supersedes: None,
                name: None,
                links: std::collections::HashMap::new(),
                custom_attributes: std::collections::HashMap::new(),
                key_material: Some(vec![0xAB; 32]),
                key_format_type: None,
                ..ObjectRecord::default()
            })
            .unwrap();

        destroy(&d, DestroyRequest { uid: "u".into() }, "c").unwrap();

        let stored = d.store.get("u").unwrap().unwrap();
        assert!(
            stored.key_material.is_none(),
            "Destroy must scrub key_material, not just flip lifecycle state"
        );

        // Export still honestly reports no material for a Destroyed
        // object (pre-existing §6.1.22 behavior) — proves this path
        // stays correct now that it's no longer the only thing hiding
        // the plaintext.
        let exported = export(
            &d,
            ExportRequest {
                uid: "u".into(),
                key_format_type: None,
                key_wrap_type: None,
                key_compression_type: None,
                key_wrapping_specification: None,
            },
            "c",
        )
        .unwrap();
        assert!(exported.managed_object.is_none());
    }
}
