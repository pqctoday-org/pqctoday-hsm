//! KMIP 3.0 §6.1.61 **Signature Verify** operation.
//!
//! > "This operation requests the server to perform a signature verify
//! > operation on the provided data using the specified verification key."
//!
//! Op codepoint `0x22` (verified — `Signature Verify = 0x00000022`).
//!
//! ## KMIP design point
//!
//! A failed verification is **not** a KMIP error — it returns a successful
//! `Signature Verify` response with `validity = Invalid`. KMIP errors are
//! reserved for protocol-level failures (missing UID, archived key,
//! policy denial, etc.).
//!
//! ## Plane mapping
//!
//! - **Plane 1** — engine.evaluate; policies may gate verify on certain
//!   algorithms (e.g. denying MD5 / SHA-1 verification under a strict
//!   compliance profile).
//! - **Plane 2** — store lookup + lifecycle gate. Per §3.4 table:
//!   `Active`, `Deactivated`, `Compromised` all permit verify (verifying
//!   legacy signatures is required even after key rotation).
//! - **Plane 3** — would call `C_VerifyInit` (PKCS#11 v3.2 §C.6.7) +
//!   `C_Verify` (§C.6.8). Signatures verified against
//!   `rust/src/ffi.rs::{C_VerifyInit, C_Verify}`. v0.1 placeholder
//!   re-runs the SHA-256 stamp from `sign.rs` to determine validity.

use std::collections::HashMap;
use time::OffsetDateTime;

use crate::error::{KmipError, Result, ResultReason};
use crate::kmip30::{PkcsOp, SignatureValidity, SignatureVerifyRequest, SignatureVerifyResponse, State};
use crate::policy::{Decision, PolicyRequest};

use super::deps::Deps;
use super::helpers::{canonical_name, emit_pkcs11, emit_request, emit_success, fail_err, state_name};

pub fn signature_verify(
    deps: &Deps,
    req: SignatureVerifyRequest,
    correlation_id: &str,
) -> Result<SignatureVerifyResponse> {
    let started = OffsetDateTime::now_utc();
    emit_request(
        deps,
        correlation_id,
        "SignatureVerify",
        format!("uid={} data_len={} sig_len={}", req.uid, req.data.len(), req.signature.len()),
    );

    let obj = deps.store.get(&req.uid)?.ok_or_else(|| {
        fail_err(deps, correlation_id, "SignatureVerify", KmipError::not_found(&req.uid))
    })?;

    // KMIP 3.0 §3.x lifecycle — Verify allowed in Active / Deactivated /
    // Compromised (need to verify legacy artefacts). Blocked in PreActive
    // (no key material yet) and Destroyed.
    match obj.state {
        State::Active | State::Deactivated | State::Compromised => {}
        _ => {
            return Err(fail_err(
                deps,
                correlation_id,
                "SignatureVerify",
                super::helpers::non_active_state_error(&req.uid, obj.state),
            ));
        }
    }

    // KMIP 3.0 §3.4 — `Process Start Date` / `Protect Stop Date`
    // window gating, mirror of `sign.rs` / `encrypt.rs` / `decrypt.rs`.
    // CS-AC-M-8 step #3 pins this with ProcessStartDate=future.
    if let Some(t) = obj.process_start_date {
        if started < t {
            return Err(fail_err(deps, correlation_id, "SignatureVerify",
                KmipError::failed(
                    crate::error::ResultReason::WrongKeyLifecycleState,
                    "SignatureVerify: now < ProcessStartDate".to_string(),
                )));
        }
    }
    if let Some(t) = obj.protect_stop_date {
        if started > t {
            return Err(fail_err(deps, correlation_id, "SignatureVerify",
                KmipError::failed(
                    crate::error::ResultReason::WrongKeyLifecycleState,
                    "SignatureVerify: now > ProtectStopDate".to_string(),
                )));
        }
    }

    // Plane-1 policy gate.
    let empty: HashMap<String, String> = HashMap::new();
    let algo = canonical_name(obj.algorithm);
    let mut p_req = PolicyRequest::minimal(
        "SignatureVerify",
        Some(&algo),
        started,
        correlation_id,
        &empty,
    );
    p_req.usage_mask = Some(obj.usage_mask);
    p_req.state = Some(state_name(obj.state));
    p_req.target_uid = Some(&req.uid);
    if let Decision::Deny { human, .. } = deps.engine.evaluate(&p_req) {
        return Err(fail_err(
            deps,
            correlation_id,
            "SignatureVerify",
            KmipError::permission_denied(human),
        ));
    }

    // Plane-3: emit (Phase 7 wires C_VerifyInit + C_Verify).
    let mech = obj.algorithm.to_pkcs11_mech(PkcsOp::SignVerify).ok_or_else(|| {
        KmipError::failed(
            ResultReason::OperationNotSupported,
            format!("algorithm {:?} has no Verify mechanism", obj.algorithm),
        )
    })?;
    emit_pkcs11(deps, correlation_id, "C_VerifyInit", Some(mech), 0, "CKR_OK");

    // Phase 7b: real bridge call when a session is wired. Falls back
    // to the SHA-256 stamp comparison for unit tests.
    let validity = match deps.engine_session {
        Some(session) => {
            let handle =
                super::helpers::find_handle_for_object(session, &obj.pkcs11_cka_id, obj.object_type)
                    .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Verify:find"))?
                    .ok_or_else(|| KmipError::not_found(&req.uid))?;
            let native_mech = super::helpers::native_sign_mech(obj.algorithm).ok_or_else(|| {
                KmipError::failed(
                    ResultReason::OperationNotSupported,
                    format!("Verify: no native mechanism for {:?}", obj.algorithm),
                )
            })?;
            // native::verify returns Ok(true)/Ok(false) for the KMIP
            // ValidityIndicator model — exactly what we need.
            match softhsmrustv3::native::verify(
                session,
                handle,
                native_mech,
                &req.data,
                &req.signature,
            ) {
                Ok(true) => SignatureValidity::Valid,
                Ok(false) => SignatureValidity::Invalid,
                Err(rv) => return Err(super::helpers::ck_rv_to_kmip_error(rv, "Verify")),
            }
        }
        None => {
            // Unit-test fallback — re-compute the SHA-256 stamp.
            let expected = placeholder_signature(&req.uid, &req.data);
            if req.signature == expected {
                SignatureValidity::Valid
            } else {
                SignatureValidity::Invalid
            }
        }
    };
    emit_pkcs11(deps, correlation_id, "C_Verify", Some(mech), 0, "CKR_OK");
    emit_success(deps, correlation_id, "SignatureVerify");

    Ok(SignatureVerifyResponse { uid: req.uid, validity })
}

fn placeholder_signature(uid: &str, data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(uid.as_bytes());
    h.update(data);
    h.finalize().to_vec()
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

    fn active(deps: &Deps, uid: &str) {
        deps.store.put(ObjectRecord {
            uid: uid.into(),
            object_type: ObjectType::PublicKey,
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

    #[test]
    fn verify_matching_signature_returns_valid() {
        let d = deps_with();
        active(&d, "u");
        let data = b"hello world".to_vec();
        let sig = placeholder_signature("u", &data);
        let r = signature_verify(&d, SignatureVerifyRequest { uid: "u".into(), data, signature: sig }, "c").unwrap();
        assert_eq!(r.validity, SignatureValidity::Valid);
    }

    #[test]
    fn verify_wrong_signature_returns_invalid_not_error() {
        let d = deps_with();
        active(&d, "u");
        let r = signature_verify(&d, SignatureVerifyRequest {
            uid: "u".into(),
            data: b"hello".to_vec(),
            signature: vec![0xff; 32],
        }, "c").unwrap();
        assert_eq!(r.validity, SignatureValidity::Invalid);
    }

    #[test]
    fn verify_allowed_in_deactivated_state() {
        let d = deps_with();
        d.store.put(ObjectRecord {
            uid: "u".into(),
            object_type: ObjectType::PublicKey,
            algorithm: KmipAlgorithm::MlDsa87,
            cryptographic_length: 0,
            usage_mask: UsageMask::VERIFY,
            state: State::Deactivated,
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
        let _ = signature_verify(&d, SignatureVerifyRequest {
            uid: "u".into(),
            data: vec![],
            signature: vec![],
        }, "c").unwrap();
        // success — Verify is permitted in Deactivated state per §3.4
    }

    #[test]
    fn verify_destroyed_returns_wrong_lifecycle_state() {
        let d = deps_with();
        d.store.put(ObjectRecord {
            uid: "u".into(),
            object_type: ObjectType::PublicKey,
            algorithm: KmipAlgorithm::MlDsa87,
            cryptographic_length: 0,
            usage_mask: UsageMask::VERIFY,
            state: State::Destroyed,
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
        let err = signature_verify(&d, SignatureVerifyRequest {
            uid: "u".into(),
            data: vec![],
            signature: vec![],
        }, "c").unwrap_err();
        // KMIP 3.0 §11 — Destroyed is an FSM-rejection state. See
        // `ops::helpers::non_active_state_error` for the citation.
        assert_eq!(err.result_reason(), ResultReason::WrongKeyLifecycleState);
    }
}
