//! KMIP 3.0 WD19 (PQC Updates) **Decapsulate** operation.
//!
//! > "This operation requests the server to perform an ML-KEM
//! > decapsulation against the referenced private (decapsulation) key."
//!
//! Op codepoint `0x42` (WD19 — right after `Encapsulate = 0x41`).
//!
//! Unlike the `Decrypt`-overload decapsulation path
//! ([`super::decrypt::decrypt`]), `Decapsulate` does **not** return the
//! recovered shared secret inline. Instead the server:
//!   1. decapsulates the ciphertext with the ML-KEM private key → `K`;
//!   2. creates a NEW managed `SecretData` object holding `K`, allocating
//!      a fresh UID;
//!   3. returns `{ UniqueIdentifier = <new> }`.
//!
//! A subsequent `Get` on the returned UID retrieves the recovered shared
//! secret as KeyMaterial.

use crate::error::{KmipError, Result, ResultReason};
use crate::kmip30::{DecapsulateRequest, DecapsulateResponse, PkcsOp, State};

use super::deps::Deps;
use super::encapsulate::{is_ml_kem, store_shared_secret};
use super::helpers::{emit_pkcs11, emit_pkcs11_result, emit_request, emit_success, fail_err};

pub fn decapsulate(
    deps: &Deps,
    req: DecapsulateRequest,
    correlation_id: &str,
) -> Result<DecapsulateResponse> {
    emit_request(
        deps,
        correlation_id,
        "Decapsulate",
        format!("uid={} ct_len={}", req.uid, req.data.len()),
    );

    let obj = deps.store.get(&req.uid)?.ok_or_else(|| {
        fail_err(deps, correlation_id, "Decapsulate", KmipError::object_not_found(&req.uid))
    })?;

    if !is_ml_kem(obj.algorithm) {
        return Err(fail_err(
            deps,
            correlation_id,
            "Decapsulate",
            KmipError::failed(
                ResultReason::OperationNotSupported,
                format!("Decapsulate requires an ML-KEM key; {:?} is not", obj.algorithm),
            ),
        ));
    }

    // KMIP 3.0 §3.4 lifecycle gate — the private key must be Active.
    if obj.state != State::Active {
        return Err(fail_err(
            deps,
            correlation_id,
            "Decapsulate",
            super::helpers::non_active_state_error(&req.uid, obj.state),
        ));
    }
    if obj.archived {
        return Err(fail_err(
            deps,
            correlation_id,
            "Decapsulate",
            KmipError::object_archived(&req.uid),
        ));
    }

    // ── Plane 1: policy gate ────────────────────────────────────────────
    // Route Decapsulate through the agility engine (see encapsulate.rs) so the
    // policy plane governs ML-KEM operations — emits the p1 PolicyDecided
    // audit event and enforces allow / deny.
    let started = time::OffsetDateTime::now_utc();
    let empty: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let stored_algo = super::helpers::canonical_name(obj.algorithm);
    let mut p_req = crate::policy::PolicyRequest::minimal(
        "Decapsulate",
        Some(&stored_algo),
        started,
        correlation_id,
        &empty,
    );
    p_req.usage_mask = Some(obj.usage_mask);
    p_req.state = Some("Active");
    p_req.current_object_algorithm = Some(&stored_algo);
    p_req.target_uid = Some(&req.uid);
    p_req.object_activation_date = obj.activation_date; // F-3 — max_key_age_days
    match deps.engine.evaluate(&p_req) {
        crate::policy::Decision::Allow { .. } => {}
        crate::policy::Decision::Deny { human, .. } => {
            return Err(fail_err(
                deps,
                correlation_id,
                "Decapsulate",
                KmipError::permission_denied(human),
            ));
        }
        crate::policy::Decision::RekeyAndProceed { .. } => {
            return Err(fail_err(
                deps,
                correlation_id,
                "Decapsulate",
                KmipError::failed(
                    ResultReason::OperationNotSupported,
                    "Decapsulate: policy requires rekey, which is not supported inline".to_string(),
                ),
            ));
        }
    }

    let mech = obj.algorithm.to_pkcs11_mech(PkcsOp::Decrypt).ok_or_else(|| {
        KmipError::failed(
            ResultReason::OperationNotSupported,
            format!("ML-KEM {:?} has no decapsulation mechanism", obj.algorithm),
        )
    })?;

    let shared_secret = match deps.engine_session {
        Some(session) => {
            // Resolve by PKCS#11 class: Decapsulate needs the PRIVATE key, but
            // a CreateKeyPair pair shares one CKA_ID across both halves, so a
            // bare `find_by_cka_id` may return the public half (CKA_DECAPSULATE
            // =false → CKR_KEY_FUNCTION_NOT_PERMITTED). (Same fix as Get/Sign.)
            let handle = super::helpers::find_handle_for_object(
                session,
                &obj.pkcs11_cka_id,
                crate::kmip30::ObjectType::PrivateKey,
            )
            .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Decap:find"))?
            .ok_or_else(|| KmipError::object_not_found(&req.uid))?;
            let native_mech = super::helpers::native_kem_mech(obj.algorithm).ok_or_else(|| {
                KmipError::failed(
                    ResultReason::OperationNotSupported,
                    format!("no KEM mechanism for {:?}", obj.algorithm),
                )
            })?;
            let r = softhsmrustv3::native::decapsulate(session, handle, native_mech, &req.data);
            emit_pkcs11_result(deps, correlation_id, "native::decapsulate", Some(native_mech), &r);
            r.map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Decap"))?
        }
        None => {
            // S-2 hardening: no engine session ⇒ fail rather than emit a fake
            // shared secret. Placeholder kept only for the crate tests.
            #[cfg(not(test))]
            {
                return Err(crate::error::KmipError::failed(
                    crate::error::ResultReason::CryptographicFailure,
                    "no engine session — cannot decapsulate without key material",
                ));
            }
            #[cfg(test)]
            {
                emit_pkcs11(
                    deps,
                    correlation_id,
                    "soft::placeholder_decapsulate",
                    Some(mech),
                    0,
                    "CKR_OK",
                );
                placeholder_bytes(&req.uid, &req.data, b"ss", 32)
            }
        }
    };

    let ss_uid = store_shared_secret(deps, obj.algorithm, shared_secret)?;

    emit_success(deps, correlation_id, "Decapsulate");

    Ok(DecapsulateResponse { uid: ss_uid })
}

/// Test-only stand-in for the engine-less unit tests; production fails closed.
#[cfg(test)]
fn placeholder_bytes(uid: &str, input: &[u8], domain: &[u8], len: usize) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(domain);
    h.update(uid.as_bytes());
    h.update(input);
    let d = h.finalize();
    d.iter().cycle().take(len).copied().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditlog::{AuditSink, RingSink};
    use crate::kmip30::{KmipAlgorithm, ObjectType, UsageMask};
    use crate::policy::Engine;
    use crate::store::{MemoryStore, ObjectRecord};
    use std::sync::Arc;

    fn deps() -> Deps {
        let ring = Arc::new(RingSink::new(64));
        let sink: Arc<dyn AuditSink> = ring.clone();
        Deps::new(
            Engine::permissive(),
            Arc::new(MemoryStore::new()),
            sink,
            super::super::deps::DepsConfig::default(),
        )
    }

    #[test]
    fn placeholder_decapsulate_creates_secret_data() {
        let d = deps();
        d.store
            .put(ObjectRecord {
                uid: "sk".to_string(),
                object_type: ObjectType::PrivateKey,
                algorithm: KmipAlgorithm::MlKem768,
                usage_mask: UsageMask::DECRYPT,
                state: State::Active,
                ..ObjectRecord::default()
            })
            .unwrap();
        let resp = decapsulate(
            &d,
            DecapsulateRequest {
                uid: "sk".to_string(),
                data: vec![0u8; 1088],
                cryptographic_parameters: None,
            },
            "t",
        )
        .unwrap();
        let ss_rec = d.store.get(&resp.uid).unwrap().unwrap();
        assert_eq!(ss_rec.object_type, ObjectType::SecretData);
        // Born PreActive — see encapsulate::store_shared_secret rationale.
        assert_eq!(ss_rec.state, State::PreActive);
        assert!(ss_rec.key_material.is_some());
        assert_ne!(resp.uid, "sk");
    }
}
