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

    let mech = obj.algorithm.to_pkcs11_mech(PkcsOp::Decrypt).ok_or_else(|| {
        KmipError::failed(
            ResultReason::OperationNotSupported,
            format!("ML-KEM {:?} has no decapsulation mechanism", obj.algorithm),
        )
    })?;

    let shared_secret = match deps.engine_session {
        Some(session) => {
            let handle = softhsmrustv3::native::find_by_cka_id(session, &obj.pkcs11_cka_id)
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
    };

    let ss_uid = store_shared_secret(deps, obj.algorithm, shared_secret)?;

    emit_success(deps, correlation_id, "Decapsulate");

    Ok(DecapsulateResponse { uid: ss_uid })
}

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
        assert_eq!(ss_rec.state, State::Active);
        assert!(ss_rec.key_material.is_some());
        assert_ne!(resp.uid, "sk");
    }
}
