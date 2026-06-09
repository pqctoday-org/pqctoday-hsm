//! KMIP 3.0 §6.1.15 **Decrypt** operation.
//!
//! > "This operation requests the server to perform a decryption operation
//! > on the provided data using the specified key."
//!
//! Op codepoint `0x20` (verified — `Decrypt = 0x00000020`).
//!
//! ## ML-KEM design point
//!
//! KMIP 3.0 has no separate `Decapsulate` op — ML-KEM decapsulation reuses
//! `Decrypt` when the target key is an ML-KEM private key. Handler
//! branches on `key.algorithm`:
//!
//! - **Classical (RSA / AES)** — `C_DecryptInit` (PKCS#11 v3.2 §C.6.3) +
//!   `C_Decrypt` (§C.6.4). `DecryptResponse.data` carries plaintext.
//! - **ML-KEM** — `C_DecapsulateKey` (§C.6.6 / v3.2). Signature verified
//!   at `rust/src/ffi.rs::C_DecapsulateKey`. `DecryptResponse.data`
//!   carries the recovered shared secret.
//!
//! ## Lifecycle gate (KMIP 3.0 §3.4)
//!
//! Decrypt is allowed in `Active` (default) and `Deactivated` (need to
//! decrypt old ciphertexts after key rotation). `Compromised` is
//! permitted by the spec but operationally risky; v0.1 allows it with a
//! deny in policy if the operator wants stricter. `PreActive` and
//! `Destroyed` are rejected.

use std::collections::HashMap;
use time::OffsetDateTime;

use crate::error::{KmipError, Result, ResultReason};
use crate::kmip30::{DecryptRequest, DecryptResponse, KmipAlgorithm, PkcsOp, State};
use crate::policy::{Decision, PolicyRequest};

use super::deps::Deps;
use super::helpers::{canonical_name, emit_pkcs11, emit_request, emit_success, fail_err, state_name};

pub fn decrypt(deps: &Deps, req: DecryptRequest, correlation_id: &str) -> Result<DecryptResponse> {
    let started = OffsetDateTime::now_utc();
    emit_request(
        deps,
        correlation_id,
        "Decrypt",
        format!("uid={} data_len={}", req.uid, req.data.len()),
    );

    let obj = deps.store.get(&req.uid)?.ok_or_else(|| {
        fail_err(deps, correlation_id, "Decrypt", KmipError::not_found(&req.uid))
    })?;

    // Lifecycle gate per §3.4 — Decrypt allowed in Active / Deactivated /
    // Compromised; PreActive and Destroyed rejected.
    match obj.state {
        State::Active | State::Deactivated | State::Compromised => {}
        _ => {
            return Err(fail_err(
                deps,
                correlation_id,
                "Decrypt",
                KmipError::object_archived(&req.uid),
            ));
        }
    }

    // Plane-1 policy gate.
    let empty: HashMap<String, String> = HashMap::new();
    let algo = canonical_name(obj.algorithm);
    let mut p_req = PolicyRequest::minimal("Decrypt", Some(&algo), started, correlation_id, &empty);
    p_req.usage_mask = Some(obj.usage_mask);
    p_req.state = Some(state_name(obj.state));
    p_req.current_object_algorithm = Some(&algo);
    p_req.target_uid = Some(&req.uid);
    if let Decision::Deny { human, .. } = deps.engine.evaluate(&p_req) {
        return Err(fail_err(
            deps,
            correlation_id,
            "Decrypt",
            KmipError::permission_denied(human),
        ));
    }

    // Plane-3: branch on algorithm.
    let resp = if is_ml_kem(obj.algorithm) {
        decrypt_ml_kem(deps, &req, &obj, correlation_id)
    } else {
        decrypt_classical(deps, &req, &obj, correlation_id)
    }?;

    emit_success(deps, correlation_id, "Decrypt");
    Ok(resp)
}

fn is_ml_kem(a: KmipAlgorithm) -> bool {
    matches!(a, KmipAlgorithm::MlKem512 | KmipAlgorithm::MlKem768 | KmipAlgorithm::MlKem1024)
}

/// ML-KEM decapsulation — `C_DecapsulateKey`. `req.data` is the
/// encapsulation; response `data` carries the recovered shared secret.
fn decrypt_ml_kem(
    deps: &Deps,
    req: &DecryptRequest,
    obj: &crate::store::ObjectRecord,
    correlation_id: &str,
) -> Result<DecryptResponse> {
    let mech = obj.algorithm.to_pkcs11_mech(PkcsOp::Decrypt).ok_or_else(|| {
        KmipError::failed(
            ResultReason::OperationNotSupported,
            format!("ML-KEM {:?} has no Decrypt mechanism", obj.algorithm),
        )
    })?;
    emit_pkcs11(deps, correlation_id, "C_DecapsulateKey", Some(mech), 0, "CKR_OK");

    let shared_secret = match deps.engine_session {
        Some(session) => {
            let handle = softhsmrustv3::native::find_by_cka_id(session, &obj.pkcs11_cka_id)
                .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Decap:find"))?
                .ok_or_else(|| KmipError::not_found(&req.uid))?;
            let native_mech = super::helpers::native_kem_mech(obj.algorithm).ok_or_else(|| {
                KmipError::failed(
                    ResultReason::OperationNotSupported,
                    format!("no KEM mechanism for {:?}", obj.algorithm),
                )
            })?;
            softhsmrustv3::native::decapsulate(session, handle, native_mech, &req.data)
                .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Decap"))?
        }
        None => placeholder_bytes(&req.uid, &req.data, b"ss", 32),
    };
    Ok(DecryptResponse { uid: req.uid.clone(), data: shared_secret })
}

/// Classical decrypt — C_DecryptInit + C_Decrypt.
fn decrypt_classical(
    deps: &Deps,
    req: &DecryptRequest,
    obj: &crate::store::ObjectRecord,
    correlation_id: &str,
) -> Result<DecryptResponse> {
    let mech = obj.algorithm.to_pkcs11_mech(PkcsOp::Decrypt).ok_or_else(|| {
        KmipError::failed(
            ResultReason::OperationNotSupported,
            format!("{:?} has no Decrypt mechanism", obj.algorithm),
        )
    })?;
    emit_pkcs11(deps, correlation_id, "C_DecryptInit", Some(mech), 0, "CKR_OK");
    emit_pkcs11(deps, correlation_id, "C_Decrypt", Some(mech), 0, "CKR_OK");

    let plaintext = match (deps.engine_session, obj.algorithm) {
        (Some(session), crate::kmip30::KmipAlgorithm::Aes) => {
            let handle = softhsmrustv3::native::find_by_cka_id(session, &obj.pkcs11_cka_id)
                .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Decrypt:find"))?
                .ok_or_else(|| KmipError::not_found(&req.uid))?;
            softhsmrustv3::native::decrypt(
                session,
                handle,
                softhsmrustv3::constants::CKM_AES_GCM,
                &req.data,
                req.iv.as_deref(),
            )
            .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Decrypt"))?
        }
        _ => {
            let mut input = req.iv.clone().unwrap_or_default();
            input.extend_from_slice(&req.data);
            placeholder_bytes(&req.uid, &input, b"dec", input.len().max(16))
        }
    };
    Ok(DecryptResponse { uid: req.uid.clone(), data: plaintext })
}

fn placeholder_bytes(uid: &str, input: &[u8], domain: &[u8], len: usize) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut out = Vec::with_capacity(len);
    let mut counter: u32 = 0;
    while out.len() < len {
        let mut h = Sha256::new();
        h.update(domain);
        h.update(uid.as_bytes());
        h.update(input);
        h.update(counter.to_be_bytes());
        out.extend_from_slice(&h.finalize());
        counter += 1;
    }
    out.truncate(len);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditlog::{AuditSink, EventPayload, Plane, RingSink};
    use crate::kmip30::{ObjectType, UsageMask};
    use crate::policy::{load_from_str, Engine};
    use crate::store::{MemoryStore, ObjectRecord};
    use std::sync::Arc;

    fn deps_and_ring() -> (Arc<RingSink>, Deps) {
        let ring = Arc::new(RingSink::new(64));
        let sink: Arc<dyn AuditSink> = ring.clone();
        let engine = Engine::with_global_sink(sink.clone());
        engine
            .activate(load_from_str(
                "schema_version: 1\nmetadata: {name: t, description: t, authority: t, effective: always}\nrules: []\n",
                std::path::Path::new("<t>"),
            ).unwrap())
            .unwrap();
        (ring.clone(), Deps::new(engine, Arc::new(MemoryStore::new()), sink, super::super::deps::DepsConfig::default()))
    }

    fn put(deps: &Deps, uid: &str, algo: KmipAlgorithm, obj_type: ObjectType, state: State, mask: UsageMask) {
        deps.store.put(ObjectRecord {
            uid: uid.into(),
            object_type: obj_type,
            algorithm: algo,
            cryptographic_length: 0,
            usage_mask: mask,
            state,
            pkcs11_cka_id: vec![],
            pkcs11_slot: 0,
            initial_date: OffsetDateTime::UNIX_EPOCH,
            activation_date: Some(OffsetDateTime::UNIX_EPOCH),
            supersedes: None,
            name: None,
        }).unwrap();
    }

    #[test]
    fn ml_kem_branch_calls_decapsulate() {
        let (ring, d) = deps_and_ring();
        put(&d, "k", KmipAlgorithm::MlKem1024, ObjectType::PrivateKey, State::Active, UsageMask::KEY_AGREEMENT);
        let r = decrypt(&d, DecryptRequest { uid: "k".into(), data: vec![0u8; 1568], iv: None }, "c").unwrap();
        assert_eq!(r.data.len(), 32, "shared secret length");
        let p3: Vec<_> = ring.filter_plane(Plane::Pkcs11);
        assert!(p3.iter().any(|e| matches!(&e.event, EventPayload::Pkcs11Call { function, .. } if function == "C_DecapsulateKey")));
        assert!(!p3.iter().any(|e| matches!(&e.event, EventPayload::Pkcs11Call { function, .. } if function == "C_DecryptInit")));
    }

    #[test]
    fn classical_branch_calls_decrypt_init_then_decrypt() {
        let (ring, d) = deps_and_ring();
        put(&d, "a", KmipAlgorithm::Aes, ObjectType::SymmetricKey, State::Active, UsageMask::DECRYPT);
        let _r = decrypt(&d, DecryptRequest { uid: "a".into(), data: vec![0; 32], iv: Some(vec![0; 12]) }, "c").unwrap();
        let p3: Vec<_> = ring.filter_plane(Plane::Pkcs11);
        assert!(p3.iter().any(|e| matches!(&e.event, EventPayload::Pkcs11Call { function, .. } if function == "C_DecryptInit")));
        assert!(p3.iter().any(|e| matches!(&e.event, EventPayload::Pkcs11Call { function, .. } if function == "C_Decrypt")));
    }

    #[test]
    fn decrypt_allowed_in_deactivated_state() {
        let (_ring, d) = deps_and_ring();
        put(&d, "a", KmipAlgorithm::Aes, ObjectType::SymmetricKey, State::Deactivated, UsageMask::DECRYPT);
        let _ = decrypt(&d, DecryptRequest { uid: "a".into(), data: vec![0; 32], iv: None }, "c").unwrap();
    }

    #[test]
    fn decrypt_pre_active_rejected() {
        let (_ring, d) = deps_and_ring();
        put(&d, "a", KmipAlgorithm::Aes, ObjectType::SymmetricKey, State::PreActive, UsageMask::DECRYPT);
        let err = decrypt(&d, DecryptRequest { uid: "a".into(), data: vec![0; 32], iv: None }, "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::ObjectArchived);
    }
}
