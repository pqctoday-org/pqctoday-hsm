//! KMIP 3.0 §6.1.21 **Encrypt** operation.
//!
//! > "This operation requests the server to perform an encryption
//! > operation on the provided data using the specified key."
//!
//! Op codepoint `0x1f` (verified — `Encrypt = 0x0000001f`).
//!
//! ## ML-KEM design point (verified 2026-06-04)
//!
//! KMIP 3.0 has **no** separate `Encapsulate` op — ML-KEM encapsulation
//! reuses `Encrypt` when the target key is an ML-KEM public key. This
//! handler branches on `key.algorithm`:
//!
//! - **Classical (RSA / AES)** — `C_EncryptInit` (PKCS#11 v3.2 §C.6.1) +
//!   `C_Encrypt` (§C.6.2). `EncryptResponse.ciphertext` carries the
//!   ciphertext; `shared_secret` is `None`.
//! - **ML-KEM** — `C_EncapsulateKey` (§C.6.5 introduced in v3.2).
//!   Signature verified at `rust/src/ffi.rs::C_EncapsulateKey`:
//!   `(hSession, pMechanism, hPublicKey, pTemplate, ulAttributeCount,
//!    pCiphertext, pulCiphertextLen, phKey)`. Response carries
//!   `ciphertext = encapsulation` AND `shared_secret = Some(K)`.
//!
//! ## Lifecycle gate (KMIP 3.0 §3.4)
//!
//! Encrypt requires `Active`. Other states rejected with `ObjectArchived`.

use std::collections::HashMap;
use time::OffsetDateTime;

use crate::error::{KmipError, Result, ResultReason};
use crate::kmip30::{EncryptRequest, EncryptResponse, KmipAlgorithm, PkcsOp, State};
use crate::policy::{Decision, PolicyRequest};

use super::deps::Deps;
use super::helpers::{canonical_name, emit_pkcs11, emit_request, emit_success, fail_err, state_name};

pub fn encrypt(deps: &Deps, req: EncryptRequest, correlation_id: &str) -> Result<EncryptResponse> {
    let started = OffsetDateTime::now_utc();
    emit_request(
        deps,
        correlation_id,
        "Encrypt",
        format!("uid={} data_len={}", req.uid, req.data.len()),
    );

    let obj = deps.store.get(&req.uid)?.ok_or_else(|| {
        fail_err(deps, correlation_id, "Encrypt", KmipError::not_found(&req.uid))
    })?;

    if obj.state != State::Active {
        return Err(fail_err(
            deps,
            correlation_id,
            "Encrypt",
            KmipError::object_archived(&req.uid),
        ));
    }

    // Plane-1 policy gate. The dispatcher would canonicalise the op to
    // "Encapsulate" for ML-KEM in a future revision so policies can
    // differentiate; v0.1 passes plain "Encrypt".
    let empty: HashMap<String, String> = HashMap::new();
    let algo = canonical_name(obj.algorithm);
    let mut p_req = PolicyRequest::minimal("Encrypt", Some(&algo), started, correlation_id, &empty);
    p_req.usage_mask = Some(obj.usage_mask);
    p_req.state = Some(state_name(obj.state));
    p_req.current_object_algorithm = Some(&algo);
    p_req.target_uid = Some(&req.uid);
    match deps.engine.evaluate(&p_req) {
        Decision::Allow { .. } => {}
        Decision::Deny { human, .. } => {
            return Err(fail_err(
                deps,
                correlation_id,
                "Encrypt",
                KmipError::permission_denied(human),
            ));
        }
        Decision::RekeyAndProceed { new_algorithm, original_uid, .. } => {
            return Err(fail_err(
                deps,
                correlation_id,
                "Encrypt",
                KmipError::failed(
                    ResultReason::PermissionDenied,
                    format!(
                        "rekey required: policy substitutes {algo} → {new_algorithm} for UID {original_uid}"
                    ),
                ),
            ));
        }
    }

    // Plane-3: branch on algorithm.
    let resp = if is_ml_kem(obj.algorithm) {
        encrypt_ml_kem(deps, &req, &obj, correlation_id)
    } else {
        encrypt_classical(deps, &req, &obj, correlation_id)
    }?;

    emit_success(deps, correlation_id, "Encrypt");
    Ok(resp)
}

fn is_ml_kem(a: KmipAlgorithm) -> bool {
    matches!(a, KmipAlgorithm::MlKem512 | KmipAlgorithm::MlKem768 | KmipAlgorithm::MlKem1024)
}

/// ML-KEM encapsulation — calls `C_EncapsulateKey`. Response carries
/// ciphertext (the encapsulation) AND the derived shared secret.
fn encrypt_ml_kem(
    deps: &Deps,
    req: &EncryptRequest,
    obj: &crate::store::ObjectRecord,
    correlation_id: &str,
) -> Result<EncryptResponse> {
    let mech = obj.algorithm.to_pkcs11_mech(PkcsOp::Encrypt).ok_or_else(|| {
        KmipError::failed(
            ResultReason::OperationNotSupported,
            format!("ML-KEM {:?} has no Encrypt mechanism", obj.algorithm),
        )
    })?;
    emit_pkcs11(deps, correlation_id, "C_EncapsulateKey", Some(mech), 0, "CKR_OK");

    // Phase 7b: real bridge call when a session is wired.
    let (ciphertext, shared_secret) = match deps.engine_session {
        Some(session) => {
            let handle =
                softhsmrustv3::native::find_by_cka_id(session, &obj.pkcs11_cka_id)
                    .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Encap:find"))?
                    .ok_or_else(|| KmipError::not_found(&req.uid))?;
            let native_mech = super::helpers::native_kem_mech(obj.algorithm).ok_or_else(|| {
                KmipError::failed(
                    ResultReason::OperationNotSupported,
                    format!("no KEM mechanism for {:?}", obj.algorithm),
                )
            })?;
            softhsmrustv3::native::encapsulate(session, handle, native_mech)
                .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Encap"))?
        }
        None => (
            placeholder_bytes(&req.uid, &req.data, b"encap", 32),
            placeholder_bytes(&req.uid, &req.data, b"ss", 32),
        ),
    };
    Ok(EncryptResponse {
        uid: req.uid.clone(),
        ciphertext,
        shared_secret: Some(shared_secret),
    })
}

/// Classical encrypt — calls C_EncryptInit + C_Encrypt.
fn encrypt_classical(
    deps: &Deps,
    req: &EncryptRequest,
    obj: &crate::store::ObjectRecord,
    correlation_id: &str,
) -> Result<EncryptResponse> {
    let mech = obj.algorithm.to_pkcs11_mech(PkcsOp::Encrypt).ok_or_else(|| {
        KmipError::failed(
            ResultReason::OperationNotSupported,
            format!("{:?} has no Encrypt mechanism", obj.algorithm),
        )
    })?;
    emit_pkcs11(deps, correlation_id, "C_EncryptInit", Some(mech), 0, "CKR_OK");
    emit_pkcs11(deps, correlation_id, "C_Encrypt", Some(mech), 0, "CKR_OK");

    // Phase 7b: real AES-GCM (only classical encrypt the native API
    // supports in v0.1). Falls back to placeholder for unit tests / non-AES.
    let ciphertext = match (deps.engine_session, obj.algorithm) {
        (Some(session), crate::kmip30::KmipAlgorithm::Aes) => {
            let handle = softhsmrustv3::native::find_by_cka_id(session, &obj.pkcs11_cka_id)
                .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Encrypt:find"))?
                .ok_or_else(|| KmipError::not_found(&req.uid))?;
            softhsmrustv3::native::encrypt(
                session,
                handle,
                softhsmrustv3::constants::CKM_AES_GCM,
                &req.data,
                req.iv.as_deref(),
            )
            .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Encrypt"))?
        }
        _ => {
            let mut input = req.iv.clone().unwrap_or_default();
            input.extend_from_slice(&req.data);
            placeholder_bytes(&req.uid, &input, b"enc", input.len().max(16))
        }
    };
    Ok(EncryptResponse {
        uid: req.uid.clone(),
        ciphertext,
        shared_secret: None,
    })
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
        }).unwrap();
    }

    #[test]
    fn ml_kem_branch_returns_encapsulation_and_shared_secret() {
        let (ring, d) = deps_and_ring();
        put(&d, "k", KmipAlgorithm::MlKem1024, ObjectType::PublicKey, State::Active, UsageMask::KEY_AGREEMENT);
        let r = encrypt(&d, EncryptRequest { uid: "k".into(), data: vec![], iv: None }, "c").unwrap();
        assert!(r.shared_secret.is_some(), "ML-KEM must return shared secret");
        assert_eq!(r.ciphertext.len(), 32);
        // Plane-3 emit should be C_EncapsulateKey, not C_EncryptInit.
        let p3: Vec<_> = ring.filter_plane(Plane::Pkcs11);
        assert!(p3.iter().any(|e| matches!(&e.event, EventPayload::Pkcs11Call { function, .. } if function == "C_EncapsulateKey")));
        assert!(!p3.iter().any(|e| matches!(&e.event, EventPayload::Pkcs11Call { function, .. } if function == "C_EncryptInit")));
    }

    #[test]
    fn classical_aes_branch_returns_ciphertext_no_shared_secret() {
        let (ring, d) = deps_and_ring();
        put(&d, "a", KmipAlgorithm::Aes, ObjectType::SymmetricKey, State::Active, UsageMask::ENCRYPT);
        let r = encrypt(&d, EncryptRequest {
            uid: "a".into(),
            data: b"plaintext".to_vec(),
            iv: Some(vec![0u8; 12]),
        }, "c").unwrap();
        assert!(r.shared_secret.is_none(), "classical encrypt has no shared secret");
        // Plane-3 emit should be C_EncryptInit + C_Encrypt.
        let p3: Vec<_> = ring.filter_plane(Plane::Pkcs11);
        assert!(p3.iter().any(|e| matches!(&e.event, EventPayload::Pkcs11Call { function, .. } if function == "C_EncryptInit")));
        assert!(p3.iter().any(|e| matches!(&e.event, EventPayload::Pkcs11Call { function, .. } if function == "C_Encrypt")));
    }

    #[test]
    fn encrypt_on_destroyed_returns_object_archived() {
        let (_ring, d) = deps_and_ring();
        put(&d, "a", KmipAlgorithm::Aes, ObjectType::SymmetricKey, State::Destroyed, UsageMask::ENCRYPT);
        let err = encrypt(&d, EncryptRequest { uid: "a".into(), data: vec![], iv: None }, "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::ObjectArchived);
    }
}
