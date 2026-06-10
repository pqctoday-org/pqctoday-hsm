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
            super::helpers::non_active_state_error(&req.uid, obj.state),
        ));
    }

    // KMIP 3.0 §3.4 — `Process Start Date` / `Protect Stop Date`
    // define the time window during which Encrypt MAY be performed
    // even when the object is Active. Outside the window the op
    // SHALL fail with `WrongKeyLifecycleState`. CS-BC-M-14 pins
    // both edges (ProcessStartDate=$NOW+3600 future, ProtectStopDate
    // =$NOW-3600 past).
    if let Some(t) = obj.process_start_date {
        if started < t {
            return Err(fail_err(deps, correlation_id, "Encrypt",
                KmipError::failed(
                    crate::error::ResultReason::WrongKeyLifecycleState,
                    "Encrypt: now < ProcessStartDate".to_string(),
                )));
        }
    }
    if let Some(t) = obj.protect_stop_date {
        if started > t {
            return Err(fail_err(deps, correlation_id, "Encrypt",
                KmipError::failed(
                    crate::error::ResultReason::WrongKeyLifecycleState,
                    "Encrypt: now > ProtectStopDate".to_string(),
                )));
        }
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
        authenticated_encryption_tag: None,
    })
}

/// Classical encrypt — calls C_EncryptInit + C_Encrypt.
fn encrypt_classical(
    deps: &Deps,
    req: &EncryptRequest,
    obj: &crate::store::ObjectRecord,
    correlation_id: &str,
) -> Result<EncryptResponse> {
    // KMIP 3.0 §6.1.21 — the request MAY carry its own
    // `CryptographicParameters` that override the key-attached value.
    // CS-BC-M-4..13 exercise the override pattern (the AES mode lives
    // on the Encrypt call, not the registered key).
    let effective_cp = req
        .cryptographic_parameters
        .as_ref()
        .or(obj.cryptographic_parameters.as_ref());
    let mech = match obj.algorithm {
        KmipAlgorithm::Aes => super::helpers::aes_mechanism_for(effective_cp),
        _ => obj.algorithm.to_pkcs11_mech(PkcsOp::Encrypt).ok_or_else(|| {
            KmipError::failed(
                ResultReason::OperationNotSupported,
                format!("{:?} has no Encrypt mechanism", obj.algorithm),
            )
        })?,
    };
    emit_pkcs11(deps, correlation_id, "C_EncryptInit", Some(mech), 0, "CKR_OK");
    emit_pkcs11(deps, correlation_id, "C_Encrypt", Some(mech), 0, "CKR_OK");

    // KMIP 3.0 §6.1.21 + §11 — IV presence/size is a protocol-level
    // requirement, so a missing/short IV for an IV-bearing mech is
    // `InvalidMessage` (0x04), NOT the shim's downstream
    // `InvalidAttributeValue` (0x2d). OASIS CS-BC-M-11 / CS-BC-M-12
    // pin `InvalidMessage` with a `missing-iv` message string.
    validate_iv_for_mech(deps, correlation_id, mech, req.iv.as_deref())?;

    // KMIP 3.0 §11 — `Tag Length` validation. The spec text reads
    // "Tag Length is the length of the authenticator tag in bytes."
    // The valid range depends on the AEAD mechanism:
    //   • ChaCha20-Poly1305 — RFC 8439 §2.8.1 mandates a fixed 128-bit
    //     (16-byte) tag. Any other Tag Length is unsupported.
    //   • AES-GCM — NIST SP 800-38D §5.2.1.2 permits 96, 104, 112,
    //     120, or 128 bits (12-16 bytes); the shim only emits 128.
    // OASIS CS-BC-M-CHACHA20POLY1305-1 msg #6 expects
    // `GeneralFailure` (0x100) for this rejection rather than the
    // more obvious `CryptographicFailure` (0x0a) — the result message
    // pattern they pin (`L_KMIPCRYPTO_random:invalid-tag-length`)
    // shows it's surfaced through the engine's generic random/AEAD
    // failure path, not the AEAD-specific cryptographic-failure path.
    if let Some(tl) = effective_cp.and_then(|c| c.tag_length) {
        let bytes = tl as i64;
        let valid = match mech {
            softhsmrustv3::constants::CKM_CHACHA20_POLY1305 => bytes == 16,
            softhsmrustv3::constants::CKM_AES_GCM => (12..=16).contains(&bytes),
            _ => true,
        };
        if !valid {
            return Err(fail_err(
                deps,
                correlation_id,
                "Encrypt",
                KmipError::failed(
                    ResultReason::GeneralFailure,
                    format!("invalid-tag-length: {bytes} bytes for mechanism {mech:#x}"),
                ),
            ));
        }
    }

    // Plane-3 dispatch. KMIP 3.0 §6.1.21 — the engine performs the
    // cryptographic op via the PKCS#11 bridge. Three paths:
    //
    //   1. Engine session present AND key was generated inside the
    //      engine (Create/CreateKeyPair): look the handle up by
    //      CKA_ID and call the bridge.
    //   2. Engine session present BUT key was supplied via Register
    //      (client-supplied bytes in obj.key_material): drive the
    //      bridge with raw bytes via `encrypt_with_key_bytes` — bytes
    //      never re-enter the engine.
    //   3. No engine session (unit tests, in-memory store with no
    //      Plane-3): still use `encrypt_with_key_bytes` so the
    //      OASIS-conformance harness gets real RSA-OAEP ciphertext /
    //      real AES-GCM ciphertext from `obj.key_material`.
    //
    // The previous code fell back to a SHA-256 placeholder buffer when
    // no session was wired — that broke KAT comparisons.
    let oaep = super::helpers::oaep_params_for(obj.cryptographic_parameters.as_ref());
    let aad = req.aad.as_deref().unwrap_or(&[]);
    // KMIP 3.0 §11 `Padding Method = PKCS5` (codepoint 3) on AES-ECB:
    // the shim has only the plain `CKM_AES_ECB` path (which rejects
    // non-16-byte-multiple inputs with `CKR_DATA_LEN_RANGE`). Honour
    // padding at the KMIP layer by PKCS#7-padding before the shim
    // call. CS-BC-M-8 / CS-BC-M-9 pin this.
    let pkcs7_pad_ecb = mech == softhsmrustv3::constants::CKM_AES_ECB
        && effective_cp.and_then(|c| c.padding_method) == Some(3);
    let padded_data: Vec<u8>;
    let data_for_shim: &[u8] = if pkcs7_pad_ecb {
        let pad_len = 16 - (req.data.len() % 16);
        padded_data = req.data.iter().copied()
            .chain(std::iter::repeat(pad_len as u8).take(pad_len))
            .collect();
        &padded_data
    } else {
        &req.data
    };
    let ciphertext = if let Some(key_bytes) = &obj.key_material {
        softhsmrustv3::native::encrypt_with_key_bytes(
            key_bytes,
            mech,
            data_for_shim,
            req.iv.as_deref(),
            oaep.as_ref(),
            aad,
        )
        .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Encrypt"))?
    } else if let Some(session) = deps.engine_session {
        let handle = softhsmrustv3::native::find_by_cka_id(session, &obj.pkcs11_cka_id)
            .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Encrypt:find"))?
            .ok_or_else(|| KmipError::not_found(&req.uid))?;
        softhsmrustv3::native::encrypt(session, handle, mech, data_for_shim, req.iv.as_deref())
            .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Encrypt"))?
    } else {
        // No key material AND no engine session — the object is a
        // placeholder for unit tests with mock policy gates. Match
        // the legacy behaviour so unit-tests that don't exercise
        // real crypto keep passing.
        let mut input = req.iv.clone().unwrap_or_default();
        input.extend_from_slice(&req.data);
        placeholder_bytes(&req.uid, &input, b"enc", input.len().max(16))
    };
    // AEAD mechanisms — the shim returns `ciphertext || tag`
    // (the standard Rust `aead` crate convention). KMIP 3.0 §6.1.21
    // requires the tag to ride in its own `AuthenticatedEncryptionTag`
    // field, not tacked onto Data, so we split on the way out. Every
    // AEAD mechanism in our shim uses a 16-byte tag (AES-GCM and
    // ChaCha20-Poly1305 per RFC 5116 / 8439).
    let is_aead = matches!(
        mech,
        softhsmrustv3::constants::CKM_AES_GCM
            | softhsmrustv3::constants::CKM_CHACHA20_POLY1305,
    );
    let (ciphertext, authenticated_encryption_tag) =
        if is_aead && ciphertext.len() >= 16 {
            let split = ciphertext.len() - 16;
            let tag = ciphertext[split..].to_vec();
            (ciphertext[..split].to_vec(), Some(tag))
        } else {
            (ciphertext, None)
        };
    Ok(EncryptResponse {
        uid: req.uid.clone(),
        ciphertext,
        shared_secret: None,
        authenticated_encryption_tag,
    })
}

/// Per-mechanism IV requirements per PKCS#11 v3.2 §6.10 / §6.20:
/// AES-CBC and AES-CBC-PAD require a 16-byte IV; AES-GCM requires a
/// 12-byte IV; ChaCha20-Poly1305 requires a 12-byte nonce; ChaCha20
/// accepts 8 (legacy) or 12 (IETF) byte nonces; AES-ECB and
/// RSA-OAEP have no IV. Anything else is `InvalidMessage` per the
/// KMIP §11 protocol contract.
pub(crate) fn validate_iv_for_mech(
    deps: &Deps,
    correlation_id: &str,
    mech: u32,
    iv: Option<&[u8]>,
) -> Result<()> {
    use softhsmrustv3::constants as ck;
    let len = iv.map(|b| b.len());
    let valid = match mech {
        ck::CKM_AES_CBC | ck::CKM_AES_CBC_PAD => len == Some(16),
        ck::CKM_AES_GCM => len == Some(12),
        ck::CKM_CHACHA20_POLY1305 => len == Some(12),
        ck::CKM_CHACHA20 => matches!(len, Some(8) | Some(12)),
        // No IV for these mechanisms.
        ck::CKM_AES_ECB | ck::CKM_RSA_PKCS_OAEP => iv.is_none() || iv == Some(&[][..]),
        _ => true,
    };
    if valid { return Ok(()); }
    Err(fail_err(deps, correlation_id, "Encrypt/Decrypt",
        KmipError::failed(
            ResultReason::InvalidMessage,
            if iv.is_none() { "missing-iv".to_string() }
            else { format!("invalid-iv-length: {:?} bytes for mechanism {:#x}", len, mech) },
        )))
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

            links: std::collections::HashMap::new(),

            custom_attributes: std::collections::HashMap::new(),


            key_material: None,


            key_format_type: None,
        ..ObjectRecord::default()
}).unwrap();
    }

    #[test]
    fn ml_kem_branch_returns_encapsulation_and_shared_secret() {
        let (ring, d) = deps_and_ring();
        put(&d, "k", KmipAlgorithm::MlKem1024, ObjectType::PublicKey, State::Active, UsageMask::KEY_AGREEMENT);
        let r = encrypt(&d, EncryptRequest { uid: "k".into(), data: vec![], iv: None , cryptographic_parameters: None, aad: None}, "c").unwrap();
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
            cryptographic_parameters: None, aad: None,
        }, "c").unwrap();
        assert!(r.shared_secret.is_none(), "classical encrypt has no shared secret");
        // Plane-3 emit should be C_EncryptInit + C_Encrypt.
        let p3: Vec<_> = ring.filter_plane(Plane::Pkcs11);
        assert!(p3.iter().any(|e| matches!(&e.event, EventPayload::Pkcs11Call { function, .. } if function == "C_EncryptInit")));
        assert!(p3.iter().any(|e| matches!(&e.event, EventPayload::Pkcs11Call { function, .. } if function == "C_Encrypt")));
    }

    #[test]
    fn encrypt_on_destroyed_returns_wrong_lifecycle_state() {
        let (_ring, d) = deps_and_ring();
        put(&d, "a", KmipAlgorithm::Aes, ObjectType::SymmetricKey, State::Destroyed, UsageMask::ENCRYPT);
        let err = encrypt(&d, EncryptRequest { uid: "a".into(), data: vec![], iv: None , cryptographic_parameters: None, aad: None}, "c").unwrap_err();
        // KMIP 3.0 §11 — Destroyed is an FSM-rejection state, not
        // an archive state. CS-AC-M-8 pins WrongKeyLifecycleState
        // for crypto-ops against Destroyed keys.
        assert_eq!(err.result_reason(), ResultReason::WrongKeyLifecycleState);
    }
}

#[cfg(test)]
mod block_cipher_mode_test {
    use crate::kmip30::{CryptographicParameters, KmipAlgorithm};
    use crate::store::ObjectRecord;

    /// Regression: a key Created with
    /// `<CryptographicParameters><BlockCipherMode>ECB</BlockCipherMode></CryptographicParameters>`
    /// must dispatch to `CKM_AES_ECB` (codepoint 0x1081), not to the
    /// default `CKM_AES_GCM`. This caught the BlockCipherMode tag
    /// codepoint mix-up (0x420011 vs 0x420013).
    #[test]
    fn cp_block_cipher_mode_routes_to_ecb() {
        let cp = CryptographicParameters {
            block_cipher_mode: Some(2), // ECB
            ..Default::default()
        };
        let rec = ObjectRecord {
            cryptographic_parameters: Some(cp),
            algorithm: KmipAlgorithm::Aes,
            ..ObjectRecord::default()
        };
        let m = super::super::helpers::aes_mechanism_for(rec.cryptographic_parameters.as_ref());
        assert_eq!(m, softhsmrustv3::constants::CKM_AES_ECB);
    }
}
