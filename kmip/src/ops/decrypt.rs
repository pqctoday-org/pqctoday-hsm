//! KMIP 3.0 §6.1.16 **Decrypt** operation.
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

use time::OffsetDateTime;

use crate::error::{KmipError, Result, ResultReason};
use crate::kmip30::{DecryptRequest, DecryptResponse, KmipAlgorithm, PkcsOp, State};
use crate::policy::{Decision, PolicyRequest};

use super::deps::Deps;
use super::helpers::{
    authorize_object, emit_pkcs11, emit_pkcs11_result, emit_request, emit_success, fail_err,
    state_name,
};

pub fn decrypt(
    deps: &Deps,
    req: DecryptRequest,
    auth: &crate::server::auth::AuthContext,
    correlation_id: &str,
) -> Result<DecryptResponse> {
    let started = OffsetDateTime::now_utc();
    emit_request(
        deps,
        correlation_id,
        "Decrypt",
        format!("uid={} data_len={}", req.uid, req.data.len()),
    );

    // Part F §F7.4 — owner-checked lookup (see get.rs for the pattern).
    let obj = authorize_object(deps, auth, &req.uid, || KmipError::object_not_found(&req.uid))
        .map_err(|e| fail_err(deps, correlation_id, "Decrypt", e))?;

    // Lifecycle gate per §3.4 — Decrypt allowed in Active / Deactivated /
    // Compromised; PreActive and Destroyed rejected.
    match obj.state {
        State::Active | State::Deactivated | State::Compromised => {}
        _ => {
            return Err(fail_err(
                deps,
                correlation_id,
                "Decrypt",
                super::helpers::non_active_state_error(&req.uid, obj.state),
            ));
        }
    }

    // K22 — KMIP 3.0 §11 `Object Archived` (0x0d): "The object SHALL
    // be recovered from the archive before performing the operation."
    if obj.archived {
        return Err(fail_err(deps, correlation_id, "Decrypt",
            KmipError::object_archived(&req.uid)));
    }

    // KMIP 3.0 §3.4 — `Process Start Date` / `Protect Stop Date`
    // mirror gate: Decrypt also requires `now >= ProcessStartDate`
    // (the key hasn't started its processing window yet otherwise).
    // CS-BC-M-14 pins both edges for Decrypt as well as Encrypt.
    if let Some(t) = obj.process_start_date {
        if started < t {
            return Err(fail_err(deps, correlation_id, "Decrypt",
                KmipError::failed(
                    crate::error::ResultReason::WrongKeyLifecycleState,
                    "Decrypt: now < ProcessStartDate".to_string(),
                )));
        }
    }
    if let Some(t) = obj.protect_stop_date {
        if started > t {
            return Err(fail_err(deps, correlation_id, "Decrypt",
                KmipError::failed(
                    crate::error::ResultReason::WrongKeyLifecycleState,
                    "Decrypt: now > ProtectStopDate".to_string(),
                )));
        }
    }

    // KMIP 3.0 §11 Cryptographic Usage Mask — Decrypt requires the
    // `Decrypt` bit (0x08). The ML-KEM branch rides the Decrypt op but
    // performs decapsulation (C_DecapsulateKey); KMIP 3.0 has no
    // `Decapsulate` usage bit (corpus keys carry `Key Agreement`), so
    // mask enforcement is skipped on the decap branch (K12, audit K-9).
    if !is_ml_kem(obj.algorithm) {
        super::helpers::enforce_usage_mask(
            deps, correlation_id, "Decrypt", &obj, crate::kmip30::UsageMask::DECRYPT,
        )?;
    }

    // Plane-1 policy gate. Y1 stored classification; Y3 qualified name.
    let stored_attrs = super::helpers::strip_x_prefixes(&obj.custom_attributes);
    let algo = super::helpers::qualified_name(obj.algorithm, obj.cryptographic_length);
    let mut p_req =
        PolicyRequest::minimal("Decrypt", Some(&algo), started, correlation_id, &stored_attrs);
    p_req.usage_mask = Some(obj.usage_mask);
    p_req.state = Some(state_name(obj.state));
    // name_pattern rules match on the stored key's Name (label-scoped rekey).
    p_req.name = obj.name.as_deref();
    p_req.current_object_algorithm = Some(&algo);
    p_req.target_uid = Some(&req.uid);
    p_req.object_activation_date = obj.activation_date; // F-3 — max_key_age_days
    // Y16 — surface the mechanism dimension so mechanism/hash/mode rules gate
    // Decrypt too (was a silent no-op — populated only on Sign/Encrypt before).
    p_req.mechanism = super::helpers::mechanism_params_from_cp(
        obj.algorithm,
        crate::kmip30::PkcsOp::Encrypt,
        req.cryptographic_parameters
            .as_ref()
            .or(obj.cryptographic_parameters.as_ref()),
    );
    // 2026-07-05 hardening: exhaustive match, not `if let Deny` — see the
    // identical note in derive_key.rs. Decrypt is a consumer op
    // (`policy::rule::is_consumer_op`): its ciphertext was already fixed by
    // an earlier Encrypt, so a substitution rule can never coherently apply
    // here; the engine/loader already guard against it, this is
    // defense-in-depth so a weakened guard fails loudly, not silently.
    match deps.engine.evaluate(&p_req) {
        Decision::Allow { .. } => {}
        Decision::Deny { kmip_reason, human, .. } => {
            return Err(fail_err(
                deps,
                correlation_id,
                "Decrypt",
                KmipError::failed(kmip_reason.to_result_reason(), human),
            ));
        }
        Decision::RekeyAndProceed { .. } => {
            return Err(fail_err(
                deps,
                correlation_id,
                "Decrypt",
                KmipError::failed(
                    ResultReason::OperationNotSupported,
                    "Decrypt: policy requires rekey, which Decrypt cannot execute",
                ),
            ));
        }
    }

    // Plane-3: branch on algorithm — but a multi-part request comes first,
    // exactly as `encrypt` decides (§6.1.21, G6). Before this branch existed
    // a streaming Decrypt fell through to the single-shot path and returned
    // Success with wrong plaintext.
    let resp = if req.init_indicator == Some(true) || req.correlation_value.is_some() {
        decrypt_streaming(deps, &req, &obj, auth, correlation_id)
    } else if is_ml_kem(obj.algorithm) {
        decrypt_ml_kem(deps, &req, &obj, auth, correlation_id)
    } else {
        decrypt_classical(deps, &req, &obj, auth, correlation_id)
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
    auth: &crate::server::auth::AuthContext,
    correlation_id: &str,
) -> Result<DecryptResponse> {
    let mech = obj.algorithm.to_pkcs11_mech(PkcsOp::Decrypt).ok_or_else(|| {
        KmipError::failed(
            ResultReason::OperationNotSupported,
            format!("ML-KEM {:?} has no Decrypt mechanism", obj.algorithm),
        )
    })?;

    // K15 — the Plane-3 record is emitted after the call with its real rv.
    let shared_secret = match deps.resolve_tenant_session(auth.identity.as_ref()).ok() {
        Some(session) => {
            // WP-4 remediation — class-aware, not the ambiguous class-blind
            // find_by_cka_id: a certified private key now shares its
            // CKA_ID with its public key AND a linked certificate.
            let handle = super::helpers::find_handle_for_object(
                session, &obj.pkcs11_cka_id, obj.object_type,
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
                emit_pkcs11(deps, correlation_id, "soft::placeholder_decapsulate", Some(mech), 0, "CKR_OK");
                placeholder_bytes(&req.uid, &req.data, b"ss", 32)
            }
        }
    };
    // §4.13.2 — count a successful Decrypt.
    super::helpers::bump_counter(deps, &req.uid, super::helpers::Counter::Decrypt);
    Ok(DecryptResponse { uid: req.uid.clone(), data: shared_secret, correlation_value: None })
}


/// §6.1.21 multi-part Decrypt (G6, 2026-09-06) — the mirror of
/// `encrypt::encrypt_streaming`, sharing the same `Deps::streams` map and the
/// same engine `MultipartCipher` with `CipherDirection::Decrypt`.
///
/// Before this existed, `DecryptRequest` had no Init/Final/Correlation fields
/// and the decoder dropped those tags, so every part of a multi-part Decrypt
/// was processed as a complete message: the client got `Success` and wrong
/// plaintext. That is the one defect in the 2026-09-06 audit that returned a
/// wrong ANSWER rather than an incomplete one.
fn decrypt_streaming(
    deps: &Deps,
    req: &DecryptRequest,
    obj: &crate::store::ObjectRecord,
    auth: &crate::server::auth::AuthContext,
    correlation_id: &str,
) -> Result<DecryptResponse> {
    use softhsmrustv3::crypto::multipart::{
        AesKey, CbcPadState, CbcState, CipherDirection, CtrState, EcbState, GcmState,
        MultipartCipher,
    };
    use super::deps::StreamCtx;

    let invalid = |msg: &str| KmipError::failed(ResultReason::InvalidMessage, msg.to_string());

    if req.init_indicator == Some(true) {
        if obj.algorithm != KmipAlgorithm::Aes {
            return Err(fail_err(deps, correlation_id, "Decrypt",
                KmipError::failed(
                    ResultReason::OperationNotSupported,
                    format!("streaming Decrypt not supported for {:?}", obj.algorithm),
                )));
        }
        let effective_cp = req
            .cryptographic_parameters
            .as_ref()
            .or(obj.cryptographic_parameters.as_ref());
        let mech = super::helpers::aes_mechanism_for(effective_cp)
            .map_err(|e| fail_err(deps, correlation_id, "Decrypt", e))?;
        let key_bytes = obj.key_material.as_ref().ok_or_else(|| {
            fail_err(deps, correlation_id, "Decrypt",
                KmipError::failed(
                    ResultReason::OperationNotSupported,
                    "streaming Decrypt requires Registered key material".to_string(),
                ))
        })?;
        let key = AesKey::new(key_bytes).ok_or_else(|| {
            fail_err(deps, correlation_id, "Decrypt",
                KmipError::failed(
                    ResultReason::CryptographicFailure,
                    format!("unsupported AES key length {}", key_bytes.len()),
                ))
        })?;
        let iv = req.iv.as_deref().unwrap_or(&[]);
        let tag_bits = effective_cp
            .and_then(|c| c.tag_length)
            .map(|n| (n as u32) * 8)
            .unwrap_or(128);
        use softhsmrustv3::constants as ck;
        let cipher = match mech {
            ck::CKM_AES_GCM => MultipartCipher::Gcm(GcmState::new(
                key, iv, req.aad.as_deref().unwrap_or(&[]), tag_bits, CipherDirection::Decrypt,
            )),
            ck::CKM_AES_ECB => MultipartCipher::Ecb(EcbState::new(key, CipherDirection::Decrypt)),
            ck::CKM_AES_CBC => {
                let iv16: [u8; 16] = iv.try_into().map_err(|_| invalid("invalid-iv-length"))?;
                MultipartCipher::Cbc(CbcState::new(key, iv16, CipherDirection::Decrypt))
            }
            ck::CKM_AES_CBC_PAD => {
                let iv16: [u8; 16] = iv.try_into().map_err(|_| invalid("invalid-iv-length"))?;
                MultipartCipher::CbcPad(CbcPadState::new(key, iv16, CipherDirection::Decrypt))
            }
            // CTR is its own inverse — one state type, no direction.
            ck::CKM_AES_CTR => {
                let cb: [u8; 16] = iv.try_into().map_err(|_| invalid("invalid-iv-length"))?;
                MultipartCipher::Ctr(CtrState::new(key, cb))
            }
            _ => {
                return Err(fail_err(deps, correlation_id, "Decrypt",
                    KmipError::failed(
                        ResultReason::OperationNotSupported,
                        format!("streaming Decrypt: unsupported mechanism {mech:#x}"),
                    )));
            }
        };
        let mut cipher = cipher;
        let pt_result = cipher.update(&req.data);
        emit_pkcs11_result(deps, correlation_id, "multipart::update", Some(mech), &pt_result);
        let pt = pt_result
            .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Decrypt:update"))?;
        let cv = deps.new_correlation_value();
        deps.streams.lock().unwrap().insert(
            cv.clone(),
            StreamCtx {
                cipher,
                uid: req.uid.clone(),
                owner: auth.identity.as_ref().map(|i| i.username.clone()),
            },
        );
        return Ok(DecryptResponse {
            uid: req.uid.clone(),
            data: pt,
            correlation_value: Some(cv),
        });
    }

    // ── Continue / close ────────────────────────────────────────────────
    let cv = req.correlation_value.as_ref().expect("checked by caller");
    let mut streams = deps.streams.lock().unwrap();
    let mut ctx = streams.remove(cv).ok_or_else(|| {
        fail_err(deps, correlation_id, "Decrypt", invalid("unknown-correlation-value"))
    })?;
    // Same anti-oracle stance as Encrypt: a foreign continuation reads as an
    // unknown handle, and the stream is put BACK so a stranger cannot destroy
    // the owner's in-flight state.
    if ctx.owner != auth.identity.as_ref().map(|i| i.username.clone()) {
        streams.insert(cv.clone(), ctx);
        return Err(fail_err(deps, correlation_id, "Decrypt", invalid("unknown-correlation-value")));
    }
    if ctx.uid != req.uid {
        return Err(fail_err(deps, correlation_id, "Decrypt",
            invalid("correlation-value/uid mismatch")));
    }
    let pt_result = ctx.cipher.update(&req.data);
    emit_pkcs11_result(deps, correlation_id, "multipart::update", None, &pt_result);
    let mut pt =
        pt_result.map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Decrypt:update"))?;
    if req.final_indicator == Some(true) {
        let tail_result = ctx.cipher.finalize();
        emit_pkcs11_result(deps, correlation_id, "multipart::finalize", None, &tail_result);
        // On the decrypt side finalize returns trailing plaintext (or, for
        // AEAD, fails the tag check) — never a tag to hand back.
        let tail = tail_result
            .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Decrypt:final"))?;
        pt.extend_from_slice(&tail);
        super::helpers::bump_counter(deps, &req.uid, super::helpers::Counter::Decrypt);
        Ok(DecryptResponse { uid: req.uid.clone(), data: pt, correlation_value: None })
    } else {
        streams.insert(cv.clone(), ctx);
        Ok(DecryptResponse {
            uid: req.uid.clone(),
            data: pt,
            correlation_value: Some(cv.clone()),
        })
    }
}

/// Classical decrypt — C_DecryptInit + C_Decrypt.
fn decrypt_classical(
    deps: &Deps,
    req: &DecryptRequest,
    obj: &crate::store::ObjectRecord,
    auth: &crate::server::auth::AuthContext,
    correlation_id: &str,
) -> Result<DecryptResponse> {
    // KMIP 3.0 §6.1.23 — request-time `CryptographicParameters`
    // override the key-attached value (mirrors Encrypt). The Baseline
    // CS-BC tests put the mode on the call, not the key.
    let effective_cp = req
        .cryptographic_parameters
        .as_ref()
        .or(obj.cryptographic_parameters.as_ref());
    let mech = match obj.algorithm {
        // K6 — total-or-failing mech selection (mirror of Encrypt):
        // unsupported BlockCipherMode / PaddingMethod fail 0x3e instead
        // of silently substituting GCM/OAEP (compliance-audit B-2).
        KmipAlgorithm::Aes => super::helpers::aes_mechanism_for(effective_cp)
            .map_err(|e| fail_err(deps, correlation_id, "Decrypt", e))?,
        KmipAlgorithm::Rsa => super::helpers::rsa_encrypt_mechanism_for(effective_cp)
            .map_err(|e| fail_err(deps, correlation_id, "Decrypt", e))?,
        _ => obj.algorithm.to_pkcs11_mech(PkcsOp::Decrypt).ok_or_else(|| {
            KmipError::failed(
                ResultReason::OperationNotSupported,
                format!("{:?} has no Decrypt mechanism", obj.algorithm),
            )
        })?,
    };

    // KMIP 3.0 §6.1.23 + §11 — IV presence/size mismatches surface
    // as `InvalidMessage` per spec (mirror of the Encrypt path).
    super::encrypt::validate_iv_for_mech(deps, correlation_id, mech, req.iv.as_deref())?;

    // KMIP 3.0 §6.1.23 Decrypt — Plane-3 dispatch through the
    // PKCS#11 bridge. Mirrors the Encrypt path:
    //   1. obj.key_material set (Register'd by client) → bridge with
    //      raw bytes (RSA-OAEP private key DER for OAEP-* tests).
    //   2. Engine session → look up the engine handle by CKA_ID.
    //   3. Neither → placeholder for unit-test path.
    // K6: OAEP params come from the SAME request-over-object effective
    // CP used for mech selection (mirror of Encrypt); only computed for
    // the OAEP mechanism so symmetric requests carrying a stray
    // HashingAlgorithm aren't rejected for an unread field.
    let oaep = if mech == softhsmrustv3::constants::CKM_RSA_PKCS_OAEP {
        super::helpers::oaep_params_for(effective_cp)
            .map_err(|e| fail_err(deps, correlation_id, "Decrypt", e))?
    } else {
        None
    };
    let aad = req.aad.as_deref().unwrap_or(&[]);
    let pkcs7_strip_ecb = mech == softhsmrustv3::constants::CKM_AES_ECB
        && effective_cp.and_then(|c| c.padding_method) == Some(3);
    // KMIP 3.0 §11 `Tag Length` — caller-selectable AEAD authenticator
    // length forwarded to the shim. CS-BC-M-GCM-1 step #6 pins 12.
    let tag_len = effective_cp
        .and_then(|c| c.tag_length)
        .map(|n| n as usize);
    // K15 — the Plane-3 audit record is emitted after each call with
    // the call's real rv, naming the actual entry point that ran.
    let mut plaintext = if let Some(key_bytes) = &obj.key_material {
        let r = softhsmrustv3::native::decrypt_with_key_bytes(
            key_bytes,
            mech,
            &req.data,
            req.iv.as_deref(),
            oaep.as_ref(),
            aad,
            tag_len,
        );
        emit_pkcs11_result(deps, correlation_id, "native::decrypt_with_key_bytes", Some(mech), &r);
        r.map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Decrypt"))?
    } else if let Some(session) = deps.resolve_tenant_session(auth.identity.as_ref()).ok() {
        // WP-4 remediation — class-aware, not the ambiguous class-blind
        // find_by_cka_id: a certified RSA private key now shares its
        // CKA_ID with its public key AND a linked certificate.
        let handle = super::helpers::find_handle_for_object(
            session, &obj.pkcs11_cka_id, obj.object_type,
        )
            .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Decrypt:find"))?
            .ok_or_else(|| KmipError::object_not_found(&req.uid))?;
        // Gap-remediation Phase F, Finding #4 — same fix as Encrypt's
        // handle-based branch: forward the already-computed
        // oaep/aad/tag_len instead of letting the engine silently
        // apply its hardcoded defaults for an engine-resident key.
        let r = softhsmrustv3::native::decrypt(
            session, handle, mech, &req.data, req.iv.as_deref(), oaep.as_ref(), aad, tag_len,
        );
        emit_pkcs11_result(deps, correlation_id, "native::decrypt", Some(mech), &r);
        r.map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Decrypt"))?
    } else {
        emit_pkcs11(deps, correlation_id, "soft::placeholder_decrypt", Some(mech), 0, "CKR_OK");
        let mut input = req.iv.clone().unwrap_or_default();
        input.extend_from_slice(&req.data);
        placeholder_bytes(&req.uid, &input, b"dec", input.len().max(16))
    };
    // KMIP 3.0 §11 PKCS5 strip — mirror of the Encrypt-side pad
    // (see `encrypt.rs::pkcs7_pad_ecb`). The last byte tells us how
    // many pad bytes to drop; validate it's in [1, 16] for a real
    // PKCS#7 stream, otherwise leave the buffer untouched.
    if pkcs7_strip_ecb {
        if let Some(&pad) = plaintext.last() {
            if (1..=16).contains(&pad) && plaintext.len() >= pad as usize {
                plaintext.truncate(plaintext.len() - pad as usize);
            }
        }
    }
    // §4.13.2 — count a successful Decrypt.
    super::helpers::bump_counter(deps, &req.uid, super::helpers::Counter::Decrypt);
    Ok(DecryptResponse { uid: req.uid.clone(), data: plaintext, correlation_value: None })
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
            .replace_all(load_from_str(
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
    fn ml_kem_branch_calls_decapsulate() {
        let (ring, d) = deps_and_ring();
        put(&d, "k", KmipAlgorithm::MlKem1024, ObjectType::PrivateKey, State::Active, UsageMask::KEY_AGREEMENT);
        let r = decrypt(&d, DecryptRequest { uid: "k".into(), data: vec![0u8; 1568], iv: None , cryptographic_parameters: None, aad: None, init_indicator: None, final_indicator: None, correlation_value: None}, &crate::server::auth::AuthContext::open(), "c").unwrap();
        assert_eq!(r.data.len(), 32, "shared secret length");
        // K15 — no engine session: the audit names the soft decap
        // fallback that actually ran, not the classical decrypt path.
        let p3: Vec<_> = ring.filter_plane(Plane::Pkcs11);
        assert!(p3.iter().any(|e| matches!(&e.event, EventPayload::Pkcs11Call { function, .. } if function == "soft::placeholder_decapsulate")));
        assert!(!p3.iter().any(|e| matches!(&e.event, EventPayload::Pkcs11Call { function, .. } if function == "soft::placeholder_decrypt")));
    }

    /// K12 — §11 Cryptographic Usage Mask: a present mask lacking the
    /// `Decrypt` bit fails with 0x29. The ML-KEM decap branch is exempt
    /// (no Decapsulate bit exists; corpus keys carry Key Agreement) —
    /// pinned by `ml_kem_branch_calls_decapsulate` above succeeding
    /// with a KEY_AGREEMENT-only mask.
    #[test]
    fn decrypt_mask_without_decrypt_bit_is_incompatible() {
        let (_ring, d) = deps_and_ring();
        put(&d, "a", KmipAlgorithm::Aes, ObjectType::SymmetricKey, State::Active, UsageMask::ENCRYPT);
        let err = decrypt(&d, DecryptRequest {
            uid: "a".into(),
            data: vec![0; 32],
            iv: Some(vec![0; 12]),
            cryptographic_parameters: None,
            aad: None, init_indicator: None, final_indicator: None, correlation_value: None }, &crate::server::auth::AuthContext::open(), "c").unwrap_err();
        assert_eq!(
            err.result_reason(),
            crate::error::ResultReason::IncompatibleCryptographicUsageMask
        );
    }

    #[test]
    fn classical_branch_audits_soft_decrypt_path() {
        let (ring, d) = deps_and_ring();
        put(&d, "a", KmipAlgorithm::Aes, ObjectType::SymmetricKey, State::Active, UsageMask::DECRYPT);
        let _r = decrypt(&d, DecryptRequest { uid: "a".into(), data: vec![0; 32], iv: Some(vec![0; 12]) , cryptographic_parameters: None, aad: None, init_indicator: None, final_indicator: None, correlation_value: None}, &crate::server::auth::AuthContext::open(), "c").unwrap();
        // K15 — no key material + no session: soft fallback is named.
        let p3: Vec<_> = ring.filter_plane(Plane::Pkcs11);
        assert!(p3.iter().any(|e| matches!(&e.event, EventPayload::Pkcs11Call { function, .. } if function == "soft::placeholder_decrypt")));
    }

    #[test]
    fn decrypt_allowed_in_deactivated_state() {
        let (_ring, d) = deps_and_ring();
        put(&d, "a", KmipAlgorithm::Aes, ObjectType::SymmetricKey, State::Deactivated, UsageMask::DECRYPT);
        // AES-GCM (the default for KmipAlgorithm::Aes) requires a
        // 12-byte IV per KMIP 3.0 §6.1.21 + NIST SP 800-38D. Supply
        // one so the lifecycle gate is what's actually under test.
        let _ = decrypt(&d, DecryptRequest { uid: "a".into(), data: vec![0; 32], iv: Some(vec![0; 12]) , cryptographic_parameters: None, aad: None, init_indicator: None, final_indicator: None, correlation_value: None}, &crate::server::auth::AuthContext::open(), "c").unwrap();
    }

    #[test]
    fn decrypt_pre_active_rejected() {
        let (_ring, d) = deps_and_ring();
        put(&d, "a", KmipAlgorithm::Aes, ObjectType::SymmetricKey, State::PreActive, UsageMask::DECRYPT);
        let err = decrypt(&d, DecryptRequest { uid: "a".into(), data: vec![0; 32], iv: None , cryptographic_parameters: None, aad: None, init_indicator: None, final_indicator: None, correlation_value: None}, &crate::server::auth::AuthContext::open(), "c").unwrap_err();
        // KMIP 3.0 §11: PreActive is a lifecycle-state failure, not
        // "object archived". ObjectArchived (0x0d) is reserved for
        // Destroyed* per §6.1.19.
        assert_eq!(err.result_reason(), ResultReason::WrongKeyLifecycleState);
    }

    /// G6 (2026-09-06) — the round trip that was broken: encrypt in parts,
    /// then DECRYPT IN PARTS and get the original bytes back.
    ///
    /// Before `decrypt_streaming` existed, `DecryptRequest` had no
    /// Init/Final/Correlation fields and the decoder dropped those tags, so
    /// each part was decrypted as if it were a whole message. The client got
    /// `Success` and wrong plaintext — a wrong ANSWER, not a refusal.
    ///
    /// Tests the SEAM (encrypt-parts → decrypt-parts), not each half against
    /// itself: a single-shot round trip passed throughout the broken period.
    #[test]
    fn multipart_decrypt_reassembles_what_multipart_encrypt_produced() {
        use crate::kmip30::EncryptRequest;
        let (_r, d) = deps_and_ring();
        let mut rec = ObjectRecord {
            uid: "aes".into(),
            object_type: ObjectType::SymmetricKey,
            algorithm: KmipAlgorithm::Aes,
            cryptographic_length: 128,
            usage_mask: UsageMask::ENCRYPT | UsageMask::DECRYPT,
            state: State::Active,
            initial_date: OffsetDateTime::UNIX_EPOCH,
            activation_date: Some(OffsetDateTime::UNIX_EPOCH),
            ..ObjectRecord::default()
        };
        rec.key_material = Some(vec![0x42; 16]);
        // ECB keeps the test about STREAM ASSEMBLY rather than IV handling.
        rec.cryptographic_parameters = Some(crate::kmip30::CryptographicParameters {
            block_cipher_mode: Some(0x02),
            ..Default::default()
        });
        d.store.put(rec).unwrap();

        let auth = crate::server::auth::AuthContext::open();
        let part1 = vec![0xAAu8; 16];
        let part2 = vec![0xBBu8; 16];

        // Encrypt in two parts.
        let e1 = crate::ops::encrypt::encrypt(&d, EncryptRequest {
            uid: "aes".into(), data: part1.clone(), init_indicator: Some(true), ..Default::default()
        }, &auth, "c").unwrap();
        let cv = e1.correlation_value.clone().expect("stream handle on the opening part");
        let e2 = crate::ops::encrypt::encrypt(&d, EncryptRequest {
            uid: "aes".into(), data: part2.clone(), correlation_value: Some(cv),
            final_indicator: Some(true), ..Default::default()
        }, &auth, "c").unwrap();
        let ciphertext: Vec<u8> = e1.ciphertext.iter().chain(e2.ciphertext.iter()).copied().collect();
        assert_eq!(ciphertext.len(), 32, "two AES blocks in, two out");

        // Decrypt the SAME ciphertext in two parts.
        let d1 = decrypt(&d, DecryptRequest {
            uid: "aes".into(), data: ciphertext[..16].to_vec(),
            init_indicator: Some(true), final_indicator: None, correlation_value: None,
            iv: None, cryptographic_parameters: None, aad: None,
        }, &auth, "c").unwrap();
        let dcv = d1.correlation_value.clone()
            .expect("Decrypt must issue a stream handle — without it the client cannot continue");
        let d2 = decrypt(&d, DecryptRequest {
            uid: "aes".into(), data: ciphertext[16..].to_vec(),
            init_indicator: None, final_indicator: Some(true), correlation_value: Some(dcv),
            iv: None, cryptographic_parameters: None, aad: None,
        }, &auth, "c").unwrap();

        let recovered: Vec<u8> = d1.data.iter().chain(d2.data.iter()).copied().collect();
        let original: Vec<u8> = part1.iter().chain(part2.iter()).copied().collect();
        assert_eq!(recovered, original,
            "multi-part decrypt must reassemble the original plaintext");
    }
}
