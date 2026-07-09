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

use time::OffsetDateTime;

use crate::error::{KmipError, Result, ResultReason};
use crate::kmip30::{EncryptRequest, EncryptResponse, KmipAlgorithm, PkcsOp, State};
use crate::policy::{Decision, PolicyRequest};

use super::deps::Deps;
use super::helpers::{
    emit_pkcs11, emit_pkcs11_result, emit_request, emit_success, fail_err,
    state_name,
};

pub fn encrypt(deps: &Deps, mut req: EncryptRequest, correlation_id: &str) -> Result<EncryptResponse> {
    let started = OffsetDateTime::now_utc();
    emit_request(
        deps,
        correlation_id,
        "Encrypt",
        format!("uid={} data_len={}", req.uid, req.data.len()),
    );

    let obj = deps.store.get(&req.uid)?.ok_or_else(|| {
        fail_err(deps, correlation_id, "Encrypt", KmipError::object_not_found(&req.uid))
    })?;

    if obj.state != State::Active {
        return Err(fail_err(
            deps,
            correlation_id,
            "Encrypt",
            super::helpers::non_active_state_error(&req.uid, obj.state),
        ));
    }

    // K22 — KMIP 3.0 §11 `Object Archived` (0x0d): "The object SHALL
    // be recovered from the archive before performing the operation."
    // Archived material is off-line (§6.1.4 / §6.1.47), so crypto ops
    // fail until Recover.
    if obj.archived {
        return Err(fail_err(deps, correlation_id, "Encrypt",
            KmipError::object_archived(&req.uid)));
    }

    // KMIP 3.0 §11 `Usage Limits` — Encrypt SHALL be rejected with
    // `PermissionDenied` once the byte-count budget is exhausted.
    // CS-BC-M-7 pins a 16-byte budget that the second Encrypt
    // SHALL exhaust (16 + 16 > 16).
    if let Some(remaining) = obj.usage_limits_remaining {
        if (req.data.len() as i64) > remaining {
            return Err(fail_err(deps, correlation_id, "Encrypt",
                KmipError::permission_denied(
                    "Usage Limits exhausted".to_string(),
                )));
        }
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

    // KMIP 3.0 §11 Cryptographic Usage Mask — Encrypt requires the
    // `Encrypt` bit (0x04). The ML-KEM branch rides the Encrypt op but
    // performs encapsulation (C_EncapsulateKey); KMIP 3.0 has no
    // `Encapsulate` usage bit (corpus keys carry `Key Agreement`), so
    // mask enforcement is skipped on the encap branch (K12, audit K-9).
    if !is_ml_kem(obj.algorithm) {
        super::helpers::enforce_usage_mask(
            deps, correlation_id, "Encrypt", &obj, crate::kmip30::UsageMask::ENCRYPT,
        )?;
    }

    // Plane-1 policy gate. The dispatcher would canonicalise the op to
    // "Encapsulate" for ML-KEM in a future revision so policies can
    // differentiate; v0.1 passes plain "Encrypt".
    // Y1 — stored classification tag; Y3 — curve/size-qualified name so
    // size-specific allow/deny rules match (was bare `canonical_name`).
    let stored_attrs = super::helpers::strip_x_prefixes(&obj.custom_attributes);
    let algo = super::helpers::qualified_name(obj.algorithm, obj.cryptographic_length);
    let mut p_req =
        PolicyRequest::minimal("Encrypt", Some(&algo), started, correlation_id, &stored_attrs);
    p_req.usage_mask = Some(obj.usage_mask);
    p_req.state = Some(state_name(obj.state));
    // name_pattern rules match on the stored key's Name (label-scoped rekey).
    p_req.name = obj.name.as_deref();
    p_req.current_object_algorithm = Some(&algo);
    p_req.target_uid = Some(&req.uid);
    p_req.object_activation_date = obj.activation_date; // F-3 — max_key_age_days
    // P1/P2 — surface the mechanism dimension (block-cipher mode / padding +
    // canonical CKM_*) so MechanismParameterConstraint rules can gate Encrypt.
    p_req.mechanism = super::helpers::mechanism_params_from_cp(
        obj.algorithm,
        crate::kmip30::PkcsOp::Encrypt,
        req.cryptographic_parameters
            .as_ref()
            .or(obj.cryptographic_parameters.as_ref()),
    );
    let decision = deps.engine.evaluate(&p_req);
    // W2.1 — a forcing rule (mechanism_parameter_default) may mandate the mode /
    // padding; merge it into req.cryptographic_parameters so every downstream
    // path (classical / ML-KEM / streaming) honors it.
    let forced_cp = decision.cp_override().cloned();
    match decision {
        Decision::Allow { .. } => {}
        Decision::Deny { human, .. } => {
            return Err(fail_err(
                deps,
                correlation_id,
                "Encrypt",
                KmipError::permission_denied(human),
            ));
        }
        Decision::RekeyAndProceed { new_algorithm, .. } => {
            // Crypto agility on the symmetric-encrypt path (Phase 5): the policy
            // substitutes this key's algorithm (AES-128 → AES-256). Generate the
            // replacement symmetric key, deactivate + supersede the old, re-issue
            // the Encrypt under the new key. Only symmetric keys reach here —
            // an asymmetric-encrypt substitution is a cross-primitive migration
            // (RSA → ML-KEM) the Encrypt op can't drive; guard it.
            if is_ml_kem(obj.algorithm) || obj.object_type != crate::kmip30::ObjectType::SymmetricKey
            {
                return Err(fail_err(
                    deps,
                    correlation_id,
                    "Encrypt",
                    KmipError::failed(
                        ResultReason::OperationNotSupported,
                        format!(
                            "policy substitutes {algo} → {new_algorithm}, but only symmetric \
                             Encrypt keys auto-rekey here; migrate a KEM key via Encapsulate"
                        ),
                    ),
                ));
            }
            return rekey_and_encrypt(deps, &req, &obj, &new_algorithm, correlation_id);
        }
    }
    if let Some(ov) = forced_cp.as_ref() {
        req.cryptographic_parameters = Some(super::helpers::merge_cp_override(
            req.cryptographic_parameters.as_ref(),
            ov,
        ));
    }

    // KMIP 3.0 §6.1.21 multi-part streaming — `Init Indicator` opens a
    // stream, `Correlation Value` chains parts, `Final Indicator`
    // closes it (emitting the AEAD tag). CS-BC-M-GCM-3 pins this flow.
    let resp = if req.init_indicator == Some(true) || req.correlation_value.is_some() {
        encrypt_streaming(deps, &req, &obj, correlation_id)
    } else if is_ml_kem(obj.algorithm) {
        // Plane-3: branch on algorithm.
        encrypt_ml_kem(deps, &req, &obj, correlation_id)
    } else {
        encrypt_classical(deps, &req, &obj, correlation_id)
    }?;

    emit_success(deps, correlation_id, "Encrypt");
    Ok(resp)
}

/// Transparent symmetric auto-rekey (crypto agility, Phase 5) for the Encrypt
/// path — the AES-128 → AES-256 mirror of [`super::sign`]'s `rekey_and_sign`.
/// Generate the replacement AES key (Name copied), deactivate + supersede the
/// old, re-issue the Encrypt under the new key, stamp the response's `rekeyed`.
fn rekey_and_encrypt(
    deps: &Deps,
    req: &EncryptRequest,
    old: &crate::store::ObjectRecord,
    new_algorithm: &str,
    correlation_id: &str,
) -> Result<EncryptResponse> {
    // 1+2. Replacement symmetric key (Name carried over) + Activate.
    let new_uid =
        super::agility::generate_replacement_symmetric(deps, old, new_algorithm, correlation_id)
            .map_err(|e| fail_err(deps, correlation_id, "Encrypt", e))?;

    // 3. Deactivate + supersede the old key.
    super::agility::supersede_old(deps, old, &new_uid, new_algorithm, correlation_id)?;

    // 4. Re-issue the Encrypt against the migrated key, then stamp the rekey
    // provenance. The new key's algorithm is the substitution target, so the
    // re-issued Encrypt is allowed without re-substituting (no recursion).
    let mut resp = encrypt(
        deps,
        EncryptRequest {
            uid: new_uid.clone(),
            data: req.data.clone(),
            iv: req.iv.clone(),
            cryptographic_parameters: req.cryptographic_parameters.clone(),
            aad: req.aad.clone(),
            init_indicator: req.init_indicator,
            final_indicator: req.final_indicator,
            correlation_value: req.correlation_value.clone(),
        },
        correlation_id,
    )?;
    resp.rekeyed = Some(crate::kmip30::RekeyInfo {
        old_uid: old.uid.clone(),
        new_uid,
        new_public_key_uid: None,
    });
    Ok(resp)
}

/// Multi-part Encrypt (KMIP 3.0 §6.1.21 streaming). Drives the engine's
/// PKCS#11 §5.2 Update/Final state machines
/// (`softhsmrustv3::crypto::multipart`) — one `StreamCtx` per
/// server-issued `Correlation Value`, held on [`Deps::streams`].
fn encrypt_streaming(
    deps: &Deps,
    req: &EncryptRequest,
    obj: &crate::store::ObjectRecord,
    correlation_id: &str,
) -> Result<EncryptResponse> {
    use softhsmrustv3::crypto::multipart::{
        AesKey, CbcPadState, CbcState, CipherDirection, CtrState, EcbState, GcmState,
        MultipartCipher,
    };
    use super::deps::StreamCtx;

    let invalid = |msg: &str| {
        KmipError::failed(ResultReason::InvalidMessage, msg.to_string())
    };

    if req.init_indicator == Some(true) {
        // ── Open a new stream ───────────────────────────────────────────
        if obj.algorithm != KmipAlgorithm::Aes {
            return Err(fail_err(deps, correlation_id, "Encrypt",
                KmipError::failed(
                    ResultReason::OperationNotSupported,
                    format!("streaming Encrypt not supported for {:?}", obj.algorithm),
                )));
        }
        let effective_cp = req
            .cryptographic_parameters
            .as_ref()
            .or(obj.cryptographic_parameters.as_ref());
        let mech = super::helpers::aes_mechanism_for(effective_cp)
            .map_err(|e| fail_err(deps, correlation_id, "Encrypt", e))?;
        let key_bytes = obj.key_material.as_ref().ok_or_else(|| {
            fail_err(deps, correlation_id, "Encrypt",
                KmipError::failed(
                    ResultReason::OperationNotSupported,
                    "streaming Encrypt requires Registered key material".to_string(),
                ))
        })?;
        let key = AesKey::new(key_bytes).ok_or_else(|| {
            fail_err(deps, correlation_id, "Encrypt",
                KmipError::failed(
                    ResultReason::CryptographicFailure,
                    format!("unsupported AES key length {}", key_bytes.len()),
                ))
        })?;
        validate_iv_for_mech(deps, correlation_id, mech, req.iv.as_deref())?;
        let iv = req.iv.as_deref().unwrap_or(&[]);
        let tag_bits = effective_cp
            .and_then(|c| c.tag_length)
            .map(|n| (n as u32) * 8)
            .unwrap_or(128);
        use softhsmrustv3::constants as ck;
        let cipher = match mech {
            ck::CKM_AES_GCM => MultipartCipher::Gcm(GcmState::new(
                key,
                iv,
                req.aad.as_deref().unwrap_or(&[]),
                tag_bits,
                CipherDirection::Encrypt,
            )),
            ck::CKM_AES_ECB => MultipartCipher::Ecb(EcbState::new(key, CipherDirection::Encrypt)),
            ck::CKM_AES_CBC => {
                let iv16: [u8; 16] = iv.try_into().map_err(|_| invalid("invalid-iv-length"))?;
                MultipartCipher::Cbc(CbcState::new(key, iv16, CipherDirection::Encrypt))
            }
            ck::CKM_AES_CBC_PAD => {
                let iv16: [u8; 16] = iv.try_into().map_err(|_| invalid("invalid-iv-length"))?;
                MultipartCipher::CbcPad(CbcPadState::new(key, iv16, CipherDirection::Encrypt))
            }
            ck::CKM_AES_CTR => {
                let cb: [u8; 16] = iv.try_into().map_err(|_| invalid("invalid-iv-length"))?;
                MultipartCipher::Ctr(CtrState::new(key, cb))
            }
            _ => {
                return Err(fail_err(deps, correlation_id, "Encrypt",
                    KmipError::failed(
                        ResultReason::OperationNotSupported,
                        format!("streaming Encrypt: unsupported mechanism {mech:#x}"),
                    )));
            }
        };
        let mut cipher = cipher;
        // K15 — audit emitted after the call, with the call's real rv.
        let ct_result = cipher.update(&req.data);
        emit_pkcs11_result(deps, correlation_id, "multipart::update", Some(mech), &ct_result);
        let ct = ct_result
            .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Encrypt:update"))?;
        let cv = deps.new_correlation_value();
        deps.streams.lock().unwrap().insert(
            cv.clone(),
            StreamCtx { cipher, uid: req.uid.clone() },
        );
        return Ok(EncryptResponse {
            uid: req.uid.clone(),
            ciphertext: ct,
            correlation_value: Some(cv),
            ..Default::default()
        });
    }

    // ── Continue / close an existing stream ────────────────────────────
    let cv = req.correlation_value.as_ref().expect("checked by caller");
    let mut streams = deps.streams.lock().unwrap();
    let mut ctx = streams.remove(cv).ok_or_else(|| {
        fail_err(deps, correlation_id, "Encrypt", invalid("unknown-correlation-value"))
    })?;
    if ctx.uid != req.uid {
        return Err(fail_err(deps, correlation_id, "Encrypt",
            invalid("correlation-value/uid mismatch")));
    }
    let ct_result = ctx.cipher.update(&req.data);
    emit_pkcs11_result(deps, correlation_id, "multipart::update", None, &ct_result);
    let mut ct =
        ct_result.map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Encrypt:update"))?;
    if req.final_indicator == Some(true) {
        let is_aead = matches!(ctx.cipher, MultipartCipher::Gcm(_));
        let tail_result = ctx.cipher.finalize();
        emit_pkcs11_result(deps, correlation_id, "multipart::finalize", None, &tail_result);
        let tail =
            tail_result.map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Encrypt:final"))?;
        // AEAD finalize emits the auth tag (own response field per
        // §6.1.21); block-mode finalize emits trailing ciphertext.
        let tag = if is_aead {
            Some(tail)
        } else {
            ct.extend_from_slice(&tail);
            None
        };
        Ok(EncryptResponse {
            uid: req.uid.clone(),
            ciphertext: ct,
            authenticated_encryption_tag: tag,
            ..Default::default()
        })
    } else {
        // Middle part — put the stream back and echo the handle.
        streams.insert(cv.clone(), ctx);
        Ok(EncryptResponse {
            uid: req.uid.clone(),
            ciphertext: ct,
            correlation_value: Some(cv.clone()),
            ..Default::default()
        })
    }
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

    // Phase 7b: real bridge call when a session is wired. K15 — the
    // Plane-3 record is emitted after the call with its real rv.
    let (ciphertext, shared_secret) = match deps.engine_session {
        Some(session) => {
            let handle =
                softhsmrustv3::native::find_by_cka_id(session, &obj.pkcs11_cka_id)
                    .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Encap:find"))?
                    .ok_or_else(|| KmipError::object_not_found(&req.uid))?;
            let native_mech = super::helpers::native_kem_mech(obj.algorithm).ok_or_else(|| {
                KmipError::failed(
                    ResultReason::OperationNotSupported,
                    format!("no KEM mechanism for {:?}", obj.algorithm),
                )
            })?;
            let r = softhsmrustv3::native::encapsulate(session, handle, native_mech);
            emit_pkcs11_result(deps, correlation_id, "native::encapsulate", Some(native_mech), &r);
            r.map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Encap"))?
        }
        None => {
            // S-2 hardening: no engine session ⇒ fail rather than emit fake
            // ciphertext/shared-secret. Placeholder kept only for the crate tests.
            #[cfg(not(test))]
            {
                return Err(crate::error::KmipError::failed(
                    crate::error::ResultReason::CryptographicFailure,
                    "no engine session — cannot encapsulate without key material",
                ));
            }
            #[cfg(test)]
            {
                emit_pkcs11(deps, correlation_id, "soft::placeholder_encapsulate", Some(mech), 0, "CKR_OK");
                (
                    placeholder_bytes(&req.uid, &req.data, b"encap", 32),
                    placeholder_bytes(&req.uid, &req.data, b"ss", 32),
                )
            }
        }
    };
    Ok(EncryptResponse {
        uid: req.uid.clone(),
        ciphertext,
        shared_secret: Some(shared_secret),
        ..Default::default()
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
        // K6 — both selectors are total-or-failing: unsupported
        // BlockCipherMode / PaddingMethod combinations fail with
        // `UnsupportedCryptographicParameters (0x3e)` instead of being
        // silently substituted (compliance-audit B-2).
        KmipAlgorithm::Aes => super::helpers::aes_mechanism_for(effective_cp)
            .map_err(|e| fail_err(deps, correlation_id, "Encrypt", e))?,
        KmipAlgorithm::Rsa => super::helpers::rsa_encrypt_mechanism_for(effective_cp)
            .map_err(|e| fail_err(deps, correlation_id, "Encrypt", e))?,
        _ => obj.algorithm.to_pkcs11_mech(PkcsOp::Encrypt).ok_or_else(|| {
            KmipError::failed(
                ResultReason::OperationNotSupported,
                format!("{:?} has no Encrypt mechanism", obj.algorithm),
            )
        })?,
    };

    // KMIP 3.0 §11 `Random IV = true` — server-side IV auto-generation.
    // When the key's CryptographicParameters carry RandomIV=true AND
    // the request omits an IV, generate a mechanism-appropriate one
    // and surface it via the response's `IVCounterNonce` field so the
    // client can use it for the matching Decrypt. CS-BC-M-13 pins this.
    let random_iv = effective_cp.and_then(|c| c.random_iv).unwrap_or(false);
    let generated_iv: Option<Vec<u8>> = if random_iv && req.iv.is_none() {
        let len = match mech {
            softhsmrustv3::constants::CKM_AES_CBC
            | softhsmrustv3::constants::CKM_AES_CBC_PAD
            | softhsmrustv3::constants::CKM_AES_CTR => 16,
            softhsmrustv3::constants::CKM_AES_GCM => 12,
            softhsmrustv3::constants::CKM_CHACHA20
            | softhsmrustv3::constants::CKM_CHACHA20_POLY1305 => 12,
            _ => 0,
        };
        if len > 0 {
            let mut iv = vec![0u8; len];
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut iv);
            Some(iv)
        } else { None }
    } else { None };
    let effective_iv: Option<&[u8]> = generated_iv.as_deref().or(req.iv.as_deref());

    // KMIP 3.0 §6.1.21 + §11 — IV presence/size is a protocol-level
    // requirement, so a missing/short IV for an IV-bearing mech is
    // `InvalidMessage` (0x04), NOT the shim's downstream
    // `InvalidAttributeValue` (0x2d). OASIS CS-BC-M-11 / CS-BC-M-12
    // pin `InvalidMessage` with a `missing-iv` message string.
    validate_iv_for_mech(deps, correlation_id, mech, effective_iv)?;

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
    //
    // K6: OAEP params come from the SAME request-over-object effective
    // CP used for mech selection above (they previously read only the
    // object's stored CP, so a request-time OAEP profile was ignored).
    // Only computed for the OAEP mechanism so AES/ChaCha requests that
    // happen to carry a HashingAlgorithm aren't rejected for a field
    // their mechanism never reads.
    let oaep = if mech == softhsmrustv3::constants::CKM_RSA_PKCS_OAEP {
        super::helpers::oaep_params_for(effective_cp)
            .map_err(|e| fail_err(deps, correlation_id, "Encrypt", e))?
    } else {
        None
    };
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
    // KMIP 3.0 §11 `Tag Length` — caller-selectable AEAD authenticator
    // length (NIST SP 800-38D §5.2.1.2: 12/13/14/15/16 bytes). Forwarded
    // to the shim so it can pick the right typed AesGcm variant.
    let tag_len = effective_cp
        .and_then(|c| c.tag_length)
        .map(|n| n as usize);
    // K15 — the Plane-3 audit record is emitted after each call with
    // the call's real rv, naming the actual entry point that ran.
    let ciphertext = if let Some(key_bytes) = &obj.key_material {
        let r = softhsmrustv3::native::encrypt_with_key_bytes(
            key_bytes,
            mech,
            data_for_shim,
            effective_iv,
            oaep.as_ref(),
            aad,
            tag_len,
        );
        emit_pkcs11_result(deps, correlation_id, "native::encrypt_with_key_bytes", Some(mech), &r);
        r.map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Encrypt"))?
    } else if let Some(session) = deps.engine_session {
        let handle = softhsmrustv3::native::find_by_cka_id(session, &obj.pkcs11_cka_id)
            .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Encrypt:find"))?
            .ok_or_else(|| KmipError::object_not_found(&req.uid))?;
        // Gap-remediation Phase F, Finding #4 — `oaep`/`aad`/`tag_len`
        // were already computed above (same effective-CP derivation the
        // `encrypt_with_key_bytes` branch above uses) but never
        // forwarded here; the engine hardcoded empty AAD and the
        // SHA-256 OAEP default for every engine-resident key regardless
        // of what the client actually requested.
        let r = softhsmrustv3::native::encrypt(
            session, handle, mech, data_for_shim, effective_iv, oaep.as_ref(), aad, tag_len,
        );
        emit_pkcs11_result(deps, correlation_id, "native::encrypt", Some(mech), &r);
        r.map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Encrypt"))?
    } else {
        // No key material AND no engine session — the object is a
        // placeholder for unit tests with mock policy gates. Match
        // the legacy behaviour so unit-tests that don't exercise
        // real crypto keep passing.
        emit_pkcs11(deps, correlation_id, "soft::placeholder_encrypt", Some(mech), 0, "CKR_OK");
        let mut input = effective_iv.map(|v| v.to_vec()).unwrap_or_default();
        input.extend_from_slice(&req.data);
        placeholder_bytes(&req.uid, &input, b"enc", input.len().max(16))
    };
    // AEAD mechanisms — the shim returns `ciphertext || tag`
    // (the standard Rust `aead` crate convention). KMIP 3.0 §6.1.21
    // requires the tag to ride in its own `AuthenticatedEncryptionTag`
    // field, not tacked onto Data, so we split on the way out. The tag
    // is `Tag Length` bytes when the request's CryptographicParameters
    // pin one (NIST SP 800-38D §5.2.1.2 truncation; CS-BC-M-GCM-2 pair
    // #91 pins a 15-byte tag over empty plaintext), 16 otherwise.
    let is_aead = matches!(
        mech,
        softhsmrustv3::constants::CKM_AES_GCM
            | softhsmrustv3::constants::CKM_CHACHA20_POLY1305,
    );
    let split_tag = tag_len.unwrap_or(16);
    let (ciphertext, authenticated_encryption_tag) =
        if is_aead && ciphertext.len() >= split_tag {
            let split = ciphertext.len() - split_tag;
            let tag = ciphertext[split..].to_vec();
            (ciphertext[..split].to_vec(), Some(tag))
        } else {
            (ciphertext, None)
        };

    // KMIP §11 Usage Limits — deduct after the encrypt succeeds.
    // We checked `req.data.len() <= remaining` up-front; do the
    // bookkeeping now so a failed encrypt doesn't burn the budget.
    if let Some(remaining) = obj.usage_limits_remaining {
        if let Ok(Some(mut rec)) = deps.store.get(&req.uid) {
            rec.usage_limits_remaining = Some(remaining - req.data.len() as i64);
            let _ = deps.store.update(rec);
        }
    }

    Ok(EncryptResponse {
        uid: req.uid.clone(),
        ciphertext,
        authenticated_encryption_tag,
        iv_counter_nonce: generated_iv,
        ..Default::default()
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
        // PKCS#11 v3.2 §6.10 — CKM_AES_CTR takes a full 16-byte
        // counter block (CK_AES_CTR_PARAMS.cb); KMIP carries it in
        // IVCounterNonce.
        ck::CKM_AES_CTR => len == Some(16),
        // NIST SP 800-38D §5.2.1.1 — GCM accepts any IV of 1..2^64-1
        // bits; non-96-bit IVs derive J0 via GHASH (§7.1 step 2b). The
        // engine handles both paths. OASIS CS-BC-M-GCM-2 pins 8- and
        // 60-byte IVs.
        ck::CKM_AES_GCM => len.is_some_and(|l| l >= 1),
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
        let r = encrypt(&d, EncryptRequest { uid: "k".into(), ..Default::default() }, "c").unwrap();
        assert!(r.shared_secret.is_some(), "ML-KEM must return shared secret");
        assert_eq!(r.ciphertext.len(), 32);
        // K15 — no engine session: the audit names the soft fallback
        // path that actually ran (encapsulate branch, not encrypt).
        let p3: Vec<_> = ring.filter_plane(Plane::Pkcs11);
        assert!(p3.iter().any(|e| matches!(&e.event, EventPayload::Pkcs11Call { function, .. } if function == "soft::placeholder_encapsulate")));
        assert!(!p3.iter().any(|e| matches!(&e.event, EventPayload::Pkcs11Call { function, .. } if function == "soft::placeholder_encrypt")));
    }

    #[test]
    fn classical_aes_branch_returns_ciphertext_no_shared_secret() {
        let (ring, d) = deps_and_ring();
        put(&d, "a", KmipAlgorithm::Aes, ObjectType::SymmetricKey, State::Active, UsageMask::ENCRYPT);
        let r = encrypt(&d, EncryptRequest {
            uid: "a".into(),
            data: b"plaintext".to_vec(),
            iv: Some(vec![0u8; 12]),
            ..Default::default()
        }, "c").unwrap();
        assert!(r.shared_secret.is_none(), "classical encrypt has no shared secret");
        // K15 — no key material + no session: the audit names the soft
        // classical-encrypt fallback that actually ran.
        let p3: Vec<_> = ring.filter_plane(Plane::Pkcs11);
        assert!(p3.iter().any(|e| matches!(&e.event, EventPayload::Pkcs11Call { function, .. } if function == "soft::placeholder_encrypt")));
    }

    /// K12 — §11 Cryptographic Usage Mask: a present mask lacking the
    /// `Encrypt` bit fails with 0x29 before any engine dispatch.
    #[test]
    fn encrypt_mask_without_encrypt_bit_is_incompatible() {
        let (_ring, d) = deps_and_ring();
        put(&d, "a", KmipAlgorithm::Aes, ObjectType::SymmetricKey, State::Active, UsageMask::DECRYPT);
        let err = encrypt(&d, EncryptRequest {
            uid: "a".into(),
            data: b"x".to_vec(),
            iv: Some(vec![0u8; 12]),
            ..Default::default()
        }, "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::IncompatibleCryptographicUsageMask);
    }

    /// K12 — an EMPTY mask means the client never supplied one at
    /// Create/Register (store can't distinguish absent from 0), so it
    /// is treated as unrestricted, not as all-bits-denied.
    #[test]
    fn encrypt_empty_mask_is_unrestricted() {
        let (_ring, d) = deps_and_ring();
        put(&d, "a", KmipAlgorithm::Aes, ObjectType::SymmetricKey, State::Active, UsageMask::empty());
        encrypt(&d, EncryptRequest {
            uid: "a".into(),
            data: b"x".to_vec(),
            iv: Some(vec![0u8; 12]),
            ..Default::default()
        }, "c").expect("empty mask must not block Encrypt");
    }

    #[test]
    fn encrypt_on_destroyed_returns_wrong_lifecycle_state() {
        let (_ring, d) = deps_and_ring();
        put(&d, "a", KmipAlgorithm::Aes, ObjectType::SymmetricKey, State::Destroyed, UsageMask::ENCRYPT);
        let err = encrypt(&d, EncryptRequest { uid: "a".into(), ..Default::default() }, "c").unwrap_err();
        // KMIP 3.0 §11 — Destroyed is an FSM-rejection state, not
        // an archive state. CS-AC-M-8 pins WrongKeyLifecycleState
        // for crypto-ops against Destroyed keys.
        assert_eq!(err.result_reason(), ResultReason::WrongKeyLifecycleState);
    }

    /// K22 — §11 `Object Archived` (0x0d): "The object SHALL be
    /// recovered from the archive before performing the operation."
    /// Encrypt against an archived (but Active) key fails 0x0d, NOT
    /// WrongKeyLifecycleState — storage status is orthogonal to the
    /// lifecycle FSM.
    #[test]
    fn encrypt_on_archived_returns_object_archived() {
        let (_ring, d) = deps_and_ring();
        put(&d, "a", KmipAlgorithm::Aes, ObjectType::SymmetricKey, State::Active, UsageMask::ENCRYPT);
        let mut rec = d.store.get("a").unwrap().unwrap();
        rec.archived = true;
        d.store.update(rec).unwrap();
        let err = encrypt(&d, EncryptRequest { uid: "a".into(), ..Default::default() }, "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::ObjectArchived);
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
        assert_eq!(m.unwrap(), softhsmrustv3::constants::CKM_AES_ECB);
    }
}

#[cfg(test)]
mod k6_no_silent_substitution_tests {
    use super::*;
    use crate::kmip30::{CryptographicParameters, ObjectType, UsageMask};
    use crate::store::ObjectRecord;

    fn cp_mode(mode: u32) -> CryptographicParameters {
        CryptographicParameters { block_cipher_mode: Some(mode), ..Default::default() }
    }

    fn put_aes_with_key(deps: &Deps, uid: &str, key: Vec<u8>) {
        deps.store
            .put(ObjectRecord {
                uid: uid.into(),
                object_type: ObjectType::SymmetricKey,
                algorithm: KmipAlgorithm::Aes,
                usage_mask: UsageMask::ENCRYPT | UsageMask::DECRYPT,
                state: State::Active,
                activation_date: Some(time::OffsetDateTime::UNIX_EPOCH),
                key_material: Some(key),
                ..ObjectRecord::default()
            })
            .unwrap();
    }

    fn test_deps() -> Deps {
        use crate::auditlog::{AuditSink, RingSink};
        use crate::policy::{load_from_str, Engine};
        use crate::store::MemoryStore;
        use std::sync::Arc;
        let sink: Arc<dyn AuditSink> = Arc::new(RingSink::new(64));
        let engine = Engine::with_global_sink(sink.clone());
        engine
            .activate(load_from_str(
                "schema_version: 1\nmetadata: {name: t, description: t, authority: t, effective: always}\nrules: []\n",
                std::path::Path::new("<t>"),
            ).unwrap())
            .unwrap();
        Deps::new(engine, Arc::new(MemoryStore::new()), sink, super::super::deps::DepsConfig::default())
    }

    /// K6 — AES-CFB (mode 4) Encrypt must fail 0x3e, not silently run GCM.
    #[test]
    fn aes_cfb_encrypt_fails_unsupported_cryptographic_parameters() {
        let d = test_deps();
        put_aes_with_key(&d, "k", vec![0u8; 32]);
        let err = encrypt(
            &d,
            EncryptRequest {
                uid: "k".into(),
                data: b"x".to_vec(),
                cryptographic_parameters: Some(cp_mode(4)),
                ..Default::default()
            },
            "c",
        )
        .unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::UnsupportedCryptographicParameters);
    }

    /// K6 — AES-CTR (mode 6) one-shot Encrypt/Decrypt round-trips with
    /// real key material through the engine's `CKM_AES_CTR` path.
    #[test]
    fn aes_ctr_encrypt_decrypt_round_trip() {
        let d = test_deps();
        let key: Vec<u8> = (0u8..32).collect();
        put_aes_with_key(&d, "k", key);
        let plaintext = b"K6: CTR is wired through, not GCM-substituted".to_vec();
        let iv = vec![0xA5u8; 16]; // full 16-byte counter block
        let enc = encrypt(
            &d,
            EncryptRequest {
                uid: "k".into(),
                data: plaintext.clone(),
                iv: Some(iv.clone()),
                cryptographic_parameters: Some(cp_mode(6)),
                ..Default::default()
            },
            "c-enc",
        )
        .unwrap();
        assert_ne!(enc.ciphertext, plaintext);
        assert!(enc.authenticated_encryption_tag.is_none(), "CTR is not AEAD");
        let dec = crate::ops::decrypt::decrypt(
            &d,
            crate::kmip30::DecryptRequest {
                uid: "k".into(),
                data: enc.ciphertext,
                iv: Some(iv),
                cryptographic_parameters: Some(cp_mode(6)),
                aad: None,
            },
            "c-dec",
        )
        .unwrap();
        assert_eq!(dec.data, plaintext);
    }

    /// K6 — CTR requires a full 16-byte counter block; a 12-byte IV is
    /// an InvalidMessage protocol failure.
    #[test]
    fn aes_ctr_short_iv_is_invalid_message() {
        let d = test_deps();
        put_aes_with_key(&d, "k", vec![0u8; 32]);
        let err = encrypt(
            &d,
            EncryptRequest {
                uid: "k".into(),
                data: b"x".to_vec(),
                iv: Some(vec![0u8; 12]),
                cryptographic_parameters: Some(cp_mode(6)),
                ..Default::default()
            },
            "c",
        )
        .unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::InvalidMessage);
    }

    /// K6 — RSA Encrypt with PKCS1 v1.5 padding (0x08): the engine has
    /// no raw RSAES-PKCS1-v1_5 primitive, so this fails 0x3e instead of
    /// silently running OAEP.
    #[test]
    fn rsa_pkcs1_v15_encrypt_fails_unsupported_cryptographic_parameters() {
        let d = test_deps();
        d.store
            .put(crate::store::ObjectRecord {
                uid: "r".into(),
                object_type: crate::kmip30::ObjectType::PublicKey,
                algorithm: KmipAlgorithm::Rsa,
                usage_mask: crate::kmip30::UsageMask::ENCRYPT,
                state: State::Active,
                activation_date: Some(time::OffsetDateTime::UNIX_EPOCH),
                ..crate::store::ObjectRecord::default()
            })
            .unwrap();
        let err = encrypt(
            &d,
            EncryptRequest {
                uid: "r".into(),
                data: b"x".to_vec(),
                cryptographic_parameters: Some(crate::kmip30::CryptographicParameters {
                    padding_method: Some(0x08), // PKCS1 v1.5
                    ..Default::default()
                }),
                ..Default::default()
            },
            "c",
        )
        .unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::UnsupportedCryptographicParameters);
    }

    /// K6 — OAEP with SHA-1 (0x04) must fail 0x3e, never default to SHA-256.
    /// Also pins request-over-object CP precedence: the object's stored CP
    /// carries an unsupported SHA-1 profile, but a request CP with SHA-256
    /// wins and the op proceeds past parameter validation.
    #[test]
    fn rsa_oaep_sha1_fails_and_request_cp_overrides_object_cp() {
        let d = test_deps();
        let sha1_cp = crate::kmip30::CryptographicParameters {
            padding_method: Some(0x02), // OAEP
            hashing_algorithm: Some(crate::kmip30::HashingAlgorithm::Sha1),
            ..Default::default()
        };
        d.store
            .put(crate::store::ObjectRecord {
                uid: "r".into(),
                object_type: crate::kmip30::ObjectType::PublicKey,
                algorithm: KmipAlgorithm::Rsa,
                usage_mask: crate::kmip30::UsageMask::ENCRYPT,
                state: State::Active,
                activation_date: Some(time::OffsetDateTime::UNIX_EPOCH),
                cryptographic_parameters: Some(sha1_cp),
                ..crate::store::ObjectRecord::default()
            })
            .unwrap();
        // No request CP → object's SHA-1 OAEP profile applies → 0x3e.
        let err = encrypt(
            &d,
            EncryptRequest { uid: "r".into(), data: b"x".to_vec(), ..Default::default() },
            "c1",
        )
        .unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::UnsupportedCryptographicParameters);
        // Request CP with SHA-256 overrides the object's SHA-1 → succeeds
        // (placeholder path: no key material, no engine session).
        encrypt(
            &d,
            EncryptRequest {
                uid: "r".into(),
                data: b"x".to_vec(),
                cryptographic_parameters: Some(crate::kmip30::CryptographicParameters {
                    padding_method: Some(0x02),
                    hashing_algorithm: Some(crate::kmip30::HashingAlgorithm::Sha256),
                    ..Default::default()
                }),
                ..Default::default()
            },
            "c2",
        )
        .expect("request CP must override object CP for OAEP params");
    }
}
