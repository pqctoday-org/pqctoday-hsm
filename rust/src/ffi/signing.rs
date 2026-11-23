// SPDX-License-Identifier: AGPL-3.0-only
//! PKCS#11 single-part and multipart signing entry points.
use super::*;

#[wasm_bindgen(js_name = _C_SignInit)]
pub fn C_SignInit(h_session: u32, p_mechanism: *mut u8, h_key: u32) -> u32 {
    // Read the mechanism and key identity BEFORE dispatch: a failed init can
    // tear down session state, and the key identity is most wanted on exactly
    // those records.
    let logging = crate::oplog::enabled();
    let ring = crate::behaviour::enabled();
    let mech = if (logging || ring) && !p_mechanism.is_null() {
        unsafe { ck_param::mech(p_mechanism).mechanism }
    } else {
        0
    };
    let key_fields = if logging {
        crate::oplog::key_fields(h_key, mech)
    } else {
        String::new()
    };
    // Timed only when a sink will see the figure: a logging-off, ring-off
    // run pays no clock read (hsm-perf-bench's measured configuration).
    let t0 = (logging || ring).then(std::time::Instant::now);

    let rv = C_SignInit_impl(h_session, p_mechanism, h_key);

    let dur = crate::behaviour::elapsed_us(t0);
    if logging {
        crate::oplog::emit(
            "C_SignInit",
            &format!(
                "sess={} mech={} mech_id=0x{:08x} {}{} rv={} rv_id=0x{:08x} dur={}",
                h_session,
                crate::oplog::mech_name(mech),
                mech,
                key_fields,
                if rv == CKR_OK { supplied_log_field(&SIGN_SUPPLIED, h_session) } else { "" },
                crate::oplog::rv_name(rv),
                rv,
                dur
            ),
        );
    }
    if ring {
        let mech = (!p_mechanism.is_null()).then_some(mech);
        crate::behaviour::emit(crate::behaviour::p11_with_key(
            crate::behaviour::OP_PKCS11_C_SIGNINIT,
            mech,
            h_key,
            rv,
            0,
            dur,
        ));
    }
    rv
}

fn C_SignInit_impl(h_session: u32, p_mechanism: *mut u8, h_key: u32) -> u32 {
    require_init!();
    require_session!(h_session);
    // C2 — the NULL-mechanism CANCEL form (see cancel_active_operation).
    if let Some(rv) = cancel_active_operation(h_session, p_mechanism, OpFamily::Sign) {
        return rv;
    }
    // PKCS#11 v3.2 §5.12 — a sign operation is already active on this session.
    if SIGN_STATE.shard(h_session).contains_key(&h_session) {
        return CKR_OPERATION_ACTIVE;
    }
    unsafe {
        if p_mechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        // PKCS#11 v3.2 §5.13.1 — key handle, visibility, key type (E5/E6),
        // and CKA_SIGN permission.
        if let Err(rv) =
            check_key_for_mech(h_session, h_key, CKA_SIGN, ck_param::mech(p_mechanism).mechanism)
        {
            return rv;
        }
        // FIPS 204 Algorithm 25 — an ML-DSA private key with s1/s2 out of
        // range never signs, however it reached the store.
        if let Err(rv) = check_ml_dsa_signing_key(h_key) {
            return rv;
        }
        let mut mech_type = ck_param::mech(p_mechanism).mechanism;
        // §4.8 Table 13 — CKA_ALLOWED_MECHANISMS, checked against the
        // caller's original request before any internal remap below.
        if let Err(rv) = check_mechanism_allowed(h_key, mech_type) {
            return rv;
        }
        // §6.4 — raw CKM_RSA_PKCS takes NO mechanism parameter; a supplied one
        // (e.g. a CK_SIGN_ADDITIONAL_CONTEXT meant for ML-DSA/SLH-DSA) is
        // CKR_MECHANISM_PARAM_INVALID.
        if mech_type == CKM_RSA_PKCS {
            if ck_param::mech(p_mechanism).has_param() {
                return CKR_MECHANISM_PARAM_INVALID;
            }
        }
        // Parse CK_EDDSA_PARAMS: if phFlag is set, use internal CKM_EDDSA_PH
        if mech_type == CKM_EDDSA {
            if eddsa_ph_flag(p_mechanism) {
                mech_type = CKM_EDDSA_PH;
            }
        }
        // GENERIC pre-hash mechanisms (CKM_HASH_ML_DSA/CKM_HASH_SLH_DSA)
        // remap onto the concrete hash-specific mechanism via their
        // CK_HASH_SIGN_ADDITIONAL_CONTEXT.hash param.
        mech_type = match remap_generic_hash_mech(h_session, p_mechanism, mech_type) {
            Ok(m) => m,
            Err(rv) => return rv,
        };
        // Mechanism parameters — see parse_sign_mech_params (shared with
        // the other two *SignInit/*VerifyInit entry points).
        let (slh_ctx, slh_det, supplied) = match parse_sign_mech_params_op(p_mechanism, mech_type, h_key, SigOp::Sign) {
            Ok(v) => v,
            Err(rv) => return rv,
        };
        mech_type = kmac_internal_mech(mech_type);
        // Composite ML-DSA (PKCS#11 v3.3 working draft, comp_sig.md): key and
        // hedge-variant checks, and a fresh streaming PH(M) for C_SignUpdate.
        if mech_type == CKM_COMP_SIG || mech_type == CKM_COMP_SIG_EXTERNAL_HASH {
            match comp_sig_init(h_key, true, slh_det) {
                Ok(p) => {
                    COMP_SIG_SIGN_PREHASH
                        .shard(h_session)
                        .insert(h_session, crate::native::composite_sig::PreHasher::new(p.pre_hash));
                }
                Err(rv) => return rv,
            }
        }
        set_supplied(&SIGN_SUPPLIED, h_session, supplied);
        SIGN_STATE.with(|s| {
            s.shard(h_session)
                .insert(h_session, (mech_type, h_key, slh_ctx, slh_det));
        });
    }
    CKR_OK
}

#[wasm_bindgen(js_name = _C_Sign)]
pub fn C_Sign(
    h_session: u32,
    p_data: *mut u8,
    ul_data_len: u32,
    p_signature: *mut u8,
    pul_signature_len: *mut u32,
) -> u32 {
    let logging = crate::oplog::enabled();
    let ring = crate::behaviour::enabled();
    let t0 = (logging || ring).then(std::time::Instant::now);

    let rv = C_Sign_impl(h_session, p_data, ul_data_len, p_signature, pul_signature_len);

    let dur = crate::behaviour::elapsed_us(t0);
    if logging {
        // probe=1 marks the mandatory PKCS#11 length-query call (p_signature
        // null) that every caller makes before the real one. A consumer
        // counting signatures must skip those rather than double every count.
        let out = if pul_signature_len.is_null() {
            0
        } else {
            unsafe { *pul_signature_len }
        };
        crate::oplog::emit(
            "C_Sign",
            &format!(
                "sess={} in={} out={} probe={} rv={} rv_id=0x{:08x} dur={}",
                h_session,
                ul_data_len,
                out,
                if p_signature.is_null() { 1 } else { 0 },
                crate::oplog::rv_name(rv),
                rv,
                dur
            ),
        );
    }
    // The session, not this call, holds the mechanism — alg stays 0 here and
    // a consumer joins on the preceding C_SignInit record, as the PQCEV
    // consumer already does. Probe calls are recorded too: they are part of
    // the caller's behaviour, and a probe storm is one of the shapes the
    // monitor exists to see.
    if ring {
        crate::behaviour::emit(crate::behaviour::p11(
            crate::behaviour::OP_PKCS11_C_SIGN,
            crate::behaviour::ALG_NONE,
            rv,
            ul_data_len as u64,
            dur,
        ));
    }
    rv
}

fn C_Sign_impl(
    h_session: u32,
    p_data: *mut u8,
    ul_data_len: u32,
    p_signature: *mut u8,
    pul_signature_len: *mut u32,
) -> u32 {
    require_init!();
    // §5.2 error priority (C2, 2026-08-13) — the session-handle class
    // takes MANDATORY precedence over argument and capability codes, so
    // this must precede every other check in the function.
    require_session!(h_session);
    // §5.2 error priority — session-handle validity outranks
    // CKR_OPERATION_NOT_INITIALIZED and argument checks.
    // §5.13.2 — "C_Sign ... MUST be called after C_SignInit without
    // intervening C_SignUpdate calls". A sign op already in its multi-part
    // phase is a sequencing error (mirror C_Digest-after-Update, round-1
    // S4/M-2); the accumulated parts MUST NOT be consumed by this error.
    if SIGN_MULTIPART_ACC.shard(h_session).contains_key(&h_session) {
        return CKR_OPERATION_ACTIVE;
    }
    if pul_signature_len.is_null() || (p_data.is_null() && ul_data_len > 0) {
        return CKR_ARGUMENTS_BAD;
    }
    // Peek first to support the size-query path (p_signature == null) without consuming state.
    let state = SIGN_STATE.shard(h_session).get(&h_session).cloned();
    let (mech, hkey, ctx_bytes, deterministic) = match state {
        Some(s) => s,
        None => return CKR_OPERATION_NOT_INITIALIZED,
    };

    unsafe {
        if p_signature.is_null() {
            *pul_signature_len = if let Some(n) = kmac_requested_len(mech, &ctx_bytes) {
                n
            } else if (hmac_general_base(mech).is_some() || mech == CKM_AES_GMAC)
                && ctx_bytes.len() >= 4
            {
                u32::from_le_bytes([ctx_bytes[0], ctx_bytes[1], ctx_bytes[2], ctx_bytes[3]])
            } else {
                get_sig_len(mech, hkey)
            };
            return CKR_OK;
        }

        // Owner decision D7 (C++ parity): a PH(M) of the wrong length for
        // the generic pre-hash mechanisms is CKR_DATA_LEN_RANGE at the real
        // C_Sign — after the size query above and after the buffer-size
        // check — and ends the operation.
        if mech == CKM_HASH_ML_DSA || mech == CKM_HASH_SLH_DSA {
            if let Some(hash) = GENERIC_HASH_STATE.shard(h_session).get(&h_session).copied() {
                let msg = std::slice::from_raw_parts(p_data, ul_data_len as usize);
                if let Err(rv) = generic_phm_len_ok(hash, msg) {
                    let need = get_sig_len(mech, hkey);
                    if *pul_signature_len < need {
                        *pul_signature_len = need;
                        return CKR_BUFFER_TOO_SMALL;
                    }
                    SIGN_STATE.shard(h_session).remove(&h_session);
                    SIGN_SUPPLIED.shard(h_session).remove(&h_session);
                    return rv;
                }
            }
        }

        // ── HSS/LMS stateful sign — single source of truth for the
        // leaf advance-and-persist core lives in `native::hbs`, shared
        // with the KMIP-facing `native::sign` path (see that module's
        // doc comment: drift here means a leaf index gets reused,
        // breaking the one-time-signature security property). ───────
        if mech == CKM_HSS {
            let msg = std::slice::from_raw_parts(p_data, ul_data_len as usize);
            let rv = match crate::native::hbs::sign_prepare(hkey, msg) {
                Ok(prepared) => {
                    // PKCS#11 v3.2 §5.2 — for a one-time (stateful) key the leaf
                    // MUST NOT be consumed until the caller's output buffer is
                    // known to be adequate. Validate the buffer FIRST; on
                    // CKR_BUFFER_TOO_SMALL leave the on-object key state
                    // unchanged and keep the operation active so the caller can
                    // retry with a larger buffer (re-signing the same leaf is
                    // deterministic and idempotent here).
                    if (*pul_signature_len as usize) < prepared.signature.len() {
                        *pul_signature_len = prepared.signature.len() as u32;
                        return CKR_BUFFER_TOO_SMALL;
                    }
                    // Buffer is adequate — now atomically advance and persist
                    // the key state, then emit the signature.
                    crate::native::hbs::sign_commit(hkey, &prepared);
                    std::ptr::copy_nonoverlapping(
                        prepared.signature.as_ptr(),
                        p_signature,
                        prepared.signature.len(),
                    );
                    *pul_signature_len = prepared.signature.len() as u32;
                    CKR_OK
                }
                Err(e) => e,
            };
            SIGN_STATE.shard(h_session).remove(&h_session);
            return rv;
        }

        // ── XMSS / XMSS^MT stateful sign — separate path (uses CKA_PRIV_STATEFUL_KEY_STATE) ───
        if mech == CKM_XMSS || mech == CKM_XMSSMT {
            let priv_bytes = match get_object_attr_bytes(hkey, CKA_PRIV_STATEFUL_KEY_STATE) {
                Some(v) => v,
                None => return CKR_KEY_TYPE_INCONSISTENT,
            };
            let msg = std::slice::from_raw_parts(p_data, ul_data_len as usize);

            // Capture hkey for the state-update closure (WASM single-threaded, no Send needed)
            let mut new_state: Option<Vec<u8>> = None;
            let mut update_fn = |new_priv: &[u8]| -> Result<(), ()> {
                new_state = Some(new_priv.to_vec());
                Ok(())
            };

            let sign_result = if mech == CKM_XMSS {
                let xmss_param =
                    match xmss_param_set_of(hkey, false) {
                        Some(p) => p,
                        None => return CKR_TEMPLATE_INCOMPLETE,
                    };
                match crate::crypto::xmss_bridge::xmss_sign(xmss_param, &priv_bytes, msg) {
                    Ok((sig, updated_sk)) => match update_fn(&updated_sk) {
                        Ok(_) => Ok(sig),
                        Err(_) => Err(CKR_FUNCTION_FAILED),
                    },
                    Err(e) => Err(e),
                }
            } else {
                let mt_param = match xmss_param_set_of(hkey, true) {
                    Some(p) => p,
                    None => return CKR_TEMPLATE_INCOMPLETE,
                };
                match crate::crypto::xmss_bridge::xmssmt_sign(mt_param, &priv_bytes, msg) {
                    Ok((sig, updated_sk)) => match update_fn(&updated_sk) {
                        Ok(_) => Ok(sig),
                        Err(_) => Err(CKR_FUNCTION_FAILED),
                    },
                    Err(e) => Err(e),
                }
            };

            let rv = match sign_result {
                Ok(sig) => {
                    // PKCS#11 v3.2 §5.2 — for a one-time (stateful) key the leaf
                    // MUST NOT be consumed until the caller's output buffer is
                    // known to be adequate. Validate the buffer FIRST; on
                    // CKR_BUFFER_TOO_SMALL leave the on-object key state
                    // unchanged and keep the operation active so the caller can
                    // retry with a larger buffer (re-signing the same leaf is
                    // deterministic and idempotent here).
                    if (*pul_signature_len as usize) < sig.len() {
                        *pul_signature_len = sig.len() as u32;
                        return CKR_BUFFER_TOO_SMALL;
                    }
                    // Buffer is adequate — now atomically advance and persist the
                    // key state, then emit the signature. Both fields (state blob
                    // + remaining-keys counter) are ONE logical "this leaf was
                    // consumed" transition — coalesced into one
                    // set_object_attrs_bytes_batch call so a crash between them
                    // can't leave disk/memory disagreeing about the last-used
                    // leaf (same hazard native::hbs::sign_commit guards against
                    // for HSS/LMS).
                    if let Some(ref new_priv_bytes) = new_state {
                        let mut changes =
                            vec![(CKA_PRIV_STATEFUL_KEY_STATE, new_priv_bytes.clone())];

                        if mech == CKM_XMSSMT {
                            // XMSS^MT: derive remaining from the MT signing-key
                            // state (the index width differs from single-tree).
                            let mt_param = xmss_param_set_of(hkey, true)
                                .unwrap_or(CKP_XMSSMT_SHA2_20_2_256);
                            let remaining_full = crate::crypto::xmss_bridge::xmssmt_keys_remaining(
                                mt_param,
                                new_priv_bytes,
                            );
                            let remaining =
                                crate::crypto::xmss_bridge::keys_remaining_cap(remaining_full);
                            changes.push((
                                CKA_PRIV_XMSS_KEYS_REMAINING,
                                remaining.to_le_bytes().to_vec(),
                            ));
                            // The standard counter moves in the same batch
                            // (v3.3 working draft, xmss_and_xmss-mt.md).
                            changes.push((
                                CKA_KEYS_REMAINING,
                                crate::crypto::xmss_bridge::keys_remaining_attr_bytes(remaining_full),
                            ));
                        } else {
                            // XMSS: derive remaining from the updated signing key state.
                            // The xmss crate stores the leaf index as big-endian bytes at offset 4
                            // inside the serialised signing key. Reading it directly is more accurate
                            // than a simple -1 decrement (the crate may skip leaves internally).
                            let xmss_param = xmss_param_set_of(hkey, false)
                                .unwrap_or(CKP_XMSS_SHA2_10_256);
                            let remaining = crate::crypto::xmss_bridge::xmss_keys_remaining(
                                xmss_param,
                                new_priv_bytes,
                            );
                            changes.push((
                                CKA_PRIV_XMSS_KEYS_REMAINING,
                                remaining.to_le_bytes().to_vec(),
                            ));
                            changes.push((
                                CKA_KEYS_REMAINING,
                                crate::crypto::xmss_bridge::keys_remaining_attr_bytes(remaining as u64),
                            ));
                        }
                        crate::state::set_object_attrs_bytes_batch(hkey, &changes);
                    }
                    std::ptr::copy_nonoverlapping(sig.as_ptr(), p_signature, sig.len());
                    *pul_signature_len = sig.len() as u32;
                    CKR_OK
                }
                Err(e) => e,
            };
            SIGN_STATE.shard(h_session).remove(&h_session);
            return rv;
        }

        // The private key material (for a composite key, mlSeed ‖ tradSK) is
        // wiped when this copy drops.
        let sk_bytes = match get_object_value(hkey) {
            Some(v) => zeroize::Zeroizing::new(v),
            None => return CKR_ARGUMENTS_BAD,
        };
        let msg = std::slice::from_raw_parts(p_data, ul_data_len as usize);
        let ps = get_object_param_set(hkey);
        // The operation's optional test inputs, validated at C_SignInit
        // (ACVP explicit-randomness plan, M2/M3): the value the signature
        // would otherwise draw, and the internal message encoding.
        let supplied = SIGN_SUPPLIED.shard(h_session).get(&h_session).cloned().unwrap_or_default();
        let rnd32 = supplied.random.as_deref().and_then(|r| <[u8; 32]>::try_from(r.as_slice()).ok());

        // then sign the digest as if it were plain CKM_ML_DSA / CKM_SLH_DSA.
        let eff_mech = mech;
        let eff_msg = msg;
        let result = match eff_mech {
            // Remediation R37 (phase 8), PKCS#11 v3.2 §6.67.6/§6.69.6: the
            // bare generic mechanisms are no longer remapped onto a
            // hash-specific one at *SignInit time (see
            // remap_generic_hash_mech's own R37 note) -- `msg` here IS the
            // caller's already-hashed PHM, and `hash` (the caller's own
            // CK_HASH_SIGN_ADDITIONAL_CONTEXT.hash) was stashed in
            // GENERIC_HASH_STATE at Init time since mech_type alone can no
            // longer carry it.
            CKM_HASH_ML_DSA => {
                match (GENERIC_HASH_STATE.shard(h_session).get(&h_session).copied(), rnd32) {
                    (Some(hash), _) if generic_phm_len_ok(hash, msg).is_err() => generic_phm_len_ok(hash, msg).map(|_| Vec::new()),
                    (Some(hash), Some(rnd)) => {
                        crate::crypto::handlers::sign_ml_dsa_phm_external_rnd(ps, &sk_bytes, msg, &ctx_bytes, hash, rnd)
                    }
                    (Some(hash), None) => sign_ml_dsa_phm(ps, &sk_bytes, msg, &ctx_bytes, hash, deterministic),
                    (None, _) => Err(CKR_MECHANISM_PARAM_INVALID),
                }
            }
            CKM_HASH_SLH_DSA => {
                match GENERIC_HASH_STATE.shard(h_session).get(&h_session).copied() {
                    Some(hash) if generic_phm_len_ok(hash, msg).is_err() => generic_phm_len_ok(hash, msg).map(|_| Vec::new()),
                    Some(hash) => match supplied.random.as_deref() {
                        Some(addrnd) => crate::crypto::handlers::sign_slh_dsa_phm_external_rnd(
                            ps, hash, &sk_bytes, msg, &ctx_bytes, addrnd,
                        ),
                        None => sign_slh_dsa_phm(ps, hash, &sk_bytes, msg, &ctx_bytes, deterministic),
                    },
                    None => Err(CKR_MECHANISM_PARAM_INVALID),
                }
            }
            m if m == CKM_ML_DSA || is_prehash_ml_dsa(m) => match rnd32 {
                Some(rnd) if m == CKM_ML_DSA => {
                    crate::crypto::handlers::sign_ml_dsa_external_rnd(ps, &sk_bytes, msg, &ctx_bytes, rnd)
                }
                Some(rnd) => {
                    crate::crypto::handlers::sign_hash_ml_dsa_external_rnd(m, ps, &sk_bytes, msg, &ctx_bytes, rnd)
                }
                None => sign_ml_dsa(m, ps, &sk_bytes, msg, &ctx_bytes, deterministic),
            },
            CKM_ML_DSA_EXTERNAL_MU => {
                // Remediation R34, PQCTODAY-VENDOR-EXT-MU. `msg` here is the
                // caller's 64-byte µ (FIPS 204 Eq. 2), not a message — see
                // takes_sign_additional_ctx's own comment for why this
                // reuses CK_SIGN_ADDITIONAL_CONTEXT rather than a new
                // struct. `ctx_bytes` carries hedgeVariant's context field,
                // which has no meaning once µ already exists — reject
                // non-empty rather than silently ignore it.
                if !ctx_bytes.is_empty() {
                    Err(CKR_MECHANISM_PARAM_INVALID)
                } else if msg.len() != PQCTODAY_ML_DSA_MU_LEN {
                    // ml_dsa.md (PKCS#11 v3.3 working draft), "ExternalMu
                    // ML-DSA: Key and Data Length": the input is exactly 64
                    // bytes. A wrong data length is CKR_DATA_LEN_RANGE, the
                    // code the v3.2 §5.13.2 C_Sign / §5.15.2 C_Verify lists
                    // carry for it (was CKR_ARGUMENTS_BAD).
                    Err(CKR_DATA_LEN_RANGE)
                } else if let Some(rnd) = rnd32 {
                    // Plan revision 9, correction 3: the hedged internal
                    // external-µ NIST groups need rnd here.
                    sign_ml_dsa_external_mu(ps, &sk_bytes, msg, rnd)
                } else if deterministic {
                    sign_ml_dsa_external_mu(ps, &sk_bytes, msg, [0u8; 32])
                } else {
                    // Fresh OS rnd (or AWS-LC's own, see crypto::awslc_pq).
                    sign_ml_dsa_external_mu_hedged(ps, &sk_bytes, msg)
                }
            }
            // FIPS 205 Alg 19 slh_sign_internal on the caller's M′: addrnd
            // supplied, else PK.seed when deterministic, else fresh n bytes.
            CKM_SLH_DSA if supplied.internal => {
                let fresh;
                let addrnd = match supplied.random.as_deref() {
                    Some(r) => Some(r.as_slice()),
                    None if deterministic => None,
                    None => {
                        let mut r = vec![0u8; slh_dsa_n(ps).unwrap_or(0)];
                        rand::RngCore::fill_bytes(&mut OsRng, &mut r);
                        fresh = r;
                        Some(fresh.as_slice())
                    }
                };
                crate::crypto::handlers::sign_slh_dsa_internal(ps, &sk_bytes, msg, addrnd)
            }
            m if m == CKM_SLH_DSA || is_prehash_slh_dsa(m) => match supplied.random.as_deref() {
                Some(addrnd) if m == CKM_SLH_DSA => crate::crypto::handlers::sign_slh_dsa_external_rnd(
                    ps, &sk_bytes, msg, &ctx_bytes, Some(addrnd),
                ),
                Some(addrnd) => crate::crypto::handlers::sign_hash_slh_dsa_external_rnd(
                    m, ps, &sk_bytes, msg, &ctx_bytes, Some(addrnd),
                ),
                None => sign_slh_dsa(m, ps, &sk_bytes, msg, &ctx_bytes, deterministic),
            },
            CKM_SHA256_HMAC | CKM_SHA384_HMAC | CKM_SHA512_HMAC | CKM_SHA3_256_HMAC
            | CKM_SHA3_512_HMAC | CKM_RIPEMD160_HMAC | CKM_SHA512_224_HMAC
            | CKM_SHA512_256_HMAC | CKM_SHA3_224_HMAC | CKM_SHA3_384_HMAC | CKM_SHA224_HMAC | CKM_SHA_1_HMAC | CKM_MD5_HMAC | CKM_AES_CMAC => {
                sign_hmac(eff_mech, &sk_bytes, eff_msg)
            }
            m if hmac_general_base(m).is_some() => {
                let (base, _) = hmac_general_base(m).unwrap();
                let mac_len = if ctx_bytes.len() >= 4 {
                    u32::from_le_bytes([ctx_bytes[0], ctx_bytes[1], ctx_bytes[2], ctx_bytes[3]])
                        as usize
                } else {
                    0
                };
                sign_hmac(base, &sk_bytes, eff_msg).map(|mut mac| {
                    mac.truncate(mac_len.max(1));
                    mac
                })
            }
            CKM_KMAC_128 | CKM_KMAC_256 => {
                if ctx_bytes.len() >= 4 {
                    let out_len = u32::from_le_bytes([
                        ctx_bytes[0],
                        ctx_bytes[1],
                        ctx_bytes[2],
                        ctx_bytes[3],
                    ]) as usize;
                    sign_kmac_ext(eff_mech, &sk_bytes, eff_msg, &ctx_bytes[4..], out_len)
                } else {
                    sign_kmac(eff_mech, &sk_bytes, eff_msg)
                }
            }
            CKM_AES_GMAC => {
                if ctx_bytes.len() < 4 {
                    Err(CKR_MECHANISM_PARAM_INVALID)
                } else {
                    let tag_len = u32::from_le_bytes([
                        ctx_bytes[0],
                        ctx_bytes[1],
                        ctx_bytes[2],
                        ctx_bytes[3],
                    ]) as usize;
                    sign_gmac(&sk_bytes, eff_msg, &ctx_bytes[4..], tag_len)
                }
            }
            CKM_SHA256_RSA_PKCS | CKM_SHA384_RSA_PKCS | CKM_SHA512_RSA_PKCS
            | CKM_SHA256_RSA_PKCS_PSS | CKM_SHA384_RSA_PKCS_PSS | CKM_SHA512_RSA_PKCS_PSS
            | CKM_SHA3_384_RSA_PKCS | CKM_SHA3_384_RSA_PKCS_PSS | CKM_RSA_PKCS
            | CKM_SHA1_RSA_PKCS | CKM_SHA1_RSA_PKCS_PSS | CKM_MD5_RSA_PKCS
            | CKM_SHA224_RSA_PKCS | CKM_SHA224_RSA_PKCS_PSS
            | CKM_SHA3_224_RSA_PKCS | CKM_SHA3_224_RSA_PKCS_PSS
            | CKM_SHA3_256_RSA_PKCS | CKM_SHA3_256_RSA_PKCS_PSS
            | CKM_SHA3_512_RSA_PKCS | CKM_SHA3_512_RSA_PKCS_PSS => {
                let pss_salt = if rsa_pss_mech_params(eff_mech).is_some() && ctx_bytes.len() >= 4 {
                    Some(u32::from_le_bytes([
                        ctx_bytes[0],
                        ctx_bytes[1],
                        ctx_bytes[2],
                        ctx_bytes[3],
                    ]) as usize)
                } else {
                    None
                };
                sign_rsa(eff_mech, &sk_bytes, eff_msg, pss_salt)
            }
            // R-1 (2026-08-24) — bare CKM_RSA_PKCS_PSS. `eff_msg` here is
            // ALREADY a digest, not a message: unlike the hash-specific PSS
            // siblings just above (whose `sign_rsa` internally hashes the
            // full message via `BlindedSigningKey<D>::sign()`), bare PSS
            // operates directly on caller-supplied hashed bytes (RFC 8017
            // §8.1 EMSA-PSS-ENCODE takes `mHash`, not `M`) — the caller has
            // hashed the message itself before calling C_Sign. ctx_bytes is
            // the 12-byte hashAlg||mgf||sLen format parse_sign_mech_params's
            // CKM_RSA_PKCS_PSS branch produces (not the 4-byte sLen-only
            // format the block above reads).
            CKM_RSA_PKCS_PSS => {
                if ctx_bytes.len() < 12 {
                    Err(CKR_MECHANISM_PARAM_INVALID)
                } else {
                    let hash_alg = u32::from_le_bytes([
                        ctx_bytes[0], ctx_bytes[1], ctx_bytes[2], ctx_bytes[3],
                    ]);
                    let s_len = u32::from_le_bytes([
                        ctx_bytes[8], ctx_bytes[9], ctx_bytes[10], ctx_bytes[11],
                    ]) as usize;
                    sign_rsa_pss_bare(hash_alg, &sk_bytes, eff_msg, s_len)
                }
            }
            // Shape 1 (plan M2, D1): CKM_ECDSA with the caller's k, range-
            // checked at C_SignInit — FIPS 186-5 §6.4.1 with k supplied.
            CKM_ECDSA if supplied.random.is_some() => crate::crypto::handlers::sign_ecdsa_explicit_k(
                ps,
                &sk_bytes,
                eff_msg,
                supplied.random.as_deref().map(|k| k.as_slice()).unwrap_or(&[]),
            ),
            // E11 — CKM_ECDSA_SHA1 / CKM_ECDSA_SHA224 are advertised and
            // sign_ecdsa implements them; this list had left them out.
            CKM_ECDSA | CKM_ECDSA_SHA1 | CKM_ECDSA_SHA224 | CKM_ECDSA_SHA256 | CKM_ECDSA_SHA384
            | CKM_ECDSA_SHA512 | CKM_ECDSA_SHA3_224 | CKM_ECDSA_SHA3_256 | CKM_ECDSA_SHA3_384
            | CKM_ECDSA_SHA3_512 => sign_ecdsa(eff_mech, ps, &sk_bytes, eff_msg),
            // ctx_bytes is CK_EDDSA_PARAMS.pContextData/ulContextDataLen,
            // parsed by parse_sign_mech_params's CKM_EDDSA branch — empty
            // means plain EdDSA, non-empty means RFC 8032 Ed25519ctx/
            // Ed448ctx (see that branch's comment for why this dispatch
            // used to always take the empty-context arm regardless of what
            // the caller supplied — T39b).
            CKM_EDDSA => {
                if ctx_bytes.is_empty() {
                    sign_eddsa(&sk_bytes, eff_msg)
                } else {
                    sign_eddsa_ctx(&sk_bytes, eff_msg, &ctx_bytes)
                }
            }
            // Ed25519ph/Ed448ph bind pContextData into the dom2/dom4 prefix
            // exactly as Ed25519ctx does, so the SAME ctx_bytes must reach
            // here. Passing None unconditionally (the pre-2026-09-26 shape)
            // signed a different scheme than the caller selected and said
            // CKR_OK while doing it.
            CKM_EDDSA_PH => sign_eddsa_ph(&sk_bytes, eff_msg, &ctx_bytes),
            // Composite ML-DSA (PKCS#11 v3.3 working draft, comp_sig.md);
            // ctx_bytes is CK_SIGN_ADDITIONAL_CONTEXT's context.
            CKM_COMP_SIG | CKM_COMP_SIG_EXTERNAL_HASH => comp_sig_sign(
                eff_mech,
                hkey,
                &sk_bytes,
                eff_msg,
                &ctx_bytes,
                deterministic,
                supplied.random.as_deref().map(|r| r.as_slice()),
            ),
            _ => Err(CKR_MECHANISM_INVALID),
        };

        let rv = match result {
            Ok(sig) => {
                if (*pul_signature_len as usize) < sig.len() {
                    *pul_signature_len = sig.len() as u32;
                    return CKR_BUFFER_TOO_SMALL;
                }
                std::ptr::copy_nonoverlapping(sig.as_ptr(), p_signature, sig.len());
                *pul_signature_len = sig.len() as u32;
                CKR_OK
            }
            Err(e) => e,
        };
        // Consume sign state after the actual sign (not the size-query path above)
        SIGN_STATE.shard(h_session).remove(&h_session);
        SIGN_SUPPLIED.shard(h_session).remove(&h_session);
        rv
    }
}

#[wasm_bindgen(js_name = _C_SignUpdate)]
pub fn C_SignUpdate(h_session: u32, p_part: *mut u8, ul_part_len: u32) -> u32 {
    require_init!();
    // §5.2 error priority (C2, 2026-08-13) — the session-handle class
    // takes MANDATORY precedence over argument and capability codes, so
    // this must precede every other check in the function.
    require_session!(h_session);
    // §5.2 error priority — session handle before operation state
    // (operate-stage, round-1 S4).
    // nonnull! convention (S2): pPart is a required input pointer, but a
    // zero-length part with a NULL pointer is legal (mirror C_Sign's pData).
    if p_part.is_null() && ul_part_len > 0 {
        return CKR_ARGUMENTS_BAD;
    }
    let mech = match multipart_op_mech(h_session, &SIGN_STATE, &SIGN_MULTIPART_ACC, true) {
        Ok(m) => m,
        Err(rv) => return rv,
    };
    if mech == CKM_COMP_SIG {
        return comp_sig_update(h_session, &COMP_SIG_SIGN_PREHASH, &SIGN_STATE, &SIGN_MULTIPART_ACC, p_part, ul_part_len);
    }
    // The op enters its multi-part phase even for an empty part — the
    // one-shot C_Sign is CKR_OPERATION_ACTIVE until C_SignFinal (mirror
    // DIGEST_MULTIPART).
    SIGN_MULTIPART_ACC.with(|s| {
        let mut m = s.shard(h_session);
        let acc = m.entry(h_session).or_default();
        if ul_part_len > 0 {
            unsafe {
                acc.extend_from_slice(std::slice::from_raw_parts(p_part, ul_part_len as usize));
            }
        }
    });
    CKR_OK
}

#[wasm_bindgen(js_name = _C_SignFinal)]
pub fn C_SignFinal(h_session: u32, p_signature: *mut u8, pul_signature_len: *mut u32) -> u32 {
    let logging = crate::oplog::enabled();
    let ring = crate::behaviour::enabled();
    let t0 = (logging || ring).then(std::time::Instant::now);

    let rv = C_SignFinal_impl(h_session, p_signature, pul_signature_len);

    let dur = crate::behaviour::elapsed_us(t0);
    if logging {
        // C_SignUpdate is deliberately NOT recorded: it produces no signature,
        // and instrumenting it would emit one line per chunk of a large input
        // for no added evidence.
        let out = if pul_signature_len.is_null() {
            0
        } else {
            unsafe { *pul_signature_len }
        };
        crate::oplog::emit(
            "C_SignFinal",
            &format!(
                "sess={} out={} probe={} rv={} rv_id=0x{:08x} dur={}",
                h_session,
                out,
                if p_signature.is_null() { 1 } else { 0 },
                crate::oplog::rv_name(rv),
                rv,
                dur
            ),
        );
    }
    if ring {
        crate::behaviour::emit(crate::behaviour::p11(
            crate::behaviour::OP_PKCS11_C_SIGNFINAL,
            crate::behaviour::ALG_NONE,
            rv,
            0,
            dur,
        ));
    }
    rv
}

fn C_SignFinal_impl(h_session: u32, p_signature: *mut u8, pul_signature_len: *mut u32) -> u32 {
    require_init!();
    // §5.2 error priority (C2, 2026-08-13) — the session-handle class
    // takes MANDATORY precedence over argument and capability codes, so
    // this must precede every other check in the function.
    require_session!(h_session);
    nonnull!(pul_signature_len);
    let mech = match multipart_op_mech(h_session, &SIGN_STATE, &SIGN_MULTIPART_ACC, true) {
        Ok(m) => m,
        Err(rv) => return rv,
    };
    if mech == CKM_COMP_SIG {
        return comp_sig_sign_final(h_session, p_signature, pul_signature_len);
    }
    // §5.13.4 — C_SignFinal with no preceding C_SignUpdate signs the empty
    // message (legal); the accumulator entry is simply absent.
    let msg = SIGN_MULTIPART_ACC
        .with(|s| s.shard(h_session).remove(&h_session))
        .unwrap_or_default();
    // Delegate to the one-shot handler over the accumulated message (the
    // accumulator entry was taken out above, so C_Sign's OPERATION_ACTIVE
    // guard passes). C_Sign already implements the §5.2 two-call convention:
    // it keeps SIGN_STATE alive on a NULL-buffer size query and on
    // CKR_BUFFER_TOO_SMALL — restore the accumulator on exactly those paths
    // so the multi-part op survives for the second call.
    let rv = C_Sign(
        h_session,
        msg.as_ptr() as *mut u8,
        msg.len() as u32,
        p_signature,
        pul_signature_len,
    );
    if rv == CKR_BUFFER_TOO_SMALL || (rv == CKR_OK && p_signature.is_null()) {
        SIGN_MULTIPART_ACC.shard(h_session).insert(h_session, msg);
    }
    rv
}

#[cfg(test)]
mod multipart_sign_verify_ffi_tests {
    //! T4 (audit: multi-part sign gap) — C_SignUpdate / C_SignFinal /
    //! C_VerifyUpdate / C_VerifyFinal: Update×N + Final equivalence with the
    //! one-shot handlers, the §5.2/§5.13/§5.15 state-machine matrix, the
    //! spec-pinned single-part-only code (CKR_OPERATION_NOT_INITIALIZED —
    //! see `multipart_op_mech`), and cancel/close cleanup.
    use super::*;
    use crate::native::test_lock;

    /// High fixed handles, disjoint from the other ffi test modules.
    const SESSION: u32 = 0x5434_1001;
    const BOGUS_SESSION: u32 = 0x5434_1FFF;
    const HMAC_KEY: u32 = 0x5434_2001;
    const HMAC_KEY_BYTES: [u8; 32] = [0x6b; 32];

    fn setup() {
        crate::state::set_initialized(true);
        SESSIONS.with(|s| {
            s.shard(SESSION).insert(
                SESSION,
                crate::state::SessionState { slot_id: 0, rw_session: true, context: 0 },
            );
        });
        // Clean slate for the op state under test.
        SIGN_STATE.shard(SESSION).remove(&SESSION);
        VERIFY_STATE.shard(SESSION).remove(&SESSION);
        SIGN_MULTIPART_ACC.shard(SESSION).remove(&SESSION);
        VERIFY_MULTIPART_ACC.shard(SESSION).remove(&SESSION);
        // Public generic-secret HMAC key (no login gate).
        OBJECTS.with(|o| {
            let mut attrs = Attributes::new();
            attrs.insert(CKA_VALUE, HMAC_KEY_BYTES.to_vec());
            store_ulong(&mut attrs, CKA_CLASS, CKO_SECRET_KEY);
            store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_GENERIC_SECRET);
            store_bool(&mut attrs, CKA_SIGN, true);
            store_bool(&mut attrs, CKA_VERIFY, true);
            o.borrow_mut().insert(HMAC_KEY, attrs);
        });
    }

    /// The CK_MECHANISM for `mech`. The hash-specific RSA-PSS mechanisms
    /// "have a parameter, a CK_RSA_PKCS_PSS_PARAMS structure" (v3.2
    /// §6.1.11) and an absent one is CKR_MECHANISM_PARAM_INVALID since E9 /
    /// decision D6, so they get the mechanism's own hash and MGF1 with a
    /// hash-length salt — the values the engine defaulted to before.
    fn mech_words(mech: u32) -> [usize; 3] {
        match rsa_pss_mech_params(mech) {
            Some((hash, mgf)) => {
                let s_len = match hash {
                    CKM_SHA_1 => 20,
                    CKM_SHA224 | CKM_SHA3_224 => 28,
                    CKM_SHA384 | CKM_SHA3_384 => 48,
                    CKM_SHA512 | CKM_SHA3_512 => 64,
                    _ => 32,
                };
                let p: &'static [usize; 3] = Box::leak(Box::new([hash as usize, mgf as usize, s_len]));
                [mech as usize, p.as_ptr() as usize, 3 * std::mem::size_of::<usize>()]
            }
            None => [mech as usize, 0, 0],
        }
    }

    fn sign_init(sess: u32, mech: u32, key: u32) -> u32 {
        let mut m = mech_words(mech);
        C_SignInit(sess, m.as_mut_ptr() as *mut u8, key)
    }

    fn verify_init(sess: u32, mech: u32, key: u32) -> u32 {
        let mut m = mech_words(mech);
        C_VerifyInit(sess, m.as_mut_ptr() as *mut u8, key)
    }

    fn s_update(sess: u32, part: &[u8]) -> u32 {
        C_SignUpdate(sess, part.as_ptr() as *mut u8, part.len() as u32)
    }

    fn v_update(sess: u32, part: &[u8]) -> u32 {
        C_VerifyUpdate(sess, part.as_ptr() as *mut u8, part.len() as u32)
    }

    /// C_SignFinal via the §5.2 two-call convention (size query, then fetch).
    fn sign_final_vec(sess: u32) -> Result<Vec<u8>, u32> {
        let mut len: u32 = 0;
        let rv = C_SignFinal(sess, std::ptr::null_mut(), &mut len);
        if rv != CKR_OK {
            return Err(rv);
        }
        let mut buf = vec![0u8; len as usize];
        let rv = C_SignFinal(sess, buf.as_mut_ptr(), &mut len);
        if rv != CKR_OK {
            return Err(rv);
        }
        buf.truncate(len as usize);
        Ok(buf)
    }

    fn one_shot_sign(sess: u32, mech: u32, key: u32, msg: &[u8]) -> Vec<u8> {
        assert_eq!(sign_init(sess, mech, key), CKR_OK);
        let mut buf = vec![0u8; 1024];
        let mut len: u32 = 1024;
        let rv = C_Sign(sess, msg.as_ptr() as *mut u8, msg.len() as u32, buf.as_mut_ptr(), &mut len);
        assert_eq!(rv, CKR_OK, "one-shot C_Sign mech 0x{mech:x}: 0x{rv:x}");
        buf.truncate(len as usize);
        buf
    }

    fn one_shot_verify(sess: u32, mech: u32, key: u32, msg: &[u8], sig: &[u8]) -> u32 {
        assert_eq!(verify_init(sess, mech, key), CKR_OK);
        C_Verify(
            sess,
            msg.as_ptr() as *mut u8,
            msg.len() as u32,
            sig.as_ptr() as *mut u8,
            sig.len() as u32,
        )
    }

    fn multipart_sign(sess: u32, mech: u32, key: u32, parts: &[&[u8]]) -> Vec<u8> {
        assert_eq!(sign_init(sess, mech, key), CKR_OK);
        for p in parts {
            assert_eq!(s_update(sess, p), CKR_OK);
        }
        sign_final_vec(sess).expect("multi-part sign final")
    }

    fn multipart_verify(sess: u32, mech: u32, key: u32, parts: &[&[u8]], sig: &[u8]) -> u32 {
        assert_eq!(verify_init(sess, mech, key), CKR_OK);
        for p in parts {
            assert_eq!(v_update(sess, p), CKR_OK);
        }
        C_VerifyFinal(sess, sig.as_ptr() as *mut u8, sig.len() as u32)
    }

    // ── Update×N + Final == one-shot (HMAC, byte-equal) ─────────────────────

    /// HMAC SHA-256/384/512: multi-part MAC over several split patterns
    /// (whole / ragged / empty leading+trailing parts) is byte-equal to the
    /// one-shot C_Sign, and VerifyUpdate/Final accepts each MAC.
    #[test]
    fn hmac_update_final_byte_equal_one_shot() {
        let _guard = test_lock::acquire();
        setup();
        let msg = b"multi-part message under test, longer than one block boundary";
        for mech in [CKM_SHA256_HMAC, CKM_SHA384_HMAC, CKM_SHA512_HMAC] {
            let expected = one_shot_sign(SESSION, mech, HMAC_KEY, msg);
            let splits: [&[&[u8]]; 3] = [
                &[&msg[..]],
                &[&msg[..3], &msg[3..17], &msg[17..]],
                &[&[], &msg[..], &[]],
            ];
            for parts in splits {
                let sig = multipart_sign(SESSION, mech, HMAC_KEY, parts);
                assert_eq!(sig, expected, "mech 0x{mech:x} split mismatch");
                assert_eq!(
                    multipart_verify(SESSION, mech, HMAC_KEY, parts, &sig),
                    CKR_OK,
                    "mech 0x{mech:x} multi-part verify"
                );
            }
        }
    }

    /// HMAC-SHA-256 Update/Final cross-checked against the `hmac` crate
    /// one-shot over the same key and message.
    #[test]
    fn hmac_update_final_matches_hmac_crate() {
        let _guard = test_lock::acquire();
        setup();
        let msg = b"cross-check against RustCrypto hmac";
        let sig = multipart_sign(
            SESSION,
            CKM_SHA256_HMAC,
            HMAC_KEY,
            &[&msg[..10], &msg[10..]],
        );
        use hmac::Mac;
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&HMAC_KEY_BYTES).unwrap();
        mac.update(msg);
        assert_eq!(sig, mac.finalize().into_bytes().to_vec());
    }

    /// R2'a (2026-09-06) — `CKM_SHA512_224_HMAC`, `CKM_SHA512_256_HMAC`,
    /// `CKM_SHA3_224_HMAC` and `CKM_SHA3_384_HMAC` were ALREADY implemented
    /// inside `crypto::handlers::sign_hmac` (and in the SP 800-108 PRF paths),
    /// but were absent from `SUPPORTED_MECHS`, from `C_GetMechanismInfo` and
    /// from the `C_Sign`/`C_Verify` dispatch arms — so `C_SignInit` rejected
    /// every one of them and no caller could reach the working code. This test
    /// fails on the pre-fix engine at the first `one_shot_sign`.
    ///
    /// Each MAC is cross-checked against the RustCrypto `hmac` crate over the
    /// same key and message, so this asserts the output is CORRECT rather than
    /// merely that the call now succeeds.
    #[test]
    fn previously_unreachable_hmac_variants_sign_verify_and_match_reference() {
        let _guard = test_lock::acquire();
        setup();
        use hmac::Mac;
        let msg = b"R2'a - these four HMAC variants used to be unreachable";

        let reference = |mech: u32| -> Vec<u8> {
            match mech {
                CKM_SHA512_224_HMAC => {
                    let mut m =
                        hmac::Hmac::<sha2::Sha512_224>::new_from_slice(&HMAC_KEY_BYTES).unwrap();
                    m.update(msg);
                    m.finalize().into_bytes().to_vec()
                }
                CKM_SHA512_256_HMAC => {
                    let mut m =
                        hmac::Hmac::<sha2::Sha512_256>::new_from_slice(&HMAC_KEY_BYTES).unwrap();
                    m.update(msg);
                    m.finalize().into_bytes().to_vec()
                }
                CKM_SHA3_224_HMAC => {
                    let mut m =
                        hmac::Hmac::<sha3::Sha3_224>::new_from_slice(&HMAC_KEY_BYTES).unwrap();
                    m.update(msg);
                    m.finalize().into_bytes().to_vec()
                }
                CKM_SHA3_384_HMAC => {
                    let mut m =
                        hmac::Hmac::<sha3::Sha3_384>::new_from_slice(&HMAC_KEY_BYTES).unwrap();
                    m.update(msg);
                    m.finalize().into_bytes().to_vec()
                }
                other => panic!("unexpected mechanism 0x{other:x}"),
            }
        };

        for (mech, name, mac_len) in [
            (CKM_SHA512_224_HMAC, "SHA-512/224", 28usize),
            (CKM_SHA512_256_HMAC, "SHA-512/256", 32),
            (CKM_SHA3_224_HMAC, "SHA3-224", 28),
            (CKM_SHA3_384_HMAC, "SHA3-384", 48),
        ] {
            assert!(
                crate::constants::SUPPORTED_MECHS.contains(&mech),
                "{name}: must be advertised through C_GetMechanismList"
            );
            let sig = one_shot_sign(SESSION, mech, HMAC_KEY, msg);
            assert_eq!(sig.len(), mac_len, "{name}: MAC length");
            assert_eq!(
                sig,
                reference(mech),
                "{name}: MAC must equal the RustCrypto reference"
            );
            assert_eq!(
                one_shot_verify(SESSION, mech, HMAC_KEY, msg, &sig),
                CKR_OK,
                "{name}: C_Verify must accept the MAC it just produced"
            );
        }
    }

    /// §3 Wave 1 (2026-09-07) — `CKM_SHA224_HMAC` plus the six remaining
    /// `_HMAC_GENERAL` variants, which the C++ engine has always advertised.
    ///
    /// The `_GENERAL` forms take a `CK_MAC_GENERAL_PARAMS` giving the number
    /// of bytes to keep, so this asserts BOTH that the full-length MAC equals
    /// the RustCrypto reference and that a truncated request returns exactly
    /// that prefix — truncation to the wrong end, or ignoring the parameter,
    /// would both still "work" without this.
    #[test]
    fn wave1_hmac_family_matches_reference_and_truncates_correctly() {
        let _guard = test_lock::acquire();
        setup();
        use hmac::Mac;
        let msg = b"wave 1 HMAC parity";

        macro_rules! reference {
            ($d:ty) => {{
                let mut m = hmac::Hmac::<$d>::new_from_slice(&HMAC_KEY_BYTES).unwrap();
                m.update(msg);
                m.finalize().into_bytes().to_vec()
            }};
        }

        // (plain, general, full reference MAC)
        let cases: [(u32, u32, Vec<u8>, &str); 6] = [
            (CKM_SHA224_HMAC, CKM_SHA224_HMAC_GENERAL, reference!(sha2::Sha224), "SHA-224"),
            (CKM_SHA512_224_HMAC, CKM_SHA512_224_HMAC_GENERAL, reference!(sha2::Sha512_224), "SHA-512/224"),
            (CKM_SHA512_256_HMAC, CKM_SHA512_256_HMAC_GENERAL, reference!(sha2::Sha512_256), "SHA-512/256"),
            (CKM_SHA3_224_HMAC, CKM_SHA3_224_HMAC_GENERAL, reference!(sha3::Sha3_224), "SHA3-224"),
            (CKM_SHA3_384_HMAC, CKM_SHA3_384_HMAC_GENERAL, reference!(sha3::Sha3_384), "SHA3-384"),
            (CKM_RIPEMD160_HMAC, CKM_RIPEMD160_HMAC_GENERAL, reference!(ripemd::Ripemd160), "RIPEMD-160"),
        ];

        for (plain, general, want, name) in cases {
            for m in [plain, general] {
                assert!(
                    crate::constants::SUPPORTED_MECHS.contains(&m),
                    "{name}: mechanism 0x{m:x} must be advertised"
                );
            }
            // Full-length MAC through the plain mechanism.
            let sig = one_shot_sign(SESSION, plain, HMAC_KEY, msg);
            assert_eq!(sig, want, "{name}: MAC must equal the RustCrypto reference");
            assert_eq!(
                one_shot_verify(SESSION, plain, HMAC_KEY, msg, &sig),
                CKR_OK,
                "{name}: verify its own MAC"
            );

            // _GENERAL with a truncated length must return that exact prefix.
            let keep = want.len() - 4;
            // CK_MAC_GENERAL_PARAMS is a bare `typedef CK_ULONG`, so it is
            // the NATIVE word width here (8 bytes on LP64), not a u32 — the
            // engine reads it with ulong(), and a 4-byte value is rejected as
            // CKR_MECHANISM_PARAM_INVALID.
            let params = (keep as std::os::raw::c_ulong).to_le_bytes();
            // CK_MECHANISM is {mechanism, pParameter, ulParameterLen}.
            let mut mech: [usize; 3] =
                [general as usize, params.as_ptr() as usize, params.len()];
            assert_eq!(
                C_SignInit(SESSION, mech.as_mut_ptr() as *mut u8, HMAC_KEY),
                CKR_OK,
                "{name}: C_SignInit(_GENERAL)"
            );
            let mut out = vec![0u8; want.len()];
            let mut out_len = out.len() as u32;
            assert_eq!(
                C_Sign(SESSION, msg.as_ptr() as *mut u8, msg.len() as u32,
                       out.as_mut_ptr(), &mut out_len),
                CKR_OK,
                "{name}: C_Sign(_GENERAL)"
            );
            assert_eq!(out_len as usize, keep, "{name}: _GENERAL honours the requested length");
            assert_eq!(
                &out[..keep],
                &want[..keep],
                "{name}: truncated MAC must be the PREFIX of the full one"
            );
        }
    }

    // ── §5.13/§5.15 sequencing: one-shot after Update ───────────────────────

    /// C_Sign while the sign op is in its multi-part phase →
    /// CKR_OPERATION_ACTIVE; the accumulated parts are NOT consumed and the
    /// op completes correctly. Same matrix for Verify.
    #[test]
    fn one_shot_after_update_operation_active_acc_preserved() {
        let _guard = test_lock::acquire();
        setup();
        let expected = one_shot_sign(SESSION, CKM_SHA256_HMAC, HMAC_KEY, b"part one and two");

        assert_eq!(sign_init(SESSION, CKM_SHA256_HMAC, HMAC_KEY), CKR_OK);
        assert_eq!(s_update(SESSION, b"part one"), CKR_OK);
        let mut buf = [0u8; 64];
        let mut len: u32 = 64;
        assert_eq!(
            C_Sign(SESSION, buf.as_ptr() as *mut u8, 4, buf.as_mut_ptr(), &mut len),
            CKR_OPERATION_ACTIVE,
        );
        // Accumulator intact — finish the op and compare.
        assert_eq!(s_update(SESSION, b" and two"), CKR_OK);
        assert_eq!(sign_final_vec(SESSION).unwrap(), expected);

        // Verify side.
        assert_eq!(verify_init(SESSION, CKM_SHA256_HMAC, HMAC_KEY), CKR_OK);
        assert_eq!(v_update(SESSION, b"part one"), CKR_OK);
        assert_eq!(
            C_Verify(
                SESSION,
                buf.as_ptr() as *mut u8,
                4,
                expected.as_ptr() as *mut u8,
                expected.len() as u32,
            ),
            CKR_OPERATION_ACTIVE,
        );
        assert_eq!(v_update(SESSION, b" and two"), CKR_OK);
        assert_eq!(
            C_VerifyFinal(SESSION, expected.as_ptr() as *mut u8, expected.len() as u32),
            CKR_OK,
        );
    }

    /// An empty C_SignUpdate part still enters the multi-part phase (one-shot
    /// blocked) and C_SignFinal then signs the empty message.
    #[test]
    fn empty_update_enters_multipart_phase() {
        let _guard = test_lock::acquire();
        setup();
        assert_eq!(sign_init(SESSION, CKM_SHA256_HMAC, HMAC_KEY), CKR_OK);
        assert_eq!(s_update(SESSION, &[]), CKR_OK);
        let mut buf = [0u8; 64];
        let mut len: u32 = 64;
        assert_eq!(
            C_Sign(SESSION, buf.as_ptr() as *mut u8, 4, buf.as_mut_ptr(), &mut len),
            CKR_OPERATION_ACTIVE,
        );
        use hmac::Mac;
        let mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&HMAC_KEY_BYTES)
            .unwrap()
            .finalize()
            .into_bytes()
            .to_vec();
        assert_eq!(sign_final_vec(SESSION).unwrap(), mac);
    }

    // ── Update/Final without Init ───────────────────────────────────────────

    /// §5.13.3/§5.13.4, §5.15.3/§5.15.4 — Update/Final without Init →
    /// CKR_OPERATION_NOT_INITIALIZED; bogus session handle outranks it
    /// (operate-stage require_session!, round-1 S4).
    #[test]
    fn update_final_without_init_or_session() {
        let _guard = test_lock::acquire();
        setup();
        let data = [0u8; 4];
        let mut len: u32 = 64;
        let mut buf = [0u8; 64];

        assert_eq!(s_update(SESSION, &data), CKR_OPERATION_NOT_INITIALIZED);
        assert_eq!(
            C_SignFinal(SESSION, buf.as_mut_ptr(), &mut len),
            CKR_OPERATION_NOT_INITIALIZED,
        );
        assert_eq!(v_update(SESSION, &data), CKR_OPERATION_NOT_INITIALIZED);
        assert_eq!(
            C_VerifyFinal(SESSION, buf.as_mut_ptr(), 32),
            CKR_OPERATION_NOT_INITIALIZED,
        );

        assert_eq!(
            C_SignUpdate(BOGUS_SESSION, data.as_ptr() as *mut u8, 4),
            CKR_SESSION_HANDLE_INVALID,
        );
        assert_eq!(
            C_SignFinal(BOGUS_SESSION, buf.as_mut_ptr(), &mut len),
            CKR_SESSION_HANDLE_INVALID,
        );
        assert_eq!(
            C_VerifyUpdate(BOGUS_SESSION, data.as_ptr() as *mut u8, 4),
            CKR_SESSION_HANDLE_INVALID,
        );
        assert_eq!(
            C_VerifyFinal(BOGUS_SESSION, buf.as_mut_ptr(), 32),
            CKR_SESSION_HANDLE_INVALID,
        );
    }

    /// C_SignFinal/C_VerifyFinal with no preceding Update signs/verifies the
    /// empty message (legal per §5.13.4).
    #[test]
    fn final_without_updates_uses_empty_message() {
        let _guard = test_lock::acquire();
        setup();
        use hmac::Mac;
        let mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&HMAC_KEY_BYTES)
            .unwrap()
            .finalize()
            .into_bytes()
            .to_vec();

        assert_eq!(sign_init(SESSION, CKM_SHA256_HMAC, HMAC_KEY), CKR_OK);
        assert_eq!(sign_final_vec(SESSION).unwrap(), mac);

        assert_eq!(verify_init(SESSION, CKM_SHA256_HMAC, HMAC_KEY), CKR_OK);
        assert_eq!(
            C_VerifyFinal(SESSION, mac.as_ptr() as *mut u8, mac.len() as u32),
            CKR_OK,
        );
    }

    // ── §5.2 two-call convention on C_SignFinal ─────────────────────────────

    /// Size query (NULL output) and CKR_BUFFER_TOO_SMALL both leave the
    /// multi-part op active; the retry completes with the correct MAC, after
    /// which the op is consumed.
    #[test]
    fn sign_final_buffer_too_small_preserves_state() {
        let _guard = test_lock::acquire();
        setup();
        let msg = b"two-call convention";
        let expected = one_shot_sign(SESSION, CKM_SHA256_HMAC, HMAC_KEY, msg);

        assert_eq!(sign_init(SESSION, CKM_SHA256_HMAC, HMAC_KEY), CKR_OK);
        assert_eq!(s_update(SESSION, msg), CKR_OK);

        // Size query: op untouched.
        let mut len: u32 = 0;
        assert_eq!(C_SignFinal(SESSION, std::ptr::null_mut(), &mut len), CKR_OK);
        assert_eq!(len, 32);

        // Short buffer: CKR_BUFFER_TOO_SMALL, required size reported, op alive.
        let mut short = [0u8; 5];
        let mut len: u32 = 5;
        assert_eq!(
            C_SignFinal(SESSION, short.as_mut_ptr(), &mut len),
            CKR_BUFFER_TOO_SMALL,
        );
        assert_eq!(len, 32);

        // Retry with an adequate buffer succeeds and matches the one-shot.
        let mut buf = vec![0u8; 32];
        let mut len: u32 = 32;
        assert_eq!(C_SignFinal(SESSION, buf.as_mut_ptr(), &mut len), CKR_OK);
        assert_eq!(buf, expected);

        // The successful Final consumed the op.
        let mut len: u32 = 32;
        assert_eq!(
            C_SignFinal(SESSION, buf.as_mut_ptr(), &mut len),
            CKR_OPERATION_NOT_INITIALIZED,
        );
    }

    // ── Single-part-only mechanisms ─────────────────────────────────────────

    /// C_SignUpdate / C_SignFinal on an op whose mechanism is single-part-only
    /// → CKR_OPERATION_NOT_INITIALIZED (the §5.13.3 return list has no
    /// CKR_MECHANISM_INVALID / CKR_FUNCTION_NOT_SUPPORTED; see
    /// `multipart_op_mech`), and the active op is terminated (a fresh
    /// C_SignInit succeeds immediately afterwards).
    #[test]
    fn single_part_only_mech_returns_spec_code_and_terminates() {
        let _guard = test_lock::acquire();
        setup();
        let data = [0u8; 4];
        let mut buf = [0u8; 64];
        let mut len: u32 = 64;
        // 0x1 = CKM_RSA_PKCS (raw, digest-less — value from pkcs11t.h; the
        // constant is not defined in constants.rs).
        const CKM_RSA_PKCS_RAW: u32 = 0x0000_0001;
        // Genuinely single-part: raw RSA/ECDSA (caller supplies the digest) and,
        // for VERIFY only, the stateful HSS/XMSS schemes (the v3.3 draft made
        // their signing multi-part; see stateful_sign_mech and
        // pkcs11_v33_audit_tests). Pure ML-DSA / SLH-DSA / EdDSA are NOT
        // listed — they gained multi-part buffering (sign_mech_supports_multipart).
        //
        // Each mechanism gets a key of its OWN type: the init now checks
        // CKA_KEY_TYPE (§5.13.1 / §5.15.1 CKR_KEY_TYPE_INCONSISTENT, E5), so the
        // generic-secret HMAC key this loop used to borrow for all four is
        // refused. The key is never exercised — no Sign/Verify reaches the
        // crypto — so only its type and usage flags matter.
        const TYPED_KEY: u32 = 0x5434_2002;
        for (mech, key_type) in [
            (CKM_RSA_PKCS_RAW, CKK_RSA),
            (CKM_ECDSA, CKK_EC),
            (CKM_HSS, CKK_HSS),
            (CKM_XMSS, CKK_XMSS),
        ] {
            OBJECTS.with(|o| {
                let mut attrs = Attributes::new();
                attrs.insert(CKA_VALUE, HMAC_KEY_BYTES.to_vec());
                store_ulong(&mut attrs, CKA_CLASS, CKO_SECRET_KEY);
                store_ulong(&mut attrs, CKA_KEY_TYPE, key_type);
                store_bool(&mut attrs, CKA_SIGN, true);
                store_bool(&mut attrs, CKA_VERIFY, true);
                o.borrow_mut().insert(TYPED_KEY, attrs);
            });
            const HMAC_KEY: u32 = TYPED_KEY;
            if !stateful_sign_mech(mech) {
                // SignUpdate path.
                assert_eq!(sign_init(SESSION, mech, HMAC_KEY), CKR_OK, "mech 0x{mech:x}");
                assert_eq!(
                    s_update(SESSION, &data),
                    CKR_OPERATION_NOT_INITIALIZED,
                    "SignUpdate mech 0x{mech:x}"
                );
                // The op was terminated — a new Init is not CKR_OPERATION_ACTIVE.
                assert_eq!(sign_init(SESSION, mech, HMAC_KEY), CKR_OK, "re-init 0x{mech:x}");
                // SignFinal path terminates too.
                assert_eq!(
                    C_SignFinal(SESSION, buf.as_mut_ptr(), &mut len),
                    CKR_OPERATION_NOT_INITIALIZED,
                    "SignFinal mech 0x{mech:x}"
                );
                assert!(!SIGN_STATE.shard(SESSION).contains_key(&SESSION));
            }

            // Verify side.
            assert_eq!(verify_init(SESSION, mech, HMAC_KEY), CKR_OK);
            assert_eq!(
                v_update(SESSION, &data),
                CKR_OPERATION_NOT_INITIALIZED,
                "VerifyUpdate mech 0x{mech:x}"
            );
            assert_eq!(verify_init(SESSION, mech, HMAC_KEY), CKR_OK);
            assert_eq!(
                C_VerifyFinal(SESSION, buf.as_mut_ptr(), 32),
                CKR_OPERATION_NOT_INITIALIZED,
                "VerifyFinal mech 0x{mech:x}"
            );
            assert!(!VERIFY_STATE.shard(SESSION).contains_key(&SESSION));
        }
    }

    // ── Cancel / close cleanup ──────────────────────────────────────────────

    /// C_SessionCancel CKF_SIGN (0x800) / CKF_VERIFY (0x2000) clears the op
    /// state AND the new accumulators.
    #[test]
    fn session_cancel_clears_multipart_accumulators() {
        let _guard = test_lock::acquire();
        setup();
        assert_eq!(sign_init(SESSION, CKM_SHA256_HMAC, HMAC_KEY), CKR_OK);
        assert_eq!(s_update(SESSION, b"doomed"), CKR_OK);
        assert_eq!(C_SessionCancel(SESSION, 0x800), CKR_OK);
        assert!(!SIGN_MULTIPART_ACC.shard(SESSION).contains_key(&SESSION));
        let mut buf = [0u8; 64];
        let mut len: u32 = 64;
        assert_eq!(
            C_SignFinal(SESSION, buf.as_mut_ptr(), &mut len),
            CKR_OPERATION_NOT_INITIALIZED,
        );

        assert_eq!(verify_init(SESSION, CKM_SHA256_HMAC, HMAC_KEY), CKR_OK);
        assert_eq!(v_update(SESSION, b"doomed"), CKR_OK);
        assert_eq!(C_SessionCancel(SESSION, 0x2000), CKR_OK);
        assert!(!VERIFY_MULTIPART_ACC.shard(SESSION).contains_key(&SESSION));
        assert_eq!(
            C_VerifyFinal(SESSION, buf.as_mut_ptr(), 32),
            CKR_OPERATION_NOT_INITIALIZED,
        );
    }

    /// C_CloseSession terminates in-flight multi-part sign/verify ops and
    /// drops their accumulators.
    #[test]
    fn close_session_clears_multipart_accumulators() {
        let _guard = test_lock::acquire();
        setup();
        let doomed: u32 = 0x5434_1002;
        SESSIONS.with(|s| {
            s.shard(doomed).insert(
                doomed,
                crate::state::SessionState { slot_id: 0, rw_session: true, context: 0 },
            );
        });
        assert_eq!(sign_init(doomed, CKM_SHA256_HMAC, HMAC_KEY), CKR_OK);
        assert_eq!(s_update(doomed, b"bye"), CKR_OK);
        assert_eq!(verify_init(doomed, CKM_SHA256_HMAC, HMAC_KEY), CKR_OK);
        assert_eq!(v_update(doomed, b"bye"), CKR_OK);

        assert_eq!(C_CloseSession(doomed), CKR_OK);
        assert!(!SIGN_STATE.shard(doomed).contains_key(&doomed));
        assert!(!VERIFY_STATE.shard(doomed).contains_key(&doomed));
        assert!(!SIGN_MULTIPART_ACC.shard(doomed).contains_key(&doomed));
        assert!(!VERIFY_MULTIPART_ACC.shard(doomed).contains_key(&doomed));
    }

    // ── VerifyFinal failure codes (same as one-shot) ────────────────────────

    /// C_VerifyFinal returns CKR_SIGNATURE_INVALID for a tampered MAC and
    /// CKR_SIGNATURE_LEN_RANGE for a wrong-length one, exactly like the
    /// one-shot C_Verify.
    #[test]
    fn verify_final_signature_invalid_and_len_range() {
        let _guard = test_lock::acquire();
        setup();
        let msg = b"verify failure codes";
        let mut mac = one_shot_sign(SESSION, CKM_SHA256_HMAC, HMAC_KEY, msg);

        mac[0] ^= 0xFF;
        assert_eq!(
            multipart_verify(SESSION, CKM_SHA256_HMAC, HMAC_KEY, &[&msg[..]], &mac),
            CKR_SIGNATURE_INVALID,
        );
        mac[0] ^= 0xFF;

        assert_eq!(
            multipart_verify(SESSION, CKM_SHA256_HMAC, HMAC_KEY, &[&msg[..]], &mac[..31]),
            CKR_SIGNATURE_LEN_RANGE,
        );
    }

    // ── Hash-composite RSA / ECDSA ──────────────────────────────────────────

    /// RSA + ECDSA hash-composite mechanisms through a real logged-in session:
    /// PKCS#1 v1.5 multi-part == one-shot byte-equal (deterministic), PSS and
    /// ECDSA multi-part signatures verify (one-shot and multi-part), in both
    /// sign→verify directions.
    #[test]
    fn rsa_ecdsa_hash_composite_multipart() {
        let _guard = test_lock::acquire();
        use crate::native::keygen::{generate_ecdsa_keypair, generate_rsa_keypair, EccCurve};
        use crate::native::session::{bootstrap_default_token, close_session, finalize, init};
        let _ = finalize();
        init().unwrap();
        let sess = bootstrap_default_token(0, "so", "user", "t4-multipart").unwrap();

        let msg = b"hash-composite multi-part message";
        let parts: [&[u8]; 3] = [&msg[..5], &[], &msg[5..]];

        // RSA PKCS#1 v1.5 — deterministic: byte-equal with the one-shot.
        let (rsa_pub, rsa_prv) = generate_rsa_keypair(sess, 2048, b"t4-rsa", "t4-rsa").unwrap();
        for mech in [CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS] {
            let expected = one_shot_sign(sess, mech, rsa_prv, msg);
            let sig = multipart_sign(sess, mech, rsa_prv, &parts);
            assert_eq!(sig, expected, "PKCS#1 v1.5 mech 0x{mech:x} not byte-equal");
            assert_eq!(
                multipart_verify(sess, mech, rsa_pub, &parts, &sig),
                CKR_OK,
                "multi-part verify mech 0x{mech:x}"
            );
        }

        // RSA-PSS — randomized salt: verify-validates in both directions.
        let pss_sig = multipart_sign(sess, CKM_SHA256_RSA_PKCS_PSS, rsa_prv, &parts);
        assert_eq!(
            one_shot_verify(sess, CKM_SHA256_RSA_PKCS_PSS, rsa_pub, msg, &pss_sig),
            CKR_OK,
            "one-shot verify of multi-part PSS signature"
        );
        let pss_one_shot = one_shot_sign(sess, CKM_SHA256_RSA_PKCS_PSS, rsa_prv, msg);
        assert_eq!(
            multipart_verify(sess, CKM_SHA256_RSA_PKCS_PSS, rsa_pub, &parts, &pss_one_shot),
            CKR_OK,
            "multi-part verify of one-shot PSS signature"
        );

        // ECDSA (hashed) — randomized k: verify-validates in both directions.
        let (ec_pub, ec_prv) =
            generate_ecdsa_keypair(sess, EccCurve::P256, b"t4-ec", "t4-ec").unwrap();
        let ec_sig = multipart_sign(sess, CKM_ECDSA_SHA256, ec_prv, &parts);
        assert_eq!(
            one_shot_verify(sess, CKM_ECDSA_SHA256, ec_pub, msg, &ec_sig),
            CKR_OK,
            "one-shot verify of multi-part ECDSA signature"
        );
        let ec_one_shot = one_shot_sign(sess, CKM_ECDSA_SHA256, ec_prv, msg);
        assert_eq!(
            multipart_verify(sess, CKM_ECDSA_SHA256, ec_pub, &parts, &ec_one_shot),
            CKR_OK,
            "multi-part verify of one-shot ECDSA signature"
        );
        // SHA-3 composite (T1 widened): multi-part sign → multi-part verify.
        let ec_sig3 = multipart_sign(sess, CKM_ECDSA_SHA3_256, ec_prv, &parts);
        assert_eq!(
            multipart_verify(sess, CKM_ECDSA_SHA3_256, ec_pub, &parts, &ec_sig3),
            CKR_OK,
            "SHA3-composite ECDSA multi-part round-trip"
        );

        close_session(sess).unwrap();
    }
}
