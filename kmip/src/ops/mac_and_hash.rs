//! KMIP 3.0 Group E (wave 1): MAC, MACVerify, Hash.
//!
//! Spec mapping:
//!
//! - MAC       §6.1.38 — keyed MAC over `data` using the Managed Object
//! - MACVerify §6.1.39 — verify a MAC against `data + mac_data`
//! - Hash      §6.1.30 — keyless cryptographic hash
//!
//! Single-part HMAC-SHA-{256,384,512,3-256,3-512} (driven by the key's
//! CryptographicAlgorithm) and Hash with SHA-{256,384,512}. SHA3-256/512
//! HMAC wired 2026-08-30 (KMIP/CACP coverage gap-analysis item 6) — the
//! engine has always supported them, only this op layer hadn't picked them
//! up. Multi-part state-machine + SHA-1 / RIPEMD aren't in the OASIS
//! corpus we test against, so they error with OperationNotSupported.
//!
//! ## Key-material routing (K15, compliance-audit B-9)
//!
//! - **Engine-resident key** (Create'd inside the engine — no
//!   `key_material` in the KMIP store, engine session wired): MAC and
//!   MACVerify run through `softhsmrustv3::native::sign` / `verify`
//!   with `CKM_SHA{256,384,512}_HMAC`. Audit names `native::sign` /
//!   `native::verify`.
//! - **KMIP-store-only key** (Register'd raw bytes in `key_material`):
//!   in-process `hmac` crate fallback — the bytes never entered the
//!   engine, so there is no handle to drive. Audit names `soft::hmac`.

use std::collections::HashMap;
use time::OffsetDateTime;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::error::{KmipError, Result, ResultReason};
use crate::kmip30::{
    HashRequest, HashResponse, HashingAlgorithm, KmipAlgorithm, MacRequest, MacResponse,
    MacVerifyRequest, MacVerifyResponse, SignatureValidity, State,
};
use crate::policy::{Decision, PolicyRequest};
use crate::store::ObjectRecord;

use super::deps::Deps;
use super::helpers::{
    emit_pkcs11, emit_pkcs11_result, emit_request, emit_success, fail_err,
    state_name,
};

// ── MAC ────────────────────────────────────────────────────────────────────

pub fn mac(
    deps: &Deps,
    req: MacRequest,
    auth: &crate::server::auth::AuthContext,
    correlation_id: &str,
) -> Result<MacResponse> {
    let started = OffsetDateTime::now_utc();
    emit_request(deps, correlation_id, "MAC", format!("uid={} data_len={}", req.uid, req.data.len()));

    // Part F §F7.4 — owner-checked lookup (see get.rs for the pattern).
    let obj = super::helpers::authorize_object(deps, auth, &req.uid, || {
        KmipError::object_not_found(&req.uid)
    })
    .map_err(|e| fail_err(deps, correlation_id, "MAC", e))?;
    require_active(&obj, "MAC")?;
    // KMIP 3.0 §11 Cryptographic Usage Mask — MAC requires the
    // `MAC Generate` bit (0x80); missing → 0x29 (K12, audit K-9).
    super::helpers::enforce_usage_mask(
        deps, correlation_id, "MAC", &obj, crate::kmip30::UsageMask::MAC_GENERATE,
    )?;
    policy_gate(deps, &obj, "MAC", started, correlation_id)?;

    // KMIP 3.0 §6.1.38 — MAC algorithm selection: request's
    // CryptographicParameters wins; else the object's stored
    // CryptographicParameters attribute; else the object's
    // CryptographicAlgorithm (e.g. a key registered as HmacShaXxx
    // directly). CS-AC-M-4/5/6 register `AES` raw key bytes with the
    // HMAC algorithm pinned via CryptographicParameters.
    let mac_algo = req
        .cryptographic_parameters
        .as_ref()
        .and_then(|cp| cp.cryptographic_algorithm)
        .or_else(|| obj.cryptographic_parameters.as_ref().and_then(|cp| cp.cryptographic_algorithm))
        .unwrap_or(obj.algorithm);

    // K15 (B-9) — engine-resident keys MAC through the engine; the
    // in-process `hmac` crate runs ONLY for KMIP-store-only keys.
    let mac_bytes = match (&obj.key_material, deps.resolve_tenant_session(auth.identity.as_ref()).ok()) {
        (None, Some(session)) => {
            let (handle, mech) =
                engine_hmac_target(deps, correlation_id, "MAC", session, &obj, mac_algo)?;
            let r = softhsmrustv3::native::sign(session, handle, mech, &req.data);
            emit_pkcs11_result(deps, correlation_id, "native::sign", Some(mech), &r);
            r.map_err(|rv| {
                fail_err(deps, correlation_id, "MAC",
                    super::helpers::ck_rv_to_kmip_error(rv, "MAC"))
            })?
        }
        (Some(key_bytes), _) => {
            let out = compute_mac(mac_algo, key_bytes, &req.data)
                .map_err(|e| fail_err(deps, correlation_id, "MAC", e))?;
            emit_pkcs11(deps, correlation_id, "soft::hmac", None, 0, "CKR_OK");
            out
        }
        (None, None) => {
            return Err(fail_err(deps, correlation_id, "MAC", KmipError::failed(
                ResultReason::CryptographicFailure,
                "MAC requires registered key material (Register / Import the key first)"
                    .to_string(),
            )));
        }
    };

    emit_success(deps, correlation_id, "MAC");
    Ok(MacResponse { uid: req.uid, mac_data: mac_bytes })
}

// ── MACVerify ──────────────────────────────────────────────────────────────

pub fn mac_verify(
    deps: &Deps,
    req: MacVerifyRequest,
    auth: &crate::server::auth::AuthContext,
    correlation_id: &str,
) -> Result<MacVerifyResponse> {
    let started = OffsetDateTime::now_utc();
    emit_request(deps, correlation_id, "MACVerify",
                 format!("uid={} data_len={} mac_len={}", req.uid, req.data.len(), req.mac_data.len()));

    // Part F §F7.4 — owner-checked lookup (see get.rs for the pattern).
    let obj = super::helpers::authorize_object(deps, auth, &req.uid, || {
        KmipError::object_not_found(&req.uid)
    })
    .map_err(|e| fail_err(deps, correlation_id, "MACVerify", e))?;
    require_active(&obj, "MACVerify")?;
    // KMIP 3.0 §11 Cryptographic Usage Mask — MAC Verify requires the
    // `MAC Verify` bit (0x100); missing → 0x29 (K12, audit K-9).
    super::helpers::enforce_usage_mask(
        deps, correlation_id, "MACVerify", &obj, crate::kmip30::UsageMask::MAC_VERIFY,
    )?;
    policy_gate(deps, &obj, "MACVerify", started, correlation_id)?;

    let mac_algo = req
        .cryptographic_parameters
        .as_ref()
        .and_then(|cp| cp.cryptographic_algorithm)
        .or_else(|| obj.cryptographic_parameters.as_ref().and_then(|cp| cp.cryptographic_algorithm))
        .unwrap_or(obj.algorithm);

    // Per KMIP §3.x: verification result is signalled via ValidityIndicator,
    // not via Result Status. Mismatched MACs do NOT raise OperationFailed.
    // K15 (B-9) — engine-resident keys verify through the engine
    // (`native::verify` HMAC dispatch); in-process recompute-and-compare
    // ONLY for KMIP-store-only keys.
    let validity = match (&obj.key_material, deps.resolve_tenant_session(auth.identity.as_ref()).ok()) {
        (None, Some(session)) => {
            let (handle, mech) =
                engine_hmac_target(deps, correlation_id, "MACVerify", session, &obj, mac_algo)?;
            let r = softhsmrustv3::native::verify(session, handle, mech, &req.data, &req.mac_data);
            emit_pkcs11_result(deps, correlation_id, "native::verify", Some(mech), &r);
            match r {
                Ok(true) => SignatureValidity::Valid,
                Ok(false) => SignatureValidity::Invalid,
                Err(rv) => {
                    return Err(fail_err(deps, correlation_id, "MACVerify",
                        super::helpers::ck_rv_to_kmip_error(rv, "MACVerify")));
                }
            }
        }
        (Some(key_bytes), _) => {
            let computed = compute_mac(mac_algo, key_bytes, &req.data)
                .map_err(|e| fail_err(deps, correlation_id, "MACVerify", e))?;
            emit_pkcs11(deps, correlation_id, "soft::hmac", None, 0, "CKR_OK");
            if computed == req.mac_data {
                SignatureValidity::Valid
            } else {
                SignatureValidity::Invalid
            }
        }
        (None, None) => {
            return Err(fail_err(deps, correlation_id, "MACVerify", KmipError::failed(
                ResultReason::CryptographicFailure,
                "MACVerify requires registered key material".to_string(),
            )));
        }
    };

    emit_success(deps, correlation_id, "MACVerify");
    Ok(MacVerifyResponse { uid: req.uid, validity })
}

// ── Hash ───────────────────────────────────────────────────────────────────

pub fn hash(deps: &Deps, req: HashRequest, correlation_id: &str) -> Result<HashResponse> {
    emit_request(deps, correlation_id, "Hash",
                 format!("data_len={} algo={:?}", req.data.len(),
                         req.cryptographic_parameters.hashing_algorithm));

    let algo = req.cryptographic_parameters.hashing_algorithm.ok_or_else(|| {
        fail_err(deps, correlation_id, "Hash", KmipError::failed(
            ResultReason::MissingData,
            "Hash requires Cryptographic Parameters with Hashing Algorithm".to_string(),
        ))
    })?;

    // W2.2 — Plane-1 gate for the keyless Hash op: surface the requested
    // Hashing Algorithm so `hash_algorithm_allowlist` can restrict it (e.g.
    // deny SHA-1). No managed object, so the request carries no algorithm/key.
    {
        let empty: HashMap<String, String> = HashMap::new();
        let mut p_req = PolicyRequest::minimal(
            "Hash",
            None,
            OffsetDateTime::now_utc(),
            correlation_id,
            &empty,
        );
        p_req.mechanism.hashing_algorithm = Some(algo as u32);
        if let Decision::Deny { kmip_reason, human, .. } = deps.engine.evaluate(&p_req) {
            return Err(fail_err(deps, correlation_id, "Hash", KmipError::failed(kmip_reason.to_result_reason(), human)));
        }
    }

    let bytes = compute_hash(algo, &req.data).map_err(|e| {
        fail_err(deps, correlation_id, "Hash", e)
    })?;

    emit_success(deps, correlation_id, "Hash");
    Ok(HashResponse { data: bytes })
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn require_active(obj: &ObjectRecord, _op: &'static str) -> Result<()> {
    if obj.state != State::Active {
        return Err(super::helpers::non_active_state_error(&obj.uid, obj.state));
    }
    // K22 — KMIP 3.0 §11 `Object Archived` (0x0d): "The object SHALL
    // be recovered from the archive before performing the operation."
    // Archived material is off-line (§6.1.4 / §6.1.49), so MAC /
    // MACVerify fail until Recover.
    if obj.archived {
        return Err(KmipError::object_archived(&obj.uid));
    }
    Ok(())
}

fn policy_gate(deps: &Deps, obj: &ObjectRecord, op: &'static str, started: OffsetDateTime, correlation_id: &str) -> Result<()> {
    // Y1 stored classification; Y3 qualified name (HMAC names already qualified).
    let stored_attrs = super::helpers::strip_x_prefixes(&obj.custom_attributes);
    let algo = super::helpers::qualified_name(obj.algorithm, obj.cryptographic_length);
    let mut p_req = PolicyRequest::minimal(op, Some(&algo), started, correlation_id, &stored_attrs);
    p_req.state = Some(state_name(obj.state));
    p_req.target_uid = Some(&obj.uid);
    if let Decision::Deny { kmip_reason, human, .. } = deps.engine.evaluate(&p_req) {
        return Err(fail_err(deps, correlation_id, op, KmipError::failed(kmip_reason.to_result_reason(), human)));
    }
    Ok(())
}

/// Resolve the engine handle + `CKM_SHA*_HMAC` mechanism for an
/// engine-resident MAC key (K15). The engine's `native::sign` /
/// `native::verify` dispatch these mechanisms directly
/// (`rust/src/native/sign.rs` HMAC arms).
fn engine_hmac_target(
    deps: &Deps,
    correlation_id: &str,
    op: &'static str,
    session: u32,
    obj: &ObjectRecord,
    mac_algo: KmipAlgorithm,
) -> Result<(u32, u32)> {
    use softhsmrustv3::constants as c;
    let mech = match mac_algo {
        KmipAlgorithm::HmacSha256 => c::CKM_SHA256_HMAC,
        KmipAlgorithm::HmacSha384 => c::CKM_SHA384_HMAC,
        KmipAlgorithm::HmacSha512 => c::CKM_SHA512_HMAC,
        // KMIP/CACP coverage gap-analysis item 6 (2026-08-30).
        KmipAlgorithm::HmacSha3_256 => c::CKM_SHA3_256_HMAC,
        KmipAlgorithm::HmacSha3_512 => c::CKM_SHA3_512_HMAC,
        other => {
            return Err(fail_err(deps, correlation_id, op, KmipError::failed(
                ResultReason::OperationNotSupported,
                format!("MAC algorithm {other:?} not supported (HmacSha256/384/512/HmacSha3-256/512)"),
            )));
        }
    };
    let handle =
        super::helpers::find_handle_for_object(session, &obj.pkcs11_cka_id, obj.object_type)
            .map_err(|rv| {
                fail_err(deps, correlation_id, op,
                    super::helpers::ck_rv_to_kmip_error(rv, op))
            })?
            .ok_or_else(|| {
                fail_err(deps, correlation_id, op, KmipError::object_not_found(&obj.uid))
            })?;
    Ok((handle, mech))
}

/// Compute HMAC over `data` using `key_bytes`. The KMIP key's
/// CryptographicAlgorithm selects the hash variant (HmacSha256/384/512).
/// K15 — in-process fallback for KMIP-store-only keys (Register'd raw
/// bytes that never entered the engine); engine-resident keys go
/// through `native::sign` / `native::verify` instead.
fn compute_mac(algo: KmipAlgorithm, key_bytes: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    Ok(match algo {
        KmipAlgorithm::HmacSha256 => {
            let mut h = <Hmac<Sha256> as Mac>::new_from_slice(key_bytes)
                .map_err(|e| KmipError::failed(ResultReason::CryptographicFailure, format!("HMAC-SHA-256 key: {e}")))?;
            h.update(data);
            h.finalize().into_bytes().to_vec()
        }
        KmipAlgorithm::HmacSha384 => {
            let mut h = <Hmac<Sha384> as Mac>::new_from_slice(key_bytes)
                .map_err(|e| KmipError::failed(ResultReason::CryptographicFailure, format!("HMAC-SHA-384 key: {e}")))?;
            h.update(data);
            h.finalize().into_bytes().to_vec()
        }
        KmipAlgorithm::HmacSha512 => {
            let mut h = <Hmac<Sha512> as Mac>::new_from_slice(key_bytes)
                .map_err(|e| KmipError::failed(ResultReason::CryptographicFailure, format!("HMAC-SHA-512 key: {e}")))?;
            h.update(data);
            h.finalize().into_bytes().to_vec()
        }
        // KMIP/CACP coverage gap-analysis item 6 (2026-08-30) — the engine
        // has supported HMAC-SHA3-256/512 all along; this crate's op layer
        // just never dispatched to it.
        KmipAlgorithm::HmacSha3_256 => {
            let mut h = <Hmac<sha3::Sha3_256> as Mac>::new_from_slice(key_bytes)
                .map_err(|e| KmipError::failed(ResultReason::CryptographicFailure, format!("HMAC-SHA3-256 key: {e}")))?;
            h.update(data);
            h.finalize().into_bytes().to_vec()
        }
        KmipAlgorithm::HmacSha3_512 => {
            let mut h = <Hmac<sha3::Sha3_512> as Mac>::new_from_slice(key_bytes)
                .map_err(|e| KmipError::failed(ResultReason::CryptographicFailure, format!("HMAC-SHA3-512 key: {e}")))?;
            h.update(data);
            h.finalize().into_bytes().to_vec()
        }
        other => return Err(KmipError::failed(
            ResultReason::OperationNotSupported,
            format!("MAC algorithm {other:?} not supported (v0.1 = HmacSha256/384/512/HmacSha3-256/512)"),
        )),
    })
}

fn compute_hash(algo: HashingAlgorithm, data: &[u8]) -> Result<Vec<u8>> {
    Ok(match algo {
        HashingAlgorithm::Sha256 => {
            let mut h = Sha256::new();
            h.update(data);
            h.finalize().to_vec()
        }
        HashingAlgorithm::Sha384 => {
            let mut h = Sha384::new();
            h.update(data);
            h.finalize().to_vec()
        }
        HashingAlgorithm::Sha512 => {
            let mut h = Sha512::new();
            h.update(data);
            h.finalize().to_vec()
        }
        // G3 (2026-09-02) — widening item: `Hash` (§6.1.30) is genuinely
        // keyless/sessionless (see this file's own header comment and the
        // `hash()` handler above, which never resolves an engine session
        // at all), so — matching the SHA-256/384/512 arms directly
        // above, the crate's own existing convention for this exact
        // function — these stay in-process too, not routed through an
        // engine mechanism. `hash_derive` (`ops/derive_key.rs`) is the
        // crate's other Hash-family function, and it's engine-backed
        // where a session is available; that pattern doesn't apply here
        // because `compute_hash` (and `hash()`, its only caller) has no
        // session parameter to route through in the first place.
        HashingAlgorithm::Sha512224 => {
            let mut h = sha2::Sha512_224::new();
            h.update(data);
            h.finalize().to_vec()
        }
        HashingAlgorithm::Sha512256 => {
            let mut h = sha2::Sha512_256::new();
            h.update(data);
            h.finalize().to_vec()
        }
        HashingAlgorithm::Sha3224 => {
            let mut h = sha3::Sha3_224::new();
            h.update(data);
            h.finalize().to_vec()
        }
        HashingAlgorithm::Sha3256 => {
            let mut h = sha3::Sha3_256::new();
            h.update(data);
            h.finalize().to_vec()
        }
        HashingAlgorithm::Sha3384 => {
            let mut h = sha3::Sha3_384::new();
            h.update(data);
            h.finalize().to_vec()
        }
        HashingAlgorithm::Sha3512 => {
            let mut h = sha3::Sha3_512::new();
            h.update(data);
            h.finalize().to_vec()
        }
        other => return Err(KmipError::failed(
            ResultReason::OperationNotSupported,
            format!(
                "Hash algorithm {other:?} not supported (v0.1 = SHA-256/384/512, \
                 SHA-512/224, SHA-512/256, SHA3-224/256/384/512)"
            ),
        )),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditlog::{AuditSink, RingSink};
    use crate::kmip30::{CryptographicParameters as CP, KmipAlgorithm, ObjectType, UsageMask};
    use crate::policy::{load_from_str, Engine};
    use crate::store::{MemoryStore, ObjectRecord};
    use std::sync::Arc;

    fn deps_with() -> Deps {
        let ring = Arc::new(RingSink::new(64));
        let sink: Arc<dyn AuditSink> = ring.clone();
        let engine = Engine::with_global_sink(sink.clone());
        engine.replace_all(load_from_str(
            "schema_version: 1\nmetadata: {name: t, description: t, authority: t, effective: always}\nrules: []\n",
            std::path::Path::new("<t>"),
        ).unwrap()).unwrap();
        Deps::new(engine, Arc::new(MemoryStore::new()), sink, super::super::deps::DepsConfig::default())
    }

    fn put_hmac(d: &Deps, uid: &str, key: Vec<u8>) {
        d.store.put(ObjectRecord {
            uid: uid.into(),
            object_type: ObjectType::SymmetricKey,
            algorithm: KmipAlgorithm::HmacSha256,
            cryptographic_length: 256,
            usage_mask: UsageMask::MAC_GENERATE | UsageMask::MAC_VERIFY,
            state: State::Active,
            pkcs11_cka_id: vec![],
            pkcs11_slot: 0,
            initial_date: OffsetDateTime::UNIX_EPOCH,
            activation_date: None,
            supersedes: None,
            name: None,
            links: HashMap::new(),
            custom_attributes: HashMap::new(),
            key_material: Some(key),
            key_format_type: Some(0x01),
        ..ObjectRecord::default()
}).unwrap();
    }

    /// K12 — §11 Cryptographic Usage Mask: MAC requires `MAC Generate`
    /// (0x80) and MACVerify requires `MAC Verify` (0x100); a present
    /// mask without the bit fails 0x29. Positive case is pinned by
    /// `mac_then_verify_round_trips` (mask = MAC_GENERATE | MAC_VERIFY).
    #[test]
    fn mac_ops_without_required_mask_bits_are_incompatible() {
        let d = deps_with();
        // Key with only MAC_VERIFY → MAC (generate) is rejected …
        d.store.put(ObjectRecord {
            uid: "v".into(),
            object_type: ObjectType::SymmetricKey,
            algorithm: KmipAlgorithm::HmacSha256,
            usage_mask: UsageMask::MAC_VERIFY,
            state: State::Active,
            key_material: Some(vec![0u8; 32]),
            ..ObjectRecord::default()
        }).unwrap();
        let err = mac(&d, MacRequest {
            uid: "v".into(),
            cryptographic_parameters: None,
            data: b"x".to_vec(),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::IncompatibleCryptographicUsageMask);
        // … and a key with only MAC_GENERATE can't MACVerify.
        d.store.put(ObjectRecord {
            uid: "g".into(),
            object_type: ObjectType::SymmetricKey,
            algorithm: KmipAlgorithm::HmacSha256,
            usage_mask: UsageMask::MAC_GENERATE,
            state: State::Active,
            key_material: Some(vec![0u8; 32]),
            ..ObjectRecord::default()
        }).unwrap();
        let err = mac_verify(&d, MacVerifyRequest {
            uid: "g".into(),
            cryptographic_parameters: None,
            data: b"x".to_vec(),
            mac_data: vec![0u8; 32],
        }, &crate::server::auth::AuthContext::open(), "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::IncompatibleCryptographicUsageMask);
    }

    #[test]
    fn mac_then_verify_round_trips() {
        let d = deps_with();
        put_hmac(&d, "u", vec![0u8; 32]);
        let m = mac(&d, MacRequest {
            uid: "u".into(),
            cryptographic_parameters: None,
            data: b"hello world".to_vec(),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        assert_eq!(m.mac_data.len(), 32, "HMAC-SHA-256 output is 32 bytes");
        let v = mac_verify(&d, MacVerifyRequest {
            uid: "u".into(),
            cryptographic_parameters: None,
            data: b"hello world".to_vec(),
            mac_data: m.mac_data,
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        assert_eq!(v.validity, SignatureValidity::Valid);
    }

    /// KMIP/CACP coverage gap-analysis item 6 (2026-08-30) — HMAC-SHA3-256
    /// via the Mac op, wired for the first time. Not just a round trip:
    /// the raw byte output is checked against an independently-computed
    /// reference (Python's `hmac`/`hashlib`, a different implementation
    /// than this crate's `hmac`/`sha3` crates), so a wrong-hash or
    /// wrong-key-handling bug that happened to be self-consistent would
    /// still be caught.
    #[test]
    fn hmac_sha3_256_matches_independent_reference() {
        let d = deps_with();
        d.store.put(ObjectRecord {
            uid: "u3".into(),
            object_type: ObjectType::SymmetricKey,
            algorithm: KmipAlgorithm::HmacSha3_256,
            cryptographic_length: 256,
            usage_mask: UsageMask::MAC_GENERATE | UsageMask::MAC_VERIFY,
            state: State::Active,
            pkcs11_cka_id: vec![],
            pkcs11_slot: 0,
            initial_date: OffsetDateTime::UNIX_EPOCH,
            activation_date: None,
            supersedes: None,
            name: None,
            links: HashMap::new(),
            custom_attributes: HashMap::new(),
            key_material: Some(vec![0u8; 32]),
            key_format_type: Some(0x01),
            ..ObjectRecord::default()
        }).unwrap();
        let m = mac(&d, MacRequest {
            uid: "u3".into(),
            cryptographic_parameters: None,
            data: b"hello world".to_vec(),
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        assert_eq!(
            hex::encode(&m.mac_data),
            "6deaf15552c952200416ed0781b5d81b53d7f709f8a764ce6a04ff83edf6376b",
            "must match an independent Python hmac/hashlib(sha3_256) computation over the same 32-byte-zero key and \"hello world\""
        );
        let v = mac_verify(&d, MacVerifyRequest {
            uid: "u3".into(),
            cryptographic_parameters: None,
            data: b"hello world".to_vec(),
            mac_data: m.mac_data,
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        assert_eq!(v.validity, SignatureValidity::Valid);
    }

    /// K15 (B-9) — a KMIP-store-only key (Register'd raw bytes, no
    /// engine handle) runs the documented in-process fallback, and the
    /// Plane-3 audit names it `soft::hmac` — never an engine entry
    /// point that didn't run.
    #[test]
    fn store_only_key_audits_soft_hmac_path() {
        use crate::auditlog::{EventPayload, Plane};
        let ring = Arc::new(RingSink::new(64));
        let sink: Arc<dyn AuditSink> = ring.clone();
        let engine = Engine::with_global_sink(sink.clone());
        engine.replace_all(load_from_str(
            "schema_version: 1\nmetadata: {name: t, description: t, authority: t, effective: always}\nrules: []\n",
            std::path::Path::new("<t>"),
        ).unwrap()).unwrap();
        let d = Deps::new(engine, Arc::new(MemoryStore::new()), sink, super::super::deps::DepsConfig::default());
        put_hmac(&d, "u", vec![7u8; 32]);
        let m = mac(&d, MacRequest {
            uid: "u".into(),
            cryptographic_parameters: None,
            data: b"payload".to_vec(),
        }, &crate::server::auth::AuthContext::open(), "c-soft").unwrap();
        mac_verify(&d, MacVerifyRequest {
            uid: "u".into(),
            cryptographic_parameters: None,
            data: b"payload".to_vec(),
            mac_data: m.mac_data,
        }, &crate::server::auth::AuthContext::open(), "c-soft").unwrap();
        let p3 = ring.filter_plane(Plane::Pkcs11);
        assert_eq!(p3.len(), 2, "one soft-path record per MAC + MACVerify");
        for e in &p3 {
            assert!(matches!(
                &e.event,
                EventPayload::Pkcs11Call { function, rv: 0, .. } if function == "soft::hmac"
            ), "expected soft::hmac, got {:?}", e.event);
        }
    }

    #[test]
    fn mac_verify_tampered_signals_invalid() {
        let d = deps_with();
        put_hmac(&d, "u", vec![0u8; 32]);
        let v = mac_verify(&d, MacVerifyRequest {
            uid: "u".into(),
            cryptographic_parameters: None,
            data: b"hello world".to_vec(),
            mac_data: vec![0xff; 32],
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        assert_eq!(v.validity, SignatureValidity::Invalid);
    }

    #[test]
    fn hash_sha256_matches_known_value() {
        let d = deps_with();
        let r = hash(&d, HashRequest {
            cryptographic_parameters: CP {
                hashing_algorithm: Some(HashingAlgorithm::Sha256),
                cryptographic_algorithm: None,
                ..CP::default()
            },
            data: b"abc".to_vec(),
        }, "c").unwrap();
        // SHA-256("abc") = ba7816bf...
        assert_eq!(hex::encode(&r.data), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    /// G3 (2026-09-02) widening — SHA-512/224, SHA-512/256, and the SHA3
    /// family, driven through the real KMIP `Hash` operation (`hash()`,
    /// the same handler `hash_sha256_matches_known_value` above exercises
    /// for SHA-256), cross-checked byte-exact against an independently
    /// computed reference: Python's stdlib `hashlib` over the identical
    /// input, computed outside this codebase.
    ///
    /// ```python
    /// import hashlib
    /// data = b"kmip g3 hash widening test"
    /// for name in ["sha512_224", "sha512_256", "sha3_224", "sha3_256", "sha3_384", "sha3_512"]:
    ///     print(name, hashlib.new(name, data).hexdigest())
    /// ```
    #[test]
    fn hash_widening_matches_hashlib() {
        let d = deps_with();
        let data = b"kmip g3 hash widening test".to_vec();
        let cases: &[(HashingAlgorithm, &str)] = &[
            (HashingAlgorithm::Sha512224, "6b1bbe8987bbb5c527b0f725d75f8b3101cb4afcada6104256b225fb"),
            (HashingAlgorithm::Sha512256, "c667acdec69910850d17e26a6d96db5a7896c38da2eda7f75d61ad69cfc6d661"),
            (HashingAlgorithm::Sha3224, "a38efa69bf6edee9f8b6681498da05f527d7bd5b19ef878d06d77e80"),
            (HashingAlgorithm::Sha3256, "99c33ff6c3595d54f8bf4963f202739daaa0c07ff6ba79cdb9a0867168ab2103"),
            (HashingAlgorithm::Sha3384, "d7d23ebb56968024e7e880ea3dc6a424fdb79d4eda78930f08aef1531008a76e8315d03fad6099a393b55efc5edbd74d"),
            (HashingAlgorithm::Sha3512, "71fb8df49cf1517bc810ca63186b7b3d1ff2cf7a30d5516576a61c1ded7a8eb7223bb94e6751bf13f9ffc6f55217ae400192d3cef88d48dc5969d75f33f98127"),
        ];
        for &(algo, expected_hex) in cases {
            let r = hash(&d, HashRequest {
                cryptographic_parameters: CP {
                    hashing_algorithm: Some(algo),
                    cryptographic_algorithm: None,
                    ..CP::default()
                },
                data: data.clone(),
            }, "c").unwrap_or_else(|e| panic!("Hash({algo:?}) failed: {e:?}"));
            assert_eq!(
                hex::encode(&r.data), expected_hex,
                "Hash({algo:?}) must match Python hashlib's independently computed digest",
            );
        }
    }

    #[test]
    fn hash_missing_algorithm_errors() {
        let d = deps_with();
        let err = hash(&d, HashRequest {
            cryptographic_parameters: CP::default(),
            data: b"abc".to_vec(),
        }, "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::MissingData);
    }
}
