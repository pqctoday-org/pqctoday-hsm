//! KMIP 3.0 Group E (wave 1): MAC, MACVerify, Hash.
//!
//! Spec mapping:
//!
//! - MAC       §6.1.36 — keyed MAC over `data` using the Managed Object
//! - MACVerify §6.1.37 — verify a MAC against `data + mac_data`
//! - Hash      §6.1.28 — keyless cryptographic hash
//!
//! Single-part HMAC-SHA-{256,384,512} (driven by the key's
//! CryptographicAlgorithm) and Hash with SHA-{256,384,512}.
//! Multi-part state-machine + SHA-1 / SHA3 / RIPEMD aren't in the OASIS
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
    canonical_name, emit_pkcs11, emit_pkcs11_result, emit_request, emit_success, fail_err,
    state_name,
};

// ── MAC ────────────────────────────────────────────────────────────────────

pub fn mac(deps: &Deps, req: MacRequest, correlation_id: &str) -> Result<MacResponse> {
    let started = OffsetDateTime::now_utc();
    emit_request(deps, correlation_id, "MAC", format!("uid={} data_len={}", req.uid, req.data.len()));

    let obj = deps.store.get(&req.uid)?.ok_or_else(|| {
        fail_err(deps, correlation_id, "MAC", KmipError::object_not_found(&req.uid))
    })?;
    require_active(&obj, "MAC")?;
    // KMIP 3.0 §11 Cryptographic Usage Mask — MAC requires the
    // `MAC Generate` bit (0x80); missing → 0x29 (K12, audit K-9).
    super::helpers::enforce_usage_mask(
        deps, correlation_id, "MAC", &obj, crate::kmip30::UsageMask::MAC_GENERATE,
    )?;
    policy_gate(deps, &obj, "MAC", started, correlation_id)?;

    // KMIP 3.0 §6.1.36 — MAC algorithm selection: request's
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
    let mac_bytes = match (&obj.key_material, deps.engine_session) {
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
    correlation_id: &str,
) -> Result<MacVerifyResponse> {
    let started = OffsetDateTime::now_utc();
    emit_request(deps, correlation_id, "MACVerify",
                 format!("uid={} data_len={} mac_len={}", req.uid, req.data.len(), req.mac_data.len()));

    let obj = deps.store.get(&req.uid)?.ok_or_else(|| {
        fail_err(deps, correlation_id, "MACVerify", KmipError::object_not_found(&req.uid))
    })?;
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
    let validity = match (&obj.key_material, deps.engine_session) {
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
    // Archived material is off-line (§6.1.4 / §6.1.47), so MAC /
    // MACVerify fail until Recover.
    if obj.archived {
        return Err(KmipError::object_archived(&obj.uid));
    }
    Ok(())
}

fn policy_gate(deps: &Deps, obj: &ObjectRecord, op: &'static str, started: OffsetDateTime, correlation_id: &str) -> Result<()> {
    let empty: HashMap<String, String> = HashMap::new();
    let algo = canonical_name(obj.algorithm);
    let mut p_req = PolicyRequest::minimal(op, Some(&algo), started, correlation_id, &empty);
    p_req.state = Some(state_name(obj.state));
    p_req.target_uid = Some(&obj.uid);
    if let Decision::Deny { human, .. } = deps.engine.evaluate(&p_req) {
        return Err(fail_err(deps, correlation_id, op, KmipError::permission_denied(human)));
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
        other => {
            return Err(fail_err(deps, correlation_id, op, KmipError::failed(
                ResultReason::OperationNotSupported,
                format!("MAC algorithm {other:?} not supported (HmacSha256/384/512)"),
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
        other => return Err(KmipError::failed(
            ResultReason::OperationNotSupported,
            format!("MAC algorithm {other:?} not supported (v0.1 = HmacSha256/384/512)"),
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
        other => return Err(KmipError::failed(
            ResultReason::OperationNotSupported,
            format!("Hash algorithm {other:?} not supported (v0.1 = SHA-256/384/512)"),
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
        engine.activate(load_from_str(
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
        }, "c").unwrap_err();
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
        }, "c").unwrap_err();
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
        }, "c").unwrap();
        assert_eq!(m.mac_data.len(), 32, "HMAC-SHA-256 output is 32 bytes");
        let v = mac_verify(&d, MacVerifyRequest {
            uid: "u".into(),
            cryptographic_parameters: None,
            data: b"hello world".to_vec(),
            mac_data: m.mac_data,
        }, "c").unwrap();
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
        engine.activate(load_from_str(
            "schema_version: 1\nmetadata: {name: t, description: t, authority: t, effective: always}\nrules: []\n",
            std::path::Path::new("<t>"),
        ).unwrap()).unwrap();
        let d = Deps::new(engine, Arc::new(MemoryStore::new()), sink, super::super::deps::DepsConfig::default());
        put_hmac(&d, "u", vec![7u8; 32]);
        let m = mac(&d, MacRequest {
            uid: "u".into(),
            cryptographic_parameters: None,
            data: b"payload".to_vec(),
        }, "c-soft").unwrap();
        mac_verify(&d, MacVerifyRequest {
            uid: "u".into(),
            cryptographic_parameters: None,
            data: b"payload".to_vec(),
            mac_data: m.mac_data,
        }, "c-soft").unwrap();
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
        }, "c").unwrap();
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
