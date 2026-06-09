//! KMIP 3.0 Group E (wave 1): MAC, MACVerify, Hash.
//!
//! Spec mapping:
//!
//! - MAC       §6.1.36 — keyed MAC over `data` using the Managed Object
//! - MACVerify §6.1.37 — verify a MAC against `data + mac_data`
//! - Hash      §6.1.28 — keyless cryptographic hash
//!
//! v0.1 supports single-part HMAC-SHA-{256,384,512} (driven by the
//! key's CryptographicAlgorithm) and Hash with SHA-{256,384,512}.
//! Multi-part state-machine + SHA-1 / SHA3 / RIPEMD aren't in the OASIS
//! corpus we test against, so they error with OperationNotSupported.

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
use super::helpers::{canonical_name, emit_request, emit_success, fail_err, state_name};

// ── MAC ────────────────────────────────────────────────────────────────────

pub fn mac(deps: &Deps, req: MacRequest, correlation_id: &str) -> Result<MacResponse> {
    let started = OffsetDateTime::now_utc();
    emit_request(deps, correlation_id, "MAC", format!("uid={} data_len={}", req.uid, req.data.len()));

    let obj = deps.store.get(&req.uid)?.ok_or_else(|| {
        fail_err(deps, correlation_id, "MAC", KmipError::not_found(&req.uid))
    })?;
    require_active(&obj, "MAC")?;
    policy_gate(deps, &obj, "MAC", started, correlation_id)?;

    let key_bytes = obj.key_material.as_deref().ok_or_else(|| {
        fail_err(deps, correlation_id, "MAC", KmipError::failed(
            ResultReason::CryptographicFailure,
            "MAC requires registered key material (Register / Import the key first)".to_string(),
        ))
    })?;
    let mac_bytes = compute_mac(obj.algorithm, key_bytes, &req.data)?;

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
        fail_err(deps, correlation_id, "MACVerify", KmipError::not_found(&req.uid))
    })?;
    require_active(&obj, "MACVerify")?;
    policy_gate(deps, &obj, "MACVerify", started, correlation_id)?;

    let key_bytes = obj.key_material.as_deref().ok_or_else(|| {
        fail_err(deps, correlation_id, "MACVerify", KmipError::failed(
            ResultReason::CryptographicFailure,
            "MACVerify requires registered key material".to_string(),
        ))
    })?;

    let computed = compute_mac(obj.algorithm, key_bytes, &req.data)?;
    // Per KMIP §3.x: verification result is signalled via ValidityIndicator,
    // not via Result Status. Mismatched MACs do NOT raise OperationFailed.
    let validity = if computed == req.mac_data {
        SignatureValidity::Valid
    } else {
        SignatureValidity::Invalid
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

/// Compute HMAC over `data` using `key_bytes`. The KMIP key's
/// CryptographicAlgorithm selects the hash variant (HmacSha256/384/512).
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
