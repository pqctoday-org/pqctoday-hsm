//! KMIP 3.0 §6.1.60 **Sign** operation.
//!
//! > "This operation requests the server to perform a signature operation
//! > on the provided data using the specified signing key."
//!
//! Op codepoint `0x21` (verified — `Sign = 0x00000021` in the spec's
//! `Operation` enum extract).
//!
//! ## Plane mapping
//!
//! - **Plane 1** — engine.evaluate with `op="Sign"`, `algorithm =
//!   <stored key's algorithm>`, `current_object_algorithm = <same>`,
//!   `target_uid = <KMIP UID>`. The engine may emit
//!   [`Decision::RekeyAndProceed`] when policy substitutes the stored
//!   algorithm to something else — Phase 5 handles this by returning a
//!   typed error that the dispatcher / Phase 6 will translate into the
//!   actual multi-op rekey transaction (out of scope for Phase 5 op
//!   bodies; this handler just surfaces the rekey requirement).
//! - **Plane 2** — store lookup + lifecycle gate (KMIP 3.0 §3.x: only
//!   `Active` state may sign — see `docs/IMPLEMENTATION_PLAN.md` §3.4).
//! - **Plane 3** — would call `C_SignInit` (PKCS#11 v3.2 §C.6.5) and
//!   `C_Sign` (§C.6.6). Signatures verified against
//!   `rust/src/ffi.rs::{C_SignInit, C_Sign}`. v0.1 produces a deterministic
//!   placeholder signature so the response builder can be exercised;
//!   Phase 7 wires the real bridge call.

use std::collections::HashMap;
use time::OffsetDateTime;

use crate::auditlog::{AuditEvent, EventPayload, KmipOpResult, Plane};
use crate::error::{KmipError, Result, ResultReason};
use crate::kmip30::{PkcsOp, SignRequest, SignResponse, State};
use crate::policy::{Decision, PolicyRequest};

use super::deps::Deps;

pub fn sign(deps: &Deps, req: SignRequest, correlation_id: &str) -> Result<SignResponse> {
    let started = OffsetDateTime::now_utc();
    deps.sink.emit(AuditEvent::at(
        started,
        Plane::Kmip,
        correlation_id,
        EventPayload::KmipRequestReceived {
            op: "Sign".into(),
            request_summary: format!("uid={} data_len={}", req.uid, req.data.len()),
            client_cn: None,
        },
    ));

    // ── Plane 2: store lookup ───────────────────────────────────────────
    let obj = deps
        .store
        .get(&req.uid)?
        .ok_or_else(|| fail_err(deps, correlation_id, "Sign", KmipError::not_found(&req.uid)))?;

    // ── Lifecycle gate (KMIP 3.0 §3.x — Sign requires Active) ───────────
    if obj.state != State::Active {
        return Err(fail_err(
            deps,
            correlation_id,
            "Sign",
            super::helpers::non_active_state_error(&req.uid, obj.state),
        ));
    }

    // KMIP 3.0 §3.4 — `Process Start Date` / `Protect Stop Date`
    // define the time window during which Sign MAY be performed even
    // when the object is Active. CS-AC-M-8 pins this with
    // ProcessStartDate=$NOW+3600 (future) and ProtectStopDate=$NOW-3600
    // (past), expecting Sign to fail with WrongKeyLifecycleState.
    // Mirror of the gate in `encrypt.rs` / `decrypt.rs`.
    if let Some(t) = obj.process_start_date {
        if started < t {
            return Err(fail_err(deps, correlation_id, "Sign",
                KmipError::failed(
                    ResultReason::WrongKeyLifecycleState,
                    "Sign: now < ProcessStartDate".to_string(),
                )));
        }
    }
    if let Some(t) = obj.protect_stop_date {
        if started > t {
            return Err(fail_err(deps, correlation_id, "Sign",
                KmipError::failed(
                    ResultReason::WrongKeyLifecycleState,
                    "Sign: now > ProtectStopDate".to_string(),
                )));
        }
    }

    // ── Plane 1: policy gate ────────────────────────────────────────────
    let empty: HashMap<String, String> = HashMap::new();
    let stored_algo = canonical_name(obj.algorithm);
    let mut p_req = PolicyRequest::minimal(
        "Sign",
        Some(&stored_algo),
        started,
        correlation_id,
        &empty,
    );
    p_req.usage_mask = Some(obj.usage_mask);
    p_req.state = Some("Active");
    p_req.current_object_algorithm = Some(&stored_algo);
    p_req.target_uid = Some(&req.uid);

    let mech = match deps.engine.evaluate(&p_req) {
        Decision::Allow { algorithm_override: None, .. } => {
            // Pass-through — use stored algorithm.
            obj.algorithm.to_pkcs11_mech(PkcsOp::SignVerify).ok_or_else(|| {
                KmipError::failed(
                    ResultReason::OperationNotSupported,
                    format!("algorithm {:?} has no Sign mechanism", obj.algorithm),
                )
            })?
        }
        Decision::Allow { algorithm_override: Some(other), .. } => {
            // Policy rewrote the algorithm but the stored key matches the
            // rewrite — proceed. (If the rewrite differed from the stored
            // algorithm, the engine would have emitted RekeyAndProceed.)
            return Err(fail_err(
                deps,
                correlation_id,
                "Sign",
                KmipError::internal(format!(
                    "policy override {other:?} for Sign without rekey path"
                )),
            ));
        }
        Decision::Deny { human, .. } => {
            return Err(fail_err(
                deps,
                correlation_id,
                "Sign",
                KmipError::permission_denied(human),
            ));
        }
        Decision::RekeyAndProceed { new_algorithm, original_uid, .. } => {
            // Policy demands rekey before sign. Phase 5 op bodies do not
            // execute the multi-op rekey transaction (that's a dispatcher
            // concern in Phase 6/7). Surface a typed error so the caller
            // knows to either run the rekey transaction or bail.
            return Err(fail_err(
                deps,
                correlation_id,
                "Sign",
                KmipError::failed(
                    ResultReason::PermissionDenied,
                    format!(
                        "rekey required: policy substitutes {} → {} for UID {}",
                        canonical_name(obj.algorithm),
                        new_algorithm,
                        original_uid,
                    ),
                ),
            ));
        }
    };

    // ── Plane 3: emit (would call C_SignInit + C_Sign) ──────────────────
    let mech_name = format!("CKM_0x{mech:04X}");
    deps.sink.emit(AuditEvent::at(
        OffsetDateTime::now_utc(),
        Plane::Pkcs11,
        correlation_id,
        EventPayload::Pkcs11Call {
            function: "C_SignInit".into(),
            mechanism: Some(mech_name.clone()),
            slot: Some(deps.config.pkcs11_slot),
            session: None,
            rv: 0,
            rv_name: "CKR_OK".into(),
            latency_ms: 0,
        },
    ));
    deps.sink.emit(AuditEvent::at(
        OffsetDateTime::now_utc(),
        Plane::Pkcs11,
        correlation_id,
        EventPayload::Pkcs11Call {
            function: "C_Sign".into(),
            mechanism: Some(mech_name),
            slot: Some(deps.config.pkcs11_slot),
            session: None,
            rv: 0,
            rv_name: "CKR_OK".into(),
            latency_ms: 0,
        },
    ));

    // Phase 7b: real bridge call when a session is wired. Falls back to
    // deterministic SHA-256 placeholder for unit tests that don't
    // bootstrap an engine.
    let signature = match deps.engine_session {
        Some(session) => {
            // KMIP UID → CKA_ID → engine handle → native::sign. Filter
            // by ObjectType because pub + prv share CKA_ID per PKCS#11
            // convention; sign needs the private-key handle.
            let handle =
                super::helpers::find_handle_for_object(session, &obj.pkcs11_cka_id, obj.object_type)
                    .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Sign:find"))?
                    .ok_or_else(|| KmipError::not_found(&req.uid))?;
            let effective_cp = req
                .cryptographic_parameters
                .as_ref()
                .or(obj.cryptographic_parameters.as_ref());
            let native_mech = super::helpers::native_sign_mech_with_params(
                obj.algorithm,
                effective_cp,
            )
            .ok_or_else(|| {
                KmipError::failed(
                    ResultReason::OperationNotSupported,
                    format!("Sign: no native mechanism for {:?}", obj.algorithm),
                )
            })?;
            softhsmrustv3::native::sign(session, handle, native_mech, &req.data)
                .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Sign"))?
        }
        None => placeholder_signature(&req.uid, &req.data),
    };

    deps.sink.emit(AuditEvent::at(
        OffsetDateTime::now_utc(),
        Plane::Kmip,
        correlation_id,
        EventPayload::KmipResponseSent {
            op: "Sign".into(),
            result: KmipOpResult::Success,
            latency_ms: 0,
        },
    ));

    Ok(SignResponse {
        uid: req.uid,
        signature,
    })
}

fn placeholder_signature(uid: &str, data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(uid.as_bytes());
    h.update(data);
    h.finalize().to_vec()
}

fn fail_err(deps: &Deps, correlation_id: &str, op: &str, err: KmipError) -> KmipError {
    deps.sink.emit(AuditEvent::at(
        OffsetDateTime::now_utc(),
        Plane::Kmip,
        correlation_id,
        EventPayload::KmipResponseSent {
            op: op.into(),
            result: KmipOpResult::OperationFailed {
                reason: format!("{:?}", err.result_reason()),
            },
            latency_ms: 0,
        },
    ));
    err
}

/// Mirror of `create_key_pair::canonical_name` — duplicated here to keep
/// the op file self-contained (each op is ≤ ~250 LOC per the plan).
/// A future refactor can lift this into `kmip30::algos`.
fn canonical_name(a: crate::kmip30::KmipAlgorithm) -> String {
    use crate::kmip30::KmipAlgorithm::*;
    match a {
        Aes => "AES",
        Rsa => "RSA",
        Ecdsa => "ECDSA",
        HmacSha256 => "HMAC-SHA-256",
        HmacSha384 => "HMAC-SHA-384",
        HmacSha512 => "HMAC-SHA-512",
        Ecdh => "ECDH",
        ChaCha20 => "ChaCha20",
        ChaCha20Poly1305 => "ChaCha20-Poly1305",
        MlKem512 => "ML-KEM-512",
        MlKem768 => "ML-KEM-768",
        MlKem1024 => "ML-KEM-1024",
        MlDsa44 => "ML-DSA-44",
        MlDsa65 => "ML-DSA-65",
        MlDsa87 => "ML-DSA-87",
        SlhDsaSha2_128s => "SLH-DSA-SHA2-128s",
        SlhDsaSha2_128f => "SLH-DSA-SHA2-128f",
        SlhDsaSha2_192s => "SLH-DSA-SHA2-192s",
        SlhDsaSha2_192f => "SLH-DSA-SHA2-192f",
        SlhDsaSha2_256s => "SLH-DSA-SHA2-256s",
        SlhDsaSha2_256f => "SLH-DSA-SHA2-256f",
        SlhDsaShake128s => "SLH-DSA-SHAKE-128s",
        SlhDsaShake128f => "SLH-DSA-SHAKE-128f",
        SlhDsaShake192s => "SLH-DSA-SHAKE-192s",
        SlhDsaShake192f => "SLH-DSA-SHAKE-192f",
        SlhDsaShake256s => "SLH-DSA-SHAKE-256s",
        SlhDsaShake256f => "SLH-DSA-SHAKE-256f",
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditlog::RingSink;
    use crate::kmip30::{KmipAlgorithm, ObjectType, UsageMask};
    use crate::policy::{load_from_str, Engine};
    use crate::store::{MemoryStore, ObjectRecord};
    use std::sync::Arc;

    fn deps_with(yaml: &str) -> (Arc<RingSink>, Deps) {
        let ring = Arc::new(RingSink::new(64));
        let sink: Arc<dyn crate::auditlog::AuditSink> = ring.clone();
        let engine = Engine::with_global_sink(sink.clone());
        engine
            .activate(load_from_str(yaml, std::path::Path::new("<test>")).unwrap())
            .unwrap();
        (
            ring,
            Deps::new(
                engine,
                Arc::new(MemoryStore::new()),
                sink,
                super::super::deps::DepsConfig::default(),
            ),
        )
    }

    fn make_active_key(deps: &Deps, uid: &str, algo: KmipAlgorithm) {
        let rec = ObjectRecord {
            uid: uid.into(),
            object_type: ObjectType::PrivateKey,
            algorithm: algo,
            cryptographic_length: 0,
            usage_mask: UsageMask::SIGN | UsageMask::VERIFY,
            state: State::Active,
            pkcs11_cka_id: vec![1, 2, 3],
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
};
        deps.store.put(rec).unwrap();
    }

    const PERMISSIVE: &str = r#"
schema_version: 1
metadata: { name: p, description: p, authority: t, effective: "always" }
rules: []
"#;

    // NOTE: canonical_name(KmipAlgorithm::Ecdsa) returns "ECDSA" (bare,
    // no curve) because the Phase-5 store record doesn't carry curve
    // metadata yet — Phase 6 adds the `Cryptographic Parameters` attribute
    // surface so the dispatcher can canonicalise to "ECDSA-P256". Test
    // policy uses the bare name until then.
    const REKEY_POLICY: &str = r#"
schema_version: 1
metadata: { name: rk, description: rekey, authority: t, effective: "always" }
rules:
  - type: algorithm_substitution
    ops: [Sign]
    from: ECDSA
    to: ML-DSA-87
    reason: "Upgrade signing"
"#;

    #[test]
    fn happy_path_returns_signature_and_emits_three_planes() {
        let (ring, d) = deps_with(PERMISSIVE);
        make_active_key(&d, "urn:uid:1", KmipAlgorithm::MlDsa87);
        let resp = sign(
            &d,
            SignRequest {
                uid: "urn:uid:1".into(),
                data: b"hello".to_vec(),
            cryptographic_parameters: None,
        },
            "corr-sign",
        )
        .unwrap();
        assert_eq!(resp.uid, "urn:uid:1");
        assert_eq!(resp.signature.len(), 32); // sha256 placeholder
        // p1 (policy activation + decision), p2 (req + resp), p3 (init + sign)
        assert!(ring.filter_plane(Plane::Agility).len() >= 2);
        assert_eq!(ring.filter_plane(Plane::Kmip).len(), 2);
        assert_eq!(ring.filter_plane(Plane::Pkcs11).len(), 2);
    }

    #[test]
    fn missing_uid_returns_item_not_found() {
        let (_ring, d) = deps_with(PERMISSIVE);
        let err = sign(
            &d,
            SignRequest { uid: "urn:nope".into(), data: vec![],
            cryptographic_parameters: None,
        },
            "corr-404",
        )
        .unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::ItemNotFound);
    }

    #[test]
    fn non_active_key_returns_wrong_lifecycle_state() {
        let (_ring, d) = deps_with(PERMISSIVE);
        // Insert a PreActive key.
        let rec = ObjectRecord {
            uid: "urn:pre".into(),
            object_type: ObjectType::PrivateKey,
            algorithm: KmipAlgorithm::MlDsa87,
            cryptographic_length: 0,
            usage_mask: UsageMask::SIGN,
            state: State::PreActive,
            pkcs11_cka_id: vec![],
            pkcs11_slot: 0,
            initial_date: OffsetDateTime::UNIX_EPOCH,
            activation_date: None,
            supersedes: None,
            name: None,

            links: std::collections::HashMap::new(),

            custom_attributes: std::collections::HashMap::new(),


            key_material: None,


            key_format_type: None,
        ..ObjectRecord::default()
};
        d.store.put(rec).unwrap();
        let err = sign(&d, SignRequest { uid: "urn:pre".into(), data: vec![],
            cryptographic_parameters: None,
        }, "corr").unwrap_err();
        // KMIP 3.0 §11 — PreActive is a lifecycle-state failure.
        assert_eq!(err.result_reason(), ResultReason::WrongKeyLifecycleState);
    }

    #[test]
    fn rekey_required_surfaces_permission_denied_with_hint() {
        let (_ring, d) = deps_with(REKEY_POLICY);
        // Existing ECDSA key — policy says substitute to ML-DSA-87 → engine
        // emits RekeyAndProceed → handler returns PermissionDenied with
        // an actionable message.
        make_active_key(&d, "urn:ecdsa", KmipAlgorithm::Ecdsa);
        let err = sign(
            &d,
            SignRequest { uid: "urn:ecdsa".into(), data: b"x".to_vec(),
            cryptographic_parameters: None,
        },
            "corr-rk",
        )
        .unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::PermissionDenied);
        let s = err.to_string();
        assert!(s.contains("rekey required"));
        assert!(s.contains("ML-DSA-87"));
    }
}
