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
//!   `rust/src/ffi.rs::{C_SignInit, C_Sign}`. The handler drives the real
//!   engine (`softhsmrustv3::native::sign_pqc` / `sign_with_pss_salt`); with
//!   no engine session it fails closed — a SHA-256 stand-in survives only
//!   under `#[cfg(test)]` for the engine-less unit tests.

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
        .ok_or_else(|| fail_err(deps, correlation_id, "Sign", KmipError::object_not_found(&req.uid)))?;

    // ── Lifecycle gate (KMIP 3.0 §3.x — Sign requires Active) ───────────
    if obj.state != State::Active {
        return Err(fail_err(
            deps,
            correlation_id,
            "Sign",
            super::helpers::non_active_state_error(&req.uid, obj.state),
        ));
    }

    // K22 — KMIP 3.0 §11 `Object Archived` (0x0d): "The object SHALL
    // be recovered from the archive before performing the operation."
    if obj.archived {
        return Err(fail_err(deps, correlation_id, "Sign",
            KmipError::object_archived(&req.uid)));
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

    // KMIP 3.0 §11 Cryptographic Usage Mask — Sign requires the `Sign`
    // bit (0x01); missing → 0x29 (K12, audit K-9).
    super::helpers::enforce_usage_mask(
        deps, correlation_id, "Sign", &obj, crate::kmip30::UsageMask::SIGN,
    )?;

    // ── Plane 1: policy gate ────────────────────────────────────────────
    // Y1 — read the classification tag off the stored key so a
    // `require_custom_attribute` gate applies at use-time too.
    let stored_attrs = super::helpers::strip_x_prefixes(&obj.custom_attributes);
    // Curve/size-QUALIFIED name (e.g. "ECDSA-P256") so the shipped policies'
    // qualified `from:`/denylist entries actually match this stored key — the
    // coarse `canonical_name` ("ECDSA") never matched, leaving the rekey rules
    // dead (cacp-wasm-remediation-plan §W1/#2).
    let stored_algo = super::helpers::qualified_name(obj.algorithm, obj.cryptographic_length);
    let mut p_req = PolicyRequest::minimal(
        "Sign",
        Some(&stored_algo),
        started,
        correlation_id,
        &stored_attrs,
    );
    p_req.usage_mask = Some(obj.usage_mask);
    p_req.state = Some("Active");
    // name_pattern rules match on the stored key's Name (label-scoped rekey).
    p_req.name = obj.name.as_deref();
    p_req.current_object_algorithm = Some(&stored_algo);
    p_req.target_uid = Some(&req.uid);
    p_req.object_activation_date = obj.activation_date; // F-3 — max_key_age_days
    // P1 — surface the mechanism dimension (hash/padding/PQC flags + canonical
    // CKM_*) so mechanism/hash policy rules can gate Sign, not just the algorithm.
    p_req.mechanism = super::helpers::mechanism_params_from_cp(
        obj.algorithm,
        crate::kmip30::PkcsOp::SignVerify,
        req.cryptographic_parameters
            .as_ref()
            .or(obj.cryptographic_parameters.as_ref()),
    );

    let decision = deps.engine.evaluate(&p_req);
    // P3 — capture any policy-forced mechanism parameters (hash / padding /
    // deterministic) to merge into the effective CryptographicParameters below.
    let forced_cp = decision.cp_override().cloned();
    let mech = match decision {
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
        Decision::RekeyAndProceed { new_algorithm, .. } => {
            // Crypto agility: the active policy substitutes this key's algorithm
            // for a new one. Execute the transparent rekey transaction (new key
            // → activate → deactivate+supersede the old → re-issue the Sign) and
            // return the signature under the migrated algorithm. The application
            // signed with an unchanged call; the engine migrated the key.
            return rekey_and_sign(deps, &req, &obj, &new_algorithm, correlation_id);
        }
    };

    // ── Plane 3: real bridge call when a session is wired ──────────────
    // K15 — the audit record is emitted AFTER `native::sign` returns,
    // with the call's real rv (a log asserting CKR_OK on failures is
    // worse than no log). Falls back to a deterministic SHA-256
    // placeholder (audited as `soft::placeholder_sign`) for unit tests
    // that don't bootstrap an engine.
    let signature = match deps.engine_session {
        Some(session) => {
            // KMIP UID → CKA_ID → engine handle → native::sign. Filter
            // by ObjectType because pub + prv share CKA_ID per PKCS#11
            // convention; sign needs the private-key handle.
            let handle =
                super::helpers::find_handle_for_object(session, &obj.pkcs11_cka_id, obj.object_type)
                    .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Sign:find"))?
                    .ok_or_else(|| KmipError::object_not_found(&req.uid))?;
            let base_cp = req
                .cryptographic_parameters
                .as_ref()
                .or(obj.cryptographic_parameters.as_ref());
            // P3 — a forcing rule (MechanismParameterDefault) may mandate the
            // hash / padding / deterministic; merge it over the base so the
            // mechanism resolution and the sign_pqc flags below honor it.
            let merged_cp;
            let effective_cp = match forced_cp.as_ref() {
                Some(ov) => {
                    merged_cp = super::helpers::merge_cp_override(base_cp, ov);
                    Some(&merged_cp)
                }
                None => base_cp,
            };
            // K6 — exact padding + hash selection (SHA-256/384/512 →
            // CKM_SHA*_RSA_PKCS{,_PSS} / CKM_ECDSA_SHA*); unsupported
            // hashes/paddings fail 0x3e instead of silently signing
            // SHA-256 (compliance-audit B-2).
            let native_mech = super::helpers::native_sign_mech_with_params(
                obj.algorithm,
                effective_cp,
            )
            .map_err(|e| fail_err(deps, correlation_id, "Sign", e))?;
            // K18 — KMIP 3.0 §11 `Salt Length`: explicit RSA-PSS salt
            // from the effective CP (same request-over-object
            // precedence as the mechanism selection above). `None`
            // keeps the engine's §6.2 hash-length default.
            let pss_salt = super::helpers::pss_salt_from_cp(native_mech, effective_cp)
                .map_err(|e| fail_err(deps, correlation_id, "Sign", e))?;
            // I4 — ML-DSA / SLH-DSA honor the PQC interface knobs from
            // CryptographicParameters (KMIP 3.0 WD19): Deterministic, Internal,
            // External Mu, Context String, Random. Classical mechanisms keep
            // the RSA-PSS-salt bridge.
            let r = if super::helpers::is_pqc_sign_mech(native_mech) {
                let det = effective_cp.and_then(|c| c.deterministic).unwrap_or(false);
                let internal = effective_cp.and_then(|c| c.internal).unwrap_or(false);
                let ext_mu = effective_cp.and_then(|c| c.external_mu).unwrap_or(false);
                let ctx = effective_cp
                    .and_then(|c| c.context_string.as_deref())
                    .unwrap_or(&[]);
                let random = effective_cp.and_then(|c| c.random.as_deref());
                softhsmrustv3::native::sign_pqc(
                    session, handle, native_mech, &req.data, ctx, det, internal, ext_mu, random,
                )
            } else {
                softhsmrustv3::native::sign_with_pss_salt(
                    session,
                    handle,
                    native_mech,
                    &req.data,
                    pss_salt,
                )
            };
            super::helpers::emit_pkcs11_result(
                deps,
                correlation_id,
                "native::sign",
                Some(native_mech),
                &r,
            );
            r.map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Sign"))?
        }
        None => {
            // S-2 hardening: NO engine session ⇒ no key material to sign with.
            // Production (any non-test build, incl. the server bin and the wasm
            // bundle) MUST fail — never emit a deterministic SHA-256 stand-in as
            // a "signature". The placeholder survives only for the crate's own
            // unit tests, which don't bootstrap an engine.
            #[cfg(not(test))]
            {
                return Err(fail_err(
                    deps,
                    correlation_id,
                    "Sign",
                    KmipError::failed(
                        ResultReason::CryptographicFailure,
                        "no engine session — cannot sign without key material",
                    ),
                ));
            }
            #[cfg(test)]
            {
                super::helpers::emit_pkcs11(
                    deps,
                    correlation_id,
                    "soft::placeholder_sign",
                    Some(mech),
                    0,
                    "CKR_OK",
                );
                placeholder_signature(&req.uid, &req.data)
            }
        }
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
        rekeyed: None,
    })
}

/// Transparent auto-rekey transaction (KMIP 3.0 crypto agility, plan §W1/#3).
///
/// The active policy substituted the stored key's algorithm, so: (1) generate a
/// fresh signing key pair under `new_algorithm`, (2) activate both halves, (3)
/// deactivate + supersede the old key (KMIP has no "Deprecated" state — the
/// §3.2 Active→Deactivated transition is the move for a superseded key, linked
/// via `x-pqctoday-supersedes`), and (4) re-issue the Sign against the new key.
///
/// The caller (an application using the original UID) gets a valid signature
/// under the migrated PQC algorithm with no code change; it can discover the new
/// UID by following the supersedes link on the old object. The new algorithm is
/// the substitution target, so the re-issued Sign is allowed without
/// re-substituting (no recursion).
fn rekey_and_sign(
    deps: &Deps,
    req: &SignRequest,
    old: &crate::store::ObjectRecord,
    new_algorithm: &str,
    correlation_id: &str,
) -> Result<SignResponse> {
    use crate::kmip30::UsageMask;

    // 1+2. Replacement signing pair (Name copied from the old key) + Activate.
    let pair = super::agility::generate_replacement_pair(
        deps,
        old,
        new_algorithm,
        UsageMask::SIGN | UsageMask::VERIFY,
        "CreateKeyPair:Sign",
        correlation_id,
    )
    .map_err(|e| fail_err(deps, correlation_id, "Sign", e))?;

    // 3. Deactivate + supersede the old key.
    super::agility::supersede_old(deps, old, &pair.private_uid, new_algorithm, correlation_id)?;

    // 4. Re-issue the original Sign against the migrated key, then stamp the
    // response with the rekey details (R7 Phase 4 — so the dispatcher's §9.5
    // Undo wave can find and delete both halves of the new key pair on
    // rollback; see `SignResponse::rekeyed`).
    let mut resp = sign(
        deps,
        SignRequest {
            uid: pair.private_uid.clone(),
            data: req.data.clone(),
            cryptographic_parameters: req.cryptographic_parameters.clone(),
        },
        correlation_id,
    )?;
    resp.rekeyed = Some(crate::kmip30::SignRekeyInfo {
        old_uid: old.uid.clone(),
        new_private_key_uid: pair.private_uid,
        new_public_key_uid: pair.public_uid,
    });
    Ok(resp)
}

/// Test-only stand-in used by the engine-less unit tests below. Production
/// builds fail closed (see the `#[cfg(not(test))]` guard in `sign`), so this
/// never compiles into a shipped artifact.
#[cfg(test)]
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
    from: ECDSA-P256
    to: ML-DSA-87
    reason: "Upgrade signing"
"#;

    /// K12 — §11 Cryptographic Usage Mask: a present mask lacking the
    /// `Sign` bit (e.g. Verify-only) fails with 0x29. Positive case is
    /// pinned by `happy_path_returns_signature_and_emits_three_planes`
    /// (mask = SIGN | VERIFY).
    #[test]
    fn sign_mask_without_sign_bit_is_incompatible() {
        let (_ring, d) = deps_with(PERMISSIVE);
        d.store.put(ObjectRecord {
            uid: "u".into(),
            object_type: ObjectType::PrivateKey,
            algorithm: KmipAlgorithm::MlDsa87,
            usage_mask: UsageMask::VERIFY,
            state: State::Active,
            activation_date: Some(OffsetDateTime::UNIX_EPOCH),
            ..ObjectRecord::default()
        }).unwrap();
        let err = sign(&d, SignRequest {
            uid: "u".into(),
            data: b"x".to_vec(),
            cryptographic_parameters: None,
        }, "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::IncompatibleCryptographicUsageMask);
    }

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
        // p1 (policy activation + decision), p2 (req + resp), p3 (one
        // record naming the soft fallback that actually ran — K15).
        assert!(ring.filter_plane(Plane::Agility).len() >= 2);
        assert_eq!(ring.filter_plane(Plane::Kmip).len(), 2);
        let p3 = ring.filter_plane(Plane::Pkcs11);
        assert_eq!(p3.len(), 1);
        assert!(matches!(
            &p3[0].event,
            EventPayload::Pkcs11Call { function, rv: 0, .. } if function == "soft::placeholder_sign"
        ));
    }

    #[test]
    fn missing_uid_returns_object_not_found() {
        let (_ring, d) = deps_with(PERMISSIVE);
        let err = sign(
            &d,
            SignRequest { uid: "urn:nope".into(), data: vec![],
            cryptographic_parameters: None,
        },
            "corr-404",
        )
        .unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::ObjectNotFound);
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
    fn rekey_transparently_migrates_and_signs() {
        let (_ring, d) = deps_with(REKEY_POLICY);
        // Existing ECDSA-P256 key — policy substitutes to ML-DSA-87 → engine
        // emits RekeyAndProceed → the handler runs the transparent rekey
        // transaction and returns a signature under the migrated PQC key.
        make_active_key(&d, "urn:ecdsa", KmipAlgorithm::Ecdsa);
        let resp = sign(
            &d,
            SignRequest { uid: "urn:ecdsa".into(), data: b"x".to_vec(),
            cryptographic_parameters: None,
        },
            "corr-rk",
        )
        .unwrap();
        // The signature is keyed on the NEW (migrated) private key, not the old UID.
        assert_ne!(resp.uid, "urn:ecdsa");
        let new_priv = d.store.get(&resp.uid).unwrap().unwrap();
        assert_eq!(new_priv.algorithm, KmipAlgorithm::MlDsa87);
        assert_eq!(new_priv.state, State::Active);
        // The old key is deactivated and superseded by the new one.
        let old = d.store.get("urn:ecdsa").unwrap().unwrap();
        assert_eq!(old.state, State::Deactivated);
        assert_eq!(old.supersedes.as_deref(), Some(resp.uid.as_str()));
        assert_eq!(
            old.links.get("x-pqctoday-supersedes").map(String::as_str),
            Some(resp.uid.as_str())
        );
    }
}
