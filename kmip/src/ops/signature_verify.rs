//! KMIP 3.0 §6.1.61 **Signature Verify** operation.
//!
//! > "This operation requests the server to perform a signature verify
//! > operation on the provided data using the specified verification key."
//!
//! Op codepoint `0x22` (verified — `Signature Verify = 0x00000022`).
//!
//! ## KMIP design point
//!
//! A failed verification is **not** a KMIP error — it returns a successful
//! `Signature Verify` response with `validity = Invalid`. KMIP errors are
//! reserved for protocol-level failures (missing UID, archived key,
//! policy denial, etc.).
//!
//! ## Plane mapping
//!
//! - **Plane 1** — engine.evaluate; policies may gate verify on certain
//!   algorithms (e.g. denying MD5 / SHA-1 verification under a strict
//!   compliance profile).
//! - **Plane 2** — store lookup + lifecycle gate. Per §3.4 table:
//!   `Active`, `Deactivated`, `Compromised` all permit verify (verifying
//!   legacy signatures is required even after key rotation).
//! - **Plane 3** — would call `C_VerifyInit` (PKCS#11 v3.2 §C.6.7) +
//!   `C_Verify` (§C.6.8). Signatures verified against
//!   `rust/src/ffi.rs::{C_VerifyInit, C_Verify}`. The handler drives the real
//!   engine (`softhsmrustv3::native::verify_pqc` / `verify_with_pss_salt`);
//!   with no engine session it fails closed — a SHA-256 stand-in survives only
//!   under `#[cfg(test)]` for the engine-less unit tests.

use time::OffsetDateTime;

use crate::error::{KmipError, Result, ResultReason};
use crate::kmip30::{PkcsOp, SignatureValidity, SignatureVerifyRequest, SignatureVerifyResponse, State};
use crate::policy::{Decision, PolicyRequest};

use super::deps::Deps;
use super::helpers::{
    emit_pkcs11, emit_pkcs11_result, emit_request, emit_success, fail_err,
    state_name,
};

pub fn signature_verify(
    deps: &Deps,
    req: SignatureVerifyRequest,
    auth: &crate::server::auth::AuthContext,
    correlation_id: &str,
) -> Result<SignatureVerifyResponse> {
    let started = OffsetDateTime::now_utc();
    emit_request(
        deps,
        correlation_id,
        "SignatureVerify",
        format!("uid={} data_len={} sig_len={}", req.uid, req.data.len(), req.signature.len()),
    );

    // Part F §F7.4 — owner-checked lookup (see get.rs for the pattern).
    let obj = super::helpers::authorize_object(deps, auth, &req.uid, || {
        KmipError::object_not_found(&req.uid)
    })
    .map_err(|e| fail_err(deps, correlation_id, "SignatureVerify", e))?;

    // KMIP 3.0 §3.x lifecycle — Verify allowed in Active / Deactivated /
    // Compromised (need to verify legacy artefacts). Blocked in PreActive
    // (no key material yet) and Destroyed.
    match obj.state {
        State::Active | State::Deactivated | State::Compromised => {}
        _ => {
            return Err(fail_err(
                deps,
                correlation_id,
                "SignatureVerify",
                super::helpers::non_active_state_error(&req.uid, obj.state),
            ));
        }
    }

    // K22 — KMIP 3.0 §11 `Object Archived` (0x0d): "The object SHALL
    // be recovered from the archive before performing the operation."
    if obj.archived {
        return Err(fail_err(deps, correlation_id, "SignatureVerify",
            KmipError::object_archived(&req.uid)));
    }

    // KMIP 3.0 §3.4 — `Process Start Date` / `Protect Stop Date`
    // window gating, mirror of `sign.rs` / `encrypt.rs` / `decrypt.rs`.
    // CS-AC-M-8 step #3 pins this with ProcessStartDate=future.
    if let Some(t) = obj.process_start_date {
        if started < t {
            return Err(fail_err(deps, correlation_id, "SignatureVerify",
                KmipError::failed(
                    crate::error::ResultReason::WrongKeyLifecycleState,
                    "SignatureVerify: now < ProcessStartDate".to_string(),
                )));
        }
    }
    if let Some(t) = obj.protect_stop_date {
        if started > t {
            return Err(fail_err(deps, correlation_id, "SignatureVerify",
                KmipError::failed(
                    crate::error::ResultReason::WrongKeyLifecycleState,
                    "SignatureVerify: now > ProtectStopDate".to_string(),
                )));
        }
    }

    // KMIP 3.0 §11 Cryptographic Usage Mask — Signature Verify requires
    // the `Verify` bit (0x02); missing → 0x29 (K12, audit K-9).
    super::helpers::enforce_usage_mask(
        deps, correlation_id, "SignatureVerify", &obj, crate::kmip30::UsageMask::VERIFY,
    )?;

    // Plane-1 policy gate. Y1 stored classification; Y3 qualified name.
    let stored_attrs = super::helpers::strip_x_prefixes(&obj.custom_attributes);
    let algo = super::helpers::qualified_name(obj.algorithm, obj.cryptographic_length);
    let mut p_req = PolicyRequest::minimal(
        "SignatureVerify",
        Some(&algo),
        started,
        correlation_id,
        &stored_attrs,
    );
    p_req.usage_mask = Some(obj.usage_mask);
    p_req.state = Some(state_name(obj.state));
    p_req.target_uid = Some(&req.uid);
    // Y16 — surface the mechanism dimension so hash/mechanism rules gate
    // SignatureVerify too (was a silent no-op on this op).
    p_req.mechanism = super::helpers::mechanism_params_from_cp(
        obj.algorithm,
        crate::kmip30::PkcsOp::SignVerify,
        req.cryptographic_parameters
            .as_ref()
            .or(obj.cryptographic_parameters.as_ref()),
    );
    if let Decision::Deny { kmip_reason, human, .. } = deps.engine.evaluate(&p_req) {
        return Err(fail_err(
            deps,
            correlation_id,
            "SignatureVerify",
            KmipError::failed(kmip_reason.to_result_reason(), human),
        ));
    }

    let mech = obj.algorithm.to_pkcs11_mech(PkcsOp::SignVerify).ok_or_else(|| {
        KmipError::failed(
            ResultReason::OperationNotSupported,
            format!("algorithm {:?} has no Verify mechanism", obj.algorithm),
        )
    })?;

    // Plane-3: real bridge call when a session is wired. K15 — the
    // audit record is emitted after `native::verify` returns with the
    // call's real rv. Falls back to the SHA-256 stamp comparison
    // (audited as `soft::placeholder_verify`) for unit tests.
    let validity = match deps.resolve_tenant_session(auth.identity.as_ref()).ok() {
        Some(session) => {
            let handle =
                super::helpers::find_handle_for_object(session, &obj.pkcs11_cka_id, obj.object_type)
                    .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Verify:find"))?
                    .ok_or_else(|| KmipError::object_not_found(&req.uid))?;
            // KMIP 3.0 §6.1.61 — pick padding/hash from the request's
            // CryptographicParameters, falling back to the object's
            // stored attribute. CS-AC-M-2 pins RSA-PSS / SHA-256 via
            // the registered CryptographicParameters; CS-AC-M-3 uses
            // PKCS1v15 / SHA-256.
            let effective_cp = req
                .cryptographic_parameters
                .as_ref()
                .or(obj.cryptographic_parameters.as_ref());
            // K6 — exact padding + hash selection: SHA-256/384/512 map
            // to the matching engine mechanism (CKM_SHA*_RSA_PKCS{,_PSS}
            // / CKM_ECDSA_SHA*, available since engine slice S6) so
            // SHA-384/512 verifies actually verify.
            //
            // KMIP 3.0 §6.1.61 — when the client pins a hash/padding the
            // server cannot run (e.g. SHA-1 with RSA-PSS), the verify
            // CANNOT succeed. Per the spec this surfaces as
            // ResultStatus=Success + ValidityIndicator=Invalid, NOT
            // OperationFailed. CS-AC-M-3 step #4 pins SHA-1 over a
            // SHA-256 signature. Other failures (no mechanism for the
            // algorithm at all) remain protocol errors.
            let native_mech = match super::helpers::native_sign_mech_with_params(
                obj.algorithm,
                effective_cp,
            ) {
                Ok(m) => m,
                Err(e)
                    if e.result_reason()
                        == ResultReason::UnsupportedCryptographicParameters =>
                {
                    // No engine call runs on this path — the pinned
                    // hash/padding has no engine mechanism, so the
                    // verify cannot succeed and the spec shape is
                    // Success + Invalid. K15: no Pkcs11Call record is
                    // fabricated for a call that never happened.
                    emit_success(deps, correlation_id, "SignatureVerify");
                    return Ok(SignatureVerifyResponse {
                        uid: req.uid,
                        validity: SignatureValidity::Invalid,
                    });
                }
                Err(e) => return Err(e),
            };
            // K18 — KMIP 3.0 §11 `Salt Length`: an explicit RSA-PSS
            // salt pins EMSA-PSS-VERIFY to exactly that length (the
            // caller's parameters are authoritative); absent keeps the
            // engine's two-candidate default (hash length / maximal).
            let pss_salt =
                super::helpers::pss_salt_from_cp(native_mech, effective_cp)?;
            // native::verify returns Ok(true)/Ok(false) for the KMIP
            // ValidityIndicator model — exactly what we need.
            // I4 — ML-DSA / SLH-DSA honor the PQC interface knobs (Internal,
            // External Mu, Context String) from CryptographicParameters. The
            // engine's verify_pqc returns Ok(())=valid / Err(SIGNATURE_INVALID)
            // =invalid; map that onto the Ok(bool) ValidityIndicator model so a
            // bad signature is "Invalid", not an operation error.
            let r = if super::helpers::is_pqc_sign_mech(native_mech) {
                let internal = effective_cp.and_then(|c| c.internal).unwrap_or(false);
                let ext_mu = effective_cp.and_then(|c| c.external_mu).unwrap_or(false);
                let ctx = effective_cp
                    .and_then(|c| c.context_string.as_deref())
                    .unwrap_or(&[]);
                match softhsmrustv3::native::verify_pqc(
                    session,
                    handle,
                    native_mech,
                    &req.data,
                    &req.signature,
                    ctx,
                    internal,
                    ext_mu,
                ) {
                    Ok(()) => Ok(true),
                    Err(rv) if rv == softhsmrustv3::constants::CKR_SIGNATURE_INVALID => Ok(false),
                    Err(rv) => Err(rv),
                }
            } else {
                softhsmrustv3::native::verify_with_pss_salt(
                    session,
                    handle,
                    native_mech,
                    &req.data,
                    &req.signature,
                    pss_salt,
                )
            };
            emit_pkcs11_result(deps, correlation_id, "native::verify", Some(native_mech), &r);
            match r {
                Ok(true) => SignatureValidity::Valid,
                Ok(false) => SignatureValidity::Invalid,
                Err(rv) => return Err(super::helpers::ck_rv_to_kmip_error(rv, "Verify")),
            }
        }
        None => {
            // S-2 hardening: NO engine session ⇒ no key material. Production MUST
            // fail rather than verify against a deterministic SHA-256 stamp (which
            // a caller could forge). Placeholder kept only for the crate's tests.
            #[cfg(not(test))]
            {
                return Err(crate::error::KmipError::failed(
                    crate::error::ResultReason::CryptographicFailure,
                    "no engine session — cannot verify without key material",
                ));
            }
            #[cfg(test)]
            {
                emit_pkcs11(deps, correlation_id, "soft::placeholder_verify", Some(mech), 0, "CKR_OK");
                let expected = placeholder_signature(&req.uid, &req.data);
                if req.signature == expected {
                    SignatureValidity::Valid
                } else {
                    SignatureValidity::Invalid
                }
            }
        }
    };
    emit_success(deps, correlation_id, "SignatureVerify");

    Ok(SignatureVerifyResponse { uid: req.uid, validity })
}

/// Test-only stand-in for the engine-less unit tests; production fails closed.
#[cfg(test)]
fn placeholder_signature(uid: &str, data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(uid.as_bytes());
    h.update(data);
    h.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditlog::{AuditSink, RingSink};
    use crate::kmip30::{KmipAlgorithm, ObjectType, UsageMask};
    use crate::policy::{load_from_str, Engine};
    use crate::store::{MemoryStore, ObjectRecord};
    use std::sync::Arc;

    fn deps_with() -> Deps {
        let ring = Arc::new(RingSink::new(64));
        let sink: Arc<dyn AuditSink> = ring.clone();
        let engine = Engine::with_global_sink(sink.clone());
        engine
            .activate(load_from_str(
                "schema_version: 1\nmetadata: {name: t, description: t, authority: t, effective: always}\nrules: []\n",
                std::path::Path::new("<t>"),
            ).unwrap())
            .unwrap();
        Deps::new(engine, Arc::new(MemoryStore::new()), sink, super::super::deps::DepsConfig::default())
    }

    fn active(deps: &Deps, uid: &str) {
        deps.store.put(ObjectRecord {
            uid: uid.into(),
            object_type: ObjectType::PublicKey,
            algorithm: KmipAlgorithm::MlDsa87,
            cryptographic_length: 0,
            usage_mask: UsageMask::SIGN | UsageMask::VERIFY,
            state: State::Active,
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

    /// K12 — §11 Cryptographic Usage Mask: a present mask lacking the
    /// `Verify` bit (e.g. Sign-only) fails with 0x29. Positive case is
    /// pinned by `verify_matching_signature_returns_valid` (mask =
    /// SIGN | VERIFY).
    #[test]
    fn verify_mask_without_verify_bit_is_incompatible() {
        let d = deps_with();
        d.store.put(ObjectRecord {
            uid: "u".into(),
            object_type: ObjectType::PublicKey,
            algorithm: KmipAlgorithm::MlDsa87,
            usage_mask: UsageMask::SIGN,
            state: State::Active,
            activation_date: Some(OffsetDateTime::UNIX_EPOCH),
            ..ObjectRecord::default()
        }).unwrap();
        let err = signature_verify(&d, SignatureVerifyRequest {
            uid: "u".into(),
            data: b"x".to_vec(),
            signature: vec![0u8; 32],
            cryptographic_parameters: None,
        }, &crate::server::auth::AuthContext::open(), "c").unwrap_err();
        assert_eq!(
            err.result_reason(),
            crate::error::ResultReason::IncompatibleCryptographicUsageMask
        );
    }

    #[test]
    fn verify_matching_signature_returns_valid() {
        let d = deps_with();
        active(&d, "u");
        let data = b"hello world".to_vec();
        let sig = placeholder_signature("u", &data);
        let r = signature_verify(&d, SignatureVerifyRequest { uid: "u".into(), data, signature: sig, cryptographic_parameters: None }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        assert_eq!(r.validity, SignatureValidity::Valid);
    }

    #[test]
    fn verify_wrong_signature_returns_invalid_not_error() {
        let d = deps_with();
        active(&d, "u");
        let r = signature_verify(&d, SignatureVerifyRequest {
            uid: "u".into(),
            data: b"hello".to_vec(),
            signature: vec![0xff; 32],
            cryptographic_parameters: None,
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        assert_eq!(r.validity, SignatureValidity::Invalid);
    }

    #[test]
    fn verify_allowed_in_deactivated_state() {
        let d = deps_with();
        d.store.put(ObjectRecord {
            uid: "u".into(),
            object_type: ObjectType::PublicKey,
            algorithm: KmipAlgorithm::MlDsa87,
            cryptographic_length: 0,
            usage_mask: UsageMask::VERIFY,
            state: State::Deactivated,
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
}).unwrap();
        let _ = signature_verify(&d, SignatureVerifyRequest {
            uid: "u".into(),
            data: vec![],
            signature: vec![],
            cryptographic_parameters: None,
        }, &crate::server::auth::AuthContext::open(), "c").unwrap();
        // success — Verify is permitted in Deactivated state per §3.4
    }

    #[test]
    fn verify_destroyed_returns_wrong_lifecycle_state() {
        let d = deps_with();
        d.store.put(ObjectRecord {
            uid: "u".into(),
            object_type: ObjectType::PublicKey,
            algorithm: KmipAlgorithm::MlDsa87,
            cryptographic_length: 0,
            usage_mask: UsageMask::VERIFY,
            state: State::Destroyed,
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
}).unwrap();
        let err = signature_verify(&d, SignatureVerifyRequest {
            uid: "u".into(),
            data: vec![],
            signature: vec![],
            cryptographic_parameters: None,
        }, &crate::server::auth::AuthContext::open(), "c").unwrap_err();
        // KMIP 3.0 §11 — Destroyed is an FSM-rejection state. See
        // `ops::helpers::non_active_state_error` for the citation.
        assert_eq!(err.result_reason(), ResultReason::WrongKeyLifecycleState);
    }
}
