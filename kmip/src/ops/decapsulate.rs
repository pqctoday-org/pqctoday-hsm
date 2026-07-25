//! KMIP 3.0 CSD02 (PQC Updates) **Decapsulate** operation.
//!
//! > "This operation requests the server to perform an ML-KEM
//! > decapsulation against the referenced private (decapsulation) key."
//!
//! Op codepoint `0x42` (CSD02 — right after `Encapsulate = 0x41`).
//!
//! Unlike the `Decrypt`-overload decapsulation path
//! ([`super::decrypt::decrypt`]), `Decapsulate` does **not** return the
//! recovered shared secret inline. Instead the server:
//!   1. decapsulates the ciphertext with the ML-KEM private key → `K`;
//!   2. creates a NEW managed `SecretData` object holding `K`, allocating
//!      a fresh UID;
//!   3. returns `{ UniqueIdentifier = <new> }`.
//!
//! A subsequent `Get` on the returned UID retrieves the recovered shared
//! secret as KeyMaterial.

use crate::error::{KmipError, Result, ResultReason};
use crate::kmip30::{DecapsulateRequest, DecapsulateResponse, PkcsOp, State};

use super::deps::Deps;
use super::encapsulate::{is_classic_mceliece, is_classical_kem, is_frodokem, is_ml_kem, store_shared_secret};
use super::helpers::{authorize_object, emit_pkcs11, emit_pkcs11_result, emit_request, emit_success, fail_err, state_name};

pub fn decapsulate(
    deps: &Deps,
    req: DecapsulateRequest,
    auth: &crate::server::auth::AuthContext,
    correlation_id: &str,
) -> Result<DecapsulateResponse> {
    emit_request(
        deps,
        correlation_id,
        "Decapsulate",
        format!("uid={} ct_len={}", req.uid, req.data.len()),
    );

    let obj = authorize_object(deps, auth, &req.uid, || KmipError::object_not_found(&req.uid))
        .map_err(|e| fail_err(deps, correlation_id, "Decapsulate", e))?;

    // K6 — Decapsulate accepts ML-KEM, the hybrid KEMs, classical
    // ECDH/X25519/X448 in DHKEM mode, and (2026-07-06) BSI TR-02102-1's
    // FrodoKEM / Classic McEliece.
    if !is_ml_kem(obj.algorithm)
        && !obj.algorithm.is_hybrid_kem()
        && !is_classical_kem(obj.algorithm)
        && !is_frodokem(obj.algorithm)
        && !is_classic_mceliece(obj.algorithm)
    {
        return Err(fail_err(
            deps,
            correlation_id,
            "Decapsulate",
            KmipError::failed(
                ResultReason::OperationNotSupported,
                format!("Decapsulate requires an ML-KEM, hybrid KEM, classical ECDH/X25519/X448, FrodoKEM, or Classic McEliece key; {:?} is not", obj.algorithm),
            ),
        ));
    }

    // Lifecycle gate per §3.4 (2026-07-05: widened to match decrypt.rs's
    // precedent) — Decapsulate allowed in Active / Deactivated / Compromised;
    // PreActive and Destroyed rejected. A KEM private key that's been
    // superseded by a crypto-agility rekey (`encapsulate.rs::rekey_and_encapsulate`)
    // is Deactivated, not destroyed — it must keep decapsulating any
    // ciphertext that was legitimately encapsulated against it *before* the
    // migration (the actual answer to "what happens to in-flight old
    // ciphertext", not ciphertext-format inference — see
    // `kmip/spec/crossref/kem-encapsulate-decapsulate.yaml`'s design notes).
    // `Encapsulate`'s own gate stays Active-only (unchanged, above in
    // encapsulate.rs) so no *new* encapsulation can target a retired key.
    match obj.state {
        State::Active | State::Deactivated | State::Compromised => {}
        _ => {
            return Err(fail_err(
                deps,
                correlation_id,
                "Decapsulate",
                super::helpers::non_active_state_error(&req.uid, obj.state),
            ));
        }
    }
    if obj.archived {
        return Err(fail_err(
            deps,
            correlation_id,
            "Decapsulate",
            KmipError::object_archived(&req.uid),
        ));
    }

    // ── Plane 1: policy gate ────────────────────────────────────────────
    // Route Decapsulate through the agility engine (see encapsulate.rs) so the
    // policy plane governs ML-KEM operations — emits the p1 PolicyDecided
    // audit event and enforces allow / deny.
    let started = time::OffsetDateTime::now_utc();
    // Y1 — stored classification tag off the KEM key.
    let stored_attrs = super::helpers::strip_x_prefixes(&obj.custom_attributes);
    let stored_algo = super::helpers::qualified_name(obj.algorithm, obj.cryptographic_length);
    let mut p_req = crate::policy::PolicyRequest::minimal(
        "Decapsulate",
        Some(&stored_algo),
        started,
        correlation_id,
        &stored_attrs,
    );
    p_req.usage_mask = Some(obj.usage_mask);
    // 2026-07-05 — report the TRUE state (was hardcoded "Active"), so a
    // policy's own `lifecycle_state_gate` can still narrow the op-level
    // Active/Deactivated/Compromised allowance above if it wants to (e.g.
    // deny Decapsulate on Compromised keys specifically). Matches
    // decrypt.rs's precedent.
    p_req.state = Some(state_name(obj.state));
    p_req.current_object_algorithm = Some(&stored_algo);
    p_req.target_uid = Some(&req.uid);
    p_req.object_activation_date = obj.activation_date; // F-3 — max_key_age_days
    match deps.engine.evaluate(&p_req) {
        crate::policy::Decision::Allow { .. } => {}
        crate::policy::Decision::Deny { kmip_reason, human, .. } => {
            return Err(fail_err(
                deps,
                correlation_id,
                "Decapsulate",
                KmipError::failed(kmip_reason.to_result_reason(), human),
            ));
        }
        crate::policy::Decision::RekeyAndProceed { .. } => {
            return Err(fail_err(
                deps,
                correlation_id,
                "Decapsulate",
                KmipError::failed(
                    ResultReason::OperationNotSupported,
                    "Decapsulate: policy requires rekey, which is not supported inline".to_string(),
                ),
            ));
        }
    }

    // K6 — hybrid KEM: the ENGINE decapsulates against the TWO non-extractable
    // private handles (ML-KEM half under `pkcs11_cka_id`, classical half under
    // `pkcs11_cka_id_secondary`), splits the composite ciphertext, and combines
    // per the algorithm's order through the derive machinery. The private key
    // material never enters this layer (that is the non-extractability fix);
    // ML-KEM implicit rejection is preserved inside the engine.
    if let Some(hybrid) = obj.algorithm.hybrid_kem() {
        let session = deps.resolve_tenant_session(auth.identity.as_ref()).ok().ok_or_else(|| {
            KmipError::failed(
                ResultReason::CryptographicFailure,
                "hybrid KEM decapsulate requires an engine session".to_string(),
            )
        })?;
        let mlkem_priv = super::helpers::find_handle_for_object(
            session,
            &obj.pkcs11_cka_id,
            crate::kmip30::ObjectType::PrivateKey,
        )
        .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Decap:find-mlkem"))?
        .ok_or_else(|| KmipError::object_not_found(&req.uid))?;
        let classical_cka_id = obj.pkcs11_cka_id_secondary.as_deref().ok_or_else(|| {
            KmipError::failed(
                ResultReason::CryptographicFailure,
                "hybrid KEM private key missing secondary (classical) CKA_ID".to_string(),
            )
        })?;
        let classical_priv = super::helpers::find_handle_for_object(
            session,
            classical_cka_id,
            crate::kmip30::ObjectType::PrivateKey,
        )
        .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Decap:find-classical"))?
        .ok_or_else(|| KmipError::object_not_found(&req.uid))?;
        let shared_secret = softhsmrustv3::native::hybrid::decapsulate(
            session,
            hybrid,
            mlkem_priv,
            classical_priv,
            &req.data,
        )
        .map_err(|rv| {
            fail_err(
                deps,
                correlation_id,
                "Decapsulate",
                super::helpers::ck_rv_to_kmip_error(rv, "hybrid decapsulate"),
            )
        })?;
        emit_pkcs11(deps, correlation_id, "soft::hybrid_kem_decapsulate", None, 0, "CKR_OK");
        let ss_uid = store_shared_secret(deps, obj.algorithm, shared_secret, auth)?;
        emit_success(deps, correlation_id, "Decapsulate");
        return Ok(DecapsulateResponse { uid: ss_uid });
    }

    let shared_secret = match deps.resolve_tenant_session(auth.identity.as_ref()).ok() {
        Some(session) => {
            // Resolve by PKCS#11 class: Decapsulate needs the PRIVATE key, but
            // a CreateKeyPair pair shares one CKA_ID across both halves, so a
            // bare `find_by_cka_id` may return the public half (CKA_DECAPSULATE
            // =false → CKR_KEY_FUNCTION_NOT_PERMITTED). (Same fix as Get/Sign.)
            let handle = super::helpers::find_handle_for_object(
                session,
                &obj.pkcs11_cka_id,
                crate::kmip30::ObjectType::PrivateKey,
            )
            .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Decap:find"))?
            .ok_or_else(|| KmipError::object_not_found(&req.uid))?;
            let native_mech = if is_classical_kem(obj.algorithm) {
                super::helpers::classical_kem_mech(obj.recommended_curve).ok_or_else(|| {
                    KmipError::failed(
                        ResultReason::OperationNotSupported,
                        format!("no classical KEM mechanism for RecommendedCurve {:?}", obj.recommended_curve),
                    )
                })?
            } else {
                super::helpers::native_kem_mech(obj.algorithm).ok_or_else(|| {
                    KmipError::failed(
                        ResultReason::OperationNotSupported,
                        format!("no KEM mechanism for {:?}", obj.algorithm),
                    )
                })?
            };
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
                // Cosmetic only (audit-log field) — placeholder builds don't
                // have a real engine session to resolve a mechanism against,
                // and this path never runs in production (see the
                // #[cfg(not(test))] arm above).
                let mech = obj.algorithm.to_pkcs11_mech(PkcsOp::Decrypt);
                emit_pkcs11(
                    deps,
                    correlation_id,
                    "soft::placeholder_decapsulate",
                    mech,
                    0,
                    "CKR_OK",
                );
                placeholder_bytes(&req.uid, &req.data, b"ss", 32)
            }
        }
    };

    let ss_uid = store_shared_secret(deps, obj.algorithm, shared_secret, auth)?;

    emit_success(deps, correlation_id, "Decapsulate");

    Ok(DecapsulateResponse { uid: ss_uid })
}

/// Test-only stand-in for the engine-less unit tests; production fails closed.
#[cfg(test)]
fn placeholder_bytes(uid: &str, input: &[u8], domain: &[u8], len: usize) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(domain);
    h.update(uid.as_bytes());
    h.update(input);
    let d = h.finalize();
    d.iter().cycle().take(len).copied().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditlog::{AuditSink, RingSink};
    use crate::kmip30::{KmipAlgorithm, ObjectType, UsageMask};
    use crate::policy::Engine;
    use crate::server::auth::AuthContext;
    use crate::store::{MemoryStore, ObjectRecord};
    use std::sync::Arc;

    fn deps() -> Deps {
        let ring = Arc::new(RingSink::new(64));
        let sink: Arc<dyn AuditSink> = ring.clone();
        Deps::new(
            Engine::permissive(),
            Arc::new(MemoryStore::new()),
            sink,
            super::super::deps::DepsConfig::default(),
        )
    }

    #[test]
    fn placeholder_decapsulate_creates_secret_data() {
        let d = deps();
        d.store
            .put(ObjectRecord {
                uid: "sk".to_string(),
                object_type: ObjectType::PrivateKey,
                algorithm: KmipAlgorithm::MlKem768,
                usage_mask: UsageMask::DECRYPT,
                state: State::Active,
                ..ObjectRecord::default()
            })
            .unwrap();
        let resp = decapsulate(
            &d,
            DecapsulateRequest {
                uid: "sk".to_string(),
                data: vec![0u8; 1088],
                cryptographic_parameters: None,
            },
            &AuthContext::open(),
            "t",
        )
        .unwrap();
        let ss_rec = d.store.get(&resp.uid).unwrap().unwrap();
        assert_eq!(ss_rec.object_type, ObjectType::SecretData);
        // Born PreActive — see encapsulate::store_shared_secret rationale.
        assert_eq!(ss_rec.state, State::PreActive);
        assert!(ss_rec.key_material.is_some());
        assert_ne!(resp.uid, "sk");
    }

    /// Classical ECDH-P256 private key is now a valid Decapsulate target
    /// (2026-07-05) — mirrors `encapsulate::tests::encapsulate_accepts_classical_ecdh_key`.
    #[test]
    fn decapsulate_accepts_classical_ecdh_key() {
        let d = deps();
        d.store
            .put(ObjectRecord {
                uid: "ecdh-sk".to_string(),
                object_type: ObjectType::PrivateKey,
                algorithm: KmipAlgorithm::Ecdh,
                recommended_curve: Some(crate::kmip30::algos::recommended_curve::P_256),
                usage_mask: UsageMask::DECRYPT,
                state: State::Active,
                ..ObjectRecord::default()
            })
            .unwrap();
        let resp = decapsulate(
            &d,
            DecapsulateRequest {
                uid: "ecdh-sk".to_string(),
                data: vec![0u8; 65], // SEC1 uncompressed P-256 point length
                cryptographic_parameters: None,
            },
            &AuthContext::open(),
            "t",
        )
        .unwrap();
        let ss_rec = d.store.get(&resp.uid).unwrap().unwrap();
        assert_eq!(ss_rec.object_type, ObjectType::SecretData);
        assert_ne!(resp.uid, "ecdh-sk");
    }
}
