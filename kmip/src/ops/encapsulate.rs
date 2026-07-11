//! KMIP 3.0 WD19 (PQC Updates) **Encapsulate** operation.
//!
//! > "This operation requests the server to perform an ML-KEM
//! > encapsulation against the referenced public (encapsulation) key."
//!
//! Op codepoint `0x41` (WD19 — right after `Deactivate = 0x40`).
//!
//! Unlike the `Encrypt`-overload encapsulation path
//! ([`super::encrypt::encrypt`]), `Encapsulate` does **not** return the
//! shared secret inline. Instead the server:
//!   1. encapsulates against the ML-KEM public key → `(ciphertext, K)`;
//!   2. creates a NEW managed `SecretData` object holding `K`, allocating
//!      a fresh UID;
//!   3. returns `{ UniqueIdentifier = <new>, Data = ciphertext }`.
//!
//! A subsequent `Get` on the returned UID retrieves the 32-byte shared
//! secret as KeyMaterial.
//!
//! ## Deterministic coins
//!
//! When the request supplies `InputKeyMaterial` (the 32-byte FIPS 203
//! §7.2 coins `m`, nested in `CryptographicParameters`), encapsulation is
//! deterministic via `native::encapsulate_deterministic` — this is the
//! entry point the OASIS KMIP 3.0 PQC interop vectors require for
//! byte-exact reproduction. Absent the coins, the server samples `m` from
//! the OS RNG via `native::encapsulate`.

use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{KmipError, Result, ResultReason};
use crate::kmip30::{
    EncapsulateRequest, EncapsulateResponse, KeyFormatType, KmipAlgorithm, ObjectType, PkcsOp,
    State,
};
use crate::store::ObjectRecord;

use super::deps::Deps;
use super::helpers::{
    emit_pkcs11, emit_pkcs11_result, emit_request, emit_success, fail_err,
};

pub fn encapsulate(
    deps: &Deps,
    req: EncapsulateRequest,
    correlation_id: &str,
) -> Result<EncapsulateResponse> {
    emit_request(
        deps,
        correlation_id,
        "Encapsulate",
        format!(
            "uid={} ikm={}",
            req.uid,
            req.input_key_material.as_ref().map_or(0, |m| m.len())
        ),
    );

    let obj = deps.store.get(&req.uid)?.ok_or_else(|| {
        fail_err(deps, correlation_id, "Encapsulate", KmipError::object_not_found(&req.uid))
    })?;

    // K6 — Encapsulate accepts ML-KEM, the hybrid KEMs (X25519MLKEM768 /
    // SecP256r1MLKEM768), classical ECDH/X25519/X448 in DHKEM mode (see
    // `is_classical_kem`), and (2026-07-06) BSI TR-02102-1's FrodoKEM /
    // Classic McEliece.
    if !is_ml_kem(obj.algorithm)
        && !obj.algorithm.is_hybrid_kem()
        && !is_classical_kem(obj.algorithm)
        && !is_frodokem(obj.algorithm)
        && !is_classic_mceliece(obj.algorithm)
    {
        return Err(fail_err(
            deps,
            correlation_id,
            "Encapsulate",
            KmipError::failed(
                ResultReason::OperationNotSupported,
                format!("Encapsulate requires an ML-KEM, hybrid KEM, classical ECDH/X25519/X448, FrodoKEM, or Classic McEliece key; {:?} is not", obj.algorithm),
            ),
        ));
    }

    // KMIP 3.0 §3.4 lifecycle gate — the public key must be Active.
    if obj.state != State::Active {
        return Err(fail_err(
            deps,
            correlation_id,
            "Encapsulate",
            super::helpers::non_active_state_error(&req.uid, obj.state),
        ));
    }
    if obj.archived {
        return Err(fail_err(
            deps,
            correlation_id,
            "Encapsulate",
            KmipError::object_archived(&req.uid),
        ));
    }

    // ── Plane 1: policy gate ────────────────────────────────────────────
    // Route Encapsulate through the agility engine like Sign / Encrypt so the
    // policy plane governs ML-KEM operations too — `engine.evaluate` emits the
    // p1 `PolicyDecided` audit event and enforces allow / deny. Without this,
    // KEM ops were a blind spot in the crypto-agility layer.
    let started = OffsetDateTime::now_utc();
    // Y1 — stored classification tag off the KEM key.
    let stored_attrs = super::helpers::strip_x_prefixes(&obj.custom_attributes);
    let stored_algo = super::helpers::qualified_name(obj.algorithm, obj.cryptographic_length);
    let mut p_req = crate::policy::PolicyRequest::minimal(
        "Encapsulate",
        Some(&stored_algo),
        started,
        correlation_id,
        &stored_attrs,
    );
    p_req.usage_mask = Some(obj.usage_mask);
    p_req.state = Some("Active");
    p_req.current_object_algorithm = Some(&stored_algo);
    p_req.target_uid = Some(&req.uid);
    p_req.object_activation_date = obj.activation_date; // F-3 — max_key_age_days
    match deps.engine.evaluate(&p_req) {
        crate::policy::Decision::Allow { .. } => {}
        crate::policy::Decision::Deny { kmip_reason, human, .. } => {
            return Err(fail_err(
                deps,
                correlation_id,
                "Encapsulate",
                KmipError::failed(kmip_reason.to_result_reason(), human),
            ));
        }
        crate::policy::Decision::RekeyAndProceed { new_algorithm, .. } => {
            // Crypto agility (2026-07-05): the active policy substitutes this
            // key-establishment key's algorithm for a new one — classical
            // ECDH/X25519/X448 migrating to ML-KEM/hybrid, mirroring the
            // Sign-side transparent rekey (`sign.rs::rekey_and_sign`).
            // `Decapsulate` can never take this branch (see
            // `policy::rule::is_consumer_op` — the engine hard-excludes it),
            // so this is sound specifically because Encapsulate originates
            // fresh output each call.
            return rekey_and_encapsulate(deps, &req, &obj, &new_algorithm, correlation_id);
        }
    }

    // K6 — hybrid KEM: the ENGINE composes ML-KEM + classical ECDH. Encapsulate
    // needs only the recipient's PUBLIC wire share (stored inline as
    // `key_material` — it is public) plus a fresh ephemeral; no private handle.
    // The engine still needs a session because the shared-secret combine runs
    // through the PKCS#11 derive machinery (`run_combiner`).
    if let Some(hybrid) = obj.algorithm.hybrid_kem() {
        let public = obj.key_material.as_deref().ok_or_else(|| {
            KmipError::failed(
                ResultReason::CryptographicFailure,
                "hybrid KEM public key has no stored material".to_string(),
            )
        })?;
        let session = deps.engine_session.ok_or_else(|| {
            KmipError::failed(
                ResultReason::CryptographicFailure,
                "hybrid KEM encapsulate requires an engine session".to_string(),
            )
        })?;
        let enc = softhsmrustv3::native::hybrid::encapsulate(session, hybrid, public).map_err(|rv| {
            fail_err(
                deps,
                correlation_id,
                "Encapsulate",
                super::helpers::ck_rv_to_kmip_error(rv, "hybrid encapsulate"),
            )
        })?;
        emit_pkcs11(deps, correlation_id, "soft::hybrid_kem_encapsulate", None, 0, "CKR_OK");
        let ss_uid = store_shared_secret(deps, obj.algorithm, enc.shared_secret)?;
        emit_success(deps, correlation_id, "Encapsulate");
        return Ok(EncapsulateResponse { uid: ss_uid, data: enc.ciphertext, rekeyed: None });
    }

    // The deterministic coins may arrive hoisted (`input_key_material`)
    // or only nested in CryptographicParameters — prefer the hoisted form.
    let coins = req.input_key_material.clone();

    let (ciphertext, shared_secret) = match deps.engine_session {
        Some(session) => {
            // Resolve the handle by PKCS#11 class: a CreateKeyPair-generated
            // ML-KEM pair stores BOTH halves under one shared CKA_ID, so a
            // bare `find_by_cka_id` can return the private half (which has
            // CKA_ENCAPSULATE=false → CKR_KEY_FUNCTION_NOT_PERMITTED).
            // Encapsulate needs the PUBLIC key. (Same fix as Get/Sign.)
            let handle = super::helpers::find_handle_for_object(
                session,
                &obj.pkcs11_cka_id,
                ObjectType::PublicKey,
            )
            .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Encap:find"))?
            .ok_or_else(|| KmipError::object_not_found(&req.uid))?;
            let native_mech = if is_classical_kem(obj.algorithm) {
                if coins.is_some() {
                    return Err(fail_err(
                        deps,
                        correlation_id,
                        "Encapsulate",
                        KmipError::failed(
                            ResultReason::BadCryptographicParameters,
                            "Encapsulate: deterministic coins (InputKeyMaterial) are an ML-KEM-only interface; classical DHKEM has no equivalent",
                        ),
                    ));
                }
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
            match &coins {
                Some(m) => {
                    let r = softhsmrustv3::native::encapsulate_deterministic(
                        session,
                        handle,
                        native_mech,
                        m,
                    );
                    emit_pkcs11_result(
                        deps,
                        correlation_id,
                        "native::encapsulate_deterministic",
                        Some(native_mech),
                        &r,
                    );
                    r.map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Encap"))?
                }
                None => {
                    let r = softhsmrustv3::native::encapsulate(session, handle, native_mech);
                    emit_pkcs11_result(
                        deps,
                        correlation_id,
                        "native::encapsulate",
                        Some(native_mech),
                        &r,
                    );
                    r.map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "Encap"))?
                }
            }
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
                // Cosmetic only (audit-log field) — see the identical note
                // in decapsulate.rs; this path never runs in production.
                let mech = obj.algorithm.to_pkcs11_mech(PkcsOp::Encrypt);
                emit_pkcs11(
                    deps,
                    correlation_id,
                    "soft::placeholder_encapsulate",
                    mech,
                    0,
                    "CKR_OK",
                );
                (
                    placeholder_bytes(&req.uid, coins.as_deref().unwrap_or_default(), b"encap", 32),
                    placeholder_bytes(&req.uid, coins.as_deref().unwrap_or_default(), b"ss", 32),
                )
            }
        }
    };

    // Create the NEW managed SecretData object holding the shared secret.
    let ss_uid = store_shared_secret(deps, obj.algorithm, shared_secret)?;

    emit_success(deps, correlation_id, "Encapsulate");

    Ok(EncapsulateResponse { uid: ss_uid, data: ciphertext, rekeyed: None })
}

/// Transparent auto-rekey transaction for classical KEM crypto-agility
/// (2026-07-05) — the `Encapsulate`-side mirror of `sign.rs::rekey_and_sign`.
///
/// The active policy substituted the stored key-pair's algorithm (e.g.
/// classical `ECDH-P256` → `ML-KEM-1024`/a hybrid), so: (1) generate a fresh
/// key **pair** under `new_algorithm`; (2) activate **both** halves — doing
/// this at the pair level, not just the public half, is what makes a
/// centralized policy migrate both `Encapsulate` (this call) and the
/// receiver's future `Decapsulate` calls: by the time the receiver next
/// decapsulates, their new private key is already Active, so that call needs
/// no rekey logic of its own (see `policy::rule::is_consumer_op` for why
/// `Decapsulate` structurally can't originate one); (3) deactivate +
/// supersede **both** halves of the old classical pair (KMIP has no
/// "Deprecated" state — the §3.2 Active→Deactivated transition is the move
/// for a superseded key, linked via `x-pqctoday-supersedes`); (4) re-issue
/// the Encapsulate against the new **public** key (Encapsulate always
/// targets the public half — unlike Sign's private-key target).
///
/// The caller (a sender using the original public-key UID) gets a valid
/// ciphertext under the migrated algorithm with no code change. The old
/// (now-Deactivated) key pair remains available for its intended residual
/// role: any in-flight `Decapsulate` of a ciphertext already encapsulated
/// against it before the migration (see decapsulate.rs's lifecycle gate).
fn rekey_and_encapsulate(
    deps: &Deps,
    req: &EncapsulateRequest,
    old: &ObjectRecord,
    new_algorithm: &str,
    correlation_id: &str,
) -> Result<EncapsulateResponse> {
    use crate::kmip30::{ActivateRequest, Attribute, CreateKeyPairRequest, UsageMask};

    let new_alg = super::create_key_pair::parse_algorithm(new_algorithm)
        .map_err(|e| fail_err(deps, correlation_id, "Encapsulate", e))?;

    // 1. Generate the replacement key-establishment key pair under the
    // policy's target (ML-KEM or a hybrid combo — `create_key_pair` already
    // handles both via `KmipAlgorithm::hybrid_kem()`). The old key's Name is
    // copied onto the replacement so the business label survives the migration
    // (Locate-by-label and the Migration tab's cards follow the successor).
    let mut common_attributes = vec![
        Attribute::CryptographicAlgorithm(new_alg),
        Attribute::CryptographicUsageMask(UsageMask::KEY_AGREEMENT),
    ];
    if let Some(name) = &old.name {
        common_attributes.push(Attribute::Name(name.clone()));
    }
    let ckp = super::create_key_pair::create_key_pair(
        deps,
        CreateKeyPairRequest {
            common_attributes,
            private_key_attributes: vec![],
            public_key_attributes: vec![],
            seed: None,
        },
        "CreateKeyPair:KeyAgreement",
        correlation_id,
    )?;

    // 2. Activate both halves — see the function doc for why this is what
    // makes the receiver's future Decapsulate need no rekey of its own.
    super::activate::activate(
        deps,
        ActivateRequest { uid: ckp.private_key_uid.clone() },
        correlation_id,
    )?;
    super::activate::activate(
        deps,
        ActivateRequest { uid: ckp.public_key_uid.clone() },
        correlation_id,
    )?;

    // 3. Deactivate + supersede the old key pair (both halves — Encapsulate
    // targets the public half, but the pair migrates together).
    let mut old_rec = old.clone();
    let from_state = format!("{:?}", old_rec.state);
    old_rec.state = State::Deactivated;
    old_rec.supersedes = Some(ckp.public_key_uid.clone());
    old_rec
        .links
        .insert("x-pqctoday-supersedes".to_string(), ckp.public_key_uid.clone());
    deps.store.update(old_rec)?;
    deps.sink.emit(crate::auditlog::AuditEvent::at(
        OffsetDateTime::now_utc(),
        crate::auditlog::Plane::Kmip,
        correlation_id,
        crate::auditlog::EventPayload::KmipObjectStateChanged {
            uid: old.uid.clone(),
            from_state,
            to_state: "Deactivated".into(),
            reason: format!(
                "superseded by {} (agility rekey → {})",
                ckp.public_key_uid, new_algorithm
            ),
        },
    ));
    // The old private half is a separate KMIP object (found via its own
    // pkcs11_cka_id) when this key was created as a key pair — deactivate it
    // too so a stray Encapsulate/Decapsulate against the private UID (if a
    // caller has it) is also correctly blocked from new use. Best-effort:
    // absence of a distinct private record (e.g. this handler was reached
    // via the public UID and the private one is untracked here) isn't fatal.
    if old.object_type == crate::kmip30::ObjectType::PublicKey {
        if let Some(priv_uid) = old.links.get("PrivateKeyLink").cloned() {
            if let Ok(Some(mut priv_rec)) = deps.store.get(&priv_uid) {
                priv_rec.state = State::Deactivated;
                priv_rec.supersedes = Some(ckp.private_key_uid.clone());
                priv_rec
                    .links
                    .insert("x-pqctoday-supersedes".to_string(), ckp.private_key_uid.clone());
                let _ = deps.store.update(priv_rec);
            }
        }
    }

    // 4. Re-issue the original Encapsulate against the new PUBLIC key (not
    // the private key — Encapsulate's Unique Identifier always names the
    // encapsulation/public half), then stamp the response with rekey
    // provenance (mirrors `SignResponse::rekeyed` — the dispatcher's Undo
    // wave can find and delete both new-key halves on rollback).
    let mut resp = encapsulate(
        deps,
        EncapsulateRequest {
            uid: ckp.public_key_uid.clone(),
            input_key_material: req.input_key_material.clone(),
            cryptographic_parameters: req.cryptographic_parameters.clone(),
        },
        correlation_id,
    )?;
    resp.rekeyed = Some(crate::kmip30::EncapsulateRekeyInfo {
        old_uid: old.uid.clone(),
        new_public_key_uid: ckp.public_key_uid,
        new_private_key_uid: ckp.private_key_uid,
    });
    Ok(resp)
}

pub(crate) fn is_ml_kem(a: KmipAlgorithm) -> bool {
    matches!(a, KmipAlgorithm::MlKem512 | KmipAlgorithm::MlKem768 | KmipAlgorithm::MlKem1024)
}

/// Classical ephemeral-static ECDH as a KEM (2026-07-05) — KMIP 3.0 WD19's
/// `DHKEM` (§11.26), PKCS#11 v3.2 §6.3.17's `CKM_ECDH1_DERIVE`-under-
/// `C_EncapsulateKey`/`C_DecapsulateKey` mode. There is no standalone
/// X25519/X448 `KmipAlgorithm` codepoint — both are modelled as `Ecdh` with
/// a `RecommendedCurve` of `CURVE25519`/`CURVE448` (see
/// `create_key_pair.rs`'s `Ecdh` branch), so this matches the bare variant.
pub(crate) fn is_classical_kem(a: KmipAlgorithm) -> bool {
    matches!(a, KmipAlgorithm::Ecdh)
}

/// FrodoKEM (BSI TR-02102-1 §2.4.1) — all 6 standard variants.
pub(crate) fn is_frodokem(a: KmipAlgorithm) -> bool {
    matches!(
        a,
        KmipAlgorithm::FrodoKem640Aes
            | KmipAlgorithm::FrodoKem640Shake
            | KmipAlgorithm::FrodoKem976Aes
            | KmipAlgorithm::FrodoKem976Shake
            | KmipAlgorithm::FrodoKem1344Aes
            | KmipAlgorithm::FrodoKem1344Shake
    )
}

/// Classic McEliece (BSI TR-02102-1 §2.4.2) — scoped to `mceliece6688128`
/// only (implementation plan Phase 0.5).
pub(crate) fn is_classic_mceliece(a: KmipAlgorithm) -> bool {
    matches!(a, KmipAlgorithm::ClassicMcEliece6688128)
}

/// Persist the derived shared secret as a fresh managed `SecretData`
/// object and return its UID. The bytes are kept verbatim in
/// `key_material` (KeyFormatType=Raw) so a subsequent `Get` returns them
/// directly (the engine never sees the shared secret as a managed
/// object — it is opaque KMIP material). Born `Active` so an immediate
/// `Get` succeeds.
pub(crate) fn store_shared_secret(
    deps: &Deps,
    source_algorithm: KmipAlgorithm,
    shared_secret: Vec<u8>,
) -> Result<String> {
    let uid = format!("urn:pqctoday:obj:{}", Uuid::new_v4());
    let now = OffsetDateTime::now_utc();
    deps.store.put(ObjectRecord {
        uid: uid.clone(),
        object_type: ObjectType::SecretData,
        // The shared secret is opaque bytes; record the source KEM
        // algorithm for provenance in attribute queries.
        algorithm: source_algorithm,
        // KMIP 3.0 §6.2 — a `SecretData` KeyBlock carries no
        // CryptographicAlgorithm/Length (the OASIS PQC interop KATs
        // expect a 2-child KeyBlock: KeyFormatType + KeyValue). The
        // wire encoder uses `cryptographic_length == 0` as the
        // "omit crypto metadata" sentinel (same as BL-M-4).
        cryptographic_length: 0,
        // KMIP 3.0 §3.x lifecycle — the derived shared secret is born
        // PreActive (never Activated). The OASIS PQC interop KATs Get it
        // then Destroy it directly; PreActive → Destroyed is a legal FSM
        // edge whereas Active is not (Active would require Revoke first,
        // as the KATs do for the key pair but NOT for the shared secret).
        state: State::PreActive,
        pkcs11_cka_id: Uuid::new_v4().as_bytes().to_vec(),
        pkcs11_slot: deps.config.pkcs11_slot,
        initial_date: now,
        activation_date: None,
        last_change_date: Some(now),
        original_creation_date: Some(now),
        key_material: Some(shared_secret),
        key_format_type: Some(KeyFormatType::Raw as u32),
        // KMIP 3.0 §6.2 — the ML-KEM shared secret is keying seed
        // material; the OASIS PQC interop KATs serve it back as
        // SecretDataType=Seed (0x02), not the Password default.
        secret_data_type: Some(0x02),
        extractable: Some(true),
        sensitive: Some(false),
        fresh: Some(true),
        ..ObjectRecord::default()
    })?;
    Ok(uid)
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
    use crate::kmip30::{DecapsulateRequest, UsageMask};
    use crate::policy::Engine;
    use crate::store::MemoryStore;
    use std::sync::Arc;
    use super::super::decapsulate::decapsulate;

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

    fn put_mlkem_pub(d: &Deps, uid: &str) {
        d.store
            .put(ObjectRecord {
                uid: uid.to_string(),
                object_type: ObjectType::PublicKey,
                algorithm: KmipAlgorithm::MlKem768,
                usage_mask: UsageMask::ENCRYPT,
                state: State::Active,
                ..ObjectRecord::default()
            })
            .unwrap();
    }

    /// Classical `Ecdh` public key with a NIST `RecommendedCurve` (P-256) —
    /// 2026-07-05, classical-KEM crypto-agility.
    fn put_ecdh_p256_pub(d: &Deps, uid: &str) {
        d.store
            .put(ObjectRecord {
                uid: uid.to_string(),
                object_type: ObjectType::PublicKey,
                algorithm: KmipAlgorithm::Ecdh,
                recommended_curve: Some(crate::kmip30::algos::recommended_curve::P_256),
                usage_mask: UsageMask::ENCRYPT,
                state: State::Active,
                ..ObjectRecord::default()
            })
            .unwrap();
    }

    #[test]
    fn placeholder_encapsulate_creates_secret_data_and_returns_ct() {
        let d = deps();
        put_mlkem_pub(&d, "pk");
        let resp = encapsulate(
            &d,
            EncapsulateRequest {
                uid: "pk".to_string(),
                input_key_material: Some(vec![0x11; 32]),
                cryptographic_parameters: None,
            },
            "t",
        )
        .unwrap();
        assert_eq!(resp.data.len(), 32, "placeholder ciphertext");
        let ss_rec = d.store.get(&resp.uid).unwrap().unwrap();
        assert_eq!(ss_rec.object_type, ObjectType::SecretData);
        // Born PreActive so a subsequent Destroy (without Revoke) is a
        // legal FSM edge — matches the OASIS PQC interop KAT flow.
        assert_eq!(ss_rec.state, State::PreActive);
        assert!(ss_rec.key_material.is_some(), "shared secret persisted");
        assert_ne!(resp.uid, "pk", "a NEW object UID is returned");
    }

    #[test]
    fn encapsulate_rejects_non_mlkem_key() {
        let d = deps();
        d.store
            .put(ObjectRecord {
                uid: "rsa".to_string(),
                object_type: ObjectType::PublicKey,
                algorithm: KmipAlgorithm::Rsa,
                state: State::Active,
                ..ObjectRecord::default()
            })
            .unwrap();
        let err = encapsulate(
            &d,
            EncapsulateRequest { uid: "rsa".to_string(), ..Default::default() },
            "t",
        )
        .unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::OperationNotSupported);
    }

    /// Classical ECDH-P256 is now a valid Encapsulate target (2026-07-05) —
    /// previously rejected the same way RSA still is above.
    #[test]
    fn encapsulate_accepts_classical_ecdh_key() {
        let d = deps();
        put_ecdh_p256_pub(&d, "ecdh-pk");
        let resp = encapsulate(
            &d,
            EncapsulateRequest { uid: "ecdh-pk".to_string(), ..Default::default() },
            "t",
        )
        .unwrap();
        assert_ne!(resp.uid, "ecdh-pk", "a NEW SecretData object UID is returned");
        let ss_rec = d.store.get(&resp.uid).unwrap().unwrap();
        assert_eq!(ss_rec.object_type, ObjectType::SecretData);
    }

    fn deps_with(yaml: &str) -> (Arc<RingSink>, Deps) {
        let ring = Arc::new(RingSink::new(64));
        let sink: Arc<dyn AuditSink> = ring.clone();
        let engine = Engine::with_global_sink(sink.clone());
        engine
            .activate(crate::policy::load_from_str(yaml, std::path::Path::new("<test>")).unwrap())
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

    const REKEY_POLICY: &str = r#"
schema_version: 1
metadata: { name: rk, description: rekey, authority: t, effective: "always" }
rules:
  - type: algorithm_substitution
    ops: [Encapsulate]
    from: ECDH-P256
    to: ML-KEM-1024
    reason: "Upgrade key-establishment to ML-KEM-1024"
"#;

    /// The centralized-policy story end to end (2026-07-05): an existing
    /// classical ECDH-P256 key PAIR + a policy substituting it to
    /// ML-KEM-1024 on `Encapsulate` → the engine emits `RekeyAndProceed` →
    /// `rekey_and_encapsulate` mints a fresh pair, activates BOTH halves,
    /// deactivates+supersedes BOTH halves of the old pair, and re-issues the
    /// Encapsulate. Mirrors `sign.rs::tests::rekey_transparently_migrates_and_signs`.
    #[test]
    fn rekey_transparently_migrates_and_encapsulates() {
        let (_ring, d) = deps_with(REKEY_POLICY);

        let mut pub_links = std::collections::HashMap::new();
        pub_links.insert("PrivateKeyLink".to_string(), "urn:ecdh-priv".to_string());
        d.store
            .put(ObjectRecord {
                uid: "urn:ecdh-pub".into(),
                object_type: ObjectType::PublicKey,
                algorithm: KmipAlgorithm::Ecdh,
                recommended_curve: Some(crate::kmip30::algos::recommended_curve::P_256),
                usage_mask: UsageMask::KEY_AGREEMENT,
                state: State::Active,
                links: pub_links,
                ..ObjectRecord::default()
            })
            .unwrap();
        let mut priv_links = std::collections::HashMap::new();
        priv_links.insert("PublicKeyLink".to_string(), "urn:ecdh-pub".to_string());
        d.store
            .put(ObjectRecord {
                uid: "urn:ecdh-priv".into(),
                object_type: ObjectType::PrivateKey,
                algorithm: KmipAlgorithm::Ecdh,
                recommended_curve: Some(crate::kmip30::algos::recommended_curve::P_256),
                usage_mask: UsageMask::KEY_AGREEMENT,
                state: State::Active,
                links: priv_links,
                ..ObjectRecord::default()
            })
            .unwrap();

        let resp = encapsulate(
            &d,
            EncapsulateRequest { uid: "urn:ecdh-pub".into(), ..Default::default() },
            "corr-rk",
        )
        .unwrap();

        let rekey = resp.rekeyed.expect("Encapsulate must report the rekey it performed");
        assert_eq!(rekey.old_uid, "urn:ecdh-pub");
        assert_ne!(rekey.new_public_key_uid, "urn:ecdh-pub");

        // New pair: ML-KEM-1024, both halves Active.
        let new_pub = d.store.get(&rekey.new_public_key_uid).unwrap().unwrap();
        assert_eq!(new_pub.algorithm, KmipAlgorithm::MlKem1024);
        assert_eq!(new_pub.state, State::Active);
        let new_priv = d.store.get(&rekey.new_private_key_uid).unwrap().unwrap();
        assert_eq!(new_priv.algorithm, KmipAlgorithm::MlKem1024);
        assert_eq!(new_priv.state, State::Active);

        // Old pair: BOTH halves Deactivated + supersede-linked — the pair-level
        // migration that lets a future Decapsulate need no rekey of its own.
        let old_pub = d.store.get("urn:ecdh-pub").unwrap().unwrap();
        assert_eq!(old_pub.state, State::Deactivated);
        assert_eq!(old_pub.supersedes.as_deref(), Some(rekey.new_public_key_uid.as_str()));
        let old_priv = d.store.get("urn:ecdh-priv").unwrap().unwrap();
        assert_eq!(old_priv.state, State::Deactivated, "private half must migrate with the public half");
        assert_eq!(old_priv.supersedes.as_deref(), Some(rekey.new_private_key_uid.as_str()));

        // The new private key must decapsulate the ciphertext Encapsulate
        // just produced. (This test harness has no real engine session, so
        // Decapsulate runs its `#[cfg(test)]` placeholder path rather than
        // real crypto — it can't independently prove the OLD classical key
        // would reject an ML-KEM ciphertext; that cross-algorithm rejection
        // is proven with a real engine at `rust/src/native/encrypt.rs`'s
        // `classical_encapsulate_wrong_mechanism_is_rejected` and the
        // `CKA_KEY_TYPE` checks in `classical_decapsulate`. What this test
        // proves is the KMIP-layer state machine: the pair-level rekey
        // happened, both new halves are Active, both old halves are
        // Deactivated+superseded.)
        let good = decapsulate(
            &d,
            DecapsulateRequest {
                uid: rekey.new_private_key_uid.clone(),
                data: resp.data.clone(),
                ..Default::default()
            },
            "corr-good",
        );
        assert!(good.is_ok(), "new key must decapsulate the ciphertext Encapsulate just produced");
    }
}
