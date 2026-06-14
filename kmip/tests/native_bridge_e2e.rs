//! Phase 7b end-to-end test: KMIP op handlers driving real
//! `softhsmrustv3::native::*` calls. Proves the §12.7.7 lock is closed
//! for the demo-critical path.
//!
//! Unlike the other integration tests in `tests/`, this one bootstraps
//! a **real** engine session before running the KMIP op handlers, and
//! exercises:
//!
//!   CreateKeyPair (ML-DSA-65) → Sign → SignatureVerify → Destroy
//!
//! All Plane-3 emissions carry real cryptographic output. The signature
//! is a FIPS-204-conformant 3309 bytes; verification returns
//! `Ok(true)`; destroy removes the engine handle.
//!
//! Serialised on a local `engine_test_lock` — the engine's
//! `lazy_static! ref _: Mutex<T>` storage means parallel tests that
//! touch engine state race during the bootstrap dance (init_token →
//! login → init_pin → logout → close → re-login). All tests in this
//! file acquire the same mutex.
//!
//! Engine state is reset (`native::finalize() + native::init()`) at the
//! start of every `#[test]` body so prior-test object/session state
//! doesn't leak.

use std::collections::HashMap;
use std::sync::Arc;
use time::OffsetDateTime;

use pqctoday_kmip::auditlog::{AuditSink, RingSink};
use pqctoday_kmip::kmip30::{
    Attribute, CreateKeyPairRequest, DestroyRequest, KmipAlgorithm, ObjectType, SignRequest,
    SignatureValidity, SignatureVerifyRequest, State, UsageMask,
};
use pqctoday_kmip::ops::activate::activate;
use pqctoday_kmip::ops::create_key_pair::create_key_pair;
use pqctoday_kmip::ops::destroy::destroy;
use pqctoday_kmip::ops::sign::sign;
use pqctoday_kmip::ops::signature_verify::signature_verify;
use pqctoday_kmip::ops::{Deps, DepsConfig};
use pqctoday_kmip::policy::{load_from_str, Engine};
use pqctoday_kmip::store::MemoryStore;

/// Serialise all e2e tests that touch the engine. The engine's
/// `lazy_static!` storage means parallel tests race during the
/// bootstrap dance.
fn engine_test_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

const PERMISSIVE_POLICY: &str = r#"
schema_version: 1
metadata: { name: t, description: t, authority: t, effective: always }
rules: []
"#;

fn build_deps_with_real_engine() -> Deps {
    build_deps_with_real_engine_and_ring().1
}

/// Same bootstrap, but also hands back the `RingSink` so tests can
/// assert on the audit trail (K15 truthful Plane-3 records).
fn build_deps_with_real_engine_and_ring() -> (Arc<RingSink>, Deps) {
    use softhsmrustv3::native::session;

    // Reset engine state for test isolation.
    let _ = session::finalize();
    session::init().expect("engine init");

    // Bootstrap a fresh token + open a user session.
    let engine_session = session::bootstrap_default_token(0, "so-pin", "user-pin", "phase7b-e2e")
        .expect("bootstrap real engine session");

    let ring = Arc::new(RingSink::new(64));
    let sink: Arc<dyn AuditSink> = ring.clone();
    let policy_engine = Engine::with_global_sink(sink.clone());
    policy_engine
        .activate(load_from_str(PERMISSIVE_POLICY, std::path::Path::new("<e2e>")).unwrap())
        .unwrap();

    let deps = Deps::new(
        policy_engine,
        Arc::new(MemoryStore::new()),
        sink,
        DepsConfig::default(),
    )
    .with_engine_session(engine_session);
    (ring, deps)
}

/// Headline demo: real ML-DSA-65 keygen → sign → verify → destroy
/// end-to-end through the KMIP op handlers, against a real
/// softhsmrustv3 engine session.
///
/// Asserts:
/// - `signature.len() == 3309` (FIPS 204 §5 ML-DSA-65)
/// - `verify` against the same data → Ok(true) → `ValidityIndicator::Valid`
/// - tampered signature → `ValidityIndicator::Invalid`
/// - `destroy` succeeds and removes the engine state
#[test]
fn ml_dsa_65_create_sign_verify_destroy_against_real_engine() {
    let _guard = engine_test_lock();
    let deps = build_deps_with_real_engine();

    // ── CreateKeyPair ────────────────────────────────────────────────────
    let create_req = CreateKeyPairRequest {
        common_attributes: vec![Attribute::CryptographicAlgorithm(KmipAlgorithm::MlDsa65)],
        private_key_attributes: vec![Attribute::CryptographicUsageMask(UsageMask::SIGN)],
        public_key_attributes: vec![Attribute::CryptographicUsageMask(UsageMask::VERIFY)],
    seed: None,
    };
    let kp_resp =
        create_key_pair(&deps, create_req, "CreateKeyPair:Sign", "e2e-create").unwrap();

    // Both halves of the keypair share the same CKA_ID — verify via the store.
    let priv_rec = deps.store.get(&kp_resp.private_key_uid).unwrap().unwrap();
    let pub_rec = deps.store.get(&kp_resp.public_key_uid).unwrap().unwrap();
    assert_eq!(priv_rec.pkcs11_cka_id, pub_rec.pkcs11_cka_id);
    assert_eq!(priv_rec.algorithm, KmipAlgorithm::MlDsa65);

    // ── Activate (lifecycle: PreActive → Active) ─────────────────────────
    use pqctoday_kmip::kmip30::ActivateRequest;
    activate(
        &deps,
        ActivateRequest { uid: priv_rec.uid.clone() },
        "e2e-activate-priv",
    )
    .unwrap();
    activate(
        &deps,
        ActivateRequest { uid: pub_rec.uid.clone() },
        "e2e-activate-pub",
    )
    .unwrap();

    // ── Sign ─────────────────────────────────────────────────────────────
    let message = b"the quick brown fox jumps over the lazy dog";
    let sig_resp = sign(
        &deps,
        SignRequest {
            uid: priv_rec.uid.clone(),
            data: message.to_vec(),
            cryptographic_parameters: None,
        },
        "e2e-sign",
    )
    .unwrap();
    assert_eq!(
        sig_resp.signature.len(),
        3309,
        "FIPS 204 §5 ML-DSA-65 signature is 3309 bytes; got {} — bridge isn't real",
        sig_resp.signature.len()
    );

    // ── SignatureVerify (correct) ────────────────────────────────────────
    let verify_resp = signature_verify(
        &deps,
        SignatureVerifyRequest {
            uid: pub_rec.uid.clone(),
            data: message.to_vec(),
            signature: sig_resp.signature.clone(),
            cryptographic_parameters: None,
        },
        "e2e-verify-ok",
    )
    .unwrap();
    assert_eq!(
        verify_resp.validity,
        SignatureValidity::Valid,
        "freshly-signed message must verify"
    );

    // ── SignatureVerify (tampered) ───────────────────────────────────────
    let mut tampered = sig_resp.signature.clone();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 0xFF;
    let verify_bad = signature_verify(
        &deps,
        SignatureVerifyRequest {
            uid: pub_rec.uid.clone(),
            data: message.to_vec(),
            signature: tampered,
            cryptographic_parameters: None,
        },
        "e2e-verify-bad",
    )
    .unwrap();
    assert_eq!(
        verify_bad.validity,
        SignatureValidity::Invalid,
        "tampered signature must be Invalid"
    );

    // ── Destroy ──────────────────────────────────────────────────────────
    // Lifecycle: Active → Deactivated → Destroyed isn't required because
    // §3.4 FSM allows Active → Destroyed when revoked first; for the e2e
    // demo we just verify Destroy on the private key handles the engine
    // cleanup gracefully (best-effort: §3.4 also allows DestroyedCompromised).
    // Mark both Deactivated first via Revoke.
    use pqctoday_kmip::kmip30::{RevocationReason, RevokeRequest};
    pqctoday_kmip::ops::revoke::revoke(
        &deps,
        RevokeRequest {
            uid: priv_rec.uid.clone(),
            reason: RevocationReason::CessationOfOperation,
        },
        "e2e-revoke",
    )
    .unwrap();
    let destroy_resp = destroy(
        &deps,
        DestroyRequest {
            uid: priv_rec.uid.clone(),
        },
        "e2e-destroy",
    )
    .unwrap();
    assert_eq!(destroy_resp.state, State::Destroyed);

    // ── Clean engine state ───────────────────────────────────────────────
    let _ = softhsmrustv3::native::session::finalize();
}

/// Same flow but ML-DSA-87: signature is 4627 bytes (FIPS 204 §5).
#[test]
fn ml_dsa_87_create_sign_verify_against_real_engine() {
    let _guard = engine_test_lock();
    let deps = build_deps_with_real_engine();

    let create_req = CreateKeyPairRequest {
        common_attributes: vec![Attribute::CryptographicAlgorithm(KmipAlgorithm::MlDsa87)],
        private_key_attributes: vec![Attribute::CryptographicUsageMask(UsageMask::SIGN)],
        public_key_attributes: vec![Attribute::CryptographicUsageMask(UsageMask::VERIFY)],
    seed: None,
    };
    let kp_resp =
        create_key_pair(&deps, create_req, "CreateKeyPair:Sign", "e2e87-create").unwrap();

    let priv_rec = deps.store.get(&kp_resp.private_key_uid).unwrap().unwrap();
    let pub_rec = deps.store.get(&kp_resp.public_key_uid).unwrap().unwrap();

    use pqctoday_kmip::kmip30::ActivateRequest;
    activate(&deps, ActivateRequest { uid: priv_rec.uid.clone() }, "a").unwrap();
    activate(&deps, ActivateRequest { uid: pub_rec.uid.clone() }, "b").unwrap();

    let sig = sign(
        &deps,
        SignRequest {
            uid: priv_rec.uid.clone(),
            data: b"hello".to_vec(),
            cryptographic_parameters: None,
        },
        "s",
    )
    .unwrap();
    assert_eq!(
        sig.signature.len(),
        4627,
        "FIPS 204 §5 ML-DSA-87 signature is 4627 bytes"
    );

    let verified = signature_verify(
        &deps,
        SignatureVerifyRequest {
            uid: pub_rec.uid.clone(),
            data: b"hello".to_vec(),
            signature: sig.signature,
            cryptographic_parameters: None,
        },
        "v",
    )
    .unwrap();
    assert_eq!(verified.validity, SignatureValidity::Valid);

    let _ = softhsmrustv3::native::session::finalize();
}

/// K6 — RSA sign/verify honors the requested hash (SHA-384 / SHA-512 →
/// the S6 engine mechanisms `CKM_SHA384/512_RSA_PKCS{,_PSS}`) end-to-end
/// through the KMIP op handlers against a real engine session:
///
/// - sign + verify round-trips per (hash, padding) combination;
/// - cross-hash verify (signed SHA-384, verified SHA-512) → `Invalid`;
/// - verify with an unrunnable hash (SHA-1) → Success + `Invalid`
///   (CS-AC-M-3 semantics), NOT a protocol error;
/// - sign with an unrunnable hash (SHA-1) →
///   `UnsupportedCryptographicParameters (0x3e)`.
#[test]
fn k6_rsa_sha384_sha512_sign_verify_against_real_engine() {
    use pqctoday_kmip::error::ResultReason;
    use pqctoday_kmip::kmip30::{ActivateRequest, CryptographicParameters, HashingAlgorithm};

    let _guard = engine_test_lock();
    let deps = build_deps_with_real_engine();

    let create_req = CreateKeyPairRequest {
        common_attributes: vec![Attribute::CryptographicAlgorithm(KmipAlgorithm::Rsa)],
        private_key_attributes: vec![Attribute::CryptographicUsageMask(UsageMask::SIGN)],
        public_key_attributes: vec![Attribute::CryptographicUsageMask(UsageMask::VERIFY)],
    seed: None,
    };
    let kp = create_key_pair(&deps, create_req, "CreateKeyPair:Sign", "k6-create").unwrap();
    let priv_uid = kp.private_key_uid;
    let pub_uid = kp.public_key_uid;
    activate(&deps, ActivateRequest { uid: priv_uid.clone() }, "k6-a1").unwrap();
    activate(&deps, ActivateRequest { uid: pub_uid.clone() }, "k6-a2").unwrap();

    let cp = |hash: HashingAlgorithm, padding: Option<u32>| CryptographicParameters {
        hashing_algorithm: Some(hash),
        padding_method: padding,
        ..Default::default()
    };
    let message = b"K6: hashes are honored, never substituted".to_vec();

    // (hash, padding): PKCS1 v1.5 (0x08) and PSS (0x0a) per the verified
    // KMIP 3.0 Padding Method enum.
    for (hash, padding) in [
        (HashingAlgorithm::Sha384, Some(0x08)),
        (HashingAlgorithm::Sha512, Some(0x08)),
        (HashingAlgorithm::Sha384, Some(0x0a)),
        (HashingAlgorithm::Sha512, Some(0x0a)),
    ] {
        let sig = sign(
            &deps,
            SignRequest {
                uid: priv_uid.clone(),
                data: message.clone(),
                cryptographic_parameters: Some(cp(hash, padding)),
            },
            "k6-sign",
        )
        .unwrap_or_else(|e| panic!("sign {hash:?}/{padding:?} failed: {e:?}"));
        assert_eq!(sig.signature.len(), 256, "RSA-2048 signature is 256 bytes");

        let ok = signature_verify(
            &deps,
            SignatureVerifyRequest {
                uid: pub_uid.clone(),
                data: message.clone(),
                signature: sig.signature.clone(),
                cryptographic_parameters: Some(cp(hash, padding)),
            },
            "k6-verify",
        )
        .unwrap();
        assert_eq!(ok.validity, SignatureValidity::Valid, "{hash:?}/{padding:?}");

        // Cross-hash: same signature verified under the other hash → Invalid.
        let other = if hash == HashingAlgorithm::Sha384 {
            HashingAlgorithm::Sha512
        } else {
            HashingAlgorithm::Sha384
        };
        let cross = signature_verify(
            &deps,
            SignatureVerifyRequest {
                uid: pub_uid.clone(),
                data: message.clone(),
                signature: sig.signature,
                cryptographic_parameters: Some(cp(other, padding)),
            },
            "k6-verify-cross",
        )
        .unwrap();
        assert_eq!(
            cross.validity,
            SignatureValidity::Invalid,
            "cross-hash verify must be Invalid, not silently re-hashed"
        );
    }

    // Verify with a hash the server can't run → Success + Invalid
    // (CS-AC-M-3 step #4 semantics).
    let sha1_verify = signature_verify(
        &deps,
        SignatureVerifyRequest {
            uid: pub_uid.clone(),
            data: message.clone(),
            signature: vec![0u8; 256],
            cryptographic_parameters: Some(cp(HashingAlgorithm::Sha1, Some(0x0a))),
        },
        "k6-verify-sha1",
    )
    .unwrap();
    assert_eq!(sha1_verify.validity, SignatureValidity::Invalid);

    // Sign with a hash the server can't run → 0x3e protocol error.
    let sha1_sign = sign(
        &deps,
        SignRequest {
            uid: priv_uid.clone(),
            data: message,
            cryptographic_parameters: Some(cp(HashingAlgorithm::Sha1, Some(0x08))),
        },
        "k6-sign-sha1",
    )
    .unwrap_err();
    assert_eq!(
        sha1_sign.result_reason(),
        ResultReason::UnsupportedCryptographicParameters
    );

    let _ = softhsmrustv3::native::session::finalize();
}

/// K18 — KMIP 3.0 §11 `Salt Length` (0x420100) threads through
/// Sign / SignatureVerify to the engine's RSA-PSS implementation
/// (round-1 K6 residual: it used to be silently left at the §6.2
/// hash-length default).
///
/// - salt = 0 makes PSS deterministic (RFC 8017 §9.1.1 — the salt is
///   the only randomness): two signs byte-match;
/// - verify with an explicit salt pins EMSA-PSS-VERIFY to exactly that
///   length (the `rsa` crate does NOT recover salt length from the
///   padding) — a salt-0 signature is Invalid under the default
///   candidates (hash length / maximal) and under a wrong salt;
/// - effective-CP precedence: a request CP overrides the object's
///   stored CP wholesale (same request-over-object rule K6 set for
///   padding/hash);
/// - salt on a non-PSS mechanism is ignored (CP is a grab-bag);
/// - negative salt → `InvalidField`; oversized salt
///   (> emLen - hLen - 2 = 222 for RSA-2048/SHA-256) →
///   `CryptographicFailure` from the engine.
#[test]
fn k18_rsa_pss_salt_length_threads_to_engine() {
    use pqctoday_kmip::error::ResultReason;
    use pqctoday_kmip::kmip30::{ActivateRequest, CryptographicParameters, HashingAlgorithm};

    let _guard = engine_test_lock();
    let deps = build_deps_with_real_engine();

    let create_req = CreateKeyPairRequest {
        common_attributes: vec![Attribute::CryptographicAlgorithm(KmipAlgorithm::Rsa)],
        private_key_attributes: vec![Attribute::CryptographicUsageMask(UsageMask::SIGN)],
        public_key_attributes: vec![Attribute::CryptographicUsageMask(UsageMask::VERIFY)],
    seed: None,
    };
    let kp = create_key_pair(&deps, create_req, "CreateKeyPair:Sign", "k18-create").unwrap();
    let priv_uid = kp.private_key_uid;
    let pub_uid = kp.public_key_uid;
    activate(&deps, ActivateRequest { uid: priv_uid.clone() }, "k18-a1").unwrap();
    activate(&deps, ActivateRequest { uid: pub_uid.clone() }, "k18-a2").unwrap();

    let cp_pss = |salt: Option<i32>| CryptographicParameters {
        hashing_algorithm: Some(HashingAlgorithm::Sha256),
        padding_method: Some(0x0a), // PSS
        salt_length: salt,
        ..Default::default()
    };
    let message = b"K18: KMIP Salt Length reaches the PSS engine".to_vec();
    let sign_with = |cp: Option<CryptographicParameters>| {
        sign(
            &deps,
            SignRequest {
                uid: priv_uid.clone(),
                data: message.clone(),
                cryptographic_parameters: cp,
            },
            "k18-sign",
        )
    };
    let verify_with = |sig: Vec<u8>, cp: Option<CryptographicParameters>| {
        signature_verify(
            &deps,
            SignatureVerifyRequest {
                uid: pub_uid.clone(),
                data: message.clone(),
                signature: sig,
                cryptographic_parameters: cp,
            },
            "k18-verify",
        )
        .unwrap()
        .validity
    };

    // ── salt = 0: deterministic sign, pinned verify ─────────────────
    let s1 = sign_with(Some(cp_pss(Some(0)))).unwrap().signature;
    let s2 = sign_with(Some(cp_pss(Some(0)))).unwrap().signature;
    assert_eq!(s1, s2, "PSS with salt 0 is deterministic — the salt reached the engine");
    assert_eq!(verify_with(s1.clone(), Some(cp_pss(Some(0)))), SignatureValidity::Valid);
    // Default verify candidates (hash length / maximal) don't include 0.
    assert_eq!(
        verify_with(s1.clone(), Some(cp_pss(None))),
        SignatureValidity::Invalid,
        "EMSA-PSS-VERIFY pins the salt length — no recovery from the padding"
    );
    assert_eq!(verify_with(s1, Some(cp_pss(Some(32)))), SignatureValidity::Invalid);

    // ── salt = 20 round-trip ────────────────────────────────────────
    let s20 = sign_with(Some(cp_pss(Some(20)))).unwrap().signature;
    assert_eq!(verify_with(s20.clone(), Some(cp_pss(Some(20)))), SignatureValidity::Valid);
    assert_eq!(verify_with(s20, Some(cp_pss(Some(0)))), SignatureValidity::Invalid);

    // ── absent salt keeps the §6.2 hash-length default ──────────────
    let sdef = sign_with(Some(cp_pss(None))).unwrap().signature;
    assert_eq!(verify_with(sdef.clone(), Some(cp_pss(Some(32)))), SignatureValidity::Valid);
    assert_eq!(verify_with(sdef, Some(cp_pss(None))), SignatureValidity::Valid);

    // ── effective-CP precedence: request CP over object CP ──────────
    // Store a CP with salt 0 on the private record (the Register path
    // sets this; CreateKeyPair leaves it None).
    let mut rec = deps.store.get(&priv_uid).unwrap().unwrap();
    rec.cryptographic_parameters = Some(cp_pss(Some(0)));
    deps.store.update(rec).unwrap();
    // No request CP → the object CP applies → deterministic salt-0.
    let o1 = sign_with(None).unwrap().signature;
    let o2 = sign_with(None).unwrap().signature;
    assert_eq!(o1, o2, "object CP salt 0 applies when the request carries none");
    assert_eq!(verify_with(o1, Some(cp_pss(Some(0)))), SignatureValidity::Valid);
    // Request CP (salt 20) overrides the object CP (salt 0) wholesale.
    let r20 = sign_with(Some(cp_pss(Some(20)))).unwrap().signature;
    assert_eq!(verify_with(r20.clone(), Some(cp_pss(Some(20)))), SignatureValidity::Valid);
    assert_eq!(
        verify_with(r20, Some(cp_pss(Some(0)))),
        SignatureValidity::Invalid,
        "request salt must override the object CP salt"
    );

    // ── salt on a non-PSS mechanism is ignored ──────────────────────
    let cp_v15_salt = CryptographicParameters {
        hashing_algorithm: Some(HashingAlgorithm::Sha256),
        padding_method: Some(0x08), // PKCS#1 v1.5
        salt_length: Some(20),
        ..Default::default()
    };
    let v15 = sign_with(Some(cp_v15_salt.clone())).unwrap().signature;
    assert_eq!(verify_with(v15, Some(cp_v15_salt)), SignatureValidity::Valid);

    // ── negative salt → InvalidField ────────────────────────────────
    assert_eq!(
        sign_with(Some(cp_pss(Some(-1)))).unwrap_err().result_reason(),
        ResultReason::InvalidField
    );
    // ── oversized salt → CryptographicFailure from the engine ───────
    assert_eq!(
        sign_with(Some(cp_pss(Some(300)))).unwrap_err().result_reason(),
        ResultReason::CryptographicFailure
    );

    let _ = softhsmrustv3::native::session::finalize();
}

// ── K9 — PQC Register usability (compliance-audit B-6) ──────────────────────
//
// Register of raw FIPS 203/204/205 key material must create a real
// engine object (S7 `native::register_*`) so subsequent Sign /
// SignatureVerify / Encrypt(encap) / Decrypt(decap) find a handle.
// Key bytes are generated in-test with the same fips204 / fips205 /
// ml-kem crates the engine's keygen uses (the engine blocks CKA_VALUE
// export of SENSITIVE private keys, so generate-then-export is not an
// option at this layer).

/// Register one half of a PQC keypair through the KMIP op handler.
/// `ActivationDate=$NOW-3600` (the OASIS corpus pattern) so the object
/// is born `Active` and crypto ops pass the lifecycle gate.
fn register_pqc(
    deps: &Deps,
    object_type: ObjectType,
    alg: KmipAlgorithm,
    format: pqctoday_kmip::kmip30::KeyFormatType,
    key_bytes: Vec<u8>,
    usage: UsageMask,
) -> pqctoday_kmip::error::Result<String> {
    use pqctoday_kmip::kmip30::{KeyBlock, RegisterRequest};
    use pqctoday_kmip::ops::register_import_export::register;
    let len_bits = (key_bytes.len() * 8) as u32;
    register(
        deps,
        RegisterRequest {
            object_type,
            attributes: vec![
                Attribute::CryptographicAlgorithm(alg),
                Attribute::CryptographicLength(len_bits),
                Attribute::CryptographicUsageMask(usage),
                Attribute::ActivationDate(
                    OffsetDateTime::now_utc().unix_timestamp() - 3600,
                ),
            ],
            managed_object: Some(KeyBlock {
                key_format_type: format,
                cryptographic_algorithm: alg,
                cryptographic_length: len_bits,
                key_value: key_bytes,
                key_wrapping_data: None,
            }),
            protection_storage_masks: None,
            certificate_payload: None,
        },
        "k9-register",
    )
    .map(|r| r.uid)
}

/// Registered ML-DSA-65 keypair (raw FIPS 204 bytes generated in-test)
/// → KMIP Sign with the registered private → SignatureVerify with the
/// registered public → Success + Valid. Also pins that the KMIP store
/// copy keeps the raw material verbatim (Get/Export unchanged).
#[test]
fn k9_register_ml_dsa_65_sign_verify_roundtrip() {
    use fips204::traits::SerDes;
    use pqctoday_kmip::kmip30::KeyFormatType;

    let _guard = engine_test_lock();
    let deps = build_deps_with_real_engine();

    let (vk, sk) = fips204::ml_dsa_65::try_keygen_with_rng(&mut rand::rngs::OsRng)
        .expect("FIPS 204 keygen");
    let sk_bytes = sk.into_bytes().to_vec();
    let pk_bytes = vk.into_bytes().to_vec();

    let priv_uid = register_pqc(
        &deps,
        ObjectType::PrivateKey,
        KmipAlgorithm::MlDsa65,
        KeyFormatType::Raw,
        sk_bytes.clone(),
        UsageMask::SIGN,
    )
    .expect("Register ML-DSA-65 private");
    let pub_uid = register_pqc(
        &deps,
        ObjectType::PublicKey,
        KmipAlgorithm::MlDsa65,
        KeyFormatType::Raw,
        pk_bytes,
        UsageMask::VERIFY,
    )
    .expect("Register ML-DSA-65 public");

    // KMIP store copy unchanged (Get/Export behaviour preserved).
    let rec = deps.store.get(&priv_uid).unwrap().unwrap();
    assert_eq!(rec.key_material.as_deref(), Some(&sk_bytes[..]));
    assert_eq!(rec.state, State::Active, "past ActivationDate → born Active");

    let message = b"K9: registered PQC keys are usable".to_vec();
    let sig = sign(
        &deps,
        SignRequest {
            uid: priv_uid,
            data: message.clone(),
            cryptographic_parameters: None,
        },
        "k9-sign",
    )
    .expect("Sign with registered ML-DSA-65 private key");
    assert_eq!(sig.signature.len(), 3309, "FIPS 204 §5 ML-DSA-65 signature");

    let verified = signature_verify(
        &deps,
        SignatureVerifyRequest {
            uid: pub_uid,
            data: message,
            signature: sig.signature,
            cryptographic_parameters: None,
        },
        "k9-verify",
    )
    .expect("SignatureVerify with registered ML-DSA-65 public key");
    assert_eq!(verified.validity, SignatureValidity::Valid);

    let _ = softhsmrustv3::native::session::finalize();
}

/// Registered ML-KEM-768 keypair → KMIP Encrypt (encapsulate) with the
/// registered public → Decrypt (decapsulate) with the registered
/// private → identical 32-byte shared secret.
#[test]
fn k9_register_ml_kem_768_encap_decap_roundtrip() {
    use ml_kem::{EncodedSizeUser, KemCore};
    use pqctoday_kmip::kmip30::{DecryptRequest, EncryptRequest, KeyFormatType};
    use pqctoday_kmip::ops::decrypt::decrypt;
    use pqctoday_kmip::ops::encrypt::encrypt;

    let _guard = engine_test_lock();
    let deps = build_deps_with_real_engine();

    let (dk, ek) = ml_kem::MlKem768::generate(&mut rand::rngs::OsRng);
    let dk_bytes = dk.as_bytes().as_slice().to_vec();
    let ek_bytes = ek.as_bytes().as_slice().to_vec();

    let priv_uid = register_pqc(
        &deps,
        ObjectType::PrivateKey,
        KmipAlgorithm::MlKem768,
        KeyFormatType::Raw,
        dk_bytes,
        UsageMask::DECRYPT,
    )
    .expect("Register ML-KEM-768 private");
    let pub_uid = register_pqc(
        &deps,
        ObjectType::PublicKey,
        KmipAlgorithm::MlKem768,
        KeyFormatType::Raw,
        ek_bytes,
        UsageMask::ENCRYPT,
    )
    .expect("Register ML-KEM-768 public");

    let enc = encrypt(
        &deps,
        EncryptRequest {
            uid: pub_uid,
            data: Vec::new(),
            iv: None,
            cryptographic_parameters: None,
            aad: None,
            init_indicator: None,
            final_indicator: None,
            correlation_value: None,
        },
        "k9-encap",
    )
    .expect("Encrypt(encapsulate) with registered ML-KEM-768 public key");
    assert_eq!(enc.ciphertext.len(), 1088, "FIPS 203 §7 ML-KEM-768 ciphertext");
    let ss_enc = enc.shared_secret.expect("encap returns shared secret");
    assert_eq!(ss_enc.len(), 32);

    let dec = decrypt(
        &deps,
        DecryptRequest {
            uid: priv_uid,
            data: enc.ciphertext,
            iv: None,
            cryptographic_parameters: None,
            aad: None,
        },
        "k9-decap",
    )
    .expect("Decrypt(decapsulate) with registered ML-KEM-768 private key");
    assert_eq!(dec.data, ss_enc, "decap must recover the encap shared secret");

    let _ = softhsmrustv3::native::session::finalize();
}

/// Registered SLH-DSA-SHAKE-128F keypair → Sign → SignatureVerify →
/// Success + Valid (signature is 17088 bytes per FIPS 205 §11).
#[test]
fn k9_register_slh_dsa_shake_128f_sign_verify_roundtrip() {
    use fips205::traits::SerDes;
    use pqctoday_kmip::kmip30::KeyFormatType;

    let _guard = engine_test_lock();
    let deps = build_deps_with_real_engine();

    let (vk, sk) = fips205::slh_dsa_shake_128f::try_keygen_with_rng(&mut rand::rngs::OsRng)
        .expect("FIPS 205 keygen");
    let sk_bytes = sk.into_bytes().to_vec();
    let pk_bytes = vk.into_bytes().to_vec();

    let priv_uid = register_pqc(
        &deps,
        ObjectType::PrivateKey,
        KmipAlgorithm::SlhDsaShake128f,
        KeyFormatType::Raw,
        sk_bytes,
        UsageMask::SIGN,
    )
    .expect("Register SLH-DSA-SHAKE-128F private");
    let pub_uid = register_pqc(
        &deps,
        ObjectType::PublicKey,
        KmipAlgorithm::SlhDsaShake128f,
        KeyFormatType::Raw,
        pk_bytes,
        UsageMask::VERIFY,
    )
    .expect("Register SLH-DSA-SHAKE-128F public");

    let message = b"K9: SLH-DSA register import".to_vec();
    let sig = sign(
        &deps,
        SignRequest {
            uid: priv_uid,
            data: message.clone(),
            cryptographic_parameters: None,
        },
        "k9-slh-sign",
    )
    .expect("Sign with registered SLH-DSA private key");
    assert_eq!(sig.signature.len(), 17088, "FIPS 205 §11 SLH-DSA-128f signature");

    let verified = signature_verify(
        &deps,
        SignatureVerifyRequest {
            uid: pub_uid,
            data: message,
            signature: sig.signature,
            cryptographic_parameters: None,
        },
        "k9-slh-verify",
    )
    .expect("SignatureVerify with registered SLH-DSA public key");
    assert_eq!(verified.validity, SignatureValidity::Valid);

    let _ = softhsmrustv3::native::session::finalize();
}

/// Wrong-length PQC material → the engine rejects with
/// `CKR_ATTRIBUTE_VALUE_INVALID` → Register fails with
/// `InvalidAttributeValue`; nothing lands in the KMIP store.
#[test]
fn k9_register_pqc_wrong_length_fails_invalid_attribute_value() {
    use pqctoday_kmip::error::ResultReason;
    use pqctoday_kmip::kmip30::KeyFormatType;

    let _guard = engine_test_lock();
    let deps = build_deps_with_real_engine();

    // 100 bytes is not a valid ML-DSA-65 sk length (2560).
    let err = register_pqc(
        &deps,
        ObjectType::PrivateKey,
        KmipAlgorithm::MlDsa65,
        KeyFormatType::Raw,
        vec![0u8; 100],
        UsageMask::SIGN,
    )
    .expect_err("wrong-length material must fail Register");
    assert_eq!(err.result_reason(), ResultReason::InvalidAttributeValue);
    assert!(
        deps.store.find(&|_| true).unwrap().is_empty(),
        "failed Register must not leave a store record"
    );

    let _ = softhsmrustv3::native::session::finalize();
}

/// A declared CryptographicLength that contradicts the supplied raw
/// material fails Register with `InvalidAttributeValue` before the
/// engine import is attempted.
#[test]
fn k9_register_pqc_length_mismatch_fails_invalid_attribute_value() {
    use pqctoday_kmip::error::ResultReason;
    use pqctoday_kmip::kmip30::{KeyBlock, KeyFormatType, RegisterRequest};
    use pqctoday_kmip::ops::register_import_export::register;

    let _guard = engine_test_lock();
    let deps = build_deps_with_real_engine();

    let err = register(
        &deps,
        RegisterRequest {
            object_type: ObjectType::PrivateKey,
            attributes: vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::MlDsa65),
                // Declared 65 bits ≠ 2560 bytes of material.
                Attribute::CryptographicLength(65),
                Attribute::CryptographicUsageMask(UsageMask::SIGN),
            ],
            managed_object: Some(KeyBlock {
                key_format_type: KeyFormatType::Raw,
                cryptographic_algorithm: KmipAlgorithm::MlDsa65,
                cryptographic_length: 65,
                key_value: vec![0u8; 2560],
                key_wrapping_data: None,
            }),
            protection_storage_masks: None,
            certificate_payload: None,
        },
        "k9-len-mismatch",
    )
    .expect_err("declared-length mismatch must fail Register");
    assert_eq!(err.result_reason(), ResultReason::InvalidAttributeValue);

    let _ = softhsmrustv3::native::session::finalize();
}

/// PQC Register in a KeyFormatType the engine import can't use (PKCS#8)
/// with an engine session wired → Register fails with `Key Format Type
/// Not Supported (0x10)` instead of succeeding unusably (B-6: no
/// succeed-then-fail-at-first-use).
#[test]
fn k9_register_pqc_pkcs8_format_fails_0x10() {
    use pqctoday_kmip::error::ResultReason;
    use pqctoday_kmip::kmip30::KeyFormatType;

    let _guard = engine_test_lock();
    let deps = build_deps_with_real_engine();

    let err = register_pqc(
        &deps,
        ObjectType::PrivateKey,
        KmipAlgorithm::MlDsa65,
        KeyFormatType::Pkcs8,
        vec![0u8; 2560],
        UsageMask::SIGN,
    )
    .expect_err("PKCS#8 PQC Register with engine session must fail");
    assert_eq!(err.result_reason(), ResultReason::KeyFormatTypeNotSupported);
    assert!(
        deps.store.find(&|_| true).unwrap().is_empty(),
        "failed Register must not leave a store record"
    );

    let _ = softhsmrustv3::native::session::finalize();
}

/// K11 / K-14 — Digest truthfulness against the real engine.
///
/// - CreateKeyPair persists a real 32-byte SHA-256 digest on BOTH
///   halves, including the non-extractable private key (computed
///   inside the engine boundary via `native::get_value_digest_sha256`
///   — the material never leaves the engine, only its hash).
/// - Create (AES) persists a digest that matches SHA-256 of the
///   engine-held `CKA_VALUE` bytes (AES keys are extractable, so the
///   cross-check can read the material directly).
/// - GetAttributes surfaces the Digest attribute carrying the
///   persisted value.
#[test]
fn k11_digest_persisted_from_real_engine_material() {
    use pqctoday_kmip::kmip30::{CreateRequest, GetAttributesRequest};
    use pqctoday_kmip::ops::create::create;
    use pqctoday_kmip::ops::get_attributes::get_attributes;
    use sha2::{Digest as _, Sha256};

    let _guard = engine_test_lock();
    let deps = build_deps_with_real_engine();

    // ── CreateKeyPair: digest present on both halves ─────────────────────
    let kp = create_key_pair(
        &deps,
        CreateKeyPairRequest {
            common_attributes: vec![Attribute::CryptographicAlgorithm(KmipAlgorithm::MlDsa65)],
            private_key_attributes: vec![Attribute::CryptographicUsageMask(UsageMask::SIGN)],
            public_key_attributes: vec![Attribute::CryptographicUsageMask(UsageMask::VERIFY)],
        seed: None,
        },
        "CreateKeyPair:Sign",
        "k11-kp",
    )
    .unwrap();
    let priv_rec = deps.store.get(&kp.private_key_uid).unwrap().unwrap();
    let pub_rec = deps.store.get(&kp.public_key_uid).unwrap().unwrap();
    let priv_digest = priv_rec.digest_value.expect("private half digest persisted");
    let pub_digest = pub_rec.digest_value.expect("public half digest persisted");
    assert_eq!(priv_digest.len(), 32);
    assert_eq!(pub_digest.len(), 32);
    assert_ne!(priv_digest, pub_digest, "halves digest different material");

    // GetAttributes surfaces the persisted private-half digest (the
    // AKLC corpus reads Digest back on the PrivateKey object).
    let r = get_attributes(
        &deps,
        GetAttributesRequest {
            uid: kp.private_key_uid.clone(),
            attribute_references: vec!["Digest".into()],
        },
        "k11-ga",
    )
    .unwrap();
    match &r.attributes[..] {
        [Attribute::Digest(dg)] => assert_eq!(dg.digest_value, priv_digest),
        other => panic!("expected exactly Digest, got {other:?}"),
    }

    // ── Create (AES): digest == SHA-256 of the engine CKA_VALUE ─────────
    let c = create(
        &deps,
        CreateRequest {
            object_type: ObjectType::SymmetricKey,
            template_attribute: vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes),
                Attribute::CryptographicLength(256),
                Attribute::CryptographicUsageMask(UsageMask::ENCRYPT | UsageMask::DECRYPT),
            ],
        },
        "k11-create",
    )
    .unwrap();
    let aes_rec = deps.store.get(&c.uid).unwrap().unwrap();
    let aes_digest = aes_rec.digest_value.expect("AES digest persisted");
    let session = deps.engine_session.unwrap();
    let handle = softhsmrustv3::native::find_by_cka_id(session, &aes_rec.pkcs11_cka_id)
        .unwrap()
        .expect("engine handle");
    let value = softhsmrustv3::native::get_attribute(
        session,
        handle,
        softhsmrustv3::constants::CKA_VALUE,
    )
    .expect("AES keys are extractable");
    assert_eq!(aes_digest, Sha256::digest(&value).to_vec());

    let _ = softhsmrustv3::native::session::finalize();
}

// ── K15 — audit-log honesty against the real engine ─────────────────────────

/// Pull all Plane-3 `Pkcs11Call` records `(function, rv, rv_name)` for a
/// correlation id.
fn p3_calls(ring: &RingSink, correlation_id: &str) -> Vec<(String, u32, String)> {
    use pqctoday_kmip::auditlog::{EventPayload, Plane};
    ring.filter_correlation_id(correlation_id)
        .into_iter()
        .filter(|e| e.plane == Plane::Pkcs11)
        .filter_map(|e| match e.event {
            EventPayload::Pkcs11Call { function, rv, rv_name, .. } => {
                Some((function, rv, rv_name))
            }
            _ => None,
        })
        .collect()
}

/// K15 — a SUCCESSFUL engine op logs the actual native entry point and
/// CKR_OK after the fact; a FAILED engine op logs the same entry point
/// with the real non-zero CK_RV (the pre-K15 code logged `rv=0 CKR_OK`
/// before the call, success or not).
#[test]
fn k15_audit_records_real_rv_and_native_entry_point() {
    use pqctoday_kmip::kmip30::{ActivateRequest, CreateRequest};
    use pqctoday_kmip::ops::activate::activate;
    use pqctoday_kmip::ops::create::create;

    let _guard = engine_test_lock();
    let (ring, deps) = build_deps_with_real_engine_and_ring();

    // ── Success: engine-generated AES key, audited after the call ───────
    let c = create(
        &deps,
        CreateRequest {
            object_type: ObjectType::SymmetricKey,
            template_attribute: vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes),
                Attribute::CryptographicLength(256),
                Attribute::CryptographicUsageMask(UsageMask::ENCRYPT),
            ],
        },
        "k15-create-ok",
    )
    .unwrap();
    let calls = p3_calls(&ring, "k15-create-ok");
    assert_eq!(
        calls,
        vec![("native::generate_aes_key".to_string(), 0, "CKR_OK".to_string())],
        "successful engine generate must be audited with the real entry point + CKR_OK"
    );

    // ── Failure: drive native::sign into a real engine error ────────────
    // Relabel the engine-resident AES record as ML-DSA-65 (object_type
    // stays SymmetricKey so the handle lookup still resolves the
    // CKO_SECRET_KEY object). Sign then dispatches CKM_ML_DSA against a
    // 32-byte secret-key handle — the engine rejects it, and the audit
    // must carry that non-zero CK_RV.
    let mut rec = deps.store.get(&c.uid).unwrap().unwrap();
    rec.algorithm = KmipAlgorithm::MlDsa65;
    rec.usage_mask = UsageMask::SIGN;
    deps.store.update(rec).unwrap();
    activate(&deps, ActivateRequest { uid: c.uid.clone() }, "k15-activate").unwrap();
    sign(
        &deps,
        SignRequest {
            uid: c.uid.clone(),
            data: b"k15".to_vec(),
            cryptographic_parameters: None,
        },
        "k15-sign-fail",
    )
    .expect_err("CKM_ML_DSA over an AES secret key must fail in the engine");
    let calls = p3_calls(&ring, "k15-sign-fail");
    assert_eq!(calls.len(), 1, "exactly one Pkcs11Call for the failed sign");
    let (function, rv, rv_name) = &calls[0];
    assert_eq!(function, "native::sign");
    assert_ne!(*rv, 0, "failed engine call must NOT be logged as CKR_OK");
    assert_ne!(rv_name, "CKR_OK");

    let _ = softhsmrustv3::native::session::finalize();
}

/// K15 (B-9) — an engine-resident HMAC key (Create'd inside the engine,
/// no `key_material` in the KMIP store) MACs through `native::sign` and
/// verifies through `native::verify` with `CKM_SHA256_HMAC`; the audit
/// names the engine path, and the MAC matches an independent in-process
/// HMAC over the engine-held key bytes.
#[test]
fn k15_hmac_mac_and_verify_route_through_engine() {
    use hmac::{Hmac, Mac as _};
    use pqctoday_kmip::kmip30::{
        ActivateRequest, CreateRequest, MacRequest, MacVerifyRequest, SignatureValidity,
    };
    use pqctoday_kmip::ops::activate::activate;
    use pqctoday_kmip::ops::create::create;
    use pqctoday_kmip::ops::mac_and_hash::{mac, mac_verify};
    use sha2::Sha256;

    let _guard = engine_test_lock();
    let (ring, deps) = build_deps_with_real_engine_and_ring();

    let c = create(
        &deps,
        CreateRequest {
            object_type: ObjectType::SymmetricKey,
            template_attribute: vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::HmacSha256),
                Attribute::CryptographicLength(256),
                Attribute::CryptographicUsageMask(
                    UsageMask::MAC_GENERATE | UsageMask::MAC_VERIFY,
                ),
            ],
        },
        "k15-hmac-create",
    )
    .unwrap();
    let rec = deps.store.get(&c.uid).unwrap().unwrap();
    assert!(rec.key_material.is_none(), "engine-resident key: no store material");
    activate(&deps, ActivateRequest { uid: c.uid.clone() }, "k15-hmac-activate").unwrap();

    // ── MAC via the engine ───────────────────────────────────────────────
    let data = b"K15: engine-resident HMAC".to_vec();
    let m = mac(
        &deps,
        MacRequest {
            uid: c.uid.clone(),
            cryptographic_parameters: None,
            data: data.clone(),
        },
        "k15-hmac-mac",
    )
    .unwrap();
    assert_eq!(m.mac_data.len(), 32, "HMAC-SHA-256 output");
    let calls = p3_calls(&ring, "k15-hmac-mac");
    assert_eq!(
        calls,
        vec![("native::sign".to_string(), 0, "CKR_OK".to_string())],
        "MAC over an engine-resident key must run through native::sign"
    );

    // Cross-check against an independent in-process HMAC over the
    // engine-held key bytes (generic secrets are extractable here).
    let session = deps.engine_session.unwrap();
    let handle = softhsmrustv3::native::find_by_cka_id(session, &rec.pkcs11_cka_id)
        .unwrap()
        .expect("engine handle");
    let key_bytes = softhsmrustv3::native::get_attribute(
        session,
        handle,
        softhsmrustv3::constants::CKA_VALUE,
    )
    .expect("generic secret CKA_VALUE");
    let mut h = <Hmac<Sha256> as hmac::Mac>::new_from_slice(&key_bytes).unwrap();
    h.update(&data);
    assert_eq!(
        m.mac_data,
        h.finalize().into_bytes().to_vec(),
        "engine HMAC must equal RFC 2104 HMAC over the engine-held key"
    );

    // ── MACVerify via the engine ─────────────────────────────────────────
    let v = mac_verify(
        &deps,
        MacVerifyRequest {
            uid: c.uid.clone(),
            cryptographic_parameters: None,
            data: data.clone(),
            mac_data: m.mac_data.clone(),
        },
        "k15-hmac-verify",
    )
    .unwrap();
    assert_eq!(v.validity, SignatureValidity::Valid);
    let calls = p3_calls(&ring, "k15-hmac-verify");
    assert_eq!(
        calls,
        vec![("native::verify".to_string(), 0, "CKR_OK".to_string())],
        "MACVerify over an engine-resident key must run through native::verify"
    );

    // Tampered MAC → Invalid via the engine path, still Success status.
    let mut bad = m.mac_data;
    bad[0] ^= 0xFF;
    let v = mac_verify(
        &deps,
        MacVerifyRequest {
            uid: c.uid,
            cryptographic_parameters: None,
            data,
            mac_data: bad,
        },
        "k15-hmac-verify-bad",
    )
    .unwrap();
    assert_eq!(v.validity, SignatureValidity::Invalid);

    let _ = softhsmrustv3::native::session::finalize();
}

/// K17 — Register accepts wrapped key material end-to-end: an HMAC key
/// Exported wrapped under an AES KEK (AES-KW over the TTLV KeyValue) is
/// Registered back with `KeyWrappingData` naming the KEK. The handler
/// unwraps, stores the cleartext, and feeds the existing engine-import
/// arm (`register_generic_secret_bytes`) — so a subsequent MAC op on
/// the re-registered key produces the same RFC 2104 HMAC as the
/// original material.
#[test]
fn k17_register_wrapped_hmac_key_then_mac_against_real_engine() {
    use hmac::{Hmac, Mac as _};
    use pqctoday_kmip::kmip30::{
        ActivateRequest, ExportRequest, KeyBlock, KeyFormatType, KeyWrappingSpec, MacRequest,
        RegisterRequest,
    };
    use pqctoday_kmip::ops::mac_and_hash::mac;
    use pqctoday_kmip::ops::register_import_export::{export, register};
    use sha2::Sha256;

    let _guard = engine_test_lock();
    let deps = build_deps_with_real_engine();

    let register_symmetric = |alg: KmipAlgorithm,
                              bits: u32,
                              usage: UsageMask,
                              kb: KeyBlock,
                              cid: &str|
     -> String {
        let uid = register(
            &deps,
            RegisterRequest {
                object_type: ObjectType::SymmetricKey,
                attributes: vec![
                    Attribute::CryptographicAlgorithm(alg),
                    Attribute::CryptographicLength(bits),
                    Attribute::CryptographicUsageMask(usage),
                ],
                managed_object: Some(kb),
                protection_storage_masks: None,
                certificate_payload: None,
            },
            cid,
        )
        .unwrap()
        .uid;
        activate(&deps, ActivateRequest { uid: uid.clone() }, cid).unwrap();
        uid
    };

    // KEK: AES-256, allowed to wrap AND unwrap.
    let kek_material = vec![0x6b; 32];
    let kek_uid = register_symmetric(
        KmipAlgorithm::Aes,
        256,
        UsageMask::WRAP_KEY | UsageMask::UNWRAP_KEY,
        KeyBlock {
            key_format_type: KeyFormatType::Raw,
            cryptographic_algorithm: KmipAlgorithm::Aes,
            cryptographic_length: 256,
            key_value: kek_material.clone(),
            key_wrapping_data: None,
        },
        "k17-kek",
    );

    // Original HMAC-SHA-256 key.
    let hmac_material = vec![0x37; 32];
    let hmac_uid = register_symmetric(
        KmipAlgorithm::HmacSha256,
        256,
        UsageMask::MAC_GENERATE,
        KeyBlock {
            key_format_type: KeyFormatType::Raw,
            cryptographic_algorithm: KmipAlgorithm::HmacSha256,
            cryptographic_length: 256,
            key_value: hmac_material.clone(),
            key_wrapping_data: None,
        },
        "k17-hmac-orig",
    );

    // Export the HMAC key wrapped under the KEK (existing K16 machinery).
    let kws = KeyWrappingSpec {
        wrapping_method: 0x01,
        encryption_key_uid: kek_uid,
        cryptographic_parameters: None,
        encoding_option: None,
        mac_signature_key_information_present: false,
    };
    let exp = export(
        &deps,
        ExportRequest {
            uid: hmac_uid,
            key_format_type: None,
            key_wrap_type: None,
            key_compression_type: None,
            key_wrapping_specification: Some(kws.clone()),
        },
        "k17-export-wrapped",
    )
    .unwrap();
    let wrapped_kb = exp.managed_object.expect("wrapped KeyBlock");
    assert!(wrapped_kb.key_wrapping_data.is_some());
    assert_ne!(wrapped_kb.key_value, hmac_material, "material left wrapped");

    // Register the wrapped KeyBlock back — KeyWrappingData names the KEK.
    let reimported_uid = register_symmetric(
        KmipAlgorithm::HmacSha256,
        256,
        UsageMask::MAC_GENERATE,
        KeyBlock {
            key_format_type: KeyFormatType::Raw,
            cryptographic_algorithm: KmipAlgorithm::HmacSha256,
            cryptographic_length: 256,
            key_value: wrapped_kb.key_value,
            key_wrapping_data: Some(kws),
        },
        "k17-register-wrapped",
    );
    let rec = deps.store.get(&reimported_uid).unwrap().unwrap();
    assert_eq!(
        rec.key_material.as_deref(),
        Some(&hmac_material[..]),
        "unwrap-and-store: re-registered material equals the original"
    );

    // Crypto op on the re-registered key works (engine import path).
    let data = b"K17: wrapped Register round-trip".to_vec();
    let m = mac(
        &deps,
        MacRequest {
            uid: reimported_uid,
            cryptographic_parameters: None,
            data: data.clone(),
        },
        "k17-mac",
    )
    .unwrap();
    let mut h = <Hmac<Sha256> as hmac::Mac>::new_from_slice(&hmac_material).unwrap();
    h.update(&data);
    assert_eq!(
        m.mac_data,
        h.finalize().into_bytes().to_vec(),
        "MAC over the re-registered key must equal HMAC over the original material"
    );

    let _ = softhsmrustv3::native::session::finalize();
}

// ── KMIP 3.0 WD19 Encapsulate / Decapsulate (first-class KEM ops) ───────────
//
// These prove the new `Encapsulate` (0x41) / `Decapsulate` (0x42) op
// handlers against the real softhsmrustv3 engine. Unlike the
// Encrypt/Decrypt overload, the new ops create a NEW managed SecretData
// object holding the shared secret and return its UID; a subsequent Get
// retrieves the 32-byte secret. The proof is byte-exact:
//
//   * deterministic encapsulation with fixed coins `m` is reproducible —
//     two Encapsulate calls with the same `m` yield identical ciphertext
//     AND identical shared secret;
//   * Decapsulate(ciphertext) recovers exactly the encapsulated shared
//     secret (KEM correctness, byte-for-byte);
//   * Get(returned UID) returns exactly that 32-byte shared secret.
//
// `pqctoday_kmip`'s `ml-kem` dependency does not enable the
// `deterministic` feature, so the test cannot recompute the expected
// vector in-process; instead it pins byte-exactness via the engine's own
// determinism + KEM correctness (the engine's deterministic encaps is
// itself ACVP/KAT byte-verified — see rust/src/native/encrypt.rs).

/// Register an ML-KEM-768 keypair (raw FIPS 203 bytes generated in-test)
/// and return `(private_uid, public_uid)`.
fn register_ml_kem_768_pair(deps: &Deps) -> (String, String) {
    use ml_kem::{EncodedSizeUser, KemCore};
    use pqctoday_kmip::kmip30::KeyFormatType;

    let (dk, ek) = ml_kem::MlKem768::generate(&mut rand::rngs::OsRng);
    let dk_bytes = dk.as_bytes().as_slice().to_vec();
    let ek_bytes = ek.as_bytes().as_slice().to_vec();

    let priv_uid = register_pqc(
        deps,
        ObjectType::PrivateKey,
        KmipAlgorithm::MlKem768,
        KeyFormatType::Raw,
        dk_bytes,
        UsageMask::DECRYPT,
    )
    .expect("Register ML-KEM-768 private");
    let pub_uid = register_pqc(
        deps,
        ObjectType::PublicKey,
        KmipAlgorithm::MlKem768,
        KeyFormatType::Raw,
        ek_bytes,
        UsageMask::ENCRYPT,
    )
    .expect("Register ML-KEM-768 public");
    (priv_uid, pub_uid)
}

/// Get a SecretData object's KeyMaterial (the shared secret bytes).
fn get_shared_secret(deps: &Deps, uid: &str) -> Vec<u8> {
    use pqctoday_kmip::kmip30::GetRequest;
    use pqctoday_kmip::ops::get::get;
    let r = get(
        deps,
        GetRequest { uid: uid.to_string(), key_format_type: None, key_wrapping_specification: None },
        "kem-get-ss",
    )
    .expect("Get shared-secret object");
    r.key_block.key_value
}

/// WD19 Encapsulate → Get(UID)==shared secret, and the deterministic
/// ciphertext is reproducible byte-for-byte across two calls with the
/// same coins. Then Decapsulate(ciphertext) → Get(UID) recovers exactly
/// that shared secret. All byte-exact.
#[test]
fn wd19_encapsulate_decapsulate_byte_exact_against_real_engine() {
    use pqctoday_kmip::kmip30::{DecapsulateRequest, EncapsulateRequest};
    use pqctoday_kmip::ops::decapsulate::decapsulate;
    use pqctoday_kmip::ops::encapsulate::encapsulate;

    let _guard = engine_test_lock();
    let deps = build_deps_with_real_engine();

    let (priv_uid, pub_uid) = register_ml_kem_768_pair(&deps);

    // FIPS 203 §7.2 deterministic coins `m` (exactly 32 bytes).
    let coins: Vec<u8> = (0u8..32).collect();

    // ── Encapsulate (deterministic) ─────────────────────────────────────
    let enc1 = encapsulate(
        &deps,
        EncapsulateRequest {
            uid: pub_uid.clone(),
            input_key_material: Some(coins.clone()),
            cryptographic_parameters: None,
        },
        "wd19-encap-1",
    )
    .expect("Encapsulate with ML-KEM-768 public key");
    assert_eq!(enc1.data.len(), 1088, "FIPS 203 §7 ML-KEM-768 ciphertext is 1088 bytes");
    assert_ne!(enc1.uid, pub_uid, "Encapsulate returns a NEW managed object UID");

    let ss1 = get_shared_secret(&deps, &enc1.uid);
    assert_eq!(ss1.len(), 32, "ML-KEM shared secret is 32 bytes");

    // ── Determinism: same coins → byte-identical ciphertext + secret ────
    let enc2 = encapsulate(
        &deps,
        EncapsulateRequest {
            uid: pub_uid.clone(),
            input_key_material: Some(coins.clone()),
            cryptographic_parameters: None,
        },
        "wd19-encap-2",
    )
    .expect("second deterministic Encapsulate");
    assert_eq!(
        enc1.data, enc2.data,
        "deterministic encapsulation: same coins MUST yield byte-identical ciphertext"
    );
    let ss2 = get_shared_secret(&deps, &enc2.uid);
    assert_eq!(ss1, ss2, "deterministic encapsulation: same coins MUST yield the same secret");

    // ── Decapsulate(ciphertext) → recovers exactly the encap secret ─────
    let dec = decapsulate(
        &deps,
        DecapsulateRequest {
            uid: priv_uid.clone(),
            data: enc1.data.clone(),
            cryptographic_parameters: None,
        },
        "wd19-decap",
    )
    .expect("Decapsulate with ML-KEM-768 private key");
    assert_ne!(dec.uid, priv_uid, "Decapsulate returns a NEW managed object UID");
    let ss_dec = get_shared_secret(&deps, &dec.uid);
    assert_eq!(
        ss_dec, ss1,
        "Decapsulate MUST recover the exact shared secret the Encapsulate produced (byte-exact)"
    );

    // Different coins → different ciphertext + secret (sanity).
    let enc3 = encapsulate(
        &deps,
        EncapsulateRequest {
            uid: pub_uid,
            input_key_material: Some(vec![0xAB; 32]),
            cryptographic_parameters: None,
        },
        "wd19-encap-3",
    )
    .unwrap();
    assert_ne!(enc3.data, enc1.data, "different coins MUST yield a different ciphertext");
    assert_ne!(get_shared_secret(&deps, &enc3.uid), ss1, "different coins → different secret");

    let _ = softhsmrustv3::native::session::finalize();
}

/// WD19 byte-exact proof against the published OASIS KMIP 3.0 PQC interop
/// vectors when `INTEROP_KAT_DIR` (or the default
/// `/tmp/kmip-pqc/kmip-3-0-pqc-tests`) is present. SKIPS cleanly when the
/// transcript directory is absent (like `tests/interop_kat.rs`).
#[test]
fn wd19_encapsulate_matches_oasis_transcript_vectors() {
    use std::path::PathBuf;

    fn interop_dir() -> Option<PathBuf> {
        let p = PathBuf::from(
            std::env::var("INTEROP_KAT_DIR")
                .unwrap_or_else(|_| "/tmp/kmip-pqc/kmip-3-0-pqc-tests".to_string()),
        );
        if p.is_dir() {
            Some(p)
        } else {
            None
        }
    }

    let dir = match interop_dir() {
        Some(d) => d,
        None => {
            eprintln!(
                "[WD19] INTEROP_KAT_DIR absent — skipping OASIS transcript byte-exact proof; \
                 in-engine determinism + KEM-correctness byte-exactness is covered by \
                 wd19_encapsulate_decapsulate_byte_exact_against_real_engine"
            );
            return;
        }
    };

    // Hex-decode helper for the transcript ByteString fields.
    fn hexd(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // Pull all `<TagName ... value="...">` occurrences for an element. The
    // OASIS XML uses the tag NAME as the element name (not a name="" attr).
    fn values(xml: &str, tag: &str) -> Vec<String> {
        let needle = format!("<{tag} ");
        let mut out = Vec::new();
        for seg in xml.split(&needle).skip(1) {
            // Stay within this element: only look before the next '>'.
            let elem = seg.split('>').next().unwrap_or(seg);
            if let Some(vi) = elem.find("value=\"") {
                let rest = &elem[vi + 7..];
                if let Some(end) = rest.find('"') {
                    out.push(rest[..end].to_string());
                }
            }
        }
        out
    }

    let stem = "ML-KEM-512-encapsulation-1-30.xml";
    let path = dir.join(stem);
    let xml = match std::fs::read_to_string(&path) {
        Ok(x) => x,
        Err(_) => {
            eprintln!("[WD19] {stem} not found in transcript dir — skipping");
            return;
        }
    };

    let _guard = engine_test_lock();
    let deps = build_deps_with_real_engine();

    // Encapsulation key (the public key the transcript Registers/uses),
    // the input coins, the expected ciphertext, and the expected shared
    // secret. Tag names follow the WD19 XML transcript vocabulary.
    // ML-KEM-512: ek = 800 B (the encapsulation key — NOT the 1632-B dk the
    // transcript also Registers), coins = 32 B, ct = 768 B.
    let ek = values(&xml, "KeyMaterial")
        .into_iter()
        .map(|s| hexd(&s))
        .find(|b| b.len() == 800);
    let coins = values(&xml, "InputKeyMaterial")
        .into_iter()
        .map(|s| hexd(&s))
        .find(|b| b.len() == 32);
    let expect_ct = values(&xml, "Data")
        .into_iter()
        .map(|s| hexd(&s))
        .find(|b| b.len() == 768);
    // The 32-byte KeyMaterial in the transcript is the expected shared secret
    // (returned by the follow-up Get on the encapsulated-secret object).
    let expect_ss = values(&xml, "KeyMaterial")
        .into_iter()
        .map(|s| hexd(&s))
        .find(|b| b.len() == 32);

    let (ek, coins, expect_ct) = match (ek, coins, expect_ct) {
        (Some(a), Some(b), Some(c)) => (a, b, c),
        _ => {
            eprintln!("[WD19] transcript {stem} missing PublicKey/InputKeyMaterial/Data — skipping");
            return;
        }
    };

    let pub_uid = register_pqc(
        &deps,
        ObjectType::PublicKey,
        KmipAlgorithm::MlKem512,
        pqctoday_kmip::kmip30::KeyFormatType::Raw,
        ek,
        UsageMask::ENCRYPT,
    )
    .expect("Register transcript ML-KEM-512 public key");

    let enc = pqctoday_kmip::ops::encapsulate::encapsulate(
        &deps,
        pqctoday_kmip::kmip30::EncapsulateRequest {
            uid: pub_uid,
            input_key_material: Some(coins),
            cryptographic_parameters: None,
        },
        "wd19-transcript-encap",
    )
    .expect("transcript Encapsulate");
    assert_eq!(enc.data, expect_ct, "ciphertext MUST byte-match the OASIS transcript");

    // The Encapsulate response UID points at a NEW shared-secret object; its
    // stored material MUST byte-match the transcript's expected shared secret
    // (what the transcript's follow-up Get returns).
    if let Some(expect_ss) = expect_ss {
        let rec = deps.store.get(&enc.uid).unwrap().unwrap();
        assert_eq!(
            rec.key_material.as_deref(),
            Some(&expect_ss[..]),
            "shared secret MUST byte-match the OASIS transcript"
        );
        eprintln!("[WD19] {stem}: Encapsulate ct + shared secret byte-exact vs OASIS transcript");
    }

    let _ = softhsmrustv3::native::session::finalize();
}

// Suppress unused-import warning when only some types are referenced in
// the active test set.
#[allow(dead_code)]
fn _unused() {
    let _: HashMap<String, String> = HashMap::new();
    let _: OffsetDateTime = OffsetDateTime::UNIX_EPOCH;
    let _: ObjectType = ObjectType::PrivateKey;
}

/// K21 — Re-key (§6.1.51) against the real engine: Create an AES-256
/// key in-engine, Activate it, Re-key it, then prove the REPLACEMENT
/// key encrypts/decrypts through the engine path (fresh engine-held
/// material under a fresh CKA_ID) while the original is Deactivated
/// with the §6.1.51 link pair in place.
#[test]
fn k21_rekeyed_aes_key_encrypts_against_real_engine() {
    use pqctoday_kmip::kmip30::{
        ActivateRequest, CreateRequest, DecryptRequest, EncryptRequest, ReKeyRequest, State,
    };
    use pqctoday_kmip::ops::activate::activate;
    use pqctoday_kmip::ops::create::create;
    use pqctoday_kmip::ops::decrypt::decrypt;
    use pqctoday_kmip::ops::encrypt::encrypt;
    use pqctoday_kmip::ops::rekey::rekey;

    let _guard = engine_test_lock();
    let (ring, deps) = build_deps_with_real_engine_and_ring();

    let c = create(
        &deps,
        CreateRequest {
            object_type: ObjectType::SymmetricKey,
            template_attribute: vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes),
                Attribute::CryptographicLength(256),
                Attribute::CryptographicUsageMask(UsageMask::ENCRYPT | UsageMask::DECRYPT),
            ],
        },
        "k21-create",
    )
    .unwrap();
    activate(&deps, ActivateRequest { uid: c.uid.clone() }, "k21-activate").unwrap();

    // ── Re-key: replacement generated through the same engine path ──
    let r = rekey(
        &deps,
        ReKeyRequest { uid: c.uid.clone(), offset: None, template_attribute: vec![] },
        "k21-rekey",
    )
    .unwrap();
    assert_ne!(r.uid, c.uid);
    let calls = p3_calls(&ring, "k21-rekey");
    assert_eq!(
        calls,
        vec![("native::generate_aes_key".to_string(), 0, "CKR_OK".to_string())],
        "Re-key must generate the replacement inside the engine (Create path)"
    );

    let new_rec = deps.store.get(&r.uid).unwrap().unwrap();
    let old_rec = deps.store.get(&c.uid).unwrap().unwrap();
    // Inheritance + lifecycle + links (Table 404 / §6.1.51).
    assert_eq!(new_rec.algorithm, KmipAlgorithm::Aes);
    assert_eq!(new_rec.cryptographic_length, 256);
    assert_eq!(new_rec.state, State::Active, "AT copied from the Active original");
    assert_ne!(new_rec.pkcs11_cka_id, old_rec.pkcs11_cka_id, "fresh engine object");
    assert_eq!(
        new_rec.links.get("ReplacedObjectLink"),
        Some(&c.uid),
        "Replaced Object Link on the replacement"
    );
    assert_eq!(
        old_rec.links.get("ReplacementObjectLink"),
        Some(&r.uid),
        "Replacement Object Link on the original"
    );
    assert_eq!(old_rec.state, State::Deactivated, "original retires when replacement activates");
    // K-14 Digest recomputed from the replacement's engine-held value.
    assert!(new_rec.digest_value.is_some());
    assert_ne!(new_rec.digest_value, old_rec.digest_value);

    // ── The replacement key encrypts + decrypts via the engine ──────
    let iv = vec![0x24u8; 12]; // AES-GCM default mechanism, 12-byte IV
    let plaintext = b"K21: re-keyed AES must encrypt".to_vec();
    let enc = encrypt(
        &deps,
        EncryptRequest {
            uid: r.uid.clone(),
            data: plaintext.clone(),
            iv: Some(iv.clone()),
            cryptographic_parameters: None,
            aad: None,
            init_indicator: None,
            final_indicator: None,
            correlation_value: None,
        },
        "k21-encrypt",
    )
    .expect("re-keyed AES key must encrypt through the engine");
    assert_ne!(enc.ciphertext, plaintext);

    let mut ct_and_tag = enc.ciphertext.clone();
    if let Some(tag) = &enc.authenticated_encryption_tag {
        ct_and_tag.extend_from_slice(tag);
    }
    let dec = decrypt(
        &deps,
        DecryptRequest {
            uid: r.uid.clone(),
            data: ct_and_tag,
            iv: Some(iv),
            cryptographic_parameters: None,
            aad: None,
        },
        "k21-decrypt",
    )
    .expect("re-keyed AES key must decrypt its own ciphertext");
    assert_eq!(dec.data, plaintext);

    let _ = softhsmrustv3::native::session::finalize();
}

/// Phase 7b gap-tightening: RSA CryptographicLength flows from the
/// KMIP attribute into `generate_rsa_keypair(bits=...)`. Smaller modulus
/// (2048) chosen for test speed — same code path covers up to 4096.
#[test]
fn rsa_create_respects_cryptographic_length_attribute() {
    let _guard = engine_test_lock();
    let deps = build_deps_with_real_engine();

    let create_req = CreateKeyPairRequest {
        common_attributes: vec![
            Attribute::CryptographicAlgorithm(KmipAlgorithm::Rsa),
            Attribute::CryptographicLength(2048),
        ],
        private_key_attributes: vec![Attribute::CryptographicUsageMask(UsageMask::SIGN)],
        public_key_attributes: vec![Attribute::CryptographicUsageMask(UsageMask::VERIFY)],
    seed: None,
    };
    let kp = create_key_pair(&deps, create_req, "CreateKeyPair:Sign", "rsa-len").unwrap();
    let priv_rec = deps.store.get(&kp.private_key_uid).unwrap().unwrap();
    assert_eq!(priv_rec.cryptographic_length, 2048);

    let _ = softhsmrustv3::native::session::finalize();
}

/// Phase 7b gap-tightening: rejecting an unsupported RSA bit length
/// surfaces as `InvalidAttributeValue`, not a generic engine error.
#[test]
fn rsa_create_rejects_unsupported_length() {
    use pqctoday_kmip::error::ResultReason;
    let _guard = engine_test_lock();
    let deps = build_deps_with_real_engine();

    let create_req = CreateKeyPairRequest {
        common_attributes: vec![
            Attribute::CryptographicAlgorithm(KmipAlgorithm::Rsa),
            Attribute::CryptographicLength(1024),
        ],
        private_key_attributes: vec![Attribute::CryptographicUsageMask(UsageMask::SIGN)],
        public_key_attributes: vec![Attribute::CryptographicUsageMask(UsageMask::VERIFY)],
    seed: None,
    };
    let err = create_key_pair(&deps, create_req, "CreateKeyPair:Sign", "rsa-bad")
        .expect_err("RSA-1024 must be rejected");
    assert_eq!(err.result_reason(), ResultReason::InvalidAttributeValue);

    let _ = softhsmrustv3::native::session::finalize();
}

/// Phase 7b gap-tightening: ECDSA curve selection via
/// `CryptographicLength` (384 → P-384). Validates the new
/// length-to-curve mapping survives the round-trip from KMIP attribute
/// through the bridge.
#[test]
fn ecdsa_create_respects_cryptographic_length_attribute() {
    let _guard = engine_test_lock();
    let deps = build_deps_with_real_engine();

    let create_req = CreateKeyPairRequest {
        common_attributes: vec![
            Attribute::CryptographicAlgorithm(KmipAlgorithm::Ecdsa),
            Attribute::CryptographicLength(384),
        ],
        private_key_attributes: vec![Attribute::CryptographicUsageMask(UsageMask::SIGN)],
        public_key_attributes: vec![Attribute::CryptographicUsageMask(UsageMask::VERIFY)],
    seed: None,
    };
    let kp = create_key_pair(&deps, create_req, "CreateKeyPair:Sign", "ec-384").unwrap();
    let priv_rec = deps.store.get(&kp.private_key_uid).unwrap().unwrap();
    assert_eq!(priv_rec.cryptographic_length, 384);

    let _ = softhsmrustv3::native::session::finalize();
}

/// Phase 7b gap-tightening: Locate's PKCS#11 reconciliation drops
/// records whose engine handle is gone. Simulates the
/// persistent-SQLite + volatile-engine restart scenario by finalising
/// the engine after CreateKeyPair, then re-init'ing without a re-keygen
/// — the orphan UID must be filtered out of the Locate response.
#[test]
fn locate_drops_orphans_when_engine_handle_is_gone() {
    use pqctoday_kmip::kmip30::LocateRequest;
    use pqctoday_kmip::ops::locate::locate;
    use softhsmrustv3::native::session;

    let _guard = engine_test_lock();
    let mut deps = build_deps_with_real_engine();

    // Create one ML-DSA-65 keypair — store has 2 records, engine has 2 handles.
    let create_req = CreateKeyPairRequest {
        common_attributes: vec![Attribute::CryptographicAlgorithm(KmipAlgorithm::MlDsa65)],
        private_key_attributes: vec![Attribute::CryptographicUsageMask(UsageMask::SIGN)],
        public_key_attributes: vec![Attribute::CryptographicUsageMask(UsageMask::VERIFY)],
    seed: None,
    };
    let _ = create_key_pair(&deps, create_req, "CreateKeyPair:Sign", "loc-create").unwrap();

    // Sanity: locate finds both halves.
    let before = locate(
        &deps,
        LocateRequest {
            attributes: vec![Attribute::CryptographicAlgorithm(KmipAlgorithm::MlDsa65)],
            maximum_items: None,
            ..Default::default()
        },
        "loc-before",
    )
    .unwrap();
    assert_eq!(
        before.uids.len(),
        2,
        "both pub + priv records must surface when engine state is fresh"
    );

    // Wipe engine state but keep the KMIP store intact — the records
    // are now orphans pointing at dead handles. Re-init with a fresh
    // bootstrap so we have a *valid* session for the reconciliation
    // probe to run against (and find nothing).
    let _ = session::finalize();
    session::init().unwrap();
    let fresh = session::bootstrap_default_token(0, "so-pin", "user-pin", "phase7b-orphan-reinit")
        .unwrap();
    deps = Deps::new(
        Engine::permissive(),
        deps.store.clone(),
        Arc::new(RingSink::new(64)),
        DepsConfig::default(),
    )
    .with_engine_session(fresh);

    let after = locate(
        &deps,
        LocateRequest {
            attributes: vec![Attribute::CryptographicAlgorithm(KmipAlgorithm::MlDsa65)],
            maximum_items: None,
            ..Default::default()
        },
        "loc-after",
    )
    .unwrap();
    assert!(
        after.uids.is_empty(),
        "orphan records must be filtered out when their PKCS#11 handle is gone (got {:?})",
        after.uids
    );

    let _ = session::finalize();
}
