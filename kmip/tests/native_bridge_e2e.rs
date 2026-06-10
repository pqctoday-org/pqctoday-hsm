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
    use softhsmrustv3::native::session;

    // Reset engine state for test isolation.
    let _ = session::finalize();
    session::init().expect("engine init");

    // Bootstrap a fresh token + open a user session.
    let engine_session = session::bootstrap_default_token(0, "so-pin", "user-pin", "phase7b-e2e")
        .expect("bootstrap real engine session");

    let ring = Arc::new(RingSink::new(64));
    let sink: Arc<dyn AuditSink> = ring;
    let policy_engine = Engine::with_global_sink(sink.clone());
    policy_engine
        .activate(load_from_str(PERMISSIVE_POLICY, std::path::Path::new("<e2e>")).unwrap())
        .unwrap();

    Deps::new(
        policy_engine,
        Arc::new(MemoryStore::new()),
        sink,
        DepsConfig::default(),
    )
    .with_engine_session(engine_session)
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

// Suppress unused-import warning when only some types are referenced in
// the active test set.
#[allow(dead_code)]
fn _unused() {
    let _: HashMap<String, String> = HashMap::new();
    let _: OffsetDateTime = OffsetDateTime::UNIX_EPOCH;
    let _: ObjectType = ObjectType::PrivateKey;
}
