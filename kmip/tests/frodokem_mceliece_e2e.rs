//! BSI TR-02102-1 §2.4.1/§2.4.2 — end-to-end FrodoKEM / Classic McEliece
//! through the KMIP op handlers.
//!
//! CreateKeyPair → Activate → Encapsulate(public) → Decapsulate(private) and
//! assert the encapsulator's and decapsulator's shared secrets match. This is
//! the step that actually makes the CACP Playground's Commands/Corpus
//! Replay/Batch tabs able to run these algorithms for real — the original
//! gap that started the FrodoKEM/Classic-McEliece/HQC implementation plan
//! this file is part of. Mirrors `hybrid_kem_e2e.rs`'s shape exactly.

use std::sync::Arc;

use pqctoday_kmip::auditlog::{AuditSink, RingSink};
use pqctoday_kmip::kmip30::{
    ActivateRequest, Attribute, CreateKeyPairRequest, DecapsulateRequest, EncapsulateRequest,
    GetRequest, KmipAlgorithm, UsageMask,
};
use pqctoday_kmip::ops::create_key_pair::create_key_pair;
use pqctoday_kmip::ops::decapsulate::decapsulate;
use pqctoday_kmip::ops::encapsulate::encapsulate;
use pqctoday_kmip::ops::get::get;
use pqctoday_kmip::ops::activate::activate;
use pqctoday_kmip::ops::{Deps, DepsConfig};
use pqctoday_kmip::policy::Engine;
use pqctoday_kmip::store::MemoryStore;

// The softhsmrustv3 engine is global (lazy_static Mutex state); serialize the
// per-test finalize/init so tests can't race (matches hybrid_kem_e2e.rs).
fn engine_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

fn deps() -> Deps {
    use softhsmrustv3::native::session;
    let _ = session::finalize();
    session::init().expect("engine init");
    let engine_session =
        session::bootstrap_default_token(0, "so-pin", "user-pin", "frodo-mceliece-e2e")
            .expect("bootstrap real engine session");
    let ring = Arc::new(RingSink::new(64));
    let sink: Arc<dyn AuditSink> = ring;
    Deps::new(Engine::permissive(), Arc::new(MemoryStore::new()), sink, DepsConfig::default())
        .with_engine_session(engine_session)
}

/// CreateKeyPair → Activate → Encapsulate → Decapsulate, asserting both
/// sides recover the identical shared secret, and that the private key
/// remains non-extractable (Get refused) — same shape as
/// `hybrid_kem_e2e.rs::round_trip`.
fn round_trip(alg: KmipAlgorithm, ss_len: usize) {
    let _g = engine_test_lock();
    let d = deps();

    let kp = create_key_pair(
        &d,
        CreateKeyPairRequest {
            common_attributes: vec![
                Attribute::CryptographicAlgorithm(alg),
                Attribute::CryptographicUsageMask(UsageMask::KEY_AGREEMENT),
            ],
            private_key_attributes: vec![],
            public_key_attributes: vec![],
            seed: None,
        },
        "CreateKeyPair:KeyAgreement",
        "ckp",
    )
    .unwrap_or_else(|e| panic!("{alg:?}: keygen failed: {e:?}"));

    for uid in [&kp.private_key_uid, &kp.public_key_uid] {
        activate(&d, ActivateRequest { uid: uid.clone() }, "act").expect("activate");
    }

    let enc = encapsulate(
        &d,
        EncapsulateRequest {
            uid: kp.public_key_uid.clone(),
            input_key_material: None,
            cryptographic_parameters: None,
        },
        "encap",
    )
    .unwrap_or_else(|e| panic!("{alg:?}: encapsulate failed: {e:?}"));
    assert!(!enc.data.is_empty(), "{alg:?}: ciphertext is non-empty");

    let dec = decapsulate(
        &d,
        DecapsulateRequest {
            uid: kp.private_key_uid.clone(),
            data: enc.data.clone(),
            cryptographic_parameters: None,
        },
        "decap",
    )
    .unwrap_or_else(|e| panic!("{alg:?}: decapsulate failed: {e:?}"));

    let ss_enc = d.store.get(&enc.uid).unwrap().unwrap().key_material.expect("encap SS material");
    let ss_dec = d.store.get(&dec.uid).unwrap().unwrap().key_material.expect("decap SS material");
    assert_eq!(
        ss_enc, ss_dec,
        "{alg:?}: encapsulator and decapsulator must derive the same shared secret"
    );
    assert_eq!(ss_enc.len(), ss_len, "{alg:?}: shared secret length");

    // Both halves are engine-native, non-extractable objects — Get must be
    // refused, same as every other PQC KEM in this crate.
    let got = get(
        &d,
        GetRequest {
            uid: kp.private_key_uid.clone(),
            key_format_type: None,
            key_wrapping_specification: None,
        },
        "get",
    );
    assert!(got.is_err(), "{alg:?}: Get on the private key must be refused (non-extractable)");
}

// ── FrodoKEM (BSI TR-02102-1 §2.4.1) — shared-secret lengths verified
// directly against `frodo-kem` v0.1.0's own `AlgorithmParams` ────────────

#[test]
fn frodokem_640_aes_round_trip() {
    round_trip(KmipAlgorithm::FrodoKem640Aes, 16);
}

#[test]
fn frodokem_640_shake_round_trip() {
    round_trip(KmipAlgorithm::FrodoKem640Shake, 16);
}

#[test]
fn frodokem_976_aes_round_trip() {
    round_trip(KmipAlgorithm::FrodoKem976Aes, 24);
}

#[test]
fn frodokem_976_shake_round_trip() {
    round_trip(KmipAlgorithm::FrodoKem976Shake, 24);
}

#[test]
fn frodokem_1344_aes_round_trip() {
    round_trip(KmipAlgorithm::FrodoKem1344Aes, 32);
}

#[test]
fn frodokem_1344_shake_round_trip() {
    round_trip(KmipAlgorithm::FrodoKem1344Shake, 32);
}

// ── Classic McEliece (BSI TR-02102-1 §2.4.2) — scoped to mceliece6688128
// only (implementation plan Phase 0.5). Keygen is slow in debug builds
// (Goppa code generation) — run with --release for a fast pass. ─────────

/// `#[ignore]`: a single mceliece6688128 keygen (Goppa code generation)
/// takes minutes in an unoptimized debug build — too slow for every CI
/// run. Run manually with `cargo test --release -- --ignored
/// classic_mceliece_6688128_round_trip` (release mode is fast).
#[test]
#[ignore = "mceliece6688128 keygen is minutes-slow in debug builds — see doc comment"]
fn classic_mceliece_6688128_round_trip() {
    round_trip(KmipAlgorithm::ClassicMcEliece6688128, 32);
}
