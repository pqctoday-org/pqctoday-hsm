//! Migration-tab estate test — `migration-classical.yaml`'s label-only
//! contract: the application passes NOTHING but a key label (plus the
//! dispatcher's usage-derived op suffix); every algorithm below is the
//! policy's decision via `name_pattern` defaults. This is the seven-key
//! classical estate the Hub Migration tab builds in section 1.

use std::collections::HashMap;
use std::path::PathBuf;
use time::OffsetDateTime;

use pqctoday_kmip::policy::{load_from_file, Engine, PolicyRequest};

fn engine() -> Engine {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("policies")
        .join("migration-classical.yaml");
    let loaded = load_from_file(&path).unwrap_or_else(|e| panic!("loading policy: {e}"));
    let eng = Engine::deny_all();
    eng.activate(loaded).expect("activation must succeed");
    eng
}

fn ts() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_780_000_000).unwrap() // 2026-05-29
}

/// (label, dispatcher-canonicalised op, algorithm the policy must choose)
const ESTATE: &[(&str, &str, &str)] = &[
    ("vault-archive-cipher", "Create", "AES-256"),
    ("payments-db-cipher", "Create", "AES-128"),
    ("partner-tls-kex", "CreateKeyPair:KeyAgreement", "X25519"),
    ("interbank-vpn-kex", "CreateKeyPair:KeyAgreement", "X448"),
    ("firmware-release-signing", "CreateKeyPair:Sign", "RSA-2048"),
    ("api-gateway-signing", "CreateKeyPair:Sign", "ECDSA-P256"),
    ("code-commit-signing", "CreateKeyPair:Sign", "Ed25519"),
];

#[test]
fn every_estate_label_resolves_to_its_classical_algorithm() {
    let eng = engine();
    let attrs = HashMap::new();
    for (label, op, expected) in ESTATE {
        let mut req = PolicyRequest::minimal(op, None, ts(), "estate", &attrs);
        req.name = Some(label);
        let d = eng.evaluate(&req);
        assert_eq!(
            d.algorithm_override(),
            Some(*expected),
            "label {label:?} under op {op:?} must resolve to {expected}"
        );
    }
}

/// The application asking for PQC BY NAME under the classical baseline is
/// denied — proves the boundary is the policy's, not the app's.
#[test]
fn explicit_pqc_is_denied_under_the_classical_baseline() {
    let eng = engine();
    let attrs = HashMap::new();
    for (op, algo) in [
        ("CreateKeyPair:Sign", "ML-DSA-44"),
        ("CreateKeyPair:KeyAgreement", "ML-KEM-768"),
        ("CreateKeyPair:KeyAgreement", "X25519MLKEM768"),
    ] {
        let req = PolicyRequest::minimal(op, Some(algo), ts(), "estate-deny", &attrs);
        assert!(
            eng.evaluate(&req).is_deny(),
            "explicit {algo} must be denied under migration-classical"
        );
    }
}

/// Labels nobody wrote rules for still work — the generic fallbacks fire.
#[test]
fn unmatched_labels_fall_back_to_generic_defaults() {
    let eng = engine();
    let attrs = HashMap::new();
    let mut req = PolicyRequest::minimal("CreateKeyPair:Sign", None, ts(), "estate-fb", &attrs);
    req.name = Some("something-entirely-else");
    assert_eq!(eng.evaluate(&req).algorithm_override(), Some("ECDSA-P256"));

    let mut kem = PolicyRequest::minimal("CreateKeyPair:KeyAgreement", None, ts(), "estate-fb2", &attrs);
    kem.name = Some("something-entirely-else");
    assert_eq!(eng.evaluate(&kem).algorithm_override(), Some("ECDH-P256"));
}
