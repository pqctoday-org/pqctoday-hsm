//! Headline-demo integration tests for the Plane-1 agility engine.
//!
//! Each test demonstrates ONE flow flipped from classical → PQC by editing
//! a policy YAML — zero application-side changes between the two halves.
//!
//! Three flows per the customer demo:
//!
//! 1. **KEM** — classical (RSA-OAEP / ECDH) → PQC (ML-KEM-1024)
//! 2. **Digital signature** — classical (ECDSA-P256) → PQC (ML-DSA-87)
//! 3. **Encryption** — classical AES → ML-KEM-protected key delivery + AES
//!
//! The "application" in these tests is the [`simulate_app`] helper: it
//! constructs a [`PolicyRequest`] that names the operation but not the
//! algorithm (or names a classical one), and asks the engine what to do.
//! Flipping the active policy flips the engine's verdict — the helper is
//! unchanged.

use std::collections::HashMap;
use std::path::Path;
use time::OffsetDateTime;

use pqctoday_kmip::policy::{
    load_from_str, Decision, Engine, PolicyRequest,
};

const CLASSICAL_KEM_POLICY: &str = r#"
schema_version: 1
metadata:
  name: classical-kem
  description: KEM defaults to ECDH-P256 for new keys
  authority: demo
  effective: "always"
rules:
  - type: algorithm_default
    ops: [CreateKeyPair]
    default_algorithm: ECDH-P256
    reason: "Pre-PQC KEM default"
"#;

const PQC_KEM_POLICY: &str = r#"
schema_version: 1
metadata:
  name: pqc-kem
  description: KEM defaults to ML-KEM-1024 for new keys
  authority: demo
  effective: "2026-01-01"
rules:
  - type: algorithm_default
    ops: [CreateKeyPair]
    default_algorithm: ML-KEM-1024
    reason: "PQC KEM default (CNSA 2.0)"
"#;

const CLASSICAL_SIG_POLICY: &str = r#"
schema_version: 1
metadata:
  name: classical-sig
  description: signatures via ECDSA-P256
  authority: demo
  effective: "always"
rules:
  - type: algorithm_default
    ops: [CreateKeyPair]
    default_algorithm: ECDSA-P256
    reason: "Pre-PQC signing default"
"#;

const PQC_SIG_POLICY: &str = r#"
schema_version: 1
metadata:
  name: pqc-sig
  description: signatures via ML-DSA-87, rekey classical at Sign
  authority: demo
  effective: "2026-01-01"
rules:
  - type: algorithm_default
    ops: [CreateKeyPair]
    default_algorithm: ML-DSA-87
    reason: "PQC signing default"
  - type: algorithm_substitution
    ops: [Sign]
    from: ECDSA-P256
    to: ML-DSA-87
    reason: "Upgrade existing classical signing keys to PQC at sign time"
"#;

const CLASSICAL_ENC_POLICY: &str = r#"
schema_version: 1
metadata:
  name: classical-enc
  description: RSA-OAEP for asymmetric encrypt
  authority: demo
  effective: "always"
rules:
  - type: algorithm_default
    ops: [CreateKeyPair]
    default_algorithm: RSA-3072
    reason: "Pre-PQC asymmetric encrypt default"
"#;

const PQC_ENC_POLICY: &str = r#"
schema_version: 1
metadata:
  name: pqc-enc
  description: ML-KEM-1024 for asymmetric encrypt + key delivery
  authority: demo
  effective: "2026-01-01"
rules:
  - type: algorithm_default
    ops: [CreateKeyPair]
    default_algorithm: ML-KEM-1024
    reason: "PQC asymmetric encrypt: ML-KEM key delivery + AES bulk"
  - type: algorithm_substitution
    ops: [Encrypt]
    from: RSA-3072
    to: ML-KEM-1024
    reason: "Upgrade existing RSA-OAEP encryption to ML-KEM"
"#;

fn engine_with(yaml: &str) -> Engine {
    let eng = Engine::deny_all();
    let loaded = load_from_str(yaml, Path::new("<demo>")).expect("test policy must parse");
    eng.activate(loaded).expect("test policy must activate");
    eng
}

fn ts() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_780_000_000).unwrap() // 2026-05-29
}

/// The "application" — UNCHANGED across all demo flows. Names the op + the
/// algorithm it inherited from a previous policy (or None for greenfield).
fn simulate_app<'a>(
    op: &'a str,
    inherited_algorithm: Option<&'a str>,
    existing_object: Option<(&'a str, &'a str)>, // (uid, stored_algorithm)
    attrs: &'a HashMap<String, String>,
) -> PolicyRequest<'a> {
    let mut req = PolicyRequest::minimal(op, inherited_algorithm, ts(), "demo-corr", attrs);
    if let Some((uid, algo)) = existing_object {
        req.target_uid = Some(uid);
        req.current_object_algorithm = Some(algo);
    }
    req
}

// ── FLOW 1 — KEM ────────────────────────────────────────────────────────────

#[test]
fn flow_kem_classical_to_pqc_via_policy_edit() {
    let attrs = HashMap::new();
    // Application asks for a new keypair without naming an algorithm.
    let req = simulate_app("CreateKeyPair", None, None, &attrs);

    let classical = engine_with(CLASSICAL_KEM_POLICY);
    let d_classical = classical.evaluate(&req);
    assert_eq!(
        d_classical.algorithm_override(),
        Some("ECDH-P256"),
        "classical policy should default to ECDH-P256"
    );

    // Security officer edits the policy YAML — no app change.
    let pqc = engine_with(PQC_KEM_POLICY);
    let d_pqc = pqc.evaluate(&req);
    assert_eq!(
        d_pqc.algorithm_override(),
        Some("ML-KEM-1024"),
        "PQC policy should default to ML-KEM-1024"
    );
}

// ── FLOW 2 — DIGITAL SIGNATURE ──────────────────────────────────────────────

#[test]
fn flow_signature_classical_to_pqc_via_policy_edit() {
    let attrs = HashMap::new();
    let create_req = simulate_app("CreateKeyPair", None, None, &attrs);

    let classical = engine_with(CLASSICAL_SIG_POLICY);
    assert_eq!(
        classical.evaluate(&create_req).algorithm_override(),
        Some("ECDSA-P256")
    );

    let pqc = engine_with(PQC_SIG_POLICY);
    assert_eq!(
        pqc.evaluate(&create_req).algorithm_override(),
        Some("ML-DSA-87")
    );
}

#[test]
fn flow_signature_rekey_classical_existing_key_on_sign() {
    // Existing ECDSA-P256 key in the store. App calls Sign against it.
    // PQC policy is active. Engine MUST emit RekeyAndProceed.
    let attrs = HashMap::new();
    let req = simulate_app(
        "Sign",
        Some("ECDSA-P256"),
        Some(("urn:pqctoday:obj:legacy-ecdsa", "ECDSA-P256")),
        &attrs,
    );

    let pqc = engine_with(PQC_SIG_POLICY);
    let d = pqc.evaluate(&req);
    match d {
        Decision::RekeyAndProceed {
            from_algorithm,
            new_algorithm,
            original_uid,
            ..
        } => {
            assert_eq!(from_algorithm, "ECDSA-P256");
            assert_eq!(new_algorithm, "ML-DSA-87");
            assert_eq!(original_uid, "urn:pqctoday:obj:legacy-ecdsa");
        }
        other => panic!("expected RekeyAndProceed, got {other:?}"),
    }
}

// ── FLOW 3 — ENCRYPTION (asymmetric) ────────────────────────────────────────

#[test]
fn flow_encryption_classical_to_pqc_via_policy_edit() {
    let attrs = HashMap::new();
    let create_req = simulate_app("CreateKeyPair", None, None, &attrs);

    let classical = engine_with(CLASSICAL_ENC_POLICY);
    assert_eq!(
        classical.evaluate(&create_req).algorithm_override(),
        Some("RSA-3072")
    );

    let pqc = engine_with(PQC_ENC_POLICY);
    assert_eq!(
        pqc.evaluate(&create_req).algorithm_override(),
        Some("ML-KEM-1024")
    );
}

#[test]
fn flow_encryption_rekey_rsa_to_mlkem_on_existing_object() {
    let attrs = HashMap::new();
    let req = simulate_app(
        "Encrypt",
        Some("RSA-3072"),
        Some(("urn:pqctoday:obj:legacy-rsa", "RSA-3072")),
        &attrs,
    );
    let pqc = engine_with(PQC_ENC_POLICY);
    let d = pqc.evaluate(&req);
    match d {
        Decision::RekeyAndProceed {
            from_algorithm,
            new_algorithm,
            ..
        } => {
            assert_eq!(from_algorithm, "RSA-3072");
            assert_eq!(new_algorithm, "ML-KEM-1024");
        }
        other => panic!("expected RekeyAndProceed, got {other:?}"),
    }
}

// ── COMBINED — security officer flips a single policy, three flows migrate ──

#[test]
fn three_flows_migrate_under_single_policy_edit() {
    let combined = r#"
schema_version: 1
metadata:
  name: combined-pqc
  description: KEM + sig + encrypt all default to PQC
  authority: security-officer
  effective: "2026-01-01"
rules:
  - type: algorithm_default
    ops: [CreateKeyPair]
    default_algorithm: ML-KEM-1024
    reason: "PQC defaults — KEM by canonical request shape"

  - type: algorithm_substitution
    ops: [Sign]
    from: ECDSA-P256
    to: ML-DSA-87
    reason: "PQC sig substitution at Sign time"

  - type: algorithm_substitution
    ops: [Encrypt]
    from: RSA-3072
    to: ML-KEM-1024
    reason: "PQC encrypt substitution at Encrypt time"
"#;
    let eng = engine_with(combined);
    let attrs = HashMap::new();

    let kem_req = simulate_app("CreateKeyPair", None, None, &attrs);
    assert_eq!(eng.evaluate(&kem_req).algorithm_override(), Some("ML-KEM-1024"));

    let sign_req = simulate_app(
        "Sign",
        Some("ECDSA-P256"),
        Some(("uid-sig", "ECDSA-P256")),
        &attrs,
    );
    assert!(matches!(
        eng.evaluate(&sign_req),
        Decision::RekeyAndProceed {
            new_algorithm,
            ..
        } if new_algorithm == "ML-DSA-87"
    ));

    let enc_req = simulate_app(
        "Encrypt",
        Some("RSA-3072"),
        Some(("uid-enc", "RSA-3072")),
        &attrs,
    );
    assert!(matches!(
        eng.evaluate(&enc_req),
        Decision::RekeyAndProceed {
            new_algorithm,
            ..
        } if new_algorithm == "ML-KEM-1024"
    ));
}
