//! Headline-demo test for the `classical.yaml` ↔ `pqc.yaml` switch.
//!
//! Simulates the Hub scenario UI dropdown: load one of two policy files,
//! issue a request against the engine, observe the verdict change between
//! the two halves. The "application" — `simulate_app` — is byte-identical
//! across both halves.
//!
//! Three flows covered: KEM, digital signature, asymmetric encryption,
//! both at create-time and at use-time (rekey path).

use std::collections::HashMap;
use std::path::PathBuf;
use time::OffsetDateTime;

use pqctoday_kmip::policy::{load_from_file, Decision, Engine, PolicyRequest, PolicyStore};

fn policies_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("policies")
}

fn engine_for(file: &str) -> Engine {
    let loaded = load_from_file(&policies_dir().join(file))
        .unwrap_or_else(|e| panic!("loading {file}: {e}"));
    let eng = Engine::deny_all();
    eng.activate(loaded).expect("activation must succeed");
    eng
}

fn ts() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_780_000_000).unwrap() // 2026-05-29
}

// ── §1: both demo policies appear in the Hub UI dropdown ────────────────────

#[test]
fn dropdown_lists_both_demo_policies() {
    let store = PolicyStore::new(policies_dir());
    let names = store.list().unwrap();
    assert!(names.contains(&"classical".to_string()), "classical missing from dropdown");
    assert!(names.contains(&"pqc".to_string()), "pqc missing from dropdown");
}

// ── §2: KEM flow flips at the CreateKeyPair boundary ───────────────────────

#[test]
fn kem_flow_dropdown_flip() {
    let attrs = HashMap::new();
    // Application: "create a KEM keypair"; dispatcher canonicalises
    // CryptographicUsageMask=KeyAgreement into the op-name suffix.
    let req = PolicyRequest::minimal("CreateKeyPair:KeyAgreement", None, ts(), "kem-demo", &attrs);

    let classical = engine_for("classical.yaml");
    assert_eq!(
        classical.evaluate(&req).algorithm_override(),
        Some("ECDH-P256"),
        "classical KEM should default to ECDH-P256"
    );

    let pqc = engine_for("pqc.yaml");
    assert_eq!(
        pqc.evaluate(&req).algorithm_override(),
        Some("ML-KEM-1024"),
        "PQC KEM should default to ML-KEM-1024"
    );
}

// ── §3: signature flow flips at the CreateKeyPair boundary ─────────────────

#[test]
fn signature_flow_dropdown_flip() {
    let attrs = HashMap::new();
    let req = PolicyRequest::minimal("CreateKeyPair:Sign", None, ts(), "sig-demo", &attrs);

    assert_eq!(
        engine_for("classical.yaml").evaluate(&req).algorithm_override(),
        Some("ECDSA-P256")
    );
    assert_eq!(
        engine_for("pqc.yaml").evaluate(&req).algorithm_override(),
        Some("ML-DSA-87")
    );
}

// ── §4: asymmetric encryption flow flips at the CreateKeyPair boundary ─────

#[test]
fn encrypt_flow_dropdown_flip() {
    let attrs = HashMap::new();
    let req = PolicyRequest::minimal("CreateKeyPair:Encrypt", None, ts(), "enc-demo", &attrs);

    assert_eq!(
        engine_for("classical.yaml").evaluate(&req).algorithm_override(),
        Some("RSA-3072")
    );
    assert_eq!(
        engine_for("pqc.yaml").evaluate(&req).algorithm_override(),
        Some("ML-KEM-1024")
    );
}

// ── §5: existing ECDSA key auto-rekeys to ML-DSA-87 on Sign after flip ─────

#[test]
fn existing_ecdsa_key_rekeys_on_sign_under_pqc() {
    let attrs = HashMap::new();
    let mut req = PolicyRequest::minimal("Sign", Some("ECDSA-P256"), ts(), "rekey-sig", &attrs);
    req.current_object_algorithm = Some("ECDSA-P256");
    req.target_uid = Some("urn:pqctoday:obj:legacy-ecdsa-001");

    // Under classical: just Allow (no substitution).
    let classical = engine_for("classical.yaml");
    assert!(classical.evaluate(&req).is_allow());

    // Under PQC: RekeyAndProceed.
    let pqc = engine_for("pqc.yaml");
    let d = pqc.evaluate(&req);
    match d {
        Decision::RekeyAndProceed {
            original_uid,
            from_algorithm,
            new_algorithm,
            ..
        } => {
            assert_eq!(original_uid, "urn:pqctoday:obj:legacy-ecdsa-001");
            assert_eq!(from_algorithm, "ECDSA-P256");
            assert_eq!(new_algorithm, "ML-DSA-87");
        }
        other => panic!("expected RekeyAndProceed under PQC, got {other:?}"),
    }
}

// ── §6: encrypt-side KEM auto-rekey is DEFERRED to Phase 5 (Y5) ────────────
//
// RSA key-transport → ML-KEM is a cross-primitive migration the Encrypt path
// cannot execute, so pqc.yaml no longer carries an `ops: [Encrypt]`
// substitution (it would have promised a rekey the engine rejects). Until the
// Encapsulate rekey path lands, an Encrypt against a legacy RSA key is simply
// allowed (not silently pretend-migrated). The live crypto-agility demo is the
// Sign-side rekey asserted in §5 above.
#[test]
fn encrypt_side_kem_rekey_is_deferred_under_pqc() {
    let attrs = HashMap::new();
    let mut req = PolicyRequest::minimal("Encrypt", Some("RSA-3072"), ts(), "rekey-enc", &attrs);
    req.current_object_algorithm = Some("RSA-3072");
    req.target_uid = Some("urn:pqctoday:obj:legacy-rsa-001");

    let pqc = engine_for("pqc.yaml");
    let d = pqc.evaluate(&req);
    assert!(
        d.is_allow(),
        "Encrypt of a legacy RSA key should be allowed (no phantom encrypt-side rekey), got {d:?}"
    );
    assert!(
        !matches!(d, Decision::RekeyAndProceed { .. }),
        "encrypt-side rekey must NOT fire — it is deferred to Phase 5"
    );
}

// ── §7: explicit PQC Create under classical policy is denied ───────────────

#[test]
fn classical_policy_denies_direct_pqc_request() {
    let attrs = HashMap::new();
    let classical = engine_for("classical.yaml");
    let req_kem = PolicyRequest::minimal("CreateKeyPair:KeyAgreement", Some("ML-KEM-1024"), ts(), "x1", &attrs);
    assert!(classical.evaluate(&req_kem).is_deny());
    let req_sig = PolicyRequest::minimal("CreateKeyPair:Sign", Some("ML-DSA-87"), ts(), "x2", &attrs);
    assert!(classical.evaluate(&req_sig).is_deny());
}

// ── §8: classical Create denied under PQC policy ───────────────────────────

#[test]
fn pqc_policy_denies_new_classical_create() {
    let attrs = HashMap::new();
    let pqc = engine_for("pqc.yaml");
    let req = PolicyRequest::minimal("CreateKeyPair:Sign", Some("ECDSA-P256"), ts(), "x3", &attrs);
    assert!(pqc.evaluate(&req).is_deny());
}

// ── §9: Hub UI dry_run round-trip for both files ──────────────────────────

#[test]
fn hub_ui_dry_run_both_policies() {
    let store = PolicyStore::new(policies_dir());
    let attrs = HashMap::new();
    let req = PolicyRequest::minimal("CreateKeyPair:Sign", None, ts(), "dry", &attrs);
    for name in ["classical", "pqc"] {
        let yaml = std::fs::read_to_string(policies_dir().join(format!("{name}.yaml"))).unwrap();
        let d = store
            .dry_run(&yaml, &req)
            .unwrap_or_else(|e| panic!("dry_run({name}): {e}"));
        // Both policies supply a signature algorithm via algorithm_default →
        // we should always get an Allow with an override.
        assert!(
            d.algorithm_override().is_some(),
            "{name} should default a signing algo via algorithm_default"
        );
    }
}
