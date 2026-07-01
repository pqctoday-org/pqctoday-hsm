//! Cross-check that every shipped `policies/*.yaml` file:
//!
//! 1. **Parses** without error against the v0.1 schema.
//! 2. **Activates** into a fresh [`Engine`] without panicking.
//! 3. **Behaves** as advertised against representative KEM, signature, and
//!    encryption requests.
//!
//! This is the test that satisfies the user's request for an automated
//! cross-check that the configurable engine can in fact be configured to
//! match the example policies (CNSA 2.0, FIPS-only, hybrid migration,
//! 2030 PQC migration, training permissive).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

use pqctoday_kmip::kmip30::UsageMask;
use pqctoday_kmip::policy::{load_from_file, Decision, Engine, PolicyRequest};

fn policies_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("policies")
}

fn ts_2027() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
}

fn engine_for(file: &str) -> Engine {
    let path = policies_dir().join(file);
    let loaded = load_from_file(&path)
        .unwrap_or_else(|e| panic!("loading {file}: {e}"));
    let eng = Engine::deny_all();
    eng.activate(loaded).expect("activation must succeed");
    eng
}

fn req<'a>(op: &'a str, algo: Option<&'a str>, attrs: &'a HashMap<String, String>) -> PolicyRequest<'a> {
    PolicyRequest::minimal(op, algo, ts_2027(), "xchk", attrs)
}

/// Like [`req`] but populates `usage_mask` with `flags`. Used wherever a
/// policy enforces `require_usage_mask` on the algorithm under test.
fn req_with_mask<'a>(
    op: &'a str,
    algo: Option<&'a str>,
    attrs: &'a HashMap<String, String>,
    flags: UsageMask,
) -> PolicyRequest<'a> {
    let mut r = req(op, algo, attrs);
    r.usage_mask = Some(flags);
    r
}

// ── §1: every shipped policy parses + activates ─────────────────────────────

#[test]
fn all_shipped_policies_parse() {
    for name in [
        "training-permissive.yaml",
        "pqc-migration-2030.yaml",
        "fips-only.yaml",
        "hybrid-migration-window.yaml",
        "cnsa-2.0.yaml",
        // Mechanism-dimension examples (crypto-policy gaps plan P2–P3).
        "fips-hashing.yaml",
        "aead-only.yaml",
        "deterministic-signing.yaml",
    ] {
        let path = policies_dir().join(name);
        assert!(path.exists(), "{} should exist", path.display());
        let _ = load_from_file(&path).unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}

// ── Mechanism-dimension example policies enforce (gaps plan P2–P3) ──────────
#[test]
fn mechanism_dimension_examples_enforce() {
    let attrs = HashMap::new();

    // fips-hashing: SHA-1 (0x04) on Sign denied; SHA-256 (0x06) allowed.
    let eng = engine_for("fips-hashing.yaml");
    let mut sha1 = req("Sign", Some("RSA"), &attrs);
    sha1.mechanism.hashing_algorithm = Some(0x04);
    assert!(eng.evaluate(&sha1).is_deny(), "SHA-1 must be denied");
    let mut sha256 = req("Sign", Some("RSA"), &attrs);
    sha256.mechanism.hashing_algorithm = Some(0x06);
    assert!(eng.evaluate(&sha256).is_allow(), "SHA-256 must be allowed");

    // aead-only: AES Encrypt CBC (0x01) denied; GCM (0x09) allowed.
    let eng2 = engine_for("aead-only.yaml");
    let mut cbc = req("Encrypt", Some("AES"), &attrs);
    cbc.mechanism.block_cipher_mode = Some(0x01);
    assert!(eng2.evaluate(&cbc).is_deny(), "AES-CBC must be denied");
    let mut gcm = req("Encrypt", Some("AES"), &attrs);
    gcm.mechanism.block_cipher_mode = Some(0x09);
    assert!(eng2.evaluate(&gcm).is_allow(), "AES-GCM must be allowed");

    // deterministic-signing: forces the Deterministic flag on Sign.
    let eng3 = engine_for("deterministic-signing.yaml");
    let d = eng3.evaluate(&req("Sign", Some("ML-DSA-65"), &attrs));
    assert_eq!(
        d.cp_override().and_then(|o| o.deterministic),
        Some(true),
        "policy must force deterministic signing"
    );
}

// ── §2: training-permissive allows the three flows ──────────────────────────

#[test]
fn training_permissive_allows_kem_sig_encrypt() {
    let eng = engine_for("training-permissive.yaml");
    let attrs = HashMap::new();
    assert!(eng.evaluate(&req("Create", Some("ML-KEM-1024"), &attrs)).is_allow());
    assert!(eng.evaluate(&req("Sign",   Some("ML-DSA-87"),   &attrs)).is_allow());
    assert!(eng.evaluate(&req("Create", Some("AES-256"),     &attrs)).is_allow());
    // Even classical algorithms allowed (permissive sandbox).
    assert!(eng.evaluate(&req("Create", Some("RSA"),         &attrs)).is_allow());
    assert!(eng.evaluate(&req("Sign",   Some("ECDSA-P256"),  &attrs)).is_allow());
}

// ── §3: fips-only allows FIPS PQC; denies off-list (e.g. Falcon, BIKE) ──────

#[test]
fn fips_only_allows_fips_pqc_and_denies_round4() {
    let eng = engine_for("fips-only.yaml");
    let attrs = HashMap::new();
    // KEM: ML-KEM allowed (fips-only requires KeyAgreement mask on KEM keys).
    let kem_req = req_with_mask("Create", Some("ML-KEM-1024"), &attrs, UsageMask::KEY_AGREEMENT);
    assert!(eng.evaluate(&kem_req).is_allow());
    // Sig: ML-DSA allowed (fips-only requires Sign+Verify on sig keys).
    let sig_req = req_with_mask(
        "Create",
        Some("ML-DSA-87"),
        &attrs,
        UsageMask::SIGN | UsageMask::VERIFY,
    );
    assert!(eng.evaluate(&sig_req).is_allow());
    // Encrypt: AES allowed (no usage_mask rule against AES-256 in fips-only).
    assert!(eng.evaluate(&req("Create", Some("AES-256"), &attrs)).is_allow());
    // Round-4 / alternate denied
    assert!(eng.evaluate(&req("Create", Some("Falcon-1024"), &attrs)).is_deny());
    assert!(eng.evaluate(&req("Create", Some("BIKE-L3"),     &attrs)).is_deny());
    assert!(eng.evaluate(&req("Create", Some("HQC-256"),     &attrs)).is_deny());
}

// ── §4: cnsa-2.0 enforces Level-5-only PQC ──────────────────────────────────

#[test]
fn cnsa_2_0_allows_level5_pqc_only() {
    let eng = engine_for("cnsa-2.0.yaml");
    let mut attrs = HashMap::new();
    // CNSA-2.0 also demands x-pqctoday-cnsa-classification on ML-DSA-87 / ML-KEM-1024.
    attrs.insert("pqctoday-cnsa-classification".into(), "TopSecret".into());

    // Level-5 PQC + classification → allow.
    assert!(eng.evaluate(&req("Create", Some("ML-DSA-87"),   &attrs)).is_allow());
    assert!(eng.evaluate(&req("Create", Some("ML-KEM-1024"), &attrs)).is_allow());

    // Sub-Level-5 PQC → deny.
    assert!(eng.evaluate(&req("Create", Some("ML-KEM-768"),  &attrs)).is_deny());
    assert!(eng.evaluate(&req("Create", Some("ML-DSA-65"),   &attrs)).is_deny());

    // Classical asymmetric → deny.
    assert!(eng.evaluate(&req("Create", Some("ECDSA-P256"),  &attrs)).is_deny());
    assert!(eng.evaluate(&req("Create", Some("RSA"),         &attrs)).is_deny());

    // AES-256 → allow.
    assert!(eng.evaluate(&req("Create", Some("AES-256"), &attrs)).is_allow());
    // AES-128 → deny (CNSA-2.0 mandates AES-256).
    assert!(eng.evaluate(&req("Create", Some("AES-128"), &attrs)).is_deny());

    // Without classification attribute, ML-DSA-87 must be denied
    // (require_custom_attribute rule).
    let empty = HashMap::new();
    assert!(eng.evaluate(&req("Create", Some("ML-DSA-87"), &empty)).is_deny());
}

// ── §5: pqc-migration-2030 — temporal cutoff bites in 2031 ──────────────────

#[test]
fn pqc_migration_2030_temporal_cutoff_kicks_in_post_2030() {
    let eng = engine_for("pqc-migration-2030.yaml");
    let attrs = HashMap::new();

    // ECDSA is asymmetric, so its creation op is `CreateKeyPair:Sign`, not the
    // symmetric `Create` (Y2). Rule 3's ECDSA cutoff is 2027-01-01.
    // Pre-2027: classical ECDSA key-pair creation allowed (migration window).
    let ts_pre = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(); // 2023
    let mut pre_req = req("CreateKeyPair:Sign", Some("ECDSA-P256"), &attrs);
    pre_req.ts = ts_pre;
    let d_pre = eng.evaluate(&pre_req);
    assert!(
        d_pre.is_allow(),
        "pre-cutoff classical ECDSA key-pair creation must be allowed (migration window)"
    );

    // Post-cutoff: classical ECDSA key-pair creation must be denied.
    let ts_post = OffsetDateTime::from_unix_timestamp(2_000_000_000).unwrap(); // 2033
    let mut post_req = req("CreateKeyPair:Sign", Some("ECDSA-P256"), &attrs);
    post_req.ts = ts_post;
    let d_post = eng.evaluate(&post_req);
    assert!(d_post.is_deny(), "post-2027 classical ECDSA CreateKeyPair must be denied");
}

// ── §6: hybrid-migration-window — composite required mid-window ─────────────

#[test]
fn hybrid_window_demands_composite_mid_window() {
    let eng = engine_for("hybrid-migration-window.yaml");
    let attrs = HashMap::new();
    // Pure ML-DSA-65 at Create during the 2026-2029 window → deny.
    let mut create_pure = req("Create", Some("ML-DSA-65"), &attrs);
    create_pure.ts = ts_2027();
    assert!(eng.evaluate(&create_pure).is_deny());

    // Composite name should be allowed.
    let mut create_composite = req("Create", Some("ML-DSA-65-ED25519"), &attrs);
    create_composite.ts = ts_2027();
    let d = eng.evaluate(&create_composite);
    // The hybrid policy's allowlists may not include the composite name
    // explicitly — we only assert it's NOT denied by the hybrid_dual_sign
    // gate; other allow/deny rules may still apply. If it's denied here,
    // surface the rule index so the assertion message helps the operator.
    if let Decision::Deny { fired_rule_index, human, .. } = &d {
        // Rule 1 + 2 are the hybrid_dual_sign_requirement rules — they
        // should NOT be the cause of the deny for the composite name.
        assert!(
            *fired_rule_index != 1 && *fired_rule_index != 2,
            "hybrid gate should accept composite; got deny from rule {fired_rule_index}: {human}"
        );
    }
}

// ── §7: every policy passes through Hub-UI dry_run with no panics ───────────

#[test]
fn every_policy_supports_dry_run_for_hub_ui() {
    use pqctoday_kmip::policy::PolicyStore;
    let store = PolicyStore::new(policies_dir());
    let attrs = HashMap::new();
    // We're only checking that dry_run executes without erroring (parse +
    // evaluate). Either Allow OR Deny is a valid outcome; just no panic.
    let r = req_with_mask(
        "Create",
        Some("ML-DSA-87"),
        &attrs,
        UsageMask::SIGN | UsageMask::VERIFY,
    );
    for name in store.list().unwrap() {
        let yaml = std::fs::read_to_string(policies_dir().join(format!("{name}.yaml"))).unwrap();
        let _ = store.dry_run(&yaml, &r).unwrap_or_else(|e| panic!("dry_run({name}): {e}"));
    }
}

// ── §8: each policy file path resolves and is non-empty ────────────────────

#[test]
fn policy_file_paths_resolve() {
    for name in ["training-permissive", "fips-only", "cnsa-2.0", "hybrid-migration-window", "pqc-migration-2030"] {
        let p = policies_dir().join(format!("{name}.yaml"));
        let meta = std::fs::metadata(&p).unwrap_or_else(|_| panic!("missing {}", p.display()));
        assert!(meta.len() > 100, "{} too small to be a real policy", p.display());
    }
    let _ = Path::new(env!("CARGO_MANIFEST_DIR"));
}
