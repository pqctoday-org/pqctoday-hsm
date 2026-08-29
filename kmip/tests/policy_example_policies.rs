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
    eng.replace_all(loaded).expect("activation must succeed");
    eng
}

/// Like [`engine_for`] but for a policy that was split into per-scope
/// modules under the modular-policy plan (2026-08-28) — activates every
/// file in `files` as a module on the same engine, reproducing the
/// monolithic file's combined behavior.
fn engine_for_set(files: &[&str]) -> Engine {
    let eng = Engine::deny_all();
    for file in files {
        let path = policies_dir().join(file);
        let loaded = load_from_file(&path)
            .unwrap_or_else(|e| panic!("loading {file}: {e}"));
        eng.activate(loaded)
            .unwrap_or_else(|e| panic!("activate {file}: {e:?}"));
    }
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
        // Split per-scope modules (modular-policy plan, 2026-08-28).
        "pqc-migration-2030-signing.yaml",
        "pqc-migration-2030-key-establishment.yaml",
        "pqc-migration-2030-encryption.yaml",
        "pqc-migration-2030-global.yaml",
        "fips-only-signing.yaml",
        "fips-only-encryption.yaml",
        "fips-only-global.yaml",
        "hybrid-migration-window-signing.yaml",
        "hybrid-migration-window-global.yaml",
        "cnsa-2.0-signing.yaml",
        "cnsa-2.0-key-establishment.yaml",
        "cnsa-2.0-encryption.yaml",
        "cnsa-2.0-global.yaml",
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
    let eng = engine_for_set(&[
        "fips-only-signing.yaml",
        "fips-only-encryption.yaml",
        "fips-only-global.yaml",
    ]);
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
    let eng = engine_for_set(&[
        "cnsa-2.0-signing.yaml",
        "cnsa-2.0-key-establishment.yaml",
        "cnsa-2.0-encryption.yaml",
        "cnsa-2.0-global.yaml",
    ]);
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
    let eng = engine_for_set(&[
        "pqc-migration-2030-signing.yaml",
        "pqc-migration-2030-key-establishment.yaml",
        "pqc-migration-2030-encryption.yaml",
        "pqc-migration-2030-global.yaml",
    ]);
    let attrs = HashMap::new();

    // ECDSA is asymmetric, so its creation op is `CreateKeyPair:Sign`, not the
    // symmetric `Create` (Y2). Rule 3's ECDSA cutoff is 2027-01-01.
    // Pre-2027: classical ECDSA key-pair creation allowed (migration window).
    //
    // Must be AFTER this policy's own `metadata.effective: "2026-01-01"` —
    // 2023 (the original value here) predates it, which had no effect
    // before A2 (2026-08-28 audit: `metadata.effective` was activation-time
    // only) but now correctly makes the whole policy inert for a
    // pre-effective-date request, which is not what this test means to
    // exercise (see `Engine::policy_is_live` / A2's per-request window
    // check in `engine.rs`).
    let ts_pre = OffsetDateTime::from_unix_timestamp(1_780_272_000).unwrap(); // 2026-06-01
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
    // 2026-07-04/05 rewrite: the unconditional composite mandate this test
    // originally checked made no signing key creatable at all during the
    // window (composites aren't instantiable by Plane 2) — fixed by making
    // the composite an OPT-IN via x-pqctoday-dual-sign=required. Pure PQC is
    // now the default-allowed path; the mandate only bites a request that
    // asks for it. Also: the classical-signing cutoff and the dual-sign
    // rule both key off `CreateKeyPair:Sign`/`Sign`, not bare `Create`
    // (which never carries an asymmetric signing algorithm in real KMIP
    // traffic) — updated accordingly.
    let eng = engine_for_set(&[
        "hybrid-migration-window-signing.yaml",
        "hybrid-migration-window-global.yaml",
    ]);
    let no_attrs = HashMap::new();

    // Pure ML-DSA-65 at CreateKeyPair:Sign during the window, untagged → allow.
    let mut create_pure = req("CreateKeyPair:Sign", Some("ML-DSA-65"), &no_attrs);
    create_pure.ts = ts_2027();
    assert!(
        eng.evaluate(&create_pure).is_allow(),
        "untagged pure PQC must be allowed — composites aren't instantiable, so the \
         mandate can't be unconditional"
    );

    // Same request, opted into dual-sign → deny (composite required for it).
    let mut opted_in = HashMap::new();
    opted_in.insert("pqctoday-dual-sign".to_string(), "required".to_string());
    let mut create_pure_optin = req("CreateKeyPair:Sign", Some("ML-DSA-65"), &opted_in);
    create_pure_optin.ts = ts_2027();
    assert!(
        eng.evaluate(&create_pure_optin).is_deny(),
        "opted-in request must be held to the composite"
    );

    // Composite name should be allowed, tagged or not.
    let mut create_composite = req("CreateKeyPair:Sign", Some("ML-DSA-65-ED25519"), &no_attrs);
    create_composite.ts = ts_2027();
    let d = eng.evaluate(&create_composite);
    // The hybrid policy's allowlists may not include the composite name
    // explicitly — we only assert it's NOT denied by the hybrid_dual_sign
    // gate; other allow/deny rules may still apply. If it's denied here,
    // surface the rule index so the assertion message helps the operator.
    if let Decision::Deny { fired_rule_index, human, .. } = &d {
        // Rule 1b + 2 are the hybrid_dual_sign_requirement rules — they
        // should NOT be the cause of the deny for the composite name.
        assert!(
            *fired_rule_index != 3 && *fired_rule_index != 4,
            "hybrid gate should accept composite; got deny from rule {fired_rule_index}: {human}"
        );
    }
}

// ── §6b: auto-migrate-on-use.yaml + migration-hybrid.yaml — behavioral
// coverage added 2026-08-28 (audit finding B11). Before this, both files were
// exercised only by the load-all/strict-lint/parse/dry-run sweeps above —
// nothing drove their substitutions end to end, which is exactly how B2's
// coverage gap (most classical Sign/Encapsulate algorithms had no rekey
// target at all) went unnoticed.

/// Every classical signing algorithm `auto-migrate-on-use.yaml` claims to
/// cover rekeys to its stated PQC target on first Sign.
#[test]
fn auto_migrate_on_use_rekeys_every_covered_signing_algorithm() {
    let engine = engine_for_set(&[
        "auto-migrate-on-use-signing.yaml",
        "auto-migrate-on-use-key-establishment.yaml",
        "auto-migrate-on-use-encryption.yaml",
        "auto-migrate-on-use-global.yaml",
    ]);
    let attrs = HashMap::new();
    for (from, to) in [
        ("ECDSA-P256", "ML-DSA-65"),
        ("ECDSA-P384", "ML-DSA-87"),
        ("ECDSA-P521", "ML-DSA-87"),
        ("RSA-2048", "ML-DSA-65"),
        ("RSA-3072", "ML-DSA-65"),
        ("RSA-4096", "ML-DSA-87"),
        ("Ed25519", "ML-DSA-65"),
        ("Ed448", "ML-DSA-87"),
    ] {
        let mut req = PolicyRequest::minimal("Sign", Some(from), ts_2027(), "auto-mig-sign", &attrs);
        req.current_object_algorithm = Some(from);
        req.target_uid = Some("urn:pqctoday:obj:legacy-signing-key");
        match engine.evaluate(&req) {
            Decision::RekeyAndProceed { new_algorithm, .. } => {
                assert_eq!(new_algorithm, to, "expected {from} to rekey to {to}");
            }
            other => panic!("expected RekeyAndProceed for {from}, got {other:?}"),
        }
    }
}

/// Every classical key-establishment algorithm `auto-migrate-on-use.yaml`
/// claims to cover rekeys to ML-KEM-768 on first Encapsulate.
#[test]
fn auto_migrate_on_use_rekeys_every_covered_kem_algorithm() {
    let engine = engine_for_set(&[
        "auto-migrate-on-use-signing.yaml",
        "auto-migrate-on-use-key-establishment.yaml",
        "auto-migrate-on-use-encryption.yaml",
        "auto-migrate-on-use-global.yaml",
    ]);
    let attrs = HashMap::new();
    for from in ["ECDH-P256", "ECDH-P384", "ECDH-P521", "X25519", "X448"] {
        let mut req =
            PolicyRequest::minimal("Encapsulate", Some(from), ts_2027(), "auto-mig-kem", &attrs);
        req.current_object_algorithm = Some(from);
        req.target_uid = Some("urn:pqctoday:obj:legacy-kem-key");
        match engine.evaluate(&req) {
            Decision::RekeyAndProceed { new_algorithm, .. } => {
                assert_eq!(new_algorithm, "ML-KEM-768", "expected {from} to rekey to ML-KEM-768");
            }
            other => panic!("expected RekeyAndProceed for {from}, got {other:?}"),
        }
    }
}

/// The class-based backstop (finding B2) denies a classical Sign/Encapsulate
/// whose algorithm has no explicit rekey target above, instead of silently
/// allowing it to keep operating classically forever. Uses an unqualified
/// family name (`RSA`, `ECDH`) — the realistic way an algorithm could reach
/// this policy without matching an exact `from:` string.
#[test]
fn auto_migrate_on_use_backstop_denies_uncovered_classical_algorithm() {
    let engine = engine_for_set(&[
        "auto-migrate-on-use-signing.yaml",
        "auto-migrate-on-use-key-establishment.yaml",
        "auto-migrate-on-use-encryption.yaml",
        "auto-migrate-on-use-global.yaml",
    ]);
    let attrs = HashMap::new();

    let mut sign_req = PolicyRequest::minimal("Sign", Some("RSA"), ts_2027(), "auto-mig-gap-sign", &attrs);
    sign_req.current_object_algorithm = Some("RSA");
    sign_req.target_uid = Some("urn:pqctoday:obj:unqualified-rsa-key");
    assert!(
        engine.evaluate(&sign_req).is_deny(),
        "an uncovered classical signing algorithm must be denied by the backstop, not allowed"
    );

    let mut kem_req =
        PolicyRequest::minimal("Encapsulate", Some("ECDH"), ts_2027(), "auto-mig-gap-kem", &attrs);
    kem_req.current_object_algorithm = Some("ECDH");
    kem_req.target_uid = Some("urn:pqctoday:obj:unqualified-ecdh-key");
    assert!(
        engine.evaluate(&kem_req).is_deny(),
        "an uncovered classical KEM algorithm must be denied by the backstop, not allowed"
    );
}

/// `migration-hybrid.yaml` rekeys classical signing keys to ML-DSA-44 and
/// classical key-establishment keys to the hybrid KEM X25519MLKEM768 on
/// first use — the file's whole stated purpose, previously untested.
#[test]
fn migration_hybrid_rekeys_signing_and_kem_to_hybrid_targets() {
    let engine = engine_for_set(&[
        "migration-hybrid-signing.yaml",
        "migration-hybrid-key-establishment.yaml",
        "migration-hybrid-encryption.yaml",
        "migration-hybrid-global.yaml",
    ]);
    let attrs = HashMap::new();

    for from in ["RSA-2048", "ECDSA-P256", "Ed25519"] {
        let mut req = PolicyRequest::minimal("Sign", Some(from), ts_2027(), "mig-hybrid-sign", &attrs);
        req.current_object_algorithm = Some(from);
        req.target_uid = Some("urn:pqctoday:obj:legacy-signing-key");
        match engine.evaluate(&req) {
            Decision::RekeyAndProceed { new_algorithm, .. } => {
                assert_eq!(new_algorithm, "ML-DSA-44", "expected {from} to rekey to ML-DSA-44");
            }
            other => panic!("expected RekeyAndProceed for {from}, got {other:?}"),
        }
    }

    for from in ["X25519", "X448"] {
        let mut req =
            PolicyRequest::minimal("Encapsulate", Some(from), ts_2027(), "mig-hybrid-kem", &attrs);
        req.current_object_algorithm = Some(from);
        req.target_uid = Some("urn:pqctoday:obj:legacy-kem-key");
        match engine.evaluate(&req) {
            Decision::RekeyAndProceed { new_algorithm, .. } => {
                assert_eq!(
                    new_algorithm, "X25519MLKEM768",
                    "expected {from} to rekey to the hybrid KEM"
                );
            }
            other => panic!("expected RekeyAndProceed for {from}, got {other:?}"),
        }
    }
}

/// `migration-hybrid.yaml` denies new classical asymmetric key creation
/// during the hybrid window, including ECDH-P521 (finding B4 — previously
/// missing from this list, the same gap `pqc.yaml` closed 2026-07-04).
#[test]
fn migration_hybrid_denies_new_classical_keys_including_ecdh_p521() {
    let engine = engine_for_set(&[
        "migration-hybrid-signing.yaml",
        "migration-hybrid-key-establishment.yaml",
        "migration-hybrid-encryption.yaml",
        "migration-hybrid-global.yaml",
    ]);
    let attrs = HashMap::new();
    for algo in ["ECDH-P521", "RSA-2048", "ECDSA-P256"] {
        let req = PolicyRequest::minimal(
            "CreateKeyPair:KeyAgreement",
            Some(algo),
            ts_2027(),
            "mig-hybrid-create",
            &attrs,
        );
        assert!(
            engine.evaluate(&req).is_deny(),
            "{algo} should be denied for new key creation during the hybrid window"
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
    for name in [
        "training-permissive",
        "fips-only-global",
        "cnsa-2.0-global",
        "hybrid-migration-window-global",
        "pqc-migration-2030-global",
    ] {
        let p = policies_dir().join(format!("{name}.yaml"));
        let meta = std::fs::metadata(&p).unwrap_or_else(|_| panic!("missing {}", p.display()));
        assert!(meta.len() > 100, "{} too small to be a real policy", p.display());
    }
    let _ = Path::new(env!("CARGO_MANIFEST_DIR"));
}
