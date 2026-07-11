//! Op-layer policy conformance suite (WP2.2 / gaps Y1-Y5, Y22).
//!
//! Every other policy test builds a `PolicyRequest` by hand and calls
//! `engine.evaluate` directly — which is exactly why the Phase-1 fail-open bugs
//! (empty custom-attrs, `CreateKeyPair:Sign` vs `Create`, bare-vs-qualified
//! names) shipped unnoticed: they live in the *op handlers*, between the wire
//! request and the engine, not in the engine itself. This suite drives REAL
//! requests through the actual op handlers with each of the 13 shipped policies
//! mounted, and asserts the exact allow/deny outcome.
//!
//! Engine-free by design: we assert on the POLICY DECISION, not crypto
//! execution. A policy denial always surfaces as `PermissionDenied`; a policy
//! allow proceeds to (engine-less) key generation and fails with
//! `CryptographicFailure` — which still proves the policy let it through. So the
//! gate is exercised without a PKCS#11 session, fast enough to run the whole
//! matrix in milliseconds. See `policy_allowed` / `policy_denied`.
//!
//! ## Venue
//!
//! `#[ignore]`-gated so plain `cargo test` (CI) skips it; the local gate runs it
//! via `cargo test --test policy_op_layer -- --include-ignored`. No new CI job
//! (project directive 2026-07-01: new suites are local-only).

use std::sync::Arc;

use pqctoday_kmip::auditlog::{AuditSink, RingSink};
use pqctoday_kmip::kmip30::{
    Attribute, CreateKeyPairRequest, CreateRequest, KmipAlgorithm, ObjectType, UsageMask,
};
use pqctoday_kmip::ops::create::create;
use pqctoday_kmip::ops::create_key_pair::create_key_pair;
use pqctoday_kmip::ops::{Deps, DepsConfig};
use pqctoday_kmip::policy::{load_from_str, Engine};
use pqctoday_kmip::store::MemoryStore;

const POLICIES_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/policies");

/// Build an engine-free Deps with the named policy file mounted (activated).
fn deps_for(policy_file: &str) -> Deps {
    let path = std::path::Path::new(POLICIES_DIR).join(policy_file);
    let yaml = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let ring = Arc::new(RingSink::new(64));
    let sink: Arc<dyn AuditSink> = ring.clone();
    let engine = Engine::with_global_sink(sink.clone());
    engine
        .activate(load_from_str(&yaml, &path).unwrap_or_else(|e| panic!("{policy_file}: {e}")))
        .unwrap_or_else(|e| panic!("activate {policy_file}: {e:?}"));
    Deps::new(engine, Arc::new(MemoryStore::new()), sink, DepsConfig::default())
}

fn usage_for(intent: &str) -> UsageMask {
    match intent {
        "sign" => UsageMask::SIGN | UsageMask::VERIFY,
        "kem" => UsageMask::KEY_AGREEMENT,
        "encrypt" => UsageMask::ENCRYPT | UsageMask::DECRYPT,
        _ => UsageMask::SIGN | UsageMask::VERIFY,
    }
}

/// The canonical op string the dispatcher derives from the usage mask
/// (`dispatcher::canonical_create_key_pair_op`) — the string the policy `ops`
/// lists key on.
fn canonical_op_for(intent: &str) -> &'static str {
    match intent {
        "kem" => "CreateKeyPair:KeyAgreement",
        "encrypt" => "CreateKeyPair:Encrypt",
        _ => "CreateKeyPair:Sign",
    }
}

/// Drive a real CreateKeyPair through the op handler. Returns Ok(()) if allowed
/// (placeholder keypair generated), Err(reason) if the policy denied it.
fn try_create_key_pair(
    deps: &Deps,
    alg: KmipAlgorithm,
    length: u32,
    intent: &str,
    custom: &[(&str, &str)],
) -> Result<(), String> {
    let mut common = vec![
        Attribute::CryptographicAlgorithm(alg),
        Attribute::CryptographicUsageMask(usage_for(intent)),
    ];
    if length > 0 {
        common.push(Attribute::CryptographicLength(length));
    }
    for (k, v) in custom {
        common.push(Attribute::Custom { name: (*k).to_string(), value: pqctoday_kmip::kmip30::CustomAttributeValue::Text((*v).to_string()) });
    }
    create_key_pair(
        deps,
        CreateKeyPairRequest {
            common_attributes: common,
            private_key_attributes: vec![],
            public_key_attributes: vec![],
            seed: None,
        },
        canonical_op_for(intent),
        "ckp",
    )
    .map(|_| ())
    .map_err(|e| format!("{:?}", e.result_reason()))
}

/// Drive a real symmetric Create through the op handler.
fn try_create_sym(
    deps: &Deps,
    alg: KmipAlgorithm,
    length: u32,
    custom: &[(&str, &str)],
) -> Result<(), String> {
    let mut t = vec![
        Attribute::CryptographicAlgorithm(alg),
        Attribute::CryptographicUsageMask(UsageMask::ENCRYPT | UsageMask::DECRYPT),
    ];
    if length > 0 {
        t.push(Attribute::CryptographicLength(length));
    }
    for (k, v) in custom {
        t.push(Attribute::Custom { name: (*k).to_string(), value: pqctoday_kmip::kmip30::CustomAttributeValue::Text((*v).to_string()) });
    }
    create(deps, CreateRequest { object_type: ObjectType::SymmetricKey, template_attribute: t }, "cr")
        .map(|_| ())
        .map_err(|e| format!("{:?}", e.result_reason()))
}

const CNSA_TAG: (&str, &str) = ("x-pqctoday-cnsa-classification", "TopSecret");

// The op handlers wrap every `Decision::Deny` as `ResultReason::PermissionDenied`
// regardless of the internal deny reason, so a policy denial is unambiguous. A
// policy *allow* proceeds to key generation which, engine-less (integration
// tests compile the crate in non-test mode, so the placeholder path is off),
// fails with `CryptographicFailure` — that still means the POLICY allowed it.
// We therefore assert on the policy decision, not on crypto execution.
fn policy_denied(r: &Result<(), String>) -> bool {
    matches!(r, Err(reason) if reason == "PermissionDenied")
}
fn policy_allowed(r: &Result<(), String>) -> bool {
    !policy_denied(r)
}

// ─────────────────────────────────────────────────────────────────────────────
// The headline fail-open regressions (Y2/Y3): classical key-pair generation
// must be DENIED under the CNSA and FIPS-PQC-strict intent, and the approved
// algorithms must be ALLOWED. Before the op-name + qualified-name fixes, the
// classical CreateKeyPair sailed through (policy gated only `Create`).
// ─────────────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "op-layer suite: run via local gate (--include-ignored)"]
fn cnsa_denies_classical_keypair_allows_approved_pqc() {
    let deps = deps_for("cnsa-2.0.yaml");

    // FAIL-OPEN REGRESSION: classical RSA/ECDSA key-pair creation must be denied.
    assert!(
        policy_denied(&try_create_key_pair(&deps, KmipAlgorithm::Rsa, 3072, "sign", &[CNSA_TAG])),
        "CNSA must DENY classical RSA key-pair generation (Y2)"
    );
    assert!(
        policy_denied(&try_create_key_pair(&deps, KmipAlgorithm::Ecdsa, 256, "sign", &[CNSA_TAG])),
        "CNSA must DENY classical ECDSA key-pair generation (Y2)"
    );

    // Sub-Level-5 PQC denied.
    assert!(
        policy_denied(&try_create_key_pair(&deps, KmipAlgorithm::MlDsa65, 0, "sign", &[CNSA_TAG])),
        "CNSA must DENY ML-DSA-65 (below Level 5)"
    );

    // Approved Level-5 PQC, WITH the required classification tag → allowed.
    assert!(
        policy_allowed(&try_create_key_pair(&deps, KmipAlgorithm::MlDsa87, 0, "sign", &[CNSA_TAG])),
        "CNSA must ALLOW ML-DSA-87 with the classification tag"
    );
    assert!(
        policy_allowed(&try_create_key_pair(&deps, KmipAlgorithm::MlKem1024, 0, "kem", &[CNSA_TAG])),
        "CNSA must ALLOW ML-KEM-1024 with the classification tag"
    );
}

#[test]
#[ignore = "op-layer suite: run via local gate (--include-ignored)"]
fn cnsa_custom_attribute_gate_is_live() {
    let deps = deps_for("cnsa-2.0.yaml");
    // Y1 REGRESSION: without the classification tag, an approved algorithm is
    // denied by require_custom_attribute; with it, allowed. Before the fix the
    // tag never reached the engine so the approved algorithm was *always* denied.
    assert!(
        policy_denied(&try_create_key_pair(&deps, KmipAlgorithm::MlDsa87, 0, "sign", &[])),
        "ML-DSA-87 WITHOUT classification tag must be denied"
    );
    assert!(
        policy_allowed(&try_create_key_pair(&deps, KmipAlgorithm::MlDsa87, 0, "sign", &[CNSA_TAG])),
        "ML-DSA-87 WITH classification tag must be allowed"
    );
}

#[test]
#[ignore = "op-layer suite: run via local gate (--include-ignored)"]
fn cnsa_symmetric_aes256_allowed_aes128_denied() {
    let deps = deps_for("cnsa-2.0.yaml");
    // Y3 REGRESSION: bare "AES" used to fail the AES-256 allowlist (bricked) and
    // the AES-128 denial was dead. Now the request qualifies to AES-256/AES-128.
    assert!(
        policy_allowed(&try_create_sym(&deps, KmipAlgorithm::Aes, 256, &[CNSA_TAG])),
        "CNSA must ALLOW AES-256 (with tag)"
    );
    assert!(
        policy_denied(&try_create_sym(&deps, KmipAlgorithm::Aes, 128, &[CNSA_TAG])),
        "CNSA must DENY AES-128"
    );
}

#[test]
#[ignore = "op-layer suite: run via local gate (--include-ignored)"]
fn fips_allows_approved_classical_and_pqc_keypairs() {
    let deps = deps_for("fips-only.yaml");
    // FIPS approves RSA/ECDSA — CreateKeyPair must be evaluated (not skipped)
    // and allowed. RSA needs >= 3072 (min_key_length).
    assert!(
        policy_allowed(&try_create_key_pair(&deps, KmipAlgorithm::Rsa, 3072, "sign", &[])),
        "FIPS must ALLOW RSA-3072 key-pair"
    );
    assert!(
        policy_denied(&try_create_key_pair(&deps, KmipAlgorithm::Rsa, 2048, "sign", &[])),
        "FIPS must DENY RSA-2048 (< 3072 min_key_length)"
    );
    assert!(
        policy_allowed(&try_create_key_pair(&deps, KmipAlgorithm::MlDsa65, 0, "sign", &[])),
        "FIPS must ALLOW ML-DSA-65"
    );
}

#[test]
#[ignore = "op-layer suite: run via local gate (--include-ignored)"]
fn pqc_policy_denies_new_classical_keypair() {
    let deps = deps_for("pqc.yaml");
    // Y15 REGRESSION: bare ECDSA/ECDH used to escape pqc.yaml's denylist. Now
    // the qualified ECDSA-P256 is caught.
    assert!(
        policy_denied(&try_create_key_pair(&deps, KmipAlgorithm::Ecdsa, 256, "sign", &[])),
        "pqc.yaml must DENY new classical ECDSA key-pair"
    );
    assert!(
        policy_allowed(&try_create_key_pair(&deps, KmipAlgorithm::MlDsa87, 0, "sign", &[])),
        "pqc.yaml must ALLOW ML-DSA-87 key-pair"
    );
}

#[test]
#[ignore = "op-layer suite: run via local gate (--include-ignored)"]
fn training_permissive_allows_everything() {
    let deps = deps_for("training-permissive.yaml");
    assert!(policy_allowed(&try_create_key_pair(&deps, KmipAlgorithm::Rsa, 3072, "sign", &[])));
    assert!(policy_allowed(&try_create_key_pair(&deps, KmipAlgorithm::MlDsa87, 0, "sign", &[])));
    assert!(policy_allowed(&try_create_sym(&deps, KmipAlgorithm::Aes, 256, &[])));
}

// ─────────────────────────────────────────────────────────────────────────────
// BSI TR-02102-1 §2.4.1/§2.4.2 — FrodoKEM / Classic McEliece. These policy
// rules (algorithm_allowlist + require_custom_attribute) already existed in
// bsi-tr-02102.yaml, naming these exact algorithm strings — but were
// unreachable dead code until the FrodoKEM/Classic-McEliece/HQC
// implementation plan made the algorithms real. This is the test that
// proves they're not dead anymore.
// ─────────────────────────────────────────────────────────────────────────────

const HYBRID_PARTNER_TAG: (&str, &str) = ("pqctoday-hybrid-partner", "X25519");

#[test]
#[ignore = "op-layer suite: run via local gate (--include-ignored)"]
fn bsi_allows_frodokem_and_mceliece_with_hybrid_partner_tag() {
    let deps = deps_for("bsi-tr-02102.yaml");
    assert!(
        policy_allowed(&try_create_key_pair(
            &deps, KmipAlgorithm::FrodoKem976Aes, 0, "kem", &[HYBRID_PARTNER_TAG]
        )),
        "BSI must ALLOW FrodoKEM-976 with the hybrid-partner tag"
    );
    assert!(
        policy_allowed(&try_create_key_pair(
            &deps, KmipAlgorithm::ClassicMcEliece6688128, 0, "kem", &[HYBRID_PARTNER_TAG]
        )),
        "BSI must ALLOW Classic-McEliece-6688128 with the hybrid-partner tag"
    );
}

#[test]
#[ignore = "op-layer suite: run via local gate (--include-ignored)"]
fn bsi_denies_frodokem_and_mceliece_without_hybrid_partner_tag() {
    let deps = deps_for("bsi-tr-02102.yaml");
    assert!(
        policy_denied(&try_create_key_pair(&deps, KmipAlgorithm::FrodoKem976Aes, 0, "kem", &[])),
        "BSI must DENY FrodoKEM-976 without the hybrid-partner tag (Rule 3)"
    );
    assert!(
        policy_denied(&try_create_key_pair(&deps, KmipAlgorithm::ClassicMcEliece6688128, 0, "kem", &[])),
        "BSI must DENY Classic-McEliece-6688128 without the hybrid-partner tag (Rule 3)"
    );
}

/// The regional contrast the codebase's own docs describe: FIPS-only and
/// CNSA 2.0 explicitly do NOT recognize FrodoKEM/Classic McEliece (they're
/// not NIST-standardized), so both must deny them outright — regardless of
/// any hybrid-partner tag — while BSI allows them. Same engine, same ops;
/// the regulator's stance is a policy file, not a code path.
#[test]
#[ignore = "op-layer suite: run via local gate (--include-ignored)"]
fn fips_and_cnsa_deny_frodokem_and_mceliece_bsi_allows() {
    for policy in ["fips-only.yaml", "cnsa-2.0.yaml"] {
        let deps = deps_for(policy);
        assert!(
            policy_denied(&try_create_key_pair(
                &deps, KmipAlgorithm::FrodoKem976Aes, 0, "kem", &[HYBRID_PARTNER_TAG, CNSA_TAG]
            )),
            "{policy} must DENY FrodoKEM-976 (not NIST-standardized)"
        );
        assert!(
            policy_denied(&try_create_key_pair(
                &deps, KmipAlgorithm::ClassicMcEliece6688128, 0, "kem", &[HYBRID_PARTNER_TAG, CNSA_TAG]
            )),
            "{policy} must DENY Classic-McEliece-6688128 (not NIST-standardized)"
        );
    }
    let bsi_deps = deps_for("bsi-tr-02102.yaml");
    assert!(policy_allowed(&try_create_key_pair(
        &bsi_deps, KmipAlgorithm::FrodoKem976Aes, 0, "kem", &[HYBRID_PARTNER_TAG]
    )));
}

/// Meta-check: every shipped policy activates and can evaluate a CreateKeyPair
/// without panicking (proves all 13 load + mount through the op layer).
#[test]
#[ignore = "op-layer suite: run via local gate (--include-ignored)"]
fn all_shipped_policies_mount_and_evaluate() {
    let dir = std::path::Path::new(POLICIES_DIR);
    let mut count = 0;
    for entry in std::fs::read_dir(dir).expect("policies dir") {
        let p = entry.unwrap().path();
        if p.extension().and_then(|e| e.to_str()) != Some("yaml") {
            continue;
        }
        let file = p.file_name().unwrap().to_string_lossy().to_string();
        let deps = deps_for(&file);
        // A CreateKeyPair either succeeds or fails with a policy reason — never
        // panics. We don't assert the outcome here (that's the per-policy tests);
        // this just proves the mount + op-layer wiring for all 13.
        let _ = try_create_key_pair(&deps, KmipAlgorithm::MlDsa87, 0, "sign", &[CNSA_TAG]);
        count += 1;
    }
    assert!(count >= 13, "expected >= 13 shipped policies, saw {count}");
}
