// SPDX-License-Identifier: AGPL-3.0-only
//
//! Checks the committed evidence of the composite test-vector validation
//! (plan Workstream V, V4 and V5; what each check proves is in
//! `rust/kat/pkcs11-v33/validation/README.md`).
//!
//! The evidence was produced by the draft authors' reference code, which runs
//! outside this crate. These tests do not re-run it. They fail if the
//! committed record stops saying what the engine relies on:
//! - every check in both runs passed on every composite set, except the
//!   documented upstream loader defect, which must still read 0/N;
//! - both runs used the pinned upstream commits, and V4 read the exact vector
//!   files this crate tests against;
//! - V5 ran with the package versions V4 used (`constraints.txt`).

use super::composite_vectors::{KEM_VECTORS_SHA256, SIG_VECTORS_SHA256};
use serde_json::Value;

const V4_RESULTS: &str = include_str!("../../kat/pkcs11-v33/validation/v4/results/results.json");
const V4_PROVENANCE: &str = include_str!("../../kat/pkcs11-v33/validation/v4/results/upstream_provenance.txt");
const V4_ENV: &str = include_str!("../../kat/pkcs11-v33/validation/v4/results/env.txt");
const V5_RESULTS: &str = include_str!("../../kat/pkcs11-v33/validation/v5/results/results.json");
const V5_PROVENANCE: &str = include_str!("../../kat/pkcs11-v33/validation/v5/results/upstream_provenance.txt");
const V5_ENV: &str = include_str!("../../kat/pkcs11-v33/validation/v5/results/env.txt");
const V5_CONSTRAINTS: &str = include_str!("../../kat/pkcs11-v33/validation/v5/scripts/constraints.txt");

const KEM_COMMIT: &str = "d77e75420034d826e14cbef0b779986511f114e9";
const SIG_COMMIT: &str = "f0627ab34acfe1aee0abce4bee91ed2b577eab76";

/// Parses a "passed/total" summary value.
fn ratio(v: &Value) -> (u32, u32) {
    let s = v.as_str().expect("summary value is a string");
    let (a, b) = s.split_once('/').expect("summary value is passed/total");
    (a.parse().expect("passed count"), b.parse().expect("total count"))
}

/// Every summary entry passed in full, except the upstream loader defect,
/// which must still be recorded as failing on every composite KEM entry.
fn assert_summary(name: &str, results: &str, expect_kem: u32, expect_sig: u32) {
    let j: Value = serde_json::from_str(results).expect("results.json parses");
    let summary = j["summary"].as_object().expect("summary object");
    assert!(!summary.is_empty(), "{name}: empty summary");
    for (key, v) in summary {
        let (passed, total) = ratio(v);
        if key.contains("loader_as_shipped") {
            assert_eq!((passed, total), (0, expect_kem), "{name}: {key} should record the upstream loader defect");
            continue;
        }
        assert_eq!(passed, total, "{name}: {key} = {passed}/{total}");
        if key.starts_with("kem_composite") || key.starts_with("kem_ref") || key.starts_with("kem_neg") {
            assert_eq!(total, expect_kem, "{name}: {key} covers {total} KEM sets");
        }
        if key.starts_with("sig_composite") || key.starts_with("sig_ref") || key.starts_with("sig_neg") {
            assert_eq!(total, expect_sig, "{name}: {key} covers {total} signature sets");
        }
    }
}

#[test]
fn v4_reference_code_confirmed_every_vector() {
    assert_summary("V4", V4_RESULTS, 12, 18);
}

#[test]
fn v5_reference_code_accepted_every_engine_output() {
    assert_summary("V5", V5_RESULTS, 12, 18);
}

#[test]
fn both_runs_used_the_pinned_upstream_commits() {
    for (name, p) in [("V4", V4_PROVENANCE), ("V5", V5_PROVENANCE)] {
        assert!(p.contains(&format!("kem {KEM_COMMIT}")), "{name}: KEM commit not pinned");
        assert!(p.contains(&format!("sigs {SIG_COMMIT}")), "{name}: signature commit not pinned");
    }
    // V4 validated the very files this crate tests against.
    assert!(V4_PROVENANCE.contains(&format!("{KEM_VECTORS_SHA256}  kem/src/testvectors.json")));
    assert!(V4_PROVENANCE.contains(&format!("{SIG_VECTORS_SHA256}  sigs/src/testvectors.json")));
}

#[test]
fn v5_ran_with_the_v4_package_versions() {
    let pins: Vec<&str> =
        V5_CONSTRAINTS.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).collect();
    assert!(!pins.is_empty(), "constraints.txt pins nothing");
    for pin in &pins {
        assert!(V4_ENV.lines().any(|l| l.trim() == *pin), "V4 env lacks {pin}");
        assert!(V5_ENV.lines().any(|l| l.trim() == *pin), "V5 env lacks {pin}");
    }
    let openssl = |env: &str| env.lines().find(|l| l.starts_with("openssl:")).map(str::to_owned);
    assert!(openssl(V4_ENV).is_some(), "V4 env records no OpenSSL version");
    assert_eq!(openssl(V4_ENV), openssl(V5_ENV), "V4 and V5 used different OpenSSL builds");
}
