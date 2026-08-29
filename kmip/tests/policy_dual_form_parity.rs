//! Monolithic ↔ split behavioral parity (WS-1a, 2026-08-28
//! gaps-remediation plan).
//!
//! 11 policies ship BOTH as one monolithic file (`classical.yaml`) and as a
//! per-scope module set (`classical-signing.yaml`, `classical-global.yaml`,
//! …) — kept side by side deliberately, because
//! `pqctoday-hub/src/wasm/kmip/kmipMeta.ts` hardcodes the monolithic
//! filenames as the Hub playground's catalog/Compare source, so deleting
//! them would break a live product surface in a different repo. Nothing
//! else checks the two forms stay behaviorally identical — this does.
//!
//! Design note (corrected from this plan's rev 1): the split-file GROUPING
//! is derived from the filesystem by naming convention
//! (`{base}.yaml` + `{base}-{scope}.yaml`), never hand-listed — a third
//! hand-maintained copy of the mapping (alongside `kmipMeta.ts`'s `files:`
//! lists) would be exactly the duplication this guard exists to catch.
//!
//! What's compared is BEHAVIOR, not YAML text — rule order can legitimately
//! differ across the split without changing what the engine decides. A
//! mismatch names both the file and the exact request that diverged.
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use pqctoday_kmip::policy::{load_from_file, Decision, Engine, PolicyRequest, Scope, UncoveredOps};
use time::OffsetDateTime;

fn policies_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("policies")
}

/// Every `{base}.yaml` that also has at least one `{base}-{scope}.yaml`
/// sibling, paired with that sibling set — discovered from the directory
/// listing, not a hand-written table.
fn dual_form_groups() -> Vec<(String, Vec<String>)> {
    let scopes: Vec<&str> = Scope::ALL.iter().map(|s| s.as_str()).collect();
    let entries: Vec<String> = fs::read_dir(policies_dir())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.ends_with(".yaml"))
        .collect();
    let bases: Vec<&String> = entries.iter().filter(|n| !scopes.iter().any(|s| {
        n.strip_suffix(".yaml").is_some_and(|stem| stem.ends_with(&format!("-{s}")))
    })).collect();

    let mut groups = Vec::new();
    for base in bases {
        let stem = base.strip_suffix(".yaml").unwrap();
        let siblings: Vec<String> = scopes
            .iter()
            .map(|s| format!("{stem}-{s}.yaml"))
            .filter(|f| entries.contains(f))
            .collect();
        if !siblings.is_empty() {
            groups.push((base.clone(), siblings));
        }
    }
    groups
}

/// Kind + the fields that actually describe the outcome — deliberately
/// excludes `fired_rule_index`/`human`/`cp_override`: rule indices and
/// message text (module-name-prefixed on the split side) are EXPECTED to
/// differ between the two forms; only the resulting behavior must match.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Allow(Option<String>),
    Rekey(String),
    Deny,
}

fn outcome(d: &Decision) -> Outcome {
    match d {
        Decision::Allow { algorithm_override, .. } => Outcome::Allow(algorithm_override.clone()),
        Decision::RekeyAndProceed { new_algorithm, .. } => Outcome::Rekey(new_algorithm.clone()),
        Decision::Deny { .. } => Outcome::Deny,
    }
}

const OPS: &[&str] = &[
    "Create",
    "CreateKeyPair:Sign",
    "CreateKeyPair:KeyAgreement",
    "CreateKeyPair:Encrypt",
    "Sign",
    "Encapsulate",
    "Encrypt",
];

const ALGORITHMS: &[Option<&str>] = &[
    None,
    Some("RSA-2048"),
    Some("RSA-3072"),
    Some("ECDSA-P256"),
    Some("ECDSA-P384"),
    Some("ECDSA-P521"),
    Some("Ed25519"),
    Some("Ed448"),
    Some("ECDH-P256"),
    Some("ECDH-P521"),
    Some("X25519"),
    Some("X448"),
    Some("AES-128"),
    Some("AES-256"),
    Some("ML-DSA-44"),
    Some("ML-DSA-87"),
    Some("ML-KEM-512"),
    Some("ML-KEM-1024"),
    Some("SLH-DSA-SHA2-128s"),
    Some("X25519MLKEM768"),
];

/// After every dual-form policy's own `effective` date (all "always" or
/// "2026-01-01") and well before "never"-default `expires`, so the sweep
/// exercises real rule behavior on both sides rather than the trivially-
/// identical "policy not live yet" case both engines already agree on.
fn sweep_ts() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_811_808_000).unwrap() // 2027-06-01
}

#[test]
fn monolithic_and_split_forms_decide_identically() {
    let groups = dual_form_groups();
    assert!(!groups.is_empty(), "no dual-form groups discovered — check the naming convention");

    let attrs = HashMap::new();
    let mut mismatches = Vec::new();

    for (base, siblings) in &groups {
        let mono = Engine::deny_all();
        mono.replace_all(load_from_file(&policies_dir().join(base)).unwrap()).unwrap();

        let split = Engine::deny_all();
        // Only rule behavior is under test — the two engines have no shared
        // notion of "uncovered" (the monolithic form has no scopes at all),
        // so an uncovered op on the split side must fall through to Allow,
        // not to a mismatch that's really just the modular default.
        split.set_uncovered_ops(UncoveredOps::Allow);
        for sibling in siblings {
            split
                .activate(load_from_file(&policies_dir().join(sibling)).unwrap())
                .unwrap_or_else(|e| panic!("{base}: activating {sibling} failed: {e:?}"));
        }

        for op in OPS {
            for algo in ALGORITHMS {
                let req = PolicyRequest::minimal(op, *algo, sweep_ts(), "parity", &attrs);
                let a = outcome(&mono.evaluate(&req));
                let b = outcome(&split.evaluate(&req));
                if a != b {
                    mismatches.push(format!(
                        "{base}: op={op} algorithm={algo:?} — monolithic={a:?} split={b:?}"
                    ));
                }
            }
        }
    }

    assert!(
        mismatches.is_empty(),
        "{} monolithic/split divergence(s):\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

/// Forward check, cheap to keep alongside the behavioral one: every module
/// file a preset's split set implies actually exists (an orphaned rename on
/// one side would otherwise only surface as a confusing hub-side failure).
#[test]
fn every_split_module_file_is_well_formed_yaml() {
    for (base, siblings) in dual_form_groups() {
        for sibling in siblings {
            let path = policies_dir().join(&sibling);
            assert!(path.exists(), "{base}: {sibling} does not exist");
            load_from_file(&path).unwrap_or_else(|e| panic!("{sibling}: {e}"));
        }
    }
}
