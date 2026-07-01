//! Value-level policy lint (WP2.1 / gap Y6).
//!
//! The loader's [`super::loader::first_unknown_rule_field`] catches unknown
//! *field keys*. This module catches unknown *values*: an algorithm / mechanism
//! / hash / op / state / mode / flag name that the engine will never match. A
//! typo in a **denylist** or **temporal_cutoff** is the dangerous case — the
//! rule silently becomes a no-op and the policy fails OPEN. A typo in an
//! **allowlist** is the opposite (over-broad deny) and is reported as a warning
//! unless `strict` is set.
//!
//! Severity policy (mirrors the remediation plan):
//! - unknown value in a *deny*-family position (denylist, temporal_cutoff,
//!   substitution `from`, mechanism_denylist) → **hard error** (fail-open risk);
//! - unknown value in an *allow*-family position (allowlist, defaults,
//!   substitution `to`, mechanism_allowlist) → **warning**, promoted to a hard
//!   error under `strict` (the local gate and the manager `/validate` run
//!   strict);
//! - unknown mechanism / hash / class / state / mode / usage-flag names are
//!   always hard errors regardless of position — those vocabularies are bounded
//!   by the engine, so an unknown one is unambiguously a typo/no-op.
//!
//! Algorithm names are special: a denylist may legitimately name a real but
//! *unimplemented* algorithm (e.g. `FrodoKEM-1344`) as defence-in-depth, so
//! [`is_known_algorithm_name`] validates against a curated registry of real
//! algorithm names (implemented **and** known-unimplemented), not just the
//! engine's `KmipAlgorithm` enum.

use super::rule::{
    is_known_algorithm_class, is_known_block_cipher_mode, is_known_ckm_name, is_known_hash_name,
    is_known_mask_generator, is_known_padding_method, is_known_usage_flag, Rule,
};

/// A lint finding: which rule, which field, the offending value, and whether it
/// is fatal at the current strictness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub rule_index: usize, // 1-based
    pub field: &'static str,
    pub value: String,
    pub fatal: bool,
    pub message: String,
}

/// Lint every rule's values. Returns all findings; the caller separates fatal
/// from advisory. `strict` promotes allow-position algorithm-name warnings to
/// fatal.
pub fn lint_rules(rules: &[Rule], strict: bool) -> Vec<Finding> {
    let mut out = Vec::new();
    for (i, rule) in rules.iter().enumerate() {
        let idx = i + 1;
        lint_one(idx, rule, strict, &mut out);
    }
    out
}

fn algo(idx: usize, field: &'static str, value: &str, fatal: bool, out: &mut Vec<Finding>) {
    if !is_known_algorithm_name(value) {
        out.push(Finding {
            rule_index: idx,
            field,
            value: value.to_string(),
            fatal,
            message: format!(
                "unknown algorithm name {value:?} — not a recognised KMIP/PQC algorithm; \
                 it will never match (a typo here silently disables the rule)"
            ),
        });
    }
}

fn bounded(
    idx: usize,
    field: &'static str,
    value: &str,
    ok: bool,
    kind: &str,
    out: &mut Vec<Finding>,
) {
    if !ok {
        out.push(Finding {
            rule_index: idx,
            field,
            value: value.to_string(),
            fatal: true, // bounded vocabularies: unknown is always a no-op
            message: format!("unknown {kind} {value:?} — not one the engine understands"),
        });
    }
}

fn lint_one(idx: usize, rule: &Rule, strict: bool, out: &mut Vec<Finding>) {
    match rule {
        Rule::AlgorithmDefault { default_algorithm, .. } => {
            algo(idx, "default_algorithm", default_algorithm, strict, out);
        }
        Rule::AlgorithmSubstitution { from, to, .. } => {
            // `from` is a deny-position match target → fatal; `to` is allow.
            algo(idx, "from", from, true, out);
            algo(idx, "to", to, strict, out);
        }
        Rule::AlgorithmAllowlist { algorithms, .. } => {
            for a in algorithms {
                algo(idx, "algorithms", a, strict, out);
            }
        }
        Rule::AlgorithmDenylist { algorithms, .. } => {
            for a in algorithms {
                algo(idx, "algorithms", a, true, out); // fail-open if typo'd
            }
        }
        Rule::MinKeyLength { algorithm, .. } => algo(idx, "algorithm", algorithm, strict, out),
        Rule::RequireUsageMask { algorithm, flags, .. } => {
            algo(idx, "algorithm", algorithm, strict, out);
            for f in flags {
                bounded(idx, "flags", f, is_known_usage_flag(f), "usage-mask flag", out);
            }
        }
        Rule::RequireCustomAttribute { algorithms, .. } => {
            for a in algorithms {
                algo(idx, "algorithms", a, strict, out);
            }
        }
        Rule::TemporalCutoff { algorithm_class, algorithms, .. } => {
            bounded(
                idx,
                "algorithm_class",
                algorithm_class,
                is_known_algorithm_class(algorithm_class),
                "algorithm_class",
                out,
            );
            for a in algorithms {
                algo(idx, "algorithms", a, true, out); // narrows a deny → fatal
            }
        }
        Rule::LifecycleStateGate { allowed_states, .. } => {
            for s in allowed_states {
                bounded(idx, "allowed_states", s, is_known_state(s), "lifecycle state", out);
            }
        }
        Rule::HybridDualSignRequirement { primary, secondary, .. } => {
            algo(idx, "primary", primary, strict, out);
            algo(idx, "secondary", secondary, strict, out);
        }
        Rule::HashAlgorithmAllowlist { hashing_algorithms, .. } => {
            for h in hashing_algorithms {
                bounded(idx, "hashing_algorithms", h, is_known_hash_name(h), "hash algorithm", out);
            }
        }
        Rule::MechanismParameterConstraint {
            algorithm,
            allowed_block_cipher_modes,
            allowed_padding_methods,
            ..
        } => {
            if let Some(a) = algorithm {
                algo(idx, "algorithm", a, strict, out);
            }
            for m in allowed_block_cipher_modes {
                bounded(idx, "allowed_block_cipher_modes", m, is_known_block_cipher_mode(m), "block cipher mode", out);
            }
            for p in allowed_padding_methods {
                bounded(idx, "allowed_padding_methods", p, is_known_padding_method(p), "padding method", out);
            }
        }
        Rule::MechanismParameterDefault {
            algorithm,
            hashing_algorithm,
            block_cipher_mode,
            padding_method,
            mask_generator,
            ..
        } => {
            if let Some(a) = algorithm {
                algo(idx, "algorithm", a, strict, out);
            }
            if let Some(h) = hashing_algorithm {
                bounded(idx, "hashing_algorithm", h, is_known_hash_name(h), "hash algorithm", out);
            }
            if let Some(m) = block_cipher_mode {
                bounded(idx, "block_cipher_mode", m, is_known_block_cipher_mode(m), "block cipher mode", out);
            }
            if let Some(p) = padding_method {
                bounded(idx, "padding_method", p, is_known_padding_method(p), "padding method", out);
            }
            if let Some(g) = mask_generator {
                bounded(idx, "mask_generator", g, is_known_mask_generator(g), "mask generator", out);
            }
        }
        Rule::MacMechanismPolicy { mac_algorithms, .. } => {
            // mac_mechanism_policy is an allowlist (only these MACs pass), so a
            // typo over-broadly DENIES rather than failing open → advisory.
            // Names are qualified algorithm names (HMAC-SHA-256).
            for a in mac_algorithms {
                algo(idx, "mac_algorithms", a, strict, out);
            }
        }
        Rule::MechanismAllowlist { mechanisms, .. } => {
            for m in mechanisms {
                bounded(idx, "mechanisms", m, is_known_ckm_name(m), "CKM_* mechanism", out);
            }
        }
        Rule::MechanismDenylist { mechanisms, .. } => {
            for m in mechanisms {
                bounded(idx, "mechanisms", m, is_known_ckm_name(m), "CKM_* mechanism", out);
            }
        }
        // No lintable value fields (ops-only / documentational).
        Rule::MaxKeyAgeDays { .. } | Rule::ComplianceProfileGate { .. } => {}
    }
}

/// Known KMIP 3.0 lifecycle state names (spec §3 State enum).
fn is_known_state(s: &str) -> bool {
    matches!(
        s,
        "PreActive" | "Active" | "Deactivated" | "Compromised" | "Destroyed"
            | "DestroyedCompromised"
    )
}

/// `true` if `name` is a recognised algorithm name — implemented **or** a real
/// but unimplemented PQC/classical algorithm a denylist may legitimately name.
///
/// Structure-aware where a family takes a suffix (AES-256, ECDSA-P384, RSA-3072,
/// SLH-DSA-SHAKE-128f), exact-match for fixed names. Deliberately curated: the
/// point is to catch typos (`AES-2566`, `ML-DSA-8`, `Falconn-512`), not to be a
/// crypto encyclopedia. Extend when a policy introduces a new real algorithm.
pub fn is_known_algorithm_name(name: &str) -> bool {
    // Bare families accepted with no suffix (they qualify at the gate).
    const BARE: &[&str] = &[
        "AES", "RSA", "ECDSA", "ECDH", "DSA", "DH", "DES", "3DES", "MD5", "SHA1",
        "ChaCha20", "ChaCha20-Poly1305", "LMS", "HSS", "XMSS", "XMSS-MT",
        "Ed25519", "Ed448", "X25519", "X448", "RSA-PKCS1-v1_5", "ECDSA-SHA1",
    ];
    if BARE.contains(&name) {
        return true;
    }
    // Hash names (used as algorithm names in some deny rules, e.g. SHA-256).
    if is_known_hash_name(name) {
        return true;
    }
    // Qualified / parameterised families.
    let known_prefixes_suffixes: &[(&str, fn(&str) -> bool)] = &[
        ("AES-", |s| matches!(s, "128" | "192" | "256")),
        ("RSA-", |s| s.parse::<u32>().is_ok()),
        ("ECDSA-P", |s| matches!(s, "256" | "384" | "521")),
        ("ECDH-P", |s| matches!(s, "256" | "384" | "521")),
        ("HMAC-SHA-", |s| matches!(s, "256" | "384" | "512")),
        ("HMAC-SHA3-", |s| matches!(s, "256" | "384" | "512")),
        ("ML-KEM-", |s| matches!(s, "512" | "768" | "1024")),
        ("ML-DSA-", is_ml_dsa_suffix),
        ("SLH-DSA-", is_slh_dsa_suffix),
        ("Falcon-", |s| matches!(s, "512" | "1024")),
        ("HQC-", |s| matches!(s, "128" | "192" | "256")),
        ("BIKE-", |s| matches!(s, "L1" | "L3" | "L5")),
        ("FrodoKEM-", |s| matches!(s, "640" | "976" | "1344")),
        ("Classic-McEliece-", |s| {
            matches!(s, "348864" | "460896" | "6688128" | "6960119" | "8192128")
        }),
    ];
    known_prefixes_suffixes
        .iter()
        .any(|(pfx, ok)| name.strip_prefix(pfx).is_some_and(|rest| ok(rest)))
}

/// ML-DSA suffix: a bare level (`44`/`65`/`87`) or a composite tail
/// (`65-ED25519`, `87-ECDSA-P384`) LAMPS names use.
fn is_ml_dsa_suffix(s: &str) -> bool {
    match s {
        "44" | "65" | "87" => true,
        // composite: <level>-<classical>
        _ => {
            let mut parts = s.splitn(2, '-');
            let level = parts.next().unwrap_or("");
            let tail = parts.next().unwrap_or("");
            matches!(level, "44" | "65" | "87")
                && matches!(
                    tail,
                    "ED25519" | "ED448" | "ECDSA-P256" | "ECDSA-P384" | "ECDSA-P521"
                )
        }
    }
}

/// SLH-DSA suffix: `<hash>-<size><s|f>`, e.g. `SHA2-128s`, `SHAKE-256f`.
fn is_slh_dsa_suffix(s: &str) -> bool {
    let rest = match s.strip_prefix("SHA2-").or_else(|| s.strip_prefix("SHAKE-")) {
        Some(r) => r,
        None => return false,
    };
    matches!(
        rest,
        "128s" | "128f" | "192s" | "192f" | "256s" | "256f"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::rule::TimeBound;

    #[test]
    fn known_algorithm_names_accepts_real_and_qualified() {
        for ok in [
            "AES", "AES-256", "RSA-3072", "ECDSA-P384", "ECDH-P256", "ML-KEM-1024",
            "ML-DSA-87", "ML-DSA-65-ED25519", "ML-DSA-87-ECDSA-P384", "SLH-DSA-SHA2-128s",
            "SLH-DSA-SHAKE-256f", "HMAC-SHA-256", "LMS", "HSS", "XMSS", "XMSS-MT",
            "Falcon-1024", "HQC-192", "BIKE-L3", "FrodoKEM-1344", "Classic-McEliece-8192128",
            "Ed25519", "X25519", "SHA-256", "RSA-PKCS1-v1_5", "ECDSA-SHA1",
        ] {
            assert!(is_known_algorithm_name(ok), "should accept {ok}");
        }
    }

    #[test]
    fn known_algorithm_names_rejects_typos() {
        for bad in [
            "AES-2566", "ML-DSA-8", "Falconn-512", "ECDSA-P255", "RSA-", "ML-KEM-2048",
            "SLH-DSA-SHA2-300s", "FrodoKEM-999", "Classic-McEliece-1", "AESX",
        ] {
            assert!(!is_known_algorithm_name(bad), "should reject {bad}");
        }
    }

    fn deny_rule(algos: &[&str]) -> Rule {
        Rule::AlgorithmDenylist {
            ops: vec!["Create".into()],
            algorithms: algos.iter().map(|s| s.to_string()).collect(),
            reason: "t".into(),
            effective_from: None,
            effective_until: None,
            exception_custom_attribute: None,
        }
    }

    fn allow_rule(algos: &[&str]) -> Rule {
        Rule::AlgorithmAllowlist {
            ops: vec!["Create".into()],
            algorithms: algos.iter().map(|s| s.to_string()).collect(),
            reason: "t".into(),
            effective_from: None,
            effective_until: None,
        }
    }

    #[test]
    fn denylist_typo_is_fatal() {
        let findings = lint_rules(&[deny_rule(&["AES-256", "ML-DSA-8"])], false);
        let fatal: Vec<_> = findings.iter().filter(|f| f.fatal).collect();
        assert_eq!(fatal.len(), 1, "the ML-DSA-8 typo must be fatal in a denylist");
        assert_eq!(fatal[0].value, "ML-DSA-8");
    }

    #[test]
    fn allowlist_typo_is_advisory_then_strict_fatal() {
        let lenient = lint_rules(&[allow_rule(&["AES-256", "ML-KEM-2048"])], false);
        assert!(lenient.iter().all(|f| !f.fatal), "allowlist typo is advisory in lenient mode");
        assert_eq!(lenient.iter().filter(|f| f.value == "ML-KEM-2048").count(), 1);

        let strict = lint_rules(&[allow_rule(&["AES-256", "ML-KEM-2048"])], true);
        assert!(strict.iter().any(|f| f.fatal && f.value == "ML-KEM-2048"),
            "allowlist typo is fatal under strict");
    }

    #[test]
    fn unknown_mechanism_is_always_fatal() {
        let rule = Rule::MechanismAllowlist {
            ops: vec!["Sign".into()],
            mechanisms: vec!["CKM_RSA_PKCS_PSS".into(), "CKM_TYPO".into()],
            reason: "t".into(),
        };
        let findings = lint_rules(&[rule], false);
        assert!(findings.iter().any(|f| f.fatal && f.value == "CKM_TYPO"),
            "an unknown CKM name is always fatal (bounded vocabulary)");
    }

    #[test]
    fn unknown_class_and_state_are_fatal() {
        let cutoff = Rule::TemporalCutoff {
            op: "Sign".into(),
            algorithm_class: "quantum".into(), // not pqc/symmetric/classical
            algorithms: vec![],
            after: TimeBound::Always,
            reason: "t".into(),
        };
        assert!(lint_rules(&[cutoff], false).iter().any(|f| f.fatal && f.value == "quantum"));

        let gate = Rule::LifecycleStateGate {
            op: "Sign".into(),
            allowed_states: vec!["Alive".into()], // not a KMIP state
            reason: "t".into(),
        };
        assert!(lint_rules(&[gate], false).iter().any(|f| f.fatal && f.value == "Alive"));
    }
}
