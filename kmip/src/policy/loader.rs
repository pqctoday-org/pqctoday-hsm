//! YAML loader for [`super::Policy`] files.
//!
//! Three entry points:
//!
//! - [`load_from_str`] — parse + validate an in-memory YAML string.
//!   The Hub UI's "test this policy draft" button calls this directly.
//! - [`load_from_file`] — convenience wrapper around `read_to_string` +
//!   `load_from_str`.
//! - [`validate`] — parse-only; returns the typed `Policy` plus a list of
//!   non-fatal warnings (e.g. unknown algorithm strings, rule types with
//!   incomplete Phase-4.5 enforcement).
//!
//! Errors carry the YAML line/column when possible (via `serde_yaml`'s
//! `Location` API) so the Hub UI can underline the offending line.

use std::path::{Path, PathBuf};
use thiserror::Error;

use super::{
    policy::Policy,
    rule::Rule,
};

#[derive(Debug, Error)]
pub enum LoaderError {
    #[error("policy file {path}: I/O error: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("policy {path}: YAML parse error at line {line}, column {col}: {msg}")]
    Parse {
        path: PathBuf,
        line: usize,
        col: usize,
        msg: String,
    },

    #[error("policy {path}: unsupported schema_version {found}; this engine accepts {expected}")]
    SchemaVersion {
        path: PathBuf,
        found: u32,
        expected: u32,
    },

    #[error("policy {path}: validation failed: {msg}")]
    Invalid { path: PathBuf, msg: String },
}

/// Loaded policy + non-fatal warnings.
#[derive(Debug)]
pub struct LoadedPolicy {
    pub policy: Policy,
    pub source: String,
    pub warnings: Vec<String>,
}

/// Parse + validate a policy from an in-memory YAML string. `display_path`
/// is the path included in errors (use `PathBuf::from("<inline>")` for the
/// Hub UI dry-run case).
pub fn load_from_str(yaml: &str, display_path: &Path) -> Result<LoadedPolicy, LoaderError> {
    load_from_str_impl(yaml, display_path, false)
}

/// Strict variant of [`load_from_str`]: value-lint findings that are advisory
/// in normal mode (unknown *allowlist* algorithm names) become hard errors
/// (WP2.1). The local gate and the `cryptopolicy-manager` `/validate` route run
/// strict so a typo in a shipped policy is caught at authoring time, not in
/// production where it silently changes enforcement.
pub fn load_from_str_strict(yaml: &str, display_path: &Path) -> Result<LoadedPolicy, LoaderError> {
    load_from_str_impl(yaml, display_path, true)
}

fn load_from_str_impl(
    yaml: &str,
    display_path: &Path,
    strict: bool,
) -> Result<LoadedPolicy, LoaderError> {
    let policy: Policy = serde_yaml::from_str(yaml).map_err(|e| {
        let (line, col) = e
            .location()
            .map(|l| (l.line(), l.column()))
            .unwrap_or((0, 0));
        LoaderError::Parse {
            path: display_path.to_path_buf(),
            line,
            col,
            msg: e.to_string(),
        }
    })?;

    if policy.schema_version != Policy::SCHEMA_VERSION {
        return Err(LoaderError::SchemaVersion {
            path: display_path.to_path_buf(),
            found: policy.schema_version,
            expected: Policy::SCHEMA_VERSION,
        });
    }

    // S-6 — fail CLOSED on unknown rule fields. `Rule` is an internally-tagged
    // enum, so serde silently DROPS a typo'd field (`algoritms:` → an empty
    // `algorithms`), turning a deny rule into a no-op — the policy fails OPEN.
    // serde can't `deny_unknown_fields` on internally-tagged enums, so we detect
    // drops by round-tripping each rule: any raw key the typed rule does NOT
    // serialize back is unknown → reject the whole policy.
    if let Some(unknown) = first_unknown_rule_field(yaml) {
        return Err(LoaderError::Parse {
            path: display_path.to_path_buf(),
            line: 0,
            col: 0,
            msg: format!(
                "rule #{}: unknown field {:?} — a typo'd field is silently dropped \
                 and would disable the rule (policy rejected to fail closed)",
                unknown.0, unknown.1
            ),
        });
    }

    // WP2.1 (Y6) — value-level lint. Fatal findings (unknown mechanism/hash/
    // state/mode/class names anywhere, and unknown algorithm names in a
    // deny-family position where a typo silently disables the rule) reject the
    // policy. Advisory findings (unknown allowlist algorithm names) surface as
    // warnings unless `strict`.
    let findings = super::lint::lint_rules(&policy.rules, strict);
    let mut warnings = check_rules(&policy.rules);
    let (fatal, advisory): (Vec<_>, Vec<_>) = findings.into_iter().partition(|f| f.fatal);
    if let Some(f) = fatal.first() {
        return Err(LoaderError::Invalid {
            path: display_path.to_path_buf(),
            msg: format!("rule #{} field `{}`: {}", f.rule_index, f.field, f.message),
        });
    }
    warnings.extend(
        advisory
            .into_iter()
            .map(|f| format!("rule {} field `{}`: {}", f.rule_index, f.field, f.message)),
    );

    Ok(LoadedPolicy {
        policy,
        source: yaml.to_string(),
        warnings,
    })
}

/// S-6 helper — returns `(rule_index_1_based, field_name)` of the first rule key
/// that the typed [`Rule`] does not round-trip back (i.e. an unknown/typo'd
/// field serde dropped), or `None` if every rule field is recognised.
fn first_unknown_rule_field(yaml: &str) -> Option<(usize, String)> {
    // Union of every field name used by any `Rule` variant (policy/rule.rs),
    // plus the `type` tag. A rule key outside this set is a field serde would
    // silently drop. A union (rather than per-`type` precision) keeps this
    // maintenance-light while still catching every misspelling — the fail-open
    // footgun. NOTE: keep in sync when a new rule field is added to rule.rs.
    const KNOWN: &[&str] = &[
        "type", "after", "algorithm", "algorithm_class", "algorithms",
        "allowed_block_cipher_modes", "allowed_padding_methods", "allowed_states",
        "attribute_name", "block_cipher_mode", "clause", "composite_oid", "days",
        "default_algorithm", "deterministic", "effective_from", "effective_until",
        "exception_custom_attribute", "flags", "from", "hashing_algorithm",
        "hashing_algorithms", "mac_algorithms", "mask_generator", "mechanisms",
        "min_bits", "op", "ops", "ops_affected", "padding_method", "primary",
        "profile", "reason", "require_deterministic", "salt_length", "secondary",
        "tag_length", "to", "triggered_by_custom_attribute",
    ];
    let top: serde_yaml::Value = serde_yaml::from_str(yaml).ok()?;
    let rules = top.get("rules")?.as_sequence()?;
    for (i, raw) in rules.iter().enumerate() {
        if let Some(map) = raw.as_mapping() {
            for k in map.keys().filter_map(|k| k.as_str()) {
                if !KNOWN.contains(&k) {
                    return Some((i + 1, k.to_string()));
                }
            }
        }
    }
    None
}

/// Read `path` from disk and delegate to [`load_from_str`].
pub fn load_from_file(path: &Path) -> Result<LoadedPolicy, LoaderError> {
    let yaml = std::fs::read_to_string(path).map_err(|source| LoaderError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    load_from_str(&yaml, path)
}

/// Validate-only entry point — for the Hub UI's "is this draft syntactically
/// valid?" check before activation.
pub fn validate(yaml: &str) -> Result<LoadedPolicy, LoaderError> {
    load_from_str(yaml, Path::new("<draft>"))
}

/// Strict validate — used by `cryptopolicy-manager`'s `/validate` route and the
/// local gate so unknown allowlist algorithm names are rejected, not just warned
/// (WP2.1).
pub fn validate_strict(yaml: &str) -> Result<LoadedPolicy, LoaderError> {
    load_from_str_strict(yaml, Path::new("<draft>"))
}

/// Non-fatal warning generation. The list of conditions is deliberately
/// small in Phase 4.5; extend as the engine grows enforcement.
fn check_rules(rules: &[Rule]) -> Vec<String> {
    let mut warnings = Vec::new();
    for (i, rule) in rules.iter().enumerate() {
        let idx = i + 1;
        match rule {
            Rule::MaxKeyAgeDays { .. } => warnings.push(format!(
                "rule {idx}: max_key_age_days fires only for ops that target an \
                 activated key (the dispatcher supplies its Activation Date); \
                 Create and never-activated objects are not aged out."
            )),
            Rule::ComplianceProfileGate { .. } => warnings.push(format!(
                "rule {idx}: compliance_profile_gate is documentational only; \
                 actual enforcement composes from preceding allowlist/denylist rules."
            )),
            _ => {}
        }
    }
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// S-6 — every shipped policy must still load (the unknown-field guard must
    /// not false-positive on a canonical rule field).
    #[test]
    fn all_shipped_policies_load() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("policies");
        for entry in std::fs::read_dir(&dir).expect("policies/ dir") {
            let p = entry.unwrap().path();
            if p.extension().and_then(|e| e.to_str()) == Some("yaml") {
                let yaml = std::fs::read_to_string(&p).unwrap();
                load_from_str(&yaml, &p).unwrap_or_else(|e| panic!("{} failed to load: {e}", p.display()));
            }
        }
    }

    /// WP2.1 (Y6) — every shipped policy must pass the STRICT value lint (no
    /// unknown algorithm/mechanism/hash/state/mode/flag names anywhere). This is
    /// the authoring-time gate the local `local-gate.sh` runs; a typo in a
    /// shipped policy fails here, not silently in production.
    #[test]
    fn all_shipped_policies_pass_strict_lint() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("policies");
        let mut failures = Vec::new();
        for entry in std::fs::read_dir(&dir).expect("policies/ dir") {
            let p = entry.unwrap().path();
            if p.extension().and_then(|e| e.to_str()) == Some("yaml") {
                let yaml = std::fs::read_to_string(&p).unwrap();
                if let Err(e) = load_from_str_strict(&yaml, &p) {
                    failures.push(format!("{}: {e}", p.file_name().unwrap().to_string_lossy()));
                }
            }
        }
        assert!(failures.is_empty(), "policies failed strict lint:\n{}", failures.join("\n"));
    }

    /// S-6 — an unknown/typo'd rule field is rejected (fails closed) rather than
    /// silently dropped into a no-op rule. (Required-field typos like
    /// `algoritms` already fail via serde's missing-field error; this covers the
    /// dangerous case — an EXTRA field that serde would silently ignore.)
    #[test]
    fn unknown_rule_field_is_rejected() {
        let yaml = r#"
schema_version: 1
metadata: { name: t, description: d, authority: a, effective: "always" }
rules:
  - type: algorithm_denylist
    ops: [Sign]
    algorithms: [RSA]
    reason: deny RSA
    bogus_field: oops
"#;
        assert_eq!(first_unknown_rule_field(yaml), Some((1, "bogus_field".to_string())));
        let err = load_from_str(yaml, std::path::Path::new("<t>")).unwrap_err();
        assert!(err.to_string().contains("unknown field"), "got: {err}");
    }

    #[test]
    fn parses_minimal_policy() {
        let yaml = r#"
schema_version: 1
metadata:
  name: minimal
  description: minimum viable
  authority: test
  effective: "always"
rules:
  - type: algorithm_allowlist
    ops: [Create]
    algorithms: [AES-256]
    reason: "not in allowlist"
"#;
        let loaded = load_from_str(yaml, Path::new("<test>")).expect("must parse");
        assert_eq!(loaded.policy.schema_version, 1);
        assert_eq!(loaded.policy.metadata.name, "minimal");
        assert_eq!(loaded.policy.rules.len(), 1);
        assert!(loaded.warnings.is_empty());
    }

    #[test]
    fn parses_mechanism_dimension_rules() {
        let yaml = r#"
schema_version: 1
metadata:
  name: mech-dim
  description: mechanism-dimension rules
  authority: test
  effective: "always"
rules:
  - type: hash_algorithm_allowlist
    ops: [Sign]
    hashing_algorithms: [SHA-256, SHA-384, SHA3-256]
    reason: "approved hashes only"
  - type: mechanism_parameter_constraint
    ops: [Encrypt]
    algorithm: AES
    allowed_block_cipher_modes: [GCM, CCM]
    reason: "AEAD only"
  - type: mac_mechanism_policy
    ops: [MAC]
    mac_algorithms: [HMAC-SHA-256, HMAC-SHA-384]
    reason: "approved MACs only"
"#;
        let loaded = load_from_str(yaml, Path::new("<test>")).expect("must parse");
        assert_eq!(loaded.policy.rules.len(), 3);
        assert!(loaded.warnings.is_empty(), "new rule types are not stubs");
        use crate::policy::Rule;
        assert!(matches!(loaded.policy.rules[0], Rule::HashAlgorithmAllowlist { .. }));
        assert!(matches!(loaded.policy.rules[1], Rule::MechanismParameterConstraint { .. }));
        assert!(matches!(loaded.policy.rules[2], Rule::MacMechanismPolicy { .. }));
    }

    #[test]
    fn rejects_unknown_schema_version() {
        let yaml = r#"
schema_version: 99
metadata:
  name: future
  description: from the future
  authority: test
  effective: "always"
rules: []
"#;
        let err = load_from_str(yaml, Path::new("<test>")).expect_err("must reject");
        assert!(matches!(err, LoaderError::SchemaVersion { found: 99, .. }));
    }

    #[test]
    fn reports_parse_error_with_location() {
        let yaml = "schema_version: 1\nmetadata: [this should be a map]\n";
        let err = load_from_str(yaml, Path::new("<test>")).expect_err("must error");
        assert!(matches!(err, LoaderError::Parse { .. }));
    }

    #[test]
    fn warns_on_max_key_age_stub() {
        let yaml = r#"
schema_version: 1
metadata:
  name: with-stub
  description: contains stub rule
  authority: test
  effective: "always"
rules:
  - type: max_key_age_days
    ops: [Sign]
    days: 365
    reason: rotate
"#;
        let loaded = load_from_str(yaml, Path::new("<test>")).unwrap();
        assert_eq!(loaded.warnings.len(), 1);
        assert!(loaded.warnings[0].contains("max_key_age_days"));
    }

    #[test]
    fn parses_substitution_rule() {
        let yaml = r#"
schema_version: 1
metadata:
  name: substitution-demo
  description: classical to PQC at CreateKeyPair time
  authority: test
  effective: "2026-01-01"
rules:
  - type: algorithm_substitution
    ops: [CreateKeyPair]
    from: ECDSA-P256
    to: ML-DSA-65
    reason: "Upgrade signing keys to PQC per migration policy"
"#;
        let loaded = load_from_str(yaml, Path::new("<test>")).unwrap();
        assert_eq!(loaded.policy.rules.len(), 1);
    }
}
