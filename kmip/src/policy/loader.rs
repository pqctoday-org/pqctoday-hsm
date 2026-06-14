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

    let warnings = check_rules(&policy.rules);

    Ok(LoadedPolicy {
        policy,
        source: yaml.to_string(),
        warnings,
    })
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

/// Non-fatal warning generation. The list of conditions is deliberately
/// small in Phase 4.5; extend as the engine grows enforcement.
fn check_rules(rules: &[Rule]) -> Vec<String> {
    let mut warnings = Vec::new();
    for (i, rule) in rules.iter().enumerate() {
        let idx = i + 1;
        match rule {
            Rule::MaxKeyAgeDays { .. } => warnings.push(format!(
                "rule {idx}: max_key_age_days is a Phase-4.5 stub — needs Phase 6 store. Rule will never fire."
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
    mac_algorithms: [HMAC-SHA256, HMAC-SHA384]
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
