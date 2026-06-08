//! [`Policy`] — the deserialised form of one `policies/*.yaml` file.
//!
//! Shape matches the YAML schema documented in `policies/README.md` exactly.
//! Serde is the only parser — there is no hand-rolled YAML walker.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::rule::Rule;

/// Top-level policy document. One per YAML file.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Policy {
    /// `schema_version` field. The engine refuses to load a file whose
    /// version it doesn't recognise. Bump [`Policy::SCHEMA_VERSION`] only
    /// when the YAML shape adds a top-level field; new rule types alone do
    /// NOT require a bump (they're additive in the `rules:` list).
    pub schema_version: u32,

    pub metadata: Metadata,

    /// Ordered. Two-pass semantics — see [`super::Engine::evaluate`].
    pub rules: Vec<Rule>,
}

impl Policy {
    /// Schema version this Phase-4.5 engine accepts. Future major changes
    /// bump this; the engine refuses anything higher.
    pub const SCHEMA_VERSION: u32 = 1;

    /// SHA-256 fingerprint of the YAML source as loaded. Stamped into every
    /// audit entry so an operator can confirm which policy revision was in
    /// effect for any given request.
    pub fn fingerprint(yaml_source: &str) -> String {
        let mut h = Sha256::new();
        h.update(yaml_source.as_bytes());
        format!("sha256:{:x}", h.finalize())
    }
}

/// Required metadata. Optional `compliance_mapping` lives separately because
/// it's purely informational (no eval behavior depends on it).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Metadata {
    pub name: String,
    pub description: String,
    pub authority: String,
    /// `effective:` field — an ISO 8601 date or the literal `"always"`.
    /// Kept as a String at this layer to preserve round-trip fidelity;
    /// rule-level windows use [`super::rule::TimeBound`] for actual checks.
    pub effective: String,
    #[serde(default)]
    pub compliance_mapping: Vec<ComplianceMapping>,
}

/// One row in `metadata.compliance_mapping`. Open shape (the example
/// policies use mixed `level:` / `status:` fields) — both are optional.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComplianceMapping {
    pub framework: String,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub level: Option<serde_yaml::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_stable() {
        let yaml = "schema_version: 1\nmetadata:\n  name: test\n";
        let fp1 = Policy::fingerprint(yaml);
        let fp2 = Policy::fingerprint(yaml);
        assert_eq!(fp1, fp2);
        assert!(fp1.starts_with("sha256:"));
        assert_eq!(fp1.len(), "sha256:".len() + 64);
    }

    #[test]
    fn fingerprint_differs_on_edit() {
        let a = Policy::fingerprint("a");
        let b = Policy::fingerprint("b");
        assert_ne!(a, b);
    }
}
