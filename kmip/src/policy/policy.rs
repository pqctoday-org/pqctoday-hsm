//! [`Policy`] — the deserialised form of one `policies/*.yaml` file.
//!
//! Shape matches the YAML schema documented in `policies/README.md` exactly.
//! Serde is the only parser — there is no hand-rolled YAML walker.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::rule::{Rule, Scope};

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
    /// Baseline schema version — every field except `metadata.expires` (see
    /// [`Policy::SCHEMA_VERSION_EXPIRES`]). The engine accepts
    /// `1..=SCHEMA_VERSION_EXPIRES` and refuses anything outside that range
    /// (`loader::load_from_str_impl`).
    ///
    /// v2 (A2, 2026-08-28 audit) adds `metadata.expires` — a policy-level
    /// validity window's end date, closing the gap the audit's YAML grammar
    /// report flagged as the single biggest hole in requirement (d)
    /// (effective + expiry dates): there was no expiry field anywhere in the
    /// grammar. v1 files are unaffected and remain fully supported —
    /// [`super::loader::load_from_str_impl`] additionally requires that a
    /// file only USE `expires` if it declares `schema_version: 2`, so the
    /// version number stays a meaningful, auditable signal of which grammar
    /// features a given policy actually relies on, not just an accepted
    /// range.
    pub const SCHEMA_VERSION: u32 = 1;
    pub const SCHEMA_VERSION_EXPIRES: u32 = 2;
    /// v3 (modular policy plan, 2026-08-28) adds `metadata.scopes` — see
    /// [`Metadata::scopes`]. Files that don't use it stay on v1/v2
    /// unaffected; `loader::load_from_str_impl` requires `scopes` only
    /// appear on a v3+ file, same pattern as v2/`expires`.
    pub const SCHEMA_VERSION_SCOPES: u32 = 3;

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
    /// `effective:` field — an ISO 8601 date, or the literal `"always"` /
    /// `"immediate"` (interchangeable — see `TimeBound::parse_str`). Kept as
    /// a String at this layer to preserve round-trip fidelity; validated at
    /// load time (`loader::load_from_str_impl`) and consulted per-request by
    /// [`super::Engine::evaluate`] (not just once at activation).
    pub effective: String,
    /// `expires:` field (A2, schema_version 2+) — an ISO 8601 date, or the
    /// literal `"never"` (also accepts `"always"`/`"immediate"` — all four
    /// unbounded synonyms parse identically). `None` means the same thing as
    /// an explicit `"never"`: the policy has no expiry, which is also the
    /// complete v1 behavior this field is additive to. A policy outside its
    /// `[effective, expires)` window is inert for a given request — checked
    /// per-request in `Engine::evaluate`, not just once at activation time
    /// the way `effective` alone used to be.
    #[serde(default)]
    pub expires: Option<String>,
    /// `scopes:` field (modular policy plan, 2026-08-28, schema_version 3+)
    /// — the one or more policy domains this file covers, from a fixed
    /// taxonomy ([`Scope`]). Empty (`None`/omitted) means "unscoped" —
    /// permanently, first-class supported for a single monolithic policy
    /// that isn't part of the modular composition model at all; an unscoped
    /// file can only be installed via `Engine::replace_all` (whole-engine
    /// swap), never `Engine::activate` (module add), which requires a
    /// non-empty `scopes`. A one-element list is what "a module" means
    /// throughout the plan; a longer list (up to all seven) is a single
    /// file covering several domains at once and is equally valid — see
    /// `cacp-modular-policy-plan-08282026.md` §0's revision note. The
    /// loader verifies every rule's ops stay inside the UNION of the
    /// declared scopes (`loader::check_scope_containment`), and that a file
    /// naming `Scope::Global` carries no resolution rules
    /// (`loader::check_global_is_gating_only`).
    #[serde(default)]
    pub scopes: Vec<Scope>,
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
