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
    rule::{is_resolution_rule, op_scope, referenced_ops, Rule, Scope},
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

    #[error("policy {path}: unsupported schema_version {found}; this engine accepts 1..={expected}")]
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

/// Everything `load_from_str_impl` does BEFORE value-level linting: parse the
/// YAML, then every structural check (unknown top-level/metadata field,
/// schema-version gating, date validation, scope containment, unknown rule
/// fields). Factored out (C3, 2026-08-28 gaps-remediation plan) so
/// [`super::store::PolicyStore::lint_draft`] can get a `Policy` to run the
/// FULL [`super::lint::lint_rules`] findings list against, instead of
/// stopping at the first fatal one the way every `LoaderError`-returning
/// path here does by design (structural errors are genuinely single-valued —
/// there's no "second" malformed YAML document — but rule-level lint
/// findings are not, and forcing them through this same one-error-at-a-time
/// shape was the actual C3 gap).
pub fn parse_and_structurally_validate(
    yaml: &str,
    display_path: &Path,
) -> Result<Policy, LoaderError> {
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

    // A5.4 (2026-08-28 audit) — fail CLOSED on an unknown top-level or
    // `metadata` key, the same fail-open footgun S-6 already closes for rule
    // fields. Neither `Policy` nor `Metadata` derives `deny_unknown_fields`
    // (a plain `#[derive(Deserialize)]` silently ignores an unrecognised
    // key), so writing `enabled: false` or `metadata.expires: "2030-01-01"`
    // against TODAY's grammar loads clean and enforces nothing — the typo
    // isn't in a rule, so S-6 alone never saw it. This matters most exactly
    // when a newer grammar (A2's `expires`, A3's `priority`) is introduced:
    // an old file experimentally trying the new key before this policy's
    // `schema_version` actually supports it now fails loudly instead of
    // silently doing nothing.
    if let Some(field) = first_unknown_top_level_or_metadata_field(yaml) {
        return Err(LoaderError::Parse {
            path: display_path.to_path_buf(),
            line: 0,
            col: 0,
            msg: format!(
                "unknown field {field:?} — a typo'd or unsupported field is silently \
                 dropped and would enforce nothing (policy rejected to fail closed)"
            ),
        });
    }

    // A2/modular-policy (2026-08-28 audit) — accept schema_version 1
    // (today's grammar, unchanged), 2 (adds metadata.expires), or 3 (adds
    // metadata.scopes). Anything else is rejected as before. `expected` in
    // the error reports the ceiling this engine understands, not a single
    // exact value — see `LoaderError::SchemaVersion`.
    if policy.schema_version == 0 || policy.schema_version > Policy::SCHEMA_VERSION_SCOPES {
        return Err(LoaderError::SchemaVersion {
            path: display_path.to_path_buf(),
            found: policy.schema_version,
            expected: Policy::SCHEMA_VERSION_SCOPES,
        });
    }

    // A2 — a file that uses `metadata.expires` must say so via
    // `schema_version: 2`. This isn't a technical necessity (this engine
    // understands `expires` regardless of the declared version — A5.4's
    // unknown-field guard is what actually protects an OLDER engine that
    // predates this field), but it keeps the version number a meaningful,
    // auditable signal: a security reviewer scanning `schema_version:`
    // across the fleet can tell which policies rely on the newer expiry
    // feature without reading every rule.
    if policy.metadata.expires.is_some() && policy.schema_version < Policy::SCHEMA_VERSION_EXPIRES
    {
        return Err(LoaderError::Invalid {
            path: display_path.to_path_buf(),
            msg: format!(
                "metadata.expires requires schema_version: {} (file declares {})",
                Policy::SCHEMA_VERSION_EXPIRES,
                policy.schema_version
            ),
        });
    }

    // A2 — validate `expires` the same way `effective` is validated below:
    // must be "never" (or an unbounded synonym) or a real YYYY-MM-DD date.
    if let Some(expires) = &policy.metadata.expires {
        if let Err(e) = super::rule::TimeBound::parse_str(expires) {
            return Err(LoaderError::Invalid {
                path: display_path.to_path_buf(),
                msg: format!(
                    "metadata.expires {expires:?} is not \"never\" or a valid YYYY-MM-DD date: {e}"
                ),
            });
        }
    }

    // A5.3 (2026-08-28 audit) — `metadata.effective` was an unvalidated free
    // string: `engine::is_future_effective` treats anything it can't parse
    // as a date as "not future", so a typo (`"2O30-01-01"`, a stray letter
    // in place of a digit) silently activated the policy IMMEDIATELY instead
    // of on the intended date — exactly the failure mode this validator
    // exists to close. Reuses `TimeBound`'s parser (now case-insensitive on
    // "always", see its doc comment) rather than a second copy of the same
    // date grammar; `Metadata::effective` itself stays a plain `String` for
    // round-trip fidelity, this only rejects it at load time if it can't
    // parse.
    if let Err(e) = super::rule::TimeBound::parse_str(&policy.metadata.effective) {
        return Err(LoaderError::Invalid {
            path: display_path.to_path_buf(),
            msg: format!(
                "metadata.effective {:?} is not \"always\" or a valid YYYY-MM-DD date: {e}",
                policy.metadata.effective
            ),
        });
    }

    // Modular-policy plan (2026-08-28) — `scopes` requires schema_version 3,
    // same gating pattern as A2's `expires`/schema_version 2 above.
    if !policy.metadata.scopes.is_empty()
        && policy.schema_version < Policy::SCHEMA_VERSION_SCOPES
    {
        return Err(LoaderError::Invalid {
            path: display_path.to_path_buf(),
            msg: format!(
                "metadata.scopes requires schema_version: {} (file declares {})",
                Policy::SCHEMA_VERSION_SCOPES,
                policy.schema_version
            ),
        });
    }

    // Modular-policy plan — a scoped file's rules must stay inside the
    // UNION of its declared scopes (containment), and a file naming
    // `Scope::Global` may never resolve an algorithm (gating-only). Both
    // are what make "policies cannot conflict" a property of the grammar
    // rather than something checked only at activation time — see
    // `check_scope_containment`/`check_global_is_gating_only`'s own doc
    // comments for the full rationale. Unscoped files (`scopes` empty) skip
    // both checks entirely — that mode has no scope concept at all.
    if !policy.metadata.scopes.is_empty() {
        if let Some(msg) = check_scope_containment(&policy.metadata.scopes, &policy.rules) {
            return Err(LoaderError::Invalid { path: display_path.to_path_buf(), msg });
        }
        if let Some(msg) = check_global_is_gating_only(&policy.metadata.scopes, &policy.rules) {
            return Err(LoaderError::Invalid { path: display_path.to_path_buf(), msg });
        }
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

    Ok(policy)
}

fn load_from_str_impl(
    yaml: &str,
    display_path: &Path,
    strict: bool,
) -> Result<LoadedPolicy, LoaderError> {
    let policy = parse_and_structurally_validate(yaml, display_path)?;

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

/// A5.4 helper — returns the first unrecognised key found at the policy
/// document's top level or inside `metadata`, or `None` if every key is
/// known. Deliberately does NOT descend into `metadata.compliance_mapping`
/// entries — that structure is purely informational (never read by
/// `check_pass2`/`resolve_pass1`), so a typo there cannot silently change
/// enforcement the way `enabled` on `metadata` itself could once that field
/// exists. `expires` (A2) and `scopes` (modular-policy plan) ARE known
/// fields now — their schema_version gates are enforced separately, right
/// after this guard runs (see `load_from_str_impl`), not here: this
/// function only asks "is this key spelled correctly / recognised at all",
/// not "is it allowed at this file's declared version".
fn first_unknown_top_level_or_metadata_field(yaml: &str) -> Option<String> {
    const TOP_LEVEL: &[&str] = &["schema_version", "metadata", "rules"];
    const METADATA: &[&str] = &[
        "name", "description", "authority", "effective", "expires", "scopes",
        "compliance_mapping",
    ];
    let top: serde_yaml::Value = serde_yaml::from_str(yaml).ok()?;
    let top_map = top.as_mapping()?;
    for k in top_map.keys().filter_map(|k| k.as_str()) {
        if !TOP_LEVEL.contains(&k) {
            return Some(k.to_string());
        }
    }
    if let Some(meta_map) = top.get("metadata").and_then(|m| m.as_mapping()) {
        for k in meta_map.keys().filter_map(|k| k.as_str()) {
            if !METADATA.contains(&k) {
                return Some(format!("metadata.{k}"));
            }
        }
    }
    None
}

/// Modular-policy plan — every rule's referenced ops must resolve to a
/// scope inside `declared` (the file's `metadata.scopes`). Returns the
/// first violation as a ready-to-report message, or `None` if the whole
/// file stays inside its declared domain(s). This is what makes "policies
/// cannot conflict" a load-time GUARANTEE rather than a hope: a
/// `key-establishment`-only file simply cannot contain a `Sign` rule, so
/// two active modules can never fight over the same op.
///
/// [`Scope::Global`] is exempt from this check entirely (checked first,
/// before the per-rule loop): its entire purpose is to gate ACROSS every
/// domain, so a rule naming `Sign`, `Encapsulate`, or even a bare
/// `CreateKeyPair` (unambiguous here — a global file has no "which domain
/// does this rule belong to" question the way a single-domain file does)
/// is exactly what it's for, not a violation. [`check_global_is_gating_only`]
/// is the check that keeps a `Global` file honest — it constrains WHAT KIND
/// of rule may appear (gating, never resolution), where this function
/// constrains WHICH OPS a non-`Global` file's rules may touch.
fn check_scope_containment(declared: &[Scope], rules: &[Rule]) -> Option<String> {
    if declared.contains(&Scope::Global) {
        return None;
    }
    for (i, rule) in rules.iter().enumerate() {
        for op in referenced_ops(rule) {
            match op_scope(op) {
                Ok(owner) if declared.contains(&owner) => {}
                Ok(owner) => {
                    return Some(format!(
                        "rule #{}: op {op:?} belongs to scope {:?}, which this file does not \
                         declare (declared: {}) — a scoped policy's rules must stay inside its \
                         own domain(s)",
                        i + 1,
                        owner.as_str(),
                        declared.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "),
                    ));
                }
                Err(reason) => {
                    return Some(format!("rule #{}: {reason}", i + 1));
                }
            }
        }
    }
    None
}

/// Modular-policy plan — a file that declares [`Scope::Global`] (anywhere
/// in its `scopes` list) may GATE any op but must never RESOLVE an
/// algorithm — `Global` isn't an op-owning domain, so there is nothing for
/// it to resolve on behalf of. Returns the first resolution rule found, or
/// `None` if the file is gating-only. Only meaningful for a file that
/// declared `Global`; the caller only invokes this when `scopes` is
/// non-empty, and a file with `Global` alongside real op-owning scopes is
/// still capped to gating-only for its ENTIRE rule set, not just the ops
/// `Global` would otherwise touch — mixing `Global` into a resolving file
/// is unusual and this makes that combination fail loudly rather than
/// silently doing something narrower than the author probably intended.
fn check_global_is_gating_only(declared: &[Scope], rules: &[Rule]) -> Option<String> {
    if !declared.contains(&Scope::Global) {
        return None;
    }
    for (i, rule) in rules.iter().enumerate() {
        if is_resolution_rule(rule) {
            return Some(format!(
                "rule #{}: a file declaring scope \"global\" may only gate, never resolve — \
                 this rule tries to default/substitute an algorithm or force a mechanism \
                 parameter, which no scope-less rule can own",
                i + 1
            ));
        }
    }
    None
}

/// S-6 helper — returns `(rule_index_1_based, field_name)` of the first rule key
/// that the typed [`Rule`] does not round-trip back (i.e. an unknown/typo'd
/// field serde dropped), or `None` if every rule field is recognised.
///
/// Per-variant (A5.2, 2026-08-28 audit) — checked against
/// [`super::rule::known_fields_for_rule_type`] for the rule's own `type:`
/// tag, not a cross-variant union. The union this replaced accepted a field
/// name valid on ANY variant everywhere, so e.g. `effective_from:` written
/// on a `mechanism_denylist` rule (a variant with no such field) loaded
/// clean and silently enforced no window at all — same fail-open footgun
/// S-6 exists to close for typo'd fields, just one variant removed. The
/// `type` tag itself is looked up first and is always valid; by the time
/// this function runs the typed `Policy` parse already accepted every rule's
/// `type:` value, so a `None` from the table lookup is unreachable in
/// practice but handled by rejecting every field on that rule rather than
/// panicking.
fn first_unknown_rule_field(yaml: &str) -> Option<(usize, String)> {
    let top: serde_yaml::Value = serde_yaml::from_str(yaml).ok()?;
    let rules = top.get("rules")?.as_sequence()?;
    for (i, raw) in rules.iter().enumerate() {
        if let Some(map) = raw.as_mapping() {
            let type_tag = map.get("type").and_then(|v| v.as_str()).unwrap_or("");
            let known = super::rule::known_fields_for_rule_type(type_tag).unwrap_or(&[]);
            for k in map.keys().filter_map(|k| k.as_str()) {
                if k != "type" && !known.contains(&k) {
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

    /// A5.4 — writing `enabled: false` against today's grammar (which has no
    /// such key) must be a load error, not a silent no-op. This is the exact
    /// scenario the audit flagged: an author reasonably expects an on/off
    /// switch to exist, writes it, and the policy loads and enforces anyway.
    #[test]
    fn unknown_top_level_field_is_rejected() {
        let yaml = r#"
schema_version: 1
metadata: { name: t, description: d, authority: a, effective: "always" }
rules: []
enabled: false
"#;
        assert_eq!(
            first_unknown_top_level_or_metadata_field(yaml),
            Some("enabled".to_string())
        );
        let err = load_from_str(yaml, std::path::Path::new("<t>")).unwrap_err();
        assert!(err.to_string().contains("unknown field"), "got: {err}");
    }

    /// A5.4 — same for a `metadata.expires` field the grammar doesn't have
    /// yet (a future schema_version 2 will; today it must be rejected).
    #[test]
    fn unknown_metadata_field_is_rejected() {
        // `expires` (A2) is now a real, known metadata field — this test
        // needs a field that will never exist, not the one A2 added.
        let yaml = r#"
schema_version: 1
metadata: { name: t, description: d, authority: a, effective: "always", bogus_field: oops }
rules: []
"#;
        assert_eq!(
            first_unknown_top_level_or_metadata_field(yaml),
            Some("metadata.bogus_field".to_string())
        );
        let err = load_from_str(yaml, std::path::Path::new("<t>")).unwrap_err();
        assert!(err.to_string().contains("unknown field"), "got: {err}");
    }

    /// A5.3 — a typo'd `effective` date must be rejected at load time
    /// instead of silently activating immediately (the pre-fix behavior:
    /// `is_future_effective` returned `false`, i.e. "not future", for any
    /// unparseable string).
    #[test]
    fn malformed_effective_date_is_rejected() {
        let yaml = r#"
schema_version: 1
metadata: { name: t, description: d, authority: a, effective: "2O30-01-01" }
rules: []
"#;
        let err = load_from_str(yaml, std::path::Path::new("<t>")).unwrap_err();
        assert!(
            err.to_string().contains("metadata.effective"),
            "expected a metadata.effective validation error, got: {err}"
        );
    }

    /// A5.3 — "always" is accepted case-insensitively in `metadata.effective`
    /// now, matching the case-insensitive check `is_future_effective` (and
    /// now `TimeBound::parse_str`) already used.
    #[test]
    fn effective_always_is_case_insensitive() {
        for variant in ["always", "Always", "ALWAYS"] {
            let yaml = format!(
                r#"
schema_version: 1
metadata: {{ name: t, description: d, authority: a, effective: "{variant}" }}
rules: []
"#
            );
            load_from_str(&yaml, std::path::Path::new("<t>"))
                .unwrap_or_else(|e| panic!("{variant:?} should be accepted: {e}"));
        }
    }

    /// A2 — `schema_version: 2` is accepted, and a v2 file may use `expires`.
    #[test]
    fn schema_version_2_with_expires_loads() {
        let yaml = r#"
schema_version: 2
metadata: { name: t, description: d, authority: a, effective: "always", expires: "2030-01-01" }
rules: []
"#;
        let loaded = load_from_str(yaml, Path::new("<t>")).expect("v2 with expires must load");
        assert_eq!(loaded.policy.metadata.expires.as_deref(), Some("2030-01-01"));
    }

    /// A2 — `expires` requires `schema_version: 2`; a v1 file using it is
    /// rejected even though `expires` is now a recognised field name (this
    /// is a schema-version-gate check, distinct from A5.4's unknown-field
    /// guard, which would happily accept it).
    #[test]
    fn expires_on_schema_version_1_is_rejected() {
        let yaml = r#"
schema_version: 1
metadata: { name: t, description: d, authority: a, effective: "always", expires: "2030-01-01" }
rules: []
"#;
        let err = load_from_str(yaml, Path::new("<t>")).unwrap_err();
        assert!(err.to_string().contains("schema_version"), "got: {err}");
    }

    /// Modular-policy plan — `scopes` requires `schema_version: 3`.
    #[test]
    fn scopes_on_schema_version_2_is_rejected() {
        let yaml = r#"
schema_version: 2
metadata: { name: t, description: d, authority: a, effective: "always", scopes: [signing] }
rules: []
"#;
        let err = load_from_str(yaml, Path::new("<t>")).unwrap_err();
        assert!(err.to_string().contains("schema_version"), "got: {err}");
    }

    /// Modular-policy plan — a rule reaching outside its file's declared
    /// scope is a load error (the load-time GUARANTEE that makes "policies
    /// cannot conflict" true by construction, not just by convention).
    #[test]
    fn rule_outside_declared_scope_is_rejected() {
        let yaml = r#"
schema_version: 3
metadata: { name: t, description: d, authority: a, effective: "always", scopes: [key-establishment] }
rules:
  - type: algorithm_default
    ops: [Sign]
    default_algorithm: ML-DSA-87
    reason: t
"#;
        let err = load_from_str(yaml, Path::new("<t>")).unwrap_err();
        assert!(err.to_string().contains("Sign"), "got: {err}");
        assert!(err.to_string().contains("signing"), "got: {err}");
    }

    /// Modular-policy plan — a bare `CreateKeyPair` (unrefined) in a scoped
    /// file is ambiguous and rejected, not silently guessed at.
    #[test]
    fn bare_create_key_pair_in_scoped_file_is_rejected() {
        let yaml = r#"
schema_version: 3
metadata: { name: t, description: d, authority: a, effective: "always", scopes: [signing] }
rules:
  - type: algorithm_denylist
    ops: [CreateKeyPair]
    algorithms: [RSA]
    reason: t
"#;
        let err = load_from_str(yaml, Path::new("<t>")).unwrap_err();
        assert!(err.to_string().contains("ambiguous"), "got: {err}");
    }

    /// Modular-policy plan — a refined `CreateKeyPair:Sign` in a `signing`
    /// file is fine (this is the whole point of the refinement).
    #[test]
    fn refined_create_key_pair_in_matching_scope_is_accepted() {
        let yaml = r#"
schema_version: 3
metadata: { name: t, description: d, authority: a, effective: "always", scopes: [signing] }
rules:
  - type: algorithm_denylist
    ops: ["CreateKeyPair:Sign"]
    algorithms: [RSA]
    reason: t
"#;
        load_from_str(yaml, Path::new("<t>")).expect("refined op in its own scope must load");
    }

    /// Modular-policy plan — `Scope::Global` may gate ANY op, including a
    /// bare `CreateKeyPair` (unambiguous for a global file — it isn't
    /// claiming to own any one domain).
    #[test]
    fn global_scope_may_gate_any_op_including_bare_create_key_pair() {
        let yaml = r#"
schema_version: 3
metadata: { name: t, description: d, authority: a, effective: "always", scopes: [global] }
rules:
  - type: algorithm_denylist
    ops: [CreateKeyPair, Sign, Encrypt, Encapsulate]
    algorithms: [DES, 3DES]
    reason: t
"#;
        load_from_str(yaml, Path::new("<t>")).expect("global file must gate any op freely");
    }

    /// Modular-policy plan — a file declaring `global` may never RESOLVE an
    /// algorithm (only gate), even though it can gate any op.
    #[test]
    fn global_scope_rejects_resolution_rules() {
        let yaml = r#"
schema_version: 3
metadata: { name: t, description: d, authority: a, effective: "always", scopes: [global] }
rules:
  - type: algorithm_default
    ops: [Sign]
    default_algorithm: ML-DSA-87
    reason: t
"#;
        let err = load_from_str(yaml, Path::new("<t>")).unwrap_err();
        assert!(err.to_string().contains("global"), "got: {err}");
    }

    /// Modular-policy plan — `Scope::Global` MAY force a mechanism
    /// parameter (`mechanism_parameter_default`): forcing "always sign
    /// deterministically" doesn't claim ownership of an op's algorithm
    /// choice the way `algorithm_default`/`algorithm_substitution` would,
    /// so it's exactly as composable as a gate. Regression test for a real
    /// bug (`is_resolution_rule` originally over-included this rule type,
    /// which would have made `deterministic-signing.yaml` — a file whose
    /// own design intent is to compose with ANY signing policy — unable to
    /// ever be `global`-scoped).
    #[test]
    fn global_scope_accepts_mechanism_parameter_forcing() {
        let yaml = r#"
schema_version: 3
metadata: { name: t, description: d, authority: a, effective: "always", scopes: [global] }
rules:
  - type: mechanism_parameter_default
    ops: [Sign]
    deterministic: true
    reason: t
"#;
        load_from_str(yaml, Path::new("<t>"))
            .expect("global scope must accept mechanism-parameter forcing");
    }

    /// Modular-policy plan — a multi-scope file (e.g. `[signing,
    /// key-establishment]`) may contain rules for either domain, but still
    /// not a third it didn't declare.
    #[test]
    fn multi_scope_file_covers_the_union() {
        let ok = r#"
schema_version: 3
metadata: { name: t, description: d, authority: a, effective: "always", scopes: [signing, key-establishment] }
rules:
  - type: algorithm_default
    ops: ["CreateKeyPair:Sign"]
    default_algorithm: ML-DSA-87
    reason: t
  - type: algorithm_default
    ops: ["CreateKeyPair:KeyAgreement"]
    default_algorithm: ML-KEM-1024
    reason: t
"#;
        load_from_str(ok, Path::new("<t>")).expect("union of declared scopes must be accepted");

        let bad = r#"
schema_version: 3
metadata: { name: t, description: d, authority: a, effective: "always", scopes: [signing, key-establishment] }
rules:
  - type: algorithm_default
    ops: [Create]
    default_algorithm: AES-256
    reason: t
"#;
        let err = load_from_str(bad, Path::new("<t>")).unwrap_err();
        assert!(err.to_string().contains("encryption"), "got: {err}");
    }

    /// Modular-policy plan, wave 3 (2026-08-28) — `ReKeyKeyPair` now
    /// refines to `:Sign`/`:KeyAgreement`/`:Encrypt` the same way
    /// `CreateKeyPair` does (`dispatcher::purpose_suffix_from_mask`), so
    /// each resolves to its own scope, and the ambiguous bare form is
    /// still rejected the same way bare `CreateKeyPair` is.
    #[test]
    fn rekey_key_pair_refinements_resolve_to_their_own_scopes() {
        for (scope, refined) in [
            ("signing", "ReKeyKeyPair:Sign"),
            ("key-establishment", "ReKeyKeyPair:KeyAgreement"),
            ("encryption", "ReKeyKeyPair:Encrypt"),
        ] {
            let yaml = format!(
                r#"
schema_version: 3
metadata: {{ name: t, description: d, authority: a, effective: "always", scopes: [{scope}] }}
rules:
  - type: algorithm_substitution
    ops: ["{refined}"]
    from: RSA-2048
    to: ML-DSA-44
    reason: t
"#
            );
            load_from_str(&yaml, Path::new("<t>"))
                .unwrap_or_else(|e| panic!("{refined} in scope {scope:?} must load: {e}"));
        }
    }

    #[test]
    fn bare_rekey_key_pair_in_scoped_file_is_rejected() {
        let yaml = r#"
schema_version: 3
metadata: { name: t, description: d, authority: a, effective: "always", scopes: [signing] }
rules:
  - type: algorithm_substitution
    ops: [ReKeyKeyPair]
    from: RSA-2048
    to: ML-DSA-44
    reason: t
"#;
        let err = load_from_str(yaml, Path::new("<t>")).unwrap_err();
        assert!(err.to_string().contains("ambiguous"), "got: {err}");
    }

    #[test]
    fn schema_version_3_is_accepted() {
        // schema_version 3 became valid with the modular-policy plan
        // (adds metadata.scopes); this test used to assert it was rejected.
        let yaml = r#"
schema_version: 3
metadata: { name: t, description: d, authority: a, effective: "always" }
rules: []
"#;
        load_from_str(yaml, Path::new("<t>")).expect("schema_version 3 must load");
    }

    /// The ceiling moved from 2 to 3 (modular-policy plan), not removed —
    /// schema_version 4 is still rejected.
    #[test]
    fn schema_version_4_is_rejected() {
        let yaml = r#"
schema_version: 4
metadata: { name: t, description: d, authority: a, effective: "always" }
rules: []
"#;
        let err = load_from_str(yaml, Path::new("<t>")).unwrap_err();
        assert!(matches!(err, LoaderError::SchemaVersion { found: 4, .. }), "got: {err}");
    }

    /// A2 — a malformed `expires` date is rejected at load time (same
    /// discipline as the A5.3 `effective` validator).
    #[test]
    fn malformed_expires_date_is_rejected() {
        let yaml = r#"
schema_version: 2
metadata: { name: t, description: d, authority: a, effective: "always", expires: "2O30-01-01" }
rules: []
"#;
        let err = load_from_str(yaml, Path::new("<t>")).unwrap_err();
        assert!(err.to_string().contains("metadata.expires"), "got: {err}");
    }

    /// A2 — "never"/"always"/"immediate" are all interchangeable unbounded
    /// synonyms, usable in either `effective` or `expires`.
    #[test]
    fn unbounded_synonyms_are_interchangeable() {
        for (effective, expires) in [("always", "never"), ("immediate", "always"), ("never", "immediate")] {
            let yaml = format!(
                r#"
schema_version: 2
metadata: {{ name: t, description: d, authority: a, effective: "{effective}", expires: "{expires}" }}
rules: []
"#
            );
            load_from_str(&yaml, Path::new("<t>"))
                .unwrap_or_else(|e| panic!("effective={effective:?} expires={expires:?} should load: {e}"));
        }
    }

    /// A5.2 — a field name that IS valid, but on a different rule variant,
    /// must now be rejected (the old cross-variant union let this through
    /// silently — `effective_from` is real, just not on `mechanism_denylist`,
    /// which has no time-window fields at all).
    #[test]
    fn field_valid_on_other_variant_is_rejected() {
        let yaml = r#"
schema_version: 1
metadata: { name: t, description: d, authority: a, effective: "always" }
rules:
  - type: mechanism_denylist
    ops: [Sign]
    mechanisms: [CKM_RSA_PKCS]
    reason: deny legacy RSA
    effective_from: "2030-01-01"
"#;
        assert_eq!(
            first_unknown_rule_field(yaml),
            Some((1, "effective_from".to_string()))
        );
        let err = load_from_str(yaml, std::path::Path::new("<t>")).unwrap_err();
        assert!(err.to_string().contains("unknown field"), "got: {err}");
    }

    /// 2026-07-05 (classical-KEM crypto-agility) — a substitution rule
    /// targeting a consumer op (Decapsulate/DeriveKey/Decrypt) is a fatal
    /// lint finding, not just an engine-level no-op — rejected at load time
    /// (even in non-strict mode, since this is a fail-open-risk position
    /// like `from`) so the mistake is caught when the policy is authored.
    #[test]
    fn substitution_targeting_decapsulate_is_rejected_at_load() {
        let yaml = r#"
schema_version: 1
metadata: { name: t, description: d, authority: a, effective: "always" }
rules:
  - type: algorithm_substitution
    ops: [Decapsulate]
    from: ECDH-P256
    to: ML-KEM-1024
    reason: "should be rejected"
"#;
        let err = load_from_str(yaml, std::path::Path::new("<t>")).unwrap_err();
        assert!(
            err.to_string().contains("consumer op"),
            "expected a consumer-op rejection, got: {err}"
        );
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
