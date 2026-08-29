//! [`PolicyStore`] — filesystem CRUD for `policies/*.yaml` files.
//!
//! Designed so the Hub scenario UI can:
//!
//! - **List** available policy files in the configured directory.
//! - **Load** a policy by name into a [`super::LoadedPolicy`] for display + edit.
//! - **Validate** an edited policy draft *without* activating it.
//! - **Save** a validated draft back to disk (with atomic rename).
//! - **Test** a draft against a sample [`super::PolicyRequest`] for dry-run
//!   evaluation in the UI's "what would this policy decide?" panel.
//!
//! Save semantics: write-then-rename onto the target path so a partially-
//! flushed write never leaves the directory with broken YAML. The on-disk
//! `policies/` directory is the source of truth — Phase 9 audit will
//! commit + push these to git for change history.
//!
//! ## Active-policy persistence
//!
//! The `policies/` directory holds N candidate policies; exactly one is
//! "active" at any moment. To survive container restart without an
//! operator re-flipping the dropdown, the active selection is persisted
//! in a small marker file [`POLICY_STORE_ACTIVE_FILE`] (= `.active`) in
//! the same directory:
//!
//! ```json
//! { "name": "pqc", "fingerprint": "sha256:...", "activated_at": "2026-..." }
//! ```
//!
//! - [`Self::activate_with_engine`] activates a policy AND writes the
//!   marker atomically (validate-then-rename).
//! - [`Self::resume_active`] reads the marker on boot and re-activates
//!   the same policy. No marker → caller decides the default (typically
//!   load `training-permissive.yaml` for sandbox, or refuse to start in
//!   production).
//!
//! This mirrors the way softhsmv3 persists slot/token state on disk so
//! key handles survive engine restarts (PKCS#11 §A) — same pattern, one
//! level up the stack.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::{
    engine::{Engine, UncoveredOps},
    lint::{lint_rules, Finding},
    loader::{load_from_file, load_from_str, LoadedPolicy, LoaderError},
};

/// Filename for the active-policy marker. Conventionally a dotfile so the
/// `*.yaml` filter in [`PolicyStore::list`] ignores it.
pub const POLICY_STORE_ACTIVE_FILE: &str = ".active";

/// Filename for the modular-policy-set marker (2026-08-28 plan). A SEPARATE
/// file from [`POLICY_STORE_ACTIVE_FILE`] rather than a versioned/migrated
/// unified format — deliberately: the legacy marker's shape, and every
/// method that reads/writes it, stay byte-for-byte unchanged (zero risk to
/// their existing tests), and the two are mutually exclusive on the engine
/// side anyway (`Engine::replace_all` vs `Engine::activate` — see
/// `engine.rs`'s module docs), so there is nothing to migrate between them.
pub const POLICY_STORE_ACTIVE_MODULES_FILE: &str = ".active-modules";

/// On-disk record of which policy is currently active. Written by
/// [`PolicyStore::write_active`] / [`PolicyStore::activate_with_engine`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActiveMarker {
    /// Stem of the YAML file (no extension, no path) — same shape as the
    /// names returned by [`PolicyStore::list`].
    pub name: String,
    /// SHA-256 fingerprint of the YAML body at activation time. Lets an
    /// operator detect "policies/<name>.yaml was edited since this marker
    /// was written" — the engine refuses to silently re-activate a
    /// fingerprint-mismatched file (see [`PolicyStore::resume_active`]).
    pub fingerprint: String,
    /// UTC timestamp when the marker was written.
    #[serde(with = "time::serde::rfc3339")]
    pub activated_at: OffsetDateTime,
}

/// On-disk record of the modular policy set (2026-08-28 plan). Written by
/// [`PolicyStore::activate_module_with_engine`] and friends.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActiveModulesMarker {
    /// `"deny"` or `"allow"` — mirrors [`UncoveredOps`] as a plain string so
    /// the marker file stays a stable, hand-readable JSON shape independent
    /// of the Rust enum's internals.
    pub uncovered_ops: String,
    pub modules: Vec<ModuleMarker>,
}

/// One entry in [`ActiveModulesMarker::modules`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModuleMarker {
    pub name: String,
    pub fingerprint: String,
    pub enabled: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub activated_at: OffsetDateTime,
}

#[derive(Clone, Debug)]
pub struct PolicyStore {
    root: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("policy store: {0}")]
    Loader(#[from] LoaderError),

    #[error("policy store: I/O error on {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("policy store: policy name {0:?} is invalid (must be non-empty, no path separators)")]
    BadName(String),

    #[error("policy store: active-marker JSON malformed: {0}")]
    BadMarker(String),

    #[error("policy store: active-marker fingerprint mismatch (marker={marker_fp}, on-disk={disk_fp}) — refusing to resume; operator must re-activate via Hub")]
    FingerprintDrift { marker_fp: String, disk_fp: String },
}

impl PolicyStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// List the filenames (without `.yaml` extension) of every policy in
    /// the store directory. Non-`.yaml` files are silently ignored.
    pub fn list(&self) -> Result<Vec<String>, StoreError> {
        let mut out = Vec::new();
        let entries = std::fs::read_dir(&self.root).map_err(|source| StoreError::Io {
            path: self.root.clone(),
            source,
        })?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("yaml") {
                continue;
            }
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                out.push(stem.to_string());
            }
        }
        out.sort();
        Ok(out)
    }

    /// Load one policy by name.
    pub fn load(&self, name: &str) -> Result<LoadedPolicy, StoreError> {
        let path = self.path_for(name)?;
        Ok(load_from_file(&path)?)
    }

    /// Parse + validate a draft YAML string without touching the disk.
    /// The Hub UI uses this on every keystroke for live syntax checking, so it
    /// is lenient (unknown allowlist algorithm names surface as warnings, not
    /// errors — don't red-flag a half-typed name).
    pub fn validate_draft(&self, yaml: &str) -> Result<LoadedPolicy, StoreError> {
        Ok(load_from_str(yaml, Path::new("<draft>"))?)
    }

    /// Strict validate — the authoring-time gate used before a policy is
    /// persisted or activated (WP2.1). Unknown allowlist algorithm names are
    /// hard errors here so a typo can never reach production.
    pub fn validate_draft_strict(&self, yaml: &str) -> Result<LoadedPolicy, StoreError> {
        Ok(super::loader::load_from_str_strict(yaml, Path::new("<draft>"))?)
    }

    /// C3 (2026-08-28 gaps-remediation plan) — every value-level lint
    /// finding for a draft, fatal and advisory alike, instead of
    /// `validate_draft_strict`'s pass/fail `Result` (which — like every
    /// other `LoaderError`-returning path — reports only the FIRST fatal
    /// finding it hits: 3 rules each with a typo'd algorithm name meant
    /// fix-reload-see-the-next-one, 3 times, in the editor's Check tab).
    /// Structural failures (bad YAML, unknown top-level field, bad schema
    /// version) still short-circuit as a single `StoreError` — those come
    /// from parsing the document itself, before there is a rule list to
    /// lint at all, and the visual editor's own generator never produces
    /// one anyway (its `EditablePolicy` model always serializes a
    /// structurally well-formed document).
    pub fn lint_draft(&self, yaml: &str) -> Result<Vec<Finding>, StoreError> {
        let policy = super::loader::parse_and_structurally_validate(yaml, Path::new("<draft>"))?;
        Ok(lint_rules(&policy.rules, true))
    }

    /// Save a (presumably already-validated) draft to disk under `name`.
    /// Atomic on POSIX: writes to a tempfile, then renames.
    pub fn save(&self, name: &str, yaml: &str) -> Result<(), StoreError> {
        // Validate STRICTLY before touching the disk — never persist a policy
        // with a typo'd algorithm/mechanism name that would silently misfire.
        let _ = self.validate_draft_strict(yaml)?;
        let target = self.path_for(name)?;
        let tmp = target.with_extension("yaml.tmp");
        std::fs::write(&tmp, yaml).map_err(|source| StoreError::Io {
            path: tmp.clone(),
            source,
        })?;
        std::fs::rename(&tmp, &target).map_err(|source| StoreError::Io {
            path: target,
            source,
        })?;
        Ok(())
    }

    /// Dry-run: build a throw-away engine from `yaml`, evaluate `req`, drop.
    /// Used by the Hub UI's "test this policy" button. Side-effect-free.
    pub fn dry_run(
        &self,
        yaml: &str,
        req: &super::request::PolicyRequest,
    ) -> Result<super::Decision, StoreError> {
        let loaded = self.validate_draft(yaml)?;
        let engine = Engine::deny_all();
        engine.replace_all(loaded).expect("activation in dry_run must succeed");
        Ok(engine.evaluate(req))
    }

    // ── Active-policy persistence (.active marker) ──────────────────────

    /// Path to the active-marker file inside the store root.
    pub fn active_marker_path(&self) -> PathBuf {
        self.root.join(POLICY_STORE_ACTIVE_FILE)
    }

    /// Read the on-disk active-policy marker, if present. `Ok(None)` for
    /// "no marker on disk" (first boot, or after [`Self::clear_active`]).
    pub fn read_active(&self) -> Result<Option<ActiveMarker>, StoreError> {
        let path = self.active_marker_path();
        let body = match std::fs::read_to_string(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(StoreError::Io { path, source }),
        };
        let marker: ActiveMarker = serde_json::from_str(&body)
            .map_err(|e| StoreError::BadMarker(e.to_string()))?;
        Ok(Some(marker))
    }

    /// Write the active-policy marker atomically (validate-then-rename
    /// onto `.active`). Called automatically by
    /// [`Self::activate_with_engine`]; the standalone form exists for
    /// tools that need to drop a marker without running the engine
    /// (e.g. ops bootstrap scripts).
    pub fn write_active(&self, name: &str, fingerprint: &str) -> Result<(), StoreError> {
        // Name must reference a real policy file — fail fast if not.
        let _ = self.path_for(name)?;
        let marker = ActiveMarker {
            name: name.to_string(),
            fingerprint: fingerprint.to_string(),
            activated_at: OffsetDateTime::now_utc(),
        };
        let body = serde_json::to_string_pretty(&marker)
            .map_err(|e| StoreError::BadMarker(e.to_string()))?;
        let target = self.active_marker_path();
        let tmp = self.root.join(format!("{POLICY_STORE_ACTIVE_FILE}.tmp"));
        std::fs::write(&tmp, body).map_err(|source| StoreError::Io {
            path: tmp.clone(),
            source,
        })?;
        std::fs::rename(&tmp, &target).map_err(|source| StoreError::Io { path: target, source })?;
        Ok(())
    }

    /// Delete the active marker. Idempotent (no-op if absent). Tests +
    /// "go back to default" tooling use this.
    pub fn clear_active(&self) -> Result<(), StoreError> {
        let path = self.active_marker_path();
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(StoreError::Io { path, source }),
        }
    }

    /// Combined: load + activate on the engine + write the marker.
    /// Hub UI's policy-dropdown `Activate` button maps to this.
    ///
    /// Returns the prior marker (if any) so the caller can audit the
    /// transition. The engine-internal `PolicyAudit` also records the
    /// activation via its existing path.
    pub fn activate_with_engine(
        &self,
        name: &str,
        engine: &Engine,
    ) -> Result<Option<ActiveMarker>, StoreError> {
        let loaded = self.load(name)?;
        let fingerprint = super::policy::Policy::fingerprint(&loaded.source);
        let prior = self.read_active()?;
        engine
            .replace_all(loaded)
            .map_err(|e| StoreError::BadMarker(format!("engine activate: {e}")))?;
        self.write_active(name, &fingerprint)?;
        Ok(prior)
    }

    /// Boot path: read `.active`, re-load the same YAML, re-activate on
    /// the engine. Returns the resumed marker, or `Ok(None)` if there
    /// was no marker on disk (caller picks a default).
    ///
    /// **Drift protection:** if the YAML file's current fingerprint
    /// differs from the marker, returns
    /// [`StoreError::FingerprintDrift`] rather than silently activating
    /// an edited policy — operator must explicitly re-activate via the
    /// Hub (this is exactly the "edited a policy file out-of-band" case
    /// that should NOT auto-resume).
    pub fn resume_active(&self, engine: &Engine) -> Result<Option<ActiveMarker>, StoreError> {
        let marker = match self.read_active()? {
            Some(m) => m,
            None => return Ok(None),
        };
        let loaded = self.load(&marker.name)?;
        let current_fp = super::policy::Policy::fingerprint(&loaded.source);
        if current_fp != marker.fingerprint {
            return Err(StoreError::FingerprintDrift {
                marker_fp: marker.fingerprint,
                disk_fp: current_fp,
            });
        }
        engine
            .replace_all(loaded)
            .map_err(|e| StoreError::BadMarker(format!("engine activate: {e}")))?;
        Ok(Some(marker))
    }

    // ── Modular policy set persistence (.active-modules marker,
    // 2026-08-28 plan) — parallels the legacy methods above one-for-one,
    // over the separate marker file and `Engine::activate`/`deactivate`/
    // `set_module_enabled`/`clear_modules` instead of `replace_all`. ──────

    /// Path to the modules marker file inside the store root.
    pub fn active_modules_marker_path(&self) -> PathBuf {
        self.root.join(POLICY_STORE_ACTIVE_MODULES_FILE)
    }

    /// Read the on-disk modules marker, if present. `Ok(None)` — no
    /// modules have ever been activated (or [`Self::clear_modules_with_engine`]
    /// ran).
    pub fn read_active_modules(&self) -> Result<Option<ActiveModulesMarker>, StoreError> {
        let path = self.active_modules_marker_path();
        let body = match std::fs::read_to_string(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(StoreError::Io { path, source }),
        };
        let marker: ActiveModulesMarker =
            serde_json::from_str(&body).map_err(|e| StoreError::BadMarker(e.to_string()))?;
        Ok(Some(marker))
    }

    fn write_active_modules(&self, marker: &ActiveModulesMarker) -> Result<(), StoreError> {
        let body = serde_json::to_string_pretty(marker)
            .map_err(|e| StoreError::BadMarker(e.to_string()))?;
        let target = self.active_modules_marker_path();
        let tmp = self.root.join(format!("{POLICY_STORE_ACTIVE_MODULES_FILE}.tmp"));
        std::fs::write(&tmp, body).map_err(|source| StoreError::Io { path: tmp.clone(), source })?;
        std::fs::rename(&tmp, &target).map_err(|source| StoreError::Io { path: target, source })?;
        Ok(())
    }

    /// Delete the modules marker. Idempotent.
    pub fn clear_active_modules(&self) -> Result<(), StoreError> {
        let path = self.active_modules_marker_path();
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(StoreError::Io { path, source }),
        }
    }

    /// Activate `name` as a module on `engine` and upsert it into the
    /// modules marker (creating the file with `uncovered_ops: "deny"` if
    /// this is the first module ever activated in this store). Mirrors
    /// [`Self::activate_with_engine`]'s shape but for the additive,
    /// non-replacing `Engine::activate`.
    pub fn activate_module_with_engine(&self, name: &str, engine: &Engine) -> Result<(), StoreError> {
        let loaded = self.load(name)?;
        let fingerprint = super::policy::Policy::fingerprint(&loaded.source);
        engine
            .activate(loaded)
            .map_err(|e| StoreError::BadMarker(format!("engine activate: {e}")))?;
        let mut marker = self.read_active_modules()?.unwrap_or_else(|| ActiveModulesMarker {
            uncovered_ops: "deny".to_string(),
            modules: Vec::new(),
        });
        marker.modules.retain(|m| m.name != name);
        marker.modules.push(ModuleMarker {
            name: name.to_string(),
            fingerprint,
            enabled: true,
            activated_at: OffsetDateTime::now_utc(),
        });
        self.write_active_modules(&marker)
    }

    /// Deactivate (remove) `name` from both the engine and the marker.
    /// `true` if it was present on the engine.
    pub fn deactivate_module_with_engine(
        &self,
        name: &str,
        engine: &Engine,
    ) -> Result<bool, StoreError> {
        let removed = engine.deactivate(name);
        if let Some(mut marker) = self.read_active_modules()? {
            let before = marker.modules.len();
            marker.modules.retain(|m| m.name != name);
            if marker.modules.len() != before {
                self.write_active_modules(&marker)?;
            }
        }
        Ok(removed)
    }

    /// Enable/disable `name` on both the engine and the marker. `true` if
    /// the name was found on the engine.
    pub fn set_module_enabled_with_engine(
        &self,
        name: &str,
        enabled: bool,
        engine: &Engine,
    ) -> Result<bool, StoreError> {
        let found = engine.set_module_enabled(name, enabled);
        if found {
            if let Some(mut marker) = self.read_active_modules()? {
                if let Some(m) = marker.modules.iter_mut().find(|m| m.name == name) {
                    m.enabled = enabled;
                    self.write_active_modules(&marker)?;
                }
            }
        }
        Ok(found)
    }

    /// Clear every module from both the engine and the marker — the
    /// fail-closed OFF (see `Engine::clear_modules`'s doc comment).
    pub fn clear_modules_with_engine(&self, engine: &Engine) -> Result<(), StoreError> {
        engine.clear_modules();
        self.clear_active_modules()
    }

    /// Set the uncovered-ops mode on both the engine and the marker.
    /// `mode` must be `"deny"` or `"allow"`.
    pub fn set_uncovered_ops_with_engine(
        &self,
        mode: &str,
        engine: &Engine,
    ) -> Result<(), StoreError> {
        let parsed = match mode {
            "deny" => UncoveredOps::Deny,
            "allow" => UncoveredOps::Allow,
            other => {
                return Err(StoreError::BadMarker(format!(
                    "unknown uncovered_ops mode {other:?} (expected \"deny\" or \"allow\")"
                )))
            }
        };
        engine.set_uncovered_ops(parsed);
        let mut marker = self.read_active_modules()?.unwrap_or_else(|| ActiveModulesMarker {
            uncovered_ops: "deny".to_string(),
            modules: Vec::new(),
        });
        marker.uncovered_ops = mode.to_string();
        self.write_active_modules(&marker)
    }

    /// Boot path: read the modules marker (if present) and re-activate
    /// every entry on `engine`, restoring `uncovered_ops` and each
    /// module's `enabled` flag. Same fingerprint-drift protection as
    /// [`Self::resume_active`] — an out-of-band edit to a module's YAML
    /// refuses to resume rather than silently activating the edited file.
    /// Returns the resumed marker, or `Ok(None)` if no modules marker
    /// exists on disk.
    pub fn resume_active_modules(
        &self,
        engine: &Engine,
    ) -> Result<Option<ActiveModulesMarker>, StoreError> {
        let marker = match self.read_active_modules()? {
            Some(m) => m,
            None => return Ok(None),
        };
        engine.set_uncovered_ops(if marker.uncovered_ops == "allow" {
            UncoveredOps::Allow
        } else {
            UncoveredOps::Deny
        });
        for m in &marker.modules {
            let loaded = self.load(&m.name)?;
            let current_fp = super::policy::Policy::fingerprint(&loaded.source);
            if current_fp != m.fingerprint {
                return Err(StoreError::FingerprintDrift {
                    marker_fp: m.fingerprint.clone(),
                    disk_fp: current_fp,
                });
            }
            engine
                .activate(loaded)
                .map_err(|e| StoreError::BadMarker(format!("engine activate: {e}")))?;
            if !m.enabled {
                engine.set_module_enabled(&m.name, false);
            }
        }
        Ok(Some(marker))
    }

    fn path_for(&self, name: &str) -> Result<PathBuf, StoreError> {
        if name.is_empty() || name.contains('/') || name.contains('\\') || name.contains("..") {
            return Err(StoreError::BadName(name.to_string()));
        }
        Ok(self.root.join(format!("{name}.yaml")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use time::OffsetDateTime;

    fn tmp_dir(prefix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "pqctoday-policy-test-{}-{}",
            prefix,
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn list_then_load_round_trip() {
        let dir = tmp_dir("list");
        let yaml = r#"
schema_version: 1
metadata:
  name: t
  description: t
  authority: t
  effective: "always"
rules: []
"#;
        std::fs::write(dir.join("alpha.yaml"), yaml).unwrap();
        std::fs::write(dir.join("beta.yaml"), yaml).unwrap();
        std::fs::write(dir.join("ignore.txt"), "not yaml").unwrap();

        let store = PolicyStore::new(&dir);
        let names = store.list().unwrap();
        assert_eq!(names, vec!["alpha", "beta"]);

        let loaded = store.load("alpha").unwrap();
        assert_eq!(loaded.policy.metadata.name, "t");
    }

    #[test]
    fn save_is_atomic_validates_first() {
        let dir = tmp_dir("save");
        let store = PolicyStore::new(&dir);

        let good = r#"
schema_version: 1
metadata:
  name: good
  description: good
  authority: t
  effective: "always"
rules: []
"#;
        store.save("good", good).unwrap();
        assert!(dir.join("good.yaml").exists());

        // Bad YAML must fail before touching disk.
        let bad = "schema_version: 99\nmetadata: not-a-map\n";
        assert!(store.save("bad", bad).is_err());
        assert!(!dir.join("bad.yaml").exists());
        // No leftover .tmp either.
        assert!(!dir.join("bad.yaml.tmp").exists());
    }

    #[test]
    fn dry_run_evaluates_without_persisting() {
        let dir = tmp_dir("dry");
        let store = PolicyStore::new(&dir);
        let yaml = r#"
schema_version: 1
metadata:
  name: dry
  description: dry-run
  authority: t
  effective: "always"
rules:
  - type: algorithm_denylist
    ops: [Sign]
    algorithms: [RSA]
    reason: "RSA banned"
"#;
        let attrs = HashMap::new();
        let req = super::super::request::PolicyRequest::minimal(
            "Sign",
            Some("RSA"),
            OffsetDateTime::UNIX_EPOCH,
            "dry-1",
            &attrs,
        );
        let d = store.dry_run(yaml, &req).unwrap();
        assert!(d.is_deny());
        // Verify no file was written.
        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn lint_draft_reports_every_finding_not_just_the_first() {
        // C3 (2026-08-28 gaps-remediation plan) — two INDEPENDENT typos, in
        // two different rules. `validate_draft_strict` would surface only
        // the first as a hard `Err`; `lint_draft` must return both.
        let dir = tmp_dir("lint-draft");
        let store = PolicyStore::new(&dir);
        let yaml = r#"
schema_version: 1
metadata:
  name: two-typos
  description: t
  authority: t
  effective: "always"
rules:
  - type: algorithm_denylist
    ops: [Sign]
    algorithms: [RSAA]
    reason: "typo one"
  - type: algorithm_denylist
    ops: [Encrypt]
    algorithms: [AES-2566]
    reason: "typo two"
"#;
        let findings = store.lint_draft(yaml).unwrap();
        let fatal: Vec<_> = findings.iter().filter(|f| f.fatal).collect();
        assert_eq!(fatal.len(), 2, "both typos must be reported, got {fatal:?}");
        assert!(fatal.iter().any(|f| f.value == "RSAA"));
        assert!(fatal.iter().any(|f| f.value == "AES-2566"));

        // A clean draft reports no findings at all.
        let clean = r#"
schema_version: 1
metadata:
  name: clean
  description: t
  authority: t
  effective: "always"
rules:
  - type: algorithm_denylist
    ops: [Sign]
    algorithms: [RSA]
    reason: "real algorithm name"
"#;
        assert!(store.lint_draft(clean).unwrap().is_empty());
    }

    #[test]
    fn bad_name_rejected() {
        let dir = tmp_dir("name");
        let store = PolicyStore::new(&dir);
        assert!(matches!(store.load(""), Err(StoreError::BadName(_))));
        assert!(matches!(store.load("../etc/passwd"), Err(StoreError::BadName(_))));
        assert!(matches!(store.load("foo/bar"), Err(StoreError::BadName(_))));
    }

    // ── Active-policy persistence ───────────────────────────────────────

    fn write_yaml(dir: &Path, name: &str) {
        std::fs::write(
            dir.join(format!("{name}.yaml")),
            format!(
                "schema_version: 1\nmetadata: {{ name: {name}, description: {name}, authority: t, effective: always }}\nrules: []\n",
            ),
        )
        .unwrap();
    }

    #[test]
    fn read_active_returns_none_when_no_marker() {
        let dir = tmp_dir("active-none");
        let store = PolicyStore::new(&dir);
        assert!(store.read_active().unwrap().is_none());
    }

    #[test]
    fn write_then_read_active_round_trip() {
        let dir = tmp_dir("active-rw");
        write_yaml(&dir, "classical");
        let store = PolicyStore::new(&dir);
        store.write_active("classical", "sha256:abc123").unwrap();
        let marker = store.read_active().unwrap().expect("marker present");
        assert_eq!(marker.name, "classical");
        assert_eq!(marker.fingerprint, "sha256:abc123");
        // Marker file is excluded from list (dotfile, no .yaml extension).
        assert_eq!(store.list().unwrap(), vec!["classical"]);
    }

    #[test]
    fn write_active_rejects_bad_name() {
        let dir = tmp_dir("active-bad");
        let store = PolicyStore::new(&dir);
        assert!(matches!(
            store.write_active("../etc/passwd", "sha256:x"),
            Err(StoreError::BadName(_))
        ));
    }

    #[test]
    fn clear_active_is_idempotent() {
        let dir = tmp_dir("active-clear");
        let store = PolicyStore::new(&dir);
        store.clear_active().unwrap(); // no-op when absent
        write_yaml(&dir, "p");
        store.write_active("p", "sha256:0").unwrap();
        assert!(store.read_active().unwrap().is_some());
        store.clear_active().unwrap();
        assert!(store.read_active().unwrap().is_none());
        // Second call still no-ops.
        store.clear_active().unwrap();
    }

    #[test]
    fn activate_with_engine_writes_marker_and_engine_observes_policy() {
        let dir = tmp_dir("aw-engine");
        write_yaml(&dir, "pqc");
        let store = PolicyStore::new(&dir);
        let engine = super::super::Engine::deny_all();

        let prior = store.activate_with_engine("pqc", &engine).unwrap();
        assert!(prior.is_none(), "no prior marker on first activate");

        // Marker now present + engine has the policy active.
        let m = store.read_active().unwrap().unwrap();
        assert_eq!(m.name, "pqc");
        assert!(m.fingerprint.starts_with("sha256:"));
        assert_eq!(engine.active().unwrap().policy.metadata.name, "pqc");
    }

    #[test]
    fn activate_with_engine_returns_prior_marker() {
        let dir = tmp_dir("aw-prior");
        write_yaml(&dir, "a");
        write_yaml(&dir, "b");
        let store = PolicyStore::new(&dir);
        let engine = super::super::Engine::deny_all();

        store.activate_with_engine("a", &engine).unwrap();
        let prior = store.activate_with_engine("b", &engine).unwrap();
        let prior = prior.expect("second activate should return prior");
        assert_eq!(prior.name, "a");
        assert_eq!(engine.active().unwrap().policy.metadata.name, "b");
    }

    #[test]
    fn resume_active_replays_marker_on_boot() {
        let dir = tmp_dir("resume-ok");
        write_yaml(&dir, "pqc");
        let store = PolicyStore::new(&dir);

        // First boot: operator activates pqc.
        let engine1 = super::super::Engine::deny_all();
        store.activate_with_engine("pqc", &engine1).unwrap();
        let original_fp = store.read_active().unwrap().unwrap().fingerprint;

        // Restart simulation: fresh engine; resume reads marker + re-activates.
        let engine2 = super::super::Engine::deny_all();
        let resumed = store.resume_active(&engine2).unwrap().expect("must resume");
        assert_eq!(resumed.name, "pqc");
        assert_eq!(resumed.fingerprint, original_fp);
        assert_eq!(engine2.active().unwrap().policy.metadata.name, "pqc");
    }

    #[test]
    fn resume_active_returns_none_when_no_marker() {
        let dir = tmp_dir("resume-empty");
        let store = PolicyStore::new(&dir);
        let engine = super::super::Engine::deny_all();
        let resumed = store.resume_active(&engine).unwrap();
        assert!(resumed.is_none());
        // Engine still in its prior (no-policy) state.
        assert!(engine.active().is_none());
    }

    #[test]
    fn resume_active_rejects_drifted_yaml() {
        let dir = tmp_dir("resume-drift");
        write_yaml(&dir, "p");
        let store = PolicyStore::new(&dir);
        let engine1 = super::super::Engine::deny_all();
        store.activate_with_engine("p", &engine1).unwrap();

        // Operator edits the YAML out-of-band between sessions (e.g. via vim,
        // not through the Hub). Fingerprint now mismatches.
        std::fs::write(
            dir.join("p.yaml"),
            "schema_version: 1\nmetadata: { name: p, description: edited, authority: t, effective: always }\nrules: []\n",
        ).unwrap();

        let engine2 = super::super::Engine::deny_all();
        let err = store.resume_active(&engine2).unwrap_err();
        assert!(matches!(err, StoreError::FingerprintDrift { .. }));
        // Engine NOT activated (refused to silently load drifted policy).
        assert!(engine2.active().is_none());
    }

    // ── Modular policy set persistence (.active-modules, 2026-08-28 plan) ──

    fn write_module_yaml(dir: &Path, name: &str, scope: &str) {
        std::fs::write(
            dir.join(format!("{name}.yaml")),
            format!(
                "schema_version: 3\nmetadata: {{ name: {name}, description: {name}, authority: t, effective: always, scopes: [{scope}] }}\nrules: []\n",
            ),
        )
        .unwrap();
    }

    #[test]
    fn activate_module_with_engine_writes_marker_and_engine_observes_it() {
        let dir = tmp_dir("mod-activate");
        write_module_yaml(&dir, "sig", "signing");
        let store = PolicyStore::new(&dir);
        let engine = super::super::Engine::deny_all();

        store.activate_module_with_engine("sig", &engine).unwrap();
        assert_eq!(engine.modules().len(), 1);
        let marker = store.read_active_modules().unwrap().expect("marker must exist");
        assert_eq!(marker.modules.len(), 1);
        assert_eq!(marker.modules[0].name, "sig");
        assert!(marker.modules[0].enabled);
        assert_eq!(marker.uncovered_ops, "deny");
    }

    #[test]
    fn activate_module_with_engine_upserts_by_name() {
        let dir = tmp_dir("mod-upsert");
        write_module_yaml(&dir, "sig", "signing");
        let store = PolicyStore::new(&dir);
        let engine = super::super::Engine::deny_all();
        store.activate_module_with_engine("sig", &engine).unwrap();
        store.activate_module_with_engine("sig", &engine).unwrap(); // re-activate, not a duplicate
        assert_eq!(engine.modules().len(), 1);
        let marker = store.read_active_modules().unwrap().unwrap();
        assert_eq!(marker.modules.len(), 1);
    }

    #[test]
    fn deactivate_module_with_engine_removes_from_both() {
        let dir = tmp_dir("mod-deactivate");
        write_module_yaml(&dir, "sig", "signing");
        let store = PolicyStore::new(&dir);
        let engine = super::super::Engine::deny_all();
        store.activate_module_with_engine("sig", &engine).unwrap();

        assert!(store.deactivate_module_with_engine("sig", &engine).unwrap());
        assert!(engine.modules().is_empty());
        assert!(store.read_active_modules().unwrap().unwrap().modules.is_empty());
        // Deactivating something absent is a clean `false`, not an error.
        assert!(!store.deactivate_module_with_engine("sig", &engine).unwrap());
    }

    #[test]
    fn set_module_enabled_with_engine_updates_both() {
        let dir = tmp_dir("mod-enable");
        write_module_yaml(&dir, "sig", "signing");
        let store = PolicyStore::new(&dir);
        let engine = super::super::Engine::deny_all();
        store.activate_module_with_engine("sig", &engine).unwrap();

        assert!(store.set_module_enabled_with_engine("sig", false, &engine).unwrap());
        let marker = store.read_active_modules().unwrap().unwrap();
        assert!(!marker.modules[0].enabled);
        assert!(!store.set_module_enabled_with_engine("nope", false, &engine).unwrap());
    }

    #[test]
    fn clear_modules_with_engine_empties_both() {
        let dir = tmp_dir("mod-clear");
        write_module_yaml(&dir, "sig", "signing");
        write_module_yaml(&dir, "kem", "key-establishment");
        let store = PolicyStore::new(&dir);
        let engine = super::super::Engine::deny_all();
        store.activate_module_with_engine("sig", &engine).unwrap();
        store.activate_module_with_engine("kem", &engine).unwrap();

        store.clear_modules_with_engine(&engine).unwrap();
        assert!(engine.modules().is_empty());
        assert!(store.read_active_modules().unwrap().is_none());
    }

    #[test]
    fn set_uncovered_ops_with_engine_persists_and_applies() {
        let dir = tmp_dir("mod-uncov");
        let store = PolicyStore::new(&dir);
        let engine = super::super::Engine::deny_all();

        store.set_uncovered_ops_with_engine("allow", &engine).unwrap();
        assert_eq!(engine.uncovered_ops(), super::super::UncoveredOps::Allow);
        assert_eq!(store.read_active_modules().unwrap().unwrap().uncovered_ops, "allow");

        let err = store.set_uncovered_ops_with_engine("sideways", &engine).unwrap_err();
        assert!(matches!(err, StoreError::BadMarker(_)));
    }

    #[test]
    fn resume_active_modules_replays_the_full_set_on_boot() {
        let dir = tmp_dir("mod-resume");
        write_module_yaml(&dir, "sig", "signing");
        write_module_yaml(&dir, "kem", "key-establishment");
        let store = PolicyStore::new(&dir);

        let engine1 = super::super::Engine::deny_all();
        store.activate_module_with_engine("sig", &engine1).unwrap();
        store.activate_module_with_engine("kem", &engine1).unwrap();
        store.set_module_enabled_with_engine("kem", false, &engine1).unwrap();
        store.set_uncovered_ops_with_engine("allow", &engine1).unwrap();

        let engine2 = super::super::Engine::deny_all();
        let resumed = store.resume_active_modules(&engine2).unwrap().expect("marker must resume");
        assert_eq!(resumed.modules.len(), 2);
        assert_eq!(engine2.modules().len(), 2);
        assert_eq!(engine2.uncovered_ops(), super::super::UncoveredOps::Allow);
        let kem_entry = engine2
            .modules()
            .into_iter()
            .find(|(p, _)| p.policy.metadata.name == "kem")
            .expect("kem must be present");
        assert!(!kem_entry.1, "kem's disabled state must survive resume");
    }

    #[test]
    fn resume_active_modules_rejects_drifted_module() {
        let dir = tmp_dir("mod-resume-drift");
        write_module_yaml(&dir, "sig", "signing");
        let store = PolicyStore::new(&dir);
        let engine1 = super::super::Engine::deny_all();
        store.activate_module_with_engine("sig", &engine1).unwrap();

        // Out-of-band edit after the marker was written.
        std::fs::write(
            dir.join("sig.yaml"),
            "schema_version: 3\nmetadata: { name: sig, description: edited, authority: t, effective: always, scopes: [signing] }\nrules: []\n",
        )
        .unwrap();

        let engine2 = super::super::Engine::deny_all();
        let err = store.resume_active_modules(&engine2).unwrap_err();
        assert!(matches!(err, StoreError::FingerprintDrift { .. }));
        assert!(engine2.modules().is_empty(), "refused resume must not partially activate");
    }

    #[test]
    fn resume_active_modules_returns_none_when_no_marker() {
        let dir = tmp_dir("mod-resume-none");
        let store = PolicyStore::new(&dir);
        let engine = super::super::Engine::deny_all();
        assert!(store.resume_active_modules(&engine).unwrap().is_none());
    }

    #[test]
    fn clear_active_modules_is_idempotent() {
        let dir = tmp_dir("mod-clear-idempotent");
        let store = PolicyStore::new(&dir);
        store.clear_active_modules().unwrap(); // no-op when absent
        write_module_yaml(&dir, "sig", "signing");
        let engine = super::super::Engine::deny_all();
        store.activate_module_with_engine("sig", &engine).unwrap();
        assert!(store.read_active_modules().unwrap().is_some());
        store.clear_active_modules().unwrap();
        assert!(store.read_active_modules().unwrap().is_none());
        store.clear_active_modules().unwrap(); // still a no-op
    }
}
