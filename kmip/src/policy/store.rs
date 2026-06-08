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

use std::path::{Path, PathBuf};

use super::{
    engine::Engine,
    loader::{load_from_file, load_from_str, LoadedPolicy, LoaderError},
};

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
    /// The Hub UI uses this on every keystroke for live syntax checking.
    pub fn validate_draft(&self, yaml: &str) -> Result<LoadedPolicy, StoreError> {
        Ok(load_from_str(yaml, Path::new("<draft>"))?)
    }

    /// Save a (presumably already-validated) draft to disk under `name`.
    /// Atomic on POSIX: writes to a tempfile, then renames.
    pub fn save(&self, name: &str, yaml: &str) -> Result<(), StoreError> {
        // Validate before touching the disk — never write garbage.
        let _ = self.validate_draft(yaml)?;
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
        engine.activate(loaded).expect("activation in dry_run must succeed");
        Ok(engine.evaluate(req))
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
    fn bad_name_rejected() {
        let dir = tmp_dir("name");
        let store = PolicyStore::new(&dir);
        assert!(matches!(store.load(""), Err(StoreError::BadName(_))));
        assert!(matches!(store.load("../etc/passwd"), Err(StoreError::BadName(_))));
        assert!(matches!(store.load("foo/bar"), Err(StoreError::BadName(_))));
    }
}
