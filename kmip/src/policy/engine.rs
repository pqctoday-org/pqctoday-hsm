//! [`Engine`] — the Plane 1 evaluator.
//!
//! ## Pipeline placement
//!
//! ```text
//!   application
//!       │  (KMIP TTLV request over TLS)
//!       ▼
//!   ┌──────────────────────────┐
//!   │  Plane 1 — Engine        │   ← this module
//!   │  evaluate(PolicyRequest) │
//!   └──────────┬───────────────┘
//!              │ Decision
//!              ▼
//!   Plane 2 — dispatcher → op handler (Phase 5)
//!              │
//!              ▼
//!   Plane 3 — softhsmrustv3::native (typed in-process path)
//! ```
//!
//! The engine ALWAYS runs before Plane 2 dispatch. A `Deny` short-circuits
//! the request with a KMIP `OperationFailed` response. A `RekeyAndProceed`
//! triggers the dispatcher's rekey transaction. A bare `Allow` flows
//! straight to the op handler — possibly with an `algorithm_override`.
//!
//! ## Two-pass evaluation
//!
//! 1. **Pass 1 — algorithm resolution.** Walk all rules; collect substitutions
//!    from `AlgorithmDefault` (when request.algorithm is `None`) and
//!    `AlgorithmSubstitution` (when request.algorithm matches `from`).
//!    **Last match wins** — later rules in the file override earlier ones,
//!    so policies can layer "general rule → specific exception".
//!
//! 2. **Pass 2 — gating.** Walk gating rules in order; first `Deny` wins.
//!    Gating rules operate against the *resolved* algorithm from Pass 1, so
//!    a substitution rule that bumps RSA → ML-DSA-65 is then evaluated
//!    against the allowlist as ML-DSA-65 (and passes if PQC is allowlisted).
//!
//! ## Rekey detection
//!
//! If Pass 1 produced a substitution AND the request targets an existing
//! object whose `current_object_algorithm` differs from the substituted
//! value, the engine emits [`Decision::RekeyAndProceed`] instead of
//! `Allow{override}`. Pass 2 still runs against the *substituted* algorithm
//! — if the substitution would itself violate a gating rule, the Deny still
//! wins (no orphan rekey to a banned algorithm).

use std::sync::{Arc, RwLock};
use time::OffsetDateTime;

use super::{
    audit::PolicyAudit,
    decision::{Decision, DenyReason},
    loader::LoadedPolicy,
    policy::Policy,
    request::PolicyRequest,
};

/// Engine state. Cheap to `.clone()` — the policy + audit live behind `Arc`.
#[derive(Clone)]
pub struct Engine {
    inner: Arc<RwLock<EngineInner>>,
    audit: Arc<PolicyAudit>,
}

struct EngineInner {
    /// `None` means "no policy loaded" — engine denies-all by default.
    active: Option<ActivePolicy>,
}

/// Currently-active policy + its source fingerprint. Audit entries cite the
/// fingerprint so an operator can correlate a decision back to the exact
/// YAML revision.
#[derive(Clone, Debug)]
pub struct ActivePolicy {
    pub policy: Arc<Policy>,
    pub source_fingerprint: String,
    pub source_path: String,
    pub loaded_at: OffsetDateTime,
}

impl Engine {
    /// Build a deny-all engine — the safe default when no policy file is
    /// supplied at startup. Sandbox / dev should call [`Self::permissive`]
    /// or load the `training-permissive.yaml` policy explicitly.
    ///
    /// Audit events land in a private 1024-slot ring. Use
    /// [`Self::with_global_sink`] if the Plane-7 server needs to fan events
    /// into a cross-plane sink that also captures KMIP + PKCS#11 events.
    pub fn deny_all() -> Self {
        Self {
            inner: Arc::new(RwLock::new(EngineInner { active: None })),
            audit: Arc::new(PolicyAudit::new(1024)),
        }
    }

    /// Build a deny-all engine wired to a cross-plane audit sink. Plane-1
    /// events ALSO land in a private 1024-slot ring for the Hub UI's
    /// dedicated Plane-1 panel.
    pub fn with_global_sink(sink: std::sync::Arc<dyn crate::auditlog::AuditSink>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(EngineInner { active: None })),
            audit: Arc::new(PolicyAudit::with_global_sink(1024, sink)),
        }
    }

    /// Build an allow-all engine — for unit tests and one-off sandbox runs.
    /// Production code SHOULD load a real policy file.
    pub fn permissive() -> Self {
        let yaml = r#"
schema_version: 1
metadata:
  name: built-in-permissive
  description: built-in allow-all (tests / sandbox)
  authority: pqctoday-hsm/engine
  effective: "always"
rules: []
"#;
        let loaded = super::loader::load_from_str(yaml, std::path::Path::new("<built-in>"))
            .expect("built-in permissive policy must parse");
        let eng = Self::deny_all();
        eng.activate(loaded).expect("built-in permissive policy must activate");
        eng
    }

    /// Activate `loaded` as the engine's policy. Atomic swap: in-flight
    /// `evaluate` calls observe either the old or the new policy, never a
    /// partially-applied one. Returns the prior policy's fingerprint (if any)
    /// for audit logging.
    pub fn activate(&self, loaded: LoadedPolicy) -> Result<Option<String>, ActivateError> {
        let LoadedPolicy {
            policy,
            source,
            warnings,
        } = loaded;
        let now = OffsetDateTime::now_utc();
        let active = ActivePolicy {
            source_fingerprint: Policy::fingerprint(&source),
            policy: Arc::new(policy),
            source_path: "<loaded>".into(),
            loaded_at: now,
        };
        let mut inner = self.inner.write().expect("engine state poisoned");
        let prior_fp = inner.active.as_ref().map(|p| p.source_fingerprint.clone());
        let new_fp = active.source_fingerprint.clone();
        let new_name = active.policy.metadata.name.clone();
        inner.active = Some(active);
        drop(inner);
        self.audit.record_activation(now, &new_name, &new_fp, prior_fp.as_deref(), &warnings);
        Ok(prior_fp)
    }

    /// Snapshot the currently-active policy. Cheap (`Arc::clone`).
    pub fn active(&self) -> Option<ActivePolicy> {
        self.inner.read().expect("engine state poisoned").active.clone()
    }

    /// Access the audit log for export to the Hub UI's policy-history panel.
    pub fn audit(&self) -> Arc<PolicyAudit> {
        Arc::clone(&self.audit)
    }

    /// Heart of Plane 1. See module docs for the two-pass semantics.
    pub fn evaluate(&self, req: &PolicyRequest) -> Decision {
        let snapshot = match self.active() {
            Some(s) => s,
            None => {
                let d = Decision::Deny {
                    kmip_reason: DenyReason::PolicyNotLoaded,
                    human: "Engine has no active policy; denying by default.".into(),
                    fired_rule_index: 0,
                };
                self.audit.record_decision(req, &d, "<no-policy>");
                return d;
            }
        };

        // ── Pass 1: resolve algorithm ────────────────────────────────────
        let mut resolved: Option<String> = req.algorithm.map(|s| s.to_string());
        let mut substituted_by: Option<usize> = None;
        for (i, rule) in snapshot.policy.rules.iter().enumerate() {
            let current_view: Option<&str> = resolved.as_deref();
            if let Some(sub) = rule.resolve_pass1(req, current_view) {
                resolved = Some(sub.new_algorithm);
                substituted_by = Some(i + 1);
            }
        }

        // ── Pass 2: gating ──────────────────────────────────────────────
        let resolved_view: Option<&str> = resolved.as_deref();
        for (i, rule) in snapshot.policy.rules.iter().enumerate() {
            if let Some(deny) = rule.check_pass2(req, resolved_view) {
                let d = Decision::Deny {
                    kmip_reason: deny.kmip_reason,
                    human: deny.human,
                    fired_rule_index: i + 1,
                };
                self.audit.record_decision(req, &d, &snapshot.source_fingerprint);
                return d;
            }
        }

        // ── Pass 1b: resolve forced mechanism parameters (plan P3) ───────
        // Last-match-wins per field, like algorithm resolution. Attached to
        // Allow so the dispatcher merges it into the effective
        // CryptographicParameters before calling the engine.
        let mut cp = super::CpOverride::default();
        for rule in snapshot.policy.rules.iter() {
            if let Some(forced) = rule.resolve_cp(req, resolved_view) {
                cp.merge(forced);
            }
        }
        let cp_override = if cp.is_empty() { None } else { Some(cp) };

        // ── Allow / RekeyAndProceed branch selection ─────────────────────
        let d = match (substituted_by, &resolved, req.current_object_algorithm, req.target_uid) {
            // Substitution fired, request targets an existing object, and
            // the substituted algorithm differs from the stored algorithm.
            (Some(rule_idx), Some(new_algo), Some(current), Some(uid)) if new_algo != current => {
                Decision::RekeyAndProceed {
                    original_uid: uid.to_string(),
                    from_algorithm: current.to_string(),
                    new_algorithm: new_algo.clone(),
                    triggered_by_rule: rule_idx,
                    human: format!(
                        "policy substituted {current} → {new_algo}; engine planning rekey of {uid}"
                    ),
                }
            }
            // Substitution fired but no existing object — plain override at
            // create-time. Dispatcher rewrites the algorithm and proceeds.
            (Some(_), Some(new_algo), _, _) if Some(new_algo.as_str()) != req.algorithm => {
                Decision::Allow {
                    algorithm_override: Some(new_algo.clone()),
                    substituted_by_rule: substituted_by,
                    cp_override,
                }
            }
            // No algorithm substitution; allow (possibly with a forced CP).
            _ => Decision::Allow {
                algorithm_override: None,
                substituted_by_rule: None,
                cp_override,
            },
        };
        self.audit.record_decision(req, &d, &snapshot.source_fingerprint);
        d
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ActivateError {
    #[error("engine state mutex poisoned: {0}")]
    Poisoned(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::Path;

    use super::super::loader::load_from_str;

    fn ts() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_750_000_000).unwrap() // mid-2025
    }

    #[test]
    fn no_policy_denies_all() {
        let eng = Engine::deny_all();
        let attrs = HashMap::new();
        let req = PolicyRequest::minimal("Sign", Some("ML-DSA-87"), ts(), "c-1", &attrs);
        let d = eng.evaluate(&req);
        assert!(d.is_deny());
        match d {
            Decision::Deny { kmip_reason, .. } => assert_eq!(kmip_reason, DenyReason::PolicyNotLoaded),
            _ => unreachable!(),
        }
    }

    #[test]
    fn permissive_allows_everything() {
        let eng = Engine::permissive();
        let attrs = HashMap::new();
        let req = PolicyRequest::minimal("Sign", Some("ML-DSA-87"), ts(), "c-2", &attrs);
        assert!(eng.evaluate(&req).is_allow());
    }

    #[test]
    fn allowlist_denies_off_list_algo() {
        let yaml = r#"
schema_version: 1
metadata:
  name: fips
  description: FIPS allowlist
  authority: test
  effective: "always"
rules:
  - type: algorithm_allowlist
    ops: [Create]
    algorithms: [AES-256, ML-DSA-87]
    reason: "Not FIPS-approved"
"#;
        let eng = Engine::deny_all();
        eng.activate(load_from_str(yaml, Path::new("<test>")).unwrap()).unwrap();
        let attrs = HashMap::new();
        let bad = PolicyRequest::minimal("Create", Some("RSA-2048"), ts(), "c-3", &attrs);
        assert!(eng.evaluate(&bad).is_deny());
        let good = PolicyRequest::minimal("Create", Some("AES-256"), ts(), "c-4", &attrs);
        assert!(eng.evaluate(&good).is_allow());
    }

    #[test]
    fn forcing_rule_attaches_cp_override() {
        let yaml = r#"
schema_version: 1
metadata:
  name: deterministic-signing
  description: force deterministic ML-DSA
  authority: test
  effective: "always"
rules:
  - type: mechanism_parameter_default
    ops: [Sign]
    deterministic: true
    reason: "deterministic signatures required"
"#;
        let eng = Engine::deny_all();
        eng.activate(load_from_str(yaml, Path::new("<test>")).unwrap()).unwrap();
        let attrs = HashMap::new();
        let req = PolicyRequest::minimal("Sign", Some("ML-DSA-65"), ts(), "c-cp", &attrs);
        let d = eng.evaluate(&req);
        assert!(d.is_allow());
        let ov = d.cp_override().expect("forcing rule attaches cp_override");
        assert_eq!(ov.deterministic, Some(true));
        // A request the rule doesn't match carries no override.
        let other = PolicyRequest::minimal("Encrypt", Some("AES-256"), ts(), "c-cp2", &attrs);
        assert!(eng.evaluate(&other).cp_override().is_none());
    }

    #[test]
    fn substitution_at_create_returns_allow_with_override() {
        let yaml = r#"
schema_version: 1
metadata:
  name: substitute-demo
  description: upgrade ECDSA to ML-DSA at create
  authority: test
  effective: "always"
rules:
  - type: algorithm_substitution
    ops: [CreateKeyPair]
    from: ECDSA-P256
    to: ML-DSA-65
    reason: "Auto-upgrade to PQC"
"#;
        let eng = Engine::deny_all();
        eng.activate(load_from_str(yaml, Path::new("<test>")).unwrap()).unwrap();
        let attrs = HashMap::new();
        let req = PolicyRequest::minimal("CreateKeyPair", Some("ECDSA-P256"), ts(), "c-5", &attrs);
        let d = eng.evaluate(&req);
        match d {
            Decision::Allow { algorithm_override, .. } => {
                assert_eq!(algorithm_override.as_deref(), Some("ML-DSA-65"));
            }
            other => panic!("expected Allow with override, got {other:?}"),
        }
    }

    #[test]
    fn substitution_with_existing_object_triggers_rekey() {
        let yaml = r#"
schema_version: 1
metadata:
  name: rekey-demo
  description: classical-to-PQC at Sign time
  authority: test
  effective: "always"
rules:
  - type: algorithm_substitution
    ops: [Sign]
    from: ECDSA-P256
    to: ML-DSA-65
    reason: "PQC required for signing"
"#;
        let eng = Engine::deny_all();
        eng.activate(load_from_str(yaml, Path::new("<test>")).unwrap()).unwrap();
        let attrs = HashMap::new();
        let mut req = PolicyRequest::minimal("Sign", Some("ECDSA-P256"), ts(), "c-6", &attrs);
        req.current_object_algorithm = Some("ECDSA-P256");
        req.target_uid = Some("urn:pqctoday:obj:abc123");
        let d = eng.evaluate(&req);
        match d {
            Decision::RekeyAndProceed { from_algorithm, new_algorithm, original_uid, .. } => {
                assert_eq!(from_algorithm, "ECDSA-P256");
                assert_eq!(new_algorithm, "ML-DSA-65");
                assert_eq!(original_uid, "urn:pqctoday:obj:abc123");
            }
            other => panic!("expected RekeyAndProceed, got {other:?}"),
        }
    }

    #[test]
    fn substitution_then_allowlist_deny_substituted_wins() {
        // Substitute RSA → ML-DSA-65, but the allowlist forbids ML-DSA-65.
        // Must Deny on the substituted algorithm (no orphan rekey to a banned algo).
        let yaml = r#"
schema_version: 1
metadata:
  name: tricky
  description: substitution to a banned algo
  authority: test
  effective: "always"
rules:
  - type: algorithm_substitution
    ops: [CreateKeyPair]
    from: RSA
    to: ML-DSA-65
    reason: "Upgrade to PQC"
  - type: algorithm_allowlist
    ops: [CreateKeyPair]
    algorithms: [AES-256]
    reason: "Only AES allowed"
"#;
        let eng = Engine::deny_all();
        eng.activate(load_from_str(yaml, Path::new("<test>")).unwrap()).unwrap();
        let attrs = HashMap::new();
        let req = PolicyRequest::minimal("CreateKeyPair", Some("RSA"), ts(), "c-7", &attrs);
        assert!(eng.evaluate(&req).is_deny());
    }

    #[test]
    fn default_rule_fills_missing_algorithm() {
        let yaml = r#"
schema_version: 1
metadata:
  name: default-demo
  description: app sends no algo
  authority: test
  effective: "always"
rules:
  - type: algorithm_default
    ops: [CreateKeyPair]
    default_algorithm: ML-DSA-87
    reason: "PQC default for new signing keys"
"#;
        let eng = Engine::deny_all();
        eng.activate(load_from_str(yaml, Path::new("<test>")).unwrap()).unwrap();
        let attrs = HashMap::new();
        let req = PolicyRequest::minimal("CreateKeyPair", None, ts(), "c-8", &attrs);
        let d = eng.evaluate(&req);
        assert_eq!(d.algorithm_override(), Some("ML-DSA-87"));
    }

    #[test]
    fn activation_swaps_policy_atomically() {
        let eng = Engine::permissive();
        let attrs = HashMap::new();
        let req = PolicyRequest::minimal("Sign", Some("RSA"), ts(), "c-9", &attrs);
        assert!(eng.evaluate(&req).is_allow());

        // Replace with a deny-all policy.
        let yaml = r#"
schema_version: 1
metadata:
  name: nothing
  description: deny everything
  authority: test
  effective: "always"
rules:
  - type: algorithm_denylist
    ops: [Sign]
    algorithms: [RSA]
    reason: "RSA banned"
"#;
        eng.activate(load_from_str(yaml, Path::new("<test>")).unwrap()).unwrap();
        assert!(eng.evaluate(&req).is_deny());
    }
}
