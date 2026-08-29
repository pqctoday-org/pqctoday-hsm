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
    rule::{GatingDeny, Severity},
};

/// Engine state. Cheap to `.clone()` — the policy + audit live behind `Arc`.
#[derive(Clone)]
pub struct Engine {
    inner: Arc<RwLock<EngineInner>>,
    audit: Arc<PolicyAudit>,
}

struct EngineInner {
    /// Legacy single-policy slot — `Engine::replace_all`'s target. `None`
    /// with an empty `modules` means "no policy loaded" — engine denies-all
    /// by default. Mutually exclusive with `modules` being non-empty: an
    /// engine is either in legacy (whole-engine-swap) mode or modular
    /// (per-scope) mode at any given moment, never both — enforced by
    /// `replace_all`/`activate` themselves, not by this struct's shape.
    active: Option<ActivePolicy>,
    /// Modular policy set (2026-08-28 plan — see
    /// `cacp-modular-policy-plan-08282026.md`). At most one entry may
    /// declare any given non-`Scope::Global` scope — enforced at
    /// `Engine::activate` time.
    modules: Vec<ModuleEntry>,
    /// What happens to a request whose op no active module's scopes cover.
    /// Only consulted in modular mode (legacy mode has no scope concept, so
    /// nothing is ever "uncovered" there). Default `Deny` — see
    /// `Engine::deny_all`.
    uncovered_ops: UncoveredOps,
}

/// One entry in the modular policy set.
#[derive(Clone, Debug)]
struct ModuleEntry {
    policy: ActivePolicy,
    /// Stays listed (visible to `Engine::modules()`) while disabled, just
    /// not consulted for resolution or gating — the per-module on/off
    /// switch. Disabling does NOT free its scope(s) for another module to
    /// claim; only `Engine::deactivate` (removal) does that.
    enabled: bool,
}

/// What the engine does with a request whose op no active module's scopes
/// cover (modular mode only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UncoveredOps {
    /// Fail closed — the engine's universal default. An op with no module
    /// claiming its scope is denied, same reason family as "no policy
    /// loaded".
    Deny,
    /// Fail open — an uncovered op proceeds ungated (though a `Global`
    /// module's gates still apply; see `Engine::evaluate_traced`'s module
    /// docs). Intended for incremental adoption and the browser playground,
    /// never a native-server default.
    Allow,
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

impl ActivePolicy {
    /// Convenience accessor — `&[]` for a legacy/unscoped policy.
    pub fn scopes(&self) -> &[super::rule::Scope] {
        &self.policy.metadata.scopes
    }
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
            inner: Arc::new(RwLock::new(EngineInner {
                active: None,
                modules: Vec::new(),
                uncovered_ops: UncoveredOps::Deny,
            })),
            audit: Arc::new(PolicyAudit::new(1024)),
        }
    }

    /// Build a deny-all engine wired to a cross-plane audit sink. Plane-1
    /// events ALSO land in a private 1024-slot ring for the Hub UI's
    /// dedicated Plane-1 panel.
    pub fn with_global_sink(sink: std::sync::Arc<dyn crate::auditlog::AuditSink>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(EngineInner {
                active: None,
                modules: Vec::new(),
                uncovered_ops: UncoveredOps::Deny,
            })),
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
        eng.replace_all(loaded).expect("built-in permissive policy must activate");
        eng
    }

    /// Activate `loaded` as the engine's policy. Atomic swap: in-flight
    /// `evaluate` calls observe either the old or the new policy, never a
    /// partially-applied one. Returns the prior policy's fingerprint (if any)
    /// for audit logging.
    pub fn replace_all(&self, loaded: LoadedPolicy) -> Result<Option<String>, ActivateError> {
        let LoadedPolicy {
            policy,
            source,
            warnings,
        } = loaded;
        let now = OffsetDateTime::now_utc();
        // S-7 — refuse to activate a policy whose `effective:` date is still in
        // the future (it would silently enforce while appearing dormant).
        if is_future_effective(&policy.metadata.effective, now) {
            return Err(ActivateError::NotYetEffective {
                effective: policy.metadata.effective.clone(),
            });
        }
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
        // Modular-policy plan — `replace_all` and `activate` are mutually
        // exclusive modes (see `EngineInner::modules`'s doc comment):
        // swapping in a whole-engine policy clears any modular set that
        // might have been active before.
        inner.modules.clear();
        drop(inner);
        self.audit.record_activation(now, &new_name, &new_fp, prior_fp.as_deref(), &warnings);
        Ok(prior_fp)
    }

    /// Add `loaded` to the modular policy set (modular-policy plan,
    /// 2026-08-28 — supersedes the earlier priority-stack A3 design; see
    /// `cacp-modular-policy-plan-08282026.md`). `loaded` MUST declare at
    /// least one `metadata.scopes` entry — an unscoped file can only be
    /// installed via [`Self::replace_all`]. Refused if:
    ///
    /// - the legacy slot is occupied ([`ActivateError::LegacyPolicyActive`]
    ///   — deactivate it via a fresh `replace_all`-based swap first; there
    ///   is no "clear legacy" verb because `replace_all` always overwrites
    ///   it);
    /// - any of `loaded`'s scopes is already claimed by a DIFFERENTLY-NAMED
    ///   active module ([`ActivateError::ScopeConflict`]) — decision 6 of
    ///   the plan: no silent replacement;
    /// - `loaded`'s `effective:` date is in the future (S-7, same rule as
    ///   `replace_all`).
    ///
    /// Activating a module whose name matches one ALREADY in the set
    /// replaces it in place (an upgrade — new revision or re-enable), which
    /// is why the conflict check above excludes same-named entries from
    /// itself.
    pub fn activate(&self, loaded: LoadedPolicy) -> Result<(), ActivateError> {
        let LoadedPolicy { policy, source, warnings } = loaded;
        if policy.metadata.scopes.is_empty() {
            return Err(ActivateError::Unscoped);
        }
        let now = OffsetDateTime::now_utc();
        if is_future_effective(&policy.metadata.effective, now) {
            return Err(ActivateError::NotYetEffective {
                effective: policy.metadata.effective.clone(),
            });
        }
        let new_scopes = policy.metadata.scopes.clone();
        let new_name = policy.metadata.name.clone();
        let active = ActivePolicy {
            source_fingerprint: Policy::fingerprint(&source),
            policy: Arc::new(policy),
            source_path: "<loaded>".into(),
            loaded_at: now,
        };

        let mut inner = self.inner.write().expect("engine state poisoned");
        if inner.active.is_some() {
            return Err(ActivateError::LegacyPolicyActive);
        }
        for m in &inner.modules {
            if m.policy.policy.metadata.name == new_name {
                continue; // Same-named entry: this call replaces it, not a conflict.
            }
            for s in &new_scopes {
                if m.policy.scopes().contains(s) {
                    return Err(ActivateError::ScopeConflict {
                        scope: s.as_str().to_string(),
                        incumbent: m.policy.policy.metadata.name.clone(),
                    });
                }
            }
        }
        let new_fp = active.source_fingerprint.clone();
        inner.modules.retain(|m| m.policy.policy.metadata.name != new_name);
        inner.modules.push(ModuleEntry { policy: active, enabled: true });
        drop(inner);
        self.audit.record_activation(now, &new_name, &new_fp, None, &warnings);
        Ok(())
    }

    /// Remove a module from the set by name. `true` if something was
    /// removed. This is the fail-closed OFF the six-requirement audit
    /// flagged as missing on the old single-slot engine: removing every
    /// module (or calling [`Self::clear_modules`]) leaves the set empty,
    /// which denies every request — genuinely turning enforcement off in
    /// the safe direction, not just pointing the engine at a different
    /// policy.
    pub fn deactivate(&self, name: &str) -> bool {
        let mut inner = self.inner.write().expect("engine state poisoned");
        let before = inner.modules.len();
        inner.modules.retain(|m| m.policy.policy.metadata.name != name);
        inner.modules.len() != before
    }

    /// Enable/disable a module by name IN PLACE, without removing it (it
    /// stays visible to [`Self::modules`] but stops being consulted for
    /// resolution or gating while disabled). Does not free its scopes for
    /// another module — see [`Self::deactivate`] for that. `true` if the
    /// name was found.
    pub fn set_module_enabled(&self, name: &str, enabled: bool) -> bool {
        let mut inner = self.inner.write().expect("engine state poisoned");
        match inner.modules.iter_mut().find(|m| m.policy.policy.metadata.name == name) {
            Some(m) => {
                m.enabled = enabled;
                true
            }
            None => false,
        }
    }

    /// Empty the modular set entirely (does not touch the legacy slot —
    /// they are independent; whichever is non-empty is the one in effect).
    pub fn clear_modules(&self) {
        self.inner.write().expect("engine state poisoned").modules.clear();
    }

    /// Release the legacy single-policy slot without loading a replacement.
    /// [`Self::activate`] refuses while it is occupied — a caller switching
    /// from a [`Self::replace_all`]-loaded policy to a modular set (e.g. the
    /// wasm playground's built-in permissive default at boot) must call this
    /// first. Falls back to the modular slot, or deny-all if that's empty too.
    pub fn release_legacy(&self) {
        self.inner.write().expect("engine state poisoned").active = None;
    }

    /// Snapshot every module — `(policy, enabled)` — for an admin listing.
    pub fn modules(&self) -> Vec<(ActivePolicy, bool)> {
        self.inner
            .read()
            .expect("engine state poisoned")
            .modules
            .iter()
            .map(|m| (m.policy.clone(), m.enabled))
            .collect()
    }

    /// Set the uncovered-ops policy (modular mode only). See
    /// [`UncoveredOps`].
    pub fn set_uncovered_ops(&self, mode: UncoveredOps) {
        self.inner.write().expect("engine state poisoned").uncovered_ops = mode;
    }

    /// Current uncovered-ops policy.
    pub fn uncovered_ops(&self) -> UncoveredOps {
        self.inner.read().expect("engine state poisoned").uncovered_ops
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
        self.evaluate_traced(req).0
    }

    /// Like [`Self::evaluate`], but also returns a per-rule execution trace
    /// reflecting what the engine ACTUALLY did this pass — which rules resolved
    /// an algorithm (defaults/substitutions/forced params), which rule denied,
    /// which were evaluated and passed, and which were skipped after the
    /// decision short-circuited. The Hub's visual simulator drives its node
    /// highlighting from this, so what the graph shows is engine-truth, not a
    /// re-implemented approximation.
    pub fn evaluate_traced(&self, req: &PolicyRequest) -> (Decision, Vec<TraceEntry>) {
        // Modular-policy plan (2026-08-28) — legacy (`replace_all`) and
        // modular (`activate`) modes are mutually exclusive (enforced at
        // activation time, see `replace_all`/`activate`'s own doc
        // comments), so `self.active()` being `None` is exactly the signal
        // to check the modular set instead of immediately denying. This
        // means the legacy path below — everything from here to the end of
        // this function — is UNCHANGED from before the modular-policy plan;
        // it only ever runs when the engine is in legacy mode.
        let snapshot = match self.active() {
            Some(s) => s,
            None => return self.evaluate_modular(req),
        };

        // A2 (2026-08-28 audit) — per-request validity window, not just the
        // one-time activation-time check `is_future_effective` used to be.
        // A policy outside `[effective, expires]` for THIS request's
        // timestamp is inert — treated exactly like "no policy loaded" so
        // the fail-safe default (deny) still holds rather than falling
        // through to some other implicit behavior. `activate()` still
        // refuses to activate a future-dated policy in the first place
        // (S-7, deliberately unchanged for now — removing that refusal is
        // most useful once multiple policies can be staged simultaneously,
        // which this single-active-policy engine does not yet support);
        // this check's real new value is `expires`, which had no
        // enforcement point anywhere before A2.
        if !policy_is_live(&snapshot.policy.metadata, req.ts) {
            let d = Decision::Deny {
                kmip_reason: DenyReason::PolicyNotLoaded,
                human: format!(
                    "Active policy {:?} is outside its validity window (effective: {}, expires: {}) for this request; denying by default.",
                    snapshot.policy.metadata.name,
                    snapshot.policy.metadata.effective,
                    snapshot.policy.metadata.expires.as_deref().unwrap_or("never"),
                ),
                fired_rule_index: 0,
            };
            self.audit.record_decision(req, &d, "<policy-outside-window>");
            return (d, Vec::new());
        }

        // Per-rule "this rule resolved an algorithm/param" notes, filled by the
        // resolve passes below; drives the `resolve` effect in the trace.
        let mut resolver_note: Vec<Option<String>> = vec![None; snapshot.policy.rules.len()];

        // ── Pass 0: resolve algorithm_default ────────────────────────────
        // A default only fills a request that specified NO algorithm. Resolve it
        // FIRST (F-2) so substitutions (Pass 1) always see the defaulted value —
        // making resolution independent of the order defaults and substitutions
        // appear in the policy. First matching default wins — with NAME-PATTERNED
        // defaults evaluated before generic ones (most-specific-wins), so a
        // `name_pattern: "payments-*"` → AES-128 rule beats the policy's generic
        // Create → AES-256 default whatever order the YAML lists them in.
        let mut resolved: Option<String> = req.algorithm.map(|s| s.to_string());
        let mut substituted_by: Option<usize> = None;
        if resolved.is_none() {
            'outer: for patterned_phase in [true, false] {
                for (i, rule) in snapshot.policy.rules.iter().enumerate() {
                    if rule.has_name_pattern() != patterned_phase {
                        continue;
                    }
                    if let Some(def) = rule.resolve_default(req) {
                        resolver_note[i] = Some(format!("default → {}", def.new_algorithm));
                        resolved = Some(def.new_algorithm);
                        substituted_by = Some(i + 1);
                        break 'outer;
                    }
                }
            }
        }

        // ── Pass 1: apply substitutions to the (default-)resolved algorithm ──
        for (i, rule) in snapshot.policy.rules.iter().enumerate() {
            let current_view: Option<&str> = resolved.as_deref();
            if let Some(sub) = rule.resolve_substitution(req, current_view) {
                resolver_note[i] =
                    Some(format!("{} → {}", current_view.unwrap_or_default(), sub.new_algorithm));
                resolved = Some(sub.new_algorithm);
                substituted_by = Some(i + 1);
            }
        }

        // ── Pass 2: gating (first deny wins; A1 warn-severity matches
        // accumulate instead of short-circuiting) ────────────────────────
        let resolved_view: Option<&str> = resolved.as_deref();
        let mut fired: Option<(usize, GatingDeny)> = None;
        let mut warnings: Vec<super::decision::PolicyWarning> = Vec::new();
        for (i, rule) in snapshot.policy.rules.iter().enumerate() {
            if let Some(deny) = rule.check_pass2(req, resolved_view) {
                match rule.severity() {
                    Severity::Deny => {
                        fired = Some((i, deny));
                        break;
                    }
                    Severity::Warn => warnings.push(super::decision::PolicyWarning {
                        rule_index: i + 1,
                        reason: deny.human,
                        policy: snapshot.policy.metadata.name.clone(),
                    }),
                }
            }
        }
        if let Some((i, deny)) = fired {
            let trace = build_trace(&resolver_note, Some(i), Some(&deny.human));
            let d = Decision::Deny {
                kmip_reason: deny.kmip_reason,
                human: deny.human,
                fired_rule_index: i + 1,
            };
            self.audit.record_decision(req, &d, &snapshot.source_fingerprint);
            return (d, trace);
        }

        // ── Pass 1b: resolve forced mechanism parameters (plan P3) ───────
        // Last-match-wins per field, like algorithm resolution. Attached to
        // Allow so the dispatcher merges it into the effective
        // CryptographicParameters before calling the engine.
        let mut cp = super::CpOverride::default();
        for (i, rule) in snapshot.policy.rules.iter().enumerate() {
            if let Some(forced) = rule.resolve_cp(req, resolved_view) {
                if resolver_note[i].is_none() {
                    resolver_note[i] = Some("forces mechanism params".into());
                }
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
                    warnings,
                }
            }
            // Substitution fired but no existing object — plain override at
            // create-time. Dispatcher rewrites the algorithm and proceeds.
            (Some(_), Some(new_algo), _, _) if Some(new_algo.as_str()) != req.algorithm => {
                Decision::Allow {
                    algorithm_override: Some(new_algo.clone()),
                    substituted_by_rule: substituted_by,
                    cp_override,
                    warnings,
                }
            }
            // No algorithm substitution; allow (possibly with a forced CP).
            _ => Decision::Allow {
                algorithm_override: None,
                substituted_by_rule: None,
                cp_override,
                warnings,
            },
        };
        let trace = build_trace(&resolver_note, None, None);
        self.audit.record_decision(req, &d, &snapshot.source_fingerprint);
        (d, trace)
    }

    /// Modular-policy evaluation path (2026-08-28 plan — see
    /// `cacp-modular-policy-plan-08282026.md`), reached only when the engine
    /// has no legacy (`replace_all`) policy active. Finds the single module
    /// whose declared scopes cover `req.op` — at most one active module
    /// ever can, by construction: `loader::check_scope_containment` keeps
    /// every rule inside its file's declared scope(s), and `Engine::activate`
    /// refuses a second module claiming an already-occupied scope — runs
    /// ITS Pass 0/1 resolution alone, then gates against that module's
    /// rules plus every live `Scope::Global` module's rules (any deny wins:
    /// "strictest wins" composed by construction, not by a precedence
    /// rule). Trace fidelity matches the legacy path exactly when exactly
    /// one module contributes (the overwhelmingly common single-module
    /// case); a genuinely multi-module decision returns an empty trace for
    /// now — full per-module trace attribution is wave 5 of the plan
    /// (absorbs the WS-C "C7" item), not required for engine correctness.
    fn evaluate_modular(&self, req: &PolicyRequest) -> (Decision, Vec<TraceEntry>) {
        let (modules, uncovered_ops) = {
            let inner = self.inner.read().expect("engine state poisoned");
            (inner.modules.clone(), inner.uncovered_ops)
        };

        if modules.is_empty() {
            let d = Decision::Deny {
                kmip_reason: DenyReason::PolicyNotLoaded,
                human: "Engine has no active policy; denying by default.".into(),
                fired_rule_index: 0,
            };
            self.audit.record_decision(req, &d, "<no-policy>");
            return (d, Vec::new());
        }

        let live = |m: &ModuleEntry| m.enabled && policy_is_live(&m.policy.policy.metadata, req.ts);

        let owning_scope = super::rule::op_scope(req.op).ok();
        let owner: Option<&ModuleEntry> = owning_scope
            .and_then(|scope| modules.iter().find(|m| live(m) && m.policy.scopes().contains(&scope)));
        let globals: Vec<&ModuleEntry> = modules
            .iter()
            .filter(|m| live(m) && m.policy.scopes().contains(&super::rule::Scope::Global))
            .collect();

        if owner.is_none() && uncovered_ops == UncoveredOps::Deny {
            let d = Decision::Deny {
                kmip_reason: DenyReason::PolicyNotLoaded,
                human: format!(
                    "No active module covers op {:?}; denying by default (uncovered-ops=deny).",
                    req.op
                ),
                fired_rule_index: 0,
            };
            self.audit.record_decision(req, &d, "<uncovered-op>");
            return (d, Vec::new());
        }

        // ── Pass 0/1 — resolution, owner module ONLY. An uncovered op under
        // uncovered-ops=allow has no owner, so nothing resolves for it; the
        // request's own algorithm (if any) passes through unchanged.
        let mut resolved: Option<String> = req.algorithm.map(|s| s.to_string());
        let mut substituted_by: Option<usize> = None;
        let mut resolver_note: Vec<Option<String>> = Vec::new();
        if let Some(owner) = owner {
            let policy = &owner.policy.policy;
            resolver_note = vec![None; policy.rules.len()];
            if resolved.is_none() {
                'outer: for patterned_phase in [true, false] {
                    for (i, rule) in policy.rules.iter().enumerate() {
                        if rule.has_name_pattern() != patterned_phase {
                            continue;
                        }
                        if let Some(def) = rule.resolve_default(req) {
                            resolver_note[i] = Some(format!("default → {}", def.new_algorithm));
                            resolved = Some(def.new_algorithm);
                            substituted_by = Some(i + 1);
                            break 'outer;
                        }
                    }
                }
            }
            for (i, rule) in policy.rules.iter().enumerate() {
                let current_view: Option<&str> = resolved.as_deref();
                if let Some(sub) = rule.resolve_substitution(req, current_view) {
                    resolver_note[i] = Some(format!(
                        "{} → {}",
                        current_view.unwrap_or_default(),
                        sub.new_algorithm
                    ));
                    resolved = Some(sub.new_algorithm);
                    substituted_by = Some(i + 1);
                }
            }
        }

        // ── Pass 2 — gating: owner's rules first, then every Global's, in
        // activation order; first deny wins. A1 (2026-08-28): a warn-severity
        // match accumulates (module-name-prefixed, same convention as the
        // Deny `human` message below) instead of short-circuiting.
        let resolved_view: Option<&str> = resolved.as_deref();
        let mut fired: Option<(&ModuleEntry, usize, GatingDeny)> = None;
        let mut warnings: Vec<super::decision::PolicyWarning> = Vec::new();
        'gate: for entry in owner.into_iter().chain(globals.iter().copied()) {
            for (i, rule) in entry.policy.policy.rules.iter().enumerate() {
                if let Some(deny) = rule.check_pass2(req, resolved_view) {
                    match rule.severity() {
                        Severity::Deny => {
                            fired = Some((entry, i, deny));
                            break 'gate;
                        }
                        Severity::Warn => warnings.push(super::decision::PolicyWarning {
                            rule_index: i + 1,
                            reason: deny.human,
                            policy: entry.policy.policy.metadata.name.clone(),
                        }),
                    }
                }
            }
        }
        if let Some((entry, i, deny)) = fired {
            let is_owner = owner.map(|o| std::ptr::eq(o, entry)).unwrap_or(false);
            let trace = if is_owner && globals.is_empty() {
                build_trace(&resolver_note, Some(i), Some(&deny.human))
            } else {
                Vec::new()
            };
            let human = format!("[{}] {}", entry.policy.policy.metadata.name, deny.human);
            let d = Decision::Deny { kmip_reason: deny.kmip_reason, human, fired_rule_index: i + 1 };
            self.audit.record_decision(req, &d, &entry.policy.source_fingerprint);
            return (d, trace);
        }

        // ── Pass 1b — forced mechanism params: Globals first, then the
        // owner, so the owning module's explicit choice for its own domain
        // wins over a generic cross-cutting default (merge()'s "last write
        // wins" per field, same rule used within one policy, extended
        // across the set).
        let mut cp = super::CpOverride::default();
        for entry in globals.iter().copied().chain(owner) {
            for rule in entry.policy.policy.rules.iter() {
                if let Some(forced) = rule.resolve_cp(req, resolved_view) {
                    cp.merge(forced);
                }
            }
        }
        let cp_override = if cp.is_empty() { None } else { Some(cp) };

        let d = match (substituted_by, &resolved, req.current_object_algorithm, req.target_uid) {
            (Some(rule_idx), Some(new_algo), Some(current), Some(uid)) if new_algo != current => {
                Decision::RekeyAndProceed {
                    original_uid: uid.to_string(),
                    from_algorithm: current.to_string(),
                    new_algorithm: new_algo.clone(),
                    triggered_by_rule: rule_idx,
                    human: format!(
                        "policy substituted {current} → {new_algo}; engine planning rekey of {uid}"
                    ),
                    warnings,
                }
            }
            (Some(_), Some(new_algo), _, _) if Some(new_algo.as_str()) != req.algorithm => {
                Decision::Allow {
                    algorithm_override: Some(new_algo.clone()),
                    substituted_by_rule: substituted_by,
                    cp_override,
                    warnings,
                }
            }
            _ => Decision::Allow {
                algorithm_override: None,
                substituted_by_rule: None,
                cp_override,
                warnings,
            },
        };
        let trace =
            if globals.is_empty() { build_trace(&resolver_note, None, None) } else { Vec::new() };
        let fingerprint_for_audit = owner
            .or_else(|| globals.first().copied())
            .map(|e| e.policy.source_fingerprint.clone())
            .unwrap_or_default();
        self.audit.record_decision(req, &d, &fingerprint_for_audit);
        (d, trace)
    }
}

/// A per-rule execution-trace entry (1-based `index`) for the Hub visual
/// simulator, so graph highlighting reflects the ENGINE's actual pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceEntry {
    /// 1-based rule number (matches `Decision`'s `fired_rule_index`).
    pub index: usize,
    /// `"resolve"` (default/substitution/forced-param fired) · `"deny"` (the
    /// rule that fired the Deny) · `"pass"` (evaluated, did not fire) · `"skip"`
    /// (not reached — evaluation short-circuited at the Deny above it).
    pub effect: &'static str,
    /// Human note (resolve morph `X → Y`, or the deny reason).
    pub note: String,
}

/// Classify every rule into a [`TraceEntry`] from what the engine computed:
/// resolver notes (Pass 0/1/1b), the fired-deny index, and the short-circuit.
fn build_trace(
    resolver_note: &[Option<String>],
    fired_idx: Option<usize>,
    deny_human: Option<&str>,
) -> Vec<TraceEntry> {
    resolver_note
        .iter()
        .enumerate()
        .map(|(i, note)| {
            let index = i + 1;
            if let Some(note) = note {
                TraceEntry { index, effect: "resolve", note: note.clone() }
            } else if fired_idx == Some(i) {
                TraceEntry { index, effect: "deny", note: deny_human.unwrap_or_default().to_string() }
            } else if fired_idx.is_some_and(|d| i > d) {
                TraceEntry { index, effect: "skip", note: "after decision".into() }
            } else {
                TraceEntry { index, effect: "pass", note: String::new() }
            }
        })
        .collect()
}

#[derive(Debug, thiserror::Error)]
pub enum ActivateError {
    #[error("engine state mutex poisoned: {0}")]
    Poisoned(String),
    /// S-7 — the policy's `effective:` date is in the future; activating it now
    /// would enforce it immediately while it looks dormant. Refused.
    #[error("policy is not yet effective (effective: {effective}); refusing to activate")]
    NotYetEffective { effective: String },
    /// Modular-policy plan — `Engine::activate` requires `metadata.scopes`;
    /// an unscoped file must go through `Engine::replace_all` instead.
    #[error("policy has no metadata.scopes — activate() requires a scoped module; use replace_all() for an unscoped/legacy policy")]
    Unscoped,
    /// Modular-policy plan — `Engine::activate` refuses while the legacy
    /// single-policy slot is occupied (mutually exclusive modes).
    #[error("a legacy (replace_all) policy is active; the engine cannot mix legacy and modular modes")]
    LegacyPolicyActive,
    /// Modular-policy plan (decision 6) — no silent replacement: activating
    /// a module whose scope is already claimed by a DIFFERENTLY-NAMED
    /// active module is refused until the incumbent is deactivated.
    #[error("scope {scope:?} is already claimed by active module {incumbent:?}; deactivate it first")]
    ScopeConflict { scope: String, incumbent: String },
}

/// S-7 — is a policy-level `effective:` value a FUTURE date? `"always"`, empty,
/// past/today dates, and unparseable values are NOT future (we don't block on a
/// malformed date — S-6 governs malformed policy fields).
/// A5.3 (2026-08-28 audit) — rewritten in terms of [`super::rule::TimeBound`]'s
/// parser rather than a second hand-rolled copy of the same date grammar.
/// The loader now rejects a malformed `metadata.effective` at load time
/// (see `loader::load_from_str_impl`), so `Err` should be unreachable for any
/// policy that arrived through the normal load path — but this function
/// takes a bare `&str`, not a type-checked `TimeBound`, so it stays
/// defensive rather than assume that: a parse failure here still means
/// "not future" (the same fail-safe direction as before this rewrite), it
/// just can no longer be reached by a typo the loader would have caught.
/// A2 (2026-08-28 audit) — `true` if `ts` falls within `metadata`'s
/// `[effective, expires]` window (inclusive both ends, matching every
/// rule-level window's semantics via the shared `rule::window_active`).
/// `effective`/`expires` are validated at load time (`loader.rs`), so
/// parsing here should always succeed for a policy that reached an active
/// engine slot; `TimeBound::Always` is the fail-safe fallback for a
/// programmatically-constructed `Metadata` that bypassed the loader (e.g. in
/// a unit test), matching `is_future_effective`'s own defensiveness.
fn policy_is_live(metadata: &super::policy::Metadata, ts: OffsetDateTime) -> bool {
    let effective = super::rule::TimeBound::parse_str(&metadata.effective)
        .unwrap_or(super::rule::TimeBound::Always);
    let expires = metadata
        .expires
        .as_deref()
        .and_then(|s| super::rule::TimeBound::parse_str(s).ok());
    super::rule::window_active(Some(&effective), expires.as_ref(), ts)
}

fn is_future_effective(effective: &str, now: OffsetDateTime) -> bool {
    match super::rule::TimeBound::parse_str(effective) {
        Ok(super::rule::TimeBound::Always) => false,
        Ok(super::rule::TimeBound::At(d)) => d > now.date(),
        Err(_) => false,
    }
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

    /// S-7 — a future-effective policy must NOT activate.
    #[test]
    fn refuses_future_effective_policy() {
        let yaml = "schema_version: 1\nmetadata: { name: f, description: d, authority: a, effective: \"2999-01-01\" }\nrules: []\n";
        let loaded = load_from_str(yaml, Path::new("<t>")).unwrap();
        let err = Engine::deny_all().replace_all(loaded).unwrap_err();
        assert!(matches!(err, ActivateError::NotYetEffective { .. }), "got {err:?}");
    }

    /// S-7 — `always` and past dates activate normally.
    #[test]
    fn accepts_always_and_past_effective() {
        for eff in ["always", "2020-01-01"] {
            let yaml = format!("schema_version: 1\nmetadata: {{ name: p, description: d, authority: a, effective: \"{eff}\" }}\nrules: []\n");
            let loaded = load_from_str(&yaml, Path::new("<t>")).unwrap();
            Engine::deny_all().replace_all(loaded).unwrap_or_else(|e| panic!("{eff}: {e}"));
        }
    }

    /// A2 — a policy past its `expires` date is inert for a request at
    /// `ts()`, treated the same as no policy loaded (fail-safe deny), NOT
    /// just refused at activation time the way `effective` alone is.
    #[test]
    fn expired_policy_denies_as_not_loaded() {
        let yaml = r#"
schema_version: 2
metadata:
  name: sunset
  description: expired policy
  authority: test
  effective: "always"
  expires: "2020-01-01"
rules: []
"#;
        let eng = Engine::deny_all();
        eng.replace_all(load_from_str(yaml, Path::new("<t>")).unwrap()).unwrap();
        let attrs = HashMap::new();
        // ts() is mid-2025 — well past the 2020-01-01 expiry.
        let req = PolicyRequest::minimal("Sign", Some("ML-DSA-87"), ts(), "c-exp", &attrs);
        let d = eng.evaluate(&req);
        assert!(d.is_deny(), "an expired policy must deny, not silently allow-all");
        match d {
            Decision::Deny { kmip_reason, .. } => assert_eq!(kmip_reason, DenyReason::PolicyNotLoaded),
            other => panic!("expected PolicyNotLoaded-style deny, got {other:?}"),
        }
    }

    /// A2 — a policy not yet at its `expires` date keeps enforcing normally
    /// (this is not a "policy expires ⇒ everything breaks" regression: only
    /// requests AFTER the expiry date are affected).
    #[test]
    fn not_yet_expired_policy_still_enforces() {
        let yaml = r#"
schema_version: 2
metadata:
  name: not-sunset-yet
  description: policy with a future expiry
  authority: test
  effective: "always"
  expires: "2030-01-01"
rules:
  - type: algorithm_allowlist
    ops: [Create]
    algorithms: [AES-256]
    reason: "Not on the allowlist"
"#;
        let eng = Engine::deny_all();
        eng.replace_all(load_from_str(yaml, Path::new("<t>")).unwrap()).unwrap();
        let attrs = HashMap::new();
        let ok = PolicyRequest::minimal("Create", Some("AES-256"), ts(), "c-notexp-ok", &attrs);
        assert!(eng.evaluate(&ok).is_allow());
        let bad = PolicyRequest::minimal("Create", Some("RSA-2048"), ts(), "c-notexp-bad", &attrs);
        let d = eng.evaluate(&bad);
        match d {
            Decision::Deny { kmip_reason, .. } => {
                assert_ne!(
                    kmip_reason,
                    DenyReason::PolicyNotLoaded,
                    "should deny via the allowlist rule, not because the policy looks unloaded"
                );
            }
            other => panic!("expected the allowlist to deny RSA-2048, got {other:?}"),
        }
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

    // ── Modular-policy plan (2026-08-28) — Engine::activate/deactivate/
    // set_module_enabled/clear_modules, scope conflicts, owning-module
    // resolution, global composition, and uncovered-ops. ──────────────────

    fn scoped_yaml(name: &str, scopes: &str, rules: &str) -> String {
        format!(
            "schema_version: 3\nmetadata: {{ name: {name}, description: d, authority: a, effective: \"always\", scopes: [{scopes}] }}\nrules:\n{rules}"
        )
    }

    fn signing_module(name: &str) -> LoadedPolicy {
        let yaml = scoped_yaml(
            name,
            "signing",
            "  - type: algorithm_default\n    ops: [\"CreateKeyPair:Sign\"]\n    default_algorithm: ML-DSA-87\n    reason: t\n",
        );
        load_from_str(&yaml, Path::new("<t>")).unwrap()
    }

    fn kem_module(name: &str) -> LoadedPolicy {
        let yaml = scoped_yaml(
            name,
            "key-establishment",
            "  - type: algorithm_default\n    ops: [\"CreateKeyPair:KeyAgreement\"]\n    default_algorithm: ML-KEM-1024\n    reason: t\n",
        );
        load_from_str(&yaml, Path::new("<t>")).unwrap()
    }

    fn global_deny_sha1_module(name: &str) -> LoadedPolicy {
        let yaml = scoped_yaml(
            name,
            "global",
            "  - type: hash_algorithm_allowlist\n    ops: [Sign]\n    hashing_algorithms: [SHA-256, SHA-384, SHA-512]\n    reason: t\n",
        );
        load_from_str(&yaml, Path::new("<t>")).unwrap()
    }

    #[test]
    fn activate_requires_scopes() {
        let yaml = "schema_version: 1\nmetadata: { name: unscoped, description: d, authority: a, effective: \"always\" }\nrules: []\n";
        let loaded = load_from_str(yaml, Path::new("<t>")).unwrap();
        let err = Engine::deny_all().activate(loaded).unwrap_err();
        assert!(matches!(err, ActivateError::Unscoped), "got {err:?}");
    }

    #[test]
    fn activate_refuses_while_legacy_active() {
        let eng = Engine::deny_all();
        eng.replace_all(load_from_str(
            "schema_version: 1\nmetadata: { name: legacy, description: d, authority: a, effective: \"always\" }\nrules: []\n",
            Path::new("<t>"),
        ).unwrap()).unwrap();
        let err = eng.activate(signing_module("sig")).unwrap_err();
        assert!(matches!(err, ActivateError::LegacyPolicyActive), "got {err:?}");
    }

    #[test]
    fn release_legacy_unblocks_activate() {
        let eng = Engine::deny_all();
        eng.replace_all(load_from_str(
            "schema_version: 1\nmetadata: { name: legacy, description: d, authority: a, effective: \"always\" }\nrules: []\n",
            Path::new("<t>"),
        ).unwrap()).unwrap();
        assert!(matches!(
            eng.activate(signing_module("sig")).unwrap_err(),
            ActivateError::LegacyPolicyActive
        ));
        eng.release_legacy();
        assert!(eng.active().is_none());
        eng.activate(signing_module("sig")).expect("activate must succeed once legacy is released");
        assert_eq!(eng.modules().len(), 1);
    }

    #[test]
    fn replace_all_clears_the_modular_set() {
        let eng = Engine::deny_all();
        eng.activate(signing_module("sig")).unwrap();
        assert_eq!(eng.modules().len(), 1);
        eng.replace_all(load_from_str(
            "schema_version: 1\nmetadata: { name: legacy, description: d, authority: a, effective: \"always\" }\nrules: []\n",
            Path::new("<t>"),
        ).unwrap()).unwrap();
        assert!(eng.modules().is_empty(), "replace_all must clear the modular set");
    }

    #[test]
    fn activate_refuses_scope_conflict_between_different_names() {
        let eng = Engine::deny_all();
        eng.activate(signing_module("sig-a")).unwrap();
        let err = eng.activate(signing_module("sig-b")).unwrap_err();
        match err {
            ActivateError::ScopeConflict { scope, incumbent } => {
                assert_eq!(scope, "signing");
                assert_eq!(incumbent, "sig-a");
            }
            other => panic!("expected ScopeConflict, got {other:?}"),
        }
    }

    #[test]
    fn activate_same_name_replaces_in_place_not_a_conflict() {
        let eng = Engine::deny_all();
        eng.activate(signing_module("sig")).unwrap();
        eng.activate(signing_module("sig")).unwrap(); // must NOT conflict with itself
        assert_eq!(eng.modules().len(), 1);
    }

    #[test]
    fn different_scopes_coexist() {
        let eng = Engine::deny_all();
        eng.activate(signing_module("sig")).unwrap();
        eng.activate(kem_module("kem")).unwrap();
        assert_eq!(eng.modules().len(), 2);
    }

    #[test]
    fn deactivate_frees_the_scope_for_reuse() {
        let eng = Engine::deny_all();
        eng.activate(signing_module("sig-a")).unwrap();
        assert!(eng.deactivate("sig-a"));
        eng.activate(signing_module("sig-b")).unwrap(); // no longer conflicts
        assert_eq!(eng.modules().len(), 1);
        assert!(!eng.deactivate("does-not-exist"));
    }

    #[test]
    fn owning_module_resolves_its_scope_only() {
        let eng = Engine::deny_all();
        eng.activate(signing_module("sig")).unwrap();
        eng.activate(kem_module("kem")).unwrap();
        let attrs = HashMap::new();
        let sign_req = PolicyRequest::minimal("CreateKeyPair:Sign", None, ts(), "c-mod-1", &attrs);
        assert_eq!(eng.evaluate(&sign_req).algorithm_override(), Some("ML-DSA-87"));
        let kem_req =
            PolicyRequest::minimal("CreateKeyPair:KeyAgreement", None, ts(), "c-mod-2", &attrs);
        assert_eq!(eng.evaluate(&kem_req).algorithm_override(), Some("ML-KEM-1024"));
    }

    #[test]
    fn disabled_module_stops_enforcing_but_stays_listed() {
        let eng = Engine::deny_all();
        eng.activate(signing_module("sig")).unwrap();
        assert!(eng.set_module_enabled("sig", false));
        assert_eq!(eng.modules().len(), 1, "disabling must not remove the entry");
        let attrs = HashMap::new();
        let req = PolicyRequest::minimal("CreateKeyPair:Sign", None, ts(), "c-mod-3", &attrs);
        // Default uncovered-ops is Deny, and the disabled module no longer
        // covers Sign, so this now denies rather than defaulting.
        assert!(eng.evaluate(&req).is_deny());
        assert!(!eng.set_module_enabled("does-not-exist", true));
    }

    #[test]
    fn global_deny_composes_with_domain_module_allow() {
        let eng = Engine::deny_all();
        eng.activate(signing_module("sig")).unwrap();
        eng.activate(global_deny_sha1_module("no-sha1")).unwrap();
        let attrs = HashMap::new();
        let mut sha1 = PolicyRequest::minimal("Sign", Some("ML-DSA-87"), ts(), "c-mod-4", &attrs);
        sha1.mechanism.hashing_algorithm = Some(0x04); // SHA-1
        assert!(eng.evaluate(&sha1).is_deny(), "the global module's deny must block Sign");
        let mut sha256 = PolicyRequest::minimal("Sign", Some("ML-DSA-87"), ts(), "c-mod-5", &attrs);
        sha256.mechanism.hashing_algorithm = Some(0x06); // SHA-256
        assert!(eng.evaluate(&sha256).is_allow(), "an allowed hash must still pass");
    }

    #[test]
    fn uncovered_op_denies_by_default_and_allows_when_configured() {
        let eng = Engine::deny_all();
        eng.activate(signing_module("sig")).unwrap();
        let attrs = HashMap::new();
        let req = PolicyRequest::minimal("Encrypt", Some("AES-256"), ts(), "c-mod-6", &attrs);
        assert_eq!(eng.uncovered_ops(), UncoveredOps::Deny, "Deny must be the default");
        let d = eng.evaluate(&req);
        match d {
            Decision::Deny { kmip_reason, .. } => assert_eq!(kmip_reason, DenyReason::PolicyNotLoaded),
            other => panic!("expected an uncovered-op deny, got {other:?}"),
        }
        eng.set_uncovered_ops(UncoveredOps::Allow);
        assert!(eng.evaluate(&req).is_allow(), "Allow mode must let an uncovered op through");
    }

    #[test]
    fn empty_modular_set_denies_all() {
        let eng = Engine::deny_all();
        let attrs = HashMap::new();
        let req = PolicyRequest::minimal("Sign", Some("ML-DSA-87"), ts(), "c-mod-7", &attrs);
        let d = eng.evaluate(&req);
        match d {
            Decision::Deny { kmip_reason, .. } => assert_eq!(kmip_reason, DenyReason::PolicyNotLoaded),
            other => panic!("expected PolicyNotLoaded, got {other:?}"),
        }
    }

    #[test]
    fn clear_modules_empties_the_set() {
        let eng = Engine::deny_all();
        eng.activate(signing_module("sig")).unwrap();
        eng.activate(kem_module("kem")).unwrap();
        eng.clear_modules();
        assert!(eng.modules().is_empty());
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
        eng.replace_all(load_from_str(yaml, Path::new("<test>")).unwrap()).unwrap();
        let attrs = HashMap::new();
        let bad = PolicyRequest::minimal("Create", Some("RSA-2048"), ts(), "c-3", &attrs);
        assert!(eng.evaluate(&bad).is_deny());
        let good = PolicyRequest::minimal("Create", Some("AES-256"), ts(), "c-4", &attrs);
        assert!(eng.evaluate(&good).is_allow());
    }

    #[test]
    fn evaluate_traced_reports_resolve_deny_skip() {
        let yaml = r#"
schema_version: 1
metadata:
  name: trace-test
  description: exercise the per-rule trace
  authority: test
  effective: "always"
rules:
  - type: algorithm_default
    ops: ["CreateKeyPair:Sign"]
    default_algorithm: ECDSA-P256
    reason: "classical default"
  - type: algorithm_denylist
    ops: [CreateKeyPair, "CreateKeyPair:Sign"]
    algorithms: [ECDSA-P256]
    reason: "no classical ecdsa"
  - type: algorithm_allowlist
    ops: [CreateKeyPair]
    algorithms: [ML-DSA-87]
    reason: "allowlist"
"#;
        let eng = Engine::deny_all();
        eng.replace_all(load_from_str(yaml, Path::new("<test>")).unwrap()).unwrap();
        let attrs = HashMap::new();

        // No algorithm → default resolves ECDSA-P256 (rule 1), denylist fires
        // (rule 2), rule 3 never reached (short-circuit).
        let req = PolicyRequest::minimal("CreateKeyPair:Sign", None, ts(), "c-t1", &attrs);
        let (d, trace) = eng.evaluate_traced(&req);
        assert!(d.is_deny());
        assert_eq!(
            trace.iter().map(|t| t.effect).collect::<Vec<_>>(),
            vec!["resolve", "deny", "skip"]
        );
        assert_eq!(trace[0].index, 1);

        // Explicit ML-DSA-87 → nothing resolves, both gates evaluate and pass.
        let ok = PolicyRequest::minimal("CreateKeyPair", Some("ML-DSA-87"), ts(), "c-t2", &attrs);
        let (d2, trace2) = eng.evaluate_traced(&ok);
        assert!(d2.is_allow());
        assert_eq!(
            trace2.iter().map(|t| t.effect).collect::<Vec<_>>(),
            vec!["pass", "pass", "pass"]
        );
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
        eng.replace_all(load_from_str(yaml, Path::new("<test>")).unwrap()).unwrap();
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
        eng.replace_all(load_from_str(yaml, Path::new("<test>")).unwrap()).unwrap();
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
        eng.replace_all(load_from_str(yaml, Path::new("<test>")).unwrap()).unwrap();
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
        eng.replace_all(load_from_str(yaml, Path::new("<test>")).unwrap()).unwrap();
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
        eng.replace_all(load_from_str(yaml, Path::new("<test>")).unwrap()).unwrap();
        let attrs = HashMap::new();
        let req = PolicyRequest::minimal("CreateKeyPair", None, ts(), "c-8", &attrs);
        let d = eng.evaluate(&req);
        assert_eq!(d.algorithm_override(), Some("ML-DSA-87"));
    }

    /// F-2 — resolution must be ORDER-INDEPENDENT: a default and a substitution
    /// that chains off it produce the same result no matter which is listed
    /// first. Here the substitution is listed BEFORE the default; pre-fix, the
    /// substitution saw `None` (request had no algo), never fired, and the result
    /// collapsed to the bare default. Post-fix (Pass 0 resolves the default
    /// first), the substitution chains: ML-DSA-65 → ML-DSA-87.
    #[test]
    fn default_resolves_before_substitution_regardless_of_order() {
        let yaml = r#"
schema_version: 1
metadata:
  name: precedence
  description: substitution listed before the default it chains off
  authority: test
  effective: "always"
rules:
  - type: algorithm_substitution
    ops: [CreateKeyPair]
    from: ML-DSA-65
    to: ML-DSA-87
    reason: "upgrade 65 → 87"
  - type: algorithm_default
    ops: [CreateKeyPair]
    default_algorithm: ML-DSA-65
    reason: "PQC default"
"#;
        let eng = Engine::deny_all();
        eng.replace_all(load_from_str(yaml, Path::new("<test>")).unwrap()).unwrap();
        let attrs = HashMap::new();
        let req = PolicyRequest::minimal("CreateKeyPair", None, ts(), "c-prec", &attrs);
        let d = eng.evaluate(&req);
        assert_eq!(
            d.algorithm_override(),
            Some("ML-DSA-87"),
            "default must resolve first so the substitution can chain off it"
        );
    }

    /// Label-pattern rules — the Migration tab's label-only contract: the
    /// SAME op with no algorithm resolves per the request's key Name, with
    /// name-patterned defaults beating the generic default even when the
    /// generic rule is listed FIRST (most-specific-wins, not YAML order).
    #[test]
    fn name_patterned_defaults_beat_generic_regardless_of_order() {
        let yaml = r#"
schema_version: 1
metadata:
  name: label-demo
  description: per-label defaults
  authority: test
  effective: "always"
rules:
  - type: algorithm_default
    ops: [Create]
    default_algorithm: AES-256
    reason: "generic symmetric default"
  - type: algorithm_default
    ops: [Create]
    name_pattern: "payments-*"
    default_algorithm: AES-128
    reason: "legacy payments cipher"
"#;
        let eng = Engine::deny_all();
        eng.replace_all(load_from_str(yaml, Path::new("<test>")).unwrap()).unwrap();
        let attrs = HashMap::new();

        let mut named = PolicyRequest::minimal("Create", None, ts(), "c-lbl-1", &attrs);
        named.name = Some("payments-db-cipher");
        assert_eq!(
            eng.evaluate(&named).algorithm_override(),
            Some("AES-128"),
            "patterned rule must win although the generic default is listed first"
        );

        let mut other = PolicyRequest::minimal("Create", None, ts(), "c-lbl-2", &attrs);
        other.name = Some("vault-archive-cipher");
        assert_eq!(eng.evaluate(&other).algorithm_override(), Some("AES-256"));

        let unnamed = PolicyRequest::minimal("Create", None, ts(), "c-lbl-3", &attrs);
        assert_eq!(
            eng.evaluate(&unnamed).algorithm_override(),
            Some("AES-256"),
            "an unnamed request never matches a patterned rule"
        );
    }

    /// A name-patterned substitution rekeys ONLY the matching key class.
    #[test]
    fn name_patterned_substitution_scopes_the_rekey() {
        let yaml = r#"
schema_version: 1
metadata:
  name: label-sub
  description: label-scoped rekey
  authority: test
  effective: "always"
rules:
  - type: algorithm_substitution
    ops: [Sign]
    name_pattern: "firmware-*"
    from: RSA-2048
    to: ML-DSA-44
    reason: "firmware signing moves to ML-DSA-44"
"#;
        let eng = Engine::deny_all();
        eng.replace_all(load_from_str(yaml, Path::new("<test>")).unwrap()).unwrap();
        let attrs = HashMap::new();

        let mut fw = PolicyRequest::minimal("Sign", Some("RSA-2048"), ts(), "c-sub-1", &attrs);
        fw.name = Some("firmware-release-signing");
        fw.current_object_algorithm = Some("RSA-2048");
        fw.target_uid = Some("uid-1");
        match eng.evaluate(&fw) {
            Decision::RekeyAndProceed { new_algorithm, .. } => {
                assert_eq!(new_algorithm, "ML-DSA-44");
            }
            other => panic!("expected RekeyAndProceed, got {other:?}"),
        }

        let mut api = PolicyRequest::minimal("Sign", Some("RSA-2048"), ts(), "c-sub-2", &attrs);
        api.name = Some("api-gateway-signing");
        api.current_object_algorithm = Some("RSA-2048");
        api.target_uid = Some("uid-2");
        assert!(
            eng.evaluate(&api).is_allow(),
            "a non-matching label must NOT trigger the firmware rekey rule"
        );
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
        eng.replace_all(load_from_str(yaml, Path::new("<test>")).unwrap()).unwrap();
        assert!(eng.evaluate(&req).is_deny());
    }

    // ── A1: deprecation warn-tier (2026-08-28 gaps-remediation plan) ──────

    #[test]
    fn severity_warn_allows_and_attaches_a_warning() {
        let eng = Engine::deny_all();
        let yaml = r#"
schema_version: 1
metadata:
  name: warn-only
  description: t
  authority: test
  effective: "always"
rules:
  - type: algorithm_denylist
    severity: warn
    ops: [Sign]
    algorithms: [RSA]
    reason: "RSA is deprecated, will be denied from 2030"
"#;
        eng.replace_all(load_from_str(yaml, Path::new("<test>")).unwrap()).unwrap();
        let attrs = HashMap::new();
        let req = PolicyRequest::minimal("Sign", Some("RSA"), OffsetDateTime::now_utc(), "a1-1", &attrs);
        let d = eng.evaluate(&req);
        assert!(d.is_allow(), "a warn match must not deny, got {d:?}");
        let warnings = d.warnings();
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].rule_index, 1);
        assert_eq!(warnings[0].policy, "warn-only");
        assert!(warnings[0].reason.contains("deprecated"));
    }

    #[test]
    fn severity_deny_default_still_denies() {
        let eng = Engine::deny_all();
        // No `severity:` field at all — must behave exactly as before A1.
        let yaml = r#"
schema_version: 1
metadata:
  name: deny-default
  description: t
  authority: test
  effective: "always"
rules:
  - type: algorithm_denylist
    ops: [Sign]
    algorithms: [RSA]
    reason: "RSA banned"
"#;
        eng.replace_all(load_from_str(yaml, Path::new("<test>")).unwrap()).unwrap();
        let attrs = HashMap::new();
        let req = PolicyRequest::minimal("Sign", Some("RSA"), OffsetDateTime::now_utc(), "a1-2", &attrs);
        let d = eng.evaluate(&req);
        assert!(d.is_deny());
        assert!(d.warnings().is_empty());
    }

    fn global_warn_rsa_module(name: &str) -> LoadedPolicy {
        let yaml = scoped_yaml(
            name,
            "global",
            "  - type: algorithm_denylist\n    severity: warn\n    ops: [Sign]\n    algorithms: [RSA]\n    reason: \"RSA is deprecated\"\n",
        );
        load_from_str(&yaml, Path::new("<t>")).unwrap()
    }

    #[test]
    fn modular_mode_attributes_a_warning_to_its_owning_module() {
        // Modular mode has more than one policy active at once — a bare
        // rule index alone doesn't say which file to look in, so the
        // warning must carry the module's name (same convention Deny's
        // `[module-name]`-prefixed human message already uses).
        let eng = Engine::deny_all();
        eng.activate(signing_module("sig")).unwrap();
        eng.activate(global_warn_rsa_module("no-rsa-global")).unwrap();
        let attrs = HashMap::new();
        let req = PolicyRequest::minimal("Sign", Some("RSA"), ts(), "a1-mod", &attrs);
        let d = eng.evaluate(&req);
        assert!(d.is_allow(), "a warn match must not deny in modular mode either, got {d:?}");
        let warnings = d.warnings();
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].policy, "no-rsa-global");
    }

    #[test]
    fn stacked_warn_then_dated_deny_flips_on_the_boundary_date() {
        // The recommended deprecation pattern: the SAME condition twice —
        // an unconditional `severity: warn` today, and a `severity: deny`
        // copy that only starts gating from a future `effective_from`.
        let eng = Engine::deny_all();
        let yaml = r#"
schema_version: 1
metadata:
  name: staged-deprecation
  description: t
  authority: test
  effective: "always"
rules:
  - type: algorithm_denylist
    severity: warn
    ops: [Sign]
    algorithms: [RSA]
    reason: "RSA is deprecated"
  - type: algorithm_denylist
    severity: deny
    ops: [Sign]
    algorithms: [RSA]
    effective_from: "2030-01-01"
    reason: "RSA banned from 2030"
"#;
        eng.replace_all(load_from_str(yaml, Path::new("<test>")).unwrap()).unwrap();
        let attrs = HashMap::new();

        // Before the sunset: only the warn rule matches (the dated deny
        // rule's own window_active check keeps it from firing at all yet).
        let before = OffsetDateTime::from_unix_timestamp(1_735_689_600).unwrap(); // 2025-01-01
        let req_before = PolicyRequest::minimal("Sign", Some("RSA"), before, "a1-3a", &attrs);
        let d_before = eng.evaluate(&req_before);
        assert!(d_before.is_allow(), "pre-sunset must still allow, got {d_before:?}");
        assert_eq!(d_before.warnings().len(), 1);

        // After the sunset: BOTH rules match — the warn rule still records
        // its warning (Pass 2 keeps walking past a warn), then the deny
        // rule fires and the walk short-circuits to Deny.
        let after = OffsetDateTime::from_unix_timestamp(1_893_456_000).unwrap(); // 2030-01-02
        let req_after = PolicyRequest::minimal("Sign", Some("RSA"), after, "a1-3b", &attrs);
        let d_after = eng.evaluate(&req_after);
        assert!(d_after.is_deny(), "post-sunset must deny, got {d_after:?}");
    }
}
