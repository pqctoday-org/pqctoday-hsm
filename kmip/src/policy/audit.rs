//! [`PolicyAudit`] — Plane-1 facade over the cross-plane [`AuditSink`].
//!
//! Phase 4.6 retrofit: PolicyAudit no longer owns its own bespoke ring +
//! event enum. It is now a thin typed wrapper that:
//!
//! 1. Holds a backing [`crate::auditlog::RingSink`] for its existing
//!    `snapshot()` API (Hub UI's "Plane-1 history" panel).
//! 2. Optionally fans every event ALSO into a global
//!    [`crate::auditlog::AuditSink`] (typically a
//!    [`crate::auditlog::CompositeSink`] that also drives Plane 2 + 3).
//!    This is how the Hub UI gets the tri-plane correlated stream.
//!
//! Engine code is unchanged — `record_activation`, `record_decision`,
//! `snapshot` keep the same call shape.

use std::sync::Arc;
use time::OffsetDateTime;

use crate::auditlog::{
    AuditEvent, AuditSink, CompositeSink, DecisionSummary, EventPayload, Plane, RingSink,
};

use super::decision::Decision;
use super::request::PolicyRequest;

/// Plane-1 audit facade. The backing [`RingSink`] is exposed via
/// [`Self::snapshot`] so existing callers (engine tests, Hub UI Plane-1
/// panel) keep working.
pub struct PolicyAudit {
    /// Where Plane-1 events land. Always at least the backing ring; if a
    /// global sink was provided it's wrapped in a [`CompositeSink`].
    sink: Arc<dyn AuditSink>,
    /// Backing in-memory ring — keeps the [`Self::snapshot`] API working.
    ring: Arc<RingSink>,
}

impl PolicyAudit {
    /// Standalone ring with `capacity` slots — no cross-plane fan-out.
    /// Default for unit tests and engines constructed via
    /// [`super::Engine::deny_all`] / [`super::Engine::permissive`].
    pub fn new(capacity: usize) -> Self {
        let ring = Arc::new(RingSink::new(capacity));
        Self {
            sink: ring.clone(),
            ring,
        }
    }

    /// Cross-plane wiring: events land in this local ring AND in the
    /// supplied global sink. Production engines built by the Phase-7
    /// server call this with the composite sink that also drives Plane 2
    /// + Plane 3 emitters.
    pub fn with_global_sink(capacity: usize, global: Arc<dyn AuditSink>) -> Self {
        let ring = Arc::new(RingSink::new(capacity));
        let composite: Arc<dyn AuditSink> = Arc::new(CompositeSink::new(vec![ring.clone(), global]));
        Self { sink: composite, ring }
    }

    /// Borrow the backing ring (Hub UI Plane-1 panel reads through this).
    pub fn ring(&self) -> Arc<RingSink> {
        self.ring.clone()
    }

    pub fn record_activation(
        &self,
        ts: OffsetDateTime,
        policy_name: &str,
        new_fp: &str,
        prior_fp: Option<&str>,
        warnings: &[String],
    ) {
        // Policy-activation events have no per-request correlation — use the
        // policy fingerprint as the grouping key in the Hub UI.
        let correlation_id = format!("policy:{new_fp}");
        let ev = AuditEvent::at(
            ts,
            Plane::Agility,
            correlation_id,
            EventPayload::PolicyActivated {
                policy_name: policy_name.into(),
                new_fingerprint: new_fp.into(),
                prior_fingerprint: prior_fp.map(str::to_string),
                warnings: warnings.to_vec(),
            },
        );
        self.sink.emit(ev);
    }

    pub fn record_decision(&self, req: &PolicyRequest, decision: &Decision, policy_fp: &str) {
        let outcome = match decision {
            Decision::Allow {
                algorithm_override,
                substituted_by_rule,
            } => DecisionSummary::Allow {
                algorithm_override: algorithm_override.clone(),
                substituted_by_rule: *substituted_by_rule,
            },
            Decision::Deny {
                human,
                fired_rule_index,
                ..
            } => DecisionSummary::Deny {
                reason: human.clone(),
                fired_rule_index: *fired_rule_index,
            },
            Decision::RekeyAndProceed {
                new_algorithm,
                original_uid,
                ..
            } => DecisionSummary::Rekey {
                new_algorithm: new_algorithm.clone(),
                original_uid: original_uid.clone(),
            },
        };
        self.sink.emit(AuditEvent::at(
            req.ts,
            Plane::Agility,
            req.correlation_id.to_string(),
            EventPayload::PolicyDecided {
                op: req.op.into(),
                algorithm: req.algorithm.map(str::to_string),
                outcome,
                policy_fingerprint: policy_fp.into(),
            },
        ));

        if let Decision::RekeyAndProceed {
            original_uid,
            from_algorithm,
            new_algorithm,
            triggered_by_rule,
            ..
        } = decision
        {
            self.sink.emit(AuditEvent::at(
                req.ts,
                Plane::Agility,
                req.correlation_id.to_string(),
                EventPayload::RekeyPlanned {
                    original_uid: original_uid.clone(),
                    from_algorithm: from_algorithm.clone(),
                    new_algorithm: new_algorithm.clone(),
                    triggered_by_rule: *triggered_by_rule,
                    policy_fingerprint: policy_fp.into(),
                },
            ));
        }
    }

    /// Snapshot the backing ring — Plane-1 events only.
    pub fn snapshot(&self) -> Vec<AuditEvent> {
        self.ring.snapshot()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn activation_logged() {
        let audit = PolicyAudit::new(8);
        audit.record_activation(OffsetDateTime::UNIX_EPOCH, "test", "sha256:abc", None, &[]);
        let snap = audit.snapshot();
        assert_eq!(snap.len(), 1);
        assert!(matches!(snap[0].event, EventPayload::PolicyActivated { .. }));
        assert_eq!(snap[0].plane, Plane::Agility);
    }

    #[test]
    fn decision_logged_and_rekey_doubles_up() {
        let audit = PolicyAudit::new(8);
        let attrs = HashMap::new();
        let req = PolicyRequest::minimal(
            "Sign",
            Some("ECDSA-P256"),
            OffsetDateTime::UNIX_EPOCH,
            "corr-1",
            &attrs,
        );
        audit.record_decision(
            &req,
            &Decision::RekeyAndProceed {
                original_uid: "u1".into(),
                from_algorithm: "ECDSA-P256".into(),
                new_algorithm: "ML-DSA-65".into(),
                triggered_by_rule: 2,
                human: "rekey".into(),
            },
            "sha256:fp",
        );
        let snap = audit.snapshot();
        assert_eq!(snap.len(), 2);
        assert!(matches!(snap[0].event, EventPayload::PolicyDecided { .. }));
        assert!(matches!(snap[1].event, EventPayload::RekeyPlanned { .. }));
        // Both events share the request's correlation_id.
        assert_eq!(snap[0].correlation_id, "corr-1");
        assert_eq!(snap[1].correlation_id, "corr-1");
    }

    #[test]
    fn ring_evicts_oldest() {
        let audit = PolicyAudit::new(2);
        for i in 0..5 {
            audit.record_activation(
                OffsetDateTime::UNIX_EPOCH,
                &format!("p{i}"),
                "sha256:fp",
                None,
                &[],
            );
        }
        assert_eq!(audit.snapshot().len(), 2);
    }

    #[test]
    fn with_global_sink_fans_out_to_both() {
        let global = Arc::new(RingSink::new(8));
        let audit = PolicyAudit::with_global_sink(8, global.clone());
        let attrs = HashMap::new();
        let req = PolicyRequest::minimal(
            "Sign",
            Some("ML-DSA-87"),
            OffsetDateTime::UNIX_EPOCH,
            "global-corr",
            &attrs,
        );
        audit.record_decision(
            &req,
            &Decision::Allow {
                algorithm_override: None,
                substituted_by_rule: None,
            },
            "sha256:fp",
        );
        // Local ring saw it.
        assert_eq!(audit.snapshot().len(), 1);
        // Global ring also saw it.
        assert_eq!(global.snapshot().len(), 1);
        assert_eq!(global.snapshot()[0].correlation_id, "global-corr");
    }
}
