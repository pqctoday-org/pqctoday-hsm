//! [`PolicyAudit`] — Plane-1 in-memory audit ring.
//!
//! Captures three event classes the Hub UI and Phase 9 audit CLI both need:
//!
//! - **PolicyActivated** — every successful [`super::Engine::activate`] call.
//!   Carries the new policy's fingerprint, the prior fingerprint (so an
//!   operator can diff which YAML was just swapped in), and any loader
//!   warnings.
//! - **Decision** — one row per `evaluate` call: the request shape +
//!   resulting [`super::Decision`] + the active policy fingerprint at the
//!   time. Lets the operator answer "why was this Sign denied at 09:14:32?"
//!   without replaying the request.
//! - **RekeyPlanned** — synthesised when an `evaluate` returns
//!   [`super::Decision::RekeyAndProceed`]. Same info as the Decision row
//!   plus the rekey-specific fields, separated so the rekey audit view in
//!   the Hub doesn't have to walk every Decision row.
//!
//! Storage is a bounded ring buffer (default 1024 entries) — sufficient
//! for a sandbox-grade engine and the per-request "what just happened?"
//! UI. Phase 9 wires this to the SQLite audit log for durable history.

use std::collections::VecDeque;
use std::sync::Mutex;
use time::OffsetDateTime;

use super::decision::Decision;
use super::request::PolicyRequest;

#[derive(Clone, Debug)]
pub enum AuditEvent {
    PolicyActivated {
        ts: OffsetDateTime,
        policy_name: String,
        new_fingerprint: String,
        prior_fingerprint: Option<String>,
        warnings: Vec<String>,
    },
    Decision {
        ts: OffsetDateTime,
        op: String,
        algorithm: Option<String>,
        correlation_id: String,
        policy_fingerprint: String,
        outcome: AuditDecision,
    },
    RekeyPlanned {
        ts: OffsetDateTime,
        correlation_id: String,
        original_uid: String,
        from_algorithm: String,
        new_algorithm: String,
        triggered_by_rule: usize,
        policy_fingerprint: String,
    },
}

/// Compact projection of [`Decision`] suitable for log persistence.
#[derive(Clone, Debug)]
pub enum AuditDecision {
    Allow {
        algorithm_override: Option<String>,
        substituted_by_rule: Option<usize>,
    },
    Deny {
        reason: String,
        fired_rule_index: usize,
    },
    Rekey {
        new_algorithm: String,
        original_uid: String,
    },
}

pub struct PolicyAudit {
    inner: Mutex<VecDeque<AuditEvent>>,
    capacity: usize,
}

impl PolicyAudit {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
        }
    }

    pub fn record_activation(
        &self,
        ts: OffsetDateTime,
        policy_name: &str,
        new_fp: &str,
        prior_fp: Option<&str>,
        warnings: &[String],
    ) {
        self.push(AuditEvent::PolicyActivated {
            ts,
            policy_name: policy_name.into(),
            new_fingerprint: new_fp.into(),
            prior_fingerprint: prior_fp.map(str::to_string),
            warnings: warnings.to_vec(),
        });
    }

    pub fn record_decision(&self, req: &PolicyRequest, decision: &Decision, policy_fp: &str) {
        let outcome = match decision {
            Decision::Allow {
                algorithm_override,
                substituted_by_rule,
            } => AuditDecision::Allow {
                algorithm_override: algorithm_override.clone(),
                substituted_by_rule: *substituted_by_rule,
            },
            Decision::Deny {
                human,
                fired_rule_index,
                ..
            } => AuditDecision::Deny {
                reason: human.clone(),
                fired_rule_index: *fired_rule_index,
            },
            Decision::RekeyAndProceed {
                new_algorithm,
                original_uid,
                ..
            } => AuditDecision::Rekey {
                new_algorithm: new_algorithm.clone(),
                original_uid: original_uid.clone(),
            },
        };
        self.push(AuditEvent::Decision {
            ts: req.ts,
            op: req.op.into(),
            algorithm: req.algorithm.map(str::to_string),
            correlation_id: req.correlation_id.into(),
            policy_fingerprint: policy_fp.into(),
            outcome,
        });

        if let Decision::RekeyAndProceed {
            original_uid,
            from_algorithm,
            new_algorithm,
            triggered_by_rule,
            ..
        } = decision
        {
            self.push(AuditEvent::RekeyPlanned {
                ts: req.ts,
                correlation_id: req.correlation_id.into(),
                original_uid: original_uid.clone(),
                from_algorithm: from_algorithm.clone(),
                new_algorithm: new_algorithm.clone(),
                triggered_by_rule: *triggered_by_rule,
                policy_fingerprint: policy_fp.into(),
            });
        }
    }

    /// Snapshot the current event ring. Cheap-ish — clones the deque.
    pub fn snapshot(&self) -> Vec<AuditEvent> {
        self.inner
            .lock()
            .expect("audit ring poisoned")
            .iter()
            .cloned()
            .collect()
    }

    fn push(&self, ev: AuditEvent) {
        let mut q = self.inner.lock().expect("audit ring poisoned");
        if q.len() == self.capacity {
            q.pop_front();
        }
        q.push_back(ev);
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
        assert_eq!(audit.snapshot().len(), 1);
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
        // Two events: Decision + RekeyPlanned
        let snap = audit.snapshot();
        assert_eq!(snap.len(), 2);
        assert!(matches!(snap[0], AuditEvent::Decision { .. }));
        assert!(matches!(snap[1], AuditEvent::RekeyPlanned { .. }));
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
}
