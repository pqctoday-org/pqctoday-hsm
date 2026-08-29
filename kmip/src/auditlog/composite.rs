//! [`CompositeSink`] — fan an event out to multiple sinks in declaration
//! order. Typical wiring:
//!
//! ```ignore
//! let ring  = Arc::new(RingSink::new(16_384));
//! let jsonl = Arc::new(JsonlSink::open("/var/log/pqctoday/audit.jsonl")?);
//! let sink  = Arc::new(CompositeSink::new(vec![ring.clone(), jsonl]));
//! engine.set_sink(sink);
//! ```
//!
//! The `ring` handle stays callable for the Hub UI's `/audit/tail` endpoint
//! while the `jsonl` writer accumulates durable forensic history.

use std::sync::Arc;

use super::event::AuditEvent;
use super::sink::AuditSink;

pub struct CompositeSink {
    sinks: Vec<Arc<dyn AuditSink>>,
}

impl CompositeSink {
    pub fn new(sinks: Vec<Arc<dyn AuditSink>>) -> Self {
        Self { sinks }
    }
}

impl AuditSink for CompositeSink {
    fn emit(&self, event: AuditEvent) {
        for sink in &self.sinks {
            // Clone on each fan-out leg so each sink owns its own copy.
            // Cheap — `AuditEvent` is small and the payload variants are
            // String + a few u32s.
            sink.emit(event.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::event::{DecisionSummary, EventPayload, Plane};
    use super::super::ring::RingSink;
    use time::OffsetDateTime;

    #[test]
    fn fan_out_to_two_rings() {
        let a = Arc::new(RingSink::new(8));
        let b = Arc::new(RingSink::new(8));
        let comp: Arc<dyn AuditSink> = Arc::new(CompositeSink::new(vec![
            a.clone(),
            b.clone(),
        ]));
        comp.emit(AuditEvent::at(
            OffsetDateTime::UNIX_EPOCH,
            Plane::Agility,
            "c1",
            EventPayload::PolicyDecided {
                op: "Sign".into(),
                algorithm: None,
                outcome: DecisionSummary::Allow {
                    algorithm_override: None,
                    substituted_by_rule: None,
                    cp_override: None,
                },
                policy_fingerprint: "sha256:0".into(),
            },
        ));
        assert_eq!(a.snapshot().len(), 1);
        assert_eq!(b.snapshot().len(), 1);
    }
}
