//! [`AuditSink`] — the trait every emitter writes through.
//!
//! Three concrete implementations ship in this module:
//!
//! - [`super::RingSink`] — bounded in-memory ring, default for sandbox /
//!   tests / Hub UI history panel.
//! - [`super::JsonlSink`] — append-only file writer, JSONL format, default
//!   for production runs.
//! - [`super::CompositeSink`] — fan-out to multiple sinks (typical wiring:
//!   `Composite(Ring, Jsonl)` so the Hub UI can tail recent history from
//!   the ring while the JSONL file accumulates durable forensic records).
//!
//! The trait is `Send + Sync` so a single sink can be cloned (via `Arc`)
//! to every plane.

use super::event::AuditEvent;

/// Object-safe sink trait. `emit` is best-effort: a sink that's full /
/// closed / errored MUST NOT panic — it should log internally and drop
/// the event. Audit MUST NEVER take down a production request.
pub trait AuditSink: Send + Sync {
    /// Append one event. Best-effort; never panics.
    fn emit(&self, event: AuditEvent);
}

/// No-op sink. Useful when audit is disabled at startup or in benchmarks.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullSink;

impl AuditSink for NullSink {
    fn emit(&self, _event: AuditEvent) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::event::{EventPayload, Plane};
    use time::OffsetDateTime;

    #[test]
    fn null_sink_swallows_events() {
        let sink = NullSink;
        sink.emit(AuditEvent::at(
            OffsetDateTime::UNIX_EPOCH,
            Plane::Agility,
            "corr",
            EventPayload::PolicyDecided {
                op: "Sign".into(),
                algorithm: None,
                outcome: super::super::event::DecisionSummary::Allow {
                    algorithm_override: None,
                    substituted_by_rule: None,
                },
                policy_fingerprint: "sha256:0".into(),
            },
        ));
    }
}
