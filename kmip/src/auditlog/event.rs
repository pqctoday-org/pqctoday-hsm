//! [`AuditEvent`] — the common envelope that every plane emits.
//!
//! Every plane (P1 agility engine, P2 KMIP dispatcher + ops, P3 PKCS#11
//! bridge) emits its events through an [`super::AuditSink`] wrapped in this
//! envelope. The Hub UI consumes the resulting stream — no per-plane
//! parser, no correlation logic in the UI: it groups by `correlation_id`
//! and orders by `ts`.
//!
//! ## Envelope shape (wire-format committed)
//!
//! ```json
//! {
//!   "ts":              "2026-06-07T14:32:11.482Z",
//!   "plane":           "p1" | "p2" | "p3",
//!   "correlation_id":  "<opaque uuid-ish string>",
//!   "event":           { … plane-specific payload … }
//! }
//! ```
//!
//! The Hub UI binds against `plane` + `event.type` to pick rendering
//! components (badge colour, icon, expand/collapse layout).
//!
//! ## Why one envelope across all planes
//!
//! Multiple planes need to fan into the same JSONL file / SSE stream / Hub
//! viewer with **no joiner step in between**. A single envelope means:
//!
//! - The Phase-7 server can serve `GET /audit/tail` as a raw passthrough.
//! - The Hub UI parses one schema, regardless of which plane emitted.
//! - `correlation_id` always lives in the same field.
//! - Adding a future plane (e.g. a KMS replication peer) costs a new
//!   `EventPayload` variant — no envelope migration.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Which plane emitted this event. Wire-format string is the
/// `#[serde(rename)]` value — Hub UI binds against these literals.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Plane {
    /// Plane 1 — Crypto Agility Management (policy engine).
    #[serde(rename = "p1")]
    Agility,
    /// Plane 2 — KMIP 3.0 dispatcher + op handlers.
    #[serde(rename = "p2")]
    Kmip,
    /// Plane 3 — PKCS#11 bridge to softhsmrustv3.
    #[serde(rename = "p3")]
    Pkcs11,
}

impl Plane {
    /// Short symbolic name (`"p1"`, `"p2"`, `"p3"`). Same as the serde rename.
    pub fn as_str(self) -> &'static str {
        match self {
            Plane::Agility => "p1",
            Plane::Kmip => "p2",
            Plane::Pkcs11 => "p3",
        }
    }
}

/// Opaque per-request identifier shared across all three planes for one
/// inbound KMIP request. The Phase-7 server allocates one at request
/// ingress; everything downstream (engine, dispatcher, op handler, bridge)
/// stamps the same value on every event it emits.
pub type CorrelationId = String;

/// Common envelope for every emitted event.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Emission timestamp. UTC.
    #[serde(with = "time::serde::rfc3339")]
    pub ts: OffsetDateTime,

    /// Which plane emitted this event.
    pub plane: Plane,

    /// Per-request correlation. Shared across all three planes for one
    /// inbound request.
    pub correlation_id: CorrelationId,

    /// Plane-specific payload.
    pub event: EventPayload,
}

impl AuditEvent {
    /// Construct an event with `ts = now()`.
    pub fn new(
        plane: Plane,
        correlation_id: impl Into<CorrelationId>,
        event: EventPayload,
    ) -> Self {
        Self {
            ts: OffsetDateTime::now_utc(),
            plane,
            correlation_id: correlation_id.into(),
            event,
        }
    }

    /// Convenience: build an event with an explicit `ts`. Tests use this
    /// to pin a deterministic clock; production should prefer [`Self::new`].
    pub fn at(
        ts: OffsetDateTime,
        plane: Plane,
        correlation_id: impl Into<CorrelationId>,
        event: EventPayload,
    ) -> Self {
        Self {
            ts,
            plane,
            correlation_id: correlation_id.into(),
            event,
        }
    }
}

/// Plane-specific event payload. Wire format: `{ "type": "<variant>", … }`
/// (serde's adjacently-tagged form maps cleanly to the Hub UI's component
/// dispatch).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum EventPayload {
    // ── Plane 1 — agility engine ──────────────────────────────────────────
    /// A new policy was activated (operator edit or startup load).
    PolicyActivated {
        policy_name: String,
        new_fingerprint: String,
        prior_fingerprint: Option<String>,
        warnings: Vec<String>,
    },
    /// Engine evaluated a request and returned a decision.
    PolicyDecided {
        op: String,
        algorithm: Option<String>,
        outcome: DecisionSummary,
        policy_fingerprint: String,
    },
    /// Engine planned a rekey — dispatcher (Phase 5) executes.
    RekeyPlanned {
        original_uid: String,
        from_algorithm: String,
        new_algorithm: String,
        triggered_by_rule: usize,
        policy_fingerprint: String,
    },

    // ── Plane 2 — KMIP ────────────────────────────────────────────────────
    /// KMIP request landed at the dispatcher. Phase 5 emits.
    KmipRequestReceived {
        op: String,
        request_summary: String,
        client_cn: Option<String>,
    },
    /// KMIP response about to leave the dispatcher. Phase 5 emits.
    KmipResponseSent {
        op: String,
        result: KmipOpResult,
        latency_ms: u32,
    },
    /// Managed-object lifecycle transition (PreActive → Active, etc.).
    /// Phase 6 emits when the store FSM fires.
    KmipObjectStateChanged {
        uid: String,
        from_state: String,
        to_state: String,
        reason: String,
    },

    // ── Plane 3 — PKCS#11 ─────────────────────────────────────────────────
    /// One PKCS#11 entry-point call. Phase 5 (op handlers) emits per call.
    Pkcs11Call {
        function: String, // "C_GenerateKeyPair", "C_Sign", "C_EncapsulateKey", ...
        mechanism: Option<String>, // CKM_* symbolic name, when applicable
        slot: Option<u32>,
        session: Option<u32>,
        rv: u32, // CK_RV — 0 for CKR_OK
        rv_name: String, // "CKR_OK", "CKR_ARGUMENTS_BAD", ...
        latency_ms: u32,
    },
    /// PKCS#11 session opened / closed. Phase 4 bridge emits when wired.
    Pkcs11SessionLifecycle {
        action: String, // "open" | "close"
        slot: u32,
        session: u32,
    },
}

/// Compact projection of `policy::Decision` for the audit envelope.
/// Wire-format committed: Hub UI renders by `outcome.type`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum DecisionSummary {
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

/// Compact KMIP response status for the audit envelope.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum KmipOpResult {
    Success,
    OperationFailed { reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plane_serde_round_trip() {
        for p in [Plane::Agility, Plane::Kmip, Plane::Pkcs11] {
            let s = serde_json::to_string(&p).unwrap();
            let back: Plane = serde_json::from_str(&s).unwrap();
            assert_eq!(p, back);
        }
        // Wire-format pin.
        assert_eq!(serde_json::to_string(&Plane::Agility).unwrap(), "\"p1\"");
        assert_eq!(serde_json::to_string(&Plane::Kmip).unwrap(), "\"p2\"");
        assert_eq!(serde_json::to_string(&Plane::Pkcs11).unwrap(), "\"p3\"");
    }

    #[test]
    fn envelope_serialises_with_iso_timestamp() {
        let ev = AuditEvent::at(
            OffsetDateTime::from_unix_timestamp(1_780_000_000).unwrap(),
            Plane::Agility,
            "corr-1",
            EventPayload::PolicyDecided {
                op: "Sign".into(),
                algorithm: Some("ML-DSA-87".into()),
                policy_fingerprint: "sha256:abc".into(),
                outcome: DecisionSummary::Allow {
                    algorithm_override: None,
                    substituted_by_rule: None,
                },
            },
        );
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("\"plane\":\"p1\""));
        assert!(json.contains("\"correlation_id\":\"corr-1\""));
        assert!(json.contains("\"type\":\"PolicyDecided\""));
        // Round-trip.
        let back: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.correlation_id, "corr-1");
        assert_eq!(back.plane, Plane::Agility);
    }
}
