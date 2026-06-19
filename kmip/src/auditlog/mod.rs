//! Cross-plane audit log surface.
//!
//! Every plane — Plane 1 (agility engine), Plane 2 (KMIP dispatcher + ops),
//! Plane 3 (PKCS#11 bridge) — emits its events through an [`AuditSink`].
//! The Hub UI is a **passive viewer** that tails the resulting stream and
//! renders rows grouped by [`event::CorrelationId`]. There is no joiner,
//! no enrichment, no correlation logic on the UI side.
//!
//! ## Layered architecture
//!
//! ```text
//!   Plane 1 ── emit() ─┐
//!   Plane 2 ── emit() ─┼─► Arc<dyn AuditSink> ─► CompositeSink ─┬─► RingSink    (admin GET /audit)
//!   Plane 3 ── emit() ─┘                                        ├─► SseSink     (SSE stream)
//!                                                                ├─► JsonlSink   (durable file)
//!                                                                ├─► SyslogSink  (UDP syslog)
//!                                                                └─► OtlpSink    (OTLP/HTTP)
//! ```
//!
//! Each plane is constructed with an `Arc<dyn AuditSink>`. Production
//! wires all three to the same sink. Tests wire each to its own
//! [`RingSink`] for isolation. The trait is `Send + Sync` so one sink
//! safely fans across concurrent emissions.
//!
//! ## What each plane emits (today vs planned)
//!
//! | Plane | Events | Status |
//! |-------|--------|--------|
//! | P1 — agility | `PolicyActivated`, `PolicyDecided`, `RekeyPlanned` | ✅ wired (this phase) |
//! | P2 — KMIP    | `KmipRequestReceived`, `KmipResponseSent`, `KmipObjectStateChanged` | ⏳ Phase 5–6 |
//! | P3 — PKCS#11 | `Pkcs11Call`, `Pkcs11SessionLifecycle` | ⏳ Phase 5 (when ops drive the bridge) |
//!
//! Variant shape is committed wire-format — Phase 5 / 6 emitters fill in
//! the payload fields, no schema change.

pub mod composite;
pub mod event;
pub mod jsonl;
pub mod otlp;
pub mod ring;
pub mod sink;
pub mod sse;
pub mod syslog;

pub use composite::CompositeSink;
pub use event::{AuditEvent, CorrelationId, DecisionSummary, EventPayload, KmipOpResult, Plane};
pub use jsonl::JsonlSink;
pub use otlp::OtlpSink;
pub use ring::RingSink;
pub use sink::{AuditSink, NullSink};
pub use sse::SseSink;
pub use syslog::SyslogSink;
