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
//! ## What each plane emits
//!
//! | Plane | Events |
//! |-------|--------|
//! | P1 — agility | `PolicyActivated`, `PolicyDecided`, `RekeyPlanned` |
//! | P2 — KMIP    | `KmipRequestReceived`, `KmipResponseSent`, `KmipObjectStateChanged` |
//! | P3 — PKCS#11 | `Pkcs11Call`, `Pkcs11SessionLifecycle` |
//!
//! All three planes are wired and emitted throughout `ops/*.rs` today
//! (`emit_request`/`emit_success`/`emit_pkcs11*` helpers), driving real
//! `Pkcs11Call` records with the actual softhsmrustv3 entry point + rv
//! whenever `deps.engine_session` is present.

pub mod composite;
pub mod event;
pub mod jsonl;
// OTLP/HTTP + SSE sinks are async (tokio) — `native` only. The wasm core
// fans audit events into the in-memory `RingSink`.
#[cfg(feature = "native")]
pub mod otlp;
pub mod ring;
pub mod sink;
#[cfg(feature = "native")]
pub mod sse;
pub mod syslog;

pub use composite::CompositeSink;
pub use event::{AuditEvent, CorrelationId, DecisionSummary, EventPayload, KmipOpResult, Plane};
pub use jsonl::JsonlSink;
#[cfg(feature = "native")]
pub use otlp::OtlpSink;
pub use ring::RingSink;
pub use sink::{AuditSink, NullSink};
#[cfg(feature = "native")]
pub use sse::SseSink;
pub use syslog::SyslogSink;
