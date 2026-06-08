//! Plane 2 — Request dispatcher.
//!
//! Routes decoded KMIP requests to `ops::*` handlers, with a Plane 1 policy
//! evaluation gate first. Per-request `correlation_id` ties policy / KMIP /
//! PKCS#11 audit-log entries together.
//!
//! Phase 0 (bootstrap): module declared, no implementation. Lands in Phase 7
//! per `docs/IMPLEMENTATION_PLAN.md` §6.
