//! Cross-plane audit log — async JSONL writer.
//!
//! One line per plane-event per request. All entries for a single application
//! request share a `correlation_id` so policy / KMIP / PKCS#11 events can be
//! joined into a forensic trace.
//!
//! Phase 0 (bootstrap): module declared, no implementation. Lands in Phase 9.
