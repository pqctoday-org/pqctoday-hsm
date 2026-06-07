//! Plane 3 — PKCS#11 bridge to `softhsmrustv3`.
//!
//! Trivial in Rust — no FFI. `use softhsmrustv3;` and wrap session management +
//! the small set of helpers the dispatcher needs (find-by-CKA_ID, RAII session
//! close on drop, vendor mech constants generated from `pkcs11-mech-manifest.json`).
//!
//! Phase 0 (bootstrap): module declared, no implementation. Lands in Phase 4.
