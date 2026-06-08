//! `pqctoday-kmip` — KMIP 3.0 PQC + classical key management wrapper over `pqctoday-hsm` PKCS#11.
//!
//! Three-plane architecture (see `docs/THREE_PLANE_ARCHITECTURE.md`):
//!
//! * **Plane 1 — Crypto Agility Management:** [`policy`] — what crypto is allowed.
//! * **Plane 2 — KMIP 3.0 Key Management:** [`codec`], [`kmip30`], [`dispatcher`], [`ops`],
//!   [`store`], [`attrmap`] — where keys live, what their attributes are, what operations
//!   are allowed.
//! * **Plane 3 — PKCS#11 Crypto Execution:** [`pkcs11bridge`] — execute the mechanism
//!   against the token. Direct dependency on `softhsmrustv3`, no FFI.
//!
//! Phase 0 (bootstrap): module skeleton only. Each module is materialised in its own
//! later phase per `docs/IMPLEMENTATION_PLAN.md` §6.

// Plane 1 — Crypto Agility Management
pub mod policy;

// Plane 2 — KMIP 3.0 Key Management
pub mod codec;
pub mod kmip30;
pub mod dispatcher;
pub mod ops;
pub mod store;
pub mod attrmap;
pub mod server;

// Plane 3 — PKCS#11 Crypto Execution
pub mod pkcs11bridge;

// Cross-plane infrastructure
pub mod auditlog;
pub mod types;
pub mod error;

pub use error::KmipError;
