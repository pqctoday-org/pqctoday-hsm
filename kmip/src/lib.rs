//! `pqctoday-kmip` — KMIP 3.0 PQC + classical key management wrapper over `pqctoday-hsm` PKCS#11.
//!
//! Three-plane architecture (see `docs/THREE_PLANE_ARCHITECTURE.md`):
//!
//! * **Plane 1 — Crypto Agility Management:** [`policy`] — what crypto is allowed.
//! * **Plane 2 — KMIP 3.0 Key Management:** [`codec`], [`kmip30`], [`dispatcher`], [`ops`],
//!   [`store`] — where keys live, what their attributes are, what operations
//!   are allowed.
//! * **Plane 3 — PKCS#11 Crypto Execution:** the [`ops`] handlers call
//!   `softhsmrustv3::native::*` directly — a typed in-process Rust path,
//!   no FFI and no separate bridge module (K1 / compliance-audit K-17).

// Plane 1 — Crypto Agility Management
pub mod policy;

// Plane 2 — KMIP 3.0 Key Management
pub mod codec;
pub mod kmip30;
pub mod dispatcher;
pub mod ops;
pub mod store;
pub mod hybrid_kem;
pub mod server;

// Cross-plane infrastructure
pub mod auditlog;

// Tests that bootstrap a real `softhsmrustv3` engine session serialize on
// `ops::helpers::engine_lock()` — the engine's object store / login state
// is process-global (`rust/src/state.rs`'s `OBJECTS`/`TOKEN_STORE` are
// singletons), so two such tests running concurrently (the default
// `cargo test` behavior) can stomp each other's `C_InitToken`/login/object
// state. There must be exactly ONE such lock crate-wide — a second,
// independent `Mutex` here (as this module used to be) doesn't block the
// first, so tests split across the two race each other anyway. See
// `ops::helpers::engine_lock`'s doc for the canonical instance.

// Prometheus `/metrics` — `native` only (the wasm core has no scrape endpoint).
#[cfg(feature = "native")]
pub mod metrics;
pub mod types;
pub mod error;

// C0 — internalized admin mTLS cert minting (no shell / openssl CLI dependency).
// `native` only — rcgen/aws_lc_rs does not cross-compile to wasm32.
#[cfg(feature = "native")]
pub mod cert_init;

// W4 — out-of-band HTTP admin facade for the Plane-1 policy plane. Source
// lives in the `cryptopolicy-manager/` sibling dir (its own component) but is
// compiled into the crate so it can share the live `policy::Engine`.
// `native` only — it is a tokio + rustls TLS HTTP server.
#[cfg(feature = "native")]
#[path = "../cryptopolicy-manager/manager.rs"]
pub mod cryptopolicy_manager;

pub use error::KmipError;
