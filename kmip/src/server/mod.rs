//! Plane 2 — KMIP server (TLS listener + connection handler).
//!
//! Phase 7 ships:
//!
//! - [`listener::serve`] — async TLS-terminated KMIP listener
//! - [`listener::tls_self_signed`] — auto-gen Ed25519 cert for sandbox use
//! - [`listener::tls_from_pem`] — load real PEM cert + key from disk
//! - [`listener::tls_mtls`] — mTLS server config (Phase 7b will wire)
//!
//! Wire framing: TTLV is self-describing per KMIP 3.0 §9.6 — no extra
//! length prefix needed. The listener reads exactly one TTLV frame per
//! connection (KMIP `Request Message`), dispatches via
//! [`crate::dispatcher::dispatch`], writes the encoded `Response Message`,
//! and closes.

pub mod listener;

pub use listener::{serve, tls_from_pem, tls_self_signed, ServerError};
