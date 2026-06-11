//! Plane 2 — KMIP server (TLS listener + connection handler).
//!
//! Phase 7 ships:
//!
//! - [`listener::serve`] — async TLS-terminated KMIP listener
//! - [`listener::tls_self_signed`] — auto-gen Ed25519 cert for sandbox use
//! - [`listener::tls_from_pem`] — load real PEM cert + key from disk
//! - [`listener::tls_mtls`] — mTLS server config (K14: wired behind
//!   `--tls-client-ca`; verified client-cert subject CN → KMIP identity)
//! - [`auth`] — K14 §8.1.2 Authentication: credential verifier +
//!   config-backed user store (open-auth when no users configured)
//!
//! Wire framing: TTLV is self-describing per KMIP 3.0 §9.6 — no extra
//! length prefix needed. The listener reads exactly one TTLV frame per
//! connection (KMIP `Request Message`), dispatches via
//! [`crate::dispatcher::dispatch`], writes the encoded `Response Message`,
//! and closes.

pub mod auth;
pub mod listener;

pub use auth::{AuthContext, AuthUser, ConfigVerifier, CredentialVerifier, Identity};
pub use listener::{serve, tls_from_pem, tls_mtls, tls_self_signed, ServerError};
