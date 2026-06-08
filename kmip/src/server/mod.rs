//! Plane 2 — KMIP server (TLS listener + connection handler).
//!
//! `tokio::net::TcpListener`, per-connection `tokio::spawn`, `tokio_rustls::TlsAcceptor`
//! with self-signed ML-DSA-65 cert generated on first start.
//!
//! Phase 0 (bootstrap): module declared, no implementation. Lands in Phase 7.
