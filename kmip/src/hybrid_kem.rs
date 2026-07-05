//! Hybrid KEM — thin re-export of the engine's implementation.
//!
//! All hybrid-KEM cryptography lives in the PKCS#11 engine
//! ([`softhsmrustv3::native::hybrid`]) where every crypto primitive belongs.
//! A hybrid key is NOT a composite blob: one KMIP object is tied to TWO
//! non-extractable PKCS#11 handles — one classical (X25519 / ECDH P-256 or
//! P-384), one ML-KEM. The op handlers (`create_key_pair` / `encapsulate` /
//! `decapsulate`) drive the engine by handle; no private material and no crypto
//! crate enters this layer.
//!
//! This module previously held a duplicate byte-based implementation (with its
//! own `ml-kem` / `x25519-dalek` / `p256` dependencies). That duplication is
//! removed — the KMIP layer now names the engine types through
//! `crate::hybrid_kem::*` and calls `softhsmrustv3::native::hybrid::*` for the
//! operations.

pub use softhsmrustv3::native::hybrid::{Encapsulated, Hybrid, HybridKeyGen};
