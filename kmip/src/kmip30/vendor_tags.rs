//! PQCToday vendor-extension TTLV tags.
//!
//! KMIP 3.0 §11.57 (Tag Enumeration) reserves the Item Tag range
//! `0x540000–0x54FFFF` for Extensions: "All tags SHALL contain either
//! the value 42 in hex or the value 54 in hex as the first byte …
//! Tags defined by this specification contain hex 42 in the first
//! byte. Extensions contain the value 54." Tags allocated here are
//! PQCToday-specific, append-only, and MUST NOT collide with the
//! standard `0x42xxxx` space in [`super::wire`]'s tag table.
//!
//! Allocations are mirrored in `kmip/pkcs11-mech-manifest.json`
//! (`vendor_tags` section) — keep both in sync.

/// `PQCToday-SharedSecret` (`0x540001`) — carries the ML-KEM
/// encapsulation shared secret in an Encrypt response payload.
///
/// KMIP 3.0 has no Encapsulate operation; this server overloads
/// Encrypt/Decrypt for ML-KEM encapsulation/decapsulation as a
/// documented vendor extension (see `docs/CONFORMANCE_REPORT.md`).
/// The shared secret previously rode the standard `IVCounterNonce`
/// tag (`0x42003d`), which is wire-ambiguous with classical RandomIV
/// responses (compliance-audit B-7); this dedicated extension tag
/// removes the collision. `IVCounterNonce` is now strictly an IV.
pub const PQCTODAY_SHARED_SECRET: u32 = 0x54_0001;
