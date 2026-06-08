//! Sign / Verify — typed dispatcher over `crypto::handlers::sign_*` and
//! `crypto::handlers::verify_*` (which already accept typed args).
//!
//! Resolves the key handle to its stored bytes via `state::*`, dispatches
//! on `mechanism` + key type, calls the right typed primitive. Returns
//! the signature as `Vec<u8>` (no caller-allocated output buffer).
//!
//! See [`super`] for the typed-vs-FFI architectural relationship.
//! Implementation lands in Phase 7b commit 4.

use super::CkRv;

/// Sign `data` with the key at `key_handle` using `mechanism`. Dispatches
/// to `crypto::handlers::sign_{ml_dsa, slh_dsa, rsa, ecdsa, eddsa, hmac}`
/// based on the stored key's algorithm.
pub fn sign(
    _session: u32,
    _key_handle: u32,
    _mechanism: u32,
    _data: &[u8],
) -> Result<Vec<u8>, CkRv> {
    unimplemented!("native::sign::sign — Phase 7b commit 4")
}

/// Verify `signature` over `data` with the key at `key_handle` using
/// `mechanism`. Returns `Ok(true)` on valid signature, `Ok(false)` on
/// invalid (NOT an error — matches the KMIP `validity_indicator` model).
/// `Err(_)` is for protocol-level failures (wrong key type, etc.).
pub fn verify(
    _session: u32,
    _key_handle: u32,
    _mechanism: u32,
    _data: &[u8],
    _signature: &[u8],
) -> Result<bool, CkRv> {
    unimplemented!("native::sign::verify — Phase 7b commit 4")
}
