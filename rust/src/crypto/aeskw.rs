//! AES Key Wrap (RFC 3394, `CKM_AES_KEY_WRAP`) and Key Wrap with Padding
//! (RFC 5649, `CKM_AES_KEY_WRAP_KWP`), dispatched on KEK length.
//!
//! One home for the aes-kw calls that used to be written out inline at every
//! wrap/unwrap site. It deliberately does NOT decide PKCS#11 return codes:
//! the `ffi` and `native` paths map the same failure to different codes on
//! purpose (e.g. an out-of-range KEK is `CKR_WRAPPING_KEY_SIZE_RANGE` from
//! `C_WrapKey` but `CKR_KEY_TYPE_INCONSISTENT` from `native::aes_key_wrap`),
//! so each call site keeps its own mapping and its own precondition checks,
//! and this module only reports *which* kind of failure happened.
//!
//! aes-kw 0.3 (the cipher-0.5 generation) takes a caller-sized output buffer
//! instead of 0.2's `*_vec` helpers. The sizes below are what its
//! implementation actually checks (read from the crate source, not its doc
//! comments, one of which is looser than the code):
//! KW wrap `n + 8`, KW unwrap `n - 8`, KWP wrap `ceil(n / 8) * 8 + 8`,
//! KWP unwrap `n - 8` (the returned slice is the unpadded plaintext).

use aes_kw::{KeyInit, KwAes128, KwAes192, KwAes256, KwpAes128, KwpAes192, KwpAes256};

/// Why a wrap/unwrap failed — callers map this to their own `CKR_*`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum KwError {
    /// KEK is not 16, 24 or 32 bytes.
    KekLen,
    /// The operation itself failed: bad input size, or (unwrap) the RFC
    /// 3394/5649 integrity check did not pass.
    Failed,
}

macro_rules! dispatch {
    ($kek:expr, $t128:ty, $t192:ty, $t256:ty, |$kw:ident| $body:expr) => {
        match $kek.len() {
            16 => { let $kw = <$t128>::new_from_slice($kek).map_err(|_| KwError::KekLen)?; $body }
            24 => { let $kw = <$t192>::new_from_slice($kek).map_err(|_| KwError::KekLen)?; $body }
            32 => { let $kw = <$t256>::new_from_slice($kek).map_err(|_| KwError::KekLen)?; $body }
            _ => Err(KwError::KekLen),
        }
    };
}

/// RFC 3394 wrap. Output is `data.len() + 8` bytes.
pub(crate) fn kw_wrap(kek: &[u8], data: &[u8]) -> Result<Vec<u8>, KwError> {
    let mut buf = vec![0u8; data.len() + 8];
    dispatch!(kek, KwAes128, KwAes192, KwAes256, |kw| {
        kw.wrap_key(data, &mut buf).map(|o| o.to_vec()).map_err(|_| KwError::Failed)
    })
}

/// RFC 3394 unwrap. Output is `wrapped.len() - 8` bytes.
pub(crate) fn kw_unwrap(kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, KwError> {
    let mut buf = vec![0u8; wrapped.len().saturating_sub(8)];
    dispatch!(kek, KwAes128, KwAes192, KwAes256, |kw| {
        kw.unwrap_key(wrapped, &mut buf).map(|o| o.to_vec()).map_err(|_| KwError::Failed)
    })
}

/// RFC 5649 wrap (any non-empty length).
pub(crate) fn kwp_wrap(kek: &[u8], data: &[u8]) -> Result<Vec<u8>, KwError> {
    let mut buf = vec![0u8; data.len().div_ceil(8) * 8 + 8];
    dispatch!(kek, KwpAes128, KwpAes192, KwpAes256, |kw| {
        kw.wrap_key(data, &mut buf).map(|o| o.to_vec()).map_err(|_| KwError::Failed)
    })
}

/// RFC 5649 unwrap; returns the unpadded plaintext.
pub(crate) fn kwp_unwrap(kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, KwError> {
    let mut buf = vec![0u8; wrapped.len().saturating_sub(8)];
    dispatch!(kek, KwpAes128, KwpAes192, KwpAes256, |kw| {
        kw.unwrap_key(wrapped, &mut buf).map(|o| o.to_vec()).map_err(|_| KwError::Failed)
    })
}
