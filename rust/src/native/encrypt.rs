//! Encrypt / Decrypt / Encapsulate / Decapsulate — typed wrappers.
//!
//! `encrypt` / `decrypt` cover the classical symmetric / asymmetric paths
//! (AES-GCM, AES-CBC, RSA-OAEP). `encapsulate` / `decapsulate` are the
//! ML-KEM-specific calls — separate functions because they return
//! (ciphertext + shared_secret) rather than just ciphertext.
//!
//! Native wrappers around `ffi::C_EncryptInit` + `ffi::C_Encrypt`,
//! `ffi::C_DecryptInit` + `ffi::C_Decrypt`, `ffi::C_EncapsulateKey`,
//! `ffi::C_DecapsulateKey` — refactored to take typed args.
//!
//! Implementation lands in Phase 7b commit 5.

use super::CkRv;

/// Classical encrypt. `mechanism` ∈ {`CKM_AES_GCM`, `CKM_AES_CBC_PAD`,
/// `CKM_RSA_PKCS_OAEP`, …}. `iv` carries IV for AES modes that need it
/// (`None` for RSA-OAEP).
pub fn encrypt(
    _session: u32,
    _key_handle: u32,
    _mechanism: u32,
    _plaintext: &[u8],
    _iv: Option<&[u8]>,
) -> Result<Vec<u8>, CkRv> {
    unimplemented!("native::encrypt::encrypt — Phase 7b commit 5")
}

/// Classical decrypt.
pub fn decrypt(
    _session: u32,
    _key_handle: u32,
    _mechanism: u32,
    _ciphertext: &[u8],
    _iv: Option<&[u8]>,
) -> Result<Vec<u8>, CkRv> {
    unimplemented!("native::encrypt::decrypt — Phase 7b commit 5")
}

/// ML-KEM encapsulation. Returns `(ciphertext, shared_secret)`.
/// `public_key_handle` MUST refer to an ML-KEM public-key object.
/// `mechanism` is `CKM_ML_KEM` (or a vendor variant).
pub fn encapsulate(
    _session: u32,
    _public_key_handle: u32,
    _mechanism: u32,
) -> Result<(Vec<u8>, Vec<u8>), CkRv> {
    unimplemented!("native::encrypt::encapsulate — Phase 7b commit 5")
}

/// ML-KEM decapsulation. Returns the recovered shared secret.
/// `ciphertext` is the encapsulation produced by `encapsulate`.
pub fn decapsulate(
    _session: u32,
    _private_key_handle: u32,
    _mechanism: u32,
    _ciphertext: &[u8],
) -> Result<Vec<u8>, CkRv> {
    unimplemented!("native::encrypt::decapsulate — Phase 7b commit 5")
}
