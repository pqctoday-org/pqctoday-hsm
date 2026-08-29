//! Encryption at rest for the token store (native builds only).
//!
//! Shape mirrors the C++ engine's `SecureDataManager`
//! (`src/lib/data_mgr/SecureDataManager.cpp`): one random 256-bit AES
//! master key per token, wrapped independently under an SO-PIN-derived key
//! and a User-PIN-derived key, so either login path unlocks the SAME master
//! key (not two different keys). Primitives are modernized rather than
//! copied: PBKDF2-HMAC-SHA256 at a much higher, fixed iteration count for
//! the wrap-key derivation (this crate already depends on `pbkdf2`/`sha2`
//! for `state::hash_pin`, which uses 10k iterations for LOGIN verification —
//! a different job from wrapping long-lived key material, so this module
//! uses its own count), and AES-256-GCM (already a dependency) instead of
//! C++'s CBC-without-authentication — a deliberate improvement: a wrong PIN
//! or corrupted blob fails the GCM tag check instead of silently decrypting
//! to garbage.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

/// OWASP's current PBKDF2-HMAC-SHA256 recommendation. This protects a
/// wrapped 256-bit master key (long-lived, unlocks every persisted secret
/// on the token) rather than gating a single login attempt, so it uses a
/// much higher count than `state::hash_pin`'s 10k.
const WRAP_KDF_ITERATIONS: u32 = 210_000;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
pub const MASTER_KEY_LEN: usize = 32;

#[derive(Debug, PartialEq, Eq)]
pub struct CryptoError;

fn derive_wrap_key(pin: &[u8], salt: &[u8; SALT_LEN]) -> [u8; MASTER_KEY_LEN] {
    let mut key = [0u8; MASTER_KEY_LEN];
    pbkdf2_hmac::<Sha256>(pin, salt, WRAP_KDF_ITERATIONS, &mut key);
    key
}

fn random_bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).map_err(|_| CryptoError)?;
    Ok(buf)
}

/// `salt(16) ‖ nonce(12) ‖ ciphertext(32) ‖ tag(16)` = 76 bytes, always.
pub fn wrap_master_key(pin: &[u8], master_key: &[u8; MASTER_KEY_LEN]) -> Result<Vec<u8>, CryptoError> {
    let salt: [u8; SALT_LEN] = random_bytes()?;
    let nonce_bytes: [u8; NONCE_LEN] = random_bytes()?;
    let wrap_key = derive_wrap_key(pin, &salt);
    let cipher = Aes256Gcm::new_from_slice(&wrap_key).map_err(|_| CryptoError)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: master_key, aad: b"" })
        .map_err(|_| CryptoError)?;
    let mut out = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Inverse of [`wrap_master_key`]. A wrong PIN or corrupted blob fails the
/// AES-GCM tag check and returns `Err` — there is no separate "is this PIN
/// right" probe, the authenticated decryption IS the check.
pub fn unwrap_master_key(pin: &[u8], wrapped: &[u8]) -> Result<[u8; MASTER_KEY_LEN], CryptoError> {
    if wrapped.len() < SALT_LEN + NONCE_LEN + TAG_LEN {
        return Err(CryptoError);
    }
    let salt: [u8; SALT_LEN] = wrapped[..SALT_LEN].try_into().unwrap();
    let nonce_bytes = &wrapped[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ciphertext = &wrapped[SALT_LEN + NONCE_LEN..];
    let wrap_key = derive_wrap_key(pin, &salt);
    let cipher = Aes256Gcm::new_from_slice(&wrap_key).map_err(|_| CryptoError)?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad: b"" })
        .map_err(|_| CryptoError)?;
    plaintext.try_into().map_err(|_| CryptoError)
}

pub fn generate_master_key() -> Result<[u8; MASTER_KEY_LEN], CryptoError> {
    random_bytes()
}

/// `nonce(12) ‖ ciphertext ‖ tag(16)`. Used for every attribute value on an
/// object with `CKA_PRIVATE == TRUE` — unlike C++'s curated per-attribute
/// list (`DBObject::attributeKind`), this engine encrypts the WHOLE
/// attribute set of a private object wholesale. Simpler, and strictly safer
/// than a maintained allow-list that can silently miss a newly added
/// attribute (see the C++/Rust persistence parity report, gap G5).
pub fn encrypt_attr(master_key: &[u8; MASTER_KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let nonce_bytes: [u8; NONCE_LEN] = random_bytes()?;
    let cipher = Aes256Gcm::new_from_slice(master_key).map_err(|_| CryptoError)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad: b"" })
        .map_err(|_| CryptoError)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn decrypt_attr(master_key: &[u8; MASTER_KEY_LEN], blob: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if blob.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError);
    }
    let nonce_bytes = &blob[..NONCE_LEN];
    let ciphertext = &blob[NONCE_LEN..];
    let cipher = Aes256Gcm::new_from_slice(master_key).map_err(|_| CryptoError)?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad: b"" })
        .map_err(|_| CryptoError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_key_round_trips_with_right_pin() {
        let mk = generate_master_key().unwrap();
        let wrapped = wrap_master_key(b"1234", &mk).unwrap();
        let unwrapped = unwrap_master_key(b"1234", &wrapped).unwrap();
        assert_eq!(mk, unwrapped);
    }

    #[test]
    fn wrong_pin_is_rejected_via_aead_tag() {
        let mk = generate_master_key().unwrap();
        let wrapped = wrap_master_key(b"1234", &mk).unwrap();
        assert_eq!(unwrap_master_key(b"0000", &wrapped), Err(CryptoError));
    }

    #[test]
    fn corrupted_blob_is_rejected() {
        let mk = generate_master_key().unwrap();
        let mut wrapped = wrap_master_key(b"1234", &mk).unwrap();
        let last = wrapped.len() - 1;
        wrapped[last] ^= 0xff;
        assert_eq!(unwrap_master_key(b"1234", &wrapped), Err(CryptoError));
    }

    #[test]
    fn attr_round_trips() {
        let mk = generate_master_key().unwrap();
        let pt = b"a very secret private key value";
        let ct = encrypt_attr(&mk, pt).unwrap();
        assert_ne!(ct, pt);
        assert_eq!(decrypt_attr(&mk, &ct).unwrap(), pt);
    }

    #[test]
    fn two_wraps_of_same_key_differ_but_both_open() {
        // Independent SO/User wraps of the SAME master key must not be
        // distinguishable-by-ciphertext and must both open to it.
        let mk = generate_master_key().unwrap();
        let so_wrapped = wrap_master_key(b"so-pin", &mk).unwrap();
        let user_wrapped = wrap_master_key(b"user-pin", &mk).unwrap();
        assert_ne!(so_wrapped, user_wrapped);
        assert_eq!(unwrap_master_key(b"so-pin", &so_wrapped).unwrap(), mk);
        assert_eq!(unwrap_master_key(b"user-pin", &user_wrapped).unwrap(), mk);
    }
}
