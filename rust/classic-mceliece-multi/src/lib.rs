//! `classic-mceliece-multi` — a fork of `classic-mceliece-rust` 3.1.0
//! (<https://github.com/Colfenor/classic-mceliece-rust>, upstream commit
//! `6e5ce0cbba807e5288b677cee07224a8e30a0876`) that compiles **all 10** Classic
//! McEliece parameter sets into one build, instead of exactly one selected by a
//! Cargo feature. See `README.md` for the fork rationale and
//! `docs/implementation-plan-classic-mceliece-all-parameter-sets-2026-09-08.md`
//! (in the parent `pqctoday-hsm` repo) for the full design record.
//!
//! Buffer types (`PublicKey`, `SecretKey`, `Ciphertext`, `SharedSecret`) are generic
//! over a bare `const N: usize` — proven on stable Rust by this fork's P0-1 spike
//! (`rust/spike-mceliece-multi/`, deleted once this crate landed): a trait
//! associated const reached through a still-generic type parameter cannot size an
//! array on stable Rust, but a bare const-generic parameter can. Each parameter
//! set's module (`mceliece348864`, `mceliece348864f`, …, `mceliece8192128f`)
//! supplies its own sizes as concrete literals at its type-alias call sites.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
use alloc::boxed::Box;
use core::fmt::Debug;

mod shared;
#[cfg(test)]
mod test_support;

pub mod mceliece348864;
pub mod mceliece348864f;
pub mod mceliece460896;
pub mod mceliece460896f;
pub mod mceliece6688128;
pub mod mceliece6688128f;
pub mod mceliece6960119;
pub mod mceliece6960119f;
pub mod mceliece8192128;
pub mod mceliece8192128f;

/// A Classic McEliece public key. `N` is `CRYPTO_PUBLICKEYBYTES` for the parameter
/// set (261,120 … 1,357,824 bytes — these are large compared to keys in most other
/// cryptographic algorithms).
#[must_use]
pub struct PublicKey<const N: usize>(Box<[u8; N]>);

impl<const N: usize> PublicKey<N> {
    pub fn as_array(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> AsRef<[u8]> for PublicKey<N> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<const N: usize> From<Box<[u8; N]>> for PublicKey<N> {
    fn from(data: Box<[u8; N]>) -> Self {
        Self(data)
    }
}

impl<const N: usize> zeroize::Zeroize for PublicKey<N> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<const N: usize> Debug for PublicKey<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("PublicKey").field(&N).finish()
    }
}

/// A Classic McEliece secret key. Should be kept on the device where it's
/// generated. `N` is `CRYPTO_SECRETKEYBYTES` for the parameter set.
#[must_use]
pub struct SecretKey<const N: usize>(Box<[u8; N]>);

impl<const N: usize> SecretKey<N> {
    /// Returns the secret key as an array of bytes. Depending on your threat model,
    /// moving the data out of `SecretKey` can be bad for security — the type is
    /// designed to keep the backing data in a single location in memory and zero it
    /// on drop.
    pub fn as_array(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> AsRef<[u8]> for SecretKey<N> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<const N: usize> From<Box<[u8; N]>> for SecretKey<N> {
    fn from(data: Box<[u8; N]>) -> Self {
        Self(data)
    }
}

impl<const N: usize> zeroize::Zeroize for SecretKey<N> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<const N: usize> zeroize::ZeroizeOnDrop for SecretKey<N> {}

impl<const N: usize> Drop for SecretKey<N> {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.zeroize();
    }
}

impl<const N: usize> Debug for SecretKey<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("SecretKey").field(&"-- redacted --").finish()
    }
}

/// The ciphertext computed by the encapsulator. `N` is `CRYPTO_CIPHERTEXTBYTES`
/// (96, 156, 194, or 208 depending on the parameter set).
#[derive(Debug)]
#[must_use]
pub struct Ciphertext<const N: usize>([u8; N]);

impl<const N: usize> Ciphertext<N> {
    pub fn as_array(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> AsRef<[u8]> for Ciphertext<N> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<const N: usize> From<[u8; N]> for Ciphertext<N> {
    fn from(data: [u8; N]) -> Self {
        Self(data)
    }
}

/// The 32-byte shared secret computed by the KEM. Returned from both the
/// encapsulator and decapsulator. Uniform length (32 bytes) across every parameter
/// set, so this type is not const-generic.
#[must_use]
pub struct SharedSecret(Box<[u8; 32]>);

impl SharedSecret {
    pub fn as_array(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<Box<[u8; 32]>> for SharedSecret {
    fn from(data: Box<[u8; 32]>) -> Self {
        Self(data)
    }
}

impl zeroize::Zeroize for SharedSecret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl zeroize::ZeroizeOnDrop for SharedSecret {}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.zeroize();
    }
}

impl Debug for SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("SharedSecret")
            .field(&"-- redacted --")
            .finish()
    }
}

/// A runtime-selectable parameter set, keyed the same way the engine's
/// `CKP_CLASSIC_MCELIECE_*` PKCS#11 attribute values are (see the implementation
/// plan §3.1) — `from_ckp`/`to_ckp` round-trip those exact values so the engine
/// FFI layer (`rust/src/native/keygen.rs`, `encrypt.rs`) never has to hardcode a
/// second copy of this mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParameterSet {
    Mceliece348864,
    Mceliece348864f,
    Mceliece460896,
    Mceliece460896f,
    Mceliece6688128,
    Mceliece6688128f,
    Mceliece6960119,
    Mceliece6960119f,
    Mceliece8192128,
    Mceliece8192128f,
}

impl ParameterSet {
    /// `(public_key_bytes, secret_key_bytes, ciphertext_bytes)` — shared_secret is
    /// always 32 and is not included.
    pub const fn sizes(self) -> (usize, usize, usize) {
        use ParameterSet::*;
        match self {
            Mceliece348864 => (
                mceliece348864::CRYPTO_PUBLICKEYBYTES,
                mceliece348864::CRYPTO_SECRETKEYBYTES,
                mceliece348864::CRYPTO_CIPHERTEXTBYTES,
            ),
            Mceliece348864f => (
                mceliece348864f::CRYPTO_PUBLICKEYBYTES,
                mceliece348864f::CRYPTO_SECRETKEYBYTES,
                mceliece348864f::CRYPTO_CIPHERTEXTBYTES,
            ),
            Mceliece460896 => (
                mceliece460896::CRYPTO_PUBLICKEYBYTES,
                mceliece460896::CRYPTO_SECRETKEYBYTES,
                mceliece460896::CRYPTO_CIPHERTEXTBYTES,
            ),
            Mceliece460896f => (
                mceliece460896f::CRYPTO_PUBLICKEYBYTES,
                mceliece460896f::CRYPTO_SECRETKEYBYTES,
                mceliece460896f::CRYPTO_CIPHERTEXTBYTES,
            ),
            Mceliece6688128 => (
                mceliece6688128::CRYPTO_PUBLICKEYBYTES,
                mceliece6688128::CRYPTO_SECRETKEYBYTES,
                mceliece6688128::CRYPTO_CIPHERTEXTBYTES,
            ),
            Mceliece6688128f => (
                mceliece6688128f::CRYPTO_PUBLICKEYBYTES,
                mceliece6688128f::CRYPTO_SECRETKEYBYTES,
                mceliece6688128f::CRYPTO_CIPHERTEXTBYTES,
            ),
            Mceliece6960119 => (
                mceliece6960119::CRYPTO_PUBLICKEYBYTES,
                mceliece6960119::CRYPTO_SECRETKEYBYTES,
                mceliece6960119::CRYPTO_CIPHERTEXTBYTES,
            ),
            Mceliece6960119f => (
                mceliece6960119f::CRYPTO_PUBLICKEYBYTES,
                mceliece6960119f::CRYPTO_SECRETKEYBYTES,
                mceliece6960119f::CRYPTO_CIPHERTEXTBYTES,
            ),
            Mceliece8192128 => (
                mceliece8192128::CRYPTO_PUBLICKEYBYTES,
                mceliece8192128::CRYPTO_SECRETKEYBYTES,
                mceliece8192128::CRYPTO_CIPHERTEXTBYTES,
            ),
            Mceliece8192128f => (
                mceliece8192128f::CRYPTO_PUBLICKEYBYTES,
                mceliece8192128f::CRYPTO_SECRETKEYBYTES,
                mceliece8192128f::CRYPTO_CIPHERTEXTBYTES,
            ),
        }
    }

    /// Name matching liboqs's own naming (`mceliece348864`, …) and this fork's own
    /// module names.
    pub const fn name(self) -> &'static str {
        use ParameterSet::*;
        match self {
            Mceliece348864 => "mceliece348864",
            Mceliece348864f => "mceliece348864f",
            Mceliece460896 => "mceliece460896",
            Mceliece460896f => "mceliece460896f",
            Mceliece6688128 => "mceliece6688128",
            Mceliece6688128f => "mceliece6688128f",
            Mceliece6960119 => "mceliece6960119",
            Mceliece6960119f => "mceliece6960119f",
            Mceliece8192128 => "mceliece8192128",
            Mceliece8192128f => "mceliece8192128f",
        }
    }
}

// Tests may use `std`
#[cfg(test)]
#[macro_use]
extern crate std;
