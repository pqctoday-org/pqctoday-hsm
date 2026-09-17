//! Hash function implementation (SHAKE256). Byte-identical across all 10 parameter
//! sets (zero parameter dependency) — copied verbatim from upstream
//! `classic-mceliece-rust` 3.1.0 `src/crypto_hash.rs`, shared via one module instead
//! of duplicated per variant.

use sha3::digest::ExtendableOutput;
use sha3::Shake256;

/// Utilizes the SHAKE256 hash function. Input and output is of arbitrary length.
#[inline]
pub(crate) fn shake256(output: &mut [u8], input: &[u8]) {
    Shake256::digest_xof(input, output);
}
