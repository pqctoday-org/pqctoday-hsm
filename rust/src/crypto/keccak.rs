// SPDX-License-Identifier: BSD-2-Clause
//
// G11 — Keccak-256 digest (vendor CKM_KECCAK_256 = 0x80000010)
//
// Used for Ethereum address derivation: keccak256(pubkey_bytes[1..65]) → last 20 bytes.
//
// This is NOT SHA3-256. Ethereum uses the original Keccak submission (pre-NIST padding),
// which differs from the FIPS 202 SHA3-256 finalization padding (0x06 vs 0x01).
//
// The C++ engine returns CKR_MECHANISM_INVALID for CKM_KECCAK_256. Only the Rust engine
// implements this mechanism.

use tiny_keccak::{Hasher, Keccak};

/// Compute Keccak-256 over the given data and return 32-byte digest.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    output
}

/// Incremental Keccak-256 state for multi-part digest operations.
/// Stored in DigestCtx::Keccak256(Vec<u8>) — we buffer all input then hash at finalize.
/// Keccak::v256 is not Clone, so we collect bytes and hash once at C_DigestFinal.
pub fn keccak256_update(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(data);
}

pub fn keccak256_finalize(buf: &[u8]) -> [u8; 32] {
    keccak256(buf)
}
