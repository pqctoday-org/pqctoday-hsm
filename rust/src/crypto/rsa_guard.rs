//! Counts private-key operations performed by the pure-Rust `rsa` crate.
//!
//! On native builds every RSA private-key operation runs in AWS-LC
//! (`crypto::awslc`, `crypto::awslc_rsa`; RUSTSEC-2023-0071, owner decision
//! 2026-10-03), so this counter must stay at zero there — the test
//! `native_rsa_private_ops_never_reach_the_rsa_crate` drives every RSA
//! private-key mechanism and asserts exactly that. On wasm32 the `rsa` crate
//! is the implementation (always blinded) and the counter just counts.

use std::sync::atomic::{AtomicU64, Ordering};

static PURE_RSA_PRIVATE_OPS: AtomicU64 = AtomicU64::new(0);

/// Call immediately before any `rsa`-crate private-key operation.
#[inline]
pub fn note_pure_rsa_private_op() {
    PURE_RSA_PRIVATE_OPS.fetch_add(1, Ordering::Relaxed);
}

pub fn pure_rsa_private_ops() -> u64 {
    PURE_RSA_PRIVATE_OPS.load(Ordering::Relaxed)
}

/// Result of a residual RSA private decrypt: `Err(Some(rv))` is a policy
/// refusal the caller must return as-is (`CKR_KEY_SIZE_RANGE` on native);
/// `Err(None)` is a decryption failure the caller maps to its own uniform
/// code (no padding-oracle distinction).
pub type Residual = Result<Vec<u8>, Option<u32>>;

#[cfg(not(target_arch = "wasm32"))]
fn native(r: Result<Vec<u8>, u32>) -> Residual {
    r.map_err(|rv| (rv == crate::constants::CKR_KEY_SIZE_RANGE).then_some(rv))
}

/// RSA-OAEP decrypt that aws-lc-rs declined (a hash ≠ MGF1 hash, a PKCS#1
/// key, a size outside its loader). Native: raw AWS-LC. wasm32: `pure`.
pub fn decrypt_oaep_residual(
    der: &[u8],
    hash_alg: u32,
    mgf: u32,
    label: &[u8],
    ct: &[u8],
    pure: impl FnOnce() -> Result<Vec<u8>, rsa::Error>,
) -> Residual {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = pure;
        native(crate::crypto::awslc_rsa::decrypt_oaep_ck(der, hash_alg, mgf, label, ct))
    }
    #[cfg(target_arch = "wasm32")]
    {
        let _ = (der, hash_alg, mgf, label, ct);
        note_pure_rsa_private_op();
        pure().map_err(|_| None)
    }
}

/// RSAES-PKCS1-v1_5 decrypt that aws-lc-rs declined. Native: raw AWS-LC.
/// wasm32: `pure`.
pub fn decrypt_pkcs1_residual(der: &[u8], ct: &[u8], pure: impl FnOnce() -> Result<Vec<u8>, rsa::Error>) -> Residual {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = pure;
        native(crate::crypto::awslc_rsa::decrypt_pkcs1(der, ct))
    }
    #[cfg(target_arch = "wasm32")]
    {
        let _ = (der, ct);
        note_pure_rsa_private_op();
        pure().map_err(|_| None)
    }
}
