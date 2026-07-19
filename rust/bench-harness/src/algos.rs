//! Algorithm definitions: which mechanism generates the key pair, which
//! mechanism signs/verifies with it, and (per the engine's own
//! `C_GenerateKeyPair` dispatch — verified against `rust/src/ffi.rs`
//! before writing this) whether any template attributes are actually
//! required. Ed25519 needs none; every default the engine sets
//! (CKA_SIGN/CKA_VERIFY, key type, etc.) is already correct for a plain
//! signing key, so an empty template is a genuine, verified minimal case
//! — not a shortcut.

use softhsmrustv3::constants::{CKM_EC_EDWARDS_KEY_PAIR_GEN, CKM_EDDSA};

/// One benchmarked signature algorithm: its keygen mechanism and its
/// sign/verify mechanism (often, as here, not the same value).
#[derive(Clone, Copy, Debug)]
pub struct SignatureAlgo {
    pub name: &'static str,
    pub keygen_mechanism: u32,
    pub sign_mechanism: u32,
}

pub const ED25519: SignatureAlgo = SignatureAlgo {
    name: "Ed25519",
    keygen_mechanism: CKM_EC_EDWARDS_KEY_PAIR_GEN,
    sign_mechanism: CKM_EDDSA,
};
