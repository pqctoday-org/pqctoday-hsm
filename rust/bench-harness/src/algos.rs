//! Algorithm definitions: which mechanism generates the key pair, which
//! mechanism signs/verifies/derives/encapsulates with it, and (per the
//! engine's own dispatch in `rust/src/ffi.rs` — verified against source
//! before writing each of these, never guessed) which template
//! attributes are actually required. Every mechanism value here is a
//! real, OASIS-assigned PKCS#11 v3.2 codepoint (cross-checked against
//! `rust/src/constants.rs`, which itself is checked against the spec's
//! `pkcs11t.h` per this repo's CLAUDE.md) — no vendor extensions.

use softhsmrustv3::constants::{
    CKA_PARAMETER_SET, CKM_EC_EDWARDS_KEY_PAIR_GEN, CKM_EC_MONTGOMERY_KEY_PAIR_GEN, CKM_EDDSA,
    CKM_ML_KEM, CKM_ML_KEM_KEY_PAIR_GEN, CKP_ML_KEM_768,
};

/// One benchmarked signature algorithm: its keygen mechanism and its
/// sign/verify mechanism (often, as here, not the same value). Ed25519
/// needs no template attributes — every default the engine sets
/// (CKA_SIGN/CKA_VERIFY, key type, etc.) is already correct for a plain
/// signing key, so an empty template is a genuine, verified minimal
/// case, not a shortcut.
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

/// One benchmarked key-agreement algorithm. `CKM_EC_MONTGOMERY_KEY_PAIR_GEN`
/// with an empty template defaults to X25519 (§6.7 — the OID in
/// CKA_EC_PARAMS only selects X448; absent, X25519 is the default,
/// verified against `ffi.rs`'s `is_x448` check). Deriving is always
/// `CKM_ECDH1_DERIVE` (§6.7/§5.18.5) — the SAME generic derive mechanism
/// used for Weierstrass-curve ECDH; the engine dispatches to the X25519
/// math internally based on the base key's own stored algorithm family,
/// so no separate "X25519 derive" mechanism exists or is needed. That
/// mechanism is hardcoded inside `pkcs11::Engine::ecdh1_derive` rather
/// than carried as a field here, since no other value is valid for it.
#[derive(Clone, Copy, Debug)]
pub struct KeyAgreementAlgo {
    pub name: &'static str,
    pub keygen_mechanism: u32,
}

pub const X25519: KeyAgreementAlgo = KeyAgreementAlgo {
    name: "X25519",
    keygen_mechanism: CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
};

/// One benchmarked KEM. `CKA_PARAMETER_SET` (§6.68.2, value `0x61d`) is a
/// REQUIRED public-key-template attribute for `CKM_ML_KEM_KEY_PAIR_GEN`
/// (confirmed against `ffi.rs`: absent → `CKR_TEMPLATE_INCOMPLETE`) —
/// unlike Ed25519/X25519 this category cannot use an empty template.
#[derive(Clone, Copy, Debug)]
pub struct KemAlgo {
    pub name: &'static str,
    pub keygen_mechanism: u32,
    pub kem_mechanism: u32,
    pub parameter_set: u32,
}

pub const ML_KEM_768: KemAlgo = KemAlgo {
    name: "ML-KEM-768",
    keygen_mechanism: CKM_ML_KEM_KEY_PAIR_GEN,
    kem_mechanism: CKM_ML_KEM,
    parameter_set: CKP_ML_KEM_768,
};

/// `CKA_PARAMETER_SET`'s attribute type constant, re-exported so `main.rs`
/// can build the one-attribute keygen template without a second import
/// path into `softhsmrustv3::constants`.
pub const PARAMETER_SET_ATTR: u32 = CKA_PARAMETER_SET;
