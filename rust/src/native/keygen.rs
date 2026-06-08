//! Key generation — typed wrappers extracted from `ffi::C_GenerateKeyPair`
//! and `ffi::C_GenerateKey`.
//!
//! Each function takes typed args (parameter set as `u32`, `CKA_ID` /
//! label as `&[u8]` / `&str`), constructs the engine-internal
//! `Attributes` map directly via `state::*`, calls the existing typed
//! crypto primitives (e.g. `ml_kem::MlKem768::generate`), and returns
//! handle(s). No CK_ATTRIBUTE template marshalling.
//!
//! See [`super`] for the typed-vs-FFI architectural relationship.
//! Implementation lands in Phase 7b commit 3 (PQC) + commit 6 (classical).

use super::CkRv;

// ── PQC ─────────────────────────────────────────────────────────────────────

/// Generate an ML-KEM keypair. `parameter_set` ∈ {`CKP_ML_KEM_512`,
/// `CKP_ML_KEM_768`, `CKP_ML_KEM_1024`} (constants in
/// `softhsmrustv3::constants`). Returns `(public_handle, private_handle)`.
pub fn generate_ml_kem_keypair(
    _session: u32,
    _parameter_set: u32,
    _cka_id: &[u8],
    _label: &str,
) -> Result<(u32, u32), CkRv> {
    unimplemented!("native::keygen::generate_ml_kem_keypair — Phase 7b commit 3")
}

/// Generate an ML-DSA keypair. `parameter_set` ∈ {`CKP_ML_DSA_44`,
/// `CKP_ML_DSA_65`, `CKP_ML_DSA_87`}.
pub fn generate_ml_dsa_keypair(
    _session: u32,
    _parameter_set: u32,
    _cka_id: &[u8],
    _label: &str,
) -> Result<(u32, u32), CkRv> {
    unimplemented!("native::keygen::generate_ml_dsa_keypair — Phase 7b commit 3")
}

/// Generate an SLH-DSA keypair. `parameter_set` ∈ {`CKP_SLH_DSA_SHA2_128S`,
/// …, `CKP_SLH_DSA_SHAKE_256F`} — 12 variants total.
pub fn generate_slh_dsa_keypair(
    _session: u32,
    _parameter_set: u32,
    _cka_id: &[u8],
    _label: &str,
) -> Result<(u32, u32), CkRv> {
    unimplemented!("native::keygen::generate_slh_dsa_keypair — Phase 7b commit 3")
}

// ── Classical ───────────────────────────────────────────────────────────────

/// Generate an RSA keypair. `bits` ∈ {2048, 3072, 4096}.
pub fn generate_rsa_keypair(
    _session: u32,
    _bits: u32,
    _cka_id: &[u8],
    _label: &str,
) -> Result<(u32, u32), CkRv> {
    unimplemented!("native::keygen::generate_rsa_keypair — Phase 7b commit 6")
}

/// Generate an ECDSA keypair. `curve_oid` is the DER-encoded
/// `CKA_EC_PARAMS` OID (e.g. P-256 = `06 08 2a 86 48 ce 3d 03 01 07`).
pub fn generate_ecdsa_keypair(
    _session: u32,
    _curve_oid: &[u8],
    _cka_id: &[u8],
    _label: &str,
) -> Result<(u32, u32), CkRv> {
    unimplemented!("native::keygen::generate_ecdsa_keypair — Phase 7b commit 6")
}

/// Generate an AES key. `bits` ∈ {128, 192, 256}. Returns a single
/// secret-key handle (not a keypair).
pub fn generate_aes_key(
    _session: u32,
    _bits: u32,
    _cka_id: &[u8],
    _label: &str,
) -> Result<u32, CkRv> {
    unimplemented!("native::keygen::generate_aes_key — Phase 7b commit 6")
}

/// Generate a Generic-Secret key (for HMAC). `bits` ∈ {128, 256, 384, 512}.
pub fn generate_generic_secret(
    _session: u32,
    _bits: u32,
    _cka_id: &[u8],
    _label: &str,
) -> Result<u32, CkRv> {
    unimplemented!("native::keygen::generate_generic_secret — Phase 7b commit 6")
}
