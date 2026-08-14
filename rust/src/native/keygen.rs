//! Key generation — typed wrappers around the engine's keygen logic.
//!
//! Each function takes typed args (parameter set as `u32`, `CKA_ID` /
//! label as `&[u8]` / `&str`), constructs the engine-internal
//! `Attributes` map directly via `state::*` helpers, calls the existing
//! typed crypto primitives (`fips204::*` / `fips205::*` / `ml_kem::*`),
//! and returns handle(s). No CK_ATTRIBUTE template marshalling.
//!
//! Implementation mirrors `ffi::C_GenerateKeyPair`'s per-mechanism arm:
//! same attribute defaults (`CKA_CLASS`, `CKA_KEY_TYPE`, etc.), same
//! crypto crate calls, same SPKI builder, same
//! `finalize_private_key_attrs` + `compute_kcv` finalisation. The
//! difference is **how the caller's CKA_ID + CKA_LABEL get in**: the C
//! ABI absorbs them via `absorb_template_attrs(template_ptr, count)`;
//! `native::*` accepts them as typed args and inserts them directly,
//! avoiding the wasm32-only attribute-template ABI.
//!
//! See [`super`] for the typed-vs-FFI architectural relationship.

use std::collections::HashMap;

use super::CkRv;
use crate::constants::*;
use crate::crypto::{
    ALGO_CLASSIC_MCELIECE, ALGO_ECDH_P256, ALGO_ECDH_X25519, ALGO_ECDH_X448, ALGO_ECDSA,
    ALGO_EDDSA, ALGO_FRODOKEM, ALGO_ML_DSA, ALGO_ML_KEM, ALGO_RSA, ALGO_SLH_DSA, CURVE_K256,
    CURVE_P256, CURVE_P384, CURVE_P521,
};
use crate::crypto::handlers::{
    build_ec_spki_p256, build_ec_spki_p384, build_ec_spki_p521, build_ed25519_spki,
    build_mldsa44_spki, build_mldsa65_spki, build_mldsa87_spki, build_mlkem1024_spki,
    build_mlkem512_spki, build_mlkem768_spki, build_slhdsa_spki, build_spki_from_parts,
    build_x25519_spki, build_x448_spki, Attributes,
};
use crate::state::{
    allocate_handle, compute_kcv, finalize_private_key_attrs, store_algo_family, store_bool,
    store_param_set, store_ulong,
};

/// `CKA_LABEL` — PKCS#11 v3.2 standard attribute (not in the engine's
/// `constants` module because the engine never reads it; it's
/// caller-supplied bookkeeping). Codepoint per pkcs11t.h.
pub const CKA_LABEL: u32 = 0x0000_0003;

/// `CKA_ID` — PKCS#11 v3.2 standard attribute. Codepoint per pkcs11t.h.
pub const CKA_ID: u32 = 0x0000_0102;

// ── ML-KEM ──────────────────────────────────────────────────────────────────

/// Generate an ML-KEM keypair. `parameter_set` ∈
/// {`CKP_ML_KEM_512`, `CKP_ML_KEM_768`, `CKP_ML_KEM_1024`}. Returns
/// `(public_handle, private_handle)`.
///
/// **Pre-condition**: `session` must be a valid R/W user session
/// (see [`super::session::open_session`]).
pub fn generate_ml_kem_keypair(
    _session: u32,
    parameter_set: u32,
    cka_id: &[u8],
    label: &str,
) -> Result<(u32, u32), CkRv> {
    ml_kem_keypair_impl(_session, parameter_set, None, cka_id, label, false)
}

/// T7 — deterministic ML-KEM keygen from a caller-supplied `CKA_SEED`
/// (`d ‖ z`, 64 bytes), per FIPS 203 Algorithm 16
/// `ML-KEM.KeyGen_internal(d, z)` (`ml-kem` crate `deterministic`
/// feature). The seed is stored on the private object under `CKA_SEED`
/// (sensitive-blocked readback set). Wrong seed length →
/// `CKR_ATTRIBUTE_VALUE_INVALID`.
pub fn generate_ml_kem_keypair_from_seed(
    _session: u32,
    parameter_set: u32,
    seed: &[u8],
    cka_id: &[u8],
    label: &str,
) -> Result<(u32, u32), CkRv> {
    ml_kem_keypair_impl(_session, parameter_set, Some(seed), cka_id, label, false)
}

/// Like [`generate_ml_kem_keypair_from_seed`] but the private key is born
/// extractable (see [`generate_ml_dsa_keypair_from_seed_extractable`]).
pub fn generate_ml_kem_keypair_from_seed_extractable(
    _session: u32,
    parameter_set: u32,
    seed: &[u8],
    cka_id: &[u8],
    label: &str,
) -> Result<(u32, u32), CkRv> {
    ml_kem_keypair_impl(_session, parameter_set, Some(seed), cka_id, label, true)
}

fn ml_kem_keypair_impl(
    _session: u32,
    parameter_set: u32,
    seed: Option<&[u8]>,
    cka_id: &[u8],
    label: &str,
    extractable: bool,
) -> Result<(u32, u32), CkRv> {
    use ml_kem::{EncodedSizeUser, KemCore};

    if let Some(s) = seed {
        // FIPS 203 §7.1 — seed material is d ‖ z, 32 bytes each.
        if s.len() != 64 {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID);
        }
    }

    let mut pub_attrs: Attributes = HashMap::new();
    let mut prv_attrs: Attributes = HashMap::new();

    // PKCS#11 v3.2 defaults — mirrors ffi::C_GenerateKeyPair @ ML-KEM arm.
    set_common_pub_attrs(&mut pub_attrs, parameter_set, ALGO_ML_KEM, CKK_ML_KEM, CKM_ML_KEM_KEY_PAIR_GEN);
    set_common_prv_attrs(&mut prv_attrs, parameter_set, ALGO_ML_KEM, CKK_ML_KEM, CKM_ML_KEM_KEY_PAIR_GEN);
    apply_extractable_override(&mut prv_attrs, extractable);
    // ML-KEM-specific flags: encapsulate / decapsulate, NOT sign / verify.
    store_bool(&mut pub_attrs, CKA_VERIFY, false);
    store_bool(&mut pub_attrs, CKA_ENCAPSULATE, true);
    store_bool(&mut prv_attrs, CKA_SIGN, false);
    store_bool(&mut prv_attrs, CKA_DECAPSULATE, true);

    // Caller bookkeeping.
    insert_id_and_label(&mut pub_attrs, cka_id, label);
    insert_id_and_label(&mut prv_attrs, cka_id, label);

    // Crypto keygen — deterministic from d ‖ z when a seed is supplied
    // (FIPS 203 Algorithm 16), OsRng otherwise.
    macro_rules! mlkem_gen {
        ($t:ty) => {{
            let (dk, ek) = match seed {
                Some(s) => {
                    let d = ml_kem::B32::try_from(&s[..32]).expect("length checked");
                    let z = ml_kem::B32::try_from(&s[32..64]).expect("length checked");
                    <$t>::generate_deterministic(&d, &z)
                }
                None => <$t>::generate(&mut rand::rngs::OsRng),
            };
            pub_attrs.insert(CKA_VALUE, ek.as_bytes().as_slice().to_vec());
            prv_attrs.insert(CKA_VALUE, dk.as_bytes().as_slice().to_vec());
        }};
    }
    match parameter_set {
        CKP_ML_KEM_512 => mlkem_gen!(ml_kem::MlKem512),
        CKP_ML_KEM_768 => mlkem_gen!(ml_kem::MlKem768),
        CKP_ML_KEM_1024 => mlkem_gen!(ml_kem::MlKem1024),
        // Table 6 — unrecognized CKA_PARAMETER_SET value in the template.
        _ => return Err(CKR_PARAMETER_SET_NOT_SUPPORTED),
    }
    // Engine-side seed storage — sensitive-blocked readback set
    // (state::attr_is_sensitive_material).
    if let Some(s) = seed {
        prv_attrs.insert(CKA_SEED, s.to_vec());
    }

    // SPKI — PKCS#11 v3.2 §4.14.
    if let Some(pk_bytes) = pub_attrs.get(&CKA_VALUE).cloned() {
        let spki = match parameter_set {
            CKP_ML_KEM_512 => build_mlkem512_spki(&pk_bytes),
            CKP_ML_KEM_768 => build_mlkem768_spki(&pk_bytes),
            CKP_ML_KEM_1024 => build_mlkem1024_spki(&pk_bytes),
            _ => Vec::new(),
        };
        if !spki.is_empty() {
            pub_attrs.insert(CKA_PUBLIC_KEY_INFO, spki);
        }
    }

    finalize_and_register(_session, pub_attrs, prv_attrs)
}

// ── ML-DSA ──────────────────────────────────────────────────────────────────

/// Generate an ML-DSA keypair. `parameter_set` ∈
/// {`CKP_ML_DSA_44`, `CKP_ML_DSA_65`, `CKP_ML_DSA_87`}.
pub fn generate_ml_dsa_keypair(
    _session: u32,
    parameter_set: u32,
    cka_id: &[u8],
    label: &str,
) -> Result<(u32, u32), CkRv> {
    ml_dsa_keypair_impl(_session, parameter_set, None, cka_id, label, false)
}

/// T7 — deterministic ML-DSA keygen from a caller-supplied `CKA_SEED`
/// (ξ, 32 bytes), per FIPS 204 Algorithm 6 `ML-DSA.KeyGen_internal(ξ)`
/// (patched fips204 `KeyGen::keygen_from_seed`). The seed is stored on
/// the private object under `CKA_SEED` (sensitive-blocked readback set).
/// Wrong seed length → `CKR_ATTRIBUTE_VALUE_INVALID`.
pub fn generate_ml_dsa_keypair_from_seed(
    _session: u32,
    parameter_set: u32,
    seed: &[u8],
    cka_id: &[u8],
    label: &str,
) -> Result<(u32, u32), CkRv> {
    ml_dsa_keypair_impl(_session, parameter_set, Some(seed), cka_id, label, false)
}

/// Like [`generate_ml_dsa_keypair_from_seed`] but the private key is born
/// `CKA_EXTRACTABLE=TRUE` / `CKA_SENSITIVE=FALSE` so its material can be
/// read back via `get_attribute(CKA_VALUE)`. For the KMIP 3.0 WD19 PQC
/// interop profile, where deterministic-from-seed keygen exists precisely
/// so the generated key can be Got and checked byte-for-byte.
pub fn generate_ml_dsa_keypair_from_seed_extractable(
    _session: u32,
    parameter_set: u32,
    seed: &[u8],
    cka_id: &[u8],
    label: &str,
) -> Result<(u32, u32), CkRv> {
    ml_dsa_keypair_impl(_session, parameter_set, Some(seed), cka_id, label, true)
}

fn ml_dsa_keypair_impl(
    _session: u32,
    parameter_set: u32,
    seed: Option<&[u8]>,
    cka_id: &[u8],
    label: &str,
    extractable: bool,
) -> Result<(u32, u32), CkRv> {
    if let Some(s) = seed {
        // FIPS 204 §3.6.1 — ξ is exactly 32 bytes.
        if s.len() != 32 {
            return Err(CKR_ATTRIBUTE_VALUE_INVALID);
        }
    }

    let mut pub_attrs: Attributes = HashMap::new();
    let mut prv_attrs: Attributes = HashMap::new();

    set_common_pub_attrs(&mut pub_attrs, parameter_set, ALGO_ML_DSA, CKK_ML_DSA, CKM_ML_DSA_KEY_PAIR_GEN);
    set_common_prv_attrs(&mut prv_attrs, parameter_set, ALGO_ML_DSA, CKK_ML_DSA, CKM_ML_DSA_KEY_PAIR_GEN);
    apply_extractable_override(&mut prv_attrs, extractable);
    // ML-DSA: sign / verify, NOT encapsulate / decapsulate.
    store_bool(&mut pub_attrs, CKA_VERIFY, true);
    store_bool(&mut pub_attrs, CKA_ENCAPSULATE, false);
    store_bool(&mut prv_attrs, CKA_SIGN, true);
    store_bool(&mut prv_attrs, CKA_DECAPSULATE, false);

    insert_id_and_label(&mut pub_attrs, cka_id, label);
    insert_id_and_label(&mut prv_attrs, cka_id, label);

    // Crypto keygen — deterministic from ξ when a seed is supplied
    // (FIPS 204 Algorithm 6), OsRng otherwise.
    macro_rules! mldsa_gen {
        ($m:ident) => {{
            use fips204::traits::{KeyGen, SerDes};
            match seed {
                Some(s) => {
                    let xi: &[u8; 32] = s.try_into().expect("length checked");
                    let (vk, sk) = fips204::$m::KG::keygen_from_seed(xi);
                    pub_attrs.insert(CKA_VALUE, SerDes::into_bytes(vk).to_vec());
                    prv_attrs.insert(CKA_VALUE, SerDes::into_bytes(sk).to_vec());
                }
                None => match fips204::$m::try_keygen_with_rng(&mut rand::rngs::OsRng) {
                    Ok((vk, sk)) => {
                        pub_attrs.insert(CKA_VALUE, SerDes::into_bytes(vk).to_vec());
                        prv_attrs.insert(CKA_VALUE, SerDes::into_bytes(sk).to_vec());
                    }
                    Err(_) => return Err(CKR_FUNCTION_FAILED),
                },
            }
        }};
    }
    match parameter_set {
        CKP_ML_DSA_44 => mldsa_gen!(ml_dsa_44),
        CKP_ML_DSA_65 => mldsa_gen!(ml_dsa_65),
        CKP_ML_DSA_87 => mldsa_gen!(ml_dsa_87),
        // Table 6 — unrecognized CKA_PARAMETER_SET value in the template.
        _ => return Err(CKR_PARAMETER_SET_NOT_SUPPORTED),
    }
    // Engine-side seed storage — sensitive-blocked readback set
    // (state::attr_is_sensitive_material).
    if let Some(s) = seed {
        prv_attrs.insert(CKA_SEED, s.to_vec());
    }

    if let Some(pk_bytes) = pub_attrs.get(&CKA_VALUE).cloned() {
        let spki = match parameter_set {
            CKP_ML_DSA_44 => build_mldsa44_spki(&pk_bytes),
            CKP_ML_DSA_65 => build_mldsa65_spki(&pk_bytes),
            CKP_ML_DSA_87 => build_mldsa87_spki(&pk_bytes),
            _ => Vec::new(),
        };
        if !spki.is_empty() {
            pub_attrs.insert(CKA_PUBLIC_KEY_INFO, spki);
        }
    }

    finalize_and_register(_session, pub_attrs, prv_attrs)
}

// ── SLH-DSA ─────────────────────────────────────────────────────────────────

/// Generate an SLH-DSA keypair. `parameter_set` ∈
/// {`CKP_SLH_DSA_SHA2_128S`, …, `CKP_SLH_DSA_SHAKE_256F`} — 12 variants.
pub fn generate_slh_dsa_keypair(
    _session: u32,
    parameter_set: u32,
    cka_id: &[u8],
    label: &str,
) -> Result<(u32, u32), CkRv> {
    slh_dsa_keypair_impl(_session, parameter_set, None, cka_id, label, false)
}

/// T7 — deterministic SLH-DSA keygen from a caller-supplied `CKA_SEED`
/// (`SK.seed ‖ SK.prf ‖ PK.seed`, 3n bytes; n = 16/24/32 per param set),
/// per FIPS 205 Algorithm 18 `slh_keygen_internal` (fips205
/// `KeyGen::keygen_with_seeds`). The seed is stored on the private object
/// under `CKA_SEED` (sensitive-blocked readback set). Wrong seed length →
/// `CKR_ATTRIBUTE_VALUE_INVALID`.
pub fn generate_slh_dsa_keypair_from_seed(
    _session: u32,
    parameter_set: u32,
    seed: &[u8],
    cka_id: &[u8],
    label: &str,
) -> Result<(u32, u32), CkRv> {
    slh_dsa_keypair_impl(_session, parameter_set, Some(seed), cka_id, label, false)
}

/// Like [`generate_slh_dsa_keypair_from_seed`] but the private key is born
/// extractable (see [`generate_ml_dsa_keypair_from_seed_extractable`]).
pub fn generate_slh_dsa_keypair_from_seed_extractable(
    _session: u32,
    parameter_set: u32,
    seed: &[u8],
    cka_id: &[u8],
    label: &str,
) -> Result<(u32, u32), CkRv> {
    slh_dsa_keypair_impl(_session, parameter_set, Some(seed), cka_id, label, true)
}

fn slh_dsa_keypair_impl(
    _session: u32,
    parameter_set: u32,
    seed: Option<&[u8]>,
    cka_id: &[u8],
    label: &str,
    extractable: bool,
) -> Result<(u32, u32), CkRv> {
    let mut pub_attrs: Attributes = HashMap::new();
    let mut prv_attrs: Attributes = HashMap::new();

    set_common_pub_attrs(&mut pub_attrs, parameter_set, ALGO_SLH_DSA, CKK_SLH_DSA, CKM_SLH_DSA_KEY_PAIR_GEN);
    set_common_prv_attrs(&mut prv_attrs, parameter_set, ALGO_SLH_DSA, CKK_SLH_DSA, CKM_SLH_DSA_KEY_PAIR_GEN);
    apply_extractable_override(&mut prv_attrs, extractable);
    store_bool(&mut pub_attrs, CKA_VERIFY, true);
    store_bool(&mut pub_attrs, CKA_ENCAPSULATE, false);
    store_bool(&mut prv_attrs, CKA_SIGN, true);
    store_bool(&mut prv_attrs, CKA_DECAPSULATE, false);

    insert_id_and_label(&mut pub_attrs, cka_id, label);
    insert_id_and_label(&mut prv_attrs, cka_id, label);

    match parameter_set {
        CKP_SLH_DSA_SHA2_128S => slh_keygen!(slh_dsa_sha2_128s, seed, pub_attrs, prv_attrs),
        CKP_SLH_DSA_SHAKE_128S => slh_keygen!(slh_dsa_shake_128s, seed, pub_attrs, prv_attrs),
        CKP_SLH_DSA_SHA2_128F => slh_keygen!(slh_dsa_sha2_128f, seed, pub_attrs, prv_attrs),
        CKP_SLH_DSA_SHAKE_128F => slh_keygen!(slh_dsa_shake_128f, seed, pub_attrs, prv_attrs),
        CKP_SLH_DSA_SHA2_192S => slh_keygen!(slh_dsa_sha2_192s, seed, pub_attrs, prv_attrs),
        CKP_SLH_DSA_SHAKE_192S => slh_keygen!(slh_dsa_shake_192s, seed, pub_attrs, prv_attrs),
        CKP_SLH_DSA_SHA2_192F => slh_keygen!(slh_dsa_sha2_192f, seed, pub_attrs, prv_attrs),
        CKP_SLH_DSA_SHAKE_192F => slh_keygen!(slh_dsa_shake_192f, seed, pub_attrs, prv_attrs),
        CKP_SLH_DSA_SHA2_256S => slh_keygen!(slh_dsa_sha2_256s, seed, pub_attrs, prv_attrs),
        CKP_SLH_DSA_SHAKE_256S => slh_keygen!(slh_dsa_shake_256s, seed, pub_attrs, prv_attrs),
        CKP_SLH_DSA_SHA2_256F => slh_keygen!(slh_dsa_sha2_256f, seed, pub_attrs, prv_attrs),
        CKP_SLH_DSA_SHAKE_256F => slh_keygen!(slh_dsa_shake_256f, seed, pub_attrs, prv_attrs),
        // Table 6 — unrecognized CKA_PARAMETER_SET value in the template.
        _ => return Err(CKR_PARAMETER_SET_NOT_SUPPORTED),
    }
    // Engine-side seed storage — sensitive-blocked readback set
    // (state::attr_is_sensitive_material).
    if let Some(s) = seed {
        prv_attrs.insert(CKA_SEED, s.to_vec());
    }

    if let Some(pk_bytes) = pub_attrs.get(&CKA_VALUE).cloned() {
        let spki = build_slhdsa_spki(parameter_set, &pk_bytes);
        if !spki.is_empty() {
            pub_attrs.insert(CKA_PUBLIC_KEY_INFO, spki);
        }
    }

    finalize_and_register(_session, pub_attrs, prv_attrs)
}

// ── Classical ───────────────────────────────────────────────────────────────

/// Generate an RSA keypair. `bits` ∈ {2048, 3072, 4096} per FIPS 186-5
/// transition (engine permits ≥ 2048). Returns `(public_handle,
/// private_handle)`.
///
/// Mirrors `ffi::C_GenerateKeyPair @ CKM_RSA_PKCS_KEY_PAIR_GEN`:
/// stores RSA modulus + public exponent on the public-key object as
/// `CKA_MODULUS` + `CKA_PUBLIC_EXPONENT` (PKCS#11 v3.2 §2.1.2 — separate
/// attributes, NOT packed into `CKA_VALUE`). Private key bytes are the
/// PKCS#8-DER-encoded `RsaPrivateKey`.
///
/// Also writes an engine-specific packed `CKA_VALUE`
/// (`[n_len:4LE][n][e]`) on the public-key object so the existing
/// `C_Encrypt(CKM_RSA_PKCS_OAEP)` path can read the public key
/// uniformly via `get_object_value()`.
pub fn generate_rsa_keypair(
    _session: u32,
    bits: u32,
    cka_id: &[u8],
    label: &str,
) -> Result<(u32, u32), CkRv> {
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::traits::PublicKeyParts;

    if !(2048..=4096).contains(&bits) {
        return Err(CKR_ARGUMENTS_BAD);
    }
    let mut rng = rand::rngs::OsRng;
    let private_key =
        rsa::RsaPrivateKey::new(&mut rng, bits as usize).map_err(|_| CKR_FUNCTION_FAILED)?;
    let public_key = rsa::RsaPublicKey::from(&private_key);

    let sk_der = private_key.to_pkcs8_der().map_err(|_| CKR_FUNCTION_FAILED)?;
    let n_bytes = public_key.n().to_bytes_be();
    let e_bytes = public_key.e().to_bytes_be();

    let mut pub_attrs: Attributes = HashMap::new();
    let mut prv_attrs: Attributes = HashMap::new();

    store_algo_family(&mut pub_attrs, ALGO_RSA);
    store_algo_family(&mut prv_attrs, ALGO_RSA);

    // PKCS#11 v3.2 — RSA public key defaults (CKA_VERIFY=true, CKA_ENCRYPT=true,
    // CKA_WRAP=true; not CKA_SIGN/DECRYPT).
    store_ulong(&mut pub_attrs, CKA_CLASS, CKO_PUBLIC_KEY);
    store_ulong(&mut pub_attrs, CKA_KEY_TYPE, CKK_RSA);
    store_ulong(&mut pub_attrs, CKA_KEY_GEN_MECHANISM, CKM_RSA_PKCS_KEY_PAIR_GEN);
    store_bool(&mut pub_attrs, CKA_TOKEN, false);
    store_bool(&mut pub_attrs, CKA_PRIVATE, false);
    store_bool(&mut pub_attrs, CKA_ENCRYPT, true);
    store_bool(&mut pub_attrs, CKA_VERIFY, true);
    store_bool(&mut pub_attrs, CKA_WRAP, true);
    store_bool(&mut pub_attrs, CKA_DERIVE, false);
    store_bool(&mut pub_attrs, CKA_LOCAL, true);

    // PKCS#11 v3.2 — RSA private key defaults.
    store_ulong(&mut prv_attrs, CKA_CLASS, CKO_PRIVATE_KEY);
    store_ulong(&mut prv_attrs, CKA_KEY_TYPE, CKK_RSA);
    store_ulong(&mut prv_attrs, CKA_KEY_GEN_MECHANISM, CKM_RSA_PKCS_KEY_PAIR_GEN);
    store_bool(&mut prv_attrs, CKA_TOKEN, false);
    store_bool(&mut prv_attrs, CKA_PRIVATE, true);
    store_bool(&mut prv_attrs, CKA_SENSITIVE, true);
    store_bool(&mut prv_attrs, CKA_EXTRACTABLE, false);
    store_bool(&mut prv_attrs, CKA_DECRYPT, true);
    store_bool(&mut prv_attrs, CKA_SIGN, true);
    store_bool(&mut prv_attrs, CKA_UNWRAP, true);
    store_bool(&mut prv_attrs, CKA_DERIVE, false);
    store_bool(&mut prv_attrs, CKA_LOCAL, true);

    // PKCS#11 v3.2 §2.1.2 — modulus + exponent as distinct attributes.
    pub_attrs.insert(CKA_MODULUS, n_bytes.clone());
    pub_attrs.insert(CKA_PUBLIC_EXPONENT, e_bytes.clone());
    store_ulong(&mut pub_attrs, CKA_MODULUS_BITS, bits);

    // SubjectPublicKeyInfo DER (CKA_PUBLIC_KEY_INFO).
    use rsa::pkcs8::EncodePublicKey;
    if let Ok(spki_der) = public_key.to_public_key_der() {
        pub_attrs.insert(CKA_PUBLIC_KEY_INFO, spki_der.as_bytes().to_vec());
    }

    // Engine-internal packed CKA_VALUE on the public key so C_Encrypt
    // (CKM_RSA_PKCS_OAEP) can reconstruct via get_object_value().
    // Format mirrors ffi.rs: [n_len:4LE][n_bytes][e_bytes].
    let mut packed = Vec::with_capacity(4 + n_bytes.len() + e_bytes.len());
    packed.extend_from_slice(&(n_bytes.len() as u32).to_le_bytes());
    packed.extend_from_slice(&n_bytes);
    packed.extend_from_slice(&e_bytes);
    pub_attrs.insert(CKA_VALUE, packed);
    prv_attrs.insert(CKA_VALUE, sk_der.as_bytes().to_vec());

    insert_id_and_label(&mut pub_attrs, cka_id, label);
    insert_id_and_label(&mut prv_attrs, cka_id, label);

    finalize_and_register(_session, pub_attrs, prv_attrs)
}

/// Generate an ECDSA keypair. `curve` is one of:
///
/// - `EccCurve::P256` (NIST P-256)
/// - `EccCurve::P384` (NIST P-384)
/// - `EccCurve::P521` (NIST P-521)
/// - `EccCurve::Secp256K1`
///
/// Returns `(public_handle, private_handle)`.
///
/// **Pre-condition**: `session` must be a valid R/W user session.
pub fn generate_ecdsa_keypair(
    _session: u32,
    curve: EccCurve,
    cka_id: &[u8],
    label: &str,
) -> Result<(u32, u32), CkRv> {
    let mut pub_attrs: Attributes = HashMap::new();
    let mut prv_attrs: Attributes = HashMap::new();

    store_algo_family(&mut pub_attrs, ALGO_ECDSA);
    store_algo_family(&mut prv_attrs, ALGO_ECDSA);

    set_common_ec_pub_attrs(&mut pub_attrs);
    set_common_ec_prv_attrs(&mut prv_attrs);

    let mut rng = rand::rngs::OsRng;

    // Per-curve keygen + attribute population.
    match curve {
        EccCurve::P256 => {
            store_param_set(&mut pub_attrs, CURVE_P256);
            store_param_set(&mut prv_attrs, CURVE_P256);
            let sk = p256::ecdsa::SigningKey::random(&mut rng);
            let vk = p256::ecdsa::VerifyingKey::from(&sk);
            prv_attrs.insert(CKA_VALUE, sk.to_bytes().to_vec());
            let vk_bytes = vk.to_encoded_point(false).as_bytes().to_vec();
            // CKA_EC_POINT: DER OCTET STRING wrapping the uncompressed SEC1 point.
            let mut ec_point = Vec::with_capacity(2 + vk_bytes.len());
            ec_point.push(0x04);
            ec_point.push(vk_bytes.len() as u8); // 65 fits in one byte (short-form)
            ec_point.extend_from_slice(&vk_bytes);
            pub_attrs.insert(CKA_EC_POINT, ec_point);
            pub_attrs.insert(CKA_PUBLIC_KEY_INFO, build_ec_spki_p256(&vk_bytes));
        }
        EccCurve::P384 => {
            store_param_set(&mut pub_attrs, CURVE_P384);
            store_param_set(&mut prv_attrs, CURVE_P384);
            let sk = p384::ecdsa::SigningKey::random(&mut rng);
            let vk = p384::ecdsa::VerifyingKey::from(&sk);
            prv_attrs.insert(CKA_VALUE, sk.to_bytes().to_vec());
            let vk_bytes = vk.to_encoded_point(false).as_bytes().to_vec();
            let mut ec_point = Vec::with_capacity(2 + vk_bytes.len());
            ec_point.push(0x04);
            ec_point.push(vk_bytes.len() as u8); // 97 fits in one byte
            ec_point.extend_from_slice(&vk_bytes);
            pub_attrs.insert(CKA_EC_POINT, ec_point);
            pub_attrs.insert(CKA_PUBLIC_KEY_INFO, build_ec_spki_p384(&vk_bytes));
        }
        EccCurve::P521 => {
            store_param_set(&mut pub_attrs, CURVE_P521);
            store_param_set(&mut prv_attrs, CURVE_P521);
            let sk = p521::ecdsa::SigningKey::random(&mut rng);
            let vk = p521::ecdsa::VerifyingKey::from(&sk);
            prv_attrs.insert(CKA_VALUE, sk.to_bytes().to_vec());
            let vk_bytes = vk.to_encoded_point(false).as_bytes().to_vec();
            // P-521 uncompressed point is 133 bytes — needs long-form DER length.
            let mut ec_point = Vec::with_capacity(3 + vk_bytes.len());
            ec_point.push(0x04);
            ec_point.push(0x81); // multi-byte length tag
            ec_point.push(vk_bytes.len() as u8); // 133
            ec_point.extend_from_slice(&vk_bytes);
            pub_attrs.insert(CKA_EC_POINT, ec_point);
            pub_attrs.insert(CKA_PUBLIC_KEY_INFO, build_ec_spki_p521(&vk_bytes));
        }
        EccCurve::Secp256K1 => {
            store_param_set(&mut pub_attrs, CURVE_K256);
            store_param_set(&mut prv_attrs, CURVE_K256);
            let sk = k256::ecdsa::SigningKey::random(&mut rng);
            let vk = k256::ecdsa::VerifyingKey::from(&sk);
            prv_attrs.insert(CKA_VALUE, sk.to_bytes().to_vec());
            let vk_bytes = vk.to_encoded_point(false).as_bytes().to_vec();
            let mut ec_point = Vec::with_capacity(2 + vk_bytes.len());
            ec_point.push(0x04);
            ec_point.push(vk_bytes.len() as u8);
            ec_point.extend_from_slice(&vk_bytes);
            pub_attrs.insert(CKA_EC_POINT, ec_point);
            // secp256k1 SPKI uses its own algorithm-id OID (1.3.132.0.10).
            // Same DER prefix the ffi path uses.
            const SECP256K1_ALG_ID: &[u8] = &[
                0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
                0x81, 0x04, 0x00, 0x0a,
            ];
            pub_attrs.insert(
                CKA_PUBLIC_KEY_INFO,
                build_spki_from_parts(SECP256K1_ALG_ID, &vk_bytes),
            );
        }
    }

    insert_id_and_label(&mut pub_attrs, cka_id, label);
    insert_id_and_label(&mut prv_attrs, cka_id, label);

    finalize_and_register(_session, pub_attrs, prv_attrs)
}

/// Generate a standalone ECDH (NIST-curve Diffie-Hellman) key pair.
/// `curve` is one of `EccCurve::P256` / `P384` / `P521` (`Secp256K1` is not a
/// KMIP-referenced ECDH curve in this stack; callers should reject it before
/// reaching here — see [`generate_ecdsa_keypair`] for the analogous ECDSA
/// path, which this mirrors structurally).
///
/// Tagged `ALGO_ECDH_P256` (the family constant used generically across all
/// three NIST curves — curve selection is the separate `CURVE_P256/384/521`
/// param-set attribute, exactly as `ALGO_ECDSA` already works across its four
/// curves) rather than `ALGO_ECDSA`, and the usage mask is
/// key-agreement-only (`CKA_DERIVE=true`, `CKA_SIGN=false`,
/// `CKA_VERIFY=false`) — unlike an ECDSA key (dual sign+derive per
/// `set_common_ec_prv_attrs`), a key a caller explicitly asked for as `ECDH`
/// should not silently also be usable for signing.
///
/// Fixes the 2026-07-05 KMIP-layer gap: `Ecdh` has a valid `KmipAlgorithm`
/// wire codepoint (`0x0e`) and is allowlisted by several crypto-agility
/// policies (bsi-tr-02102, fips-only, classical.yaml), but until this
/// function existed `CreateKeyPair` for it always failed with
/// `OperationNotSupported` — the policy plane said "allowed" for an
/// operation Plane 2 could never actually perform.
///
/// Returns `(public_handle, private_handle)`.
///
/// **Pre-condition**: `session` must be a valid R/W user session.
pub fn generate_ecdh_keypair(
    _session: u32,
    curve: EccCurve,
    cka_id: &[u8],
    label: &str,
) -> Result<(u32, u32), CkRv> {
    let mut pub_attrs: Attributes = HashMap::new();
    let mut prv_attrs: Attributes = HashMap::new();

    store_algo_family(&mut pub_attrs, ALGO_ECDH_P256);
    store_algo_family(&mut prv_attrs, ALGO_ECDH_P256);

    store_ulong(&mut pub_attrs, CKA_CLASS, CKO_PUBLIC_KEY);
    store_ulong(&mut pub_attrs, CKA_KEY_TYPE, CKK_EC);
    store_ulong(&mut pub_attrs, CKA_KEY_GEN_MECHANISM, CKM_EC_KEY_PAIR_GEN);
    store_bool(&mut pub_attrs, CKA_TOKEN, false);
    store_bool(&mut pub_attrs, CKA_PRIVATE, false);
    store_bool(&mut pub_attrs, CKA_ENCRYPT, false);
    store_bool(&mut pub_attrs, CKA_VERIFY, false);
    store_bool(&mut pub_attrs, CKA_WRAP, false);
    store_bool(&mut pub_attrs, CKA_DERIVE, false);
    // Classical-KEM crypto-agility (2026-07-05): PKCS#11 v3.2 §6.3.17 permits
    // CKM_ECDH1_DERIVE under C_EncapsulateKey/C_DecapsulateKey as well as
    // C_DeriveKey (same mechanism, independent permission flags, Table 78) —
    // this is the ephemeral-static "DHKEM" mode KMIP 3.0 WD19 names in its
    // KEM Algorithm enum. Enabling it alongside CKA_DERIVE lets one key serve
    // both the existing static-static DeriveKey path and the new Encapsulate/
    // Decapsulate path.
    store_bool(&mut pub_attrs, CKA_ENCAPSULATE, true);
    store_bool(&mut pub_attrs, CKA_LOCAL, true);

    store_ulong(&mut prv_attrs, CKA_CLASS, CKO_PRIVATE_KEY);
    store_ulong(&mut prv_attrs, CKA_KEY_TYPE, CKK_EC);
    store_ulong(&mut prv_attrs, CKA_KEY_GEN_MECHANISM, CKM_EC_KEY_PAIR_GEN);
    store_bool(&mut prv_attrs, CKA_TOKEN, false);
    store_bool(&mut prv_attrs, CKA_PRIVATE, true);
    store_bool(&mut prv_attrs, CKA_SENSITIVE, true);
    store_bool(&mut prv_attrs, CKA_EXTRACTABLE, false);
    store_bool(&mut prv_attrs, CKA_DECRYPT, false);
    store_bool(&mut prv_attrs, CKA_SIGN, false);
    store_bool(&mut prv_attrs, CKA_UNWRAP, false);
    store_bool(&mut prv_attrs, CKA_DERIVE, true);
    store_bool(&mut prv_attrs, CKA_DECAPSULATE, true);
    store_bool(&mut prv_attrs, CKA_LOCAL, true);

    let mut rng = rand::rngs::OsRng;

    match curve {
        EccCurve::P256 => {
            store_param_set(&mut pub_attrs, CURVE_P256);
            store_param_set(&mut prv_attrs, CURVE_P256);
            let sk = p256::ecdsa::SigningKey::random(&mut rng);
            let vk = p256::ecdsa::VerifyingKey::from(&sk);
            prv_attrs.insert(CKA_VALUE, sk.to_bytes().to_vec());
            let vk_bytes = vk.to_encoded_point(false).as_bytes().to_vec();
            let mut ec_point = Vec::with_capacity(2 + vk_bytes.len());
            ec_point.push(0x04);
            ec_point.push(vk_bytes.len() as u8); // 65 fits in one byte
            ec_point.extend_from_slice(&vk_bytes);
            pub_attrs.insert(CKA_EC_POINT, ec_point);
            pub_attrs.insert(CKA_PUBLIC_KEY_INFO, build_ec_spki_p256(&vk_bytes));
        }
        EccCurve::P384 => {
            store_param_set(&mut pub_attrs, CURVE_P384);
            store_param_set(&mut prv_attrs, CURVE_P384);
            let sk = p384::ecdsa::SigningKey::random(&mut rng);
            let vk = p384::ecdsa::VerifyingKey::from(&sk);
            prv_attrs.insert(CKA_VALUE, sk.to_bytes().to_vec());
            let vk_bytes = vk.to_encoded_point(false).as_bytes().to_vec();
            let mut ec_point = Vec::with_capacity(2 + vk_bytes.len());
            ec_point.push(0x04);
            ec_point.push(vk_bytes.len() as u8); // 97 fits in one byte
            ec_point.extend_from_slice(&vk_bytes);
            pub_attrs.insert(CKA_EC_POINT, ec_point);
            pub_attrs.insert(CKA_PUBLIC_KEY_INFO, build_ec_spki_p384(&vk_bytes));
        }
        EccCurve::P521 => {
            store_param_set(&mut pub_attrs, CURVE_P521);
            store_param_set(&mut prv_attrs, CURVE_P521);
            let sk = p521::ecdsa::SigningKey::random(&mut rng);
            let vk = p521::ecdsa::VerifyingKey::from(&sk);
            prv_attrs.insert(CKA_VALUE, sk.to_bytes().to_vec());
            let vk_bytes = vk.to_encoded_point(false).as_bytes().to_vec();
            // P-521 uncompressed point is 133 bytes — needs long-form DER length.
            let mut ec_point = Vec::with_capacity(3 + vk_bytes.len());
            ec_point.push(0x04);
            ec_point.push(0x81); // multi-byte length tag
            ec_point.push(vk_bytes.len() as u8); // 133
            ec_point.extend_from_slice(&vk_bytes);
            pub_attrs.insert(CKA_EC_POINT, ec_point);
            pub_attrs.insert(CKA_PUBLIC_KEY_INFO, build_ec_spki_p521(&vk_bytes));
        }
        EccCurve::Secp256K1 => {
            return Err(CKR_MECHANISM_INVALID);
        }
    }

    insert_id_and_label(&mut pub_attrs, cka_id, label);
    insert_id_and_label(&mut prv_attrs, cka_id, label);

    finalize_and_register(_session, pub_attrs, prv_attrs)
}

/// Generate an Ed25519 (RFC 8032 EdDSA over Curve25519, Edwards form) key
/// pair. Distinct from [`generate_ecdh_keypair`]'s Montgomery-form X25519 in
/// every respect: key type (`CKK_EC_EDWARDS`, not `CKK_EC_MONTGOMERY`),
/// mechanism (`CKM_EC_EDWARDS_KEY_PAIR_GEN`/`CKM_EDDSA`, not
/// `CKM_EC_MONTGOMERY_KEY_PAIR_GEN`/`CKM_X25519`), purpose (signing, not key
/// agreement), and OID (`id-Ed25519` = `1.3.101.112`, not `id-X25519` =
/// `1.3.101.110` — verified directly against RFC 8410, not inferred from the
/// adjacent arc). Sign/Verify dispatch for `CKM_EDDSA` already exists
/// (`native::sign`/`native::verify` → `crypto::handlers::sign_eddsa`/
/// `verify_eddsa`) — this function is the only missing piece for a full
/// KMIP `CreateKeyPair` round trip (2026-07-05, P1).
///
/// Returns `(public_handle, private_handle)`.
///
/// **Pre-condition**: `session` must be a valid R/W user session.
pub fn generate_ed25519_keypair(
    _session: u32,
    cka_id: &[u8],
    label: &str,
) -> Result<(u32, u32), CkRv> {
    let mut pub_attrs: Attributes = HashMap::new();
    let mut prv_attrs: Attributes = HashMap::new();

    store_algo_family(&mut pub_attrs, ALGO_EDDSA);
    store_algo_family(&mut prv_attrs, ALGO_EDDSA);

    store_ulong(&mut pub_attrs, CKA_CLASS, CKO_PUBLIC_KEY);
    store_ulong(&mut pub_attrs, CKA_KEY_TYPE, CKK_EC_EDWARDS);
    store_ulong(&mut pub_attrs, CKA_KEY_GEN_MECHANISM, CKM_EC_EDWARDS_KEY_PAIR_GEN);
    store_bool(&mut pub_attrs, CKA_TOKEN, false);
    store_bool(&mut pub_attrs, CKA_PRIVATE, false);
    store_bool(&mut pub_attrs, CKA_ENCRYPT, false);
    store_bool(&mut pub_attrs, CKA_VERIFY, true);
    store_bool(&mut pub_attrs, CKA_WRAP, false);
    store_bool(&mut pub_attrs, CKA_DERIVE, false);
    store_bool(&mut pub_attrs, CKA_LOCAL, true);

    store_ulong(&mut prv_attrs, CKA_CLASS, CKO_PRIVATE_KEY);
    store_ulong(&mut prv_attrs, CKA_KEY_TYPE, CKK_EC_EDWARDS);
    store_ulong(&mut prv_attrs, CKA_KEY_GEN_MECHANISM, CKM_EC_EDWARDS_KEY_PAIR_GEN);
    store_bool(&mut prv_attrs, CKA_TOKEN, false);
    store_bool(&mut prv_attrs, CKA_PRIVATE, true);
    store_bool(&mut prv_attrs, CKA_SENSITIVE, true);
    store_bool(&mut prv_attrs, CKA_EXTRACTABLE, false);
    store_bool(&mut prv_attrs, CKA_DECRYPT, false);
    store_bool(&mut prv_attrs, CKA_SIGN, true);
    store_bool(&mut prv_attrs, CKA_UNWRAP, false);
    store_bool(&mut prv_attrs, CKA_DERIVE, false);
    store_bool(&mut prv_attrs, CKA_LOCAL, true);

    let mut rng = rand::rngs::OsRng;
    let sk = ed25519_dalek::SigningKey::generate(&mut rng);
    let vk = sk.verifying_key();

    prv_attrs.insert(CKA_VALUE, sk.to_bytes().to_vec()); // 32-byte seed
    let vk_bytes = vk.to_bytes().to_vec(); // 32-byte encoded point
    // Matches the existing raw-FFI Ed25519 keygen convention (ffi.rs
    // CKM_EC_EDWARDS_KEY_PAIR_GEN): the encoded point lives in CKA_VALUE on
    // the public object, not CKA_EC_POINT (that attribute is the SEC1/DER
    // convention `get_ec_point_sec1` expects for Weierstrass curves — Ed25519
    // isn't one, and stuffing a raw Edwards point through that SEC1 stripper
    // would corrupt it if the point's first byte happened to be 0x04).
    pub_attrs.insert(CKA_VALUE, vk_bytes.clone());
    pub_attrs.insert(CKA_PUBLIC_KEY_INFO, build_ed25519_spki(&vk_bytes));

    insert_id_and_label(&mut pub_attrs, cka_id, label);
    insert_id_and_label(&mut prv_attrs, cka_id, label);

    finalize_and_register(_session, pub_attrs, prv_attrs)
}

/// Generate an X25519 (RFC 7748 Montgomery-form ECDH over Curve25519) key
/// pair. This is the native typed parallel of the FFI
/// `CKM_EC_MONTGOMERY_KEY_PAIR_GEN` X25519 branch (`ffi.rs`) — same crypto
/// (`x25519_dalek`), same object shape (`CKK_EC_MONTGOMERY`, 32-byte scalar in
/// `CKA_VALUE`, raw public point in `CKA_VALUE`/`CKA_EC_POINT`, id-X25519 OID
/// `1.3.101.110` in `CKA_EC_PARAMS`), exposed to native callers so the hybrid
/// KEM code can create the classical half of X25519MLKEM768 as an ordinary
/// NON-EXTRACTABLE engine object (its private scalar never leaves the HSM).
///
/// Distinct from [`generate_ed25519_keypair`]: key agreement (`CKA_DERIVE`),
/// not signing; Montgomery form, not Edwards.
///
/// Returns `(public_handle, private_handle)`.
pub fn generate_x25519_keypair(
    _session: u32,
    cka_id: &[u8],
    label: &str,
) -> Result<(u32, u32), CkRv> {
    let mut pub_attrs: Attributes = HashMap::new();
    let mut prv_attrs: Attributes = HashMap::new();

    store_algo_family(&mut pub_attrs, ALGO_ECDH_X25519);
    store_algo_family(&mut prv_attrs, ALGO_ECDH_X25519);

    store_ulong(&mut pub_attrs, CKA_CLASS, CKO_PUBLIC_KEY);
    store_ulong(&mut pub_attrs, CKA_KEY_TYPE, CKK_EC_MONTGOMERY);
    store_ulong(&mut pub_attrs, CKA_KEY_GEN_MECHANISM, CKM_EC_MONTGOMERY_KEY_PAIR_GEN);
    store_bool(&mut pub_attrs, CKA_TOKEN, false);
    store_bool(&mut pub_attrs, CKA_PRIVATE, false);
    store_bool(&mut pub_attrs, CKA_ENCRYPT, false);
    store_bool(&mut pub_attrs, CKA_VERIFY, false);
    store_bool(&mut pub_attrs, CKA_WRAP, false);
    store_bool(&mut pub_attrs, CKA_DERIVE, false);
    // Classical-KEM crypto-agility (2026-07-05) — see the identical note in
    // generate_ecdh_keypair: CKM_EC_MONTGOMERY_KEY_DERIVE is valid under
    // C_EncapsulateKey/C_DecapsulateKey too (PKCS#11 v3.2 §6.3.17-equivalent
    // for Montgomery curves), same mechanism as C_DeriveKey.
    store_bool(&mut pub_attrs, CKA_ENCAPSULATE, true);
    store_bool(&mut pub_attrs, CKA_LOCAL, true);

    store_ulong(&mut prv_attrs, CKA_CLASS, CKO_PRIVATE_KEY);
    store_ulong(&mut prv_attrs, CKA_KEY_TYPE, CKK_EC_MONTGOMERY);
    store_ulong(&mut prv_attrs, CKA_KEY_GEN_MECHANISM, CKM_EC_MONTGOMERY_KEY_PAIR_GEN);
    store_bool(&mut prv_attrs, CKA_TOKEN, false);
    store_bool(&mut prv_attrs, CKA_PRIVATE, true);
    store_bool(&mut prv_attrs, CKA_SENSITIVE, true);
    store_bool(&mut prv_attrs, CKA_EXTRACTABLE, false);
    store_bool(&mut prv_attrs, CKA_DECRYPT, false);
    store_bool(&mut prv_attrs, CKA_SIGN, false);
    store_bool(&mut prv_attrs, CKA_UNWRAP, false);
    store_bool(&mut prv_attrs, CKA_DERIVE, true);
    store_bool(&mut prv_attrs, CKA_DECAPSULATE, true);
    store_bool(&mut prv_attrs, CKA_LOCAL, true);

    let mut rng = rand::rngs::OsRng;
    let sk = x25519_dalek::StaticSecret::random_from_rng(&mut rng);
    let pk = x25519_dalek::PublicKey::from(&sk);
    let pk_bytes = pk.as_bytes().to_vec(); // 32-byte public
    let sk_bytes = sk.to_bytes().to_vec(); // 32-byte scalar

    prv_attrs.insert(CKA_VALUE, sk_bytes);
    pub_attrs.insert(CKA_VALUE, pk_bytes.clone());
    pub_attrs.insert(CKA_PUBLIC_KEY_INFO, build_x25519_spki(&pk_bytes));

    // PKCS#11 v3.2 §6.7 — CKA_EC_PARAMS carries the DER OID for id-X25519
    // (RFC 8410, 1.3.101.110 = 06 03 2b 65 6e). Same convention as the FFI arm.
    let oid_x25519: Vec<u8> = vec![0x06, 0x03, 0x2b, 0x65, 0x6e];
    pub_attrs.insert(CKA_EC_PARAMS, oid_x25519.clone());
    prv_attrs.insert(CKA_EC_PARAMS, oid_x25519);

    // CKA_EC_POINT — DER OCTET STRING wrapping the raw 32-byte public key.
    //
    // DELIBERATE SCOPE LIMIT (E4, 2026-08-13): the PKCS#11 surface
    // (`ffi::C_GenerateKeyPair`) now emits the BARE little-endian bytes the
    // Montgomery public-key table mandates, and drops CKA_VALUE from public
    // keys entirely. This NATIVE path keeps both the DER wrapper and
    // CKA_VALUE because it is not the Cryptoki surface the Standard governs,
    // and because `native::hybrid::keygen` reads the public share through
    // `get_object_value`. Every reader of either encoding goes through
    // `ec_point_unwrap` / `state::get_key_material`, which accept both, so
    // the two surfaces interoperate — but they are NOT byte-identical, and
    // aligning them is follow-up work, not something this item did.
    let mut ec_point = Vec::with_capacity(2 + pk_bytes.len());
    ec_point.push(0x04u8); // OCTET STRING tag
    ec_point.push(pk_bytes.len() as u8); // 0x20 = 32
    ec_point.extend_from_slice(&pk_bytes);
    pub_attrs.insert(CKA_EC_POINT, ec_point);

    insert_id_and_label(&mut pub_attrs, cka_id, label);
    insert_id_and_label(&mut prv_attrs, cka_id, label);

    finalize_and_register(_session, pub_attrs, prv_attrs)
}

/// Generate an X448 (RFC 7748 Montgomery-form ECDH over Curve448) key pair —
/// the 448-bit sibling of [`generate_x25519_keypair`], parallel to the FFI
/// `CKM_EC_MONTGOMERY_KEY_PAIR_GEN` X448 branch (`ffi.rs`). Same object shape
/// (`CKK_EC_MONTGOMERY`, 56-byte scalar in `CKA_VALUE`, raw public point in
/// `CKA_VALUE`/`CKA_EC_POINT`, id-X448 OID `1.3.101.111` in `CKA_EC_PARAMS`),
/// NON-EXTRACTABLE. Exposed so the KMIP layer can create X448 as
/// `ECDH` + `RecommendedCurve = CURVE448`.
///
/// Returns `(public_handle, private_handle)`.
pub fn generate_x448_keypair(
    _session: u32,
    cka_id: &[u8],
    label: &str,
) -> Result<(u32, u32), CkRv> {
    use x448::{PublicKey as X448PublicKey, StaticSecret as X448StaticSecret};

    let mut pub_attrs: Attributes = HashMap::new();
    let mut prv_attrs: Attributes = HashMap::new();

    store_algo_family(&mut pub_attrs, ALGO_ECDH_X448);
    store_algo_family(&mut prv_attrs, ALGO_ECDH_X448);

    store_ulong(&mut pub_attrs, CKA_CLASS, CKO_PUBLIC_KEY);
    store_ulong(&mut pub_attrs, CKA_KEY_TYPE, CKK_EC_MONTGOMERY);
    store_ulong(&mut pub_attrs, CKA_KEY_GEN_MECHANISM, CKM_EC_MONTGOMERY_KEY_PAIR_GEN);
    store_bool(&mut pub_attrs, CKA_TOKEN, false);
    store_bool(&mut pub_attrs, CKA_PRIVATE, false);
    store_bool(&mut pub_attrs, CKA_ENCRYPT, false);
    store_bool(&mut pub_attrs, CKA_VERIFY, false);
    store_bool(&mut pub_attrs, CKA_WRAP, false);
    store_bool(&mut pub_attrs, CKA_DERIVE, false);
    // Classical-KEM crypto-agility (2026-07-05) — see the identical note in
    // generate_ecdh_keypair.
    store_bool(&mut pub_attrs, CKA_ENCAPSULATE, true);
    store_bool(&mut pub_attrs, CKA_LOCAL, true);

    store_ulong(&mut prv_attrs, CKA_CLASS, CKO_PRIVATE_KEY);
    store_ulong(&mut prv_attrs, CKA_KEY_TYPE, CKK_EC_MONTGOMERY);
    store_ulong(&mut prv_attrs, CKA_KEY_GEN_MECHANISM, CKM_EC_MONTGOMERY_KEY_PAIR_GEN);
    store_bool(&mut prv_attrs, CKA_TOKEN, false);
    store_bool(&mut prv_attrs, CKA_PRIVATE, true);
    store_bool(&mut prv_attrs, CKA_SENSITIVE, true);
    store_bool(&mut prv_attrs, CKA_EXTRACTABLE, false);
    store_bool(&mut prv_attrs, CKA_DECRYPT, false);
    store_bool(&mut prv_attrs, CKA_SIGN, false);
    store_bool(&mut prv_attrs, CKA_UNWRAP, false);
    store_bool(&mut prv_attrs, CKA_DERIVE, true);
    store_bool(&mut prv_attrs, CKA_DECAPSULATE, true);
    store_bool(&mut prv_attrs, CKA_LOCAL, true);

    // x448's StaticSecret is built from 56 random bytes (matches the FFI arm).
    let mut sk_bytes_arr = [0u8; 56];
    getrandom::getrandom(&mut sk_bytes_arr).map_err(|_| CKR_FUNCTION_FAILED)?;
    let sk = X448StaticSecret::from(sk_bytes_arr);
    let pk = X448PublicKey::from(&sk);
    let pk_bytes = pk.as_bytes().to_vec(); // 56-byte public
    let sk_bytes = sk.as_bytes().to_vec(); // 56-byte scalar

    prv_attrs.insert(CKA_VALUE, sk_bytes);
    pub_attrs.insert(CKA_VALUE, pk_bytes.clone());
    pub_attrs.insert(CKA_PUBLIC_KEY_INFO, build_x448_spki(&pk_bytes));

    // PKCS#11 v3.2 §6.7 — id-X448 OID (RFC 8410, 1.3.101.111 = 06 03 2b 65 6f).
    let oid_x448: Vec<u8> = vec![0x06, 0x03, 0x2b, 0x65, 0x6f];
    pub_attrs.insert(CKA_EC_PARAMS, oid_x448.clone());
    prv_attrs.insert(CKA_EC_PARAMS, oid_x448);

    let mut ec_point = Vec::with_capacity(2 + pk_bytes.len());
    ec_point.push(0x04u8); // OCTET STRING tag
    ec_point.push(pk_bytes.len() as u8); // 0x38 = 56
    ec_point.extend_from_slice(&pk_bytes);
    pub_attrs.insert(CKA_EC_POINT, ec_point);

    insert_id_and_label(&mut pub_attrs, cka_id, label);
    insert_id_and_label(&mut prv_attrs, cka_id, label);

    finalize_and_register(_session, pub_attrs, prv_attrs)
}

/// Generate an AES secret key. `bits` ∈ {128, 192, 256} per PKCS#11
/// v3.2 §6.5.
pub fn generate_aes_key(
    _session: u32,
    bits: u32,
    cka_id: &[u8],
    label: &str,
) -> Result<u32, CkRv> {
    // NIST SP 800-38A AES key sizes are 128/192/256. Extending to
    // honour 192-bit keys (OASIS SKFF-M-{2,6,10}). PKCS#11 v3.2 §6.5
    // permits any of the three; the engine has no algorithmic block
    // on the intermediate size.
    let bytes = match bits {
        128 => 16usize,
        192 => 24usize,
        256 => 32usize,
        _ => return Err(CKR_ARGUMENTS_BAD),
    };
    let mut key = vec![0u8; bytes];
    getrandom::getrandom(&mut key).map_err(|_| CKR_FUNCTION_FAILED)?;
    let attrs = build_aes_attrs(key, bytes as u32, cka_id, label);
    Ok(alloc_in_session_slot(_session, finalize_secret_attrs(attrs)))
}

/// Register an existing RSA private key supplied as PKCS#8 DER bytes.
///
/// Creates a `CKO_PRIVATE_KEY` object with `CKK_RSA`, storing the
/// PKCS#8 DER bytes at `CKA_VALUE` (the same place `sign_rsa` reads
/// from via `from_pkcs8_der`). Returns the engine handle so the
/// caller can wire it into a KMIP UID → handle mapping.
///
/// Used by KMIP's `Register` op when a client supplies a PrivateKey
/// with `KeyFormatType=PKCS#8`. CS-AC-M-{1..6,8} exercise this path
/// against an RSA-2048 signing key.
pub fn register_rsa_private_key_pkcs8(
    _session: u32,
    pkcs8_der: &[u8],
    cka_id: &[u8],
    label: &str,
) -> Result<u32, CkRv> {
    use crate::constants::{CKA_CLASS, CKA_DECRYPT, CKA_KEY_TYPE, CKA_SIGN, CKA_VALUE, CKK_RSA, CKO_PRIVATE_KEY};
    let mut attrs = std::collections::HashMap::new();
    store_ulong(&mut attrs, CKA_CLASS, CKO_PRIVATE_KEY);
    store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_RSA);
    store_bool(&mut attrs, CKA_SIGN, true);
    store_bool(&mut attrs, CKA_DECRYPT, true);
    attrs.insert(CKA_VALUE, pkcs8_der.to_vec());
    insert_id_and_label(&mut attrs, cka_id, label);
    // PKCS#11 v3.2 §4.3/§4.9 — IMPORTED key provenance: not locally generated,
    // not always-sensitive, not never-extractable. Exportable by default
    // (KMIP Register'd material round-trips through Get).
    store_bool(&mut attrs, CKA_TOKEN, false);
    store_bool(&mut attrs, CKA_PRIVATE, false);
    store_bool(&mut attrs, CKA_SENSITIVE, false);
    store_bool(&mut attrs, CKA_EXTRACTABLE, true);
    store_bool(&mut attrs, CKA_LOCAL, false);
    store_ulong(&mut attrs, CKA_KEY_GEN_MECHANISM, CKM_UNAVAILABLE_INFORMATION);
    store_bool(&mut attrs, CKA_ALWAYS_SENSITIVE, false);
    store_bool(&mut attrs, CKA_NEVER_EXTRACTABLE, false);
    compute_kcv(&mut attrs);
    Ok(alloc_in_session_slot(_session, attrs))
}

/// Register an existing RSA public key supplied as either PKCS#1
/// (RSAPublicKey, `SEQUENCE { modulus, publicExponent }`) or PKCS#8
/// (SubjectPublicKeyInfo) DER bytes. Parses the DER to extract `n` and
/// `e`, stored as `CKA_MODULUS` + `CKA_PUBLIC_EXPONENT` (the form
/// `verify_rsa` reads via `get_rsa_public_components`).
///
/// Used by KMIP Register when the client provides an RSA PublicKey.
/// CS-AC-M-2 exercises this path against a SignatureVerify op.
///
/// Gap-remediation Phase D, Finding #3 — this previously accepted PKCS#1
/// only, despite the KMIP-layer caller's own doc comment claiming PKCS#8
/// support too; a PKCS#8-form Register call would fail here and the KMIP
/// layer discarded the `Result`, so the client saw a wire `Success` with
/// no real engine object. Same `from_public_key_der` → `from_pkcs1_der`
/// fallback order `rsa_public_key_from_any_der` (`native/encrypt.rs`)
/// already uses for the analogous Encrypt/Decrypt DER-parsing path.
pub fn register_rsa_public_key_der(
    _session: u32,
    der: &[u8],
    cka_id: &[u8],
    label: &str,
) -> Result<u32, CkRv> {
    use crate::constants::{
        CKA_CLASS, CKA_ENCRYPT, CKA_KEY_TYPE, CKA_MODULUS, CKA_MODULUS_BITS,
        CKA_PUBLIC_EXPONENT, CKA_VALUE, CKA_VERIFY, CKK_RSA, CKO_PUBLIC_KEY,
    };
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::pkcs8::DecodePublicKey;
    use rsa::traits::PublicKeyParts;
    let pk = rsa::RsaPublicKey::from_public_key_der(der)
        .or_else(|_| rsa::RsaPublicKey::from_pkcs1_der(der))
        .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
    let n_bytes = pk.n().to_bytes_be();
    let e_bytes = pk.e().to_bytes_be();
    let bits = (n_bytes.len() as u32) * 8;
    let mut attrs = std::collections::HashMap::new();
    store_ulong(&mut attrs, CKA_CLASS, CKO_PUBLIC_KEY);
    store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_RSA);
    store_bool(&mut attrs, CKA_VERIFY, true);
    store_bool(&mut attrs, CKA_ENCRYPT, true);
    attrs.insert(CKA_MODULUS, n_bytes);
    attrs.insert(CKA_PUBLIC_EXPONENT, e_bytes);
    store_ulong(&mut attrs, CKA_MODULUS_BITS, bits);
    // Keep the raw DER too — some KMIP paths (Get) want to round-trip
    // the original Register material.
    attrs.insert(CKA_VALUE, der.to_vec());
    insert_id_and_label(&mut attrs, cka_id, label);
    // PKCS#11 v3.2 §4.3 — imported, not locally generated.
    store_bool(&mut attrs, CKA_LOCAL, false);
    store_ulong(&mut attrs, CKA_KEY_GEN_MECHANISM, CKM_UNAVAILABLE_INFORMATION);
    compute_kcv(&mut attrs);
    Ok(alloc_in_session_slot(_session, attrs))
}

/// Register an externally-supplied ECDSA public key from its DER
/// `SubjectPublicKeyInfo` (RFC 5480) — the KMIP-Register/Certify-CSR-
/// verification counterpart of [`generate_ecdsa_keypair`], which this
/// mirrors attribute-for-attribute (verify-only usage: `CKA_VERIFY=true`,
/// `CKA_SIGN` absent, since only the private half a caller never has
/// signs). Added 2026-07 for the pure-Rust Certify/Validate port: neither
/// a CSR's self-signature check nor an X.509 chain-link signature check
/// can be performed against an ECDSA key without a way to import that
/// key's PUBLIC half into the engine as a transient verify object — RSA
/// and the PQC families already had this ([`register_rsa_public_key_der`],
/// [`register_ml_dsa_public_key`]); ECDSA/Ed25519 (see
/// [`register_ed25519_public_key`] below) did not, because nothing before
/// this needed to VERIFY against an externally-supplied EC key — keygen +
/// signing with engine-generated EC keys already worked.
///
/// Curve is determined from the SPKI's own AlgorithmIdentifier, decoded
/// via `spki`'s real DER parser (`SubjectPublicKeyInfoOwned::from_der`) —
/// the same RustCrypto family the kmip crate uses for X.509 elsewhere in
/// this port — not by hand-matching fixed byte prefixes. RFC 5480: the
/// algorithm OID is always `id-ecPublicKey` (1.2.840.10045.2.1); the
/// specific curve is the `ECParameters` CHOICE carried in the
/// AlgorithmIdentifier's `parameters` field, which — in its common
/// `namedCurve` form — is itself just an OID, decoded here the same way.
pub fn register_ecdsa_public_key(
    _session: u32,
    der: &[u8],
    cka_id: &[u8],
    label: &str,
) -> Result<u32, CkRv> {
    use crate::crypto::handlers::{build_ec_spki_p256, build_ec_spki_p384, build_ec_spki_p521};
    use spki::der::{Decode, Encode};
    use spki::SubjectPublicKeyInfoOwned;

    const EC_PUBLIC_KEY_OID: &str = "1.2.840.10045.2.1";
    const SECP256R1_OID: &str = "1.2.840.10045.3.1.7";
    const SECP384R1_OID: &str = "1.3.132.0.34";
    const SECP521R1_OID: &str = "1.3.132.0.35";

    let spki = SubjectPublicKeyInfoOwned::from_der(der).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
    if spki.algorithm.oid.to_string() != EC_PUBLIC_KEY_OID {
        return Err(CKR_KEY_TYPE_INCONSISTENT);
    }
    let curve_oid = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.decode_as::<spki::ObjectIdentifier>().ok())
        .ok_or(CKR_KEY_TYPE_INCONSISTENT)?
        .to_string();
    let point = spki.subject_public_key.raw_bytes();

    // Validate the point is genuinely ON the named curve — the one place
    // this function touches actual EC math, and it happens here in the
    // engine (rust/), never in the kmip crate, per the crypto/encoding
    // boundary this port holds to throughout.
    let (curve, param_set, canonical_spki): (EccCurve, u32, Vec<u8>) =
        if curve_oid == SECP256R1_OID {
            p256::PublicKey::from_sec1_bytes(point).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            (EccCurve::P256, CURVE_P256, build_ec_spki_p256(point))
        } else if curve_oid == SECP384R1_OID {
            p384::PublicKey::from_sec1_bytes(point).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            (EccCurve::P384, CURVE_P384, build_ec_spki_p384(point))
        } else if curve_oid == SECP521R1_OID {
            p521::PublicKey::from_sec1_bytes(point).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            (EccCurve::P521, CURVE_P521, build_ec_spki_p521(point))
        } else {
            return Err(CKR_KEY_TYPE_INCONSISTENT); // e.g. secp256k1, or explicit (non-named) params
        };
    let _ = EccCurve::Secp256K1; // silence unused-variant warning; not reachable here by design

    let mut attrs: Attributes = HashMap::new();
    store_algo_family(&mut attrs, ALGO_ECDSA);
    set_common_ec_pub_attrs(&mut attrs);
    store_param_set(&mut attrs, param_set);

    // CKA_EC_POINT: DER OCTET STRING wrapping the uncompressed SEC1 point
    // — identical wrapping convention to `generate_ecdsa_keypair`.
    let mut ec_point = Vec::with_capacity(3 + point.len());
    ec_point.push(0x04);
    ec_point.extend_from_slice(&crate::crypto::handlers::der_length(point.len()));
    ec_point.extend_from_slice(point);
    attrs.insert(CKA_EC_POINT, ec_point);
    // Store the CANONICAL re-derived SPKI (not the caller's original DER
    // bytes verbatim) — matches `register_rsa_public_key_der`'s convention
    // of storing what the engine itself would produce, so a subsequent Get
    // always returns a form the engine's own builders vouch for. Curve
    // already validated above; `.to_der()` failing here would mean this
    // engine's own SPKI encoder produced something spki's decoder itself
    // rejects — treat that as a bug, not a client-input error.
    let _ = curve; // used only to select param_set/builder above
    attrs.insert(
        CKA_PUBLIC_KEY_INFO,
        SubjectPublicKeyInfoOwned::from_der(&canonical_spki)
            .and_then(|s| s.to_der())
            .unwrap_or(canonical_spki),
    );
    insert_id_and_label(&mut attrs, cka_id, label);
    // PKCS#11 v3.2 §4.3 — imported, not locally generated.
    store_bool(&mut attrs, CKA_LOCAL, false);
    store_ulong(&mut attrs, CKA_KEY_GEN_MECHANISM, CKM_UNAVAILABLE_INFORMATION);
    compute_kcv(&mut attrs);
    Ok(alloc_in_session_slot(_session, attrs))
}

/// Register an externally-supplied Ed25519 public key from its DER
/// `SubjectPublicKeyInfo` (RFC 8410) — see [`register_ecdsa_public_key`]'s
/// doc comment for why this function exists. Mirrors
/// [`generate_ed25519_keypair`]'s public-object attribute layout exactly,
/// including the RFC 8410 convention this engine already follows: the raw
/// 32-byte Edwards point lives in `CKA_VALUE`, not `CKA_EC_POINT` (that
/// attribute's SEC1-stripping convention is for Weierstrass curves only —
/// see `generate_ed25519_keypair`'s comment on exactly this point). Real
/// DER parsing via `spki`, same as [`register_ecdsa_public_key`].
pub fn register_ed25519_public_key(
    _session: u32,
    der: &[u8],
    cka_id: &[u8],
    label: &str,
) -> Result<u32, CkRv> {
    use crate::crypto::handlers::build_ed25519_spki;
    use spki::der::Decode;
    use spki::SubjectPublicKeyInfoOwned;

    const ED25519_OID: &str = "1.3.101.112";

    let spki = SubjectPublicKeyInfoOwned::from_der(der).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
    if spki.algorithm.oid.to_string() != ED25519_OID {
        return Err(CKR_KEY_TYPE_INCONSISTENT);
    }
    let point = spki.subject_public_key.raw_bytes();
    let point_arr: [u8; 32] = point.try_into().map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
    // The one EC-math touch point, in the engine, never in kmip: confirm
    // this is genuinely a point on the curve before it's ever handed to
    // C_Verify — a malformed point must fail HERE, not surface as a
    // confusing verify-time error later.
    ed25519_dalek::VerifyingKey::from_bytes(&point_arr).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;

    let mut attrs: Attributes = HashMap::new();
    store_algo_family(&mut attrs, ALGO_EDDSA);
    store_ulong(&mut attrs, CKA_CLASS, CKO_PUBLIC_KEY);
    store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_EC_EDWARDS);
    store_bool(&mut attrs, CKA_TOKEN, false);
    store_bool(&mut attrs, CKA_PRIVATE, false);
    store_bool(&mut attrs, CKA_ENCRYPT, false);
    store_bool(&mut attrs, CKA_VERIFY, true);
    store_bool(&mut attrs, CKA_WRAP, false);
    store_bool(&mut attrs, CKA_DERIVE, false);
    attrs.insert(CKA_VALUE, point.to_vec());
    attrs.insert(CKA_PUBLIC_KEY_INFO, build_ed25519_spki(point));
    insert_id_and_label(&mut attrs, cka_id, label);
    store_bool(&mut attrs, CKA_LOCAL, false);
    store_ulong(&mut attrs, CKA_KEY_GEN_MECHANISM, CKM_UNAVAILABLE_INFORMATION);
    compute_kcv(&mut attrs);
    Ok(alloc_in_session_slot(_session, attrs))
}

/// Register an existing HMAC / Generic Secret key supplied as raw key
/// bytes. Used by KMIP Register when the client provides a SymmetricKey
/// with `CryptographicAlgorithm = HMAC_SHA{256,384,512}`. CS-AC-M-{4,5,6}
/// exercise this path against MAC / MACVerify ops.
pub fn register_generic_secret_bytes(
    _session: u32,
    key_bytes: &[u8],
    cka_id: &[u8],
    label: &str,
) -> Result<u32, CkRv> {
    let mut attrs = build_generic_secret_attrs(
        key_bytes.to_vec(),
        key_bytes.len() as u32,
        cka_id,
        label,
    );
    // PKCS#11 v3.2 §4.3/§4.10 — IMPORTED key provenance (overrides the
    // generated-key values from the attr builder). Must NOT call
    // finalize_private_key_attrs here: that would derive ALWAYS_SENSITIVE /
    // NEVER_EXTRACTABLE as if the key had been born inside the token.
    store_bool(&mut attrs, CKA_LOCAL, false);
    store_ulong(&mut attrs, CKA_KEY_GEN_MECHANISM, CKM_UNAVAILABLE_INFORMATION);
    store_bool(&mut attrs, CKA_ALWAYS_SENSITIVE, false);
    store_bool(&mut attrs, CKA_NEVER_EXTRACTABLE, false);
    compute_kcv(&mut attrs);
    Ok(alloc_in_session_slot(_session, attrs))
}

// ── PQC key import (fix-plan S7, consumed by KMIP K9 / B-6) ─────────────────
//
// Each `register_*` function accepts raw FIPS 203/204/205 key bytes plus
// the `CKP_*` parameter set, validates the byte length against the
// parameter-set table (and, where the crate backend can fail, performs the
// structural deserialization at import time so a bad key is rejected with
// `CKR_ATTRIBUTE_VALUE_INVALID` here rather than panicking/erroring at
// first use), and stores an object byte-compatible with what
// `native::sign` / `native::encrypt` read at use time (`CKA_VALUE` +
// engine param-set + `CKA_SIGN`/`CKA_VERIFY`/`CKA_ENCAPSULATE`/
// `CKA_DECAPSULATE` gates).
//
// Imported provenance per PKCS#11 v3.2 §4.3/§4.9/§4.10: `CKA_LOCAL=FALSE`,
// `CKA_KEY_GEN_MECHANISM=CK_UNAVAILABLE_INFORMATION`, and — because the
// key material existed outside the token — `CKA_ALWAYS_SENSITIVE=FALSE` /
// `CKA_NEVER_EXTRACTABLE=FALSE` (same pattern as
// `register_rsa_private_key_pkcs8` / `register_generic_secret_bytes`).
// Private keys keep the keygen default `CKA_SENSITIVE=TRUE`.

/// Register an existing ML-DSA private (signing) key supplied as raw
/// FIPS 204 `sk` bytes. `parameter_set` ∈ {`CKP_ML_DSA_44`, `_65`, `_87`}.
///
/// Byte length must match the FIPS 204 §5 table (2560 / 4032 / 4896);
/// the key is structurally deserialized via `fips204` at import time.
/// Wrong length or undecodable material → `CKR_ATTRIBUTE_VALUE_INVALID`.
pub fn register_ml_dsa_private_key(
    _session: u32,
    parameter_set: u32,
    sk_bytes: &[u8],
    cka_id: &[u8],
    label: &str,
) -> Result<u32, CkRv> {
    let (sk_len, _) = ml_dsa_key_lens(parameter_set).ok_or(CKR_ARGUMENTS_BAD)?;
    if sk_bytes.len() != sk_len {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID);
    }
    validate_ml_dsa_key(parameter_set, sk_bytes, true)?;
    Ok(register_pqc_private(
        _session,
        parameter_set,
        ALGO_ML_DSA,
        CKK_ML_DSA,
        CKM_ML_DSA_KEY_PAIR_GEN,
        true,  // CKA_SIGN — keygen default for the DSA families
        false, // CKA_DECAPSULATE
        sk_bytes,
        cka_id,
        label,
    ))
}

/// Register an existing ML-DSA public (verification) key supplied as raw
/// FIPS 204 `pk` bytes (1312 / 1952 / 2592). Also stores the
/// `CKA_PUBLIC_KEY_INFO` SPKI, mirroring keygen.
pub fn register_ml_dsa_public_key(
    _session: u32,
    parameter_set: u32,
    pk_bytes: &[u8],
    cka_id: &[u8],
    label: &str,
) -> Result<u32, CkRv> {
    let (_, pk_len) = ml_dsa_key_lens(parameter_set).ok_or(CKR_ARGUMENTS_BAD)?;
    if pk_bytes.len() != pk_len {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID);
    }
    validate_ml_dsa_key(parameter_set, pk_bytes, false)?;
    let spki = match parameter_set {
        CKP_ML_DSA_44 => build_mldsa44_spki(pk_bytes),
        CKP_ML_DSA_65 => build_mldsa65_spki(pk_bytes),
        CKP_ML_DSA_87 => build_mldsa87_spki(pk_bytes),
        _ => Vec::new(),
    };
    Ok(register_pqc_public(
        _session,
        parameter_set,
        ALGO_ML_DSA,
        CKK_ML_DSA,
        CKM_ML_DSA_KEY_PAIR_GEN,
        true,  // CKA_VERIFY
        false, // CKA_ENCAPSULATE
        pk_bytes,
        spki,
        cka_id,
        label,
    ))
}

/// Register an existing ML-KEM private (decapsulation) key supplied as
/// raw FIPS 203 `dk` bytes. `parameter_set` ∈ {`CKP_ML_KEM_512`, `_768`,
/// `_1024`}; length per FIPS 203 §7 (1632 / 2400 / 3168). Sets
/// `CKA_DECAPSULATE=TRUE`, mirroring keygen defaults.
///
/// The `ml-kem` backend's `DecapsulationKey::from_bytes` is infallible
/// for a correct-length encoding, so the length check **is** the
/// structural check for this family.
pub fn register_ml_kem_private_key(
    _session: u32,
    parameter_set: u32,
    dk_bytes: &[u8],
    cka_id: &[u8],
    label: &str,
) -> Result<u32, CkRv> {
    let (dk_len, _) = ml_kem_key_lens(parameter_set).ok_or(CKR_ARGUMENTS_BAD)?;
    if dk_bytes.len() != dk_len {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID);
    }
    Ok(register_pqc_private(
        _session,
        parameter_set,
        ALGO_ML_KEM,
        CKK_ML_KEM,
        CKM_ML_KEM_KEY_PAIR_GEN,
        false, // CKA_SIGN
        true,  // CKA_DECAPSULATE — keygen default for ML-KEM
        dk_bytes,
        cka_id,
        label,
    ))
}

/// Register an existing ML-KEM public (encapsulation) key supplied as
/// raw FIPS 203 `ek` bytes (800 / 1184 / 1568). Sets
/// `CKA_ENCAPSULATE=TRUE` and stores the SPKI, mirroring keygen.
pub fn register_ml_kem_public_key(
    _session: u32,
    parameter_set: u32,
    ek_bytes: &[u8],
    cka_id: &[u8],
    label: &str,
) -> Result<u32, CkRv> {
    let (_, ek_len) = ml_kem_key_lens(parameter_set).ok_or(CKR_ARGUMENTS_BAD)?;
    if ek_bytes.len() != ek_len {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID);
    }
    let spki = match parameter_set {
        CKP_ML_KEM_512 => build_mlkem512_spki(ek_bytes),
        CKP_ML_KEM_768 => build_mlkem768_spki(ek_bytes),
        CKP_ML_KEM_1024 => build_mlkem1024_spki(ek_bytes),
        _ => Vec::new(),
    };
    Ok(register_pqc_public(
        _session,
        parameter_set,
        ALGO_ML_KEM,
        CKK_ML_KEM,
        CKM_ML_KEM_KEY_PAIR_GEN,
        false, // CKA_VERIFY
        true,  // CKA_ENCAPSULATE — keygen default for ML-KEM
        ek_bytes,
        spki,
        cka_id,
        label,
    ))
}

/// FrodoKEM parameter-set table: `CKP_FRODOKEM_*` → `(sk_len, pk_len)`,
/// verified directly against `frodo-kem` v0.1.0's own `AlgorithmParams`
/// (see the mechanism_info comment in ffi.rs for how — not the spec PDF,
/// to avoid a crate/spec version mismatch).
fn frodokem_key_lens(parameter_set: u32) -> Option<(usize, usize)> {
    match parameter_set {
        CKP_FRODOKEM_640_AES | CKP_FRODOKEM_640_SHAKE => Some((19888, 9616)),
        CKP_FRODOKEM_976_AES | CKP_FRODOKEM_976_SHAKE => Some((31296, 15632)),
        CKP_FRODOKEM_1344_AES | CKP_FRODOKEM_1344_SHAKE => Some((43088, 21520)),
        _ => None,
    }
}

/// Register an existing FrodoKEM private (decryption) key supplied as raw
/// bytes. Sets `CKA_DECAPSULATE=TRUE`, mirroring keygen.
pub fn register_frodokem_private_key(
    _session: u32,
    parameter_set: u32,
    dk_bytes: &[u8],
    cka_id: &[u8],
    label: &str,
) -> Result<u32, CkRv> {
    let (dk_len, _) = frodokem_key_lens(parameter_set).ok_or(CKR_ARGUMENTS_BAD)?;
    if dk_bytes.len() != dk_len {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID);
    }
    Ok(register_pqc_private(
        _session,
        parameter_set,
        ALGO_FRODOKEM,
        CKK_PQCTODAY_FRODOKEM,
        CKM_PQCTODAY_FRODOKEM_KEY_PAIR_GEN,
        false, // CKA_SIGN
        true,  // CKA_DECAPSULATE
        dk_bytes,
        cka_id,
        label,
    ))
}

/// Register an existing FrodoKEM public (encryption) key supplied as raw
/// bytes. Sets `CKA_ENCAPSULATE=TRUE`, mirroring keygen. No SPKI builder
/// exists for FrodoKEM (no standard AlgorithmIdentifier OID is registered
/// for it), so `CKA_PUBLIC_KEY_INFO` is left unset — same as any other
/// algorithm without one (see `register_pqc_public`'s `spki.is_empty()`
/// guard).
pub fn register_frodokem_public_key(
    _session: u32,
    parameter_set: u32,
    ek_bytes: &[u8],
    cka_id: &[u8],
    label: &str,
) -> Result<u32, CkRv> {
    let (_, ek_len) = frodokem_key_lens(parameter_set).ok_or(CKR_ARGUMENTS_BAD)?;
    if ek_bytes.len() != ek_len {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID);
    }
    Ok(register_pqc_public(
        _session,
        parameter_set,
        ALGO_FRODOKEM,
        CKK_PQCTODAY_FRODOKEM,
        CKM_PQCTODAY_FRODOKEM_KEY_PAIR_GEN,
        false, // CKA_VERIFY
        true,  // CKA_ENCAPSULATE
        ek_bytes,
        Vec::new(),
        cka_id,
        label,
    ))
}

/// Register an existing Classic McEliece private (secret) key supplied as
/// raw bytes. Scoped to `mceliece6688128` only (implementation plan Phase
/// 0.5) — `parameter_set` MUST be `CKP_CLASSIC_MCELIECE_6688128`.
pub fn register_classic_mceliece_private_key(
    _session: u32,
    parameter_set: u32,
    sk_bytes: &[u8],
    cka_id: &[u8],
    label: &str,
) -> Result<u32, CkRv> {
    if parameter_set != CKP_CLASSIC_MCELIECE_6688128 {
        return Err(CKR_ARGUMENTS_BAD);
    }
    if sk_bytes.len() != classic_mceliece_rust::CRYPTO_SECRETKEYBYTES {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID);
    }
    Ok(register_pqc_private(
        _session,
        parameter_set,
        ALGO_CLASSIC_MCELIECE,
        CKK_PQCTODAY_CLASSIC_MCELIECE,
        CKM_PQCTODAY_CLASSIC_MCELIECE_KEY_PAIR_GEN,
        false, // CKA_SIGN
        true,  // CKA_DECAPSULATE
        sk_bytes,
        cka_id,
        label,
    ))
}

/// Register an existing Classic McEliece public key supplied as raw bytes.
/// Scoped to `mceliece6688128` only. No SPKI builder exists for Classic
/// McEliece (no standard AlgorithmIdentifier OID is registered for it).
pub fn register_classic_mceliece_public_key(
    _session: u32,
    parameter_set: u32,
    pk_bytes: &[u8],
    cka_id: &[u8],
    label: &str,
) -> Result<u32, CkRv> {
    if parameter_set != CKP_CLASSIC_MCELIECE_6688128 {
        return Err(CKR_ARGUMENTS_BAD);
    }
    if pk_bytes.len() != classic_mceliece_rust::CRYPTO_PUBLICKEYBYTES {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID);
    }
    Ok(register_pqc_public(
        _session,
        parameter_set,
        ALGO_CLASSIC_MCELIECE,
        CKK_PQCTODAY_CLASSIC_MCELIECE,
        CKM_PQCTODAY_CLASSIC_MCELIECE_KEY_PAIR_GEN,
        false, // CKA_VERIFY
        true,  // CKA_ENCAPSULATE
        pk_bytes,
        Vec::new(),
        cka_id,
        label,
    ))
}

/// Register an existing SLH-DSA private key supplied as raw FIPS 205
/// `sk` bytes. `parameter_set` is one of the 12 `CKP_SLH_DSA_*` values;
/// length is `4n` per FIPS 205 §9.1 (64 / 96 / 128 for n = 16 / 24 / 32),
/// taken from the `fips205` crate's per-variant `SK_LEN` (same source
/// keygen serializes from).
pub fn register_slh_dsa_private_key(
    _session: u32,
    parameter_set: u32,
    sk_bytes: &[u8],
    cka_id: &[u8],
    label: &str,
) -> Result<u32, CkRv> {
    let (sk_len, _) = slh_dsa_key_lens(parameter_set).ok_or(CKR_ARGUMENTS_BAD)?;
    if sk_bytes.len() != sk_len {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID);
    }
    validate_slh_dsa_key(parameter_set, sk_bytes, true)?;
    Ok(register_pqc_private(
        _session,
        parameter_set,
        ALGO_SLH_DSA,
        CKK_SLH_DSA,
        CKM_SLH_DSA_KEY_PAIR_GEN,
        true,  // CKA_SIGN
        false, // CKA_DECAPSULATE
        sk_bytes,
        cka_id,
        label,
    ))
}

/// Register an existing SLH-DSA public key supplied as raw FIPS 205
/// `pk` bytes (`2n`: 32 / 48 / 64). Stores the SPKI, mirroring keygen.
pub fn register_slh_dsa_public_key(
    _session: u32,
    parameter_set: u32,
    pk_bytes: &[u8],
    cka_id: &[u8],
    label: &str,
) -> Result<u32, CkRv> {
    let (_, pk_len) = slh_dsa_key_lens(parameter_set).ok_or(CKR_ARGUMENTS_BAD)?;
    if pk_bytes.len() != pk_len {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID);
    }
    validate_slh_dsa_key(parameter_set, pk_bytes, false)?;
    let spki = build_slhdsa_spki(parameter_set, pk_bytes);
    Ok(register_pqc_public(
        _session,
        parameter_set,
        ALGO_SLH_DSA,
        CKK_SLH_DSA,
        CKM_SLH_DSA_KEY_PAIR_GEN,
        true,  // CKA_VERIFY
        false, // CKA_ENCAPSULATE
        pk_bytes,
        spki,
        cka_id,
        label,
    ))
}

// ── HSS/LMS (RFC 8554) ───────────────────────────────────────────────────

/// Register an existing HSS/LMS private key given the raw serialized
/// `hbs-lms` private-key state blob (the same `CKA_PRIV_STATEFUL_KEY_STATE`
/// format `ffi::C_GenerateKeyPair @ CKM_HSS_KEY_PAIR_GEN` produces).
///
/// v0.1 supports exactly **one** parameter combination: single-level HSS
/// (i.e. plain LMS — RFC 8554 §6: an HSS key with 1 level is an LMS key),
/// `CKP_LMS_SHA256_M32_H5` / `CKP_LMOTS_SHA256_N32_W4` — the same default
/// `ffi::C_GenerateKeyPair`'s HSS arm falls back to when the caller
/// supplies no explicit params. KMIP has no attribute to select a
/// different combination yet; broader coverage is a natural follow-up,
/// not a correctness gap in what this does support.
///
/// The leaf index starts at 0 (fresh key). If the supplied state blob is
/// not actually fresh (e.g. re-registering a partially-used key from a
/// backup), the caller is responsible for that being true — this
/// function has no way to verify a state blob's prior usage history.
pub fn register_hss_private_key(
    session: u32,
    priv_state_bytes: &[u8],
    cka_id: &[u8],
    label: &str,
) -> Result<u32, CkRv> {
    if priv_state_bytes.is_empty() {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID);
    }
    let lms_param = CKP_LMS_SHA256_M32_H5;
    let lmots_param = CKP_LMOTS_SHA256_N32_W4;
    let total_sigs = crate::crypto::lms::lms_param_max_leaves(lms_param)
        .unwrap_or(0)
        .min(u32::MAX as u64) as u32;

    let mut attrs: Attributes = HashMap::new();
    store_ulong(&mut attrs, CKA_CLASS, CKO_PRIVATE_KEY);
    store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_HSS);
    store_ulong(&mut attrs, CKA_HSS_LMS_TYPE, 1); // levels — single-level HSS = LMS
    store_ulong(&mut attrs, CKA_LMS_PARAM_SET, lms_param);
    store_ulong(&mut attrs, CKA_LMOTS_PARAM_SET, lmots_param);
    store_ulong(&mut attrs, CKA_HSS_KEYS_REMAINING, total_sigs);
    store_bool(&mut attrs, CKA_TOKEN, false);
    store_bool(&mut attrs, CKA_PRIVATE, true);
    store_bool(&mut attrs, CKA_SENSITIVE, true);
    store_bool(&mut attrs, CKA_EXTRACTABLE, false);
    store_bool(&mut attrs, CKA_SIGN, true);
    attrs.insert(CKA_PRIV_STATEFUL_KEY_STATE, priv_state_bytes.to_vec());
    attrs.insert(CKA_PRIV_LEAF_INDEX, 0u64.to_le_bytes().to_vec());
    insert_id_and_label(&mut attrs, cka_id, label);
    // Imported provenance — matches `register_pqc_private`'s convention.
    store_bool(&mut attrs, CKA_LOCAL, false);
    store_ulong(&mut attrs, CKA_KEY_GEN_MECHANISM, CKM_UNAVAILABLE_INFORMATION);
    compute_kcv(&mut attrs);
    Ok(alloc_in_session_slot(session, attrs))
}

/// Register an existing HSS/LMS public key given the raw `hbs-lms`
/// public-key bytes. Same v0.1 single-parameter-combination scope as
/// [`register_hss_private_key`].
pub fn register_hss_public_key(
    session: u32,
    pub_key_bytes: &[u8],
    cka_id: &[u8],
    label: &str,
) -> Result<u32, CkRv> {
    if pub_key_bytes.is_empty() {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID);
    }
    let lms_param = CKP_LMS_SHA256_M32_H5;
    let lmots_param = CKP_LMOTS_SHA256_N32_W4;

    let mut attrs: Attributes = HashMap::new();
    store_ulong(&mut attrs, CKA_CLASS, CKO_PUBLIC_KEY);
    store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_HSS);
    store_ulong(&mut attrs, CKA_HSS_LMS_TYPE, 1);
    store_ulong(&mut attrs, CKA_LMS_PARAM_SET, lms_param);
    store_ulong(&mut attrs, CKA_LMOTS_PARAM_SET, lmots_param);
    store_bool(&mut attrs, CKA_TOKEN, false);
    store_bool(&mut attrs, CKA_PRIVATE, false);
    store_bool(&mut attrs, CKA_VERIFY, true);
    attrs.insert(CKA_VALUE, pub_key_bytes.to_vec());
    insert_id_and_label(&mut attrs, cka_id, label);
    store_bool(&mut attrs, CKA_LOCAL, false);
    store_ulong(&mut attrs, CKA_KEY_GEN_MECHANISM, CKM_UNAVAILABLE_INFORMATION);
    compute_kcv(&mut attrs);
    Ok(alloc_in_session_slot(session, attrs))
}

/// Generate a Generic-Secret key (HMAC etc.). `bits` ∈ [8, 4096] in
/// multiples of 8 (engine permits 1..=512 bytes).
pub fn generate_generic_secret(
    _session: u32,
    bits: u32,
    cka_id: &[u8],
    label: &str,
) -> Result<u32, CkRv> {
    if !(8..=4096).contains(&bits) || bits % 8 != 0 {
        return Err(CKR_ARGUMENTS_BAD);
    }
    let bytes = (bits / 8) as usize;
    let mut key = vec![0u8; bytes];
    getrandom::getrandom(&mut key).map_err(|_| CKR_FUNCTION_FAILED)?;
    let attrs = build_generic_secret_attrs(key, bytes as u32, cka_id, label);
    Ok(alloc_in_session_slot(_session, finalize_secret_attrs(attrs)))
}

/// ECDSA curve identifier used by [`generate_ecdsa_keypair`]. v0.1
/// covers the four curves the engine supports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EccCurve {
    P256,
    P384,
    P521,
    Secp256K1,
}

// ── FrodoKEM (BSI TR-02102-1 §2.4.1) ─────────────────────────────────────────

/// Maps a `CKP_FRODOKEM_*` parameter set to the `frodo-kem` crate's
/// `Algorithm` enum. Only the 6 standard variants are exposed — eFrodoKEM
/// (ephemeral/one-time-use) intentionally is not (see the FrodoKEM /
/// Classic-McEliece / HQC implementation plan, Phase 0.8: there is nothing
/// to cross-validate the ephemeral variants against).
pub(crate) fn frodokem_algorithm(parameter_set: u32) -> Result<frodo_kem::Algorithm, CkRv> {
    use frodo_kem::Algorithm;
    match parameter_set {
        CKP_FRODOKEM_640_AES => Ok(Algorithm::FrodoKem640Aes),
        CKP_FRODOKEM_640_SHAKE => Ok(Algorithm::FrodoKem640Shake),
        CKP_FRODOKEM_976_AES => Ok(Algorithm::FrodoKem976Aes),
        CKP_FRODOKEM_976_SHAKE => Ok(Algorithm::FrodoKem976Shake),
        CKP_FRODOKEM_1344_AES => Ok(Algorithm::FrodoKem1344Aes),
        CKP_FRODOKEM_1344_SHAKE => Ok(Algorithm::FrodoKem1344Shake),
        _ => Err(CKR_ARGUMENTS_BAD),
    }
}

/// Generate a FrodoKEM keypair. `parameter_set` ∈ the 6 `CKP_FRODOKEM_*`
/// standard variants. Returns `(public_handle, private_handle)`.
///
/// RNG note: `frodo-kem` requires `rand_core 0.10`'s `CryptoRng`, not the
/// engine's usual `rand 0.8`/`rand::rngs::OsRng` — incompatible major
/// versions of the same trait. Uses `getrandom_0_4::SysRng` (already a
/// engine dependency for the wasm32 entropy source) wrapped in
/// `UnwrapErr`, exactly as `frodo-kem`'s own documented usage shows.
pub fn generate_frodokem_keypair(
    _session: u32,
    parameter_set: u32,
    cka_id: &[u8],
    label: &str,
) -> Result<(u32, u32), CkRv> {
    use getrandom_0_4::rand_core::UnwrapErr;
    use getrandom_0_4::SysRng;

    let alg = frodokem_algorithm(parameter_set)?;

    let mut pub_attrs: Attributes = HashMap::new();
    let mut prv_attrs: Attributes = HashMap::new();

    set_common_pub_attrs(&mut pub_attrs, parameter_set, ALGO_FRODOKEM, CKK_PQCTODAY_FRODOKEM, CKM_PQCTODAY_FRODOKEM_KEY_PAIR_GEN);
    set_common_prv_attrs(&mut prv_attrs, parameter_set, ALGO_FRODOKEM, CKK_PQCTODAY_FRODOKEM, CKM_PQCTODAY_FRODOKEM_KEY_PAIR_GEN);
    // FrodoKEM-specific flags: encapsulate / decapsulate, NOT sign / verify.
    store_bool(&mut pub_attrs, CKA_VERIFY, false);
    store_bool(&mut pub_attrs, CKA_ENCAPSULATE, true);
    store_bool(&mut prv_attrs, CKA_SIGN, false);
    store_bool(&mut prv_attrs, CKA_DECAPSULATE, true);

    insert_id_and_label(&mut pub_attrs, cka_id, label);
    insert_id_and_label(&mut prv_attrs, cka_id, label);

    let mut rng = UnwrapErr(SysRng);
    let (ek, dk) = alg.generate_keypair(&mut rng);
    pub_attrs.insert(CKA_VALUE, ek.value().to_vec());
    prv_attrs.insert(CKA_VALUE, dk.value().to_vec());

    finalize_and_register(_session, pub_attrs, prv_attrs)
}

// ── Classic McEliece (BSI TR-02102-1 §2.4.2) ─────────────────────────────────

/// Generate a Classic McEliece keypair. Scoped to `mceliece6688128` only
/// (see implementation plan Phase 0.5 — `classic-mceliece-rust` can only
/// have one parameter-set feature compiled in at a time); `parameter_set`
/// MUST be `CKP_CLASSIC_MCELIECE_6688128`. Returns `(public_handle,
/// private_handle)`.
///
/// Unlike FrodoKEM, `classic-mceliece-rust` uses `rand 0.8`'s
/// `CryptoRng`/`RngCore` (confirmed against its own `Cargo.toml`) — the
/// same version the rest of this engine already uses, so
/// `rand::rngs::OsRng` works directly here.
pub fn generate_classic_mceliece_keypair(
    _session: u32,
    parameter_set: u32,
    cka_id: &[u8],
    label: &str,
) -> Result<(u32, u32), CkRv> {
    if parameter_set != CKP_CLASSIC_MCELIECE_6688128 {
        return Err(CKR_ARGUMENTS_BAD);
    }

    let mut pub_attrs: Attributes = HashMap::new();
    let mut prv_attrs: Attributes = HashMap::new();

    set_common_pub_attrs(&mut pub_attrs, parameter_set, ALGO_CLASSIC_MCELIECE, CKK_PQCTODAY_CLASSIC_MCELIECE, CKM_PQCTODAY_CLASSIC_MCELIECE_KEY_PAIR_GEN);
    set_common_prv_attrs(&mut prv_attrs, parameter_set, ALGO_CLASSIC_MCELIECE, CKK_PQCTODAY_CLASSIC_MCELIECE, CKM_PQCTODAY_CLASSIC_MCELIECE_KEY_PAIR_GEN);
    store_bool(&mut pub_attrs, CKA_VERIFY, false);
    store_bool(&mut pub_attrs, CKA_ENCAPSULATE, true);
    store_bool(&mut prv_attrs, CKA_SIGN, false);
    store_bool(&mut prv_attrs, CKA_DECAPSULATE, true);

    insert_id_and_label(&mut pub_attrs, cka_id, label);
    insert_id_and_label(&mut prv_attrs, cka_id, label);

    let mut rng = rand::rngs::OsRng;
    let (pk, sk) = classic_mceliece_rust::keypair_boxed(&mut rng);
    pub_attrs.insert(CKA_VALUE, pk.as_ref().to_vec());
    prv_attrs.insert(CKA_VALUE, sk.as_ref().to_vec());

    finalize_and_register(_session, pub_attrs, prv_attrs)
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Shared public-key attribute defaults — matches the
/// `ffi::C_GenerateKeyPair` body for all three PQC families.
fn set_common_pub_attrs(
    attrs: &mut Attributes,
    parameter_set: u32,
    algo_family: u32,
    key_type: u32,
    keygen_mechanism: u32,
) {
    store_param_set(attrs, parameter_set);
    store_algo_family(attrs, algo_family);
    store_ulong(attrs, CKA_CLASS, CKO_PUBLIC_KEY);
    store_ulong(attrs, CKA_KEY_TYPE, key_type);
    store_ulong(attrs, CKA_PARAMETER_SET, parameter_set);
    store_ulong(attrs, CKA_KEY_GEN_MECHANISM, keygen_mechanism);
    store_bool(attrs, CKA_TOKEN, false);
    store_bool(attrs, CKA_PRIVATE, false);
    store_bool(attrs, CKA_ENCRYPT, false);
    store_bool(attrs, CKA_WRAP, false);
    store_bool(attrs, CKA_DERIVE, false);
    store_bool(attrs, CKA_LOCAL, true);
}

fn set_common_prv_attrs(
    attrs: &mut Attributes,
    parameter_set: u32,
    algo_family: u32,
    key_type: u32,
    keygen_mechanism: u32,
) {
    store_param_set(attrs, parameter_set);
    store_algo_family(attrs, algo_family);
    store_ulong(attrs, CKA_CLASS, CKO_PRIVATE_KEY);
    store_ulong(attrs, CKA_KEY_TYPE, key_type);
    store_ulong(attrs, CKA_PARAMETER_SET, parameter_set);
    store_ulong(attrs, CKA_KEY_GEN_MECHANISM, keygen_mechanism);
    store_bool(attrs, CKA_TOKEN, false);
    store_bool(attrs, CKA_PRIVATE, true);
    store_bool(attrs, CKA_SENSITIVE, true);
    store_bool(attrs, CKA_EXTRACTABLE, false);
    store_bool(attrs, CKA_DECRYPT, false);
    store_bool(attrs, CKA_UNWRAP, false);
    store_bool(attrs, CKA_DERIVE, false);
    store_bool(attrs, CKA_LOCAL, true);
}

/// Flip a freshly-built private-key attribute set to be exportable
/// (`CKA_SENSITIVE=FALSE`, `CKA_EXTRACTABLE=TRUE`) when `extractable` is
/// set. Applied at creation time — the PKCS#11 v3.2 §4.9/§4.10 one-way
/// policy (set_attribute only allows SENSITIVE FALSE→TRUE and EXTRACTABLE
/// TRUE→FALSE) forbids relaxing these after the object exists, so callers
/// that need an exportable key MUST request it here. No-op when false, so
/// the secure default (sensitive, non-extractable) is preserved.
fn apply_extractable_override(attrs: &mut Attributes, extractable: bool) {
    if extractable {
        store_bool(attrs, CKA_SENSITIVE, false);
        store_bool(attrs, CKA_EXTRACTABLE, true);
    }
}

/// Shared ECDSA public-key attribute defaults — mirrors `ffi::C_GenerateKeyPair @
/// CKM_EC_KEY_PAIR_GEN`. CKA_VERIFY=true, CKA_ENCRYPT/WRAP/DERIVE=false.
fn set_common_ec_pub_attrs(attrs: &mut Attributes) {
    store_ulong(attrs, CKA_CLASS, CKO_PUBLIC_KEY);
    store_ulong(attrs, CKA_KEY_TYPE, CKK_EC);
    store_ulong(attrs, CKA_KEY_GEN_MECHANISM, CKM_EC_KEY_PAIR_GEN);
    store_bool(attrs, CKA_TOKEN, false);
    store_bool(attrs, CKA_PRIVATE, false);
    store_bool(attrs, CKA_ENCRYPT, false);
    store_bool(attrs, CKA_VERIFY, true);
    store_bool(attrs, CKA_WRAP, false);
    store_bool(attrs, CKA_DERIVE, false);
    store_bool(attrs, CKA_LOCAL, true);
}

/// Shared ECDSA private-key attribute defaults. CKA_SIGN=true,
/// CKA_DERIVE=true (supports ECDH), CKA_SENSITIVE+EXTRACTABLE per FIPS.
fn set_common_ec_prv_attrs(attrs: &mut Attributes) {
    store_ulong(attrs, CKA_CLASS, CKO_PRIVATE_KEY);
    store_ulong(attrs, CKA_KEY_TYPE, CKK_EC);
    store_ulong(attrs, CKA_KEY_GEN_MECHANISM, CKM_EC_KEY_PAIR_GEN);
    store_bool(attrs, CKA_TOKEN, false);
    store_bool(attrs, CKA_PRIVATE, true);
    store_bool(attrs, CKA_SENSITIVE, true);
    store_bool(attrs, CKA_EXTRACTABLE, false);
    store_bool(attrs, CKA_DECRYPT, false);
    store_bool(attrs, CKA_SIGN, true);
    store_bool(attrs, CKA_UNWRAP, false);
    store_bool(attrs, CKA_DERIVE, true); // ECDH-capable per PKCS#11 v3.2 §2.3
    store_bool(attrs, CKA_LOCAL, true);
}

/// Build the attribute map for an AES secret key. Mirrors
/// `ffi::C_GenerateKey @ CKM_AES_KEY_GEN`.
fn build_aes_attrs(key: Vec<u8>, key_len_bytes: u32, cka_id: &[u8], label: &str) -> Attributes {
    let mut attrs: Attributes = HashMap::new();
    attrs.insert(CKA_VALUE, key);
    store_ulong(&mut attrs, CKA_CLASS, CKO_SECRET_KEY);
    store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_AES);
    store_ulong(&mut attrs, CKA_VALUE_LEN, key_len_bytes);
    store_ulong(&mut attrs, CKA_KEY_GEN_MECHANISM, CKM_AES_KEY_GEN);
    store_bool(&mut attrs, CKA_TOKEN, false);
    store_bool(&mut attrs, CKA_PRIVATE, false);
    // Exportable by default: KMIP Get/Export reads CKA_VALUE through the
    // native sensitivity gate (SENSITIVE || !EXTRACTABLE blocks). A KMIP
    // Sensitive attribute flips these at registration time.
    store_bool(&mut attrs, CKA_SENSITIVE, false);
    store_bool(&mut attrs, CKA_EXTRACTABLE, true);
    store_bool(&mut attrs, CKA_ENCRYPT, true);
    store_bool(&mut attrs, CKA_DECRYPT, true);
    store_bool(&mut attrs, CKA_WRAP, true);
    store_bool(&mut attrs, CKA_UNWRAP, true);
    store_bool(&mut attrs, CKA_SIGN, false);
    store_bool(&mut attrs, CKA_VERIFY, false);
    store_bool(&mut attrs, CKA_DERIVE, false);
    store_bool(&mut attrs, CKA_LOCAL, true);
    insert_id_and_label(&mut attrs, cka_id, label);
    attrs
}

/// Build the attribute map for a Generic-Secret key (HMAC). Mirrors
/// `ffi::C_GenerateKey @ CKM_GENERIC_SECRET_KEY_GEN`.
pub(crate) fn build_generic_secret_attrs(
    key: Vec<u8>,
    key_len_bytes: u32,
    cka_id: &[u8],
    label: &str,
) -> Attributes {
    let mut attrs: Attributes = HashMap::new();
    attrs.insert(CKA_VALUE, key);
    store_ulong(&mut attrs, CKA_CLASS, CKO_SECRET_KEY);
    store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_GENERIC_SECRET);
    store_ulong(&mut attrs, CKA_VALUE_LEN, key_len_bytes);
    store_ulong(&mut attrs, CKA_KEY_GEN_MECHANISM, CKM_GENERIC_SECRET_KEY_GEN);
    store_bool(&mut attrs, CKA_TOKEN, false);
    // Exportable by default: KMIP Get/Export reads CKA_VALUE through the
    // native sensitivity gate (SENSITIVE || !EXTRACTABLE blocks). A KMIP
    // Sensitive attribute flips these at registration time.
    store_bool(&mut attrs, CKA_SENSITIVE, false);
    store_bool(&mut attrs, CKA_EXTRACTABLE, true);
    store_bool(&mut attrs, CKA_ENCRYPT, false);
    store_bool(&mut attrs, CKA_DECRYPT, false);
    store_bool(&mut attrs, CKA_WRAP, false);
    store_bool(&mut attrs, CKA_UNWRAP, false);
    store_bool(&mut attrs, CKA_SIGN, true); // HMAC signing
    store_bool(&mut attrs, CKA_VERIFY, true);
    store_bool(&mut attrs, CKA_DERIVE, false);
    store_bool(&mut attrs, CKA_LOCAL, true);
    insert_id_and_label(&mut attrs, cka_id, label);
    attrs
}

/// Finalise a secret-key (AES / Generic Secret) attribute map: runs
/// `finalize_private_key_attrs` (sets CKA_ALWAYS_SENSITIVE +
/// CKA_NEVER_EXTRACTABLE) + `compute_kcv`.
fn finalize_secret_attrs(mut attrs: Attributes) -> Attributes {
    finalize_private_key_attrs(&mut attrs);
    compute_kcv(&mut attrs);
    attrs
}

/// FIPS 204 §5 parameter-set table: `CKP_ML_DSA_*` → `(sk_len, pk_len)`.
/// Lengths come from the `fips204` crate's per-variant constants — the
/// same source `generate_ml_dsa_keypair` serializes from.
fn ml_dsa_key_lens(parameter_set: u32) -> Option<(usize, usize)> {
    match parameter_set {
        CKP_ML_DSA_44 => Some((fips204::ml_dsa_44::SK_LEN, fips204::ml_dsa_44::PK_LEN)),
        CKP_ML_DSA_65 => Some((fips204::ml_dsa_65::SK_LEN, fips204::ml_dsa_65::PK_LEN)),
        CKP_ML_DSA_87 => Some((fips204::ml_dsa_87::SK_LEN, fips204::ml_dsa_87::PK_LEN)),
        _ => None,
    }
}

/// FIPS 203 §7 parameter-set table: `CKP_ML_KEM_*` → `(dk_len, ek_len)`.
/// Derived from the `ml-kem` crate's encoded sizes (512: 1632/800,
/// 768: 2400/1184, 1024: 3168/1568) — same source keygen serializes from.
fn ml_kem_key_lens(parameter_set: u32) -> Option<(usize, usize)> {
    use ml_kem::array::typenum::Unsigned;
    use ml_kem::{EncodedSizeUser, KemCore};
    macro_rules! lens {
        ($k:ty) => {
            Some((
                <<<$k as KemCore>::DecapsulationKey as EncodedSizeUser>::EncodedSize as Unsigned>::USIZE,
                <<<$k as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize as Unsigned>::USIZE,
            ))
        };
    }
    match parameter_set {
        CKP_ML_KEM_512 => lens!(ml_kem::MlKem512),
        CKP_ML_KEM_768 => lens!(ml_kem::MlKem768),
        CKP_ML_KEM_1024 => lens!(ml_kem::MlKem1024),
        _ => None,
    }
}

/// FIPS 205 §9.1 parameter-set table: `CKP_SLH_DSA_*` → `(sk_len, pk_len)`
/// = `(4n, 2n)` for n = 16 / 24 / 32. Taken from the `fips205` crate's
/// per-variant `SK_LEN` / `PK_LEN` — same source keygen serializes from.
fn slh_dsa_key_lens(parameter_set: u32) -> Option<(usize, usize)> {
    macro_rules! lens {
        ($m:ident) => {
            Some((fips205::$m::SK_LEN, fips205::$m::PK_LEN))
        };
    }
    match parameter_set {
        CKP_SLH_DSA_SHA2_128S => lens!(slh_dsa_sha2_128s),
        CKP_SLH_DSA_SHAKE_128S => lens!(slh_dsa_shake_128s),
        CKP_SLH_DSA_SHA2_128F => lens!(slh_dsa_sha2_128f),
        CKP_SLH_DSA_SHAKE_128F => lens!(slh_dsa_shake_128f),
        CKP_SLH_DSA_SHA2_192S => lens!(slh_dsa_sha2_192s),
        CKP_SLH_DSA_SHAKE_192S => lens!(slh_dsa_shake_192s),
        CKP_SLH_DSA_SHA2_192F => lens!(slh_dsa_sha2_192f),
        CKP_SLH_DSA_SHAKE_192F => lens!(slh_dsa_shake_192f),
        CKP_SLH_DSA_SHA2_256S => lens!(slh_dsa_sha2_256s),
        CKP_SLH_DSA_SHAKE_256S => lens!(slh_dsa_shake_256s),
        CKP_SLH_DSA_SHA2_256F => lens!(slh_dsa_sha2_256f),
        CKP_SLH_DSA_SHAKE_256F => lens!(slh_dsa_shake_256f),
        _ => None,
    }
}

/// Structural import-time validation for ML-DSA key material: run the
/// same `fips204` `try_from_bytes` deserialization the sign/verify
/// handlers perform at use time, so undecodable material fails at
/// import with `CKR_ATTRIBUTE_VALUE_INVALID` instead of at first use.
/// Caller has already length-checked `bytes`.
fn validate_ml_dsa_key(parameter_set: u32, bytes: &[u8], private: bool) -> Result<(), CkRv> {
    use fips204::traits::SerDes;
    macro_rules! chk {
        ($m:ident) => {{
            if private {
                let arr: [u8; fips204::$m::SK_LEN] =
                    bytes.try_into().map_err(|_| CKR_ATTRIBUTE_VALUE_INVALID)?;
                fips204::$m::PrivateKey::try_from_bytes(arr)
                    .map(|_| ())
                    .map_err(|_| CKR_ATTRIBUTE_VALUE_INVALID)
            } else {
                let arr: [u8; fips204::$m::PK_LEN] =
                    bytes.try_into().map_err(|_| CKR_ATTRIBUTE_VALUE_INVALID)?;
                fips204::$m::PublicKey::try_from_bytes(arr)
                    .map(|_| ())
                    .map_err(|_| CKR_ATTRIBUTE_VALUE_INVALID)
            }
        }};
    }
    match parameter_set {
        CKP_ML_DSA_44 => chk!(ml_dsa_44),
        CKP_ML_DSA_65 => chk!(ml_dsa_65),
        CKP_ML_DSA_87 => chk!(ml_dsa_87),
        _ => Err(CKR_ARGUMENTS_BAD),
    }
}

/// Structural import-time validation for SLH-DSA key material via the
/// `fips205` `try_from_bytes` deserialization (mirrors the use-time
/// handler path). Caller has already length-checked `bytes`.
fn validate_slh_dsa_key(parameter_set: u32, bytes: &[u8], private: bool) -> Result<(), CkRv> {
    use fips205::traits::SerDes;
    macro_rules! chk {
        ($m:ident) => {{
            if private {
                let arr: [u8; fips205::$m::SK_LEN] =
                    bytes.try_into().map_err(|_| CKR_ATTRIBUTE_VALUE_INVALID)?;
                fips205::$m::PrivateKey::try_from_bytes(&arr)
                    .map(|_| ())
                    .map_err(|_| CKR_ATTRIBUTE_VALUE_INVALID)
            } else {
                let arr: [u8; fips205::$m::PK_LEN] =
                    bytes.try_into().map_err(|_| CKR_ATTRIBUTE_VALUE_INVALID)?;
                fips205::$m::PublicKey::try_from_bytes(&arr)
                    .map(|_| ())
                    .map_err(|_| CKR_ATTRIBUTE_VALUE_INVALID)
            }
        }};
    }
    match parameter_set {
        CKP_SLH_DSA_SHA2_128S => chk!(slh_dsa_sha2_128s),
        CKP_SLH_DSA_SHAKE_128S => chk!(slh_dsa_shake_128s),
        CKP_SLH_DSA_SHA2_128F => chk!(slh_dsa_sha2_128f),
        CKP_SLH_DSA_SHAKE_128F => chk!(slh_dsa_shake_128f),
        CKP_SLH_DSA_SHA2_192S => chk!(slh_dsa_sha2_192s),
        CKP_SLH_DSA_SHAKE_192S => chk!(slh_dsa_shake_192s),
        CKP_SLH_DSA_SHA2_192F => chk!(slh_dsa_sha2_192f),
        CKP_SLH_DSA_SHAKE_192F => chk!(slh_dsa_shake_192f),
        CKP_SLH_DSA_SHA2_256S => chk!(slh_dsa_sha2_256s),
        CKP_SLH_DSA_SHAKE_256S => chk!(slh_dsa_shake_256s),
        CKP_SLH_DSA_SHA2_256F => chk!(slh_dsa_sha2_256f),
        CKP_SLH_DSA_SHAKE_256F => chk!(slh_dsa_shake_256f),
        _ => Err(CKR_ARGUMENTS_BAD),
    }
}

/// Build + allocate an imported PQC **private**-key object: keygen
/// attribute layout (`set_common_prv_attrs` — `CKA_SENSITIVE=TRUE`,
/// `CKA_EXTRACTABLE=FALSE`) with imported-provenance overrides per
/// PKCS#11 v3.2 §4.3/§4.9/§4.10. Must NOT call
/// `finalize_private_key_attrs` (that would derive ALWAYS_SENSITIVE /
/// NEVER_EXTRACTABLE as if the key had been born inside the token).
#[allow(clippy::too_many_arguments)]
fn register_pqc_private(
    session: u32,
    parameter_set: u32,
    algo_family: u32,
    key_type: u32,
    keygen_mechanism: u32,
    can_sign: bool,
    can_decapsulate: bool,
    key_bytes: &[u8],
    cka_id: &[u8],
    label: &str,
) -> u32 {
    let mut attrs: Attributes = HashMap::new();
    set_common_prv_attrs(&mut attrs, parameter_set, algo_family, key_type, keygen_mechanism);
    store_bool(&mut attrs, CKA_SIGN, can_sign);
    store_bool(&mut attrs, CKA_DECAPSULATE, can_decapsulate);
    attrs.insert(CKA_VALUE, key_bytes.to_vec());
    insert_id_and_label(&mut attrs, cka_id, label);
    // Imported provenance — overrides the generated-key values set above.
    store_bool(&mut attrs, CKA_LOCAL, false);
    store_ulong(&mut attrs, CKA_KEY_GEN_MECHANISM, CKM_UNAVAILABLE_INFORMATION);
    store_bool(&mut attrs, CKA_ALWAYS_SENSITIVE, false);
    store_bool(&mut attrs, CKA_NEVER_EXTRACTABLE, false);
    compute_kcv(&mut attrs);
    alloc_in_session_slot(session, attrs)
}

/// Build + allocate an imported PQC **public**-key object: keygen
/// attribute layout + SPKI, with imported-provenance overrides
/// (`CKA_LOCAL=FALSE`, `CKA_KEY_GEN_MECHANISM=CK_UNAVAILABLE_INFORMATION`).
#[allow(clippy::too_many_arguments)]
fn register_pqc_public(
    session: u32,
    parameter_set: u32,
    algo_family: u32,
    key_type: u32,
    keygen_mechanism: u32,
    can_verify: bool,
    can_encapsulate: bool,
    key_bytes: &[u8],
    spki: Vec<u8>,
    cka_id: &[u8],
    label: &str,
) -> u32 {
    let mut attrs: Attributes = HashMap::new();
    set_common_pub_attrs(&mut attrs, parameter_set, algo_family, key_type, keygen_mechanism);
    store_bool(&mut attrs, CKA_VERIFY, can_verify);
    store_bool(&mut attrs, CKA_ENCAPSULATE, can_encapsulate);
    attrs.insert(CKA_VALUE, key_bytes.to_vec());
    if !spki.is_empty() {
        attrs.insert(CKA_PUBLIC_KEY_INFO, spki);
    }
    insert_id_and_label(&mut attrs, cka_id, label);
    // Imported provenance — overrides the generated-key values set above.
    store_bool(&mut attrs, CKA_LOCAL, false);
    store_ulong(&mut attrs, CKA_KEY_GEN_MECHANISM, CKM_UNAVAILABLE_INFORMATION);
    compute_kcv(&mut attrs);
    alloc_in_session_slot(session, attrs)
}

/// T3 (multi-slot scoping) — allocate an object stamped with the creating
/// session's slot id so token-scoped enumeration (`C_FindObjects`,
/// [`super::object::find_all_by_cka_id`]) attributes it to the right token.
/// An unknown session stamps slot 0, the primary token, which preserves the
/// single-slot KMIP/wasm behavior.
pub(crate) fn alloc_in_session_slot(session: u32, mut attrs: Attributes) -> u32 {
    crate::state::tag_object_slot(session, &mut attrs);
    allocate_handle(attrs)
}

pub(crate) fn insert_id_and_label(attrs: &mut Attributes, cka_id: &[u8], label: &str) {
    if !cka_id.is_empty() {
        attrs.insert(CKA_ID, cka_id.to_vec());
    }
    if !label.is_empty() {
        attrs.insert(CKA_LABEL, label.as_bytes().to_vec());
    }
}

/// Finalise attribute maps (private-key flags + KCV) and allocate
/// engine object handles. Mirrors the tail of each `ffi::C_GenerateKeyPair`
/// arm.
fn finalize_and_register(
    session: u32,
    mut pub_attrs: Attributes,
    mut prv_attrs: Attributes,
) -> Result<(u32, u32), CkRv> {
    finalize_private_key_attrs(&mut prv_attrs);
    compute_kcv(&mut pub_attrs);
    compute_kcv(&mut prv_attrs);
    let pub_h = alloc_in_session_slot(session, pub_attrs);
    let prv_h = alloc_in_session_slot(session, prv_attrs);
    Ok((pub_h, prv_h))
}

/// SLH-DSA keygen — wraps the `fips205` per-variant calls with the same
/// shape so the per-variant match stays a single line. `$m` is the
/// `fips205` parameter-set module; `$seed` is `Option<&[u8]>` — `Some`
/// runs FIPS 205 Algorithm 18 `slh_keygen_internal(SK.seed, SK.prf,
/// PK.seed)` deterministically from a `3n`-byte seed (wrong length →
/// `CKR_ATTRIBUTE_VALUE_INVALID`), `None` keeps the OsRng path
/// (Algorithm 21). `$pub_attrs` / `$prv_attrs` are the maps to populate
/// with `CKA_VALUE`. Mirrors the C-ABI `crate::slh_dsa_keygen!` macro.
macro_rules! slh_keygen {
    ($m:ident, $seed:expr, $pub_attrs:expr, $prv_attrs:expr) => {{
        use fips205::traits::{KeyGen, SerDes};
        const N: usize = fips205::$m::N;
        match $seed {
            Some(s) => {
                if s.len() != 3 * N {
                    return Err(CKR_ATTRIBUTE_VALUE_INVALID);
                }
                // FIPS 205 §9.1 — CKA_SEED = SK.seed ‖ SK.prf ‖ PK.seed.
                let (vk, sk) = fips205::$m::KG::keygen_with_seeds::<N>(
                    s[..N].try_into().expect("length checked"),
                    s[N..2 * N].try_into().expect("length checked"),
                    s[2 * N..].try_into().expect("length checked"),
                );
                $pub_attrs.insert(CKA_VALUE, SerDes::into_bytes(vk).to_vec());
                $prv_attrs.insert(CKA_VALUE, SerDes::into_bytes(sk).to_vec());
            }
            None => match fips205::$m::try_keygen_with_rng(&mut rand::rngs::OsRng) {
                Ok((vk, sk)) => {
                    $pub_attrs.insert(CKA_VALUE, SerDes::into_bytes(vk).to_vec());
                    $prv_attrs.insert(CKA_VALUE, SerDes::into_bytes(sk).to_vec());
                }
                Err(_) => return Err(CKR_FUNCTION_FAILED),
            },
        }
    }};
}
use slh_keygen;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::session::{bootstrap_default_token, close_session, finalize, init};
    use crate::state::get_object_value;
    use crate::native::test_lock;

    fn fresh_session() -> u32 {
        let _ = finalize();
        init().unwrap();
        bootstrap_default_token(0, "so", "user", "pqctoday-test").unwrap()
    }

    // ── register_ecdsa_public_key / register_ed25519_public_key ─────────
    //
    // Real round-trip KATs, not just "does it not panic": generate a
    // keypair NATIVELY, sign with the private half, export the public
    // half's REAL CKA_PUBLIC_KEY_INFO (produced by generate_*_keypair —
    // this crate's own encode side), import it back as an INDEPENDENT
    // object via the new register_* function (the decode side), then
    // verify the ORIGINAL signature against the RE-IMPORTED handle. This
    // is the exact shape the pure-Rust Certify/Validate port needs: an
    // externally-supplied SPKI (from a CSR or a chain certificate) must
    // verify a signature made by whatever produced that SPKI, regardless
    // of which engine instance minted it.
    use crate::state::get_object_attr_bytes;
    use crate::constants::CKA_PUBLIC_KEY_INFO;

    #[test]
    fn register_ecdsa_public_key_round_trips_p256_p384_p521() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let msg = b"pure-rust cert-ops KAT";

        for (curve, mech) in [
            (EccCurve::P256, CKM_ECDSA_SHA256),
            (EccCurve::P384, CKM_ECDSA_SHA384),
            (EccCurve::P521, CKM_ECDSA_SHA512),
        ] {
            let (pub_h, prv_h) =
                generate_ecdsa_keypair(session, curve, b"\x01", "ecdsa-kat").unwrap();
            let sig = crate::native::sign::sign(session, prv_h, mech, msg).unwrap();
            let spki = get_object_attr_bytes(pub_h, CKA_PUBLIC_KEY_INFO)
                .expect("generate_ecdsa_keypair must set CKA_PUBLIC_KEY_INFO");

            let reimported = register_ecdsa_public_key(session, &spki, b"\x02", "reimport")
                .unwrap_or_else(|e| panic!("{curve:?}: register failed: {e:x}"));
            assert_ne!(reimported, pub_h, "must be an independent object");

            let ok = crate::native::sign::verify(session, reimported, mech, msg, &sig)
                .unwrap_or_else(|e| panic!("{curve:?}: verify errored: {e:x}"));
            assert!(ok, "{curve:?}: signature must verify against the re-imported key");

            // Negative: a corrupted signature must fail, not silently pass.
            let mut bad_sig = sig.clone();
            let last = bad_sig.len() - 1;
            bad_sig[last] ^= 0xff;
            let bad_ok = crate::native::sign::verify(session, reimported, mech, msg, &bad_sig)
                .unwrap_or_else(|e| panic!("{curve:?}: verify(bad sig) errored: {e:x}"));
            assert!(!bad_ok, "{curve:?}: corrupted signature must NOT verify");
        }
        close_session(session).unwrap();
    }

    #[test]
    fn register_ed25519_public_key_round_trips() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let msg = b"pure-rust cert-ops KAT ed25519";

        let (pub_h, prv_h) = generate_ed25519_keypair(session, b"\x01", "ed25519-kat").unwrap();
        let sig = crate::native::sign::sign(session, prv_h, CKM_EDDSA, msg).unwrap();
        let spki = get_object_attr_bytes(pub_h, CKA_PUBLIC_KEY_INFO)
            .expect("generate_ed25519_keypair must set CKA_PUBLIC_KEY_INFO");

        let reimported = register_ed25519_public_key(session, &spki, b"\x02", "reimport")
            .expect("register_ed25519_public_key must accept its own generator's SPKI");
        assert_ne!(reimported, pub_h);

        let ok = crate::native::sign::verify(session, reimported, CKM_EDDSA, msg, &sig)
            .expect("verify must not error");
        assert!(ok, "signature must verify against the re-imported key");

        let mut bad_sig = sig.clone();
        let last = bad_sig.len() - 1;
        bad_sig[last] ^= 0xff;
        let bad_ok = crate::native::sign::verify(session, reimported, CKM_EDDSA, msg, &bad_sig)
            .expect("verify must not error");
        assert!(!bad_ok, "corrupted signature must NOT verify");
        close_session(session).unwrap();
    }

    #[test]
    fn register_ecdsa_public_key_rejects_malformed_and_wrong_algorithm_der() {
        let _guard = test_lock::acquire();
        let session = fresh_session();

        assert!(register_ecdsa_public_key(session, &[], b"\x01", "empty").is_err());
        assert!(register_ecdsa_public_key(session, &[0x30, 0x00], b"\x01", "empty-seq").is_err());

        // A genuine Ed25519 SPKI must be rejected by the ECDSA importer —
        // and vice versa — proving the OID check actually discriminates,
        // not just "parses as *some* valid SPKI".
        let (ed_pub, _) = generate_ed25519_keypair(session, b"\x01", "ed-for-negative").unwrap();
        let ed_spki = get_object_attr_bytes(ed_pub, CKA_PUBLIC_KEY_INFO).unwrap();
        assert!(register_ecdsa_public_key(session, &ed_spki, b"\x02", "wrong-alg").is_err());

        let (ec_pub, _) =
            generate_ecdsa_keypair(session, EccCurve::P256, b"\x01", "ec-for-negative").unwrap();
        let ec_spki = get_object_attr_bytes(ec_pub, CKA_PUBLIC_KEY_INFO).unwrap();
        assert!(register_ed25519_public_key(session, &ec_spki, b"\x02", "wrong-alg").is_err());

        close_session(session).unwrap();
    }

    /// `register_ecdsa_public_key` only recognizes P-256/P-384/P-521 (the
    /// three curves `EccCurve` maps to a `CURVE_*` PKCS#11 param set for
    /// import). secp256k1 is a real, generateable curve in this engine
    /// (`generate_ecdsa_keypair(.., EccCurve::Secp256K1, ..)`), so this
    /// uses a REAL secp256k1 SPKI (this engine's own encoder, not a
    /// hand-spliced fixture) to prove the curve check genuinely
    /// discriminates rather than accepting anything `id-ecPublicKey`.
    #[test]
    fn register_ecdsa_public_key_rejects_unrecognized_curve() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, _) =
            generate_ecdsa_keypair(session, EccCurve::Secp256K1, b"\x01", "k1-src").unwrap();
        let spki = get_object_attr_bytes(pub_h, CKA_PUBLIC_KEY_INFO)
            .expect("generate_ecdsa_keypair must set CKA_PUBLIC_KEY_INFO for secp256k1 too");

        assert!(
            register_ecdsa_public_key(session, &spki, b"\x02", "bad-curve").is_err(),
            "secp256k1 is a real id-ecPublicKey SPKI but not one of the recognized curves"
        );
        close_session(session).unwrap();
    }

    /// ML-KEM-768 keygen produces a valid keypair. FIPS 203 §7.4 — the
    /// encapsulation key is 1184 bytes.
    #[test]
    fn ml_kem_768_keygen_produces_expected_length() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) =
            generate_ml_kem_keypair(session, CKP_ML_KEM_768, b"\x01\x02\x03", "kem-test").unwrap();
        assert!(pub_h > 0 && prv_h > 0 && pub_h != prv_h);

        let pub_value = get_object_value(pub_h).expect("public key CKA_VALUE");
        assert_eq!(pub_value.len(), 1184, "FIPS 203 §7.4 ML-KEM-768 ek = 1184 bytes");
        let prv_value = get_object_value(prv_h).expect("private key CKA_VALUE");
        assert_eq!(prv_value.len(), 2400, "FIPS 203 §7.4 ML-KEM-768 dk = 2400 bytes");

        close_session(session).unwrap();
    }

    /// ML-KEM-1024: FIPS 203 §7.4 — ek = 1568 bytes, dk = 3168 bytes.
    #[test]
    fn ml_kem_1024_keygen_produces_expected_length() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) =
            generate_ml_kem_keypair(session, CKP_ML_KEM_1024, b"\x01", "kem1024").unwrap();
        assert_eq!(get_object_value(pub_h).unwrap().len(), 1568);
        assert_eq!(get_object_value(prv_h).unwrap().len(), 3168);
        close_session(session).unwrap();
    }

    /// FrodoKEM-640-AES keygen produces a valid keypair with the sizes
    /// verified directly against `frodo-kem` v0.1.0's own
    /// `AlgorithmParams` (see mechanism_info comment in ffi.rs) — not the
    /// spec PDF, to avoid any crate/spec version mismatch.
    #[test]
    fn frodokem_640_aes_keygen_produces_expected_length() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) = generate_frodokem_keypair(
            session,
            CKP_FRODOKEM_640_AES,
            b"\x01",
            "frodo640aes-test",
        )
        .unwrap();
        assert!(pub_h > 0 && prv_h > 0 && pub_h != prv_h);
        assert_eq!(get_object_value(pub_h).unwrap().len(), 9616);
        assert_eq!(get_object_value(prv_h).unwrap().len(), 19888);
        close_session(session).unwrap();
    }

    /// FrodoKEM-1344-SHAKE (BSI's largest recommended parameter set,
    /// §2.4.1) — pk = 21520 bytes, sk = 43088 bytes.
    #[test]
    fn frodokem_1344_shake_keygen_produces_expected_length() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) = generate_frodokem_keypair(
            session,
            CKP_FRODOKEM_1344_SHAKE,
            b"\x01",
            "frodo1344shake-test",
        )
        .unwrap();
        assert_eq!(get_object_value(pub_h).unwrap().len(), 21520);
        assert_eq!(get_object_value(prv_h).unwrap().len(), 43088);
        close_session(session).unwrap();
    }

    /// Classic McEliece (mceliece6688128 — BSI's recommended Category-5
    /// pick, §2.4.2) — pk = 1,044,992 bytes, sk = 13,932 bytes, verified
    /// directly against `classic-mceliece-rust` v2.0.2's
    /// `CRYPTO_PUBLICKEYBYTES`/`CRYPTO_SECRETKEYBYTES` for this variant.
    ///
    /// `#[ignore]`: a single mceliece6688128 keygen (Goppa code generation)
    /// takes minutes in an unoptimized debug build — too slow for every CI
    /// run. Run manually with `cargo test --release -- --ignored
    /// classic_mceliece_6688128_keygen` (release mode is fast).
    #[test]
    #[ignore = "mceliece6688128 keygen is minutes-slow in debug builds — see doc comment"]
    fn classic_mceliece_6688128_keygen_produces_expected_length() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) = generate_classic_mceliece_keypair(
            session,
            CKP_CLASSIC_MCELIECE_6688128,
            b"\x01",
            "mceliece-test",
        )
        .unwrap();
        assert!(pub_h > 0 && prv_h > 0 && pub_h != prv_h);
        assert_eq!(get_object_value(pub_h).unwrap().len(), 1_044_992);
        assert_eq!(get_object_value(prv_h).unwrap().len(), 13_932);
        close_session(session).unwrap();
    }

    /// Classic McEliece rejects any parameter set other than the one
    /// scoped variant (Phase 0.5 — the crate can't compile in more than
    /// one at a time).
    #[test]
    fn classic_mceliece_rejects_wrong_parameter_set() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let result = generate_classic_mceliece_keypair(session, 0xFF, b"\x01", "bad-ps");
        assert_eq!(result.unwrap_err(), CKR_ARGUMENTS_BAD);
        close_session(session).unwrap();
    }

    /// ML-DSA-65: FIPS 204 §5 — verification key = 1952 bytes,
    /// signing key = 4032 bytes.
    #[test]
    fn ml_dsa_65_keygen_produces_expected_length() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) =
            generate_ml_dsa_keypair(session, CKP_ML_DSA_65, b"\xaa\xbb", "sig-test").unwrap();
        assert_eq!(get_object_value(pub_h).unwrap().len(), 1952, "FIPS 204 §5 ML-DSA-65 vk");
        assert_eq!(get_object_value(prv_h).unwrap().len(), 4032, "FIPS 204 §5 ML-DSA-65 sk");
        close_session(session).unwrap();
    }

    /// ML-DSA-87: FIPS 204 §5 — vk = 2592, sk = 4896.
    #[test]
    fn ml_dsa_87_keygen_produces_expected_length() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) =
            generate_ml_dsa_keypair(session, CKP_ML_DSA_87, b"\x01", "ml-dsa-87").unwrap();
        assert_eq!(get_object_value(pub_h).unwrap().len(), 2592);
        assert_eq!(get_object_value(prv_h).unwrap().len(), 4896);
        close_session(session).unwrap();
    }

    /// SLH-DSA-SHA2-128F: FIPS 205 §10 — pk = 32, sk = 64 bytes.
    #[test]
    fn slh_dsa_sha2_128f_keygen_produces_expected_length() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) = generate_slh_dsa_keypair(
            session,
            CKP_SLH_DSA_SHA2_128F,
            b"\x01",
            "slh-test",
        )
        .unwrap();
        assert_eq!(get_object_value(pub_h).unwrap().len(), 32, "FIPS 205 §10 SLH-DSA-128 pk");
        assert_eq!(get_object_value(prv_h).unwrap().len(), 64, "FIPS 205 §10 SLH-DSA-128 sk");
        close_session(session).unwrap();
    }

    /// SLH-DSA-SHA2-256S: pk = 64, sk = 128 bytes.
    #[test]
    fn slh_dsa_sha2_256s_keygen_produces_expected_length() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) = generate_slh_dsa_keypair(
            session,
            CKP_SLH_DSA_SHA2_256S,
            b"\x02",
            "slh-256",
        )
        .unwrap();
        assert_eq!(get_object_value(pub_h).unwrap().len(), 64);
        assert_eq!(get_object_value(prv_h).unwrap().len(), 128);
        close_session(session).unwrap();
    }

    /// Bad parameter set → CKR_PARAMETER_SET_NOT_SUPPORTED (PKCS#11 v3.2
    /// Table 6; was the generic CKR_ARGUMENTS_BAD before the dedicated code
    /// was added — see also `unrecognized_parameter_set_is_rejected_with_dedicated_error`).
    #[test]
    fn ml_kem_invalid_parameter_set_returns_err() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let result = generate_ml_kem_keypair(session, 0xDEADBEEF, b"\x01", "x");
        assert!(matches!(result, Err(CKR_PARAMETER_SET_NOT_SUPPORTED)));
        close_session(session).unwrap();
    }

    /// CKA_ID + CKA_LABEL are stored and retrievable.
    #[test]
    fn caller_supplied_id_and_label_are_stored() {
        use crate::state::get_object_attr_bytes;
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let cka_id = b"unique-key-id-12345";
        let label = "my-ml-dsa-key";
        let (pub_h, _) =
            generate_ml_dsa_keypair(session, CKP_ML_DSA_65, cka_id, label).unwrap();

        let stored_id = get_object_attr_bytes(pub_h, CKA_ID).expect("CKA_ID stored");
        assert_eq!(stored_id, cka_id);
        let stored_label = get_object_attr_bytes(pub_h, CKA_LABEL).expect("CKA_LABEL stored");
        assert_eq!(stored_label, label.as_bytes());

        close_session(session).unwrap();
    }

    // ── Classical ──────────────────────────────────────────────────────────

    /// RSA-2048 keygen: modulus stored as separate attribute (PKCS#11
    /// v3.2 §2.1.2), CKA_MODULUS_BITS = 2048.
    #[test]
    fn rsa_2048_keygen_stores_modulus_and_exponent() {
        use crate::state::{get_object_attr_bytes, get_object_attr_u32};
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, _prv_h) = generate_rsa_keypair(session, 2048, b"\x01", "rsa-2048").unwrap();
        let modulus = get_object_attr_bytes(pub_h, CKA_MODULUS).expect("CKA_MODULUS");
        assert!(
            modulus.len() >= 254 && modulus.len() <= 256,
            "RSA-2048 modulus byte length {}",
            modulus.len()
        );
        let exponent = get_object_attr_bytes(pub_h, CKA_PUBLIC_EXPONENT).expect("CKA_PUBLIC_EXPONENT");
        assert!(!exponent.is_empty(), "exponent stored");
        let bits = get_object_attr_u32(pub_h, CKA_MODULUS_BITS).expect("CKA_MODULUS_BITS");
        assert_eq!(bits, 2048);
        close_session(session).unwrap();
    }

    /// RSA bits out of range → CKR_ARGUMENTS_BAD.
    #[test]
    fn rsa_invalid_bits_returns_err() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        assert_eq!(
            generate_rsa_keypair(session, 1024, b"\x01", "small").unwrap_err(),
            CKR_ARGUMENTS_BAD,
        );
        assert_eq!(
            generate_rsa_keypair(session, 8192, b"\x01", "big").unwrap_err(),
            CKR_ARGUMENTS_BAD,
        );
        close_session(session).unwrap();
    }

    /// ECDSA P-256: scalar = 32 bytes, uncompressed point = 65 bytes
    /// (1 + 32 + 32).
    #[test]
    fn ecdsa_p256_keygen_produces_expected_lengths() {
        use crate::state::{get_ec_point_sec1, get_object_value};
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) =
            generate_ecdsa_keypair(session, EccCurve::P256, b"\x01", "ec-p256").unwrap();
        let sk_bytes = get_object_value(prv_h).expect("CKA_VALUE on private");
        assert_eq!(sk_bytes.len(), 32, "P-256 scalar = 32 bytes");
        let ec_point = get_ec_point_sec1(pub_h).expect("CKA_EC_POINT");
        assert_eq!(ec_point.len(), 65, "P-256 uncompressed point = 1+32+32");
        assert_eq!(ec_point[0], 0x04, "uncompressed point starts with 0x04");
        close_session(session).unwrap();
    }

    /// ECDSA P-384: scalar = 48, point = 97 bytes.
    #[test]
    fn ecdsa_p384_keygen_produces_expected_lengths() {
        use crate::state::{get_ec_point_sec1, get_object_value};
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) =
            generate_ecdsa_keypair(session, EccCurve::P384, b"\x01", "ec-p384").unwrap();
        assert_eq!(get_object_value(prv_h).unwrap().len(), 48);
        assert_eq!(get_ec_point_sec1(pub_h).unwrap().len(), 97);
        close_session(session).unwrap();
    }

    /// ECDSA P-521: scalar = 66, point = 133 bytes.
    #[test]
    fn ecdsa_p521_keygen_produces_expected_lengths() {
        use crate::state::{get_ec_point_sec1, get_object_value};
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) =
            generate_ecdsa_keypair(session, EccCurve::P521, b"\x01", "ec-p521").unwrap();
        assert_eq!(get_object_value(prv_h).unwrap().len(), 66);
        assert_eq!(get_ec_point_sec1(pub_h).unwrap().len(), 133);
        close_session(session).unwrap();
    }

    /// ECDH P-256/384/521 keygen: same point-length shape as ECDSA on the
    /// same curve (it's the same elliptic-curve math), but tagged
    /// `ALGO_ECDH_P256` (never `ALGO_ECDSA`) — the 2026-07-05 fix's whole
    /// point is that a caller who asked for `Ecdh` gets a key that is NOT
    /// silently interchangeable with an ECDSA signing key at the KMIP layer.
    #[test]
    fn ecdh_keygen_produces_expected_lengths_and_family_tag() {
        use crate::state::{get_ec_point_sec1, get_object_algo_family, get_object_param_set, get_object_value};
        let _guard = test_lock::acquire();
        let session = fresh_session();

        let (pub_h, prv_h) =
            generate_ecdh_keypair(session, EccCurve::P256, b"\x01", "ecdh-p256").unwrap();
        assert_eq!(get_object_value(prv_h).unwrap().len(), 32, "P-256 scalar");
        assert_eq!(get_ec_point_sec1(pub_h).unwrap().len(), 65, "P-256 point");
        assert_eq!(get_object_algo_family(prv_h), ALGO_ECDH_P256, "tagged ECDH, not ECDSA");
        assert_eq!(get_object_param_set(prv_h), CURVE_P256);

        let (pub_h, prv_h) =
            generate_ecdh_keypair(session, EccCurve::P384, b"\x02", "ecdh-p384").unwrap();
        assert_eq!(get_object_value(prv_h).unwrap().len(), 48, "P-384 scalar");
        assert_eq!(get_ec_point_sec1(pub_h).unwrap().len(), 97, "P-384 point");
        assert_eq!(get_object_algo_family(prv_h), ALGO_ECDH_P256);
        assert_eq!(get_object_param_set(prv_h), CURVE_P384);

        let (pub_h, prv_h) =
            generate_ecdh_keypair(session, EccCurve::P521, b"\x03", "ecdh-p521").unwrap();
        assert_eq!(get_object_value(prv_h).unwrap().len(), 66, "P-521 scalar");
        assert_eq!(get_ec_point_sec1(pub_h).unwrap().len(), 133, "P-521 point");
        assert_eq!(get_object_algo_family(prv_h), ALGO_ECDH_P256);
        assert_eq!(get_object_param_set(prv_h), CURVE_P521);

        close_session(session).unwrap();
    }

    /// Secp256K1 has no KMIP-referenced ECDH use in this stack — must be
    /// rejected, not silently produce a key.
    #[test]
    fn ecdh_keygen_rejects_secp256k1() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        assert_eq!(
            generate_ecdh_keypair(session, EccCurve::Secp256K1, b"\x01", "ecdh-k256"),
            Err(CKR_MECHANISM_INVALID)
        );
        close_session(session).unwrap();
    }

    /// Ed25519 keygen: 32-byte seed, 32-byte encoded point, tagged
    /// `ALGO_EDDSA` (never `ALGO_ECDH_P256` — Edwards signing key, not
    /// Montgomery key-agreement key, despite sharing the underlying curve).
    #[test]
    fn ed25519_keygen_produces_expected_lengths_and_family_tag() {
        use crate::state::{get_object_algo_family, get_object_attr_u32, get_object_value};
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) =
            generate_ed25519_keypair(session, b"\x01", "ed25519-1").unwrap();
        assert_eq!(get_object_value(prv_h).unwrap().len(), 32, "Ed25519 seed");
        assert_eq!(get_object_value(pub_h).unwrap().len(), 32, "Ed25519 encoded point");
        assert_eq!(get_object_algo_family(prv_h), ALGO_EDDSA, "tagged EdDSA, not ECDH/ECDSA");
        assert_eq!(get_object_attr_u32(pub_h, CKA_KEY_TYPE), Some(CKK_EC_EDWARDS));
        close_session(session).unwrap();
    }

    /// X25519 keygen: 32-byte scalar + 32-byte public point, tagged
    /// `ALGO_ECDH_X25519`, `CKK_EC_MONTGOMERY`, and — critically for the hybrid
    /// KEM — the private key is NON-EXTRACTABLE / sensitive (its scalar never
    /// leaves the HSM). Parallels the FFI `CKM_EC_MONTGOMERY_KEY_PAIR_GEN` arm.
    #[test]
    fn x25519_keygen_lengths_family_and_non_extractable() {
        use crate::state::{get_object_algo_family, get_object_attr_bytes, get_object_attr_u32, get_object_value};
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) = generate_x25519_keypair(session, b"\x01", "x25519-1").unwrap();
        assert_eq!(get_object_value(prv_h).unwrap().len(), 32, "X25519 scalar");
        assert_eq!(get_object_value(pub_h).unwrap().len(), 32, "X25519 public point");
        assert_eq!(get_object_algo_family(prv_h), ALGO_ECDH_X25519, "tagged X25519 ECDH");
        assert_eq!(get_object_attr_u32(prv_h, CKA_KEY_TYPE), Some(CKK_EC_MONTGOMERY));
        // The security-critical properties for hybrid-KEM use (store_bool encodes
        // a single 0x00/0x01 byte):
        assert_eq!(get_object_attr_bytes(prv_h, CKA_EXTRACTABLE), Some(vec![0x00]), "non-extractable");
        assert_eq!(get_object_attr_bytes(prv_h, CKA_SENSITIVE), Some(vec![0x01]), "sensitive");
        close_session(session).unwrap();
    }

    /// X448 keygen: 56-byte scalar + 56-byte public point, tagged
    /// `ALGO_ECDH_X448`, `CKK_EC_MONTGOMERY`, NON-EXTRACTABLE. Parallels the
    /// FFI `CKM_EC_MONTGOMERY_KEY_PAIR_GEN` X448 branch. Used for KMIP
    /// `ECDH` + `RecommendedCurve = CURVE448`.
    #[test]
    fn x448_keygen_lengths_family_and_non_extractable() {
        use crate::state::{get_object_algo_family, get_object_attr_bytes, get_object_attr_u32, get_object_value};
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) = generate_x448_keypair(session, b"\x01", "x448-1").unwrap();
        assert_eq!(get_object_value(prv_h).unwrap().len(), 56, "X448 scalar");
        assert_eq!(get_object_value(pub_h).unwrap().len(), 56, "X448 public point");
        assert_eq!(get_object_algo_family(prv_h), ALGO_ECDH_X448, "tagged X448 ECDH");
        assert_eq!(get_object_attr_u32(prv_h, CKA_KEY_TYPE), Some(CKK_EC_MONTGOMERY));
        assert_eq!(get_object_attr_bytes(prv_h, CKA_EXTRACTABLE), Some(vec![0x00]), "non-extractable");
        assert_eq!(get_object_attr_bytes(prv_h, CKA_SENSITIVE), Some(vec![0x01]), "sensitive");
        close_session(session).unwrap();
    }

    /// The public key round-trips through sign/verify — the whole point of
    /// this fix (2026-07-05, P1): the generic `native::sign`/`native::verify`
    /// dispatch already handles `CKM_EDDSA`; this proves keygen produces
    /// key material those functions actually accept.
    #[test]
    fn ed25519_keygen_produces_a_working_signing_key() {
        use crate::native::sign::{sign, verify};
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) =
            generate_ed25519_keypair(session, b"\x02", "ed25519-2").unwrap();
        let msg = b"hybrid KEM audit trail, 2026-07-05";
        let sig = sign(session, prv_h, CKM_EDDSA, msg).expect("sign");
        assert_eq!(sig.len(), 64, "Ed25519 signature is 64 bytes");
        assert!(verify(session, pub_h, CKM_EDDSA, msg, &sig).unwrap());
        // Tampered message must not verify.
        assert!(!verify(session, pub_h, CKM_EDDSA, b"tampered", &sig).unwrap());
        close_session(session).unwrap();
    }

    /// AES-128: 16-byte key.
    #[test]
    fn aes_128_keygen_produces_16_byte_key() {
        use crate::state::{get_object_attr_u32, get_object_value};
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let handle = generate_aes_key(session, 128, b"\x01", "aes-128").unwrap();
        assert_eq!(get_object_value(handle).unwrap().len(), 16);
        assert_eq!(get_object_attr_u32(handle, CKA_VALUE_LEN).unwrap(), 16);
        close_session(session).unwrap();
    }

    /// AES-256: 32-byte key.
    #[test]
    fn aes_256_keygen_produces_32_byte_key() {
        use crate::state::get_object_value;
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let handle = generate_aes_key(session, 256, b"\x01", "aes-256").unwrap();
        assert_eq!(get_object_value(handle).unwrap().len(), 32);
        close_session(session).unwrap();
    }

    /// AES invalid bit length → CKR_ARGUMENTS_BAD; 192 is a valid
    /// PKCS#11 v3.2 §6.5 size (OASIS SKFF-M-{2,6,10}).
    #[test]
    fn aes_invalid_bits_returns_err() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        assert_eq!(
            generate_aes_key(session, 100, b"\x01", "x").unwrap_err(),
            CKR_ARGUMENTS_BAD,
        );
        let handle = generate_aes_key(session, 192, b"\x01", "x").unwrap();
        assert_eq!(get_object_value(handle).unwrap().len(), 24);
        close_session(session).unwrap();
    }

    /// Generic secret 256-bit (HMAC-SHA-256 key size).
    #[test]
    fn generic_secret_256_keygen_produces_32_byte_key() {
        use crate::state::get_object_value;
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let handle = generate_generic_secret(session, 256, b"\x01", "hmac-key").unwrap();
        assert_eq!(get_object_value(handle).unwrap().len(), 32);
        close_session(session).unwrap();
    }

    /// AES-GCM encrypt → decrypt round-trip (deferred from commit 5
    /// pending classical keygen — now wired).
    #[test]
    fn aes_256_gcm_encrypt_decrypt_round_trip() {
        use crate::native::encrypt::{decrypt, encrypt};
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let handle = generate_aes_key(session, 256, b"\x01", "aes-gcm").unwrap();
        let iv = vec![0x42u8; 12];
        let plaintext = b"the quick brown fox";
        let ciphertext =
            encrypt(session, handle, CKM_AES_GCM, plaintext, Some(&iv), None, &[], None).unwrap();
        // AES-GCM ciphertext = plaintext.len() + 16-byte tag.
        assert_eq!(ciphertext.len(), plaintext.len() + 16);
        let recovered =
            decrypt(session, handle, CKM_AES_GCM, &ciphertext, Some(&iv), None, &[], None).unwrap();
        assert_eq!(recovered, plaintext);
        close_session(session).unwrap();
    }

    /// Gap-remediation Phase F, Finding #4 — the handle-based `encrypt`/
    /// `decrypt` previously hardcoded empty AAD unconditionally; real
    /// client-supplied AAD must now genuinely authenticate the
    /// ciphertext (round-trips when matched, fails when tampered),
    /// exactly like the raw-bytes `encrypt_with_key_bytes` path already
    /// did.
    #[test]
    fn aes_256_gcm_engine_handle_honors_real_aad() {
        use crate::native::encrypt::{decrypt, encrypt};
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let handle = generate_aes_key(session, 256, b"\x01", "aes-gcm-aad").unwrap();
        let iv = vec![0x24u8; 12];
        let plaintext = b"Phase F: real AAD must genuinely authenticate";
        let aad = b"associated-data-not-encrypted";

        let ciphertext =
            encrypt(session, handle, CKM_AES_GCM, plaintext, Some(&iv), None, aad, None).unwrap();
        let recovered =
            decrypt(session, handle, CKM_AES_GCM, &ciphertext, Some(&iv), None, aad, None).unwrap();
        assert_eq!(recovered, plaintext, "decrypt with the matching AAD must recover the plaintext");

        let err = decrypt(
            session, handle, CKM_AES_GCM, &ciphertext, Some(&iv), None, b"wrong-aad", None,
        )
        .unwrap_err();
        assert_eq!(
            err, CKR_ENCRYPTED_DATA_INVALID,
            "decrypt with mismatched AAD must fail authentication, not silently succeed",
        );
        close_session(session).unwrap();
    }

    /// Gap-remediation Phase F, Finding #4 — the handle-based `encrypt`/
    /// `decrypt` previously hardcoded SHA-256/MGF1-SHA-256 for RSA-OAEP
    /// unconditionally. Proves an explicit non-default hash (SHA-384) is
    /// genuinely used, not silently ignored: encrypting with SHA-384 and
    /// decrypting with the SHA-256 default must fail (wrong padding
    /// hash), while decrypting with SHA-384 explicitly must recover the
    /// plaintext.
    #[test]
    fn rsa_oaep_engine_handle_honors_explicit_hash_override() {
        use crate::native::encrypt::{decrypt, encrypt, OaepHash, OaepParams};
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_handle, priv_handle) =
            generate_rsa_keypair(session, 2048, b"\x01", "rsa-oaep-hash").unwrap();
        let plaintext = b"Phase F: OAEP hash override must be real";

        let sha384 = OaepParams { hash: Some(OaepHash::Sha384), mgf_hash: Some(OaepHash::Sha384), label: None };
        let ciphertext = encrypt(
            session, pub_handle, CKM_RSA_PKCS_OAEP, plaintext, None, Some(&sha384), &[], None,
        )
        .unwrap();

        // SHA-256 default (no override) must NOT decrypt SHA-384-OAEP
        // ciphertext — proves encrypt genuinely used SHA-384, not a
        // silently-ignored parameter.
        let default_err = decrypt(
            session, priv_handle, CKM_RSA_PKCS_OAEP, &ciphertext, None, None, &[], None,
        )
        .unwrap_err();
        assert_eq!(default_err, CKR_ENCRYPTED_DATA_INVALID);

        // The matching SHA-384 override on decrypt recovers the plaintext.
        let recovered = decrypt(
            session, priv_handle, CKM_RSA_PKCS_OAEP, &ciphertext, None, Some(&sha384), &[], None,
        )
        .unwrap();
        assert_eq!(recovered, plaintext);
        close_session(session).unwrap();
    }

    /// AES-GCM tampered ciphertext → CKR_ENCRYPTED_DATA_INVALID
    /// (PKCS#11 v3.2 §6.13).
    #[test]
    fn aes_256_gcm_decrypt_tampered_ciphertext_returns_err() {
        use crate::native::encrypt::{decrypt, encrypt};
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let handle = generate_aes_key(session, 256, b"\x01", "tamper").unwrap();
        let iv = vec![0u8; 12];
        let mut ct =
            encrypt(session, handle, CKM_AES_GCM, b"hello", Some(&iv), None, &[], None).unwrap();
        ct[0] ^= 0xFF;
        let err =
            decrypt(session, handle, CKM_AES_GCM, &ct, Some(&iv), None, &[], None).unwrap_err();
        assert_eq!(err, CKR_ENCRYPTED_DATA_INVALID);
        close_session(session).unwrap();
    }

    // ── PQC key import (S7) ────────────────────────────────────────────────

    /// Read a stored CK_BBOOL attribute (None if absent).
    fn attr_bool(handle: u32, attr: u32) -> Option<bool> {
        crate::state::get_object_attr_bytes(handle, attr).map(|v| !v.is_empty() && v[0] == 0x01)
    }

    /// ML-DSA-65 generate → export raw key bytes → reimport → sign with
    /// the imported private + verify with the imported public; cross-check
    /// both directions against the in-engine generated keypair.
    #[test]
    fn ml_dsa_65_import_roundtrip_sign_verify() {
        use crate::native::sign::{sign, verify};
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (gen_pub, gen_prv) =
            generate_ml_dsa_keypair(session, CKP_ML_DSA_65, b"\x01", "gen-mldsa").unwrap();
        let sk = get_object_value(gen_prv).unwrap();
        let pk = get_object_value(gen_pub).unwrap();

        let imp_prv =
            register_ml_dsa_private_key(session, CKP_ML_DSA_65, &sk, b"\x02", "imp-sk").unwrap();
        let imp_pub =
            register_ml_dsa_public_key(session, CKP_ML_DSA_65, &pk, b"\x02", "imp-pk").unwrap();

        let msg = b"imported ML-DSA key material";
        let sig = sign(session, imp_prv, CKM_ML_DSA, msg).expect("sign with imported sk");
        assert_eq!(sig.len(), 3309, "FIPS 204 §5 ML-DSA-65 signature");
        assert!(verify(session, imp_pub, CKM_ML_DSA, msg, &sig).unwrap());
        // Cross-check: imported-key signature verifies under the generated
        // public, and vice versa (byte-compatible objects).
        assert!(verify(session, gen_pub, CKM_ML_DSA, msg, &sig).unwrap());
        let gen_sig = sign(session, gen_prv, CKM_ML_DSA, msg).unwrap();
        assert!(verify(session, imp_pub, CKM_ML_DSA, msg, &gen_sig).unwrap());

        close_session(session).unwrap();
    }

    /// ML-KEM-768 generate → reimport ek/dk → encapsulate with the
    /// imported public, decapsulate with both the imported and the
    /// generated private → identical shared secrets.
    #[test]
    fn ml_kem_768_import_roundtrip_encap_decap() {
        use crate::native::encrypt::{decapsulate, encapsulate};
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (gen_pub, gen_prv) =
            generate_ml_kem_keypair(session, CKP_ML_KEM_768, b"\x01", "gen-mlkem").unwrap();
        let dk = get_object_value(gen_prv).unwrap();
        let ek = get_object_value(gen_pub).unwrap();

        let imp_prv =
            register_ml_kem_private_key(session, CKP_ML_KEM_768, &dk, b"\x02", "imp-dk").unwrap();
        let imp_pub =
            register_ml_kem_public_key(session, CKP_ML_KEM_768, &ek, b"\x02", "imp-ek").unwrap();

        let (ct, ss_enc) = encapsulate(session, imp_pub, CKM_ML_KEM).unwrap();
        assert_eq!(ct.len(), 1088, "FIPS 203 §7 ML-KEM-768 ciphertext");
        assert_eq!(ss_enc.len(), 32);
        assert_eq!(decapsulate(session, imp_prv, CKM_ML_KEM, &ct).unwrap(), ss_enc);
        // Cross-check against the generated private key.
        assert_eq!(decapsulate(session, gen_prv, CKM_ML_KEM, &ct).unwrap(), ss_enc);

        close_session(session).unwrap();
    }

    /// SLH-DSA-SHAKE-128F generate → reimport → sign/verify round-trip
    /// with cross-checks against the generated keypair.
    #[test]
    fn slh_dsa_shake_128f_import_roundtrip_sign_verify() {
        use crate::native::sign::{sign, verify};
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (gen_pub, gen_prv) =
            generate_slh_dsa_keypair(session, CKP_SLH_DSA_SHAKE_128F, b"\x01", "gen-slh").unwrap();
        let sk = get_object_value(gen_prv).unwrap();
        let pk = get_object_value(gen_pub).unwrap();

        let imp_prv =
            register_slh_dsa_private_key(session, CKP_SLH_DSA_SHAKE_128F, &sk, b"\x02", "imp-sk")
                .unwrap();
        let imp_pub =
            register_slh_dsa_public_key(session, CKP_SLH_DSA_SHAKE_128F, &pk, b"\x02", "imp-pk")
                .unwrap();

        let msg = b"imported SLH-DSA key material";
        let sig = sign(session, imp_prv, CKM_SLH_DSA, msg).expect("sign with imported sk");
        assert_eq!(sig.len(), 17088, "FIPS 205 §11 SLH-DSA-128f signature");
        assert!(verify(session, imp_pub, CKM_SLH_DSA, msg, &sig).unwrap());
        assert!(verify(session, gen_pub, CKM_SLH_DSA, msg, &sig).unwrap());
        let gen_sig = sign(session, gen_prv, CKM_SLH_DSA, msg).unwrap();
        assert!(verify(session, imp_pub, CKM_SLH_DSA, msg, &gen_sig).unwrap());

        close_session(session).unwrap();
    }

    /// Imported private keys carry imported provenance: ALWAYS_SENSITIVE=
    /// FALSE / NEVER_EXTRACTABLE=FALSE / LOCAL=FALSE (§4.9/4.10), while a
    /// generated private key reports ALWAYS_SENSITIVE=TRUE. SENSITIVE
    /// stays TRUE (keygen default).
    #[test]
    fn imported_pqc_private_reports_imported_provenance() {
        use crate::state::get_object_attr_u32;
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (_, gen_prv) =
            generate_ml_dsa_keypair(session, CKP_ML_DSA_44, b"\x01", "gen").unwrap();
        assert_eq!(attr_bool(gen_prv, CKA_ALWAYS_SENSITIVE), Some(true));
        assert_eq!(attr_bool(gen_prv, CKA_NEVER_EXTRACTABLE), Some(true));

        let sk = get_object_value(gen_prv).unwrap();
        let imp_prv =
            register_ml_dsa_private_key(session, CKP_ML_DSA_44, &sk, b"\x02", "imp").unwrap();
        assert_eq!(attr_bool(imp_prv, CKA_ALWAYS_SENSITIVE), Some(false));
        assert_eq!(attr_bool(imp_prv, CKA_NEVER_EXTRACTABLE), Some(false));
        assert_eq!(attr_bool(imp_prv, CKA_LOCAL), Some(false));
        assert_eq!(attr_bool(imp_prv, CKA_SENSITIVE), Some(true));
        assert_eq!(
            get_object_attr_u32(imp_prv, CKA_KEY_GEN_MECHANISM),
            Some(CKM_UNAVAILABLE_INFORMATION)
        );
        assert_eq!(get_object_attr_u32(imp_prv, CKA_PARAMETER_SET), Some(CKP_ML_DSA_44));
        assert_eq!(get_object_attr_u32(imp_prv, CKA_KEY_TYPE), Some(CKK_ML_DSA));

        close_session(session).unwrap();
    }

    /// Wrong-length ML-DSA key material → CKR_ATTRIBUTE_VALUE_INVALID;
    /// unknown parameter set → CKR_ARGUMENTS_BAD.
    #[test]
    fn ml_dsa_import_wrong_length_rejected() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        // FIPS 204 §5 lengths for a *different* parameter set.
        assert_eq!(
            register_ml_dsa_private_key(session, CKP_ML_DSA_65, &vec![0u8; 2560], b"", "")
                .unwrap_err(),
            CKR_ATTRIBUTE_VALUE_INVALID,
        );
        assert_eq!(
            register_ml_dsa_public_key(session, CKP_ML_DSA_87, &vec![0u8; 1952], b"", "")
                .unwrap_err(),
            CKR_ATTRIBUTE_VALUE_INVALID,
        );
        assert_eq!(
            register_ml_dsa_private_key(session, 0xDEADBEEF, &vec![0u8; 2560], b"", "")
                .unwrap_err(),
            CKR_ARGUMENTS_BAD,
        );
        close_session(session).unwrap();
    }

    /// Wrong-length ML-KEM key material per FIPS 203 §7 → rejected.
    #[test]
    fn ml_kem_import_wrong_length_rejected() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        assert_eq!(
            register_ml_kem_private_key(session, CKP_ML_KEM_512, &vec![0u8; 2400], b"", "")
                .unwrap_err(),
            CKR_ATTRIBUTE_VALUE_INVALID,
        );
        assert_eq!(
            register_ml_kem_public_key(session, CKP_ML_KEM_1024, &vec![0u8; 1184], b"", "")
                .unwrap_err(),
            CKR_ATTRIBUTE_VALUE_INVALID,
        );
        assert_eq!(
            register_ml_kem_public_key(session, 0xDEADBEEF, &vec![0u8; 800], b"", "")
                .unwrap_err(),
            CKR_ARGUMENTS_BAD,
        );
        close_session(session).unwrap();
    }

    /// Wrong-length SLH-DSA key material per FIPS 205 §9.1 (sk=4n, pk=2n)
    /// → rejected; lengths differ across the three security levels.
    #[test]
    fn slh_dsa_import_wrong_length_rejected() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        // 128-bit level sk (64 bytes) offered as a 192-level key.
        assert_eq!(
            register_slh_dsa_private_key(session, CKP_SLH_DSA_SHA2_192S, &vec![0u8; 64], b"", "")
                .unwrap_err(),
            CKR_ATTRIBUTE_VALUE_INVALID,
        );
        // 256-level pk (64 bytes) offered as a 128-level key.
        assert_eq!(
            register_slh_dsa_public_key(session, CKP_SLH_DSA_SHAKE_128F, &vec![0u8; 64], b"", "")
                .unwrap_err(),
            CKR_ATTRIBUTE_VALUE_INVALID,
        );
        assert_eq!(
            register_slh_dsa_private_key(session, 0xDEADBEEF, &vec![0u8; 64], b"", "").unwrap_err(),
            CKR_ARGUMENTS_BAD,
        );
        close_session(session).unwrap();
    }

    /// Imported public keys carry the keygen-equivalent SPKI
    /// (CKA_PUBLIC_KEY_INFO), byte-identical to the generated object's.
    #[test]
    fn imported_pqc_public_carries_spki() {
        use crate::state::get_object_attr_bytes;
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (gen_pub, _) =
            generate_ml_kem_keypair(session, CKP_ML_KEM_512, b"\x01", "gen").unwrap();
        let ek = get_object_value(gen_pub).unwrap();
        let imp_pub =
            register_ml_kem_public_key(session, CKP_ML_KEM_512, &ek, b"\x02", "imp").unwrap();
        assert_eq!(
            get_object_attr_bytes(imp_pub, CKA_PUBLIC_KEY_INFO),
            get_object_attr_bytes(gen_pub, CKA_PUBLIC_KEY_INFO),
        );
        close_session(session).unwrap();
    }

    /// HMAC-SHA-256 sign + verify via the generic-secret key.
    #[test]
    fn hmac_sha256_via_generic_secret_round_trip() {
        use crate::native::sign::{sign, verify};
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let handle = generate_generic_secret(session, 256, b"\x01", "hmac-key").unwrap();
        let mac = sign(session, handle, CKM_SHA256_HMAC, b"data").unwrap();
        assert_eq!(mac.len(), 32, "HMAC-SHA-256 output = 32 bytes");
        assert!(verify(session, handle, CKM_SHA256_HMAC, b"data", &mac).unwrap());
        // Tampered tag → Ok(false), not Err.
        let mut bad = mac.clone();
        bad[0] ^= 0xFF;
        assert_eq!(verify(session, handle, CKM_SHA256_HMAC, b"data", &bad), Ok(false));
        close_session(session).unwrap();
    }

    // ── T7 — seed-deterministic PQC keygen (CKA_SEED) ───────────────────────

    fn hex_decode(s: &str) -> Vec<u8> {
        assert_eq!(s.len() % 2, 0, "odd hex length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    /// NIST ACVP ML-DSA keyGen KATs (FIPS 204 Algorithm 6
    /// `ML-DSA.KeyGen_internal(ξ)`): for every parameter set, seed ξ from
    /// the official vector file must reproduce the expected pk and sk
    /// byte-for-byte through `generate_ml_dsa_keypair_from_seed`.
    /// Vector source: fips204-patched/tests/nist_vectors/ML-DSA-keyGen-FIPS204.
    #[test]
    fn ml_dsa_keygen_from_seed_matches_acvp_kats() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fips204-patched/tests/nist_vectors/ML-DSA-keyGen-FIPS204/internalProjection.json"
        );
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).expect("vector file"))
                .expect("vector json");
        let mut covered = 0;
        for group in doc["testGroups"].as_array().expect("testGroups") {
            let ps = match group["parameterSet"].as_str().unwrap() {
                "ML-DSA-44" => CKP_ML_DSA_44,
                "ML-DSA-65" => CKP_ML_DSA_65,
                "ML-DSA-87" => CKP_ML_DSA_87,
                other => panic!("unknown parameterSet {other}"),
            };
            // ≥1 vector per parameter set (first three of each group keeps
            // the suite fast — full-file replay lives in the fork's tests).
            for tc in group["tests"].as_array().unwrap().iter().take(3) {
                let seed = hex_decode(tc["seed"].as_str().unwrap());
                let (pub_h, prv_h) =
                    generate_ml_dsa_keypair_from_seed(session, ps, &seed, b"\x01", "kat").unwrap();
                assert_eq!(
                    get_object_value(pub_h).unwrap(),
                    hex_decode(tc["pk"].as_str().unwrap()),
                    "pk mismatch ps=0x{ps:x} tcId={}",
                    tc["tcId"]
                );
                assert_eq!(
                    get_object_value(prv_h).unwrap(),
                    hex_decode(tc["sk"].as_str().unwrap()),
                    "sk mismatch ps=0x{ps:x} tcId={}",
                    tc["tcId"]
                );
                covered += 1;
            }
        }
        assert!(covered >= 9, "all three ML-DSA parameter sets covered");
        close_session(session).unwrap();
    }

    /// NIST ACVP SLH-DSA keyGen KATs (FIPS 205 Algorithm 18
    /// `slh_keygen_internal(SK.seed, SK.prf, PK.seed)`): CKA_SEED =
    /// skSeed ‖ skPrf ‖ pkSeed must reproduce the expected pk/sk. The
    /// in-repo vector file covers 4 of the 12 parameter sets
    /// (SHA2-128s, SHA2-192f, SHAKE-192s, SHAKE-256f); the remaining 8
    /// are covered by the determinism test below.
    /// Vector source: fips205-patched/tests/nist_acvp_vectors/SLH-DSA-keyGen-FIPS205.
    #[test]
    fn slh_dsa_keygen_from_seed_matches_acvp_kats() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fips205-patched/tests/nist_acvp_vectors/SLH-DSA-keyGen-FIPS205/internalProjection.json"
        );
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).expect("vector file"))
                .expect("vector json");
        let mut covered = 0;
        for group in doc["testGroups"].as_array().expect("testGroups") {
            let ps = match group["parameterSet"].as_str().unwrap() {
                "SLH-DSA-SHA2-128s" => CKP_SLH_DSA_SHA2_128S,
                "SLH-DSA-SHA2-192f" => CKP_SLH_DSA_SHA2_192F,
                "SLH-DSA-SHAKE-192s" => CKP_SLH_DSA_SHAKE_192S,
                "SLH-DSA-SHAKE-256f" => CKP_SLH_DSA_SHAKE_256F,
                other => panic!("unknown parameterSet {other}"),
            };
            for tc in group["tests"].as_array().unwrap().iter().take(2) {
                let mut seed = hex_decode(tc["skSeed"].as_str().unwrap());
                seed.extend(hex_decode(tc["skPrf"].as_str().unwrap()));
                seed.extend(hex_decode(tc["pkSeed"].as_str().unwrap()));
                let (pub_h, prv_h) =
                    generate_slh_dsa_keypair_from_seed(session, ps, &seed, b"\x01", "kat")
                        .unwrap();
                assert_eq!(
                    get_object_value(pub_h).unwrap(),
                    hex_decode(tc["pk"].as_str().unwrap()),
                    "pk mismatch ps=0x{ps:x} tcId={}",
                    tc["tcId"]
                );
                assert_eq!(
                    get_object_value(prv_h).unwrap(),
                    hex_decode(tc["sk"].as_str().unwrap()),
                    "sk mismatch ps=0x{ps:x} tcId={}",
                    tc["tcId"]
                );
                covered += 1;
            }
        }
        assert!(covered >= 8, "all four vectored SLH-DSA parameter sets covered");
        close_session(session).unwrap();
    }

    /// ML-KEM seed determinism (FIPS 203 Algorithm 16 — no official keyGen
    /// vectors with d‖z are in-repo, so this asserts the deterministic
    /// contract instead): same d‖z twice → identical ek/dk for every
    /// parameter set; different seed → different keys; and the
    /// deterministic keypair encap/decap round-trips.
    #[test]
    fn ml_kem_keygen_from_seed_deterministic_and_round_trips() {
        use crate::native::encrypt::{decapsulate, encapsulate};
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let seed_a = [0x42u8; 64];
        let seed_b = [0x43u8; 64];
        for ps in [CKP_ML_KEM_512, CKP_ML_KEM_768, CKP_ML_KEM_1024] {
            let (pub1, prv1) =
                generate_ml_kem_keypair_from_seed(session, ps, &seed_a, b"\x01", "det").unwrap();
            let (pub2, prv2) =
                generate_ml_kem_keypair_from_seed(session, ps, &seed_a, b"\x02", "det").unwrap();
            let (pub3, _) =
                generate_ml_kem_keypair_from_seed(session, ps, &seed_b, b"\x03", "det").unwrap();
            assert_eq!(
                get_object_value(pub1).unwrap(),
                get_object_value(pub2).unwrap(),
                "same seed → same ek (ps=0x{ps:x})"
            );
            assert_eq!(
                get_object_value(prv1).unwrap(),
                get_object_value(prv2).unwrap(),
                "same seed → same dk (ps=0x{ps:x})"
            );
            assert_ne!(
                get_object_value(pub1).unwrap(),
                get_object_value(pub3).unwrap(),
                "different seed → different ek (ps=0x{ps:x})"
            );
            // Functional: deterministic keypair encap/decap round-trips.
            let (ct, ss_enc) = encapsulate(session, pub1, CKM_ML_KEM).unwrap();
            let ss_dec = decapsulate(session, prv2, CKM_ML_KEM, &ct).unwrap();
            assert_eq!(ss_enc, ss_dec, "encap/decap shared secret (ps=0x{ps:x})");
        }
        close_session(session).unwrap();
    }

    /// ML-DSA / SLH-DSA seed determinism ×2 runs + functional sign/verify
    /// on the deterministic keypair. Covers the 8 SLH-DSA parameter sets
    /// that have no in-repo ACVP keyGen vectors (and one vectored one as a
    /// control), plus ML-DSA-44 (KATs cover byte-exactness above).
    #[test]
    fn dsa_keygen_from_seed_deterministic_and_functional() {
        use crate::native::sign::{sign, verify};
        let _guard = test_lock::acquire();
        let session = fresh_session();

        // ML-DSA: ξ = 32 bytes.
        let xi = [0xA5u8; 32];
        let (pub1, prv1) =
            generate_ml_dsa_keypair_from_seed(session, CKP_ML_DSA_44, &xi, b"\x01", "d").unwrap();
        let (pub2, _) =
            generate_ml_dsa_keypair_from_seed(session, CKP_ML_DSA_44, &xi, b"\x02", "d").unwrap();
        assert_eq!(get_object_value(pub1).unwrap(), get_object_value(pub2).unwrap());
        let sig = sign(session, prv1, CKM_ML_DSA, b"t7-data").unwrap();
        assert!(verify(session, pub2, CKM_ML_DSA, b"t7-data", &sig).unwrap());

        // SLH-DSA: 3n bytes; all 12 parameter sets (uses the fast 'f'
        // variants' sign only on one set to keep runtime sane).
        for (ps, n) in [
            (CKP_SLH_DSA_SHA2_128S, 16usize),
            (CKP_SLH_DSA_SHAKE_128S, 16),
            (CKP_SLH_DSA_SHA2_128F, 16),
            (CKP_SLH_DSA_SHAKE_128F, 16),
            (CKP_SLH_DSA_SHA2_192S, 24),
            (CKP_SLH_DSA_SHAKE_192S, 24),
            (CKP_SLH_DSA_SHA2_192F, 24),
            (CKP_SLH_DSA_SHAKE_192F, 24),
            (CKP_SLH_DSA_SHA2_256S, 32),
            (CKP_SLH_DSA_SHAKE_256S, 32),
            (CKP_SLH_DSA_SHA2_256F, 32),
            (CKP_SLH_DSA_SHAKE_256F, 32),
        ] {
            let seed = vec![0x5Au8; 3 * n];
            let (p1, _) =
                generate_slh_dsa_keypair_from_seed(session, ps, &seed, b"\x01", "s").unwrap();
            let (p2, _) =
                generate_slh_dsa_keypair_from_seed(session, ps, &seed, b"\x02", "s").unwrap();
            assert_eq!(
                get_object_value(p1).unwrap(),
                get_object_value(p2).unwrap(),
                "same seed → same pk (ps=0x{ps:x})"
            );
        }
        // Functional sign/verify on one deterministic SLH-DSA keypair.
        let seed = vec![0x77u8; 48];
        let (spub, sprv) =
            generate_slh_dsa_keypair_from_seed(session, CKP_SLH_DSA_SHA2_128F, &seed, b"\x03", "s")
                .unwrap();
        let sig = sign(session, sprv, CKM_SLH_DSA, b"t7-slh").unwrap();
        assert!(verify(session, spub, CKM_SLH_DSA, b"t7-slh", &sig).unwrap());

        close_session(session).unwrap();
    }

    /// Per-family / per-param-set seed length validation:
    /// CKR_ATTRIBUTE_VALUE_INVALID on any wrong length (ξ ≠ 32,
    /// d‖z ≠ 64, SLH ≠ 3n with n per param set).
    #[test]
    fn keygen_from_seed_rejects_wrong_lengths() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        for bad in [0usize, 31, 33, 64] {
            assert_eq!(
                generate_ml_dsa_keypair_from_seed(
                    session,
                    CKP_ML_DSA_65,
                    &vec![0u8; bad],
                    b"\x01",
                    "bad"
                )
                .unwrap_err(),
                CKR_ATTRIBUTE_VALUE_INVALID,
                "ML-DSA seed len {bad}"
            );
        }
        for bad in [0usize, 32, 63, 65] {
            assert_eq!(
                generate_ml_kem_keypair_from_seed(
                    session,
                    CKP_ML_KEM_768,
                    &vec![0u8; bad],
                    b"\x01",
                    "bad"
                )
                .unwrap_err(),
                CKR_ATTRIBUTE_VALUE_INVALID,
                "ML-KEM seed len {bad}"
            );
        }
        // SLH-DSA: 3n is param-set dependent — a 48-byte seed is valid for
        // n=16 but invalid for n=24/32, and vice versa.
        for (ps, wrong) in [
            (CKP_SLH_DSA_SHA2_128S, 72usize),
            (CKP_SLH_DSA_SHA2_192S, 48),
            (CKP_SLH_DSA_SHAKE_256F, 72),
            (CKP_SLH_DSA_SHAKE_128F, 47),
        ] {
            assert_eq!(
                generate_slh_dsa_keypair_from_seed(
                    session,
                    ps,
                    &vec![0u8; wrong],
                    b"\x01",
                    "bad"
                )
                .unwrap_err(),
                CKR_ATTRIBUTE_VALUE_INVALID,
                "SLH-DSA ps=0x{ps:x} seed len {wrong}"
            );
        }
        close_session(session).unwrap();
    }

    /// No CKA_SEED → OsRng path unchanged: two random generations differ
    /// (per family).
    #[test]
    fn keygen_without_seed_remains_random() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (a, _) = generate_ml_dsa_keypair(session, CKP_ML_DSA_44, b"\x01", "r").unwrap();
        let (b, _) = generate_ml_dsa_keypair(session, CKP_ML_DSA_44, b"\x02", "r").unwrap();
        assert_ne!(get_object_value(a).unwrap(), get_object_value(b).unwrap());
        let (a, _) = generate_ml_kem_keypair(session, CKP_ML_KEM_512, b"\x03", "r").unwrap();
        let (b, _) = generate_ml_kem_keypair(session, CKP_ML_KEM_512, b"\x04", "r").unwrap();
        assert_ne!(get_object_value(a).unwrap(), get_object_value(b).unwrap());
        let (a, _) =
            generate_slh_dsa_keypair(session, CKP_SLH_DSA_SHA2_128F, b"\x05", "r").unwrap();
        let (b, _) =
            generate_slh_dsa_keypair(session, CKP_SLH_DSA_SHA2_128F, b"\x06", "r").unwrap();
        assert_ne!(get_object_value(a).unwrap(), get_object_value(b).unwrap());
        close_session(session).unwrap();
    }

    /// PKCS#11 v3.2 Table 6 — an unrecognized CKA_PARAMETER_SET value must
    /// fail with the dedicated `CKR_PARAMETER_SET_NOT_SUPPORTED`, not the
    /// generic `CKR_ARGUMENTS_BAD`/`CKR_ATTRIBUTE_VALUE_INVALID`. Covers all
    /// three PQC families' keygen entry points.
    #[test]
    fn unrecognized_parameter_set_is_rejected_with_dedicated_error() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        const BOGUS_PARAM_SET: u32 = 0xffff_fffe;

        assert_eq!(
            generate_ml_kem_keypair(session, BOGUS_PARAM_SET, b"\x01", "bad-kem").unwrap_err(),
            CKR_PARAMETER_SET_NOT_SUPPORTED
        );
        assert_eq!(
            generate_ml_dsa_keypair(session, BOGUS_PARAM_SET, b"\x02", "bad-dsa").unwrap_err(),
            CKR_PARAMETER_SET_NOT_SUPPORTED
        );
        assert_eq!(
            generate_slh_dsa_keypair(session, BOGUS_PARAM_SET, b"\x03", "bad-slh").unwrap_err(),
            CKR_PARAMETER_SET_NOT_SUPPORTED
        );

        close_session(session).unwrap();
    }
}
