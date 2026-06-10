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
    ALGO_ECDSA, ALGO_ML_DSA, ALGO_ML_KEM, ALGO_RSA, ALGO_SLH_DSA, CURVE_K256, CURVE_P256,
    CURVE_P384, CURVE_P521,
};
use crate::crypto::handlers::{
    build_ec_spki_p256, build_ec_spki_p384, build_ec_spki_p521, build_mldsa44_spki,
    build_mldsa65_spki, build_mldsa87_spki, build_mlkem1024_spki, build_mlkem512_spki,
    build_mlkem768_spki, build_slhdsa_spki, build_spki_from_parts, Attributes,
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
    use ml_kem::{EncodedSizeUser, KemCore};

    let mut pub_attrs: Attributes = HashMap::new();
    let mut prv_attrs: Attributes = HashMap::new();

    // PKCS#11 v3.2 defaults — mirrors ffi::C_GenerateKeyPair @ ML-KEM arm.
    set_common_pub_attrs(&mut pub_attrs, parameter_set, ALGO_ML_KEM, CKK_ML_KEM, CKM_ML_KEM_KEY_PAIR_GEN);
    set_common_prv_attrs(&mut prv_attrs, parameter_set, ALGO_ML_KEM, CKK_ML_KEM, CKM_ML_KEM_KEY_PAIR_GEN);
    // ML-KEM-specific flags: encapsulate / decapsulate, NOT sign / verify.
    store_bool(&mut pub_attrs, CKA_VERIFY, false);
    store_bool(&mut pub_attrs, CKA_ENCAPSULATE, true);
    store_bool(&mut prv_attrs, CKA_SIGN, false);
    store_bool(&mut prv_attrs, CKA_DECAPSULATE, true);

    // Caller bookkeeping.
    insert_id_and_label(&mut pub_attrs, cka_id, label);
    insert_id_and_label(&mut prv_attrs, cka_id, label);

    // Crypto keygen.
    let mut rng = rand::rngs::OsRng;
    match parameter_set {
        CKP_ML_KEM_512 => {
            let (dk, ek) = ml_kem::MlKem512::generate(&mut rng);
            pub_attrs.insert(CKA_VALUE, ek.as_bytes().as_slice().to_vec());
            prv_attrs.insert(CKA_VALUE, dk.as_bytes().as_slice().to_vec());
        }
        CKP_ML_KEM_768 => {
            let (dk, ek) = ml_kem::MlKem768::generate(&mut rng);
            pub_attrs.insert(CKA_VALUE, ek.as_bytes().as_slice().to_vec());
            prv_attrs.insert(CKA_VALUE, dk.as_bytes().as_slice().to_vec());
        }
        CKP_ML_KEM_1024 => {
            let (dk, ek) = ml_kem::MlKem1024::generate(&mut rng);
            pub_attrs.insert(CKA_VALUE, ek.as_bytes().as_slice().to_vec());
            prv_attrs.insert(CKA_VALUE, dk.as_bytes().as_slice().to_vec());
        }
        _ => return Err(CKR_ARGUMENTS_BAD),
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

    finalize_and_register(pub_attrs, prv_attrs)
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
    let mut pub_attrs: Attributes = HashMap::new();
    let mut prv_attrs: Attributes = HashMap::new();

    set_common_pub_attrs(&mut pub_attrs, parameter_set, ALGO_ML_DSA, CKK_ML_DSA, CKM_ML_DSA_KEY_PAIR_GEN);
    set_common_prv_attrs(&mut prv_attrs, parameter_set, ALGO_ML_DSA, CKK_ML_DSA, CKM_ML_DSA_KEY_PAIR_GEN);
    // ML-DSA: sign / verify, NOT encapsulate / decapsulate.
    store_bool(&mut pub_attrs, CKA_VERIFY, true);
    store_bool(&mut pub_attrs, CKA_ENCAPSULATE, false);
    store_bool(&mut prv_attrs, CKA_SIGN, true);
    store_bool(&mut prv_attrs, CKA_DECAPSULATE, false);

    insert_id_and_label(&mut pub_attrs, cka_id, label);
    insert_id_and_label(&mut prv_attrs, cka_id, label);

    let mut rng = rand::rngs::OsRng;
    match parameter_set {
        CKP_ML_DSA_44 => match fips204::ml_dsa_44::try_keygen_with_rng(&mut rng) {
            Ok((vk, sk)) => {
                pub_attrs.insert(CKA_VALUE, fips204::traits::SerDes::into_bytes(vk).to_vec());
                prv_attrs.insert(CKA_VALUE, fips204::traits::SerDes::into_bytes(sk).to_vec());
            }
            Err(_) => return Err(CKR_FUNCTION_FAILED),
        },
        CKP_ML_DSA_65 => match fips204::ml_dsa_65::try_keygen_with_rng(&mut rng) {
            Ok((vk, sk)) => {
                pub_attrs.insert(CKA_VALUE, fips204::traits::SerDes::into_bytes(vk).to_vec());
                prv_attrs.insert(CKA_VALUE, fips204::traits::SerDes::into_bytes(sk).to_vec());
            }
            Err(_) => return Err(CKR_FUNCTION_FAILED),
        },
        CKP_ML_DSA_87 => match fips204::ml_dsa_87::try_keygen_with_rng(&mut rng) {
            Ok((vk, sk)) => {
                pub_attrs.insert(CKA_VALUE, fips204::traits::SerDes::into_bytes(vk).to_vec());
                prv_attrs.insert(CKA_VALUE, fips204::traits::SerDes::into_bytes(sk).to_vec());
            }
            Err(_) => return Err(CKR_FUNCTION_FAILED),
        },
        _ => return Err(CKR_ARGUMENTS_BAD),
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

    finalize_and_register(pub_attrs, prv_attrs)
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
    use fips205::traits::SerDes;

    let mut pub_attrs: Attributes = HashMap::new();
    let mut prv_attrs: Attributes = HashMap::new();

    set_common_pub_attrs(&mut pub_attrs, parameter_set, ALGO_SLH_DSA, CKK_SLH_DSA, CKM_SLH_DSA_KEY_PAIR_GEN);
    set_common_prv_attrs(&mut prv_attrs, parameter_set, ALGO_SLH_DSA, CKK_SLH_DSA, CKM_SLH_DSA_KEY_PAIR_GEN);
    store_bool(&mut pub_attrs, CKA_VERIFY, true);
    store_bool(&mut pub_attrs, CKA_ENCAPSULATE, false);
    store_bool(&mut prv_attrs, CKA_SIGN, true);
    store_bool(&mut prv_attrs, CKA_DECAPSULATE, false);

    insert_id_and_label(&mut pub_attrs, cka_id, label);
    insert_id_and_label(&mut prv_attrs, cka_id, label);

    let mut rng = rand::rngs::OsRng;
    match parameter_set {
        CKP_SLH_DSA_SHA2_128S => slh_keygen!(fips205::slh_dsa_sha2_128s::try_keygen_with_rng, rng, pub_attrs, prv_attrs),
        CKP_SLH_DSA_SHAKE_128S => slh_keygen!(fips205::slh_dsa_shake_128s::try_keygen_with_rng, rng, pub_attrs, prv_attrs),
        CKP_SLH_DSA_SHA2_128F => slh_keygen!(fips205::slh_dsa_sha2_128f::try_keygen_with_rng, rng, pub_attrs, prv_attrs),
        CKP_SLH_DSA_SHAKE_128F => slh_keygen!(fips205::slh_dsa_shake_128f::try_keygen_with_rng, rng, pub_attrs, prv_attrs),
        CKP_SLH_DSA_SHA2_192S => slh_keygen!(fips205::slh_dsa_sha2_192s::try_keygen_with_rng, rng, pub_attrs, prv_attrs),
        CKP_SLH_DSA_SHAKE_192S => slh_keygen!(fips205::slh_dsa_shake_192s::try_keygen_with_rng, rng, pub_attrs, prv_attrs),
        CKP_SLH_DSA_SHA2_192F => slh_keygen!(fips205::slh_dsa_sha2_192f::try_keygen_with_rng, rng, pub_attrs, prv_attrs),
        CKP_SLH_DSA_SHAKE_192F => slh_keygen!(fips205::slh_dsa_shake_192f::try_keygen_with_rng, rng, pub_attrs, prv_attrs),
        CKP_SLH_DSA_SHA2_256S => slh_keygen!(fips205::slh_dsa_sha2_256s::try_keygen_with_rng, rng, pub_attrs, prv_attrs),
        CKP_SLH_DSA_SHAKE_256S => slh_keygen!(fips205::slh_dsa_shake_256s::try_keygen_with_rng, rng, pub_attrs, prv_attrs),
        CKP_SLH_DSA_SHA2_256F => slh_keygen!(fips205::slh_dsa_sha2_256f::try_keygen_with_rng, rng, pub_attrs, prv_attrs),
        CKP_SLH_DSA_SHAKE_256F => slh_keygen!(fips205::slh_dsa_shake_256f::try_keygen_with_rng, rng, pub_attrs, prv_attrs),
        _ => return Err(CKR_ARGUMENTS_BAD),
    }

    if let Some(pk_bytes) = pub_attrs.get(&CKA_VALUE).cloned() {
        let spki = build_slhdsa_spki(parameter_set, &pk_bytes);
        if !spki.is_empty() {
            pub_attrs.insert(CKA_PUBLIC_KEY_INFO, spki);
        }
    }

    finalize_and_register(pub_attrs, prv_attrs)
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

    finalize_and_register(pub_attrs, prv_attrs)
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

    finalize_and_register(pub_attrs, prv_attrs)
}

/// Generate an AES secret key. `bits` ∈ {128, 256} (192 is permitted by
/// PKCS#11 but the engine only supports 128 and 256 today).
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
    Ok(allocate_handle(finalize_secret_attrs(attrs)))
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
    finalize_private_key_attrs(&mut attrs);
    compute_kcv(&mut attrs);
    Ok(allocate_handle(attrs))
}

/// Register an existing RSA public key supplied as PKCS#1 (RSAPublicKey)
/// or PKCS#8 (SubjectPublicKeyInfo) DER bytes. Used by KMIP Register
/// when the client provides an RSA PublicKey. CS-AC-M-2 exercises this
/// path against an Encrypt op.
pub fn register_rsa_public_key_der(
    _session: u32,
    der: &[u8],
    cka_id: &[u8],
    label: &str,
) -> Result<u32, CkRv> {
    use crate::constants::{CKA_CLASS, CKA_ENCRYPT, CKA_KEY_TYPE, CKA_VALUE, CKA_VERIFY, CKK_RSA, CKO_PUBLIC_KEY};
    let mut attrs = std::collections::HashMap::new();
    store_ulong(&mut attrs, CKA_CLASS, CKO_PUBLIC_KEY);
    store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_RSA);
    store_bool(&mut attrs, CKA_VERIFY, true);
    store_bool(&mut attrs, CKA_ENCRYPT, true);
    attrs.insert(CKA_VALUE, der.to_vec());
    insert_id_and_label(&mut attrs, cka_id, label);
    compute_kcv(&mut attrs);
    Ok(allocate_handle(attrs))
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
    finalize_private_key_attrs(&mut attrs);
    compute_kcv(&mut attrs);
    Ok(allocate_handle(attrs))
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
    Ok(allocate_handle(finalize_secret_attrs(attrs)))
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
    store_bool(&mut attrs, CKA_SENSITIVE, false);
    store_bool(&mut attrs, CKA_EXTRACTABLE, false);
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
fn build_generic_secret_attrs(
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
    store_bool(&mut attrs, CKA_SENSITIVE, false);
    store_bool(&mut attrs, CKA_EXTRACTABLE, false);
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

fn insert_id_and_label(attrs: &mut Attributes, cka_id: &[u8], label: &str) {
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
    mut pub_attrs: Attributes,
    mut prv_attrs: Attributes,
) -> Result<(u32, u32), CkRv> {
    finalize_private_key_attrs(&mut prv_attrs);
    compute_kcv(&mut pub_attrs);
    compute_kcv(&mut prv_attrs);
    let pub_h = allocate_handle(pub_attrs);
    let prv_h = allocate_handle(prv_attrs);
    Ok((pub_h, prv_h))
}

/// SLH-DSA keygen — wraps the `fips205::*::try_keygen_with_rng` calls
/// with the same shape so the per-variant match stays a single line.
/// `$func` is the fully-qualified keygen path; `$rng` is `OsRng`;
/// `$pub_attrs` / `$prv_attrs` are the maps to populate with `CKA_VALUE`.
macro_rules! slh_keygen {
    ($func:path, $rng:ident, $pub_attrs:expr, $prv_attrs:expr) => {{
        match $func(&mut $rng) {
            Ok((vk, sk)) => {
                $pub_attrs.insert(CKA_VALUE, vk.into_bytes().to_vec());
                $prv_attrs.insert(CKA_VALUE, sk.into_bytes().to_vec());
            }
            Err(_) => return Err(CKR_FUNCTION_FAILED),
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

    /// Bad parameter set → CKR_ARGUMENTS_BAD.
    #[test]
    fn ml_kem_invalid_parameter_set_returns_err() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let result = generate_ml_kem_keypair(session, 0xDEADBEEF, b"\x01", "x");
        assert!(matches!(result, Err(CKR_ARGUMENTS_BAD)));
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

    /// AES invalid bit length → CKR_ARGUMENTS_BAD.
    #[test]
    fn aes_invalid_bits_returns_err() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        assert_eq!(
            generate_aes_key(session, 100, b"\x01", "x").unwrap_err(),
            CKR_ARGUMENTS_BAD,
        );
        assert_eq!(
            generate_aes_key(session, 192, b"\x01", "x").unwrap_err(),
            CKR_ARGUMENTS_BAD,
        );
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
        let ciphertext = encrypt(session, handle, CKM_AES_GCM, plaintext, Some(&iv)).unwrap();
        // AES-GCM ciphertext = plaintext.len() + 16-byte tag.
        assert_eq!(ciphertext.len(), plaintext.len() + 16);
        let recovered = decrypt(session, handle, CKM_AES_GCM, &ciphertext, Some(&iv)).unwrap();
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
        let mut ct = encrypt(session, handle, CKM_AES_GCM, b"hello", Some(&iv)).unwrap();
        ct[0] ^= 0xFF;
        let err = decrypt(session, handle, CKM_AES_GCM, &ct, Some(&iv)).unwrap_err();
        assert_eq!(err, CKR_ENCRYPTED_DATA_INVALID);
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
}
