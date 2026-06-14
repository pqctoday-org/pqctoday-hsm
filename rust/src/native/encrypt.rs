//! Encrypt / Decrypt / Encapsulate / Decapsulate — typed wrappers.
//!
//! - **`encapsulate`** / **`decapsulate`** are the ML-KEM-specific calls.
//!   Unlike the C ABI's `C_EncapsulateKey` / `C_DecapsulateKey` (which
//!   allocate engine OBJECTS for the shared secret and return a handle),
//!   the native API returns the shared secret bytes directly — that's
//!   the shape KMIP's `Encrypt`/`Decrypt` responses need, and it lets
//!   the caller decide whether to wrap the SS in another HSM object.
//!
//! - **`encrypt`** / **`decrypt`** cover the classical symmetric paths
//!   (AES-GCM in v0.1; AES-CBC, AES-CTR, RSA-OAEP can be added when
//!   KMIP exposes them). Asymmetric encrypt (RSA-OAEP) and additional
//!   AES modes are TODO; commit 5 ships the dispatch skeleton + ML-KEM
//!   full coverage, classical AES tests follow in commit 6 alongside
//!   `generate_aes_key`.
//!
//! Implementation mirrors `ffi::C_Encrypt` / `ffi::C_Decrypt` /
//! `ffi::C_EncapsulateKey` / `ffi::C_DecapsulateKey` minus the wasm32
//! pointer marshalling for templates + the SS-handle allocation path.
//!
//! See [`super`] for the typed-vs-FFI architectural relationship.

use super::CkRv;
use crate::constants::*;
use crate::state::{get_object_attr_u32, get_object_param_set, get_object_value, OBJECTS};

// PKCS#11 v3.2 §5.18 — KEM permission flags. CKA_ENCAPSULATE / CKA_DECAPSULATE.
use crate::constants::{CKA_DECAPSULATE, CKA_DECRYPT, CKA_ENCAPSULATE, CKA_ENCRYPT};

/// ML-KEM encapsulation. Returns `(ciphertext, shared_secret)`.
///
/// `public_key_handle` MUST refer to an ML-KEM public-key object with
/// `CKA_ENCAPSULATE = true`. `mechanism` is `CKM_ML_KEM`.
///
/// Ciphertext / shared-secret lengths per FIPS 203 §7:
/// - ML-KEM-512:  ct = 768, ss = 32
/// - ML-KEM-768:  ct = 1088, ss = 32
/// - ML-KEM-1024: ct = 1568, ss = 32
pub fn encapsulate(
    _session: u32,
    public_key_handle: u32,
    mechanism: u32,
) -> Result<(Vec<u8>, Vec<u8>), CkRv> {
    use ml_kem::{kem::Encapsulate, EncodedSizeUser, KemCore};

    if mechanism != CKM_ML_KEM {
        return Err(CKR_MECHANISM_INVALID);
    }
    if !check_flag(public_key_handle, CKA_ENCAPSULATE) {
        return Err(CKR_KEY_FUNCTION_NOT_PERMITTED);
    }

    // PKCS#11 v3.2 §5.18.8 — CKM_ML_KEM requires an ML-KEM key
    // (compliance-audit P-10).
    if get_object_attr_u32(public_key_handle, CKA_KEY_TYPE) != Some(CKK_ML_KEM) {
        return Err(CKR_KEY_TYPE_INCONSISTENT);
    }
    let ps = get_object_param_set(public_key_handle);
    // P-10: no silent ML-KEM-768 default — a key without
    // CKA_PARAMETER_SET is an incomplete object.
    if ps == 0 {
        return Err(CKR_TEMPLATE_INCOMPLETE);
    }
    let pub_key_bytes = get_object_value(public_key_handle).ok_or(CKR_ARGUMENTS_BAD)?;
    let mut rng = rand::rngs::OsRng;

    let (ct, ss) = match ps {
        CKP_ML_KEM_512 => {
            let ek_enc = ml_kem::array::Array::try_from(pub_key_bytes.as_slice())
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let ek = <ml_kem::MlKem512 as KemCore>::EncapsulationKey::from_bytes(&ek_enc);
            let (ct, ss) =
                Encapsulate::encapsulate(&ek, &mut rng).map_err(|_| CKR_FUNCTION_FAILED)?;
            (ct.as_slice().to_vec(), ss.as_slice().to_vec())
        }
        CKP_ML_KEM_768 => {
            let ek_enc = ml_kem::array::Array::try_from(pub_key_bytes.as_slice())
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let ek = <ml_kem::MlKem768 as KemCore>::EncapsulationKey::from_bytes(&ek_enc);
            let (ct, ss) =
                Encapsulate::encapsulate(&ek, &mut rng).map_err(|_| CKR_FUNCTION_FAILED)?;
            (ct.as_slice().to_vec(), ss.as_slice().to_vec())
        }
        CKP_ML_KEM_1024 => {
            let ek_enc = ml_kem::array::Array::try_from(pub_key_bytes.as_slice())
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let ek = <ml_kem::MlKem1024 as KemCore>::EncapsulationKey::from_bytes(&ek_enc);
            let (ct, ss) =
                Encapsulate::encapsulate(&ek, &mut rng).map_err(|_| CKR_FUNCTION_FAILED)?;
            (ct.as_slice().to_vec(), ss.as_slice().to_vec())
        }
        _ => return Err(CKR_ARGUMENTS_BAD),
    };
    Ok((ct, ss))
}

/// ML-KEM **deterministic** encapsulation with caller-supplied coins
/// (FIPS 203 §7.2 `ML-KEM.Encaps_internal(ek, m)`).
///
/// Identical to [`encapsulate`] except the 32-byte message `m` (the
/// encapsulation randomness) is supplied by the caller instead of drawn from
/// the OS RNG. This is the entry point the OASIS KMIP 3.0 PQC interop
/// encapsulation vectors require: each provides a fixed `m` and expects a
/// fixed ciphertext + shared secret. The randomized [`encapsulate`] cannot
/// reproduce those — only this `_internal` form can.
///
/// SECURITY: `m` MUST be uniformly random for the KEM to be IND-CCA2 secure
/// (FIPS 203 §3.3). This entry point exists for KAT/interop reproducibility
/// and deterministic-coins KMIP requests; production encapsulation must use
/// [`encapsulate`], which samples `m` from the OS RNG.
///
/// `coins` must be exactly 32 bytes → otherwise `CKR_ARGUMENTS_BAD`.
pub fn encapsulate_deterministic(
    _session: u32,
    public_key_handle: u32,
    mechanism: u32,
    coins: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CkRv> {
    use ml_kem::{EncapsulateDeterministic, EncodedSizeUser, KemCore};

    if mechanism != CKM_ML_KEM {
        return Err(CKR_MECHANISM_INVALID);
    }
    if !check_flag(public_key_handle, CKA_ENCAPSULATE) {
        return Err(CKR_KEY_FUNCTION_NOT_PERMITTED);
    }
    if get_object_attr_u32(public_key_handle, CKA_KEY_TYPE) != Some(CKK_ML_KEM) {
        return Err(CKR_KEY_TYPE_INCONSISTENT);
    }
    let ps = get_object_param_set(public_key_handle);
    if ps == 0 {
        return Err(CKR_TEMPLATE_INCOMPLETE);
    }
    // FIPS 203 §7.2 — m is exactly 32 bytes.
    let m = ml_kem::B32::try_from(coins).map_err(|_| CKR_ARGUMENTS_BAD)?;
    let pub_key_bytes = get_object_value(public_key_handle).ok_or(CKR_ARGUMENTS_BAD)?;

    let (ct, ss) = match ps {
        CKP_ML_KEM_512 => {
            let ek_enc = ml_kem::array::Array::try_from(pub_key_bytes.as_slice())
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let ek = <ml_kem::MlKem512 as KemCore>::EncapsulationKey::from_bytes(&ek_enc);
            let (ct, ss) = ek
                .encapsulate_deterministic(&m)
                .map_err(|_| CKR_FUNCTION_FAILED)?;
            (ct.as_slice().to_vec(), ss.as_slice().to_vec())
        }
        CKP_ML_KEM_768 => {
            let ek_enc = ml_kem::array::Array::try_from(pub_key_bytes.as_slice())
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let ek = <ml_kem::MlKem768 as KemCore>::EncapsulationKey::from_bytes(&ek_enc);
            let (ct, ss) = ek
                .encapsulate_deterministic(&m)
                .map_err(|_| CKR_FUNCTION_FAILED)?;
            (ct.as_slice().to_vec(), ss.as_slice().to_vec())
        }
        CKP_ML_KEM_1024 => {
            let ek_enc = ml_kem::array::Array::try_from(pub_key_bytes.as_slice())
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let ek = <ml_kem::MlKem1024 as KemCore>::EncapsulationKey::from_bytes(&ek_enc);
            let (ct, ss) = ek
                .encapsulate_deterministic(&m)
                .map_err(|_| CKR_FUNCTION_FAILED)?;
            (ct.as_slice().to_vec(), ss.as_slice().to_vec())
        }
        _ => return Err(CKR_ARGUMENTS_BAD),
    };
    Ok((ct, ss))
}

/// ML-KEM decapsulation. Returns the recovered shared secret.
///
/// `private_key_handle` MUST refer to an ML-KEM private-key object with
/// `CKA_DECAPSULATE = true`. `ciphertext` length must match the
/// parameter set's ML-KEM ct size (768 / 1088 / 1568 for 512 / 768 / 1024).
pub fn decapsulate(
    _session: u32,
    private_key_handle: u32,
    mechanism: u32,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CkRv> {
    use ml_kem::{kem::Decapsulate, EncodedSizeUser, KemCore};

    if mechanism != CKM_ML_KEM {
        return Err(CKR_MECHANISM_INVALID);
    }
    if !check_flag(private_key_handle, CKA_DECAPSULATE) {
        return Err(CKR_KEY_FUNCTION_NOT_PERMITTED);
    }

    // PKCS#11 v3.2 §5.18.9 — CKM_ML_KEM requires an ML-KEM key
    // (compliance-audit P-10).
    if get_object_attr_u32(private_key_handle, CKA_KEY_TYPE) != Some(CKK_ML_KEM) {
        return Err(CKR_KEY_TYPE_INCONSISTENT);
    }
    let ps = get_object_param_set(private_key_handle);
    // P-10: no silent ML-KEM-768 default — a key without
    // CKA_PARAMETER_SET is an incomplete object.
    if ps == 0 {
        return Err(CKR_TEMPLATE_INCOMPLETE);
    }
    let expected_ct_len: usize = match ps {
        CKP_ML_KEM_512 => 768,
        CKP_ML_KEM_768 => 1088,
        CKP_ML_KEM_1024 => 1568,
        _ => return Err(CKR_ARGUMENTS_BAD),
    };
    if ciphertext.len() != expected_ct_len {
        return Err(CKR_ARGUMENTS_BAD);
    }

    let prv_key_bytes = get_object_value(private_key_handle).ok_or(CKR_ARGUMENTS_BAD)?;

    let ss = match ps {
        CKP_ML_KEM_512 => {
            let dk_enc = ml_kem::array::Array::try_from(prv_key_bytes.as_slice())
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let dk = <ml_kem::MlKem512 as KemCore>::DecapsulationKey::from_bytes(&dk_enc);
            let ct_enc =
                ml_kem::array::Array::try_from(ciphertext).map_err(|_| CKR_ARGUMENTS_BAD)?;
            Decapsulate::decapsulate(&dk, &ct_enc).map_err(|_| CKR_FUNCTION_FAILED)?
        }
        CKP_ML_KEM_768 => {
            let dk_enc = ml_kem::array::Array::try_from(prv_key_bytes.as_slice())
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let dk = <ml_kem::MlKem768 as KemCore>::DecapsulationKey::from_bytes(&dk_enc);
            let ct_enc =
                ml_kem::array::Array::try_from(ciphertext).map_err(|_| CKR_ARGUMENTS_BAD)?;
            Decapsulate::decapsulate(&dk, &ct_enc).map_err(|_| CKR_FUNCTION_FAILED)?
        }
        CKP_ML_KEM_1024 => {
            let dk_enc = ml_kem::array::Array::try_from(prv_key_bytes.as_slice())
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let dk = <ml_kem::MlKem1024 as KemCore>::DecapsulationKey::from_bytes(&dk_enc);
            let ct_enc =
                ml_kem::array::Array::try_from(ciphertext).map_err(|_| CKR_ARGUMENTS_BAD)?;
            Decapsulate::decapsulate(&dk, &ct_enc).map_err(|_| CKR_FUNCTION_FAILED)?
        }
        _ => return Err(CKR_ARGUMENTS_BAD),
    };
    Ok(ss.as_slice().to_vec())
}

/// Classical encrypt. v0.1 supports `CKM_AES_GCM`.
///
/// For AES-GCM, `iv` is the 12-byte nonce. Empty AAD is used; if KMIP
/// ever exposes AAD in its Encrypt request, this function can grow an
/// optional `aad` arg.
///
/// `mechanism` selects:
/// - `CKM_AES_GCM`: AES-128/256-GCM (12-byte IV) — Rust `aes-gcm`.
/// - `CKM_AES_ECB` / `CKM_AES_CBC` / `CKM_AES_CBC_PAD` / `CKM_AES_CTR`:
///   block / counter modes (CTR takes the full 16-byte counter block
///   as `iv`, per PKCS#11 v3.2 §6.10 `CK_AES_CTR_PARAMS.cb`; KMIP K6
///   wires `BlockCipherMode=CTR` here).
/// - `CKM_RSA_PKCS_OAEP`: RSA OAEP with **SHA-256** hash + MGF1-SHA-256
///   (the only OAEP profile the OASIS Baseline corpus exercises;
///   §11.x lists the full set). Public key is stored as X.509
///   SubjectPublicKeyInfo DER (the form `C_RegisterObject` accepts
///   from the KMIP `Register` op).
///
/// Other modes return `CKR_MECHANISM_INVALID`.
pub fn encrypt(
    _session: u32,
    key_handle: u32,
    mechanism: u32,
    plaintext: &[u8],
    iv: Option<&[u8]>,
) -> Result<Vec<u8>, CkRv> {
    if !check_flag(key_handle, CKA_ENCRYPT) {
        return Err(CKR_KEY_FUNCTION_NOT_PERMITTED);
    }
    let key_bytes = get_object_value(key_handle).ok_or(CKR_ARGUMENTS_BAD)?;

    match mechanism {
        CKM_AES_GCM => {
            let iv = iv.ok_or(CKR_ARGUMENTS_BAD)?;
            // Handle-based encrypt has no AAD plumbing yet — use empty.
            // KMIP callers that need AEAD with AAD go through
            // `encrypt_with_key_bytes` instead.
            aes_gcm_encrypt(&key_bytes, iv, plaintext, &[], None)
        }
        CKM_AES_ECB => aes_ecb_encrypt(&key_bytes, plaintext),
        CKM_AES_CBC => {
            let iv = iv.ok_or(CKR_ARGUMENTS_BAD)?;
            aes_cbc_encrypt(&key_bytes, iv, plaintext)
        }
        CKM_AES_CBC_PAD => {
            let iv = iv.ok_or(CKR_ARGUMENTS_BAD)?;
            aes_cbc_pad_encrypt(&key_bytes, iv, plaintext)
        }
        CKM_AES_CTR => {
            let iv = iv.ok_or(CKR_ARGUMENTS_BAD)?;
            aes_ctr_apply(&key_bytes, iv, plaintext)
        }
        CKM_CHACHA20 => {
            let iv = iv.ok_or(CKR_ARGUMENTS_BAD)?;
            chacha20_encrypt(&key_bytes, iv, plaintext)
        }
        CKM_CHACHA20_POLY1305 => {
            let iv = iv.ok_or(CKR_ARGUMENTS_BAD)?;
            chacha20_poly1305_encrypt(&key_bytes, iv, plaintext, &[])
        }
        CKM_RSA_PKCS_OAEP => {
            // Handle-based path doesn't carry parameters yet; defaults
            // to SHA-256/MGF1-SHA-256/no-label (the Baseline default).
            rsa_oaep_encrypt(&key_bytes, plaintext, &OaepParams::sha256_default())
        }
        _ => Err(CKR_MECHANISM_INVALID),
    }
}

/// Classical decrypt. See [`encrypt`] for the mechanism table.
pub fn decrypt(
    _session: u32,
    key_handle: u32,
    mechanism: u32,
    ciphertext: &[u8],
    iv: Option<&[u8]>,
) -> Result<Vec<u8>, CkRv> {
    if !check_flag(key_handle, CKA_DECRYPT) {
        return Err(CKR_KEY_FUNCTION_NOT_PERMITTED);
    }
    let key_bytes = get_object_value(key_handle).ok_or(CKR_ARGUMENTS_BAD)?;

    match mechanism {
        CKM_AES_GCM => {
            let iv = iv.ok_or(CKR_ARGUMENTS_BAD)?;
            aes_gcm_decrypt(&key_bytes, iv, ciphertext, &[], None)
        }
        CKM_AES_ECB => aes_ecb_decrypt(&key_bytes, ciphertext),
        CKM_AES_CBC => {
            let iv = iv.ok_or(CKR_ARGUMENTS_BAD)?;
            aes_cbc_decrypt(&key_bytes, iv, ciphertext)
        }
        CKM_AES_CBC_PAD => {
            let iv = iv.ok_or(CKR_ARGUMENTS_BAD)?;
            aes_cbc_pad_decrypt(&key_bytes, iv, ciphertext)
        }
        CKM_AES_CTR => {
            // CTR is self-inverse — same keystream XOR for both directions.
            let iv = iv.ok_or(CKR_ARGUMENTS_BAD)?;
            aes_ctr_apply(&key_bytes, iv, ciphertext)
        }
        CKM_CHACHA20 => {
            let iv = iv.ok_or(CKR_ARGUMENTS_BAD)?;
            // ChaCha20 is symmetric / self-inverse — same primitive
            // for encrypt and decrypt.
            chacha20_encrypt(&key_bytes, iv, ciphertext)
        }
        CKM_CHACHA20_POLY1305 => {
            let iv = iv.ok_or(CKR_ARGUMENTS_BAD)?;
            chacha20_poly1305_decrypt(&key_bytes, iv, ciphertext, &[])
        }
        CKM_RSA_PKCS_OAEP => {
            rsa_oaep_decrypt(&key_bytes, ciphertext, &OaepParams::sha256_default())
        }
        _ => Err(CKR_MECHANISM_INVALID),
    }
}

/// OAEP padding parameters per PKCS#11 v3.2 §6.13 (`CK_RSA_PKCS_OAEP_PARAMS`).
/// Used by [`encrypt_with_key_bytes`] / [`decrypt_with_key_bytes`] when
/// the mechanism is `CKM_RSA_PKCS_OAEP`; the KMIP layer reads these
/// fields off the key's `CryptographicParameters` attribute (KMIP 3.0
/// §11 — `HashingAlgorithm`, `MaskGenerator`, `MaskGeneratorHashingAlgorithm`,
/// `PSource`).
#[derive(Clone, Copy, Debug)]
pub enum OaepHash {
    /// PKCS#11 `CKM_SHA256` codepoint 0x250.
    Sha256,
    /// PKCS#11 `CKM_SHA384` codepoint 0x260.
    Sha384,
    /// PKCS#11 `CKM_SHA512` codepoint 0x270.
    Sha512,
}

#[derive(Clone, Debug, Default)]
pub struct OaepParams<'a> {
    pub hash: Option<OaepHash>,
    pub mgf_hash: Option<OaepHash>,
    /// `pSourceData` — OAEP label bytes. None ≡ empty label.
    pub label: Option<&'a [u8]>,
}

impl OaepParams<'_> {
    /// SHA-256 hash + MGF1-SHA-256 + empty label — the simplest
    /// profile, used when the KMIP key carries no
    /// `CryptographicParameters` at all.
    pub fn sha256_default() -> Self {
        Self {
            hash: Some(OaepHash::Sha256),
            mgf_hash: Some(OaepHash::Sha256),
            label: None,
        }
    }
}

/// Encrypt with raw key bytes — bypass the engine lookup. KMIP
/// `Register` stores the client-supplied key bytes outside the
/// engine, so calls from that path need a direct entry point. The
/// mechanism semantics are identical to [`encrypt`] but for
/// `CKM_RSA_PKCS_OAEP` the caller can pass `oaep` to override the
/// default SHA-256 / MGF1-SHA-256 / no-label profile.
///
/// Returns the same `CkRv` codes as [`encrypt`] so the KMIP error
/// mapping in `ops/helpers.rs::ck_rv_to_kmip_error` carries through.
pub fn encrypt_with_key_bytes(
    key_bytes: &[u8],
    mechanism: u32,
    plaintext: &[u8],
    iv: Option<&[u8]>,
    oaep: Option<&OaepParams>,
    aad: &[u8],
    tag_len: Option<usize>,
) -> Result<Vec<u8>, CkRv> {
    match mechanism {
        CKM_AES_GCM => {
            let iv = iv.ok_or(CKR_ARGUMENTS_BAD)?;
            aes_gcm_encrypt(key_bytes, iv, plaintext, aad, tag_len)
        }
        CKM_AES_ECB => aes_ecb_encrypt(key_bytes, plaintext),
        CKM_AES_CBC => {
            let iv = iv.ok_or(CKR_ARGUMENTS_BAD)?;
            aes_cbc_encrypt(key_bytes, iv, plaintext)
        }
        CKM_AES_CBC_PAD => {
            let iv = iv.ok_or(CKR_ARGUMENTS_BAD)?;
            aes_cbc_pad_encrypt(key_bytes, iv, plaintext)
        }
        CKM_AES_CTR => {
            let iv = iv.ok_or(CKR_ARGUMENTS_BAD)?;
            aes_ctr_apply(key_bytes, iv, plaintext)
        }
        CKM_CHACHA20 => {
            let iv = iv.ok_or(CKR_ARGUMENTS_BAD)?;
            chacha20_encrypt(key_bytes, iv, plaintext)
        }
        CKM_CHACHA20_POLY1305 => {
            let iv = iv.ok_or(CKR_ARGUMENTS_BAD)?;
            chacha20_poly1305_encrypt(key_bytes, iv, plaintext, aad)
        }
        CKM_RSA_PKCS_OAEP => {
            let default = OaepParams::sha256_default();
            let p = oaep.unwrap_or(&default);
            rsa_oaep_encrypt(key_bytes, plaintext, p)
        }
        _ => Err(CKR_MECHANISM_INVALID),
    }
}

/// Decrypt with raw key bytes — symmetric counterpart to
/// [`encrypt_with_key_bytes`].
pub fn decrypt_with_key_bytes(
    key_bytes: &[u8],
    mechanism: u32,
    ciphertext: &[u8],
    iv: Option<&[u8]>,
    oaep: Option<&OaepParams>,
    aad: &[u8],
    tag_len: Option<usize>,
) -> Result<Vec<u8>, CkRv> {
    match mechanism {
        CKM_AES_GCM => {
            let iv = iv.ok_or(CKR_ARGUMENTS_BAD)?;
            aes_gcm_decrypt(key_bytes, iv, ciphertext, aad, tag_len)
        }
        CKM_AES_ECB => aes_ecb_decrypt(key_bytes, ciphertext),
        CKM_AES_CBC => {
            let iv = iv.ok_or(CKR_ARGUMENTS_BAD)?;
            aes_cbc_decrypt(key_bytes, iv, ciphertext)
        }
        CKM_AES_CBC_PAD => {
            let iv = iv.ok_or(CKR_ARGUMENTS_BAD)?;
            aes_cbc_pad_decrypt(key_bytes, iv, ciphertext)
        }
        CKM_AES_CTR => {
            // CTR is self-inverse — same keystream XOR for both directions.
            let iv = iv.ok_or(CKR_ARGUMENTS_BAD)?;
            aes_ctr_apply(key_bytes, iv, ciphertext)
        }
        CKM_CHACHA20 => {
            let iv = iv.ok_or(CKR_ARGUMENTS_BAD)?;
            chacha20_encrypt(key_bytes, iv, ciphertext)
        }
        CKM_CHACHA20_POLY1305 => {
            let iv = iv.ok_or(CKR_ARGUMENTS_BAD)?;
            chacha20_poly1305_decrypt(key_bytes, iv, ciphertext, aad)
        }
        CKM_RSA_PKCS_OAEP => {
            let default = OaepParams::sha256_default();
            let p = oaep.unwrap_or(&default);
            rsa_oaep_decrypt(key_bytes, ciphertext, p)
        }
        _ => Err(CKR_MECHANISM_INVALID),
    }
}

// ── RSA-OAEP ────────────────────────────────────────────────────────────────

/// Parse an RSA public key from either X.509 SubjectPublicKeyInfo
/// (KMIP `KeyFormatType = X_509`, the most common Register form) or
/// PKCS#1 raw `RSAPublicKey` DER (KMIP `KeyFormatType = PKCS_1`).
fn rsa_public_key_from_any_der(bytes: &[u8]) -> Result<rsa::RsaPublicKey, CkRv> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::pkcs8::DecodePublicKey;
    rsa::RsaPublicKey::from_public_key_der(bytes)
        .or_else(|_| rsa::RsaPublicKey::from_pkcs1_der(bytes))
        .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)
}

/// Parse an RSA private key from either PKCS#8 PrivateKeyInfo (KMIP
/// `KeyFormatType = PKCS_8`) or PKCS#1 raw `RSAPrivateKey` DER (KMIP
/// `KeyFormatType = PKCS_1`).
fn rsa_private_key_from_any_der(bytes: &[u8]) -> Result<rsa::RsaPrivateKey, CkRv> {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs8::DecodePrivateKey;
    rsa::RsaPrivateKey::from_pkcs8_der(bytes)
        .or_else(|_| rsa::RsaPrivateKey::from_pkcs1_der(bytes))
        .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)
}

/// Build an [`rsa::Oaep`] from `(hash, mgf_hash, label)`. The `rsa`
/// crate's constructor is generic over `T: Digest + DynDigest`, so
/// runtime hash selection means picking one of the SHA-2 variants
/// at every callsite. All five OAEP-family OASIS conformance tests
/// reach this matrix (SHA-256 / SHA-384 / SHA-512 in either slot).
fn oaep_for(p: &OaepParams) -> rsa::Oaep {
    let h = p.hash.unwrap_or(OaepHash::Sha256);
    let m = p.mgf_hash.unwrap_or(h);
    macro_rules! mk {
        ($H:ty, $M:ty) => {
            match p.label {
                Some(l) => {
                    let s = String::from_utf8_lossy(l).into_owned();
                    rsa::Oaep::new_with_mgf_hash_and_label::<$H, $M, String>(s)
                }
                None => rsa::Oaep::new_with_mgf_hash::<$H, $M>(),
            }
        };
    }
    match (h, m) {
        (OaepHash::Sha256, OaepHash::Sha256) => mk!(sha2::Sha256, sha2::Sha256),
        (OaepHash::Sha256, OaepHash::Sha384) => mk!(sha2::Sha256, sha2::Sha384),
        (OaepHash::Sha256, OaepHash::Sha512) => mk!(sha2::Sha256, sha2::Sha512),
        (OaepHash::Sha384, OaepHash::Sha256) => mk!(sha2::Sha384, sha2::Sha256),
        (OaepHash::Sha384, OaepHash::Sha384) => mk!(sha2::Sha384, sha2::Sha384),
        (OaepHash::Sha384, OaepHash::Sha512) => mk!(sha2::Sha384, sha2::Sha512),
        (OaepHash::Sha512, OaepHash::Sha256) => mk!(sha2::Sha512, sha2::Sha256),
        (OaepHash::Sha512, OaepHash::Sha384) => mk!(sha2::Sha512, sha2::Sha384),
        (OaepHash::Sha512, OaepHash::Sha512) => mk!(sha2::Sha512, sha2::Sha512),
    }
}

/// RSA OAEP encrypt — accepts both X.509 SPKI and PKCS#1 RSAPublicKey
/// DER for the public-key bytes.
fn rsa_oaep_encrypt(pub_der: &[u8], plaintext: &[u8], params: &OaepParams) -> Result<Vec<u8>, CkRv> {
    let public_key = rsa_public_key_from_any_der(pub_der)?;
    let padding = oaep_for(params);
    let mut rng = rand::rngs::OsRng;
    public_key
        .encrypt(&mut rng, padding, plaintext)
        .map_err(|_| CKR_FUNCTION_FAILED)
}

/// RSA OAEP decrypt — accepts both PKCS#8 PrivateKeyInfo and PKCS#1
/// RSAPrivateKey DER. CS-AC-M-OAEP-10 registers with
/// `KeyFormatType=PKCS_1`, `HashingAlgorithm=SHA_384`,
/// `MaskGeneratorHashingAlgorithm=SHA_256`, and a `PSource` label.
fn rsa_oaep_decrypt(priv_der: &[u8], ciphertext: &[u8], params: &OaepParams) -> Result<Vec<u8>, CkRv> {
    let private_key = rsa_private_key_from_any_der(priv_der)?;
    let padding = oaep_for(params);
    private_key
        .decrypt(padding, ciphertext)
        // PKCS#11 v3.2 §6.13 — OAEP decode failure on RSA decrypt
        // surfaces as CKR_ENCRYPTED_DATA_INVALID, matching the AES-GCM
        // branch's tag-failure semantics.
        .map_err(|_| CKR_ENCRYPTED_DATA_INVALID)
}

// ── AES-GCM ─────────────────────────────────────────────────────────────────

/// AES-GCM encrypt with caller-selectable tag length and IV length.
///
/// `tag_len`: tag size in bytes (default 16; NIST SP 800-38D §5.2.1.2
/// allows 12–16). `iv`: any length ≥ 1 — non-96-bit IVs derive J0 via
/// GHASH per §7.1 step 2b (OASIS CS-BC-M-GCM-2 pins 8- and 60-byte
/// IVs). Backed by the KAT-verified streaming `GcmState`, which also
/// covers AES-192 — the one-shot `aes-gcm` crate handles neither
/// arbitrary IV lengths nor 24-byte keys.
fn aes_gcm_encrypt(
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
    aad: &[u8],
    tag_len: Option<usize>,
) -> Result<Vec<u8>, CkRv> {
    use crate::crypto::multipart::{AesKey, CipherDirection, GcmState, MultipartCipher};
    if iv.is_empty() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    let k = AesKey::new(key).ok_or(CKR_KEY_TYPE_INCONSISTENT)?;
    let tag_bits = (tag_len.unwrap_or(16) as u32) * 8;
    let mut st =
        MultipartCipher::Gcm(GcmState::new(k, iv, aad, tag_bits, CipherDirection::Encrypt));
    let mut out = st.update(plaintext)?;
    out.extend_from_slice(&st.finalize()?);
    Ok(out)
}

/// AES-GCM decrypt. `ciphertext` carries the tag appended (the shim
/// convention); tag verification failure → `CKR_ENCRYPTED_DATA_INVALID`.
fn aes_gcm_decrypt(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
    tag_len: Option<usize>,
) -> Result<Vec<u8>, CkRv> {
    use crate::crypto::multipart::{AesKey, CipherDirection, GcmState, MultipartCipher};
    if iv.is_empty() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    let k = AesKey::new(key).ok_or(CKR_KEY_TYPE_INCONSISTENT)?;
    let tag_bits = (tag_len.unwrap_or(16) as u32) * 8;
    let mut st =
        MultipartCipher::Gcm(GcmState::new(k, iv, aad, tag_bits, CipherDirection::Decrypt));
    let mut out = st.update(ciphertext)?;
    out.extend_from_slice(&st.finalize()?);
    Ok(out)
}

// ── AES-KW (RFC 3394 / NIST SP 800-38F KW-AE) ──────────────────────────────

/// AES Key Wrap with raw KEK bytes — the `native` counterpart of
/// `ffi::C_WrapKey(CKM_AES_KEY_WRAP)`. `plaintext` must be a multiple
/// of 8 bytes and ≥ 16 (RFC 3394 §2.2.1); output is 8 bytes longer.
/// KMIP callers (Get with `KeyWrappingSpecification`, BlockCipherMode
/// `NISTKeyWrap`) wrap the TTLV-encoded KeyValue, which is 8-aligned
/// by construction (TTLV §9.6 pads every frame to 8 bytes).
pub fn aes_key_wrap(kek: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CkRv> {
    use aes::cipher::generic_array::GenericArray;
    if plaintext.len() % 8 != 0 || plaintext.len() < 16 {
        return Err(CKR_DATA_LEN_RANGE);
    }
    let mut buf = vec![0u8; plaintext.len() + 8];
    let ok = match kek.len() {
        16 => aes_kw::KekAes128::new(GenericArray::from_slice(kek)).wrap(plaintext, &mut buf).is_ok(),
        24 => aes_kw::KekAes192::new(GenericArray::from_slice(kek)).wrap(plaintext, &mut buf).is_ok(),
        32 => aes_kw::KekAes256::new(GenericArray::from_slice(kek)).wrap(plaintext, &mut buf).is_ok(),
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT),
    };
    if ok { Ok(buf) } else { Err(CKR_FUNCTION_FAILED) }
}

/// AES Key Unwrap (RFC 3394 §2.2.2) — inverse of [`aes_key_wrap`].
/// Integrity-check failure → `CKR_ENCRYPTED_DATA_INVALID`.
pub fn aes_key_unwrap(kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, CkRv> {
    use aes::cipher::generic_array::GenericArray;
    if wrapped.len() % 8 != 0 || wrapped.len() < 24 {
        return Err(CKR_ENCRYPTED_DATA_LEN_RANGE);
    }
    let mut buf = vec![0u8; wrapped.len() - 8];
    let ok = match kek.len() {
        16 => aes_kw::KekAes128::new(GenericArray::from_slice(kek)).unwrap(wrapped, &mut buf).is_ok(),
        24 => aes_kw::KekAes192::new(GenericArray::from_slice(kek)).unwrap(wrapped, &mut buf).is_ok(),
        32 => aes_kw::KekAes256::new(GenericArray::from_slice(kek)).unwrap(wrapped, &mut buf).is_ok(),
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT),
    };
    if ok { Ok(buf) } else { Err(CKR_ENCRYPTED_DATA_INVALID) }
}

// ── AES-ECB ────────────────────────────────────────────────────────────────
//
// PKCS#11 v3.2 §6.10 — `CKM_AES_ECB`. No IV, no padding. The plaintext
// length MUST be a positive multiple of the AES block size (16); the
// ciphertext is the same length. We refuse non-multiple-of-16 inputs
// with `CKR_DATA_LEN_RANGE` to match the spec.

fn aes_ecb_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CkRv> {
    use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
    if plaintext.is_empty() || plaintext.len() % 16 != 0 {
        return Err(CKR_DATA_LEN_RANGE);
    }
    let mut out = plaintext.to_vec();
    fn enc<C: BlockEncrypt + KeyInit>(k: &[u8], buf: &mut [u8]) -> Result<(), CkRv> {
        let cipher = C::new_from_slice(k).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
        for block in buf.chunks_exact_mut(16) {
            cipher.encrypt_block(GenericArray::from_mut_slice(block));
        }
        Ok(())
    }
    match key.len() {
        16 => enc::<aes::Aes128>(key, &mut out)?,
        32 => enc::<aes::Aes256>(key, &mut out)?,
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT),
    }
    Ok(out)
}

fn aes_ecb_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CkRv> {
    use aes::cipher::{BlockDecrypt, KeyInit, generic_array::GenericArray};
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return Err(CKR_ENCRYPTED_DATA_LEN_RANGE);
    }
    let mut out = ciphertext.to_vec();
    fn dec<C: BlockDecrypt + KeyInit>(k: &[u8], buf: &mut [u8]) -> Result<(), CkRv> {
        let cipher = C::new_from_slice(k).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
        for block in buf.chunks_exact_mut(16) {
            cipher.decrypt_block(GenericArray::from_mut_slice(block));
        }
        Ok(())
    }
    match key.len() {
        16 => dec::<aes::Aes128>(key, &mut out)?,
        32 => dec::<aes::Aes256>(key, &mut out)?,
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT),
    }
    Ok(out)
}

// ── AES-CBC ────────────────────────────────────────────────────────────────
//
// PKCS#11 v3.2 §6.10 — `CKM_AES_CBC`. Requires a 16-byte IV; plaintext
// MUST be a multiple of 16 (no padding). Use `CKM_AES_CBC_PAD` (not
// implemented here) for PKCS#7 padding.

fn aes_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CkRv> {
    use cbc::cipher::{BlockEncryptMut, KeyIvInit};
    if iv.len() != 16 {
        return Err(CKR_ARGUMENTS_BAD);
    }
    if plaintext.is_empty() || plaintext.len() % 16 != 0 {
        return Err(CKR_DATA_LEN_RANGE);
    }
    let mut out = vec![0u8; plaintext.len()];
    match key.len() {
        16 => {
            let cipher = cbc::Encryptor::<aes::Aes128>::new_from_slices(key, iv)
                .map_err(|_| CKR_ARGUMENTS_BAD)?;
            cipher
                .encrypt_padded_b2b_mut::<aes::cipher::block_padding::NoPadding>(plaintext, &mut out)
                .map_err(|_| CKR_FUNCTION_FAILED)?;
        }
        32 => {
            let cipher = cbc::Encryptor::<aes::Aes256>::new_from_slices(key, iv)
                .map_err(|_| CKR_ARGUMENTS_BAD)?;
            cipher
                .encrypt_padded_b2b_mut::<aes::cipher::block_padding::NoPadding>(plaintext, &mut out)
                .map_err(|_| CKR_FUNCTION_FAILED)?;
        }
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT),
    }
    Ok(out)
}

// ── AES-CBC with PKCS#7 padding ────────────────────────────────────────────
//
// PKCS#11 v3.2 §6.10 — `CKM_AES_CBC_PAD`. CBC + PKCS#7 padding (so
// arbitrary-length plaintext is allowed). The ciphertext is always a
// multiple of 16. KMIP 3.0 §11 `Padding Method = PKCS5` (codepoint 3)
// together with `Block Cipher Mode = CBC` selects this in the KMIP
// layer.

fn aes_cbc_pad_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CkRv> {
    use cbc::cipher::{BlockEncryptMut, KeyIvInit};
    if iv.len() != 16 {
        return Err(CKR_ARGUMENTS_BAD);
    }
    // PKCS#7 grows the buffer by 1..=16 bytes; round up to the next
    // multiple of 16.
    let out_len = (plaintext.len() / 16 + 1) * 16;
    let mut out = vec![0u8; out_len];
    match key.len() {
        16 => {
            let cipher = cbc::Encryptor::<aes::Aes128>::new_from_slices(key, iv)
                .map_err(|_| CKR_ARGUMENTS_BAD)?;
            cipher
                .encrypt_padded_b2b_mut::<aes::cipher::block_padding::Pkcs7>(plaintext, &mut out)
                .map_err(|_| CKR_FUNCTION_FAILED)?;
        }
        32 => {
            let cipher = cbc::Encryptor::<aes::Aes256>::new_from_slices(key, iv)
                .map_err(|_| CKR_ARGUMENTS_BAD)?;
            cipher
                .encrypt_padded_b2b_mut::<aes::cipher::block_padding::Pkcs7>(plaintext, &mut out)
                .map_err(|_| CKR_FUNCTION_FAILED)?;
        }
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT),
    }
    Ok(out)
}

fn aes_cbc_pad_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CkRv> {
    use cbc::cipher::{BlockDecryptMut, KeyIvInit};
    if iv.len() != 16 {
        return Err(CKR_ARGUMENTS_BAD);
    }
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return Err(CKR_ENCRYPTED_DATA_LEN_RANGE);
    }
    let mut out = vec![0u8; ciphertext.len()];
    let plain_len = match key.len() {
        16 => {
            let cipher = cbc::Decryptor::<aes::Aes128>::new_from_slices(key, iv)
                .map_err(|_| CKR_ARGUMENTS_BAD)?;
            cipher
                .decrypt_padded_b2b_mut::<aes::cipher::block_padding::Pkcs7>(ciphertext, &mut out)
                .map_err(|_| CKR_ENCRYPTED_DATA_INVALID)?
                .len()
        }
        32 => {
            let cipher = cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv)
                .map_err(|_| CKR_ARGUMENTS_BAD)?;
            cipher
                .decrypt_padded_b2b_mut::<aes::cipher::block_padding::Pkcs7>(ciphertext, &mut out)
                .map_err(|_| CKR_ENCRYPTED_DATA_INVALID)?
                .len()
        }
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT),
    };
    out.truncate(plain_len);
    Ok(out)
}

// ── AES-CTR ────────────────────────────────────────────────────────────────
//
// PKCS#11 v3.2 §6.10 — `CKM_AES_CTR`. `iv` is the full 16-byte initial
// counter block (`CK_AES_CTR_PARAMS.cb`); the stream is self-inverse so
// one helper serves both directions. Backed by the KAT-verified
// streaming `CtrState` (NIST SP 800-38A §6.5 increment function),
// which also covers AES-192.

fn aes_ctr_apply(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, CkRv> {
    use crate::crypto::multipart::{AesKey, CtrState, MultipartCipher};
    let cb: [u8; 16] = iv.try_into().map_err(|_| CKR_ARGUMENTS_BAD)?;
    let k = AesKey::new(key).ok_or(CKR_KEY_TYPE_INCONSISTENT)?;
    let mut st = MultipartCipher::Ctr(CtrState::new(k, cb));
    let mut out = st.update(data)?;
    out.extend_from_slice(&st.finalize()?);
    Ok(out)
}

// ── ChaCha20 / ChaCha20-Poly1305 ───────────────────────────────────────────
//
// PKCS#11 v3.2 §6.20 — IETF ChaCha20 (32-byte key, 12-byte nonce,
// stream cipher) and ChaCha20-Poly1305 AEAD (RFC 8439). Cipher impls
// live in the `chacha20` + `chacha20poly1305` crates already in our
// `Cargo.toml`.

// pub(crate): the wasm FFI one-shot C_Encrypt/C_Decrypt arms (T1) reuse
// these so the two surfaces stay byte-identical.
pub(crate) fn chacha20_encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CkRv> {
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    if key.len() != 32 {
        return Err(CKR_ARGUMENTS_BAD);
    }
    // PKCS#11 v3.2 §6.20 lets `CKM_CHACHA20` accept either an 8-byte
    // (RFC 7539 "legacy" / DJB original) or 12-byte (IETF) nonce.
    // OASIS BC-CHACHA20-* tests use the 8-byte legacy form.
    let mut buf = plaintext.to_vec();
    match nonce.len() {
        8 => {
            let mut cipher = chacha20::ChaCha20Legacy::new(key.into(), nonce.into());
            cipher.apply_keystream(&mut buf);
        }
        12 => {
            let mut cipher = chacha20::ChaCha20::new(key.into(), nonce.into());
            cipher.apply_keystream(&mut buf);
        }
        _ => return Err(CKR_ARGUMENTS_BAD),
    }
    Ok(buf)
}

pub(crate) fn chacha20_poly1305_encrypt(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CkRv> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
    if key.len() != 32 || nonce.len() != 12 {
        return Err(CKR_ARGUMENTS_BAD);
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| CKR_FUNCTION_FAILED)
}

pub(crate) fn chacha20_poly1305_decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CkRv> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
    if key.len() != 32 || nonce.len() != 12 {
        return Err(CKR_ARGUMENTS_BAD);
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| CKR_ENCRYPTED_DATA_INVALID)
}

fn aes_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CkRv> {
    use cbc::cipher::{BlockDecryptMut, KeyIvInit};
    if iv.len() != 16 {
        return Err(CKR_ARGUMENTS_BAD);
    }
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return Err(CKR_ENCRYPTED_DATA_LEN_RANGE);
    }
    let mut out = vec![0u8; ciphertext.len()];
    match key.len() {
        16 => {
            let cipher = cbc::Decryptor::<aes::Aes128>::new_from_slices(key, iv)
                .map_err(|_| CKR_ARGUMENTS_BAD)?;
            cipher
                .decrypt_padded_b2b_mut::<aes::cipher::block_padding::NoPadding>(ciphertext, &mut out)
                .map_err(|_| CKR_ENCRYPTED_DATA_INVALID)?;
        }
        32 => {
            let cipher = cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv)
                .map_err(|_| CKR_ARGUMENTS_BAD)?;
            cipher
                .decrypt_padded_b2b_mut::<aes::cipher::block_padding::NoPadding>(ciphertext, &mut out)
                .map_err(|_| CKR_ENCRYPTED_DATA_INVALID)?;
        }
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT),
    }
    Ok(out)
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Check a single CK_BBOOL attribute on the key. Returns `false` if the
/// key is missing or the flag is not set. Mirrors `check_can_sign`
/// in [`super::sign`].
fn check_flag(key_handle: u32, attr_type: u32) -> bool {
    OBJECTS.with(|o| {
        o.borrow()
            .get(&key_handle)
            .and_then(|attrs| attrs.get(&attr_type))
            .map(|v| !v.is_empty() && v[0] == 0x01)
            .unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::keygen::{generate_ml_dsa_keypair, generate_ml_kem_keypair};
    use crate::native::session::{bootstrap_default_token, close_session, finalize, init};
    use crate::native::test_lock;

    /// RFC 3394 §4.1 — wrap 128 bits of key data with a 128-bit KEK.
    #[test]
    fn aes_key_wrap_rfc3394_kat() {
        let kek: Vec<u8> = (0x00..=0x0f).collect();
        let pt: Vec<u8> = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];
        let expected = [
            0x1f, 0xa6, 0x8b, 0x0a, 0x81, 0x12, 0xb4, 0x47,
            0xae, 0xf3, 0x4b, 0xd8, 0xfb, 0x5a, 0x7b, 0x82,
            0x9d, 0x3e, 0x86, 0x23, 0x71, 0xd2, 0xcf, 0xe5,
        ];
        let wrapped = aes_key_wrap(&kek, &pt).unwrap();
        assert_eq!(wrapped, expected);
        assert_eq!(aes_key_unwrap(&kek, &wrapped).unwrap(), pt);
        // Tampered ciphertext → integrity-check failure.
        let mut bad = wrapped.clone();
        bad[0] ^= 1;
        assert_eq!(aes_key_unwrap(&kek, &bad).unwrap_err(), CKR_ENCRYPTED_DATA_INVALID);
        // Non-8-multiple input rejected per RFC 3394 §2.2.1.
        assert_eq!(aes_key_wrap(&kek, &pt[..15]).unwrap_err(), CKR_DATA_LEN_RANGE);
    }

    fn fresh_session() -> u32 {
        let _ = finalize();
        init().unwrap();
        bootstrap_default_token(0, "so", "user", "native-encap-test").unwrap()
    }

    /// ML-KEM-768 round-trip: keygen → encap(pub_h) → decap(prv_h, ct) →
    /// shared secrets match exactly. FIPS 203 §7.4 — ct=1088, ss=32.
    #[test]
    fn ml_kem_768_encap_decap_round_trip() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) =
            generate_ml_kem_keypair(session, CKP_ML_KEM_768, b"\x01", "kem-768").unwrap();

        let (ct, ss_enc) = encapsulate(session, pub_h, CKM_ML_KEM).unwrap();
        assert_eq!(ct.len(), 1088, "FIPS 203 §7.4 ML-KEM-768 ct = 1088 bytes");
        assert_eq!(ss_enc.len(), 32, "FIPS 203 §7.4 ML-KEM-768 ss = 32 bytes");

        let ss_dec = decapsulate(session, prv_h, CKM_ML_KEM, &ct).unwrap();
        assert_eq!(ss_enc, ss_dec, "encap SS must equal decap SS");

        close_session(session).unwrap();
    }

    /// ML-KEM-512: ct=768, ss=32 (FIPS 203 §7.4).
    #[test]
    fn ml_kem_512_encap_decap_round_trip() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) =
            generate_ml_kem_keypair(session, CKP_ML_KEM_512, b"\x01", "kem-512").unwrap();
        let (ct, ss_enc) = encapsulate(session, pub_h, CKM_ML_KEM).unwrap();
        assert_eq!(ct.len(), 768);
        assert_eq!(ss_enc.len(), 32);
        let ss_dec = decapsulate(session, prv_h, CKM_ML_KEM, &ct).unwrap();
        assert_eq!(ss_enc, ss_dec);
        close_session(session).unwrap();
    }

    /// ML-KEM-1024: ct=1568, ss=32.
    #[test]
    fn ml_kem_1024_encap_decap_round_trip() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) =
            generate_ml_kem_keypair(session, CKP_ML_KEM_1024, b"\x01", "kem-1024").unwrap();
        let (ct, ss_enc) = encapsulate(session, pub_h, CKM_ML_KEM).unwrap();
        assert_eq!(ct.len(), 1568);
        let ss_dec = decapsulate(session, prv_h, CKM_ML_KEM, &ct).unwrap();
        assert_eq!(ss_enc, ss_dec);
        close_session(session).unwrap();
    }

    /// Encap with the private-key handle (CKA_ENCAPSULATE = false on
    /// private side) → CKR_KEY_FUNCTION_NOT_PERMITTED.
    #[test]
    fn encap_with_private_key_handle_is_denied() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (_pub_h, prv_h) =
            generate_ml_kem_keypair(session, CKP_ML_KEM_768, b"\x01", "denied").unwrap();
        let result = encapsulate(session, prv_h, CKM_ML_KEM);
        assert_eq!(result.unwrap_err(), CKR_KEY_FUNCTION_NOT_PERMITTED);
        close_session(session).unwrap();
    }

    /// Decap with the public-key handle (CKA_DECAPSULATE = false on
    /// public side) → CKR_KEY_FUNCTION_NOT_PERMITTED.
    #[test]
    fn decap_with_public_key_handle_is_denied() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, _prv_h) =
            generate_ml_kem_keypair(session, CKP_ML_KEM_768, b"\x01", "denied").unwrap();
        let bogus_ct = vec![0u8; 1088];
        let result = decapsulate(session, pub_h, CKM_ML_KEM, &bogus_ct);
        assert_eq!(result.unwrap_err(), CKR_KEY_FUNCTION_NOT_PERMITTED);
        close_session(session).unwrap();
    }

    /// Encap on an ML-DSA key (CKA_ENCAPSULATE=false on signing keys) →
    /// CKR_KEY_FUNCTION_NOT_PERMITTED. Cross-family permission check.
    #[test]
    fn ml_dsa_key_cannot_encapsulate() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, _) =
            generate_ml_dsa_keypair(session, CKP_ML_DSA_65, b"\x01", "dsa-not-kem").unwrap();
        let result = encapsulate(session, pub_h, CKM_ML_KEM);
        assert_eq!(result.unwrap_err(), CKR_KEY_FUNCTION_NOT_PERMITTED);
        close_session(session).unwrap();
    }

    /// Wrong mechanism on encap → CKR_MECHANISM_INVALID.
    #[test]
    fn encap_with_wrong_mechanism_returns_err() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, _) =
            generate_ml_kem_keypair(session, CKP_ML_KEM_768, b"\x01", "wrong-mech").unwrap();
        let result = encapsulate(session, pub_h, CKM_ML_DSA);
        assert_eq!(result.unwrap_err(), CKR_MECHANISM_INVALID);
        close_session(session).unwrap();
    }

    /// Decap with wrong-length ciphertext → CKR_ARGUMENTS_BAD.
    #[test]
    fn decap_with_wrong_ciphertext_length_returns_err() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (_pub_h, prv_h) =
            generate_ml_kem_keypair(session, CKP_ML_KEM_768, b"\x01", "wrong-len").unwrap();
        // ML-KEM-768 expects ct.len() == 1088; pass 1024.
        let result = decapsulate(session, prv_h, CKM_ML_KEM, &vec![0u8; 1024]);
        assert_eq!(result.unwrap_err(), CKR_ARGUMENTS_BAD);
        close_session(session).unwrap();
    }

    /// Distinct encap calls produce different ciphertexts but valid
    /// decap each time (probabilistic encapsulation per FIPS 203 §6.2).
    #[test]
    fn encap_is_probabilistic_but_decap_recovers_each_time() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) =
            generate_ml_kem_keypair(session, CKP_ML_KEM_768, b"\x01", "probabilistic").unwrap();
        let (ct1, ss1) = encapsulate(session, pub_h, CKM_ML_KEM).unwrap();
        let (ct2, ss2) = encapsulate(session, pub_h, CKM_ML_KEM).unwrap();
        // Two distinct ciphertexts (overwhelming probability — both
        // sampled from a 256-bit random space).
        assert_ne!(ct1, ct2, "encap must be probabilistic");
        assert_ne!(ss1, ss2);
        // Each decapsulates to its own SS.
        assert_eq!(decapsulate(session, prv_h, CKM_ML_KEM, &ct1).unwrap(), ss1);
        assert_eq!(decapsulate(session, prv_h, CKM_ML_KEM, &ct2).unwrap(), ss2);
        close_session(session).unwrap();
    }

    /// S5 (compliance-audit P-10): encap/decap on a non-ML-KEM key
    /// (AES secret key with the KEM usage flags forced on so the
    /// permission check passes) → CKR_KEY_TYPE_INCONSISTENT.
    #[test]
    fn encap_decap_on_aes_key_is_key_type_inconsistent() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let h_aes: u32 = 0x4E4B_0001;
        OBJECTS.with(|o| {
            let mut attrs = crate::crypto::handlers::Attributes::new();
            attrs.insert(CKA_VALUE, vec![0x42u8; 32]);
            crate::state::store_ulong(&mut attrs, CKA_CLASS, CKO_SECRET_KEY);
            crate::state::store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_AES);
            crate::state::store_bool(&mut attrs, CKA_ENCAPSULATE, true);
            crate::state::store_bool(&mut attrs, CKA_DECAPSULATE, true);
            o.borrow_mut().insert(h_aes, attrs);
        });
        assert_eq!(
            encapsulate(session, h_aes, CKM_ML_KEM).unwrap_err(),
            CKR_KEY_TYPE_INCONSISTENT
        );
        assert_eq!(
            decapsulate(session, h_aes, CKM_ML_KEM, &[0u8; 1088]).unwrap_err(),
            CKR_KEY_TYPE_INCONSISTENT
        );
        OBJECTS.with(|o| o.borrow_mut().remove(&h_aes));
        close_session(session).unwrap();
    }

    /// S5 (compliance-audit P-10): an ML-KEM object with no
    /// CKA_PARAMETER_SET no longer silently defaults to ML-KEM-768 —
    /// CKR_TEMPLATE_INCOMPLETE. Keygen always stores a param set since
    /// S3, so the broken object is hand-built in the store.
    #[test]
    fn encap_decap_without_param_set_is_template_incomplete() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let h_kem: u32 = 0x4E4B_0002;
        OBJECTS.with(|o| {
            let mut attrs = crate::crypto::handlers::Attributes::new();
            attrs.insert(CKA_VALUE, vec![0u8; 1184]); // ML-KEM-768 ek size
            crate::state::store_ulong(&mut attrs, CKA_CLASS, CKO_PUBLIC_KEY);
            crate::state::store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_ML_KEM);
            crate::state::store_bool(&mut attrs, CKA_ENCAPSULATE, true);
            crate::state::store_bool(&mut attrs, CKA_DECAPSULATE, true);
            // Deliberately NO store_param_set().
            o.borrow_mut().insert(h_kem, attrs);
        });
        assert_eq!(
            encapsulate(session, h_kem, CKM_ML_KEM).unwrap_err(),
            CKR_TEMPLATE_INCOMPLETE
        );
        assert_eq!(
            decapsulate(session, h_kem, CKM_ML_KEM, &[0u8; 1088]).unwrap_err(),
            CKR_TEMPLATE_INCOMPLETE
        );
        OBJECTS.with(|o| o.borrow_mut().remove(&h_kem));
        close_session(session).unwrap();
    }

    /// NIST SP 800-38A F.5.5 — AES-256-CTR one-shot KAT through the
    /// `encrypt_with_key_bytes` / `decrypt_with_key_bytes` dispatch
    /// (K6: KMIP `BlockCipherMode=CTR` routes here).
    #[test]
    fn aes_256_ctr_one_shot_kat_sp800_38a_f55() {
        let key = hex_lit("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let cb = hex_lit("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let pt = hex_lit("6bc1bee22e409f96e93d7e117393172a");
        let expected_ct = hex_lit("601ec313775789a5b7a7f504bbf3d228");
        let ct = encrypt_with_key_bytes(&key, CKM_AES_CTR, &pt, Some(&cb), None, &[], None)
            .expect("CTR encrypt");
        assert_eq!(ct, expected_ct);
        let back = decrypt_with_key_bytes(&key, CKM_AES_CTR, &ct, Some(&cb), None, &[], None)
            .expect("CTR decrypt");
        assert_eq!(back, pt);
        // Counter block must be exactly 16 bytes.
        assert_eq!(
            encrypt_with_key_bytes(&key, CKM_AES_CTR, &pt, Some(&cb[..12]), None, &[], None)
                .unwrap_err(),
            CKR_ARGUMENTS_BAD
        );
    }

    fn hex_lit(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // ── AES-GCM tests deferred to commit 6 alongside generate_aes_key ──────
    //
    // The encrypt() / decrypt() dispatch + aes_gcm_{encrypt,decrypt}
    // helpers are implemented in this commit (mirrors ffi::C_Encrypt's
    // AES-GCM path) but need a real AES key to test against. Commit 6
    // adds `generate_aes_key(session, bits, cka_id, label)` and the
    // round-trip tests land alongside it.
}
