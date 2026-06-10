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
use crate::state::{get_object_param_set, get_object_value, OBJECTS};

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

    let ps = get_object_param_set(public_key_handle);
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
        CKP_ML_KEM_768 | 0 => {
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

    let ps = get_object_param_set(private_key_handle);
    let expected_ct_len: usize = match ps {
        CKP_ML_KEM_512 => 768,
        CKP_ML_KEM_768 | 0 => 1088,
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
        CKP_ML_KEM_768 | 0 => {
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
/// - `CKM_RSA_PKCS_OAEP`: RSA OAEP with **SHA-256** hash + MGF1-SHA-256
///   (the only OAEP profile the OASIS Baseline corpus exercises;
///   §11.x lists the full set). Public key is stored as X.509
///   SubjectPublicKeyInfo DER (the form `C_RegisterObject` accepts
///   from the KMIP `Register` op).
///
/// Other modes (AES-CBC, AES-CTR, other OAEP hashes) return
/// `CKR_MECHANISM_INVALID`.
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

/// AES-GCM encrypt with caller-selectable tag length.
///
/// `tag_len`: tag size in bytes (default 16; NIST SP 800-38D §5.2.1.2
/// allows 12, 13, 14, 15, 16). Smaller tags reduce on-wire size at the
/// cost of forgery probability. CS-BC-M-GCM-1 step #6 pins a 12-byte
/// tag against the standard NIST AES-128-GCM test vector.
fn aes_gcm_encrypt(
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
    aad: &[u8],
    tag_len: Option<usize>,
) -> Result<Vec<u8>, CkRv> {
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::aead::generic_array::typenum::{U12, U16};
    use aes_gcm::{aead::{Aead, Payload}, AesGcm, Aes128Gcm, Aes256Gcm, KeyInit};
    if iv.len() != 12 {
        return Err(CKR_ARGUMENTS_BAD);
    }
    let nonce = GenericArray::from_slice(iv);
    let payload = Payload { msg: plaintext, aad };
    match (key.len(), tag_len.unwrap_or(16)) {
        (16, 16) => {
            let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            cipher.encrypt(nonce, payload).map_err(|_| CKR_FUNCTION_FAILED)
        }
        (32, 16) => {
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            cipher.encrypt(nonce, payload).map_err(|_| CKR_FUNCTION_FAILED)
        }
        (16, 12) => {
            let cipher: AesGcm<aes::Aes128, U12, U12> =
                AesGcm::new_from_slice(key).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            cipher.encrypt(nonce, payload).map_err(|_| CKR_FUNCTION_FAILED)
        }
        (32, 12) => {
            let cipher: AesGcm<aes::Aes256, U12, U12> =
                AesGcm::new_from_slice(key).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            cipher.encrypt(nonce, payload).map_err(|_| CKR_FUNCTION_FAILED)
        }
        // Silence-the-warning hint: `U16` is implicit in the default arms above.
        (_, _) => {
            let _ = std::marker::PhantomData::<U16>;
            Err(CKR_KEY_TYPE_INCONSISTENT)
        }
    }
}

fn aes_gcm_decrypt(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
    tag_len: Option<usize>,
) -> Result<Vec<u8>, CkRv> {
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::aead::generic_array::typenum::U12;
    use aes_gcm::{aead::{Aead, Payload}, AesGcm, Aes128Gcm, Aes256Gcm, KeyInit};
    if iv.len() != 12 {
        return Err(CKR_ARGUMENTS_BAD);
    }
    let nonce = GenericArray::from_slice(iv);
    let payload = Payload { msg: ciphertext, aad };
    match (key.len(), tag_len.unwrap_or(16)) {
        (16, 16) => {
            let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            cipher.decrypt(nonce, payload).map_err(|_| CKR_ENCRYPTED_DATA_INVALID)
        }
        (32, 16) => {
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            cipher.decrypt(nonce, payload).map_err(|_| CKR_ENCRYPTED_DATA_INVALID)
        }
        (16, 12) => {
            let cipher: AesGcm<aes::Aes128, U12, U12> =
                AesGcm::new_from_slice(key).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            cipher.decrypt(nonce, payload).map_err(|_| CKR_ENCRYPTED_DATA_INVALID)
        }
        (32, 12) => {
            let cipher: AesGcm<aes::Aes256, U12, U12> =
                AesGcm::new_from_slice(key).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            cipher.decrypt(nonce, payload).map_err(|_| CKR_ENCRYPTED_DATA_INVALID)
        }
        _ => Err(CKR_KEY_TYPE_INCONSISTENT),
    }
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

// ── ChaCha20 / ChaCha20-Poly1305 ───────────────────────────────────────────
//
// PKCS#11 v3.2 §6.20 — IETF ChaCha20 (32-byte key, 12-byte nonce,
// stream cipher) and ChaCha20-Poly1305 AEAD (RFC 8439). Cipher impls
// live in the `chacha20` + `chacha20poly1305` crates already in our
// `Cargo.toml`.

fn chacha20_encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CkRv> {
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

fn chacha20_poly1305_encrypt(
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

fn chacha20_poly1305_decrypt(
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

    // ── AES-GCM tests deferred to commit 6 alongside generate_aes_key ──────
    //
    // The encrypt() / decrypt() dispatch + aes_gcm_{encrypt,decrypt}
    // helpers are implemented in this commit (mirrors ffi::C_Encrypt's
    // AES-GCM path) but need a real AES key to test against. Commit 6
    // adds `generate_aes_key(session, bits, cka_id, label)` and the
    // round-trip tests land alongside it.
}
