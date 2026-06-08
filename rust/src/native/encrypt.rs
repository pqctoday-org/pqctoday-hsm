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
/// Other modes (AES-CBC, AES-CTR, RSA-OAEP) return
/// `CKR_MECHANISM_INVALID` in v0.1 — easy to add when KMIP needs them.
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
            aes_gcm_encrypt(&key_bytes, iv, plaintext)
        }
        _ => Err(CKR_MECHANISM_INVALID),
    }
}

/// Classical decrypt. v0.1 supports `CKM_AES_GCM`.
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
            aes_gcm_decrypt(&key_bytes, iv, ciphertext)
        }
        _ => Err(CKR_MECHANISM_INVALID),
    }
}

// ── AES-GCM ─────────────────────────────────────────────────────────────────

fn aes_gcm_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CkRv> {
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::{aead::{Aead, Payload}, Aes128Gcm, Aes256Gcm, KeyInit};
    if iv.len() != 12 {
        return Err(CKR_ARGUMENTS_BAD);
    }
    let nonce = GenericArray::from_slice(iv);
    let payload = Payload { msg: plaintext, aad: &[] };
    match key.len() {
        16 => {
            let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            cipher.encrypt(nonce, payload).map_err(|_| CKR_FUNCTION_FAILED)
        }
        32 => {
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            cipher.encrypt(nonce, payload).map_err(|_| CKR_FUNCTION_FAILED)
        }
        _ => Err(CKR_KEY_TYPE_INCONSISTENT),
    }
}

fn aes_gcm_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CkRv> {
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::{aead::{Aead, Payload}, Aes128Gcm, Aes256Gcm, KeyInit};
    if iv.len() != 12 {
        return Err(CKR_ARGUMENTS_BAD);
    }
    let nonce = GenericArray::from_slice(iv);
    let payload = Payload { msg: ciphertext, aad: &[] };
    match key.len() {
        16 => {
            let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            // GCM tag failure → CKR_ENCRYPTED_DATA_INVALID (PKCS#11 v3.2 §6.13).
            cipher.decrypt(nonce, payload).map_err(|_| CKR_ENCRYPTED_DATA_INVALID)
        }
        32 => {
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            cipher.decrypt(nonce, payload).map_err(|_| CKR_ENCRYPTED_DATA_INVALID)
        }
        _ => Err(CKR_KEY_TYPE_INCONSISTENT),
    }
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
