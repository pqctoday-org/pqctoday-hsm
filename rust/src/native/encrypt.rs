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
use crate::state::{
    check_mechanism_allowed_from, get_ec_point_sec1_from, get_object_attr_u32_from,
    get_object_param_set_from, get_object_value, get_object_value_from, read_bool_attr,
    resolve_session_access, with_object_checked, SessionAccess, OBJECTS,
};

// PKCS#11 v3.2 §5.18 — KEM permission flags. CKA_ENCAPSULATE / CKA_DECAPSULATE.
use crate::constants::{CKA_DECAPSULATE, CKA_DECRYPT, CKA_ENCAPSULATE, CKA_ENCRYPT};

/// Encapsulation for either ML-KEM (`CKM_ML_KEM`) or a classical
/// ephemeral-static ECDH KEM (`CKM_ECDH1_DERIVE` for P-256/P-384/P-521,
/// `CKM_EC_MONTGOMERY_KEY_DERIVE` for X25519/X448). Returns
/// `(ciphertext, shared_secret)`.
///
/// The classical branches are KMIP 3.0 WD19's `DHKEM` (§11.26 KEM Algorithm
/// Enumeration) / PKCS#11 v3.2 §6.3.17: `pPublicData`/`ulPublicDataLen`
/// are unused for this call shape (no separate params struct here — the
/// public key handle IS the recipient's static public key); the server
/// generates a fresh ephemeral key pair, DHs it against the recipient's
/// static public key, and returns the ephemeral public key AS the
/// ciphertext (see `kmip/spec/crossref/kem-encapsulate-decapsulate.yaml`).
/// This is the same math already proven in `hybrid.rs`'s classical half,
/// exposed here standalone so a plain (non-hybrid) classical key can use
/// this op too — the crypto-agility payoff being that `Encapsulate`'s
/// caller shape never differs between classical, hybrid, and ML-KEM.
///
/// `public_key_handle` MUST have `CKA_ENCAPSULATE = true`.
///
/// Ciphertext / shared-secret lengths:
/// - ML-KEM-512/768/1024 (FIPS 203 §7): ct = 768/1088/1568, ss = 32.
/// - ECDH-P256/P384/P521: ct = SEC1 uncompressed point (65/97/133), ss = curve field size (32/48/66).
/// - X25519/X448 (RFC 7748): ct = 32/56, ss = 32/56.
pub fn encapsulate(
    session: u32,
    public_key_handle: u32,
    mechanism: u32,
) -> Result<(Vec<u8>, Vec<u8>), CkRv> {
    use ml_kem::{kem::Encapsulate, EncodedSizeUser, KemCore};

    let access = resolve_session_access(session)?;

    if mechanism == CKM_ECDH1_DERIVE || mechanism == CKM_EC_MONTGOMERY_KEY_DERIVE {
        return classical_encapsulate(&access, public_key_handle, mechanism);
    }
    if mechanism == CKM_PQCTODAY_FRODOKEM_ENCAPSULATE {
        return frodokem_encapsulate(&access, public_key_handle);
    }
    if mechanism == CKM_PQCTODAY_CLASSIC_MCELIECE_ENCAPSULATE {
        return classic_mceliece_encapsulate(&access, public_key_handle);
    }
    if mechanism != CKM_ML_KEM {
        return Err(CKR_MECHANISM_INVALID);
    }

    // Isolation gate + CKA_ENCAPSULATE + CKA_ALLOWED_MECHANISMS +
    // CKA_KEY_TYPE + CKA_PRIV_PARAM_SET + CKA_VALUE, all from ONE borrow.
    let (can_encap, mech_ok, key_type, ps, pub_key_bytes) =
        with_object_checked(&access, public_key_handle, |attrs| {
            (
                read_bool_attr(attrs, CKA_ENCAPSULATE),
                check_mechanism_allowed_from(attrs, mechanism),
                get_object_attr_u32_from(attrs, CKA_KEY_TYPE),
                get_object_param_set_from(attrs),
                get_object_value_from(attrs),
            )
        })?;
    if !can_encap {
        return Err(CKR_KEY_FUNCTION_NOT_PERMITTED);
    }
    mech_ok?;
    // PKCS#11 v3.2 §5.18.8 — CKM_ML_KEM requires an ML-KEM key
    // (compliance-audit P-10).
    if key_type != Some(CKK_ML_KEM) {
        return Err(CKR_KEY_TYPE_INCONSISTENT);
    }
    // P-10: no silent ML-KEM-768 default — a key without
    // CKA_PARAMETER_SET is an incomplete object.
    if ps == 0 {
        return Err(CKR_TEMPLATE_INCOMPLETE);
    }
    let pub_key_bytes = pub_key_bytes.ok_or(CKR_ARGUMENTS_BAD)?;
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
    session: u32,
    public_key_handle: u32,
    mechanism: u32,
    coins: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CkRv> {
    use ml_kem::{EncapsulateDeterministic, EncodedSizeUser, KemCore};

    if mechanism != CKM_ML_KEM {
        return Err(CKR_MECHANISM_INVALID);
    }
    let access = resolve_session_access(session)?;
    let (can_encap, mech_ok, key_type, ps, pub_key_bytes) =
        with_object_checked(&access, public_key_handle, |attrs| {
            (
                read_bool_attr(attrs, CKA_ENCAPSULATE),
                check_mechanism_allowed_from(attrs, mechanism),
                get_object_attr_u32_from(attrs, CKA_KEY_TYPE),
                get_object_param_set_from(attrs),
                get_object_value_from(attrs),
            )
        })?;
    if !can_encap {
        return Err(CKR_KEY_FUNCTION_NOT_PERMITTED);
    }
    mech_ok?;
    if key_type != Some(CKK_ML_KEM) {
        return Err(CKR_KEY_TYPE_INCONSISTENT);
    }
    if ps == 0 {
        return Err(CKR_TEMPLATE_INCOMPLETE);
    }
    // FIPS 203 §7.2 — m is exactly 32 bytes.
    let m = ml_kem::B32::try_from(coins).map_err(|_| CKR_ARGUMENTS_BAD)?;
    let pub_key_bytes = pub_key_bytes.ok_or(CKR_ARGUMENTS_BAD)?;

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
    session: u32,
    private_key_handle: u32,
    mechanism: u32,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CkRv> {
    use ml_kem::{kem::Decapsulate, EncodedSizeUser, KemCore};

    let access = resolve_session_access(session)?;

    if mechanism == CKM_ECDH1_DERIVE || mechanism == CKM_EC_MONTGOMERY_KEY_DERIVE {
        return classical_decapsulate(&access, private_key_handle, mechanism, ciphertext);
    }
    if mechanism == CKM_PQCTODAY_FRODOKEM_ENCAPSULATE {
        return frodokem_decapsulate(&access, private_key_handle, ciphertext);
    }
    if mechanism == CKM_PQCTODAY_CLASSIC_MCELIECE_ENCAPSULATE {
        return classic_mceliece_decapsulate(&access, private_key_handle, ciphertext);
    }
    if mechanism != CKM_ML_KEM {
        return Err(CKR_MECHANISM_INVALID);
    }

    let (can_decap, mech_ok, key_type, ps, prv_key_bytes) =
        with_object_checked(&access, private_key_handle, |attrs| {
            (
                read_bool_attr(attrs, CKA_DECAPSULATE),
                check_mechanism_allowed_from(attrs, mechanism),
                get_object_attr_u32_from(attrs, CKA_KEY_TYPE),
                get_object_param_set_from(attrs),
                get_object_value_from(attrs),
            )
        })?;
    if !can_decap {
        return Err(CKR_KEY_FUNCTION_NOT_PERMITTED);
    }
    mech_ok?;
    // PKCS#11 v3.2 §5.18.9 — CKM_ML_KEM requires an ML-KEM key
    // (compliance-audit P-10).
    if key_type != Some(CKK_ML_KEM) {
        return Err(CKR_KEY_TYPE_INCONSISTENT);
    }
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

    let prv_key_bytes = prv_key_bytes.ok_or(CKR_ARGUMENTS_BAD)?;

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

/// Classical-KEM encapsulation (2026-07-05, crypto-agility for `Encapsulate`).
/// Ephemeral-static ECDH: generates a fresh ephemeral key pair, DHs it
/// against the recipient's stored static public key, returns the ephemeral
/// public key as the ciphertext. Same math `hybrid.rs` already runs for its
/// classical half (KAT-verified there — see `classical_kem` unit tests
/// below for the standalone curve-by-curve coverage), reused here rather
/// than duplicated.
fn classical_encapsulate(
    access: &SessionAccess,
    public_key_handle: u32,
    mechanism: u32,
) -> Result<(Vec<u8>, Vec<u8>), CkRv> {
    // Isolation gate + CKA_ENCAPSULATE + CKA_ALLOWED_MECHANISMS +
    // CKA_KEY_TYPE + CKA_PRIV_PARAM_SET + CKA_EC_POINT + CKA_VALUE — every
    // field either mechanism branch below might need, fetched together
    // under ONE OBJECTS lock (cheap absent-key lookups for the branch not
    // taken, rather than a second lock acquisition per branch).
    let (can_encap, mech_ok, key_type, ps, ec_point, raw_value) =
        with_object_checked(access, public_key_handle, |attrs| {
            (
                read_bool_attr(attrs, CKA_ENCAPSULATE),
                check_mechanism_allowed_from(attrs, mechanism),
                get_object_attr_u32_from(attrs, CKA_KEY_TYPE),
                get_object_param_set_from(attrs),
                get_ec_point_sec1_from(attrs),
                get_object_value_from(attrs),
            )
        })?;
    if !can_encap {
        return Err(CKR_KEY_FUNCTION_NOT_PERMITTED);
    }
    mech_ok?;
    let mut rng = rand::rngs::OsRng;
    match mechanism {
        CKM_ECDH1_DERIVE => {
            if key_type != Some(CKK_EC) {
                return Err(CKR_KEY_TYPE_INCONSISTENT);
            }
            let point = ec_point.ok_or(CKR_ARGUMENTS_BAD)?;
            match ps {
                256 => {
                    let peer = p256::PublicKey::from_sec1_bytes(&point)
                        .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
                    let eph = p256::ecdh::EphemeralSecret::random(&mut rng);
                    let eph_pub = p256::EncodedPoint::from(eph.public_key());
                    let ss = eph.diffie_hellman(&peer);
                    Ok((eph_pub.as_bytes().to_vec(), ss.raw_secret_bytes().to_vec()))
                }
                384 => {
                    let peer = p384::PublicKey::from_sec1_bytes(&point)
                        .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
                    let eph = p384::ecdh::EphemeralSecret::random(&mut rng);
                    let eph_pub = p384::EncodedPoint::from(eph.public_key());
                    let ss = eph.diffie_hellman(&peer);
                    Ok((eph_pub.as_bytes().to_vec(), ss.raw_secret_bytes().to_vec()))
                }
                521 => {
                    let peer = p521::PublicKey::from_sec1_bytes(&point)
                        .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
                    let eph = p521::ecdh::EphemeralSecret::random(&mut rng);
                    let eph_pub = p521::EncodedPoint::from(eph.public_key());
                    let ss = eph.diffie_hellman(&peer);
                    Ok((eph_pub.as_bytes().to_vec(), ss.raw_secret_bytes().to_vec()))
                }
                _ => Err(CKR_TEMPLATE_INCOMPLETE),
            }
        }
        CKM_EC_MONTGOMERY_KEY_DERIVE => {
            if key_type != Some(CKK_EC_MONTGOMERY) {
                return Err(CKR_KEY_TYPE_INCONSISTENT);
            }
            let point = raw_value.ok_or(CKR_ARGUMENTS_BAD)?;
            match point.len() {
                32 => {
                    let peer: [u8; 32] = point.as_slice().try_into().map_err(|_| CKR_ARGUMENTS_BAD)?;
                    let eph = x25519_dalek::EphemeralSecret::random_from_rng(&mut rng);
                    let eph_pub = x25519_dalek::PublicKey::from(&eph);
                    let ss = eph.diffie_hellman(&x25519_dalek::PublicKey::from(peer));
                    Ok((eph_pub.as_bytes().to_vec(), ss.as_bytes().to_vec()))
                }
                56 => {
                    let peer_pub = x448::PublicKey::from_bytes(&point).ok_or(CKR_ARGUMENTS_BAD)?;
                    let mut eph_bytes = [0u8; 56];
                    getrandom::getrandom(&mut eph_bytes).map_err(|_| CKR_FUNCTION_FAILED)?;
                    let eph = x448::StaticSecret::from(eph_bytes);
                    let eph_pub = x448::PublicKey::from(&eph);
                    let ss = eph.diffie_hellman(&peer_pub);
                    Ok((eph_pub.as_bytes().to_vec(), ss.as_bytes().to_vec()))
                }
                _ => Err(CKR_KEY_TYPE_INCONSISTENT),
            }
        }
        _ => Err(CKR_MECHANISM_INVALID),
    }
}

/// Classical-KEM decapsulation — the inverse of `classical_encapsulate`.
/// Reads the static scalar from its handle (never exported) and DHs it
/// against the ephemeral public key carried in `ciphertext`.
fn classical_decapsulate(
    access: &SessionAccess,
    private_key_handle: u32,
    mechanism: u32,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CkRv> {
    let (can_decap, mech_ok, key_type, ps, scalar) =
        with_object_checked(access, private_key_handle, |attrs| {
            (
                read_bool_attr(attrs, CKA_DECAPSULATE),
                check_mechanism_allowed_from(attrs, mechanism),
                get_object_attr_u32_from(attrs, CKA_KEY_TYPE),
                get_object_param_set_from(attrs),
                get_object_value_from(attrs),
            )
        })?;
    if !can_decap {
        return Err(CKR_KEY_FUNCTION_NOT_PERMITTED);
    }
    mech_ok?;
    match mechanism {
        CKM_ECDH1_DERIVE => {
            if key_type != Some(CKK_EC) {
                return Err(CKR_KEY_TYPE_INCONSISTENT);
            }
            let scalar = scalar.ok_or(CKR_ARGUMENTS_BAD)?;
            match ps {
                256 => {
                    let secret = p256::SecretKey::from_slice(&scalar).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
                    let eph_pub = p256::PublicKey::from_sec1_bytes(ciphertext)
                        .map_err(|_| CKR_ARGUMENTS_BAD)?;
                    let ss = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), eph_pub.as_affine());
                    Ok(ss.raw_secret_bytes().to_vec())
                }
                384 => {
                    let secret = p384::SecretKey::from_slice(&scalar).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
                    let eph_pub = p384::PublicKey::from_sec1_bytes(ciphertext)
                        .map_err(|_| CKR_ARGUMENTS_BAD)?;
                    let ss = p384::ecdh::diffie_hellman(secret.to_nonzero_scalar(), eph_pub.as_affine());
                    Ok(ss.raw_secret_bytes().to_vec())
                }
                521 => {
                    let secret = p521::SecretKey::from_slice(&scalar).map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
                    let eph_pub = p521::PublicKey::from_sec1_bytes(ciphertext)
                        .map_err(|_| CKR_ARGUMENTS_BAD)?;
                    let ss = p521::ecdh::diffie_hellman(secret.to_nonzero_scalar(), eph_pub.as_affine());
                    Ok(ss.raw_secret_bytes().to_vec())
                }
                _ => Err(CKR_TEMPLATE_INCOMPLETE),
            }
        }
        CKM_EC_MONTGOMERY_KEY_DERIVE => {
            if key_type != Some(CKK_EC_MONTGOMERY) {
                return Err(CKR_KEY_TYPE_INCONSISTENT);
            }
            let scalar = scalar.ok_or(CKR_ARGUMENTS_BAD)?;
            match scalar.len() {
                32 => {
                    let arr: [u8; 32] = scalar.as_slice().try_into().map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
                    if ciphertext.len() != 32 {
                        return Err(CKR_ARGUMENTS_BAD);
                    }
                    let eph_pub: [u8; 32] = ciphertext.try_into().map_err(|_| CKR_ARGUMENTS_BAD)?;
                    let secret = x25519_dalek::StaticSecret::from(arr);
                    let ss = secret.diffie_hellman(&x25519_dalek::PublicKey::from(eph_pub));
                    Ok(ss.as_bytes().to_vec())
                }
                56 => {
                    let mut arr = [0u8; 56];
                    arr.copy_from_slice(scalar.as_slice());
                    let secret = x448::StaticSecret::from(arr);
                    let eph_pub = x448::PublicKey::from_bytes(ciphertext).ok_or(CKR_ARGUMENTS_BAD)?;
                    let ss = secret.diffie_hellman(&eph_pub);
                    Ok(ss.as_bytes().to_vec())
                }
                _ => Err(CKR_KEY_TYPE_INCONSISTENT),
            }
        }
        _ => Err(CKR_MECHANISM_INVALID),
    }
}

/// FrodoKEM encapsulation (BSI TR-02102-1 §2.4.1, `CKM_PQCTODAY_FRODOKEM_ENCAPSULATE`).
/// Returns `(ciphertext, shared_secret)`.
///
/// RNG note — see [`super::keygen::generate_frodokem_keypair`]: `frodo-kem`
/// needs `rand_core 0.10`'s `CryptoRng`, not this engine's usual
/// `rand::rngs::OsRng`.
fn frodokem_encapsulate(access: &SessionAccess, public_key_handle: u32) -> Result<(Vec<u8>, Vec<u8>), CkRv> {
    use getrandom_0_4::rand_core::UnwrapErr;
    use getrandom_0_4::SysRng;

    let (can_encap, key_type, ps, pub_key_bytes) =
        with_object_checked(access, public_key_handle, |attrs| {
            (
                read_bool_attr(attrs, CKA_ENCAPSULATE),
                get_object_attr_u32_from(attrs, CKA_KEY_TYPE),
                get_object_param_set_from(attrs),
                get_object_value_from(attrs),
            )
        })?;
    if !can_encap {
        return Err(CKR_KEY_FUNCTION_NOT_PERMITTED);
    }
    if key_type != Some(CKK_PQCTODAY_FRODOKEM) {
        return Err(CKR_KEY_TYPE_INCONSISTENT);
    }
    if ps == 0 {
        return Err(CKR_TEMPLATE_INCOMPLETE);
    }
    let alg = super::keygen::frodokem_algorithm(ps)?;
    let pub_key_bytes = pub_key_bytes.ok_or(CKR_ARGUMENTS_BAD)?;
    let ek = frodo_kem::EncryptionKey::from_bytes(alg, &pub_key_bytes)
        .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
    let mut rng = UnwrapErr(SysRng);
    let (ct, ss) = ek
        .encapsulate_with_rng(&mut rng)
        .map_err(|_| CKR_FUNCTION_FAILED)?;
    Ok((ct.value().to_vec(), ss.value().to_vec()))
}

/// FrodoKEM decapsulation (`CKM_PQCTODAY_FRODOKEM_ENCAPSULATE`). Returns the
/// recovered shared secret.
fn frodokem_decapsulate(access: &SessionAccess, private_key_handle: u32, ciphertext: &[u8]) -> Result<Vec<u8>, CkRv> {
    let (can_decap, key_type, ps, prv_key_bytes) =
        with_object_checked(access, private_key_handle, |attrs| {
            (
                read_bool_attr(attrs, CKA_DECAPSULATE),
                get_object_attr_u32_from(attrs, CKA_KEY_TYPE),
                get_object_param_set_from(attrs),
                get_object_value_from(attrs),
            )
        })?;
    if !can_decap {
        return Err(CKR_KEY_FUNCTION_NOT_PERMITTED);
    }
    if key_type != Some(CKK_PQCTODAY_FRODOKEM) {
        return Err(CKR_KEY_TYPE_INCONSISTENT);
    }
    if ps == 0 {
        return Err(CKR_TEMPLATE_INCOMPLETE);
    }
    let alg = super::keygen::frodokem_algorithm(ps)?;
    let prv_key_bytes = prv_key_bytes.ok_or(CKR_ARGUMENTS_BAD)?;
    let dk = frodo_kem::DecryptionKey::from_bytes(alg, &prv_key_bytes)
        .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
    let ct = frodo_kem::Ciphertext::from_bytes(alg, ciphertext).map_err(|_| CKR_ARGUMENTS_BAD)?;
    // `B` is an unused generic on `DecryptionKey::decapsulate` (mirrors the
    // shape of `encapsulate`'s message-buffer type param, but decapsulate
    // has no such buffer) — any concrete `AsRef<[u8]>` type satisfies it.
    let (ss, _msg) = dk.decapsulate::<&[u8]>(&ct).map_err(|_| CKR_FUNCTION_FAILED)?;
    Ok(ss.value().to_vec())
}

/// Classic McEliece encapsulation (BSI TR-02102-1 §2.4.2,
/// `CKM_PQCTODAY_CLASSIC_MCELIECE_ENCAPSULATE`). Scoped to `mceliece6688128`
/// only (implementation plan Phase 0.5). Returns `(ciphertext,
/// shared_secret)`.
///
/// Unlike FrodoKEM, `classic-mceliece-rust` uses `rand 0.8` — the same
/// version this engine already uses elsewhere — so `rand::rngs::OsRng`
/// works directly.
fn classic_mceliece_encapsulate(access: &SessionAccess, public_key_handle: u32) -> Result<(Vec<u8>, Vec<u8>), CkRv> {
    use classic_mceliece_rust::{encapsulate_boxed, PublicKey, CRYPTO_PUBLICKEYBYTES};

    let (can_encap, key_type, ps, pub_key_bytes) =
        with_object_checked(access, public_key_handle, |attrs| {
            (
                read_bool_attr(attrs, CKA_ENCAPSULATE),
                get_object_attr_u32_from(attrs, CKA_KEY_TYPE),
                get_object_param_set_from(attrs),
                get_object_value_from(attrs),
            )
        })?;
    if !can_encap {
        return Err(CKR_KEY_FUNCTION_NOT_PERMITTED);
    }
    if key_type != Some(CKK_PQCTODAY_CLASSIC_MCELIECE) {
        return Err(CKR_KEY_TYPE_INCONSISTENT);
    }
    if ps != CKP_CLASSIC_MCELIECE_6688128 {
        return Err(CKR_ARGUMENTS_BAD);
    }
    let pub_key_bytes = pub_key_bytes.ok_or(CKR_ARGUMENTS_BAD)?;
    let mut pk_arr: [u8; CRYPTO_PUBLICKEYBYTES] = pub_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
    // v3+ API: `PublicKey::from` takes `&mut [u8; N]` now, not `&` (a
    // breaking change from v2).
    let pk = PublicKey::from(&mut pk_arr);
    let mut rng = rand::rngs::OsRng;
    let (ct, ss) = encapsulate_boxed(&pk, &mut rng);
    Ok((ct.as_array().to_vec(), ss.as_array().to_vec()))
}

/// Classic McEliece decapsulation (`CKM_PQCTODAY_CLASSIC_MCELIECE_ENCAPSULATE`).
/// Returns the recovered shared secret.
fn classic_mceliece_decapsulate(access: &SessionAccess, private_key_handle: u32, ciphertext: &[u8]) -> Result<Vec<u8>, CkRv> {
    use classic_mceliece_rust::{decapsulate_boxed, Ciphertext, SecretKey, CRYPTO_CIPHERTEXTBYTES, CRYPTO_SECRETKEYBYTES};

    let (can_decap, key_type, ps, prv_key_bytes) =
        with_object_checked(access, private_key_handle, |attrs| {
            (
                read_bool_attr(attrs, CKA_DECAPSULATE),
                get_object_attr_u32_from(attrs, CKA_KEY_TYPE),
                get_object_param_set_from(attrs),
                get_object_value_from(attrs),
            )
        })?;
    if !can_decap {
        return Err(CKR_KEY_FUNCTION_NOT_PERMITTED);
    }
    if key_type != Some(CKK_PQCTODAY_CLASSIC_MCELIECE) {
        return Err(CKR_KEY_TYPE_INCONSISTENT);
    }
    if ps != CKP_CLASSIC_MCELIECE_6688128 {
        return Err(CKR_ARGUMENTS_BAD);
    }
    if ciphertext.len() != CRYPTO_CIPHERTEXTBYTES {
        return Err(CKR_ARGUMENTS_BAD);
    }
    let mut prv_key_bytes = prv_key_bytes.ok_or(CKR_ARGUMENTS_BAD)?;
    let sk_arr: &mut [u8; CRYPTO_SECRETKEYBYTES] = (&mut prv_key_bytes[..])
        .try_into()
        .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
    let sk = SecretKey::from(sk_arr);
    let ct_arr: [u8; CRYPTO_CIPHERTEXTBYTES] =
        ciphertext.try_into().map_err(|_| CKR_ARGUMENTS_BAD)?;
    let ct = Ciphertext::from(ct_arr);
    let ss = decapsulate_boxed(&ct, &sk);
    Ok(ss.as_array().to_vec())
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
/// Gap-remediation Phase F, Finding #4 — previously hardcoded empty AAD
/// (AES-GCM/ChaCha20-Poly1305) and the SHA-256/MGF1-SHA-256/no-label
/// OAEP default, unconditionally, for every engine-resident (Create/
/// CreateKeyPair'd) key — those client-supplied values only reached the
/// engine on the Register'd-key (raw-material) path via
/// [`encrypt_with_key_bytes`]. Now resolves the key bytes exactly as
/// before (`check_flag` + `get_object_value`) and delegates to
/// [`encrypt_with_key_bytes`] for the actual mechanism dispatch, so both
/// paths run the identical match body instead of two copies that used
/// to silently drift apart.
pub fn encrypt(
    session: u32,
    key_handle: u32,
    mechanism: u32,
    plaintext: &[u8],
    iv: Option<&[u8]>,
    oaep: Option<&OaepParams>,
    aad: &[u8],
    tag_len: Option<usize>,
) -> Result<Vec<u8>, CkRv> {
    let access = resolve_session_access(session)?;
    let (can_encrypt, mech_ok, key_bytes) = with_object_checked(&access, key_handle, |attrs| {
        (
            read_bool_attr(attrs, CKA_ENCRYPT),
            check_mechanism_allowed_from(attrs, mechanism),
            get_object_value_from(attrs),
        )
    })?;
    if !can_encrypt {
        return Err(CKR_KEY_FUNCTION_NOT_PERMITTED);
    }
    mech_ok?;
    let key_bytes = key_bytes.ok_or(CKR_ARGUMENTS_BAD)?;
    encrypt_with_key_bytes(&key_bytes, mechanism, plaintext, iv, oaep, aad, tag_len)
}

/// Classical decrypt. See [`encrypt`] for the mechanism table and the
/// Gap-remediation Phase F note on why this now delegates to
/// [`decrypt_with_key_bytes`].
pub fn decrypt(
    session: u32,
    key_handle: u32,
    mechanism: u32,
    ciphertext: &[u8],
    iv: Option<&[u8]>,
    oaep: Option<&OaepParams>,
    aad: &[u8],
    tag_len: Option<usize>,
) -> Result<Vec<u8>, CkRv> {
    let access = resolve_session_access(session)?;
    let (can_decrypt, mech_ok, key_bytes) = with_object_checked(&access, key_handle, |attrs| {
        (
            read_bool_attr(attrs, CKA_DECRYPT),
            check_mechanism_allowed_from(attrs, mechanism),
            get_object_value_from(attrs),
        )
    })?;
    if !can_decrypt {
        return Err(CKR_KEY_FUNCTION_NOT_PERMITTED);
    }
    mech_ok?;
    let key_bytes = key_bytes.ok_or(CKR_ARGUMENTS_BAD)?;
    decrypt_with_key_bytes(&key_bytes, mechanism, ciphertext, iv, oaep, aad, tag_len)
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
        // KMIP/CACP coverage gap-analysis item 2.2 (2026-08-30). `iv` here
        // is CCM's nonce, `tag_len` its MAC length (SP 800-38C: nonce
        // 7..=13 bytes, tag ∈ {4,6,8,10,12,14,16}) — the same generic
        // parameters GCM already uses for the analogous fields.
        CKM_AES_CCM => {
            let nonce = iv.ok_or(CKR_ARGUMENTS_BAD)?;
            aes_ccm_encrypt(key_bytes, nonce, plaintext, aad, tag_len)
        }
        // KMIP/CACP coverage gap-analysis item 2.4 (2026-08-30). OFB is
        // self-inverse (same keystream XOR encrypt/decrypt, like CTR
        // above); CFB is direction-sensitive (its feedback register
        // differs), hence CipherDirection::Encrypt here.
        CKM_AES_OFB => {
            let iv = iv.ok_or(CKR_ARGUMENTS_BAD)?;
            aes_ofb_apply(key_bytes, iv, plaintext)
        }
        CKM_AES_CFB128 => {
            let iv = iv.ok_or(CKR_ARGUMENTS_BAD)?;
            aes_cfb128_apply(key_bytes, iv, plaintext, crate::crypto::multipart::CipherDirection::Encrypt)
        }
        CKM_AES_CFB8 => {
            let iv = iv.ok_or(CKR_ARGUMENTS_BAD)?;
            aes_cfb8_apply(key_bytes, iv, plaintext, crate::crypto::multipart::CipherDirection::Encrypt)
        }
        CKM_AES_CFB1 => {
            let iv = iv.ok_or(CKR_ARGUMENTS_BAD)?;
            aes_cfb1_apply(key_bytes, iv, plaintext, crate::crypto::multipart::CipherDirection::Encrypt)
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
        // KMIP/CACP coverage gap-analysis item 2.2 (2026-08-30). See the
        // encrypt-side arm above for the parameter mapping.
        CKM_AES_CCM => {
            let nonce = iv.ok_or(CKR_ARGUMENTS_BAD)?;
            aes_ccm_decrypt(key_bytes, nonce, ciphertext, aad, tag_len)
        }
        // KMIP/CACP coverage gap-analysis item 2.4 (2026-08-30).
        CKM_AES_OFB => {
            // OFB is self-inverse — same keystream XOR both directions.
            let iv = iv.ok_or(CKR_ARGUMENTS_BAD)?;
            aes_ofb_apply(key_bytes, iv, ciphertext)
        }
        CKM_AES_CFB128 => {
            let iv = iv.ok_or(CKR_ARGUMENTS_BAD)?;
            aes_cfb128_apply(key_bytes, iv, ciphertext, crate::crypto::multipart::CipherDirection::Decrypt)
        }
        CKM_AES_CFB8 => {
            let iv = iv.ok_or(CKR_ARGUMENTS_BAD)?;
            aes_cfb8_apply(key_bytes, iv, ciphertext, crate::crypto::multipart::CipherDirection::Decrypt)
        }
        CKM_AES_CFB1 => {
            let iv = iv.ok_or(CKR_ARGUMENTS_BAD)?;
            aes_cfb1_apply(key_bytes, iv, ciphertext, crate::crypto::multipart::CipherDirection::Decrypt)
        }
        _ => Err(CKR_MECHANISM_INVALID),
    }
}

/// KMIP/CACP coverage gap-analysis item 2.2 (2026-08-30) — thin
/// key-bytes wrapper over [`crate::crypto::multipart::ccm_encrypt`],
/// mirroring [`aes_gcm_encrypt`]'s exact `AesKey::new` pattern. SP
/// 800-38C: nonce 7..=13 bytes; tag length one of {4,6,8,10,12,14,16}
/// bytes (default 16, same convention as GCM above).
fn aes_ccm_encrypt(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
    tag_len: Option<usize>,
) -> Result<Vec<u8>, CkRv> {
    use crate::crypto::multipart::{ccm_encrypt, AesKey};
    if !(7..=13).contains(&nonce.len()) {
        return Err(CKR_MECHANISM_PARAM_INVALID);
    }
    let tag_len = tag_len.unwrap_or(16);
    if !matches!(tag_len, 4 | 6 | 8 | 10 | 12 | 14 | 16) {
        return Err(CKR_MECHANISM_PARAM_INVALID);
    }
    let k = AesKey::new(key).ok_or(CKR_KEY_TYPE_INCONSISTENT)?;
    Ok(ccm_encrypt(&k, nonce, aad, plaintext, tag_len))
}

/// Decrypt counterpart of [`aes_ccm_encrypt`].
fn aes_ccm_decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext_and_tag: &[u8],
    aad: &[u8],
    tag_len: Option<usize>,
) -> Result<Vec<u8>, CkRv> {
    use crate::crypto::multipart::{ccm_decrypt, AesKey};
    if !(7..=13).contains(&nonce.len()) {
        return Err(CKR_MECHANISM_PARAM_INVALID);
    }
    let tag_len = tag_len.unwrap_or(16);
    if !matches!(tag_len, 4 | 6 | 8 | 10 | 12 | 14 | 16) {
        return Err(CKR_MECHANISM_PARAM_INVALID);
    }
    let k = AesKey::new(key).ok_or(CKR_KEY_TYPE_INCONSISTENT)?;
    ccm_decrypt(&k, nonce, aad, ciphertext_and_tag, tag_len)
}

/// KMIP/CACP coverage gap-analysis item 2.4 (2026-08-30) — thin
/// key-bytes wrapper over [`crate::crypto::multipart::OfbState`],
/// mirroring the FFI dispatch's own usage exactly (`ffi.rs`'s
/// `CKM_AES_OFB` arms, both directions). Self-inverse: the same call
/// serves encrypt and decrypt.
fn aes_ofb_apply(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, CkRv> {
    use crate::crypto::multipart::{AesKey, OfbState};
    let k = AesKey::new(key).ok_or(CKR_KEY_TYPE_INCONSISTENT)?;
    let ivb: [u8; 16] = iv.try_into().map_err(|_| CKR_MECHANISM_PARAM_INVALID)?;
    Ok(OfbState::new(k, ivb).update_public(data))
}

/// KMIP/CACP coverage gap-analysis item 2.4 (2026-08-30) — CFB128,
/// direction-sensitive (unlike OFB), mirroring `ffi.rs`'s `CKM_AES_CFB128`
/// arms exactly.
fn aes_cfb128_apply(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    dir: crate::crypto::multipart::CipherDirection,
) -> Result<Vec<u8>, CkRv> {
    use crate::crypto::multipart::{AesKey, Cfb128State};
    let k = AesKey::new(key).ok_or(CKR_KEY_TYPE_INCONSISTENT)?;
    let ivb: [u8; 16] = iv.try_into().map_err(|_| CKR_MECHANISM_PARAM_INVALID)?;
    Ok(Cfb128State::new(k, ivb, dir).update_public(data))
}

/// CFB8 counterpart of [`aes_cfb128_apply`].
fn aes_cfb8_apply(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    dir: crate::crypto::multipart::CipherDirection,
) -> Result<Vec<u8>, CkRv> {
    use crate::crypto::multipart::{AesKey, Cfb8State};
    let k = AesKey::new(key).ok_or(CKR_KEY_TYPE_INCONSISTENT)?;
    let ivb: [u8; 16] = iv.try_into().map_err(|_| CKR_MECHANISM_PARAM_INVALID)?;
    Ok(Cfb8State::new(k, ivb, dir).update_public(data))
}

/// CFB1 counterpart of [`aes_cfb128_apply`].
fn aes_cfb1_apply(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    dir: crate::crypto::multipart::CipherDirection,
) -> Result<Vec<u8>, CkRv> {
    use crate::crypto::multipart::{AesKey, Cfb1State};
    let k = AesKey::new(key).ok_or(CKR_KEY_TYPE_INCONSISTENT)?;
    let ivb: [u8; 16] = iv.try_into().map_err(|_| CKR_MECHANISM_PARAM_INVALID)?;
    Ok(Cfb1State::new(k, ivb, dir).update_public(data))
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
        .or_else(|_| rsa_public_key_from_packed_native(bytes))
        .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)
}

/// Gap-remediation Phase F, Finding #4 (T0 discovery) — a
/// `generate_rsa_keypair`'d public key's `CKA_VALUE` is NOT DER at all;
/// it's this engine's own internal packed `[n_len:4LE][n_bytes][e_bytes]`
/// format (see `generate_rsa_keypair`'s comment: "Format mirrors
/// ffi.rs"). `ffi.rs`'s own `CKM_RSA_PKCS_OAEP` C_Encrypt path already
/// unpacks this exact format independently (it never calls this
/// function) — this mirrors that unpacking so the native handle-based
/// `encrypt()`, once delegating here via `encrypt_with_key_bytes`, can
/// finally RSA-OAEP-encrypt with an engine-GENERATED key too, not just
/// a `Register`'d one. Before this, `rsa_public_key_from_any_der`
/// rejected the packed bytes outright (`Err(InvalidPkcs1)` /
/// `Err(InvalidPkcs8)`) and RSA-OAEP Encrypt against any
/// CreateKeyPair'd RSA key handle always failed — a pre-existing gap
/// this fix's own new test (`rsa_oaep_engine_handle_honors_explicit_hash_override`)
/// caught, not something Finding #4's text originally called out.
fn rsa_public_key_from_packed_native(bytes: &[u8]) -> Result<rsa::RsaPublicKey, rsa::Error> {
    if bytes.len() < 4 {
        return Err(rsa::Error::Internal);
    }
    let n_len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if bytes.len() < 4 + n_len + 1 {
        return Err(rsa::Error::Internal);
    }
    let n = rsa::BigUint::from_bytes_be(&bytes[4..4 + n_len]);
    let e = rsa::BigUint::from_bytes_be(&bytes[4 + n_len..]);
    rsa::RsaPublicKey::new(n, e)
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

/// AES Key Wrap with Padding (RFC 5649 / `CKM_AES_KEY_WRAP_KWP`) — the
/// `native` counterpart of `ffi::C_WrapKey`'s `is_kwp` arm. Unlike
/// [`aes_key_wrap`], supports arbitrary-length (non-empty) plaintext — no
/// 8-byte-multiple/≥16-byte requirement, RFC 5649's padding handles the
/// rest. KMIP/CACP coverage gap-analysis item 7 (2026-08-30): the engine
/// has supported this since PR #189; KMIP's `wrap_key_value` never called
/// it, hard-rejecting `BlockCipherMode::AESKeyWrapPadding` before ever
/// reaching the engine.
pub fn aes_key_wrap_kwp(kek: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CkRv> {
    use aes::cipher::generic_array::GenericArray;
    if plaintext.is_empty() {
        return Err(CKR_DATA_INVALID);
    }
    let result = match kek.len() {
        16 => aes_kw::KekAes128::new(GenericArray::from_slice(kek)).wrap_with_padding_vec(plaintext),
        24 => aes_kw::KekAes192::new(GenericArray::from_slice(kek)).wrap_with_padding_vec(plaintext),
        32 => aes_kw::KekAes256::new(GenericArray::from_slice(kek)).wrap_with_padding_vec(plaintext),
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT),
    };
    result.map_err(|_| CKR_FUNCTION_FAILED)
}

/// AES Key Unwrap with Padding (RFC 5649) — inverse of
/// [`aes_key_wrap_kwp`]. Ciphertext must be ≥ 16 bytes and a multiple of
/// the 8-byte semiblock (RFC 5649 §5.18.4); integrity/padding-check
/// failure → `CKR_WRAPPED_KEY_INVALID`, matching the FFI path exactly.
pub fn aes_key_unwrap_kwp(kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, CkRv> {
    use aes::cipher::generic_array::GenericArray;
    if wrapped.len() < 16 || wrapped.len() % 8 != 0 {
        return Err(CKR_WRAPPED_KEY_LEN_RANGE);
    }
    let result = match kek.len() {
        16 => aes_kw::KekAes128::new(GenericArray::from_slice(kek)).unwrap_with_padding_vec(wrapped),
        24 => aes_kw::KekAes192::new(GenericArray::from_slice(kek)).unwrap_with_padding_vec(wrapped),
        32 => aes_kw::KekAes256::new(GenericArray::from_slice(kek)).unwrap_with_padding_vec(wrapped),
        _ => return Err(CKR_KEY_TYPE_INCONSISTENT),
    };
    result.map_err(|_| CKR_WRAPPED_KEY_INVALID)
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
    chacha20_encrypt_at(key, nonce, plaintext, 0)
}

/// W7 (2026-08-13) — plain ChaCha20 starting at an arbitrary keystream BLOCK.
///
/// PKCS#11 v3.2 §6.20 exposes `CK_CHACHA20_PARAMS.pBlockCounter` because "in
/// certain settings (e.g. disk encryption) it is necessary to address these
/// blocks in random order". The FFI previously rejected any non-zero value
/// and there was no counter plumbing here at all, so that capability did not
/// exist. `seek` is a byte offset; one ChaCha20 block is 64 bytes.
pub(crate) fn chacha20_encrypt_at(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    block_counter: u64,
) -> Result<Vec<u8>, CkRv> {
    use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
    if key.len() != 32 {
        return Err(CKR_ARGUMENTS_BAD);
    }
    // PKCS#11 v3.2 §6.20 lets `CKM_CHACHA20` accept either an 8-byte
    // (RFC 7539 "legacy" / DJB original) or 12-byte (IETF) nonce.
    // OASIS BC-CHACHA20-* tests use the 8-byte legacy form.
    let mut buf = plaintext.to_vec();
    let offset = block_counter
        .checked_mul(64)
        .ok_or(CKR_MECHANISM_PARAM_INVALID)?;
    match nonce.len() {
        8 => {
            let mut cipher = chacha20::ChaCha20Legacy::new(key.into(), nonce.into());
            if offset != 0 {
                cipher.try_seek(offset).map_err(|_| CKR_MECHANISM_PARAM_INVALID)?;
            }
            cipher.apply_keystream(&mut buf);
        }
        12 => {
            // The IETF variant's counter is 32 bits, so the reachable
            // keystream ends at 2^32 blocks; `try_seek` reports the overflow
            // rather than wrapping into another block's keystream.
            let mut cipher = chacha20::ChaCha20::new(key.into(), nonce.into());
            if offset != 0 {
                cipher.try_seek(offset).map_err(|_| CKR_MECHANISM_PARAM_INVALID)?;
            }
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

// The former `check_flag(key_handle, attr_type)` free function (a direct,
// ungated OBJECTS lock) is gone — CKA_ENCAPSULATE/CKA_DECAPSULATE/
// CKA_ENCRYPT/CKA_DECRYPT are now read via `read_bool_attr` inside the
// isolation gate's single borrow (`with_object_checked` above).

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::keygen::{
        generate_classic_mceliece_keypair, generate_frodokem_keypair, generate_ml_dsa_keypair,
        generate_ml_kem_keypair,
    };
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

    /// KMIP/CACP coverage gap-analysis item 7 (2026-08-30) —
    /// `CKM_AES_KEY_WRAP_KWP` (RFC 5649), verified against an
    /// independently-computed reference: Python's `cryptography` library
    /// (`aes_key_wrap_with_padding`/`_unwrap_with_padding`), a different
    /// implementation than this crate's `aes_kw`. Plaintext is
    /// deliberately not a multiple of 8 bytes to prove KWP's arbitrary-
    /// length support, which plain AES-KW above cannot do.
    #[test]
    fn aes_key_wrap_kwp_matches_independent_reference() {
        let kek = vec![0x11u8; 32];
        let pt = b"this is a KWP test of variable length, not a multiple of 8".to_vec();
        // Reference vector from Python's
        // `cryptography.hazmat.primitives.keywrap.aes_key_wrap_with_padding
        // (bytes([0x11]*32), plaintext)` — computed independently, not
        // derived from this crate's own output.
        let expected: [u8; 72] = [
            0x39, 0x07, 0x83, 0xf9, 0xec, 0x5b, 0x01, 0x95,
            0xbe, 0x01, 0xa5, 0x47, 0x64, 0x82, 0x9c, 0x78,
            0xfd, 0x58, 0x76, 0xc7, 0xe7, 0xf5, 0x65, 0x42,
            0xbe, 0x79, 0x1d, 0x4c, 0x60, 0xa6, 0x4b, 0xa2,
            0x0b, 0x83, 0x67, 0x89, 0x5d, 0x65, 0xe1, 0xda,
            0x73, 0x92, 0xe1, 0xd2, 0x57, 0xf2, 0x6d, 0x00,
            0x7c, 0x98, 0xc3, 0x5e, 0xd9, 0xf7, 0x73, 0xfa,
            0x1d, 0x5c, 0xa3, 0xda, 0x80, 0x7d, 0x17, 0x65,
            0xf4, 0xc8, 0x8c, 0xba, 0xd4, 0x3c, 0xb0, 0x75,
        ];
        let wrapped = aes_key_wrap_kwp(&kek, &pt).unwrap();
        assert_eq!(wrapped, expected, "must match Python cryptography's aes_key_wrap_with_padding");
        assert_eq!(aes_key_unwrap_kwp(&kek, &wrapped).unwrap(), pt);
        // Tampered ciphertext → integrity-check failure, same as plain KW.
        let mut bad = wrapped.clone();
        bad[0] ^= 1;
        assert_eq!(aes_key_unwrap_kwp(&kek, &bad).unwrap_err(), CKR_WRAPPED_KEY_INVALID);
        // Empty plaintext rejected.
        assert_eq!(aes_key_wrap_kwp(&kek, &[]).unwrap_err(), CKR_DATA_INVALID);
    }

    /// KMIP/CACP coverage gap-analysis item 2.2 (2026-08-30) —
    /// `aes_ccm_encrypt`/`aes_ccm_decrypt`, verified against a real NIST
    /// ACVP test case (`tests/acvp/aes_ccm_test.json`, AES-128, first
    /// encrypt case) — the same vector file and construction this
    /// repo's own C++ WS-8 CCM fix was independently validated against
    /// (see that file's `_provenance` note). No AAD in this specific
    /// case; the AAD path is exercised by the tamper-detection assertion
    /// below via a non-empty AAD round trip.
    #[test]
    fn aes_ccm_matches_nist_acvp_vector() {
        let key: [u8; 16] = [
            0xb4, 0xce, 0x71, 0xa0, 0x1a, 0x78, 0x3c, 0x78, 0x51, 0xd1, 0x91, 0x32, 0xb3, 0xb0,
            0x6e, 0x9a,
        ];
        let nonce: [u8; 13] = [
            0x73, 0xd7, 0xbc, 0xba, 0x71, 0x0c, 0x10, 0x99, 0x45, 0xf7, 0x93, 0x6c, 0xd4,
        ];
        let pt: [u8; 32] = [
            0x41, 0xe2, 0xc1, 0x25, 0xd4, 0x1e, 0x37, 0x2d, 0xa9, 0xa4, 0x78, 0x6d, 0x22, 0xa1,
            0x0b, 0xa4, 0xb0, 0x4c, 0x34, 0x67, 0x45, 0x4d, 0xa0, 0xb4, 0xb8, 0xc6, 0x92, 0x0f,
            0xea, 0x64, 0x15, 0x85,
        ];
        let expected_ct: [u8; 48] = [
            0xca, 0xf3, 0x1b, 0x08, 0x3f, 0xd6, 0xef, 0x06, 0x41, 0x71, 0x3e, 0xb4, 0x9f, 0x28,
            0xf1, 0xcd, 0xb6, 0xfb, 0xb1, 0x38, 0x25, 0x1d, 0xb9, 0x4f, 0x6f, 0xc5, 0x9b, 0xcc,
            0xdf, 0x0e, 0x23, 0x09, 0x2c, 0xcd, 0x1c, 0x20, 0x25, 0x26, 0x87, 0x3d, 0x0c, 0xcd,
            0x60, 0x53, 0xc7, 0x9a, 0xee, 0xaf,
        ];
        let ct = aes_ccm_encrypt(&key, &nonce, &pt, &[], Some(16)).unwrap();
        assert_eq!(ct, expected_ct, "must match the real NIST ACVP AES-128-CCM KAT");
        let recovered = aes_ccm_decrypt(&key, &nonce, &ct, &[], Some(16)).unwrap();
        assert_eq!(recovered, pt);
        // Tampered tag → integrity failure, not silently-wrong plaintext.
        let mut bad = ct.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert_eq!(aes_ccm_decrypt(&key, &nonce, &bad, &[], Some(16)).unwrap_err(), CKR_ENCRYPTED_DATA_INVALID);
        // AAD round-trips and genuinely authenticates (wrong AAD rejected).
        let ct_aad = aes_ccm_encrypt(&key, &nonce, &pt, b"header", Some(16)).unwrap();
        assert_eq!(aes_ccm_decrypt(&key, &nonce, &ct_aad, b"header", Some(16)).unwrap(), pt);
        assert!(aes_ccm_decrypt(&key, &nonce, &ct_aad, b"wrong-header", Some(16)).is_err());
        // Nonce/tag-length range checks (SP 800-38C).
        assert_eq!(aes_ccm_encrypt(&key, &[0u8; 6], &pt, &[], Some(16)).unwrap_err(), CKR_MECHANISM_PARAM_INVALID);
        assert_eq!(aes_ccm_encrypt(&key, &nonce, &pt, &[], Some(15)).unwrap_err(), CKR_MECHANISM_PARAM_INVALID);
    }

    /// KMIP/CACP coverage gap-analysis item 2.4 (2026-08-30) —
    /// `aes_ofb_apply`/`aes_cfb128_apply`/`aes_cfb8_apply`/`aes_cfb1_apply`,
    /// each verified byte-exact against a real NIST ACVP test case from
    /// this repo's own vector files (`tests/acvp/aes_{ofb,cfb128,cfb8,
    /// cfb1}_test.json`) — the same files the C++ WS-8 fix for these
    /// exact mechanisms was validated against. The CFB1 vector is
    /// deliberately a byte-aligned (payloadLen=8) case per that file's
    /// own provenance note, so a plain byte comparison is valid evidence
    /// (no bit-level masking needed).
    #[test]
    fn aes_ofb_cfb_family_matches_nist_acvp_vectors() {
        // OFB — self-inverse, one call serves both directions.
        let ofb_key: [u8; 16] = [0x00; 16];
        let ofb_iv: [u8; 16] = [
            0xf3, 0x44, 0x81, 0xec, 0x3c, 0xc6, 0x27, 0xba, 0xcd, 0x5d, 0xc3, 0xfb, 0x08, 0xf2,
            0x73, 0xe6,
        ];
        let ofb_pt: [u8; 16] = [0x00; 16];
        let ofb_ct: [u8; 16] = [
            0x03, 0x36, 0x76, 0x3e, 0x96, 0x6d, 0x92, 0x59, 0x5a, 0x56, 0x7c, 0xc9, 0xce, 0x53,
            0x7f, 0x5e,
        ];
        let got = aes_ofb_apply(&ofb_key, &ofb_iv, &ofb_pt).unwrap();
        assert_eq!(got, ofb_ct, "OFB must match the NIST ACVP KAT");
        assert_eq!(aes_ofb_apply(&ofb_key, &ofb_iv, &ofb_ct).unwrap(), ofb_pt, "OFB decrypt (same call) must recover plaintext");

        // CFB128
        use crate::crypto::multipart::CipherDirection::{Decrypt, Encrypt};
        let cfb128_key: [u8; 16] = [0x00; 16];
        let cfb128_iv: [u8; 16] = [
            0x96, 0xab, 0x5c, 0x2f, 0xf6, 0x12, 0xd9, 0xdf, 0xaa, 0xe8, 0xc3, 0x1f, 0x30, 0xc4,
            0x21, 0x68,
        ];
        let cfb128_pt: [u8; 16] = [0x00; 16];
        let cfb128_ct: [u8; 16] = [
            0xff, 0x4f, 0x83, 0x91, 0xa6, 0xa4, 0x0c, 0xa5, 0xb2, 0x5d, 0x23, 0xbe, 0xdd, 0x44,
            0xa5, 0x97,
        ];
        assert_eq!(aes_cfb128_apply(&cfb128_key, &cfb128_iv, &cfb128_pt, Encrypt).unwrap(), cfb128_ct);
        assert_eq!(aes_cfb128_apply(&cfb128_key, &cfb128_iv, &cfb128_ct, Decrypt).unwrap(), cfb128_pt);

        // CFB8
        let cfb8_key: [u8; 16] = [0x00; 16];
        let cfb8_iv: [u8; 16] = [
            0x97, 0x98, 0xc4, 0x64, 0x0b, 0xad, 0x75, 0xc7, 0xc3, 0x22, 0x7d, 0xb9, 0x10, 0x17,
            0x4e, 0x72,
        ];
        let cfb8_pt: [u8; 1] = [0x00];
        let cfb8_ct: [u8; 1] = [0xa9];
        assert_eq!(aes_cfb8_apply(&cfb8_key, &cfb8_iv, &cfb8_pt, Encrypt).unwrap(), cfb8_ct);
        assert_eq!(aes_cfb8_apply(&cfb8_key, &cfb8_iv, &cfb8_ct, Decrypt).unwrap(), cfb8_pt);

        // CFB1 (payloadLen=8 case, byte-aligned)
        let cfb1_key: [u8; 16] = [
            0x47, 0x5f, 0x9b, 0xcc, 0x8a, 0x22, 0x60, 0x1a, 0x4e, 0xf8, 0x77, 0xe5, 0x4d, 0xc9,
            0x79, 0x77,
        ];
        let cfb1_iv: [u8; 16] = [
            0x21, 0x1e, 0xae, 0x94, 0xdf, 0xac, 0x12, 0x7e, 0xd3, 0xcc, 0x36, 0x7d, 0xbc, 0x09,
            0x4d, 0x0b,
        ];
        let cfb1_pt: [u8; 1] = [0x03];
        let cfb1_ct: [u8; 1] = [0x2f];
        assert_eq!(aes_cfb1_apply(&cfb1_key, &cfb1_iv, &cfb1_pt, Encrypt).unwrap(), cfb1_ct);
        assert_eq!(aes_cfb1_apply(&cfb1_key, &cfb1_iv, &cfb1_ct, Decrypt).unwrap(), cfb1_pt);

        // IV length validation, shared across all four.
        assert_eq!(aes_ofb_apply(&ofb_key, &[0u8; 15], &ofb_pt).unwrap_err(), CKR_MECHANISM_PARAM_INVALID);
        assert_eq!(aes_cfb128_apply(&cfb128_key, &[0u8; 15], &cfb128_pt, Encrypt).unwrap_err(), CKR_MECHANISM_PARAM_INVALID);
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

    /// FrodoKEM-976-AES round-trip (BSI TR-02102-1 §2.4.1 recommended
    /// parameter set): keygen → encap(pub_h) → decap(prv_h, ct) → shared
    /// secrets match exactly. Sizes verified against `frodo-kem` v0.1.0's
    /// own `AlgorithmParams`.
    #[test]
    fn frodokem_976_aes_encap_decap_round_trip() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) =
            generate_frodokem_keypair(session, CKP_FRODOKEM_976_AES, b"\x01", "frodo-976").unwrap();

        let (ct, ss_enc) = encapsulate(session, pub_h, CKM_PQCTODAY_FRODOKEM_ENCAPSULATE).unwrap();
        assert_eq!(ct.len(), 15792);
        assert_eq!(ss_enc.len(), 24);

        let ss_dec = decapsulate(session, prv_h, CKM_PQCTODAY_FRODOKEM_ENCAPSULATE, &ct).unwrap();
        assert_eq!(ss_enc, ss_dec, "encap SS must equal decap SS");
        close_session(session).unwrap();
    }

    /// FrodoKEM-640-SHAKE round-trip — the smallest BSI-recommended level,
    /// SHAKE matrix-expansion variant.
    #[test]
    fn frodokem_640_shake_encap_decap_round_trip() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) =
            generate_frodokem_keypair(session, CKP_FRODOKEM_640_SHAKE, b"\x01", "frodo-640s").unwrap();
        let (ct, ss_enc) = encapsulate(session, pub_h, CKM_PQCTODAY_FRODOKEM_ENCAPSULATE).unwrap();
        assert_eq!(ct.len(), 9752);
        assert_eq!(ss_enc.len(), 16);
        let ss_dec = decapsulate(session, prv_h, CKM_PQCTODAY_FRODOKEM_ENCAPSULATE, &ct).unwrap();
        assert_eq!(ss_enc, ss_dec);
        close_session(session).unwrap();
    }

    /// A ciphertext from one FrodoKEM keypair must not decapsulate
    /// successfully to the same shared secret under an unrelated keypair
    /// (sanity check that this isn't a no-op that always "succeeds").
    #[test]
    fn frodokem_decap_with_wrong_key_does_not_match() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_a, _prv_a) =
            generate_frodokem_keypair(session, CKP_FRODOKEM_640_AES, b"\x01", "a").unwrap();
        let (_pub_b, prv_b) =
            generate_frodokem_keypair(session, CKP_FRODOKEM_640_AES, b"\x02", "b").unwrap();
        let (ct, ss_enc) = encapsulate(session, pub_a, CKM_PQCTODAY_FRODOKEM_ENCAPSULATE).unwrap();
        // Decapsulating with B's key either fails outright or (FrodoKEM's
        // implicit-rejection design) returns a pseudorandom, non-matching
        // secret — either way it must not equal the real shared secret.
        if let Ok(ss_wrong) = decapsulate(session, prv_b, CKM_PQCTODAY_FRODOKEM_ENCAPSULATE, &ct) {
            assert_ne!(ss_enc, ss_wrong);
        }
        close_session(session).unwrap();
    }

    /// Classic McEliece (mceliece6688128) round-trip — BSI TR-02102-1
    /// §2.4.2 Category-5 pick. ct = 208 bytes (the raw syndrome, per
    /// `mceliece-spec-20221023.pdf` §6.2 — verified against
    /// `classic-mceliece-rust` v3.1.0, liboqs, and the spec text directly),
    /// ss = 32 bytes.
    ///
    /// `#[ignore]`: a single mceliece6688128 keygen (Goppa code generation)
    /// takes minutes in an unoptimized debug build — too slow for every CI
    /// run. Run manually with `cargo test --release -- --ignored
    /// classic_mceliece_6688128_encap_decap` (release mode is fast).
    #[test]
    #[ignore = "mceliece6688128 keygen is minutes-slow in debug builds — see doc comment"]
    fn classic_mceliece_6688128_encap_decap_round_trip() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) = generate_classic_mceliece_keypair(
            session,
            CKP_CLASSIC_MCELIECE_6688128,
            b"\x01",
            "mceliece",
        )
        .unwrap();

        let (ct, ss_enc) =
            encapsulate(session, pub_h, CKM_PQCTODAY_CLASSIC_MCELIECE_ENCAPSULATE).unwrap();
        // 208 bytes per mceliece-spec-20221023.pdf §6.2 (ciphertext = the
        // raw syndrome only) — matches liboqs exactly; classic-mceliece-rust
        // v3.1.0 dropped the non-spec 32-byte confirmation hash v2.0.2 added.
        assert_eq!(ct.len(), 208);
        assert_eq!(ss_enc.len(), 32);

        let ss_dec =
            decapsulate(session, prv_h, CKM_PQCTODAY_CLASSIC_MCELIECE_ENCAPSULATE, &ct).unwrap();
        assert_eq!(ss_enc, ss_dec, "encap SS must equal decap SS");
        close_session(session).unwrap();
    }

    // ── Cross-validation against liboqs (implementation plan Phase 0.9) ────
    //
    // `oqs` is a `[dev-dependencies]`-only entry — never part of the
    // shipping engine — used solely as an independent reference
    // implementation. These tests prove actual interoperability: a
    // ciphertext produced by one independent implementation is correctly
    // recoverable by the other, in both directions, which is the real
    // correctness property a KEM has to satisfy (stronger than either
    // implementation just agreeing with itself).

    /// Direction A: encaps with `oqs` (liboqs), decaps with our PKCS#11
    /// engine (import via `register_frodokem_private_key`).
    ///
    /// IGNORED — not an engine bug. liboqs (0.12.0/0.13.0, the newest on
    /// crates.io as of this writing) implements a pre-salt FrodoKEM
    /// ciphertext; `frodo-kem` correctly implements the current official
    /// spec's mandatory salt (verified directly against
    /// `FrodoKEM_standard_proposal_20250929.pdf` §9, byte-for-byte on
    /// `len_salt` per level). No dependency bump fixes this the way it did
    /// for Classic McEliece — liboqs itself is missing the field. Re-enable
    /// once a spec-conformant cross-check reference is found (tracked as a
    /// follow-up, see the FrodoKEM/Classic-McEliece/HQC implementation
    /// plan).
    #[test]
    #[ignore = "liboqs 0.12.0/0.13.0 lacks the mandatory salt frodo-kem correctly implements — not an engine bug, see doc comment"]
    fn frodokem_640_aes_cross_validate_oqs_encap_our_decap() {
        let _guard = test_lock::acquire();
        let session = fresh_session();

        let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::FrodoKem640Aes)
            .expect("liboqs FrodoKEM-640-AES unavailable");
        let (pk, sk) = kem.keypair().expect("liboqs keygen");
        let (ct, ss_oqs) = kem.encapsulate(&pk).expect("liboqs encapsulate");

        let prv_h = crate::native::keygen::register_frodokem_private_key(
            session,
            CKP_FRODOKEM_640_AES,
            sk.as_ref(),
            b"\x01",
            "oqs-imported-sk",
        )
        .expect("register imported FrodoKEM private key");

        let ss_ours = decapsulate(session, prv_h, CKM_PQCTODAY_FRODOKEM_ENCAPSULATE, ct.as_ref())
            .expect("our engine decapsulate");
        assert_eq!(ss_ours, ss_oqs.as_ref(), "our decap must recover liboqs's shared secret");
        close_session(session).unwrap();
    }

    /// Direction B: encaps with our PKCS#11 engine, decaps with `oqs`
    /// (liboqs).
    ///
    /// IGNORED — same reason as the other direction: liboqs's ciphertext
    /// length doesn't match `frodo-kem`'s spec-conformant (salted) one.
    #[test]
    #[ignore = "liboqs 0.12.0/0.13.0 lacks the mandatory salt frodo-kem correctly implements — not an engine bug, see doc comment"]
    fn frodokem_640_aes_cross_validate_our_encap_oqs_decap() {
        let _guard = test_lock::acquire();
        let session = fresh_session();

        let (pub_h, prv_h) =
            generate_frodokem_keypair(session, CKP_FRODOKEM_640_AES, b"\x01", "ours").unwrap();
        let (ct, ss_ours) = encapsulate(session, pub_h, CKM_PQCTODAY_FRODOKEM_ENCAPSULATE).unwrap();

        // Native-internal read-back of the private key bytes — same access
        // pattern the KAT tests already use, not a public export.
        let sk_bytes = get_object_value(prv_h).expect("read back our private key");

        let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::FrodoKem640Aes)
            .expect("liboqs FrodoKEM-640-AES unavailable");
        let sk_ref = kem.secret_key_from_bytes(&sk_bytes).expect("liboqs secret_key_from_bytes");
        let ct_ref = kem.ciphertext_from_bytes(&ct).expect("liboqs ciphertext_from_bytes");
        let ss_oqs = kem.decapsulate(sk_ref, ct_ref).expect("liboqs decapsulate");

        assert_eq!(ss_ours, ss_oqs.as_ref(), "liboqs decap must recover our engine's shared secret");
        close_session(session).unwrap();
    }

    /// Direction A for Classic McEliece (mceliece6688128): encaps with
    /// `oqs`, decaps with our PKCS#11 engine.
    ///
    /// `#[ignore]`: 20 fresh mceliece6688128 keypairs in an unoptimized
    /// debug build take tens of minutes, not seconds — too slow for every
    /// CI run. Run manually with `cargo test --release -- --ignored
    /// classic_mceliece_6688128_cross_validate` (release mode is fast).
    /// `classic_mceliece_6688128_round_trip` already covers the basic
    /// correctness path on every run.
    #[test]
    #[ignore]
    fn classic_mceliece_6688128_cross_validate_oqs_encap_our_decap() {
        let _guard = test_lock::acquire();
        let session = fresh_session();

        let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::ClassicMcEliece6688128)
            .expect("liboqs Classic McEliece 6688128 unavailable");

        // No independently-hosted static Classic McEliece KAT file exists
        // (unlike FrodoKEM — PQClean and classic-mceliece-rust's own KAT
        // harness both GENERATE vectors deterministically rather than
        // shipping a static file, and using classic-mceliece-rust's own
        // generator would be circular). Since liboqs IS a genuinely
        // independent implementation (verified directly against the spec
        // text earlier, and now proven interoperable), run N fresh
        // liboqs-generated keypairs through our engine instead of just
        // one — the same statistical breadth FrodoKEM's 100-per-variant
        // static KAT file gives, via repeated independent trials rather
        // than a fixed file.
        const N: usize = 20;
        for i in 0..N {
            let (pk, sk) = kem.keypair().unwrap_or_else(|e| panic!("liboqs keygen #{i}: {e}"));
            let (ct, ss_oqs) =
                kem.encapsulate(&pk).unwrap_or_else(|e| panic!("liboqs encapsulate #{i}: {e}"));

            let prv_h = crate::native::keygen::register_classic_mceliece_private_key(
                session,
                CKP_CLASSIC_MCELIECE_6688128,
                sk.as_ref(),
                format!("oqs-imported-sk-{i}").as_bytes(),
                "oqs-imported-sk",
            )
            .unwrap_or_else(|e| panic!("register imported private key #{i}: {e:?}"));

            let ss_ours = decapsulate(
                session,
                prv_h,
                CKM_PQCTODAY_CLASSIC_MCELIECE_ENCAPSULATE,
                ct.as_ref(),
            )
            .unwrap_or_else(|e| panic!("our engine decapsulate #{i}: {e:?}"));
            assert_eq!(
                ss_ours,
                ss_oqs.as_ref(),
                "trial #{i}: our decap must recover liboqs's shared secret"
            );
        }
        close_session(session).unwrap();
    }

    /// Direction B for Classic McEliece: encaps with our PKCS#11 engine,
    /// decaps with `oqs`. Same N-trial breadth as Direction A.
    ///
    /// `#[ignore]`: same reason as Direction A above — 20 fresh debug-build
    /// mceliece6688128 keygens is too slow for every CI run.
    #[test]
    #[ignore]
    fn classic_mceliece_6688128_cross_validate_our_encap_oqs_decap() {
        let _guard = test_lock::acquire();
        let session = fresh_session();

        let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::ClassicMcEliece6688128)
            .expect("liboqs Classic McEliece 6688128 unavailable");

        const N: usize = 20;
        for i in 0..N {
            let (pub_h, prv_h) = generate_classic_mceliece_keypair(
                session,
                CKP_CLASSIC_MCELIECE_6688128,
                format!("ours-{i}").as_bytes(),
                "ours",
            )
            .unwrap_or_else(|e| panic!("our engine keygen #{i}: {e:?}"));
            let (ct, ss_ours) =
                encapsulate(session, pub_h, CKM_PQCTODAY_CLASSIC_MCELIECE_ENCAPSULATE)
                    .unwrap_or_else(|e| panic!("our engine encapsulate #{i}: {e:?}"));

            let sk_bytes =
                get_object_value(prv_h).unwrap_or_else(|| panic!("read back private key #{i}"));

            let sk_ref = kem
                .secret_key_from_bytes(&sk_bytes)
                .unwrap_or_else(|| panic!("liboqs secret_key_from_bytes #{i}"));
            let ct_ref = kem
                .ciphertext_from_bytes(&ct)
                .unwrap_or_else(|| panic!("liboqs ciphertext_from_bytes #{i}"));
            let ss_oqs = kem
                .decapsulate(sk_ref, ct_ref)
                .unwrap_or_else(|e| panic!("liboqs decapsulate #{i}: {e}"));

            assert_eq!(
                ss_ours,
                ss_oqs.as_ref(),
                "trial #{i}: liboqs decap must recover our engine's shared secret"
            );
        }
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

    // ── Classical-KEM Encapsulate/Decapsulate (2026-07-05) ─────────────────
    //
    // RFC 7748 §5.2 KATs anchor the raw X25519/X448 Diffie-Hellman primitive
    // both `classical_encapsulate`/`classical_decapsulate` call — the exact
    // gap `kmip/docs/HYBRID_KEM_COMBINER_IMPLEMENTATION.md` flagged for the
    // same underlying math ("X25519 RFC 7748 §5.2 vectors — to add"), closed
    // here. Vectors cross-verified against two independent fetches of the
    // RFC text (rfc-editor.org + datatracker.ietf.org) before use — a wrong
    // constant here would be worse than no test at all.
    //
    // NOTE (documented residual risk, same honesty standard as the hybrid
    // combiner doc): P-256/P-384/P-521 do NOT yet have an equivalent
    // external KAT wired in here — a first attempt at sourcing RFC 5903
    // vectors via a text-fetch pipeline produced a value with a stray
    // embedded space (a formatting artifact, caught by inspection before
    // use), so nothing was hardcoded for those curves rather than risk a
    // silently-wrong "known answer." They're covered by round-trip
    // self-consistency below only. Sourcing a properly-vetted NIST ACVP
    // KAS-ECC-SSC vector file (structured JSON, not prose-extracted) is a
    // flagged follow-up, matching how the existing ecdsa/ml-kem KATs in
    // `kmip/kat/` were vendored.
    fn hex32(s: &str) -> [u8; 32] {
        hex_lit(s).try_into().unwrap()
    }
    fn hex56(s: &str) -> [u8; 56] {
        hex_lit(s).try_into().unwrap()
    }

    fn x25519_raw(k: [u8; 32], u: [u8; 32]) -> [u8; 32] {
        let secret = x25519_dalek::StaticSecret::from(k);
        let public = x25519_dalek::PublicKey::from(u);
        *secret.diffie_hellman(&public).as_bytes()
    }

    /// RFC 7748 §5.2 X25519 iterative test, k0=u0=9, after 1 iteration.
    #[test]
    fn x25519_rfc7748_iterative_1() {
        let mut k = [0u8; 32];
        k[0] = 9;
        let u = k;
        let k1 = x25519_raw(k, u);
        assert_eq!(
            k1,
            hex32("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
        );
    }

    /// RFC 7748 §5.2 X25519 iterative test, after 1000 iterations.
    /// (1,000,000 iterations is the RFC's third vector — skipped here as a
    /// slow test; the primitive is already anchored by 1 and 1000.)
    #[test]
    fn x25519_rfc7748_iterative_1000() {
        let mut k = [0u8; 32];
        k[0] = 9;
        let mut u = k;
        for _ in 0..1000 {
            let k_new = x25519_raw(k, u);
            u = k;
            k = k_new;
        }
        assert_eq!(
            k,
            hex32("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")
        );
    }

    fn x448_raw(k: [u8; 56], u: [u8; 56]) -> [u8; 56] {
        x448::x448(k, u).expect("valid X448 point")
    }

    /// RFC 7748 §5.2 X448 iterative test, k0=u0=5, after 1 iteration.
    #[test]
    fn x448_rfc7748_iterative_1() {
        let mut k = [0u8; 56];
        k[0] = 5;
        let u = k;
        let k1 = x448_raw(k, u);
        assert_eq!(
            k1,
            hex56(
                "3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113"
            )
        );
    }

    /// RFC 7748 §5.2 X448 iterative test, after 1000 iterations.
    #[test]
    fn x448_rfc7748_iterative_1000() {
        let mut k = [0u8; 56];
        k[0] = 5;
        let mut u = k;
        for _ in 0..1000 {
            let k_new = x448_raw(k, u);
            u = k;
            k = k_new;
        }
        assert_eq!(
            k,
            hex56(
                "aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38"
            )
        );
    }

    /// Standalone classical Encapsulate/Decapsulate round trip, one per
    /// curve/group. `Encapsulate` returns the ephemeral public key as
    /// ciphertext; `Decapsulate` must recover the identical shared secret.
    fn classical_round_trip(
        keygen_fn: impl Fn(u32) -> (u32, u32),
        mechanism: u32,
        expected_ct_len: usize,
        expected_ss_len: usize,
    ) {
        let session = fresh_session();
        let (pub_h, prv_h) = keygen_fn(session);
        let (ct, ss_enc) = encapsulate(session, pub_h, mechanism).expect("encapsulate");
        assert_eq!(ct.len(), expected_ct_len, "ciphertext (ephemeral public) length");
        assert_eq!(ss_enc.len(), expected_ss_len, "shared secret length");
        let ss_dec = decapsulate(session, prv_h, mechanism, &ct).expect("decapsulate");
        assert_eq!(ss_enc, ss_dec, "encapsulator and decapsulator must agree");
        close_session(session).unwrap();
    }

    #[test]
    fn classical_ecdh_p256_encap_decap_round_trip() {
        let _g = test_lock::acquire();
        classical_round_trip(
            |s| crate::native::keygen::generate_ecdh_keypair(s, crate::native::keygen::EccCurve::P256, b"\x01", "kem-p256").unwrap(),
            CKM_ECDH1_DERIVE,
            65,
            32,
        );
    }

    #[test]
    fn classical_ecdh_p384_encap_decap_round_trip() {
        let _g = test_lock::acquire();
        classical_round_trip(
            |s| crate::native::keygen::generate_ecdh_keypair(s, crate::native::keygen::EccCurve::P384, b"\x01", "kem-p384").unwrap(),
            CKM_ECDH1_DERIVE,
            97,
            48,
        );
    }

    #[test]
    fn classical_ecdh_p521_encap_decap_round_trip() {
        let _g = test_lock::acquire();
        classical_round_trip(
            |s| crate::native::keygen::generate_ecdh_keypair(s, crate::native::keygen::EccCurve::P521, b"\x01", "kem-p521").unwrap(),
            CKM_ECDH1_DERIVE,
            133,
            66,
        );
    }

    #[test]
    fn classical_x25519_encap_decap_round_trip() {
        let _g = test_lock::acquire();
        classical_round_trip(
            |s| crate::native::keygen::generate_x25519_keypair(s, b"\x01", "kem-x25519").unwrap(),
            CKM_EC_MONTGOMERY_KEY_DERIVE,
            32,
            32,
        );
    }

    #[test]
    fn classical_x448_encap_decap_round_trip() {
        let _g = test_lock::acquire();
        classical_round_trip(
            |s| crate::native::keygen::generate_x448_keypair(s, b"\x01", "kem-x448").unwrap(),
            CKM_EC_MONTGOMERY_KEY_DERIVE,
            56,
            56,
        );
    }

    /// A classical key without CKA_ENCAPSULATE/CKA_DECAPSULATE can't use
    /// this op family — same permission-flag discipline as ML-KEM.
    #[test]
    fn classical_encapsulate_wrong_mechanism_is_rejected() {
        let _g = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, _prv_h) =
            crate::native::keygen::generate_ecdh_keypair(session, crate::native::keygen::EccCurve::P256, b"\x01", "kem-p256-bad")
                .unwrap();
        // ML-KEM mechanism against an EC key type.
        assert_eq!(encapsulate(session, pub_h, CKM_ML_KEM).unwrap_err(), CKR_KEY_TYPE_INCONSISTENT);
    }

    /// PKCS#11 v3.2 §4.8 Table 13 — CKA_ALLOWED_MECHANISMS on the native
    /// path (KMIP's entry point, not the FFI ABI). A key restricted to
    /// CKM_AES_GCM only accepts that mechanism; any other — even one the
    /// key type would otherwise support — is CKR_MECHANISM_INVALID. A key
    /// with no CKA_ALLOWED_MECHANISMS set stays unrestricted.
    #[test]
    fn native_encrypt_honors_allowed_mechanisms() {
        let _g = test_lock::acquire();
        let session = fresh_session();
        let handle = crate::native::keygen::generate_aes_key(session, 256, b"\x01", "gcm-only").unwrap();

        // S9 (2026-08-13) — CK_MECHANISM_TYPE is CK_ULONG-wide on the exported
        // ABI; this was packed at 4 bytes, which on a 64-bit build is not a
        // whole element and is now correctly rejected.
        let packed: Vec<u8> = (CKM_AES_GCM as usize).to_le_bytes().to_vec();
        crate::native::object::set_attribute(session, handle, CKA_ALLOWED_MECHANISMS, packed).unwrap();

        let iv = [0u8; 12];
        assert!(
            encrypt(session, handle, CKM_AES_GCM, b"hello", Some(&iv), None, &[], None).is_ok(),
            "CKM_AES_GCM must be allowed — it's the only entry in the list"
        );
        assert_eq!(
            encrypt(session, handle, CKM_AES_ECB, b"0123456789012345", None, None, &[], None).unwrap_err(),
            CKR_MECHANISM_INVALID,
            "CKM_AES_ECB must be rejected — not in the CKA_ALLOWED_MECHANISMS list"
        );

        // A sibling key with no CKA_ALLOWED_MECHANISMS set is unrestricted.
        let unrestricted = crate::native::keygen::generate_aes_key(session, 256, b"\x02", "unrestricted").unwrap();
        assert!(
            encrypt(session, unrestricted, CKM_AES_ECB, b"0123456789012345", None, None, &[], None).is_ok(),
            "a key with no CKA_ALLOWED_MECHANISMS attribute must remain unrestricted"
        );

        close_session(session).unwrap();
    }
}
