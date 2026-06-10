//! Sign / Verify — typed dispatcher over `crypto::handlers::sign_*` and
//! `crypto::handlers::verify_*` (which already accept typed args).
//!
//! Resolves the key handle to its stored bytes via `state::*`, dispatches
//! on `mechanism` based on the engine's existing per-family logic, calls
//! the right typed primitive. Returns the signature as `Vec<u8>` (no
//! caller-allocated output buffer).
//!
//! Mirrors the dispatch logic in `ffi::C_Sign` / `ffi::C_Verify` exactly,
//! minus the wasm32 pointer marshalling and the stateful HSS / XMSS / LMS
//! paths (those require coordinated `CKA_STATEFUL_KEY_STATE` updates
//! that don't map cleanly to the Result<Vec<u8>, _> shape; KMIP doesn't
//! need them per Phase 4.5 FIPS-only scope).
//!
//! See [`super`] for the typed-vs-FFI architectural relationship.

use super::CkRv;
use crate::constants::*;
use crate::crypto::handlers::{
    is_prehash_ml_dsa, is_prehash_slh_dsa, sign_ecdsa, sign_eddsa, sign_eddsa_ph, sign_hmac,
    sign_kmac, sign_ml_dsa, sign_rsa, sign_slh_dsa, verify_ecdsa, verify_eddsa, verify_eddsa_ph,
    verify_hmac, verify_ml_dsa, verify_rsa, verify_slh_dsa,
};
use crate::state::{
    get_ec_point_sec1, get_object_attr_u32, get_object_param_set, get_object_value,
    get_rsa_public_components, OBJECTS,
};

// PKCS#11 v3.2 §5.12.4 — `CKA_SIGN` (private key) / `CKA_VERIFY` (public key)
// must be true before sign / verify is permitted. Engine constants:
use crate::constants::{CKA_SIGN, CKA_VERIFY};

/// Sign `data` with the key at `key_handle` using `mechanism`. Dispatches
/// to `crypto::handlers::sign_{ml_dsa, slh_dsa, rsa, ecdsa, eddsa, hmac,
/// kmac}` based on `mechanism`.
///
/// **Pre-conditions**:
/// - `key_handle` must refer to a key with `CKA_SIGN = true`. For PQC
///   sig algorithms this is the **private** key from
///   [`super::keygen::generate_ml_dsa_keypair`] / `generate_slh_dsa_keypair`.
/// - `mechanism` must match the key's algorithm family
///   (`CKM_ML_DSA` for ML-DSA keys, `CKM_SLH_DSA` for SLH-DSA, etc.).
///
/// **Returns** the raw signature bytes — length is per FIPS spec
/// (e.g. ML-DSA-65: 3309, ML-DSA-87: 4627).
pub fn sign(
    _session: u32,
    key_handle: u32,
    mechanism: u32,
    data: &[u8],
) -> Result<Vec<u8>, CkRv> {
    // CKA_SIGN gate.
    if !check_can_sign(key_handle, CKA_SIGN) {
        return Err(CKR_KEY_FUNCTION_NOT_PERMITTED);
    }

    let sk_bytes = get_object_value(key_handle).ok_or(CKR_ARGUMENTS_BAD)?;
    let ps = get_object_param_set(key_handle);

    match mechanism {
        m if m == CKM_ML_DSA || is_prehash_ml_dsa(m) => {
            // Native surface signs with empty context, hedged (the FIPS 204
            // defaults) — same convention as the SLH-DSA arm below.
            sign_ml_dsa(m, ps, &sk_bytes, data, &[], false)
        }
        m if m == CKM_SLH_DSA || is_prehash_slh_dsa(m) => {
            // v0.1: SLH-DSA signing uses empty context + non-deterministic
            // (random hedge). FIPS 205 §10. KMIP's Phase-5 Sign handler
            // doesn't expose a context param yet; if it ever does, this
            // signature can grow optional args.
            sign_slh_dsa(m, ps, &sk_bytes, data, &[], false)
        }
        CKM_SHA256_HMAC | CKM_SHA384_HMAC | CKM_SHA512_HMAC | CKM_SHA3_256_HMAC
        | CKM_SHA3_512_HMAC => sign_hmac(mechanism, &sk_bytes, data),
        CKM_KMAC_128 | CKM_KMAC_256 => sign_kmac(mechanism, &sk_bytes, data),
        CKM_SHA256_RSA_PKCS | CKM_SHA256_RSA_PKCS_PSS => sign_rsa(mechanism, &sk_bytes, data, None),
        CKM_ECDSA | CKM_ECDSA_SHA256 | CKM_ECDSA_SHA384 | CKM_ECDSA_SHA512 => {
            sign_ecdsa(mechanism, ps, &sk_bytes, data)
        }
        CKM_EDDSA => sign_eddsa(&sk_bytes, data),
        CKM_EDDSA_PH => sign_eddsa_ph(&sk_bytes, data),
        _ => Err(CKR_MECHANISM_INVALID),
    }
}

/// Verify `signature` over `data` with the key at `key_handle` using
/// `mechanism`.
///
/// **Returns**:
/// - `Ok(true)` — signature is valid.
/// - `Ok(false)` — signature is invalid (matches KMIP's
///   `validity_indicator` model — a failed verification is NOT a
///   protocol error).
/// - `Err(_)` — protocol-level failure (wrong key type, bad mechanism,
///   missing key material, …).
pub fn verify(
    _session: u32,
    key_handle: u32,
    mechanism: u32,
    data: &[u8],
    signature: &[u8],
) -> Result<bool, CkRv> {
    // CKA_VERIFY gate.
    if !check_can_sign(key_handle, CKA_VERIFY) {
        return Err(CKR_KEY_FUNCTION_NOT_PERMITTED);
    }

    // For most algorithms `CKA_VALUE` holds the verification key bytes
    // (ML-DSA, SLH-DSA, EdDSA, HMAC, KMAC). RSA/ECDSA public keys are
    // stored in dedicated attributes (modulus+exp / EC point).
    let pk_bytes = get_object_value(key_handle).unwrap_or_default();
    let ps = get_object_param_set(key_handle);

    let result: Result<(), CkRv> = match mechanism {
        m if m == CKM_ML_DSA || is_prehash_ml_dsa(m) => {
            verify_ml_dsa(m, ps, &pk_bytes, data, signature, &[])
        }
        m if m == CKM_SLH_DSA || is_prehash_slh_dsa(m) => {
            verify_slh_dsa(m, ps, &pk_bytes, data, signature, &[])
        }
        CKM_SHA256_HMAC | CKM_SHA384_HMAC | CKM_SHA512_HMAC | CKM_SHA3_256_HMAC
        | CKM_SHA3_512_HMAC => verify_hmac(mechanism, &pk_bytes, data, signature),
        CKM_KMAC_128 | CKM_KMAC_256 => {
            // KMAC verify is constant-time signature comparison against a
            // fresh MAC, mirroring `ffi::C_Verify` behaviour.
            match sign_kmac(mechanism, &pk_bytes, data) {
                Ok(mac) => {
                    use subtle::ConstantTimeEq;
                    if mac.len() == signature.len() && mac.ct_eq(signature).into() {
                        Ok(())
                    } else {
                        Err(CKR_SIGNATURE_INVALID)
                    }
                }
                Err(e) => Err(e),
            }
        }
        CKM_SHA256_RSA_PKCS | CKM_SHA256_RSA_PKCS_PSS => match get_rsa_public_components(key_handle) {
            Some((n, e)) => verify_rsa(mechanism, &n, &e, data, signature, None),
            None => Err(CKR_KEY_TYPE_INCONSISTENT),
        },
        CKM_ECDSA | CKM_ECDSA_SHA256 | CKM_ECDSA_SHA384 | CKM_ECDSA_SHA512 => {
            match get_ec_point_sec1(key_handle) {
                Some(point) => verify_ecdsa(mechanism, ps, &point, data, signature),
                None => Err(CKR_KEY_TYPE_INCONSISTENT),
            }
        }
        CKM_EDDSA => verify_eddsa(&pk_bytes, data, signature),
        CKM_EDDSA_PH => verify_eddsa_ph(&pk_bytes, data, signature),
        _ => Err(CKR_MECHANISM_INVALID),
    };

    match result {
        Ok(()) => Ok(true),
        // CKR_SIGNATURE_INVALID is the "valid call, signature didn't
        // verify" outcome — surface as Ok(false), matching the KMIP
        // ValidityIndicator model.
        Err(CKR_SIGNATURE_INVALID) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Check `CKA_SIGN` (for sign) or `CKA_VERIFY` (for verify) on the key.
/// Returns `false` if the key is missing or the flag is not set.
fn check_can_sign(key_handle: u32, attr_type: u32) -> bool {
    // PKCS#11 v3.2 §5.12.4 — single-byte CK_BBOOL: 0x01 = true.
    OBJECTS.with(|o| {
        o.borrow()
            .get(&key_handle)
            .and_then(|attrs| attrs.get(&attr_type))
            .map(|v| !v.is_empty() && v[0] == 0x01)
            .unwrap_or(false)
    })
}

// Suppress unused-import warning when not all dispatch paths reference
// every helper (e.g. get_object_attr_u32 only used by future LMS path).
#[allow(dead_code)]
fn _suppress_unused() {
    let _: fn(u32, u32) -> Option<u32> = get_object_attr_u32;
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
        bootstrap_default_token(0, "so", "user", "native-sign-test").unwrap()
    }

    /// ML-DSA-65 round-trip: keygen → sign → verify(correct) → Ok(true).
    /// FIPS 204 §5 — ML-DSA-65 signature is 3309 bytes.
    #[test]
    fn ml_dsa_65_sign_then_verify_returns_valid() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) =
            generate_ml_dsa_keypair(session, CKP_ML_DSA_65, b"\x01\x02", "sig-key").unwrap();

        let message = b"the quick brown fox jumps over the lazy dog";
        let sig = sign(session, prv_h, CKM_ML_DSA, message).expect("sign must succeed");
        assert_eq!(sig.len(), 3309, "FIPS 204 §5 ML-DSA-65 signature = 3309 bytes");

        let valid = verify(session, pub_h, CKM_ML_DSA, message, &sig).expect("verify must succeed");
        assert!(valid, "freshly-signed message must verify");

        close_session(session).unwrap();
    }

    /// ML-DSA-87: signature = 4627 bytes (FIPS 204 §5).
    #[test]
    fn ml_dsa_87_sign_then_verify_returns_valid() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) =
            generate_ml_dsa_keypair(session, CKP_ML_DSA_87, b"\x03", "sig-87").unwrap();
        let sig = sign(session, prv_h, CKM_ML_DSA, b"hello").unwrap();
        assert_eq!(sig.len(), 4627);
        assert!(verify(session, pub_h, CKM_ML_DSA, b"hello", &sig).unwrap());
        close_session(session).unwrap();
    }

    /// Tampered signature → Ok(false), NOT Err. Matches KMIP
    /// `ValidityIndicator::Invalid` semantics.
    #[test]
    fn tampered_signature_returns_ok_false_not_err() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) =
            generate_ml_dsa_keypair(session, CKP_ML_DSA_65, b"\x01", "tamper").unwrap();
        let mut sig = sign(session, prv_h, CKM_ML_DSA, b"data").unwrap();
        // Flip a byte in the middle of the signature.
        let mid = sig.len() / 2;
        sig[mid] ^= 0xFF;
        let result = verify(session, pub_h, CKM_ML_DSA, b"data", &sig);
        assert_eq!(result, Ok(false), "tampered sig is Ok(false), not Err");
        close_session(session).unwrap();
    }

    /// Signing with the public-key handle (CKA_SIGN = false) →
    /// CKR_KEY_FUNCTION_NOT_PERMITTED.
    #[test]
    fn sign_with_public_key_handle_is_denied() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, _prv_h) =
            generate_ml_dsa_keypair(session, CKP_ML_DSA_65, b"\x01", "denied").unwrap();
        let result = sign(session, pub_h, CKM_ML_DSA, b"data");
        assert_eq!(result, Err(CKR_KEY_FUNCTION_NOT_PERMITTED));
        close_session(session).unwrap();
    }

    /// Verifying with the private-key handle (CKA_VERIFY = false) →
    /// CKR_KEY_FUNCTION_NOT_PERMITTED.
    #[test]
    fn verify_with_private_key_handle_is_denied() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (_pub_h, prv_h) =
            generate_ml_dsa_keypair(session, CKP_ML_DSA_65, b"\x01", "denied").unwrap();
        let result = verify(session, prv_h, CKM_ML_DSA, b"data", b"\x00" .repeat(3309).as_slice());
        assert_eq!(result, Err(CKR_KEY_FUNCTION_NOT_PERMITTED));
        close_session(session).unwrap();
    }

    /// Unknown mechanism → CKR_MECHANISM_INVALID.
    #[test]
    fn unknown_mechanism_returns_err() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (_pub_h, prv_h) =
            generate_ml_dsa_keypair(session, CKP_ML_DSA_65, b"\x01", "unknown-mech").unwrap();
        let result = sign(session, prv_h, 0xDEAD_BEEF, b"data");
        assert_eq!(result, Err(CKR_MECHANISM_INVALID));
        close_session(session).unwrap();
    }

    /// Sign with an ML-KEM key (CKA_SIGN=false) → denied. Cross-family
    /// check that the permission gate works.
    #[test]
    fn ml_kem_key_cannot_be_used_for_signing() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (_pub_h, prv_h) =
            generate_ml_kem_keypair(session, CKP_ML_KEM_768, b"\x01", "kem-not-sig").unwrap();
        let result = sign(session, prv_h, CKM_ML_DSA, b"data");
        assert_eq!(result, Err(CKR_KEY_FUNCTION_NOT_PERMITTED));
        close_session(session).unwrap();
    }

    /// Empty message — ML-DSA is well-defined for any message length
    /// per FIPS 204. Signature still 3309 bytes.
    #[test]
    fn ml_dsa_65_sign_empty_message() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, prv_h) =
            generate_ml_dsa_keypair(session, CKP_ML_DSA_65, b"\x01", "empty-msg").unwrap();
        let sig = sign(session, prv_h, CKM_ML_DSA, b"").unwrap();
        assert_eq!(sig.len(), 3309);
        assert!(verify(session, pub_h, CKM_ML_DSA, b"", &sig).unwrap());
        close_session(session).unwrap();
    }
}
