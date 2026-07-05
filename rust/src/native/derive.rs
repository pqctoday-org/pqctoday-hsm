//! Key derivation — typed wrappers over the engine's `C_DeriveKey` mechanisms
//! (the `native::*` counterpart to the FFI derive path, per the module-level
//! typed-vs-FFI architectural relationship in [`super`]).
//!
//! These exist so the KMIP layer can compose a hybrid-KEM shared secret
//! entirely in-HSM without any crypto crate of its own: it calls
//! [`concatenate_keys`] (and, as the combiner set grows, the digest/HKDF
//! derive wrappers) against key *handles*, and only the final combined secret
//! is ever released. Private component keys never leave the engine.
//!
//! Every function here maps 1:1 to a standard PKCS#11 v3.2 derive mechanism,
//! so a combiner built from them is conformant by construction — PKCS#11 v3.2
//! has no dedicated hybrid-KEM mechanism (verified against the published
//! spec), only these composable building blocks.

use std::collections::HashMap;

use super::CkRv;
use crate::constants::*;
use crate::crypto::handlers::Attributes;
use crate::state::{
    allocate_handle_owned, compute_kcv, get_object_value, store_bool, store_ulong,
};

/// Register a freshly-derived generic-secret key `value` as a session object
/// and return its handle. Mirrors the FFI `C_DeriveKey` finalization
/// (`ffi.rs`): the derived key is extractable/non-sensitive (it IS the
/// caller's requested output — e.g. a KEM shared secret meant to be read),
/// not locally generated (`CKA_LOCAL = false`,
/// `CKA_KEY_GEN_MECHANISM = UNAVAILABLE`), and carries a KCV per PKCS#11 v3.2
/// §4.11.
fn register_derived_secret(session: u32, value: Vec<u8>) -> u32 {
    let mut attrs: Attributes = HashMap::new();
    let vlen = value.len() as u32;
    attrs.insert(CKA_VALUE, value);
    store_ulong(&mut attrs, CKA_CLASS, CKO_SECRET_KEY);
    store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_GENERIC_SECRET);
    store_ulong(&mut attrs, CKA_VALUE_LEN, vlen);
    store_bool(&mut attrs, CKA_EXTRACTABLE, true);
    store_bool(&mut attrs, CKA_SENSITIVE, false);
    store_bool(&mut attrs, CKA_TOKEN, false);
    store_bool(&mut attrs, CKA_PRIVATE, false);
    // PKCS#11 v3.2 §4.3 Table 13 — a DERIVED key is not locally generated.
    store_bool(&mut attrs, CKA_LOCAL, false);
    store_ulong(&mut attrs, CKA_KEY_GEN_MECHANISM, CKM_UNAVAILABLE_INFORMATION);
    // §4.9/§4.10 — derived-from-external-material ⇒ never ALWAYS_SENSITIVE /
    // NEVER_EXTRACTABLE.
    store_bool(&mut attrs, CKA_ALWAYS_SENSITIVE, false);
    store_bool(&mut attrs, CKA_NEVER_EXTRACTABLE, false);
    compute_kcv(&mut attrs);
    allocate_handle_owned(session, attrs)
}

/// `CKM_CONCATENATE_BASE_AND_KEY` (PKCS#11 v3.2 §6.43.3): derive a new
/// generic-secret key whose value is `base.CKA_VALUE ‖ second.CKA_VALUE`.
///
/// This is the universal step-1 building block for every hybrid-KEM combiner
/// (the classical ‖ PQC concatenation); a hash/KDF second step, when a
/// combiner needs one, chains another `native::` derive wrapper onto the
/// handle this returns. All in-HSM — the two component secrets are addressed
/// by handle and only the combined result is produced.
///
/// Returns `CKR_KEY_HANDLE_INVALID` if either handle has no readable value.
///
/// **Pre-condition**: `session` must be a valid R/W user session; both
/// handles must reference secret-key objects with a `CKA_VALUE`.
pub fn concatenate_keys(session: u32, base: u32, second: u32) -> Result<u32, CkRv> {
    let base_val = get_object_value(base).ok_or(CKR_KEY_HANDLE_INVALID)?;
    let second_val = get_object_value(second).ok_or(CKR_KEY_HANDLE_INVALID)?;
    let combined = [base_val.as_slice(), second_val.as_slice()].concat();
    Ok(register_derived_secret(session, combined))
}

/// `CKM_CONCATENATE_BASE_AND_DATA` (PKCS#11 v3.2 §6.43.4): derive a new
/// generic-secret key whose value is `base.CKA_VALUE ‖ data`.
///
/// The transcript-binding building block — appends non-key material
/// (ciphertext, public key, domain-separation label) onto a running secret
/// before a hash step, as constructions like X-Wing and Chempat require.
///
/// **Pre-condition**: `session` valid R/W; `base` a secret key with a value.
pub fn concatenate_data(session: u32, base: u32, data: &[u8]) -> Result<u32, CkRv> {
    let base_val = get_object_value(base).ok_or(CKR_KEY_HANDLE_INVALID)?;
    let combined = [base_val.as_slice(), data].concat();
    Ok(register_derived_secret(session, combined))
}

/// Digest key-derivation (PKCS#11 v3.2 §6.22 SHA-2 / §6.29 SHA-3): derive a
/// new generic-secret key whose value is `SHAx(base.CKA_VALUE)`, left-
/// truncated to `out_len` bytes when supplied (`None` keeps the full digest).
///
/// The hash-second-step for concat-then-hash combiners (SSH
/// `mlkem768x25519-sha256`: SHA-256 of `ss_mlkem ‖ ss_x25519`, verified from
/// the OpenSSH source; X-Wing: SHA3-256 of `ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ label`,
/// verified from draft-connolly-cfrg-xwing-kem). `mech` selects the digest;
/// any non-digest-derivation mechanism → `CKR_MECHANISM_INVALID`.
/// The base key's value is read in-HSM and never leaves.
///
/// **Pre-condition**: `session` valid R/W; `base` a secret key with a value.
pub fn digest_key_derivation(
    session: u32,
    base: u32,
    mech: u32,
    out_len: Option<usize>,
) -> Result<u32, CkRv> {
    let base_val = get_object_value(base).ok_or(CKR_KEY_HANDLE_INVALID)?;
    let mut digest = digest_of(mech, &base_val)?;
    if let Some(n) = out_len {
        if n > digest.len() {
            // Can't stretch a digest — §6.22: the requested key is longer than
            // the hash provides.
            return Err(CKR_KEY_SIZE_RANGE);
        }
        digest.truncate(n); // §6.22 — leftmost bytes.
    }
    Ok(register_derived_secret(session, digest))
}

/// Pure digest-key-derivation transform: `SHAx(data)` per `mech` (one of the
/// `CKM_SHA*_KEY_DERIVATION` codepoints). Shared by [`digest_key_derivation`]
/// (native) and the `C_DeriveKey` FFI arm so the mechanism→hasher mapping
/// exists once. `CKR_MECHANISM_INVALID` for any non-digest-derivation mech.
pub(crate) fn digest_of(mech: u32, data: &[u8]) -> Result<Vec<u8>, CkRv> {
    use sha2::Digest as _;
    Ok(match mech {
        CKM_SHA256_KEY_DERIVATION => sha2::Sha256::digest(data).to_vec(),
        CKM_SHA384_KEY_DERIVATION => sha2::Sha384::digest(data).to_vec(),
        CKM_SHA512_KEY_DERIVATION => sha2::Sha512::digest(data).to_vec(),
        CKM_SHA3_256_KEY_DERIVATION => sha3::Sha3_256::digest(data).to_vec(),
        CKM_SHA3_384_KEY_DERIVATION => sha3::Sha3_384::digest(data).to_vec(),
        CKM_SHA3_512_KEY_DERIVATION => sha3::Sha3_512::digest(data).to_vec(),
        _ => return Err(CKR_MECHANISM_INVALID),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::test_lock;

    fn fresh_session() -> u32 {
        let _ = crate::native::session::finalize();
        crate::native::session::init().expect("engine init");
        crate::native::session::bootstrap_default_token(0, "so", "user", "concat-test")
            .expect("bootstrap session")
    }

    /// Register a generic-secret object with a known value, return its handle.
    fn secret_with_value(session: u32, value: &[u8]) -> u32 {
        let mut attrs: Attributes = HashMap::new();
        attrs.insert(CKA_VALUE, value.to_vec());
        store_ulong(&mut attrs, CKA_CLASS, CKO_SECRET_KEY);
        store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_GENERIC_SECRET);
        store_ulong(&mut attrs, CKA_VALUE_LEN, value.len() as u32);
        store_bool(&mut attrs, CKA_EXTRACTABLE, true);
        allocate_handle_owned(session, attrs)
    }

    #[test]
    fn concatenate_appends_second_after_base() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        // Spec §6.43.3 worked example: base 0x01234567, other 0x89ABCDEF →
        // 0x0123456789ABCDEF.
        let base = secret_with_value(session, &[0x01, 0x23, 0x45, 0x67]);
        let second = secret_with_value(session, &[0x89, 0xAB, 0xCD, 0xEF]);
        let out = concatenate_keys(session, base, second).unwrap();
        assert_eq!(
            get_object_value(out).unwrap(),
            vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]
        );
    }

    #[test]
    fn concatenate_length_is_sum_and_order_matters() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        // X25519MLKEM768 shape: ML-KEM ss (32) ‖ X25519 ss (32) = 64 bytes.
        let mlkem = secret_with_value(session, &[0xAA; 32]);
        let x25519 = secret_with_value(session, &[0xBB; 32]);
        let out = concatenate_keys(session, mlkem, x25519).unwrap();
        let v = get_object_value(out).unwrap();
        assert_eq!(v.len(), 64, "sum of the two component lengths");
        assert_eq!(&v[..32], &[0xAA; 32], "base (ML-KEM) first");
        assert_eq!(&v[32..], &[0xBB; 32], "second (X25519) last");
        // Reversed order gives a different secret — the per-variant ordering
        // is load-bearing (X25519MLKEM768 vs SecP256r1MLKEM768).
        let out_rev = concatenate_keys(session, x25519, mlkem).unwrap();
        assert_ne!(get_object_value(out_rev).unwrap(), v);
    }

    #[test]
    fn concatenate_missing_value_is_handle_invalid() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let base = secret_with_value(session, &[0x01, 0x02]);
        assert_eq!(
            concatenate_keys(session, base, 0xDEAD_BEEF),
            Err(CKR_KEY_HANDLE_INVALID)
        );
    }

    #[test]
    fn concatenate_data_appends_raw_bytes() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        // Spec §6.43.4 worked example: base 0x01234567, data 0x89ABCDEF.
        let base = secret_with_value(session, &[0x01, 0x23, 0x45, 0x67]);
        let out = concatenate_data(session, base, &[0x89, 0xAB, 0xCD, 0xEF]).unwrap();
        assert_eq!(
            get_object_value(out).unwrap(),
            vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]
        );
    }

    #[test]
    fn digest_key_derivation_matches_known_sha256() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        // Canonical KAT: SHA-256("abc") =
        // ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad.
        let base = secret_with_value(session, b"abc");
        let out = digest_key_derivation(session, base, CKM_SHA256_KEY_DERIVATION, None).unwrap();
        let expect: Vec<u8> = (0..32)
            .map(|i| {
                u8::from_str_radix(
                    &"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                        [i * 2..i * 2 + 2],
                    16,
                )
                .unwrap()
            })
            .collect();
        assert_eq!(get_object_value(out).unwrap(), expect);
    }

    #[test]
    fn digest_key_derivation_truncates_to_requested_length() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        // SHA-512 of "abc" truncated to 32 bytes = leftmost 32 of the 64-byte
        // digest (used e.g. to fit a 256-bit AES key out of a hash step).
        let base = secret_with_value(session, b"abc");
        let full =
            digest_key_derivation(session, base, CKM_SHA512_KEY_DERIVATION, None).unwrap();
        let full_v = get_object_value(full).unwrap();
        assert_eq!(full_v.len(), 64);
        let base2 = secret_with_value(session, b"abc");
        let trunc =
            digest_key_derivation(session, base2, CKM_SHA512_KEY_DERIVATION, Some(32)).unwrap();
        assert_eq!(get_object_value(trunc).unwrap(), full_v[..32].to_vec());
    }

    #[test]
    fn digest_key_derivation_rejects_overlong_request_and_bad_mech() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let base = secret_with_value(session, b"abc");
        // Can't stretch a 32-byte SHA-256 to 40 bytes.
        assert_eq!(
            digest_key_derivation(session, base, CKM_SHA256_KEY_DERIVATION, Some(40)),
            Err(CKR_KEY_SIZE_RANGE)
        );
        let base2 = secret_with_value(session, b"abc");
        assert_eq!(
            digest_key_derivation(session, base2, CKM_CONCATENATE_BASE_AND_KEY, None),
            Err(CKR_MECHANISM_INVALID)
        );
    }
}
