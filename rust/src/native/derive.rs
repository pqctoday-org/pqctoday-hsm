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
}
