//! G12 — Split Key secret sharing (`CKM_PQCTODAY_SPLIT_KEY`), typed
//! handle-based API.
//!
//! **Security model**: exactly like every other `native::*` operation
//! (`sign`, `hbs`, ...), the caller (the KMIP server) never sees a raw
//! secret byte. [`split`] takes a *handle* to an already-registered
//! engine secret, reads its `CKA_VALUE` internally, and returns
//! handles to N newly-registered share objects. [`join`] takes handles
//! to share objects, reads their `CKA_VALUE` internally, and returns a
//! handle to one newly-registered reconstructed object. The actual
//! finite-field / prime-field arithmetic lives in
//! [`crate::crypto::split_key`] (pure functions, unit-tested in
//! isolation there); this module is purely the handle/object-store
//! plumbing around it.

use std::collections::HashMap;

use super::CkRv;
use crate::constants::{CKR_ARGUMENTS_BAD, CKR_DATA_LEN_RANGE, CKR_FUNCTION_FAILED};
use crate::crypto::split_key::{self, Gf256Polynomial, SplitKeyError, SplitKeyMethod};
use crate::native::keygen::{alloc_in_session_slot, build_generic_secret_attrs, insert_id_and_label};
use crate::state::get_object_value;

fn map_err(e: SplitKeyError) -> CkRv {
    match e {
        SplitKeyError::SecretTooLargeForPrimeField => CKR_DATA_LEN_RANGE,
        SplitKeyError::InvalidThreshold
        | SplitKeyError::XorPartsMustEqualThreshold
        | SplitKeyError::InsufficientShares
        | SplitKeyError::DuplicateShareIndex
        | SplitKeyError::TooManyParts
        | SplitKeyError::MalformedShare => CKR_ARGUMENTS_BAD,
    }
}

/// Split the secret held at `secret_handle` into `parts` shares (§11.54
/// `method`, optionally parameterized by `polynomial` for the two
/// GF(2^8)-based methods). Returns `(key_part_identifier, handle)`
/// pairs — the KMIP layer needs `key_part_identifier` (the share's
/// §4.30 index / finite-field x-coordinate) to persist on each new
/// object's KMIP attributes; it is NOT recoverable from the handle
/// alone. Each returned handle is a real engine object (a `Generic
/// Secret` key holding that share's raw bytes as `CKA_VALUE`) — same
/// sensitivity defaults as any other `native::register_generic_secret_bytes`
/// import.
#[allow(clippy::too_many_arguments)]
pub fn split(
    session: u32,
    secret_handle: u32,
    parts: u32,
    threshold: u32,
    method: SplitKeyMethod,
    polynomial: Option<Gf256Polynomial>,
    cka_id_prefix: &[u8],
    label: &str,
) -> Result<Vec<(u32, u32)>, CkRv> {
    let secret = get_object_value(secret_handle).ok_or(CKR_ARGUMENTS_BAD)?;

    let register_share = |index: u32, bytes: Vec<u8>| -> u32 {
        // Distinguish each share's CKA_ID from the others and from the
        // original secret's — appends the share index to the caller's prefix.
        let mut cka_id = cka_id_prefix.to_vec();
        cka_id.extend_from_slice(&index.to_be_bytes());
        let mut attrs = build_generic_secret_attrs(bytes.clone(), bytes.len() as u32, &cka_id, label);
        insert_id_and_label(&mut attrs, &cka_id, label);
        alloc_in_session_slot(session, attrs)
    };

    match method {
        SplitKeyMethod::Xor => {
            if parts != threshold {
                return Err(map_err(SplitKeyError::XorPartsMustEqualThreshold));
            }
            let shares = split_key::split_xor(&secret, parts);
            Ok(shares
                .into_iter()
                .enumerate()
                .map(|(i, bytes)| ((i + 1) as u32, register_share((i + 1) as u32, bytes)))
                .collect())
        }
        SplitKeyMethod::PolynomialPrimeField => {
            let shares =
                split_key::split_prime_field(&secret, parts, threshold).map_err(map_err)?;
            Ok(shares
                .into_iter()
                .map(|(idx, bytes)| (idx, register_share(idx, bytes)))
                .collect())
        }
        SplitKeyMethod::PolynomialGf256 => {
            let poly = polynomial.ok_or(CKR_ARGUMENTS_BAD)?;
            let shares =
                split_key::split_gf256(&secret, parts, threshold, poly).map_err(map_err)?;
            Ok(shares
                .into_iter()
                .map(|(idx, bytes)| (idx as u32, register_share(idx as u32, bytes)))
                .collect())
        }
        SplitKeyMethod::PolynomialGf65536 => {
            let poly = polynomial.ok_or(CKR_ARGUMENTS_BAD)?;
            let shares =
                split_key::split_gf65536(&secret, parts, threshold, poly).map_err(map_err)?;
            Ok(shares
                .into_iter()
                .map(|(idx, bytes)| (idx as u32, register_share(idx as u32, bytes)))
                .collect())
        }
    }
}

/// Reconstruct a secret from `shares` (`(key_part_identifier, handle)`
/// pairs — the KMIP layer supplies both, read back from the persisted
/// share objects' KMIP attributes; the engine does not track split-key
/// metadata on the share objects themselves, only their raw bytes).
/// `expected_len` is the original secret's byte length (needed to
/// de-pad the GF(2^16)/Prime-Field reconstructions). Returns a handle
/// to one newly-registered engine object holding the reconstructed
/// bytes.
#[allow(clippy::too_many_arguments)]
pub fn join(
    session: u32,
    shares: &[(u32, u32)],
    threshold: u32,
    method: SplitKeyMethod,
    polynomial: Option<Gf256Polynomial>,
    expected_len: usize,
    cka_id: &[u8],
    label: &str,
) -> Result<u32, CkRv> {
    let mut bytes_by_index: HashMap<u32, Vec<u8>> = HashMap::new();
    for &(idx, handle) in shares {
        let bytes = get_object_value(handle).ok_or(CKR_ARGUMENTS_BAD)?;
        bytes_by_index.insert(idx, bytes);
    }

    let joined = match method {
        SplitKeyMethod::Xor => {
            let ordered: Vec<Vec<u8>> = bytes_by_index.into_values().collect();
            split_key::join_xor(&ordered)
        }
        SplitKeyMethod::PolynomialPrimeField => {
            let pts: Vec<(u32, Vec<u8>)> = bytes_by_index.into_iter().collect();
            split_key::join_prime_field(&pts, threshold, expected_len).map_err(map_err)?
        }
        SplitKeyMethod::PolynomialGf256 => {
            let poly = polynomial.ok_or(CKR_ARGUMENTS_BAD)?;
            let pts: Vec<(u8, Vec<u8>)> = bytes_by_index
                .into_iter()
                .map(|(idx, b)| (idx as u8, b))
                .collect();
            split_key::join_gf256(&pts, threshold, poly).map_err(map_err)?
        }
        SplitKeyMethod::PolynomialGf65536 => {
            let poly = polynomial.ok_or(CKR_ARGUMENTS_BAD)?;
            let pts: Vec<(u16, Vec<u8>)> = bytes_by_index
                .into_iter()
                .map(|(idx, b)| (idx as u16, b))
                .collect();
            split_key::join_gf65536(&pts, threshold, expected_len, poly).map_err(map_err)?
        }
    };

    if joined.is_empty() && expected_len > 0 {
        return Err(CKR_FUNCTION_FAILED);
    }
    let mut attrs = build_generic_secret_attrs(joined.clone(), joined.len() as u32, cka_id, label);
    insert_id_and_label(&mut attrs, cka_id, label);
    Ok(alloc_in_session_slot(session, attrs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::keygen::register_generic_secret_bytes;
    use crate::native::session::{bootstrap_default_token, close_session, finalize, init};
    use crate::native::test_lock;
    use crate::state::get_object_value as read_value;

    fn fresh_session() -> u32 {
        let _ = finalize();
        init().unwrap();
        bootstrap_default_token(0, "so", "user", "split-key-test").unwrap()
    }

    #[test]
    fn xor_split_then_join_via_handles_reconstructs() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let secret = b"a 32-byte secret key material!!";
        let secret_h = register_generic_secret_bytes(session, secret, b"\x01", "orig").unwrap();

        let shares = split(session, secret_h, 4, 4, SplitKeyMethod::Xor, None, b"\x02", "share").unwrap();
        assert_eq!(shares.len(), 4);

        let joined_h = join(
            session, &shares, 4, SplitKeyMethod::Xor, None, secret.len(), b"\x03", "joined",
        )
        .unwrap();
        assert_eq!(read_value(joined_h).unwrap(), secret);
        close_session(session).unwrap();
    }

    #[test]
    fn gf256_split_then_join_via_handles_with_threshold_subset() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let secret = b"AES-256 key material, 32 bytes!";
        let secret_h = register_generic_secret_bytes(session, secret, b"\x01", "orig").unwrap();

        let shares = split(
            session, secret_h, 5, 3, SplitKeyMethod::PolynomialGf256,
            Some(Gf256Polynomial::Polynomial283), b"\x02", "share",
        )
        .unwrap();
        assert_eq!(shares.len(), 5);

        // Join with only 3 of the 5 shares.
        let subset = &shares[1..4];
        let joined_h = join(
            session, subset, 3, SplitKeyMethod::PolynomialGf256,
            Some(Gf256Polynomial::Polynomial283), secret.len(), b"\x03", "joined",
        )
        .unwrap();
        assert_eq!(read_value(joined_h).unwrap(), secret);
        close_session(session).unwrap();
    }

    #[test]
    fn gf65536_split_then_join_via_handles_reconstructs() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let secret = b"a 16-byte-secret";
        let secret_h = register_generic_secret_bytes(session, secret, b"\x01", "orig").unwrap();

        let shares = split(
            session, secret_h, 5, 3, SplitKeyMethod::PolynomialGf65536,
            Some(Gf256Polynomial::Polynomial285), b"\x02", "share",
        )
        .unwrap();
        let joined_h = join(
            session, &shares[..3], 3, SplitKeyMethod::PolynomialGf65536,
            Some(Gf256Polynomial::Polynomial285), secret.len(), b"\x03", "joined",
        )
        .unwrap();
        assert_eq!(read_value(joined_h).unwrap(), secret);
        close_session(session).unwrap();
    }

    #[test]
    fn prime_field_split_then_join_via_handles_reconstructs() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let secret = b"a 32-byte AES-256 secret key!!!";
        let secret_h = register_generic_secret_bytes(session, secret, b"\x01", "orig").unwrap();

        let shares = split(
            session, secret_h, 5, 3, SplitKeyMethod::PolynomialPrimeField, None, b"\x02", "share",
        )
        .unwrap();
        let joined_h = join(
            session, &shares[..3], 3, SplitKeyMethod::PolynomialPrimeField, None, secret.len(),
            b"\x03", "joined",
        )
        .unwrap();
        assert_eq!(read_value(joined_h).unwrap(), secret);
        close_session(session).unwrap();
    }

    #[test]
    fn join_with_fewer_than_threshold_handles_fails() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let secret = b"secret16bytes!!!";
        let secret_h = register_generic_secret_bytes(session, secret, b"\x01", "orig").unwrap();
        let shares = split(
            session, secret_h, 5, 4, SplitKeyMethod::PolynomialGf256,
            Some(Gf256Polynomial::Polynomial283), b"\x02", "share",
        )
        .unwrap();
        let err = join(
            session, &shares[..2], 4, SplitKeyMethod::PolynomialGf256,
            Some(Gf256Polynomial::Polynomial283), secret.len(), b"\x03", "joined",
        )
        .unwrap_err();
        assert_eq!(err, CKR_ARGUMENTS_BAD);
        close_session(session).unwrap();
    }

    #[test]
    fn xor_split_rejects_parts_not_equal_threshold() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let secret = b"secret16bytes!!!";
        let secret_h = register_generic_secret_bytes(session, secret, b"\x01", "orig").unwrap();
        let err = split(session, secret_h, 5, 3, SplitKeyMethod::Xor, None, b"\x02", "share")
            .unwrap_err();
        assert_eq!(err, CKR_ARGUMENTS_BAD);
        close_session(session).unwrap();
    }
}
