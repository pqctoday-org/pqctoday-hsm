//! LAMPS composite-KEM support (draft-ietf-lamps-pq-composite-kem-17) —
//! wraps an EXISTING hybrid-KEM public key's raw wire share into a
//! proper X.509 SubjectPublicKeyInfo DER for `Certify`.
//!
//! ## Scope discipline (invariant 0a — no crypto in kmip, only encoding)
//!
//! Pure byte assembly: one `AlgorithmIdentifier`/`BIT STRING` wrap
//! around bytes the engine already produced. No signing, no
//! verification, no key generation happens here — `certify.rs`'s
//! existing signing path (composite or single-algorithm, whichever the
//! designated CA uses) is unchanged by this module.
//!
//! ## Design: reuse, not duplicate (per the locked clarifying-question
//! decision — "Reuse existing hybrid keys... no new key type")
//!
//! A composite-KEM certificate's subject public key is *exactly* a
//! hybrid-KEM key's existing wire share (`hybrid_kem.rs` /
//! `softhsmrustv3::native::hybrid::keygen`'s `.public`,
//! `mlkemPK || tradPK` per draft-17 §4.1) — the K6 `CreateKeyPair`
//! hybrid-KEM path (`create_key_pair.rs`) and `Encapsulate`/
//! `Decapsulate` (`ops/encapsulate.rs`/`ops/decapsulate.rs`) already
//! read/write that exact byte layout as the PublicKey object's
//! `key_material`. This module does NOT change that storage format —
//! it only wraps those same bytes in a composite-KEM SPKI at
//! `Certify`-read-time, the one place the bytes need to look like a
//! standard X.509 `SubjectPublicKeyInfo` instead of a raw wire share.
//!
//! ## Reference material — and an honest scope boundary found there
//!
//! OIDs and byte order ported from the hub's `certBuilder.ts` /
//! `HybridCryptoService.ts::generateCompositeKEMCert` (draft-17 §6):
//! only `id-MLKEM768-X25519-SHA3-256` (`1.3.6.1.5.5.7.6.58`) is
//! actually wired there — `HybridCryptoService.ts` rejects the P-256
//! classical variant at runtime with "reserved in LAMPS draft... but
//! not wired in this workshop", and `SecP384r1MlKem1024` has no
//! composite-KEM OID anywhere in that reference at all. Per the
//! standing "do not guess or hallucinate" instruction, this module
//! mirrors that boundary exactly rather than inventing an unverified
//! OID/byte-order for the other two hybrid variants — `composite_kem_oid`
//! returns `None` for them, and callers degrade honestly (KMIP
//! `OperationNotSupported`), not silently.

use der::asn1::BitString;
use der::Encode;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use std::str::FromStr;

use crate::error::{KmipError, Result, ResultReason};
use crate::hybrid_kem::Hybrid;

/// id-MLKEM768-X25519-SHA3-256 — draft-ietf-lamps-pq-composite-kem-17
/// §6, matches `certBuilder.ts::COMPOSITE_KEM_MLKEM768_X25519_OID_STR`
/// (there verified "against the IANA PKIX arc as of 2026-07-03").
pub const MLKEM768_X25519_OID: &str = "1.3.6.1.5.5.7.6.58";

/// The composite-KEM OID for a hybrid variant, or `None` if draft-17
/// support for it isn't verified anywhere in the reference material
/// (see module doc). `SecP256r1MlKem768`'s OID
/// (`1.3.6.1.5.5.7.6.59`, id-MLKEM768-ECDH-P256-SHA3-256) is a real
/// draft-17 codepoint but deliberately excluded here — no wired
/// byte-order reference exists to cross-check against.
pub const fn composite_kem_oid(hybrid: Hybrid) -> Option<&'static str> {
    match hybrid {
        Hybrid::X25519MlKem768 => Some(MLKEM768_X25519_OID),
        Hybrid::SecP256r1MlKem768 | Hybrid::SecP384r1MlKem1024 => None,
    }
}

/// Wrap a hybrid-KEM public key's raw wire share (as already stored on
/// a hybrid `PublicKey` `ObjectRecord`'s `key_material` — unchanged
/// format, see module doc) into a composite-KEM `SubjectPublicKeyInfo`
/// DER. `Err(OperationNotSupported)` for a hybrid variant with no
/// verified composite-KEM OID (see [`composite_kem_oid`]).
pub fn wrap_composite_kem_spki(hybrid: Hybrid, wire_share: &[u8]) -> Result<Vec<u8>> {
    let oid_str = composite_kem_oid(hybrid).ok_or_else(|| {
        KmipError::failed(
            ResultReason::OperationNotSupported,
            format!(
                "{hybrid:?}: composite-KEM certification has no verified draft-17 OID/byte-order \
                 reference (only X25519MlKem768 does — see composite_kem.rs module doc)"
            ),
        )
    })?;
    let oid = der::oid::ObjectIdentifier::from_str(oid_str).expect("static OID");
    let spki = SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned { oid, parameters: None },
        subject_public_key: BitString::from_bytes(wire_share).map_err(|e| {
            KmipError::failed(ResultReason::CryptographicFailure, format!("composite-KEM SPKI: {e}"))
        })?,
    };
    spki.to_der()
        .map_err(|e| KmipError::failed(ResultReason::CryptographicFailure, format!("composite-KEM SPKI DER: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_mlkem768_resolves_the_draft17_oid() {
        assert_eq!(composite_kem_oid(Hybrid::X25519MlKem768), Some(MLKEM768_X25519_OID));
    }

    #[test]
    fn secp256r1_and_secp384r1_are_honestly_unsupported_not_guessed() {
        assert_eq!(composite_kem_oid(Hybrid::SecP256r1MlKem768), None);
        assert_eq!(composite_kem_oid(Hybrid::SecP384r1MlKem1024), None);
    }

    #[test]
    fn wrap_produces_the_exact_draft17_layout() {
        // mlkem768PublicKey(1184) || x25519PublicKey(32) = 1216 B, per
        // certBuilder.ts's own worked comment.
        let wire_share = vec![0xabu8; 1184 + 32];
        let der = wrap_composite_kem_spki(Hybrid::X25519MlKem768, &wire_share).unwrap();

        use der::Decode;
        let parsed = SubjectPublicKeyInfoOwned::from_der(&der).unwrap();
        assert_eq!(parsed.algorithm.oid.to_string(), MLKEM768_X25519_OID);
        assert_eq!(parsed.subject_public_key.raw_bytes(), wire_share.as_slice());
    }

    #[test]
    fn wrap_rejects_unsupported_hybrid_honestly() {
        let err = wrap_composite_kem_spki(Hybrid::SecP256r1MlKem768, &[0u8; 10]).unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::OperationNotSupported);
    }
}
