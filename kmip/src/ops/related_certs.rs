//! RFC 9763 Related Certificates — validate a certificate's
//! `RelatedCertificate` extension (OID `1.3.6.1.5.5.7.1.36`): a SHA-256
//! binding hash over another certificate's full DER, proving intent to
//! relate the two (e.g. a PQC migration companion to a classical cert).
//!
//! ## Scope: validation only (WP-C10)
//!
//! RFC 9763 defines no KMIP issuance concept either — `certBuilder.ts`'s
//! own `buildRelatedCertPair` is a DEMO convenience (a 2-pass/3-pass
//! hash-chaining dance to produce a bidirectional pair), not something
//! a `CreateKeyPair`/`Certify` request shape maps onto. No
//! `CreateKeyPair`/`Certify` counterpart here, matching
//! `catalyst.rs`'s WP-C9 scope.
//!
//! ## Reference: `certBuilder.ts::buildRelatedCertPair`
//!
//! The extension value is `SEQUENCE { AlgorithmIdentifier hashAlgorithm,
//! OCTET STRING hashValue }` (`buildRelatedExt`'s own construction), and
//! the hash is computed over the referenced certificate's FULL signed
//! DER (`crypto.subtle.digest('SHA-256', certA_draft.buffer)`) — NOT
//! just its TBS. This implementation supports SHA-256 only (the only
//! algorithm the reference ever produces), degrading honestly
//! (`OperationNotSupported`) for any other `hashAlgorithm` OID rather
//! than guessing at one.
//!
//! ## Companion identification — a real structural question, not guessed
//!
//! RFC 9763's extension carries ONLY a hash, no explicit pointer to
//! which supplied certificate it names. This resolves it structurally:
//! search every OTHER certificate in the same `validate_chain` request
//! for one whose digest matches the claim.
//! - A match → the binding is confirmed (`Bound`).
//! - No match, and nothing else was even supplied to check against →
//!   `Unknown` (nothing to check — same "can't complete the chain"
//!   degrade `validate_chain` already uses when an issuer isn't in the
//!   supplied set).
//! - No match, but OTHER certificates WERE supplied → `Invalid` (an
//!   explicit hash claim that doesn't correspond to anything actually
//!   present is a real, checkable failure, not an absence of data).
//!
//! ## Scope discipline (invariant 0a — no crypto in kmip, only encoding)
//!
//! The one hash this module needs goes through
//! `softhsmrustv3::native::digest` — the same engine primitive
//! `composite_sig.rs::build_message_representative` uses for its
//! `PH(TBS)` step — never a local `sha2` call.

use der::asn1::OctetString;
use der::{Decode, Sequence};
use spki::AlgorithmIdentifierOwned;

use crate::error::{KmipError, Result, ResultReason};

use super::deps::Deps;

/// RelatedCertificate — RFC 9763, id-pe 36.
pub const RELATED_CERT_OID: &str = "1.3.6.1.5.5.7.1.36";
const SHA256_OID: &str = "2.16.840.1.101.3.4.2.1";

/// `RelatedCertificate ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashValue OCTET STRING }`
/// (RFC 9763 §3, matching `buildRelatedExt`'s `SEQUENCE { AlgorithmIdentifier, OCTET STRING(hash) }`).
#[derive(Sequence)]
struct RelatedCertificateValue {
    hash_algorithm: AlgorithmIdentifierOwned,
    hash_value: OctetString,
}

/// Outcome of checking one certificate's `RelatedCertificate` claim
/// against the rest of the supplied set.
#[derive(Debug, PartialEq, Eq)]
pub enum RelatedCertVerdict {
    /// A supplied certificate's digest matches the claimed hash.
    Bound,
    /// The claimed hash matches nothing in the supplied set, and
    /// nothing else was even supplied to check it against.
    Unknown,
    /// The claimed hash matches nothing in the supplied set, but other
    /// certificates WERE supplied — an unconfirmed/broken binding.
    Invalid,
}

/// Decode a `RelatedCertificate` extension's raw `extnValue` content
/// (already unwrapped from its outer OCTET STRING by the caller's X.509
/// extension parser) into `(hashAlgorithm OID, claimed hash bytes)`.
pub fn extract_related_cert_claim(ext_value: &[u8]) -> Result<(String, Vec<u8>)> {
    let parsed = RelatedCertificateValue::from_der(ext_value).map_err(|e| {
        KmipError::failed(ResultReason::InvalidField, format!("RelatedCertificate (ext 1.3.6.1.5.5.7.1.36): {e}"))
    })?;
    Ok((parsed.hash_algorithm.oid.to_string(), parsed.hash_value.as_bytes().to_vec()))
}

/// Check a claimed `(hashAlgorithm OID, hash)` against every OTHER
/// certificate's real digest among `all_der`, computed via
/// `native::digest` — see module doc for the 3-way verdict rationale.
/// `self_index` is skipped (a certificate never counts as its own
/// companion).
pub fn resolve_related_cert(
    deps: &Deps,
    hash_algorithm_oid: &str,
    claimed_hash: &[u8],
    all_der: &[Vec<u8>],
    self_index: usize,
) -> Result<RelatedCertVerdict> {
    if hash_algorithm_oid != SHA256_OID {
        return Err(KmipError::failed(
            ResultReason::OperationNotSupported,
            format!(
                "RelatedCertificate: unsupported hashAlgorithm {hash_algorithm_oid} \
                 (only SHA-256 is verified against the reference implementation)"
            ),
        ));
    }
    let _session = deps.engine_session.ok_or_else(|| {
        KmipError::failed(ResultReason::CryptographicFailure, "RelatedCertificate: no engine session to compute digests")
    })?;

    let mut saw_other = false;
    for (i, candidate) in all_der.iter().enumerate() {
        if i == self_index {
            continue;
        }
        saw_other = true;
        let digest = softhsmrustv3::native::digest(softhsmrustv3::constants::CKM_SHA256, candidate)
            .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "RelatedCertificate:digest"))?;
        if digest == claimed_hash {
            return Ok(RelatedCertVerdict::Bound);
        }
    }
    Ok(if saw_other { RelatedCertVerdict::Invalid } else { RelatedCertVerdict::Unknown })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn deps_with_session() -> (Deps, std::sync::MutexGuard<'static, ()>) {
        use softhsmrustv3::native::session::{bootstrap_default_token, finalize, init};
        let guard = super::super::helpers::engine_lock();
        let _ = finalize();
        init().expect("engine init");
        let session = bootstrap_default_token(0, "so", "user", "related-certs-test").expect("bootstrap session");
        use crate::auditlog::RingSink;
        use crate::store::MemoryStore;
        let sink: std::sync::Arc<dyn crate::auditlog::AuditSink> = std::sync::Arc::new(RingSink::new(64));
        let deps = Deps::new(
            crate::policy::Engine::permissive(),
            std::sync::Arc::new(MemoryStore::new()),
            sink,
            super::super::deps::DepsConfig::default(),
        )
        .with_engine_session(session);
        (deps, guard)
    }

    /// `pub(crate)` — reused directly by `validate.rs`'s own test for
    /// the `validate_chain` 3-way-verdict wiring, same cross-file
    /// test-fixture-reuse precedent as `catalyst::tests::
    /// build_catalyst_tbs_and_sign`.
    pub(crate) fn build_related_ext_der(hash: &[u8]) -> Vec<u8> {
        use der::Encode;
        let value = RelatedCertificateValue {
            hash_algorithm: AlgorithmIdentifierOwned {
                oid: der::oid::ObjectIdentifier::new(SHA256_OID).unwrap(),
                parameters: None,
            },
            hash_value: OctetString::new(hash.to_vec()).unwrap(),
        };
        value.to_der().unwrap()
    }

    #[test]
    fn round_trips_hash_algorithm_and_claimed_hash() {
        let hash = vec![0xabu8; 32];
        let ext_der = build_related_ext_der(&hash);
        let (oid, claimed) = extract_related_cert_claim(&ext_der).unwrap();
        assert_eq!(oid, SHA256_OID);
        assert_eq!(claimed, hash);
    }

    #[test]
    fn malformed_extension_is_a_structural_error() {
        let err = extract_related_cert_claim(&[0xde, 0xad, 0xbe, 0xef]).unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::InvalidField);
    }

    #[test]
    fn matching_companion_in_the_supplied_set_is_bound() {
        let (deps, _g) = deps_with_session();
        let companion = b"a certificate's full signed DER, whatever it is".to_vec();
        let real_hash = softhsmrustv3::native::digest(softhsmrustv3::constants::CKM_SHA256, &companion).unwrap();

        let all = vec![b"self placeholder DER".to_vec(), companion];
        let verdict = resolve_related_cert(&deps, SHA256_OID, &real_hash, &all, 0).unwrap();
        assert_eq!(verdict, RelatedCertVerdict::Bound);
    }

    #[test]
    fn no_other_certs_supplied_is_unknown_not_invalid() {
        let (deps, _g) = deps_with_session();
        let claimed = vec![0x11u8; 32];
        let all = vec![b"self placeholder DER".to_vec()];
        let verdict = resolve_related_cert(&deps, SHA256_OID, &claimed, &all, 0).unwrap();
        assert_eq!(verdict, RelatedCertVerdict::Unknown);
    }

    #[test]
    fn other_certs_supplied_but_none_match_is_invalid() {
        let (deps, _g) = deps_with_session();
        let claimed = vec![0x11u8; 32]; // matches nothing real
        let all = vec![b"self placeholder DER".to_vec(), b"an unrelated companion DER".to_vec()];
        let verdict = resolve_related_cert(&deps, SHA256_OID, &claimed, &all, 0).unwrap();
        assert_eq!(verdict, RelatedCertVerdict::Invalid);
    }

    #[test]
    fn unsupported_hash_algorithm_is_honest_not_guessed() {
        let (deps, _g) = deps_with_session();
        let err = resolve_related_cert(&deps, "2.16.840.1.101.3.4.2.3" /* SHA-512 */, &[0u8; 64], &[vec![], vec![]], 0)
            .unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::OperationNotSupported);
    }
}
