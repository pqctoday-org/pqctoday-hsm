//! Self-signed X.509 certificate construction for a signature-capable
//! keypair already generated on the token (see [`crate::verbs::generate_key_pair`])
//! — issuer == subject, `TBSCertificate` signed by the SAME keypair's own
//! private key via [`crate::verbs::sign`] (never raw key material — the
//! same session+handle path every other verb in this crate uses).
//! Exposed as the 8th verb, [`crate::verbs::get_self_signed_certificate`].
//!
//! Real, live-discovered need (not planned from the start): the gRPC/REST
//! surface had no verb anywhere that returned a public key's bytes at
//! all — `GenerateKeyPairResponse` carries only two `uint32` handles.
//! Without this, a caller could generate a remote keypair and sign/verify/
//! encapsulate/decapsulate with it, but never hand its public key to
//! anything outside this same session (e.g. into a Java `KeyStore`/PKIX
//! validation flow, or to an external peer).
//!
//! ## Why this crate builds its own X.509 logic
//!
//! `pqctoday-kmip`'s own `ops/certify.rs` (`bootstrap_ca_certificate`/
//! `issue_certificate`) is the closest working precedent in this repo for
//! "build + sign a `TBSCertificate` against a token-resident key" — read
//! in full before writing this file, not reimplemented from a guess.
//! Reimplemented here rather than taken as a dependency for two real
//! reasons: (1) that crate's cert-building is tightly coupled to its own
//! `Deps`/`ObjectRecord`/store abstractions, not raw session+handle args;
//! (2) it does **not** support Ed25519 as a certificate-signing algorithm
//! — `signature_alg_and_mech` explicitly rejects it
//! (`"algorithm Ed25519 cannot be used as a Certify CA key"`) — but this
//! crate's own signature-capable algorithm set is exactly Ed25519 +
//! ML-DSA-44/65/87 (`Algorithm::is_signature()`), so Ed25519 support is
//! required, not optional. Ed25519's own X.509 `AlgorithmIdentifier`
//! convention (parameters MUST be absent, same as ML-DSA/SLH-DSA) was
//! verified directly against RFC 8410 §3/§6 before writing
//! [`signature_alg_identifier`] below, not assumed from the ML-DSA
//! precedent alone.
//!
//! ## ML-KEM is out of scope here
//!
//! A KEM key has no signing capability, so a "self-signed" certificate is
//! not cryptographically meaningful for it — a real certificate for an
//! ML-KEM public key needs a **separate**, genuinely signature-capable CA
//! key to sign it, which is a different, bigger operation than this
//! function (closer to `pqctoday-kmip`'s own general `certify()`, not
//! `bootstrap_ca_certificate()`) and out of scope for this verb.
//! [`self_signed_certificate`] rejects non-signature algorithms with
//! `CKR_ARGUMENTS_BAD`, matching `verbs::sign`/`verbs::verify`'s own
//! `algorithm.is_signature()` assertions.

use std::str::FromStr;

use der::asn1::BitString;
use der::{Decode, Encode};
use spki::SubjectPublicKeyInfoOwned;
use time::OffsetDateTime;
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};

use crate::algorithm::Algorithm;
use crate::error::CkError;
use crate::verbs;
use softhsmrustv3::constants::{CKA_PUBLIC_KEY_INFO, CKR_ARGUMENTS_BAD, CKR_GENERAL_ERROR};

// AlgorithmIdentifier OIDs — id-ml-dsa-44/65/87 match pqctoday-kmip's own
// ops/certify.rs constants exactly (NIST CSOR arc / draft-ietf-lamps-
// dilithium-certificates); id-Ed25519 is RFC 8410 §3 (also the same OID
// bytes, `06 03 2B 65 70`, used throughout this whole engagement's own
// Java-side ED25519_OID constants).
const OID_ED25519: &str = "1.3.101.112";
const OID_ML_DSA_44: &str = "2.16.840.1.101.3.4.3.17";
const OID_ML_DSA_65: &str = "2.16.840.1.101.3.4.3.18";
const OID_ML_DSA_87: &str = "2.16.840.1.101.3.4.3.19";

/// This crate's [`CkError`] carries only a raw `CKR_*` code (no message
/// field, by design — see `error.rs`'s own doc), so every DER/ASN.1
/// library error collapses to `CKR_GENERAL_ERROR` here, matching how
/// `verbs.rs`'s own functions never invent a `CKR_*` value the engine
/// didn't actually produce for genuine engine failures — this is the one
/// class of error in this file that is NOT engine-sourced (a malformed
/// TBSCertificate would be a bug in this function, not a token
/// condition), so `CKR_GENERAL_ERROR` (the same code the proto's own
/// `Pkcs11Error` enum reserves for exactly this "something went wrong,
/// not a specific spec condition" case) is the honest choice.
fn der_err<E: std::fmt::Debug>(_e: E) -> CkError {
    CkError(CKR_GENERAL_ERROR)
}

fn signature_alg_identifier(algorithm: Algorithm) -> Result<spki::AlgorithmIdentifierOwned, CkError> {
    let oid_str = match algorithm {
        Algorithm::Ed25519 => OID_ED25519,
        Algorithm::MlDsa44 => OID_ML_DSA_44,
        Algorithm::MlDsa65 => OID_ML_DSA_65,
        Algorithm::MlDsa87 => OID_ML_DSA_87,
        Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024 => return Err(CkError(CKR_ARGUMENTS_BAD)),
    };
    let oid = der::oid::ObjectIdentifier::from_str(oid_str).map_err(der_err)?;
    // Ed25519 and ML-DSA both require ABSENT parameters (RFC 8410 §3/§6
    // for Ed25519; the same convention pqctoday-kmip's own certify.rs
    // already established for ML-DSA/SLH-DSA, per draft-ietf-lamps-
    // dilithium-certificates).
    Ok(spki::AlgorithmIdentifierOwned { oid, parameters: None })
}

/// Monotonic-ish serial source, process-local — same shape as
/// `pqctoday-kmip`'s own `certify.rs::next_serial` (nanosecond timestamp,
/// high bit cleared so the DER INTEGER encodes positive). Reimplemented
/// here rather than shared since that function is private to its own
/// crate and this crate deliberately doesn't depend on it (see module
/// doc).
fn next_serial() -> Vec<u8> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let now = OffsetDateTime::now_utc().unix_timestamp_nanos() as u64;
    let n = now.wrapping_add(COUNTER.fetch_add(1, Ordering::Relaxed));
    let mut bytes = n.to_be_bytes().to_vec();
    bytes[0] &= 0x7f;
    bytes
}

/// Build a self-signed X.509 certificate (DER) for a signature-capable
/// keypair already generated on the token: issuer == subject == `CN=
/// {subject_cn}`, the real live `SubjectPublicKeyInfo` read via
/// `CKA_PUBLIC_KEY_INFO` (never re-derived or guessed from raw key
/// bytes), signed over its own `TBSCertificate` DER by `private_handle`
/// through [`crate::verbs::sign`] — the exact same signing path (and
/// hedged-PQC defaults) the `Sign` verb itself already uses and this
/// crate's own test suite already proves correct for both Ed25519 and
/// ML-DSA. No extensions (`BasicConstraints`/`KeyUsage` are a
/// CA-specific concern — matches `pqctoday-kmip`'s own ordinary
/// `Certify` path, not its `bootstrap_ca_certificate` root-CA path).
pub fn self_signed_certificate(
    session: u32,
    public_handle: u32,
    private_handle: u32,
    algorithm: Algorithm,
    subject_cn: &str,
    validity_days: i64,
) -> Result<Vec<u8>, CkError> {
    if !algorithm.is_signature() {
        return Err(CkError(CKR_ARGUMENTS_BAD));
    }

    let spki_der = softhsmrustv3::native::get_attribute(session, public_handle, CKA_PUBLIC_KEY_INFO)
        .ok_or(CkError(CKR_ARGUMENTS_BAD))?;
    let spki = SubjectPublicKeyInfoOwned::from_der(&spki_der).map_err(der_err)?;

    let name = Name::from_str(&format!("CN={subject_cn}")).map_err(der_err)?;
    let now = OffsetDateTime::now_utc();
    // One day of backdating, matching bootstrap_ca_certificate's own
    // convention — a small clock-skew allowance so a client whose clock
    // is slightly behind this server doesn't see a not-yet-valid cert.
    let not_before = now - time::Duration::days(1);
    let not_after = now + time::Duration::days(validity_days.max(1));

    let signature_alg = signature_alg_identifier(algorithm)?;

    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&next_serial()).map_err(der_err)?,
        signature: signature_alg.clone(),
        issuer: name.clone(),
        validity: Validity {
            not_before: Time::try_from(std::time::SystemTime::from(not_before)).map_err(der_err)?,
            not_after: Time::try_from(std::time::SystemTime::from(not_after)).map_err(der_err)?,
        },
        subject: name,
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: None,
    };

    let tbs_der = tbs.to_der().map_err(der_err)?;
    // Neither Ed25519 nor ML-DSA needs a raw-to-DER signature conversion
    // (that's an ECDSA-only concern for its raw r||s — DER-wrapping is
    // NOT needed here); both go into the BIT STRING as-is, same as
    // pqctoday-kmip's own `issue_certificate` match arm for these two
    // algorithm families.
    let signature = verbs::sign(session, private_handle, algorithm, &tbs_der)?;

    let cert = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: signature_alg,
        signature: BitString::from_bytes(&signature).map_err(der_err)?,
    };
    cert.to_der().map_err(der_err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::fresh_session;
    use serial_test::serial;

    #[test]
    #[serial]
    fn ed25519_self_signed_cert_parses_and_is_self_signed() {
        let session = fresh_session();
        let (pub_h, prv_h) =
            verbs::generate_key_pair(session, Algorithm::Ed25519, b"\xC1", "cert-ed25519").expect("keygen");
        let der = self_signed_certificate(session, pub_h, prv_h, Algorithm::Ed25519, "cert-test-ed25519", 30)
            .expect("self_signed_certificate");
        let cert = Certificate::from_der(&der).expect("re-parse the DER we just built");
        assert_eq!(
            cert.tbs_certificate.issuer.to_string(),
            cert.tbs_certificate.subject.to_string(),
            "issuer and subject must match for a self-signed cert"
        );
        assert_eq!(cert.tbs_certificate.signature.oid.to_string(), OID_ED25519);
    }

    #[test]
    #[serial]
    fn ml_dsa_65_self_signed_cert_signature_verifies_against_its_own_public_key() {
        let session = fresh_session();
        let (pub_h, prv_h) =
            verbs::generate_key_pair(session, Algorithm::MlDsa65, b"\xC2", "cert-mldsa65").expect("keygen");
        let der = self_signed_certificate(session, pub_h, prv_h, Algorithm::MlDsa65, "cert-test-ml-dsa-65", 30)
            .expect("self_signed_certificate");
        let cert = Certificate::from_der(&der).expect("re-parse the DER we just built");
        let tbs_der = cert.tbs_certificate.to_der().expect("re-encode TBS for the check below");
        let sig = cert.signature.raw_bytes();
        // The REAL correctness check: the embedded signature must verify
        // via this same token's own Verify path against the embedded
        // TBSCertificate bytes and the same public key — not just "the
        // DER re-parses", which would pass even for a garbage signature.
        let ok = verbs::verify(session, pub_h, Algorithm::MlDsa65, &tbs_der, sig).expect("verify");
        assert!(ok, "the certificate's own embedded signature must verify against its own TBSCertificate + public key");
    }

    #[test]
    #[serial]
    fn ml_kem_key_rejected_with_ckr_arguments_bad() {
        let session = fresh_session();
        let (pub_h, prv_h) =
            verbs::generate_key_pair(session, Algorithm::MlKem768, b"\xC3", "cert-mlkem-reject").expect("keygen");
        let err = self_signed_certificate(session, pub_h, prv_h, Algorithm::MlKem768, "cert-test-ml-kem", 30)
            .expect_err("ML-KEM has no signing capability — must be rejected, not silently accepted");
        assert_eq!(err.raw(), CKR_ARGUMENTS_BAD);
    }
}
