//! KMIP 3.0 §6.1.62 **Validate** operation — certificate-chain validation.
//!
//! > "This operation requests the server to validate a certificate chain
//! > and return information on its validity."
//!
//! Op codepoint `0x17` (verified — `Validate = 0x00000017`).
//!
//! ## KMIP design point
//!
//! Like Signature Verify, a *negative* result is **not** a KMIP error —
//! it returns a successful `Validate` response with a `Validity
//! Indicator` of `Invalid` or `Unknown`. KMIP errors (Object Not Found,
//! Invalid Object Type, …) are reserved for protocol-level failures:
//! a referenced UID that doesn't exist, or one that names a non-
//! Certificate object.
//!
//! ## Validation depth actually implemented
//!
//! The supplied `Certificate`s (inline DER) plus the DER of any
//! referenced stored Certificate objects together form one candidate
//! chain. With the `ring`-backed `x509-parser` `verify` feature this
//! handler performs:
//!
//! 1. **Parse** every certificate (RFC 5280). A certificate whose bytes
//!    don't parse makes the whole chain `Invalid`.
//! 2. **Validity-date** — each certificate must be valid at the request's
//!    `Validity Date` (or "now" when omitted, per §6.1.62). A cert that
//!    is expired / not-yet-valid at that instant → `Invalid`.
//! 3. **Chain-link + signature** — for every non-self-signed certificate
//!    in the set, find its issuer *within the supplied/stored set* by
//!    matching Issuer DN ⟷ Subject DN and verify the certificate's
//!    signature against that issuer's public key (`ring`: RSA-PKCS1v15
//!    and ECDSA over SHA-256/384/512). A present-but-failing signature
//!    → `Invalid`.
//!
//! ### What returns `Unknown` (never a false `Valid`)
//!
//! - The chain does not terminate in a self-signed (root / trust-anchor)
//!   certificate within the supplied set — i.e. some certificate's issuer
//!   is **not present**, so the path to a trust anchor cannot be
//!   completed. The server holds no separate trust-anchor store, so it
//!   honestly cannot affirm such a chain.
//! - A signature uses an algorithm `ring` cannot verify (the
//!   `verify_signature` call errors for an *unsupported* algorithm rather
//!   than an actually-bad signature).
//!
//! `Valid` is returned **only** when every certificate parsed, every
//! certificate is within its validity window at the requested instant,
//! every non-root link's signature verified against an issuer in the
//! set, and the chain terminates in a self-signed certificate present in
//! the set. Anything that cannot be affirmatively checked degrades to
//! `Unknown`; anything that affirmatively fails is `Invalid`.
//!
//! This is intentionally *not* a full RFC 5280 path validation (no name
//! constraints, no basicConstraints/keyUsage/EKU enforcement, no
//! revocation, no external trust store) — those would over-promise given
//! the available crates. The depth is documented here so the result is
//! honest about its limits.

use ::time::OffsetDateTime;
use x509_parser::prelude::*;

use crate::error::{KmipError, Result};
use crate::kmip30::{ObjectType, SignatureValidity, ValidateRequest, ValidateResponse};

use super::deps::Deps;
use super::helpers::{emit_request, emit_success, fail_err};

pub fn validate(
    deps: &Deps,
    req: ValidateRequest,
    correlation_id: &str,
) -> Result<ValidateResponse> {
    emit_request(
        deps,
        correlation_id,
        "Validate",
        format!(
            "inline_certs={} stored_uids={} validity_date={}",
            req.certificates.len(),
            req.uids.len(),
            req.validity_date.map(|t| t.to_string()).unwrap_or_else(|| "now".into()),
        ),
    );

    // Resolve every referenced stored Certificate object to its DER.
    // ObjectNotFound when a UID is absent; InvalidObjectType when the UID
    // names a non-Certificate object — both are protocol errors per
    // §6.1.62 Table 442 (Object Not Found / Invalid Object Type).
    let mut ders: Vec<Vec<u8>> = Vec::with_capacity(req.certificates.len() + req.uids.len());
    for uid in &req.uids {
        let obj = deps.store.get(uid)?.ok_or_else(|| {
            fail_err(deps, correlation_id, "Validate", KmipError::object_not_found(uid))
        })?;
        if obj.object_type != ObjectType::Certificate {
            return Err(fail_err(
                deps,
                correlation_id,
                "Validate",
                KmipError::invalid_object_type(format!(
                    "Validate: UID {uid} is {:?}, not a Certificate",
                    obj.object_type
                )),
            ));
        }
        match obj.key_material {
            Some(der) if !der.is_empty() => ders.push(der),
            _ => {
                // A Certificate object with no stored DER cannot be
                // validated — treat as an Invalid chain rather than a
                // protocol error (the object exists and is the right type).
                emit_success(deps, correlation_id, "Validate");
                return Ok(ValidateResponse { validity: SignatureValidity::Invalid });
            }
        }
    }
    // Inline certificate DER blobs from the request.
    ders.extend(req.certificates.iter().cloned());

    // An empty chain cannot be affirmed valid (§6.1.62 validates "a
    // certificate chain"); nothing to check → Unknown.
    if ders.is_empty() {
        emit_success(deps, correlation_id, "Validate");
        return Ok(ValidateResponse { validity: SignatureValidity::Unknown });
    }

    let validity = validate_chain(&ders, req.validity_date.unwrap_or_else(OffsetDateTime::now_utc));
    emit_success(deps, correlation_id, "Validate");
    Ok(ValidateResponse { validity })
}

/// Core chain check. See the module doc for the exact Valid/Invalid/
/// Unknown contract. Pure (no `deps`) so it is directly unit-testable.
fn validate_chain(ders: &[Vec<u8>], at: OffsetDateTime) -> SignatureValidity {
    // 1. Parse every certificate. Any parse failure → Invalid.
    let mut certs: Vec<X509Certificate> = Vec::with_capacity(ders.len());
    for der in ders {
        match X509Certificate::from_der(der) {
            Ok((_, c)) => certs.push(c),
            Err(_) => return SignatureValidity::Invalid,
        }
    }

    // 2. Validity-date window for every certificate at `at`.
    let asn1_at = match ASN1Time::from_timestamp(at.unix_timestamp()) {
        Ok(t) => t,
        Err(_) => return SignatureValidity::Unknown,
    };
    for c in &certs {
        if !c.validity().is_valid_at(asn1_at) {
            return SignatureValidity::Invalid;
        }
    }

    // 3. Chain-link + signature. For each certificate, find an issuer in
    // the set (Issuer DN == some cert's Subject DN). Self-signed certs
    // (issuer == own subject) are candidate trust anchors.
    let mut degrade_unknown = false;
    let mut saw_self_signed_anchor = false;

    for c in &certs {
        let self_signed = c.issuer() == c.subject();

        // Locate the issuer's public key within the supplied set.
        let issuer = if self_signed {
            Some(c)
        } else {
            certs.iter().find(|cand| cand.subject() == c.issuer())
        };

        match issuer {
            Some(iss) => {
                // Verify this cert's signature against the issuer key.
                match c.verify_signature(Some(iss.public_key())) {
                    Ok(()) => {
                        if self_signed {
                            saw_self_signed_anchor = true;
                        }
                    }
                    Err(X509Error::SignatureVerificationError) => {
                        // A signature that affirmatively fails → Invalid.
                        return SignatureValidity::Invalid;
                    }
                    Err(_) => {
                        // Unsupported algorithm / other parse issue in the
                        // signature path — cannot affirm, so degrade.
                        degrade_unknown = true;
                    }
                }
            }
            None => {
                // The issuer is not in the supplied/stored set, so the
                // path to a trust anchor cannot be completed here.
                degrade_unknown = true;
            }
        }
    }

    // A chain we couldn't fully resolve, or one that never reached a
    // self-signed anchor in the set, cannot be affirmed Valid.
    if degrade_unknown || !saw_self_signed_anchor {
        return SignatureValidity::Unknown;
    }
    SignatureValidity::Valid
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditlog::{AuditSink, RingSink};
    use crate::kmip30::{KmipAlgorithm, State, UsageMask};
    use crate::policy::Engine;
    use crate::store::{MemoryStore, ObjectRecord};
    use std::sync::Arc;

    fn deps_with() -> Deps {
        let ring = Arc::new(RingSink::new(64));
        let sink: Arc<dyn AuditSink> = ring.clone();
        Deps::new(
            Engine::permissive(),
            Arc::new(MemoryStore::new()),
            sink,
            super::super::deps::DepsConfig::default(),
        )
    }

    /// rcgen `CertificateParams::new(SAN)` leaves the *distinguished
    /// name* empty, so issuer/subject DN comparison can't distinguish
    /// certs. Build params with an explicit CommonName so the chain-link
    /// matching in `validate_chain` (Issuer DN ⟷ Subject DN) is
    /// meaningful, plus an explicit validity window.
    fn params_with_cn(cn: &str) -> rcgen::CertificateParams {
        let mut p = rcgen::CertificateParams::new(vec![format!("{cn}.test")]).unwrap();
        p.distinguished_name.push(rcgen::DnType::CommonName, cn);
        // Valid roughly now ± a few years so the validity-date tests have
        // headroom on both sides.
        let now = OffsetDateTime::now_utc();
        p.not_before = now - ::time::Duration::days(1);
        p.not_after = now + ::time::Duration::days(365 * 5);
        p
    }

    /// A self-signed ECDSA-P256 CA with CN="root", valid now ± window.
    fn self_signed_der() -> Vec<u8> {
        let key = rcgen::KeyPair::generate().unwrap();
        params_with_cn("root").self_signed(&key).unwrap().der().to_vec()
    }

    fn put_cert(deps: &Deps, uid: &str, der: Vec<u8>) {
        deps.store
            .put(ObjectRecord {
                uid: uid.into(),
                object_type: ObjectType::Certificate,
                algorithm: KmipAlgorithm::Ecdsa,
                usage_mask: UsageMask::VERIFY,
                state: State::Active,
                key_material: Some(der),
                ..ObjectRecord::default()
            })
            .unwrap();
    }

    #[test]
    fn self_signed_cert_is_valid() {
        let der = self_signed_der();
        assert_eq!(validate_chain(&[der], OffsetDateTime::now_utc()), SignatureValidity::Valid);
    }

    #[test]
    fn expired_cert_is_invalid() {
        // Validate the self-signed cert at an instant far in the future,
        // past its not_after — the validity-window check fails.
        let der = self_signed_der();
        let far_future = OffsetDateTime::now_utc() + ::time::Duration::days(365 * 100);
        assert_eq!(validate_chain(&[der], far_future), SignatureValidity::Invalid);
    }

    #[test]
    fn not_yet_valid_cert_is_invalid() {
        // Far in the past, before not_before.
        let der = self_signed_der();
        let far_past = OffsetDateTime::from_unix_timestamp(0).unwrap();
        assert_eq!(validate_chain(&[der], far_past), SignatureValidity::Invalid);
    }

    #[test]
    fn missing_issuer_is_unknown() {
        // A leaf (non-self-signed) whose issuer isn't in the set →
        // Unknown. Generate a CA, then issue a leaf signed by it, then
        // validate the leaf ALONE.
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_cert = params_with_cn("issuer-ca").self_signed(&ca_key).unwrap();

        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = params_with_cn("leaf").signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();

        // Leaf alone — issuer (CA) absent.
        assert_eq!(
            validate_chain(&[leaf.der().to_vec()], OffsetDateTime::now_utc()),
            SignatureValidity::Unknown
        );
    }

    #[test]
    fn leaf_with_ca_chain_is_valid() {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_cert = params_with_cn("issuer-ca").self_signed(&ca_key).unwrap();

        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = params_with_cn("leaf").signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();

        // Leaf + its self-signed CA → full chain to a self-signed anchor.
        assert_eq!(
            validate_chain(
                &[leaf.der().to_vec(), ca_cert.der().to_vec()],
                OffsetDateTime::now_utc()
            ),
            SignatureValidity::Valid
        );
    }

    #[test]
    fn broken_chain_wrong_issuer_signature_is_invalid() {
        // Two independent self-signed CAs with the SAME subject/issuer DN
        // would be needed to force a signature mismatch; instead, take a
        // leaf signed by CA-A but pair it with CA-B that happens to share
        // the issuer DN. Simpler: corrupt a byte in a self-signed cert's
        // signature region → parse-ok but signature fails.
        let mut der = self_signed_der();
        // Flip a bit late in the DER (within the signature BIT STRING).
        let n = der.len();
        der[n - 1] ^= 0x01;
        // Either the signature fails (Invalid) — the intended outcome.
        assert_eq!(
            validate_chain(&[der], OffsetDateTime::now_utc()),
            SignatureValidity::Invalid
        );
    }

    #[test]
    fn garbage_der_is_invalid() {
        assert_eq!(
            validate_chain(&[vec![0xff, 0x00, 0x01]], OffsetDateTime::now_utc()),
            SignatureValidity::Invalid
        );
    }

    #[test]
    fn stored_uid_not_found_is_object_not_found() {
        let d = deps_with();
        let err = validate(
            &d,
            ValidateRequest { certificates: vec![], uids: vec!["nope".into()], validity_date: None },
            "c",
        )
        .unwrap_err();
        assert_eq!(err.result_reason(), crate::error::ResultReason::ObjectNotFound);
    }

    #[test]
    fn stored_uid_non_certificate_is_invalid_object_type() {
        let d = deps_with();
        d.store
            .put(ObjectRecord {
                uid: "sym".into(),
                object_type: ObjectType::SymmetricKey,
                algorithm: KmipAlgorithm::Aes,
                usage_mask: UsageMask::ENCRYPT,
                state: State::Active,
                ..ObjectRecord::default()
            })
            .unwrap();
        let err = validate(
            &d,
            ValidateRequest { certificates: vec![], uids: vec!["sym".into()], validity_date: None },
            "c",
        )
        .unwrap_err();
        assert_eq!(err.result_reason(), crate::error::ResultReason::InvalidObjectType);
    }

    #[test]
    fn stored_self_signed_uid_is_valid() {
        let d = deps_with();
        put_cert(&d, "ca", self_signed_der());
        let r = validate(
            &d,
            ValidateRequest { certificates: vec![], uids: vec!["ca".into()], validity_date: None },
            "c",
        )
        .unwrap();
        assert_eq!(r.validity, SignatureValidity::Valid);
    }
}
