//! draft-bonnell-lamps-chameleon-certs-07 — validate a "delta"
//! certificate reconstructed from a primary certificate's
//! `DeltaCertificateDescriptor` extension (OID `2.16.840.1.114027.80.6.1`).
//!
//! ## Scope: STRUCTURAL VALIDATION ONLY — no issuance (WP-C11)
//!
//! This draft is EXPIRED — re-confirmed fresh against
//! datatracker.ietf.org at execution time (2026-07-10, per the plan's
//! own instruction not to trust its 2026-07-10 snapshot without
//! re-checking): "This Internet-Draft is no longer active," still
//! carrying its personal-name form (`draft-bonnell-...`, never renamed
//! to `draft-ietf-lamps-...`), no working-group adoption, no RFC path.
//! Validating a format nobody will legitimately issue is acceptable
//! coverage; investing in issuance for it is not. No
//! `CreateKeyPair`/`Certify` counterpart here — a stronger reason than
//! `catalyst.rs`'s/`related_certs.rs`'s validation-only scope (those
//! are live/published specs simply not mapped to a KMIP issuance
//! concept; this one is an abandoned draft).
//!
//! ## Reference: `certBuilder.ts::buildChameleonCert`
//!
//! ```text
//! DeltaCertificateDescriptor ::= SEQUENCE {
//!     serialNumber          CertificateSerialNumber,
//!     [0] EXPLICIT          AlgorithmIdentifier,     -- delta's own sig alg
//!     subjectPublicKeyInfo  SubjectPublicKeyInfo,    -- delta's own SPKI
//!     signatureValue        BIT STRING               -- delta's own signature
//! }
//! ```
//!
//! Confirmed against `buildChameleonCert`'s own construction: the delta
//! certificate's issuer/validity/subject and OTHER extensions (e.g.
//! `basicConstraintsExt()`) are IDENTICAL to the primary's — only
//! serial number, signature algorithm, SPKI, and signature differ
//! (`deltaTbs`/`primaryTbs` both built from the exact same `name`/
//! `validity`). So reconstructing the delta's TBS means: take the
//! primary's parsed TBS, substitute those 3 fields from the descriptor,
//! drop the `DeltaCertificateDescriptor` extension itself from the
//! extensions list (keep everything else), and re-encode — the same
//! "DER is canonical, safe to re-encode" reasoning
//! `catalyst.rs::tbs_minus_alt_sig_value` already relies on.
//!
//! ## Scope discipline (invariant 0a — no crypto in kmip, only encoding)
//!
//! Pure DER parsing/substitution/re-assembly. The one signature check
//! routes through `spki_verify::verify_with_spki`, like every other
//! verify path in this crate.

use der::asn1::BitString;
use der::{Decode, Encode, Sequence};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::serial_number::SerialNumber;
use x509_cert::TbsCertificate;

use crate::error::{KmipError, Result, ResultReason};

use super::deps::Deps;
use super::spki_verify::{verify_with_spki, SpkiVerdict};

/// DeltaCertificateDescriptor.
pub const DELTA_CERT_DESC_OID: &str = "2.16.840.1.114027.80.6.1";

#[derive(Sequence)]
struct DeltaCertificateDescriptor {
    serial_number: SerialNumber,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    signature_algorithm: AlgorithmIdentifierOwned,
    subject_public_key_info: SubjectPublicKeyInfoOwned,
    signature_value: BitString,
}

/// The reconstructed delta certificate's signing inputs, ready for
/// [`verify_delta_signature`].
#[derive(Debug)]
pub struct DeltaCert {
    pub tbs_der: Vec<u8>,
    pub spki: SubjectPublicKeyInfoOwned,
    pub sig_alg: AlgorithmIdentifierOwned,
    pub signature: Vec<u8>,
}

/// Parse the `DeltaCertificateDescriptor` extension from a primary TBS
/// and reconstruct the delta certificate's own TBS (see module doc).
///
/// `Ok(None)` if the primary carries no such extension — an ordinary,
/// non-Chameleon cert, not an error. `Err` if present but malformed.
pub fn reconstruct_delta(primary_tbs: &TbsCertificate) -> Result<Option<DeltaCert>> {
    let exts = primary_tbs.extensions.as_deref().unwrap_or(&[]);
    let delta_ext = match exts.iter().find(|e| e.extn_id.to_string() == DELTA_CERT_DESC_OID) {
        Some(e) => e,
        None => return Ok(None),
    };

    let descriptor = DeltaCertificateDescriptor::from_der(delta_ext.extn_value.as_bytes()).map_err(|e| {
        KmipError::failed(
            ResultReason::InvalidField,
            format!("DeltaCertificateDescriptor (ext 2.16.840.1.114027.80.6.1): {e}"),
        )
    })?;

    let mut delta_tbs = primary_tbs.clone();
    delta_tbs.serial_number = descriptor.serial_number;
    delta_tbs.signature = descriptor.signature_algorithm.clone();
    delta_tbs.subject_public_key_info = descriptor.subject_public_key_info.clone();
    // An empty `Vec` and an absent field are NOT the same DER encoding
    // for this `[3] EXPLICIT OPTIONAL` field — `Some(vec![])` still
    // emits the empty `[3] { SEQUENCE {} }` wrapper, `None` omits it
    // entirely. When the descriptor extension was the ONLY extension,
    // filtering it out must collapse to `None`, matching what a delta
    // TBS with genuinely no extensions field would have been signed
    // over (caught by this file's own `real_delta_signature_
    // reconstructs_and_verifies` test failing before this fix).
    delta_tbs.extensions = delta_tbs.extensions.and_then(|exts| {
        let remaining: Vec<_> = exts.into_iter().filter(|e| e.extn_id.to_string() != DELTA_CERT_DESC_OID).collect();
        if remaining.is_empty() {
            None
        } else {
            Some(remaining)
        }
    });

    let tbs_der = delta_tbs
        .to_der()
        .map_err(|e| KmipError::failed(ResultReason::GeneralFailure, format!("Chameleon delta TBS re-encode: {e}")))?;

    Ok(Some(DeltaCert {
        tbs_der,
        spki: descriptor.subject_public_key_info,
        sig_alg: descriptor.signature_algorithm,
        signature: descriptor.signature_value.raw_bytes().to_vec(),
    }))
}

/// Verify the reconstructed delta certificate's own signature against
/// its own SPKI — an entirely independent check from the primary
/// certificate's signature (which `validate.rs`'s ordinary path already
/// verifies).
pub fn verify_delta_signature(deps: &Deps, delta: &DeltaCert) -> Result<SpkiVerdict> {
    verify_with_spki(deps, &delta.spki, &delta.sig_alg, &delta.tbs_der, &delta.signature)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use der::oid::ObjectIdentifier;
    use std::str::FromStr;
    use x509_cert::certificate::Version;
    use x509_cert::ext::Extension;
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber as X509SerialNumber;
    use x509_cert::time::{Time, Validity};

    fn deps_with_session() -> (Deps, std::sync::MutexGuard<'static, ()>) {
        use softhsmrustv3::native::session::{bootstrap_default_token, finalize, init};
        let guard = super::super::helpers::engine_lock();
        let _ = finalize();
        init().expect("engine init");
        let session = bootstrap_default_token(0, "so", "user", "chameleon-test").expect("bootstrap session");
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

    /// Build a minimal Chameleon-shaped, fully self-signed primary
    /// certificate: ML-DSA-65 primary SPKI, ECDSA-P256 delta SPKI in
    /// the DeltaCertificateDescriptor extension, both real engine keys.
    /// Mirrors `certBuilder.ts::buildChameleonCert`'s 2-step process
    /// exactly (delta signed first, over its own minimal TBS; primary
    /// signed second, over the primary TBS carrying the descriptor).
    /// Returns `(signed certificate DER, primary TBS)` — `pub(crate)`,
    /// reused directly by `validate.rs`'s own test for the
    /// `validate_chain` wiring, same cross-file test-fixture-reuse
    /// precedent as `catalyst::tests::build_catalyst_tbs_and_sign`.
    pub(crate) fn build_chameleon_primary_tbs(session: u32, tamper_delta_sig: bool) -> (Vec<u8>, TbsCertificate) {
        use softhsmrustv3::constants as c;
        use softhsmrustv3::native;

        let mldsa_cka = b"chameleon-mldsa".to_vec();
        let ec_cka = b"chameleon-ec".to_vec();
        native::generate_ml_dsa_keypair(session, c::CKP_ML_DSA_65, &mldsa_cka, "chameleon-mldsa")
            .expect("ML-DSA primary keygen");
        native::generate_ecdsa_keypair(session, native::EccCurve::P256, &ec_cka, "chameleon-ec")
            .expect("EC delta keygen");

        let mldsa_pub_h =
            super::super::helpers::find_handle_for_object(session, &mldsa_cka, crate::kmip30::ObjectType::PublicKey)
                .unwrap()
                .unwrap();
        let ec_pub_h =
            super::super::helpers::find_handle_for_object(session, &ec_cka, crate::kmip30::ObjectType::PublicKey)
                .unwrap()
                .unwrap();
        let mldsa_spki_der = native::get_attribute(session, mldsa_pub_h, c::CKA_PUBLIC_KEY_INFO).unwrap();
        let ec_spki_der = native::get_attribute(session, ec_pub_h, c::CKA_PUBLIC_KEY_INFO).unwrap();
        let mldsa_spki = SubjectPublicKeyInfoOwned::from_der(&mldsa_spki_der).unwrap();
        let ec_spki = SubjectPublicKeyInfoOwned::from_der(&ec_spki_der).unwrap();

        let ec_sig_alg = AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::from_str("1.2.840.10045.4.3.2").unwrap(), // ecdsa-with-SHA256
            parameters: None,
        };
        let mldsa_sig_alg = AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::from_str("2.16.840.1.101.3.4.3.18").unwrap(), // id-ml-dsa-65
            parameters: None,
        };

        let name = Name::from_str("CN=Chameleon Test").unwrap();
        let now = time::OffsetDateTime::now_utc();
        let validity = Validity {
            not_before: Time::try_from(std::time::SystemTime::from(now - time::Duration::days(1))).unwrap(),
            not_after: Time::try_from(std::time::SystemTime::from(now + time::Duration::days(365))).unwrap(),
        };
        let delta_serial = X509SerialNumber::new(&[0x02]).unwrap();

        // A non-descriptor extension present on BOTH TBSes — matching
        // `certBuilder.ts::buildChameleonCert`'s actual construction
        // (both `deltaTbs`/`primaryTbs` always carry `basicConstraintsExt()`
        // too, never JUST the descriptor), so this fixture exercises the
        // "other extensions survive reconstruction" path the reference
        // always hits, not only the descriptor-was-the-only-extension
        // edge case.
        use const_oid::AssociatedOid;
        use der::Encode as _;
        use x509_cert::ext::pkix::{KeyUsage, KeyUsages};
        let key_usage = KeyUsage(KeyUsages::DigitalSignature.into());
        let key_usage_ext = Extension {
            extn_id: KeyUsage::OID,
            critical: false,
            extn_value: der::asn1::OctetString::new(key_usage.to_der().unwrap()).unwrap(),
        };

        // Delta TBS: same issuer/subject/validity as the primary will
        // use, but the delta's OWN serial/sig-alg/SPKI, plus the shared
        // KeyUsage extension — no descriptor extension (it doesn't
        // reference itself).
        let delta_tbs = TbsCertificate {
            version: Version::V3,
            serial_number: delta_serial.clone(),
            signature: ec_sig_alg.clone(),
            issuer: name.clone(),
            validity,
            subject: name.clone(),
            subject_public_key_info: ec_spki.clone(),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(vec![key_usage_ext.clone()]),
        };
        let delta_tbs_der = delta_tbs.to_der().unwrap();
        let ec_priv_h =
            super::super::helpers::find_handle_for_object(session, &ec_cka, crate::kmip30::ObjectType::PrivateKey)
                .unwrap()
                .unwrap();
        let delta_raw_sig = native::sign(session, ec_priv_h, c::CKM_ECDSA_SHA256, &delta_tbs_der).expect("EC delta sign");
        let delta_sig_der = super::super::certify::ecdsa_raw_to_der(&delta_raw_sig).expect("EC sig DER wrap");
        let mut delta_sig_bytes = delta_sig_der;
        if tamper_delta_sig {
            let last = delta_sig_bytes.len() - 1;
            delta_sig_bytes[last] ^= 0xff;
        }

        // DeltaCertificateDescriptor extension.
        let descriptor = DeltaCertificateDescriptor {
            serial_number: delta_serial,
            signature_algorithm: ec_sig_alg,
            subject_public_key_info: ec_spki,
            signature_value: BitString::from_bytes(&delta_sig_bytes).unwrap(),
        };
        let descriptor_der = descriptor.to_der().unwrap();
        let delta_ext = Extension {
            extn_id: ObjectIdentifier::from_str(DELTA_CERT_DESC_OID).unwrap(),
            critical: false,
            extn_value: der::asn1::OctetString::new(descriptor_der).unwrap(),
        };

        // Primary TBS: same issuer/subject/validity, ML-DSA-65 SPKI,
        // carries the shared KeyUsage extension AND the descriptor.
        let primary_tbs = TbsCertificate {
            version: Version::V3,
            serial_number: X509SerialNumber::new(&[0x01]).unwrap(),
            signature: mldsa_sig_alg.clone(),
            issuer: name.clone(),
            validity,
            subject: name,
            subject_public_key_info: mldsa_spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(vec![key_usage_ext, delta_ext]),
        };

        // Self-signed (issuer == subject) primary signature, so
        // `validate.rs::validate_chain` can drive the assembled
        // certificate directly without any separate CA fixture.
        let primary_tbs_der = primary_tbs.to_der().unwrap();
        let mldsa_priv_h =
            super::super::helpers::find_handle_for_object(session, &mldsa_cka, crate::kmip30::ObjectType::PrivateKey)
                .unwrap()
                .unwrap();
        let primary_sig =
            native::sign_pqc(session, mldsa_priv_h, c::CKM_ML_DSA, &primary_tbs_der, b"", false, false, false, None)
                .expect("ML-DSA primary sign");
        let cert = x509_cert::Certificate {
            tbs_certificate: primary_tbs.clone(),
            signature_algorithm: mldsa_sig_alg,
            signature: BitString::from_bytes(&primary_sig).unwrap(),
        };
        let cert_der = cert.to_der().expect("assemble Chameleon certificate DER");

        (cert_der, primary_tbs)
    }

    #[test]
    fn ordinary_cert_with_no_delta_descriptor_is_none() {
        let (deps, _g) = deps_with_session();
        let session = deps.engine_session.unwrap();
        let (_cert_der, mut tbs) = build_chameleon_primary_tbs(session, false);
        tbs.extensions = None;
        assert!(reconstruct_delta(&tbs).unwrap().is_none());
    }

    #[test]
    fn real_delta_signature_reconstructs_and_verifies() {
        let (deps, _g) = deps_with_session();
        let session = deps.engine_session.unwrap();
        let (_cert_der, tbs) = build_chameleon_primary_tbs(session, false);

        let delta = reconstruct_delta(&tbs).unwrap().expect("DeltaCertificateDescriptor present");
        // The reconstructed delta TBS keeps the OTHER extension (KeyUsage)
        // but drops the descriptor itself.
        use const_oid::AssociatedOid;
        use x509_cert::ext::pkix::KeyUsage;
        let reparsed = TbsCertificate::from_der(&delta.tbs_der).unwrap();
        let remaining_oids: Vec<String> =
            reparsed.extensions.unwrap_or_default().iter().map(|e| e.extn_id.to_string()).collect();
        assert_eq!(remaining_oids, vec![KeyUsage::OID.to_string()]);

        let verdict = verify_delta_signature(&deps, &delta).unwrap();
        assert_eq!(verdict, SpkiVerdict::Valid, "a real ECDSA delta signature over the reconstructed TBS must verify");
    }

    #[test]
    fn tampered_delta_signature_is_invalid() {
        let (deps, _g) = deps_with_session();
        let session = deps.engine_session.unwrap();
        let (_cert_der, tbs) = build_chameleon_primary_tbs(session, true);

        let delta = reconstruct_delta(&tbs).unwrap().expect("DeltaCertificateDescriptor present");
        let verdict = verify_delta_signature(&deps, &delta).unwrap();
        assert_eq!(verdict, SpkiVerdict::Invalid, "a tampered delta signature must never verify");
    }

    #[test]
    fn malformed_descriptor_is_a_structural_error() {
        let (deps, _g) = deps_with_session();
        let session = deps.engine_session.unwrap();
        let (_cert_der, mut tbs) = build_chameleon_primary_tbs(session, false);
        // Corrupt the descriptor extension's content specifically (not
        // the KeyUsage extension also present) — found by OID, not a
        // hardcoded index.
        if let Some(exts) = tbs.extensions.as_mut() {
            let descriptor_ext = exts.iter_mut().find(|e| e.extn_id.to_string() == DELTA_CERT_DESC_OID).unwrap();
            descriptor_ext.extn_value = der::asn1::OctetString::new(vec![0xde, 0xad, 0xbe, 0xef]).unwrap();
        }
        let err = reconstruct_delta(&tbs).unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::InvalidField);
    }
}
