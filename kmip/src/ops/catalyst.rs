//! ITU-T X.509 (2019) §9.8 Alternative Signature ("Catalyst") —
//! validate a certificate carrying an alt signature in extensions
//! `2.5.29.72`/`73`/`74`, independent of its ordinary primary
//! signature.
//!
//! ## Scope: validation only (WP-C9)
//!
//! §9.8 defines no KMIP issuance concept — Catalyst is "one cert, two
//! independent signatures," not a new key type (unlike
//! `composite_sig.rs`/`composite_kem.rs`, this module has no
//! `CreateKeyPair`/`Certify` counterpart).
//!
//! ## Reference: `certBuilder.ts::buildAltSigCert`
//!
//! The alt signature covers a DIFFERENT TBS than the primary — the
//! same `TBSCertificate` fields, but with extensions `2.5.29.72`
//! (`SubjectAltPublicKeyInfo`) and `2.5.29.73` (`AltSignatureAlgorithm`)
//! present and `2.5.29.74` (`AltSignatureValue`) ABSENT (it cannot sign
//! over its own value — `buildAltSigCert`'s own "Step 1: Build TBS with
//! ext 72+73 but WITHOUT ext 74"). Each extension's `extnValue` OCTET
//! STRING wraps exactly one inner DER value directly (confirmed against
//! `buildExtension`'s own source: `extnValue: new OctetString(value)`) —
//! ext72 wraps a bare `SubjectPublicKeyInfo` SEQUENCE, ext73 a bare
//! `AlgorithmIdentifier` SEQUENCE, ext74 a BIT STRING carrying the raw
//! alt signature bytes.
//!
//! `tbs_minus_alt_sig_value` reconstructs "TBS-minus-ext74" by parsing
//! the received TBS, dropping the one extension, and re-encoding — safe
//! because DER is canonical (X.690 §10): every other field is copied
//! unchanged from already-valid DER, so re-encoding reproduces the
//! exact bytes a direct from-scratch encode (`certBuilder.ts`'s own
//! `tbsForAltSigDer`) would have produced.
//!
//! ## Scope discipline (invariant 0a — no crypto in kmip, only encoding)
//!
//! Pure DER parsing/assembly. Both signature checks route through
//! `spki_verify::verify_with_spki`, exactly like every other verify
//! path in this crate.

use der::asn1::BitString;
use der::{Decode, Encode};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::TbsCertificate;

use crate::error::{KmipError, Result, ResultReason};

use super::deps::Deps;
use super::spki_verify::{verify_with_spki, SpkiVerdict};

/// SubjectAltPublicKeyInfo — ITU-T X.509 (2019) §9.8.
pub const ALT_SIG_PUBKEY_OID: &str = "2.5.29.72";
/// AltSignatureAlgorithm.
pub const ALT_SIG_ALG_OID: &str = "2.5.29.73";
/// AltSignatureValue.
pub const ALT_SIG_VALUE_OID: &str = "2.5.29.74";

/// The 3 alt-sig extensions' decoded content.
#[derive(Debug)]
pub struct AltSigFields {
    pub alt_spki: SubjectPublicKeyInfoOwned,
    pub alt_sig_alg: AlgorithmIdentifierOwned,
    pub alt_sig_value: Vec<u8>,
}

/// Extract and decode the 3 alt-sig extensions from a parsed TBS.
///
/// `Ok(None)` if NONE of the 3 OIDs are present — the ordinary,
/// non-Catalyst case, not an error. `Err` if some but not all 3 are
/// present, or any is malformed — a real structural problem in a cert
/// that is clearly attempting to be Catalyst-shaped.
pub fn extract_alt_sig_fields(tbs: &TbsCertificate) -> Result<Option<AltSigFields>> {
    let exts = tbs.extensions.as_deref().unwrap_or(&[]);
    let find = |oid: &str| exts.iter().find(|e| e.extn_id.to_string() == oid);

    let (ext72, ext73, ext74) = (find(ALT_SIG_PUBKEY_OID), find(ALT_SIG_ALG_OID), find(ALT_SIG_VALUE_OID));
    if ext72.is_none() && ext73.is_none() && ext74.is_none() {
        return Ok(None);
    }
    let ext72 = ext72.ok_or_else(|| {
        KmipError::failed(ResultReason::InvalidField, "Catalyst cert: extension 2.5.29.72 (alt SPKI) missing")
    })?;
    let ext73 = ext73.ok_or_else(|| {
        KmipError::failed(ResultReason::InvalidField, "Catalyst cert: extension 2.5.29.73 (alt sig alg) missing")
    })?;
    let ext74 = ext74.ok_or_else(|| {
        KmipError::failed(ResultReason::InvalidField, "Catalyst cert: extension 2.5.29.74 (alt sig value) missing")
    })?;

    let alt_spki = SubjectPublicKeyInfoOwned::from_der(ext72.extn_value.as_bytes()).map_err(|e| {
        KmipError::failed(ResultReason::InvalidField, format!("Catalyst alt SPKI (ext 2.5.29.72): {e}"))
    })?;
    let alt_sig_alg = AlgorithmIdentifierOwned::from_der(ext73.extn_value.as_bytes()).map_err(|e| {
        KmipError::failed(ResultReason::InvalidField, format!("Catalyst alt sig alg (ext 2.5.29.73): {e}"))
    })?;
    let alt_sig_bitstring = BitString::from_der(ext74.extn_value.as_bytes()).map_err(|e| {
        KmipError::failed(ResultReason::InvalidField, format!("Catalyst alt sig value (ext 2.5.29.74): {e}"))
    })?;

    Ok(Some(AltSigFields {
        alt_spki,
        alt_sig_alg,
        alt_sig_value: alt_sig_bitstring.raw_bytes().to_vec(),
    }))
}

/// Reconstruct the exact bytes the alt signature was computed over: the
/// same `TBSCertificate` with the `2.5.29.74` (AltSignatureValue)
/// extension removed (see module doc for why re-encoding is safe here).
pub fn tbs_minus_alt_sig_value(tbs: &TbsCertificate) -> Result<Vec<u8>> {
    let mut without_alt = tbs.clone();
    without_alt.extensions = without_alt
        .extensions
        .map(|exts| exts.into_iter().filter(|e| e.extn_id.to_string() != ALT_SIG_VALUE_OID).collect());
    without_alt
        .to_der()
        .map_err(|e| KmipError::failed(ResultReason::GeneralFailure, format!("Catalyst tbs-minus-ext74 re-encode: {e}")))
}

/// Verify the alt signature against the alt SPKI, over tbs-minus-ext74.
///
/// The caller (`validate.rs`) is responsible for ALSO verifying the
/// PRIMARY signature over the full TBS via the ordinary path and
/// AND-combining both verdicts — this function only speaks to the alt
/// half, mirroring the split `verify_composite_signature` uses for
/// composite-signature's two halves (WP-C4).
pub fn verify_alt_signature(deps: &Deps, fields: &AltSigFields, tbs_minus_alt: &[u8]) -> Result<SpkiVerdict> {
    verify_with_spki(deps, &fields.alt_spki, &fields.alt_sig_alg, tbs_minus_alt, &fields.alt_sig_value)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use der::oid::ObjectIdentifier;
    use std::str::FromStr;
    use x509_cert::ext::Extension;
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::time::{Time, Validity};
    use x509_cert::certificate::Version;

    fn deps_with_session() -> (Deps, std::sync::MutexGuard<'static, ()>) {
        use softhsmrustv3::native::session::{bootstrap_default_token, finalize, init};
        let guard = super::super::helpers::engine_lock();
        let _ = finalize();
        init().expect("engine init");
        let session = bootstrap_default_token(0, "so", "user", "catalyst-test").expect("bootstrap session");
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

    /// Build a minimal Catalyst-shaped TBS: ECDSA-P256 primary SPKI,
    /// ML-DSA-65 alt SPKI in ext 72/73/74, both real engine keys.
    /// Mirrors `certify.rs::bootstrap_ca_certificate`'s TBS-building
    /// shape (`Name`/`Validity`/`SerialNumber` construction) and
    /// `certBuilder.ts::buildAltSigCert`'s 4-step process exactly.
    /// `pub(crate)` — reused directly by `validate.rs`'s own test for
    /// the `validate_chain` AND-verdict wiring, same cross-file test-
    /// fixture-reuse precedent as `certify::tests::bootstrap_ca`.
    pub(crate) fn build_catalyst_tbs_and_sign(session: u32, tamper_alt_sig: bool) -> (Vec<u8>, TbsCertificate) {
        use softhsmrustv3::constants as c;
        use softhsmrustv3::native;

        let ec_cka = b"catalyst-ec".to_vec();
        let mldsa_cka = b"catalyst-mldsa".to_vec();
        native::generate_ecdsa_keypair(session, native::EccCurve::P256, &ec_cka, "catalyst-ec")
            .expect("EC primary keygen");
        native::generate_ml_dsa_keypair(session, c::CKP_ML_DSA_65, &mldsa_cka, "catalyst-mldsa")
            .expect("ML-DSA alt keygen");

        let ec_pub_h = super::super::helpers::find_handle_for_object(session, &ec_cka, crate::kmip30::ObjectType::PublicKey)
            .unwrap()
            .unwrap();
        let mldsa_pub_h = super::super::helpers::find_handle_for_object(session, &mldsa_cka, crate::kmip30::ObjectType::PublicKey)
            .unwrap()
            .unwrap();
        let ec_spki_der = native::get_attribute(session, ec_pub_h, c::CKA_PUBLIC_KEY_INFO).unwrap();
        let mldsa_spki_der = native::get_attribute(session, mldsa_pub_h, c::CKA_PUBLIC_KEY_INFO).unwrap();
        let ec_spki = SubjectPublicKeyInfoOwned::from_der(&ec_spki_der).unwrap();

        let ec_sig_alg = AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::from_str("1.2.840.10045.4.3.2").unwrap(), // ecdsa-with-SHA256
            parameters: None,
        };
        let mldsa_sig_alg = AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::from_str("2.16.840.1.101.3.4.3.18").unwrap(), // id-ml-dsa-65
            parameters: None,
        };

        let name = Name::from_str("CN=Catalyst Test").unwrap();
        let now = time::OffsetDateTime::now_utc();
        let validity = Validity {
            not_before: Time::try_from(std::time::SystemTime::from(now - time::Duration::days(1))).unwrap(),
            not_after: Time::try_from(std::time::SystemTime::from(now + time::Duration::days(365))).unwrap(),
        };

        let ext72 = Extension {
            extn_id: ObjectIdentifier::from_str(ALT_SIG_PUBKEY_OID).unwrap(),
            critical: false,
            extn_value: der::asn1::OctetString::new(mldsa_spki_der.clone()).unwrap(),
        };
        let ext73 = Extension {
            extn_id: ObjectIdentifier::from_str(ALT_SIG_ALG_OID).unwrap(),
            critical: false,
            extn_value: der::asn1::OctetString::new(mldsa_sig_alg.to_der().unwrap()).unwrap(),
        };

        // Step 1/2: TBS with ext72+73 only, signed by the alt (ML-DSA) key.
        let tbs_for_alt = TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::new(&[0x01]).unwrap(),
            signature: ec_sig_alg.clone(),
            issuer: name.clone(),
            validity,
            subject: name.clone(),
            subject_public_key_info: ec_spki.clone(),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(vec![ext72.clone(), ext73.clone()]),
        };
        let tbs_for_alt_der = tbs_for_alt.to_der().unwrap();
        // ML-DSA signing needs the PRIVATE handle — resolve it the same
        // way `sign_tbs_with_plan` does. No context string: ITU-T X.509
        // §9.8 defines no LAMPS-style label convention (unlike
        // composite_sig.rs's draft-19 signatureLabel).
        let mldsa_priv_h = super::super::helpers::find_handle_for_object(session, &mldsa_cka, crate::kmip30::ObjectType::PrivateKey)
            .unwrap()
            .unwrap();
        let alt_sig = native::sign_pqc(session, mldsa_priv_h, c::CKM_ML_DSA, &tbs_for_alt_der, b"", false, false, false, None);
        let mut alt_sig_bytes = alt_sig.expect("ML-DSA alt sign");
        if tamper_alt_sig {
            let last = alt_sig_bytes.len() - 1;
            alt_sig_bytes[last] ^= 0xff;
        }

        // Extension 74: BIT STRING of the alt signature.
        let alt_sig_bitstring_der = BitString::from_bytes(&alt_sig_bytes).unwrap().to_der().unwrap();
        let ext74 = Extension {
            extn_id: ObjectIdentifier::from_str(ALT_SIG_VALUE_OID).unwrap(),
            critical: false,
            extn_value: der::asn1::OctetString::new(alt_sig_bitstring_der).unwrap(),
        };

        // Step 3: final TBS with all 3 extensions.
        let tbs_final = TbsCertificate {
            extensions: Some(vec![ext72, ext73, ext74]),
            ..tbs_for_alt
        };
        let tbs_final_der = tbs_final.to_der().unwrap();

        // Step 4: primary (ECDSA) signature over the FINAL TBS, and the
        // fully assembled + signed Certificate — self-signed (issuer ==
        // subject), so `validate.rs::validate_chain` can drive it
        // directly without any separate CA fixture.
        let ec_priv_h = super::super::helpers::find_handle_for_object(session, &ec_cka, crate::kmip30::ObjectType::PrivateKey)
            .unwrap()
            .unwrap();
        let primary_raw_sig = native::sign(session, ec_priv_h, softhsmrustv3::constants::CKM_ECDSA_SHA256, &tbs_final_der)
            .expect("EC primary sign");
        let primary_sig_der = super::super::certify::ecdsa_raw_to_der(&primary_raw_sig).expect("EC sig DER wrap");
        let cert = x509_cert::Certificate {
            tbs_certificate: tbs_final.clone(),
            signature_algorithm: ec_sig_alg,
            signature: BitString::from_bytes(&primary_sig_der).unwrap(),
        };
        let cert_der = cert.to_der().expect("assemble Catalyst certificate DER");

        (cert_der, tbs_final)
    }

    #[test]
    fn ordinary_cert_with_no_catalyst_extensions_is_none() {
        let (deps, _g) = deps_with_session();
        let session = deps.engine_session.unwrap();
        let (_der, tbs) = build_catalyst_tbs_and_sign(session, false);
        // Strip the extensions entirely — an ordinary, non-Catalyst TBS.
        let mut plain = tbs;
        plain.extensions = None;
        assert!(extract_alt_sig_fields(&plain).unwrap().is_none());
    }

    #[test]
    fn real_alt_signature_extracts_and_verifies() {
        let (deps, _g) = deps_with_session();
        let session = deps.engine_session.unwrap();
        let (_der, tbs) = build_catalyst_tbs_and_sign(session, false);

        let fields = extract_alt_sig_fields(&tbs).unwrap().expect("Catalyst extensions present");
        let tbs_minus_alt = tbs_minus_alt_sig_value(&tbs).unwrap();
        // tbs-minus-ext74 must have exactly 2 extensions (72, 73), not 3.
        let reparsed = TbsCertificate::from_der(&tbs_minus_alt).unwrap();
        assert_eq!(reparsed.extensions.as_ref().map(|e| e.len()), Some(2));

        let verdict = verify_alt_signature(&deps, &fields, &tbs_minus_alt).unwrap();
        assert_eq!(verdict, SpkiVerdict::Valid, "a real ML-DSA alt signature over the correct bytes must verify");
    }

    #[test]
    fn tampered_alt_signature_is_invalid() {
        let (deps, _g) = deps_with_session();
        let session = deps.engine_session.unwrap();
        let (_der, tbs) = build_catalyst_tbs_and_sign(session, true);

        let fields = extract_alt_sig_fields(&tbs).unwrap().expect("Catalyst extensions present");
        let tbs_minus_alt = tbs_minus_alt_sig_value(&tbs).unwrap();
        let verdict = verify_alt_signature(&deps, &fields, &tbs_minus_alt).unwrap();
        assert_eq!(verdict, SpkiVerdict::Invalid, "a tampered alt signature must never verify");
    }

    #[test]
    fn partial_catalyst_extensions_is_a_structural_error() {
        let (deps, _g) = deps_with_session();
        let session = deps.engine_session.unwrap();
        let (_der, tbs) = build_catalyst_tbs_and_sign(session, false);
        let mut partial = tbs;
        // Keep only ext72 — 73/74 missing.
        partial.extensions = partial.extensions.map(|exts| exts.into_iter().take(1).collect());
        let err = extract_alt_sig_fields(&partial).unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::InvalidField);
    }
}
