//! Host-side TEST manufacturing CA (owner decision 4).
//!
//! Its private key lives in this host-side struct, never in a token, and a
//! fresh root is generated per instance. Certificates it issues use only
//! `PQCTODAY EDUCATIONAL TEST` names and the documentation OID arc. It also
//! exposes deliberately malformed issuance helpers so negative tests can
//! build wrong-purpose, expired and substituted credentials.

use der::{Decode, Encode};
use spki07::SubjectPublicKeyInfoOwned;
use x509_cert::certificate::Certificate;
use x509_cert::request::CertReq;
use x509_cert::serial_number::SerialNumber;

use super::oids::Purpose;
use super::pki;
use crate::constants::*;

pub struct TestManufacturingCa {
    sk: Vec<u8>,
    root: Certificate,
    root_der: Vec<u8>,
    crl_number: u64,
    revoked: Vec<(SerialNumber, u64)>,
}

impl TestManufacturingCa {
    /// A fresh root valid from `now - 60` for ten years.
    pub fn new(now: u64) -> Result<Self, u32> {
        Self::new_with_validity(now.saturating_sub(60), now + 10 * 365 * 86_400)
    }

    pub fn new_with_validity(not_before: u64, not_after: u64) -> Result<Self, u32> {
        let (pk, sk) = super::mldsa65_keygen()?;
        let spki = spki_of(&crate::crypto::handlers::build_mldsa65_spki(&pk))?;
        let tag = super::hex(&super::random32()?[..4]);
        let nm = pki::name(&format!("{} Manufacturing Root {tag}", super::EDUCATIONAL_LABEL));
        let ski = pki::key_id(&spki);
        let tbs = pki::tbs_certificate(
            pki::random_serial()?,
            nm.clone(),
            nm,
            spki,
            not_before,
            not_after,
            pki::ca_extensions(1, &ski, None),
        );
        let sig = super::mldsa65_sign(&sk, &super::asn1::to_der(&tbs)?)?;
        let root_der = pki::assemble_certificate(tbs, &sig)?;
        let root = Certificate::from_der(&root_der).map_err(|_| CKR_DEVICE_ERROR)?;
        Ok(Self { sk, root, root_der, crl_number: 0, revoked: Vec::new() })
    }

    pub fn root_der(&self) -> &[u8] {
        &self.root_der
    }

    /// Issue a device-issuer certificate for a token's CSR, after checking
    /// the CSR's proof of possession and that it carries an ML-DSA-65 key.
    pub fn issue_device(&self, csr_der: &[u8], now: u64) -> Result<Vec<u8>, u32> {
        let spki = verify_csr(csr_der)?;
        self.issue_device_for_spki(spki, now.saturating_sub(60), now + 5 * 365 * 86_400)
    }

    /// Negative-test helper: issue a device certificate for any SPKI with any
    /// validity (no proof of possession).
    pub fn issue_device_for_spki(&self, spki: SubjectPublicKeyInfoOwned, not_before: u64, not_after: u64) -> Result<Vec<u8>, u32> {
        let tag = super::hex(&super::sha256(spki.subject_public_key.raw_bytes())[..4]);
        let ski = pki::key_id(&spki);
        let root_ski = pki::key_id(&self.root.tbs_certificate.subject_public_key_info);
        let tbs = pki::tbs_certificate(
            pki::random_serial()?,
            self.root.tbs_certificate.subject.clone(),
            pki::name(&format!("{} Device {tag}", super::EDUCATIONAL_LABEL)),
            spki,
            not_before,
            not_after,
            pki::ca_extensions(0, &ski, Some(&root_ski)),
        );
        let sig = super::mldsa65_sign(&self.sk, &super::asn1::to_der(&tbs)?)?;
        pki::assemble_certificate(tbs, &sig)
    }

    pub fn revoke(&mut self, cert_der: &[u8], at: u64) -> Result<(), u32> {
        let c = Certificate::from_der(cert_der).map_err(|_| CKR_DATA_INVALID)?;
        self.revoked.push((c.tbs_certificate.serial_number, at));
        Ok(())
    }

    /// Next root CRL (CRLNumber increments), current from `this_update`.
    pub fn crl(&mut self, this_update: u64, next_update: u64) -> Result<Vec<u8>, u32> {
        self.crl_number += 1;
        self.crl_with_number(self.crl_number, this_update, next_update)
    }

    /// Negative-test helper: a CRL with an arbitrary number.
    pub fn crl_with_number(&self, number: u64, this_update: u64, next_update: u64) -> Result<Vec<u8>, u32> {
        let tbs = pki::build_crl_tbs(&self.root, number, this_update, next_update, &self.revoked)
            .map_err(|_| CKR_DEVICE_ERROR)?;
        let sig = super::mldsa65_sign(&self.sk, &super::asn1::to_der(&tbs)?)?;
        pki::assemble_crl(tbs, &sig)
    }
}

impl TestManufacturingCa {
    /// Issue a replication admin-authority certificate for `spki` (admin
    /// addendum §1): a leaf directly under this root, EKU `.2.7`.
    pub fn issue_admin_authority(&self, spki: SubjectPublicKeyInfoOwned, now: u64) -> Result<Vec<u8>, u32> {
        let tag = super::hex(&super::sha256(spki.subject_public_key.raw_bytes())[..4]);
        let ski = pki::key_id(&spki);
        let root_ski = pki::key_id(&self.root.tbs_certificate.subject_public_key_info);
        let tbs = pki::tbs_certificate(
            pki::random_serial()?,
            self.root.tbs_certificate.subject.clone(),
            pki::name(&format!("{} Replication Admin Authority {tag}", super::EDUCATIONAL_LABEL)),
            spki,
            now.saturating_sub(60),
            now + 2 * 365 * 86_400,
            pki::admin_authority_extensions(&ski, &root_ski),
        );
        let sig = super::mldsa65_sign(&self.sk, &super::asn1::to_der(&tbs)?)?;
        pki::assemble_certificate(tbs, &sig)
    }
}

/// A host-side admin-authority key and its certificate (operator host, never
/// a board), for tests and the M12 courier.
pub struct AdminAuthorityKey {
    sk: Vec<u8>,
    pub cert_der: Vec<u8>,
}

impl AdminAuthorityKey {
    pub fn new(ca: &TestManufacturingCa, now: u64) -> Result<Self, u32> {
        let (pk, sk) = super::mldsa65_keygen()?;
        let spki = spki_of(&crate::crypto::handlers::build_mldsa65_spki(&pk))?;
        let cert_der = ca.issue_admin_authority(spki, now)?;
        Ok(Self { sk, cert_der })
    }

    /// `adminKeyID` = SHA-256(DER SPKI of the certificate).
    pub fn key_id(&self) -> [u8; 32] {
        let c = Certificate::from_der(&self.cert_der).expect("own certificate");
        super::sha256(&c.tbs_certificate.subject_public_key_info.to_der().expect("spki"))
    }

    /// ML-DSA-65, empty context.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, u32> {
        super::mldsa65_sign(&self.sk, msg)
    }
}

/// A host-side rogue "device issuer" (a key the token never held), for
/// negative tests: substituted keys and wrong-purpose leaves.
pub struct RogueIssuer {
    pub sk: Vec<u8>,
    pub cert: Certificate,
}

impl RogueIssuer {
    /// A device certificate issued by `ca` for a host-held key.
    pub fn new(ca: &TestManufacturingCa, now: u64) -> Result<Self, u32> {
        let (pk, sk) = super::mldsa65_keygen()?;
        let spki = spki_of(&crate::crypto::handlers::build_mldsa65_spki(&pk))?;
        let der = ca.issue_device_for_spki(spki, now.saturating_sub(60), now + 365 * 86_400)?;
        let cert = Certificate::from_der(&der).map_err(|_| CKR_DEVICE_ERROR)?;
        Ok(Self { sk, cert })
    }

    pub fn cert_der(&self) -> Vec<u8> {
        self.cert.to_der().expect("cert")
    }

    /// Issue a leaf for `spki` claiming `purpose` (no profile enforcement).
    pub fn issue_leaf(&self, purpose: Purpose, spki: SubjectPublicKeyInfoOwned, now: u64) -> Result<Vec<u8>, u32> {
        let ski = pki::key_id(&spki);
        let aki = pki::key_id(&self.cert.tbs_certificate.subject_public_key_info);
        let tbs = pki::tbs_certificate(
            pki::random_serial()?,
            self.cert.tbs_certificate.subject.clone(),
            pki::name(&format!("{} rogue {}", super::EDUCATIONAL_LABEL, purpose.label())),
            spki,
            now.saturating_sub(60),
            now + 365 * 86_400,
            pki::leaf_extensions(purpose, &ski, &aki),
        );
        let sig = super::mldsa65_sign(&self.sk, &super::asn1::to_der(&tbs)?)?;
        pki::assemble_certificate(tbs, &sig)
    }

    /// An empty, current CRL for this rogue issuer.
    pub fn crl(&self, number: u64, this_update: u64, next_update: u64) -> Result<Vec<u8>, u32> {
        let tbs = pki::build_crl_tbs(&self.cert, number, this_update, next_update, &[]).map_err(|_| CKR_DEVICE_ERROR)?;
        let sig = super::mldsa65_sign(&self.sk, &super::asn1::to_der(&tbs)?)?;
        pki::assemble_crl(tbs, &sig)
    }
}

pub fn spki_of(der: &[u8]) -> Result<SubjectPublicKeyInfoOwned, u32> {
    SubjectPublicKeyInfoOwned::from_der(der).map_err(|_| CKR_DEVICE_ERROR)
}

/// Verify a PKCS#10 request's self-signature (proof of possession) and
/// return its ML-DSA-65 SPKI.
pub fn verify_csr(csr_der: &[u8]) -> Result<SubjectPublicKeyInfoOwned, u32> {
    let csr: CertReq = super::asn1::decode_strict(csr_der, pki::MAX_CERT_DER)?;
    if csr.algorithm != pki::ml_dsa_65_alg() {
        return Err(CKR_SIGNATURE_INVALID);
    }
    let spki = csr.info.public_key.clone();
    if spki.algorithm != pki::ml_dsa_65_alg() || spki.subject_public_key.raw_bytes().len() != 1952 {
        return Err(CKR_SIGNATURE_INVALID);
    }
    let info = csr.info.to_der().map_err(|_| CKR_DATA_INVALID)?;
    if !super::mldsa65_verify(spki.subject_public_key.raw_bytes(), &info, csr.signature.raw_bytes()) {
        return Err(CKR_SIGNATURE_INVALID);
    }
    Ok(spki)
}
