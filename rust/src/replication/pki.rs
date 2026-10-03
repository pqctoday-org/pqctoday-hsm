//! Certificate and CRL profiles (spec §4.2) and chain validation.
//!
//! Pure functions over DER plus caller-supplied trust inputs, shared by the
//! engine (whose trust inputs are its enrolled records) and the host-side
//! verifier (whose trust inputs are bytes it was handed). Every failure is a
//! [`Reject`] with a reason for the audit log; the public return code is
//! chosen by the caller (review K0B-R-13).

use std::str::FromStr;
use std::time::Duration;

use der::asn1::{BitString, OctetString};
use der::{Decode, Encode};
use spki07::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::crl::{CertificateList, RevokedCert, TbsCertList};
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, CrlNumber, ExtendedKeyUsage, KeyUsage, KeyUsages,
    SubjectKeyIdentifier,
};
use x509_cert::ext::Extension;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};

use super::oids::{self, Purpose};
use super::Profile;

pub const MAX_CERT_DER: usize = 8 * 1024;

/// A refusal reason (audit only; never returned to a caller).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reject(pub &'static str);

pub type PkiResult<T> = Result<T, Reject>;

fn r<T>(why: &'static str) -> PkiResult<T> {
    Err(Reject(why))
}

pub fn ml_dsa_65_alg() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned { oid: oids::ML_DSA_65, parameters: None }
}

pub fn to_time(unix: u64) -> Time {
    Time::try_from(std::time::UNIX_EPOCH + Duration::from_secs(unix)).expect("representable time")
}

pub fn time_secs(t: &Time) -> u64 {
    t.to_unix_duration().as_secs()
}

/// Device identifier (spec edit E-03, reviews K0B-R-03/R-10):
/// SHA-256 over the DER SubjectPublicKeyInfo of the device certificate.
pub fn device_id_of(device_cert: &Certificate) -> [u8; 32] {
    let spki = device_cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .expect("SPKI re-encodes");
    super::sha256(&spki)
}

/// Key identifier: first 20 bytes of SHA-256 over the subjectPublicKey bits.
pub fn key_id(spki: &SubjectPublicKeyInfoOwned) -> Vec<u8> {
    super::sha256(spki.subject_public_key.raw_bytes())[..20].to_vec()
}

/// SHA-384 over a certificate's DER SubjectPublicKeyInfo (`recipientKeyHash`).
pub fn spki_hash(cert: &Certificate) -> [u8; 48] {
    super::sha384(&cert.tbs_certificate.subject_public_key_info.to_der().expect("SPKI"))
}

/// Fresh positive, non-zero, unpredictable 128-bit serial (spec §4.2).
pub fn random_serial() -> Result<SerialNumber, u32> {
    let mut b = super::random32()?;
    b[0] &= 0x7f;
    b[0] |= 0x40; // non-zero and minimal encoding fixed at 16 bytes
    SerialNumber::new(&b[..16]).map_err(|_| crate::constants::CKR_DEVICE_ERROR)
}

fn ext<T: const_oid::AssociatedOid + Encode>(critical: bool, value: &T) -> Extension {
    Extension {
        extn_id: T::OID,
        critical,
        extn_value: OctetString::new(value.to_der().expect("extension DER")).expect("ext"),
    }
}

/// Extensions for a CA certificate (`path_len` 1 = test root, 0 = device issuer).
pub fn ca_extensions(path_len: u8, ski: &[u8], aki: Option<&[u8]>) -> Vec<Extension> {
    let mut v = vec![
        ext(true, &BasicConstraints { ca: true, path_len_constraint: Some(path_len) }),
        ext(true, &KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign)),
        ext(false, &SubjectKeyIdentifier(OctetString::new(ski.to_vec()).expect("ski"))),
    ];
    if let Some(a) = aki {
        v.push(ext(
            false,
            &AuthorityKeyIdentifier {
                key_identifier: Some(OctetString::new(a.to_vec()).expect("aki")),
                ..Default::default()
            },
        ));
    }
    v
}

/// Extensions for a function leaf of `purpose` (spec §4.2 table).
pub fn leaf_extensions(purpose: Purpose, ski: &[u8], aki: &[u8]) -> Vec<Extension> {
    let ku = if purpose.is_kem() {
        KeyUsage(KeyUsages::KeyEncipherment.into())
    } else {
        KeyUsage(KeyUsages::DigitalSignature.into())
    };
    vec![
        ext(true, &BasicConstraints { ca: false, path_len_constraint: None }),
        ext(true, &ku),
        ext(true, &ExtendedKeyUsage(vec![purpose.oid()])),
        ext(false, &SubjectKeyIdentifier(OctetString::new(ski.to_vec()).expect("ski"))),
        ext(
            false,
            &AuthorityKeyIdentifier {
                key_identifier: Some(OctetString::new(aki.to_vec()).expect("aki")),
                ..Default::default()
            },
        ),
    ]
}

pub fn tbs_certificate(
    serial: SerialNumber,
    issuer: Name,
    subject: Name,
    spki: SubjectPublicKeyInfoOwned,
    not_before: u64,
    not_after: u64,
    extensions: Vec<Extension>,
) -> TbsCertificate {
    TbsCertificate {
        version: Version::V3,
        serial_number: serial,
        signature: ml_dsa_65_alg(),
        issuer,
        validity: Validity { not_before: to_time(not_before), not_after: to_time(not_after) },
        subject,
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(extensions),
    }
}

pub fn assemble_certificate(tbs: TbsCertificate, signature: &[u8]) -> Result<Vec<u8>, u32> {
    let c = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: ml_dsa_65_alg(),
        signature: BitString::from_bytes(signature).map_err(|_| crate::constants::CKR_DEVICE_ERROR)?,
    };
    super::asn1::to_der(&c)
}

pub fn name(cn: &str) -> Name {
    Name::from_str(&format!("CN={cn}")).expect("static name")
}

pub fn parse_cert(der: &[u8]) -> PkiResult<Certificate> {
    super::asn1::decode_strict::<Certificate>(der, MAX_CERT_DER).map_err(|_| Reject("certificate DER"))
}

fn spki_key<'a>(spki: &'a SubjectPublicKeyInfoOwned, alg: &der::oid::ObjectIdentifier, len: usize) -> PkiResult<&'a [u8]> {
    if &spki.algorithm.oid != alg || spki.algorithm.parameters.is_some() {
        return r("SPKI algorithm");
    }
    let k = spki.subject_public_key.raw_bytes();
    if k.len() != len || spki.subject_public_key.unused_bits() != 0 {
        return r("SPKI key length");
    }
    Ok(k)
}

pub fn mldsa65_public(cert: &Certificate) -> PkiResult<&[u8]> {
    spki_key(&cert.tbs_certificate.subject_public_key_info, &oids::ML_DSA_65, 1952)
}

pub fn mlkem768_public(cert: &Certificate) -> PkiResult<&[u8]> {
    spki_key(&cert.tbs_certificate.subject_public_key_info, &oids::ML_KEM_768, 1184)
}

/// Verify `cert`'s ML-DSA-65 signature under `issuer_pk`.
fn verify_signed(cert: &Certificate, issuer_pk: &[u8]) -> PkiResult<()> {
    if cert.signature_algorithm != ml_dsa_65_alg() || cert.tbs_certificate.signature != ml_dsa_65_alg() {
        return r("signature algorithm");
    }
    let tbs = cert.tbs_certificate.to_der().map_err(|_| Reject("tbs DER"))?;
    if cert.signature.unused_bits() != 0 || !super::mldsa65_verify(issuer_pk, &tbs, cert.signature.raw_bytes()) {
        return r("certificate signature");
    }
    Ok(())
}

struct Exts {
    bc: Option<(bool, BasicConstraints)>,
    ku: Option<(bool, KeyUsage)>,
    eku: Option<(bool, ExtendedKeyUsage)>,
    ski: Option<Vec<u8>>,
    aki: Option<Vec<u8>>,
}

/// Extract the profile extensions; any unrecognised CRITICAL extension, any
/// duplicate, and (for non-educational validators) any documentation-arc OID
/// is refused.
fn profile_exts(cert: &Certificate, profile: Profile) -> PkiResult<Exts> {
    use const_oid::AssociatedOid;
    let mut e = Exts { bc: None, ku: None, eku: None, ski: None, aki: None };
    let mut seen = Vec::new();
    for x in cert.tbs_certificate.extensions.as_deref().unwrap_or(&[]) {
        if seen.contains(&x.extn_id) {
            return r("duplicate extension");
        }
        seen.push(x.extn_id);
        let v = x.extn_value.as_bytes();
        if x.extn_id == BasicConstraints::OID {
            e.bc = Some((x.critical, BasicConstraints::from_der(v).map_err(|_| Reject("bc"))?));
        } else if x.extn_id == KeyUsage::OID {
            e.ku = Some((x.critical, KeyUsage::from_der(v).map_err(|_| Reject("ku"))?));
        } else if x.extn_id == ExtendedKeyUsage::OID {
            let eku = ExtendedKeyUsage::from_der(v).map_err(|_| Reject("eku"))?;
            if profile != Profile::Educational && eku.0.iter().any(oids::is_documentation_arc) {
                return r("documentation OID outside educational profile");
            }
            e.eku = Some((x.critical, eku));
        } else if x.extn_id == SubjectKeyIdentifier::OID {
            e.ski = Some(SubjectKeyIdentifier::from_der(v).map_err(|_| Reject("ski"))?.0.as_bytes().to_vec());
        } else if x.extn_id == AuthorityKeyIdentifier::OID {
            let aki = AuthorityKeyIdentifier::from_der(v).map_err(|_| Reject("aki"))?;
            e.aki = aki.key_identifier.map(|k| k.as_bytes().to_vec());
        } else if x.critical {
            return r("unrecognised critical extension");
        }
    }
    Ok(e)
}

fn check_validity(cert: &Certificate, now: u64) -> PkiResult<()> {
    let v = &cert.tbs_certificate.validity;
    if now < time_secs(&v.not_before) || now > time_secs(&v.not_after) {
        return r("certificate not valid at host time");
    }
    Ok(())
}

fn check_serial(cert: &Certificate) -> PkiResult<()> {
    let s = cert.tbs_certificate.serial_number.as_bytes();
    if s.is_empty() || s.iter().all(|b| *b == 0) || s[0] & 0x80 != 0 {
        return r("serial");
    }
    Ok(())
}

/// Validate a test manufacturing root: self-issued, self-signed ML-DSA-65,
/// `cA=TRUE pathLen=1`, critical KU exactly keyCertSign|cRLSign.
pub fn validate_root(root: &Certificate, now: u64, profile: Profile) -> PkiResult<()> {
    if root.tbs_certificate.version != Version::V3 {
        return r("root version");
    }
    check_serial(root)?;
    let pk = mldsa65_public(root)?;
    let e = profile_exts(root, profile)?;
    match e.bc {
        Some((true, BasicConstraints { ca: true, path_len_constraint: Some(1) })) => {}
        _ => return r("root basic constraints"),
    }
    match e.ku {
        Some((true, ku)) if ku == KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign) => {}
        _ => return r("root key usage"),
    }
    if e.eku.is_some() || e.ski.is_none() {
        return r("root extensions");
    }
    if root.tbs_certificate.issuer != root.tbs_certificate.subject {
        return r("root not self-issued");
    }
    check_validity(root, now)?;
    verify_signed(root, pk)
}

/// Validate a device-issuer certificate directly under `root`.
pub fn validate_device(device: &Certificate, root: &Certificate, now: u64, profile: Profile) -> PkiResult<()> {
    if device.tbs_certificate.version != Version::V3 {
        return r("device version");
    }
    check_serial(device)?;
    mldsa65_public(device)?;
    let e = profile_exts(device, profile)?;
    match e.bc {
        Some((true, BasicConstraints { ca: true, path_len_constraint: Some(0) })) => {}
        _ => return r("device basic constraints"),
    }
    match e.ku {
        Some((true, ku)) if ku == KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign) => {}
        _ => return r("device key usage"),
    }
    if e.eku.is_some() {
        return r("device carries an EKU");
    }
    let root_e = profile_exts(root, profile)?;
    if device.tbs_certificate.issuer != root.tbs_certificate.subject || e.aki != root_e.ski || e.ski.is_none() {
        return r("device issuer/authority identifier");
    }
    check_validity(device, now)?;
    verify_signed(device, mldsa65_public(root)?)
}

/// Validate a function leaf of `purpose` directly under `device`.
pub fn validate_leaf(leaf: &Certificate, device: &Certificate, purpose: Purpose, now: u64, profile: Profile) -> PkiResult<()> {
    if purpose == Purpose::DeviceIssuer {
        return r("device issuer is not a leaf");
    }
    if leaf.tbs_certificate.version != Version::V3 {
        return r("leaf version");
    }
    check_serial(leaf)?;
    if purpose.is_kem() {
        mlkem768_public(leaf)?;
    } else {
        mldsa65_public(leaf)?;
    }
    let e = profile_exts(leaf, profile)?;
    match e.bc {
        Some((true, BasicConstraints { ca: false, path_len_constraint: None })) => {}
        _ => return r("leaf basic constraints"),
    }
    let want_ku = if purpose.is_kem() {
        KeyUsage(KeyUsages::KeyEncipherment.into())
    } else {
        KeyUsage(KeyUsages::DigitalSignature.into())
    };
    match e.ku {
        Some((true, ku)) if ku == want_ku => {}
        _ => return r("leaf key usage"),
    }
    match &e.eku {
        Some((true, eku)) if eku.0 == vec![purpose.oid()] => {}
        _ => return r("leaf purpose"),
    }
    let dev_e = profile_exts(device, profile)?;
    if leaf.tbs_certificate.issuer != device.tbs_certificate.subject || e.aki != dev_e.ski || e.ski.is_none() {
        return r("leaf issuer/authority identifier");
    }
    check_validity(leaf, now)?;
    verify_signed(leaf, mldsa65_public(device)?)
}

// ── CRLs (spec §4.2 revocation; owner decision 5) ──────────────────────────

/// A verified CRL: its issuer key id, number, next update and revoked serials.
#[derive(Clone, Debug)]
pub struct VerifiedCrl {
    pub issuer_key_id: Vec<u8>,
    pub number: u64,
    pub this_update: u64,
    pub next_update: u64,
    pub revoked: Vec<Vec<u8>>,
}

pub fn build_crl_tbs(
    issuer: &Certificate,
    number: u64,
    this_update: u64,
    next_update: u64,
    revoked: &[(SerialNumber, u64)],
) -> PkiResult<TbsCertList> {
    let ski = profile_exts(issuer, Profile::Educational)?.ski.ok_or(Reject("issuer SKI"))?;
    let num = der::asn1::Uint::new(&number.to_be_bytes()).map_err(|_| Reject("crl number"))?;
    Ok(TbsCertList {
        version: Version::V2,
        signature: ml_dsa_65_alg(),
        issuer: issuer.tbs_certificate.subject.clone(),
        this_update: to_time(this_update),
        next_update: Some(to_time(next_update)),
        revoked_certificates: if revoked.is_empty() {
            None
        } else {
            Some(
                revoked
                    .iter()
                    .map(|(s, at)| RevokedCert { serial_number: s.clone(), revocation_date: to_time(*at), crl_entry_extensions: None })
                    .collect(),
            )
        },
        crl_extensions: Some(vec![
            ext(false, &CrlNumber(num)),
            ext(
                false,
                &AuthorityKeyIdentifier {
                    key_identifier: Some(OctetString::new(ski).map_err(|_| Reject("aki"))?),
                    ..Default::default()
                },
            ),
        ]),
    })
}

pub fn assemble_crl(tbs: TbsCertList, signature: &[u8]) -> Result<Vec<u8>, u32> {
    let c = CertificateList {
        tbs_cert_list: tbs,
        signature_algorithm: ml_dsa_65_alg(),
        signature: BitString::from_bytes(signature).map_err(|_| crate::constants::CKR_DEVICE_ERROR)?,
    };
    super::asn1::to_der(&c)
}

/// Verify a CRL issued by `issuer` and current at `now`.
pub fn verify_crl(der: &[u8], issuer: &Certificate, now: u64) -> PkiResult<VerifiedCrl> {
    use const_oid::AssociatedOid;
    let crl: CertificateList = super::asn1::decode_strict(der, super::records::MAX_CRL_DER).map_err(|_| Reject("CRL DER"))?;
    let t = &crl.tbs_cert_list;
    if t.version != Version::V2 || t.signature != ml_dsa_65_alg() || crl.signature_algorithm != ml_dsa_65_alg() {
        return r("CRL algorithm/version");
    }
    if t.issuer != issuer.tbs_certificate.subject {
        return r("CRL issuer name");
    }
    let mut number = None;
    let mut aki = None;
    for x in t.crl_extensions.as_deref().unwrap_or(&[]) {
        if x.extn_id == CrlNumber::OID {
            let n = CrlNumber::from_der(x.extn_value.as_bytes()).map_err(|_| Reject("crl number"))?;
            let b = n.0.as_bytes();
            if b.len() > 8 {
                return r("crl number size");
            }
            let mut buf = [0u8; 8];
            buf[8 - b.len()..].copy_from_slice(b);
            number = Some(u64::from_be_bytes(buf));
        } else if x.extn_id == AuthorityKeyIdentifier::OID {
            aki = AuthorityKeyIdentifier::from_der(x.extn_value.as_bytes())
                .map_err(|_| Reject("crl aki"))?
                .key_identifier
                .map(|k| k.as_bytes().to_vec());
        } else if x.critical {
            return r("unrecognised critical CRL extension");
        }
    }
    let issuer_ski = profile_exts(issuer, Profile::Educational)?.ski;
    if aki.is_none() || aki != issuer_ski {
        return r("CRL authority key identifier");
    }
    let number = number.ok_or(Reject("CRL number missing"))?;
    let this_update = time_secs(&t.this_update);
    let next_update = t.next_update.as_ref().map(time_secs).ok_or(Reject("nextUpdate missing"))?;
    if now < this_update || now >= next_update {
        return r("CRL not current at host time");
    }
    let entries = t.revoked_certificates.as_deref().unwrap_or(&[]);
    if entries.len() > super::records::MAX_CRL_ENTRIES {
        return r("CRL too many entries");
    }
    let tbs = t.to_der().map_err(|_| Reject("crl tbs"))?;
    if crl.signature.unused_bits() != 0 || !super::mldsa65_verify(mldsa65_public(issuer)?, &tbs, crl.signature.raw_bytes()) {
        return r("CRL signature");
    }
    Ok(VerifiedCrl {
        issuer_key_id: issuer_ski.unwrap_or_default(),
        number,
        this_update,
        next_update,
        revoked: entries.iter().map(|e| e.serial_number.as_bytes().to_vec()).collect(),
    })
}

// ── Chains (spec §4.2; review K0B-R-03) ────────────────────────────────────

/// Trust inputs for one validation: enrolled roots and every CRL the
/// verifier holds (root CRLs and peer device-issuer CRLs).
#[derive(Clone, Debug, Default)]
pub struct TrustInputs {
    pub roots: Vec<Vec<u8>>,
    pub crls: Vec<Vec<u8>>,
}

/// A validated `[leaf, device]` chain.
#[derive(Clone, Debug)]
pub struct ValidChain {
    pub leaf: Certificate,
    pub device: Certificate,
    pub device_id: [u8; 32],
}

/// Find a current CRL issued by `issuer` among `crls` (fail closed: none
/// current means refusal). The highest CRL number wins.
fn current_crl(crls: &[Vec<u8>], issuer: &Certificate, now: u64) -> PkiResult<VerifiedCrl> {
    crls.iter()
        .filter_map(|der| verify_crl(der, issuer, now).ok())
        .max_by_key(|c| c.number)
        .ok_or(Reject("no current CRL for issuer"))
}

/// Validate a device certificate against the trust inputs: chains to an
/// enrolled root and is not revoked on that root's current CRL.
pub fn validate_device_trusted(device: &Certificate, trust: &TrustInputs, now: u64, profile: Profile) -> PkiResult<Certificate> {
    for root_der in &trust.roots {
        let Ok(root) = parse_cert(root_der) else { continue };
        if validate_root(&root, now, profile).is_err() || validate_device(device, &root, now, profile).is_err() {
            continue;
        }
        let crl = current_crl(&trust.crls, &root, now)?;
        if crl.revoked.iter().any(|s| s.as_slice() == device.tbs_certificate.serial_number.as_bytes()) {
            return r("device certificate revoked");
        }
        return Ok(root);
    }
    r("device does not chain to an enrolled root")
}

/// Validate a protocol chain `[leaf, device]` for `purpose`.
pub fn validate_chain(chain: &[Certificate], purpose: Purpose, trust: &TrustInputs, now: u64, profile: Profile) -> PkiResult<ValidChain> {
    if chain.len() != 2 {
        return r("chain length");
    }
    let (leaf, device) = (&chain[0], &chain[1]);
    let total = leaf.to_der().map(|d| d.len()).unwrap_or(usize::MAX)
        + device.to_der().map(|d| d.len()).unwrap_or(usize::MAX);
    if total > 16 * 1024 {
        return r("chain size");
    }
    validate_device_trusted(device, trust, now, profile)?;
    validate_leaf(leaf, device, purpose, now, profile)?;
    let crl = current_crl(&trust.crls, device, now)?;
    if crl.revoked.iter().any(|s| s.as_slice() == leaf.tbs_certificate.serial_number.as_bytes()) {
        return r("function certificate revoked");
    }
    Ok(ValidChain { leaf: leaf.clone(), device: device.clone(), device_id: device_id_of(device) })
}

/// Encode a chain as the spec's `SEQUENCE SIZE(2) OF Certificate` element list.
pub fn chain_from_ders(ders: &[Vec<u8>]) -> PkiResult<Vec<Certificate>> {
    ders.iter().map(|d| parse_cert(d)).collect()
}
