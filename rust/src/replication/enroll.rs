//! K2 — device enrollment, function issuance, revocation and policy
//! enrollment (plan R1; spec §4).
//!
//! The SO drives every operation here; a user session gets
//! `CKR_USER_TYPE_INVALID`. Enrollment is append-only: a token enrolls one
//! device identity once, and re-enrollment, CRL rollback and partial writes
//! are refused rather than silently replacing state.
//!
//! Return codes (design note §C): bad DER → `CKR_DATA_INVALID`; a credential
//! that fails its profile, chain, signature, validity or revocation check →
//! `CKR_SIGNATURE_INVALID`; an operation out of sequence or a weakening
//! replacement → `CKR_ACTION_PROHIBITED`; a full table → `CKR_DEVICE_MEMORY`.

use der::{Decode, Encode};
use x509_cert::certificate::Certificate;
use x509_cert::request::{CertReq, CertReqInfo, Version as CsrVersion};

use super::asn1::{self, EnrollmentRecord};
use super::oids::Purpose;
use super::pki::{self, TrustInputs};
use super::records::{self, *};
use super::{now_unix, oplog_event, require_profile, require_so, Profile};
use crate::constants::*;
use crate::crypto::handlers::Attributes;

fn enrollment(slot: u32) -> Option<(u32, EnrollmentRecord)> {
    records::list(slot, ROLE_ENROLLMENT)
        .into_iter()
        .next()
        .and_then(|(h, a)| EnrollmentRecord::from_der(records::record_bytes(&a)).ok().map(|r| (h, r)))
}

fn enrollment_state(slot: u32) -> u8 {
    enrollment(slot).map(|(_, r)| r.state).unwrap_or(0)
}

fn sig_invalid<T>(_: pki::Reject) -> Result<T, u32> {
    Err(CKR_SIGNATURE_INVALID)
}

/// Trust inputs from this slot's enrolled state.
pub fn trust_inputs(slot: u32) -> TrustInputs {
    TrustInputs {
        roots: records::trust_anchors(slot),
        crls: records::crls(slot).into_iter().map(|(_, _, der)| der).collect(),
    }
}

/// Step 1: generate the device identity key in the token and return a
/// PKCS#10 request signed by it (proof of possession).
pub fn begin_device_enrollment(so_session: u32) -> Result<Vec<u8>, u32> {
    require_profile()?;
    let slot = require_so(so_session)?;
    if enrollment_state(slot) != 0 || !records::list(slot, ROLE_DEVICE_KEY).is_empty() {
        return Err(CKR_ACTION_PROHIBITED);
    }
    let (pk, sk) = super::mldsa65_keygen()?;
    let spki_der = crate::crypto::handlers::build_mldsa65_spki(&pk);
    let spki = super::test_ca::spki_of(&spki_der)?;
    let tag = super::hex(&super::sha256(&pk)[..4]);
    let info = CertReqInfo {
        version: CsrVersion::V1,
        subject: pki::name(&format!("{} Device {tag}", super::EDUCATIONAL_LABEL)),
        public_key: spki,
        attributes: Default::default(),
    };
    let sig = super::mldsa65_sign(&sk, &asn1::to_der(&info)?)?;
    let csr = asn1::to_der(&CertReq {
        info,
        algorithm: pki::ml_dsa_65_alg(),
        signature: der::asn1::BitString::from_bytes(&sig).map_err(|_| CKR_DEVICE_ERROR)?,
    })?;
    let (pubk, prv) = records::new_function_key_pair(Purpose::DeviceIssuer, pk, sk);
    let rec = asn1::to_der(&EnrollmentRecord { state: 1, csr: asn1::octets(&csr), crl_number: 0 })?;
    let enrollment = records::new_record(ROLE_ENROLLMENT, CKO_DATA, "device enrollment", Vec::new(), rec, false);
    crate::state::commit_objects_atomically(so_session, vec![pubk, prv, enrollment], Vec::new())?;
    oplog_event("enroll_begin", slot, &[("device_spki_sha256", super::hex(&super::sha256(&spki_der)))]);
    Ok(csr)
}

/// Step 2: enroll the manufacturing trust anchor, the device certificate it
/// issued for this token's own key, and the root's current CRL.
pub fn complete_device_enrollment(so_session: u32, root_der: &[u8], device_cert_der: &[u8], root_crl_der: &[u8]) -> Result<(), u32> {
    require_profile()?;
    let slot = require_so(so_session)?;
    let (enroll_h, rec) = enrollment(slot).ok_or(CKR_ACTION_PROHIBITED)?;
    if rec.state != 1 {
        return Err(CKR_ACTION_PROHIBITED);
    }
    let now = now_unix();
    let root = pki::parse_cert(root_der).or_else(|_| Err(CKR_DATA_INVALID))?;
    let device = pki::parse_cert(device_cert_der).or_else(|_| Err(CKR_DATA_INVALID))?;
    pki::validate_root(&root, now, Profile::Educational).or_else(sig_invalid)?;
    pki::validate_device(&device, &root, now, Profile::Educational).or_else(sig_invalid)?;
    // Key substitution: the certificate must certify THIS token's device key.
    let (_, dev_pub) = records::function_public(slot, Purpose::DeviceIssuer).ok_or(CKR_DEVICE_ERROR)?;
    let ours = dev_pub.get(&CKA_PUBLIC_KEY_INFO).cloned().unwrap_or_default();
    if device.tbs_certificate.subject_public_key_info.to_der().ok() != Some(ours) {
        return Err(CKR_SIGNATURE_INVALID);
    }
    let crl = pki::verify_crl(root_crl_der, &root, now).or_else(sig_invalid)?;
    if crl.revoked.iter().any(|s| s.as_slice() == device.tbs_certificate.serial_number.as_bytes()) {
        return Err(CKR_SIGNATURE_INVALID);
    }
    let mut anchor = records::new_record(ROLE_TRUST_ANCHOR, CKO_CERTIFICATE, "manufacturing trust anchor", root_der.to_vec(), Vec::new(), false);
    crate::state::store_bool(&mut anchor, CKA_TRUSTED, true);
    let mut dev_cert = records::new_record(ROLE_CERT, CKO_CERTIFICATE, "device issuer certificate", device_cert_der.to_vec(), Vec::new(), false);
    dev_cert.insert(CKA_PQCTODAY_FUNCTION_PURPOSE, vec![Purpose::DeviceIssuer as u8]);
    let crl_rec = records::new_record(ROLE_CRL, CKO_DATA, "manufacturing root CRL", root_crl_der.to_vec(), crl.issuer_key_id.clone(), false);
    let new_rec = asn1::to_der(&EnrollmentRecord { state: 2, ..rec })?;
    crate::state::commit_objects_atomically(
        so_session,
        vec![anchor, dev_cert, crl_rec],
        vec![(enroll_h, vec![(CKA_PRIV_REPL_RECORD, new_rec)])],
    )?;
    oplog_event("enroll_complete", slot, &[("device_id", super::hex(&pki::device_id_of(&device)))]);
    Ok(())
}

/// Constrained issuance (`CKM_PQCTODAY_ISSUE_FUNCTION_CERTIFICATE`
/// semantics): the device issuer checks that the TBS is exactly the approved
/// profile for `purpose` before it signs.
fn issue_function_cert(slot: u32, device: &Certificate, purpose: Purpose, spki_der: &[u8], now: u64) -> Result<Vec<u8>, u32> {
    let spki = super::test_ca::spki_of(spki_der)?;
    let ski = pki::key_id(&spki);
    let aki = pki::key_id(&device.tbs_certificate.subject_public_key_info);
    let not_after = pki::time_secs(&device.tbs_certificate.validity.not_after).min(now + 2 * 365 * 86_400);
    let tbs = pki::tbs_certificate(
        pki::random_serial()?,
        device.tbs_certificate.subject.clone(),
        pki::name(&format!("{} {} {}", super::EDUCATIONAL_LABEL, purpose.label(), super::hex(&pki::device_id_of(device)[..4]))),
        spki,
        now.saturating_sub(60),
        not_after,
        pki::leaf_extensions(purpose, &ski, &aki),
    );
    // Profile gate before signing.
    if tbs.issuer != device.tbs_certificate.subject
        || tbs.extensions.as_deref() != Some(&pki::leaf_extensions(purpose, &ski, &aki)[..])
        || tbs.signature != pki::ml_dsa_65_alg()
    {
        return Err(CKR_DEVICE_ERROR);
    }
    let (_, device_sk) = records::function_secret(slot, Purpose::DeviceIssuer).ok_or(CKR_DEVICE_ERROR)?;
    let sig = super::mldsa65_sign(&device_sk, &asn1::to_der(&tbs)?)?;
    let der = pki::assemble_certificate(tbs, &sig)?;
    let leaf = pki::parse_cert(&der).or_else(|_| Err(CKR_DEVICE_ERROR))?;
    pki::validate_leaf(&leaf, device, purpose, now, Profile::Educational).or_else(|_| Err(CKR_DEVICE_ERROR))?;
    Ok(der)
}

/// Step 3: generate the five function keys in the token, certify each under
/// the device issuer with exactly one purpose, and publish the device
/// issuer's first (empty) CRL for them.
pub fn issue_function_certificates(so_session: u32) -> Result<(), u32> {
    require_profile()?;
    let slot = require_so(so_session)?;
    let (enroll_h, rec) = enrollment(slot).ok_or(CKR_ACTION_PROHIBITED)?;
    if rec.state != 2 {
        return Err(CKR_ACTION_PROHIBITED);
    }
    let now = now_unix();
    let device = pki::parse_cert(&records::certificate(slot, Purpose::DeviceIssuer).ok_or(CKR_DEVICE_ERROR)?)
        .or_else(|_| Err(CKR_DEVICE_ERROR))?;
    let mut new_objects: Vec<Attributes> = Vec::new();
    for purpose in Purpose::LEAVES {
        let (pk, sk) = if purpose.is_kem() { super::mlkem768_keygen()? } else { super::mldsa65_keygen()? };
        let (pubk, prv) = records::new_function_key_pair(purpose, pk, sk);
        let spki_der = pubk.get(&CKA_PUBLIC_KEY_INFO).cloned().ok_or(CKR_DEVICE_ERROR)?;
        let cert = issue_function_cert(slot, &device, purpose, &spki_der, now)?;
        let mut cert_rec = records::new_record(ROLE_CERT, CKO_CERTIFICATE, &format!("{} certificate", purpose.label()), cert, Vec::new(), false);
        cert_rec.insert(CKA_PQCTODAY_FUNCTION_PURPOSE, vec![purpose as u8]);
        new_objects.extend([pubk, prv, cert_rec]);
    }
    let crl = sign_device_crl(slot, &device, 1, now, now + 30 * 86_400, &[])?;
    let ski = pki::key_id(&device.tbs_certificate.subject_public_key_info);
    new_objects.push(records::new_record(ROLE_CRL, CKO_DATA, "device issuer CRL", crl, ski, false));
    let new_rec = asn1::to_der(&EnrollmentRecord { state: 3, crl_number: 1, ..rec })?;
    crate::state::commit_objects_atomically(so_session, new_objects, vec![(enroll_h, vec![(CKA_PRIV_REPL_RECORD, new_rec)])])?;
    oplog_event("functions_issued", slot, &[("device_id", super::hex(&pki::device_id_of(&device)))]);
    Ok(())
}

/// Rotate the recovery-recipient key (plan R3.5). The new key is certified
/// by the same device issuer — the continuity proof is that chain. The old
/// key, its public half and its certificate are retained as RETIRED: new
/// requests name only the new key, while packages already sealed to the old
/// key (an offline backup in transit) still import. Revoking the old
/// certificate afterwards is a separate, explicit `issue_device_crl` step.
pub fn rotate_recovery_key(so_session: u32) -> Result<(), u32> {
    require_profile()?;
    let slot = require_so(so_session)?;
    if enrollment_state(slot) != 3 {
        return Err(CKR_ACTION_PROHIBITED);
    }
    let now = now_unix();
    let device = pki::parse_cert(&records::certificate(slot, Purpose::DeviceIssuer).ok_or(CKR_DEVICE_ERROR)?)
        .or_else(|_| Err(CKR_DEVICE_ERROR))?;
    let p = Purpose::RecoveryRecipient;
    let mut retire = Vec::new();
    for role in [ROLE_FUNCTION_KEY, ROLE_FUNCTION_PUBLIC, ROLE_CERT] {
        for (h, a) in records::list(slot, role) {
            if records::purpose_of(&a) == Some(p) && !records::is_retired(&a) {
                retire.push((h, vec![(CKA_PRIV_REPL_RECORD, records::RETIRED.to_vec())]));
            }
        }
    }
    let (pk, sk) = super::mlkem768_keygen()?;
    let (pubk, prv) = records::new_function_key_pair(p, pk, sk);
    let spki_der = pubk.get(&CKA_PUBLIC_KEY_INFO).cloned().ok_or(CKR_DEVICE_ERROR)?;
    let cert = issue_function_cert(slot, &device, p, &spki_der, now)?;
    let mut cert_rec = records::new_record(ROLE_CERT, CKO_CERTIFICATE, "recovery recipient certificate (rotated)", cert, Vec::new(), false);
    cert_rec.insert(CKA_PQCTODAY_FUNCTION_PURPOSE, vec![p as u8]);
    crate::state::commit_objects_atomically(so_session, vec![pubk, prv, cert_rec], retire)?;
    oplog_event("recovery_rotated", slot, &[("new_spki_sha384", super::hex(&super::sha384(&spki_der)))]);
    Ok(())
}

fn sign_device_crl(slot: u32, device: &Certificate, number: u64, this: u64, next: u64, revoked: &[(x509_cert::serial_number::SerialNumber, u64)]) -> Result<Vec<u8>, u32> {
    let tbs = pki::build_crl_tbs(device, number, this, next, revoked).map_err(|_| CKR_DEVICE_ERROR)?;
    let (_, device_sk) = records::function_secret(slot, Purpose::DeviceIssuer).ok_or(CKR_DEVICE_ERROR)?;
    let sig = super::mldsa65_sign(&device_sk, &asn1::to_der(&tbs)?)?;
    pki::assemble_crl(tbs, &sig)
}

/// Publish the next device-issuer CRL, adding `revoke` (function purposes of
/// this device) to everything already revoked. Returns the CRL DER for peers.
pub fn issue_device_crl(so_session: u32, revoke: &[Purpose], validity_secs: u64) -> Result<Vec<u8>, u32> {
    issue_device_crl_with(so_session, revoke, &[], validity_secs)
}

/// [`issue_device_crl`], additionally revoking specific (e.g. retired)
/// function certificates of this device by DER.
pub fn issue_device_crl_with(so_session: u32, revoke: &[Purpose], retired_to_revoke: &[Vec<u8>], validity_secs: u64) -> Result<Vec<u8>, u32> {
    require_profile()?;
    let slot = require_so(so_session)?;
    let (enroll_h, rec) = enrollment(slot).ok_or(CKR_ACTION_PROHIBITED)?;
    if rec.state != 3 || revoke.contains(&Purpose::DeviceIssuer) {
        return Err(CKR_ACTION_PROHIBITED);
    }
    let now = now_unix();
    let device = pki::parse_cert(&records::certificate(slot, Purpose::DeviceIssuer).ok_or(CKR_DEVICE_ERROR)?)
        .or_else(|_| Err(CKR_DEVICE_ERROR))?;
    let ski = pki::key_id(&device.tbs_certificate.subject_public_key_info);
    let (crl_h, _, current) = records::crls(slot).into_iter().find(|(_, k, _)| *k == ski).ok_or(CKR_DEVICE_ERROR)?;
    let mut revoked: Vec<(x509_cert::serial_number::SerialNumber, u64)> = Vec::new();
    if let Ok(cur) = x509_cert::crl::CertificateList::from_der(&current) {
        for e in cur.tbs_cert_list.revoked_certificates.unwrap_or_default() {
            revoked.push((e.serial_number, pki::time_secs(&e.revocation_date)));
        }
    }
    for p in revoke {
        let c = pki::parse_cert(&records::certificate(slot, *p).ok_or(CKR_DEVICE_ERROR)?).or_else(|_| Err(CKR_DEVICE_ERROR))?;
        if !revoked.iter().any(|(s, _)| *s == c.tbs_certificate.serial_number) {
            revoked.push((c.tbs_certificate.serial_number, now));
        }
    }
    for c in retired_to_revoke {
        let c = pki::parse_cert(c).or_else(|_| Err(CKR_DATA_INVALID))?;
        if c.tbs_certificate.issuer != device.tbs_certificate.subject {
            return Err(CKR_ARGUMENTS_BAD);
        }
        if !revoked.iter().any(|(s, _)| *s == c.tbs_certificate.serial_number) {
            revoked.push((c.tbs_certificate.serial_number, now));
        }
    }
    let number = rec.crl_number + 1;
    let crl = sign_device_crl(slot, &device, number, now, now + validity_secs.max(1), &revoked)?;
    let new_rec = asn1::to_der(&EnrollmentRecord { crl_number: number, ..rec })?;
    crate::state::commit_objects_atomically(
        so_session,
        Vec::new(),
        vec![(crl_h, vec![(CKA_VALUE, crl.clone())]), (enroll_h, vec![(CKA_PRIV_REPL_RECORD, new_rec)])],
    )?;
    oplog_event("device_crl", slot, &[("crl_number", number.to_string()), ("revoked", revoked.len().to_string())]);
    Ok(crl)
}

/// Enroll a newer CRL: the manufacturing root's (no `issuer_device_cert`) or a
/// peer device issuer's (with that peer's device certificate, which must
/// itself chain to an enrolled root and be unrevoked). CRL numbers must
/// strictly increase per issuer.
pub fn enroll_crl(so_session: u32, crl_der: &[u8], issuer_device_cert: Option<&[u8]>) -> Result<(), u32> {
    require_profile()?;
    let slot = require_so(so_session)?;
    if enrollment_state(slot) < 2 {
        return Err(CKR_ACTION_PROHIBITED);
    }
    if crl_der.len() > MAX_CRL_DER {
        return Err(CKR_DATA_INVALID);
    }
    let now = now_unix();
    let trust = trust_inputs(slot);
    let verified = match issuer_device_cert {
        None => trust
            .roots
            .iter()
            .filter_map(|r| pki::parse_cert(r).ok())
            .find_map(|root| pki::verify_crl(crl_der, &root, now).ok())
            .ok_or(CKR_SIGNATURE_INVALID)?,
        Some(dev_der) => {
            let dev = pki::parse_cert(dev_der).or_else(|_| Err(CKR_DATA_INVALID))?;
            pki::validate_device_trusted(&dev, &trust, now, Profile::Educational).or_else(sig_invalid)?;
            pki::verify_crl(crl_der, &dev, now).or_else(sig_invalid)?
        }
    };
    let existing = records::crls(slot).into_iter().find(|(_, k, _)| *k == verified.issuer_key_id);
    match existing {
        Some((h, _, old)) => {
            let old_number = x509_cert::crl::CertificateList::from_der(&old)
                .ok()
                .and_then(|c| {
                    use const_oid::AssociatedOid;
                    c.tbs_cert_list.crl_extensions.unwrap_or_default().into_iter().find(|x| x.extn_id == x509_cert::ext::pkix::CrlNumber::OID)
                        .and_then(|x| x509_cert::ext::pkix::CrlNumber::from_der(x.extn_value.as_bytes()).ok())
                        .map(|n| n.0.as_bytes().iter().fold(0u64, |a, b| (a << 8) | *b as u64))
                })
                .unwrap_or(0);
            if verified.number <= old_number {
                return Err(CKR_ACTION_PROHIBITED);
            }
            crate::state::commit_objects_atomically(so_session, Vec::new(), vec![(h, vec![(CKA_VALUE, crl_der.to_vec())])])?;
        }
        None => {
            if records::crls(slot).len() >= MAX_CRLS_PER_SLOT {
                return Err(CKR_DEVICE_MEMORY);
            }
            let rec = records::new_record(ROLE_CRL, CKO_DATA, "enrolled CRL", crl_der.to_vec(), verified.issuer_key_id.clone(), false);
            crate::state::commit_objects_atomically(so_session, vec![rec], Vec::new())?;
        }
    }
    oplog_event("crl_enrolled", slot, &[("issuer_key_id", super::hex(&verified.issuer_key_id)), ("crl_number", verified.number.to_string())]);
    Ok(())
}

/// Enroll an immutable replication policy; returns its SHA-384 identifier.
/// Enrolling identical DER again is idempotent.
pub fn enroll_policy(so_session: u32, policy_der: &[u8]) -> Result<[u8; 48], u32> {
    require_profile()?;
    let slot = require_so(so_session)?;
    let view = records::parse_policy(policy_der)?;
    // Version 1 profiles: no per-type constraint (AES / ML-KEM-768 /
    // ML-DSA-65), or the FHE seed profile (FHE P1).
    if view.type_constraint_hash != super::sha384(b"") && view.type_constraint_hash != super::fhe::profile_constraint_hash() {
        return Err(CKR_DATA_INVALID);
    }
    if records::find_policy(slot, &view.id).is_some() {
        return Ok(view.id);
    }
    if records::list(slot, ROLE_POLICY).len() >= MAX_POLICIES_PER_SLOT {
        return Err(CKR_DEVICE_MEMORY);
    }
    let rec = records::new_record(ROLE_POLICY, CKO_DATA, "replication policy", policy_der.to_vec(), Vec::new(), false);
    crate::state::commit_objects_atomically(so_session, vec![rec], Vec::new())?;
    oplog_event("policy_enrolled", slot, &[("policy", super::hex(&view.id))]);
    Ok(view.id)
}

// ── Public read accessors (any session) ────────────────────────────────────

fn any_slot(session: u32) -> Result<u32, u32> {
    require_profile()?;
    super::session_slot_checked(session)
}

pub fn device_certificate(session: u32) -> Result<Vec<u8>, u32> {
    function_certificate(session, Purpose::DeviceIssuer)
}

pub fn function_certificate(session: u32, purpose: Purpose) -> Result<Vec<u8>, u32> {
    let slot = any_slot(session)?;
    records::certificate(slot, purpose).ok_or(CKR_ACTION_PROHIBITED)
}

/// `[leaf, device issuer]` for `purpose` — the spec's two-certificate chain.
pub fn function_chain(session: u32, purpose: Purpose) -> Result<Vec<Vec<u8>>, u32> {
    Ok(vec![function_certificate(session, purpose)?, device_certificate(session)?])
}

pub fn device_id(session: u32) -> Result<[u8; 32], u32> {
    let der = device_certificate(session)?;
    let c = pki::parse_cert(&der).or_else(|_| Err(CKR_DEVICE_ERROR))?;
    Ok(pki::device_id_of(&c))
}

/// This token's current device-issuer CRL (for peers to enroll).
pub fn own_device_crl(session: u32) -> Result<Vec<u8>, u32> {
    let slot = any_slot(session)?;
    let device = pki::parse_cert(&records::certificate(slot, Purpose::DeviceIssuer).ok_or(CKR_ACTION_PROHIBITED)?)
        .or_else(|_| Err(CKR_DEVICE_ERROR))?;
    let ski = pki::key_id(&device.tbs_certificate.subject_public_key_info);
    records::crls(slot).into_iter().find(|(_, k, _)| *k == ski).map(|(_, _, d)| d).ok_or(CKR_DEVICE_ERROR)
}

/// True once the slot holds a device identity with issued function keys.
pub fn hierarchy_ready(slot: u32) -> bool {
    enrollment_state(slot) == 3
}
