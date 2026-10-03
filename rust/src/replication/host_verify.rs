//! Host-side verifier (plan R2.2, item 2): verification over PUBLIC bytes
//! only — evidence, receipts and packages — against trust inputs the host
//! supplies (a manufacturing root and CRLs). It never touches engine state,
//! so a test or the Hub can check an engine's claims independently of the
//! engine that produced them.
//!
//! It shares the evidence verification core with the engine
//! ([`super::evidence::verify_evidence_core`]); what differs is where trust
//! comes from. The K3 agreement tests feed both paths the same vectors.

use der::Encode;

use super::asn1::{self, ReplicationPackage, ReplicationReceipt};
use super::evidence::{self, EvidenceClaims, EvidenceRole};
use super::oids::{self, Purpose};
use super::pki::{self, Reject, TrustInputs};
use super::Profile;

pub use super::pki::TrustInputs as HostTrust;

pub const RECEIPT_DOMAIN: &[u8] = b"PQCToday Key Replication Receipt 1.0";
pub const PACKAGE_DOMAIN: &[u8] = b"PQCToday Key Replication Package 1.0";
pub const MAX_RECEIPT_DER: usize = 32 * 1024;
pub const MAX_PACKAGE_DER: usize = 256 * 1024;

/// Verify general key-attestation evidence for `expected_challenge`.
pub fn verify_key_evidence(
    evidence_der: &[u8],
    trust: &TrustInputs,
    expected_challenge: &[u8; 32],
    now: u64,
    profile: Profile,
) -> Result<EvidenceClaims, Reject> {
    evidence::verify_evidence_core(evidence_der, trust, now, profile, EvidenceRole::KeyAttestation, expected_challenge, None)
        .map(|v| v.claims)
}

/// Public facts a verified receipt establishes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptView {
    pub transaction_id: [u8; 32],
    pub destination_device_id: [u8; 32],
    pub installed_unique_id: String,
    pub lineage_id: [u8; 32],
    pub installed_policy: [u8; 48],
    pub committed_at: u64,
}

fn prefixed(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(domain.len() + 1 + body.len());
    m.extend_from_slice(domain);
    m.push(0);
    m.extend_from_slice(body);
    m
}

pub(crate) fn receipt_signed_bytes(tbs_der: &[u8]) -> Vec<u8> {
    prefixed(RECEIPT_DOMAIN, tbs_der)
}

pub(crate) fn package_signed_bytes(tbs_der: &[u8]) -> Vec<u8> {
    prefixed(PACKAGE_DOMAIN, tbs_der)
}

/// Verify a receipt against the exact package it acknowledges and the
/// request that package answered (spec §7; reviews K0B-R-10, K0B-R2-09).
/// Beyond the signer chain and package hash, it requires: the claimed
/// destination device is the receipt signer's device; that device is the
/// one the package was sealed to (the request's recipient chain, whose key
/// hash the package header carries); and the receipt's transaction,
/// lineage and installed policy equal the package header's.
pub fn verify_receipt(
    receipt_der: &[u8],
    package_der: &[u8],
    request_der: &[u8],
    trust: &TrustInputs,
    now: u64,
    profile: Profile,
) -> Result<ReceiptView, Reject> {
    if profile != Profile::Educational {
        return Err(Reject("documentation OIDs outside educational profile"));
    }
    let r: ReplicationReceipt = asn1::decode_strict(receipt_der, MAX_RECEIPT_DER).map_err(|_| Reject("receipt DER"))?;
    let t = &r.tbs;
    if t.version != 1 || t.suite != oids::SUITE_V1 || r.signature_algorithm != asn1::ml_dsa_65_alg() {
        return Err(Reject("receipt version/suite/algorithm"));
    }
    let chain = pki::validate_chain(&t.receipt_signer_chain, Purpose::ReceiptSigning, trust, now, profile)?;
    let f32 = |o: &der::asn1::OctetString| <[u8; 32]>::try_from(o.as_bytes()).map_err(|_| Reject("field size"));
    let dest = f32(&t.destination_device_id)?;
    if dest != chain.device_id {
        return Err(Reject("receipt device differs from signer chain"));
    }
    if t.package_hash.as_bytes() != super::sha384(package_der) {
        return Err(Reject("receipt package hash"));
    }
    let pkg: ReplicationPackage = asn1::decode_strict(package_der, MAX_PACKAGE_DER).map_err(|_| Reject("package DER"))?;
    let h = &pkg.tbs.header;
    let req: asn1::ReplicationRequest =
        asn1::decode_strict(request_der, super::package::MAX_REQUEST_DER).map_err(|_| Reject("request DER"))?;
    let recipient = pki::validate_chain(&req.recipient_chain, Purpose::RecoveryRecipient, trust, now, profile)?;
    if h.recipient_key_hash.as_bytes() != pki::spki_hash(&recipient.leaf)
        || req.transaction_id != h.transaction_id
        || recipient.device_id != dest
    {
        return Err(Reject("receipt signer is not the package's recipient"));
    }
    if t.transaction_id != h.transaction_id || t.lineage_id != h.lineage_id || t.installed_policy != h.destination_policy {
        return Err(Reject("receipt fields differ from the package header"));
    }
    let tbs_der = t.to_der().map_err(|_| Reject("receipt tbs"))?;
    if r.signature.unused_bits() != 0
        || !super::mldsa65_verify(pki::mldsa65_public(&chain.leaf)?, &receipt_signed_bytes(&tbs_der), r.signature.raw_bytes())
    {
        return Err(Reject("receipt signature"));
    }
    Ok(ReceiptView {
        transaction_id: f32(&t.transaction_id)?,
        destination_device_id: dest,
        installed_unique_id: t.installed_unique_id.clone(),
        lineage_id: f32(&t.lineage_id)?,
        installed_policy: t.installed_policy.as_bytes().try_into().map_err(|_| Reject("policy size"))?,
        committed_at: t.committed_at.to_unix_duration().as_secs(),
    })
}

/// Public metadata of a package, for display (no verification, no secrets —
/// the payload is ciphertext and stays that way).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageView {
    pub operation: asn1::Operation,
    pub transaction_id: Vec<u8>,
    pub domain_id: Vec<u8>,
    pub source_unique_id: String,
    pub lineage_id: Vec<u8>,
    pub source_policy: Vec<u8>,
    pub destination_policy: Vec<u8>,
    pub recipient_key_hash: Vec<u8>,
    pub transferred_budget: u32,
    pub ciphertext_len: usize,
    pub package_hash: [u8; 48],
}

pub fn inspect_package(package_der: &[u8]) -> Result<PackageView, Reject> {
    let p: ReplicationPackage = asn1::decode_strict(package_der, MAX_PACKAGE_DER).map_err(|_| Reject("package DER"))?;
    let h = &p.tbs.header;
    Ok(PackageView {
        operation: h.operation,
        transaction_id: h.transaction_id.as_bytes().to_vec(),
        domain_id: h.domain_id.as_bytes().to_vec(),
        source_unique_id: h.source_unique_id.clone(),
        lineage_id: h.lineage_id.as_bytes().to_vec(),
        source_policy: h.source_policy.as_bytes().to_vec(),
        destination_policy: h.destination_policy.as_bytes().to_vec(),
        recipient_key_hash: h.recipient_key_hash.as_bytes().to_vec(),
        transferred_budget: h.transferred_budget,
        ciphertext_len: p.tbs.ciphertext.as_bytes().len(),
        package_hash: super::sha384(package_der),
    })
}
