//! DER structures for the replication interface (spec §5–§8), the evidence
//! container (draft-ietf-rats-pkix-key-attestation-07 §5/§8 shape, as the
//! K0A spike pinned it) and the engine's internal durable records.
//!
//! Strictness (review K0B-R-02): every received structure is decoded with
//! [`decode_strict`], which also re-encodes and byte-compares, so any BER,
//! non-minimal or otherwise non-canonical input is refused before a
//! signature is checked over it.

use der::asn1::{Any, BitString, GeneralizedTime, ObjectIdentifier, OctetString};
use der::{Decode, Encode, Enumerated, Sequence};
use spki07::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::Certificate;

use crate::constants::CKR_DATA_INVALID;

/// Decode `bytes` as `T`, refuse anything over `max`, and require that the
/// canonical re-encoding is byte-identical to the input.
pub fn decode_strict<'a, T>(bytes: &'a [u8], max: usize) -> Result<T, u32>
where
    T: Decode<'a> + Encode,
{
    if bytes.is_empty() || bytes.len() > max {
        return Err(CKR_DATA_INVALID);
    }
    let v = T::from_der(bytes).map_err(|_| CKR_DATA_INVALID)?;
    let again = v.to_der().map_err(|_| CKR_DATA_INVALID)?;
    if again != bytes {
        return Err(CKR_DATA_INVALID);
    }
    Ok(v)
}

pub fn to_der<T: Encode>(v: &T) -> Result<Vec<u8>, u32> {
    v.to_der().map_err(|_| crate::constants::CKR_DEVICE_ERROR)
}

pub fn octets(b: &[u8]) -> OctetString {
    OctetString::new(b.to_vec()).expect("bounded octet string")
}

pub fn ml_dsa_65_alg() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned { oid: super::oids::ML_DSA_65, parameters: None }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Enumerated)]
#[repr(u32)]
pub enum Operation {
    LiveClone = 0,
    OfflineBackup = 1,
    Restore = 2,
}

impl Operation {
    pub fn bit(self) -> usize {
        self as usize
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Enumerated)]
#[repr(u32)]
pub enum KeyClass {
    SecretKey = 0,
    PrivateKey = 1,
}

// ── Evidence (RATS -07 container) ──────────────────────────────────────────

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Evidence {
    pub tbs: TbsEvidence,
    pub signatures: Vec<SignatureBlock>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub intermediate_certificates: Option<Vec<Certificate>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SignatureBlock {
    pub sid: SignerIdentifier,
    pub signature_algorithm: AlgorithmIdentifierOwned,
    pub signature_value: OctetString,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SignerIdentifier {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub key_id: Option<OctetString>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    pub subject_public_key_info: Option<SubjectPublicKeyInfoOwned>,
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", optional = "true")]
    pub certificate: Option<Certificate>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TbsEvidence {
    pub version: u8,
    pub reported_elements: Vec<ReportedElement>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ReportedElement {
    pub element_type: ObjectIdentifier,
    pub claims: Vec<ReportedClaim>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ReportedClaim {
    pub claim_type: ObjectIdentifier,
    #[asn1(optional = "true")]
    pub value: Option<Any>,
}

// ── Request / package / receipt (spec §5–§7) ───────────────────────────────

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ReplicationRequest {
    pub version: u8,
    pub operation: Operation,
    pub suite: ObjectIdentifier,
    pub transaction_id: OctetString,
    pub source_challenge: OctetString,
    pub destination_challenge: OctetString,
    pub domain_id: OctetString,
    pub requested_policy: OctetString,
    pub recipient_chain: Vec<Certificate>,
    pub recipient_evidence: Evidence,
}

/// Spec §6 header plus `transferredBudget` (spec edit E-12, review
/// K0B-R-12): the replica budget moved from the source to this copy. Signed,
/// so the destination cannot be granted more than the source gave up.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ReplicationProtectedHeader {
    pub version: u8,
    pub operation: Operation,
    pub suite: ObjectIdentifier,
    pub transaction_id: OctetString,
    pub domain_id: OctetString,
    pub source_unique_id: String,
    pub lineage_id: OctetString,
    pub source_policy: OctetString,
    pub destination_policy: OctetString,
    pub recipient_key_hash: OctetString,
    pub transferred_budget: u32,
    pub source_chain: Vec<Certificate>,
    pub source_evidence: Evidence,
    pub type_extension_hash: OctetString,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ReplicationPackageTbs {
    pub header: ReplicationProtectedHeader,
    pub encapsulated: OctetString,
    pub ciphertext: OctetString,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ReplicationPackage {
    pub tbs: ReplicationPackageTbs,
    pub signature_algorithm: AlgorithmIdentifierOwned,
    pub signature: BitString,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ReplicatedAttribute {
    pub attr_type: u32,
    pub value: OctetString,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ReplicatedKeyPayload {
    pub version: u8,
    pub key_class: KeyClass,
    pub key_type: u32,
    pub protected_value: OctetString,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub paired_public: Option<OctetString>,
    pub attributes: Vec<ReplicatedAttribute>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    pub type_extension: Option<OctetString>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ReplicationReceiptTbs {
    pub version: u8,
    pub suite: ObjectIdentifier,
    pub transaction_id: OctetString,
    pub package_hash: OctetString,
    pub destination_device_id: OctetString,
    pub installed_unique_id: String,
    pub lineage_id: OctetString,
    pub installed_policy: OctetString,
    pub committed_at: GeneralizedTime,
    pub receipt_signer_chain: Vec<Certificate>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ReplicationReceipt {
    pub tbs: ReplicationReceiptTbs,
    pub signature_algorithm: AlgorithmIdentifierOwned,
    pub signature: BitString,
}

fn default_false() -> bool {
    false
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ReplicationPolicy {
    pub version: u8,
    pub domain_id: OctetString,
    pub operations: BitString,
    pub allowed_peer_device_ids: Vec<OctetString>,
    pub not_before: GeneralizedTime,
    pub not_after: GeneralizedTime,
    pub max_replicas: u32,
    pub allowed_mechanisms: Vec<u32>,
    #[asn1(default = "default_false")]
    pub allow_same_device: bool,
    pub type_constraint_hash: OctetString,
}

/// Canonical provenance (spec edit E-12b, review K0B-R-12): the value of
/// `CKA_PQCTODAY_REPLICATION_PROVENANCE` on an installed replica.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ReplicationProvenance {
    pub version: u8,
    pub operation: Operation,
    pub source_device_id: OctetString,
    pub source_unique_id: String,
    pub lineage_id: OctetString,
    pub transaction_id: OctetString,
    pub package_hash: OctetString,
    pub committed_at: GeneralizedTime,
}

// ── Internal durable records (never on the wire) ───────────────────────────

/// An issued, not yet consumed verifier challenge (review K0B-R-04).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct ChallengeRecord {
    /// 0 = source challenge, 1 = destination challenge.
    pub role: u8,
    pub challenge: OctetString,
    /// Bound transaction (destination challenges are issued with one; a
    /// source challenge becomes bound when a package consumes it).
    pub transaction_id: OctetString,
    pub operation: Operation,
    pub requested_policy: OctetString,
    pub issued_at: u64,
    pub expires_at: u64,
    pub consumed: bool,
}

/// Destination consumption-ledger entry (spec §3.2; review K0B-R-09).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct LedgerRecord {
    pub transaction_id: OctetString,
    /// 1 = reserved, 2 = committed.
    pub state: u8,
    pub package_hash: OctetString,
    pub installed_unique_id: String,
    pub receipt: OctetString,
}

/// Source package cache entry (spec §3.1; review K0B-R-07).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct PackageCacheRecord {
    pub transaction_id: OctetString,
    pub request_hash: OctetString,
    pub source_unique_id: String,
    pub package: OctetString,
    /// Host time of creation; entries are pruned after
    /// `package::CACHE_RETENTION_SECS` (review K0B-R2-04).
    pub created_at: u64,
}

/// Pending device enrollment: the CSR the device key produced.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct EnrollmentRecord {
    /// 1 = CSR issued, awaiting certificate; 2 = enrolled; 3 = functions issued.
    pub state: u8,
    pub csr: OctetString,
    pub crl_number: u64,
}
