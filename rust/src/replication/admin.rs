//! Replication admin interface (admin addendum 1.0, draft 3.2, owner-approved
//! 2026-10-03): signed SO operations with an engine nonce, a strictly
//! increasing sequence, a durable replay ledger and signed receipts.
//!
//! An admin call is authorized by ALL of: a real SO login on an R/W session
//! (§1.1 item 2), an ML-DSA-65 signature from the enrolled admin authority,
//! the engine's current nonce, and `sequence == stored + 1`. Every effect —
//! the staged operation, the new sequence, the replay-ledger entry (which is
//! also the durable audit record) and the receipt — lands in ONE store
//! transaction (A-03); the nonce is consumed only after it commits.
//!
//! Return codes (§4): malformed input → `CKR_DATA_INVALID`; every
//! syntactically valid trust/authorization failure → `CKR_ACTION_PROHIBITED`
//! (reason in the audit log only); ledger full → `CKR_DEVICE_MEMORY`; ledger
//! integrity or commit failure → `CKR_DEVICE_ERROR`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use der::asn1::{BitString, GeneralizedTime, Null, OctetString};
use der::{Decode, Encode, Enumerated, Sequence};
use spki07::AlgorithmIdentifierOwned;
use x509_cert::certificate::Certificate;

use super::asn1::{self, decode_strict};
use super::enroll::{self, Staged};
use super::oids::Purpose;
use super::pki::{self, TrustInputs};
use super::records;
use super::{note_refusal, now_unix, oplog_event, require_profile, require_so, Profile};
use crate::constants::*;
use crate::crypto::handlers::Attributes;

pub const REQUEST_DOMAIN: &[u8] = b"PQCToday Replication Admin 1.0";
pub const RECEIPT_DOMAIN: &[u8] = b"PQCToday Replication Admin Receipt 1.0";
pub const MAX_ADMIN_REQUEST_DER: usize = 96 * 1024;
pub const MAX_ADMIN_RECEIPT_DER: usize = 96 * 1024;
pub const MAX_LEDGER_ENTRIES: usize = 1024;
pub const MAX_LEDGER_BYTES: usize = 64 * 1024 * 1024;
pub const NONCE_LIFETIME: Duration = Duration::from_secs(60);
/// Ledger entries may be pruned only once older than this (§3.5).
pub const LEDGER_RETENTION_SECS: u64 = 30 * 86_400;
const MAX_SEQUENCE: u64 = i64::MAX as u64;
const SIG_LEN: usize = super::package::ML_DSA_65_SIG_LEN;

/// `CKA_PQCTODAY_FUNCTION_PURPOSE` value of an admin-authority record (§9.2).
pub const PURPOSE_ADMIN_AUTHORITY_VALUE: u8 = 7;
pub const ROLE_ADMIN_AUTHORITY: u8 = 16;
pub const ROLE_ADMIN_LEDGER: u8 = 17;
pub const ROLE_ADMIN_TOMBSTONE: u8 = 18;

// ── ASN.1 (§3.1) ────────────────────────────────────────────────────────────

/// `FunctionPurpose`: only the five revocable leaf purposes decode.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Enumerated)]
#[repr(u32)]
pub enum RevocablePurpose {
    KeyAttestation = 2,
    PackageSigning = 3,
    RecoveryRecipient = 4,
    PeerAuthentication = 5,
    ReceiptSigning = 6,
}

impl RevocablePurpose {
    pub fn purpose(self) -> Purpose {
        match self {
            Self::KeyAttestation => Purpose::KeyAttestation,
            Self::PackageSigning => Purpose::PackageSigning,
            Self::RecoveryRecipient => Purpose::RecoveryRecipient,
            Self::PeerAuthentication => Purpose::PeerAuthentication,
            Self::ReceiptSigning => Purpose::ReceiptSigning,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct EnrollCrlOp {
    pub crl: OctetString,
    #[asn1(optional = "true")]
    pub issuer_device_cert: Option<OctetString>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct EnrollPolicyOp {
    pub policy: OctetString,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct IssueDeviceCrlOp {
    pub revoke: Vec<RevocablePurpose>,
    pub retired_to_revoke: Vec<OctetString>,
    pub validity_seconds: u32,
}

/// `AdminTbsRequest`. The trailing `AdminOperation` CHOICE (explicit tags
/// [0]–[4]) is modelled as five OPTIONAL explicit-tagged fields of which
/// exactly one must be present: the DER is byte-identical to the CHOICE.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct AdminTbsRequest {
    pub version: u8,
    pub device_id: OctetString,
    pub admin_key_id: OctetString,
    pub nonce: OctetString,
    pub sequence: u64,
    pub issued_at: GeneralizedTime,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub enroll_crl: Option<EnrollCrlOp>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    pub enroll_policy: Option<EnrollPolicyOp>,
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", optional = "true")]
    pub rotate_recovery_key: Option<Null>,
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    pub issue_function_certs: Option<Null>,
    #[asn1(context_specific = "4", tag_mode = "EXPLICIT", optional = "true")]
    pub issue_device_crl: Option<IssueDeviceCrlOp>,
}

/// The operation a request carries, by value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdminOperation {
    EnrollCrl { crl: Vec<u8>, issuer_device_cert: Option<Vec<u8>> },
    EnrollPolicy { policy: Vec<u8> },
    RotateRecoveryKey,
    IssueFunctionCerts,
    IssueDeviceCrl { revoke: Vec<RevocablePurpose>, retired_to_revoke: Vec<Vec<u8>>, validity_seconds: u32 },
}

impl AdminOperation {
    pub fn name(&self) -> &'static str {
        match self {
            Self::EnrollCrl { .. } => "enrollCrl",
            Self::EnrollPolicy { .. } => "enrollPolicy",
            Self::RotateRecoveryKey => "rotateRecoveryKey",
            Self::IssueFunctionCerts => "issueFunctionCerts",
            Self::IssueDeviceCrl { .. } => "issueDeviceCrl",
        }
    }
}

impl AdminTbsRequest {
    /// The single operation, or `CKR_DATA_INVALID` unless exactly one arm is
    /// present and its lists are ordered and unique (§3.1).
    pub fn operation(&self) -> Result<AdminOperation, u32> {
        let arms = [
            self.enroll_crl.is_some(),
            self.enroll_policy.is_some(),
            self.rotate_recovery_key.is_some(),
            self.issue_function_certs.is_some(),
            self.issue_device_crl.is_some(),
        ];
        if arms.iter().filter(|x| **x).count() != 1 {
            return Err(CKR_DATA_INVALID);
        }
        if let Some(op) = &self.enroll_crl {
            let crl = op.crl.as_bytes().to_vec();
            let dev = op.issuer_device_cert.as_ref().map(|c| c.as_bytes().to_vec());
            if crl.is_empty() || crl.len() > 65_536 || dev.as_ref().is_some_and(|d| d.is_empty() || d.len() > 8_192) {
                return Err(CKR_DATA_INVALID);
            }
            return Ok(AdminOperation::EnrollCrl { crl, issuer_device_cert: dev });
        }
        if let Some(op) = &self.enroll_policy {
            let policy = op.policy.as_bytes().to_vec();
            if policy.is_empty() || policy.len() > 8_192 {
                return Err(CKR_DATA_INVALID);
            }
            return Ok(AdminOperation::EnrollPolicy { policy });
        }
        if self.rotate_recovery_key.is_some() {
            return Ok(AdminOperation::RotateRecoveryKey);
        }
        if self.issue_function_certs.is_some() {
            return Ok(AdminOperation::IssueFunctionCerts);
        }
        let op = self.issue_device_crl.as_ref().ok_or(CKR_DATA_INVALID)?;
        let retired: Vec<Vec<u8>> = op.retired_to_revoke.iter().map(|o| o.as_bytes().to_vec()).collect();
        let strictly_ascending = |v: &[Vec<u8>]| v.windows(2).all(|w| w[0] < w[1]);
        if op.revoke.len() > 5
            || !op.revoke.windows(2).all(|w| w[0] < w[1])
            || retired.len() > 64
            || retired.iter().any(|c| c.is_empty() || c.len() > 8_192)
            || !strictly_ascending(&retired)
            || !(60..=2_592_000).contains(&op.validity_seconds)
        {
            return Err(CKR_DATA_INVALID);
        }
        Ok(AdminOperation::IssueDeviceCrl { revoke: op.revoke.clone(), retired_to_revoke: retired, validity_seconds: op.validity_seconds })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct AdminSignedRequest {
    pub tbs: AdminTbsRequest,
    pub signature_algorithm: AlgorithmIdentifierOwned,
    pub signature: BitString,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct AdminTbsReceipt {
    pub version: u8,
    pub device_id: OctetString,
    pub request_hash: OctetString,
    pub sequence: u64,
    pub result_digest: OctetString,
    #[asn1(optional = "true")]
    pub output: Option<OctetString>,
    pub committed_at: GeneralizedTime,
    pub receipt_signer_chain: Vec<Certificate>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct AdminReceipt {
    pub tbs: AdminTbsReceipt,
    pub signature_algorithm: AlgorithmIdentifierOwned,
    pub signature: BitString,
}

/// Signed bytes: `domain || 0x00 || DER(tbs)`, empty ML-DSA context.
pub fn signed_bytes(domain: &[u8], tbs_der: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(domain.len() + 1 + tbs_der.len());
    m.extend_from_slice(domain);
    m.push(0);
    m.extend_from_slice(tbs_der);
    m
}

pub fn gtime(unix: u64) -> Result<GeneralizedTime, u32> {
    GeneralizedTime::from_unix_duration(Duration::from_secs(unix)).map_err(|_| CKR_DEVICE_ERROR)
}

// ── Durable records ─────────────────────────────────────────────────────────

/// Admin-authority state (`CKA_PRIV_REPL_RECORD` of its record).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct AuthorityRecord {
    active: bool,
    sequence: u64,
}

/// One committed admin request (§3.5). It is also the durable audit record
/// of the commit (§3.2 step 9; the `oplog` line is derived from it).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct LedgerEntry {
    request_hash: OctetString,
    sequence: u64,
    admin_key_id: OctetString,
    committed_at: u64,
    operation: String,
    request: OctetString,
    receipt: OctetString,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct Tombstone {
    request_hash: OctetString,
    sequence: u64,
    admin_key_id: OctetString,
}

struct Authority {
    handle: u32,
    cert: Certificate,
    key_id: [u8; 32],
    sequence: u64,
}

fn key_id_of(cert: &Certificate) -> Result<[u8; 32], u32> {
    Ok(super::sha256(&cert.tbs_certificate.subject_public_key_info.to_der().map_err(|_| CKR_DEVICE_ERROR)?))
}

/// The slot's active admin authority. A stored record that fails to decode
/// is an integrity failure, never "absent".
fn active_authority(slot: u32) -> Result<Option<Authority>, u32> {
    let mut found = None;
    for (h, a) in records::list(slot, ROLE_ADMIN_AUTHORITY) {
        let rec = AuthorityRecord::from_der(records::record_bytes(&a)).map_err(|_| CKR_DEVICE_ERROR)?;
        if !rec.active {
            continue;
        }
        if found.is_some() {
            return Err(CKR_DEVICE_ERROR); // at most one active authority (§1)
        }
        let cert_der = records::value_bytes(&a).to_vec();
        let cert = pki::parse_cert(&cert_der).map_err(|_| CKR_DEVICE_ERROR)?;
        let key_id = key_id_of(&cert)?;
        found = Some(Authority { handle: h, cert, key_id, sequence: rec.sequence });
    }
    Ok(found)
}

fn ledger(slot: u32) -> Result<Vec<(u32, LedgerEntry)>, u32> {
    records::list(slot, ROLE_ADMIN_LEDGER)
        .into_iter()
        .map(|(h, a)| LedgerEntry::from_der(records::record_bytes(&a)).map(|e| (h, e)).map_err(|_| CKR_DEVICE_ERROR))
        .collect()
}

fn tombstones(slot: u32) -> Result<Vec<Tombstone>, u32> {
    records::list(slot, ROLE_ADMIN_TOMBSTONE)
        .into_iter()
        .map(|(_, a)| Tombstone::from_der(records::record_bytes(&a)).map_err(|_| CKR_DEVICE_ERROR))
        .collect()
}

// ── Board-local bootstrap (§1; never reachable through the interface) ──────

fn validate_authority_cert(slot: u32, cert_der: &[u8], now: u64) -> Result<Certificate, u32> {
    let cert = pki::parse_cert(cert_der).map_err(|_| CKR_DATA_INVALID)?;
    pki::validate_admin_authority_trusted(&cert, &enroll::trust_inputs(slot), None, now, Profile::Educational)
        .map_err(|r| refuse(slot, r.0))?;
    Ok(cert)
}

fn authority_record(cert_der: &[u8]) -> Result<Attributes, u32> {
    let rec = asn1::to_der(&AuthorityRecord { active: true, sequence: 0 })?;
    let mut a = records::new_record(ROLE_ADMIN_AUTHORITY, CKO_CERTIFICATE, "replication admin authority", cert_der.to_vec(), rec, false);
    a.insert(CKA_PQCTODAY_FUNCTION_PURPOSE, vec![PURPOSE_ADMIN_AUTHORITY_VALUE]);
    Ok(a)
}

/// Enroll the slot's first admin-authority certificate (SO, board-local).
/// It must chain directly to the enrolled root and be unrevoked on its
/// current CRL. Its sequence starts at 0.
pub fn enroll_admin_authority(so_session: u32, cert_der: &[u8]) -> Result<(), u32> {
    let _op = super::package::op_lock();
    require_profile()?;
    let slot = require_so(so_session)?;
    if !enroll::hierarchy_ready(slot) {
        return Err(CKR_ACTION_PROHIBITED);
    }
    if !records::list(slot, ROLE_ADMIN_AUTHORITY).is_empty() {
        return Err(CKR_ACTION_PROHIBITED); // replacement is its own step
    }
    let cert = validate_authority_cert(slot, cert_der, now_unix())?;
    crate::state::commit_objects_atomically(so_session, vec![authority_record(cert_der)?], Vec::new())?;
    oplog_event("admin_authority_enrolled", slot, &[("admin_key_id", super::hex(&key_id_of(&cert)?))]);
    Ok(())
}

/// Replace the active admin authority (SO, board-local only, so a stolen
/// admin key cannot enroll its own successor). The new authority's sequence
/// starts at 0; committed receipts of the old one stay recoverable.
pub fn replace_admin_authority(so_session: u32, cert_der: &[u8]) -> Result<(), u32> {
    let _op = super::package::op_lock();
    require_profile()?;
    let slot = require_so(so_session)?;
    let old = active_authority(slot)?.ok_or(CKR_ACTION_PROHIBITED)?;
    let cert = validate_authority_cert(slot, cert_der, now_unix())?;
    let new_id = key_id_of(&cert)?;
    if new_id == old.key_id {
        return Err(CKR_ACTION_PROHIBITED);
    }
    let retired = asn1::to_der(&AuthorityRecord { active: false, sequence: old.sequence })?;
    crate::state::commit_objects_atomically(so_session, vec![authority_record(cert_der)?], vec![(old.handle, vec![(CKA_PRIV_REPL_RECORD, retired)])])?;
    oplog_event("admin_authority_replaced", slot, &[("old", super::hex(&old.key_id)), ("new", super::hex(&new_id))]);
    Ok(())
}

/// Board-local maintenance (§3.5): prune ledger entries older than the
/// retention period AND below their admin key's current sequence, leaving a
/// tombstone so a pruned request can never re-execute. Returns the count.
pub fn prune_admin_ledger(so_session: u32) -> Result<usize, u32> {
    let _op = super::package::op_lock();
    require_profile()?;
    let slot = require_so(so_session)?;
    let now = now_unix();
    // Only the ACTIVE authority's newest entry must stay retryable; a
    // replaced authority's sequence can never advance, so all of its entries
    // past retention are prunable.
    let mut current: HashMap<Vec<u8>, u64> = HashMap::new();
    if let Some(a) = active_authority(slot)? {
        current.insert(a.key_id.to_vec(), a.sequence);
    }
    let mut tombs = Vec::new();
    let mut gone = Vec::new();
    for (h, e) in ledger(slot)? {
        let cur = current.get(e.admin_key_id.as_bytes()).copied().unwrap_or(u64::MAX);
        if now.saturating_sub(e.committed_at) >= LEDGER_RETENTION_SECS && e.sequence < cur {
            let t = Tombstone { request_hash: e.request_hash.clone(), sequence: e.sequence, admin_key_id: e.admin_key_id.clone() };
            tombs.push(records::new_record(ROLE_ADMIN_TOMBSTONE, CKO_DATA, "admin ledger tombstone", Vec::new(), asn1::to_der(&t)?, false));
            gone.push(h);
        }
    }
    let n = gone.len();
    if n > 0 {
        crate::state::commit_objects_atomically(so_session, tombs, Vec::new())?;
        for h in gone {
            super::discard_object(h);
        }
        oplog_event("admin_ledger_pruned", slot, &[("entries", n.to_string())]);
    }
    Ok(n)
}

// ── Nonce (§3.3): in memory, one per slot, 60 s monotonic ─────────────────

static NONCES: Mutex<Option<HashMap<u32, ([u8; 32], Instant)>>> = Mutex::new(None);

fn nonces() -> std::sync::MutexGuard<'static, Option<HashMap<u32, ([u8; 32], Instant)>>> {
    NONCES.lock().unwrap_or_else(|e| e.into_inner())
}

fn current_nonce(slot: u32) -> Option<[u8; 32]> {
    nonces().as_ref()?.get(&slot).filter(|(_, at)| at.elapsed() < NONCE_LIFETIME).map(|(n, _)| *n)
}

fn consume_nonce(slot: u32, n: &[u8; 32]) {
    let mut g = nonces();
    if let Some(m) = g.as_mut() {
        if m.get(&slot).is_some_and(|(cur, _)| cur == n) {
            m.remove(&slot);
        }
    }
}

/// Forget every nonce (engine reset and tests); a restart has the same effect.
pub fn clear_nonces() {
    *nonces() = None;
}

/// Test hook: age the slot's nonce past its lifetime.
#[cfg(feature = "test-support")]
pub fn expire_nonce_for_test(slot: u32) {
    if let Some(m) = nonces().as_mut() {
        if let Some((_, at)) = m.get_mut(&slot) {
            *at = Instant::now().checked_sub(NONCE_LIFETIME + Duration::from_secs(1)).unwrap_or(*at);
        }
    }
}

/// `C_PQCTODAY_AdminIssueNonce` (§2.1 ordinal 0): a fresh non-zero 256-bit
/// nonce that REPLACES the slot's current one. Never written to the store.
pub fn issue_nonce(so_session: u32) -> Result<[u8; 32], u32> {
    let _op = super::package::op_lock();
    require_profile()?;
    let slot = require_so(so_session)?;
    if active_authority(slot)?.is_none() {
        return Err(refuse(slot, "no admin authority enrolled"));
    }
    let n = loop {
        let n = super::random32()?;
        if n != [0u8; 32] {
            break n;
        }
    };
    nonces().get_or_insert_with(HashMap::new).insert(slot, (n, Instant::now()));
    oplog_event("admin_nonce", slot, &[("result", "ok".into())]);
    Ok(n)
}

// ── Execute (§3.2) ──────────────────────────────────────────────────────────

fn refuse(slot: u32, reason: &'static str) -> u32 {
    note_refusal(reason);
    oplog_event("admin_refused", slot, &[("reason", reason.into())]);
    CKR_ACTION_PROHIBITED
}

/// Collapse a stage function's trust/sequence codes to §4's single code;
/// syntax, capacity and device errors keep theirs.
fn collapse(slot: u32, rv: u32) -> u32 {
    match rv {
        CKR_DATA_INVALID | CKR_DEVICE_MEMORY | CKR_DEVICE_ERROR => rv,
        _ => refuse(slot, "operation refused by its stage"),
    }
}

/// Everything `execute` and `execute_len` agree on, up to (not including)
/// the commit.
struct Prepared {
    slot: u32,
    request_hash: [u8; 48],
    replay: Option<Vec<u8>>,
    staged: Option<Staged>,
    authority: Option<Authority>,
    sequence: u64,
    nonce: [u8; 32],
    operation: &'static str,
}

/// B-06: embedded payloads must parse before any trust check.
fn check_payload_syntax(op: &AdminOperation) -> Result<(), u32> {
    match op {
        AdminOperation::EnrollCrl { crl, issuer_device_cert } => {
            x509_cert::crl::CertificateList::from_der(crl).map_err(|_| CKR_DATA_INVALID)?;
            if let Some(c) = issuer_device_cert {
                pki::parse_cert(c).map_err(|_| CKR_DATA_INVALID)?;
            }
        }
        AdminOperation::EnrollPolicy { policy } => {
            records::parse_policy(policy).map_err(|_| CKR_DATA_INVALID)?;
        }
        AdminOperation::IssueDeviceCrl { retired_to_revoke, .. } => {
            for c in retired_to_revoke {
                pki::parse_cert(c).map_err(|_| CKR_DATA_INVALID)?;
            }
        }
        AdminOperation::RotateRecoveryKey | AdminOperation::IssueFunctionCerts => {}
    }
    Ok(())
}

fn prepare(so_session: u32, request_der: &[u8]) -> Result<Prepared, u32> {
    // Step 1: SO + R/W + profile; base §9 preconditions before payload parsing.
    require_profile()?;
    let slot = require_so(so_session)?;
    if !enroll::hierarchy_ready(slot) {
        return Err(CKR_ACTION_PROHIBITED);
    }
    // Step 2: strict DER under §8 bounds, before allocation or signatures.
    let req: AdminSignedRequest = decode_strict(request_der, MAX_ADMIN_REQUEST_DER)?;
    let tbs = &req.tbs;
    if tbs.version != 1
        || tbs.device_id.as_bytes().len() != 32
        || tbs.admin_key_id.as_bytes().len() != 32
        || tbs.nonce.as_bytes().len() != 32
        || tbs.sequence == 0
        || tbs.sequence > MAX_SEQUENCE
        || req.signature_algorithm != pki::ml_dsa_65_alg()
        || req.signature.unused_bits() != 0
        || req.signature.raw_bytes().len() != SIG_LEN
    {
        return Err(CKR_DATA_INVALID);
    }
    let op = tbs.operation()?;
    check_payload_syntax(&op)?;
    let request_hash = super::sha384(request_der);
    let operation = op.name();

    // Step 3: committed retry first — no freshness, nonce or sequence check.
    for (_, e) in ledger(slot)? {
        if e.request_hash.as_bytes() == request_hash {
            if e.request.as_bytes() != request_der {
                return Err(CKR_DEVICE_ERROR); // hash collision or corrupted entry
            }
            let receipt = e.receipt.as_bytes().to_vec();
            return Ok(Prepared { slot, request_hash, replay: Some(receipt), staged: None, authority: None, sequence: e.sequence, nonce: [0; 32], operation });
        }
    }
    if tombstones(slot)?.iter().any(|t| t.request_hash.as_bytes() == request_hash) {
        return Err(refuse(slot, "request pruned (tombstone)"));
    }

    // Step 4: this device, the active authority.
    let own_id = super::enroll::device_id_of_slot(slot)?;
    if tbs.device_id.as_bytes() != own_id {
        return Err(refuse(slot, "request names another device"));
    }
    let auth = active_authority(slot)?.ok_or_else(|| refuse(slot, "no admin authority enrolled"))?;
    if tbs.admin_key_id.as_bytes() != auth.key_id {
        return Err(refuse(slot, "request names another admin key"));
    }

    // Step 5: authority chain and current root CRL (B2: a root CRL being
    // enrolled is verified first and used for this check).
    let now = now_unix();
    let trust: TrustInputs = enroll::trust_inputs(slot);
    let renewing = match &op {
        AdminOperation::EnrollCrl { crl, issuer_device_cert: None } => trust
            .roots
            .iter()
            .filter_map(|r| pki::parse_cert(r).ok())
            .find_map(|root| pki::verify_crl(crl, &root, now).ok())
            .filter(|v| v.number > enroll::stored_crl_number(slot, &v.issuer_key_id)),
        _ => None,
    };
    pki::validate_admin_authority_trusted(&auth.cert, &trust, renewing.as_ref(), now, Profile::Educational)
        .map_err(|r| refuse(slot, r.0))?;

    // Step 6: signature.
    let pk = pki::mldsa65_public(&auth.cert).map_err(|r| refuse(slot, r.0))?;
    let tbs_der = asn1::to_der(tbs)?;
    if !super::mldsa65_verify(pk, &signed_bytes(REQUEST_DOMAIN, &tbs_der), req.signature.raw_bytes()) {
        return Err(refuse(slot, "admin request signature"));
    }

    // Step 7: freshness.
    let nonce: [u8; 32] = tbs.nonce.as_bytes().try_into().map_err(|_| CKR_DATA_INVALID)?;
    if current_nonce(slot) != Some(nonce) {
        return Err(refuse(slot, "nonce not current"));
    }
    if auth.sequence >= MAX_SEQUENCE || tbs.sequence != auth.sequence + 1 {
        return Err(refuse(slot, "sequence is not stored + 1"));
    }

    // Step 8: operation-specific stage (writes nothing).
    let staged = match op {
        AdminOperation::EnrollCrl { crl, issuer_device_cert } => enroll::stage_enroll_crl(slot, &crl, issuer_device_cert.as_deref()),
        AdminOperation::EnrollPolicy { policy } => enroll::stage_enroll_policy(slot, &policy),
        AdminOperation::RotateRecoveryKey => enroll::stage_rotate_recovery_key(slot),
        AdminOperation::IssueFunctionCerts => enroll::stage_reissue_function_certificates(slot),
        AdminOperation::IssueDeviceCrl { revoke, retired_to_revoke, validity_seconds } => {
            // B-01: the active receipt-signing leaf signs this very receipt.
            if revoke.contains(&RevocablePurpose::ReceiptSigning) {
                return Err(refuse(slot, "revoking the active receipt-signing leaf"));
            }
            let purposes: Vec<Purpose> = revoke.iter().map(|p| p.purpose()).collect();
            enroll::stage_issue_device_crl(slot, &purposes, &retired_to_revoke, validity_seconds as u64)
        }
    }
    .map_err(|rv| collapse(slot, rv))?;
    let sequence = tbs.sequence;
    Ok(Prepared { slot, request_hash, replay: None, staged: Some(staged), authority: Some(auth), sequence, nonce, operation })
}

/// Build and sign the receipt with the CURRENT receipt-signing key (before
/// the commit, so for `issueFunctionCerts` the outgoing key signs). With
/// `sign == false` the signature is a zero placeholder of exact length.
fn receipt(slot: u32, p: &Prepared, staged: &Staged, sign: bool) -> Result<Vec<u8>, u32> {
    let chain = vec![
        pki::parse_cert(&records::certificate(slot, Purpose::ReceiptSigning).ok_or(CKR_DEVICE_ERROR)?).map_err(|_| CKR_DEVICE_ERROR)?,
        pki::parse_cert(&records::certificate(slot, Purpose::DeviceIssuer).ok_or(CKR_DEVICE_ERROR)?).map_err(|_| CKR_DEVICE_ERROR)?,
    ];
    let tbs = AdminTbsReceipt {
        version: 1,
        device_id: asn1::octets(&super::enroll::device_id_of_slot(slot)?),
        request_hash: asn1::octets(&p.request_hash),
        sequence: p.sequence,
        result_digest: asn1::octets(&staged.result_digest),
        output: staged.output.as_deref().map(asn1::octets),
        committed_at: gtime(now_unix())?,
        receipt_signer_chain: chain,
    };
    let tbs_der = asn1::to_der(&tbs)?;
    let sig = if sign {
        let (_, sk) = records::function_secret(slot, Purpose::ReceiptSigning).ok_or(CKR_DEVICE_ERROR)?;
        super::mldsa65_sign(&sk, &signed_bytes(RECEIPT_DOMAIN, &tbs_der))?
    } else {
        vec![0u8; SIG_LEN]
    };
    let der = asn1::to_der(&AdminReceipt {
        tbs,
        signature_algorithm: pki::ml_dsa_65_alg(),
        signature: BitString::from_bytes(&sig).map_err(|_| CKR_DEVICE_ERROR)?,
    })?;
    if der.len() > MAX_ADMIN_RECEIPT_DER {
        return Err(CKR_DEVICE_ERROR);
    }
    Ok(der)
}

/// `C_PQCTODAY_AdminExecute` (§2.1 ordinal 1): verify, stage and commit one
/// signed admin request; returns the DER `AdminReceipt`. An exact retry of a
/// committed request returns its stored receipt byte-for-byte.
pub fn execute(so_session: u32, request_der: &[u8]) -> Result<Vec<u8>, u32> {
    let _op = super::package::op_lock();
    let p = prepare(so_session, request_der)?;
    let slot = p.slot;
    if let Some(r) = p.replay {
        oplog_event("admin_execute", slot, &[("request_hash", super::hex(&p.request_hash)), ("result", "replayed".into())]);
        return Ok(r);
    }
    let staged = p.staged.as_ref().ok_or(CKR_DEVICE_ERROR)?;
    let auth = p.authority.as_ref().ok_or(CKR_DEVICE_ERROR)?;
    let receipt_der = receipt(slot, &p, staged, true)?;
    // §3.5 capacity, checked before the commit; never evicts.
    let entries = ledger(slot)?;
    let used: usize = records::list(slot, ROLE_ADMIN_LEDGER).iter().map(|(_, a)| records::record_bytes(a).len()).sum();
    let entry_der = asn1::to_der(&LedgerEntry {
        request_hash: asn1::octets(&p.request_hash),
        sequence: p.sequence,
        admin_key_id: asn1::octets(&auth.key_id),
        committed_at: now_unix(),
        operation: p.operation.to_string(),
        request: asn1::octets(request_der),
        receipt: asn1::octets(&receipt_der),
    })?;
    let audit = vec![
        ("request_hash", super::hex(&p.request_hash)),
        ("admin_key_id", super::hex(&auth.key_id)),
        ("sequence", p.sequence.to_string()),
        ("operation", p.operation.to_string()),
    ];
    if entries.len() >= MAX_LEDGER_ENTRIES || used + entry_der.len() > MAX_LEDGER_BYTES {
        oplog_event("admin_execute", slot, &[audit.as_slice(), &[("result", "ledger full".into())]].concat());
        return Err(CKR_DEVICE_MEMORY);
    }
    let ledger_obj = records::new_record(ROLE_ADMIN_LEDGER, CKO_DATA, "admin replay ledger entry", Vec::new(), entry_der, false);
    let seq_update = (auth.handle, vec![(CKA_PRIV_REPL_RECORD, asn1::to_der(&AuthorityRecord { active: true, sequence: p.sequence })?)]);
    let nonce = p.nonce;
    let staged = p.staged.ok_or(CKR_DEVICE_ERROR)?;
    // Step 9: ONE commit — staged effect + ledger/audit entry + new sequence.
    // The nonce is consumed only once that commit is durable.
    enroll::commit_staged(so_session, slot, staged, vec![ledger_obj], vec![seq_update]).map_err(|_| CKR_DEVICE_ERROR)?;
    consume_nonce(slot, &nonce);
    oplog_event("admin_execute", slot, &[audit.as_slice(), &[("result", "committed".into())]].concat());
    Ok(receipt_der)
}

/// Exact length of [`execute`]'s receipt for the same request (base §3
/// sizing): the same checks, the stage, and a receipt with a placeholder
/// signature of exact length — nothing is committed, the nonce stays current.
pub fn execute_len(so_session: u32, request_der: &[u8]) -> Result<usize, u32> {
    let _op = super::package::op_lock();
    let p = prepare(so_session, request_der)?;
    if let Some(r) = &p.replay {
        return Ok(r.len());
    }
    let staged = p.staged.as_ref().ok_or(CKR_DEVICE_ERROR)?;
    receipt(p.slot, &p, staged, false).map(|d| d.len())
}
