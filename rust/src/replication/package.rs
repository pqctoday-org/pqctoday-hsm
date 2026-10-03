//! K4 — protected replication: challenges, package creation, atomic import,
//! receipts, the consumption ledger and `CloneKey` (plan R3; spec §3, §5–§11).
//!
//! Ceremony (spec §5.1 as amended by review K0B-R-04/R-07):
//! 1. source:      [`issue_source_challenge`] → `sourceChallenge` (reserved, 5 min);
//! 2. destination: [`begin_receive`] → `ReplicationRequest` DER. The
//!    destination generates the transaction ID and `destinationChallenge`,
//!    reserves both durably, and signs evidence over `sourceChallenge`;
//! 3. source:      [`create_replication_package`] consumes `sourceChallenge`,
//!    verifies the destination, moves replica budget and caches the package;
//! 4. destination: [`import_replication_package`] verifies the source,
//!    reserves the transaction, decrypts, installs and commits atomically.
//!
//! Every trust, identity, recipient and policy refusal returns
//! `CKR_ACTION_PROHIBITED` (review K0B-R-13 collapses spec §9 items 9 and
//! 10); the specific reason goes to the audit log only.

use der::Decode;
use x509_cert::Certificate;

use super::asn1::{self, *};
use super::evidence::{self, EvidenceClaims, EvidenceRole};
use super::host_verify::{package_signed_bytes, receipt_signed_bytes};
use super::oids::{self, Purpose};
use super::pki::{self, Reject};
use super::records::{self, *};
use super::{crash_check, now_unix, oplog_event, require_profile, require_user, require_user_rw, CrashPoint, Profile};
use crate::constants::*;
use crate::crypto::handlers::{Attributes, ALGO_ML_DSA, ALGO_ML_KEM};
use crate::native::CKA_ID;
use crate::state::{store_bool, store_ulong};

pub const HPKE_INFO_LABEL: &[u8] = b"PQCToday Key Replication 1.0";
pub const MAX_REQUEST_DER: usize = 64 * 1024;
pub const MAX_PLAINTEXT: usize = 128 * 1024;
pub const MAX_PACKAGE_DER: usize = 256 * 1024;
pub const MAX_RECEIPT_DER: usize = 32 * 1024;
pub const ML_KEM_768_CT_LEN: usize = 1088;
pub const ML_DSA_65_SIG_LEN: usize = 3309;
/// Lifetime of a live challenge reservation (spec §5.1 freshness window).
pub const LIVE_CHALLENGE_SECS: u64 = evidence::FRESHNESS_SECS;
/// How long a source keeps a created package for byte-identical retry. Long
/// after the destination's live reservation and the evidence freshness
/// window, so a retained transaction ID can never be replayed into a new
/// package once its entry is pruned (review K0B-R2-04).
pub const CACHE_RETENTION_SECS: u64 = 3600;

/// Delete dead replication records on `slot`: consumed or expired
/// challenge reservations, and cached packages past retention. Ledger
/// entries are NEVER pruned (spec §10: no silent eviction).
fn prune(slot: u32) {
    let now = now_unix();
    for (h, r) in open_challenges(slot) {
        if r.consumed || now > r.expires_at {
            super::discard_object(h);
        }
    }
    for (h, a) in records::list(slot, ROLE_PACKAGE_CACHE) {
        let dead = PackageCacheRecord::from_der(records::record_bytes(&a))
            .map(|r| now >= r.created_at.saturating_add(CACHE_RETENTION_SECS))
            .unwrap_or(true);
        if dead {
            super::discard_object(h);
        }
    }
}

/// Cancel an abandoned, unconsumed destination reservation (for example an
/// offline backup that was never created). Refused once an import has
/// reserved or committed the transaction.
pub fn cancel_receive(user_session: u32, transaction_id: &[u8; 32]) -> Result<(), u32> {
    let _op = op_lock();
    require_profile()?;
    let slot = require_user_rw(user_session)?;
    if ledger_entry(slot, transaction_id).is_some() {
        return Err(CKR_ACTION_PROHIBITED);
    }
    let Some((h, _)) = open_challenges(slot)
        .into_iter()
        .find(|(_, r)| r.role == 1 && !r.consumed && r.transaction_id.as_bytes() == transaction_id)
    else {
        return Err(CKR_ACTION_PROHIBITED);
    };
    super::discard_object(h);
    oplog_event("receive_cancel", slot, &[("transaction", super::hex(transaction_id))]);
    Ok(())
}

/// Serializes every replication state transition in this process (plan
/// R3.6: concurrent calls on the same transaction). Held for the whole of a
/// challenge issue, receive, create or import, so two racing imports of one
/// package cannot both observe "no ledger entry".
static OP_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn op_lock() -> std::sync::MutexGuard<'static, ()> {
    OP_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

const LEDGER_RESERVED: u8 = 1;
const LEDGER_COMMITTED: u8 = 2;

fn deny<T>(slot: u32, why: Reject) -> Result<T, u32> {
    super::note_refusal(why.0);
    oplog_event("refused", slot, &[("reason", format!("\"{}\"", why.0))]);
    Err(CKR_ACTION_PROHIBITED)
}

fn f32(o: &der::asn1::OctetString) -> Result<[u8; 32], u32> {
    o.as_bytes().try_into().map_err(|_| CKR_DATA_INVALID)
}

fn f48(o: &der::asn1::OctetString) -> Result<[u8; 48], u32> {
    o.as_bytes().try_into().map_err(|_| CKR_DATA_INVALID)
}

fn ready(slot: u32) -> Result<(), u32> {
    if super::enroll::hierarchy_ready(slot) {
        Ok(())
    } else {
        Err(CKR_ACTION_PROHIBITED)
    }
}

fn gt(t: u64) -> Result<der::asn1::GeneralizedTime, u32> {
    der::asn1::GeneralizedTime::from_unix_duration(std::time::Duration::from_secs(t)).map_err(|_| CKR_DEVICE_ERROR)
}

// ── Challenge reservations (review K0B-R-04) ───────────────────────────────

fn open_challenges(slot: u32) -> Vec<(u32, ChallengeRecord)> {
    records::list(slot, ROLE_CHALLENGE)
        .into_iter()
        .filter_map(|(h, a)| ChallengeRecord::from_der(records::record_bytes(&a)).ok().map(|r| (h, r)))
        .collect()
}

fn reserve_challenge(session: u32, slot: u32, rec: ChallengeRecord) -> Result<(), u32> {
    let now = now_unix();
    if open_challenges(slot).iter().filter(|(_, r)| !r.consumed && r.expires_at >= now).count() >= MAX_OPEN_CHALLENGES {
        return Err(CKR_DEVICE_MEMORY);
    }
    let obj = records::new_record(ROLE_CHALLENGE, CKO_DATA, "challenge reservation", Vec::new(), asn1::to_der(&rec)?, true);
    crate::state::commit_objects_atomically(session, vec![obj], Vec::new())?;
    Ok(())
}

/// Source step 1: a fresh, recorded 32-byte challenge the destination's
/// evidence must sign. Expires after [`LIVE_CHALLENGE_SECS`]; one use.
pub fn issue_source_challenge(user_session: u32) -> Result<[u8; 32], u32> {
    let _op = op_lock();
    require_profile()?;
    let slot = require_user_rw(user_session)?;
    ready(slot)?;
    prune(slot);
    let c = super::random32()?;
    let now = now_unix();
    reserve_challenge(
        user_session,
        slot,
        ChallengeRecord {
            role: 0,
            challenge: asn1::octets(&c),
            transaction_id: asn1::octets(&[0u8; 32]),
            operation: Operation::LiveClone,
            requested_policy: asn1::octets(&[0u8; 48]),
            issued_at: now,
            expires_at: now + LIVE_CHALLENGE_SECS,
            consumed: false,
        },
    )?;
    oplog_event("challenge", slot, &[("role", "source".into())]);
    Ok(c)
}

/// Destination step 2: reserve a transaction and `destinationChallenge`,
/// and return the signed `ReplicationRequest` for the source.
///
/// The reservation lifetime is the freshness bound the import will apply:
/// five minutes for a live clone or restore, the requested policy's
/// `notAfter` for an offline backup (whose package is imported later).
pub fn begin_receive(
    user_session: u32,
    operation: Operation,
    source_challenge: &[u8; 32],
    domain_id: &[u8; 32],
    requested_policy: &[u8; 48],
) -> Result<Vec<u8>, u32> {
    let _op = op_lock();
    require_profile()?;
    let slot = require_user_rw(user_session)?;
    ready(slot)?;
    prune(slot);
    if *source_challenge == [0u8; 32] {
        return Err(CKR_ARGUMENTS_BAD);
    }
    let now = now_unix();
    let pol = records::parse_policy(&records::find_policy(slot, requested_policy).ok_or(CKR_ACTION_PROHIBITED)?)?;
    if !pol.permits(operation) || pol.domain != *domain_id || now < pol.not_before || now >= pol.not_after {
        return Err(CKR_ACTION_PROHIBITED);
    }
    let txid = super::random32()?;
    let dchal = super::random32()?;
    let expires_at = if operation == Operation::OfflineBackup { pol.not_after } else { now + LIVE_CHALLENGE_SECS };
    let (_, recovery_pub) = records::function_public(slot, Purpose::RecoveryRecipient).ok_or(CKR_ACTION_PROHIBITED)?;
    let claims = EvidenceClaims {
        nonce: *source_challenge,
        role: EvidenceRole::Destination,
        transaction_id: Some(txid),
        domain_id: Some(*domain_id),
        policy: Some(*requested_policy),
        device_id: evidence::platform_device_id(slot)?,
        engine: evidence::ENGINE_IDENTITY.to_string(),
        custody_scope: evidence::CUSTODY_SCOPE.to_string(),
        issued_at: now,
        key: evidence::key_claims_from(&recovery_pub)?,
    };
    let ev = Evidence::from_der(&evidence::sign_evidence(slot, &claims)?).map_err(|_| CKR_DEVICE_ERROR)?;
    let chain = pki::chain_from_ders(&super::enroll::function_chain(user_session, Purpose::RecoveryRecipient)?)
        .map_err(|_| CKR_DEVICE_ERROR)?;
    let req = ReplicationRequest {
        version: 1,
        operation,
        suite: oids::SUITE_V1,
        transaction_id: asn1::octets(&txid),
        source_challenge: asn1::octets(source_challenge),
        destination_challenge: asn1::octets(&dchal),
        domain_id: asn1::octets(domain_id),
        requested_policy: asn1::octets(requested_policy),
        recipient_chain: chain,
        recipient_evidence: ev,
    };
    let der = asn1::to_der(&req)?;
    reserve_challenge(
        user_session,
        slot,
        ChallengeRecord {
            role: 1,
            challenge: asn1::octets(&dchal),
            transaction_id: asn1::octets(&txid),
            operation,
            requested_policy: asn1::octets(requested_policy),
            issued_at: now,
            expires_at,
            consumed: false,
        },
    )?;
    oplog_event("receive_begin", slot, &[("transaction", super::hex(&txid)), ("operation", format!("{operation:?}"))]);
    Ok(der)
}

// ── Source side ─────────────────────────────────────────────────────────────

/// Payload attribute allowlist per key class (spec §6).
fn payload_allowlist(key_type: u32) -> &'static [u32] {
    match key_type {
        CKK_AES => &[CKA_ENCRYPT, CKA_DECRYPT, CKA_WRAP, CKA_UNWRAP, CKA_SIGN, CKA_VERIFY],
        CKK_ML_DSA => &[CKA_SIGN],
        CKK_ML_KEM => &[CKA_DECAPSULATE],
        _ => &[],
    }
}

/// Everything about the source key the package needs.
struct SourceKey {
    handle: u32,
    attrs: Attributes,
    key_type: u32,
    unique_id: String,
    policy_id: [u8; 48],
    lineage: [u8; 32],
    budget: u32,
}

/// Spec §9 items 3–6: session, role, visibility, eligibility.
fn source_key(session: u32, h_key: u32) -> Result<(u32, SourceKey), u32> {
    require_profile()?;
    let slot = require_user_rw(session)?;
    if !crate::state::can_access_handle(session, h_key) {
        return Err(CKR_KEY_HANDLE_INVALID);
    }
    let attrs = records::object_attrs(h_key).ok_or(CKR_KEY_HANDLE_INVALID)?;
    if crate::state::object_slot_of(&attrs) != slot {
        return Err(CKR_KEY_HANDLE_INVALID);
    }
    let key_type = crate::state::get_object_attr_u32_from(&attrs, CKA_KEY_TYPE).unwrap_or(u32::MAX);
    let class = crate::state::get_object_attr_u32_from(&attrs, CKA_CLASS).unwrap_or(u32::MAX);
    let ps = crate::state::get_object_param_set_from(&attrs);
    let eligible_type = matches!(
        (class, key_type),
        (CKO_SECRET_KEY, CKK_AES)
    ) || (class == CKO_PRIVATE_KEY && key_type == CKK_ML_KEM && ps == CKP_ML_KEM_768)
        || (class == CKO_PRIVATE_KEY && key_type == CKK_ML_DSA && ps == CKP_ML_DSA_65);
    let policy = attrs.get(&CKA_PQCTODAY_REPLICATION_POLICY_ID).cloned();
    let binding = attrs.get(&CKA_PRIV_REPL_BINDING).cloned();
    let b = |t| crate::state::read_bool_attr(&attrs, t);
    // Engine binding marker AND the public attribute must agree; a key
    // without both was never bound (plan invariants 1, 2, 12).
    let bound = policy.is_some() && policy == binding && records::role_of(&attrs).is_none();
    if !eligible_type || !bound || !b(CKA_SENSITIVE) || b(CKA_EXTRACTABLE) || b(CKA_COPYABLE) || b(CKA_MODIFIABLE) {
        return Err(CKR_KEY_FUNCTION_NOT_PERMITTED);
    }
    let policy_id: [u8; 48] = policy.unwrap().as_slice().try_into().map_err(|_| CKR_KEY_FUNCTION_NOT_PERMITTED)?;
    let lineage: [u8; 32] = attrs
        .get(&CKA_PQCTODAY_REPLICATION_LINEAGE_ID)
        .and_then(|v| v.as_slice().try_into().ok())
        .ok_or(CKR_KEY_FUNCTION_NOT_PERMITTED)?;
    let budget = attrs
        .get(&CKA_PRIV_REPL_BUDGET)
        .and_then(|v| v.as_slice().try_into().ok())
        .map(u32::from_le_bytes)
        .unwrap_or(0);
    let unique_id = String::from_utf8(attrs.get(&CKA_UNIQUE_ID).cloned().unwrap_or_default()).map_err(|_| CKR_DEVICE_ERROR)?;
    Ok((slot, SourceKey { handle: h_key, attrs, key_type, unique_id, policy_id, lineage, budget }))
}

/// Spec §9 item 7: bounded canonical request DER, version, suite, sizes.
fn parse_request(request: &[u8]) -> Result<ReplicationRequest, u32> {
    let req: ReplicationRequest = asn1::decode_strict(request, MAX_REQUEST_DER)?;
    if req.version != 1 || req.suite != oids::SUITE_V1 || req.recipient_chain.len() != 2 {
        return Err(CKR_DATA_INVALID);
    }
    f32(&req.transaction_id)?;
    f32(&req.source_challenge)?;
    f32(&req.destination_challenge)?;
    f32(&req.domain_id)?;
    f48(&req.requested_policy)?;
    Ok(req)
}

fn cached_package(slot: u32, txid: &[u8; 32]) -> Option<(u32, PackageCacheRecord)> {
    records::list(slot, ROLE_PACKAGE_CACHE).into_iter().find_map(|(h, a)| {
        PackageCacheRecord::from_der(records::record_bytes(&a))
            .ok()
            .filter(|r| r.transaction_id.as_bytes() == txid)
            .map(|r| (h, r))
    })
}

/// Exact-retry check (spec §3.1; review K0B-R-07): a cached package for this
/// transaction is returned only for the identical request and source key.
fn cache_hit(slot: u32, req: &ReplicationRequest, request: &[u8], key: &SourceKey) -> Result<Option<Vec<u8>>, u32> {
    let txid = f32(&req.transaction_id)?;
    match cached_package(slot, &txid) {
        None => Ok(None),
        Some((_, rec)) => {
            if rec.request_hash.as_bytes() == super::sha384(request) && rec.source_unique_id == key.unique_id {
                Ok(Some(rec.package.as_bytes().to_vec()))
            } else {
                deny(slot, Reject("transaction ID reused with a different request or key"))
            }
        }
    }
}

fn build_payload(key: &SourceKey) -> Result<Vec<u8>, u32> {
    let value = key.attrs.get(&CKA_VALUE).cloned().ok_or(CKR_DEVICE_ERROR)?;
    let (class, paired) = match key.key_type {
        CKK_AES => (KeyClass::SecretKey, None),
        _ => {
            // The paired public value: the canonical raw key inside the SPKI.
            let spki = key.attrs.get(&CKA_PUBLIC_KEY_INFO).ok_or(CKR_DEVICE_ERROR)?;
            let s = super::test_ca::spki_of(spki)?;
            (KeyClass::PrivateKey, Some(asn1::octets(s.subject_public_key.raw_bytes())))
        }
    };
    let attributes = payload_allowlist(key.key_type)
        .iter()
        .map(|t| ReplicatedAttribute {
            attr_type: *t,
            value: asn1::octets(&[crate::state::read_bool_attr(&key.attrs, *t) as u8]),
        })
        .collect();
    let p = ReplicatedKeyPayload {
        version: 1,
        key_class: class,
        key_type: key.key_type,
        protected_value: asn1::octets(&value),
        paired_public: paired,
        attributes,
        type_extension: None,
    };
    asn1::to_der(&p)
}

/// Assemble a package; with `sign == false` every signature, encapsulation
/// and ciphertext is a zero placeholder of the exact final length (sizing
/// performs no cryptography and consumes no randomness).
struct Assembly {
    header: ReplicationProtectedHeader,
    payload_len: usize,
}

fn assemble(slot: u32, key: &SourceKey, req: &ReplicationRequest, budget_out: u32, issued_at: u64, sign: bool) -> Result<(Assembly, EvidenceClaims), u32> {
    let txid = f32(&req.transaction_id)?;
    let claims = EvidenceClaims {
        nonce: f32(&req.destination_challenge)?,
        role: EvidenceRole::Source,
        transaction_id: Some(txid),
        domain_id: Some(f32(&req.domain_id)?),
        policy: Some(key.policy_id),
        device_id: evidence::platform_device_id(slot)?,
        engine: evidence::ENGINE_IDENTITY.to_string(),
        custody_scope: evidence::CUSTODY_SCOPE.to_string(),
        issued_at,
        key: evidence::key_claims_from(&key.attrs)?,
    };
    let source_evidence = if sign {
        Evidence::from_der(&evidence::sign_evidence(slot, &claims)?).map_err(|_| CKR_DEVICE_ERROR)?
    } else {
        // Same shape and lengths as the signed evidence.
        let leaf = pki::parse_cert(&records::certificate(slot, Purpose::KeyAttestation).ok_or(CKR_DEVICE_ERROR)?).map_err(|_| CKR_DEVICE_ERROR)?;
        let dev = pki::parse_cert(&records::certificate(slot, Purpose::DeviceIssuer).ok_or(CKR_DEVICE_ERROR)?).map_err(|_| CKR_DEVICE_ERROR)?;
        Evidence {
            tbs: evidence::encode_tbs(&claims)?,
            signatures: vec![SignatureBlock {
                sid: SignerIdentifier { key_id: None, subject_public_key_info: None, certificate: Some(leaf) },
                signature_algorithm: asn1::ml_dsa_65_alg(),
                signature_value: asn1::octets(&[0u8; ML_DSA_65_SIG_LEN]),
            }],
            intermediate_certificates: Some(vec![dev]),
        }
    };
    let recipient_leaf = &req.recipient_chain[0];
    let header = ReplicationProtectedHeader {
        version: 1,
        operation: req.operation,
        suite: oids::SUITE_V1,
        transaction_id: req.transaction_id.clone(),
        domain_id: req.domain_id.clone(),
        source_unique_id: key.unique_id.clone(),
        lineage_id: asn1::octets(&key.lineage),
        source_policy: asn1::octets(&key.policy_id),
        destination_policy: req.requested_policy.clone(),
        recipient_key_hash: asn1::octets(&pki::spki_hash(recipient_leaf)),
        transferred_budget: budget_out,
        source_chain: pki::chain_from_ders(&[
            records::certificate(slot, Purpose::PackageSigning).ok_or(CKR_DEVICE_ERROR)?,
            records::certificate(slot, Purpose::DeviceIssuer).ok_or(CKR_DEVICE_ERROR)?,
        ])
        .map_err(|_| CKR_DEVICE_ERROR)?,
        source_evidence,
        type_extension_hash: asn1::octets(&super::sha384(b"")),
    };
    let payload_len = build_payload(key)?.len();
    Ok((Assembly { header, payload_len }, claims))
}

fn finish_unsigned(a: &Assembly) -> Result<Vec<u8>, u32> {
    let p = ReplicationPackage {
        tbs: ReplicationPackageTbs {
            header: a.header.clone(),
            encapsulated: asn1::octets(&[0u8; ML_KEM_768_CT_LEN]),
            ciphertext: asn1::octets(&vec![0u8; a.payload_len + 16]),
        },
        signature_algorithm: asn1::ml_dsa_65_alg(),
        signature: der::asn1::BitString::from_bytes(&[0u8; ML_DSA_65_SIG_LEN]).map_err(|_| CKR_DEVICE_ERROR)?,
    };
    asn1::to_der(&p)
}

/// The budget this export transfers, without validating trust: the
/// requested policy's quota, capped so source + all descendants never exceed
/// the source's remaining budget (review K0B-R-12 conservation rule).
fn transfer_budget(slot: u32, key: &SourceKey, req: &ReplicationRequest) -> u32 {
    // Review K0B-R2-10: the destination chooses the requested policy, so it
    // must not choose how much budget leaves the source. Version 1 transfers
    // exactly one replica right to an offline backup (so the backup HSM can
    // restore onward) and nothing to a live clone or restore target.
    if req.operation != Operation::OfflineBackup {
        return 0;
    }
    let requested_max = records::find_policy(slot, req.requested_policy.as_bytes())
        .and_then(|d| records::parse_policy(&d).ok())
        .map(|p| p.max_replicas)
        .unwrap_or(0);
    1u32.min(requested_max).min(key.budget.saturating_sub(1))
}

/// `C_PQCTODAY_CreateReplicationPackage` sizing: the exact length the
/// package will have. No randomness, cryptography, authorization
/// consumption or ledger mutation (spec §3.1).
pub fn replication_package_length(session: u32, h_key: u32, request: &[u8]) -> Result<usize, u32> {
    let (slot, key) = source_key(session, h_key)?;
    let req = parse_request(request)?;
    ready(slot)?;
    if let Some(p) = cache_hit(slot, &req, request, &key)? {
        return Ok(p.len());
    }
    let (a, _) = assemble(slot, &key, &req, transfer_budget(slot, &key, &req), now_unix(), false)?;
    Ok(finish_unsigned(&a)?.len())
}

/// Source step 3 (`C_PQCTODAY_CreateReplicationPackage`, sufficient buffer).
pub fn create_replication_package(session: u32, h_key: u32, request: &[u8]) -> Result<Vec<u8>, u32> {
    let _op = op_lock();
    let (slot, key) = source_key(session, h_key)?;
    let req = parse_request(request)?;
    ready(slot)?;
    if let Some(p) = cache_hit(slot, &req, request, &key)? {
        oplog_event("package_retry", slot, &[("transaction", super::hex(req.transaction_id.as_bytes()))]);
        return Ok(p);
    }
    let now = now_unix();
    let txid = f32(&req.transaction_id)?;
    let trust = super::enroll::trust_inputs(slot);

    // Source policy and operation.
    let src_pol = records::parse_policy(&records::find_policy(slot, &key.policy_id).ok_or(CKR_KEY_FUNCTION_NOT_PERMITTED)?)?;
    if !src_pol.permits(req.operation) || now < src_pol.not_before || now >= src_pol.not_after {
        return deny(slot, Reject("source policy does not permit operation now"));
    }
    if req.domain_id.as_bytes() != src_pol.domain {
        return deny(slot, Reject("domain"));
    }
    // Requested destination policy: enrolled here too, equal or stricter.
    let Some(dst_der) = records::find_policy(slot, req.requested_policy.as_bytes()) else {
        return deny(slot, Reject("requested policy not enrolled at source"));
    };
    let dst_pol = records::parse_policy(&dst_der)?;
    if !dst_pol.is_equal_or_stricter_than(&src_pol) || !dst_pol.permits(req.operation) {
        return deny(slot, Reject("requested policy weakens the source policy"));
    }
    // Destination identity: recovery chain and fresh evidence.
    let rchain = match pki::validate_chain(&req.recipient_chain, Purpose::RecoveryRecipient, &trust, now, Profile::Educational) {
        Ok(c) => c,
        Err(e) => return deny(slot, e),
    };
    let src_chal = f32(&req.source_challenge)?;
    let ev = match evidence::verify_evidence_core(
        &asn1::to_der(&req.recipient_evidence)?,
        &trust,
        now,
        Profile::Educational,
        EvidenceRole::Destination,
        &src_chal,
        None,
    ) {
        Ok(v) => v,
        Err(e) => return deny(slot, e),
    };
    let c = &ev.claims;
    if ev.chain.device_id != rchain.device_id {
        return deny(slot, Reject("destination evidence and recovery chain name different devices"));
    }
    if c.transaction_id != Some(txid)
        || c.domain_id != Some(src_pol.domain)
        || c.policy.as_ref().map(|p| p.as_slice()) != Some(req.requested_policy.as_bytes())
        || c.key.public_hash != Some(pki::spki_hash(&rchain.leaf))
    {
        return deny(slot, Reject("destination evidence binding"));
    }
    // Peer allowlist and same-device rule (spec §3.3).
    let own_device = evidence::platform_device_id(slot)?;
    if !src_pol.peers.contains(&rchain.device_id) {
        return deny(slot, Reject("destination device not in source policy allowlist"));
    }
    if rchain.device_id == own_device && !(src_pol.allow_same_device && dst_pol.allow_same_device) {
        return deny(slot, Reject("same-device replication not permitted"));
    }
    // Challenge reservation: issued here, unused, unexpired (K0B-R-04).
    let Some((chal_h, chal)) = open_challenges(slot)
        .into_iter()
        .find(|(_, r)| r.role == 0 && r.challenge.as_bytes() == src_chal)
    else {
        return deny(slot, Reject("source challenge was not issued by this token"));
    };
    if chal.consumed || now > chal.expires_at {
        return deny(slot, Reject("source challenge consumed or expired"));
    }
    // Budget (K0B-R-12): this export costs one plus whatever it transfers.
    if key.budget == 0 {
        return deny(slot, Reject("replica budget exhausted"));
    }
    let transferred = transfer_budget(slot, &key, &req);
    let remaining = key.budget - 1 - transferred;
    prune(slot);
    if records::list(slot, ROLE_PACKAGE_CACHE).len() >= MAX_CACHED_PACKAGES {
        return Err(CKR_DEVICE_MEMORY);
    }

    // Seal and sign.
    let (a, _) = assemble(slot, &key, &req, transferred, now, true)?;
    let h_der = asn1::to_der(&a.header)?;
    let mut info = HPKE_INFO_LABEL.to_vec();
    info.push(0);
    info.extend_from_slice(&super::sha384(&h_der));
    let ek = pki::mlkem768_public(&rchain.leaf).map_err(|_| CKR_DEVICE_ERROR)?.to_vec();
    let mut payload = build_payload(&key)?;
    let sealed = crate::native::hpke::seal_replication_v1(&ek, &info, &h_der, &payload);
    zeroize::Zeroize::zeroize(&mut payload);
    let (enc, ct) = sealed.map_err(|_| CKR_DEVICE_ERROR)?;
    let tbs = ReplicationPackageTbs { header: a.header, encapsulated: asn1::octets(&enc), ciphertext: asn1::octets(&ct) };
    let tbs_der = asn1::to_der(&tbs)?;
    let (_, signer) = records::function_secret(slot, Purpose::PackageSigning).ok_or(CKR_DEVICE_ERROR)?;
    let sig = super::mldsa65_sign(&signer, &package_signed_bytes(&tbs_der))?;
    let pkg = asn1::to_der(&ReplicationPackage {
        tbs,
        signature_algorithm: asn1::ml_dsa_65_alg(),
        signature: der::asn1::BitString::from_bytes(&sig).map_err(|_| CKR_DEVICE_ERROR)?,
    })?;
    if pkg.len() > MAX_PACKAGE_DER {
        return Err(CKR_DEVICE_ERROR);
    }
    crash_check(CrashPoint::CreateBeforeCommit)?;

    // One commit: cache entry, consumed challenge, decremented budget.
    let cache = PackageCacheRecord {
        transaction_id: asn1::octets(&txid),
        request_hash: asn1::octets(&super::sha384(request)),
        source_unique_id: key.unique_id.clone(),
        package: asn1::octets(&pkg),
        created_at: now,
    };
    let cache_obj = records::new_record(ROLE_PACKAGE_CACHE, CKO_DATA, "cached replication package (ciphertext)", Vec::new(), asn1::to_der(&cache)?, true);
    let used = ChallengeRecord { consumed: true, transaction_id: asn1::octets(&txid), ..chal };
    crate::state::commit_objects_atomically(
        session,
        vec![cache_obj],
        vec![
            (chal_h, vec![(CKA_PRIV_REPL_RECORD, asn1::to_der(&used)?)]),
            (key.handle, vec![(CKA_PRIV_REPL_BUDGET, remaining.to_le_bytes().to_vec())]),
        ],
    )?;
    oplog_event(
        "package_create",
        slot,
        &[
            ("transaction", super::hex(&txid)),
            ("source_unique_id", key.unique_id.clone()),
            ("destination_device", super::hex(&rchain.device_id)),
            ("transferred_budget", transferred.to_string()),
            ("package_sha384", super::hex(&super::sha384(&pkg))),
        ],
    );
    Ok(pkg)
}

// ── Destination side ────────────────────────────────────────────────────────

/// Template entries an import may carry (spec §8): labels/ids, and usage
/// flags only when they TIGHTEN (FALSE).
fn validate_import_template(template: &[(u32, Vec<u8>)]) -> Result<(), u32> {
    const TIGHTEN_ONLY: &[u32] = &[CKA_ENCRYPT, CKA_DECRYPT, CKA_WRAP, CKA_UNWRAP, CKA_SIGN, CKA_VERIFY, CKA_DECAPSULATE, CKA_ENCAPSULATE];
    for (t, v) in template {
        match *t {
            CKA_LABEL | CKA_ID => {}
            t if TIGHTEN_ONLY.contains(&t) => {
                if v.as_slice() != [0] {
                    return Err(CKR_TEMPLATE_INCONSISTENT);
                }
            }
            _ => return Err(CKR_TEMPLATE_INCONSISTENT),
        }
    }
    Ok(())
}

fn parse_package(package: &[u8]) -> Result<ReplicationPackage, u32> {
    let p: ReplicationPackage = asn1::decode_strict(package, MAX_PACKAGE_DER)?;
    let h = &p.tbs.header;
    if h.version != 1 || h.suite != oids::SUITE_V1 || p.signature_algorithm != asn1::ml_dsa_65_alg() || h.source_chain.len() != 2 {
        return Err(CKR_DATA_INVALID);
    }
    f32(&h.transaction_id)?;
    f32(&h.domain_id)?;
    f32(&h.lineage_id)?;
    f48(&h.source_policy)?;
    f48(&h.destination_policy)?;
    f48(&h.recipient_key_hash)?;
    f48(&h.type_extension_hash)?;
    if h.source_unique_id.len() != 36 {
        return Err(CKR_DATA_INVALID);
    }
    // Review K0B-R-06: component lengths are checked before any cryptography.
    let ct_len = p.tbs.ciphertext.as_bytes().len();
    if p.tbs.encapsulated.as_bytes().len() != ML_KEM_768_CT_LEN || ct_len < 16 || ct_len > MAX_PLAINTEXT + 16 {
        return Err(CKR_DATA_INVALID);
    }
    Ok(p)
}

fn ledger_entry(slot: u32, txid: &[u8; 32]) -> Option<(u32, LedgerRecord)> {
    records::list(slot, ROLE_LEDGER).into_iter().find_map(|(h, a)| {
        LedgerRecord::from_der(records::record_bytes(&a))
            .ok()
            .filter(|r| r.transaction_id.as_bytes() == txid)
            .map(|r| (h, r))
    })
}

fn find_by_unique_id(slot: u32, uid: &str) -> Option<u32> {
    crate::state::OBJECTS.with(|o| {
        o.borrow()
            .iter()
            .find(|(_, a)| crate::state::object_slot_of(a) == slot && a.get(&CKA_UNIQUE_ID).map(|v| v.as_slice()) == Some(uid.as_bytes()))
            .map(|(h, _)| *h)
    })
}

/// Fixed receipt length for this destination slot (spec §3.2 sizing call).
pub fn receipt_length_for_slot(slot: u32) -> Result<usize, u32> {
    let chain = pki::chain_from_ders(&[
        records::certificate(slot, Purpose::ReceiptSigning).ok_or(CKR_ACTION_PROHIBITED)?,
        records::certificate(slot, Purpose::DeviceIssuer).ok_or(CKR_ACTION_PROHIBITED)?,
    ])
    .map_err(|_| CKR_DEVICE_ERROR)?;
    let r = ReplicationReceipt {
        tbs: ReplicationReceiptTbs {
            version: 1,
            suite: oids::SUITE_V1,
            transaction_id: asn1::octets(&[0u8; 32]),
            package_hash: asn1::octets(&[0u8; 48]),
            destination_device_id: asn1::octets(&[0u8; 32]),
            installed_unique_id: "0".repeat(36),
            lineage_id: asn1::octets(&[0u8; 32]),
            installed_policy: asn1::octets(&[0u8; 48]),
            committed_at: gt(now_unix())?,
            receipt_signer_chain: chain,
        },
        signature_algorithm: asn1::ml_dsa_65_alg(),
        signature: der::asn1::BitString::from_bytes(&[0u8; ML_DSA_65_SIG_LEN]).map_err(|_| CKR_DEVICE_ERROR)?,
    };
    Ok(asn1::to_der(&r)?.len())
}

/// `C_PQCTODAY_ImportReplicationPackage` sizing: validates the package's DER
/// shape, then reports the exact receipt length. Creates nothing.
pub fn replication_receipt_length(session: u32, package: &[u8]) -> Result<usize, u32> {
    require_profile()?;
    let slot = require_user_rw(session)?;
    parse_package(package)?; // §9 item 7 before any state check
    ready(slot)?;
    receipt_length_for_slot(slot)
}

/// Validated, decrypted key material ready to install.
struct Staged {
    key_type: u32,
    secret: Vec<u8>,
    public: Option<Vec<u8>>,
    usage: Vec<(u32, bool)>,
}

impl Drop for Staged {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.secret);
    }
}

/// Spec §6 payload validation, including the engine's full private/public
/// consistency checks (spec §6 "the importer performs...").
fn validate_payload(pt: &[u8], ev_key: &evidence::KeyClaims) -> Result<Staged, u32> {
    let bad = CKR_ENCRYPTED_DATA_INVALID;
    let p: ReplicatedKeyPayload = asn1::decode_strict(pt, MAX_PLAINTEXT).map_err(|_| bad)?;
    if p.version != 1 || p.type_extension.is_some() {
        return Err(bad);
    }
    let secret = p.protected_value.as_bytes().to_vec();
    let public = p.paired_public.as_ref().map(|o| o.as_bytes().to_vec());
    match (p.key_class, p.key_type) {
        (KeyClass::SecretKey, CKK_AES) => {
            if ![16, 24, 32].contains(&secret.len()) || public.is_some() || ev_key.parameter_set != secret.len() as u32 {
                return Err(bad);
            }
        }
        (KeyClass::PrivateKey, CKK_ML_KEM) => {
            let pk = public.as_deref().ok_or(bad)?;
            if secret.len() != 2400 || pk.len() != 1184 || ev_key.parameter_set != CKP_ML_KEM_768 {
                return Err(bad);
            }
            // FIPS 203 §7.3 checks; the embedded ek must be the paired one.
            if crate::native::keygen::ml_kem_dk_check(CKP_ML_KEM_768, &secret) != Some(true)
                || crate::native::keygen::ml_kem_ek_check(CKP_ML_KEM_768, pk) != Some(true)
                || &secret[1152..1152 + 1184] != pk
            {
                return Err(bad);
            }
            if ev_key.public_hash != Some(super::sha384(&crate::crypto::handlers::build_mlkem768_spki(pk))) {
                return Err(bad);
            }
        }
        (KeyClass::PrivateKey, CKK_ML_DSA) => {
            use fips204::traits::{SerDes, Signer};
            let pk = public.as_deref().ok_or(bad)?;
            if secret.len() != 4032 || pk.len() != 1952 || ev_key.parameter_set != CKP_ML_DSA_65 {
                return Err(bad);
            }
            let arr: [u8; 4032] = secret.as_slice().try_into().map_err(|_| bad)?;
            let sk = fips204::ml_dsa_65::PrivateKey::try_from_bytes(arr).map_err(|_| bad)?;
            if sk.get_public_key().into_bytes().as_slice() != pk {
                return Err(bad);
            }
            if ev_key.public_hash != Some(super::sha384(&crate::crypto::handlers::build_mldsa65_spki(pk))) {
                return Err(bad);
            }
        }
        _ => return Err(bad),
    }
    if p.key_type != ev_key.key_type {
        return Err(bad);
    }
    let allow = payload_allowlist(p.key_type);
    if p.attributes.is_empty() || p.attributes.len() > 64 || p.attributes.windows(2).any(|w| w[0].attr_type >= w[1].attr_type) {
        return Err(bad);
    }
    let mut usage = Vec::new();
    for a in &p.attributes {
        let v = a.value.as_bytes();
        if !allow.contains(&a.attr_type) || v.len() != 1 || v[0] > 1 {
            return Err(bad);
        }
        usage.push((a.attr_type, v[0] == 1));
    }
    Ok(Staged { key_type: p.key_type, secret, public, usage })
}

/// Build the installed private/secret object and its public partner.
fn installed_objects(
    st: &Staged,
    header: &ReplicationProtectedHeader,
    dst_policy: &PolicyView,
    provenance: Vec<u8>,
    unique_id: Vec<u8>,
    template: &[(u32, Vec<u8>)],
) -> (Attributes, Option<Attributes>) {
    let mut a: Attributes = Default::default();
    let lineage = header.lineage_id.as_bytes().to_vec();
    let (class, ps, algo) = match st.key_type {
        CKK_AES => (CKO_SECRET_KEY, 0, 0),
        CKK_ML_KEM => (CKO_PRIVATE_KEY, CKP_ML_KEM_768, ALGO_ML_KEM),
        _ => (CKO_PRIVATE_KEY, CKP_ML_DSA_65, ALGO_ML_DSA),
    };
    store_ulong(&mut a, CKA_CLASS, class);
    store_ulong(&mut a, CKA_KEY_TYPE, st.key_type);
    if ps != 0 {
        crate::state::store_param_set(&mut a, ps);
        crate::state::store_algo_family(&mut a, algo);
        store_ulong(&mut a, CKA_PARAMETER_SET, ps);
    } else {
        store_ulong(&mut a, CKA_VALUE_LEN, st.secret.len() as u32);
    }
    store_bool(&mut a, CKA_TOKEN, true);
    store_bool(&mut a, CKA_PRIVATE, true);
    store_bool(&mut a, CKA_SENSITIVE, true);
    store_bool(&mut a, CKA_EXTRACTABLE, false);
    store_bool(&mut a, CKA_COPYABLE, false);
    store_bool(&mut a, CKA_MODIFIABLE, false);
    store_bool(&mut a, CKA_DERIVE, false);
    // Owner decision 1: imported history plus separate provenance.
    store_bool(&mut a, CKA_LOCAL, false);
    store_bool(&mut a, CKA_ALWAYS_SENSITIVE, false);
    store_bool(&mut a, CKA_NEVER_EXTRACTABLE, false);
    store_ulong(&mut a, CKA_KEY_GEN_MECHANISM, CKM_UNAVAILABLE_INFORMATION);
    for (t, v) in &st.usage {
        let tightened = template.iter().any(|(tt, tv)| tt == t && tv.as_slice() == [0]);
        store_bool(&mut a, *t, *v && !tightened);
    }
    a.insert(CKA_VALUE, st.secret.clone());
    a.insert(CKA_UNIQUE_ID, unique_id);
    a.insert(CKA_PQCTODAY_REPLICATION_POLICY_ID, dst_policy.id.to_vec());
    a.insert(CKA_PRIV_REPL_BINDING, dst_policy.id.to_vec());
    a.insert(CKA_PQCTODAY_REPLICATION_LINEAGE_ID, lineage.clone());
    a.insert(CKA_PQCTODAY_REPLICATION_PROVENANCE, provenance);
    a.insert(CKA_PRIV_REPL_BUDGET, header.transferred_budget.to_le_bytes().to_vec());
    a.insert(CKA_ALLOWED_MECHANISMS, records::encode_mechanisms(&dst_policy.allowed_mechanisms));
    for (t, v) in template {
        if *t == CKA_LABEL || *t == CKA_ID {
            a.insert(*t, v.clone());
        }
    }
    if st.key_type == CKK_AES {
        crate::state::compute_kcv(&mut a);
        return (a, None);
    }
    let pk = st.public.clone().unwrap_or_default();
    let spki = if st.key_type == CKK_ML_KEM {
        crate::crypto::handlers::build_mlkem768_spki(&pk)
    } else {
        crate::crypto::handlers::build_mldsa65_spki(&pk)
    };
    a.insert(CKA_PUBLIC_KEY_INFO, spki.clone());
    // Review K0B-R-11: the public partner is a token object sharing CKA_ID
    // and the lineage, so it is found deterministically from the private key.
    let mut p: Attributes = Default::default();
    store_ulong(&mut p, CKA_CLASS, CKO_PUBLIC_KEY);
    store_ulong(&mut p, CKA_KEY_TYPE, st.key_type);
    crate::state::store_param_set(&mut p, ps);
    crate::state::store_algo_family(&mut p, algo);
    store_ulong(&mut p, CKA_PARAMETER_SET, ps);
    store_bool(&mut p, CKA_TOKEN, true);
    store_bool(&mut p, CKA_PRIVATE, false);
    store_bool(&mut p, CKA_MODIFIABLE, false);
    store_bool(&mut p, CKA_LOCAL, false);
    store_ulong(&mut p, CKA_KEY_GEN_MECHANISM, CKM_UNAVAILABLE_INFORMATION);
    store_bool(&mut p, CKA_VERIFY, st.key_type == CKK_ML_DSA);
    store_bool(&mut p, CKA_ENCAPSULATE, st.key_type == CKK_ML_KEM);
    store_bool(&mut p, CKA_ENCRYPT, false);
    store_bool(&mut p, CKA_WRAP, false);
    store_bool(&mut p, CKA_DERIVE, false);
    p.insert(CKA_VALUE, pk);
    p.insert(CKA_PUBLIC_KEY_INFO, spki);
    p.insert(CKA_PQCTODAY_REPLICATION_LINEAGE_ID, lineage);
    for (t, v) in template {
        if *t == CKA_LABEL || *t == CKA_ID {
            p.insert(*t, v.clone());
        }
    }
    (a, Some(p))
}

/// Destination step 4 (`C_PQCTODAY_ImportReplicationPackage`, execution
/// call). Returns the installed private/secret handle and the signed receipt.
///
/// An exact retry of a committed transaction is the recovery operation: it
/// returns the existing object and the byte-identical stored receipt without
/// decrypting again. A retry after a crash BEFORE the commit (state
/// "reserved") re-runs the import from the beginning (review K0B-R-09).
pub fn import_replication_package(session: u32, package: &[u8], template: &[(u32, Vec<u8>)]) -> Result<(u32, Vec<u8>), u32> {
    let _op = op_lock();
    require_profile()?;
    let slot = require_user_rw(session)?;
    let pkg = parse_package(package)?;
    ready(slot)?;
    validate_import_template(template)?;
    let h = &pkg.tbs.header;
    let txid = f32(&h.transaction_id)?;
    let pkg_hash = super::sha384(package);
    let now = now_unix();

    // Recovery path / conflicting transaction.
    let existing = ledger_entry(slot, &txid);
    if let Some((_, rec)) = &existing {
        if rec.package_hash.as_bytes() != pkg_hash {
            return deny(slot, Reject("different package for a reserved/consumed transaction"));
        }
        if rec.state == LEDGER_COMMITTED {
            let Some(handle) = find_by_unique_id(slot, &rec.installed_unique_id) else {
                // Terminal: the replica was deleted; consumption is never cleared.
                return deny(slot, Reject("committed replica no longer present"));
            };
            oplog_event("receipt_recovery", slot, &[("transaction", super::hex(&txid))]);
            return Ok((handle, rec.receipt.as_bytes().to_vec()));
        }
    }

    // Destination reservation for this transaction.
    let Some((chal_h, chal)) = open_challenges(slot)
        .into_iter()
        .find(|(_, r)| r.role == 1 && r.transaction_id.as_bytes() == txid)
    else {
        return deny(slot, Reject("no destination reservation for transaction"));
    };
    if chal.consumed || now > chal.expires_at {
        return deny(slot, Reject("destination reservation consumed or expired"));
    }
    if chal.operation != h.operation || chal.requested_policy.as_bytes() != h.destination_policy.as_bytes() {
        return deny(slot, Reject("package operation/policy differs from reservation"));
    }
    // Recipient binding: the current recovery key, or a retained retired
    // one (rotation continuity, plan R3.5).
    let Some(recovery_dk) = records::recovery_secret_for(slot, h.recipient_key_hash.as_bytes()) else {
        return deny(slot, Reject("package is for a different recipient"));
    };
    // Source chain, package signature, source evidence.
    let trust = super::enroll::trust_inputs(slot);
    let schain = match pki::validate_chain(&h.source_chain, Purpose::PackageSigning, &trust, now, Profile::Educational) {
        Ok(c) => c,
        Err(e) => return deny(slot, e),
    };
    let tbs_der = asn1::to_der(&pkg.tbs)?;
    let signer_pk = pki::mldsa65_public(&schain.leaf).map_err(|_| CKR_DEVICE_ERROR)?;
    if pkg.signature.unused_bits() != 0 || !super::mldsa65_verify(signer_pk, &package_signed_bytes(&tbs_der), pkg.signature.raw_bytes()) {
        return deny(slot, Reject("package signature"));
    }
    let dchal = f32(&chal.challenge)?;
    let ev = match evidence::verify_evidence_core(
        &asn1::to_der(&h.source_evidence)?,
        &trust,
        now,
        Profile::Educational,
        EvidenceRole::Source,
        &dchal,
        Some((chal.issued_at, chal.expires_at)),
    ) {
        Ok(v) => v,
        Err(e) => return deny(slot, e),
    };
    let c = &ev.claims;
    if ev.chain.device_id != schain.device_id {
        return deny(slot, Reject("source evidence and package signer name different devices"));
    }
    let src_policy = f48(&h.source_policy)?;
    if c.transaction_id != Some(txid)
        || c.domain_id.as_ref().map(|d| d.as_slice()) != Some(h.domain_id.as_bytes())
        || c.policy != Some(src_policy)
        || c.key.unique_id != h.source_unique_id
        || c.key.lineage.as_ref().map(|l| l.as_slice()) != Some(h.lineage_id.as_bytes())
        || c.key.policy != Some(src_policy)
        || !c.key.sensitive
        || c.key.extractable
    {
        return deny(slot, Reject("source evidence binding"));
    }
    // Destination policy, peer allowlist, budget, type extension.
    let Some(dst_der) = records::find_policy(slot, h.destination_policy.as_bytes()) else {
        return deny(slot, Reject("destination policy not enrolled"));
    };
    let dst_pol = records::parse_policy(&dst_der)?;
    // Spec §3.2 step 4 (review K0B-R2-05): the destination re-checks the
    // ordering itself rather than trusting the source to have done it.
    let Some(src_der) = records::find_policy(slot, h.source_policy.as_bytes()) else {
        return deny(slot, Reject("source policy not enrolled at destination"));
    };
    if !dst_pol.is_equal_or_stricter_than(&records::parse_policy(&src_der)?) {
        return deny(slot, Reject("destination policy weaker than source policy"));
    }
    let own_device = evidence::platform_device_id(slot)?;
    if !dst_pol.permits(h.operation)
        || dst_pol.domain.as_slice() != h.domain_id.as_bytes()
        || now < dst_pol.not_before
        || now >= dst_pol.not_after
        || h.transferred_budget > dst_pol.max_replicas
        || h.type_extension_hash.as_bytes() != super::sha384(b"")
    {
        return deny(slot, Reject("destination policy refuses package"));
    }
    if !dst_pol.peers.contains(&schain.device_id) || (schain.device_id == own_device && !dst_pol.allow_same_device) {
        return deny(slot, Reject("source device not allowed by destination policy"));
    }

    // Reserve (durable), unless an exact pre-commit retry already did.
    let ledger_h = match existing {
        Some((lh, _)) => lh,
        None => {
            if records::list(slot, ROLE_LEDGER).len() >= MAX_LEDGER_ENTRIES {
                return Err(CKR_DEVICE_MEMORY);
            }
            let rec = LedgerRecord {
                transaction_id: asn1::octets(&txid),
                state: LEDGER_RESERVED,
                package_hash: asn1::octets(&pkg_hash),
                installed_unique_id: String::new(),
                receipt: asn1::octets(&[]),
            };
            let obj = records::new_record(ROLE_LEDGER, CKO_DATA, "consumption ledger entry", Vec::new(), asn1::to_der(&rec)?, true);
            crate::state::commit_objects_atomically(session, vec![obj], Vec::new())?[0]
        }
    };
    crash_check(CrashPoint::ImportAfterReserve)?;

    // Decapsulate and decrypt inside the engine.
    let dk = recovery_dk;
    let h_der = asn1::to_der(h)?;
    let mut info = HPKE_INFO_LABEL.to_vec();
    info.push(0);
    info.extend_from_slice(&super::sha384(&h_der));
    let mut pt = crate::native::hpke::open_replication_v1(&dk, pkg.tbs.encapsulated.as_bytes(), &info, &h_der, pkg.tbs.ciphertext.as_bytes())?;
    let staged = validate_payload(&pt, &c.key);
    zeroize::Zeroize::zeroize(&mut pt);
    let staged = staged?;
    crash_check(CrashPoint::ImportAfterDecrypt)?;

    // Stage objects and the receipt.
    let unique_id = crate::state::reserve_unique_id();
    let committed_at = now;
    let provenance = asn1::to_der(&ReplicationProvenance {
        version: 1,
        operation: h.operation,
        source_device_id: asn1::octets(&schain.device_id),
        source_unique_id: h.source_unique_id.clone(),
        lineage_id: h.lineage_id.clone(),
        transaction_id: h.transaction_id.clone(),
        package_hash: asn1::octets(&pkg_hash),
        committed_at: gt(committed_at)?,
    })?;
    let (prv, pubk) = installed_objects(&staged, h, &dst_pol, provenance, unique_id.clone(), template);
    let receipt_chain = pki::chain_from_ders(&[
        records::certificate(slot, Purpose::ReceiptSigning).ok_or(CKR_DEVICE_ERROR)?,
        records::certificate(slot, Purpose::DeviceIssuer).ok_or(CKR_DEVICE_ERROR)?,
    ])
    .map_err(|_| CKR_DEVICE_ERROR)?;
    let uid_str = String::from_utf8(unique_id).map_err(|_| CKR_DEVICE_ERROR)?;
    let rtbs = ReplicationReceiptTbs {
        version: 1,
        suite: oids::SUITE_V1,
        transaction_id: h.transaction_id.clone(),
        package_hash: asn1::octets(&pkg_hash),
        destination_device_id: asn1::octets(&own_device),
        installed_unique_id: uid_str.clone(),
        lineage_id: h.lineage_id.clone(),
        installed_policy: asn1::octets(&dst_pol.id),
        committed_at: gt(committed_at)?,
        receipt_signer_chain: receipt_chain,
    };
    let (_, rsk) = records::function_secret(slot, Purpose::ReceiptSigning).ok_or(CKR_DEVICE_ERROR)?;
    let rsig = super::mldsa65_sign(&rsk, &receipt_signed_bytes(&asn1::to_der(&rtbs)?))?;
    let receipt = asn1::to_der(&ReplicationReceipt {
        tbs: rtbs,
        signature_algorithm: asn1::ml_dsa_65_alg(),
        signature: der::asn1::BitString::from_bytes(&rsig).map_err(|_| CKR_DEVICE_ERROR)?,
    })?;
    crash_check(CrashPoint::ImportBeforeCommit)?;

    // ONE commit: replica (+ public partner), ledger → committed, reservation consumed.
    let committed = LedgerRecord {
        transaction_id: asn1::octets(&txid),
        state: LEDGER_COMMITTED,
        package_hash: asn1::octets(&pkg_hash),
        installed_unique_id: uid_str.clone(),
        receipt: asn1::octets(&receipt),
    };
    let used = ChallengeRecord { consumed: true, ..chal };
    let mut objs = vec![prv];
    if let Some(p) = pubk {
        objs.push(p);
    }
    let handles = crate::state::commit_objects_atomically(
        session,
        objs,
        vec![
            (ledger_h, vec![(CKA_PRIV_REPL_RECORD, asn1::to_der(&committed)?)]),
            (chal_h, vec![(CKA_PRIV_REPL_RECORD, asn1::to_der(&used)?)]),
        ],
    )?;
    oplog_event(
        "package_import",
        slot,
        &[
            ("transaction", super::hex(&txid)),
            ("installed_unique_id", uid_str),
            ("source_device", super::hex(&schain.device_id)),
            ("package_sha384", super::hex(&pkg_hash)),
        ],
    );
    crash_check(CrashPoint::ImportAfterCommit)?;
    Ok((handles[0], receipt))
}

/// `C_PQCTODAY_CloneKey`: the same create → import protocol in memory when
/// one module addresses both sessions. No second wire format, no direct
/// object copy; the receipt is verified with the source token's own trust
/// inputs before the call returns.
pub fn clone_key(
    source_session: u32,
    h_key: u32,
    destination_session: u32,
    request: &[u8],
    template: &[(u32, Vec<u8>)],
) -> Result<(u32, Vec<u8>), u32> {
    require_profile()?;
    let src_slot = require_user_rw(source_session)?;
    require_user_rw(destination_session)?;
    validate_import_template(template)?;
    let package = create_replication_package(source_session, h_key, request)?;
    let (handle, receipt) = import_replication_package(destination_session, &package, template)?;
    let trust = super::enroll::trust_inputs(src_slot);
    // The destination has already committed. A receipt that fails here is
    // reported as CKR_DEVICE_ERROR with the replica installed (spec §3.3).
    if super::host_verify::verify_receipt(&receipt, &package, request, &trust, now_unix(), Profile::Educational).is_err() {
        return Err(CKR_DEVICE_ERROR);
    }
    oplog_event("clone", src_slot, &[("transaction", super::hex(&super::sha384(&package)[..8]))]);
    Ok((handle, receipt))
}

/// `CloneKey` sizing: the destination's fixed receipt length.
/// `CloneKey` sizing: validates the source side first (spec §9 items 3–7,
/// review K0B-R2-08), then reports the destination's fixed receipt length.
pub fn clone_receipt_length(source_session: u32, h_key: u32, request: &[u8], destination_session: u32) -> Result<usize, u32> {
    let (src_slot, _) = source_key(source_session, h_key)?;
    let slot = require_user_rw(destination_session)?;
    parse_request(request)?;
    ready(src_slot)?;
    ready(slot)?;
    receipt_length_for_slot(slot)
}

#[allow(dead_code)]
fn _assert_cert_type(_: &Certificate) {}
