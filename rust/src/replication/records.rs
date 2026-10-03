//! Engine-owned replication state, stored as ordinary token objects.
//!
//! Every hierarchy credential, policy, CRL, challenge reservation, ledger
//! entry, cached package and receipt is a `CKA_TOKEN=TRUE` object tagged
//! with the engine-private `CKA_PRIV_REPL_ROLE`. Two consequences carry the
//! design:
//! - durability is the token's: the state snapshot (F14) and the SQLite
//!   store persist these objects exactly as they persist keys; and
//! - callers can see public records (spec §4) but can never forge one:
//!   engine-private attributes are skipped from every template and refused
//!   on every write, and the objects are non-modifiable, non-copyable and
//!   non-destroyable.

use std::collections::HashMap;

use crate::constants::*;
use crate::crypto::handlers::{Attributes, ALGO_ML_DSA, ALGO_ML_KEM};
use crate::state::{store_bool, store_ulong, OBJECTS};

use super::asn1::{self, ReplicationPolicy};
use super::oids::Purpose;

/// PKCS#11 v3.2 `CKA_LABEL` (not in the engine's constants table).
pub const CKA_LABEL: u32 = 0x0000_0003;

pub const ROLE_DEVICE_KEY: u8 = 1;
pub const ROLE_DEVICE_PUBLIC: u8 = 2;
pub const ROLE_FUNCTION_KEY: u8 = 3;
pub const ROLE_FUNCTION_PUBLIC: u8 = 4;
pub const ROLE_CERT: u8 = 5;
pub const ROLE_TRUST_ANCHOR: u8 = 6;
pub const ROLE_CRL: u8 = 7;
pub const ROLE_POLICY: u8 = 8;
pub const ROLE_CHALLENGE: u8 = 9;
pub const ROLE_LEDGER: u8 = 10;
pub const ROLE_PACKAGE_CACHE: u8 = 11;
pub const ROLE_ENROLLMENT: u8 = 12;

/// Spec §10 / review K0B-R-15 bounds.
pub const MAX_POLICIES_PER_SLOT: usize = 64;
pub const MAX_POLICY_DER: usize = 8 * 1024;
pub const MAX_CRLS_PER_SLOT: usize = 64;
pub const MAX_CRL_DER: usize = 64 * 1024;
pub const MAX_CRL_ENTRIES: usize = 1024;
pub const MAX_CACHED_PACKAGES: usize = 256;
pub const MAX_LEDGER_ENTRIES: usize = 4096;
pub const MAX_OPEN_CHALLENGES: usize = 1024;

/// Full attribute map of a handle, including secret attributes. Engine use only.
pub fn object_attrs(handle: u32) -> Option<Attributes> {
    OBJECTS.with(|o| o.borrow().get(&handle).cloned())
}

pub fn role_of(attrs: &Attributes) -> Option<u8> {
    attrs.get(&CKA_PRIV_REPL_ROLE).and_then(|v| v.first().copied())
}

pub fn purpose_of(attrs: &Attributes) -> Option<Purpose> {
    attrs
        .get(&CKA_PQCTODAY_FUNCTION_PURPOSE)
        .and_then(|v| v.first().copied())
        .and_then(Purpose::from_u8)
}

/// All records of `role` on `slot`, ordered by handle (creation order).
pub fn list(slot: u32, role: u8) -> Vec<(u32, Attributes)> {
    let mut v: Vec<(u32, Attributes)> = OBJECTS.with(|o| {
        o.borrow()
            .iter()
            .filter(|(_, a)| role_of(a) == Some(role) && crate::state::object_slot_of(a) == slot)
            .map(|(h, a)| (*h, a.clone()))
            .collect()
    });
    v.sort_by_key(|(h, _)| *h);
    v
}

pub fn record_bytes(attrs: &Attributes) -> &[u8] {
    attrs.get(&CKA_PRIV_REPL_RECORD).map(|v| v.as_slice()).unwrap_or(&[])
}

pub fn value_bytes(attrs: &Attributes) -> &[u8] {
    attrs.get(&CKA_VALUE).map(|v| v.as_slice()).unwrap_or(&[])
}

fn label(what: &str) -> Vec<u8> {
    format!("{} {}", super::EDUCATIONAL_LABEL, what).into_bytes()
}

/// A public, immutable, SO-owned data/certificate record (spec §4).
pub fn new_record(role: u8, class: u32, what: &str, value: Vec<u8>, record: Vec<u8>, private: bool) -> Attributes {
    let mut a: Attributes = HashMap::new();
    store_ulong(&mut a, CKA_CLASS, class);
    store_bool(&mut a, CKA_TOKEN, true);
    store_bool(&mut a, CKA_PRIVATE, private);
    store_bool(&mut a, CKA_MODIFIABLE, false);
    store_bool(&mut a, CKA_COPYABLE, false);
    store_bool(&mut a, CKA_DESTROYABLE, false);
    a.insert(CKA_LABEL, label(what));
    if class == CKO_DATA {
        a.insert(CKA_APPLICATION, b"pqctoday-key-replication-educational".to_vec());
    }
    if class == CKO_CERTIFICATE {
        store_ulong(&mut a, CKA_CERTIFICATE_TYPE, CKC_X_509);
    }
    a.insert(CKA_VALUE, value);
    a.insert(CKA_PRIV_REPL_ROLE, vec![role]);
    if !record.is_empty() {
        a.insert(CKA_PRIV_REPL_RECORD, record);
    }
    a
}

/// Attributes of a non-replicable hierarchy key pair (spec §4: one immutable
/// purpose each; mechanism allowlist names only that purpose). Neither half
/// is usable through the ordinary C_Sign / C_Decapsulate dispatch: the usage
/// flags are FALSE and the allowlist names an engine-internal mechanism, so a
/// function key is never a general signing or decapsulation oracle.
pub fn new_function_key_pair(purpose: Purpose, public: Vec<u8>, private: Vec<u8>) -> (Attributes, Attributes) {
    let (key_type, ps, algo, spki, gen_mech) = if purpose.is_kem() {
        (
            CKK_ML_KEM,
            CKP_ML_KEM_768,
            ALGO_ML_KEM,
            crate::crypto::handlers::build_mlkem768_spki(&public),
            CKM_ML_KEM_KEY_PAIR_GEN,
        )
    } else {
        (
            CKK_ML_DSA,
            CKP_ML_DSA_65,
            ALGO_ML_DSA,
            crate::crypto::handlers::build_mldsa65_spki(&public),
            CKM_ML_DSA_KEY_PAIR_GEN,
        )
    };
    let constrained = match purpose {
        Purpose::DeviceIssuer => CKM_PQCTODAY_ISSUE_FUNCTION_CERTIFICATE,
        Purpose::KeyAttestation => CKM_PQCTODAY_SIGN_KEY_ATTESTATION,
        // Package, receipt and peer-authentication signatures and recovery
        // decapsulation happen only inside the replication operations, which
        // address the key directly; the allowlist is empty so no ordinary
        // mechanism can reach it.
        _ => 0,
    };
    let (priv_role, pub_role) = if purpose == Purpose::DeviceIssuer {
        (ROLE_DEVICE_KEY, ROLE_DEVICE_PUBLIC)
    } else {
        (ROLE_FUNCTION_KEY, ROLE_FUNCTION_PUBLIC)
    };
    let mut pubk: Attributes = HashMap::new();
    let mut prv: Attributes = HashMap::new();
    for (a, class) in [(&mut pubk, CKO_PUBLIC_KEY), (&mut prv, CKO_PRIVATE_KEY)] {
        store_ulong(a, CKA_CLASS, class);
        store_ulong(a, CKA_KEY_TYPE, key_type);
        crate::state::store_param_set(a, ps);
        crate::state::store_algo_family(a, algo);
        store_ulong(a, CKA_PARAMETER_SET, ps);
        store_bool(a, CKA_TOKEN, true);
        store_bool(a, CKA_MODIFIABLE, false);
        store_bool(a, CKA_COPYABLE, false);
        store_bool(a, CKA_DESTROYABLE, false);
        store_bool(a, CKA_LOCAL, true);
        store_ulong(a, CKA_KEY_GEN_MECHANISM, gen_mech);
        store_bool(a, CKA_SIGN, false);
        store_bool(a, CKA_VERIFY, false);
        store_bool(a, CKA_ENCAPSULATE, false);
        store_bool(a, CKA_DECAPSULATE, false);
        store_bool(a, CKA_DERIVE, false);
        a.insert(CKA_LABEL, label(&format!("{} function", purpose.label())));
        a.insert(CKA_PQCTODAY_FUNCTION_PURPOSE, vec![purpose as u8]);
        a.insert(CKA_ALLOWED_MECHANISMS, if constrained == 0 { Vec::new() } else { encode_mechanisms(&[constrained]) });
    }
    store_bool(&mut pubk, CKA_PRIVATE, false);
    pubk.insert(CKA_VALUE, public);
    pubk.insert(CKA_PUBLIC_KEY_INFO, spki.clone());
    pubk.insert(CKA_PRIV_REPL_ROLE, vec![pub_role]);
    store_bool(&mut prv, CKA_PRIVATE, true);
    store_bool(&mut prv, CKA_SENSITIVE, true);
    store_bool(&mut prv, CKA_EXTRACTABLE, false);
    store_bool(&mut prv, CKA_ALWAYS_SENSITIVE, true);
    store_bool(&mut prv, CKA_NEVER_EXTRACTABLE, true);
    prv.insert(CKA_VALUE, private);
    prv.insert(CKA_PUBLIC_KEY_INFO, spki);
    prv.insert(CKA_PRIV_REPL_ROLE, vec![priv_role]);
    (pubk, prv)
}

/// CKA_ALLOWED_MECHANISMS encoding (CK_MECHANISM_TYPE array at the exported
/// CK_ULONG width, see `state::MECHANISM_TYPE_SIZE`).
pub fn encode_mechanisms(mechs: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(mechs.len() * crate::state::MECHANISM_TYPE_SIZE);
    for m in mechs {
        out.extend_from_slice(&(*m as usize).to_le_bytes());
    }
    out
}

/// Marker in `CKA_PRIV_REPL_RECORD` of a retired (rotated-out) function
/// key, public key or certificate. Retained for continuity, never selected
/// for new operations.
pub const RETIRED: &[u8] = b"retired";

pub fn is_retired(a: &Attributes) -> bool {
    record_bytes(a) == RETIRED
}

/// The ACTIVE (latest, non-retired) record of `purpose` and `role`.
fn active(slot: u32, role: u8, purpose: Purpose) -> Option<(u32, Attributes)> {
    list(slot, role).into_iter().rev().find(|(_, a)| purpose_of(a) == Some(purpose) && !is_retired(a))
}

/// The active private function key (`(handle, raw secret)`) of `purpose`.
pub fn function_secret(slot: u32, purpose: Purpose) -> Option<(u32, Vec<u8>)> {
    let role = if purpose == Purpose::DeviceIssuer { ROLE_DEVICE_KEY } else { ROLE_FUNCTION_KEY };
    active(slot, role, purpose).and_then(|(h, a)| a.get(&CKA_VALUE).cloned().map(|v| (h, v)))
}

pub fn function_public(slot: u32, purpose: Purpose) -> Option<(u32, Attributes)> {
    let role = if purpose == Purpose::DeviceIssuer { ROLE_DEVICE_PUBLIC } else { ROLE_FUNCTION_PUBLIC };
    active(slot, role, purpose)
}

/// Active DER certificate of `purpose` on `slot` (the device certificate for
/// [`Purpose::DeviceIssuer`]).
pub fn certificate(slot: u32, purpose: Purpose) -> Option<Vec<u8>> {
    active(slot, ROLE_CERT, purpose).map(|(_, a)| value_bytes(&a).to_vec())
}

/// Decapsulation key of the current OR a retained recovery key whose
/// certificate SPKI hashes to `recipient_hash` (rotation continuity).
pub fn recovery_secret_for(slot: u32, recipient_hash: &[u8]) -> Option<Vec<u8>> {
    let spki_hash = |spki: &[u8]| super::sha384(spki);
    list(slot, ROLE_FUNCTION_KEY)
        .into_iter()
        .filter(|(_, a)| purpose_of(a) == Some(Purpose::RecoveryRecipient))
        .find(|(_, a)| a.get(&CKA_PUBLIC_KEY_INFO).map(|s| spki_hash(s).as_slice() == recipient_hash).unwrap_or(false))
        .and_then(|(_, a)| a.get(&CKA_VALUE).cloned())
}

pub fn trust_anchors(slot: u32) -> Vec<Vec<u8>> {
    list(slot, ROLE_TRUST_ANCHOR).into_iter().map(|(_, a)| value_bytes(&a).to_vec()).collect()
}

/// Every enrolled CRL on `slot` as `(handle, issuer key id, DER)`.
pub fn crls(slot: u32) -> Vec<(u32, Vec<u8>, Vec<u8>)> {
    list(slot, ROLE_CRL)
        .into_iter()
        .map(|(h, a)| (h, record_bytes(&a).to_vec(), value_bytes(&a).to_vec()))
        .collect()
}

pub fn find_policy(slot: u32, policy_id: &[u8]) -> Option<Vec<u8>> {
    list(slot, ROLE_POLICY)
        .into_iter()
        .map(|(_, a)| value_bytes(&a).to_vec())
        .find(|der| super::sha384(der).as_slice() == policy_id)
}

/// Decoded, validated view of a canonical [`ReplicationPolicy`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyView {
    pub id: [u8; 48],
    pub domain: [u8; 32],
    pub operations: [bool; 3],
    pub peers: Vec<[u8; 32]>,
    pub not_before: u64,
    pub not_after: u64,
    pub max_replicas: u32,
    pub allowed_mechanisms: Vec<u32>,
    pub allow_same_device: bool,
    pub type_constraint_hash: [u8; 48],
}

impl PolicyView {
    pub fn permits(&self, op: asn1::Operation) -> bool {
        self.operations[op.bit()]
    }

    /// Spec §8: `self` (destination) equal to or stricter than `source`.
    pub fn is_equal_or_stricter_than(&self, source: &PolicyView) -> bool {
        self.domain == source.domain
            && self.type_constraint_hash == source.type_constraint_hash
            && (0..3).all(|i| !self.operations[i] || source.operations[i])
            && self.peers.iter().all(|p| source.peers.contains(p))
            && self.allowed_mechanisms.iter().all(|m| source.allowed_mechanisms.contains(m))
            && self.not_before >= source.not_before
            && self.not_after <= source.not_after
            && self.max_replicas <= source.max_replicas
            && (!self.allow_same_device || source.allow_same_device)
    }
}

/// Strictly parse and validate a policy (spec §8; K0B-R-15 size bound).
pub fn parse_policy(der: &[u8]) -> Result<PolicyView, u32> {
    let p: ReplicationPolicy = asn1::decode_strict(der, MAX_POLICY_DER)?;
    let fixed32 = |o: &der::asn1::OctetString| -> Result<[u8; 32], u32> {
        o.as_bytes().try_into().map_err(|_| CKR_DATA_INVALID)
    };
    if p.version != 1 {
        return Err(CKR_DATA_INVALID);
    }
    let domain = fixed32(&p.domain_id)?;
    let ops = &p.operations;
    if ops.bit_len() != 3 {
        return Err(CKR_DATA_INVALID);
    }
    let raw = ops.raw_bytes().first().copied().unwrap_or(0);
    let operations = [raw & 0x80 != 0, raw & 0x40 != 0, raw & 0x20 != 0];
    if p.allowed_peer_device_ids.is_empty() || p.allowed_peer_device_ids.len() > 64 {
        return Err(CKR_DATA_INVALID);
    }
    let mut peers = Vec::with_capacity(p.allowed_peer_device_ids.len());
    for d in &p.allowed_peer_device_ids {
        peers.push(fixed32(d)?);
    }
    if peers.windows(2).any(|w| w[0] >= w[1]) {
        return Err(CKR_DATA_INVALID);
    }
    if p.allowed_mechanisms.len() > 64 || p.allowed_mechanisms.windows(2).any(|w| w[0] >= w[1]) {
        return Err(CKR_DATA_INVALID);
    }
    if p.max_replicas == 0 || p.max_replicas > 65535 {
        return Err(CKR_DATA_INVALID);
    }
    let not_before = p.not_before.to_unix_duration().as_secs();
    let not_after = p.not_after.to_unix_duration().as_secs();
    if not_before >= not_after {
        return Err(CKR_DATA_INVALID);
    }
    let tch: [u8; 48] = p.type_constraint_hash.as_bytes().try_into().map_err(|_| CKR_DATA_INVALID)?;
    Ok(PolicyView {
        id: super::sha384(der),
        domain,
        operations,
        peers,
        not_before,
        not_after,
        max_replicas: p.max_replicas,
        allowed_mechanisms: p.allowed_mechanisms,
        allow_same_device: p.allow_same_device,
        type_constraint_hash: tch,
    })
}

/// Build canonical policy DER for the v1 key profiles (helper for SO
/// tooling and tests).
pub fn build_policy(
    domain: [u8; 32],
    operations: [bool; 3],
    peers: Vec<[u8; 32]>,
    not_before: u64,
    not_after: u64,
    max_replicas: u32,
    allowed_mechanisms: Vec<u32>,
    allow_same_device: bool,
) -> Result<Vec<u8>, u32> {
    build_policy_with_constraint(domain, operations, peers, not_before, not_after, max_replicas, allowed_mechanisms, allow_same_device, super::sha384(b""))
}

/// [`build_policy`] with an explicit profile `typeConstraintHash` (e.g.
/// `fhe::profile_constraint_hash()` for FHE seeds).
pub fn build_policy_with_constraint(
    domain: [u8; 32],
    operations: [bool; 3],
    mut peers: Vec<[u8; 32]>,
    not_before: u64,
    not_after: u64,
    max_replicas: u32,
    mut allowed_mechanisms: Vec<u32>,
    allow_same_device: bool,
    type_constraint_hash: [u8; 48],
) -> Result<Vec<u8>, u32> {
    peers.sort_unstable();
    peers.dedup();
    allowed_mechanisms.sort_unstable();
    allowed_mechanisms.dedup();
    let bits = (operations[0] as u8) << 7 | (operations[1] as u8) << 6 | (operations[2] as u8) << 5;
    let gt = |t: u64| {
        der::asn1::GeneralizedTime::from_unix_duration(std::time::Duration::from_secs(t))
            .map_err(|_| CKR_ARGUMENTS_BAD)
    };
    let p = ReplicationPolicy {
        version: 1,
        domain_id: asn1::octets(&domain),
        operations: der::asn1::BitString::new(5, vec![bits]).map_err(|_| CKR_ARGUMENTS_BAD)?,
        allowed_peer_device_ids: peers.iter().map(|d| asn1::octets(d)).collect(),
        not_before: gt(not_before)?,
        not_after: gt(not_after)?,
        max_replicas,
        allowed_mechanisms,
        allow_same_device,
        type_constraint_hash: asn1::octets(&type_constraint_hash),
    };
    asn1::to_der(&p)
}
