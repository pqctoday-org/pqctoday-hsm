//! FHE P1 — the FHE seed as a replicable key class (FHE plan §6.2, §6.3, §6.7;
//! P1 row of §9).
//!
//! P1 uses an OPAQUE seed: 32 random bytes standing in for a TFHE client-key
//! seed, with no FHE backend. What P1 proves is custody: the seed is
//! non-extractable, its FHE attributes are immutable, it replicates only
//! through the K4 interface with an authenticated recovery descriptor, and
//! its typed decryption policy travels with it and can only be preserved or
//! tightened. No key-regeneration or decryption claim is made until P2.
//!
//! The descriptor rides in the K4 payload's `typeExtension`; the package
//! header's `typeExtensionHash` binds it under the package signature, and the
//! replication policy's `typeConstraintHash` selects the FHE profile.

use der::asn1::OctetString;
use der::{Enumerated, Sequence};

use super::asn1;
use super::records::{self, MAX_POLICY_DER};
use crate::constants::*;

/// Records role for an enrolled FHE decryption policy.
pub const ROLE_FHE_DECRYPT_POLICY: u8 = 13;

/// The only scheme and generator version P1 accepts.
pub const FHE_SCHEME_TFHE: &str = "tfhe-rs";
pub const FHE_GENERATOR_VERSIONS: &[u32] = &[1];
/// Opaque P1 seed length (a TFHE-rs client-key seed is 128 bits; 32 bytes
/// leaves room and is what the fixture uses).
pub const FHE_SEED_LEN: usize = 32;
pub const MAX_DESCRIPTOR_DER: usize = 4 * 1024;

/// Allowlisted parameter sets (plan §6.2: no caller-supplied cryptographic
/// parameters). P2 replaces the placeholder hash with the canonical encoding
/// of the pinned TFHE-rs parameter set.
pub const FHE_PARAM_SETS: &[(u32, &str)] = &[(1, "tfhe-rs PARAM_MESSAGE_2_CARRY_2_KS_PBS (custody profile v1)")];

pub fn param_hash(param_set: u32) -> Option<[u8; 48]> {
    FHE_PARAM_SETS
        .iter()
        .find(|(id, _)| *id == param_set)
        .map(|(_, name)| super::sha384(name.as_bytes()))
}

pub fn library_id() -> &'static str {
    "tfhe-rs (P1 opaque-seed fixture; no backend linked)"
}

// ── Profile constraint (replication policy typeConstraintHash) ─────────────

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct FheProfileConstraint {
    pub version: u8,
    pub scheme: String,
    pub param_sets: Vec<u32>,
}

/// Canonical DER of the version-1 FHE profile constraint.
pub fn profile_constraint_der() -> Vec<u8> {
    asn1::to_der(&FheProfileConstraint {
        version: 1,
        scheme: FHE_SCHEME_TFHE.to_string(),
        param_sets: FHE_PARAM_SETS.iter().map(|(id, _)| *id).collect(),
    })
    .expect("static constraint")
}

/// `typeConstraintHash` a replication policy must carry to govern FHE seeds.
pub fn profile_constraint_hash() -> [u8; 48] {
    super::sha384(&profile_constraint_der())
}

// ── Typed decryption policy (FHE plan §6.3) ────────────────────────────────

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Sequence)]
pub struct FheType {
    /// Exact TFHE-rs high-level type name, e.g. "FheUint8".
    pub type_name: String,
    pub width_bits: u16,
    pub param_set: u32,
    pub serialization_version: u16,
    pub compressed_allowed: bool,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Enumerated)]
#[repr(u32)]
pub enum PredicateKind {
    /// Released plaintext ≤ bound.
    MaxValue = 0,
    /// Released plaintext ≥ bound (e.g. "count ≥ k").
    MinValue = 1,
}

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Sequence)]
pub struct Predicate {
    pub kind: PredicateKind,
    pub bound: u64,
}

fn default_false() -> bool {
    false
}

/// Rules 1–5 of §6.3, as one immutable, SO-enrolled, canonical DER policy.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct FheDecryptPolicy {
    pub version: u8,
    /// Rule 1: what may be released (strictly sorted, unique).
    pub allowed_output_types: Vec<FheType>,
    /// Rule 2: input types never releasable (strictly sorted, unique).
    pub never_release: Vec<FheType>,
    /// Rule 3: post-decrypt predicates (strictly sorted, unique kinds).
    pub predicates: Vec<Predicate>,
    /// Rule 5: enrolled third-party recipients as SHA-384 of their ML-KEM
    /// recipient certificate SPKI (strictly sorted); empty = owner only.
    pub recipients: Vec<OctetString>,
    #[asn1(default = "default_false")]
    pub recipient_only: bool,
    /// Rate limit: decrypt calls (released or refused) per object.
    pub max_decrypts: u32,
}

/// Validated view of an enrolled decryption policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecryptPolicyView {
    pub id: [u8; 48],
    pub policy: FheDecryptPolicy,
}

pub fn parse_decrypt_policy(der: &[u8]) -> Result<DecryptPolicyView, u32> {
    let p: FheDecryptPolicy = asn1::decode_strict(der, MAX_POLICY_DER)?;
    let sorted_unique = |v: &[FheType]| v.windows(2).all(|w| w[0] < w[1]);
    if p.version != 1
        || p.allowed_output_types.is_empty()
        || p.allowed_output_types.len() > 32
        || p.never_release.len() > 32
        || p.predicates.len() > 8
        || p.recipients.len() > 16
        || p.max_decrypts == 0
        || !sorted_unique(&p.allowed_output_types)
        || !sorted_unique(&p.never_release)
        || !p.predicates.windows(2).all(|w| w[0].kind < w[1].kind)
        || !p.recipients.windows(2).all(|w| w[0].as_bytes() < w[1].as_bytes())
        || p.recipients.iter().any(|r| r.as_bytes().len() != 48)
        || (p.recipient_only && p.recipients.is_empty())
    {
        return Err(CKR_DATA_INVALID);
    }
    // Every type must use an allowlisted parameter set; an input type can
    // never also be releasable.
    let known = |t: &FheType| param_hash(t.param_set).is_some() && t.width_bits > 0 && t.width_bits <= 256;
    if !p.allowed_output_types.iter().all(known)
        || !p.never_release.iter().all(known)
        || p.allowed_output_types.iter().any(|t| p.never_release.contains(t))
    {
        return Err(CKR_DATA_INVALID);
    }
    Ok(DecryptPolicyView { id: super::sha384(der), policy: p })
}

impl DecryptPolicyView {
    /// §6.3 "preserving or tightening": `self` (destination) releases a
    /// subset to a subset of recipients under at least the same predicates
    /// and rate limit.
    pub fn is_equal_or_stricter_than(&self, src: &DecryptPolicyView) -> bool {
        let d = &self.policy;
        let s = &src.policy;
        let preds_ok = s.predicates.iter().all(|sp| {
            d.predicates.iter().any(|dp| {
                dp.kind == sp.kind
                    && match sp.kind {
                        PredicateKind::MaxValue => dp.bound <= sp.bound,
                        PredicateKind::MinValue => dp.bound >= sp.bound,
                    }
            })
        });
        d.allowed_output_types.iter().all(|t| s.allowed_output_types.contains(t))
            && s.never_release.iter().all(|t| d.never_release.contains(t))
            && preds_ok
            && d.recipients.iter().all(|r| s.recipients.contains(r))
            && (d.recipient_only || !s.recipient_only)
            && d.max_decrypts <= s.max_decrypts
    }
}

pub fn find_decrypt_policy(slot: u32, id: &[u8]) -> Option<DecryptPolicyView> {
    records::list(slot, ROLE_FHE_DECRYPT_POLICY)
        .into_iter()
        .map(|(_, a)| records::value_bytes(&a).to_vec())
        .find(|der| super::sha384(der).as_slice() == id)
        .and_then(|der| parse_decrypt_policy(&der).ok())
}

/// SO enrollment of an immutable FHE decryption policy (§6.3 "Policy
/// provisioning"). Returns its SHA-384 identifier; identical DER is idempotent.
pub fn enroll_fhe_decrypt_policy(so_session: u32, policy_der: &[u8]) -> Result<[u8; 48], u32> {
    super::require_profile()?;
    let slot = super::require_so(so_session)?;
    let view = parse_decrypt_policy(policy_der)?;
    if find_decrypt_policy(slot, &view.id).is_some() {
        return Ok(view.id);
    }
    if records::list(slot, ROLE_FHE_DECRYPT_POLICY).len() >= records::MAX_POLICIES_PER_SLOT {
        return Err(CKR_DEVICE_MEMORY);
    }
    let rec = records::new_record(ROLE_FHE_DECRYPT_POLICY, CKO_DATA, "FHE decryption policy", policy_der.to_vec(), Vec::new(), false);
    crate::state::commit_objects_atomically(so_session, vec![rec], Vec::new())?;
    super::oplog_event("fhe_policy_enrolled", slot, &[("policy", super::hex(&view.id))]);
    Ok(view.id)
}

// ── Recovery descriptor (package typeExtension) ────────────────────────────

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct FheRecoveryDescriptor {
    pub version: u8,
    pub scheme: String,
    pub param_set: u32,
    pub param_hash: OctetString,
    pub library: String,
    pub generator_version: u32,
    pub lineage_id: OctetString,
    pub decrypt_policy: OctetString,
}

/// The descriptor for an FHE seed object, recomputed from its immutable attributes.
pub fn descriptor_for(attrs: &crate::crypto::handlers::Attributes) -> Result<Vec<u8>, u32> {
    let s = |t| attrs.get(&t).cloned().ok_or(CKR_KEY_FUNCTION_NOT_PERMITTED);
    let ps = crate::state::get_object_attr_u32_from(attrs, CKA_PQCTODAY_FHE_PARAM_SET).ok_or(CKR_KEY_FUNCTION_NOT_PERMITTED)?;
    asn1::to_der(&FheRecoveryDescriptor {
        version: 1,
        scheme: String::from_utf8(s(CKA_PQCTODAY_FHE_SCHEME)?).map_err(|_| CKR_DEVICE_ERROR)?,
        param_set: ps,
        param_hash: asn1::octets(&s(CKA_PQCTODAY_FHE_PARAM_HASH)?),
        library: String::from_utf8(s(CKA_PQCTODAY_FHE_LIBRARY)?).map_err(|_| CKR_DEVICE_ERROR)?,
        generator_version: 1,
        lineage_id: asn1::octets(&s(CKA_PQCTODAY_FHE_LINEAGE_ID)?),
        decrypt_policy: asn1::octets(&s(CKA_PQCTODAY_FHE_DECRYPT_POLICY)?),
    })
}

/// Destination-side validation of a decrypted descriptor (§6.7.5: tampered
/// descriptor, unsupported generator version). `header_lineage` is the
/// signed package header's lineage. Every failure is
/// `CKR_ENCRYPTED_DATA_INVALID` (authenticated plaintext inconsistent).
pub fn validate_descriptor(der: &[u8], header_lineage: &[u8]) -> Result<FheRecoveryDescriptor, u32> {
    let bad = CKR_ENCRYPTED_DATA_INVALID;
    let d: FheRecoveryDescriptor = asn1::decode_strict(der, MAX_DESCRIPTOR_DER).map_err(|_| bad)?;
    if d.version != 1
        || d.scheme != FHE_SCHEME_TFHE
        || !FHE_GENERATOR_VERSIONS.contains(&d.generator_version)
        || param_hash(d.param_set).map(|h| h.to_vec()) != Some(d.param_hash.as_bytes().to_vec())
        || d.lineage_id.as_bytes() != header_lineage
        || d.decrypt_policy.as_bytes().len() != 48
    {
        return Err(bad);
    }
    Ok(d)
}

// ── Opaque-seed fixture (test builds only; plan P1 exit gate) ──────────────

/// Create a bound, replicable FHE seed object from 32 fresh random bytes
/// under an enrolled replication policy (FHE profile) and an enrolled
/// decryption policy. TEST-ONLY: absent from every build without
/// `test-support`, so no shipped artefact has a seed-import hook.
#[cfg(feature = "test-support")]
pub fn create_opaque_seed_fixture(
    user_session: u32,
    param_set: u32,
    replication_policy: &[u8; 48],
    decrypt_policy: &[u8; 48],
) -> Result<u32, u32> {
    use crate::state::{store_bool, store_ulong};
    super::require_profile()?;
    let slot = super::require_user_rw(user_session)?;
    let pol = records::parse_policy(&records::find_policy(slot, replication_policy).ok_or(CKR_TEMPLATE_INCONSISTENT)?)?;
    if pol.type_constraint_hash != profile_constraint_hash() || find_decrypt_policy(slot, decrypt_policy).is_none() {
        return Err(CKR_TEMPLATE_INCONSISTENT);
    }
    // §6.2 F8: no caller-visible KDF on the seed; only the FHE mechanisms.
    let fhe_mechs = [CKM_PQCTODAY_FHE_DERIVE_PUBLIC, CKM_PQCTODAY_FHE_DECRYPT];
    if !pol.allowed_mechanisms.iter().all(|m| fhe_mechs.contains(m)) {
        return Err(CKR_TEMPLATE_INCONSISTENT);
    }
    let ph = param_hash(param_set).ok_or(CKR_TEMPLATE_INCONSISTENT)?;
    let seed = super::random32()?;
    let lineage = super::random32()?;
    let mut a: crate::crypto::handlers::Attributes = Default::default();
    store_ulong(&mut a, CKA_CLASS, CKO_SECRET_KEY);
    store_ulong(&mut a, CKA_KEY_TYPE, CKK_PQCTODAY_FHE);
    store_ulong(&mut a, CKA_VALUE_LEN, FHE_SEED_LEN as u32);
    crate::state::store_param_set(&mut a, param_set);
    for (t, v) in [
        (CKA_TOKEN, true),
        (CKA_PRIVATE, true),
        (CKA_SENSITIVE, true),
        (CKA_EXTRACTABLE, false),
        (CKA_COPYABLE, false),
        (CKA_MODIFIABLE, false),
        (CKA_DERIVE, true),
        (CKA_DECRYPT, true),
        (CKA_ENCRYPT, false),
        (CKA_SIGN, false),
        (CKA_WRAP, false),
        (CKA_UNWRAP, false),
        (CKA_LOCAL, true),
        (CKA_ALWAYS_SENSITIVE, true),
        (CKA_NEVER_EXTRACTABLE, true),
    ] {
        store_bool(&mut a, t, v);
    }
    store_ulong(&mut a, CKA_KEY_GEN_MECHANISM, CKM_PQCTODAY_FHE_KEY_GEN);
    a.insert(CKA_VALUE, seed.to_vec());
    a.insert(CKA_PQCTODAY_FHE_SCHEME, FHE_SCHEME_TFHE.as_bytes().to_vec());
    store_ulong(&mut a, CKA_PQCTODAY_FHE_PARAM_SET, param_set);
    a.insert(CKA_PQCTODAY_FHE_PARAM_HASH, ph.to_vec());
    a.insert(CKA_PQCTODAY_FHE_LIBRARY, library_id().as_bytes().to_vec());
    a.insert(CKA_PQCTODAY_FHE_LINEAGE_ID, lineage.to_vec());
    a.insert(CKA_PQCTODAY_FHE_DECRYPT_POLICY, decrypt_policy.to_vec());
    a.insert(CKA_PQCTODAY_REPLICATION_POLICY_ID, replication_policy.to_vec());
    a.insert(CKA_PRIV_REPL_BINDING, replication_policy.to_vec());
    a.insert(CKA_PQCTODAY_REPLICATION_LINEAGE_ID, lineage.to_vec());
    a.insert(CKA_PRIV_REPL_BUDGET, pol.max_replicas.to_le_bytes().to_vec());
    a.insert(CKA_ALLOWED_MECHANISMS, records::encode_mechanisms(&pol.allowed_mechanisms));
    let h = crate::state::commit_objects_atomically(user_session, vec![a], Vec::new())?[0];
    super::oplog_event("fhe_seed_fixture", slot, &[("lineage", super::hex(&lineage))]);
    Ok(h)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ty(name: &str, w: u16) -> FheType {
        FheType { type_name: name.into(), width_bits: w, param_set: 1, serialization_version: 1, compressed_allowed: false }
    }

    fn policy(out: Vec<FheType>, never: Vec<FheType>, max_value: Option<u64>, max_decrypts: u32) -> FheDecryptPolicy {
        FheDecryptPolicy {
            version: 1,
            allowed_output_types: out,
            never_release: never,
            predicates: max_value.map(|b| vec![Predicate { kind: PredicateKind::MaxValue, bound: b }]).unwrap_or_default(),
            recipients: vec![],
            recipient_only: false,
            max_decrypts,
        }
    }

    fn view(p: &FheDecryptPolicy) -> DecryptPolicyView {
        parse_decrypt_policy(&asn1::to_der(p).unwrap()).unwrap()
    }

    #[test]
    fn decrypt_policy_ordering_preserve_or_tighten() {
        let src = view(&policy(vec![ty("FheBool", 1), ty("FheUint8", 8)], vec![ty("FheUint64", 64)], Some(65535), 100));
        assert!(src.is_equal_or_stricter_than(&src));
        let tighter = view(&policy(vec![ty("FheBool", 1)], vec![ty("FheUint64", 64)], Some(255), 10));
        assert!(tighter.is_equal_or_stricter_than(&src));
        // Releases a type the source did not allow.
        let wider = view(&policy(vec![ty("FheBool", 1), ty("FheUint16", 16)], vec![ty("FheUint64", 64)], Some(255), 10));
        assert!(!wider.is_equal_or_stricter_than(&src));
        // Drops a never-release input type, loosens the predicate, or raises the rate limit.
        assert!(!view(&policy(vec![ty("FheBool", 1)], vec![], Some(255), 10)).is_equal_or_stricter_than(&src));
        assert!(!view(&policy(vec![ty("FheBool", 1)], vec![ty("FheUint64", 64)], Some(1 << 20), 10)).is_equal_or_stricter_than(&src));
        assert!(!view(&policy(vec![ty("FheBool", 1)], vec![ty("FheUint64", 64)], None, 10)).is_equal_or_stricter_than(&src));
        assert!(!view(&policy(vec![ty("FheBool", 1)], vec![ty("FheUint64", 64)], Some(255), 1000)).is_equal_or_stricter_than(&src));
    }

    #[test]
    fn decrypt_policy_parse_refusals() {
        let bad = |p: FheDecryptPolicy| parse_decrypt_policy(&asn1::to_der(&p).unwrap()).is_err();
        assert!(bad(policy(vec![], vec![], None, 1)), "no releasable type");
        assert!(bad(policy(vec![ty("FheUint8", 8)], vec![ty("FheUint8", 8)], None, 1)), "input type also releasable");
        assert!(bad(policy(vec![ty("FheUint8", 8), ty("FheBool", 1)], vec![], None, 1)), "unsorted");
        assert!(bad(policy(vec![ty("FheBool", 1)], vec![], None, 0)), "zero rate limit");
        let mut unknown = ty("FheBool", 1);
        unknown.param_set = 99;
        assert!(bad(policy(vec![unknown], vec![], None, 1)), "unknown parameter set");
        let mut ro = policy(vec![ty("FheBool", 1)], vec![], None, 1);
        ro.recipient_only = true;
        assert!(bad(ro), "recipient-only with no recipient");
    }

    fn descriptor(version: u8, generator: u32, lineage: [u8; 32], param_hash_bytes: Vec<u8>) -> Vec<u8> {
        asn1::to_der(&FheRecoveryDescriptor {
            version,
            scheme: FHE_SCHEME_TFHE.into(),
            param_set: 1,
            param_hash: asn1::octets(&param_hash_bytes),
            library: library_id().into(),
            generator_version: generator,
            lineage_id: asn1::octets(&lineage),
            decrypt_policy: asn1::octets(&[7u8; 48]),
        })
        .unwrap()
    }

    #[test]
    fn descriptor_tamper_and_unsupported_version_are_refused() {
        let ph = param_hash(1).unwrap().to_vec();
        let lin = [3u8; 32];
        assert!(validate_descriptor(&descriptor(1, 1, lin, ph.clone()), &lin).is_ok());
        let e = Err(CKR_ENCRYPTED_DATA_INVALID);
        assert_eq!(validate_descriptor(&descriptor(1, 2, lin, ph.clone()), &lin).map(|_| ()), e, "unsupported generator version");
        assert_eq!(validate_descriptor(&descriptor(2, 1, lin, ph.clone()), &lin).map(|_| ()), e, "unsupported descriptor version");
        assert_eq!(validate_descriptor(&descriptor(1, 1, lin, vec![0; 48]), &lin).map(|_| ()), e, "parameter hash mismatch");
        assert_eq!(validate_descriptor(&descriptor(1, 1, lin, ph), &[4u8; 32]).map(|_| ()), e, "lineage differs from signed header");
        assert_eq!(validate_descriptor(b"\x30\x00", &lin).map(|_| ()), e, "malformed");
    }
}
