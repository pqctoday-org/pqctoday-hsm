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
/// Streamed CKKS (Lattigo-compatible evaluation keys), educational-fhe only.
pub const FHE_SCHEME_CKKS: &str = "ckks-stream";
pub const FHE_GENERATOR_VERSIONS: &[u32] = &[1];
/// Opaque P1 seed length (a TFHE-rs client-key seed is 128 bits; 32 bytes
/// leaves room and is what the fixture uses).
pub const FHE_SEED_LEN: usize = 32;
pub const MAX_DESCRIPTOR_DER: usize = 4 * 1024;

/// Allowlisted parameter sets (plan §6.2: no caller-supplied cryptographic
/// parameters; P0B spec §4). Version 1 has exactly one entry.
pub const FHE_PARAM_SETS: &[(u32, &str)] = &[(1, "PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128")];

/// P0B §4 canonical parameter encoding.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct FheParamSetV1 {
    pub id: u32,
    pub library: String,
    pub version: String,
    pub commit: OctetString,
    pub param_name: String,
    pub config: String,
    pub kdf: String,
}

/// TFHE-rs tag `tfhe-rs-1.8.1`, commit 187fc0b95ab35352422deec6c027d0bd8743b6db.
pub const TFHE_COMMIT: [u8; 20] = [
    0x18, 0x7f, 0xc0, 0xb9, 0x5a, 0xb3, 0x53, 0x52, 0x42, 0x2d, 0xeb, 0x6c, 0x02, 0x7d, 0x0b, 0xd8, 0x74, 0x3b, 0x6d,
    0xb6,
];

/// Scheme of a registered parameter set.
pub fn scheme_for(param_set: u32) -> Option<&'static str> {
    if FHE_PARAM_SETS.iter().any(|(id, _)| *id == param_set) {
        return Some(FHE_SCHEME_TFHE);
    }
    #[cfg(feature = "educational-fhe")]
    if super::fhe_ckks::params::find(param_set).is_some() {
        return Some(FHE_SCHEME_CKKS);
    }
    None
}

/// DER of `FheParamSetV1` for a registry ID.
pub fn param_set_der(param_set: u32) -> Option<Vec<u8>> {
    #[cfg(feature = "educational-fhe")]
    if let Some(ps) = super::fhe_ckks::params::find(param_set) {
        return asn1::to_der(&FheParamSetV1 {
            id: ps.id,
            library: "lattigo".into(),
            version: "6.2.0".into(),
            commit: asn1::octets(&super::fhe_ckks::params::fingerprint(ps)),
            param_name: ps.name.into(),
            config: super::fhe_ckks::params::CONFIG_V1.into(),
            kdf: "sp800-108-ctr-hmac-sha384/v1".into(),
        })
        .ok();
    }
    let (id, name) = FHE_PARAM_SETS.iter().find(|(id, _)| *id == param_set)?;
    asn1::to_der(&FheParamSetV1 {
        id: *id,
        library: "tfhe-rs".into(),
        version: "1.8.1".into(),
        commit: asn1::octets(&TFHE_COMMIT),
        param_name: (*name).into(),
        config: "ConfigBuilder::default().use_dedicated_oprf_key(false)".into(),
        kdf: "sp800-108-ctr-hmac-sha384/v1".into(),
    })
    .ok()
}

/// `CKA_PQCTODAY_FHE_PARAM_HASH`: SHA-384 of the canonical encoding (P0B §4;
/// this retired P1's placeholder hash).
pub fn param_hash(param_set: u32) -> Option<[u8; 48]> {
    param_set_der(param_set).map(|d| super::sha384(&d))
}

pub fn library_id() -> &'static str {
    "tfhe-rs 1.8.1 187fc0b9"
}

/// `CKA_PQCTODAY_FHE_LIBRARY` for a registered parameter set.
pub fn library_for(param_set: u32) -> &'static str {
    if scheme_for(param_set) == Some(FHE_SCHEME_CKKS) {
        "lattigo 6.2.0 streamed-evk/v1"
    } else {
        library_id()
    }
}

/// P0B §3 / amendment A1: the seed's fixed derive template, a profile
/// constant. The engine sets it at KEY_GEN and re-sets it on install, so a
/// replica never loses it; it is never caller-supplied.
pub fn seed_derive_template() -> Vec<u8> {
    let mut out = Vec::new();
    let mut put = |t: u32, v: &[u8]| {
        out.extend_from_slice(&t.to_le_bytes());
        out.extend_from_slice(&(v.len() as u32).to_le_bytes());
        out.extend_from_slice(v);
    };
    put(CKA_CLASS, &(CKO_PUBLIC_KEY as usize).to_le_bytes());
    put(CKA_KEY_TYPE, &(CKK_PQCTODAY_FHE_PUBLIC as usize).to_le_bytes());
    put(CKA_TOKEN, &[0]);
    put(CKA_PRIVATE, &[0]);
    out
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

/// Canonical DER of the version-1 streamed-CKKS profile constraint.
#[cfg(feature = "educational-fhe")]
pub fn ckks_profile_constraint_der() -> Vec<u8> {
    asn1::to_der(&FheProfileConstraint {
        version: 1,
        scheme: FHE_SCHEME_CKKS.to_string(),
        param_sets: super::fhe_ckks::params::CKKS_PARAM_SETS.iter().map(|p| p.id).collect(),
    })
    .expect("static constraint")
}

/// `typeConstraintHash` of the streamed-CKKS seed profile.
#[cfg(feature = "educational-fhe")]
pub fn ckks_profile_constraint_hash() -> [u8; 48] {
    super::sha384(&ckks_profile_constraint_der())
}

/// The profile hash that governs seeds of `scheme`.
pub fn profile_constraint_hash_for(scheme: &str) -> Option<[u8; 48]> {
    match scheme {
        FHE_SCHEME_TFHE => Some(profile_constraint_hash()),
        #[cfg(feature = "educational-fhe")]
        FHE_SCHEME_CKKS => Some(ckks_profile_constraint_hash()),
        _ => None,
    }
}

/// Every FHE profile hash a replication policy may carry.
pub fn is_fhe_profile_hash(h: &[u8; 48]) -> bool {
    [FHE_SCHEME_TFHE, FHE_SCHEME_CKKS].iter().any(|s| profile_constraint_hash_for(s).as_ref() == Some(h))
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

fn default_true() -> bool {
    true
}

fn default_stat_bits() -> u8 {
    30
}

/// Version 2 release rules for streamed-CKKS seeds (plan §4.5): what leaves the
/// token is at most `max_values` decoded slots, rounded to 2^-precision_bits,
/// each part bounded by 2^value_bound_log2, at the one accepted level-0 scale;
/// flooding per audience, sized by `stat_security_bits` and `max_decrypts`.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct CkksReleasePolicy {
    pub max_values: u32,
    pub precision_bits: u8,
    pub value_bound_log2: u8,
    pub scale_log2: u8,
    // Context tags: two adjacent BOOLEAN DEFAULT fields would be ambiguous.
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", default = "default_true")]
    pub flood_recipients: bool,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", default = "default_false")]
    pub flood_owner: bool,
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", default = "default_stat_bits")]
    pub stat_security_bits: u8,
}

impl CkksReleasePolicy {
    /// Per-request leakage bound under model B (plan §4.5), in bits.
    pub fn bits_per_release(&self) -> u64 {
        self.max_values as u64 * 2 * (self.precision_bits as u64 + self.value_bound_log2 as u64 + 1)
    }
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
    /// Version 2 only: CKKS release rules. Absent in version 1, so every
    /// version 1 (TFHE) policy keeps its DER and identifier.
    #[asn1(context_specific = "0", optional = "true")]
    pub ckks: Option<CkksReleasePolicy>,
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
    if !matches!((p.version, &p.ckks), (1, None) | (2, Some(_)))
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
        // P0B §5.3: version 1 refuses compressed ciphertext lists.
        || p.allowed_output_types.iter().chain(p.never_release.iter()).any(|t| t.compressed_allowed)
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
    // Version 1 lists TFHE types only; version 2 lists streamed-CKKS types only.
    let scheme = if p.version == 1 { FHE_SCHEME_TFHE } else { FHE_SCHEME_CKKS };
    if !p.allowed_output_types.iter().chain(p.never_release.iter()).all(|t| scheme_for(t.param_set) == Some(scheme)) {
        return Err(CKR_DATA_INVALID);
    }
    if let Some(c) = &p.ckks {
        #[cfg(feature = "educational-fhe")]
        let max_slots = p.allowed_output_types.iter().filter_map(|t| super::fhe_ckks::params::find(t.param_set)).map(|ps| ps.n() / 2).min().unwrap_or(0);
        #[cfg(not(feature = "educational-fhe"))]
        let max_slots = 0usize;
        if c.max_values == 0
            || c.max_values as usize > max_slots
            || !(1..=30).contains(&c.precision_bits)
            || c.value_bound_log2 > 30
            || !(20..=60).contains(&c.scale_log2)
            || c.precision_bits >= c.scale_log2
            || !(1..=64).contains(&c.stat_security_bits)
            || !p.predicates.is_empty()
        {
            return Err(CKR_DATA_INVALID);
        }
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
            && d.version == s.version
            && match (&d.ckks, &s.ckks) {
                (None, None) => true,
                // Replication may only narrow a CKKS release (plan §4.5).
                (Some(dc), Some(sc)) => {
                    dc.max_values <= sc.max_values
                        && dc.precision_bits <= sc.precision_bits
                        && dc.value_bound_log2 <= sc.value_bound_log2
                        && dc.scale_log2 == sc.scale_log2
                        && dc.stat_security_bits >= sc.stat_security_bits
                        && (dc.flood_recipients || !sc.flood_recipients)
                        && (dc.flood_owner || !sc.flood_owner)
                }
                _ => false,
            }
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
        || scheme_for(d.param_set) != Some(d.scheme.as_str())
        || !FHE_GENERATOR_VERSIONS.contains(&d.generator_version)
        || param_hash(d.param_set).map(|h| h.to_vec()) != Some(d.param_hash.as_bytes().to_vec())
        || d.lineage_id.as_bytes() != header_lineage
        || d.decrypt_policy.as_bytes().len() != 48
    {
        return Err(bad);
    }
    Ok(d)
}

// ── KEY_GEN core (P0B §5.1) ────────────────────────────────────────────────

/// Generate a bound, replicable FHE seed under an enrolled FHE-profile
/// replication policy and an enrolled decryption policy. User role, R/W.
/// `label`/`id` are the only caller-settable attributes (§5.1).
pub fn generate_fhe_seed(
    user_session: u32,
    param_set: u32,
    replication_policy: &[u8; 48],
    decrypt_policy: &[u8; 48],
    label: Option<&[u8]>,
    id: Option<&[u8]>,
) -> Result<u32, u32> {
    generate_fhe_seed_inner(user_session, param_set, replication_policy, decrypt_policy, label, id, None)
}

/// KEY_GEN with a caller-chosen seed value, for known-answer runs only
/// (test-support builds; never in a shipped artefact).
#[cfg(feature = "test-support")]
pub fn generate_fhe_seed_with_value_for_test(
    user_session: u32,
    param_set: u32,
    replication_policy: &[u8; 48],
    decrypt_policy: &[u8; 48],
    seed: &[u8; 32],
    id: &[u8],
) -> Result<u32, u32> {
    generate_fhe_seed_inner(user_session, param_set, replication_policy, decrypt_policy, Some(b"KAT seed (test-support)"), Some(id), Some(*seed))
}

fn generate_fhe_seed_inner(
    user_session: u32,
    param_set: u32,
    replication_policy: &[u8; 48],
    decrypt_policy: &[u8; 48],
    label: Option<&[u8]>,
    id: Option<&[u8]>,
    fixed_seed: Option<[u8; 32]>,
) -> Result<u32, u32> {
    use crate::state::{store_bool, store_ulong};
    super::require_profile()?;
    let slot = super::require_user_rw(user_session)?;
    let pol = records::parse_policy(&records::find_policy(slot, replication_policy).ok_or(CKR_TEMPLATE_INCONSISTENT)?)?;
    let scheme = scheme_for(param_set).ok_or(CKR_TEMPLATE_INCONSISTENT)?;
    if Some(pol.type_constraint_hash) != profile_constraint_hash_for(scheme) {
        return Err(CKR_TEMPLATE_INCONSISTENT);
    }
    // TFHE seeds take version 1 policies; CKKS seeds take version 2 policies
    // that release this parameter set's type (plan §4.5).
    let dp = find_decrypt_policy(slot, decrypt_policy).ok_or(CKR_TEMPLATE_INCONSISTENT)?;
    let fits = match scheme {
        FHE_SCHEME_TFHE => dp.policy.version == 1,
        _ => dp.policy.version == 2 && dp.policy.allowed_output_types.iter().any(|t| t.param_set == param_set),
    };
    if !fits {
        return Err(CKR_TEMPLATE_INCONSISTENT);
    }
    // §6.2 F8: no caller-visible KDF on the seed; only the FHE mechanisms.
    let fhe_mechs = [CKM_PQCTODAY_FHE_DERIVE_PUBLIC, CKM_PQCTODAY_FHE_DECRYPT];
    if !pol.allowed_mechanisms.iter().all(|m| fhe_mechs.contains(m)) {
        return Err(CKR_TEMPLATE_INCONSISTENT);
    }
    let ph = param_hash(param_set).ok_or(CKR_TEMPLATE_INCONSISTENT)?;
    let seed = match fixed_seed {
        Some(v) => v,
        None => super::random32()?,
    };
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
        (CKA_TRUSTED, false),
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
    a.insert(CKA_DERIVE_TEMPLATE, seed_derive_template());
    a.insert(CKA_PQCTODAY_FHE_SCHEME, scheme.as_bytes().to_vec());
    store_ulong(&mut a, CKA_PQCTODAY_FHE_PARAM_SET, param_set);
    a.insert(CKA_PQCTODAY_FHE_PARAM_HASH, ph.to_vec());
    a.insert(CKA_PQCTODAY_FHE_LIBRARY, library_for(param_set).as_bytes().to_vec());
    a.insert(CKA_PQCTODAY_FHE_LINEAGE_ID, lineage.to_vec());
    a.insert(CKA_PQCTODAY_FHE_DECRYPT_POLICY, decrypt_policy.to_vec());
    a.insert(CKA_PQCTODAY_REPLICATION_POLICY_ID, replication_policy.to_vec());
    a.insert(CKA_PRIV_REPL_BINDING, replication_policy.to_vec());
    a.insert(CKA_PQCTODAY_REPLICATION_LINEAGE_ID, lineage.to_vec());
    a.insert(CKA_PRIV_REPL_BUDGET, pol.max_replicas.to_le_bytes().to_vec());
    a.insert(CKA_ALLOWED_MECHANISMS, records::encode_mechanisms(&pol.allowed_mechanisms));
    if let Some(l) = label {
        a.insert(records::CKA_LABEL, l.to_vec());
    }
    if let Some(i) = id {
        a.insert(crate::native::CKA_ID, i.to_vec());
    }
    let h = crate::state::commit_objects_atomically(user_session, vec![a], Vec::new())?[0];
    super::oplog_event("fhe_seed_generated", slot, &[("lineage", super::hex(&lineage))]);
    Ok(h)
}

/// P1 test fixture name, kept for the P1 suite: now the real KEY_GEN core.
#[cfg(feature = "test-support")]
pub fn create_opaque_seed_fixture(
    user_session: u32,
    param_set: u32,
    replication_policy: &[u8; 48],
    decrypt_policy: &[u8; 48],
) -> Result<u32, u32> {
    generate_fhe_seed(user_session, param_set, replication_policy, decrypt_policy, None, None)
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
            ckks: None,
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
        let mut compressed = ty("FheBool", 1);
        compressed.compressed_allowed = true;
        assert!(bad(policy(vec![compressed], vec![], None, 1)), "compressed lists refused in v1 (P0B §5.3)");
    }

    #[cfg(feature = "educational-fhe")]
    fn ckks_policy(c: CkksReleasePolicy) -> FheDecryptPolicy {
        let t = FheType { type_name: "CkksPlaintextQ0".into(), width_bits: 64, param_set: 0x8002, serialization_version: 2, compressed_allowed: false };
        FheDecryptPolicy { version: 2, allowed_output_types: vec![t], never_release: vec![], predicates: vec![], recipients: vec![], recipient_only: false, max_decrypts: 100, ckks: Some(c) }
    }

    #[cfg(feature = "educational-fhe")]
    fn ckks_block() -> CkksReleasePolicy {
        CkksReleasePolicy { max_values: 512, precision_bits: 20, value_bound_log2: 10, scale_log2: 40, flood_recipients: true, flood_owner: false, stat_security_bits: 30 }
    }

    /// PV1–PV3 (plan §4.5): version/scheme pairing, ranges, canonical DER with
    /// defaults omitted, and replication may only narrow a CKKS release.
    #[cfg(feature = "educational-fhe")]
    #[test]
    fn decrypt_policy_v2_ckks_rules() {
        let der = |p: &FheDecryptPolicy| asn1::to_der(p).unwrap();
        let ok = ckks_policy(ckks_block());
        let v = parse_decrypt_policy(&der(&ok)).expect("valid v2");
        // Defaults (flood_recipients = true, flood_owner = false, 30 bits) are not encoded.
        let mut explicit = ok.clone();
        explicit.ckks.as_mut().unwrap().stat_security_bits = 31;
        assert!(der(&explicit).len() > der(&ok).len());
        // A version 1 policy encodes no [0] element, so its DER and identifier are unchanged.
        let t = policy(vec![ty("FheBool", 1)], vec![], None, 1);
        let mut t_der = der(&t);
        let mut with_field = t.clone();
        with_field.ckks = Some(ckks_block());
        assert!(der(&with_field).len() > t_der.len() && parse_decrypt_policy(&t_der).is_ok());
        t_der.clear();
        let bad = |p: FheDecryptPolicy| parse_decrypt_policy(&der(&p)).is_err();
        let mut v1_with_ckks = ok.clone();
        v1_with_ckks.version = 1;
        assert!(bad(v1_with_ckks), "v1 must not carry ckks");
        let mut v2_without = ok.clone();
        v2_without.ckks = None;
        assert!(bad(v2_without), "v2 must carry ckks");
        let mut tfhe_in_v2 = ok.clone();
        tfhe_in_v2.allowed_output_types = vec![ty("FheBool", 1)];
        assert!(bad(tfhe_in_v2), "v2 lists CKKS types only");
        let mut tfhe_v1_ckks_type = policy(vec![ty("FheBool", 1)], vec![], None, 1);
        tfhe_v1_ckks_type.allowed_output_types = ok.allowed_output_types.clone();
        assert!(bad(tfhe_v1_ckks_type), "v1 lists TFHE types only");
        for f in [
            |c: &mut CkksReleasePolicy| c.max_values = 0,
            |c: &mut CkksReleasePolicy| c.max_values = 513,
            |c: &mut CkksReleasePolicy| c.precision_bits = 0,
            |c: &mut CkksReleasePolicy| c.precision_bits = 31,
            |c: &mut CkksReleasePolicy| c.value_bound_log2 = 31,
            |c: &mut CkksReleasePolicy| c.scale_log2 = 19,
            |c: &mut CkksReleasePolicy| c.stat_security_bits = 0,
        ] {
            let mut c = ckks_block();
            f(&mut c);
            assert!(bad(ckks_policy(c)), "range refusal");
        }
        let mut with_pred = ok.clone();
        with_pred.predicates = vec![Predicate { kind: PredicateKind::MaxValue, bound: 1 }];
        assert!(bad(with_pred), "value predicates are not defined for CKKS");
        // Replication ordering.
        let narrow = |f: fn(&mut CkksReleasePolicy)| {
            let mut c = ckks_block();
            f(&mut c);
            let d = parse_decrypt_policy(&der(&ckks_policy(c.clone()))).unwrap_or_else(|e| panic!("{e} {c:?}"));
            d.is_equal_or_stricter_than(&v)
        };
        assert!(narrow(|c| c.max_values = 16));
        assert!(narrow(|c| c.precision_bits = 10));
        assert!(narrow(|c| c.stat_security_bits = 40));
        assert!(narrow(|c| c.flood_owner = true));
        let mut both = ckks_block();
        both.flood_recipients = false;
        both.flood_owner = true;
        assert_eq!(parse_decrypt_policy(&der(&ckks_policy(both.clone()))).unwrap().policy.ckks, Some(both), "tagged defaults round-trip");
        assert!(!narrow(|c| c.flood_recipients = false), "flooding cannot be switched off");
        assert!(!narrow(|c| c.precision_bits = 21));
        assert!(!narrow(|c| c.scale_log2 = 41), "scale is kept");
        assert!(!narrow(|c| c.stat_security_bits = 29));
        assert!(!view(&t).is_equal_or_stricter_than(&v) && !v.is_equal_or_stricter_than(&view(&t)), "no v1/v2 crossing");
        assert_eq!(ckks_block().bits_per_release(), 512 * 2 * 31);
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
