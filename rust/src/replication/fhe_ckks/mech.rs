//! `CKM_PQCTODAY_FHE_DERIVE_PUBLIC` parameter version 2 and
//! `CKM_PQCTODAY_FHE_DECRYPT` for streamed-CKKS seeds (plan §3.2).
//!
//! ```c
//! typedef struct CK_PQCTODAY_FHE_DERIVE_PUBLIC_PARAMS_V2 {
//!     CK_ULONG ulVersion;      /* 2 */
//!     CK_ULONG ulPublicKind;   /* 3 key-set descriptor, 4 public key, 5 evaluation-key chunk */
//!     CK_ULONG ulKeyIndex;     /* kind 5: index into the registry's key list */
//!     CK_ULONG ulDigit;        /* kind 5: gadget digit */
//!     CK_ULONG ulLimbFrom;     /* kinds 4, 5: first limb */
//!     CK_ULONG ulLimbTo;       /* kinds 4, 5: one past the last limb */
//! } CK_PQCTODAY_FHE_DERIVE_PUBLIC_PARAMS_V2;
//! ```
//!
//! Every output is a public SESSION object (`CKA_TOKEN=false`), never
//! persisted, sized before allocation against the 64 MiB per-object cap.
//! Chunk bytes are deterministic in (seed, parameter set, index), so any
//! chunk can be requested again, in any order, on any token holding a replica
//! of the seed, and gives the same bytes. The token never holds the key set.

use der::asn1::OctetString;
use der::Sequence;
use zeroize::Zeroize;

use super::params::{self, CkksParamSet};
use super::spec::Generator;
use crate::constants::*;
use crate::crypto::handlers::Attributes;
use crate::replication::fhe::{self, FheType};
use crate::replication::fhe_tfhe::{self as tf, DecryptOutput, W};
use crate::replication::{asn1, records};

pub const PUBLIC_KIND_CKKS_DESCRIPTOR: u32 = 3;
pub const PUBLIC_KIND_CKKS_PUBLIC_KEY: u32 = 4;
pub const PUBLIC_KIND_CKKS_EVK_CHUNK: u32 = 5;

/// Decrypt input: magic ‖ param set (u32 LE) ‖ level (u32 LE, must be 0) ‖ c0 ‖ c1 (N × u64 LE each, NTT domain, mod q0).
pub const CT_MAGIC: &[u8; 8] = b"PQCKKS01";
/// The single CKKS release type: centered plaintext coefficients mod q0.
pub const CKKS_TYPE_NAME: &str = "CkksPlaintextQ0";
/// Owner output header: type 2 (CKKS coefficients), width 64 bits (BE).
pub const OUT_HEADER: [u8; 3] = [2, 0, 64];

/// Public key-set descriptor: everything a receiver needs besides the chunks.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct CkksKeySetDescriptorV1 {
    pub generator_version: u32,
    pub param_set: u32,
    pub param_hash: OctetString,
    pub lineage: OctetString,
    pub a_seed: OctetString,
    pub key_count: u32,
    pub pk_limbs: u32,
}

/// True when `h` is an FHE seed of a streamed-CKKS parameter set (no access
/// check: the mechanism path repeats every check through `seed_object`).
pub fn is_ckks_seed(h: u32) -> bool {
    records::object_attrs(h)
        .and_then(|a| crate::state::get_object_attr_u32_from(&a, CKA_PQCTODAY_FHE_PARAM_SET))
        .is_some_and(|ps| params::find(ps).is_some())
}

fn ckks_seed(session: u32, h: u32, mechanism: u32) -> Result<(u32, tf::SeedObject, &'static CkksParamSet), u32> {
    let (slot, so) = tf::seed_object(session, h, mechanism)?;
    let ps = crate::state::get_object_attr_u32_from(&so.attrs, CKA_PQCTODAY_FHE_PARAM_SET).and_then(params::find).ok_or(CKR_KEY_TYPE_INCONSISTENT)?;
    if so.attrs.get(&CKA_PQCTODAY_FHE_SCHEME).map(|v| v.as_slice()) != Some(fhe::FHE_SCHEME_CKKS.as_bytes()) {
        return Err(CKR_KEY_TYPE_INCONSISTENT);
    }
    Ok((slot, so, ps))
}

/// Derive one bounded piece of public CKKS material as a public session object.
pub fn derive_public_v2(session: u32, h_seed: u32, kind: u32, k: u32, d: u32, from: usize, to: usize) -> Result<u32, u32> {
    let (slot, so, ps) = ckks_seed(session, h_seed, CKM_PQCTODAY_FHE_DERIVE_PUBLIC)?;
    let n = ps.n();
    // Size and index checks before any allocation (FHE plan §6.6).
    match kind {
        PUBLIC_KIND_CKKS_DESCRIPTOR => {}
        PUBLIC_KIND_CKKS_PUBLIC_KEY => {
            if from >= to || to > ps.pk_limbs() {
                return Err(CKR_MECHANISM_PARAM_INVALID);
            }
        }
        PUBLIC_KIND_CKKS_EVK_CHUNK => {
            let key = ps.keys.get(k as usize).ok_or(CKR_MECHANISM_PARAM_INVALID)?;
            if d as usize >= key.dnum() || from >= to || to > key.limbs() {
                return Err(CKR_MECHANISM_PARAM_INVALID);
            }
        }
        _ => return Err(CKR_MECHANISM_PARAM_INVALID),
    }
    if kind != PUBLIC_KIND_CKKS_DESCRIPTOR && (to - from).saturating_mul(n * 8) > tf::MAX_PUBLIC_OBJECT {
        return Err(CKR_DEVICE_MEMORY);
    }
    let g = Generator::new(ps, &so.seed);
    let value = match kind {
        PUBLIC_KIND_CKKS_DESCRIPTOR => asn1::to_der(&CkksKeySetDescriptorV1 {
            generator_version: 1,
            param_set: ps.id,
            param_hash: asn1::octets(so.attrs.get(&CKA_PQCTODAY_FHE_PARAM_HASH).ok_or(CKR_DEVICE_ERROR)?),
            lineage: asn1::octets(so.attrs.get(&CKA_PQCTODAY_FHE_LINEAGE_ID).ok_or(CKR_DEVICE_ERROR)?),
            a_seed: asn1::octets(&g.a_seed),
            key_count: ps.keys.len() as u32,
            pk_limbs: ps.pk_limbs() as u32,
        })?,
        PUBLIC_KIND_CKKS_PUBLIC_KEY => g.pk_chunk(from, to).map_err(|_| CKR_MECHANISM_PARAM_INVALID)?,
        _ => g.chunk(k, d, from, to).map_err(|_| CKR_MECHANISM_PARAM_INVALID)?,
    };
    drop(g);
    let mut a: Attributes = Default::default();
    crate::state::store_ulong(&mut a, CKA_CLASS, CKO_PUBLIC_KEY);
    crate::state::store_ulong(&mut a, CKA_KEY_TYPE, CKK_PQCTODAY_FHE_PUBLIC);
    crate::state::store_bool(&mut a, CKA_TOKEN, false);
    crate::state::store_bool(&mut a, CKA_PRIVATE, false);
    crate::state::store_bool(&mut a, CKA_MODIFIABLE, false);
    crate::state::store_bool(&mut a, CKA_LOCAL, false);
    crate::state::store_ulong(&mut a, CKA_PQCTODAY_FHE_PUBLIC_KIND, kind);
    for t in [CKA_PQCTODAY_FHE_PARAM_HASH, CKA_PQCTODAY_FHE_LINEAGE_ID] {
        if let Some(v) = so.attrs.get(&t) {
            a.insert(t, v.clone());
        }
    }
    a.insert(CKA_VALUE, value);
    let h = crate::state::commit_objects_atomically(session, vec![a], Vec::new())?[0];
    if kind != PUBLIC_KIND_CKKS_EVK_CHUNK {
        crate::replication::oplog_event("fhe_ckks_derive_public", slot, &[("kind", kind.to_string())]);
    }
    Ok(h)
}

/// `C_DeriveKey(CKM_PQCTODAY_FHE_DERIVE_PUBLIC)` with parameter version 2.
///
/// # Safety
/// FFI pointers as for `C_DeriveKey`.
pub unsafe fn ffi_derive_public_v2(session: u32, base: u32, p_param: *const u8, param_len: usize, tmpl: *mut u8, n: u32) -> Result<u32, u32> {
    let b = tf::param_bytes(p_param, param_len, 6 * W)?;
    if tf::ulong_at(b, 0) != 2 {
        return Err(CKR_MECHANISM_PARAM_INVALID);
    }
    let f = |i: usize| tf::ulong_at(b, i * W);
    let kind = u32::try_from(f(1)).map_err(|_| CKR_MECHANISM_PARAM_INVALID)?;
    let k = u32::try_from(f(2)).map_err(|_| CKR_MECHANISM_PARAM_INVALID)?;
    let d = u32::try_from(f(3)).map_err(|_| CKR_MECHANISM_PARAM_INVALID)?;
    let ul = |v: &[u8]| (v.len() == W).then(|| tf::ulong_at(v, 0) as u32);
    for (t, v) in tf::read_template(tmpl, n)? {
        let ok = match t {
            records::CKA_LABEL => true,
            t if t == crate::native::CKA_ID => true,
            CKA_TOKEN | CKA_PRIVATE => tf::bool_of(&v) == Some(false),
            CKA_CLASS => ul(&v) == Some(CKO_PUBLIC_KEY),
            CKA_KEY_TYPE => ul(&v) == Some(CKK_PQCTODAY_FHE_PUBLIC),
            _ => false,
        };
        if !ok {
            return Err(CKR_TEMPLATE_INCONSISTENT);
        }
    }
    derive_public_v2(session, base, kind, k, d, f(4), f(5))
}

/// Shape-level type gate: the input names this seed's parameter set, level 0,
/// and the exact length; the policy must allow the CKKS release type.
fn type_gate(p: &fhe::FheDecryptPolicy, ps: &CkksParamSet, input: &[u8]) -> Option<FheType> {
    let n = ps.n();
    if input.len() != 16 + 16 * n || &input[..8] != CT_MAGIC {
        return None;
    }
    let pset = u32::from_le_bytes(input[8..12].try_into().ok()?);
    let level = u32::from_le_bytes(input[12..16].try_into().ok()?);
    if pset != ps.id || level != 0 {
        return None;
    }
    p.allowed_output_types.iter().find(|t| t.type_name == CKKS_TYPE_NAME && t.param_set == ps.id && !t.compressed_allowed).cloned()
}

fn output_len(ps: &CkksParamSet) -> usize {
    OUT_HEADER.len() + 8 * ps.n()
}

/// `C_Decrypt(CKM_PQCTODAY_FHE_DECRYPT)` for a CKKS seed, in the order of the
/// FHE spec §5.3 (requester, allowlist, size query, counter, recipient, type
/// gate, never-release, decryption, predicates, release). CKKS values are
/// approximate vectors, so value predicates are refused, not evaluated.
pub fn decrypt(session: u32, h_seed: u32, recipient: &[u8; 48], input: &[u8], size_only: bool) -> Result<(usize, Option<DecryptOutput>), u32> {
    let (slot, so, ps) = ckks_seed(session, h_seed, CKM_PQCTODAY_FHE_DECRYPT)?;
    if input.is_empty() || input.len() > tf::MAX_DECRYPT_INPUT {
        return Err(CKR_DATA_LEN_RANGE);
    }
    let pid = so.attrs.get(&CKA_PQCTODAY_FHE_DECRYPT_POLICY).cloned().ok_or(CKR_DEVICE_ERROR)?;
    let policy = fhe::find_decrypt_policy(slot, &pid).ok_or_else(|| tf::refuse(slot, "decryption policy not enrolled"))?;
    let p = &policy.policy;
    let owner = *recipient == [0u8; 48];
    if size_only {
        type_gate(p, ps, input).ok_or_else(|| tf::refuse(slot, "type gate"))?;
        return Ok((if owner { output_len(ps) } else { 0 }, None));
    }
    let used = so.attrs.get(&tf::CKA_PRIV_FHE_DECRYPT_COUNT).and_then(|v| v.as_slice().try_into().ok()).map(u64::from_le_bytes).unwrap_or(0);
    if used >= p.max_decrypts as u64 {
        return Err(tf::refuse(slot, "decrypt budget exhausted"));
    }
    let counter = used + 1;
    crate::state::commit_objects_atomically(session, Vec::new(), vec![(so.handle, vec![(tf::CKA_PRIV_FHE_DECRYPT_COUNT, counter.to_le_bytes().to_vec())])])?;
    if (owner && p.recipient_only) || (!owner && !p.recipients.iter().any(|r| r.as_bytes() == recipient)) {
        return Err(tf::refuse(slot, "recipient not allowed"));
    }
    let ty = type_gate(p, ps, input).ok_or_else(|| tf::refuse(slot, "type gate"))?;
    if p.never_release.contains(&ty) {
        return Err(tf::refuse(slot, "never-release type"));
    }
    if !p.predicates.is_empty() {
        return Err(tf::refuse(slot, "predicate"));
    }
    let n = ps.n();
    let words = |off: usize| -> Vec<u64> { (0..n).map(|i| u64::from_le_bytes(input[off + 8 * i..off + 8 * i + 8].try_into().unwrap())).collect() };
    let (c0, c1) = (words(16), words(16 + 8 * n));
    let g = Generator::new(ps, &so.seed);
    let m = g.decrypt_q0(&c0, &c1);
    drop(g);
    let mut m = m.map_err(|_| tf::refuse(slot, "type gate"))?;
    // Noise flooding (educational bound, params::FLOOD_LOG2), fresh randomness.
    let mut fk = crate::replication::random32()?;
    let mut st = super::spec::Stream::new(&fk);
    fk.zeroize();
    let span = (1u64 << (params::FLOOD_LOG2 + 1)) + 1;
    let mut plain = OUT_HEADER.to_vec();
    plain.reserve(8 * n);
    for v in m.iter() {
        let f = (st.u64() % span) as i64 - (1i64 << params::FLOOD_LOG2);
        plain.extend_from_slice(&(v + f).to_le_bytes());
    }
    m.zeroize();
    crate::replication::oplog_event(
        "fhe_decrypt_released",
        slot,
        &[("policy", crate::replication::hex(&policy.id)), ("type", ty.type_name.clone()), ("counter", counter.to_string()), ("recipient", if owner { "owner".into() } else { crate::replication::hex(recipient) })],
    );
    if owner {
        return Ok((plain.len(), Some(DecryptOutput::Owner(plain))));
    }
    let sealed = tf::seal_release(slot, &so.attrs, &policy.id, recipient, counter, &plain);
    plain.zeroize();
    let sealed = sealed?;
    Ok((sealed.len(), Some(DecryptOutput::Sealed(sealed))))
}
