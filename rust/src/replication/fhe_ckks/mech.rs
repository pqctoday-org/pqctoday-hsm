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

/// Decrypt input, serialization version 2: magic ‖ param set ‖ level (must be
/// 0) ‖ log2 scale ‖ reserved 0 (u32 LE each) ‖ c0 ‖ c1 (N × u64 LE each, NTT
/// domain, mod q0). The scale is the caller's statement; the policy accepts one.
pub const CT_MAGIC: &[u8; 8] = b"PQCKKS02";
pub const CT_VERSION: u16 = 2;
const CT_HEADER: usize = 24;
/// The single CKKS release type: decoded slots of a level-0 ciphertext.
pub const CKKS_TYPE_NAME: &str = "CkksPlaintextQ0";
/// Release format: type 3 (rounded CKKS slots) ‖ precision bits ‖ slot count
/// (u16 BE), then per slot round(re·2^p), round(im·2^p) as i64 LE.
pub const OUT_TYPE: u8 = 3;

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
    let ul = tf::template_ulong;
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
/// the policy's scale and the exact length; the policy must allow the exact
/// CKKS release type (name, set, width 64, serialization version 2).
fn type_gate(p: &fhe::FheDecryptPolicy, c: &fhe::CkksReleasePolicy, ps: &CkksParamSet, input: &[u8]) -> Option<FheType> {
    let n = ps.n();
    if input.len() != CT_HEADER + 16 * n || &input[..8] != CT_MAGIC {
        return None;
    }
    let w = |o: usize| u32::from_le_bytes(input[o..o + 4].try_into().unwrap());
    if w(8) != ps.id || w(12) != 0 || w(16) != c.scale_log2 as u32 || w(20) != 0 {
        return None;
    }
    p.allowed_output_types
        .iter()
        .find(|t| t.type_name == CKKS_TYPE_NAME && t.param_set == ps.id && t.width_bits == 64 && t.serialization_version == CT_VERSION && !t.compressed_allowed)
        .cloned()
}

fn output_len(c: &fhe::CkksReleasePolicy) -> usize {
    4 + 16 * c.max_values as usize
}

/// Flood width in bits, log2 σ = λ_s/2 + log2(√q_max) + log2 B (plan §4.6),
/// with B the registry's measured post-bootstrap noise bound.
pub fn flood_sigma_log2(c: &fhe::CkksReleasePolicy, max_decrypts: u32, ps: &CkksParamSet) -> f64 {
    c.stat_security_bits as f64 / 2.0 + (max_decrypts as f64).log2() / 2.0 + params::noise_bound_log2(ps)
}

/// Rounded Gaussian with standard deviation 2^sigma_log2 (Box–Muller on the
/// token DRBG), one value per coefficient.
fn flood(m: &mut [i64], sigma_log2: f64) -> Result<(), u32> {
    let mut k = crate::replication::random32()?;
    let mut st = super::spec::Stream::new(&k);
    k.zeroize();
    let sigma = sigma_log2.exp2();
    let unit = |st: &mut super::spec::Stream| ((st.u64() >> 11) as f64 + 0.5) / (1u64 << 53) as f64;
    for v in m.iter_mut() {
        let (u1, u2) = (unit(&mut st), unit(&mut st));
        let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
        *v = v.saturating_add((sigma * z).round() as i64);
    }
    Ok(())
}

/// Lattigo's CKKS decoding of a level-0 plaintext (centered coefficients) at
/// full slot count N/2: `polyToComplexNoCRT` then `SpecialFFTDouble`.
pub fn decode_slots(m: &[i64], scale_log2: u8) -> Vec<(f64, f64)> {
    let n = m.len();
    let slots = n / 2;
    let big_m = 2 * n;
    let scale = (scale_log2 as f64).exp2();
    let mut v: Vec<(f64, f64)> = (0..slots).map(|i| (m[i] as f64 / scale, m[i + slots] as f64 / scale)).collect();
    // GetRootsComplex128(M)
    let quarm = big_m >> 2;
    let angle = 2.0 * std::f64::consts::PI / big_m as f64;
    let mut roots = vec![(0f64, 0f64); big_m + 1];
    for i in 0..quarm {
        roots[i] = ((angle * i as f64).cos(), 0.0);
    }
    for i in 0..quarm {
        roots[quarm - i].1 += roots[i].0;
    }
    for i in 1..quarm + 1 {
        let r = roots[quarm - i];
        roots[i + quarm] = (-r.0, r.1);
        roots[i + 2 * quarm] = (-roots[i].0, -roots[i].1);
        roots[i + 3 * quarm] = (r.0, -r.1);
    }
    roots[big_m] = roots[0];
    let mut rot = vec![0usize; quarm];
    let mut f = 1usize;
    for r in rot.iter_mut() {
        *r = f;
        f = (f * 5) & (big_m - 1);
    }
    // SpecialFFTDouble(values, slots, M, rotGroup, roots)
    let log_n = slots.trailing_zeros();
    for i in 0..slots {
        let j = if log_n == 0 { 0 } else { i.reverse_bits() >> (usize::BITS - log_n) };
        if i < j {
            v.swap(i, j);
        }
    }
    let log_m = big_m.trailing_zeros() as i32;
    for loglen in 1..=log_n as i32 {
        let len = 1usize << loglen;
        let lenh = len >> 1;
        let lenq = len << 2;
        let log_gap = log_m - 2 - loglen;
        let mask = lenq - 1;
        for i in (0..slots).step_by(len) {
            for j in 0..lenh {
                let (k, kh) = (i + j, i + j + lenh);
                let r = roots[(rot[j] & mask) << log_gap];
                let b = v[kh];
                let t = (b.0 * r.0 - b.1 * r.1, b.0 * r.1 + b.1 * r.0);
                let a = v[k];
                v[k] = (a.0 + t.0, a.1 + t.1);
                v[kh] = (a.0 - t.0, a.1 - t.1);
            }
        }
    }
    v
}

/// `C_Decrypt(CKM_PQCTODAY_FHE_DECRYPT)` for a CKKS seed under a version 2
/// policy (plan §4.5): requester, allowlist, size query, counter, recipient,
/// exact type and scale, never-release, decryption (+ flooding when the
/// policy asks for it), in-token decoding to `max_values` slots, range check,
/// rounding, release. Every refusal after the counter consumes it and is the
/// same `CKR_ACTION_PROHIBITED`.
pub fn decrypt(session: u32, h_seed: u32, recipient: &[u8; 48], input: &[u8], size_only: bool) -> Result<(usize, Option<DecryptOutput>), u32> {
    let (slot, so, ps) = ckks_seed(session, h_seed, CKM_PQCTODAY_FHE_DECRYPT)?;
    if input.is_empty() || input.len() > tf::MAX_DECRYPT_INPUT {
        return Err(CKR_DATA_LEN_RANGE);
    }
    let pid = so.attrs.get(&CKA_PQCTODAY_FHE_DECRYPT_POLICY).cloned().ok_or(CKR_DEVICE_ERROR)?;
    let policy = fhe::find_decrypt_policy(slot, &pid).ok_or_else(|| tf::refuse(slot, "decryption policy not enrolled"))?;
    let p = &policy.policy;
    let c = p.ckks.as_ref().ok_or_else(|| tf::refuse(slot, "policy version"))?;
    let owner = *recipient == [0u8; 48];
    if size_only {
        type_gate(p, c, ps, input).ok_or_else(|| tf::refuse(slot, "type gate"))?;
        // Exact for the owner; an upper bound for a sealed release (Codex #2).
        return Ok((if owner { output_len(c) } else { tf::sealed_len_bound(slot, &so.attrs, recipient, output_len(c))? }, None));
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
    let ty = type_gate(p, c, ps, input).ok_or_else(|| tf::refuse(slot, "type gate"))?;
    if p.never_release.contains(&ty) {
        return Err(tf::refuse(slot, "never-release type"));
    }
    let n = ps.n();
    let words = |off: usize| -> Vec<u64> { (0..n).map(|i| u64::from_le_bytes(input[off + 8 * i..off + 8 * i + 8].try_into().unwrap())).collect() };
    let (c0, c1) = (words(CT_HEADER), words(CT_HEADER + 8 * n));
    let g = Generator::new(ps, &so.seed);
    let m = g.decrypt_q0(&c0, &c1);
    drop(g);
    let mut m = m.map_err(|_| tf::refuse(slot, "type gate"))?;
    let flooded = if owner { c.flood_owner } else { c.flood_recipients };
    if flooded {
        let sigma_log2 = flood_sigma_log2(c, p.max_decrypts, ps);
        if !sigma_log2.is_finite() || sigma_log2 > 62.0 {
            m.zeroize();
            return Err(tf::refuse(slot, "no flooding width for this parameter set"));
        }
        if let Err(e) = flood(&mut m, sigma_log2) {
            m.zeroize();
            return Err(e);
        }
    }
    let mut slots = decode_slots(&m, c.scale_log2);
    m.zeroize();
    slots.truncate(c.max_values as usize);
    let bound = (c.value_bound_log2 as f64).exp2();
    if slots.iter().any(|&(re, im)| !(re.abs() < bound && im.abs() < bound)) {
        slots.iter_mut().for_each(|v| *v = (0.0, 0.0));
        return Err(tf::refuse(slot, "value range"));
    }
    let unit = (c.precision_bits as f64).exp2();
    let mut plain = vec![OUT_TYPE, c.precision_bits];
    plain.extend_from_slice(&(slots.len() as u16).to_be_bytes());
    for (re, im) in slots.iter() {
        plain.extend_from_slice(&((re * unit).round() as i64).to_le_bytes());
        plain.extend_from_slice(&((im * unit).round() as i64).to_le_bytes());
    }
    slots.iter_mut().for_each(|v| *v = (0.0, 0.0));
    crate::replication::oplog_event(
        "fhe_decrypt_released",
        slot,
        &[
            ("policy", crate::replication::hex(&policy.id)),
            ("type", ty.type_name.clone()),
            ("counter", counter.to_string()),
            ("flooded", flooded.to_string()),
            ("recipient", if owner { "owner".into() } else { crate::replication::hex(recipient) }),
        ],
    );
    if owner {
        return Ok((plain.len(), Some(DecryptOutput::Owner(plain))));
    }
    let sealed = tf::seal_release(slot, &so.attrs, &policy.id, recipient, counter, &plain);
    plain.zeroize();
    let sealed = sealed?;
    Ok((sealed.len(), Some(DecryptOutput::Sealed(sealed))))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A plaintext whose coefficients encode slot values through Lattigo's
    /// encoding decodes back: the constant polynomial c·Δ gives c in every slot.
    #[test]
    fn decode_constant_and_monomial() {
        let n = 1024;
        let mut m = vec![0i64; n];
        m[0] = 3 << 30;
        let v = decode_slots(&m, 30);
        assert!(v.iter().all(|&(re, im)| (re - 3.0).abs() < 1e-9 && im.abs() < 1e-9));
        // X^(N/2) evaluates to ±i at every root: purely imaginary unit slots.
        let mut m = vec![0i64; n];
        m[n / 2] = 1 << 30;
        let v = decode_slots(&m, 30);
        assert!(v.iter().all(|&(re, im)| re.abs() < 1e-9 && (im.abs() - 1.0).abs() < 1e-9));
    }
}
