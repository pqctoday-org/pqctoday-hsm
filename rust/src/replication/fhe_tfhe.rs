//! FHE P2 — TFHE custody inside the token (P0B spec
//! `docs/proposals/pkcs11-ckm-pqctoday-fhe-proposal.md`, revision 2).
//!
//! Compiled only with the non-default `educational-fhe` feature. The seed
//! never leaves the engine: every operation derives the TFHE client-key seed
//! (§5.5), regenerates the client key, uses it and zeroizes both before
//! returning. Only public material, policy-checked plaintext, or a signed
//! HPKE-sealed release crosses the boundary. The scheme-neutral custody code
//! (seed access, sealed release, C ABI helpers) lives in `fhe_custody` and is
//! re-exported here so existing `fhe_tfhe::…` paths keep working.

use tfhe::prelude::*;
use tfhe::safe_serialization::{safe_deserialize_conformant, safe_serialize};
use tfhe::{ClientKey, CompactPublicKey, CompressedServerKey, ConfigBuilder, Seed};
use zeroize::Zeroize;

pub use super::fhe_custody::*;
use super::fhe::{self, FheType, PredicateKind};
use super::records;
use crate::constants::*;
use crate::crypto::handlers::Attributes;

pub const KDF_LABEL: &[u8] = b"pqctoday-fhe/tfhe-client-key-seed";
pub const PARAM_NAME_V1: &str = "PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128";
pub const LIBRARY_V1: &str = "tfhe-rs 1.8.1 187fc0b9";

pub const PUBLIC_KIND_COMPRESSED_SERVER_KEY: u32 = 1;
pub const PUBLIC_KIND_COMPACT_PUBLIC_KEY: u32 = 2;

fn config_v1() -> tfhe::Config {
    ConfigBuilder::default().use_dedicated_oprf_key(false).build()
}

// ── §5.5 seed derivation (generator version 1) ─────────────────────────────

fn lp(fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for f in fields {
        out.extend_from_slice(&(f.len() as u32).to_be_bytes());
        out.extend_from_slice(f);
    }
    out
}

/// SP 800-108r1 counter mode, PRF HMAC-SHA-384, one block, first 16 bytes
/// big-endian → TFHE-rs `Seed(u128)`.
pub fn derive_tfhe_seed(seed: &[u8; 32]) -> u128 {
    use hmac::{Hmac, Mac};
    let context = lp(&[b"TFHE", PARAM_NAME_V1.as_bytes(), b"cfg:no-dedicated-oprf", b"client", b"v1"]);
    let mut mac = <Hmac<sha2::Sha384> as Mac>::new_from_slice(seed).expect("any key length");
    mac.update(&1u32.to_be_bytes());
    mac.update(KDF_LABEL);
    mac.update(&[0u8]);
    mac.update(&context);
    mac.update(&128u32.to_be_bytes());
    let mut block = mac.finalize().into_bytes();
    let mut first = [0u8; 16];
    first.copy_from_slice(&block[..16]);
    block.as_mut_slice().zeroize();
    u128::from_be_bytes(first)
}

/// The client key for a seed. Callers must drop it promptly; it is never
/// stored, cached or returned across the FFI.
pub fn client_key_for(seed: &[u8; 32]) -> ClientKey {
    let mut s = derive_tfhe_seed(seed);
    let ck = ClientKey::generate_with_seed(config_v1(), Seed(s));
    s.zeroize();
    ck
}

// ── §5.2 DERIVE_PUBLIC ─────────────────────────────────────────────────────

/// Derive fresh public material from the seed as a public SESSION object.
pub fn derive_public(session: u32, h_seed: u32, kind: u32) -> Result<u32, u32> {
    let (slot, so) = seed_object(session, h_seed, CKM_PQCTODAY_FHE_DERIVE_PUBLIC)?;
    if so.attrs.get(&CKA_PQCTODAY_FHE_SCHEME).map(|v| v.as_slice()) != Some(fhe::FHE_SCHEME_TFHE.as_bytes()) {
        // A streamed-CKKS seed uses parameter version 2 (fhe_ckks::mech).
        return Err(CKR_MECHANISM_PARAM_INVALID);
    }
    if kind != PUBLIC_KIND_COMPRESSED_SERVER_KEY && kind != PUBLIC_KIND_COMPACT_PUBLIC_KEY {
        return Err(CKR_MECHANISM_PARAM_INVALID);
    }
    let ck = client_key_for(&so.seed);
    let mut blob = Vec::new();
    let r = if kind == PUBLIC_KIND_COMPRESSED_SERVER_KEY {
        safe_serialize(&CompressedServerKey::new(&ck), &mut blob, MAX_PUBLIC_OBJECT as u64)
    } else {
        safe_serialize(&CompactPublicKey::new(&ck), &mut blob, MAX_PUBLIC_OBJECT as u64)
    };
    drop(ck);
    r.map_err(|_| CKR_DEVICE_MEMORY)?;
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
    a.insert(CKA_VALUE, blob);
    let h = crate::state::commit_objects_atomically(session, vec![a], Vec::new())?[0];
    super::oplog_event("fhe_derive_public", slot, &[("kind", kind.to_string())]);
    Ok(h)
}

/// A matched releasable type and its decrypted value.
struct Matched {
    ty: FheType,
}

fn type_header(ty: &FheType) -> [u8; 3] {
    let tag = if ty.type_name == "FheBool" { 0u8 } else { 1u8 };
    let w = ty.width_bits.to_be_bytes();
    [tag, w[0], w[1]]
}

fn output_len(ty: &FheType) -> usize {
    3 + (ty.width_bits as usize).div_ceil(8)
}

/// Rule 1: the first allowed type whose conformance parameters the input
/// satisfies. Shape only — never touches the key.
fn type_gate(policy: &fhe::FheDecryptPolicy, input: &[u8]) -> Option<Matched> {
    use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128 as P;
    let lim = MAX_DECRYPT_INPUT as u64;
    macro_rules! conf {
        ($t:ty, $p:ty) => {
            safe_deserialize_conformant::<$t>(input, lim, &<$p>::from(P)).is_ok()
        };
    }
    for ty in &policy.allowed_output_types {
        if ty.param_set != 1 || ty.compressed_allowed || ty.serialization_version != 1 {
            continue;
        }
        let ok = match (ty.type_name.as_str(), ty.width_bits) {
            ("FheBool", 1) => conf!(tfhe::FheBool, tfhe::FheBoolConformanceParams),
            ("FheUint2", 2) => conf!(tfhe::FheUint2, tfhe::FheUint2ConformanceParams),
            ("FheUint4", 4) => conf!(tfhe::FheUint4, tfhe::FheUint4ConformanceParams),
            ("FheUint8", 8) => conf!(tfhe::FheUint8, tfhe::FheUint8ConformanceParams),
            ("FheUint16", 16) => conf!(tfhe::FheUint16, tfhe::FheUint16ConformanceParams),
            ("FheUint32", 32) => conf!(tfhe::FheUint32, tfhe::FheUint32ConformanceParams),
            ("FheUint64", 64) => conf!(tfhe::FheUint64, tfhe::FheUint64ConformanceParams),
            _ => false,
        };
        if ok {
            return Some(Matched { ty: ty.clone() });
        }
    }
    None
}

fn decrypt_value(ty: &FheType, input: &[u8], ck: &ClientKey) -> Option<u64> {
    let lim = MAX_DECRYPT_INPUT as u64;
    use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128 as P;
    macro_rules! dec {
        ($t:ty, $p:ty, $out:ty) => {{
            let ct = safe_deserialize_conformant::<$t>(input, lim, &<$p>::from(P)).ok()?;
            let v: $out = ct.decrypt(ck);
            Some(v as u64)
        }};
    }
    match ty.type_name.as_str() {
        "FheBool" => {
            let ct = safe_deserialize_conformant::<tfhe::FheBool>(input, lim, &tfhe::FheBoolConformanceParams::from(P)).ok()?;
            let v: bool = ct.decrypt(ck);
            Some(v as u64)
        }
        "FheUint2" => dec!(tfhe::FheUint2, tfhe::FheUint2ConformanceParams, u8),
        "FheUint4" => dec!(tfhe::FheUint4, tfhe::FheUint4ConformanceParams, u8),
        "FheUint8" => dec!(tfhe::FheUint8, tfhe::FheUint8ConformanceParams, u8),
        "FheUint16" => dec!(tfhe::FheUint16, tfhe::FheUint16ConformanceParams, u16),
        "FheUint32" => dec!(tfhe::FheUint32, tfhe::FheUint32ConformanceParams, u32),
        "FheUint64" => dec!(tfhe::FheUint64, tfhe::FheUint64ConformanceParams, u64),
        _ => None,
    }
}

/// TFHE half of `C_Decrypt(CKM_PQCTODAY_FHE_DECRYPT)`; `fhe_custody::decrypt`
/// routes every non-CKKS seed here.
pub(crate) fn decrypt_tfhe(session: u32, h_seed: u32, recipient: &[u8; 48], input: &[u8], size_only: bool) -> Result<(usize, Option<DecryptOutput>), u32> {
    let (slot, so) = seed_object(session, h_seed, CKM_PQCTODAY_FHE_DECRYPT)?;
    if input.is_empty() || input.len() > MAX_DECRYPT_INPUT {
        return Err(CKR_DATA_LEN_RANGE);
    }
    let pid = so.attrs.get(&CKA_PQCTODAY_FHE_DECRYPT_POLICY).cloned().ok_or(CKR_DEVICE_ERROR)?;
    let policy = fhe::find_decrypt_policy(slot, &pid).ok_or_else(|| refuse(slot, "decryption policy not enrolled"))?;
    let p = &policy.policy;
    let owner = *recipient == [0u8; 48];
    if size_only {
        let m = type_gate(p, input).ok_or_else(|| refuse(slot, "type gate"))?;
        // Exact for the owner; an upper bound for a sealed release (Codex #2).
        return Ok((if owner { output_len(&m.ty) } else { sealed_len_bound(slot, &so.attrs, recipient, output_len(&m.ty))? }, None));
    }
    // Step 4: reserve one unit of the counter durably, before any work.
    let used = so.attrs.get(&CKA_PRIV_FHE_DECRYPT_COUNT).and_then(|v| v.as_slice().try_into().ok()).map(u64::from_le_bytes).unwrap_or(0);
    if used >= p.max_decrypts as u64 {
        return Err(refuse(slot, "decrypt budget exhausted"));
    }
    let counter = used + 1;
    crate::state::commit_objects_atomically(session, Vec::new(), vec![(so.handle, vec![(CKA_PRIV_FHE_DECRYPT_COUNT, counter.to_le_bytes().to_vec())])])?;
    // Step 5: rule 5 (recipient), independent of the plaintext.
    if (owner && p.recipient_only) || (!owner && !p.recipients.iter().any(|r| r.as_bytes() == recipient)) {
        return Err(refuse(slot, "recipient not allowed"));
    }
    // Steps 6–7: type gate, never-release.
    let m = type_gate(p, input).ok_or_else(|| refuse(slot, "type gate"))?;
    if p.never_release.contains(&m.ty) {
        return Err(refuse(slot, "never-release type"));
    }
    // Step 8: decrypt with a regenerated, immediately dropped client key.
    let ck = client_key_for(&so.seed);
    let value = decrypt_value(&m.ty, input, &ck);
    drop(ck);
    let value = value.ok_or_else(|| refuse(slot, "type gate"))?;
    // Step 9: predicates.
    for pr in &p.predicates {
        let ok = match pr.kind {
            PredicateKind::MaxValue => value <= pr.bound,
            PredicateKind::MinValue => value >= pr.bound,
        };
        if !ok {
            return Err(refuse(slot, "predicate"));
        }
    }
    // Step 10: release.
    let mut plain = type_header(&m.ty).to_vec();
    let nbytes = (m.ty.width_bits as usize).div_ceil(8);
    plain.extend_from_slice(&value.to_le_bytes()[..nbytes.min(8)]);
    plain.resize(3 + nbytes, 0);
    super::oplog_event(
        "fhe_decrypt_released",
        slot,
        &[("policy", super::hex(&policy.id)), ("type", m.ty.type_name.clone()), ("counter", counter.to_string()), ("recipient", if owner { "owner".into() } else { super::hex(recipient) })],
    );
    if owner {
        return Ok((plain.len(), Some(DecryptOutput::Owner(plain))));
    }
    let sealed = seal_release(slot, &so.attrs, &policy.id, recipient, counter, &plain);
    plain.zeroize();
    let sealed = sealed?;
    Ok((sealed.len(), Some(DecryptOutput::Sealed(sealed))))
}

// ── §5.4 ENCRYPT (test builds only) ────────────────────────────────────────

/// Encrypt an owner-output-format plaintext under the seed's client key.
/// TEST-ONLY (known-answer vectors); absent without `test-support`.
#[cfg(feature = "test-support")]
pub fn encrypt_for_test(session: u32, h_seed: u32, type_name: &str, value: u64) -> Result<Vec<u8>, u32> {
    let (_, so) = seed_object_any(session, h_seed)?;
    let ck = client_key_for(&so.seed);
    let mut out = Vec::new();
    let lim = MAX_DECRYPT_INPUT as u64;
    let r = match type_name {
        "FheBool" => safe_serialize(&tfhe::FheBool::encrypt(value != 0, &ck), &mut out, lim),
        "FheUint8" => safe_serialize(&tfhe::FheUint8::encrypt(value as u8, &ck), &mut out, lim),
        "FheUint16" => safe_serialize(&tfhe::FheUint16::encrypt(value as u16, &ck), &mut out, lim),
        "FheUint32" => safe_serialize(&tfhe::FheUint32::encrypt(value as u32, &ck), &mut out, lim),
        "FheUint64" => safe_serialize(&tfhe::FheUint64::encrypt(value, &ck), &mut out, lim),
        _ => return Err(CKR_MECHANISM_PARAM_INVALID),
    };
    r.map_err(|_| CKR_DEVICE_ERROR)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §5.5 known-answer vector `client-key-kat-v1`.
    #[test]
    fn kat_client_key_v1() {
        let seed: [u8; 32] = core::array::from_fn(|i| i as u8);
        assert_eq!(derive_tfhe_seed(&seed), 0xf6eb1c9a88a4442c8a7449536c3d12dc);
        let ck = client_key_for(&seed);
        let mut buf = Vec::new();
        safe_serialize(&ck, &mut buf, 1 << 32).unwrap();
        assert_eq!(buf.len(), 24_087);
        let h: String = super::super::sha256(&buf).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(h, "9f5d847e4d1121eef9d75fcc473e89ee5306523f9cb140384eba5aa85a55b77b");
    }
}

// ── C ABI dispatch helpers, TFHE half (P0B §5; via fhe_custody / ffi.rs) ──

/// `C_DeriveKey(CKM_PQCTODAY_FHE_DERIVE_PUBLIC)` parameter version 1 (TFHE
/// kinds 1/2); `fhe_custody::ffi_derive_public` routes here.
///
/// # Safety
/// FFI pointers as for `C_DeriveKey`.
pub(crate) unsafe fn ffi_derive_public_v1(session: u32, base: u32, p_param: *const u8, param_len: usize, tmpl: *mut u8, n: u32) -> Result<u32, u32> {
    let b = param_bytes(p_param, param_len, 2 * W)?;
    if ulong_at(b, 0) != 1 {
        return Err(CKR_MECHANISM_PARAM_INVALID);
    }
    let kind = u32::try_from(ulong_at(b, W)).map_err(|_| CKR_MECHANISM_PARAM_INVALID)?;
    let ul = template_ulong;
    for (t, v) in read_template(tmpl, n)? {
        let ok = match t {
            records::CKA_LABEL => true,
            t if t == crate::native::CKA_ID => true,
            CKA_TOKEN | CKA_PRIVATE => bool_of(&v) == Some(false),
            CKA_CLASS => ul(&v) == Some(CKO_PUBLIC_KEY),
            CKA_KEY_TYPE => ul(&v) == Some(CKK_PQCTODAY_FHE_PUBLIC),
            _ => false,
        };
        if !ok {
            return Err(CKR_TEMPLATE_INCONSISTENT);
        }
    }
    derive_public(session, base, kind)
}

/// `C_EncryptInit(CKM_PQCTODAY_FHE_ENCRYPT)` — test builds only (§5.4).
///
/// # Safety
/// FFI pointers as for `C_EncryptInit`.
#[cfg(feature = "test-support")]
pub unsafe fn ffi_encrypt_init(session: u32, key: u32) -> Result<(), u32> {
    seed_object_any(session, key)?;
    ops(|m| m.insert(session, FheOp::Encrypt { key }));
    Ok(())
}

/// `C_Encrypt` for an active FHE test encryption: input is the owner-output
/// format (3-byte header + LE value).
///
/// # Safety
/// FFI pointers as for `C_Encrypt`.
#[cfg(feature = "test-support")]
pub unsafe fn ffi_encrypt(session: u32, input: *const u8, in_len: u32, out: *mut u8, out_len: *mut u32) -> u32 {
    let Some(FheOp::Encrypt { key }) = active(session) else {
        return CKR_OPERATION_NOT_INITIALIZED;
    };
    if input.is_null() || out_len.is_null() || in_len < 4 {
        cancel(session);
        return CKR_ARGUMENTS_BAD;
    }
    let b = std::slice::from_raw_parts(input, in_len as usize);
    let width = u16::from_be_bytes([b[1], b[2]]);
    let mut v = [0u8; 8];
    let n = (b.len() - 3).min(8);
    v[..n].copy_from_slice(&b[3..3 + n]);
    let name = match (b[0], width) {
        (0, 1) => "FheBool",
        (1, 8) => "FheUint8",
        (1, 16) => "FheUint16",
        (1, 32) => "FheUint32",
        (1, 64) => "FheUint64",
        _ => {
            cancel(session);
            return CKR_DATA_INVALID;
        }
    };
    let ct = match encrypt_for_test(session, key, name, u64::from_le_bytes(v)) {
        Ok(c) => c,
        Err(e) => {
            cancel(session);
            return e;
        }
    };
    if out.is_null() {
        *out_len = ct.len() as u32;
        return CKR_OK;
    }
    if (*out_len as usize) < ct.len() {
        *out_len = ct.len() as u32;
        return CKR_BUFFER_TOO_SMALL;
    }
    cancel(session);
    std::ptr::copy_nonoverlapping(ct.as_ptr(), out, ct.len());
    *out_len = ct.len() as u32;
    CKR_OK
}
