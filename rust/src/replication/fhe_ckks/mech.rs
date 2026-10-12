//! `CKM_PQCTODAY_FHE_DERIVE_PUBLIC` parameter version 2 and
//! `CKM_PQCTODAY_FHE_DECRYPT` for streamed-CKKS seeds (plan §3.2).
//!
//! ```c
//! typedef struct CK_PQCTODAY_FHE_DERIVE_PUBLIC_PARAMS_V2 {
//!     CK_ULONG ulVersion;      /* 2 */
//!     CK_ULONG ulPublicKind;   /* 3 key-set descriptor, 4 public key, 5 evaluation-key chunk, 6 manifest */
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
//!
//! Ledger and manifest (plan §3.2, E3): kind 3 starts (or restarts) a
//! per-session ledger for the seed; every kind-4/5 object is recorded in it as
//! `(kind, key, digit, from, to, SHA-256(value))` and needs a ledger for the
//! same seed (`CKR_OPERATION_NOT_INITIALIZED` otherwise). Kind 6 (key, digit
//! and limbs all 0) returns a DER `CkksSignedManifestV1` signed by the device's
//! receipt-signing key, only when the ledger covers the public key and every
//! (key, digit) exactly once (`CKR_FUNCTION_FAILED` otherwise), and then
//! clears the ledger:
//!
//! ```text
//! CkksChunkHash ::= SEQUENCE { kind INTEGER, key INTEGER, digit INTEGER,
//!     from INTEGER, to INTEGER, sha256 OCTET STRING (SIZE(32)) }
//! CkksManifestTbsV1 ::= SEQUENCE { version INTEGER (1),
//!     descriptorHash OCTET STRING (SIZE(32)), paramHash OCTET STRING,
//!     lineage OCTET STRING, entries SEQUENCE OF CkksChunkHash }
//! CkksSignedManifestV1 ::= SEQUENCE { tbs CkksManifestTbsV1,
//!     signature OCTET STRING, signerChain SEQUENCE OF Certificate }
//! signed bytes = "PQCToday CKKS Manifest 1.0" || 0x00 || DER(tbs)
//! ```
//!
//! Entries are in ledger order: (kind, key, digit, from) ascending.

use std::collections::BTreeMap;

use der::asn1::OctetString;
use der::Sequence;
use x509_cert::Certificate;
use zeroize::Zeroize;

use super::params::{self, CkksParamSet};
use super::spec::Generator;
use crate::constants::*;
use crate::crypto::handlers::Attributes;
use crate::replication::fhe::{self, FheType};
use crate::replication::fhe_custody::{self as tf, DecryptOutput, W};
use crate::replication::{asn1, records};

pub const PUBLIC_KIND_CKKS_DESCRIPTOR: u32 = 3;
pub const PUBLIC_KIND_CKKS_PUBLIC_KEY: u32 = 4;
pub const PUBLIC_KIND_CKKS_EVK_CHUNK: u32 = 5;
pub const PUBLIC_KIND_CKKS_MANIFEST: u32 = 6;
/// Domain separator of the token-signed manifest (signed bytes are this ‖ 0x00 ‖ DER(tbs)).
pub const MANIFEST_DOMAIN: &[u8] = b"PQCToday CKKS Manifest 1.0";

/// Decrypt input, serialization version 2 (one-prime sets, release level 0):
/// magic ‖ param set ‖ level (must be 0) ‖ log2 scale ‖ reserved 0 (u32 LE
/// each) ‖ c0 ‖ c1 (N × u64 LE each, NTT domain, mod q0). The scale is the
/// caller's statement; the policy accepts one.
pub const CT_MAGIC: &[u8; 8] = b"PQCKKS02";
pub const CT_VERSION: u16 = 2;
/// Decrypt input, serialization version 3 (E13): the same header with the
/// level the set releases at (`params::release_level`, 1 for registry ID 3),
/// then c0 limbs 0..=level and c1 limbs 0..=level (N × u64 LE each, NTT
/// domain, limb-major). Version 2 stays the format of the level-0 sets.
pub const CT_MAGIC_V3: &[u8; 8] = b"PQCKKS03";
pub const CT_VERSION_V3: u16 = 3;
const CT_HEADER: usize = 24;
/// CKKS release type of a level-0 ciphertext: its decoded slots.
pub const CKKS_TYPE_NAME: &str = "CkksPlaintextQ0";
/// CKKS release type of a level-1 ciphertext (two primes, registry ID 3).
pub const CKKS_TYPE_NAME_Q1: &str = "CkksPlaintextQ1";

/// The release type a decryption policy lists for a parameter set: its
/// release level's type name, width 64, serialization version 2 for level 0
/// and 3 above.
pub fn release_type(ps: &CkksParamSet) -> FheType {
    let level = params::release_level(ps);
    FheType {
        type_name: if level == 0 { CKKS_TYPE_NAME } else { CKKS_TYPE_NAME_Q1 }.into(),
        width_bits: 64,
        param_set: ps.id,
        serialization_version: if level == 0 { CT_VERSION } else { CT_VERSION_V3 },
        compressed_allowed: false,
    }
}
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

/// One ledger entry of the token-signed manifest.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct CkksChunkHash {
    pub kind: u32,
    pub key: u32,
    pub digit: u32,
    pub from: u32,
    pub to: u32,
    pub sha256: OctetString,
}

/// What the token signs: the descriptor it served and every chunk hash.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct CkksManifestTbsV1 {
    pub version: u32,
    pub descriptor_hash: OctetString,
    pub param_hash: OctetString,
    pub lineage: OctetString,
    pub entries: Vec<CkksChunkHash>,
}

/// Kind 6 output.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct CkksSignedManifestV1 {
    pub tbs: CkksManifestTbsV1,
    pub signature: OctetString,
    pub signer_chain: Vec<Certificate>,
}

/// The bytes the receipt-signing key signs for a manifest.
pub fn manifest_signed_bytes(tbs: &CkksManifestTbsV1) -> Result<Vec<u8>, u32> {
    let mut msg = MANIFEST_DOMAIN.to_vec();
    msg.push(0);
    msg.extend_from_slice(&asn1::to_der(tbs)?);
    Ok(msg)
}

/// Receiver side: decode a `CkksSignedManifestV1`, validate its signer chain
/// for the receipt-signing purpose against `trust` at `now`, and verify the
/// ML-DSA-65 signature. Returns the TBS and the signer's device id. Coverage
/// and chunk hashes are the caller's to check against the files it holds.
pub fn verify_ckks_manifest(der: &[u8], trust: &crate::replication::pki::TrustInputs, now: u64) -> Result<(CkksManifestTbsV1, [u8; 32]), u32> {
    use crate::replication::{oids::Purpose, pki};
    let m: CkksSignedManifestV1 = asn1::decode_strict(der, tf::MAX_PUBLIC_OBJECT)?;
    if m.tbs.version != 1 || m.tbs.descriptor_hash.as_bytes().len() != 32 || m.tbs.entries.iter().any(|e| e.sha256.as_bytes().len() != 32) {
        return Err(CKR_SIGNATURE_INVALID);
    }
    let chain = pki::validate_chain(&m.signer_chain, Purpose::ReceiptSigning, trust, now, crate::replication::Profile::Educational).map_err(|_| CKR_SIGNATURE_INVALID)?;
    let pk = pki::mldsa65_public(&chain.leaf).map_err(|_| CKR_SIGNATURE_INVALID)?;
    if !crate::replication::mldsa65_verify(pk, &manifest_signed_bytes(&m.tbs)?, m.signature.as_bytes()) {
        return Err(CKR_SIGNATURE_INVALID);
    }
    Ok((m.tbs, chain.device_id))
}

// ── Session ledger (E3) ────────────────────────────────────────────────────

pub(super) type LedgerKey = (u32, u32, u32, u32); // (kind, key, digit, from)

pub(super) struct Ledger {
    pub(super) slot: u32,
    pub(super) seed_handle: u32,
    /// Rotation ledgers (parameter version 3): the old seed. `None` for a
    /// key-set ledger (version 2); the two never stand in for each other.
    pub(super) old_seed: Option<u32>,
    pub(super) descriptor_hash: [u8; 32],
    pub(super) entries: BTreeMap<LedgerKey, (u32, [u8; 32])>,
    /// An overlapping range or a different hash for a repeated range was
    /// seen: the manifest is refused until a new descriptor restarts the ledger.
    pub(super) invalid: bool,
}

impl Ledger {
    pub(super) fn record(&mut self, kind: u32, k: u32, d: u32, from: u32, to: u32, hash: [u8; 32]) {
        use std::ops::Bound::{Excluded, Unbounded};
        let key = (kind, k, d, from);
        if let Some(&(t, h)) = self.entries.get(&key) {
            // An identical repeat is idempotent; anything else is a conflict.
            if t != to || h != hash {
                self.invalid = true;
            }
            return;
        }
        let same = |o: &LedgerKey| (o.0, o.1, o.2) == (kind, k, d);
        let before = self.entries.range(..key).next_back().is_some_and(|(o, &(t, _))| same(o) && t > from);
        let after = self.entries.range((Excluded(key), Unbounded)).next().is_some_and(|(o, _)| same(o) && o.3 < to);
        if before || after {
            self.invalid = true;
            return;
        }
        self.entries.insert(key, (to, hash));
    }

    /// The public key and every (key, digit) of `ps` covered exactly once.
    fn covers(&self, ps: &CkksParamSet) -> bool {
        let mut groups = vec![(PUBLIC_KIND_CKKS_PUBLIC_KEY, 0u32, 0u32, ps.pk_limbs())];
        for (k, key) in ps.keys.iter().enumerate() {
            groups.extend((0..key.dnum()).map(|d| (PUBLIC_KIND_CKKS_EVK_CHUNK, k as u32, d as u32, key.limbs())));
        }
        self.covers_groups(groups)
    }

    /// Every digit of the rotation key covered exactly once (key index 0).
    pub(super) fn covers_rotation(&self, ps: &CkksParamSet) -> bool {
        let k = ps.rotation_desc();
        self.covers_groups((0..k.dnum()).map(|d| (PUBLIC_KIND_CKKS_EVK_CHUNK, 0u32, d as u32, k.limbs())).collect())
    }

    /// Each (kind, key, digit, limbs) group tiled exactly once, nothing else.
    fn covers_groups(&self, groups: Vec<(u32, u32, u32, usize)>) -> bool {
        if self.invalid {
            return false;
        }
        let mut used = 0usize;
        for (kind, k, d, limbs) in groups {
            let mut at = 0u32;
            while (at as usize) < limbs {
                match self.entries.get(&(kind, k, d, at)) {
                    Some(&(to, _)) if to > at => at = to,
                    _ => return false,
                }
                used += 1;
            }
            if at as usize != limbs {
                return false;
            }
        }
        used == self.entries.len()
    }
}

/// One ledger per session, keyed by session handle.
static LEDGERS: std::sync::Mutex<BTreeMap<u32, Ledger>> = std::sync::Mutex::new(BTreeMap::new());

pub(super) fn ledgers() -> std::sync::MutexGuard<'static, BTreeMap<u32, Ledger>> {
    LEDGERS.lock().unwrap_or_else(|e| e.into_inner())
}

/// Drop the ledger of `session` (C_CloseSession).
pub fn clear_ledger_for_session(session: u32) {
    ledgers().remove(&session);
}

/// Drop every ledger on `slot` (C_CloseAllSessions, C_Logout, C_InitToken).
pub fn clear_ledgers_for_slot(slot: u32) {
    ledgers().retain(|_, l| l.slot != slot);
}

/// Drop every ledger (C_Finalize).
pub fn clear_ledgers() {
    ledgers().clear();
}

fn clear_ledgers_for_seed(h: u32) {
    ledgers().retain(|_, l| l.seed_handle != h && l.old_seed != Some(h));
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

/// One cached generator for the whole token (A9): regenerating the secret
/// costs about 6 ms per call on an M4 Pro core and about 10x that on a
/// Cortex-A55, a fixed cost that dominates small chunks. The entry is bound
/// to the session, the seed handle and the seed bytes, expires after
/// `GEN_CACHE_IDLE_SECS` without use, and is zeroized on C_CloseSession,
/// C_CloseAllSessions, C_Logout and C_Finalize (`clear_generator_cache`) and
/// when the seed object is destroyed or modified (`clear_generator_cache_for`).
/// Not hooked into `drop_key_caches`: C_DestroyObject on each exported chunk
/// would empty it on every call.
/// Output bytes are unchanged; the trade-off is that the expanded secret stays
/// in token memory for the duration of an export.
#[cfg(not(target_arch = "wasm32"))]
struct GenCacheEntry {
    session: u32,
    seed_handle: u32,
    last_used: std::time::Instant,
    generator: std::sync::Arc<Generator>,
}

#[cfg(not(target_arch = "wasm32"))]
static GEN_CACHE: std::sync::Mutex<Option<GenCacheEntry>> = std::sync::Mutex::new(None);
#[cfg(not(target_arch = "wasm32"))]
pub const GEN_CACHE_IDLE_SECS: u64 = 30;

/// Drop (and so zeroize) the cached generator.
pub fn clear_generator_cache() {
    #[cfg(not(target_arch = "wasm32"))]
    if let Ok(mut c) = GEN_CACHE.lock() {
        *c = None;
    }
}

/// Drop the cached generator if it was built from object `h` (its seed is
/// being destroyed or changed), and every ledger for that seed.
pub fn clear_generator_cache_for(h: u32) {
    clear_ledgers_for_seed(h);
    #[cfg(not(target_arch = "wasm32"))]
    if let Ok(mut c) = GEN_CACHE.lock() {
        if c.as_ref().is_some_and(|e| e.seed_handle == h) {
            *c = None;
        }
    }
    #[cfg(target_arch = "wasm32")]
    let _ = h;
}

/// The seed handle the cached generator was built from (tests only).
#[cfg(feature = "test-support")]
pub fn generator_cache_seed_for_test() -> Option<u32> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        GEN_CACHE.lock().ok().and_then(|c| c.as_ref().map(|e| e.seed_handle))
    }
    #[cfg(target_arch = "wasm32")]
    None
}

/// Whether `session` holds a ledger, and for which (seed, old seed) (tests only).
#[cfg(feature = "test-support")]
pub fn ledger_for_test(session: u32) -> Option<(u32, Option<u32>)> {
    ledgers().get(&session).map(|l| (l.seed_handle, l.old_seed))
}

fn generator_for(session: u32, h_seed: u32, ps: &'static CkksParamSet, seed: &[u8; 32]) -> std::sync::Arc<Generator> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        if let Ok(mut c) = GEN_CACHE.lock() {
            let fresh = c.as_ref().is_some_and(|e| {
                e.session == session && e.seed_handle == h_seed && e.last_used.elapsed().as_secs() < GEN_CACHE_IDLE_SECS && e.generator.same_seed(ps, seed)
            });
            if !fresh {
                *c = Some(GenCacheEntry { session, seed_handle: h_seed, last_used: std::time::Instant::now(), generator: std::sync::Arc::new(Generator::new(ps, seed)) });
            }
            let e = c.as_mut().expect("just set");
            e.last_used = std::time::Instant::now();
            return e.generator.clone();
        }
    }
    let _ = (session, h_seed);
    std::sync::Arc::new(Generator::new(ps, seed))
}

/// Derive one bounded piece of public CKKS material as a public session object.
pub fn derive_public_v2(session: u32, h_seed: u32, kind: u32, k: u32, d: u32, from: usize, to: usize) -> Result<u32, u32> {
    let (slot, so, ps) = ckks_seed(session, h_seed, CKM_PQCTODAY_FHE_DERIVE_PUBLIC)?;
    let n = ps.n();
    // Size and index checks before any allocation (FHE plan §6.6).
    match kind {
        PUBLIC_KIND_CKKS_DESCRIPTOR => {}
        PUBLIC_KIND_CKKS_MANIFEST => {
            if (k, d, from, to) != (0, 0, 0, 0) {
                return Err(CKR_MECHANISM_PARAM_INVALID);
            }
            return derive_manifest(session, slot, h_seed, &so, ps);
        }
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
    // A chunk needs this session's ledger for this seed (refused before any work).
    if kind != PUBLIC_KIND_CKKS_DESCRIPTOR && !ledgers().get(&session).is_some_and(|l| l.seed_handle == h_seed && l.old_seed.is_none()) {
        return Err(CKR_OPERATION_NOT_INITIALIZED);
    }
    let g = generator_for(session, h_seed, ps, &so.seed);
    let value = match kind {
        PUBLIC_KIND_CKKS_DESCRIPTOR => keyset_descriptor_der(&so, ps, &g)?,
        PUBLIC_KIND_CKKS_PUBLIC_KEY => g.pk_chunk(from, to).map_err(|_| CKR_MECHANISM_PARAM_INVALID)?,
        _ => g.chunk(k, d, from, to).map_err(|_| CKR_MECHANISM_PARAM_INVALID)?,
    };
    drop(g);
    {
        let mut l = ledgers();
        let hash = crate::replication::sha256(&value);
        if kind == PUBLIC_KIND_CKKS_DESCRIPTOR {
            l.insert(session, Ledger { slot, seed_handle: h_seed, old_seed: None, descriptor_hash: hash, entries: BTreeMap::new(), invalid: false });
        } else {
            // Re-checked under the lock: a close or destroy may have run meanwhile.
            let led = l.get_mut(&session).filter(|x| x.seed_handle == h_seed && x.old_seed.is_none()).ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
            led.record(kind, k, d, from as u32, to as u32, hash);
        }
    }
    let h = public_object(session, &so, kind, value)?;
    if kind != PUBLIC_KIND_CKKS_EVK_CHUNK {
        crate::replication::oplog_event("fhe_ckks_derive_public", slot, &[("kind", kind.to_string())]);
    }
    Ok(h)
}

/// Kind 6: sign the session's ledger if it covers the set exactly once.
fn derive_manifest(session: u32, slot: u32, h_seed: u32, so: &tf::SeedObject, ps: &'static CkksParamSet) -> Result<u32, u32> {
    let refuse = |why: &str| {
        crate::replication::oplog_event("fhe_ckks_manifest_refused", slot, &[("reason", format!("\"{why}\""))]);
        CKR_FUNCTION_FAILED
    };
    let (descriptor_hash, entries) = {
        let l = ledgers();
        let led = l.get(&session).filter(|x| x.seed_handle == h_seed && x.old_seed.is_none()).ok_or(CKR_OPERATION_NOT_INITIALIZED)?;
        if led.invalid {
            return Err(refuse("overlapping or conflicting chunk"));
        }
        if !led.covers(ps) {
            return Err(refuse("incomplete coverage"));
        }
        let entries: Vec<CkksChunkHash> = led
            .entries
            .iter()
            .map(|(&(kind, key, digit, from), &(to, h))| CkksChunkHash { kind, key, digit, from, to, sha256: asn1::octets(&h) })
            .collect();
        (led.descriptor_hash, entries)
    };
    let tbs = CkksManifestTbsV1 {
        version: 1,
        descriptor_hash: asn1::octets(&descriptor_hash),
        param_hash: asn1::octets(so.attrs.get(&CKA_PQCTODAY_FHE_PARAM_HASH).ok_or(CKR_DEVICE_ERROR)?),
        lineage: asn1::octets(so.attrs.get(&CKA_PQCTODAY_FHE_LINEAGE_ID).ok_or(CKR_DEVICE_ERROR)?),
        entries,
    };
    let (sig, chain) = tf::receipt_sign(slot, &manifest_signed_bytes(&tbs)?)?;
    let value = asn1::to_der(&CkksSignedManifestV1 { tbs, signature: asn1::octets(&sig), signer_chain: chain })?;
    if value.len() > tf::MAX_PUBLIC_OBJECT {
        return Err(CKR_DEVICE_MEMORY);
    }
    let h = public_object(session, so, PUBLIC_KIND_CKKS_MANIFEST, value)?;
    // Signed once: the next manifest needs a fresh descriptor and full export.
    let mut l = ledgers();
    if l.get(&session).is_some_and(|x| x.seed_handle == h_seed && x.old_seed.is_none() && x.descriptor_hash == descriptor_hash) {
        l.remove(&session);
    }
    drop(l);
    crate::replication::oplog_event("fhe_ckks_derive_public", slot, &[("kind", PUBLIC_KIND_CKKS_MANIFEST.to_string())]);
    Ok(h)
}

/// Kind 3 (version 2): the seed's public key-set descriptor.
pub(super) fn keyset_descriptor_der(so: &tf::SeedObject, ps: &CkksParamSet, g: &Generator) -> Result<Vec<u8>, u32> {
    asn1::to_der(&CkksKeySetDescriptorV1 {
        generator_version: params::GENERATOR_VERSION,
        param_set: ps.id,
        param_hash: asn1::octets(so.attrs.get(&CKA_PQCTODAY_FHE_PARAM_HASH).ok_or(CKR_DEVICE_ERROR)?),
        lineage: asn1::octets(so.attrs.get(&CKA_PQCTODAY_FHE_LINEAGE_ID).ok_or(CKR_DEVICE_ERROR)?),
        a_seed: asn1::octets(&g.a_seed),
        key_count: ps.keys.len() as u32,
        pk_limbs: ps.pk_limbs() as u32,
    })
}

/// Store `value` as a public, non-token session object of `kind`.
pub(super) fn public_object(session: u32, so: &tf::SeedObject, kind: u32, value: Vec<u8>) -> Result<u32, u32> {
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
    Ok(crate::state::commit_objects_atomically(session, vec![a], Vec::new())?[0])
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
    check_public_template(tmpl, n)?;
    derive_public_v2(session, base, kind, k, d, f(4), f(5))
}

/// The derive template may only restate the fixed public-object template
/// plus CKA_LABEL/CKA_ID.
///
/// # Safety
/// FFI pointers as for `C_DeriveKey`.
pub(super) unsafe fn check_public_template(tmpl: *mut u8, n: u32) -> Result<(), u32> {
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
    Ok(())
}

/// `C_DeriveKey(CKM_PQCTODAY_FHE_DERIVE_PUBLIC)` with parameter version 3:
/// the CKKS rotation key (E10, `rotation`). The two seeds are named by their
/// lineages in the parameter; `hBaseKey` must be `CK_INVALID_HANDLE`.
///
/// # Safety
/// FFI pointers as for `C_DeriveKey`.
pub unsafe fn ffi_derive_public_v3(session: u32, base: u32, p_param: *const u8, param_len: usize, tmpl: *mut u8, n: u32) -> Result<u32, u32> {
    let b = tf::param_bytes(p_param, param_len, 6 * W + 64)?;
    if tf::ulong_at(b, 0) != 3 {
        return Err(CKR_MECHANISM_PARAM_INVALID);
    }
    if base != 0 {
        return Err(CKR_KEY_HANDLE_INVALID);
    }
    let f = |i: usize| tf::ulong_at(b, i * W);
    let u = |i: usize| u32::try_from(f(i)).map_err(|_| CKR_MECHANISM_PARAM_INVALID);
    let (kind, k, d) = (u(1)?, u(2)?, u(3)?);
    let old: [u8; 32] = b[6 * W..6 * W + 32].try_into().unwrap();
    let new: [u8; 32] = b[6 * W + 32..6 * W + 64].try_into().unwrap();
    check_public_template(tmpl, n)?;
    super::rotation::derive_rotation(session, &old, &new, kind, k, d, f(4), f(5))
}

/// Shape-level type gate: the input names this seed's parameter set, the
/// set's release level, the policy's scale and the exact length, in the
/// serialization version of that level (2 for level 0, 3 above); the policy
/// must allow the exact CKKS release type (`release_type`). Returns the type
/// and the level.
fn type_gate(p: &fhe::FheDecryptPolicy, c: &fhe::CkksReleasePolicy, ps: &CkksParamSet, input: &[u8]) -> Option<(FheType, usize)> {
    let n = ps.n();
    let level = params::release_level(ps);
    if input.len() < CT_HEADER {
        return None;
    }
    let magic = if level == 0 { CT_MAGIC } else { CT_MAGIC_V3 };
    if input.len() != CT_HEADER + 16 * n * (level + 1) || &input[..8] != magic {
        return None;
    }
    let w = |o: usize| u32::from_le_bytes(input[o..o + 4].try_into().unwrap());
    if w(8) != ps.id || w(12) != level as u32 || w(16) != c.scale_log2 as u32 || w(20) != 0 {
        return None;
    }
    let want = release_type(ps);
    p.allowed_output_types.iter().find(|t| **t == want).cloned().map(|t| (t, level))
}

fn output_len(c: &fhe::CkksReleasePolicy) -> usize {
    4 + 16 * c.max_values as usize
}

/// q of the flooding analysis: the number of decryptions an adversary can
/// obtain under one secret. Every copy of a lineage (the original and at most
/// `maxReplicas` replicas, which keep the source's replication limit and its
/// decryption policy unchanged, §6.3–§6.4 of the FHE proposal) starts its own
/// counter at 0, so the lineage releases at most (maxReplicas + 1) × maxDecrypts.
pub fn lineage_releases(max_decrypts: u32, max_replicas: u32) -> u64 {
    (max_replicas as u64 + 1) * max_decrypts as u64
}

/// Flood width in bits: the standard deviation of the noise added to each
/// coefficient, following Li, Micciancio, Schultz and Sorrell (CRYPTO 2022,
/// ePrint 2022/816) exactly. Definition 18 adds N_Z^n(0, σ²·t²·I_n) to the
/// decrypted ring element, and Corollary 2 sets σ = √(24·q·n)·2^(s/2) for
/// (c, s)-bit q-IND-CPA^D security. So
///
///   log2(σ·t) = s/2 + ½·log2(24·q·n) + log2 t,
///
/// with s = λ_s (`statSecurityBits`), q = `releases` (the lineage total,
/// `lineage_releases`), n the ring degree of the set, and t = B, the
/// registry's per-coefficient ∞-norm bound of the release-level error
/// (`params::noise_bound_log2`). The √n converts that ∞-norm bound into the
/// ℓ2 bound the Gaussian mechanism needs (‖e‖₂ ≤ √n·‖e‖∞), as in the proof of
/// Corollary 2.
pub fn flood_sigma_log2(c: &fhe::CkksReleasePolicy, releases: u64, ps: &CkksParamSet) -> f64 {
    c.stat_security_bits as f64 / 2.0 + (24.0 * releases as f64 * ps.n() as f64).log2() / 2.0 + params::noise_bound_log2(ps)
}

/// Widest flood (log2 σ) the token draws for a one-prime release (registry
/// IDs 2 and 0x8002, release modulus q0 ≈ 2^55–2^60), unchanged from the
/// first build.
pub const FLOOD_MAX_LOG2_ONE_PRIME: f64 = 62.0;
/// Widest flood (log2 σ) for a two-prime release (registry ID 3, q0·q1 ≈
/// 2^105, scale 2^90). Every draw is below 8.7·σ < 2^83.2, 20 bits under
/// q0·q1/2 ≈ 2^104, so a flooded coefficient keeps the size of a level-1
/// plaintext and stays far inside i128. A wider width would serve nothing: at
/// σ = 2^80 the decoded slot noise (about σ·√n·4.5 ≈ 2^90.2 at n = 2^16) is
/// already as large as the scale, so the release carries no bits.
pub const FLOOD_MAX_LOG2_TWO_PRIME: f64 = 80.0;

/// The flood width cap of a set, by the number of primes it releases over.
pub fn flood_max_log2(ps: &CkksParamSet) -> f64 {
    if params::release_level(ps) == 0 {
        FLOOD_MAX_LOG2_ONE_PRIME
    } else {
        FLOOD_MAX_LOG2_TWO_PRIME
    }
}

/// Width (log2 σ) up to which one rounded double-precision draw has full
/// integer resolution: |σ·z| < 2^(45+4) for every Box–Muller output
/// (|z| < 8.7), so the spacing of doubles stays below 1.
pub const FLOOD_SINGLE_DRAW_MAX_LOG2: f64 = 45.0;
/// Width of the fine component of a split draw (see `flood`).
pub const FLOOD_FINE_LOG2: f64 = 44.0;

/// Rounded Gaussian with standard deviation 2^sigma_log2 (Box–Muller on the
/// token DRBG), one value per coefficient, added in 128-bit arithmetic.
///
/// Up to 2^45 (registry IDs 2 and 0x8002) this is one draw, round(σ·z), as
/// first built. Above it a single double would leave the low bits of the
/// sum on a coarse grid (spacing 2^(log2 σ + 4 − 52), e.g. 2^9 at σ = 2^57.6)
/// and so reveal them; the draw is split into two independent rounded
/// Gaussians, round(σ_c·z1) + round(σ_f·z2) with σ_f = 2^44 and
/// σ_c = √(σ² − σ_f²). The sum has variance σ², and the fine component has
/// full integer resolution and is far wider than the coarse one's grid, so
/// the low bits are covered. At the two-prime cap (σ = 2^80) the coarse grid
/// is 2^(80 + 3.2 − 52) ≈ 2^31, still 13 bits below σ_f, and every draw is
/// below 2^83.2, so the sum cannot overflow i128.
fn flood(m: &mut [i128], sigma_log2: f64) -> Result<(), u32> {
    let mut k = crate::replication::random32()?;
    let mut st = super::spec::Stream::new(&k);
    k.zeroize();
    let unit = |st: &mut super::spec::Stream| ((st.u64() >> 11) as f64 + 0.5) / (1u64 << 53) as f64;
    let normal = |st: &mut super::spec::Stream| {
        let (u1, u2) = (unit(st), unit(st));
        (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
    };
    if sigma_log2 <= FLOOD_SINGLE_DRAW_MAX_LOG2 {
        let sigma = sigma_log2.exp2();
        for v in m.iter_mut() {
            *v = v.saturating_add((sigma * normal(&mut st)).round() as i128);
        }
    } else {
        let fine = FLOOD_FINE_LOG2.exp2();
        let coarse = ((2.0 * sigma_log2).exp2() - fine * fine).sqrt();
        for v in m.iter_mut() {
            let c = (coarse * normal(&mut st)).round() as i128;
            let f = (fine * normal(&mut st)).round() as i128;
            *v = v.saturating_add(c).saturating_add(f);
        }
    }
    Ok(())
}

/// Lattigo's CKKS decoding of a level-0 plaintext (centered coefficients) at
/// full slot count N/2: `polyToComplexNoCRT` then `SpecialFFTDouble`.
pub fn decode_slots(m: &[i64], scale_log2: u8) -> Vec<(f64, f64)> {
    decode_slots_wide(&m.iter().map(|&x| x as i128).collect::<Vec<_>>(), scale_log2)
}

/// `decode_slots` for 128-bit coefficients (a level-1 plaintext of registry
/// ID 3, |m| < 2^105). Each coefficient is rounded to the nearest double
/// before scaling, a relative error of at most 2^-53.
pub fn decode_slots_wide(m: &[i128], scale_log2: u8) -> Vec<(f64, f64)> {
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

/// Who may receive a release, and whether it may be flooded, for a set. A set
/// without a measured flood bound (`params::owner_release_only`, registry ID 4)
/// releases to its owner only and unflooded: flooding needs the bound B
/// (`flood_sigma_log2`) and a third-party release needs flooding. The rule is
/// explicit, and also enforced when the policy is parsed
/// (`fhe::parse_decrypt_policy`); it is checked here again for a policy that
/// predates the set's registration. Sets with a bound are never refused here.
pub fn release_gate(ps: &CkksParamSet, owner: bool, flooded: bool) -> Result<(), &'static str> {
    if params::owner_release_only(ps) {
        if !owner {
            return Err("owner-release-only parameter set: no third-party release");
        }
        if flooded {
            return Err("owner-release-only parameter set: no measured flood bound");
        }
    }
    Ok(())
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
    let (ty, level) = type_gate(p, c, ps, input).ok_or_else(|| tf::refuse(slot, "type gate"))?;
    if p.never_release.contains(&ty) {
        return Err(tf::refuse(slot, "never-release type"));
    }
    let flooded = if owner { c.flood_owner } else { c.flood_recipients };
    release_gate(ps, owner, flooded).map_err(|why| tf::refuse(slot, why))?;
    let len = ps.n() * (level + 1);
    let words = |off: usize| -> Vec<u64> { (0..len).map(|i| u64::from_le_bytes(input[off + 8 * i..off + 8 * i + 8].try_into().unwrap())).collect() };
    let (c0, c1) = (words(CT_HEADER), words(CT_HEADER + 8 * len));
    let g = Generator::new(ps, &so.seed);
    let m = g.decrypt_level(level, &c0, &c1);
    drop(g);
    let mut m = m.map_err(|_| tf::refuse(slot, "type gate"))?;
    if flooded {
        // q is the lineage total (LMSS22 Corollary 2): this seed's replication
        // limit, which every replica keeps (package import refuses a CKKS
        // replica under a different limit), and the shared decryption policy.
        // The engine-written binding names the policy (the public attribute
        // alone is not trusted).
        let max_replicas = so
            .attrs
            .get(&CKA_PRIV_REPL_BINDING)
            .and_then(|id| records::find_policy(slot, id))
            .and_then(|der| records::parse_policy(&der).ok())
            .map(|rp| rp.max_replicas);
        let Some(max_replicas) = max_replicas else {
            m.zeroize();
            return Err(tf::refuse(slot, "no flooding width: replication policy not enrolled"));
        };
        let sigma_log2 = flood_sigma_log2(c, lineage_releases(p.max_decrypts, max_replicas), ps);
        if !sigma_log2.is_finite() || sigma_log2 > flood_max_log2(ps) {
            m.zeroize();
            return Err(tf::refuse(slot, "no flooding width for this parameter set"));
        }
        if let Err(e) = flood(&mut m, sigma_log2) {
            m.zeroize();
            return Err(e);
        }
    }
    let mut slots = decode_slots_wide(&m, c.scale_log2);
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
        // The 128-bit path agrees, and decodes a scale-2^90 constant.
        let m: Vec<i64> = (0..n as i64).map(|i| (i * 7919 - 4000) << 20).collect();
        assert_eq!(decode_slots(&m, 40), decode_slots_wide(&m.iter().map(|&x| x as i128).collect::<Vec<_>>(), 40));
        let mut w = vec![0i128; n];
        w[0] = 3 << 90;
        assert!(decode_slots_wide(&w, 90).iter().all(|&(re, im)| (re - 3.0).abs() < 1e-12 && im.abs() < 1e-12));
    }

    /// The split draw above 2^45 (E13): standard deviation within 2 % of σ,
    /// and the low bits are not on a grid (a single double at these widths
    /// leaves the low 9 to 31 bits of every draw at zero). Checked at the
    /// old registry ID 3 width (2^57.6), the LMSS22 Corollary 2 width
    /// (2^69.1, `flood_formula_lmss22_corollary2`) and just under the
    /// two-prime cap (2^79.9), where draws reach 2^83 and must neither
    /// overflow nor lose their low bits.
    #[test]
    fn wide_flood_width_and_low_bits() {
        let n = 1 << 14;
        for sigma_log2 in [15.0 + (10_000f64).log2() / 2.0 + 36.0, 69.0973015, FLOOD_MAX_LOG2_TWO_PRIME - 0.1] {
            let mut m = vec![0i128; n];
            flood(&mut m, sigma_log2).unwrap();
            let var = m.iter().map(|&v| (v as f64) * (v as f64)).sum::<f64>() / n as f64;
            let ratio = var.sqrt() / sigma_log2.exp2();
            assert!((0.98..1.02).contains(&ratio), "σ = 2^{sigma_log2}: std/σ = {ratio}");
            for bit in [0, 8, 20] {
                let set = m.iter().filter(|&&v| (v >> bit) & 1 == 1).count() as f64 / n as f64;
                assert!((0.45..0.55).contains(&set), "σ = 2^{sigma_log2}: bit {bit} set in {set}");
            }
            assert!(m.iter().all(|&v| v.unsigned_abs() < 1u128 << 84), "σ = 2^{sigma_log2}: a draw beyond 2^84");
        }
        // Below 2^45: one draw, as first built (still full resolution).
        let mut m = vec![0i128; n];
        flood(&mut m, 31.6).unwrap();
        let var = m.iter().map(|&v| (v as f64) * (v as f64)).sum::<f64>() / n as f64;
        assert!((0.98..1.02).contains(&(var.sqrt() / 31.6f64.exp2())));
    }
    /// The explicit owner-release-only rule (registry ID 4: no measured flood
    /// bound). Sets with a bound are never refused by the gate.
    #[test]
    fn release_gate_refuses_third_party_and_flooded_for_unbounded_sets() {
        let ps4 = params::find(4).unwrap();
        assert_eq!(release_gate(ps4, true, false), Ok(()), "owner, unflooded");
        assert!(release_gate(ps4, true, true).is_err(), "owner, flooded");
        assert!(release_gate(ps4, false, true).is_err(), "third party, flooded");
        assert!(release_gate(ps4, false, false).is_err(), "third party, unflooded");
        for id in [2u32, 3, 0x8002] {
            let ps = params::find(id).unwrap();
            for (owner, flooded) in [(true, false), (true, true), (false, true), (false, false)] {
                assert_eq!(release_gate(ps, owner, flooded), Ok(()), "set {id}, owner {owner}, flooded {flooded}");
            }
        }
    }

    /// LMSS22 Corollary 2 pinned by hand. Policy as in the gate F custodian:
    /// λ_s = 30, maxDecrypts = 10,000, maxReplicas = 4, so
    /// q = (4 + 1) × 10,000 = 50,000.
    ///   24·q = 1,200,000; log2 1.2e6 = log2 1.2 + 6·log2 10
    ///        = 0.2630344 + 19.9315686 = 20.1946030
    ///   n = 2^16 (IDs 2, 3): ½·log2(24·q·n) = ½·(20.1946030 + 16) = 18.0973015
    ///   n = 2^10 (0x8002):   ½·log2(24·q·n) = ½·(20.1946030 + 10) = 15.0973015
    ///   ID 3 (log2 B = 36): 15 + 18.0973015 + 36 = 69.0973015
    ///   ID 2 (log2 B = 10): 15 + 18.0973015 + 10 = 43.0973015
    ///   0x8002 (log2 B = 12): 15 + 15.0973015 + 12 = 42.0973015
    /// The width before this change, λ_s/2 + ½·log2(maxDecrypts) + log2 B,
    /// was 57.6438562 for ID 3: ½·log2(24·n) = 10.2924813 narrower (the √24
    /// and √n of Corollary 2), plus ½·log2 5 = 1.1609640 for the replicas.
    #[test]
    fn flood_formula_lmss22_corollary2() {
        let c = fhe::CkksReleasePolicy { max_values: 1, precision_bits: 30, value_bound_log2: 10, scale_log2: 90, flood_recipients: true, flood_owner: true, stat_security_bits: 30 };
        let q = lineage_releases(10_000, 4);
        assert_eq!(q, 50_000);
        let at = |id: u32| flood_sigma_log2(&c, q, params::find(id).unwrap());
        for (id, want, cap) in [(3u32, 69.0973015, 80.0), (2, 43.0973015, 62.0), (0x8002, 42.0973015, 62.0)] {
            let got = at(id);
            assert!((got - want).abs() < 1e-6, "ID {id}: log2 σ = {got}, hand value {want}");
            assert_eq!(flood_max_log2(params::find(id).unwrap()), cap);
            assert!(got < cap, "ID {id} within its cap");
        }
        let old = 15.0 + (10_000f64).log2() / 2.0 + 36.0;
        assert!((old - 57.6438562).abs() < 1e-6);
        assert!((at(3) - old - (10.2924813 + 1.1609640)).abs() < 1e-6);
        // One copy, one decryption: q = 1 gives s/2 + ½·log2(24·n) + log2 B.
        assert!((flood_sigma_log2(&c, lineage_releases(1, 0), params::find(3).unwrap()) - (15.0 + 10.2924813 + 36.0)).abs() < 1e-6);
    }
}
