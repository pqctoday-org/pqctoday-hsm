//! Native CPU path for ML-DSA (FIPS 204) and ML-KEM (FIPS 203) over AWS-LC.
//!
//! ## Why
//!
//! The engine's own ML-DSA (`fips204-patched`) and ML-KEM (`ml-kem-patched`)
//! are portable Rust. AWS-LC, already linked into every native build through
//! `aws-lc-rs` (see `crypto::awslc`), carries `mldsa-native` and
//! `mlkem-native` with hand-written AArch64 NEON back ends for the NTT, the
//! inverse NTT, the pointwise products, rejection sampling and the norm /
//! decompose / unpack helpers. On the KV260 (Cortex-A53) the NTT alone is 43 %
//! of an ML-DSA-65 signature (pqctoday-cacp
//! `docs/kv260-rust-pkcs11-baselines-09132026.md`).
//!
//! aws-lc-sys 0.44.0 builds both back ends for `aarch64` Linux and gates each
//! native routine at run time on `CRYPTO_is_NEON_capable()` (AWS-LC's own
//! `mldsa_aarch64_meta.h` / `mlkem_aarch64_meta.h`), falling back to the C
//! reference code when NEON is absent (or masked with `OPENSSL_armcap=0`).
//! Plain Armv8.0-A cores such as the A53 and A55 have NEON, so they take the
//! assembly. They lack the Armv8.2 SHA3 instructions, so AWS-LC's Keccak runs
//! its scalar AArch64 assembly there; the container host used for development
//! (Apple M5) has SHA3 and is therefore NOT representative of the boards.
//!
//! ## What is routed here (coverage matrix)
//!
//! Only operations AWS-LC's PUBLIC API (the `aws-lc-sys` bindings, i.e. the
//! `include/openssl` headers) can perform with the exact FIPS semantics the
//! engine already has. Everything else keeps the pure-Rust path:
//!
//! | operation | here | reason when not |
//! |---|---|---|
//! | ML-DSA KeyGen from ξ (all keygens: the engine always keeps ξ) | yes | |
//! | ML-DSA pure sign, hedged, any context ≤ 255 B | yes | |
//! | ML-DSA pure sign, deterministic (`CKH_DETERMINISTIC_REQUIRED`) | no | no public rnd control; `ml_dsa_*_sign_internal` is not in the headers |
//! | ML-DSA sign with a caller-supplied rnd (ACVP / KMIP `<Random>`) | no | same |
//! | ML-DSA pure verify, any context ≤ 255 B | yes | |
//! | HashML-DSA (10 `CKM_HASH_ML_DSA_*` + generic `CKM_HASH_ML_DSA`) sign/verify | no | AWS-LC has no pre-hash API |
//! | ML-DSA internal interface (`Sign_internal` / `Verify_internal`) | no | not in the headers |
//! | external µ sign, hedged | yes | `EVP_PKEY_sign` on a PQDSA key |
//! | external µ sign, deterministic / explicit rnd | no | no rnd control |
//! | external µ verify | yes | `EVP_PKEY_verify` on a PQDSA key |
//! | ML-KEM KeyGen from (d ‖ z) | with `awslc-pq-mlkem-seeded` | `EVP_PKEY_keygen_deterministic` (all-bindings only) |
//! | ML-KEM Encaps with the engine-drawn m | with `awslc-pq-mlkem-seeded` | `EVP_PKEY_encapsulate_deterministic` (all-bindings only) |
//! | ML-KEM Decaps (implicit rejection) | yes | `EVP_PKEY_decapsulate` |
//!
//! Every function returns `Option<_>` with the same rule as `crypto::awslc`:
//! `None` means "not handled here — the caller MUST run its existing
//! pure-Rust code", which stays the conformance reference. `None` is returned
//! for the uncovered variants above, for any input whose length is not the
//! exact FIPS length (so the pure-Rust path keeps producing its own error
//! code), and whenever AWS-LC rejects an input. AWS-LC checks MORE than the
//! Rust crates do (ML-DSA: `sk` must be self-consistent, `t0` and `tr`
//! recomputed; ML-KEM: the FIPS 203 §7.2 / §7.3 encapsulation-key modulus
//! check and decapsulation-key hash check), so an input AWS-LC rejects goes
//! to the Rust crate and is handled exactly as before this module existed.
//!
//! Signatures are hedged in both implementations, so a routed signature is
//! not byte-equal to a fips204 one; it is a valid FIPS 204 signature that
//! fips204 verifies (and vice versa) — the tests prove both directions.
//! Every deterministic output (keygen, encapsulation for a given m,
//! decapsulation) IS byte-identical and the tests prove that too.
//!
//! ## Accelerator precedence
//!
//! On the KV260 `mldsa` FPGA profile, `hw_accel` installs a fips204 ML-DSA-65
//! hook (whole-signature signer, or the older matrix/vector engine). It then
//! calls [`defer_mldsa65_to_accelerator`], and every ML-DSA-65 signature —
//! and, for the matrix/vector hook, ML-DSA-65 key generation — stays on
//! fips204 so the FPGA keeps first claim, with fips204's own CPU loop as its
//! fallback. Verification, ML-DSA-44/87, ML-KEM, and every board without an
//! ML-DSA accelerator (the i.MX 95) use this module.
//!
//! ## Switches
//!
//! * Cargo feature `awslc-pq` (default): compiles this module on native
//!   targets. On `wasm32` nothing here exists: the module and `aws-lc-sys`
//!   are both gated on `not(target_arch = "wasm32")`.
//! * `PQC_AWSLC_PQ_DISABLE=1` in the environment of the process: every call
//!   returns `None`, i.e. the engine runs fips204 / ml-kem exactly as before.
//!   Read once per process.

use std::collections::HashMap;
use std::os::raw::c_int;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use aws_lc_sys as sys;
use sha2::{Digest, Sha256};

use crate::constants::*;

// ── switches ───────────────────────────────────────────────────────────────

/// Name of the runtime escape hatch.
pub const DISABLE_ENV: &str = "PQC_AWSLC_PQ_DISABLE";

/// `true` when [`DISABLE_ENV`] asks for the pure-Rust path. Kept separate
/// from the cached read so the parser itself is testable.
pub fn disabled_by(value: Option<&str>) -> bool {
    matches!(
        value.map(str::trim),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

/// Whether this module handles anything in this process.
pub fn enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| !disabled_by(std::env::var(DISABLE_ENV).ok().as_deref()))
}

static MLDSA65_ACCELERATED: AtomicBool = AtomicBool::new(false);
static MLDSA65_KEYGEN_ACCELERATED: AtomicBool = AtomicBool::new(false);

/// Called by `hw_accel` when it installs a fips204 ML-DSA-65 hardware hook.
/// `keygen` is true for the matrix/vector hook, which fips204 also uses in
/// key generation. From then on ML-DSA-65 signing (and, with `keygen`, key
/// generation) stays on fips204 so the accelerator keeps precedence.
pub fn defer_mldsa65_to_accelerator(keygen: bool) {
    MLDSA65_ACCELERATED.store(true, Ordering::SeqCst);
    if keygen {
        MLDSA65_KEYGEN_ACCELERATED.store(true, Ordering::SeqCst);
    }
}

/// The routing rule, separated from the process-wide switches so it can be
/// tested without flipping them: handled here iff the path is on and this is
/// not ML-DSA-65 while an ML-DSA-65 accelerator hook owns the operation.
fn gate(ps: u32, on: bool, mldsa65_accelerated: bool) -> bool {
    on && !(is_mldsa65(ps) && mldsa65_accelerated)
}

fn mldsa_sign_here(ps: u32) -> bool {
    gate(ps, enabled(), MLDSA65_ACCELERATED.load(Ordering::SeqCst))
}

fn mldsa_keygen_here(ps: u32) -> bool {
    gate(
        ps,
        enabled(),
        MLDSA65_KEYGEN_ACCELERATED.load(Ordering::SeqCst),
    )
}

/// `handlers` treats a key without `CKA_PARAMETER_SET` (0) as ML-DSA-65.
fn is_mldsa65(ps: u32) -> bool {
    ps == CKP_ML_DSA_65 || ps == 0
}

// ── parameter sets ─────────────────────────────────────────────────────────

struct MldsaParams {
    nid: c_int,
    pk_len: usize,
    sk_len: usize,
    sig_len: usize,
}

fn mldsa_params(ps: u32) -> Option<MldsaParams> {
    // FIPS 204 Table 2.
    match ps {
        CKP_ML_DSA_44 => Some(MldsaParams {
            nid: sys::NID_MLDSA44,
            pk_len: 1312,
            sk_len: 2560,
            sig_len: 2420,
        }),
        CKP_ML_DSA_65 | 0 => Some(MldsaParams {
            nid: sys::NID_MLDSA65,
            pk_len: 1952,
            sk_len: 4032,
            sig_len: 3309,
        }),
        CKP_ML_DSA_87 => Some(MldsaParams {
            nid: sys::NID_MLDSA87,
            pk_len: 2592,
            sk_len: 4896,
            sig_len: 4627,
        }),
        _ => None,
    }
}

struct MlkemParams {
    nid: c_int,
    ek_len: usize,
    dk_len: usize,
    ct_len: usize,
}

fn mlkem_params(ps: u32) -> Option<MlkemParams> {
    // FIPS 203 Table 3.
    match ps {
        CKP_ML_KEM_512 => Some(MlkemParams {
            nid: sys::NID_MLKEM512,
            ek_len: 800,
            dk_len: 1632,
            ct_len: 768,
        }),
        CKP_ML_KEM_768 => Some(MlkemParams {
            nid: sys::NID_MLKEM768,
            ek_len: 1184,
            dk_len: 2400,
            ct_len: 1088,
        }),
        CKP_ML_KEM_1024 => Some(MlkemParams {
            nid: sys::NID_MLKEM1024,
            ek_len: 1568,
            dk_len: 3168,
            ct_len: 1568,
        }),
        _ => None,
    }
}

const ML_KEM_SS_LEN: usize = 32;
const ML_DSA_MU_LEN: usize = 64;
const ML_DSA_MAX_CTX: usize = 255;

// ── owned AWS-LC objects ───────────────────────────────────────────────────

/// An owned `EVP_PKEY`. AWS-LC `EVP_PKEY`s are reference counted with
/// atomics and only read by signing / verification, which is how `aws-lc-rs`
/// shares them across threads too.
struct Pkey(*mut sys::EVP_PKEY);
unsafe impl Send for Pkey {}
unsafe impl Sync for Pkey {}
impl Drop for Pkey {
    fn drop(&mut self) {
        unsafe { sys::EVP_PKEY_free(self.0) }
    }
}
impl Pkey {
    fn new(p: *mut sys::EVP_PKEY) -> Option<Self> {
        if p.is_null() {
            clear_errors();
            None
        } else {
            Some(Pkey(p))
        }
    }

    fn raw(&self, private: bool, expected: usize) -> Option<Vec<u8>> {
        let mut out = vec![0u8; expected];
        let mut len = expected;
        let ok = unsafe {
            if private {
                sys::EVP_PKEY_get_raw_private_key(self.0, out.as_mut_ptr(), &mut len)
            } else {
                sys::EVP_PKEY_get_raw_public_key(self.0, out.as_mut_ptr(), &mut len)
            }
        };
        if ok != 1 || len != expected {
            clear_errors();
            return None;
        }
        Some(out)
    }
}

struct PkeyCtx(*mut sys::EVP_PKEY_CTX);
impl Drop for PkeyCtx {
    fn drop(&mut self) {
        unsafe { sys::EVP_PKEY_CTX_free(self.0) }
    }
}
impl PkeyCtx {
    fn for_key(key: &Pkey) -> Option<Self> {
        let p = unsafe { sys::EVP_PKEY_CTX_new(key.0, ptr::null_mut()) };
        if p.is_null() {
            clear_errors();
            None
        } else {
            Some(PkeyCtx(p))
        }
    }
}

struct MdCtx(*mut sys::EVP_MD_CTX);
impl Drop for MdCtx {
    fn drop(&mut self) {
        unsafe { sys::EVP_MD_CTX_free(self.0) }
    }
}
impl MdCtx {
    fn new() -> Option<Self> {
        let p = unsafe { sys::EVP_MD_CTX_new() };
        if p.is_null() { None } else { Some(MdCtx(p)) }
    }
}

/// AWS-LC reports failures on a thread-local error queue; drain it so a
/// rejected input (which we answer with `None`) does not accumulate there.
fn clear_errors() {
    unsafe { sys::ERR_clear_error() }
}

// ── ML-DSA private-key cache ───────────────────────────────────────────────
//
// Importing an expanded ML-DSA private key is not a copy in AWS-LC: it
// recomputes t = A·s1 + s2 and H(pk) to check the key (pk_from_sk), which
// costs about as much as a key generation. The engine hands handlers key
// BYTES, so parsed keys are cached by a hash of those bytes — the same design
// and argument as `crypto::awslc_keycache` (a hit requires already holding
// the key bytes; FIFO bound; emptied on every PKCS#11 lifecycle event that
// ends a key's accessibility, through `awslc_keycache::clear`).

/// Resident parsed ML-DSA keys. ML-DSA-87's `EVP_PKEY` is ~12 kB.
pub const MAX_KEYS: usize = 64;

struct KeyCache {
    map: HashMap<[u8; 32], Arc<Pkey>>,
    order: Vec<[u8; 32]>,
}

fn key_cache() -> std::sync::MutexGuard<'static, KeyCache> {
    static C: OnceLock<Mutex<KeyCache>> = OnceLock::new();
    C.get_or_init(|| {
        Mutex::new(KeyCache {
            map: HashMap::new(),
            order: Vec::new(),
        })
    })
    .lock()
    .unwrap_or_else(|e| e.into_inner())
}

static KEY_HITS: AtomicU64 = AtomicU64::new(0);
static KEY_MISSES: AtomicU64 = AtomicU64::new(0);

/// `(hits, misses)` of the ML-DSA key cache since process start (tests).
pub fn key_cache_stats() -> (u64, u64) {
    (
        KEY_HITS.load(Ordering::Relaxed),
        KEY_MISSES.load(Ordering::Relaxed),
    )
}

/// Drop every parsed ML-DSA private key. Idempotent.
pub fn clear_key_cache() {
    let mut c = key_cache();
    c.map.clear();
    c.order.clear();
}

fn mldsa_private_key(p: &MldsaParams, sk: &[u8]) -> Option<Arc<Pkey>> {
    let mut h = Sha256::new();
    h.update(b"pqctoday/awslc-pq/mldsa-sk/v1");
    h.update((p.nid as u32).to_le_bytes());
    h.update(sk);
    let id: [u8; 32] = h.finalize().into();
    if let Some(hit) = key_cache().map.get(&id).cloned() {
        KEY_HITS.fetch_add(1, Ordering::Relaxed);
        return Some(hit);
    }
    KEY_MISSES.fetch_add(1, Ordering::Relaxed);
    // Built outside the lock (milliseconds on an A53); a racing thread may
    // build the same key twice, which costs one import and is harmless.
    let key = Arc::new(Pkey::new(unsafe {
        sys::EVP_PKEY_pqdsa_new_raw_private_key(p.nid, sk.as_ptr(), sk.len())
    })?);
    let mut c = key_cache();
    if !c.map.contains_key(&id) {
        while c.order.len() >= MAX_KEYS {
            let oldest = c.order.remove(0);
            c.map.remove(&oldest);
        }
        c.order.push(id);
        c.map.insert(id, Arc::clone(&key));
    }
    Some(key)
}

// ── ML-DSA ─────────────────────────────────────────────────────────────────

/// FIPS 204 Algorithm 6 `ML-DSA.KeyGen_internal(ξ)`: `(pk, sk)` in the FIPS
/// 204 encodings, byte-identical to fips204 `keygen_from_seed`.
pub fn mldsa_keygen_from_seed(ps: u32, xi: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let p = mldsa_params(ps)?;
    if !mldsa_keygen_here(ps) || xi.len() != 32 {
        return None;
    }
    let key = Pkey::new(unsafe {
        sys::EVP_PKEY_pqdsa_new_raw_private_key(p.nid, xi.as_ptr(), xi.len())
    })?;
    Some((key.raw(false, p.pk_len)?, key.raw(true, p.sk_len)?))
}

/// Pure ML-DSA, hedged (FIPS 204 Algorithm 2 with fresh rnd), context string
/// `ctx`. `None` for any input the pure-Rust path must handle.
pub fn mldsa_sign(ps: u32, sk: &[u8], msg: &[u8], ctx: &[u8]) -> Option<Vec<u8>> {
    let p = mldsa_params(ps)?;
    if !mldsa_sign_here(ps) || sk.len() != p.sk_len || ctx.len() > ML_DSA_MAX_CTX {
        return None;
    }
    let key = mldsa_private_key(&p, sk)?;
    let md = MdCtx::new()?;
    let mut sig = vec![0u8; p.sig_len];
    let mut sig_len = sig.len();
    let ok = unsafe {
        let mut pctx: *mut sys::EVP_PKEY_CTX = ptr::null_mut();
        sys::EVP_DigestSignInit(md.0, &mut pctx, ptr::null(), ptr::null_mut(), key.0) == 1
            && (ctx.is_empty()
                || sys::EVP_PKEY_CTX_set1_signature_context_string(pctx, ctx.as_ptr(), ctx.len())
                    == 1)
            && sys::EVP_DigestSign(
                md.0,
                sig.as_mut_ptr(),
                &mut sig_len,
                msg.as_ptr(),
                msg.len(),
            ) == 1
    };
    if !ok || sig_len != p.sig_len {
        clear_errors();
        return None;
    }
    Some(sig)
}

/// Pure ML-DSA verification with context `ctx`. `Some(true/false)` is the
/// verdict; `None` hands the call to fips204 (wrong lengths, unknown set,
/// AWS-LC refused the public key, or the path is disabled).
pub fn mldsa_verify(ps: u32, pk: &[u8], msg: &[u8], sig: &[u8], ctx: &[u8]) -> Option<bool> {
    let p = mldsa_params(ps)?;
    if !enabled() || pk.len() != p.pk_len || sig.len() != p.sig_len || ctx.len() > ML_DSA_MAX_CTX {
        return None;
    }
    let key =
        Pkey::new(unsafe { sys::EVP_PKEY_pqdsa_new_raw_public_key(p.nid, pk.as_ptr(), pk.len()) })?;
    let md = MdCtx::new()?;
    let mut pctx: *mut sys::EVP_PKEY_CTX = ptr::null_mut();
    let init = unsafe {
        sys::EVP_DigestVerifyInit(md.0, &mut pctx, ptr::null(), ptr::null_mut(), key.0) == 1
            && (ctx.is_empty()
                || sys::EVP_PKEY_CTX_set1_signature_context_string(pctx, ctx.as_ptr(), ctx.len())
                    == 1)
    };
    if !init {
        clear_errors();
        return None;
    }
    let ok =
        unsafe { sys::EVP_DigestVerify(md.0, sig.as_ptr(), sig.len(), msg.as_ptr(), msg.len()) }
            == 1;
    if !ok {
        clear_errors();
    }
    Some(ok)
}

/// External-µ ML-DSA signing, hedged: `mu` is the 64-byte message
/// representative µ = H(tr ‖ M′) (FIPS 204 Algorithm 7 line 6).
pub fn mldsa_sign_mu(ps: u32, sk: &[u8], mu: &[u8]) -> Option<Vec<u8>> {
    let p = mldsa_params(ps)?;
    if !mldsa_sign_here(ps) || sk.len() != p.sk_len || mu.len() != ML_DSA_MU_LEN {
        return None;
    }
    let key = mldsa_private_key(&p, sk)?;
    let pctx = PkeyCtx::for_key(&key)?;
    let mut sig = vec![0u8; p.sig_len];
    let mut sig_len = sig.len();
    let ok = unsafe {
        sys::EVP_PKEY_sign_init(pctx.0) == 1
            && sys::EVP_PKEY_sign(
                pctx.0,
                sig.as_mut_ptr(),
                &mut sig_len,
                mu.as_ptr(),
                mu.len(),
            ) == 1
    };
    if !ok || sig_len != p.sig_len {
        clear_errors();
        return None;
    }
    Some(sig)
}

/// External-µ ML-DSA verification (FIPS 204 Algorithm 8 from line 7).
pub fn mldsa_verify_mu(ps: u32, pk: &[u8], mu: &[u8], sig: &[u8]) -> Option<bool> {
    let p = mldsa_params(ps)?;
    if !enabled() || pk.len() != p.pk_len || sig.len() != p.sig_len || mu.len() != ML_DSA_MU_LEN {
        return None;
    }
    let key =
        Pkey::new(unsafe { sys::EVP_PKEY_pqdsa_new_raw_public_key(p.nid, pk.as_ptr(), pk.len()) })?;
    let pctx = PkeyCtx::for_key(&key)?;
    if unsafe { sys::EVP_PKEY_verify_init(pctx.0) } != 1 {
        clear_errors();
        return None;
    }
    let ok =
        unsafe { sys::EVP_PKEY_verify(pctx.0, sig.as_ptr(), sig.len(), mu.as_ptr(), mu.len()) }
            == 1;
    if !ok {
        clear_errors();
    }
    Some(ok)
}

// ── ML-KEM ─────────────────────────────────────────────────────────────────

/// FIPS 203 Algorithm 16 `ML-KEM.KeyGen_internal(d, z)` with `seed = d ‖ z`:
/// `(ek, dk)`, byte-identical to ml-kem `generate_deterministic(d, z)`.
#[cfg(feature = "awslc-pq-mlkem-seeded")]
pub fn mlkem_keygen_from_seed(ps: u32, seed: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let p = mlkem_params(ps)?;
    if !enabled() || seed.len() != 64 {
        return None;
    }
    let ctx = unsafe { sys::EVP_PKEY_CTX_new_id(sys::EVP_PKEY_KEM, ptr::null_mut()) };
    if ctx.is_null() {
        clear_errors();
        return None;
    }
    let ctx = PkeyCtx(ctx);
    let mut out: *mut sys::EVP_PKEY = ptr::null_mut();
    let mut seed_len = seed.len();
    let ok = unsafe {
        sys::EVP_PKEY_CTX_kem_set_params(ctx.0, p.nid) == 1
            && sys::EVP_PKEY_keygen_init(ctx.0) == 1
            && sys::EVP_PKEY_keygen_deterministic(ctx.0, &mut out, seed.as_ptr(), &mut seed_len)
                == 1
    };
    let key = Pkey::new(out);
    if !ok {
        clear_errors();
        return None;
    }
    let key = key?;
    Some((key.raw(false, p.ek_len)?, key.raw(true, p.dk_len)?))
}

/// FIPS 203 Algorithm 17 `ML-KEM.Encaps_internal(ek, m)`: `(c, K)`. The
/// caller draws `m` (32 bytes) from its own RNG exactly as ml-kem's
/// `encapsulate(rng)` would, so both paths consume the RNG identically.
/// `None` also when AWS-LC's FIPS 203 §7.2 modulus check rejects `ek`.
#[cfg(feature = "awslc-pq-mlkem-seeded")]
pub fn mlkem_encaps(ps: u32, ek: &[u8], m: &[u8; 32]) -> Option<(Vec<u8>, Vec<u8>)> {
    let p = mlkem_params(ps)?;
    if !enabled() || ek.len() != p.ek_len {
        return None;
    }
    let key =
        Pkey::new(unsafe { sys::EVP_PKEY_kem_new_raw_public_key(p.nid, ek.as_ptr(), ek.len()) })?;
    let pctx = PkeyCtx::for_key(&key)?;
    let mut ct = vec![0u8; p.ct_len];
    let mut ss = vec![0u8; ML_KEM_SS_LEN];
    let (mut ct_len, mut ss_len, mut m_len) = (ct.len(), ss.len(), m.len());
    let ok = unsafe {
        sys::EVP_PKEY_encapsulate_deterministic(
            pctx.0,
            ct.as_mut_ptr(),
            &mut ct_len,
            ss.as_mut_ptr(),
            &mut ss_len,
            m.as_ptr(),
            &mut m_len,
        ) == 1
    };
    if !ok || ct_len != p.ct_len || ss_len != ML_KEM_SS_LEN {
        clear_errors();
        return None;
    }
    Some((ct, ss))
}

/// Without `awslc-pq-mlkem-seeded` the universal aws-lc-sys bindings lack the
/// deterministic KeyGen / Encaps entry points, so both stay on ml-kem.
#[cfg(not(feature = "awslc-pq-mlkem-seeded"))]
pub fn mlkem_keygen_from_seed(_ps: u32, _seed: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    None
}

/// See [`mlkem_keygen_from_seed`]: ml-kem handles Encaps without the opt-in feature.
#[cfg(not(feature = "awslc-pq-mlkem-seeded"))]
pub fn mlkem_encaps(_ps: u32, _ek: &[u8], _m: &[u8; 32]) -> Option<(Vec<u8>, Vec<u8>)> {
    None
}

/// FIPS 203 Algorithm 18 `ML-KEM.Decaps_internal(dk, c)`, including implicit
/// rejection (a mismatching re-encryption yields K̄ = J(z ‖ c), not an error).
/// `None` when AWS-LC's §7.3 hash check rejects `dk`.
pub fn mlkem_decaps(ps: u32, dk: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    let p = mlkem_params(ps)?;
    if !enabled() || dk.len() != p.dk_len || ct.len() != p.ct_len {
        return None;
    }
    let key =
        Pkey::new(unsafe { sys::EVP_PKEY_kem_new_raw_secret_key(p.nid, dk.as_ptr(), dk.len()) })?;
    let pctx = PkeyCtx::for_key(&key)?;
    let mut ss = vec![0u8; ML_KEM_SS_LEN];
    let mut ss_len = ss.len();
    let ok = unsafe {
        sys::EVP_PKEY_decapsulate(pctx.0, ss.as_mut_ptr(), &mut ss_len, ct.as_ptr(), ct.len())
    } == 1;
    if !ok || ss_len != ML_KEM_SS_LEN {
        clear_errors();
        return None;
    }
    Some(ss)
}

#[cfg(test)]
mod tests {
    //! Correctness evidence for the routing. Byte-identity where the output
    //! is deterministic, cross-verification both ways where it is hedged, the
    //! NIST ACVP files that are in the repo, and the fallback for inputs
    //! AWS-LC refuses. Each test compares against fips204 / ml-kem called
    //! DIRECTLY, never through the routed handlers, so a routing bug cannot
    //! compare a path with itself.
    use super::*;
    use crate::crypto::handlers;
    use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
    use sha3::digest::{ExtendableOutput, Update, XofReader};

    macro_rules! per_set {
        ($ps:expr, $m:ident => $body:expr) => {
            match $ps {
                CKP_ML_DSA_44 => {
                    use fips204::ml_dsa_44 as $m;
                    $body
                }
                CKP_ML_DSA_65 => {
                    use fips204::ml_dsa_65 as $m;
                    $body
                }
                CKP_ML_DSA_87 => {
                    use fips204::ml_dsa_87 as $m;
                    $body
                }
                other => panic!("not an ML-DSA set: {other}"),
            }
        };
    }

    const SETS: [u32; 3] = [CKP_ML_DSA_44, CKP_ML_DSA_65, CKP_ML_DSA_87];

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn json(rel: &str) -> serde_json::Value {
        let path = format!("{}/{rel}", env!("CARGO_MANIFEST_DIR"));
        serde_json::from_str(&std::fs::read_to_string(&path).expect(&path)).unwrap()
    }

    fn ps_of(name: &str) -> u32 {
        match name {
            "ML-DSA-44" => CKP_ML_DSA_44,
            "ML-DSA-65" => CKP_ML_DSA_65,
            "ML-DSA-87" => CKP_ML_DSA_87,
            "ML-KEM-512" => CKP_ML_KEM_512,
            "ML-KEM-768" => CKP_ML_KEM_768,
            "ML-KEM-1024" => CKP_ML_KEM_1024,
            other => panic!("{other}"),
        }
    }

    fn fips_keygen(ps: u32, xi: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
        per_set!(ps, m => {
            let (pk, sk) = m::KG::keygen_from_seed(xi);
            (pk.into_bytes().to_vec(), sk.into_bytes().to_vec())
        })
    }

    fn fips_verify(ps: u32, pk: &[u8], msg: &[u8], sig: &[u8], ctx: &[u8]) -> bool {
        per_set!(ps, m => {
            let pk = m::PublicKey::try_from_bytes(pk.try_into().unwrap()).unwrap();
            match sig.try_into() {
                Ok(sig) => pk.verify(msg, &sig, ctx),
                Err(_) => false,
            }
        })
    }

    fn fips_sign_rnd(ps: u32, sk: &[u8], msg: &[u8], ctx: &[u8], rnd: [u8; 32]) -> Vec<u8> {
        per_set!(ps, m => {
            let sk = m::PrivateKey::try_from_bytes(sk.try_into().unwrap()).unwrap();
            sk.try_sign_with_rng(&mut handlers::FixedRng::new(&rnd), msg, ctx).unwrap().to_vec()
        })
    }

    #[allow(deprecated)]
    fn fips_verify_mu(ps: u32, pk: &[u8], mu: &[u8; 64], sig: &[u8]) -> bool {
        per_set!(ps, m => {
            let pk = m::PublicKey::try_from_bytes(pk.try_into().unwrap()).unwrap();
            m::_internal_verify_external_mu(&pk, mu, sig.try_into().unwrap())
        })
    }

    #[allow(deprecated)]
    fn fips_sign_mu(ps: u32, sk: &[u8], mu: &[u8; 64], rnd: [u8; 32]) -> Vec<u8> {
        per_set!(ps, m => {
            let sk = m::PrivateKey::try_from_bytes(sk.try_into().unwrap()).unwrap();
            m::_internal_sign_external_mu(&sk, mu, rnd).unwrap().to_vec()
        })
    }

    fn shake256(parts: &[&[u8]], out: &mut [u8]) {
        let mut h = sha3::Shake256::default();
        for p in parts {
            h.update(p);
        }
        h.finalize_xof().read(out);
    }

    /// µ = H(H(pk, 64) ‖ M′, 64) — FIPS 204 Algorithm 7 lines 6-7.
    fn mu_of(pk: &[u8], m_prime: &[&[u8]]) -> [u8; 64] {
        let mut tr = [0u8; 64];
        shake256(&[pk], &mut tr);
        let mut parts: Vec<&[u8]> = vec![&tr];
        parts.extend_from_slice(m_prime);
        let mut mu = [0u8; 64];
        shake256(&parts, &mut mu);
        mu
    }

    /// These tests call the AWS-LC functions themselves, which answer `None`
    /// under `PQC_AWSLC_PQ_DISABLE=1`; the gate also runs the suite that way.
    fn active() -> bool {
        if !enabled() {
            eprintln!("{DISABLE_ENV} set: AWS-LC path off, test skipped");
        }
        enabled()
    }

    fn key(ps: u32, i: u8) -> (Vec<u8>, Vec<u8>) {
        fips_keygen(ps, &[i.wrapping_mul(37).wrapping_add(ps as u8); 32])
    }

    #[test]
    fn escape_hatch_values() {
        for on in ["1", "true", "yes", "on", " 1 "] {
            assert!(disabled_by(Some(on)), "{on:?}");
        }
        for off in ["0", "", "false", "no"] {
            assert!(!disabled_by(Some(off)), "{off:?}");
        }
        assert!(!disabled_by(None));
    }

    #[test]
    fn accelerator_gate_keeps_mldsa65_on_fips204() {
        for accelerated in [false, true] {
            assert!(gate(CKP_ML_DSA_44, true, accelerated));
            assert!(gate(CKP_ML_DSA_87, true, accelerated));
            assert_eq!(gate(CKP_ML_DSA_65, true, accelerated), !accelerated);
            assert_eq!(
                gate(0, true, accelerated),
                !accelerated,
                "unset set is ML-DSA-65"
            );
            for ps in SETS {
                assert!(!gate(ps, false, accelerated), "escape hatch wins");
            }
        }
    }

    /// All 75 NIST ACVP ML-DSA keyGen vectors, AWS-LC and the routed
    /// handler, byte for byte.
    #[test]
    fn mldsa_keygen_acvp_all_vectors() {
        if !active() {
            return;
        }
        let doc = json(
            "fips204-patched/tests/nist_vectors/ML-DSA-keyGen-FIPS204/internalProjection.json",
        );
        let mut n = 0;
        for g in doc["testGroups"].as_array().unwrap() {
            let ps = ps_of(g["parameterSet"].as_str().unwrap());
            for tc in g["tests"].as_array().unwrap() {
                let xi: [u8; 32] = hex(tc["seed"].as_str().unwrap()).try_into().unwrap();
                let want = (
                    hex(tc["pk"].as_str().unwrap()),
                    hex(tc["sk"].as_str().unwrap()),
                );
                assert_eq!(
                    mldsa_keygen_from_seed(ps, &xi).expect("routed"),
                    want,
                    "tcId {}",
                    tc["tcId"]
                );
                assert_eq!(handlers::ml_dsa_keygen_from_seed(ps, &xi).unwrap(), want);
                n += 1;
            }
        }
        assert_eq!(n, 75);
    }

    /// NIST ACVP ML-DSA sigGen (internal interface, deterministic and hedged
    /// with the vector's rnd): AWS-LC cannot produce these (no rnd control),
    /// so it must ACCEPT every expected signature — via external µ, since
    /// µ = H(tr ‖ M′) is exactly what the internal interface signs.
    #[test]
    fn mldsa_acvp_siggen_signatures_verify_on_awslc() {
        if !active() {
            return;
        }
        let doc = json(
            "fips204-patched/tests/nist_vectors/ML-DSA-sigGen-FIPS204/internalProjection.json",
        );
        let mut n = 0;
        for g in doc["testGroups"].as_array().unwrap() {
            let ps = ps_of(g["parameterSet"].as_str().unwrap());
            let p = mldsa_params(ps).unwrap();
            for tc in g["tests"].as_array().unwrap() {
                let sk = hex(tc["sk"].as_str().unwrap());
                let pk = Pkey::new(unsafe {
                    sys::EVP_PKEY_pqdsa_new_raw_private_key(p.nid, sk.as_ptr(), sk.len())
                })
                .expect("ACVP sk imports")
                .raw(false, p.pk_len)
                .unwrap();
                let msg = hex(tc["message"].as_str().unwrap());
                let sig = hex(tc["signature"].as_str().unwrap());
                let mu = mu_of(&pk, &[&msg]);
                assert_eq!(
                    mldsa_verify_mu(ps, &pk, &mu, &sig),
                    Some(true),
                    "tcId {}",
                    tc["tcId"]
                );
                assert!(fips_verify_mu(ps, &pk, &mu, &sig));
                n += 1;
            }
        }
        assert_eq!(n, 60);
    }

    /// NIST ACVP ML-DSA sigVer: the AWS-LC verdict equals the expected
    /// `testPassed` on every vector (modified message / signature, z too
    /// large, too many hints).
    #[test]
    fn mldsa_acvp_sigver_verdicts() {
        if !active() {
            return;
        }
        let doc = json(
            "fips204-patched/tests/nist_vectors/ML-DSA-sigVer-FIPS204/internalProjection.json",
        );
        let mut n = 0;
        for g in doc["testGroups"].as_array().unwrap() {
            let ps = ps_of(g["parameterSet"].as_str().unwrap());
            let pk = hex(g["pk"].as_str().unwrap());
            for tc in g["tests"].as_array().unwrap() {
                let msg = hex(tc["message"].as_str().unwrap());
                let sig = hex(tc["signature"].as_str().unwrap());
                let want = tc["testPassed"].as_bool().unwrap();
                let mu = mu_of(&pk, &[&msg]);
                assert_eq!(
                    mldsa_verify_mu(ps, &pk, &mu, &sig),
                    Some(want),
                    "tcId {} {}",
                    tc["tcId"],
                    tc["reason"]
                );
                assert_eq!(fips_verify_mu(ps, &pk, &mu, &sig), want);
                n += 1;
            }
        }
        assert_eq!(n, 45);
    }

    /// Hedged pure ML-DSA, every set, empty / short / 255-byte contexts:
    /// AWS-LC signatures verify under fips204 and fips204 signatures verify
    /// under AWS-LC; a different context, message or one flipped signature
    /// bit is rejected by both.
    #[test]
    fn mldsa_hedged_cross_verification() {
        if !active() {
            return;
        }
        let long_ctx = [0xc3u8; 255];
        for ps in SETS {
            for (i, ctx) in [&b""[..], b"pkcs11 ctx", &long_ctx].into_iter().enumerate() {
                let (pk, sk) = key(ps, i as u8);
                let msg = format!("message {ps} {i}").into_bytes();
                let a = mldsa_sign(ps, &sk, &msg, ctx).expect("routed");
                assert!(fips_verify(ps, &pk, &msg, &a, ctx), "AWS-LC -> fips204");
                let f = fips_sign_rnd(ps, &sk, &msg, ctx, [i as u8 ^ 0x55; 32]);
                assert_eq!(
                    mldsa_verify(ps, &pk, &msg, &f, ctx),
                    Some(true),
                    "fips204 -> AWS-LC"
                );
                // Hedged: two AWS-LC signatures of the same input differ.
                assert_ne!(a, mldsa_sign(ps, &sk, &msg, ctx).unwrap());
                let other_ctx = b"other";
                assert_eq!(mldsa_verify(ps, &pk, &msg, &a, other_ctx), Some(false));
                assert!(!fips_verify(ps, &pk, &msg, &a, other_ctx));
                let mut bad = a.clone();
                bad[17] ^= 1;
                assert_eq!(mldsa_verify(ps, &pk, &msg, &bad, ctx), Some(false));
                assert!(!fips_verify(ps, &pk, &msg, &bad, ctx));
                assert_eq!(
                    mldsa_verify(ps, &pk, b"other message", &f, ctx),
                    Some(false)
                );
            }
        }
    }

    /// External µ: µ computed per FIPS 204 from (pk, ctx, M). AWS-LC's
    /// µ-signature is a valid PURE signature of M under ctx (fips204), and
    /// fips204's µ-signature verifies under AWS-LC both as µ and as pure.
    #[test]
    fn mldsa_external_mu_cross_verification() {
        if !active() {
            return;
        }
        for ps in SETS {
            let (pk, sk) = key(ps, 9);
            let (msg, ctx) = (b"external mu message".as_slice(), b"ctx".as_slice());
            let mu = mu_of(&pk, &[&[0u8, ctx.len() as u8], ctx, msg]);
            let a = mldsa_sign_mu(ps, &sk, &mu).expect("routed");
            assert!(fips_verify_mu(ps, &pk, &mu, &a));
            assert!(fips_verify(ps, &pk, msg, &a, ctx));
            let f = fips_sign_mu(ps, &sk, &mu, [3; 32]);
            assert_eq!(mldsa_verify_mu(ps, &pk, &mu, &f), Some(true));
            assert_eq!(mldsa_verify(ps, &pk, msg, &f, ctx), Some(true));
            let mut mu2 = mu;
            mu2[0] ^= 1;
            assert_eq!(mldsa_verify_mu(ps, &pk, &mu2, &f), Some(false));
            // Wrong µ length is not handled here (the engine answers it).
            assert_eq!(mldsa_sign_mu(ps, &sk, &mu[..63]), None);
            assert_eq!(mldsa_verify_mu(ps, &pk, &mu[..63], &f), None);
        }
    }

    /// The variants AWS-LC does not cover keep fips204 byte for byte through
    /// the routed handlers: deterministic pure, HashML-DSA (deterministic),
    /// generic CKM_HASH_ML_DSA over a PHM, the internal interface, external
    /// µ with an explicit rnd, and pure signing with an explicit rnd.
    #[test]
    #[allow(deprecated)]
    fn uncovered_variants_stay_byte_identical() {
        use sha2::Digest as _;
        for ps in SETS {
            let (pk, sk) = key(ps, 4);
            let (msg, ctx) = (b"det".as_slice(), b"c".as_slice());
            let det = handlers::sign_ml_dsa(CKM_ML_DSA, ps, &sk, msg, ctx, true).unwrap();
            assert_eq!(
                det,
                fips_sign_rnd(ps, &sk, msg, ctx, [0; 32]),
                "deterministic pure"
            );
            assert_eq!(
                handlers::verify_ml_dsa(CKM_ML_DSA, ps, &pk, msg, &det, ctx),
                Ok(())
            );

            let hashed =
                handlers::sign_ml_dsa(CKM_HASH_ML_DSA_SHA256, ps, &sk, msg, ctx, true).unwrap();
            let want = per_set!(ps, m => {
                let k = m::PrivateKey::try_from_bytes(sk.as_slice().try_into().unwrap()).unwrap();
                k.try_hash_sign_with_rng(&mut handlers::FixedRng::new(&[0u8; 32]), msg, ctx, &fips204::Ph::SHA256).unwrap().to_vec()
            });
            assert_eq!(hashed, want, "HashML-DSA deterministic");
            assert_eq!(
                handlers::verify_ml_dsa(CKM_HASH_ML_DSA_SHA256, ps, &pk, msg, &hashed, ctx),
                Ok(())
            );
            // A HashML-DSA signature is not a pure one (and the pure path,
            // which is routed, must say so).
            assert_eq!(
                handlers::verify_ml_dsa(CKM_ML_DSA, ps, &pk, msg, &hashed, ctx),
                Err(CKR_SIGNATURE_INVALID)
            );

            let phm = sha2::Sha256::digest(msg);
            let generic = handlers::sign_ml_dsa_phm(ps, &sk, &phm, ctx, CKM_SHA256, true).unwrap();
            assert_eq!(generic, hashed, "generic CKM_HASH_ML_DSA over the same PHM");

            let internal = handlers::sign_ml_dsa_internal(ps, &sk, msg, &[], [7; 32]).unwrap();
            let want = per_set!(ps, m => {
                let k = m::PrivateKey::try_from_bytes(sk.as_slice().try_into().unwrap()).unwrap();
                m::_internal_sign(&k, msg, &[], [7; 32]).unwrap().to_vec()
            });
            assert_eq!(internal, want, "internal interface");

            let mu = mu_of(&pk, &[&[0u8, 1], ctx, msg]);
            assert_eq!(
                handlers::sign_ml_dsa_external_mu(ps, &sk, &mu, [5; 32]).unwrap(),
                fips_sign_mu(ps, &sk, &mu, [5; 32]),
                "external mu, explicit rnd"
            );
            assert_eq!(
                handlers::sign_ml_dsa_external_rnd(ps, &sk, msg, ctx, [6; 32]).unwrap(),
                fips_sign_rnd(ps, &sk, msg, ctx, [6; 32]),
                "pure, explicit rnd"
            );
        }
    }

    /// Routed handlers keep their error codes for malformed input.
    #[test]
    fn handler_error_codes_unchanged() {
        let ps = CKP_ML_DSA_44;
        let (pk, sk) = key(ps, 1);
        let sig = handlers::sign_ml_dsa(CKM_ML_DSA, ps, &sk, b"m", b"", false).unwrap();
        let v = |pk: &[u8], sig: &[u8], ctx: &[u8]| {
            handlers::verify_ml_dsa(CKM_ML_DSA, ps, pk, b"m", sig, ctx)
        };
        assert_eq!(v(&pk, &sig, b""), Ok(()));
        assert_eq!(v(&pk[1..], &sig, b""), Err(CKR_KEY_TYPE_INCONSISTENT));
        assert_eq!(v(&pk, &sig[1..], b""), Err(CKR_SIGNATURE_INVALID));
        assert_eq!(v(&pk, &sig, &[0u8; 256]), Err(CKR_SIGNATURE_INVALID));
        assert_eq!(
            handlers::sign_ml_dsa(CKM_ML_DSA, ps, &sk[1..], b"m", b"", false),
            Err(CKR_KEY_TYPE_INCONSISTENT)
        );
        assert_eq!(
            handlers::sign_ml_dsa(CKM_ML_DSA, 0x77, &sk, b"m", b"", false),
            Err(CKR_KEY_TYPE_INCONSISTENT)
        );
        assert_eq!(
            handlers::sign_ml_dsa(CKM_ML_DSA, ps, &sk, b"m", &[0u8; 256], false),
            Err(CKR_FUNCTION_FAILED)
        );
        assert_eq!(
            handlers::verify_ml_dsa_external_mu(ps, &pk, &[0u8; 63], &sig),
            Err(CKR_ARGUMENTS_BAD)
        );
        assert_eq!(
            handlers::sign_ml_dsa_external_mu_hedged(ps, &sk, &[0u8; 63]),
            Err(CKR_ARGUMENTS_BAD)
        );
    }

    /// A private key whose stored `tr` does not match its public key: AWS-LC
    /// refuses to import it, and the handler then does exactly what fips204
    /// does with it (fips204 does not check `tr`).
    #[test]
    fn inconsistent_private_key_falls_back_to_fips204() {
        for ps in SETS {
            let (_, mut sk) = key(ps, 2);
            sk[70] ^= 0x80; // inside tr (bytes 64..128)
            assert_eq!(mldsa_sign(ps, &sk, b"m", b""), None);
            let direct = per_set!(ps, m => m::PrivateKey::try_from_bytes(sk.as_slice().try_into().unwrap())
                .map(|k| k.try_sign_with_rng(&mut handlers::FixedRng::new(&[0u8; 32]), b"m", b"").map(|s| s.to_vec())));
            let routed = handlers::sign_ml_dsa(CKM_ML_DSA, ps, &sk, b"m", b"", true);
            assert_eq!(routed.ok(), direct.ok().and_then(|r| r.ok()));
            assert_eq!(
                handlers::sign_ml_dsa(CKM_ML_DSA, ps, &sk, b"m", b"", false).is_ok(),
                routed_is_ok(ps, &sk)
            );
        }
    }

    fn routed_is_ok(ps: u32, sk: &[u8]) -> bool {
        per_set!(ps, m => m::PrivateKey::try_from_bytes(sk.try_into().unwrap()).is_ok())
    }

    /// The parsed-key cache hands back the same AWS-LC key for the same bytes
    /// and is emptied by the engine's cache-clear hook.
    #[test]
    fn private_key_cache_reuses_the_parsed_key() {
        if !active() {
            return;
        }
        let (_, sk) = key(CKP_ML_DSA_87, 3);
        let p = mldsa_params(CKP_ML_DSA_87).unwrap();
        let a = mldsa_private_key(&p, &sk).unwrap();
        let b = mldsa_private_key(&p, &sk).unwrap();
        // Another test may clear the cache between the two lookups; retry
        // once before calling it a miss.
        let same = Arc::ptr_eq(&a, &b) || {
            let c = mldsa_private_key(&p, &sk).unwrap();
            Arc::ptr_eq(&c, &mldsa_private_key(&p, &sk).unwrap())
        };
        assert!(same, "second lookup must hit");
        let (hits, _) = key_cache_stats();
        assert!(hits >= 1);
    }

    // ── ML-KEM ──────────────────────────────────────────────────────────────

    const KEM_SETS: [u32; 3] = [CKP_ML_KEM_512, CKP_ML_KEM_768, CKP_ML_KEM_1024];

    macro_rules! per_kem {
        ($ps:expr, $t:ident => $body:expr) => {
            match $ps {
                CKP_ML_KEM_512 => {
                    type $t = ml_kem::MlKem512;
                    $body
                }
                CKP_ML_KEM_768 => {
                    type $t = ml_kem::MlKem768;
                    $body
                }
                CKP_ML_KEM_1024 => {
                    type $t = ml_kem::MlKem1024;
                    $body
                }
                other => panic!("not an ML-KEM set: {other}"),
            }
        };
    }

    fn rust_keygen(ps: u32, dz: &[u8; 64]) -> (Vec<u8>, Vec<u8>) {
        use ml_kem::{EncodedSizeUser, KemCore};
        per_kem!(ps, K => {
            let d = ml_kem::B32::try_from(&dz[..32]).unwrap();
            let z = ml_kem::B32::try_from(&dz[32..]).unwrap();
            let (dk, ek) = K::generate_deterministic(&d, &z);
            (ek.as_bytes().to_vec(), dk.as_bytes().to_vec())
        })
    }

    fn rust_encaps(ps: u32, ek: &[u8], m: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
        use ml_kem::{EncapsulateDeterministic, EncodedSizeUser, KemCore};
        per_kem!(ps, K => {
            let ek = <K as KemCore>::EncapsulationKey::from_bytes(&ek.try_into().unwrap());
            let (c, k) = ek.encapsulate_deterministic(&ml_kem::B32::from(*m)).unwrap();
            (c.to_vec(), k.to_vec())
        })
    }

    fn rust_decaps(ps: u32, dk: &[u8], ct: &[u8]) -> Vec<u8> {
        use ml_kem::kem::Decapsulate;
        use ml_kem::{EncodedSizeUser, KemCore};
        per_kem!(ps, K => {
            let dk = <K as KemCore>::DecapsulationKey::from_bytes(&dk.try_into().unwrap());
            dk.decapsulate(&ct.try_into().unwrap()).unwrap().to_vec()
        })
    }

    /// The in-repo NIST ACVP ML-KEM encapDecap vectors (one decapsulation
    /// case per set): AWS-LC, the routed handler and ml-kem all give the
    /// expected shared secret.
    #[test]
    fn mlkem_acvp_decaps_vectors() {
        if !active() {
            return;
        }
        let doc = json("../tests/acvp/mlkem_test.json");
        let mut n = 0;
        for g in doc["testGroups"].as_array().unwrap() {
            let ps = ps_of(g["parameterSet"].as_str().unwrap());
            for tc in g["tests"].as_array().unwrap() {
                let (sk, ct, ss) = (
                    hex(tc["sk"].as_str().unwrap()),
                    hex(tc["ct"].as_str().unwrap()),
                    hex(tc["ss"].as_str().unwrap()),
                );
                assert_eq!(
                    mlkem_decaps(ps, &sk, &ct).as_deref(),
                    Some(ss.as_slice()),
                    "tcId {}",
                    tc["tcId"]
                );
                assert_eq!(handlers::ml_kem_decaps(ps, &sk, &ct).unwrap(), ss);
                assert_eq!(rust_decaps(ps, &sk, &ct), ss);
                n += 1;
            }
        }
        assert_eq!(n, 3);
    }

    /// KeyGen(d ‖ z), Encaps(ek, m) and Decaps: AWS-LC and ml-kem agree byte
    /// for byte over many seeds; tampered ciphertexts take the implicit
    /// rejection branch identically in both (K̄ = J(z ‖ c), not an error).
    #[test]
    fn mlkem_byte_identity_and_implicit_rejection() {
        if !active() {
            return;
        }
        for ps in KEM_SETS {
            for i in 0..24u8 {
                let mut dz = [0u8; 64];
                for (j, b) in dz.iter_mut().enumerate() {
                    *b = (j as u8).wrapping_mul(i | 1).wrapping_add(ps as u8);
                }
                let (ek, dk) = rust_keygen(ps, &dz);
                if cfg!(feature = "awslc-pq-mlkem-seeded") {
                    assert_eq!(
                        mlkem_keygen_from_seed(ps, &dz).unwrap(),
                        (ek.clone(), dk.clone())
                    );
                }
                assert_eq!(
                    handlers::ml_kem_keygen_from_seed(ps, &dz).unwrap(),
                    (ek.clone(), dk.clone())
                );
                let m = [i ^ 0xa5; 32];
                let (ct, ss) = rust_encaps(ps, &ek, &m);
                if cfg!(feature = "awslc-pq-mlkem-seeded") {
                    assert_eq!(mlkem_encaps(ps, &ek, &m).unwrap(), (ct.clone(), ss.clone()));
                }
                assert_eq!(
                    handlers::ml_kem_encaps(ps, &ek, &m).unwrap(),
                    (ct.clone(), ss.clone())
                );
                assert_eq!(mlkem_decaps(ps, &dk, &ct).unwrap(), ss);
                let mut bad = ct.clone();
                let at = usize::from(i) % bad.len();
                bad[at] ^= 1 << (i % 8);
                let rejected = rust_decaps(ps, &dk, &bad);
                assert_ne!(rejected, ss);
                assert_eq!(
                    mlkem_decaps(ps, &dk, &bad).unwrap(),
                    rejected,
                    "implicit rejection"
                );
                assert_eq!(handlers::ml_kem_decaps(ps, &dk, &bad).unwrap(), rejected);
            }
        }
    }

    /// FIPS 203 input checks: AWS-LC refuses an encapsulation key with a
    /// coefficient ≥ q and a decapsulation key whose H(ek) is wrong; the
    /// routed handlers then return exactly what ml-kem (which checks
    /// neither) returned before this module existed.
    #[test]
    fn mlkem_invalid_keys_fall_back_to_ml_kem() {
        for ps in KEM_SETS {
            let (ek, dk) = rust_keygen(ps, &[0x11; 64]);
            let mut bad_ek = ek.clone();
            bad_ek[0] = 0xff; // first 12-bit coefficient becomes ≥ 3840 > q
            bad_ek[1] |= 0x0f;
            let m = [0x22; 32];
            assert_eq!(mlkem_encaps(ps, &bad_ek, &m), None);
            assert_eq!(
                handlers::ml_kem_encaps(ps, &bad_ek, &m).unwrap(),
                rust_encaps(ps, &bad_ek, &m)
            );

            let (ct, _) = rust_encaps(ps, &ek, &m);
            let mut bad_dk = dk.clone();
            let h_at = dk.len() - 64; // dk = dk_pke ‖ ek ‖ H(ek) ‖ z
            bad_dk[h_at] ^= 1;
            assert_eq!(mlkem_decaps(ps, &bad_dk, &ct), None);
            assert_eq!(
                handlers::ml_kem_decaps(ps, &bad_dk, &ct).unwrap(),
                rust_decaps(ps, &bad_dk, &ct)
            );

            // Lengths and unknown sets keep the engine's error codes.
            assert_eq!(
                handlers::ml_kem_encaps(ps, &ek[1..], &m),
                Err(CKR_KEY_TYPE_INCONSISTENT)
            );
            assert_eq!(
                handlers::ml_kem_decaps(ps, &dk[1..], &ct),
                Err(CKR_KEY_TYPE_INCONSISTENT)
            );
            assert_eq!(
                handlers::ml_kem_decaps(ps, &dk, &ct[1..]),
                Err(CKR_ARGUMENTS_BAD)
            );
        }
        assert_eq!(
            handlers::ml_kem_encaps(0x9, &[0; 800], &[0; 32]),
            Err(CKR_ARGUMENTS_BAD)
        );
        assert_eq!(
            handlers::ml_kem_keygen_from_seed(CKP_ML_KEM_768, &[0; 63]),
            None
        );
    }
}
