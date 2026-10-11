//! Streamed CKKS generator, version 1 (plan §3.1). Normative reference:
//! pqctoday-fhe `reference-runs/ckks-stream-oracle/spec.go`; this port must
//! produce identical bytes.
//!
//! KDF(label, ctx, L) = first L bytes of ‖_{i≥1} HMAC-SHA-384(seed, [i]_32 ‖
//! "pqctoday-fhe/ckks/" ‖ label ‖ 0x00 ‖ ctx ‖ [8L]_32), ctx = LP("CKKS") ‖
//! LP(paramName) ‖ LP(paramHash) ‖ LP("v1") ‖ LP(extra…). Streams are
//! AES-256-CTR with a zero IV (owner decision Q4, 2026-10-10). The public `a`
//! limbs use the key HMAC-SHA-256(aSeed, "pqctoday-fhe/ckks/a/v1" ‖ KeyID ‖
//! [d]_32 ‖ [j]_32); `params::key_id` names a key by kind, Galois element and
//! levels, never by list position.
//!
//! Secret-dependent steps (fixed-weight sampler, Gaussian CDT, reductions,
//! Montgomery conversion) run a fixed sequence of operations with branch-free
//! comparisons; rejection loops depend only on discarded stream words.

use aes::cipher::{Block, BlockCipherEncrypt, KeyInit};
use hmac::{Hmac, Mac};
use zeroize::Zeroize;

use super::params::*;
use super::params_gen::GAUSSIAN_CDT;
use super::ring::{automorphism_ntt_index, mform, mred, Modulus};

const GAUSS_BOUND: i64 = 19;

/// KDF labels of generator version 1 (gate V: frozen, `freeze.rs`). Every
/// generator KDF call names one of these; a new or changed label is a new
/// generator version.
pub mod label {
    pub const SECRET: &str = "secret";
    pub const SPARSE_SECRET: &str = "sparse-secret";
    pub const A_SEED: &str = "a-seed";
    pub const PK_ERROR: &str = "pk-error";
    pub const ERROR: &str = "error";
    pub const ROTATION_A_SEED: &str = "rotation-a-seed";
    pub const ROTATION_ERROR: &str = "rotation-error";
}
pub const KDF_LABELS_V1: [&str; 7] = [label::SECRET, label::SPARSE_SECRET, label::A_SEED, label::PK_ERROR, label::ERROR, label::ROTATION_A_SEED, label::ROTATION_ERROR];
/// KDF label prefix, the context's version field and the a-expansion domain
/// of generator version 1.
pub const KDF_PREFIX: &[u8] = b"pqctoday-fhe/ckks/";
pub const KDF_CONTEXT_VERSION: &[u8] = b"v1";
pub const A_EXPAND_DOMAIN: &[u8] = b"pqctoday-fhe/ckks/a/v1";

fn lp(fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for f in fields {
        out.extend_from_slice(&(f.len() as u32).to_be_bytes());
        out.extend_from_slice(f);
    }
    out
}

/// AES-256-CTR keystream, 128-bit big-endian counter from zero (Go `cipher.NewCTR`).
/// The keystream is produced `STREAM_BLOCKS` blocks at a time so the AES
/// instructions run pipelined (A7); the bytes are identical to block-by-block CTR.
pub struct Stream {
    cipher: aes::Aes256,
    ctr: u128,
    buf: [u8; 16 * STREAM_BLOCKS],
    pos: usize,
}

const STREAM_BLOCKS: usize = 64;

impl Stream {
    pub fn new(key: &[u8; 32]) -> Self {
        Stream { cipher: aes::Aes256::new_from_slice(key).expect("32-byte key"), ctr: 0, buf: [0; 16 * STREAM_BLOCKS], pos: 16 * STREAM_BLOCKS }
    }
    fn refill(&mut self) {
        let mut blocks = [Block::<aes::Aes256>::default(); STREAM_BLOCKS];
        for b in blocks.iter_mut() {
            *b = Block::<aes::Aes256>::from(self.ctr.to_be_bytes());
            self.ctr = self.ctr.wrapping_add(1);
        }
        self.cipher.encrypt_blocks(&mut blocks);
        for (i, b) in blocks.iter().enumerate() {
            self.buf[16 * i..16 * i + 16].copy_from_slice(b);
        }
        blocks.iter_mut().for_each(|b| b.as_mut_slice().zeroize());
        self.pos = 0;
    }
    fn byte(&mut self) -> u8 {
        if self.pos == self.buf.len() {
            self.refill();
        }
        let v = self.buf[self.pos];
        self.pos += 1;
        v
    }
    fn take<const L: usize>(&mut self) -> [u8; L] {
        let mut out = [0u8; L];
        if self.pos + L <= self.buf.len() {
            out.copy_from_slice(&self.buf[self.pos..self.pos + L]);
            self.pos += L;
        } else {
            out.iter_mut().for_each(|x| *x = self.byte());
        }
        out
    }
    pub fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.take::<8>())
    }
    pub fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.take::<4>())
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

/// Uniform in [0, m) by rejection on the low bits of a u32.
fn below(st: &mut Stream, m: u32) -> u32 {
    let mask = if m <= 1 { 0 } else { u32::MAX >> (m - 1).leading_zeros() };
    loop {
        let r = st.u32() & mask;
        if r < m {
            return r;
        }
    }
}

/// All-ones when a == b, else zero, without a branch.
#[inline(always)]
fn ct_eq_mask(a: u32, b: u32) -> u64 {
    let x = (a ^ b) as u64;
    ((x | x.wrapping_neg()) >> 63).wrapping_sub(1)
}

/// Fixed-weight ternary polynomial (Sendrier's method as in HQC; the oracle's
/// `ternary`): position i = i + below(n − i) with a sign byte; a backward pass
/// replaces a position equal to any later one by i; then every coefficient is
/// scanned against every position. Comparisons and selections are branch-free.
fn ternary(st: &mut Stream, n: usize, h: usize) -> Vec<i64> {
    let mut pos = vec![0u32; h];
    let mut sgn = vec![0i64; h];
    for i in 0..h {
        pos[i] = i as u32 + below(st, (n - i) as u32);
        sgn[i] = 1 - 2 * (st.byte() & 1) as i64;
    }
    for i in (0..h).rev() {
        let mut dup = 0u64;
        for j in i + 1..h {
            dup |= ct_eq_mask(pos[j], pos[i]);
        }
        pos[i] = ((pos[i] as u64 & !dup) | (i as u64 & dup)) as u32;
    }
    let mut out = vec![0i64; n];
    for (c, o) in out.iter_mut().enumerate() {
        let mut v = 0u64;
        for i in 0..h {
            v |= (sgn[i] as u64) & ct_eq_mask(pos[i], c as u32);
        }
        *o = v as i64;
    }
    pos.zeroize();
    sgn.zeroize();
    out
}

fn gaussian(st: &mut Stream, n: usize) -> Vec<i64> {
    (0..n)
        .map(|_| {
            let r = st.u64();
            let c: i64 = GAUSSIAN_CDT.iter().map(|&t| (r >= t) as i64).sum();
            c - GAUSS_BOUND
        })
        .collect()
}

/// Uniform public `a` limb, used as stored (NTT and Montgomery domains).
pub fn uniform_a(a_seed: &[u8; 32], key_id: &[u8; 17], d: u32, j: u32, q: u64, n: usize) -> Vec<u64> {
    let mut m = <Hmac<sha2::Sha256> as Mac>::new_from_slice(a_seed).expect("any key length");
    m.update(A_EXPAND_DOMAIN);
    m.update(key_id);
    m.update(&d.to_be_bytes());
    m.update(&j.to_be_bytes());
    let key: [u8; 32] = m.finalize().into_bytes().into();
    let mut st = Stream::new(&key);
    let mask = if q.leading_zeros() == 0 { u64::MAX } else { (1u64 << (64 - q.leading_zeros())) - 1 };
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        let r = st.u64() & mask;
        if r < q {
            out.push(r);
        }
    }
    out
}

/// Worker threads per chunk (A6): `PQC_CKKS_THREADS` if set (1 disables), else
/// the available cores; always 1 on wasm32.
pub fn chunk_threads() -> usize {
    #[cfg(target_arch = "wasm32")]
    {
        1
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::env::var("PQC_CKKS_THREADS").ok().and_then(|v| v.parse().ok()).filter(|&t: &usize| t >= 1).unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1))
    }
}

/// Limbs [from, to) of one chunk (A6): limbs are independent, so they run on
/// up to `chunk_threads()` cores; the output keeps limb order, so the bytes do
/// not depend on the thread count.
fn run_limbs(from: usize, to: usize, n: usize, limb: impl Fn(usize) -> Result<Vec<u8>, ()> + Sync) -> Result<Vec<u8>, ()> {
    let threads = chunk_threads().min(to - from);
    let mut out = Vec::with_capacity((to - from) * n * 8);
    if threads <= 1 {
        for j in from..to {
            out.extend_from_slice(&limb(j)?);
        }
    } else {
        let limbs: Vec<usize> = (from..to).collect();
        let per = limbs.len().div_ceil(threads);
        let limb = &limb;
        let parts: Vec<Result<Vec<Vec<u8>>, ()>> = std::thread::scope(|sc| {
            let hs: Vec<_> = limbs.chunks(per).map(|js| sc.spawn(move || js.iter().map(|&j| limb(j)).collect::<Result<Vec<_>, ()>>())).collect();
            hs.into_iter().map(|h| h.join().unwrap_or(Err(()))).collect()
        });
        for part in parts {
            for l in part? {
                out.extend_from_slice(&l);
            }
        }
    }
    Ok(out)
}

/// Public inputs of a rotation key (E10): the SHA-256 of each seed's key-set
/// descriptor (`CkksKeySetDescriptorV1` DER, which carries its lineage and
/// a-seed) and the rotation key's public a-seed (`rotation_a_seed`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotationCtx {
    pub old_descriptor_hash: [u8; 32],
    pub new_descriptor_hash: [u8; 32],
    pub a_seed: [u8; 32],
}

/// The secrets and public seed regenerated from one FHE seed. Zeroized on drop.
pub struct Generator {
    pub ps: &'static CkksParamSet,
    seed: [u8; 32],
    s: Vec<i64>,
    ss: Vec<i64>,
    pub a_seed: [u8; 32],
    param_hash: [u8; 32],
    /// The last digit's error polynomial (key id, digit, coefficients): the
    /// export walks a digit's limbs over several calls (A9). Zeroized on
    /// replacement and on drop.
    err_cache: std::sync::Mutex<Option<([u8; 17], u32, Vec<i64>)>>,
    /// Per-modulus NTT tables and MForm(NTT(s)) (A7): both depend only on the
    /// modulus, yet every key and digit used to rebuild them. Bounded by
    /// `PQC_CKKS_CACHE_MB` (default 64; 0 disables); the secret part is
    /// zeroized on drop. Bytes are unchanged.
    limb_cache: std::sync::Mutex<std::collections::HashMap<u64, std::sync::Arc<LimbCtx>>>,
}

/// Cached per-modulus context: public NTT tables and the secret in NTT form.
pub struct LimbCtx {
    pub m: Modulus,
    pub s_ntt: Vec<u64>,
}

impl Drop for LimbCtx {
    fn drop(&mut self) {
        self.s_ntt.zeroize();
    }
}

fn limb_cache_budget() -> usize {
    #[cfg(target_arch = "wasm32")]
    {
        0
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::env::var("PQC_CKKS_CACHE_MB").ok().and_then(|v| v.parse::<usize>().ok()).unwrap_or(64) << 20
    }
}

impl Drop for Generator {
    fn drop(&mut self) {
        self.seed.zeroize();
        self.s.zeroize();
        self.ss.zeroize();
        if let Ok(mut c) = self.err_cache.lock() {
            if let Some((_, _, e)) = c.as_mut() {
                e.zeroize();
            }
            *c = None;
        }
    }
}

impl Generator {
    pub fn new(ps: &'static CkksParamSet, seed: &[u8; 32]) -> Self {
        let mut g = Generator { ps, seed: *seed, s: Vec::new(), ss: Vec::new(), a_seed: [0; 32], param_hash: param_hash(ps), err_cache: std::sync::Mutex::new(None), limb_cache: Default::default() };
        let n = ps.n();
        let mut k = g.kdf32(label::SECRET, &[]);
        g.s = ternary(&mut Stream::new(&k), n, ps.h);
        k.zeroize();
        if ps.ephemeral_h != 0 {
            let mut k = g.kdf32(label::SPARSE_SECRET, &[]);
            g.ss = ternary(&mut Stream::new(&k), n, ps.ephemeral_h);
            k.zeroize();
        }
        g.a_seed = g.kdf32(label::A_SEED, &[]);
        g
    }

    /// NTT tables and MForm(NTT(s)) for modulus `q`, from the cache when it
    /// fits the budget (each entry ≈ 24·N bytes).
    fn limb_ctx(&self, q: u64, g: u64, n: usize) -> std::sync::Arc<LimbCtx> {
        if let Ok(c) = self.limb_cache.lock() {
            if let Some(e) = c.get(&q) {
                return e.clone();
            }
        }
        let m = Modulus::new(q, g, n);
        let s_ntt = m.ntt_mform_of(&self.s);
        let ctx = std::sync::Arc::new(LimbCtx { m, s_ntt });
        if let Ok(mut c) = self.limb_cache.lock() {
            if (c.len() + 1) * 24 * n <= limb_cache_budget() {
                c.insert(q, ctx.clone());
            }
        }
        ctx
    }

    /// Constant-time check that this generator was built from `seed`.
    pub fn same_seed(&self, ps: &CkksParamSet, seed: &[u8; 32]) -> bool {
        let diff = self.seed.iter().zip(seed).fold(0u8, |a, (x, y)| a | (x ^ y));
        diff == 0 && self.ps.id == ps.id
    }

    /// The digit's error polynomial, from the one-entry cache when the
    /// previous call used the same key and digit (bytes are unchanged).
    fn cached_error(&self, k: &KeyDesc, d: u32) -> Vec<i64> {
        let id = key_id(k);
        if let Ok(c) = self.err_cache.lock() {
            if let Some((cid, cd, e)) = c.as_ref() {
                if *cid == id && *cd == d {
                    return e.clone();
                }
            }
        }
        let e = self.error_poly(k, Some(d));
        if let Ok(mut c) = self.err_cache.lock() {
            if let Some((_, _, old)) = c.as_mut() {
                old.zeroize();
            }
            *c = Some((id, d, e.clone()));
        }
        e
    }

    fn kdf32(&self, label: &str, extra: &[&[u8]]) -> [u8; 32] {
        let mut ctx = lp(&[b"CKKS", self.ps.name.as_bytes(), &self.param_hash, KDF_CONTEXT_VERSION]);
        ctx.extend_from_slice(&lp(extra));
        let mut m = <Hmac<sha2::Sha384> as Mac>::new_from_slice(&self.seed).expect("any key length");
        m.update(&1u32.to_be_bytes());
        m.update(KDF_PREFIX);
        m.update(label.as_bytes());
        m.update(&[0]);
        m.update(&ctx);
        m.update(&(8 * 32u32).to_be_bytes());
        let mut block = m.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&block[..32]);
        block.as_mut_slice().zeroize();
        out
    }

    fn error_poly(&self, k: &KeyDesc, d: Option<u32>) -> Vec<i64> {
        let id = key_id(k);
        let mut key = match d {
            None => self.kdf32(label::PK_ERROR, &[&id]),
            Some(d) => self.kdf32(label::ERROR, &[&id, &d.to_be_bytes()]),
        };
        let e = gaussian(&mut Stream::new(&key), self.ps.n());
        key.zeroize();
        e
    }

    /// The b limbs [from, to) of key `k_idx`, digit `d`, as u64 little-endian bytes.
    pub fn chunk(&self, k_idx: u32, d: u32, from: usize, to: usize) -> Result<Vec<u8>, ()> {
        let ps = self.ps;
        let k = *ps.keys.get(k_idx as usize).ok_or(())?;
        if (d as usize) >= k.dnum() || from >= to || to > k.limbs() {
            return Err(());
        }
        let n = ps.n();
        let id = key_id(&k);
        let mut e = self.cached_error(&k, d);
        let mut prod_p = num_bigint::BigUint::from(1u32);
        for p in &ps.p[..=k.level_p] {
            prod_p *= *p;
        }
        let digit = k.level_p + 1;
        let gal_idx = if k.kind == KIND_GALOIS {
            let nth = 2 * n as u64;
            let inv = super::ring::pow_mod(k.gal_el, nth - 1, nth);
            Some(automorphism_ntt_index(n, inv))
        } else {
            None
        };
        // One limb: everything below depends only on (j, shared read-only inputs).
        let limb = |j: usize| -> Result<Vec<u8>, ()> {
            let (q, g) = ps.key_limb(&k, j).ok_or(())?;
            let ctx = self.limb_ctx(q, g, n);
            let m = &ctx.m;
            let mut s_main = ctx.s_ntt.clone();
            let (mut sk_out, mut sk_in): (Vec<u64>, Vec<u64>) = match k.kind {
                KIND_RELIN => {
                    let sq = s_main.iter().map(|&x| mred(x, x, q, m.qinv)).collect();
                    (s_main.clone(), sq)
                }
                KIND_GALOIS => {
                    let idx = gal_idx.as_ref().ok_or(())?;
                    (idx.iter().map(|&i| s_main[i]).collect(), s_main.clone())
                }
                KIND_DENSE_TO_SPARSE => (m.ntt_mform_of(&self.ss), s_main.clone()),
                KIND_SPARSE_TO_DENSE => (s_main.clone(), m.ntt_mform_of(&self.ss)),
                _ => return Err(()),
            };
            s_main.zeroize();
            let mut b = m.ntt_mform_of(&e);
            let a = uniform_a(&self.a_seed, &id, d, j as u32, q, n);
            for i in 0..n {
                b[i] = m.sub(b[i], mred(a[i], sk_out[i], q, m.qinv));
            }
            if j <= k.level_q && j >= d as usize * digit && j < (d as usize + 1) * digit {
                let pm = (&prod_p % q).to_u64_digits().first().copied().unwrap_or(0);
                let pm = mform(pm, q);
                for i in 0..n {
                    b[i] = m.add(b[i], mred(sk_in[i], pm, q, m.qinv));
                }
            }
            sk_out.zeroize();
            sk_in.zeroize();
            let mut bytes = Vec::with_capacity(n * 8);
            for v in &b {
                bytes.extend_from_slice(&v.to_le_bytes());
            }
            Ok(bytes)
        };
        let out = run_limbs(from, to, n, limb);
        e.zeroize();
        out
    }

    /// Public a-seed of the rotation key from `old` to this generator's
    /// secret (E10), bound to both key-set descriptor hashes.
    pub fn rotation_a_seed(&self, ctx: &RotationCtx) -> [u8; 32] {
        self.kdf32(label::ROTATION_A_SEED, &[&ctx.old_descriptor_hash, &ctx.new_descriptor_hash])
    }

    /// Gate V change detector: SHA-256 over this generator's KDF output for
    /// every version 1 label (fixed extra context "gate-v"), then the first
    /// 16 words of one a-expansion under key 0's KeyID. It runs the production
    /// `kdf32` and `uniform_a`, so a change to the label set, the prefix, the
    /// context layout or version field, the PRF, or the a-expansion changes it.
    #[cfg(test)]
    pub(crate) fn kdf_fingerprint(&self) -> [u8; 32] {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        for l in KDF_LABELS_V1 {
            h.update(l.as_bytes());
            h.update(self.kdf32(l, &[b"gate-v"]));
        }
        let k = &self.ps.keys[0];
        for w in uniform_a(&self.a_seed, &key_id(k), 0, 0, self.ps.q[0], 16) {
            h.update(w.to_le_bytes());
        }
        h.finalize().into()
    }

    /// The b limbs [from, to) of digit `d` of the rotation key (E10): the
    /// key-switching key from `old`'s secret (input) to this generator's
    /// secret (output) over the residual basis,
    /// b_j = MForm(NTT_j(e)) − a_j ⊙ Ŝ_new + [j in digit d's Q range] · MForm(P_res mod q_j) ⊙ Ŝ_old,
    /// Lattigo's `GenEvaluationKeyNew(skInput = s_old, skOutput = s_new)` at
    /// the residual levels. The error is keyed by this (the new) seed under
    /// the label "rotation-error" with both descriptor hashes, the KeyID and
    /// the digit; `a` is expanded from `ctx.a_seed` under the KeyID (kind 5),
    /// so no limb can coincide with a key-set limb.
    pub fn rotation_chunk(&self, old: &Generator, ctx: &RotationCtx, d: u32, from: usize, to: usize) -> Result<Vec<u8>, ()> {
        let ps = self.ps;
        if old.ps.id != ps.id {
            return Err(());
        }
        let k = ps.rotation_desc();
        if (d as usize) >= k.dnum() || from >= to || to > k.limbs() {
            return Err(());
        }
        let n = ps.n();
        let id = key_id(&k);
        let mut key = self.kdf32(label::ROTATION_ERROR, &[&ctx.old_descriptor_hash, &ctx.new_descriptor_hash, &id, &d.to_be_bytes()]);
        let mut e = gaussian(&mut Stream::new(&key), n);
        key.zeroize();
        let mut prod_p = num_bigint::BigUint::from(1u32);
        for p in ps.residual_p {
            prod_p *= *p;
        }
        let digit = k.level_p + 1;
        let limb = |j: usize| -> Result<Vec<u8>, ()> {
            let (q, g) = ps.pk_limb(j).ok_or(())?;
            let new_ctx = self.limb_ctx(q, g, n);
            let old_ctx = old.limb_ctx(q, g, n);
            let m = &new_ctx.m;
            let mut b = m.ntt_mform_of(&e);
            let a = uniform_a(&ctx.a_seed, &id, d, j as u32, q, n);
            for i in 0..n {
                b[i] = m.sub(b[i], mred(a[i], new_ctx.s_ntt[i], q, m.qinv));
            }
            if j <= k.level_q && j >= d as usize * digit && j < (d as usize + 1) * digit {
                let pm = (&prod_p % q).to_u64_digits().first().copied().unwrap_or(0);
                let pm = mform(pm, q);
                for i in 0..n {
                    b[i] = m.add(b[i], mred(old_ctx.s_ntt[i], pm, q, m.qinv));
                }
            }
            let mut bytes = Vec::with_capacity(n * 8);
            for v in &b {
                bytes.extend_from_slice(&v.to_le_bytes());
            }
            Ok(bytes)
        };
        let out = run_limbs(from, to, n, limb);
        e.zeroize();
        out
    }

    /// The public-key b limbs [from, to) over the residual basis.
    pub fn pk_chunk(&self, from: usize, to: usize) -> Result<Vec<u8>, ()> {
        let ps = self.ps;
        if from >= to || to > ps.pk_limbs() {
            return Err(());
        }
        let n = ps.n();
        let pk = ps.pk_desc();
        let id = key_id(&pk);
        let mut e = self.error_poly(&pk, None);
        let mut out = Vec::with_capacity((to - from) * n * 8);
        for j in from..to {
            let (q, g) = ps.pk_limb(j).ok_or(())?;
            let m = Modulus::new(q, g, n);
            let mut s = m.ntt_mform_of(&self.s);
            let mut b = m.ntt_mform_of(&e);
            let a = uniform_a(&self.a_seed, &id, 0, j as u32, q, n);
            for i in 0..n {
                b[i] = m.sub(b[i], mred(a[i], s[i], q, m.qinv));
            }
            s.zeroize();
            for v in &b {
                out.extend_from_slice(&v.to_le_bytes());
            }
        }
        e.zeroize();
        Ok(out)
    }

    /// m = c0 + c1·s mod Q_L, Q_L = q0·…·q_L, for a level-`level` ciphertext
    /// over the residual basis in the NTT domain (standard form); `c0` and
    /// `c1` hold limbs 0..=level, limb-major (N words each). Returned as
    /// centered integer coefficients in (−Q_L/2, Q_L/2]. Levels 0 and 1 only
    /// (Q_1 < 2^106 fits i128): limb 1 is joined to limb 0 by Garner's CRT,
    /// x = a0 + q0·((a1 − a0)·q0⁻¹ mod q1), and centered without a branch on
    /// the secret-dependent value. Level 0 is the one-prime release of
    /// registry IDs 2 and 0x8002, as first built.
    pub fn decrypt_level(&self, level: usize, c0: &[u64], c1: &[u64]) -> Result<Vec<i128>, ()> {
        let ps = self.ps;
        let n = ps.n();
        let limbs = level + 1;
        if level > 1 || level >= ps.residual_q.len() || c0.len() != limbs * n || c1.len() != limbs * n {
            return Err(());
        }
        let mut a: Vec<Vec<u64>> = Vec::with_capacity(limbs);
        for j in 0..limbs {
            let (q, g) = ps.pk_limb(j).ok_or(())?;
            let (x0, x1) = (&c0[j * n..(j + 1) * n], &c1[j * n..(j + 1) * n]);
            if x0.iter().chain(x1).any(|&v| v >= q) {
                a.iter_mut().for_each(|v| v.zeroize());
                return Err(());
            }
            let m = Modulus::new(q, g, n);
            let mut s = m.ntt_mform_of(&self.s);
            let mut p: Vec<u64> = (0..n).map(|i| m.add(x0[i], mred(x1[i], s[i], q, m.qinv))).collect();
            s.zeroize();
            m.intt(&mut p);
            a.push(p);
        }
        let q0 = ps.residual_q[0] as u128;
        let (big_q, inv) = if level == 1 {
            let q1 = ps.residual_q[1];
            (q0 * q1 as u128, super::ring::pow_mod(ps.residual_q[0] % q1, q1 - 2, q1) as u128)
        } else {
            (q0, 0)
        };
        let half = big_q / 2;
        let out = (0..n)
            .map(|i| {
                let a0 = a[0][i] as u128;
                let x = if level == 1 {
                    let q1 = ps.residual_q[1] as u128;
                    let a1 = a[1][i] as u128;
                    // (a1 − a0 mod q1)·q0⁻¹ mod q1; all products < 2^90.
                    let t = ((a1 + q1 - a0 % q1) % q1) * inv % q1;
                    a0 + q0 * t
                } else {
                    a0
                };
                // x − Q if x > Q/2, by mask.
                let over = ((half.wrapping_sub(x)) >> 127) as u64; // 1 when x > half
                let mask = 0u128.wrapping_sub(over as u128);
                (x as i128).wrapping_sub((big_q & mask) as i128)
            })
            .collect();
        a.iter_mut().for_each(|v| v.zeroize());
        Ok(out)
    }

    /// Test support: a level-`level` ciphertext of the integer plaintext `m`
    /// (centered coefficients, |m| < Q_L/2) under this generator's secret,
    /// c1 uniform from `rand`, c0 = NTT(m + e) − c1·s with e from the
    /// Gaussian CDT; limb-major NTT-domain words, as `decrypt_level` reads.
    #[cfg(feature = "test-support")]
    pub fn encrypt_for_test(&self, level: usize, m: &[i128], rand: &[u8; 32]) -> Result<(Vec<u64>, Vec<u64>), ()> {
        let ps = self.ps;
        let n = ps.n();
        if m.len() != n || level >= ps.residual_q.len() {
            return Err(());
        }
        let e = gaussian(&mut Stream::new(rand), n);
        let (mut c0, mut c1) = (Vec::with_capacity((level + 1) * n), Vec::with_capacity((level + 1) * n));
        for j in 0..=level {
            let (q, g) = ps.pk_limb(j).ok_or(())?;
            let md = Modulus::new(q, g, n);
            let a = uniform_a(rand, &[0xEE; 17], 0, j as u32, q, n);
            let s = md.ntt_mform_of(&self.s);
            let qi = q as i128;
            let mut p: Vec<u64> = (0..n).map(|i| (((m[i] + e[i] as i128) % qi + qi) % qi) as u64).collect();
            md.ntt(&mut p);
            for i in 0..n {
                p[i] = md.sub(p[i], mred(a[i], s[i], q, md.qinv));
            }
            c0.extend_from_slice(&p);
            c1.extend_from_slice(&a);
        }
        Ok((c0, c1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    fn hexs(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Known answers from the pqctoday-fhe oracle (Lattigo-based reference spec)
    /// for the INSECURE test ring and the seed 00..1f: every key, the public key
    /// and the public a-seed must match byte for byte.
    #[test]
    fn kat_matches_reference_spec_test_ring() {
        let kat: serde_json::Value = serde_json::from_str(include_str!("../../../kat/fhe-ckks-kat-32770.json")).unwrap();
        let ps = super::super::params::find(0x8002).unwrap();
        let seed: [u8; 32] = core::array::from_fn(|i| i as u8);
        let g = Generator::new(ps, &seed);
        assert_eq!(hexs(&g.a_seed), kat["aSeed"].as_str().unwrap());
        assert_eq!(hexs(&sha2::Sha256::digest(g.pk_chunk(0, ps.pk_limbs()).unwrap())), kat["pkSha256"].as_str().unwrap());
        let want = kat["keySha256"].as_array().unwrap();
        assert_eq!(want.len(), ps.keys.len());
        for (k, key) in ps.keys.iter().enumerate() {
            let mut h = sha2::Sha256::new();
            for d in 0..key.dnum() {
                h.update(g.chunk(k as u32, d as u32, 0, key.limbs()).unwrap());
            }
            assert_eq!(hexs(&h.finalize()), want[k].as_str().unwrap(), "key {k}");
        }
    }

    fn kat_2() -> serde_json::Value {
        serde_json::from_str(include_str!("../../../kat/fhe-ckks-kat-2.json")).unwrap()
    }

    fn key_hash(g: &Generator, k: usize) -> String {
        let key = &g.ps.keys[k];
        let mut h = sha2::Sha256::new();
        for d in 0..key.dnum() {
            h.update(g.chunk(k as u32, d as u32, 0, key.limbs()).unwrap());
        }
        hexs(&h.finalize())
    }

    /// Registry ID 2 against the oracle KAT (gate V, E1′; seed 00..1f):
    /// registry entry, a-seed, public key, the first words of key 0 and the
    /// one-limb dense-to-sparse key. The full key list is
    /// `kat_registry_2_all_keys` (ignored by default: GBs of chunks).
    #[test]
    fn kat_registry_2_matches_reference_spec() {
        let kat = kat_2();
        let ps = super::super::params::find(2).unwrap();
        assert_eq!(ps.name, kat["name"].as_str().unwrap());
        assert_eq!(hexs(&param_hash(ps)), kat["paramHash"].as_str().unwrap());
        assert_eq!(ps.keys.len() as u64, kat["keyCount"].as_u64().unwrap());
        let g = Generator::new(ps, &core::array::from_fn(|i| i as u8));
        assert_eq!(hexs(&g.a_seed), kat["aSeed"].as_str().unwrap());
        assert_eq!(g.s.iter().filter(|&&v| v != 0).count() as u64, kat["secretWeight"].as_u64().unwrap());
        assert_eq!(hexs(&sha2::Sha256::digest(g.pk_chunk(0, ps.pk_limbs()).unwrap())), kat["pkSha256"].as_str().unwrap());
        let first = g.chunk(0, 0, 0, 1).unwrap();
        let words: Vec<u64> = (0..4).map(|i| u64::from_le_bytes(first[8 * i..8 * i + 8].try_into().unwrap())).collect();
        let want: Vec<u64> = kat["firstChunkFirstWords"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap()).collect();
        assert_eq!(words, want);
        let hashes = kat["keySha256"].as_array().unwrap();
        let k = ps.keys.iter().position(|k| k.kind == KIND_DENSE_TO_SPARSE).unwrap();
        assert_eq!(key_hash(&g, k), hashes[k].as_str().unwrap(), "key {k}");
    }

    #[test]
    #[ignore = "GBs of chunks; run with --ignored in a release build"]
    fn kat_registry_2_all_keys() {
        let kat = kat_2();
        let ps = super::super::params::find(2).unwrap();
        let g = Generator::new(ps, &core::array::from_fn(|i| i as u8));
        let hashes = kat["keySha256"].as_array().unwrap();
        for k in 0..ps.keys.len() {
            assert_eq!(key_hash(&g, k), hashes[k].as_str().unwrap(), "key {k}");
        }
    }

    /// Rotation key (E10) known answers from the pqctoday-fhe rotation check
    /// (`reference-runs/ckks-rotation-check`, command `kat`): old seed 00..1f,
    /// new seed 20..3f, descriptor hashes 40..5f and 60..7f, test ring.
    #[test]
    fn rotation_kat_matches_reference_spec_test_ring() {
        let kat: serde_json::Value = serde_json::from_str(include_str!("../../../kat/fhe-ckks-rotation-kat-32770.json")).unwrap();
        let ps = super::super::params::find(0x8002).unwrap();
        let old = Generator::new(ps, &core::array::from_fn(|i| i as u8));
        let new = Generator::new(ps, &core::array::from_fn(|i| 0x20 + i as u8));
        let mut ctx = RotationCtx { old_descriptor_hash: core::array::from_fn(|i| 0x40 + i as u8), new_descriptor_hash: core::array::from_fn(|i| 0x60 + i as u8), a_seed: [0; 32] };
        ctx.a_seed = new.rotation_a_seed(&ctx);
        assert_eq!(hexs(&ctx.a_seed), kat["aSeed"].as_str().unwrap());
        let k = ps.rotation_desc();
        assert_eq!(k.dnum() as u64, kat["digits"].as_u64().unwrap());
        assert_eq!(k.limbs() as u64, kat["limbs"].as_u64().unwrap());
        let mut h = sha2::Sha256::new();
        for d in 0..k.dnum() {
            let all = new.rotation_chunk(&old, &ctx, d as u32, 0, k.limbs()).unwrap();
            // Limb ranges compose.
            let parts: Vec<u8> = (0..k.limbs()).flat_map(|j| new.rotation_chunk(&old, &ctx, d as u32, j, j + 1).unwrap()).collect();
            assert_eq!(all, parts);
            h.update(&all);
        }
        assert_eq!(hexs(&h.finalize()), kat["keySha256"].as_str().unwrap());
        // Direction matters: the key from new to old is a different key.
        assert_ne!(old.rotation_chunk(&new, &ctx, 0, 0, 1).unwrap(), new.rotation_chunk(&old, &ctx, 0, 0, 1).unwrap());
        // Bounds.
        assert!(new.rotation_chunk(&old, &ctx, k.dnum() as u32, 0, 1).is_err() && new.rotation_chunk(&old, &ctx, 0, 0, k.limbs() + 1).is_err());
        let other = Generator::new(super::super::params::find(2).unwrap(), &[1; 32]);
        assert!(new.rotation_chunk(&other, &ctx, 0, 0, 1).is_err(), "parameter sets differ");
    }

    /// Determinism (S2): limb ranges compose, and a repeat gives identical bytes.
    #[test]
    fn chunks_compose_and_repeat() {
        let ps = super::super::params::find(0x8002).unwrap();
        let seed = [7u8; 32];
        let g = Generator::new(ps, &seed);
        let k = ps.keys[1];
        let all = g.chunk(1, 2, 0, k.limbs()).unwrap();
        let mut parts = Vec::new();
        for j in 0..k.limbs() {
            parts.extend(Generator::new(ps, &seed).chunk(1, 2, j, j + 1).unwrap());
        }
        assert_eq!(all, parts);
        assert!(g.chunk(99, 0, 0, 1).is_err() && g.chunk(1, 99, 0, 1).is_err() && g.chunk(1, 0, 0, 99).is_err());
    }
}

#[cfg(test)]
mod profile {
    use super::*;
    use std::time::Instant;

    /// Per-call fixed cost at N = 2^16 (plan §8.2, A9): where does it go?
    #[test]
    #[ignore]
    fn profile_per_call_cost() {
        let ps = super::super::params::find(2).unwrap();
        let seed = [7u8; 32];
        let t = Instant::now();
        let g = Generator::new(ps, &seed);
        let g_new = t.elapsed();
        let k = ps.keys[1];
        let t = Instant::now();
        let e = g.error_poly(&k, Some(0));
        let err = t.elapsed();
        let t = Instant::now();
        let n = ps.n();
        let mut st = Stream::new(&[1u8; 32]);
        let tern = ternary(&mut st, n, ps.h);
        let tern_t = t.elapsed();
        let t = Instant::now();
        let one = g.chunk(1, 0, 0, 1).unwrap();
        let chunk1 = t.elapsed();
        let t = Instant::now();
        let eight = g.chunk(1, 0, 0, 8).unwrap();
        let chunk8 = t.elapsed();
        eprintln!("Generator::new {g_new:?} (ternary alone {tern_t:?}); error_poly {err:?}; chunk(1 limb) {chunk1:?}; chunk(8 limbs) {chunk8:?}; {} {} {}", e.len(), tern.len(), one.len() + eight.len());
        // Per-limb parts (A7): NTT of the secret, NTT of the error, a-expansion, pointwise work.
        let (q, gr) = ps.key_limb(&k, 0).unwrap();
        let t = Instant::now();
        let m = Modulus::new(q, gr, n);
        let tables = t.elapsed();
        let t = Instant::now();
        let sn = m.ntt_mform_of(&g.s);
        let ntt_s = t.elapsed();
        let t = Instant::now();
        let en = m.ntt_mform_of(&e);
        let ntt_e = t.elapsed();
        let t = Instant::now();
        let a = uniform_a(&g.a_seed, &key_id(&k), 0, 0, q, n);
        let a_t = t.elapsed();
        let t = Instant::now();
        let mut acc = 0u64;
        for i in 0..n {
            acc ^= m.sub(en[i], mred(a[i], sn[i], q, m.qinv));
        }
        let pw = t.elapsed();
        eprintln!("per limb: Modulus::new (tables) {tables:?}; NTT(s) {ntt_s:?}; NTT(e) {ntt_e:?}; uniform_a {a_t:?}; pointwise {pw:?} ({acc})");
    }
}
