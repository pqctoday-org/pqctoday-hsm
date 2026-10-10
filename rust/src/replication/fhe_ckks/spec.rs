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

fn lp(fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for f in fields {
        out.extend_from_slice(&(f.len() as u32).to_be_bytes());
        out.extend_from_slice(f);
    }
    out
}

/// AES-256-CTR keystream, 128-bit big-endian counter from zero (Go `cipher.NewCTR`).
pub struct Stream {
    cipher: aes::Aes256,
    ctr: u128,
    buf: [u8; 16],
    pos: usize,
}

impl Stream {
    pub fn new(key: &[u8; 32]) -> Self {
        Stream { cipher: aes::Aes256::new_from_slice(key).expect("32-byte key"), ctr: 0, buf: [0; 16], pos: 16 }
    }
    fn byte(&mut self) -> u8 {
        if self.pos == 16 {
            let mut b = Block::<aes::Aes256>::from(self.ctr.to_be_bytes());
            self.cipher.encrypt_block(&mut b);
            self.buf.copy_from_slice(&b);
            self.ctr = self.ctr.wrapping_add(1);
            self.pos = 0;
        }
        let v = self.buf[self.pos];
        self.pos += 1;
        v
    }
    pub fn u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        b.iter_mut().for_each(|x| *x = self.byte());
        u64::from_le_bytes(b)
    }
    pub fn u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        b.iter_mut().for_each(|x| *x = self.byte());
        u32::from_le_bytes(b)
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
    m.update(b"pqctoday-fhe/ckks/a/v1");
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

/// The secrets and public seed regenerated from one FHE seed. Zeroized on drop.
pub struct Generator {
    pub ps: &'static CkksParamSet,
    seed: [u8; 32],
    s: Vec<i64>,
    ss: Vec<i64>,
    pub a_seed: [u8; 32],
    param_hash: [u8; 32],
}

impl Drop for Generator {
    fn drop(&mut self) {
        self.seed.zeroize();
        self.s.zeroize();
        self.ss.zeroize();
    }
}

impl Generator {
    pub fn new(ps: &'static CkksParamSet, seed: &[u8; 32]) -> Self {
        let mut g = Generator { ps, seed: *seed, s: Vec::new(), ss: Vec::new(), a_seed: [0; 32], param_hash: param_hash(ps) };
        let n = ps.n();
        let mut k = g.kdf32("secret", &[]);
        g.s = ternary(&mut Stream::new(&k), n, ps.h);
        k.zeroize();
        if ps.ephemeral_h != 0 {
            let mut k = g.kdf32("sparse-secret", &[]);
            g.ss = ternary(&mut Stream::new(&k), n, ps.ephemeral_h);
            k.zeroize();
        }
        g.a_seed = g.kdf32("a-seed", &[]);
        g
    }

    fn kdf32(&self, label: &str, extra: &[&[u8]]) -> [u8; 32] {
        let mut ctx = lp(&[b"CKKS", self.ps.name.as_bytes(), &self.param_hash, b"v1"]);
        ctx.extend_from_slice(&lp(extra));
        let mut m = <Hmac<sha2::Sha384> as Mac>::new_from_slice(&self.seed).expect("any key length");
        m.update(&1u32.to_be_bytes());
        m.update(b"pqctoday-fhe/ckks/");
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
            None => self.kdf32("pk-error", &[&id]),
            Some(d) => self.kdf32("error", &[&id, &d.to_be_bytes()]),
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
        let mut e = self.error_poly(&k, Some(d));
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
        let mut out = Vec::with_capacity((to - from) * n * 8);
        for j in from..to {
            let (q, g) = ps.key_limb(&k, j).ok_or(())?;
            let m = Modulus::new(q, g, n);
            let mut s_main = m.ntt_mform_of(&self.s);
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
            for v in &b {
                out.extend_from_slice(&v.to_le_bytes());
            }
        }
        e.zeroize();
        Ok(out)
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

    /// m = c0 + c1·s mod q0 for a level-0 ciphertext in the NTT domain
    /// (standard form), returned as centered integer coefficients.
    pub fn decrypt_q0(&self, c0: &[u64], c1: &[u64]) -> Result<Vec<i64>, ()> {
        let ps = self.ps;
        let n = ps.n();
        if c0.len() != n || c1.len() != n {
            return Err(());
        }
        let (q, g) = ps.pk_limb(0).ok_or(())?;
        if c0.iter().chain(c1).any(|&v| v >= q) {
            return Err(());
        }
        let m = Modulus::new(q, g, n);
        let mut s = m.ntt_mform_of(&self.s);
        let mut p: Vec<u64> = (0..n).map(|i| m.add(c0[i], mred(c1[i], s[i], q, m.qinv))).collect();
        s.zeroize();
        m.intt(&mut p);
        let half = q / 2;
        let out = p.iter().map(|&v| if v > half { -((q - v) as i64) } else { v as i64 }).collect();
        p.zeroize();
        Ok(out)
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
