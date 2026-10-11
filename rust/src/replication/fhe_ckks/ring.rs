//! 64-bit RNS arithmetic for the streamed CKKS generator (plan §5.2): Montgomery
//! reduction with R = 2^64, and the negacyclic NTT of the pinned Lattigo v6.2.0
//! (`ring/ntt.go`: Cooley–Tukey, bit-reversed Montgomery twiddles from the
//! smallest primitive root), so that every output value is byte-identical to
//! Lattigo's. Primes must satisfy q ≡ 1 (mod 2N) and 6q ≤ 2^64 (the lazy
//! butterflies hold values up to 6q; Codex #9).
//!
//! Variable × variable products use Montgomery reduction (owner decision
//! 2026-10-10). This is the portable scalar layer (ladder step A1); faster
//! kernels must reproduce it bit for bit (test S8).

/// One RNS modulus with its NTT tables.
pub struct Modulus {
    pub q: u64,
    /// q^-1 mod 2^64 (Lattigo `GenMRedConstant`).
    pub qinv: u64,
    /// Forward twiddles ψ^k in Montgomery form, bit-reversed order (length N).
    roots_fwd: Vec<u64>,
    /// Backward twiddles ψ^-k in Montgomery form, bit-reversed order.
    roots_bwd: Vec<u64>,
    /// N^-1 in Montgomery form.
    n_inv: u64,
    /// 2^128 mod q: mred(x, r2) = MForm(x) without a division.
    r2: u64,
    pub n: usize,
}

#[inline(always)]
fn mul_wide(a: u64, b: u64) -> (u64, u64) {
    let p = (a as u128) * (b as u128);
    ((p >> 64) as u64, p as u64)
}

/// x·y·2^-64 mod q, fully reduced (Lattigo `MRed`).
#[inline(always)]
pub fn mred(x: u64, y: u64, q: u64, qinv: u64) -> u64 {
    let (hi, lo) = mul_wide(x, y);
    let (h, _) = mul_wide(lo.wrapping_mul(qinv), q);
    let r = hi.wrapping_sub(h).wrapping_add(q);
    // Branch-free conditional subtraction.
    let m = ((r >= q) as u64).wrapping_neg();
    r - (q & m)
}

/// x·y·2^-64 mod q in [0, 2q) (Lattigo `MRedLazy`).
#[inline(always)]
pub fn mred_lazy(x: u64, y: u64, q: u64, qinv: u64) -> u64 {
    let (hi, lo) = mul_wide(x, y);
    let (h, _) = mul_wide(lo.wrapping_mul(qinv), q);
    hi.wrapping_sub(h).wrapping_add(q)
}

/// a·2^64 mod q (Montgomery form).
#[inline]
pub fn mform(a: u64, q: u64) -> u64 {
    ((((a % q) as u128) << 64) % (q as u128)) as u64
}

#[inline(always)]
fn csub(r: u64, q: u64) -> u64 {
    let m = ((r >= q) as u64).wrapping_neg();
    r - (q & m)
}

pub fn pow_mod(mut b: u64, mut e: u64, q: u64) -> u64 {
    let mut r: u64 = 1;
    b %= q;
    while e > 0 {
        if e & 1 == 1 {
            r = ((r as u128 * b as u128) % q as u128) as u64;
        }
        b = ((b as u128 * b as u128) % q as u128) as u64;
        e >>= 1;
    }
    r
}

fn bit_reverse(x: u64, bits: u32) -> u64 {
    if bits == 0 {
        0
    } else {
        x.reverse_bits() >> (64 - bits)
    }
}

impl Modulus {
    /// Tables for ring degree `n` (a power of two) and the registry's primitive root `g`.
    pub fn new(q: u64, g: u64, n: usize) -> Self {
        assert!(n.is_power_of_two() && q <= u64::MAX / 6 && q % (2 * n as u64) == 1);
        let nth_root = 2 * n as u64;
        let mut qinv: u64 = 1;
        let mut qq = q;
        for _ in 0..63 {
            qinv = qinv.wrapping_mul(qq);
            qq = qq.wrapping_mul(qq);
        }
        let log_n = n.trailing_zeros();
        let n_inv = mform(pow_mod(n as u64, q - 2, q), q);
        let psi = mform(pow_mod(g, (q - 1) / nth_root, q), q);
        let psi_inv = mform(pow_mod(g, q - ((q - 1) / nth_root) - 1, q), q);
        let mut roots_fwd = vec![0u64; n];
        let mut roots_bwd = vec![0u64; n];
        roots_fwd[0] = mform(1, q);
        roots_bwd[0] = mform(1, q);
        for j in 1..n as u64 {
            let prev = bit_reverse(j - 1, log_n) as usize;
            let next = bit_reverse(j, log_n) as usize;
            roots_fwd[next] = mred(roots_fwd[prev], psi, q, qinv);
            roots_bwd[next] = mred(roots_bwd[prev], psi_inv, q, qinv);
        }
        let r2 = ((1u128 << 64) % q as u128 * ((1u128 << 64) % q as u128) % q as u128) as u64;
        Modulus { q, qinv, roots_fwd, roots_bwd, n_inv, r2, n }
    }

    /// In-place forward NTT; input in [0, q), output fully reduced in [0, q).
    pub fn ntt(&self, p: &mut [u64]) {
        let (q, qinv, n) = (self.q, self.qinv, self.n);
        let two_q = 2 * q;
        let four_q = 4 * q;
        let mut t = n >> 1;
        let mut m = 1;
        while m < n {
            for i in 0..m {
                let j1 = (i * t) << 1;
                let f = self.roots_fwd[m + i];
                for jx in j1..j1 + t {
                    let jy = jx + t;
                    let u = csub(p[jx], four_q);
                    let v = mred_lazy(p[jy], f, q, qinv);
                    p[jx] = u + v;
                    p[jy] = u + two_q - v;
                }
            }
            m <<= 1;
            t >>= 1;
        }
        // Values are in [0, 6q): reduce without a division.
        for x in p.iter_mut() {
            *x = csub(csub(csub(*x, four_q), two_q), q);
        }
    }

    /// In-place inverse NTT; input and output in [0, q).
    pub fn intt(&self, p: &mut [u64]) {
        let (q, qinv, n) = (self.q, self.qinv, self.n);
        let two_q = q << 1;
        let four_q = q << 2;
        let mut t = 1;
        let mut m = n;
        while m > 1 {
            let h = m >> 1;
            let mut j1 = 0;
            for i in 0..h {
                let f = self.roots_bwd[h + i];
                for jx in j1..j1 + t {
                    let jy = jx + t;
                    let (u, v) = (p[jx], p[jy]);
                    let x = csub(u + v, two_q);
                    p[jx] = x;
                    p[jy] = mred_lazy(u + four_q - v, f, q, qinv);
                }
                j1 += 2 * t;
            }
            t <<= 1;
            m >>= 1;
        }
        // Values are in [0, 2q).
        for x in p.iter_mut() {
            *x = mred(csub(*x, q), self.n_inv, q, qinv);
        }
    }

    /// Integer polynomial with |x| < q (secrets and errors) → MForm(NTT(x mod q)),
    /// branch-free and without a division.
    pub fn ntt_mform_of(&self, x: &[i64]) -> Vec<u64> {
        let q = self.q;
        let mut p: Vec<u64> = x
            .iter()
            .map(|&v| {
                debug_assert!(v.unsigned_abs() < q);
                let neg = ((v >> 63) as u64) & q;
                csub((v as u64).wrapping_add(neg), q)
            })
            .collect();
        self.ntt(&mut p);
        for v in p.iter_mut() {
            *v = mred(*v, self.r2, q, self.qinv);
        }
        p
    }

    #[inline(always)]
    pub fn sub(&self, a: u64, b: u64) -> u64 {
        csub(a + self.q - b, self.q)
    }

    #[inline(always)]
    pub fn add(&self, a: u64, b: u64) -> u64 {
        csub(a + b, self.q)
    }
}

/// Lattigo `AutomorphismNTTIndex(N, 2N, galEl)`.
pub fn automorphism_ntt_index(n: usize, gal_el: u64) -> Vec<usize> {
    let nth_root = 2 * n as u64;
    // Lattigo: bits.Len64(NthRoot-1) - 1, i.e. log2(N).
    let log_nth = 64 - (nth_root - 1).leading_zeros() - 1;
    let mask = nth_root - 1;
    (0..n as u64)
        .map(|i| {
            let tmp1 = 2 * bit_reverse(i, log_nth) + 1;
            let tmp2 = ((gal_el.wrapping_mul(tmp1) & mask) - 1) >> 1;
            bit_reverse(tmp2, log_nth) as usize
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntt_round_trip_and_negacyclic_product() {
        let q = 0xfffffffffffc001u64; // 2^60-class prime ≡ 1 mod 2^11 (test ring)
        let m = Modulus::new(q, 0xa, 1024);
        let a: Vec<u64> = (0..1024u64).map(|i| (i * 7919 + 13) % q).collect();
        let mut p = a.clone();
        m.ntt(&mut p);
        m.intt(&mut p);
        assert_eq!(p, a);
        // X * X^(N-1) = X^N = -1 in the negacyclic ring.
        let mut x = vec![0u64; 1024];
        x[1] = 1;
        let mut y = vec![0u64; 1024];
        y[1023] = 1;
        m.ntt(&mut x);
        m.ntt(&mut y);
        let mut z: Vec<u64> = x.iter().zip(&y).map(|(a, b)| mred(*a, mform(*b, q), q, m.qinv)).collect();
        m.intt(&mut z);
        assert_eq!(z[0], q - 1);
        assert!(z[1..].iter().all(|&v| v == 0));
    }
}
