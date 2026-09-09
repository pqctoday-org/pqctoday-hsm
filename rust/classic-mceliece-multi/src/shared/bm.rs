//! Berlekamp-Massey algorithm (<http://crypto.stanford.edu/~mironov/cs359/massey.pdf>).
//! Adapted from upstream `classic-mceliece-rust` 3.1.0 `src/bm.rs`, slice-based with
//! narrow/wide variants and a caller-supplied `SYS_T+1`-length scratch buffer pair
//! (`c`/`b` in upstream's fixed-array version) — the internal `[0u16; SYS_T+1]`
//! locals cannot be sized by a bare `SYS_T` const generic on stable Rust (same
//! restriction `shared/controlbits.rs`'s module doc explains). The one remaining
//! fixed-size local (`t`, upstream's per-iteration snapshot of `c` before mutation)
//! uses a `[Gf; MAX_SYS_T_PLUS_1]` sized to the largest SYS_T across all 10 variants
//! (128, i.e. 129) rather than a heap allocation — SYS_T never exceeds that bound in
//! this fork, and only the first `sys_t+1` elements are ever read.

use super::gf::{gf_frac_narrow, gf_frac_wide, gf_mul_narrow, gf_mul_wide, Gf};

/// One more than the largest `SYS_T` among all 10 parameter sets (348864:64,
/// 460896:96, 6688128/8192128:128, 6960119:119) — sizes the `t`-snapshot scratch.
const MAX_SYS_T_PLUS_1: usize = 129;

fn min(a: usize, b: usize) -> usize {
    let c = (a < b) as isize;
    let d = c << (isize::BITS - 1);
    let e = (d >> (isize::BITS - 1)) as usize;
    (a & e) | (b & !e)
}

/// The Berlekamp-Massey algorithm — narrow family. `out.len() == SYS_T+1`,
/// `s.len() == 2*SYS_T`, `c_scratch.len() == b_scratch.len() == SYS_T+1`.
pub(crate) fn bm_narrow(out: &mut [Gf], s: &mut [Gf], c_scratch: &mut [Gf], b_scratch: &mut [Gf]) {
    let sys_t = out.len() - 1;
    debug_assert_eq!(s.len(), 2 * sys_t);
    debug_assert_eq!(c_scratch.len(), sys_t + 1);
    debug_assert_eq!(b_scratch.len(), sys_t + 1);
    debug_assert!(sys_t + 1 <= MAX_SYS_T_PLUS_1);

    let mut l: u16 = 0;
    let mut mle: u16;
    let mut mne: u16;
    let mut t = [0u16; MAX_SYS_T_PLUS_1];

    let c = c_scratch;
    let b = b_scratch;
    c.fill(0);
    b.fill(0);

    let mut base: Gf = 1;

    b[1] = 1;
    c[0] = 1;

    for n in 0..(2 * sys_t) {
        let mut d: Gf = 0;
        for i in 0..=min(n, sys_t) {
            d ^= gf_mul_narrow(c[i], s[n - i], 12, 0x0FFF);
        }
        mne = d;
        mne = mne.wrapping_sub(1);
        mne >>= 15;
        mne = mne.wrapping_sub(1);

        mle = n as u16;
        mle = mle.wrapping_sub(l.wrapping_mul(2));
        mle >>= 15;
        mle = mle.wrapping_sub(1);
        mle &= mne;

        t[..=sys_t].copy_from_slice(&c[..=sys_t]);

        let f: Gf = gf_frac_narrow(base, d, 12, 0x0FFF);

        for i in 0..=sys_t {
            c[i] ^= gf_mul_narrow(f, b[i], 12, 0x0FFF) & mne;
        }

        l = (l & !mle) | ((n as u16 + 1 - l) & mle);

        for i in 0..=sys_t {
            b[i] = (b[i] & !mle) | (t[i] & mle);
        }

        base = (base & !mle) | (d & mle);

        for i in (1..=sys_t).rev() {
            b[i] = b[i - 1];
        }
        b[0] = 0;
    }

    for i in 0..=sys_t {
        out[i] = c[sys_t - i];
    }
}

/// The Berlekamp-Massey algorithm — wide family. Same shapes as [`bm_narrow`].
pub(crate) fn bm_wide(out: &mut [Gf], s: &mut [Gf], c_scratch: &mut [Gf], b_scratch: &mut [Gf]) {
    let sys_t = out.len() - 1;
    debug_assert_eq!(s.len(), 2 * sys_t);
    debug_assert_eq!(c_scratch.len(), sys_t + 1);
    debug_assert_eq!(b_scratch.len(), sys_t + 1);
    debug_assert!(sys_t + 1 <= MAX_SYS_T_PLUS_1);

    let mut l: u16 = 0;
    let mut mle: u16;
    let mut mne: u16;
    let mut t = [0u16; MAX_SYS_T_PLUS_1];

    let c = c_scratch;
    let b = b_scratch;
    c.fill(0);
    b.fill(0);

    let mut base: Gf = 1;

    b[1] = 1;
    c[0] = 1;

    for n in 0..(2 * sys_t) {
        let mut d: Gf = 0;
        for i in 0..=min(n, sys_t) {
            d ^= gf_mul_wide(c[i], s[n - i], 13, 0x1FFF);
        }
        mne = d;
        mne = mne.wrapping_sub(1);
        mne >>= 15;
        mne = mne.wrapping_sub(1);

        mle = n as u16;
        mle = mle.wrapping_sub(l.wrapping_mul(2));
        mle >>= 15;
        mle = mle.wrapping_sub(1);
        mle &= mne;

        t[..=sys_t].copy_from_slice(&c[..=sys_t]);

        let f: Gf = gf_frac_wide(base, d, 0x1FFF);

        for i in 0..=sys_t {
            c[i] ^= gf_mul_wide(f, b[i], 13, 0x1FFF) & mne;
        }

        l = (l & !mle) | ((n as u16 + 1 - l) & mle);

        for i in 0..=sys_t {
            b[i] = (b[i] & !mle) | (t[i] & mle);
        }

        base = (base & !mle) | (d & mle);

        for i in (1..=sys_t).rev() {
            b[i] = b[i - 1];
        }
        b[0] = 0;
    }

    for i in 0..=sys_t {
        out[i] = c[sys_t - i];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bm_narrow_smoke() {
        // Not a KAT (that lives in each size-family module against the official
        // vectors) — a cheap structural check that bm runs to completion on a
        // plausible SYS_T=64 input without panicking.
        const SYS_T: usize = 64;
        let mut locator = [0u16; SYS_T + 1];
        let mut s = [0u16; SYS_T * 2];
        for (i, v) in s.iter_mut().enumerate() {
            *v = i as u16;
        }
        let mut c_scratch = [0u16; SYS_T + 1];
        let mut b_scratch = [0u16; SYS_T + 1];
        bm_narrow(&mut locator, &mut s, &mut c_scratch, &mut b_scratch);
    }

    #[test]
    fn test_bm_wide_smoke() {
        const SYS_T: usize = 128;
        let mut locator = [0u16; SYS_T + 1];
        let mut s = [0u16; SYS_T * 2];
        for (i, v) in s.iter_mut().enumerate() {
            *v = i as u16;
        }
        let mut c_scratch = [0u16; SYS_T + 1];
        let mut b_scratch = [0u16; SYS_T + 1];
        bm_wide(&mut locator, &mut s, &mut c_scratch, &mut b_scratch);
    }
}
