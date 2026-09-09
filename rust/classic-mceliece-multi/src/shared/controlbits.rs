//! Nassimi-Sahni control-bits computation for a Beneš network.
//!
//! [^ns]: David Nassimi, Sartaj Sahni "Parallel algorithms to set up the Benes
//!        permutation network"
//! [^cb]: Daniel J. Bernstein "Verified fast formulas for control bits for
//!        permutation networks" <https://cr.yp.to/papers/controlbits-20200923.pdf>
//!
//! Copied from upstream `classic-mceliece-rust` 3.1.0 `src/controlbits.rs`. Upstream's
//! `controlbitsfrompermutation` allocates two `GFBITS`-sized local arrays
//! (`[i32; 2*(1<<GFBITS)]`, `[i32; 1<<(GFBITS-1)]`) itself; a bare const-generic
//! `GFBITS` parameter on this function CANNOT size those arrays on stable Rust —
//! confirmed directly (`rustc`: "generic parameters may not be used in const
//! operations") for expressions like `2*(1<<GFBITS)`, not just for the `P::CONST`
//! case P0-1 already found. The fix used here: the two buffers become caller-supplied
//! slices instead of function-internal fixed arrays, so this file has **zero**
//! parameter dependency at all and is truly shared across all 10 variants (unlike
//! upstream's per-feature-build copy, this is the only copy in the whole fork). Each
//! of the 5 size-family modules allocates the two buffers at its own call site, where
//! `GFBITS` (12 or 13) is a concrete literal and the expression compiles trivially.

use super::int32_sort::int32_sort;

/// Layer implements one layer of the Beneš network.
///
/// It permutes elements `p` according to control bits `cb` in-place.
/// Thus, one layer of the Beneš network is created and if some control bits are set
/// the corresponding transposition is applied. Parameter `s` equals `n.len()` and
/// `s` configures `stride-2^s` conditional swaps.
///
/// The following requirement is undocumented in C:
///   `assert!(1 << (s + 1) <= n);`
fn layer(p: &mut [i16], cb: &[u8], s: i32, n: i32) {
    debug_assert_eq!(p.len(), n as usize);
    debug_assert!(1 << (s + 1) <= n);

    let stride = 1 << s;
    let mut index = 0;

    for i in (0..n as usize).step_by(stride * 2) {
        for j in 0..stride {
            let mut d = p[i + j] ^ p[i + j + stride];
            let mut m = ((cb[index >> 3] >> (index & 7)) & 1) as i16;
            m = -m;
            d &= m;
            p[i + j] ^= d;
            p[i + j + stride] ^= d;
            index += 1;
        }
    }
}

/// `cbrecursion` implements a recursion step of `controlbitsfrompermutation`.
///
/// Pick `w ∈ {1, 2, …, 14}. Let `n = 2^w`.
/// `out` must be a reference to a slice with `((2*w-1)*(1<<(w-1))+7)/8` or more bytes.
/// It must zero-initialized before the first recursive call.
/// `step` is initialized with 0 and doubles in each recursion step.
/// `pi_offset` is an offset within temp slice ref (or aux in the first recursive call).
/// `temp` is an intermediate reference to a slice used for recursive computation and
/// temporarily stores values. It must be able to carry at least 2・n elements.
/// `aux` is an auxiliary reference to a slice. It points to the elements to be permuted.
/// After the first recursive iterations, the elements are stored in `temp` and thus `aux`
/// won't be read anymore. The first `n/2` elements are read.
#[allow(clippy::too_many_arguments)]
fn cbrecursion(
    out: &mut [u8],
    mut pos: usize,
    step: usize,
    pi_offset: usize,
    w: usize,
    n: usize,
    temp: &mut [i32],
    aux: &[i32],
) {
    debug_assert!(temp.len() >= 2 * n);
    debug_assert!(aux.len() >= n / 2);
    debug_assert!(pi_offset <= 3 * n);

    if w == 1 {
        let first = if pi_offset == 0 {
            aux[0]
        } else {
            temp[pi_offset]
        } as i16;
        out[pos >> 3] ^= (first << (pos & 7)) as u8;
        return;
    }

    for x in 0..n {
        let perm = if pi_offset == 0 {
            aux[pi_offset + x / 2]
        } else {
            temp[pi_offset + x / 2]
        };
        let low: i32 = perm & 0xffff;
        let high: i32 = perm >> 16;
        if x % 2 == 0 {
            temp[x] = ((low ^ 1) << 16) | (high & 0xffff);
        } else {
            temp[x] = ((high ^ 1) << 16) | (low & 0xffff);
        }
    }
    int32_sort(&mut temp[..n]); /* A = (id<<16)+pibar */

    for x in 0..n {
        let ax: i32 = temp[x];
        let px: i32 = ax & 0xffff;
        let mut cx: i32 = px;
        if (x as i32) < cx {
            cx = x as i32;
        }
        temp[n + x] = (px << 16) | cx;
    }
    /* B = (p<<16)+c */

    for (x, itr_temp) in temp.iter_mut().enumerate().take(n) {
        *itr_temp = (*itr_temp << 16) | (x as i32); /* A = (pibar<<16)+id */
    }
    int32_sort(&mut temp[0..n]); /* A = (id<<16)+pibar^-1 */

    for x in 0..n {
        temp[x] = (temp[x] << 16) + (temp[n + x] >> 16); /* A = (pibar^(-1)<<16)+pibar */
    }
    int32_sort(&mut temp[0..n]); /* A = (id<<16)+pibar^2 */

    if w <= 10 {
        for x in 0..n {
            temp[n + x] = ((temp[x] & 0xffff) << 10) | (temp[n + x] & 0x3ff);
        }

        for _ in 1..(w - 1) {
            /* B = (p<<10)+c */

            for x in 0..n {
                temp[x] = ((temp[n + x] & (0xfffffc << 8)) << 6) | (x as i32); /* A = (p<<16)+id */
            }
            int32_sort(&mut temp[0..n]); /* A = (id<<16)+p^{-1} */

            for x in 0..n {
                temp[x] = (temp[x] << 20) | temp[n + x]; /* A = (p^{-1}<<20)+(p<<10)+c */
            }
            int32_sort(&mut temp[0..n]); /* A = (id<<20)+(pp<<10)+cp */

            for x in 0..n {
                let ppcpx: i32 = temp[x] & 0xfffff;
                let mut ppcx: i32 = (temp[x] & 0xffc00) | (temp[n + x] & 0x3ff);
                if ppcpx < ppcx {
                    ppcx = ppcpx;
                }
                temp[n + x] = ppcx;
            }
        }
        for x in 0..n {
            temp[n + x] &= 0x3ff;
        }
    } else {
        for x in 0..n {
            temp[n + x] = (temp[x] << 16) | (temp[n + x] & 0xffff);
        }
        for i in 1..(w - 1) {
            /* B = (p<<16)+c */

            for x in 0..n {
                temp[x] = (temp[n + x] & (0xffff << 16)) | (x as i32);
            }
            int32_sort(&mut temp[0..n]); /* A = (id<<16)+p^(-1) */

            for x in 0..n {
                temp[x] = (temp[x] << 16) | (temp[n + x] & 0xffff);
            }
            /* A = p^(-1)<<16+c */

            if i < w - 2 {
                for x in 0..n {
                    temp[n + x] = (temp[x] & (0xffff << 16)) | (temp[n + x] >> 16);
                }
                /* B = (p^(-1)<<16)+p */
                int32_sort(&mut temp[n..2 * n]); /* B = (id<<16)+p^(-2) */
                for x in 0..n {
                    temp[n + x] = (temp[n + x] << 16) | (temp[x] & 0xffff);
                }
                /* B = (p^(-2)<<16)+c */
            }

            int32_sort(&mut temp[0..n]);
            /* A = id<<16+cp */
            for x in 0..n {
                let cpx: i32 = (temp[n + x] & (0xffff << 16)) | (temp[x] & 0xffff);
                if cpx < temp[n + x] {
                    temp[n + x] = cpx;
                }
            }
        }
        for x in 0..n {
            temp[n + x] &= 0xffff;
        }
    }

    for x in 0..n {
        let perm: i32 = if pi_offset == 0 {
            aux[pi_offset + x / 2]
        } else {
            temp[pi_offset + x / 2]
        };
        if x % 2 == 0 {
            temp[x] = ((perm & 0xffff) << 16) + (x as i32);
        } else {
            temp[x] = (perm & (0xffff << 16)) + (x as i32);
        }
    }
    int32_sort(&mut temp[0..n]); /* A = (id<<16)+pi^(-1) */

    for j in 0..(n / 2) {
        let x = 2 * j as i32;
        let fj: i32 = temp[n + (x as usize)] & 1; /* f[j] */
        let fx: i32 = x + fj; /* F[x] */
        let fx1: i32 = fx ^ 1; /* F[x+1] */

        out[pos >> 3] ^= (fj << (pos & 7)) as u8;
        pos += step;

        temp[n + x as usize] = (temp[x as usize] << 16) | fx;
        temp[n + x as usize + 1] = (temp[x as usize + 1] << 16) | fx1;
    }
    /* B = (pi^(-1)<<16)+F */

    int32_sort(&mut temp[n..2 * n]); /* B = (id<<16)+F(pi) */

    pos += (2 * w - 3) * step * (n / 2);

    for k in 0..(n / 2) {
        let y = 2 * k as i32;
        let lk: i32 = temp[n + y as usize] & 1; /* l[k] */
        let ly: i32 = y + lk; /* L[y] */
        let ly1: i32 = ly ^ 1; /* L[y+1] */

        out[pos >> 3] ^= (lk << (pos & 7)) as u8;
        pos += step;

        temp[y as usize] = (ly << 16) | (temp[n + y as usize] & 0xffff);
        temp[y as usize + 1] = (ly1 << 16) | (temp[n + y as usize + 1] & 0xffff);
    }
    /* A = (L<<16)+F(pi) */

    int32_sort(&mut temp[0..n]); /* A = (id<<16)+F(pi(L)) = (id<<16)+M */

    pos -= (2 * w - 2) * step * (n / 2);

    for j in 0..(n / 2) {
        if j % 2 == 0 {
            temp[n + n / 4..][j / 2] =
                (temp[n + n / 4..][j / 2] & (0xffff << 16)) | ((temp[2 * j] & 0xffff) >> 1);
            temp[n + n / 4..][(j + n / 2) / 2] = (temp[n + n / 4..][(j + n / 2) / 2]
                & (0xffff << 16))
                | ((temp[2 * j + 1] & 0xffff) >> 1);
        } else {
            temp[n + n / 4..][j / 2] =
                (temp[n + n / 4..][j / 2] & 0xffff) | ((temp[2 * j] & 0xfffe) << 15);
            temp[n + n / 4..][(j + n / 2) / 2] =
                (temp[n + n / 4..][(j + n / 2) / 2] & 0xffff) | ((temp[2 * j + 1] & 0xfffe) << 15);
        }
    }

    cbrecursion(out, pos, step * 2, n + n / 4, w - 1, n / 2, temp, aux);
    cbrecursion(
        out,
        pos + step,
        step * 2,
        n + n / 2,
        w - 1,
        n / 2,
        temp,
        aux,
    );
}

/// controlbitsfrompermutation computes control bits.
///
/// Pick `w` ∈ {1, 2, …, 14}. Let `n = 2^w`. `temp_buf` must have length `>= 2*n`,
/// `pi_as_i32_buf` length `>= n/2`, `pi_test_buf` length `>= n` — sized by the
/// caller (upstream sized these `[i32; 2*(1<<GFBITS)]` / `[i32; 1<<(GFBITS-1)]` /
/// `[i16; 1<<GFBITS]` internally; here the caller passes them in, see the module doc).
///
/// Let `pi` have `n` elements which is a permutation of integers 0, 1, …, n-1
/// (consider it as map from the index to the value at this index). The control
/// bits provide the configuration for a Beneš network in order to implement the
/// permutation specified by `pi`. The first control bit is the LSB of out[0].
#[allow(clippy::too_many_arguments)]
pub(crate) fn controlbitsfrompermutation(
    out: &mut [u8],
    pi: &[i16],
    w: usize,
    n: usize,
    temp_buf: &mut [i32],
    pi_as_i32_buf: &mut [i32],
    pi_test_buf: &mut [i16],
) {
    debug_assert_eq!(n, 1 << w);
    debug_assert_eq!(pi.len(), n);
    debug_assert_eq!(out.len(), ((2 * w - 1) * n / 2).div_ceil(8));
    debug_assert!(temp_buf.len() >= 2 * n);
    debug_assert!(pi_as_i32_buf.len() >= n / 2);
    debug_assert!(pi_test_buf.len() >= n);

    let temp = temp_buf;
    let mut diff: i16 = 0;

    // reinterpret pi as i32 array
    let pi_as_i32 = pi_as_i32_buf;
    for i in 0..(n / 2) {
        pi_as_i32[i] = pi[2 * i] as i32 | ((pi[2 * i + 1] as i32) << 16);
    }

    let mut sub = out;

    loop {
        sub.fill(0);
        cbrecursion(sub, 0, 1, 0, w, n, temp, pi_as_i32);

        let pi_test = &mut pi_test_buf[..n];
        for (i, itr_pi_test) in pi_test.iter_mut().enumerate() {
            *itr_pi_test = i as i16;
        }

        for i in 0..w {
            layer(pi_test, sub, i as i32, n as i32);
            sub = &mut sub[(n >> 4)..];
        }

        for i in (0..w - 1).rev() {
            layer(pi_test, sub, i as i32, n as i32);
            sub = &mut sub[(n >> 4)..];
        }

        for i in 0..n {
            diff |= pi[i] ^ pi_test[i];
        }

        if diff == 0 {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A simple testcase for layer(). Retrieved from the upstream crate's own test
    // (input/output mapping traces to the C reference implementation).
    #[test]
    fn test_layer_1() {
        const N: i32 = 4;
        const S: i32 = 1;
        let mut p = [0i16, 3, 7, 11];
        let cb = [63u8; 1];

        layer(&mut p, &cb, S, N);

        assert_eq!(p, [7i16, 11, 0, 3]);
    }

    #[test]
    fn test_layer_2() {
        const N: i32 = 8;
        const S: i32 = 2;
        let mut p = [0i16, 3, 7, 11, 13, 17, 23, 0];
        let cb = [0xAAu8, 0xFF, 0x02];

        layer(&mut p, &cb, S, N);

        assert_eq!(p, [0i16, 17, 7, 0, 13, 3, 23, 11]);
    }

    #[test]
    fn test_cbrecursion_1() {
        const W: usize = 3;
        const N: usize = 1 << W;

        let pi: [i16; N] = [0i16, 2, 4, 6, 1, 3, 5, 7];
        const STEP: usize = 1;
        const POS: usize = 0;

        let mut temp: [i32; 2 * N] = [0i32; 2 * 8];
        let mut out: [u8; 3] = [0u8; 3];

        let mut pi_as_i32: [i32; N / 2] = [0i32; N / 2];
        for i in 0..(N / 2) {
            pi_as_i32[i] = pi[2 * i] as i32 | ((pi[2 * i + 1] as i32) << 16);
        }

        cbrecursion(&mut out, POS, STEP, 0, W, N, &mut temp, &pi_as_i32);

        assert_eq!(out, [0xCAu8, 0x66, 0x0C]);
    }

    #[test]
    fn test_controlbitsfrompermutation_smoke() {
        // Not a KAT (those live in the per-variant modules' own tests against the
        // official vectors) — just proves the caller-supplied-buffer refactor still
        // round-trips a permutation for a small w, matching cbrecursion's own
        // correctness loop (the `diff == 0` convergence check inside the function).
        const W: usize = 4;
        const N: usize = 1 << W;
        let mut pi = [0i16; N];
        for (i, p) in pi.iter_mut().enumerate() {
            *p = ((i * 7 + 3) % N) as i16;
        }
        // ensure pi is actually a permutation of 0..N (7 and N=16 are coprime)
        let mut seen = [false; N];
        for &p in &pi {
            assert!(!seen[p as usize]);
            seen[p as usize] = true;
        }

        let mut out = [0u8; ((2 * W - 1) * N / 2).div_ceil(8)];
        let mut temp = [0i32; 2 * N];
        let mut pi_as_i32 = [0i32; N / 2];
        let mut pi_test = [0i16; N];

        controlbitsfrompermutation(&mut out, &pi, W, N, &mut temp, &mut pi_as_i32, &mut pi_test);
        // controlbitsfrompermutation only returns once its internal convergence
        // check (diff == 0) passes, so reaching here at all is the assertion.
    }
}
