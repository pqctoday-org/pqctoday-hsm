//! Public key generation. Adapted from upstream `classic-mceliece-rust` 3.1.0
//! `src/pk_gen.rs`, slice-based with a `Vec` of fixed-width rows for the working
//! matrix (`mat`) — its row COUNT (`PK_NROWS`) and column count (`SYS_N/8`) are both
//! runtime values, so it can't be a single fixed-size 2D array without a const
//! generic in an array-length expression (same restriction as everywhere else in
//! this fork); a `Vec<[u8; MAX_SYS_N_DIV_8]>` (heap-allocated row count, each row a
//! fixed 1024-byte buffer — a safe upper bound on `SYS_N/8` for every variant, only
//! the first `sys_n/8` bytes of each row are ever read or written) sidesteps that
//! cleanly, matching the crate's `alloc`-feature default (same as upstream, which
//! also boxes `mat` when `alloc` is enabled).
//!
//! Four bodies, matching the real axes (see `docs/implementation-plan-classic-
//! mceliece-all-parameter-sets-2026-09-08.md` §4.0): `pk_gen_plain` (non-`f`,
//! non-6960119 — 348864/460896/6688128/8192128), `pk_gen_6960119` (non-`f`,
//! 6960119's bit-realigned writeback), `pk_gen_f` (`f`-generic `mov_columns` path —
//! 348864f/460896f/6688128f/8192128f), `pk_gen_f_6960119f` (`f` + 6960119f's own
//! 9-byte-realigned `mov_columns` internals + the 6960119 writeback). Each takes
//! `root_fn`/`bitrev_fn` as function pointers so the same body serves both the
//! narrow and wide families (348864's non-`f` case is narrow, the rest are wide).

extern crate alloc;
use alloc::vec::Vec;

/// Safe upper bound on `SYS_N/8` across all 10 parameter sets (8192/8 = 1024).
const MAX_SYS_N_DIV_8: usize = 1024;
/// Safe upper bound on `1 << GFBITS` across all 10 parameter sets (GFBITS<=13).
const MAX_2_POW_GFBITS: usize = 1 << 13;

type RootFn = fn(&mut [u16], &[u16], &[u16]);
type BitrevFn = fn(u16) -> u16;
type GfInvFn = fn(u16) -> u16;
type GfMulFn = fn(u16, u16) -> u16;

/// Return number of trailing zeros of the non-zero input `input` — `f` variants only.
fn ctz(input: u64) -> i32 {
    let (mut m, mut r) = (0i32, 0i32);
    for i in 0..64 {
        let b = ((input >> i) & 1) as i32;
        m |= b;
        r += (m ^ 1) & (b ^ 1);
    }
    r
}

/// Takes two 16-bit integers and determines whether they are equal (u64::MAX) or
/// different (0) — `f` variants only.
fn same_mask(x: u16, y: u16) -> u64 {
    let mut mask = (x ^ y) as u64;
    mask = mask.wrapping_sub(1);
    mask >>= 63;
    mask = 0u64.wrapping_sub(mask);
    mask
}

/// Move columns in matrix `mat` — the shared `f`-variant body (4 of the 5 `f`
/// sizes; 6960119f has its own, see [`mov_columns_6960119f`]).
fn mov_columns(
    mat: &mut [[u8; MAX_SYS_N_DIV_8]],
    pi: &mut [i16],
    pivots: &mut u64,
    pk_nrows: usize,
) -> i32 {
    let mut buf = [0u64; 64];
    let mut ctz_list = [0u64; 32];

    let row = pk_nrows - 32;
    let block_idx = row / 8;

    for i in 0..32 {
        buf[i] = u64::from_le_bytes(mat[row + i][block_idx..block_idx + 8].try_into().unwrap());
    }

    *pivots = 0;
    for i in 0..32 {
        let mut t = buf[i];
        for j in i + 1..32 {
            t |= buf[j];
        }

        if t == 0 {
            return -1;
        }

        ctz_list[i] = ctz(t) as u64;
        let s = ctz_list[i] as usize;

        *pivots |= 1u64 << s;

        for j in i + 1..32 {
            let mut mask = (buf[i] >> s) & 1;
            mask = mask.wrapping_sub(1);
            buf[i] ^= buf[j] & mask;
        }

        for j in i + 1..32 {
            let mut mask = (buf[j] >> s) & 1;
            mask = 0u64.wrapping_sub(mask);
            buf[j] ^= buf[i] & mask;
        }
    }

    for j in 0..32 {
        for k in j + 1..64 {
            let mut d = (pi[row + j] ^ pi[row + k]) as u64;
            d &= same_mask(k as u16, ctz_list[j] as u16);
            pi[row + j] ^= d as i16;
            pi[row + k] ^= d as i16;
        }
    }

    for i in 0..pk_nrows {
        let mut t = u64::from_le_bytes(mat[i][block_idx..block_idx + 8].try_into().unwrap());

        for j in 0..32 {
            let mut d: u64 = t >> j;
            d ^= t >> ctz_list[j];
            d &= 1;

            t ^= d << ctz_list[j];
            t ^= d << j;
        }

        mat[i][block_idx..block_idx + 8].copy_from_slice(&t.to_le_bytes());
    }

    0
}

/// Move columns — 6960119f's own body (its `PK_NROWS = 1547` isn't a multiple of 8,
/// so it needs a 9-byte bit-shifted realignment `mov_columns` doesn't).
fn mov_columns_6960119f(
    mat: &mut [[u8; MAX_SYS_N_DIV_8]],
    pi: &mut [i16],
    pivots: &mut u64,
    pk_nrows: usize,
) -> i32 {
    let mut buf = [0u64; 64];
    let mut ctz_list = [0u64; 32];

    let row = pk_nrows - 32;
    let block_idx = row / 8;
    let tail = row % 8;
    let mut tmp = [0u8; 9];

    for i in 0..32 {
        tmp.copy_from_slice(&mat[row + i][block_idx..block_idx + 9]);
        for j in 0..8 {
            tmp[j] = (tmp[j] >> tail) | (tmp[j + 1] << (8 - tail));
        }
        buf[i] = u64::from_le_bytes(tmp[0..8].try_into().unwrap());
    }

    *pivots = 0;
    for i in 0..32 {
        let mut t = buf[i];
        for j in i + 1..32 {
            t |= buf[j];
        }

        if t == 0 {
            return -1;
        }

        ctz_list[i] = ctz(t) as u64;
        let s = ctz_list[i] as usize;

        *pivots |= 1u64 << s;

        for j in i + 1..32 {
            let mut mask = (buf[i] >> s) & 1;
            mask = mask.wrapping_sub(1);
            buf[i] ^= buf[j] & mask;
        }

        for j in i + 1..32 {
            let mut mask = (buf[j] >> s) & 1;
            mask = 0u64.wrapping_sub(mask);
            buf[j] ^= buf[i] & mask;
        }
    }

    for j in 0..32 {
        for k in j + 1..64 {
            let mut d = (pi[row + j] ^ pi[row + k]) as u64;
            d &= same_mask(k as u16, ctz_list[j] as u16);
            pi[row + j] ^= d as i16;
            pi[row + k] ^= d as i16;
        }
    }

    for i in 0..pk_nrows {
        for k in 0..9 {
            tmp[k] = mat[i][block_idx + k];
        }
        for k in 0..8 {
            tmp[k] = (tmp[k] >> tail) | (tmp[k + 1] << (8 - tail));
        }

        let mut t = u64::from_le_bytes(tmp[0..8].try_into().unwrap());

        for j in 0..32 {
            let mut d = t >> j;
            d ^= t >> ctz_list[j];
            d &= 1;

            t ^= d << ctz_list[j];
            t ^= d << j;
        }

        tmp[0..8].copy_from_slice(&t.to_le_bytes());

        mat[i][block_idx + 8] = (mat[i][block_idx + 8] >> tail << tail) | (tmp[7] >> (8 - tail));
        mat[i][block_idx + 0] = (tmp[0] << tail) | (mat[i][block_idx] << (8 - tail) >> (8 - tail));

        for k in (1..=7).rev() {
            mat[i][block_idx + k] = (tmp[k] << tail) | (tmp[k - 1] >> (8 - tail));
        }
    }

    0
}

/// Shared Gaussian-elimination + `pk` writeback core. `mov_columns_hook` is called
/// (when `Some`) at `row == pk_nrows - 32`, matching upstream's `f`-only hook inside
/// the elimination loop; `writeback` selects the plain vs 6960119-bit-realigned
/// writeback.
#[allow(clippy::too_many_arguments)]
fn pk_gen_core(
    pk: &mut [u8],
    sk: &[u8],
    perm: &[u32],
    pi: &mut [i16],
    pivots: Option<&mut u64>,
    sys_n: usize,
    sys_t: usize,
    gfbits: usize,
    gfmask: u16,
    pk_nrows: usize,
    pk_row_bytes: usize,
    root_fn: RootFn,
    bitrev_fn: BitrevFn,
    gf_inv_fn: GfInvFn,
    gf_mul_fn: GfMulFn,
    padded_writeback: bool,
    use_6960119f_mov_columns: bool,
) -> i32 {
    let two_pow_gfbits = 1usize << gfbits;
    debug_assert!(two_pow_gfbits <= MAX_2_POW_GFBITS);
    debug_assert_eq!(sk.len(), 2 * sys_t);
    debug_assert_eq!(perm.len(), two_pow_gfbits);
    debug_assert_eq!(pi.len(), two_pow_gfbits);

    let mut buf = [0u64; MAX_2_POW_GFBITS];
    let buf = &mut buf[..two_pow_gfbits];

    let sys_n_div_8 = sys_n.div_ceil(8);
    let mut mat: Vec<[u8; MAX_SYS_N_DIV_8]> = alloc::vec![[0u8; MAX_SYS_N_DIV_8]; pk_nrows];

    let mut g = [0u16; 129]; // MAX_SYS_T + 1
    let g = &mut g[..=sys_t];
    let mut l = [0u16; 8192]; // MAX_SYS_N
    let l = &mut l[..sys_n];
    let mut inv = [0u16; 8192];
    let inv = &mut inv[..sys_n];

    g[sys_t] = 1;
    for (i, chunk) in sk.chunks(2).take(sys_t).enumerate() {
        g[i] = u16::from_le_bytes(chunk.try_into().unwrap()) & gfmask;
    }

    for i in 0..two_pow_gfbits {
        buf[i] = perm[i] as u64;
        buf[i] <<= 31;
        buf[i] |= i as u64;
    }

    // `shared::uint64_sort::uint64_sort` is const-generic on `N`, but
    // `two_pow_gfbits` is only known at runtime inside this shared function (it
    // varies 4096/8192 across variants and this function isn't monomorphized per
    // variant) — so it can't be called here. `slice_uint64_sort` below is the same
    // djbsort algorithm over a runtime-length slice instead.
    slice_uint64_sort(buf);

    for i in 1..two_pow_gfbits {
        if buf[i - 1] >> 31 == buf[i] >> 31 {
            return -1;
        }
    }

    for i in 0..two_pow_gfbits {
        pi[i] = buf[i] as i16 & gfmask as i16;
    }

    for i in 0..sys_n {
        l[i] = bitrev_fn(pi[i] as u16);
    }

    root_fn(inv, g, l);

    for itr_inv in inv.iter_mut() {
        *itr_inv = gf_inv_fn(*itr_inv);
    }

    for i in 0..sys_t {
        for j in (0..sys_n).step_by(8) {
            for k in 0..gfbits {
                let mut b = ((inv[j + 7] >> k) & 1) as u8;
                b <<= 1;
                b |= ((inv[j + 6] >> k) & 1) as u8;
                b <<= 1;
                b |= ((inv[j + 5] >> k) & 1) as u8;
                b <<= 1;
                b |= ((inv[j + 4] >> k) & 1) as u8;
                b <<= 1;
                b |= ((inv[j + 3] >> k) & 1) as u8;
                b <<= 1;
                b |= ((inv[j + 2] >> k) & 1) as u8;
                b <<= 1;
                b |= ((inv[j + 1] >> k) & 1) as u8;
                b <<= 1;
                b |= ((inv[j] >> k) & 1) as u8;

                mat[i * gfbits + k][j / 8] = b;
            }
        }
        for j in 0..sys_n {
            inv[j] = gf_mul_fn(inv[j], l[j]);
        }
    }

    // gaussian elimination
    let rows = pk_nrows.div_ceil(8);
    let mut pivots = pivots;

    for i in 0..rows {
        for j in 0..8 {
            let row = i * 8 + j;

            if row >= pk_nrows {
                break;
            }

            if let Some(ref mut pv) = pivots {
                if row == pk_nrows - 32 {
                    let rc = if use_6960119f_mov_columns {
                        mov_columns_6960119f(&mut mat, pi, pv, pk_nrows)
                    } else {
                        mov_columns(&mut mat, pi, pv, pk_nrows)
                    };
                    if rc != 0 {
                        return -1;
                    }
                }
            }

            for k in (row + 1)..pk_nrows {
                let mut mask = mat[row][i] ^ mat[k][i];
                mask >>= j;
                mask &= 1;
                mask = 0u8.wrapping_sub(mask);

                for c in 0..sys_n_div_8 {
                    mat[row][c] ^= mat[k][c] & mask;
                }
            }

            if ((mat[row][i] >> j) & 1) == 0 {
                return -1;
            }

            for k in 0..pk_nrows {
                if k == row {
                    continue;
                }

                let mut mask = mat[k][i] >> j;
                mask &= 1;
                mask = 0u8.wrapping_sub(mask);

                for c in 0..sys_n_div_8 {
                    mat[k][c] ^= mat[row][c] & mask;
                }
            }
        }
    }

    if !padded_writeback {
        for i in 0..pk_nrows {
            pk[i * pk_row_bytes..(i + 1) * pk_row_bytes]
                .copy_from_slice(&mat[i][pk_nrows / 8..pk_nrows / 8 + pk_row_bytes]);
        }
    } else {
        let tail = pk_nrows % 8;
        let inner_pk_accesses = (sys_n_div_8 - 1) - (pk_nrows - 1) / 8 + 1;
        for i in 0..pk_nrows {
            for (idx, j) in ((pk_nrows - 1) / 8..sys_n_div_8 - 1).enumerate() {
                pk[i * inner_pk_accesses + idx] = (mat[i][j] >> tail) | (mat[i][j + 1] << (8 - tail));
            }
            pk[(i + 1) * inner_pk_accesses - 1] = mat[i][sys_n_div_8 - 1] >> tail;
        }
    }

    0
}

/// Constant-time-ish djbsort over a runtime-length `u64` slice — identical
/// algorithm to `shared/uint64_sort.rs`'s const-generic version, needed here
/// because `pk_gen_core`'s `buf` length (`1 << GFBITS`) is a runtime value, not a
/// compile-time const generic argument.
fn slice_uint64_sort(x: &mut [u64]) {
    let n = x.len();
    if n < 2 {
        return;
    }
    let mut top = 1;
    while top < n.wrapping_sub(top) {
        top += top;
    }

    fn minmax(mut a: u64, mut b: u64) -> (u64, u64) {
        let d: u64 = (!b & a) | ((!b | a) & (b.wrapping_sub(a)));
        let mut c: u64 = d >> 63;
        c = 0u64.wrapping_sub(c);
        c &= a ^ b;
        a ^= c;
        b ^= c;
        (a, b)
    }

    let mut p = top;
    while p > 0 {
        for i in 0..(n - p) {
            if (i & p) == 0 {
                let (a, b) = minmax(x[i], x[i + p]);
                x[i] = a;
                x[i + p] = b;
            }
        }
        let mut q = top;
        while q > p {
            for i in 0..(n - q) {
                if (i & p) == 0 {
                    let mut a = x[i + p];
                    let mut r = q;
                    while r > p {
                        let (ta, tb) = minmax(a, x[i + r]);
                        x[i + r] = tb;
                        a = ta;
                        r >>= 1;
                    }
                    x[i + p] = a;
                }
            }
            q >>= 1;
        }
        p >>= 1;
    }
}

/// Public key generation — non-`f`, non-6960119 (348864, 460896, 6688128, 8192128).
#[allow(clippy::too_many_arguments)]
pub(crate) fn pk_gen_plain(
    pk: &mut [u8],
    sk: &[u8],
    perm: &[u32],
    pi: &mut [i16],
    sys_n: usize,
    sys_t: usize,
    gfbits: usize,
    gfmask: u16,
    pk_nrows: usize,
    pk_row_bytes: usize,
    root_fn: RootFn,
    bitrev_fn: BitrevFn,
    gf_inv_fn: GfInvFn,
    gf_mul_fn: GfMulFn,
) -> i32 {
    pk_gen_core(
        pk, sk, perm, pi, None, sys_n, sys_t, gfbits, gfmask, pk_nrows, pk_row_bytes, root_fn,
        bitrev_fn, gf_inv_fn, gf_mul_fn, false, false,
    )
}

/// Public key generation — non-`f`, 6960119/6960119's non-byte-aligned writeback
/// (used by plain 6960119; 6960119f uses [`pk_gen_f_6960119f`] instead).
#[allow(clippy::too_many_arguments)]
pub(crate) fn pk_gen_6960119(
    pk: &mut [u8],
    sk: &[u8],
    perm: &[u32],
    pi: &mut [i16],
    sys_n: usize,
    sys_t: usize,
    gfbits: usize,
    gfmask: u16,
    pk_nrows: usize,
    pk_row_bytes: usize,
    root_fn: RootFn,
    bitrev_fn: BitrevFn,
    gf_inv_fn: GfInvFn,
    gf_mul_fn: GfMulFn,
) -> i32 {
    pk_gen_core(
        pk, sk, perm, pi, None, sys_n, sys_t, gfbits, gfmask, pk_nrows, pk_row_bytes, root_fn,
        bitrev_fn, gf_inv_fn, gf_mul_fn, true, false,
    )
}

/// Public key generation — `f`-generic (348864f, 460896f, 6688128f, 8192128f).
#[allow(clippy::too_many_arguments)]
pub(crate) fn pk_gen_f(
    pk: &mut [u8],
    sk: &[u8],
    perm: &[u32],
    pi: &mut [i16],
    pivots: &mut u64,
    sys_n: usize,
    sys_t: usize,
    gfbits: usize,
    gfmask: u16,
    pk_nrows: usize,
    pk_row_bytes: usize,
    root_fn: RootFn,
    bitrev_fn: BitrevFn,
    gf_inv_fn: GfInvFn,
    gf_mul_fn: GfMulFn,
) -> i32 {
    pk_gen_core(
        pk, sk, perm, pi, Some(pivots), sys_n, sys_t, gfbits, gfmask, pk_nrows, pk_row_bytes,
        root_fn, bitrev_fn, gf_inv_fn, gf_mul_fn, false, false,
    )
}

/// Public key generation — 6960119f (`f`'s `mov_columns` uses its own 9-byte
/// realignment, and the writeback is the 6960119-family bit-realigned form).
#[allow(clippy::too_many_arguments)]
pub(crate) fn pk_gen_f_6960119f(
    pk: &mut [u8],
    sk: &[u8],
    perm: &[u32],
    pi: &mut [i16],
    pivots: &mut u64,
    sys_n: usize,
    sys_t: usize,
    gfbits: usize,
    gfmask: u16,
    pk_nrows: usize,
    pk_row_bytes: usize,
    root_fn: RootFn,
    bitrev_fn: BitrevFn,
    gf_inv_fn: GfInvFn,
    gf_mul_fn: GfMulFn,
) -> i32 {
    pk_gen_core(
        pk, sk, perm, pi, Some(pivots), sys_n, sys_t, gfbits, gfmask, pk_nrows, pk_row_bytes,
        root_fn, bitrev_fn, gf_inv_fn, gf_mul_fn, true, true,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ctz() {
        const EXPECTED: [i32; 16] = [64, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0];
        for i in 0..16 {
            assert_eq!(ctz(i as u64), EXPECTED[i]);
        }
    }

    #[test]
    fn test_same_mask() {
        assert_eq!(same_mask(3, 3), 0xFFFFFFFFFFFFFFFF);
        assert_eq!(same_mask(3, 4), 0);
    }

    #[test]
    fn test_slice_uint64_sort() {
        let mut x: [u64; 16] = core::array::from_fn(|i| (16 - i) as u64);
        slice_uint64_sort(&mut x);
        for i in 1..x.len() {
            assert!(x[i] >= x[i - 1]);
        }
    }
}
