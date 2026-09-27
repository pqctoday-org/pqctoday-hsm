//! Generation of the secret key's irreducible polynomial. Adapted from upstream
//! `classic-mceliece-rust` 3.1.0 `src/sk_gen.rs`, slice-based. `genpoly_gen`'s
//! reduction step depends on `gf_mul_inplace`, which is a 4-way family (see
//! `shared/gf.rs`: 348864 / 460896 / 6960119 / {6688128,8192128} all have distinct
//! reduction taps) — so this file has four variants, one per `gf_mul_inplace_*`
//! family, matching that split exactly (not the narrow/wide 2-way split most other
//! shared files use). The internal `mat: [[0u16; SYS_T]; SYS_T+1]` local is bounded
//! at the crate-wide maximum SYS_T (128, `shared/bm.rs`'s `MAX_SYS_T_PLUS_1`) rather
//! than sized by a const generic, for the same reason `bm.rs`'s scratch buffer is.

use super::gf::{
    gf_inv_narrow, gf_inv_wide, gf_iszero, gf_mul_inplace_348864, gf_mul_inplace_460896,
    gf_mul_inplace_6960119, gf_mul_inplace_wide128, gf_mul_narrow, gf_mul_wide, Gf,
};

/// One more than the largest `SYS_T` among all 10 parameter sets — see `bm.rs`.
const MAX_SYS_T: usize = 128;

macro_rules! genpoly_gen_body {
    ($name:ident, $gf_mul:expr, $gf_inv:expr, $gf_mul_inplace:expr, $gfbits:expr, $gfmask:expr) => {
        /// Take element `f` in `GF((2^m)^t)` and return minimal polynomial `out` of
        /// `f`. Returns 0 for success and -1 for failure. `out.len() == f.len() ==
        /// SYS_T`.
        pub(crate) fn $name(out: &mut [Gf], f: &[Gf]) -> isize {
            let sys_t = out.len();
            debug_assert_eq!(f.len(), sys_t);
            debug_assert!(sys_t <= MAX_SYS_T);

            let mut mat_storage = [[0u16; MAX_SYS_T]; MAX_SYS_T + 1];
            let mat = &mut mat_storage[..=sys_t];
            mat[0][0] = 1;
            for v in mat[0][1..sys_t].iter_mut() {
                *v = 0;
            }
            mat[1][..sys_t].copy_from_slice(f);

            let mut prod_scratch = [0u16; 2 * MAX_SYS_T - 1];
            for j in 2..=sys_t {
                let (left, right) = mat.split_at_mut(j);
                let prev = &left[j - 1][..sys_t];
                let dest = &mut right[0][..sys_t];
                $gf_mul_inplace(dest, prev, f, &mut prod_scratch[..2 * sys_t - 1]);
            }

            for j in 0..sys_t {
                for k in (j + 1)..sys_t {
                    let mask = gf_iszero(mat[j][j]);

                    let mut c = j;
                    while c < sys_t + 1 {
                        mat[c][j] ^= mat[c][k] & mask;
                        c += 1;
                    }
                }

                if mat[j][j] == 0 {
                    return -1;
                }

                let inv = $gf_inv(mat[j][j]);

                for itr_mat in mat.iter_mut() {
                    itr_mat[j] = $gf_mul(itr_mat[j], inv);
                }

                for k in 0..sys_t {
                    if k != j {
                        let t = mat[j][k];

                        for itr_mat in mat.iter_mut() {
                            itr_mat[k] ^= $gf_mul(itr_mat[j], t);
                        }
                    }
                }
            }

            out[..sys_t].copy_from_slice(&mat[sys_t][..sys_t]);

            let _ = ($gfbits, $gfmask); // kept for documentation symmetry with the other family fns
            0
        }
    };
}

genpoly_gen_body!(
    genpoly_gen_348864,
    |a, b| gf_mul_narrow(a, b, 12, 0x0FFF),
    |a| gf_inv_narrow(a, 12, 0x0FFF),
    gf_mul_inplace_348864,
    12usize,
    0x0FFFu16
);
genpoly_gen_body!(
    genpoly_gen_460896,
    |a, b| gf_mul_wide(a, b, 13, 0x1FFF),
    |a| gf_inv_wide(a, 0x1FFF),
    gf_mul_inplace_460896,
    13usize,
    0x1FFFu16
);
genpoly_gen_body!(
    genpoly_gen_6960119,
    |a, b| gf_mul_wide(a, b, 13, 0x1FFF),
    |a| gf_inv_wide(a, 0x1FFF),
    gf_mul_inplace_6960119,
    13usize,
    0x1FFFu16
);
genpoly_gen_body!(
    genpoly_gen_wide128,
    |a, b| gf_mul_wide(a, b, 13, 0x1FFF),
    |a| gf_inv_wide(a, 0x1FFF),
    gf_mul_inplace_wide128,
    13usize,
    0x1FFFu16
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genpoly_gen_348864_smoke() {
        // f = [1, 2, 3, ...] is not guaranteed irreducible, so genpoly_gen may
        // legitimately return -1 — this only proves the plumbing (slice lengths,
        // scratch buffers) doesn't panic, ahead of the real per-variant KATs.
        const SYS_T: usize = 64;
        let mut f = [0u16; SYS_T];
        for (i, v) in f.iter_mut().enumerate() {
            *v = (i as u16).wrapping_add(1);
        }
        let mut out = [0u16; SYS_T];
        let _ = genpoly_gen_348864(&mut out, &f);
    }
}
