//! Syndrome computation. Adapted from upstream `classic-mceliece-rust` 3.1.0
//! `src/synd.rs`, slice-based with narrow/wide variants (see `shared/root.rs`'s
//! module doc — same reasoning applies here).

use super::gf::{gf_add, gf_inv_narrow, gf_inv_wide, gf_mul_narrow, gf_mul_wide, Gf};
use super::root::{eval_narrow, eval_wide};

/// Given Goppa polynomial `f`, support `l`, and received word `r`, compute `out`,
/// the syndrome of length `2*SYS_T` — narrow family. `out.len() == 2 * (f.len()-1)`,
/// `l.len() == r.len() * 8` (rounded).
pub(crate) fn synd_narrow(out: &mut [Gf], f: &[Gf], l: &[Gf], r: &[u8]) {
    out.fill(0);

    for i in 0..l.len() {
        let c: Gf = (r[i / 8] >> (i % 8)) as u16 & 1;
        let e: Gf = eval_narrow(f, l[i]);
        let mut e_inv: Gf = gf_inv_narrow(gf_mul_narrow(e, e, 12, 0x0FFF), 12, 0x0FFF);

        for itr_out in out.iter_mut() {
            *itr_out = gf_add(*itr_out, gf_mul_narrow(e_inv, c, 12, 0x0FFF));
            e_inv = gf_mul_narrow(e_inv, l[i], 12, 0x0FFF);
        }
    }
}

/// Wide family equivalent of [`synd_narrow`].
pub(crate) fn synd_wide(out: &mut [Gf], f: &[Gf], l: &[Gf], r: &[u8]) {
    out.fill(0);

    for i in 0..l.len() {
        let c: Gf = (r[i / 8] >> (i % 8)) as u16 & 1;
        let e: Gf = eval_wide(f, l[i]);
        let mut e_inv: Gf = gf_inv_wide(gf_mul_wide(e, e, 13, 0x1FFF), 0x1FFF);

        for itr_out in out.iter_mut() {
            *itr_out = gf_add(*itr_out, gf_mul_wide(e_inv, c, 13, 0x1FFF));
            e_inv = gf_mul_wide(e_inv, l[i], 13, 0x1FFF);
        }
    }
}
