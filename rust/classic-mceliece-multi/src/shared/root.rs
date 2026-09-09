//! Evaluate a polynomial at one or more field elements. Adapted from upstream
//! `classic-mceliece-rust` 3.1.0 `src/root.rs`, slice-based (see `shared/gf.rs`'s
//! module doc for why) with two variants matching `gf_mul`'s own narrow/wide split
//! — `f`/`l`/`out` lengths (`SYS_T+1`/`SYS_N`) are runtime slice lengths, not
//! const-generic array lengths, so this file needs no per-size duplication at all,
//! only the narrow/wide family split `gf.rs` already has.

use super::gf::{gf_add, gf_mul_narrow, gf_mul_wide, Gf};

/// Evaluate polynomial `f` with argument `a` — narrow family (`f.len() == SYS_T+1`).
pub(crate) fn eval_narrow(f: &[Gf], a: Gf) -> Gf {
    let sys_t = f.len() - 1;
    let mut r: Gf = f[sys_t];
    for i in (0..=sys_t - 1).rev() {
        r = gf_mul_narrow(r, a, 12, 0x0FFF);
        r = gf_add(r, f[i]);
    }
    r
}

/// Given polynomial `f` and a list of field elements `l`, write the roots `out`
/// satisfying `[ f(a) for a in l ]` — narrow family.
pub(crate) fn root_narrow(out: &mut [Gf], f: &[Gf], l: &[Gf]) {
    debug_assert_eq!(out.len(), l.len());
    for i in 0..l.len() {
        out[i] = eval_narrow(f, l[i]);
    }
}

/// Evaluate polynomial `f` with argument `a` — wide family (`f.len() == SYS_T+1`).
pub(crate) fn eval_wide(f: &[Gf], a: Gf) -> Gf {
    let sys_t = f.len() - 1;
    let mut r: Gf = f[sys_t];
    for i in (0..=sys_t - 1).rev() {
        r = gf_mul_wide(r, a, 13, 0x1FFF);
        r = gf_add(r, f[i]);
    }
    r
}

/// Given polynomial `f` and a list of field elements `l`, write the roots `out`
/// satisfying `[ f(a) for a in l ]` — wide family.
pub(crate) fn root_wide(out: &mut [Gf], f: &[Gf], l: &[Gf]) {
    debug_assert_eq!(out.len(), l.len());
    for i in 0..l.len() {
        out[i] = eval_wide(f, l[i]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_narrow_and_wide_agree_on_structure() {
        // f(x) = 0 for the all-zero polynomial, both families — trivial but
        // exercises the whole eval loop without needing a real KAT here (the real
        // per-variant KATs live in each size-family module's own tests).
        let f = [0u16; 65]; // SYS_T=64 -> SYS_T+1=65
        let l: [u16; 5] = [0, 1, 2, 3, 4];
        let mut out = [0u16; 5];
        root_narrow(&mut out, &f, &l);
        assert_eq!(out, [0u16; 5]);

        let f = [0u16; 129]; // SYS_T=128 -> SYS_T+1=129
        let mut out = [0u16; 5];
        root_wide(&mut out, &f, &l);
        assert_eq!(out, [0u16; 5]);
    }
}
