//! Niederreiter decryption with the Berlekamp decoder. Adapted from upstream
//! `classic-mceliece-rust` 3.1.0 `src/decrypt.rs`, slice-based with narrow/wide
//! variants (the function itself does no per-size arithmetic beyond passing runtime
//! lengths through to `support_gen`/`synd`/`bm`/`root`, so — unlike `sk_gen.rs` —
//! this collapses to the plain 2-way narrow/wide split, not a 4- or 5-way one).
//! `sys_t` is an explicit parameter (upstream derives it implicitly from a
//! crate-level `SYS_T` const; here `sk`'s two segments — `irr` = `2*sys_t` bytes,
//! `cond` = the rest — can't be split without knowing `sys_t`, so the caller states
//! it). Internal scratch is bounded at the crate-wide maximum SYS_T/SYS_N (128 /
//! 8192) rather than sized by a const generic, matching `bm.rs`'s pattern.

use super::benes::{support_gen_narrow, support_gen_wide};
use super::bm::{bm_narrow, bm_wide};
use super::gf::gf_iszero;
use super::root::{root_narrow, root_wide};
use super::synd::{synd_narrow, synd_wide};
use super::util::load_gf;

/// The largest SYS_T among all 10 parameter sets (see `bm.rs`).
const MAX_SYS_T: usize = 128;
/// The largest SYS_N among all 10 parameter sets (8192, for 8192128/8192128f).
const MAX_SYS_N: usize = 8192;

/// Niederreiter decryption — narrow family (348864/348864f). `e.len() == SYS_N/8`,
/// `sk` = `irr` (`2*sys_t` bytes) `|| cond` (`COND_BYTES` bytes), `c.len() ==
/// SYND_BYTES`. Returns 0 on success, 1 on failure (matching upstream's C-style
/// status byte).
pub(crate) fn decrypt_narrow(e: &mut [u8], sys_t: usize, sk: &[u8], c: &[u8]) -> u8 {
    decrypt_generic(
        e,
        sys_t,
        sk,
        c,
        0x0FFF,
        support_gen_narrow,
        synd_narrow,
        bm_narrow,
        root_narrow,
    )
}

/// Niederreiter decryption — wide family (the other eight variants). Same shapes as
/// [`decrypt_narrow`].
pub(crate) fn decrypt_wide(e: &mut [u8], sys_t: usize, sk: &[u8], c: &[u8]) -> u8 {
    decrypt_generic(
        e,
        sys_t,
        sk,
        c,
        0x1FFF,
        support_gen_wide,
        synd_wide,
        bm_wide,
        root_wide,
    )
}

#[allow(clippy::too_many_arguments)]
fn decrypt_generic(
    e: &mut [u8],
    sys_t: usize,
    sk: &[u8],
    c: &[u8],
    gfmask: u16,
    support_gen: fn(&mut [u16], &[u8]),
    synd: fn(&mut [u16], &[u16], &[u16], &[u8]),
    bm: fn(&mut [u16], &mut [u16], &mut [u16], &mut [u16]),
    root: fn(&mut [u16], &[u16], &[u16]),
) -> u8 {
    debug_assert!(sys_t <= MAX_SYS_T);
    let sys_n = e.len() * 8;
    debug_assert!(sys_n <= MAX_SYS_N);
    let synd_bytes = c.len();
    let irr_bytes = sys_t * 2;
    debug_assert!(sk.len() >= irr_bytes);
    let cond = &sk[irr_bytes..];

    let mut r = [0u8; MAX_SYS_N / 8];
    let r = &mut r[..sys_n / 8];

    let mut g = [0u16; MAX_SYS_T + 1];
    let g = &mut g[..=sys_t];
    let mut l = [0u16; MAX_SYS_N];
    let l = &mut l[..sys_n];

    let mut s = [0u16; MAX_SYS_T * 2];
    let s = &mut s[..2 * sys_t];
    let mut s_cmp = [0u16; MAX_SYS_T * 2];
    let s_cmp = &mut s_cmp[..2 * sys_t];
    let mut locator = [0u16; MAX_SYS_T + 1];
    let locator = &mut locator[..=sys_t];
    let mut images = [0u16; MAX_SYS_N];
    let images = &mut images[..sys_n];
    let mut c_scratch = [0u16; MAX_SYS_T + 1];
    let c_scratch = &mut c_scratch[..=sys_t];
    let mut b_scratch = [0u16; MAX_SYS_T + 1];
    let b_scratch = &mut b_scratch[..=sys_t];

    r[..synd_bytes].copy_from_slice(&c[..synd_bytes]);
    r[synd_bytes..].fill(0);

    for (i, chunk) in sk[..irr_bytes].chunks(2).take(sys_t).enumerate() {
        g[i] = load_gf(chunk.try_into().unwrap(), gfmask);
    }
    g[sys_t] = 1;

    support_gen(l, cond);

    synd(s, g, l, r);

    // Upstream declares `s: &mut` on `bm()` but its body never writes into it (only
    // reads `s[n-i]`) — passing the same slice through, not a copy, matches
    // upstream's own post-`bm()` use of `s` unchanged in the `check` computation
    // below.
    bm(locator, s, c_scratch, b_scratch);

    root(images, locator, l);

    e.fill(0);

    let mut w: i32 = 0;
    for i in 0..sys_n {
        let t = gf_iszero(images[i]) & 1;
        e[i / 8] |= (t << (i % 8)) as u8;
        w += t as i32;
    }

    synd(s_cmp, g, l, e);

    let mut check = w as u16;
    check ^= sys_t as u16;

    for i in 0..2 * sys_t {
        check |= s[i] ^ s_cmp[i];
    }

    check = check.wrapping_sub(1);
    check >>= 15;

    (check ^ 1) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decrypt_narrow_smoke() {
        // Structural smoke test only (no real KAT here — those are per-variant,
        // against the official vectors, in each size-family module). Proves the
        // slice-length plumbing doesn't panic on a plausible SYS_T=64/SYS_N=3488
        // all-zero input (an all-zero secret key isn't a real McEliece key, but the
        // function must still run to completion, returning failure).
        const SYS_T: usize = 64;
        const SYS_N: usize = 3488;
        const COND_BYTES: usize = (1 << (12 - 4)) * (2 * 12 - 1);
        let sk = alloc::vec![0u8; SYS_T * 2 + COND_BYTES];
        let c = alloc::vec![0u8; SYS_T.div_ceil(8) * 13]; // arbitrary plausible SYND_BYTES-ish length, not exact
        let mut e = alloc::vec![0u8; SYS_N / 8];
        let _ = decrypt_narrow(&mut e, SYS_T, &sk, &c);
    }
}
