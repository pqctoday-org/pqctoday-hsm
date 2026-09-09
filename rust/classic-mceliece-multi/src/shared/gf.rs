//! Galois field operations. Adapted from upstream `classic-mceliece-rust` 3.1.0
//! `src/gf.rs`: bodies are copied verbatim per branch, but every function that only
//! ever operated on scalars is unconditionally shared here (`gf_iszero`, `gf_add`,
//! and the small fixed `[u64; 3..6]` lookup tables in the wide square/mul helpers are
//! not SYS_T/SYS_N/GFBITS-sized at all, so they need no per-variant duplication in
//! the first place). Where upstream's `#[cfg(...)]` split is real (`gf_mul`/`gf_sq`/
//! `gf_frac`/`gf_inv`: 348864 vs the rest; `gf_mul_inplace`'s reduction: 4-way), both
//! bodies are kept, suffixed `_narrow`/`_wide` (348864-family vs the other four
//! sizes, which all share GFBITS=13) or by size name for `gf_mul_inplace`'s
//! 4-way split. `GFBITS` is passed as a plain runtime `usize` (not a const generic)
//! wherever it's only used as a loop bound, never to size an array — no const-generic
//! machinery is needed for that. `gf_mul_inplace` takes slices (not
//! `[Gf; SYS_T]`-shaped fixed arrays as upstream does) with a caller-supplied scratch
//! buffer, exactly mirroring the fix `shared/controlbits.rs` already applies for the
//! same reason (a fixed array sized by an expression of a generic parameter does not
//! compile on stable Rust — confirmed directly, see that file's doc comment).

pub(crate) type Gf = u16;

/// Does Gf element `a` have value 0? Returns yes (8191 = `u16::MAX/8`) or no (0) as Gf element.
pub(crate) fn gf_iszero(a: Gf) -> Gf {
    let mut t = (a as u32).wrapping_sub(1u32);
    t >>= 19;
    t as u16
}

/// Add Gf elements stored bitwise in `in0` and `in1` (XOR — addition in GF(2)).
pub(crate) fn gf_add(in0: Gf, in1: Gf) -> Gf {
    in0 ^ in1
}

// ── 348864-family (GFBITS = 12) ─────────────────────────────────────────────

/// Multiplication of two Gf elements — 348864/348864f body.
pub(crate) fn gf_mul_narrow(in0: Gf, in1: Gf, gfbits: usize, gfmask: u16) -> Gf {
    let (mut tmp, t0, t1, mut t): (u64, u64, u64, u64);

    t0 = in0 as u64;
    t1 = in1 as u64;

    tmp = t0 * (t1 & 1);

    for i in 1..gfbits {
        tmp ^= t0 * (t1 & (1 << i));
    }

    t = tmp & 0x7FC000;
    tmp ^= t >> 9;
    tmp ^= t >> 12;

    t = tmp & 0x3000;
    tmp ^= t >> 9;
    tmp ^= t >> 12;

    tmp as u16 & gfmask
}

/// Computes the square `in0^2` — 348864/348864f only.
fn gf_sq_narrow(in0: Gf, gfmask: u16) -> Gf {
    let b = [0x55555555u32, 0x33333333, 0x0F0F0F0F, 0x00FF00FF];

    let mut x: u32 = in0 as u32;
    x = (x | (x << 8)) & b[3];
    x = (x | (x << 4)) & b[2];
    x = (x | (x << 2)) & b[1];
    x = (x | (x << 1)) & b[0];

    let mut t = x & 0x7FC000;
    x ^= t >> 9;
    x ^= t >> 12;

    t = x & 0x3000;
    x ^= t >> 9;
    x ^= t >> 12;

    x as u16 & gfmask
}

/// Computes the division `num/den` — 348864/348864f body.
pub(crate) fn gf_frac_narrow(den: Gf, num: Gf, gfbits: usize, gfmask: u16) -> Gf {
    gf_mul_narrow(gf_inv_narrow(den, gfbits, gfmask), num, gfbits, gfmask)
}

/// Computes the inverse element of `in0` — 348864/348864f body.
pub(crate) fn gf_inv_narrow(in0: Gf, gfbits: usize, gfmask: u16) -> Gf {
    let mut out = gf_sq_narrow(in0, gfmask);
    let tmp_11 = gf_mul_narrow(out, in0, gfbits, gfmask); // 11

    out = gf_sq_narrow(tmp_11, gfmask);
    out = gf_sq_narrow(out, gfmask);
    let tmp_1111 = gf_mul_narrow(out, tmp_11, gfbits, gfmask); // 1111

    out = gf_sq_narrow(tmp_1111, gfmask);
    out = gf_sq_narrow(out, gfmask);
    out = gf_sq_narrow(out, gfmask);
    out = gf_sq_narrow(out, gfmask);
    out = gf_mul_narrow(out, tmp_1111, gfbits, gfmask); // 11111111

    out = gf_sq_narrow(out, gfmask);
    out = gf_sq_narrow(out, gfmask);
    out = gf_mul_narrow(out, tmp_11, gfbits, gfmask); // 1111111111

    out = gf_sq_narrow(out, gfmask);
    out = gf_mul_narrow(out, in0, gfbits, gfmask); // 11111111111

    gf_sq_narrow(out, gfmask) // 111111111110
}

// ── wide family (GFBITS = 13: 460896, 6688128, 6960119, 8192128, all f/non-f) ──

/// Multiplication of two Gf elements — shared body for every GFBITS=13 variant.
pub(crate) fn gf_mul_wide(in0: Gf, in1: Gf, gfbits: usize, gfmask: u16) -> Gf {
    let t0: u64 = in0 as u64;
    let t1: u64 = in1 as u64;
    let mut tmp: u64 = t0 * (t1 & 1);

    for i in 1..gfbits {
        tmp ^= t0 * (t1 & (1 << i));
    }

    let mut t: u64 = tmp & 0x1FF0000;
    tmp ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);

    t = tmp & 0x000E000;
    tmp ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);

    tmp as u16 & gfmask
}

/// Computes the double-square `(in0^2)^2` — wide family only.
#[inline]
fn gf_sq2(in0: Gf, gfmask: u16) -> Gf {
    const B: [u64; 4] = [
        0x1111111111111111,
        0x0303030303030303,
        0x000F000F000F000F,
        0x000000FF000000FF,
    ];
    const M: [u64; 4] = [
        0x0001FF0000000000,
        0x000000FF80000000,
        0x000000007FC00000,
        0x00000000003FE000,
    ];

    let mut x: u64 = in0 as u64;
    let mut t: u64;

    x = (x | (x << 24)) & B[3];
    x = (x | (x << 12)) & B[2];
    x = (x | (x << 6)) & B[1];
    x = (x | (x << 3)) & B[0];

    for i in 0..4 {
        t = x & M[i];
        x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
    }

    (x & gfmask as u64) as u16
}

/// Computes `(in0^2)*m` — wide family only.
#[inline]
fn gf_sqmul(in0: Gf, m: Gf, gfmask: u16) -> Gf {
    let mut x: u64;
    let mut t0: u64;
    let t1: u64;
    let mut t: u64;

    const M: [u64; 3] = [0x0000001FF0000000, 0x000000000FF80000, 0x000000000007E000];

    t0 = in0 as u64;
    t1 = m as u64;

    x = (t1 << 6) * (t0 & (1 << 6));

    t0 ^= t0 << 7;

    x ^= t1 * (t0 & (0x04001));
    x ^= (t1 * (t0 & (0x08002))) << 1;
    x ^= (t1 * (t0 & (0x10004))) << 2;
    x ^= (t1 * (t0 & (0x20008))) << 3;
    x ^= (t1 * (t0 & (0x40010))) << 4;
    x ^= (t1 * (t0 & (0x80020))) << 5;

    for i in 0..3 {
        t = x & M[i];
        x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
    }

    (x & gfmask as u64) as u16
}

/// Computes `((in0^2)^2)*m` — wide family only.
#[inline]
fn gf_sq2mul(in0: Gf, m: Gf, gfmask: u16) -> Gf {
    let mut x: u64;
    let mut t0: u64;
    let t1: u64;
    let mut t: u64;

    const M: [u64; 6] = [
        0x1FF0000000000000,
        0x000FF80000000000,
        0x000007FC00000000,
        0x00000003FE000000,
        0x0000000001FE0000,
        0x000000000001E000,
    ];

    t0 = in0 as u64;
    t1 = m as u64;

    x = (t1 << 18) * (t0 & (1 << 6));

    t0 ^= t0 << 21;

    x ^= t1 * (t0 & (0x010000001));
    x ^= (t1 * (t0 & (0x020000002))) << 3;
    x ^= (t1 * (t0 & (0x040000004))) << 6;
    x ^= (t1 * (t0 & (0x080000008))) << 9;
    x ^= (t1 * (t0 & (0x100000010))) << 12;
    x ^= (t1 * (t0 & (0x200000020))) << 15;

    for i in 0..6 {
        t = x & M[i];
        x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
    }

    (x & gfmask as u64) as u16
}

/// Computes the division `num/den` — wide family body.
pub(crate) fn gf_frac_wide(den: Gf, num: Gf, gfmask: u16) -> Gf {
    let tmp_11 = gf_sqmul(den, den, gfmask); // ^11
    let tmp_1111 = gf_sq2mul(tmp_11, tmp_11, gfmask); // ^1111
    let mut out = gf_sq2(tmp_1111, gfmask);
    out = gf_sq2mul(out, tmp_1111, gfmask); // ^11111111
    out = gf_sq2(out, gfmask);
    out = gf_sq2mul(out, tmp_1111, gfmask); // ^111111111111

    gf_sqmul(out, num, gfmask) // ^1111111111110 = ^-1
}

/// Computes the inverse element of `den` — wide family body.
pub(crate) fn gf_inv_wide(den: Gf, gfmask: u16) -> Gf {
    gf_frac_wide(den, 1, gfmask)
}

// ── gf_mul_inplace: multiply in GF((2^m)^t); slice-based (not `[Gf; SYS_T]`) so
// this stays param-free source, with the caller supplying a `2*SYS_T-1`-length
// scratch buffer — the fixed-array version cannot be made generic over SYS_T on
// stable Rust for the same reason `shared/controlbits.rs`'s buffers can't be. ──

/// `out`, `in0`, `in1` must all have the same length (`SYS_T`); `prod_scratch` must
/// have length `2*SYS_T - 1`. Reduction taps: 348864/348864f body.
pub(crate) fn gf_mul_inplace_348864(out: &mut [Gf], in0: &[Gf], in1: &[Gf], prod_scratch: &mut [Gf]) {
    let sys_t = out.len();
    debug_assert_eq!(in0.len(), sys_t);
    debug_assert_eq!(in1.len(), sys_t);
    debug_assert_eq!(prod_scratch.len(), 2 * sys_t - 1);
    let prod = prod_scratch;
    prod.fill(0);

    for i in 0..sys_t {
        for j in 0..sys_t {
            prod[i + j] ^= gf_mul_narrow(in0[i], in1[j], 12, 0x0FFF);
        }
    }

    for i in (sys_t..=(sys_t - 1) * 2).rev() {
        prod[i - sys_t + 3] ^= prod[i];
        prod[i - sys_t + 1] ^= prod[i];
        prod[i - sys_t] ^= gf_mul_narrow(prod[i], 2, 12, 0x0FFF);
    }

    out.copy_from_slice(&prod[0..sys_t]);
}

/// Reduction taps: 460896/460896f body.
pub(crate) fn gf_mul_inplace_460896(out: &mut [Gf], in0: &[Gf], in1: &[Gf], prod_scratch: &mut [Gf]) {
    let sys_t = out.len();
    debug_assert_eq!(in0.len(), sys_t);
    debug_assert_eq!(in1.len(), sys_t);
    debug_assert_eq!(prod_scratch.len(), 2 * sys_t - 1);
    let prod = prod_scratch;
    prod.fill(0);

    for i in 0..sys_t {
        for j in 0..sys_t {
            prod[i + j] ^= gf_mul_wide(in0[i], in1[j], 13, 0x1FFF);
        }
    }

    for i in (sys_t..=(sys_t - 1) * 2).rev() {
        prod[i - sys_t + 10] ^= prod[i];
        prod[i - sys_t + 9] ^= prod[i];
        prod[i - sys_t + 6] ^= prod[i];
        prod[i - sys_t] ^= prod[i];
    }

    out.copy_from_slice(&prod[0..sys_t]);
}

/// Reduction taps: 6960119/6960119f body.
pub(crate) fn gf_mul_inplace_6960119(out: &mut [Gf], in0: &[Gf], in1: &[Gf], prod_scratch: &mut [Gf]) {
    let sys_t = out.len();
    debug_assert_eq!(in0.len(), sys_t);
    debug_assert_eq!(in1.len(), sys_t);
    debug_assert_eq!(prod_scratch.len(), 2 * sys_t - 1);
    let prod = prod_scratch;
    prod.fill(0);

    for i in 0..sys_t {
        for j in 0..sys_t {
            prod[i + j] ^= gf_mul_wide(in0[i], in1[j], 13, 0x1FFF);
        }
    }

    for i in (sys_t..=(sys_t - 1) * 2).rev() {
        prod[i - sys_t + 8] ^= prod[i];
        prod[i - sys_t] ^= prod[i];
    }

    out.copy_from_slice(&prod[0..sys_t]);
}

/// Reduction taps: 6688128/6688128f/8192128/8192128f body (shared — both sizes have
/// GFBITS=13 and the same field polynomial).
pub(crate) fn gf_mul_inplace_wide128(out: &mut [Gf], in0: &[Gf], in1: &[Gf], prod_scratch: &mut [Gf]) {
    let sys_t = out.len();
    debug_assert_eq!(in0.len(), sys_t);
    debug_assert_eq!(in1.len(), sys_t);
    debug_assert_eq!(prod_scratch.len(), 2 * sys_t - 1);
    let prod = prod_scratch;
    prod.fill(0);

    for i in 0..sys_t {
        for j in 0..sys_t {
            prod[i + j] ^= gf_mul_wide(in0[i], in1[j], 13, 0x1FFF);
        }
    }

    for i in (sys_t..=(sys_t - 1) * 2).rev() {
        prod[i - sys_t + 7] ^= prod[i];
        prod[i - sys_t + 2] ^= prod[i];
        prod[i - sys_t + 1] ^= prod[i];
        prod[i - sys_t] ^= prod[i];
    }

    out.copy_from_slice(&prod[0..sys_t]);
}

// ── plain `fn(u16) -> u16` / `fn(u16, u16) -> u16` adapters, for callers (e.g.
// `pk_gen::pk_gen_core`) that need a bare function pointer without GFBITS/GFMASK
// baked in per call. Only two pairs exist because GFBITS/GFMASK are uniform within
// each family (12/0x0FFF narrow, 13/0x1FFF wide) across every variant that uses
// them — not one pair per parameter set. ──

pub(crate) fn gf_inv_narrow_fn(a: Gf) -> Gf {
    gf_inv_narrow(a, 12, 0x0FFF)
}

pub(crate) fn gf_mul_narrow_fn(a: Gf, b: Gf) -> Gf {
    gf_mul_narrow(a, b, 12, 0x0FFF)
}

pub(crate) fn gf_inv_wide_fn(a: Gf) -> Gf {
    gf_inv_wide(a, 0x1FFF)
}

pub(crate) fn gf_mul_wide_fn(a: Gf, b: Gf) -> Gf {
    gf_mul_wide(a, b, 13, 0x1FFF)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn narrow_and_wide_mul_agree_with_reference_values() {
        // gf_mul(1, x) == x for both families (multiplicative identity) — cheap,
        // family-agnostic sanity check pending the real per-variant KATs.
        assert_eq!(gf_mul_narrow(1, 0x0ABC, 12, 0x0FFF), 0x0ABC);
        assert_eq!(gf_mul_wide(1, 0x1ABC, 13, 0x1FFF), 0x1ABC);
    }

    #[test]
    fn gf_inv_narrow_is_involution_partner_of_mul() {
        // a * inv(a) == 1 for a != 0, both families — proves gf_inv/gf_mul agree
        // with each other even though gf_inv_narrow's own body never calls gf_mul
        // via gf_frac (348864 defines gf_inv directly, unlike the wide family).
        for a in [1u16, 7, 0x0BCD, 0x0FFE] {
            let inv = gf_inv_narrow(a, 12, 0x0FFF);
            assert_eq!(gf_mul_narrow(a, inv, 12, 0x0FFF), 1, "a=0x{a:04X}");
        }
        for a in [1u16, 7, 0x1BCD, 0x1FFE] {
            let inv = gf_inv_wide(a, 0x1FFF);
            assert_eq!(gf_mul_wide(a, inv, 13, 0x1FFF), 1, "a=0x{a:04X}");
        }
    }
}
