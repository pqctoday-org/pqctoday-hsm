//! Compute error vector and syndrome to get the ciphertext. Adapted from upstream
//! `classic-mceliece-rust` 3.1.0 `src/encrypt.rs`, slice-based. Two independent
//! axes here, each genuinely 2-way and NOT aligned with the narrow/wide split used
//! elsewhere: `gen_e` splits 8192128-family (direct sampling, no range filter since
//! `SYS_N == 1<<GFBITS` there) vs the other eight (range-reject-and-retry);
//! `syndrome` splits 6960119-family (bit-realignment for its non-byte-aligned
//! `PK_NROWS`) vs the other eight (plain). Since 8192128 and 6960119 are disjoint
//! groups, the three real combinations needed are `gen_e_rangereject +
//! syndrome_plain` (6 of 10: 348864/348864f/460896/460896f/6688128/6688128f),
//! `gen_e_rangereject + syndrome_padded` (6960119/6960119f), and `gen_e_direct +
//! syndrome_plain` (8192128/8192128f) — exposed as three `encrypt_*` entry points.

use super::util::load_gf;
use rand::{CryptoRng, RngCore};

/// Takes two 16-bit integers and determines whether they are equal (u8::MAX) or different (0).
fn same_mask_u8(x: u16, y: u16) -> u8 {
    let mut mask = (x ^ y) as u32;
    mask = mask.wrapping_sub(1);
    mask = mask.wrapping_shr(31);
    mask = 0u32.wrapping_sub(mask);
    (mask & 0xFF) as u8
}

/// The largest SYS_T among all 10 parameter sets.
const MAX_SYS_T: usize = 128;

/// Generation of `e`, an error vector of weight `SYS_T` (`e.len() == SYS_N/8`,
/// `sys_t`/`sys_n`/`gfmask` explicit — this body is shared by both the narrow
/// (0x0FFF) and wide (0x1FFF) families, unlike most other shared files, so the
/// mask can't be hardcoded here) — the 9-of-10 range-reject-and-retry body.
fn gen_e_rangereject<R: CryptoRng + RngCore>(
    e: &mut [u8],
    sys_t: usize,
    sys_n: usize,
    gfmask: u16,
    rng: &mut R,
) {
    debug_assert!(sys_t <= MAX_SYS_T);
    let mut ind = [0u16; MAX_SYS_T];
    let ind = &mut ind[..sys_t];
    let mut val = [0u8; MAX_SYS_T];
    let val = &mut val[..sys_t];

    loop {
        let mut bytes = [0u8; MAX_SYS_T * 4];
        let bytes = &mut bytes[..sys_t * 4];
        rng.fill_bytes(bytes);

        let mut nums = [0u16; MAX_SYS_T * 2];
        let nums = &mut nums[..sys_t * 2];
        for (i, chunk) in bytes.chunks(2).enumerate() {
            nums[i] = load_gf(chunk.try_into().unwrap(), gfmask);
        }

        let mut count = 0;
        for itr_num in nums.iter() {
            if count >= sys_t {
                break;
            }
            if *itr_num < sys_n as u16 {
                ind[count] = *itr_num;
                count += 1;
            }
        }

        if count < sys_t {
            continue;
        }

        let mut eq = 0;
        for i in 1..sys_t {
            for j in 0..i {
                if ind[i] == ind[j] {
                    eq = 1;
                }
            }
        }

        if eq == 0 {
            break;
        }
    }

    for j in 0..sys_t {
        val[j] = 1 << (ind[j] & 7);
    }

    for (i, itr_e) in e.iter_mut().enumerate() {
        *itr_e = 0;
        for j in 0..sys_t {
            let mask: u8 = same_mask_u8(i as u16, ind[j] >> 3);
            *itr_e |= val[j] & mask;
        }
    }
}

/// Generation of `e` — 8192128/8192128f body (no range filter: `SYS_N == 1<<GFBITS`
/// for this size, so every sampled index is already in range).
fn gen_e_direct<R: CryptoRng + RngCore>(e: &mut [u8], sys_t: usize, rng: &mut R) {
    debug_assert!(sys_t <= MAX_SYS_T);
    let sys_n_div_8 = e.len();
    let mut ind = [0u16; MAX_SYS_T];
    let ind = &mut ind[..sys_t];
    let mut bytes = [0u8; MAX_SYS_T * 2];
    let bytes = &mut bytes[..sys_t * 2];
    let mut val = [0u8; MAX_SYS_T];
    let val = &mut val[..sys_t];

    loop {
        rng.fill_bytes(bytes);

        for (i, chunk) in bytes.chunks(2).enumerate() {
            ind[i] = load_gf(chunk.try_into().unwrap(), 0x1FFF);
        }

        let mut eq = 0;
        for i in 1..sys_t {
            for j in 0..i {
                if ind[i] == ind[j] {
                    eq = 1;
                }
            }
        }

        if eq == 0 {
            break;
        }
    }

    for j in 0..sys_t {
        val[j] = 1 << (ind[j] & 7);
    }

    for i in 0..sys_n_div_8 {
        e[i] = 0;
        for j in 0..sys_t {
            let mask: u8 = same_mask_u8(i as u16, ind[j] >> 3);
            e[i] |= val[j] & mask;
        }
    }
}

/// The largest `SYS_N/8` among all 10 parameter sets (8192128/8192128f).
const MAX_SYS_N_DIV_8: usize = 8192 / 8;

/// Syndrome computation — the 8-of-10 plain body. `s.len() == pk_nrows.div_ceil(8)`,
/// `pk.len() == pk_nrows * pk_row_bytes`, `e.len() == sys_n/8`.
fn syndrome_plain(s: &mut [u8], pk: &[u8], e: &[u8], pk_nrows: usize, pk_row_bytes: usize) {
    let sys_n_div_8 = e.len();
    let mut row = [0u8; MAX_SYS_N_DIV_8];
    let row = &mut row[..sys_n_div_8];

    let mut pk_segment = pk;

    s.fill(0);

    for i in 0..pk_nrows {
        row.fill(0);

        for j in 0..pk_row_bytes {
            row[sys_n_div_8 - pk_row_bytes + j] = pk_segment[j];
        }

        row[i / 8] |= 1 << (i % 8);

        let mut b = 0u8;
        for j in 0..sys_n_div_8 {
            b ^= row[j] & e[j];
        }

        b ^= b >> 4;
        b ^= b >> 2;
        b ^= b >> 1;
        b &= 1;

        s[i / 8] |= b << (i % 8);

        pk_segment = &pk_segment[pk_row_bytes..];
    }
}

/// Syndrome computation — 6960119/6960119f body (bit-realignment: `PK_NROWS` isn't a
/// multiple of 8 for this size). Same shapes as [`syndrome_plain`].
fn syndrome_padded(s: &mut [u8], pk: &[u8], e: &[u8], pk_nrows: usize, pk_row_bytes: usize) {
    let sys_n_div_8 = e.len();
    let mut row = [0u8; MAX_SYS_N_DIV_8];
    let row = &mut row[..sys_n_div_8];

    let mut pk_segment = pk;
    let tail = pk_nrows % 8;

    s.fill(0);

    for i in 0..pk_nrows {
        row.fill(0);

        for j in 0..pk_row_bytes {
            row[sys_n_div_8 - pk_row_bytes + j] = pk_segment[j];
        }

        for j in ((sys_n_div_8 - pk_row_bytes)..sys_n_div_8).rev() {
            row[j] = (row[j] << tail) | (row[j - 1] >> (8 - tail));
        }

        row[i / 8] |= 1 << (i % 8);

        let mut b = 0u8;
        for j in 0..sys_n_div_8 {
            b ^= row[j] & e[j];
        }

        b ^= b >> 4;
        b ^= b >> 2;
        b ^= b >> 1;
        b &= 1;

        s[i / 8] |= b << (i % 8);

        pk_segment = &pk_segment[pk_row_bytes..];
    }
}

/// Encryption routine — 6-of-10 (range-reject `gen_e` + plain `syndrome`):
/// 348864, 348864f, 460896, 460896f, 6688128, 6688128f.
#[allow(clippy::too_many_arguments)]
pub(crate) fn encrypt_rangereject_plain<R: CryptoRng + RngCore>(
    s: &mut [u8],
    pk: &[u8],
    e: &mut [u8],
    sys_t: usize,
    sys_n: usize,
    gfmask: u16,
    pk_nrows: usize,
    pk_row_bytes: usize,
    rng: &mut R,
) {
    gen_e_rangereject(e, sys_t, sys_n, gfmask, rng);
    syndrome_plain(s, pk, e, pk_nrows, pk_row_bytes);
}

/// Encryption routine — 6960119/6960119f (range-reject `gen_e` + padded `syndrome`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn encrypt_rangereject_padded<R: CryptoRng + RngCore>(
    s: &mut [u8],
    pk: &[u8],
    e: &mut [u8],
    sys_t: usize,
    sys_n: usize,
    gfmask: u16,
    pk_nrows: usize,
    pk_row_bytes: usize,
    rng: &mut R,
) {
    gen_e_rangereject(e, sys_t, sys_n, gfmask, rng);
    syndrome_padded(s, pk, e, pk_nrows, pk_row_bytes);
}

/// Encryption routine — 8192128/8192128f (direct `gen_e` + plain `syndrome`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn encrypt_direct_plain<R: CryptoRng + RngCore>(
    s: &mut [u8],
    pk: &[u8],
    e: &mut [u8],
    sys_t: usize,
    pk_nrows: usize,
    pk_row_bytes: usize,
    rng: &mut R,
) {
    gen_e_direct(e, sys_t, rng);
    syndrome_plain(s, pk, e, pk_nrows, pk_row_bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::XorShiftRng;

    #[test]
    fn test_encrypt_rangereject_plain_smoke() {
        // Structural smoke test only — proves the slice-length plumbing across
        // gen_e + syndrome doesn't panic for a plausible 348864-shaped call. Real
        // per-variant KATs live in each size-family module.
        const SYS_T: usize = 64;
        const SYS_N: usize = 3488;
        const PK_NROWS: usize = SYS_T * 12;
        const PK_NCOLS: usize = SYS_N - PK_NROWS;
        const PK_ROW_BYTES: usize = PK_NCOLS.div_ceil(8);
        let pk = alloc::vec![0u8; PK_NROWS * PK_ROW_BYTES];
        let mut e = alloc::vec![0u8; SYS_N / 8];
        let mut s = alloc::vec![0u8; PK_NROWS.div_ceil(8)];
        let mut rng = XorShiftRng::new(42);
        encrypt_rangereject_plain(
            &mut s, &pk, &mut e, SYS_T, SYS_N, 0x0FFF, PK_NROWS, PK_ROW_BYTES, &mut rng,
        );
    }
}
