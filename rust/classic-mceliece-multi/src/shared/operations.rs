//! KEM orchestration: `crypto_kem_keypair` / `crypto_kem_enc` / `crypto_kem_dec`.
//! Adapted from upstream `classic-mceliece-rust` 3.1.0 `src/operations.rs`.
//!
//! Four `crypto_kem_keypair_*` variants matching `pk_gen`'s own four-way axis
//! (plain / 6960119 / f / f_6960119f — see `shared/pk_gen.rs`'s module doc), each
//! written out directly rather than unified behind a closure: the orchestration
//! loop itself is short (~60 lines) and identical in structure across all four, so
//! duplicating it four times is a smaller correctness risk than inventing a runtime
//! dispatch scheme for pk_gen's differing `pivots`/writeback signature. `enc`/`dec`
//! split 2-way (6960119-family padded vs the other eight plain), matching
//! `encrypt.rs`.

use super::crypto_hash::shake256;
use super::util::store_gf;
use rand::{CryptoRng, RngCore};

/// This function determines (in a constant-time manner) whether the padding bits of
/// `pk` are all zero. `pk.len() == pk_nrows * pk_row_bytes`.
fn check_pk_padding(pk: &[u8], pk_nrows: usize, pk_row_bytes: usize, pk_ncols: usize) -> u8 {
    let mut b = 0u8;
    for i in 0..pk_nrows {
        b |= pk[i * pk_row_bytes + pk_row_bytes - 1];
    }
    b >>= pk_ncols % 8;
    b = b.wrapping_sub(1);
    b >>= 7;
    b.wrapping_sub(1)
}

/// This function determines (in a constant-time manner) whether the padding bits of
/// `c` are all zero.
fn check_c_padding(c: &[u8], pk_nrows: usize) -> u8 {
    let mut b = c[c.len() - 1] >> (pk_nrows % 8);
    b = b.wrapping_sub(1);
    b >>= 7;
    b.wrapping_sub(1)
}

/// KEM Encapsulation — the 8-of-10 plain body (everyone except 6960119/6960119f).
/// `encrypt_fn` is one of `encrypt::encrypt_rangereject_plain` (curried down to this
/// shape by the caller) or `encrypt::encrypt_direct_plain`.
pub(crate) fn crypto_kem_enc_plain<R: CryptoRng + RngCore>(
    c: &mut [u8],
    key: &mut [u8; 32],
    pk: &[u8],
    e_buf: &mut [u8],
    rng: &mut R,
    mut encrypt: impl FnMut(&mut [u8], &[u8], &mut [u8], &mut R),
) {
    let sys_n_div_8 = e_buf.len();
    let synd_bytes = c.len();

    let mut one_ec = alloc::vec![0u8; 1 + sys_n_div_8 + synd_bytes];
    one_ec[0] = 1;

    encrypt(c, pk, e_buf, rng);

    one_ec[1..1 + sys_n_div_8].copy_from_slice(e_buf);
    one_ec[1 + sys_n_div_8..1 + sys_n_div_8 + synd_bytes].copy_from_slice(&c[..synd_bytes]);

    shake256(key, &one_ec);
}

/// KEM Encapsulation — 6960119/6960119f (padded).
pub(crate) fn crypto_kem_enc_padded<R: CryptoRng + RngCore>(
    c: &mut [u8],
    key: &mut [u8; 32],
    pk: &[u8],
    e_buf: &mut [u8],
    rng: &mut R,
    pk_nrows: usize,
    pk_row_bytes: usize,
    pk_ncols: usize,
    mut encrypt: impl FnMut(&mut [u8], &[u8], &mut [u8], &mut R),
) -> u8 {
    let sys_n_div_8 = e_buf.len();
    let synd_bytes = c.len();

    let mut one_ec = alloc::vec![0u8; 1 + sys_n_div_8 + synd_bytes];
    one_ec[0] = 1;

    let padding_ok = check_pk_padding(pk, pk_nrows, pk_row_bytes, pk_ncols);

    encrypt(c, pk, e_buf, rng);

    one_ec[1..1 + sys_n_div_8].copy_from_slice(e_buf);
    one_ec[1 + sys_n_div_8..1 + sys_n_div_8 + synd_bytes].copy_from_slice(&c[..synd_bytes]);

    shake256(key, &one_ec);

    let mask = padding_ok ^ 0xFF;
    for b in c.iter_mut().take(synd_bytes) {
        *b &= mask;
    }
    for b in key.iter_mut() {
        *b &= mask;
    }

    padding_ok
}

/// KEM Decapsulation — the 8-of-10 plain body.
pub(crate) fn crypto_kem_dec_plain(
    key: &mut [u8; 32],
    c: &[u8],
    sk_irr_cond: &[u8],
    sk_s: &[u8],
    e_buf: &mut [u8],
    decrypt: impl FnOnce(&mut [u8], &[u8], &[u8]) -> u8,
) -> u8 {
    let sys_n_div_8 = e_buf.len();
    let synd_bytes = c.len();

    let mut preimage = alloc::vec![0u8; 1 + sys_n_div_8 + synd_bytes];

    let ret_decrypt: u8 = decrypt(e_buf, sk_irr_cond, c);

    let mut m = ret_decrypt as u16;
    m = m.wrapping_sub(1);
    m >>= 8;

    preimage[0] = (m & 1) as u8;

    for i in 0..sys_n_div_8 {
        preimage[1 + i] = (!m as u8 & sk_s[i]) | (m as u8 & e_buf[i]);
    }

    preimage[1 + sys_n_div_8..1 + sys_n_div_8 + synd_bytes].copy_from_slice(&c[..synd_bytes]);

    shake256(key, &preimage);

    0
}

/// KEM Decapsulation — 6960119/6960119f (padded).
pub(crate) fn crypto_kem_dec_padded(
    key: &mut [u8; 32],
    c: &[u8],
    sk_irr_cond: &[u8],
    sk_s: &[u8],
    e_buf: &mut [u8],
    pk_nrows: usize,
    decrypt: impl FnOnce(&mut [u8], &[u8], &[u8]) -> u8,
) -> u8 {
    let sys_n_div_8 = e_buf.len();
    let synd_bytes = c.len();

    let mut preimage = alloc::vec![0u8; 1 + sys_n_div_8 + synd_bytes];

    let padding_ok = check_c_padding(c, pk_nrows);

    let ret_decrypt: u8 = decrypt(e_buf, sk_irr_cond, c);

    let mut m = ret_decrypt as u16;
    m = m.wrapping_sub(1);
    m >>= 8;

    preimage[0] = (m & 1) as u8;

    for i in 0..sys_n_div_8 {
        preimage[1 + i] = (!m as u8 & sk_s[i]) | (m as u8 & e_buf[i]);
    }

    preimage[1 + sys_n_div_8..1 + sys_n_div_8 + synd_bytes].copy_from_slice(&c[..synd_bytes]);

    shake256(key, &preimage);

    let mask = padding_ok;
    for b in key.iter_mut() {
        *b |= mask;
    }

    padding_ok
}

/// Sizes needed by keypair generation, gathered so each of the four
/// `crypto_kem_keypair_*` variants below takes one struct instead of a dozen
/// separate `usize`/`u16` arguments.
#[derive(Clone, Copy)]
pub(crate) struct KeypairSizes {
    pub(crate) sys_n: usize,
    pub(crate) sys_t: usize,
    pub(crate) gfbits: usize,
    pub(crate) gfmask: u16,
    pub(crate) cond_bytes: usize,
    pub(crate) irr_bytes: usize,
    pub(crate) pk_nrows: usize,
    pub(crate) pk_row_bytes: usize,
}

type RootFn = fn(&mut [u16], &[u16], &[u16]);
type BitrevFn = fn(u16) -> u16;
type GfInvFn = fn(u16) -> u16;
type GfMulFn = fn(u16, u16) -> u16;
type GenpolyGenFn = fn(&mut [u16], &[u16]) -> isize;

/// Shared seed-expansion / retry-loop body. `pk_gen_call` wraps whichever of
/// `pk_gen::pk_gen_plain` / `_6960119` / `_f` / `_f_6960119f` this variant needs
/// (each already curried to a uniform `FnMut(&mut [u8], &[u8], &[u32], &mut [i16])
/// -> i32` by its caller below) and `finalize_pivots` writes the final 8
/// pivot-position bytes (`0xFFFFFFFF` for non-`f`, or whatever `pk_gen` computed,
/// for `f`).
#[allow(clippy::too_many_arguments)]
fn crypto_kem_keypair_core<R: CryptoRng + RngCore>(
    pk: &mut [u8],
    sk: &mut [u8],
    rng: &mut R,
    sizes: KeypairSizes,
    genpoly_gen: GenpolyGenFn,
    mut pk_gen_call: impl FnMut(&mut [u8], &[u8], &[u32], &mut [i16]) -> i32,
    mut finalize_pivots: impl FnMut() -> u64,
) {
    let sys_n = sizes.sys_n;
    let sys_t = sizes.sys_t;
    let gfbits = sizes.gfbits;
    let cond_bytes = sizes.cond_bytes;
    let irr_bytes = sizes.irr_bytes;

    let mut seed = [0u8; 33];
    seed[0] = 64;

    let s_base = 32 + 8 + irr_bytes + cond_bytes;
    let seed_end = sys_n / 8 + (1 << gfbits) * 4 + sys_t * 2;
    let irr_polys = sys_n / 8 + (1 << gfbits) * 4;
    let perm = sys_n / 8;

    let mut r = alloc::vec![0u8; seed_end + 32];

    let mut f = alloc::vec![0u16; sys_t];
    let mut irr = alloc::vec![0u16; sys_t];

    let mut perm_arr = alloc::vec![0u32; 1 << gfbits];
    let mut pi = alloc::vec![0i16; 1 << gfbits];

    rng.fill_bytes(&mut seed[1..]);

    loop {
        shake256(&mut r[..], &seed[0..33]);

        sk[..32].copy_from_slice(&seed[1..]);
        seed[1..].copy_from_slice(&r[r.len() - 32..]);

        for (i, chunk) in r[irr_polys..seed_end].chunks(2).enumerate() {
            f[i] = u16::from_le_bytes(chunk.try_into().unwrap()) & sizes.gfmask;
        }

        if genpoly_gen(&mut irr, &f) != 0 {
            continue;
        }

        for (i, chunk) in sk[40..40 + irr_bytes].chunks_mut(2).enumerate() {
            store_gf(chunk.try_into().unwrap(), irr[i]);
        }

        for (i, chunk) in r[perm..irr_polys].chunks(4).enumerate() {
            perm_arr[i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }

        if pk_gen_call(pk, &sk[40..40 + irr_bytes], &perm_arr, &mut pi) != 0 {
            continue;
        }

        let mut temp = alloc::vec![0i32; 2 * (1 << gfbits)];
        let mut pi_as_i32 = alloc::vec![0i32; 1 << (gfbits - 1)];
        let mut pi_test = alloc::vec![0i16; 1 << gfbits];
        super::controlbits::controlbitsfrompermutation(
            &mut sk[(40 + irr_bytes)..(40 + irr_bytes + cond_bytes)],
            &pi,
            gfbits,
            1 << gfbits,
            &mut temp,
            &mut pi_as_i32,
            &mut pi_test,
        );

        sk[s_base..s_base + sys_n / 8].copy_from_slice(&r[0..sys_n / 8]);

        let pivots = finalize_pivots();
        sk[32..40].copy_from_slice(&pivots.to_le_bytes());

        break;
    }
}

/// Public entry point for the four non-`f` / `f` × plain / 6960119 combinations —
/// the caller (each size-family module) supplies the right `root_fn`/`bitrev_fn`/
/// `gf_inv_fn`/`gf_mul_fn`/`genpoly_gen` for its family and picks the matching
/// `pk_gen::pk_gen_*` function.
#[allow(clippy::too_many_arguments)]
pub(crate) fn crypto_kem_keypair_plain<R: CryptoRng + RngCore>(
    pk: &mut [u8],
    sk: &mut [u8],
    rng: &mut R,
    sizes: KeypairSizes,
    root_fn: RootFn,
    bitrev_fn: BitrevFn,
    gf_inv_fn: GfInvFn,
    gf_mul_fn: GfMulFn,
    genpoly_gen: GenpolyGenFn,
) {
    crypto_kem_keypair_core(
        pk,
        sk,
        rng,
        sizes,
        genpoly_gen,
        |pk, sk_irr, perm, pi| {
            super::pk_gen::pk_gen_plain(
                pk, sk_irr, perm, pi, sizes.sys_n, sizes.sys_t, sizes.gfbits, sizes.gfmask,
                sizes.pk_nrows, sizes.pk_row_bytes, root_fn, bitrev_fn, gf_inv_fn, gf_mul_fn,
            )
        },
        || 0xFFFFFFFFu64,
    );
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn crypto_kem_keypair_6960119<R: CryptoRng + RngCore>(
    pk: &mut [u8],
    sk: &mut [u8],
    rng: &mut R,
    sizes: KeypairSizes,
    root_fn: RootFn,
    bitrev_fn: BitrevFn,
    gf_inv_fn: GfInvFn,
    gf_mul_fn: GfMulFn,
    genpoly_gen: GenpolyGenFn,
) {
    crypto_kem_keypair_core(
        pk,
        sk,
        rng,
        sizes,
        genpoly_gen,
        |pk, sk_irr, perm, pi| {
            super::pk_gen::pk_gen_6960119(
                pk, sk_irr, perm, pi, sizes.sys_n, sizes.sys_t, sizes.gfbits, sizes.gfmask,
                sizes.pk_nrows, sizes.pk_row_bytes, root_fn, bitrev_fn, gf_inv_fn, gf_mul_fn,
            )
        },
        || 0xFFFFFFFFu64,
    );
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn crypto_kem_keypair_f<R: CryptoRng + RngCore>(
    pk: &mut [u8],
    sk: &mut [u8],
    rng: &mut R,
    sizes: KeypairSizes,
    root_fn: RootFn,
    bitrev_fn: BitrevFn,
    gf_inv_fn: GfInvFn,
    gf_mul_fn: GfMulFn,
    genpoly_gen: GenpolyGenFn,
) {
    let pivots = core::cell::Cell::new(0u64);
    crypto_kem_keypair_core(
        pk,
        sk,
        rng,
        sizes,
        genpoly_gen,
        |pk, sk_irr, perm, pi| {
            let mut pv = pivots.get();
            let rc = super::pk_gen::pk_gen_f(
                pk, sk_irr, perm, pi, &mut pv, sizes.sys_n, sizes.sys_t, sizes.gfbits,
                sizes.gfmask, sizes.pk_nrows, sizes.pk_row_bytes, root_fn, bitrev_fn, gf_inv_fn,
                gf_mul_fn,
            );
            pivots.set(pv);
            rc
        },
        || pivots.get(),
    );
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn crypto_kem_keypair_f_6960119f<R: CryptoRng + RngCore>(
    pk: &mut [u8],
    sk: &mut [u8],
    rng: &mut R,
    sizes: KeypairSizes,
    root_fn: RootFn,
    bitrev_fn: BitrevFn,
    gf_inv_fn: GfInvFn,
    gf_mul_fn: GfMulFn,
    genpoly_gen: GenpolyGenFn,
) {
    let pivots = core::cell::Cell::new(0u64);
    crypto_kem_keypair_core(
        pk,
        sk,
        rng,
        sizes,
        genpoly_gen,
        |pk, sk_irr, perm, pi| {
            let mut pv = pivots.get();
            let rc = super::pk_gen::pk_gen_f_6960119f(
                pk, sk_irr, perm, pi, &mut pv, sizes.sys_n, sizes.sys_t, sizes.gfbits,
                sizes.gfmask, sizes.pk_nrows, sizes.pk_row_bytes, root_fn, bitrev_fn, gf_inv_fn,
                gf_mul_fn,
            );
            pivots.set(pv);
            rc
        },
        || pivots.get(),
    );
}
