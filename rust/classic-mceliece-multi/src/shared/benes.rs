//! Beneš network application ("McBits Revisited" by Tung Chou, 2017,
//! <https://eprint.iacr.org/2017/793.pdf>). Adapted from upstream
//! `classic-mceliece-rust` 3.1.0 `src/benes.rs`.
//!
//! Every buffer here is sized by `GFBITS` alone (never `SYS_N`/`SYS_T`), and
//! `GFBITS` only takes two values across all 10 parameter sets — 12 for
//! 348864/348864f, 13 for the other eight (`COND_BYTES` and every local `[u64;64]`/
//! `[u64;32]`/`[u8;512]`/`[u8;1024]` buffer below is therefore uniform *within* each
//! group). That means, unlike `pk_gen.rs`/`operations.rs`, this whole file collapses
//! to exactly two variants — `narrow` (348864/348864f) and `wide` (the other eight)
//! — not one copy per size. `support_gen` takes `s: &mut [Gf]` (a slice, not
//! `[Gf; SYS_N]`) so its one genuinely SYS_N-sized parameter doesn't need a const
//! generic either; the caller (each size-family module) passes a slice of the right
//! runtime length.

use super::gf::Gf;
use super::transpose;
use super::util;

// ── narrow (348864 / 348864f, GFBITS = 12, COND_BYTES = 5888) ──────────────────

/// Layers of the Beneš network for the narrow family.
fn layer_narrow(data: &mut [u64], bits: &[u64], lgs: usize) {
    let mut index = 0;
    let s = 1 << lgs;

    let mut i = 0usize;
    while i < 64 {
        for j in i..(i + s) {
            let mut d = data[j] ^ data[j + s];
            d &= bits[index];
            index += 1;

            data[j] ^= d;
            data[j + s] ^= d;
        }
        i += s * 2;
    }
}

/// Apply Beneš network in-place to array `r` (narrow family: `r` is 512 bytes,
/// `bits` is `COND_BYTES` = 5888 bytes for GFBITS=12).
fn apply_benes_narrow(r: &mut [u8; 512], bits: &[u8], rev: usize) {
    debug_assert_eq!(bits.len(), 5888);
    let mut bs = [0u64; 64];
    let mut cond = [0u64; 64];

    fn sub(a: &[u8], off: usize, len: usize) -> &[u8] {
        &a[off..off + len]
    }

    if rev == 0 {
        for i in 0..64 {
            bs[i] = u64::from_le_bytes(sub(r, i * 8, 8).try_into().unwrap());
        }

        transpose::transpose_64x64_inplace(&mut bs);

        for low in 0..6 {
            for i in 0..64 {
                cond[i] = u32::from_le_bytes(sub(bits, low * 256 + i * 4, 4).try_into().unwrap()) as u64;
            }
            transpose::transpose_64x64_inplace(&mut cond);
            layer_narrow(&mut bs, &cond, low);
        }

        transpose::transpose_64x64_inplace(&mut bs);

        for low in 0..6 {
            for i in 0..32 {
                cond[i] = u64::from_le_bytes(sub(bits, (low + 6) * 256 + i * 8, 8).try_into().unwrap());
            }
            layer_narrow(&mut bs, &cond, low);
        }
        for low in (0..5).rev() {
            for i in 0..32 {
                cond[i] = u64::from_le_bytes(
                    sub(bits, (4 - low + 6 + 6) * 256 + i * 8, 8).try_into().unwrap(),
                );
            }
            layer_narrow(&mut bs, &cond, low);
        }

        transpose::transpose_64x64_inplace(&mut bs);

        for low in (0..6).rev() {
            for i in 0..64 {
                cond[i] = u32::from_le_bytes(
                    sub(bits, (5 - low + 6 + 6 + 5) * 256 + i * 4, 4).try_into().unwrap(),
                ) as u64;
            }
            transpose::transpose_64x64_inplace(&mut cond);
            layer_narrow(&mut bs, &cond, low);
        }

        transpose::transpose_64x64_inplace(&mut bs);

        for i in 0..64 {
            r[i * 8..i * 8 + 8].copy_from_slice(&bs[i].to_le_bytes());
        }
    } else {
        for i in 0..64 {
            bs[i] = u64::from_le_bytes(sub(r, i * 8, 8).try_into().unwrap());
        }

        transpose::transpose_64x64_inplace(&mut bs);

        for low in 0..6 {
            for i in 0..64 {
                cond[i] = u32::from_le_bytes(
                    sub(bits, (2 * 12 - 2) * 256 - low * 256 + i * 4, 4).try_into().unwrap(),
                ) as u64;
            }
            transpose::transpose_64x64_inplace(&mut cond);
            layer_narrow(&mut bs, &cond, low);
        }

        transpose::transpose_64x64_inplace(&mut bs);

        for low in 0..6 {
            for i in 0..32 {
                cond[i] = u64::from_le_bytes(
                    sub(bits, (2 * 12 - 2 - 6) * 256 - low * 256 + i * 8, 8)
                        .try_into()
                        .unwrap(),
                );
            }
            layer_narrow(&mut bs, &cond, low);
        }
        for low in (0..5).rev() {
            for i in 0..32 {
                cond[i] = u64::from_le_bytes(
                    sub(
                        bits,
                        (2 * 12 - 2 - 6 - 6) * 256 - (4 - low) * 256 + i * 8,
                        8,
                    )
                    .try_into()
                    .unwrap(),
                );
                layer_narrow(&mut bs, &cond, low);
            }
        }

        transpose::transpose_64x64_inplace(&mut bs);

        for low in (0..6).rev() {
            for i in 0..64 {
                cond[i] = u32::from_le_bytes(
                    sub(
                        bits,
                        (2 * 12 - 2 - 6 - 6 - 5) * 256 - (5 - low) * 256 + i * 4,
                        4,
                    )
                    .try_into()
                    .unwrap(),
                ) as u64;
            }
            transpose::transpose_64x64_inplace(&mut cond);
            layer_narrow(&mut bs, &cond, low);
        }

        transpose::transpose_64x64_inplace(&mut bs);

        for i in 0..64 {
            r[i * 8..i * 8 + 8].copy_from_slice(&bs[i].to_le_bytes());
        }
    }
}

/// Support generation — 348864/348864f. `s` must have length `SYS_N` (3488);
/// `c` must have length `COND_BYTES` (5888).
pub(crate) fn support_gen_narrow(s: &mut [Gf], c: &[u8]) {
    debug_assert_eq!(c.len(), 5888);
    let mut a: Gf;
    let mut l = [[0u8; (1 << 12) / 8]; 12];

    for i in 0..(1 << 12) {
        a = util::bitrev_narrow(i as Gf);

        for (j, itr_l) in l.iter_mut().enumerate() {
            itr_l[i / 8] |= (((a >> j) & 1) << (i % 8)) as u8;
        }
    }

    for itr_l in l.iter_mut() {
        let arr: &mut [u8; 512] = itr_l;
        apply_benes_narrow(arr, c, 0);
    }

    for (i, itr_s) in s.iter_mut().enumerate() {
        *itr_s = 0;
        for j in (0..=11).rev() {
            *itr_s <<= 1;
            *itr_s |= ((l[j][i / 8] >> (i % 8)) & 1) as u16;
        }
    }
}

// ── wide family (460896, 6688128, 6960119, 8192128, all f/non-f — GFBITS = 13,
// COND_BYTES = 12800) ───────────────────────────────────────────────────────────

/// Inner layers of the Beneš network — wide family.
fn layer_in(data: &mut [[u64; 64]; 2], bits: &[u64; 64], lgs: usize) {
    let mut d: u64;
    let mut index = 0;

    let s = 1 << lgs;

    let mut i = 0usize;
    while i < 64 {
        for j in i..(i + s) {
            d = data[0][j + 0] ^ data[0][j + s];
            d &= bits[index];
            index += 1;

            data[0][j + 0] ^= d;
            data[0][j + s] ^= d;

            d = data[1][j + 0] ^ data[1][j + s];
            d &= bits[index];
            index += 1;

            data[1][j + 0] ^= d;
            data[1][j + s] ^= d;
        }
        i += s * 2;
    }
}

/// Exterior layers of the Beneš network — wide family.
fn layer_ex(data: &mut [[u64; 64]; 2], bits: &[u64], lgs: usize) {
    let mut data0_idx = 0;
    let mut data1_idx = 32;

    let s = 1 << lgs;
    if s == 64 {
        for j in 0..64 {
            let mut d = data[0][j + 0] ^ data[1][j];
            d &= bits[data0_idx];
            data0_idx += 1;

            data[0][j + 0] ^= d;
            data[1][j] ^= d;
        }
    } else {
        let mut i: usize = 0;
        while i < 64 {
            for j in i..(i + s) {
                let mut d = data[0][j + 0] ^ data[0][j + s];
                d &= bits[data0_idx];
                data0_idx += 1;

                data[0][j + 0] ^= d;
                data[0][j + s] ^= d;

                d = data[1][j + 0] ^ data[1][j + s];
                d &= bits[data1_idx];
                data1_idx += 1;

                data[1][j + 0] ^= d;
                data[1][j + s] ^= d;
            }
            i += s * 2;
        }
    }
}

/// Apply Beneš network in-place to array `r` (wide family: `r` is 1024 bytes,
/// `bits` is `COND_BYTES` = 12800 bytes for GFBITS=13).
fn apply_benes_wide(r: &mut [u8; 1024], bits: &[u8], rev: usize) {
    debug_assert_eq!(bits.len(), 12800);
    let mut r_int_v = [[0u64; 64]; 2];
    let mut r_int_h = [[0u64; 64]; 2];
    let mut b_int_v = [0u64; 64];
    let mut b_int_h = [0u64; 64];

    let mut calc_index = if rev == 0 { 0 } else { 12288 };

    for (i, chunk) in r.chunks(16).enumerate() {
        r_int_v[0][i] = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
        r_int_v[1][i] = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
    }

    transpose::transpose(&mut r_int_h[0], r_int_v[0]);
    transpose::transpose(&mut r_int_h[1], r_int_v[1]);

    for iter in 0..=6 {
        for (i, chunk) in bits[calc_index..(calc_index + 512)].chunks(8).enumerate() {
            b_int_v[i] = u64::from_le_bytes(chunk.try_into().unwrap());
        }

        calc_index = if rev == 0 {
            calc_index + 512
        } else {
            calc_index - 512
        };

        transpose::transpose(&mut b_int_h, b_int_v);

        layer_ex(&mut r_int_h, &b_int_h, iter);
    }

    transpose::transpose(&mut r_int_v[0], r_int_h[0]);
    transpose::transpose(&mut r_int_v[1], r_int_h[1]);

    for iter in 0..=5 {
        for (i, chunk) in bits[calc_index..(calc_index + 512)].chunks(8).enumerate() {
            b_int_v[i] = u64::from_le_bytes(chunk.try_into().unwrap());
        }

        calc_index = if rev == 0 {
            calc_index + 512
        } else {
            calc_index - 512
        };

        layer_in(&mut r_int_v, &b_int_v, iter);
    }

    for iter in (0..=4).rev() {
        for (i, chunk) in bits[calc_index..(calc_index + 512)].chunks(8).enumerate() {
            b_int_v[i] = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        calc_index = if rev == 0 {
            calc_index + 512
        } else {
            calc_index - 512
        };

        layer_in(&mut r_int_v, &b_int_v, iter);
    }

    transpose::transpose(&mut r_int_h[0], r_int_v[0]);
    transpose::transpose(&mut r_int_h[1], r_int_v[1]);

    for iter in (0..=6).rev() {
        for (i, chunk) in bits[calc_index..(calc_index + 512)].chunks(8).enumerate() {
            b_int_v[i] = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        calc_index = if rev == 0 || iter == 0 {
            calc_index + 512
        } else {
            calc_index - 512
        };

        transpose::transpose(&mut b_int_h, b_int_v);

        layer_ex(&mut r_int_h, &b_int_h, iter);
    }

    transpose::transpose(&mut r_int_v[0], r_int_h[0]);
    transpose::transpose(&mut r_int_v[1], r_int_h[1]);

    for (i, chunk) in r.chunks_mut(16).enumerate() {
        chunk[0..8].copy_from_slice(&r_int_v[0][i].to_le_bytes());
        chunk[8..16].copy_from_slice(&r_int_v[1][i].to_le_bytes());
    }
}

/// Support generation — the other eight variants. `s` must have length `SYS_N`
/// (per-size: 4608/6688/6960/8192); `c` must have length `COND_BYTES` (12800).
pub(crate) fn support_gen_wide(s: &mut [Gf], c: &[u8]) {
    debug_assert_eq!(c.len(), 12800);
    let mut a: Gf;
    let mut l = [[0u8; (1 << 13) / 8]; 13];

    for i in 0..(1 << 13) {
        a = util::bitrev_wide(i as Gf);

        for (j, itr_l) in l.iter_mut().enumerate() {
            itr_l[i / 8] |= (((a >> j) & 1) << (i % 8)) as u8;
        }
    }

    for itr_l in l.iter_mut() {
        let arr: &mut [u8; 1024] = itr_l;
        apply_benes_wide(arr, c, 0);
    }

    for (i, itr_s) in s.iter_mut().enumerate() {
        *itr_s = 0;
        for j in (0..=12).rev() {
            *itr_s <<= 1;
            *itr_s |= ((l[j][i / 8] >> (i % 8)) & 1) as u16;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Traced to the C reference implementation via upstream's own test (input/output
    // mapping is family-agnostic — GFBITS/SYS_N play no role in `layer` itself).
    #[test]
    fn test_layer_narrow() {
        let mut data = [0u64; 64];
        let mut bits = [0u64; 32];
        for (i, d) in data.iter_mut().enumerate() {
            *d = 0xAAAA ^ (i as u64 * 17);
        }
        for (i, d) in bits.iter_mut().enumerate() {
            *d = (i as u64) << 3;
        }
        layer_narrow(&mut data, &bits, 4);
        assert_eq!(
            data,
            [
                0xAAAA, 0xAABB, 0xAA98, 0xAA89, 0xAAEE, 0xAADF, 0xAADC, 0xAAED, 0xAA22, 0xAA33,
                0xAA10, 0xAA41, 0xAA66, 0xAA57, 0xAA54, 0xAA25, 0xABBA, 0xAB8B, 0xAB88, 0xABF9,
                0xABFE, 0xABEF, 0xABCC, 0xAB1D, 0xAB32, 0xAB03, 0xAB00, 0xAB31, 0xAB76, 0xAB67,
                0xAB44, 0xA8D5, 0xA88A, 0xA89B, 0xA8F8, 0xA8E9, 0xA8CE, 0xA87F, 0xA83C, 0xA80D,
                0xA802, 0xA853, 0xA870, 0xA861, 0xA846, 0xA8B7, 0xA9B4, 0xA985, 0xA99A, 0xA9EB,
                0xA9E8, 0xA9D9, 0xA9DE, 0xA98F, 0xA92C, 0xA93D, 0xA912, 0xA923, 0xA960, 0xA951,
                0xA956, 0xAE47, 0xAEA4, 0xAEB5
            ]
        );
    }

    #[test]
    fn test_layer_ex() {
        let mut data = [[0u64; 64]; 2];
        let mut bits = [0u64; 64];

        for i in 0..64 {
            data[0][i] = 0xFC81 ^ (i as u64 * 17);
            data[1][i] = 0x9837 ^ (i as u64 * 3);
        }
        for i in 0..64 {
            bits[i] = (i as u64) << 3;
        }
        layer_ex(&mut data, &bits, 5);

        assert_eq!(
            data,
            [
                [
                    0xFC81, 0xFC90, 0xFCA3, 0xFCB2, 0xFCE5, 0xFCF4, 0xFCC7, 0xFCD6, 0xFC09, 0xFC18,
                    0xFC6B, 0xFC7A, 0xFC6D, 0xFC7C, 0xFC0F, 0xFC1E, 0xFD91, 0xFDA0, 0xFDB3, 0xFDC2,
                    0xFDF5, 0xFD44, 0xFD57, 0xFD26, 0xFD19, 0xFD68, 0xFD7B, 0xFD4A, 0xFD7D, 0xFD8C,
                    0xFD9F, 0xFEAE, 0xFEA1, 0xFEB0, 0xFEC3, 0xFED2, 0xFEC5, 0xFED4, 0xFE27, 0xFE36,
                    0xFE29, 0xFE38, 0xFE0B, 0xFE1A, 0xFE4D, 0xFE5C, 0xFFEF, 0xFFFE, 0xFFB1, 0xFFC0,
                    0xFFD3, 0xFFE2, 0xFFD5, 0xFFA4, 0xFFB7, 0xFF06, 0xFF39, 0xFF08, 0xFF1B, 0xFF6A,
                    0xFF5D, 0xF86C, 0xF87F, 0xF88E
                ],
                [
                    0x9837, 0x9834, 0x9831, 0x983E, 0x981B, 0x9818, 0x9805, 0x9802, 0x986F, 0x986C,
                    0x9869, 0x9816, 0x9833, 0x9830, 0x983D, 0x983A, 0x9887, 0x9884, 0x9881, 0x988E,
                    0x98AB, 0x98A8, 0x98D5, 0x98D2, 0x98BF, 0x98BC, 0x98B9, 0x98A6, 0x9883, 0x9880,
                    0x988D, 0x988A, 0x9857, 0x9854, 0x9851, 0x985E, 0x987B, 0x9878, 0x9865, 0x9862,
                    0x980F, 0x980C, 0x9809, 0x98B6, 0x9893, 0x9890, 0x989D, 0x989A, 0x9827, 0x9824,
                    0x9821, 0x982E, 0x980B, 0x9808, 0x9835, 0x9832, 0x985F, 0x985C, 0x9859, 0x9846,
                    0x9863, 0x9860, 0x986D, 0x986A
                ]
            ]
        );
    }
}
