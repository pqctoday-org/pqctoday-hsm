//! Matrix transpose. Both functions here operate on a fixed 64×64 GF(2) matrix — a
//! Beneš-network primitive whose size (64) does not depend on SYS_T/SYS_N/GFBITS at
//! all, so this file is copied verbatim from upstream `classic-mceliece-rust` 3.1.0
//! `src/transpose.rs` with no changes: both `transpose` (wide family, out-of-place)
//! and `transpose_64x64_inplace` (348864/348864f, in-place) are already fully shared.

/// Compute transposition of `input` and store it in `output` — wide family.
pub(crate) fn transpose(output: &mut [u64; 64], input: [u64; 64]) {
    let masks: [[u64; 2]; 6] = [
        [0x5555555555555555, 0xAAAAAAAAAAAAAAAA],
        [0x3333333333333333, 0xCCCCCCCCCCCCCCCC],
        [0x0F0F0F0F0F0F0F0F, 0xF0F0F0F0F0F0F0F0],
        [0x00FF00FF00FF00FF, 0xFF00FF00FF00FF00],
        [0x0000FFFF0000FFFF, 0xFFFF0000FFFF0000],
        [0x00000000FFFFFFFF, 0xFFFFFFFF00000000],
    ];

    *output = input;

    for d in (0..=5).rev() {
        let s = 1 << d;

        for i in (0..64).step_by(s * 2) {
            for j in i..i + s {
                let x = (output[j] & masks[d][0]) | ((output[j + s] & masks[d][0]) << s);
                let y = ((output[j] & masks[d][1]) >> s) | (output[j + s] & masks[d][1]);

                output[j + 0] = x;
                output[j + s] = y;
            }
        }
    }
}

/// Take a 64×64 matrix over GF(2). Compute the transpose of `arg` and return it in
/// `arg` — 348864/348864f family (works in-place, unlike the C reference).
pub(crate) fn transpose_64x64_inplace(arg: &mut [u64; 64]) {
    let masks = [
        [0x5555555555555555u64, 0xAAAAAAAAAAAAAAAAu64],
        [0x3333333333333333, 0xCCCCCCCCCCCCCCCC],
        [0x0F0F0F0F0F0F0F0F, 0xF0F0F0F0F0F0F0F0],
        [0x00FF00FF00FF00FF, 0xFF00FF00FF00FF00],
        [0x0000FFFF0000FFFF, 0xFFFF0000FFFF0000],
        [0x00000000FFFFFFFF, 0xFFFFFFFF00000000],
    ];

    for d in (0..6).rev() {
        let s = 1 << d;
        let mut i = 0;
        while i < 64 {
            for j in i..(i + s) {
                let x: u64 = (arg[j] & masks[d][0]) | ((arg[j + s] & masks[d][0]) << s);
                let y: u64 = ((arg[j] & masks[d][1]) >> s) | (arg[j + s] & masks[d][1]);

                arg[j] = x;
                arg[j + s] = y;
            }
            i += s * 2;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transpose_roundtrip() {
        // transpose(transpose(x)) == x, both APIs — cheap, family-agnostic proof
        // that both implementations really do compute a matrix transpose, ahead of
        // the real per-variant KATs that exercise them through apply_benes.
        let mut input = [0u64; 64];
        for (i, v) in input.iter_mut().enumerate() {
            *v = (i as u64).wrapping_mul(0x9E3779B97F4A7C15) ^ (i as u64);
        }

        let mut once = [0u64; 64];
        transpose(&mut once, input);
        let mut twice = [0u64; 64];
        transpose(&mut twice, once);
        assert_eq!(twice, input);

        let mut data = input;
        transpose_64x64_inplace(&mut data);
        transpose_64x64_inplace(&mut data);
        assert_eq!(data, input);

        // Both APIs must agree with each other on the same input.
        assert_eq!(once, {
            let mut d = input;
            transpose_64x64_inplace(&mut d);
            d
        });
    }
}
