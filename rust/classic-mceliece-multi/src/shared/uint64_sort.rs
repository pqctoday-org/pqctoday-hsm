//! Sort an array of u64 elements in constant-time. Already const-generic on stable
//! Rust upstream (`fn uint64_sort<const N: usize>`), so byte-identical across all 10
//! parameter sets with zero further change needed — copied verbatim from upstream
//! `classic-mceliece-rust` 3.1.0 `src/uint64_sort.rs`.
//!
//! `#[allow(dead_code)]`: no current call site in this fork actually has a
//! compile-time-known `N` to instantiate this with — `pk_gen.rs`'s only sort
//! (`1 << GFBITS` elements) needs `GFBITS` at runtime inside one shared, non-generic
//! function (see `shared/pk_gen.rs::slice_uint64_sort`, the runtime-length
//! equivalent this fork actually uses there), so this const-generic version is kept
//! only as a faithful, tested port of upstream's own API for a future
//! variant-specific fast path, not as currently-live code.

/// If `a > b`, swap `a` and `b` in-place. Otherwise keep values.
///
/// This differs from the C implementation, because the C implementation
/// only works for 63-bit integers. Instead this implementation is based on
/// "side-channel effective overflow check of variable c" from the book
/// "Hacker's Delight" 2–13 Overflow Detection, Section Unsigned Add/Subtract p. 40
#[allow(dead_code)]
const fn uint64_minmax(mut a: u64, mut b: u64) -> (u64, u64) {
    let d: u64 = (!b & a) | ((!b | a) & (b.wrapping_sub(a)));
    let mut c: u64 = d >> 63;
    c = 0u64.wrapping_sub(c);
    c &= a ^ b;
    a ^= c;
    b ^= c;

    (a, b)
}

/// Sort a sequence of integers using a sorting network to achieve constant time.
/// To our understanding, this implements [djbsort](https://sorting.cr.yp.to/).
#[allow(dead_code)]
pub(crate) fn uint64_sort<const N: usize>(x: &mut [u64; N]) {
    if N < 2 {
        return;
    }
    let mut top = 1;

    while top < N.wrapping_sub(top) {
        top += top;
    }

    let mut p = top;
    while p > 0 {
        for i in 0..(N - p) {
            if (i & p) == 0 {
                let (tmp_xi, tmp_xip) = uint64_minmax(x[i], x[i + p]);
                x[i] = tmp_xi;
                x[i + p] = tmp_xip;
            }
        }
        let mut q = top;
        while q > p {
            for i in 0..(N - q) {
                if (i & p) == 0 {
                    let mut a = x[i + p];
                    let mut r = q;
                    while r > p {
                        let (tmp_a, tmp_xir) = uint64_minmax(a, x[i + r]);
                        x[i + r] = tmp_xir;
                        a = tmp_a;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uint64_minmax() {
        assert_eq!(uint64_minmax(42, 10), (10, 42));
        assert_eq!(uint64_minmax(0xffffffffffffffff, 1), (1, 0xffffffffffffffff));
    }

    #[test]
    fn test_uint64_sort() {
        let mut array: [u64; 64] = core::array::from_fn(|i| {
            ((i as u64).wrapping_mul(2654435761)).wrapping_add(12345) % 1_000_003
        });

        uint64_sort(&mut array);

        for i in 1..array.len() {
            assert!(array[i] >= array[i - 1]);
        }
    }
}
