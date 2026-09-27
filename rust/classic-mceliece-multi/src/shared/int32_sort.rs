//! Sort an array of i32 elements in constant-time. Byte-identical across all 10
//! parameter sets (zero parameter dependency) — copied verbatim from upstream
//! `classic-mceliece-rust` 3.1.0 `src/int32_sort.rs`.

/// If `a > b`, swap `a` and `b` in-place. Otherwise keep values.
/// Implements `(min(a, b), max(a, b))` in constant time.
const fn int32_minmax(mut a: i32, mut b: i32) -> (i32, i32) {
    let ab: i32 = b ^ a;
    let mut c: i32 = (!b & a) | ((!b | a) & (b.wrapping_sub(a)));
    c ^= ab & (c ^ b);
    c >>= 31;
    c &= ab;
    a ^= c;
    b ^= c;

    (a, b)
}

/// Sort a sequence of integers using a sorting network to achieve constant time.
/// To our understanding, this implements [djbsort](https://sorting.cr.yp.to/).
pub(crate) fn int32_sort(x: &mut [i32]) {
    let n = x.len();
    let (mut top, mut p, mut q, mut r, mut i): (usize, usize, usize, usize, usize);

    if n < 2 {
        return;
    }
    top = 1;
    while top < n.wrapping_sub(top) {
        top += top;
    }

    p = top;
    while p > 0 {
        i = 0;
        while i < n - p {
            if (i & p) == 0 {
                let (tmp_xi, tmp_xip) = int32_minmax(x[i], x[i + p]);
                x[i] = tmp_xi;
                x[i + p] = tmp_xip;
            }
            i += 1;
        }
        i = 0;
        q = top;
        while q > p {
            while i < n - q {
                if (i & p) == 0 {
                    let mut a = x[i + p];
                    r = q;
                    while r > p {
                        let (tmp_a, tmp_xir) = int32_minmax(a, x[i + r]);
                        x[i + r] = tmp_xir;
                        a = tmp_a;
                        r >>= 1;
                    }
                    x[i + p] = a;
                }
                i += 1;
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
    fn test_int32_minmax() {
        let (x, y) = int32_minmax(45, -17);
        assert_eq!((x, y), (-17, 45));

        let (x, y) = int32_minmax(i32::MAX, 2);
        assert_eq!((x, y), (2, i32::MAX));

        let (x, y) = int32_minmax(i32::MAX, i32::MIN);
        assert_eq!((x, y), (i32::MIN, i32::MAX));
    }

    #[test]
    fn test_int32_sort() {
        // Deterministic (no external RNG dependency): a fixed pseudo-random-looking
        // permutation is enough to prove the sorting network is order-preserving.
        let mut array: [i32; 64] = core::array::from_fn(|i| {
            let x = (i as i64 * 2654435761 + 12345) % 1_000_003;
            (x - 500_000) as i32
        });

        int32_sort(&mut array);

        for i in 1..array.len() {
            assert!(array[i] > array[i - 1]);
        }
    }
}
