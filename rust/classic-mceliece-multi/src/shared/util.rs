//! Loading/storing data in little-endian fashion and `bitrev`. Adapted from upstream
//! `classic-mceliece-rust` 3.1.0 `src/util.rs` — `store_gf`/`load_gf` take an
//! explicit `gfmask` (0x0FFF for the 348864-family, 0x1FFF for the wide family)
//! instead of importing a crate-level `GFMASK` const, so this file needs no
//! per-variant duplication at all. `bitrev`'s final shift genuinely differs by
//! family (`>> 4` narrow, `>> 3` wide) — kept as two functions.

use super::gf::Gf;

/// Store Gf element `gf` in array `dest`.
#[inline(always)]
pub(crate) fn store_gf(dest: &mut [u8; 2], gf: Gf) {
    *dest = gf.to_le_bytes();
}

/// Interpret 2 bytes from `src` as integer and return it as Gf element, masked to `gfmask`.
#[inline(always)]
pub(crate) fn load_gf(src: &[u8; 2], gfmask: u16) -> Gf {
    u16::from_le_bytes(*src) & gfmask
}

/// Reverse the bits of Gf element `a` — 348864/348864f (12-bit field).
pub(crate) fn bitrev_narrow(mut a: Gf) -> Gf {
    a = ((a & 0x00FF) << 8) | ((a & 0xFF00) >> 8);
    a = ((a & 0x0F0F) << 4) | ((a & 0xF0F0) >> 4);
    a = ((a & 0x3333) << 2) | ((a & 0xCCCC) >> 2);
    a = ((a & 0x5555) << 1) | ((a & 0xAAAA) >> 1);
    a >> 4
}

/// Reverse the bits of Gf element `a` — the other 8 variants (13-bit field).
pub(crate) fn bitrev_wide(mut a: Gf) -> Gf {
    a = ((a & 0x00FF) << 8) | ((a & 0xFF00) >> 8);
    a = ((a & 0x0F0F) << 4) | ((a & 0xF0F0) >> 4);
    a = ((a & 0x3333) << 2) | ((a & 0xCCCC) >> 2);
    a = ((a & 0x5555) << 1) | ((a & 0xAAAA) >> 1);
    a >> 3
}

/// Allocate a `Box<[u8; SIZE]>` directly on the heap without first putting the array
/// on the stack.
#[inline(always)]
pub(crate) fn alloc_boxed_array<const SIZE: usize>() -> alloc::boxed::Box<[u8; SIZE]> {
    alloc::boxed::Box::<[u8; SIZE]>::try_from(alloc::vec![0u8; SIZE].into_boxed_slice()).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_gf() {
        assert_eq!(load_gf(&[0xAB, 0x42], 0x1FFF), 0x02AB);
    }

    #[test]
    fn test_bitrev_narrow() {
        assert_eq!(bitrev_narrow(0b1011_0111_0111_1011), 0b0000_1101_1110_1110);
        assert_eq!(bitrev_narrow(0b0110_1010_0101_1011), 0b0000_1101_1010_0101);
    }

    #[test]
    fn test_bitrev_wide() {
        assert_eq!(bitrev_wide(0b1011_0111_0111_1011), 0b0001_1011_1101_1101);
        assert_eq!(bitrev_wide(0b0110_1010_0101_1011), 0b0001_1011_0100_1010);
    }
}
