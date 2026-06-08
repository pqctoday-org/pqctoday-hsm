//! KMIP TTLV `Tag` field — 24-bit big-endian codepoint identifying the
//! semantic role of a value in a KMIP message.
//!
//! Tags occupy the wire format's first 3 bytes (see [`super::mod`]'s
//! diagram). The OASIS-published codepoints we recognise are extracted
//! into `spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json` by
//! `tools/extract_kmip_spec.rs` (Phase 1).
//!
//! ## Why a newtype, not a closed enum
//!
//! The Phase-1 extraction landed **395** tag codepoints. Encoding all of
//! them as named enum variants would mean hand-mirroring the OASIS
//! registry; the registry can grow at any revision and that's not the
//! source of truth we want to maintain in this file. Instead `Tag` is a
//! transparent `u32` newtype with:
//!
//! - Compile-time constants for the tags we actually USE in our op
//!   handlers, generated from the Phase-3 algo / attr / op tables and
//!   centralised here so encode/decode round-trip them by name.
//! - A free-form constructor for anything else, so the codec can round-trip
//!   unknown-to-us-but-valid tags from a real client.
//!
//! The wire encoding only cares about the 24-bit codepoint; symbolic names
//! are a developer convenience.

use std::fmt;

/// 24-bit KMIP TTLV tag codepoint.
///
/// Wire layout: 3 big-endian bytes (`[byte_0, byte_1, byte_2]`) where
/// `byte_0 << 16 | byte_1 << 8 | byte_2` is the codepoint. Codepoints
/// above `0x00FFFFFF` cannot fit and are rejected at construction.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Tag(pub u32);

impl Tag {
    /// Construct from a raw codepoint. Returns `None` if the value does not
    /// fit in 24 bits.
    #[inline]
    pub const fn new(codepoint: u32) -> Option<Self> {
        if codepoint > 0x00_FF_FF_FF { None } else { Some(Tag(codepoint)) }
    }

    /// Raw codepoint as a `u32` (high byte is always zero).
    #[inline]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Big-endian 3-byte wire encoding.
    #[inline]
    pub fn to_be_bytes(self) -> [u8; 3] {
        let b = self.0.to_be_bytes();
        // b is [00, MSB, mid, LSB] because high byte is always 0.
        [b[1], b[2], b[3]]
    }

    /// Construct from a 3-byte big-endian wire encoding.
    #[inline]
    pub fn from_be_bytes(b: [u8; 3]) -> Self {
        Tag(((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32))
    }
}

impl fmt::Debug for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Show the canonical KMIP spelling: 6 hex digits, lowercase.
        // e.g. `Tag(0x420028)`.
        write!(f, "Tag(0x{:06x})", self.0)
    }
}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:06x}", self.0)
    }
}

// ── Tags used by the codec's own KAT vectors and the v0.1 op set ────────────
//
// These names match the OASIS extraction (see
// spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json) and are the symbolic
// surface the rest of the subsystem reaches for. Add a constant here when
// a new op handler or attribute needs to encode/decode a specific tag by
// name; keep the list narrow — for unknown tags the codec uses `Tag::new`
// directly without needing a symbolic name.

impl Tag {
    pub const ACTIVATION_DATE: Tag = Tag(0x42_00_01);
    pub const APPLICATION_DATA: Tag = Tag(0x42_00_02);
    pub const APPLICATION_NAMESPACE: Tag = Tag(0x42_00_03);
    pub const BATCH_COUNT: Tag = Tag(0x42_00_0d);
    pub const BATCH_ITEM: Tag = Tag(0x42_00_0f);
    pub const CRYPTOGRAPHIC_ALGORITHM: Tag = Tag(0x42_00_28);
    pub const CRYPTOGRAPHIC_LENGTH: Tag = Tag(0x42_00_2a);
    pub const OBJECT_TYPE: Tag = Tag(0x42_00_57);
    pub const OPERATION: Tag = Tag(0x42_00_5c);
    pub const PROTOCOL_VERSION: Tag = Tag(0x42_00_69);
    pub const PROTOCOL_VERSION_MAJOR: Tag = Tag(0x42_00_6a);
    pub const PROTOCOL_VERSION_MINOR: Tag = Tag(0x42_00_6b);
    pub const REQUEST_HEADER: Tag = Tag(0x42_00_77);
    pub const REQUEST_MESSAGE: Tag = Tag(0x42_00_78);
    pub const REQUEST_PAYLOAD: Tag = Tag(0x42_00_79);
    pub const UNIQUE_IDENTIFIER: Tag = Tag(0x42_00_94);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_24bit_bytes() {
        for cp in [0x000000, 0x420001, 0x42005c, 0x420094, 0xffffff] {
            let t = Tag::new(cp).expect("in-range");
            let b = t.to_be_bytes();
            assert_eq!(Tag::from_be_bytes(b), t);
            assert_eq!(t.as_u32(), cp);
        }
    }

    #[test]
    fn rejects_codepoints_above_24_bit() {
        assert!(Tag::new(0x01_00_00_00).is_none());
        assert!(Tag::new(0xffff_ffff).is_none());
    }

    #[test]
    fn debug_format_matches_spec_notation() {
        let t = Tag::CRYPTOGRAPHIC_ALGORITHM;
        assert_eq!(format!("{t:?}"), "Tag(0x420028)");
        assert_eq!(format!("{t}"),   "0x420028");
    }

    #[test]
    fn batch_count_constant_matches_kat_vector() {
        // kat/ttlv-wire/01-integer-batch-count-1.bin starts with the bytes
        // [42 00 0d 02 …]; the first 3 bytes are the BatchCount tag.
        let bytes: [u8; 3] = Tag::BATCH_COUNT.to_be_bytes();
        assert_eq!(bytes, [0x42, 0x00, 0x0d]);
    }

    #[test]
    fn cryptographic_algorithm_constant_matches_pqc_kat_vector() {
        // kat/ttlv-wire/03-enum-cryptographic-algorithm-ml-kem-768.bin starts
        // with [42 00 28 05 …]; first 3 bytes are CryptographicAlgorithm.
        assert_eq!(Tag::CRYPTOGRAPHIC_ALGORITHM.to_be_bytes(), [0x42, 0x00, 0x28]);
    }
}
