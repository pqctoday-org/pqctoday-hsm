//! KMIP TTLV `Value` field — the typed payload of a TTLV frame, plus the
//! `ItemType` byte that precedes it on the wire.
//!
//! See OASIS KMIP 3.0 §9.1.1 for the normative item-type registry and §9.2
//! for the encoding rules of each type.
//!
//! Each [`Value`] variant carries:
//! - the **typed payload** (e.g. `i32` for Integer, `Vec<u8>` for ByteString),
//! - which the [`encode`](super::encode) writer serialises using the rules
//!   in §9.2 (big-endian for numerics, zero-padding to 8-byte alignment for
//!   value bytes), and
//! - which the [`decode`](super::decode) reader reconstructs after reading
//!   the item-type byte and length field.
//!
//! Structures are special: their payload is a sequence of nested TTLV frames
//! (each carrying its own `Tag`). The codec preserves child order, since
//! KMIP ops are order-sensitive (e.g. Common Attributes always precede
//! Private Key Attributes inside a `CreateKeyPair` request).

use super::Tag;

/// KMIP TTLV item-type byte (§9.1.1). Wire-byte value in the right column.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ItemType {
    Structure          = 0x01,
    Integer            = 0x02,
    LongInteger        = 0x03,
    BigInteger         = 0x04,
    Enumeration        = 0x05,
    Boolean            = 0x06,
    TextString         = 0x07,
    ByteString         = 0x08,
    DateTime           = 0x09,
    Interval           = 0x0A,
    DateTimeExtended   = 0x0B,
}

impl ItemType {
    /// Wire byte for this item type.
    #[inline]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }

    /// Reverse mapping. `None` for bytes outside the §9.1.1 registry.
    #[inline]
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Structure),
            0x02 => Some(Self::Integer),
            0x03 => Some(Self::LongInteger),
            0x04 => Some(Self::BigInteger),
            0x05 => Some(Self::Enumeration),
            0x06 => Some(Self::Boolean),
            0x07 => Some(Self::TextString),
            0x08 => Some(Self::ByteString),
            0x09 => Some(Self::DateTime),
            0x0A => Some(Self::Interval),
            0x0B => Some(Self::DateTimeExtended),
            _ => None,
        }
    }
}

/// One TTLV frame — a tagged, typed payload.
///
/// Every variant has wire-encoding rules in OASIS KMIP 3.0 §9.2.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// `[child_0, child_1, …]` — nested TTLV frames in document order.
    ///
    /// §9.2 — the value bytes are themselves a concatenation of complete
    /// TTLV frames, each carrying its own tag/type/length/value.
    Structure(Vec<TtlvFrame>),

    /// Signed 32-bit, big-endian, padded to 8 bytes (§9.2.2).
    Integer(i32),

    /// Signed 64-bit, big-endian, exactly 8 bytes (§9.2.3).
    LongInteger(i64),

    /// Arbitrary-precision signed integer, big-endian two's-complement,
    /// must be a multiple of 8 bytes (§9.2.4). We hold the raw value bytes
    /// because the on-wire size matters for round-trip equality, and the
    /// codec is the layer responsible for ensuring it is a multiple of 8.
    BigInteger(Vec<u8>),

    /// Unsigned 32-bit, big-endian, padded to 8 bytes (§9.2.5). The
    /// codepoint space is per-enum (e.g. `Operation`, `CryptographicAlgorithm`).
    /// We store the raw `u32`; symbolic interpretation belongs to Phase 3
    /// (`src/kmip30/algos.rs` and friends).
    Enumeration(u32),

    /// 8-byte payload (§9.2.6) — wire bytes are `0x0…01` for true, `0x0…00`
    /// for false. The codec rejects other values.
    Boolean(bool),

    /// UTF-8 bytes, zero-padded to 8 (§9.2.7).
    TextString(String),

    /// Arbitrary opaque bytes, zero-padded to 8 (§9.2.8).
    ByteString(Vec<u8>),

    /// POSIX-style seconds since epoch in a signed 64-bit field
    /// (§9.2.9 — encoded as LongInteger, distinguished by item type).
    /// Stored as raw `i64` so the codec is bit-exact even for the OASIS
    /// "now" sentinel value `0x0000_0000_0000_0000`.
    DateTime(i64),

    /// 32-bit unsigned seconds; padded to 8 (§9.2.10).
    Interval(u32),

    /// KMIP 2.0+ extension (§9.2.11). 64-bit signed value carrying
    /// microsecond precision since epoch.
    DateTimeExtended(i64),
}

impl Value {
    /// Item-type byte that goes on the wire for this value.
    pub const fn item_type(&self) -> ItemType {
        match self {
            Value::Structure(_)        => ItemType::Structure,
            Value::Integer(_)          => ItemType::Integer,
            Value::LongInteger(_)      => ItemType::LongInteger,
            Value::BigInteger(_)       => ItemType::BigInteger,
            Value::Enumeration(_)      => ItemType::Enumeration,
            Value::Boolean(_)          => ItemType::Boolean,
            Value::TextString(_)       => ItemType::TextString,
            Value::ByteString(_)       => ItemType::ByteString,
            Value::DateTime(_)         => ItemType::DateTime,
            Value::Interval(_)         => ItemType::Interval,
            Value::DateTimeExtended(_) => ItemType::DateTimeExtended,
        }
    }
}

/// A complete TTLV frame: tag + typed value. The `(Tag, Value)` shape is what
/// every encode / decode site round-trips.
#[derive(Clone, Debug, PartialEq)]
pub struct TtlvFrame {
    pub tag: Tag,
    pub value: Value,
}

impl TtlvFrame {
    #[inline]
    pub const fn new(tag: Tag, value: Value) -> Self {
        TtlvFrame { tag, value }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn item_type_byte_round_trip() {
        for b in [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B] {
            let t = ItemType::from_byte(b).expect("known item type");
            assert_eq!(t.as_byte(), b);
        }
    }

    #[test]
    fn item_type_byte_rejects_unknown() {
        assert!(ItemType::from_byte(0x00).is_none());
        assert!(ItemType::from_byte(0x0C).is_none());
        assert!(ItemType::from_byte(0xff).is_none());
    }

    #[test]
    fn value_item_type_dispatch_covers_all_variants() {
        // Exhaustively check every Value variant maps to the right byte; if a
        // new variant is added without updating `item_type()`, this fails to
        // compile due to the non-exhaustive match.
        let cases: [(Value, ItemType); 11] = [
            (Value::Structure(vec![]),     ItemType::Structure),
            (Value::Integer(0),            ItemType::Integer),
            (Value::LongInteger(0),        ItemType::LongInteger),
            (Value::BigInteger(vec![0; 8]), ItemType::BigInteger),
            (Value::Enumeration(0),        ItemType::Enumeration),
            (Value::Boolean(false),        ItemType::Boolean),
            (Value::TextString(String::new()),    ItemType::TextString),
            (Value::ByteString(vec![]),    ItemType::ByteString),
            (Value::DateTime(0),           ItemType::DateTime),
            (Value::Interval(0),           ItemType::Interval),
            (Value::DateTimeExtended(0),   ItemType::DateTimeExtended),
        ];
        for (v, expected) in cases {
            assert_eq!(v.item_type(), expected);
        }
    }
}
