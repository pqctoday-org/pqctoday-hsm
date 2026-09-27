//! KMIP TTLV `Value` field — the typed payload of a TTLV frame, plus the
//! `ItemType` byte that precedes it on the wire.
//!
//! See OASIS KMIP 3.0 CSD02 §11.25 for the normative Item Type enumeration and
//! §10.1.2 for the per-type encoding rules (§10.1.3 length, §10.1.5 padding).
//!
//! Citation note (2026-09-06): these previously read "§9.1.1 / §10.1.2", which are
//! KMIP 2.x section numbers — in CSD02 §9.x is Message Data Structures. The
//! `section61_citation_drift` test only guards §6.1.x, so these drifted unseen.
//!
//! Each [`Value`] variant carries:
//! - the **typed payload** (e.g. `i32` for Integer, `Vec<u8>` for ByteString),
//! - which the [`encode`](super::encode) writer serialises using the rules
//!   in §10.1.2 (big-endian for numerics, zero-padding to 8-byte alignment for
//!   value bytes), and
//! - which the [`decode`](super::decode) reader reconstructs after reading
//!   the item-type byte and length field.
//!
//! Structures are special: their payload is a sequence of nested TTLV frames
//! (each carrying its own `Tag`). The codec preserves child order, since
//! KMIP ops are order-sensitive (e.g. Common Attributes always precede
//! Private Key Attributes inside a `CreateKeyPair` request).

use super::Tag;

/// KMIP TTLV item-type byte (§11.25). Wire-byte value in the right column.
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
    /// KMIP 3.0 (§11.25). A managed object's own Unique Identifier. UTF-8,
    /// encoded exactly like a Text String (§10.1.2) but a distinct type, so a
    /// peer can tell an object's identity from an arbitrary string.
    Identifier         = 0x0C,
    /// KMIP 3.0 (§11.25). An **early-binding** link to one specific object,
    /// by its Unique Identifier (§4.35 preamble).
    Reference          = 0x0D,
    /// KMIP 3.0 (§11.25). A **late-binding** link, resolved to whichever
    /// object currently carries the matching `Name` attribute (§4.35 preamble).
    NameReference      = 0x0E,
}

impl ItemType {
    /// Wire byte for this item type.
    #[inline]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }

    /// Reverse mapping. `None` for bytes outside the §11.25 registry.
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
            0x0C => Some(Self::Identifier),
            0x0D => Some(Self::Reference),
            0x0E => Some(Self::NameReference),
            _ => None,
        }
    }
}

/// One TTLV frame — a tagged, typed payload.
///
/// Every variant has wire-encoding rules in OASIS KMIP 3.0 §10.1.2.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// `[child_0, child_1, …]` — nested TTLV frames in document order.
    ///
    /// §10.1.2 — the value bytes are themselves a concatenation of complete
    /// TTLV frames, each carrying its own tag/type/length/value.
    Structure(Vec<TtlvFrame>),

    /// Signed 32-bit, big-endian, padded to 8 bytes (§10.1.2).
    Integer(i32),

    /// Signed 64-bit, big-endian, exactly 8 bytes (§10.1.2).
    LongInteger(i64),

    /// Arbitrary-precision signed integer, big-endian two's-complement,
    /// must be a multiple of 8 bytes (§10.1.2). We hold the raw value bytes
    /// because the on-wire size matters for round-trip equality, and the
    /// codec is the layer responsible for ensuring it is a multiple of 8.
    BigInteger(Vec<u8>),

    /// Unsigned 32-bit, big-endian, padded to 8 bytes (§10.1.2). The
    /// codepoint space is per-enum (e.g. `Operation`, `CryptographicAlgorithm`).
    /// We store the raw `u32`; symbolic interpretation belongs to Phase 3
    /// (`src/kmip30/algos.rs` and friends).
    Enumeration(u32),

    /// 8-byte payload (§10.1.2) — wire bytes are `0x0…01` for true, `0x0…00`
    /// for false. The codec rejects other values.
    Boolean(bool),

    /// UTF-8 bytes, zero-padded to 8 (§10.1.2).
    TextString(String),

    /// Arbitrary opaque bytes, zero-padded to 8 (§10.1.2).
    ByteString(Vec<u8>),

    /// POSIX-style seconds since epoch in a signed 64-bit field
    /// (§10.1.2 — encoded as LongInteger, distinguished by item type).
    /// Stored as raw `i64` so the codec is bit-exact even for the OASIS
    /// "now" sentinel value `0x0000_0000_0000_0000`.
    DateTime(i64),

    /// 32-bit unsigned seconds; padded to 8 (§10.1.2).
    Interval(u32),

    /// KMIP 2.0+ extension (§10.1.2). 64-bit signed value carrying
    /// microsecond precision since epoch.
    DateTimeExtended(i64),

    // ── KMIP 3.0 identifier/reference types (§11.25) ────────────────────
    //
    // All three are "Sequences of bytes that encode character values
    // according to [RFC3629] the UTF-8 encoding standard" (§10.1.2) with
    // "Varies" length (§10.1.3) and the same 8-byte padding as Text String
    // (§10.1.4). They are byte-identical to a Text String on the wire
    // EXCEPT for the type byte — which is the whole point: the type says
    // what the string means, so a peer need not infer it from the tag.
    //
    // Added 2026-09-06. Before that the codec stopped at 0x0B and the OASIS
    // corpus was replayed only after the harness rewrote all three to Text
    // String, so "1234/1234 byte-identical" measured a downgraded rendering.

    /// `Identifier` (0x0C) — a managed object's own Unique Identifier.
    Identifier(String),

    /// `Reference` (0x0D) — early-binding link to a specific object's UID.
    Reference(String),

    /// `Name Reference` (0x0E) — late-binding link, resolved via `Name`.
    NameReference(String),
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
            Value::Identifier(_)       => ItemType::Identifier,
            Value::Reference(_)        => ItemType::Reference,
            Value::NameReference(_)    => ItemType::NameReference,
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
        for b in [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
                  0x0C, 0x0D, 0x0E] {
            let t = ItemType::from_byte(b).expect("known item type");
            assert_eq!(t.as_byte(), b);
        }
    }

    #[test]
    fn item_type_byte_rejects_unknown() {
        assert!(ItemType::from_byte(0x00).is_none());
        // 0x0C-0x0E are now REAL types (§11.25); 0x0F is the first unassigned.
        assert!(ItemType::from_byte(0x0F).is_none());
        assert!(ItemType::from_byte(0xff).is_none());
    }

    #[test]
    fn value_item_type_dispatch_covers_all_variants() {
        // Exhaustively check every Value variant maps to the right byte; if a
        // new variant is added without updating `item_type()`, this fails to
        // compile due to the non-exhaustive match.
        let cases: [(Value, ItemType); 14] = [
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
            (Value::Identifier(String::new()),    ItemType::Identifier),
            (Value::Reference(String::new()),     ItemType::Reference),
            (Value::NameReference(String::new()), ItemType::NameReference),
        ];
        for (v, expected) in cases {
            assert_eq!(v.item_type(), expected);
        }
    }
}
