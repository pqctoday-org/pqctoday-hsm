//! TTLV decoder — turns bytes back into a [`TtlvFrame`].
//!
//! Hand-rolled, no `nom` dependency. The decoder works against a borrowed
//! `&[u8]` and a moving cursor; primitives that read a specific number of
//! bytes advance the cursor, primitives that fail return early with a
//! [`CodecError`] naming what went wrong.
//!
//! KMIP TTLV wire layout (recap from [`super::mod`] / OASIS KMIP 3.0 §9.6):
//!
//! ```text
//! ┌────────┬──────┬────────┬──── Length bytes ────┬─── padding ───┐
//! │  Tag   │ Type │ Length │      Value           │ 0..7 zero bytes│
//! │ 3 byte │  1 B │  4 BE  │                       │ (to align next │
//! │        │      │        │                       │  frame to 8)   │
//! └────────┴──────┴────────┴───────────────────────┴────────────────┘
//! ```
//!
//! Structures recursively contain TTLV children — each child's frame is
//! itself 8-aligned, so structures do not need an outer pad.

use super::value::{ItemType, TtlvFrame, Value};
use super::{CodecError, Result, Tag, MAX_STRUCTURE_DEPTH};

/// Decode a single TTLV frame from the start of `input`.
///
/// Returns the frame and the number of bytes consumed (including any padding
/// AFTER the value). Use [`decode_one`] if you don't care about the consumed
/// byte count.
pub fn decode(input: &[u8]) -> Result<(TtlvFrame, usize)> {
    let mut pos = 0;
    let frame = decode_frame(input, &mut pos, 0)?;
    Ok((frame, pos))
}

/// Decode a single TTLV frame from `input`. Convenience for tests + callers
/// that don't need the byte-count.
pub fn decode_one(input: &[u8]) -> Result<TtlvFrame> {
    decode(input).map(|(f, _)| f)
}

/// Decode a frame starting at `*pos`, advancing `*pos` past the frame and
/// any trailing alignment padding.
fn decode_frame(input: &[u8], pos: &mut usize, depth: usize) -> Result<TtlvFrame> {
    if depth > MAX_STRUCTURE_DEPTH {
        return Err(CodecError::StructureTooDeep(MAX_STRUCTURE_DEPTH));
    }

    let start = *pos;
    require_remaining(input, start, 8)?; // 3 tag + 1 type + 4 length

    let tag = Tag::from_be_bytes([input[start], input[start + 1], input[start + 2]]);
    let type_byte = input[start + 3];
    let item_type =
        ItemType::from_byte(type_byte).ok_or(CodecError::UnknownItemType(type_byte))?;
    let length = u32::from_be_bytes([
        input[start + 4],
        input[start + 5],
        input[start + 6],
        input[start + 7],
    ]);

    *pos += 8;
    let value = decode_value(input, pos, item_type, length, depth)?;

    // Pad to alignment for everything EXCEPT Structure.
    if item_type != ItemType::Structure {
        let pad_needed = (8 - (length as usize) % 8) % 8;
        if pad_needed > 0 {
            require_remaining(input, *pos, pad_needed)?;
            // Spec §9.6: padding MUST be zero bytes; reject anything else.
            for off in 0..pad_needed {
                if input[*pos + off] != 0 {
                    return Err(CodecError::NonZeroPadding { offset: *pos + off });
                }
            }
            *pos += pad_needed;
        }
    }

    Ok(TtlvFrame { tag, value })
}

/// Decode the typed value bytes given the item-type byte + length field.
fn decode_value(
    input: &[u8],
    pos: &mut usize,
    item_type: ItemType,
    length: u32,
    depth: usize,
) -> Result<Value> {
    let len_usize = length as usize;
    require_remaining(input, *pos, len_usize)?;
    let start = *pos;
    let end = start + len_usize;

    let value = match item_type {
        ItemType::Structure => {
            // Body is concatenated TTLV children. Recurse, accumulating until
            // we have consumed exactly `length` bytes.
            let mut children = Vec::new();
            let body_end = start + len_usize;
            while *pos < body_end {
                children.push(decode_frame(input, pos, depth + 1)?);
            }
            // It would be a spec violation for a child to overshoot the
            // declared Structure length — defensive check.
            if *pos != body_end {
                return Err(CodecError::InvalidLength {
                    item_type,
                    actual: (*pos - start) as u32,
                    expected: length,
                });
            }
            return Ok(Value::Structure(children));
        }
        ItemType::Integer => {
            check_fixed_length(item_type, length, 4)?;
            let v = i32::from_be_bytes([
                input[start], input[start + 1], input[start + 2], input[start + 3],
            ]);
            Value::Integer(v)
        }
        ItemType::LongInteger => {
            check_fixed_length(item_type, length, 8)?;
            let v = i64::from_be_bytes([
                input[start],     input[start + 1], input[start + 2], input[start + 3],
                input[start + 4], input[start + 5], input[start + 6], input[start + 7],
            ]);
            Value::LongInteger(v)
        }
        ItemType::BigInteger => {
            if len_usize == 0 || len_usize % 8 != 0 {
                return Err(CodecError::InvalidLength {
                    item_type,
                    actual: length,
                    expected: ((len_usize + 7) / 8 * 8) as u32,
                });
            }
            Value::BigInteger(input[start..end].to_vec())
        }
        ItemType::Enumeration => {
            check_fixed_length(item_type, length, 4)?;
            let v = u32::from_be_bytes([
                input[start], input[start + 1], input[start + 2], input[start + 3],
            ]);
            Value::Enumeration(v)
        }
        ItemType::Boolean => {
            check_fixed_length(item_type, length, 8)?;
            let raw = u64::from_be_bytes([
                input[start],     input[start + 1], input[start + 2], input[start + 3],
                input[start + 4], input[start + 5], input[start + 6], input[start + 7],
            ]);
            match raw {
                0 => Value::Boolean(false),
                1 => Value::Boolean(true),
                _ => return Err(CodecError::InvalidBoolean(raw)),
            }
        }
        ItemType::TextString => {
            let s = std::str::from_utf8(&input[start..end])
                .map_err(|_| CodecError::InvalidUtf8)?;
            Value::TextString(s.to_string())
        }
        ItemType::ByteString => Value::ByteString(input[start..end].to_vec()),
        ItemType::DateTime => {
            check_fixed_length(item_type, length, 8)?;
            let v = i64::from_be_bytes([
                input[start],     input[start + 1], input[start + 2], input[start + 3],
                input[start + 4], input[start + 5], input[start + 6], input[start + 7],
            ]);
            Value::DateTime(v)
        }
        ItemType::Interval => {
            check_fixed_length(item_type, length, 4)?;
            let v = u32::from_be_bytes([
                input[start], input[start + 1], input[start + 2], input[start + 3],
            ]);
            Value::Interval(v)
        }
        ItemType::DateTimeExtended => {
            check_fixed_length(item_type, length, 8)?;
            let v = i64::from_be_bytes([
                input[start],     input[start + 1], input[start + 2], input[start + 3],
                input[start + 4], input[start + 5], input[start + 6], input[start + 7],
            ]);
            Value::DateTimeExtended(v)
        }
    };

    *pos = end;
    Ok(value)
}

#[inline]
fn check_fixed_length(item_type: ItemType, actual: u32, expected: u32) -> Result<()> {
    if actual != expected {
        Err(CodecError::InvalidLength {
            item_type,
            actual,
            expected,
        })
    } else {
        Ok(())
    }
}

#[inline]
fn require_remaining(input: &[u8], pos: usize, needed: usize) -> Result<()> {
    if input.len().saturating_sub(pos) < needed {
        Err(CodecError::UnexpectedEof {
            needed: needed - (input.len() - pos),
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Tag;

    #[test]
    fn decodes_kat_vector_01_integer_batch_count_1() {
        let bytes = [
            0x42, 0x00, 0x0d, 0x02, 0x00, 0x00, 0x00, 0x04,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        let (frame, n) = decode(&bytes).expect("decode");
        assert_eq!(n, 16);
        assert_eq!(frame.tag, Tag::BATCH_COUNT);
        assert_eq!(frame.value, Value::Integer(1));
    }

    #[test]
    fn decodes_kat_vector_03_pqc_enum_ml_kem_768() {
        let bytes = [
            0x42, 0x00, 0x28, 0x05, 0x00, 0x00, 0x00, 0x04,
            0x00, 0x00, 0x00, 0x3a, 0x00, 0x00, 0x00, 0x00,
        ];
        let frame = decode_one(&bytes).expect("decode");
        assert_eq!(frame.tag, Tag::CRYPTOGRAPHIC_ALGORITHM);
        assert_eq!(frame.value, Value::Enumeration(0x0000_003a));
    }

    #[test]
    fn rejects_non_zero_padding() {
        // BatchCount Integer = 1, with 0xFF in a padding byte
        let bytes = [
            0x42, 0x00, 0x0d, 0x02, 0x00, 0x00, 0x00, 0x04,
            0x00, 0x00, 0x00, 0x01, 0xff, 0x00, 0x00, 0x00,
        ];
        match decode(&bytes) {
            Err(CodecError::NonZeroPadding { .. }) => (),
            other => panic!("expected NonZeroPadding, got {other:?}"),
        }
    }

    #[test]
    fn rejects_unknown_item_type_byte() {
        let bytes = [
            0x42, 0x00, 0x0d, 0xff, 0x00, 0x00, 0x00, 0x04,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(decode(&bytes), Err(CodecError::UnknownItemType(0xff)));
    }

    #[test]
    fn rejects_wrong_integer_length() {
        // Integer with Length = 8 (should be 4)
        let bytes = [
            0x42, 0x00, 0x0d, 0x02, 0x00, 0x00, 0x00, 0x08,
            0, 0, 0, 0, 0, 0, 0, 1,
        ];
        match decode(&bytes) {
            Err(CodecError::InvalidLength { item_type: ItemType::Integer, .. }) => (),
            other => panic!("expected InvalidLength, got {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_boolean() {
        // Boolean with raw value = 2
        let bytes = [
            0x42, 0x00, 0x0d, 0x06, 0x00, 0x00, 0x00, 0x08,
            0, 0, 0, 0, 0, 0, 0, 2,
        ];
        assert_eq!(decode(&bytes), Err(CodecError::InvalidBoolean(2)));
    }

    #[test]
    fn rejects_eof_in_header() {
        let bytes = [0x42, 0x00, 0x0d, 0x02, 0x00]; // only 5 bytes
        match decode(&bytes) {
            Err(CodecError::UnexpectedEof { .. }) => (),
            other => panic!("expected UnexpectedEof, got {other:?}"),
        }
    }

    #[test]
    fn decodes_nested_structure_protocol_version() {
        // kat/ttlv-wire/06-structure-protocol-version-3-0.bin (40 bytes)
        let bytes = [
            // Outer: ProtocolVersion Structure, Length = 32
            0x42, 0x00, 0x69, 0x01, 0x00, 0x00, 0x00, 0x20,
            // Inner: ProtocolVersionMajor = 3 (Integer)
            0x42, 0x00, 0x6a, 0x02, 0x00, 0x00, 0x00, 0x04,
            0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
            // Inner: ProtocolVersionMinor = 0 (Integer)
            0x42, 0x00, 0x6b, 0x02, 0x00, 0x00, 0x00, 0x04,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let (frame, n) = decode(&bytes).expect("decode");
        assert_eq!(n, 40);
        assert_eq!(frame.tag, Tag::PROTOCOL_VERSION);
        match frame.value {
            Value::Structure(children) => {
                assert_eq!(children.len(), 2);
                assert_eq!(children[0].tag, Tag::PROTOCOL_VERSION_MAJOR);
                assert_eq!(children[0].value, Value::Integer(3));
                assert_eq!(children[1].tag, Tag::PROTOCOL_VERSION_MINOR);
                assert_eq!(children[1].value, Value::Integer(0));
            }
            _ => panic!("expected Structure"),
        }
    }
}
