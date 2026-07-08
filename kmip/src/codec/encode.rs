//! TTLV encoder — turns a [`TtlvFrame`] (or root [`Value`]) into bytes.
//!
//! Wire format (OASIS KMIP 3.0 §9.6):
//!
//! ```text
//! ┌──── 3 bytes ────┬─ 1 ──┬──── 4 bytes ───┬───── L bytes ─────┬─── pad ───┐
//! │       Tag       │ Type │   Length (BE)  │       Value        │ 0..7 bytes│
//! └─────────────────┴──────┴────────────────┴────────────────────┴───────────┘
//! ```
//!
//! Length is the **unpadded** value-byte count (big-endian u32). The encoder
//! appends zero bytes after the value to bring the next frame onto an
//! 8-byte boundary. Structures are the only type that does not need padding —
//! their value is itself a concatenation of TTLV frames, and each child
//! frame is already 8-byte-aligned, so the outer Length is automatically a
//! multiple of 8.

use bytes::{BufMut, BytesMut};

use super::value::{ItemType, TtlvFrame, Value};
use super::ALIGNMENT;
#[cfg(test)]
use super::Tag;

/// Encode a single TTLV frame into the buffer. Convenience for the common
/// "root frame" case.
pub fn encode(frame: &TtlvFrame, buf: &mut BytesMut) {
    encode_frame(frame, buf);
}

/// Encode a single TTLV frame at the current end of the buffer.
fn encode_frame(frame: &TtlvFrame, buf: &mut BytesMut) {
    let tag_bytes = frame.tag.to_be_bytes();
    let type_byte = frame.value.item_type().as_byte();

    // Write tag + type. Length is filled in after we know the value length —
    // we reserve 4 bytes and patch them in place.
    buf.put_slice(&tag_bytes);
    buf.put_u8(type_byte);

    let len_offset = buf.len();
    buf.put_u32(0); // placeholder

    let value_start = buf.len();
    encode_value(&frame.value, buf);
    let value_end = buf.len();
    let value_len = (value_end - value_start) as u32;

    // Patch the length field.
    buf[len_offset..len_offset + 4].copy_from_slice(&value_len.to_be_bytes());

    // Pad to 8-byte boundary for every type EXCEPT Structure (whose body is
    // already aligned because each child is).
    if frame.value.item_type() != ItemType::Structure {
        let needed = pad_count(value_len as usize);
        for _ in 0..needed {
            buf.put_u8(0);
        }
    }
}

/// Number of zero bytes required after a value of `n` bytes to align the
/// next frame to [`ALIGNMENT`].
#[inline]
fn pad_count(n: usize) -> usize {
    (ALIGNMENT - (n % ALIGNMENT)) % ALIGNMENT
}

/// Write the typed value bytes (length-field exclusive). The caller (above)
/// handles tag/type/length framing and padding.
fn encode_value(value: &Value, buf: &mut BytesMut) {
    match value {
        Value::Structure(children) => {
            for child in children {
                encode_frame(child, buf);
            }
        }
        Value::Integer(i) => {
            buf.put_i32(*i);
        }
        Value::LongInteger(i) => {
            buf.put_i64(*i);
        }
        Value::BigInteger(bytes) => {
            // KMIP §9.2.4: BigInteger byte length is already a multiple of 8.
            // We trust the caller to have ensured this; the codec does not
            // re-normalise. (Encoder is faithful — decoder validates.)
            buf.put_slice(bytes);
        }
        Value::Enumeration(u) => {
            buf.put_u32(*u);
        }
        Value::Boolean(b) => {
            buf.put_u64(if *b { 1 } else { 0 });
        }
        Value::TextString(s) => {
            buf.put_slice(s.as_bytes());
        }
        Value::ByteString(bytes) => {
            buf.put_slice(bytes);
        }
        Value::DateTime(seconds) => {
            buf.put_i64(*seconds);
        }
        Value::Interval(u) => {
            buf.put_u32(*u);
        }
        Value::DateTimeExtended(usec) => {
            buf.put_i64(*usec);
        }
    }
}

/// Convenience for encode-to-Vec. Returns a freshly-allocated buffer.
pub fn encode_to_vec(frame: &TtlvFrame) -> Vec<u8> {
    let mut buf = BytesMut::with_capacity(32);
    encode(frame, &mut buf);
    buf.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_value_one_encodes_to_kat_vector_01() {
        // kat/ttlv-wire/01-integer-batch-count-1.bin (filename predates the
        // Tag::SYNTHETIC_TEST_TAG rename — this codepoint is a synthetic
        // probe for the Integer/Boolean primitive codec paths, not a real
        // KMIP 3.0 attribute; 0x42000d is Reserved in 3.0, see the tag's
        // doc comment):
        //   42 00 0d 02 00 00 00 04 00 00 00 01 00 00 00 00
        //   ^^^^^^^^ tag (synthetic test probe = 0x42000d)
        //            ^^ type (Integer = 0x02)
        //               ^^^^^^^^^^^ length 4
        //                          ^^^^^^^^^^^ value (1, signed 32-bit BE)
        //                                     ^^^^^^^^^^^ 4 bytes of padding
        let frame = TtlvFrame::new(Tag::SYNTHETIC_TEST_TAG, Value::Integer(1));
        let bytes = encode_to_vec(&frame);
        assert_eq!(
            bytes,
            vec![
                0x42, 0x00, 0x0d, 0x02, 0x00, 0x00, 0x00, 0x04,
                0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            ]
        );
    }

    #[test]
    fn pqc_enumeration_ml_kem_768_encodes_to_kat_vector_03() {
        // kat/ttlv-wire/03-enum-cryptographic-algorithm-ml-kem-768.bin:
        //   42 00 28 05 00 00 00 04 00 00 00 3a 00 00 00 00
        let frame = TtlvFrame::new(
            Tag::CRYPTOGRAPHIC_ALGORITHM,
            Value::Enumeration(0x0000_003a), // ML-KEM-768 per OASIS 3.0 §10.2.6
        );
        let bytes = encode_to_vec(&frame);
        assert_eq!(
            bytes,
            vec![
                0x42, 0x00, 0x28, 0x05, 0x00, 0x00, 0x00, 0x04,
                0x00, 0x00, 0x00, 0x3a, 0x00, 0x00, 0x00, 0x00,
            ]
        );
    }

    #[test]
    fn boolean_true_pads_to_8_bytes() {
        let frame = TtlvFrame::new(Tag::SYNTHETIC_TEST_TAG, Value::Boolean(true));
        let bytes = encode_to_vec(&frame);
        // header (3+1+4=8) + value (8) + pad (0 — Boolean body is already 8)
        assert_eq!(bytes.len(), 16);
        assert_eq!(&bytes[12..16], &[0, 0, 0, 1]); // low byte of value=1
    }

    #[test]
    fn structure_body_is_already_aligned() {
        let inner_a = TtlvFrame::new(Tag::PROTOCOL_VERSION_MAJOR, Value::Integer(3));
        let inner_b = TtlvFrame::new(Tag::PROTOCOL_VERSION_MINOR, Value::Integer(0));
        let frame = TtlvFrame::new(
            Tag::PROTOCOL_VERSION,
            Value::Structure(vec![inner_a, inner_b]),
        );
        let bytes = encode_to_vec(&frame);
        // header 8 + inner_a 16 + inner_b 16 = 40 (no trailing pad)
        assert_eq!(bytes.len(), 40);
        // Structure length field = inner_a + inner_b = 32 bytes
        assert_eq!(&bytes[4..8], &[0, 0, 0, 32]);
    }

    #[test]
    fn text_string_pads_to_alignment() {
        // 5-byte text string → 3-byte pad
        let frame = TtlvFrame::new(
            Tag::UNIQUE_IDENTIFIER,
            Value::TextString("pqc-1".to_string()),
        );
        let bytes = encode_to_vec(&frame);
        // header 8 + value 5 + pad 3 = 16
        assert_eq!(bytes.len(), 16);
        // Length field reports the unpadded value length (5)
        assert_eq!(&bytes[4..8], &[0, 0, 0, 5]);
        // Last 3 bytes are zero padding
        assert_eq!(&bytes[13..16], &[0, 0, 0]);
    }

    #[test]
    fn pad_count_works() {
        assert_eq!(pad_count(0), 0);
        assert_eq!(pad_count(1), 7);
        assert_eq!(pad_count(5), 3);
        assert_eq!(pad_count(7), 1);
        assert_eq!(pad_count(8), 0);
        assert_eq!(pad_count(9), 7);
    }
}
