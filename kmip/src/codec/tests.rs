//! Codec round-trip tests — `decode(encode(v)) == v` for every [`Value`]
//! variant via property-based testing (`proptest`).
//!
//! The 6 golden KAT vectors at `kat/ttlv-wire/*.bin` are replayed in the
//! sibling integration test `tests/kat_replay.rs`; this file is the unit-test
//! layer that exercises the whole `Value` enum exhaustively against random
//! payloads.

use super::value::{TtlvFrame, Value};
use super::{decode_one, encode_to_vec, Tag};

use proptest::prelude::*;

// ── Strategies ──────────────────────────────────────────────────────────────

/// Any 24-bit-fitting tag codepoint. The Tag newtype rejects anything above
/// `0x00FFFFFF` at construction time.
fn arb_tag() -> impl Strategy<Value = Tag> {
    any::<u32>().prop_map(|u| Tag::new(u & 0x00FF_FFFF).expect("masked to 24-bit"))
}

/// All Value variants EXCEPT Structure. Structure recursion is exercised in
/// `arb_value` via a tree generator with bounded depth.
fn arb_leaf_value() -> impl Strategy<Value = Value> {
    prop_oneof![
        any::<i32>().prop_map(Value::Integer),
        any::<i64>().prop_map(Value::LongInteger),
        // BigInteger must be a nonzero multiple of 8 bytes per spec §9.2.4.
        (1usize..=4).prop_map(|n| Value::BigInteger(vec![0xab; n * 8])),
        any::<u32>().prop_map(Value::Enumeration),
        any::<bool>().prop_map(Value::Boolean),
        // Text is restricted to ASCII so we don't blow proptest budgets on UTF-8
        // multibyte cases; UTF-8 handling is covered by a separate test below.
        "[ -~]{0,32}".prop_map(Value::TextString),
        prop::collection::vec(any::<u8>(), 0..=24).prop_map(Value::ByteString),
        any::<i64>().prop_map(Value::DateTime),
        any::<u32>().prop_map(Value::Interval),
        any::<i64>().prop_map(Value::DateTimeExtended),
    ]
}

/// Any Value, including nested Structures with bounded depth.
fn arb_value() -> impl Strategy<Value = Value> {
    let leaf = arb_leaf_value();
    leaf.prop_recursive(
        4,   // max depth
        16,  // total nodes
        4,   // max children per Structure
        |inner| {
            prop::collection::vec(
                (arb_tag(), inner).prop_map(|(tag, value)| TtlvFrame::new(tag, value)),
                0..=4,
            )
            .prop_map(Value::Structure)
        },
    )
}

fn arb_frame() -> impl Strategy<Value = TtlvFrame> {
    (arb_tag(), arb_value()).prop_map(|(tag, value)| TtlvFrame::new(tag, value))
}

// ── Round-trip tests ────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// Decoding the bytes produced by `encode` yields the original frame.
    #[test]
    fn encode_then_decode_yields_original_frame(frame in arb_frame()) {
        let bytes = encode_to_vec(&frame);
        let decoded = decode_one(&bytes).expect("decode");
        prop_assert_eq!(decoded, frame);
    }

    /// Encoding is a function of the frame — same input, same bytes.
    #[test]
    fn encode_is_deterministic(frame in arb_frame()) {
        let a = encode_to_vec(&frame);
        let b = encode_to_vec(&frame);
        prop_assert_eq!(a, b);
    }

    /// Encoded output has length a multiple of 8 bytes (frame is 8-aligned).
    #[test]
    fn encoded_length_is_multiple_of_8(frame in arb_frame()) {
        let bytes = encode_to_vec(&frame);
        prop_assert_eq!(bytes.len() % 8, 0);
    }
}

// ── Explicit UTF-8 + boundary cases ─────────────────────────────────────────

#[test]
fn text_string_round_trips_unicode() {
    let frame = TtlvFrame::new(
        Tag::UNIQUE_IDENTIFIER,
        Value::TextString("π=3.14, ☃, ☃snow!".to_string()),
    );
    let bytes = encode_to_vec(&frame);
    let decoded = decode_one(&bytes).expect("decode");
    assert_eq!(decoded, frame);
}

#[test]
fn empty_byte_string_round_trips() {
    let frame = TtlvFrame::new(Tag::APPLICATION_DATA, Value::ByteString(vec![]));
    let bytes = encode_to_vec(&frame);
    let decoded = decode_one(&bytes).expect("decode");
    assert_eq!(decoded, frame);
    // empty ByteString: 8-byte header + 0-byte value + 0-byte pad = 8
    assert_eq!(bytes.len(), 8);
}

#[test]
fn empty_structure_round_trips() {
    let frame = TtlvFrame::new(Tag::REQUEST_PAYLOAD, Value::Structure(vec![]));
    let bytes = encode_to_vec(&frame);
    let decoded = decode_one(&bytes).expect("decode");
    assert_eq!(decoded, frame);
    // empty Structure: 8-byte header + 0-byte value + 0-byte pad = 8
    assert_eq!(bytes.len(), 8);
}

#[test]
fn max_depth_structure_round_trips() {
    // Build a structure nested to depth (MAX_STRUCTURE_DEPTH - 1) to stay
    // within the decoder's limit. At MAX_STRUCTURE_DEPTH itself the decoder
    // would reject (separate test below).
    let mut v = Value::Integer(42);
    for _ in 0..(crate::codec::MAX_STRUCTURE_DEPTH - 1) {
        v = Value::Structure(vec![TtlvFrame::new(Tag::BATCH_ITEM, v)]);
    }
    let frame = TtlvFrame::new(Tag::REQUEST_MESSAGE, v);
    let bytes = encode_to_vec(&frame);
    let decoded = decode_one(&bytes).expect("decode");
    assert_eq!(decoded, frame);
}

#[test]
fn over_max_depth_structure_is_rejected_on_decode() {
    // Build a frame past the depth limit.
    let mut v = Value::Integer(0);
    for _ in 0..=crate::codec::MAX_STRUCTURE_DEPTH {
        v = Value::Structure(vec![TtlvFrame::new(Tag::BATCH_ITEM, v)]);
    }
    let frame = TtlvFrame::new(Tag::REQUEST_MESSAGE, v);
    let bytes = encode_to_vec(&frame);
    match decode_one(&bytes) {
        Err(crate::codec::CodecError::StructureTooDeep(_)) => (),
        other => panic!("expected StructureTooDeep, got {other:?}"),
    }
}
