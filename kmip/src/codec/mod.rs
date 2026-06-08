//! Plane 2 foundation — KMIP TTLV codec (hand-rolled).
//!
//! KMIP TTLV (Tag-Type-Length-Value) is the wire format used by every KMIP
//! message. See OASIS KMIP 3.0 §9 (file:
//! `spec/oasis-kmip-3.0/kmip-spec-v3.0.html`, section 9.x).
//!
//! Layout (KMIP 3.0 §9.6):
//!
//! ```text
//! ┌────────┬──────┬────────┬─────────────────────────┐
//! │  Tag   │ Type │ Length │  Value (+ zero pad to   │
//! │ 3 byte │  1 B │  4 B   │  next 8-byte boundary)  │
//! └────────┴──────┴────────┴─────────────────────────┘
//! ```
//!
//! - Tag is a 24-bit big-endian unsigned codepoint (the registry uses
//!   the range `0x420000`–`0x4FFFFF` for KMIP standard tags; private/vendor
//!   tags start at `0x540000`).
//! - Type is one of 11 KMIP TTLV item-type bytes (see [`value::ItemType`]).
//! - Length is the number of value bytes BEFORE alignment padding, big-endian.
//! - Value is exactly `length` bytes, followed by zero-padding to the next
//!   8-byte boundary. Structures are an exception — their value is itself
//!   a sequence of TTLVs and is already aligned because each child TTLV is.
//!
//! Module layout (per IMPLEMENTATION_PLAN.md §6 Phase 2):
//!
//! - [`tag`]    — `Tag` newtype + try-from-u32 mapping.
//! - [`value`]  — `Value` enum (11 variants matching the type bytes).
//! - [`encode`] — `encode(&Value, &mut BytesMut)` with 8-byte alignment.
//! - [`decode`] — `decode(&[u8]) -> Result<(Value, usize), CodecError>`.
//! - tests live alongside in `tests.rs` (proptest round-trip) and
//!   `tests/kat_replay.rs` (byte-exact replay of `kat/ttlv-wire/*.bin`).

pub mod tag;
pub mod value;
pub mod encode;
pub mod decode;

#[cfg(test)]
mod tests;

pub use tag::Tag;
pub use value::{ItemType, TtlvFrame, Value};
pub use encode::{encode, encode_to_vec};
pub use decode::{decode, decode_one};

use thiserror::Error;

/// Errors produced by [`decode`] and [`encode`].
///
/// Error variants name their failure mode rather than the byte offset; the
/// caller is expected to wrap with positional context if needed.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CodecError {
    /// Decode ran out of bytes before completing a TTLV frame.
    #[error("unexpected end of input (need at least {needed} more bytes)")]
    UnexpectedEof { needed: usize },

    /// First byte of the type field is not one of the 11 defined KMIP item types.
    #[error("unknown TTLV item type byte: 0x{0:02x}")]
    UnknownItemType(u8),

    /// `Length` field did not match the actual value length for a fixed-length
    /// type (e.g. Integer must have `Length == 4`, Boolean must be 8).
    #[error("invalid length {actual} for type {item_type:?} (expected {expected})")]
    InvalidLength {
        item_type: value::ItemType,
        actual: u32,
        expected: u32,
    },

    /// Padding bytes were non-zero. KMIP §9.6 mandates zero padding.
    #[error("non-zero padding byte at offset {offset}")]
    NonZeroPadding { offset: usize },

    /// Boolean value byte was not 0x00 or 0x01.
    #[error("invalid boolean value: 0x{0:016x} (must be 0 or 1)")]
    InvalidBoolean(u64),

    /// TextString value was not valid UTF-8.
    #[error("invalid UTF-8 in TextString value")]
    InvalidUtf8,

    /// Encoder/decoder reached a structurally-recursive boundary that is
    /// deeper than the implementation's max depth. Defensive — prevents
    /// stack overflow on adversarial input.
    #[error("structure nesting too deep (limit {0})")]
    StructureTooDeep(usize),
}

pub type Result<T> = std::result::Result<T, CodecError>;

/// Maximum structure nesting depth accepted by [`decode`]. The KMIP spec does
/// not impose a normative limit; this is a defensive cap against adversarial
/// input. Real-world KMIP messages rarely exceed ~10 levels of nesting.
pub const MAX_STRUCTURE_DEPTH: usize = 64;

/// All KMIP TTLV values align to 8-byte boundaries.
pub const ALIGNMENT: usize = 8;
