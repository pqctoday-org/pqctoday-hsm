//! Plane 2 foundation — KMIP TTLV codec (hand-rolled).
//!
//! `Tag` enum (KMIP 1.4 + 2.0 + 3.0 codepoints), `Value` enum (Integer, LongInteger,
//! BigInteger, Boolean, Enumeration, Interval, DateTime, ByteString, TextString,
//! Structure), `encode` and `decode` functions, proptest round-trip.
//!
//! Phase 0 (bootstrap): module declared, no implementation. Lands in Phase 2
//! per `docs/IMPLEMENTATION_PLAN.md` §6 (~3,500–5,000 LOC including tests).
