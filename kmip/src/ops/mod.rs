//! Plane 2 — KMIP 3.0 operation handlers.
//!
//! Each handler is one file (≤ ~250 LOC including tests + spec citations).
//! The set Phase 5 ships in this session:
//!
//! | File | KMIP 3.0 § | Op codepoint |
//! |---|---|---|
//! | [`query`]           | 6.1.45 | 0x18 |
//! | [`create_key_pair`] | 6.1.11 | 0x02 |
//! | [`sign`]            | 6.1.60 | 0x21 |
//!
//! Remaining 9 ops (Create, Get, Locate, Activate, Revoke, Destroy,
//! Encrypt, Decrypt, SignatureVerify) follow the same template:
//!
//! 1. Emit Plane-2 `KmipRequestReceived`.
//! 2. Pre-flight store lookup + lifecycle gate (per `docs/IMPLEMENTATION_PLAN.md` §3.4).
//! 3. Call `deps.engine.evaluate(&policy_request)`.
//! 4. Map `(KmipAlgorithm, PkcsOp) → CKM_*` via
//!    `KmipAlgorithm::to_pkcs11_mech` (Phase 3).
//! 5. Emit Plane-3 `Pkcs11Call`s; call the bridge (Phase 7 wires real
//!    softhsmrustv3 entries; v0.1 uses placeholders so tests run without
//!    a token).
//! 6. Persist any store mutations.
//! 7. Emit Plane-2 `KmipResponseSent`.
//!
//! Note: KMIP 3.0 does NOT add separate `Encapsulate` / `Decapsulate` ops.
//! ML-KEM encapsulation reuses `Encrypt`; ML-KEM decapsulation reuses
//! `Decrypt`. The handler branches on key algorithm.

pub mod create_key_pair;
pub mod deps;
pub mod query;
pub mod sign;

pub use deps::{Deps, DepsConfig};
