//! Plane 2 — KMIP 3.0 operation handlers.
//!
//! Each handler is one file (≤ ~250 LOC including tests + spec citations).
//! The set Phase 5 ships in this session:
//!
//! | File | KMIP 3.0 § | Op codepoint |
//! |---|---|---|
//! | [`activate`]          | 6.1.1  | 0x12 |
//! | [`create`]            | 6.1.8  | 0x01 |
//! | [`create_key_pair`]   | 6.1.11 | 0x02 |
//! | [`decrypt`]           | 6.1.15 | 0x20 |
//! | [`destroy`]           | 6.1.19 | 0x14 |
//! | [`encrypt`]           | 6.1.21 | 0x1f |
//! | [`get`]               | 6.1.23 | 0x0a |
//! | [`locate`]            | 6.1.32 | 0x08 |
//! | [`query`]             | 6.1.45 | 0x18 |
//! | [`revoke`]            | 6.1.49 | 0x13 |
//! | [`sign`]              | 6.1.60 | 0x21 |
//! | [`signature_verify`]  | 6.1.61 | 0x22 |
//!
//! All 12 v0.1 KMIP ops shipped. Shared helpers (audit emission, canonical
//! algorithm names) live in [`helpers`] so every op file stays focused on
//! its own KMIP semantics.
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

pub mod activate;
pub mod create;
pub mod create_key_pair;
pub mod decrypt;
pub mod deps;
pub mod destroy;
pub mod encrypt;
pub mod get;
pub mod get_attribute_list;
pub mod get_attributes;
pub mod helpers;
pub mod interop;
pub mod locate;
pub mod query;
pub mod revoke;
pub mod sign;
pub mod signature_verify;

pub use deps::{Deps, DepsConfig};
