//! Plane 2 — KMIP object store + lifecycle FSM.
//!
//! Phase 5 (this) ships the [`KeyStore`] trait + [`MemoryStore`] impl —
//! the minimum surface the op handlers need to compile + test. Phase 6
//! ships the SQLite-backed durable store with full lifecycle FSM
//! enforcement per `docs/IMPLEMENTATION_PLAN.md` §3.4.

pub mod memory;
pub mod traits;

pub use memory::MemoryStore;
pub use traits::{KeyStore, ObjectRecord, Uid};
