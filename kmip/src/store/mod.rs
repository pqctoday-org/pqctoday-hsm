//! Plane 2 — KMIP object store + lifecycle FSM.
//!
//! Two backends:
//!
//! - [`MemoryStore`] — in-process, lost on restart. Unit tests + sandbox
//!   dev runs where durability isn't required.
//! - [`SqliteStore`] — Phase-6 durable store via `rusqlite` +
//!   `rusqlite_migration`. Drop-in swap for `MemoryStore` (same trait,
//!   same record shape). Schema per `docs/IMPLEMENTATION_PLAN.md` §3.3.
//!
//! Both run every state-changing `update` through
//! [`lifecycle::enforce_transition`] — defense-in-depth on top of the
//! handler-level FSM checks in Phase 5.

pub mod lifecycle;
pub mod memory;
// Durable SQLite backend — `native` only (bundled SQLite C does not
// cross-compile to wasm32; the wasm core uses `MemoryStore`).
#[cfg(feature = "native")]
pub mod sqlite;
pub mod traits;

pub use memory::MemoryStore;
#[cfg(feature = "native")]
pub use sqlite::SqliteStore;
pub use traits::{KeyStore, ObjectRecord, Uid};
