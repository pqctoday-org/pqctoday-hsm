//! Plane 2 — SQLite-backed KMIP object store + lifecycle FSM.
//!
//! `rusqlite` wrapper, CRUD, lifecycle state transitions per
//! `docs/IMPLEMENTATION_PLAN.md` §3.4, KMIP `Locate` query builder, `rusqlite_migration`
//! schema versioning.
//!
//! Phase 0 (bootstrap): module declared, no implementation. Lands in Phase 6.
