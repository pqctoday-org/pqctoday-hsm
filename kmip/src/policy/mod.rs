//! Plane 1 — Crypto Agility Management Plane.
//!
//! Policy engine, rule types, YAML loader, inventory, compliance mapping.
//!
//! Phase 0 (bootstrap): module declared, no implementation. Lands in Phase 4.5
//! per `docs/IMPLEMENTATION_PLAN.md` §6. Built BEFORE op handlers (Phase 5) so
//! `dispatcher` can call `policy::Engine::evaluate()` before any op work.
