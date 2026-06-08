//! Plane 2 — KMIP operation handlers (one file per op, ≤100 LOC each).
//!
//! v0.1 op set per `docs/IMPLEMENTATION_PLAN.md` §6 Phase 5:
//! `query`, `create_sym`, `create_asym`, `get`, `locate`, `activate`, `revoke`,
//! `destroy`, `encrypt`, `decrypt`, `sign`, `signature_verify`.
//!
//! Note: KMIP 3.0 does NOT add separate `Encapsulate` / `Decapsulate` ops. ML-KEM
//! encapsulation reuses `Encrypt`; ML-KEM decapsulation reuses `Decrypt`. The
//! handler branches on key algorithm.
//!
//! Phase 0 (bootstrap): module declared, no implementations. Lands in Phase 5.
