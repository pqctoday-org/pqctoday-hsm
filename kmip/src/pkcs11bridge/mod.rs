//! Plane 3 — PKCS#11 bridge to `softhsmrustv3`.
//!
//! Wraps the raw PKCS#11 v3.2 C ABI exposed by the engine in a safe Rust
//! surface that Phase 5 op handlers can drive without thinking about raw
//! pointers or `CK_RV` codepoints.
//!
//! Layout (per `docs/IMPLEMENTATION_PLAN.md` §6 Phase 4):
//!
//! - [`error`]   — `BridgeError` enum mapping `CKR_*` return codes.
//! - [`mechs`]   — PKCS#11 mechanism constants the bridge cares about. Pulls
//!                 the FIPS-only vendor codepoints from
//!                 [`crate::kmip30::algos`] so there's one mech table for
//!                 the whole subsystem.
//! - [`session`] — RAII [`session::Session`] wrapper. `open()` initialises
//!                 the engine, opens an R/W user session, logs in. `drop()`
//!                 closes the session. Op-method bodies (sign / encapsulate
//!                 / etc.) are not in this phase — they land in Phase 5
//!                 alongside the handlers that consume them.
//!
//! Phase 4 deliberately does NOT call into any softhsmrustv3 entry point
//! beyond `C_Initialize`, `C_OpenSession`, `C_CloseSession`, and `C_Login`
//! — the rest are coupled to op semantics that belong with their handlers.

pub mod error;
pub mod mechs;
pub mod session;

pub use error::{BridgeError, CkRv, Result, CKR_OK};
pub use session::{Session, SessionHandle, SlotId};
