//! `softhsmrustv3::native` — typed Rust API for native callers.
//!
//! See [`docs/NATIVE_API.md`](../../docs/NATIVE_API.md) for the full
//! scoping document.
//!
//! ## Problem this module solves
//!
//! `pub mod ffi` exposes the PKCS#11 C ABI designed for wasm32:
//! `CK_ATTRIBUTE.pValue` is a 32-bit pointer (cast through `as usize as
//! *const u8`). On wasm32 pointers ARE 32 bits and this works. On native
//! 64-bit hosts the pointer is silently truncated, leading to garbage
//! reads or UB on dereference. The `pqctoday-hsm/openmls-provider/
//! wasm-smoke/` crate gates its `softhsmrustv3` dep behind
//! `cfg(target_arch = "wasm32")` for exactly this reason.
//!
//! `pub mod native` exposes the **same engine functionality** through
//! typed Rust signatures — no pointer marshalling, no CK_ATTRIBUTE
//! templates — so the `pqctoday-hsm/kmip/` native server can drive the
//! engine without the wasm32 ABI hazards.
//!
//! ## Status
//!
//! **Skeleton** (this commit). All functions are `unimplemented!()` stubs.
//! Implementations land in the follow-up commits enumerated in §9 of the
//! scoping doc — one sub-module per commit, each with focused tests.
//!
//! ## Architectural relationship to `ffi`
//!
//! `native::*` and `ffi::C_*` are **parallel surfaces** over the same
//! engine internals (`crypto::handlers::sign_*` / `verify_*` typed
//! primitives, plus `state::*` typed object storage). The `ffi` surface
//! is the marshalling layer for wasm32 + PKCS#11 spec compliance; the
//! `native` surface is the typed pass-through for native Rust callers.
//! No behaviour change to `ffi` is allowed — see `docs/NATIVE_API.md` §5.
//!
//! ## Threading model
//!
//! Native callers MUST pin all `native::*` calls to one OS thread (the
//! engine's `OBJECTS` / `SESSIONS` storage is `thread_local!`). Phase 4's
//! `Session: !Send` in `pqctoday-hsm/kmip/` already aligns the KMIP
//! server with this constraint. See `docs/NATIVE_API.md` §4 (Option A).

pub mod encrypt;
pub mod keygen;
pub mod object;
pub mod session;
pub mod sign;

pub use encrypt::*;
pub use keygen::*;
pub use object::*;
pub use session::*;
pub use sign::*;

/// `CK_RV` (PKCS#11 return value). Matches `ffi::CkRv` / the C ABI's
/// `CKR_*` codepoints. The native API surfaces these as `Result<T, CkRv>`
/// so KMIP can map them to KMIP `ResultReason` without an intermediate
/// type. `CKR_OK = 0x00000000` is `Ok(_)`; any other `CK_RV` is `Err(_)`.
pub type CkRv = u32;
