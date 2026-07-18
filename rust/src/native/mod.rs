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
//! **Implemented.** Each sub-module (keygen / sign / encrypt / object /
//! session / parity) drives the real PKCS#11 engine and is covered by
//! focused tests — no `unimplemented!()` stubs remain on this surface.
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
//! CORRECTED 2026-07-18 (was stale — see the hsm-perf-bench plan,
//! `rust-hsm-perf-bench-scenario-plan-07182026.md` §B7, and the
//! `test_lock` doc comment below, which already had this right). Engine
//! storage (`OBJECTS`, `SESSIONS`, `TOKEN_STORE`, and everything else in
//! `state.rs`) is `lazy_static! ref _: Mutex<T>` — **global, not
//! `thread_local!`** — so `native::*` calls from multiple OS threads are
//! memory-safe with no pinning requirement. This is empirically verified,
//! not just source-read: `tests/multitenant_concurrency.rs` drives 20
//! threads concurrently through keygen/sign/verify on one shared token
//! (real contention on the global `OBJECTS` mutex) with zero corruption.
//! `pqctoday-hsm/kmip/` has no `Session: !Send` wrapper (never
//! implemented — the pinned-thread "Option A" design in
//! `docs/NATIVE_API.md` §4 describes a plan that was superseded by the
//! simpler global-mutex approach the code actually took); KMIP already
//! calls `native::*` from tokio's multi-threaded blocking pool today.
//!
//! What IS still true and load-bearing: two DIFFERENT sessions must not
//! share one multi-part operation across threads (SIGN_STATE etc. are
//! keyed by session handle, not thread — see `state.rs`), and PKCS#11
//! login state is per-TOKEN, not per-session (§5.6) — only the first
//! `C_Login` on a token succeeds, so concurrent callers on one token
//! should log in once, then open sessions without repeating login.
//!
//! One CONFIRMED, currently-open gap: unlike `ffi::C_*` (which enforces
//! `state::can_access_object` token-scoping at 8 call sites), `native::*`
//! does NOT enforce it — a native caller holding a numeric object handle
//! can operate on it regardless of which slot/tenant it belongs to. KMIP
//! uses `native::*` exclusively with one shared `engine_session` for
//! every client and has no compensating ownership check of its own
//! (verified: no owner/Identity field in the KeyStore trait, no
//! ownership check in the dispatcher). This must be closed — either by
//! adding the `can_access_object` gate to `native::*`, or by KMIP
//! tracking per-Identity object ownership — before any multi-tenant
//! design that relies on native-surface isolation is real.

pub mod agree;
pub mod derive;
pub mod encrypt;
pub(crate) mod hbs;
pub mod hybrid;
pub mod keygen;
pub mod object;
pub mod session;
pub mod sign;
pub mod split_key;

pub use agree::*;
pub use derive::*;
pub use encrypt::*;
pub use keygen::*;
pub use object::*;
pub use session::*;
pub use split_key::{join, split};
pub use sign::*;

/// `CK_RV` (PKCS#11 return value). Matches `ffi::CkRv` / the C ABI's
/// `CKR_*` codepoints. The native API surfaces these as `Result<T, CkRv>`
/// so KMIP can map them to KMIP `ResultReason` without an intermediate
/// type. `CKR_OK = 0x00000000` is `Ok(_)`; any other `CK_RV` is `Err(_)`.
pub type CkRv = u32;

#[cfg(test)]
mod parity;

#[cfg(test)]
mod prehash_kat;

#[cfg(test)]
mod prehash_kat_slh;

#[cfg(test)]
pub(crate) mod test_lock {
    //! Shared mutex serialising every test in `native::*` that touches
    //! engine state.
    //!
    //! Engine storage (`OBJECTS`, `SESSIONS`, `TOKEN_STORE`) is
    //! `lazy_static! ref _: Mutex<T>` — **global**, not `thread_local!`.
    //! cargo test runs tests in parallel by default; without this lock,
    //! the engine's lifecycle dance (`init_token` → SO login →
    //! `init_pin` → logout → user login) races across threads, producing
    //! `CKR_SESSION_EXISTS` (0xB6) or `CKR_USER_NOT_LOGGED_IN` (0x101).
    //!
    //! Acquire at the top of every `#[test]` body that calls
    //! `native::*`: `let _guard = test_lock::acquire();`.
    use std::sync::{Mutex, MutexGuard, OnceLock};

    pub fn acquire() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }
}
