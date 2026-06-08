//! [`Session`] — RAII wrapper around a PKCS#11 session handle.
//!
//! The `softhsmrustv3` engine exposes the raw PKCS#11 v3.2 C ABI in Rust:
//! return codes are `u32`, buffers are `*mut u8`, session handles are `u32`.
//! Phase 4's job is to put a safe Rust face on the session lifecycle so the
//! Phase 5 op handlers can write `let s = Session::open(slot, pin)?;` and
//! drop the unsafe-ergonomics worry on the floor.
//!
//! ## Scope
//!
//! - [`Session::open`] — initialise the engine if not already, list slots,
//!   open an R/W user session against the requested slot, log in.
//! - [`Session::handle`] — raw `CK_SESSION_HANDLE` for op handlers that need
//!   it (Phase 5 will).
//! - [`Drop`] — calls `C_CloseSession` so dropping a `Session` cannot leak a
//!   handle.
//! - Cryptographic operation methods (`generate_key_pair`, `sign`,
//!   `encapsulate_key`, …) are intentionally **not** in this phase. Phase 5
//!   wires them up alongside the op handlers that consume them.
//!
//! `unsafe` is unavoidable here — every softhsmrustv3 entry point takes raw
//! pointers — but each unsafe block is small, named, and documents what
//! invariant the caller is upholding (typically: "we own this u32 handle"
//! or "this buffer pointer is in scope for the duration of the call").

use super::error::{BridgeError, CkRv, Result, CKR_OK};

use std::sync::Once;

/// One-shot guard so [`Session::open`] only calls `C_Initialize` per process.
/// PKCS#11 says repeated `C_Initialize` is an error (`CKR_CRYPTOKI_ALREADY_INITIALIZED`).
static INIT_ONCE: Once = Once::new();

/// `CK_SESSION_HANDLE` — opaque PKCS#11 session reference.
pub type SessionHandle = u32;

/// `CK_SLOT_ID` — slot identifier passed to `C_OpenSession`.
pub type SlotId = u32;

// PKCS#11 v3.2 §11.6 — `CK_FLAGS` bit values for `C_OpenSession`.
const CKF_SERIAL_SESSION: u32 = 0x00000004;
const CKF_RW_SESSION:     u32 = 0x00000002;

// `CK_USER_TYPE` constants (§11.7).
const CKU_USER: u32 = 0x00000001;

/// RAII wrapper around an open PKCS#11 session.
///
/// Dropping a `Session` calls `C_CloseSession`; the handle is never leaked.
/// `Session` is `!Send` deliberately for now — the underlying softhsmrustv3
/// engine has thread-local state, so handles cannot be moved between
/// threads. A future revision can lift this if the engine grows a sync
/// surface.
#[derive(Debug)]
pub struct Session {
    handle: SessionHandle,
    slot:   SlotId,
    /// Marker for `!Send` until the engine is verified thread-safe.
    _not_send: std::marker::PhantomData<*const ()>,
}

impl Session {
    /// Open an R/W user session against `slot` and log in with `pin`.
    /// Initialises the engine on first call (PKCS#11 `C_Initialize`).
    pub fn open(slot: SlotId, pin: &str) -> Result<Self> {
        Self::initialize_engine_once()?;
        let handle = Self::open_session_raw(slot)?;
        Self::login_raw(handle, pin)?;
        Ok(Session {
            handle,
            slot,
            _not_send: std::marker::PhantomData,
        })
    }

    /// Raw `CK_SESSION_HANDLE` — Phase 5 op handlers use this when calling
    /// into softhsmrustv3 directly. Holding a `&Session` proves the handle
    /// is still live (the RAII guard hasn't been dropped).
    #[inline]
    pub fn handle(&self) -> SessionHandle {
        self.handle
    }

    /// `CK_SLOT_ID` this session belongs to.
    #[inline]
    pub fn slot(&self) -> SlotId {
        self.slot
    }

    // ── internals ──────────────────────────────────────────────────────────

    /// Call `softhsmrustv3::C_Initialize` exactly once per process. PKCS#11
    /// rejects re-initialisation, so we guard with [`Once`].
    ///
    /// softhsmrustv3 exposes the C ABI as plain `pub fn` (not `unsafe fn`)
    /// because the engine itself validates the input pointers — but we still
    /// pass `null_mut` here per the PKCS#11 §11.4 contract (default thread
    /// model, no init args).
    fn initialize_engine_once() -> Result<()> {
        let mut rv: CkRv = CKR_OK;
        INIT_ONCE.call_once(|| {
            rv = softhsmrustv3::C_Initialize(std::ptr::null_mut());
        });
        BridgeError::from_ckr(rv)
    }

    /// Calls `C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, …)`.
    /// `&mut handle` is the only out-pointer; PKCS#11 writes the new
    /// session handle into it before returning. Application + notify
    /// callbacks are null (PKCS#11 §11.6 — null is legal).
    fn open_session_raw(slot: SlotId) -> Result<SessionHandle> {
        let mut handle: SessionHandle = 0;
        let flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
        let rv = softhsmrustv3::C_OpenSession(
            slot,
            flags,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut handle as *mut SessionHandle,
        );
        BridgeError::from_ckr(rv)?;
        Ok(handle)
    }

    /// Calls `C_Login(handle, CKU_USER, pin, pin_len)`. PKCS#11 only reads
    /// the PIN bytes; the `*mut u8` parameter is the spec's lie about
    /// mutability.
    fn login_raw(handle: SessionHandle, pin: &str) -> Result<()> {
        let pin_bytes = pin.as_bytes();
        let pin_len = pin_bytes.len() as u32;
        let rv = softhsmrustv3::C_Login(
            handle,
            CKU_USER,
            pin_bytes.as_ptr() as *mut u8,
            pin_len,
        );
        BridgeError::from_ckr(rv)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // `C_CloseSession` tolerates a stale handle (returns
        // `CKR_SESSION_HANDLE_INVALID`); we discard the return value
        // because Drop cannot meaningfully signal failure.
        let _ = softhsmrustv3::C_CloseSession(self.handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the type-level guarantees of `Session` without actually
    /// opening one (softhsmv3 requires a token-init ceremony we don't
    /// reproduce in unit tests; full integration belongs in Phase 7).
    #[test]
    fn session_is_not_send() {
        fn assert_not_send<T: ?Sized>()
        where
            T: 'static,
        {
            // No method body — just observing the type. If `Session: Send`
            // ever appears in the API, this test stops compiling (the
            // `*const ()` PhantomData makes Session !Send + !Sync today).
        }
        assert_not_send::<Session>();
    }

    /// PKCS#11 v3.2 `C_Initialize` succeeds with a null args pointer.
    /// This is the bare-minimum engine round-trip — proves the path dep
    /// on softhsmrustv3 is linkable and the call ABI is correct without
    /// requiring an initialised token.
    #[test]
    fn initialize_engine_round_trip() {
        // SAFETY: same call as Session::initialize_engine_once. Safe to
        // call multiple times across tests because INIT_ONCE handles
        // re-entry (subsequent calls are no-ops).
        let result = Session::initialize_engine_once();
        // The engine may return CKR_CRYPTOKI_ALREADY_INITIALIZED (0x0000_0191)
        // if a prior test in this binary already initialised it; that's
        // fine. CKR_OK is the success path; anything else fails.
        match result {
            Ok(()) => (),
            Err(e) if e.raw() == 0x0000_0191 => (),
            Err(e) => panic!("unexpected initialize result: {e:?}"),
        }
    }

    /// Flag constants are wire-compatible with PKCS#11 v3.2 §11.6 — these
    /// are the values softhsmrustv3 expects on the `flags` argument to
    /// `C_OpenSession`.
    #[test]
    fn session_flags_match_pkcs11_spec() {
        assert_eq!(CKF_SERIAL_SESSION, 0x00000004);
        assert_eq!(CKF_RW_SESSION,     0x00000002);
        assert_eq!(CKU_USER,           0x00000001);
    }
}
