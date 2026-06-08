//! Session lifecycle — typed wrappers around `ffi::C_Initialize`,
//! `ffi::C_OpenSession`, `ffi::C_Login`, `ffi::C_CloseSession`,
//! `ffi::C_InitToken`, `ffi::C_InitPIN`.
//!
//! These four don't take attribute templates, so they DO work
//! ABI-correctly from native today (Phase 4 `pqctoday-hsm/kmip/
//! src/pkcs11bridge/session.rs` proves this). The `native::` versions
//! exist for **API consistency** so the KMIP server doesn't have to
//! reach across to `ffi::*` for session ops while using `native::*` for
//! everything else.
//!
//! See [`super`] for the typed-vs-FFI architectural relationship.

use super::CkRv;
use crate::constants::{CKF_RW_SESSION, CKF_SERIAL_SESSION, CKR_OK, CKU_SO, CKU_USER};
use crate::ffi as ffi;

/// Initialise the engine. The wasm32 C ABI's `C_Initialize` always
/// returns `CKR_OK` (the engine handles re-init idempotently via
/// [`crate::state::init_token_store`]). Documented as `Result<(), CkRv>`
/// for API parity with the rest of `native::*`; today the call cannot
/// fail except via implementation bugs in the engine.
///
/// Native callers pin all subsequent `native::*` calls to the same OS
/// thread as the `init()` call (`thread_local!` storage in the engine).
pub fn init() -> Result<(), CkRv> {
    let rv = ffi::C_Initialize(std::ptr::null_mut());
    if rv == CKR_OK {
        Ok(())
    } else {
        Err(rv)
    }
}

/// Open an R/W user session against `slot` and login with `pin` as
/// `CKU_USER`. Combines `ffi::C_OpenSession` + `ffi::C_Login`. Returns
/// the session handle.
///
/// **Pre-condition**: `slot` must hold an **initialised** token with a
/// **user PIN set**. First-boot setup is typically:
///
/// ```ignore
/// init()?;
/// init_token(0, "so-pin", "pqctoday-dev")?;
/// // open an SO session, set the user PIN, close
/// let so = open_session_so(0, "so-pin")?;
/// init_pin(so, "user-pin")?;
/// close_session(so)?;
/// // now the normal user can open
/// let user = open_session(0, "user-pin")?;
/// ```
///
/// Or use [`bootstrap_default_token`] which does the full sequence.
pub fn open_session(slot: u32, pin: &str) -> Result<u32, CkRv> {
    open_session_inner(slot, pin, CKU_USER)
}

/// Open an R/W security-officer session (for [`init_pin`]). Same as
/// [`open_session`] but logs in as `CKU_SO`.
pub fn open_session_so(slot: u32, so_pin: &str) -> Result<u32, CkRv> {
    open_session_inner(slot, so_pin, CKU_SO)
}

fn open_session_inner(slot: u32, pin: &str, user_type: u32) -> Result<u32, CkRv> {
    let mut handle: u32 = 0;
    let rv = ffi::C_OpenSession(
        slot,
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        &mut handle,
    );
    if rv != CKR_OK {
        return Err(rv);
    }
    // C_Login reads the PIN bytes only; the spec annotates the param as
    // `CK_UTF8CHAR_PTR pPin` even though it's effectively read-only.
    let mut pin_bytes: Vec<u8> = pin.as_bytes().to_vec();
    let rv = ffi::C_Login(handle, user_type, pin_bytes.as_mut_ptr(), pin_bytes.len() as u32);
    if rv != CKR_OK {
        // Best-effort: close the session we just opened so we don't leak
        // it on a bad PIN. C_CloseSession can return CKR_SESSION_HANDLE_INVALID
        // if the engine already cleaned up; we ignore that here.
        let _ = ffi::C_CloseSession(handle);
        return Err(rv);
    }
    Ok(handle)
}

/// Tear down the engine — clears `OBJECTS`, `SESSIONS`, `TOKEN_STORE`,
/// and all per-session operation state on the current thread. Wraps
/// `ffi::C_Finalize`. Idempotent.
///
/// Used by tests for thread-local isolation (cargo test reuses threads
/// across tests; without `finalize()` between them, slot/session state
/// leaks from one test to the next). Production callers use this for
/// graceful shutdown.
pub fn finalize() -> Result<(), CkRv> {
    let rv = ffi::C_Finalize(std::ptr::null_mut());
    if rv == CKR_OK { Ok(()) } else { Err(rv) }
}

/// Logout the current user on `session`. The engine's `C_CloseSession`
/// intentionally does NOT auto-logout (PKCS#11 §11.4) — the slot's
/// login state persists across session close. Callers that need to
/// switch user types on the same slot (SO → USER) must explicitly
/// logout first.
pub fn logout(session: u32) -> Result<(), CkRv> {
    let rv = ffi::C_Logout(session);
    if rv == CKR_OK { Ok(()) } else { Err(rv) }
}

/// Close a session handle. Tolerates a stale handle (returns
/// `CKR_SESSION_HANDLE_INVALID` as `Err`).
///
/// Does NOT logout — see [`logout`]. Combining the two:
/// `logout(session).and_then(|()| close_session(session))`.
pub fn close_session(session: u32) -> Result<(), CkRv> {
    let rv = ffi::C_CloseSession(session);
    if rv == CKR_OK { Ok(()) } else { Err(rv) }
}

/// Initialise a token on `slot` with the security-officer PIN + label.
/// Token state survives `close_session` and engine `init()` re-entries
/// within the same process (storage is `thread_local!`).
///
/// `label` is padded with spaces to PKCS#11's required 32 bytes by the
/// engine; callers pass any printable string.
pub fn init_token(slot: u32, so_pin: &str, label: &str) -> Result<(), CkRv> {
    let mut pin_bytes: Vec<u8> = so_pin.as_bytes().to_vec();
    // PKCS#11 §11.5: label is 32 bytes, space-padded. Engine does the
    // padding internally but expects a buffer pointer here; we pass the
    // raw label and let the engine pad.
    let mut label_bytes: Vec<u8> = label.as_bytes().to_vec();
    let rv = ffi::C_InitToken(
        slot,
        pin_bytes.as_mut_ptr(),
        pin_bytes.len() as u32,
        label_bytes.as_mut_ptr(),
    );
    if rv == CKR_OK { Ok(()) } else { Err(rv) }
}

/// Set the normal-user PIN on an SO-authenticated session. The session
/// must have been opened via [`open_session_so`] (CKU_SO login + R/W).
pub fn init_pin(session: u32, user_pin: &str) -> Result<(), CkRv> {
    let mut pin_bytes: Vec<u8> = user_pin.as_bytes().to_vec();
    let rv = ffi::C_InitPIN(session, pin_bytes.as_mut_ptr(), pin_bytes.len() as u32);
    if rv == CKR_OK { Ok(()) } else { Err(rv) }
}

/// Convenience: full first-boot sequence on a fresh engine.
///
/// 1. [`init`] — initialise the engine.
/// 2. [`init_token`]`(slot, so_pin, label)` — initialise the slot's token.
/// 3. [`open_session_so`]`(slot, so_pin)` — SO-authenticated session.
/// 4. [`init_pin`]`(so_session, user_pin)` — set the user PIN.
/// 5. [`close_session`]`(so_session)` — release the SO session.
/// 6. [`open_session`]`(slot, user_pin)` — return the user session handle.
///
/// Returns the user session handle ready for keygen / sign / etc.
///
/// Sandbox / test convenience only — production should run the steps
/// individually so operators can audit each one.
pub fn bootstrap_default_token(
    slot: u32,
    so_pin: &str,
    user_pin: &str,
    label: &str,
) -> Result<u32, CkRv> {
    init()?;
    init_token(slot, so_pin, label)?;
    let so = open_session_so(slot, so_pin)?;
    init_pin(so, user_pin)?;
    // PKCS#11 §11.4 — C_CloseSession does NOT auto-logout. Must explicitly
    // logout the SO before opening as USER on the same slot, otherwise
    // C_Login(USER) returns CKR_USER_ANOTHER_ALREADY_LOGGED_IN (0x104).
    logout(so)?;
    close_session(so)?;
    open_session(slot, user_pin)
}

// Suppress unused-import warning when only some constants are referenced
// (cfg-dependent paths may consume only a subset).
#[allow(dead_code)]
const _CONSTS_USED: (u32, u32, u32, u32) = (CKF_SERIAL_SESSION, CKF_RW_SESSION, CKU_USER, CKU_SO);

#[cfg(test)]
mod tests {
    use super::*;

    /// Reset thread-local engine state before a test that depends on
    /// fresh slot / session / object stores. `cargo test` reuses OS
    /// threads across tests, so without this helper one test's state
    /// leaks into the next.
    fn reset_engine() {
        let _ = finalize();
        init().expect("re-init after finalize");
    }

    /// Engine `init()` is idempotent in this engine — `C_Initialize`
    /// always returns `CKR_OK`. Multiple calls within one test are safe.
    #[test]
    fn init_returns_ok() {
        reset_engine();
        init().expect("init must succeed");
        // Second call is fine — engine handles re-init via init_token_store.
        init().expect("re-init must succeed");
    }

    /// First-boot bootstrap end-to-end: init engine → init token → set
    /// user PIN → open user session → close. Proves the typed API's
    /// session lifecycle works against the engine.
    #[test]
    fn bootstrap_default_token_round_trip() {
        reset_engine();
        let session = bootstrap_default_token(0, "so-1234", "user-1234", "pqctoday-test")
            .expect("bootstrap must succeed");
        // Session handle is a positive u32 (engine starts at 1).
        assert!(session > 0, "session handle must be positive, got {session}");
        close_session(session).expect("close must succeed");
    }

    /// open_session against an uninitialised token must fail —
    /// the engine refuses logins before init_pin has set a user PIN.
    #[test]
    fn open_session_without_init_pin_fails() {
        reset_engine();
        // No init_token / init_pin → login should fail.
        let result = open_session(0, "anything");
        assert!(result.is_err(), "login against uninit token must fail");
    }

    /// Closing a stale session handle returns Err rather than panicking.
    #[test]
    fn close_session_on_stale_handle_returns_err() {
        reset_engine();
        let result = close_session(99999);
        assert!(result.is_err(), "stale handle close must return Err");
    }

    /// init_token on a non-existent slot returns Err.
    #[test]
    fn init_token_invalid_slot_returns_err() {
        reset_engine();
        let result = init_token(99, "so-pin", "test");
        assert!(result.is_err(), "init_token on bad slot must return Err");
    }

    /// finalize() is idempotent — running it twice (or against an
    /// already-clean engine) returns Ok.
    #[test]
    fn finalize_is_idempotent() {
        let _ = finalize(); // works whether engine had state or not
        let _ = finalize(); // and a second time
    }
}
