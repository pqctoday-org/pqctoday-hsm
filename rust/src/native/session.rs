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

/// Idempotent engine initialisation. Calls `ffi::C_Initialize`; treats
/// `CKR_CRYPTOKI_ALREADY_INITIALIZED` (0x00000191) as success.
pub fn init() -> Result<(), CkRv> {
    unimplemented!("native::session::init — Phase 7b commit 2")
}

/// Open an R/W user session against `slot` and login with `pin`.
/// Combines `ffi::C_OpenSession` + `ffi::C_Login`. Returns the session
/// handle.
pub fn open_session(_slot: u32, _pin: &str) -> Result<u32, CkRv> {
    unimplemented!("native::session::open_session — Phase 7b commit 2")
}

/// Close a session handle.
pub fn close_session(_session: u32) -> Result<(), CkRv> {
    unimplemented!("native::session::close_session — Phase 7b commit 2")
}

/// Initialise a token on `slot` with the security-officer PIN.
/// Token state survives `close_session` but not engine restart unless
/// the storage backend persists it.
pub fn init_token(_slot: u32, _so_pin: &str, _label: &str) -> Result<(), CkRv> {
    unimplemented!("native::session::init_token — Phase 7b commit 2")
}

/// Set the normal-user PIN on an SO-authenticated session.
pub fn init_pin(_session: u32, _user_pin: &str) -> Result<(), CkRv> {
    unimplemented!("native::session::init_pin — Phase 7b commit 2")
}
