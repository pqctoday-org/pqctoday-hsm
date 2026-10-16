//! Helpers shared by the named PKCS#11 interfaces served over KMIP Operation PKCS_11 (0x33): the protected
//! replication bridge (`replication_bridge`, educational builds) and the FHE custody bridge (`fhe_bridge`, default
//! native build, plan D02387 WP-B).
//!
//! - object lookup by `CKA_UNIQUE_ID` inside the caller's session, serialised because the engine's find operation
//!   is per-session state and KMIP connections can share one engine session;
//! - the security-officer context: each SO call runs in a fresh engine application context with a real SO login,
//!   using the board-local, root-only SO PIN file configured at server start (replication addendum §1.1, owner O7).

use std::sync::Mutex;

use softhsmrustv3::constants::{CKA_UNIQUE_ID, CKF_RW_SESSION, CKF_SERIAL_SESSION, CKR_OK, CKU_SO};

/// mTLS client-certificate CN of the token's security officer over KMIP: one SO identity for the replication admin
/// interface and the FHE interface (owner decision 2026-10-15).
pub const ROLE_SO_CN: &str = "replication-admin";

// PKCS#11 return codes used by the bridges (values from pkcs11t.h).
pub(crate) const CKR_ARGUMENTS_BAD: u32 = 0x0000_0007;
pub(crate) const CKR_DATA_INVALID: u32 = 0x0000_0020;
pub(crate) const CKR_FUNCTION_NOT_SUPPORTED: u32 = 0x0000_0054;
pub(crate) const CKR_KEY_HANDLE_INVALID: u32 = 0x0000_0060;
pub(crate) const CKR_USER_NOT_LOGGED_IN: u32 = 0x0000_0101;
pub(crate) const CKR_USER_TYPE_INVALID: u32 = 0x0000_0103;

/// Board-local, root-only file holding the SO PIN (owner O7). Set once at server start.
static SO_PIN_FILE: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
/// Slot the SO context logs into (the server's `--slot`).
static ADMIN_SLOT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Configure the SO path (server start). The first call wins; both bridges read the same file.
pub fn configure_admin(pin_file: std::path::PathBuf, slot: u32) {
    let _ = SO_PIN_FILE.set(pin_file);
    ADMIN_SLOT.store(slot, std::sync::atomic::Ordering::Relaxed);
}

/// Connection metadata for an SO application context (replication addendum §5, A-16): the client certificate hash
/// and listener address the TLS listener authenticated for this request, stamped into the engine's audit lines.
/// Without a TLS connection (an in-process call) the certificate hash stays all-zero and `listener` is `fallback`.
pub(crate) fn admin_context_meta(role: &str, fallback: &str) -> softhsmrustv3::app_context::ContextMeta {
    let conn = crate::server::conn_meta::current();
    softhsmrustv3::app_context::ContextMeta {
        role: role.to_string(),
        client_cert_sha256: conn.as_ref().map(|c| c.client_cert_sha256).unwrap_or([0u8; 32]),
        listener: conn.map(|c| c.listener).unwrap_or_else(|| fallback.to_string()),
        correlation: None,
    }
}

/// Run `f` in a fresh application context: open a R/W session in it, SO login with the board-local PIN, run, log
/// out; the guard destroys the context and its sessions. The KMIP server closes each connection after one Request
/// Message, so this per-request context is the per-connection context of the replication addendum §1.1. User work
/// in the default context is not paused.
pub(crate) fn so_call(meta: softhsmrustv3::app_context::ContextMeta, f: impl FnOnce(u32) -> Result<Vec<u8>, u32>) -> Result<Vec<u8>, u32> {
    use softhsmrustv3::app_context::{self, ContextGuard};
    let pin = SO_PIN_FILE
        .get()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|s| s.trim().to_string())
        .ok_or(CKR_USER_NOT_LOGGED_IN)?;
    let guard = ContextGuard::new(meta);
    let slot = ADMIN_SLOT.load(std::sync::atomic::Ordering::Relaxed);
    let h = app_context::open_session(guard.id(), slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)?;
    let mut p = pin.into_bytes();
    let rv = softhsmrustv3::ffi::C_Login(h, CKU_SO, p.as_mut_ptr(), p.len() as u32);
    zeroize_vec(&mut p);
    if rv != CKR_OK {
        return Err(rv);
    }
    let r = f(h);
    let _ = softhsmrustv3::ffi::C_Logout(h);
    drop(guard);
    r
}

pub(crate) fn zeroize_vec(v: &mut [u8]) {
    for b in v.iter_mut() {
        unsafe { std::ptr::write_volatile(b, 0) };
    }
}

/// The engine's find operation is per-session state, and KMIP connections share one engine session in
/// single-tenant mode, so key lookups are serialised.
static FIND_LOCK: Mutex<()> = Mutex::new(());

/// Exactly one object visible to `s` with this `CKA_UNIQUE_ID`, else `CKR_KEY_HANDLE_INVALID`.
pub(crate) fn by_uid(s: u32, uid: &[u8]) -> Result<u32, u32> {
    let _g = FIND_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let value = uid.to_vec();
    let template = [CKA_UNIQUE_ID as usize, value.as_ptr() as usize, value.len()];
    let ffi = |rv: u32| if rv == CKR_OK { Ok(()) } else { Err(rv) };
    ffi(softhsmrustv3::ffi::C_FindObjectsInit(s, template.as_ptr() as *mut u8, 1))?;
    let mut buf = [0u32; 2];
    let mut n = 0u32;
    let rv = softhsmrustv3::ffi::C_FindObjects(s, buf.as_mut_ptr(), 2, &mut n);
    let _ = softhsmrustv3::ffi::C_FindObjectsFinal(s);
    ffi(rv)?;
    if n == 1 { Ok(buf[0]) } else { Err(CKR_KEY_HANDLE_INVALID) }
}

/// The engine's replication profile is process-global: tests in either bridge that select or clear it must not
/// overlap.
#[cfg(test)]
pub(crate) fn profile_lock() -> std::sync::MutexGuard<'static, ()> {
    static L: Mutex<()> = Mutex::new(());
    L.lock().unwrap_or_else(|e| e.into_inner())
}
