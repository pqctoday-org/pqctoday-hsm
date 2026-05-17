// ── Native (non-wasm32) session layer ────────────────────────────────────────
//
// On wasm32 none of this compiles: `cryptoki` uses `libloading` / `dlopen`
// which browsers don't support. The wasm32 path uses `WasmPkcs11Backend`
// in `backend.rs` which talks to `softhsmrustv3` directly as a Rust dep.
//
// `HsmConfig` is re-exported on both targets so callers can always refer to
// the type, even though on wasm32 it has no fields (never constructed).

/// Configuration for connecting to a PKCS#11 module.
#[derive(Debug, Clone)]
pub struct HsmConfig {
    /// Path to the PKCS#11 module shared library
    /// (e.g. `/usr/local/lib/softhsm/libsofthsm2.so` or our softhsmv3 .so).
    #[cfg(not(target_arch = "wasm32"))]
    pub module_path: std::path::PathBuf,
    /// Slot to open. `None` → pick the first slot with an initialised token.
    #[cfg(not(target_arch = "wasm32"))]
    pub slot_index: Option<usize>,
    /// User PIN. `None` → operate in public-session mode (verify-only).
    #[cfg(not(target_arch = "wasm32"))]
    pub user_pin: Option<String>,
}

#[cfg(not(target_arch = "wasm32"))]
impl HsmConfig {
    pub fn new(module_path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            module_path: module_path.into(),
            slot_index: None,
            user_pin: None,
        }
    }

    pub fn with_pin(mut self, pin: impl Into<String>) -> Self {
        self.user_pin = Some(pin.into());
        self
    }

    pub fn with_slot(mut self, idx: usize) -> Self {
        self.slot_index = Some(idx);
        self
    }
}

// ── Native-only HsmSession ────────────────────────────────────────────────────

#[cfg(not(target_arch = "wasm32"))]
use std::sync::Arc;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::Mutex;

#[cfg(not(target_arch = "wasm32"))]
use cryptoki::context::{CInitializeArgs, Pkcs11};
#[cfg(not(target_arch = "wasm32"))]
use cryptoki::session::{Session, UserType};
#[cfg(not(target_arch = "wasm32"))]
use cryptoki::slot::Slot;
#[cfg(not(target_arch = "wasm32"))]
use cryptoki::types::AuthPin;

#[cfg(not(target_arch = "wasm32"))]
use crate::error::PqcTodayError;

/// A live, logged-in PKCS#11 session shared by the provider's sub-providers.
///
/// `Pkcs11` owns the library handle; `Session` owns the session. Both are
/// kept inside an `Arc<Mutex<…>>` because `OpenMlsCrypto` is `Send + Sync`
/// and is used from arbitrary threads inside OpenMLS.
#[cfg(not(target_arch = "wasm32"))]
pub struct HsmSession {
    pub(crate) ctx: Arc<Pkcs11>,
    pub(crate) slot: Slot,
    pub(crate) session: Arc<Mutex<Session>>,
}

#[cfg(not(target_arch = "wasm32"))]
impl HsmSession {
    /// Open a session against `cfg.module_path`, optionally logging in.
    pub fn open(cfg: &HsmConfig) -> Result<Self, PqcTodayError> {
        let ctx = Pkcs11::new(&cfg.module_path)?;
        ctx.initialize(CInitializeArgs::OsThreads)?;

        let slots = ctx.get_slots_with_initialized_token()?;
        let slot = match cfg.slot_index {
            Some(i) => *slots.get(i).ok_or(PqcTodayError::NotInitialised)?,
            None => *slots.first().ok_or(PqcTodayError::NotInitialised)?,
        };

        let session = ctx.open_rw_session(slot)?;
        if let Some(pin) = &cfg.user_pin {
            session.login(UserType::User, Some(&AuthPin::new(pin.clone())))?;
        }

        Ok(Self {
            ctx: Arc::new(ctx),
            slot,
            session: Arc::new(Mutex::new(session)),
        })
    }

    pub fn slot(&self) -> Slot {
        self.slot
    }

    /// Open a **new independent session** against the same PKCS#11 context.
    ///
    /// Used when two co-resident providers need to share one HSM module but
    /// keep their session state separate. Logs the new session in as
    /// `UserType::User` if a PIN is supplied. The returned `HsmSession`
    /// shares the underlying `Arc<Pkcs11>` (no second `C_Initialize`),
    /// shares the slot, but owns its own `Session` handle.
    pub fn open_additional_session(&self, user_pin: Option<&str>) -> Result<Self, PqcTodayError> {
        let session = self.ctx.open_rw_session(self.slot)?;
        if let Some(pin) = user_pin {
            session.login(UserType::User, Some(&AuthPin::new(pin.to_string())))?;
        }
        Ok(Self {
            ctx: Arc::clone(&self.ctx),
            slot: self.slot,
            session: Arc::new(Mutex::new(session)),
        })
    }

    /// Borrow the session mutex for a single PKCS#11 call.
    pub(crate) fn with_session<R>(
        &self,
        f: impl FnOnce(&Session) -> Result<R, PqcTodayError>,
    ) -> Result<R, PqcTodayError> {
        let guard = self.session.lock().map_err(|_| PqcTodayError::NotInitialised)?;
        f(&guard)
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Clone for HsmSession {
    fn clone(&self) -> Self {
        Self {
            ctx: Arc::clone(&self.ctx),
            slot: self.slot,
            session: Arc::clone(&self.session),
        }
    }
}
