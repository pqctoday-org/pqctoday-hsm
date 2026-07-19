//! Thin, safety-scoped wrapper around a dlopen'd `softhsmrustv3` shared
//! library, driven purely through its standard PKCS#11 C ABI function
//! table (`CK_FUNCTION_LIST`).
//!
//! hsm-perf-bench plan §A4.1/§P4 — this is deliberately the ONLY way this
//! crate talks to the engine. It never calls into `softhsmrustv3::native::*`
//! or `softhsmrustv3::ffi::*` directly (the crate is a path dependency
//! purely for its public `CK_*` type/const definitions — the Rust-native
//! equivalent of `#include`-ing `pkcs11.h`/`pkcs11t.h`/`pkcs11f.h`, resolved
//! at compile time, touching no runtime state). Every operation goes
//! through the ONE loaded library instance's own function pointers, so all
//! engine state — sessions, tokens, objects — lives in exactly the memory
//! image a real PKCS#11 application would load. Mixing this with a native
//! Rust dependency on the crate's stateful functions would silently create
//! a SECOND, independent copy of the engine's process-global state in the
//! harness's own statically-linked code — sessions/handles from one would
//! be invisible to the other. This module's whole point is to make that
//! mistake impossible: nothing outside `pkcs11.rs` ever sees the raw
//! function table.

use softhsmrustv3::ck_abi::{
    CK_ATTRIBUTE, CK_FLAGS, CK_FUNCTION_LIST, CK_FUNCTION_LIST_PTR, CK_MECHANISM,
    CK_OBJECT_HANDLE, CK_RV, CK_SESSION_HANDLE, CK_SLOT_ID, CK_ULONG, CK_USER_TYPE,
};
use softhsmrustv3::constants::{CKF_RW_SESSION, CKF_SERIAL_SESSION, CKR_OK, CKU_SO, CKU_USER};

use anyhow::{bail, Context, Result};

/// `CK_ULONG`/`CK_RV`/`CK_FLAGS` are all `c_ulong` in the engine's ABI
/// (matching the real PKCS#11 C header — `unsigned long`, 64-bit on
/// macOS/Linux LP64), while this crate's `constants` module keeps its
/// `CKR_*`/`CKF_*` values as plain `u32` (their true bit width — PKCS#11
/// reserves the upper 32 bits of `CK_ULONG` for vendor use, never sets
/// them for defined constants). `as CK_RV` at each use site bridges that,
/// matching the pattern the engine's own `ck_abi.rs` uses internally.
const CKR_OK_RV: CK_RV = CKR_OK as CK_RV;

/// A loaded engine instance and its resolved v2.40 function table.
///
/// Holds the `libloading::Library` for the process's lifetime — the
/// function pointers inside `CK_FUNCTION_LIST` are only valid while the
/// library stays mapped, so this struct must outlive every call made
/// through it. `functions` points into the LOADED LIBRARY's own static
/// data (see `ck_abi.rs::FUNCTION_LIST`), not anything in this process's
/// own binary.
pub struct Engine {
    // Never read after construction — kept alive so the dlopen'd image
    // (and the function pointers `functions` points into) stays mapped.
    _library: libloading::Library,
    functions: *const CK_FUNCTION_LIST,
}

// SAFETY: `CK_FUNCTION_LIST`'s entries are `unsafe extern "C" fn` pointers
// into a loaded shared library's own read-only code segment — calling them
// concurrently from multiple threads is exactly what a PKCS#11 library is
// required to support (PKCS#11 v3.2 §6.5.1: "Cryptoki libraries... are
// safe for multi-threaded access"), and is the whole point of this
// benchmark. The pointer itself never changes after construction.
unsafe impl Send for Engine {}
unsafe impl Sync for Engine {}

impl Engine {
    /// Load `library_path` and resolve its v2.40 function table via
    /// `C_GetFunctionList` — the standard PKCS#11 §5.4 pre-initialization
    /// entry point every real application uses.
    pub fn load(library_path: &str) -> Result<Self> {
        // SAFETY: dlopen'ing an arbitrary path is inherently unsafe (the
        // loaded code runs with this process's full privileges) — bounded
        // here to a path the harness's own caller supplies (a benchmark
        // tool operated by whoever is already running it, not untrusted
        // input from a network request).
        let library = unsafe { libloading::Library::new(library_path) }
            .with_context(|| format!("dlopen {library_path:?}"))?;

        type GetFunctionListFn =
            unsafe extern "C" fn(*mut CK_FUNCTION_LIST_PTR) -> CK_RV;
        // SAFETY: `C_GetFunctionList` is the one symbol PKCS#11 §5.4
        // guarantees every conformant library exports under this exact
        // name, with this exact signature.
        let get_function_list: libloading::Symbol<GetFunctionListFn> =
            unsafe { library.get(b"C_GetFunctionList\0") }
                .context("resolve C_GetFunctionList")?;

        let mut list_ptr: CK_FUNCTION_LIST_PTR = std::ptr::null_mut();
        // SAFETY: `list_ptr` is a valid, non-null out-pointer; the callee
        // (this very library) is required by §5.4 to write a pointer to
        // its own static function-list table, valid for the library's
        // entire loaded lifetime.
        let rv = unsafe { get_function_list(&mut list_ptr) };
        if rv != CKR_OK_RV || list_ptr.is_null() {
            bail!("C_GetFunctionList failed: rv=0x{rv:x}");
        }

        Ok(Self { _library: library, functions: list_ptr })
    }

    // SAFETY (every accessor below): `self.functions` was populated by a
    // successful `C_GetFunctionList` call and the backing library is kept
    // alive by `self._library` for as long as `self` exists, so
    // dereferencing it is sound for the lifetime of every borrow below.
    // `CK_FUNCTION_LIST { version, f: FnListV240 }` — `.f` is the actual
    // per-function pointer table; `funcs()` skips straight to it.
    fn funcs(&self) -> &softhsmrustv3::ck_abi::FnListV240 {
        unsafe { &(*self.functions).f }
    }

    pub fn initialize(&self) -> Result<()> {
        // SAFETY: PKCS#11 §5.6 — a null pInitArgs is always valid.
        ck(unsafe { (self.funcs().C_Initialize)(std::ptr::null_mut()) }, "C_Initialize")
    }

    pub fn finalize(&self) -> Result<()> {
        // SAFETY: PKCS#11 §5.6 — pReserved must be null; we pass null.
        ck(unsafe { (self.funcs().C_Finalize)(std::ptr::null_mut()) }, "C_Finalize")
    }

    /// §5.5 two-call convention: query the count, allocate, fill.
    /// Per this engine's own `C_GetSlotList` (mirroring real SoftHSM):
    /// if every existing slot already has an initialized token, the call
    /// itself manufactures a fresh UNINITIALIZED slot before returning —
    /// "always keep one blank token available for `C_InitToken`" is the
    /// documented SoftHSM multi-token model, not a vendor extension. This
    /// is the ONLY mechanism this harness uses to grow beyond slot 0.
    pub fn get_slot_list(&self) -> Result<Vec<CK_SLOT_ID>> {
        let mut count: CK_ULONG = 0;
        // SAFETY: a null slot-list pointer with a valid `count` out-param
        // is the documented "size query" call (§5.5).
        ck(
            unsafe { (self.funcs().C_GetSlotList)(0, std::ptr::null_mut(), &mut count) },
            "C_GetSlotList(size)",
        )?;
        let mut slots = vec![0 as CK_SLOT_ID; count as usize];
        // SAFETY: `slots` has exactly `count` elements, matching what we
        // just told the engine to expect via `&mut count`.
        ck(
            unsafe { (self.funcs().C_GetSlotList)(0, slots.as_mut_ptr(), &mut count) },
            "C_GetSlotList(fill)",
        )?;
        slots.truncate(count as usize);
        Ok(slots)
    }

    pub fn init_token(&self, slot: CK_SLOT_ID, so_pin: &str, label: &str) -> Result<()> {
        let mut pin = so_pin.as_bytes().to_vec();
        // PKCS#11 §5.4 — C_InitToken's label is ALWAYS a fixed 32-byte,
        // space-padded field with NO separate length parameter; the
        // engine reads exactly 32 bytes from this pointer regardless of
        // what we intend, so under-sizing it would read out of bounds.
        let mut label_buf = [0x20u8; 32];
        let label_bytes = label.as_bytes();
        let n = label_bytes.len().min(32);
        label_buf[..n].copy_from_slice(&label_bytes[..n]);
        // SAFETY: `pin`/`label_buf` are valid, correctly-sized buffers
        // for the duration of this call.
        ck(
            unsafe {
                (self.funcs().C_InitToken)(
                    slot,
                    pin.as_mut_ptr(),
                    pin.len() as CK_ULONG,
                    label_buf.as_mut_ptr(),
                )
            },
            "C_InitToken",
        )
    }

    pub fn open_session(&self, slot: CK_SLOT_ID) -> Result<CK_SESSION_HANDLE> {
        let flags: CK_FLAGS = (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS;
        let mut handle: CK_SESSION_HANDLE = 0;
        // SAFETY: notify callback/application pointers are optional per
        // §5.6 when the library never issues surrender callbacks (this
        // engine doesn't); null is the documented "no callback" value.
        ck(
            unsafe {
                (self.funcs().C_OpenSession)(
                    slot,
                    flags,
                    std::ptr::null_mut(),
                    None,
                    &mut handle,
                )
            },
            "C_OpenSession",
        )?;
        Ok(handle)
    }

    pub fn close_session(&self, session: CK_SESSION_HANDLE) -> Result<()> {
        ck(unsafe { (self.funcs().C_CloseSession)(session) }, "C_CloseSession")
    }

    pub fn login(&self, session: CK_SESSION_HANDLE, user_type: CK_USER_TYPE, pin: &str) -> Result<()> {
        let mut pin_bytes = pin.as_bytes().to_vec();
        ck(
            unsafe {
                (self.funcs().C_Login)(session, user_type, pin_bytes.as_mut_ptr(), pin_bytes.len() as CK_ULONG)
            },
            "C_Login",
        )
    }

    pub fn login_so(&self, session: CK_SESSION_HANDLE, pin: &str) -> Result<()> {
        self.login(session, CKU_SO as CK_USER_TYPE, pin)
    }

    pub fn login_user(&self, session: CK_SESSION_HANDLE, pin: &str) -> Result<()> {
        self.login(session, CKU_USER as CK_USER_TYPE, pin)
    }

    pub fn logout(&self, session: CK_SESSION_HANDLE) -> Result<()> {
        ck(unsafe { (self.funcs().C_Logout)(session) }, "C_Logout")
    }

    pub fn init_pin(&self, session: CK_SESSION_HANDLE, pin: &str) -> Result<()> {
        let mut pin_bytes = pin.as_bytes().to_vec();
        ck(
            unsafe { (self.funcs().C_InitPIN)(session, pin_bytes.as_mut_ptr(), pin_bytes.len() as CK_ULONG) },
            "C_InitPIN",
        )
    }

    /// Full multi-tenant token bring-up on `slot`, mirroring the exact
    /// sequence `softhsmrustv3::native::session::bootstrap_default_token`
    /// uses internally (and what the KMIP server's `provision_tenant`
    /// calls natively) — reproduced here purely through the standard C
    /// ABI. Returns a live, USER-logged-in session on `slot`.
    pub fn bootstrap_token(&self, slot: CK_SLOT_ID, so_pin: &str, user_pin: &str, label: &str) -> Result<CK_SESSION_HANDLE> {
        self.init_token(slot, so_pin, label)?;
        let so_session = self.open_session(slot)?;
        self.login_so(so_session, so_pin)?;
        self.init_pin(so_session, user_pin)?;
        // PKCS#11 §11.4 — C_CloseSession does not auto-logout; must
        // explicitly logout the SO before a USER login on the same slot,
        // else C_Login(USER) returns CKR_USER_ANOTHER_ALREADY_LOGGED_IN.
        self.logout(so_session)?;
        self.close_session(so_session)?;
        let user_session = self.open_session(slot)?;
        self.login_user(user_session, user_pin)?;
        Ok(user_session)
    }

    pub fn generate_key_pair(
        &self,
        session: CK_SESSION_HANDLE,
        mechanism: u32,
        pub_template: &mut [CK_ATTRIBUTE],
        priv_template: &mut [CK_ATTRIBUTE],
    ) -> Result<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)> {
        let mut mech = CK_MECHANISM {
            mechanism: mechanism as CK_ULONG,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        let mut pub_handle: CK_OBJECT_HANDLE = 0;
        let mut priv_handle: CK_OBJECT_HANDLE = 0;
        ck(
            unsafe {
                (self.funcs().C_GenerateKeyPair)(
                    session,
                    &mut mech,
                    pub_template.as_mut_ptr(),
                    pub_template.len() as CK_ULONG,
                    priv_template.as_mut_ptr(),
                    priv_template.len() as CK_ULONG,
                    &mut pub_handle,
                    &mut priv_handle,
                )
            },
            "C_GenerateKeyPair",
        )?;
        Ok((pub_handle, priv_handle))
    }

    pub fn sign_init(&self, session: CK_SESSION_HANDLE, mechanism: u32, key: CK_OBJECT_HANDLE) -> Result<()> {
        let mut mech = CK_MECHANISM {
            mechanism: mechanism as CK_ULONG,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        ck(unsafe { (self.funcs().C_SignInit)(session, &mut mech, key) }, "C_SignInit")
    }

    /// Two-call convention: query length, then fill.
    pub fn sign(&self, session: CK_SESSION_HANDLE, data: &[u8]) -> Result<Vec<u8>> {
        let mut data = data.to_vec();
        let mut sig_len: CK_ULONG = 0;
        ck(
            unsafe {
                (self.funcs().C_Sign)(session, data.as_mut_ptr(), data.len() as CK_ULONG, std::ptr::null_mut(), &mut sig_len)
            },
            "C_Sign(size)",
        )?;
        let mut sig = vec![0u8; sig_len as usize];
        ck(
            unsafe {
                (self.funcs().C_Sign)(session, data.as_mut_ptr(), data.len() as CK_ULONG, sig.as_mut_ptr(), &mut sig_len)
            },
            "C_Sign(fill)",
        )?;
        sig.truncate(sig_len as usize);
        Ok(sig)
    }

    pub fn verify_init(&self, session: CK_SESSION_HANDLE, mechanism: u32, key: CK_OBJECT_HANDLE) -> Result<()> {
        let mut mech = CK_MECHANISM {
            mechanism: mechanism as CK_ULONG,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        ck(unsafe { (self.funcs().C_VerifyInit)(session, &mut mech, key) }, "C_VerifyInit")
    }

    /// `Ok(true)` valid, `Ok(false)` genuinely invalid signature
    /// (`CKR_SIGNATURE_INVALID`/`CKR_SIGNATURE_LEN_RANGE`), `Err` for any
    /// other failure.
    pub fn verify(&self, session: CK_SESSION_HANDLE, data: &[u8], signature: &[u8]) -> Result<bool> {
        let mut data = data.to_vec();
        let mut sig = signature.to_vec();
        let rv = unsafe {
            (self.funcs().C_Verify)(
                session,
                data.as_mut_ptr(),
                data.len() as CK_ULONG,
                sig.as_mut_ptr(),
                sig.len() as CK_ULONG,
            )
        };
        const CKR_SIGNATURE_INVALID: CK_RV = 0xC0;
        const CKR_SIGNATURE_LEN_RANGE: CK_RV = 0xC1;
        match rv {
            CKR_OK_RV => Ok(true),
            CKR_SIGNATURE_INVALID | CKR_SIGNATURE_LEN_RANGE => Ok(false),
            other => bail!("C_Verify failed: rv=0x{other:x}"),
        }
    }
}

fn ck(rv: CK_RV, op: &str) -> Result<()> {
    if rv == CKR_OK_RV {
        Ok(())
    } else {
        bail!("{op} failed: rv=0x{rv:x}")
    }
}
