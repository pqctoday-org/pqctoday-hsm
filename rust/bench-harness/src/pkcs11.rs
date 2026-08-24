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
    CK_ATTRIBUTE, CK_ATTRIBUTE_TYPE, CK_FLAGS, CK_FUNCTION_LIST, CK_FUNCTION_LIST_3_2,
    CK_FUNCTION_LIST_PTR, CK_INTERFACE_PTR, CK_INTERFACE_PTR_PTR, CK_MECHANISM,
    CK_OBJECT_HANDLE, CK_RV, CK_SESSION_HANDLE, CK_SLOT_ID, CK_ULONG, CK_USER_TYPE,
    CK_VERSION, CK_VOID_PTR,
};
use softhsmrustv3::constants::{
    CKA_EC_PARAMS, CKA_MODULUS_BITS, CKA_PARAMETER_SET, CKF_RW_SESSION, CKF_SERIAL_SESSION, CKR_OK,
    CKU_SO, CKU_USER,
};

use crate::algos::KeygenParam;
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
    // (and the function pointers `functions`/`functions_3_2` point into)
    // stays mapped.
    _library: libloading::Library,
    functions: *const CK_FUNCTION_LIST,
    /// The v3.2 interface (§5.3/§5.5 `C_GetInterface`), needed for
    /// functions added after v2.40 — `C_EncapsulateKey`/`C_DecapsulateKey`
    /// here. `C_GetFunctionList` is frozen at v2.40 for ABI back-compat
    /// (confirmed against `rust/src/ck_abi.rs`'s own doc comments); a
    /// v3.2-aware client resolves the newer functions through the
    /// interface mechanism instead, exactly as done here.
    ///
    /// `None` when the loaded module has no `C_GetInterface` export at all,
    /// or answers `C_GetInterface("PKCS 11", {3,2})` with anything but
    /// success — sandbox-bench-transport-arms-plan-08242026.md WP4c: a
    /// p11-kit-remoted module is exactly this case (p11-kit's RPC protocol
    /// carries PKCS#11 3.0 calls but has no ENCAPSULATE/DECAPSULATE call
    /// IDs at all, verified against its master source 2026-08-24). Every
    /// v2.40-only function keeps working through `funcs()`; only the two
    /// KEM entry points become unavailable, reported as a clear error
    /// rather than a `load()`-time hard failure or a null-pointer crash.
    functions_3_2: Option<*const CK_FUNCTION_LIST_3_2>,
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

        // §5.3/§5.5 — resolve the v3.2 interface via C_GetInterface, the
        // standard way to reach functions added after v2.40. Interface
        // name is the literal "PKCS 11" (with a space) per the spec;
        // requesting version {3,2} explicitly avoids relying on the
        // library's default-interface ordering.
        //
        // OPTIONAL (WP4c, 2026-08-24): a module with no `C_GetInterface`
        // export at all (stock p11-kit-client.so exports only the frozen
        // v2.40 table) or one that answers with anything but success is
        // NOT a load failure — it just means the two v3.2-only functions
        // this harness needs for the KEM cells are unavailable through
        // this particular module. Every v2.40 function still works. See
        // `functions_3_2`'s doc comment.
        type GetInterfaceFn = unsafe extern "C" fn(
            *mut u8,
            *mut CK_VERSION,
            CK_INTERFACE_PTR_PTR,
            CK_FLAGS,
        ) -> CK_RV;
        let functions_3_2 = match unsafe { library.get::<GetInterfaceFn>(b"C_GetInterface\0") } {
            Err(_) => None,
            Ok(get_interface) => {
                let mut interface_name: [u8; 8] = *b"PKCS 11\0";
                let mut version_3_2 = CK_VERSION { major: 3, minor: 2 };
                let mut interface_ptr: CK_INTERFACE_PTR = std::ptr::null_mut();
                // SAFETY: `interface_name`/`version_3_2` are valid buffers
                // for the duration of this call; `interface_ptr` is a
                // valid non-null out-pointer per §5.5.
                let rv = unsafe {
                    get_interface(interface_name.as_mut_ptr(), &mut version_3_2, &mut interface_ptr, 0)
                };
                if rv != CKR_OK_RV || interface_ptr.is_null() {
                    None
                } else {
                    // SAFETY: a successful C_GetInterface returns a
                    // CK_INTERFACE whose pFunctionList, per the {3,2}
                    // version we requested, points to a
                    // CK_FUNCTION_LIST_3_2 — the engine's own
                    // C_GetInterface dispatch (rust/src/ck_abi.rs) only
                    // ever populates it that way for a 3.2 match.
                    Some(unsafe { (*interface_ptr).pFunctionList as *const CK_FUNCTION_LIST_3_2 })
                }
            }
        };

        Ok(Self { _library: library, functions: list_ptr, functions_3_2 })
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

    /// The v3.2-only function segment (`C_EncapsulateKey`/`C_DecapsulateKey`),
    /// resolved via `C_GetInterface` in `load()`. `None` when the loaded
    /// module exposes no v3.2 interface — see `functions_3_2`'s doc.
    fn funcs_32(&self) -> Option<&softhsmrustv3::ck_abi::FnListV32Ext> {
        self.functions_3_2.map(|p| unsafe { &(*p).f32 })
    }

    /// True when this module can drive `C_EncapsulateKey`/`C_DecapsulateKey`
    /// at all — the KEM cells are skipped with a clear reason, not run and
    /// left to crash, when this is false.
    pub fn supports_kem(&self) -> bool {
        self.functions_3_2.is_some()
    }

    pub fn initialize(&self) -> Result<()> {
        // SAFETY: PKCS#11 §5.6 — a null pInitArgs is always valid.
        ck(unsafe { (self.funcs().C_Initialize)(std::ptr::null_mut()) }, "C_Initialize")
    }

    pub fn finalize(&self) -> Result<()> {
        // SAFETY: PKCS#11 §5.6 — pReserved must be null; we pass null.
        ck(unsafe { (self.funcs().C_Finalize)(std::ptr::null_mut()) }, "C_Finalize")
    }

    /// §5.4 `C_GetInfo` — `libraryVersion` as `"major.minor"`. Stamped on
    /// every JSONL result row (plan §A7 honesty item: "engine version...
    /// stamped on every result set") so before/after engine-side changes
    /// (e.g. the F2–F5 lock-collapse gate) are distinguishable in the data,
    /// not just asserted in a commit message.
    pub fn library_version(&self) -> Result<String> {
        let mut info: softhsmrustv3::ck_abi::CK_INFO = unsafe { std::mem::zeroed() };
        ck(unsafe { (self.funcs().C_GetInfo)(&mut info) }, "C_GetInfo")?;
        Ok(format!("{}.{}", info.libraryVersion.major, info.libraryVersion.minor))
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

    /// §5.7.5 two-call convention. `CKR_ATTRIBUTE_TYPE_INVALID` (attribute
    /// absent on this object — not this crate's harness-only convention,
    /// the engine's own real return code, see `ffi.rs::C_GetAttributeValue`)
    /// is surfaced as a normal `Err`, same as any other non-OK `rv`.
    pub fn get_attribute_value(&self, session: CK_SESSION_HANDLE, object: CK_OBJECT_HANDLE, attr_type: u32) -> Result<Vec<u8>> {
        let mut attr = CK_ATTRIBUTE { attrType: attr_type as CK_ATTRIBUTE_TYPE, pValue: std::ptr::null_mut(), ulValueLen: 0 };
        ck(
            unsafe { (self.funcs().C_GetAttributeValue)(session, object, &mut attr, 1) },
            "C_GetAttributeValue(size)",
        )?;
        let mut buf = vec![0u8; attr.ulValueLen as usize];
        attr.pValue = buf.as_mut_ptr() as CK_VOID_PTR;
        ck(
            unsafe { (self.funcs().C_GetAttributeValue)(session, object, &mut attr, 1) },
            "C_GetAttributeValue(fill)",
        )?;
        buf.truncate(attr.ulValueLen as usize);
        Ok(buf)
    }

    /// §5.18.5 `C_DeriveKey` with `CKM_ECDH1_DERIVE` (§6.7 — also the
    /// mechanism for X25519/X448 Montgomery-curve agreement, dispatched by
    /// the engine from the base key's own stored algorithm family; see
    /// `algos::KeyAgreementAlgo`'s doc comment). Builds the standard
    /// `CK_ECDH1_DERIVE_PARAMS` internally — nothing outside this module
    /// needs to know that struct's raw layout, same discipline as `funcs()`
    /// keeping the function table private. `kdf = CKD_NULL` (§6.7 — no
    /// post-processing; the raw shared value becomes the key), no shared
    /// data, `peer_public_point` is the peer's `CKA_EC_POINT` value
    /// (DER-OCTET-STRING-wrapped — the engine strips the wrapper itself,
    /// confirmed against `ffi.rs`'s `C_DeriveKey` ECDH branch).
    pub fn ecdh1_derive(
        &self,
        session: CK_SESSION_HANDLE,
        base_key: CK_OBJECT_HANDLE,
        peer_public_point: &mut [u8],
    ) -> Result<CK_OBJECT_HANDLE> {
        const CKD_NULL: CK_ULONG = 1; // PKCS#11 v3.2 §6.7 Table 26 — no KDF.
        #[repr(C)]
        struct CkEcdh1DeriveParams {
            kdf: CK_ULONG,
            ul_shared_data_len: CK_ULONG,
            p_shared_data: CK_VOID_PTR,
            ul_public_data_len: CK_ULONG,
            p_public_data: CK_VOID_PTR,
        }
        let mut params = CkEcdh1DeriveParams {
            kdf: CKD_NULL,
            ul_shared_data_len: 0,
            p_shared_data: std::ptr::null_mut(),
            ul_public_data_len: peer_public_point.len() as CK_ULONG,
            p_public_data: peer_public_point.as_mut_ptr() as CK_VOID_PTR,
        };
        let mut mech = CK_MECHANISM {
            mechanism: softhsmrustv3::constants::CKM_ECDH1_DERIVE as CK_ULONG,
            pParameter: &mut params as *mut CkEcdh1DeriveParams as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CkEcdh1DeriveParams>() as CK_ULONG,
        };
        let mut derived: CK_OBJECT_HANDLE = 0;
        ck(
            unsafe {
                (self.funcs().C_DeriveKey)(session, &mut mech, base_key, std::ptr::null_mut(), 0, &mut derived)
            },
            "C_DeriveKey(ECDH1)",
        )?;
        Ok(derived)
    }

    /// §5.18.8 `C_EncapsulateKey`. `public_key` must carry `CKA_ENCAPSULATE`
    /// (engine-set by default on ML-KEM public keys). Two-call convention
    /// for the ciphertext buffer, same pattern as `sign`.
    pub fn encapsulate_key(
        &self,
        session: CK_SESSION_HANDLE,
        mechanism: u32,
        public_key: CK_OBJECT_HANDLE,
        template: &mut [CK_ATTRIBUTE],
    ) -> Result<(Vec<u8>, CK_OBJECT_HANDLE)> {
        let funcs_32 = self.funcs_32().ok_or_else(|| {
            anyhow::anyhow!(
                "unsupported-by-transport: this module exposes no PKCS#11 v3.2 interface \
                 (C_GetInterface unavailable or refused) — C_EncapsulateKey cannot be driven"
            )
        })?;
        let mut mech = CK_MECHANISM { mechanism: mechanism as CK_ULONG, pParameter: std::ptr::null_mut(), ulParameterLen: 0 };
        let mut ct_len: CK_ULONG = 0;
        let mut ss_handle: CK_OBJECT_HANDLE = 0;
        ck(
            unsafe {
                (funcs_32.C_EncapsulateKey)(
                    session, &mut mech, public_key,
                    template.as_mut_ptr(), template.len() as CK_ULONG,
                    std::ptr::null_mut(), &mut ct_len, &mut ss_handle,
                )
            },
            "C_EncapsulateKey(size)",
        )?;
        let mut ciphertext = vec![0u8; ct_len as usize];
        ck(
            unsafe {
                (funcs_32.C_EncapsulateKey)(
                    session, &mut mech, public_key,
                    template.as_mut_ptr(), template.len() as CK_ULONG,
                    ciphertext.as_mut_ptr(), &mut ct_len, &mut ss_handle,
                )
            },
            "C_EncapsulateKey(fill)",
        )?;
        ciphertext.truncate(ct_len as usize);
        Ok((ciphertext, ss_handle))
    }

    /// §5.18.9 `C_DecapsulateKey`. `private_key` must carry `CKA_DECAPSULATE`
    /// (engine-set by default on ML-KEM private keys).
    pub fn decapsulate_key(
        &self,
        session: CK_SESSION_HANDLE,
        mechanism: u32,
        private_key: CK_OBJECT_HANDLE,
        ciphertext: &[u8],
        template: &mut [CK_ATTRIBUTE],
    ) -> Result<CK_OBJECT_HANDLE> {
        let funcs_32 = self.funcs_32().ok_or_else(|| {
            anyhow::anyhow!(
                "unsupported-by-transport: this module exposes no PKCS#11 v3.2 interface \
                 (C_GetInterface unavailable or refused) — C_DecapsulateKey cannot be driven"
            )
        })?;
        let mut mech = CK_MECHANISM { mechanism: mechanism as CK_ULONG, pParameter: std::ptr::null_mut(), ulParameterLen: 0 };
        let mut ciphertext = ciphertext.to_vec();
        let mut ss_handle: CK_OBJECT_HANDLE = 0;
        ck(
            unsafe {
                (funcs_32.C_DecapsulateKey)(
                    session, &mut mech, private_key,
                    template.as_mut_ptr(), template.len() as CK_ULONG,
                    ciphertext.as_mut_ptr(), ciphertext.len() as CK_ULONG, &mut ss_handle,
                )
            },
            "C_DecapsulateKey",
        )?;
        Ok(ss_handle)
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

    /// `generate_key_pair`, but builds the public-key template from an
    /// `algos::KeygenParam` — the one place that knows how to encode each
    /// kind of required attribute (raw `CKA_EC_PARAMS` OID bytes at their
    /// real declared length, vs. `CKA_PARAMETER_SET` as a bare 4-byte
    /// `u32` regardless of this platform's 8-byte native `CK_ULONG` —
    /// see `crypto/handlers.rs::get_attr_ulong`, which reads exactly 4
    /// bytes at `pValue` no matter what `ulValueLen` says). Keeping this
    /// encoding logic here, not in `algos.rs`, matches the module's own
    /// rule: nothing outside `pkcs11.rs` builds a `CK_ATTRIBUTE` by hand.
    pub fn generate_key_pair_with_param(
        &self,
        session: CK_SESSION_HANDLE,
        mechanism: u32,
        param: KeygenParam,
    ) -> Result<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)> {
        match param {
            KeygenParam::None => self.generate_key_pair(session, mechanism, &mut [], &mut []),
            KeygenParam::EcParamsOid(oid) => {
                let mut oid = oid.to_vec();
                let mut pub_template = [CK_ATTRIBUTE {
                    attrType: CKA_EC_PARAMS as CK_ATTRIBUTE_TYPE,
                    pValue: oid.as_mut_ptr() as CK_VOID_PTR,
                    ulValueLen: oid.len() as CK_ULONG,
                }];
                self.generate_key_pair(session, mechanism, &mut pub_template, &mut [])
            }
            KeygenParam::ParameterSet(value) => {
                let mut value = value;
                let mut pub_template = [CK_ATTRIBUTE {
                    attrType: CKA_PARAMETER_SET as CK_ATTRIBUTE_TYPE,
                    pValue: &mut value as *mut u32 as CK_VOID_PTR,
                    ulValueLen: std::mem::size_of::<u32>() as CK_ULONG,
                }];
                self.generate_key_pair(session, mechanism, &mut pub_template, &mut [])
            }
            KeygenParam::RsaModulusBits(bits) => {
                // Same plain-4-byte-u32 convention as ParameterSet above —
                // confirmed against ffi.rs's CKM_RSA_PKCS_KEY_PAIR_GEN
                // dispatch (get_attr_ulong), not native CK_ULONG width.
                // No CKA_PUBLIC_EXPONENT: the engine generates and stores
                // that itself, not caller-supplied.
                let mut bits = bits;
                let mut pub_template = [CK_ATTRIBUTE {
                    attrType: CKA_MODULUS_BITS as CK_ATTRIBUTE_TYPE,
                    pValue: &mut bits as *mut u32 as CK_VOID_PTR,
                    ulValueLen: std::mem::size_of::<u32>() as CK_ULONG,
                }];
                self.generate_key_pair(session, mechanism, &mut pub_template, &mut [])
            }
        }
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

    /// Builds a real `CK_RSA_PKCS_OAEP_PARAMS` (§6.4.4) at native width —
    /// `#[repr(C)]` struct of `CK_ULONG`/`CK_VOID_PTR` fields, same pattern
    /// as `ecdh1_derive`'s own params struct above. `mechanism` comes from
    /// the caller (`algo.encrypt_mechanism`, matching how `sign_init`
    /// takes `algo.sign_mechanism` rather than hardcoding it here) — one
    /// fixed, standard OAEP configuration regardless of which RSA-OAEP
    /// mechanism is passed: SHA-256 / MGF1-SHA256 / CKZ_DATA_SPECIFIED
    /// with an empty label, no per-algorithm parameterization needed.
    fn oaep_mechanism(mechanism: u32) -> (CK_MECHANISM, Box<CkRsaPkcsOaepParams>) {
        use softhsmrustv3::constants::{CKG_MGF1_SHA256, CKM_SHA256, CKZ_DATA_SPECIFIED};
        let mut params = Box::new(CkRsaPkcsOaepParams {
            hash_alg: CKM_SHA256 as CK_ULONG,
            mgf: CKG_MGF1_SHA256 as CK_ULONG,
            source: CKZ_DATA_SPECIFIED as CK_ULONG,
            p_source_data: std::ptr::null_mut(),
            ul_source_data_len: 0,
        });
        let mech = CK_MECHANISM {
            mechanism: mechanism as CK_ULONG,
            pParameter: params.as_mut() as *mut CkRsaPkcsOaepParams as CK_VOID_PTR,
            ulParameterLen: std::mem::size_of::<CkRsaPkcsOaepParams>() as CK_ULONG,
        };
        (mech, params)
    }

    pub fn encrypt_init(&self, session: CK_SESSION_HANDLE, mechanism: u32, key: CK_OBJECT_HANDLE) -> Result<()> {
        let (mut mech, _params) = Self::oaep_mechanism(mechanism);
        ck(unsafe { (self.funcs().C_EncryptInit)(session, &mut mech, key) }, "C_EncryptInit")
    }

    /// Two-call convention, same as `sign`.
    pub fn encrypt(&self, session: CK_SESSION_HANDLE, data: &[u8]) -> Result<Vec<u8>> {
        let mut data = data.to_vec();
        let mut out_len: CK_ULONG = 0;
        ck(
            unsafe {
                (self.funcs().C_Encrypt)(session, data.as_mut_ptr(), data.len() as CK_ULONG, std::ptr::null_mut(), &mut out_len)
            },
            "C_Encrypt(size)",
        )?;
        let mut out = vec![0u8; out_len as usize];
        ck(
            unsafe {
                (self.funcs().C_Encrypt)(session, data.as_mut_ptr(), data.len() as CK_ULONG, out.as_mut_ptr(), &mut out_len)
            },
            "C_Encrypt(fill)",
        )?;
        out.truncate(out_len as usize);
        Ok(out)
    }

    pub fn decrypt_init(&self, session: CK_SESSION_HANDLE, mechanism: u32, key: CK_OBJECT_HANDLE) -> Result<()> {
        let (mut mech, _params) = Self::oaep_mechanism(mechanism);
        ck(unsafe { (self.funcs().C_DecryptInit)(session, &mut mech, key) }, "C_DecryptInit")
    }

    /// Two-call convention, same as `sign`.
    pub fn decrypt(&self, session: CK_SESSION_HANDLE, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut ct = ciphertext.to_vec();
        let mut out_len: CK_ULONG = 0;
        ck(
            unsafe {
                (self.funcs().C_Decrypt)(session, ct.as_mut_ptr(), ct.len() as CK_ULONG, std::ptr::null_mut(), &mut out_len)
            },
            "C_Decrypt(size)",
        )?;
        let mut out = vec![0u8; out_len as usize];
        ck(
            unsafe {
                (self.funcs().C_Decrypt)(session, ct.as_mut_ptr(), ct.len() as CK_ULONG, out.as_mut_ptr(), &mut out_len)
            },
            "C_Decrypt(fill)",
        )?;
        out.truncate(out_len as usize);
        Ok(out)
    }
}

/// `CK_RSA_PKCS_OAEP_PARAMS` (§6.4.4) — `CK_ULONG`/`CK_VOID_PTR` fields are
/// native width on this platform (matching the fixed `parse_oaep_params`
/// on the engine side, see hsm-perf-bench FIPS-gap plan Part B2).
#[repr(C)]
struct CkRsaPkcsOaepParams {
    hash_alg: CK_ULONG,
    mgf: CK_ULONG,
    source: CK_ULONG,
    p_source_data: CK_VOID_PTR,
    ul_source_data_len: CK_ULONG,
}

fn ck(rv: CK_RV, op: &str) -> Result<()> {
    if rv == CKR_OK_RV {
        Ok(())
    } else {
        bail!("{op} failed: rv=0x{rv:x}")
    }
}
