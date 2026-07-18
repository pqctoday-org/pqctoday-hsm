//! `ck_abi` — native (non-wasm32) pkcs11.h-conformant C ABI exports.
//!
//! ## Why this module exists (round-2 T8, audit H-1 residual)
//!
//! The `ffi` module is the engine's wasm32 ABI: every `C_*` takes `u32`
//! handles/lengths and `*mut u8` blobs laid out with 4-byte `CK_ULONG`s and
//! 4-byte linear-memory "pointers". That is exactly right for wasm32 (the JS
//! shim is the function table — C function pointers cannot cross
//! wasm-bindgen), but it is NOT the pkcs11.h ABI on a 64-bit native host,
//! where `CK_ULONG` is `unsigned long` (8 bytes on LP64) and pointers are 8
//! bytes. A native consumer that `dlsym`s `C_GetFunctionList` must receive
//! function pointers with the REAL pkcs11.h signatures.
//!
//! This module provides that: `repr(C)` `CK_FUNCTION_LIST`,
//! `CK_FUNCTION_LIST_3_0` and `CK_FUNCTION_LIST_3_2` structs whose fields
//! follow pkcs11f.h in exact order (68 / 92 / 104 entries — asserted by
//! tests), populated with thin adapter shims that translate
//! `CK_ULONG`/handle widths to the internal u32 ABI with CHECKED narrowing
//! (Option B of the T8 design: the internal ABI is u32 everywhere, so a
//! direct export of the internal symbols would lie to a 64-bit caller).
//!
//! ## Translation rules
//!
//! * Scalars (`CK_ULONG`, handles, flags): checked narrowing. Overflow →
//!   `CKR_SESSION_HANDLE_INVALID` / `CKR_OBJECT_HANDLE_INVALID` /
//!   `CKR_SLOT_ID_INVALID` / `CKR_MECHANISM_INVALID` / `CKR_ARGUMENTS_BAD`
//!   as appropriate (never silent truncation).
//! * Top-level byte buffers (`CK_BYTE_PTR` + length): passed through —
//!   they are direct function arguments, so the full 64-bit pointer
//!   survives.
//! * `CK_ULONG_PTR` out-params (two-call convention): adapted through a u32
//!   scratch; the result is widened back, mapping the 32-bit
//!   `CK_UNAVAILABLE_INFORMATION` sentinel (`0xFFFF_FFFF`) to the native
//!   `~0UL`.
//! * Info structs (`CK_INFO`, `CK_SLOT_INFO`, `CK_TOKEN_INFO`,
//!   `CK_SESSION_INFO`, `CK_MECHANISM_INFO`): the engine writes its packed
//!   wasm32 layout into a scratch blob; the shim re-expands it field by
//!   field into the caller's native `repr(C)` struct.
//! * `CK_MECHANISM` / `CK_ATTRIBUTE` templates: the top-level struct is
//!   re-packed into the engine's 12-byte wasm shape. **Embedded pointers**
//!   (`pParameter` / `pValue`) are the documented residual limit: the
//!   engine dereferences them as 32-bit linear-memory addresses, so on a
//!   64-bit host they cannot be represented at all (macOS reserves the low
//!   4 GiB as `__PAGEZERO`; there is no u32-addressable memory). A non-NULL
//!   embedded pointer on a 64-bit target therefore returns
//!   `CKR_FUNCTION_FAILED` instead of risking UB. NULL `pValue` size-query
//!   templates and parameterless mechanisms translate exactly. On a 32-bit
//!   native target the layouts coincide and everything passes through with
//!   full fidelity.
//!
//! wasm32 builds compile none of this (`lib.rs` gates the module) and keep
//! the documented JS-shim function table.

#![allow(non_camel_case_types)]
#![allow(clippy::missing_safety_doc)]

use crate::constants::*;
use std::os::raw::{c_ulong, c_void};

// ─────────────────────────────────────────────────────────────────────────
// pkcs11t.h types (native widths)
// ─────────────────────────────────────────────────────────────────────────

pub type CK_BYTE = u8;
pub type CK_BBOOL = u8;
/// `unsigned long` — 8 bytes on LP64 (macOS/Linux 64-bit), 4 bytes on
/// 32-bit targets and LLP64 Windows; matches pkcs11.h `CK_ULONG` exactly.
pub type CK_ULONG = c_ulong;
pub type CK_RV = CK_ULONG;
pub type CK_FLAGS = CK_ULONG;
pub type CK_SLOT_ID = CK_ULONG;
pub type CK_SESSION_HANDLE = CK_ULONG;
pub type CK_OBJECT_HANDLE = CK_ULONG;
pub type CK_USER_TYPE = CK_ULONG;
pub type CK_MECHANISM_TYPE = CK_ULONG;
pub type CK_ATTRIBUTE_TYPE = CK_ULONG;
pub type CK_NOTIFICATION = CK_ULONG;
pub type CK_SESSION_VALIDATION_FLAGS_TYPE = CK_ULONG;

pub type CK_BYTE_PTR = *mut u8;
pub type CK_UTF8CHAR_PTR = *mut u8;
pub type CK_VOID_PTR = *mut c_void;
pub type CK_ULONG_PTR = *mut CK_ULONG;
pub type CK_FLAGS_PTR = *mut CK_FLAGS;
pub type CK_SLOT_ID_PTR = *mut CK_SLOT_ID;
pub type CK_SESSION_HANDLE_PTR = *mut CK_SESSION_HANDLE;
pub type CK_OBJECT_HANDLE_PTR = *mut CK_OBJECT_HANDLE;
pub type CK_MECHANISM_TYPE_PTR = *mut CK_MECHANISM_TYPE;
/// `CK_ASYNC_DATA` is never dereferenced by the engine stubs — opaque.
pub type CK_ASYNC_DATA_PTR = *mut c_void;

pub type CK_NOTIFY =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_NOTIFICATION, CK_VOID_PTR) -> CK_RV>;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CK_VERSION {
    pub major: CK_BYTE,
    pub minor: CK_BYTE,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CK_INFO {
    pub cryptokiVersion: CK_VERSION,
    pub manufacturerID: [u8; 32],
    pub flags: CK_FLAGS,
    pub libraryDescription: [u8; 32],
    pub libraryVersion: CK_VERSION,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CK_SLOT_INFO {
    pub slotDescription: [u8; 64],
    pub manufacturerID: [u8; 32],
    pub flags: CK_FLAGS,
    pub hardwareVersion: CK_VERSION,
    pub firmwareVersion: CK_VERSION,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CK_TOKEN_INFO {
    pub label: [u8; 32],
    pub manufacturerID: [u8; 32],
    pub model: [u8; 16],
    pub serialNumber: [u8; 16],
    pub flags: CK_FLAGS,
    pub ulMaxSessionCount: CK_ULONG,
    pub ulSessionCount: CK_ULONG,
    pub ulMaxRwSessionCount: CK_ULONG,
    pub ulRwSessionCount: CK_ULONG,
    pub ulMaxPinLen: CK_ULONG,
    pub ulMinPinLen: CK_ULONG,
    pub ulTotalPublicMemory: CK_ULONG,
    pub ulFreePublicMemory: CK_ULONG,
    pub ulTotalPrivateMemory: CK_ULONG,
    pub ulFreePrivateMemory: CK_ULONG,
    pub hardwareVersion: CK_VERSION,
    pub firmwareVersion: CK_VERSION,
    pub utcTime: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CK_SESSION_INFO {
    pub slotID: CK_SLOT_ID,
    pub state: CK_ULONG,
    pub flags: CK_FLAGS,
    pub ulDeviceError: CK_ULONG,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CK_MECHANISM_INFO {
    pub ulMinKeySize: CK_ULONG,
    pub ulMaxKeySize: CK_ULONG,
    pub flags: CK_FLAGS,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CK_MECHANISM {
    pub mechanism: CK_MECHANISM_TYPE,
    pub pParameter: CK_VOID_PTR,
    pub ulParameterLen: CK_ULONG,
}
pub type CK_MECHANISM_PTR = *mut CK_MECHANISM;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CK_ATTRIBUTE {
    pub attrType: CK_ATTRIBUTE_TYPE, // `type` in pkcs11t.h (Rust keyword)
    pub pValue: CK_VOID_PTR,
    pub ulValueLen: CK_ULONG,
}
pub type CK_ATTRIBUTE_PTR = *mut CK_ATTRIBUTE;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CK_INTERFACE {
    pub pInterfaceName: CK_UTF8CHAR_PTR,
    pub pFunctionList: CK_VOID_PTR,
    pub flags: CK_FLAGS,
}
pub type CK_INTERFACE_PTR = *mut CK_INTERFACE;
pub type CK_INTERFACE_PTR_PTR = *mut CK_INTERFACE_PTR;

/// Native `CK_UNAVAILABLE_INFORMATION` is `(~0UL)` (PKCS#11 v3.2 §4.2);
/// the engine's wasm ABI uses the 32-bit sentinel `0xFFFF_FFFF`.
pub const CK_UNAVAILABLE_INFORMATION_NATIVE: CK_ULONG = CK_ULONG::MAX;

// ─────────────────────────────────────────────────────────────────────────
// Translation helpers
// ─────────────────────────────────────────────────────────────────────────

#[inline]
fn rv(code: u32) -> CK_RV {
    code as CK_RV
}

#[inline]
fn narrow(v: CK_ULONG) -> Option<u32> {
    u32::try_from(v).ok()
}

/// Widen a 32-bit engine length/ULONG, mapping the 32-bit
/// `CK_UNAVAILABLE_INFORMATION` sentinel to the native `~0UL`.
#[inline]
fn widen(v: u32) -> CK_ULONG {
    if v == 0xFFFF_FFFF {
        CK_UNAVAILABLE_INFORMATION_NATIVE
    } else {
        v as CK_ULONG
    }
}

macro_rules! narrow_or {
    ($v:expr, $err:expr) => {
        match narrow($v) {
            Some(x) => x,
            None => return rv($err),
        }
    };
}

/// Two-call-convention length out-param: clamp the caller's `CK_ULONG`
/// into a u32 scratch, run the engine call, write the (widened) result
/// back only if the engine changed it (so a caller's >4 GiB capacity is
/// never clobbered by the clamped value on an untouched error path).
unsafe fn with_len_out(p: CK_ULONG_PTR, f: impl FnOnce(*mut u32) -> u32) -> CK_RV {
    if p.is_null() {
        // §5.2 — a NULL length pointer is always invalid; do not let the
        // engine (which does not null-check every path) dereference it.
        return rv(CKR_ARGUMENTS_BAD);
    }
    let initial: u32 = if *p > u32::MAX as CK_ULONG {
        u32::MAX
    } else {
        *p as u32
    };
    let mut tmp = initial;
    let code = f(&mut tmp);
    if tmp != initial {
        *p = widen(tmp);
    }
    rv(code)
}

/// Out-param for a single handle (session/object): u32 scratch, widened
/// back on CKR_OK.
unsafe fn with_handle_out(p: *mut CK_ULONG, f: impl FnOnce(*mut u32) -> u32) -> CK_RV {
    if p.is_null() {
        // Engine paths return CKR_ARGUMENTS_BAD for NULL out-handles; some
        // take it as `*mut u32` they immediately deref — refuse up front.
        return rv(CKR_ARGUMENTS_BAD);
    }
    let mut h: u32 = 0;
    let code = f(&mut h);
    if code == CKR_OK {
        *p = h as CK_ULONG;
    }
    rv(code)
}

/// Largest scratch array used for `CK_ULONG`-array two-call translation
/// (slots, mechanisms, found objects). Spec-legal: C_FindObjects may
/// return fewer handles than `ulMaxObjectCount`.
const MAX_ARRAY_SCRATCH: usize = 65536;

/// Two-call convention over a caller `CK_ULONG` array + count: the engine
/// works on a u32 scratch array, results are widened back.
unsafe fn ulong_array_two_call(
    p_arr: *mut CK_ULONG,
    pul_count: CK_ULONG_PTR,
    call: impl Fn(*mut u32, *mut u32) -> u32,
) -> CK_RV {
    if pul_count.is_null() {
        return rv(call(std::ptr::null_mut(), std::ptr::null_mut()));
    }
    if p_arr.is_null() {
        let mut c: u32 = 0;
        let code = call(std::ptr::null_mut(), &mut c);
        if code == CKR_OK {
            *pul_count = c as CK_ULONG;
        }
        return rv(code);
    }
    let cap = (*pul_count).min(MAX_ARRAY_SCRATCH as CK_ULONG) as u32;
    let mut scratch = vec![0u32; cap as usize];
    let mut c: u32 = cap;
    let code = call(scratch.as_mut_ptr(), &mut c);
    if code == CKR_OK {
        for (i, v) in scratch.iter().take((c as usize).min(cap as usize)).enumerate() {
            *p_arr.add(i) = widen(*v);
        }
    }
    if code == CKR_OK || code == CKR_BUFFER_TOO_SMALL {
        *pul_count = c as CK_ULONG;
    }
    rv(code)
}

/// Represent an EMBEDDED pointer (CK_MECHANISM.pParameter /
/// CK_ATTRIBUTE.pValue) in the engine's 32-bit linear-memory ABI.
///
/// On 32-bit native targets the layouts coincide and the address always
/// fits. On 64-bit targets there is no u32-addressable memory (macOS keeps
/// the low 4 GiB as `__PAGEZERO`), and even a low-mapped buffer would be
/// misparsed (native struct layouts differ) — so a non-NULL embedded
/// pointer is refused with `CKR_FUNCTION_FAILED` (documented H-1
/// residual) rather than risking UB.
/// Native-pointer-width embed of a caller pointer (usize == u32 on wasm32,
/// u64 on native) — carries the full pointer instead of truncating it.
#[inline]
fn embed_ptr(p: *mut c_void) -> usize {
    p as usize
}

/// Re-pack a native CK_MECHANISM into `[type, pParameter, ulParameterLen]`
/// at native pointer width (3 × usize).
unsafe fn xlate_mech(p: CK_MECHANISM_PTR) -> Result<Option<[usize; 3]>, CK_RV> {
    if p.is_null() {
        return Ok(None); // engine produces its own CKR_ARGUMENTS_BAD
    }
    let m = &*p;
    let t = narrow(m.mechanism).ok_or(rv(CKR_MECHANISM_INVALID))?;
    let pv = embed_ptr(m.pParameter);
    let ln = if m.pParameter.is_null() {
        0usize
    } else {
        narrow(m.ulParameterLen).ok_or(rv(CKR_ARGUMENTS_BAD))? as usize
    };
    Ok(Some([t as usize, pv, ln]))
}

#[inline]
fn mech_ptr(m: &mut Option<[usize; 3]>) -> *mut u8 {
    match m {
        Some(b) => b.as_mut_ptr() as *mut u8,
        None => std::ptr::null_mut(),
    }
}

/// Re-pack a native CK_ATTRIBUTE template into the engine's 12-byte-entry
/// wasm shape. Returns the scratch template and the narrowed count.
unsafe fn xlate_template(
    p: CK_ATTRIBUTE_PTR,
    count: CK_ULONG,
) -> Result<(Option<Vec<usize>>, u32), CK_RV> {
    let n = narrow(count).ok_or(rv(CKR_ARGUMENTS_BAD))?;
    if p.is_null() {
        return Ok((None, n));
    }
    // Native-pointer-width triples [type, pValue, ulValueLen]. usize == u32 on
    // wasm32 (byte-identical to the old layout) and u64 on native, so this
    // carries the full pValue instead of truncating it (the embed_ptr/H-1 fix).
    let mut v: Vec<usize> = Vec::with_capacity(n as usize * 3);
    for i in 0..n as usize {
        let a = &*p.add(i);
        let t = narrow(a.attrType).ok_or(rv(CKR_ATTRIBUTE_TYPE_INVALID))?;
        let pv = a.pValue as usize;
        // ulValueLen may be the native CK_UNAVAILABLE_INFORMATION sentinel
        // (a caller re-using an output template) — carry it at native width.
        let ln = if a.ulValueLen == CK_UNAVAILABLE_INFORMATION_NATIVE {
            usize::MAX
        } else {
            narrow(a.ulValueLen).ok_or(rv(CKR_ARGUMENTS_BAD))? as usize
        };
        v.extend_from_slice(&[t as usize, pv, ln]);
    }
    Ok((Some(v), n))
}

#[inline]
fn tmpl_ptr(t: &mut Option<Vec<usize>>) -> *mut u8 {
    match t {
        Some(v) => v.as_mut_ptr() as *mut u8,
        None => std::ptr::null_mut(),
    }
}

macro_rules! xlate_mech_or {
    ($p:expr) => {
        match xlate_mech($p) {
            Ok(m) => m,
            Err(e) => return e,
        }
    };
}

macro_rules! xlate_tmpl_or {
    ($p:expr, $c:expr) => {
        match xlate_template($p, $c) {
            Ok(t) => t,
            Err(e) => return e,
        }
    };
}

// ─────────────────────────────────────────────────────────────────────────
// Shim shape macros (the repetitive groups)
// ─────────────────────────────────────────────────────────────────────────

/// (hSession) -> CK_RV
macro_rules! shim_session_only {
    ($($name:ident),+ $(,)?) => {$(
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(hSession: CK_SESSION_HANDLE) -> CK_RV {
            let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
            rv(crate::ffi::$name(h))
        }
    )+};
}

/// (hSession, CK_BYTE_PTR, CK_ULONG) -> CK_RV — buffer passes through.
macro_rules! shim_sess_buf {
    ($($name:ident),+ $(,)?) => {$(
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(
            hSession: CK_SESSION_HANDLE,
            pData: CK_BYTE_PTR,
            ulLen: CK_ULONG,
        ) -> CK_RV {
            let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
            let l = narrow_or!(ulLen, CKR_ARGUMENTS_BAD);
            rv(crate::ffi::$name(h, pData, l))
        }
    )+};
}

/// (hSession, in_ptr, in_len, out_ptr, out_len_ptr) -> CK_RV
macro_rules! shim_sess_in_outlen {
    ($($name:ident),+ $(,)?) => {$(
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(
            hSession: CK_SESSION_HANDLE,
            pIn: CK_BYTE_PTR,
            ulInLen: CK_ULONG,
            pOut: CK_BYTE_PTR,
            pulOutLen: CK_ULONG_PTR,
        ) -> CK_RV {
            let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
            let l = narrow_or!(ulInLen, CKR_ARGUMENTS_BAD);
            with_len_out(pulOutLen, |po| crate::ffi::$name(h, pIn, l, pOut, po))
        }
    )+};
}

/// (hSession, out_ptr, out_len_ptr) -> CK_RV
macro_rules! shim_sess_outlen {
    ($($name:ident),+ $(,)?) => {$(
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(
            hSession: CK_SESSION_HANDLE,
            pOut: CK_BYTE_PTR,
            pulOutLen: CK_ULONG_PTR,
        ) -> CK_RV {
            let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
            with_len_out(pulOutLen, |po| crate::ffi::$name(h, pOut, po))
        }
    )+};
}

/// (hSession, in_ptr, in_len, in2_ptr, in2_len) -> CK_RV
macro_rules! shim_sess_buf_buf {
    ($($name:ident),+ $(,)?) => {$(
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(
            hSession: CK_SESSION_HANDLE,
            pA: CK_BYTE_PTR,
            ulALen: CK_ULONG,
            pB: CK_BYTE_PTR,
            ulBLen: CK_ULONG,
        ) -> CK_RV {
            let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
            let la = narrow_or!(ulALen, CKR_ARGUMENTS_BAD);
            let lb = narrow_or!(ulBLen, CKR_ARGUMENTS_BAD);
            rv(crate::ffi::$name(h, pA, la, pB, lb))
        }
    )+};
}

/// (hSession, CK_MECHANISM_PTR, hKey) -> CK_RV
macro_rules! shim_mech_key {
    ($($name:ident),+ $(,)?) => {$(
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(
            hSession: CK_SESSION_HANDLE,
            pMechanism: CK_MECHANISM_PTR,
            hKey: CK_OBJECT_HANDLE,
        ) -> CK_RV {
            let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
            let k = narrow_or!(hKey, CKR_OBJECT_HANDLE_INVALID);
            let mut mech = xlate_mech_or!(pMechanism);
            rv(crate::ffi::$name(h, mech_ptr(&mut mech), k))
        }
    )+};
}

/// (hSession, pParam, ulParamLen) -> CK_RV — param IGNORED by the engine
/// (message sign/verify family) → opaque pass-through.
macro_rules! shim_msg_param_only {
    ($($name:ident),+ $(,)?) => {$(
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(
            hSession: CK_SESSION_HANDLE,
            pParameter: CK_VOID_PTR,
            ulParameterLen: CK_ULONG,
        ) -> CK_RV {
            let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
            let l = narrow_or!(ulParameterLen, CKR_ARGUMENTS_BAD);
            rv(crate::ffi::$name(h, pParameter as *mut u8, l))
        }
    )+};
}

/// (hSession, pParam, ulParamLen, pData, ulDataLen, pSig, pulSigLen) — the
/// sign-message shape (param ignored by the engine).
macro_rules! shim_msg_sign {
    ($($name:ident),+ $(,)?) => {$(
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(
            hSession: CK_SESSION_HANDLE,
            pParameter: CK_VOID_PTR,
            ulParameterLen: CK_ULONG,
            pData: CK_BYTE_PTR,
            ulDataLen: CK_ULONG,
            pSignature: CK_BYTE_PTR,
            pulSignatureLen: CK_ULONG_PTR,
        ) -> CK_RV {
            let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
            let pl = narrow_or!(ulParameterLen, CKR_ARGUMENTS_BAD);
            let dl = narrow_or!(ulDataLen, CKR_ARGUMENTS_BAD);
            with_len_out(pulSignatureLen, |po| {
                crate::ffi::$name(h, pParameter as *mut u8, pl, pData, dl, pSignature, po)
            })
        }
    )+};
}

/// (hSession, pParam, ulParamLen, pData, ulDataLen, pSig, ulSigLen) — the
/// verify-message shape (param ignored by the engine).
macro_rules! shim_msg_verify {
    ($($name:ident),+ $(,)?) => {$(
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(
            hSession: CK_SESSION_HANDLE,
            pParameter: CK_VOID_PTR,
            ulParameterLen: CK_ULONG,
            pData: CK_BYTE_PTR,
            ulDataLen: CK_ULONG,
            pSignature: CK_BYTE_PTR,
            ulSignatureLen: CK_ULONG,
        ) -> CK_RV {
            let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
            let pl = narrow_or!(ulParameterLen, CKR_ARGUMENTS_BAD);
            let dl = narrow_or!(ulDataLen, CKR_ARGUMENTS_BAD);
            let sl = narrow_or!(ulSignatureLen, CKR_ARGUMENTS_BAD);
            rv(crate::ffi::$name(h, pParameter as *mut u8, pl, pData, dl, pSignature, sl))
        }
    )+};
}

/// Formerly bailed CKR_FUNCTION_FAILED on 64-bit because CK_GCM_MESSAGE_PARAMS
/// was parsed as a wasm (32-bit) layout. parse_gcm_msg_params (read) and the
/// pTag writeback in C_EncryptMessageNext/Final (native usize word 4) now both
/// operate at native pointer width, so the AES-GCM message family works on
/// 64-bit — this guard is a no-op (kept as a seam in case re-gating is needed).
macro_rules! guard_gcm_msg_param {
    ($p:expr) => {{
        let _ = &$p;
    }};
}

// ─────────────────────────────────────────────────────────────────────────
// Shims — PKCS#11 v2.40 list (68 functions, pkcs11f.h order)
// ─────────────────────────────────────────────────────────────────────────

/// Native CK_C_INITIALIZE_ARGS (pkcs11t.h): four mutex callbacks, flags,
/// pReserved. CORRECTED 2026-07-18 (was stale): the engine is NOT
/// single-threaded — its state is a global `Mutex` shared by every
/// thread (see `native/mod.rs` "Threading model" and
/// `tests/multitenant_concurrency.rs`'s 20-thread contention test), so
/// it does its own internal locking regardless of what the caller
/// requests. Per PKCS#11 v3.2 §5.6, a library that locks internally MAY
/// ignore the caller's `CKF_OS_LOCKING_OK` flag and mutex callbacks — so
/// accepting and ignoring them here is conformant, not a shortcut.
/// pReserved must still be NULL (this crate has no C_Initialize
/// extension reachable through the native ABI; the wasm-facing
/// `ffi::C_Initialize` has a separate, `#[cfg(feature = "acvp")]`-gated
/// pReserved use for test/KAT tooling only).
#[repr(C)]
struct CK_C_INITIALIZE_ARGS {
    CreateMutex: *mut c_void,
    DestroyMutex: *mut c_void,
    LockMutex: *mut c_void,
    UnlockMutex: *mut c_void,
    flags: CK_FLAGS,
    pReserved: CK_VOID_PTR,
}

pub unsafe extern "C" fn C_Initialize(pInitArgs: CK_VOID_PTR) -> CK_RV {
    if pInitArgs.is_null() {
        return rv(crate::ffi::C_Initialize(std::ptr::null_mut()));
    }
    let args = &*(pInitArgs as *const CK_C_INITIALIZE_ARGS);
    if !args.pReserved.is_null() {
        return rv(CKR_ARGUMENTS_BAD);
    }
    rv(crate::ffi::C_Initialize(std::ptr::null_mut()))
}

pub unsafe extern "C" fn C_Finalize(pReserved: CK_VOID_PTR) -> CK_RV {
    rv(crate::ffi::C_Finalize(pReserved as *mut u8))
}

pub unsafe extern "C" fn C_GetInfo(pInfo: *mut CK_INFO) -> CK_RV {
    if pInfo.is_null() {
        return rv(CKR_ARGUMENTS_BAD);
    }
    // Engine blob (72 B): version@0, manufacturerID@2..34, flags(u32)@34,
    // libraryDescription@38..70, libraryVersion@70.
    let mut blob = [0u8; 72];
    let code = crate::ffi::C_GetInfo(blob.as_mut_ptr());
    if code == CKR_OK {
        let out = &mut *pInfo;
        out.cryptokiVersion = CK_VERSION { major: blob[0], minor: blob[1] };
        out.manufacturerID.copy_from_slice(&blob[2..34]);
        out.flags = widen(u32::from_le_bytes(blob[34..38].try_into().unwrap()));
        out.libraryDescription.copy_from_slice(&blob[38..70]);
        out.libraryVersion = CK_VERSION { major: blob[70], minor: blob[71] };
    }
    rv(code)
}

// C_GetFunctionList — defined below with the statics (exported symbol).

pub unsafe extern "C" fn C_GetSlotList(
    tokenPresent: CK_BBOOL,
    pSlotList: CK_SLOT_ID_PTR,
    pulCount: CK_ULONG_PTR,
) -> CK_RV {
    ulong_array_two_call(pSlotList, pulCount, |arr, cnt| {
        crate::ffi::C_GetSlotList(tokenPresent, arr, cnt)
    })
}

pub unsafe extern "C" fn C_GetSlotInfo(slotID: CK_SLOT_ID, pInfo: *mut CK_SLOT_INFO) -> CK_RV {
    let slot = narrow_or!(slotID, CKR_SLOT_ID_INVALID);
    if pInfo.is_null() {
        return rv(CKR_ARGUMENTS_BAD);
    }
    // Engine blob (104 B): desc@0..64, mfr@64..96, flags(u32)@96, hw@100, fw@102.
    let mut blob = [0u8; 104];
    let code = crate::ffi::C_GetSlotInfo(slot, blob.as_mut_ptr());
    if code == CKR_OK {
        let out = &mut *pInfo;
        out.slotDescription.copy_from_slice(&blob[0..64]);
        out.manufacturerID.copy_from_slice(&blob[64..96]);
        out.flags = widen(u32::from_le_bytes(blob[96..100].try_into().unwrap()));
        out.hardwareVersion = CK_VERSION { major: blob[100], minor: blob[101] };
        out.firmwareVersion = CK_VERSION { major: blob[102], minor: blob[103] };
    }
    rv(code)
}

pub unsafe extern "C" fn C_GetTokenInfo(slotID: CK_SLOT_ID, pInfo: *mut CK_TOKEN_INFO) -> CK_RV {
    let slot = narrow_or!(slotID, CKR_SLOT_ID_INVALID);
    if pInfo.is_null() {
        return rv(CKR_ARGUMENTS_BAD);
    }
    // Engine blob (160 B): label@0..32, mfr@32..64, model@64..80,
    // serial@80..96, flags(u32)@96, 10×u32 ULONG fields @100..140,
    // hw@140, fw@142, utcTime@144..160.
    let mut blob = [0u8; 160];
    let code = crate::ffi::C_GetTokenInfo(slot, blob.as_mut_ptr());
    if code == CKR_OK {
        let u = |off: usize| u32::from_le_bytes(blob[off..off + 4].try_into().unwrap());
        let out = &mut *pInfo;
        out.label.copy_from_slice(&blob[0..32]);
        out.manufacturerID.copy_from_slice(&blob[32..64]);
        out.model.copy_from_slice(&blob[64..80]);
        out.serialNumber.copy_from_slice(&blob[80..96]);
        out.flags = widen(u(96));
        out.ulMaxSessionCount = widen(u(100));
        out.ulSessionCount = widen(u(104));
        out.ulMaxRwSessionCount = widen(u(108));
        out.ulRwSessionCount = widen(u(112));
        out.ulMaxPinLen = widen(u(116));
        out.ulMinPinLen = widen(u(120));
        out.ulTotalPublicMemory = widen(u(124));
        out.ulFreePublicMemory = widen(u(128));
        out.ulTotalPrivateMemory = widen(u(132));
        out.ulFreePrivateMemory = widen(u(136));
        out.hardwareVersion = CK_VERSION { major: blob[140], minor: blob[141] };
        out.firmwareVersion = CK_VERSION { major: blob[142], minor: blob[143] };
        out.utcTime.copy_from_slice(&blob[144..160]);
    }
    rv(code)
}

pub unsafe extern "C" fn C_GetMechanismList(
    slotID: CK_SLOT_ID,
    pMechanismList: CK_MECHANISM_TYPE_PTR,
    pulCount: CK_ULONG_PTR,
) -> CK_RV {
    let slot = narrow_or!(slotID, CKR_SLOT_ID_INVALID);
    ulong_array_two_call(pMechanismList, pulCount, |arr, cnt| {
        crate::constants::C_GetMechanismList(slot, arr, cnt)
    })
}

pub unsafe extern "C" fn C_GetMechanismInfo(
    slotID: CK_SLOT_ID,
    mechType: CK_MECHANISM_TYPE,
    pInfo: *mut CK_MECHANISM_INFO,
) -> CK_RV {
    let slot = narrow_or!(slotID, CKR_SLOT_ID_INVALID);
    let mt = narrow_or!(mechType, CKR_MECHANISM_INVALID);
    if pInfo.is_null() {
        return rv(CKR_ARGUMENTS_BAD);
    }
    let mut blob = [0u8; 12]; // 3 × u32: min, max, flags
    let code = crate::ffi::C_GetMechanismInfo(slot, mt, blob.as_mut_ptr());
    if code == CKR_OK {
        let u = |off: usize| u32::from_le_bytes(blob[off..off + 4].try_into().unwrap());
        let out = &mut *pInfo;
        out.ulMinKeySize = widen(u(0));
        out.ulMaxKeySize = widen(u(4));
        out.flags = widen(u(8));
    }
    rv(code)
}

pub unsafe extern "C" fn C_InitToken(
    slotID: CK_SLOT_ID,
    pPin: CK_UTF8CHAR_PTR,
    ulPinLen: CK_ULONG,
    pLabel: CK_UTF8CHAR_PTR,
) -> CK_RV {
    let slot = narrow_or!(slotID, CKR_SLOT_ID_INVALID);
    let l = narrow_or!(ulPinLen, CKR_ARGUMENTS_BAD);
    rv(crate::ffi::C_InitToken(slot, pPin, l, pLabel))
}

shim_sess_buf!(C_InitPIN);
shim_sess_buf_buf!(C_SetPIN);

pub unsafe extern "C" fn C_OpenSession(
    slotID: CK_SLOT_ID,
    flags: CK_FLAGS,
    _pApplication: CK_VOID_PTR,
    _Notify: CK_NOTIFY,
    phSession: CK_SESSION_HANDLE_PTR,
) -> CK_RV {
    let slot = narrow_or!(slotID, CKR_SLOT_ID_INVALID);
    let fl = narrow_or!(flags, CKR_ARGUMENTS_BAD);
    // The engine never issues notifications — pApplication/Notify are
    // accepted and ignored (passed as NULL to the internal ABI).
    with_handle_out(phSession, |ph| {
        crate::ffi::C_OpenSession(slot, fl, std::ptr::null_mut(), std::ptr::null_mut(), ph)
    })
}

shim_session_only!(C_CloseSession);

pub unsafe extern "C" fn C_CloseAllSessions(slotID: CK_SLOT_ID) -> CK_RV {
    let slot = narrow_or!(slotID, CKR_SLOT_ID_INVALID);
    rv(crate::ffi::C_CloseAllSessions(slot))
}

pub unsafe extern "C" fn C_GetSessionInfo(
    hSession: CK_SESSION_HANDLE,
    pInfo: *mut CK_SESSION_INFO,
) -> CK_RV {
    let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
    if pInfo.is_null() {
        return rv(CKR_ARGUMENTS_BAD);
    }
    let mut blob = [0u8; 16]; // 4 × u32: slotID, state, flags, ulDeviceError
    let code = crate::ffi::C_GetSessionInfo(h, blob.as_mut_ptr());
    if code == CKR_OK {
        let u = |off: usize| u32::from_le_bytes(blob[off..off + 4].try_into().unwrap());
        let out = &mut *pInfo;
        out.slotID = widen(u(0));
        out.state = widen(u(4));
        out.flags = widen(u(8));
        out.ulDeviceError = widen(u(12));
    }
    rv(code)
}

shim_sess_outlen!(C_GetOperationState);

pub unsafe extern "C" fn C_SetOperationState(
    hSession: CK_SESSION_HANDLE,
    pOperationState: CK_BYTE_PTR,
    ulOperationStateLen: CK_ULONG,
    hEncryptionKey: CK_OBJECT_HANDLE,
    hAuthenticationKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
    let l = narrow_or!(ulOperationStateLen, CKR_ARGUMENTS_BAD);
    let he = narrow_or!(hEncryptionKey, CKR_OBJECT_HANDLE_INVALID);
    let ha = narrow_or!(hAuthenticationKey, CKR_OBJECT_HANDLE_INVALID);
    rv(crate::ffi::C_SetOperationState(h, pOperationState, l, he, ha))
}

pub unsafe extern "C" fn C_Login(
    hSession: CK_SESSION_HANDLE,
    userType: CK_USER_TYPE,
    pPin: CK_UTF8CHAR_PTR,
    ulPinLen: CK_ULONG,
) -> CK_RV {
    let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
    let ut = narrow_or!(userType, CKR_USER_TYPE_INVALID);
    let l = narrow_or!(ulPinLen, CKR_ARGUMENTS_BAD);
    rv(crate::ffi::C_Login(h, ut, pPin, l))
}

shim_session_only!(C_Logout);

pub unsafe extern "C" fn C_CreateObject(
    hSession: CK_SESSION_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
    phObject: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
    let (mut tmpl, n) = xlate_tmpl_or!(pTemplate, ulCount);
    with_handle_out(phObject, |ph| {
        crate::ffi::C_CreateObject(h, tmpl_ptr(&mut tmpl), n, ph)
    })
}

pub unsafe extern "C" fn C_CopyObject(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
    phNewObject: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
    let ho = narrow_or!(hObject, CKR_OBJECT_HANDLE_INVALID);
    let (mut tmpl, n) = xlate_tmpl_or!(pTemplate, ulCount);
    with_handle_out(phNewObject, |ph| {
        crate::ffi::C_CopyObject(h, ho, tmpl_ptr(&mut tmpl), n, ph)
    })
}

pub unsafe extern "C" fn C_DestroyObject(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
) -> CK_RV {
    let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
    let ho = narrow_or!(hObject, CKR_OBJECT_HANDLE_INVALID);
    rv(crate::ffi::C_DestroyObject(h, ho))
}

pub unsafe extern "C" fn C_GetObjectSize(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pulSize: CK_ULONG_PTR,
) -> CK_RV {
    let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
    let ho = narrow_or!(hObject, CKR_OBJECT_HANDLE_INVALID);
    if pulSize.is_null() {
        return rv(CKR_ARGUMENTS_BAD);
    }
    let mut sz: u32 = 0;
    let code = crate::ffi::C_GetObjectSize(h, ho, &mut sz);
    if code == CKR_OK {
        *pulSize = widen(sz);
    }
    rv(code)
}

pub unsafe extern "C" fn C_GetAttributeValue(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
) -> CK_RV {
    let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
    let ho = narrow_or!(hObject, CKR_OBJECT_HANDLE_INVALID);
    let (mut tmpl, n) = xlate_tmpl_or!(pTemplate, ulCount);
    let code = crate::ffi::C_GetAttributeValue(h, ho, tmpl_ptr(&mut tmpl), n);
    // Write the per-attribute lengths back (set on OK, BUFFER_TOO_SMALL,
    // ATTRIBUTE_SENSITIVE and ATTRIBUTE_TYPE_INVALID — §5.7.5), widening
    // the CK_UNAVAILABLE_INFORMATION sentinel.
    if let Some(v) = &tmpl {
        if !pTemplate.is_null() {
            for i in 0..n as usize {
                // v[..] is native-width usize already (usize::MAX == native
                // CK_UNAVAILABLE_INFORMATION), so write it straight through.
                (*pTemplate.add(i)).ulValueLen = v[i * 3 + 2] as CK_ULONG;
            }
        }
    }
    rv(code)
}

pub unsafe extern "C" fn C_SetAttributeValue(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
) -> CK_RV {
    let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
    let ho = narrow_or!(hObject, CKR_OBJECT_HANDLE_INVALID);
    let (mut tmpl, n) = xlate_tmpl_or!(pTemplate, ulCount);
    rv(crate::ffi::C_SetAttributeValue(h, ho, tmpl_ptr(&mut tmpl), n))
}

pub unsafe extern "C" fn C_FindObjectsInit(
    hSession: CK_SESSION_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
) -> CK_RV {
    let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
    let (mut tmpl, n) = xlate_tmpl_or!(pTemplate, ulCount);
    rv(crate::ffi::C_FindObjectsInit(h, tmpl_ptr(&mut tmpl), n))
}

pub unsafe extern "C" fn C_FindObjects(
    hSession: CK_SESSION_HANDLE,
    phObject: CK_OBJECT_HANDLE_PTR,
    ulMaxObjectCount: CK_ULONG,
    pulObjectCount: CK_ULONG_PTR,
) -> CK_RV {
    let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
    if phObject.is_null() || pulObjectCount.is_null() {
        return rv(CKR_ARGUMENTS_BAD);
    }
    // Returning fewer handles than ulMaxObjectCount is spec-legal — the
    // caller loops until the count comes back 0.
    let cap = ulMaxObjectCount.min(MAX_ARRAY_SCRATCH as CK_ULONG) as u32;
    let mut scratch = vec![0u32; cap as usize];
    let mut cnt: u32 = 0;
    let code = crate::ffi::C_FindObjects(h, scratch.as_mut_ptr(), cap, &mut cnt);
    if code == CKR_OK {
        for (i, v) in scratch.iter().take((cnt as usize).min(cap as usize)).enumerate() {
            *phObject.add(i) = *v as CK_OBJECT_HANDLE;
        }
        *pulObjectCount = cnt as CK_ULONG;
    }
    rv(code)
}

shim_session_only!(C_FindObjectsFinal);

shim_mech_key!(C_EncryptInit);
shim_sess_in_outlen!(C_Encrypt, C_EncryptUpdate);
shim_sess_outlen!(C_EncryptFinal);
shim_mech_key!(C_DecryptInit);
shim_sess_in_outlen!(C_Decrypt, C_DecryptUpdate);
shim_sess_outlen!(C_DecryptFinal);

pub unsafe extern "C" fn C_DigestInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
) -> CK_RV {
    let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
    let mut mech = xlate_mech_or!(pMechanism);
    rv(crate::ffi::C_DigestInit(h, mech_ptr(&mut mech)))
}

shim_sess_in_outlen!(C_Digest);
shim_sess_buf!(C_DigestUpdate);

pub unsafe extern "C" fn C_DigestKey(hSession: CK_SESSION_HANDLE, hKey: CK_OBJECT_HANDLE) -> CK_RV {
    let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
    let k = narrow_or!(hKey, CKR_OBJECT_HANDLE_INVALID);
    rv(crate::ffi::C_DigestKey(h, k))
}

shim_sess_outlen!(C_DigestFinal);

shim_mech_key!(C_SignInit);
shim_sess_in_outlen!(C_Sign);
shim_sess_buf!(C_SignUpdate);
shim_sess_outlen!(C_SignFinal);
shim_mech_key!(C_SignRecoverInit);
shim_sess_in_outlen!(C_SignRecover);

shim_mech_key!(C_VerifyInit);
shim_sess_buf_buf!(C_Verify);
shim_sess_buf!(C_VerifyUpdate, C_VerifyFinal);
shim_mech_key!(C_VerifyRecoverInit);
shim_sess_in_outlen!(C_VerifyRecover);

shim_sess_in_outlen!(
    C_DigestEncryptUpdate,
    C_DecryptDigestUpdate,
    C_SignEncryptUpdate,
    C_DecryptVerifyUpdate,
);

pub unsafe extern "C" fn C_GenerateKey(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
    phKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
    let mut mech = xlate_mech_or!(pMechanism);
    let (mut tmpl, n) = xlate_tmpl_or!(pTemplate, ulCount);
    with_handle_out(phKey, |ph| {
        crate::ffi::C_GenerateKey(h, mech_ptr(&mut mech), tmpl_ptr(&mut tmpl), n, ph)
    })
}

pub unsafe extern "C" fn C_GenerateKeyPair(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    pPublicKeyTemplate: CK_ATTRIBUTE_PTR,
    ulPublicKeyAttributeCount: CK_ULONG,
    pPrivateKeyTemplate: CK_ATTRIBUTE_PTR,
    ulPrivateKeyAttributeCount: CK_ULONG,
    phPublicKey: CK_OBJECT_HANDLE_PTR,
    phPrivateKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
    let mut mech = xlate_mech_or!(pMechanism);
    let (mut tpub, npub) = xlate_tmpl_or!(pPublicKeyTemplate, ulPublicKeyAttributeCount);
    let (mut tprv, nprv) = xlate_tmpl_or!(pPrivateKeyTemplate, ulPrivateKeyAttributeCount);
    if phPublicKey.is_null() || phPrivateKey.is_null() {
        return rv(CKR_ARGUMENTS_BAD);
    }
    let mut hpub: u32 = 0;
    let mut hprv: u32 = 0;
    let code = crate::ffi::C_GenerateKeyPair(
        h,
        mech_ptr(&mut mech),
        tmpl_ptr(&mut tpub),
        npub,
        tmpl_ptr(&mut tprv),
        nprv,
        &mut hpub,
        &mut hprv,
    );
    if code == CKR_OK {
        *phPublicKey = hpub as CK_OBJECT_HANDLE;
        *phPrivateKey = hprv as CK_OBJECT_HANDLE;
    }
    rv(code)
}

pub unsafe extern "C" fn C_WrapKey(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hWrappingKey: CK_OBJECT_HANDLE,
    hKey: CK_OBJECT_HANDLE,
    pWrappedKey: CK_BYTE_PTR,
    pulWrappedKeyLen: CK_ULONG_PTR,
) -> CK_RV {
    let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
    let hw = narrow_or!(hWrappingKey, CKR_OBJECT_HANDLE_INVALID);
    let hk = narrow_or!(hKey, CKR_OBJECT_HANDLE_INVALID);
    let mut mech = xlate_mech_or!(pMechanism);
    with_len_out(pulWrappedKeyLen, |po| {
        crate::ffi::C_WrapKey(h, mech_ptr(&mut mech), hw, hk, pWrappedKey, po)
    })
}

pub unsafe extern "C" fn C_UnwrapKey(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hUnwrappingKey: CK_OBJECT_HANDLE,
    pWrappedKey: CK_BYTE_PTR,
    ulWrappedKeyLen: CK_ULONG,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulAttributeCount: CK_ULONG,
    phKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
    let hu = narrow_or!(hUnwrappingKey, CKR_OBJECT_HANDLE_INVALID);
    let wl = narrow_or!(ulWrappedKeyLen, CKR_ARGUMENTS_BAD);
    let mut mech = xlate_mech_or!(pMechanism);
    let (mut tmpl, n) = xlate_tmpl_or!(pTemplate, ulAttributeCount);
    with_handle_out(phKey, |ph| {
        crate::ffi::C_UnwrapKey(
            h,
            mech_ptr(&mut mech),
            hu,
            pWrappedKey,
            wl,
            tmpl_ptr(&mut tmpl),
            n,
            ph,
        )
    })
}

pub unsafe extern "C" fn C_DeriveKey(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hBaseKey: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulAttributeCount: CK_ULONG,
    phKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
    let hb = narrow_or!(hBaseKey, CKR_OBJECT_HANDLE_INVALID);
    let mut mech = xlate_mech_or!(pMechanism);
    let (mut tmpl, n) = xlate_tmpl_or!(pTemplate, ulAttributeCount);
    with_handle_out(phKey, |ph| {
        crate::ffi::C_DeriveKey(h, mech_ptr(&mut mech), hb, tmpl_ptr(&mut tmpl), n, ph)
    })
}

shim_sess_buf!(C_SeedRandom, C_GenerateRandom);
shim_session_only!(C_GetFunctionStatus, C_CancelFunction);

pub unsafe extern "C" fn C_WaitForSlotEvent(
    flags: CK_FLAGS,
    pSlot: CK_SLOT_ID_PTR,
    pReserved: CK_VOID_PTR,
) -> CK_RV {
    let fl = narrow_or!(flags, CKR_ARGUMENTS_BAD);
    let mut slot: u32 = 0;
    let code = crate::ffi::C_WaitForSlotEvent(fl, &mut slot, pReserved as *mut u8);
    if code == CKR_OK && !pSlot.is_null() {
        *pSlot = slot as CK_SLOT_ID;
    }
    rv(code)
}

// ─────────────────────────────────────────────────────────────────────────
// Shims — PKCS#11 v3.0 additions (24 functions)
// ─────────────────────────────────────────────────────────────────────────

// C_GetInterfaceList / C_GetInterface — defined below with the statics
// (exported symbols).

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_LoginUser(
    hSession: CK_SESSION_HANDLE,
    userType: CK_USER_TYPE,
    pPin: CK_UTF8CHAR_PTR,
    ulPinLen: CK_ULONG,
    pUsername: CK_UTF8CHAR_PTR,
    ulUsernameLen: CK_ULONG,
) -> CK_RV {
    let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
    let ut = narrow_or!(userType, CKR_USER_TYPE_INVALID);
    let pl = narrow_or!(ulPinLen, CKR_ARGUMENTS_BAD);
    let ul = narrow_or!(ulUsernameLen, CKR_ARGUMENTS_BAD);
    rv(crate::ffi::C_LoginUser(h, ut, pPin, pl, pUsername, ul))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_SessionCancel(hSession: CK_SESSION_HANDLE, flags: CK_FLAGS) -> CK_RV {
    let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
    let fl = narrow_or!(flags, CKR_ARGUMENTS_BAD);
    rv(crate::ffi::C_SessionCancel(h, fl))
}

shim_mech_key!(C_MessageEncryptInit, C_MessageDecryptInit);

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_EncryptMessage(
    hSession: CK_SESSION_HANDLE,
    pParameter: CK_VOID_PTR,
    ulParameterLen: CK_ULONG,
    pAssociatedData: CK_BYTE_PTR,
    ulAssociatedDataLen: CK_ULONG,
    pPlaintext: CK_BYTE_PTR,
    ulPlaintextLen: CK_ULONG,
    pCiphertext: CK_BYTE_PTR,
    pulCiphertextLen: CK_ULONG_PTR,
) -> CK_RV {
    let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
    guard_gcm_msg_param!(pParameter);
    let pl = narrow_or!(ulParameterLen, CKR_ARGUMENTS_BAD);
    let al = narrow_or!(ulAssociatedDataLen, CKR_ARGUMENTS_BAD);
    let dl = narrow_or!(ulPlaintextLen, CKR_ARGUMENTS_BAD);
    with_len_out(pulCiphertextLen, |po| {
        crate::ffi::C_EncryptMessage(
            h,
            pParameter as *mut u8,
            pl,
            pAssociatedData,
            al,
            pPlaintext,
            dl,
            pCiphertext,
            po,
        )
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_EncryptMessageBegin(
    hSession: CK_SESSION_HANDLE,
    pParameter: CK_VOID_PTR,
    ulParameterLen: CK_ULONG,
    pAssociatedData: CK_BYTE_PTR,
    ulAssociatedDataLen: CK_ULONG,
) -> CK_RV {
    let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
    guard_gcm_msg_param!(pParameter);
    let pl = narrow_or!(ulParameterLen, CKR_ARGUMENTS_BAD);
    let al = narrow_or!(ulAssociatedDataLen, CKR_ARGUMENTS_BAD);
    rv(crate::ffi::C_EncryptMessageBegin(
        h,
        pParameter as *mut u8,
        pl,
        pAssociatedData,
        al,
    ))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_EncryptMessageNext(
    hSession: CK_SESSION_HANDLE,
    pParameter: CK_VOID_PTR,
    ulParameterLen: CK_ULONG,
    pPlaintextPart: CK_BYTE_PTR,
    ulPlaintextPartLen: CK_ULONG,
    pCiphertextPart: CK_BYTE_PTR,
    pulCiphertextPartLen: CK_ULONG_PTR,
    flags: CK_FLAGS,
) -> CK_RV {
    let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
    guard_gcm_msg_param!(pParameter);
    let pl = narrow_or!(ulParameterLen, CKR_ARGUMENTS_BAD);
    let dl = narrow_or!(ulPlaintextPartLen, CKR_ARGUMENTS_BAD);
    let fl = narrow_or!(flags, CKR_ARGUMENTS_BAD);
    with_len_out(pulCiphertextPartLen, |po| {
        crate::ffi::C_EncryptMessageNext(
            h,
            pParameter as *mut u8,
            pl,
            pPlaintextPart,
            dl,
            pCiphertextPart,
            po,
            fl,
        )
    })
}

shim_session_only!(C_MessageEncryptFinal, C_MessageDecryptFinal);

pub unsafe extern "C" fn C_DecryptMessage(
    hSession: CK_SESSION_HANDLE,
    pParameter: CK_VOID_PTR,
    ulParameterLen: CK_ULONG,
    pAssociatedData: CK_BYTE_PTR,
    ulAssociatedDataLen: CK_ULONG,
    pCiphertext: CK_BYTE_PTR,
    ulCiphertextLen: CK_ULONG,
    pPlaintext: CK_BYTE_PTR,
    pulPlaintextLen: CK_ULONG_PTR,
) -> CK_RV {
    let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
    guard_gcm_msg_param!(pParameter);
    let pl = narrow_or!(ulParameterLen, CKR_ARGUMENTS_BAD);
    let al = narrow_or!(ulAssociatedDataLen, CKR_ARGUMENTS_BAD);
    let cl = narrow_or!(ulCiphertextLen, CKR_ARGUMENTS_BAD);
    with_len_out(pulPlaintextLen, |po| {
        crate::ffi::C_DecryptMessage(
            h,
            pParameter as *mut u8,
            pl,
            pAssociatedData,
            al,
            pCiphertext,
            cl,
            pPlaintext,
            po,
        )
    })
}

pub unsafe extern "C" fn C_DecryptMessageBegin(
    hSession: CK_SESSION_HANDLE,
    pParameter: CK_VOID_PTR,
    ulParameterLen: CK_ULONG,
    pAssociatedData: CK_BYTE_PTR,
    ulAssociatedDataLen: CK_ULONG,
) -> CK_RV {
    let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
    guard_gcm_msg_param!(pParameter);
    let pl = narrow_or!(ulParameterLen, CKR_ARGUMENTS_BAD);
    let al = narrow_or!(ulAssociatedDataLen, CKR_ARGUMENTS_BAD);
    rv(crate::ffi::C_DecryptMessageBegin(
        h,
        pParameter as *mut u8,
        pl,
        pAssociatedData,
        al,
    ))
}

pub unsafe extern "C" fn C_DecryptMessageNext(
    hSession: CK_SESSION_HANDLE,
    pParameter: CK_VOID_PTR,
    ulParameterLen: CK_ULONG,
    pCiphertextPart: CK_BYTE_PTR,
    ulCiphertextPartLen: CK_ULONG,
    pPlaintextPart: CK_BYTE_PTR,
    pulPlaintextPartLen: CK_ULONG_PTR,
    flags: CK_FLAGS,
) -> CK_RV {
    let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
    guard_gcm_msg_param!(pParameter);
    let pl = narrow_or!(ulParameterLen, CKR_ARGUMENTS_BAD);
    let cl = narrow_or!(ulCiphertextPartLen, CKR_ARGUMENTS_BAD);
    let fl = narrow_or!(flags, CKR_ARGUMENTS_BAD);
    with_len_out(pulPlaintextPartLen, |po| {
        crate::ffi::C_DecryptMessageNext(
            h,
            pParameter as *mut u8,
            pl,
            pCiphertextPart,
            cl,
            pPlaintextPart,
            po,
            fl,
        )
    })
}

shim_mech_key!(C_MessageSignInit, C_MessageVerifyInit);
shim_msg_sign!(C_SignMessage, C_SignMessageNext);
shim_msg_param_only!(C_SignMessageBegin, C_VerifyMessageBegin);
shim_session_only!(C_MessageSignFinal, C_MessageVerifyFinal);
shim_msg_verify!(C_VerifyMessage, C_VerifyMessageNext);

// ─────────────────────────────────────────────────────────────────────────
// Shims — PKCS#11 v3.2 additions (12 functions)
// ─────────────────────────────────────────────────────────────────────────

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_EncapsulateKey(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hPublicKey: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulAttributeCount: CK_ULONG,
    pCiphertext: CK_BYTE_PTR,
    pulCiphertextLen: CK_ULONG_PTR,
    phKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
    let hp = narrow_or!(hPublicKey, CKR_OBJECT_HANDLE_INVALID);
    let mut mech = xlate_mech_or!(pMechanism);
    let (mut tmpl, n) = xlate_tmpl_or!(pTemplate, ulAttributeCount);
    let mut hk: u32 = 0;
    let code = with_len_out(pulCiphertextLen, |po| {
        crate::ffi::C_EncapsulateKey(
            h,
            mech_ptr(&mut mech),
            hp,
            tmpl_ptr(&mut tmpl),
            n,
            pCiphertext,
            po,
            &mut hk,
        )
    });
    // The key handle is produced only on the real call (§5.23 — the
    // NULL-ciphertext size query creates nothing).
    if code == rv(CKR_OK) && !pCiphertext.is_null() && !phKey.is_null() {
        *phKey = hk as CK_OBJECT_HANDLE;
    }
    code
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_DecapsulateKey(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hPrivateKey: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulAttributeCount: CK_ULONG,
    pCiphertext: CK_BYTE_PTR,
    ulCiphertextLen: CK_ULONG,
    phKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
    let hp = narrow_or!(hPrivateKey, CKR_OBJECT_HANDLE_INVALID);
    let cl = narrow_or!(ulCiphertextLen, CKR_ARGUMENTS_BAD);
    let mut mech = xlate_mech_or!(pMechanism);
    let (mut tmpl, n) = xlate_tmpl_or!(pTemplate, ulAttributeCount);
    with_handle_out(phKey, |ph| {
        crate::ffi::C_DecapsulateKey(
            h,
            mech_ptr(&mut mech),
            hp,
            tmpl_ptr(&mut tmpl),
            n,
            pCiphertext,
            cl,
            ph,
        )
    })
}

pub unsafe extern "C" fn C_VerifySignatureInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
    pSignature: CK_BYTE_PTR,
    ulSignatureLen: CK_ULONG,
) -> CK_RV {
    let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
    let k = narrow_or!(hKey, CKR_OBJECT_HANDLE_INVALID);
    let sl = narrow_or!(ulSignatureLen, CKR_ARGUMENTS_BAD);
    let mut mech = xlate_mech_or!(pMechanism);
    rv(crate::ffi::C_VerifySignatureInit(
        h,
        mech_ptr(&mut mech),
        k,
        pSignature,
        sl,
    ))
}

shim_sess_buf!(C_VerifySignature, C_VerifySignatureUpdate);
shim_session_only!(C_VerifySignatureFinal);

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetSessionValidationFlags(
    hSession: CK_SESSION_HANDLE,
    flagsType: CK_SESSION_VALIDATION_FLAGS_TYPE,
    pFlags: CK_FLAGS_PTR,
) -> CK_RV {
    let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
    let t = narrow_or!(flagsType, CKR_ARGUMENTS_BAD);
    let mut fl: u32 = 0;
    let code = crate::ffi::C_GetSessionValidationFlags(h, t, &mut fl);
    if code == CKR_OK && !pFlags.is_null() {
        *pFlags = widen(fl);
    }
    rv(code)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_AsyncComplete(
    hSession: CK_SESSION_HANDLE,
    pFunctionName: CK_UTF8CHAR_PTR,
    pResult: CK_ASYNC_DATA_PTR,
) -> CK_RV {
    let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
    // Engine stub never dereferences pResult — opaque pass-through.
    rv(crate::ffi::C_AsyncComplete(h, pFunctionName, pResult as *mut u8))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_AsyncGetID(
    hSession: CK_SESSION_HANDLE,
    pFunctionName: CK_UTF8CHAR_PTR,
    pulID: CK_ULONG_PTR,
) -> CK_RV {
    let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
    let mut id: u32 = 0;
    let code = crate::ffi::C_AsyncGetID(h, pFunctionName, &mut id);
    if code == CKR_OK && !pulID.is_null() {
        *pulID = widen(id);
    }
    rv(code)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_AsyncJoin(
    hSession: CK_SESSION_HANDLE,
    pFunctionName: CK_UTF8CHAR_PTR,
    ulID: CK_ULONG,
    pData: CK_BYTE_PTR,
    ulData: CK_ULONG,
) -> CK_RV {
    let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
    let id = narrow_or!(ulID, CKR_ARGUMENTS_BAD);
    let dl = narrow_or!(ulData, CKR_ARGUMENTS_BAD);
    rv(crate::ffi::C_AsyncJoin(h, pFunctionName, id, pData, dl))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_WrapKeyAuthenticated(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hWrappingKey: CK_OBJECT_HANDLE,
    hKey: CK_OBJECT_HANDLE,
    pAssociatedData: CK_BYTE_PTR,
    ulAssociatedDataLen: CK_ULONG,
    pWrappedKey: CK_BYTE_PTR,
    pulWrappedKeyLen: CK_ULONG_PTR,
) -> CK_RV {
    let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
    let hw = narrow_or!(hWrappingKey, CKR_OBJECT_HANDLE_INVALID);
    let hk = narrow_or!(hKey, CKR_OBJECT_HANDLE_INVALID);
    let al = narrow_or!(ulAssociatedDataLen, CKR_ARGUMENTS_BAD);
    let mut mech = xlate_mech_or!(pMechanism);
    with_len_out(pulWrappedKeyLen, |po| {
        crate::ffi::C_WrapKeyAuthenticated(
            h,
            mech_ptr(&mut mech),
            hw,
            hk,
            pAssociatedData,
            al,
            pWrappedKey,
            po,
        )
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_UnwrapKeyAuthenticated(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hUnwrappingKey: CK_OBJECT_HANDLE,
    pWrappedKey: CK_BYTE_PTR,
    ulWrappedKeyLen: CK_ULONG,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulAttributeCount: CK_ULONG,
    pAssociatedData: CK_BYTE_PTR,
    ulAssociatedDataLen: CK_ULONG,
    phKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV {
    let h = narrow_or!(hSession, CKR_SESSION_HANDLE_INVALID);
    let hu = narrow_or!(hUnwrappingKey, CKR_OBJECT_HANDLE_INVALID);
    let wl = narrow_or!(ulWrappedKeyLen, CKR_ARGUMENTS_BAD);
    let al = narrow_or!(ulAssociatedDataLen, CKR_ARGUMENTS_BAD);
    let mut mech = xlate_mech_or!(pMechanism);
    let (mut tmpl, n) = xlate_tmpl_or!(pTemplate, ulAttributeCount);
    with_handle_out(phKey, |ph| {
        crate::ffi::C_UnwrapKeyAuthenticated(
            h,
            mech_ptr(&mut mech),
            hu,
            pWrappedKey,
            wl,
            tmpl_ptr(&mut tmpl),
            n,
            pAssociatedData,
            al,
            ph,
        )
    })
}

// ─────────────────────────────────────────────────────────────────────────
// CK_FUNCTION_LIST structs — fields in EXACT pkcs11f.h order.
//
// pkcs11.h builds the three structs by including pkcs11f.h with the
// CK_PKCS11_2_0_ONLY / CK_PKCS11_3_0_ONLY guards:
//   CK_FUNCTION_LIST      = C_Initialize .. C_WaitForSlotEvent   (68)
//   CK_FUNCTION_LIST_3_0  = + C_GetInterfaceList .. C_MessageVerifyFinal (92)
//   CK_FUNCTION_LIST_3_2  = + C_EncapsulateKey .. C_UnwrapKeyAuthenticated (104)
//
// All members after the CK_VERSION header are pointer-sized, so composing
// the flat C struct out of repr(C) segments below is layout-identical.
// ─────────────────────────────────────────────────────────────────────────

/// C_Initialize .. C_WaitForSlotEvent — the 68 PKCS#11 v2.40 entry points.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FnListV240 {
    pub C_Initialize: unsafe extern "C" fn(CK_VOID_PTR) -> CK_RV,
    pub C_Finalize: unsafe extern "C" fn(CK_VOID_PTR) -> CK_RV,
    pub C_GetInfo: unsafe extern "C" fn(*mut CK_INFO) -> CK_RV,
    pub C_GetFunctionList: unsafe extern "C" fn(*mut *mut CK_FUNCTION_LIST) -> CK_RV,
    pub C_GetSlotList: unsafe extern "C" fn(CK_BBOOL, CK_SLOT_ID_PTR, CK_ULONG_PTR) -> CK_RV,
    pub C_GetSlotInfo: unsafe extern "C" fn(CK_SLOT_ID, *mut CK_SLOT_INFO) -> CK_RV,
    pub C_GetTokenInfo: unsafe extern "C" fn(CK_SLOT_ID, *mut CK_TOKEN_INFO) -> CK_RV,
    pub C_GetMechanismList:
        unsafe extern "C" fn(CK_SLOT_ID, CK_MECHANISM_TYPE_PTR, CK_ULONG_PTR) -> CK_RV,
    pub C_GetMechanismInfo:
        unsafe extern "C" fn(CK_SLOT_ID, CK_MECHANISM_TYPE, *mut CK_MECHANISM_INFO) -> CK_RV,
    pub C_InitToken:
        unsafe extern "C" fn(CK_SLOT_ID, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR) -> CK_RV,
    pub C_InitPIN: unsafe extern "C" fn(CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG) -> CK_RV,
    pub C_SetPIN: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_UTF8CHAR_PTR,
        CK_ULONG,
        CK_UTF8CHAR_PTR,
        CK_ULONG,
    ) -> CK_RV,
    pub C_OpenSession: unsafe extern "C" fn(
        CK_SLOT_ID,
        CK_FLAGS,
        CK_VOID_PTR,
        CK_NOTIFY,
        CK_SESSION_HANDLE_PTR,
    ) -> CK_RV,
    pub C_CloseSession: unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV,
    pub C_CloseAllSessions: unsafe extern "C" fn(CK_SLOT_ID) -> CK_RV,
    pub C_GetSessionInfo: unsafe extern "C" fn(CK_SESSION_HANDLE, *mut CK_SESSION_INFO) -> CK_RV,
    pub C_GetOperationState:
        unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV,
    pub C_SetOperationState: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_OBJECT_HANDLE,
        CK_OBJECT_HANDLE,
    ) -> CK_RV,
    pub C_Login:
        unsafe extern "C" fn(CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_ULONG) -> CK_RV,
    pub C_Logout: unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV,
    pub C_CreateObject: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_ATTRIBUTE_PTR,
        CK_ULONG,
        CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV,
    pub C_CopyObject: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_OBJECT_HANDLE,
        CK_ATTRIBUTE_PTR,
        CK_ULONG,
        CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV,
    pub C_DestroyObject: unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE) -> CK_RV,
    pub C_GetObjectSize:
        unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ULONG_PTR) -> CK_RV,
    pub C_GetAttributeValue: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_OBJECT_HANDLE,
        CK_ATTRIBUTE_PTR,
        CK_ULONG,
    ) -> CK_RV,
    pub C_SetAttributeValue: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_OBJECT_HANDLE,
        CK_ATTRIBUTE_PTR,
        CK_ULONG,
    ) -> CK_RV,
    pub C_FindObjectsInit:
        unsafe extern "C" fn(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG) -> CK_RV,
    pub C_FindObjects: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_OBJECT_HANDLE_PTR,
        CK_ULONG,
        CK_ULONG_PTR,
    ) -> CK_RV,
    pub C_FindObjectsFinal: unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV,
    pub C_EncryptInit:
        unsafe extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV,
    pub C_Encrypt: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
    pub C_EncryptUpdate: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
    pub C_EncryptFinal:
        unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV,
    pub C_DecryptInit:
        unsafe extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV,
    pub C_Decrypt: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
    pub C_DecryptUpdate: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
    pub C_DecryptFinal:
        unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV,
    pub C_DigestInit: unsafe extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR) -> CK_RV,
    pub C_Digest: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
    pub C_DigestUpdate: unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV,
    pub C_DigestKey: unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE) -> CK_RV,
    pub C_DigestFinal: unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV,
    pub C_SignInit:
        unsafe extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV,
    pub C_Sign: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
    pub C_SignUpdate: unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV,
    pub C_SignFinal: unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV,
    pub C_SignRecoverInit:
        unsafe extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV,
    pub C_SignRecover: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
    pub C_VerifyInit:
        unsafe extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV,
    pub C_Verify: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
    ) -> CK_RV,
    pub C_VerifyUpdate: unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV,
    pub C_VerifyFinal: unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV,
    pub C_VerifyRecoverInit:
        unsafe extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV,
    pub C_VerifyRecover: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
    pub C_DigestEncryptUpdate: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
    pub C_DecryptDigestUpdate: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
    pub C_SignEncryptUpdate: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
    pub C_DecryptVerifyUpdate: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
    pub C_GenerateKey: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_MECHANISM_PTR,
        CK_ATTRIBUTE_PTR,
        CK_ULONG,
        CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV,
    pub C_GenerateKeyPair: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_MECHANISM_PTR,
        CK_ATTRIBUTE_PTR,
        CK_ULONG,
        CK_ATTRIBUTE_PTR,
        CK_ULONG,
        CK_OBJECT_HANDLE_PTR,
        CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV,
    pub C_WrapKey: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_MECHANISM_PTR,
        CK_OBJECT_HANDLE,
        CK_OBJECT_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
    pub C_UnwrapKey: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_MECHANISM_PTR,
        CK_OBJECT_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_ATTRIBUTE_PTR,
        CK_ULONG,
        CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV,
    pub C_DeriveKey: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_MECHANISM_PTR,
        CK_OBJECT_HANDLE,
        CK_ATTRIBUTE_PTR,
        CK_ULONG,
        CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV,
    pub C_SeedRandom: unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV,
    pub C_GenerateRandom: unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV,
    pub C_GetFunctionStatus: unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV,
    pub C_CancelFunction: unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV,
    pub C_WaitForSlotEvent:
        unsafe extern "C" fn(CK_FLAGS, CK_SLOT_ID_PTR, CK_VOID_PTR) -> CK_RV,
}

/// C_GetInterfaceList .. C_MessageVerifyFinal — the 24 v3.0 additions.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FnListV30Ext {
    pub C_GetInterfaceList: unsafe extern "C" fn(CK_INTERFACE_PTR, CK_ULONG_PTR) -> CK_RV,
    pub C_GetInterface: unsafe extern "C" fn(
        CK_UTF8CHAR_PTR,
        *mut CK_VERSION,
        CK_INTERFACE_PTR_PTR,
        CK_FLAGS,
    ) -> CK_RV,
    pub C_LoginUser: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_USER_TYPE,
        CK_UTF8CHAR_PTR,
        CK_ULONG,
        CK_UTF8CHAR_PTR,
        CK_ULONG,
    ) -> CK_RV,
    pub C_SessionCancel: unsafe extern "C" fn(CK_SESSION_HANDLE, CK_FLAGS) -> CK_RV,
    pub C_MessageEncryptInit:
        unsafe extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV,
    pub C_EncryptMessage: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_VOID_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
    pub C_EncryptMessageBegin: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_VOID_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
    ) -> CK_RV,
    pub C_EncryptMessageNext: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_VOID_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
        CK_FLAGS,
    ) -> CK_RV,
    pub C_MessageEncryptFinal: unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV,
    pub C_MessageDecryptInit:
        unsafe extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV,
    pub C_DecryptMessage: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_VOID_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
    pub C_DecryptMessageBegin: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_VOID_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
    ) -> CK_RV,
    pub C_DecryptMessageNext: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_VOID_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
        CK_FLAGS,
    ) -> CK_RV,
    pub C_MessageDecryptFinal: unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV,
    pub C_MessageSignInit:
        unsafe extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV,
    pub C_SignMessage: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_VOID_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
    pub C_SignMessageBegin:
        unsafe extern "C" fn(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG) -> CK_RV,
    pub C_SignMessageNext: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_VOID_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
    pub C_MessageSignFinal: unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV,
    pub C_MessageVerifyInit:
        unsafe extern "C" fn(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE) -> CK_RV,
    pub C_VerifyMessage: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_VOID_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
    ) -> CK_RV,
    pub C_VerifyMessageBegin:
        unsafe extern "C" fn(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG) -> CK_RV,
    pub C_VerifyMessageNext: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_VOID_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
    ) -> CK_RV,
    pub C_MessageVerifyFinal: unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV,
}

/// C_EncapsulateKey .. C_UnwrapKeyAuthenticated — the 12 v3.2 additions.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FnListV32Ext {
    pub C_EncapsulateKey: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_MECHANISM_PTR,
        CK_OBJECT_HANDLE,
        CK_ATTRIBUTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
        CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV,
    pub C_DecapsulateKey: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_MECHANISM_PTR,
        CK_OBJECT_HANDLE,
        CK_ATTRIBUTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV,
    pub C_VerifySignatureInit: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_MECHANISM_PTR,
        CK_OBJECT_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
    ) -> CK_RV,
    pub C_VerifySignature: unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV,
    pub C_VerifySignatureUpdate:
        unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV,
    pub C_VerifySignatureFinal: unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV,
    pub C_GetSessionValidationFlags: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_SESSION_VALIDATION_FLAGS_TYPE,
        CK_FLAGS_PTR,
    ) -> CK_RV,
    pub C_AsyncComplete:
        unsafe extern "C" fn(CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ASYNC_DATA_PTR) -> CK_RV,
    pub C_AsyncGetID:
        unsafe extern "C" fn(CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG_PTR) -> CK_RV,
    pub C_AsyncJoin: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_UTF8CHAR_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
    ) -> CK_RV,
    pub C_WrapKeyAuthenticated: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_MECHANISM_PTR,
        CK_OBJECT_HANDLE,
        CK_OBJECT_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG_PTR,
    ) -> CK_RV,
    pub C_UnwrapKeyAuthenticated: unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_MECHANISM_PTR,
        CK_OBJECT_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_ATTRIBUTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_OBJECT_HANDLE_PTR,
    ) -> CK_RV,
}

/// pkcs11.h `struct CK_FUNCTION_LIST` (v2.40 — 68 entries).
#[repr(C)]
pub struct CK_FUNCTION_LIST {
    pub version: CK_VERSION,
    pub f: FnListV240,
}

/// pkcs11.h `struct CK_FUNCTION_LIST_3_0` (92 entries).
#[repr(C)]
pub struct CK_FUNCTION_LIST_3_0 {
    pub version: CK_VERSION,
    pub f: FnListV240,
    pub f30: FnListV30Ext,
}

/// pkcs11.h `struct CK_FUNCTION_LIST_3_2` (104 entries).
#[repr(C)]
pub struct CK_FUNCTION_LIST_3_2 {
    pub version: CK_VERSION,
    pub f: FnListV240,
    pub f30: FnListV30Ext,
    pub f32: FnListV32Ext,
}

pub type CK_FUNCTION_LIST_PTR = *mut CK_FUNCTION_LIST;
pub type CK_FUNCTION_LIST_PTR_PTR = *mut CK_FUNCTION_LIST_PTR;

const FN_240: FnListV240 = FnListV240 {
    C_Initialize,
    C_Finalize,
    C_GetInfo,
    C_GetFunctionList,
    C_GetSlotList,
    C_GetSlotInfo,
    C_GetTokenInfo,
    C_GetMechanismList,
    C_GetMechanismInfo,
    C_InitToken,
    C_InitPIN,
    C_SetPIN,
    C_OpenSession,
    C_CloseSession,
    C_CloseAllSessions,
    C_GetSessionInfo,
    C_GetOperationState,
    C_SetOperationState,
    C_Login,
    C_Logout,
    C_CreateObject,
    C_CopyObject,
    C_DestroyObject,
    C_GetObjectSize,
    C_GetAttributeValue,
    C_SetAttributeValue,
    C_FindObjectsInit,
    C_FindObjects,
    C_FindObjectsFinal,
    C_EncryptInit,
    C_Encrypt,
    C_EncryptUpdate,
    C_EncryptFinal,
    C_DecryptInit,
    C_Decrypt,
    C_DecryptUpdate,
    C_DecryptFinal,
    C_DigestInit,
    C_Digest,
    C_DigestUpdate,
    C_DigestKey,
    C_DigestFinal,
    C_SignInit,
    C_Sign,
    C_SignUpdate,
    C_SignFinal,
    C_SignRecoverInit,
    C_SignRecover,
    C_VerifyInit,
    C_Verify,
    C_VerifyUpdate,
    C_VerifyFinal,
    C_VerifyRecoverInit,
    C_VerifyRecover,
    C_DigestEncryptUpdate,
    C_DecryptDigestUpdate,
    C_SignEncryptUpdate,
    C_DecryptVerifyUpdate,
    C_GenerateKey,
    C_GenerateKeyPair,
    C_WrapKey,
    C_UnwrapKey,
    C_DeriveKey,
    C_SeedRandom,
    C_GenerateRandom,
    C_GetFunctionStatus,
    C_CancelFunction,
    C_WaitForSlotEvent,
};

const FN_30_EXT: FnListV30Ext = FnListV30Ext {
    C_GetInterfaceList,
    C_GetInterface,
    C_LoginUser,
    C_SessionCancel,
    C_MessageEncryptInit,
    C_EncryptMessage,
    C_EncryptMessageBegin,
    C_EncryptMessageNext,
    C_MessageEncryptFinal,
    C_MessageDecryptInit,
    C_DecryptMessage,
    C_DecryptMessageBegin,
    C_DecryptMessageNext,
    C_MessageDecryptFinal,
    C_MessageSignInit,
    C_SignMessage,
    C_SignMessageBegin,
    C_SignMessageNext,
    C_MessageSignFinal,
    C_MessageVerifyInit,
    C_VerifyMessage,
    C_VerifyMessageBegin,
    C_VerifyMessageNext,
    C_MessageVerifyFinal,
};

const FN_32_EXT: FnListV32Ext = FnListV32Ext {
    C_EncapsulateKey,
    C_DecapsulateKey,
    C_VerifySignatureInit,
    C_VerifySignature,
    C_VerifySignatureUpdate,
    C_VerifySignatureFinal,
    C_GetSessionValidationFlags,
    C_AsyncComplete,
    C_AsyncGetID,
    C_AsyncJoin,
    C_WrapKeyAuthenticated,
    C_UnwrapKeyAuthenticated,
};

/// The exported v2.40 list — `version` is the Cryptoki version the list
/// complies with, per §5.4.
pub static FUNCTION_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: CK_VERSION { major: 2, minor: 40 },
    f: FN_240,
};

pub static FUNCTION_LIST_3_0: CK_FUNCTION_LIST_3_0 = CK_FUNCTION_LIST_3_0 {
    version: CK_VERSION { major: 3, minor: 0 },
    f: FN_240,
    f30: FN_30_EXT,
};

pub static FUNCTION_LIST_3_2: CK_FUNCTION_LIST_3_2 = CK_FUNCTION_LIST_3_2 {
    version: CK_VERSION { major: 3, minor: 2 },
    f: FN_240,
    f30: FN_30_EXT,
    f32: FN_32_EXT,
};

// ─────────────────────────────────────────────────────────────────────────
// Exported entry points (dlsym surface): C_GetFunctionList,
// C_GetInterfaceList, C_GetInterface — §5.4 pre-initialization surface.
// ─────────────────────────────────────────────────────────────────────────

/// §5.4 — returns the v2.40 `CK_FUNCTION_LIST`. Callable before
/// C_Initialize. The 3.0/3.2 lists are reachable via C_GetInterface.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetFunctionList(ppFunctionList: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    if ppFunctionList.is_null() {
        return rv(CKR_ARGUMENTS_BAD);
    }
    *ppFunctionList = &FUNCTION_LIST as *const CK_FUNCTION_LIST as CK_FUNCTION_LIST_PTR;
    rv(CKR_OK)
}

static INTERFACE_NAME: [u8; 8] = *b"PKCS 11\0";

/// CK_INTERFACE contains raw pointers into immutable statics — safe to
/// share across threads.
#[repr(transparent)]
struct SyncInterface(CK_INTERFACE);
unsafe impl Sync for SyncInterface {}

/// Interface records, default (highest version) first — C_GetInterface
/// with a NULL version returns the first name match.
static INTERFACES: [SyncInterface; 3] = [
    SyncInterface(CK_INTERFACE {
        pInterfaceName: &INTERFACE_NAME as *const u8 as CK_UTF8CHAR_PTR,
        pFunctionList: &FUNCTION_LIST_3_2 as *const CK_FUNCTION_LIST_3_2 as CK_VOID_PTR,
        flags: 0,
    }),
    SyncInterface(CK_INTERFACE {
        pInterfaceName: &INTERFACE_NAME as *const u8 as CK_UTF8CHAR_PTR,
        pFunctionList: &FUNCTION_LIST_3_0 as *const CK_FUNCTION_LIST_3_0 as CK_VOID_PTR,
        flags: 0,
    }),
    SyncInterface(CK_INTERFACE {
        pInterfaceName: &INTERFACE_NAME as *const u8 as CK_UTF8CHAR_PTR,
        pFunctionList: &FUNCTION_LIST as *const CK_FUNCTION_LIST as CK_VOID_PTR,
        flags: 0,
    }),
];

#[inline]
fn iface_version(i: &SyncInterface) -> CK_VERSION {
    // pFunctionList always begins with a CK_VERSION header.
    unsafe { *(i.0.pFunctionList as *const CK_VERSION) }
}

/// §5.5 — native C_GetInterfaceList: real CK_INTERFACE records whose
/// pFunctionList pointers reference the actual function-list statics
/// (unlike wasm32, where pFunctionList carries a CK_VERSION header only —
/// the JS shim is the function table there). Callable before C_Initialize.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetInterfaceList(
    pInterfacesList: CK_INTERFACE_PTR,
    pulCount: CK_ULONG_PTR,
) -> CK_RV {
    if pulCount.is_null() {
        return rv(CKR_ARGUMENTS_BAD);
    }
    let n = INTERFACES.len() as CK_ULONG;
    if pInterfacesList.is_null() {
        *pulCount = n;
        return rv(CKR_OK);
    }
    if *pulCount < n {
        *pulCount = n;
        return rv(CKR_BUFFER_TOO_SMALL);
    }
    for (i, ifc) in INTERFACES.iter().enumerate() {
        *pInterfacesList.add(i) = ifc.0;
    }
    *pulCount = n;
    rv(CKR_OK)
}

/// §5.5 — native C_GetInterface. NULL name/version match the default
/// ("PKCS 11", highest version = 3.2). Callable before C_Initialize.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetInterface(
    pInterfaceName: CK_UTF8CHAR_PTR,
    pVersion: *mut CK_VERSION,
    ppInterface: CK_INTERFACE_PTR_PTR,
    flags: CK_FLAGS,
) -> CK_RV {
    if ppInterface.is_null() {
        return rv(CKR_ARGUMENTS_BAD);
    }
    // Name must be "PKCS 11" (NUL-terminated) when supplied.
    if !pInterfaceName.is_null() {
        let got = std::slice::from_raw_parts(pInterfaceName, INTERFACE_NAME.len());
        if got != INTERFACE_NAME {
            *ppInterface = std::ptr::null_mut();
            return rv(CKR_FUNCTION_FAILED);
        }
    }
    for ifc in INTERFACES.iter() {
        if !pVersion.is_null() && iface_version(ifc) != *pVersion {
            continue;
        }
        // All requested flags must be supported by the interface.
        if (ifc.0.flags & flags) != flags {
            continue;
        }
        *ppInterface = &ifc.0 as *const CK_INTERFACE as CK_INTERFACE_PTR;
        return rv(CKR_OK);
    }
    *ppInterface = std::ptr::null_mut();
    rv(CKR_FUNCTION_FAILED)
}

// ─────────────────────────────────────────────────────────────────────────
// Tests (native only — the whole module is cfg'd out on wasm32)
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    const PTR: usize = size_of::<*const ()>();

    /// pkcs11.h slot counts, derived from pkcs11f.h's version guards:
    /// 2.40 = C_Initialize..C_WaitForSlotEvent = 68;
    /// 3.0 adds C_GetInterfaceList..C_MessageVerifyFinal = 92;
    /// 3.2 adds C_EncapsulateKey..C_UnwrapKeyAuthenticated = 104.
    #[test]
    fn function_list_slot_counts_and_layout() {
        // CK_VERSION (2 bytes) pads to one pointer before the first slot.
        assert_eq!(size_of::<CK_FUNCTION_LIST>(), PTR * (1 + 68));
        assert_eq!(size_of::<CK_FUNCTION_LIST_3_0>(), PTR * (1 + 92));
        assert_eq!(size_of::<CK_FUNCTION_LIST_3_2>(), PTR * (1 + 104));
        // Segment structs are pure pointer arrays (no internal padding).
        assert_eq!(size_of::<FnListV240>(), PTR * 68);
        assert_eq!(size_of::<FnListV30Ext>(), PTR * 24);
        assert_eq!(size_of::<FnListV32Ext>(), PTR * 12);
        // Native CK_INTERFACE: two pointers + CK_ULONG.
        assert_eq!(size_of::<CK_INTERFACE>(), PTR * 2 + size_of::<CK_ULONG>());
    }

    #[test]
    fn function_list_versions() {
        assert_eq!(FUNCTION_LIST.version, CK_VERSION { major: 2, minor: 40 });
        assert_eq!(FUNCTION_LIST_3_0.version, CK_VERSION { major: 3, minor: 0 });
        assert_eq!(FUNCTION_LIST_3_2.version, CK_VERSION { major: 3, minor: 2 });
    }

    /// Every slot of every list is a non-NULL function pointer.
    #[test]
    fn every_slot_non_null() {
        unsafe {
            let checks: [(*const u8, usize); 3] = [
                (&FUNCTION_LIST as *const _ as *const u8, 68),
                (&FUNCTION_LIST_3_0 as *const _ as *const u8, 92),
                (&FUNCTION_LIST_3_2 as *const _ as *const u8, 104),
            ];
            for (base, slots) in checks {
                let p = base.add(PTR) as *const usize; // skip version+padding
                for i in 0..slots {
                    assert_ne!(*p.add(i), 0, "slot {i} of {slots}-entry list is NULL");
                }
            }
        }
    }

    /// Full round-trip THROUGH the exported function-list pointers:
    /// C_GetFunctionList → C_Initialize(NULL) → C_GetInfo → C_OpenSession
    /// → C_GetTokenInfo → C_GetSessionInfo → C_CloseSession → C_Finalize.
    #[test]
    fn round_trip_through_function_list() {
        let _guard = crate::native::test_lock::acquire();
        unsafe {
            let mut pfl: CK_FUNCTION_LIST_PTR = std::ptr::null_mut();
            assert_eq!(C_GetFunctionList(&mut pfl), rv(CKR_OK));
            assert!(!pfl.is_null());
            let fl = &*pfl;
            assert_eq!(fl.version, CK_VERSION { major: 2, minor: 40 });

            // Other test modules may have left the engine initialized.
            if crate::state::is_initialized() {
                (fl.f.C_Finalize)(std::ptr::null_mut());
            }
            assert_eq!((fl.f.C_Initialize)(std::ptr::null_mut()), rv(CKR_OK));
            assert_eq!(
                (fl.f.C_Initialize)(std::ptr::null_mut()),
                rv(CKR_CRYPTOKI_ALREADY_INITIALIZED)
            );

            // C_GetInfo → native CK_INFO with widened flags.
            let mut info: CK_INFO = std::mem::zeroed();
            assert_eq!((fl.f.C_GetInfo)(&mut info), rv(CKR_OK));
            assert_eq!(info.cryptokiVersion, CK_VERSION { major: 3, minor: 2 });
            assert!(info.manufacturerID.starts_with(b"SoftHSMv3 Rust WASM"));
            assert_eq!(info.flags, 0);

            // C_OpenSession on slot 0 (created by C_Initialize).
            let mut session: CK_SESSION_HANDLE = 0;
            let flags = (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS;
            assert_eq!(
                (fl.f.C_OpenSession)(0, flags, std::ptr::null_mut(), None, &mut session),
                rv(CKR_OK)
            );
            assert_ne!(session, 0);

            // Narrowing guard: an impossible 64-bit session handle is
            // refused, not truncated.
            if size_of::<CK_ULONG>() > 4 {
                assert_eq!(
                    (fl.f.C_CloseSession)(CK_SESSION_HANDLE::MAX),
                    rv(CKR_SESSION_HANDLE_INVALID)
                );
            }

            // C_GetTokenInfo → native CK_TOKEN_INFO; the 32-bit
            // CK_UNAVAILABLE_INFORMATION sentinel must widen to ~0UL.
            let mut ti: CK_TOKEN_INFO = std::mem::zeroed();
            assert_eq!((fl.f.C_GetTokenInfo)(0, &mut ti), rv(CKR_OK));
            assert!(ti.label.starts_with(b"SoftHSM3-Rust"));
            assert_eq!(ti.ulMaxSessionCount, CK_UNAVAILABLE_INFORMATION_NATIVE);
            assert_eq!(ti.ulTotalPublicMemory, CK_UNAVAILABLE_INFORMATION_NATIVE);
            assert!(ti.ulSessionCount >= 1);
            assert_eq!(ti.hardwareVersion, CK_VERSION { major: 3, minor: 2 });

            // C_GetSessionInfo → native CK_SESSION_INFO.
            let mut si: CK_SESSION_INFO = std::mem::zeroed();
            assert_eq!((fl.f.C_GetSessionInfo)(session, &mut si), rv(CKR_OK));
            assert_eq!(si.slotID, 0);
            assert_eq!(si.flags & CKF_SERIAL_SESSION as CK_FLAGS, CKF_SERIAL_SESSION as CK_FLAGS);

            assert_eq!((fl.f.C_CloseSession)(session), rv(CKR_OK));
            assert_eq!((fl.f.C_Finalize)(std::ptr::null_mut()), rv(CKR_OK));
        }
    }

    /// Two-call convention through the adapter: C_GetMechanismList with a
    /// native CK_ULONG count (out-param length translation both ways).
    #[test]
    fn mechanism_list_two_call_translation() {
        let _guard = crate::native::test_lock::acquire();
        unsafe {
            crate::state::set_initialized(true);
            crate::state::ensure_slot(0);

            // Size query.
            let mut count: CK_ULONG = 0;
            assert_eq!(
                C_GetMechanismList(0, std::ptr::null_mut(), &mut count),
                rv(CKR_OK)
            );
            assert_eq!(count as usize, SUPPORTED_MECHS.len());

            // Too-small buffer → CKR_BUFFER_TOO_SMALL, count corrected.
            let mut small = vec![0 as CK_MECHANISM_TYPE; 1];
            let mut small_count: CK_ULONG = 1;
            assert_eq!(
                C_GetMechanismList(0, small.as_mut_ptr(), &mut small_count),
                rv(CKR_BUFFER_TOO_SMALL)
            );
            assert_eq!(small_count as usize, SUPPORTED_MECHS.len());

            // Full fetch: every entry widened from the engine's u32 table.
            let mut list = vec![0 as CK_MECHANISM_TYPE; count as usize];
            let mut full_count: CK_ULONG = count;
            assert_eq!(
                C_GetMechanismList(0, list.as_mut_ptr(), &mut full_count),
                rv(CKR_OK)
            );
            assert_eq!(full_count, count);
            for (got, want) in list.iter().zip(SUPPORTED_MECHS.iter()) {
                assert_eq!(*got, *want as CK_MECHANISM_TYPE);
            }

            // C_GetMechanismInfo widening.
            let mut mi: CK_MECHANISM_INFO = std::mem::zeroed();
            assert_eq!(
                C_GetMechanismInfo(0, CKM_SHA256 as CK_MECHANISM_TYPE, &mut mi),
                rv(CKR_OK)
            );
            assert_eq!(mi.flags, 0x400); // CKF_DIGEST
        }
    }

    /// Data-path crypto through the 3.2 list pointers: parameterless
    /// CK_MECHANISM translation + two-call output length on C_Digest.
    #[test]
    fn digest_through_pointers() {
        let _guard = crate::native::test_lock::acquire();
        unsafe {
            // Reach the 3.2 list the way a consumer would: C_GetInterface.
            let mut pifc: CK_INTERFACE_PTR = std::ptr::null_mut();
            assert_eq!(
                C_GetInterface(std::ptr::null_mut(), std::ptr::null_mut(), &mut pifc, 0),
                rv(CKR_OK)
            );
            let fl = &*((*pifc).pFunctionList as *const CK_FUNCTION_LIST_3_2);
            assert_eq!(fl.version, CK_VERSION { major: 3, minor: 2 });

            if crate::state::is_initialized() {
                (fl.f.C_Finalize)(std::ptr::null_mut());
            }
            assert_eq!((fl.f.C_Initialize)(std::ptr::null_mut()), rv(CKR_OK));
            let mut session: CK_SESSION_HANDLE = 0;
            let flags = (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS;
            assert_eq!(
                (fl.f.C_OpenSession)(0, flags, std::ptr::null_mut(), None, &mut session),
                rv(CKR_OK)
            );

            let mut mech = CK_MECHANISM {
                mechanism: CKM_SHA256 as CK_MECHANISM_TYPE,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            };
            assert_eq!((fl.f.C_DigestInit)(session, &mut mech), rv(CKR_OK));

            let data = b"abc";
            // Two-call: size query first.
            let mut dlen: CK_ULONG = 0;
            assert_eq!(
                (fl.f.C_Digest)(
                    session,
                    data.as_ptr() as *mut u8,
                    data.len() as CK_ULONG,
                    std::ptr::null_mut(),
                    &mut dlen
                ),
                rv(CKR_OK)
            );
            assert_eq!(dlen, 32);
            let mut digest = vec![0u8; dlen as usize];
            assert_eq!(
                (fl.f.C_Digest)(
                    session,
                    data.as_ptr() as *mut u8,
                    data.len() as CK_ULONG,
                    digest.as_mut_ptr(),
                    &mut dlen
                ),
                rv(CKR_OK)
            );
            assert_eq!(dlen, 32);
            // SHA-256("abc") — FIPS 180-4 known answer.
            assert_eq!(
                digest[..4],
                [0xba, 0x78, 0x16, 0xbf],
                "SHA-256(\"abc\") prefix mismatch: {digest:02x?}"
            );

            (fl.f.C_CloseSession)(session);
            (fl.f.C_Finalize)(std::ptr::null_mut());
        }
    }

    /// Interface lookup by name/version returns the right list (and real
    /// pFunctionList pointers — the native cfg-split of round-1's
    /// version-header-only wasm behavior).
    #[test]
    fn interface_lookup_by_name_and_version() {
        unsafe {
            // Two-call list.
            let mut count: CK_ULONG = 0;
            assert_eq!(C_GetInterfaceList(std::ptr::null_mut(), &mut count), rv(CKR_OK));
            assert_eq!(count, 3);
            let mut too_small = [std::mem::zeroed::<CK_INTERFACE>(); 1];
            let mut small_count: CK_ULONG = 1;
            assert_eq!(
                C_GetInterfaceList(too_small.as_mut_ptr(), &mut small_count),
                rv(CKR_BUFFER_TOO_SMALL)
            );
            assert_eq!(small_count, 3);
            let mut ifaces = [std::mem::zeroed::<CK_INTERFACE>(); 3];
            assert_eq!(C_GetInterfaceList(ifaces.as_mut_ptr(), &mut count), rv(CKR_OK));
            assert_eq!(
                ifaces[0].pFunctionList,
                &FUNCTION_LIST_3_2 as *const _ as CK_VOID_PTR
            );
            assert_eq!(
                ifaces[2].pFunctionList,
                &FUNCTION_LIST as *const _ as CK_VOID_PTR
            );

            // Default lookup → 3.2.
            let mut p: CK_INTERFACE_PTR = std::ptr::null_mut();
            assert_eq!(
                C_GetInterface(std::ptr::null_mut(), std::ptr::null_mut(), &mut p, 0),
                rv(CKR_OK)
            );
            assert_eq!((*p).pFunctionList, &FUNCTION_LIST_3_2 as *const _ as CK_VOID_PTR);

            // Explicit name + version 3.0 → the 3.0 list.
            let mut name = *b"PKCS 11\0";
            let mut v30 = CK_VERSION { major: 3, minor: 0 };
            assert_eq!(C_GetInterface(name.as_mut_ptr(), &mut v30, &mut p, 0), rv(CKR_OK));
            assert_eq!((*p).pFunctionList, &FUNCTION_LIST_3_0 as *const _ as CK_VOID_PTR);
            assert_eq!((&*((*p).pFunctionList as *const CK_FUNCTION_LIST_3_0)).version, v30);

            // Version 2.40 → the legacy list.
            let mut v240 = CK_VERSION { major: 2, minor: 40 };
            assert_eq!(C_GetInterface(name.as_mut_ptr(), &mut v240, &mut p, 0), rv(CKR_OK));
            assert_eq!((*p).pFunctionList, &FUNCTION_LIST as *const _ as CK_VOID_PTR);

            // Unknown version / wrong name → CKR_FUNCTION_FAILED.
            let mut v99 = CK_VERSION { major: 9, minor: 9 };
            assert_eq!(
                C_GetInterface(name.as_mut_ptr(), &mut v99, &mut p, 0),
                rv(CKR_FUNCTION_FAILED)
            );
            let mut bad = *b"Vendor X\0";
            assert_eq!(
                C_GetInterface(bad.as_mut_ptr(), std::ptr::null_mut(), &mut p, 0),
                rv(CKR_FUNCTION_FAILED)
            );
        }
    }

    /// 64-bit hosts: embedded mechanism-parameter pointers cannot be
    /// represented in the engine's 32-bit linear-memory ABI — the shim
    /// must refuse (CKR_FUNCTION_FAILED) instead of truncating into UB.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn embedded_pointer_marshaled_on_64_bit() {
        let _guard = crate::native::test_lock::acquire();
        unsafe {
            crate::state::set_initialized(true);
            crate::state::ensure_slot(0);
            let mut session: CK_SESSION_HANDLE = 0;
            let flags = (CKF_SERIAL_SESSION | CKF_RW_SESSION) as CK_FLAGS;
            assert_eq!(
                C_OpenSession(0, flags, std::ptr::null_mut(), None, &mut session),
                rv(CKR_OK)
            );
            let mut iv = [0u8; 16];
            let mut mech = CK_MECHANISM {
                mechanism: CKM_SHA256 as CK_MECHANISM_TYPE,
                pParameter: iv.as_mut_ptr() as CK_VOID_PTR,
                ulParameterLen: iv.len() as CK_ULONG,
            };
            // Native 64-bit re-plumb: a non-NULL mechanism parameter carrying a
            // 64-bit stack pointer is now marshaled at native width (no longer
            // refused or truncated), so the operation initialises successfully.
            assert_eq!(
                C_DigestInit(session, &mut mech),
                rv(CKR_OK),
                "64-bit stack pointer in pParameter must be handled, not refused"
            );
            C_SessionCancel(session, 0xFFFF_FFFF as CK_FLAGS); // clear digest op
            // NULL-parameter mechanisms translate exactly.
            mech.pParameter = std::ptr::null_mut();
            mech.ulParameterLen = 0;
            assert_eq!(C_DigestInit(session, &mut mech), rv(CKR_OK));
            C_SessionCancel(session, 0xFFFF_FFFF as CK_FLAGS); // clear digest op
            C_CloseSession(session);
        }
    }
}
