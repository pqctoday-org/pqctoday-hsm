//! Native `PQCTODAY_KEY_REPLICATION_1_0` function list (spec §2).
//!
//! Separately versioned and discovered only through the standard
//! `C_GetInterface` / `C_GetInterfaceList` — never appended to, and never
//! changing, `CK_FUNCTION_LIST_3_2`. Discovery additionally requires the
//! educational profile to have been selected at runtime
//! ([`super::select_educational_profile`]); see `ck_abi::C_GetInterface`.
//!
//! Argument precedence follows spec §9: library initialized, ABI arguments,
//! then the engine operation's own ordering.

use crate::ck_abi::*;
use crate::constants::*;

fn rv(code: u32) -> CK_RV {
    code as CK_RV
}

fn handle(h: CK_ULONG) -> Option<u32> {
    u32::try_from(h).ok()
}

/// Read a native CK_ATTRIBUTE template into owned `(type, value)` pairs.
unsafe fn template(p: CK_ATTRIBUTE_PTR, n: CK_ULONG) -> Result<Vec<(u32, Vec<u8>)>, u32> {
    if n == 0 {
        return Ok(Vec::new());
    }
    if p.is_null() || n > 64 {
        return Err(CKR_ARGUMENTS_BAD);
    }
    let mut out = Vec::with_capacity(n as usize);
    for i in 0..n as usize {
        let a = &*p.add(i);
        let t = u32::try_from(a.attrType).map_err(|_| CKR_ATTRIBUTE_TYPE_INVALID)?;
        let len = a.ulValueLen as usize;
        if len > 4096 || (len > 0 && a.pValue.is_null()) {
            return Err(CKR_ARGUMENTS_BAD);
        }
        let v = if len == 0 { Vec::new() } else { std::slice::from_raw_parts(a.pValue as *const u8, len).to_vec() };
        out.push((t, v));
    }
    Ok(out)
}

unsafe fn input<'a>(p: CK_BYTE_PTR, n: CK_ULONG) -> Result<&'a [u8], u32> {
    if p.is_null() || n == 0 {
        return Err(CKR_ARGUMENTS_BAD);
    }
    Ok(std::slice::from_raw_parts(p as *const u8, n as usize))
}

unsafe fn write_out(out: CK_BYTE_PTR, pul: CK_ULONG_PTR, bytes: &[u8]) -> CK_RV {
    if (*pul as usize) < bytes.len() {
        *pul = bytes.len() as CK_ULONG;
        return rv(CKR_BUFFER_TOO_SMALL);
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
    *pul = bytes.len() as CK_ULONG;
    rv(CKR_OK)
}

pub unsafe extern "C" fn C_PQCTODAY_CreateReplicationPackage(
    hSourceSession: CK_SESSION_HANDLE,
    hSourceKey: CK_OBJECT_HANDLE,
    pRequest: CK_BYTE_PTR,
    ulRequestLen: CK_ULONG,
    pPackage: CK_BYTE_PTR,
    pulPackageLen: CK_ULONG_PTR,
) -> CK_RV {
    if !crate::state::is_initialized() {
        return rv(CKR_CRYPTOKI_NOT_INITIALIZED);
    }
    if pulPackageLen.is_null() {
        return rv(CKR_ARGUMENTS_BAD);
    }
    let request = match input(pRequest, ulRequestLen) {
        Ok(r) => r,
        Err(e) => return rv(e),
    };
    let (Some(s), Some(k)) = (handle(hSourceSession), handle(hSourceKey)) else {
        return rv(CKR_SESSION_HANDLE_INVALID);
    };
    let len = match super::replication_package_length(s, k, request) {
        Ok(l) => l,
        Err(e) => return rv(e),
    };
    if pPackage.is_null() {
        *pulPackageLen = len as CK_ULONG;
        return rv(CKR_OK);
    }
    if (*pulPackageLen as usize) < len {
        *pulPackageLen = len as CK_ULONG;
        return rv(CKR_BUFFER_TOO_SMALL);
    }
    match super::create_replication_package(s, k, request) {
        // A retry after a too-small buffer returns the byte-identical
        // cached package (spec §3.1).
        Ok(pkg) => write_out(pPackage, pulPackageLen, &pkg),
        Err(e) => rv(e),
    }
}

pub unsafe extern "C" fn C_PQCTODAY_ImportReplicationPackage(
    hDestinationSession: CK_SESSION_HANDLE,
    pPackage: CK_BYTE_PTR,
    ulPackageLen: CK_ULONG,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulAttributeCount: CK_ULONG,
    phInstalledKey: CK_OBJECT_HANDLE_PTR,
    pReceipt: CK_BYTE_PTR,
    pulReceiptLen: CK_ULONG_PTR,
) -> CK_RV {
    if !crate::state::is_initialized() {
        return rv(CKR_CRYPTOKI_NOT_INITIALIZED);
    }
    if pulReceiptLen.is_null() {
        return rv(CKR_ARGUMENTS_BAD);
    }
    // Spec §3.2: phInstalledKey is NULL on the sizing call, non-NULL on execution.
    if pReceipt.is_null() != phInstalledKey.is_null() {
        return rv(CKR_ARGUMENTS_BAD);
    }
    let package = match input(pPackage, ulPackageLen) {
        Ok(p) => p,
        Err(e) => return rv(e),
    };
    let tmpl = match template(pTemplate, ulAttributeCount) {
        Ok(t) => t,
        Err(e) => return rv(e),
    };
    let Some(s) = handle(hDestinationSession) else {
        return rv(CKR_SESSION_HANDLE_INVALID);
    };
    let len = match super::replication_receipt_length(s, package) {
        Ok(l) => l,
        Err(e) => return rv(e),
    };
    if pReceipt.is_null() {
        *pulReceiptLen = len as CK_ULONG;
        return rv(CKR_OK);
    }
    // A too-small receipt buffer fails before any reservation.
    if (*pulReceiptLen as usize) < len {
        *pulReceiptLen = len as CK_ULONG;
        return rv(CKR_BUFFER_TOO_SMALL);
    }
    match super::import_replication_package(s, package, &tmpl) {
        Ok((h, receipt)) => {
            *phInstalledKey = h as CK_OBJECT_HANDLE;
            write_out(pReceipt, pulReceiptLen, &receipt)
        }
        Err(e) => rv(e),
    }
}

pub unsafe extern "C" fn C_PQCTODAY_CloneKey(
    hSourceSession: CK_SESSION_HANDLE,
    hSourceKey: CK_OBJECT_HANDLE,
    hDestinationSession: CK_SESSION_HANDLE,
    pRequest: CK_BYTE_PTR,
    ulRequestLen: CK_ULONG,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulAttributeCount: CK_ULONG,
    phInstalledKey: CK_OBJECT_HANDLE_PTR,
    pReceipt: CK_BYTE_PTR,
    pulReceiptLen: CK_ULONG_PTR,
) -> CK_RV {
    if !crate::state::is_initialized() {
        return rv(CKR_CRYPTOKI_NOT_INITIALIZED);
    }
    if pulReceiptLen.is_null() || pReceipt.is_null() != phInstalledKey.is_null() {
        return rv(CKR_ARGUMENTS_BAD);
    }
    let request = match input(pRequest, ulRequestLen) {
        Ok(r) => r,
        Err(e) => return rv(e),
    };
    let tmpl = match template(pTemplate, ulAttributeCount) {
        Ok(t) => t,
        Err(e) => return rv(e),
    };
    let (Some(s), Some(k), Some(d)) = (handle(hSourceSession), handle(hSourceKey), handle(hDestinationSession)) else {
        return rv(CKR_SESSION_HANDLE_INVALID);
    };
    let len = match super::clone_receipt_length(s, k, request, d) {
        Ok(l) => l,
        Err(e) => return rv(e),
    };
    if pReceipt.is_null() {
        *pulReceiptLen = len as CK_ULONG;
        return rv(CKR_OK);
    }
    if (*pulReceiptLen as usize) < len {
        *pulReceiptLen = len as CK_ULONG;
        return rv(CKR_BUFFER_TOO_SMALL);
    }
    match super::clone_key(s, k, d, request, &tmpl) {
        Ok((h, receipt)) => {
            *phInstalledKey = h as CK_OBJECT_HANDLE;
            write_out(pReceipt, pulReceiptLen, &receipt)
        }
        Err(e) => rv(e),
    }
}

/// The version-1 vendor function list (spec §2).
pub static REPLICATION_FUNCTION_LIST: PQCTODAY_KEY_REPLICATION_FUNCTION_LIST_1_0 =
    PQCTODAY_KEY_REPLICATION_FUNCTION_LIST_1_0 {
        version: CK_VERSION { major: 1, minor: 0 },
        C_PQCTODAY_CreateReplicationPackage,
        C_PQCTODAY_ImportReplicationPackage,
        C_PQCTODAY_CloneKey,
    };
