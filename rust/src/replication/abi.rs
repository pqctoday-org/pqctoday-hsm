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

// ── Admin addendum §2.1 / §2.2 ─────────────────────────────────────────────

/// Fixed-size output: NULL buffer → the length, no randomness or mutation;
/// too small → `CKR_BUFFER_TOO_SMALL` before any work.
unsafe fn fixed_out(out: CK_BYTE_PTR, pul: CK_ULONG_PTR, len: usize) -> Option<CK_RV> {
    if out.is_null() {
        *pul = len as CK_ULONG;
        return Some(rv(CKR_OK));
    }
    if (*pul as usize) < len {
        *pul = len as CK_ULONG;
        return Some(rv(CKR_BUFFER_TOO_SMALL));
    }
    None
}

pub unsafe extern "C" fn C_PQCTODAY_AdminIssueNonce(hSOSession: CK_SESSION_HANDLE, pNonce: CK_BYTE_PTR, pulNonceLen: CK_ULONG_PTR) -> CK_RV {
    if !crate::state::is_initialized() {
        return rv(CKR_CRYPTOKI_NOT_INITIALIZED);
    }
    if pulNonceLen.is_null() {
        return rv(CKR_ARGUMENTS_BAD);
    }
    let Some(s) = handle(hSOSession) else {
        return rv(CKR_SESSION_HANDLE_INVALID);
    };
    if let Some(r) = fixed_out(pNonce, pulNonceLen, 32) {
        return r;
    }
    match super::admin::issue_nonce(s) {
        Ok(n) => write_out(pNonce, pulNonceLen, &n),
        Err(e) => rv(e),
    }
}

pub unsafe extern "C" fn C_PQCTODAY_AdminExecute(
    hSOSession: CK_SESSION_HANDLE,
    pSignedRequest: CK_BYTE_PTR,
    ulSignedRequestLen: CK_ULONG,
    pReceipt: CK_BYTE_PTR,
    pulReceiptLen: CK_ULONG_PTR,
) -> CK_RV {
    if !crate::state::is_initialized() {
        return rv(CKR_CRYPTOKI_NOT_INITIALIZED);
    }
    if pulReceiptLen.is_null() {
        return rv(CKR_ARGUMENTS_BAD);
    }
    let req = match input(pSignedRequest, ulSignedRequestLen) {
        Ok(r) => r,
        Err(e) => return rv(e),
    };
    let Some(s) = handle(hSOSession) else {
        return rv(CKR_SESSION_HANDLE_INVALID);
    };
    let len = match super::admin::execute_len(s, req) {
        Ok(l) => l,
        Err(e) => return rv(e),
    };
    if let Some(r) = fixed_out(pReceipt, pulReceiptLen, len) {
        return r;
    }
    match super::admin::execute(s, req) {
        Ok(receipt) => write_out(pReceipt, pulReceiptLen, &receipt),
        Err(e) => rv(e),
    }
}

pub unsafe extern "C" fn C_PQCTODAY_IssueSourceChallenge(hUserSession: CK_SESSION_HANDLE, pChallenge: CK_BYTE_PTR, pulChallengeLen: CK_ULONG_PTR) -> CK_RV {
    if !crate::state::is_initialized() {
        return rv(CKR_CRYPTOKI_NOT_INITIALIZED);
    }
    if pulChallengeLen.is_null() {
        return rv(CKR_ARGUMENTS_BAD);
    }
    let Some(s) = handle(hUserSession) else {
        return rv(CKR_SESSION_HANDLE_INVALID);
    };
    if let Some(r) = fixed_out(pChallenge, pulChallengeLen, 32) {
        return r;
    }
    match super::issue_source_challenge(s) {
        Ok(c) => write_out(pChallenge, pulChallengeLen, &c),
        Err(e) => rv(e),
    }
}

pub unsafe extern "C" fn C_PQCTODAY_BeginReceive(
    hUserSession: CK_SESSION_HANDLE,
    pBeginReceive: CK_BYTE_PTR,
    ulBeginReceiveLen: CK_ULONG,
    pRequest: CK_BYTE_PTR,
    pulRequestLen: CK_ULONG_PTR,
) -> CK_RV {
    if !crate::state::is_initialized() {
        return rv(CKR_CRYPTOKI_NOT_INITIALIZED);
    }
    if pulRequestLen.is_null() {
        return rv(CKR_ARGUMENTS_BAD);
    }
    let der = match input(pBeginReceive, ulBeginReceiveLen) {
        Ok(d) => d,
        Err(e) => return rv(e),
    };
    let Some(s) = handle(hUserSession) else {
        return rv(CKR_SESSION_HANDLE_INVALID);
    };
    let (op, chal, domain, policy) = match super::admin::BeginReceive::parse(der) {
        Ok(v) => v,
        Err(e) => return rv(e),
    };
    let len = match super::begin_receive_len(s, op, &chal, &domain, &policy) {
        Ok(l) => l,
        Err(e) => return rv(e),
    };
    if let Some(r) = fixed_out(pRequest, pulRequestLen, len) {
        return r;
    }
    match super::begin_receive(s, op, &chal, &domain, &policy) {
        Ok(req) => write_out(pRequest, pulRequestLen, &req),
        Err(e) => rv(e),
    }
}

pub unsafe extern "C" fn C_PQCTODAY_CancelReceive(hUserSession: CK_SESSION_HANDLE, pTransactionID: CK_BYTE_PTR, ulTransactionIDLen: CK_ULONG) -> CK_RV {
    if !crate::state::is_initialized() {
        return rv(CKR_CRYPTOKI_NOT_INITIALIZED);
    }
    let txid: [u8; 32] = match input(pTransactionID, ulTransactionIDLen).map(|t| t.try_into()) {
        Ok(Ok(t)) => t,
        _ => return rv(CKR_ARGUMENTS_BAD),
    };
    let Some(s) = handle(hUserSession) else {
        return rv(CKR_SESSION_HANDLE_INVALID);
    };
    match super::cancel_receive(s, &txid) {
        Ok(()) => rv(CKR_OK),
        Err(e) => rv(e),
    }
}

pub unsafe extern "C" fn C_PQCTODAY_AttestKey(
    hUserSession: CK_SESSION_HANDLE,
    hKey: CK_OBJECT_HANDLE,
    pChallenge: CK_BYTE_PTR,
    ulChallengeLen: CK_ULONG,
    pEvidence: CK_BYTE_PTR,
    pulEvidenceLen: CK_ULONG_PTR,
) -> CK_RV {
    if !crate::state::is_initialized() {
        return rv(CKR_CRYPTOKI_NOT_INITIALIZED);
    }
    if pulEvidenceLen.is_null() {
        return rv(CKR_ARGUMENTS_BAD);
    }
    let chal: [u8; 32] = match input(pChallenge, ulChallengeLen).map(|c| c.try_into()) {
        Ok(Ok(c)) => c,
        _ => return rv(CKR_ARGUMENTS_BAD),
    };
    let (Some(s), Some(k)) = (handle(hUserSession), handle(hKey)) else {
        return rv(CKR_SESSION_HANDLE_INVALID);
    };
    let len = match super::evidence::attest_key_len(s, k, &chal) {
        Ok(l) => l,
        Err(e) => return rv(e),
    };
    if let Some(r) = fixed_out(pEvidence, pulEvidenceLen, len) {
        return r;
    }
    match super::attest_key(s, k, &chal) {
        Ok(ev) => write_out(pEvidence, pulEvidenceLen, &ev),
        Err(e) => rv(e),
    }
}

/// Admin addendum §2.1 function list.
pub static ADMIN_FUNCTION_LIST: PQCTODAY_KEY_REPLICATION_ADMIN_FUNCTION_LIST_1_0 = PQCTODAY_KEY_REPLICATION_ADMIN_FUNCTION_LIST_1_0 {
    version: CK_VERSION { major: 1, minor: 0 },
    C_PQCTODAY_AdminIssueNonce,
    C_PQCTODAY_AdminExecute,
};

/// Admin addendum §2.2 function list.
pub static CEREMONY_FUNCTION_LIST: PQCTODAY_KEY_REPLICATION_CEREMONY_FUNCTION_LIST_1_0 = PQCTODAY_KEY_REPLICATION_CEREMONY_FUNCTION_LIST_1_0 {
    version: CK_VERSION { major: 1, minor: 0 },
    C_PQCTODAY_IssueSourceChallenge,
    C_PQCTODAY_BeginReceive,
    C_PQCTODAY_CancelReceive,
    C_PQCTODAY_AttestKey,
};
