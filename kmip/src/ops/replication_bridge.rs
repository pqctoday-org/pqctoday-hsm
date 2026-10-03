//! KMIP 3.0 PKCS#11-operation (0x33) binding for protected key replication.
//!
//! PQCTODAY EDUCATIONAL TEST ONLY — compiled only with `--features educational-replication`
//! and inert until the server selects the educational profile (`--educational-replication`).
//! Status: **pre-ceremony-ABI** (engine owner 7f, 2026-10-03). The v1 interface is mapped
//! as specified in the admin/ceremony addendum §6; the user-level ceremony calls use a
//! TEST interface name and call the existing Rust functions directly. That test interface is
//! replaced by `PQCTODAY_KEY_REPLICATION_CEREMONY_1_0` shims before this branch merges anywhere.
//!
//! Rules (7f conditions + addendum §6):
//! - every call runs in the caller's USER R/W session (`resolve_tenant_session`); the engine
//!   enforces the role, and no SO operation is reachable through this module;
//! - engine DER (requests, packages, receipts, evidence) is passed through UNPARSED — the engine
//!   bounds and strictly parses it; only the small `KeyCall` wrapper is decoded here, strictly;
//! - keys are referenced by `CKA_UNIQUE_ID`, resolved inside the session, exactly one match;
//! - `CloneKey` is not offered: it needs both sessions in one module, never true over KMIP.

use std::sync::Mutex;

use softhsmrustv3::constants::{CKA_UNIQUE_ID, CKR_OK};
use softhsmrustv3::replication as repl;

pub const IFACE_V1: &str = "PQCTODAY_KEY_REPLICATION_1_0";
/// Pre-ABI test interface (7f): removed when the CEREMONY_1_0 shims land.
pub const IFACE_CEREMONY_TEST: &str = "PQCTODAY_KEY_REPLICATION_EDU_CEREMONY_TEST";

// PKCS#11 return codes used here (values from pkcs11t.h).
const CKR_ARGUMENTS_BAD: u32 = 0x0000_0007;
const CKR_FUNCTION_NOT_SUPPORTED: u32 = 0x0000_0054;
const CKR_KEY_HANDLE_INVALID: u32 = 0x0000_0060;
const CKR_DATA_INVALID: u32 = 0x0000_0020;
const CKR_USER_NOT_LOGGED_IN: u32 = 0x0000_0101;

/// Maximum Input Parameters accepted before anything else (base §10 package bound + wrapper).
const MAX_INPUT: usize = 256 * 1024 + 64;

/// The engine's find operation is per-session state, and KMIP connections share one engine
/// session in single-tenant mode, so key lookups are serialised.
static FIND_LOCK: Mutex<()> = Mutex::new(());

/// True when `interface` names one of the replication interfaces this build serves.
pub fn handles(interface: Option<&str>) -> bool {
    matches!(interface, Some(IFACE_V1) | Some(IFACE_CEREMONY_TEST))
}

/// Dispatch one call. `function` is the KMIP `PKCS#11 Function` value, which KMIP 3.0 §11.39
/// defines as the **1-based** offset in the function list (review A-06), so ordinal = value − 1.
/// Returns `(CK_RV, output)`.
pub fn dispatch(engine_session: Result<u32, ()>, interface: &str, function: u32, input: &[u8]) -> (u32, Option<Vec<u8>>) {
    let Some(ordinal) = function.checked_sub(1) else {
        return (CKR_ARGUMENTS_BAD, None);
    };
    if !repl::educational_profile_selected() {
        return (CKR_FUNCTION_NOT_SUPPORTED, None);
    }
    let Ok(s) = engine_session else {
        return (CKR_USER_NOT_LOGGED_IN, None);
    };
    if input.len() > MAX_INPUT {
        return (CKR_DATA_INVALID, None);
    }
    let r = match (interface, ordinal) {
        // v1: 0 CreateReplicationPackage — Input = DER KeyCall { uid, request }.
        (IFACE_V1, 0) => key_call(input).and_then(|(uid, request)| {
            let h = by_uid(s, uid)?;
            repl::create_replication_package(s, h, request)
        }),
        // v1: 1 ImportReplicationPackage — Input = package DER; Output = receipt DER.
        (IFACE_V1, 1) => repl::import_replication_package(s, input, &[]).map(|(_h, receipt)| receipt),
        // v1: 2 CloneKey — not meaningful over a network transport.
        (IFACE_V1, 2) => Err(CKR_FUNCTION_NOT_SUPPORTED),
        // test 0 IssueSourceChallenge — no input; Output = 32 bytes.
        (IFACE_CEREMONY_TEST, 0) if input.is_empty() => repl::issue_source_challenge(s).map(|c| c.to_vec()),
        // test 1 BeginReceive — Input = op(1) ‖ sourceChallenge(32) ‖ domainID(32) ‖ policyID(48).
        (IFACE_CEREMONY_TEST, 1) if input.len() == 113 => {
            let op = match input[0] {
                0 => repl::asn1::Operation::LiveClone,
                1 => repl::asn1::Operation::OfflineBackup,
                2 => repl::asn1::Operation::Restore,
                _ => return (CKR_ARGUMENTS_BAD, None),
            };
            let chal: [u8; 32] = input[1..33].try_into().unwrap();
            let domain: [u8; 32] = input[33..65].try_into().unwrap();
            let policy: [u8; 48] = input[65..113].try_into().unwrap();
            repl::begin_receive(s, op, &chal, &domain, &policy)
        }
        // test 2 CancelReceive — Input = transactionID(32).
        (IFACE_CEREMONY_TEST, 2) if input.len() == 32 => {
            repl::cancel_receive(s, input.try_into().unwrap()).map(|()| Vec::new())
        }
        // test 3 AttestKey — Input = DER KeyCall { uid, challenge(32) }; Output = evidence DER.
        (IFACE_CEREMONY_TEST, 3) => key_call(input).and_then(|(uid, chal)| {
            let chal: [u8; 32] = chal.try_into().map_err(|_| CKR_ARGUMENTS_BAD)?;
            repl::evidence::attest_key(s, by_uid(s, uid)?, &chal)
        }),
        (IFACE_V1, _) | (IFACE_CEREMONY_TEST, _) => Err(CKR_ARGUMENTS_BAD),
        _ => Err(CKR_FUNCTION_NOT_SUPPORTED),
    };
    match r {
        Ok(out) => (CKR_OK, Some(out)),
        Err(rv) => (rv, None),
    }
}

/// Exactly one object visible to `s` with this `CKA_UNIQUE_ID`, else `CKR_KEY_HANDLE_INVALID`.
fn by_uid(s: u32, uid: &[u8]) -> Result<u32, u32> {
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

/// Strict DER: `SEQUENCE { keyUniqueID UTF8String (SIZE(36)), payload OCTET STRING }`,
/// definite minimal lengths, nothing trailing. Returns `(uid, payload)`.
fn key_call(der: &[u8]) -> Result<(&[u8], &[u8]), u32> {
    let bad = CKR_DATA_INVALID;
    let (tag, body, rest) = tlv(der).ok_or(bad)?;
    if tag != 0x30 || !rest.is_empty() {
        return Err(bad);
    }
    let (t1, uid, rest) = tlv(body).ok_or(bad)?;
    let (t2, payload, rest) = tlv(rest).ok_or(bad)?;
    if t1 != 0x0c || uid.len() != 36 || t2 != 0x04 || !rest.is_empty() {
        return Err(bad);
    }
    Ok((uid, payload))
}

/// One DER TLV with a minimal definite length (short form < 128; long form 1–3 octets, no
/// leading zero, value ≥ 128). Returns `(tag, value, remainder)`.
fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, b) = b.split_first()?;
    let (&first, b) = b.split_first()?;
    let (len, b) = if first < 0x80 {
        (first as usize, b)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 3 || b.len() < n || b[0] == 0 {
            return None;
        }
        let len = b[..n].iter().fold(0usize, |a, &x| (a << 8) | x as usize);
        if len < 0x80 {
            return None;
        }
        (len, &b[n..])
    };
    if b.len() < len {
        return None;
    }
    Some((tag, &b[..len], &b[len..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(tag: u8, v: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        match v.len() {
            n if n < 0x80 => out.push(n as u8),
            n if n < 0x100 => out.extend([0x81, n as u8]),
            n if n < 0x10000 => out.extend([0x82, (n >> 8) as u8, n as u8]),
            n => out.extend([0x83, (n >> 16) as u8, (n >> 8) as u8, n as u8]),
        }
        out.extend_from_slice(v);
        out
    }

    fn call(uid: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut body = enc(0x0c, uid);
        body.extend(enc(0x04, payload));
        enc(0x30, &body)
    }

    #[test]
    fn key_call_round_trips_and_is_strict() {
        let uid = [b'a'; 36];
        let payload = vec![7u8; 300];
        let der = call(&uid, &payload);
        assert_eq!(key_call(&der).unwrap(), (&uid[..], &payload[..]));
        // trailing byte, wrong uid length, wrong tags, non-minimal length
        let mut t = der.clone();
        t.push(0);
        assert!(key_call(&t).is_err());
        assert!(key_call(&call(&[b'a'; 35], &payload)).is_err());
        let mut wrong = der.clone();
        wrong[0] = 0x31;
        assert!(key_call(&wrong).is_err());
        assert!(tlv(&[0x04, 0x81, 0x05, 1, 2, 3, 4, 5]).is_none(), "long form for a short length");
        assert!(tlv(&[0x04, 0x82, 0x00, 0x90]).is_none(), "leading zero length octet");
    }

    #[test]
    fn refuses_unless_the_educational_profile_is_selected() {
        repl::clear_profile();
        assert_eq!(dispatch(Ok(1), IFACE_V1, 2, b"x").0, CKR_FUNCTION_NOT_SUPPORTED);
    }

    #[test]
    fn kmip_function_value_zero_is_refused_because_it_is_one_based() {
        repl::select_educational_profile();
        assert_eq!(dispatch(Ok(1), IFACE_V1, 0, b"").0, CKR_ARGUMENTS_BAD);
        repl::clear_profile();
    }

    #[test]
    fn interface_names_are_exact() {
        assert!(handles(Some(IFACE_V1)) && handles(Some(IFACE_CEREMONY_TEST)));
        assert!(!handles(Some("PKCS 11")) && !handles(None) && !handles(Some("PQCTODAY_KEY_REPLICATION_1_")));
    }
}
