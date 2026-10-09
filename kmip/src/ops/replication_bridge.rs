//! KMIP 3.0 PKCS#11-operation (0x33) binding for protected key replication.
//!
//! PQCTODAY EDUCATIONAL TEST ONLY — compiled only with `--features educational-replication`
//! and inert until the server selects the educational profile (`--educational-replication`).
//! The v1, ceremony and admin interfaces are mapped as specified in the admin/ceremony addendum
//! §6. The ceremony calls are served under `PQCTODAY_KEY_REPLICATION_CEREMONY_1_0` (addendum
//! §6.9 envelopes). The temporary lab name `PQCTODAY_KEY_REPLICATION_EDU_CEREMONY_TEST`, with its
//! flat 113-byte BeginReceive input, stays as a DEPRECATED ALIAS for one release (removed in the
//! next one); see hsm-kmip-ceremony-interface-plan-10042026.md.
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
/// Ceremony interface (addendum §2.2, §6.9): 1 IssueSourceChallenge, 2 BeginReceive (DER),
/// 3 CancelReceive, 4 AttestKey on the KMIP wire.
pub const IFACE_CEREMONY: &str = "PQCTODAY_KEY_REPLICATION_CEREMONY_1_0";
/// DEPRECATED alias of [`IFACE_CEREMONY`] for one release: the old lab test name, whose
/// BeginReceive input is the flat 113-byte form. Removed in the next release.
pub const IFACE_CEREMONY_TEST: &str = "PQCTODAY_KEY_REPLICATION_EDU_CEREMONY_TEST";
/// Admin interface (addendum §2.1): 1 AdminIssueNonce, 2 AdminExecute on the KMIP wire.
pub const IFACE_ADMIN: &str = "PQCTODAY_KEY_REPLICATION_ADMIN_1_0";
/// mTLS client-certificate CN of the admin role (pre-ABI: CN, not the A-04 EKU).
pub const ROLE_ADMIN_CN: &str = "replication-admin";

/// Board-local, root-only file holding the SO PIN (owner O7). Set once at server start.
static SO_PIN_FILE: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
/// Slot the admin context logs into (the server's `--slot`).
static ADMIN_SLOT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Configure the admin path (server start, `--replication-so-pin-file`).
pub fn configure_admin(pin_file: std::path::PathBuf, slot: u32) {
    let _ = SO_PIN_FILE.set(pin_file);
    ADMIN_SLOT.store(slot, std::sync::atomic::Ordering::Relaxed);
}

/// One admin call in a fresh application context: open a R/W session in it, SO login with
/// the board-local PIN, run the call, log out; the guard destroys the context and its
/// sessions. The KMIP server closes each connection after one Request Message, so this
/// per-request context is the per-connection context of addendum §1.1. User work in the
/// default context is not paused (C1).
/// Connection metadata for the admin application context (addendum §5, A-16): the client
/// certificate hash and listener address the TLS listener authenticated for this request. The
/// engine stamps them into its audit lines. Without a TLS connection (an in-process call) there is
/// no certificate, and the fields keep their empty values.
fn admin_context_meta() -> softhsmrustv3::app_context::ContextMeta {
    let conn = crate::server::conn_meta::current();
    softhsmrustv3::app_context::ContextMeta {
        role: ROLE_ADMIN_CN.to_string(),
        client_cert_sha256: conn.as_ref().map(|c| c.client_cert_sha256).unwrap_or([0u8; 32]),
        listener: conn.map(|c| c.listener).unwrap_or_else(|| "kmip-replication-bridge".to_string()),
        correlation: None,
    }
}

fn admin_call(ordinal: u32, input: &[u8]) -> Result<Vec<u8>, u32> {
    use softhsmrustv3::app_context::{self, ContextGuard};
    let pin = SO_PIN_FILE
        .get()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|s| s.trim().to_string())
        .ok_or(CKR_USER_NOT_LOGGED_IN)?;
    let guard = ContextGuard::new(admin_context_meta());
    let slot = ADMIN_SLOT.load(std::sync::atomic::Ordering::Relaxed);
    let h = app_context::open_session(guard.id(), slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)?;
    let mut p = pin.into_bytes();
    let rv = softhsmrustv3::ffi::C_Login(h, CKU_SO, p.as_mut_ptr(), p.len() as u32);
    zeroize_vec(&mut p);
    if rv != CKR_OK {
        return Err(rv);
    }
    let r = match (ordinal, input.is_empty()) {
        (0, true) => repl::admin::issue_nonce(h).map(|n| n.to_vec()),
        (1, false) => repl::admin::execute(h, input),
        _ => Err(CKR_ARGUMENTS_BAD),
    };
    let _ = softhsmrustv3::ffi::C_Logout(h);
    drop(guard);
    r
}

fn zeroize_vec(v: &mut [u8]) {
    for b in v.iter_mut() {
        unsafe { std::ptr::write_volatile(b, 0) };
    }
}

// PKCS#11 return codes used here (values from pkcs11t.h).
const CKR_ARGUMENTS_BAD: u32 = 0x0000_0007;
const CKR_FUNCTION_NOT_SUPPORTED: u32 = 0x0000_0054;
const CKR_KEY_HANDLE_INVALID: u32 = 0x0000_0060;
const CKR_DATA_INVALID: u32 = 0x0000_0020;
const CKR_USER_NOT_LOGGED_IN: u32 = 0x0000_0101;
const CKR_USER_TYPE_INVALID: u32 = 0x0000_0103;
use softhsmrustv3::constants::{CKF_RW_SESSION, CKF_SERIAL_SESSION, CKU_SO};

/// Maximum Input Parameters accepted before anything else (base §10 package bound + wrapper).
const MAX_INPUT: usize = 256 * 1024 + 64;

/// The engine's find operation is per-session state, and KMIP connections share one engine
/// session in single-tenant mode, so key lookups are serialised.
static FIND_LOCK: Mutex<()> = Mutex::new(());

/// True when `interface` names one of the replication interfaces this build serves.
pub fn handles(interface: Option<&str>) -> bool {
    matches!(interface, Some(IFACE_V1) | Some(IFACE_CEREMONY) | Some(IFACE_CEREMONY_TEST) | Some(IFACE_ADMIN))
}

/// Dispatch one call. `function` is the KMIP `PKCS#11 Function` value, which KMIP 3.0 §11.39
/// defines as the **1-based** offset in the function list (review A-06), so ordinal = value − 1.
/// Returns `(CK_RV, output)`.
pub fn dispatch(engine_session: Result<u32, ()>, interface: &str, function: u32, input: &[u8]) -> (u32, Option<Vec<u8>>) {
    dispatch_as(engine_session, None, interface, function, input)
}

/// Role-aware dispatch: `peer` is the authenticated client identity (mTLS CN in open-auth).
/// Admin requires the admin role and runs in its OWN application context with a real SO
/// login (C1, addendum §1.1); user interfaces refuse the admin role.
pub fn dispatch_as(engine_session: Result<u32, ()>, peer: Option<&str>, interface: &str, function: u32, input: &[u8]) -> (u32, Option<Vec<u8>>) {
    let Some(ordinal) = function.checked_sub(1) else {
        return (CKR_ARGUMENTS_BAD, None);
    };
    if !repl::educational_profile_selected() {
        return (CKR_FUNCTION_NOT_SUPPORTED, None);
    }
    let is_admin_peer = peer == Some(ROLE_ADMIN_CN);
    if interface == IFACE_ADMIN {
        if !is_admin_peer {
            return (CKR_USER_TYPE_INVALID, None);
        }
        return match admin_call(ordinal, input) {
            Ok(out) => (CKR_OK, Some(out)),
            Err(rv) => (rv, None),
        };
    }
    if is_admin_peer {
        return (CKR_USER_TYPE_INVALID, None);
    }
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
        (IFACE_CEREMONY, n) => ceremony(s, false, n, input),
        (IFACE_CEREMONY_TEST, n) => {
            tracing::warn!("deprecated KMIP interface name {IFACE_CEREMONY_TEST}: use {IFACE_CEREMONY}");
            ceremony(s, true, n, input)
        }
        (IFACE_V1, _) => Err(CKR_ARGUMENTS_BAD),
        _ => Err(CKR_FUNCTION_NOT_SUPPORTED),
    };
    match r {
        Ok(out) => (CKR_OK, Some(out)),
        Err(rv) => (rv, None),
    }
}

/// The four user-level ceremony calls (addendum §6.9). `legacy` selects the old lab encoding of
/// BeginReceive (flat `op ‖ sourceChallenge(32) ‖ domainID(32) ‖ policyID(48)`, 113 bytes); the
/// real interface takes the `BeginReceive` DER, strictly decoded by the engine's own parser.
fn ceremony(s: u32, legacy: bool, ordinal: u32, input: &[u8]) -> Result<Vec<u8>, u32> {
    match ordinal {
        // 0 IssueSourceChallenge — no input; Output = 32 bytes.
        0 if input.is_empty() => repl::issue_source_challenge(s).map(|c| c.to_vec()),
        // 1 BeginReceive — Output = ReplicationRequest DER.
        1 if legacy && input.len() == 113 => {
            let op = match input[0] {
                0 => repl::asn1::Operation::LiveClone,
                1 => repl::asn1::Operation::OfflineBackup,
                2 => repl::asn1::Operation::Restore,
                _ => return Err(CKR_ARGUMENTS_BAD),
            };
            let chal: [u8; 32] = input[1..33].try_into().unwrap();
            let domain: [u8; 32] = input[33..65].try_into().unwrap();
            let policy: [u8; 48] = input[65..113].try_into().unwrap();
            repl::begin_receive(s, op, &chal, &domain, &policy)
        }
        1 if !legacy => {
            let (op, chal, domain, policy) = repl::admin::BeginReceive::parse(input)?;
            repl::begin_receive(s, op, &chal, &domain, &policy)
        }
        // 2 CancelReceive — Input = transactionID(32).
        2 if input.len() == 32 => repl::cancel_receive(s, input.try_into().unwrap()).map(|()| Vec::new()),
        // 3 AttestKey — Input = DER KeyCall { uid, challenge(32) }; Output = evidence DER.
        3 => key_call(input).and_then(|(uid, chal)| {
            let chal: [u8; 32] = chal.try_into().map_err(|_| CKR_ARGUMENTS_BAD)?;
            repl::evidence::attest_key(s, by_uid(s, uid)?, &chal)
        }),
        _ => Err(CKR_ARGUMENTS_BAD),
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

    /// The educational profile is process-global: tests that select or clear it must not overlap.
    fn profile_lock() -> std::sync::MutexGuard<'static, ()> {
        static L: std::sync::Mutex<()> = std::sync::Mutex::new(());
        L.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// True when the call got past the bridge's own routing and decoding (the engine, which is not
    /// initialised in these unit tests, answered), as opposed to being refused by the bridge.
    fn reached_the_engine(rv: u32) -> bool {
        !matches!(rv, CKR_ARGUMENTS_BAD | CKR_DATA_INVALID | CKR_FUNCTION_NOT_SUPPORTED)
    }

    fn begin_receive_der() -> Vec<u8> {
        let b = repl::admin::BeginReceive {
            version: 1,
            operation: repl::asn1::Operation::LiveClone,
            source_challenge: repl::asn1::octets(&[1u8; 32]),
            domain_id: repl::asn1::octets(&[2u8; 32]),
            requested_policy: repl::asn1::octets(&[3u8; 48]),
        };
        repl::asn1::to_der(&b).unwrap()
    }

    fn begin_receive_flat() -> Vec<u8> {
        let mut v = vec![0u8];
        v.extend_from_slice(&[1u8; 32]);
        v.extend_from_slice(&[2u8; 32]);
        v.extend_from_slice(&[3u8; 48]);
        v
    }

    #[test]
    fn refuses_unless_the_educational_profile_is_selected() {
        let _g = profile_lock();
        repl::clear_profile();
        assert_eq!(dispatch(Ok(1), IFACE_V1, 2, b"x").0, CKR_FUNCTION_NOT_SUPPORTED);
        assert_eq!(dispatch(Ok(1), IFACE_CEREMONY, 1, b"").0, CKR_FUNCTION_NOT_SUPPORTED);
        assert_eq!(dispatch(Ok(1), IFACE_CEREMONY_TEST, 1, b"").0, CKR_FUNCTION_NOT_SUPPORTED);
    }

    #[test]
    fn kmip_function_value_zero_is_refused_because_it_is_one_based() {
        let _g = profile_lock();
        repl::select_educational_profile();
        assert_eq!(dispatch(Ok(1), IFACE_V1, 0, b"").0, CKR_ARGUMENTS_BAD);
        assert_eq!(dispatch(Ok(1), IFACE_CEREMONY, 0, b"").0, CKR_ARGUMENTS_BAD);
        assert_eq!(dispatch(Ok(1), IFACE_CEREMONY_TEST, 0, b"").0, CKR_ARGUMENTS_BAD);
        repl::clear_profile();
    }

    #[test]
    fn interface_names_are_exact() {
        assert_eq!(IFACE_CEREMONY, "PQCTODAY_KEY_REPLICATION_CEREMONY_1_0");
        assert!(handles(Some(IFACE_V1)) && handles(Some(IFACE_CEREMONY)) && handles(Some(IFACE_CEREMONY_TEST)) && handles(Some(IFACE_ADMIN)));
        assert!(!handles(Some("PKCS 11")) && !handles(None) && !handles(Some("PQCTODAY_KEY_REPLICATION_1_")));
        assert!(!handles(Some("PQCTODAY_KEY_REPLICATION_CEREMONY_2_0")) && !handles(Some("PQCTODAY_KEY_REPLICATION_CEREMONY_1_0 ")));
    }

    /// The real ceremony interface takes the BeginReceive DER (addendum §6.9) and refuses the
    /// old flat form; the other three calls keep their envelopes.
    #[test]
    fn the_real_ceremony_interface_takes_begin_receive_der() {
        let _g = profile_lock();
        repl::select_educational_profile();
        // BeginReceive (function 2).
        assert!(reached_the_engine(dispatch(Ok(1), IFACE_CEREMONY, 2, &begin_receive_der()).0), "DER is routed to the engine");
        assert_eq!(dispatch(Ok(1), IFACE_CEREMONY, 2, &begin_receive_flat()).0, CKR_DATA_INVALID, "the flat form is not DER");
        assert_eq!(dispatch(Ok(1), IFACE_CEREMONY, 2, b"").0, CKR_DATA_INVALID);
        let mut trailing = begin_receive_der();
        trailing.push(0);
        assert_eq!(dispatch(Ok(1), IFACE_CEREMONY, 2, &trailing).0, CKR_DATA_INVALID, "trailing bytes are refused");
        // IssueSourceChallenge (1) takes no input; CancelReceive (3) takes exactly 32 bytes.
        assert!(reached_the_engine(dispatch(Ok(1), IFACE_CEREMONY, 1, b"").0));
        assert_eq!(dispatch(Ok(1), IFACE_CEREMONY, 1, b"x").0, CKR_ARGUMENTS_BAD);
        assert!(reached_the_engine(dispatch(Ok(1), IFACE_CEREMONY, 3, &[7u8; 32]).0));
        assert_eq!(dispatch(Ok(1), IFACE_CEREMONY, 3, &[7u8; 31]).0, CKR_ARGUMENTS_BAD);
        // AttestKey (4) needs a strict KeyCall; nothing beyond function 4 exists.
        assert_eq!(dispatch(Ok(1), IFACE_CEREMONY, 4, b"junk").0, CKR_DATA_INVALID);
        assert_eq!(dispatch(Ok(1), IFACE_CEREMONY, 5, b"").0, CKR_ARGUMENTS_BAD);
        assert_eq!(dispatch(Err(()), IFACE_CEREMONY, 1, b"").0, CKR_USER_NOT_LOGGED_IN);
        repl::clear_profile();
    }

    /// Decision (plan note 2026-10-04): the old lab name stays as a deprecated alias for one
    /// release, with its flat BeginReceive input, so archived courier builds keep working. It does
    /// not accept the DER form. Remove this test together with the alias.
    #[test]
    fn the_old_test_name_is_a_deprecated_alias_with_the_flat_input() {
        let _g = profile_lock();
        repl::select_educational_profile();
        assert!(reached_the_engine(dispatch(Ok(1), IFACE_CEREMONY_TEST, 2, &begin_receive_flat()).0), "flat form still routed");
        assert_eq!(dispatch(Ok(1), IFACE_CEREMONY_TEST, 2, &begin_receive_der()).0, CKR_ARGUMENTS_BAD, "DER is not the alias's form");
        let mut bad_op = begin_receive_flat();
        bad_op[0] = 9;
        assert_eq!(dispatch(Ok(1), IFACE_CEREMONY_TEST, 2, &bad_op).0, CKR_ARGUMENTS_BAD);
        assert!(reached_the_engine(dispatch(Ok(1), IFACE_CEREMONY_TEST, 1, b"").0));
        assert!(reached_the_engine(dispatch(Ok(1), IFACE_CEREMONY_TEST, 3, &[7u8; 32]).0));
        assert_eq!(dispatch(Ok(1), IFACE_CEREMONY_TEST, 5, b"").0, CKR_ARGUMENTS_BAD);
        repl::clear_profile();
    }

    #[test]
    fn an_unknown_ceremony_version_is_not_served() {
        let _g = profile_lock();
        repl::select_educational_profile();
        assert_eq!(dispatch(Ok(1), "PQCTODAY_KEY_REPLICATION_CEREMONY_2_0", 1, b"").0, CKR_FUNCTION_NOT_SUPPORTED);
        repl::clear_profile();
    }
}

#[cfg(test)]
mod admin_meta_tests {
    use super::*;
    use crate::server::conn_meta::{self, ConnMeta};
    use softhsmrustv3::app_context::{self, ContextGuard};

    /// A-16: the application context the admin path creates carries the certificate hash and
    /// listener of the connection being served, not zeros, so the engine's audit lines name the
    /// certificate that made the call. (The engine side, which writes these fields into the audit
    /// line, is tested in rust/tests/replication_admin.rs.)
    #[test]
    fn the_admin_context_carries_the_connection_certificate_hash() {
        let meta = ConnMeta::from_leaf(b"client-leaf-der", "10.77.0.1:5696".into());
        let _scope = conn_meta::enter(Some(meta.clone()));
        let guard = ContextGuard::new(admin_context_meta());
        let got = app_context::context_meta(guard.id()).expect("context exists");
        assert_eq!(got.client_cert_sha256, meta.client_cert_sha256);
        assert_ne!(got.client_cert_sha256, [0u8; 32], "not the all-zero placeholder");
        assert_eq!(got.listener, "10.77.0.1:5696");
        assert_eq!(got.role, ROLE_ADMIN_CN);
    }

    #[test]
    fn a_different_connection_gets_a_different_hash() {
        let a = ConnMeta::from_leaf(b"cert-a", "a:1".into());
        let b = ConnMeta::from_leaf(b"cert-b", "b:2".into());
        let ha = {
            let _s = conn_meta::enter(Some(a));
            admin_context_meta().client_cert_sha256
        };
        let hb = {
            let _s = conn_meta::enter(Some(b));
            admin_context_meta().client_cert_sha256
        };
        assert_ne!(ha, hb);
    }

    #[test]
    fn without_a_tls_connection_the_fields_keep_their_empty_values() {
        assert!(conn_meta::current().is_none());
        let m = admin_context_meta();
        assert_eq!(m.client_cert_sha256, [0u8; 32]);
        assert_eq!(m.role, ROLE_ADMIN_CN);
    }
}
