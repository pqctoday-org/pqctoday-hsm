//! C1 — per-connection PKCS#11 application contexts (addendum §1.1, A-05).
//!
//! Proves, through the engine's public API:
//! * an SO and a normal user log in side by side in separate contexts, each
//!   context obeying the v3.2 one-role / R-O rules on its own;
//! * one context cannot use, observe or outlive another's sessions or
//!   private objects;
//! * a logout in one context never re-keys handles another logged-in context
//!   still holds (any role), and a context that logged out cannot revive its
//!   old handles by logging in again while another context is logged in;
//! * the context lifecycle (create / open / destroy / guard) and its
//!   immutable metadata;
//! * native C callers (the default context) keep pre-C1 behaviour.

use softhsmrustv3::app_context::{self, ContextGuard, ContextMeta, DEFAULT_CONTEXT};
use softhsmrustv3::constants::*;
use softhsmrustv3::{ffi, native, state};
use std::sync::{Mutex, MutexGuard, OnceLock};

const SO_PIN: &str = "12345678";
const USER_PIN: &str = "87654321";
const RW: u32 = CKF_SERIAL_SESSION | CKF_RW_SESSION;
const RO: u32 = CKF_SERIAL_SESSION;
const CKA_LABEL: u32 = 0x0000_0003;

/// The engine state is process-global; every test serializes on this.
fn serialize() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
}

fn meta(role: &str, n: u8) -> ContextMeta {
    ContextMeta {
        role: role.to_string(),
        client_cert_sha256: [n; 32],
        listener: "crypto-plane:5696".to_string(),
        correlation: Some(format!("corr-{n}")),
    }
}

/// Fresh initialized token with a user PIN on `slot`; no session left open.
fn token(slot: u32) {
    native::init().expect("init");
    state::ensure_slot(slot);
    native::init_token(slot, SO_PIN, &format!("c1-{slot}")).expect("init_token");
    let so = native::open_session_so(slot, SO_PIN).expect("so session");
    native::init_pin(so, USER_PIN).expect("init_pin");
    native::logout(so).expect("logout");
    native::close_session(so).expect("close");
}

fn login(h: u32, user_type: u32, pin: &str) -> u32 {
    let mut p = pin.as_bytes().to_vec();
    ffi::C_Login(h, user_type, p.as_mut_ptr(), p.len() as u32)
}

/// (state, rv) of C_GetSessionInfo.
fn session_state(h: u32) -> (u32, u32) {
    let mut info = [0u32; 4];
    let rv = ffi::C_GetSessionInfo(h, info.as_mut_ptr() as *mut u8);
    (info[1], rv)
}

/// A private TOKEN object (AES key) created through `session`, tagged `id`.
fn private_token_key(session: u32, id: &[u8]) -> u32 {
    let h = native::keygen::generate_aes_key(session, 128, id, "c1").expect("aes");
    state::OBJECTS.with(|o| {
        let mut o = o.borrow_mut();
        let a = o.get_mut(&h).expect("object");
        a.insert(CKA_TOKEN, vec![1]);
        a.insert(CKA_PRIVATE, vec![1]);
    });
    h
}

/// A private SESSION object owned by `session`.
fn private_session_key(session: u32, id: &[u8]) -> u32 {
    let h = native::keygen::generate_aes_key(session, 128, id, "c1-session").expect("aes");
    state::OBJECTS.with(|o| {
        let mut o = o.borrow_mut();
        let a = o.get_mut(&h).expect("object");
        a.insert(CKA_TOKEN, vec![0]);
        a.insert(CKA_PRIVATE, vec![1]);
        a.insert(CKA_PRIV_OWNER_SESSION, session.to_le_bytes().to_vec());
    });
    h
}

fn sees(session: u32, h: u32) -> bool {
    native::object::get_attribute(session, h, CKA_LABEL).is_some()
}

#[test]
fn so_and_user_log_in_side_by_side_in_separate_contexts() {
    let _g = serialize();
    let slot = 41;
    token(slot);
    let a = ContextGuard::new(meta("replication-admin", 1));
    let b = ContextGuard::new(meta("user", 2));

    let sa = app_context::open_session(a.id(), slot, RW).unwrap();
    let sb = app_context::open_session(b.id(), slot, RW).unwrap();
    assert_eq!(login(sa, CKU_SO, SO_PIN), CKR_OK);
    // Before C1 this was CKR_USER_ANOTHER_ALREADY_LOGGED_IN.
    assert_eq!(login(sb, CKU_USER, USER_PIN), CKR_OK);

    assert_eq!(session_state(sa), (CKS_RW_SO_FUNCTIONS, CKR_OK));
    assert_eq!(session_state(sb), (CKS_RW_USER_FUNCTIONS, CKR_OK));
    assert!(state::session_is_so(sa) && !state::session_user_logged_in(sa));
    assert!(state::session_user_logged_in(sb) && !state::session_is_so(sb));
    assert!(state::session_logged_in(sa) && state::session_logged_in(sb));

    // The default (native) context is untouched: still public.
    let mut sd = 0u32;
    assert_eq!(ffi::C_OpenSession(slot, RW, std::ptr::null_mut(), std::ptr::null_mut(), &mut sd), CKR_OK);
    assert_eq!(session_state(sd), (CKS_RW_PUBLIC_SESSION, CKR_OK));
    assert!(!state::session_logged_in(sd));

    // Within one context the v3.2 rules still hold.
    let sa2 = app_context::open_session(a.id(), slot, RW).unwrap();
    assert_eq!(session_state(sa2).0, CKS_RW_SO_FUNCTIONS, "login state is shared inside a context");
    assert_eq!(login(sa2, CKU_USER, USER_PIN), CKR_USER_ANOTHER_ALREADY_LOGGED_IN);
    assert_eq!(login(sa2, CKU_SO, SO_PIN), CKR_USER_ALREADY_LOGGED_IN);
    assert_eq!(app_context::open_session(a.id(), slot, RO), Err(CKR_SESSION_READ_WRITE_SO_EXISTS));
    let sb_ro = app_context::open_session(b.id(), slot, RO).expect("R/O is fine in the user context");
    assert_eq!(session_state(sb_ro), (CKS_RO_USER_FUNCTIONS, CKR_OK));
    // An R/O session in ANOTHER context does not block an SO login here,
    // but one in the SAME context does.
    let c = ContextGuard::new(meta("replication-admin", 3));
    let sc = app_context::open_session(c.id(), slot, RW).unwrap();
    assert_eq!(login(sc, CKU_SO, SO_PIN), CKR_OK, "B's R/O session is another application's");
    let d = ContextGuard::new(meta("replication-admin", 4));
    let sd_rw = app_context::open_session(d.id(), slot, RW).unwrap();
    let _sd_ro = app_context::open_session(d.id(), slot, RO).unwrap();
    assert_eq!(login(sd_rw, CKU_SO, SO_PIN), CKR_SESSION_READ_ONLY_EXISTS);

    drop((a, b, c, d));
    assert_eq!(ffi::C_CloseSession(sd), CKR_OK);
    assert_eq!(app_context::context_count(), 0);
}

#[test]
fn one_context_cannot_use_observe_or_outlive_anothers_sessions() {
    let _g = serialize();
    let slot = 42;
    token(slot);
    let a = ContextGuard::new(meta("replication-admin", 1));
    let b = ContextGuard::new(meta("user", 2));
    let sa = app_context::open_session(a.id(), slot, RW).unwrap();
    let sb = app_context::open_session(b.id(), slot, RW).unwrap();
    assert_eq!(login(sa, CKU_SO, SO_PIN), CKR_OK);
    assert_eq!(login(sb, CKU_USER, USER_PIN), CKR_OK);

    // Sessions are bound to their context.
    assert_eq!(app_context::check_session(b.id(), sb), Ok(()));
    assert_eq!(app_context::check_session(a.id(), sb), Err(CKR_SESSION_HANDLE_INVALID));
    assert_eq!(app_context::check_session(b.id(), sa), Err(CKR_SESSION_HANDLE_INVALID));
    assert_eq!(app_context::check_session(DEFAULT_CONTEXT, sb), Err(CKR_SESSION_HANDLE_INVALID));
    assert_eq!(app_context::context_sessions(b.id()), vec![sb]);

    // B's private objects: B sees them; the SO context and a public context do not.
    let tok = private_token_key(sb, b"c1-tok");
    let ses = private_session_key(sb, b"c1-ses");
    assert!(sees(sb, tok) && sees(sb, ses));
    assert!(!sees(sa, tok) && !sees(sa, ses), "SO context must not observe user objects");
    let p = ContextGuard::new(meta("user", 3));
    let sp = app_context::open_session(p.id(), slot, RW).unwrap();
    assert!(!sees(sp, tok) && !sees(sp, ses), "public context must not observe private objects");
    assert_eq!(native::object::find_all_by_cka_id(sp, b"c1-tok").unwrap(), Vec::<u32>::new());

    // Destroying B closes its sessions and its private session objects die
    // with them; the token object survives; A is unaffected.
    let b_id = b.id();
    drop(b);
    assert_eq!(session_state(sb).1, CKR_SESSION_HANDLE_INVALID, "B's session must not outlive B");
    assert!(!state::object_exists(ses), "B's private session object must die with B");
    assert!(app_context::context_meta(b_id).is_none());
    assert_eq!(app_context::open_session(b_id, slot, RW), Err(CKR_ARGUMENTS_BAD));
    assert_eq!(session_state(sa), (CKS_RW_SO_FUNCTIONS, CKR_OK), "A unaffected by B's teardown");
    assert!(state::object_exists(tok));
    // A later context logging in as user finds the token object again.
    let c = ContextGuard::new(meta("user", 4));
    let sc = app_context::open_session(c.id(), slot, RW).unwrap();
    assert_eq!(login(sc, CKU_USER, USER_PIN), CKR_OK);
    assert_eq!(native::object::find_all_by_cka_id(sc, b"c1-tok").unwrap().len(), 1);
    drop((a, c, p));
}

#[test]
fn logout_in_one_context_never_rekeys_handles_another_context_holds() {
    let _g = serialize();
    let slot = 43;
    token(slot);
    let a = ContextGuard::new(meta("user", 1));
    let b = ContextGuard::new(meta("user", 2));
    let sa = app_context::open_session(a.id(), slot, RW).unwrap();
    let sb = app_context::open_session(b.id(), slot, RW).unwrap();
    assert_eq!(login(sa, CKU_USER, USER_PIN), CKR_OK);
    assert_eq!(login(sb, CKU_USER, USER_PIN), CKR_OK);
    let k = private_token_key(sb, b"c1-k");
    let a_ses = private_session_key(sa, b"c1-a-ses");
    let b_ses = private_session_key(sb, b"c1-b-ses");
    assert!(sees(sa, k) && sees(sb, k));

    // A logs out while B is logged in: no re-key; only A's session objects die.
    assert_eq!(ffi::C_Logout(sa), CKR_OK);
    assert!(state::object_exists(k), "k must keep its handle while B is logged in");
    assert!(sees(sb, k), "B's handle stays valid");
    assert!(!sees(sa, k), "A's handle is unusable at once");
    assert!(!state::object_exists(a_ses), "A's private session object is destroyed");
    assert!(state::object_exists(b_ses), "B's private session object survives");
    // A may not revive its old handle by logging in again while B is logged in.
    assert_eq!(login(sa, CKU_USER, USER_PIN), CKR_USER_TOO_MANY_TYPES);
    assert_eq!(login(sa, CKU_SO, SO_PIN), CKR_USER_TOO_MANY_TYPES);
    // A fresh context is not pending and logs in normally.
    let c = ContextGuard::new(meta("user", 3));
    let sc = app_context::open_session(c.id(), slot, RW).unwrap();
    assert_eq!(login(sc, CKU_USER, USER_PIN), CKR_OK);
    assert!(sees(sc, k));
    assert_eq!(ffi::C_Logout(sc), CKR_OK);
    assert!(state::object_exists(k), "B still logged in: still no re-key");

    // B, the last login on the slot, logs out: the re-key runs now.
    assert_eq!(ffi::C_Logout(sb), CKR_OK);
    assert!(!state::object_exists(k), "the last logout re-keys private token objects");
    assert!(!state::object_exists(b_ses));
    // Pending marks are cleared: A logs in again, its old handle stays dead,
    // and the object is findable under a fresh handle.
    assert_eq!(login(sa, CKU_USER, USER_PIN), CKR_OK);
    assert!(!sees(sa, k));
    let found = native::object::find_all_by_cka_id(sa, b"c1-k").unwrap();
    assert_eq!(found.len(), 1, "exactly one copy, under a new handle");
    assert_ne!(found[0], k);
    drop((a, b, c));
}

#[test]
fn an_so_login_elsewhere_also_defers_the_rekey() {
    let _g = serialize();
    let slot = 44;
    token(slot);
    let admin = ContextGuard::new(meta("replication-admin", 1));
    let user = ContextGuard::new(meta("user", 2));
    let s_admin = app_context::open_session(admin.id(), slot, RW).unwrap();
    let s_user = app_context::open_session(user.id(), slot, RW).unwrap();
    assert_eq!(login(s_admin, CKU_SO, SO_PIN), CKR_OK);
    assert_eq!(login(s_user, CKU_USER, USER_PIN), CKR_OK);
    let k = private_token_key(s_user, b"c1-so");

    // The user logs out while the admin (SO) is staging: no re-key.
    assert_eq!(ffi::C_Logout(s_user), CKR_OK);
    assert!(state::object_exists(k), "an SO login elsewhere holds the re-key back");
    assert_eq!(login(s_user, CKU_USER, USER_PIN), CKR_USER_TOO_MANY_TYPES);

    // The admin's logout is the last one: re-key.
    assert_eq!(ffi::C_Logout(s_admin), CKR_OK);
    assert!(!state::object_exists(k));
    assert_eq!(login(s_user, CKU_USER, USER_PIN), CKR_OK);
    assert_eq!(native::object::find_all_by_cka_id(s_user, b"c1-so").unwrap().len(), 1);
    drop((admin, user));
}

#[test]
fn destroying_a_logged_in_context_follows_the_logout_rules() {
    let _g = serialize();
    let slot = 45;
    token(slot);
    let a = ContextGuard::new(meta("user", 1));
    let sa = app_context::open_session(a.id(), slot, RW).unwrap();
    assert_eq!(login(sa, CKU_USER, USER_PIN), CKR_OK);
    let k = private_token_key(sa, b"c1-d");
    {
        let b = ContextGuard::new(meta("user", 2));
        let sb = app_context::open_session(b.id(), slot, RW).unwrap();
        assert_eq!(login(sb, CKU_USER, USER_PIN), CKR_OK);
        // b dropped here: its logout is deferred because A is logged in.
    }
    assert!(state::object_exists(k) && sees(sa, k));
    // Destroying A, the last login, re-keys.
    drop(a);
    assert!(!state::object_exists(k));
    assert_eq!(app_context::context_count(), 0);
    // A destroyed context cannot be destroyed twice or reused.
    let id = {
        let g = ContextGuard::new(meta("user", 3));
        g.id()
    };
    app_context::destroy_context(id);
    assert_eq!(app_context::open_session(id, slot, RW), Err(CKR_ARGUMENTS_BAD));
}

#[test]
fn native_close_all_sessions_leaves_connection_contexts_alone() {
    let _g = serialize();
    let slot = 46;
    token(slot);
    let a = ContextGuard::new(meta("user", 1));
    let sa = app_context::open_session(a.id(), slot, RW).unwrap();
    assert_eq!(login(sa, CKU_USER, USER_PIN), CKR_OK);
    let mut sd = 0u32;
    assert_eq!(ffi::C_OpenSession(slot, RW, std::ptr::null_mut(), std::ptr::null_mut(), &mut sd), CKR_OK);
    assert_eq!(login(sd, CKU_SO, SO_PIN), CKR_OK, "the default context is its own application");

    assert_eq!(ffi::C_CloseAllSessions(slot), CKR_OK);
    assert_eq!(session_state(sd).1, CKR_SESSION_HANDLE_INVALID);
    assert_eq!(session_state(sa), (CKS_RW_USER_FUNCTIONS, CKR_OK), "§5.6.3: only the caller's application");
    drop(a);
}

#[test]
fn metadata_is_attached_at_creation_and_read_per_session() {
    let _g = serialize();
    let slot = 47;
    token(slot);
    let m = meta("replication-admin", 9);
    let a = ContextGuard::new(m.clone());
    let sa = app_context::open_session(a.id(), slot, RW).unwrap();
    assert_eq!(state::session_context_meta(sa), Some(m.clone()));
    assert_eq!(app_context::context_meta(a.id()), Some(m));
    assert_eq!(app_context::session_context(sa), a.id());
    let mut sd = 0u32;
    assert_eq!(ffi::C_OpenSession(slot, RW, std::ptr::null_mut(), std::ptr::null_mut(), &mut sd), CKR_OK);
    assert_eq!(state::session_context_meta(sd), None, "default context has no metadata");
    assert_eq!(app_context::session_context(sd), DEFAULT_CONTEXT);
    assert_eq!(state::session_context_meta(0xDEAD_BEEF), None);
    assert_eq!(ffi::C_CloseSession(sd), CKR_OK);
    drop(a);
}

#[test]
fn default_context_keeps_pre_c1_logout_rekey() {
    let _g = serialize();
    let slot = 48;
    token(slot);
    let s = native::open_session(slot, USER_PIN).expect("user session");
    let k = private_token_key(s, b"c1-native");
    native::logout(s).expect("logout");
    assert!(!state::object_exists(k), "no other context: re-key exactly as before C1");
    assert_eq!(login(s, CKU_USER, USER_PIN), CKR_OK);
    let found = native::object::find_all_by_cka_id(s, b"c1-native").unwrap();
    assert_eq!(found.len(), 1);
    assert_ne!(found[0], k);
    native::close_session(s).expect("close");
}

#[test]
fn concurrent_contexts_login_and_teardown_without_deadlock() {
    let _g = serialize();
    let slot = 49;
    token(slot);
    let threads: Vec<_> = (0..8u8)
        .map(|t| {
            std::thread::spawn(move || {
                for i in 0..25u8 {
                    let g = ContextGuard::new(meta(if t % 2 == 0 { "user" } else { "replication-admin" }, i));
                    let s = app_context::open_session(g.id(), slot, RW).unwrap();
                    let rv = if t % 2 == 0 { login(s, CKU_USER, USER_PIN) } else { login(s, CKU_SO, SO_PIN) };
                    assert_eq!(rv, CKR_OK, "thread {t} iteration {i}");
                    if i % 3 == 0 {
                        assert_eq!(ffi::C_Logout(s), CKR_OK);
                    }
                }
            })
        })
        .collect();
    for t in threads {
        t.join().expect("thread");
    }
    assert_eq!(app_context::context_count(), 0);
    // Every context is gone, so the slot ends with no login at all.
    let mut sd = 0u32;
    assert_eq!(ffi::C_OpenSession(slot, RW, std::ptr::null_mut(), std::ptr::null_mut(), &mut sd), CKR_OK);
    assert_eq!(session_state(sd).0, CKS_RW_PUBLIC_SESSION);
    assert_eq!(login(sd, CKU_USER, USER_PIN), CKR_OK, "no stale pending mark on the default context");
    assert_eq!(ffi::C_CloseSession(sd), CKR_OK);
}
