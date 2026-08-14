//! Concurrency regression suite, grown from the P0b/P0c feasibility spikes
//! for the hsm-perf-bench plan (rev 2, Part B — see
//! rust-hsm-perf-bench-scenario-plan-07182026.md in the workspace root).
//!
//!   P0b — can 4 independent tenant tokens be brought online in one process
//!         and used concurrently without cross-tenant interference? PASSES
//!         for keygen/sign/verify AND for isolation: `native::*` originally
//!         did not enforce `state::can_access_object` token-scoping (only
//!         `ffi::C_*` did), so a native caller (e.g. KMIP, which uses
//!         `native::*` exclusively) could reach across tenants by handle.
//!         Closed in Part F (2026-07-18): every by-handle `native::*`
//!         function now gates through the same predicate.
//!   P0c — 20 threads hammering ONE shared token concurrently (real
//!         contention on the global `OBJECTS` mutex), every thread's
//!         signature verified against its own key. PASSES after a real bug
//!         fix: see `login_exclusivity_holds_under_concurrent_attempts`
//!         below and the `C_Login` fix in `src/ffi.rs`.

use softhsmrustv3::native;
use softhsmrustv3::state;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

const CKM_ML_DSA: u32 = 0x0000_001D;
const CKP_ML_DSA_65: u32 = 0x2;
const CKF_SERIAL_SESSION: u32 = 0x0000_0004;
const CKF_RW_SESSION: u32 = 0x0000_0002;

/// All three tests below drive the engine's process-wide global state
/// directly (native::init/finalize, TOKEN_STORE, OBJECTS) — they are NOT
/// safe to run concurrently WITH EACH OTHER (e.g. login_exclusivity's
/// per-round native::finalize() would wipe state out from under p0b/p0c
/// mid-flight). cargo test's default parallel-within-a-binary execution
/// requires this file to self-serialize; can't reuse the engine's own
/// `native::test_lock` (it's `pub(crate)`, invisible from this external
/// integration-test crate). Acquire at the top of every #[test] body.
fn serialize() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
}

/// Open a session on an ALREADY-logged-in token without attempting our own
/// login (native::open_session always logs in, which is per-token
/// exclusive — see the p0c setup comment). Mirrors
/// native::session::open_session_inner minus the C_Login call.
fn open_session_only(slot: u32) -> u32 {
    let mut handle: u32 = 0;
    let rv = softhsmrustv3::ffi::C_OpenSession(
        slot,
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        &mut handle,
    );
    assert_eq!(rv, 0, "C_OpenSession failed: {rv}");
    handle
}

fn bring_up_tenant(slot: u32) -> u32 {
    state::ensure_slot(slot);
    native::init_token(slot, "12345678", &format!("tenant-{slot}")).expect("init_token");
    let so = native::open_session_so(slot, "12345678").expect("open SO session");
    native::init_pin(so, "87654321").expect("init_pin");
    native::logout(so).expect("logout SO");
    native::close_session(so).expect("close SO session");
    native::open_session(slot, "87654321").expect("open user session")
}

#[test]
fn p0b_four_independent_tenant_tokens() {
    let _guard = serialize();
    native::init().expect("engine init");

    let sessions: Vec<u32> = (1..=4).map(bring_up_tenant).collect();
    assert_eq!(sessions.len(), 4);

    // Each tenant gets its own ML-DSA-65 keypair, correctly slot-tagged
    // (tag_object_slot derives CKA_PRIV_SLOT_ID from the creating session).
    let mut keys = Vec::new();
    for &sess in &sessions {
        let (pubh, privh) =
            native::generate_ml_dsa_keypair(sess, CKP_ML_DSA_65, b"p0b", "p0b-key").expect("keygen");
        keys.push((pubh, privh));
    }

    for (i, &sess) in sessions.iter().enumerate() {
        let (_pubh, privh) = keys[i];
        let msg = b"p0b cross-tenant isolation check";
        let sig = native::sign_pqc(sess, privh, CKM_ML_DSA, msg, &[], true, false, false, None)
            .unwrap_or_else(|e| panic!("tenant {} sign failed: {:?}", i, e));
        // Own tenant can verify its own signature.
        native::verify_pqc(sess, keys[i].0, CKM_ML_DSA, msg, &sig, &[], false, false)
            .unwrap_or_else(|e| panic!("tenant {} self-verify failed: {:?}", i, e));

        // GAP CLOSED 2026-07-18 (rust-hsm-perf-bench-scenario-plan-07182026.md
        // Part F): `state::can_access_object` used to be called ONLY from
        // `ffi::C_*` (8 call sites); `native::*` never called it, so the
        // KMIP server (which uses `native::*` exclusively) had no
        // object-level tenant isolation even though the ffi/ck_abi C ABI
        // always enforced it correctly. Every by-handle `native::*`
        // function (sign/verify/encrypt/decrypt/encapsulate/decapsulate/
        // agree/get+set attribute/destroy/split+join/hybrid) now routes
        // through the same gate (`with_object_checked` /
        // `resolve_session_access` in state.rs) — cross-tenant handle use
        // must fail exactly like the ffi surface always has.
        let other = sessions[(i + 1) % sessions.len()];
        let cross = native::verify_pqc(other, keys[i].0, CKM_ML_DSA, msg, &sig, &[], false, false);
        assert!(
            cross.is_err(),
            "tenant {} object was reachable from a different tenant's session — isolation gate regressed",
            i
        );
    }

    println!(
        "P0b: 4 independent tenant tokens created, correctly slot-tagged, each signs/verifies its own \
         key, and cross-tenant handle access is now uniformly denied by native::* — the same isolation \
         ffi::C_* / ck_abi::C_* always enforced."
    );
}

#[test]
fn p0c_twenty_threads_one_shared_token() {
    let _guard = serialize();
    native::init().expect("engine init");
    state::ensure_slot(9);
    native::init_token(9, "12345678", "shared").expect("init_token");
    let so = native::open_session_so(9, "12345678").expect("open SO session");
    native::init_pin(so, "87654321").expect("init_pin");
    native::logout(so).expect("logout SO");
    native::close_session(so).expect("close SO session");

    // PKCS#11 login state is per-TOKEN, not per-session (§5.6) — log in
    // ONCE here; every thread below opens its own session on the
    // already-logged-in token (the real-world multi-threaded usage
    // pattern: an application logs in once, then opens many concurrent
    // sessions). Each thread calling native::open_session (which attempts
    // its own login) would be a MISUSE of the API and correctly gets
    // CKR_USER_ALREADY_LOGGED_IN after the C_Login atomicity fix below.
    //
    // S6 (2026-08-13) — this session is now HELD OPEN for the duration.
    // PKCS#11 v3.2 §5.6.2 makes closing the LAST session on a slot return the
    // token's login state to public, which the engine previously did not
    // implement; the test used to close this session immediately and rely on
    // the login surviving, so every worker thread's session came up
    // authenticated by accident. Keeping one session open is both the
    // conformant way to express "the application is logged in" and the real
    // usage pattern the comment above describes.
    let setup_session = native::open_session(9, "87654321").expect("initial login+session");

    const THREADS: usize = 20;
    const OPS_PER_THREAD: usize = 200;

    let ok_count = Arc::new(AtomicU64::new(0));
    let err_count = Arc::new(AtomicU64::new(0));
    let start = Instant::now();

    std::thread::scope(|scope| {
        for t in 0..THREADS {
            let ok_count = Arc::clone(&ok_count);
            let err_count = Arc::clone(&err_count);
            scope.spawn(move || {
                // Each thread opens its OWN session on the SAME shared,
                // already-logged-in token — this is the real
                // multi-tenant-on-one-token contention pattern, all
                // hammering the same OBJECTS mutex.
                let sess = open_session_only(9);
                let (pubh, privh) = native::generate_ml_dsa_keypair(
                    sess,
                    CKP_ML_DSA_65,
                    format!("thread-{t}").as_bytes(),
                    &format!("t{t}-key"),
                )
                .unwrap_or_else(|e| panic!("thread {t} keygen failed: {e:?}"));

                let msg = format!("payload from thread {t}").into_bytes();
                for i in 0..OPS_PER_THREAD {
                    let sig_result = native::sign_pqc(
                        sess, privh, CKM_ML_DSA, &msg, &[], true, false, false, None,
                    );
                    match sig_result {
                        Ok(sig) => {
                            // The critical correctness check: MY signature
                            // must verify against MY key, every single
                            // time, under maximum concurrent contention.
                            // Any cross-thread state corruption (wrong key
                            // bytes read, wrong context) shows up here.
                            match native::verify_pqc(
                                sess, pubh, CKM_ML_DSA, &msg, &sig, &[], false, false,
                            ) {
                                Ok(()) => {
                                    ok_count.fetch_add(1, Ordering::Relaxed);
                                }
                                Err(e) => {
                                    err_count.fetch_add(1, Ordering::Relaxed);
                                    eprintln!(
                                        "thread {t} op {i}: signature did NOT verify against own key: {e:?}"
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            err_count.fetch_add(1, Ordering::Relaxed);
                            eprintln!("thread {t} op {i}: sign failed: {e:?}");
                        }
                    }
                }
                native::close_session(sess).ok();
            });
        }
    });

    let elapsed: Duration = start.elapsed();
    let ok = ok_count.load(Ordering::Relaxed);
    let err = err_count.load(Ordering::Relaxed);
    let total = ok + err;
    let ops_per_sec = total as f64 / elapsed.as_secs_f64();

    println!(
        "P0c: {THREADS} threads x {OPS_PER_THREAD} sign+verify ops on ONE shared token \
         in {elapsed:?} ({ops_per_sec:.0} ops/sec) — ok={ok} err={err}"
    );

    // The application's login-holding session is released only now that every
    // worker has finished (S6 — closing it earlier logs the token out).
    native::close_session(setup_session).ok();

    assert_eq!(err, 0, "{err} operations failed or corrupted under 20-thread contention");
    assert_eq!(ok, (THREADS * OPS_PER_THREAD) as u64);
}

/// Regression test for the TOCTOU race found 2026-07-18 while writing
/// P0c above: `ffi::C_Login` used to read the token's `login_state` from
/// a `.cloned()` snapshot taken under one `TOKEN_STORE` lock acquisition,
/// then write the new state in a SEPARATE, later lock acquisition. Under
/// concurrent `C_Login` calls on the same token, many threads could all
/// read the pre-login snapshot before any of them wrote — so all of them
/// passed the "not already logged in" exclusivity check and all
/// "succeeded", silently violating PKCS#11 v3.2 §5.6 (only one login
/// wins; every other caller must get `CKR_USER_ALREADY_LOGGED_IN`).
///
/// Fixed by making the read-check-write one atomic critical section
/// (single lock acquisition) in `C_Login`. This test drives 20 threads at
/// `C_Login(CKU_USER)` on the same fresh token simultaneously and asserts
/// EXACTLY one succeeds — repeated across several rounds, since the
/// original bug was a race (probabilistic, not deterministic every run).
#[test]
fn login_exclusivity_holds_under_concurrent_attempts() {
    let _guard = serialize();
    const ROUNDS: u32 = 20;
    const THREADS: usize = 20;

    for round in 0..ROUNDS {
        native::finalize().ok();
        native::init().expect("engine init");
        let slot = 20 + round; // fresh slot per round, avoids cross-round state
        state::ensure_slot(slot);
        native::init_token(slot, "12345678", "race-check").expect("init_token");
        let so = native::open_session_so(slot, "12345678").expect("open SO session");
        native::init_pin(so, "87654321").expect("init_pin");
        native::logout(so).expect("logout SO");
        native::close_session(so).expect("close SO session");

        let ok_count = Arc::new(AtomicU64::new(0));
        let already_count = Arc::new(AtomicU64::new(0));
        let unexpected = Arc::new(AtomicU64::new(0));

        std::thread::scope(|scope| {
            for _ in 0..THREADS {
                let ok_count = Arc::clone(&ok_count);
                let already_count = Arc::clone(&already_count);
                let unexpected = Arc::clone(&unexpected);
                scope.spawn(move || {
                    let session = open_session_only(slot);
                    let mut pin: Vec<u8> = b"87654321".to_vec();
                    const CKU_USER: u32 = 1;
                    let rv = softhsmrustv3::ffi::C_Login(
                        session,
                        CKU_USER,
                        pin.as_mut_ptr(),
                        pin.len() as u32,
                    );
                    const CKR_OK: u32 = 0;
                    const CKR_USER_ALREADY_LOGGED_IN: u32 = 0x0000_0100;
                    match rv {
                        CKR_OK => {
                            ok_count.fetch_add(1, Ordering::Relaxed);
                        }
                        CKR_USER_ALREADY_LOGGED_IN => {
                            already_count.fetch_add(1, Ordering::Relaxed);
                        }
                        other => {
                            unexpected.fetch_add(1, Ordering::Relaxed);
                            eprintln!("round {round}: unexpected C_Login rv={other}");
                        }
                    }
                });
            }
        });

        let ok = ok_count.load(Ordering::Relaxed);
        let already = already_count.load(Ordering::Relaxed);
        let bad = unexpected.load(Ordering::Relaxed);

        assert_eq!(bad, 0, "round {round}: {bad} C_Login calls returned an unexpected code");
        assert_eq!(
            ok, 1,
            "round {round}: exactly one thread should win C_Login's exclusivity check, got {ok} \
             (TOCTOU race regressed — see fix in ffi::C_Login)"
        );
        assert_eq!(
            already,
            (THREADS - 1) as u64,
            "round {round}: the other {} threads should all see CKR_USER_ALREADY_LOGGED_IN, got {}",
            THREADS - 1,
            already
        );
    }

    println!(
        "login_exclusivity_holds_under_concurrent_attempts PASS: {ROUNDS} rounds x {THREADS} \
         concurrent C_Login(USER) calls, exactly 1 winner every round"
    );
}
