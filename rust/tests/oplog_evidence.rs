//! V2 gate — the Rust engine's operation-evidence log actually emits, and emits
//! the same grammar the C++ engine does.
//!
//! This is an INTEGRATION test on purpose, not a unit test. `oplog`'s sink is a
//! process-wide `OnceLock` resolved from `SOFTHSM3_OP_LOG` the first time
//! anything asks whether logging is enabled. A unit test inside the crate would
//! share that resolution with the other 300-odd tests in the same binary — the
//! first one to touch the engine would pin the sink to "disabled" and this
//! check would silently pass while proving nothing. An integration test gets
//! its own process, so setting the variable here is the first and only word on
//! the subject.
//!
//! For the same reason there is no "logging off produces nothing" case here: it
//! cannot share a process with the "logging on" case. That half is covered
//! against the C++ engine, where it is verifiable from a separate run.

use softhsmrustv3::constants::*;
use softhsmrustv3::{ffi, native, state};

/// Build the packed CK_MECHANISM the `ffi::*` layer expects: the mechanism
/// field is a native-width CK_ULONG (read as its low 4 bytes, little-endian),
/// followed by the parameter pointer and length as `usize`. Matches how
/// `ffi::C_SignInit` itself parses it (`*(p as *const u32)`, then
/// `*((p as *const usize).add(1))`).
fn mechanism(mech: u32) -> [usize; 3] {
    [mech as usize, 0, 0]
}

#[test]
fn rust_engine_emits_pqcev_records_for_ml_dsa_signing() {
    let dir = std::env::temp_dir().join(format!("pqcev-rust-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let log_path = dir.join("hsm-ops.log");
    // SAFETY: single-threaded, before any engine code has run, so nothing can
    // be reading the environment concurrently.
    unsafe { std::env::set_var(softhsmrustv3::oplog::ENV_VAR, &log_path) };

    assert!(
        softhsmrustv3::oplog::enabled(),
        "sink did not open — the rest of this test would pass vacuously"
    );

    native::init().expect("engine init");
    let slot = 0u32;
    state::ensure_slot(slot);
    native::init_token(slot, "12345678", "evidence").expect("init_token");
    let so = native::open_session_so(slot, "12345678").expect("SO session");
    native::init_pin(so, "87654321").expect("init_pin");
    native::logout(so).expect("logout SO");
    native::close_session(so).expect("close SO session");
    let sess = native::open_session(slot, "87654321").expect("user session");

    let (_pubh, privh) =
        native::generate_ml_dsa_keypair(sess, CKP_ML_DSA_65, b"ev", "evidence-mldsa65")
            .expect("keygen");

    // Drive the INSTRUMENTED entry points, not the native::* helpers — the
    // wrappers under test sit on ffi::C_*.
    let mut mech = mechanism(CKM_ML_DSA);
    let rv = ffi::C_SignInit(sess, mech.as_mut_ptr() as *mut u8, privh);
    assert_eq!(rv, CKR_OK, "C_SignInit");

    let msg = b"rust operation-evidence smoke test";
    let mut sig_len: u32 = 0;
    let rv = ffi::C_Sign(
        sess,
        msg.as_ptr() as *mut u8,
        msg.len() as u32,
        std::ptr::null_mut(),
        &mut sig_len,
    );
    assert_eq!(rv, CKR_OK, "C_Sign length query");
    let mut sig = vec![0u8; sig_len as usize];
    let rv = ffi::C_Sign(
        sess,
        msg.as_ptr() as *mut u8,
        msg.len() as u32,
        sig.as_mut_ptr(),
        &mut sig_len,
    );
    assert_eq!(rv, CKR_OK, "C_Sign");
    assert_eq!(sig_len, 3309, "ML-DSA-65 signature length (FIPS 204 Table 2)");

    let log = std::fs::read_to_string(&log_path).expect("evidence log readable");
    let records: Vec<&str> = log.lines().filter(|l| l.starts_with("PQCEV ")).collect();
    assert!(
        !records.is_empty(),
        "no PQCEV records were written to {log_path:?}"
    );

    // The init record must name the mechanism, the key, and the parameter set —
    // those three are what make a claim like "ML-DSA-65 signed inside the
    // token" checkable rather than asserted.
    let init = records
        .iter()
        .find(|r| r.contains("op=C_SignInit"))
        .unwrap_or_else(|| panic!("no C_SignInit record in:\n{log}"));
    for expected in [
        "mech=CKM_ML_DSA",
        "mech_id=0x0000001d",
        "key=evidence-mldsa65",
        "paramset=ML-DSA-65",
        "rv=CKR_OK",
    ] {
        assert!(init.contains(expected), "C_SignInit missing {expected}: {init}");
    }

    // Two C_Sign records: the mandatory length query and the real signature.
    // The probe flag is what lets a consumer count signatures without doubling.
    let signs: Vec<&&str> = records
        .iter()
        .filter(|r| r.contains("op=C_Sign "))
        .collect();
    assert_eq!(signs.len(), 2, "expected a probe and a real sign: {signs:?}");
    assert!(
        signs.iter().any(|r| r.contains("probe=1")),
        "no length-query record"
    );
    let real = signs
        .iter()
        .find(|r| r.contains("probe=0"))
        .expect("no real signature record");
    assert!(
        real.contains("out=3309"),
        "signature size not reported as measured: {real}"
    );

    // The join key the consumer relies on: C_Sign carries no mechanism, so it
    // is paired to its C_SignInit by (pid, sess). Both must carry both fields.
    for r in [init, real] {
        assert!(r.contains(&format!("sess={sess}")), "missing sess=: {r}");
        assert!(r.contains("pid="), "missing pid=: {r}");
        assert!(r.starts_with("PQCEV v=1 ts="), "grammar drift: {r}");
    }

    let _ = std::fs::remove_dir_all(&dir);
}
