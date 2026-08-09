//! V3 gate — with `SOFTHSM3_OP_LOG` unset, instrumenting the ABI must not cost
//! the benchmark anything measurable.
//!
//! `hsm-perf-bench` reaches ~62,000 signs/sec through this crate. A logger that
//! costs even a microsecond per operation would move that number, and a
//! published ops/sec figure that silently includes logging overhead is a
//! measurement of the logger.
//!
//! This test does NOT assert a threshold — a wall-clock number on a shared
//! developer machine is too noisy to gate a build on, and a flaky perf
//! assertion gets muted rather than fixed. It prints the rate so the A/B
//! against the pre-instrumentation commit can be done deliberately:
//!
//!   cargo test --release --test oplog_zero_cost -- --nocapture --ignored
//!
//! Run it on this commit and on the parent, with the env var unset both times.
//! Ignored by default because it is a measurement, not a correctness check.

use softhsmrustv3::constants::*;
use softhsmrustv3::{ffi, native, state};

fn mechanism(mech: u32) -> [usize; 3] {
    [mech as usize, 0, 0]
}

#[test]
#[ignore = "measurement, not a correctness check — see module docs"]
fn ml_dsa_sign_rate_with_logging_disabled() {
    // Explicitly unset, not merely assumed: inheriting a set variable from the
    // surrounding shell would measure the logging-ON path and report it as the
    // logging-OFF baseline, which is exactly the mistake this gate exists to
    // prevent.
    // SAFETY: single-threaded, before any engine code has run.
    unsafe { std::env::remove_var(softhsmrustv3::oplog::ENV_VAR) };
    assert!(
        !softhsmrustv3::oplog::enabled(),
        "logging is ON — this run would report the wrong baseline"
    );

    native::init().expect("engine init");
    let slot = 0u32;
    state::ensure_slot(slot);
    native::init_token(slot, "12345678", "bench").expect("init_token");
    let so = native::open_session_so(slot, "12345678").expect("SO session");
    native::init_pin(so, "87654321").expect("init_pin");
    native::logout(so).expect("logout SO");
    native::close_session(so).expect("close SO session");
    let sess = native::open_session(slot, "87654321").expect("user session");
    let (_pubh, privh) =
        native::generate_ml_dsa_keypair(sess, CKP_ML_DSA_65, b"bn", "bench-mldsa65")
            .expect("keygen");

    let msg = b"zero-cost check";
    const N: u32 = 3000;

    // Warm up so the first-call OnceLock resolution and any lazy allocation
    // land outside the measured window.
    for _ in 0..50 {
        one_sign(sess, privh, msg);
    }

    let start = std::time::Instant::now();
    for _ in 0..N {
        one_sign(sess, privh, msg);
    }
    let elapsed = start.elapsed();

    let per_op_ns = elapsed.as_nanos() as f64 / N as f64;
    let ops_per_sec = N as f64 / elapsed.as_secs_f64();
    println!(
        "ML-DSA-65 C_SignInit+C_Sign, logging OFF: {ops_per_sec:.0} ops/sec ({per_op_ns:.0} ns/op) over {N} ops"
    );
}

fn one_sign(sess: u32, privh: u32, msg: &[u8]) {
    let mut mech = mechanism(CKM_ML_DSA);
    let rv = ffi::C_SignInit(sess, mech.as_mut_ptr() as *mut u8, privh);
    assert_eq!(rv, CKR_OK);
    let mut sig = vec![0u8; 4096];
    let mut sig_len: u32 = sig.len() as u32;
    let rv = ffi::C_Sign(
        sess,
        msg.as_ptr() as *mut u8,
        msg.len() as u32,
        sig.as_mut_ptr(),
        &mut sig_len,
    );
    assert_eq!(rv, CKR_OK);
}
