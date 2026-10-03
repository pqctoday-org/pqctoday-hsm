//! C1 — two-context variant of `replication_store.rs` (K0B-R2-02 under
//! per-connection application contexts). Own test binary: configuring a
//! store is process-global.
//!
//! Hazard it pins: `C_Logout` re-keys private handles and moves their durable
//! rows. With contexts, a logout in one context must not move a handle that
//! another, still logged-in, context is using — or that context's next commit
//! would write a second row under the old handle. Here two connection
//! contexts and the native context share the source token; contexts log out
//! and are destroyed while another context commits a replication package.
//! After the last logout, and again after a restart from the SQLite store
//! alone, there is still exactly one source object and the budget stays spent.
#![cfg(feature = "educational-replication")]

mod replication_common;
use replication_common::*;

use softhsmrustv3::app_context::{self, ContextGuard, ContextMeta};
use softhsmrustv3::constants::*;
use softhsmrustv3::native;
use softhsmrustv3::replication::{self as repl, asn1::Operation};

const RW: u32 = CKF_SERIAL_SESSION | CKF_RW_SESSION;

fn meta(n: u8) -> ContextMeta {
    ContextMeta {
        role: "user".into(),
        client_cert_sha256: [n; 32],
        listener: "crypto-plane:5696".into(),
        correlation: None,
    }
}

fn user_session(ctx: u64, slot: u32) -> u32 {
    let s = app_context::open_session(ctx, slot, RW).unwrap();
    let mut pin = USER.as_bytes().to_vec();
    assert_eq!(softhsmrustv3::ffi::C_Login(s, CKU_USER, pin.as_mut_ptr(), pin.len() as u32), CKR_OK);
    s
}

#[test]
fn two_contexts_logout_and_restart_keep_one_copy_and_conserve_budget() {
    let _g = lock();
    let dir = std::env::temp_dir().join(format!("pqctoday-repl-store-ctx-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    softhsmrustv3::ffi::reset_all_engine_state_for_test();
    softhsmrustv3::store::configure_persistent_store(&dir).unwrap();
    let mut w = world(2);
    let p = w.enroll_policy_everywhere(&w.policy([true, true, true], 1, test_mechs()));
    let (src, _) = gen_key(w.tokens[0].user, Kp::Aes(32), &p);
    let lineage = native::get_attribute(w.tokens[0].user, src, CKA_PQCTODAY_REPLICATION_LINEAGE_ID).unwrap();
    let src_uid = uid(w.tokens[0].user, src);
    let slot0 = w.tokens[0].slot;

    // Two connection contexts log in on the source token beside the native one.
    let a = ContextGuard::new(meta(1));
    let b = ContextGuard::new(meta(2));
    let sa = user_session(a.id(), slot0);
    let sb = user_session(b.id(), slot0);
    assert!(native::get_attribute(sa, src, CKA_UNIQUE_ID).is_some(), "A sees the source");
    assert!(native::get_attribute(sb, src, CKA_UNIQUE_ID).is_some(), "B sees the source");

    // A logs out and is destroyed; three more contexts log in, out, and go.
    // Others stay logged in throughout, so the source handle must not move.
    native::logout(sa).unwrap();
    drop(a);
    for n in 3..6 {
        let c = ContextGuard::new(meta(n));
        let sc = user_session(c.id(), slot0);
        native::logout(sc).unwrap();
    }
    assert_eq!(by_uid(&src_uid), Some(src), "no re-key while another context is logged in");
    assert_eq!(replicas_with_lineage(slot0, &lineage), 1);

    // B commits with the handle it has held all along.
    let chal = repl::issue_source_challenge(sb).expect("source challenge in context B");
    let req = repl::begin_receive(w.tokens[1].user, Operation::LiveClone, &chal, &DOMAIN, &p).expect("begin receive");
    let pkg = repl::create_replication_package(sb, src, &req).expect("B's handle is still valid");
    let (_, receipt) = repl::import_replication_package(w.tokens[1].user, &pkg, &[]).unwrap();

    // The last logouts on the slot re-key once and move the durable row once.
    native::logout(sb).unwrap();
    drop(b);
    assert_eq!(by_uid(&src_uid), Some(src), "the native context is still logged in");
    native::logout(w.tokens[0].user).unwrap();
    let mut pin = USER.as_bytes().to_vec();
    assert_eq!(softhsmrustv3::ffi::C_Login(w.tokens[0].user, CKU_USER, pin.as_mut_ptr(), pin.len() as u32), CKR_OK);
    assert_eq!(replicas_with_lineage(slot0, &lineage), 1, "exactly one bound source object after the re-key");
    let src = by_uid(&src_uid).unwrap();
    assert!(
        repl::create_replication_package(w.tokens[0].user, src, &request(&w, 0, 1, Operation::LiveClone, &p)).is_err(),
        "budget 1 spent"
    );
    assert_eq!(app_context::context_count(), 0);

    // Restart from the SQLite store alone.
    softhsmrustv3::ffi::reset_all_engine_state_for_test();
    let _ = native::finalize();
    softhsmrustv3::store::configure_persistent_store(&dir).unwrap();
    native::init().unwrap();
    for t in w.tokens.iter_mut() {
        t.user = native::open_session(t.slot, USER).expect("login after restart");
    }
    assert_eq!(replicas_with_lineage(0, &lineage), 1, "one source after restart");
    assert_eq!(replicas_with_lineage(1, &lineage), 1, "one replica after restart");
    let (_, again) = repl::import_replication_package(w.tokens[1].user, &pkg, &[]).expect("exact retry recovers");
    assert_eq!(again, receipt, "byte-identical receipt from the durable ledger");
    let src = by_uid(&src_uid).unwrap();
    assert!(
        repl::create_replication_package(w.tokens[0].user, src, &request(&w, 0, 1, Operation::LiveClone, &p)).is_err(),
        "the spent budget survived the restart"
    );

    softhsmrustv3::store::configure(std::sync::Arc::new(softhsmrustv3::store::MemoryStore));
    let _ = std::fs::remove_dir_all(&dir);
}
