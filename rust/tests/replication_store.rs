//! K4 under the durable SQLite store (review K0B-R2-02, K0B-R2-03). Own test
//! binary: configuring a store is process-global.
#![cfg(feature = "educational-replication")]

mod replication_common;
use replication_common::*;

use softhsmrustv3::constants::*;
use softhsmrustv3::native;
use softhsmrustv3::replication::{self as repl, asn1::Operation};

fn relogin(w: &World, i: usize) {
    let t = &w.tokens[i];
    native::logout(t.user).unwrap();
    let mut pin = USER.as_bytes().to_vec();
    assert_eq!(softhsmrustv3::ffi::C_Login(t.user, CKU_USER, pin.as_mut_ptr(), pin.len() as u32), CKR_OK);
}

#[test]
fn store_relogin_and_restart_keep_one_copy_and_conserve_budget() {
    let _g = lock();
    let dir = std::env::temp_dir().join(format!("pqctoday-repl-store-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    softhsmrustv3::ffi::reset_all_engine_state_for_test();
    softhsmrustv3::store::configure_persistent_store(&dir).unwrap();
    let mut w = world(2);
    let p = w.enroll_policy_everywhere(&w.policy([true, true, true], 1, test_mechs()));
    let (src, _) = gen_key(w.tokens[0].user, Kp::Aes(32), &p);
    let lineage = native::get_attribute(w.tokens[0].user, src, CKA_PQCTODAY_REPLICATION_LINEAGE_ID).unwrap();
    let src_uid = uid(w.tokens[0].user, src);

    // R2-02: logout re-keys private handles; the next login must not
    // rehydrate a second copy from the store.
    for _ in 0..3 {
        relogin(&w, 0);
    }
    assert_eq!(replicas_with_lineage(0, &lineage), 1, "exactly one bound source object after relogins");
    let src = by_uid(&src_uid).unwrap();
    let req = request(&w, 0, 1, Operation::LiveClone, &p);
    let pkg = repl::create_replication_package(w.tokens[0].user, src, &req).unwrap();
    let (_, receipt) = repl::import_replication_package(w.tokens[1].user, &pkg, &[]).unwrap();
    assert!(repl::create_replication_package(w.tokens[0].user, src, &request(&w, 0, 1, Operation::LiveClone, &p)).is_err(), "budget 1 spent");

    // R2-03: restart from the SQLite store alone.
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
