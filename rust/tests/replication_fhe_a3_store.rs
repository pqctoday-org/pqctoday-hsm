//! FHE decrypt counters across an engine restart (plan D02387 WP-A3; spec
//! docs/proposals/pkcs11-ckm-pqctoday-fhe-proposal.md §6.4, §10 gate 5) under the durable SQLite store. Own test
//! binary: configuring a store is process-global.
#![cfg(all(pqc_ckks_custody, feature = "test-support"))]

mod replication_common;
use replication_common::*;

use der::Encode;
use softhsmrustv3::constants::*;
use softhsmrustv3::native;
use softhsmrustv3::replication::fhe_ckks::{mech, params, spec::Generator};
use softhsmrustv3::replication::fhe_custody::{self as fc, DecryptOutput};
use softhsmrustv3::replication::{self as repl, fhe, records};

const PS: u32 = 0x8002;
const OWNER: [u8; 48] = [0; 48];

fn counter(h: u32) -> u64 {
    records::object_attrs(h).and_then(|a| a.get(&fc::CKA_PRIV_FHE_DECRYPT_COUNT).map(|v| u64::from_le_bytes(v.as_slice().try_into().unwrap()))).unwrap_or(0)
}

/// Every unit spent before a restart, released or refused, is still spent after it: the counter is reserved durably,
/// in the same store commit, before any decryption work (§6.4). The seed is still not destroyable after the restart,
/// and the budget runs out exactly at maxDecrypts across the two engine lifetimes.
#[test]
fn decrypt_counter_survives_an_engine_restart() {
    let _g = lock();
    let dir = std::env::temp_dir().join(format!("pqctoday-fhe-a3-store-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    softhsmrustv3::ffi::reset_all_engine_state_for_test();
    softhsmrustv3::store::configure_persistent_store(&dir).unwrap();
    let mut w = world(1);
    let ps = params::find(PS).unwrap();
    let rp = records::build_policy_with_constraint(
        DOMAIN, [true, true, true], w.device_ids(), w.now - 60, w.now + 30 * 86_400, 4,
        vec![CKM_PQCTODAY_FHE_DERIVE_PUBLIC, CKM_PQCTODAY_FHE_DECRYPT], false, fhe::ckks_profile_constraint_hash(),
    )
    .unwrap();
    let dp = fhe::FheDecryptPolicy {
        version: 2,
        allowed_output_types: vec![mech::release_type(ps)],
        never_release: vec![],
        predicates: vec![],
        recipients: vec![],
        recipient_only: false,
        max_decrypts: 4,
        ckks: Some(fhe::CkksReleasePolicy { max_values: (ps.n() / 2) as u32, precision_bits: 20, value_bound_log2: 10, scale_log2: ps.log_default_scale as u8, flood_recipients: true, flood_owner: false, stat_security_bits: 30 }),
    }
    .to_der()
    .unwrap();
    let (rpid, dpid) = w.as_so(0, |so| (repl::enroll_policy(so, &rp).unwrap(), fhe::enroll_fhe_decrypt_policy(so, &dp).unwrap()));
    let seed_value = [31u8; 32];
    let s = w.tokens[0].user;
    let h = fhe::generate_fhe_seed_with_value_for_test(s, PS, &rpid, &dpid, &seed_value, b"restart").expect("KEY_GEN");
    let m: Vec<i128> = (0..ps.n() as i128).map(|i| ((i % 7) - 3) << 20).collect();
    let (c0, c1) = Generator::new(ps, &seed_value).encrypt_for_test(0, &m, &[5u8; 32]).unwrap();
    let mut ct = mech::CT_MAGIC.to_vec();
    for v in [PS, 0, ps.log_default_scale as u32, 0] {
        ct.extend_from_slice(&v.to_le_bytes());
    }
    for v in c0.iter().chain(&c1) {
        ct.extend_from_slice(&v.to_le_bytes());
    }
    let release = |s: u32, h: u32| fc::decrypt(s, h, &OWNER, &ct, false).map(|(_, o)| matches!(o, Some(DecryptOutput::Owner(_))));

    // Before the restart: one release and one refusal (an unenrolled recipient), two units.
    assert_eq!(release(s, h), Ok(true));
    assert_eq!(fc::decrypt(s, h, &[5u8; 48], &ct, false).map(|_| ()), Err(CKR_ACTION_PROHIBITED));
    assert_eq!(counter(h), 2);

    // Restart from the SQLite store alone.
    softhsmrustv3::ffi::reset_all_engine_state_for_test();
    let _ = native::finalize();
    softhsmrustv3::store::configure_persistent_store(&dir).unwrap();
    repl::select_educational_profile();
    native::init().unwrap();
    for t in w.tokens.iter_mut() {
        t.user = native::open_session(t.slot, USER).expect("login after restart");
    }
    let s = w.tokens[0].user;
    let found = native::find_all_by_cka_id(s, b"restart").unwrap();
    assert_eq!(found.len(), 1, "one seed after the restart");
    let h = found[0];
    assert_eq!(counter(h), 2, "both units survived the restart");
    assert_eq!(native::get_attribute_bool(s, h, CKA_DESTROYABLE), Some(false));
    assert_eq!(softhsmrustv3::ffi::C_DestroyObject(s, h), CKR_ACTION_PROHIBITED, "still not destroyable");

    // The two remaining units, then the budget is exhausted.
    assert_eq!(release(s, h), Ok(true));
    assert_eq!(release(s, h), Ok(true));
    assert_eq!(counter(h), 4);
    assert_eq!(release(s, h), Err(CKR_ACTION_PROHIBITED));
    assert_eq!(repl::last_refusal(), Some("decrypt budget exhausted"));

    // A second restart: still exhausted.
    softhsmrustv3::ffi::reset_all_engine_state_for_test();
    let _ = native::finalize();
    softhsmrustv3::store::configure_persistent_store(&dir).unwrap();
    repl::select_educational_profile();
    native::init().unwrap();
    let s = native::open_session(0, USER).expect("login after the second restart");
    let h = native::find_all_by_cka_id(s, b"restart").unwrap()[0];
    assert_eq!(counter(h), 4);
    assert_eq!(release(s, h), Err(CKR_ACTION_PROHIBITED));

    softhsmrustv3::store::configure(std::sync::Arc::new(softhsmrustv3::store::MemoryStore));
    let _ = std::fs::remove_dir_all(&dir);
}
