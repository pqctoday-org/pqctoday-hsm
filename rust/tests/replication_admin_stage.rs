//! Admin addendum A-03 (stage + common commit) and the BeginReceive length
//! function (§2.2): staging changes nothing, `resultDigest`/output follow
//! §3.6, and sizing is exact and side-effect free.
#![cfg(all(feature = "educational-replication", feature = "test-support"))]

mod replication_common;
use replication_common::*;

use sha2::Digest;
use softhsmrustv3::constants::*;
use softhsmrustv3::replication::{self as repl, asn1::Operation, oids::Purpose};

fn sha384(b: &[u8]) -> [u8; 48] {
    sha2::Sha384::digest(b).into()
}

/// Every object in the engine, by handle → attribute count: a stage must
/// leave this byte-for-byte unchanged.
fn snapshot() -> Vec<(u32, usize)> {
    let mut v: Vec<(u32, usize)> = softhsmrustv3::state::OBJECTS.with(|o| o.borrow().iter().map(|(h, a)| (*h, a.len())).collect());
    v.sort_unstable();
    v
}

#[test]
fn a03_stages_write_nothing_and_commit_applies_the_effect() {
    let _g = lock();
    let mut w = world(2);
    let slot = w.tokens[0].slot;
    let policy = w.policy([true, true, true], 3, test_mechs());
    // A newer root CRL (the fixture enrolled one at now-10).
    let crl = w.ca.crl(w.now - 5, w.now + 7 * 86_400).unwrap();

    w.as_so(0, |so| {
        // enrollPolicy: output = resultDigest = policy ID.
        let before = snapshot();
        let st = repl::stage_enroll_policy(slot, &policy).unwrap();
        assert_eq!(snapshot(), before, "stage_enroll_policy wrote state");
        let id = st.result_digest;
        assert_eq!(st.output.as_deref(), Some(&id[..]));
        let (out, digest) = repl::commit_staged(so, slot, st, Vec::new(), Vec::new()).unwrap();
        assert_eq!((out.unwrap(), digest), (id.to_vec(), id));
        assert_eq!(repl::enroll_policy(so, &policy).unwrap(), id, "public call agrees and stays idempotent");
        // Re-staging identical DER stages nothing.
        let again = repl::stage_enroll_policy(slot, &policy).unwrap();
        assert!(again.new_objects.is_empty() && again.updates.is_empty());

        // enrollCrl: resultDigest = SHA-384(CRL DER).
        let before = snapshot();
        let st = repl::stage_enroll_crl(slot, &crl, None).unwrap();
        assert_eq!(snapshot(), before, "stage_enroll_crl wrote state");
        assert_eq!(st.result_digest, sha384(&crl));
        repl::commit_staged(so, slot, st, Vec::new(), Vec::new()).unwrap();
        assert_eq!(repl::enroll_crl(so, &crl, None), Err(CKR_ACTION_PROHIBITED), "same CRL number again is a rollback");

        // issueDeviceCrl: output = CRL DER, resultDigest = its SHA-384.
        let before = snapshot();
        let st = repl::stage_issue_device_crl(slot, &[], &[], 3_600).unwrap();
        assert_eq!(snapshot(), before, "stage_issue_device_crl wrote state");
        let crl_out = st.output.clone().unwrap();
        assert_eq!(st.result_digest, sha384(&crl_out));
        repl::commit_staged(so, slot, st, Vec::new(), Vec::new()).unwrap();
        assert_eq!(repl::own_device_crl(so).unwrap(), crl_out);

        // rotateRecoveryKey: resultDigest = SHA-384(new recovery certificate).
        let old = repl::function_certificate(so, Purpose::RecoveryRecipient).unwrap();
        let before = snapshot();
        let st = repl::stage_rotate_recovery_key(slot).unwrap();
        assert_eq!(snapshot(), before, "stage_rotate_recovery_key wrote state");
        let digest = st.result_digest;
        repl::commit_staged(so, slot, st, Vec::new(), Vec::new()).unwrap();
        let new = repl::function_certificate(so, Purpose::RecoveryRecipient).unwrap();
        assert_ne!(new, old);
        assert_eq!(digest, sha384(&new));
    });
}

#[test]
fn a03_a_failed_stage_changes_nothing() {
    let _g = lock();
    let w = world(1);
    let slot = w.tokens[0].slot;
    w.as_so(0, |_| {
        let before = snapshot();
        assert_eq!(repl::stage_issue_device_crl(slot, &[Purpose::DeviceIssuer], &[], 60).err(), Some(CKR_ACTION_PROHIBITED));
        assert_eq!(repl::stage_enroll_crl(slot, b"not a crl", None).err(), Some(CKR_SIGNATURE_INVALID));
        assert_eq!(repl::stage_enroll_policy(slot, b"\x30\x00").err(), Some(CKR_DATA_INVALID));
        assert_eq!(snapshot(), before);
    });
}

#[test]
fn begin_receive_len_is_exact_and_side_effect_free() {
    let _g = lock();
    let w = world(2);
    let p = w.enroll_policy_everywhere(&w.policy([true, true, true], 3, test_mechs()));
    let (src, dst) = (w.tokens[0].user, w.tokens[1].user);
    for op in [Operation::LiveClone, Operation::OfflineBackup, Operation::Restore] {
        let chal = repl::issue_source_challenge(src).unwrap();
        let before = snapshot();
        let n = repl::begin_receive_len(dst, op, &chal, &DOMAIN, &p).unwrap();
        assert_eq!(snapshot(), before, "{op:?}: sizing changed the token");
        let der = repl::begin_receive(dst, op, &chal, &DOMAIN, &p).unwrap();
        assert_eq!(n, der.len(), "{op:?}: sizing is exact");
    }
    // Same refusals as the real call.
    let chal = repl::issue_source_challenge(src).unwrap();
    assert_eq!(repl::begin_receive_len(dst, Operation::LiveClone, &chal, &[0x11; 32], &p), Err(CKR_ACTION_PROHIBITED));
    assert_eq!(repl::begin_receive_len(dst, Operation::LiveClone, &[0; 32], &DOMAIN, &p), Err(CKR_ARGUMENTS_BAD));
    assert_eq!(repl::begin_receive_len(dst, Operation::LiveClone, &chal, &DOMAIN, &[7; 48]), Err(CKR_ACTION_PROHIBITED));
}

#[test]
fn a14_reissue_rotates_all_five_and_keeps_continuity() {
    let _g = lock();
    let w = world(2);
    let p = w.enroll_policy_everywhere(&w.policy([true, true, true], 4, test_mechs()));
    let slot0 = w.tokens[0].slot;
    // An offline backup sealed to token 0's CURRENT recovery key, in flight
    // across the re-issuance.
    let (src, _) = gen_key(w.tokens[1].user, Kp::Aes(32), &p);
    let backup = repl::create_replication_package(w.tokens[1].user, src, &request(&w, 1, 0, Operation::OfflineBackup, &p)).unwrap();

    let old: Vec<Vec<u8>> = Purpose::LEAVES.iter().map(|p| repl::function_certificate(w.tokens[0].user, *p).unwrap()).collect();
    let digest = w.as_so(0, |so| {
        let before = snapshot();
        let st = repl::stage_reissue_function_certificates(slot0).unwrap();
        assert_eq!(snapshot(), before, "stage_reissue wrote state");
        let (_, d) = repl::commit_staged(so, slot0, st, Vec::new(), Vec::new()).unwrap();
        d
    });
    let new: Vec<Vec<u8>> = Purpose::LEAVES.iter().map(|p| repl::function_certificate(w.tokens[0].user, *p).unwrap()).collect();
    for (o, n) in old.iter().zip(&new) {
        assert_ne!(o, n, "every purpose re-issued");
    }
    assert_eq!(digest, sha384(&new.concat()), "resultDigest = SHA-384(5 new leaves in purpose order)");
    assert!(repl::hierarchy_ready(slot0), "enrollment stays complete");

    // T1: the retired recovery key still opens the in-flight backup.
    repl::import_replication_package(w.tokens[0].user, &backup, &[]).expect("backup sealed to the retired recovery key imports");
    // New keys work end to end: live clone 0 → 1 under the re-issued chain.
    let (k0, _) = gen_key(w.tokens[0].user, Kp::MlDsa, &p);
    let pkg = repl::create_replication_package(w.tokens[0].user, k0, &request(&w, 0, 1, Operation::LiveClone, &p)).unwrap();
    repl::import_replication_package(w.tokens[1].user, &pkg, &[]).expect("peer accepts the re-issued chain");

    // T2 + A-15: the next device CRL continues the number, may revoke a
    // RETIRED leaf by DER, and the peer accepts it.
    let dev0 = repl::device_certificate(w.tokens[0].user).unwrap();
    let crl = w.as_so(0, |so| repl::issue_device_crl_with(so, &[], &[old[1].clone()], 3_600).expect("revoke the retired package-signing leaf"));
    w.as_so(1, |so| repl::enroll_crl(so, &crl, Some(&dev0)).expect("peer accepts the continued CRL number"));
}

#[test]
fn a15_revoke_by_der_only_for_retained_retired_certificates() {
    let _g = lock();
    let w = world(2);
    let active = repl::function_certificate(w.tokens[0].user, Purpose::PackageSigning).unwrap();
    let foreign = repl::function_certificate(w.tokens[1].user, Purpose::PackageSigning).unwrap();
    w.as_so(0, |so| {
        assert_eq!(repl::issue_device_crl_with(so, &[], &[active.clone()], 60), Err(CKR_ACTION_PROHIBITED), "active certificate");
        assert_eq!(repl::issue_device_crl_with(so, &[], &[foreign.clone()], 60), Err(CKR_ACTION_PROHIBITED), "another device's certificate");
        assert_eq!(repl::issue_device_crl_with(so, &[], &[b"junk".to_vec()], 60), Err(CKR_DATA_INVALID), "not a certificate");
        repl::reissue_function_certificates(so).unwrap();
        // Now the old leaf is retired and retained: allowed.
        repl::issue_device_crl_with(so, &[], &[active.clone()], 60).expect("retired and retained");
    });
}
