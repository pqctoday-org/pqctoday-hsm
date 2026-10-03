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
