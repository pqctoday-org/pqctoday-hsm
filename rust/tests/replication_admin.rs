//! Admin addendum 1.0 (draft 3.2) — signed admin requests end to end: every
//! operation, the §3.2 verification order and its refusals, exact retry,
//! sizing, the B2 root-CRL renewal path, authority replacement and ledger
//! pruning. Receipts are checked with the host verifier (public bytes only).
#![cfg(all(feature = "educational-replication", feature = "test-support"))]

mod replication_common;
use replication_common::*;

use sha2::Digest;
use softhsmrustv3::constants::*;
use softhsmrustv3::native;
use softhsmrustv3::replication::admin::{self, AdminOperation, RevocablePurpose};
use softhsmrustv3::replication::{self as repl, admin_host, host_verify, oids::Purpose, test_ca::AdminAuthorityKey, Profile};

fn sha384(b: &[u8]) -> [u8; 48] {
    sha2::Sha384::digest(b).into()
}

struct Admin {
    key: AdminAuthorityKey,
    device_id: [u8; 32],
}

fn setup(w: &World) -> Admin {
    let key = AdminAuthorityKey::new(&w.ca, w.now).unwrap();
    w.as_so(0, |so| admin::enroll_admin_authority(so, &key.cert_der).expect("enroll admin authority"));
    Admin { key, device_id: repl::device_id(w.tokens[0].user).unwrap() }
}

/// A signed request for `op` with an explicit nonce and sequence.
fn signed(a: &Admin, key: &AdminAuthorityKey, nonce: &[u8; 32], seq: u64, op: &AdminOperation) -> Vec<u8> {
    let tbs = admin_host::tbs_request(&a.device_id, &key.key_id(), nonce, seq, 1_790_000_000, op).unwrap();
    let sig = key.sign(&admin_host::request_signed_bytes(&tbs)).unwrap();
    admin_host::signed_request(&tbs, &sig).unwrap()
}

/// Issue a nonce and execute `op` at `seq` as SO on token 0.
fn run(w: &World, a: &Admin, seq: u64, op: &AdminOperation) -> (Vec<u8>, Result<Vec<u8>, u32>) {
    w.as_so(0, |so| {
        let n = admin::issue_nonce(so).unwrap();
        let req = signed(a, &a.key, &n, seq, op);
        let r = admin::execute(so, &req);
        (req, r)
    })
}

fn verify(w: &World, receipt: &[u8], req: &[u8]) -> Result<host_verify::AdminReceiptView, &'static str> {
    host_verify::verify_admin_receipt(receipt, req, &repl::trust_inputs(w.tokens[0].slot), w.now, Profile::Educational).map_err(|r| r.0)
}

#[test]
fn admin_every_operation_commits_and_its_receipt_verifies() {
    let _g = lock();
    let mut w = world(2);
    let a = setup(&w);

    // enrollPolicy: resultDigest = output = policy ID.
    let pol = w.policy([true, true, true], 2, test_mechs());
    let (req, r) = run(&w, &a, 1, &AdminOperation::EnrollPolicy { policy: pol.clone() });
    let v = verify(&w, &r.unwrap(), &req).expect("receipt verifies");
    assert_eq!(v.sequence, 1);
    assert_eq!(Some(v.result_digest.to_vec()), v.output);
    let id = w.as_so(0, |so| repl::enroll_policy(so, &pol).unwrap());
    assert_eq!(v.result_digest, id, "the policy is enrolled");

    // rotateRecoveryKey: resultDigest = SHA-384(new recovery certificate).
    let (req, r) = run(&w, &a, 2, &AdminOperation::RotateRecoveryKey);
    let v = verify(&w, &r.unwrap(), &req).unwrap();
    assert_eq!(v.result_digest, sha384(&repl::function_certificate(w.tokens[0].user, Purpose::RecoveryRecipient).unwrap()));

    // issueFunctionCerts: the OUTGOING receipt key signs (B-01), and its
    // receipt still verifies while that key is only retired.
    let old_receipt_leaf = repl::function_certificate(w.tokens[0].user, Purpose::ReceiptSigning).unwrap();
    let (req3, r3) = run(&w, &a, 3, &AdminOperation::IssueFunctionCerts);
    let r3 = r3.unwrap();
    let new: Vec<Vec<u8>> = Purpose::LEAVES.iter().map(|p| repl::function_certificate(w.tokens[0].user, *p).unwrap()).collect();
    let v = verify(&w, &r3, &req3).expect("signed by the outgoing, merely retired key");
    assert_eq!(v.result_digest, sha384(&new.concat()));

    // issueDeviceCrl: revoke that retired receipt leaf by DER; output = CRL.
    let (req, r) = run(&w, &a, 4, &AdminOperation::IssueDeviceCrl { revoke: vec![], retired_to_revoke: vec![old_receipt_leaf], validity_seconds: 3_600 });
    let v = verify(&w, &r.unwrap(), &req).unwrap();
    let crl = v.output.clone().unwrap();
    assert_eq!(v.result_digest, sha384(&crl));
    assert_eq!(repl::own_device_crl(w.tokens[0].user).unwrap(), crl);
    // §3.6: receipts are judged against CURRENT CRLs — #3's signer is now listed.
    assert!(verify(&w, &r3, &req3).is_err(), "a listed signer fails whatever committedAt says");

    // enrollCrl: a newer root CRL.
    let root_crl = w.ca.crl(w.now - 5, w.now + 7 * 86_400).unwrap();
    let (req, r) = run(&w, &a, 5, &AdminOperation::EnrollCrl { crl: root_crl.clone(), issuer_device_cert: None });
    assert_eq!(verify(&w, &r.unwrap(), &req).unwrap().result_digest, sha384(&root_crl));
}

#[test]
fn admin_retry_is_byte_identical_and_sizing_changes_nothing() {
    let _g = lock();
    let w = world(1);
    let a = setup(&w);
    let pol = w.policy([true, true, true], 2, test_mechs());
    let op = AdminOperation::EnrollPolicy { policy: pol };
    w.as_so(0, |so| {
        let n = admin::issue_nonce(so).unwrap();
        let req = signed(&a, &a.key, &n, 1, &op);
        let len = admin::execute_len(so, &req).unwrap();
        let again = admin::execute_len(so, &req).unwrap();
        assert_eq!(len, again, "sizing consumed neither nonce nor sequence");
        let receipt = admin::execute(so, &req).unwrap();
        assert_eq!(receipt.len(), len, "sizing is exact");
        // Exact retry after the commit: no nonce or sequence check applies.
        assert_eq!(admin::execute(so, &req).unwrap(), receipt);
        assert_eq!(admin::execute_len(so, &req).unwrap(), receipt.len());
        // The consumed nonce cannot carry a NEW request.
        let req2 = signed(&a, &a.key, &n, 2, &AdminOperation::RotateRecoveryKey);
        assert_eq!(admin::execute(so, &req2), Err(CKR_ACTION_PROHIBITED));
    });
}

#[test]
fn admin_refusals_follow_the_verification_order() {
    let _g = lock();
    let w = world(2);
    let a = setup(&w);
    let op = AdminOperation::RotateRecoveryKey;
    w.as_so(0, |so| {
        let n = admin::issue_nonce(so).unwrap();
        // Replaced nonce.
        let n2 = admin::issue_nonce(so).unwrap();
        assert_eq!(admin::execute(so, &signed(&a, &a.key, &n, 1, &op)), Err(CKR_ACTION_PROHIBITED), "replaced nonce");
        // Expired nonce (60 s monotonic).
        admin::expire_nonce_for_test(w.tokens[0].slot);
        assert_eq!(admin::execute(so, &signed(&a, &a.key, &n2, 1, &op)), Err(CKR_ACTION_PROHIBITED), "expired nonce");
        let n = admin::issue_nonce(so).unwrap();
        // Sequence gap and replayed sequence.
        assert_eq!(admin::execute(so, &signed(&a, &a.key, &n, 2, &op)), Err(CKR_ACTION_PROHIBITED), "sequence gap");
        // Wrong device.
        let other = Admin { key: AdminAuthorityKey::new(&w.ca, w.now).unwrap(), device_id: [9; 32] };
        let tbs = admin_host::tbs_request(&other.device_id, &a.key.key_id(), &n, 1, 0, &op).unwrap();
        let req = admin_host::signed_request(&tbs, &a.key.sign(&admin_host::request_signed_bytes(&tbs)).unwrap()).unwrap();
        assert_eq!(admin::execute(so, &req), Err(CKR_ACTION_PROHIBITED), "another device");
        // Unenrolled admin key (valid certificate under the same root).
        assert_eq!(admin::execute(so, &signed(&a, &other.key, &n, 1, &op)), Err(CKR_ACTION_PROHIBITED), "unenrolled key");
        // Bad signature.
        let mut req = signed(&a, &a.key, &n, 1, &op);
        let last = req.len() - 1;
        req[last] ^= 1;
        assert_eq!(admin::execute(so, &req), Err(CKR_ACTION_PROHIBITED), "signature");
        // B-01: never revoke the active receipt-signing leaf.
        let b01 = AdminOperation::IssueDeviceCrl { revoke: vec![RevocablePurpose::ReceiptSigning], retired_to_revoke: vec![], validity_seconds: 60 };
        assert_eq!(admin::execute(so, &signed(&a, &a.key, &n, 1, &b01)), Err(CKR_ACTION_PROHIBITED), "B-01");
        // Syntax before trust (B-06): junk, and a policy that is not DER.
        assert_eq!(admin::execute(so, b"\x30\x00"), Err(CKR_DATA_INVALID));
        let junk = AdminOperation::EnrollPolicy { policy: b"not a policy".to_vec() };
        assert_eq!(admin::execute(so, &signed(&a, &a.key, &n, 1, &junk)), Err(CKR_DATA_INVALID));
        // None of that consumed the nonce or the sequence.
        admin::execute(so, &signed(&a, &a.key, &n, 1, &op)).expect("the honest request still succeeds");
    });
    // A USER session cannot execute or get a nonce.
    assert_eq!(admin::issue_nonce(w.tokens[0].user), Err(CKR_USER_TYPE_INVALID));
    assert_eq!(admin::execute(w.tokens[0].user, b"\x30\x00"), Err(CKR_USER_TYPE_INVALID));
}

#[test]
fn admin_unsorted_lists_are_malformed() {
    let _g = lock();
    let w = world(1);
    let a = setup(&w);
    w.as_so(0, |so| {
        let n = admin::issue_nonce(so).unwrap();
        // Hand-build an unsorted `revoke` list: the encoder sorts, so swap the
        // two ENUMERATED bytes in the DER afterwards and re-sign.
        let op = AdminOperation::IssueDeviceCrl {
            revoke: vec![RevocablePurpose::KeyAttestation, RevocablePurpose::PackageSigning],
            retired_to_revoke: vec![],
            validity_seconds: 60,
        };
        let mut tbs = admin_host::tbs_request(&a.device_id, &a.key.key_id(), &n, 1, 0, &op).unwrap();
        let pat = [0x0a, 0x01, 0x02, 0x0a, 0x01, 0x03];
        let at = tbs.windows(6).position(|x| x == pat).expect("revoke list");
        tbs[at + 2] = 0x03;
        tbs[at + 5] = 0x02;
        let req = admin_host::signed_request(&tbs, &a.key.sign(&admin_host::request_signed_bytes(&tbs)).unwrap()).unwrap();
        assert_eq!(admin::execute(so, &req), Err(CKR_DATA_INVALID));
    });
}

#[test]
fn admin_revoked_authority_fails_and_root_crl_renewal_avoids_deadlock() {
    let _g = lock();
    let mut w = world(1);
    let a = setup(&w);
    // B2: the stored root CRL (7 days) expires; every other admin call fails
    // closed, but enrolling a NEWER root CRL is evaluated against that CRL.
    repl::set_clock_override(Some(w.now + 8 * 86_400));
    let (_, r) = run(&w, &a, 1, &AdminOperation::RotateRecoveryKey);
    assert_eq!(r, Err(CKR_ACTION_PROHIBITED), "no current root CRL: fail closed");
    let later = w.now + 8 * 86_400;
    let fresh = w.ca.crl(later - 5, later + 7 * 86_400).unwrap();
    let (_, r) = run(&w, &a, 1, &AdminOperation::EnrollCrl { crl: fresh, issuer_device_cert: None });
    r.expect("root CRL renewal is not deadlocked");
    // A newer root CRL that LISTS the admin authority cannot be enrolled by it.
    w.ca.revoke(&a.key.cert_der, later).unwrap();
    let listing = w.ca.crl(later - 4, later + 7 * 86_400).unwrap();
    let (_, r) = run(&w, &a, 2, &AdminOperation::EnrollCrl { crl: listing.clone(), issuer_device_cert: None });
    assert_eq!(r, Err(CKR_ACTION_PROHIBITED), "the new CRL revokes the requester");
    // Once that CRL is enrolled locally, the authority is refused outright.
    w.as_so(0, |so| repl::enroll_crl(so, &listing, None).unwrap());
    let (_, r) = run(&w, &a, 2, &AdminOperation::RotateRecoveryKey);
    assert_eq!(r, Err(CKR_ACTION_PROHIBITED), "revoked authority");
    repl::set_clock_override(Some(w.now));
}

#[test]
fn admin_replacement_and_pruning() {
    let _g = lock();
    let w = world(1);
    let a = setup(&w);
    let pol = w.policy([true, true, true], 2, test_mechs());
    let (req1, r1) = run(&w, &a, 1, &AdminOperation::EnrollPolicy { policy: pol });
    let r1 = r1.unwrap();
    // Enrolment is one-shot; replacement is the board-local step.
    let b = Admin { key: AdminAuthorityKey::new(&w.ca, w.now).unwrap(), device_id: a.device_id };
    w.as_so(0, |so| {
        assert_eq!(admin::enroll_admin_authority(so, &b.key.cert_der), Err(CKR_ACTION_PROHIBITED));
        admin::replace_admin_authority(so, &b.key.cert_der).unwrap();
    });
    let (_, r) = run(&w, &a, 2, &AdminOperation::RotateRecoveryKey);
    assert_eq!(r, Err(CKR_ACTION_PROHIBITED), "the old key no longer authorizes");
    let (_, r) = run(&w, &b, 1, &AdminOperation::RotateRecoveryKey);
    r.expect("the new authority starts at sequence 1");
    // The old authority's committed receipt is still recoverable by retry.
    w.as_so(0, |so| assert_eq!(admin::execute(so, &req1).unwrap(), r1));
    // Pruning after 30 days leaves a tombstone: the retry is now terminal.
    repl::set_clock_override(Some(w.now + 31 * 86_400));
    w.as_so(0, |so| {
        assert!(admin::prune_admin_ledger(so).unwrap() >= 1);
        assert_eq!(admin::execute(so, &req1), Err(CKR_ACTION_PROHIBITED), "tombstone");
    });
    repl::set_clock_override(Some(w.now));
    let _ = native::finalize;
}

#[test]
fn admin_and_ceremony_interfaces_are_discovered_and_callable() {
    use softhsmrustv3::ck_abi::*;
    let _g = lock();
    let w = world(2);
    let a = setup(&w);
    unsafe {
        let mut v10 = CK_VERSION { major: 1, minor: 0 };
        let mut p: CK_INTERFACE_PTR = std::ptr::null_mut();
        let mut admin_name = b"PQCTODAY_KEY_REPLICATION_ADMIN_1_0\0".to_vec();
        assert_eq!(C_GetInterface(admin_name.as_mut_ptr(), &mut v10, &mut p, 0), CKR_OK as CK_RV);
        let af = &*((*p).pFunctionList as *const PQCTODAY_KEY_REPLICATION_ADMIN_FUNCTION_LIST_1_0);
        assert_eq!(af.version, v10);
        let mut cer_name = b"PQCTODAY_KEY_REPLICATION_CEREMONY_1_0\0".to_vec();
        assert_eq!(C_GetInterface(cer_name.as_mut_ptr(), &mut v10, &mut p, 0), CKR_OK as CK_RV);
        let cf = &*((*p).pFunctionList as *const PQCTODAY_KEY_REPLICATION_CEREMONY_FUNCTION_LIST_1_0);
        // Wrong version is refused; the profile gates both.
        let mut v11 = CK_VERSION { major: 1, minor: 1 };
        assert_eq!(C_GetInterface(admin_name.as_mut_ptr(), &mut v11, &mut p, 0), CKR_FUNCTION_FAILED as CK_RV);
        repl::clear_profile();
        assert_eq!(C_GetInterface(cer_name.as_mut_ptr(), &mut v10, &mut p, 0), CKR_FUNCTION_FAILED as CK_RV);
        repl::select_educational_profile();

        // Admin: nonce (sizing first), then execute (sizing, too small, real).
        let pol = w.policy([true, true, true], 2, test_mechs());
        let receipt = w.as_so(0, |so| {
            let so = so as CK_ULONG;
            let mut n = [0u8; 32];
            let mut nl: CK_ULONG = 0;
            assert_eq!((af.C_PQCTODAY_AdminIssueNonce)(so, std::ptr::null_mut(), &mut nl), 0);
            assert_eq!(nl, 32);
            assert_eq!((af.C_PQCTODAY_AdminIssueNonce)(so, n.as_mut_ptr(), &mut nl), 0);
            let mut req = signed(&a, &a.key, &n, 1, &AdminOperation::EnrollPolicy { policy: pol.clone() });
            let mut len: CK_ULONG = 0;
            assert_eq!((af.C_PQCTODAY_AdminExecute)(so, req.as_mut_ptr(), req.len() as CK_ULONG, std::ptr::null_mut(), &mut len), 0);
            let mut small = vec![0u8; 8];
            let mut sl: CK_ULONG = 8;
            assert_eq!((af.C_PQCTODAY_AdminExecute)(so, req.as_mut_ptr(), req.len() as CK_ULONG, small.as_mut_ptr(), &mut sl), CKR_BUFFER_TOO_SMALL as CK_RV);
            let mut out = vec![0u8; len as usize];
            assert_eq!((af.C_PQCTODAY_AdminExecute)(so, req.as_mut_ptr(), req.len() as CK_ULONG, out.as_mut_ptr(), &mut len), 0);
            assert_eq!(len as usize, out.len(), "sizing was exact");
            (req, out)
        });
        verify(&w, &receipt.1, &receipt.0).expect("receipt from the C ABI verifies");

        // Ceremony: challenge on 0, BeginReceive on 1 (sizing exact), attest, cancel.
        let ps = w.enroll_policy_everywhere(&w.policy([true, true, true], 2, test_mechs()));
        let (s0, s1) = (w.tokens[0].user as CK_ULONG, w.tokens[1].user as CK_ULONG);
        let mut chal = [0u8; 32];
        let mut cl: CK_ULONG = 32;
        assert_eq!((cf.C_PQCTODAY_IssueSourceChallenge)(s0, chal.as_mut_ptr(), &mut cl), 0);
        use der::Encode;
        let mut br = admin::BeginReceive {
            version: 1,
            operation: repl::asn1::Operation::OfflineBackup,
            source_challenge: der::asn1::OctetString::new(chal.to_vec()).unwrap(),
            domain_id: der::asn1::OctetString::new(DOMAIN.to_vec()).unwrap(),
            requested_policy: der::asn1::OctetString::new(ps.to_vec()).unwrap(),
        }
        .to_der()
        .unwrap();
        let mut rl: CK_ULONG = 0;
        assert_eq!((cf.C_PQCTODAY_BeginReceive)(s1, br.as_mut_ptr(), br.len() as CK_ULONG, std::ptr::null_mut(), &mut rl), 0);
        let mut rq = vec![0u8; rl as usize];
        assert_eq!((cf.C_PQCTODAY_BeginReceive)(s1, br.as_mut_ptr(), br.len() as CK_ULONG, rq.as_mut_ptr(), &mut rl), 0);
        assert_eq!(rl as usize, rq.len(), "BeginReceive sizing was exact");
        let parsed: [u8; 32] = {
            use der::Decode;
            repl::asn1::ReplicationRequest::from_der(&rq).unwrap().transaction_id.as_bytes().try_into().unwrap()
        };
        let (k, _) = gen_key(w.tokens[0].user, Kp::MlDsa, &ps);
        let mut el: CK_ULONG = 0;
        let mut c2 = [5u8; 32];
        assert_eq!((cf.C_PQCTODAY_AttestKey)(s0, k as CK_ULONG, c2.as_mut_ptr(), 32, std::ptr::null_mut(), &mut el), 0);
        let mut ev = vec![0u8; el as usize];
        assert_eq!((cf.C_PQCTODAY_AttestKey)(s0, k as CK_ULONG, c2.as_mut_ptr(), 32, ev.as_mut_ptr(), &mut el), 0);
        assert_eq!(el as usize, ev.len(), "AttestKey sizing was exact");
        let mut tx = parsed;
        assert_eq!((cf.C_PQCTODAY_CancelReceive)(s1, tx.as_mut_ptr(), 32), 0, "the unconsumed reservation cancels");
        assert_eq!((cf.C_PQCTODAY_CancelReceive)(s1, tx.as_mut_ptr(), 31), CKR_ARGUMENTS_BAD as CK_RV);
    }
}
