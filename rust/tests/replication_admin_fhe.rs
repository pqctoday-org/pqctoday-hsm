//! Signed admin operations for FHE custody (plan D02387 WP-A2): [5] enrollFheDecryptPolicy and
//! [6] enrollFheRecipient go through the same signed-update path as the replication admin operations (signature,
//! nonce, sequence, ledger, receipt). INSECURE test ring 0x8002 only.
#![cfg(all(pqc_ckks_custody, feature = "test-support"))]

mod replication_common;
use replication_common::*;

use der::Encode;
use softhsmrustv3::constants::*;
use softhsmrustv3::replication::admin::{self, AdminOperation};
use softhsmrustv3::replication::fhe_ckks::{mech, params};
use softhsmrustv3::replication::{self as repl, admin_host, fhe, host_verify, test_ca::AdminAuthorityKey, Profile};

const PS: u32 = 0x8002;

struct Admin {
    key: AdminAuthorityKey,
    device_id: [u8; 32],
}

fn setup(w: &World) -> Admin {
    let key = AdminAuthorityKey::new(&w.ca, w.now).unwrap();
    w.as_so(0, |so| admin::enroll_admin_authority(so, &key.cert_der).expect("enroll admin authority"));
    Admin { key, device_id: repl::device_id(w.tokens[0].user).unwrap() }
}

fn signed(a: &Admin, key: &AdminAuthorityKey, nonce: &[u8; 32], seq: u64, op: &AdminOperation) -> Vec<u8> {
    let tbs = admin_host::tbs_request(&a.device_id, &key.key_id(), nonce, seq, 1_790_000_000, op).unwrap();
    let sig = key.sign(&admin_host::request_signed_bytes(&tbs)).unwrap();
    admin_host::signed_request(&tbs, &sig).unwrap()
}

fn run_with(w: &World, a: &Admin, key: &AdminAuthorityKey, seq: u64, op: &AdminOperation) -> (Vec<u8>, Result<Vec<u8>, u32>) {
    w.as_so(0, |so| {
        let n = admin::issue_nonce(so).unwrap();
        let req = signed(a, key, &n, seq, op);
        let r = admin::execute(so, &req);
        (req, r)
    })
}

fn ckks_policy(max_decrypts: u32) -> Vec<u8> {
    let ps = params::find(PS).unwrap();
    fhe::FheDecryptPolicy {
        version: 2,
        allowed_output_types: vec![fhe::FheType { type_name: mech::CKKS_TYPE_NAME.into(), width_bits: 64, param_set: PS, serialization_version: mech::CT_VERSION, compressed_allowed: false }],
        never_release: vec![],
        predicates: vec![],
        recipients: vec![],
        recipient_only: false,
        max_decrypts,
        ckks: Some(fhe::CkksReleasePolicy { max_values: (ps.n() / 2) as u32, precision_bits: 20, value_bound_log2: 10, scale_log2: ps.log_default_scale as u8, flood_recipients: true, flood_owner: false, stat_security_bits: 30 }),
    }
    .to_der()
    .unwrap()
}

#[test]
fn admin_enrolls_an_fhe_decryption_policy_with_a_verified_receipt() {
    let _g = lock();
    let w = world(1);
    let a = setup(&w);
    let pol = ckks_policy(100);

    let (req, r) = run_with(&w, &a, &a.key, 1, &AdminOperation::EnrollFheDecryptPolicy { policy: pol.clone() });
    let receipt = r.expect("enrollFheDecryptPolicy commits");
    let view = host_verify::verify_admin_receipt(&receipt, &req, &repl::trust_inputs(w.tokens[0].slot), w.now, Profile::Educational).expect("receipt verifies");
    // The policy is enrolled: the legacy Rust path now finds it (idempotent) and returns the same ID as the receipt.
    let id = w.as_so(0, |so| fhe::enroll_fhe_decrypt_policy(so, &pol).unwrap());
    assert_eq!(view.output.as_deref(), Some(&id[..]));
    assert_eq!(view.result_digest, id);

    // Re-enrolling the same policy through the admin path is a no-op that still commits a receipt at the next sequence.
    let (_, r2) = run_with(&w, &a, &a.key, 2, &AdminOperation::EnrollFheDecryptPolicy { policy: pol });
    assert!(r2.is_ok());
}

#[test]
fn admin_fhe_operations_are_refused_like_every_admin_operation() {
    let _g = lock();
    let w = world(1);
    let a = setup(&w);

    // Not signed by the enrolled authority.
    let other = AdminAuthorityKey::new(&w.ca, w.now).unwrap();
    let (_, r) = run_with(&w, &a, &other, 1, &AdminOperation::EnrollFheDecryptPolicy { policy: ckks_policy(100) });
    assert!(r.is_err(), "a request signed by a non-enrolled authority must be refused");

    // Malformed payloads: not a decryption policy; an empty or oversized recipient chain; a recipient chain that is not
    // a certificate.
    let (_, r) = run_with(&w, &a, &a.key, 1, &AdminOperation::EnrollFheDecryptPolicy { policy: vec![0x30, 0x00] });
    assert_eq!(r, Err(CKR_DATA_INVALID));
    let (_, r) = run_with(&w, &a, &a.key, 1, &AdminOperation::EnrollFheRecipient { chain: vec![] });
    assert_eq!(r, Err(CKR_DATA_INVALID));
    let (_, r) = run_with(&w, &a, &a.key, 1, &AdminOperation::EnrollFheRecipient { chain: vec![vec![0u8; 16]; 5] });
    assert_eq!(r, Err(CKR_DATA_INVALID));
    let (_, r) = run_with(&w, &a, &a.key, 1, &AdminOperation::EnrollFheRecipient { chain: vec![vec![0x30, 0x03, 0x02, 0x01, 0x01]] });
    assert_eq!(r, Err(CKR_DATA_INVALID));

    // After the refusals the authority's sequence is unchanged: a correct request at sequence 1 still commits.
    let (_, r) = run_with(&w, &a, &a.key, 1, &AdminOperation::EnrollFheDecryptPolicy { policy: ckks_policy(50) });
    assert!(r.is_ok());
}
