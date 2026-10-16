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

/// Owner decisions 2026-10-15: an FHE seed is not destroyable (`CKA_DESTROYABLE = FALSE`), so the normal user's
/// `C_DestroyObject` is refused; the security officer's signed `[7] destroyFheSeed` removes it after its receipt is
/// committed, and an exact retry returns the same receipt. And PKCS#11 v3.2 §5.2: a `C_Decrypt` buffer below the
/// size-query length gets `CKR_BUFFER_TOO_SMALL`, the operation stays active and no decryption is counted.
#[test]
fn fhe_seeds_are_destroyed_only_by_a_signed_so_request_and_a_short_buffer_spends_nothing() {
    use softhsmrustv3::native;
    use softhsmrustv3::replication::fhe_ckks::spec::Generator;
    use softhsmrustv3::replication::records;
    let _g = lock();
    let w = world(1);
    let a = setup(&w);
    let rp = records::build_policy_with_constraint(
        DOMAIN, [true, true, true], w.device_ids(), w.now - 60, w.now + 30 * 86_400, 4,
        vec![CKM_PQCTODAY_FHE_DERIVE_PUBLIC, CKM_PQCTODAY_FHE_DECRYPT], false, fhe::ckks_profile_constraint_hash(),
    )
    .unwrap();
    let rpid = w.as_so(0, |so| repl::enroll_policy(so, &rp).unwrap());
    let (req1, r) = run_with(&w, &a, &a.key, 1, &AdminOperation::EnrollFheDecryptPolicy { policy: ckks_policy(1) });
    let view1 = host_verify::verify_admin_receipt(&r.expect("policy enrolled"), &req1, &repl::trust_inputs(w.tokens[0].slot), w.now, Profile::Educational).unwrap();
    let dpid: [u8; 48] = view1.output.expect("policy ID").try_into().unwrap();
    let s = w.tokens[0].user;
    let seed_value = [9u8; 32];
    let h = fhe::generate_fhe_seed_with_value_for_test(s, PS, &rpid, &dpid, &seed_value, b"destroy-test").expect("KEY_GEN");
    assert_eq!(native::get_attribute_bool(s, h, CKA_DESTROYABLE), Some(false));
    assert_eq!(softhsmrustv3::ffi::C_DestroyObject(s, h), CKR_ACTION_PROHIBITED, "not destroyable by the normal user");

    // Short buffer: refused before decrypting; the policy's single decryption is still available afterwards.
    let ps = params::find(PS).unwrap();
    let m: Vec<i128> = (0..ps.n() as i128).map(|i| (i % 7 - 3) << 20).collect();
    let (c0, c1) = Generator::new(ps, &seed_value).encrypt_for_test(0, &m, &[5u8; 32]).unwrap();
    let mut ct = mech::CT_MAGIC.to_vec();
    for v in [PS, 0, 40, 0] {
        ct.extend_from_slice(&v.to_le_bytes());
    }
    for v in c0.iter().chain(&c1) {
        ct.extend_from_slice(&v.to_le_bytes());
    }
    let w_ = std::mem::size_of::<usize>();
    let mut prm = vec![0u8; (w_ + 48).next_multiple_of(w_)];
    prm[..w_].copy_from_slice(&1usize.to_ne_bytes());
    let mut mm = [CKM_PQCTODAY_FHE_DECRYPT as usize, prm.as_ptr() as usize, prm.len()];
    assert_eq!(softhsmrustv3::ffi::C_DecryptInit(s, mm.as_mut_ptr() as *mut u8, h), CKR_OK);
    let mut n = 0u32;
    assert_eq!(softhsmrustv3::ffi::C_Decrypt(s, ct.as_ptr() as *mut u8, ct.len() as u32, std::ptr::null_mut(), &mut n), CKR_OK);
    let mut out = vec![0u8; n as usize];
    let mut short = 1u32;
    assert_eq!(softhsmrustv3::ffi::C_Decrypt(s, ct.as_ptr() as *mut u8, ct.len() as u32, out.as_mut_ptr(), &mut short), CKR_BUFFER_TOO_SMALL);
    assert_eq!(short, n, "the needed length comes back");
    assert_eq!(softhsmrustv3::ffi::C_Decrypt(s, ct.as_ptr() as *mut u8, ct.len() as u32, out.as_mut_ptr(), &mut n), CKR_OK, "still active, and the one allowed decryption was not spent");

    // The SO destroys the seed by lineage; the receipt's output is the lineage; an exact retry replays it.
    let lineage: [u8; 32] = native::get_attribute(s, h, CKA_PQCTODAY_FHE_LINEAGE_ID).unwrap().try_into().unwrap();
    let (req, r) = run_with(&w, &a, &a.key, 2, &AdminOperation::DestroyFheSeed { lineage });
    let receipt = r.expect("destroyFheSeed commits");
    let view = host_verify::verify_admin_receipt(&receipt, &req, &repl::trust_inputs(w.tokens[0].slot), w.now, Profile::Educational).expect("receipt verifies");
    assert_eq!(view.output.as_deref(), Some(&lineage[..]));
    assert!(native::find_all_by_cka_id(s, b"destroy-test").unwrap_or_default().is_empty(), "the seed is gone");
    let replay = w.as_so(0, |so| admin::execute(so, &req));
    assert_eq!(replay, Ok(receipt), "an exact retry returns the stored receipt");
    // A malformed lineage is refused before any trust check.
    let mut bad = AdminOperation::DestroyFheSeed { lineage };
    if let AdminOperation::DestroyFheSeed { lineage } = &mut bad {
        lineage[0] ^= 1;
    }
    let (_, r) = run_with(&w, &a, &a.key, 3, &bad);
    assert!(r.is_err(), "no seed with that lineage");
}
