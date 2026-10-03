//! FHE P2 acceptance (P0B spec rev 2 §10 gate 3; FHE plan §6.3 tests and P2
//! exit): TFHE custody with a real client key, policy-gated decryption,
//! signed recipient releases, and recovery that preserves client-key
//! identity (old ciphertexts decrypt after restore with the source destroyed).
#![cfg(all(feature = "educational-fhe", feature = "test-support"))]

mod replication_common;
use replication_common::*;

use softhsmrustv3::constants::*;
use softhsmrustv3::native;
use softhsmrustv3::replication::{self as repl, asn1::Operation, fhe, fhe_tfhe as tf, records};

fn ty(name: &str, w: u16) -> fhe::FheType {
    fhe::FheType { type_name: name.into(), width_bits: w, param_set: 1, serialization_version: 1, compressed_allowed: false }
}

fn dp(recipients: Vec<[u8; 48]>, recipient_only: bool, max: u32) -> Vec<u8> {
    use der::Encode;
    let mut r = recipients;
    r.sort();
    fhe::FheDecryptPolicy {
        version: 1,
        allowed_output_types: vec![ty("FheBool", 1), ty("FheUint8", 8)],
        never_release: vec![ty("FheUint64", 64)],
        predicates: vec![fhe::Predicate { kind: fhe::PredicateKind::MaxValue, bound: 200 }],
        recipients: r.iter().map(|x| der::asn1::OctetString::new(x.to_vec()).unwrap()).collect(),
        recipient_only,
        max_decrypts: max,
    }
    .to_der()
    .unwrap()
}

fn fhe_repl_policy(w: &World, max: u32) -> Vec<u8> {
    records::build_policy_with_constraint(
        DOMAIN, [true, true, true], w.device_ids(), w.now - 60, w.now + 30 * 86_400, max,
        vec![CKM_PQCTODAY_FHE_DERIVE_PUBLIC, CKM_PQCTODAY_FHE_DECRYPT], false, fhe::profile_constraint_hash(),
    )
    .unwrap()
}

fn enroll_all(w: &World, on: &[usize], decrypt_policy: &[u8]) -> ([u8; 48], [u8; 48], [u8; 48]) {
    let (s, d) = (fhe_repl_policy(w, 8), fhe_repl_policy(w, 1));
    let mut ids = ([0; 48], [0; 48], [0; 48]);
    for &i in on {
        ids = w.as_so(i, |so| (repl::enroll_policy(so, &s).unwrap(), repl::enroll_policy(so, &d).unwrap(), fhe::enroll_fhe_decrypt_policy(so, decrypt_policy).unwrap()));
    }
    ids
}

const OWNER: [u8; 48] = [0; 48];

fn owner_value(out: &tf::DecryptOutput) -> (u8, u16, u64) {
    let tf::DecryptOutput::Owner(b) = out else { panic!("expected owner output") };
    let mut v = [0u8; 8];
    v[..b.len() - 3].copy_from_slice(&b[3..]);
    (b[0], u16::from_be_bytes([b[1], b[2]]), u64::from_le_bytes(v))
}

#[test]
fn p2_keygen_derive_public_and_policy_gated_decrypt() {
    let _g = lock();
    let w = world(1);
    let (ps, _, dpid) = enroll_all(&w, &[0], &dp(vec![], false, 1000));
    let s = w.tokens[0].user;
    let seed = fhe::generate_fhe_seed(s, 1, &ps, &dpid, Some(b"edu-seed"), None).expect("KEY_GEN");
    assert_eq!(native::get_attribute(s, seed, CKA_VALUE), None);
    assert_eq!(native::get_attribute(s, seed, CKA_PQCTODAY_FHE_PARAM_HASH).unwrap(), fhe::param_hash(1).unwrap().to_vec());
    // Public material is a public SESSION object; the compact public key is small.
    let pk = tf::derive_public(s, seed, tf::PUBLIC_KIND_COMPACT_PUBLIC_KEY).unwrap();
    assert_eq!(native::get_attribute_bool(s, pk, CKA_TOKEN), Some(false));
    assert!(native::get_attribute(s, pk, CKA_VALUE).unwrap().len() > 30_000);
    // Each allowed type releases.
    let b = tf::encrypt_for_test(s, seed, "FheBool", 1).unwrap();
    let (_, out) = tf::decrypt(s, seed, &OWNER, &b, false).unwrap();
    assert_eq!(owner_value(&out.unwrap()), (0, 1, 1));
    let c = tf::encrypt_for_test(s, seed, "FheUint8", 77).unwrap();
    let (n, _) = tf::decrypt(s, seed, &OWNER, &c, true).unwrap();
    assert_eq!(n, 4, "size query: 3-byte header + 1 byte");
    let (_, out) = tf::decrypt(s, seed, &OWNER, &c, false).unwrap();
    assert_eq!(owner_value(&out.unwrap()), (1, 8, 77));
    // Refusals, all one code: disallowed width, never-release input, predicate.
    let refused = |blob: &[u8]| tf::decrypt(s, seed, &OWNER, blob, false).map(|_| ());
    assert_eq!(refused(&tf::encrypt_for_test(s, seed, "FheUint16", 5).unwrap()), Err(CKR_ACTION_PROHIBITED));
    assert_eq!(repl::last_refusal(), Some("type gate"));
    assert_eq!(refused(&tf::encrypt_for_test(s, seed, "FheUint64", 5).unwrap()), Err(CKR_ACTION_PROHIBITED));
    assert_eq!(refused(&tf::encrypt_for_test(s, seed, "FheUint8", 250).unwrap()), Err(CKR_ACTION_PROHIBITED));
    assert_eq!(repl::last_refusal(), Some("predicate"));
    assert_eq!(refused(b"not a ciphertext"), Err(CKR_ACTION_PROHIBITED));
    // Oversized input is refused before any work.
    assert_eq!(refused(&vec![0u8; tf::MAX_DECRYPT_INPUT + 1]), Err(CKR_DATA_LEN_RANGE));
    // The SO cannot decrypt.
    let c2 = c.clone();
    w.as_so(0, |so| assert_eq!(tf::decrypt(so, seed, &OWNER, &c2, false).map(|_| ()), Err(CKR_USER_TYPE_INVALID)));
}

#[test]
fn p2_refusals_consume_the_counter() {
    let _g = lock();
    let w = world(1);
    let (ps, _, dpid) = enroll_all(&w, &[0], &dp(vec![], false, 3));
    let s = w.tokens[0].user;
    let seed = fhe::generate_fhe_seed(s, 1, &ps, &dpid, None, None).unwrap();
    let good = tf::encrypt_for_test(s, seed, "FheUint8", 1).unwrap();
    let bad = tf::encrypt_for_test(s, seed, "FheUint8", 255).unwrap();
    // Size queries are free.
    for _ in 0..10 {
        tf::decrypt(s, seed, &OWNER, &good, true).unwrap();
    }
    assert!(tf::decrypt(s, seed, &OWNER, &bad, false).is_err());
    assert!(tf::decrypt(s, seed, &OWNER, &bad, false).is_err());
    tf::decrypt(s, seed, &OWNER, &good, false).expect("third call still within budget");
    assert_eq!(tf::decrypt(s, seed, &OWNER, &good, false).map(|_| ()), Err(CKR_ACTION_PROHIBITED));
    assert_eq!(repl::last_refusal(), Some("decrypt budget exhausted"));
}

#[test]
fn p2_signed_recipient_release_and_recipient_only() {
    let _g = lock();
    let w = world(2);
    // Token 1's recovery recipient is the enrolled third party.
    let rchain = repl::function_chain(w.tokens[1].user, repl::oids::Purpose::RecoveryRecipient).unwrap();
    let r_hash = w.as_so(0, |so| tf::enroll_fhe_recipient(so, &rchain).unwrap());
    let (ps, _, dpid) = enroll_all(&w, &[0], &dp(vec![r_hash], true, 100));
    let s = w.tokens[0].user;
    let seed = fhe::generate_fhe_seed(s, 1, &ps, &dpid, None, None).unwrap();
    let c = tf::encrypt_for_test(s, seed, "FheUint8", 42).unwrap();
    // Recipient-only: the owner never gets plaintext.
    assert_eq!(tf::decrypt(s, seed, &OWNER, &c, false).map(|_| ()), Err(CKR_ACTION_PROHIBITED));
    // An unenrolled recipient is refused.
    assert_eq!(tf::decrypt(s, seed, &[9u8; 48], &c, false).map(|_| ()), Err(CKR_ACTION_PROHIBITED));
    let (_, out) = tf::decrypt(s, seed, &r_hash, &c, false).unwrap();
    let tf::DecryptOutput::Sealed(sealed) = out.unwrap() else { panic!("sealed expected") };
    let lineage: [u8; 32] = native::get_attribute(s, seed, CKA_PQCTODAY_FHE_LINEAGE_ID).unwrap().try_into().unwrap();
    let opened = tf::open_release(w.tokens[1].user, &sealed, &lineage, &dpid).expect("recipient verifies and opens");
    assert_eq!(opened.plaintext, vec![1, 0, 8, 42]);
    assert_eq!(opened.signer_device_id, w.device_ids()[0], "signed by the seed's token");
    // Tampering with the sealed release breaks the signature.
    let mut t = sealed.clone();
    let n = t.len();
    t[n / 2] ^= 1;
    assert!(tf::open_release(w.tokens[1].user, &t, &lineage, &dpid).is_err());
}

#[test]
fn p2_restore_preserves_client_key_and_old_ciphertexts_decrypt() {
    let _g = lock();
    let w = world(3);
    let (ps, pd, dpid) = enroll_all(&w, &[0, 1, 2], &dp(vec![], false, 1000));
    let s0 = w.tokens[0].user;
    let seed = fhe::generate_fhe_seed(s0, 1, &ps, &dpid, None, None).unwrap();
    // Data encrypted before the backup.
    let old = tf::encrypt_for_test(s0, seed, "FheUint8", 123).unwrap();
    let backup = repl::create_replication_package(s0, seed, &request(&w, 0, 1, Operation::OfflineBackup, &pd)).unwrap();
    assert_eq!(softhsmrustv3::ffi::C_DestroyObject(s0, seed), CKR_OK, "source test instance destroyed");
    repl::set_clock_override(Some(w.now + 3600));
    let (bk, _) = repl::import_replication_package(w.tokens[1].user, &backup, &[]).unwrap();
    let (rest, _) = repl::import_replication_package(
        w.tokens[2].user,
        &repl::create_replication_package(w.tokens[1].user, bk, &request(&w, 1, 2, Operation::Restore, &pd)).unwrap(),
        &[],
    )
    .unwrap();
    repl::set_clock_override(Some(w.now));
    for (tok, h) in [(1usize, bk), (2, rest)] {
        let (_, out) = tf::decrypt(w.tokens[tok].user, h, &OWNER, &old, false).expect("pre-backup ciphertext decrypts");
        assert_eq!(owner_value(&out.unwrap()), (1, 8, 123));
        // A11: the fixed derive template is re-set on install.
        assert_eq!(records::object_attrs(h).unwrap()[&CKA_DERIVE_TEMPLATE], fhe::seed_derive_template());
    }
    // Fresh public material from the restored seed.
    tf::derive_public(w.tokens[2].user, rest, tf::PUBLIC_KIND_COMPACT_PUBLIC_KEY).unwrap();
}
