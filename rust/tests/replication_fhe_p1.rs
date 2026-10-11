//! FHE P1 acceptance (FHE plan §9 P1 exit gate): both K4 replication flows
//! for an opaque FHE-seed fixture, decryption-policy and profile refusals,
//! descriptor binding, and custody. No TFHE backend; no decryption claim.
#![cfg(feature = "educational-replication")]

mod replication_common;
use replication_common::*;

use softhsmrustv3::constants::*;
use softhsmrustv3::native;
use softhsmrustv3::replication::{self as repl, asn1::Operation, fhe, records};

fn fhe_type(name: &str, w: u16) -> fhe::FheType {
    fhe::FheType { type_name: name.into(), width_bits: w, param_set: 1, serialization_version: 1, compressed_allowed: false }
}

fn decrypt_policy_der() -> Vec<u8> {
    use der::Encode;
    fhe::FheDecryptPolicy {
        version: 1,
        allowed_output_types: vec![fhe_type("FheBool", 1), fhe_type("FheUint8", 8)],
        never_release: vec![fhe_type("FheUint64", 64)],
        predicates: vec![fhe::Predicate { kind: fhe::PredicateKind::MaxValue, bound: 255 }],
        recipients: vec![],
        recipient_only: false,
        max_decrypts: 1000,
        ckks: None,
    }
    .to_der()
    .unwrap()
}

/// FHE-profile replication policies (source generous, destination 1 replica)
/// plus one decryption policy, enrolled on `on` tokens.
fn fhe_policies(w: &World, on: &[usize]) -> ([u8; 48], [u8; 48], [u8; 48]) {
    let mechs = vec![CKM_PQCTODAY_FHE_DERIVE_PUBLIC, CKM_PQCTODAY_FHE_DECRYPT];
    let mk = |max| records::build_policy_with_constraint(DOMAIN, [true, true, true], w.device_ids(), w.now - 60, w.now + 30 * 86_400, max, mechs.clone(), false, fhe::profile_constraint_hash()).unwrap();
    let (src, dst, dp) = (mk(8), mk(1), decrypt_policy_der());
    let mut ids = ([0u8; 48], [0u8; 48], [0u8; 48]);
    for &i in on {
        ids = w.as_so(i, |so| {
            (repl::enroll_policy(so, &src).unwrap(), repl::enroll_policy(so, &dst).unwrap(), fhe::enroll_fhe_decrypt_policy(so, &dp).unwrap())
        });
    }
    ids
}

fn seed_value(h: u32) -> Vec<u8> {
    records::object_attrs(h).unwrap()[&CKA_VALUE].clone()
}

const FHE_ATTRS: [u32; 6] = [
    CKA_PQCTODAY_FHE_SCHEME,
    CKA_PQCTODAY_FHE_PARAM_SET,
    CKA_PQCTODAY_FHE_PARAM_HASH,
    CKA_PQCTODAY_FHE_LIBRARY,
    CKA_PQCTODAY_FHE_LINEAGE_ID,
    CKA_PQCTODAY_FHE_DECRYPT_POLICY,
];

#[test]
fn p1_fhe_seed_live_clone_and_offline_restore_with_source_destroyed() {
    let _g = lock();
    let w = world(3);
    let (ps, pd, dp) = fhe_policies(&w, &[0, 1, 2]);
    let src = fhe::create_opaque_seed_fixture(w.tokens[0].user, 1, &ps, &dp).expect("fixture");
    let original = seed_value(src);
    let attrs0: Vec<_> = FHE_ATTRS.iter().map(|a| native::get_attribute(w.tokens[0].user, src, *a)).collect();
    assert!(attrs0.iter().all(|v| v.is_some()));
    // Live clone 0 → 1.
    let (live, receipt) = repl::import_replication_package(
        w.tokens[1].user,
        &repl::create_replication_package(w.tokens[0].user, src, &request(&w, 0, 1, Operation::LiveClone, &pd)).unwrap(),
        &[],
    )
    .expect("live clone");
    assert!(!receipt.is_empty());
    // Offline backup 0 → 2, destroy the source, a day later import, then restore 2 → 1.
    let backup = repl::create_replication_package(w.tokens[0].user, src, &request(&w, 0, 2, Operation::OfflineBackup, &pd)).unwrap();
    assert_eq!(softhsmrustv3::ffi::C_DestroyObject(w.tokens[0].user, src), CKR_OK);
    repl::set_clock_override(Some(w.now + 86_400));
    let (bk, _) = repl::import_replication_package(w.tokens[2].user, &backup, &[]).expect("offline import");
    let restored_pkg = repl::create_replication_package(w.tokens[2].user, bk, &request(&w, 2, 1, Operation::Restore, &pd)).unwrap();
    let (restored, _) = repl::import_replication_package(w.tokens[1].user, &restored_pkg, &[]).expect("restore");
    repl::set_clock_override(Some(w.now));
    for (tok, h) in [(1usize, live), (2, bk), (1, restored)] {
        let s = w.tokens[tok].user;
        // Same seed (engine-internal check; P2 proves it with TFHE decryption).
        assert_eq!(seed_value(h), original, "seed identity preserved");
        // FHE identity, parameters, library and decrypt policy preserved.
        let attrs: Vec<_> = FHE_ATTRS.iter().map(|a| native::get_attribute(s, h, *a)).collect();
        assert_eq!(attrs, attrs0);
        // Custody: never readable, imported history plus provenance.
        assert_eq!(native::get_attribute(s, h, CKA_VALUE), None);
        assert_eq!(native::get_attribute_bool(s, h, CKA_EXTRACTABLE), Some(false));
        assert_eq!(native::get_attribute_bool(s, h, CKA_LOCAL), Some(false));
        assert!(native::get_attribute(s, h, CKA_PQCTODAY_REPLICATION_PROVENANCE).is_some());
        // Attestation reports the FHE parameter set and true history.
        let ev = repl::attest_key(s, h, &[9; 32]).unwrap();
        let c = repl::host_verify::verify_key_evidence(&ev, &trust_of(&w, tok), &[9; 32], w.now, repl::Profile::Educational).unwrap();
        assert_eq!((c.key.key_type, c.key.parameter_set, c.key.local), (CKK_PQCTODAY_FHE, 1, false));
    }
}

#[test]
fn p1_missing_decrypt_policy_at_destination_is_refused() {
    let _g = lock();
    let w = world(2);
    // Replication policies on both, decrypt policy only on the source.
    let mechs = vec![CKM_PQCTODAY_FHE_DERIVE_PUBLIC, CKM_PQCTODAY_FHE_DECRYPT];
    let mk = |max| records::build_policy_with_constraint(DOMAIN, [true, true, true], w.device_ids(), w.now - 60, w.now + 30 * 86_400, max, mechs.clone(), false, fhe::profile_constraint_hash()).unwrap();
    let (src, dst) = (mk(8), mk(1));
    let ps = w.enroll_policy_everywhere(&src);
    let pd = w.enroll_policy_everywhere(&dst);
    let dp = w.as_so(0, |so| fhe::enroll_fhe_decrypt_policy(so, &decrypt_policy_der()).unwrap());
    let seed = fhe::create_opaque_seed_fixture(w.tokens[0].user, 1, &ps, &dp).unwrap();
    let lineage = native::get_attribute(w.tokens[0].user, seed, CKA_PQCTODAY_FHE_LINEAGE_ID).unwrap();
    let pkg = repl::create_replication_package(w.tokens[0].user, seed, &request(&w, 0, 1, Operation::LiveClone, &pd)).unwrap();
    assert_eq!(repl::import_replication_package(w.tokens[1].user, &pkg, &[]).map(|_| ()), Err(CKR_ACTION_PROHIBITED));
    assert_eq!(repl::last_refusal(), Some("FHE decryption policy not enrolled at destination"));
    assert_eq!(replicas_with_lineage(1, &lineage), 0, "nothing installed");
}

#[test]
fn p1_profiles_do_not_cross_and_fhe_attributes_are_immutable() {
    let _g = lock();
    let w = world(1);
    let (ps, _, dp) = fhe_policies(&w, &[0]);
    let (v1_src, _) = policies(&w);
    let s = w.tokens[0].user;
    // An AES key cannot bind to an FHE-profile policy, nor an FHE seed to a v1 policy.
    assert_eq!(gen_aes(s, 32, Some(&ps)), Err(CKR_TEMPLATE_INCONSISTENT));
    assert_eq!(fhe::create_opaque_seed_fixture(s, 1, &v1_src, &dp), Err(CKR_TEMPLATE_INCONSISTENT));
    // Unknown parameter set / unenrolled decrypt policy.
    assert_eq!(fhe::create_opaque_seed_fixture(s, 99, &ps, &dp), Err(CKR_TEMPLATE_INCONSISTENT));
    assert_eq!(fhe::create_opaque_seed_fixture(s, 1, &ps, &[1u8; 48]), Err(CKR_TEMPLATE_INCONSISTENT));
    let seed = fhe::create_opaque_seed_fixture(s, 1, &ps, &dp).unwrap();
    for a in FHE_ATTRS.iter().chain([CKA_PQCTODAY_FHE_PUBLIC_KIND, CKA_ALLOWED_MECHANISMS, CKA_EXTRACTABLE].iter()) {
        let one = [(*a, vec![1u8; 48])];
        let t = raw_template(&one);
        assert_ne!(softhsmrustv3::ffi::C_SetAttributeValue(s, seed, t.as_ptr() as *mut u8, 1), CKR_OK, "attr {a:#x} mutable");
    }
    // A caller can never create an object claiming FHE attributes.
    let forged = vec![(CKA_CLASS, ul(CKO_SECRET_KEY)), (CKA_KEY_TYPE, ul(CKK_GENERIC_SECRET)), (CKA_VALUE, vec![1u8; 32]), (CKA_PQCTODAY_FHE_LINEAGE_ID, vec![0u8; 32])];
    let t = raw_template(&forged);
    let mut h = 0;
    assert_eq!(softhsmrustv3::ffi::C_CreateObject(s, t.as_ptr() as *mut u8, forged.len() as u32, &mut h), CKR_ATTRIBUTE_READ_ONLY);
    // Standard export paths refuse the seed.
    let kek = gen_aes(s, 32, None).unwrap();
    let mut m = [CKM_AES_KEY_WRAP as usize, 0, 0];
    let mut len = 0u32;
    assert_ne!(softhsmrustv3::ffi::C_WrapKey(s, m.as_mut_ptr() as *mut u8, kek, seed, std::ptr::null_mut(), &mut len), CKR_OK);
    let weaker = [(CKA_EXTRACTABLE, bb(true))];
    let t = raw_template(&weaker);
    assert_ne!(softhsmrustv3::ffi::C_CopyObject(s, seed, t.as_ptr() as *mut u8, 1, &mut h), CKR_OK);
}
