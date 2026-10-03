//! K2 acceptance — hierarchy and enrollment (plan R1.4; spec §4.2).
#![cfg(feature = "educational-replication")]

mod replication_common;
use replication_common::*;

use softhsmrustv3::constants::*;
use softhsmrustv3::native;
use softhsmrustv3::replication::{
    self as repl,
    oids::Purpose,
    pki,
    test_ca::{spki_of, RogueIssuer, TestManufacturingCa},
    Profile,
};

/// Fresh, un-enrolled token on `slot` with an SO session.
fn bare(slot: u32) -> u32 {
    native::init_token(slot, SO, "bare").unwrap();
    let so = native::open_session_so(slot, SO).unwrap();
    native::init_pin(so, USER).unwrap();
    so
}

#[test]
fn k2_two_tokens_enroll_under_one_root_and_verify_each_other() {
    let _g = lock();
    let w = world(2);
    for (a, b) in [(0usize, 1usize), (1, 0)] {
        let trust = trust_of(&w, a);
        for p in Purpose::LEAVES {
            let chain = pki::chain_from_ders(&repl::function_chain(w.tokens[b].user, p).unwrap()).unwrap();
            let v = pki::validate_chain(&chain, p, &trust, w.now, Profile::Educational).expect("peer function chain");
            assert_eq!(v.device_id, w.device_ids()[b]);
            // Each certificate carries exactly its own purpose (wrong-purpose refusal).
            for q in Purpose::LEAVES.into_iter().filter(|q| *q != p) {
                assert!(pki::validate_chain(&chain, q, &trust, w.now, Profile::Educational).is_err(), "{p:?} used as {q:?}");
            }
            // The documentation arc is refused outside the educational profile.
            assert!(pki::validate_chain(&chain, p, &trust, w.now, Profile::Production).is_err());
        }
    }
    // Function keys and certificates are immutable, non-copyable, non-destroyable,
    // and never a general signing/decapsulation oracle.
    let s = w.tokens[0].user;
    for (h, _) in repl::records::list(w.tokens[0].slot, repl::records::ROLE_FUNCTION_KEY) {
        assert_eq!(native::get_attribute_bool(s, h, CKA_DESTROYABLE), Some(false));
        assert_eq!(native::get_attribute(s, h, CKA_VALUE), None);
        assert!(native::sign(s, h, CKM_ML_DSA, b"oracle?").is_err(), "function key signs only inside the engine");
        assert_ne!(softhsmrustv3::ffi::C_DestroyObject(s, h), CKR_OK);
    }
}

#[test]
fn k2_enrollment_negative_cases() {
    let _g = lock();
    let w = world(1);
    let now = w.now;
    let mut ca = w.ca;
    let other = TestManufacturingCa::new(now).unwrap();
    // Wrong / untrusted root: device certificate from a different CA.
    let so = bare(1);
    let csr = repl::begin_device_enrollment(so).unwrap();
    let foreign = other.issue_device(&csr, now).unwrap();
    let crl = ca.crl(now - 10, now + 86_400).unwrap();
    assert_eq!(repl::complete_device_enrollment(so, ca.root_der(), &foreign, &crl), Err(CKR_SIGNATURE_INVALID), "untrusted root");
    // Key substitution: the root certifies a DIFFERENT key than the token's.
    let (pk, _) = {
        let rogue = RogueIssuer::new(&ca, now).unwrap();
        (rogue.cert.tbs_certificate.subject_public_key_info.clone(), rogue.sk)
    };
    let substituted = ca.issue_device_for_spki(pk, now - 60, now + 86_400).unwrap();
    assert_eq!(repl::complete_device_enrollment(so, ca.root_der(), &substituted, &crl), Err(CKR_SIGNATURE_INVALID), "key substitution");
    // Expired and not-yet-valid device certificates (host clock).
    let spki = repl::test_ca::verify_csr(&csr).unwrap();
    let expired = ca.issue_device_for_spki(spki.clone(), now - 1000, now - 10).unwrap();
    assert_eq!(repl::complete_device_enrollment(so, ca.root_der(), &expired, &crl), Err(CKR_SIGNATURE_INVALID), "expired");
    let future = ca.issue_device_for_spki(spki.clone(), now + 1000, now + 2000).unwrap();
    assert_eq!(repl::complete_device_enrollment(so, ca.root_der(), &future, &crl), Err(CKR_SIGNATURE_INVALID), "not yet valid");
    // Revoked device certificate.
    let good = ca.issue_device(&csr, now).unwrap();
    ca.revoke(&good, now - 5).unwrap();
    let crl2 = ca.crl(now - 10, now + 86_400).unwrap();
    assert_eq!(repl::complete_device_enrollment(so, ca.root_der(), &good, &crl2), Err(CKR_SIGNATURE_INVALID), "revoked device");
    // Stale root CRL (fail closed).
    let stale = ca.crl(now - 1000, now - 500).unwrap();
    let good2 = ca.issue_device(&csr, now).unwrap();
    assert_eq!(repl::complete_device_enrollment(so, ca.root_der(), &good2, &stale), Err(CKR_SIGNATURE_INVALID), "stale CRL");
    // Garbage DER.
    assert_eq!(repl::complete_device_enrollment(so, b"\x30\x00", &good2, &crl2), Err(CKR_DATA_INVALID));
    // Now enroll correctly; replacement afterwards is refused.
    let fresh = ca.crl(now - 10, now + 86_400).unwrap();
    repl::complete_device_enrollment(so, ca.root_der(), &good2, &fresh).expect("valid enrollment");
    assert_eq!(repl::begin_device_enrollment(so), Err(CKR_ACTION_PROHIBITED), "no silent re-enrollment");
    assert_eq!(repl::complete_device_enrollment(so, ca.root_der(), &good2, &fresh), Err(CKR_ACTION_PROHIBITED));
    repl::issue_function_certificates(so).unwrap();
    assert_eq!(repl::issue_function_certificates(so), Err(CKR_ACTION_PROHIBITED), "functions issued once");
    // CRL rollback refused; a newer root CRL accepted.
    assert_eq!(repl::enroll_crl(so, &fresh, None), Err(CKR_ACTION_PROHIBITED), "same CRL number");
    let newer = ca.crl(now - 10, now + 86_400).unwrap();
    repl::enroll_crl(so, &newer, None).expect("newer CRL");
    assert_eq!(repl::enroll_crl(so, &crl2, None), Err(CKR_ACTION_PROHIBITED), "older CRL number");
}

#[test]
fn k2_so_only_and_role_boundaries() {
    let _g = lock();
    let w = world(1);
    let user = w.tokens[0].user;
    assert_eq!(repl::begin_device_enrollment(user), Err(CKR_USER_TYPE_INVALID));
    assert_eq!(repl::enroll_policy(user, &w.policy([true, true, true], 1, test_mechs())), Err(CKR_USER_TYPE_INVALID));
    assert_eq!(repl::issue_device_crl(user, &[], 60), Err(CKR_USER_TYPE_INVALID));
    assert_eq!(repl::rotate_recovery_key(user), Err(CKR_USER_TYPE_INVALID));
    // Public session.
    let mut public = 0u32;
    assert_eq!(softhsmrustv3::ffi::C_OpenSession(1, CKF_SERIAL_SESSION | CKF_RW_SESSION, std::ptr::null_mut(), std::ptr::null_mut(), &mut public), CKR_OK);
    native::init_token(1, SO, "x").ok();
    // The SO cannot use a user's key operations (spec §4).
    let so = w.as_so(0, |so| {
        assert_eq!(repl::issue_source_challenge(so), Err(CKR_USER_TYPE_INVALID));
        so
    });
    let _ = so;
    // Without the educational profile nothing is available.
    repl::clear_profile();
    assert_eq!(repl::device_certificate(user), Err(CKR_FUNCTION_NOT_SUPPORTED));
    repl::select_educational_profile();
}

#[test]
fn k2_pure_pqc_profile_refuses_wrong_parameter_sets_and_classical_keys() {
    let _g = lock();
    let w = world(1);
    let rogue = RogueIssuer::new(&w.ca, w.now).unwrap();
    // A leaf whose SPKI is ML-DSA-44 (wrong parameter set) or P-256 (classical).
    let (pk44, _) = softhsmrustv3::crypto::handlers::ml_dsa_keygen_from_seed(CKP_ML_DSA_44, &[1u8; 32]).unwrap();
    let spki44 = spki_of(&softhsmrustv3::crypto::handlers::build_mldsa44_spki(&pk44)).unwrap();
    let p256 = spki_of(&hex_der("3059301306072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")).unwrap();
    let crl = rogue.crl(1, w.now - 10, w.now + 86_400).unwrap();
    let trust = pki::TrustInputs { roots: vec![w.ca.root_der().to_vec()], crls: vec![crl] };
    for spki in [spki44, p256] {
        let leaf = rogue.issue_leaf(Purpose::KeyAttestation, spki, w.now).unwrap();
        let chain = pki::chain_from_ders(&[leaf, rogue.cert_der()]).unwrap();
        assert!(pki::validate_chain(&chain, Purpose::KeyAttestation, &trust, w.now, Profile::Educational).is_err());
    }
}

fn hex_der(h: &str) -> Vec<u8> {
    (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn k2_function_revocation_follows_issuer_boundaries() {
    let _g = lock();
    let w = world(2);
    let trust_before = trust_of(&w, 0);
    let chain = pki::chain_from_ders(&repl::function_chain(w.tokens[1].user, Purpose::PackageSigning).unwrap()).unwrap();
    pki::validate_chain(&chain, Purpose::PackageSigning, &trust_before, w.now, Profile::Educational).unwrap();
    let crl = w.as_so(1, |so| repl::issue_device_crl(so, &[Purpose::PackageSigning], 86_400).unwrap());
    let dev1 = repl::device_certificate(w.tokens[1].user).unwrap();
    w.as_so(0, |so| repl::enroll_crl(so, &crl, Some(&dev1)).unwrap());
    let trust = trust_of(&w, 0);
    assert!(pki::validate_chain(&chain, Purpose::PackageSigning, &trust, w.now, Profile::Educational).is_err(), "revoked function cert");
    let rchain = pki::chain_from_ders(&repl::function_chain(w.tokens[1].user, Purpose::RecoveryRecipient).unwrap()).unwrap();
    pki::validate_chain(&rchain, Purpose::RecoveryRecipient, &trust, w.now, Profile::Educational).expect("other functions unaffected");
    // A root-only CRL cannot revoke a leaf issued by a device issuer: the
    // manufacturing root's CRL is not consulted for function certificates.
    let mut ca = w.ca;
    ca.revoke(&repl::function_certificate(w.tokens[1].user, Purpose::RecoveryRecipient).unwrap(), w.now).unwrap();
    let root_crl = ca.crl(w.now - 10, w.now + 86_400).unwrap();
    let t2 = pki::TrustInputs { roots: trust.roots.clone(), crls: trust.crls.iter().cloned().chain([root_crl]).collect() };
    pki::validate_chain(&rchain, Purpose::RecoveryRecipient, &t2, w.now, Profile::Educational).expect("root CRL does not reach device-issued leaves");
}

#[test]
fn k2_snapshot_format_f14() {
    use softhsmrustv3::state_snapshot::{deserialize_token_state, serialize_token_state};
    let _g = lock();
    let w = world(1);
    let (ps, _) = policies(&w);
    let key = gen_aes(w.tokens[0].user, 32, Some(&ps)).unwrap();
    let key_uid = uid(w.tokens[0].user, key);
    let snap = serialize_token_state();
    assert_eq!(&snap[..8], b"SHR3SNP3");
    assert_eq!(&snap[snap.len() - 8..], b"SNP3END\0");
    // Round trip keeps the hierarchy.
    deserialize_token_state(&snap).unwrap();
    assert!(repl::records::list(0, repl::records::ROLE_TRUST_ANCHOR).len() == 1);
    // Truncated / partially written / extended snapshots are refused, and the
    // engine is left untouched.
    let objects_before = softhsmrustv3::state::OBJECTS.with(|o| o.borrow().len());
    for bad in [snap[..snap.len() - 1].to_vec(), snap[..snap.len() - 20].to_vec(), [snap.clone(), vec![0]].concat()] {
        assert_eq!(deserialize_token_state(&bad), Err(CKR_GENERAL_ERROR));
    }
    let mut count_lie = snap.clone();
    let n = count_lie.len();
    count_lie[n - 12] ^= 1; // replication-object count in the trailer
    assert_eq!(deserialize_token_state(&count_lie), Err(CKR_GENERAL_ERROR));
    assert_eq!(softhsmrustv3::state::OBJECTS.with(|o| o.borrow().len()), objects_before);
    // A newer format is refused with the allocated code.
    let mut newer = snap.clone();
    newer[7] = b'4';
    assert_eq!(deserialize_token_state(&newer), Err(CKR_PQCTODAY_SNAPSHOT_FORMAT_UNSUPPORTED));
    let mut newer_section = snap.clone();
    newer_section[n - 16] = 2; // section version
    assert_eq!(deserialize_token_state(&newer_section), Err(CKR_PQCTODAY_SNAPSHOT_FORMAT_UNSUPPORTED));
    // An absurd attribute count is refused, not allocated (K0B-R2-12).
    let mut bad_count = snap.clone();
    let pos = find_first_attr_count(&snap);
    bad_count[pos..pos + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(deserialize_token_state(&bad_count), Err(CKR_GENERAL_ERROR));
    // SNP2 migrates with EMPTY replication state: the hierarchy is gone and
    // the bound key keeps its material but loses eligibility.
    let mut v2 = snap[..n - 20].to_vec();
    v2[..8].copy_from_slice(b"SHR3SNP2");
    deserialize_token_state(&v2).expect("SNP2 migrates");
    assert!(repl::records::list(0, repl::records::ROLE_TRUST_ANCHOR).is_empty());
    let migrated = by_uid(&key_uid).expect("key survives migration");
    let attrs = repl::records::object_attrs(migrated).unwrap();
    assert!(!attrs.contains_key(&CKA_PQCTODAY_REPLICATION_POLICY_ID) && !attrs.contains_key(&CKA_PRIV_REPL_BINDING));
}

/// Offset of the first object's attribute count in a snapshot.
fn find_first_attr_count(snap: &[u8]) -> usize {
    let mut p = 8 + 4 + 8;
    let tokens = u32::from_le_bytes(snap[p..p + 4].try_into().unwrap()) as usize;
    p += 4;
    for _ in 0..tokens {
        p += 4 + 1 + 32 + 16 + 32;
        let has_user = snap[p];
        p += 1 + if has_user != 0 { 16 + 32 } else { 0 };
    }
    p += 4; // object count
    p + 4 // past the first handle
}
