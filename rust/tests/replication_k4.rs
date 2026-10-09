//! K4 acceptance — protected replication (plan R3.7; spec §10/§12; review
//! K0B dispositions). Every positive case runs for AES-128/192/256,
//! ML-KEM-768 and ML-DSA-65.
#![cfg(feature = "educational-replication")]

mod replication_common;
use replication_common::*;

use softhsmrustv3::constants::*;
use softhsmrustv3::native;
use softhsmrustv3::replication::{self as repl, asn1::Operation, host_verify, oids::Purpose, CrashPoint, Profile};

const PROHIBITED: Result<(), u32> = Err(CKR_ACTION_PROHIBITED);

fn create(w: &World, s: usize, key: u32, req: &[u8]) -> Result<Vec<u8>, u32> {
    repl::create_replication_package(w.tokens[s].user, key, req)
}

fn import(w: &World, d: usize, pkg: &[u8]) -> Result<(u32, Vec<u8>), u32> {
    repl::import_replication_package(w.tokens[d].user, pkg, &[])
}

fn err<T: std::fmt::Debug>(r: Result<T, u32>) -> Result<(), u32> {
    r.map(|_| ())
}

// ── Positive cases ──────────────────────────────────────────────────────────

#[test]
fn k4_explicit_create_transport_import_all_profiles() {
    let _g = lock();
    let w = world(2);
    let (ps, pd) = policies(&w);
    for kp in ALL {
        let (src, src_pub) = gen_key(w.tokens[0].user, kp, &ps);
        let req = request(&w, 0, 1, Operation::LiveClone, &pd);
        let pkg = create(&w, 0, src, &req).expect("create");
        let (rep, receipt) = import(&w, 1, &pkg).expect("import");
        host_verify::verify_receipt(&receipt, &pkg, &req, &trust_of(&w, 0), w.now, Profile::Educational).expect("receipt");
        prove_same_key(kp, w.tokens[0].user, src, src_pub, w.tokens[1].user, rep);
        // Installed custody and history (owner decision 1; spec §4).
        let b = |a| native::get_attribute_bool(w.tokens[1].user, rep, a).unwrap();
        assert!(b(CKA_SENSITIVE) && !b(CKA_EXTRACTABLE) && !b(CKA_COPYABLE) && !b(CKA_MODIFIABLE), "{kp:?}");
        assert!(!b(CKA_LOCAL) && !b(CKA_ALWAYS_SENSITIVE) && !b(CKA_NEVER_EXTRACTABLE), "{kp:?}");
        assert_eq!(native::get_attribute_u32(w.tokens[1].user, rep, CKA_KEY_GEN_MECHANISM), Some(CKM_UNAVAILABLE_INFORMATION));
        assert!(native::get_attribute(w.tokens[1].user, rep, CKA_PQCTODAY_REPLICATION_PROVENANCE).is_some());
        assert_eq!(native::get_attribute(w.tokens[1].user, rep, CKA_PQCTODAY_REPLICATION_POLICY_ID).unwrap(), pd.to_vec());
        assert_ne!(uid(w.tokens[1].user, rep), uid(w.tokens[0].user, src), "fresh CKA_UNIQUE_ID");
    }
}

#[test]
fn k4_clone_key_is_equivalent_to_explicit_create_import() {
    let _g = lock();
    let w = world(3);
    let (ps, pd) = policies(&w);
    for kp in ALL {
        let (src, src_pub) = gen_key(w.tokens[0].user, kp, &ps);
        // Explicit path to token 1, CloneKey to token 2 (same module).
        let req1 = request(&w, 0, 1, Operation::LiveClone, &pd);
        let pkg = create(&w, 0, src, &req1).unwrap();
        let (h1, r1) = import(&w, 1, &pkg).unwrap();
        let req2 = request(&w, 0, 2, Operation::LiveClone, &pd);
        let (h2, r2) = repl::clone_key(w.tokens[0].user, src, w.tokens[2].user, &req2, &[]).expect("clone");
        prove_same_key(kp, w.tokens[0].user, src, src_pub, w.tokens[2].user, h2);
        // Same installed attribute semantics, modulo identity fields.
        for a in [CKA_CLASS, CKA_KEY_TYPE, CKA_SENSITIVE, CKA_EXTRACTABLE, CKA_LOCAL, CKA_ALWAYS_SENSITIVE,
                  CKA_NEVER_EXTRACTABLE, CKA_KEY_GEN_MECHANISM, CKA_ALLOWED_MECHANISMS, CKA_COPYABLE, CKA_MODIFIABLE,
                  CKA_PQCTODAY_REPLICATION_POLICY_ID, CKA_PQCTODAY_REPLICATION_LINEAGE_ID, CKA_PUBLIC_KEY_INFO] {
            assert_eq!(native::get_attribute(w.tokens[1].user, h1, a), native::get_attribute(w.tokens[2].user, h2, a), "{kp:?} attr {a:#x}");
        }
        // Same receipt structure and size; both verify independently.
        assert_eq!(r1.len(), r2.len());
        let v1 = host_verify::verify_receipt(&r1, &pkg, &req1, &trust_of(&w, 0), w.now, Profile::Educational).unwrap();
        use der::Decode;
        let t2 = repl::asn1::ReplicationReceipt::from_der(&r2).unwrap().tbs;
        assert_eq!(t2.lineage_id.as_bytes(), v1.lineage_id, "{kp:?} same lineage");
        assert_eq!(t2.installed_policy.as_bytes(), v1.installed_policy, "{kp:?} same installed policy");
        assert_eq!(t2.destination_device_id.as_bytes(), w.device_ids()[2], "{kp:?} clone receipt names token 2");
        assert_eq!(t2.installed_unique_id.as_bytes(), uid(w.tokens[2].user, h2).as_slice());
    }
}

#[test]
fn k4_offline_backup_then_restore_with_source_destroyed() {
    let _g = lock();
    let w = world(3); // 0 = operational source, 1 = backup HSM, 2 = new token
    let (ps, pd) = policies(&w);
    for kp in ALL {
        let (src, src_pub) = gen_key(w.tokens[0].user, kp, &ps);
        let src_public_value = src_pub.map(|p| native::get_attribute(w.tokens[0].user, p, CKA_VALUE).unwrap());
        let req = request(&w, 0, 1, Operation::OfflineBackup, &pd);
        let backup = create(&w, 0, src, &req).expect("backup package");
        // Source key destroyed; the package is all that leaves the source.
        assert_eq!(softhsmrustv3::ffi::C_DestroyObject(w.tokens[0].user, src), CKR_OK);
        // A day later the backup HSM imports the downloaded ciphertext.
        repl::set_clock_override(Some(w.now + 86_400));
        let (bk, _) = import(&w, 1, &backup).expect("offline import on backup HSM after a day");
        // Restore onward to a new authorized token.
        let req2 = request(&w, 1, 2, Operation::Restore, &pd);
        let restored_pkg = create(&w, 1, bk, &req2).expect("restore package from backup HSM");
        let (restored, _) = import(&w, 2, &restored_pkg).expect("restore import");
        repl::set_clock_override(Some(w.now));
        // Functional proof: AES against the backup copy; ML-KEM/ML-DSA
        // against the ORIGINAL source public key, which still exists on token 0.
        match kp {
            Kp::Aes(_) => prove_same_key(kp, w.tokens[1].user, bk, None, w.tokens[2].user, restored),
            _ => {
                assert_eq!(by_public_value(&src_public_value.unwrap()).len(), 3, "source + backup + restored public partners");
                prove_same_key(kp, w.tokens[0].user, 0, src_pub, w.tokens[2].user, restored);
            }
        }
    }
}

/// The installed public partner with this raw public value (spec R-11).
fn by_public_value(v: &[u8]) -> Vec<u32> {
    softhsmrustv3::state::OBJECTS.with(|o| {
        o.borrow()
            .iter()
            .filter(|(_, a)| softhsmrustv3::state::get_object_attr_u32_from(a, CKA_CLASS) == Some(CKO_PUBLIC_KEY) && a.get(&CKA_VALUE).map(|x| x.as_slice()) == Some(v))
            .map(|(h, _)| *h)
            .collect()
    })
}

#[test]
fn k4_recovery_key_rotation_keeps_in_flight_backups_restorable() {
    let _g = lock();
    let w = world(2);
    let (ps, pd) = policies(&w);
    let (src, _) = gen_key(w.tokens[0].user, Kp::Aes(32), &ps);
    let src_uid = uid(w.tokens[0].user, src);
    let req_old = request(&w, 0, 1, Operation::OfflineBackup, &pd);
    let pkg_old = create(&w, 0, src, &req_old).unwrap();
    let old_recovery = purpose_cert(&w, 1, Purpose::RecoveryRecipient);
    w.as_so(1, |so| repl::rotate_recovery_key(so).expect("rotate"));
    let new_recovery = purpose_cert(&w, 1, Purpose::RecoveryRecipient);
    assert_ne!(old_recovery, new_recovery);
    // Continuity: same device issuer certifies both.
    let dev = repl::pki::parse_cert(&repl::device_certificate(w.tokens[1].user).unwrap()).unwrap();
    for c in [&old_recovery, &new_recovery] {
        repl::pki::validate_leaf(&repl::pki::parse_cert(c).unwrap(), &dev, Purpose::RecoveryRecipient, w.now, Profile::Educational).unwrap();
    }
    // The in-flight package (sealed to the retired key) still imports.
    let src = by_uid(&src_uid).unwrap();
    let (old_rep, _) = import(&w, 1, &pkg_old).expect("package for retired key imports");
    prove_same_key(Kp::Aes(32), w.tokens[0].user, src, None, w.tokens[1].user, old_rep);
    // New requests name the new key.
    let (src2, _) = gen_key(w.tokens[0].user, Kp::Aes(32), &ps);
    let req_new = request(&w, 0, 1, Operation::LiveClone, &pd);
    let pkg_new = create(&w, 0, src2, &req_new).unwrap();
    let view = host_verify::inspect_package(&pkg_new).unwrap();
    let new_hash = repl::pki::spki_hash(&repl::pki::parse_cert(&new_recovery).unwrap());
    assert_eq!(view.recipient_key_hash, new_hash.to_vec());
    import(&w, 1, &pkg_new).expect("package for new key imports");
}

#[test]
fn k4_policy_preserved_or_tightened() {
    let _g = lock();
    let w = world(2);
    let (ps, _) = policies(&w);
    // Tighter: liveClone only, ML-DSA only, shorter validity, 1 replica.
    let tight = repl::records::build_policy(DOMAIN, [true, false, false], w.device_ids(), w.now - 30, w.now + 86_400, 1, vec![CKM_ML_DSA], false).unwrap();
    let tight_id = w.enroll_policy_everywhere(&tight);
    let (src, src_pub) = gen_key(w.tokens[0].user, Kp::MlDsa, &ps);
    let req = request(&w, 0, 1, Operation::LiveClone, &tight_id);
    let (rep, _) = import(&w, 1, &create(&w, 0, src, &req).unwrap()).unwrap();
    prove_same_key(Kp::MlDsa, w.tokens[0].user, src, src_pub, w.tokens[1].user, rep);
    let mechs = native::get_attribute(w.tokens[1].user, rep, CKA_ALLOWED_MECHANISMS).unwrap();
    assert_eq!(softhsmrustv3::state::parse_allowed_mechanisms(&mechs), vec![CKM_ML_DSA]);
    // A tighter-policy replica cannot do what the policy removed.
    assert!(native::sign(w.tokens[1].user, rep, CKM_HASH_ML_DSA_SHA256, b"x").is_err());
}

#[test]
fn k4_sizing_is_side_effect_free_and_retry_is_byte_identical() {
    let _g = lock();
    let w = world(2);
    let (ps, pd) = policies(&w);
    let (src, _) = gen_key(w.tokens[0].user, Kp::MlKem, &ps);
    let budget = || repl::records::object_attrs(src).unwrap().get(&CKA_PRIV_REPL_BUDGET).cloned();
    let budget_before = budget();
    let req = request(&w, 0, 1, Operation::LiveClone, &pd);
    let n_cache = repl::records::list(w.tokens[0].slot, repl::records::ROLE_PACKAGE_CACHE).len();
    let len = repl::replication_package_length(w.tokens[0].user, src, &req).unwrap();
    let len2 = repl::replication_package_length(w.tokens[0].user, src, &req).unwrap();
    assert_eq!(len, len2);
    assert_eq!(repl::records::list(w.tokens[0].slot, repl::records::ROLE_PACKAGE_CACHE).len(), n_cache, "sizing creates no cache entry");
    assert_eq!(budget(), budget_before, "sizing moves no budget");
    let chal_open = repl::records::list(w.tokens[0].slot, repl::records::ROLE_CHALLENGE).len();
    assert!(chal_open > 0);
    let p1 = create(&w, 0, src, &req).unwrap();
    assert_eq!(p1.len(), len);
    let p2 = create(&w, 0, src, &req).unwrap();
    assert_eq!(p1, p2, "exact retry returns the cached bytes");
    // Import sizing creates no reservation.
    let n_ledger = repl::records::list(w.tokens[1].slot, repl::records::ROLE_LEDGER).len();
    repl::replication_receipt_length(w.tokens[1].user, &p1).unwrap();
    assert_eq!(repl::records::list(w.tokens[1].slot, repl::records::ROLE_LEDGER).len(), n_ledger);
}

#[test]
fn k4_budget_is_conserved_across_a_lineage_k0b_r12() {
    let _g = lock();
    let w = world(3);
    // The source may make at most 2 replicas in total across all descendants.
    let pol = w.policy([true, true, true], 2, test_mechs());
    let p = w.enroll_policy_everywhere(&pol);
    let (src, _) = gen_key(w.tokens[0].user, Kp::Aes(16), &p);
    let lineage = native::get_attribute(w.tokens[0].user, src, CKA_PQCTODAY_REPLICATION_LINEAGE_ID).unwrap();
    // Live clones transfer nothing (review K0B-R2-10): each costs the source 1.
    let (b, _) = import(&w, 1, &create(&w, 0, src, &request(&w, 0, 1, Operation::LiveClone, &p)).unwrap()).unwrap();
    let (c, _) = import(&w, 2, &create(&w, 0, src, &request(&w, 0, 2, Operation::LiveClone, &p)).unwrap()).unwrap();
    assert_eq!(err(create(&w, 0, src, &request(&w, 0, 1, Operation::LiveClone, &p))), PROHIBITED, "source budget exhausted");
    assert_eq!(repl::last_refusal(), Some("replica budget exhausted"));
    // Replicas received no budget and cannot forward the lineage.
    assert_eq!(err(create(&w, 1, b, &request(&w, 1, 2, Operation::LiveClone, &p))), PROHIBITED);
    assert_eq!(repl::last_refusal(), Some("replica budget exhausted"));
    assert_eq!(err(create(&w, 2, c, &request(&w, 2, 0, Operation::LiveClone, &p))), PROHIBITED);
    let total: usize = (0..3).map(|i| replicas_with_lineage(w.tokens[i].slot, &lineage)).sum();
    assert_eq!(total, 3, "original + exactly maxReplicas copies");
}

#[test]
fn k4_one_request_cannot_drain_the_source_k0b_r2_10() {
    let _g = lock();
    let w = world(2);
    let (ps, _) = policies(&w);
    let (src, _) = gen_key(w.tokens[0].user, Kp::Aes(32), &ps);
    // The destination asks for the SOURCE policy itself (equal = "stricter").
    import(&w, 1, &create(&w, 0, src, &request(&w, 0, 1, Operation::LiveClone, &ps)).unwrap()).unwrap();
    let budget = u32::from_le_bytes(repl::records::object_attrs(src).unwrap()[&CKA_PRIV_REPL_BUDGET].as_slice().try_into().unwrap());
    assert_eq!(budget, 15, "one live clone costs exactly one");
}

// ── Negative cases ──────────────────────────────────────────────────────────

#[test]
fn k4_standard_functions_never_export_or_weaken_a_bound_key() {
    let _g = lock();
    let w = world(1);
    let (ps, _) = policies(&w);
    let s = w.tokens[0].user;
    for kp in ALL {
        let (k, _) = gen_key(s, kp, &ps);
        assert_eq!(native::get_attribute(s, k, CKA_VALUE), None, "{kp:?} CKA_VALUE");
        // Ordinary wrap under an AES-KW key.
        let kek = gen_aes(s, 32, None).unwrap();
        let mut mech = [CKM_AES_KEY_WRAP as usize, 0, 0];
        let mut len = 0u32;
        let rv = softhsmrustv3::ffi::C_WrapKey(s, mech.as_mut_ptr() as *mut u8, kek, k, std::ptr::null_mut(), &mut len);
        assert_ne!(rv, CKR_OK, "{kp:?} wrap");
        // Copy into a weaker object.
        let weaker = [(CKA_EXTRACTABLE, bb(true))];
        let t = raw_template(&weaker);
        let mut h = 0;
        assert_ne!(softhsmrustv3::ffi::C_CopyObject(s, k, t.as_ptr() as *mut u8, 1, &mut h), CKR_OK, "{kp:?} copy");
        // Mutation of the binding, lineage, provenance or allowlist.
        for (a, v) in [
            (CKA_PQCTODAY_REPLICATION_POLICY_ID, vec![0u8; 48]),
            (CKA_PQCTODAY_REPLICATION_LINEAGE_ID, vec![0u8; 32]),
            (CKA_PQCTODAY_REPLICATION_PROVENANCE, vec![1]),
            (CKA_ALLOWED_MECHANISMS, ul(CKM_AES_GCM)),
            (CKA_EXTRACTABLE, bb(true)),
        ] {
            let one = [(a, v)];
            let t = raw_template(&one);
            assert_ne!(softhsmrustv3::ffi::C_SetAttributeValue(s, k, t.as_ptr() as *mut u8, 1), CKR_OK, "{kp:?} set {a:#x}");
        }
    }
}

#[test]
fn k4_eligibility_is_opt_in_at_creation_only() {
    let _g = lock();
    let w = world(2);
    let (ps, pd) = policies(&w);
    let s = w.tokens[0].user;
    let count = || softhsmrustv3::state::OBJECTS.with(|o| o.borrow().len());
    // Unenrolled policy → refused, and no key left behind.
    let before = count();
    assert_eq!(gen_aes(s, 32, Some(&[7u8; 48])), Err(CKR_TEMPLATE_INCONSISTENT));
    assert_eq!(count(), before);
    // Extractable / copyable with a policy → refused.
    for bad in [CKA_EXTRACTABLE, CKA_COPYABLE, CKA_MODIFIABLE] {
        let attrs = vec![
            (CKA_CLASS, ul(CKO_SECRET_KEY)), (CKA_KEY_TYPE, ul(CKK_AES)), (CKA_VALUE_LEN, ul(32)),
            (CKA_TOKEN, bb(true)), (CKA_SENSITIVE, bb(true)), (bad, bb(true)),
            (CKA_PQCTODAY_REPLICATION_POLICY_ID, ps.to_vec()),
        ];
        let t = raw_template(&attrs);
        let mut m = [CKM_AES_KEY_GEN as usize, 0, 0];
        let mut h = 0;
        assert_eq!(softhsmrustv3::ffi::C_GenerateKey(s, m.as_mut_ptr() as *mut u8, t.as_ptr() as *mut u8, attrs.len() as u32, &mut h), CKR_TEMPLATE_INCONSISTENT);
    }
    // Engine-computed attributes can never be supplied.
    for forged in [CKA_PQCTODAY_REPLICATION_LINEAGE_ID, CKA_PQCTODAY_REPLICATION_PROVENANCE, CKA_PQCTODAY_FUNCTION_PURPOSE] {
        let attrs = vec![(CKA_CLASS, ul(CKO_SECRET_KEY)), (CKA_KEY_TYPE, ul(CKK_AES)), (CKA_VALUE_LEN, ul(32)), (forged, vec![0u8; 32])];
        let t = raw_template(&attrs);
        let mut m = [CKM_AES_KEY_GEN as usize, 0, 0];
        let mut h = 0;
        assert_eq!(softhsmrustv3::ffi::C_GenerateKey(s, m.as_mut_ptr() as *mut u8, t.as_ptr() as *mut u8, attrs.len() as u32, &mut h), CKR_ATTRIBUTE_READ_ONLY);
    }
    // C_CreateObject with a plaintext value cannot claim a binding.
    let attrs = vec![(CKA_CLASS, ul(CKO_SECRET_KEY)), (CKA_KEY_TYPE, ul(CKK_AES)), (CKA_VALUE, vec![1u8; 32]), (CKA_PQCTODAY_REPLICATION_POLICY_ID, ps.to_vec())];
    let t = raw_template(&attrs);
    let mut h = 0;
    assert_eq!(softhsmrustv3::ffi::C_CreateObject(s, t.as_ptr() as *mut u8, attrs.len() as u32, &mut h), CKR_ATTRIBUTE_READ_ONLY);
    // Excluded classes: generic secret, ML-DSA-44, HSS.
    let attrs = vec![(CKA_CLASS, ul(CKO_SECRET_KEY)), (CKA_KEY_TYPE, ul(CKK_GENERIC_SECRET)), (CKA_VALUE_LEN, ul(32)), (CKA_TOKEN, bb(true)), (CKA_SENSITIVE, bb(true)), (CKA_PQCTODAY_REPLICATION_POLICY_ID, ps.to_vec())];
    let t = raw_template(&attrs);
    let mut m = [CKM_GENERIC_SECRET_KEY_GEN as usize, 0, 0];
    assert_eq!(softhsmrustv3::ffi::C_GenerateKey(s, m.as_mut_ptr() as *mut u8, t.as_ptr() as *mut u8, attrs.len() as u32, &mut h), CKR_TEMPLATE_INCONSISTENT);
    // An unbound key, a device key and a function key are not replicable.
    let unbound = gen_aes(s, 32, None).unwrap();
    let req = request(&w, 0, 1, Operation::LiveClone, &pd);
    assert_eq!(err(create(&w, 0, unbound, &req)), Err(CKR_KEY_FUNCTION_NOT_PERMITTED));
    for role in [repl::records::ROLE_DEVICE_KEY, repl::records::ROLE_FUNCTION_KEY] {
        let (fk, _) = repl::records::list(w.tokens[0].slot, role)[0].clone();
        assert_eq!(err(create(&w, 0, fk, &req)), Err(CKR_KEY_FUNCTION_NOT_PERMITTED));
    }
}

#[test]
fn k4_trust_identity_and_policy_refusals_k0b_r13() {
    let _g = lock();
    let w = world(3);
    let (ps, pd) = policies(&w);
    // Every policy this test uses is enrolled BEFORE any key exists: an SO
    // step logs the user out, which re-keys private handles.
    let weak = repl::records::build_policy(DOMAIN, [true, true, true], w.device_ids(), w.now - 60, w.now + 30 * 86_400, 500, test_mechs(), false).unwrap();
    let weak_id = w.enroll_policy_everywhere(&weak);
    let other = repl::records::build_policy([0x11; 32], [true, true, true], w.device_ids(), w.now - 60, w.now + 30 * 86_400, 1, test_mechs(), false).unwrap();
    let other_id = w.enroll_policy_everywhere(&other);
    let (src, _) = gen_key(w.tokens[0].user, Kp::Aes(32), &ps);
    // Wrong recipient: package for 1 imported on 2.
    let pkg = create(&w, 0, src, &request(&w, 0, 1, Operation::LiveClone, &pd)).unwrap();
    assert_eq!(err(import(&w, 2, &pkg)), PROHIBITED, "wrong recipient");
    // Honest reason (review K0B-R2-07): token 2 never reserved this
    // transaction, so the reservation check refuses before the recipient
    // binding is reached. The recipient check is defence in depth: a
    // package can only match another token's reservation by forging the
    // source's signature.
    assert_eq!(repl::last_refusal(), Some("no destination reservation for transaction"));
    // Tampering: header, ciphertext and signature bytes.
    for at in [pkg.len() / 3, pkg.len() - 4000, pkg.len() - 10] {
        let mut t = pkg.clone();
        t[at] ^= 0x01;
        let r = err(import(&w, 1, &t));
        assert!(r == PROHIBITED || r == Err(CKR_DATA_INVALID), "tamper at {at}: {r:?}");
    }
    import(&w, 1, &pkg).expect("untampered still imports");
    // Stale destination evidence.
    let req = request(&w, 0, 1, Operation::LiveClone, &pd);
    repl::set_clock_override(Some(w.now + 400));
    assert_eq!(err(create(&w, 0, src, &req)), PROHIBITED, "stale evidence");
    repl::set_clock_override(Some(w.now));
    // Weakening policy: destination asks for MORE replicas than the source allows.
    let (src2, _) = gen_key(w.tokens[0].user, Kp::Aes(32), &ps);
    assert_eq!(err(create(&w, 0, src2, &request(&w, 0, 1, Operation::LiveClone, &weak_id))), PROHIBITED, "weakening");
    // Wrong domain.
    let chal = repl::issue_source_challenge(w.tokens[0].user).unwrap();
    let req = repl::begin_receive(w.tokens[1].user, Operation::LiveClone, &chal, &[0x11; 32], &other_id).unwrap();
    assert_eq!(err(create(&w, 0, src2, &req)), PROHIBITED, "wrong domain");
    // Source challenge not issued by the source / reused.
    let req = repl::begin_receive(w.tokens[1].user, Operation::LiveClone, &[0x42; 32], &DOMAIN, &pd).unwrap();
    assert_eq!(err(create(&w, 0, src2, &req)), PROHIBITED, "unissued challenge");
    let chal = repl::issue_source_challenge(w.tokens[0].user).unwrap();
    let r1 = repl::begin_receive(w.tokens[1].user, Operation::LiveClone, &chal, &DOMAIN, &pd).unwrap();
    let r2 = repl::begin_receive(w.tokens[2].user, Operation::LiveClone, &chal, &DOMAIN, &pd).unwrap();
    create(&w, 0, src2, &r1).unwrap();
    let (src3, _) = gen_key(w.tokens[0].user, Kp::Aes(32), &ps);
    assert_eq!(err(create(&w, 0, src3, &r2)), PROHIBITED, "challenge reuse across transactions");
    // Same transaction ID for a different source key (K0B-R-07).
    let r3 = request(&w, 0, 2, Operation::LiveClone, &pd);
    create(&w, 0, src3, &r3).unwrap();
    let (src4, _) = gen_key(w.tokens[0].user, Kp::Aes(32), &ps);
    assert_eq!(err(create(&w, 0, src4, &r3)), PROHIBITED, "txid reuse across keys");
}

#[test]
fn k4_substitution_untrusted_root_revocation_and_same_device() {
    let _g = lock();
    let w = world(3);
    let (ps, pd) = policies(&w);
    let (src, _) = gen_key(w.tokens[0].user, Kp::MlDsa, &ps);
    // Key substitution: token 2's (valid) recovery chain with token 1's evidence.
    use der::{Decode, Encode};
    let req = request(&w, 0, 1, Operation::LiveClone, &pd);
    let mut parsed = repl::asn1::ReplicationRequest::from_der(&req).unwrap();
    parsed.recipient_chain = repl::pki::chain_from_ders(&repl::function_chain(w.tokens[2].user, Purpose::RecoveryRecipient).unwrap()).unwrap();
    assert_eq!(err(create(&w, 0, src, &parsed.to_der().unwrap())), PROHIBITED, "recipient chain substitution (K0B-R-03)");
    // Revocation: token 1 revokes its recovery cert; token 0 learns it.
    let crl = w.as_so(1, |so| repl::issue_device_crl(so, &[Purpose::RecoveryRecipient], 86_400).unwrap());
    let dev1 = repl::device_certificate(w.tokens[1].user).unwrap();
    let src_uid = uid(w.tokens[0].user, src);
    w.as_so(0, |so| repl::enroll_crl(so, &crl, Some(&dev1)).unwrap());
    let src = by_uid(&src_uid).unwrap();
    assert_eq!(err(create(&w, 0, src, &request(&w, 0, 1, Operation::LiveClone, &pd))), PROHIBITED, "revoked recovery cert");
    // CRL rollback is refused.
    let old = w.as_so(1, |so| repl::own_device_crl(so).unwrap());
    let src_uid = uid(w.tokens[0].user, src);
    assert_eq!(w.as_so(0, |so| repl::enroll_crl(so, &old, Some(&dev1))), Err(CKR_ACTION_PROHIBITED));
    // Same device: policy forbids it.
    let src = by_uid(&src_uid).unwrap();
    let chal = repl::issue_source_challenge(w.tokens[0].user).unwrap();
    let req = repl::begin_receive(w.tokens[0].user, Operation::LiveClone, &chal, &DOMAIN, &pd).unwrap();
    assert_eq!(err(create(&w, 0, src, &req)), PROHIBITED, "same device");
    // Expired CRL (fail closed): advance past every CRL's nextUpdate.
    repl::set_clock_override(Some(w.now + 40 * 86_400));
    let chal = repl::issue_source_challenge(w.tokens[0].user).unwrap();
    assert_eq!(err(repl::begin_receive(w.tokens[1].user, Operation::LiveClone, &chal, &DOMAIN, &pd)), PROHIBITED, "expired policy/CRLs fail closed");
    repl::set_clock_override(Some(w.now));
}

#[test]
fn k4_untrusted_root_is_refused() {
    let _g = lock();
    let w = world(2);
    let (ps, pd) = policies(&w);
    // A third token enrolled under a DIFFERENT manufacturing root.
    let s3 = 2u32;
    native::init_token(s3, SO, "rogue").unwrap();
    let so = native::open_session_so(s3, SO).unwrap();
    native::init_pin(so, USER).unwrap();
    let mut rogue = repl::test_ca::TestManufacturingCa::new(w.now).unwrap();
    let csr = repl::begin_device_enrollment(so).unwrap();
    let dev = rogue.issue_device(&csr, w.now).unwrap();
    let crl = rogue.crl(w.now - 10, w.now + 86_400).unwrap();
    repl::complete_device_enrollment(so, rogue.root_der(), &dev, &crl).unwrap();
    repl::issue_function_certificates(so).unwrap();
    repl::enroll_policy(so, &w.policy([true, true, true], 1, test_mechs())).unwrap();
    native::logout(so).unwrap();
    let user3 = native::open_session(s3, USER).unwrap();
    let (src, _) = gen_key(w.tokens[0].user, Kp::Aes(16), &ps);
    let chal = repl::issue_source_challenge(w.tokens[0].user).unwrap();
    let req = repl::begin_receive(user3, Operation::LiveClone, &chal, &DOMAIN, &pd).unwrap();
    assert_eq!(err(create(&w, 0, src, &req)), PROHIBITED);
}

#[test]
fn k4_malformed_requests_and_packages() {
    let _g = lock();
    let w = world(2);
    let (ps, pd) = policies(&w);
    let (src, _) = gen_key(w.tokens[0].user, Kp::Aes(32), &ps);
    let req = request(&w, 0, 1, Operation::LiveClone, &pd);
    assert_eq!(err(create(&w, 0, src, b"\x30\x03\x02\x01\x01")), Err(CKR_DATA_INVALID));
    assert_eq!(err(create(&w, 0, src, &vec![0x30; 70 * 1024])), Err(CKR_DATA_INVALID), "oversized");
    // BER long-form length for the outer SEQUENCE.
    let mut ber = vec![0x30, 0x84];
    let body = &req[4..];
    ber.extend_from_slice(&(body.len() as u32).to_be_bytes());
    ber.extend_from_slice(body);
    assert_eq!(err(create(&w, 0, src, &ber)), Err(CKR_DATA_INVALID), "BER rejected");
    assert_eq!(err(import(&w, 1, b"not a package")), Err(CKR_DATA_INVALID));
    // Template that tries to weaken or set server-managed values.
    let pkg = create(&w, 0, src, &req).unwrap();
    for t in [vec![(CKA_EXTRACTABLE, bb(true))], vec![(CKA_ENCRYPT, bb(true))], vec![(CKA_VALUE, vec![0; 32])]] {
        assert_eq!(err(repl::import_replication_package(w.tokens[1].user, &pkg, &t)), Err(CKR_TEMPLATE_INCONSISTENT));
    }
    // Tightening is allowed.
    let (h, _) = repl::import_replication_package(w.tokens[1].user, &pkg, &[(CKA_ENCRYPT, bb(false)), (CKA_LABEL, b"edu".to_vec())]).unwrap();
    assert_eq!(native::get_attribute_bool(w.tokens[1].user, h, CKA_ENCRYPT), Some(false));
    // Role / login precedence.
    assert_eq!(err(repl::import_replication_package(0xdead, &pkg, &[])), Err(CKR_SESSION_HANDLE_INVALID));
}

#[test]
fn k4_replay_and_duplicate_install_are_refused() {
    let _g = lock();
    let w = world(2);
    let (ps, pd) = policies(&w);
    for kp in ALL {
        let (src, _) = gen_key(w.tokens[0].user, kp, &ps);
        let lineage = native::get_attribute(w.tokens[0].user, src, CKA_PQCTODAY_REPLICATION_LINEAGE_ID).unwrap();
        let req = request(&w, 0, 1, Operation::LiveClone, &pd);
        let pkg = create(&w, 0, src, &req).unwrap();
        let (h1, r1) = import(&w, 1, &pkg).unwrap();
        let (h2, r2) = import(&w, 1, &pkg).expect("exact retry is recovery");
        assert_eq!((h1, &r1), (h2, &r2), "{kp:?} same handle, byte-identical receipt");
        assert_eq!(replicas_with_lineage(w.tokens[1].slot, &lineage), 1, "{kp:?} no second install");
    }
}

#[test]
fn k4_every_crash_window_recovers_to_exactly_one_key() {
    let _g = lock();
    for point in [
        CrashPoint::CreateBeforeCommit,
        CrashPoint::ImportAfterReserve,
        CrashPoint::ImportAfterDecrypt,
        CrashPoint::ImportBeforeCommit,
        CrashPoint::ImportAfterCommit,
    ] {
        let mut w = world(2);
        let (ps, pd) = policies(&w);
        let (src, src_pub) = gen_key(w.tokens[0].user, Kp::MlKem, &ps);
        let lineage = native::get_attribute(w.tokens[0].user, src, CKA_PQCTODAY_REPLICATION_LINEAGE_ID).unwrap();
        let req = request(&w, 0, 1, Operation::LiveClone, &pd);
        repl::inject_crash(Some(point));
        let pkg = match create(&w, 0, src, &req) {
            Err(CKR_DEVICE_ERROR) => {
                assert_eq!(point, CrashPoint::CreateBeforeCommit);
                // Durable state survives a restart: snapshot → reload.
                restart(&mut w);
                create(&w, 0, by_uid_after_restart(&w, 0, &lineage), &req).expect("create retry after crash")
            }
            r => r.expect("create"),
        };
        let first = import(&w, 1, &pkg);
        if point != CrashPoint::CreateBeforeCommit {
            assert_eq!(err(first.clone()), Err(CKR_DEVICE_ERROR), "{point:?}");
            restart(&mut w);
        }
        let (h, receipt) = import(&w, 1, &pkg).expect("retry after crash");
        let (h2, receipt2) = import(&w, 1, &pkg).expect("second retry");
        assert_eq!((h, &receipt), (h2, &receipt2), "{point:?}");
        assert_eq!(replicas_with_lineage(w.tokens[1].slot, &lineage), 1, "{point:?} exactly one key");
        let src = by_uid_after_restart(&w, 0, &lineage);
        let src_pub = src_pub.map(|_| public_partner(w.tokens[0].slot, &lineage));
        prove_same_key(Kp::MlKem, w.tokens[0].user, src, src_pub, w.tokens[1].user, h);
    }
}

/// Fill `slot`'s consumption ledger with synthetic committed entries until it
/// holds `total` entries. The entries carry random transaction ids and mark
/// nothing as installed, so they only occupy capacity.
fn fill_ledger_to(w: &World, d: usize, total: usize) {
    use repl::asn1::LedgerRecord;
    use repl::records::{self, ROLE_LEDGER};
    let have = records::list(w.tokens[d].slot, ROLE_LEDGER).len();
    let mut objs = Vec::new();
    for i in have..total {
        let mut txid = [0u8; 32];
        txid[..8].copy_from_slice(&(i as u64).to_be_bytes());
        txid[8] = 0xfe; // never a real transaction id (real ones are random)
        let rec = LedgerRecord {
            transaction_id: repl::asn1::octets(&txid),
            state: 2,
            package_hash: repl::asn1::octets(&[0u8; 48]),
            installed_unique_id: String::new(),
            receipt: repl::asn1::octets(&[]),
        };
        objs.push(records::new_record(ROLE_LEDGER, CKO_DATA, "consumption ledger entry", Vec::new(), repl::asn1::to_der(&rec).unwrap(), true));
    }
    softhsmrustv3::state::commit_objects_atomically(w.tokens[d].user, objs, Vec::new()).expect("fill ledger");
    assert_eq!(records::list(w.tokens[d].slot, ROLE_LEDGER).len(), total);
}

/// Spec §10 / review K0B-R-15: the destination consumption ledger holds at
/// most 4,096 entries. The bound is enforced, not just declared: a full ledger
/// refuses a new import with CKR_DEVICE_MEMORY and reserves and installs
/// nothing; the 4,096th entry is accepted; and an import that already holds
/// its reservation still completes when the ledger is full.
#[test]
fn k4_ledger_capacity_is_enforced_k0b_r15() {
    use repl::records::{self, ROLE_LEDGER, MAX_LEDGER_ENTRIES};
    assert_eq!(MAX_LEDGER_ENTRIES, 4096);
    let _g = lock();

    // 1. Full ledger: a fresh import is refused and leaves no trace.
    let w = world(2);
    let (ps, pd) = policies(&w);
    let (src, _) = gen_key(w.tokens[0].user, Kp::Aes(32), &ps);
    let lineage = native::get_attribute(w.tokens[0].user, src, CKA_PQCTODAY_REPLICATION_LINEAGE_ID).unwrap();
    let pkg = create(&w, 0, src, &request(&w, 0, 1, Operation::LiveClone, &pd)).unwrap();
    fill_ledger_to(&w, 1, MAX_LEDGER_ENTRIES);
    assert_eq!(err(import(&w, 1, &pkg)), Err(CKR_DEVICE_MEMORY), "full ledger refuses a new import");
    assert_eq!(records::list(w.tokens[1].slot, ROLE_LEDGER).len(), MAX_LEDGER_ENTRIES, "nothing reserved");
    assert_eq!(replicas_with_lineage(w.tokens[1].slot, &lineage), 0, "nothing installed");

    // 2. One slot free: the import is accepted and takes the last entry.
    let w = world(2);
    let (ps, pd) = policies(&w);
    let (src, _) = gen_key(w.tokens[0].user, Kp::Aes(32), &ps);
    let lineage = native::get_attribute(w.tokens[0].user, src, CKA_PQCTODAY_REPLICATION_LINEAGE_ID).unwrap();
    let pkg = create(&w, 0, src, &request(&w, 0, 1, Operation::LiveClone, &pd)).unwrap();
    fill_ledger_to(&w, 1, MAX_LEDGER_ENTRIES - 1);
    import(&w, 1, &pkg).expect("the 4,096th entry is accepted");
    assert_eq!(records::list(w.tokens[1].slot, ROLE_LEDGER).len(), MAX_LEDGER_ENTRIES);
    assert_eq!(replicas_with_lineage(w.tokens[1].slot, &lineage), 1);

    // 3. An import that already reserved its entry completes on a full ledger.
    let w = world(2);
    let (ps, pd) = policies(&w);
    let (src, _) = gen_key(w.tokens[0].user, Kp::Aes(32), &ps);
    let lineage = native::get_attribute(w.tokens[0].user, src, CKA_PQCTODAY_REPLICATION_LINEAGE_ID).unwrap();
    let pkg = create(&w, 0, src, &request(&w, 0, 1, Operation::LiveClone, &pd)).unwrap();
    repl::inject_crash(Some(CrashPoint::ImportAfterReserve));
    assert_eq!(err(import(&w, 1, &pkg)), Err(CKR_DEVICE_ERROR), "crash after the reservation");
    repl::inject_crash(None);
    assert_eq!(records::list(w.tokens[1].slot, ROLE_LEDGER).len(), 1, "one reservation survived");
    fill_ledger_to(&w, 1, MAX_LEDGER_ENTRIES);
    import(&w, 1, &pkg).expect("the reserved import completes although the ledger is now full");
    assert_eq!(records::list(w.tokens[1].slot, ROLE_LEDGER).len(), MAX_LEDGER_ENTRIES, "no extra entry");
    assert_eq!(replicas_with_lineage(w.tokens[1].slot, &lineage), 1, "exactly one key");
}

/// Simulate a process restart: serialize nonvolatile state, wipe the engine,
/// reload, and log the users back in.
fn restart(w: &mut World) {
    let snap = softhsmrustv3::state_snapshot::serialize_token_state();
    softhsmrustv3::ffi::reset_all_engine_state_for_test();
    let _ = native::finalize();
    native::init().unwrap();
    softhsmrustv3::state_snapshot::deserialize_token_state(&snap).expect("reload snapshot");
    for t in w.tokens.iter_mut() {
        t.user = native::open_session(t.slot, USER).expect("re-login after restart");
    }
}

fn by_uid_after_restart(_w: &World, slot: usize, lineage: &[u8]) -> u32 {
    softhsmrustv3::state::OBJECTS.with(|o| {
        o.borrow()
            .iter()
            .find(|(_, a)| {
                softhsmrustv3::state::object_slot_of(a) == slot as u32
                    && a.get(&CKA_PQCTODAY_REPLICATION_LINEAGE_ID).map(|v| v.as_slice()) == Some(lineage)
                    && softhsmrustv3::state::get_object_attr_u32_from(a, CKA_CLASS) != Some(CKO_PUBLIC_KEY)
            })
            .map(|(h, _)| *h)
            .unwrap()
    })
}

fn public_partner(slot: u32, lineage: &[u8]) -> u32 {
    softhsmrustv3::state::OBJECTS.with(|o| {
        o.borrow()
            .iter()
            .find(|(_, a)| {
                softhsmrustv3::state::object_slot_of(a) == slot
                    && a.get(&CKA_PQCTODAY_REPLICATION_LINEAGE_ID).map(|v| v.as_slice()) == Some(lineage)
                    && softhsmrustv3::state::get_object_attr_u32_from(a, CKA_CLASS) == Some(CKO_PUBLIC_KEY)
            })
            .map(|(h, _)| *h)
            .unwrap()
    })
}

#[test]
fn k4_concurrent_duplicate_imports_install_once() {
    let _g = lock();
    let w = world(2);
    let (ps, pd) = policies(&w);
    let (src, _) = gen_key(w.tokens[0].user, Kp::Aes(24), &ps);
    let lineage = native::get_attribute(w.tokens[0].user, src, CKA_PQCTODAY_REPLICATION_LINEAGE_ID).unwrap();
    let pkg = create(&w, 0, src, &request(&w, 0, 1, Operation::LiveClone, &pd)).unwrap();
    let dst = w.tokens[1].user;
    let results: Vec<_> = std::thread::scope(|sc| {
        (0..8).map(|_| sc.spawn(|| repl::import_replication_package(dst, &pkg, &[]))).collect::<Vec<_>>()
            .into_iter().map(|h| h.join().unwrap()).collect()
    });
    let first = results[0].clone().unwrap();
    for r in &results {
        assert_eq!(r.as_ref().unwrap(), &first);
    }
    assert_eq!(replicas_with_lineage(w.tokens[1].slot, &lineage), 1);
}

#[test]
fn k4_native_interface_discovery_and_calls() {
    use softhsmrustv3::ck_abi::*;
    let _g = lock();
    let w = world(2);
    let (ps, pd) = policies(&w);
    unsafe {
        let mut name = b"PQCTODAY_KEY_REPLICATION_1_0\0".to_vec();
        let mut p: CK_INTERFACE_PTR = std::ptr::null_mut();
        // Exact version required; unknown version/flags/NULL version refused.
        for (v, f) in [(Some((1, 1)), 0), (Some((2, 0)), 0), (None, 0), (Some((1, 0)), 1)] {
            let mut ver = v.map(|(a, b)| CK_VERSION { major: a, minor: b });
            let vp = ver.as_mut().map(|x| x as *mut CK_VERSION).unwrap_or(std::ptr::null_mut());
            assert_eq!(C_GetInterface(name.as_mut_ptr(), vp, &mut p, f), CKR_FUNCTION_FAILED as CK_RV);
        }
        let mut v10 = CK_VERSION { major: 1, minor: 0 };
        assert_eq!(C_GetInterface(name.as_mut_ptr(), &mut v10, &mut p, 0), CKR_OK as CK_RV);
        let fl = &*((*p).pFunctionList as *const PQCTODAY_KEY_REPLICATION_FUNCTION_LIST_1_0);
        assert_eq!(fl.version, v10);
        // NULL name still selects the standard 3.2 list.
        let mut q: CK_INTERFACE_PTR = std::ptr::null_mut();
        assert_eq!(C_GetInterface(std::ptr::null_mut(), std::ptr::null_mut(), &mut q, 0), CKR_OK as CK_RV);
        assert_eq!(*((*q).pFunctionList as *const CK_VERSION), CK_VERSION { major: 3, minor: 2 });
        // The list includes the three vendor interfaces (v1, admin,
        // ceremony) last, only while selected.
        let mut n: CK_ULONG = 0;
        C_GetInterfaceList(std::ptr::null_mut(), &mut n);
        assert_eq!(n, 6);
        repl::clear_profile();
        C_GetInterfaceList(std::ptr::null_mut(), &mut n);
        assert_eq!(n, 3);
        assert_eq!(C_GetInterface(name.as_mut_ptr(), &mut v10, &mut p, 0), CKR_FUNCTION_FAILED as CK_RV);
        repl::select_educational_profile();

        // Create → import through the function list.
        let (src, _) = gen_key(w.tokens[0].user, Kp::Aes(32), &ps);
        let mut req = request(&w, 0, 1, Operation::LiveClone, &pd);
        let mut len: CK_ULONG = 0;
        let s0 = w.tokens[0].user as CK_ULONG;
        assert_eq!((fl.C_PQCTODAY_CreateReplicationPackage)(s0, src as CK_ULONG, req.as_mut_ptr(), req.len() as CK_ULONG, std::ptr::null_mut(), &mut len), 0);
        let mut small = vec![0u8; 10];
        let mut small_len: CK_ULONG = 10;
        assert_eq!((fl.C_PQCTODAY_CreateReplicationPackage)(s0, src as CK_ULONG, req.as_mut_ptr(), req.len() as CK_ULONG, small.as_mut_ptr(), &mut small_len), CKR_BUFFER_TOO_SMALL as CK_RV);
        assert_eq!(small_len, len);
        let mut pkg = vec![0u8; len as usize];
        assert_eq!((fl.C_PQCTODAY_CreateReplicationPackage)(s0, src as CK_ULONG, req.as_mut_ptr(), req.len() as CK_ULONG, pkg.as_mut_ptr(), &mut len), 0);
        let s1 = w.tokens[1].user as CK_ULONG;
        let mut rlen: CK_ULONG = 0;
        let mut hk: CK_OBJECT_HANDLE = 0;
        // phInstalledKey must be NULL on the sizing call.
        assert_eq!((fl.C_PQCTODAY_ImportReplicationPackage)(s1, pkg.as_mut_ptr(), len, std::ptr::null_mut(), 0, &mut hk, std::ptr::null_mut(), &mut rlen), CKR_ARGUMENTS_BAD as CK_RV);
        assert_eq!((fl.C_PQCTODAY_ImportReplicationPackage)(s1, pkg.as_mut_ptr(), len, std::ptr::null_mut(), 0, std::ptr::null_mut(), std::ptr::null_mut(), &mut rlen), 0);
        // Too-small receipt buffer fails before reservation.
        let mut tiny: CK_ULONG = 4;
        let mut tb = [0u8; 4];
        assert_eq!((fl.C_PQCTODAY_ImportReplicationPackage)(s1, pkg.as_mut_ptr(), len, std::ptr::null_mut(), 0, &mut hk, tb.as_mut_ptr(), &mut tiny), CKR_BUFFER_TOO_SMALL as CK_RV);
        assert!(repl::records::list(w.tokens[1].slot, repl::records::ROLE_LEDGER).is_empty());
        let mut receipt = vec![0u8; rlen as usize];
        assert_eq!((fl.C_PQCTODAY_ImportReplicationPackage)(s1, pkg.as_mut_ptr(), len, std::ptr::null_mut(), 0, &mut hk, receipt.as_mut_ptr(), &mut rlen), 0);
        prove_same_key(Kp::Aes(32), w.tokens[0].user, src, None, w.tokens[1].user, hk as u32);
        // CloneKey through the list.
        let (src2, _) = gen_key(w.tokens[0].user, Kp::Aes(16), &ps);
        let mut req2 = request(&w, 0, 1, Operation::LiveClone, &pd);
        let mut rlen2 = rlen;
        let mut receipt2 = vec![0u8; rlen as usize];
        let mut hk2: CK_OBJECT_HANDLE = 0;
        assert_eq!((fl.C_PQCTODAY_CloneKey)(s0, src2 as CK_ULONG, s1, req2.as_mut_ptr(), req2.len() as CK_ULONG, std::ptr::null_mut(), 0, &mut hk2, receipt2.as_mut_ptr(), &mut rlen2), 0);
        prove_same_key(Kp::Aes(16), w.tokens[0].user, src2, None, w.tokens[1].user, hk2 as u32);
    }
}

// ── Two independent processes (plan R1.4 / R3.7) ───────────────────────────

const CHILD_ENV: &str = "PQCTODAY_REPL_CHILD_DIR";

fn wait_for(dir: &std::path::Path, name: &str) -> Vec<u8> {
    let p = dir.join(name);
    for _ in 0..1200 {
        if let Ok(b) = std::fs::read(&p) {
            if std::fs::metadata(dir.join(format!("{name}.done"))).is_ok() {
                return b;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("timed out waiting for {name}");
}

fn put(dir: &std::path::Path, name: &str, data: &[u8]) {
    std::fs::write(dir.join(name), data).unwrap();
    std::fs::write(dir.join(format!("{name}.done")), b"").unwrap();
}

/// Destination half, run in a CHILD process (no-op when run normally).
#[test]
fn k4_two_process_child_destination() {
    let Ok(dir) = std::env::var(CHILD_ENV) else { return };
    let dir = std::path::PathBuf::from(dir);
    let now: u64 = String::from_utf8(wait_for(&dir, "now")).unwrap().parse().unwrap();
    softhsmrustv3::ffi::reset_all_engine_state_for_test();
    repl::set_clock_override(Some(now));
    repl::select_educational_profile();
    native::init().unwrap();
    native::init_token(0, SO, "child").unwrap();
    let so = native::open_session_so(0, SO).unwrap();
    native::init_pin(so, USER).unwrap();
    put(&dir, "csr", &repl::begin_device_enrollment(so).unwrap());
    let (root, dev, crl) = (wait_for(&dir, "root"), wait_for(&dir, "dev"), wait_for(&dir, "rootcrl"));
    repl::complete_device_enrollment(so, &root, &dev, &crl).unwrap();
    repl::issue_function_certificates(so).unwrap();
    put(&dir, "b_dev", &repl::device_certificate(so).unwrap());
    put(&dir, "b_crl", &repl::own_device_crl(so).unwrap());
    put(&dir, "b_id", &repl::device_id(so).unwrap());
    let (a_dev, a_crl, policy) = (wait_for(&dir, "a_dev"), wait_for(&dir, "a_crl"), wait_for(&dir, "policy"));
    repl::enroll_crl(so, &a_crl, Some(&a_dev)).unwrap();
    let pid = repl::enroll_policy(so, &policy).unwrap();
    native::logout(so).unwrap();
    let user = native::open_session(0, USER).unwrap();
    let chal: [u8; 32] = wait_for(&dir, "chal").try_into().unwrap();
    put(&dir, "request", &repl::begin_receive(user, Operation::LiveClone, &chal, &DOMAIN, &pid).unwrap());
    let pkg = wait_for(&dir, "package");
    let (h, receipt) = repl::import_replication_package(user, &pkg, &[]).unwrap();
    put(&dir, "receipt", &receipt);
    let ct = wait_for(&dir, "ct");
    let pt = native::decrypt(user, h, CKM_AES_GCM, &ct, Some(&[3u8; 12]), None, b"", Some(16)).unwrap();
    put(&dir, "pt", &pt);
}

#[test]
fn k4_two_process_create_transport_import() {
    if std::env::var(CHILD_ENV).is_ok() {
        return;
    }
    let _g = lock();
    let dir = std::env::temp_dir().join(format!("pqctoday-repl-{}-{}", std::process::id(), repl_nonce()));
    std::fs::create_dir_all(&dir).unwrap();
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "k4_two_process_child_destination", "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, &dir)
        .spawn()
        .unwrap();
    let w = world(1);
    put(&dir, "now", w.now.to_string().as_bytes());
    let mut ca = w.ca;
    let csr = wait_for(&dir, "csr");
    put(&dir, "root", ca.root_der());
    put(&dir, "dev", &ca.issue_device(&csr, w.now).unwrap());
    let rootcrl = ca.crl(w.now - 10, w.now + 86_400).unwrap();
    put(&dir, "rootcrl", &rootcrl);
    let (b_dev, b_crl, b_id) = (wait_for(&dir, "b_dev"), wait_for(&dir, "b_crl"), wait_for(&dir, "b_id"));
    let a = &w.tokens[0];
    native::logout(a.user).unwrap();
    let so = native::open_session_so(0, SO).unwrap();
    repl::enroll_crl(so, &rootcrl, None).unwrap();
    repl::enroll_crl(so, &b_crl, Some(&b_dev)).unwrap();
    let a_id = repl::device_id(so).unwrap();
    let policy = repl::records::build_policy(DOMAIN, [true, true, true], vec![a_id, b_id.try_into().unwrap()], w.now - 60, w.now + 86_400, 1, test_mechs(), false).unwrap();
    let pid = repl::enroll_policy(so, &policy).unwrap();
    put(&dir, "a_dev", &repl::device_certificate(so).unwrap());
    put(&dir, "a_crl", &repl::own_device_crl(so).unwrap());
    put(&dir, "policy", &policy);
    native::logout(so).unwrap();
    native::close_session(so).unwrap();
    let user = native::open_session(0, USER).unwrap();
    // The source key is bound to the same policy (max 1 → transfers 0).
    let src = gen_aes(user, 32, Some(&pid)).unwrap();
    put(&dir, "chal", &repl::issue_source_challenge(user).unwrap());
    let req = wait_for(&dir, "request");
    let pkg = repl::create_replication_package(user, src, &req).unwrap();
    put(&dir, "package", &pkg);
    let receipt = wait_for(&dir, "receipt");
    host_verify::verify_receipt(&receipt, &pkg, &req, &repl::trust_inputs(0), w.now, Profile::Educational).expect("child's receipt verifies in parent");
    let ct = native::encrypt(user, src, CKM_AES_GCM, b"across processes", Some(&[3u8; 12]), None, b"", Some(16)).unwrap();
    put(&dir, "ct", &ct);
    assert_eq!(wait_for(&dir, "pt"), b"across processes");
    let status = child.wait_with_output().unwrap().status;
    assert!(status.success(), "child process failed");
    let _ = std::fs::remove_dir_all(&dir);
}

fn repl_nonce() -> String {
    format!("{:x}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos())
}

// ── Second independent review (K0B-R2-*) regressions ───────────────────────

#[test]
fn k4_restricted_keys_are_not_eligible_k0b_r2_01() {
    let _g = lock();
    let w = world(1);
    let (ps, _) = policies(&w);
    let s = w.tokens[0].user;
    // A DECAPSULATE_TEMPLATE the payload could not carry → binding refused,
    // and no key is left behind.
    let inner = [(CKA_EXTRACTABLE, bb(false))];
    let inner_t = raw_template(&inner);
    let inner_bytes: Vec<u8> = inner_t.iter().flat_map(|x| x.to_le_bytes()).collect();
    let pubt_a = vec![(CKA_TOKEN, bb(true)), (CKA_PARAMETER_SET, ul(CKP_ML_KEM_768)), (CKA_ENCAPSULATE, bb(true))];
    let prvt_a = vec![
        (CKA_TOKEN, bb(true)), (CKA_SENSITIVE, bb(true)), (CKA_EXTRACTABLE, bb(false)), (CKA_COPYABLE, bb(false)),
        (CKA_MODIFIABLE, bb(false)), (CKA_DECAPSULATE, bb(true)), (CKA_DECAPSULATE_TEMPLATE, inner_bytes),
        (CKA_PQCTODAY_REPLICATION_POLICY_ID, ps.to_vec()),
    ];
    let (pubt, prvt) = (raw_template(&pubt_a), raw_template(&prvt_a));
    let mut m = [CKM_ML_KEM_KEY_PAIR_GEN as usize, 0, 0];
    let (mut hp, mut hk) = (0u32, 0u32);
    let before = softhsmrustv3::state::OBJECTS.with(|o| o.borrow().len());
    let rv = softhsmrustv3::ffi::C_GenerateKeyPair(s, m.as_mut_ptr() as *mut u8, pubt.as_ptr() as *mut u8, pubt_a.len() as u32,
        prvt.as_ptr() as *mut u8, prvt_a.len() as u32, &mut hp, &mut hk);
    assert_eq!(rv, CKR_TEMPLATE_INCONSISTENT);
    assert_eq!(softhsmrustv3::state::OBJECTS.with(|o| o.borrow().len()), before, "no half-bound key left");
    let _ = inner_t;
}

#[test]
fn k4_importer_rechecks_source_policy_k0b_r2_05() {
    let _g = lock();
    let w = world(2);
    // The source policy is enrolled ONLY at the source.
    let src_pol = w.policy([true, true, true], 4, test_mechs());
    let ps = w.as_so(0, |so| repl::enroll_policy(so, &src_pol).unwrap());
    let dst_pol = w.policy([true, true, true], 1, test_mechs());
    let pd = w.enroll_policy_everywhere(&dst_pol);
    let (src, _) = gen_key(w.tokens[0].user, Kp::Aes(16), &ps);
    let pkg = create(&w, 0, src, &request(&w, 0, 1, Operation::LiveClone, &pd)).unwrap();
    assert_eq!(err(import(&w, 1, &pkg)), PROHIBITED);
    assert_eq!(repl::last_refusal(), Some("source policy not enrolled at destination"));
}

#[test]
fn k4_read_only_sessions_cannot_mutate_k0b_r2_06() {
    let _g = lock();
    let w = world(2);
    let (ps, pd) = policies(&w);
    let (src, _) = gen_key(w.tokens[0].user, Kp::Aes(32), &ps);
    let pkg = create(&w, 0, src, &request(&w, 0, 1, Operation::LiveClone, &pd)).unwrap();
    let mut ro = 0u32;
    assert_eq!(softhsmrustv3::ffi::C_OpenSession(1, CKF_SERIAL_SESSION, std::ptr::null_mut(), std::ptr::null_mut(), &mut ro), CKR_OK);
    assert_eq!(err(repl::import_replication_package(ro, &pkg, &[])), Err(CKR_SESSION_READ_ONLY));
    assert_eq!(err(repl::issue_source_challenge(ro)), Err(CKR_SESSION_READ_ONLY));
    assert!(repl::records::list(1, repl::records::ROLE_LEDGER).is_empty(), "no reservation from a R/O session");
}

#[test]
fn k4_expired_peer_crl_fails_closed_k0b_r2_07() {
    let _g = lock();
    let w = world(2);
    let (ps, pd) = policies(&w);
    let (src, _) = gen_key(w.tokens[0].user, Kp::Aes(32), &ps);
    // Policies (30 days) and certificates stay valid; the root CRL (7 days)
    // does not.
    repl::set_clock_override(Some(w.now + 8 * 86_400));
    let req = request(&w, 0, 1, Operation::LiveClone, &pd);
    assert_eq!(err(create(&w, 0, src, &req)), PROHIBITED);
    assert_eq!(repl::last_refusal(), Some("no current CRL for issuer"));
    repl::set_clock_override(Some(w.now));
}

#[test]
fn k4_records_are_pruned_and_reservations_cancellable_k0b_r2_04() {
    let _g = lock();
    let w = world(2);
    let (ps, pd) = policies(&w);
    for _ in 0..10 {
        repl::issue_source_challenge(w.tokens[0].user).unwrap();
    }
    let (src, _) = gen_key(w.tokens[0].user, Kp::Aes(32), &ps);
    create(&w, 0, src, &request(&w, 0, 1, Operation::LiveClone, &pd)).unwrap();
    assert_eq!(repl::records::list(0, repl::records::ROLE_PACKAGE_CACHE).len(), 1);
    // Past every window: dead challenges and the cached package are pruned.
    repl::set_clock_override(Some(w.now + 2 * 3600));
    repl::issue_source_challenge(w.tokens[0].user).unwrap();
    assert_eq!(repl::records::list(0, repl::records::ROLE_CHALLENGE).len(), 1, "only the fresh challenge remains");
    let (src2, _) = gen_key(w.tokens[0].user, Kp::Aes(32), &ps);
    create(&w, 0, src2, &request(&w, 0, 1, Operation::LiveClone, &pd)).unwrap();
    assert_eq!(repl::records::list(0, repl::records::ROLE_PACKAGE_CACHE).len(), 1, "expired cache entry pruned");
    // An abandoned offline-backup reservation can be cancelled.
    let chal = repl::issue_source_challenge(w.tokens[0].user).unwrap();
    let req = repl::begin_receive(w.tokens[1].user, Operation::OfflineBackup, &chal, &DOMAIN, &pd).unwrap();
    use der::Decode;
    let txid: [u8; 32] = repl::asn1::ReplicationRequest::from_der(&req).unwrap().transaction_id.as_bytes().try_into().unwrap();
    repl::cancel_receive(w.tokens[1].user, &txid).unwrap();
    let (src3, _) = gen_key(w.tokens[0].user, Kp::Aes(32), &ps);
    let pkg = create(&w, 0, src3, &req).unwrap();
    assert_eq!(err(import(&w, 1, &pkg)), PROHIBITED, "cancelled reservation cannot be used");
    repl::set_clock_override(Some(w.now));
}

#[test]
fn k4_receipt_is_bound_to_the_packages_recipient_k0b_r2_09() {
    let _g = lock();
    let w = world(3);
    let (ps, pd) = policies(&w);
    let (src, _) = gen_key(w.tokens[0].user, Kp::Aes(32), &ps);
    let req1 = request(&w, 0, 1, Operation::LiveClone, &pd);
    let pkg1 = create(&w, 0, src, &req1).unwrap();
    let (_, r1) = import(&w, 1, &pkg1).unwrap();
    let req2 = request(&w, 0, 2, Operation::LiveClone, &pd);
    let pkg2 = create(&w, 0, src, &req2).unwrap();
    let (_, r2) = import(&w, 2, &pkg2).unwrap();
    let t = trust_of(&w, 0);
    host_verify::verify_receipt(&r1, &pkg1, &req1, &t, w.now, Profile::Educational).unwrap();
    // Token 2's genuine receipt does not verify as an acknowledgement of a
    // package sealed to token 1, nor against the wrong request.
    assert!(host_verify::verify_receipt(&r2, &pkg1, &req1, &t, w.now, Profile::Educational).is_err());
    assert!(host_verify::verify_receipt(&r1, &pkg1, &req2, &t, w.now, Profile::Educational).is_err());
}

#[test]
fn k4_clone_sizing_checks_the_source_first_k0b_r2_08() {
    use softhsmrustv3::ck_abi::*;
    let _g = lock();
    let w = world(2);
    let (_, pd) = policies(&w);
    let mut req = request(&w, 0, 1, Operation::LiveClone, &pd);
    unsafe {
        let mut name = b"PQCTODAY_KEY_REPLICATION_1_0\0".to_vec();
        let mut v = CK_VERSION { major: 1, minor: 0 };
        let mut p: CK_INTERFACE_PTR = std::ptr::null_mut();
        assert_eq!(C_GetInterface(name.as_mut_ptr(), &mut v, &mut p, 0), 0);
        let fl = &*((*p).pFunctionList as *const PQCTODAY_KEY_REPLICATION_FUNCTION_LIST_1_0);
        let mut len: CK_ULONG = 0;
        let rv = (fl.C_PQCTODAY_CloneKey)(w.tokens[0].user as CK_ULONG, 0xdead, w.tokens[1].user as CK_ULONG,
            req.as_mut_ptr(), req.len() as CK_ULONG, std::ptr::null_mut(), 0, std::ptr::null_mut(), std::ptr::null_mut(), &mut len);
        assert_eq!(rv, CKR_KEY_HANDLE_INVALID as CK_ULONG);
    }
}

#[test]
fn k4_native_destroy_respects_destroyable_k0b_r2_11() {
    let _g = lock();
    let w = world(1);
    let (ps, _) = policies(&w);
    let (h, _) = repl::records::list(0, repl::records::ROLE_POLICY)[0].clone();
    assert_eq!(native::destroy_object(w.tokens[0].user, h), Err(CKR_ACTION_PROHIBITED));
    let _ = ps;
}
