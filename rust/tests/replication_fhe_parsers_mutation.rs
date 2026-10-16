//! Parser robustness for FHE custody (plan D02387 WP-A3; spec docs/proposals/pkcs11-ckm-pqctoday-fhe-proposal.md
//! §10 gate 5, "fuzzing of the policy and parameter parsers"). The repository has no cargo-fuzz targets, so these are
//! deterministic mutation tests with a fixed-seed xorshift: every truncation, extensions, every single-byte change at
//! every position (three masks), and seeded random rewrites of a valid encoding, plus wholly random buffers. For every
//! mutant each engine parser must not panic, and must either refuse it cleanly or return a value whose canonical DER is
//! exactly the input (no second encoding of one value is accepted).
//!
//! Inputs: `FheDecryptPolicy` versions 1 and 2, the recovery descriptor, the CKKS key-set descriptor and signed manifest
//! (real ones, from the token), the TFHE signed manifest (educational-fhe builds), `AdminSignedRequest` with each FHE
//! operation [5], [6] and [7], and the CKKS decrypt input. Signed objects also go through their verifier on a sample
//! of mutants: a mutated manifest never verifies, a mutated admin request never commits.
#![cfg(all(pqc_ckks_custody, feature = "test-support"))]

mod replication_common;
use replication_common::*;

use der::{Decode, Encode};
use softhsmrustv3::constants::*;
use softhsmrustv3::native;
use softhsmrustv3::replication::admin::{self, AdminOperation, AdminSignedRequest};
use softhsmrustv3::replication::fhe_ckks::{mech, params, spec::Generator};
use softhsmrustv3::replication::fhe_custody as fc;
use softhsmrustv3::replication::{self as repl, admin_host, asn1, fhe, oids::Purpose, records};

/// xorshift64*, fixed seed: the same mutants on every run and platform.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

/// Call `f` on every mutant of `valid` (never on `valid` itself), one reused buffer at a time. Exhaustive classes:
/// every proper prefix; 1..=8 appended bytes; every position XORed with 0x01, 0x80 and 0xff. Seeded classes: `random`
/// rewrites of 1..=8 random positions, `random / 4` insertions or deletions of a short run, and `random / 4` wholly
/// random buffers of up to twice the length.
fn for_each_mutant(valid: &[u8], seed: u64, random: usize, mut f: impl FnMut(usize, &[u8])) {
    let mut rng = Rng(seed | 1);
    let mut i = 0usize;
    let mut emit = |v: &[u8], f: &mut dyn FnMut(usize, &[u8])| {
        if v != valid {
            f(i, v);
            i += 1;
        }
    };
    for n in 0..valid.len() {
        emit(&valid[..n], &mut f);
    }
    let mut v = valid.to_vec();
    for n in 1..=8 {
        v.truncate(valid.len());
        let tail = rng.bytes(n);
        v.extend(tail);
        emit(&v, &mut f);
    }
    v.truncate(valid.len());
    for p in 0..valid.len() {
        for mask in [0x01u8, 0x80, 0xff] {
            v[p] ^= mask;
            emit(&v, &mut f);
            v[p] ^= mask;
        }
    }
    for _ in 0..random {
        let mut w = valid.to_vec();
        for _ in 0..1 + rng.below(8) {
            let p = rng.below(w.len());
            w[p] = rng.next() as u8;
        }
        emit(&w, &mut f);
    }
    for _ in 0..random / 4 {
        let mut w = valid.to_vec();
        let at = rng.below(w.len());
        if rng.next() & 1 == 0 {
            let len = 1 + rng.below(16);
            let run = rng.bytes(len);
            let _ = w.splice(at..at, run);
        } else {
            let end = (at + 1 + rng.below(16)).min(w.len());
            w.drain(at..end);
        }
        emit(&w, &mut f);
    }
    for _ in 0..random / 4 {
        let n = rng.below(2 * valid.len() + 1);
        let w = rng.bytes(n);
        emit(&w, &mut f);
    }
}

/// Run `parse` on every mutant: no panic; `Some(der)` (accepted) only when `der` is the mutant itself. Returns the
/// number of mutants accepted.
fn check(name: &str, valid: &[u8], seed: u64, random: usize, parse: impl Fn(&[u8]) -> Option<Vec<u8>>) -> usize {
    assert_eq!(parse(valid).as_deref(), Some(valid), "{name}: the valid input parses and re-encodes to itself");
    let mut accepted = 0;
    for_each_mutant(valid, seed, random, |i, m| {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| parse(m)));
        match r {
            Err(_) => panic!("{name}: mutant {i} ({} bytes) panicked: {}", m.len(), hex(m)),
            Ok(Some(der)) => {
                assert_eq!(der, m, "{name}: mutant {i} accepted but re-encodes differently");
                accepted += 1;
            }
            Ok(None) => {}
        }
    });
    accepted
}

/// A deterministic sample of `n` mutants, for the slower verifiers: one prefix, extension, single-byte change or
/// short random rewrite each.
fn sample(valid: &[u8], seed: u64, n: usize) -> Vec<Vec<u8>> {
    let mut rng = Rng(seed ^ 0x5eed);
    let mut out = Vec::new();
    while out.len() < n {
        let mut v = valid.to_vec();
        match rng.below(4) {
            0 => v.truncate(rng.below(valid.len())),
            1 => {
                let k = 1 + rng.below(8);
                let tail = rng.bytes(k);
                v.extend(tail);
            }
            2 => {
                let p = rng.below(v.len());
                v[p] ^= [0x01u8, 0x80, 0xff][rng.below(3)];
            }
            _ => {
                for _ in 0..1 + rng.below(8) {
                    let p = rng.below(v.len());
                    v[p] = rng.next() as u8;
                }
            }
        }
        if v != valid {
            out.push(v);
        }
    }
    out
}

fn hex(b: &[u8]) -> String {
    b.iter().take(64).map(|x| format!("{x:02x}")).collect()
}

fn strict<T: for<'a> Decode<'a> + Encode>(m: &[u8], max: usize) -> Option<Vec<u8>> {
    asn1::decode_strict::<T>(m, max).ok().map(|v| v.to_der().unwrap())
}

fn tfhe_type(name: &str, w: u16) -> fhe::FheType {
    fhe::FheType { type_name: name.into(), width_bits: w, param_set: 1, serialization_version: 1, compressed_allowed: false }
}

fn policy_v1() -> Vec<u8> {
    fhe::FheDecryptPolicy {
        version: 1,
        allowed_output_types: vec![tfhe_type("FheBool", 1), tfhe_type("FheUint8", 8)],
        never_release: vec![tfhe_type("FheUint64", 64)],
        predicates: vec![fhe::Predicate { kind: fhe::PredicateKind::MaxValue, bound: 200 }, fhe::Predicate { kind: fhe::PredicateKind::MinValue, bound: 1 }],
        recipients: vec![der::asn1::OctetString::new(vec![3u8; 48]).unwrap(), der::asn1::OctetString::new(vec![4u8; 48]).unwrap()],
        recipient_only: true,
        max_decrypts: 1000,
        ckks: None,
    }
    .to_der()
    .unwrap()
}

fn policy_v2() -> Vec<u8> {
    let ps = params::find(0x8002).unwrap();
    fhe::FheDecryptPolicy {
        version: 2,
        allowed_output_types: vec![mech::release_type(ps)],
        never_release: vec![],
        predicates: vec![],
        recipients: vec![der::asn1::OctetString::new(vec![3u8; 48]).unwrap()],
        recipient_only: false,
        max_decrypts: 100,
        ckks: Some(fhe::CkksReleasePolicy { max_values: 64, precision_bits: 20, value_bound_log2: 10, scale_log2: ps.log_default_scale as u8, flood_recipients: true, flood_owner: true, stat_security_bits: 40 }),
    }
    .to_der()
    .unwrap()
}

/// `parse_decrypt_policy`: an accepted mutant is canonical and its ID is its SHA-384.
fn parse_policy(m: &[u8]) -> Option<Vec<u8>> {
    let v = fhe::parse_decrypt_policy(m).ok()?;
    let der = v.policy.to_der().unwrap();
    assert_eq!(v.id.to_vec(), sha384(m));
    Some(der)
}

fn sha384(b: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    sha2::Sha384::digest(b).to_vec()
}

#[test]
fn decrypt_policy_parser_survives_mutation() {
    let v1 = check("FheDecryptPolicy v1", &policy_v1(), 0xa3_0001, 4000, parse_policy);
    let v2 = check("FheDecryptPolicy v2", &policy_v2(), 0xa3_0002, 4000, parse_policy);
    eprintln!("policy mutants accepted as other valid policies: v1 {v1}, v2 {v2}");
}

#[test]
fn recovery_descriptor_parser_survives_mutation() {
    let lineage = [6u8; 32];
    for (set, scheme) in [(1u32, fhe::FHE_SCHEME_TFHE), (0x8002, fhe::FHE_SCHEME_CKKS), (3, fhe::FHE_SCHEME_CKKS)] {
        let d = fhe::FheRecoveryDescriptor {
            version: 1,
            scheme: scheme.into(),
            param_set: set,
            param_hash: der::asn1::OctetString::new(fhe::param_hash(set).unwrap().to_vec()).unwrap(),
            library: fhe::library_for(set),
            generator_version: 1,
            lineage_id: der::asn1::OctetString::new(lineage.to_vec()).unwrap(),
            decrypt_policy: der::asn1::OctetString::new(vec![7u8; 48]).unwrap(),
        }
        .to_der()
        .unwrap();
        check(&format!("FheRecoveryDescriptor set {set}"), &d, 0xa3_0010 + set as u64, 4000, |m| fhe::validate_descriptor(m, &lineage).ok().map(|d| d.to_der().unwrap()));
    }
}

/// The CKKS key-set descriptor and the token-signed manifest, both real (the token on the test ring), and the TFHE
/// signed manifest. A sample of manifest mutants goes through the verifier: none verifies.
#[test]
fn ckks_descriptor_and_signed_manifests_survive_mutation() {
    let _g = lock();
    let w = world(1);
    let ps = params::find(0x8002).unwrap();
    let rp = records::build_policy_with_constraint(
        DOMAIN, [true, true, true], w.device_ids(), w.now - 60, w.now + 30 * 86_400, 4,
        vec![CKM_PQCTODAY_FHE_DERIVE_PUBLIC, CKM_PQCTODAY_FHE_DECRYPT], false, fhe::ckks_profile_constraint_hash(),
    )
    .unwrap();
    let mut dp: fhe::FheDecryptPolicy = Decode::from_der(&policy_v2()).unwrap();
    dp.recipients.clear();
    let dp = dp.to_der().unwrap();
    let (rpid, dpid) = w.as_so(0, |so| (repl::enroll_policy(so, &rp).unwrap(), fhe::enroll_fhe_decrypt_policy(so, &dp).unwrap()));
    let s = w.tokens[0].user;
    let h = fhe::generate_fhe_seed_with_value_for_test(s, 0x8002, &rpid, &dpid, &[1u8; 32], b"mutation").unwrap();
    let derive = |kind: u32, k: u32, d: u32, from: usize, to: usize| {
        let o = mech::derive_public_v2(s, h, kind, k, d, from, to).unwrap();
        let v = native::get_attribute(s, o, CKA_VALUE).unwrap();
        assert_eq!(softhsmrustv3::ffi::C_DestroyObject(s, o), CKR_OK);
        v
    };
    let desc = derive(mech::PUBLIC_KIND_CKKS_DESCRIPTOR, 0, 0, 0, 0);
    derive(mech::PUBLIC_KIND_CKKS_PUBLIC_KEY, 0, 0, 0, ps.pk_limbs());
    for (k, key) in ps.keys.iter().enumerate() {
        for d in 0..key.dnum() {
            derive(mech::PUBLIC_KIND_CKKS_EVK_CHUNK, k as u32, d as u32, 0, key.limbs());
        }
    }
    let manifest = derive(mech::PUBLIC_KIND_CKKS_MANIFEST, 0, 0, 0, 0);
    let trust = trust_of(&w, 0);
    assert!(mech::verify_ckks_manifest(&manifest, &trust, w.now).is_ok());

    check("CkksKeySetDescriptorV1", &desc, 0xa3_0020, 4000, |m| strict::<mech::CkksKeySetDescriptorV1>(m, 4096));
    check("CkksSignedManifestV1", &manifest, 0xa3_0021, 4000, |m| strict::<mech::CkksSignedManifestV1>(m, fc::MAX_PUBLIC_OBJECT));
    for (i, m) in sample(&manifest, 0xa3_0022, 300).iter().enumerate() {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| mech::verify_ckks_manifest(m, &trust, w.now)));
        assert!(matches!(r, Ok(Err(_))), "mutated CKKS manifest {i} verified or panicked");
    }

    // TFHE signed manifest (parameter version 1, kind 3): the same shape, built here around the token's real
    // receipt-signing chain (deriving kinds 1 and 2 for a real one costs a 30 MB server key).
    #[cfg(feature = "educational-fhe")]
    {
        use softhsmrustv3::replication::fhe_tfhe as tf;
        // [receipt-signing certificate, device certificate], as the token signs with.
        let chain: Vec<x509_cert::Certificate> = repl::function_chain(s, Purpose::ReceiptSigning).unwrap().iter().map(|c| Decode::from_der(c).unwrap()).collect();
        let m = tf::TfheSignedManifestV1 {
            tbs: tf::TfheManifestTbsV1 {
                version: 1,
                param_hash: der::asn1::OctetString::new(fhe::param_hash(1).unwrap().to_vec()).unwrap(),
                lineage: der::asn1::OctetString::new(vec![9u8; 32]).unwrap(),
                entries: vec![
                    tf::TfheExportHash { kind: 1, sha256: der::asn1::OctetString::new(vec![1u8; 32]).unwrap() },
                    tf::TfheExportHash { kind: 2, sha256: der::asn1::OctetString::new(vec![2u8; 32]).unwrap() },
                ],
            },
            signature: der::asn1::OctetString::new(vec![0u8; 3309]).unwrap(),
            signer_chain: chain,
        }
        .to_der()
        .unwrap();
        check("TfheSignedManifestV1", &m, 0xa3_0023, 4000, |x| strict::<tf::TfheSignedManifestV1>(x, fc::MAX_PUBLIC_OBJECT));
        for (i, x) in sample(&m, 0xa3_0024, 200).iter().enumerate() {
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| tf::verify_tfhe_manifest(x, &trust, w.now)));
            assert!(matches!(r, Ok(Err(_))), "mutated TFHE manifest {i} verified or panicked");
        }
    }
}

/// `AdminSignedRequest` carrying each FHE operation: strict decode, the operation's own syntax check
/// (`AdminTbsRequest::operation`) and, for [5], the policy parser. A sample goes through `admin::execute` in a real
/// SO session with an enrolled admin authority: none commits.
#[test]
fn admin_requests_with_fhe_operations_survive_mutation() {
    use softhsmrustv3::replication::test_ca::AdminAuthorityKey;
    let _g = lock();
    let w = world(1);
    let key = AdminAuthorityKey::new(&w.ca, w.now).unwrap();
    w.as_so(0, |so| admin::enroll_admin_authority(so, &key.cert_der).unwrap());
    let dev = repl::device_id(w.tokens[0].user).unwrap();
    let rchain = repl::function_chain(w.tokens[0].user, Purpose::RecoveryRecipient).unwrap();
    let ops = [
        AdminOperation::EnrollFheDecryptPolicy { policy: policy_v2() },
        AdminOperation::EnrollFheRecipient { chain: rchain },
        AdminOperation::DestroyFheSeed { lineage: [8u8; 32] },
    ];
    let parse = |m: &[u8]| -> Option<Vec<u8>> {
        let r: AdminSignedRequest = asn1::decode_strict(m, admin::MAX_ADMIN_REQUEST_DER).ok()?;
        if let Ok(AdminOperation::EnrollFheDecryptPolicy { policy }) = r.tbs.operation() {
            let _ = fhe::parse_decrypt_policy(&policy);
        }
        Some(r.to_der().unwrap())
    };
    for (i, op) in ops.iter().enumerate() {
        let tbs = admin_host::tbs_request(&dev, &key.key_id(), &[2u8; 32], 1, w.now, op).unwrap();
        let req = admin_host::signed_request(&tbs, &key.sign(&admin_host::request_signed_bytes(&tbs)).unwrap()).unwrap();
        // The recipient chain makes [6] large; fewer random rewrites keep the run short.
        check(&format!("AdminSignedRequest [{}]", 5 + i), &req, 0xa3_0030 + i as u64, if i == 1 { 1000 } else { 4000 }, &parse);
        let samples = sample(&req, 0xa3_0040 + i as u64, 100);
        let results: Vec<Result<Vec<u8>, u32>> = w.as_so(0, |so| samples.iter().map(|m| admin::execute(so, m)).collect());
        for (j, r) in results.iter().enumerate() {
            assert!(r.is_err(), "mutated admin request [{}] sample {j} committed", 5 + i);
        }
    }
}

/// The CKKS decrypt input: the size query is shape-only and spends nothing, so every mutant goes through it (an
/// accepted mutant keeps the valid header and length: only coefficient words changed); a sample goes through real
/// decryptions, which never panic and refuse with the one policy code or a length code.
#[test]
fn ckks_decrypt_input_survives_mutation() {
    let _g = lock();
    let w = world(1);
    let ps = params::find(0x8002).unwrap();
    let rp = records::build_policy_with_constraint(
        DOMAIN, [true, true, true], w.device_ids(), w.now - 60, w.now + 30 * 86_400, 4,
        vec![CKM_PQCTODAY_FHE_DERIVE_PUBLIC, CKM_PQCTODAY_FHE_DECRYPT], false, fhe::ckks_profile_constraint_hash(),
    )
    .unwrap();
    let mut dp: fhe::FheDecryptPolicy = Decode::from_der(&policy_v2()).unwrap();
    dp.recipients.clear();
    dp.max_decrypts = 100_000;
    dp.ckks.as_mut().unwrap().flood_owner = false;
    let dp = dp.to_der().unwrap();
    let (rpid, dpid) = w.as_so(0, |so| (repl::enroll_policy(so, &rp).unwrap(), fhe::enroll_fhe_decrypt_policy(so, &dp).unwrap()));
    let s = w.tokens[0].user;
    let seed_value = [4u8; 32];
    let h = fhe::generate_fhe_seed_with_value_for_test(s, 0x8002, &rpid, &dpid, &seed_value, b"ct-mutation").unwrap();
    let m: Vec<i128> = (0..ps.n() as i128).map(|i| ((i % 5) - 2) << 20).collect();
    let (c0, c1) = Generator::new(ps, &seed_value).encrypt_for_test(0, &m, &[5u8; 32]).unwrap();
    let mut ct = mech::CT_MAGIC.to_vec();
    for v in [0x8002u32, 0, ps.log_default_scale as u32, 0] {
        ct.extend_from_slice(&v.to_le_bytes());
    }
    for v in c0.iter().chain(&c1) {
        ct.extend_from_slice(&v.to_le_bytes());
    }
    let header = 24;
    assert!(fc::decrypt(s, h, &[0u8; 48], &ct, false).is_ok());
    // Size query: exhaustive over the header, prefixes and extensions; seeded over the coefficient words.
    let size_query = |i: usize, x: &[u8]| {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fc::decrypt(s, h, &[0u8; 48], x, true)));
        match r {
            Err(_) => panic!("decrypt size query panicked on mutant {i}"),
            Ok(Ok(_)) => assert!(x.len() == ct.len() && x[..header] == ct[..header], "mutant {i} passed the type gate with another shape"),
            Ok(Err(e)) => assert!(matches!(e, CKR_ACTION_PROHIBITED | CKR_DATA_LEN_RANGE), "mutant {i}: {e:#x}"),
        }
    };
    let mut full = Vec::with_capacity(ct.len() + 64);
    for_each_mutant(&ct[..header + 64], 0xa3_0050, 2000, |i, x| {
        full.clear();
        full.extend_from_slice(x);
        if x.len() >= header + 64 {
            full.extend_from_slice(&ct[header + 64..]);
        }
        size_query(i, &full);
    });
    for (i, x) in sample(&ct, 0xa3_0051, 500).iter().enumerate() {
        size_query(i, x);
    }
    let before = records::object_attrs(h).unwrap().get(&fc::CKA_PRIV_FHE_DECRYPT_COUNT).cloned();
    assert_eq!(before, Some(1u64.to_le_bytes().to_vec()), "size queries spent nothing");
    for (i, x) in sample(&ct, 0xa3_0052, 150).iter().enumerate() {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fc::decrypt(s, h, &[0u8; 48], x, false)));
        match r {
            Err(_) => panic!("decrypt panicked on mutant {i}"),
            Ok(Ok(_)) => assert!(x.len() == ct.len() && x[..header] == ct[..header]),
            Ok(Err(e)) => assert!(matches!(e, CKR_ACTION_PROHIBITED | CKR_DATA_LEN_RANGE), "mutant {i}: {e:#x}"),
        }
    }
}
