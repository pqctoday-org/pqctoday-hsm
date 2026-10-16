//! Registry ID 3 (E13, option O2b of pqctoday-fhe
//! docs/ckks/ckks-flooding-parameter-options-2026-10-11.md): META-BTS with two
//! bootstraps per refresh, scale 2^90, release over two primes. Known answers
//! against the pqctoday-fhe oracle (Lattigo-based reference spec), the
//! two-prime decryption with flooding sized by the registry noise bound
//! (gate F floor), serialization versions 2 and 3, and the policy scale range.
//!
//! Registry ID 4 (OpenFHE v1.6.0 `match128`; pqctoday-fhe
//! docs/ckks/ckks-openfhe-registry-entry-spec-2026-10-12.md): known answers
//! against the oracle, and the owner-release-only rule of a set without a
//! measured flood bound.
#![cfg(all(pqc_ckks_custody, feature = "test-support"))]

mod replication_common;
use replication_common::*;

use sha2::Digest;
use softhsmrustv3::constants::*;
use softhsmrustv3::replication::fhe_ckks::{mech, params, spec::Generator};
use softhsmrustv3::replication::fhe_custody::DecryptOutput;
use softhsmrustv3::replication::{self as repl, fhe, records};

const KAT_SEED: [u8; 32] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31];

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn kat() -> serde_json::Value {
    serde_json::from_str(include_str!("../kat/fhe-ckks-kat-3.json")).unwrap()
}

/// SHA-256 over every digit of key `k`, each digit over all its limbs (the oracle's `keySha256`).
fn key_hash(g: &Generator, k: usize) -> String {
    let key = &g.ps.keys[k];
    let mut h = sha2::Sha256::new();
    for d in 0..key.dnum() {
        h.update(g.chunk(k as u32, d as u32, 0, key.limbs()).unwrap());
    }
    hexs(&h.finalize())
}

/// Registry entry, a-seed, public key, the first words of key 0 and the two
/// ephemeral-secret keys against the oracle KAT (seed 00..1f). The full key
/// list is `kat_registry_3_all_keys` (ignored by default: 4.4 GB of chunks).
#[test]
fn kat_registry_3_matches_reference_spec() {
    let kat = kat();
    let ps = params::find(3).unwrap();
    assert_eq!(ps.name, kat["name"].as_str().unwrap());
    assert_eq!(hexs(&params::param_hash(ps)), kat["paramHash"].as_str().unwrap());
    assert_eq!(ps.keys.len() as u64, kat["keyCount"].as_u64().unwrap());
    assert_eq!((ps.log_n, ps.log_default_scale, ps.h, ps.ephemeral_h), (16, 90, 192, 32));
    assert_eq!(params::release_level(ps), 1);
    // Q0·Q1 = 105 bits (study §3).
    let q01 = (ps.residual_q[0] as f64).log2() + (ps.residual_q[1] as f64).log2();
    assert!((104.5..105.5).contains(&q01), "{q01}");
    let g = Generator::new(ps, &KAT_SEED);
    assert_eq!(hexs(&g.a_seed), kat["aSeed"].as_str().unwrap());
    assert_eq!(hexs(&sha2::Sha256::digest(g.pk_chunk(0, ps.pk_limbs()).unwrap())), kat["pkSha256"].as_str().unwrap());
    let first = g.chunk(0, 0, 0, 1).unwrap();
    let words: Vec<u64> = (0..4).map(|i| u64::from_le_bytes(first[8 * i..8 * i + 8].try_into().unwrap())).collect();
    let want: Vec<u64> = kat["firstChunkFirstWords"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap()).collect();
    assert_eq!(words, want);
    let hashes = kat["keySha256"].as_array().unwrap();
    for (k, key) in ps.keys.iter().enumerate() {
        if key.kind == params::KIND_DENSE_TO_SPARSE || key.kind == params::KIND_SPARSE_TO_DENSE {
            assert_eq!(key_hash(&g, k), hashes[k].as_str().unwrap(), "key {k}");
        }
    }
}

#[test]
#[ignore = "4.4 GB of chunks; run with --ignored in a release build"]
fn kat_registry_3_all_keys() {
    let kat = kat();
    let ps = params::find(3).unwrap();
    let g = Generator::new(ps, &KAT_SEED);
    let hashes = kat["keySha256"].as_array().unwrap();
    for k in 0..ps.keys.len() {
        assert_eq!(key_hash(&g, k), hashes[k].as_str().unwrap(), "key {k}");
    }
}

/// One token with the CKKS profile and a version 2 decryption policy for
/// `ps_id` (its release type, all slots, 2^-precision, |v| < 2^10, the set's
/// scale, λ_s = 30, 10,000 decrypts; owner releases flooded when
/// `flood_owner`) and the KAT seed. Returns (world, user session, seed).
fn setup(ps_id: u32, precision_bits: u8, flood_owner: bool) -> (World, u32, u32) {
    use der::Encode;
    let w = world(1);
    let ps = params::find(ps_id).unwrap();
    let rp = records::build_policy_with_constraint(
        DOMAIN, [true, true, true], w.device_ids(), w.now - 60, w.now + 30 * 86_400, 4,
        vec![CKM_PQCTODAY_FHE_DERIVE_PUBLIC, CKM_PQCTODAY_FHE_DECRYPT], false, fhe::ckks_profile_constraint_hash(),
    )
    .unwrap();
    let dpol = fhe::FheDecryptPolicy {
        version: 2,
        allowed_output_types: vec![mech::release_type(ps)],
        never_release: vec![],
        predicates: vec![],
        recipients: vec![],
        recipient_only: false,
        max_decrypts: 10_000,
        ckks: Some(fhe::CkksReleasePolicy { max_values: (ps.n() / 2) as u32, precision_bits, value_bound_log2: 10, scale_log2: ps.log_default_scale as u8, flood_recipients: true, flood_owner, stat_security_bits: 30 }),
    }
    .to_der()
    .unwrap();
    let (rpid, dpid) = w.as_so(0, |so| (repl::enroll_policy(so, &rp).unwrap(), fhe::enroll_fhe_decrypt_policy(so, &dpol).unwrap()));
    let s = w.tokens[0].user;
    let seed = fhe::generate_fhe_seed_with_value_for_test(s, ps_id, &rpid, &dpid, &KAT_SEED, b"ckks-flood-seed").expect("KEY_GEN");
    (w, s, seed)
}

/// Header ‖ c0 limbs ‖ c1 limbs, as the oracle's `e2e` writes it.
fn ct_bytes(magic: &[u8; 8], ps_id: u32, level: u32, scale: u32, c0: &[u64], c1: &[u64]) -> Vec<u8> {
    let mut b = magic.to_vec();
    for v in [ps_id, level, scale, 0] {
        b.extend_from_slice(&v.to_le_bytes());
    }
    for v in c0.iter().chain(c1) {
        b.extend_from_slice(&v.to_le_bytes());
    }
    b
}

/// Deterministic plaintext coefficients, |m| < 2^82 (slot values of a few units at scale 2^90).
fn plaintext(n: usize, bound_log2: u32) -> Vec<i128> {
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let v = (x as i64) as i128;
            if bound_log2 >= 63 {
                v << (bound_log2 - 63)
            } else {
                v >> (63 - bound_log2)
            }
        })
        .collect()
}

/// Precision (−log2 of the largest real or imaginary error) of an owner release against `want`.
fn release_precision(out: &[u8], want: &[(f64, f64)]) -> f64 {
    assert_eq!(out[0], mech::OUT_TYPE);
    let unit = (out[1] as f64).exp2();
    let cnt = u16::from_be_bytes([out[2], out[3]]) as usize;
    assert_eq!((cnt, out.len()), (want.len(), 4 + 16 * cnt));
    let mut m = 0f64;
    for (i, &(re, im)) in want.iter().enumerate() {
        let r = i64::from_le_bytes(out[4 + 16 * i..12 + 16 * i].try_into().unwrap()) as f64 / unit;
        let j = i64::from_le_bytes(out[12 + 16 * i..20 + 16 * i].try_into().unwrap()) as f64 / unit;
        m = m.max((r - re).abs()).max((j - im).abs());
    }
    -m.log2()
}

fn owner_release(s: u32, seed: u32, input: &[u8]) -> Result<Vec<u8>, u32> {
    match mech::decrypt(s, seed, &[0u8; 48], input, false)? {
        (_, Some(DecryptOutput::Owner(v))) => Ok(v),
        _ => panic!("owner release expected"),
    }
}

/// Gate F on registry ID 3: a level-1 ciphertext decrypted over q0·q1 and
/// flooded with the LMSS22 Corollary 2 width, σ = 2^(15 + ½·log2(24·q·n) +
/// log2 B) with q = (4 + 1) × 10,000 = 50,000 (the policy's replica limit and
/// decrypt budget), n = 2^16, log2 B = 36: σ = 2^69.10. The release keeps
/// about 90 − 69.1 − 9.7 ≈ 11.2 bits on all 32,768 slots (the decoded noise
/// grows by √n and the maximum over the slots adds about 2.2 bits). The
/// earlier width, 2^57.64, left about 22.7 bits. Unflooded, the same
/// ciphertext releases at the 2^-30 rounding.
#[test]
fn flooded_two_prime_release_precision_registry_3() {
    let _g = lock();
    let ps = params::find(3).unwrap();
    let n = ps.n();
    let m = plaintext(n, 82);
    let want = mech::decode_slots_wide(&m, 90);
    let g = Generator::new(ps, &KAT_SEED);
    let (c0, c1) = g.encrypt_for_test(1, &m, &[7u8; 32]).unwrap();
    // The decryption itself returns m + e (|e| < 20).
    let back = g.decrypt_level(1, &c0, &c1).unwrap();
    assert!(back.iter().zip(&m).all(|(a, b)| (a - b).abs() < 20));
    drop(g);
    let input = ct_bytes(mech::CT_MAGIC_V3, 3, 1, 90, &c0, &c1);

    let sigma = mech::flood_sigma_log2(&fhe::CkksReleasePolicy { max_values: 1, precision_bits: 30, value_bound_log2: 10, scale_log2: 90, flood_recipients: true, flood_owner: true, stat_security_bits: 30 }, mech::lineage_releases(10_000, 4), ps);
    // Above the one-prime cap (2^62), within the two-prime cap (2^80).
    assert!(sigma > mech::FLOOD_MAX_LOG2_ONE_PRIME && sigma < mech::flood_max_log2(ps), "σ = 2^{sigma}");

    let (_w, s, seed) = setup(3, 30, true);
    let p = release_precision(&owner_release(s, seed, &input).unwrap(), &want);
    eprintln!("registry 3 flooded release (σ = 2^{sigma:.2}): {p:.2} bits");
    assert!(p >= 10.5, "flooded precision {p}");
    assert!(p <= 12.5, "flooding at the Corollary 2 width: {p}");
    drop(_w);

    let (_w, s, seed) = setup(3, 30, false);
    let p = release_precision(&owner_release(s, seed, &input).unwrap(), &want);
    eprintln!("registry 3 unflooded release: {p:.2} bits");
    assert!(p >= 29.0, "unflooded precision {p}");
}

/// Serialization: registry ID 3 takes version 3 at level 1 only; the
/// level-0 test ring keeps version 2 (and refuses version 3). Every refusal
/// is the same CKR_ACTION_PROHIBITED.
#[test]
fn serialization_versions_per_set() {
    let _g = lock();
    let ps = params::find(3).unwrap();
    let n = ps.n();
    let m = plaintext(n, 82);
    let g = Generator::new(ps, &KAT_SEED);
    let (c0, c1) = g.encrypt_for_test(1, &m, &[9u8; 32]).unwrap();
    drop(g);
    let (_w, s, seed) = setup(3, 20, false);
    assert!(owner_release(s, seed, &ct_bytes(mech::CT_MAGIC_V3, 3, 1, 90, &c0, &c1)).is_ok());
    let refused = Err(CKR_ACTION_PROHIBITED);
    assert_eq!(owner_release(s, seed, &ct_bytes(mech::CT_MAGIC, 3, 1, 90, &c0, &c1)), refused, "v2 magic on set 3");
    assert_eq!(owner_release(s, seed, &ct_bytes(mech::CT_MAGIC_V3, 3, 0, 90, &c0[..n], &c1[..n])), refused, "level 0 on set 3");
    assert_eq!(owner_release(s, seed, &ct_bytes(mech::CT_MAGIC_V3, 3, 1, 89, &c0, &c1)), refused, "scale differs from the policy");
    assert_eq!(owner_release(s, seed, &ct_bytes(mech::CT_MAGIC_V3, 3, 1, 90, &c0, &c1)[..24 + 16 * n]), refused, "one limb only");
    drop(_w);

    // Test ring (level 0): version 2 still accepted; version 3 refused.
    let ps = params::find(0x8002).unwrap();
    let n = ps.n();
    let m = plaintext(n, 30);
    let want = mech::decode_slots_wide(&m, 40);
    let g = Generator::new(ps, &KAT_SEED);
    let (c0, c1) = g.encrypt_for_test(0, &m, &[5u8; 32]).unwrap();
    drop(g);
    let (_w, s, seed) = setup(0x8002, 20, false);
    let out = owner_release(s, seed, &ct_bytes(mech::CT_MAGIC, 0x8002, 0, 40, &c0, &c1)).expect("version 2 on the test ring");
    assert!(release_precision(&out, &want) >= 19.0);
    assert_eq!(owner_release(s, seed, &ct_bytes(mech::CT_MAGIC_V3, 0x8002, 0, 40, &c0, &c1)), refused, "v3 on a level-0 set");
}

/// q of LMSS22 Corollary 2 is the lineage total, (maxReplicas + 1) ×
/// maxDecrypts, and each copy computes it from its own replication policy.
/// A CKKS replica is therefore installed only under the source's replica
/// limit: a narrower limit (1 under a source of 4, which the generic
/// "equal or stricter" rule allows) is refused and installs nothing; the
/// same limit is accepted, and the replica floods an owner release.
#[test]
fn ckks_replica_keeps_the_source_replica_limit() {
    use der::Encode;
    use softhsmrustv3::native;
    use softhsmrustv3::replication::asn1::Operation;
    let _g = lock();
    let w = world(2);
    let ps = params::find(0x8002).unwrap();
    let mk = |max| {
        records::build_policy_with_constraint(
            DOMAIN, [true, true, true], w.device_ids(), w.now - 60, w.now + 30 * 86_400, max,
            vec![CKM_PQCTODAY_FHE_DERIVE_PUBLIC, CKM_PQCTODAY_FHE_DECRYPT], false, fhe::ckks_profile_constraint_hash(),
        )
        .unwrap()
    };
    let dpol = fhe::FheDecryptPolicy {
        version: 2,
        allowed_output_types: vec![mech::release_type(ps)],
        never_release: vec![],
        predicates: vec![],
        recipients: vec![],
        recipient_only: false,
        max_decrypts: 100,
        ckks: Some(fhe::CkksReleasePolicy { max_values: (ps.n() / 2) as u32, precision_bits: 20, value_bound_log2: 10, scale_log2: ps.log_default_scale as u8, flood_recipients: true, flood_owner: true, stat_security_bits: 30 }),
    }
    .to_der()
    .unwrap();
    let (rp4, rp1) = (w.enroll_policy_everywhere(&mk(4)), w.enroll_policy_everywhere(&mk(1)));
    let mut dp = [0u8; 48];
    for i in 0..2 {
        dp = w.as_so(i, |so| fhe::enroll_fhe_decrypt_policy(so, &dpol).unwrap());
    }
    let (u0, u1) = (w.tokens[0].user, w.tokens[1].user);
    let src = fhe::generate_fhe_seed_with_value_for_test(u0, ps.id, &rp4, &dp, &KAT_SEED, b"ckks-replica-src").expect("KEY_GEN");
    let lineage = native::get_attribute(u0, src, CKA_PQCTODAY_FHE_LINEAGE_ID).unwrap();

    let narrow = repl::create_replication_package(u0, src, &request(&w, 0, 1, Operation::LiveClone, &rp1)).expect("package");
    assert_eq!(repl::import_replication_package(u1, &narrow, &[]).map(|_| ()), Err(CKR_ACTION_PROHIBITED));
    assert_eq!(repl::last_refusal(), Some("CKKS seed replica must keep the source policy's maxReplicas"));
    assert_eq!(replicas_with_lineage(w.tokens[1].slot, &lineage), 0, "nothing installed");

    let same = repl::create_replication_package(u0, src, &request(&w, 0, 1, Operation::LiveClone, &rp4)).expect("package");
    let (replica, _) = repl::import_replication_package(u1, &same, &[]).expect("replica under the source's limit");
    let m = plaintext(ps.n(), 30);
    let g = Generator::new(ps, &KAT_SEED);
    let (c0, c1) = g.encrypt_for_test(0, &m, &[3u8; 32]).unwrap();
    drop(g);
    let input = ct_bytes(mech::CT_MAGIC, ps.id, 0, ps.log_default_scale, &c0, &c1);
    // Flooded at q = (4 + 1) × 100 on both copies: σ = 2^(15 + ½·log2(24·500·2^10) + 12) = 2^38.78.
    let sigma = mech::flood_sigma_log2(&fhe::CkksReleasePolicy { max_values: 1, precision_bits: 20, value_bound_log2: 10, scale_log2: 40, flood_recipients: true, flood_owner: true, stat_security_bits: 30 }, mech::lineage_releases(100, 4), ps);
    assert!((sigma - 38.7753730).abs() < 1e-6, "σ = 2^{sigma}");
    let want = mech::decode_slots_wide(&m, ps.log_default_scale as u8);
    for (s, h) in [(u0, src), (u1, replica)] {
        let p = release_precision(&owner_release(s, h, &input).expect("flooded owner release"), &want);
        assert!(p < 0.0, "a 2^38.8 flood at scale 2^40 leaves no bits: {p}");
    }
}

// ── Registry ID 4: OpenFHE v1.6.0 match128 ─────────────────────────────────

fn kat4() -> serde_json::Value {
    serde_json::from_str(include_str!("../kat/fhe-ckks-kat-4.json")).unwrap()
}

/// Registry entry, a-seed, public key, the first words of key 0 and the two
/// sparse-encapsulation keys (dense-to-sparse over Q[0] ‖ P', sparse-to-dense
/// over Q ‖ P) against the oracle KAT (seed 00..1f). The full key list is
/// `kat_registry_4_all_keys` (ignored by default: 6.5 GB of chunks).
#[test]
fn kat_registry_4_matches_reference_spec() {
    let kat = kat4();
    let ps = params::find(4).unwrap();
    assert_eq!(ps.name, kat["name"].as_str().unwrap());
    assert_eq!(hexs(&params::param_hash(ps)), kat["paramHash"].as_str().unwrap());
    assert_eq!(ps.keys.len() as u64, kat["keyCount"].as_u64().unwrap());
    let g = Generator::new(ps, &KAT_SEED);
    assert_eq!(hexs(&g.a_seed), kat["aSeed"].as_str().unwrap());
    assert_eq!(kat["secretWeight"].as_u64().unwrap(), 192);
    assert_eq!(hexs(&sha2::Sha256::digest(g.pk_chunk(0, ps.pk_limbs()).unwrap())), kat["pkSha256"].as_str().unwrap());
    let first = g.chunk(0, 0, 0, 1).unwrap();
    let words: Vec<u64> = (0..4).map(|i| u64::from_le_bytes(first[8 * i..8 * i + 8].try_into().unwrap())).collect();
    let want: Vec<u64> = kat["firstChunkFirstWords"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap()).collect();
    assert_eq!(words, want);
    let hashes = kat["keySha256"].as_array().unwrap();
    for (k, key) in ps.keys.iter().enumerate() {
        if key.kind == params::KIND_DENSE_TO_SPARSE_AUX || key.kind == params::KIND_SPARSE_TO_DENSE {
            assert_eq!(key_hash(&g, k), hashes[k].as_str().unwrap(), "key {k}");
        }
    }
}

#[test]
#[ignore = "6.5 GB of chunks; run with --ignored in a release build"]
fn kat_registry_4_all_keys() {
    let kat = kat4();
    let ps = params::find(4).unwrap();
    let g = Generator::new(ps, &KAT_SEED);
    let hashes = kat["keySha256"].as_array().unwrap();
    for k in 0..ps.keys.len() {
        assert_eq!(key_hash(&g, k), hashes[k].as_str().unwrap(), "key {k}");
    }
}

/// A version 2 decryption policy for `ps_ids` (owner release of every slot at 2^-20, |v| < 2^10).
fn policy_der(ps_ids: &[u32], recipients: Vec<der::asn1::OctetString>, flood_owner: bool) -> Vec<u8> {
    use der::Encode;
    let mut types: Vec<_> = ps_ids.iter().map(|&i| mech::release_type(params::find(i).unwrap())).collect();
    types.sort();
    fhe::FheDecryptPolicy {
        version: 2,
        allowed_output_types: types,
        never_release: vec![],
        predicates: vec![],
        recipients,
        recipient_only: false,
        max_decrypts: 100,
        ckks: Some(fhe::CkksReleasePolicy { max_values: 16, precision_bits: 20, value_bound_log2: 10, scale_log2: 52, flood_recipients: true, flood_owner, stat_security_bits: 30 }),
    }
    .to_der()
    .unwrap()
}

/// Registry ID 4 has no measured flood bound, so it is owner-release-only: a
/// policy that names a third-party recipient or floods the owner release for
/// it is refused when it is parsed and enrolled, the decryption gate refuses
/// both again, and the owner's unflooded release works at the policy's
/// rounding. The sets with a bound (here ID 3) take the same policies as before.
#[test]
fn registry_4_is_owner_release_only() {
    let _g = lock();
    let recipient = der::asn1::OctetString::new(vec![7u8; 48]).unwrap();
    let ok = |der: &[u8]| fhe::parse_decrypt_policy(der).is_ok();
    // The owner-only, unflooded policy is accepted; a recipient or an owner flood is not.
    assert!(ok(&policy_der(&[4], vec![], false)));
    assert!(!ok(&policy_der(&[4], vec![recipient.clone()], false)), "a third-party recipient");
    assert!(!ok(&policy_der(&[4], vec![], true)), "a flooded owner release");
    assert!(!ok(&policy_der(&[4, 3], vec![recipient.clone()], false)), "a mixed list that includes ID 4");
    // The same policies on a set with a bound are unchanged. (Scale 52 is within the one-prime range only.)
    assert!(ok(&policy_der(&[2], vec![recipient.clone()], true)));
    assert!(ok(&policy_der(&[0x8002], vec![recipient], true)));

    // The token enrols the owner-only policy and refuses the others.
    let w = world(1);
    let enroll = |der: &[u8]| w.as_so(0, |so| fhe::enroll_fhe_decrypt_policy(so, der));
    assert!(enroll(&policy_der(&[4], vec![], false)).is_ok());
    assert_eq!(enroll(&policy_der(&[4], vec![], true)), Err(CKR_DATA_INVALID));
    drop(w);

    // Owner release at ID 4: one prime, serialization version 2, scale 2^52, rounding 2^-20.
    let ps = params::find(4).unwrap();
    let n = ps.n();
    let m = plaintext(n, 52);
    let want = mech::decode_slots_wide(&m, 52);
    let g = Generator::new(ps, &KAT_SEED);
    let (c0, c1) = g.encrypt_for_test(0, &m, &[11u8; 32]).unwrap();
    // The decryption itself returns m + e (|e| < 20).
    let back = g.decrypt_level(0, &c0, &c1).unwrap();
    assert!(back.iter().zip(&m).all(|(a, b)| (a - b).abs() < 20));
    drop(g);
    let (_w, s, seed) = setup(4, 20, false);
    let out = owner_release(s, seed, &ct_bytes(mech::CT_MAGIC, 4, 0, 52, &c0, &c1)).expect("owner release at ID 4");
    let p = release_precision(&out, &want);
    eprintln!("registry 4 owner release: {p:.2} bits");
    assert!(p >= 19.0, "owner release precision {p}");
    let refused = Err(CKR_ACTION_PROHIBITED);
    assert_eq!(owner_release(s, seed, &ct_bytes(mech::CT_MAGIC_V3, 4, 0, 52, &c0, &c1)), refused, "v3 magic on a one-prime set");
    assert_eq!(owner_release(s, seed, &ct_bytes(mech::CT_MAGIC, 4, 0, 51, &c0, &c1)), refused, "scale differs from the policy");
}
