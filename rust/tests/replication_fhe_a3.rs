//! FHE custody hardening for the default build (plan D02387 WP-A3; spec
//! docs/proposals/pkcs11-ckm-pqctoday-fhe-proposal.md §10 gate 5): native known answers through the token for every
//! registered parameter set, the negative cases (wrong role, budget exhausted, wrong lineage or foreign seed,
//! oversized input at every entry point, seeds that cannot be destroyed, generated or replicated), the decrypt-counter
//! race found by the release-path review, and pending operations ending with their session. Counters across an engine
//! restart are `replication_fhe_a3_store.rs` (its own binary: the durable store is process-global); the parser
//! mutation tests are `replication_fhe_parsers_mutation.rs`.
//!
//! Runs in the default native build with `test-support` (CKKS custody, no TFHE-rs) and with
//! `educational-fhe,test-support`, which adds the TFHE registry ID 1 known answers.
#![cfg(all(pqc_ckks_custody, feature = "test-support"))]

mod replication_common;
use replication_common::*;

use der::Encode;
use sha2::Digest;
use softhsmrustv3::constants::*;
use softhsmrustv3::ffi;
use softhsmrustv3::native;
use softhsmrustv3::replication::admin::{self, AdminOperation};
use softhsmrustv3::replication::fhe_ckks::{freeze, mech, params, spec::Generator};
use softhsmrustv3::replication::fhe_custody::{self as fc, DecryptOutput};
use softhsmrustv3::replication::{self as repl, admin_host, asn1::Operation, fhe, oids::Purpose, records};

const OWNER: [u8; 48] = [0; 48];
const KAT_SEED: [u8; 32] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31];
const W: usize = std::mem::size_of::<usize>();
const TEST_RING: u32 = 0x8002;

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A CKKS-profile replication policy over this world's devices.
fn ckks_repl_policy(w: &World, max_replicas: u32) -> Vec<u8> {
    records::build_policy_with_constraint(
        DOMAIN, [true, true, true], w.device_ids(), w.now - 60, w.now + 30 * 86_400, max_replicas,
        vec![CKM_PQCTODAY_FHE_DERIVE_PUBLIC, CKM_PQCTODAY_FHE_DECRYPT], false, fhe::ckks_profile_constraint_hash(),
    )
    .unwrap()
}

/// A version 2 decryption policy for one parameter set: its release type, every slot, 2^-20, |v| < 2^10, the set's
/// scale, owner releases unflooded, recipient releases flooded.
fn ckks_dpol(ps_id: u32, max_decrypts: u32, recipients: Vec<[u8; 48]>) -> Vec<u8> {
    let ps = params::find(ps_id).unwrap();
    let mut r = recipients;
    r.sort();
    fhe::FheDecryptPolicy {
        version: 2,
        allowed_output_types: vec![mech::release_type(ps)],
        never_release: vec![],
        predicates: vec![],
        recipients: r.iter().map(|x| der::asn1::OctetString::new(x.to_vec()).unwrap()).collect(),
        recipient_only: false,
        max_decrypts,
        ckks: Some(fhe::CkksReleasePolicy { max_values: (ps.n() / 2) as u32, precision_bits: 20, value_bound_log2: 10, scale_log2: ps.log_default_scale as u8, flood_recipients: true, flood_owner: false, stat_security_bits: 30 }),
    }
    .to_der()
    .unwrap()
}

/// One token, the CKKS profile, a test-ring decryption policy with `max_decrypts`, and a seed with value `seed` and
/// CKA_ID `id`. Returns (world, user session, seed handle).
fn setup(max_decrypts: u32, seed: &[u8; 32], id: &[u8]) -> (World, u32, u32) {
    let w = world(1);
    let (rp, dp) = (ckks_repl_policy(&w, 4), ckks_dpol(TEST_RING, max_decrypts, vec![]));
    let (rpid, dpid) = w.as_so(0, |so| (repl::enroll_policy(so, &rp).unwrap(), fhe::enroll_fhe_decrypt_policy(so, &dp).unwrap()));
    let s = w.tokens[0].user;
    let h = fhe::generate_fhe_seed_with_value_for_test(s, TEST_RING, &rpid, &dpid, seed, id).expect("KEY_GEN");
    (w, s, h)
}

/// Slot values small against the scale: coefficient i is ((i mod 7) − 3)·2^(scale − 20).
fn small_plaintext(ps: &'static params::CkksParamSet) -> Vec<i128> {
    let shift = ps.log_default_scale as u32 - 20;
    (0..ps.n() as i128).map(|i| ((i % 7) - 3) << shift).collect()
}

/// A release-level ciphertext of `m` under the secret of `seed`, in the token's input format.
fn ciphertext(ps: &'static params::CkksParamSet, seed: &[u8; 32], m: &[i128], rand: u8) -> Vec<u8> {
    let level = params::release_level(ps);
    let (c0, c1) = Generator::new(ps, seed).encrypt_for_test(level, m, &[rand; 32]).unwrap();
    let mut b = if level == 0 { mech::CT_MAGIC.to_vec() } else { mech::CT_MAGIC_V3.to_vec() };
    for v in [ps.id, level as u32, ps.log_default_scale as u32, 0] {
        b.extend_from_slice(&v.to_le_bytes());
    }
    for v in c0.iter().chain(&c1) {
        b.extend_from_slice(&v.to_le_bytes());
    }
    b
}

/// The engine-private decrypt counter of a seed (§6.4).
fn counter(h: u32) -> u64 {
    records::object_attrs(h).and_then(|a| a.get(&fc::CKA_PRIV_FHE_DECRYPT_COUNT).map(|v| u64::from_le_bytes(v.as_slice().try_into().unwrap()))).unwrap_or(0)
}

fn owner_release(s: u32, h: u32, ct: &[u8]) -> Result<Vec<u8>, u32> {
    match fc::decrypt(s, h, &OWNER, ct, false)? {
        (_, Some(DecryptOutput::Owner(v))) => Ok(v),
        _ => panic!("owner release expected"),
    }
}

/// Largest error of an owner release against the slots of `m`.
fn release_error(out: &[u8], m: &[i128], scale: u8) -> f64 {
    let want = mech::decode_slots_wide(m, scale);
    assert_eq!(out[0], mech::OUT_TYPE);
    let unit = (out[1] as f64).exp2();
    let cnt = u16::from_be_bytes([out[2], out[3]]) as usize;
    assert_eq!(out.len(), 4 + 16 * cnt);
    (0..cnt)
        .map(|i| {
            let re = i64::from_le_bytes(out[4 + 16 * i..12 + 16 * i].try_into().unwrap()) as f64 / unit;
            let im = i64::from_le_bytes(out[12 + 16 * i..20 + 16 * i].try_into().unwrap()) as f64 / unit;
            (re - want[i].0).abs().max((im - want[i].1).abs())
        })
        .fold(0.0, f64::max)
}

/// derive → read CKA_VALUE → destroy, like the custodian.
fn derive(s: u32, h: u32, kind: u32, k: u32, d: u32, from: usize, to: usize) -> Result<Vec<u8>, u32> {
    let o = mech::derive_public_v2(s, h, kind, k, d, from, to)?;
    let v = native::get_attribute(s, o, CKA_VALUE).expect("CKA_VALUE");
    assert_eq!(ffi::C_DestroyObject(s, o), CKR_OK);
    Ok(v)
}

fn open_rw_session(slot: u32) -> u32 {
    let mut h = 0u32;
    assert_eq!(ffi::C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, std::ptr::null_mut(), std::ptr::null_mut(), &mut h), CKR_OK);
    h
}

fn decrypt_params(recipient: &[u8; 48]) -> Vec<u8> {
    let mut p = vec![0u8; (W + 48).next_multiple_of(W)];
    p[..W].copy_from_slice(&1usize.to_ne_bytes());
    p[W..W + 48].copy_from_slice(recipient);
    p
}

// ── Known answers through the token ────────────────────────────────────────

/// Registry IDs 0x8002, 2, 3 and 4, each through the token with the KAT seed 00..1f: the seed's
/// CKA_PQCTODAY_FHE_PARAM_HASH equals the frozen generator table (`freeze.rs`, whose ID 4 value was reproduced by an
/// independent DER encoder); the key-set descriptor (DERIVE_PUBLIC kind 3) carries the oracle's a-seed and key count;
/// the public key exported chunk by chunk through DERIVE_PUBLIC hashes to the oracle's `pkSha256`; the first evaluation
/// key chunk starts with the oracle's first words. The expected values are the committed pqctoday-fhe oracle files
/// (`rust/kat/fhe-ckks-kat-*.json`, Lattigo v6.2.0 reference spec), not values computed by this engine. Then a
/// decryption: a plaintext encrypted outside the token under the same KAT secret is released to the owner within the
/// 2^-20 rounding (an independent path: the test's encryption against the token's decryption).
#[test]
fn kat_ckks_registry_ids_through_the_token() {
    let _g = lock();
    let w = world(1);
    let rp = ckks_repl_policy(&w, 4);
    let sets = [TEST_RING, 2, 3, 4];
    let (rpid, dpids) = w.as_so(0, |so| {
        let rpid = repl::enroll_policy(so, &rp).unwrap();
        (rpid, sets.map(|id| fhe::enroll_fhe_decrypt_policy(so, &ckks_dpol(id, 10, vec![])).unwrap()))
    });
    let s = w.tokens[0].user;
    let kats: [(u32, &str); 4] = [
        (TEST_RING, include_str!("../kat/fhe-ckks-kat-32770.json")),
        (2, include_str!("../kat/fhe-ckks-kat-2.json")),
        (3, include_str!("../kat/fhe-ckks-kat-3.json")),
        (4, include_str!("../kat/fhe-ckks-kat-4.json")),
    ];
    for (i, (id, file)) in kats.iter().enumerate() {
        let kat: serde_json::Value = serde_json::from_str(file).unwrap();
        assert_eq!(kat["paramSet"].as_u64(), Some(*id as u64));
        assert_eq!(kat["seed"].as_str(), Some(hexs(&KAT_SEED).as_str()), "the oracle ran on the KAT seed");
        let ps = params::find(*id).unwrap();
        let h = fhe::generate_fhe_seed_with_value_for_test(s, *id, &rpid, &dpids[i], &KAT_SEED, format!("kat-{id}").as_bytes()).expect("KEY_GEN");
        let frozen = freeze::FROZEN.iter().find(|g| g.version == params::GENERATOR_VERSION).unwrap().sets.iter().find(|f| f.id == *id).unwrap();
        assert_eq!(hexs(&native::get_attribute(s, h, CKA_PQCTODAY_FHE_PARAM_HASH).unwrap()), frozen.fhe_param_hash, "set {id}: CKA_PQCTODAY_FHE_PARAM_HASH");
        assert_eq!(kat["paramHash"].as_str(), Some(frozen.param_hash), "set {id}: oracle and frozen table agree");

        let desc = derive(s, h, mech::PUBLIC_KIND_CKKS_DESCRIPTOR, 0, 0, 0, 0).expect("descriptor");
        let d: mech::CkksKeySetDescriptorV1 = der::Decode::from_der(&desc).unwrap();
        assert_eq!((d.generator_version, d.param_set), (1, *id));
        assert_eq!(hexs(d.a_seed.as_bytes()), kat["aSeed"].as_str().unwrap(), "set {id}: a-seed");
        assert_eq!(d.key_count as u64, kat["keyCount"].as_u64().unwrap(), "set {id}: key count");
        assert_eq!(d.param_hash.as_bytes(), &native::get_attribute(s, h, CKA_PQCTODAY_FHE_PARAM_HASH).unwrap()[..]);

        let mut pk = sha2::Sha256::new();
        for from in (0..ps.pk_limbs()).step_by(8) {
            pk.update(derive(s, h, mech::PUBLIC_KIND_CKKS_PUBLIC_KEY, 0, 0, from, (from + 8).min(ps.pk_limbs())).expect("pk chunk"));
        }
        assert_eq!(hexs(&pk.finalize()), kat["pkSha256"].as_str().unwrap(), "set {id}: public key through DERIVE_PUBLIC");
        let first = derive(s, h, mech::PUBLIC_KIND_CKKS_EVK_CHUNK, 0, 0, 0, 1).expect("first chunk");
        let words: Vec<u64> = (0..4).map(|j| u64::from_le_bytes(first[8 * j..8 * j + 8].try_into().unwrap())).collect();
        let want: Vec<u64> = kat["firstChunkFirstWords"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap()).collect();
        assert_eq!(words, want, "set {id}: first evaluation-key words");

        let m = small_plaintext(ps);
        let out = owner_release(s, h, &ciphertext(ps, &KAT_SEED, &m, 5)).expect("owner release");
        let err = release_error(&out, &m, ps.log_default_scale as u8);
        assert!(err <= 2f64.powi(-19), "set {id}: release error {err}");
        assert_eq!(counter(h), 1);
    }
}

/// TFHE registry ID 1 through the token (educational-fhe builds). Three independent paths:
/// - the parameter hash: SHA-384 of `FheParamSetV1` with the spec §4 values, DER-encoded by hand in this test (not
///   through the engine's `der` types), equals the seed's CKA_PQCTODAY_FHE_PARAM_HASH;
/// - the client key: `client_key_for(00..1f)` reproduces the committed §5.5 vector (derived seed `0xf6eb…12dc`,
///   SHA-256 `9f5d847e…b77b`, 24,087 bytes);
/// - the token: a seed installed with the KAT value decrypts a ciphertext made outside the token with that KAT client
///   key, and a ciphertext the token makes (test-only ENCRYPT) decrypts outside with the KAT client key.
#[cfg(feature = "educational-fhe")]
#[test]
fn kat_tfhe_registry_1_through_the_token() {
    use softhsmrustv3::replication::fhe_tfhe as tf;
    use tfhe::prelude::*;
    use tfhe::safe_serialization::{safe_deserialize_conformant, safe_serialize};
    use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128 as P;
    let _g = lock();

    // Hand-written DER of FheParamSetV1 (spec §4).
    fn tlv(tag: u8, v: &[u8]) -> Vec<u8> {
        let mut o = vec![tag];
        match v.len() {
            n if n < 0x80 => o.push(n as u8),
            n if n < 0x100 => o.extend([0x81, n as u8]),
            n => o.extend([0x82, (n >> 8) as u8, n as u8]),
        }
        o.extend_from_slice(v);
        o
    }
    let commit: Vec<u8> = (0..40).step_by(2).map(|i| u8::from_str_radix(&"187fc0b95ab35352422deec6c027d0bd8743b6db"[i..i + 2], 16).unwrap()).collect();
    let body = [
        tlv(0x02, &[1]),
        tlv(0x0c, b"tfhe-rs"),
        tlv(0x0c, b"1.8.1"),
        tlv(0x04, &commit),
        tlv(0x0c, b"PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128"),
        tlv(0x0c, b"ConfigBuilder::default().use_dedicated_oprf_key(false)"),
        tlv(0x0c, b"sp800-108-ctr-hmac-sha384/v1"),
    ]
    .concat();
    let want_hash: Vec<u8> = sha2::Sha384::digest(tlv(0x30, &body)).to_vec();

    // The §5.5 vector.
    assert_eq!(tf::derive_tfhe_seed(&KAT_SEED), 0xf6eb1c9a88a4442c8a7449536c3d12dc);
    let ck = tf::client_key_for(&KAT_SEED);
    let mut ck_bytes = Vec::new();
    safe_serialize(&ck, &mut ck_bytes, 1 << 32).unwrap();
    assert_eq!((ck_bytes.len(), hexs(&sha2::Sha256::digest(&ck_bytes))), (24_087, "9f5d847e4d1121eef9d75fcc473e89ee5306523f9cb140384eba5aa85a55b77b".to_string()));

    let w = world(1);
    let rp = records::build_policy_with_constraint(
        DOMAIN, [true, true, true], w.device_ids(), w.now - 60, w.now + 30 * 86_400, 4,
        vec![CKM_PQCTODAY_FHE_DERIVE_PUBLIC, CKM_PQCTODAY_FHE_DECRYPT], false, fhe::profile_constraint_hash(),
    )
    .unwrap();
    let ty = |n: &str, b: u16| fhe::FheType { type_name: n.into(), width_bits: b, param_set: 1, serialization_version: 1, compressed_allowed: false };
    let dp = fhe::FheDecryptPolicy { version: 1, allowed_output_types: vec![ty("FheBool", 1), ty("FheUint8", 8)], never_release: vec![], predicates: vec![], recipients: vec![], recipient_only: false, max_decrypts: 10, ckks: None }.to_der().unwrap();
    let (rpid, dpid) = w.as_so(0, |so| (repl::enroll_policy(so, &rp).unwrap(), fhe::enroll_fhe_decrypt_policy(so, &dp).unwrap()));
    let s = w.tokens[0].user;
    let h = fhe::generate_fhe_seed_with_value_for_test(s, 1, &rpid, &dpid, &KAT_SEED, b"tfhe-kat").expect("KEY_GEN");
    let got = native::get_attribute(s, h, CKA_PQCTODAY_FHE_PARAM_HASH).unwrap();
    assert_eq!(got, want_hash, "CKA_PQCTODAY_FHE_PARAM_HASH = SHA-384 of the hand-encoded FheParamSetV1");
    assert_eq!(fhe::param_hash(1).unwrap().to_vec(), want_hash);

    // Outside → token.
    let mut ct = Vec::new();
    safe_serialize(&tfhe::FheUint8::encrypt(173u8, &ck), &mut ct, fc::MAX_DECRYPT_INPUT as u64).unwrap();
    let (_, out) = fc::decrypt(s, h, &OWNER, &ct, false).expect("token decrypts the KAT key's ciphertext");
    assert_eq!(out, Some(DecryptOutput::Owner(vec![1, 0, 8, 173])));
    // Token → outside.
    let ct = tf::encrypt_for_test(s, h, "FheUint8", 77).unwrap();
    let back: tfhe::FheUint8 = safe_deserialize_conformant(ct.as_slice(), fc::MAX_DECRYPT_INPUT as u64, &tfhe::FheUint8ConformanceParams::from(P)).unwrap();
    let v: u8 = back.decrypt(&ck);
    assert_eq!(v, 77);
}

// ── Roles, lineage and foreign seeds ───────────────────────────────────────

/// Wrong role (F15): the security officer gets CKR_USER_TYPE_INVALID for KEY_GEN, DERIVE_PUBLIC and DECRYPT, over the
/// Rust API and the C ABI; a read-only user session gets CKR_SESSION_READ_ONLY; a public session gets
/// CKR_USER_NOT_LOGGED_IN; the normal user gets CKR_USER_TYPE_INVALID for every SO operation (policy and recipient
/// enrolment, the admin nonce and execute). A user of another token cannot reach the seed by handle
/// (CKR_KEY_HANDLE_INVALID). No refusal spends a counter unit.
///
/// Found by this test in the default build (no TFHE-rs): `fhe_custody::decrypt` routed by object type before the role
/// check, so the SO, or a public session, holding a handle that was not a CKKS seed got CKR_KEY_TYPE_INCONSISTENT
/// instead of its role error, and could tell CKKS seeds from other handles. The role is now checked first.
#[test]
fn wrong_roles_and_foreign_tokens_are_refused_before_the_counter() {
    let _g = lock();
    let w = world(2);
    let (rp, dp) = (ckks_repl_policy(&w, 4), ckks_dpol(TEST_RING, 10, vec![]));
    let mut ids = ([0u8; 48], [0u8; 48]);
    for i in 0..2 {
        ids = w.as_so(i, |so| (repl::enroll_policy(so, &rp).unwrap(), fhe::enroll_fhe_decrypt_policy(so, &dp).unwrap()));
    }
    let (rpid, dpid) = ids;
    let (u0, u1) = (w.tokens[0].user, w.tokens[1].user);
    let ps = params::find(TEST_RING).unwrap();
    let seed_value = [9u8; 32];
    let h = fhe::generate_fhe_seed_with_value_for_test(u0, TEST_RING, &rpid, &dpid, &seed_value, b"roles").unwrap();
    let ct = ciphertext(ps, &seed_value, &small_plaintext(ps), 5);
    let lineage = native::get_attribute(u0, h, CKA_PQCTODAY_FHE_LINEAGE_ID).unwrap();

    // A user of the other token, by handle.
    assert_eq!(fc::decrypt(u1, h, &OWNER, &ct, false).map(|_| ()), Err(CKR_KEY_HANDLE_INVALID));
    assert_eq!(fc::decrypt(u1, h, &OWNER, &ct, true).map(|_| ()), Err(CKR_KEY_HANDLE_INVALID));
    assert_eq!(mech::derive_public_v2(u1, h, mech::PUBLIC_KIND_CKKS_DESCRIPTOR, 0, 0, 0, 0), Err(CKR_KEY_HANDLE_INVALID));

    // Read-only user session.
    let mut ro = 0u32;
    assert_eq!(ffi::C_OpenSession(0, CKF_SERIAL_SESSION, std::ptr::null_mut(), std::ptr::null_mut(), &mut ro), CKR_OK);
    assert_eq!(fc::decrypt(ro, h, &OWNER, &ct, false).map(|_| ()), Err(CKR_SESSION_READ_ONLY));
    assert_eq!(fhe::generate_fhe_seed(ro, TEST_RING, &rpid, &dpid, None, None), Err(CKR_SESSION_READ_ONLY));
    assert_eq!(ffi::C_CloseSession(ro), CKR_OK);

    // The normal user may not run any SO operation.
    assert_eq!(fhe::enroll_fhe_decrypt_policy(u0, &dp), Err(CKR_USER_TYPE_INVALID));
    let rchain = repl::function_chain(u1, Purpose::RecoveryRecipient).unwrap();
    assert_eq!(fc::enroll_fhe_recipient(u0, &rchain), Err(CKR_USER_TYPE_INVALID));
    assert_eq!(admin::issue_nonce(u0), Err(CKR_USER_TYPE_INVALID));
    assert_eq!(admin::execute(u0, &[0x30, 0x00]), Err(CKR_USER_TYPE_INVALID));
    assert_eq!(counter(h), 0, "no refusal so far reached the counter");

    // The SO: Rust API and C ABI. Handles to private objects are re-keyed at logout, so the SO is handed the
    // user's handle as it was (it names no object the SO can use) and, after, the user re-finds the seed.
    let (so_rust, so_abi) = w.as_so(0, |so| {
        let rust = [
            fhe::generate_fhe_seed(so, TEST_RING, &rpid, &dpid, None, None).err(),
            mech::derive_public_v2(so, h, mech::PUBLIC_KIND_CKKS_DESCRIPTOR, 0, 0, 0, 0).err(),
            fc::decrypt(so, h, &OWNER, &ct, false).err(),
            fc::decrypt(so, h, &OWNER, &ct, true).err(),
            // A handle that names nothing: still the role error, not an object error (§5.3 step 1 first).
            fc::decrypt(so, 0x00de_adbe, &OWNER, &ct, false).err(),
        ];
        let mut kp = Vec::new();
        kp.extend_from_slice(&1usize.to_ne_bytes());
        kp.extend_from_slice(&(TEST_RING as usize).to_ne_bytes());
        kp.extend_from_slice(&rpid);
        kp.extend_from_slice(&dpid);
        let mut km = [CKM_PQCTODAY_FHE_KEY_GEN as usize, kp.as_ptr() as usize, kp.len()];
        let mut nh = 0u32;
        let keygen_rv = ffi::C_GenerateKey(so, km.as_mut_ptr() as *mut u8, std::ptr::null_mut(), 0, &mut nh);
        let dprm = decrypt_params(&OWNER);
        let mut dm = [CKM_PQCTODAY_FHE_DECRYPT as usize, dprm.as_ptr() as usize, dprm.len()];
        let init = ffi::C_DecryptInit(so, dm.as_mut_ptr() as *mut u8, h);
        (rust, [keygen_rv, init])
    });
    assert_eq!(so_rust, [Some(CKR_USER_TYPE_INVALID); 5], "SO through the Rust API");
    assert_eq!(so_abi, [CKR_USER_TYPE_INVALID; 2], "SO through the C ABI");

    // A public session: the user logged out.
    native::logout(u0).unwrap();
    let public = open_rw_session(0);
    let h_pub = h;
    assert_eq!(fc::decrypt(public, h_pub, &OWNER, &ct, false).map(|_| ()), Err(CKR_USER_NOT_LOGGED_IN));
    assert_eq!(fc::decrypt(public, 0x00de_adbe, &OWNER, &ct, true).map(|_| ()), Err(CKR_USER_NOT_LOGGED_IN), "no object probe before the role check");
    assert_eq!(fhe::generate_fhe_seed(public, TEST_RING, &rpid, &dpid, None, None), Err(CKR_USER_NOT_LOGGED_IN));
    assert_eq!(ffi::C_CloseSession(public), CKR_OK);
    let mut pin = USER.as_bytes().to_vec();
    assert_eq!(ffi::C_Login(u0, CKU_USER, pin.as_mut_ptr(), pin.len() as u32), CKR_OK);
    let h = native::find_all_by_cka_id(u0, b"roles").unwrap()[0];
    assert_eq!(native::get_attribute(u0, h, CKA_PQCTODAY_FHE_LINEAGE_ID).unwrap(), lineage);
    assert_eq!(counter(h), 0, "no refusal spent a unit");
    // The owner still decrypts.
    owner_release(u0, h, &ct).expect("the owner's release");
    assert_eq!(counter(h), 1);
}

/// Budget exhausted (§6.4): every call with a buffer spends one unit, released or refused; a foreign ciphertext
/// (encrypted under another seed: wrong lineage) decrypts to noise and is refused by the value range, spending its
/// unit; an unenrolled recipient is refused and spends its unit; then the budget is exhausted and even a good
/// ciphertext is refused without spending anything more. Size queries are free throughout.
#[test]
fn budget_exhausted_and_foreign_ciphertexts_spend_the_counter() {
    let _g = lock();
    let seed_value = [9u8; 32];
    let (_w, s, h) = setup(3, &seed_value, b"budget");
    let ps = params::find(TEST_RING).unwrap();
    let m = small_plaintext(ps);
    let good = ciphertext(ps, &seed_value, &m, 5);
    let foreign = ciphertext(ps, &[8u8; 32], &m, 5);
    for _ in 0..5 {
        fc::decrypt(s, h, &OWNER, &good, true).unwrap();
        fc::decrypt(s, h, &OWNER, &foreign, true).unwrap();
    }
    assert_eq!(counter(h), 0, "size queries are free");
    owner_release(s, h, &good).expect("first unit");
    assert_eq!(counter(h), 1);
    assert_eq!(owner_release(s, h, &foreign), Err(CKR_ACTION_PROHIBITED), "another seed's ciphertext");
    assert_eq!(repl::last_refusal(), Some("value range"));
    assert_eq!(counter(h), 2, "the refusal spent its unit");
    assert_eq!(fc::decrypt(s, h, &[7u8; 48], &good, false).map(|_| ()), Err(CKR_ACTION_PROHIBITED), "recipient not in the policy");
    assert_eq!(repl::last_refusal(), Some("recipient not allowed"));
    assert_eq!(counter(h), 3);
    assert_eq!(owner_release(s, h, &good), Err(CKR_ACTION_PROHIBITED));
    assert_eq!(repl::last_refusal(), Some("decrypt budget exhausted"));
    assert_eq!(counter(h), 3, "an exhausted budget stays at its maximum");
    // The C ABI path ends the operation on the refusal.
    let p = decrypt_params(&OWNER);
    let mut mm = [CKM_PQCTODAY_FHE_DECRYPT as usize, p.as_ptr() as usize, p.len()];
    assert_eq!(ffi::C_DecryptInit(s, mm.as_mut_ptr() as *mut u8, h), CKR_OK);
    let mut out = vec![0u8; 1 << 16];
    let mut n = out.len() as u32;
    assert_eq!(ffi::C_Decrypt(s, good.as_ptr() as *mut u8, good.len() as u32, out.as_mut_ptr(), &mut n), CKR_ACTION_PROHIBITED);
    assert!(fc::active(s).is_none(), "the refusal ended the operation");
    assert_eq!(counter(h), 3);
}

/// Wrong lineage on the recipient side: a signed, sealed release opens only for the lineage and decryption policy it
/// was made under, and only on the recipient's token. Any other lineage or policy, or opening on the seed's own token,
/// fails the signature check (CKR_SIGNATURE_INVALID) and opens nothing.
#[test]
fn sealed_release_opens_only_for_its_lineage_policy_and_recipient() {
    let _g = lock();
    let w = world(2);
    let rchain = repl::function_chain(w.tokens[1].user, Purpose::RecoveryRecipient).unwrap();
    let r_hash = w.as_so(0, |so| fc::enroll_fhe_recipient(so, &rchain).unwrap());
    let (rp, dp) = (ckks_repl_policy(&w, 4), ckks_dpol(TEST_RING, 10, vec![r_hash]));
    let (rpid, dpid) = w.as_so(0, |so| (repl::enroll_policy(so, &rp).unwrap(), fhe::enroll_fhe_decrypt_policy(so, &dp).unwrap()));
    let s = w.tokens[0].user;
    let seed_value = [11u8; 32];
    let h = fhe::generate_fhe_seed_with_value_for_test(s, TEST_RING, &rpid, &dpid, &seed_value, b"sealed").unwrap();
    let ps = params::find(TEST_RING).unwrap();
    let ct = ciphertext(ps, &seed_value, &small_plaintext(ps), 5);
    let (_, out) = fc::decrypt(s, h, &r_hash, &ct, false).expect("flooded recipient release");
    let Some(DecryptOutput::Sealed(sealed)) = out else { panic!("sealed release expected") };
    let lineage: [u8; 32] = native::get_attribute(s, h, CKA_PQCTODAY_FHE_LINEAGE_ID).unwrap().try_into().unwrap();
    let opened = fc::open_release(w.tokens[1].user, &sealed, &lineage, &dpid).expect("the recipient opens it");
    assert_eq!(opened.counter, 1);
    assert_eq!(opened.plaintext[0], mech::OUT_TYPE);
    let mut other = lineage;
    other[0] ^= 1;
    assert_eq!(fc::open_release(w.tokens[1].user, &sealed, &other, &dpid), Err(CKR_SIGNATURE_INVALID), "another lineage");
    let mut other_policy = dpid;
    other_policy[47] ^= 1;
    assert_eq!(fc::open_release(w.tokens[1].user, &sealed, &lineage, &other_policy), Err(CKR_SIGNATURE_INVALID), "another policy");
    assert_eq!(fc::open_release(s, &sealed, &lineage, &dpid), Err(CKR_SIGNATURE_INVALID), "not addressed to the seed's own token");
}

// ── Oversized and malformed input at every entry point ─────────────────────

/// Every entry point refuses oversized or malformed input with its own code, before any work and without spending a
/// counter unit: the decrypt input (Rust API and C ABI, 4 MiB cap and empty), the decrypt, key-generation and
/// derive parameters (every wrong length, out-of-range values), the KEY_GEN template (more than 64 attributes, a value
/// over 4 KiB, a forbidden attribute), the decryption policy (over 8 KiB), and the signed admin payloads ([5] policy over
/// 8 KiB, [6] chain of five or a certificate over 8 KiB, [7] lineage of 31 or 33 bytes, a request over 96 KiB).
#[test]
fn oversized_and_malformed_inputs_are_refused_at_every_entry_point() {
    let _g = lock();
    let seed_value = [9u8; 32];
    let (w, s, h) = setup(10, &seed_value, b"oversized");
    let ps = params::find(TEST_RING).unwrap();

    // Decrypt input, Rust API.
    let big = vec![0u8; fc::MAX_DECRYPT_INPUT + 1];
    for size_only in [true, false] {
        assert_eq!(fc::decrypt(s, h, &OWNER, &big, size_only).map(|_| ()), Err(CKR_DATA_LEN_RANGE));
        assert_eq!(fc::decrypt(s, h, &OWNER, &[], size_only).map(|_| ()), Err(CKR_DATA_LEN_RANGE));
    }
    // Decrypt input, C ABI: refused, the operation ends.
    let p = decrypt_params(&OWNER);
    let mut mm = [CKM_PQCTODAY_FHE_DECRYPT as usize, p.as_ptr() as usize, p.len()];
    for out_null in [true, false] {
        assert_eq!(ffi::C_DecryptInit(s, mm.as_mut_ptr() as *mut u8, h), CKR_OK);
        let mut out = vec![0u8; 64];
        let mut n = 64u32;
        let outp = if out_null { std::ptr::null_mut() } else { out.as_mut_ptr() };
        assert_eq!(ffi::C_Decrypt(s, big.as_ptr() as *mut u8, big.len() as u32, outp, &mut n), CKR_DATA_LEN_RANGE);
        assert!(fc::active(s).is_none());
    }
    // Decrypt parameters: every length but the one, a null pointer, an unknown version.
    let good_len = (W + 48).next_multiple_of(W);
    let buf = vec![0u8; 1 << 16];
    for len in [0, 1, W, W + 47, good_len - 1, good_len + 1, good_len + W, 1 << 16] {
        let mut m = [CKM_PQCTODAY_FHE_DECRYPT as usize, buf.as_ptr() as usize, len];
        assert_eq!(ffi::C_DecryptInit(s, m.as_mut_ptr() as *mut u8, h), CKR_MECHANISM_PARAM_INVALID, "decrypt parameter length {len}");
    }
    let mut m = [CKM_PQCTODAY_FHE_DECRYPT as usize, 0, good_len];
    assert_eq!(ffi::C_DecryptInit(s, m.as_mut_ptr() as *mut u8, h), CKR_MECHANISM_PARAM_INVALID, "null parameter");
    let mut v2 = decrypt_params(&OWNER);
    v2[..W].copy_from_slice(&2usize.to_ne_bytes());
    let mut m = [CKM_PQCTODAY_FHE_DECRYPT as usize, v2.as_ptr() as usize, v2.len()];
    assert_eq!(ffi::C_DecryptInit(s, m.as_mut_ptr() as *mut u8, h), CKR_MECHANISM_PARAM_INVALID, "version 2");
    assert!(fc::active(s).is_none());

    // KEY_GEN parameters and template.
    let rpid: [u8; 48] = native::get_attribute(s, h, CKA_PQCTODAY_REPLICATION_POLICY_ID).unwrap().try_into().unwrap();
    let dpid: [u8; 48] = native::get_attribute(s, h, CKA_PQCTODAY_FHE_DECRYPT_POLICY).unwrap().try_into().unwrap();
    let keygen_params = |version: usize, set: usize| {
        let mut kp = Vec::new();
        kp.extend_from_slice(&version.to_ne_bytes());
        kp.extend_from_slice(&set.to_ne_bytes());
        kp.extend_from_slice(&rpid);
        kp.extend_from_slice(&dpid);
        kp
    };
    let keygen = |kp: &[u8], len: usize, tmpl: &[usize], n: u32| {
        let mut m = [CKM_PQCTODAY_FHE_KEY_GEN as usize, kp.as_ptr() as usize, len];
        let mut nh = 0u32;
        let t = if tmpl.is_empty() { std::ptr::null_mut() } else { tmpl.as_ptr() as *mut u8 };
        ffi::C_GenerateKey(s, m.as_mut_ptr() as *mut u8, t, n, &mut nh)
    };
    let kp = keygen_params(1, TEST_RING as usize);
    let mut long = kp.clone();
    long.resize(1 << 16, 0);
    for len in [0, 1, kp.len() - 1, kp.len() + 1, 1 << 16] {
        assert_eq!(keygen(&long, len, &[], 0), CKR_MECHANISM_PARAM_INVALID, "KEY_GEN parameter length {len}");
    }
    assert_eq!(keygen(&keygen_params(0, TEST_RING as usize), kp.len(), &[], 0), CKR_MECHANISM_PARAM_INVALID, "version 0");
    if W == 8 {
        assert_eq!(keygen(&keygen_params(1, 1usize << 33), kp.len(), &[], 0), CKR_MECHANISM_PARAM_INVALID, "parameter set above 32 bits");
    }
    assert_eq!(keygen(&keygen_params(1, 0x7777), kp.len(), &[], 0), CKR_TEMPLATE_INCONSISTENT, "unregistered parameter set");
    let tok = bb(true);
    let many: Vec<(u32, Vec<u8>)> = (0..65).map(|_| (CKA_TOKEN, tok.clone())).collect();
    assert_eq!(keygen(&kp, kp.len(), &raw_template(&many), 65), CKR_ARGUMENTS_BAD, "65 template attributes");
    let label = vec![(CKA_LABEL, vec![b'x'; 4097])];
    assert_eq!(keygen(&kp, kp.len(), &raw_template(&label), 1), CKR_ARGUMENTS_BAD, "a 4097-byte label");
    let forbidden = vec![(CKA_EXTRACTABLE, bb(true))];
    assert_eq!(keygen(&kp, kp.len(), &raw_template(&forbidden), 1), CKR_TEMPLATE_INCONSISTENT);
    let destroyable = vec![(CKA_DESTROYABLE, bb(true))];
    assert_eq!(keygen(&kp, kp.len(), &raw_template(&destroyable), 1), CKR_TEMPLATE_INCONSISTENT, "a destroyable seed cannot be asked for");

    // DERIVE_PUBLIC parameters: every length but versions 1 (TFHE), 2 and 3, and out-of-range values in version 2.
    let derive_raw = |words: &[usize], len: usize| {
        let mut b: Vec<u8> = words.iter().flat_map(|v| v.to_ne_bytes()).collect();
        b.resize(b.len().max(1 << 16), 0);
        let mut m = [CKM_PQCTODAY_FHE_DERIVE_PUBLIC as usize, b.as_ptr() as usize, len];
        let mut nh = 0u32;
        ffi::C_DeriveKey(s, m.as_mut_ptr() as *mut u8, h, std::ptr::null_mut(), 0, &mut nh)
    };
    for len in [0, 1, W, 2 * W - 1, 2 * W + 1, 6 * W - 1, 6 * W + 1, 6 * W + 63, 6 * W + 65, 1 << 16] {
        assert_eq!(derive_raw(&[2, mech::PUBLIC_KIND_CKKS_DESCRIPTOR as usize], len), CKR_MECHANISM_PARAM_INVALID, "derive parameter length {len}");
    }
    let pk = mech::PUBLIC_KIND_CKKS_PUBLIC_KEY as usize;
    let evk = mech::PUBLIC_KIND_CKKS_EVK_CHUNK as usize;
    let limbs = ps.pk_limbs();
    for (words, why) in [
        ([2, usize::MAX, 0, 0, 0, 1], "kind above 32 bits"),
        ([2, 99, 0, 0, 0, 1], "unknown kind"),
        ([2, pk, 0, 0, 0, limbs + 1], "past the last limb"),
        ([2, pk, 0, 0, 0, usize::MAX], "limb index at usize::MAX"),
        ([2, pk, 0, 0, 3, 3], "empty range"),
        ([2, pk, 0, 0, 4, 3], "reversed range"),
        ([2, evk, ps.keys.len(), 0, 0, 1], "no such key"),
        ([2, evk, 0, 99, 0, 1], "no such digit"),
        ([2, evk, usize::MAX, 0, 0, 1], "key above 32 bits"),
        ([2, mech::PUBLIC_KIND_CKKS_MANIFEST as usize, 0, 0, 0, 1], "manifest takes no range"),
        ([7, pk, 0, 0, 0, 1], "unknown version"),
    ] {
        assert_eq!(derive_raw(&words, 6 * W), CKR_MECHANISM_PARAM_INVALID, "{why}");
    }
    // Version 1 names a TFHE kind: refused for a CKKS seed (and in a build without TFHE-rs altogether).
    assert_eq!(derive_raw(&[1, 2], 2 * W), CKR_MECHANISM_PARAM_INVALID, "parameter version 1 on a CKKS seed");
    assert_eq!(counter(h), 0, "nothing above reached the counter");

    // Decryption policy over 8 KiB, valid in every other respect: refused at enrolment.
    let mut huge: fhe::FheDecryptPolicy = der::Decode::from_der(&ckks_dpol(TEST_RING, 10, vec![])).unwrap();
    huge.never_release = vec![fhe::FheType { type_name: "x".repeat(9000), width_bits: 64, param_set: TEST_RING, serialization_version: mech::CT_VERSION, compressed_allowed: false }];
    let huge = huge.to_der().unwrap();
    assert!(huge.len() > 8192);
    assert_eq!(w.as_so(0, |so| fhe::enroll_fhe_decrypt_policy(so, &huge)), Err(CKR_DATA_INVALID));
    assert_eq!(w.as_so(0, |so| fhe::enroll_fhe_decrypt_policy(so, &vec![0x30; 8193])), Err(CKR_DATA_INVALID));

    // Signed admin payloads: malformed is CKR_DATA_INVALID before any trust check, so no signature is needed.
    let dev = repl::device_id(w.tokens[0].user).unwrap();
    let request = |op: &AdminOperation, edit: &dyn Fn(&mut admin::AdminTbsRequest)| -> Vec<u8> {
        let tbs = admin_host::tbs_request(&dev, &[3u8; 32], &[4u8; 32], 1, w.now, op).unwrap();
        let mut t: admin::AdminTbsRequest = der::Decode::from_der(&tbs).unwrap();
        edit(&mut t);
        admin_host::signed_request(&t.to_der().unwrap(), &[0u8; 3309]).unwrap()
    };
    let none = |_: &mut admin::AdminTbsRequest| {};
    let cases: Vec<(Vec<u8>, &str)> = vec![
        (request(&AdminOperation::EnrollFheDecryptPolicy { policy: vec![0x30; 8193] }, &none), "[5] policy over 8 KiB"),
        (request(&AdminOperation::EnrollFheDecryptPolicy { policy: vec![] }, &none), "[5] empty policy"),
        (request(&AdminOperation::EnrollFheRecipient { chain: vec![vec![0x30, 0]; 5] }, &none), "[6] chain of five"),
        (request(&AdminOperation::EnrollFheRecipient { chain: vec![vec![0x30; 8193]] }, &none), "[6] certificate over 8 KiB"),
        (request(&AdminOperation::EnrollFheRecipient { chain: vec![] }, &none), "[6] empty chain"),
        (
            request(&AdminOperation::DestroyFheSeed { lineage: [1; 32] }, &|t: &mut admin::AdminTbsRequest| t.destroy_fhe_seed = Some(admin::DestroyFheSeedOp { lineage: der::asn1::OctetString::new(vec![1; 31]).unwrap() })),
            "[7] lineage of 31 bytes",
        ),
        (
            request(&AdminOperation::DestroyFheSeed { lineage: [1; 32] }, &|t: &mut admin::AdminTbsRequest| t.destroy_fhe_seed = Some(admin::DestroyFheSeedOp { lineage: der::asn1::OctetString::new(vec![1; 33]).unwrap() })),
            "[7] lineage of 33 bytes",
        ),
        (vec![0x30; admin::MAX_ADMIN_REQUEST_DER + 1], "request over 96 KiB"),
    ];
    let got: Vec<(u32, &str)> = w.as_so(0, |so| cases.iter().map(|(r, why)| (admin::execute(so, r).err().unwrap_or(CKR_OK), *why)).collect());
    for (rv, why) in got {
        assert_eq!(rv, CKR_DATA_INVALID, "{why}");
    }
}

// ── Seeds cannot be destroyed, generated or replicated ─────────────────────

/// F16: a generated seed and its replica are both CKA_DESTROYABLE = FALSE. The normal user's C_DestroyObject gets
/// CKR_ACTION_PROHIBITED on each; neither can be made destroyable with C_SetAttributeValue (the seed is not
/// modifiable) or copied into a destroyable object (not copyable). The replica starts its own counter at 0 (§6.4).
#[test]
fn generated_and_replicated_seeds_cannot_be_destroyed() {
    let _g = lock();
    let w = world(2);
    let rp = ckks_repl_policy(&w, 4);
    let dp = ckks_dpol(TEST_RING, 10, vec![]);
    let rpid = w.enroll_policy_everywhere(&rp);
    let mut dpid = [0u8; 48];
    for i in 0..2 {
        dpid = w.as_so(i, |so| fhe::enroll_fhe_decrypt_policy(so, &dp).unwrap());
    }
    let (u0, u1) = (w.tokens[0].user, w.tokens[1].user);
    let seed_value = [13u8; 32];
    let src = fhe::generate_fhe_seed_with_value_for_test(u0, TEST_RING, &rpid, &dpid, &seed_value, b"no-destroy").unwrap();
    let ps = params::find(TEST_RING).unwrap();
    let ct = ciphertext(ps, &seed_value, &small_plaintext(ps), 5);
    owner_release(u0, src, &ct).unwrap();
    let pkg = repl::create_replication_package(u0, src, &request(&w, 0, 1, Operation::LiveClone, &rpid)).expect("package");
    let (replica, _) = repl::import_replication_package(u1, &pkg, &[]).expect("replica");
    for (s, h, what) in [(u0, src, "generated"), (u1, replica, "replicated")] {
        assert_eq!(native::get_attribute_bool(s, h, CKA_DESTROYABLE), Some(false), "{what}");
        assert_eq!(ffi::C_DestroyObject(s, h), CKR_ACTION_PROHIBITED, "{what}: C_DestroyObject");
        let attrs = vec![(CKA_DESTROYABLE, bb(true))];
        let t = raw_template(&attrs);
        assert_ne!(ffi::C_SetAttributeValue(s, h, t.as_ptr() as *mut u8, 1), CKR_OK, "{what}: made destroyable");
        let mut copy = 0u32;
        assert_ne!(ffi::C_CopyObject(s, h, t.as_ptr() as *mut u8, 1, &mut copy), CKR_OK, "{what}: copied");
        assert_eq!(native::get_attribute_bool(s, h, CKA_DESTROYABLE), Some(false), "{what}: unchanged");
    }
    assert_eq!(counter(src), 1);
    assert_eq!(counter(replica), 0, "a replica starts its own counter");
    owner_release(u1, replica, &ct).expect("the replica decrypts the source's ciphertext");
}

// ── Release-path review: the counter race ──────────────────────────────────

/// Found by the WP-A3 review of the decrypt-release path: both decrypt paths read the counter from the attribute
/// snapshot taken when the seed was resolved and committed snapshot + 1, so concurrent calls on one seed could pass the
/// budget check with the same count and commit the same value (two decryptions for one unit, and one release more
/// than maxDecrypts at the boundary). The reservation now re-reads and writes under one lock
/// (`fhe_custody::reserve_decrypt_unit`). Sixteen threads, each with its own session, race 64 owner decryptions
/// against a budget of 12: exactly 12 are released and the counter ends at 12. Against the decrypt paths as they were
/// (1b7bc9af) this test failed in three of three runs on the M4 Pro, with 22, 21 and 25 releases for the budget of 12.
#[test]
fn concurrent_decrypts_never_exceed_the_budget() {
    let _g = lock();
    let seed_value = [21u8; 32];
    let budget = 12u32;
    let (_w, _s, h) = setup(budget, &seed_value, b"race");
    let ps = params::find(TEST_RING).unwrap();
    let ct = std::sync::Arc::new(ciphertext(ps, &seed_value, &small_plaintext(ps), 5));
    let sessions: Vec<u32> = (0..16).map(|_| open_rw_session(0)).collect();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(sessions.len()));
    let threads: Vec<_> = sessions
        .iter()
        .map(|&s| {
            let (ct, barrier) = (ct.clone(), barrier.clone());
            std::thread::spawn(move || {
                barrier.wait();
                (0..4).filter(|_| matches!(fc::decrypt(s, h, &OWNER, &ct, false), Ok((_, Some(DecryptOutput::Owner(_)))))).count()
            })
        })
        .collect();
    let released: usize = threads.into_iter().map(|t| t.join().expect("no panic")).sum();
    assert_eq!(released, budget as usize, "releases equal the budget");
    assert_eq!(counter(h), budget as u64, "one unit per release");
    for s in sessions {
        assert_eq!(ffi::C_CloseSession(s), CKR_OK);
    }
}

/// PKCS#11 v3.2 §5.6: closing a session ends its active operations. A pending FHE decryption is dropped with its
/// session (it used to stay in the engine's operation table after C_CloseSession).
#[test]
fn closing_a_session_ends_its_pending_fhe_decryption() {
    let _g = lock();
    let (_w, _s, h) = setup(10, &[23u8; 32], b"close");
    let s2 = open_rw_session(0);
    let p = decrypt_params(&OWNER);
    let mut mm = [CKM_PQCTODAY_FHE_DECRYPT as usize, p.as_ptr() as usize, p.len()];
    assert_eq!(ffi::C_DecryptInit(s2, mm.as_mut_ptr() as *mut u8, h), CKR_OK);
    assert!(fc::active(s2).is_some());
    assert_eq!(ffi::C_CloseSession(s2), CKR_OK);
    assert!(fc::active(s2).is_none(), "the pending decryption ended with its session");
}
