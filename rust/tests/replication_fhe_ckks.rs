//! Streamed-CKKS ledger and token-signed manifest (plan
//! pqctoday-fhe docs/ckks/ckks-streamed-evaluation-keys-plan-2026-10-10.md
//! §3.2 kind 6, E3; §7 S5 integrity). INSECURE test ring 0x8002 only.
#![cfg(all(feature = "educational-ckks", feature = "test-support"))]

mod replication_common;
use replication_common::*;

use sha2::Digest;
use softhsmrustv3::constants::*;
use softhsmrustv3::native;
use softhsmrustv3::replication::fhe_ckks::{mech, params};
use softhsmrustv3::replication::{self as repl, fhe, records};

const PS: u32 = 0x8002;
const KAT_SEED: [u8; 32] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31];

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// One token with the CKKS replication profile, a version 2 decryption policy
/// and the KAT seed 00..1f on the test ring. Returns (world, user session, seed).
fn setup() -> (World, u32, u32) {
    use der::Encode;
    let w = world(1);
    let ps = params::find(PS).unwrap();
    let rp = records::build_policy_with_constraint(
        DOMAIN, [true, true, true], w.device_ids(), w.now - 60, w.now + 30 * 86_400, 4,
        vec![CKM_PQCTODAY_FHE_DERIVE_PUBLIC, CKM_PQCTODAY_FHE_DECRYPT], false, fhe::ckks_profile_constraint_hash(),
    )
    .unwrap();
    let dpol = fhe::FheDecryptPolicy {
        version: 2,
        allowed_output_types: vec![fhe::FheType { type_name: mech::CKKS_TYPE_NAME.into(), width_bits: 64, param_set: PS, serialization_version: mech::CT_VERSION, compressed_allowed: false }],
        never_release: vec![],
        predicates: vec![],
        recipients: vec![],
        recipient_only: false,
        max_decrypts: 100,
        ckks: Some(fhe::CkksReleasePolicy { max_values: (ps.n() / 2) as u32, precision_bits: 20, value_bound_log2: 10, scale_log2: ps.log_default_scale as u8, flood_recipients: true, flood_owner: false, stat_security_bits: 30 }),
    }
    .to_der()
    .unwrap();
    let (rpid, dpid) = w.as_so(0, |so| (repl::enroll_policy(so, &rp).unwrap(), fhe::enroll_fhe_decrypt_policy(so, &dpol).unwrap()));
    let s = w.tokens[0].user;
    let seed = fhe::generate_fhe_seed_with_value_for_test(s, PS, &rpid, &dpid, &KAT_SEED, b"ckks-ledger-seed").expect("KEY_GEN");
    (w, s, seed)
}

/// A second R/W session on slot 0 (the user is already logged in on the slot).
fn extra_session() -> u32 {
    let mut h = 0u32;
    assert_eq!(softhsmrustv3::ffi::C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, std::ptr::null_mut(), std::ptr::null_mut(), &mut h), CKR_OK);
    h
}

/// derive → read CKA_VALUE → destroy, like the custodian.
fn derive(s: u32, seed: u32, kind: u32, k: u32, d: u32, from: usize, to: usize) -> Result<Vec<u8>, u32> {
    let h = mech::derive_public_v2(s, seed, kind, k, d, from, to)?;
    let v = native::get_attribute(s, h, CKA_VALUE).expect("CKA_VALUE");
    assert_eq!(softhsmrustv3::ffi::C_DestroyObject(s, h), CKR_OK);
    Ok(v)
}

fn manifest(s: u32, seed: u32) -> Result<Vec<u8>, u32> {
    derive(s, seed, mech::PUBLIC_KIND_CKKS_MANIFEST, 0, 0, 0, 0)
}

/// Every chunk the custodian would request, in its order: (kind, k, d, from, to).
fn plan(per: usize) -> Vec<(u32, u32, u32, usize, usize)> {
    let ps = params::find(PS).unwrap();
    let mut v = Vec::new();
    for from in (0..ps.pk_limbs()).step_by(per) {
        v.push((mech::PUBLIC_KIND_CKKS_PUBLIC_KEY, 0, 0, from, (from + per).min(ps.pk_limbs())));
    }
    for (k, key) in ps.keys.iter().enumerate() {
        for d in 0..key.dnum() {
            for from in (0..key.limbs()).step_by(per) {
                v.push((mech::PUBLIC_KIND_CKKS_EVK_CHUNK, k as u32, d as u32, from, (from + per).min(key.limbs())));
            }
        }
    }
    v
}

/// Descriptor then every chunk; returns (descriptor, chunks with their bytes).
#[allow(clippy::type_complexity)]
fn export(s: u32, seed: u32, per: usize) -> (Vec<u8>, Vec<((u32, u32, u32, usize, usize), Vec<u8>)>) {
    let desc = derive(s, seed, mech::PUBLIC_KIND_CKKS_DESCRIPTOR, 0, 0, 0, 0).expect("descriptor");
    let chunks = plan(per).into_iter().map(|c| (c, derive(s, seed, c.0, c.1, c.2, c.3, c.4).expect("chunk"))).collect();
    (desc, chunks)
}

#[test]
fn ckks_manifest_signed_after_exact_coverage() {
    let _g = lock();
    let (w, s, seed) = setup();
    let ps = params::find(PS).unwrap();
    // 3 limbs per call: uneven last chunks.
    let (desc, chunks) = export(s, seed, 3);
    let der = manifest(s, seed).expect("manifest after full coverage");

    // Signature and chain: validated against this token's trust inputs.
    let (tbs, device) = mech::verify_ckks_manifest(&der, &trust_of(&w, 0), w.now).expect("manifest verifies");
    assert_eq!(device, w.device_ids()[0]);
    let m: mech::CkksSignedManifestV1 = der::Decode::from_der(&der).unwrap();
    assert_eq!(m.signature.as_bytes().len(), 3309, "ML-DSA-65 signature");
    assert_eq!(m.signer_chain.len(), 2);

    // TBS binds the descriptor, the parameter hash and the lineage.
    assert_eq!(tbs.version, 1);
    assert_eq!(tbs.descriptor_hash.as_bytes(), sha2::Sha256::digest(&desc).as_slice());
    assert_eq!(tbs.param_hash.as_bytes(), native::get_attribute(s, seed, CKA_PQCTODAY_FHE_PARAM_HASH).unwrap().as_slice());
    assert_eq!(tbs.lineage.as_bytes(), native::get_attribute(s, seed, CKA_PQCTODAY_FHE_LINEAGE_ID).unwrap().as_slice());

    // Exact coverage: one entry per chunk, each hash = SHA-256 of that chunk,
    // in ledger order (kind, key, digit, from).
    let mut want: Vec<_> = chunks.iter().map(|(c, b)| ((c.0, c.1, c.2, c.3 as u32), c.4 as u32, sha2::Sha256::digest(b).to_vec())).collect();
    want.sort();
    assert_eq!(tbs.entries.len(), want.len());
    for (e, (key, to, h)) in tbs.entries.iter().zip(want.iter()) {
        assert_eq!((e.kind, e.key, e.digit, e.from), *key);
        assert_eq!(e.to, *to);
        assert_eq!(e.sha256.as_bytes(), h.as_slice());
    }

    // Kinds 3/4/5 bytes unchanged: the chunks recompose to the oracle KAT.
    let kat: serde_json::Value = serde_json::from_str(include_str!("../kat/fhe-ckks-kat-32770.json")).unwrap();
    let pk: Vec<u8> = chunks.iter().filter(|(c, _)| c.0 == mech::PUBLIC_KIND_CKKS_PUBLIC_KEY).flat_map(|(_, b)| b.clone()).collect();
    assert_eq!(hexs(&sha2::Sha256::digest(&pk)), kat["pkSha256"].as_str().unwrap());
    let want_keys = kat["keySha256"].as_array().unwrap();
    for k in 0..ps.keys.len() as u32 {
        let mut h = sha2::Sha256::new();
        chunks.iter().filter(|(c, _)| c.0 == mech::PUBLIC_KIND_CKKS_EVK_CHUNK && c.1 == k).for_each(|(_, b)| h.update(b));
        assert_eq!(hexs(&h.finalize()), want_keys[k as usize].as_str().unwrap(), "key {k}");
    }
    let d: mech::CkksKeySetDescriptorV1 = der::Decode::from_der(&desc).unwrap();
    assert_eq!(hexs(d.a_seed.as_bytes()), kat["aSeed"].as_str().unwrap());

    // Tampering: a flipped signature byte or entry hash no longer verifies.
    let mut bad = m.clone();
    let mut sig = bad.signature.as_bytes().to_vec();
    sig[0] ^= 1;
    bad.signature = der::asn1::OctetString::new(sig).unwrap();
    assert_eq!(mech::verify_ckks_manifest(&der::Encode::to_der(&bad).unwrap(), &trust_of(&w, 0), w.now), Err(CKR_SIGNATURE_INVALID));
    let mut bad = m.clone();
    let mut h = bad.tbs.entries[0].sha256.as_bytes().to_vec();
    h[0] ^= 1;
    bad.tbs.entries[0].sha256 = der::asn1::OctetString::new(h).unwrap();
    assert_eq!(mech::verify_ckks_manifest(&der::Encode::to_der(&bad).unwrap(), &trust_of(&w, 0), w.now), Err(CKR_SIGNATURE_INVALID));
    let mut bad = m.clone();
    bad.tbs.entries.pop();
    assert_eq!(mech::verify_ckks_manifest(&der::Encode::to_der(&bad).unwrap(), &trust_of(&w, 0), w.now), Err(CKR_SIGNATURE_INVALID));

    // The ledger is consumed by the manifest: a second one needs a new export.
    assert_eq!(manifest(s, seed), Err(CKR_OPERATION_NOT_INITIALIZED));

    // Determinism (S2): a second export gives the same chunk bytes and the same TBS.
    let (desc2, chunks2) = export(s, seed, 3);
    assert_eq!(desc2, desc);
    assert_eq!(chunks2, chunks);
    let (tbs2, _) = mech::verify_ckks_manifest(&manifest(s, seed).unwrap(), &trust_of(&w, 0), w.now).unwrap();
    assert_eq!(tbs2, tbs);
}

#[test]
fn ckks_ledger_refusals() {
    let _g = lock();
    let (_w, s, seed) = setup();
    let ps = params::find(PS).unwrap();
    let pk = mech::PUBLIC_KIND_CKKS_PUBLIC_KEY;

    // No descriptor in this session: chunks and manifest refused.
    assert_eq!(derive(s, seed, pk, 0, 0, 0, 1), Err(CKR_OPERATION_NOT_INITIALIZED));
    assert_eq!(derive(s, seed, mech::PUBLIC_KIND_CKKS_EVK_CHUNK, 0, 0, 0, 1), Err(CKR_OPERATION_NOT_INITIALIZED));
    assert_eq!(manifest(s, seed), Err(CKR_OPERATION_NOT_INITIALIZED));
    // Kind 6 takes no indices.
    derive(s, seed, mech::PUBLIC_KIND_CKKS_DESCRIPTOR, 0, 0, 0, 0).unwrap();
    assert_eq!(derive(s, seed, mech::PUBLIC_KIND_CKKS_MANIFEST, 0, 0, 0, 1), Err(CKR_MECHANISM_PARAM_INVALID));
    assert_eq!(derive(s, seed, mech::PUBLIC_KIND_CKKS_MANIFEST, 1, 0, 0, 0), Err(CKR_MECHANISM_PARAM_INVALID));

    // Partial coverage: everything but the last chunk.
    let all = plan(4);
    for c in &all[..all.len() - 1] {
        derive(s, seed, c.0, c.1, c.2, c.3, c.4).unwrap();
    }
    assert_eq!(manifest(s, seed), Err(CKR_FUNCTION_FAILED), "missing chunk");
    // Identical repeats are idempotent; completing the set signs.
    let c = all[0];
    derive(s, seed, c.0, c.1, c.2, c.3, c.4).unwrap();
    let c = *all.last().unwrap();
    derive(s, seed, c.0, c.1, c.2, c.3, c.4).unwrap();
    manifest(s, seed).expect("complete after idempotent repeat");

    // Overlap with different bounds: [0,2) then [1,3) of the public key.
    derive(s, seed, mech::PUBLIC_KIND_CKKS_DESCRIPTOR, 0, 0, 0, 0).unwrap();
    derive(s, seed, pk, 0, 0, 0, 2).unwrap();
    derive(s, seed, pk, 0, 0, 1, 3).unwrap();
    for c in plan(4) {
        derive(s, seed, c.0, c.1, c.2, c.3, c.4).unwrap();
    }
    assert_eq!(manifest(s, seed), Err(CKR_FUNCTION_FAILED), "overlap");
    // Same start, different end: also a conflict.
    derive(s, seed, mech::PUBLIC_KIND_CKKS_DESCRIPTOR, 0, 0, 0, 0).unwrap();
    derive(s, seed, pk, 0, 0, 0, 1).unwrap();
    derive(s, seed, pk, 0, 0, 0, 2).unwrap();
    assert_eq!(manifest(s, seed), Err(CKR_FUNCTION_FAILED), "same start, different bounds");
    // A new descriptor restarts the ledger: a clean export now signs.
    export(s, seed, ps.pk_limbs());
    manifest(s, seed).expect("fresh ledger");
}

#[test]
fn ckks_ledger_is_per_session_and_cleared_on_close() {
    let _g = lock();
    let (_w, s, seed) = setup();

    // Full export in session A; session B has no ledger.
    let a = extra_session();
    export(a, seed, 8);
    let b = extra_session();
    assert_eq!(manifest(b, seed), Err(CKR_OPERATION_NOT_INITIALIZED));
    // Close A: its ledger is gone; a new session C cannot sign without re-export.
    native::close_session(a).unwrap();
    let c = extra_session();
    assert_eq!(manifest(c, seed), Err(CKR_OPERATION_NOT_INITIALIZED));
    assert_eq!(derive(c, seed, mech::PUBLIC_KIND_CKKS_PUBLIC_KEY, 0, 0, 0, 1), Err(CKR_OPERATION_NOT_INITIALIZED));
    export(c, seed, 8);
    manifest(c, seed).expect("re-export in the new session");

    // C_CloseAllSessions clears every ledger on the slot.
    export(b, seed, 8);
    assert_eq!(softhsmrustv3::ffi::C_CloseAllSessions(0), CKR_OK);
    let d = native::open_session(0, USER).unwrap();
    let seed = native::find_all_by_cka_id(d, b"ckks-ledger-seed").unwrap()[0];
    assert_eq!(manifest(d, seed), Err(CKR_OPERATION_NOT_INITIALIZED));
    let _ = s;
}
