//! Hash-signature engine, end to end against the register simulator.
//!
//! The simulator (`pqc_hw::hashsig_device::sim`) models the ABI v1 register
//! map, DMA request/completion records, validation and zeroisation; its
//! crypto backend is this crate's own software (`hw_accel::SoftwareSimBackend`).
//! The accelerator is admitted exactly as `C_Initialize` admits a real one
//! (QUERY_CAPS, RESET_CORE, known answer) and installed with the real hooks,
//! so every operation below runs through fips205 / hbs-lms → hook → pool →
//! ABI driver → simulated registers and DMA, and back.
//!
//! Each test compares hook-on output with hook-off output byte for byte and
//! checks that the engine really executed (or really did not execute) the
//! command.
//!
//! Only built with `--features hw-accel` on linux/aarch64 (the `pqc-rust`
//! container). The hash crates are slow unoptimised; run with
//! `--config 'profile.dev.package."*".opt-level=3'` for a quick run.
#![cfg(all(feature = "hw-accel", target_os = "linux", target_arch = "aarch64"))]

use pqc_hw::hashsig_device::abi::{Caps, Command, Status};
use pqc_hw::hashsig_device::pool::{HashsigAccelerator, Lane, Opener, Routing};
use pqc_hw::hashsig_device::sim::{Fault, SimHandle};
use pqc_hw::hashsig_device::{Engine, Health};
use softhsmrustv3::hw_accel;
use std::sync::atomic::Ordering;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Duration;

const PHYS: u64 = 0x7000_0000;
/// Largest LMS subtree the simulated engine claims; H10 trees exercise the
/// split path (root on ARM from two engine-computed children).
const LMS_MAX_K: u32 = 8;
/// Largest XMSS tree (h/d) the simulated engine claims; XMSS trees are
/// offered whole, so a 16-high tree stays on ARM.
const XMSS_MAX_K: u32 = 10;

fn caps() -> Caps {
    let s_sets = (1 << 1) | (1 << 2) | (1 << 5) | (1 << 6) | (1 << 9) | (1 << 10);
    Caps {
        caps_version: 1,
        lanes: 1,
        hash_cores: 0b111,
        clock_hz: 250_000_000,
        commands: (1 << 20) | (1 << 22) | (1 << 23) | (1 << 24) | (1 << 25) | (1 << 26),
        slh_sign_sets: s_sets,
        slh_keygen_sets: s_sets,
        lms_families: 0b1111,
        lmots_w: 0b1111,
        lms_max_subtree_height: LMS_MAX_K,
        // SHA2 n32/n24, SHAKE128 n32, SHAKE256 n32/n24 (the n = 64 OIDs are
        // never claimed in v1). Whole trees up to h/d = 10.
        xmss_families: 0b1_1111,
        xmss_max_subtree_height: XMSS_MAX_K,
        build_id: 0x041a_a370,
        max_batch: 16,
        sha256_cores: 2,
        sha512_cores: 1,
        keccak_rounds_per_clock: 1,
        generic_lanes: 1,
        ..Caps::default()
    }
}

struct Fixture {
    sim: SimHandle,
    accel: &'static HashsigAccelerator,
}

/// Admits and installs the simulated engine once per process; tests run
/// one at a time because they share it (and inject faults into it).
fn fixture() -> (MutexGuard<'static, ()>, &'static Fixture) {
    static SERIAL: Mutex<()> = Mutex::new(());
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    let guard = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let fixture = FIXTURE.get_or_init(|| {
        let sim = SimHandle::new(caps(), 1 << 20, PHYS, Box::new(hw_accel::SoftwareSimBackend));
        let opener_sim = sim.clone();
        let opener: Opener = Box::new(move |_| {
            Ok(Box::new(Engine::new(opener_sim.registers(), opener_sim.dma())?) as Box<dyn Lane>)
        });
        let accel = HashsigAccelerator::probe(
            opener,
            1,
            Routing::parse("all=fpga").unwrap(),
            4,
            hw_accel::software_reference(),
            None,
        )
        .expect("simulated engine passes QUERY_CAPS + RESET_CORE + known answer");
        assert!(accel.has_known_answer());
        assert_eq!(sim.executed(Command::SlhKeygen), 1, "the known answer ran on the engine");
        assert!(hw_accel::install_hashsig(accel));
        Fixture {
            sim,
            accel: hw_accel::hashsig().unwrap(),
        }
    });
    // Leave every test with a Ready engine, whatever the previous one did.
    fixture.sim.finish_hung();
    fixture.accel.set_enabled(true);
    fixture.accel.set_routing(Routing::parse("all=fpga").unwrap());
    fixture.accel.reset_recovery_backoff();
    let (sk, pk) = ([7u8; 16], [8u8; 16]);
    let _ = fixture.accel.slh_keygen(
        2,
        pqc_hw::hashsig_device::abi::SlhKeygenInput { sk_seed: &sk, pk_seed: &pk },
    );
    assert_eq!(fixture.accel.health(), vec![Some(Health::Ready)]);
    (guard, fixture)
}

// ---------------------------------------------------------------------------
// SLH-DSA
// ---------------------------------------------------------------------------

struct SlhRun {
    pk: Vec<u8>,
    sk: Vec<u8>,
    pure: Vec<u8>,
    prehash: Vec<u8>,
}

macro_rules! slh_run {
    ($m:ident) => {{
        use fips205::traits::{KeyGen, SerDes, Signer, Verifier};
        const N: usize = fips205::$m::N;
        let sk_seed: [u8; N] = core::array::from_fn(|i| i as u8);
        let sk_prf: [u8; N] = core::array::from_fn(|i| 0x40 + i as u8);
        let pk_seed: [u8; N] = core::array::from_fn(|i| 0x80 + i as u8);
        let (pk, sk) = fips205::$m::KG::keygen_with_seeds::<N>(&sk_seed, &sk_prf, &pk_seed);
        let message = b"hashsig engine byte-identity";
        let pure = sk.try_sign(message, b"ctx", false).unwrap();
        let prehash = sk
            .try_hash_sign(message, b"", &fips205::Ph::SHA256, false)
            .unwrap();
        assert!(pk.verify(message, &pure, b"ctx"));
        assert!(pk.hash_verify(message, &prehash, b"", &fips205::Ph::SHA256));
        // A hedged signature cannot be compared, but must verify.
        let hedged = sk.try_sign(message, b"", true).unwrap();
        assert!(pk.verify(message, &hedged, b""));
        // Key import re-derives PK.root (SLH_KEYGEN on the engine when claimed).
        let sk_bytes = sk.clone().into_bytes();
        assert!(fips205::$m::PrivateKey::try_from_bytes(&sk_bytes).is_ok());
        SlhRun {
            pk: pk.into_bytes().to_vec(),
            sk: sk_bytes.to_vec(),
            pure: pure.to_vec(),
            prehash: prehash.to_vec(),
        }
    }};
}

fn check_slh(fixture: &Fixture, id: u32, run: fn() -> SlhRun) {
    let (sim, accel) = (&fixture.sim, fixture.accel);
    accel.set_enabled(false);
    let (sign0, keygen0) = (sim.executed(Command::SlhSign), sim.executed(Command::SlhKeygen));
    let off = run();
    assert_eq!(sim.executed(Command::SlhSign), sign0, "hook off: engine unused");
    assert_eq!(sim.executed(Command::SlhKeygen), keygen0);

    accel.set_enabled(true);
    let hardware0 = accel.stats().hardware.load(Ordering::Relaxed);
    let on = run();
    // keygen + import check (each run twice and compared); pure + pre-hash
    // + hedged signatures.
    assert_eq!(sim.executed(Command::SlhKeygen), keygen0 + 4, "set {id}: SLH_KEYGEN on the engine");
    assert_eq!(sim.executed(Command::SlhSign), sign0 + 3, "set {id}: SLH_SIGN on the engine");
    assert_eq!(accel.stats().hardware.load(Ordering::Relaxed), hardware0 + 7);
    assert_eq!(on.pk, off.pk, "set {id}: public key");
    assert_eq!(on.sk, off.sk, "set {id}: private key");
    assert_eq!(on.pure, off.pure, "set {id}: pure signature");
    assert_eq!(on.prehash, off.prehash, "set {id}: pre-hash signature");
    assert!(sim.dma_is_zero(), "no secret left in the DMA buffer");
    assert_eq!(sim.inputs_left_nonzero(), 0);
}

#[test]
fn slh_dsa_shake_128s_is_byte_identical() {
    let (_g, f) = fixture();
    check_slh(f, 2, || slh_run!(slh_dsa_shake_128s));
}

#[test]
fn slh_dsa_sha2_128s_is_byte_identical() {
    let (_g, f) = fixture();
    check_slh(f, 1, || slh_run!(slh_dsa_sha2_128s));
}

#[test]
fn slh_dsa_shake_192s_is_byte_identical() {
    let (_g, f) = fixture();
    check_slh(f, 6, || slh_run!(slh_dsa_shake_192s));
}

#[test]
fn slh_dsa_sha2_192s_is_byte_identical() {
    let (_g, f) = fixture();
    check_slh(f, 5, || slh_run!(slh_dsa_sha2_192s));
}

#[test]
fn slh_dsa_shake_256s_is_byte_identical() {
    let (_g, f) = fixture();
    check_slh(f, 10, || slh_run!(slh_dsa_shake_256s));
}

#[test]
fn slh_dsa_sha2_256s_is_byte_identical() {
    let (_g, f) = fixture();
    check_slh(f, 9, || slh_run!(slh_dsa_sha2_256s));
}

#[test]
fn unclaimed_f_sets_and_cpu_routed_families_never_reach_the_engine() {
    let (_g, f) = fixture();
    let sign0 = f.sim.executed(Command::SlhSign);
    let keygen0 = f.sim.executed(Command::SlhKeygen);
    {
        use fips205::traits::{KeyGen, Signer};
        let (_, sk) = fips205::slh_dsa_shake_128f::KG::keygen_with_seeds::<16>(&[1; 16], &[2; 16], &[3; 16]);
        let _ = sk.try_sign(b"m", b"", false).unwrap();
    }
    assert_eq!(f.sim.executed(Command::SlhSign), sign0, "f sets are never claimed");
    assert_eq!(f.sim.executed(Command::SlhKeygen), keygen0);

    // The default routing pins SHA-2 to the CPU and sends SHAKE to the engine.
    f.accel.set_routing(Routing::default());
    {
        use fips205::traits::{KeyGen, Signer};
        let (_, sk) = fips205::slh_dsa_sha2_128s::KG::keygen_with_seeds::<16>(&[1; 16], &[2; 16], &[3; 16]);
        let _ = sk.try_sign(b"m", b"", false).unwrap();
        assert_eq!(f.sim.executed(Command::SlhSign), sign0, "SHA2 → CPU by default");
        let (_, sk) = fips205::slh_dsa_shake_128s::KG::keygen_with_seeds::<16>(&[1; 16], &[2; 16], &[3; 16]);
        let _ = sk.try_sign(b"m", b"", false).unwrap();
        assert_eq!(f.sim.executed(Command::SlhSign), sign0 + 1, "SHAKE → engine by default");
    }
}

// ---------------------------------------------------------------------------
// Fallback: contention and device errors
// ---------------------------------------------------------------------------

fn shake128s_key() -> fips205::slh_dsa_shake_128s::PrivateKey {
    use fips205::traits::KeyGen;
    fips205::slh_dsa_shake_128s::KG::keygen_with_seeds::<16>(&[4; 16], &[5; 16], &[6; 16]).1
}

fn sign_with(sk: &fips205::slh_dsa_shake_128s::PrivateKey) -> Vec<u8> {
    use fips205::traits::Signer;
    sk.try_sign(b"fallback", b"", false).unwrap().to_vec()
}

fn shake128s_signature() -> Vec<u8> {
    sign_with(&shake128s_key())
}

#[test]
fn contention_runs_on_arm_with_identical_output() {
    let (_g, f) = fixture();
    f.accel.set_enabled(false);
    let expected = shake128s_signature();
    f.accel.set_enabled(true);
    let _ = shake128s_signature(); // learns the wall time used for the timeout

    // Thread A takes the engine and its command hangs; thread B must not
    // wait for it: it signs on ARM immediately.
    f.sim.inject(Fault::Hang);
    let contended0 = f.accel.stats().contended.load(Ordering::Relaxed);
    let holder = std::thread::spawn(shake128s_signature);
    let started = std::time::Instant::now();
    while !f.sim.is_hung() {
        assert!(started.elapsed() < Duration::from_secs(60), "thread A never reached the engine");
        std::thread::sleep(Duration::from_millis(1));
    }
    let arm = shake128s_signature();
    assert_eq!(arm, expected, "contended caller: ARM result");
    assert!(f.accel.stats().contended.load(Ordering::Relaxed) > contended0);
    f.sim.finish_hung();
    assert_eq!(holder.join().unwrap(), expected, "engine holder: same bytes");
}

#[test]
fn engine_errors_fall_back_with_identical_output_and_recover() {
    let (_g, f) = fixture();
    f.accel.set_enabled(false);
    let expected = shake128s_signature();
    f.accel.set_enabled(true);
    let sk = shake128s_key();

    for fault in [
        Fault::Status(Status::InternalError),
        Fault::StaleCompletion,
        Fault::Status(Status::UnsupportedParameterSet),
    ] {
        let errors0 = f.accel.stats().errors.load(Ordering::Relaxed);
        f.sim.inject(fault);
        assert_eq!(sign_with(&sk), expected, "{fault:?}");
        assert_eq!(f.accel.stats().errors.load(Ordering::Relaxed), errors0 + 1, "{fault:?}");
        // The next call recovers a degraded engine (RESET_CORE + known answer).
        let sign0 = f.sim.executed(Command::SlhSign);
        f.accel.reset_recovery_backoff();
        assert_eq!(sign_with(&sk), expected);
        assert_eq!(f.sim.executed(Command::SlhSign), sign0 + 1, "{fault:?}: engine back in service");
    }

    // A silently corrupted signature fails the ARM check against PK.root:
    // it is never released and the CPU signs instead.
    let rejected0 = f.accel.stats().rejected_outputs.load(Ordering::Relaxed);
    f.sim.inject(Fault::CorruptPayload);
    assert_eq!(sign_with(&sk), expected);
    assert_eq!(f.accel.stats().rejected_outputs.load(Ordering::Relaxed), rejected0 + 1);
    // Whatever the recovery back-off decides next, output stays identical.
    assert_eq!(sign_with(&sk), expected);
}

#[test]
fn a_corrupted_keygen_root_is_never_used() {
    use fips205::traits::SerDes;
    let (_g, f) = fixture();
    f.accel.set_enabled(false);
    let expected = shake128s_key().into_bytes();
    f.accel.set_enabled(true);
    // One of the two SLH_KEYGEN runs returns a flipped root: the roots
    // disagree, the root is computed on ARM, the key is the right one.
    let rejected0 = f.accel.stats().rejected_outputs.load(Ordering::Relaxed);
    let keygen0 = f.sim.executed(Command::SlhKeygen);
    f.sim.inject(Fault::CorruptPayload);
    assert_eq!(shake128s_key().into_bytes(), expected);
    assert_eq!(f.sim.executed(Command::SlhKeygen), keygen0 + 2);
    assert_eq!(f.accel.stats().rejected_outputs.load(Ordering::Relaxed), rejected0 + 1);
    // And a healthy engine's root is accepted.
    f.accel.reset_recovery_backoff();
    assert_eq!(shake128s_key().into_bytes(), expected);
}

#[test]
fn a_key_whose_root_does_not_match_fails_the_same_way_on_and_off() {
    use fips205::traits::{KeyGen, SerDes, Signer};
    let (_g, f) = fixture();
    let (_, sk) = fips205::slh_dsa_shake_128s::KG::keygen_with_seeds::<16>(&[1; 16], &[2; 16], &[3; 16]);
    let mut bytes = sk.into_bytes();
    bytes[63] ^= 1; // PK.root
    let bad = fips205::slh_dsa_shake_128s::PrivateKey::from_bytes_unchecked(&bytes);
    f.accel.set_enabled(false);
    assert!(bad.try_sign(b"m", b"", false).is_err());
    f.accel.set_enabled(true);
    let sign0 = f.sim.executed(Command::SlhSign);
    assert!(bad.try_sign(b"m", b"", false).is_err(), "no signature from a corrupted key");
    assert_eq!(f.sim.executed(Command::SlhSign), sign0 + 1, "the engine saw it and refused");
}

// ---------------------------------------------------------------------------
// LMS / HSS
// ---------------------------------------------------------------------------

struct LmsRun {
    vk: Vec<u8>,
    sk: Vec<u8>,
    signatures: Vec<Vec<u8>>,
    updated_keys: Vec<Vec<u8>>,
}

fn lms_run<H: hbs_lms::HashChain>(params: &[hbs_lms::HssParameter<H>]) -> LmsRun {
    let mut seed = hbs_lms::Seed::<H>::default();
    for (i, byte) in seed.as_mut_slice().iter_mut().enumerate() {
        *byte = 0x30 + i as u8;
    }
    let (sk, vk) = hbs_lms::keygen::<H>(params, &seed, None).unwrap();
    let mut key = sk.as_slice().to_vec();
    let mut signatures = Vec::new();
    let mut updated_keys = Vec::new();
    for message in [b"first".as_slice(), b"second", b"third"] {
        let mut updated = None;
        let mut update = |new_key: &[u8]| {
            updated = Some(new_key.to_vec());
            Ok(())
        };
        let signature = hbs_lms::sign::<H>(message, &key, &mut update, None).unwrap();
        let new_key = updated.expect("index persisted before the signature is returned");
        assert!(hbs_lms::verify::<H>(message, signature.as_ref(), vk.as_slice()).is_ok());
        signatures.push(signature.as_ref().to_vec());
        updated_keys.push(new_key.clone());
        key = new_key;
    }
    LmsRun {
        vk: vk.as_slice().to_vec(),
        sk: sk.as_slice().to_vec(),
        signatures,
        updated_keys,
    }
}

fn check_lms<H: hbs_lms::HashChain>(fixture: &Fixture, label: &str, params: &[hbs_lms::HssParameter<H>]) {
    let (sim, accel) = (&fixture.sim, fixture.accel);
    accel.set_enabled(false);
    let merkle0 = sim.executed(Command::MerkleSubtree);
    let off = lms_run(params);
    assert_eq!(sim.executed(Command::MerkleSubtree), merkle0, "{label}: hook off");
    accel.set_enabled(true);
    let on = lms_run(params);
    assert!(sim.executed(Command::MerkleSubtree) > merkle0, "{label}: engine used");
    assert_eq!(on.vk, off.vk, "{label}: public key");
    assert_eq!(on.sk, off.sk, "{label}: private key");
    assert_eq!(on.signatures, off.signatures, "{label}: signatures");
    assert_eq!(on.updated_keys, off.updated_keys, "{label}: persisted key states");
    assert!(sim.dma_is_zero());
}

#[test]
fn lms_every_family_is_byte_identical() {
    use hbs_lms::{HssParameter, LmotsAlgorithm as W, LmsAlgorithm as T};
    use hbs_lms::{Sha256_192, Sha256_256, Shake256_192, Shake256_256};
    let (_g, f) = fixture();
    check_lms(f, "SHAKE256/M32 H5/W4", &[HssParameter::<Shake256_256>::new(W::LmotsW4, T::LmsH5)]);
    check_lms(f, "SHAKE256/M24 H5/W8", &[HssParameter::<Shake256_192>::new(W::LmotsW8, T::LmsH5)]);
    check_lms(f, "SHA-256/M32 H5/W2", &[HssParameter::<Sha256_256>::new(W::LmotsW2, T::LmsH5)]);
    check_lms(f, "SHA-256/M24 H5/W1", &[HssParameter::<Sha256_192>::new(W::LmotsW1, T::LmsH5)]);
}

#[test]
fn lms_tall_tree_and_hss_are_byte_identical() {
    use hbs_lms::{HssParameter, LmotsAlgorithm as W, LmsAlgorithm as T, Shake256_256};
    let (_g, f) = fixture();
    // H10 > the claimed maximum subtree (8): the root and top levels are
    // hashed on ARM from engine-computed height-8 subtrees.
    check_lms(f, "SHAKE256/M32 H10/W4", &[HssParameter::<Shake256_256>::new(W::LmotsW4, T::LmsH10)]);
    check_lms(
        f,
        "HSS SHAKE256/M32 H5/W8 + H5/W4",
        &[
            HssParameter::<Shake256_256>::new(W::LmotsW8, T::LmsH5),
            HssParameter::<Shake256_256>::new(W::LmotsW4, T::LmsH5),
        ],
    );
}

#[test]
fn lms_sha256_follows_the_routing_policy() {
    use hbs_lms::{HssParameter, LmotsAlgorithm as W, LmsAlgorithm as T, Sha256_256, Shake256_256};
    let (_g, f) = fixture();
    f.accel.set_routing(Routing::default());
    let merkle0 = f.sim.executed(Command::MerkleSubtree);
    let _ = lms_run(&[HssParameter::<Sha256_256>::new(W::LmotsW4, T::LmsH5)]);
    assert_eq!(f.sim.executed(Command::MerkleSubtree), merkle0, "SHA-256 → CPU by default");
    let _ = lms_run(&[HssParameter::<Shake256_256>::new(W::LmotsW4, T::LmsH5)]);
    assert!(f.sim.executed(Command::MerkleSubtree) > merkle0, "SHAKE256 → engine by default");
}

#[test]
fn engine_path_never_releases_a_signature_whose_index_was_not_persisted() {
    use softhsmrustv3::crypto::lms::{hss_keygen, hss_sign, hss_verify};
    let (_g, f) = fixture();
    let lms_type = 0x0F; // SHAKE256/M32 H5
    let (public, private) = hss_keygen(1, &[lms_type], &[0x0B]).unwrap();
    let merkle0 = f.sim.executed(Command::MerkleSubtree);

    // Persisting the reserved index fails: no signature is returned.
    let mut refuse = |_: &[u8]| Err(());
    assert!(hss_sign(lms_type, &private, b"m", &mut refuse).is_err());
    assert!(f.sim.executed(Command::MerkleSubtree) > merkle0, "the tree work ran on the engine");

    // Persisting succeeds: exactly one update, before the signature exists
    // for the caller, and the signature verifies.
    let mut updates = Vec::new();
    let mut persist = |key: &[u8]| {
        updates.push(key.to_vec());
        Ok(())
    };
    let signature = hss_sign(lms_type, &private, b"m", &mut persist).unwrap();
    assert_eq!(updates.len(), 1);
    assert_ne!(updates[0], private, "the persisted key has advanced its index");
    assert!(hss_verify(&public, b"m", &signature, lms_type));
}

#[test]
fn every_command_leaves_the_engine_scrubbed() {
    let (_g, f) = fixture();
    let zeroizations0 = f.sim.caps().zeroizations;
    let _ = shake128s_signature();
    assert!(f.sim.caps().zeroizations > zeroizations0);
    assert!(f.sim.dma_is_zero());
    assert_eq!(f.sim.starts_while_busy(), 0);
}

// ---------------------------------------------------------------------------
// XMSS / XMSS^MT
// ---------------------------------------------------------------------------

struct XmssRun {
    vk: Vec<u8>,
    sk: Vec<u8>,
    signatures: Vec<Vec<u8>>,
    updated_keys: Vec<Vec<u8>>,
}

/// `mt_oid`: the RFC 8391 XMSS^MT OID. xmss 0.1.0-pre.0 serialises it bare,
/// and re-parsing then picks the single-tree OID of the same number; the
/// engine's xmss_bridge rewrites the prefix to the crate's internal XMSS^MT
/// encoding (0x0001_0000 | oid) and so does this test.
fn xmss_run<P: xmss::XmssParameter>(signatures: usize, mt_oid: Option<u32>) -> XmssRun {
    let seed: Vec<u8> = (0..P::SEED_LEN).map(|i| 0x20 + i as u8).collect();
    let mut pair = xmss::KeyPair::<P>::from_seed(&seed).unwrap();
    let mut vk = pair.verifying_key().as_ref().to_vec();
    let mut sk = pair.signing_key().as_ref().to_vec();
    if let Some(oid) = mt_oid {
        let internal = (0x0001_0000u32 | oid).to_be_bytes();
        vk[..4].copy_from_slice(&internal);
        sk[..4].copy_from_slice(&internal);
    }
    let verifier = xmss::VerifyingKey::<P>::try_from(vk.as_slice()).unwrap();
    let mut key = sk.clone();
    let mut run = XmssRun { vk, sk, signatures: Vec::new(), updated_keys: Vec::new() };
    for i in 0..signatures {
        let message = [b'x', i as u8];
        let mut signer = xmss::SigningKey::<P>::try_from(key.as_slice()).unwrap();
        let signature = signer.sign_detached(&message).unwrap();
        verifier.verify_detached(&signature, &message).unwrap();
        key = signer.as_ref().to_vec();
        run.signatures.push(signature.as_ref().to_vec());
        run.updated_keys.push(key.clone());
    }
    run
}

fn check_xmss<P: xmss::XmssParameter>(
    fixture: &Fixture,
    label: &str,
    signatures: usize,
    mt_oid: Option<u32>,
    claimed: bool,
) {
    let (sim, accel) = (&fixture.sim, fixture.accel);
    accel.set_enabled(false);
    let merkle0 = sim.executed(Command::MerkleSubtree);
    let off = xmss_run::<P>(signatures, mt_oid);
    assert_eq!(sim.executed(Command::MerkleSubtree), merkle0, "{label}: hook off");
    accel.set_enabled(true);
    let on = xmss_run::<P>(signatures, mt_oid);
    if claimed {
        assert!(sim.executed(Command::MerkleSubtree) > merkle0, "{label}: engine used");
    } else {
        assert_eq!(sim.executed(Command::MerkleSubtree), merkle0, "{label}: not claimed, ARM");
    }
    assert_eq!(on.vk, off.vk, "{label}: public key");
    assert_eq!(on.sk, off.sk, "{label}: private key");
    assert_eq!(on.signatures, off.signatures, "{label}: signatures");
    assert_eq!(on.updated_keys, off.updated_keys, "{label}: persisted key states");
    assert!(sim.dma_is_zero());
}

#[test]
fn xmss_every_claimed_family_is_byte_identical() {
    let (_g, f) = fixture();
    check_xmss::<xmss::XmssShake_10_256>(f, "XMSS-SHAKE_10_256 (SHAKE128 n32)", 2, None, true);
    check_xmss::<xmss::XmssShake256_10_192>(f, "XMSS-SHAKE256_10_192", 2, None, true);
    check_xmss::<xmss::XmssSha2_10_256>(f, "XMSS-SHA2_10_256", 2, None, true);
    check_xmss::<xmss::XmssSha2_10_192>(f, "XMSS-SHA2_10_192", 1, None, true);
    check_xmss::<xmss::XmssShake256_10_256>(f, "XMSS-SHAKE256_10_256", 1, None, true);
}

#[test]
fn xmssmt_layers_are_byte_identical() {
    let (_g, f) = fixture();
    // d = 4 trees of height 5 and d = 2 trees of height 10: every layer's
    // tree (with its layer and tree address) goes to the engine.
    check_xmss::<xmss::XmssMtShake_20_4_256>(f, "XMSS^MT-SHAKE_20/4_256", 3, Some(0x12), true);
    check_xmss::<xmss::XmssMtShake256_20_2_192>(f, "XMSS^MT-SHAKE256_20/2_192", 2, Some(0x31), true);
}

#[test]
fn xmss_unclaimed_heights_and_n64_stay_on_arm() {
    use pqc_hw::hashsig_device::abi::xmss_param_set;
    let (_g, f) = fixture();
    // n = 64 is never claimed in v1.
    check_xmss::<xmss::XmssMtShake_20_4_512>(f, "XMSS^MT-SHAKE_20/4_512", 1, Some(0x1a), false);
    // h/d = 16 or 20 is above the claimed whole-tree height (building one on
    // ARM here would take minutes, so only the routing decision is checked).
    assert!(!f.accel.wants(Command::MerkleSubtree, xmss_param_set(0x08), 16)); // XMSS-SHAKE_16_256
    assert!(!f.accel.wants(Command::MerkleSubtree, xmss_param_set(0x0001_0016), 20)); // ^MT 60/3
    assert!(f.accel.wants(Command::MerkleSubtree, xmss_param_set(0x07), 10)); // XMSS-SHAKE_10_256
}
