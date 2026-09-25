//! Whole-signature ML-DSA-65 accelerator, end to end against the lane
//! simulator.
//!
//! The simulator (`pqc_hw::mldsa_sign_sim`) models the ABI v2 register map,
//! DMA request/completion records, context binding and bank scrubbing; its
//! crypto backend is fips204's own rejection loop over exactly the bytes the
//! signer reads (`hw_accel::mldsa65_reference_backend`). Every signature
//! below therefore runs fips204 → sign hook → lane pool → ABI driver →
//! simulated registers and DMA → back, and is compared byte for byte with
//! the software path (hook off) or with the NIST ACVP vectors.
//!
//! Only built with `--features hw-accel` on linux/aarch64 (the `pqc-rust`
//! container).
#![cfg(all(feature = "hw-accel", target_os = "linux", target_arch = "aarch64"))]

use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes};
use pqc_hw::mldsa_sign::WaitMode;
use pqc_hw::mldsa_sign_sim::{Fault, SimCounters, SimLane, SimTiming};
use softhsmrustv3::crypto::handlers;
use softhsmrustv3::hw_accel;
use std::sync::{Mutex, MutexGuard, OnceLock};

const CKM_ML_DSA: u32 = 0x1d;
const CKM_HASH_ML_DSA_SHA256: u32 = 0x23;
const CKP_ML_DSA_65: u32 = 0x2;
const LANES: usize = 2;

struct Fixture {
    lanes: Vec<SimLane>,
}

impl Fixture {
    fn signs(&self) -> u64 {
        self.lanes.iter().map(|lane| lane.counters().signs).sum()
    }
    fn counters(&self, lane: usize) -> SimCounters {
        self.lanes[lane].counters()
    }
}

/// Installs two simulated lanes once per process; tests run one at a time
/// because they share them (and toggle the hook, and inject faults).
fn fixture() -> (MutexGuard<'static, ()>, &'static Fixture) {
    static SERIAL: Mutex<()> = Mutex::new(());
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    let guard = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
    let fixture = FIXTURE.get_or_init(|| {
        let lanes: Vec<SimLane> = (0..LANES)
            .map(|index| {
                SimLane::new(
                    1 << 20,
                    0x7000_0000 + ((index as u64) << 20),
                    hw_accel::mldsa65_reference_backend(),
                    SimTiming::default(),
                )
            })
            .collect();
        assert!(hw_accel::install_mldsa65_sim(lanes.clone(), WaitMode::Sleep));
        Fixture { lanes }
    });
    hw_accel::set_mldsa65_sign_enabled(true);
    (guard, fixture)
}

fn decode_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn key(seed: u8) -> Vec<u8> {
    let (_pk, sk) = ml_dsa_65::KG::keygen_from_seed(&[seed; 32]);
    sk.into_bytes().to_vec()
}

fn both_ways<T: PartialEq + std::fmt::Debug>(fixture: &Fixture, sign: impl Fn() -> T) -> T {
    hw_accel::set_mldsa65_sign_enabled(false);
    let before = fixture.signs();
    let software = sign();
    assert_eq!(fixture.signs(), before, "hook off must not reach the device");
    hw_accel::set_mldsa65_sign_enabled(true);
    let accelerated = sign();
    assert!(fixture.signs() > before, "hook on must reach the device");
    assert_eq!(accelerated, software, "accelerated output must be byte-identical");
    accelerated
}

#[test]
fn acvp_siggen_ml_dsa_65_vectors_pass_through_the_accelerator() {
    let (_guard, fixture) = fixture();
    let text = std::fs::read_to_string(
        "fips204-patched/tests/nist_vectors/ML-DSA-sigGen-FIPS204/internalProjection.json",
    )
    .expect("ACVP sigGen vectors");
    let vectors: serde_json::Value = serde_json::from_str(&text).unwrap();
    let before = fixture.signs();
    let mut checked = 0;
    for group in vectors["testGroups"].as_array().unwrap() {
        if group["parameterSet"] != "ML-DSA-65" {
            continue;
        }
        for test in group["tests"].as_array().unwrap() {
            let sk = decode_hex(test["sk"].as_str().unwrap());
            let message = decode_hex(test["message"].as_str().unwrap());
            let expected = decode_hex(test["signature"].as_str().unwrap());
            let rnd: [u8; 32] = test["rnd"]
                .as_str()
                .map_or([0u8; 32], |r| decode_hex(r).try_into().unwrap());
            let sk = ml_dsa_65::PrivateKey::try_from_bytes(sk.try_into().unwrap()).unwrap();
            #[allow(deprecated)]
            let signature = ml_dsa_65::_internal_sign(&sk, &message, &[], rnd).unwrap();
            assert_eq!(signature.to_vec(), expected, "tcId {}", test["tcId"]);
            checked += 1;
        }
    }
    assert_eq!(checked, 20, "both ML-DSA-65 groups (deterministic and hedged)");
    assert_eq!(
        fixture.signs() - before,
        checked,
        "every vector was signed by the (simulated) accelerator"
    );
}

#[test]
fn engine_signatures_are_identical_with_the_hook_on_and_off() {
    let (_guard, fixture) = fixture();
    for seed in 0..4u8 {
        let sk = key(seed);
        let message = format!("byte identity {seed}").into_bytes();
        // Deterministic ML-DSA and HashML-DSA through the PKCS#11 handler.
        both_ways(fixture, || {
            handlers::sign_ml_dsa(CKM_ML_DSA, CKP_ML_DSA_65, &sk, &message, b"ctx", true).unwrap()
        });
        both_ways(fixture, || {
            handlers::sign_ml_dsa(CKM_HASH_ML_DSA_SHA256, CKP_ML_DSA_65, &sk, &message, &[], true)
                .unwrap()
        });
        // Hedged ML-DSA with a fixed rnd.
        both_ways(fixture, || {
            handlers::sign_ml_dsa_external_rnd(CKP_ML_DSA_65, &sk, &message, &[], [seed ^ 0xa5; 32])
                .unwrap()
        });
    }
}

#[test]
fn concurrent_signers_share_both_lanes_and_stay_byte_identical() {
    let (_guard, fixture) = fixture();
    let keys: Vec<Vec<u8>> = (10..16).map(key).collect();
    hw_accel::set_mldsa65_sign_enabled(false);
    let expected: Vec<Vec<u8>> = keys
        .iter()
        .map(|sk| handlers::sign_ml_dsa(CKM_ML_DSA, CKP_ML_DSA_65, sk, b"concurrent", &[], true).unwrap())
        .collect();
    hw_accel::set_mldsa65_sign_enabled(true);
    let before: Vec<u64> = (0..LANES).map(|lane| fixture.counters(lane).signs).collect();
    std::thread::scope(|scope| {
        for (sk, want) in keys.iter().zip(&expected) {
            scope.spawn(move || {
                for _ in 0..8 {
                    let got = handlers::sign_ml_dsa(CKM_ML_DSA, CKP_ML_DSA_65, sk, b"concurrent", &[], true)
                        .unwrap();
                    assert_eq!(&got, want);
                }
            });
        }
    });
    let used: Vec<u64> = (0..LANES).map(|lane| fixture.counters(lane).signs - before[lane]).collect();
    assert!(used.iter().all(|n| *n > 0), "both lanes signed: {used:?}");
}

#[test]
fn device_failures_fall_back_to_identical_software_signatures() {
    let (_guard, fixture) = fixture();
    let sk = key(42);
    let reference = {
        hw_accel::set_mldsa65_sign_enabled(false);
        let r = handlers::sign_ml_dsa(CKM_ML_DSA, CKP_ML_DSA_65, &sk, b"fallback", &[], true).unwrap();
        hw_accel::set_mldsa65_sign_enabled(true);
        r
    };
    for fault in [Fault::SignStatus(-4), Fault::StaleCompletion, Fault::HangSign] {
        for lane in &fixture.lanes {
            lane.inject(fault);
        }
        let got = handlers::sign_ml_dsa(CKM_ML_DSA, CKP_ML_DSA_65, &sk, b"fallback", &[], true).unwrap();
        assert_eq!(got, reference, "{fault:?}: the software fallback signs identically");
        let pending: usize = fixture.lanes.iter().map(SimLane::pending_faults).sum();
        assert!(pending < LANES, "{fault:?} was actually hit by the device path");
        // Drop faults the operation did not consume; finish hung commands.
        for lane in &fixture.lanes {
            lane.clear_faults();
            lane.release_hang();
        }
    }
    // The pool recovers: a failed lane is reopened and signs again.
    let before = fixture.signs();
    for _ in 0..4 {
        let got = handlers::sign_ml_dsa(CKM_ML_DSA, CKP_ML_DSA_65, &sk, b"fallback", &[], true).unwrap();
        assert_eq!(got, reference);
    }
    assert!(fixture.signs() > before, "lanes are back in service after faults");
}

#[test]
fn alternating_keys_use_the_right_matrix_and_prefer_the_lane_that_holds_it() {
    let (_guard, fixture) = fixture();
    let keys: Vec<Vec<u8>> = (30..33).map(key).collect();
    hw_accel::set_mldsa65_sign_enabled(false);
    let expected: Vec<Vec<u8>> = keys
        .iter()
        .map(|sk| handlers::sign_ml_dsa(CKM_ML_DSA, CKP_ML_DSA_65, sk, b"alternate", &[], true).unwrap())
        .collect();
    hw_accel::set_mldsa65_sign_enabled(true);
    let loads = || fixture.lanes.iter().map(|l| l.counters().loads).sum::<u64>();
    // Three keys over two lanes, one caller: every switch of key on a lane
    // must reload that lane's matrix (a stale matrix would sign wrongly).
    for round in 0..4 {
        for (sk, want) in keys.iter().zip(&expected) {
            let got = handlers::sign_ml_dsa(CKM_ML_DSA, CKP_ML_DSA_65, sk, b"alternate", &[], true).unwrap();
            assert_eq!(&got, want, "round {round}");
        }
    }
    // Two keys over two lanes: after one upload each, affinity keeps each
    // key on the lane that holds its matrix.
    let (a, b) = (&keys[0], &keys[1]);
    let _ = handlers::sign_ml_dsa(CKM_ML_DSA, CKP_ML_DSA_65, a, b"warm", &[], true).unwrap();
    let _ = handlers::sign_ml_dsa(CKM_ML_DSA, CKP_ML_DSA_65, b, b"warm", &[], true).unwrap();
    let before = loads();
    for _ in 0..10 {
        let got = handlers::sign_ml_dsa(CKM_ML_DSA, CKP_ML_DSA_65, a, b"alternate", &[], true).unwrap();
        assert_eq!(got, expected[0]);
        let got = handlers::sign_ml_dsa(CKM_ML_DSA, CKP_ML_DSA_65, b, b"alternate", &[], true).unwrap();
        assert_eq!(got, expected[1]);
    }
    assert_eq!(loads(), before, "no matrix upload once each key has a lane");
}
