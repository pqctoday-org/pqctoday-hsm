//! The ML-DSA-65 signer-lane driver against the lane simulator.

use pqc_hw::mldsa_sign::WaitMode;
use pqc_hw::mldsa_sign_lane::{
    SignDma, SignLane, INPUT_OFFSET, MATRIX_COEFFICIENTS, S1_COEFFICIENTS, S2_COEFFICIENTS,
    SECRET_BYTES, SIGNATURE_BYTES, T0_COEFFICIENTS,
};
use pqc_hw::mldsa_sign_sim::{Fault, FnBackend, SignJob, SimLane, SimTiming};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use std::time::Duration;

const PHYS: u64 = 0x7000_0000;
const TIMEOUT: Duration = Duration::from_millis(250);

/// A deterministic stand-in for the fabric: the "signature" is SHAKE256 of
/// everything the signer read, and the attempt count is taken from it.
fn digest_backend(job: &SignJob<'_>) -> Result<(Vec<u8>, u32), i32> {
    let mut shake = sha3::Shake256::default();
    shake.update(job.matrix);
    shake.update(job.secrets);
    let mut signature = vec![0u8; SIGNATURE_BYTES];
    shake.finalize_xof().read(&mut signature);
    Ok((signature.clone(), u32::from(signature[0] % 7) + 1))
}

fn expected(matrix: &[i32], s1: &[i32], s2: &[i32], t0: &[i32], mu: &[u8; 64], rho: &[u8; 64]) -> Vec<u8> {
    let le = |v: &[i32]| v.iter().flat_map(|c| c.to_le_bytes()).collect::<Vec<u8>>();
    let mut secrets = le(s1);
    secrets.extend(le(s2));
    secrets.extend(le(t0));
    secrets.extend_from_slice(mu);
    secrets.extend_from_slice(rho);
    let matrix = le(matrix);
    digest_backend(&SignJob { matrix: &matrix, secrets: &secrets, randomized: true, attempt_limit: 128 })
        .unwrap()
        .0
}

type Inputs = (Vec<i32>, Vec<i32>, Vec<i32>, Vec<i32>, [u8; 64], [u8; 64]);

fn inputs(seed: i32) -> Inputs {
    let poly = |n: usize, k: i32| (0..n as i32).map(|i| i.wrapping_mul(31).wrapping_add(k)).collect();
    (
        poly(MATRIX_COEFFICIENTS, seed),
        poly(S1_COEFFICIENTS, seed + 1),
        poly(S2_COEFFICIENTS, seed + 2),
        poly(T0_COEFFICIENTS, seed + 3),
        [seed as u8; 64],
        [seed as u8 ^ 0x5a; 64],
    )
}

fn lane(sim: &SimLane, mode: WaitMode) -> SignLane<pqc_hw::mldsa_sign_sim::SimRegisters, pqc_hw::mldsa_sign_sim::SimDma> {
    SignLane::new(sim.parts(mode)).unwrap()
}

fn sim(timing: SimTiming) -> SimLane {
    SimLane::new(1 << 20, PHYS, Box::new(FnBackend(digest_backend)), timing)
}

#[test]
fn signs_through_every_wait_mode_with_identical_output() {
    let (a, s1, s2, t0, mu, rho) = inputs(3);
    let want = expected(&a, &s1, &s2, &t0, &mu, &rho);
    let timing = SimTiming {
        sign_base: Duration::from_micros(200),
        sign_per_attempt: Duration::from_micros(50),
        dma_phase: Duration::from_micros(20),
        ..SimTiming::default()
    };
    for mode in [WaitMode::Spin, WaitMode::Sleep, WaitMode::Interrupt] {
        let sim = sim(timing);
        let mut lane = lane(&sim, mode);
        for _ in 0..3 {
            let got = lane.sign(&a, &s1, &s2, &t0, &mu, &rho, true, 128, TIMEOUT).unwrap();
            assert_eq!(got, want, "{mode:?}");
        }
        let counters = sim.counters();
        assert_eq!(counters.loads, 1, "matrix uploaded once for one key ({mode:?})");
        assert_eq!(counters.signs, 3);
        assert_eq!(lane.stats().signs, 3);
        assert_eq!(lane.stats().attempts, counters.attempts);
        assert!(sim.banks_scrubbed(), "secret and signature banks scrubbed after publish");
        // The hardware clears the staged secrets from DDR after DISPATCH.
        let staged = &lane.dma().bytes()[INPUT_OFFSET..INPUT_OFFSET + SECRET_BYTES];
        assert!(staged.iter().all(|b| *b == 0), "input region cleared ({mode:?})");
        if mode != WaitMode::Spin {
            // A sleeping or interrupt-driven wait polls the control register
            // a handful of times, not thousands.
            assert!(
                lane.stats().register_polls < 200,
                "{mode:?}: {} polls",
                lane.stats().register_polls
            );
        }
    }
}

#[test]
fn a_new_matrix_reloads_the_context_and_signs_with_it() {
    let sim = sim(SimTiming::default());
    let mut lane = lane(&sim, WaitMode::Spin);
    let (a, s1, s2, t0, mu, rho) = inputs(5);
    let (b, ..) = inputs(9);
    lane.sign(&a, &s1, &s2, &t0, &mu, &rho, false, 128, TIMEOUT).unwrap();
    let got = lane.sign(&b, &s1, &s2, &t0, &mu, &rho, false, 128, TIMEOUT).unwrap();
    assert_eq!(got, expected(&b, &s1, &s2, &t0, &mu, &rho));
    assert_eq!(sim.counters().loads, 2);
}

#[test]
fn faults_fail_the_operation_and_never_return_a_signature() {
    let (a, s1, s2, t0, mu, rho) = inputs(7);

    let sim_a = sim(SimTiming::default());
    let mut lane_a = lane(&sim_a, WaitMode::Sleep);
    sim_a.inject(Fault::SignStatus(-4));
    assert!(lane_a.sign(&a, &s1, &s2, &t0, &mu, &rho, true, 128, TIMEOUT).is_err());
    // A signer error is not a transport failure: the lane keeps working.
    assert!(lane_a.sign(&a, &s1, &s2, &t0, &mu, &rho, true, 128, TIMEOUT).is_ok());

    let sim_b = sim(SimTiming::default());
    let mut lane_b = lane(&sim_b, WaitMode::Interrupt);
    lane_b.sign(&a, &s1, &s2, &t0, &mu, &rho, true, 128, TIMEOUT).unwrap();
    sim_b.inject(Fault::StaleCompletion);
    let error = lane_b.sign(&a, &s1, &s2, &t0, &mu, &rho, true, 128, TIMEOUT).unwrap_err();
    assert!(error.to_string().contains("stale"), "{error}");

    let sim_c = sim(SimTiming::default());
    let mut lane_c = lane(&sim_c, WaitMode::Sleep);
    sim_c.inject(Fault::HangSign);
    let error = lane_c
        .sign(&a, &s1, &s2, &t0, &mu, &rho, true, 128, Duration::from_millis(5))
        .unwrap_err();
    assert!(error.to_string().contains("Timeout"), "{error}");
}

#[test]
fn modelled_syncs_are_counted_with_their_ranges() {
    let sim = sim(SimTiming::default());
    let mut lane = lane(&sim, WaitMode::Spin);
    let (a, s1, s2, t0, mu, rho) = inputs(11);
    lane.sign(&a, &s1, &s2, &t0, &mu, &rho, true, 128, TIMEOUT).unwrap();
    let before = sim.counters();
    lane.sign(&a, &s1, &s2, &t0, &mu, &rho, true, 128, TIMEOUT).unwrap();
    let after = sim.counters();
    assert_eq!(after.syncs_for_device - before.syncs_for_device, 1);
    assert_eq!(after.syncs_for_cpu - before.syncs_for_cpu, 1);
    println!(
        "per sign: sync_for_device {} B, sync_for_cpu {} B",
        after.sync_bytes_for_device - before.sync_bytes_for_device,
        after.sync_bytes_for_cpu - before.sync_bytes_for_cpu
    );
}
