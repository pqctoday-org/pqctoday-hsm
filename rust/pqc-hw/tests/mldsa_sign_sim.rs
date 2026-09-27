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
    let mut spin_polls = 0;
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
        if mode == WaitMode::Spin {
            spin_polls = lane.stats().register_polls;
        } else {
            // A sleeping or interrupt-driven wait polls only during its first
            // SPIN_FIRST, then blocks: far fewer register reads than spinning
            // through the whole modelled signature.
            assert!(
                lane.stats().register_polls * 4 < spin_polls,
                "{mode:?}: {} polls vs {spin_polls} spinning",
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
    // Only the request, padding and secret input are cleaned for the
    // device; only the completion and signature are invalidated for the CPU.
    assert_eq!(
        after.sync_bytes_for_device - before.sync_bytes_for_device,
        pqc_hw::mldsa_sign_lane::SIGN_DEVICE_EXTENT as u64
    );
    assert_eq!(
        after.sync_bytes_for_cpu - before.sync_bytes_for_cpu,
        pqc_hw::mldsa_sign_lane::SIGN_OUTPUT_BYTES as u64
    );
    println!(
        "per sign: sync_for_device {} B, sync_for_cpu {} B",
        after.sync_bytes_for_device - before.sync_bytes_for_device,
        after.sync_bytes_for_cpu - before.sync_bytes_for_cpu
    );
}

#[test]
fn the_lane_reloads_only_when_the_matrix_id_changes() {
    use pqc_hw::mldsa_sign_lane::{SignInputs, SliceInputs};
    let sim = sim(SimTiming::default());
    let mut lane = lane(&sim, WaitMode::Spin);
    let (a, s1, s2, t0, mu, rho) = inputs(21);
    let (b, ..) = inputs(22);
    let input = |matrix: &'static [i32]| SliceInputs { matrix, s1: &s1, s2: &s2, t0: &t0, mu: &mu, rho_prime: &rho, randomized: true };
    let a: &'static [i32] = Box::leak(a.into_boxed_slice());
    let b: &'static [i32] = Box::leak(b.into_boxed_slice());
    let mut signature = vec![0u8; SIGNATURE_BYTES];
    for (matrix, loads) in [(a, 1), (a, 1), (b, 2), (b, 2), (a, 3)] {
        lane.sign_into(&input(matrix), 128, TIMEOUT, &mut signature).unwrap();
        assert_eq!(signature, expected(matrix, &s1, &s2, &t0, &mu, &rho));
        assert_eq!(sim.counters().loads, loads);
        assert_eq!(lane.resident_matrix(), Some(input(matrix).matrix_id()));
    }
    // A wrong-sized output buffer is refused before anything is submitted.
    let signs = sim.counters().signs;
    assert!(lane.sign_into(&input(a), 128, TIMEOUT, &mut [0u8; 10]).is_err());
    assert_eq!(sim.counters().signs, signs);
}

/// An interrupt line that never fires (e.g. not wired in a bitstream).
struct DeadLine;

impl pqc_hw::mldsa_sign::Interrupt for DeadLine {
    fn drain(&mut self) -> std::io::Result<()> {
        Ok(())
    }
    fn unmask(&mut self) -> std::io::Result<()> {
        Ok(())
    }
    fn wait(&mut self, timeout: Duration) -> std::io::Result<bool> {
        std::thread::sleep(timeout);
        Ok(false)
    }
}

#[test]
fn a_line_that_never_fires_falls_back_to_sleep_polling() {
    let timing = SimTiming {
        sign_base: Duration::from_micros(300),
        dma_phase: Duration::from_micros(40),
        ..SimTiming::default()
    };
    let sim = sim(timing);
    let mut parts = sim.parts(WaitMode::Interrupt);
    parts.dma_interrupt = Some(Box::new(DeadLine));
    parts.signer_interrupt = Some(Box::new(DeadLine));
    let mut lane = SignLane::new(parts).unwrap();
    let (a, s1, s2, t0, mu, rho) = inputs(31);
    let want = expected(&a, &s1, &s2, &t0, &mu, &rho);
    for _ in 0..6 {
        assert_eq!(lane.sign(&a, &s1, &s2, &t0, &mu, &rho, true, 128, TIMEOUT).unwrap(), want);
    }
    assert_eq!(lane.wait_modes(), (WaitMode::Sleep, WaitMode::Sleep));
    assert!(lane.stats().signer_missed_interrupts >= 3);
    assert_eq!(lane.stats().signer_interrupts, 0);
}
