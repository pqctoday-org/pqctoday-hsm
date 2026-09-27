use pqc_hw::keccak::{COUNT, Engine, Error, INPUT, JOBS, OUTPUT, Submission};
use pqc_hw::sim::SimulatedKeccak;
use std::time::Duration;

fn submission() -> Submission {
    Submission {
        jobs_phys: 0x1_2345_6000,
        count: 2,
        input_phys: 0x2_0000_1000,
        input_capacity: 512,
        output_phys: 0x2_0000_4000,
        output_capacity: 1024,
    }
}
#[test]
fn writes_64_bit_addresses_and_completes() {
    let mut engine = Engine::new(SimulatedKeccak::success());
    engine
        .submit_polling(submission(), Duration::from_millis(10))
        .unwrap();
    let sim = engine.into_inner();
    assert!(sim.writes.contains(&(JOBS, 0x2345_6000)));
    assert!(sim.writes.contains(&(JOBS + 4, 1)));
    assert!(sim.writes.contains(&(COUNT, 2)));
    assert!(sim.writes.contains(&(INPUT, 0x0000_1000)));
    assert!(sim.writes.contains(&(OUTPUT, 0x0000_4000)));
}
#[test]
fn propagates_hardware_error() {
    let mut engine = Engine::new(SimulatedKeccak::error(-2));
    assert_eq!(
        engine.submit_polling(submission(), Duration::from_millis(10)),
        Err(Error::Hardware(-2))
    );
}
#[test]
fn times_out_and_rejects_invalid_submission() {
    let mut engine = Engine::new(SimulatedKeccak::never_completes());
    assert_eq!(
        engine.submit_polling(submission(), Duration::ZERO),
        Err(Error::Timeout)
    );
    let mut engine = Engine::new(SimulatedKeccak::success());
    let mut bad = submission();
    bad.jobs_phys = 0;
    assert_eq!(
        engine.submit_polling(bad, Duration::from_millis(1)),
        Err(Error::InvalidAddress)
    );
}
