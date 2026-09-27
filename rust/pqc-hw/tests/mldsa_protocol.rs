use pqc_hw::keccak::RegisterIo;
use pqc_hw::mldsa::{CONTROL, Engine, Error, MATRIX_HAT, OUTPUT, RETURN, Submission, VECTOR};
use std::collections::BTreeMap;
use std::time::Duration;

struct Registers {
    values: BTreeMap<usize, u32>,
    writes: Vec<(usize, u32)>,
    complete: bool,
}

impl Registers {
    fn new(complete: bool) -> Self {
        Self {
            values: BTreeMap::new(),
            writes: Vec::new(),
            complete,
        }
    }
}

impl RegisterIo for Registers {
    fn read32(&mut self, offset: usize) -> u32 {
        if offset == CONTROL {
            if self.writes.is_empty() {
                return 1 << 2;
            }
            if self.complete {
                return (1 << 1) | (1 << 2);
            }
        }
        *self.values.get(&offset).unwrap_or(&0)
    }

    fn write32(&mut self, offset: usize, value: u32) {
        self.writes.push((offset, value));
        self.values.insert(offset, value);
    }
}

fn submission() -> Submission {
    Submission {
        matrix_hat_phys: 0x7000_0000,
        vector_phys: 0x7000_7800,
        output_phys: 0x7000_8c00,
    }
}

#[test]
fn writes_three_64_bit_addresses_and_completes() {
    let mut engine = Engine::new(Registers::new(true));
    engine
        .submit_polling(submission(), Duration::from_millis(10))
        .unwrap();
    let registers = engine.into_inner();
    for (offset, low) in [
        (MATRIX_HAT, 0x7000_0000),
        (VECTOR, 0x7000_7800),
        (OUTPUT, 0x7000_8c00),
    ] {
        assert!(registers.writes.contains(&(offset, low)));
        assert!(registers.writes.contains(&(offset + 4, 0)));
    }
}

#[test]
fn rejects_zero_and_misaligned_addresses() {
    for bad_address in [0, 0x7000_0004] {
        let mut bad = submission();
        bad.vector_phys = bad_address;
        let mut engine = Engine::new(Registers::new(true));
        assert_eq!(
            engine.submit_polling(bad, Duration::from_millis(1)),
            Err(Error::InvalidAddress)
        );
    }
}

#[test]
fn propagates_hardware_error_and_timeout() {
    let mut failed = Registers::new(true);
    failed.values.insert(RETURN, (-2_i32) as u32);
    let mut engine = Engine::new(failed);
    assert_eq!(
        engine.submit_polling(submission(), Duration::from_millis(1)),
        Err(Error::Hardware(-2))
    );

    let mut engine = Engine::new(Registers::new(false));
    assert_eq!(
        engine.submit_polling(submission(), Duration::ZERO),
        Err(Error::Timeout)
    );
}
