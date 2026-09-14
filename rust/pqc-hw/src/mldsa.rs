//! Register-level contract for the resident ML-DSA-65 matrix/vector engine.

use crate::keccak::RegisterIo;
use std::fmt;
use std::time::{Duration, Instant};

pub const MLDSA65_CONTROL_BASE: u64 = 0xa001_0000;
pub const CONTROL: usize = 0x00;
pub const GIER: usize = 0x04;
pub const IP_IER: usize = 0x08;
pub const IP_ISR: usize = 0x0c;
pub const RETURN: usize = 0x10;
pub const MATRIX_HAT: usize = 0x18;
pub const VECTOR: usize = 0x24;
pub const OUTPUT: usize = 0x30;

const AP_START: u32 = 1 << 0;
const AP_DONE: u32 = 1 << 1;
const AP_IDLE: u32 = 1 << 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Submission {
    pub matrix_hat_phys: u64,
    pub vector_phys: u64,
    pub output_phys: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    Busy,
    Timeout,
    Hardware(i32),
    InvalidAddress,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}

pub struct Engine<R> {
    registers: R,
}

impl<R: RegisterIo> Engine<R> {
    pub fn new(registers: R) -> Self {
        Self { registers }
    }

    pub fn into_inner(self) -> R {
        self.registers
    }

    pub fn submit_polling(
        &mut self,
        submission: Submission,
        timeout: Duration,
    ) -> Result<(), Error> {
        if [
            submission.matrix_hat_phys,
            submission.vector_phys,
            submission.output_phys,
        ]
        .into_iter()
        .any(|address| address == 0 || address & 63 != 0)
        {
            return Err(Error::InvalidAddress);
        }
        if self.registers.read32(CONTROL) & AP_IDLE == 0 {
            return Err(Error::Busy);
        }
        self.write64(MATRIX_HAT, submission.matrix_hat_phys);
        self.write64(VECTOR, submission.vector_phys);
        self.write64(OUTPUT, submission.output_phys);
        self.registers.write32(CONTROL, AP_START);
        let deadline = Instant::now() + timeout;
        loop {
            if self.registers.read32(CONTROL) & AP_DONE != 0 {
                let status = self.registers.read32(RETURN) as i32;
                return if status == 0 {
                    Ok(())
                } else {
                    Err(Error::Hardware(status))
                };
            }
            if Instant::now() >= deadline {
                return Err(Error::Timeout);
            }
            std::hint::spin_loop();
        }
    }

    pub fn enable_completion_interrupt(&mut self) {
        self.registers.write32(GIER, 1);
        self.registers.write32(IP_IER, 1);
    }

    pub fn acknowledge_interrupt(&mut self) {
        self.registers.write32(IP_ISR, 1);
    }

    fn write64(&mut self, offset: usize, value: u64) {
        self.registers.write32(offset, value as u32);
        self.registers.write32(offset + 4, (value >> 32) as u32);
    }
}
