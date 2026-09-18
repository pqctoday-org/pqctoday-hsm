//! Register protocol for the split ML-DSA-65 DMA and resident signer design.

use crate::keccak::RegisterIo;
use std::fmt;
use std::time::{Duration, Instant};

pub const MAILBOX_BASE: u64 = 0xa000_0000;
pub const SIGNATURE_BASE: u64 = 0xa000_2000;
pub const DMA_CONTROL_BASE: u64 = 0xa001_0000;
pub const SIGNER_CONTROL_BASE: u64 = 0xa002_0000;
pub const MATRIX_BASE: u64 = 0xc000_0000;
pub const SECRET_BASE: u64 = 0xc000_0000;

const CONTROL: usize = 0x00;
const RETURN: usize = 0x10;
const AP_START: u32 = 1;
const AP_DONE: u32 = 2;
const AP_IDLE: u32 = 4;

const DMA_PHASE: usize = 0x18;
const DMA_WORD_COUNT: usize = 0x20;
const DMA_ADDRESS: usize = 0x28;

const SIGN_COMMAND: usize = 0x18;
const SIGN_MATRIX: usize = 0x20;
const SIGN_TENANT: usize = 0x2c;
const SIGN_GENERATION: usize = 0x34;
const SIGN_RHO_PRIME: usize = 0x3c;
const SIGN_MU: usize = 0x48;
const SIGN_START_KAPPA: usize = 0x54;
const SIGN_ATTEMPT_LIMIT: usize = 0x5c;
const SIGN_S1: usize = 0x64;
const SIGN_S2: usize = 0x70;
const SIGN_T0: usize = 0x7c;
const SIGN_SIGNATURE: usize = 0x88;
const SIGN_DIAGNOSTICS: usize = 0x94;
const SIGN_CONTEXT_INFO: usize = 0xa0;

pub const PHASE_DISPATCH: u32 = 0;
pub const PHASE_PUBLISH: u32 = 1;
pub const PHASE_ABORT: u32 = 2;
pub const PHASE_RESET: u32 = 3;

pub const COMMAND_LOAD: u32 = 1;
pub const COMMAND_SIGN: u32 = 2;
pub const COMMAND_INVALIDATE: u32 = 3;

pub const SECRET_S1_OFFSET: u64 = 0;
pub const SECRET_S2_OFFSET: u64 = 5 * 256 * 4;
pub const SECRET_T0_OFFSET: u64 = (5 + 6) * 256 * 4;
pub const SECRET_MU_OFFSET: u64 = 17 * 256 * 4;
pub const SECRET_RHO_PRIME_OFFSET: u64 = SECRET_MU_OFFSET + 64;
pub const DIAGNOSTICS_OFFSET: u64 = 36 * 4;
pub const CONTEXT_INFO_OFFSET: u64 = 46 * 4;

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

pub struct DmaController<R> {
    registers: R,
}

impl<R: RegisterIo> DmaController<R> {
    pub fn new(registers: R) -> Self {
        Self { registers }
    }

    pub fn into_inner(self) -> R {
        self.registers
    }

    pub fn run(
        &mut self,
        phase: u32,
        dma_words: u32,
        dma_phys: u64,
        timeout: Duration,
    ) -> Result<i32, Error> {
        if dma_words < 16 || dma_phys == 0 || dma_phys & 63 != 0 {
            return Err(Error::InvalidAddress);
        }
        ensure_idle(&mut self.registers)?;
        self.registers.write32(DMA_PHASE, phase);
        self.registers.write32(DMA_WORD_COUNT, dma_words);
        write64(&mut self.registers, DMA_ADDRESS, dma_phys);
        start_and_wait(&mut self.registers, timeout)
    }
}

pub struct Signer<R> {
    registers: R,
    mailbox_base: u64,
    signature_base: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct SignSubmission {
    pub tenant: u32,
    pub generation: u32,
    pub attempt_limit: u16,
}

impl<R: RegisterIo> Signer<R> {
    pub fn new(registers: R) -> Self {
        Self::new_with_memory_map(registers, MAILBOX_BASE, SIGNATURE_BASE)
    }

    pub fn new_with_memory_map(registers: R, mailbox_base: u64, signature_base: u64) -> Self {
        Self {
            registers,
            mailbox_base,
            signature_base,
        }
    }

    pub fn into_inner(self) -> R {
        self.registers
    }

    pub fn load(&mut self, tenant: u32, timeout: Duration) -> Result<i32, Error> {
        self.configure_common(COMMAND_LOAD, tenant, 0);
        self.registers.write32(SIGN_START_KAPPA, 0);
        self.registers.write32(SIGN_ATTEMPT_LIMIT, 0);
        start_and_wait(&mut self.registers, timeout)
    }

    pub fn sign(&mut self, submission: SignSubmission, timeout: Duration) -> Result<i32, Error> {
        self.configure_common(COMMAND_SIGN, submission.tenant, submission.generation);
        self.registers.write32(SIGN_START_KAPPA, 0);
        self.registers
            .write32(SIGN_ATTEMPT_LIMIT, u32::from(submission.attempt_limit));
        start_and_wait(&mut self.registers, timeout)
    }

    pub fn invalidate(
        &mut self,
        tenant: u32,
        generation: u32,
        timeout: Duration,
    ) -> Result<i32, Error> {
        self.configure_common(COMMAND_INVALIDATE, tenant, generation);
        self.registers.write32(SIGN_START_KAPPA, 0);
        self.registers.write32(SIGN_ATTEMPT_LIMIT, 0);
        start_and_wait(&mut self.registers, timeout)
    }

    fn configure_common(&mut self, command: u32, tenant: u32, generation: u32) {
        self.registers.write32(SIGN_COMMAND, command);
        write64(&mut self.registers, SIGN_MATRIX, MATRIX_BASE);
        self.registers.write32(SIGN_TENANT, tenant);
        self.registers.write32(SIGN_GENERATION, generation);
        write64(
            &mut self.registers,
            SIGN_RHO_PRIME,
            SECRET_BASE + SECRET_RHO_PRIME_OFFSET,
        );
        write64(&mut self.registers, SIGN_MU, SECRET_BASE + SECRET_MU_OFFSET);
        write64(&mut self.registers, SIGN_S1, SECRET_BASE + SECRET_S1_OFFSET);
        write64(&mut self.registers, SIGN_S2, SECRET_BASE + SECRET_S2_OFFSET);
        write64(&mut self.registers, SIGN_T0, SECRET_BASE + SECRET_T0_OFFSET);
        write64(&mut self.registers, SIGN_SIGNATURE, self.signature_base);
        write64(
            &mut self.registers,
            SIGN_DIAGNOSTICS,
            self.mailbox_base + DIAGNOSTICS_OFFSET,
        );
        write64(
            &mut self.registers,
            SIGN_CONTEXT_INFO,
            self.mailbox_base + CONTEXT_INFO_OFFSET,
        );
    }
}

fn ensure_idle(registers: &mut impl RegisterIo) -> Result<(), Error> {
    if registers.read32(CONTROL) & AP_IDLE == 0 {
        Err(Error::Busy)
    } else {
        Ok(())
    }
}

fn start_and_wait(registers: &mut impl RegisterIo, timeout: Duration) -> Result<i32, Error> {
    ensure_idle(registers)?;
    registers.write32(CONTROL, AP_START);
    let deadline = Instant::now() + timeout;
    loop {
        if registers.read32(CONTROL) & AP_DONE != 0 {
            return Ok(registers.read32(RETURN) as i32);
        }
        if Instant::now() >= deadline {
            return Err(Error::Timeout);
        }
        std::hint::spin_loop();
    }
}

fn write64(registers: &mut impl RegisterIo, offset: usize, value: u64) {
    registers.write32(offset, value as u32);
    registers.write32(offset + 4, (value >> 32) as u32);
}
