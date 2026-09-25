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
const GIE: usize = 0x04;
const IER: usize = 0x08;
const ISR: usize = 0x0c;
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
        self.start(phase, dma_words, dma_phys)?;
        wait_done(&mut self.registers, &mut Wait::spin(), timeout)
    }

    /// Writes the phase descriptor and sets `ap_start`; does not wait.
    pub fn start(&mut self, phase: u32, dma_words: u32, dma_phys: u64) -> Result<(), Error> {
        if dma_words < 16 || dma_phys == 0 || dma_phys & 63 != 0 {
            return Err(Error::InvalidAddress);
        }
        ensure_idle(&mut self.registers)?;
        self.registers.write32(DMA_PHASE, phase);
        self.registers.write32(DMA_WORD_COUNT, dma_words);
        write64(&mut self.registers, DMA_ADDRESS, dma_phys);
        self.registers.write32(CONTROL, AP_START);
        Ok(())
    }

    pub fn registers_mut(&mut self) -> &mut R {
        &mut self.registers
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
        self.start_load(tenant)?;
        wait_done(&mut self.registers, &mut Wait::spin(), timeout)
    }

    pub fn sign(&mut self, submission: SignSubmission, timeout: Duration) -> Result<i32, Error> {
        self.start_sign(submission)?;
        wait_done(&mut self.registers, &mut Wait::spin(), timeout)
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
        start(&mut self.registers)?;
        wait_done(&mut self.registers, &mut Wait::spin(), timeout)
    }

    /// Configures and starts a LOAD command; does not wait.
    pub fn start_load(&mut self, tenant: u32) -> Result<(), Error> {
        self.configure_common(COMMAND_LOAD, tenant, 0);
        self.registers.write32(SIGN_START_KAPPA, 0);
        self.registers.write32(SIGN_ATTEMPT_LIMIT, 0);
        start(&mut self.registers)
    }

    /// Configures and starts a SIGN command; does not wait.
    pub fn start_sign(&mut self, submission: SignSubmission) -> Result<(), Error> {
        self.configure_common(COMMAND_SIGN, submission.tenant, submission.generation);
        self.registers.write32(SIGN_START_KAPPA, 0);
        self.registers
            .write32(SIGN_ATTEMPT_LIMIT, u32::from(submission.attempt_limit));
        start(&mut self.registers)
    }

    pub fn registers_mut(&mut self) -> &mut R {
        &mut self.registers
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

fn start(registers: &mut impl RegisterIo) -> Result<(), Error> {
    ensure_idle(registers)?;
    registers.write32(CONTROL, AP_START);
    Ok(())
}

/// Interrupt line of one HLS block (a UIO device on Linux, or a simulator).
pub trait Interrupt: Send {
    /// Discards interrupt events that are already pending.
    fn drain(&mut self) -> std::io::Result<()>;
    /// Re-enables the line (UIO `irqcontrol`).
    fn unmask(&mut self) -> std::io::Result<()>;
    /// Blocks until an interrupt event arrives or `timeout` elapses.
    /// `Ok(true)` when an event was consumed.
    fn wait(&mut self, timeout: Duration) -> std::io::Result<bool>;
}

/// How a caller waits for `ap_done`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitMode {
    /// Busy-poll the control register: lowest latency, burns a core.
    Spin,
    /// Sleep between control-register polls.
    Sleep,
    /// Block on the block's interrupt; the control register stays the
    /// authority (an event only means "look now").
    Interrupt,
}

impl WaitMode {
    /// `PQC_HW_MLDSA_WAIT=spin|sleep|irq`; `None` when unset or unknown.
    pub fn from_env() -> Option<Self> {
        match std::env::var("PQC_HW_MLDSA_WAIT").ok()?.as_str() {
            "spin" => Some(Self::Spin),
            "sleep" => Some(Self::Sleep),
            "irq" | "interrupt" => Some(Self::Interrupt),
            _ => None,
        }
    }
}

/// Polling step of [`WaitMode::Sleep`], and the longest interval between
/// control-register checks in [`WaitMode::Interrupt`] (a lost interrupt
/// then costs at most this much latency, never a timeout).
pub const SLEEP_STEP: Duration = Duration::from_micros(100);
pub const INTERRUPT_SLICE: Duration = Duration::from_millis(1);

/// Per-block waiting state: the mode, the interrupt (if any), and the
/// shortest completion seen, which [`WaitMode::Sleep`] sleeps through first.
pub struct Wait {
    pub mode: WaitMode,
    pub interrupt: Option<Box<dyn Interrupt>>,
    shortest: Option<Duration>,
    /// Completions noticed by the control register although no interrupt
    /// arrived within [`INTERRUPT_SLICE`].
    pub missed_interrupts: u64,
    pub interrupts: u64,
    pub register_polls: u64,
}

impl Wait {
    pub fn spin() -> Self {
        Self::new(WaitMode::Spin, None)
    }

    pub fn new(mode: WaitMode, interrupt: Option<Box<dyn Interrupt>>) -> Self {
        let mode = if mode == WaitMode::Interrupt && interrupt.is_none() {
            WaitMode::Sleep
        } else {
            mode
        };
        Self {
            mode,
            interrupt,
            shortest: None,
            missed_interrupts: 0,
            interrupts: 0,
            register_polls: 0,
        }
    }

    /// Prepares the interrupt for the next command: acknowledge the block's
    /// ISR, drop stale events, re-enable the line. Call before `ap_start`.
    /// Falls back to [`WaitMode::Sleep`] if the line cannot be armed.
    pub fn arm(&mut self, registers: &mut impl RegisterIo) {
        if self.mode != WaitMode::Interrupt {
            return;
        }
        acknowledge_interrupt(registers);
        let armed = self
            .interrupt
            .as_mut()
            .is_some_and(|irq| irq.drain().is_ok() && irq.unmask().is_ok());
        if !armed {
            self.mode = WaitMode::Sleep;
        }
    }

    fn learn(&mut self, elapsed: Duration) {
        self.shortest = Some(self.shortest.map_or(elapsed, |s| s.min(elapsed)));
    }
}

/// Enables the block's `ap_done` interrupt output (GIE + IER bit 0).
pub fn enable_done_interrupt(registers: &mut impl RegisterIo) {
    acknowledge_interrupt(registers);
    registers.write32(IER, 1);
    registers.write32(GIE, 1);
}

/// Clears the toggle-on-write ISR bits that are set, deasserting the line.
pub fn acknowledge_interrupt(registers: &mut impl RegisterIo) {
    let pending = registers.read32(ISR) & 3;
    if pending != 0 {
        registers.write32(ISR, pending);
    }
}

/// Waits for `ap_done` after a start and returns the block's return value.
pub fn wait_done(
    registers: &mut impl RegisterIo,
    wait: &mut Wait,
    timeout: Duration,
) -> Result<i32, Error> {
    let started = Instant::now();
    let deadline = started + timeout;
    let mut first_sleep = true;
    loop {
        wait.register_polls += 1;
        if registers.read32(CONTROL) & AP_DONE != 0 {
            wait.learn(started.elapsed());
            if wait.mode == WaitMode::Interrupt {
                acknowledge_interrupt(registers);
            }
            return Ok(registers.read32(RETURN) as i32);
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(Error::Timeout);
        }
        match wait.mode {
            WaitMode::Spin => std::hint::spin_loop(),
            WaitMode::Sleep => {
                // Sleep through most of the shortest completion seen so far,
                // then poll at a fixed step.
                let step = if first_sleep {
                    first_sleep = false;
                    wait.shortest
                        .map_or(SLEEP_STEP, |s| s.mul_f32(0.9).max(SLEEP_STEP))
                        .saturating_sub(started.elapsed())
                        .max(Duration::from_micros(1))
                } else {
                    SLEEP_STEP
                };
                std::thread::sleep(step.min(deadline - now));
            }
            WaitMode::Interrupt => {
                let slice = INTERRUPT_SLICE.min(deadline - now);
                let irq = wait.interrupt.as_mut().expect("interrupt mode has a line");
                match irq.wait(slice) {
                    Ok(true) => wait.interrupts += 1,
                    Ok(false) => {
                        if registers.read32(CONTROL) & AP_DONE != 0 {
                            // Done without an event: count it, then treat it
                            // as the completion it is.
                            wait.missed_interrupts += 1;
                            wait.learn(started.elapsed());
                            acknowledge_interrupt(registers);
                            return Ok(registers.read32(RETURN) as i32);
                        }
                    }
                    Err(_) => wait.mode = WaitMode::Sleep,
                }
            }
        }
    }
}

fn write64(registers: &mut impl RegisterIo, offset: usize, value: u64) {
    registers.write32(offset, value as u32);
    registers.write32(offset + 4, (value >> 32) as u32);
}
