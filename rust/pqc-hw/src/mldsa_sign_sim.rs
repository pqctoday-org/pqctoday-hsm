//! Simulator of one whole-signature ML-DSA-65 signer lane (ABI v2).
//!
//! It models what the driver can observe, following the HLS sources in
//! pqctoday-cacp `fpga/ntt` (`mldsa65_dma_controller.cpp`, the signer's
//! AXI-Lite map and `SIGN_LOOP_ABI.md`):
//!
//! * three register windows (DMA controller, signer, mailbox) with
//!   `ap_start`/`ap_done` (clear-on-read)/`ap_idle`, GIE/IER and a
//!   toggle-on-write ISR;
//! * DISPATCH: request validation, output-region clear, secret or matrix
//!   copy into the lane's banks, input-region clear after a SIGN;
//! * LOAD/SIGN: generation binding; the signature comes from a
//!   [`SignBackend`];
//! * PUBLISH: completion record + signature written to the output region,
//!   banks scrubbed; ABORT.
//!
//! Timing is modelled, not measured: each command completes `latency` after
//! its start (the control register reads "busy" until then), and every cache
//! sync can be charged a busy-wait cost. Both are configured by the caller
//! ([`SimTiming`]), so a host-path profile can run the real driver against a
//! chosen FPGA latency. The cryptography itself costs the calling thread
//! nothing in the model backend ([`ModelBackend`]); the reference backend
//! computes real signatures for byte-identity tests.

use crate::keccak::RegisterIo;
use crate::mldsa_sign::{Interrupt, WaitMode};
use crate::mldsa_sign_lane::{
    LaneParts, SignDma, ABI_VERSION, COMMAND_LOAD, COMMAND_SIGN, COMPLETION_BYTES,
    COMPLETION_MAGIC, MATRIX_BYTES, REQUEST_BYTES, REQUEST_MAGIC, SECRET_BYTES,
    SIGNATURE_BYTES, SIGN_DETERMINISTIC, SIGN_OUTPUT_BYTES, SIGN_RANDOMIZED,
};
use std::cell::UnsafeCell;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

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
const SIGN_COMMAND: usize = 0x18;
const SIGN_GENERATION: usize = 0x34;
const SIGN_ATTEMPT_LIMIT: usize = 0x5c;

const STATUS_BAD_DESCRIPTOR: i32 = -1;
const STATUS_STALE_CONTEXT: i32 = -2;
const STATUS_ATTEMPT_LIMIT: i32 = -4;
const STATUS_TIMEOUT: i32 = -6;

const MB_STATE: usize = 0;
const MB_SIGNER_STATUS: usize = 11;
const STATE_IDLE: u32 = 0;
const STATE_READY: u32 = 1;
const STATE_RESULT: u32 = 2;

/// Everything the signer reads for one SIGN: the resident matrix bank and
/// the staged secret input, as the little-endian bytes the DMA copied.
pub struct SignJob<'a> {
    pub matrix: &'a [u8],
    /// s1 ‖ s2 ‖ t0 ‖ mu ‖ rho' (`SECRET_BYTES`).
    pub secrets: &'a [u8],
    pub randomized: bool,
    pub attempt_limit: u32,
}

/// The computation the fabric performs.
pub trait SignBackend: Send + Sync {
    /// Returns the encoded signature and the number of rejection-loop
    /// attempts it took, or a signer status.
    fn sign(&self, job: &SignJob<'_>) -> Result<(Vec<u8>, u32), i32>;
}

/// Reference backend: a closure computing the real rejection loop (the
/// engine crate plugs in fips204's software loop).
pub struct FnBackend<F>(pub F);

impl<F> SignBackend for FnBackend<F>
where
    F: Fn(&SignJob<'_>) -> Result<(Vec<u8>, u32), i32> + Send + Sync,
{
    fn sign(&self, job: &SignJob<'_>) -> Result<(Vec<u8>, u32), i32> {
        (self.0)(job)
    }
}

/// Throughput-model backend: no cryptography. The signature is zero bytes
/// (the caller does not verify it) and the attempt count is drawn from a
/// geometric distribution with the given mean, as ML-DSA's rejection loop
/// is (each attempt is accepted independently with probability 1/mean).
pub struct ModelBackend {
    mean_attempts: f64,
    state: AtomicU64,
}

impl ModelBackend {
    pub fn new(mean_attempts: f64, seed: u64) -> Self {
        Self {
            mean_attempts: mean_attempts.max(1.0),
            state: AtomicU64::new(seed | 1),
        }
    }

    fn uniform(&self) -> f64 {
        // xorshift64*, shared by the lanes; quality is irrelevant here.
        let mut x = self.state.load(Ordering::Relaxed);
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state.store(x, Ordering::Relaxed);
        (x.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 11) as f64 / (1u64 << 53) as f64
    }
}

impl SignBackend for ModelBackend {
    fn sign(&self, _job: &SignJob<'_>) -> Result<(Vec<u8>, u32), i32> {
        let p = 1.0 / self.mean_attempts;
        let u = self.uniform().max(f64::MIN_POSITIVE);
        let attempts = if p >= 1.0 {
            1
        } else {
            (u.ln() / (1.0 - p).ln()).floor() as u32 + 1
        };
        Ok((vec![0u8; SIGNATURE_BYTES], attempts))
    }
}

/// Modelled timing, in the caller's time base.
#[derive(Clone, Copy, Debug, Default)]
pub struct SimTiming {
    /// Signer SIGN latency: `sign_base + attempts * sign_per_attempt`.
    pub sign_base: Duration,
    pub sign_per_attempt: Duration,
    /// Signer LOAD latency.
    pub load: Duration,
    /// DMA DISPATCH and PUBLISH latency each.
    pub dma_phase: Duration,
    /// CPU cost charged (busy-wait) per cache-sync call, plus per 64-byte line.
    pub sync_call: Duration,
    pub sync_per_line: Duration,
}

/// Faults a test can inject into the next signer command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fault {
    /// The next SIGN never completes.
    HangSign,
    /// The next SIGN reports this status.
    SignStatus(i32),
    /// The next PUBLISH writes a completion with the wrong request id.
    StaleCompletion,
}

/// Counters a test or profile reads back.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SimCounters {
    pub dispatches: u64,
    pub publishes: u64,
    pub loads: u64,
    pub signs: u64,
    pub aborts: u64,
    pub syncs_for_device: u64,
    pub sync_bytes_for_device: u64,
    pub syncs_for_cpu: u64,
    pub sync_bytes_for_cpu: u64,
    pub control_reads: u64,
    pub attempts: u64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Block {
    Dma,
    Signer,
    Mailbox,
}

struct BlockRegs {
    values: [u32; 64],
    running: bool,
    ready_at: Option<Instant>,
    never: bool,
    done_latched: bool,
    gie: u32,
    ier: u32,
    isr: u32,
}

impl Default for BlockRegs {
    fn default() -> Self {
        Self {
            values: [0; 64],
            running: false,
            ready_at: None,
            never: false,
            done_latched: false,
            gie: 0,
            ier: 0,
            isr: 0,
        }
    }
}

struct State {
    dma: BlockRegs,
    signer: BlockRegs,
    mailbox: [u32; 48],
    matrix_bank: Vec<u8>,
    secret_bank: Vec<u8>,
    signature_bank: Vec<u8>,
    attempts: u32,
    context_valid: bool,
    generation: u32,
    active_generation: u32,
    request: [u32; 16],
    backend: Box<dyn SignBackend>,
    timing: SimTiming,
    faults: Vec<Fault>,
    counters: SimCounters,
}

/// DMA memory shared by the driver and the device model, like the real
/// u-dma-buf allocation. The device model touches it only inside a register
/// write made by the lane's owner (a DMA `ap_start`), when the driver holds
/// no borrow of it: the lane's `&mut self` methods end every slice borrow
/// before they start the DMA controller.
struct SharedMem {
    bytes: UnsafeCell<Box<[u8]>>,
}

unsafe impl Send for SharedMem {}
unsafe impl Sync for SharedMem {}

/// Handle on one simulated lane; clone freely.
#[derive(Clone)]
pub struct SimLane {
    state: Arc<Mutex<State>>,
    memory: Arc<SharedMem>,
    phys: u64,
}

impl SimLane {
    pub fn new(dma_bytes: usize, phys: u64, backend: Box<dyn SignBackend>, timing: SimTiming) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                dma: BlockRegs::default(),
                signer: BlockRegs::default(),
                mailbox: [0; 48],
                matrix_bank: vec![0; MATRIX_BYTES],
                secret_bank: vec![0; SECRET_BYTES],
                signature_bank: vec![0; SIGNATURE_BYTES],
                attempts: 0,
                context_valid: false,
                generation: 0,
                active_generation: 0,
                request: [0; 16],
                backend,
                timing,
                faults: Vec::new(),
                counters: SimCounters::default(),
            })),
            memory: Arc::new(SharedMem {
                bytes: UnsafeCell::new(vec![0u8; dma_bytes].into_boxed_slice()),
            }),
            phys,
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn counters(&self) -> SimCounters {
        self.lock().counters
    }

    pub fn set_timing(&self, timing: SimTiming) {
        self.lock().timing = timing;
    }

    pub fn inject(&self, fault: Fault) {
        self.lock().faults.push(fault);
    }

    /// Faults injected and not yet consumed by a command.
    pub fn pending_faults(&self) -> usize {
        self.lock().faults.len()
    }

    /// Drops faults that no command has consumed yet.
    pub fn clear_faults(&self) {
        self.lock().faults.clear();
    }

    /// Lets a hung signer command finish now (as a fabric reset would).
    pub fn release_hang(&self) {
        let mut state = self.lock();
        if state.signer.never {
            state.signer.never = false;
            state.signer.ready_at = Some(Instant::now());
        }
    }

    /// True when the secret bank and signature bank are all zero.
    pub fn banks_scrubbed(&self) -> bool {
        let state = self.lock();
        state.secret_bank.iter().all(|b| *b == 0) && state.signature_bank.iter().all(|b| *b == 0)
    }

    /// The lane's register windows, DMA memory and interrupt lines, ready
    /// for [`crate::mldsa_sign_lane::SignLane::new`].
    pub fn parts(&self, wait_mode: WaitMode) -> LaneParts<SimRegisters, SimDma> {
        LaneParts {
            dma_control: SimRegisters { lane: self.clone(), block: Block::Dma },
            signer_control: SimRegisters { lane: self.clone(), block: Block::Signer },
            mailbox: SimRegisters { lane: self.clone(), block: Block::Mailbox },
            dma: SimDma { lane: self.clone() },
            mailbox_base: crate::mldsa_sign::MAILBOX_BASE,
            signature_base: crate::mldsa_sign::SIGNATURE_BASE,
            dma_interrupt: Some(Box::new(SimInterrupt { lane: self.clone(), block: Block::Dma })),
            signer_interrupt: Some(Box::new(SimInterrupt { lane: self.clone(), block: Block::Signer })),
            wait_mode,
        }
    }

    #[allow(clippy::mut_from_ref)]
    fn memory(&self) -> &mut [u8] {
        // See `SharedMem`: only called by the device model from inside a
        // register write, or by `SimDma` through `&self`/`&mut self`.
        unsafe { &mut *self.memory.bytes.get() }
    }
}

fn read_word(memory: &[u8], index: usize) -> u32 {
    u32::from_le_bytes(memory[index * 4..index * 4 + 4].try_into().unwrap())
}

fn write_word(memory: &mut [u8], offset: usize, value: u32) {
    memory[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn busy_wait(duration: Duration) {
    if duration.is_zero() {
        return;
    }
    let until = Instant::now() + duration;
    while Instant::now() < until {
        std::hint::spin_loop();
    }
}

impl State {
    fn block(&mut self, block: Block) -> &mut BlockRegs {
        match block {
            Block::Dma => &mut self.dma,
            Block::Signer => &mut self.signer,
            Block::Mailbox => unreachable!("mailbox has no control block"),
        }
    }

    fn complete_after(&mut self, block: Block, latency: Duration, result: i32) {
        let regs = self.block(block);
        regs.values[RETURN / 4] = result as u32;
        regs.running = true;
        regs.never = false;
        regs.ready_at = Some(Instant::now() + latency);
    }

    fn dma_start(&mut self, memory: &mut [u8]) {
        let phase = self.dma.values[DMA_PHASE / 4];
        let words = self.dma.values[DMA_WORD_COUNT / 4] as usize;
        let latency = self.timing.dma_phase;
        let result = match phase {
            0 => self.dispatch(memory, words * 4),
            1 => self.publish(memory),
            2 => {
                self.counters.aborts += 1;
                self.scrub_banks();
                self.context_valid = false;
                self.mailbox[MB_STATE] = STATE_IDLE;
                STATUS_TIMEOUT
            }
            3 => {
                self.scrub_banks();
                self.mailbox = [0; 48];
                0
            }
            _ => STATUS_BAD_DESCRIPTOR,
        };
        self.complete_after(Block::Dma, latency, result);
    }

    fn dispatch(&mut self, memory: &mut [u8], dma_bytes: usize) -> i32 {
        self.counters.dispatches += 1;
        if self.mailbox[MB_STATE] != STATE_IDLE {
            return STATUS_BAD_DESCRIPTOR;
        }
        let r: [u32; 16] = core::array::from_fn(|i| read_word(memory, i));
        let (command, flags, input_offset, input_len, output_offset, output_len) =
            (r[3], r[4], r[9] as usize, r[10] as usize, r[11] as usize, r[12] as usize);
        let valid = r[0] == REQUEST_MAGIC
            && r[1] == u32::from(ABI_VERSION) | ((REQUEST_BYTES as u32) << 16)
            && r[2] == REQUEST_BYTES as u32
            && (r[6] != 0 || r[7] != 0)
            && r[14] != 0
            && input_offset >= REQUEST_BYTES
            && input_offset % 64 == 0
            && output_offset % 64 == 0
            && input_offset + input_len <= dma_bytes
            && output_offset + output_len <= dma_bytes
            && output_len >= COMPLETION_BYTES
            && (input_offset + input_len <= output_offset || output_offset + output_len <= input_offset)
            && match command {
                COMMAND_LOAD => input_len == MATRIX_BYTES && flags == 0,
                COMMAND_SIGN => {
                    input_len == SECRET_BYTES
                        && (flags == SIGN_DETERMINISTIC || flags == SIGN_RANDOMIZED)
                        && output_len >= SIGN_OUTPUT_BYTES
                        && r[8] != 0
                        && r[13] != 0
                }
                _ => false,
            };
        if !valid {
            return STATUS_BAD_DESCRIPTOR;
        }
        self.request = r;
        let clear = if command == COMMAND_SIGN { SIGN_OUTPUT_BYTES } else { COMPLETION_BYTES };
        memory[output_offset..output_offset + clear].fill(0);
        if command == COMMAND_SIGN {
            if !self.context_valid || r[8] != self.active_generation {
                memory[input_offset..input_offset + input_len].fill(0);
                self.write_completion(memory, STATUS_STALE_CONTEXT, 0);
                return STATUS_STALE_CONTEXT;
            }
            self.secret_bank
                .copy_from_slice(&memory[input_offset..input_offset + SECRET_BYTES]);
            memory[input_offset..input_offset + input_len].fill(0);
        } else {
            self.matrix_bank
                .copy_from_slice(&memory[input_offset..input_offset + MATRIX_BYTES]);
        }
        self.mailbox[MB_STATE] = STATE_READY;
        1
    }

    fn signer_start(&mut self) {
        let command = self.signer.values[SIGN_COMMAND / 4];
        let generation = self.signer.values[SIGN_GENERATION / 4];
        let limit = self.signer.values[SIGN_ATTEMPT_LIMIT / 4];
        match command {
            1 => {
                self.counters.loads += 1;
                self.generation = self.generation.wrapping_add(1).max(1);
                let latency = self.timing.load;
                self.complete_after(Block::Signer, latency, 0);
            }
            2 => {
                self.counters.signs += 1;
                if let Some(index) = self.faults.iter().position(|f| *f == Fault::HangSign) {
                    self.faults.remove(index);
                    self.signer.running = true;
                    self.signer.never = true;
                    self.signer.ready_at = None;
                    return;
                }
                let forced = self.faults.iter().position(|f| matches!(f, Fault::SignStatus(_)));
                let (status, attempts) = if let Some(index) = forced {
                    let Fault::SignStatus(status) = self.faults.remove(index) else {
                        unreachable!()
                    };
                    (status, 0)
                } else if generation != self.generation || generation == 0 {
                    (STATUS_STALE_CONTEXT, 0)
                } else {
                    let job = SignJob {
                        matrix: &self.matrix_bank,
                        secrets: &self.secret_bank,
                        randomized: self.request[4] == SIGN_RANDOMIZED,
                        attempt_limit: limit,
                    };
                    match self.backend.sign(&job) {
                        Ok((signature, attempts)) if attempts <= limit => {
                            self.signature_bank.copy_from_slice(&signature);
                            (0, attempts)
                        }
                        Ok(_) => (STATUS_ATTEMPT_LIMIT, limit),
                        Err(status) => (status, 0),
                    }
                };
                self.attempts = attempts;
                self.counters.attempts += u64::from(attempts);
                let latency = self.timing.sign_base
                    + self.timing.sign_per_attempt * attempts.max(1);
                self.complete_after(Block::Signer, latency, status);
            }
            _ => self.complete_after(Block::Signer, Duration::ZERO, STATUS_BAD_DESCRIPTOR),
        }
    }

    fn publish(&mut self, memory: &mut [u8]) -> i32 {
        self.counters.publishes += 1;
        if self.mailbox[MB_STATE] != STATE_RESULT {
            return STATUS_BAD_DESCRIPTOR;
        }
        let command = self.request[3];
        let mut status = self.mailbox[MB_SIGNER_STATUS] as i32;
        let mut output_bytes = 0;
        if command == COMMAND_LOAD {
            if status == 0 {
                self.context_valid = true;
                self.active_generation = self.generation;
            } else {
                self.context_valid = false;
            }
        } else if command == COMMAND_SIGN {
            if status == 0 {
                if self.attempts == 0 || self.attempts > self.request[13] {
                    status = STATUS_ATTEMPT_LIMIT;
                } else {
                    let base = self.request[11] as usize + COMPLETION_BYTES;
                    memory[base..base + SIGNATURE_BYTES].copy_from_slice(&self.signature_bank);
                    output_bytes = SIGNATURE_BYTES as u32;
                }
            }
            self.scrub_banks();
        }
        self.write_completion(memory, status, output_bytes);
        self.mailbox[MB_STATE] = STATE_IDLE;
        status
    }

    fn write_completion(&mut self, memory: &mut [u8], status: i32, output_bytes: u32) {
        let base = self.request[11] as usize;
        let mut request_id = (self.request[6], self.request[7]);
        if let Some(index) = self.faults.iter().position(|f| *f == Fault::StaleCompletion) {
            self.faults.remove(index);
            request_id.0 = request_id.0.wrapping_add(1);
        }
        let generation = if self.request[3] == COMMAND_LOAD { self.generation } else { self.active_generation };
        let words = [
            COMPLETION_MAGIC,
            u32::from(ABI_VERSION) | ((COMPLETION_BYTES as u32) << 16),
            status as u32,
            0,
            request_id.0,
            request_id.1,
            0,
            generation,
            self.attempts,
            0,
            output_bytes,
        ];
        memory[base..base + COMPLETION_BYTES].fill(0);
        for (index, word) in words.into_iter().enumerate() {
            write_word(memory, base + index * 4, word);
        }
    }

    fn scrub_banks(&mut self) {
        self.secret_bank.fill(0);
        self.signature_bank.fill(0);
    }
}

/// One register window of a simulated lane.
pub struct SimRegisters {
    lane: SimLane,
    block: Block,
}

impl RegisterIo for SimRegisters {
    fn read32(&mut self, offset: usize) -> u32 {
        let mut state = self.lane.lock();
        if self.block == Block::Mailbox {
            return state.mailbox[offset / 4];
        }
        let block = self.block;
        if offset == CONTROL {
            state.counters.control_reads += 1;
        }
        let regs = state.block(block);
        let finished = regs.running
            && !regs.never
            && regs.ready_at.is_some_and(|at| Instant::now() >= at);
        if finished {
            regs.running = false;
            regs.done_latched = true;
            if regs.ier & 1 != 0 {
                regs.isr |= 1;
            }
        }
        match offset {
            CONTROL => {
                if regs.running {
                    0
                } else if regs.done_latched {
                    regs.done_latched = false; // clear-on-read
                    AP_DONE | AP_IDLE
                } else {
                    AP_IDLE
                }
            }
            GIE => regs.gie,
            IER => regs.ier,
            ISR => regs.isr,
            _ => regs.values[offset / 4],
        }
    }

    fn write32(&mut self, offset: usize, value: u32) {
        let mut state = self.lane.lock();
        if self.block == Block::Mailbox {
            state.mailbox[offset / 4] = value;
            return;
        }
        let block = self.block;
        match offset {
            CONTROL if value & AP_START != 0 => {
                if state.block(block).running {
                    return; // ap_start is ignored while busy
                }
                match block {
                    Block::Dma => {
                        let memory = self.lane.memory();
                        state.dma_start(memory);
                    }
                    Block::Signer => state.signer_start(),
                    Block::Mailbox => unreachable!(),
                }
            }
            GIE => state.block(block).gie = value & 1,
            IER => state.block(block).ier = value & 3,
            ISR => state.block(block).isr ^= value & 3,
            _ => state.block(block).values[offset / 4] = value,
        }
    }
}

/// The simulated DMA buffer. Syncs are charged the modelled CPU cost.
pub struct SimDma {
    lane: SimLane,
}

impl SimDma {
    fn charge(&self, len: usize, for_device: bool) {
        let timing = {
            let mut state = self.lane.lock();
            if for_device {
                state.counters.syncs_for_device += 1;
                state.counters.sync_bytes_for_device += len as u64;
            } else {
                state.counters.syncs_for_cpu += 1;
                state.counters.sync_bytes_for_cpu += len as u64;
            }
            state.timing
        };
        busy_wait(timing.sync_call + timing.sync_per_line * len.div_ceil(64) as u32);
    }
}

impl SignDma for SimDma {
    fn len(&self) -> usize {
        self.lane.memory().len()
    }
    fn phys_addr(&self) -> u64 {
        self.lane.phys
    }
    fn bytes(&self) -> &[u8] {
        self.lane.memory()
    }
    fn bytes_mut(&mut self) -> &mut [u8] {
        self.lane.memory()
    }
    fn sync_for_device(&mut self, offset: usize, len: usize) -> io::Result<()> {
        if len == 0 || offset + len > self.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "sync range"));
        }
        self.charge(len, true);
        Ok(())
    }
    fn sync_for_cpu(&mut self, offset: usize, len: usize) -> io::Result<()> {
        if len == 0 || offset + len > self.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "sync range"));
        }
        self.charge(len, false);
        Ok(())
    }
    fn clear(&mut self) -> io::Result<()> {
        self.lane.memory().fill(0);
        Ok(())
    }
}

/// A simulated interrupt line: `wait` sleeps until the block's modelled
/// completion, like a real interrupt wake-up.
pub struct SimInterrupt {
    lane: SimLane,
    block: Block,
}

impl Interrupt for SimInterrupt {
    fn drain(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn unmask(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn wait(&mut self, timeout: Duration) -> io::Result<bool> {
        let ready_at = {
            let mut state = self.lane.lock();
            let regs = state.block(self.block);
            if regs.running && !regs.never {
                regs.ready_at
            } else if regs.done_latched || !regs.running {
                Some(Instant::now())
            } else {
                None
            }
        };
        let now = Instant::now();
        match ready_at {
            Some(at) if at <= now + timeout => {
                if at > now {
                    std::thread::sleep(at - now);
                }
                Ok(true)
            }
            _ => {
                std::thread::sleep(timeout);
                Ok(false)
            }
        }
    }
}
