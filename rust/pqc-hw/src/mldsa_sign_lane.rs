//! Transport-independent driver for one whole-signature ML-DSA-65 signer
//! lane (pqctoday-cacp `fpga/ntt/SIGN_LOOP_ABI.md`, ABI v2).
//!
//! A lane is three register windows (DMA controller, signer, mailbox) and
//! one DMA buffer. [`SignLane`] is generic over both, so the same protocol
//! code runs against the Linux UIO/u-dma-buf mappings
//! ([`crate::mldsa_sign_device`]) and the simulator
//! ([`crate::mldsa_sign_sim`]).

use crate::keccak::RegisterIo;
use crate::mldsa_sign::{
    enable_done_interrupt, wait_done, DmaController, SignSubmission, Signer, Wait, WaitMode,
    PHASE_ABORT, PHASE_DISPATCH, PHASE_PUBLISH,
};
use crate::stage::{self, Stage};
use std::io;
use std::time::Duration;

pub const MATRIX_COEFFICIENTS: usize = 6 * 5 * 256;
pub const S1_COEFFICIENTS: usize = 5 * 256;
pub const S2_COEFFICIENTS: usize = 6 * 256;
pub const T0_COEFFICIENTS: usize = 6 * 256;
pub const MATRIX_BYTES: usize = MATRIX_COEFFICIENTS * 4;
pub const SECRET_POLY_BYTES: usize = (S1_COEFFICIENTS + S2_COEFFICIENTS + T0_COEFFICIENTS) * 4;
pub const SECRET_BYTES: usize = SECRET_POLY_BYTES + 128;
pub const SIGNATURE_BYTES: usize = 3309;
pub const COMPLETION_BYTES: usize = 128;

pub const REQUEST_MAGIC: u32 = 0x3244_534d;
pub const COMPLETION_MAGIC: u32 = 0x3243_444d;
pub const ABI_VERSION: u16 = 2;
pub const REQUEST_BYTES: usize = 64;
pub const INPUT_OFFSET: usize = 0x100;
pub const OUTPUT_OFFSET: usize = 0x8000;
pub const SIGN_OUTPUT_BYTES: usize = COMPLETION_BYTES + SIGNATURE_BYTES;
pub const TENANT: u32 = 0x5051_4354;
pub const COMMAND_LOAD: u32 = 1;
pub const COMMAND_SIGN: u32 = 2;
pub const SIGN_DETERMINISTIC: u32 = 1;
pub const SIGN_RANDOMIZED: u32 = 2;
const STATE_RESULT: u32 = 2;
const MB_STATE: usize = 0;
const MB_SIGNER_STATUS: usize = 11 * 4;

/// The DMA buffer shared with one lane. The KV260 u-dma-buf is not
/// `dma-coherent`, so every hand-over is bracketed by cache maintenance.
pub trait SignDma {
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn phys_addr(&self) -> u64;
    fn bytes(&self) -> &[u8];
    fn bytes_mut(&mut self) -> &mut [u8];
    fn sync_for_device(&mut self, offset: usize, len: usize) -> io::Result<()>;
    fn sync_for_cpu(&mut self, offset: usize, len: usize) -> io::Result<()>;
    /// Zero the whole buffer and make the zeroes device-visible.
    fn clear(&mut self) -> io::Result<()>;
}

#[cfg(unix)]
impl SignDma for crate::dma::Buffer {
    fn len(&self) -> usize {
        crate::dma::Buffer::len(self)
    }
    fn phys_addr(&self) -> u64 {
        crate::dma::Buffer::phys_addr(self)
    }
    fn bytes(&self) -> &[u8] {
        self.as_slice()
    }
    fn bytes_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
    fn sync_for_device(&mut self, offset: usize, len: usize) -> io::Result<()> {
        self.sync_range_for_device(offset, len)
    }
    fn sync_for_cpu(&mut self, offset: usize, len: usize) -> io::Result<()> {
        self.sync_range_for_cpu(offset, len)
    }
    fn clear(&mut self) -> io::Result<()> {
        crate::dma::Buffer::clear(self)
    }
}

/// The lane's register windows and memory map.
pub struct LaneParts<R, D> {
    pub dma_control: R,
    pub signer_control: R,
    pub mailbox: R,
    pub dma: D,
    pub mailbox_base: u64,
    pub signature_base: u64,
    /// Interrupt lines of the DMA controller and the signer, if wired.
    pub dma_interrupt: Option<Box<dyn crate::mldsa_sign::Interrupt>>,
    pub signer_interrupt: Option<Box<dyn crate::mldsa_sign::Interrupt>>,
    pub wait_mode: WaitMode,
}

/// Per-lane counters, read by diagnostics and tests.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LaneStats {
    pub signs: u64,
    pub context_loads: u64,
    /// Sum of the `attempts` field of successful sign completions.
    pub attempts: u64,
    pub signer_interrupts: u64,
    pub signer_missed_interrupts: u64,
    pub register_polls: u64,
}

pub struct SignLane<R, D> {
    dma_controller: DmaController<R>,
    signer: Signer<R>,
    mailbox: R,
    dma: D,
    dma_wait: Wait,
    signer_wait: Wait,
    matrix: Vec<i32>,
    generation: u32,
    request_id: u64,
    healthy: bool,
    stats: LaneStats,
}

impl<R: RegisterIo, D: SignDma> SignLane<R, D> {
    pub fn new(parts: LaneParts<R, D>) -> io::Result<Self> {
        let LaneParts {
            mut dma_control,
            mut signer_control,
            mailbox,
            mut dma,
            mailbox_base,
            signature_base,
            dma_interrupt,
            signer_interrupt,
            wait_mode,
        } = parts;
        if dma.len() < OUTPUT_OFFSET + SIGN_OUTPUT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DMA buffer is too small",
            ));
        }
        dma.clear()?;
        let dma_wait = Wait::new(wait_mode, dma_interrupt);
        let signer_wait = Wait::new(wait_mode, signer_interrupt);
        if dma_wait.mode == WaitMode::Interrupt {
            enable_done_interrupt(&mut dma_control);
        }
        if signer_wait.mode == WaitMode::Interrupt {
            enable_done_interrupt(&mut signer_control);
        }
        Ok(Self {
            dma_controller: DmaController::new(dma_control),
            signer: Signer::new_with_memory_map(signer_control, mailbox_base, signature_base),
            mailbox,
            dma,
            dma_wait,
            signer_wait,
            matrix: Vec::new(),
            generation: 0,
            request_id: 0,
            healthy: true,
            stats: LaneStats::default(),
        })
    }

    pub fn stats(&self) -> LaneStats {
        let mut stats = self.stats;
        stats.signer_interrupts = self.signer_wait.interrupts;
        stats.signer_missed_interrupts = self.signer_wait.missed_interrupts;
        stats.register_polls = self.signer_wait.register_polls + self.dma_wait.register_polls;
        stats
    }

    pub fn wait_modes(&self) -> (WaitMode, WaitMode) {
        (self.dma_wait.mode, self.signer_wait.mode)
    }

    pub fn dma(&self) -> &D {
        &self.dma
    }

    pub fn load_context(&mut self, matrix: &[i32], timeout: Duration) -> io::Result<()> {
        self.ensure_healthy()?;
        if matrix.len() != MATRIX_COEFFICIENTS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid ML-DSA-65 matrix",
            ));
        }
        let started = stage::start();
        let resident = self.matrix == matrix;
        stage::end(Stage::ContextCheck, started);
        if resident {
            return Ok(());
        }
        let started = stage::start();
        self.next_request();
        self.write_request(COMMAND_LOAD, 0, MATRIX_BYTES, COMPLETION_BYTES, 0, 0);
        encode_i32(
            &mut self.dma.bytes_mut()[INPUT_OFFSET..INPUT_OFFSET + MATRIX_BYTES],
            matrix,
        );
        self.execute_dispatch(timeout)?;
        self.signer_wait.arm(self.signer.registers_mut());
        self.signer
            .start_load(TENANT)
            .map_err(hw_error)?;
        let status =
            wait_done(self.signer.registers_mut(), &mut self.signer_wait, timeout).map_err(hw_error)?;
        self.publish(status, timeout)?;
        let completion = self.read_completion()?;
        if completion.status != 0 || completion.generation == 0 {
            return self.quarantine(format!("context load failed: {}", completion.status));
        }
        self.generation = completion.generation;
        self.matrix.clear();
        self.matrix.extend_from_slice(matrix);
        self.stats.context_loads += 1;
        stage::end(Stage::ContextLoad, started);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        &mut self,
        matrix: &[i32],
        s1: &[i32],
        s2: &[i32],
        t0: &[i32],
        mu: &[u8; 64],
        rho_prime: &[u8; 64],
        randomized: bool,
        attempt_limit: u16,
        timeout: Duration,
    ) -> io::Result<Vec<u8>> {
        self.load_context(matrix, timeout)?;
        if s1.len() != S1_COEFFICIENTS
            || s2.len() != S2_COEFFICIENTS
            || t0.len() != T0_COEFFICIENTS
            || attempt_limit == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid ML-DSA-65 signing input",
            ));
        }
        let started = stage::start();
        self.next_request();
        self.write_request(
            COMMAND_SIGN,
            self.generation,
            SECRET_BYTES,
            SIGN_OUTPUT_BYTES,
            u32::from(attempt_limit),
            if randomized {
                SIGN_RANDOMIZED
            } else {
                SIGN_DETERMINISTIC
            },
        );
        let input = &mut self.dma.bytes_mut()[INPUT_OFFSET..INPUT_OFFSET + SECRET_BYTES];
        let s1_end = S1_COEFFICIENTS * 4;
        let s2_end = s1_end + S2_COEFFICIENTS * 4;
        let t0_end = s2_end + T0_COEFFICIENTS * 4;
        encode_i32(&mut input[..s1_end], s1);
        encode_i32(&mut input[s1_end..s2_end], s2);
        encode_i32(&mut input[s2_end..t0_end], t0);
        input[t0_end..t0_end + 64].copy_from_slice(mu);
        input[t0_end + 64..t0_end + 128].copy_from_slice(rho_prime);
        stage::end(Stage::Encode, started);
        self.execute_dispatch(timeout)?;
        let started = stage::start();
        self.signer_wait.arm(self.signer.registers_mut());
        self.signer
            .start_sign(SignSubmission {
                tenant: TENANT,
                generation: self.generation,
                attempt_limit,
            })
            .map_err(hw_error)?;
        let status =
            wait_done(self.signer.registers_mut(), &mut self.signer_wait, timeout).map_err(hw_error)?;
        stage::end(Stage::SignerWait, started);
        self.publish(status, timeout)?;
        let started = stage::start();
        let completion = self.read_completion()?;
        if completion.status != 0 || completion.output_bytes != SIGNATURE_BYTES as u32 {
            return Err(io::Error::other(format!(
                "FPGA sign failed: {}",
                completion.status
            )));
        }
        let signature = self.dma.bytes()
            [OUTPUT_OFFSET + COMPLETION_BYTES..OUTPUT_OFFSET + SIGN_OUTPUT_BYTES]
            .to_vec();
        self.stats.signs += 1;
        self.stats.attempts += u64::from(completion.attempts);
        stage::end(Stage::Readback, started);
        Ok(signature)
    }

    fn execute_dispatch(&mut self, timeout: Duration) -> io::Result<()> {
        let started = stage::start();
        self.dma
            .sync_for_device(0, OUTPUT_OFFSET + SIGN_OUTPUT_BYTES)?;
        stage::end(Stage::SyncForDevice, started);
        let started = stage::start();
        let result = self.run_dma(PHASE_DISPATCH, timeout)?;
        stage::end(Stage::Dispatch, started);
        if result != 1 {
            return self.quarantine(format!("DMA dispatch returned {result}"));
        }
        Ok(())
    }

    fn run_dma(&mut self, phase: u32, timeout: Duration) -> io::Result<i32> {
        let words = (self.dma.len() / 4) as u32;
        let phys = self.dma.phys_addr();
        self.dma_wait.arm(self.dma_controller.registers_mut());
        self.dma_controller
            .start(phase, words, phys)
            .map_err(hw_error)?;
        wait_done(
            self.dma_controller.registers_mut(),
            &mut self.dma_wait,
            timeout,
        )
        .map_err(hw_error)
    }

    fn publish(&mut self, signer_status: i32, timeout: Duration) -> io::Result<()> {
        let started = stage::start();
        self.mailbox.write32(MB_SIGNER_STATUS, signer_status as u32);
        self.mailbox.write32(MB_STATE, STATE_RESULT);
        let status = self.run_dma(PHASE_PUBLISH, timeout)?;
        stage::end(Stage::Publish, started);
        let started = stage::start();
        self.dma
            .sync_for_cpu(OUTPUT_OFFSET, SIGN_OUTPUT_BYTES)?;
        stage::end(Stage::SyncForCpu, started);
        if status != signer_status {
            return self.quarantine(format!(
                "DMA publish returned {status}, signer returned {signer_status}"
            ));
        }
        Ok(())
    }

    fn write_request(
        &mut self,
        command: u32,
        generation: u32,
        input_len: usize,
        output_len: usize,
        attempts: u32,
        flags: u32,
    ) {
        let request_id = self.request_id;
        let words = [
            REQUEST_MAGIC,
            u32::from(ABI_VERSION) | ((REQUEST_BYTES as u32) << 16),
            REQUEST_BYTES as u32,
            command,
            flags,
            0,
            request_id as u32,
            (request_id >> 32) as u32,
            generation,
            INPUT_OFFSET as u32,
            input_len as u32,
            OUTPUT_OFFSET as u32,
            output_len as u32,
            attempts,
            TENANT,
            0,
        ];
        let dma = self.dma.bytes_mut();
        dma[..REQUEST_BYTES].fill(0);
        for (index, word) in words.into_iter().enumerate() {
            dma[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        dma[OUTPUT_OFFSET..OUTPUT_OFFSET + SIGN_OUTPUT_BYTES].fill(0);
    }

    fn read_completion(&self) -> io::Result<Completion> {
        let output = &self.dma.bytes()[OUTPUT_OFFSET..OUTPUT_OFFSET + COMPLETION_BYTES];
        if read_u32(output, 0) != COMPLETION_MAGIC
            || read_u32(output, 4) & 0xffff != u32::from(ABI_VERSION)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid FPGA completion",
            ));
        }
        let request_id = u64::from(read_u32(output, 16)) | (u64::from(read_u32(output, 20)) << 32);
        if request_id != self.request_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stale FPGA completion",
            ));
        }
        Ok(Completion {
            status: read_u32(output, 8) as i32,
            generation: read_u32(output, 28),
            attempts: read_u32(output, 32),
            output_bytes: read_u32(output, 40),
        })
    }

    fn next_request(&mut self) {
        self.request_id = self.request_id.wrapping_add(1).max(1);
    }

    fn ensure_healthy(&self) -> io::Result<()> {
        if self.healthy {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "ML-DSA FPGA session is quarantined",
            ))
        }
    }

    fn quarantine<T>(&mut self, message: String) -> io::Result<T> {
        self.healthy = false;
        let words = (self.dma.len() / 4) as u32;
        let _ = self.dma_controller.run(
            PHASE_ABORT,
            words,
            self.dma.phys_addr(),
            Duration::from_millis(50),
        );
        Err(io::Error::other(message))
    }
}

struct Completion {
    status: i32,
    generation: u32,
    attempts: u32,
    output_bytes: u32,
}

pub(crate) fn encode_i32(output: &mut [u8], input: &[i32]) {
    for (chunk, coefficient) in output.chunks_exact_mut(4).zip(input) {
        chunk.copy_from_slice(&coefficient.to_le_bytes());
    }
}

fn read_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        input[offset..offset + 4]
            .try_into()
            .expect("fixed-width field"),
    )
}

fn hw_error(error: crate::mldsa_sign::Error) -> io::Error {
    io::Error::other(error)
}
