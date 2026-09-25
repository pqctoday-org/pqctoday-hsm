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

/// The inputs of one signature, written straight into the lane's DMA buffer.
pub trait SignInputs {
    /// Identity of the public matrix. Two inputs with the same id MUST have
    /// the same matrix (ML-DSA: `ρ`, since `Â = ExpandA(ρ)`); the lane skips
    /// the upload when it already holds that id.
    fn matrix_id(&self) -> [u8; 32];
    /// Writes the matrix (`MATRIX_BYTES`, little-endian `i32`).
    fn write_matrix(&self, out: &mut [u8]) -> bool;
    /// Writes `s1 ‖ s2 ‖ t0` (`SECRET_POLY_BYTES`, little-endian `i32`).
    fn write_secret_polys(&self, out: &mut [u8]) -> bool;
    fn mu(&self) -> &[u8; 64];
    fn rho_prime(&self) -> &[u8; 64];
    fn randomized(&self) -> bool;
}

/// [`SignInputs`] over flattened coefficient slices (diagnostics and the
/// original slice API). The matrix id is a SHAKE256 digest of the matrix,
/// so identity is by content, as the slice API always compared.
pub struct SliceInputs<'a> {
    pub matrix: &'a [i32],
    pub s1: &'a [i32],
    pub s2: &'a [i32],
    pub t0: &'a [i32],
    pub mu: &'a [u8; 64],
    pub rho_prime: &'a [u8; 64],
    pub randomized: bool,
}

impl SignInputs for SliceInputs<'_> {
    fn matrix_id(&self) -> [u8; 32] {
        use sha3::digest::{ExtendableOutput, Update, XofReader};
        let mut shake = sha3::Shake256::default();
        shake.update(b"pqc-hw/mldsa65-matrix-id");
        for coefficient in self.matrix {
            shake.update(&coefficient.to_le_bytes());
        }
        let mut id = [0u8; 32];
        shake.finalize_xof().read(&mut id);
        id
    }
    fn write_matrix(&self, out: &mut [u8]) -> bool {
        if self.matrix.len() != MATRIX_COEFFICIENTS || out.len() != MATRIX_BYTES {
            return false;
        }
        encode_i32(out, self.matrix);
        true
    }
    fn write_secret_polys(&self, out: &mut [u8]) -> bool {
        if self.s1.len() != S1_COEFFICIENTS
            || self.s2.len() != S2_COEFFICIENTS
            || self.t0.len() != T0_COEFFICIENTS
            || out.len() != SECRET_POLY_BYTES
        {
            return false;
        }
        let (s1, rest) = out.split_at_mut(S1_COEFFICIENTS * 4);
        let (s2, t0) = rest.split_at_mut(S2_COEFFICIENTS * 4);
        encode_i32(s1, self.s1);
        encode_i32(s2, self.s2);
        encode_i32(t0, self.t0);
        true
    }
    fn mu(&self) -> &[u8; 64] {
        self.mu
    }
    fn rho_prime(&self) -> &[u8; 64] {
        self.rho_prime
    }
    fn randomized(&self) -> bool {
        self.randomized
    }
}

/// Bytes the DMA controller reads for a SIGN (request, padding, input) and
/// for a LOAD; only these are cleaned before DISPATCH.
pub const SIGN_DEVICE_EXTENT: usize = INPUT_OFFSET + SECRET_BYTES;
pub const LOAD_DEVICE_EXTENT: usize = INPUT_OFFSET + MATRIX_BYTES;

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
    /// Identity of the matrix the signer holds (valid while `generation`).
    matrix_id: Option<[u8; 32]>,
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
            matrix_id: None,
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

    /// The matrix id the signer currently holds, if any.
    pub fn resident_matrix(&self) -> Option<[u8; 32]> {
        self.matrix_id
    }

    /// Uploads the matrix unless the signer already holds `inputs`' id.
    pub fn load_context_from(&mut self, inputs: &dyn SignInputs, timeout: Duration) -> io::Result<()> {
        self.ensure_healthy()?;
        let started = stage::start();
        let id = inputs.matrix_id();
        let resident = self.matrix_id == Some(id);
        stage::end(Stage::ContextCheck, started);
        if resident {
            return Ok(());
        }
        let started = stage::start();
        // A failed upload leaves no context the lane could mistake for valid.
        self.matrix_id = None;
        self.next_request();
        self.write_request(COMMAND_LOAD, 0, MATRIX_BYTES, COMPLETION_BYTES, 0, 0);
        if !inputs.write_matrix(&mut self.dma.bytes_mut()[INPUT_OFFSET..INPUT_OFFSET + MATRIX_BYTES]) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid ML-DSA-65 matrix",
            ));
        }
        self.execute_dispatch(LOAD_DEVICE_EXTENT, timeout)?;
        self.signer
            .start_load(TENANT)
            .map_err(hw_error)?;
        let status =
            wait_done(self.signer.registers_mut(), &mut self.signer_wait, timeout).map_err(hw_error)?;
        self.publish(status, COMPLETION_BYTES, timeout)?;
        let completion = self.read_completion()?;
        if completion.status != 0 || completion.generation == 0 {
            return self.quarantine(format!("context load failed: {}", completion.status));
        }
        self.generation = completion.generation;
        self.matrix_id = Some(id);
        self.stats.context_loads += 1;
        stage::end(Stage::ContextLoad, started);
        Ok(())
    }

    /// Slice form of [`Self::load_context_from`].
    pub fn load_context(&mut self, matrix: &[i32], timeout: Duration) -> io::Result<()> {
        let zero = [0u8; 64];
        self.load_context_from(
            &SliceInputs {
                matrix,
                s1: &[],
                s2: &[],
                t0: &[],
                mu: &zero,
                rho_prime: &zero,
                randomized: false,
            },
            timeout,
        )
    }

    /// Signs with the lane: the matrix is uploaded only if the signer does
    /// not hold it, the secret input is written straight into the DMA
    /// buffer, and the 3,309-byte signature is copied into `signature`.
    pub fn sign_into(
        &mut self,
        inputs: &dyn SignInputs,
        attempt_limit: u16,
        timeout: Duration,
        signature: &mut [u8],
    ) -> io::Result<()> {
        if signature.len() != SIGNATURE_BYTES || attempt_limit == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid ML-DSA-65 signing request",
            ));
        }
        self.load_context_from(inputs, timeout)?;
        let started = stage::start();
        self.next_request();
        self.write_request(
            COMMAND_SIGN,
            self.generation,
            SECRET_BYTES,
            SIGN_OUTPUT_BYTES,
            u32::from(attempt_limit),
            if inputs.randomized() {
                SIGN_RANDOMIZED
            } else {
                SIGN_DETERMINISTIC
            },
        );
        let input = &mut self.dma.bytes_mut()[INPUT_OFFSET..INPUT_OFFSET + SECRET_BYTES];
        let (polys, tail) = input.split_at_mut(SECRET_POLY_BYTES);
        if !inputs.write_secret_polys(polys) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid ML-DSA-65 signing input",
            ));
        }
        tail[..64].copy_from_slice(inputs.mu());
        tail[64..128].copy_from_slice(inputs.rho_prime());
        stage::end(Stage::Encode, started);
        self.execute_dispatch(SIGN_DEVICE_EXTENT, timeout)?;
        let started = stage::start();
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
        self.publish(status, SIGN_OUTPUT_BYTES, timeout)?;
        let started = stage::start();
        let completion = self.read_completion()?;
        if completion.status != 0 || completion.output_bytes != SIGNATURE_BYTES as u32 {
            return Err(io::Error::other(format!(
                "FPGA sign failed: {}",
                completion.status
            )));
        }
        signature.copy_from_slice(
            &self.dma.bytes()[OUTPUT_OFFSET + COMPLETION_BYTES..OUTPUT_OFFSET + SIGN_OUTPUT_BYTES],
        );
        self.stats.signs += 1;
        self.stats.attempts += u64::from(completion.attempts);
        stage::end(Stage::Readback, started);
        Ok(())
    }

    /// Slice form of [`Self::sign_into`].
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
        let mut signature = vec![0u8; SIGNATURE_BYTES];
        self.sign_into(
            &SliceInputs {
                matrix,
                s1,
                s2,
                t0,
                mu,
                rho_prime,
                randomized,
            },
            attempt_limit,
            timeout,
            &mut signature,
        )?;
        Ok(signature)
    }

    fn execute_dispatch(&mut self, device_extent: usize, timeout: Duration) -> io::Result<()> {
        // Only the request, padding and input are CPU-written; the DMA
        // controller clears the output region itself at DISPATCH.
        let started = stage::start();
        self.dma.sync_for_device(0, device_extent)?;
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

    fn publish(&mut self, signer_status: i32, output_extent: usize, timeout: Duration) -> io::Result<()> {
        let started = stage::start();
        self.mailbox.write32(MB_SIGNER_STATUS, signer_status as u32);
        self.mailbox.write32(MB_STATE, STATE_RESULT);
        let status = self.run_dma(PHASE_PUBLISH, timeout)?;
        stage::end(Stage::Publish, started);
        let started = stage::start();
        self.dma.sync_for_cpu(OUTPUT_OFFSET, output_extent)?;
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
        // The output region is not written here: the DMA controller clears
        // it at DISPATCH, and a completion is accepted only with this
        // request's id, so a stale record can never be taken for a result.
        let dma = self.dma.bytes_mut();
        for (index, word) in words.into_iter().enumerate() {
            dma[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
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
