//! Linux UIO/DMA transport for the whole ML-DSA-65 signing operation.

use crate::dma::Buffer;
use crate::keccak::RegisterIo;
use crate::mldsa_sign::{
    DmaController, SignSubmission, Signer, DMA_CONTROL_BASE, MAILBOX_BASE, PHASE_ABORT,
    PHASE_DISPATCH, PHASE_PUBLISH, SIGNATURE_BASE, SIGNER_CONTROL_BASE,
};
use crate::uio::Mapping;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::time::Duration;

pub const MATRIX_COEFFICIENTS: usize = 6 * 5 * 256;
pub const S1_COEFFICIENTS: usize = 5 * 256;
pub const S2_COEFFICIENTS: usize = 6 * 256;
pub const T0_COEFFICIENTS: usize = 6 * 256;
pub const MATRIX_BYTES: usize = MATRIX_COEFFICIENTS * 4;
pub const SECRET_BYTES: usize = (S1_COEFFICIENTS + S2_COEFFICIENTS + T0_COEFFICIENTS) * 4 + 128;
pub const SIGNATURE_BYTES: usize = 3309;
pub const COMPLETION_BYTES: usize = 128;

const REQUEST_MAGIC: u32 = 0x3244_534d;
const COMPLETION_MAGIC: u32 = 0x3243_444d;
const ABI_VERSION: u16 = 2;
const REQUEST_BYTES: usize = 64;
const INPUT_OFFSET: usize = 0x100;
const OUTPUT_OFFSET: usize = 0x8000;
const SIGN_OUTPUT_BYTES: usize = COMPLETION_BYTES + SIGNATURE_BYTES;
const TENANT: u32 = 0x5051_4354;
const STATE_RESULT: u32 = 2;
const MB_STATE: usize = 0;
const MB_SIGNER_STATUS: usize = 11 * 4;
const SIGN_DETERMINISTIC: u32 = 1;
const SIGN_RANDOMIZED: u32 = 2;

pub const MLDSA65_SIGN_LANES: usize = 2;

#[derive(Clone, Copy)]
struct LaneConfig {
    mailbox_base: u64,
    signature_base: u64,
    dma_control_base: u64,
    signer_control_base: u64,
    lock_path: &'static str,
    dma_path: &'static str,
    dma_sysfs_path: &'static str,
}

const LANES: [LaneConfig; MLDSA65_SIGN_LANES] = [
    LaneConfig {
        mailbox_base: MAILBOX_BASE,
        signature_base: SIGNATURE_BASE,
        dma_control_base: DMA_CONTROL_BASE,
        signer_control_base: SIGNER_CONTROL_BASE,
        lock_path: "/run/lock/pqc-accel-dma.lock",
        dma_path: "/dev/pqc-accel-dma",
        dma_sysfs_path: "/sys/class/u-dma-buf/pqc-accel-dma",
    },
    LaneConfig {
        mailbox_base: 0xa003_0000,
        signature_base: 0xa003_2000,
        dma_control_base: 0xa004_0000,
        signer_control_base: 0xa005_0000,
        lock_path: "/run/lock/pqc-accel-dma1.lock",
        dma_path: "/dev/pqc-accel-dma1",
        dma_sysfs_path: "/sys/class/u-dma-buf/pqc-accel-dma1",
    },
];

pub struct Mldsa65SignSession {
    dma_controller: DmaController<Mapping>,
    signer: Signer<Mapping>,
    mailbox: Mapping,
    dma: Buffer,
    matrix: Vec<i32>,
    generation: u32,
    request_id: u64,
    healthy: bool,
    _lock: File,
}

unsafe impl Send for Mldsa65SignSession {}

impl Mldsa65SignSession {
    pub fn open() -> io::Result<Self> {
        Self::open_lane(0)
    }

    pub fn open_lane(lane: usize) -> io::Result<Self> {
        let config = LANES.get(lane).copied().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid ML-DSA FPGA lane")
        })?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(config.lock_path)?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "FPGA DMA allocation is owned by another process",
            ));
        }
        let dma_uio = Mapping::find_by_address("/sys/class/uio", config.dma_control_base)?;
        let signer_uio = Mapping::find_by_address("/sys/class/uio", config.signer_control_base)?;
        let mailbox_uio = Mapping::find_by_address("/sys/class/uio", config.mailbox_base)?;
        let mut dma = Buffer::open(config.dma_path, config.dma_sysfs_path)?;
        if dma.len() < OUTPUT_OFFSET + SIGN_OUTPUT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DMA buffer is too small",
            ));
        }
        dma.clear()?;
        Ok(Self {
            dma_controller: DmaController::new(Mapping::open(dma_uio, 0x10000)?),
            signer: Signer::new_with_memory_map(
                Mapping::open(signer_uio, 0x10000)?,
                config.mailbox_base,
                config.signature_base,
            ),
            mailbox: Mapping::open(mailbox_uio, 0x2000)?,
            dma,
            matrix: Vec::new(),
            generation: 0,
            request_id: 0,
            healthy: true,
            _lock: lock,
        })
    }

    pub fn load_context(&mut self, matrix: &[i32], timeout: Duration) -> io::Result<()> {
        self.ensure_healthy()?;
        if matrix.len() != MATRIX_COEFFICIENTS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid ML-DSA-65 matrix",
            ));
        }
        if self.matrix == matrix {
            return Ok(());
        }
        self.next_request();
        self.write_request(1, 0, MATRIX_BYTES, COMPLETION_BYTES, 0, 0);
        encode_i32(
            &mut self.dma.as_mut_slice()[INPUT_OFFSET..INPUT_OFFSET + MATRIX_BYTES],
            matrix,
        );
        self.execute_dispatch(timeout)?;
        let status = self.signer.load(TENANT, timeout).map_err(hw_error)?;
        self.publish(status, timeout)?;
        let completion = self.read_completion()?;
        if completion.status != 0 || completion.generation == 0 {
            return self.quarantine(format!("context load failed: {}", completion.status));
        }
        self.generation = completion.generation;
        self.matrix.clear();
        self.matrix.extend_from_slice(matrix);
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
        self.next_request();
        self.write_request(
            2,
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
        let input = &mut self.dma.as_mut_slice()[INPUT_OFFSET..INPUT_OFFSET + SECRET_BYTES];
        let s1_end = S1_COEFFICIENTS * 4;
        let s2_end = s1_end + S2_COEFFICIENTS * 4;
        let t0_end = s2_end + T0_COEFFICIENTS * 4;
        encode_i32(&mut input[..s1_end], s1);
        encode_i32(&mut input[s1_end..s2_end], s2);
        encode_i32(&mut input[s2_end..t0_end], t0);
        input[t0_end..t0_end + 64].copy_from_slice(mu);
        input[t0_end + 64..t0_end + 128].copy_from_slice(rho_prime);
        self.execute_dispatch(timeout)?;
        let status = self
            .signer
            .sign(
                SignSubmission {
                    tenant: TENANT,
                    generation: self.generation,
                    attempt_limit,
                },
                timeout,
            )
            .map_err(hw_error)?;
        self.publish(status, timeout)?;
        let completion = self.read_completion()?;
        if completion.status != 0 || completion.output_bytes != SIGNATURE_BYTES as u32 {
            return Err(io::Error::other(format!(
                "FPGA sign failed: {}",
                completion.status
            )));
        }
        Ok(
            self.dma.as_slice()
                [OUTPUT_OFFSET + COMPLETION_BYTES..OUTPUT_OFFSET + SIGN_OUTPUT_BYTES]
                .to_vec(),
        )
    }

    fn execute_dispatch(&mut self, timeout: Duration) -> io::Result<()> {
        self.dma
            .sync_range_for_device(0, OUTPUT_OFFSET + SIGN_OUTPUT_BYTES)?;
        let result = self
            .dma_controller
            .run(
                PHASE_DISPATCH,
                (self.dma.len() / 4) as u32,
                self.dma.phys_addr(),
                timeout,
            )
            .map_err(hw_error)?;
        if result != 1 {
            return self.quarantine(format!("DMA dispatch returned {result}"));
        }
        Ok(())
    }

    fn publish(&mut self, signer_status: i32, timeout: Duration) -> io::Result<()> {
        self.mailbox.write32(MB_SIGNER_STATUS, signer_status as u32);
        self.mailbox.write32(MB_STATE, STATE_RESULT);
        let status = self
            .dma_controller
            .run(
                PHASE_PUBLISH,
                (self.dma.len() / 4) as u32,
                self.dma.phys_addr(),
                timeout,
            )
            .map_err(hw_error)?;
        self.dma
            .sync_range_for_cpu(OUTPUT_OFFSET, SIGN_OUTPUT_BYTES)?;
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
        let dma = self.dma.as_mut_slice();
        dma[..REQUEST_BYTES].fill(0);
        for (index, word) in words.into_iter().enumerate() {
            dma[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        dma[OUTPUT_OFFSET..OUTPUT_OFFSET + SIGN_OUTPUT_BYTES].fill(0);
    }

    fn read_completion(&self) -> io::Result<Completion> {
        let output = &self.dma.as_slice()[OUTPUT_OFFSET..OUTPUT_OFFSET + COMPLETION_BYTES];
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
        let _ = self.dma_controller.run(
            PHASE_ABORT,
            (self.dma.len() / 4) as u32,
            self.dma.phys_addr(),
            Duration::from_millis(50),
        );
        Err(io::Error::other(message))
    }
}

struct Completion {
    status: i32,
    generation: u32,
    output_bytes: u32,
}

fn encode_i32(output: &mut [u8], input: &[i32]) {
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
