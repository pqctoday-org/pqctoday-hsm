//! Linux UIO/DMA transport for the whole ML-DSA-65 signing operation.
//!
//! The protocol lives in [`crate::mldsa_sign_lane`]; this module only finds
//! and maps one lane's UIO windows and u-dma-buf allocation.

use crate::dma::Buffer;
use crate::mldsa_sign::{
    DMA_CONTROL_BASE, MAILBOX_BASE, SIGNATURE_BASE, SIGNER_CONTROL_BASE, WaitMode,
};
use crate::mldsa_sign_lane::{LaneParts, SignLane};
use crate::uio::{Mapping, UioInterrupt};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::time::Duration;

pub use crate::mldsa_sign_lane::{
    COMPLETION_BYTES, MATRIX_BYTES, MATRIX_COEFFICIENTS, S1_COEFFICIENTS, S2_COEFFICIENTS,
    SECRET_BYTES, SIGNATURE_BYTES, T0_COEFFICIENTS,
};

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

/// One open signer lane: the protocol driver plus the process-exclusive
/// lock on its DMA allocation.
pub struct Mldsa65SignSession {
    lane: SignLane<Mapping, Buffer>,
    _lock: File,
}

// The mappings are exclusively owned by the session and every register/DMA
// access requires `&mut self`; shared access still requires the caller's
// per-lane mutex.
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
        let dma = Buffer::open(config.dma_path, config.dma_sysfs_path)?;
        // The mldsa overlay wires both HLS blocks' `interrupt` outputs to
        // PL-PS IRQ lines (GIC SPI 89-92) under generic-uio. A waiting
        // worker blocks on the line instead of spinning a core for the whole
        // signature; the control register stays the authority, and a line
        // that never fires falls back to sleep-polling (mldsa_sign::Wait).
        let interrupt = |path: &std::path::Path| {
            UioInterrupt::open(path)
                .ok()
                .map(|irq| Box::new(irq) as Box<dyn crate::mldsa_sign::Interrupt>)
        };
        let dma_interrupt = interrupt(&dma_uio);
        let signer_interrupt = interrupt(&signer_uio);
        let lane = SignLane::new(LaneParts {
            dma_control: Mapping::open(&dma_uio, 0x10000)?,
            signer_control: Mapping::open(&signer_uio, 0x10000)?,
            mailbox: Mapping::open(mailbox_uio, 0x2000)?,
            dma,
            mailbox_base: config.mailbox_base,
            signature_base: config.signature_base,
            dma_interrupt,
            signer_interrupt,
            // PQC_HW_MLDSA_WAIT=spin|sleep|irq overrides for A/B runs.
            wait_mode: WaitMode::from_env().unwrap_or(WaitMode::Interrupt),
        })?;
        Ok(Self { lane, _lock: lock })
    }

    pub fn lane(&self) -> &SignLane<Mapping, Buffer> {
        &self.lane
    }

    pub fn lane_mut(&mut self) -> &mut SignLane<Mapping, Buffer> {
        &mut self.lane
    }

    pub fn load_context(&mut self, matrix: &[i32], timeout: Duration) -> io::Result<()> {
        self.lane.load_context(matrix, timeout)
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
        self.lane.sign(
            matrix,
            s1,
            s2,
            t0,
            mu,
            rho_prime,
            randomized,
            attempt_limit,
            timeout,
        )
    }
}
