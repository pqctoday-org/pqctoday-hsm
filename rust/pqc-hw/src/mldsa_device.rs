//! Linux UIO/DMA transport for the resident ML-DSA-65 matrix/vector engine.

use crate::dma::Buffer;
use crate::mldsa::{Engine, MLDSA65_CONTROL_BASE, Submission};
use crate::uio::Mapping;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::time::Duration;
use std::time::Instant;

pub const COEFFICIENT_BYTES: usize = 4;
pub const MLDSA_N: usize = 256;
pub const MLDSA_Q: i32 = 8_380_417;
pub const MLDSA65_K: usize = 6;
pub const MLDSA65_L: usize = 5;
pub const MATRIX_COEFFICIENTS: usize = MLDSA65_K * MLDSA65_L * MLDSA_N;
pub const VECTOR_COEFFICIENTS: usize = MLDSA65_L * MLDSA_N;
pub const OUTPUT_COEFFICIENTS: usize = MLDSA65_K * MLDSA_N;

pub const MATRIX_OFFSET: usize = 0x0000;
pub const VECTOR_OFFSET: usize = 0x7800;
pub const OUTPUT_OFFSET: usize = 0x8c00;
pub const TOTAL_BYTES: usize = 0xa400;

#[derive(Clone, Copy, Debug, Default)]
pub struct Mldsa65Timings {
    pub encode: Duration,
    pub sync_for_device: Duration,
    pub hardware: Duration,
    pub sync_for_cpu: Duration,
    pub decode_validate: Duration,
    pub scrub: Duration,
    pub total: Duration,
}

pub struct Mldsa65Session {
    engine: Engine<Mapping>,
    dma: Buffer,
    healthy: bool,
    matrix_loaded: bool,
    _lock: File,
}

impl Mldsa65Session {
    pub fn open() -> io::Result<Self> {
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open("/run/lock/pqc-accel-dma.lock")?;
        let result = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "FPGA DMA allocation is owned by another process",
            ));
        }

        let uio = Mapping::find_by_address("/sys/class/uio", MLDSA65_CONTROL_BASE)?;
        let mut dma = Buffer::open("/dev/pqc-accel-dma", "/sys/class/u-dma-buf/pqc-accel-dma")?;
        if dma.len() < TOTAL_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DMA buffer too small for ML-DSA-65 resident command",
            ));
        }
        dma.clear()?;
        Ok(Self {
            engine: Engine::new(Mapping::open(uio, 0x10000)?),
            dma,
            healthy: true,
            matrix_loaded: false,
            _lock: lock,
        })
    }

    /// Upload a public ML-DSA-65 NTT-domain matrix once for subsequent
    /// cached executions. Loading a different matrix replaces the slot.
    pub fn load_matrix(&mut self, matrix_hat: &[i32]) -> io::Result<Duration> {
        if !self.healthy {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "ML-DSA FPGA session is quarantined",
            ));
        }
        validate_matrix(matrix_hat)?;
        let started = Instant::now();
        encode_coefficients(
            &mut self.dma.as_mut_slice()[MATRIX_OFFSET..VECTOR_OFFSET],
            matrix_hat,
        );
        self.dma
            .sync_range_for_device(MATRIX_OFFSET, VECTOR_OFFSET - MATRIX_OFFSET)?;
        self.matrix_loaded = true;
        Ok(started.elapsed())
    }

    pub fn execute_cached(&mut self, vector: &[i32], timeout: Duration) -> io::Result<Vec<i32>> {
        self.execute_cached_profiled(vector, timeout)
            .map(|(output, _)| output)
    }

    /// Execute with the matrix already retained in the session's DMA slot.
    /// Only the vector/output region changes ownership for each operation.
    pub fn execute_cached_profiled(
        &mut self,
        vector: &[i32],
        timeout: Duration,
    ) -> io::Result<(Vec<i32>, Mldsa65Timings)> {
        if !self.healthy {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "ML-DSA FPGA session is quarantined",
            ));
        }
        if !self.matrix_loaded {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "ML-DSA matrix has not been loaded",
            ));
        }
        validate_vector(vector)?;
        let total_started = Instant::now();

        let started = Instant::now();
        encode_coefficients(
            &mut self.dma.as_mut_slice()[VECTOR_OFFSET..OUTPUT_OFFSET],
            vector,
        );
        self.dma.as_mut_slice()[OUTPUT_OFFSET..TOTAL_BYTES].fill(0);
        let encode = started.elapsed();

        let started = Instant::now();
        self.dma
            .sync_range_for_device(VECTOR_OFFSET, TOTAL_BYTES - VECTOR_OFFSET)?;
        let sync_for_device = started.elapsed();

        let base = self.dma.phys_addr();
        let started = Instant::now();
        if let Err(error) = self.engine.submit_polling(
            Submission {
                matrix_hat_phys: base + MATRIX_OFFSET as u64,
                vector_phys: base + VECTOR_OFFSET as u64,
                output_phys: base + OUTPUT_OFFSET as u64,
            },
            timeout,
        ) {
            self.healthy = false;
            return Err(io::Error::other(error));
        }
        let hardware = started.elapsed();

        let started = Instant::now();
        self.dma
            .sync_range_for_cpu(OUTPUT_OFFSET, TOTAL_BYTES - OUTPUT_OFFSET)?;
        let sync_for_cpu = started.elapsed();

        let started = Instant::now();
        let output = decode_coefficients(&self.dma.as_slice()[OUTPUT_OFFSET..TOTAL_BYTES]);
        validate_output(&output).inspect_err(|_| self.healthy = false)?;
        let decode_validate = started.elapsed();

        let started = Instant::now();
        self.dma
            .clear_range(VECTOR_OFFSET, TOTAL_BYTES - VECTOR_OFFSET)?;
        let scrub = started.elapsed();
        let total = total_started.elapsed();
        Ok((
            output,
            Mldsa65Timings {
                encode,
                sync_for_device,
                hardware,
                sync_for_cpu,
                decode_validate,
                scrub,
                total,
            },
        ))
    }

    pub fn execute(
        &mut self,
        matrix_hat: &[i32],
        vector: &[i32],
        timeout: Duration,
    ) -> io::Result<Vec<i32>> {
        self.execute_profiled(matrix_hat, vector, timeout)
            .map(|(output, _)| output)
    }

    pub fn execute_profiled(
        &mut self,
        matrix_hat: &[i32],
        vector: &[i32],
        timeout: Duration,
    ) -> io::Result<(Vec<i32>, Mldsa65Timings)> {
        if !self.healthy {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "ML-DSA FPGA session is quarantined",
            ));
        }
        let total_started = Instant::now();
        validate_inputs(matrix_hat, vector)?;

        let started = Instant::now();
        encode_coefficients(
            &mut self.dma.as_mut_slice()[MATRIX_OFFSET..VECTOR_OFFSET],
            matrix_hat,
        );
        encode_coefficients(
            &mut self.dma.as_mut_slice()[VECTOR_OFFSET..OUTPUT_OFFSET],
            vector,
        );
        self.dma.as_mut_slice()[OUTPUT_OFFSET..TOTAL_BYTES].fill(0);
        let encode = started.elapsed();

        let started = Instant::now();
        self.dma.sync_range_for_device(MATRIX_OFFSET, TOTAL_BYTES)?;
        let sync_for_device = started.elapsed();

        let base = self.dma.phys_addr();
        let started = Instant::now();
        if let Err(error) = self.engine.submit_polling(
            Submission {
                matrix_hat_phys: base + MATRIX_OFFSET as u64,
                vector_phys: base + VECTOR_OFFSET as u64,
                output_phys: base + OUTPUT_OFFSET as u64,
            },
            timeout,
        ) {
            self.healthy = false;
            return Err(io::Error::other(error));
        }
        let hardware = started.elapsed();

        let started = Instant::now();
        self.dma
            .sync_range_for_cpu(OUTPUT_OFFSET, TOTAL_BYTES - OUTPUT_OFFSET)?;
        let sync_for_cpu = started.elapsed();

        let started = Instant::now();
        let output = decode_coefficients(&self.dma.as_slice()[OUTPUT_OFFSET..TOTAL_BYTES]);
        validate_output(&output).inspect_err(|_| self.healthy = false)?;
        let decode_validate = started.elapsed();

        let started = Instant::now();
        self.dma.clear_range(MATRIX_OFFSET, TOTAL_BYTES)?;
        let scrub = started.elapsed();
        let total = total_started.elapsed();
        Ok((
            output,
            Mldsa65Timings {
                encode,
                sync_for_device,
                hardware,
                sync_for_cpu,
                decode_validate,
                scrub,
                total,
            },
        ))
    }
}

pub fn execute_mldsa65_matvec(
    matrix_hat: &[i32],
    vector: &[i32],
    timeout: Duration,
) -> io::Result<Vec<i32>> {
    Mldsa65Session::open()?.execute(matrix_hat, vector, timeout)
}

fn validate_inputs(matrix_hat: &[i32], vector: &[i32]) -> io::Result<()> {
    validate_matrix(matrix_hat)?;
    validate_vector(vector)
}

fn validate_matrix(matrix_hat: &[i32]) -> io::Result<()> {
    if matrix_hat.len() != MATRIX_COEFFICIENTS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid ML-DSA-65 matrix dimensions",
        ));
    }
    if matrix_hat
        .iter()
        .any(|&coefficient| !(0..MLDSA_Q).contains(&coefficient))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "non-canonical ML-DSA matrix coefficient",
        ));
    }
    Ok(())
}

fn validate_vector(vector: &[i32]) -> io::Result<()> {
    if vector.len() != VECTOR_COEFFICIENTS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid ML-DSA-65 vector dimensions",
        ));
    }
    if vector
        .iter()
        .any(|&coefficient| !(-MLDSA_Q + 1..MLDSA_Q).contains(&coefficient))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ML-DSA vector coefficient outside supported range",
        ));
    }
    Ok(())
}

fn validate_output(output: &[i32]) -> io::Result<()> {
    if output
        .iter()
        .any(|&coefficient| !(0..MLDSA_Q).contains(&coefficient))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "FPGA returned a non-canonical ML-DSA coefficient",
        ));
    }
    Ok(())
}

fn encode_coefficients(destination: &mut [u8], coefficients: &[i32]) {
    debug_assert_eq!(destination.len(), coefficients.len() * COEFFICIENT_BYTES);
    for (bytes, coefficient) in destination.chunks_mut(COEFFICIENT_BYTES).zip(coefficients) {
        bytes.copy_from_slice(&coefficient.to_le_bytes());
    }
}

fn decode_coefficients(source: &[u8]) -> Vec<i32> {
    source
        .chunks(COEFFICIENT_BYTES)
        .map(|bytes| i32::from_le_bytes(bytes.try_into().expect("four-byte chunk")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resident_layout_is_aligned_contiguous_and_sized() {
        assert_eq!(VECTOR_OFFSET, MATRIX_COEFFICIENTS * COEFFICIENT_BYTES);
        assert_eq!(
            OUTPUT_OFFSET,
            VECTOR_OFFSET + VECTOR_COEFFICIENTS * COEFFICIENT_BYTES
        );
        assert_eq!(
            TOTAL_BYTES,
            OUTPUT_OFFSET + OUTPUT_COEFFICIENTS * COEFFICIENT_BYTES
        );
        for offset in [MATRIX_OFFSET, VECTOR_OFFSET, OUTPUT_OFFSET, TOTAL_BYTES] {
            assert_eq!(offset & 63, 0);
        }
    }

    #[test]
    fn coefficient_wire_format_is_signed_little_endian() {
        let input = [0, 1, -1, 8_380_416];
        let mut encoded = [0_u8; 16];
        encode_coefficients(&mut encoded, &input);
        assert_eq!(&encoded[8..12], &[0xff, 0xff, 0xff, 0xff]);
        assert_eq!(decode_coefficients(&encoded), input);
    }

    #[test]
    fn rejects_wrong_dimensions_and_unsafe_coefficients() {
        let mut matrix = vec![0; MATRIX_COEFFICIENTS];
        let mut vector = vec![0; VECTOR_COEFFICIENTS];
        assert!(validate_inputs(&matrix[..MATRIX_COEFFICIENTS - 1], &vector).is_err());
        matrix[0] = MLDSA_Q;
        assert!(validate_inputs(&matrix, &vector).is_err());
        matrix[0] = 0;
        vector[0] = -MLDSA_Q;
        assert!(validate_inputs(&matrix, &vector).is_err());
        vector[0] = MLDSA_Q - 1;
        assert!(validate_inputs(&matrix, &vector).is_ok());
    }
}
