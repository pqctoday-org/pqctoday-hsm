//! Linux UIO/DMA transport for the resident ML-DSA-65 matrix/vector engine.

use crate::dma::Buffer;
use crate::mldsa::{Engine, MLDSA65_CONTROL_BASE, Submission};
use crate::uio::Mapping;
use std::io;
use std::time::Duration;

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

pub fn execute_mldsa65_matvec(
    matrix_hat: &[i32],
    vector: &[i32],
    timeout: Duration,
) -> io::Result<Vec<i32>> {
    validate_inputs(matrix_hat, vector)?;

    let uio = Mapping::find_by_address("/sys/class/uio", MLDSA65_CONTROL_BASE)?;
    let mut dma = Buffer::open("/dev/pqc-accel-dma", "/sys/class/u-dma-buf/pqc-accel-dma")?;
    if dma.len() < TOTAL_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DMA buffer too small for ML-DSA-65 resident command",
        ));
    }

    encode_coefficients(
        &mut dma.as_mut_slice()[MATRIX_OFFSET..VECTOR_OFFSET],
        matrix_hat,
    );
    encode_coefficients(
        &mut dma.as_mut_slice()[VECTOR_OFFSET..OUTPUT_OFFSET],
        vector,
    );
    dma.as_mut_slice()[OUTPUT_OFFSET..TOTAL_BYTES].fill(0);
    dma.sync_for_device()?;

    let base = dma.phys_addr();
    Engine::new(Mapping::open(uio, 0x10000)?)
        .submit_polling(
            Submission {
                matrix_hat_phys: base + MATRIX_OFFSET as u64,
                vector_phys: base + VECTOR_OFFSET as u64,
                output_phys: base + OUTPUT_OFFSET as u64,
            },
            timeout,
        )
        .map_err(io::Error::other)?;

    dma.sync_for_cpu()?;
    let output = decode_coefficients(&dma.as_slice()[OUTPUT_OFFSET..TOTAL_BYTES]);
    if output
        .iter()
        .any(|&coefficient| !(0..MLDSA_Q).contains(&coefficient))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "FPGA returned a non-canonical ML-DSA coefficient",
        ));
    }
    dma.clear()?;
    Ok(output)
}

fn validate_inputs(matrix_hat: &[i32], vector: &[i32]) -> io::Result<()> {
    if matrix_hat.len() != MATRIX_COEFFICIENTS || vector.len() != VECTOR_COEFFICIENTS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid ML-DSA-65 matrix/vector dimensions",
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

fn encode_coefficients(destination: &mut [u8], coefficients: &[i32]) {
    debug_assert_eq!(destination.len(), coefficients.len() * COEFFICIENT_BYTES);
    for (bytes, coefficient) in destination
        .chunks_exact_mut(COEFFICIENT_BYTES)
        .zip(coefficients)
    {
        bytes.copy_from_slice(&coefficient.to_le_bytes());
    }
}

fn decode_coefficients(source: &[u8]) -> Vec<i32> {
    source
        .chunks_exact(COEFFICIENT_BYTES)
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
