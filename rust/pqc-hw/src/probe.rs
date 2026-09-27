//! Optional hardware probe. Failure leaves the software HSM usable.
use crate::dma::Buffer;
use crate::keccak::{Engine, Submission};
use crate::uio::Mapping;
use std::io;
use std::time::Duration;

const EXPECTED: [u8; 32] = [
    0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2, 0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
    0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b, 0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32,
];

pub fn sha3_256_self_test() -> io::Result<()> {
    let uio = Mapping::find_by_address("/sys/class/uio", 0xa000_0000)?;
    let mut dma = Buffer::open("/dev/pqc-accel-dma", "/sys/class/u-dma-buf/pqc-accel-dma")?;
    if dma.len() < 128 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DMA buffer too small",
        ));
    }
    let base = dma.phys_addr();
    let memory = dma.as_mut_slice();
    memory[..128].fill(0);
    // 32-byte KeccakJob at 0; input at 64; output at 96.
    memory[16..20].copy_from_slice(&3_u32.to_le_bytes());
    memory[20..24].copy_from_slice(&32_u32.to_le_bytes());
    memory[24..28].copy_from_slice(&1_u32.to_le_bytes());
    memory[64..67].copy_from_slice(b"abc");
    dma.sync_for_device()?;
    let mut engine = Engine::new(Mapping::open(uio, 0x10000)?);
    let result = engine.submit_polling(
        Submission {
            jobs_phys: base,
            count: 1,
            input_phys: base + 64,
            input_capacity: 3,
            output_phys: base + 96,
            output_capacity: 32,
        },
        Duration::from_secs(2),
    );
    if let Err(error) = result {
        return Err(io::Error::other(error));
    }
    dma.sync_for_cpu()?;
    if dma.as_slice()[96..128] != EXPECTED {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "FPGA SHA3-256 known-answer mismatch",
        ));
    }
    Ok(())
}
