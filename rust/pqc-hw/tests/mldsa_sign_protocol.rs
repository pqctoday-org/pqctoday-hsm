use pqc_hw::keccak::RegisterIo;
use pqc_hw::mldsa_sign::{
    DmaController, Error, SignSubmission, Signer, CONTEXT_INFO_OFFSET, DIAGNOSTICS_OFFSET,
    MAILBOX_BASE, MATRIX_BASE, PHASE_DISPATCH, SECRET_BASE, SECRET_MU_OFFSET,
    SECRET_RHO_PRIME_OFFSET, SECRET_S1_OFFSET, SECRET_S2_OFFSET, SECRET_T0_OFFSET, SIGNATURE_BASE,
};
use std::collections::BTreeMap;
use std::time::Duration;

const CONTROL: usize = 0x00;
const RETURN: usize = 0x10;

struct Registers {
    values: BTreeMap<usize, u32>,
    writes: Vec<(usize, u32)>,
    complete: bool,
}

impl Registers {
    fn new(complete: bool) -> Self {
        Self {
            values: BTreeMap::new(),
            writes: Vec::new(),
            complete,
        }
    }

    fn wrote64(&self, offset: usize, value: u64) -> bool {
        self.writes.contains(&(offset, value as u32))
            && self.writes.contains(&(offset + 4, (value >> 32) as u32))
    }
}

impl RegisterIo for Registers {
    fn read32(&mut self, offset: usize) -> u32 {
        if offset == CONTROL {
            if !self.writes.iter().any(|(register, _)| *register == CONTROL) {
                return 1 << 2;
            }
            if self.complete {
                return (1 << 1) | (1 << 2);
            }
            return 1 << 2;
        }
        *self.values.get(&offset).unwrap_or(&0)
    }

    fn write32(&mut self, offset: usize, value: u32) {
        self.writes.push((offset, value));
        self.values.insert(offset, value);
    }
}

#[test]
fn dma_dispatch_writes_phase_size_and_physical_address() {
    let mut controller = DmaController::new(Registers::new(true));
    assert_eq!(
        controller
            .run(
                PHASE_DISPATCH,
                0x40000,
                0x6760_0000,
                Duration::from_millis(10),
            )
            .unwrap(),
        0
    );
    let registers = controller.into_inner();
    assert!(registers.writes.contains(&(0x18, PHASE_DISPATCH)));
    assert!(registers.writes.contains(&(0x20, 0x40000)));
    assert!(registers.wrote64(0x28, 0x6760_0000));
}

#[test]
fn signer_writes_all_resident_buffer_addresses() {
    let mut signer = Signer::new(Registers::new(true));
    signer
        .sign(
            SignSubmission {
                tenant: 0x5051_4354,
                generation: 9,
                attempt_limit: 128,
            },
            Duration::from_millis(10),
        )
        .unwrap();
    let registers = signer.into_inner();

    for (offset, address) in [
        (0x20, MATRIX_BASE),
        (0x3c, SECRET_BASE + SECRET_RHO_PRIME_OFFSET),
        (0x48, SECRET_BASE + SECRET_MU_OFFSET),
        (0x64, SECRET_BASE + SECRET_S1_OFFSET),
        (0x70, SECRET_BASE + SECRET_S2_OFFSET),
        (0x7c, SECRET_BASE + SECRET_T0_OFFSET),
        (0x88, SIGNATURE_BASE),
        (0x94, MAILBOX_BASE + DIAGNOSTICS_OFFSET),
        (0xa0, MAILBOX_BASE + CONTEXT_INFO_OFFSET),
    ] {
        assert!(
            registers.wrote64(offset, address),
            "missing address at 0x{offset:x}"
        );
    }
    assert!(registers.writes.contains(&(0x2c, 0x5051_4354)));
    assert!(registers.writes.contains(&(0x34, 9)));
    assert!(registers.writes.contains(&(0x5c, 128)));
}

#[test]
fn signer_uses_the_selected_lanes_memory_map() {
    const LANE1_MAILBOX: u64 = 0xa003_0000;
    const LANE1_SIGNATURE: u64 = 0xa003_2000;
    let mut signer =
        Signer::new_with_memory_map(Registers::new(true), LANE1_MAILBOX, LANE1_SIGNATURE);
    signer
        .sign(
            SignSubmission {
                tenant: 1,
                generation: 2,
                attempt_limit: 3,
            },
            Duration::from_millis(10),
        )
        .unwrap();
    let registers = signer.into_inner();

    assert!(registers.wrote64(0x88, LANE1_SIGNATURE));
    assert!(registers.wrote64(0x94, LANE1_MAILBOX + DIAGNOSTICS_OFFSET));
    assert!(registers.wrote64(0xa0, LANE1_MAILBOX + CONTEXT_INFO_OFFSET));
}

#[test]
fn rejects_bad_dma_addresses_and_propagates_timeout() {
    for bad_address in [0, 0x6760_0004] {
        let mut controller = DmaController::new(Registers::new(true));
        assert_eq!(
            controller.run(PHASE_DISPATCH, 16, bad_address, Duration::from_millis(1)),
            Err(Error::InvalidAddress)
        );
    }

    let mut signer = Signer::new(Registers::new(false));
    assert_eq!(
        signer.sign(
            SignSubmission {
                tenant: 1,
                generation: 1,
                attempt_limit: 1,
            },
            Duration::ZERO,
        ),
        Err(Error::Timeout)
    );

    let mut failed = Registers::new(true);
    failed.values.insert(RETURN, (-7_i32) as u32);
    let mut signer = Signer::new(failed);
    assert_eq!(
        signer.sign(
            SignSubmission {
                tenant: 1,
                generation: 1,
                attempt_limit: 1,
            },
            Duration::from_millis(1),
        ),
        Ok(-7)
    );
}
