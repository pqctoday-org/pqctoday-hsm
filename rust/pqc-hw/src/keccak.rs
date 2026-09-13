use std::fmt;
use std::time::{Duration, Instant};

pub const CONTROL: usize = 0x00;
pub const GIER: usize = 0x04;
pub const IP_IER: usize = 0x08;
pub const IP_ISR: usize = 0x0c;
pub const RETURN: usize = 0x10;
pub const JOBS: usize = 0x18;
pub const COUNT: usize = 0x24;
pub const INPUT: usize = 0x2c;
pub const INPUT_CAPACITY: usize = 0x38;
pub const OUTPUT: usize = 0x44;
pub const OUTPUT_CAPACITY: usize = 0x50;

const AP_START: u32 = 1 << 0;
const AP_DONE: u32 = 1 << 1;
const AP_IDLE: u32 = 1 << 2;
pub(crate) const AP_DONE_FOR_SIM: u32 = AP_DONE;
pub(crate) const AP_IDLE_FOR_SIM: u32 = AP_IDLE;

pub trait RegisterIo {
    fn read32(&mut self, offset: usize) -> u32;
    fn write32(&mut self, offset: usize, value: u32);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Mode {
    Sha3_256 = 1,
    Sha3_512 = 2,
    Shake128 = 3,
    Shake256 = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct Job {
    pub input_offset: u64,
    pub output_offset: u64,
    pub input_length: u32,
    pub output_length: u32,
    pub mode: u32,
    pub flags: u32,
}
const _: () = assert!(std::mem::size_of::<Job>() == 32);

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    Busy,
    Timeout,
    Hardware(i32),
    InvalidAddress,
    TooManyJobs,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug)]
pub struct Submission {
    pub jobs_phys: u64,
    pub count: u32,
    pub input_phys: u64,
    pub input_capacity: u64,
    pub output_phys: u64,
    pub output_capacity: u64,
}

pub struct Engine<R> {
    registers: R,
}
impl<R: RegisterIo> Engine<R> {
    pub fn new(registers: R) -> Self {
        Self { registers }
    }
    pub fn into_inner(self) -> R {
        self.registers
    }

    pub fn submit_polling(&mut self, job: Submission, timeout: Duration) -> Result<(), Error> {
        if job.count > 4096 {
            return Err(Error::TooManyJobs);
        }
        if job.count != 0 && (job.jobs_phys == 0 || job.input_phys == 0 || job.output_phys == 0) {
            return Err(Error::InvalidAddress);
        }
        if self.registers.read32(CONTROL) & AP_IDLE == 0 {
            return Err(Error::Busy);
        }
        self.write64(JOBS, job.jobs_phys);
        self.registers.write32(COUNT, job.count);
        self.write64(INPUT, job.input_phys);
        self.write64(INPUT_CAPACITY, job.input_capacity);
        self.write64(OUTPUT, job.output_phys);
        self.write64(OUTPUT_CAPACITY, job.output_capacity);
        self.registers.write32(CONTROL, AP_START);
        let deadline = Instant::now() + timeout;
        loop {
            if self.registers.read32(CONTROL) & AP_DONE != 0 {
                let status = self.registers.read32(RETURN) as i32;
                return if status == 0 {
                    Ok(())
                } else {
                    Err(Error::Hardware(status))
                };
            }
            if Instant::now() >= deadline {
                return Err(Error::Timeout);
            }
            std::hint::spin_loop();
        }
    }
    pub fn enable_completion_interrupt(&mut self) {
        self.registers.write32(GIER, 1);
        self.registers.write32(IP_IER, 1);
    }
    pub fn acknowledge_interrupt(&mut self) {
        self.registers.write32(IP_ISR, 1);
    }
    fn write64(&mut self, offset: usize, value: u64) {
        self.registers.write32(offset, value as u32);
        self.registers.write32(offset + 4, (value >> 32) as u32);
    }
}
