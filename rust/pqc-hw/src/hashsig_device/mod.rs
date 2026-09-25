//! Driver for the `hashsig` profile's hash-signature scheme engine (ABI v1).
//!
//! The hardware contract is `pqctoday-cacp` `fpga/hashsig/ABI.md` +
//! `fpga/hashsig/hashsig_abi.hpp`. This module follows it step for step:
//!
//! * [`abi`]: packed request / completion / `Caps` records, parameter-set
//!   tables and input encoding (ABI.md §4–§7).
//! * [`Engine`]: the submission sequence of ABI.md §3 for one engine
//!   instance, generic over the register window ([`RegisterIo`]) and the DMA
//!   buffer ([`DmaRegion`]) so the same code runs against the real UIO/u-dma-buf
//!   mappings ([`device`], Linux) and the register simulator ([`sim`]).
//! * [`pool`]: per-instance sessions, `try_lock` + timeout + ARM fallback,
//!   degradation/recovery, and the per-hash-family routing policy.
//!
//! The engine is stateless compute: it never sees or advances an LMS/XMSS
//! index, and the only secrets that enter it (SK.seed, SEED, SK_SEED) are
//! zeroed from the DMA buffer by the engine after it reads them and again,
//! with the whole buffer, by this driver after every command.

pub mod abi;
#[cfg(unix)]
pub mod device;
pub mod pool;
pub mod sim;

use crate::keccak::RegisterIo;
use abi::{
    Caps, Command, Completion, HashFamily, InputError, Operation, ParamSet, Request, Status,
    ABI_VERSION, AP_DONE, AP_IDLE, AP_START, COMPLETION_BYTES, COMPLETION_MAGIC, DMA_ALIGNMENT,
    DMA_MAX_BYTES, DMA_MIN_BYTES, REG_AP_CTRL, REG_DMA_BYTES, REG_DMA_HI, REG_DMA_LO, REG_RETURN,
    REQUEST_BYTES, REQUEST_MAGIC,
};
use std::collections::HashMap;
use std::fmt;
use std::io;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// DMA layout used for every single-record request (ABI.md §4: input and
/// output 64-byte aligned, after the 64-byte request, not overlapping).
pub const INPUT_OFFSET: usize = 0x40;
/// Largest input is 160 bytes (SLH_SIGN): 0x40 + 0xa0 = 0xe0 ≤ 0x100.
pub const OUTPUT_OFFSET: usize = 0x100;
/// Tenant tag echoed by the engine ("PQCT"). The engine keeps no tenant state.
pub const TENANT_TAG: u32 = 0x5051_4354;
/// Minimum driver timeout (ABI.md §9: `max(1 s, 4 × estimate)`).
pub const MIN_TIMEOUT: Duration = Duration::from_secs(1);
/// Input slot per request-table record (largest input 160, 64-byte aligned).
pub const INPUT_SLOT: usize = 192;

fn align(offset: usize) -> usize {
    offset.div_ceil(DMA_ALIGNMENT) * DMA_ALIGNMENT
}

/// The DMA buffer shared with one engine instance.
///
/// The KV260 image does not mark the u-dma-buf `dma-coherent`, so every
/// hand-over is bracketed by explicit cache maintenance (ABI.md §2).
pub trait DmaRegion {
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Bus address the engine uses (DMA_LO/DMA_HI).
    fn phys_addr(&self) -> u64;
    /// Copy `data` into the buffer at `offset`.
    fn write(&mut self, offset: usize, data: &[u8]);
    /// Copy `out.len()` bytes from `offset`.
    fn read(&self, offset: usize, out: &mut [u8]);
    fn sync_for_device(&mut self, offset: usize, len: usize) -> io::Result<()>;
    fn sync_for_cpu(&mut self, offset: usize, len: usize) -> io::Result<()>;
    /// Zero the whole buffer and make the zeroes device-visible.
    fn scrub(&mut self) -> io::Result<()>;
}

#[cfg(unix)]
impl DmaRegion for crate::dma::Buffer {
    fn len(&self) -> usize {
        crate::dma::Buffer::len(self)
    }
    fn phys_addr(&self) -> u64 {
        crate::dma::Buffer::phys_addr(self)
    }
    fn write(&mut self, offset: usize, data: &[u8]) {
        self.as_mut_slice()[offset..offset + data.len()].copy_from_slice(data);
    }
    fn read(&self, offset: usize, out: &mut [u8]) {
        out.copy_from_slice(&self.as_slice()[offset..offset + out.len()]);
    }
    fn sync_for_device(&mut self, offset: usize, len: usize) -> io::Result<()> {
        self.sync_range_for_device(offset, len)
    }
    fn sync_for_cpu(&mut self, offset: usize, len: usize) -> io::Result<()> {
        self.sync_range_for_cpu(offset, len)
    }
    fn scrub(&mut self) -> io::Result<()> {
        self.clear()
    }
}

/// Engine health (ABI.md §3, §5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Health {
    Ready,
    /// A timeout, an invalid completion, `RootMismatch` or `InternalError`.
    /// Restored only by `RESET_CORE` + a known-answer `SLH_KEYGEN` (or
    /// MERKLE_SUBTREE when no SLH-DSA set is claimed) once `ap_idle` is seen.
    Degraded,
    /// `ScrubFailure`: never used again by this process.
    Disabled,
}

#[derive(Debug)]
pub enum Error {
    /// The engine was not idle at submission; nothing was written.
    Busy,
    /// No `ap_done` within the timeout. The command keeps running (HLS
    /// `ap_ctrl_hs` has no abort); the engine is now degraded.
    Timeout,
    /// The engine is degraded or disabled; nothing was submitted.
    Unavailable(Health),
    /// Driver-side input check failed; nothing was submitted.
    Input(InputError),
    /// The engine refused the command without a fault (unsupported command or
    /// parameter set, or a descriptor/input the engine considers invalid,
    /// which is a driver bug). Health is unchanged.
    Rejected(Status),
    /// The engine reported a fault (`RootMismatch`, `InternalError`,
    /// `ScrubFailure`). The engine is now degraded or disabled.
    Fault(Status),
    /// The completion record did not match the request. Hardware failure.
    BadCompletion(&'static str),
    /// DMA cache maintenance failed.
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Busy => write!(f, "hashsig engine busy"),
            Self::Timeout => write!(f, "hashsig engine timed out"),
            Self::Unavailable(health) => write!(f, "hashsig engine unavailable ({health:?})"),
            Self::Input(error) => write!(f, "hashsig input rejected by driver: {error:?}"),
            Self::Rejected(status) => write!(f, "hashsig engine rejected command: {status}"),
            Self::Fault(status) => write!(f, "hashsig engine fault: {status}"),
            Self::BadCompletion(what) => write!(f, "hashsig completion invalid: {what}"),
            Self::Io(error) => write!(f, "hashsig DMA sync failed: {error}"),
        }
    }
}

impl std::error::Error for Error {}

/// A successful command.
#[derive(Debug)]
pub struct Output {
    /// Payload bytes (public: signatures, roots, auth nodes, `Caps`).
    pub payload: Vec<u8>,
    pub hash_steps: u64,
    pub lanes: u32,
    pub elapsed: Duration,
}

/// Per-hash-operation cost used for the first timeout of a
/// (command, param set, k) before its wall time has been learned. Deliberately
/// pessimistic (about 2× the Phase 4/5 model: 26 cycles per Keccak-f[1600] on
/// one lane, SHA2-128s sign ≈ 1.45 s at 250 MHz on one generic lane).
const SHAKE_OP_NS: u64 = 250;
const SHA2_OP_NS: u64 = 1_200;

/// One engine instance: its register window and its DMA buffer.
pub struct Engine<R, D> {
    registers: R,
    dma: D,
    request_id: u64,
    health: Health,
    /// Wall time of the first successful completion of each
    /// (command, param set, k): hash_steps is deterministic in those (§9).
    learned: HashMap<(u32, u32, u32), Duration>,
    caps: Option<Caps>,
    /// A timed-out command may still write the buffer until `ap_idle`.
    awaiting_idle: bool,
}

impl<R: RegisterIo, D: DmaRegion> Engine<R, D> {
    /// Wraps an engine instance. The DMA buffer is validated against the ABI
    /// limits and scrubbed before first use.
    pub fn new(registers: R, mut dma: D) -> io::Result<Self> {
        let len = dma.len();
        if len < DMA_MIN_BYTES || len as u64 > DMA_MAX_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "hashsig DMA buffer size outside the ABI range",
            ));
        }
        if dma.phys_addr() == 0 || !dma.phys_addr().is_multiple_of(DMA_ALIGNMENT as u64) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "hashsig DMA buffer is not 64-byte aligned",
            ));
        }
        dma.scrub()?;
        Ok(Self {
            registers,
            dma,
            request_id: 0,
            health: Health::Ready,
            learned: HashMap::new(),
            caps: None,
            awaiting_idle: false,
        })
    }

    pub fn health(&self) -> Health {
        self.health
    }

    pub fn caps(&self) -> Option<&Caps> {
        self.caps.as_ref()
    }

    /// Mark the engine degraded (e.g. a caller-side check of its output failed).
    pub fn mark_degraded(&mut self) {
        if self.health == Health::Ready {
            self.health = Health::Degraded;
        }
    }

    pub fn into_parts(self) -> (R, D) {
        (self.registers, self.dma)
    }

    pub fn registers_mut(&mut self) -> &mut R {
        &mut self.registers
    }

    /// Reads AP_CTRL once. `ap_done` is clear-on-read, so this is only used
    /// when no command is outstanding.
    pub fn is_idle(&mut self) -> bool {
        let idle = self.registers.read32(REG_AP_CTRL) & AP_IDLE != 0;
        if idle {
            self.awaiting_idle = false;
        }
        idle
    }

    /// QUERY_CAPS. Also caches the result for timeout estimates.
    pub fn query_caps(&mut self) -> Result<Caps, Error> {
        let output = self.execute(&Operation::QueryCaps, None)?;
        let caps = Caps::decode(&output.payload);
        self.caps = Some(caps);
        Ok(caps)
    }

    /// SCRUB: zero every secret-bearing engine memory on demand.
    pub fn scrub(&mut self) -> Result<(), Error> {
        self.execute(&Operation::Scrub, None).map(|_| ())
    }

    /// Restore a degraded engine: wait for `ap_idle`, `RESET_CORE` (which
    /// scrubs and reads every word back), then a known-answer command whose
    /// payload must equal `expected`. Returns the new health.
    pub fn recover(&mut self, kat: &Operation<'_>, expected: &[u8]) -> Health {
        if self.health != Health::Degraded {
            return self.health;
        }
        if !self.is_idle() {
            return self.health;
        }
        if self.dma.scrub().is_err() {
            return self.health;
        }
        match self.submit(&Operation::ResetCore, None) {
            Ok(_) => {}
            Err(Error::Fault(Status::ScrubFailure)) => {
                self.health = Health::Disabled;
                return self.health;
            }
            Err(_) => return self.health,
        }
        match self.submit(kat, None) {
            Ok(output) if output.payload.as_slice() == expected => {
                self.health = Health::Ready;
            }
            Ok(_) => {}
            Err(Error::Fault(Status::ScrubFailure)) => self.health = Health::Disabled,
            Err(_) => {}
        }
        self.health
    }

    /// Runs one command (ABI.md §3 steps 2–8). The caller holds the engine
    /// lock (step 1). `timeout = None` uses §9's `max(1 s, 4 × estimate)`.
    pub fn execute(&mut self, op: &Operation<'_>, timeout: Option<Duration>) -> Result<Output, Error> {
        if self.health != Health::Ready {
            return Err(Error::Unavailable(self.health));
        }
        self.submit(op, timeout)
    }

    /// Runs up to `MAX_BATCH` commands in one start as a request table
    /// (ABI.md §4.1). The outer `Err` is a failure of the whole submission
    /// (busy, timeout, invalid completion, ...); otherwise each record has its
    /// own result, in order. A record the engine refused does not stop the
    /// ones after it, exactly as in the engine.
    pub fn execute_batch(
        &mut self,
        ops: &[Operation<'_>],
        timeout: Option<Duration>,
    ) -> Result<Vec<Result<Output, Error>>, Error> {
        if self.health != Health::Ready {
            return Err(Error::Unavailable(self.health));
        }
        self.submit_batch(ops, timeout)
    }

    fn submit(&mut self, op: &Operation<'_>, timeout: Option<Duration>) -> Result<Output, Error> {
        self.submit_batch(std::slice::from_ref(op), timeout)?
            .pop()
            .expect("one record, one result")
    }

    /// Largest request table this engine accepts.
    pub fn max_batch(&self) -> usize {
        self.caps
            .map_or(1, |c| c.max_batch.clamp(1, abi::MAX_BATCH) as usize)
    }

    fn submit_batch(
        &mut self,
        ops: &[Operation<'_>],
        timeout: Option<Duration>,
    ) -> Result<Vec<Result<Output, Error>>, Error> {
        let records = ops.len();
        if records == 0 || records > abi::MAX_BATCH as usize || (records > 1 && records > self.max_batch()) {
            return Err(Error::Input(InputError::FieldLength));
        }
        // Encode (and range-check) every input before touching the device.
        // Layout: the request table, then one 192-byte input slot per record
        // (the largest input is 160), then the output regions, all 64-byte
        // aligned. A single record lands at 0x40 / 0x100 (INPUT_OFFSET,
        // OUTPUT_OFFSET).
        let table = REQUEST_BYTES * records;
        let mut inputs = Vec::with_capacity(records);
        let mut payload_lens = Vec::with_capacity(records);
        let mut estimate = Duration::ZERO;
        for op in ops {
            let payload_len = op.payload_bytes().map_err(Error::Input)?;
            let param = op.decoded_param().map_err(Error::Input)?;
            let mut input = Zeroizing::new(vec![0u8; op.command().input_len()]);
            op.encode_input(&mut input).map_err(Error::Input)?;
            estimate = estimate.saturating_add(self.estimate_for(op, param.as_ref()));
            inputs.push(input);
            payload_lens.push(payload_len);
        }
        let input_base = table;
        let output_base = align(input_base + INPUT_SLOT * records).max(OUTPUT_OFFSET);
        let mut output_offsets = Vec::with_capacity(records);
        let mut end = output_base;
        for payload_len in &payload_lens {
            output_offsets.push(end);
            end = align(end + COMPLETION_BYTES + payload_len);
        }
        if end > self.dma.len() {
            return Err(Error::Input(InputError::FieldLength));
        }

        // Step 2: require ap_idle (one read; a latched value, never re-read).
        if self.awaiting_idle || self.registers.read32(REG_AP_CTRL) & AP_IDLE == 0 {
            return Err(Error::Busy);
        }

        let mut requests = Vec::with_capacity(records);
        for (index, op) in ops.iter().enumerate() {
            self.request_id = self.request_id.wrapping_add(1).max(1);
            let input_len = inputs[index].len();
            requests.push(Request {
                magic: REQUEST_MAGIC,
                abi_version: ABI_VERSION,
                header_bytes: REQUEST_BYTES as u16,
                total_bytes: if index == 0 { table as u32 } else { REQUEST_BYTES as u32 },
                command: op.command() as u32,
                flags: 0,
                param_set: op.param_set(),
                request_id: self.request_id,
                input_offset: if input_len == 0 {
                    0
                } else {
                    (input_base + INPUT_SLOT * index) as u32
                },
                input_length: input_len as u32,
                output_offset: output_offsets[index] as u32,
                output_length: (COMPLETION_BYTES + payload_lens[index]) as u32,
                tenant_tag: TENANT_TAG,
                reserved: [0; 3],
            });
        }
        let timeout = timeout.unwrap_or(MIN_TIMEOUT.max(estimate.saturating_mul(4)));
        let started = Instant::now();
        let result = self.run(&requests, &inputs, timeout);
        // Step 8 (every path): the whole buffer is zeroed before the lock is
        // released, so no secret input or output survives the command.
        let scrubbed = self.dma.scrub();
        let completed = match result {
            Ok(done) => done,
            Err(error) => {
                if matches!(error, Error::Timeout | Error::BadCompletion(_) | Error::Io(_)) {
                    self.mark_degraded();
                }
                return Err(error);
            }
        };
        if let Err(error) = scrubbed {
            self.mark_degraded();
            return Err(Error::Io(error));
        }
        let elapsed = started.elapsed();
        let per_record = elapsed / records as u32;
        let mut results = Vec::with_capacity(records);
        for ((status, completion, payload), op) in completed.into_iter().zip(ops) {
            results.push(match status {
                Status::Success => {
                    self.learned
                        .entry((op.command() as u32, op.param_set(), op.subtree_height()))
                        .or_insert(per_record);
                    Ok(Output {
                        payload,
                        hash_steps: completion.hash_steps,
                        lanes: completion.lanes,
                        elapsed: per_record,
                    })
                }
                Status::UnsupportedCommand
                | Status::UnsupportedParameterSet
                | Status::BadDescriptor
                | Status::InvalidInput => Err(Error::Rejected(status)),
                Status::RootMismatch | Status::InternalError => {
                    self.mark_degraded();
                    Err(Error::Fault(status))
                }
                Status::ScrubFailure => {
                    self.health = Health::Disabled;
                    Err(Error::Fault(status))
                }
            });
        }
        Ok(results)
    }

    /// Steps 3–7. Returns each record's status, completion and payload.
    fn run(
        &mut self,
        requests: &[Request],
        inputs: &[Zeroizing<Vec<u8>>],
        timeout: Duration,
    ) -> Result<Vec<(Status, Completion, Vec<u8>)>, Error> {
        // Step 3: the request table at offset 0, each input at its
        // input_offset. The rest of the buffer is already zero (scrubbed
        // after the previous command).
        for (index, (request, input)) in requests.iter().zip(inputs).enumerate() {
            let mut record = [0u8; REQUEST_BYTES];
            request.encode(&mut record);
            self.dma.write(REQUEST_BYTES * index, &record);
            if !input.is_empty() {
                self.dma.write(request.input_offset as usize, input);
            }
        }
        // Step 4: sync_for_device over the whole buffer.
        let len = self.dma.len();
        self.dma.sync_for_device(0, len).map_err(Error::Io)?;
        // Step 5: DMA address and size, then ap_start.
        let phys = self.dma.phys_addr();
        self.registers.write32(REG_DMA_LO, phys as u32);
        self.registers.write32(REG_DMA_HI, (phys >> 32) as u32);
        self.registers.write32(REG_DMA_BYTES, len as u32);
        self.registers.write32(REG_AP_CTRL, AP_START);
        // Step 6: wait for ap_done. Polling backs off to a sleep so a
        // long SLH-DSA command does not occupy an ARM core.
        let deadline = Instant::now() + timeout;
        let mut spins = 0u32;
        loop {
            let control = self.registers.read32(REG_AP_CTRL);
            if control & AP_DONE != 0 {
                break;
            }
            if Instant::now() >= deadline {
                self.awaiting_idle = true;
                return Err(Error::Timeout);
            }
            if spins < 256 {
                spins += 1;
                std::hint::spin_loop();
            } else {
                let step = Duration::from_micros(u64::from((spins - 255).min(1000)));
                spins = spins.saturating_add(16);
                std::thread::sleep(step);
            }
        }
        // Step 7: sync_for_cpu, RETURN, completions.
        self.dma.sync_for_cpu(0, len).map_err(Error::Io)?;
        let returned = self.registers.read32(REG_RETURN) as i32;
        let mut first_failure = 0;
        let mut done = Vec::with_capacity(requests.len());
        for request in requests {
            let output = request.output_offset as usize;
            let mut record = [0u8; COMPLETION_BYTES];
            self.dma.read(output, &mut record);
            let completion = Completion::decode(&record);
            if completion.magic != COMPLETION_MAGIC {
                return Err(Error::BadCompletion("magic"));
            }
            if completion.abi_version != ABI_VERSION {
                return Err(Error::BadCompletion("abi_version"));
            }
            if usize::from(completion.record_bytes) != COMPLETION_BYTES {
                return Err(Error::BadCompletion("record_bytes"));
            }
            if completion.request_id != request.request_id {
                return Err(Error::BadCompletion("request_id"));
            }
            if completion.command != request.command {
                return Err(Error::BadCompletion("command"));
            }
            if completion.tenant_tag != request.tenant_tag {
                return Err(Error::BadCompletion("tenant_tag"));
            }
            let Some(status) = Status::from_i32(completion.status) else {
                return Err(Error::BadCompletion("unknown status"));
            };
            if first_failure == 0 {
                first_failure = completion.status;
            }
            let payload_len = request.output_length as usize - COMPLETION_BYTES;
            if status == Status::Success {
                if completion.output_bytes as usize != payload_len {
                    return Err(Error::BadCompletion("output_bytes"));
                }
                let mut payload = vec![0u8; payload_len];
                self.dma.read(output + COMPLETION_BYTES, &mut payload);
                done.push((status, completion, payload));
            } else {
                if completion.output_bytes != 0 {
                    return Err(Error::BadCompletion("payload on failure"));
                }
                done.push((status, completion, Vec::new()));
            }
        }
        // RETURN is 0, or the status of the first record that failed.
        if returned != first_failure {
            return Err(Error::BadCompletion("status differs from RETURN"));
        }
        Ok(done)
    }

    /// Estimated engine time of one command: the learned wall time of this
    /// (command, param set, k), or the pessimistic cost model.
    fn estimate_for(&self, op: &Operation<'_>, param: Option<&ParamSet>) -> Duration {
        let key = (op.command() as u32, op.param_set(), op.subtree_height());
        if let Some(learned) = self.learned.get(&key) {
            return *learned;
        }
        let ops = abi::estimated_hash_ops(op.command(), param, op.subtree_height());
        let (per_op, lanes) = match param.map(ParamSet::family) {
            Some(HashFamily::Sha2) => (
                SHA2_OP_NS,
                self.caps.map_or(1, |c| c.lanes_for(HashFamily::Sha2)),
            ),
            _ => (
                SHAKE_OP_NS,
                self.caps.map_or(1, |c| c.lanes_for(HashFamily::Shake)),
            ),
        };
        Duration::from_nanos(ops.saturating_mul(per_op) / u64::from(lanes))
    }

    /// ABI.md §9: `max(1 s, 4 × estimate)`; the estimate is the learned wall
    /// time of this (command, param set, k), or the pessimistic cost model.
    pub fn timeout_for(&self, op: &Operation<'_>, param: Option<&ParamSet>) -> Duration {
        MIN_TIMEOUT.max(self.estimate_for(op, param).saturating_mul(4))
    }

    /// Whether a (command, param set, k) already has a learned wall time.
    pub fn learned_time(&self, command: Command, param_set: u32, k: u32) -> Option<Duration> {
        self.learned.get(&(command as u32, param_set, k)).copied()
    }
}
