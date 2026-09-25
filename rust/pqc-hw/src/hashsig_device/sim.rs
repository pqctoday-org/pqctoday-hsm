//! Register + DMA simulator of the hashsig engine (ABI.md §10).
//!
//! It models what software can observe: the AXI4-Lite map (clear-on-read
//! `ap_done`/`ap_ready`, toggle-on-write ISR, `ap_start` ignored while busy),
//! the request table and the validation order of §4, input-region zeroing on
//! every path where the input region is valid, output-region zeroing before
//! work, the completion record of §5, the payload sizes of §6 and the `Caps`
//! layout of §6.4. The cryptography itself comes from a [`SimBackend`]: the
//! engine crate's tests plug in the Rust software implementations (fips205,
//! hbs-lms), which is exactly what the fabric must match byte for byte.
//!
//! [`SimRegisters`] and [`SimDma`] are two handles on one shared state, so
//! the driver's [`super::Engine`] runs against it unchanged.

use super::abi::{
    self, Caps, Command, Completion, LmsParam, ParamSet, Request, SlhParam, Status, XmssParam,
    ABI_VERSION, AP_DONE, AP_IDLE, AP_READY, AP_START, AUTH_LEAF_NONE, CAPS_BYTES,
    COMPLETION_BYTES, COMPLETION_MAGIC, DMA_ALIGNMENT, DMA_MAX_BYTES, MAX_BATCH, REG_AP_CTRL,
    REG_DMA_BYTES, REG_DMA_HI, REG_DMA_LO, REG_GIE, REG_IER, REG_ISR, REG_RETURN, REQUEST_BYTES,
    REQUEST_MAGIC,
};
use super::DmaRegion;
use crate::keccak::RegisterIo;
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex, MutexGuard};
use zeroize::Zeroizing;

/// Decoded SLH_SIGN fields handed to the backend.
pub struct SlhSignFields {
    pub sk_seed: Zeroizing<Vec<u8>>,
    pub pk_seed: Vec<u8>,
    pub pk_root: Vec<u8>,
    pub md: Vec<u8>,
    pub idx_tree: u64,
    pub idx_leaf: u32,
}

/// Decoded MERKLE_SUBTREE fields handed to the backend.
pub struct MerkleFields {
    pub seed: Zeroizing<Vec<u8>>,
    pub public: Vec<u8>,
    pub subtree_height: u32,
    pub leaf_start: u32,
    pub auth_leaf: u32,
    pub layer: u32,
    pub tree_address: u64,
}

/// The computation the fabric performs, supplied by the test.
pub trait SimBackend: Send {
    /// SIG_FORS ‖ SIG_HT, or `RootMismatch` when the top root ≠ PK.root.
    fn slh_sign(&self, param: &SlhParam, fields: &SlhSignFields) -> Result<Vec<u8>, Status>;
    /// PK.root.
    fn slh_keygen(&self, param: &SlhParam, sk_seed: &[u8], pk_seed: &[u8]) -> Result<Vec<u8>, Status>;
    /// root ‖ auth[0..k−1].
    fn merkle_lms(&self, param: &LmsParam, fields: &MerkleFields) -> Result<Vec<u8>, Status>;
    fn merkle_xmss(&self, param: &XmssParam, fields: &MerkleFields) -> Result<Vec<u8>, Status>;
}

/// A backend with no cryptography: every command fails with `InternalError`.
/// Enough for protocol tests that only use QUERY_CAPS / SCRUB / RESET_CORE.
pub struct NoBackend;

impl SimBackend for NoBackend {
    fn slh_sign(&self, _: &SlhParam, _: &SlhSignFields) -> Result<Vec<u8>, Status> {
        Err(Status::InternalError)
    }
    fn slh_keygen(&self, _: &SlhParam, _: &[u8], _: &[u8]) -> Result<Vec<u8>, Status> {
        Err(Status::InternalError)
    }
    fn merkle_lms(&self, _: &LmsParam, _: &MerkleFields) -> Result<Vec<u8>, Status> {
        Err(Status::InternalError)
    }
    fn merkle_xmss(&self, _: &XmssParam, _: &MerkleFields) -> Result<Vec<u8>, Status> {
        Err(Status::InternalError)
    }
}

/// Faults a test can inject. Each applies to the next command(s) started.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fault {
    /// The next command never completes (`ap_idle` stays low) until
    /// [`SimHandle::finish_hung`] is called.
    Hang,
    /// The next command completes with this status and no payload.
    Status(Status),
    /// The next successful payload has one byte flipped (a silent fabric fault).
    CorruptPayload,
    /// The next completion carries a wrong `request_id`.
    StaleCompletion,
    /// The next RESET_CORE reports `ScrubFailure`.
    ScrubFailureOnReset,
}

struct State {
    memory: Vec<u8>,
    phys: u64,
    control: u32,
    gie: u32,
    ier: u32,
    isr: u32,
    ret: u32,
    dma_lo: u32,
    dma_hi: u32,
    dma_bytes: u32,
    caps: Caps,
    backend: Box<dyn SimBackend>,
    faults: Vec<Fault>,
    /// A hung command: its request table is run when the test releases it.
    hung: bool,
    executed: HashMap<Command, u64>,
    starts_while_busy: u64,
    /// Every input region the engine read, after it zeroed it. Tests assert
    /// no secret survives in the buffer.
    inputs_left_nonzero: u64,
}

/// Shared simulator state; clone handles freely.
#[derive(Clone)]
pub struct SimHandle(Arc<Mutex<State>>);

impl SimHandle {
    /// A new engine with the given capabilities, a `dma_bytes` buffer at bus
    /// address `phys`, and the given backend.
    pub fn new(caps: Caps, dma_bytes: usize, phys: u64, backend: Box<dyn SimBackend>) -> Self {
        Self(Arc::new(Mutex::new(State {
            memory: vec![0; dma_bytes],
            phys,
            control: AP_IDLE,
            gie: 0,
            ier: 0,
            isr: 0,
            ret: 0,
            dma_lo: 0,
            dma_hi: 0,
            dma_bytes: 0,
            caps,
            backend,
            faults: Vec::new(),
            hung: false,
            executed: HashMap::new(),
            starts_while_busy: 0,
            inputs_left_nonzero: 0,
        })))
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn registers(&self) -> SimRegisters {
        SimRegisters(self.clone())
    }

    pub fn dma(&self) -> SimDma {
        let phys = self.lock().phys;
        SimDma {
            sim: self.clone(),
            phys,
        }
    }

    pub fn inject(&self, fault: Fault) {
        self.lock().faults.push(fault);
    }

    /// Finish a hung command: run it now and raise `ap_done`.
    pub fn finish_hung(&self) {
        let mut state = self.lock();
        if state.hung {
            state.hung = false;
            state.faults.retain(|f| *f != Fault::Hang);
            state.start();
        }
    }

    /// True while a command started under [`Fault::Hang`] is outstanding.
    pub fn is_hung(&self) -> bool {
        self.lock().hung
    }

    pub fn executed(&self, command: Command) -> u64 {
        *self.lock().executed.get(&command).unwrap_or(&0)
    }

    pub fn caps(&self) -> Caps {
        self.lock().caps
    }

    pub fn starts_while_busy(&self) -> u64 {
        self.lock().starts_while_busy
    }

    pub fn inputs_left_nonzero(&self) -> u64 {
        self.lock().inputs_left_nonzero
    }

    /// True when every byte of the DMA buffer is zero.
    pub fn dma_is_zero(&self) -> bool {
        self.lock().memory.iter().all(|b| *b == 0)
    }

    /// Direct access for protocol tests that write raw request tables.
    pub fn with_memory<T>(&self, f: impl FnOnce(&mut [u8]) -> T) -> T {
        f(&mut self.lock().memory)
    }
}

/// The engine's AXI4-Lite window.
pub struct SimRegisters(SimHandle);

impl RegisterIo for SimRegisters {
    fn read32(&mut self, offset: usize) -> u32 {
        let mut state = self.0.lock();
        match offset {
            REG_AP_CTRL => {
                let value = state.control;
                // ap_done and ap_ready are clear-on-read.
                state.control &= !(AP_DONE | AP_READY);
                value
            }
            REG_GIE => state.gie,
            REG_IER => state.ier,
            REG_ISR => state.isr,
            REG_RETURN => state.ret,
            REG_DMA_LO => state.dma_lo,
            REG_DMA_HI => state.dma_hi,
            REG_DMA_BYTES => state.dma_bytes,
            _ => 0,
        }
    }

    fn write32(&mut self, offset: usize, value: u32) {
        let mut state = self.0.lock();
        match offset {
            REG_AP_CTRL => {
                if value & AP_START != 0 {
                    if state.control & AP_IDLE == 0 {
                        // ap_start while not idle has no effect.
                        state.starts_while_busy += 1;
                        return;
                    }
                    state.control &= !AP_IDLE;
                    if state.faults.first() == Some(&Fault::Hang) {
                        state.hung = true;
                        return;
                    }
                    state.start();
                }
            }
            REG_GIE => state.gie = value & 1,
            REG_IER => state.ier = value & 3,
            REG_ISR => state.isr ^= value & 3, // toggle-on-write
            REG_DMA_LO => state.dma_lo = value,
            REG_DMA_HI => state.dma_hi = value,
            REG_DMA_BYTES => state.dma_bytes = value,
            _ => {}
        }
    }
}

/// The engine's DMA buffer, as the driver sees it.
pub struct SimDma {
    sim: SimHandle,
    phys: u64,
}

impl DmaRegion for SimDma {
    fn len(&self) -> usize {
        self.sim.lock().memory.len()
    }
    fn phys_addr(&self) -> u64 {
        self.phys
    }
    fn write(&mut self, offset: usize, data: &[u8]) {
        self.sim.lock().memory[offset..offset + data.len()].copy_from_slice(data);
    }
    fn read(&self, offset: usize, out: &mut [u8]) {
        out.copy_from_slice(&self.sim.lock().memory[offset..offset + out.len()]);
    }
    fn sync_for_device(&mut self, _offset: usize, _len: usize) -> io::Result<()> {
        Ok(())
    }
    fn sync_for_cpu(&mut self, _offset: usize, _len: usize) -> io::Result<()> {
        Ok(())
    }
    fn scrub(&mut self) -> io::Result<()> {
        self.sim.lock().memory.fill(0);
        Ok(())
    }
}

impl State {
    /// Runs the request table (ABI.md §4) and raises `ap_done`.
    fn start(&mut self) {
        let status = self.run_table();
        self.ret = status as u32;
        self.control |= AP_DONE | AP_IDLE | AP_READY;
        if self.gie & 1 != 0 && self.ier & 1 != 0 {
            self.isr |= 1;
        }
    }

    fn run_table(&mut self) -> i32 {
        let address = u64::from(self.dma_lo) | (u64::from(self.dma_hi) << 32);
        let dma_bytes = u64::from(self.dma_bytes);
        // Step 1: DMA_BYTES range. RETURN only, nothing written.
        if !(64..=DMA_MAX_BYTES).contains(&dma_bytes) || dma_bytes > self.memory.len() as u64 {
            return Status::BadDescriptor as i32;
        }
        if address != self.phys {
            // The fabric would read arbitrary DDR; the model refuses.
            return Status::BadDescriptor as i32;
        }
        let first = Request::decode(&self.memory[..REQUEST_BYTES]);
        let records = if first.magic == REQUEST_MAGIC
            && first.abi_version == ABI_VERSION
            && usize::from(first.header_bytes) == REQUEST_BYTES
            && first.total_bytes.is_multiple_of(64)
            && (64..=64 * MAX_BATCH).contains(&first.total_bytes)
        {
            first.total_bytes / 64
        } else {
            1
        };
        let mut result = 0;
        for index in 0..records {
            let status = self.run_record(index as usize, records, dma_bytes as usize);
            if result == 0 && status != 0 {
                result = status;
            }
        }
        result
    }

    fn run_record(&mut self, index: usize, records: u32, dma_bytes: usize) -> i32 {
        let table = 64 * records as usize;
        let request = Request::decode(&self.memory[index * 64..index * 64 + 64]);
        let region_ok = |offset: u32, len: u32| -> bool {
            let (offset, len) = (offset as usize, len as usize);
            offset >= table
                && offset % DMA_ALIGNMENT == 0
                && offset.checked_add(len).is_some_and(|end| end <= dma_bytes)
        };
        let input_valid = request.input_length == 0 && request.input_offset == 0
            || request.input_length != 0 && region_ok(request.input_offset, request.input_length);
        let input = if request.input_length != 0 && input_valid {
            let start = request.input_offset as usize;
            Some(start..start + request.input_length as usize)
        } else {
            None
        };
        // Step 2: the output region must hold a completion, else no completion.
        let output_ok = request.output_length as usize >= COMPLETION_BYTES
            && request.output_offset >= 64
            && region_ok(request.output_offset, request.output_length);
        if !output_ok {
            self.zero_input(input.clone());
            self.caps.commands_failed = self.caps.commands_failed.saturating_add(1);
            return Status::BadDescriptor as i32;
        }
        let out = request.output_offset as usize;
        self.memory[out..out + COMPLETION_BYTES].fill(0);

        let mut status = self.validate(&request, index, records, input_valid, out);
        let command = Command::from_u32(request.command);
        let param = command.and_then(|c| ParamSet::decode(c, request.param_set));
        let mut subtree_height = 0;
        let mut payload = Vec::new();
        if status == Status::Success {
            // Steps 6 and 7 need the decoded command.
            let command = command.expect("validated");
            if let Some(range) = &input
                && command == Command::MerkleSubtree {
                    subtree_height = abi::get_u32(&self.memory[range.clone()], 64);
                }
            let payload_len = abi::payload_bytes(command, param.as_ref(), subtree_height);
            if request.input_length as usize != command.input_len()
                || (request.output_length as usize) < COMPLETION_BYTES + payload_len
            {
                status = Status::BadDescriptor;
            } else {
                let end = out + COMPLETION_BYTES + payload_len;
                self.memory[out + COMPLETION_BYTES..end].fill(0);
                let input_bytes = Zeroizing::new(
                    input
                        .clone()
                        .map(|range| self.memory[range].to_vec())
                        .unwrap_or_default(),
                );
                // The engine reads the input into private memory, then wipes DDR.
                self.zero_input(input.clone());
                match self.execute(command, param, &input_bytes, payload_len) {
                    Ok(bytes) => payload = bytes,
                    Err(error) => status = error,
                }
            }
        }
        self.zero_input(input);
        *self.executed.entry(command.unwrap_or(Command::Scrub)).or_insert(0) += 1;

        let mut completion = Completion {
            magic: COMPLETION_MAGIC,
            abi_version: ABI_VERSION,
            record_bytes: COMPLETION_BYTES as u16,
            status: status as i32,
            fallback_reason: status.fallback_reason(),
            request_id: request.request_id,
            command: request.command,
            param_set: request.param_set,
            output_bytes: 0,
            tenant_tag: request.tenant_tag,
            total_cycles: 0,
            hash_steps: 0,
            lanes: self.caps.lanes,
            reserved: 0,
        };
        if status == Status::Success {
            if let Some(Fault::CorruptPayload) = self.faults.first() {
                self.faults.remove(0);
                if let Some(byte) = payload.last_mut() {
                    *byte ^= 0x01;
                }
            }
            completion.output_bytes = payload.len() as u32;
            let family_lanes = param
                .as_ref()
                .map_or(1, |p| u64::from(self.caps.lanes_for(p.family())));
            completion.hash_steps = command.map_or(0, |c| {
                abi::estimated_hash_ops(c, param.as_ref(), subtree_height) / family_lanes
            });
            let start = out + COMPLETION_BYTES;
            self.memory[start..start + payload.len()].copy_from_slice(&payload);
            self.caps.commands_completed = self.caps.commands_completed.saturating_add(1);
        } else {
            self.caps.commands_failed = self.caps.commands_failed.saturating_add(1);
        }
        if let Some(Fault::StaleCompletion) = self.faults.first() {
            self.faults.remove(0);
            completion.request_id ^= 0x8000_0000_0000_0000;
        }
        completion.encode(&mut self.memory[out..out + COMPLETION_BYTES]);
        // Every command ends with a scrub of every internal memory.
        self.caps.zeroizations = self.caps.zeroizations.saturating_add(1);
        status as i32
    }

    /// Steps 3–5.
    fn validate(
        &self,
        request: &Request,
        index: usize,
        records: u32,
        input_valid: bool,
        out: usize,
    ) -> Status {
        let expected_total = if index == 0 { 64 * records } else { 64 };
        let input_end = request.input_offset as usize + request.input_length as usize;
        let output_end = out + request.output_length as usize;
        let overlap = request.input_length != 0
            && (request.input_offset as usize) < output_end
            && out < input_end;
        if request.magic != REQUEST_MAGIC
            || request.abi_version != ABI_VERSION
            || usize::from(request.header_bytes) != REQUEST_BYTES
            || request.total_bytes != expected_total
            || request.flags != 0
            || request.reserved != [0; 3]
            || request.request_id == 0
            || request.tenant_tag == 0
            || !input_valid
            || overlap
        {
            return Status::BadDescriptor;
        }
        let Some(command) = Command::from_u32(request.command) else {
            return Status::UnsupportedCommand;
        };
        if !self.caps.implements(command) {
            return Status::UnsupportedCommand;
        }
        if command.takes_param_set() {
            // Step 5 checks the claim without the subtree height; the height
            // is a field-level check (step 7).
            if !self.caps.claims(command, request.param_set, 0) {
                return Status::UnsupportedParameterSet;
            }
        } else if request.param_set != 0 {
            return Status::UnsupportedParameterSet;
        }
        Status::Success
    }

    /// Step 7 and the command itself.
    fn execute(
        &mut self,
        command: Command,
        param: Option<ParamSet>,
        input: &[u8],
        payload_len: usize,
    ) -> Result<Vec<u8>, Status> {
        if let Some(Fault::Status(status)) = self.faults.first().copied() {
            self.faults.remove(0);
            return Err(status);
        }
        match (command, param) {
            (Command::QueryCaps, None) => {
                let mut caps = vec![0u8; CAPS_BYTES];
                self.caps.encode(&mut caps);
                Ok(caps)
            }
            (Command::Scrub, None) => Ok(Vec::new()),
            (Command::ResetCore, None) => {
                if let Some(Fault::ScrubFailureOnReset) = self.faults.first() {
                    self.faults.remove(0);
                    return Err(Status::ScrubFailure);
                }
                Ok(Vec::new())
            }
            (Command::SlhSign, Some(ParamSet::Slh(p))) => {
                let n = p.n;
                let md_len = p.md_bytes();
                if !zero_tail(&input[0..32], n)
                    || !zero_tail(&input[32..64], n)
                    || !zero_tail(&input[64..96], n)
                    || !zero_tail(&input[96..144], md_len)
                    || abi::get_u32(input, 156) != 0
                {
                    return Err(Status::InvalidInput);
                }
                let fields = SlhSignFields {
                    sk_seed: Zeroizing::new(input[0..n].to_vec()),
                    pk_seed: input[32..32 + n].to_vec(),
                    pk_root: input[64..64 + n].to_vec(),
                    md: input[96..96 + md_len].to_vec(),
                    idx_tree: abi::get_u64(input, 144),
                    idx_leaf: abi::get_u32(input, 152),
                };
                if fields.idx_tree >> p.idx_tree_bits() != 0 || fields.idx_leaf >> p.hp != 0 {
                    return Err(Status::InvalidInput);
                }
                check_len(self.backend.slh_sign(p, &fields), payload_len)
            }
            (Command::SlhKeygen, Some(ParamSet::Slh(p))) => {
                if !zero_tail(&input[0..32], p.n) || !zero_tail(&input[32..64], p.n) {
                    return Err(Status::InvalidInput);
                }
                let sk_seed = Zeroizing::new(input[0..p.n].to_vec());
                check_len(
                    self.backend.slh_keygen(p, &sk_seed, &input[32..32 + p.n]),
                    payload_len,
                )
            }
            (Command::MerkleSubtree, Some(param)) => {
                let n = param.n();
                let public_len = if matches!(param, ParamSet::Lms(_)) { 16 } else { n };
                let fields = MerkleFields {
                    seed: Zeroizing::new(input[0..n].to_vec()),
                    public: input[32..32 + public_len].to_vec(),
                    subtree_height: abi::get_u32(input, 64),
                    leaf_start: abi::get_u32(input, 68),
                    auth_leaf: abi::get_u32(input, 72),
                    layer: abi::get_u32(input, 76),
                    tree_address: abi::get_u64(input, 80),
                };
                let height = param.merkle_height().unwrap_or(0);
                let range = abi::MerkleInput {
                    seed: &fields.seed,
                    public: &fields.public,
                    subtree_height: fields.subtree_height,
                    leaf_start: fields.leaf_start,
                    auth_leaf: fields.auth_leaf,
                    layer: fields.layer,
                    tree_address: fields.tree_address,
                };
                if !zero_tail(&input[0..32], n)
                    || !zero_tail(&input[32..64], public_len)
                    || input[88..128].iter().any(|b| *b != 0)
                    || !abi::merkle_range_ok(&param, height, &range)
                    || !self.caps.claims(command, param_set_of(&param), fields.subtree_height)
                {
                    return Err(Status::InvalidInput);
                }
                let result = match param {
                    ParamSet::Lms(p) => self.backend.merkle_lms(&p, &fields),
                    ParamSet::Xmss(p) => self.backend.merkle_xmss(&p, &fields),
                    ParamSet::Slh(_) => Err(Status::InternalError),
                };
                let mut payload = check_len(result, payload_len)?;
                if fields.auth_leaf == AUTH_LEAF_NONE {
                    payload[n..].fill(0);
                }
                Ok(payload)
            }
            _ => Err(Status::InternalError),
        }
    }

    fn zero_input(&mut self, range: Option<std::ops::Range<usize>>) {
        if let Some(range) = range {
            self.memory[range.clone()].fill(0);
            if self.memory[range].iter().any(|b| *b != 0) {
                self.inputs_left_nonzero += 1;
            }
        }
    }
}

fn param_set_of(param: &ParamSet) -> u32 {
    match param {
        ParamSet::Slh(p) => p.id,
        ParamSet::Lms(p) => abi::lms_param_set(p.lms_type, p.lmots_type),
        ParamSet::Xmss(p) => abi::xmss_param_set(p.raw_oid),
    }
}

fn zero_tail(field: &[u8], used: usize) -> bool {
    field[used..].iter().all(|b| *b == 0)
}

fn check_len(result: Result<Vec<u8>, Status>, expected: usize) -> Result<Vec<u8>, Status> {
    match result {
        Ok(bytes) if bytes.len() == expected => Ok(bytes),
        Ok(_) => Err(Status::InternalError),
        Err(status) => Err(status),
    }
}
