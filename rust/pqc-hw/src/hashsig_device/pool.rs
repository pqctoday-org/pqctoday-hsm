//! Engine sessions, ARM-fallback policy and hash-family routing.
//!
//! [`HashsigAccelerator`] is what the scheme hooks call. It answers `None`
//! whenever the operation should run on ARM, and the caller then runs its
//! unchanged software path:
//!
//! * the engine does not claim the (command, parameter set, subtree height)
//!   in `QUERY_CAPS` (ABI.md §6.4), or
//! * the routing policy pins the parameter set's hash family to the CPU, or
//! * every engine instance is busy (`try_lock`, never a wait), degraded,
//!   disabled, timed out, or answered with an error.
//!
//! # Routing policy
//!
//! Set `PQC_HASHSIG_ROUTE` to a comma-separated list of `family=target`,
//! where `family` is `shake`, `sha2` or `all` and `target` is `fpga` or `cpu`.
//! Later entries win. The default is `shake=fpga,sha2=cpu`: the A53's
//! SHA-256 instructions beat one fabric SHA-256 unit, so SLH-DSA-SHA2, LMS
//! SHA-256 and XMSS SHA2 stay on the CPU unless the operator writes
//! `PQC_HASHSIG_ROUTE=sha2=fpga` (or `all=fpga`). `PQC_HASHSIG_ROUTE=all=cpu`
//! keeps the engine probed but unused; `PQC_HW_DISABLE=1` skips the probe.
//!
//! `PQC_HASHSIG_MERKLE_MIN_HEIGHT` (default 4) is the smallest LMS/XMSS
//! subtree sent to the engine; smaller subtrees cost less on ARM than a
//! submission.

use super::abi::{
    self, Caps, Command, HashFamily, MerkleInput, Operation, ParamSet, SlhKeygenInput,
    SlhSignInput, AUTH_LEAF_NONE,
};
use super::{Engine, Error, Health, Output};
use crate::keccak::RegisterIo;
use std::cell::Cell;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const ROUTE_ENV: &str = "PQC_HASHSIG_ROUTE";
pub const MERKLE_MIN_HEIGHT_ENV: &str = "PQC_HASHSIG_MERKLE_MIN_HEIGHT";
pub const DEFAULT_MERKLE_MIN_HEIGHT: u32 = 4;
/// A degraded engine is offered a recovery attempt at most this often.
pub const RECOVERY_INTERVAL: Duration = Duration::from_secs(5);

/// One engine instance as the pool sees it.
pub trait Lane: Send {
    fn execute(&mut self, op: &Operation<'_>) -> Result<Output, Error>;
    /// A request table (ABI.md §4.1): one result per record, in order.
    fn execute_batch(&mut self, ops: &[Operation<'_>]) -> Result<Vec<Result<Output, Error>>, Error>;
    /// Largest request table the engine accepts (`Caps.max_batch`).
    fn max_batch(&self) -> usize;
    fn health(&self) -> Health;
    fn mark_degraded(&mut self);
    fn recover(&mut self, kat: &Operation<'_>, expected: &[u8]) -> Health;
    fn query_caps(&mut self) -> Result<Caps, Error>;
    fn reset_core(&mut self) -> Result<(), Error>;
}

impl<R: RegisterIo + Send, D: super::DmaRegion + Send> Lane for Engine<R, D> {
    fn execute(&mut self, op: &Operation<'_>) -> Result<Output, Error> {
        Engine::execute(self, op, None)
    }
    fn execute_batch(&mut self, ops: &[Operation<'_>]) -> Result<Vec<Result<Output, Error>>, Error> {
        Engine::execute_batch(self, ops, None)
    }
    fn max_batch(&self) -> usize {
        Engine::max_batch(self)
    }
    fn health(&self) -> Health {
        Engine::health(self)
    }
    fn mark_degraded(&mut self) {
        Engine::mark_degraded(self);
    }
    fn recover(&mut self, kat: &Operation<'_>, expected: &[u8]) -> Health {
        Engine::recover(self, kat, expected)
    }
    fn query_caps(&mut self) -> Result<Caps, Error> {
        Engine::query_caps(self)
    }
    fn reset_core(&mut self) -> Result<(), Error> {
        Engine::execute(self, &Operation::ResetCore, None).map(|_| ())
    }
}

/// Where a hash family's operations run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Target {
    Fpga,
    Cpu,
}

/// Per-hash-family preference. See the module documentation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Routing {
    pub shake: Target,
    pub sha2: Target,
}

impl Default for Routing {
    fn default() -> Self {
        Self {
            shake: Target::Fpga,
            sha2: Target::Cpu,
        }
    }
}

impl Routing {
    pub fn target(&self, family: HashFamily) -> Target {
        match family {
            HashFamily::Shake => self.shake,
            HashFamily::Sha2 => self.sha2,
        }
    }

    /// Parses `family=target[,family=target...]` on top of the default.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let mut routing = Self::default();
        for entry in spec
            .split([',', ';', ' '])
            .map(str::trim)
            .filter(|e| !e.is_empty())
        {
            let (family, target) = entry
                .split_once('=')
                .ok_or_else(|| format!("`{entry}`: expected family=target"))?;
            let target = match target.trim().to_ascii_lowercase().as_str() {
                "fpga" | "hw" => Target::Fpga,
                "cpu" | "arm" => Target::Cpu,
                other => return Err(format!("`{other}`: target must be fpga or cpu")),
            };
            match family.trim().to_ascii_lowercase().as_str() {
                "shake" => routing.shake = target,
                "sha2" => routing.sha2 = target,
                "all" => {
                    routing.shake = target;
                    routing.sha2 = target;
                }
                other => return Err(format!("`{other}`: family must be shake, sha2 or all")),
            }
        }
        Ok(routing)
    }

    /// The routing from `PQC_HASHSIG_ROUTE`; an invalid value keeps the
    /// default and returns the parse error for the diagnostic log.
    pub fn from_env() -> (Self, Option<String>) {
        match std::env::var(ROUTE_ENV) {
            Ok(spec) => match Self::parse(&spec) {
                Ok(routing) => (routing, None),
                Err(error) => (Self::default(), Some(format!("{ROUTE_ENV}: {error}"))),
            },
            Err(_) => (Self::default(), None),
        }
    }
}

fn encode_routing(routing: Routing) -> u8 {
    u8::from(routing.shake == Target::Fpga) | (u8::from(routing.sha2 == Target::Fpga) << 1)
}

fn decode_routing(bits: u8) -> Routing {
    let target = |bit: u8| if bits & bit != 0 { Target::Fpga } else { Target::Cpu };
    Routing {
        shake: target(1),
        sha2: target(2),
    }
}

pub fn merkle_min_height_from_env() -> u32 {
    std::env::var(MERKLE_MIN_HEIGHT_ENV)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(DEFAULT_MERKLE_MIN_HEIGHT)
}

/// Software reference computations, used for the known-answer test that
/// admits an engine at probe time and restores a degraded one.
#[derive(Clone, Copy, Default)]
pub struct Reference {
    pub slh_keygen: Option<SlhKeygenReference>,
    pub merkle: Option<MerkleReference>,
}

/// PK.root for (SLH param id, SK.seed, PK.seed), computed in software.
pub type SlhKeygenReference = fn(u32, &[u8], &[u8]) -> Option<Vec<u8>>;
/// root ‖ auth for (MERKLE_SUBTREE param set, input), computed in software.
pub type MerkleReference = fn(u32, &MerkleInput<'_>) -> Option<Vec<u8>>;

/// Known-answer command with public, fixed inputs.
struct Kat {
    command: Command,
    param_set: u32,
    seed: Vec<u8>,
    public: Vec<u8>,
    subtree_height: u32,
    expected: Vec<u8>,
}

impl Kat {
    fn operation(&self) -> Operation<'_> {
        match self.command {
            Command::SlhKeygen => Operation::SlhKeygen {
                param: self.param_set,
                input: SlhKeygenInput {
                    sk_seed: &self.seed,
                    pk_seed: &self.public,
                },
            },
            _ => Operation::Merkle {
                param: self.param_set,
                input: MerkleInput {
                    seed: &self.seed,
                    public: &self.public,
                    subtree_height: self.subtree_height,
                    leaf_start: 0,
                    auth_leaf: 0,
                    layer: 0,
                    tree_address: 0,
                },
            },
        }
    }

    /// Picks the cheapest claimed command and computes its answer in software.
    fn build(caps: &Caps, reference: &Reference) -> Option<Self> {
        if let Some(keygen) = reference.slh_keygen {
            for id in [2u32, 6, 10, 1, 5, 9] {
                if caps.claims(Command::SlhKeygen, id, 0) {
                    let n = abi::slh_param(id)?.n;
                    let seed: Vec<u8> = (0..n as u8).collect();
                    let public: Vec<u8> = (0..n as u8).map(|b| b ^ 0xa5).collect();
                    let expected = keygen(id, &seed, &public)?;
                    return Some(Self {
                        command: Command::SlhKeygen,
                        param_set: id,
                        seed,
                        public,
                        subtree_height: 0,
                        expected,
                    });
                }
            }
        }
        let merkle = reference.merkle?;
        let mut candidates = Vec::new();
        for (lms, lmots) in [(0x0F, 0x0B), (0x14, 0x0F), (0x05, 0x03), (0x0A, 0x07)] {
            candidates.push(abi::lms_param_set(lms, lmots));
        }
        for oid in [0x07u32, 0x10, 0x13, 0x01, 0x0d] {
            candidates.push(abi::xmss_param_set(oid));
        }
        for param_set in candidates {
            let k = 2.min(match ParamSet::decode(Command::MerkleSubtree, param_set)? {
                ParamSet::Lms(_) => caps.lms_max_subtree_height,
                _ => caps.xmss_max_subtree_height,
            });
            if !caps.claims(Command::MerkleSubtree, param_set, k) {
                continue;
            }
            let param = ParamSet::decode(Command::MerkleSubtree, param_set)?;
            let n = param.n();
            let seed: Vec<u8> = (0..n as u8).collect();
            let public: Vec<u8> = match param {
                ParamSet::Lms(_) => (0..16u8).map(|b| b ^ 0x5a).collect(),
                _ => (0..n as u8).map(|b| b ^ 0x5a).collect(),
            };
            let mut kat = Self {
                command: Command::MerkleSubtree,
                param_set,
                seed,
                public,
                subtree_height: k,
                expected: Vec::new(),
            };
            let expected = match kat.operation() {
                Operation::Merkle { input, .. } => merkle(param_set, &input)?,
                _ => return None,
            };
            kat.expected = expected;
            return Some(kat);
        }
        None
    }
}

/// Counters for diagnostics and tests.
#[derive(Default, Debug)]
pub struct Stats {
    /// Operations completed by the engine.
    pub hardware: AtomicU64,
    /// Operations sent to ARM because every instance was locked by another thread.
    pub contended: AtomicU64,
    /// Operations sent to ARM after an engine error or timeout.
    pub errors: AtomicU64,
    /// Engine outputs the caller's ARM-side check rejected.
    pub rejected_outputs: AtomicU64,
    /// Successful recoveries of a degraded engine.
    pub recoveries: AtomicU64,
}

struct Slot {
    lane: Option<Box<dyn Lane>>,
    last_recovery: Option<Instant>,
}

pub type Opener = Box<dyn Fn(usize) -> io::Result<Box<dyn Lane>> + Send + Sync>;

thread_local! {
    /// Instance that produced this thread's last hardware result, so a
    /// rejected output can be charged to it.
    static LAST_INSTANCE: Cell<Option<usize>> = const { Cell::new(None) };
}

pub struct HashsigAccelerator {
    caps: Caps,
    /// Bit 0: SHAKE → engine; bit 1: SHA-2 → engine.
    routing: AtomicU8,
    min_merkle_height: u32,
    slots: Vec<Mutex<Slot>>,
    /// Set without the lock when an output of that instance was rejected.
    suspect: Vec<AtomicBool>,
    opener: Opener,
    next: AtomicUsize,
    kat: Option<Kat>,
    enabled: AtomicBool,
    stats: Stats,
    log: fn(&str),
}

fn no_log(_: &str) {}

impl HashsigAccelerator {
    /// Opens instance 0, reads `QUERY_CAPS`, runs `RESET_CORE` and a
    /// known-answer command. Any failure means "no engine": the caller
    /// installs no hook.
    pub fn probe(
        opener: Opener,
        instances: usize,
        routing: Routing,
        min_merkle_height: u32,
        reference: Reference,
        log: Option<fn(&str)>,
    ) -> Result<Self, String> {
        let mut lane = opener(0).map_err(|e| format!("open: {e}"))?;
        let caps = lane.query_caps().map_err(|e| format!("QUERY_CAPS: {e}"))?;
        if caps.caps_version != 1 {
            return Err(format!("unsupported caps_version {}", caps.caps_version));
        }
        let claims_slh = (caps.slh_sign_sets | caps.slh_keygen_sets) != 0
            && (caps.implements(Command::SlhSign) || caps.implements(Command::SlhKeygen));
        let claims_merkle = caps.implements(Command::MerkleSubtree)
            && ((caps.lms_families != 0 && caps.lmots_w != 0) || caps.xmss_families != 0);
        if !claims_slh && !claims_merkle {
            return Err("engine claims no parameter set".into());
        }
        lane.reset_core().map_err(|e| format!("RESET_CORE: {e}"))?;
        let kat = Kat::build(&caps, &reference);
        if let Some(kat) = &kat {
            let output = lane
                .execute(&kat.operation())
                .map_err(|e| format!("known-answer command: {e}"))?;
            if output.payload != kat.expected {
                return Err("known-answer mismatch".into());
            }
        }
        let instances = instances.max(1);
        let mut slots = Vec::with_capacity(instances);
        slots.push(Mutex::new(Slot {
            lane: Some(lane),
            last_recovery: None,
        }));
        for _ in 1..instances {
            slots.push(Mutex::new(Slot {
                lane: None,
                last_recovery: None,
            }));
        }
        Ok(Self {
            caps,
            routing: AtomicU8::new(encode_routing(routing)),
            min_merkle_height,
            suspect: (0..instances).map(|_| AtomicBool::new(false)).collect(),
            slots,
            opener,
            next: AtomicUsize::new(0),
            kat,
            enabled: AtomicBool::new(true),
            stats: Stats::default(),
            log: log.unwrap_or(no_log),
        })
    }

    pub fn caps(&self) -> &Caps {
        &self.caps
    }

    pub fn routing(&self) -> Routing {
        decode_routing(self.routing.load(Ordering::Relaxed))
    }

    /// Change the routing policy at run time.
    pub fn set_routing(&self, routing: Routing) {
        self.routing.store(encode_routing(routing), Ordering::Relaxed);
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    pub fn has_known_answer(&self) -> bool {
        self.kat.is_some()
    }

    /// Runtime switch: `false` sends everything to ARM (tests, operators).
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::SeqCst);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }

    /// Whether an operation would be offered to the engine at all. Cheap and
    /// lock-free: the scheme hooks call it for every tree node.
    pub fn wants(&self, command: Command, param_set: u32, subtree_height: u32) -> bool {
        if !self.is_enabled() || !self.caps.claims(command, param_set, subtree_height) {
            return false;
        }
        if command == Command::MerkleSubtree && subtree_height < self.min_merkle_height {
            return false;
        }
        ParamSet::decode(command, param_set)
            .is_some_and(|p| self.routing().target(p.family()) == Target::Fpga)
    }

    /// SLH_SIGN: SIG_FORS ‖ SIG_HT, or `None` to sign on ARM.
    pub fn slh_sign(&self, param: u32, input: SlhSignInput<'_>) -> Option<Vec<u8>> {
        if !self.wants(Command::SlhSign, param, 0) {
            return None;
        }
        self.run(&Operation::SlhSign { param, input })
            .map(|o| o.payload)
    }

    /// SLH_KEYGEN: PK.root, or `None` to compute it on ARM.
    ///
    /// A signature from the engine is checked on ARM against PK.root before
    /// it is used, but nothing on ARM can check a root short of recomputing
    /// it. The command therefore runs twice and a root is accepted only when
    /// both runs agree; a disagreement is reported like a rejected output and
    /// the root is computed on ARM. (Keygen is rare, and two engine runs still
    /// cost a fraction of one ARM run.) A persistent fault that repeats
    /// exactly is caught by the known-answer test at admission and recovery,
    /// and at the latest by the PK.root check of the first signature.
    pub fn slh_keygen(&self, param: u32, input: SlhKeygenInput<'_>) -> Option<Vec<u8>> {
        if !self.wants(Command::SlhKeygen, param, 0) {
            return None;
        }
        let op = Operation::SlhKeygen { param, input };
        let first = self.run(&op)?.payload;
        let second = self.run(&op)?.payload;
        if first != second {
            self.report_rejected_output();
            return None;
        }
        Some(first)
    }

    /// MERKLE_SUBTREE: root ‖ auth[0..k−1], or `None` to build it on ARM.
    pub fn merkle(&self, param: u32, input: MerkleInput<'_>) -> Option<Vec<u8>> {
        if !self.wants(Command::MerkleSubtree, param, input.subtree_height) {
            return None;
        }
        self.run(&Operation::Merkle { param, input })
            .map(|o| o.payload)
    }

    /// MERKLE_SUBTREE for several subtrees of one tree, all of height
    /// `inputs[i].subtree_height` (the same for every input), sent as request
    /// tables of up to `Caps.max_batch` records. Returns every payload, or
    /// `None` (build them all on ARM) when the engine does not take them or
    /// any record fails. The minimum-height policy applies to the leaves of
    /// the whole call, so many small subtrees still make one worthwhile
    /// submission.
    pub fn merkle_batch(&self, param: u32, inputs: &[MerkleInput<'_>]) -> Option<Vec<Vec<u8>>> {
        let k = inputs.first()?.subtree_height;
        if inputs.iter().any(|input| input.subtree_height != k)
            || !self.is_enabled()
            || !self.caps.claims(Command::MerkleSubtree, param, k)
        {
            return None;
        }
        let leaves = (inputs.len() as u64).saturating_mul(1u64 << k.min(63));
        if leaves < 1u64 << self.min_merkle_height.min(63) {
            return None;
        }
        if !ParamSet::decode(Command::MerkleSubtree, param)
            .is_some_and(|p| self.routing().target(p.family()) == Target::Fpga)
        {
            return None;
        }
        let ops: Vec<Operation<'_>> = inputs
            .iter()
            .map(|input| Operation::Merkle { param, input: *input })
            .collect();
        let chunk = (self.caps.max_batch.clamp(1, abi::MAX_BATCH)) as usize;
        let mut payloads = Vec::with_capacity(inputs.len());
        for ops in ops.chunks(chunk) {
            let results = self.with_lane(|lane| lane.execute_batch(ops))?;
            for result in results {
                match result {
                    Ok(output) => payloads.push(output.payload),
                    Err(error) => {
                        self.stats.errors.fetch_add(1, Ordering::Relaxed);
                        (self.log)(&format!("hashsig engine batch record: {error}; running on ARM"));
                        return None;
                    }
                }
            }
        }
        Some(payloads)
    }

    /// The caller's ARM-side check of this thread's last hardware output
    /// failed (e.g. an SLH-DSA signature that does not verify). The engine
    /// that produced it is degraded before its next use.
    pub fn report_rejected_output(&self) {
        self.stats.rejected_outputs.fetch_add(1, Ordering::Relaxed);
        if let Some(index) = LAST_INSTANCE.with(Cell::take)
            && let Some(flag) = self.suspect.get(index) {
                flag.store(true, Ordering::SeqCst);
            }
        (self.log)("hashsig engine output failed the ARM check; engine degraded");
    }

    /// Health of every opened instance (`None`: not opened yet).
    pub fn health(&self) -> Vec<Option<Health>> {
        self.slots
            .iter()
            .map(|slot| {
                slot.lock()
                    .ok()
                    .and_then(|s| s.lane.as_ref().map(|l| l.health()))
            })
            .collect()
    }

    fn run(&self, op: &Operation<'_>) -> Option<Output> {
        self.with_lane(|lane| lane.execute(op))
    }

    /// Runs `work` on the first free, healthy engine instance (try_lock,
    /// never a wait), with the ARM-fallback bookkeeping of every hook.
    fn with_lane<T>(&self, mut work: impl FnMut(&mut dyn Lane) -> Result<T, Error>) -> Option<T> {
        let count = self.slots.len();
        let first = self.next.fetch_add(1, Ordering::Relaxed) % count;
        let mut contended = 0;
        for offset in 0..count {
            let index = (first + offset) % count;
            // Never wait behind another request: a contending caller runs the
            // whole operation on ARM instead.
            let Ok(mut slot) = self.slots[index].try_lock() else {
                contended += 1;
                continue;
            };
            if slot.lane.is_none() {
                match (self.opener)(index) {
                    Ok(lane) => slot.lane = Some(lane),
                    Err(error) => {
                        (self.log)(&format!("hashsig engine {index} open failed: {error}"));
                        continue;
                    }
                }
            }
            if self.suspect[index].swap(false, Ordering::SeqCst)
                && let Some(lane) = slot.lane.as_mut() {
                    lane.mark_degraded();
                }
            self.maybe_recover(index, &mut slot);
            let Some(lane) = slot.lane.as_mut() else {
                continue;
            };
            if lane.health() != Health::Ready {
                continue;
            }
            match work(lane.as_mut()) {
                Ok(output) => {
                    self.stats.hardware.fetch_add(1, Ordering::Relaxed);
                    LAST_INSTANCE.with(|last| last.set(Some(index)));
                    return Some(output);
                }
                Err(Error::Busy) => contended += 1,
                Err(error @ (Error::Rejected(_) | Error::Input(_))) => {
                    // Every instance would refuse the same request.
                    self.stats.errors.fetch_add(1, Ordering::Relaxed);
                    (self.log)(&format!("hashsig engine {index}: {error}; running on ARM"));
                    return None;
                }
                Err(error) => {
                    self.stats.errors.fetch_add(1, Ordering::Relaxed);
                    (self.log)(&format!("hashsig engine {index}: {error}; running on ARM"));
                }
            }
        }
        if contended == count {
            self.stats.contended.fetch_add(1, Ordering::Relaxed);
        }
        None
    }

    fn maybe_recover(&self, index: usize, slot: &mut Slot) {
        let Some(lane) = slot.lane.as_mut() else {
            return;
        };
        if lane.health() != Health::Degraded {
            return;
        }
        let Some(kat) = &self.kat else {
            return;
        };
        if slot
            .last_recovery
            .is_some_and(|at| at.elapsed() < RECOVERY_INTERVAL)
        {
            return;
        }
        slot.last_recovery = Some(Instant::now());
        match lane.recover(&kat.operation(), &kat.expected) {
            Health::Ready => {
                self.stats.recoveries.fetch_add(1, Ordering::Relaxed);
                (self.log)(&format!("hashsig engine {index} recovered"));
            }
            Health::Disabled => {
                (self.log)(&format!("hashsig engine {index} disabled (scrub failure)"));
            }
            Health::Degraded => {}
        }
    }

    /// Forget the recovery back-off (tests).
    pub fn reset_recovery_backoff(&self) {
        for slot in &self.slots {
            if let Ok(mut slot) = slot.lock() {
                slot.last_recovery = None;
            }
        }
    }
}

/// Convenience for MERKLE_SUBTREE callers: the input for the subtree of
/// height `k` rooted at node `index` of an LMS tree of height `h` (RFC 8554
/// node numbering, root = 1), without an authentication path.
pub fn lms_node_subtree(h: u32, index: u64) -> Option<(u32, u32)> {
    if index == 0 || index >> (h + 1) != 0 {
        return None;
    }
    let level = 63 - index.leading_zeros();
    let k = h - level;
    let leaf_start = (index << k) - (1u64 << h);
    Some((k, u32::try_from(leaf_start).ok()?))
}

pub const NO_AUTH: u32 = AUTH_LEAF_NONE;
