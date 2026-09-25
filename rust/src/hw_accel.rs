//! Optional K26 accelerator probe. A failed probe never blocks PKCS#11.
//!
//! `C_Initialize` probes every engine a KV260 profile can load and installs
//! only the hooks the loaded profile supports (plan §3.3: the engine needs no
//! configuration of its own; anything missing runs on ARM):
//!
//! * `mldsa` profile — the whole-signature ML-DSA-65 signers (or the older
//!   resident matrix/vector engine).
//! * `hashsig` profile — the hash-signature engine (`pqc_hw::hashsig_device`,
//!   pqctoday-cacp `fpga/hashsig/ABI.md`). After `QUERY_CAPS`, `RESET_CORE`
//!   and a known-answer command, the fips205 `SLH_SIGN` / `SLH_KEYGEN` hooks
//!   and the hbs-lms / xmss `MERKLE_SUBTREE` hooks are installed for the
//!   commands and schemes the engine implements; each call is then routed to
//!   the engine only for a parameter set it claims and the routing policy
//!   sends there.
//!
//! Runtime switches (environment of the process that calls `C_Initialize`):
//!
//! * `PQC_HW_DISABLE=1` — probe nothing; everything on ARM.
//! * `PQC_HASHSIG_ROUTE` — per hash family, `family=fpga|cpu`, comma
//!   separated, `family` ∈ {`shake`, `sha2`, `all`}. Default
//!   `shake=fpga,sha2=cpu`: SLH-DSA-SHA2, LMS SHA-256 and XMSS SHA2 stay on
//!   the A53, whose SHA-256 instructions beat one fabric SHA-256 unit.
//!   `PQC_HASHSIG_ROUTE=sha2=fpga` sends them to the engine as well;
//!   `all=cpu` keeps the engine idle.
//! * `PQC_HASHSIG_MERKLE_MIN_HEIGHT` — fewest leaves (2^value, default 4)
//!   worth one engine call; the node caches' many small subtrees are sent
//!   together in request tables and count together.
//!
//! LMS and XMSS trees are served from their in-memory node caches
//! (hbs-lms-patched and xmss-patched `tree_cache`); the engine only fills a
//! cache miss, at the cache's lowest cached height (LMS max(4, h−16), XMSS 3),
//! and the levels above are hashed on the CPU, so the cache holds exactly
//! what the CPU would have put there and later signatures hit it.
//! * `PQC_HW_DIAGNOSTICS=1` — one stderr line per probe decision or fallback.
//! * `PQC_HW_MLDSA_WAIT=spin|sleep|irq` — how a worker waits for an ML-DSA
//!   lane (default `irq`: block on the UIO interrupt, the control register
//!   stays the authority, a line that never fires falls back to `sleep`).
//! * `PQC_HW_DMA_SYNC=sysfs` — cache maintenance through the three sysfs
//!   writes instead of one u-dma-buf ioctl (A/B runs).
//! * `PQC_HW_STAGE_PROFILE=1` — per-stage host-path timing; the table and
//!   per-lane counters (signs, FPGA attempts, interrupts) are printed to
//!   stderr at `C_Finalize`.
//!
//! Every hook keeps the ML-DSA lanes' policy: `try_lock` (a contending
//! caller runs the whole operation on ARM, never waits), a bounded timeout,
//! and ARM fallback on any error. Output is byte-identical with or without
//! the engine, and LMS/XMSS indices are reserved and persisted by the
//! software path before a signature is released, exactly as without it.
use pqc_hw::hashsig_device::abi::{
    self, Command, MerkleInput, ParamSet, SlhKeygenInput, SlhSignInput, AUTH_LEAF_NONE,
};
use pqc_hw::hashsig_device::pool::{self, HashsigAccelerator, Lane, Opener, Reference, Routing};
use pqc_hw::keccak::RegisterIo;
use pqc_hw::mldsa_sign_lane::{LaneStats, SignDma, SignInputs, SignLane};
use pqc_hw::stage::{self, Stage};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock, TryLockError};
use std::time::Duration;

static AVAILABLE: OnceLock<bool> = OnceLock::new();

struct ResidentMldsa65 {
    session: pqc_hw::mldsa_device::Mldsa65Session,
    matrix: Vec<i32>,
}

/// One whole-signature ML-DSA-65 signer lane as the signing hook sees it:
/// the device session, or a simulated lane in tests and host-path profiles.
pub trait Mldsa65Lane: Send {
    fn sign_into(
        &mut self,
        inputs: &dyn SignInputs,
        attempt_limit: u16,
        timeout: Duration,
        signature: &mut [u8],
    ) -> io::Result<()>;
    fn stats(&self) -> LaneStats;
}

impl<R: RegisterIo + Send, D: SignDma + Send> Mldsa65Lane for SignLane<R, D> {
    fn sign_into(
        &mut self,
        inputs: &dyn SignInputs,
        attempt_limit: u16,
        timeout: Duration,
        signature: &mut [u8],
    ) -> io::Result<()> {
        SignLane::sign_into(self, inputs, attempt_limit, timeout, signature)
    }
    fn stats(&self) -> LaneStats {
        SignLane::stats(self)
    }
}

impl Mldsa65Lane for pqc_hw::mldsa_sign_device::Mldsa65SignSession {
    fn sign_into(
        &mut self,
        inputs: &dyn SignInputs,
        attempt_limit: u16,
        timeout: Duration,
        signature: &mut [u8],
    ) -> io::Result<()> {
        self.lane_mut()
            .sign_into(inputs, attempt_limit, timeout, signature)
    }
    fn stats(&self) -> LaneStats {
        self.lane().stats()
    }
}

/// fips204's borrowed signing inputs, as the lane driver consumes them: the
/// matrix is identified by `ρ` and every buffer is written straight into
/// the lane's DMA memory.
struct Fips204Inputs<'a, 'b>(&'a fips204::Mldsa65SignInput<'b>);

impl SignInputs for Fips204Inputs<'_, '_> {
    fn matrix_id(&self) -> [u8; 32] {
        *self.0.matrix_id()
    }
    fn write_matrix(&self, out: &mut [u8]) -> bool {
        self.0.write_matrix(out)
    }
    fn write_secret_polys(&self, out: &mut [u8]) -> bool {
        self.0.write_secret_polys(out)
    }
    fn mu(&self) -> &[u8; 64] {
        self.0.mu()
    }
    fn rho_prime(&self) -> &[u8; 64] {
        self.0.rho_prime()
    }
    fn randomized(&self) -> bool {
        self.0.randomized()
    }
}

/// Opens lane `index` (called lazily, and again after a lane failed).
pub type Mldsa65LaneOpener = Box<dyn Fn(usize) -> io::Result<Box<dyn Mldsa65Lane>> + Send + Sync>;

struct SignPool {
    lanes: Vec<Mutex<Option<Box<dyn Mldsa65Lane>>>>,
    /// First 8 bytes of the matrix id each lane last held (0 = none): read
    /// without the lane lock to prefer the lane that already holds a key's
    /// matrix. Only a hint; the lane itself compares the full id.
    resident: Vec<AtomicU64>,
    /// Counters of lanes that were closed after a failure, so a report
    /// covers the whole process.
    retired: Mutex<Vec<LaneStats>>,
    opener: Mldsa65LaneOpener,
    next: AtomicUsize,
}

static MLDSA65_SIGN: OnceLock<SignPool> = OnceLock::new();
/// Runtime switch for the whole-signature hook (tests compare on and off).
static MLDSA65_SIGN_ENABLED: AtomicBool = AtomicBool::new(true);
const SIGN_TIMEOUT: Duration = Duration::from_millis(250);
const SIGN_ATTEMPT_LIMIT: u16 = 128;

/// Installs the whole-signature ML-DSA-65 hook over `lanes` lanes opened
/// by `opener`. `C_Initialize` calls this after a successful device probe;
/// tests and the host-path profile call it with simulated lanes. Returns
/// `false` when a pool was already installed in this process (hooks are
/// process-wide and set once).
pub fn install_mldsa65_sign(lanes: usize, opener: Mldsa65LaneOpener) -> bool {
    let pool = SignPool {
        lanes: (0..lanes.max(1)).map(|_| Mutex::new(None)).collect(),
        resident: (0..lanes.max(1)).map(|_| AtomicU64::new(0)).collect(),
        retired: Mutex::new(Vec::new()),
        opener,
        next: AtomicUsize::new(0),
    };
    if MLDSA65_SIGN.set(pool).is_err() {
        return false;
    }
    let _installed = fips204::set_mldsa65_sign_hook(mldsa65_sign);
    true
}

/// Turns the installed whole-signature hook on or off at run time. Off,
/// every ML-DSA-65 signature runs on the CPU exactly as without a device.
pub fn set_mldsa65_sign_enabled(on: bool) {
    MLDSA65_SIGN_ENABLED.store(on, Ordering::SeqCst);
}

/// Counters of every lane that has been open in this process, summed per
/// lane index where a lane was reopened. Lanes busy right now are skipped.
pub fn mldsa65_lane_stats() -> Vec<LaneStats> {
    let Some(pool) = MLDSA65_SIGN.get() else {
        return Vec::new();
    };
    let mut out = pool.retired.lock().unwrap_or_else(|e| e.into_inner()).clone();
    for lane in &pool.lanes {
        if let Ok(guard) = lane.try_lock()
            && let Some(lane) = guard.as_ref()
        {
            out.push(lane.stats());
        }
    }
    out
}

/// Installs the whole-signature hook over simulated lanes (tests and the
/// host-path profile). Each lane is reopened on the same simulated device
/// after a failure, as `C_Initialize`'s pool reopens a device lane.
pub fn install_mldsa65_sim(
    lanes: Vec<pqc_hw::mldsa_sign_sim::SimLane>,
    mode: pqc_hw::mldsa_sign::WaitMode,
) -> bool {
    let count = lanes.len();
    install_mldsa65_sign(
        count,
        Box::new(move |index| {
            let lane = SignLane::new(lanes[index].parts(mode))?;
            Ok(Box::new(lane) as Box<dyn Mldsa65Lane>)
        }),
    )
}

/// The fabric's computation for the lane simulator: fips204's own
/// ML-DSA-65 rejection loop over exactly the bytes the signer reads.
pub fn mldsa65_reference_backend() -> Box<dyn pqc_hw::mldsa_sign_sim::SignBackend> {
    use pqc_hw::mldsa_sign_lane::SECRET_POLY_BYTES;
    Box::new(pqc_hw::mldsa_sign_sim::FnBackend(
        |job: &pqc_hw::mldsa_sign_sim::SignJob<'_>| {
            let le = |bytes: &[u8]| {
                bytes
                    .chunks_exact(4)
                    .map(|c| i32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                    .collect::<Vec<i32>>()
            };
            let matrix = le(job.matrix);
            let polys = le(&job.secrets[..SECRET_POLY_BYTES]);
            let (s1, rest) = polys.split_at(5 * 256);
            let (s2, t0) = rest.split_at(6 * 256);
            let tail = &job.secrets[SECRET_POLY_BYTES..];
            let mu: [u8; 64] = tail[..64].try_into().map_err(|_| -1)?;
            let rho_prime: [u8; 64] = tail[64..128].try_into().map_err(|_| -1)?;
            fips204::ml_dsa_65::reference_sign_loop(&matrix, s1, s2, t0, &mu, &rho_prime)
                .map(|(signature, attempts)| (signature.to_vec(), attempts))
                .ok_or(-1)
        },
    ))
}

/// Routes fips204's ML-DSA stage timings into `pqc_hw::stage` and turns the
/// profiler on. Diagnostics only.
pub fn install_stage_profile() {
    stage::enable(true);
    let _installed = fips204::set_mldsa_stage_hook(forward_stage);
}

fn forward_stage(which: fips204::MldsaStage, ns: u64) {
    let mapped = match which {
        fips204::MldsaStage::KeyDecode => Stage::KeyDecode,
        fips204::MldsaStage::ExpandA => Stage::ExpandA,
        fips204::MldsaStage::MessageHash => Stage::MessageHash,
        fips204::MldsaStage::Flatten => Stage::Flatten,
        fips204::MldsaStage::Accelerator => Stage::Accelerator,
        fips204::MldsaStage::SoftwareLoop => Stage::SoftwareLoop,
    };
    stage::record(mapped, ns);
}

/// The stage table and lane counters as text, one record per line
/// (`PQC_HW_STAGE` / `PQC_HW_LANE`); empty when profiling is off.
pub fn stage_report() -> String {
    if !stage::enabled() {
        return String::new();
    }
    let mut out = String::new();
    for line in stage::snapshot().render().lines() {
        out.push_str("PQC_HW_STAGE\t");
        out.push_str(line);
        out.push('\n');
    }
    for (index, lane) in mldsa65_lane_stats().iter().enumerate() {
        let mean = if lane.signs == 0 { 0.0 } else { lane.attempts as f64 / lane.signs as f64 };
        out.push_str(&format!(
            "PQC_HW_LANE\t{index}\tsigns={}\tattempts={}\tmean_attempts={mean:.3}\tcontext_loads={}\tinterrupts={}\tmissed_interrupts={}\tregister_polls={}\n",
            lane.signs,
            lane.attempts,
            lane.context_loads,
            lane.signer_interrupts,
            lane.signer_missed_interrupts,
            lane.register_polls
        ));
    }
    out
}

/// Called from `C_Finalize`: prints [`stage_report`] to stderr when
/// `PQC_HW_STAGE_PROFILE=1` enabled the profiler.
pub fn report_on_finalize() {
    let report = stage_report();
    if !report.is_empty() {
        eprint!("{report}");
    }
}

static MLDSA65: OnceLock<Mutex<Option<ResidentMldsa65>>> = OnceLock::new();

/// The hash-signature engine, once admitted.
static HASHSIG: OnceLock<HashsigAccelerator> = OnceLock::new();

pub fn probe_on_initialize() {
    if stage::enable_from_env() {
        install_stage_profile();
    }
    let _available = AVAILABLE.get_or_init(|| {
        if std::env::var_os("PQC_HW_DISABLE").is_some_and(|value| value == "1") {
            return false;
        }
        // The two profiles never load together; each probe finds nothing in
        // the other's profile and costs a sysfs scan there.
        let mldsa = probe_mldsa();
        let hashsig = probe_hashsig();
        mldsa || hashsig
    });
}

fn probe_mldsa() -> bool {
    match pqc_hw::mldsa_sign_device::Mldsa65SignSession::open() {
        Ok(_) => {
            diagnostic("selected whole-signature ML-DSA-65 accelerator");
            install_mldsa65_sign(
                pqc_hw::mldsa_sign_device::MLDSA65_SIGN_LANES,
                Box::new(|lane| {
                    pqc_hw::mldsa_sign_device::Mldsa65SignSession::open_lane(lane)
                        .map(|session| Box::new(session) as Box<dyn Mldsa65Lane>)
                }),
            )
        }
        Err(sign_error) => match pqc_hw::mldsa_device::Mldsa65Session::open() {
            Ok(_) => {
                diagnostic(&format!(
                    "whole-signature probe failed ({sign_error}); selected resident matvec accelerator"
                ));
                let _installed = fips204::set_mldsa65_matvec_hook(mldsa65_matvec);
                true
            }
            Err(matvec_error) => {
                diagnostic(&format!(
                    "accelerator probe failed: whole-signature={sign_error}; matvec={matvec_error}"
                ));
                false
            }
        },
    }
}

fn probe_hashsig() -> bool {
    use pqc_hw::hashsig_device::device::{HashsigSession, ENGINES};
    // No UIO map at the engine's address (e.g. the mldsa profile): nothing is
    // opened, created or locked.
    if !HashsigSession::present(0) {
        diagnostic("hash-signature engine absent");
        return false;
    }
    let (routing, warning) = Routing::from_env();
    if let Some(warning) = warning {
        diagnostic(&format!("{warning}; using the default routing"));
    }
    let opener: Opener =
        Box::new(|instance| HashsigSession::open(instance).map(|s| Box::new(s) as Box<dyn Lane>));
    match HashsigAccelerator::probe(
        opener,
        ENGINES.len(),
        routing,
        pool::merkle_min_height_from_env(),
        software_reference(),
        Some(diagnostic),
    ) {
        Ok(accelerator) => install_hashsig(accelerator),
        Err(error) => {
            diagnostic(&format!("hash-signature engine probe failed: {error}"));
            false
        }
    }
}

/// Admits a probed hash-signature engine and installs the scheme hooks for
/// the commands it implements. Returns `false` when an engine was already
/// installed in this process (hooks are process-wide and set once).
///
/// `C_Initialize` calls this after a successful probe; tests call it with an
/// accelerator built on the register simulator.
pub fn install_hashsig(accelerator: HashsigAccelerator) -> bool {
    let caps = *accelerator.caps();
    let routing = accelerator.routing();
    if HASHSIG.set(accelerator).is_err() {
        return false;
    }
    let mut installed = Vec::new();
    if caps.implements(Command::SlhSign) && caps.slh_sign_sets != 0 {
        let _ = fips205::set_slh_sign_hook(slh_sign_hook);
        let _ = fips205::set_slh_reject_hook(slh_reject_hook);
        installed.push("SLH_SIGN");
    }
    if caps.implements(Command::SlhKeygen) && caps.slh_keygen_sets != 0 {
        let _ = fips205::set_slh_keygen_hook(slh_keygen_hook);
        installed.push("SLH_KEYGEN");
    }
    if caps.implements(Command::MerkleSubtree) && caps.lms_families != 0 && caps.lmots_w != 0 {
        let _ = hbs_lms::set_merkle_subtree_hook(lms_subtree_hook, lms_wants_hook);
        installed.push("MERKLE_SUBTREE(LMS)");
    }
    if caps.implements(Command::MerkleSubtree) && caps.xmss_families != 0 {
        let _ = xmss::set_xmss_subtree_hook(xmss_subtree_hook, xmss_wants_hook);
        installed.push("MERKLE_SUBTREE(XMSS)");
    }
    diagnostic(&format!(
        "selected hash-signature engine: build {:#x}, {} lane(s) ({} generic), \
         SLH sign sets {:#x}, keygen sets {:#x}, LMS families {:#x}/W {:#x}, \
         XMSS families {:#x}; routing shake={:?} sha2={:?}; hooks: {}",
        caps.build_id,
        caps.lanes,
        caps.generic_lanes,
        caps.slh_sign_sets,
        caps.slh_keygen_sets,
        caps.lms_families,
        caps.lmots_w,
        caps.xmss_families,
        routing.shake,
        routing.sha2,
        installed.join(", ")
    ));
    true
}

/// The admitted hash-signature engine, if any.
pub fn hashsig() -> Option<&'static HashsigAccelerator> {
    HASHSIG.get()
}

fn slh_sign_hook(
    param: u32,
    sk_seed: &[u8],
    pk_seed: &[u8],
    pk_root: &[u8],
    md: &[u8],
    idx_tree: u64,
    idx_leaf: u32,
) -> Option<Vec<u8>> {
    HASHSIG.get()?.slh_sign(
        param,
        SlhSignInput {
            sk_seed,
            pk_seed,
            pk_root,
            md,
            idx_tree,
            idx_leaf,
        },
    )
}

fn slh_reject_hook(param: u32) {
    if let Some(accelerator) = HASHSIG.get() {
        diagnostic(&format!(
            "hash-signature engine SLH_SIGN output for set {param} failed the ARM check"
        ));
        accelerator.report_rejected_output();
    }
}

fn slh_keygen_hook(param: u32, sk_seed: &[u8], pk_seed: &[u8]) -> Option<Vec<u8>> {
    HASHSIG
        .get()?
        .slh_keygen(param, SlhKeygenInput { sk_seed, pk_seed })
}

fn lms_subtree_hook(
    lms_type: u32,
    lmots_type: u32,
    seed: &[u8],
    identifier: &[u8],
    subtree_height: u32,
    leaf_starts: &[u32],
) -> Option<Vec<Vec<u8>>> {
    if lms_type > 0xff || lmots_type > 0xff {
        return None;
    }
    let inputs: Vec<MerkleInput<'_>> = leaf_starts
        .iter()
        .map(|&leaf_start| MerkleInput {
            seed,
            public: identifier,
            subtree_height,
            leaf_start,
            auth_leaf: AUTH_LEAF_NONE,
            layer: 0,
            tree_address: 0,
        })
        .collect();
    let payloads = HASHSIG
        .get()?
        .merkle_batch(abi::lms_param_set(lms_type, lmots_type), &inputs)?;
    let n = payloads.first()?.len() / (subtree_height as usize + 1);
    Some(
        payloads
            .into_iter()
            .map(|mut payload| {
                payload.truncate(n);
                payload
            })
            .collect(),
    )
}

fn lms_wants_hook(lms_type: u32, lmots_type: u32, subtree_height: u32, subtrees: usize) -> bool {
    lms_type <= 0xff
        && lmots_type <= 0xff
        && HASHSIG.get().is_some_and(|accelerator| {
            accelerator.wants_merkle(abi::lms_param_set(lms_type, lmots_type), subtree_height, subtrees)
        })
}

fn xmss_subtree_hook(
    raw_oid: u32,
    sk_seed: &[u8],
    pub_seed: &[u8],
    subtree_height: u32,
    leaf_starts: &[u32],
    layer: u32,
    tree_address: u64,
) -> Option<Vec<Vec<u8>>> {
    if raw_oid > 0x00ff_ffff {
        return None;
    }
    let inputs: Vec<MerkleInput<'_>> = leaf_starts
        .iter()
        .map(|&leaf_start| MerkleInput {
            seed: sk_seed,
            public: pub_seed,
            subtree_height,
            leaf_start,
            auth_leaf: AUTH_LEAF_NONE,
            layer,
            tree_address,
        })
        .collect();
    let payloads = HASHSIG.get()?.merkle_batch(abi::xmss_param_set(raw_oid), &inputs)?;
    let n = payloads.first()?.len() / (subtree_height as usize + 1);
    Some(
        payloads
            .into_iter()
            .map(|mut payload| {
                payload.truncate(n);
                payload
            })
            .collect(),
    )
}

fn xmss_wants_hook(raw_oid: u32, subtree_height: u32, subtrees: usize) -> bool {
    raw_oid <= 0x00ff_ffff
        && HASHSIG.get().is_some_and(|accelerator| {
            accelerator.wants_merkle(abi::xmss_param_set(raw_oid), subtree_height, subtrees)
        })
}

/// Software computations the engine must reproduce, for its known-answer test.
pub fn software_reference() -> Reference {
    Reference {
        slh_keygen: Some(reference_slh_keygen),
        merkle: Some(reference_merkle),
    }
}

fn reference_slh_keygen(param: u32, sk_seed: &[u8], pk_seed: &[u8]) -> Option<Vec<u8>> {
    fips205::reference_slh_keygen_root(param, sk_seed, pk_seed).ok()
}

fn reference_merkle(param: u32, input: &MerkleInput<'_>) -> Option<Vec<u8>> {
    match ParamSet::decode(Command::MerkleSubtree, param)? {
        ParamSet::Lms(p) => hbs_lms::reference_merkle_subtree(
            p.lms_type,
            p.lmots_type,
            input.seed,
            input.public,
            input.subtree_height,
            input.leaf_start,
            (input.auth_leaf != AUTH_LEAF_NONE).then_some(input.auth_leaf),
        ),
        ParamSet::Xmss(p) => xmss::reference_merkle_subtree(
            p.raw_oid,
            input.seed,
            input.public,
            input.subtree_height,
            input.leaf_start,
            (input.auth_leaf != AUTH_LEAF_NONE).then_some(input.auth_leaf),
            input.layer,
            input.tree_address,
        ),
        ParamSet::Slh(_) => None,
    }
}

/// A register-simulator backend that answers every command with the engine
/// crate's own software implementations (fips205, hbs-lms): exactly what the
/// fabric must reproduce byte for byte.
pub struct SoftwareSimBackend;

impl pqc_hw::hashsig_device::sim::SimBackend for SoftwareSimBackend {
    fn slh_sign(
        &self,
        param: &abi::SlhParam,
        fields: &pqc_hw::hashsig_device::sim::SlhSignFields,
    ) -> Result<Vec<u8>, abi::Status> {
        fips205::reference_slh_sign_payload(
            param.id,
            &fields.sk_seed,
            &fields.pk_seed,
            &fields.pk_root,
            &fields.md,
            fields.idx_tree,
            fields.idx_leaf,
        )
        .map_err(|error| match error {
            fips205::ReferenceError::RootMismatch => abi::Status::RootMismatch,
            fips205::ReferenceError::InvalidInput => abi::Status::InvalidInput,
        })
    }

    fn slh_keygen(
        &self,
        param: &abi::SlhParam,
        sk_seed: &[u8],
        pk_seed: &[u8],
    ) -> Result<Vec<u8>, abi::Status> {
        fips205::reference_slh_keygen_root(param.id, sk_seed, pk_seed)
            .map_err(|_| abi::Status::InvalidInput)
    }

    fn merkle_lms(
        &self,
        param: &abi::LmsParam,
        fields: &pqc_hw::hashsig_device::sim::MerkleFields,
    ) -> Result<Vec<u8>, abi::Status> {
        hbs_lms::reference_merkle_subtree(
            param.lms_type,
            param.lmots_type,
            &fields.seed,
            &fields.public,
            fields.subtree_height,
            fields.leaf_start,
            (fields.auth_leaf != AUTH_LEAF_NONE).then_some(fields.auth_leaf),
        )
        .ok_or(abi::Status::InvalidInput)
    }

    fn merkle_xmss(
        &self,
        param: &abi::XmssParam,
        fields: &pqc_hw::hashsig_device::sim::MerkleFields,
    ) -> Result<Vec<u8>, abi::Status> {
        xmss::reference_merkle_subtree(
            param.raw_oid,
            &fields.seed,
            &fields.public,
            fields.subtree_height,
            fields.leaf_start,
            (fields.auth_leaf != AUTH_LEAF_NONE).then_some(fields.auth_leaf),
            fields.layer,
            fields.tree_address,
        )
        .ok_or(abi::Status::InvalidInput)
    }
}

fn mldsa65_sign(input: &fips204::Mldsa65SignInput<'_>, signature: &mut [u8]) -> bool {
    if !MLDSA65_SIGN_ENABLED.load(Ordering::Relaxed) {
        return false;
    }
    let Some(pool) = MLDSA65_SIGN.get() else {
        return false;
    };
    let inputs = Fips204Inputs(input);
    let id = input.matrix_id();
    let fingerprint = u64::from_le_bytes(id[..8].try_into().expect("8 bytes")) | 1;
    let lanes = pool.lanes.len();
    let started = stage::start();
    // Lane order: a lane that already holds this key's matrix first (no
    // 30 KB upload), then round-robin. Every lane is only ever try-locked:
    // a contending worker signs on the CPU instead of waiting.
    let first = pool.next.fetch_add(1, Ordering::Relaxed) % lanes;
    let preferred = (0..lanes)
        .map(|offset| (first + offset) % lanes)
        .find(|lane| pool.resident[*lane].load(Ordering::Relaxed) == fingerprint);
    let order = preferred
        .into_iter()
        .chain((0..lanes).map(|offset| (first + offset) % lanes).filter(|lane| Some(*lane) != preferred));
    for lane in order {
        let mut resident = match pool.lanes[lane].try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) | Err(TryLockError::Poisoned(_)) => continue,
        };
        if resident.is_none() {
            *resident = (pool.opener)(lane).ok();
        }
        let Some(state) = resident.as_mut() else {
            continue;
        };
        stage::end(Stage::LaneAcquire, started);
        match state.sign_into(&inputs, SIGN_ATTEMPT_LIMIT, SIGN_TIMEOUT, signature) {
            Ok(()) => {
                pool.resident[lane].store(fingerprint, Ordering::Relaxed);
                return true;
            }
            Err(error) => {
                diagnostic(&format!(
                    "whole-signature accelerator lane {lane} failed: {error}"
                ));
                pool.resident[lane].store(0, Ordering::Relaxed);
                if let Some(closed) = resident.take() {
                    pool.retired
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(closed.stats());
                }
            }
        }
    }
    false
}

pub fn available() -> bool {
    *AVAILABLE.get().unwrap_or(&false)
}

fn mldsa65_matvec(matrix: &[i32], vector: &[i32]) -> Option<Vec<i32>> {
    // The resident accelerator is single-issue. Never make a PKCS #11 worker
    // wait behind another request: an available worker uses the FPGA while a
    // contending worker immediately executes the complete operation on ARM.
    // This also contains a wedged device call to its owning worker instead of
    // blocking every signing thread on the process-global mutex.
    let mut resident = match MLDSA65.get_or_init(|| Mutex::new(None)).try_lock() {
        Ok(guard) => guard,
        Err(TryLockError::WouldBlock) => return None,
        Err(TryLockError::Poisoned(_)) => return None,
    };
    if resident.is_none() {
        *resident = Some(ResidentMldsa65 {
            session: pqc_hw::mldsa_device::Mldsa65Session::open().ok()?,
            matrix: Vec::new(),
        });
    }
    let state = resident.as_mut()?;
    if state.matrix != matrix {
        if let Err(error) = state.session.load_matrix(matrix) {
            diagnostic(&format!("matrix upload failed: {error}"));
            *resident = None;
            return None;
        }
        state.matrix.clear();
        state.matrix.extend_from_slice(matrix);
    }
    match state
        .session
        .execute_cached(vector, Duration::from_millis(250))
    {
        Ok(output) => Some(output),
        Err(error) => {
            diagnostic(&format!("resident matvec failed: {error}"));
            *resident = None;
            None
        }
    }
}

fn diagnostic(message: &str) {
    if std::env::var_os("PQC_HW_DIAGNOSTICS").is_some_and(|value| value == "1") {
        eprintln!("PQC_HW_DIAGNOSTIC\t{message}");
    }
}
