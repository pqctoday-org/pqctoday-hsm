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
//! * `PQC_HASHSIG_MERKLE_MIN_HEIGHT` — smallest LMS/XMSS subtree sent to the
//!   engine (default 4). XMSS trees are offered whole (k = h/d); a tree taller
//!   than `Caps.xmss_max_subtree_height` is built on ARM.
//! * `PQC_HW_DIAGNOSTICS=1` — one stderr line per probe decision or fallback.
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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock, TryLockError};
use std::time::Duration;

static AVAILABLE: OnceLock<bool> = OnceLock::new();

struct ResidentMldsa65 {
    session: pqc_hw::mldsa_device::Mldsa65Session,
    matrix: Vec<i32>,
}

const SIGN_LANES: usize = pqc_hw::mldsa_sign_device::MLDSA65_SIGN_LANES;
type SignLane = Mutex<Option<pqc_hw::mldsa_sign_device::Mldsa65SignSession>>;
static MLDSA65_SIGN: OnceLock<[SignLane; SIGN_LANES]> = OnceLock::new();
static NEXT_SIGN_LANE: AtomicUsize = AtomicUsize::new(0);

static MLDSA65: OnceLock<Mutex<Option<ResidentMldsa65>>> = OnceLock::new();

/// The hash-signature engine, once admitted.
static HASHSIG: OnceLock<HashsigAccelerator> = OnceLock::new();

pub fn probe_on_initialize() {
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
            let _installed = fips204::set_mldsa65_sign_hook(mldsa65_sign);
            true
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
        let _ = hbs_lms::set_merkle_subtree_hook(lms_subtree_hook);
        installed.push("MERKLE_SUBTREE(LMS)");
    }
    if caps.implements(Command::MerkleSubtree) && caps.xmss_families != 0 {
        let _ = xmss::set_xmss_subtree_hook(xmss_subtree_hook);
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
    leaf_start: u32,
) -> Option<Vec<u8>> {
    if lms_type > 0xff || lmots_type > 0xff {
        return None;
    }
    let payload = HASHSIG.get()?.merkle(
        abi::lms_param_set(lms_type, lmots_type),
        MerkleInput {
            seed,
            public: identifier,
            subtree_height,
            leaf_start,
            auth_leaf: AUTH_LEAF_NONE,
            layer: 0,
            tree_address: 0,
        },
    )?;
    let n = payload.len() / (subtree_height as usize + 1);
    Some(payload[..n].to_vec())
}

#[allow(clippy::too_many_arguments)]
fn xmss_subtree_hook(
    raw_oid: u32,
    sk_seed: &[u8],
    pub_seed: &[u8],
    subtree_height: u32,
    leaf_start: u32,
    auth_leaf: u32,
    layer: u32,
    tree_address: u64,
) -> Option<Vec<u8>> {
    if raw_oid > 0x00ff_ffff {
        return None;
    }
    HASHSIG.get()?.merkle(
        abi::xmss_param_set(raw_oid),
        MerkleInput {
            seed: sk_seed,
            public: pub_seed,
            subtree_height,
            leaf_start,
            auth_leaf,
            layer,
            tree_address,
        },
    )
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

fn mldsa65_sign(
    matrix: &[i32],
    s1: &[i32],
    s2: &[i32],
    t0: &[i32],
    mu: &[u8; 64],
    rho_prime: &[u8; 64],
    randomized: bool,
) -> Option<Vec<u8>> {
    let lanes = MLDSA65_SIGN.get_or_init(|| std::array::from_fn(|_| Mutex::new(None)));
    let first = NEXT_SIGN_LANE.fetch_add(1, Ordering::Relaxed) % SIGN_LANES;
    for offset in 0..SIGN_LANES {
        let lane = (first + offset) % SIGN_LANES;
        let mut resident = match lanes[lane].try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) | Err(TryLockError::Poisoned(_)) => continue,
        };
        if resident.is_none() {
            *resident = pqc_hw::mldsa_sign_device::Mldsa65SignSession::open_lane(lane).ok();
        }
        let Some(state) = resident.as_mut() else {
            continue;
        };
        match state.sign(
            matrix,
            s1,
            s2,
            t0,
            mu,
            rho_prime,
            randomized,
            128,
            Duration::from_millis(250),
        ) {
            Ok(signature) => return Some(signature),
            Err(error) => {
                diagnostic(&format!(
                    "whole-signature accelerator lane {lane} failed: {error}"
                ));
                *resident = None;
            }
        }
    }
    None
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
