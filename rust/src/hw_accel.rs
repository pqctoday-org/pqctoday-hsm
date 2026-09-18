//! Optional K26 accelerator probe. A failed probe never blocks PKCS#11.
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

pub fn probe_on_initialize() {
    let _available = AVAILABLE.get_or_init(|| {
        if std::env::var_os("PQC_HW_DISABLE").is_some_and(|value| value == "1") {
            return false;
        }
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
    });
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
