//! Optional K26 accelerator probe. A failed probe never blocks PKCS#11.
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

static AVAILABLE: OnceLock<bool> = OnceLock::new();

struct ResidentMldsa65 {
    session: pqc_hw::mldsa_device::Mldsa65Session,
    matrix: Vec<i32>,
}

static MLDSA65: OnceLock<Mutex<Option<ResidentMldsa65>>> = OnceLock::new();

pub fn probe_on_initialize() {
    let available = *AVAILABLE.get_or_init(|| {
        if std::env::var_os("PQC_HW_DISABLE").is_some_and(|value| value == "1") {
            return false;
        }
        pqc_hw::mldsa_device::Mldsa65Session::open().is_ok()
    });
    if available {
        let _installed = fips204::set_mldsa65_matvec_hook(mldsa65_matvec);
    }
}

pub fn available() -> bool {
    *AVAILABLE.get().unwrap_or(&false)
}

fn mldsa65_matvec(matrix: &[i32], vector: &[i32]) -> Option<Vec<i32>> {
    let mut resident = MLDSA65.get_or_init(|| Mutex::new(None)).lock().ok()?;
    if resident.is_none() {
        *resident = Some(ResidentMldsa65 {
            session: pqc_hw::mldsa_device::Mldsa65Session::open().ok()?,
            matrix: Vec::new(),
        });
    }
    let state = resident.as_mut()?;
    if state.matrix != matrix {
        if state.session.load_matrix(matrix).is_err() {
            *resident = None;
            return None;
        }
        state.matrix.clear();
        state.matrix.extend_from_slice(matrix);
    }
    match state.session.execute_cached(vector, Duration::from_millis(250)) {
        Ok(output) => Some(output),
        Err(_) => {
            *resident = None;
            None
        }
    }
}
