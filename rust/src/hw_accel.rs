//! Optional K26 accelerator probe. A failed probe never blocks PKCS#11.
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

static AVAILABLE: OnceLock<bool> = OnceLock::new();
static ENGINE: Mutex<()> = Mutex::new(());

pub fn probe_on_initialize() {
    let available = *AVAILABLE.get_or_init(|| {
        if std::env::var_os("PQC_HW_DISABLE").is_some_and(|value| value == "1") {
            return false;
        }
        pqc_hw::probe::sha3_256_self_test().is_ok()
    });
    if available {
        let _installed = fips204::set_expand_a_hook(expand_a);
    }
}

pub fn available() -> bool {
    *AVAILABLE.get().unwrap_or(&false)
}

fn expand_a(inputs: &[[u8; 34]], output_length: usize) -> Option<Vec<Vec<u8>>> {
    let _engine = ENGINE.lock().ok()?;
    let requests: Vec<_> = inputs
        .iter()
        .map(|input| pqc_hw::device::Request {
            mode: pqc_hw::keccak::Mode::Shake128,
            input,
            output_length,
        })
        .collect();
    pqc_hw::device::execute_batch(&requests, Duration::from_millis(250)).ok()
}
