//! The eight verbs (seven original benchmark verbs + `get_self_signed_certificate`,
//! added 2026-08-25 — see `cert.rs`'s own module doc for why), mapped onto
//! `softhsmrustv3::native` calls —
//! the same functions the KMIP server's ops layer drives
//! (`kmip/src/ops/*`). Transport-agnostic: `remoting/grpc` and
//! `remoting/rest` both call only what's in this file.
//!
//! ## Session model (WP1, decision 5)
//!
//! One engine process bootstrap per service process ([`bootstrap`], called
//! once at startup) logs the token in as the benchmark user, exactly once.
//! **Real PKCS#11 login state is per-TOKEN, not per-session** — a second
//! `C_Login` on an already-logged-in token returns
//! `CKR_USER_ALREADY_LOGGED_IN`, confirmed the hard way (this module's own
//! test suite hit it before this design settled: calling the combined
//! `native::open_session` — which performs `C_OpenSession` + `C_Login`
//! together — for a SECOND client session failed with exactly that code).
//! So [`open_session`] does NOT call `native::open_session`; it opens a
//! bare session via `ffi::C_OpenSession` directly (no login attempt) and
//! separately checks the caller's PIN at the application layer against the
//! well-known benchmark credential — giving the wire contract a
//! meaningful wrong-credential outcome (`CKR_PIN_INCORRECT`) without
//! re-triggering the engine's per-token login constraint. This mirrors
//! bench-harness's own worker-session pattern (`pkcs11.rs`: "one
//! `C_OpenSession` per worker thread... no per-worker login because login
//! state is per-token not per-session").
//!
//! Single-tenant by design (plan §1.3's inherited-gap note applies). The
//! user PIN defaults to the well-known benchmark value "1234" so the sandbox,
//! bench-harness and developer runs keep working unchanged. A deployment sets
//! a real one (2026-10-11, owner decision for the CACP appliance boards):
//!
//! - `PKCS11_REMOTE_USER_PIN_FILE` — path of a file holding the PIN (first
//!   line, surrounding whitespace ignored); wins over the variable below.
//!   Set but unreadable, empty or out of range is a startup error, never a
//!   silent fall back to the benchmark PIN.
//! - `PKCS11_REMOTE_USER_PIN` — the PIN itself (for containers/tests).
//! - `PKCS11_REMOTE_TOKEN_LABEL` — token label, default `pqctoday-remoting`.
//!
//! The SO PIN is never used by a client, so it is random per process.

use crate::algorithm::Algorithm;
use crate::error::CkError;
use softhsmrustv3::constants::{
    CKF_RW_SESSION, CKF_SERIAL_SESSION, CKR_MECHANISM_INVALID, CKR_OK, CKR_PIN_INCORRECT,
};
use softhsmrustv3::{ffi, native};

const SLOT: u32 = 0;
/// Default user PIN: the well-known benchmark value. See module doc.
const DEFAULT_USER_PIN: &str = "1234";
const DEFAULT_TOKEN_LABEL: &str = "pqctoday-remoting";
/// The engine's advertised `ulMinPinLen` / `ulMaxPinLen`.
const PIN_LEN: std::ops::RangeInclusive<usize> = 4..=256;

struct Credentials {
    user_pin: String,
    so_pin: String,
    label: String,
}

static CREDENTIALS: std::sync::OnceLock<Credentials> = std::sync::OnceLock::new();

fn credentials() -> Result<&'static Credentials, CkError> {
    if let Some(c) = CREDENTIALS.get() {
        return Ok(c);
    }
    let c = load_credentials(|k| std::env::var(k).ok())?;
    Ok(CREDENTIALS.get_or_init(|| c))
}

fn load_credentials(var: impl Fn(&str) -> Option<String>) -> Result<Credentials, CkError> {
    let user_pin = if let Some(path) = var("PKCS11_REMOTE_USER_PIN_FILE").filter(|p| !p.is_empty()) {
        let text = std::fs::read_to_string(&path).map_err(|e| {
            eprintln!("pqctoday-remoting: cannot read PKCS11_REMOTE_USER_PIN_FILE {path}: {e}");
            CkError(softhsmrustv3::constants::CKR_GENERAL_ERROR)
        })?;
        text.lines().next().unwrap_or("").trim().to_string()
    } else if let Some(pin) = var("PKCS11_REMOTE_USER_PIN") {
        pin.trim().to_string()
    } else {
        DEFAULT_USER_PIN.to_string()
    };
    if !PIN_LEN.contains(&user_pin.len()) {
        eprintln!(
            "pqctoday-remoting: user PIN must be {}-{} bytes, got {}",
            PIN_LEN.start(),
            PIN_LEN.end(),
            user_pin.len()
        );
        return Err(CkError(softhsmrustv3::constants::CKR_PIN_LEN_RANGE));
    }
    let label = var("PKCS11_REMOTE_TOKEN_LABEL")
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .unwrap_or_else(|| DEFAULT_TOKEN_LABEL.to_string());
    Ok(Credentials { user_pin, so_pin: random_hex(16)?, label })
}

fn random_hex(bytes: usize) -> Result<String, CkError> {
    use std::io::Read;
    let mut buf = vec![0u8; bytes];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .map_err(|_| CkError(softhsmrustv3::constants::CKR_GENERAL_ERROR))?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// Compare without an early exit on the first differing byte.
fn pin_matches(given: &str, expected: &str) -> bool {
    let (a, b) = (given.as_bytes(), expected.as_bytes());
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// One-time engine + token bootstrap. Call exactly once per process before
/// serving any request. Idempotent is NOT guaranteed by the engine for
/// `init_token` — callers must not call this twice in one process. Leaves
/// the token logged in as the benchmark user for the process's lifetime;
/// the bootstrap session handle itself is intentionally discarded (client
/// sessions are opened separately by [`open_session`]).
pub fn bootstrap() -> Result<(), CkError> {
    let c = credentials()?;
    native::bootstrap_default_token(SLOT, &c.so_pin, &c.user_pin, &c.label)
        .map(|_| ())
        .map_err(CkError::from)
}

pub struct HealthInfo {
    pub ok: bool,
    pub remoting_core_version: &'static str,
}

pub fn health() -> HealthInfo {
    HealthInfo { ok: true, remoting_core_version: env!("CARGO_PKG_VERSION") }
}

/// Open a new session as the configured user. `pin` must equal the user
/// PIN from [`credentials`] — checked here at the application layer (see
/// module doc for why this can't be a real per-session `C_Login`); a
/// mismatch returns the real spec `CKR_PIN_INCORRECT` numeric code, so the
/// wire error-mapping contract (WP5a) is exercised identically to a
/// genuine engine-sourced error even though the check itself is ours.
pub fn open_session(pin: &str) -> Result<u32, CkError> {
    if !pin_matches(pin, &credentials()?.user_pin) {
        return Err(CkError(CKR_PIN_INCORRECT));
    }
    let mut handle: u32 = 0;
    let rv = ffi::C_OpenSession(
        SLOT,
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        &mut handle,
    );
    if rv == CKR_OK { Ok(handle) } else { Err(CkError(rv)) }
}

pub fn close_session(session: u32) -> Result<(), CkError> {
    let rv = ffi::C_CloseSession(session);
    if rv == CKR_OK { Ok(()) } else { Err(CkError(rv)) }
}

/// `(public_handle, private_handle)`.
pub fn generate_key_pair(
    session: u32,
    algorithm: Algorithm,
    cka_id: &[u8],
    label: &str,
) -> Result<(u32, u32), CkError> {
    let result = match algorithm {
        Algorithm::Ed25519 => native::generate_ed25519_keypair(session, cka_id, label),
        Algorithm::MlDsa44 | Algorithm::MlDsa65 | Algorithm::MlDsa87 => {
            let ps = algorithm.parameter_set().expect("ML-DSA cells carry a parameter set");
            native::generate_ml_dsa_keypair(session, ps, cka_id, label)
        }
        Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024 => {
            let ps = algorithm.parameter_set().expect("ML-KEM cells carry a parameter set");
            native::generate_ml_kem_keypair(session, ps, cka_id, label)
        }
    };
    result.map_err(CkError::from)
}

/// Sign `data` with the private key at `key_handle`. `algorithm` must be a
/// signature cell (Ed25519 or ML-DSA-*) — calling this with a KEM
/// algorithm is a caller bug, not a wire condition, so it panics rather
/// than manufacturing a CKR_* code that never came from the engine.
///
/// `external_mu` (added 2026-08-31): FIPS 204 external-µ mode,
/// ML-DSA-only — when true, `data` is treated as the already-computed
/// 64-byte message representative µ rather than the raw message (see
/// `SignRequest.external_mu`'s proto doc). `external_mu=true` with
/// `Algorithm::Ed25519` is a genuine WIRE condition (a caller can trigger
/// it from network input, unlike the KEM/signature mismatch above), so it
/// returns `CKR_MECHANISM_INVALID` rather than asserting.
pub fn sign(
    session: u32,
    key_handle: u32,
    algorithm: Algorithm,
    data: &[u8],
    external_mu: bool,
) -> Result<Vec<u8>, CkError> {
    assert!(algorithm.is_signature(), "sign() called with a KEM algorithm: {algorithm}");
    if external_mu && algorithm == Algorithm::Ed25519 {
        return Err(CkError(CKR_MECHANISM_INVALID));
    }
    let mechanism = algorithm.sign_mechanism();
    let result = match algorithm {
        Algorithm::Ed25519 => native::sign(session, key_handle, mechanism, data),
        // External-hedged default (deterministic=false, internal=false,
        // random=None) — matches bench-harness's own KMIP arm convention
        // (kmip.rs's `sign` helper), so a cross-arm comparison isn't
        // secretly comparing different signing modes. `external_mu` is
        // the one knob this verb exposes on the wire.
        _ => native::sign_pqc(session, key_handle, mechanism, data, &[], false, false, external_mu, None),
    };
    result.map_err(CkError::from)
}

/// Verify `signature` over `data`. Returns `Ok(true/false)` for a
/// well-formed check (matching the engine's own `native::verify`
/// convention); `Err` only for a genuine fault, never for "the signature
/// didn't check out" — `native::verify_pqc`'s `Err(CKR_SIGNATURE_INVALID)`
/// is normalized to `Ok(false)` here so callers see one convention
/// regardless of algorithm family. `external_mu` — see [`sign`]'s doc.
pub fn verify(
    session: u32,
    key_handle: u32,
    algorithm: Algorithm,
    data: &[u8],
    signature: &[u8],
    external_mu: bool,
) -> Result<bool, CkError> {
    assert!(algorithm.is_signature(), "verify() called with a KEM algorithm: {algorithm}");
    if external_mu && algorithm == Algorithm::Ed25519 {
        return Err(CkError(CKR_MECHANISM_INVALID));
    }
    let mechanism = algorithm.sign_mechanism();
    match algorithm {
        Algorithm::Ed25519 => native::verify(session, key_handle, mechanism, data, signature).map_err(CkError::from),
        _ => {
            match native::verify_pqc(session, key_handle, mechanism, data, signature, &[], false, external_mu) {
                Ok(()) => Ok(true),
                Err(rv) if rv == softhsmrustv3::constants::CKR_SIGNATURE_INVALID => Ok(false),
                Err(e) => Err(CkError::from(e)),
            }
        }
    }
}

/// Encapsulate against the public key at `key_handle`. Returns
/// `(ciphertext, shared_secret)`.
pub fn encapsulate(session: u32, key_handle: u32, algorithm: Algorithm) -> Result<(Vec<u8>, Vec<u8>), CkError> {
    assert!(algorithm.is_kem(), "encapsulate() called with a signature algorithm: {algorithm}");
    native::encapsulate(session, key_handle, algorithm.kem_mechanism()).map_err(CkError::from)
}

/// Decapsulate `ciphertext` with the private key at `key_handle`.
pub fn decapsulate(
    session: u32,
    key_handle: u32,
    algorithm: Algorithm,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CkError> {
    assert!(algorithm.is_kem(), "decapsulate() called with a signature algorithm: {algorithm}");
    native::decapsulate(session, key_handle, algorithm.kem_mechanism(), ciphertext).map_err(CkError::from)
}

/// The 8th verb (added 2026-08-25): build and return a self-signed X.509
/// certificate (DER) for a signature-capable keypair already generated
/// on this token — the only verb in this crate that returns a public
/// key's real bytes at all. See `cert.rs`'s own module doc for the full
/// design (why this needed adding, why it's built independently of
/// `pqctoday-kmip`'s own certificate code, and why ML-KEM is rejected).
pub fn get_self_signed_certificate(
    session: u32,
    public_handle: u32,
    private_handle: u32,
    algorithm: Algorithm,
    subject_cn: &str,
    validity_days: i64,
) -> Result<Vec<u8>, CkError> {
    crate::cert::self_signed_certificate(session, public_handle, private_handle, algorithm, subject_cn, validity_days)
}

#[cfg(test)]
mod credential_tests {
    use super::*;
    use std::collections::HashMap;

    fn load(vars: &[(&str, &str)]) -> Result<Credentials, CkError> {
        let m: HashMap<String, String> = vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        load_credentials(|k| m.get(k).cloned())
    }

    #[test]
    fn defaults_keep_the_benchmark_pin_and_label() {
        let c = load(&[]).unwrap();
        assert_eq!((c.user_pin.as_str(), c.label.as_str()), ("1234", "pqctoday-remoting"));
        assert_eq!(c.so_pin.len(), 32);
        assert_ne!(c.so_pin, load(&[]).unwrap().so_pin, "SO PIN is random per load");
    }

    #[test]
    fn pin_file_wins_over_the_variable() {
        let dir = std::env::temp_dir().join(format!("remoting-pin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("pin");
        std::fs::write(&f, "  board-pin-77 \nignored second line\n").unwrap();
        let c = load(&[("PKCS11_REMOTE_USER_PIN_FILE", f.to_str().unwrap()), ("PKCS11_REMOTE_USER_PIN", "env-pin")]).unwrap();
        assert_eq!(c.user_pin, "board-pin-77");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn variable_and_label_are_used() {
        let c = load(&[("PKCS11_REMOTE_USER_PIN", "env-pin"), ("PKCS11_REMOTE_TOKEN_LABEL", "mx95-remote")]).unwrap();
        assert_eq!((c.user_pin.as_str(), c.label.as_str()), ("env-pin", "mx95-remote"));
    }

    #[test]
    fn a_configured_but_unusable_pin_is_an_error_not_the_default() {
        assert!(load(&[("PKCS11_REMOTE_USER_PIN_FILE", "/nonexistent/remoting-pin")]).is_err());
        assert_eq!(load(&[("PKCS11_REMOTE_USER_PIN", "123")]).err().map(|e| e.0), Some(softhsmrustv3::constants::CKR_PIN_LEN_RANGE));
        assert!(load(&[("PKCS11_REMOTE_USER_PIN", "")]).is_err());
    }

    #[test]
    fn pin_comparison() {
        assert!(pin_matches("1234", "1234"));
        assert!(!pin_matches("1235", "1234"));
        assert!(!pin_matches("12345", "1234"));
    }
}
