//! The seven benchmark verbs, mapped onto `softhsmrustv3::native` calls —
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
//! Single-tenant by design (plan §1.3's inherited-gap note applies): the
//! bootstrap PIN is a well-known benchmark constant, not a security
//! boundary, matching the existing bench-harness/KMIP in-process control
//! arm's own convention (`kmip.rs`'s `bootstrap_default_token(0, "so-pin",
//! "1234", "bench-control")`).

use crate::algorithm::Algorithm;
use crate::error::CkError;
use softhsmrustv3::constants::{CKF_RW_SESSION, CKF_SERIAL_SESSION, CKR_OK, CKR_PIN_INCORRECT};
use softhsmrustv3::{ffi, native};

/// Benchmark-only constants — not a security boundary. See module doc.
const SLOT: u32 = 0;
const SO_PIN: &str = "so-pin";
const USER_PIN: &str = "1234";
const TOKEN_LABEL: &str = "pqctoday-remoting";

/// One-time engine + token bootstrap. Call exactly once per process before
/// serving any request. Idempotent is NOT guaranteed by the engine for
/// `init_token` — callers must not call this twice in one process. Leaves
/// the token logged in as the benchmark user for the process's lifetime;
/// the bootstrap session handle itself is intentionally discarded (client
/// sessions are opened separately by [`open_session`]).
pub fn bootstrap() -> Result<(), CkError> {
    native::bootstrap_default_token(SLOT, SO_PIN, USER_PIN, TOKEN_LABEL)
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

/// Open a new session as the benchmark user. `pin` must equal the
/// well-known [`USER_PIN`] — checked here at the application layer (see
/// module doc for why this can't be a real per-session `C_Login`); a
/// mismatch returns the real spec `CKR_PIN_INCORRECT` numeric code, so the
/// wire error-mapping contract (WP5a) is exercised identically to a
/// genuine engine-sourced error even though the check itself is ours.
pub fn open_session(pin: &str) -> Result<u32, CkError> {
    if pin != USER_PIN {
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
pub fn sign(session: u32, key_handle: u32, algorithm: Algorithm, data: &[u8]) -> Result<Vec<u8>, CkError> {
    assert!(algorithm.is_signature(), "sign() called with a KEM algorithm: {algorithm}");
    let mechanism = algorithm.sign_mechanism();
    let result = match algorithm {
        Algorithm::Ed25519 => native::sign(session, key_handle, mechanism, data),
        // External-hedged default (deterministic=false, internal=false,
        // external_mu=false, random=None) — matches bench-harness's own
        // KMIP arm convention (kmip.rs's `sign` helper), so a cross-arm
        // comparison isn't secretly comparing different signing modes.
        _ => native::sign_pqc(session, key_handle, mechanism, data, &[], false, false, false, None),
    };
    result.map_err(CkError::from)
}

/// Verify `signature` over `data`. Returns `Ok(true/false)` for a
/// well-formed check (matching the engine's own `native::verify`
/// convention); `Err` only for a genuine fault, never for "the signature
/// didn't check out" — `native::verify_pqc`'s `Err(CKR_SIGNATURE_INVALID)`
/// is normalized to `Ok(false)` here so callers see one convention
/// regardless of algorithm family.
pub fn verify(
    session: u32,
    key_handle: u32,
    algorithm: Algorithm,
    data: &[u8],
    signature: &[u8],
) -> Result<bool, CkError> {
    assert!(algorithm.is_signature(), "verify() called with a KEM algorithm: {algorithm}");
    let mechanism = algorithm.sign_mechanism();
    match algorithm {
        Algorithm::Ed25519 => native::verify(session, key_handle, mechanism, data, signature).map_err(CkError::from),
        _ => {
            match native::verify_pqc(session, key_handle, mechanism, data, signature, &[], false, false) {
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
