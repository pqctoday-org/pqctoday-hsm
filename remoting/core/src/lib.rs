//! Transport-agnostic verb layer for the PKCS#11 remoting services. See
//! `verbs.rs` for the eight verbs and their session model, `algorithm.rs`
//! for the representative cell set, `error.rs` for the CKR_*
//! error-mapping contract both wire formats share, `cert.rs` for the
//! self-signed-certificate verb's own X.509 construction logic.

mod cert;
pub mod algorithm;
pub mod error;
pub mod verbs;
pub mod verbs_v32;

pub use algorithm::Algorithm;
pub use error::CkError;

/// Shared test-only bootstrap gate — used by BOTH this module's own
/// `tests` below and `cert::tests`. A real bug caught live while adding
/// `cert.rs`'s own tests, not hypothetical: `verbs::bootstrap()`'s own
/// doc says calling it twice in one process is not supported
/// (`C_InitToken` is not idempotent), and Rust unit tests across
/// different modules of the SAME crate all run in the SAME test binary
/// process — a second, independently-`Once`-gated bootstrap call in
/// `cert.rs` genuinely raced this one and failed with a real `CkError`
/// from the engine, which then poisoned ITS OWN `Once` for every other
/// test relying on it. One shared gate for the whole test binary is the
/// actual fix, not per-module `Once`s that happen to look identical.
#[cfg(test)]
pub(crate) mod test_support {
    use super::verbs;

    static BOOTSTRAP: std::sync::Once = std::sync::Once::new();

    /// The engine's storage is process-global (`lazy_static! Mutex<T>`),
    /// so every test that touches it must run `#[serial]` — parallel
    /// tests in this binary would otherwise race the same token/session
    /// state, exactly the reason `native::test_lock` exists inside the
    /// engine crate's own tests (not reachable from here — it's
    /// `pub(crate)` there). `C_InitToken` wipes and re-creates the token
    /// on every call, so calling it once per test (rather than once per
    /// process) would invalidate every other test's handles out from
    /// under it — hence the `Once`, not a per-test call.
    pub(crate) fn fresh_session() -> u32 {
        BOOTSTRAP.call_once(|| verbs::bootstrap().expect("bootstrap"));
        verbs::open_session("1234").expect("open_session")
    }

    pub(crate) fn ensure_bootstrapped() {
        BOOTSTRAP.call_once(|| verbs::bootstrap().expect("bootstrap"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    #[serial]
    fn ed25519_sign_then_verify_round_trips() {
        let session = test_support::fresh_session();
        let (_pub_h, prv_h) =
            verbs::generate_key_pair(session, Algorithm::Ed25519, b"\x01", "t").expect("keygen");
        let (pub_h2, _) =
            verbs::generate_key_pair(session, Algorithm::Ed25519, b"\x02", "t2").expect("keygen2");
        let msg = b"hello remoting";
        let sig = verbs::sign(session, prv_h, Algorithm::Ed25519, msg).expect("sign");
        // Verify against the WRONG key's public half must be false, not an error.
        let ok = verbs::verify(session, pub_h2, Algorithm::Ed25519, msg, &sig).expect("verify");
        assert!(!ok, "signature must not validate against an unrelated key");
    }

    #[test]
    #[serial]
    fn ml_dsa_65_sign_then_verify_round_trips() {
        let session = test_support::fresh_session();
        let (pub_h, prv_h) =
            verbs::generate_key_pair(session, Algorithm::MlDsa65, b"\x03", "sig").expect("keygen");
        let msg = b"the quick brown fox";
        let sig = verbs::sign(session, prv_h, Algorithm::MlDsa65, msg).expect("sign");
        let ok = verbs::verify(session, pub_h, Algorithm::MlDsa65, msg, &sig).expect("verify");
        assert!(ok, "correct ML-DSA-65 signature must validate");
        let mut tampered = sig.clone();
        tampered[0] ^= 0xFF;
        let ok2 = verbs::verify(session, pub_h, Algorithm::MlDsa65, msg, &tampered).expect("verify tampered");
        assert!(!ok2, "tampered signature must not validate (and must not error)");
    }

    #[test]
    #[serial]
    fn ml_kem_768_encapsulate_then_decapsulate_recovers_shared_secret() {
        let session = test_support::fresh_session();
        let (pub_h, prv_h) =
            verbs::generate_key_pair(session, Algorithm::MlKem768, b"\x04", "kem").expect("keygen");
        let (ct, ss_enc) = verbs::encapsulate(session, pub_h, Algorithm::MlKem768).expect("encap");
        let ss_dec = verbs::decapsulate(session, prv_h, Algorithm::MlKem768, &ct).expect("decap");
        assert_eq!(ss_enc, ss_dec, "shared secret must round-trip through encap/decap");
    }

    #[test]
    #[serial]
    fn wrong_pin_surfaces_ckr_pin_incorrect() {
        test_support::ensure_bootstrapped();
        let err = verbs::open_session("not-the-pin").expect_err("wrong pin must fail");
        assert_eq!(err.raw(), softhsmrustv3::constants::CKR_PIN_INCORRECT);
    }
}
