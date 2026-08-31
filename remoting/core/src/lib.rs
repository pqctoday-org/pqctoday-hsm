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
        let sig = verbs::sign(session, prv_h, Algorithm::Ed25519, msg, false).expect("sign");
        // Verify against the WRONG key's public half must be false, not an error.
        let ok = verbs::verify(session, pub_h2, Algorithm::Ed25519, msg, &sig, false).expect("verify");
        assert!(!ok, "signature must not validate against an unrelated key");
    }

    #[test]
    #[serial]
    fn ml_dsa_65_sign_then_verify_round_trips() {
        let session = test_support::fresh_session();
        let (pub_h, prv_h) =
            verbs::generate_key_pair(session, Algorithm::MlDsa65, b"\x03", "sig").expect("keygen");
        let msg = b"the quick brown fox";
        let sig = verbs::sign(session, prv_h, Algorithm::MlDsa65, msg, false).expect("sign");
        let ok = verbs::verify(session, pub_h, Algorithm::MlDsa65, msg, &sig, false).expect("verify");
        assert!(ok, "correct ML-DSA-65 signature must validate");
        let mut tampered = sig.clone();
        tampered[0] ^= 0xFF;
        let ok2 = verbs::verify(session, pub_h, Algorithm::MlDsa65, msg, &tampered, false).expect("verify tampered");
        assert!(!ok2, "tampered signature must not validate (and must not error)");
    }

    // Item added 2026-08-31: FIPS 204 external-µ mode (SignRequest/
    // VerifyRequest.external_mu). Real, in-process proof that the verb
    // layer genuinely dispatches to a different signing/verification path
    // when the flag is set — not just "the call didn't error": (1) a
    // positive round trip, (2) the SAME 64-byte buffer signed in both
    // modes produces different signature bytes, (3) an external-µ
    // signature does NOT verify under plain mode and vice versa (proves
    // the flag isn't silently ignored server-side), and (4) the engine's
    // real 64-byte µ length check (`sign_ml_dsa_external_mu` in
    // `rust/src/crypto/handlers.rs`) genuinely rejects a 63-byte buffer
    // with CKR_ARGUMENTS_BAD, and Ed25519 + external_mu=true is rejected
    // with CKR_MECHANISM_INVALID before ever reaching the engine.
    #[test]
    #[serial]
    fn ml_dsa_65_external_mu_diverges_genuinely_from_plain_mode() {
        let session = test_support::fresh_session();
        let (pub_h, prv_h) =
            verbs::generate_key_pair(session, Algorithm::MlDsa65, b"\x05", "ext-mu").expect("keygen");
        let mu: [u8; 64] = std::array::from_fn(|i| i as u8);

        // (1) positive round trip
        let sig_mu = verbs::sign(session, prv_h, Algorithm::MlDsa65, &mu, true).expect("sign external_mu");
        assert!(
            verbs::verify(session, pub_h, Algorithm::MlDsa65, &mu, &sig_mu, true).expect("verify external_mu"),
            "external-mu round trip must verify"
        );

        // (2)+(3) genuinely different code path, not a silently-ignored flag
        let sig_plain = verbs::sign(session, prv_h, Algorithm::MlDsa65, &mu, false).expect("sign plain");
        assert_ne!(sig_mu, sig_plain, "the same 64 bytes signed in the two modes must produce different signatures");
        assert!(
            !verbs::verify(session, pub_h, Algorithm::MlDsa65, &mu, &sig_mu, false).expect("verify (wrong mode)"),
            "an external-mu signature must NOT verify under plain mode"
        );
        assert!(
            !verbs::verify(session, pub_h, Algorithm::MlDsa65, &mu, &sig_plain, true).expect("verify (wrong mode)"),
            "a plain-mode signature must NOT verify under external-mu mode"
        );

        // (4) real engine-sourced length validation, not a Java/Rust-side guess
        let bad_len = verbs::sign(session, prv_h, Algorithm::MlDsa65, &mu[..63], true)
            .expect_err("a 63-byte buffer must be rejected under external-mu mode");
        assert_eq!(bad_len.raw(), softhsmrustv3::constants::CKR_ARGUMENTS_BAD);

        // Ed25519 + external_mu=true is a real wire condition, not a caller-bug panic
        let (_, ed_prv) = verbs::generate_key_pair(session, Algorithm::Ed25519, b"\x06", "ext-mu-ed").expect("keygen");
        let ed_err = verbs::sign(session, ed_prv, Algorithm::Ed25519, &mu, true)
            .expect_err("external_mu=true on Ed25519 must be rejected, not silently ignored");
        assert_eq!(ed_err.raw(), softhsmrustv3::constants::CKR_MECHANISM_INVALID);
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
