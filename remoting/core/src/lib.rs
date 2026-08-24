//! Transport-agnostic verb layer for the PKCS#11 remoting services. See
//! `verbs.rs` for the seven benchmark verbs and their session model,
//! `algorithm.rs` for the representative cell set, `error.rs` for the
//! CKR_* error-mapping contract both wire formats share.

pub mod algorithm;
pub mod error;
pub mod verbs;

pub use algorithm::Algorithm;
pub use error::CkError;

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    /// The engine's storage is process-global (`lazy_static! Mutex<T>`),
    /// so every test that touches it runs `#[serial]` — parallel tests in
    /// this binary would otherwise race the same token/session state,
    /// exactly the reason `native::test_lock` exists inside the engine
    /// crate's own tests (not reachable from here — it's `pub(crate)`).
    // ONE shared bootstrap for the whole test binary — `C_InitToken` wipes
    // and re-creates the token on every call, so calling it once per test
    // (rather than once per process) would invalidate every other test's
    // handles out from under it.
    static BOOTSTRAP: std::sync::Once = std::sync::Once::new();

    fn fresh_bootstrap() -> u32 {
        BOOTSTRAP.call_once(|| verbs::bootstrap().expect("bootstrap"));
        verbs::open_session("1234").expect("open_session")
    }

    #[test]
    #[serial]
    fn ed25519_sign_then_verify_round_trips() {
        let session = fresh_bootstrap();
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
        let session = fresh_bootstrap();
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
        let session = fresh_bootstrap();
        let (pub_h, prv_h) =
            verbs::generate_key_pair(session, Algorithm::MlKem768, b"\x04", "kem").expect("keygen");
        let (ct, ss_enc) = verbs::encapsulate(session, pub_h, Algorithm::MlKem768).expect("encap");
        let ss_dec = verbs::decapsulate(session, prv_h, Algorithm::MlKem768, &ct).expect("decap");
        assert_eq!(ss_enc, ss_dec, "shared secret must round-trip through encap/decap");
    }

    #[test]
    #[serial]
    fn wrong_pin_surfaces_ckr_pin_incorrect() {
        BOOTSTRAP.call_once(|| verbs::bootstrap().expect("bootstrap"));
        let err = verbs::open_session("not-the-pin").expect_err("wrong pin must fail");
        assert_eq!(err.raw(), softhsmrustv3::constants::CKR_PIN_INCORRECT);
    }
}
