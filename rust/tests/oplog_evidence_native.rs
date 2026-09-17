//! Gap-2 remediation (docs/remediation-plan-auth-visibility-evidence-log-09102026.md)
//! — the `native::*` entry points KMIP and PKCS#11 remoting actually call
//! (never `ffi::C_*`, confirmed by `grep -rl oplog kmip/src rust/src` before
//! this change) now emit the same PQCEV grammar as the ffi:: wrappers.
//!
//! Separate integration-test FILE from `oplog_evidence.rs` on purpose — same
//! reason that file gives for not adding a "logging off" case in-process:
//! `oplog`'s sink is a per-binary `OnceLock`, so a second `#[test]` fn in
//! that same file would share its already-resolved sink rather than getting
//! its own. A new file is a new test binary, hence a new process.

use softhsmrustv3::constants::*;
use softhsmrustv3::{native, state};

#[test]
fn native_entry_points_emit_pqcev_records() {
    let dir = std::env::temp_dir().join(format!("pqcev-rust-native-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let log_path = dir.join("hsm-ops.log");
    // SAFETY: single-threaded, before any engine code has run.
    unsafe { std::env::set_var(softhsmrustv3::oplog::ENV_VAR, &log_path) };

    assert!(
        softhsmrustv3::oplog::enabled(),
        "sink did not open — the rest of this test would pass vacuously"
    );

    native::init().expect("engine init");
    let slot = 0u32;
    state::ensure_slot(slot);
    native::init_token(slot, "12345678", "evidence-native").expect("init_token");
    let so = native::open_session_so(slot, "12345678").expect("SO session");
    native::init_pin(so, "87654321").expect("init_pin");
    native::logout(so).expect("logout SO");
    native::close_session(so).expect("close SO session");
    let sess = native::open_session(slot, "87654321").expect("user session");

    // ── GenerateKeyPair (ML-DSA) + Sign (PQC path: native::sign_pqc) ────────
    let (mldsa_pub, mldsa_priv) =
        native::generate_ml_dsa_keypair(sess, CKP_ML_DSA_65, b"ev", "evidence-mldsa65")
            .expect("ml-dsa keygen");
    let msg = b"native-path operation-evidence smoke test";
    let sig = native::sign_pqc(
        sess,
        mldsa_priv,
        CKM_ML_DSA,
        msg,
        b"",
        false,
        false,
        false,
        None,
    )
    .expect("sign_pqc");
    assert_eq!(sig.len(), 3309, "ML-DSA-65 signature length (FIPS 204 Table 2)");

    // ── GenerateKeyPair (Ed25519) + Sign (classical path: native::sign) ─────
    // The exact call PKCS#11 remoting makes for its benchmark's Ed25519 arm
    // (remoting/core/src/verbs.rs: `Algorithm::Ed25519 => native::sign(...)`).
    let (ed_pub, ed_priv) =
        native::generate_ed25519_keypair(sess, b"ev", "evidence-ed25519").expect("ed25519 keygen");
    let ed_sig = native::sign(sess, ed_priv, CKM_EDDSA, msg).expect("sign (classical)");
    assert_eq!(ed_sig.len(), 64, "Ed25519 signature length (RFC 8032)");

    // ── GenerateKeyPair (ML-KEM) + EncapsulateKey + DecapsulateKey ──────────
    let (mlkem_pub, mlkem_priv) =
        native::generate_ml_kem_keypair(sess, CKP_ML_KEM_768, b"ev", "evidence-mlkem768")
            .expect("ml-kem keygen");
    let (ct, ss_enc) = native::encapsulate(sess, mlkem_pub, CKM_ML_KEM).expect("encapsulate");
    let ss_dec = native::decapsulate(sess, mlkem_priv, CKM_ML_KEM, &ct).expect("decapsulate");
    assert_eq!(ss_enc, ss_dec, "encapsulate/decapsulate shared secret must match");

    // ── Verify (remediation-plan-verify-evidence-and-relp-receiver-pqc-
    // 09102026.md): both entry points, genuine AND corrupted signatures, so
    // the evidence log distinguishes a real CKR_OK from a real
    // CKR_SIGNATURE_INVALID rather than only ever proving the happy path.
    let ok = native::verify(sess, ed_pub, CKM_EDDSA, msg, &ed_sig).expect("verify (classical)");
    assert!(ok, "genuine Ed25519 signature must verify");
    let mut bad_ed_sig = ed_sig.clone();
    bad_ed_sig[0] ^= 0xFF;
    let bad = native::verify(sess, ed_pub, CKM_EDDSA, msg, &bad_ed_sig).expect("verify (classical, corrupted)");
    assert!(!bad, "corrupted Ed25519 signature must NOT verify");

    native::verify_pqc(sess, mldsa_pub, CKM_ML_DSA, msg, &sig, b"", false, false)
        .expect("verify_pqc: genuine ML-DSA signature must verify");
    let mut bad_mldsa_sig = sig.clone();
    bad_mldsa_sig[0] ^= 0xFF;
    let verify_pqc_err = native::verify_pqc(sess, mldsa_pub, CKM_ML_DSA, msg, &bad_mldsa_sig, b"", false, false)
        .expect_err("corrupted ML-DSA signature must be rejected");
    assert_eq!(verify_pqc_err, CKR_SIGNATURE_INVALID);

    let log = std::fs::read_to_string(&log_path).expect("evidence log readable");
    let records: Vec<&str> = log.lines().filter(|l| l.starts_with("PQCEV ")).collect();

    // Three GenerateKeyPair records: ML-DSA, Ed25519, ML-KEM.
    let keygens: Vec<&&str> = records.iter().filter(|r| r.contains("op=C_GenerateKeyPair")).collect();
    assert_eq!(keygens.len(), 3, "expected 3 GenerateKeyPair records: {keygens:?}");
    assert!(keygens.iter().any(|r| r.contains("mech=CKM_ML_DSA_KEY_PAIR_GEN")));
    assert!(keygens.iter().any(|r| r.contains("mech=CKM_EC_EDWARDS_KEY_PAIR_GEN")));
    assert!(keygens.iter().any(|r| r.contains("mech=CKM_ML_KEM_KEY_PAIR_GEN")));
    for r in &keygens {
        assert!(r.contains("rv=CKR_OK"), "keygen should have succeeded: {r}");
        assert!(!r.contains("hpriv=0 "), "private handle must be non-zero on success: {r}");
    }

    // Two sign operations (sign_pqc for ML-DSA, sign for Ed25519), each as a
    // paired C_SignInit + C_Sign, matching the ffi:: grammar exactly.
    let sign_inits: Vec<&&str> = records.iter().filter(|r| r.contains("op=C_SignInit")).collect();
    let signs: Vec<&&str> = records.iter().filter(|r| r.contains("op=C_Sign ")).collect();
    assert_eq!(sign_inits.len(), 2, "expected 2 C_SignInit records: {sign_inits:?}");
    assert_eq!(signs.len(), 2, "expected 2 C_Sign records: {signs:?}");
    assert!(sign_inits.iter().any(|r| r.contains("mech=CKM_ML_DSA ") || r.contains("mech=CKM_ML_DSA\t")));
    assert!(sign_inits.iter().any(|r| r.contains("mech=CKM_EDDSA")));
    assert!(signs.iter().any(|r| r.contains("out=3309")), "ML-DSA sign record");
    assert!(signs.iter().any(|r| r.contains("out=64")), "Ed25519 sign record");
    for r in &signs {
        assert!(r.contains("probe=0"), "native sign has no length-query phase: {r}");
        assert!(r.contains("rv=CKR_OK"), "sign should have succeeded: {r}");
    }

    // One EncapsulateKey, one DecapsulateKey.
    let encaps: Vec<&&str> = records.iter().filter(|r| r.contains("op=C_EncapsulateKey")).collect();
    let decaps: Vec<&&str> = records.iter().filter(|r| r.contains("op=C_DecapsulateKey")).collect();
    assert_eq!(encaps.len(), 1, "expected 1 EncapsulateKey record: {encaps:?}");
    assert_eq!(decaps.len(), 1, "expected 1 DecapsulateKey record: {decaps:?}");
    assert!(encaps[0].contains("mech=CKM_ML_KEM"));
    assert!(encaps[0].contains("rv=CKR_OK"));
    assert!(decaps[0].contains("mech=CKM_ML_KEM"));
    assert!(decaps[0].contains("rv=CKR_OK"));
    // ML-KEM-768 ciphertext is 1088 bytes (FIPS 203 §7).
    assert!(encaps[0].contains("ct=1088"), "encaps ciphertext size: {}", encaps[0]);
    assert!(decaps[0].contains("ct=1088"), "decaps ciphertext size: {}", decaps[0]);

    // Four verify operations (2 classical via native::verify, 2 PQC via
    // native::verify_pqc — genuine + corrupted each), each as a paired
    // C_VerifyInit + C_Verify, matching the ffi:: grammar exactly.
    let verify_inits: Vec<&&str> = records.iter().filter(|r| r.contains("op=C_VerifyInit")).collect();
    let verifies: Vec<&&str> = records.iter().filter(|r| r.contains("op=C_Verify ")).collect();
    assert_eq!(verify_inits.len(), 4, "expected 4 C_VerifyInit records: {verify_inits:?}");
    assert_eq!(verifies.len(), 4, "expected 4 C_Verify records: {verifies:?}");
    let ok_verifies: Vec<&&&str> = verifies.iter().filter(|r| r.contains("rv=CKR_OK")).collect();
    let invalid_verifies: Vec<&&&str> =
        verifies.iter().filter(|r| r.contains("rv=CKR_SIGNATURE_INVALID")).collect();
    assert_eq!(ok_verifies.len(), 2, "2 genuine signatures should verify OK: {verifies:?}");
    assert_eq!(
        invalid_verifies.len(), 2,
        "2 corrupted signatures should be rejected, not silently ignored: {verifies:?}"
    );
    for r in &verifies {
        assert!(r.contains("probe=0"), "native verify has no length-query phase: {r}");
    }

    // Grammar/join-key sanity, same as oplog_evidence.rs.
    for r in &records {
        assert!(r.contains(&format!("sess={sess}")), "missing sess=: {r}");
        assert!(r.contains("pid="), "missing pid=: {r}");
        assert!(r.starts_with("PQCEV v=1 ts="), "grammar drift: {r}");
    }

    let _ = std::fs::remove_dir_all(&dir);
}
