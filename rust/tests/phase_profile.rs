#![cfg(feature = "phase-profile")]

use softhsmrustv3::constants::{
    CKM_ML_DSA, CKP_ML_DSA_65, CKP_ML_KEM_768, CKP_SLH_DSA_SHAKE_128S,
};
use softhsmrustv3::{native, state};

#[test]
fn diagnostic_profile_covers_all_target_algorithms_without_secret_data() {
    let dir = std::env::temp_dir().join(format!("pqc-phase-profile-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp directory");
    let output = dir.join("phases.jsonl");
    unsafe { std::env::set_var("PQC_PHASE_PROFILE_OUTPUT", &output) };

    native::init().expect("engine init");
    state::ensure_slot(0);
    native::init_token(0, "12345678", "phase-profile").expect("token init");
    let so = native::open_session_so(0, "12345678").expect("SO login");
    native::init_pin(so, "87654321").expect("user PIN");
    native::logout(so).expect("SO logout");
    native::close_session(so).expect("close SO session");
    let session = native::open_session(0, "87654321").expect("user login");

    native::generate_ml_kem_keypair(session, CKP_ML_KEM_768, b"p", "profile-mlkem")
        .expect("ML-KEM keygen");
    let (public, private) =
        native::generate_ml_dsa_keypair(session, CKP_ML_DSA_65, b"p", "profile-mldsa")
            .expect("ML-DSA keygen");
    native::generate_slh_dsa_keypair(session, CKP_SLH_DSA_SHAKE_128S, b"p", "profile-slhdsa")
        .expect("SLH-DSA keygen");

    let message = b"profile rejection-loop boundaries";
    let signature = native::sign_pqc(
        session, private, CKM_ML_DSA, message, &[], true, false, false, None,
    )
    .expect("ML-DSA-65 signing");
    native::verify_pqc(
        session, public, CKM_ML_DSA, message, &signature, &[], false, false,
    )
    .expect("ML-DSA-65 verification");

    let contents = std::fs::read_to_string(&output).expect("profile output");
    let records: Vec<serde_json::Value> = contents
        .lines()
        .map(|line| serde_json::from_str(line).expect("valid JSONL record"))
        .collect();
    for algorithm in ["ML-KEM-768", "ML-DSA-65", "SLH-DSA"] {
        let row = records
            .iter()
            .find(|row| row["algorithm"] == algorithm && row["operation"] == "keygen")
            .unwrap_or_else(|| panic!("missing {algorithm} keygen record: {records:?}"));
        assert_eq!(row["schema"], "pqctoday.pqc-phase-profile.v1");
        assert!(row["duration_ns"].as_u64().unwrap() > 0);
        assert!(row.get("input").is_none());
        assert!(row.get("output").is_none());
    }
    let signed = records
        .iter()
        .find(|row| row["algorithm"] == "ML-DSA-65" && row["operation"] == "sign")
        .expect("ML-DSA-65 sign record");
    let loop_metric = &signed["rejection_loop"];
    let attempts = loop_metric["attempts"].as_u64().expect("attempt count");
    let bounds = loop_metric["rejected_bounds"].as_u64().expect("bounds rejects");
    let hint = loop_metric["rejected_hint"].as_u64().expect("hint rejects");
    assert!(attempts >= 1);
    assert_eq!(attempts, bounds + hint + 1);
    assert_eq!(loop_metric["accepted"], 1);
    assert!(signed.get("rho_prime").is_none());
    assert!(signed.get("secret").is_none());

    native::close_session(session).expect("close session");
    let _ = std::fs::remove_dir_all(dir);
}
