//! Accelerator precedence for the AWS-LC CPU path (`crypto::awslc_pq`).
//!
//! When `hw_accel` installs a fips204 ML-DSA-65 hook it calls
//! `awslc_pq::defer_mldsa65_to_accelerator`. From then on ML-DSA-65 signing
//! (and, for the matrix/vector hook, key generation) must stay on fips204 so
//! the FPGA keeps first claim; verification and the other parameter sets keep
//! the AWS-LC path. The switch is process-wide and one-way, so this lives in
//! its own test binary (its own process).
#![cfg(not(target_arch = "wasm32"))]

use softhsmrustv3::constants::*;
use softhsmrustv3::crypto::awslc_pq;
use softhsmrustv3::crypto::handlers;

#[cfg(feature = "hw-accel")]
static HOOK_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Stands in for the FPGA signer: counts the call and declines, so fips204
/// finishes the signature on the CPU (its normal fallback).
#[cfg(feature = "hw-accel")]
fn declining_sign_hook(_input: &fips204::Mldsa65SignInput<'_>, _signature: &mut [u8]) -> bool {
    HOOK_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    false
}

#[test]
fn installed_mldsa65_hook_keeps_signing_on_fips204() {
    if !awslc_pq::enabled() {
        eprintln!("PQC_AWSLC_PQ_DISABLE set: nothing is routed, nothing to check");
        return;
    }
    let keys = |ps| handlers::ml_dsa_keygen_from_seed(ps, &[5; 32]).unwrap();
    let (pk65, sk65) = keys(CKP_ML_DSA_65);
    let (_, sk44) = keys(CKP_ML_DSA_44);

    // Before any accelerator: ML-DSA-65 signing and keygen are routed.
    assert!(awslc_pq::mldsa_sign(CKP_ML_DSA_65, &sk65, b"m", b"").is_some());
    assert!(awslc_pq::mldsa_keygen_from_seed(CKP_ML_DSA_65, &[5; 32]).is_some());

    #[cfg(feature = "hw-accel")]
    assert!(fips204::set_mldsa65_sign_hook(declining_sign_hook));
    awslc_pq::defer_mldsa65_to_accelerator(true);

    // ML-DSA-65 signing and keygen now decline the AWS-LC path ...
    assert!(awslc_pq::mldsa_sign(CKP_ML_DSA_65, &sk65, b"m", b"").is_none());
    assert!(
        awslc_pq::mldsa_sign(0, &sk65, b"m", b"").is_none(),
        "unset set = ML-DSA-65"
    );
    assert!(awslc_pq::mldsa_sign_mu(CKP_ML_DSA_65, &sk65, &[1; 64]).is_none());
    assert!(awslc_pq::mldsa_keygen_from_seed(CKP_ML_DSA_65, &[5; 32]).is_none());
    // ... while verification and the other sets keep it.
    assert!(awslc_pq::mldsa_sign(CKP_ML_DSA_44, &sk44, b"m", b"").is_some());
    let sig = handlers::sign_ml_dsa(CKM_ML_DSA, CKP_ML_DSA_65, &sk65, b"m", b"", false).unwrap();
    assert_eq!(
        awslc_pq::mldsa_verify(CKP_ML_DSA_65, &pk65, b"m", &sig, b""),
        Some(true)
    );
    // Keys are unchanged whichever backend generates them.
    assert_eq!(
        handlers::ml_dsa_keygen_from_seed(CKP_ML_DSA_65, &[5; 32]).unwrap(),
        (pk65, sk65)
    );

    // The routed handler's ML-DSA-65 signature went through the hook.
    #[cfg(feature = "hw-accel")]
    assert!(
        HOOK_CALLS.load(std::sync::atomic::Ordering::SeqCst) >= 1,
        "fips204 offered it to the accelerator"
    );
}
