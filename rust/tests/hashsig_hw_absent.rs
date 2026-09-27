//! A profile without the hash-signature engine (today's `mldsa` profile, or
//! no FPGA at all) behaves exactly as before: `C_Initialize`'s probe finds no
//! UIO map at the engine's address, opens, creates and locks nothing, and
//! installs no hook, so every hash-based signature runs on ARM.
#![cfg(all(feature = "hw-accel", target_os = "linux", target_arch = "aarch64"))]

use softhsmrustv3::hw_accel;

#[test]
fn probe_without_the_engine_installs_nothing() {
    use pqc_hw::hashsig_device::device::{HashsigSession, ENGINES};
    assert!(!HashsigSession::present(0), "no hashsig UIO map on this host");
    hw_accel::probe_on_initialize();
    assert!(hw_accel::hashsig().is_none());
    assert!(!hw_accel::available());
    assert!(
        !std::path::Path::new(ENGINES[0].lock_path).exists(),
        "the absent engine's lock file is never created"
    );

    // Hash-based signing is unchanged (and still deterministic).
    use fips205::traits::{KeyGen, Signer, Verifier};
    let (pk, sk) = fips205::slh_dsa_shake_128s::KG::keygen_with_seeds::<16>(&[1; 16], &[2; 16], &[3; 16]);
    let first = sk.try_sign(b"m", b"", false).unwrap();
    assert_eq!(first, sk.try_sign(b"m", b"", false).unwrap());
    assert!(pk.verify(b"m", &first, b""));
}
