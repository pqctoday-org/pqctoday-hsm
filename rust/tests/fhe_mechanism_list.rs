// SPDX-License-Identifier: AGPL-3.0-only
//! FHE custody mechanisms in C_GetMechanismList / C_GetMechanismInfo (owner decision F19, plan D02387 WP-A3; spec
//! docs/proposals/pkcs11-ckm-pqctoday-fhe-proposal.md §8, §10, §12). Runs in the default native build: KEY_GEN,
//! DERIVE_PUBLIC and DECRYPT are listed and answered once the replication profile is selected, never before, and the
//! test-only ENCRYPT never. One test in its own binary: the profile is process-global.
#![cfg(pqc_ckks_custody)]

use softhsmrustv3::constants::*;
use softhsmrustv3::native;
use softhsmrustv3::replication as repl;

fn list(slot: u32) -> Vec<u32> {
    let mut n = 0u32;
    assert_eq!(C_GetMechanismList(slot, std::ptr::null_mut(), &mut n), CKR_OK);
    let mut v = vec![0u32; n as usize];
    assert_eq!(C_GetMechanismList(slot, v.as_mut_ptr(), &mut n), CKR_OK);
    v.truncate(n as usize);
    v
}

fn info(slot: u32, m: u32) -> Result<(u32, u32, u32), u32> {
    let mut i = [0u32; 3];
    match softhsmrustv3::ffi::C_GetMechanismInfo(slot, m, i.as_mut_ptr() as *mut u8) {
        CKR_OK => Ok((i[0], i[1], i[2])),
        rv => Err(rv),
    }
}

const CKF_DECRYPT: u32 = 0x0000_0200;
const CKF_GENERATE: u32 = 0x0000_8000;
const CKF_DERIVE: u32 = 0x0008_0000;

#[test]
fn fhe_mechanisms_listed_with_the_profile_and_encrypt_never() {
    let _ = native::finalize();
    native::init().expect("init");
    native::init_token(0, "so-pin-list", "fhe-list").expect("init token");
    let fhe = [CKM_PQCTODAY_FHE_KEY_GEN, CKM_PQCTODAY_FHE_DERIVE_PUBLIC, CKM_PQCTODAY_FHE_DECRYPT];

    // Without the profile nothing of custody is discoverable (§12): the mechanisms would return
    // CKR_FUNCTION_NOT_SUPPORTED, so they are neither listed nor answered.
    repl::clear_profile();
    let base = list(0);
    assert_eq!(base, SUPPORTED_MECHS.to_vec());
    for m in fhe.iter().chain([&CKM_PQCTODAY_FHE_ENCRYPT]) {
        assert!(!base.contains(m), "{m:#x} listed without the profile");
        assert_eq!(info(0, *m), Err(CKR_MECHANISM_INVALID), "{m:#x} answered without the profile");
    }

    // With the profile: the three are appended, once each, with the §8 values.
    repl::select_educational_profile();
    let with = list(0);
    assert_eq!(with.len(), base.len() + 3);
    assert_eq!(&with[..base.len()], &base[..]);
    assert_eq!(&with[base.len()..], &fhe[..]);
    assert_eq!(with.iter().filter(|m| fhe.contains(m)).count(), 3, "listed once each");
    assert_eq!(info(0, CKM_PQCTODAY_FHE_KEY_GEN), Ok((32, 32, CKF_GENERATE)));
    assert_eq!(info(0, CKM_PQCTODAY_FHE_DERIVE_PUBLIC), Ok((32, 32, CKF_DERIVE)));
    assert_eq!(info(0, CKM_PQCTODAY_FHE_DECRYPT), Ok((32, 32, CKF_DECRYPT)));
    // Every listed mechanism is answerable (R6.2), the FHE ones included.
    for m in &with {
        assert!(info(0, *m).is_ok(), "{m:#x} listed but not answered");
    }
    // ENCRYPT (test builds only, §5.4) stays hidden in every build.
    assert!(!with.contains(&CKM_PQCTODAY_FHE_ENCRYPT));
    assert_eq!(info(0, CKM_PQCTODAY_FHE_ENCRYPT), Err(CKR_MECHANISM_INVALID));
    // The two-call convention with a short buffer reports the longer count.
    let mut n = base.len() as u32;
    let mut short = vec![0u32; base.len()];
    assert_eq!(C_GetMechanismList(0, short.as_mut_ptr(), &mut n), CKR_BUFFER_TOO_SMALL);
    assert_eq!(n as usize, with.len());

    repl::clear_profile();
    assert_eq!(list(0), base, "listing follows the profile");
    let _ = native::finalize();
}
