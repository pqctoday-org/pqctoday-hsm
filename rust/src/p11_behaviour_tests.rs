//! PKCS#11 v3.2 behaviour findings E5–E10, E18, E19 (ACVP gap-closure plan,
//! 2026-09-25). Each test mirrors a Hub G-8 error-path probe
//! (`pqctoday-hub` `src/wasm/pkcs11ConformanceRunner/errorPathCatalog.ts`)
//! against the real FFI entry points, and asserts the PKCS#11 v3.2 value the
//! probe asserts — never the engine's previous answer.
//!
//! Keys are hand-inserted into the object store (public, so no login gate)
//! with exactly the attributes the check under test reads; no test here
//! reaches the cryptography, so key material is placeholder bytes.

use super::*;
use crate::native::test_lock;

/// High fixed handles, disjoint from every other ffi test module.
const SESSION: u32 = 0x5E50_1001;
const RO_SESSION: u32 = 0x5E50_1002;
const AES_KEY: u32 = 0x5E50_2001;
const EC_PRIV: u32 = 0x5E50_2002;
const EC_PUB: u32 = 0x5E50_2003;
const AES_NO_USAGE: u32 = 0x5E50_2004;
const EC_PUB_NO_USAGE: u32 = 0x5E50_2005;
const TYPED_NO_USAGE: u32 = 0x5E50_2006;

const CKF_ENCRYPT: u32 = 0x0000_0100;
const CKF_DECRYPT: u32 = 0x0000_0200;
const CKF_SIGN: u32 = 0x0000_0800;
const CKF_SIGN_RECOVER: u32 = 0x0000_1000;
const CKF_VERIFY: u32 = 0x0000_2000;
const CKF_VERIFY_RECOVER: u32 = 0x0000_4000;
const CKF_DERIVE: u32 = 0x0008_0000;

/// Every usage attribute an operation in this file may check.
const ALL_USAGE: [u32; 10] = [
    CKA_ENCRYPT,
    CKA_DECRYPT,
    CKA_SIGN,
    CKA_VERIFY,
    CKA_SIGN_RECOVER,
    CKA_VERIFY_RECOVER,
    CKA_WRAP,
    CKA_UNWRAP,
    CKA_DERIVE,
    CKA_ENCAPSULATE,
];

fn put_key(handle: u32, class: u32, key_type: u32, value_len: usize, usage: bool) {
    OBJECTS.with(|o| {
        let mut attrs = Attributes::new();
        attrs.insert(CKA_VALUE, vec![0x42u8; value_len]);
        store_ulong(&mut attrs, CKA_CLASS, class);
        store_ulong(&mut attrs, CKA_KEY_TYPE, key_type);
        store_bool(&mut attrs, CKA_PRIVATE, false);
        store_bool(&mut attrs, CKA_EXTRACTABLE, true);
        for a in ALL_USAGE {
            store_bool(&mut attrs, a, usage);
        }
        store_bool(&mut attrs, CKA_DECAPSULATE, usage);
        o.borrow_mut().insert(handle, attrs);
    });
}

fn setup() {
    crate::state::set_initialized(true);
    SESSIONS.with(|s| {
        let mut s = s.borrow_mut();
        s.insert(SESSION, crate::state::SessionState { slot_id: 0, rw_session: true });
        s.insert(RO_SESSION, crate::state::SessionState { slot_id: 0, rw_session: false });
    });
    TOKEN_STORE.with(|ts| {
        ts.borrow_mut().entry(0).or_insert_with(|| crate::state::TokenState {
            slot_id: 0,
            initialized: true,
            label: [0u8; 32],
            login_state: crate::state::LoginState::User,
            so_pin_salt: [0u8; 16],
            so_pin_hash: [0u8; 32],
            user_pin_salt: None,
            user_pin_hash: None,
        });
    });
    for sess in [SESSION, RO_SESSION] {
        SIGN_STATE.with(|s| s.borrow_mut().remove(&sess));
        VERIFY_STATE.with(|s| s.borrow_mut().remove(&sess));
        ENCRYPT_STATE.with(|s| s.borrow_mut().remove(&sess));
        DECRYPT_STATE.with(|s| s.borrow_mut().remove(&sess));
        SIGN_RECOVER_STATE.with(|s| s.borrow_mut().remove(&sess));
        VERIFY_RECOVER_STATE.with(|s| s.borrow_mut().remove(&sess));
        MESSAGE_ENCRYPT_STATE.with(|s| s.borrow_mut().remove(&sess));
        MESSAGE_DECRYPT_STATE.with(|s| s.borrow_mut().remove(&sess));
    }
    // The G-8 probe's wrong keys: AES-256 with every usage attribute set
    // (for asymmetric mechanisms) and an EC P-256 pair (for secret-key
    // mechanisms) — errorPathProbes.ts `wrongKey`.
    put_key(AES_KEY, CKO_SECRET_KEY, CKK_AES, 32, true);
    put_key(EC_PRIV, CKO_PRIVATE_KEY, CKK_EC, 32, true);
    put_key(EC_PUB, CKO_PUBLIC_KEY, CKK_EC, 65, true);
    put_key(AES_NO_USAGE, CKO_SECRET_KEY, CKK_AES, 32, false);
    put_key(EC_PUB_NO_USAGE, CKO_PUBLIC_KEY, CKK_EC, 65, false);
}

fn mech0(m: u32) -> [usize; 3] {
    [m as usize, 0, 0]
}

/// The probe's wrong-type key for `mech`: an EC key when the mechanism
/// accepts AES keys (a secret-key mechanism), otherwise the AES key.
fn wrong_key_for(mech: u32, public_role: bool) -> u32 {
    let allowed = mech_key_types(mech)
        .unwrap_or_else(|| panic!("mechanism {mech:#x} has no key-type entry (mech_key_types)"));
    if allowed.contains(&CKK_AES) || allowed.contains(&CKK_GENERIC_SECRET) {
        if public_role { EC_PUB } else { EC_PRIV }
    } else {
        AES_KEY
    }
}

/// Mechanisms with no key-type check at init, each for a stated reason:
/// PBKDF2 takes no base key (the password travels in its parameter), and the
/// vendor BIP32 derivations validate the base key's own chain-code material.
const NO_KEY_TYPE_CHECK: &[u32] = &[CKM_PKCS5_PBKD2, CKM_BIP32_MASTER_DERIVE, CKM_BIP32_CHILD_DERIVE];

/// Advertised mechanisms whose C_GetMechanismInfo flags include `flag`.
/// Deliberately NOT filtered through `mech_key_types`: a mechanism that
/// loses its table entry must fail these tests, not silently drop out.
fn advertised_with(flag: u32) -> Vec<u32> {
    SUPPORTED_MECHS
        .iter()
        .copied()
        .filter(|m| mechanism_info(*m).map(|(_, _, f)| f & flag != 0).unwrap_or(false))
        .filter(|m| !NO_KEY_TYPE_CHECK.contains(m))
        .collect()
}

// ── E5 — wrong key type accepted at operation init ──────────────────────────

/// §5.13.1 / §5.15.1 (return values), §5.1.6 CKR_KEY_TYPE_INCONSISTENT:
/// C_SignInit / C_VerifyInit (and C_MessageSignInit / C_MessageVerifyInit,
/// which delegate to them) with a key of another type. The G-8 probe found
/// CKR_OK for all 85 probed sign mechanisms.
#[test]
fn e5_sign_verify_init_wrong_key_type_is_key_type_inconsistent() {
    let _guard = test_lock::acquire();
    setup();
    let sign = advertised_with(CKF_SIGN);
    let verify = advertised_with(CKF_VERIFY);
    assert!(sign.len() >= 80, "expected the full sign surface, got {}", sign.len());
    for mech in &sign {
        let mut m = mech0(*mech);
        let rv = C_SignInit(SESSION, m.as_mut_ptr() as *mut u8, wrong_key_for(*mech, false));
        assert_eq!(rv, CKR_KEY_TYPE_INCONSISTENT, "C_SignInit mech {mech:#x}");
    }
    for mech in &verify {
        let mut m = mech0(*mech);
        let rv = C_VerifyInit(SESSION, m.as_mut_ptr() as *mut u8, wrong_key_for(*mech, true));
        assert_eq!(rv, CKR_KEY_TYPE_INCONSISTENT, "C_VerifyInit mech {mech:#x}");
    }
    // §5.14.1 / §5.16.1 — the message-based forms (CKM_ML_DSA, CKM_SLH_DSA).
    for mech in [CKM_ML_DSA, CKM_SLH_DSA] {
        let mut m = mech0(mech);
        assert_eq!(
            C_MessageSignInit(SESSION, m.as_mut_ptr() as *mut u8, AES_KEY),
            CKR_KEY_TYPE_INCONSISTENT,
            "C_MessageSignInit mech {mech:#x}"
        );
        assert_eq!(
            C_MessageVerifyInit(SESSION, m.as_mut_ptr() as *mut u8, AES_KEY),
            CKR_KEY_TYPE_INCONSISTENT,
            "C_MessageVerifyInit mech {mech:#x}"
        );
    }
    assert!(!SIGN_STATE.with(|s| s.borrow().contains_key(&SESSION)), "no sign op may start");
    assert!(!VERIFY_STATE.with(|s| s.borrow().contains_key(&SESSION)), "no verify op may start");
}

/// §5.8.1 / §5.10.1: C_EncryptInit / C_DecryptInit. The probe found CKR_OK
/// for CKM_RSA_PKCS / CKM_RSA_PKCS_OAEP with an AES key.
#[test]
fn e5_encrypt_decrypt_init_wrong_key_type_is_key_type_inconsistent() {
    let _guard = test_lock::acquire();
    setup();
    let enc = advertised_with(CKF_ENCRYPT);
    assert!(enc.contains(&CKM_RSA_PKCS) && enc.contains(&CKM_RSA_PKCS_OAEP));
    for mech in &enc {
        let mut m = mech0(*mech);
        let rv = C_EncryptInit(SESSION, m.as_mut_ptr() as *mut u8, wrong_key_for(*mech, true));
        assert_eq!(rv, CKR_KEY_TYPE_INCONSISTENT, "C_EncryptInit mech {mech:#x}");
    }
    for mech in &advertised_with(CKF_DECRYPT) {
        let mut m = mech0(*mech);
        let rv = C_DecryptInit(SESSION, m.as_mut_ptr() as *mut u8, wrong_key_for(*mech, false));
        assert_eq!(rv, CKR_KEY_TYPE_INCONSISTENT, "C_DecryptInit mech {mech:#x}");
    }
    assert!(!ENCRYPT_STATE.with(|s| s.borrow().contains_key(&SESSION)));
    assert!(!DECRYPT_STATE.with(|s| s.borrow().contains_key(&SESSION)));
}

/// §5.13.5 / §5.15.5: C_SignRecoverInit / C_VerifyRecoverInit (CKM_RSA_PKCS,
/// CKM_RSA_X_509) with an AES key.
#[test]
fn e5_recover_init_wrong_key_type_is_key_type_inconsistent() {
    let _guard = test_lock::acquire();
    setup();
    assert_eq!(advertised_with(CKF_SIGN_RECOVER).len(), 2, "CKM_RSA_PKCS + CKM_RSA_X_509");
    assert_eq!(advertised_with(CKF_VERIFY_RECOVER).len(), 2, "CKM_RSA_PKCS + CKM_RSA_X_509");
    for mech in advertised_with(CKF_SIGN_RECOVER) {
        let mut m = mech0(mech);
        assert_eq!(
            C_SignRecoverInit(SESSION, m.as_mut_ptr() as *mut u8, AES_KEY),
            CKR_KEY_TYPE_INCONSISTENT,
            "C_SignRecoverInit mech {mech:#x}"
        );
    }
    for mech in advertised_with(CKF_VERIFY_RECOVER) {
        let mut m = mech0(mech);
        assert_eq!(
            C_VerifyRecoverInit(SESSION, m.as_mut_ptr() as *mut u8, AES_KEY),
            CKR_KEY_TYPE_INCONSISTENT,
            "C_VerifyRecoverInit mech {mech:#x}"
        );
    }
}

/// §5.18.5: C_DeriveKey with a base key of another type. The probe found
/// CKR_OK for all 17 probed derive mechanisms (CKM_ECDH1_DERIVE with an AES
/// key actually derived a secret).
#[test]
fn e5_derive_wrong_base_key_type_is_key_type_inconsistent() {
    let _guard = test_lock::acquire();
    setup();
    let derive = advertised_with(CKF_DERIVE);
    assert!(derive.len() >= 17, "expected the full derive surface, got {}", derive.len());
    for mech in &derive {
        let mut m = mech0(*mech);
        let mut h_new: u32 = 0;
        let rv = C_DeriveKey(
            SESSION,
            m.as_mut_ptr() as *mut u8,
            wrong_key_for(*mech, false),
            std::ptr::null_mut(),
            0,
            &mut h_new,
        );
        assert_eq!(rv, CKR_KEY_TYPE_INCONSISTENT, "C_DeriveKey mech {mech:#x}");
        assert_eq!(h_new, 0, "mech {mech:#x}: no key object on failure");
    }
}

/// §5.9.1 / §5.11.1: C_MessageEncryptInit / C_MessageDecryptInit
/// (CKM_AES_GCM) with an EC key.
#[test]
fn e5_message_encrypt_init_wrong_key_type_is_key_type_inconsistent() {
    let _guard = test_lock::acquire();
    setup();
    let mut m = mech0(CKM_AES_GCM);
    assert_eq!(
        C_MessageEncryptInit(SESSION, m.as_mut_ptr() as *mut u8, EC_PUB),
        CKR_KEY_TYPE_INCONSISTENT
    );
    assert_eq!(
        C_MessageDecryptInit(SESSION, m.as_mut_ptr() as *mut u8, EC_PRIV),
        CKR_KEY_TYPE_INCONSISTENT
    );
}

// ── E6 — CKR_KEY_TYPE_INCONSISTENT outranks CKR_KEY_FUNCTION_NOT_PERMITTED ───

/// §5.1.6: CKR_KEY_TYPE_INCONSISTENT "has a higher priority than
/// CKR_KEY_FUNCTION_NOT_PERMITTED". A wrong-type key that ALSO lacks the
/// usage attribute reported CKR_KEY_FUNCTION_NOT_PERMITTED for 13 AES /
/// ChaCha20 mechanisms at C_EncryptInit / C_DecryptInit, the RSA recover
/// inits, C_MessageEncryptInit, and C_EncapsulateKey — for which §5.18.8
/// does not list CKR_KEY_FUNCTION_NOT_PERMITTED at all.
#[test]
fn e6_key_type_outranks_key_function_not_permitted() {
    let _guard = test_lock::acquire();
    setup();
    for mech in advertised_with(CKF_ENCRYPT) {
        let wrong = if wrong_key_for(mech, true) == AES_KEY { AES_NO_USAGE } else { EC_PUB_NO_USAGE };
        let mut m = mech0(mech);
        assert_eq!(
            C_EncryptInit(SESSION, m.as_mut_ptr() as *mut u8, wrong),
            CKR_KEY_TYPE_INCONSISTENT,
            "C_EncryptInit mech {mech:#x}"
        );
        assert_eq!(
            C_DecryptInit(SESSION, m.as_mut_ptr() as *mut u8, wrong),
            CKR_KEY_TYPE_INCONSISTENT,
            "C_DecryptInit mech {mech:#x}"
        );
    }
    for mech in [CKM_RSA_PKCS, CKM_RSA_X_509] {
        let mut m = mech0(mech);
        assert_eq!(
            C_SignRecoverInit(SESSION, m.as_mut_ptr() as *mut u8, AES_NO_USAGE),
            CKR_KEY_TYPE_INCONSISTENT
        );
        assert_eq!(
            C_VerifyRecoverInit(SESSION, m.as_mut_ptr() as *mut u8, AES_NO_USAGE),
            CKR_KEY_TYPE_INCONSISTENT
        );
    }
    let mut gcm = mech0(CKM_AES_GCM);
    assert_eq!(
        C_MessageEncryptInit(SESSION, gcm.as_mut_ptr() as *mut u8, EC_PUB_NO_USAGE),
        CKR_KEY_TYPE_INCONSISTENT
    );
    // C_EncapsulateKey (§5.18.8) — CKM_ML_KEM and ECDH-as-KEM with an AES key
    // that also lacks CKA_ENCAPSULATE.
    for mech in [CKM_ML_KEM, CKM_ECDH1_DERIVE] {
        let mut m = mech0(mech);
        let mut ct_len: u32 = 0;
        let mut h_new: u32 = 0;
        assert_eq!(
            C_EncapsulateKey(
                SESSION,
                m.as_mut_ptr() as *mut u8,
                AES_NO_USAGE,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut ct_len,
                &mut h_new,
            ),
            CKR_KEY_TYPE_INCONSISTENT,
            "C_EncapsulateKey mech {mech:#x}"
        );
    }
}

/// The other half of the §5.1.6 ordering: a key of the RIGHT type without
/// the usage attribute still answers CKR_KEY_FUNCTION_NOT_PERMITTED (the
/// G-8 `key-function-not-permitted` probe, which already passed — kept
/// passing).
#[test]
fn e6_right_type_without_usage_is_still_key_function_not_permitted() {
    let _guard = test_lock::acquire();
    setup();
    put_key(TYPED_NO_USAGE, CKO_SECRET_KEY, CKK_AES, 32, false);
    let mut cbc = mech0(CKM_AES_CBC);
    assert_eq!(
        C_EncryptInit(SESSION, cbc.as_mut_ptr() as *mut u8, TYPED_NO_USAGE),
        CKR_KEY_FUNCTION_NOT_PERMITTED
    );
    let mut cmac = mech0(CKM_AES_CMAC);
    assert_eq!(
        C_SignInit(SESSION, cmac.as_mut_ptr() as *mut u8, TYPED_NO_USAGE),
        CKR_KEY_FUNCTION_NOT_PERMITTED
    );
    put_key(TYPED_NO_USAGE, CKO_PRIVATE_KEY, CKK_ML_DSA, 32, false);
    let mut mldsa = mech0(CKM_ML_DSA);
    assert_eq!(
        C_SignInit(SESSION, mldsa.as_mut_ptr() as *mut u8, TYPED_NO_USAGE),
        CKR_KEY_FUNCTION_NOT_PERMITTED
    );
}
