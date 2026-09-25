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
        ts.borrow_mut()
            .entry(0)
            .or_insert_with(|| crate::state::TokenState {
                slot_id: 0,
                initialized: true,
                label: [0u8; 32],
                login_state: crate::state::LoginState::User,
                so_pin_salt: [0u8; 16],
                so_pin_hash: [0u8; 32],
                user_pin_salt: None,
                user_pin_hash: None,
            })
            .login_state = crate::state::LoginState::User;
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

// ── E7 — wrap / unwrap key-type codes ────────────────────────────────────────

const CKF_WRAP: u32 = 0x0002_0000;
const CKF_UNWRAP: u32 = 0x0004_0000;
const WRAP_TARGET: u32 = 0x5E50_2010;

fn wrap_with(mech: u32, h_wrapping: u32) -> u32 {
    let mut m = mech0(mech);
    let mut out = [0u8; 1024];
    let mut out_len = out.len() as u32;
    C_WrapKey(SESSION, m.as_mut_ptr() as *mut u8, h_wrapping, WRAP_TARGET, out.as_mut_ptr(), &mut out_len)
}

fn unwrap_with(mech: u32, h_unwrapping: u32) -> u32 {
    let mut m = mech0(mech);
    let mut wrapped = [0x5au8; 40];
    let mut h_new: u32 = 0;
    let rv = C_UnwrapKey(
        SESSION,
        m.as_mut_ptr() as *mut u8,
        h_unwrapping,
        wrapped.as_mut_ptr(),
        wrapped.len() as u32,
        std::ptr::null_mut(),
        0,
        &mut h_new,
    );
    assert_eq!(h_new, 0, "mech {mech:#x}: no key object on failure");
    rv
}

/// §5.18.3 / §5.18.4 return values list CKR_WRAPPING_KEY_TYPE_INCONSISTENT /
/// CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT and neither lists
/// CKR_KEY_TYPE_INCONSISTENT. The probe found RSA wrap/unwrap with an AES
/// key answering CKR_KEY_TYPE_INCONSISTENT, and AES wrap/unwrap with an EC
/// key (which lacks CKA_WRAP/CKA_UNWRAP) answering
/// CKR_KEY_FUNCTION_NOT_PERMITTED — which §5.18.3/§5.18.4 do not list and
/// §5.1.6 ranks below the type code.
#[test]
fn e7_wrap_unwrap_wrong_key_type_uses_the_role_specific_code() {
    let _guard = test_lock::acquire();
    setup();
    put_key(WRAP_TARGET, CKO_SECRET_KEY, CKK_GENERIC_SECRET, 32, true);
    let wrap = advertised_with(CKF_WRAP);
    let unwrap = advertised_with(CKF_UNWRAP);
    for m in [CKM_AES_KEY_WRAP, CKM_AES_KEY_WRAP_PAD, CKM_AES_KEY_WRAP_KWP, CKM_RSA_PKCS, CKM_RSA_PKCS_OAEP] {
        assert!(wrap.contains(&m) && unwrap.contains(&m), "{m:#x} advertised for wrap+unwrap");
    }
    for mech in &wrap {
        // Wrapping is the public-key role for RSA; the EC key for AES
        // mechanisms is the probe's EC public key, whose CKA_WRAP the probe
        // leaves unset — covered by the _NO_USAGE variant too.
        for wrong in [wrong_key_for(*mech, true), if wrong_key_for(*mech, true) == AES_KEY { AES_NO_USAGE } else { EC_PUB_NO_USAGE }] {
            assert_eq!(
                wrap_with(*mech, wrong),
                CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
                "C_WrapKey mech {mech:#x} key {wrong:#x}"
            );
        }
    }
    for mech in &unwrap {
        for wrong in [wrong_key_for(*mech, false), if wrong_key_for(*mech, false) == AES_KEY { AES_NO_USAGE } else { EC_PUB_NO_USAGE }] {
            assert_eq!(
                unwrap_with(*mech, wrong),
                CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
                "C_UnwrapKey mech {mech:#x} key {wrong:#x}"
            );
        }
    }
}

/// E7 — a wrapping key of the right type but a size the mechanism cannot
/// use: §5.18.3 / §5.18.4 list CKR_(UN)WRAPPING_KEY_SIZE_RANGE; the AES-KW
/// arms answered CKR_KEY_TYPE_INCONSISTENT for a 20-byte CKK_AES key.
#[test]
fn e7_wrap_unwrap_wrong_aes_kek_size_is_size_range() {
    let _guard = test_lock::acquire();
    setup();
    put_key(WRAP_TARGET, CKO_SECRET_KEY, CKK_GENERIC_SECRET, 32, true);
    put_key(TYPED_NO_USAGE, CKO_SECRET_KEY, CKK_AES, 20, true);
    for mech in [CKM_AES_KEY_WRAP, CKM_AES_KEY_WRAP_KWP] {
        assert_eq!(wrap_with(mech, TYPED_NO_USAGE), CKR_WRAPPING_KEY_SIZE_RANGE, "wrap {mech:#x}");
        let mut m = mech0(mech);
        let mut wrapped = [0x5au8; 40];
        let mut h_new: u32 = 0;
        assert_eq!(
            C_UnwrapKey(
                SESSION,
                m.as_mut_ptr() as *mut u8,
                TYPED_NO_USAGE,
                wrapped.as_mut_ptr(),
                wrapped.len() as u32,
                std::ptr::null_mut(),
                0,
                &mut h_new,
            ),
            CKR_UNWRAPPING_KEY_SIZE_RANGE,
            "unwrap {mech:#x}"
        );
    }
}

// ── E9 / E18 — malformed mechanism parameters (decision D6) ─────────────────

const AES_TYPED: u32 = 0x5E50_2020;
const XTS_TYPED: u32 = 0x5E50_2021;
const CHACHA_TYPED: u32 = 0x5E50_2022;

/// A key of the mechanism's own type with every usage attribute set.
fn right_key_for(mech: u32) -> u32 {
    match mech {
        CKM_AES_XTS => XTS_TYPED,
        CKM_CHACHA20 | CKM_CHACHA20_POLY1305 => CHACHA_TYPED,
        _ => AES_TYPED,
    }
}

fn put_symmetric_keys() {
    put_key(AES_TYPED, CKO_SECRET_KEY, CKK_AES, 32, true);
    put_key(XTS_TYPED, CKO_SECRET_KEY, CKK_AES_XTS, 64, true);
    put_key(CHACHA_TYPED, CKO_SECRET_KEY, CKK_CHACHA20, 32, true);
}

fn mech_with_param(mech: u32, param: &mut [u8]) -> [usize; 3] {
    [mech as usize, param.as_mut_ptr() as usize, param.len()]
}

/// §5.8.1 / §5.10.1 return values, §5.1.6 CKR_MECHANISM_PARAM_INVALID
/// ("invalid parameters were supplied to the mechanism"). The G-8 probe
/// replaced each mechanism's required parameter by a single byte: 11 of
/// them answered CKR_ARGUMENTS_BAD, which C_EncryptInit's §5.8.1 list does
/// not contain (CKM_AES_CTR already answered correctly). Decision D6.
#[test]
fn e9_one_byte_symmetric_parameter_is_mechanism_param_invalid() {
    let _guard = test_lock::acquire();
    setup();
    put_symmetric_keys();
    for mech in [
        CKM_AES_CBC,
        CKM_AES_CBC_PAD,
        CKM_AES_CCM,
        CKM_AES_CFB1,
        CKM_AES_CFB8,
        CKM_AES_CFB128,
        CKM_AES_GCM,
        CKM_AES_OFB,
        CKM_AES_XTS,
        CKM_AES_CTR,
        CKM_CHACHA20,
        CKM_CHACHA20_POLY1305,
    ] {
        let mut one = [0u8; 1];
        let mut m = mech_with_param(mech, &mut one);
        assert_eq!(
            C_EncryptInit(SESSION, m.as_mut_ptr() as *mut u8, right_key_for(mech)),
            CKR_MECHANISM_PARAM_INVALID,
            "C_EncryptInit mech {mech:#x}"
        );
        assert_eq!(
            C_DecryptInit(SESSION, m.as_mut_ptr() as *mut u8, right_key_for(mech)),
            CKR_MECHANISM_PARAM_INVALID,
            "C_DecryptInit mech {mech:#x}"
        );
        // An absent required parameter is the same defect.
        let mut none = mech0(mech);
        assert_eq!(
            C_EncryptInit(SESSION, none.as_mut_ptr() as *mut u8, right_key_for(mech)),
            CKR_MECHANISM_PARAM_INVALID,
            "C_EncryptInit mech {mech:#x}, no parameter"
        );
    }
    assert!(!ENCRYPT_STATE.with(|s| s.borrow().contains_key(&SESSION)));
    assert!(!DECRYPT_STATE.with(|s| s.borrow().contains_key(&SESSION)));
}

/// E18 — §6.11 (AES-CBC, CBC-PAD, OFB, CFB*) and §6.15 (XTS): the parameter
/// is a 16-byte IV / tweak. The WS-E NIST vectors found a wrong-length IV
/// answered CKR_ARGUMENTS_BAD (shorter) or silently truncated to 16 bytes
/// (longer). Both are CKR_MECHANISM_PARAM_INVALID; exactly 16 bytes starts
/// the operation.
#[test]
fn e18_aes_iv_of_the_wrong_length_is_mechanism_param_invalid() {
    let _guard = test_lock::acquire();
    setup();
    put_symmetric_keys();
    for mech in [
        CKM_AES_CBC,
        CKM_AES_CBC_PAD,
        CKM_AES_OFB,
        CKM_AES_CFB1,
        CKM_AES_CFB8,
        CKM_AES_CFB128,
        CKM_AES_XTS,
    ] {
        for len in [8usize, 12, 15, 17, 24, 32] {
            let mut iv = vec![0x11u8; len];
            let mut m = mech_with_param(mech, &mut iv);
            assert_eq!(
                C_EncryptInit(SESSION, m.as_mut_ptr() as *mut u8, right_key_for(mech)),
                CKR_MECHANISM_PARAM_INVALID,
                "C_EncryptInit mech {mech:#x}, {len}-byte IV"
            );
            assert_eq!(
                C_DecryptInit(SESSION, m.as_mut_ptr() as *mut u8, right_key_for(mech)),
                CKR_MECHANISM_PARAM_INVALID,
                "C_DecryptInit mech {mech:#x}, {len}-byte IV"
            );
        }
        let mut iv = vec![0x11u8; 16];
        let mut m = mech_with_param(mech, &mut iv);
        assert_eq!(
            C_EncryptInit(SESSION, m.as_mut_ptr() as *mut u8, right_key_for(mech)),
            CKR_OK,
            "C_EncryptInit mech {mech:#x}, 16-byte IV"
        );
        // §5.8.1 — pMechanism = NULL_PTR terminates the operation.
        assert_eq!(C_EncryptInit(SESSION, std::ptr::null_mut(), right_key_for(mech)), CKR_OK);
    }
}

// ── E9 — RSA-PSS / RSA-OAEP parameter structs are validated (decision D6) ───

const RSA_PRIV: u32 = 0x5E50_2030;
const RSA_PUB: u32 = 0x5E50_2031;

/// RSA-2048 key objects carrying only what the init-time checks read:
/// CKK_RSA, the usage attributes and a 2048-bit CKA_MODULUS.
fn put_rsa_keys() {
    let mut n = vec![0x5au8; 256];
    n[0] = 0xc3; // top bit set → a 2048-bit modulus
    for (h, class) in [(RSA_PRIV, CKO_PRIVATE_KEY), (RSA_PUB, CKO_PUBLIC_KEY)] {
        put_key(h, class, CKK_RSA, 64, true);
        OBJECTS.with(|o| {
            o.borrow_mut().get_mut(&h).unwrap().insert(CKA_MODULUS, n.clone());
        });
    }
}

/// `CK_RSA_PKCS_PSS_PARAMS` at native width.
fn pss(hash_alg: u32, mgf: u32, s_len: usize) -> [usize; 3] {
    [hash_alg as usize, mgf as usize, s_len]
}

const PSS_MECHS: [(u32, u32, u32, usize); 9] = [
    (CKM_SHA1_RSA_PKCS_PSS, CKM_SHA_1, CKG_MGF1_SHA1, 20),
    (CKM_SHA224_RSA_PKCS_PSS, CKM_SHA224, CKG_MGF1_SHA224, 28),
    (CKM_SHA256_RSA_PKCS_PSS, CKM_SHA256, CKG_MGF1_SHA256, 32),
    (CKM_SHA384_RSA_PKCS_PSS, CKM_SHA384, CKG_MGF1_SHA384, 48),
    (CKM_SHA512_RSA_PKCS_PSS, CKM_SHA512, CKG_MGF1_SHA512, 64),
    (CKM_SHA3_224_RSA_PKCS_PSS, CKM_SHA3_224, CKG_MGF1_SHA3_224, 28),
    (CKM_SHA3_256_RSA_PKCS_PSS, CKM_SHA3_256, CKG_MGF1_SHA3_256, 32),
    (CKM_SHA3_384_RSA_PKCS_PSS, CKM_SHA3_384, CKG_MGF1_SHA3_384, 48),
    (CKM_SHA3_512_RSA_PKCS_PSS, CKM_SHA3_512, CKG_MGF1_SHA3_512, 64),
];

fn sign_verify_init_with(mech: u32, param: &mut [usize], len: usize) -> (u32, u32) {
    let mut m: [usize; 3] = [mech as usize, param.as_mut_ptr() as usize, len];
    let s = C_SignInit(SESSION, m.as_mut_ptr() as *mut u8, RSA_PRIV);
    if s == CKR_OK {
        assert_eq!(C_SignInit(SESSION, std::ptr::null_mut(), RSA_PRIV), CKR_OK);
    }
    let v = C_VerifyInit(SESSION, m.as_mut_ptr() as *mut u8, RSA_PUB);
    if v == CKR_OK {
        assert_eq!(C_VerifyInit(SESSION, std::ptr::null_mut(), RSA_PUB), CKR_OK);
    }
    (s, v)
}

/// §6.1.9 (CK_RSA_PKCS_PSS_PARAMS) and §6.1.10/§6.1.11 ("It has a parameter,
/// a CK_RSA_PKCS_PSS_PARAMS structure"; "sLen … must be less than or equal
/// to k*-2-hLen"), §5.1.6 CKR_MECHANISM_PARAM_INVALID. The G-8 probe found
/// C_SignInit / C_VerifyInit accepting a 1-byte parameter (CKR_OK) for all
/// nine hash-specific PSS mechanisms: a short or absent struct silently fell
/// back to defaults, and sLen was never bounded.
#[test]
fn e9_rsa_pss_parameter_struct_is_validated() {
    let _guard = test_lock::acquire();
    setup();
    put_rsa_keys();
    let usz = std::mem::size_of::<usize>();
    for (mech, hash, mgf, hlen) in PSS_MECHS {
        let bad = CKR_MECHANISM_PARAM_INVALID;
        let mut p = pss(hash, mgf, hlen);
        assert_eq!(sign_verify_init_with(mech, &mut p, 1), (bad, bad), "{mech:#x}: 1-byte parameter");
        assert_eq!(sign_verify_init_with(mech, &mut p, 2 * usz), (bad, bad), "{mech:#x}: short struct");
        assert_eq!(sign_verify_init_with(mech, &mut p, 0), (bad, bad), "{mech:#x}: absent parameter");
        let mut wrong_hash = pss(if hash == CKM_SHA256 { CKM_SHA384 } else { CKM_SHA256 }, mgf, hlen);
        assert_eq!(sign_verify_init_with(mech, &mut wrong_hash, 3 * usz), (bad, bad), "{mech:#x}: hashAlg");
        // 2048-bit modulus: k* = 256, so sLen ≤ 254 − hLen.
        let max = 256 - 2 - hlen;
        let mut too_long = pss(hash, mgf, max + 1);
        assert_eq!(sign_verify_init_with(mech, &mut too_long, 3 * usz), (bad, bad), "{mech:#x}: sLen {}", max + 1);
        let mut at_max = pss(hash, mgf, max);
        assert_eq!(sign_verify_init_with(mech, &mut at_max, 3 * usz), (CKR_OK, CKR_OK), "{mech:#x}: sLen {max}");
        let mut good = pss(hash, mgf, hlen);
        assert_eq!(sign_verify_init_with(mech, &mut good, 3 * usz), (CKR_OK, CKR_OK), "{mech:#x}: valid");
    }
    // Bare CKM_RSA_PKCS_PSS (§6.1.10): same struct, same sLen bound.
    let mut p = pss(CKM_SHA256, CKG_MGF1_SHA256, 32);
    let bad = CKR_MECHANISM_PARAM_INVALID;
    assert_eq!(sign_verify_init_with(CKM_RSA_PKCS_PSS, &mut p, 1), (bad, bad));
    let mut too_long = pss(CKM_SHA256, CKG_MGF1_SHA256, 223);
    assert_eq!(sign_verify_init_with(CKM_RSA_PKCS_PSS, &mut too_long, 3 * usz), (bad, bad));
    assert_eq!(sign_verify_init_with(CKM_RSA_PKCS_PSS, &mut p, 3 * usz), (CKR_OK, CKR_OK));
}

/// `CK_RSA_PKCS_OAEP_PARAMS` at native width; the label (if any) must
/// outlive the returned words.
fn oaep(hash_alg: u32, mgf: u32, source: u32, label: Option<&[u8]>, label_len: usize) -> [usize; 5] {
    [
        hash_alg as usize,
        mgf as usize,
        source as usize,
        label.map(|l| l.as_ptr() as usize).unwrap_or(0),
        label_len,
    ]
}

/// Every OAEP entry point with `param` (length `len`): encrypt, decrypt,
/// wrap and unwrap init. Returns the four return values.
fn oaep_calls(param: &mut [usize], len: usize) -> [u32; 4] {
    let mut m: [usize; 3] = [CKM_RSA_PKCS_OAEP as usize, param.as_mut_ptr() as usize, len];
    let e = C_EncryptInit(SESSION, m.as_mut_ptr() as *mut u8, RSA_PUB);
    if e == CKR_OK {
        assert_eq!(C_EncryptInit(SESSION, std::ptr::null_mut(), RSA_PUB), CKR_OK);
    }
    let d = C_DecryptInit(SESSION, m.as_mut_ptr() as *mut u8, RSA_PRIV);
    if d == CKR_OK {
        assert_eq!(C_DecryptInit(SESSION, std::ptr::null_mut(), RSA_PRIV), CKR_OK);
    }
    let mut out = [0u8; 512];
    let mut out_len = out.len() as u32;
    let w = C_WrapKey(SESSION, m.as_mut_ptr() as *mut u8, RSA_PUB, WRAP_TARGET, out.as_mut_ptr(), &mut out_len);
    let mut wrapped = [0x5au8; 256];
    let mut h_new: u32 = 0;
    let u = C_UnwrapKey(
        SESSION,
        m.as_mut_ptr() as *mut u8,
        RSA_PRIV,
        wrapped.as_mut_ptr(),
        wrapped.len() as u32,
        std::ptr::null_mut(),
        0,
        &mut h_new,
    );
    [e, d, w, u]
}

/// §6.1.7 (CK_RSA_PKCS_OAEP_PARAMS: "source must be CKZ_DATA_SPECIFIED";
/// pSourceData "must be NULL_PTR" exactly when ulSourceDataLen is 0) and
/// §6.1.8 ("It has a parameter, a CK_RSA_PKCS_OAEP_PARAMS structure"),
/// §5.1.6 CKR_MECHANISM_PARAM_INVALID. The G-8 probe found a 1-byte
/// parameter accepted (CKR_OK) by C_EncryptInit / C_DecryptInit /
/// C_WrapKey / C_UnwrapKey: a short or absent struct silently became
/// SHA-256 / MGF1-SHA-256, and `source` was only checked for a non-empty
/// label.
#[test]
fn e9_rsa_oaep_parameter_struct_is_validated() {
    let _guard = test_lock::acquire();
    setup();
    put_rsa_keys();
    put_key(WRAP_TARGET, CKO_SECRET_KEY, CKK_GENERIC_SECRET, 32, true);
    let usz = std::mem::size_of::<usize>();
    let full = 5 * usz;
    let bad = [CKR_MECHANISM_PARAM_INVALID; 4];
    let mut p = oaep(CKM_SHA256, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED, None, 0);
    assert_eq!(oaep_calls(&mut p, 1), bad, "1-byte parameter");
    assert_eq!(oaep_calls(&mut p, usz), bad, "hashAlg-only prefix");
    assert_eq!(oaep_calls(&mut p, 4 * usz), bad, "short struct");
    assert_eq!(oaep_calls(&mut p, 0), bad, "absent parameter");
    let mut no_source = oaep(CKM_SHA256, CKG_MGF1_SHA256, 0, None, 0);
    assert_eq!(oaep_calls(&mut no_source, full), bad, "source = 0");
    let mut null_label = oaep(CKM_SHA256, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED, None, 4);
    assert_eq!(oaep_calls(&mut null_label, full), bad, "NULL pSourceData, ulSourceDataLen 4");
    let mut no_mgf = oaep(CKM_SHA256, 0, CKZ_DATA_SPECIFIED, None, 0);
    assert_eq!(oaep_calls(&mut no_mgf, full), bad, "mgf = 0");
    let mut unsupported = oaep(CKM_MD5, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED, None, 0);
    assert_eq!(oaep_calls(&mut unsupported, full), bad, "hashAlg the engine cannot use for OAEP");
    // A well-formed struct gets past parameter validation: the inits start,
    // and wrap / unwrap proceed to the (placeholder) key material.
    let mut good = oaep(CKM_SHA256, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED, None, 0);
    let rv = oaep_calls(&mut good, full);
    assert_eq!(&rv[..2], &[CKR_OK, CKR_OK], "valid struct, encrypt/decrypt init");
    assert!(
        rv[2] != CKR_MECHANISM_PARAM_INVALID && rv[3] != CKR_MECHANISM_PARAM_INVALID,
        "valid struct must not be refused as a parameter error: {rv:x?}"
    );
    let label = b"label";
    let mut labelled = oaep(CKM_SHA384, CKG_MGF1_SHA384, CKZ_DATA_SPECIFIED, Some(label), label.len());
    let rv = oaep_calls(&mut labelled, full);
    assert_eq!(&rv[..2], &[CKR_OK, CKR_OK], "valid labelled struct");
}

// ── E9 — C_DeriveKey with hBaseKey = 0 ──────────────────────────────────────

/// §5.18.5 return values, §5.1.6 CKR_KEY_HANDLE_INVALID ("We reiterate here
/// that 0 is never a valid key handle"). The G-8 probe found
/// CKR_ARGUMENTS_BAD for CKM_ECDH1_DERIVE, CKM_ECDH1_COFACTOR_DERIVE and
/// CKM_HKDF_DERIVE: the base-key check was skipped for handle 0 (reserved for
/// PBKDF2, which has no base key) and the mechanism arm then failed its own
/// value lookup. Every advertised derive mechanism that takes a base key now
/// answers CKR_KEY_HANDLE_INVALID; PBKDF2 keeps accepting 0.
#[test]
fn e9_derive_with_base_key_handle_zero_is_key_handle_invalid() {
    let _guard = test_lock::acquire();
    setup();
    let derive = advertised_with(CKF_DERIVE);
    for m in [CKM_ECDH1_DERIVE, CKM_ECDH1_COFACTOR_DERIVE, CKM_HKDF_DERIVE] {
        assert!(derive.contains(&m), "{m:#x} is advertised for derive");
    }
    for mech in derive.iter().copied().chain([CKM_BIP32_MASTER_DERIVE, CKM_BIP32_CHILD_DERIVE]) {
        let mut m = mech0(mech);
        let mut h_new: u32 = 0;
        assert_eq!(
            C_DeriveKey(SESSION, m.as_mut_ptr() as *mut u8, 0, std::ptr::null_mut(), 0, &mut h_new),
            CKR_KEY_HANDLE_INVALID,
            "C_DeriveKey mech {mech:#x}, hBaseKey = 0"
        );
        assert_eq!(h_new, 0);
    }
    // PBKDF2 derives from the password in its parameter, not from a key.
    let mut m = mech0(CKM_PKCS5_PBKD2);
    let mut h_new: u32 = 0;
    assert_ne!(
        C_DeriveKey(SESSION, m.as_mut_ptr() as *mut u8, 0, std::ptr::null_mut(), 0, &mut h_new),
        CKR_KEY_HANDLE_INVALID,
        "PBKDF2 takes no base key"
    );
}

// ── E10 — C_EncapsulateKey / C_DecapsulateKey in a read-only session ─────────

/// `[CKA_TOKEN, &CK_TRUE, 1]` — a template asking for a token object.
fn token_true_template() -> [usize; 3] {
    let v: &'static u8 = Box::leak(Box::new(1u8));
    [CKA_TOKEN as usize, v as *const u8 as usize, 1]
}

/// §5.18.8 / §5.18.9 return values, §5.1.6 CKR_SESSION_READ_ONLY ("unable to
/// accomplish the desired action because it is a read-only session"), §5.7.1
/// ("Only session objects can be created during a read-only session"). The
/// G-8 probe found C_EncapsulateKey / C_DecapsulateKey creating a token
/// object (CKA_TOKEN = CK_TRUE) from a session opened without
/// CKF_RW_SESSION: CKR_OK for CKM_ML_KEM (all three sets) and
/// CKM_ECDH1_DERIVE. Every other key-creating call already refused.
#[test]
fn e10_kem_calls_cannot_create_a_token_object_in_a_read_only_session() {
    let _guard = test_lock::acquire();
    setup();
    // A real ML-KEM-512 pair and ciphertext, made in the R/W session, so the
    // only thing wrong with the R/O calls below is the session.
    let ps: &'static crate::ck_abi::CK_ULONG =
        Box::leak(Box::new(CKP_ML_KEM_512 as crate::ck_abi::CK_ULONG));
    let mut pub_tpl = [CKA_PARAMETER_SET as usize, ps as *const _ as usize, std::mem::size_of::<crate::ck_abi::CK_ULONG>()];
    let mut prv_tpl = pub_tpl;
    let mut kg = mech0(CKM_ML_KEM_KEY_PAIR_GEN);
    let (mut h_pub, mut h_prv) = (0u32, 0u32);
    assert_eq!(
        C_GenerateKeyPair(
            SESSION,
            kg.as_mut_ptr() as *mut u8,
            pub_tpl.as_mut_ptr() as *mut u8,
            1,
            prv_tpl.as_mut_ptr() as *mut u8,
            1,
            &mut h_pub,
            &mut h_prv,
        ),
        CKR_OK
    );
    let mut kem = mech0(CKM_ML_KEM);
    let mut ct = vec![0u8; 768];
    let mut ct_len = ct.len() as u32;
    let mut h_ss: u32 = 0;
    assert_eq!(
        C_EncapsulateKey(SESSION, kem.as_mut_ptr() as *mut u8, h_pub, std::ptr::null_mut(), 0, ct.as_mut_ptr(), &mut ct_len, &mut h_ss),
        CKR_OK
    );

    let mut tok = token_true_template();
    let before = OBJECTS.with(|o| o.borrow().len());
    let mut ct2 = vec![0u8; 768];
    let mut ct2_len = ct2.len() as u32;
    let mut h_new: u32 = 0;
    assert_eq!(
        C_EncapsulateKey(
            RO_SESSION,
            kem.as_mut_ptr() as *mut u8,
            h_pub,
            tok.as_mut_ptr() as *mut u8,
            1,
            ct2.as_mut_ptr(),
            &mut ct2_len,
            &mut h_new,
        ),
        CKR_SESSION_READ_ONLY,
        "C_EncapsulateKey(CKM_ML_KEM) with CKA_TOKEN=TRUE in a R/O session"
    );
    assert_eq!(h_new, 0);
    assert_eq!(
        C_DecapsulateKey(
            RO_SESSION,
            kem.as_mut_ptr() as *mut u8,
            h_prv,
            tok.as_mut_ptr() as *mut u8,
            1,
            ct.as_mut_ptr(),
            ct_len,
            &mut h_new,
        ),
        CKR_SESSION_READ_ONLY,
        "C_DecapsulateKey(CKM_ML_KEM) with CKA_TOKEN=TRUE in a R/O session"
    );
    assert_eq!(h_new, 0);
    // ECDH-as-KEM goes through the same gate.
    let mut ecdh = mech0(CKM_ECDH1_DERIVE);
    let mut n = 65u32;
    let mut pt = [0u8; 65];
    assert_eq!(
        C_EncapsulateKey(RO_SESSION, ecdh.as_mut_ptr() as *mut u8, EC_PUB, tok.as_mut_ptr() as *mut u8, 1, pt.as_mut_ptr(), &mut n, &mut h_new),
        CKR_SESSION_READ_ONLY
    );
    assert_eq!(
        C_DecapsulateKey(RO_SESSION, ecdh.as_mut_ptr() as *mut u8, EC_PRIV, tok.as_mut_ptr() as *mut u8, 1, pt.as_mut_ptr(), 65, &mut h_new),
        CKR_SESSION_READ_ONLY
    );
    assert_eq!(OBJECTS.with(|o| o.borrow().len()), before, "no object may be created");
    // A session object (CKA_TOKEN absent → FALSE) is still allowed in R/O.
    let mut ct3 = vec![0u8; 768];
    let mut ct3_len = ct3.len() as u32;
    assert_eq!(
        C_EncapsulateKey(RO_SESSION, kem.as_mut_ptr() as *mut u8, h_pub, std::ptr::null_mut(), 0, ct3.as_mut_ptr(), &mut ct3_len, &mut h_new),
        CKR_OK,
        "a session-object encapsulation is permitted in a R/O session"
    );
}

// ── E10 — a second C_MessageEncryptInit while one is active ─────────────────

/// §5.9.1 / §5.11.1 return values, §5.1.6 CKR_OPERATION_ACTIVE ("an active
/// operation … prevents Cryptoki from activating the specified operation").
/// The G-8 probe found a second C_MessageEncryptInit / C_MessageDecryptInit
/// (CKM_AES_GCM, AES-128/256) on the same session returning CKR_OK — it
/// silently replaced the active context. Message-sign/verify and every
/// single-part init already refused. C_Message*Final ends the operation, so
/// a new init succeeds after it.
#[test]
fn e10_second_message_encrypt_init_is_operation_active() {
    let _guard = test_lock::acquire();
    setup();
    put_symmetric_keys();
    let mut gcm = mech0(CKM_AES_GCM);
    assert_eq!(C_MessageEncryptInit(SESSION, gcm.as_mut_ptr() as *mut u8, AES_TYPED), CKR_OK);
    assert_eq!(
        C_MessageEncryptInit(SESSION, gcm.as_mut_ptr() as *mut u8, AES_TYPED),
        CKR_OPERATION_ACTIVE,
        "second C_MessageEncryptInit"
    );
    assert_eq!(C_MessageEncryptFinal(SESSION), CKR_OK);
    assert_eq!(C_MessageEncryptInit(SESSION, gcm.as_mut_ptr() as *mut u8, AES_TYPED), CKR_OK);
    assert_eq!(C_MessageEncryptFinal(SESSION), CKR_OK);

    assert_eq!(C_MessageDecryptInit(SESSION, gcm.as_mut_ptr() as *mut u8, AES_TYPED), CKR_OK);
    assert_eq!(
        C_MessageDecryptInit(SESSION, gcm.as_mut_ptr() as *mut u8, AES_TYPED),
        CKR_OPERATION_ACTIVE,
        "second C_MessageDecryptInit"
    );
    assert_eq!(C_MessageDecryptFinal(SESSION), CKR_OK);
    assert_eq!(C_MessageDecryptInit(SESSION, gcm.as_mut_ptr() as *mut u8, AES_TYPED), CKR_OK);
    assert_eq!(C_MessageDecryptFinal(SESSION), CKR_OK);
}
