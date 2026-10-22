// SPDX-License-Identifier: AGPL-3.0-only
//
//! `CKA_KEYS_REMAINING` (0x61c) on XMSS and XMSS^MT private keys — PKCS#11
//! v3.3 working draft, `xmss_and_xmss-mt.md` (OASIS PKCS 11 TC commit
//! 9ef73f9): the XMSS and XMSS^MT private key tables carry
//! `CKA_KEYS_REMAINING ^2,4^`, "The minimum of the following two values: 1)
//! The number of one-time private keys remaining; 2) 2^32-1", and key pair
//! generation contributes it to the new private key. The public key tables
//! do not list it. Plan workstream A6.
//!
//! The engine-private counter `CKA_PRIV_XMSS_KEYS_REMAINING` (0xFFFF0007)
//! stays; these tests check the standard attribute moves in step with it.
//!
//! Included from `ffi.rs` via `#[path]` so `use super::*` resolves to the FFI
//! module and its private helpers.

use super::*;
use crate::crypto::xmss_bridge::{keys_remaining_attr_bytes, keys_remaining_cap};
use crate::native::test_lock;

const SESSION: u32 = 0x4B52_0001;

fn setup() {
    crate::state::set_initialized(true);
    SESSIONS.insert(SESSION, crate::state::SessionState { slot_id: 0, rw_session: true, context: 0 });
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
}

/// CK_ULONG-width little-endian bytes.
fn ulong(v: u32) -> Vec<u8> {
    (v as usize).to_le_bytes().to_vec()
}

fn gen_pair(mech: u32, param_set: u32) -> (u32, u32) {
    let mut m = [0usize; 3];
    m[0] = mech as usize;
    let val = ulong(param_set);
    let mut t: [usize; 3] = [CKA_PARAMETER_SET as usize, val.as_ptr() as usize, val.len()];
    let (mut hp, mut hs) = (0u32, 0u32);
    let rv = unsafe {
        C_GenerateKeyPair_impl(
            SESSION,
            m.as_mut_ptr() as *mut u8,
            t.as_mut_ptr() as *mut u8,
            1,
            std::ptr::null_mut(),
            0,
            &mut hp,
            &mut hs,
        )
    };
    assert_eq!(rv, CKR_OK, "key pair generation for mechanism {mech:#x} set {param_set:#x}");
    (hp, hs)
}

/// The attribute as a caller reads it, through C_GetAttributeValue.
fn read_keys_remaining(h: u32) -> Result<u64, u32> {
    let mut buf = vec![0u8; std::mem::size_of::<usize>()];
    let mut t: [usize; 3] = [CKA_KEYS_REMAINING as usize, buf.as_mut_ptr() as usize, buf.len()];
    let rv = C_GetAttributeValue(SESSION, h, t.as_mut_ptr() as *mut u8, 1);
    if rv != CKR_OK {
        return Err(rv);
    }
    assert_eq!(t[2], std::mem::size_of::<usize>(), "CKA_KEYS_REMAINING is a CK_ULONG");
    let mut w = [0u8; 8];
    w[..buf.len()].copy_from_slice(&buf);
    Ok(u64::from_le_bytes(w))
}

fn internal_counter(h: u32) -> u32 {
    crate::state::get_object_attr_u32(h, CKA_PRIV_XMSS_KEYS_REMAINING).expect("internal counter")
}

fn sign(mech: u32, hs: u32, msg: &[u8]) -> Result<Vec<u8>, u32> {
    let mut m: [usize; 3] = [mech as usize, 0, 0];
    let rv = C_SignInit(SESSION, m.as_mut_ptr() as *mut u8, hs);
    if rv != CKR_OK {
        return Err(rv);
    }
    let mut d = msg.to_vec();
    let mut sig = vec![0u8; 64 * 1024];
    let mut len = sig.len() as u32;
    let rv = C_Sign(SESSION, d.as_mut_ptr(), d.len() as u32, sig.as_mut_ptr(), &mut len);
    if rv != CKR_OK {
        return Err(rv);
    }
    sig.truncate(len as usize);
    Ok(sig)
}

fn verify(mech: u32, hp: u32, msg: &[u8], sig: &[u8]) -> u32 {
    let mut m: [usize; 3] = [mech as usize, 0, 0];
    assert_eq!(C_VerifyInit(SESSION, m.as_mut_ptr() as *mut u8, hp), CKR_OK);
    let mut d = msg.to_vec();
    let mut s = sig.to_vec();
    C_Verify(SESSION, d.as_mut_ptr(), d.len() as u32, s.as_mut_ptr(), s.len() as u32)
}

#[test]
fn keys_remaining_cap_is_min_of_count_and_2_pow_32_minus_1() {
    assert_eq!(keys_remaining_cap(0), 0);
    assert_eq!(keys_remaining_cap(1024), 1024);
    assert_eq!(keys_remaining_cap(0xFFFF_FFFE), 0xFFFF_FFFE);
    assert_eq!(keys_remaining_cap(0xFFFF_FFFF), 0xFFFF_FFFF);
    assert_eq!(keys_remaining_cap(1u64 << 32), 0xFFFF_FFFF);
    assert_eq!(keys_remaining_cap(1u64 << 40), 0xFFFF_FFFF);
    assert_eq!(keys_remaining_cap(1u64 << 60), 0xFFFF_FFFF);
    assert_eq!(keys_remaining_cap(u64::MAX), 0xFFFF_FFFF);
    // Stored at CK_ULONG width, and the cap is the count 2^32-1 — never
    // widened to CK_UNAVAILABLE_INFORMATION on a 64-bit CK_ULONG.
    let b = keys_remaining_attr_bytes(1u64 << 40);
    assert_eq!(b.len(), std::mem::size_of::<usize>());
    let mut w = [0u8; 8];
    w[..b.len()].copy_from_slice(&b);
    assert_eq!(u64::from_le_bytes(w), 0xFFFF_FFFF);
}

#[test]
fn xmss_keys_remaining_is_on_the_private_key_and_counts_down() {
    let _guard = test_lock::acquire();
    setup();
    let (hp, hs) = gen_pair(CKM_XMSS_KEY_PAIR_GEN, CKP_XMSS_SHA2_10_256);

    // Private key only (xmss_and_xmss-mt.md private key table; the public
    // key table does not list it).
    assert_eq!(read_keys_remaining(hs), Ok(1024), "2^10 one-time keys at generation");
    assert_eq!(read_keys_remaining(hp), Err(CKR_ATTRIBUTE_TYPE_INVALID));

    // The attribute is engine truth: a caller cannot raise it.
    let v = ulong(99_999);
    let mut t: [usize; 3] = [CKA_KEYS_REMAINING as usize, v.as_ptr() as usize, v.len()];
    assert_eq!(C_SetAttributeValue(SESSION, hs, t.as_mut_ptr() as *mut u8, 1), CKR_ATTRIBUTE_READ_ONLY);

    let msg = b"A6: CKA_KEYS_REMAINING moves with every signature";
    for want in [1023u64, 1022, 1021] {
        let sig = sign(CKM_XMSS, hs, msg).expect("sign");
        assert_eq!(verify(CKM_XMSS, hp, msg, &sig), CKR_OK);
        assert_eq!(read_keys_remaining(hs), Ok(want));
        assert_eq!(internal_counter(hs) as u64, want, "standard and internal counters agree");
    }

    // Jump the stored state to the last leaf (index bytes 4..8, big-endian,
    // after the 4-byte OID — see xmss_bridge::xmss_keys_remaining).
    let mut st = crate::state::get_object_attr_bytes(hs, CKA_PRIV_STATEFUL_KEY_STATE).unwrap();
    st[4..8].copy_from_slice(&1023u32.to_be_bytes());
    crate::state::set_object_attrs_bytes_batch(hs, &[(CKA_PRIV_STATEFUL_KEY_STATE, st)]);

    let sig = sign(CKM_XMSS, hs, msg).expect("the last one-time key still signs");
    assert_eq!(verify(CKM_XMSS, hp, msg, &sig), CKR_OK);
    assert_eq!(read_keys_remaining(hs), Ok(0), "the last leaf leaves zero");
    assert_eq!(internal_counter(hs), 0);

    // Exhausted: signing is refused and the counter stays at zero.
    assert!(sign(CKM_XMSS, hs, msg).is_err(), "an exhausted XMSS key must not sign");
    assert_eq!(read_keys_remaining(hs), Ok(0));
}

#[test]
fn xmssmt_keys_remaining_counts_down_and_caps_large_trees() {
    let _guard = test_lock::acquire();
    setup();
    let msg = b"A6: XMSS^MT";

    // Height 20 fits in 32 bits: the exact count.
    let (hp, hs) = gen_pair(CKM_XMSSMT_KEY_PAIR_GEN, CKP_XMSSMT_SHA2_20_4_256);
    assert_eq!(read_keys_remaining(hs), Ok(1 << 20));
    assert_eq!(read_keys_remaining(hp), Err(CKR_ATTRIBUTE_TYPE_INVALID));
    let sig = sign(CKM_XMSSMT, hs, msg).expect("sign");
    assert_eq!(verify(CKM_XMSSMT, hp, msg, &sig), CKR_OK);
    assert_eq!(read_keys_remaining(hs), Ok((1 << 20) - 1));
    assert_eq!(internal_counter(hs), (1 << 20) - 1);

    // Height 40 exceeds it: capped at 2^32-1 at generation and after a
    // signature (2^40 - 1 is still above the cap).
    let (_hp, hs) = gen_pair(CKM_XMSSMT_KEY_PAIR_GEN, CKP_XMSSMT_SHA2_40_8_256);
    assert_eq!(read_keys_remaining(hs), Ok(0xFFFF_FFFF));
    sign(CKM_XMSSMT, hs, msg).expect("sign");
    assert_eq!(read_keys_remaining(hs), Ok(0xFFFF_FFFF));
    assert_eq!(internal_counter(hs), 0xFFFF_FFFF);
}
