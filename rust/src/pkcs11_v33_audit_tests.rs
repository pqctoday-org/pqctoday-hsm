// SPDX-License-Identifier: AGPL-3.0-only
//
//! PKCS#11 v3.2 → v3.3 working-draft delta: the engine gaps found by the
//! 2026-10-21 delta audit (OASIS PKCS 11 TC commit 9ef73f9), one section per
//! fix area. Each test drives the real `C_*` entry points.
//!
//! Included from `ffi.rs` via `#[path]` so `use super::*` resolves to the FFI
//! module and its private helpers.

use super::*;
use crate::native::test_lock;

/// High fixed session handle, disjoint from every other ffi test module.
const SESSION: u32 = 0x5633_4101;

fn setup() {
    crate::state::set_initialized(true);
    SESSIONS.with(|s| {
        s.shard(SESSION)
            .insert(SESSION, crate::state::SessionState { slot_id: 0, rw_session: true, context: 0 });
    });
    set_login(crate::state::LoginState::User);
}

fn set_login(state: crate::state::LoginState) {
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
            .login_state = state;
    });
}

/// CK_ULONG-width little-endian bytes (what an LP64 caller sends).
fn ulong(v: u32) -> Vec<u8> {
    (v as usize).to_le_bytes().to_vec()
}

fn words(entries: &[(u32, Vec<u8>)]) -> Vec<usize> {
    entries
        .iter()
        .flat_map(|(t, v)| {
            let p = if v.is_empty() { 0 } else { v.as_ptr() as usize };
            [*t as usize, p, v.len()]
        })
        .collect()
}

fn keypair(mech: u32, pub_entries: &[(u32, Vec<u8>)], prv_entries: &[(u32, Vec<u8>)]) -> (u32, u32, u32) {
    let mut m: [usize; 3] = [mech as usize, 0, 0];
    let mut pw = words(pub_entries);
    let mut sw = words(prv_entries);
    let (mut h_pub, mut h_prv) = (0u32, 0u32);
    let rv = C_GenerateKeyPair(
        SESSION,
        m.as_mut_ptr() as *mut u8,
        pw.as_mut_ptr() as *mut u8,
        pub_entries.len() as u32,
        sw.as_mut_ptr() as *mut u8,
        prv_entries.len() as u32,
        &mut h_pub,
        &mut h_prv,
    );
    (rv, h_pub, h_prv)
}

fn shake256_64(parts: &[&[u8]]) -> [u8; 64] {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    let mut h = sha3::Shake256::default();
    for p in parts {
        h.update(p);
    }
    let mut out = [0u8; 64];
    h.finalize_xof().read(&mut out);
    out
}

// ── µ generation (CKM_ML_DSA_EXTERNAL_MU_GEN) ───────────────────────────────

fn ml_dsa_pair(ps: u32) -> (u32, u32) {
    let pub_entries = vec![
        (CKA_CLASS, ulong(CKO_PUBLIC_KEY)),
        (CKA_KEY_TYPE, ulong(CKK_ML_DSA)),
        (CKA_TOKEN, vec![0]),
        (CKA_VERIFY, vec![1]),
        (CKA_PARAMETER_SET, ulong(ps)),
    ];
    let prv_entries = vec![
        (CKA_CLASS, ulong(CKO_PRIVATE_KEY)),
        (CKA_KEY_TYPE, ulong(CKK_ML_DSA)),
        (CKA_TOKEN, vec![0]),
        (CKA_PRIVATE, vec![1]),
        (CKA_SENSITIVE, vec![1]),
        (CKA_SIGN, vec![1]),
    ];
    let (rv, hp, hs) = keypair(CKM_ML_DSA_KEY_PAIR_GEN, &pub_entries, &prv_entries);
    assert_eq!(rv, CKR_OK, "ML-DSA key pair, set {ps:#x}");
    (hp, hs)
}

/// `C_DigestInit(CKM_ML_DSA_EXTERNAL_MU_GEN, CK_MU_GEN_PARAMS{hKey, pTR, ctx})`.
fn mu_gen_init(h_key: u32, tr: &[u8], ctx: &[u8]) -> u32 {
    let params: [usize; 5] = [
        h_key as usize,
        if tr.is_empty() { 0 } else { tr.as_ptr() as usize },
        tr.len(),
        if ctx.is_empty() { 0 } else { ctx.as_ptr() as usize },
        ctx.len(),
    ];
    let mut m: [usize; 3] = [
        CKM_ML_DSA_EXTERNAL_MU_GEN as usize,
        params.as_ptr() as usize,
        std::mem::size_of_val(&params),
    ];
    C_DigestInit(SESSION, m.as_mut_ptr() as *mut u8)
}

/// µ through the single-part (`parts.len() == 1`) or multi-part digest path.
fn mu_gen(h_key: u32, tr: &[u8], ctx: &[u8], parts: &[&[u8]]) -> Result<Vec<u8>, u32> {
    let rv = mu_gen_init(h_key, tr, ctx);
    if rv != CKR_OK {
        return Err(rv);
    }
    let mut out = vec![0u8; 64];
    let mut len = out.len() as u32;
    let rv = if parts.len() == 1 {
        let mut d = parts[0].to_vec();
        C_Digest(SESSION, d.as_mut_ptr(), d.len() as u32, out.as_mut_ptr(), &mut len)
    } else {
        for p in parts {
            let mut d = p.to_vec();
            assert_eq!(C_DigestUpdate(SESSION, d.as_mut_ptr(), d.len() as u32), CKR_OK);
        }
        C_DigestFinal(SESSION, out.as_mut_ptr(), &mut len)
    };
    if rv != CKR_OK {
        return Err(rv);
    }
    out.truncate(len as usize);
    Ok(out)
}

fn sign_with(h_key: u32, mech: u32, params: Option<&[usize]>, data: &[u8]) -> Result<Vec<u8>, u32> {
    let mut m: [usize; 3] = match params {
        Some(p) => [mech as usize, p.as_ptr() as usize, std::mem::size_of_val(p)],
        None => [mech as usize, 0, 0],
    };
    let rv = C_SignInit(SESSION, m.as_mut_ptr() as *mut u8, h_key);
    if rv != CKR_OK {
        return Err(rv);
    }
    let mut d = data.to_vec();
    let mut sig = vec![0u8; 8192];
    let mut len = sig.len() as u32;
    let rv = C_Sign(SESSION, d.as_mut_ptr(), d.len() as u32, sig.as_mut_ptr(), &mut len);
    if rv != CKR_OK {
        return Err(rv);
    }
    sig.truncate(len as usize);
    Ok(sig)
}

fn verify_with(h_key: u32, mech: u32, params: Option<&[usize]>, data: &[u8], sig: &[u8]) -> u32 {
    let mut m: [usize; 3] = match params {
        Some(p) => [mech as usize, p.as_ptr() as usize, std::mem::size_of_val(p)],
        None => [mech as usize, 0, 0],
    };
    let rv = C_VerifyInit(SESSION, m.as_mut_ptr() as *mut u8, h_key);
    if rv != CKR_OK {
        return rv;
    }
    let mut d = data.to_vec();
    let mut s = sig.to_vec();
    C_Verify(SESSION, d.as_mut_ptr(), d.len() as u32, s.as_mut_ptr(), s.len() as u32)
}

/// ml_dsa.md (v3.3 working draft): hKey is "public or private"; tr is
/// H(pk, 64) (FIPS 204 Algorithm 7 line 6) whichever half is named. µ from
/// the public handle, the private handle, a precomputed tr, and an independent
/// FIPS 204 Eq. 2 computation must all agree, single- and multi-part; and a
/// signature over that µ with CKM_ML_DSA_EXTERNAL_MU must verify as a plain
/// CKM_ML_DSA signature over the message with the same context.
///
/// Before the fix the private handle hashed the private key's CKA_VALUE, so
/// its µ differed and the signature failed to verify.
#[test]
fn mu_gen_from_public_private_and_tr_agree_and_sign_verifies() {
    let _guard = test_lock::acquire();
    setup();
    let msg = b"external mu: public, private and tr agree";
    let ctx = b"v33 audit ctx";
    for ps in [CKP_ML_DSA_44, CKP_ML_DSA_65, CKP_ML_DSA_87] {
        let (hp, hs) = ml_dsa_pair(ps);
        let pk = crate::state::get_object_value(hp).expect("public CKA_VALUE");
        let tr = shake256_64(&[&pk]);
        let want = shake256_64(&[&tr, &[0u8], &[ctx.len() as u8], ctx, msg]);

        let mu_pub = mu_gen(hp, &[], ctx, &[msg]).expect("µ from the public key");
        let mu_prv = mu_gen(hs, &[], ctx, &[msg]).expect("µ from the private key");
        let mu_tr = mu_gen(0, &tr, ctx, &[msg]).expect("µ from tr");
        let mu_parts = mu_gen(hs, &[], ctx, &[&msg[..7], &msg[7..20], &msg[20..]]).expect("multi-part µ");
        assert_eq!(mu_pub, want.to_vec(), "public handle, set {ps:#x}");
        assert_eq!(mu_prv, want.to_vec(), "private handle, set {ps:#x}");
        assert_eq!(mu_tr, want.to_vec(), "precomputed tr, set {ps:#x}");
        assert_eq!(mu_parts, want.to_vec(), "multi-part, set {ps:#x}");

        let sig = sign_with(hs, CKM_ML_DSA_EXTERNAL_MU, None, &mu_prv).expect("sign µ");
        // CKH_HEDGE_PREFERRED = 0 (pkcs11t.h); not in constants.rs.
        let vparams: [usize; 3] = [0, ctx.as_ptr() as usize, ctx.len()];
        assert_eq!(verify_with(hp, CKM_ML_DSA, Some(&vparams), msg, &sig), CKR_OK, "set {ps:#x}");
        assert_eq!(verify_with(hp, CKM_ML_DSA_EXTERNAL_MU, None, &mu_pub, &sig), CKR_OK);
        // And the message really is bound: another message does not verify.
        assert_eq!(
            verify_with(hp, CKM_ML_DSA, Some(&vparams), b"another message", &sig),
            CKR_SIGNATURE_INVALID
        );
    }
}

/// The key handle is resolved like any other key an operation uses: not a
/// key, not ML-DSA, absent, or a private object the session may not see are
/// all refused before anything is hashed.
#[test]
fn mu_gen_refuses_wrong_or_hidden_keys() {
    let _guard = test_lock::acquire();
    setup();
    let (hp, hs) = ml_dsa_pair(CKP_ML_DSA_44);
    let msg = b"m";

    // A secret key (its CKA_VALUE is secret material) — wrong key type.
    let aes = 0x5633_41A1;
    let data = 0x5633_41A2;
    let slh = 0x5633_41A3;
    OBJECTS.with(|o| {
        let mut o = o.borrow_mut();
        let mut a = Attributes::new();
        store_ulong(&mut a, CKA_CLASS, CKO_SECRET_KEY);
        store_ulong(&mut a, CKA_KEY_TYPE, CKK_AES);
        a.insert(CKA_VALUE, vec![0x42; 32]);
        o.insert(aes, a);
        let mut d = Attributes::new();
        store_ulong(&mut d, CKA_CLASS, CKO_DATA);
        d.insert(CKA_VALUE, b"not a key".to_vec());
        o.insert(data, d);
        let mut s = Attributes::new();
        store_ulong(&mut s, CKA_CLASS, CKO_PUBLIC_KEY);
        store_ulong(&mut s, CKA_KEY_TYPE, CKK_SLH_DSA);
        s.insert(CKA_VALUE, vec![7; 32]);
        o.insert(slh, s);
    });
    assert_eq!(mu_gen(aes, &[], &[], &[msg]), Err(CKR_KEY_TYPE_INCONSISTENT), "secret key");
    assert_eq!(mu_gen(slh, &[], &[], &[msg]), Err(CKR_KEY_TYPE_INCONSISTENT), "SLH-DSA key");
    assert_eq!(mu_gen(data, &[], &[], &[msg]), Err(CKR_KEY_HANDLE_INVALID), "data object");
    assert_eq!(mu_gen(0x5633_41FF, &[], &[], &[msg]), Err(CKR_KEY_HANDLE_INVALID), "no object");

    // A private ML-DSA key is invisible without the user login, so it cannot
    // feed the digest; its public half (not CKA_PRIVATE) still can.
    set_login(crate::state::LoginState::Public);
    assert_eq!(mu_gen(hs, &[], &[], &[msg]), Err(CKR_KEY_HANDLE_INVALID), "private key, logged out");
    assert!(mu_gen(hp, &[], &[], &[msg]).is_ok(), "public key, logged out");
    set_login(crate::state::LoginState::User);
    assert!(mu_gen(hs, &[], &[], &[msg]).is_ok(), "private key, logged in");

    // Exactly one of hKey / pTR, and tr is 64 bytes (unchanged rules).
    assert_eq!(mu_gen(hp, &[1; 64], &[], &[msg]), Err(CKR_ARGUMENTS_BAD));
    assert_eq!(mu_gen(0, &[], &[], &[msg]), Err(CKR_ARGUMENTS_BAD));
    assert_eq!(mu_gen(0, &[1; 63], &[], &[msg]), Err(CKR_ARGUMENTS_BAD));
    OBJECTS.with(|o| {
        let mut o = o.borrow_mut();
        for h in [aes, data, slh, hp, hs] {
            o.remove(&h);
        }
    });
}

/// ml_dsa.md "ExternalMu ML-DSA: Key and Data Length": the input is exactly
/// 64 bytes; anything else is CKR_DATA_LEN_RANGE (in the C_Sign and C_Verify
/// return lists), not CKR_ARGUMENTS_BAD.
#[test]
fn external_mu_wrong_length_is_data_len_range() {
    let _guard = test_lock::acquire();
    setup();
    let (hp, hs) = ml_dsa_pair(CKP_ML_DSA_44);
    let mu = mu_gen(hp, &[], &[], &[b"x"]).unwrap();
    let sig = sign_with(hs, CKM_ML_DSA_EXTERNAL_MU, None, &mu).unwrap();
    for len in [0usize, 63, 65] {
        let bad = vec![0x5a; len];
        assert_eq!(sign_with(hs, CKM_ML_DSA_EXTERNAL_MU, None, &bad), Err(CKR_DATA_LEN_RANGE), "sign, {len} bytes");
        assert_eq!(verify_with(hp, CKM_ML_DSA_EXTERNAL_MU, None, &bad, &sig), CKR_DATA_LEN_RANGE, "verify, {len} bytes");
    }
    OBJECTS.with(|o| {
        o.borrow_mut().remove(&hp);
        o.borrow_mut().remove(&hs);
    });
}
