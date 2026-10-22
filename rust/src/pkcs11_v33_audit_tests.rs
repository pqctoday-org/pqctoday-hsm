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

// ── Template attributes ─────────────────────────────────────────────────────

/// The published v3.2 header's values (pkcs11t-canonical-v3.2.h:658-659).
const V32_ENCAPSULATE_TEMPLATE: u32 = 0x0000_062a;
const V32_DECAPSULATE_TEMPLATE: u32 = 0x0000_062b;

const STRIDE: usize = std::mem::size_of::<usize>() * 3;

fn create(entries: &[(u32, Vec<u8>)]) -> Result<u32, u32> {
    let mut w = words(entries);
    let mut h = 0u32;
    match C_CreateObject(SESSION, w.as_mut_ptr() as *mut u8, entries.len() as u32, &mut h) {
        CKR_OK => Ok(h),
        rv => Err(rv),
    }
}

fn ml_kem_pair(pub_extra: Vec<(u32, Vec<u8>)>, prv_extra: Vec<(u32, Vec<u8>)>) -> (u32, u32) {
    let mut pub_entries = vec![
        (CKA_CLASS, ulong(CKO_PUBLIC_KEY)),
        (CKA_KEY_TYPE, ulong(CKK_ML_KEM)),
        (CKA_TOKEN, vec![0]),
        (CKA_ENCAPSULATE, vec![1]),
        (CKA_PARAMETER_SET, ulong(CKP_ML_KEM_768)),
    ];
    pub_entries.extend(pub_extra);
    let mut prv_entries = vec![
        (CKA_CLASS, ulong(CKO_PRIVATE_KEY)),
        (CKA_KEY_TYPE, ulong(CKK_ML_KEM)),
        (CKA_TOKEN, vec![0]),
        (CKA_DECAPSULATE, vec![1]),
    ];
    prv_entries.extend(prv_extra);
    let (rv, hp, hs) = keypair(CKM_ML_KEM_KEY_PAIR_GEN, &pub_entries, &prv_entries);
    assert_eq!(rv, CKR_OK, "ML-KEM key pair");
    (hp, hs)
}

fn secret_template(extractable: bool) -> Vec<(u32, Vec<u8>)> {
    vec![
        (CKA_CLASS, ulong(CKO_SECRET_KEY)),
        (CKA_KEY_TYPE, ulong(CKK_GENERIC_SECRET)),
        (CKA_TOKEN, vec![0]),
        (CKA_EXTRACTABLE, vec![extractable as u8]),
    ]
}

fn encapsulate(hp: u32, tmpl: &[(u32, Vec<u8>)]) -> (u32, Vec<u8>, u32) {
    let mut m: [usize; 3] = [CKM_ML_KEM as usize, 0, 0];
    let mut w = words(tmpl);
    let mut ct = vec![0u8; 4096];
    let mut ct_len = ct.len() as u32;
    let mut hk = 0u32;
    let rv = C_EncapsulateKey(
        SESSION,
        m.as_mut_ptr() as *mut u8,
        hp,
        w.as_mut_ptr() as *mut u8,
        tmpl.len() as u32,
        ct.as_mut_ptr(),
        &mut ct_len,
        &mut hk,
    );
    ct.truncate(ct_len as usize);
    (rv, ct, hk)
}

fn decapsulate(hs: u32, tmpl: &[(u32, Vec<u8>)], ct: &[u8]) -> (u32, u32) {
    let mut m: [usize; 3] = [CKM_ML_KEM as usize, 0, 0];
    let mut w = words(tmpl);
    let mut c = ct.to_vec();
    let mut hk = 0u32;
    let rv = C_DecapsulateKey(
        SESSION,
        m.as_mut_ptr() as *mut u8,
        hs,
        w.as_mut_ptr() as *mut u8,
        tmpl.len() as u32,
        c.as_mut_ptr(),
        c.len() as u32,
        &mut hk,
    );
    (rv, hk)
}

/// Read one attribute's length (NULL pValue) through C_GetAttributeValue.
fn attr_len(h: u32, t: u32) -> (u32, usize) {
    let mut a: [usize; 3] = [t as usize, 0, 0];
    let rv = C_GetAttributeValue(SESSION, h, a.as_mut_ptr() as *mut u8, 1);
    (rv, a[2])
}

/// The full two-step v3.3 read of a template attribute: discover the types
/// and lengths, then fetch the values. Returns the (type, value) pairs.
fn read_template_attr(h: u32, t: u32) -> Vec<(u32, Vec<u8>)> {
    let (rv, len) = attr_len(h, t);
    assert_eq!(rv, CKR_OK);
    assert_eq!(len % STRIDE, 0, "a CK_ATTRIBUTE[] length");
    let n = len / STRIDE;
    // Discovery: every type CK_UNAVAILABLE_INFORMATION, pValue NULL, len 0.
    let mut inner: Vec<usize> = (0..n).flat_map(|_| [usize::MAX, 0, 0]).collect();
    let mut a: [usize; 3] = [t as usize, inner.as_mut_ptr() as usize, len];
    assert_eq!(C_GetAttributeValue(SESSION, h, a.as_mut_ptr() as *mut u8, 1), CKR_OK);
    assert_eq!(a[2], len);
    let mut bufs: Vec<Vec<u8>> = (0..n).map(|i| vec![0u8; inner[i * 3 + 2]]).collect();
    for (i, b) in bufs.iter_mut().enumerate() {
        inner[i * 3 + 1] = if b.is_empty() { 0 } else { b.as_mut_ptr() as usize };
    }
    assert_eq!(C_GetAttributeValue(SESSION, h, a.as_mut_ptr() as *mut u8, 1), CKR_OK);
    (0..n).map(|i| (inner[i * 3] as u32, bufs[i][..inner[i * 3 + 2]].to_vec())).collect()
}

/// A program built against the published v3.2 header names the KEM template
/// attributes 0x62a / 0x62b. Before the fix the engine stored them under that
/// unknown type and enforced nothing; now they are the same attributes as the
/// v3.3 values, enforced and readable under either value.
#[test]
fn v32_header_kem_template_values_are_enforced() {
    let _guard = test_lock::acquire();
    setup();
    let restrict = vec![(CKA_EXTRACTABLE, vec![0u8])];
    let rw = words(&restrict);
    let as_bytes = |w: &Vec<usize>| unsafe {
        std::slice::from_raw_parts(w.as_ptr() as *const u8, w.len() * std::mem::size_of::<usize>()).to_vec()
    };
    let rbytes = as_bytes(&rw);
    let (hp, hs) = ml_kem_pair(
        vec![(V32_ENCAPSULATE_TEMPLATE, rbytes.clone())],
        vec![(V32_DECAPSULATE_TEMPLATE, rbytes.clone())],
    );
    // Enforced: CKR_KEY_HANDLE_INVALID on encapsulate, CKR_TEMPLATE_INCONSISTENT
    // on decapsulate (key_management_functions.md).
    let (rv, _, _) = encapsulate(hp, &secret_template(true));
    assert_eq!(rv, CKR_KEY_HANDLE_INVALID, "encapsulate template set at 0x62a");
    let (rv, ct, _) = encapsulate(hp, &secret_template(false));
    assert_eq!(rv, CKR_OK);
    assert_eq!(decapsulate(hs, &secret_template(true), &ct).0, CKR_TEMPLATE_INCONSISTENT);
    assert_eq!(decapsulate(hs, &secret_template(false), &ct).0, CKR_OK);
    // One attribute, two names.
    for (h, a, b) in [
        (hp, V32_ENCAPSULATE_TEMPLATE, CKA_ENCAPSULATE_TEMPLATE),
        (hs, V32_DECAPSULATE_TEMPLATE, CKA_DECAPSULATE_TEMPLATE),
    ] {
        assert_eq!(attr_len(h, a), (CKR_OK, STRIDE));
        assert_eq!(read_template_attr(h, a), vec![(CKA_EXTRACTABLE, vec![0u8])]);
        assert_eq!(read_template_attr(h, b), vec![(CKA_EXTRACTABLE, vec![0u8])]);
    }
    // C_SetAttributeValue under the v3.2 value replaces the same attribute.
    let allow = vec![(CKA_EXTRACTABLE, vec![1u8])];
    let aw = words(&allow);
    let abytes = as_bytes(&aw);
    let mut t: [usize; 3] = [V32_ENCAPSULATE_TEMPLATE as usize, abytes.as_ptr() as usize, abytes.len()];
    assert_eq!(C_SetAttributeValue(SESSION, hp, t.as_mut_ptr() as *mut u8, 1), CKR_OK);
    assert_eq!(read_template_attr(hp, CKA_ENCAPSULATE_TEMPLATE), vec![(CKA_EXTRACTABLE, vec![1u8])]);
    assert_eq!(encapsulate(hp, &secret_template(true)).0, CKR_OK);
    assert_eq!(encapsulate(hp, &secret_template(false)).0, CKR_KEY_HANDLE_INVALID);
}

/// v3.3 key_objects.md "Template Attributes": C_GetAttributeValue returns a
/// CK_ATTRIBUTE[] — length query, discovery with CK_UNAVAILABLE_INFORMATION
/// types, value fetch in any order, CKR_TEMPLATE_INCONSISTENT for an array
/// that does not describe the stored template, CKR_BUFFER_TOO_SMALL for a
/// small inner buffer. Before the fix the caller got the engine's internal
/// `u32 type ‖ u32 len ‖ bytes` blob.
#[test]
fn template_attribute_read_back_is_a_ck_attribute_array() {
    let _guard = test_lock::acquire();
    setup();
    let label = b"wrapped-by-kek".to_vec();
    let inner = vec![
        (CKA_CLASS, ulong(CKO_SECRET_KEY)),
        (CKA_EXTRACTABLE, vec![1u8]),
        (CKA_SUBJECT, label.clone()),
    ];
    let iw = words(&inner);
    let ibytes = unsafe {
        std::slice::from_raw_parts(iw.as_ptr() as *const u8, iw.len() * std::mem::size_of::<usize>()).to_vec()
    };
    let kek = create(&[
        (CKA_CLASS, ulong(CKO_SECRET_KEY)),
        (CKA_KEY_TYPE, ulong(CKK_AES)),
        (CKA_TOKEN, vec![0]),
        (CKA_VALUE, vec![0x11; 16]),
        (CKA_WRAP, vec![1]),
        (CKA_WRAP_TEMPLATE, ibytes),
    ])
    .expect("KEK with a wrap template");

    assert_eq!(attr_len(kek, CKA_WRAP_TEMPLATE), (CKR_OK, 3 * STRIDE));
    assert_eq!(read_template_attr(kek, CKA_WRAP_TEMPLATE), inner, "discovery, then values");

    // Known types in another order, values fetched directly.
    let mut cls = vec![0u8; std::mem::size_of::<usize>()];
    let mut lab = vec![0u8; 64];
    let mut ext = vec![0u8; 1];
    let mut arr: Vec<usize> = vec![
        CKA_SUBJECT as usize, lab.as_mut_ptr() as usize, lab.len(),
        CKA_CLASS as usize, cls.as_mut_ptr() as usize, cls.len(),
        CKA_EXTRACTABLE as usize, ext.as_mut_ptr() as usize, ext.len(),
    ];
    let mut a: [usize; 3] = [CKA_WRAP_TEMPLATE as usize, arr.as_mut_ptr() as usize, 3 * STRIDE];
    assert_eq!(C_GetAttributeValue(SESSION, kek, a.as_mut_ptr() as *mut u8, 1), CKR_OK);
    assert_eq!(&lab[..arr[2]], &label[..]);
    assert_eq!(cls, ulong(CKO_SECRET_KEY));
    assert_eq!(ext, vec![1u8]);

    // NULL inner pValue with a known type: the length only.
    let mut arr: Vec<usize> = vec![
        CKA_SUBJECT as usize, 0, 0,
        CKA_CLASS as usize, 0, 0,
        CKA_EXTRACTABLE as usize, 0, 0,
    ];
    let mut a: [usize; 3] = [CKA_WRAP_TEMPLATE as usize, arr.as_mut_ptr() as usize, 3 * STRIDE];
    assert_eq!(C_GetAttributeValue(SESSION, kek, a.as_mut_ptr() as *mut u8, 1), CKR_OK);
    assert_eq!([arr[2], arr[5], arr[8]], [label.len(), std::mem::size_of::<usize>(), 1]);

    // A small inner buffer: CK_UNAVAILABLE_INFORMATION and BUFFER_TOO_SMALL.
    let mut small = vec![0u8; 3];
    let mut arr: Vec<usize> = vec![
        CKA_SUBJECT as usize, small.as_mut_ptr() as usize, small.len(),
        CKA_CLASS as usize, 0, 0,
        CKA_EXTRACTABLE as usize, 0, 0,
    ];
    let mut a: [usize; 3] = [CKA_WRAP_TEMPLATE as usize, arr.as_mut_ptr() as usize, 3 * STRIDE];
    assert_eq!(C_GetAttributeValue(SESSION, kek, a.as_mut_ptr() as *mut u8, 1), CKR_BUFFER_TOO_SMALL);
    assert_eq!(arr[2], usize::MAX);

    // Inconsistent arrays: an unknown type, a duplicate, a mix of known and
    // CK_UNAVAILABLE_INFORMATION types, and a wrong array size.
    for bad in [
        vec![CKA_SUBJECT as usize, 0, 0, CKA_CLASS as usize, 0, 0, CKA_SIGN as usize, 0, 0],
        vec![CKA_SUBJECT as usize, 0, 0, CKA_SUBJECT as usize, 0, 0, CKA_CLASS as usize, 0, 0],
        vec![CKA_SUBJECT as usize, 0, 0, usize::MAX, 0, 0, usize::MAX, 0, 0],
    ] {
        let mut arr = bad.clone();
        let mut a: [usize; 3] = [CKA_WRAP_TEMPLATE as usize, arr.as_mut_ptr() as usize, 3 * STRIDE];
        assert_eq!(
            C_GetAttributeValue(SESSION, kek, a.as_mut_ptr() as *mut u8, 1),
            CKR_TEMPLATE_INCONSISTENT,
            "{bad:x?}"
        );
        assert_eq!(a[2], usize::MAX);
    }
    let mut arr: Vec<usize> = vec![usize::MAX, 0, 0, usize::MAX, 0, 0];
    let mut a: [usize; 3] = [CKA_WRAP_TEMPLATE as usize, arr.as_mut_ptr() as usize, 2 * STRIDE];
    assert_eq!(C_GetAttributeValue(SESSION, kek, a.as_mut_ptr() as *mut u8, 1), CKR_TEMPLATE_INCONSISTENT);
    OBJECTS.with(|o| o.borrow_mut().remove(&kek));
}

/// C_SetAttributeValue deep-copies a template attribute (key_objects.md:
/// tokens "MUST NOT store the template attribute value as received"). It used
/// to store the caller's CK_ATTRIBUTE structs, i.e. pointers into memory the
/// caller frees right after the call.
#[test]
fn set_attribute_value_deep_copies_a_template() {
    let _guard = test_lock::acquire();
    setup();
    let kek = create(&[
        (CKA_CLASS, ulong(CKO_SECRET_KEY)),
        (CKA_KEY_TYPE, ulong(CKK_AES)),
        (CKA_TOKEN, vec![0]),
        (CKA_VALUE, vec![0x22; 16]),
        (CKA_WRAP, vec![1]),
    ])
    .unwrap();
    {
        let label = b"short-lived caller buffer".to_vec();
        let inner = vec![(CKA_SUBJECT, label)];
        let iw = words(&inner);
        let mut t: [usize; 3] = [
            CKA_WRAP_TEMPLATE as usize,
            iw.as_ptr() as usize,
            iw.len() * std::mem::size_of::<usize>(),
        ];
        assert_eq!(C_SetAttributeValue(SESSION, kek, t.as_mut_ptr() as *mut u8, 1), CKR_OK);
        // The stored form holds the label bytes themselves, not a pointer.
        let stored = OBJECTS.with(|o| o.borrow()[&kek][&CKA_WRAP_TEMPLATE].clone());
        assert_eq!(
            crate::crypto::handlers::parse_flat_attr_array(&stored),
            Some(vec![(CKA_SUBJECT, b"short-lived caller buffer".to_vec())])
        );
    } // caller memory released here
    assert_eq!(
        read_template_attr(kek, CKA_WRAP_TEMPLATE),
        vec![(CKA_SUBJECT, b"short-lived caller buffer".to_vec())]
    );
    OBJECTS.with(|o| o.borrow_mut().remove(&kek));
}

/// key_objects.md: an implementation may "deny any recursion, returning
/// CKR_TEMPLATE_INCONSISTENT". A template attribute inside a template
/// attribute is refused on every path that takes one; before the fix its
/// raw pointer bytes were stored.
#[test]
fn nested_template_attributes_are_refused() {
    let _guard = test_lock::acquire();
    setup();
    let deepest = vec![(CKA_EXTRACTABLE, vec![0u8])];
    let dw = words(&deepest);
    let nested = vec![
        (CKA_CLASS, ulong(CKO_SECRET_KEY)),
        (CKA_DERIVE_TEMPLATE, unsafe {
            std::slice::from_raw_parts(dw.as_ptr() as *const u8, dw.len() * std::mem::size_of::<usize>()).to_vec()
        }),
    ];
    let nw = words(&nested);
    let nbytes = unsafe {
        std::slice::from_raw_parts(nw.as_ptr() as *const u8, nw.len() * std::mem::size_of::<usize>()).to_vec()
    };
    let base = vec![
        (CKA_CLASS, ulong(CKO_SECRET_KEY)),
        (CKA_KEY_TYPE, ulong(CKK_AES)),
        (CKA_TOKEN, vec![0]),
        (CKA_VALUE, vec![0x33; 16]),
        (CKA_WRAP, vec![1]),
    ];
    // C_CreateObject.
    let mut with_nested = base.clone();
    with_nested.push((CKA_WRAP_TEMPLATE, nbytes.clone()));
    assert_eq!(create(&with_nested), Err(CKR_TEMPLATE_INCONSISTENT));
    // C_SetAttributeValue.
    let kek = create(&base).unwrap();
    let mut t: [usize; 3] = [CKA_UNWRAP_TEMPLATE as usize, nbytes.as_ptr() as usize, nbytes.len()];
    assert_eq!(C_SetAttributeValue(SESSION, kek, t.as_mut_ptr() as *mut u8, 1), CKR_TEMPLATE_INCONSISTENT);
    assert_eq!(attr_len(kek, CKA_UNWRAP_TEMPLATE).0, CKR_ATTRIBUTE_TYPE_INVALID, "nothing stored");
    // Key pair generation (the template absorbed by absorb_template_attrs).
    let pub_entries = vec![
        (CKA_CLASS, ulong(CKO_PUBLIC_KEY)),
        (CKA_KEY_TYPE, ulong(CKK_ML_KEM)),
        (CKA_TOKEN, vec![0]),
        (CKA_PARAMETER_SET, ulong(CKP_ML_KEM_768)),
        (CKA_ENCAPSULATE_TEMPLATE, nbytes.clone()),
    ];
    let prv_entries = vec![(CKA_CLASS, ulong(CKO_PRIVATE_KEY)), (CKA_TOKEN, vec![0])];
    assert_eq!(keypair(CKM_ML_KEM_KEY_PAIR_GEN, &pub_entries, &prv_entries).0, CKR_TEMPLATE_INCONSISTENT);
    // A ragged array is CKR_ATTRIBUTE_VALUE_INVALID, as on the create path.
    let ragged = vec![0u8; STRIDE + 1];
    let mut t: [usize; 3] = [CKA_WRAP_TEMPLATE as usize, ragged.as_ptr() as usize, ragged.len()];
    assert_eq!(C_SetAttributeValue(SESSION, kek, t.as_mut_ptr() as *mut u8, 1), CKR_ATTRIBUTE_VALUE_INVALID);
    OBJECTS.with(|o| o.borrow_mut().remove(&kek));
}

// ── CKA_DECAPSULATE_TEMPLATE / CKA_UNWRAP_TEMPLATE applied ──────────────────

fn flat(entries: &[(u32, Vec<u8>)]) -> (Vec<usize>, Vec<u8>) {
    let w = words(entries);
    let b = unsafe { std::slice::from_raw_parts(w.as_ptr() as *const u8, w.len() * std::mem::size_of::<usize>()).to_vec() };
    (w, b)
}

fn attr_bytes(h: u32, t: u32) -> Option<Vec<u8>> {
    OBJECTS.with(|o| o.borrow().get(&h).and_then(|a| a.get(&t).cloned()))
}

/// key_management_functions.md (v3.3): CKA_DECAPSULATE_TEMPLATE is "an
/// attribute set that will be added to attributes of the key to be
/// decapsulated"; the user template is applied after it, and a conflict is
/// CKR_TEMPLATE_INCONSISTENT. The engine used to compare only, so a caller
/// who left an attribute out was refused instead of getting it applied.
#[test]
fn decapsulate_template_is_applied_then_checked() {
    let _guard = test_lock::acquire();
    setup();
    let restrict = vec![(CKA_EXTRACTABLE, vec![0u8]), (CKA_SENSITIVE, vec![1u8])];
    let (_w, rbytes) = flat(&restrict);
    let (hp, hs) = ml_kem_pair(vec![], vec![(CKA_DECAPSULATE_TEMPLATE, rbytes)]);
    let (rv, ct, _) = encapsulate(hp, &secret_template(true));
    assert_eq!(rv, CKR_OK);

    // The caller names neither attribute: both are added.
    let bare = vec![
        (CKA_CLASS, ulong(CKO_SECRET_KEY)),
        (CKA_KEY_TYPE, ulong(CKK_GENERIC_SECRET)),
        (CKA_TOKEN, vec![0]),
    ];
    let (rv, hk) = decapsulate(hs, &bare, &ct);
    assert_eq!(rv, CKR_OK, "omitted attributes are applied, not refused");
    assert_eq!(attr_bytes(hk, CKA_EXTRACTABLE), Some(vec![0u8]));
    assert_eq!(attr_bytes(hk, CKA_SENSITIVE), Some(vec![1u8]));

    // Agreeing with the template is fine; contradicting it is refused.
    assert_eq!(decapsulate(hs, &secret_template(false), &ct).0, CKR_OK);
    assert_eq!(decapsulate(hs, &secret_template(true), &ct).0, CKR_TEMPLATE_INCONSISTENT);

    // An entry naming engine truth the template cannot change (the 32-byte
    // ML-KEM secret's CKA_VALUE_LEN) must agree with it.
    let lentries = vec![(CKA_VALUE_LEN, ulong(16))];
    let (_w, lbytes) = flat(&lentries);
    let (_hp2, hs2) = ml_kem_pair(vec![], vec![(CKA_DECAPSULATE_TEMPLATE, lbytes)]);
    let (_, ct2, _) = encapsulate(_hp2, &secret_template(true));
    assert_eq!(decapsulate(hs2, &bare, &ct2).0, CKR_TEMPLATE_INCONSISTENT);
}

/// v3.2 §5.18.4: CKA_UNWRAP_TEMPLATE has the same "added to" rule, on
/// C_UnwrapKey and C_UnwrapKeyAuthenticated (which never consulted it).
#[test]
fn unwrap_template_is_applied_then_checked() {
    let _guard = test_lock::acquire();
    setup();
    let uentries = vec![(CKA_EXTRACTABLE, vec![0u8])];
    let (_w, ubytes) = flat(&uentries);
    let kek = create(&[
        (CKA_CLASS, ulong(CKO_SECRET_KEY)),
        (CKA_KEY_TYPE, ulong(CKK_AES)),
        (CKA_TOKEN, vec![0]),
        (CKA_VALUE, vec![0x44; 16]),
        (CKA_WRAP, vec![1]),
        (CKA_UNWRAP, vec![1]),
        (CKA_UNWRAP_TEMPLATE, ubytes),
    ])
    .unwrap();
    let target = create(&[
        (CKA_CLASS, ulong(CKO_SECRET_KEY)),
        (CKA_KEY_TYPE, ulong(CKK_AES)),
        (CKA_TOKEN, vec![0]),
        (CKA_VALUE, vec![0x55; 16]),
        (CKA_EXTRACTABLE, vec![1]),
        (CKA_SENSITIVE, vec![0]),
    ])
    .unwrap();
    let mut m: [usize; 3] = [CKM_AES_KEY_WRAP as usize, 0, 0];
    let mut wrapped = vec![0u8; 64];
    let mut wlen = wrapped.len() as u32;
    assert_eq!(
        C_WrapKey(SESSION, m.as_mut_ptr() as *mut u8, kek, target, wrapped.as_mut_ptr(), &mut wlen),
        CKR_OK
    );
    wrapped.truncate(wlen as usize);
    let unwrap = |tmpl: &[(u32, Vec<u8>)]| -> (u32, u32) {
        let mut m: [usize; 3] = [CKM_AES_KEY_WRAP as usize, 0, 0];
        let mut w = words(tmpl);
        let mut wr = wrapped.clone();
        let mut h = 0u32;
        let rv = C_UnwrapKey(
            SESSION,
            m.as_mut_ptr() as *mut u8,
            kek,
            wr.as_mut_ptr(),
            wr.len() as u32,
            w.as_mut_ptr() as *mut u8,
            tmpl.len() as u32,
            &mut h,
        );
        (rv, h)
    };
    let base = vec![
        (CKA_CLASS, ulong(CKO_SECRET_KEY)),
        (CKA_KEY_TYPE, ulong(CKK_AES)),
        (CKA_TOKEN, vec![0]),
    ];
    let (rv, h) = unwrap(&base);
    assert_eq!(rv, CKR_OK, "an omitted attribute is applied");
    assert_eq!(attr_bytes(h, CKA_EXTRACTABLE), Some(vec![0u8]));
    let mut contra = base.clone();
    contra.push((CKA_EXTRACTABLE, vec![1]));
    assert_eq!(unwrap(&contra).0, CKR_TEMPLATE_INCONSISTENT);
    let mut agree = base.clone();
    agree.push((CKA_EXTRACTABLE, vec![0]));
    assert_eq!(unwrap(&agree).0, CKR_OK);
}

// ── HSS key generation and CKA_KEYS_REMAINING ───────────────────────────────

fn ulongs(vals: &[u32]) -> Vec<u8> {
    vals.iter().flat_map(|v| ulong(*v)).collect()
}

fn hss_keypair(param: Option<&[usize; 17]>, prv_extra: Vec<(u32, Vec<u8>)>, pub_extra: Vec<(u32, Vec<u8>)>) -> (u32, u32, u32) {
    let mut pub_entries = vec![
        (CKA_CLASS, ulong(CKO_PUBLIC_KEY)),
        (CKA_KEY_TYPE, ulong(CKK_HSS)),
        (CKA_TOKEN, vec![0]),
    ];
    pub_entries.extend(pub_extra);
    let mut prv_entries = vec![
        (CKA_CLASS, ulong(CKO_PRIVATE_KEY)),
        (CKA_KEY_TYPE, ulong(CKK_HSS)),
        (CKA_TOKEN, vec![0]),
    ];
    prv_entries.extend(prv_extra);
    let mut m: [usize; 3] = match param {
        Some(p) => [CKM_HSS_KEY_PAIR_GEN as usize, p.as_ptr() as usize, std::mem::size_of_val(p)],
        None => [CKM_HSS_KEY_PAIR_GEN as usize, 0, 0],
    };
    let mut pw = words(&pub_entries);
    let mut sw = words(&prv_entries);
    let (mut hp, mut hs) = (0u32, 0u32);
    let rv = C_GenerateKeyPair(
        SESSION,
        m.as_mut_ptr() as *mut u8,
        pw.as_mut_ptr() as *mut u8,
        pub_entries.len() as u32,
        sw.as_mut_ptr() as *mut u8,
        prv_entries.len() as u32,
        &mut hp,
        &mut hs,
    );
    (rv, hp, hs)
}

fn legacy_hss_param(lms: &[u32], lmots: &[u32]) -> [usize; 17] {
    let mut p = [0usize; 17];
    p[0] = lms.len();
    for (i, v) in lms.iter().enumerate() {
        p[1 + i] = *v as usize;
    }
    for (i, v) in lmots.iter().enumerate() {
        p[9 + i] = *v as usize;
    }
    p
}

fn hss_template(levels: u32, lms: &[u32], lmots: &[u32]) -> Vec<(u32, Vec<u8>)> {
    vec![
        (CKA_HSS_LEVELS, ulong(levels)),
        (CKA_HSS_LMS_TYPES, ulongs(lms)),
        (CKA_HSS_LMOTS_TYPES, ulongs(lmots)),
    ]
}

/// The attribute as a caller reads it: (rv, ulValueLen, value).
fn read_ulong_attr(h: u32, t: u32) -> (u32, usize, u64) {
    let mut buf = vec![0u8; 8];
    let mut a: [usize; 3] = [t as usize, buf.as_mut_ptr() as usize, buf.len()];
    let rv = C_GetAttributeValue(SESSION, h, a.as_mut_ptr() as *mut u8, 1);
    let mut w = [0u8; 8];
    if rv == CKR_OK {
        w[..a[2]].copy_from_slice(&buf[..a[2]]);
    }
    (rv, a[2], u64::from_le_bytes(w))
}

/// v3.2 §6.14 / v3.3 hss.md: "The mechanism generates HSS public/private key
/// pairs for the scheme specified by the CKA_HSS_LEVELS, CKA_HSS_LMS_TYPES,
/// and CKA_HSS_LMOTS_TYPES attributes of the template for the private key."
/// Before the fix those attributes were ignored and a spec-following caller
/// silently got the single-level default.
#[test]
fn hss_keygen_takes_the_scheme_from_the_private_template() {
    let _guard = test_lock::acquire();
    setup();
    let lms = [CKP_LMS_SHA256_M32_H5, CKP_LMS_SHA256_M32_H5];
    let lmots = [CKP_LMOTS_SHA256_N32_W8, CKP_LMOTS_SHA256_N32_W4];
    let (rv, hp, hs) = hss_keypair(None, hss_template(2, &lms, &lmots), vec![]);
    assert_eq!(rv, CKR_OK);
    // Contributed to the public key: the level count and the top level's types.
    assert_eq!(read_ulong_attr(hp, CKA_HSS_LEVELS).2, 2);
    assert_eq!(read_ulong_attr(hp, CKA_HSS_LMS_TYPE).2, CKP_LMS_SHA256_M32_H5 as u64);
    assert_eq!(read_ulong_attr(hp, CKA_HSS_LMOTS_TYPE).2, CKP_LMOTS_SHA256_N32_W8 as u64);
    // The private key keeps the full lists.
    assert_eq!(attr_bytes(hs, CKA_HSS_LMS_TYPES), Some(ulongs(&lms)));
    assert_eq!(attr_bytes(hs, CKA_HSS_LMOTS_TYPES), Some(ulongs(&lmots)));
    // The key really is two levels: 2^5 * 2^5 signatures, and an HSS
    // signature with one signed public key (RFC 8554 §6.2: 4 + (L-1)*... ),
    // longer than a single-level one.
    assert_eq!(read_ulong_attr(hs, CKA_KEYS_REMAINING), (CKR_OK, std::mem::size_of::<usize>(), 1024));
    let msg = b"two-level HSS";
    let sig = sign_with(hs, CKM_HSS, None, msg).expect("sign");
    assert_eq!(verify_with(hp, CKM_HSS, None, msg, &sig), CKR_OK);
    let (_, hp1, hs1) = hss_keypair(None, vec![], vec![]);
    let sig1 = sign_with(hs1, CKM_HSS, None, msg).unwrap();
    assert_eq!(u32::from_be_bytes(sig[..4].try_into().unwrap()), 1, "Nspk = L-1 = 1");
    assert_eq!(u32::from_be_bytes(sig1[..4].try_into().unwrap()), 0, "default stays single-level");
    assert_eq!(verify_with(hp1, CKM_HSS, None, msg, &sig1), CKR_OK);
    // The scheme is fixed once the key exists.
    let v = ulong(1);
    let mut t: [usize; 3] = [CKA_HSS_LEVELS as usize, v.as_ptr() as usize, v.len()];
    assert_eq!(C_SetAttributeValue(SESSION, hs, t.as_mut_ptr() as *mut u8, 1), CKR_ATTRIBUTE_READ_ONLY);
}

/// The legacy vendor mechanism parameter keeps working; with the template it
/// must describe the same scheme. Incomplete, inconsistent and invalid
/// template schemes are refused.
#[test]
fn hss_keygen_parameter_precedence_and_template_checks() {
    let _guard = test_lock::acquire();
    setup();
    let lms = [CKP_LMS_SHA256_M32_H5, CKP_LMS_SHA256_M32_H5];
    let lmots = [CKP_LMOTS_SHA256_N32_W4, CKP_LMOTS_SHA256_N32_W4];
    let param = legacy_hss_param(&lms, &lmots);
    let (rv, hp, _) = hss_keypair(Some(&param), vec![], vec![]);
    assert_eq!(rv, CKR_OK, "legacy parameter alone");
    assert_eq!(read_ulong_attr(hp, CKA_HSS_LEVELS).2, 2);
    assert_eq!(hss_keypair(Some(&param), hss_template(2, &lms, &lmots), vec![]).0, CKR_OK, "agreeing");
    assert_eq!(
        hss_keypair(Some(&param), hss_template(1, &lms[..1], &lmots[..1]), vec![]).0,
        CKR_TEMPLATE_INCONSISTENT,
        "template and parameter disagree"
    );
    // One or two of the three attributes.
    assert_eq!(
        hss_keypair(None, vec![(CKA_HSS_LEVELS, ulong(1))], vec![]).0,
        CKR_TEMPLATE_INCOMPLETE
    );
    // List lengths must equal CKA_HSS_LEVELS.
    assert_eq!(
        hss_keypair(None, hss_template(2, &lms[..1], &lmots), vec![]).0,
        CKR_TEMPLATE_INCONSISTENT
    );
    // Levels out of range, unknown or mixed-family types.
    assert_eq!(hss_keypair(None, hss_template(0, &[], &[]), vec![]).0, CKR_ATTRIBUTE_VALUE_INVALID);
    assert_eq!(
        hss_keypair(None, hss_template(1, &[0x77], &[CKP_LMOTS_SHA256_N32_W4]), vec![]).0,
        CKR_ATTRIBUTE_VALUE_INVALID
    );
    assert_eq!(
        hss_keypair(None, hss_template(1, &[CKP_LMS_SHA256_M32_H5], &[CKP_LMOTS_SHAKE_N32_W4]), vec![]).0,
        CKR_ATTRIBUTE_VALUE_INVALID
    );
    // A public template naming a contributed attribute with another value.
    assert_eq!(
        hss_keypair(None, hss_template(2, &lms, &lmots), vec![(CKA_HSS_LEVELS, ulong(1))]).0,
        CKR_TEMPLATE_INCONSISTENT
    );
}

/// hss.md: CKA_KEYS_REMAINING is on the private key only, is a CK_ULONG, and
/// is capped at 2^32-1 — a real count, not CK_UNAVAILABLE_INFORMATION. It
/// used to be on the public key too, read "unavailable" at the cap, and was
/// rewritten as 4 bytes after the first signature.
#[test]
fn hss_keys_remaining_width_cap_and_placement() {
    let _guard = test_lock::acquire();
    setup();
    let word = std::mem::size_of::<usize>();
    let (rv, hp, hs) = hss_keypair(None, vec![], vec![]);
    assert_eq!(rv, CKR_OK);
    assert_eq!(read_ulong_attr(hp, CKA_KEYS_REMAINING).0, CKR_ATTRIBUTE_TYPE_INVALID, "not on the public key");
    assert_eq!(read_ulong_attr(hs, CKA_KEYS_REMAINING), (CKR_OK, word, 32));
    sign_with(hs, CKM_HSS, None, b"one").unwrap();
    assert_eq!(read_ulong_attr(hs, CKA_KEYS_REMAINING), (CKR_OK, word, 31), "still a CK_ULONG");

    // A scheme above 2^32 signatures (H25 over H10 = 2^35): the count stays
    // at the cap after a signature. The levels are restated on the object
    // directly — generating an H25 tree in a unit test is not practical.
    assert_eq!(crate::native::hbs::hss_capacity(&[CKP_LMS_SHA256_M32_H25, CKP_LMS_SHA256_M32_H10]), 1u64 << 35);
    crate::state::set_object_attrs_bytes_batch(
        hs,
        &[(CKA_HSS_LMS_TYPES, ulongs(&[CKP_LMS_SHA256_M32_H25, CKP_LMS_SHA256_M32_H10]))],
    );
    sign_with(hs, CKM_HSS, None, b"two").unwrap();
    assert_eq!(read_ulong_attr(hs, CKA_KEYS_REMAINING), (CKR_OK, word, 0xFFFF_FFFF));
}

// ── XMSS / XMSS^MT exhaustion ───────────────────────────────────────────────

fn stateful_pair(mech: u32, param_set: u32) -> (u32, u32) {
    let pub_entries = vec![(CKA_TOKEN, vec![0]), (CKA_PARAMETER_SET, ulong(param_set))];
    let prv_entries = vec![(CKA_TOKEN, vec![0])];
    let (rv, hp, hs) = keypair(mech, &pub_entries, &prv_entries);
    assert_eq!(rv, CKR_OK, "key pair {mech:#x}/{param_set:#x}");
    (hp, hs)
}

/// CKR_KEY_EXHAUSTED (v3.3 function_return_values.md, listed for C_Sign) for
/// an XMSS or XMSS^MT key with no one-time key left. It was
/// CKR_FUNCTION_FAILED. The state is unchanged and a retry gives the same code.
#[test]
fn exhausted_xmss_keys_report_key_exhausted() {
    let _guard = test_lock::acquire();
    setup();
    let msg = b"exhausted";
    // XMSS-SHA2_10_256: the index is the big-endian u32 after the 4-byte OID.
    let (hp, hs) = stateful_pair(CKM_XMSS_KEY_PAIR_GEN, CKP_XMSS_SHA2_10_256);
    let mut st = crate::state::get_object_attr_bytes(hs, CKA_PRIV_STATEFUL_KEY_STATE).unwrap();
    st[4..8].copy_from_slice(&1023u32.to_be_bytes());
    crate::state::set_object_attrs_bytes_batch(hs, &[(CKA_PRIV_STATEFUL_KEY_STATE, st)]);
    let sig = sign_with(hs, CKM_XMSS, None, msg).expect("the last one-time key signs");
    assert_eq!(verify_with(hp, CKM_XMSS, None, msg, &sig), CKR_OK);
    let before = crate::state::get_object_attr_bytes(hs, CKA_PRIV_STATEFUL_KEY_STATE);
    assert_eq!(sign_with(hs, CKM_XMSS, None, msg), Err(CKR_KEY_EXHAUSTED));
    assert_eq!(sign_with(hs, CKM_XMSS, None, msg), Err(CKR_KEY_EXHAUSTED));
    assert_eq!(crate::state::get_object_attr_bytes(hs, CKA_PRIV_STATEFUL_KEY_STATE), before);

    // XMSS^MT-SHA2_20/2_256: a 3-byte index (ceil(20/8)) after the OID.
    let (_hp, hs) = stateful_pair(CKM_XMSSMT_KEY_PAIR_GEN, CKP_XMSSMT_SHA2_20_2_256);
    let mut st = crate::state::get_object_attr_bytes(hs, CKA_PRIV_STATEFUL_KEY_STATE).unwrap();
    st[4..7].copy_from_slice(&(1u32 << 20).to_be_bytes()[1..]);
    crate::state::set_object_attrs_bytes_batch(hs, &[(CKA_PRIV_STATEFUL_KEY_STATE, st)]);
    assert_eq!(sign_with(hs, CKM_XMSSMT, None, msg), Err(CKR_KEY_EXHAUSTED));
}

// ── Multi-part signing for HSS / XMSS; C_VerifySignatureUpdate single-part ──

fn sign_update(parts: &[&[u8]]) -> u32 {
    for p in parts {
        let mut d = p.to_vec();
        let rv = C_SignUpdate(SESSION, d.as_mut_ptr(), d.len() as u32);
        if rv != CKR_OK {
            return rv;
        }
    }
    CKR_OK
}

fn verify_signature(h_key: u32, mech: u32, params: Option<&[usize]>, parts: &[&[u8]], sig: &[u8]) -> u32 {
    let mut m: [usize; 3] = match params {
        Some(p) => [mech as usize, p.as_ptr() as usize, std::mem::size_of_val(p)],
        None => [mech as usize, 0, 0],
    };
    let mut s = sig.to_vec();
    let rv = C_VerifySignatureInit(SESSION, m.as_mut_ptr() as *mut u8, h_key, s.as_mut_ptr(), s.len() as u32);
    if rv != CKR_OK {
        return rv;
    }
    for p in parts {
        let mut d = p.to_vec();
        let rv = C_VerifySignatureUpdate(SESSION, d.as_mut_ptr(), d.len() as u32);
        if rv != CKR_OK {
            return rv;
        }
    }
    C_VerifySignatureFinal(SESSION)
}

/// v3.3 working draft (TC commit 3f7d0dd, #69): HSS, XMSS and XMSS^MT signing
/// may be multi-part. The parts are buffered and the leaf is consumed once,
/// at C_SignFinal, and only when the output buffer is adequate — a size query
/// or a too-small buffer spends nothing. Verification stays single-part on
/// C_Verify / C_VerifyUpdate and multi-part through C_VerifySignature*.
/// The engine refused C_SignUpdate for these mechanisms (the v3.2 rule).
#[test]
fn stateful_signing_is_multi_part_and_consumes_one_leaf() {
    let _guard = test_lock::acquire();
    setup();
    let parts: [&[u8]; 3] = [b"multi-", b"part ", b"stateful signing"];
    let whole: Vec<u8> = parts.concat();
    let (rv, hp_hss, hs_hss) = hss_keypair(None, vec![], vec![]);
    assert_eq!(rv, CKR_OK);
    let (hp_x, hs_x) = stateful_pair(CKM_XMSS_KEY_PAIR_GEN, CKP_XMSS_SHA2_10_256);
    for (mech, hp, hs, start) in [(CKM_HSS, hp_hss, hs_hss, 32u64), (CKM_XMSS, hp_x, hs_x, 1024)] {
        let remaining = || read_ulong_attr(hs, CKA_KEYS_REMAINING).2;
        assert_eq!(remaining(), start);
        let mut m: [usize; 3] = [mech as usize, 0, 0];
        assert_eq!(C_SignInit(SESSION, m.as_mut_ptr() as *mut u8, hs), CKR_OK);
        assert_eq!(sign_update(&parts), CKR_OK, "C_SignUpdate, mech {mech:#x}");
        // One-shot C_Sign during the multi-part phase stays a sequencing error.
        let mut d = whole.clone();
        let mut tmp = vec![0u8; 8];
        let mut tl = tmp.len() as u32;
        assert_eq!(C_Sign(SESSION, d.as_mut_ptr(), d.len() as u32, tmp.as_mut_ptr(), &mut tl), CKR_OPERATION_ACTIVE);
        // Size query and a too-small buffer: no leaf consumed, op still active.
        let mut len = 0u32;
        assert_eq!(C_SignFinal(SESSION, std::ptr::null_mut(), &mut len), CKR_OK);
        assert!(len > 0);
        let mut small = vec![0u8; 16];
        let mut sl = small.len() as u32;
        assert_eq!(C_SignFinal(SESSION, small.as_mut_ptr(), &mut sl), CKR_BUFFER_TOO_SMALL);
        assert_eq!(remaining(), start, "no leaf spent before the signature is delivered");
        let mut sig = vec![0u8; len.max(sl) as usize];
        let mut l = sig.len() as u32;
        assert_eq!(C_SignFinal(SESSION, sig.as_mut_ptr(), &mut l), CKR_OK);
        sig.truncate(l as usize);
        assert_eq!(remaining(), start - 1, "exactly one leaf");
        // The signature is over the concatenated parts.
        assert_eq!(verify_with(hp, mech, None, &whole, &sig), CKR_OK);
        assert_eq!(verify_signature(hp, mech, None, &parts, &sig), CKR_OK, "C_VerifySignatureUpdate");
        // C_VerifyUpdate stays refused for these mechanisms.
        let mut m: [usize; 3] = [mech as usize, 0, 0];
        assert_eq!(C_VerifyInit(SESSION, m.as_mut_ptr() as *mut u8, hp), CKR_OK);
        let mut d = whole.clone();
        assert_eq!(C_VerifyUpdate(SESSION, d.as_mut_ptr(), d.len() as u32), CKR_OPERATION_NOT_INITIALIZED);
        // The next multi-part signature uses the next leaf.
        assert_eq!(C_SignInit(SESSION, m.as_mut_ptr() as *mut u8, hs), CKR_OK);
        assert_eq!(sign_update(&parts), CKR_OK);
        let mut sig2 = vec![0u8; sig.len() + 64];
        let mut l2 = sig2.len() as u32;
        assert_eq!(C_SignFinal(SESSION, sig2.as_mut_ptr(), &mut l2), CKR_OK);
        sig2.truncate(l2 as usize);
        assert_ne!(sig2, sig, "a different one-time key");
        assert_eq!(remaining(), start - 2);
    }
}

/// v3.3 ml_dsa.md: the generic CKM_HASH_ML_DSA's C_VerifySignature is
/// single-part only. C_VerifySignatureUpdate (and Final) now refuse every
/// mechanism C_VerifyUpdate refuses — ending the operation with
/// CKR_OPERATION_NOT_INITIALIZED — instead of buffering all but one.
#[test]
fn verify_signature_update_enforces_single_part_mechanisms() {
    let _guard = test_lock::acquire();
    setup();
    let (hp, hs) = ml_dsa_pair(CKP_ML_DSA_44);
    // The generic mechanism signs a caller-computed digest (here a SHA-256-sized one).
    let msg = &[0x6d_u8; 32];
    // CK_HASH_SIGN_ADDITIONAL_CONTEXT {hedgeVariant, pContext, ulContextLen, hash}.
    let params: [usize; 4] = [0, 0, 0, CKM_SHA256 as usize];
    let sig = sign_with(hs, CKM_HASH_ML_DSA, Some(&params), msg).expect("generic HashML-DSA sign");
    // Single-part through C_VerifySignature is fine.
    assert_eq!(verify_signature_one(hp, &params, msg, &sig), CKR_OK);
    // Multi-part is refused and the operation is gone.
    assert_eq!(verify_signature(hp, CKM_HASH_ML_DSA, Some(&params), &[msg], &sig), CKR_OPERATION_NOT_INITIALIZED);
    assert_eq!(C_VerifySignatureFinal(SESSION), CKR_OPERATION_NOT_INITIALIZED);
    // Pure ML-DSA stays multi-part.
    let sig = sign_with(hs, CKM_ML_DSA, None, msg).unwrap();
    assert_eq!(verify_signature(hp, CKM_ML_DSA, None, &[&msg[..5], &msg[5..]], &sig), CKR_OK);
}

/// One-shot C_VerifySignatureInit + C_VerifySignature.
fn verify_signature_one(hp: u32, params: &[usize], msg: &[u8], sig: &[u8]) -> u32 {
    let mut m: [usize; 3] = [CKM_HASH_ML_DSA as usize, params.as_ptr() as usize, std::mem::size_of_val(params)];
    let mut s = sig.to_vec();
    assert_eq!(C_VerifySignatureInit(SESSION, m.as_mut_ptr() as *mut u8, hp, s.as_mut_ptr(), s.len() as u32), CKR_OK);
    let mut d = msg.to_vec();
    C_VerifySignature(SESSION, d.as_mut_ptr(), d.len() as u32)
}
