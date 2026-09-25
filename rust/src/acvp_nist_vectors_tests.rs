//! NIST ACVP-Server vectors and advertised-cell probes driven through the
//! real `C_*` entry points (gap-closure plan 2026-09-25, findings E11–E17).
//!
//! Every NIST case here is byte-copied, unmodified, from the pqctoday-hub
//! WS-E subsets (branch `feat/acvp-ws-e-breadth` @ c9c75a6240c1), which are
//! themselves subsets of the pinned upstream files. Each fixture carries its
//! own `_provenance` block; the upstream identity is repeated here so the
//! pin is visible where the assertions are:
//!
//! | fixture (`rust/kat/acvp-ws-e/`) | upstream path in usnistgov/ACVP-Server@975de31e | upstream sha256 | fixture sha256 |
//! |---|---|---|---|
//! | `aesgcm_acvp_test.json` | `gen-val/json-files/ACVP-AES-GCM-1.0/internalProjection.json` | `0703118c1f751f32cdb8d32b8e54d5f80eb9bbe7bb99b83a6b0221cb40b34f0e` | `20c469db21b8961c883fc69151735d8b235b459c3a43cc2d8530668b7b3a9467` |
//! | `ecdsa_sigver_acvp_test.json` | `gen-val/json-files/ECDSA-SigVer-FIPS186-5/internalProjection.json` | `45f9e9425e68b099d9c029e0e75ec04e9cc5943b60fa24cdb4d5af778f350b63` | `3c2df55c23270ca28dd9748770ba8c8952c0f44afd40e5537824382b3b112ac3` |
//! | `rsa_sigver_acvp_test.json` | `gen-val/json-files/RSA-SigVer-FIPS186-5/internalProjection.json` | `86088be5f46b3b10794357495c6d914af4a4c03b97bd3d185482f2d47d338578` | `7b2c745820a1523bba6b4d9688edb11b40fac86e06acb320443a2e21f95756ec` |
//! | `pbkdf2_acvp_test.json` | `gen-val/json-files/PBKDF-1.0/internalProjection.json` | `09d0742e01e1ddfa484eeb1cbae3d2061620ebd6dc85fdabdbb2679713a6269f` | `b3ace24d957a4fd4b6e1cecb4ca437d3e413f0d5bfe66ec7de696a3d0b2d5715` |
//! | `kmac_acvp_test.json` | `gen-val/json-files/KMAC-128-1.0/internalProjection.json` | `43ee39f587abbf5c4ada9236ba0d55fd9f6ea4f03b6e73598846c5920515f476` | `fb60c4c592c2a2e148eedc523a1aab6d44d5b8c018ce0184b815730e77cb7f98` |
//! | `hmac_acvp_matrix_test.json` | `gen-val/json-files/HMAC-SHA2-256-2.0/internalProjection.json` (+10 sibling HMAC-* files, one per group; each group names its own path + sha256) | `a9d0734b93aee71bc6f30b47daab782fd96b39688afe4fbddb009e99402ec989` (SHA2-256 file) | `ab2306a2a1ce446b4d939a67eda54c490812a2a0447652d929682c5a47a427b4` |
//!
//! The non-NIST probes (E11) are labelled where they appear, with the
//! published source of every expected value.
use crate::ck_param;
use crate::constants::*;
use crate::ffi::*;
use crate::native::test_lock;

const CKF_SIGN: u32 = 0x0000_0800;

fn fixture(name: &str) -> serde_json::Value {
    let path = format!("{}/kat/acvp-ws-e/{name}", env!("CARGO_MANIFEST_DIR"));
    let s = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    serde_json::from_str(&s).unwrap_or_else(|e| panic!("parse {path}: {e}"))
}

fn hx(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd-length hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn s<'a>(v: &'a serde_json::Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or_else(|| panic!("field {k} missing: {v}"))
}

fn setup_session() -> u32 {
    assert_eq!(C_Initialize(std::ptr::null_mut()), CKR_OK);
    crate::state::ensure_slot(0);
    let so_pin = b"12345678";
    assert_eq!(
        C_InitToken(0, so_pin.as_ptr() as *mut u8, so_pin.len() as u32, [0u8; 32].as_mut_ptr()),
        CKR_OK
    );
    let mut session = 0u32;
    assert_eq!(
        C_OpenSession(0, 0x0000_0004 | 0x0000_0002, std::ptr::null_mut(), std::ptr::null_mut(), &mut session),
        CKR_OK
    );
    assert_eq!(C_Login(session, 0, so_pin.as_ptr() as *mut u8, so_pin.len() as u32), CKR_OK);
    let user_pin = b"user1234";
    assert_eq!(C_InitPIN(session, user_pin.as_ptr() as *mut u8, user_pin.len() as u32), CKR_OK);
    assert_eq!(C_Logout(session), CKR_OK);
    assert_eq!(C_Login(session, 1, user_pin.as_ptr() as *mut u8, user_pin.len() as u32), CKR_OK);
    session
}

/// A `CK_MECHANISM` at this target's native layout pointing at `param`.
fn mechanism(mech: u32, param: &[u8]) -> Vec<u8> {
    let l = &ck_param::mechanism::LAYOUT;
    let mut b = vec![0u8; l.size()];
    let w = ck_param::WORD;
    let o = l.offset(ck_param::mechanism::MECHANISM);
    b[o..o + w].copy_from_slice(&(mech as usize).to_ne_bytes());
    let o = l.offset(ck_param::mechanism::P_PARAMETER);
    let p = if param.is_empty() { std::ptr::null() } else { param.as_ptr() };
    b[o..o + w].copy_from_slice(&(p as usize).to_ne_bytes());
    let o = l.offset(ck_param::mechanism::UL_PARAMETER_LEN);
    b[o..o + w].copy_from_slice(&param.len().to_ne_bytes());
    b
}

/// A parameter struct at this target's native layout: every listed field
/// is a CK_ULONG or pointer written at native word width.
fn pack(l: &ck_param::Struct, vals: &[(usize, usize)]) -> Vec<u8> {
    let mut b = vec![0u8; l.size()];
    let w = ck_param::WORD;
    for &(field, v) in vals {
        let o = l.offset(field);
        b[o..o + w].copy_from_slice(&v.to_ne_bytes());
    }
    b
}

fn ptr(v: &[u8]) -> usize {
    if v.is_empty() { 0 } else { v.as_ptr() as usize }
}

fn ul(v: u32) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

fn create(session: u32, attrs: &[(u32, Vec<u8>)]) -> Result<u32, u32> {
    let tmpl: Vec<usize> = attrs
        .iter()
        .flat_map(|(t, v)| [*t as usize, v.as_ptr() as usize, v.len()])
        .collect();
    let mut h = 0u32;
    match C_CreateObject(session, tmpl.as_ptr() as *mut u8, attrs.len() as u32, &mut h) {
        CKR_OK => Ok(h),
        rv => Err(rv),
    }
}

fn template(attrs: &[(u32, Vec<u8>)]) -> Vec<usize> {
    attrs
        .iter()
        .flat_map(|(t, v)| [*t as usize, v.as_ptr() as usize, v.len()])
        .collect()
}

fn secret_key(session: u32, key_type: u32, value: &[u8]) -> u32 {
    create(
        session,
        &[
            (CKA_CLASS, ul(CKO_SECRET_KEY)),
            (CKA_KEY_TYPE, ul(key_type)),
            (CKA_VALUE, value.to_vec()),
            (CKA_ENCRYPT, vec![1]),
            (CKA_DECRYPT, vec![1]),
            (CKA_SIGN, vec![1]),
            (CKA_VERIFY, vec![1]),
        ],
    )
    .expect("create secret key")
}

fn obj_value(h: u32) -> Vec<u8> {
    crate::state::OBJECTS
        .with(|o| o.borrow().get(&h).and_then(|a| a.get(&CKA_VALUE).cloned()))
        .expect("CKA_VALUE")
}

fn verify(session: u32, mech: &[u8], h_key: u32, msg: &[u8], sig: &[u8]) -> u32 {
    let rv = C_VerifyInit(session, mech.as_ptr() as *mut u8, h_key);
    if rv != CKR_OK {
        return rv;
    }
    C_Verify(session, msg.as_ptr() as *mut u8, msg.len() as u32, sig.as_ptr() as *mut u8, sig.len() as u32)
}

fn sign(session: u32, mech: &[u8], h_key: u32, msg: &[u8]) -> Result<Vec<u8>, u32> {
    let rv = C_SignInit(session, mech.as_ptr() as *mut u8, h_key);
    if rv != CKR_OK {
        return Err(rv);
    }
    let mut len = 0u32;
    let rv = C_Sign(session, msg.as_ptr() as *mut u8, msg.len() as u32, std::ptr::null_mut(), &mut len);
    if rv != CKR_OK {
        return Err(rv);
    }
    let mut out = vec![0u8; len as usize];
    let rv = C_Sign(session, msg.as_ptr() as *mut u8, msg.len() as u32, out.as_mut_ptr(), &mut len);
    if rv != CKR_OK {
        return Err(rv);
    }
    out.truncate(len as usize);
    Ok(out)
}

fn mech_info(mech: u32) -> (u32, u32, u32) {
    let mut info = [0u32; 3];
    assert_eq!(C_GetMechanismInfo(0, mech, info.as_mut_ptr() as *mut u8), CKR_OK, "mech {mech:#x}");
    (info[0], info[1], info[2])
}

// ── EC helpers ──────────────────────────────────────────────────────────────

fn curve_oid(curve: &str) -> Vec<u8> {
    match curve {
        "P-224" => vec![0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x21],
        "P-256" => vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
        "P-384" => vec![0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22],
        "P-521" => vec![0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23],
        "secp256k1" => vec![0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a],
        other => panic!("curve {other}"),
    }
}

fn field_bytes(curve: &str) -> usize {
    match curve {
        "P-224" => 28,
        "P-256" | "secp256k1" => 32,
        "P-384" => 48,
        "P-521" => 66,
        other => panic!("curve {other}"),
    }
}

fn left_pad(v: &[u8], n: usize) -> Vec<u8> {
    let v = &v[v.len().saturating_sub(n)..];
    let mut out = vec![0u8; n - v.len()];
    out.extend_from_slice(v);
    out
}

/// DER OCTET STRING around an uncompressed SEC1 point (X.690 short or
/// long-form length).
fn der_point(point: &[u8]) -> Vec<u8> {
    let mut out = vec![0x04];
    if point.len() < 0x80 {
        out.push(point.len() as u8);
    } else {
        out.extend_from_slice(&[0x81, point.len() as u8]);
    }
    out.extend_from_slice(point);
    out
}

fn ec_keypair(session: u32, mech: u32, curve: &str) -> Result<(u32, u32), u32> {
    let params = curve_oid(curve);
    let pubt = [(CKA_EC_PARAMS, params.clone()), (CKA_VERIFY, vec![1])];
    let prvt = [(CKA_SIGN, vec![1])];
    let (tp, tv) = (template(&pubt), template(&prvt));
    let m = mechanism(mech, &[]);
    let (mut hp, mut hv) = (0u32, 0u32);
    match C_GenerateKeyPair(
        session,
        m.as_ptr() as *mut u8,
        tp.as_ptr() as *mut u8,
        pubt.len() as u32,
        tv.as_ptr() as *mut u8,
        prvt.len() as u32,
        &mut hp,
        &mut hv,
    ) {
        CKR_OK => Ok((hp, hv)),
        rv => Err(rv),
    }
}

// ═══ E12 — AES-GCM, every IV length CK_GCM_PARAMS allows ═══════════════════

/// ACVP-AES-GCM-1.0: all 60 cases (IV 96 and 120 bits, tag 128 and 32 bits,
/// encrypt and decrypt, including upstream authentication failures).
/// PKCS#11 v3.2 §6.13.x CK_GCM_PARAMS: ulIvLen may be any value from 1 to
/// 2^32-1 bytes; SP 800-38D §7.1 step 2 derives J0 by GHASH for every IV
/// length other than 96 bits.
#[test]
fn e12_aes_gcm_nist_all_iv_lengths() {
    let _g = test_lock::acquire();
    let session = setup_session();
    let doc = fixture("aesgcm_acvp_test.json");
    let (mut enc, mut dec_ok, mut dec_rej) = (0, 0, 0);
    for g in doc["testGroups"].as_array().unwrap() {
        let dir = s(g, "direction");
        let iv_bits = g["ivLen"].as_u64().unwrap() as usize;
        let tag_bits = g["tagLen"].as_u64().unwrap() as usize;
        for t in g["tests"].as_array().unwrap() {
            let tc = &t["tcId"];
            let key = hx(s(t, "key"));
            let iv = hx(s(t, "iv"));
            let aad = hx(s(t, "aad"));
            assert_eq!(iv.len() * 8, iv_bits);
            let hk = secret_key(session, CKK_AES, &key);
            let p = pack(
                &ck_param::gcm::LAYOUT,
                &[
                    (ck_param::gcm::P_IV, ptr(&iv)),
                    (ck_param::gcm::UL_IV_LEN, iv.len()),
                    (ck_param::gcm::UL_IV_BITS, iv_bits),
                    (ck_param::gcm::P_AAD, ptr(&aad)),
                    (ck_param::gcm::UL_AAD_LEN, aad.len()),
                    (ck_param::gcm::UL_TAG_BITS, tag_bits),
                ],
            );
            let m = mechanism(CKM_AES_GCM, &p);
            let mut ct_tag = hx(s(t, "ct"));
            ct_tag.extend_from_slice(&hx(s(t, "tag")));
            if dir == "encrypt" {
                let pt = hx(s(t, "pt"));
                assert_eq!(C_EncryptInit(session, m.as_ptr() as *mut u8, hk), CKR_OK, "tc {tc} EncryptInit");
                let mut out = vec![0u8; pt.len() + 16];
                let mut len = out.len() as u32;
                assert_eq!(
                    C_Encrypt(session, pt.as_ptr() as *mut u8, pt.len() as u32, out.as_mut_ptr(), &mut len),
                    CKR_OK,
                    "tc {tc} Encrypt"
                );
                out.truncate(len as usize);
                assert_eq!(out, ct_tag, "tc {tc} ct||tag");
                enc += 1;
            } else {
                assert_eq!(C_DecryptInit(session, m.as_ptr() as *mut u8, hk), CKR_OK, "tc {tc} DecryptInit");
                let mut out = vec![0u8; ct_tag.len() + 16];
                let mut len = out.len() as u32;
                let rv = C_Decrypt(session, ct_tag.as_ptr() as *mut u8, ct_tag.len() as u32, out.as_mut_ptr(), &mut len);
                if t["testPassed"].as_bool().unwrap() {
                    assert_eq!(rv, CKR_OK, "tc {tc} Decrypt");
                    out.truncate(len as usize);
                    assert_eq!(out, hx(s(t, "pt")), "tc {tc} pt");
                    dec_ok += 1;
                } else {
                    // An authentication failure, refused at C_Decrypt after
                    // the tag check (not at init for the IV length).
                    assert_eq!(rv, CKR_ENCRYPTED_DATA_INVALID, "tc {tc} must fail the tag check");
                    dec_rej += 1;
                }
            }
        }
    }
    assert_eq!(enc + dec_ok + dec_rej, 60, "all 60 NIST cases executed");
    assert_eq!(enc, 30);
}
