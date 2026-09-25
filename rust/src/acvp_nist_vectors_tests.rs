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

/// A CK_ULONG attribute value at this target's native width.
fn ul(v: u32) -> Vec<u8> {
    (v as usize).to_ne_bytes().to_vec()
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

// ═══ E13 — ECDSA SigVer (FIPS 186-5), P-224 included ═══════════════════════

fn ecdsa_hash_mech(hash: &str) -> u32 {
    match hash {
        "SHA2-224" => CKM_ECDSA_SHA224,
        "SHA2-256" => CKM_ECDSA_SHA256,
        "SHA2-384" => CKM_ECDSA_SHA384,
        "SHA2-512" => CKM_ECDSA_SHA512,
        "SHA3-224" => CKM_ECDSA_SHA3_224,
        "SHA3-256" => CKM_ECDSA_SHA3_256,
        "SHA3-384" => CKM_ECDSA_SHA3_384,
        "SHA3-512" => CKM_ECDSA_SHA3_512,
        other => panic!("hash {other}"),
    }
}

/// ECDSA-SigVer-FIPS186-5: every executed group (P-224/256/384/521 x
/// SHA2-256/512, SHA3-256/512; 7 cases each: 1 valid + 6 invalid reasons).
/// Signatures over a modified message, r or s, or a zero r or s must be
/// refused at C_Verify with CKR_SIGNATURE_INVALID; a modified key may be
/// refused at any step.
#[test]
fn e13_ecdsa_sigver_nist_all_curves() {
    let _g = test_lock::acquire();
    let session = setup_session();
    let doc = fixture("ecdsa_sigver_acvp_test.json");
    let (mut ok, mut rej, mut p224) = (0, 0, 0);
    for g in doc["testGroups"].as_array().unwrap() {
        let curve = s(g, "curve");
        let mech = mechanism(ecdsa_hash_mech(s(g, "hashAlg")), &[]);
        let n = field_bytes(curve);
        for t in g["tests"].as_array().unwrap() {
            let tc = &t["tcId"];
            let mut point = vec![0x04];
            point.extend_from_slice(&left_pad(&hx(s(t, "qx")), n));
            point.extend_from_slice(&left_pad(&hx(s(t, "qy")), n));
            let mut sig = left_pad(&hx(s(t, "r")), n);
            sig.extend_from_slice(&left_pad(&hx(s(t, "s")), n));
            let msg = hx(s(t, "message"));
            let hk = create(
                session,
                &[
                    (CKA_CLASS, ul(CKO_PUBLIC_KEY)),
                    (CKA_KEY_TYPE, ul(CKK_EC)),
                    (CKA_EC_PARAMS, curve_oid(curve)),
                    (CKA_EC_POINT, der_point(&point)),
                    (CKA_VERIFY, vec![1]),
                ],
            );
            let passed = t["testPassed"].as_bool().unwrap();
            let reason = s(t, "reason");
            let rv = match hk {
                Ok(h) => verify(session, &mech, h, &msg, &sig),
                Err(rv) => rv,
            };
            if passed {
                assert_eq!(rv, CKR_OK, "tc {tc} {curve} valid signature");
                ok += 1;
            } else if reason == "modify key" {
                assert_ne!(rv, CKR_OK, "tc {tc} {curve} modified key accepted");
                rej += 1;
            } else {
                assert_eq!(rv, CKR_SIGNATURE_INVALID, "tc {tc} {curve} ({reason})");
                rej += 1;
            }
            if curve == "P-224" {
                p224 += 1;
            }
        }
    }
    assert_eq!(ok + rej, 112, "all 112 executed NIST cases");
    assert_eq!(p224, 28, "the 28 P-224 cases");
}

/// Advertisement == dispatch: every CKM_ECDSA* mechanism's advertised
/// ulMinKeySize covers P-224, and P-224 private keys sign through C_Sign
/// with every hash-composite ECDSA mechanism (the signature then verifies
/// through C_Verify and fails on a changed message). The private scalar is
/// FIPS 186-5-irrelevant here (a product-authored fixed value, 1..=28).
#[test]
fn e13_ecdsa_p224_advertised_and_signs() {
    let _g = test_lock::acquire();
    let session = setup_session();
    for m in [
        CKM_ECDSA, CKM_ECDSA_SHA1, CKM_ECDSA_SHA224, CKM_ECDSA_SHA256, CKM_ECDSA_SHA384,
        CKM_ECDSA_SHA512, CKM_ECDSA_SHA3_224, CKM_ECDSA_SHA3_256, CKM_ECDSA_SHA3_384,
        CKM_ECDSA_SHA3_512,
    ] {
        let (min, max, _) = mech_info(m);
        assert!(min <= 224 && max >= 521, "mech {m:#x} advertises {min}..{max}");
    }
    let d: Vec<u8> = (1u8..=28).collect();
    let sk = p224::ecdsa::SigningKey::from_slice(&d).unwrap();
    let point = sk.verifying_key().to_encoded_point(false).as_bytes().to_vec();
    let h_prv = create(
        session,
        &[
            (CKA_CLASS, ul(CKO_PRIVATE_KEY)),
            (CKA_KEY_TYPE, ul(CKK_EC)),
            (CKA_EC_PARAMS, curve_oid("P-224")),
            (CKA_VALUE, d.clone()),
            (CKA_SIGN, vec![1]),
        ],
    )
    .expect("P-224 private key");
    let h_pub = create(
        session,
        &[
            (CKA_CLASS, ul(CKO_PUBLIC_KEY)),
            (CKA_KEY_TYPE, ul(CKK_EC)),
            (CKA_EC_PARAMS, curve_oid("P-224")),
            (CKA_EC_POINT, der_point(&point)),
            (CKA_VERIFY, vec![1]),
        ],
    )
    .expect("P-224 public key");
    let msg = b"P-224 advertised == dispatched";
    // (CKM_ECDSA_SHA1 / CKM_ECDSA_SHA224 are covered, on every curve, by the
    // E11 matrix below.)
    for m in [
        CKM_ECDSA_SHA256, CKM_ECDSA_SHA384, CKM_ECDSA_SHA512, CKM_ECDSA_SHA3_224,
        CKM_ECDSA_SHA3_256, CKM_ECDSA_SHA3_384, CKM_ECDSA_SHA3_512,
    ] {
        let mech = mechanism(m, &[]);
        let sig = sign(session, &mech, h_prv, msg).unwrap_or_else(|rv| panic!("sign {m:#x}: {rv:#x}"));
        assert_eq!(sig.len(), 56, "mech {m:#x}: r||s on P-224 is 56 bytes");
        assert_eq!(verify(session, &mech, h_pub, msg, &sig), CKR_OK, "verify {m:#x}");
        assert_eq!(verify(session, &mech, h_pub, b"other", &sig), CKR_SIGNATURE_INVALID, "tamper {m:#x}");
    }
    // Raw CKM_ECDSA over a SHA-256 digest verifies as CKM_ECDSA_SHA256
    // (both condition the digest to the leftmost 224 bits, FIPS 186-5 §6.4).
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(msg).to_vec();
    let sig = sign(session, &mechanism(CKM_ECDSA, &[]), h_prv, &digest).expect("raw sign");
    assert_eq!(verify(session, &mechanism(CKM_ECDSA_SHA256, &[]), h_pub, msg, &sig), CKR_OK);
    assert_eq!(verify(session, &mechanism(CKM_ECDSA, &[]), h_pub, &digest, &sig), CKR_OK);
}

// ═══ E14 — RSA SigVer (FIPS 186-5) with public exponents above 2^33 - 1 ═══

/// RSA-SigVer-FIPS186-5: the four executed groups (PKCS#1 v1.5/SHA2-256 at
/// 2048/3072/4096 bits, PSS/SHA3-256/MGF1 at 2048 bits; 6 cases each). Two
/// groups carry exponents FIPS 186-5 §A.1.1 allows (odd, 2^16 < e < 2^256)
/// but wider than 33 bits: e = 0xC9986A9C84FEE9 (56 bits) and
/// e = 0x0ACC245201D531 (52 bits).
#[test]
fn e14_rsa_sigver_nist_large_exponents() {
    let _g = test_lock::acquire();
    let session = setup_session();
    let doc = fixture("rsa_sigver_acvp_test.json");
    let (mut ok, mut rej, mut wide_e) = (0, 0, 0);
    for g in doc["testGroups"].as_array().unwrap() {
        let n = hx(s(g, "n"));
        let e_hex = s(g, "e");
        let e = hx(&if e_hex.len() % 2 == 1 { format!("0{e_hex}") } else { e_hex.to_string() });
        let pss_params;
        let mech = match (s(g, "sigType"), s(g, "hashAlg")) {
            ("pkcs1v1.5", "SHA2-256") => mechanism(CKM_SHA256_RSA_PKCS, &[]),
            ("pss", "SHA3-256") => {
                pss_params = pack(
                    &ck_param::pss::LAYOUT,
                    &[
                        (ck_param::pss::HASH_ALG, CKM_SHA3_256 as usize),
                        (ck_param::pss::MGF, CKG_MGF1_SHA3_256 as usize),
                        (ck_param::pss::S_LEN, g["saltLen"].as_u64().unwrap() as usize),
                    ],
                );
                mechanism(CKM_SHA3_256_RSA_PKCS_PSS, &pss_params)
            }
            other => panic!("group {other:?}"),
        };
        let significant = e.iter().skip_while(|&&b| b == 0).count();
        let e_bits = if significant == 0 { 0 } else { significant * 8 - e[e.len() - significant].leading_zeros() as usize };
        for t in g["tests"].as_array().unwrap() {
            let tc = &t["tcId"];
            let hk = create(
                session,
                &[
                    (CKA_CLASS, ul(CKO_PUBLIC_KEY)),
                    (CKA_KEY_TYPE, ul(CKK_RSA)),
                    (CKA_MODULUS, n.clone()),
                    (CKA_PUBLIC_EXPONENT, e.clone()),
                    (CKA_VERIFY, vec![1]),
                ],
            )
            .expect("RSA public key");
            let rv = verify(session, &mech, hk, &hx(s(t, "message")), &hx(s(t, "signature")));
            if t["testPassed"].as_bool().unwrap() {
                assert_eq!(rv, CKR_OK, "tc {tc} (e = {e_bits} bits) valid signature");
                ok += 1;
            } else {
                assert_eq!(rv, CKR_SIGNATURE_INVALID, "tc {tc} (e = {e_bits} bits) {}", s(t, "reason"));
                rej += 1;
            }
            if e_bits > 33 {
                wide_e += 1;
            }
        }
    }
    assert_eq!(ok + rej, 24, "all 24 executed NIST cases");
    assert_eq!(wide_e, 12, "the 12 cases whose e exceeds 2^33 - 1");
}

/// The FIPS 186-5 §A.1.1 bound is kept at the top: an exponent of 2^256 + 1
/// (odd, but >= 2^256) is refused. Product-authored probe, not a NIST case.
#[test]
fn e14_rsa_exponent_at_or_above_2_256_refused() {
    let doc = fixture("rsa_sigver_acvp_test.json");
    let g = &doc["testGroups"][0];
    let n = hx(s(g, "n"));
    let t = &g["tests"][0];
    let mut e = vec![0x01];
    e.extend_from_slice(&[0u8; 31]);
    e.push(0x01); // 2^256 + 1
    assert!(
        crate::crypto::handlers::verify_rsa(
            CKM_SHA256_RSA_PKCS,
            &n,
            &e,
            &hx(s(t, "message")),
            &hx(s(t, "signature")),
            None
        )
        .is_err()
    );
}

// ═══ E15 — PBKDF2 (SP 800-132) PRFs; the < 1000-iteration floor stays ═════

const PRF_HMAC_SHA1: usize = 0x01; // CKP_PKCS5_PBKD2_HMAC_SHA1 (pkcs11t.h)
const PRF_HMAC_SHA224: usize = 0x03; // CKP_PKCS5_PBKD2_HMAC_SHA224 (pkcs11t.h)

fn pbkdf2_derive(session: u32, prf: usize, iterations: usize, password: &[u8], salt: &[u8], len: usize) -> Result<Vec<u8>, u32> {
    let p = pack(
        &ck_param::pbkd2::LAYOUT,
        &[
            (ck_param::pbkd2::SALT_SOURCE, CKZ_DATA_SPECIFIED as usize),
            (ck_param::pbkd2::P_SALT_SOURCE_DATA, ptr(salt)),
            (ck_param::pbkd2::UL_SALT_SOURCE_DATA_LEN, salt.len()),
            (ck_param::pbkd2::ITERATIONS, iterations),
            (ck_param::pbkd2::PRF, prf),
            (ck_param::pbkd2::P_PASSWORD, ptr(password)),
            (ck_param::pbkd2::UL_PASSWORD_LEN, password.len()),
        ],
    );
    let m = mechanism(CKM_PKCS5_PBKD2, &p);
    let attrs = [
        (CKA_CLASS, ul(CKO_SECRET_KEY)),
        (CKA_KEY_TYPE, ul(CKK_GENERIC_SECRET)),
        (CKA_VALUE_LEN, ul(len as u32)),
    ];
    let t = template(&attrs);
    let mut h = 0u32;
    match C_DeriveKey(session, m.as_ptr() as *mut u8, 0, t.as_ptr() as *mut u8, attrs.len() as u32, &mut h) {
        CKR_OK => Ok(obj_value(h)),
        rv => Err(rv),
    }
}

/// PBKDF 1.0 (HMAC-SHA2-224, the only PRF the pinned sample registers):
/// the four cases with >= 1000 iterations derive the NIST key byte-exact;
/// tc20 (iterationCount = 1) is refused by the engine's documented policy
/// floor (decision D7, 2026-09-25) with CKR_MECHANISM_PARAM_INVALID — the
/// code PKCS#11 v3.2 §5.1.6 gives a mechanism parameter the token will not
/// accept — never with a derived key.
#[test]
fn e15_pbkdf2_nist_sha224_prf_and_iteration_floor() {
    let _g = test_lock::acquire();
    let session = setup_session();
    let doc = fixture("pbkdf2_acvp_test.json");
    let g = &doc["testGroups"][0];
    assert_eq!(s(g, "hmacAlg"), "SHA2-224");
    let (mut derived, mut floor) = (0, 0);
    for t in g["tests"].as_array().unwrap() {
        let tc = &t["tcId"];
        let iterations = t["iterationCount"].as_u64().unwrap() as usize;
        let want = hx(s(t, "derivedKey"));
        assert_eq!(want.len() * 8, t["keyLen"].as_u64().unwrap() as usize);
        let got = pbkdf2_derive(session, PRF_HMAC_SHA224, iterations, s(t, "password").as_bytes(), &hx(s(t, "salt")), want.len());
        if iterations >= 1000 {
            assert_eq!(got, Ok(want), "tc {tc}");
            derived += 1;
        } else {
            assert_eq!(got, Err(CKR_MECHANISM_PARAM_INVALID), "tc {tc}: {iterations} iterations is below the policy floor");
            floor += 1;
        }
    }
    assert_eq!((derived, floor), (4, 1));
}

/// Every PRF the C++ engine implements is implemented here too, byte-equal
/// to the RustCrypto pbkdf2 reference with the same PRF (product-authored
/// inputs; RFC 6070 test 3 for HMAC-SHA1: P="password", S="salt", c=4096,
/// dkLen=20 -> 4b007901b765489abead49d926f721d065a429c1).
#[test]
fn e15_pbkdf2_prf_parity_with_cpp() {
    let _g = test_lock::acquire();
    let session = setup_session();
    assert_eq!(
        pbkdf2_derive(session, PRF_HMAC_SHA1, 4096, b"password", b"salt", 20),
        Ok(hx("4b007901b765489abead49d926f721d065a429c1")),
        "RFC 6070 §2 test 3"
    );
    // An unimplemented PRF (CKP_PKCS5_PBKD2_HMAC_GOSTR3411) is a parameter
    // the token does not accept.
    assert_eq!(pbkdf2_derive(session, 0x02, 4096, b"password", b"salt", 20), Err(CKR_MECHANISM_PARAM_INVALID));
}

// ═══ E16 — KMAC honours CK_PQCTODAY_KMAC_PARAMS.ulOutputLen ═══════════════

fn kmac_params(customization: &[u8], out_len: usize) -> Vec<u8> {
    pack(
        &ck_param::kmac::LAYOUT,
        &[
            (ck_param::kmac::P_CUSTOMIZATION, ptr(customization)),
            (ck_param::kmac::UL_CUSTOMIZATION_LEN, customization.len()),
            (ck_param::kmac::UL_OUTPUT_LEN, out_len),
        ],
    )
}

/// KMAC-128 1.0 MVT (non-XOF, hex customization): tc799 is a valid 478-byte
/// MAC and must verify; tc771 is a 32-byte MAC the upstream marks invalid
/// and must be refused with CKR_SIGNATURE_INVALID. The same parameters
/// must SIGN to the NIST MAC too (size query included).
#[test]
fn e16_kmac128_nist_mvt_output_length() {
    let _g = test_lock::acquire();
    let session = setup_session();
    let doc = fixture("kmac_acvp_test.json");
    let mut seen = 0;
    for t in doc["testGroups"][0]["tests"].as_array().unwrap() {
        let tc = &t["tcId"];
        let key = hx(s(t, "key"));
        let msg = hx(s(t, "msg"));
        let mac = hx(s(t, "mac"));
        let cust = hx(s(t, "customizationHex"));
        let out_len = t["macLen"].as_u64().unwrap() as usize / 8;
        assert_eq!(mac.len(), out_len);
        let hk = secret_key(session, CKK_GENERIC_SECRET, &key);
        let p = kmac_params(&cust, out_len);
        let m = mechanism(CKM_KMAC_128, &p);
        let rv = verify(session, &m, hk, &msg, &mac);
        if t["testPassed"].as_bool().unwrap() {
            assert_eq!(rv, CKR_OK, "tc {tc}: valid {out_len}-byte MAC");
            let sig = sign(session, &m, hk, &msg).unwrap_or_else(|rv| panic!("tc {tc} sign: {rv:#x}"));
            assert_eq!(sig, mac, "tc {tc}: C_Sign output");
        } else {
            assert_eq!(rv, CKR_SIGNATURE_INVALID, "tc {tc}: invalid MAC");
        }
        seen += 1;
    }
    assert_eq!(seen, 2);
}

/// A MAC whose length differs from the requested ulOutputLen is a length
/// error (PKCS#11 v3.2 §5.15.2 CKR_SIGNATURE_LEN_RANGE), and ulOutputLen = 0
/// keeps the mechanism default (32 bytes for KMAC-128, 64 for KMAC-256).
/// Product-authored probe.
#[test]
fn e16_kmac_length_checks_follow_the_parameter() {
    let _g = test_lock::acquire();
    let session = setup_session();
    let hk = secret_key(session, CKK_GENERIC_SECRET, &[0x42u8; 32]);
    let msg = b"kmac output length";
    for (mech, default_len) in [(CKM_KMAC_128, 32usize), (CKM_KMAC_256, 64)] {
        let p = kmac_params(b"", 0);
        let m = mechanism(mech, &p);
        let sig = sign(session, &m, hk, msg).expect("default-length sign");
        assert_eq!(sig.len(), default_len);
        assert_eq!(verify(session, &m, hk, msg, &sig), CKR_OK);

        let p = kmac_params(b"", 100);
        let m = mechanism(mech, &p);
        let sig = sign(session, &m, hk, msg).expect("100-byte sign");
        assert_eq!(sig.len(), 100);
        assert_eq!(verify(session, &m, hk, msg, &sig), CKR_OK);
        assert_eq!(verify(session, &m, hk, msg, &sig[..99]), CKR_SIGNATURE_LEN_RANGE);
        assert_eq!(verify(session, &m, hk, msg, &sig[..default_len]), CKR_SIGNATURE_LEN_RANGE);
    }
}

// ═══ E17 — HMAC key-size advertisement matches what the engine accepts ════

/// Every HMAC / HMAC_GENERAL mechanism, paired with its general twin.
const HMAC_MECHS: &[(u32, u32)] = &[
    (CKM_MD5_HMAC, CKM_MD5_HMAC_GENERAL),
    (CKM_SHA_1_HMAC, CKM_SHA_1_HMAC_GENERAL),
    (CKM_RIPEMD160_HMAC, CKM_RIPEMD160_HMAC_GENERAL),
    (CKM_SHA224_HMAC, CKM_SHA224_HMAC_GENERAL),
    (CKM_SHA256_HMAC, CKM_SHA256_HMAC_GENERAL),
    (CKM_SHA384_HMAC, CKM_SHA384_HMAC_GENERAL),
    (CKM_SHA512_HMAC, CKM_SHA512_HMAC_GENERAL),
    (CKM_SHA512_224_HMAC, CKM_SHA512_224_HMAC_GENERAL),
    (CKM_SHA512_256_HMAC, CKM_SHA512_256_HMAC_GENERAL),
    (CKM_SHA3_224_HMAC, CKM_SHA3_224_HMAC_GENERAL),
    (CKM_SHA3_256_HMAC, CKM_SHA3_256_HMAC_GENERAL),
    (CKM_SHA3_384_HMAC, CKM_SHA3_384_HMAC_GENERAL),
    (CKM_SHA3_512_HMAC, CKM_SHA3_512_HMAC_GENERAL),
];

fn hmac_general_mech(hash: &str) -> u32 {
    match hash {
        "SHA-1" => CKM_SHA_1_HMAC_GENERAL,
        "SHA2-224" => CKM_SHA224_HMAC_GENERAL,
        "SHA2-256" => CKM_SHA256_HMAC_GENERAL,
        "SHA2-384" => CKM_SHA384_HMAC_GENERAL,
        "SHA2-512" => CKM_SHA512_HMAC_GENERAL,
        "SHA2-512/224" => CKM_SHA512_224_HMAC_GENERAL,
        "SHA2-512/256" => CKM_SHA512_256_HMAC_GENERAL,
        "SHA3-224" => CKM_SHA3_224_HMAC_GENERAL,
        "SHA3-256" => CKM_SHA3_256_HMAC_GENERAL,
        "SHA3-384" => CKM_SHA3_384_HMAC_GENERAL,
        "SHA3-512" => CKM_SHA3_512_HMAC_GENERAL,
        other => panic!("hash {other}"),
    }
}

/// HMAC 2.0 AFT, one upstream file per digest (11 digests, 63 cases, keys
/// 1..256 bytes): C_Sign with CK_MAC_GENERAL_PARAMS reproduces the NIST MAC,
/// C_Verify accepts it — and every key length the engine accepts lies
/// inside what C_GetMechanismInfo advertises for both the general and the
/// fixed-length mechanism. FIPS 198-1 §4 / RFC 2104 §3 allow any key
/// length (a key longer than the block is hashed first); PKCS#11 v3.2
/// §6.22.3 only says a FIPS-198 token "may" require >= half the digest.
#[test]
fn e17_hmac_nist_keys_inside_advertised_range() {
    let _g = test_lock::acquire();
    let session = setup_session();
    let doc = fixture("hmac_acvp_matrix_test.json");
    let mut n = 0;
    for g in doc["testGroups"].as_array().unwrap() {
        let general = hmac_general_mech(s(g, "hashAlg"));
        let fixed = HMAC_MECHS.iter().find(|(_, gm)| *gm == general).unwrap().0;
        for t in g["tests"].as_array().unwrap() {
            let tc = &t["tcId"];
            let key = hx(s(t, "key"));
            let mac = hx(s(t, "mac"));
            for m in [general, fixed] {
                let (min, max, _) = mech_info(m);
                assert!(
                    (min as usize..=max as usize).contains(&key.len()),
                    "tc {tc}: {}-byte key outside mech {m:#x}'s advertised {min}..{max}",
                    key.len()
                );
            }
            let hk = secret_key(session, CKK_GENERIC_SECRET, &key);
            let p = pack(&ck_param::mac_general::LAYOUT, &[(ck_param::mac_general::UL_MAC_LENGTH, mac.len())]);
            let mech = mechanism(general, &p);
            let msg = hx(s(t, "msg"));
            assert_eq!(sign(session, &mech, hk, &msg), Ok(mac.clone()), "tc {tc} C_Sign");
            assert_eq!(verify(session, &mech, hk, &msg, &mac), CKR_OK, "tc {tc} C_Verify");
            n += 1;
        }
    }
    assert_eq!(n, 63, "every case in the 11 groups");
}

/// The advertised range, stated: 1 to 512 bytes for every HMAC mechanism —
/// the same bounds as this engine's CKM_GENERIC_SECRET_KEY_GEN — and both
/// ends really work. RFC 4231 §4.3 test case 2 (4-byte key "Jefe") and a
/// 512-byte key round-trip through C_Sign/C_Verify on every mechanism.
#[test]
fn e17_hmac_advertised_bounds_execute() {
    let _g = test_lock::acquire();
    let session = setup_session();
    assert_eq!(mech_info(CKM_GENERIC_SECRET_KEY_GEN).0, 1);
    let msg = b"what do ya want for nothing?";
    let jefe = secret_key(session, CKK_GENERIC_SECRET, b"Jefe");
    let big = secret_key(session, CKK_GENERIC_SECRET, &[0x5au8; 512]);
    for &(fixed, general) in HMAC_MECHS {
        for m in [fixed, general] {
            let (min, max, _) = mech_info(m);
            assert_eq!((min, max), (1, 512), "mech {m:#x}");
        }
        let mech = mechanism(fixed, &[]);
        for hk in [jefe, big] {
            let mac = sign(session, &mech, hk, msg).unwrap_or_else(|rv| panic!("{fixed:#x}: {rv:#x}"));
            assert_eq!(verify(session, &mech, hk, msg, &mac), CKR_OK);
        }
    }
    // RFC 4231 §4.3, HMAC-SHA-256 with the 4-byte key.
    assert_eq!(
        sign(session, &mechanism(CKM_SHA256_HMAC, &[]), jefe, msg),
        Ok(hx("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"))
    );
}

// ═══ E11 — advertised cells that did not execute (G-8 probes) ═════════════
//
// For each cell the G-8 probes found advertised but failing, the fix was to
// make it execute (see each test). These are product-authored probes: the
// expected values are either self-consistency across two engine paths that
// compute the same function, or published KATs cited inline.

const HASH_ECDSA_MECHS: &[u32] = &[
    CKM_ECDSA_SHA1, CKM_ECDSA_SHA224, CKM_ECDSA_SHA256, CKM_ECDSA_SHA384, CKM_ECDSA_SHA512,
    CKM_ECDSA_SHA3_224, CKM_ECDSA_SHA3_256, CKM_ECDSA_SHA3_384, CKM_ECDSA_SHA3_512,
];

/// E11(a) — CKM_ECDSA_SHA1 / CKM_ECDSA_SHA224 were advertised (CKF_SIGN |
/// CKF_VERIFY, 224..521) and accepted at C_SignInit, then C_Sign returned
/// CKR_MECHANISM_INVALID on every curve: the C_Sign/C_Verify dispatch lists
/// named every other hash-composite ECDSA mechanism but not these two. Every
/// advertised hash-composite ECDSA mechanism must now sign and verify on
/// every generated curve, single- and multi-part, and bind the message.
#[test]
fn e11_every_hash_ecdsa_mechanism_executes_on_every_curve() {
    let _g = test_lock::acquire();
    let session = setup_session();
    let msg = b"E11 advertised == dispatched";
    for curve in ["P-256", "secp256k1", "P-384", "P-521"] {
        let (h_pub, h_prv) = ec_keypair(session, CKM_EC_KEY_PAIR_GEN, curve).expect("keygen");
        for &m in HASH_ECDSA_MECHS {
            let (min, max, flags) = mech_info(m);
            assert!(flags & 0x800 != 0 && min <= 256 && max >= 521, "{m:#x} advertisement");
            let mech = mechanism(m, &[]);
            let sig = sign(session, &mech, h_prv, msg).unwrap_or_else(|rv| panic!("{curve} {m:#x} C_Sign: {rv:#x}"));
            assert_eq!(sig.len(), 2 * field_bytes(curve), "{curve} {m:#x}");
            assert_eq!(verify(session, &mech, h_pub, msg, &sig), CKR_OK, "{curve} {m:#x} C_Verify");
            assert_eq!(verify(session, &mech, h_pub, b"tampered", &sig), CKR_SIGNATURE_INVALID, "{curve} {m:#x}");
            // Multi-part (§5.13.3/§5.15.3): hash-composite mechanisms stream.
            assert_eq!(C_SignInit(session, mech.as_ptr() as *mut u8, h_prv), CKR_OK);
            for part in [&msg[..7], &msg[7..]] {
                assert_eq!(C_SignUpdate(session, part.as_ptr() as *mut u8, part.len() as u32), CKR_OK, "{curve} {m:#x} SignUpdate");
            }
            let mut mp = vec![0u8; 132];
            let mut len = mp.len() as u32;
            assert_eq!(C_SignFinal(session, mp.as_mut_ptr(), &mut len), CKR_OK, "{curve} {m:#x} SignFinal");
            mp.truncate(len as usize);
            assert_eq!(verify(session, &mech, h_pub, msg, &mp), CKR_OK, "{curve} {m:#x} multi-part signature");
        }
    }
}

/// E11(b) — raw CKM_ECDSA on P-521 refused a 32-byte input with
/// CKR_FUNCTION_FAILED (the RustCrypto prehash API wants at least half the
/// field). PKCS#11 v3.2 §6.3.12 takes any input length for raw ECDSA, and
/// FIPS 186-5 §6.4.1 uses the leftmost min(N, len) bits of it, so a short
/// input is its own integer value. Checked on every curve and several input
/// lengths — including by cross-verifying the raw signature of SHA-256(M)
/// as a CKM_ECDSA_SHA256 signature of M, which computes the same e.
#[test]
fn e11_raw_ecdsa_accepts_any_digest_length() {
    use sha2::Digest as _;
    let _g = test_lock::acquire();
    let session = setup_session();
    let msg = b"raw ECDSA input conditioning";
    let raw = mechanism(CKM_ECDSA, &[]);
    for curve in ["P-256", "secp256k1", "P-384", "P-521"] {
        let (h_pub, h_prv) = ec_keypair(session, CKM_EC_KEY_PAIR_GEN, curve).expect("keygen");
        for len in [1usize, 16, 20, 28, 32, 48, 64, 66] {
            let input: Vec<u8> = (0..len as u8).map(|b| b.wrapping_mul(37).wrapping_add(1)).collect();
            let sig = sign(session, &raw, h_prv, &input).unwrap_or_else(|rv| panic!("{curve} raw {len}: {rv:#x}"));
            assert_eq!(verify(session, &raw, h_pub, &input, &sig), CKR_OK, "{curve} raw {len}");
        }
        let d = sha2::Sha256::digest(msg).to_vec();
        let sig = sign(session, &raw, h_prv, &d).expect("raw sign of a SHA-256 digest");
        assert_eq!(verify(session, &mechanism(CKM_ECDSA_SHA256, &[]), h_pub, msg, &sig), CKR_OK, "{curve}: raw(SHA-256(M)) == ECDSA_SHA256(M)");
    }
}

/// E11(c) — AES-192 is inside every AES mechanism's advertised 16..32-byte
/// range, but single-part CKM_AES_CBC_PAD returned CKR_KEY_TYPE_INCONSISTENT
/// and C_MessageEncryptInit(CKM_AES_GCM) CKR_KEY_SIZE_RANGE for a 24-byte
/// key. KATs: NIST SP 800-38A §F.2.3 CBC-AES192.Encrypt (the four blocks;
/// the fifth, the PKCS#7 pad block, computed with pyca/cryptography 49.0.0),
/// and McGrew-Viega GCM specification test case 8 (K = 0^192, IV = 0^96,
/// P = 0^128 -> C = 98e7247c07f0fe411c267e4384b0f600,
/// T = 2ff58d80033927ab8ef4d4587514f0fb).
#[test]
fn e11_aes192_cbc_pad_and_message_gcm() {
    let _g = test_lock::acquire();
    let session = setup_session();
    let key = hx("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    let iv = hx("000102030405060708090a0b0c0d0e0f");
    let pt = hx("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
    let want = hx("4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd612ccd79224b350935d45dd6a98f8176");
    let hk = secret_key(session, CKK_AES, &key);
    let m = mechanism(CKM_AES_CBC_PAD, &iv);
    assert_eq!(C_EncryptInit(session, m.as_ptr() as *mut u8, hk), CKR_OK);
    let mut out = vec![0u8; 96];
    let mut len = out.len() as u32;
    assert_eq!(C_Encrypt(session, pt.as_ptr() as *mut u8, pt.len() as u32, out.as_mut_ptr(), &mut len), CKR_OK, "C_Encrypt AES-192 CBC_PAD");
    out.truncate(len as usize);
    assert_eq!(out, want, "SP 800-38A F.2.3 + PKCS#7 pad block");
    assert_eq!(C_DecryptInit(session, m.as_ptr() as *mut u8, hk), CKR_OK);
    let mut back = vec![0u8; 96];
    let mut len = back.len() as u32;
    assert_eq!(C_Decrypt(session, out.as_ptr() as *mut u8, out.len() as u32, back.as_mut_ptr(), &mut len), CKR_OK, "C_Decrypt AES-192 CBC_PAD");
    back.truncate(len as usize);
    assert_eq!(back, pt);

    // Message-based GCM (§5.9 / §5.11) with an AES-192 key.
    let gk = secret_key(session, CKK_AES, &[0u8; 24]);
    let gm = mechanism(CKM_AES_GCM, &[]);
    let mut nonce = [0u8; 12];
    let mut tag = [0u8; 16];
    let msg_params = |nonce: &mut [u8; 12], tag: &mut [u8; 16]| -> Vec<usize> {
        // CK_GCM_MESSAGE_PARAMS: pIv, ulIvLen, ulIvFixedBits, ivGenerator, pTag, ulTagBits
        vec![nonce.as_mut_ptr() as usize, 12, 0, 0, tag.as_mut_ptr() as usize, 128]
    };
    assert_eq!(C_MessageEncryptInit(session, gm.as_ptr() as *mut u8, gk), CKR_OK, "C_MessageEncryptInit AES-192");
    let p = msg_params(&mut nonce, &mut tag);
    let zero = [0u8; 16];
    let mut ct = [0u8; 16];
    let mut ct_len = 16u32;
    assert_eq!(
        C_EncryptMessage(session, p.as_ptr() as *mut u8, (p.len() * ck_param::WORD) as u32, std::ptr::null(), 0, zero.as_ptr(), 16, ct.as_mut_ptr(), &mut ct_len),
        CKR_OK
    );
    assert_eq!(C_MessageEncryptFinal(session), CKR_OK);
    assert_eq!(ct.to_vec(), hx("98e7247c07f0fe411c267e4384b0f600"), "GCM test case 8 C");
    assert_eq!(tag.to_vec(), hx("2ff58d80033927ab8ef4d4587514f0fb"), "GCM test case 8 T");
    assert_eq!(C_MessageDecryptInit(session, gm.as_ptr() as *mut u8, gk), CKR_OK, "C_MessageDecryptInit AES-192");
    let p = msg_params(&mut nonce, &mut tag);
    let mut pt2 = [0xffu8; 16];
    let mut pt2_len = 16u32;
    assert_eq!(
        C_DecryptMessage(session, p.as_ptr() as *mut u8, (p.len() * ck_param::WORD) as u32, std::ptr::null(), 0, ct.as_ptr(), 16, pt2.as_mut_ptr(), &mut pt2_len),
        CKR_OK
    );
    assert_eq!(pt2, zero);
    assert_eq!(C_MessageDecryptFinal(session), CKR_OK);
}
