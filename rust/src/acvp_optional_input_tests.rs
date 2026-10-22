//! Optional test inputs — the ACVP explicit-randomness model (plan
//! `acvp-explicit-randomness-model-plan-10212026.md`, revision 9; P1/P4) —
//! through the real `C_*` entry points.
//!
//! - **Shape 1** (M2): `CKM_ML_KEM` C_EncapsulateKey with `pParameter` = m.
//!   (`CKM_ECDSA` + k is in `ffi::ecdsa_k_shape1_ffi_tests`, composites in
//!   `composite_kem_tests` / `composite_sig_tests`.)
//! - **Shape 2** (M3): the extended `CK_SIGN_ADDITIONAL_CONTEXT` /
//!   `CK_HASH_SIGN_ADDITIONAL_CONTEXT` with `pRandom` (ML-DSA rnd, SLH-DSA
//!   addrnd) and `messageEncoding` (internal = FIPS 204 / 205 internal
//!   interface).
//!
//! NIST vectors: `kat/acvp-randomness/nist_optional_input.json`, made by
//! `kat/acvp-randomness/make_fixture.py` from the five upstream
//! ACVP-Server@975de31e internalProjection files (sha256-pinned there): every
//! one of the 81 unique groups the Hub skips for the five optional-input
//! reasons, with at least one case each (all 75 ML-KEM cases). The full 909
//! cases run with `PQC_ACVP_NIST_DIR=<dir with the five files> cargo test
//! --release acvp_optional_input_tests::full_nist -- --ignored`.
//!
//! Every ML-DSA internal group runs through the standard
//! `CKM_ML_DSA_EXTERNAL_MU` (owner decision D6, plan rev 10): µ =
//! SHAKE256(tr ‖ M′, 64), tr = SHAKE256(pk, 64), FIPS 204 Alg 7 line 6, with
//! rnd in the extended struct where the group is hedged. The internal
//! encoding is SLH-DSA only. SHA-512/224 and SHA-512/256 pre-hash cases go
//! through the generic CKM_HASH_ML_DSA / CKM_HASH_SLH_DSA (decision D5).
use crate::ck_param;
use crate::constants::*;
use crate::ffi::*;
use crate::native::test_lock;
use sha2::Digest;

/// CK_HEDGE_TYPE values (pkcs11t.h): CKH_HEDGE_PREFERRED.
const CKH_HEDGE_PREFERRED: u32 = 0;

const FIXTURE: &str = include_str!("../kat/acvp-randomness/nist_optional_input.json");

fn hx(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd-length hex");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

fn sha256(b: &[u8]) -> String {
    sha2::Sha256::digest(b).iter().map(|x| format!("{x:02x}")).collect()
}

fn setup() -> u32 {
    let _ = crate::native::session::finalize();
    crate::native::session::init().unwrap();
    crate::native::session::bootstrap_default_token(0, "so", "user", "optional-input").unwrap()
}

/// A `CK_MECHANISM` at this target's native layout pointing at `param`.
fn mechanism(mech: u32, param: &[u8]) -> Vec<u8> {
    let l = &ck_param::mechanism::LAYOUT;
    let mut b = vec![0u8; l.size()];
    let w = ck_param::WORD;
    let put = |b: &mut Vec<u8>, f: usize, v: usize| {
        let o = l.offset(f);
        b[o..o + w].copy_from_slice(&v.to_ne_bytes());
    };
    put(&mut b, ck_param::mechanism::MECHANISM, mech as usize);
    put(&mut b, ck_param::mechanism::P_PARAMETER, if param.is_empty() { 0 } else { param.as_ptr() as usize });
    put(&mut b, ck_param::mechanism::UL_PARAMETER_LEN, param.len());
    b
}

fn pack(l: &ck_param::Struct, vals: &[usize]) -> Vec<u8> {
    let mut b = vec![0u8; l.size()];
    let w = ck_param::WORD;
    for (i, v) in vals.iter().enumerate() {
        let o = l.offset(i);
        b[o..o + w].copy_from_slice(&v.to_ne_bytes());
    }
    b
}

fn p(v: &[u8]) -> usize {
    if v.is_empty() { 0 } else { v.as_ptr() as usize }
}

/// Standard `CK_SIGN_ADDITIONAL_CONTEXT`.
fn std_ctx(hedge: u32, ctx: &[u8]) -> Vec<u8> {
    pack(&ck_param::sign_ctx::LAYOUT, &[hedge as usize, p(ctx), ctx.len()])
}

/// Extended form: standard fields + pRandom, ulRandomLen, messageEncoding.
fn ext_ctx(hedge: u32, ctx: &[u8], random: &[u8], encoding: usize) -> Vec<u8> {
    pack(&ck_param::sign_ctx_ext::LAYOUT, &[hedge as usize, p(ctx), ctx.len(), p(random), random.len(), encoding])
}

/// Extended `CK_HASH_SIGN_ADDITIONAL_CONTEXT`.
fn ext_hash_ctx(hedge: u32, ctx: &[u8], hash: u32, random: &[u8], encoding: usize) -> Vec<u8> {
    pack(
        &ck_param::hash_sign_ctx_ext::LAYOUT,
        &[hedge as usize, p(ctx), ctx.len(), hash as usize, p(random), random.len(), encoding],
    )
}

fn ul(v: u32) -> Vec<u8> {
    (v as usize).to_ne_bytes().to_vec()
}

fn create(session: u32, attrs: &[(u32, Vec<u8>)]) -> u32 {
    let tmpl: Vec<usize> = attrs.iter().flat_map(|(t, v)| [*t as usize, v.as_ptr() as usize, v.len()]).collect();
    let mut h = 0u32;
    assert_eq!(C_CreateObject(session, tmpl.as_ptr() as *mut u8, attrs.len() as u32, &mut h), CKR_OK, "C_CreateObject");
    h
}

fn private_key(session: u32, kt: u32, ps: u32, sk: &[u8], sensitive: bool) -> u32 {
    create(
        session,
        &[
            (CKA_CLASS, ul(CKO_PRIVATE_KEY)),
            (CKA_KEY_TYPE, ul(kt)),
            (CKA_TOKEN, vec![0]),
            (CKA_SENSITIVE, vec![sensitive as u8]),
            (CKA_SIGN, vec![1]),
            (CKA_PARAMETER_SET, ul(ps)),
            (CKA_VALUE, sk.to_vec()),
        ],
    )
}

fn public_key(session: u32, kt: u32, ps: u32, pk: &[u8], usage: u32) -> u32 {
    create(
        session,
        &[
            (CKA_CLASS, ul(CKO_PUBLIC_KEY)),
            (CKA_KEY_TYPE, ul(kt)),
            (CKA_TOKEN, vec![0]),
            (usage, vec![1]),
            (CKA_PARAMETER_SET, ul(ps)),
            (CKA_VALUE, pk.to_vec()),
        ],
    )
}

fn sign_init(session: u32, mech: u32, param: &[u8], h: u32) -> u32 {
    let m = mechanism(mech, param);
    C_SignInit(session, m.as_ptr() as *mut u8, h)
}

fn verify_init(session: u32, mech: u32, param: &[u8], h: u32) -> u32 {
    let m = mechanism(mech, param);
    C_VerifyInit(session, m.as_ptr() as *mut u8, h)
}

fn sign(session: u32, mech: u32, param: &[u8], h: u32, msg: &[u8]) -> Result<Vec<u8>, u32> {
    let rv = sign_init(session, mech, param, h);
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

fn verify(session: u32, mech: u32, param: &[u8], h: u32, msg: &[u8], sig: &[u8]) -> u32 {
    let rv = verify_init(session, mech, param, h);
    if rv != CKR_OK {
        return rv;
    }
    C_Verify(session, msg.as_ptr() as *mut u8, msg.len() as u32, sig.as_ptr() as *mut u8, sig.len() as u32)
}

/// C_EncapsulateKey → (rv, ciphertext, shared secret).
fn encapsulate(session: u32, mech: u32, param: &[u8], h_pub: u32) -> (u32, Vec<u8>, Vec<u8>) {
    let m = mechanism(mech, param);
    let mut ct = vec![0u8; 4096];
    let mut ct_len = ct.len() as u32;
    let mut h = 0u32;
    let rv = C_EncapsulateKey(session, m.as_ptr() as *mut u8, h_pub, std::ptr::null_mut(), 0, ct.as_mut_ptr(), &mut ct_len, &mut h);
    if rv != CKR_OK {
        return (rv, vec![], vec![]);
    }
    ct.truncate(ct_len as usize);
    (rv, ct, crate::state::get_object_value(h).expect("ss"))
}

fn decapsulate(session: u32, mech: u32, param: &[u8], h_prv: u32, ct: &[u8]) -> (u32, Vec<u8>) {
    let m = mechanism(mech, param);
    let mut ct = ct.to_vec();
    let mut h = 0u32;
    let rv = C_DecapsulateKey(session, m.as_ptr() as *mut u8, h_prv, std::ptr::null_mut(), 0, ct.as_mut_ptr(), ct.len() as u32, &mut h);
    if rv != CKR_OK {
        return (rv, vec![]);
    }
    (rv, crate::state::get_object_value(h).expect("ss"))
}

fn ml_kem_ps(name: &str) -> u32 {
    match name {
        "ML-KEM-512" => CKP_ML_KEM_512,
        "ML-KEM-768" => CKP_ML_KEM_768,
        "ML-KEM-1024" => CKP_ML_KEM_1024,
        _ => panic!("{name}"),
    }
}

fn ml_dsa_ps(name: &str) -> u32 {
    match name {
        "ML-DSA-44" => CKP_ML_DSA_44,
        "ML-DSA-65" => CKP_ML_DSA_65,
        "ML-DSA-87" => CKP_ML_DSA_87,
        _ => panic!("{name}"),
    }
}

fn slh_dsa_ps(name: &str) -> u32 {
    match name {
        "SLH-DSA-SHA2-128s" => CKP_SLH_DSA_SHA2_128S,
        "SLH-DSA-SHAKE-128s" => CKP_SLH_DSA_SHAKE_128S,
        "SLH-DSA-SHA2-128f" => CKP_SLH_DSA_SHA2_128F,
        "SLH-DSA-SHAKE-128f" => CKP_SLH_DSA_SHAKE_128F,
        "SLH-DSA-SHA2-192s" => CKP_SLH_DSA_SHA2_192S,
        "SLH-DSA-SHAKE-192s" => CKP_SLH_DSA_SHAKE_192S,
        "SLH-DSA-SHA2-192f" => CKP_SLH_DSA_SHA2_192F,
        "SLH-DSA-SHAKE-192f" => CKP_SLH_DSA_SHAKE_192F,
        "SLH-DSA-SHA2-256s" => CKP_SLH_DSA_SHA2_256S,
        "SLH-DSA-SHAKE-256s" => CKP_SLH_DSA_SHAKE_256S,
        "SLH-DSA-SHA2-256f" => CKP_SLH_DSA_SHA2_256F,
        "SLH-DSA-SHAKE-256f" => CKP_SLH_DSA_SHAKE_256F,
        _ => panic!("{name}"),
    }
}

/// (hash-specific ML-DSA mech, hash-specific SLH-DSA mech, digest mech for
/// the generic form). SHAKE has no generic `hash` value; SHA-512/224 and
/// SHA-512/256 have no hash-specific mechanism and go through the generic
/// one only (owner decision D5).
fn prehash_mechs(hash_alg: &str) -> (Option<u32>, Option<u32>, Option<u32>) {
    match hash_alg {
        "SHA2-224" => (Some(CKM_HASH_ML_DSA_SHA224), Some(CKM_HASH_SLH_DSA_SHA224), Some(CKM_SHA224)),
        "SHA2-256" => (Some(CKM_HASH_ML_DSA_SHA256), Some(CKM_HASH_SLH_DSA_SHA256), Some(CKM_SHA256)),
        "SHA2-384" => (Some(CKM_HASH_ML_DSA_SHA384), Some(CKM_HASH_SLH_DSA_SHA384), Some(CKM_SHA384)),
        "SHA2-512" => (Some(CKM_HASH_ML_DSA_SHA512), Some(CKM_HASH_SLH_DSA_SHA512), Some(CKM_SHA512)),
        "SHA2-512/224" => (None, None, Some(CKM_SHA512_224)),
        "SHA2-512/256" => (None, None, Some(CKM_SHA512_256)),
        "SHA3-224" => (Some(CKM_HASH_ML_DSA_SHA3_224), Some(CKM_HASH_SLH_DSA_SHA3_224), Some(CKM_SHA3_224)),
        "SHA3-256" => (Some(CKM_HASH_ML_DSA_SHA3_256), Some(CKM_HASH_SLH_DSA_SHA3_256), Some(CKM_SHA3_256)),
        "SHA3-384" => (Some(CKM_HASH_ML_DSA_SHA3_384), Some(CKM_HASH_SLH_DSA_SHA3_384), Some(CKM_SHA3_384)),
        "SHA3-512" => (Some(CKM_HASH_ML_DSA_SHA3_512), Some(CKM_HASH_SLH_DSA_SHA3_512), Some(CKM_SHA3_512)),
        "SHAKE-128" => (Some(CKM_HASH_ML_DSA_SHAKE128), Some(CKM_HASH_SLH_DSA_SHAKE128), None),
        "SHAKE-256" => (Some(CKM_HASH_ML_DSA_SHAKE256), Some(CKM_HASH_SLH_DSA_SHAKE256), None),
        _ => panic!("{hash_alg}"),
    }
}

/// PH(M) for the generic pre-hash mechanisms (FIPS 204 Alg 4 / FIPS 205
/// Alg 23, SHA-2 / SHA-3 rows).
fn ph(hash_alg: &str, m: &[u8]) -> Vec<u8> {
    match hash_alg {
        "SHA2-224" => sha2::Sha224::digest(m).to_vec(),
        "SHA2-256" => sha2::Sha256::digest(m).to_vec(),
        "SHA2-384" => sha2::Sha384::digest(m).to_vec(),
        "SHA2-512" => sha2::Sha512::digest(m).to_vec(),
        "SHA2-512/224" => sha2::Sha512_224::digest(m).to_vec(),
        "SHA2-512/256" => sha2::Sha512_256::digest(m).to_vec(),
        "SHA3-224" => sha3::Sha3_224::digest(m).to_vec(),
        "SHA3-256" => sha3::Sha3_256::digest(m).to_vec(),
        "SHA3-384" => sha3::Sha3_384::digest(m).to_vec(),
        "SHA3-512" => sha3::Sha3_512::digest(m).to_vec(),
        _ => panic!("{hash_alg}"),
    }
}

fn shake256_64(parts: &[&[u8]]) -> Vec<u8> {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    let mut h = sha3::Shake256::default();
    for p in parts {
        h.update(p);
    }
    let mut out = vec![0u8; 64];
    h.finalize_xof().read(&mut out);
    out
}

/// µ = SHAKE256(SHAKE256(pk, 64) ‖ M′, 64) — FIPS 204 Alg 7 line 6, the
/// standard CKM_ML_DSA_EXTERNAL_MU route for the internal groups.
fn mu_of(pk: &[u8], m_prime: &[u8]) -> Vec<u8> {
    shake256_64(&[&shake256_64(&[pk]), m_prime])
}

fn s<'a>(v: &'a serde_json::Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or_else(|| panic!("field {k} missing"))
}

fn fixture() -> serde_json::Value {
    serde_json::from_str(FIXTURE).expect("fixture json")
}

fn file<'a>(doc: &'a serde_json::Value, src: &str) -> &'a serde_json::Value {
    doc["files"].as_array().unwrap().iter().find(|f| f["source"] == src).unwrap_or_else(|| panic!("{src}"))
}

/// One NIST sigGen case through the optional inputs. Returns the signature.
fn run_sig_gen(session: u32, algo: &str, g: &serde_json::Value, t: &serde_json::Value) -> Vec<u8> {
    let internal = g["signatureInterface"] == "internal";
    let prehash = g["preHash"] == "preHash";
    let det = g["deterministic"].as_bool().unwrap();
    let ext_mu = g["externalMu"].as_bool().unwrap_or(false);
    let sk = hx(s(t, "sk"));
    let pk = hx(s(t, "pk"));
    let ctx = t["context"].as_str().map(hx).unwrap_or_default();
    let rnd = t["rnd"].as_str().or(t["additionalRandomness"].as_str()).map(hx).unwrap_or_default();
    let hedge = if det { CKH_DETERMINISTIC_REQUIRED } else { CKH_HEDGE_PREFERRED };
    let tag = format!("{algo} tg{} tc{} ({})", g["tgId"], t["tcId"], g["parameterSet"]);
    let (kt, ps) = if algo == "ML-DSA" {
        (CKK_ML_DSA, ml_dsa_ps(s(g, "parameterSet")))
    } else {
        (CKK_SLH_DSA, slh_dsa_ps(s(g, "parameterSet")))
    };
    let hk = private_key(session, kt, ps, &sk, false);
    let hp = public_key(session, kt, ps, &pk, CKA_VERIFY);
    let pure = if algo == "ML-DSA" { CKM_ML_DSA } else { CKM_SLH_DSA };
    let sig = if ext_mu {
        // Hedged internal external-µ (plan revision 9, correction 3): rnd on
        // CKM_ML_DSA_EXTERNAL_MU, data = µ.
        let mu = hx(s(t, "mu"));
        let sig = sign(session, CKM_ML_DSA_EXTERNAL_MU, &ext_ctx(hedge, &[], &rnd, 0), hk, &mu).expect(&tag);
        assert_eq!(verify(session, CKM_ML_DSA_EXTERNAL_MU, &[], hp, &mu, &sig), CKR_OK, "{tag}: verifies");
        sig
    } else if internal && algo == "ML-DSA" {
        // Owner decision D6: the standard CKM_ML_DSA_EXTERNAL_MU route, µ =
        // SHAKE256(tr ‖ M′, 64) computed here; rnd only where hedged. The
        // internal encoding is refused for ML-DSA.
        let m = hx(s(t, "message"));
        assert_eq!(sign_init(session, CKM_ML_DSA, &ext_ctx(hedge, &[], &rnd, 1), hk), CKR_MECHANISM_PARAM_INVALID, "{tag}: D6");
        let mu = mu_of(&pk, &m);
        let param = if det { std_ctx(CKH_DETERMINISTIC_REQUIRED, &[]) } else { ext_ctx(hedge, &[], &rnd, 0) };
        let sig = sign(session, CKM_ML_DSA_EXTERNAL_MU, &param, hk, &mu).expect(&tag);
        assert_eq!(verify(session, CKM_ML_DSA_EXTERNAL_MU, &[], hp, &mu, &sig), CKR_OK, "{tag}: verifies");
        sig
    } else if internal {
        let m = hx(s(t, "message"));
        let sig = sign(session, pure, &ext_ctx(hedge, &[], &rnd, 1), hk, &m).expect(&tag);
        assert_eq!(verify(session, pure, &ext_ctx(CKH_HEDGE_PREFERRED, &[], &[], 1), hp, &m, &sig), CKR_OK, "{tag}: verifies (internal)");
        sig
    } else if prehash {
        let m = hx(s(t, "message"));
        let (mdsa, mslh, digest) = prehash_mechs(s(t, "hashAlg"));
        let specific = if algo == "ML-DSA" { mdsa } else { mslh };
        let mut sig = None;
        if let Some(mech) = specific {
            let s1 = sign(session, mech, &ext_ctx(hedge, &ctx, &rnd, 0), hk, &m).expect(&tag);
            assert_eq!(verify(session, mech, &std_ctx(0, &ctx), hp, &m, &s1), CKR_OK, "{tag}: verifies");
            sig = Some(s1);
        }
        if let Some(d) = digest {
            // The generic mechanism over PH(M), extended hash form (the only
            // route for SHA-512/224 and SHA-512/256, decision D5).
            let generic = if algo == "ML-DSA" { CKM_HASH_ML_DSA } else { CKM_HASH_SLH_DSA };
            let phm = ph(s(t, "hashAlg"), &m);
            let g2 = sign(session, generic, &ext_hash_ctx(hedge, &ctx, d, &rnd, 0), hk, &phm).expect(&tag);
            let vctx = ext_hash_ctx(0, &ctx, d, &[], 0);
            assert_eq!(verify(session, generic, &vctx, hp, &phm, &g2), CKR_OK, "{tag}: generic verifies");
            if let Some(s1) = &sig {
                assert_eq!(&g2, s1, "{tag}: generic CKM_HASH_* route");
            }
            sig = Some(g2);
        }
        sig.expect("a PKCS#11 route")
    } else {
        let m = hx(s(t, "message"));
        let sig = sign(session, pure, &ext_ctx(hedge, &ctx, &rnd, 0), hk, &m).expect(&tag);
        assert_eq!(verify(session, pure, &std_ctx(0, &ctx), hp, &m, &sig), CKR_OK, "{tag}: verifies");
        sig
    };
    assert_eq!(
        (sig.len(), sha256(&sig)),
        (t["signature_len"].as_u64().unwrap() as usize, s(t, "signature_sha256").to_string()),
        "{tag}: differs from NIST"
    );
    sig
}

/// One NIST sigVer internal case: SLH-DSA through messageEncoding =
/// internal, ML-DSA through the standard CKM_ML_DSA_EXTERNAL_MU (D6).
fn run_sig_ver(session: u32, algo: &str, g: &serde_json::Value, t: &serde_json::Value) {
    assert_eq!(g["signatureInterface"], "internal");
    let pk = hx(s(t, "pk"));
    let m = hx(s(t, "message"));
    let sig = hx(s(t, "signature"));
    let tag = format!("{algo} sigVer tg{} tc{} ({})", g["tgId"], t["tcId"], g["parameterSet"]);
    let (kt, ps, mech) = if algo == "ML-DSA" {
        (CKK_ML_DSA, ml_dsa_ps(s(g, "parameterSet")), CKM_ML_DSA)
    } else {
        (CKK_SLH_DSA, slh_dsa_ps(s(g, "parameterSet")), CKM_SLH_DSA)
    };
    let hp = public_key(session, kt, ps, &pk, CKA_VERIFY);
    let want_ok = t["testPassed"].as_bool().unwrap();
    let ok_codes = [CKR_SIGNATURE_INVALID, CKR_SIGNATURE_LEN_RANGE];
    let rv = if algo == "ML-DSA" {
        // Decision D6: the standard CKM_ML_DSA_EXTERNAL_MU route; the
        // internal encoding is refused for ML-DSA verification too.
        assert_eq!(verify_init(session, mech, &ext_ctx(0, &[], &[], 1), hp), CKR_MECHANISM_PARAM_INVALID, "{tag}: D6");
        verify(session, CKM_ML_DSA_EXTERNAL_MU, &[], hp, &mu_of(&pk, &m), &sig)
    } else {
        verify(session, mech, &ext_ctx(0, &[], &[], 1), hp, &m, &sig)
    };
    if want_ok {
        assert_eq!(rv, CKR_OK, "{tag}");
    } else {
        assert!(ok_codes.contains(&rv), "{tag}: rv 0x{rv:x} for an invalid signature ({})", t["reason"]);
    }
}

// ── NIST: every in-scope group ─────────────────────────────────────────────

#[test]
fn nist_ml_kem_encapsulation_with_supplied_m_all_cases() {
    let _guard = test_lock::acquire();
    let session = setup();
    let doc = fixture();
    let f = file(&doc, "ML-KEM-encapDecap-FIPS203");
    let (mut groups, mut cases) = (0, 0);
    for g in f["testGroups"].as_array().unwrap() {
        assert_eq!(g["function"], "encapsulation");
        let ps = ml_kem_ps(s(g, "parameterSet"));
        for t in g["tests"].as_array().unwrap() {
            let h = public_key(session, CKK_ML_KEM, ps, &hx(s(t, "ek")), CKA_ENCAPSULATE);
            let m = hx(s(t, "m"));
            let (rv, c, k) = encapsulate(session, CKM_ML_KEM, &m, h);
            assert_eq!(rv, CKR_OK);
            assert_eq!((c, k), (hx(s(t, "c")), hx(s(t, "k"))), "tg{} tc{}", g["tgId"], t["tcId"]);
            cases += 1;
        }
        groups += 1;
    }
    assert_eq!((groups, cases), (3, 75));
}

#[test]
fn nist_ml_dsa_sig_gen_every_group() {
    let _guard = test_lock::acquire();
    let session = setup();
    let doc = fixture();
    let f = file(&doc, "ML-DSA-sigGen-FIPS204");
    let mut n = 0;
    for g in f["testGroups"].as_array().unwrap() {
        for t in g["tests"].as_array().unwrap() {
            run_sig_gen(session, "ML-DSA", g, t);
        }
        n += 1;
    }
    assert_eq!(n, 15, "3 pure hedged + 3 pre-hash hedged + 6 internal hedged + 3 internal deterministic (all internal via external-µ)");
}

#[test]
fn nist_ml_dsa_sig_ver_internal_every_group() {
    let _guard = test_lock::acquire();
    let session = setup();
    let doc = fixture();
    let f = file(&doc, "ML-DSA-sigVer-FIPS204");
    let mut n = 0;
    for g in f["testGroups"].as_array().unwrap() {
        let tests = g["tests"].as_array().unwrap();
        assert!(tests.iter().any(|t| t["testPassed"] == true) && tests.iter().any(|t| t["testPassed"] == false));
        for t in tests {
            run_sig_ver(session, "ML-DSA", g, t);
        }
        n += 1;
    }
    assert_eq!(n, 3);
}

/// Run `f` on a thread with a large stack: the fips205 "s" parameter sets
/// keep whole hypertree layers on the stack, which overflows the default
/// test-thread stack in unoptimised builds.
fn big_stack(f: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new().stack_size(256 << 20).spawn(f).unwrap().join().unwrap();
}

#[test]
fn nist_slh_dsa_sig_gen_every_group() {
    let _guard = test_lock::acquire();
    big_stack(nist_slh_dsa_sig_gen_every_group_body);
}

fn nist_slh_dsa_sig_gen_every_group_body() {
    let session = setup();
    let doc = fixture();
    let f = file(&doc, "SLH-DSA-sigGen-FIPS205");
    let mut kinds = std::collections::BTreeMap::new();
    for g in f["testGroups"].as_array().unwrap() {
        for t in g["tests"].as_array().unwrap() {
            run_sig_gen(session, "SLH-DSA", g, t);
        }
        let kind = format!("{}/{}/{}", g["signatureInterface"], g["preHash"], g["deterministic"]);
        *kinds.entry(kind).or_insert(0) += 1;
    }
    let total: usize = kinds.values().sum();
    assert_eq!(total, 48, "{kinds:?}");
    assert_eq!(kinds.len(), 4, "pure hedged, pre-hash hedged, internal hedged, internal deterministic: {kinds:?}");
}

#[test]
fn nist_slh_dsa_sig_ver_internal_every_group() {
    let _guard = test_lock::acquire();
    let session = setup();
    let doc = fixture();
    let f = file(&doc, "SLH-DSA-sigVer-FIPS205");
    let mut n = 0;
    for g in f["testGroups"].as_array().unwrap() {
        for t in g["tests"].as_array().unwrap() {
            run_sig_ver(session, "SLH-DSA", g, t);
        }
        n += 1;
    }
    assert_eq!(n, 12);
}

/// All 909 cases of the 81 groups, from the upstream files (not committed:
/// ~84 MB). `PQC_ACVP_NIST_DIR` names a directory holding
/// `ML-KEM-encapDecap-FIPS203.json`, `ML-DSA-sigGen-FIPS204.json`,
/// `ML-DSA-sigVer-FIPS204.json`, `SLH-DSA-sigGen-FIPS205.json`,
/// `SLH-DSA-sigVer-FIPS205.json` (the internalProjection files). Only the
/// groups in the committed fixture run. Signatures are compared in full.
#[test]
#[ignore = "needs PQC_ACVP_NIST_DIR; run with --release"]
fn full_nist_all_cases_of_every_in_scope_group() {
    let _guard = test_lock::acquire();
    big_stack(full_nist_body);
}

fn full_nist_body() {
    let dir = std::env::var("PQC_ACVP_NIST_DIR").expect("PQC_ACVP_NIST_DIR");
    let session = setup();
    let doc = fixture();
    let mut total = 0usize;
    let mut groups = 0usize;
    for f in doc["files"].as_array().unwrap() {
        let src = s(f, "source");
        let raw = std::fs::read(format!("{dir}/{src}.json")).expect("upstream file");
        assert_eq!(sha256(&raw), s(f, "source_sha256"), "{src}: not the pinned upstream file");
        let up: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        let algo = if src.starts_with("ML-DSA") { "ML-DSA" } else { "SLH-DSA" };
        let before = total;
        for g in f["testGroups"].as_array().unwrap() {
            let ug = up["testGroups"].as_array().unwrap().iter().find(|u| u["tgId"] == g["tgId"]).unwrap();
            for t in ug["tests"].as_array().unwrap() {
                if src.starts_with("ML-KEM") {
                    let h = public_key(session, CKK_ML_KEM, ml_kem_ps(s(g, "parameterSet")), &hx(s(t, "ek")), CKA_ENCAPSULATE);
                    let (rv, c, k) = encapsulate(session, CKM_ML_KEM, &hx(s(t, "m")), h);
                    assert_eq!((rv, c, k), (CKR_OK, hx(s(t, "c")), hx(s(t, "k"))));
                } else if src.contains("sigGen") {
                    let mut tt = t.clone();
                    let sig = hx(s(t, "signature"));
                    tt["signature_sha256"] = serde_json::Value::String(sha256(&sig));
                    tt["signature_len"] = serde_json::Value::from(sig.len());
                    assert_eq!(run_sig_gen(session, algo, g, &tt), sig);
                } else {
                    run_sig_ver(session, algo, g, t);
                }
                total += 1;
            }
            groups += 1;
        }
        eprintln!("full NIST: {src}: {} groups, {} cases (cumulative {total})", f["testGroups"].as_array().unwrap().len(), total - before);
        crate::state::OBJECTS.with(|o| o.borrow_mut().clear());
    }
    eprintln!("full NIST: {groups} groups, {total} cases");
    assert_eq!((groups, total), (81, 909));
}

// ── Faults, sabotage, interoperation ───────────────────────────────────────

fn first_case<'a>(doc: &'a serde_json::Value, src: &str, pred: impl Fn(&serde_json::Value) -> bool) -> (&'a serde_json::Value, &'a serde_json::Value) {
    let g = file(doc, src)["testGroups"].as_array().unwrap().iter().find(|g| pred(g)).expect("group");
    (g, &g["tests"][0])
}

#[test]
fn sabotage_a_changed_value_or_expectation_fails() {
    let _guard = test_lock::acquire();
    let session = setup();
    let doc = fixture();
    // ML-KEM: one bit of m changes c and K.
    let (g, t) = first_case(&doc, "ML-KEM-encapDecap-FIPS203", |_| true);
    let h = public_key(session, CKK_ML_KEM, ml_kem_ps(s(g, "parameterSet")), &hx(s(t, "ek")), CKA_ENCAPSULATE);
    let mut m = hx(s(t, "m"));
    let (_, c, k) = encapsulate(session, CKM_ML_KEM, &m, h);
    assert_eq!(c, hx(s(t, "c")), "positive control");
    let mut flipped_c = c.clone();
    flipped_c[0] ^= 1;
    assert_ne!(flipped_c, hx(s(t, "c")), "a changed expected value is a mismatch");
    m[0] ^= 1;
    let (_, c2, k2) = encapsulate(session, CKM_ML_KEM, &m, h);
    assert_ne!(c2, c);
    assert_ne!(k2, k);
    // ML-DSA hedged pure: one bit of rnd changes the signature.
    let (g, t) = first_case(&doc, "ML-DSA-sigGen-FIPS204", |g| g["signatureInterface"] == "external" && g["preHash"] == "pure");
    let ps = ml_dsa_ps(s(g, "parameterSet"));
    let hk = private_key(session, CKK_ML_DSA, ps, &hx(s(t, "sk")), false);
    let (msg, ctx, mut rnd) = (hx(s(t, "message")), hx(s(t, "context")), hx(s(t, "rnd")));
    let good = sign(session, CKM_ML_DSA, &ext_ctx(0, &ctx, &rnd, 0), hk, &msg).unwrap();
    assert_eq!(sha256(&good), s(t, "signature_sha256"));
    rnd[31] ^= 0x80;
    let bad = sign(session, CKM_ML_DSA, &ext_ctx(0, &ctx, &rnd, 0), hk, &msg).unwrap();
    assert_ne!(sha256(&bad), s(t, "signature_sha256"));
    // SLH-DSA internal hedged: one bit of addrnd changes the signature.
    let (g, t) = first_case(&doc, "SLH-DSA-sigGen-FIPS205", |g| {
        g["signatureInterface"] == "internal" && g["deterministic"] == false && s(g, "parameterSet").ends_with('f')
    });
    let ps = slh_dsa_ps(s(g, "parameterSet"));
    let hk = private_key(session, CKK_SLH_DSA, ps, &hx(s(t, "sk")), false);
    let (msg, mut addrnd) = (hx(s(t, "message")), hx(s(t, "additionalRandomness")));
    let good = sign(session, CKM_SLH_DSA, &ext_ctx(0, &[], &addrnd, 1), hk, &msg).unwrap();
    assert_eq!(sha256(&good), s(t, "signature_sha256"));
    addrnd[0] ^= 1;
    let bad = sign(session, CKM_SLH_DSA, &ext_ctx(0, &[], &addrnd, 1), hk, &msg).unwrap();
    assert_ne!(sha256(&bad), s(t, "signature_sha256"));
}

#[test]
fn ml_kem_supplied_m_interoperates_and_decapsulate_refuses_a_parameter() {
    let _guard = test_lock::acquire();
    let session = setup();
    let mut mm: [usize; 3] = [CKM_ML_KEM_KEY_PAIR_GEN as usize, 0, 0];
    let ps = ul(CKP_ML_KEM_768);
    let pub_t: Vec<(u32, Vec<u8>)> = vec![(CKA_TOKEN, vec![0]), (CKA_ENCAPSULATE, vec![1]), (CKA_PARAMETER_SET, ps.clone())];
    let prv_t: Vec<(u32, Vec<u8>)> = vec![(CKA_TOKEN, vec![0]), (CKA_DECAPSULATE, vec![1])];
    let w = |a: &[(u32, Vec<u8>)]| a.iter().flat_map(|(t, v)| [*t as usize, v.as_ptr() as usize, v.len()]).collect::<Vec<usize>>();
    let (pw, sw) = (w(&pub_t), w(&prv_t));
    let (mut hp, mut hk) = (0u32, 0u32);
    assert_eq!(
        C_GenerateKeyPair(session, mm.as_mut_ptr() as *mut u8, pw.as_ptr() as *mut u8, 3, sw.as_ptr() as *mut u8, 2, &mut hp, &mut hk),
        CKR_OK
    );
    let m = [0x42u8; 32];
    let (rv, c1, k1) = encapsulate(session, CKM_ML_KEM, &m, hp);
    assert_eq!(rv, CKR_OK);
    let (_, c2, k2) = encapsulate(session, CKM_ML_KEM, &m, hp);
    assert_eq!((&c1, &k1), (&c2, &k2), "same m, same (c, K)");
    // The ciphertext is ordinary: standard decapsulation recovers K.
    assert_eq!(decapsulate(session, CKM_ML_KEM, &[], hk, &c1), (CKR_OK, k1.clone()));
    // Absent m: randomised exactly as before.
    let (_, c3, k3) = encapsulate(session, CKM_ML_KEM, &[], hp);
    let (_, c4, _) = encapsulate(session, CKM_ML_KEM, &[], hp);
    assert_ne!(c3, c4);
    assert_eq!(decapsulate(session, CKM_ML_KEM, &[], hk, &c3), (CKR_OK, k3));
    // A malformed m is refused before the session is looked up (C++ parity).
    let bad_m = [0u8; 31];
    let bm = mechanism(CKM_ML_KEM, &bad_m);
    let (mut l, mut hh) = (0u32, 0u32);
    assert_eq!(
        C_EncapsulateKey(0xdead_beef, bm.as_ptr() as *mut u8, hp, std::ptr::null_mut(), 0, std::ptr::null_mut(), &mut l, &mut hh),
        CKR_MECHANISM_PARAM_INVALID
    );
    // Wrong lengths, and a NULL pointer with a length.
    assert_eq!(encapsulate(session, CKM_ML_KEM, &[0u8; 31], hp).0, CKR_MECHANISM_PARAM_INVALID);
    assert_eq!(encapsulate(session, CKM_ML_KEM, &[0u8; 33], hp).0, CKR_MECHANISM_PARAM_INVALID);
    let mut raw: [usize; 3] = [CKM_ML_KEM as usize, 0, 32];
    let mut ct = vec![0u8; 2048];
    let mut ct_len = ct.len() as u32;
    let mut h = 0u32;
    assert_eq!(
        C_EncapsulateKey(session, raw.as_mut_ptr() as *mut u8, hp, std::ptr::null_mut(), 0, ct.as_mut_ptr(), &mut ct_len, &mut h),
        CKR_MECHANISM_PARAM_INVALID
    );
    // Decapsulation draws nothing: any parameter is refused (new behaviour,
    // plan revision 9 correction 2).
    assert_eq!(decapsulate(session, CKM_ML_KEM, &m, hk, &c1).0, CKR_MECHANISM_PARAM_INVALID);
    assert_eq!(decapsulate(session, CKM_ML_KEM, &[0u8; 1], hk, &c1).0, CKR_MECHANISM_PARAM_INVALID);
}

/// One ML-DSA-44 and one SLH-DSA-SHA2-128f key pair from the fixture, for the
/// refusal tests (sk, pk, ps).
fn keys(doc: &serde_json::Value) -> ((Vec<u8>, Vec<u8>, u32), (Vec<u8>, Vec<u8>, u32)) {
    let (g, t) = first_case(doc, "ML-DSA-sigGen-FIPS204", |g| g["parameterSet"] == "ML-DSA-44");
    let mldsa = (hx(s(t, "sk")), hx(s(t, "pk")), ml_dsa_ps(s(g, "parameterSet")));
    let (g, t) = first_case(doc, "SLH-DSA-sigGen-FIPS205", |g| g["parameterSet"] == "SLH-DSA-SHA2-128f");
    let slh = (hx(s(t, "sk")), hx(s(t, "pk")), slh_dsa_ps(s(g, "parameterSet")));
    (mldsa, slh)
}

#[test]
fn refusals_are_at_init_with_mechanism_param_invalid() {
    let _guard = test_lock::acquire();
    let session = setup();
    let doc = fixture();
    let ((dsk, dpk, dps), (ssk, spk, sps)) = keys(&doc);
    let hd = private_key(session, CKK_ML_DSA, dps, &dsk, false);
    let hdp = public_key(session, CKK_ML_DSA, dps, &dpk, CKA_VERIFY);
    let hs = private_key(session, CKK_SLH_DSA, sps, &ssk, false);
    let hsp = public_key(session, CKK_SLH_DSA, sps, &spk, CKA_VERIFY);
    let r32 = [7u8; 32];
    let r16 = [7u8; 16];
    let bad = |rv: u32, what: &str| assert_eq!(rv, CKR_MECHANISM_PARAM_INVALID, "{what}");
    let ok = |rv: u32, what: &str| assert_eq!(rv, CKR_OK, "{what}");
    let cancel = |sess: u32| {
        crate::state::SIGN_STATE.shard(sess).remove(&sess);
        crate::state::VERIFY_STATE.shard(sess).remove(&sess);
    };

    // Wrong random lengths (ML-DSA 32; SLH-DSA-128f n = 16).
    bad(sign_init(session, CKM_ML_DSA, &ext_ctx(0, &[], &r32[..31], 0), hd), "ML-DSA rnd 31");
    bad(sign_init(session, CKM_ML_DSA, &ext_ctx(0, &[], &[7u8; 33], 0), hd), "ML-DSA rnd 33");
    bad(sign_init(session, CKM_HASH_ML_DSA_SHA256, &ext_ctx(0, &[], &r16, 0), hd), "HashML-DSA rnd 16");
    bad(sign_init(session, CKM_ML_DSA_EXTERNAL_MU, &ext_ctx(0, &[], &r16, 0), hd), "external-µ rnd 16");
    bad(sign_init(session, CKM_SLH_DSA, &ext_ctx(0, &[], &r32, 0), hs), "SLH-DSA-128f addrnd 32");
    bad(sign_init(session, CKM_SLH_DSA, &ext_ctx(0, &[], &r16[..15], 0), hs), "SLH-DSA-128f addrnd 15");
    bad(sign_init(session, CKM_HASH_SLH_DSA, &ext_hash_ctx(0, &[], CKM_SHA256, &[7u8; 17], 0), hs), "generic addrnd 17");
    ok(sign_init(session, CKM_SLH_DSA, &ext_ctx(0, &[], &r16, 0), hs), "SLH-DSA-128f addrnd 16");
    cancel(session);
    ok(sign_init(session, CKM_HASH_ML_DSA, &ext_hash_ctx(1, &[], CKM_SHA256, &r32, 0), hd), "generic rnd 32, hedge required");
    cancel(session);

    // A supplied value with CKH_DETERMINISTIC_REQUIRED is a contradiction.
    bad(sign_init(session, CKM_ML_DSA, &ext_ctx(CKH_DETERMINISTIC_REQUIRED, &[], &r32, 0), hd), "det + rnd");
    bad(sign_init(session, CKM_SLH_DSA, &ext_ctx(CKH_DETERMINISTIC_REQUIRED, &[], &r16, 1), hs), "det + addrnd internal");
    bad(sign_init(session, CKM_ML_DSA_EXTERNAL_MU, &ext_ctx(CKH_DETERMINISTIC_REQUIRED, &[], &r32, 0), hd), "det + rnd external-µ");

    // A random value is not a verification input.
    bad(verify_init(session, CKM_ML_DSA, &ext_ctx(0, &[], &r32, 0), hdp), "verify + rnd");
    bad(verify_init(session, CKM_SLH_DSA, &ext_ctx(0, &[], &r16, 1), hsp), "verify internal + addrnd");
    let pr = ext_ctx(0, &[], &r32, 0);
    let m = mechanism(CKM_ML_DSA, &pr);
    let mut sig = vec![0u8; 2420];
    bad(C_VerifySignatureInit(session, m.as_ptr() as *mut u8, hdp, sig.as_mut_ptr(), sig.len() as u32), "VerifySignatureInit + rnd");

    // Internal encoding: pure CKM_ML_DSA / CKM_SLH_DSA only, empty context.
    bad(sign_init(session, CKM_HASH_ML_DSA_SHA256, &ext_ctx(0, &[], &[], 1), hd), "internal + HashML-DSA");
    bad(sign_init(session, CKM_HASH_SLH_DSA_SHA256, &ext_ctx(0, &[], &[], 1), hs), "internal + HashSLH-DSA");
    bad(sign_init(session, CKM_HASH_ML_DSA, &ext_hash_ctx(0, &[], CKM_SHA256, &[], 1), hd), "internal + generic HashML-DSA");
    bad(sign_init(session, CKM_ML_DSA_EXTERNAL_MU, &ext_ctx(0, &[], &[], 1), hd), "internal + external-µ");
    bad(sign_init(session, CKM_ML_DSA, &ext_ctx(0, b"ctx", &[], 1), hd), "internal + context");
    // Decision D6: no internal encoding for any ML-DSA mechanism.
    bad(sign_init(session, CKM_ML_DSA, &ext_ctx(0, &[], &[], 1), hd), "internal + CKM_ML_DSA");
    bad(sign_init(session, CKM_ML_DSA, &ext_ctx(CKH_DETERMINISTIC_REQUIRED, &[], &[], 1), hd), "internal deterministic + CKM_ML_DSA");
    bad(sign_init(session, CKM_ML_DSA, &ext_ctx(0, &[], &r32, 1), hd), "internal hedged rnd + CKM_ML_DSA");
    bad(verify_init(session, CKM_ML_DSA, &ext_ctx(0, &[], &[], 1), hdp), "verify internal + CKM_ML_DSA");
    bad(verify_init(session, CKM_SLH_DSA, &ext_ctx(0, b"c", &[], 1), hsp), "verify internal + context");
    bad(verify_init(session, CKM_HASH_SLH_DSA_SHA256, &ext_ctx(0, &[], &[], 1), hsp), "verify internal + HashSLH-DSA");
    bad(sign_init(session, CKM_ML_DSA, &ext_ctx(0, &[], &[], 2), hd), "messageEncoding 2");

    // The one size rule: standard or extended, nothing else (was: short read
    // as absent, long tail ignored).
    let std = std_ctx(0, &[]);
    let ext = ext_ctx(0, &[], &[], 0);
    let w = ck_param::WORD;
    let mut longer = ext.clone();
    longer.extend_from_slice(&vec![0u8; w]);
    for (param, what) in [
        (&std[..std.len() - 1], "standard - 1"),
        (&ext[..ext.len() - w], "extended - one word"),
        (&longer[..], "extended + one word"),
        (&std[..1], "one byte"),
    ] {
        bad(sign_init(session, CKM_ML_DSA, param, hd), what);
        bad(verify_init(session, CKM_SLH_DSA, param, hsp), what);
    }
    // pRandom NULL with a length, and a pointer with length 0.
    let nul = pack(&ck_param::sign_ctx_ext::LAYOUT, &[0, 0, 0, 0, 32, 0]);
    bad(sign_init(session, CKM_ML_DSA, &nul, hd), "pRandom NULL, ulRandomLen 32");
    let zero = pack(&ck_param::sign_ctx_ext::LAYOUT, &[0, 0, 0, p(&r32), 0, 0]);
    ok(sign_init(session, CKM_ML_DSA, &zero, hd), "pRandom set, ulRandomLen 0 = absent");
    cancel(session);
    bad(sign_init(session, CKM_ML_DSA, &ext_ctx(5, &[], &r32, 0), hd), "random + unknown hedge");

    // Message-based operations refuse single-operation inputs.
    let mr = mechanism(CKM_ML_DSA, &pr);
    bad(C_MessageSignInit(session, mr.as_ptr() as *mut u8, hd), "C_MessageSignInit + rnd");
    let pi = ext_ctx(0, &[], &[], 1);
    let mi = mechanism(CKM_ML_DSA, &pi);
    bad(C_MessageVerifyInit(session, mi.as_ptr() as *mut u8, hdp), "C_MessageVerifyInit + internal");
    // The extended form itself, even without inputs, on the message
    // interface (C++ parity, D2), and as a per-message parameter.
    let pe = ext_ctx(0, &[], &[], 0);
    let me = mechanism(CKM_ML_DSA, &pe);
    bad(C_MessageSignInit(session, me.as_ptr() as *mut u8, hd), "C_MessageSignInit, extended form");
    bad(C_MessageVerifyInit(session, me.as_ptr() as *mut u8, hdp), "C_MessageVerifyInit, extended form");
    let ms = mechanism(CKM_ML_DSA, &[]);
    ok(C_MessageSignInit(session, ms.as_ptr() as *mut u8, hd), "C_MessageSignInit, standard");
    let msg = b"m";
    let mut sig = vec![0u8; 2420];
    let mut sl = sig.len() as u32;
    bad(
        C_SignMessage(session, pe.as_ptr() as *mut u8, pe.len() as u32, msg.as_ptr() as *mut u8, 1, sig.as_mut_ptr(), &mut sl),
        "per-message extended form",
    );
    assert_eq!(C_MessageSignFinal(session), CKR_OK);
}

#[test]
fn absent_inputs_keep_standard_behaviour() {
    let _guard = test_lock::acquire();
    let session = setup();
    let doc = fixture();
    let ((dsk, dpk, dps), _) = keys(&doc);
    let hd = private_key(session, CKK_ML_DSA, dps, &dsk, false);
    let hdp = public_key(session, CKK_ML_DSA, dps, &dpk, CKA_VERIFY);
    let msg = b"standard behaviour";
    // Hedged, absent or via the extended form with no random: randomised.
    let a = sign(session, CKM_ML_DSA, &[], hd, msg).unwrap();
    let b = sign(session, CKM_ML_DSA, &ext_ctx(0, &[], &[], 0), hd, msg).unwrap();
    assert_ne!(a, b);
    // Deterministic: standard and extended forms agree byte for byte.
    let c = sign(session, CKM_ML_DSA, &std_ctx(CKH_DETERMINISTIC_REQUIRED, b"x"), hd, msg).unwrap();
    let d = sign(session, CKM_ML_DSA, &ext_ctx(CKH_DETERMINISTIC_REQUIRED, b"x", &[], 0), hd, msg).unwrap();
    assert_eq!(c, d);
    // rnd = {0}^32 supplied is FIPS 204's deterministic variant (Alg 2 line 5).
    let e = sign(session, CKM_ML_DSA, &ext_ctx(0, b"x", &[0u8; 32], 0), hd, msg).unwrap();
    assert_eq!(e, c);
    for sig in [&a, &b, &c, &e] {
        assert_eq!(verify(session, CKM_ML_DSA, &std_ctx(0, if sig == &a || sig == &b { b"" } else { b"x" }), hdp, msg, sig), CKR_OK);
    }
    // A supplied value does not leak into the next operation.
    let r = [9u8; 32];
    let f1 = sign(session, CKM_ML_DSA, &ext_ctx(0, &[], &r, 0), hd, msg).unwrap();
    let f2 = sign(session, CKM_ML_DSA, &[], hd, msg).unwrap();
    let f3 = sign(session, CKM_ML_DSA, &ext_ctx(0, &[], &r, 0), hd, msg).unwrap();
    assert_eq!(f1, f3);
    assert_ne!(f1, f2);
    assert!(crate::state::SIGN_SUPPLIED.shard(session).get(&session).is_none(), "consumed by C_Sign");
}

/// Invalid internal signatures are rejected with the expected codes, and the
/// internal and external encodings do not verify each other's signatures.
#[test]
fn internal_encoding_rejects_invalid_signatures() {
    let _guard = test_lock::acquire();
    let session = setup();
    let doc = fixture();
    let ((dsk, dpk, dps), (ssk, spk, sps)) = keys(&doc);
    // Decision D6: ML-DSA refuses the internal encoding on every Init.
    let hdk = private_key(session, CKK_ML_DSA, dps, &dsk, false);
    let hdp = public_key(session, CKK_ML_DSA, dps, &dpk, CKA_VERIFY);
    let int = ext_ctx(0, &[], &[], 1);
    assert_eq!(sign_init(session, CKM_ML_DSA, &int, hdk), CKR_MECHANISM_PARAM_INVALID);
    assert_eq!(verify_init(session, CKM_ML_DSA, &int, hdp), CKR_MECHANISM_PARAM_INVALID);
    let mi = mechanism(CKM_ML_DSA, &int);
    let mut sg = vec![0u8; 2420];
    assert_eq!(C_VerifySignatureInit(session, mi.as_ptr() as *mut u8, hdp, sg.as_mut_ptr(), sg.len() as u32), CKR_MECHANISM_PARAM_INVALID);
    for (kt, ps, sk, pk, mech) in [(CKK_SLH_DSA, sps, &ssk, &spk, CKM_SLH_DSA)] {
        let hk = private_key(session, kt, ps, sk, false);
        let hp = public_key(session, kt, ps, pk, CKA_VERIFY);
        let m = b"M-prime as given";
        let internal = ext_ctx(0, &[], &[], 1);
        let sig = sign(session, mech, &internal, hk, m).unwrap();
        assert_eq!(verify(session, mech, &internal, hp, m, &sig), CKR_OK);
        let mut t = sig.clone();
        t[10] ^= 1;
        assert_eq!(verify(session, mech, &internal, hp, m, &t), CKR_SIGNATURE_INVALID);
        assert_eq!(verify(session, mech, &internal, hp, m, &sig[..sig.len() - 1]), CKR_SIGNATURE_LEN_RANGE);
        let mut short = sig[..sig.len() - 1].to_vec();
        assert_eq!(C_VerifySignatureInit(session, mechanism(mech, &internal).as_ptr() as *mut u8, hp, short.as_mut_ptr(), short.len() as u32), CKR_OK);
        assert_eq!(C_VerifySignature(session, m.as_ptr() as *mut u8, m.len() as u32), CKR_SIGNATURE_LEN_RANGE, "C_VerifySignature, wrong length");
        let mut short2 = sig[..sig.len() - 1].to_vec();
        assert_eq!(C_VerifySignatureInit(session, mechanism(mech, &[]).as_ptr() as *mut u8, hp, short2.as_mut_ptr(), short2.len() as u32), CKR_OK);
        assert_eq!(C_VerifySignature(session, m.as_ptr() as *mut u8, m.len() as u32), CKR_SIGNATURE_LEN_RANGE, "standard C_VerifySignature, wrong length");
        assert_eq!(verify(session, mech, &[], hp, m, &sig[..sig.len() - 1]), CKR_SIGNATURE_LEN_RANGE, "standard C_Verify, wrong length");
        assert_eq!(verify(session, mech, &internal, hp, b"another M-prime", &sig), CKR_SIGNATURE_INVALID);
        // Not an external-interface signature over the same bytes.
        assert_eq!(verify(session, mech, &[], hp, m, &sig), CKR_SIGNATURE_INVALID);
        let ext = sign(session, mech, &[], hk, m).unwrap();
        assert_eq!(verify(session, mech, &internal, hp, m, &ext), CKR_SIGNATURE_INVALID);
        // C_VerifySignatureInit carries the encoding too.
        let mi = mechanism(mech, &internal);
        let mut s2 = sig.clone();
        assert_eq!(C_VerifySignatureInit(session, mi.as_ptr() as *mut u8, hp, s2.as_mut_ptr(), s2.len() as u32), CKR_OK);
        assert_eq!(C_VerifySignature(session, m.as_ptr() as *mut u8, m.len() as u32), CKR_OK);
        assert_eq!(C_VerifySignatureInit(session, mi.as_ptr() as *mut u8, hp, t.as_mut_ptr(), t.len() as u32), CKR_OK);
        assert_eq!(C_VerifySignature(session, m.as_ptr() as *mut u8, m.len() as u32), CKR_SIGNATURE_INVALID);
    }
}

/// Decision D0 = (a): no guard. A chosen value works with sensitive and
/// non-sensitive keys alike — pinned, so a guard cannot be added by accident.
#[test]
fn d0a_no_guard_sensitive_and_non_sensitive_keys() {
    let _guard = test_lock::acquire();
    let session = setup();
    let doc = fixture();
    let ((dsk, _, dps), (ssk, _, sps)) = keys(&doc);
    let r32 = [3u8; 32];
    let r16 = [3u8; 16];
    let msg = b"no guard";
    let mut out = vec![];
    for sensitive in [true, false] {
        let hd = private_key(session, CKK_ML_DSA, dps, &dsk, sensitive);
        let hs = private_key(session, CKK_SLH_DSA, sps, &ssk, sensitive);
        let a = sign(session, CKM_ML_DSA, &ext_ctx(0, &[], &r32, 0), hd, msg).expect("ML-DSA rnd");
        let b = sign(session, CKM_SLH_DSA, &ext_ctx(0, &[], &r16, 1), hs, msg).expect("SLH-DSA addrnd");
        out.push((a, b));
    }
    assert_eq!(out[0], out[1], "same value, same signature, whatever CKA_SENSITIVE says");
    // ML-KEM m on a public key needs no sensitivity rule; ECDSA k is in
    // ffi::ecdsa_k_shape1_ffi_tests (imported with CKA_SENSITIVE unset).
}

/// Owner decision D5: the generic CKM_HASH_ML_DSA / CKM_HASH_SLH_DSA take
/// hash = CKM_SHA512_224 / CKM_SHA512_256. OID correctness is checked
/// independently: M′ = 0x01 ‖ len(ctx) ‖ ctx ‖ OID ‖ PH(M) is built here
/// with the FIPS 204 / 205 OID (2.16.840.1.101.3.4.2.5 / .6) and signed
/// through the standard route (ML-DSA: CKM_ML_DSA_EXTERNAL_MU over µ;
/// SLH-DSA: the internal encoding), deterministically, and must equal the
/// generic mechanism's deterministic signature. Sabotage: the neighbouring
/// OID gives a different signature, and a changed PH(M) does not verify.
#[test]
fn d5_sha512_t_generic_prehash_oid_and_sabotage() {
    let _guard = test_lock::acquire();
    let session = setup();
    let doc = fixture();
    let ((dsk, dpk, dps), (ssk, spk, sps)) = keys(&doc);
    let hd = private_key(session, CKK_ML_DSA, dps, &dsk, false);
    let hdp = public_key(session, CKK_ML_DSA, dps, &dpk, CKA_VERIFY);
    let hs = private_key(session, CKK_SLH_DSA, sps, &ssk, false);
    let hsp = public_key(session, CKK_SLH_DSA, sps, &spk, CKA_VERIFY);
    let msg = b"pre-hashed with SHA-512/t";
    let ctx = b"ctx";
    for (alg, digest, last) in [("SHA2-512/224", CKM_SHA512_224, 0x05u8), ("SHA2-512/256", CKM_SHA512_256, 0x06u8)] {
        let phm = ph(alg, msg);
        let m_prime = |oid_last: u8| {
            let mut v = vec![1u8, ctx.len() as u8];
            v.extend_from_slice(ctx);
            v.extend_from_slice(&[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, oid_last]);
            v.extend_from_slice(&phm);
            v
        };
        let det = ext_hash_ctx(CKH_DETERMINISTIC_REQUIRED, ctx, digest, &[], 0);
        // ML-DSA
        let g = sign(session, CKM_HASH_ML_DSA, &det, hd, &phm).expect(alg);
        let want = sign(session, CKM_ML_DSA_EXTERNAL_MU, &std_ctx(CKH_DETERMINISTIC_REQUIRED, &[]), hd, &mu_of(&dpk, &m_prime(last))).unwrap();
        assert_eq!(g, want, "ML-DSA {alg}: OID in M'");
        let wrong = sign(session, CKM_ML_DSA_EXTERNAL_MU, &std_ctx(CKH_DETERMINISTIC_REQUIRED, &[]), hd, &mu_of(&dpk, &m_prime(last ^ 3))).unwrap();
        assert_ne!(g, wrong, "ML-DSA {alg}: the OID matters");
        assert_eq!(verify(session, CKM_HASH_ML_DSA, &det, hdp, &phm, &g), CKR_OK);
        let mut bad = phm.clone();
        bad[0] ^= 1;
        assert_eq!(verify(session, CKM_HASH_ML_DSA, &det, hdp, &bad, &g), CKR_SIGNATURE_INVALID);

        // SLH-DSA
        let g = sign(session, CKM_HASH_SLH_DSA, &det, hs, &phm).expect(alg);
        let want = sign(session, CKM_SLH_DSA, &ext_ctx(CKH_DETERMINISTIC_REQUIRED, &[], &[], 1), hs, &m_prime(last)).unwrap();
        assert_eq!(g, want, "SLH-DSA {alg}: OID in M'");
        let wrong = sign(session, CKM_SLH_DSA, &ext_ctx(CKH_DETERMINISTIC_REQUIRED, &[], &[], 1), hs, &m_prime(last ^ 3)).unwrap();
        assert_ne!(g, wrong, "SLH-DSA {alg}: the OID matters");
        assert_eq!(verify(session, CKM_HASH_SLH_DSA, &det, hsp, &phm, &g), CKR_OK);
        assert_eq!(verify(session, CKM_HASH_SLH_DSA, &det, hsp, &bad, &g), CKR_SIGNATURE_INVALID);
    }
}

/// Owner decision D7: a PH(M) whose length is not the digest length of
/// `hash` is CKR_DATA_LEN_RANGE on C_Sign and C_Verify of the generic
/// CKM_HASH_ML_DSA / CKM_HASH_SLH_DSA (v3.3 "Key and Data Length" tables),
/// for every family and several hashes including SHA-512/224. With or
/// without a supplied rnd / addrnd.
#[test]
fn d7_wrong_phm_length_is_data_len_range() {
    let _guard = test_lock::acquire();
    let session = setup();
    let doc = fixture();
    let ((dsk, dpk, dps), (ssk, spk, sps)) = keys(&doc);
    let hd = private_key(session, CKK_ML_DSA, dps, &dsk, false);
    let hdp = public_key(session, CKK_ML_DSA, dps, &dpk, CKA_VERIFY);
    let hs = private_key(session, CKK_SLH_DSA, sps, &ssk, false);
    let hsp = public_key(session, CKK_SLH_DSA, sps, &spk, CKA_VERIFY);
    for (alg, digest) in [("SHA2-512/224", CKM_SHA512_224), ("SHA2-256", CKM_SHA256), ("SHA3-512", CKM_SHA3_512)] {
        let phm = ph(alg, b"m");
        let std = ext_hash_ctx(0, &[], digest, &[], 0);
        for (generic, hk, hp, rlen) in [(CKM_HASH_ML_DSA, hd, hdp, 32usize), (CKM_HASH_SLH_DSA, hs, hsp, 16)] {
            let good = sign(session, generic, &std, hk, &phm).expect(alg);
            let rnd = vec![5u8; rlen];
            let with_rnd = ext_hash_ctx(0, &[], digest, &rnd, 0);
            for bad in [&phm[..phm.len() - 1], &[phm.clone(), vec![0]].concat()[..], &[0u8; 64][..]] {
                if bad.len() == phm.len() {
                    continue;
                }
                assert_eq!(sign(session, generic, &std, hk, bad).unwrap_err(), CKR_DATA_LEN_RANGE, "{alg} 0x{generic:x} sign len {}", bad.len());
                assert_eq!(sign(session, generic, &with_rnd, hk, bad).unwrap_err(), CKR_DATA_LEN_RANGE, "{alg} sign+rnd len {}", bad.len());
                assert_eq!(verify(session, generic, &std, hp, bad, &good), CKR_DATA_LEN_RANGE, "{alg} 0x{generic:x} verify len {}", bad.len());
            }
            assert_eq!(verify(session, generic, &std, hp, &phm, &good), CKR_OK, "{alg}");
        }
    }
}
