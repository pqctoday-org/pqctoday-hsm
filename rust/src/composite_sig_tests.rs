// SPDX-License-Identifier: AGPL-3.0-only
//
//! Composite ML-DSA through the PKCS#11 boundary — PKCS#11 v3.3 working draft
//! (`comp_sig.md`, OASIS PKCS 11 TC commit 9ef73f9) over
//! draft-ietf-lamps-pq-composite-sigs-19. Plan workstream A4 and the
//! signature halves of V3 (vector consistency) and V6 (derived negative
//! vectors).
//!
//! Vectors: `rust/kat/pkcs11-v33/composite-sig/testvectors.json`, the LAMPS
//! upstream file (provenance: `rust/kat/pkcs11-v33/PROVENANCE.md`; its
//! sha256 is pinned by `native::composite_vectors`): per set `pk`, `sk`
//! (mldsaSeed ‖ tradSK), `s` (over the shared `m`, empty ctx) and
//! `sWithContext` (over `m` with the shared `ctx`). Signing is randomised
//! (hedged ML-DSA, PSS salts), so the vectors prove verification exactly;
//! signing is proven by round trip, by our signature verifying under the
//! vector's own `pk`, and by the V3 checker below accepting our output.
//!
//! The V3 checker is written from the draft text alone and uses only the
//! engine's single-algorithm verifiers — nothing from
//! `native::composite_sig` — so a fault in the composite code cannot hide in
//! both.
//!
//! Included from `ffi.rs` via `#[path]` so `use super::*` resolves to the FFI
//! module and its private helpers, like `composite_kem_tests`.

use super::*;
use crate::native::composite::{
    kem_params, sig_params, CompositeSigParams, COMPOSITE_KEM_SETS, COMPOSITE_SIG_SETS,
};
use crate::native::composite_vectors::{b64, SIG_VECTORS};
use crate::native::test_lock;
use serde_json::Value;

/// High fixed session handle, disjoint from every other ffi test module.
const SESSION: u32 = 0x4D50_4C02;

/// `CKH_HEDGE_PREFERRED` (pkcs11t.h: 0x00000000UL), the default hedge
/// variant; the engine names only CKH_DETERMINISTIC_REQUIRED.
const CKH_HEDGE_PREFERRED: u32 = 0;

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

// ── Vectors ──────────────────────────────────────────────────────────────

/// One composite LAMPS signature vector, decoded.
struct Vector {
    p: &'static CompositeSigParams,
    tc_id: String,
    pk: Vec<u8>,
    sk: Vec<u8>,
    s: Vec<u8>,
    s_ctx: Vec<u8>,
}

struct Doc {
    m: Vec<u8>,
    ctx: Vec<u8>,
    vectors: Vec<Vector>,
}

fn doc() -> Doc {
    let d: Value = serde_json::from_slice(SIG_VECTORS).expect("vector file parses");
    let tests = d["tests"].as_array().unwrap();
    let field = |e: &Value, f: &str| b64(e[f].as_str().unwrap_or_else(|| panic!("field {f}")));
    let vectors = COMPOSITE_SIG_SETS
        .iter()
        .map(|p| {
            let e = tests.iter().find(|e| e["tcId"] == p.name).unwrap_or_else(|| panic!("no vector {}", p.name));
            Vector {
                p,
                tc_id: p.name.to_string(),
                pk: field(e, "pk"),
                sk: field(e, "sk"),
                s: field(e, "s"),
                s_ctx: field(e, "sWithContext"),
            }
        })
        .collect();
    Doc { m: b64(d["m"].as_str().unwrap()), ctx: b64(d["ctx"].as_str().unwrap()), vectors }
}

// ── PKCS#11 plumbing ──────────────────────────────────────────────────────

/// CK_ULONG-width little-endian bytes (what an LP64 caller sends).
fn ulong(v: u32) -> Vec<u8> {
    (v as usize).to_le_bytes().to_vec()
}

fn words(entries: &[(u32, Vec<u8>)]) -> Vec<usize> {
    let mut w = Vec::with_capacity(entries.len() * 3);
    for (t, v) in entries {
        w.push(*t as usize);
        w.push(v.as_ptr() as usize);
        w.push(v.len());
    }
    w
}

fn create(entries: Vec<(u32, Vec<u8>)>) -> (u32, u32) {
    let mut w = words(&entries);
    let mut h: u32 = 0;
    let rv = C_CreateObject(SESSION, w.as_mut_ptr() as *mut u8, entries.len() as u32, &mut h);
    (rv, h)
}

fn import_public(ckp: u32, pk: &[u8]) -> (u32, u32) {
    create(vec![
        (CKA_CLASS, ulong(CKO_PUBLIC_KEY)),
        (CKA_KEY_TYPE, ulong(CKK_COMP_SIG)),
        (CKA_PARAMETER_SET, ulong(ckp)),
        (CKA_VERIFY, vec![1]),
        (CKA_TOKEN, vec![0]),
        (CKA_VALUE, pk.to_vec()),
    ])
}

fn import_private(ckp: u32, sk: &[u8]) -> (u32, u32) {
    create(vec![
        (CKA_CLASS, ulong(CKO_PRIVATE_KEY)),
        (CKA_KEY_TYPE, ulong(CKK_COMP_SIG)),
        (CKA_PARAMETER_SET, ulong(ckp)),
        (CKA_SIGN, vec![1]),
        (CKA_SENSITIVE, vec![1]),
        (CKA_EXTRACTABLE, vec![0]),
        (CKA_TOKEN, vec![0]),
        (CKA_PRIVATE, vec![0]),
        (CKA_VALUE, sk.to_vec()),
    ])
}

fn generate(mech: u32, pub_t: Vec<(u32, Vec<u8>)>, prv_t: Vec<(u32, Vec<u8>)>) -> (u32, u32, u32) {
    let mut m: [usize; 3] = [mech as usize, 0, 0];
    let mut pw = words(&pub_t);
    let mut kw = words(&prv_t);
    let (mut hp, mut hk) = (0u32, 0u32);
    let rv = C_GenerateKeyPair(
        SESSION,
        m.as_mut_ptr() as *mut u8,
        pw.as_mut_ptr() as *mut u8,
        pub_t.len() as u32,
        kw.as_mut_ptr() as *mut u8,
        prv_t.len() as u32,
        &mut hp,
        &mut hk,
    );
    (rv, hp, hk)
}

fn generate_comp_sig(ckp: u32) -> (u32, u32, u32) {
    generate(CKM_COMP_SIG_KEY_PAIR_GEN, vec![(CKA_PARAMETER_SET, ulong(ckp))], vec![(CKA_PRIVATE, vec![0])])
}

fn value(h: u32) -> Vec<u8> {
    crate::state::get_object_value(h).expect("object has CKA_VALUE")
}

fn destroy(hs: &[u32]) {
    for &h in hs {
        if h != 0 {
            OBJECTS.with(|o| o.borrow_mut().remove(&h));
        }
    }
}

/// A `CK_SIGN_ADDITIONAL_CONTEXT` (hedgeVariant, pContext, ulContextLen at
/// native width; ml_dsa.md).
struct SignCtx {
    words: [usize; 3],
    _ctx: Vec<u8>,
}

fn sign_ctx(hedge: u32, ctx: &[u8]) -> SignCtx {
    let c = ctx.to_vec();
    let p = if c.is_empty() { 0 } else { c.as_ptr() as usize };
    SignCtx { words: [hedge as usize, p, c.len()], _ctx: c }
}

/// `CK_MECHANISM` words, with the parameter when given.
fn mech(m: u32, param: Option<&SignCtx>) -> [usize; 3] {
    match param {
        Some(p) => [m as usize, p.words.as_ptr() as usize, std::mem::size_of_val(&p.words)],
        None => [m as usize, 0, 0],
    }
}

fn sign_init(m: u32, param: Option<&SignCtx>, hk: u32) -> u32 {
    let mut mm = mech(m, param);
    C_SignInit(SESSION, mm.as_mut_ptr() as *mut u8, hk)
}

fn verify_init(m: u32, param: Option<&SignCtx>, hp: u32) -> u32 {
    let mut mm = mech(m, param);
    C_VerifyInit(SESSION, mm.as_mut_ptr() as *mut u8, hp)
}

/// C_SignInit + the two-call C_Sign → (rv, signature).
fn sign(m: u32, param: Option<&SignCtx>, hk: u32, data: &[u8]) -> (u32, Vec<u8>) {
    let rv = sign_init(m, param, hk);
    if rv != CKR_OK {
        return (rv, Vec::new());
    }
    let mut d = data.to_vec();
    let mut len = 0u32;
    assert_eq!(C_Sign(SESSION, d.as_mut_ptr(), d.len() as u32, std::ptr::null_mut(), &mut len), CKR_OK);
    let mut sig = vec![0u8; len as usize];
    let rv = C_Sign(SESSION, d.as_mut_ptr(), d.len() as u32, sig.as_mut_ptr(), &mut len);
    sig.truncate(len as usize);
    (rv, sig)
}

/// C_SignInit + C_SignUpdate per chunk + the two-call C_SignFinal.
fn sign_multi(m: u32, param: Option<&SignCtx>, hk: u32, data: &[u8], chunk: usize) -> (u32, Vec<u8>) {
    let rv = sign_init(m, param, hk);
    if rv != CKR_OK {
        return (rv, Vec::new());
    }
    for part in data.chunks(chunk) {
        let mut part = part.to_vec();
        let rv = C_SignUpdate(SESSION, part.as_mut_ptr(), part.len() as u32);
        if rv != CKR_OK {
            return (rv, Vec::new());
        }
    }
    let mut len = 0u32;
    assert_eq!(C_SignFinal(SESSION, std::ptr::null_mut(), &mut len), CKR_OK);
    let mut sig = vec![0u8; len as usize];
    let rv = C_SignFinal(SESSION, sig.as_mut_ptr(), &mut len);
    sig.truncate(len as usize);
    (rv, sig)
}

fn verify(m: u32, param: Option<&SignCtx>, hp: u32, data: &[u8], sig: &[u8]) -> u32 {
    let rv = verify_init(m, param, hp);
    if rv != CKR_OK {
        return rv;
    }
    let (mut d, mut s) = (data.to_vec(), sig.to_vec());
    C_Verify(SESSION, d.as_mut_ptr(), d.len() as u32, s.as_mut_ptr(), s.len() as u32)
}

fn verify_multi(m: u32, param: Option<&SignCtx>, hp: u32, data: &[u8], chunk: usize, sig: &[u8]) -> u32 {
    let rv = verify_init(m, param, hp);
    if rv != CKR_OK {
        return rv;
    }
    for part in data.chunks(chunk) {
        let mut part = part.to_vec();
        let rv = C_VerifyUpdate(SESSION, part.as_mut_ptr(), part.len() as u32);
        if rv != CKR_OK {
            return rv;
        }
    }
    let mut s = sig.to_vec();
    C_VerifyFinal(SESSION, s.as_mut_ptr(), s.len() as u32)
}

/// PKCS#11 v3.2 C_VerifySignatureInit with the signature bound up front;
/// `chunk` None = single-part C_VerifySignature, Some = Update/Final.
fn verify_signature(m: u32, param: Option<&SignCtx>, hp: u32, data: &[u8], chunk: Option<usize>, sig: &[u8]) -> u32 {
    let mut mm = mech(m, param);
    let mut s = sig.to_vec();
    let rv = C_VerifySignatureInit(SESSION, mm.as_mut_ptr() as *mut u8, hp, s.as_mut_ptr(), s.len() as u32);
    if rv != CKR_OK {
        return rv;
    }
    match chunk {
        None => {
            let mut d = data.to_vec();
            C_VerifySignature(SESSION, d.as_mut_ptr(), d.len() as u32)
        }
        Some(n) => {
            for part in data.chunks(n) {
                let mut part = part.to_vec();
                let rv = C_VerifySignatureUpdate(SESSION, part.as_mut_ptr(), part.len() as u32);
                if rv != CKR_OK {
                    return rv;
                }
            }
            C_VerifySignatureFinal(SESSION)
        }
    }
}

// ── The draft, written out independently of native::composite_sig ────────

/// ML-DSA level from the algorithm name: "MLDSA44" / "MLDSA65" / "MLDSA87".
fn ml_level(tc_id: &str) -> (u32, usize, usize) {
    // (CKP, public key, signature) — draft §4 Table 1.
    if tc_id.contains("MLDSA44") {
        (CKP_ML_DSA_44, 1312, 2420)
    } else if tc_id.contains("MLDSA65") {
        (CKP_ML_DSA_65, 1952, 3309)
    } else {
        assert!(tc_id.contains("MLDSA87"), "{tc_id}");
        (CKP_ML_DSA_87, 2592, 4627)
    }
}

/// `Label` (§6): "COMPSIG-" followed by the identifier name without "id-",
/// except that the two brainpool labels abbreviate the curve
/// ("COMPSIG-MLDSA65-ECDSA-BP256-SHA512", "COMPSIG-MLDSA87-ECDSA-BP384-SHA512").
fn draft_label(tc_id: &str) -> Vec<u8> {
    let name = tc_id.strip_prefix("id-").unwrap().replace("brainpoolP256r1", "BP256").replace("brainpoolP384r1", "BP384");
    format!("COMPSIG-{name}").into_bytes()
}

/// PH(M) per the name's suffix (§6 "Pre-Hash function"), SHAKE256 with 64
/// bytes of output (§6 note "**").
fn draft_ph(tc_id: &str, m: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    if tc_id.ends_with("-SHA256") {
        sha2::Sha256::digest(m).to_vec()
    } else if tc_id.ends_with("-SHA512") {
        sha2::Sha512::digest(m).to_vec()
    } else {
        assert!(tc_id.ends_with("-SHAKE256"), "{tc_id}");
        use sha3::digest::{ExtendableOutput, Update, XofReader};
        let mut h = sha3::Shake256::default();
        h.update(m);
        let mut out = vec![0u8; 64];
        h.finalize_xof().read(&mut out);
        out
    }
}

/// `M' = Prefix ‖ Label ‖ len(ctx) ‖ ctx ‖ PH(M)` (§2.2), Prefix the ASCII of
/// "CompositeAlgorithmSignatures2025".
fn draft_m_prime(tc_id: &str, ctx: &[u8], ph: &[u8]) -> Vec<u8> {
    let mut out = b"CompositeAlgorithmSignatures2025".to_vec();
    out.extend_from_slice(&draft_label(tc_id));
    out.push(ctx.len() as u8);
    out.extend_from_slice(ctx);
    out.extend_from_slice(ph);
    out
}

/// The traditional algorithm from the §6 entry (copied here from the draft
/// text, not from native::composite).
enum DraftTrad {
    /// engine hash-specific RSA mechanism, PSS salt.
    Rsa(u32, Option<usize>),
    /// engine CKM_ECDSA_SHAnnn, curve.
    Ecdsa(u32, u32),
    EdDsa,
}

fn draft_trad(tc_id: &str) -> DraftTrad {
    use crate::crypto::handlers::{CURVE_P256, CURVE_P384, CURVE_P521};
    match tc_id {
        // id-RSASSA-PSS, §6.1 Table 2 (SHA-256, MGF1-SHA-256, salt 32).
        "id-MLDSA44-RSA2048-PSS-SHA256" | "id-MLDSA65-RSA3072-PSS-SHA512" | "id-MLDSA87-RSA3072-PSS-SHA512" => {
            DraftTrad::Rsa(CKM_SHA256_RSA_PKCS_PSS, Some(32))
        }
        // id-RSASSA-PSS, §6.1 Table 3 (SHA-384, MGF1-SHA-384, salt 48).
        "id-MLDSA65-RSA4096-PSS-SHA512" | "id-MLDSA87-RSA4096-PSS-SHA512" => {
            DraftTrad::Rsa(CKM_SHA384_RSA_PKCS_PSS, Some(48))
        }
        // sha256WithRSAEncryption.
        "id-MLDSA44-RSA2048-PKCS15-SHA256" | "id-MLDSA65-RSA3072-PKCS15-SHA512" => DraftTrad::Rsa(CKM_SHA256_RSA_PKCS, None),
        // sha384WithRSAEncryption.
        "id-MLDSA65-RSA4096-PKCS15-SHA512" => DraftTrad::Rsa(CKM_SHA384_RSA_PKCS, None),
        // ecdsa-with-SHA256 / SHA384 / SHA512 on secp256r1 / 384r1 / 521r1.
        "id-MLDSA44-ECDSA-P256-SHA256" | "id-MLDSA65-ECDSA-P256-SHA512" => DraftTrad::Ecdsa(CKM_ECDSA_SHA256, CURVE_P256),
        "id-MLDSA65-ECDSA-P384-SHA512" | "id-MLDSA87-ECDSA-P384-SHA512" => DraftTrad::Ecdsa(CKM_ECDSA_SHA384, CURVE_P384),
        "id-MLDSA87-ECDSA-P521-SHA512" => DraftTrad::Ecdsa(CKM_ECDSA_SHA512, CURVE_P521),
        // id-Ed25519 / id-Ed448, pure.
        "id-MLDSA44-Ed25519-SHA512" | "id-MLDSA65-Ed25519-SHA512" | "id-MLDSA87-Ed448-SHAKE256" => DraftTrad::EdDsa,
        other => panic!("no draft entry for {other}"),
    }
}

/// tradPK from tradSK by each component crate's own parser (§4 encodings:
/// RSAPrivateKey, RFC 5915 ECPrivateKey, raw EdDSA).
fn independent_trad_public(tc_id: &str, sk: &[u8]) -> Vec<u8> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    match draft_trad(tc_id) {
        DraftTrad::Rsa(..) => {
            use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPublicKey};
            let k = rsa::RsaPrivateKey::from_pkcs1_der(sk).expect("RSAPrivateKey");
            rsa::RsaPublicKey::from(&k).to_pkcs1_der().unwrap().as_bytes().to_vec()
        }
        DraftTrad::Ecdsa(_, 256) => p256::SecretKey::from_sec1_der(sk).unwrap().public_key().to_encoded_point(false).as_bytes().to_vec(),
        DraftTrad::Ecdsa(_, 384) => p384::SecretKey::from_sec1_der(sk).unwrap().public_key().to_encoded_point(false).as_bytes().to_vec(),
        DraftTrad::Ecdsa(_, _) => p521::SecretKey::from_sec1_der(sk).unwrap().public_key().to_encoded_point(false).as_bytes().to_vec(),
        DraftTrad::EdDsa if sk.len() == 32 => {
            ed25519_dalek::SigningKey::from_bytes(sk.try_into().unwrap()).verifying_key().to_bytes().to_vec()
        }
        DraftTrad::EdDsa => ed448_goldilocks::SigningKey::try_from(sk).unwrap().verifying_key().to_bytes().to_vec(),
    }
}

/// Which halves of `s` verify over the M' for `ctx` (§3.3 step 4), checked
/// with the engine's single-algorithm verifiers only: (ML-DSA half with
/// ctx = Label, traditional half). `pk`/`s` are split per §4.1/§4.3 with the
/// Table 1 ML-DSA lengths.
fn halves_verify(tc_id: &str, pk: &[u8], m: &[u8], ctx: &[u8], s: &[u8]) -> (bool, bool) {
    use crate::crypto::handlers::{verify_ecdsa, verify_eddsa, verify_ml_dsa, verify_rsa};
    let (ckp, pk_len, sig_len) = ml_level(tc_id);
    let (ml_pk, trad_pk) = pk.split_at(pk_len);
    if s.len() <= sig_len {
        return (false, false);
    }
    let (ml_sig, trad_sig) = s.split_at(sig_len);
    let mp = draft_m_prime(tc_id, ctx, &draft_ph(tc_id, m));
    let ml_ok = verify_ml_dsa(CKM_ML_DSA, ckp, ml_pk, &mp, ml_sig, &draft_label(tc_id)).is_ok();
    let trad_ok = match draft_trad(tc_id) {
        DraftTrad::Rsa(mech, salt) => {
            use rsa::pkcs1::DecodeRsaPublicKey;
            use rsa::traits::PublicKeyParts;
            let k = rsa::RsaPublicKey::from_pkcs1_der(trad_pk).expect("RSAPublicKey");
            verify_rsa(mech, &k.n().to_bytes_be(), &k.e().to_bytes_be(), &mp, trad_sig, salt).is_ok()
        }
        DraftTrad::Ecdsa(mech, curve) => {
            // RFC 3279 Ecdsa-Sig-Value (DER) → the engine's r ‖ s form.
            let raw = match curve {
                256 => p256::ecdsa::Signature::from_der(trad_sig).map(|s| s.to_bytes().to_vec()).ok(),
                384 => p384::ecdsa::Signature::from_der(trad_sig).map(|s| s.to_bytes().to_vec()).ok(),
                _ => p521::ecdsa::Signature::from_der(trad_sig).map(|s| s.to_bytes().to_vec()).ok(),
            };
            raw.is_some_and(|r| verify_ecdsa(mech, curve, trad_pk, &mp, &r).is_ok())
        }
        DraftTrad::EdDsa => verify_eddsa(trad_pk, &mp, trad_sig).is_ok(),
    };
    (ml_ok, trad_ok)
}

// ── V3: the vectors themselves ─────────────────────────────────────────────

/// Plan V3 (signatures), all 18 vectors: split `pk`/`sk` (§4.1/§4.2) and
/// re-derive both public halves (ML-DSA KeyGen_internal from mldsaSeed,
/// FIPS 204 Algorithm 6; the traditional key by its own crate); the label in
/// the table equals the one the §6 name gives; then split `s` and
/// `sWithContext` (§4.3) and verify EACH HALF SEPARATELY over the M' built
/// here from §2.2 — `s` with the empty ctx, `sWithContext` with the
/// top-level ctx — and check each half fails under the other ctx. Brainpool
/// rows: their traditional half needs brainpool curves, which the engine
/// does not have yet; their ML-DSA halves are still checked, and the
/// composite import is asserted unsupported.
#[test]
fn v3_composite_sig_vectors_halves_verify_independently() {
    let _guard = test_lock::acquire();
    setup();
    let d = doc();
    let mut full = 0;
    let mut ml_only = Vec::new();
    for v in &d.vectors {
        let id = v.tc_id.as_str();
        assert_eq!(v.p.label, draft_label(id).as_slice(), "{id}: label");
        let (ckp, pk_len, sig_len) = ml_level(id);
        assert_eq!(ckp, v.p.ml_dsa, "{id}");
        let (ml_pk, trad_pk) = v.pk.split_at(pk_len);
        let (seed, trad_sk) = v.sk.split_at(32);
        let (derived, _) = crate::crypto::handlers::ml_dsa_keygen_from_seed(ckp, seed.try_into().unwrap()).unwrap();
        assert_eq!(derived, ml_pk, "{id}: mldsaPK from mldsaSeed");
        assert!(v.s.len() > sig_len && v.s_ctx.len() > sig_len, "{id}");
        assert!(v.p.signature_size().admits(v.s.len()) && v.p.signature_size().admits(v.s_ctx.len()), "{id}: sizes");
        if !v.p.supported {
            // ML-DSA half only, from the engine's verifier.
            let mp = draft_m_prime(id, &[], &draft_ph(id, &d.m));
            assert!(
                crate::crypto::handlers::verify_ml_dsa(CKM_ML_DSA, ckp, ml_pk, &mp, &v.s[..sig_len], v.p.label).is_ok(),
                "{id}: ML-DSA half of s"
            );
            assert_eq!(import_public(v.p.ckp, &v.pk).0, CKR_PARAMETER_SET_NOT_SUPPORTED, "{id}");
            ml_only.push(id.to_string());
            continue;
        }
        assert_eq!(independent_trad_public(id, trad_sk), trad_pk, "{id}: tradPK from tradSK");
        assert_eq!(halves_verify(id, &v.pk, &d.m, &[], &v.s), (true, true), "{id}: s, empty ctx");
        assert_eq!(halves_verify(id, &v.pk, &d.m, &d.ctx, &v.s_ctx), (true, true), "{id}: sWithContext");
        assert_eq!(halves_verify(id, &v.pk, &d.m, &d.ctx, &v.s), (false, false), "{id}: s under ctx");
        assert_eq!(halves_verify(id, &v.pk, &d.m, &[], &v.s_ctx), (false, false), "{id}: sWithContext without ctx");
        full += 1;
    }
    assert_eq!(full, 16);
    assert_eq!(ml_only, ["id-MLDSA65-ECDSA-brainpoolP256r1-SHA512", "id-MLDSA87-ECDSA-brainpoolP384r1-SHA512"]);
}

// ── A4: KATs ─────────────────────────────────────────────────────────────

/// Verification KAT, all 16 supported vectors: `pk` imported through
/// C_CreateObject; `s` verifies under CKM_COMP_SIG with no parameter and
/// with an empty CK_SIGN_ADDITIONAL_CONTEXT, `sWithContext` with the
/// top-level ctx; both through CKM_COMP_SIG_EXTERNAL_HASH with PH(m)
/// computed here; both multi-part (C_VerifyUpdate in 7-byte parts) and
/// through C_VerifySignature, single- and multi-part.
#[test]
fn kat_verify_all_supported_vectors() {
    let _guard = test_lock::acquire();
    setup();
    let d = doc();
    let mut n = 0;
    for v in d.vectors.iter().filter(|v| v.p.supported) {
        let id = v.tc_id.as_str();
        let (rv, hp) = import_public(v.p.ckp, &v.pk);
        assert_eq!(rv, CKR_OK, "{id}");
        let none = sign_ctx(CKH_HEDGE_PREFERRED, &[]);
        let with = sign_ctx(CKH_HEDGE_PREFERRED, &d.ctx);
        let ph = draft_ph(id, &d.m);
        assert_eq!(verify(CKM_COMP_SIG, None, hp, &d.m, &v.s), CKR_OK, "{id}: s");
        assert_eq!(verify(CKM_COMP_SIG, Some(&none), hp, &d.m, &v.s), CKR_OK, "{id}: s, empty ctx param");
        assert_eq!(verify(CKM_COMP_SIG, Some(&with), hp, &d.m, &v.s_ctx), CKR_OK, "{id}: sWithContext");
        assert_eq!(verify(CKM_COMP_SIG_EXTERNAL_HASH, None, hp, &ph, &v.s), CKR_OK, "{id}: external hash s");
        assert_eq!(verify(CKM_COMP_SIG_EXTERNAL_HASH, Some(&with), hp, &ph, &v.s_ctx), CKR_OK, "{id}: external hash sWithContext");
        assert_eq!(verify_multi(CKM_COMP_SIG, None, hp, &d.m, 7, &v.s), CKR_OK, "{id}: multi-part s");
        assert_eq!(verify_multi(CKM_COMP_SIG, Some(&with), hp, &d.m, 7, &v.s_ctx), CKR_OK, "{id}: multi-part sWithContext");
        assert_eq!(verify_signature(CKM_COMP_SIG, None, hp, &d.m, None, &v.s), CKR_OK, "{id}: C_VerifySignature");
        assert_eq!(verify_signature(CKM_COMP_SIG, Some(&with), hp, &d.m, Some(5), &v.s_ctx), CKR_OK, "{id}: C_VerifySignatureUpdate");
        assert_eq!(verify_signature(CKM_COMP_SIG_EXTERNAL_HASH, None, hp, &ph, None, &v.s), CKR_OK, "{id}: C_VerifySignature external hash");
        destroy(&[hp]);
        n += 1;
    }
    assert_eq!(n, 16);
}

/// The vectors' private keys sign: `sk` imported, our signature (empty ctx
/// and the top-level ctx, single- and multi-part, and external hash)
/// verifies through the engine under the VECTOR's `pk`, and both of its
/// halves pass the independent V3 checker.
#[test]
fn kat_imported_private_key_signs_verifiably() {
    let _guard = test_lock::acquire();
    setup();
    let d = doc();
    let mut n = 0;
    for v in d.vectors.iter().filter(|v| v.p.supported) {
        let id = v.tc_id.as_str();
        let (rv, hk) = import_private(v.p.ckp, &v.sk);
        assert_eq!(rv, CKR_OK, "{id}");
        let (rv, hp) = import_public(v.p.ckp, &v.pk);
        assert_eq!(rv, CKR_OK, "{id}");
        let with = sign_ctx(CKH_HEDGE_PREFERRED, &d.ctx);
        let (rv, s) = sign(CKM_COMP_SIG, None, hk, &d.m);
        assert_eq!(rv, CKR_OK, "{id}: sign");
        assert!(v.p.signature_size().admits(s.len()), "{id}: size {}", s.len());
        let (rv, s_ctx) = sign(CKM_COMP_SIG, Some(&with), hk, &d.m);
        assert_eq!(rv, CKR_OK, "{id}: sign with ctx");
        let (rv, s_multi) = sign_multi(CKM_COMP_SIG, Some(&with), hk, &d.m, 11);
        assert_eq!(rv, CKR_OK, "{id}: multi-part sign");
        let (rv, s_ext) = sign(CKM_COMP_SIG_EXTERNAL_HASH, None, hk, &draft_ph(id, &d.m));
        assert_eq!(rv, CKR_OK, "{id}: external-hash sign");
        assert_eq!(verify(CKM_COMP_SIG, None, hp, &d.m, &s), CKR_OK, "{id}");
        assert_eq!(verify(CKM_COMP_SIG, Some(&with), hp, &d.m, &s_ctx), CKR_OK, "{id}");
        assert_eq!(verify(CKM_COMP_SIG, Some(&with), hp, &d.m, &s_multi), CKR_OK, "{id}");
        assert_eq!(verify(CKM_COMP_SIG, None, hp, &d.m, &s_ext), CKR_OK, "{id}");
        assert_eq!(halves_verify(id, &v.pk, &d.m, &[], &s), (true, true), "{id}: V3 checker, s");
        assert_eq!(halves_verify(id, &v.pk, &d.m, &d.ctx, &s_ctx), (true, true), "{id}: V3 checker, ctx");
        assert_eq!(halves_verify(id, &v.pk, &d.m, &d.ctx, &s_multi), (true, true), "{id}: V3 checker, multi-part");
        destroy(&[hk, hp]);
        n += 1;
    }
    assert_eq!(n, 16);
}

// ── Key generation and round trips ───────────────────────────────────────

/// CKM_COMP_SIG_KEY_PAIR_GEN for all 16 supported sets: object attributes,
/// value sizes, the public half re-derivable from the private value, and
/// round trips — single-part, multi-part (one-shot == streamed: with
/// CKH_DETERMINISTIC_REQUIRED the two signatures are byte-identical for every
/// set that can sign deterministically; for the PSS and P-521 sets each
/// verifies under the other form), external hash against CKM_COMP_SIG, and the V3 checker
/// on the generated pair. Brainpool and an unknown set:
/// CKR_PARAMETER_SET_NOT_SUPPORTED.
#[test]
fn keygen_and_round_trip_all_supported_sets() {
    let _guard = test_lock::acquire();
    setup();
    let msg: Vec<u8> = (0..1000u32).map(|i| (i * 7) as u8).collect();
    let mut n = 0;
    for p in COMPOSITE_SIG_SETS.iter() {
        let (rv, hp, hk) = generate_comp_sig(p.ckp);
        if !p.supported {
            assert_eq!(rv, CKR_PARAMETER_SET_NOT_SUPPORTED, "{}", p.name);
            continue;
        }
        let id = p.name;
        assert_eq!(rv, CKR_OK, "{id}");
        assert_eq!(get_object_attr_u32(hp, CKA_KEY_TYPE), Some(CKK_COMP_SIG));
        assert_eq!(get_object_attr_u32(hk, CKA_PARAMETER_SET), Some(p.ckp));
        assert_eq!(get_object_attr_u32(hk, CKA_KEY_GEN_MECHANISM), Some(CKM_COMP_SIG_KEY_PAIR_GEN));
        let pk = value(hp);
        assert!(p.public_key_size().admits(pk.len()) && p.private_key_size().admits(value(hk).len()), "{id}");
        assert_eq!(independent_trad_public(id, &value(hk)[32..]), pk[ml_level(id).1..], "{id}: tradPK");

        let ctx = sign_ctx(CKH_HEDGE_PREFERRED, b"round trip");
        let (rv, s) = sign(CKM_COMP_SIG, Some(&ctx), hk, &msg);
        assert_eq!(rv, CKR_OK, "{id}");
        assert_eq!(verify(CKM_COMP_SIG, Some(&ctx), hp, &msg, &s), CKR_OK, "{id}");
        assert_eq!(halves_verify(id, &pk, &msg, b"round trip", &s), (true, true), "{id}: V3 checker");
        let (rv, s_multi) = sign_multi(CKM_COMP_SIG, Some(&ctx), hk, &msg, 64);
        assert_eq!(rv, CKR_OK, "{id}");
        assert_eq!(verify(CKM_COMP_SIG, Some(&ctx), hp, &msg, &s_multi), CKR_OK, "{id}: streamed, verified one-shot");
        assert_eq!(verify_multi(CKM_COMP_SIG, Some(&ctx), hp, &msg, 100, &s), CKR_OK, "{id}: one-shot, verified streamed");
        let det = sign_ctx(CKH_DETERMINISTIC_REQUIRED, b"round trip");
        if crate::native::composite_sig::deterministic_available(p) {
            let (rv, a) = sign(CKM_COMP_SIG, Some(&det), hk, &msg);
            assert_eq!(rv, CKR_OK, "{id}");
            let (rv, b) = sign_multi(CKM_COMP_SIG, Some(&det), hk, &msg, 33);
            assert_eq!(rv, CKR_OK, "{id}");
            assert_eq!(a, b, "{id}: multi-part == single-part");
            let ph = draft_ph(id, &msg);
            let (rv, c) = sign(CKM_COMP_SIG_EXTERNAL_HASH, Some(&det), hk, &ph);
            assert_eq!(rv, CKR_OK, "{id}");
            assert_eq!(a, c, "{id}: external hash == CKM_COMP_SIG");
        } else {
            assert_eq!(sign_init(CKM_COMP_SIG, Some(&det), hk), CKR_MECHANISM_PARAM_INVALID, "{id}: randomised traditional half");
        }
        let (rv, s_ext) = sign(CKM_COMP_SIG_EXTERNAL_HASH, Some(&ctx), hk, &draft_ph(id, &msg));
        assert_eq!(rv, CKR_OK, "{id}");
        assert_eq!(verify(CKM_COMP_SIG, Some(&ctx), hp, &msg, &s_ext), CKR_OK, "{id}: external hash, verified on M");
        assert_eq!(verify(CKM_COMP_SIG_EXTERNAL_HASH, Some(&ctx), hp, &draft_ph(id, &msg), &s), CKR_OK, "{id}");
        destroy(&[hp, hk]);
        n += 1;
    }
    assert_eq!(n, 16);
    assert_eq!(generate_comp_sig(0x7f).0, CKR_PARAMETER_SET_NOT_SUPPORTED);
    assert_eq!(generate(CKM_COMP_SIG_KEY_PAIR_GEN, vec![], vec![]).0, CKR_TEMPLATE_INCOMPLETE);
    assert_eq!(
        generate(
            CKM_COMP_SIG_KEY_PAIR_GEN,
            vec![(CKA_PARAMETER_SET, ulong(CKP_COMP_SIG_MLDSA44_ED25519_SHA512)), (CKA_KEY_TYPE, ulong(CKK_COMP_KEM))],
            vec![]
        )
        .0,
        CKR_TEMPLATE_INCONSISTENT
    );
}

// ── V6: negative vectors derived from the good ones ─────────────────────

/// Derived failures per supported vector, each expected outcome from
/// draft-19 §3.3 ("Valid signature" only if every component validates):
/// - one bit flipped in the ML-DSA half, or in the traditional half:
///   CKR_SIGNATURE_INVALID;
/// - truncated by one byte: CKR_SIGNATURE_LEN_RANGE where the traditional
///   length is fixed (RSA, EdDSA; §3.3 step 2 "not of the correct ...
///   length"), CKR_SIGNATURE_INVALID for DER ECDSA (Appendix A `*`: a shorter
///   value is a possible length, the DER no longer decodes);
/// - another set's whole signature: never CKR_OK; this set's halves
///   swapped (tradSig ‖ mldsaSig): never CKR_OK; the ML-DSA half of another
///   set at the same ML-DSA level spliced in: CKR_SIGNATURE_INVALID (the
///   label is ML-DSA's ctx, §3.2 step 4);
/// - `sWithContext` with a wrong ctx or no ctx, `s` with the ctx, or a
///   different message: CKR_SIGNATURE_INVALID.
#[test]
fn v6_derived_negative_vectors() {
    let _guard = test_lock::acquire();
    setup();
    let d = doc();
    let all: Vec<&Vector> = d.vectors.iter().filter(|v| v.p.supported).collect();
    for (i, v) in all.iter().enumerate() {
        let id = v.tc_id.as_str();
        let (rv, hp) = import_public(v.p.ckp, &v.pk);
        assert_eq!(rv, CKR_OK, "{id}");
        let with = sign_ctx(CKH_HEDGE_PREFERRED, &d.ctx);
        let check = |param: Option<&SignCtx>, msg: &[u8], s: &[u8]| verify(CKM_COMP_SIG, param, hp, msg, s);
        let n = v.p.ml_dsa_signature_len();

        let mut s = v.s.clone();
        s[n / 2] ^= 0x01;
        assert_eq!(check(None, &d.m, &s), CKR_SIGNATURE_INVALID, "{id}: ML-DSA half flipped");
        let mut s = v.s.clone();
        let last = s.len() - 1;
        s[last] ^= 0x01;
        assert_eq!(check(None, &d.m, &s), CKR_SIGNATURE_INVALID, "{id}: traditional half flipped");
        let truncated = check(None, &d.m, &v.s[..v.s.len() - 1]);
        if v.p.classical_sizes.output.is_exact() {
            assert_eq!(truncated, CKR_SIGNATURE_LEN_RANGE, "{id}: truncated");
        } else {
            assert_eq!(truncated, CKR_SIGNATURE_INVALID, "{id}: truncated DER");
        }
        let other = all[(i + 1) % all.len()];
        assert_ne!(check(None, &d.m, &other.s), CKR_OK, "{id}: signature of {}", other.tc_id);
        let mut swapped = v.s[n..].to_vec();
        swapped.extend_from_slice(&v.s[..n]);
        assert_ne!(check(None, &d.m, &swapped), CKR_OK, "{id}: halves swapped");
        if let Some(same) = all.iter().find(|o| o.p.ml_dsa == v.p.ml_dsa && o.p.ckp != v.p.ckp) {
            let mut spliced = same.s[..n].to_vec();
            spliced.extend_from_slice(&v.s[n..]);
            assert_eq!(check(None, &d.m, &spliced), CKR_SIGNATURE_INVALID, "{id}: ML-DSA half of {}", same.tc_id);
        }
        let wrong = sign_ctx(CKH_HEDGE_PREFERRED, b"another context");
        assert_eq!(check(Some(&wrong), &d.m, &v.s_ctx), CKR_SIGNATURE_INVALID, "{id}: wrong ctx");
        assert_eq!(check(None, &d.m, &v.s_ctx), CKR_SIGNATURE_INVALID, "{id}: ctx missing");
        assert_eq!(check(Some(&with), &d.m, &v.s), CKR_SIGNATURE_INVALID, "{id}: s under ctx");
        let mut m2 = d.m.clone();
        m2[0] ^= 0x01;
        assert_eq!(check(None, &m2, &v.s), CKR_SIGNATURE_INVALID, "{id}: wrong message");
        assert_eq!(verify_multi(CKM_COMP_SIG, None, hp, &m2, 7, &v.s), CKR_SIGNATURE_INVALID, "{id}: wrong message, streamed");
        destroy(&[hp]);
    }
}

/// CKM_COMP_SIG_EXTERNAL_HASH: the input must be exactly PH's length
/// (comp_sig.md: "MUST require PH(M) to be 64 bytes long" for SHA512) —
/// otherwise CKR_DATA_LEN_RANGE on both C_Sign and C_Verify (see
/// composite_sig::message_representative); and it is single-part only
/// (comp_sig.md table footnote 1): C_SignUpdate / C_VerifyUpdate /
/// C_VerifySignatureUpdate end the operation with
/// CKR_OPERATION_NOT_INITIALIZED (the engine's rule for every single-part
/// mechanism, multipart_op_mech).
#[test]
fn external_hash_length_and_single_part_rules() {
    let _guard = test_lock::acquire();
    setup();
    for ckp in [CKP_COMP_SIG_MLDSA44_ECDSA_P256_SHA256, CKP_COMP_SIG_MLDSA65_ED25519_SHA512, CKP_COMP_SIG_MLDSA87_ED448_SHAKE256] {
        let p = sig_params(ckp).unwrap();
        let (rv, hp, hk) = generate_comp_sig(ckp);
        assert_eq!(rv, CKR_OK);
        let len = p.pre_hash.output_len();
        assert_eq!(len, if ckp == CKP_COMP_SIG_MLDSA44_ECDSA_P256_SHA256 { 32 } else { 64 }, "{}", p.name);
        for bad in [len - 1, len + 1, 0, 48] {
            assert_eq!(sign(CKM_COMP_SIG_EXTERNAL_HASH, None, hk, &vec![0u8; bad]).0, CKR_DATA_LEN_RANGE, "{}: {bad}", p.name);
        }
        let (rv, s) = sign(CKM_COMP_SIG_EXTERNAL_HASH, None, hk, &vec![0x5a; len]);
        assert_eq!(rv, CKR_OK);
        assert_eq!(verify(CKM_COMP_SIG_EXTERNAL_HASH, None, hp, &vec![0x5a; len], &s), CKR_OK);
        assert_eq!(verify(CKM_COMP_SIG_EXTERNAL_HASH, None, hp, &vec![0x5a; len + 1], &s), CKR_DATA_LEN_RANGE);
        // Multi-part refused, and the operation is gone afterwards.
        let mut part = vec![0x5a; len];
        assert_eq!(sign_init(CKM_COMP_SIG_EXTERNAL_HASH, None, hk), CKR_OK);
        assert_eq!(C_SignUpdate(SESSION, part.as_mut_ptr(), len as u32), CKR_OPERATION_NOT_INITIALIZED);
        let mut l = 0u32;
        assert_eq!(C_SignFinal(SESSION, std::ptr::null_mut(), &mut l), CKR_OPERATION_NOT_INITIALIZED);
        assert_eq!(verify_init(CKM_COMP_SIG_EXTERNAL_HASH, None, hp), CKR_OK);
        assert_eq!(C_VerifyUpdate(SESSION, part.as_mut_ptr(), len as u32), CKR_OPERATION_NOT_INITIALIZED);
        let mut sig = s.clone();
        assert_eq!(C_VerifyFinal(SESSION, sig.as_mut_ptr(), sig.len() as u32), CKR_OPERATION_NOT_INITIALIZED);
        assert_eq!(
            verify_signature(CKM_COMP_SIG_EXTERNAL_HASH, None, hp, &vec![0x5a; len], Some(len), &s),
            CKR_OPERATION_NOT_INITIALIZED
        );
        assert_eq!(C_VerifySignatureFinal(SESSION), CKR_OPERATION_NOT_INITIALIZED);
        destroy(&[hp, hk]);
    }
}

/// Parameter, hedge, key and buffer rules:
/// - a ctx of 256 bytes: CKR_MECHANISM_PARAM_INVALID at C_SignInit and
///   C_VerifyInit (draft §3.2/§3.3 step 1: len(ctx) > 255 is an error);
///   255 bytes works;
/// - the default hedge variant signs hedged ML-DSA (two signatures differ);
///   CKH_DETERMINISTIC_REQUIRED on an Ed25519 set gives identical ones;
/// - a key of another type: CKR_KEY_TYPE_INCONSISTENT (mech_key_types);
/// - the size query reports the set's maximum (Appendix A), a short buffer
///   is CKR_BUFFER_TOO_SMALL and leaves the operation running, single- and
///   multi-part.
#[test]
fn parameter_hedge_key_and_buffer_rules() {
    let _guard = test_lock::acquire();
    setup();
    let p = sig_params(CKP_COMP_SIG_MLDSA65_ECDSA_P256_SHA512).unwrap();
    let (rv, hp, hk) = generate_comp_sig(p.ckp);
    assert_eq!(rv, CKR_OK);
    let long = sign_ctx(CKH_HEDGE_PREFERRED, &[7u8; 256]);
    assert_eq!(sign_init(CKM_COMP_SIG, Some(&long), hk), CKR_MECHANISM_PARAM_INVALID);
    assert_eq!(verify_init(CKM_COMP_SIG, Some(&long), hp), CKR_MECHANISM_PARAM_INVALID);
    let max = sign_ctx(CKH_HEDGE_PREFERRED, &[7u8; 255]);
    let (rv, s) = sign(CKM_COMP_SIG, Some(&max), hk, b"m");
    assert_eq!(rv, CKR_OK);
    assert_eq!(verify(CKM_COMP_SIG, Some(&max), hp, b"m", &s), CKR_OK);
    assert_eq!(sign_init(CKM_COMP_SIG, Some(&sign_ctx(7, &[])), hk), CKR_MECHANISM_PARAM_INVALID, "unknown hedge variant");

    let (_, a) = sign(CKM_COMP_SIG, None, hk, b"m");
    let (_, b) = sign(CKM_COMP_SIG, None, hk, b"m");
    assert_ne!(a[..p.ml_dsa_signature_len()], b[..p.ml_dsa_signature_len()], "hedged ML-DSA");

    let (rv, hp_ed, hk_ed) = generate_comp_sig(CKP_COMP_SIG_MLDSA44_ED25519_SHA512);
    assert_eq!(rv, CKR_OK);
    let det = sign_ctx(CKH_DETERMINISTIC_REQUIRED, &[]);
    assert_eq!(sign(CKM_COMP_SIG, Some(&det), hk_ed, b"m").1, sign(CKM_COMP_SIG, Some(&det), hk_ed, b"m").1);

    // Key type: an ML-DSA key under CKM_COMP_SIG, a composite key under CKM_ML_DSA.
    let (rv, hp_ml, hk_ml) =
        generate(CKM_ML_DSA_KEY_PAIR_GEN, vec![(CKA_PARAMETER_SET, ulong(CKP_ML_DSA_65)), (CKA_VERIFY, vec![1])], vec![(CKA_SIGN, vec![1])]);
    assert_eq!(rv, CKR_OK);
    assert_eq!(sign_init(CKM_COMP_SIG, None, hk_ml), CKR_KEY_TYPE_INCONSISTENT);
    assert_eq!(verify_init(CKM_COMP_SIG_EXTERNAL_HASH, None, hp_ml), CKR_KEY_TYPE_INCONSISTENT);
    assert_eq!(sign_init(CKM_ML_DSA, None, hk), CKR_KEY_TYPE_INCONSISTENT);

    // Size query and short buffer, single-part.
    assert_eq!(sign_init(CKM_COMP_SIG, None, hk), CKR_OK);
    let mut msg = b"m".to_vec();
    let mut len = 0u32;
    assert_eq!(C_Sign(SESSION, msg.as_mut_ptr(), 1, std::ptr::null_mut(), &mut len), CKR_OK);
    assert_eq!(len as usize, p.signature_size().bytes());
    assert_eq!(len, 3309 + 72);
    let mut small = vec![0u8; 100];
    let mut l = 100u32;
    assert_eq!(C_Sign(SESSION, msg.as_mut_ptr(), 1, small.as_mut_ptr(), &mut l), CKR_BUFFER_TOO_SMALL);
    let mut sig = vec![0u8; len as usize];
    let mut l = len;
    assert_eq!(C_Sign(SESSION, msg.as_mut_ptr(), 1, sig.as_mut_ptr(), &mut l), CKR_OK, "operation survived");
    sig.truncate(l as usize);
    assert_eq!(verify(CKM_COMP_SIG, None, hp, b"m", &sig), CKR_OK);

    // Multi-part: the same, and the streamed state survives both.
    assert_eq!(sign_init(CKM_COMP_SIG, None, hk), CKR_OK);
    assert_eq!(C_SignUpdate(SESSION, msg.as_mut_ptr(), 1), CKR_OK);
    assert_eq!(C_Sign(SESSION, msg.as_mut_ptr(), 1, sig.as_mut_ptr(), &mut l), CKR_OPERATION_ACTIVE);
    let mut l = 0u32;
    assert_eq!(C_SignFinal(SESSION, std::ptr::null_mut(), &mut l), CKR_OK);
    assert_eq!(l, len);
    let mut l = 100u32;
    assert_eq!(C_SignFinal(SESSION, small.as_mut_ptr(), &mut l), CKR_BUFFER_TOO_SMALL);
    let mut more = b"!".to_vec();
    assert_eq!(C_SignUpdate(SESSION, more.as_mut_ptr(), 1), CKR_OK, "still in the multi-part phase");
    let mut sig = vec![0u8; len as usize];
    let mut l = len;
    assert_eq!(C_SignFinal(SESSION, sig.as_mut_ptr(), &mut l), CKR_OK);
    sig.truncate(l as usize);
    assert_eq!(verify(CKM_COMP_SIG, None, hp, b"m!", &sig), CKR_OK);
    let mut l = 0u32;
    assert_eq!(C_SignFinal(SESSION, std::ptr::null_mut(), &mut l), CKR_OPERATION_NOT_INITIALIZED, "operation ended");

    destroy(&[hp, hk, hp_ed, hk_ed, hp_ml, hk_ml]);
}

/// comp_sig.md: ulMinKeySize/ulMaxKeySize are composite public-key bytes.
/// Smallest supported: id-MLDSA44-Ed25519-SHA512, 1312 + 32 = 1344;
/// largest: id-MLDSA87-RSA4096-PSS-SHA512, 2592 + 526 (RSA public key
/// maximum, draft Appendix A) = 3118. Flags: CKF_GENERATE_KEY_PAIR;
/// CKF_SIGN | CKF_VERIFY. All three advertised.
#[test]
fn mechanism_info_and_advertising() {
    assert_eq!(mechanism_info(CKM_COMP_SIG_KEY_PAIR_GEN), Some((1344, 3118, 0x0001_0000)));
    assert_eq!(mechanism_info(CKM_COMP_SIG), Some((1344, 3118, 0x0800 | 0x2000)));
    assert_eq!(mechanism_info(CKM_COMP_SIG_EXTERNAL_HASH), Some((1344, 3118, 0x0800 | 0x2000)));
    for m in [CKM_COMP_SIG_KEY_PAIR_GEN, CKM_COMP_SIG, CKM_COMP_SIG_EXTERNAL_HASH] {
        assert!(SUPPORTED_MECHS.contains(&m), "{m:#x}");
    }
}

// ── V5 fixture (our output, for the reference implementation) ────────────

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Plan V5 input, NOT a test of its own and ignored by default: writes
/// engine-generated artefacts for the reference implementation to check —
/// for each of the 16 signature sets a fresh pk and signatures over the
/// vector file's `m`, without and with its `ctx`; for each of the 10 KEM
/// sets a fresh ek, its dk, a ciphertext and the engine's shared secret k.
/// The private values and k are read here through the crate-internal object
/// store, which only test code can reach; the PKCS#11 API never exports
/// them (the private keys are sensitive and non-extractable). Throwaway keys,
/// never committed.
///
/// Run: `PQCTODAY_V5_FIXTURE_OUT=/path/out.json cargo test --lib
/// v5_fixture_generator -- --ignored`.
#[test]
#[ignore]
fn v5_fixture_generator() {
    let out = std::env::var("PQCTODAY_V5_FIXTURE_OUT").expect("set PQCTODAY_V5_FIXTURE_OUT to the output path");
    let _guard = test_lock::acquire();
    setup();
    let d = doc();
    let with = sign_ctx(CKH_HEDGE_PREFERRED, &d.ctx);
    let mut sigs = Vec::new();
    for p in COMPOSITE_SIG_SETS.iter().filter(|p| p.supported) {
        let (rv, hp, hk) = generate_comp_sig(p.ckp);
        assert_eq!(rv, CKR_OK, "{}", p.name);
        let (rv, s) = sign(CKM_COMP_SIG, None, hk, &d.m);
        assert_eq!(rv, CKR_OK);
        let (rv, s_ctx) = sign(CKM_COMP_SIG, Some(&with), hk, &d.m);
        assert_eq!(rv, CKR_OK);
        sigs.push(serde_json::json!({
            "tcId": p.name, "pk": hex(&value(hp)), "s": hex(&s), "sWithContext": hex(&s_ctx),
        }));
        destroy(&[hp, hk]);
    }
    let mut kems = Vec::new();
    for p in COMPOSITE_KEM_SETS.iter().filter(|p| p.supported) {
        assert!(kem_params(p.ckp).is_some());
        let (rv, hp, hk) = generate(CKM_COMP_KEM_KEY_PAIR_GEN, vec![(CKA_PARAMETER_SET, ulong(p.ckp))], vec![(CKA_PRIVATE, vec![0])]);
        assert_eq!(rv, CKR_OK, "{}", p.name);
        let mut mm: [usize; 3] = [CKM_COMP_KEM as usize, 0, 0];
        let mut ct = vec![0u8; p.ciphertext_size().bytes()];
        let mut ct_len = ct.len() as u32;
        let mut hs = 0u32;
        let rv = C_EncapsulateKey(
            SESSION,
            mm.as_mut_ptr() as *mut u8,
            hp,
            std::ptr::null_mut(),
            0,
            ct.as_mut_ptr(),
            &mut ct_len,
            &mut hs,
        );
        assert_eq!(rv, CKR_OK, "{}", p.name);
        ct.truncate(ct_len as usize);
        kems.push(serde_json::json!({
            "tcId": p.name, "ek": hex(&value(hp)), "dk": hex(&value(hk)), "c": hex(&ct), "k": hex(&value(hs)),
        }));
        destroy(&[hp, hk, hs]);
    }
    let doc = serde_json::json!({
        "source": "pqctoday-hsm Rust engine, self-generated (NOT upstream vectors)",
        "encoding": "hex",
        "m": hex(&d.m),
        "ctx": hex(&d.ctx),
        "sig": sigs,
        "kem": kems,
    });
    std::fs::write(&out, serde_json::to_vec_pretty(&doc).unwrap()).expect("write fixture");
    eprintln!("wrote {} signature and {} KEM entries to {out}", 16, 10);
}
