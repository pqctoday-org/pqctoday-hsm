//! Project Wycheproof ML-DSA sign vectors at the PKCS#11 boundary, and the
//! two Rust-engine defects they found (2026-09-30).
//!
//! Defects (hub open-gaps `wycheproof-rust-mldsa-sk-range` and
//! `wycheproof-rust-mldsa-empty-seed`, measured on wasm bundles built from
//! pqctoday-hsm 68278dfe):
//!
//! * **B1** — `C_CreateObject(CKO_PRIVATE_KEY, CKK_ML_DSA, CKA_VALUE = sk)`
//!   accepted an expanded private key whose s1 or s2 coefficients lie outside
//!   [−η, η], and `C_Sign` then signed with it. FIPS 204 Algorithm 25
//!   (`skDecode`) lines 3 and 6 note that BitUnpack "may lie outside [−η, η],
//!   if input is malformed"; the vendored `fips204` decode only bounded each
//!   coefficient by its 3-/4-bit field width, so nothing refused it.
//!   Wycheproof `InvalidPrivateKey`: tg4/tc52 + tg5/tc53 (ML-DSA-44),
//!   tg4/tc56 + tg5/tc57 (ML-DSA-65), tg4/tc47 + tg5/tc48 (ML-DSA-87).
//! * **B2** — a zero-length `CKA_SEED` in the `C_GenerateKeyPair` template
//!   read as ABSENT (`get_attr_bytes` returns `None` for `ulValueLen == 0`),
//!   so the caller asked for a deterministic key and silently got a random
//!   one. Wycheproof "empty private seed": tg22/tc84 (ML-DSA-44), tg24/tc91
//!   (ML-DSA-65), tg24/tc82 (ML-DSA-87). The same read served ML-KEM and
//!   SLH-DSA key generation, which Wycheproof has no 0-byte case for; they
//!   are covered by `empty_cka_seed_refused_for_every_seeded_keygen` below.
//!
//! Vectors: `rust/kat/wycheproof/wycheproof_mldsa_{44,65,87}_sign_{noseed,seed}_test.json`,
//! byte-copied from the pqctoday-hub vendored set (branch
//! `feat/wycheproof-pqc-0930` @ aa963d2da, `src/data/acvp/`), which are
//! themselves declared subsets of C2SP/wycheproof @ 3fa63dd0 — each file
//! carries its own `_provenance` block (upstream path, upstream sha256, and
//! the one excluded `Randomized` case per file). Apache-2.0, see
//! `rust/kat/wycheproof/WYCHEPROOF-LICENSE.txt`. Wycheproof is an
//! independent oracle, not a standards publication: a pass here means
//! "agrees with Project Wycheproof 3fa63dd0 for this case".
//!
//! | fixture | sha256 |
//! |---|---|
//! | `wycheproof_mldsa_44_sign_noseed_test.json` | `4b174941a80c3653e1af6e3ffa668f06fff90bbc7931e154556e410a836297fb` |
//! | `wycheproof_mldsa_44_sign_seed_test.json` | `c86e86563354639a508ce81a7781a61bbe666acf81fdca7ad387187774d6dd84` |
//! | `wycheproof_mldsa_65_sign_noseed_test.json` | `2487aadbb7df8409008f1ff98dc6feb4adf48aa069e173c34f848726b8855c7f` |
//! | `wycheproof_mldsa_65_sign_seed_test.json` | `5cb19d19e5dabcf3c2f112060b6a3893177307fef28f4df22c2c4394022a84ea` |
//! | `wycheproof_mldsa_87_sign_noseed_test.json` | `cc39a9aff6346035c9d69e5e2f79c87fea99afbe58eeed1e0dd45972d8c0f13b` |
//! | `wycheproof_mldsa_87_sign_seed_test.json` | `18cc1554e2f46bcecdf88e94bd4357483e342545e698a070b624cf4b81f65ff8` |
//!
//! The full-file tests are the over-rejection guard: every Wycheproof
//! `valid` case must still import (or generate) and sign byte-exact.
//!
//! Included from `ffi.rs` via `#[path]` so `use super::*` resolves to the FFI
//! module and its private helpers, like `mlkem_input_check_tests`.

use super::*;
use crate::native::test_lock;
use serde_json::Value;

/// High fixed session handle, disjoint from every other ffi test module.
const SESSION: u32 = 0x5759_4301;

/// The six B1 cases: (parameter set, tgId, tcId).
const SK_RANGE_CASES: [(u32, usize, u64); 6] = [
    (44, 4, 52),
    (44, 5, 53),
    (65, 4, 56),
    (65, 5, 57),
    (87, 4, 47),
    (87, 5, 48),
];

/// The three B2 cases: (parameter set, tgId, tcId).
const EMPTY_SEED_CASES: [(u32, usize, u64); 3] = [(44, 22, 84), (65, 24, 91), (87, 24, 82)];

fn setup() {
    crate::state::set_initialized(true);
    SESSIONS.with(|s| {
        s.shard(SESSION)
            .insert(SESSION, crate::state::SessionState { slot_id: 0, rw_session: true, context: 0 });
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
}

fn fixture(v: u32, kind: &str) -> Value {
    let path = format!(
        "{}/kat/wycheproof/wycheproof_mldsa_{v}_sign_{kind}_test.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let s = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    serde_json::from_str(&s).unwrap_or_else(|e| panic!("parse {path}: {e}"))
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd-length hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn ps_of(v: u32) -> u32 {
    match v {
        44 => CKP_ML_DSA_44,
        65 => CKP_ML_DSA_65,
        87 => CKP_ML_DSA_87,
        other => panic!("ML-DSA-{other}"),
    }
}

/// CK_ULONG-width little-endian bytes (what an LP64 caller sends).
fn ulong(v: u32) -> Vec<u8> {
    (v as usize).to_le_bytes().to_vec()
}

fn words(entries: &[(u32, Vec<u8>)]) -> Vec<usize> {
    entries
        .iter()
        .flat_map(|(t, v)| {
            // A zero-length value is sent with a NULL pValue, as a C caller
            // holding an empty buffer typically does.
            let p = if v.is_empty() { 0 } else { v.as_ptr() as usize };
            [*t as usize, p, v.len()]
        })
        .collect()
}

/// Wycheproof (tgId, test) for one case of a fixture.
fn case(doc: &Value, tg: usize, tc: u64) -> (Value, Value) {
    let g = doc["testGroups"][tg - 1].clone();
    let t = g["tests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["tcId"].as_u64() == Some(tc))
        .unwrap_or_else(|| panic!("tg{tg}/tc{tc} not in fixture"))
        .clone();
    (g, t)
}

fn import_sk(ps: u32, sk: &[u8]) -> (u32, u32) {
    let entries = vec![
        (CKA_CLASS, ulong(CKO_PRIVATE_KEY)),
        (CKA_KEY_TYPE, ulong(CKK_ML_DSA)),
        (CKA_TOKEN, vec![0]),
        (CKA_PRIVATE, vec![1]),
        (CKA_SENSITIVE, vec![1]),
        (CKA_SIGN, vec![1]),
        (CKA_PARAMETER_SET, ulong(ps)),
        (CKA_VALUE, sk.to_vec()),
    ];
    let mut w = words(&entries);
    let mut h: u32 = 0;
    let rv = C_CreateObject(SESSION, w.as_mut_ptr() as *mut u8, entries.len() as u32, &mut h);
    (rv, h)
}

/// `C_GenerateKeyPair(CKM_ML_DSA_KEY_PAIR_GEN)` with `CKA_SEED = seed` in the
/// PRIVATE template, exactly as the hub's Wycheproof driver sends it.
/// Returns (rv, h_pub, h_prv).
fn generate_from_seed(ps: u32, seed: &[u8]) -> (u32, u32, u32) {
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
        (CKA_SEED, seed.to_vec()),
    ];
    keypair(CKM_ML_DSA_KEY_PAIR_GEN, &pub_entries, &prv_entries)
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

/// Deterministic sign (CK_SIGN_ADDITIONAL_CONTEXT hedgeVariant =
/// CKH_DETERMINISTIC_REQUIRED, context `ctx`) over `data`. `Err((step, rv))`
/// names the call that refused.
fn sign_deterministic(h_key: u32, mech: u32, data: &[u8], ctx: &[u8]) -> Result<Vec<u8>, (&'static str, u32)> {
    let params: [usize; 3] = [
        CKH_DETERMINISTIC_REQUIRED as usize,
        if ctx.is_empty() { 0 } else { ctx.as_ptr() as usize },
        ctx.len(),
    ];
    let mut m: [usize; 3] = [mech as usize, params.as_ptr() as usize, std::mem::size_of_val(&params)];
    let rv = C_SignInit(SESSION, m.as_mut_ptr() as *mut u8, h_key);
    if rv != CKR_OK {
        return Err(("C_SignInit", rv));
    }
    let mut sig = vec![0u8; 8192];
    let mut len = sig.len() as u32;
    let rv = C_Sign(SESSION, data.as_ptr() as *mut u8, data.len() as u32, sig.as_mut_ptr(), &mut len);
    if rv != CKR_OK {
        return Err(("C_Sign", rv));
    }
    sig.truncate(len as usize);
    Ok(sig)
}

fn obj_value(h: u32) -> Vec<u8> {
    crate::state::get_object_value(h).expect("CKA_VALUE")
}

fn destroy(h: u32) {
    if h != 0 {
        OBJECTS.with(|o| o.borrow_mut().remove(&h));
    }
}

fn is_internal(t: &Value) -> bool {
    t["flags"]
        .as_array()
        .map(|f| f.iter().any(|x| x == "Internal"))
        .unwrap_or(false)
}

/// The signing step of one Wycheproof sign case against `h_prv`: external µ
/// (vendor 0x403c) for an `Internal` case, pure ML-DSA over msg otherwise.
fn sign_case(h_prv: u32, t: &Value) -> Result<Vec<u8>, (&'static str, u32)> {
    if is_internal(t) {
        sign_deterministic(h_prv, CKM_ML_DSA_EXTERNAL_MU, &unhex(t["mu"].as_str().unwrap()), &[])
    } else {
        let ctx = t["ctx"].as_str().map(unhex).unwrap_or_default();
        sign_deterministic(h_prv, CKM_ML_DSA, &unhex(t["msg"].as_str().unwrap_or("")), &ctx)
    }
}

// ── B1: out-of-range s1 / s2 ────────────────────────────────────────────────

/// B1 through `C_CreateObject` (PKCS#11 v3.2 §4.1.1 rule 2): each of the six
/// Wycheproof `InvalidPrivateKey` keys → exactly CKR_ATTRIBUTE_VALUE_INVALID,
/// no object. Before the fix all six returned CKR_OK and then signed.
#[test]
fn wycheproof_sk_out_of_range_refused_at_create_object() {
    let _guard = test_lock::acquire();
    setup();
    for (v, tg, tc) in SK_RANGE_CASES {
        let doc = fixture(v, "noseed");
        let (g, t) = case(&doc, tg, tc);
        assert_eq!(t["result"], "invalid");
        assert!(t["comment"].as_str().unwrap().contains("out of range"), "{}", t["comment"]);
        let sk = unhex(g["privateKey"].as_str().unwrap());
        assert_eq!(
            crate::native::keygen::ml_dsa_sk_range_check(ps_of(v), &sk),
            Some(false),
            "ML-DSA-{v} tg{tg}/tc{tc}: range check verdict"
        );
        let (rv, h) = import_sk(ps_of(v), &sk);
        destroy(h);
        assert_eq!(
            rv, CKR_ATTRIBUTE_VALUE_INVALID,
            "ML-DSA-{v} tg{tg}/tc{tc} ({}): C_CreateObject must refuse the key",
            t["comment"]
        );
        assert_eq!(h, 0, "ML-DSA-{v} tg{tg}/tc{tc}: no object may be created");
    }
}

/// B1 for a key that is ALREADY in the store — one created before this fix,
/// or restored from a snapshot — placed there directly, bypassing every
/// import check. `C_SignInit` and `C_MessageSignInit` refuse it with
/// CKR_KEY_TYPE_INCONSISTENT (§5.13.1 / §5.1.6; the code this engine already
/// returns for ML-DSA key material that cannot be decoded), and no signature
/// is produced, deterministic or hedged.
#[test]
fn wycheproof_sk_out_of_range_already_stored_refused_at_sign_init() {
    let _guard = test_lock::acquire();
    setup();
    for (v, tg, tc) in SK_RANGE_CASES {
        let doc = fixture(v, "noseed");
        let (g, _) = case(&doc, tg, tc);
        let sk = unhex(g["privateKey"].as_str().unwrap());
        let mut attrs = Attributes::new();
        store_ulong(&mut attrs, CKA_CLASS, CKO_PRIVATE_KEY);
        store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_ML_DSA);
        store_param_set(&mut attrs, ps_of(v));
        store_bool(&mut attrs, CKA_TOKEN, false);
        store_bool(&mut attrs, CKA_PRIVATE, false);
        store_bool(&mut attrs, CKA_SIGN, true);
        attrs.insert(CKA_VALUE, sk);
        let h = crate::state::allocate_handle_owned(SESSION, attrs);

        let det = sign_deterministic(h, CKM_ML_DSA, b"Hello world", &[]);
        assert_eq!(det, Err(("C_SignInit", CKR_KEY_TYPE_INCONSISTENT)), "ML-DSA-{v} tg{tg}/tc{tc} deterministic");
        // Hedged (no parameter): on native builds this is the AWS-LC route.
        let mut m: [usize; 3] = [CKM_ML_DSA as usize, 0, 0];
        assert_eq!(
            C_SignInit(SESSION, m.as_mut_ptr() as *mut u8, h),
            CKR_KEY_TYPE_INCONSISTENT,
            "ML-DSA-{v} tg{tg}/tc{tc} hedged"
        );
        assert_eq!(
            C_MessageSignInit(SESSION, m.as_mut_ptr() as *mut u8, h),
            CKR_KEY_TYPE_INCONSISTENT,
            "ML-DSA-{v} tg{tg}/tc{tc} C_MessageSignInit"
        );
        destroy(h);
    }
}

/// B1 below the PKCS#11 layer: every signing entry point the engine and the
/// KMIP server call with raw key bytes refuses an out-of-range key — the
/// hedged pure route (AWS-LC on native builds), the deterministic,
/// pre-hash, internal and external-µ routes (fips204), and KMIP's
/// `register_ml_dsa_private_key`.
#[test]
fn wycheproof_sk_out_of_range_refused_by_every_signing_route() {
    let _guard = test_lock::acquire();
    setup();
    use crate::crypto::handlers as hd;
    for (v, tg, tc) in SK_RANGE_CASES {
        let doc = fixture(v, "noseed");
        let (g, _) = case(&doc, tg, tc);
        let sk = unhex(g["privateKey"].as_str().unwrap());
        let ps = ps_of(v);
        let tag = format!("ML-DSA-{v} tg{tg}/tc{tc}");
        assert!(hd::sign_ml_dsa(CKM_ML_DSA, ps, &sk, b"m", &[], false).is_err(), "{tag}: hedged");
        assert!(hd::sign_ml_dsa(CKM_ML_DSA, ps, &sk, b"m", &[], true).is_err(), "{tag}: deterministic");
        assert!(
            hd::sign_ml_dsa(CKM_HASH_ML_DSA_SHA256, ps, &sk, b"m", &[], true).is_err(),
            "{tag}: HashML-DSA"
        );
        assert!(hd::sign_ml_dsa_internal(ps, &sk, b"m", &[], [0u8; 32]).is_err(), "{tag}: internal");
        assert!(hd::sign_ml_dsa_external_mu(ps, &sk, &[0u8; 64], [0u8; 32]).is_err(), "{tag}: external mu");
        assert!(hd::sign_ml_dsa_external_mu_hedged(ps, &sk, &[0u8; 64]).is_err(), "{tag}: external mu hedged");
        assert!(hd::sign_ml_dsa_external_rnd(ps, &sk, b"m", &[], [0u8; 32]).is_err(), "{tag}: external rnd");
        assert_eq!(
            crate::native::keygen::register_ml_dsa_private_key(SESSION, ps, &sk, b"id", "l"),
            Err(CKR_ATTRIBUTE_VALUE_INVALID),
            "{tag}: KMIP register"
        );
    }
}

/// B1 through `C_UnwrapKey` (AES-KWP): an out-of-range key is refused with
/// CKR_WRAPPED_KEY_INVALID (§5.18.4, the code the SLH-DSA PK.root check at
/// the same site already uses); the matching in-range key from the same
/// fixture still unwraps.
#[test]
fn wycheproof_sk_out_of_range_refused_at_unwrap() {
    let _guard = test_lock::acquire();
    setup();
    let kek_bytes = [0x5au8; 32];
    let kek_entries = vec![
        (CKA_CLASS, ulong(CKO_SECRET_KEY)),
        (CKA_KEY_TYPE, ulong(CKK_AES)),
        (CKA_TOKEN, vec![0]),
        (CKA_UNWRAP, vec![1]),
        (CKA_VALUE, kek_bytes.to_vec()),
    ];
    let mut kw = words(&kek_entries);
    let mut kek = 0u32;
    assert_eq!(C_CreateObject(SESSION, kw.as_mut_ptr() as *mut u8, 5, &mut kek), CKR_OK);
    let unwrap = |ps: u32, sk: &[u8]| -> (u32, u32) {
        let mut wrapped = crate::crypto::aeskw::kwp_wrap(&kek_bytes, sk).ok().unwrap();
        let entries = vec![
            (CKA_CLASS, ulong(CKO_PRIVATE_KEY)),
            (CKA_KEY_TYPE, ulong(CKK_ML_DSA)),
            (CKA_PARAMETER_SET, ulong(ps)),
            (CKA_TOKEN, vec![0]),
            (CKA_SIGN, vec![1]),
        ];
        let w = words(&entries);
        let mut m: [usize; 3] = [CKM_AES_KEY_WRAP_KWP as usize, 0, 0];
        let mut h = 0u32;
        let rv = C_UnwrapKey(
            SESSION,
            m.as_mut_ptr() as *mut u8,
            kek,
            wrapped.as_mut_ptr(),
            wrapped.len() as u32,
            w.as_ptr() as *mut u8,
            entries.len() as u32,
            &mut h,
        );
        (rv, h)
    };
    for (v, tg, tc) in SK_RANGE_CASES {
        let doc = fixture(v, "noseed");
        let (g, _) = case(&doc, tg, tc);
        let (rv, h) = unwrap(ps_of(v), &unhex(g["privateKey"].as_str().unwrap()));
        destroy(h);
        assert_eq!(rv, CKR_WRAPPED_KEY_INVALID, "ML-DSA-{v} tg{tg}/tc{tc}");
        // tg1 holds a valid key in every noseed file.
        let good = unhex(doc["testGroups"][0]["privateKey"].as_str().unwrap());
        let (rv, h) = unwrap(ps_of(v), &good);
        destroy(h);
        assert_eq!(rv, CKR_OK, "ML-DSA-{v} tg1 valid key must still unwrap");
    }
    destroy(kek);
}

/// The range check is exact at its boundary, for every parameter set: a
/// fresh key with its first s1 coefficient, first s2 coefficient or last s2
/// coefficient set to the encoded value 2η (coefficient −η, legal) is
/// accepted; set to 2η + 1 (coefficient −η − 1) it is refused. t0 is never
/// refused (its 13-bit field holds exactly [−2^12 + 1, 2^12], FIPS 204
/// Algorithm 25 line 9).
#[test]
fn ml_dsa_sk_range_check_boundaries() {
    use crate::native::keygen::ml_dsa_sk_range_check;
    // (ps, η, bitlen(2η), k, l)
    for (ps, eta, c, k, l) in [
        (CKP_ML_DSA_44, 2u32, 3usize, 4usize, 4usize),
        (CKP_ML_DSA_65, 4, 4, 6, 5),
        (CKP_ML_DSA_87, 2, 3, 8, 7),
    ] {
        let (_, sk) = crate::crypto::handlers::ml_dsa_keygen_from_seed(ps, &[7u8; 32]).unwrap();
        assert_eq!(ml_dsa_sk_range_check(ps, &sk), Some(true), "ps {ps:#x}: fresh key");
        // Write `x` into coefficient number `idx` of the packed s1‖s2 field.
        let set = |sk: &mut Vec<u8>, idx: usize, x: u32| {
            for b in 0..c {
                let bit = idx * c + b;
                let (byte, off) = (128 + bit / 8, bit % 8);
                if (x >> b) & 1 == 1 {
                    sk[byte] |= 1 << off;
                } else {
                    sk[byte] &= !(1 << off);
                }
            }
        };
        let last = (k + l) * 256 - 1;
        for idx in [0usize, l * 256, last] {
            let mut ok = sk.clone();
            set(&mut ok, idx, 2 * eta);
            assert_eq!(ml_dsa_sk_range_check(ps, &ok), Some(true), "ps {ps:#x} coeff {idx} = -η");
            set(&mut ok, idx, 0);
            assert_eq!(ml_dsa_sk_range_check(ps, &ok), Some(true), "ps {ps:#x} coeff {idx} = +η");
            let mut bad = sk.clone();
            set(&mut bad, idx, 2 * eta + 1);
            assert_eq!(ml_dsa_sk_range_check(ps, &bad), Some(false), "ps {ps:#x} coeff {idx} = -η-1");
        }
        // t0: flip every bit of the field; still in range by construction.
        let mut t0 = sk.clone();
        let t0_start = 128 + (k + l) * 256 * c / 8;
        for b in t0[t0_start..].iter_mut() {
            *b ^= 0xff;
        }
        assert_eq!(ml_dsa_sk_range_check(ps, &t0), Some(true), "ps {ps:#x}: t0 is never out of range");
        // Wrong length; no / unknown parameter set (CKP_* values are only
        // unique per key type, so "not ML-DSA" is the caller's key-type test).
        assert_eq!(ml_dsa_sk_range_check(ps, &sk[..sk.len() - 1]), Some(false));
        assert_eq!(ml_dsa_sk_range_check(0, &sk), None);
        assert_eq!(ml_dsa_sk_range_check(0x7fff, &sk), None);
    }
}

// ── B2: empty CKA_SEED ──────────────────────────────────────────────────────

/// B2 for ML-DSA, the three Wycheproof "empty private seed" cases:
/// `C_GenerateKeyPair` with a zero-length CKA_SEED → exactly
/// CKR_ATTRIBUTE_VALUE_INVALID (§4.1.1 rule 2), no objects. Before the fix
/// each returned CKR_OK with a RANDOM key pair.
#[test]
fn wycheproof_empty_seed_refused_at_generate_key_pair() {
    let _guard = test_lock::acquire();
    setup();
    for (v, tg, tc) in EMPTY_SEED_CASES {
        let doc = fixture(v, "seed");
        let (g, t) = case(&doc, tg, tc);
        assert_eq!(t["result"], "invalid");
        assert_eq!(t["comment"], "empty private seed");
        let seed = unhex(g["privateSeed"].as_str().unwrap());
        assert!(seed.is_empty());
        let (rv, h_pub, h_prv) = generate_from_seed(ps_of(v), &seed);
        destroy(h_pub);
        destroy(h_prv);
        assert_eq!(rv, CKR_ATTRIBUTE_VALUE_INVALID, "ML-DSA-{v} tg{tg}/tc{tc}");
        assert_eq!((h_pub, h_prv), (0, 0), "ML-DSA-{v} tg{tg}/tc{tc}: no objects");
    }
}

/// B2 for every key-generation mechanism that reads CKA_SEED — ML-DSA,
/// ML-KEM and SLH-DSA (deterministic generation) and the two vendor KEMs
/// (which refuse any seed): a zero-length CKA_SEED, in the private template
/// or in the public one (each site's fallback), is refused with
/// CKR_ATTRIBUTE_VALUE_INVALID instead of being read as "no seed". A
/// zero-length value with a non-NULL pValue is refused the same way.
#[test]
fn empty_cka_seed_refused_for_every_seeded_keygen() {
    let _guard = test_lock::acquire();
    setup();
    let cases: [(&str, u32, u32, u32); 9] = [
        ("ML-DSA-44", CKM_ML_DSA_KEY_PAIR_GEN, CKK_ML_DSA, CKP_ML_DSA_44),
        ("ML-DSA-87", CKM_ML_DSA_KEY_PAIR_GEN, CKK_ML_DSA, CKP_ML_DSA_87),
        ("ML-KEM-512", CKM_ML_KEM_KEY_PAIR_GEN, CKK_ML_KEM, CKP_ML_KEM_512),
        ("ML-KEM-768", CKM_ML_KEM_KEY_PAIR_GEN, CKK_ML_KEM, CKP_ML_KEM_768),
        ("ML-KEM-1024", CKM_ML_KEM_KEY_PAIR_GEN, CKK_ML_KEM, CKP_ML_KEM_1024),
        ("SLH-DSA-SHA2-128F", CKM_SLH_DSA_KEY_PAIR_GEN, CKK_SLH_DSA, CKP_SLH_DSA_SHA2_128F),
        ("SLH-DSA-SHAKE-256F", CKM_SLH_DSA_KEY_PAIR_GEN, CKK_SLH_DSA, CKP_SLH_DSA_SHAKE_256F),
        ("FrodoKEM-976-AES", CKM_PQCTODAY_FRODOKEM_KEY_PAIR_GEN, 0, CKP_FRODOKEM_976_AES),
        (
            "Classic-McEliece-6688128",
            CKM_PQCTODAY_CLASSIC_MCELIECE_KEY_PAIR_GEN,
            0,
            CKP_CLASSIC_MCELIECE_6688128,
        ),
    ];
    let mut wrong: Vec<String> = Vec::new();
    for (name, mech, kt, ps) in cases {
        for in_private in [true, false] {
            let mut pub_entries = vec![(CKA_TOKEN, vec![0]), (CKA_PARAMETER_SET, ulong(ps))];
            let mut prv_entries = vec![(CKA_TOKEN, vec![0]), (CKA_PRIVATE, vec![1])];
            if kt != 0 {
                pub_entries.push((CKA_KEY_TYPE, ulong(kt)));
                prv_entries.push((CKA_KEY_TYPE, ulong(kt)));
            }
            let target = if in_private { &mut prv_entries } else { &mut pub_entries };
            target.push((CKA_SEED, Vec::new()));
            let (rv, h_pub, h_prv) = keypair(mech, &pub_entries, &prv_entries);
            destroy(h_pub);
            destroy(h_prv);
            let tpl = if in_private { "private" } else { "public" };
            if rv != CKR_ATTRIBUTE_VALUE_INVALID {
                wrong.push(format!("{name}: empty CKA_SEED in the {tpl} template -> rv {rv:#x}"));
            }
        }
        // Zero ulValueLen with a non-NULL pValue (a caller passing an empty
        // but allocated buffer).
        let dummy = [0u8; 1];
        let mut pub_entries = vec![(CKA_TOKEN, vec![0]), (CKA_PARAMETER_SET, ulong(ps))];
        if kt != 0 {
            pub_entries.push((CKA_KEY_TYPE, ulong(kt)));
        }
        let mut pw = words(&pub_entries);
        let mut sw: Vec<usize> = vec![CKA_SEED as usize, dummy.as_ptr() as usize, 0];
        let mut m: [usize; 3] = [mech as usize, 0, 0];
        let (mut h_pub, mut h_prv) = (0u32, 0u32);
        let rv = C_GenerateKeyPair(
            SESSION,
            m.as_mut_ptr() as *mut u8,
            pw.as_mut_ptr() as *mut u8,
            pub_entries.len() as u32,
            sw.as_mut_ptr() as *mut u8,
            1,
            &mut h_pub,
            &mut h_prv,
        );
        destroy(h_pub);
        destroy(h_prv);
        if rv != CKR_ATTRIBUTE_VALUE_INVALID {
            wrong.push(format!("{name}: empty non-NULL CKA_SEED -> rv {rv:#x}"));
        }
    }
    assert!(wrong.is_empty(), "{} empty-seed key generation(s) not refused:\n{}", wrong.len(), wrong.join("\n"));
}

// ── Full files: no over-rejection ───────────────────────────────────────────

/// Every case of the three `sign_noseed` files: a `valid` case imports with
/// CKR_OK and signs deterministically byte-exact to Wycheproof's signature;
/// an `invalid` case (wrong sk length, s1/s2 out of range, ctx > 255 bytes)
/// is refused at some step. Counts are asserted so a fixture or harness
/// change cannot silently shrink the run.
#[test]
fn wycheproof_sign_noseed_files_all_cases() {
    let _guard = test_lock::acquire();
    setup();
    let mut wrong: Vec<String> = Vec::new();
    for (v, want_valid, want_invalid) in [(44u32, 67usize, 5usize), (65, 72, 5), (87, 63, 5)] {
        let doc = fixture(v, "noseed");
        let ps = ps_of(v);
        let (mut valid, mut invalid) = (0usize, 0usize);
        for (gi, g) in doc["testGroups"].as_array().unwrap().iter().enumerate() {
            let sk = unhex(g["privateKey"].as_str().unwrap());
            for t in g["tests"].as_array().unwrap() {
                let tag = format!("ML-DSA-{v} tg{}/tc{} ({})", gi + 1, t["tcId"], t["comment"]);
                let (rv, h) = import_sk(ps, &sk);
                let outcome = if rv != CKR_OK {
                    Err(("C_CreateObject", rv))
                } else {
                    sign_case(h, t)
                };
                destroy(h);
                match t["result"].as_str().unwrap() {
                    "valid" => {
                        valid += 1;
                        match outcome {
                            Err(e) => wrong.push(format!("{tag}: valid case refused at {e:?}")),
                            Ok(sig) if sig != unhex(t["sig"].as_str().unwrap()) => {
                                wrong.push(format!("{tag}: signature differs"))
                            }
                            Ok(_) => {}
                        }
                    }
                    "invalid" => {
                        invalid += 1;
                        if outcome.is_ok() {
                            wrong.push(format!("{tag}: invalid case was signed"));
                        }
                    }
                    other => panic!("{tag}: unexpected result {other}"),
                }
            }
        }
        assert_eq!((valid, invalid), (want_valid, want_invalid), "ML-DSA-{v} noseed case counts");
    }
    assert!(wrong.is_empty(), "{} noseed case(s) disagree with Wycheproof:\n{}", wrong.len(), wrong.join("\n"));
}

/// Every case of the three `sign_seed` files: a `valid` case generates from
/// `privateSeed` with CKR_OK, its public key byte-matches Wycheproof's, and
/// it signs byte-exact; an `invalid` case (seed of 0, 31 or 33 bytes, ctx >
/// 255 bytes) is refused at some step.
#[test]
fn wycheproof_sign_seed_files_all_cases() {
    let _guard = test_lock::acquire();
    setup();
    let mut wrong: Vec<String> = Vec::new();
    for (v, want_valid, want_invalid) in [(44u32, 81usize, 4usize), (65, 100, 4), (87, 91, 4)] {
        let doc = fixture(v, "seed");
        let ps = ps_of(v);
        let (mut valid, mut invalid) = (0usize, 0usize);
        for (gi, g) in doc["testGroups"].as_array().unwrap().iter().enumerate() {
            let seed = unhex(g["privateSeed"].as_str().unwrap());
            for t in g["tests"].as_array().unwrap() {
                let tag = format!("ML-DSA-{v} tg{}/tc{} ({})", gi + 1, t["tcId"], t["comment"]);
                let (rv, h_pub, h_prv) = generate_from_seed(ps, &seed);
                let outcome = if rv != CKR_OK {
                    Err(("C_GenerateKeyPair", rv))
                } else {
                    match g["publicKey"].as_str() {
                        Some(pk) if obj_value(h_pub) != unhex(pk) => Err(("public key from seed differs", CKR_OK)),
                        _ => sign_case(h_prv, t),
                    }
                };
                destroy(h_pub);
                destroy(h_prv);
                match t["result"].as_str().unwrap() {
                    "valid" => {
                        valid += 1;
                        match outcome {
                            Err(e) => wrong.push(format!("{tag}: valid case refused at {e:?}")),
                            Ok(sig) if sig != unhex(t["sig"].as_str().unwrap()) => {
                                wrong.push(format!("{tag}: signature differs"))
                            }
                            Ok(_) => {}
                        }
                    }
                    "invalid" => {
                        invalid += 1;
                        if outcome.is_ok() {
                            wrong.push(format!("{tag}: invalid case was signed"));
                        }
                    }
                    other => panic!("{tag}: unexpected result {other}"),
                }
            }
        }
        assert_eq!((valid, invalid), (want_valid, want_invalid), "ML-DSA-{v} seed case counts");
    }
    assert!(wrong.is_empty(), "{} seed case(s) disagree with Wycheproof:\n{}", wrong.len(), wrong.join("\n"));
}
