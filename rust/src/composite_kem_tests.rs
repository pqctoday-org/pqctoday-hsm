//! Composite ML-KEM through the PKCS#11 boundary — PKCS#11 v3.3 working draft
//! (`comp_kem.md`, OASIS PKCS 11 TC commit 9ef73f9) over
//! draft-ietf-lamps-pq-composite-kem-23. Plan workstream A2/A3 and the KEM
//! halves of V3 (vector consistency) and V6 (derived negative vectors).
//!
//! Vectors: `rust/kat/pkcs11-v33/composite-kem/testvectors.json`, the LAMPS
//! upstream file (provenance: `rust/kat/pkcs11-v33/PROVENANCE.md`; its
//! sha256 is pinned by `native::composite_vectors`). Encapsulation is
//! randomised, so the vectors prove decapsulation exactly (`dk`, `c` → `k`);
//! encapsulation is proven by round trip.
//!
//! Included from `ffi.rs` via `#[path]` so `use super::*` resolves to the FFI
//! module and its private helpers, like `mlkem_input_check_tests`.

use super::*;
use crate::native::composite::{kem_params, CompositeKemParams, CompositeParams, EcCurve, KemClassical, COMPOSITE_KEM_SETS};
use crate::native::composite_key::{self, Layout};
use crate::native::composite_vectors::{b64, tlv, KEM_VECTORS};
use crate::native::test_lock;
use serde_json::Value;

/// High fixed session handle, disjoint from every other ffi test module.
const SESSION: u32 = 0x4D50_4C01;

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

/// One composite LAMPS vector, decoded.
struct Vector {
    p: &'static CompositeKemParams,
    ek: Vec<u8>,
    dk: Vec<u8>,
    dk_pkcs8: Vec<u8>,
    c: Vec<u8>,
    k: Vec<u8>,
    x5c: Vec<u8>,
}

fn doc() -> Value {
    serde_json::from_slice(KEM_VECTORS).expect("vector file parses")
}

fn field(e: &Value, f: &str) -> Vec<u8> {
    b64(e[f].as_str().unwrap_or_else(|| panic!("field {f}")))
}

/// The 12 composite vectors, in table (CKP) order.
fn vectors() -> Vec<Vector> {
    let d = doc();
    let tests = d["tests"].as_array().unwrap();
    COMPOSITE_KEM_SETS
        .iter()
        .map(|p| {
            let e = tests.iter().find(|e| e["tcId"] == p.name).unwrap_or_else(|| panic!("no vector {}", p.name));
            Vector {
                p,
                ek: field(e, "ek"),
                dk: field(e, "dk"),
                dk_pkcs8: field(e, "dk_pkcs8"),
                c: field(e, "c"),
                k: field(e, "k"),
                x5c: field(e, "x5c"),
            }
        })
        .collect()
}

fn supported() -> Vec<Vector> {
    vectors().into_iter().filter(|v| v.p.supported).collect()
}

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

fn import_private(ckp: u32, dk: &[u8], extra: Vec<(u32, Vec<u8>)>) -> (u32, u32) {
    let mut t = vec![
        (CKA_CLASS, ulong(CKO_PRIVATE_KEY)),
        (CKA_KEY_TYPE, ulong(CKK_COMP_KEM)),
        (CKA_PARAMETER_SET, ulong(ckp)),
        (CKA_DECAPSULATE, vec![1]),
        (CKA_SENSITIVE, vec![1]),
        (CKA_EXTRACTABLE, vec![0]),
        (CKA_TOKEN, vec![0]),
        (CKA_PRIVATE, vec![0]),
        (CKA_VALUE, dk.to_vec()),
    ];
    t.extend(extra);
    create(t)
}

fn import_public(ckp: u32, ek: &[u8]) -> (u32, u32) {
    create(vec![
        (CKA_CLASS, ulong(CKO_PUBLIC_KEY)),
        (CKA_KEY_TYPE, ulong(CKK_COMP_KEM)),
        (CKA_PARAMETER_SET, ulong(ckp)),
        (CKA_ENCAPSULATE, vec![1]),
        (CKA_TOKEN, vec![0]),
        (CKA_VALUE, ek.to_vec()),
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

fn generate_comp_kem(ckp: u32) -> (u32, u32, u32) {
    generate(CKM_COMP_KEM_KEY_PAIR_GEN, vec![(CKA_PARAMETER_SET, ulong(ckp))], vec![(CKA_PRIVATE, vec![0])])
}

/// `CK_MECHANISM` words; `param` non-empty sets pParameter/ulParameterLen.
fn mech(m: u32, param: &[u8]) -> [usize; 3] {
    if param.is_empty() {
        [m as usize, 0, 0]
    } else {
        [m as usize, param.as_ptr() as usize, param.len()]
    }
}

/// C_EncapsulateKey with a buffer of `cap` bytes (`0`: a NULL pCiphertext,
/// the length query) → (rv, ct or the queried length's worth, ss handle).
fn encapsulate_with(m: u32, param: &[u8], h_pub: u32, cap: usize) -> (u32, Vec<u8>, u32) {
    let mut mm = mech(m, param);
    let mut ct = vec![0u8; cap];
    let mut ct_len = cap as u32;
    let mut h: u32 = 0;
    let p_ct = if cap == 0 { std::ptr::null_mut() } else { ct.as_mut_ptr() };
    let rv = C_EncapsulateKey(
        SESSION,
        mm.as_mut_ptr() as *mut u8,
        h_pub,
        std::ptr::null_mut(),
        0,
        p_ct,
        &mut ct_len,
        &mut h,
    );
    if cap == 0 {
        ct = vec![0u8; ct_len as usize];
    }
    ct.truncate(ct_len as usize);
    (rv, ct, h)
}

fn decapsulate_with(m: u32, param: &[u8], h_prv: u32, ct: &[u8]) -> (u32, u32) {
    let mut mm = mech(m, param);
    let mut ct = ct.to_vec();
    let mut h: u32 = 0;
    let rv = C_DecapsulateKey(
        SESSION,
        mm.as_mut_ptr() as *mut u8,
        h_prv,
        std::ptr::null_mut(),
        0,
        ct.as_mut_ptr(),
        ct.len() as u32,
        &mut h,
    );
    (rv, h)
}

fn decapsulate(h_prv: u32, ct: &[u8]) -> (u32, u32) {
    decapsulate_with(CKM_COMP_KEM, &[], h_prv, ct)
}

fn value(h: u32) -> Vec<u8> {
    crate::state::get_object_value(h).expect("object has CKA_VALUE")
}

fn attr(h: u32, t: u32) -> Option<Vec<u8>> {
    crate::state::get_object_attr_bytes(h, t)
}

fn flag(h: u32, t: u32) -> bool {
    attr(h, t).is_some_and(|v| v.first() == Some(&1))
}

fn destroy(hs: &[u32]) {
    for &h in hs {
        if h != 0 {
            OBJECTS.with(|o| o.borrow_mut().remove(&h));
        }
    }
}

/// The SubjectPublicKeyInfo TLV of an X.509 certificate (RFC 5280 §4.1).
fn cert_spki(cert: &[u8]) -> Vec<u8> {
    let (t, cert_body, _) = tlv(cert, 0);
    assert_eq!(t, 0x30);
    let (t, tbs, tbs_len) = tlv(cert, cert_body);
    assert_eq!(t, 0x30);
    let mut i = tbs;
    let mut fields = Vec::new();
    while i < tbs + tbs_len && fields.len() < 7 {
        let (t, s, l) = tlv(cert, i);
        fields.push((t, i, s + l));
        i = s + l;
    }
    let skip = usize::from(fields[0].0 == 0xa0);
    let (t, start, end) = fields[skip + 5];
    assert_eq!(t, 0x30, "subjectPublicKeyInfo");
    cert[start..end].to_vec()
}

/// (algorithm OID body, privateKey OCTET STRING contents) of a PKCS#8
/// OneAsymmetricKey (RFC 5958 §2), which must hold nothing else.
fn pkcs8_parts(der: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (t, body, len) = tlv(der, 0);
    assert_eq!((t, body + len), (0x30, der.len()));
    let (t, v, vl) = tlv(der, body);
    assert_eq!((t, &der[v..v + vl]), (0x02, &[0u8][..]), "version 0");
    let (t, a, al) = tlv(der, v + vl);
    assert_eq!(t, 0x30);
    let (t, o, ol) = tlv(der, a);
    assert_eq!((t, o + ol), (0x06, a + al), "algorithm: OID, parameters absent");
    let (t, k, kl) = tlv(der, a + al);
    assert_eq!((t, k + kl), (0x04, der.len()), "privateKey last");
    (der[o..o + ol].to_vec(), der[k..k + kl].to_vec())
}

/// `tradPK` from `tradSK` by a route independent of `composite_key`: each
/// component's own crate parser (`sec1` ECPrivateKey for EC, PKCS#1 for RSA).
fn independent_trad_public(c: KemClassical, sk: &[u8]) -> Vec<u8> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    match c {
        KemClassical::RsaOaep { .. } => {
            use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPublicKey};
            let k = rsa::RsaPrivateKey::from_pkcs1_der(sk).expect("RSAPrivateKey");
            rsa::RsaPublicKey::from(&k).to_pkcs1_der().unwrap().as_bytes().to_vec()
        }
        KemClassical::Ecdh { curve: EcCurve::P256 } => {
            p256::SecretKey::from_sec1_der(sk).unwrap().public_key().to_encoded_point(false).as_bytes().to_vec()
        }
        KemClassical::Ecdh { curve: EcCurve::P384 } => {
            p384::SecretKey::from_sec1_der(sk).unwrap().public_key().to_encoded_point(false).as_bytes().to_vec()
        }
        KemClassical::Ecdh { curve: EcCurve::P521 } => {
            p521::SecretKey::from_sec1_der(sk).unwrap().public_key().to_encoded_point(false).as_bytes().to_vec()
        }
        KemClassical::X25519 => {
            let k: [u8; 32] = sk.try_into().unwrap();
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(k)).as_bytes().to_vec()
        }
        KemClassical::X448 => {
            let k: [u8; 56] = sk.try_into().unwrap();
            x448::PublicKey::from(&x448::StaticSecret::from(k)).as_bytes().to_vec()
        }
        other => panic!("no independent derivation for {other:?}"),
    }
}

// ── V3: the vectors themselves ─────────────────────────────────────────────

/// Plan V3 (KEM): every composite vector is internally consistent when
/// checked with the engine's already-trusted single-algorithm code and
/// independent parsers — before any composite code is trusted with it.
/// Split `ek`/`dk` per draft §4.1/§4.2; ML-KEM `ek` re-derived from
/// `mlkemSeed` (FIPS 203 KeyGen_internal); the classical public key
/// re-derived from `tradSK`; every size against the parameter table;
/// `dk_pkcs8` wraps exactly `dk` under the set's OID; the `x5c`
/// certificate's SPKI is the set's OID (parameters absent) over exactly
/// `ek`. The two brainpool vectors are reported, not silently passed.
#[test]
fn v3_composite_kem_vectors_are_internally_consistent() {
    let mut checked = 0;
    let mut skipped = Vec::new();
    for v in vectors() {
        let p = v.p;
        let name = p.name;
        // Sizes against the table (draft §4 Table 1 + Appendix A).
        assert!(p.public_key_size().admits(v.ek.len()), "{name}: ek size {}", v.ek.len());
        assert!(p.private_key_size().admits(v.dk.len()), "{name}: dk size {}", v.dk.len());
        assert!(p.ciphertext_size().admits(v.c.len()), "{name}: c size {}", v.c.len());
        assert_eq!(v.k.len(), 32, "{name}: k is 256 bits (§3.4)");
        let layout = Layout::from(CompositeParams::Kem(p));
        let (ml_pk, trad_pk) = layout.split_public(&v.ek).unwrap_or_else(|| panic!("{name}: ek splits"));
        let (seed, trad_sk) = layout.split_private(&v.dk).unwrap_or_else(|| panic!("{name}: dk splits"));
        assert_eq!(ml_pk.len(), p.ml_kem_public_key_len(), "{name}");
        assert_eq!(seed.len(), 64, "{name}: mlkemSeed = d ‖ z");
        assert!(p.classical_sizes.output.admits(v.c.len() - p.ml_kem_ciphertext_len()), "{name}: tradCT size");

        // dk_pkcs8 wraps the same dk, under the set's OID.
        let (oid, inner) = pkcs8_parts(&v.dk_pkcs8);
        assert_eq!(oid, composite_key::oid_body(p.oid), "{name}: PKCS#8 OID");
        assert_eq!(inner, v.dk, "{name}: PKCS#8 privateKey is dk");

        // The certificate's SPKI is exactly the composite SPKI the engine
        // builds for ek (OID, parameters absent, BIT STRING = ek).
        assert_eq!(cert_spki(&v.x5c), composite_key::spki(p.oid, &v.ek), "{name}: x5c SPKI");

        if !p.supported {
            // Plan decision D2: brainpool comes last (A5). The engine must say
            // so, not pass the vector by accident.
            assert_eq!(
                composite_key::supported_layout(CKK_COMP_KEM, p.ckp, CKR_ATTRIBUTE_VALUE_INVALID).unwrap_err(),
                CKR_PARAMETER_SET_NOT_SUPPORTED,
                "{name}"
            );
            eprintln!("SKIP {name}: brainpool curve not in the engine yet (plan A5); sizes, PKCS#8 and x5c checked");
            skipped.push(name);
            continue;
        }

        // ML half: the engine's FIPS 203 KeyGen_internal(d, z).
        let (ek, _dk) = crate::crypto::handlers::ml_kem_keygen_from_seed(p.ml_kem, seed).unwrap();
        assert_eq!(ek, ml_pk, "{name}: mlkemPK from mlkemSeed");
        // Classical half: an independent parser, then the engine's own.
        assert_eq!(independent_trad_public(p.classical, trad_sk), trad_pk, "{name}: tradPK from tradSK");
        assert_eq!(
            composite_key::trad_public_from_private(layout.trad, trad_sk).unwrap(),
            trad_pk,
            "{name}: engine tradPK"
        );
        assert_eq!(composite_key::public_from_private(&layout, &v.dk).unwrap(), v.ek, "{name}");
        assert!(composite_key::public_is_valid(&layout, &v.ek), "{name}");
        checked += 1;
    }
    assert_eq!(checked, 10, "supported composite vectors");
    assert_eq!(skipped, ["id-MLKEM768-ECDH-brainpoolP256r1-SHA3-256", "id-MLKEM1024-ECDH-brainpoolP384r1-SHA3-256"]);

    // The two plain ML-KEM entries cross-check the single-algorithm code the
    // composite path builds on: KeyGen_internal from the 64-byte seed gives
    // ek, and Decaps gives k.
    let d = doc();
    for (tc, ps) in [("id-alg-ml-kem-768", CKP_ML_KEM_768), ("id-alg-ml-kem-1024", CKP_ML_KEM_1024)] {
        let e = d["tests"].as_array().unwrap().iter().find(|e| e["tcId"] == tc).unwrap();
        let (ek, dk) = crate::crypto::handlers::ml_kem_keygen_from_seed(ps, &field(e, "dk")).unwrap();
        assert_eq!(ek, field(e, "ek"), "{tc}: ek");
        assert_eq!(crate::crypto::handlers::ml_kem_decaps(ps, &dk, &field(e, "c")).unwrap(), field(e, "k"), "{tc}: k");
    }
}

// ── A2: objects ──────────────────────────────────────────────────────────

/// Import of every supported `dk` and `ek` (comp_kem.md object tables): the
/// engine re-derives the public key from the private value and stores the
/// composite SPKI, which equals the vector certificate's. Brainpool imports
/// are CKR_PARAMETER_SET_NOT_SUPPORTED.
#[test]
fn import_vector_keys_and_spki() {
    let _guard = test_lock::acquire();
    setup();
    for v in vectors() {
        let name = v.p.name;
        let spki = cert_spki(&v.x5c);
        if !v.p.supported {
            assert_eq!(import_private(v.p.ckp, &v.dk, vec![]).0, CKR_PARAMETER_SET_NOT_SUPPORTED, "{name}");
            assert_eq!(import_public(v.p.ckp, &v.ek).0, CKR_PARAMETER_SET_NOT_SUPPORTED, "{name}");
            continue;
        }
        let (rv, hk) = import_private(v.p.ckp, &v.dk, vec![]);
        assert_eq!(rv, CKR_OK, "{name}: private import");
        assert_eq!(attr(hk, CKA_PUBLIC_KEY_INFO), Some(spki.clone()), "{name}: private CKA_PUBLIC_KEY_INFO");
        let (rv, hp) = import_public(v.p.ckp, &v.ek);
        assert_eq!(rv, CKR_OK, "{name}: public import");
        assert_eq!(attr(hp, CKA_PUBLIC_KEY_INFO), Some(spki.clone()), "{name}: public CKA_PUBLIC_KEY_INFO");
        // A caller SPKI that matches is accepted.
        let (rv, hk2) = import_private(v.p.ckp, &v.dk, vec![(CKA_PUBLIC_KEY_INFO, spki)]);
        assert_eq!(rv, CKR_OK, "{name}: private import with matching SPKI");
        destroy(&[hk, hp, hk2]);
    }
}

/// The object model is shared by both families: CKK_COMP_SIG keys import
/// from the LAMPS signature vectors (`pk`, `sk` = mldsaSeed ‖ tradSK,
/// composite-sigs-19 §4.1/§4.2) with both public halves re-derived from the
/// private value, and the stored SPKI equals the vector certificate's. No
/// signature mechanism exists yet (step 3); the brainpool sets are refused.
#[test]
fn composite_sig_objects_import_from_lamps_vectors() {
    let _guard = test_lock::acquire();
    setup();
    let d: Value = serde_json::from_slice(crate::native::composite_vectors::SIG_VECTORS).unwrap();
    let mut imported = 0;
    for p in crate::native::composite::COMPOSITE_SIG_SETS.iter() {
        let e = d["tests"].as_array().unwrap().iter().find(|e| e["tcId"] == p.name).unwrap();
        let (pk, sk) = (field(e, "pk"), field(e, "sk"));
        let spki = cert_spki(&field(e, "x5c"));
        assert_eq!(spki, composite_key::spki(p.oid, &pk), "{}: x5c SPKI", p.name);
        let import = |class: u32, value: &[u8]| {
            create(vec![
                (CKA_CLASS, ulong(class)),
                (CKA_KEY_TYPE, ulong(CKK_COMP_SIG)),
                (CKA_PARAMETER_SET, ulong(p.ckp)),
                (CKA_TOKEN, vec![0]),
                (CKA_PRIVATE, vec![0]),
                (CKA_VALUE, value.to_vec()),
            ])
        };
        if !p.supported {
            assert_eq!(import(CKO_PRIVATE_KEY, &sk).0, CKR_PARAMETER_SET_NOT_SUPPORTED, "{}", p.name);
            continue;
        }
        let layout = Layout::from(CompositeParams::Sig(p));
        assert_eq!(composite_key::public_from_private(&layout, &sk).unwrap(), pk, "{}: pk from sk", p.name);
        let (rv, hk) = import(CKO_PRIVATE_KEY, &sk);
        assert_eq!(rv, CKR_OK, "{}: private import", p.name);
        assert_eq!(attr(hk, CKA_PUBLIC_KEY_INFO), Some(spki.clone()), "{}", p.name);
        let (rv, hp) = import(CKO_PUBLIC_KEY, &pk);
        assert_eq!(rv, CKR_OK, "{}: public import", p.name);
        assert_eq!(attr(hp, CKA_PUBLIC_KEY_INFO), Some(spki), "{}", p.name);
        destroy(&[hk, hp]);
        imported += 1;
    }
    assert_eq!(imported, 16);
}

/// Import refusals, PKCS#11 v3.2 §4.1.1 (codes listed on
/// `composite_key::check_imported_key`): halves of different keys against
/// the caller's SPKI → CKR_TEMPLATE_INCONSISTENT; a value one byte short →
/// CKR_ATTRIBUTE_VALUE_INVALID; no CKA_PARAMETER_SET → CKR_TEMPLATE_INCOMPLETE;
/// a CKA_PARAMETER_SET naming no set → CKR_ATTRIBUTE_VALUE_INVALID.
#[test]
fn import_refuses_swapped_halves_and_malformed_values() {
    let _guard = test_lock::acquire();
    setup();
    for v in supported() {
        let name = v.p.name;
        let spki = cert_spki(&v.x5c);
        let layout = Layout::from(CompositeParams::Kem(v.p));
        // Swap the traditional half for a fresh key of the same algorithm.
        let (_, other_trad) = composite_key::trad_generate(layout.trad).unwrap();
        let mut swapped = v.dk[..64].to_vec();
        swapped.extend_from_slice(&other_trad);
        assert_eq!(
            import_private(v.p.ckp, &swapped, vec![(CKA_PUBLIC_KEY_INFO, spki.clone())]).0,
            CKR_TEMPLATE_INCONSISTENT,
            "{name}: trad half swapped"
        );
        // Swap the ML half (another seed).
        let mut swapped = v.dk.clone();
        swapped[0] ^= 0x01;
        assert_eq!(
            import_private(v.p.ckp, &swapped, vec![(CKA_PUBLIC_KEY_INFO, spki.clone())]).0,
            CKR_TEMPLATE_INCONSISTENT,
            "{name}: ML half swapped"
        );
        // One byte short.
        assert_eq!(
            import_private(v.p.ckp, &v.dk[..v.dk.len() - 1], vec![]).0,
            CKR_ATTRIBUTE_VALUE_INVALID,
            "{name}: dk truncated"
        );
        assert_eq!(import_public(v.p.ckp, &v.ek[..v.ek.len() - 1]).0, CKR_ATTRIBUTE_VALUE_INVALID, "{name}: ek truncated");
        // The ML half alone.
        assert_eq!(import_public(v.p.ckp, &v.ek[..v.p.ml_kem_public_key_len()]).0, CKR_ATTRIBUTE_VALUE_INVALID, "{name}");
    }
    let v = &supported()[0];
    assert_eq!(
        create(vec![
            (CKA_CLASS, ulong(CKO_PRIVATE_KEY)),
            (CKA_KEY_TYPE, ulong(CKK_COMP_KEM)),
            (CKA_PRIVATE, vec![0]),
            (CKA_VALUE, v.dk.clone()),
        ])
        .0,
        CKR_TEMPLATE_INCOMPLETE,
        "no CKA_PARAMETER_SET"
    );
    assert_eq!(import_private(0x7f, &v.dk, vec![]).0, CKR_ATTRIBUTE_VALUE_INVALID, "unknown set");
}

/// Key-pair generation for every supported set (comp_kem.md "key pair
/// generation"): attribute contributions, sensitivity defaults, the SPKI,
/// and that the private CKA_VALUE never reads back; then an encapsulate →
/// decapsulate round trip through the FFI for each set.
#[test]
fn keygen_attributes_and_round_trip_all_supported_sets() {
    let _guard = test_lock::acquire();
    setup();
    for p in COMPOSITE_KEM_SETS.iter().filter(|p| p.supported) {
        let name = p.name;
        let (rv, hp, hk) = generate_comp_kem(p.ckp);
        assert_eq!(rv, CKR_OK, "{name}: keygen");
        let layout = Layout::from(CompositeParams::Kem(p));
        let pk = value(hp);
        assert!(composite_key::public_is_valid(&layout, &pk), "{name}: generated public value");
        for (h, class) in [(hp, CKO_PUBLIC_KEY), (hk, CKO_PRIVATE_KEY)] {
            assert_eq!(get_object_attr_u32(h, CKA_CLASS), Some(class), "{name}");
            assert_eq!(get_object_attr_u32(h, CKA_KEY_TYPE), Some(CKK_COMP_KEM), "{name}");
            assert_eq!(get_object_attr_u32(h, CKA_PARAMETER_SET), Some(p.ckp), "{name}: CKA_PARAMETER_SET");
            assert_eq!(get_object_attr_u32(h, CKA_KEY_GEN_MECHANISM), Some(CKM_COMP_KEM_KEY_PAIR_GEN), "{name}");
            assert!(flag(h, CKA_LOCAL), "{name}");
            assert_eq!(attr(h, CKA_PUBLIC_KEY_INFO), Some(composite_key::spki(p.oid, &pk)), "{name}: SPKI");
        }
        assert!(flag(hp, CKA_ENCAPSULATE) && !flag(hp, CKA_VERIFY), "{name}");
        assert!(flag(hk, CKA_DECAPSULATE) && !flag(hk, CKA_SIGN), "{name}");
        assert!(flag(hk, CKA_SENSITIVE) && !flag(hk, CKA_EXTRACTABLE), "{name}: private defaults");
        assert!(flag(hk, CKA_ALWAYS_SENSITIVE) && flag(hk, CKA_NEVER_EXTRACTABLE), "{name}");
        // The private value is mlkemSeed ‖ tradSK and re-derives the public one.
        assert_eq!(composite_key::public_from_private(&layout, &value(hk)).unwrap(), pk, "{name}");
        // ... and never leaves through C_GetAttributeValue.
        let mut t = super::conformance_v32_tests::Tmpl::new(vec![(CKA_VALUE, vec![0u8; 4096])]);
        let n = t.count();
        assert_eq!(C_GetAttributeValue(SESSION, hk, t.ptr(), n), CKR_ATTRIBUTE_SENSITIVE, "{name}: private CKA_VALUE");

        // Length query, then the real call.
        let want = p.ciphertext_size().bytes();
        let (rv, ct, h_none) = encapsulate_with(CKM_COMP_KEM, &[], hp, 0);
        assert_eq!((rv, ct.len(), h_none), (CKR_OK, want, 0), "{name}: length query");
        assert_eq!(encapsulate_with(CKM_COMP_KEM, &[], hp, want - 1).0, CKR_BUFFER_TOO_SMALL, "{name}");
        let (rv, ct, h_enc) = encapsulate_with(CKM_COMP_KEM, &[], hp, want);
        assert_eq!(rv, CKR_OK, "{name}: encapsulate");
        assert_eq!(ct.len(), want, "{name}: ciphertext length");
        let (rv, h_dec) = decapsulate(hk, &ct);
        assert_eq!(rv, CKR_OK, "{name}: decapsulate");
        let (ss_e, ss_d) = (value(h_enc), value(h_dec));
        assert_eq!(ss_e.len(), 32, "{name}: 256-bit secret");
        assert_eq!(ss_e, ss_d, "{name}: round trip");
        assert_eq!(get_object_attr_u32(h_dec, CKA_VALUE_LEN), Some(32), "{name}");
        assert_eq!(get_object_attr_u32(h_dec, CKA_KEY_TYPE), Some(CKK_GENERIC_SECRET), "{name}");
        destroy(&[hp, hk, h_enc, h_dec]);
    }
}

/// Template rules of CKM_COMP_KEM_KEY_PAIR_GEN.
#[test]
fn keygen_template_rules() {
    let _guard = test_lock::acquire();
    setup();
    let x25519 = kem_params(CKP_COMP_KEM_MLKEM768_X25519).unwrap().ckp;
    // No parameter set in the public template (comp_kem.md: it is given there).
    assert_eq!(generate(CKM_COMP_KEM_KEY_PAIR_GEN, vec![], vec![]).0, CKR_TEMPLATE_INCOMPLETE);
    // Brainpool and an unknown value: not supported by this token.
    for ckp in [CKP_COMP_KEM_MLKEM768_ECDH_BRAINPOOLP256R1, CKP_COMP_KEM_MLKEM1024_ECDH_BRAINPOOLP384R1, 0x7f] {
        assert_eq!(generate_comp_kem(ckp).0, CKR_PARAMETER_SET_NOT_SUPPORTED, "ckp {ckp:#x}");
    }
    // The private template may restate the set, never contradict it.
    let (rv, hp, hk) = generate(
        CKM_COMP_KEM_KEY_PAIR_GEN,
        vec![(CKA_PARAMETER_SET, ulong(x25519))],
        vec![(CKA_PARAMETER_SET, ulong(x25519)), (CKA_PRIVATE, vec![0])],
    );
    assert_eq!(rv, CKR_OK);
    destroy(&[hp, hk]);
    assert_eq!(
        generate(
            CKM_COMP_KEM_KEY_PAIR_GEN,
            vec![(CKA_PARAMETER_SET, ulong(x25519))],
            vec![(CKA_PARAMETER_SET, ulong(CKP_COMP_KEM_MLKEM768_ECDH_P256))],
        )
        .0,
        CKR_TEMPLATE_INCONSISTENT
    );
    // A CKA_KEY_TYPE contradicting the mechanism (V4 rule).
    assert_eq!(
        generate(CKM_COMP_KEM_KEY_PAIR_GEN, vec![(CKA_PARAMETER_SET, ulong(x25519)), (CKA_KEY_TYPE, ulong(CKK_ML_KEM))], vec![]).0,
        CKR_TEMPLATE_INCONSISTENT
    );
    // The composite key tables have no CKA_SEED.
    assert_eq!(
        generate(CKM_COMP_KEM_KEY_PAIR_GEN, vec![(CKA_PARAMETER_SET, ulong(x25519))], vec![(CKA_SEED, vec![0u8; 64])]).0,
        CKR_ATTRIBUTE_TYPE_INVALID
    );
}

/// comp_kem.md: ulMinKeySize/ulMaxKeySize are composite public-key bytes.
/// Smallest supported: id-MLKEM768-X25519, 1184 + 32 = 1216 (draft
/// Appendix A); largest: id-MLKEM1024-RSA3072, 1568 + 398 (RSA public key
/// maximum) = 1966. Flags: CKF_GENERATE_KEY_PAIR; CKF_ENCAPSULATE |
/// CKF_DECAPSULATE. Both advertised.
#[test]
fn mechanism_info_and_advertising() {
    assert_eq!(mechanism_info(CKM_COMP_KEM_KEY_PAIR_GEN), Some((1216, 1966, 0x0001_0000)));
    assert_eq!(mechanism_info(CKM_COMP_KEM), Some((1216, 1966, 0x1000_0000 | 0x2000_0000)));
    assert!(SUPPORTED_MECHS.contains(&CKM_COMP_KEM_KEY_PAIR_GEN));
    assert!(SUPPORTED_MECHS.contains(&CKM_COMP_KEM));
    // The signature mechanisms are not built yet and stay unadvertised.
    for m in [CKM_COMP_SIG_KEY_PAIR_GEN, CKM_COMP_SIG, CKM_COMP_SIG_EXTERNAL_HASH] {
        assert!(!SUPPORTED_MECHS.contains(&m) && mechanism_info(m).is_none(), "{m:#x}");
    }
}

// ── A3: the KAT ──────────────────────────────────────────────────────────

/// Decapsulation KAT, all 10 supported LAMPS vectors: `dk` imported through
/// C_CreateObject, `c` through C_DecapsulateKey, the secret key's value
/// must be `k` (draft §3.3 + §3.4).
#[test]
fn kat_decapsulate_all_supported_vectors() {
    let _guard = test_lock::acquire();
    setup();
    let mut n = 0;
    for v in supported() {
        let (rv, hk) = import_private(v.p.ckp, &v.dk, vec![]);
        assert_eq!(rv, CKR_OK, "{}", v.p.name);
        let (rv, hs) = decapsulate(hk, &v.c);
        assert_eq!(rv, CKR_OK, "{}: decapsulate", v.p.name);
        assert_eq!(value(hs), v.k, "{}: k", v.p.name);
        destroy(&[hk, hs]);
        n += 1;
    }
    assert_eq!(n, 10);
}

// ── V6: negative vectors derived from the good ones ─────────────────────

/// Derived failures per vector, each expected outcome from draft-23:
/// - one bit flipped in the ML-KEM part of `c`: CKR_OK and a secret ≠ `k`.
///   ML-KEM decapsulation is implicitly rejecting (§3.5, FIPS 203 §7.3).
/// - one bit flipped in the traditional part: RSA-OAEP and ECDH refuse it
///   (OAEP decoding fails; the point leaves the curve), and the composite
///   "MUST be explicitly rejecting whenever one of its components is" (§3.5)
///   → CKR_WRAPPED_KEY_INVALID. X25519 / X448 accept every non-low-order
///   u-coordinate (RFC 7748 §5), so the call succeeds, and the combiner's
///   tradCT input (§3.4) makes the secret differ from `k`.
/// - truncated by one byte, extended by one byte, or the ciphertext of
///   another set: CKR_WRAPPED_KEY_LEN_RANGE (§4.3 fixed lengths; §3.3 for
///   RSA modulus-size ciphertexts).
#[test]
fn v6_derived_negative_vectors() {
    let _guard = test_lock::acquire();
    setup();
    let all = supported();
    for (i, v) in all.iter().enumerate() {
        let name = v.p.name;
        let (rv, hk) = import_private(v.p.ckp, &v.dk, vec![]);
        assert_eq!(rv, CKR_OK, "{name}");
        let ml_ct = v.p.ml_kem_ciphertext_len();

        let mut c = v.c.clone();
        c[ml_ct / 2] ^= 0x01;
        let (rv, hs) = decapsulate(hk, &c);
        assert_eq!(rv, CKR_OK, "{name}: ML-KEM half flipped (implicit rejection)");
        assert_ne!(value(hs), v.k, "{name}: ML-KEM half flipped gives another secret");
        destroy(&[hs]);

        let mut c = v.c.clone();
        let last = c.len() - 1;
        c[last] ^= 0x01;
        let (rv, hs) = decapsulate(hk, &c);
        match v.p.classical {
            KemClassical::RsaOaep { .. } | KemClassical::Ecdh { .. } => {
                assert_eq!(rv, CKR_WRAPPED_KEY_INVALID, "{name}: traditional half flipped (explicit rejection)");
                assert_eq!(hs, 0, "{name}: no key object");
            }
            KemClassical::X25519 | KemClassical::X448 => {
                assert_eq!(rv, CKR_OK, "{name}: traditional half flipped");
                assert_ne!(value(hs), v.k, "{name}: tradCT is bound by the combiner");
                destroy(&[hs]);
            }
        }

        assert_eq!(decapsulate(hk, &v.c[..v.c.len() - 1]).0, CKR_WRAPPED_KEY_LEN_RANGE, "{name}: truncated");
        let mut longer = v.c.clone();
        longer.push(0);
        assert_eq!(decapsulate(hk, &longer).0, CKR_WRAPPED_KEY_LEN_RANGE, "{name}: one byte longer");
        let other = &all[(i + 1) % all.len()];
        assert_ne!(other.c.len(), v.c.len());
        assert_eq!(decapsulate(hk, &other.c).0, CKR_WRAPPED_KEY_LEN_RANGE, "{name}: ciphertext of {}", other.p.name);

        // The untouched vector still decapsulates to k.
        let (rv, hs) = decapsulate(hk, &v.c);
        assert_eq!((rv, value(hs)), (CKR_OK, v.k.clone()), "{name}");
        destroy(&[hk, hs]);
    }
}

/// CKM_COMP_KEM "has no parameters" (comp_kem.md) → a parameter is
/// CKR_MECHANISM_PARAM_INVALID on both calls. Wrong key types →
/// CKR_KEY_TYPE_INCONSISTENT (v3.2 §5.18.8 / §5.18.9): a plain ML-KEM key
/// under CKM_COMP_KEM, a composite key under CKM_ML_KEM, and the composite
/// public key passed to C_DecapsulateKey is refused for lacking
/// CKA_DECAPSULATE.
#[test]
fn v6_parameter_and_key_type_refusals() {
    let _guard = test_lock::acquire();
    setup();
    let v = supported().into_iter().find(|v| v.p.classical == KemClassical::X25519).unwrap();
    let (_, hk) = import_private(v.p.ckp, &v.dk, vec![]);
    let (_, hp) = import_public(v.p.ckp, &v.ek);
    let param = [0u8; 8];
    assert_eq!(decapsulate_with(CKM_COMP_KEM, &param, hk, &v.c).0, CKR_MECHANISM_PARAM_INVALID);
    assert_eq!(encapsulate_with(CKM_COMP_KEM, &param, hp, 4096).0, CKR_MECHANISM_PARAM_INVALID);
    // pParameter NULL but ulParameterLen non-zero.
    let mut m: [usize; 3] = [CKM_COMP_KEM as usize, 0, 4];
    let mut ct = v.c.clone();
    let mut h = 0u32;
    assert_eq!(
        C_DecapsulateKey(SESSION, m.as_mut_ptr() as *mut u8, hk, std::ptr::null_mut(), 0, ct.as_mut_ptr(), ct.len() as u32, &mut h),
        CKR_MECHANISM_PARAM_INVALID
    );

    let (rv, mp, mk) = generate(CKM_ML_KEM_KEY_PAIR_GEN, vec![(CKA_PARAMETER_SET, ulong(CKP_ML_KEM_768))], vec![(CKA_PRIVATE, vec![0])]);
    assert_eq!(rv, CKR_OK);
    assert_eq!(decapsulate_with(CKM_COMP_KEM, &[], mk, &v.c).0, CKR_KEY_TYPE_INCONSISTENT, "ML-KEM key, CKM_COMP_KEM");
    assert_eq!(encapsulate_with(CKM_COMP_KEM, &[], mp, 4096).0, CKR_KEY_TYPE_INCONSISTENT, "ML-KEM key, CKM_COMP_KEM");
    assert_eq!(decapsulate_with(CKM_ML_KEM, &[], hk, &v.c[..1088]).0, CKR_KEY_TYPE_INCONSISTENT, "composite key, CKM_ML_KEM");
    assert_eq!(encapsulate_with(CKM_ML_KEM, &[], hp, 4096).0, CKR_KEY_TYPE_INCONSISTENT, "composite key, CKM_ML_KEM");
    assert_eq!(decapsulate(hp, &v.c).0, CKR_KEY_FUNCTION_NOT_PERMITTED, "public key cannot decapsulate");
    destroy(&[hk, hp, mp, mk]);
}
