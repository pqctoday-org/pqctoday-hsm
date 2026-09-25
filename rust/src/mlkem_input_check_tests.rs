//! FIPS 203 §7.2 / §7.3 ML-KEM input checks at the PKCS#11 boundary
//! (2026-09-25).
//!
//! Defect: the engine accepted every NIST ACVP-Server encapDecap VAL
//! `encapsulationKeyCheck` / `decapsulationKeyCheck` case marked
//! `testPassed=false` (ek with a coefficient ≥ q; dk whose embedded
//! `h ≠ H(ek)`), and answered a wrong-length ciphertext with
//! CKR_ENCRYPTED_DATA_INVALID, a code PKCS#11 v3.2 §5.18.9 does not list.
//!
//! Vectors: `rust/kat/mlkem-keycheck-acvp.json` — byte-copied NIST
//! ACVP-Server@975de31e cases (provenance inside the file). Every assertion is
//! verdict/return-code/byte exact; nothing here is a round-trip-only check.
//!
//! Included from `ffi.rs` via `#[path]` so `use super::*` resolves to the FFI
//! module and its private helpers, like `conformance_v32_tests`.

use super::*;
use crate::native::test_lock;
use serde_json::Value;

/// High fixed session handle, disjoint from every other ffi test module.
const SESSION: u32 = 0x4D50_4001;

fn setup() {
    crate::state::set_initialized(true);
    SESSIONS.with(|s| {
        s.borrow_mut()
            .insert(SESSION, crate::state::SessionState { slot_id: 0, rw_session: true });
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

fn kat() -> Value {
    serde_json::from_str(include_str!("../kat/mlkem-keycheck-acvp.json")).expect("parse kat")
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn ps_of(name: &str) -> u32 {
    match name {
        "ML-KEM-512" => CKP_ML_KEM_512,
        "ML-KEM-768" => CKP_ML_KEM_768,
        "ML-KEM-1024" => CKP_ML_KEM_1024,
        other => panic!("unknown parameter set {other}"),
    }
}

fn ct_len_of(ps: u32) -> usize {
    match ps {
        CKP_ML_KEM_512 => 768,
        CKP_ML_KEM_768 => 1088,
        CKP_ML_KEM_1024 => 1568,
        _ => unreachable!(),
    }
}

/// CK_ULONG-width little-endian bytes (what an LP64 caller sends).
fn ulong(v: u32) -> Vec<u8> {
    (v as usize).to_le_bytes().to_vec()
}

/// `C_CreateObject` through the real FFI entry point with a CK_ATTRIBUTE
/// array built from `entries`. Returns (rv, handle).
fn create(entries: Vec<(u32, Vec<u8>)>) -> (u32, u32) {
    let mut words: Vec<usize> = Vec::with_capacity(entries.len() * 3);
    for (t, v) in &entries {
        words.push(*t as usize);
        words.push(v.as_ptr() as usize);
        words.push(v.len());
    }
    let mut h: u32 = 0;
    let rv = C_CreateObject(SESSION, words.as_mut_ptr() as *mut u8, entries.len() as u32, &mut h);
    (rv, h)
}

fn import_ek(ps: u32, ek: &[u8]) -> (u32, u32) {
    create(vec![
        (CKA_CLASS, ulong(CKO_PUBLIC_KEY)),
        (CKA_KEY_TYPE, ulong(CKK_ML_KEM)),
        (CKA_PARAMETER_SET, ulong(ps)),
        (CKA_ENCAPSULATE, vec![1]),
        (CKA_TOKEN, vec![0]),
        (CKA_VALUE, ek.to_vec()),
    ])
}

fn import_dk(ps: u32, dk: &[u8]) -> (u32, u32) {
    create(vec![
        (CKA_CLASS, ulong(CKO_PRIVATE_KEY)),
        (CKA_KEY_TYPE, ulong(CKK_ML_KEM)),
        (CKA_PARAMETER_SET, ulong(ps)),
        (CKA_DECAPSULATE, vec![1]),
        (CKA_TOKEN, vec![0]),
        (CKA_PRIVATE, vec![0]),
        (CKA_VALUE, dk.to_vec()),
    ])
}

fn encapsulate(h_pub: u32, ct_buf_len: usize) -> (u32, u32) {
    let mut mech: [usize; 3] = [CKM_ML_KEM as usize, 0, 0];
    let mut ct = vec![0u8; ct_buf_len];
    let mut ct_len = ct_buf_len as u32;
    let mut h_new: u32 = 0;
    let rv = C_EncapsulateKey(
        SESSION,
        mech.as_mut_ptr() as *mut u8,
        h_pub,
        std::ptr::null_mut(),
        0,
        ct.as_mut_ptr(),
        &mut ct_len,
        &mut h_new,
    );
    (rv, h_new)
}

fn decapsulate(h_prv: u32, ct: &[u8]) -> (u32, u32) {
    let mut mech: [usize; 3] = [CKM_ML_KEM as usize, 0, 0];
    let mut ct = ct.to_vec();
    let mut h_new: u32 = 0;
    let rv = C_DecapsulateKey(
        SESSION,
        mech.as_mut_ptr() as *mut u8,
        h_prv,
        std::ptr::null_mut(),
        0,
        ct.as_mut_ptr(),
        ct.len() as u32,
        &mut h_new,
    );
    (rv, h_new)
}

fn destroy(h: u32) {
    if h != 0 {
        OBJECTS.with(|o| o.borrow_mut().remove(&h));
    }
}

/// The helper verdicts themselves, against NIST's `testPassed` — all 12
/// key-check cases (6 valid, 6 invalid), no FFI in between.
#[test]
fn fips203_key_check_helpers_match_nist_verdicts() {
    let doc = kat();
    let cases = doc["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 12, "fixture must carry all 12 key-check cases");
    let mut invalid_seen = 0;
    for c in cases {
        let ps = ps_of(c["parameterSet"].as_str().unwrap());
        let want = c["testPassed"].as_bool().unwrap();
        let got = match c["function"].as_str().unwrap() {
            "encapsulationKeyCheck" => {
                crate::native::keygen::ml_kem_ek_check(ps, &unhex(c["ek"].as_str().unwrap()))
            }
            "decapsulationKeyCheck" => {
                crate::native::keygen::ml_kem_dk_check(ps, &unhex(c["dk"].as_str().unwrap()))
            }
            other => panic!("unexpected function {other}"),
        };
        assert_eq!(got, Some(want), "tc{} ({}) verdict", c["tcId"], c["reason"]);
        if !want {
            invalid_seen += 1;
        }
    }
    assert_eq!(invalid_seen, 6);
}

/// FIPS 203 §7.2/§7.3 through `C_CreateObject` (PKCS#11 v3.2 §4.1.1 rule 2):
/// a NIST-invalid key → exactly CKR_ATTRIBUTE_VALUE_INVALID, no object; a
/// NIST-valid key → CKR_OK, and the key then works under C_EncapsulateKey /
/// C_DecapsulateKey (all-zero ciphertext of the right length: ML-KEM's
/// implicit rejection returns CKR_OK with a 32-byte secret).
#[test]
fn nist_key_checks_through_create_object() {
    let _guard = test_lock::acquire();
    setup();
    let doc = kat();
    for c in doc["cases"].as_array().unwrap() {
        let ps = ps_of(c["parameterSet"].as_str().unwrap());
        let valid = c["testPassed"].as_bool().unwrap();
        let tag = format!("tc{} {} ({})", c["tcId"], c["parameterSet"], c["reason"]);
        let is_ek = c["function"] == "encapsulationKeyCheck";
        let (rv, h) = if is_ek {
            import_ek(ps, &unhex(c["ek"].as_str().unwrap()))
        } else {
            import_dk(ps, &unhex(c["dk"].as_str().unwrap()))
        };
        if !valid {
            assert_eq!(rv, CKR_ATTRIBUTE_VALUE_INVALID, "{tag}: must be rejected at import");
            assert_eq!(h, 0, "{tag}: no object on failure");
            continue;
        }
        assert_eq!(rv, CKR_OK, "{tag}: NIST-valid key must import");
        let (rv2, h_ss) = if is_ek {
            encapsulate(h, ct_len_of(ps))
        } else {
            decapsulate(h, &vec![0u8; ct_len_of(ps)])
        };
        assert_eq!(rv2, CKR_OK, "{tag}: NIST-valid key must be usable");
        assert_eq!(get_object_value(h_ss).map(|v| v.len()), Some(32), "{tag}");
        destroy(h_ss);
        destroy(h);
    }
}

/// A NIST-valid dk still decapsulates BYTE-EXACTLY after the checks: the
/// shared secret equals NIST's `k` for the lowest-tcId "valid decapsulation"
/// case of each parameter set.
#[test]
fn nist_valid_decapsulation_is_byte_exact() {
    let _guard = test_lock::acquire();
    setup();
    let doc = kat();
    let cases = doc["decapsulation_cases"].as_array().unwrap();
    assert_eq!(cases.len(), 3);
    for c in cases {
        let ps = ps_of(c["parameterSet"].as_str().unwrap());
        let (rv, h) = import_dk(ps, &unhex(c["dk"].as_str().unwrap()));
        assert_eq!(rv, CKR_OK, "tc{}", c["tcId"]);
        let (rv2, h_ss) = decapsulate(h, &unhex(c["c"].as_str().unwrap()));
        assert_eq!(rv2, CKR_OK, "tc{}", c["tcId"]);
        assert_eq!(
            get_object_value(h_ss),
            Some(unhex(c["k"].as_str().unwrap())),
            "tc{}: shared secret must equal NIST k",
            c["tcId"]
        );
        destroy(h_ss);
        destroy(h);
    }
}

/// Use-time backstop: a NIST-invalid key that reached the store WITHOUT
/// C_CreateObject (as C_UnwrapKey or a pre-fix persisted object would) must
/// still never be run through ML-KEM.Encaps / ML-KEM.Decaps.
#[test]
fn invalid_keys_injected_into_store_are_refused_at_use() {
    let _guard = test_lock::acquire();
    setup();
    let doc = kat();
    let mut handle = 0x4D50_4100u32;
    for c in doc["cases"].as_array().unwrap() {
        if c["testPassed"].as_bool().unwrap() {
            continue;
        }
        let ps = ps_of(c["parameterSet"].as_str().unwrap());
        let is_ek = c["function"] == "encapsulationKeyCheck";
        handle += 1;
        OBJECTS.with(|o| {
            let mut attrs = Attributes::new();
            if is_ek {
                attrs.insert(CKA_VALUE, unhex(c["ek"].as_str().unwrap()));
                store_ulong(&mut attrs, CKA_CLASS, CKO_PUBLIC_KEY);
                store_bool(&mut attrs, CKA_ENCAPSULATE, true);
            } else {
                attrs.insert(CKA_VALUE, unhex(c["dk"].as_str().unwrap()));
                store_ulong(&mut attrs, CKA_CLASS, CKO_PRIVATE_KEY);
                store_bool(&mut attrs, CKA_DECAPSULATE, true);
            }
            store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_ML_KEM);
            store_param_set(&mut attrs, ps);
            o.borrow_mut().insert(handle, attrs);
        });
        let (rv, h_ss) = if is_ek {
            encapsulate(handle, ct_len_of(ps))
        } else {
            decapsulate(handle, &vec![0u8; ct_len_of(ps)])
        };
        assert_eq!(rv, CKR_KEY_TYPE_INCONSISTENT, "tc{} ({})", c["tcId"], c["reason"]);
        assert_eq!(h_ss, 0, "tc{}: no key object on failure", c["tcId"]);
        destroy(handle);
    }
}

/// Length boundaries, ML-KEM-512 (FIPS 203 §7.2 / §7.3 type checks):
/// ek/dk one byte short or long → CKR_ATTRIBUTE_VALUE_INVALID at
/// C_CreateObject; ciphertext one byte short/long or another parameter set's
/// length → CKR_WRAPPED_KEY_LEN_RANGE (PKCS#11 v3.2 §5.18.9 list; §5.1.6
/// "invalid solely on the basis of its length"), never a key object.
#[test]
fn length_boundaries_have_spec_return_codes() {
    let _guard = test_lock::acquire();
    setup();
    let doc = kat();
    let cases = doc["cases"].as_array().unwrap();
    let pick = |f: &str| {
        cases
            .iter()
            .find(|c| c["parameterSet"] == "ML-KEM-512" && c["function"] == f && c["testPassed"] == true)
            .unwrap()
    };
    let ek = unhex(pick("encapsulationKeyCheck")["ek"].as_str().unwrap());
    let dk = unhex(pick("decapsulationKeyCheck")["dk"].as_str().unwrap());
    assert_eq!((ek.len(), dk.len()), (800, 1632));
    let ps = CKP_ML_KEM_512;

    let mut ek_long = ek.clone();
    ek_long.push(0);
    for (label, bad) in [("ek-1", ek[..ek.len() - 1].to_vec()), ("ek+1", ek_long)] {
        assert_eq!(import_ek(ps, &bad), (CKR_ATTRIBUTE_VALUE_INVALID, 0), "{label}");
    }
    let mut dk_long = dk.clone();
    dk_long.push(0);
    for (label, bad) in [("dk-1", dk[..dk.len() - 1].to_vec()), ("dk+1", dk_long)] {
        assert_eq!(import_dk(ps, &bad), (CKR_ATTRIBUTE_VALUE_INVALID, 0), "{label}");
    }

    let (rv, h_prv) = import_dk(ps, &dk);
    assert_eq!(rv, CKR_OK);
    for (label, len) in [("ct-1", 767usize), ("ct+1", 769), ("ct=768-set", 1088), ("ct=0", 0)] {
        let buf = vec![0x5Au8; len.max(1)];
        let (rv, h_ss) = decapsulate(h_prv, &buf[..len]);
        assert_eq!(rv, CKR_WRAPPED_KEY_LEN_RANGE, "{label}");
        assert_eq!(h_ss, 0, "{label}: no key object on failure");
    }
    let (rv, h_ss) = decapsulate(h_prv, &vec![0u8; 768]);
    assert_eq!(rv, CKR_OK, "exact length must be accepted");
    destroy(h_ss);
    destroy(h_prv);
}

/// The KMIP ingress (`native::register_ml_kem_{private,public}_key`) applies
/// the same checks: NIST-invalid → CKR_ATTRIBUTE_VALUE_INVALID, valid → Ok.
#[test]
fn native_register_applies_the_same_checks() {
    let _guard = test_lock::acquire();
    let _ = crate::native::session::finalize();
    crate::native::session::init().expect("engine init");
    let session = crate::native::session::bootstrap_default_token(0, "so", "user", "mlkem-check")
        .expect("bootstrap session");
    let doc = kat();
    for c in doc["cases"].as_array().unwrap() {
        let ps = ps_of(c["parameterSet"].as_str().unwrap());
        let valid = c["testPassed"].as_bool().unwrap();
        let r = if c["function"] == "encapsulationKeyCheck" {
            crate::native::keygen::register_ml_kem_public_key(
                session,
                ps,
                &unhex(c["ek"].as_str().unwrap()),
                b"ek",
                "check",
            )
        } else {
            crate::native::keygen::register_ml_kem_private_key(
                session,
                ps,
                &unhex(c["dk"].as_str().unwrap()),
                b"dk",
                "check",
            )
        };
        if valid {
            assert!(r.is_ok(), "tc{}: valid key must register", c["tcId"]);
        } else {
            assert_eq!(r, Err(CKR_ATTRIBUTE_VALUE_INVALID), "tc{} ({})", c["tcId"], c["reason"]);
        }
    }
    let _ = crate::native::session::finalize();
}
