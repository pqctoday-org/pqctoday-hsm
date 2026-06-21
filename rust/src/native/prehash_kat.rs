//! NIST ACVP **HashML-DSA** (FIPS 204 §5.4 pre-hash) known-answer tests.
//!
//! The patched `fips204` fork adds the pre-hash (`Ph`) variants the upstream
//! crate was missing — SHA-224/384, SHA3-224/256/384/512, SHAKE-256 — for full
//! PKCS#11 v3.2 §6.67 `CKM_HASH_ML_DSA_*` coverage. Those added paths previously
//! had **no** known-answer-test coverage anywhere (the upstream NIST vectors the
//! fork ships are pure ML-DSA only).
//!
//! This test closes that gap against NIST's *official* vectors. NIST's
//! external-interface `deterministic` sigGen groups fix `rnd = 0^32`, so
//! `try_hash_sign_with_seed([0;32], M, ctx, PH)` must byte-equal the published
//! `signature`. Because `DummyRng` copies the seed in verbatim and the
//! underlying ML-DSA core is the NIST-validated `sign_internal`, a byte match
//! proves the *only* new code — the `Ph` → OID/digest framing in `hashing.rs` —
//! is correct. Vectors + provenance: `rust/kat/mldsa-prehash-acvp.json`.

use fips204::traits::{SerDes, Signer};
use fips204::Ph;
use serde_json::Value;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn ph_from(s: &str) -> Ph {
    match s {
        "SHA224" => Ph::SHA224,
        "SHA256" => Ph::SHA256,
        "SHA384" => Ph::SHA384,
        "SHA512" => Ph::SHA512,
        "SHA3_224" => Ph::SHA3_224,
        "SHA3_256" => Ph::SHA3_256,
        "SHA3_384" => Ph::SHA3_384,
        "SHA3_512" => Ph::SHA3_512,
        "SHAKE128" => Ph::SHAKE128,
        "SHAKE256" => Ph::SHAKE256,
        other => panic!("unknown pre-hash {other}"),
    }
}

macro_rules! sign_case {
    ($m:path, $sk:expr, $msg:expr, $ctx:expr, $ph:expr) => {{
        use $m as p;
        let arr: [u8; p::SK_LEN] = $sk.try_into().expect("sk length");
        let sk = p::PrivateKey::try_from_bytes(arr).expect("deserialize sk");
        sk.try_hash_sign_with_seed(&[0u8; 32], &$msg, &$ctx, &$ph)
            .expect("hash-sign")
            .to_vec()
    }};
}

#[test]
fn hash_ml_dsa_prehash_matches_nist_acvp() {
    let doc: Value =
        serde_json::from_str(include_str!("../../kat/mldsa-prehash-acvp.json")).expect("parse kat");
    let cases = doc["cases"].as_array().expect("cases array");

    // Guard: every engine-supported pre-hash (10) × every parameter set (3).
    assert_eq!(cases.len(), 30, "expected full Ph × parameter-set coverage");
    let mut seen = std::collections::BTreeSet::new();

    for c in cases {
        let ps = c["paramSet"].as_str().unwrap();
        let ph_name = c["ph"].as_str().unwrap();
        let ph = ph_from(ph_name);
        let sk = unhex(c["sk"].as_str().unwrap());
        let msg = unhex(c["message"].as_str().unwrap_or(""));
        let ctx = unhex(c["context"].as_str().unwrap_or(""));
        let expected = unhex(c["signature"].as_str().unwrap());

        let got = match ps {
            "ML-DSA-44" => sign_case!(fips204::ml_dsa_44, sk, msg, ctx, ph),
            "ML-DSA-65" => sign_case!(fips204::ml_dsa_65, sk, msg, ctx, ph),
            "ML-DSA-87" => sign_case!(fips204::ml_dsa_87, sk, msg, ctx, ph),
            other => panic!("unknown parameter set {other}"),
        };
        assert_eq!(got, expected, "{ps} / {ph_name}: signature != NIST vector");
        seen.insert((ps.to_string(), ph_name.to_string()));
    }
    assert_eq!(seen.len(), 30, "duplicate or missing (paramSet, Ph) pairs");
}
