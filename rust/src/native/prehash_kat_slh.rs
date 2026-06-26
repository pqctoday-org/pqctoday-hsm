//! NIST ACVP **HashSLH-DSA** (FIPS 205 pre-hash) known-answer tests.
//!
//! Companion to `prehash_kat` (HashML-DSA). Validates the patched `fips205`
//! added pre-hash (`Ph`) variants — SHA-224/384, SHA3-224/256/384/512,
//! SHAKE-256 — for PKCS#11 v3.2 §6.69 `CKM_HASH_SLH_DSA_*`, which previously
//! had no known-answer-test coverage.
//!
//! NIST's external-interface `deterministic` sigGen groups fix the SLH-DSA
//! randomizer `opt_rand = PK.seed`, which is exactly what
//! `try_hash_sign(M, ctx, PH, hedged = false)` uses — so a byte match against
//! the published `signature` proves the added `Ph` framing is correct. Limited
//! to the fast (`128f`) parameter sets (both SHA2- and SHAKE-internal) to keep
//! the unoptimized test-build runtime bounded while still exercising every
//! pre-hash. Vectors + provenance: `rust/kat/slhdsa-prehash-acvp.json`.

use fips205::traits::{SerDes, Signer};
use fips205::Ph;
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
        let sk = p::PrivateKey::try_from_bytes(&arr).expect("deserialize sk");
        // hedged = false ⇒ deterministic randomizer opt_rand = PK.seed,
        // matching ACVP `deterministic: true`.
        sk.try_hash_sign(&$msg, &$ctx, &$ph, false)
            .expect("hash-sign")
            .to_vec()
    }};
}

#[test]
fn hash_slh_dsa_prehash_matches_nist_acvp() {
    let doc: Value = serde_json::from_str(include_str!("../../kat/slhdsa-prehash-acvp.json"))
        .expect("parse kat");
    let cases = doc["cases"].as_array().expect("cases array");
    assert_eq!(cases.len(), 20, "expected 10 Ph × 2 fast parameter sets");

    for c in cases {
        let ps = c["paramSet"].as_str().unwrap();
        let module = c["mod"].as_str().unwrap();
        let ph_name = c["ph"].as_str().unwrap();
        let ph = ph_from(ph_name);
        let sk = unhex(c["sk"].as_str().unwrap());
        let msg = unhex(c["message"].as_str().unwrap_or(""));
        let ctx = unhex(c["context"].as_str().unwrap_or(""));
        let expected = unhex(c["signature"].as_str().unwrap());

        let got = match module {
            "slh_dsa_sha2_128f" => sign_case!(fips205::slh_dsa_sha2_128f, sk, msg, ctx, ph),
            "slh_dsa_shake_128f" => sign_case!(fips205::slh_dsa_shake_128f, sk, msg, ctx, ph),
            other => panic!("unmapped parameter set {other}"),
        };
        assert_eq!(got, expected, "{ps} / {ph_name}: signature != NIST vector");
    }
}
