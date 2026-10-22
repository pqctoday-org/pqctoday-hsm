// SPDX-License-Identifier: AGPL-3.0-only
//
//! Project Wycheproof brainpoolP256r1 / brainpoolP384r1 vectors for the
//! engine's brainpool ECDSA verification and ECDH (`crypto::brainpool`,
//! 2026-10-21).
//!
//! Vectors: `rust/kat/wycheproof/wycheproof_{ecdsa,ecdh}_brainpool*_test.json`,
//! C2SP/wycheproof @ 3fa63dd0344abb611f1fb1d77e119938603ea230,
//! `testvectors_v1/`, each with a `_provenance` block (upstream path, upstream
//! sha256, how the case is run here). Apache-2.0, see
//! `rust/kat/wycheproof/WYCHEPROOF-LICENSE.txt`. Wycheproof is an independent
//! oracle, not a standards publication: a pass means "agrees with Project
//! Wycheproof 3fa63dd0 for this case".
//!
//! | fixture | upstream sha256 |
//! |---|---|
//! | `wycheproof_ecdsa_brainpoolP256r1_sha256_p1363_test.json` | `beddd2f5367292929411830de16995dd8afd9a14e811a3d9f8a041d024c6fe35` |
//! | `wycheproof_ecdsa_brainpoolP384r1_sha384_p1363_test.json` | `d3a1c429a56c4e26daf10a7db148653edb2588076b506839d73e254272aca7e0` |
//! | `wycheproof_ecdsa_brainpoolP256r1_sha256_test.json` | `0c1bb62a715cf20a0de88d5e81d05dbd8d0b439e4e8edd88d2229e98961583d4` |
//! | `wycheproof_ecdsa_brainpoolP384r1_sha384_test.json` | `b7338b35a71d3269abde4c2548ea6f95dff17f80ba5f34c20f9821da37963694` |
//! | `wycheproof_ecdh_brainpoolP256r1_test.json` | `8502c0259d85813d93cba5a664245b2d5ad1cdd3480a77337f3b377b8d63ccf4` |
//! | `wycheproof_ecdh_brainpoolP384r1_test.json` | `f32542f287664e337e1cc516e879de201ac023b6759a0d0637a4b687e96fd04f` |
//!
//! Result policy: `valid` must be accepted (ECDH: and give `shared`),
//! `invalid` must be refused, `acceptable` is recorded without an assertion.
//!
//! Included from `ffi.rs` via `#[path]`, like `wycheproof_mldsa_tests`.

use super::*;
use crate::crypto::brainpool::{self, CURVE_BP256R1, CURVE_BP384R1};
use serde_json::Value;

fn load(name: &str) -> Value {
    let path = format!("{}/kat/wycheproof/{name}", env!("CARGO_MANIFEST_DIR"));
    let s = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    serde_json::from_str(&s).expect("vector JSON")
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

fn hex_field(t: &Value, f: &str) -> Vec<u8> {
    unhex(t[f].as_str().unwrap_or_else(|| panic!("field {f}")))
}

#[derive(Default, Debug)]
struct Tally {
    valid: usize,
    invalid: usize,
    acceptable_accepted: usize,
    acceptable_refused: usize,
    not_expressible: usize,
}

/// Runs every case of an ECDSA verify file through `check`, which returns
/// whether the engine accepted the signature.
fn run_ecdsa(file: &str, check: impl Fn(&[u8], &[u8], &[u8]) -> bool) -> Tally {
    let d = load(file);
    let mut t = Tally::default();
    for g in d["testGroups"].as_array().unwrap() {
        let q = unhex(g["publicKey"]["uncompressed"].as_str().unwrap());
        for c in g["tests"].as_array().unwrap() {
            let tc = c["tcId"].as_u64().unwrap();
            let ok = check(&q, &hex_field(c, "msg"), &hex_field(c, "sig"));
            match c["result"].as_str().unwrap() {
                "valid" => {
                    assert!(ok, "{file} tcId {tc}: valid signature refused");
                    t.valid += 1;
                }
                "invalid" => {
                    assert!(!ok, "{file} tcId {tc}: invalid signature accepted ({})", c["comment"]);
                    t.invalid += 1;
                }
                _ if ok => t.acceptable_accepted += 1,
                _ => t.acceptable_refused += 1,
            }
        }
    }
    t
}

#[test]
fn wycheproof_ecdsa_p1363_verify() {
    for (file, mech, curve, cases) in [
        ("wycheproof_ecdsa_brainpoolP256r1_sha256_p1363_test.json", CKM_ECDSA_SHA256, CURVE_BP256R1, 261),
        ("wycheproof_ecdsa_brainpoolP384r1_sha384_p1363_test.json", CKM_ECDSA_SHA384, CURVE_BP384R1, 0),
    ] {
        let t = run_ecdsa(file, |q, m, s| crate::crypto::handlers::verify_ecdsa(mech, curve, q, m, s).is_ok());
        eprintln!("{file}: {t:?}");
        assert!(t.valid > 0 && t.invalid > 0, "{file}");
        if cases > 0 {
            assert_eq!(t.valid + t.invalid + t.acceptable_accepted + t.acceptable_refused, cases, "{file}");
        }
    }
}

/// The DER files exercise the composite signature path's tradSig decoder
/// (`brainpool::sig_der_to_raw`, strict DER) before the same verifier.
#[test]
fn wycheproof_ecdsa_der_verify() {
    for (file, mech, curve) in [
        ("wycheproof_ecdsa_brainpoolP256r1_sha256_test.json", CKM_ECDSA_SHA256, CURVE_BP256R1),
        ("wycheproof_ecdsa_brainpoolP384r1_sha384_test.json", CKM_ECDSA_SHA384, CURVE_BP384R1),
    ] {
        let t = run_ecdsa(file, |q, m, s| {
            brainpool::sig_der_to_raw(curve, s)
                .and_then(|raw| crate::crypto::handlers::verify_ecdsa(mech, curve, q, m, &raw))
                .is_ok()
        });
        eprintln!("{file}: {t:?}");
        assert!(t.valid > 0 && t.invalid > 0, "{file}");
    }
}

/// One definite-length TLV `(tag, body, rest)`; `None` for anything
/// truncated or not minimally encoded.
fn tlv(buf: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = buf.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (first as usize, rest)
    } else {
        let k = (first & 0x7f) as usize;
        if k == 0 || k > 2 || rest.len() < k || rest[0] == 0 {
            return None;
        }
        let len = rest[..k].iter().fold(0usize, |a, &b| (a << 8) | b as usize);
        if len < 0x80 {
            return None;
        }
        (len, &rest[k..])
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

/// The peer point of a Wycheproof ECDH `public` SPKI, when its
/// AlgorithmIdentifier is exactly id-ecPublicKey + this curve's namedCurve
/// OID (the only form a PKCS#11 caller's CKA_EC_PARAMS-named peer can
/// have). `None`: an SPKI this boundary cannot express (explicit or other
/// curve parameters, malformed ASN.1).
fn spki_point(curve: u32, spki: &[u8]) -> Option<Vec<u8>> {
    let mut alg = vec![0x30, 0x14, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    alg.extend_from_slice(&brainpool::ec_params(curve)?);
    let (tag, body, rest) = tlv(spki)?;
    if tag != 0x30 || !rest.is_empty() || !body.starts_with(&alg) {
        return None;
    }
    let (tag, bits, rest) = tlv(&body[alg.len()..])?;
    if tag != 0x03 || !rest.is_empty() || bits.first() != Some(&0) {
        return None;
    }
    Some(bits[1..].to_vec())
}

#[test]
fn wycheproof_ecdh() {
    for (file, curve, cases) in [
        ("wycheproof_ecdh_brainpoolP256r1_test.json", CURVE_BP256R1, 804),
        ("wycheproof_ecdh_brainpoolP384r1_test.json", CURVE_BP384R1, 0),
    ] {
        let n = brainpool::field_len(curve).unwrap();
        let d = load(file);
        let mut t = Tally::default();
        let mut total = 0;
        for g in d["testGroups"].as_array().unwrap() {
            assert_eq!(g["encoding"], "asn", "{file}");
            for c in g["tests"].as_array().unwrap() {
                total += 1;
                let tc = c["tcId"].as_u64().unwrap();
                let result = c["result"].as_str().unwrap();
                let Some(point) = spki_point(curve, &hex_field(c, "public")) else {
                    // Not expressible as a PKCS#11 peer on this curve. A
                    // `valid` case can never be in this class with a named
                    // curve, so this also guards the parser.
                    assert_ne!(result, "valid", "{file} tcId {tc}: valid case not expressible");
                    t.not_expressible += 1;
                    continue;
                };
                // Wycheproof private keys are DER INTEGER magnitudes: drop a
                // sign byte, left-pad to the field width.
                let mut d_bytes = hex_field(c, "private");
                while d_bytes.len() > n && d_bytes[0] == 0 {
                    d_bytes.remove(0);
                }
                let mut sk = vec![0u8; n - d_bytes.len()];
                sk.extend_from_slice(&d_bytes);
                let got = brainpool::ecdh(curve, &sk, &point);
                match result {
                    "valid" => {
                        assert_eq!(got.map(|z| z.to_vec()).ok(), Some(hex_field(c, "shared")), "{file} tcId {tc}");
                        t.valid += 1;
                    }
                    "invalid" => {
                        assert!(got.is_err(), "{file} tcId {tc}: invalid public key accepted ({})", c["comment"]);
                        t.invalid += 1;
                    }
                    _ => {
                        match got {
                            Ok(z) => {
                                assert_eq!(z.to_vec(), hex_field(c, "shared"), "{file} tcId {tc}: accepted, wrong secret");
                                t.acceptable_accepted += 1;
                            }
                            Err(_) => t.acceptable_refused += 1,
                        }
                    }
                }
            }
        }
        eprintln!("{file}: {t:?}");
        if cases > 0 {
            assert_eq!(total, cases, "{file}");
        }
        assert!(t.valid > 0 && t.invalid > 0, "{file}");
    }
}
