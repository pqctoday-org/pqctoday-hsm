// SPDX-License-Identifier: AGPL-3.0-only
//
//! Coverage gate for the LAMPS composite test vectors (plan Workstream V,
//! V2). Provenance of the files: `rust/kat/pkcs11-v33/PROVENANCE.md`.
//!
//! Fails unless every `CKP_COMP_SIG_*` and `CKP_COMP_KEM_*` value in the
//! PKCS#11 v3.3 TC header (30 in all) maps to exactly one upstream vector
//! whose `tcId` is the parameter table row's algorithm name and whose OID —
//! read from the vector's own PKCS#8 `privateKeyAlgorithm` and found in its
//! `x5c` certificate — is the row's OID. The vectors carry no label field;
//! the label is bound to the row, which `composite.rs` checks against the
//! draft text. Also fails if an upstream file is replaced without its
//! sha256 being recorded, or gains, drops or renames an entry.
//!
//! No cryptography runs here: the vectors are run through the engine in
//! later steps.

use super::composite::{CompositeFamily, COMPOSITE_KEM_SETS, COMPOSITE_SIG_SETS, params_by_ckp};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const KEM_VECTORS: &[u8] = include_bytes!("../../kat/pkcs11-v33/composite-kem/testvectors.json");
const SIG_VECTORS: &[u8] = include_bytes!("../../kat/pkcs11-v33/composite-sig/testvectors.json");
const IDENTIFIERS: &str = include_str!("../../kat/pkcs11-v33/pkcs11-v33-identifiers.json");

/// sha256 of the upstream files as recorded in PROVENANCE.md.
const KEM_VECTORS_SHA256: &str = "1b8d80f3ce623f368466eda44820f8b82ca67c9955e213d212c997137ef9ff24";
const SIG_VECTORS_SHA256: &str = "a60f697f9fd94c3cd5e4501a40c4396d9a9ffc7cf0f8a1ddd87dedbb46a7abf0";

/// The plain (non-composite) entries each file also carries, with the OID
/// of their PKCS#8 key (FIPS 203 / FIPS 204 NIST arcs).
const PLAIN_KEM: [(&str, &str); 2] =
    [("id-alg-ml-kem-768", "2.16.840.1.101.3.4.4.2"), ("id-alg-ml-kem-1024", "2.16.840.1.101.3.4.4.3")];
const PLAIN_SIG: [(&str, &str); 3] = [
    ("id-ML-DSA-44", "2.16.840.1.101.3.4.3.17"),
    ("id-ML-DSA-65", "2.16.840.1.101.3.4.3.18"),
    ("id-ML-DSA-87", "2.16.840.1.101.3.4.3.19"),
];

fn sha256_hex(b: &[u8]) -> String {
    Sha256::digest(b).iter().map(|x| format!("{x:02x}")).collect()
}

/// Standard base64 (RFC 4648 §4, with padding), as the vector files use.
fn b64(s: &str) -> Vec<u8> {
    fn val(c: u8) -> u32 {
        match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a' + 26) as u32,
            b'0'..=b'9' => (c - b'0' + 52) as u32,
            b'+' => 62,
            b'/' => 63,
            _ => panic!("not base64: {c:#x}"),
        }
    }
    let s = s.as_bytes();
    assert_eq!(s.len() % 4, 0, "base64 length");
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for chunk in s.chunks(4) {
        let pad = chunk.iter().filter(|&&c| c == b'=').count();
        let n = chunk.iter().take(4 - pad).fold(0u32, |acc, &c| (acc << 6) | val(c)) << (6 * pad);
        out.extend_from_slice(&n.to_be_bytes()[1..4 - pad]);
    }
    out
}

/// One DER TLV header at `i`: (tag, start of contents, length).
fn tlv(der: &[u8], i: usize) -> (u8, usize, usize) {
    let tag = der[i];
    let first = der[i + 1] as usize;
    if first < 0x80 {
        return (tag, i + 2, first);
    }
    let n = first & 0x7f;
    let len = der[i + 2..i + 2 + n].iter().fold(0usize, |a, &b| (a << 8) | b as usize);
    (tag, i + 2 + n, len)
}

fn oid_string(body: &[u8]) -> String {
    let mut arcs = vec![(body[0] / 40) as u64, (body[0] % 40) as u64];
    let mut acc = 0u64;
    for &b in &body[1..] {
        acc = (acc << 7) | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            arcs.push(acc);
            acc = 0;
        }
    }
    arcs.iter().map(u64::to_string).collect::<Vec<_>>().join(".")
}

/// The algorithm OID of a PKCS#8 OneAsymmetricKey (RFC 5958 §2):
/// SEQUENCE { INTEGER version, SEQUENCE { OID, ... }, ... }. Returns the OID
/// string and its full DER TLV.
fn pkcs8_oid(der: &[u8]) -> (String, Vec<u8>) {
    let (t, i, _) = tlv(der, 0);
    assert_eq!(t, 0x30, "OneAsymmetricKey is a SEQUENCE");
    let (t, v, vl) = tlv(der, i);
    assert_eq!(t, 0x02, "version INTEGER");
    let (t, a, _) = tlv(der, v + vl);
    assert_eq!(t, 0x30, "privateKeyAlgorithm SEQUENCE");
    let (t, o, ol) = tlv(der, a);
    assert_eq!(t, 0x06, "algorithm OID");
    (oid_string(&der[o..o + ol]), der[a..o + ol].to_vec())
}

/// tcId → (OID from the PKCS#8 key, whether the x5c holds that OID TLV).
fn vector_oids(raw: &[u8], pkcs8_field: &str) -> (Value, BTreeMap<String, (String, bool)>) {
    let v: Value = serde_json::from_slice(raw).expect("vector file parses");
    let mut map = BTreeMap::new();
    for e in v["tests"].as_array().expect("tests array") {
        let tc = e["tcId"].as_str().expect("tcId").to_string();
        let (oid, oid_tlv) = pkcs8_oid(&b64(e[pkcs8_field].as_str().expect("pkcs8 field")));
        let cert = b64(e["x5c"].as_str().expect("x5c"));
        let in_cert = cert.windows(oid_tlv.len()).any(|w| w == oid_tlv.as_slice());
        assert!(map.insert(tc.clone(), (oid, in_cert)).is_none(), "duplicate tcId {tc}");
    }
    (v, map)
}

/// The `CKP_COMP_*` values the TC header defines, per family.
fn header_ckps() -> Vec<(CompositeFamily, String, u32)> {
    let v: Value = serde_json::from_str(IDENTIFIERS).expect("identifiers parse");
    v["identifiers"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| {
            let name = e["name"].as_str().unwrap();
            let fam = if name.starts_with("CKP_COMP_SIG_") {
                CompositeFamily::Sig
            } else if name.starts_with("CKP_COMP_KEM_") {
                CompositeFamily::Kem
            } else {
                return None;
            };
            let val = u32::from_str_radix(e["value"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
            Some((fam, name.to_string(), val))
        })
        .collect()
}

#[test]
fn composite_vector_files_match_recorded_sha256() {
    assert_eq!(sha256_hex(KEM_VECTORS), KEM_VECTORS_SHA256, "composite-kem/testvectors.json changed");
    assert_eq!(sha256_hex(SIG_VECTORS), SIG_VECTORS_SHA256, "composite-sig/testvectors.json changed");
}

#[test]
fn composite_vectors_cover_every_ckp_exactly_once() {
    let (_, kem) = vector_oids(KEM_VECTORS, "dk_pkcs8");
    let (sig_json, sig) = vector_oids(SIG_VECTORS, "sk_pkcs8");
    assert!(sig_json["m"].is_string() && sig_json["ctx"].is_string(), "shared m and ctx");
    assert_eq!(kem.len(), 14, "KEM entries");
    assert_eq!(sig.len(), 21, "signature entries");

    let ckps = header_ckps();
    assert_eq!(ckps.iter().filter(|c| c.0 == CompositeFamily::Sig).count(), 18);
    assert_eq!(ckps.iter().filter(|c| c.0 == CompositeFamily::Kem).count(), 12);

    let mut used: BTreeMap<(bool, String), String> = BTreeMap::new();
    for (fam, name, ckp) in &ckps {
        let row = params_by_ckp(*fam, *ckp).unwrap_or_else(|| panic!("{name}: no table row"));
        let (vectors, row_name) = match fam {
            CompositeFamily::Sig => (&sig, super::composite::sig_params(*ckp).unwrap().name),
            CompositeFamily::Kem => (&kem, super::composite::kem_params(*ckp).unwrap().name),
        };
        let matches: Vec<&String> = vectors.keys().filter(|tc| tc.as_str() == row_name).collect();
        assert_eq!(matches.len(), 1, "{name}: {} vectors named {row_name}", matches.len());
        let (oid, in_cert) = &vectors[row_name];
        assert_eq!(oid, row.oid(), "{name}: vector PKCS#8 OID");
        assert!(*in_cert, "{name}: x5c does not carry OID {oid}");
        assert!(
            used.insert((*fam == CompositeFamily::Sig, row_name.to_string()), name.clone()).is_none(),
            "{row_name} claimed twice"
        );
    }
    assert_eq!(used.len(), 30);

    // Every remaining entry is one of the known plain ones, with its OID.
    for (vectors, plain) in [(&kem, &PLAIN_KEM[..]), (&sig, &PLAIN_SIG[..])] {
        let composite: Vec<&str> = COMPOSITE_SIG_SETS.iter().map(|p| p.name).chain(COMPOSITE_KEM_SETS.iter().map(|p| p.name)).collect();
        let rest: Vec<&String> = vectors.keys().filter(|tc| !composite.contains(&tc.as_str())).collect();
        assert_eq!(rest.len(), plain.len(), "unexpected entries: {rest:?}");
        for (tc, oid) in plain {
            let (got, in_cert) = vectors.get(*tc).unwrap_or_else(|| panic!("missing plain entry {tc}"));
            assert_eq!(got, oid, "{tc}");
            assert!(*in_cert, "{tc}: x5c does not carry OID");
        }
    }
}

#[test]
fn composite_vectors_base64_and_der_helpers() {
    assert_eq!(b64("TWFu"), b"Man");
    assert_eq!(b64("TWE="), b"Ma");
    assert_eq!(b64("TQ=="), b"M");
    // 1.3.6.1.5.5.7.6.37 = 06 08 2B 06 01 05 05 07 06 25
    assert_eq!(oid_string(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x25]), "1.3.6.1.5.5.7.6.37");
    // 2.16.840.1.101.3.4.3.17: multi-byte arc 840 = 86 48
    assert_eq!(oid_string(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11]), "2.16.840.1.101.3.4.3.17");
}
