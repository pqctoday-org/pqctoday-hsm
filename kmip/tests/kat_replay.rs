//! KAT replay — every byte-exact vector in `kat/ttlv-wire/` round-trips
//! through `codec::decode → codec::encode` to the same bytes.
//!
//! This is the integration-test layer that proves the codec is wire-correct
//! against vectors derived directly from OASIS KMIP 3.0 §9 (see
//! `kat/ttlv-wire/manifest.json` + the generator at
//! `tools/gen_ttlv_kats.py`).
//!
//! Acts as a regression gate: if a codec change breaks round-trip
//! byte-equality for any golden vector, this test fails loudly.

use std::fs;
use std::path::Path;

use pqctoday_kmip::codec::{decode, encode_to_vec};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
struct Manifest {
    vectors: Vec<VectorEntry>,
}

#[derive(Deserialize)]
struct VectorEntry {
    filename: String,
    description: String,
    size_bytes: usize,
    sha256: String,
}

fn manifest_path() -> &'static Path {
    Path::new("kat/ttlv-wire/manifest.json")
}

fn vector_path(filename: &str) -> std::path::PathBuf {
    Path::new("kat/ttlv-wire").join(filename)
}

fn read_manifest() -> Manifest {
    let s = fs::read_to_string(manifest_path()).expect("read kat/ttlv-wire/manifest.json");
    serde_json::from_str(&s).expect("parse manifest.json")
}

fn hex_sha256(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let digest = h.finalize();
    let mut out = String::with_capacity(64);
    for b in digest.iter() {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[test]
fn manifest_lists_at_least_six_vectors() {
    // Phase 1 landed 6 hand-crafted vectors. Sanity check we still have them.
    let m = read_manifest();
    assert!(
        m.vectors.len() >= 6,
        "expected ≥6 KAT vectors, got {}",
        m.vectors.len()
    );
}

#[test]
fn every_vector_decodes_then_re_encodes_byte_exact() {
    let manifest = read_manifest();
    let mut checked = 0usize;

    for entry in &manifest.vectors {
        let bytes = fs::read(vector_path(&entry.filename))
            .unwrap_or_else(|e| panic!("read {}: {e}", entry.filename));
        assert_eq!(
            bytes.len(),
            entry.size_bytes,
            "{}: file size {} != manifest size_bytes {}",
            entry.filename,
            bytes.len(),
            entry.size_bytes
        );

        // Verify the manifest sha256 matches the on-disk file (drift detector).
        let on_disk_sha = hex_sha256(&bytes);
        assert_eq!(
            on_disk_sha, entry.sha256,
            "{}: on-disk sha256 {} != manifest sha256 {}",
            entry.filename, on_disk_sha, entry.sha256
        );

        // Decode, then re-encode, and expect byte-exact equality.
        let (frame, consumed) = decode(&bytes)
            .unwrap_or_else(|e| panic!("decode {}: {:?}", entry.filename, e));
        assert_eq!(
            consumed,
            bytes.len(),
            "{}: decode consumed {} bytes, file is {} bytes — leftover suggests \
             trailing junk or a missing pad",
            entry.filename,
            consumed,
            bytes.len()
        );

        let re_encoded = encode_to_vec(&frame);
        assert_eq!(
            re_encoded, bytes,
            "{} (description: {}): re-encode differs from original",
            entry.filename, entry.description
        );

        checked += 1;
    }

    // Sanity: we walked the whole manifest.
    assert_eq!(checked, manifest.vectors.len());
}
