//! OASIS KMIP 3.0 codec round-trip integration tests.
//!
//! Drives every TTLV byte vector under
//! `conformance/oasis_corpus_bytes/{pristine,stubbed}/` through our Rust
//! codec and asserts decode → encode produces byte-identical output.
//!
//! Vector provenance: extracted from the official OASIS
//! `kmip-profiles-v3.0.zip` (`test-cases/kmip-v3.0/{mandatory,optional}/*.xml`),
//! encoded to TTLV via `conformance/harness/oasis_codec.py`, and locked by
//! SHA-256 in each tier's `manifest.json`.
//!
//! - **`pristine`** (124 vectors) — every byte traces directly to an OASIS
//!   XML message with no placeholders. A regression here is a real
//!   compliance break.
//! - **`stubbed`** (1234 vectors) — full corpus with `$NOW`,
//!   `$UNIQUE_IDENTIFIER_n`, etc. substituted by neutral fillers.
//!   Proves codec consistency across the full KMIP 3.0 structural
//!   diversity; a few bytes per vector reflect our stub conventions
//!   rather than OASIS-canonical values.
//!
//! Regenerate vectors after spec / codec changes with:
//!
//! ```bash
//! python3 conformance/harness/generate_byte_vectors.py
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use pqctoday_kmip::codec::{decode_one, encode_to_vec};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
struct Manifest {
    tier: String,
    vectors: Vec<VectorEntry>,
}

#[derive(Deserialize)]
struct VectorEntry {
    filename: String,
    source_file: String,
    message_type: String,
    size_bytes: usize,
    sha256: String,
}

fn tier_root(tier: &str) -> PathBuf {
    Path::new("conformance/oasis_corpus_bytes").join(tier)
}

fn load_manifest(tier: &str) -> Manifest {
    let p = tier_root(tier).join("manifest.json");
    let s = fs::read_to_string(&p).unwrap_or_else(|e| {
        panic!("read {}: {} — run `python3 conformance/harness/generate_byte_vectors.py` first", p.display(), e)
    });
    let m: Manifest = serde_json::from_str(&s).expect("parse manifest");
    assert_eq!(m.tier, tier, "manifest tier mismatch");
    m
}

fn hex_sha256(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let d = h.finalize();
    let mut out = String::with_capacity(64);
    for b in d.iter() {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Walk one tier: each vector's bytes must (a) match the manifest sha256,
/// (b) decode without error, (c) re-encode byte-identical.
///
/// Returns the count of pass / fail / total for reporting; the test driver
/// asserts the failure count is zero.
fn run_tier(tier: &str) -> (usize, usize, Vec<String>) {
    let manifest = load_manifest(tier);
    let mut ok = 0usize;
    let mut failures: Vec<String> = Vec::new();
    let total = manifest.vectors.len();

    for entry in &manifest.vectors {
        let path = tier_root(tier).join(&entry.filename);
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                failures.push(format!("{}: read error {e}", entry.filename));
                continue;
            }
        };

        if bytes.len() != entry.size_bytes {
            failures.push(format!(
                "{}: size mismatch — file {} bytes, manifest claims {}",
                entry.filename,
                bytes.len(),
                entry.size_bytes
            ));
            continue;
        }
        let actual_hash = hex_sha256(&bytes);
        if actual_hash != entry.sha256 {
            failures.push(format!(
                "{}: sha256 mismatch — file {actual_hash}, manifest {}",
                entry.filename, entry.sha256
            ));
            continue;
        }

        // Codec round-trip: decode → encode → assert byte-equal.
        let frame = match decode_one(&bytes) {
            Ok(v) => v,
            Err(e) => {
                failures.push(format!(
                    "{}: decode failed [{}/{}]: {e}",
                    entry.filename, entry.message_type, entry.source_file
                ));
                continue;
            }
        };
        let re_encoded = encode_to_vec(&frame);

        if re_encoded != bytes {
            failures.push(format!(
                "{}: NOT byte-equal after round-trip [{}/{}] (in={}, out={})",
                entry.filename,
                entry.message_type,
                entry.source_file,
                bytes.len(),
                re_encoded.len()
            ));
            continue;
        }
        ok += 1;
    }

    (ok, total, failures)
}

#[test]
fn pristine_oasis_corpus_round_trips_byte_exact() {
    let (ok, total, failures) = run_tier("pristine");
    eprintln!("pristine OASIS round-trip: {ok}/{total} pass");
    for f in failures.iter().take(20) {
        eprintln!("  - {f}");
    }
    if !failures.is_empty() {
        eprintln!("  ({} total failures)", failures.len());
    }
    assert!(
        failures.is_empty(),
        "{} pristine OASIS vectors failed codec round-trip — see stderr",
        failures.len()
    );
}

#[test]
fn stubbed_oasis_corpus_round_trips_byte_exact() {
    let (ok, total, failures) = run_tier("stubbed");
    eprintln!("stubbed OASIS round-trip: {ok}/{total} pass");
    for f in failures.iter().take(20) {
        eprintln!("  - {f}");
    }
    if !failures.is_empty() {
        eprintln!("  ({} total failures)", failures.len());
    }
    assert!(
        failures.is_empty(),
        "{} stubbed OASIS vectors failed codec round-trip — see stderr",
        failures.len()
    );
}

#[test]
fn manifest_message_type_breakdown_matches_expectation() {
    // Documents the expected message-type mix; if either number changes
    // it's almost certainly because the OASIS corpus or generator
    // semantics shifted — re-run generate_byte_vectors.py and update.
    let pristine = load_manifest("pristine");
    let stubbed = load_manifest("stubbed");
    let n_pristine_req = pristine.vectors.iter().filter(|v| v.message_type == "RequestMessage").count();
    let n_stubbed_req = stubbed.vectors.iter().filter(|v| v.message_type == "RequestMessage").count();
    let n_stubbed_rsp = stubbed.vectors.iter().filter(|v| v.message_type == "ResponseMessage").count();

    // Pristine = placeholder-free messages; responses always carry $NOW so
    // they're never pristine. The count is a regression gate.
    assert_eq!(pristine.vectors.len(), n_pristine_req, "pristine tier must be all-Requests");

    // Stubbed corpus splits ~50/50 request vs response.
    assert!(n_stubbed_req > 0 && n_stubbed_rsp > 0, "stubbed tier must contain both message types");
    assert_eq!(
        n_stubbed_req + n_stubbed_rsp,
        stubbed.vectors.len(),
        "stubbed tier must contain only Request/Response messages"
    );
}
