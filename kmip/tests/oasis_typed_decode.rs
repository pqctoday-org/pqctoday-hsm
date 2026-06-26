//! OASIS KMIP 3.0 — TYPED request-decode coverage.
//!
//! The sibling [`oasis_codec_roundtrip`] proves the *generic* TTLV frame codec
//! round-trips every corpus byte (tag/type/length/value in == out). That check
//! never reaches the server's typed message layer. THIS test goes one layer up:
//! it drives every **RequestMessage** vector in the pristine + stubbed corpora
//! through the *typed* parser [`decode_request_message`] — the same entry point
//! the live server uses — proving the server's KMIP request parser accepts the
//! full structural diversity of the OASIS corpus, not just that the bytes frame.
//!
//! Any operation present in the corpus that the typed decoder cannot map to a
//! `RequestPayload` surfaces here as a failure (rather than being invisible
//! behind the frame-level round-trip).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use pqctoday_kmip::kmip30::decode_request_message;
use serde::Deserialize;

#[derive(Deserialize)]
struct Manifest {
    vectors: Vec<VectorEntry>,
}

#[derive(Deserialize)]
struct VectorEntry {
    filename: String,
    source_file: String,
    message_type: String,
}

fn tier_root(tier: &str) -> PathBuf {
    Path::new("conformance/oasis_corpus_bytes").join(tier)
}

fn load_manifest(tier: &str) -> Manifest {
    let p = tier_root(tier).join("manifest.json");
    let s = fs::read_to_string(&p).unwrap_or_else(|e| {
        panic!(
            "read {}: {e} — run `python3 conformance/harness/generate_byte_vectors.py` first",
            p.display()
        )
    });
    serde_json::from_str(&s).expect("parse manifest")
}

/// Typed-decode every RequestMessage vector across both tiers. Returns
/// (ok_count, per-operation tally, failures).
fn run() -> (usize, BTreeMap<String, usize>, Vec<String>) {
    let mut ok = 0usize;
    let mut by_op: BTreeMap<String, usize> = BTreeMap::new();
    let mut failures: Vec<String> = Vec::new();

    for tier in ["pristine", "stubbed"] {
        let manifest = load_manifest(tier);
        for e in &manifest.vectors {
            if e.message_type != "RequestMessage" {
                continue;
            }
            let bytes = match fs::read(tier_root(tier).join(&e.filename)) {
                Ok(b) => b,
                Err(err) => {
                    failures.push(format!("{}: read error {err}", e.filename));
                    continue;
                }
            };
            match decode_request_message(&bytes) {
                Ok(msg) => {
                    ok += 1;
                    for bi in &msg.batch_items {
                        *by_op.entry(format!("{:?}", bi.operation)).or_insert(0) += 1;
                    }
                }
                Err(err) => failures.push(format!(
                    "{} [{}]: TYPED decode failed: {err}",
                    e.filename, e.source_file
                )),
            }
        }
    }
    (ok, by_op, failures)
}

#[test]
fn oasis_corpus_typed_request_decode() {
    let (ok, by_op, failures) = run();
    eprintln!(
        "TYPED request-decode: {ok} ok, {} failed, {} distinct operations",
        failures.len(),
        by_op.len()
    );
    for (op, n) in &by_op {
        eprintln!("  {op:<30} {n}");
    }
    for f in failures.iter().take(60) {
        eprintln!("  FAIL {f}");
    }
    if failures.len() > 60 {
        eprintln!("  … and {} more", failures.len() - 60);
    }
    assert!(
        failures.is_empty(),
        "{} OASIS request vectors failed the TYPED decoder — see stderr",
        failures.len()
    );
}
