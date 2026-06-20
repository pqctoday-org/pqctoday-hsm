//! OASIS KMIP 3.0 — typed request ENCODER round-trip (F-6).
//!
//! For every RequestMessage vector in the pristine + stubbed corpora:
//!   1. `d1 = decode_request_message(bytes)`            (typed parse — already gated elsewhere)
//!   2. `e1 = encode_request_message(d1)`               (the new encoder; `None` = op not yet supported)
//!   3. if `Some(e1)`: it MUST re-decode, and re-encoding MUST be IDEMPOTENT
//!      (`encode(decode(e1)) == e1`) — proves the encoder emits valid, stable bytes
//!      without needing `PartialEq` on the typed tree.
//!   4. **byte-exact** (`e1 == bytes`) is reported per-op but NOT asserted: typed
//!      decode is intentionally lossy (drops unmodeled fields, folds IDPlaceholder
//!      → sentinel), so byte-exactness only holds where nothing was dropped.
//!
//! The hard gate is idempotence on every *implemented* op; coverage (how many ops
//! / vectors the encoder handles, and how many are byte-exact) is printed so the
//! encoder can grow op-by-op against a real number.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use pqctoday_kmip::kmip30::message::RequestPayload;
use pqctoday_kmip::kmip30::{decode_request_message, encode_request_message};
use serde::Deserialize;

#[derive(Deserialize)]
struct Manifest {
    vectors: Vec<VectorEntry>,
}
#[derive(Deserialize)]
struct VectorEntry {
    filename: String,
    message_type: String,
}

fn tier_root(tier: &str) -> PathBuf {
    Path::new("conformance/oasis_corpus_bytes").join(tier)
}
fn load_manifest(tier: &str) -> Manifest {
    let p = tier_root(tier).join("manifest.json");
    let s = fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()));
    serde_json::from_str(&s).expect("parse manifest")
}

#[derive(Default, Clone)]
struct OpStat {
    total: usize,
    encodable: usize,
    byte_exact: usize,
}

/// A message the SERVER ITSELF could not decode — its typed parse produced a
/// `DecodeFailed` batch item (e.g. the deprecated DES3 / DSA algorithms the
/// KmipAlgorithm enum rejects, which `dispatcher_replay.py` also SKIPs). There
/// is nothing meaningful to re-encode, so these are excluded by construction
/// rather than counted as encoder gaps — the encoder boundary equals the
/// decoder boundary.
fn server_rejected(d: &pqctoday_kmip::kmip30::message::RequestMessage) -> bool {
    d.batch_items
        .iter()
        .any(|bi| matches!(bi.payload, RequestPayload::DecodeFailed { .. }))
}

#[test]
fn oasis_request_encoder_roundtrip() {
    let mut by_op: BTreeMap<String, OpStat> = BTreeMap::new();
    let mut total = 0usize;
    let mut encodable = 0usize;
    let mut byte_exact = 0usize;
    let mut idempotence_failures: Vec<String> = Vec::new();
    let mut unencodable: Vec<String> = Vec::new();

    for tier in ["pristine", "stubbed"] {
        for e in &load_manifest(tier).vectors {
            if e.message_type != "RequestMessage" {
                continue;
            }
            let bytes = fs::read(tier_root(tier).join(&e.filename)).expect("read vector");
            let d1 = match decode_request_message(&bytes) {
                Ok(m) => m,
                Err(_) => continue, // typed-decode gate owns this; not our concern here
            };
            let op = d1
                .batch_items
                .first()
                .map(|bi| format!("{:?}", bi.operation))
                .unwrap_or_else(|| "<none>".into());
            let st = by_op.entry(op.clone()).or_default();
            st.total += 1;
            total += 1;

            let Some(e1) = encode_request_message(&d1) else {
                if !server_rejected(&d1) {
                    let ops: Vec<String> =
                        d1.batch_items.iter().map(|bi| format!("{:?}", bi.operation)).collect();
                    unencodable.push(format!("{} [{}]", e.filename, ops.join("+")));
                }
                continue;
            };
            st.encodable += 1;
            encodable += 1;

            // Idempotence (hard gate): the encoder's output must re-decode, and
            // re-encoding it must reproduce the same bytes.
            match decode_request_message(&e1) {
                Ok(d2) => match encode_request_message(&d2) {
                    Some(e2) if e2 == e1 => {}
                    Some(_) => idempotence_failures
                        .push(format!("{} [{op}]: re-encode not idempotent", e.filename)),
                    None => idempotence_failures
                        .push(format!("{} [{op}]: re-decode then encode → None", e.filename)),
                },
                Err(err) => idempotence_failures
                    .push(format!("{} [{op}]: encoder output did NOT decode: {err}", e.filename)),
            }

            if e1 == bytes {
                st.byte_exact += 1;
                byte_exact += 1;
            }
        }
    }

    eprintln!(
        "\nrequest ENCODER coverage: {encodable}/{total} messages encodable, \
         {byte_exact} byte-exact vs OASIS, {} idempotence failures",
        idempotence_failures.len()
    );
    eprintln!("  {:<22} {:>6} {:>10} {:>11}", "operation", "total", "encodable", "byte-exact");
    for (op, s) in &by_op {
        let mark = if s.encodable == s.total { "" } else { "  ← partial" };
        eprintln!(
            "  {:<22} {:>6} {:>10} {:>11}{mark}",
            op, s.total, s.encodable, s.byte_exact
        );
    }
    for f in idempotence_failures.iter().take(40) {
        eprintln!("  IDEMPOTENCE-FAIL {f}");
    }
    if !unencodable.is_empty() {
        eprintln!("  UNENCODABLE ({}):", unencodable.len());
        for u in &unencodable {
            eprintln!("    {u}");
        }
    }

    assert!(
        idempotence_failures.is_empty(),
        "{} implemented-op vectors broke encoder idempotence — see stderr",
        idempotence_failures.len()
    );
    // 100% of the IN-SCOPE corpus must be encodable; only the documented
    // out-of-scope cases (deprecated crypto / key wrapping) may be unencodable.
    assert!(
        unencodable.is_empty(),
        "{} in-scope request vectors are NOT encodable (regression) — see stderr",
        unencodable.len()
    );
}
