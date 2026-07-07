//! FrodoKEM official KAT vectors — all 600 (100 × 6 variants), no sampling.
//!
//! Source: `microsoft/PQCrypto-LWEKE` (frodokem.org's own cited reference
//! implementation), the salted (current-spec) variant — see
//! `kmip/kat/frodokem/README.md` for full provenance. This is the primary
//! correctness evidence for FrodoKEM specifically because the dynamic
//! liboqs cross-check (Phase 0.9 of the implementation plan) is unavailable
//! for FrodoKEM — liboqs 0.12.0/0.13.0 doesn't implement the salted
//! variant, so there's nothing to cross-check against, and static KAT
//! coverage substitutes for it.
//!
//! Each vector: register the known `sk` into the engine, decapsulate the
//! known `ct`, assert the recovered shared secret equals the known `ss`
//! byte-for-byte. Every vector in every file is checked — an `#[ignore]`
//! or a `count < N` cap here would silently narrow coverage back down to a
//! sample, exactly what the whole point of switching from spot-check KAT
//! to full-file KAT was meant to avoid.

use softhsmrustv3::constants::*;
use softhsmrustv3::native::keygen::register_frodokem_private_key;
use softhsmrustv3::native::{decapsulate, session};

const KAT_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/kat/frodokem/raw");

struct Vector {
    count: u32,
    sk: Vec<u8>,
    ct: Vec<u8>,
    ss: Vec<u8>,
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// Parse a NIST `.rsp`-format KAT file's `count`/`sk`/`ct`/`ss` fields.
/// Ignores `seed`/`pk` (unused here — encapsulation isn't being re-derived,
/// only decapsulation of the known ciphertext against the known key).
fn parse_rsp(path: &std::path::Path) -> Vec<Vector> {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let mut vectors = Vec::with_capacity(100);
    let mut count: Option<u32> = None;
    let mut sk: Option<Vec<u8>> = None;
    let mut ct: Option<Vec<u8>> = None;
    let mut ss: Option<Vec<u8>> = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("count = ") {
            // A new "count = N" starts the next vector; flush the previous
            // one first (if fully populated).
            if let (Some(c), Some(k), Some(c2), Some(s)) = (count, sk.take(), ct.take(), ss.take())
            {
                vectors.push(Vector { count: c, sk: k, ct: c2, ss: s });
            }
            count = Some(v.parse().expect("count is a u32"));
        } else if let Some(v) = line.strip_prefix("sk = ") {
            sk = Some(hex_decode(v));
        } else if let Some(v) = line.strip_prefix("ct = ") {
            ct = Some(hex_decode(v));
        } else if let Some(v) = line.strip_prefix("ss = ") {
            ss = Some(hex_decode(v));
        }
    }
    // Flush the final vector.
    if let (Some(c), Some(k), Some(c2), Some(s)) = (count, sk, ct, ss) {
        vectors.push(Vector { count: c, sk: k, ct: c2, ss: s });
    }
    vectors
}

fn engine_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// Run every vector in `file` against `parameter_set`, asserting the engine
/// recovers the exact known shared secret for every single one. Panics
/// with the first failing `count` (not just "some vector failed") so a
/// regression is immediately actionable.
fn check_all_vectors(file: &str, parameter_set: u32) {
    let _g = engine_test_lock();
    let _ = session::finalize();
    session::init().expect("engine init");
    let sess = session::bootstrap_default_token(0, "so", "user", "frodo-kat")
        .expect("bootstrap session");

    let path = std::path::Path::new(KAT_DIR).join(file);
    let vectors = parse_rsp(&path);
    assert_eq!(vectors.len(), 100, "{file}: expected exactly 100 KAT vectors");

    let mut checked = 0;
    for v in &vectors {
        let cka_id = format!("frodo-kat-{}", v.count).into_bytes();
        let prv_h = register_frodokem_private_key(sess, parameter_set, &v.sk, &cka_id, "kat")
            .unwrap_or_else(|e| panic!("{file} count={}: register failed: {e}", v.count));
        let recovered =
            decapsulate(sess, prv_h, CKM_PQCTODAY_FRODOKEM_ENCAPSULATE, &v.ct).unwrap_or_else(|e| {
                panic!("{file} count={}: decapsulate failed: {e}", v.count)
            });
        assert_eq!(
            recovered, v.ss,
            "{file} count={}: recovered shared secret does not match official KAT",
            v.count
        );
        checked += 1;
    }
    assert_eq!(checked, 100, "{file}: only checked {checked}/100 vectors");
}

#[test]
fn frodokem_640_aes_all_100_kat_vectors_pass() {
    check_all_vectors("PQCkemKAT_19888.rsp", CKP_FRODOKEM_640_AES);
}

#[test]
fn frodokem_640_shake_all_100_kat_vectors_pass() {
    check_all_vectors("PQCkemKAT_19888_shake.rsp", CKP_FRODOKEM_640_SHAKE);
}

#[test]
fn frodokem_976_aes_all_100_kat_vectors_pass() {
    check_all_vectors("PQCkemKAT_31296.rsp", CKP_FRODOKEM_976_AES);
}

#[test]
fn frodokem_976_shake_all_100_kat_vectors_pass() {
    check_all_vectors("PQCkemKAT_31296_shake.rsp", CKP_FRODOKEM_976_SHAKE);
}

#[test]
fn frodokem_1344_aes_all_100_kat_vectors_pass() {
    check_all_vectors("PQCkemKAT_43088.rsp", CKP_FRODOKEM_1344_AES);
}

#[test]
fn frodokem_1344_shake_all_100_kat_vectors_pass() {
    check_all_vectors("PQCkemKAT_43088_shake.rsp", CKP_FRODOKEM_1344_SHAKE);
}
