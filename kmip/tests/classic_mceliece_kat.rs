//! Classic McEliece official KAT vectors — all 100 (10 × 10 variants), no
//! sampling.
//!
//! Source: the official Round-4 submission's own KAT package
//! (`classic.mceliece.org`) — see `kmip/kat/classic-mceliece/README.md` for
//! full provenance. Implementation plan §6 item 4: `kmip/kat/classic-
//! mceliece/` was "sourced, not yet consumed" until this file — the KAT
//! vectors existed and were already covered by `manifest.sha256`'s
//! integrity check, but nothing in the `kmip` crate actually decapsulated
//! them through the engine until now.
//!
//! Each vector: register the known `sk` into the engine, decapsulate the
//! known `ct`, assert the recovered shared secret equals the known `ss`
//! byte-for-byte. Every vector in every file is checked — same discipline
//! as `frodokem_kat.rs`, this file's direct model. Unlike FrodoKEM's 100
//! vectors per variant, Classic McEliece's official package ships exactly
//! 10 per variant (`count = 0`..`9` — confirmed by the KAT README, not
//! assumed; the smaller count matches the far larger key sizes here).
//!
//! Decapsulate-only, matching the implementation plan's §5.5(a)/§4.1 step 5
//! design and the Rust fork's own `classic-mceliece-multi/tests/
//! kat_verification.rs`: Classic McEliece's `encapsulate` draws
//! non-deterministic randomness for the error vector, so only decapsulation
//! (deterministic given `sk`/`ct`) is KAT-checkable.

use softhsmrustv3::constants::*;
use softhsmrustv3::native::keygen::register_classic_mceliece_private_key;
use softhsmrustv3::native::{decapsulate, session};

const KAT_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/kat/classic-mceliece/raw");

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
    let mut vectors = Vec::with_capacity(10);
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
fn check_all_vectors(dir: &str, parameter_set: u32) {
    let _g = engine_test_lock();
    let _ = session::finalize();
    session::init().expect("engine init");
    let sess = session::bootstrap_default_token(0, "so", "user", "mceliece-kat")
        .expect("bootstrap session");

    let path = std::path::Path::new(KAT_DIR).join(dir).join("kat_kem.rsp");
    let vectors = parse_rsp(&path);
    assert_eq!(vectors.len(), 10, "{dir}: expected exactly 10 KAT vectors");

    let mut checked = 0;
    for v in &vectors {
        let cka_id = format!("mceliece-kat-{}", v.count).into_bytes();
        let prv_h = register_classic_mceliece_private_key(sess, parameter_set, &v.sk, &cka_id, "kat")
            .unwrap_or_else(|e| panic!("{dir} count={}: register failed: {e}", v.count));
        let recovered = decapsulate(sess, prv_h, CKM_PQCTODAY_CLASSIC_MCELIECE_ENCAPSULATE, &v.ct)
            .unwrap_or_else(|e| panic!("{dir} count={}: decapsulate failed: {e}", v.count));
        assert_eq!(
            recovered, v.ss,
            "{dir} count={}: recovered shared secret does not match official KAT",
            v.count
        );
        checked += 1;
    }
    assert_eq!(checked, 10, "{dir}: only checked {checked}/10 vectors");
}

#[test]
fn classic_mceliece_348864_all_10_kat_vectors_pass() {
    check_all_vectors("mceliece348864", CKP_CLASSIC_MCELIECE_348864);
}

#[test]
fn classic_mceliece_348864f_all_10_kat_vectors_pass() {
    check_all_vectors("mceliece348864f", CKP_CLASSIC_MCELIECE_348864F);
}

#[test]
fn classic_mceliece_460896_all_10_kat_vectors_pass() {
    check_all_vectors("mceliece460896", CKP_CLASSIC_MCELIECE_460896);
}

#[test]
fn classic_mceliece_460896f_all_10_kat_vectors_pass() {
    check_all_vectors("mceliece460896f", CKP_CLASSIC_MCELIECE_460896F);
}

#[test]
fn classic_mceliece_6688128_all_10_kat_vectors_pass() {
    check_all_vectors("mceliece6688128", CKP_CLASSIC_MCELIECE_6688128);
}

#[test]
fn classic_mceliece_6688128f_all_10_kat_vectors_pass() {
    check_all_vectors("mceliece6688128f", CKP_CLASSIC_MCELIECE_6688128F);
}

#[test]
fn classic_mceliece_6960119_all_10_kat_vectors_pass() {
    check_all_vectors("mceliece6960119", CKP_CLASSIC_MCELIECE_6960119);
}

#[test]
fn classic_mceliece_6960119f_all_10_kat_vectors_pass() {
    check_all_vectors("mceliece6960119f", CKP_CLASSIC_MCELIECE_6960119F);
}

#[test]
fn classic_mceliece_8192128_all_10_kat_vectors_pass() {
    check_all_vectors("mceliece8192128", CKP_CLASSIC_MCELIECE_8192128);
}

#[test]
fn classic_mceliece_8192128f_all_10_kat_vectors_pass() {
    check_all_vectors("mceliece8192128f", CKP_CLASSIC_MCELIECE_8192128F);
}
