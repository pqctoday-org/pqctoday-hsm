//! RFC 9420 §8 key-schedule KAT — drives our provider's HSM-routed
//! `hkdf_extract` / `hkdf_expand` through the **published intermediate
//! values** in [`key-schedule.json`](../test-vectors/key-schedule.json).
//!
//! Strategy: we don't reimplement the full MLS key schedule (~500 lines
//! of openmls-internal types — `JoinerSecret`, `PskSecret`, etc.).
//! Instead, for every epoch in every supported ciphersuite, we take
//! `joiner_secret` and `psk_secret` AS PUBLISHED in the vector and verify
//! the derivation that produces `welcome_secret`:
//!
//! ```text
//!   intermediate_secret = HKDF.Extract(joiner_secret, psk_secret)
//!   welcome_secret      = DeriveSecret(intermediate_secret, "welcome")
//!                       = ExpandWithLabel(intermediate_secret,
//!                                         "welcome", "", Nh)
//! ```
//!
//! Per RFC 9420 §8.1 / §8.4 + the explicit graph in
//! `openmls::schedule::mod.rs`. This exercises both:
//!   1. Our PKCS#11-routed HKDF-Extract under MLS-style inputs
//!      (joiner_secret as salt, psk_secret as IKM)
//!   2. Our PKCS#11-routed HKDF-Expand with the MLS `KDFLabel` encoding
//!
//! If `welcome_secret` matches byte-exactly across every epoch in every
//! supported ciphersuite, the HSM-routed HKDF surface used by openmls's
//! key schedule is correct.
//!
//! Run: `cargo test --release --test rfc9420_kats -- --test-threads=1 --nocapture`

use std::io::Write;
use std::path::PathBuf;

use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use serde::Deserialize;

use openmls_pqctoday_crypto::{HsmConfig, PqcTodayProvider};
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::HashType;
use openmls_traits::OpenMlsProvider;

const SO_PIN: &str = "12345678";
const USER_PIN: &str = "1234";

fn resolve_module() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("PKCS11_MODULE") {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return Some(pb);
        }
    }
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for rel in &[
        "../../build/src/lib/libsofthsmv3.dylib",
        "../../build/src/lib/libsofthsmv3.so",
        "../../build_fresh/src/lib/libsofthsmv3.dylib",
        "../../build-pqctoday/src/lib/libsofthsmv3.so",
    ] {
        let p = here.join(rel);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

struct TestEnv {
    _tokens_dir: tempfile::TempDir,
    _conf_file: tempfile::NamedTempFile,
    provider: PqcTodayProvider,
}

fn setup_provider() -> Option<TestEnv> {
    let module = resolve_module()?;
    let tokens_dir = tempfile::tempdir().unwrap();
    let mut conf_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(
        conf_file,
        "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR",
        tokens_dir.path().display()
    )
    .unwrap();
    std::env::set_var("SOFTHSM2_CONF", conf_file.path());

    let ctx = Pkcs11::new(&module).expect("load module");
    ctx.initialize(CInitializeArgs::OsThreads).expect("init");
    let slot = *ctx.get_slots_with_token().unwrap().first().unwrap();
    ctx.init_token(slot, &AuthPin::new(SO_PIN.into()), "rfc9420-kat")
        .expect("init_token");
    {
        let so = ctx.open_rw_session(slot).unwrap();
        so.login(UserType::So, Some(&AuthPin::new(SO_PIN.into()))).unwrap();
        so.init_pin(&AuthPin::new(USER_PIN.into())).unwrap();
        so.logout().ok();
    }
    drop(ctx);

    let cfg = HsmConfig::new(module).with_pin(USER_PIN);
    let provider = PqcTodayProvider::new(&cfg).expect("provider");
    Some(TestEnv {
        _tokens_dir: tokens_dir,
        _conf_file: conf_file,
        provider,
    })
}

// ── key-schedule.json subset we care about ───────────────────────────────────
//
// We deliberately deserialise into our own struct subset (vs reusing
// `openmls::schedule::tests_and_kats::kats::key_schedule::KeyScheduleTestVector`)
// because that type is gated behind openmls's `test-utils` feature, which
// pulls in an incompatible `wasm-bindgen-test = "0.3.50"` pin. See
// `test-vectors/SOURCE.md` for the gap analysis.

#[derive(Debug, Deserialize)]
struct Epoch {
    joiner_secret: String,
    psk_secret: String,
    welcome_secret: String,
    // Many more fields exist — left unread; this struct deserialises what
    // we need.
}

#[derive(Debug, Deserialize)]
struct KeyScheduleVector {
    cipher_suite: u16,
    epochs: Vec<Epoch>,
}

// ── RFC 9420 §8: MLS KDFLabel encoding for ExpandWithLabel ──────────────────
//
// ```text
// struct {
//     uint16 length;
//     opaque label<V>;     // "MLS 1.0 " ‖ Label
//     opaque context<V>;
// } KDFLabel;
// ```
//
// `opaque ...<V>` is TLS-style variable-length: 1- or 2-byte length prefix
// using a quic-style varint. For our values here all lengths fit in one
// byte (<64), so we emit a single-byte prefix.

fn kdf_label(length: u16, label: &str, context: &[u8]) -> Vec<u8> {
    let prefixed_label = format!("MLS 1.0 {label}");
    let plabel_bytes = prefixed_label.as_bytes();
    let mut out = Vec::with_capacity(2 + 1 + plabel_bytes.len() + 1 + context.len());
    out.extend_from_slice(&length.to_be_bytes());
    // QUIC-style varint length prefix: 1 byte for len < 64.
    assert!(plabel_bytes.len() < 64, "label too long for single-byte prefix");
    out.push(plabel_bytes.len() as u8);
    out.extend_from_slice(plabel_bytes);
    assert!(context.len() < 64, "context too long for single-byte prefix");
    out.push(context.len() as u8);
    out.extend_from_slice(context);
    out
}

fn hash_len(cs: u16) -> usize {
    match cs {
        1 | 2 | 3 => 32, // SHA-256-based ciphersuites
        4 | 5 | 6 => 48, // SHA-384-based
        7 => 64,         // SHA-512-based
        _ => 0,
    }
}

fn hash_type(cs: u16) -> Option<HashType> {
    match cs {
        1 | 2 | 3 => Some(HashType::Sha2_256),
        4 | 5 | 6 => Some(HashType::Sha2_384),
        7 => Some(HashType::Sha2_512),
        _ => None,
    }
}

fn supports_cs(provider: &PqcTodayProvider, cs: u16) -> bool {
    use openmls_traits::types::Ciphersuite;
    let Ok(c) = Ciphersuite::try_from(cs) else {
        return false;
    };
    provider.crypto().supports(c).is_ok()
}

// ── KAT runner ───────────────────────────────────────────────────────────────

#[test]
fn rfc9420_treekem_vectors_structural_kat() {
    // ── treekem.json structural KAT ──────────────────────────────────────────
    //
    // The full `kat_treekem::run_test_vector` runner is gated behind openmls's
    // `test-utils` feature, which conflicts with our dep chain
    // (`hpke-rs → libcrux → js-sys = 0.3.98` vs. `wasm-bindgen-test = "0.3.50"`
    // pinned by `test-utils`). See `test-vectors/SOURCE.md §dependency-constraints`.
    //
    // What we CAN validate without the internal runner:
    //
    //   1. Every `confirmed_transcript_hash` for a supported ciphersuite decodes
    //      to exactly `hash_len(cipher_suite)` bytes — proves the vector file is
    //      well-formed AND that our ciphersuite → hash-length dispatch is correct.
    //
    //   2. Every `commit_secret` inside each `update_path` decodes to the same
    //      expected hash length — same structural invariant for the per-path
    //      output secret.
    //
    // Together these assert that all 77 vectors parse cleanly and that our
    // hash-length helpers agree with the published values for every ciphersuite
    // present in the file. The vectors are retained for the full
    // `kat_treekem::run_test_vector` run that will replace this test once the
    // dep conflict is resolved (tracked as v0.3 work item in SOURCE.md).

    // We need a live module only to resolve `supports_cs`; the structural
    // checks below don't actually drive crypto. Skip gracefully if absent.
    let env = match setup_provider() {
        Some(e) => e,
        None => {
            eprintln!("skip: no PKCS#11 module found");
            return;
        }
    };

    #[derive(Debug, serde::Deserialize)]
    struct UpdatePath {
        commit_secret: String,
        // Other fields present in the JSON are intentionally ignored.
    }

    #[derive(Debug, serde::Deserialize)]
    struct TreeKemVector {
        cipher_suite: u16,
        confirmed_transcript_hash: String,
        update_paths: Vec<UpdatePath>,
        // Other top-level fields (epoch, group_id, leaves_private,
        // ratchet_tree, tree_hash_after) are intentionally ignored.
    }

    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("test-vectors")
        .join("treekem.json");
    let bytes = std::fs::read(&path).expect("read treekem.json");
    let vectors: Vec<TreeKemVector> = serde_json::from_slice(&bytes).expect("parse treekem.json");

    let mut ran_vectors = 0usize;
    let mut ran_paths = 0usize;
    let mut skipped_vectors = 0usize;

    for (vi, v) in vectors.iter().enumerate() {
        if !supports_cs(&env.provider, v.cipher_suite) {
            skipped_vectors += 1;
            continue;
        }
        let nh = hash_len(v.cipher_suite);
        assert!(
            nh > 0,
            "vector {vi}: cipher_suite {} has unknown hash_len",
            v.cipher_suite
        );

        // ── confirmed_transcript_hash ─────────────────────────────────────
        let cth = hex::decode(&v.confirmed_transcript_hash).unwrap_or_else(|e| {
            panic!(
                "vector {vi} (cs={}): confirmed_transcript_hash hex decode failed: {e}",
                v.cipher_suite
            )
        });
        assert_eq!(
            cth.len(),
            nh,
            "vector {vi} (cs={}): confirmed_transcript_hash is {} bytes, expected {nh}",
            v.cipher_suite,
            cth.len()
        );

        // ── update_paths → commit_secret ─────────────────────────────────
        for (pi, up) in v.update_paths.iter().enumerate() {
            let cs = hex::decode(&up.commit_secret).unwrap_or_else(|e| {
                panic!(
                    "vector {vi} (cs={}) update_path {pi}: commit_secret hex decode failed: {e}",
                    v.cipher_suite
                )
            });
            assert_eq!(
                cs.len(),
                nh,
                "vector {vi} (cs={}) update_path {pi}: commit_secret is {} bytes, expected {nh}",
                v.cipher_suite,
                cs.len()
            );
            ran_paths += 1;
        }

        ran_vectors += 1;
    }

    eprintln!(
        "treekem structural KAT: ran {ran_vectors} vector(s) covering {ran_paths} update_path(s); \
         skipped {skipped_vectors} (unsupported ciphersuites)"
    );
    assert!(
        ran_vectors > 0,
        "at least one supported ciphersuite must run"
    );
}

#[test]
fn rfc9420_key_schedule_hkdf_kat() {
    let env = match setup_provider() {
        Some(e) => e,
        None => {
            eprintln!("skip: no PKCS#11 module found");
            return;
        }
    };
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("test-vectors")
        .join("key-schedule.json");
    let bytes = std::fs::read(&path).expect("read vectors");
    let vectors: Vec<KeyScheduleVector> = serde_json::from_slice(&bytes).expect("parse json");

    let mut ran_vectors = 0;
    let mut ran_epochs = 0;
    let mut skipped_vectors = 0;

    for v in &vectors {
        if !supports_cs(&env.provider, v.cipher_suite) {
            skipped_vectors += 1;
            continue;
        }
        let h = hash_type(v.cipher_suite).expect("hash type");
        let nh = hash_len(v.cipher_suite);

        for (i, e) in v.epochs.iter().enumerate() {
            let joiner_secret = hex::decode(&e.joiner_secret).unwrap();
            let psk_secret = hex::decode(&e.psk_secret).unwrap();
            let expected_welcome = hex::decode(&e.welcome_secret).unwrap();

            // Step 1: intermediate_secret = HKDF.Extract(joiner_secret, psk_secret)
            let intermediate = env
                .provider
                .crypto()
                .hkdf_extract(h, &joiner_secret, &psk_secret)
                .unwrap();

            // Step 2: welcome_secret = ExpandWithLabel(intermediate, "welcome", "", Nh)
            let label = kdf_label(nh as u16, "welcome", &[]);
            let computed_welcome = env
                .provider
                .crypto()
                .hkdf_expand(h, intermediate.as_slice(), &label, nh)
                .unwrap();
            assert_eq!(
                hex::encode(computed_welcome.as_slice()),
                hex::encode(&expected_welcome),
                "cs={} epoch={i}: welcome_secret mismatch",
                v.cipher_suite
            );

            ran_epochs += 1;
        }
        ran_vectors += 1;
    }

    eprintln!(
        "key-schedule KAT: ran {ran_vectors} vector(s) covering {ran_epochs} epoch(s); \
         skipped {skipped_vectors} (unsupported ciphersuites)"
    );
    assert!(ran_vectors > 0, "at least one supported ciphersuite must run");
    assert!(ran_epochs > 0, "at least one epoch must run");
}
