//! X-Wing through the **Rust** engine (`softhsmrustv3`), not the C++ module.
//!
//! Why this file exists alongside `kem_ffi.rs`: the C++ path needs `dlopen`, a
//! hand-written C ABI, and workarounds for four mechanisms `cryptoki` cannot
//! name — and it crashes under parallel tests. This path is an ordinary Rust
//! dependency: plain functions, typed `Result`s, no `unsafe`, shared state
//! behind a real `Mutex` (`GlobalState<T>(Mutex<T>)` in `rust/src/state.rs`).
//!
//! No environment variables, no token directory, no module path. If this file
//! passes, `kem_ffi.rs` and its SIGSEGV can be deleted rather than debugged.

#![cfg(not(target_arch = "wasm32"))]

use softhsmrustv3::native::encrypt;

/// draft-connolly-cfrg-xwing-kem-10 §5.3 — XWingLabel, 6 bytes.
const XWING_LABEL: [u8; 6] = [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c];

fn vector(field: &str) -> Vec<u8> {
    let raw = std::fs::read_to_string("tests/fixtures/xwing_kat.json")
        .expect("X-Wing KAT fixture missing");
    let key = format!("\"{field}\": \"");
    let start = raw.find(&key).expect("field not in fixture") + key.len();
    let end = raw[start..].find('"').unwrap() + start;
    hex::decode(&raw[start..end]).expect("bad hex in fixture")
}

/// SHA3-256 and SHAKE-256 come from the same crates the engine uses, so the
/// combiner here is the engine's arithmetic rather than a second opinion.
fn sha3_256(data: &[u8]) -> Vec<u8> {
    use sha3::Digest;
    sha3::Sha3_256::digest(data).to_vec()
}

fn shake256(data: &[u8], out: usize) -> Vec<u8> {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    let mut h = sha3::Shake256::default();
    h.update(data);
    let mut r = h.finalize_xof();
    let mut buf = vec![0u8; out];
    r.read(&mut buf);
    buf
}

/// The engine's own primitives reproduce the draft's seed expansion.
///
/// Checked first and separately: if this fails, nothing downstream is
/// interpretable, and the fault is in the XOF rather than the KEM.
#[test]
fn seed_expansion_matches_draft() {
    let seed = vector("seed");
    let expanded = shake256(&seed, 96);
    assert_eq!(
        hex::encode(&expanded),
        "c44829d2b269887f6150dfaee5a25a704cbc607e57d18a2ffc8734633333cff0\
         f0fc6fa4e4827531168087ef223e9b070c5a78a789fd46d4c604d69b1139d4da\
         cd3f2cce66ed130e5e73a0ebd454e15488885a2a1544252a20e0f58b6e8fc27b",
        "SHAKE256(seed, 96) mismatch"
    );
}

/// The engine exposes ML-KEM encapsulation and decapsulation as plain
/// functions. This is the whole reason for the switch: on the C++ path these
/// are PKCS#11 v3.2 entry points that `cryptoki` cannot reach at all.
#[test]
fn ml_kem_functions_are_directly_callable() {
    // Proves the API shape and that the crate links natively. A real session is
    // set up in the round-trip test below; here we only assert that calling
    // with an invalid session is a typed error rather than a crash or a panic —
    // the C ABI equivalent would have been an opaque CK_RV through a raw
    // pointer, if it were reachable at all.
    let r = encrypt::encapsulate(0xdead_beef, 0xdead_beef, 0x0000_0017);
    assert!(r.is_err(), "an invalid session must be a typed Err, not a panic");
}

/// X-Wing decapsulation against the draft's published ciphertext and secret,
/// with ML-KEM computed by the Rust engine.
///
/// The whole construction in one assertion: seed expansion, deterministic
/// ML-KEM keygen from the derived d‖z, ML-KEM decapsulation in the engine,
/// X25519, and the SHA3-256 combiner. One wrong byte anywhere fails it.
#[test]
fn xwing_decapsulate_matches_draft_vector() {
    use softhsmrustv3::native::{keygen, session};

    let _ = session::finalize();
    session::init().expect("engine init");
    let sess = session::bootstrap_default_token(0, "so", "user", "xwing-kat")
        .expect("bootstrap session");

    // §5.2: expanded = SHAKE256(sk, 96); (d,z) = [0..64]; sk_X = [64..96]
    let expanded = shake256(&vector("seed"), 96);

    // CKP_ML_KEM_768 = 2 (pkcs11t.h). Extractable so the KAT can read the
    // public key back out; the live path has no such need.
    let (h_pub, h_priv) = keygen::generate_ml_kem_keypair_from_seed_extractable(
        sess, 2, &expanded[0..64], b"xwing-kat", "xwing-kat",
    )
    .expect("deterministic ML-KEM-768 keygen");

    let mut sk_x = [0u8; 32];
    sk_x.copy_from_slice(&expanded[64..96]);
    let sk_x = x25519_dalek::StaticSecret::from(sk_x);
    let pk_x = x25519_dalek::PublicKey::from(&sk_x);

    // §5.5: ct_M = ct[0..1088], ct_X = ct[1088..1120]
    let ct = vector("ct");
    assert_eq!(ct.len(), 1120, "X-Wing ciphertext is 1120 bytes");
    let (ct_m, ct_x) = ct.split_at(1088);

    // CKM_ML_KEM = 0x17
    let ss_m = encrypt::decapsulate(sess, h_priv, 0x0000_0017, ct_m)
        .expect("ML-KEM decapsulate");

    let mut ct_x_arr = [0u8; 32];
    ct_x_arr.copy_from_slice(ct_x);
    let ss_x = sk_x.diffie_hellman(&x25519_dalek::PublicKey::from(ct_x_arr));

    // §5.3: SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ XWingLabel)
    let mut input = Vec::with_capacity(32 * 4 + XWING_LABEL.len());
    input.extend_from_slice(&ss_m);
    input.extend_from_slice(ss_x.as_bytes());
    input.extend_from_slice(ct_x);
    input.extend_from_slice(pk_x.as_bytes());
    input.extend_from_slice(&XWING_LABEL);

    assert_eq!(
        hex::encode(sha3_256(&input)),
        hex::encode(vector("ss")),
        "X-Wing shared secret does not match the draft vector"
    );
    let _ = h_pub;
}
