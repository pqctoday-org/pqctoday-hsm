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


/// One engine session for the whole binary.
///
/// Each test used to call `finalize()` then `init()`, which works alone and
/// races when cargo runs them in parallel — they tear down each other's global
/// engine state. The engine is process-global by design; the tests have to
/// share it rather than each own it.
fn shared_session() -> u32 {
    use softhsmrustv3::native::session;
    static S: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *S.get_or_init(|| {
        session::init().expect("engine init");
        session::bootstrap_default_token(0, "so", "user", "xwing-tests")
            .expect("bootstrap session")
    })
}

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
    use softhsmrustv3::native::keygen;
    let sess = shared_session();

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

/// ChaCha20-Poly1305 on the Rust engine, against a known answer.
///
/// Reached through the public raw-key entry point rather than the `pub(crate)`
/// primitive — HPKE hands us key bytes, not a key object, so this is the
/// natural shape. Vector generated with Python `cryptography`.
#[test]
fn chacha20_poly1305_matches_known_answer() {
    use softhsmrustv3::native::encrypt as enc;
    const M: u32 = 0x0000_4021;

    let key: Vec<u8> = (0u8..32).collect();
    let nonce: Vec<u8> = (0u8..12).collect();
    let (aad, pt) = (b"aad-test".as_slice(), b"post-quantum MLS".as_slice());

    let ct = enc::encrypt_with_key_bytes(&key, M, pt, Some(&nonce), None, aad, None)
        .expect("chacha seal");
    assert_eq!(
        hex::encode(&ct),
        "f9947b740466d021d9f74a9eb8504230bd98b19137baba92bbb1746ab710b38c",
        "ChaCha20-Poly1305 ciphertext mismatch"
    );

    let back = enc::decrypt_with_key_bytes(&key, M, &ct, Some(&nonce), None, aad, None)
        .expect("chacha open");
    assert_eq!(back, pt);

    // Authentication must be real: a flipped tag bit has to fail.
    let mut bad = ct.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    assert!(
        enc::decrypt_with_key_bytes(&key, M, &bad, Some(&nonce), None, aad, None).is_err(),
        "a tampered tag was accepted"
    );
}

/// Encapsulate against a raw peer key, decapsulate on the handle side.
///
/// The shape the wire actually uses: the sender has only bytes, the receiver
/// only its own object. Also the last operation that was still on the C++ FFI.
#[test]
fn ml_kem_encapsulate_to_raw_key_round_trips() {
    use softhsmrustv3::native::{keygen, object};
    let sess = shared_session();

    let seed: Vec<u8> = (0u8..64).collect();
    let (h_pub, h_priv) = keygen::generate_ml_kem_keypair_from_seed_extractable(
        sess, 2, &seed, b"encap-rt", "encap-rt",
    )
    .expect("keygen");

    let pk = object::get_attribute(sess, h_pub, 0x0000_0011).expect("CKA_VALUE");
    assert_eq!(pk.len(), 1184, "ML-KEM-768 encapsulation key is 1184 bytes");

    let h_peer = keygen::register_ml_kem_public_key(sess, 2, &pk, b"peer", "peer")
        .expect("import peer key");
    let (ct, ss_send) = encrypt::encapsulate(sess, h_peer, 0x0000_0017).expect("encapsulate");
    assert_eq!(ct.len(), 1088, "ML-KEM-768 ciphertext is 1088 bytes");

    let ss_recv = encrypt::decapsulate(sess, h_priv, 0x0000_0017, &ct).expect("decapsulate");
    assert_eq!(ss_send, ss_recv, "sender and receiver disagree on the secret");
    assert!(ss_send.iter().any(|&b| b != 0), "secret is all zeroes");
}
