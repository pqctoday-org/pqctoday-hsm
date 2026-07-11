//! Cross-implementation KEM interop: our KMIP Encapsulate/Decapsulate ops
//! versus OpenSSL's KEM, in BOTH directions. This proves our KEM is byte-
//! interoperable with a reference implementation (OpenSSL 3.5) — not merely
//! self-consistent.
//!
//! Scope note (honest): OpenSSL cannot serialize the X25519MLKEM768 *composite*
//! key (no encoders for the TLS-group hybrid — verified on 3.5.6 and 3.6.2), so
//! a whole-hybrid-key exchange through the CLI is impossible. But OpenSSL DOES
//! serialize standalone ML-KEM-768, and our hybrid is exactly
//! `ek_mlkem ‖ x_pub` / `ct_mlkem ‖ x_eph` / `ss_mlkem ‖ ss_x25519`. So we test
//! the ML-KEM half whole (here) and the hybrid decomposed (see
//! openssl_hybrid_interop.rs). Together with the RFC 7748 X25519 KAT and the
//! draft-order structural asserts, that is a full interop proof.
//!
//! Requires the `openssl` CLI on PATH (present in the build container, 3.5.6).

use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use pqctoday_kmip::auditlog::{AuditSink, RingSink};
use pqctoday_kmip::kmip30::{
    Attribute, DecapsulateRequest, EncapsulateRequest, KeyBlock, KeyFormatType, KmipAlgorithm,
    ObjectType, RegisterRequest, UsageMask,
};
use pqctoday_kmip::kmip30::{ActivateRequest, CreateKeyPairRequest};
use pqctoday_kmip::ops::activate::activate;
use pqctoday_kmip::ops::create_key_pair::create_key_pair;
use pqctoday_kmip::ops::decapsulate::decapsulate;
use pqctoday_kmip::ops::encapsulate::encapsulate;
use pqctoday_kmip::ops::register_import_export::register;
use pqctoday_kmip::ops::{Deps, DepsConfig};
use pqctoday_kmip::policy::Engine;
use pqctoday_kmip::store::MemoryStore;

const MLKEM768_EK: usize = 1184;
const MLKEM768_CT: usize = 1088;
const X25519_LEN: usize = 32;
/// 12-byte X25519 SubjectPublicKeyInfo prefix (SEQUENCE / AlgId(OID id-X25519
/// 1.3.101.110) / BIT STRING header) — constant for the 32-byte raw key.
const X25519_SPKI_PREFIX: [u8; 12] =
    [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00];

fn engine_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

fn deps() -> Deps {
    use softhsmrustv3::native::session;
    let _ = session::finalize();
    session::init().expect("engine init");
    let s = session::bootstrap_default_token(0, "so-pin", "user-pin", "ossl-interop")
        .expect("bootstrap engine session");
    let ring = Arc::new(RingSink::new(64));
    let sink: Arc<dyn AuditSink> = ring;
    Deps::new(Engine::permissive(), Arc::new(MemoryStore::new()), sink, DepsConfig::default())
        .with_engine_session(s)
}

/// Per-test scratch dir under the system temp.
fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("kem-interop-{tag}"));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("mkdir");
    d
}

/// Whether the `openssl` CLI on PATH supports ML-KEM-768 (requires OpenSSL
/// 3.5+; the container this was developed against has 3.5.6). CI's plain
/// `ubuntu-24.04` runner (the "Rust Tests" job, unlike the C++ jobs which
/// build OpenSSL 3.6 from source) ships the distro default (3.0.13), which
/// predates ML-KEM entirely — `genpkey -algorithm ML-KEM-768` fails with
/// "unsupported...Global default library context". Interop tests degrade
/// gracefully (skip, not fail) in an environment lacking the capability
/// they're testing, rather than hard-failing CI on an unrelated OpenSSL
/// version gap.
fn openssl_supports_mlkem768() -> bool {
    let dir = std::env::temp_dir();
    Command::new("openssl")
        .args(["genpkey", "-algorithm", "ML-KEM-768", "-out", "/dev/null"])
        .current_dir(&dir)
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

/// Run `openssl <args>` in `dir`, panicking with stderr on failure.
fn ossl(dir: &PathBuf, args: &[&str]) {
    let out = Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("spawn openssl (is it on PATH?)");
    assert!(
        out.status.success(),
        "openssl {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
}

fn read(dir: &PathBuf, name: &str) -> Vec<u8> {
    std::fs::read(dir.join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"))
}
fn write(dir: &PathBuf, name: &str, bytes: &[u8]) {
    std::fs::write(dir.join(name), bytes).expect("write");
}

fn register_key(
    d: &Deps,
    object_type: ObjectType,
    alg: KmipAlgorithm,
    key_bytes: Vec<u8>,
    usage: UsageMask,
) -> String {
    use time::OffsetDateTime;
    let len_bits = (key_bytes.len() * 8) as u32;
    register(
        d,
        RegisterRequest {
            secret_data_type: None,
            object_type,
            attributes: vec![
                Attribute::CryptographicAlgorithm(alg),
                Attribute::CryptographicLength(len_bits),
                Attribute::CryptographicUsageMask(usage),
                // Past activation date → born Active (encaps/decaps accept it).
                Attribute::ActivationDate(OffsetDateTime::now_utc().unix_timestamp() - 3600),
            ],
            managed_object: Some(KeyBlock {
                key_format_type: KeyFormatType::Raw,
                cryptographic_algorithm: alg,
                cryptographic_length: len_bits,
                key_value: key_bytes,
                key_wrapping_data: None,
            }),
            protection_storage_masks: None,
            certificate_payload: None,
        },
        "interop-register",
    )
    .expect("register")
    .uid
}

/// Direction 1 — OUR KMIP Encapsulate ↔ OpenSSL decapsulate.
///
/// OpenSSL generates the ML-KEM-768 keypair; we register its public key and
/// encapsulate to it through the KMIP op; OpenSSL decapsulates our ciphertext
/// with its private key. The two shared secrets MUST match — proving our
/// encapsulation (ek parsing, FIPS 203 encaps, ciphertext encoding) is
/// byte-interoperable with OpenSSL's decapsulation.
#[test]
fn mlkem768_our_encap_openssl_decap() {
    if !openssl_supports_mlkem768() {
        eprintln!("skipping: openssl CLI on PATH has no ML-KEM-768 support (needs OpenSSL 3.5+)");
        return;
    }
    let _g = engine_test_lock();
    let dir = tmpdir("d1");
    let d = deps();

    // OpenSSL keypair; extract the raw 1184-byte ek from the SPKI DER tail.
    ossl(&dir, &["genpkey", "-algorithm", "ML-KEM-768", "-out", "m.pem"]);
    ossl(&dir, &["pkey", "-in", "m.pem", "-pubout", "-outform", "DER", "-out", "m_pub.der"]);
    let spki = read(&dir, "m_pub.der");
    let ek = spki[spki.len() - MLKEM768_EK..].to_vec();

    // Register the public key and encapsulate through the KMIP op.
    let pub_uid = register_key(&d, ObjectType::PublicKey, KmipAlgorithm::MlKem768, ek, UsageMask::ENCRYPT);
    let enc = encapsulate(
        &d,
        EncapsulateRequest { uid: pub_uid, input_key_material: None, cryptographic_parameters: None },
        "encap",
    )
    .expect("KMIP encapsulate");
    assert_eq!(enc.data.len(), 1088, "ML-KEM-768 ciphertext length");
    let ss_ours = d.store.get(&enc.uid).unwrap().unwrap().key_material.expect("encap SS");

    // OpenSSL decapsulates our ciphertext with its private key.
    write(&dir, "ct.bin", &enc.data);
    ossl(&dir, &["pkeyutl", "-decap", "-inkey", "m.pem", "-in", "ct.bin", "-secret", "ss_ossl.bin"]);
    let ss_ossl = read(&dir, "ss_ossl.bin");

    assert_eq!(ss_ours, ss_ossl, "our encaps and OpenSSL decaps must agree (interop)");
    assert_eq!(ss_ours.len(), 32);
}

/// Direction 2 — OpenSSL encapsulate ↔ OUR KMIP Decapsulate.
///
/// We generate the ML-KEM-768 keypair (ml-kem crate), register the private key;
/// OpenSSL encapsulates to our public key (raw ek wrapped in a minimal SPKI);
/// we decapsulate OpenSSL's ciphertext through the KMIP op. Secrets MUST match —
/// proving our decapsulation interoperates with OpenSSL's encapsulation.
#[test]
fn mlkem768_openssl_encap_our_decap() {
    use ml_kem::{EncodedSizeUser, KemCore};
    if !openssl_supports_mlkem768() {
        eprintln!("skipping: openssl CLI on PATH has no ML-KEM-768 support (needs OpenSSL 3.5+)");
        return;
    }
    let _g = engine_test_lock();
    let dir = tmpdir("d2");
    let d = deps();

    let (dk, ek) = ml_kem::MlKem768::generate(&mut rand::rngs::OsRng);
    let dk_bytes = dk.as_bytes().as_slice().to_vec();
    let ek_bytes = ek.as_bytes().as_slice().to_vec();
    let priv_uid = register_key(&d, ObjectType::PrivateKey, KmipAlgorithm::MlKem768, dk_bytes, UsageMask::DECRYPT);

    // Wrap our raw ek in the ML-KEM-768 SPKI so OpenSSL can load it. The 22-byte
    // SPKI prefix (SEQUENCE/AlgId(OID id-alg-ml-kem-768)/BIT STRING header) is
    // constant for the fixed 1184-byte ek — lift it from a throwaway OpenSSL key.
    ossl(&dir, &["genpkey", "-algorithm", "ML-KEM-768", "-out", "throwaway.pem"]);
    ossl(&dir, &["pkey", "-in", "throwaway.pem", "-pubout", "-outform", "DER", "-out", "tw_pub.der"]);
    let tw = read(&dir, "tw_pub.der");
    let prefix = tw[..tw.len() - MLKEM768_EK].to_vec();
    assert_eq!(prefix.len(), 22, "ML-KEM-768 SPKI prefix is 22 bytes");
    let ek_spki = [prefix.as_slice(), &ek_bytes].concat();
    write(&dir, "our_ek.der", &ek_spki);

    // OpenSSL encapsulates to our public key.
    ossl(&dir, &[
        "pkeyutl", "-encap", "-inkey", "our_ek.der", "-keyform", "DER", "-pubin",
        "-out", "ct.bin", "-secret", "ss_ossl.bin",
    ]);
    let ct = read(&dir, "ct.bin");
    let ss_ossl = read(&dir, "ss_ossl.bin");
    assert_eq!(ct.len(), 1088);

    // We decapsulate OpenSSL's ciphertext through the KMIP op.
    let dec = decapsulate(
        &d,
        DecapsulateRequest { uid: priv_uid, data: ct, cryptographic_parameters: None },
        "decap",
    )
    .expect("KMIP decapsulate");
    let ss_ours = d.store.get(&dec.uid).unwrap().unwrap().key_material.expect("decap SS");

    assert_eq!(ss_ours, ss_ossl, "OpenSSL encaps and our decaps must agree (interop)");
    assert_eq!(ss_ours.len(), 32);
}

/// Hybrid, decomposed — OUR KMIP X25519MLKEM768 Encapsulate ↔ OpenSSL's
/// ML-KEM-768 decapsulate ‖ X25519 derive.
///
/// OpenSSL can't serialize the composite key, so we build the hybrid public
/// wire share from OpenSSL's serializable component publics (`ek ‖ x_pub`,
/// ML-KEM first per draft-ietf-tls-ecdhe-mlkem), register it, and encapsulate
/// through the KMIP op. We then split our ciphertext (`ct_mlkem ‖ x_eph`) and
/// verify our 64-byte shared secret equals OpenSSL's `ML-KEM.Decap(ct_mlkem) ‖
/// X25519(x_priv, x_eph)`. This proves our hybrid encaps interoperates end-to-
/// end: public-key wire order, ML-KEM encaps, X25519 ephemeral DH, ciphertext
/// order, AND the shared-secret combiner order — all against OpenSSL.
#[test]
fn x25519mlkem768_our_encap_openssl_component_decap() {
    if !openssl_supports_mlkem768() {
        eprintln!("skipping: openssl CLI on PATH has no ML-KEM-768 support (needs OpenSSL 3.5+)");
        return;
    }
    let _g = engine_test_lock();
    let dir = tmpdir("h1");
    let d = deps();

    // OpenSSL component keypairs; extract raw ek (1184) and x_pub (32).
    ossl(&dir, &["genpkey", "-algorithm", "ML-KEM-768", "-out", "m.pem"]);
    ossl(&dir, &["pkey", "-in", "m.pem", "-pubout", "-outform", "DER", "-out", "m_pub.der"]);
    let ek = { let s = read(&dir, "m_pub.der"); s[s.len() - MLKEM768_EK..].to_vec() };
    ossl(&dir, &["genpkey", "-algorithm", "X25519", "-out", "x.pem"]);
    ossl(&dir, &["pkey", "-in", "x.pem", "-pubout", "-outform", "DER", "-out", "x_pub.der"]);
    let x_pub = { let s = read(&dir, "x_pub.der"); s[s.len() - X25519_LEN..].to_vec() };

    // Hybrid wire share: ek ‖ x_pub (ML-KEM first).
    let wire = [ek.as_slice(), x_pub.as_slice()].concat();
    assert_eq!(wire.len(), MLKEM768_EK + X25519_LEN);
    let pub_uid = register_key(
        &d,
        ObjectType::PublicKey,
        KmipAlgorithm::X25519MlKem768,
        wire,
        UsageMask::KEY_AGREEMENT,
    );

    // Our KMIP hybrid Encapsulate.
    let enc = encapsulate(
        &d,
        EncapsulateRequest { uid: pub_uid, input_key_material: None, cryptographic_parameters: None },
        "encap",
    )
    .expect("KMIP hybrid encapsulate");
    assert_eq!(enc.data.len(), MLKEM768_CT + X25519_LEN, "hybrid ciphertext length");
    let ss_ours = d.store.get(&enc.uid).unwrap().unwrap().key_material.expect("encap SS");
    assert_eq!(ss_ours.len(), 64);

    // Verify each half against OpenSSL: ct = ct_mlkem ‖ x_eph.
    let (ct_mlkem, x_eph) = enc.data.split_at(MLKEM768_CT);
    write(&dir, "ct_m.bin", ct_mlkem);
    ossl(&dir, &["pkeyutl", "-decap", "-inkey", "m.pem", "-in", "ct_m.bin", "-secret", "ss_m.bin"]);
    let ss_m = read(&dir, "ss_m.bin");

    // X25519: derive our static secret against our ephemeral public.
    let eph_spki = [X25519_SPKI_PREFIX.as_slice(), x_eph].concat();
    write(&dir, "eph.der", &eph_spki);
    ossl(&dir, &["pkey", "-pubin", "-inform", "DER", "-in", "eph.der", "-pubout", "-out", "eph.pem"]);
    ossl(&dir, &["pkeyutl", "-derive", "-inkey", "x.pem", "-peerkey", "eph.pem", "-out", "ss_x.bin"]);
    let ss_x = read(&dir, "ss_x.bin");

    let expected = [ss_m.as_slice(), ss_x.as_slice()].concat();
    assert_eq!(
        ss_ours, expected,
        "our hybrid SS must equal OpenSSL ML-KEM.Decap(ct_mlkem) ‖ X25519(x_eph) — wire order + combiner interop"
    );
}

/// Hybrid, decomposed, reverse — OpenSSL ML-KEM encapsulate ‖ X25519 derive ↔
/// OUR KMIP X25519MLKEM768 Decapsulate.
///
/// We CreateKeyPair a hybrid key through KMIP (private stays non-extractable in
/// the engine); split its public wire share into `ek ‖ x_pub`; have OpenSSL
/// ML-KEM-encapsulate to our `ek` and X25519-derive against our `x_pub` with a
/// fresh ephemeral; assemble the hybrid ciphertext `ct_mlkem ‖ x_eph` and
/// combined secret `ss_mlkem ‖ ss_x25519`; then our KMIP Decapsulate must
/// recover exactly that secret. Proves our hybrid DECAPS interoperates with
/// OpenSSL-produced components (ciphertext split, ML-KEM decaps, X25519 DH,
/// combiner order).
#[test]
fn x25519mlkem768_openssl_component_encap_our_decap() {
    if !openssl_supports_mlkem768() {
        eprintln!("skipping: openssl CLI on PATH has no ML-KEM-768 support (needs OpenSSL 3.5+)");
        return;
    }
    let _g = engine_test_lock();
    let dir = tmpdir("h2");
    let d = deps();

    // Our hybrid keypair via KMIP; activate both halves.
    let kp = create_key_pair(
        &d,
        CreateKeyPairRequest {
            common_attributes: vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::X25519MlKem768),
                Attribute::CryptographicUsageMask(UsageMask::KEY_AGREEMENT),
            ],
            private_key_attributes: vec![],
            public_key_attributes: vec![],
            seed: None,
        },
        "CreateKeyPair:KeyAgreement",
        "ckp",
    )
    .expect("hybrid keygen");
    for uid in [&kp.private_key_uid, &kp.public_key_uid] {
        activate(&d, ActivateRequest { uid: uid.clone() }, "act").expect("activate");
    }

    // Our public wire share = ek ‖ x_pub.
    let wire = d.store.get(&kp.public_key_uid).unwrap().unwrap().key_material.expect("pub wire share");
    assert_eq!(wire.len(), MLKEM768_EK + X25519_LEN);
    let (ek_ours, x_pub_ours) = wire.split_at(MLKEM768_EK);

    // OpenSSL ML-KEM encapsulates to our ek (wrapped in a minimal SPKI).
    ossl(&dir, &["genpkey", "-algorithm", "ML-KEM-768", "-out", "throwaway.pem"]);
    ossl(&dir, &["pkey", "-in", "throwaway.pem", "-pubout", "-outform", "DER", "-out", "tw_pub.der"]);
    let m_prefix = { let s = read(&dir, "tw_pub.der"); s[..s.len() - MLKEM768_EK].to_vec() };
    write(&dir, "our_ek.der", &[m_prefix.as_slice(), ek_ours].concat());
    ossl(&dir, &[
        "pkeyutl", "-encap", "-inkey", "our_ek.der", "-keyform", "DER", "-pubin",
        "-out", "ct_m.bin", "-secret", "ss_m.bin",
    ]);
    let ct_mlkem = read(&dir, "ct_m.bin");
    let ss_m = read(&dir, "ss_m.bin");

    // OpenSSL X25519 ephemeral, DH against our x_pub → ss_x + x_eph.
    ossl(&dir, &["genpkey", "-algorithm", "X25519", "-out", "eph.pem"]);
    ossl(&dir, &["pkey", "-in", "eph.pem", "-pubout", "-outform", "DER", "-out", "eph_pub.der"]);
    let x_eph = { let s = read(&dir, "eph_pub.der"); s[s.len() - X25519_LEN..].to_vec() };
    write(&dir, "our_xpub.der", &[X25519_SPKI_PREFIX.as_slice(), x_pub_ours].concat());
    ossl(&dir, &["pkey", "-pubin", "-inform", "DER", "-in", "our_xpub.der", "-pubout", "-out", "our_xpub.pem"]);
    ossl(&dir, &["pkeyutl", "-derive", "-inkey", "eph.pem", "-peerkey", "our_xpub.pem", "-out", "ss_x.bin"]);
    let ss_x = read(&dir, "ss_x.bin");

    // Assemble the hybrid ciphertext and expected secret, then OUR Decapsulate.
    let hybrid_ct = [ct_mlkem.as_slice(), x_eph.as_slice()].concat();
    assert_eq!(hybrid_ct.len(), MLKEM768_CT + X25519_LEN);
    let expected = [ss_m.as_slice(), ss_x.as_slice()].concat();

    let dec = decapsulate(
        &d,
        DecapsulateRequest { uid: kp.private_key_uid, data: hybrid_ct, cryptographic_parameters: None },
        "decap",
    )
    .expect("KMIP hybrid decapsulate");
    let ss_ours = d.store.get(&dec.uid).unwrap().unwrap().key_material.expect("decap SS");

    assert_eq!(
        ss_ours, expected,
        "our hybrid decaps must recover OpenSSL's ML-KEM.Encap ‖ X25519 shared secret (interop)"
    );
    assert_eq!(ss_ours.len(), 64);
}
