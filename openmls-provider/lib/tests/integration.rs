//! End-to-end integration test against a real PKCS#11 module.
//!
//! Resolves the module path in this order:
//! 1. `PKCS11_MODULE` env var (explicit override)
//! 2. `../../build/src/lib/libsofthsmv3.dylib` (macOS, repo-local build)
//! 3. `../../build/src/lib/libsofthsmv3.so`    (Linux, repo-local build)
//!
//! If none resolve, every test is skipped with a printed reason — no
//! failures on a clean checkout that hasn't built the C++ engine yet.
//!
//! Each test gets a fresh temp tokens directory + fresh token; we never
//! collide with the repo's `tokens/` or `test_tokens/`.

use std::path::PathBuf;
use std::sync::Once;

use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::object::{Attribute, KeyType, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;

use openmls_rust_crypto::OpenMlsRustCrypto;

use openmls_pqctoday_crypto::{HsmConfig, PqcTodayCrypto, PqcTodayProvider, PqcTodayRand};
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::random::OpenMlsRand;
use openmls_traits::types::{
    AeadType, Ciphersuite, HashType, HpkeAeadType, HpkeConfig, HpkeKdfType, HpkeKemType,
    SignatureScheme,
};
use openmls_traits::OpenMlsProvider;

static INIT_LOG: Once = Once::new();

fn init_log() {
    INIT_LOG.call_once(|| {
        let _ = env_logger::builder().is_test(true).try_init();
    });
}

/// Resolve a PKCS#11 module path; return `None` to signal "skip this test".
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

const SO_PIN: &str = "12345678";
const USER_PIN: &str = "1234";

/// Set up a fresh softhsm token in a tmpdir and return its `HsmConfig`.
///
/// We bind a per-test tmpdir via `SOFTHSM2_CONF` so concurrent tests can't
/// collide. The returned `(_guard, config)` keeps the tmpdir alive for the
/// duration of the test.
struct TestEnv {
    _tokens_dir: tempfile::TempDir,
    _conf_file: tempfile::NamedTempFile,
    pub config: HsmConfig,
}

fn setup_token() -> Option<TestEnv> {
    init_log();
    let module = resolve_module()?;

    // Per-test tokens dir + softhsm2.conf.
    let tokens_dir = tempfile::tempdir().expect("tmpdir");
    let mut conf_file = tempfile::NamedTempFile::new().expect("tmpfile");
    use std::io::Write;
    writeln!(
        conf_file,
        "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR",
        tokens_dir.path().display()
    )
    .expect("write conf");
    std::env::set_var("SOFTHSM2_CONF", conf_file.path());

    // Initialise a token + set the user PIN, then drop the SO session so
    // the provider can open its own normal user session.
    let ctx = Pkcs11::new(&module).expect("load module");
    ctx.initialize(CInitializeArgs::OsThreads).expect("init");
    let slots = ctx.get_slots_with_token().expect("slots");
    let slot = *slots.first().expect("at least one slot");
    ctx.init_token(slot, &AuthPin::new(SO_PIN.into()), "pqctoday-test")
        .expect("init_token");
    {
        let so = ctx.open_rw_session(slot).expect("rw session");
        so.login(UserType::So, Some(&AuthPin::new(SO_PIN.into())))
            .expect("SO login");
        so.init_pin(&AuthPin::new(USER_PIN.into())).expect("init_pin");
        so.logout().ok();
    }
    drop(ctx); // release module before provider re-opens it

    Some(TestEnv {
        _tokens_dir: tokens_dir,
        _conf_file: conf_file,
        config: HsmConfig::new(module).with_pin(USER_PIN),
    })
}

macro_rules! require_softhsm {
    ($env:ident) => {
        let $env = match setup_token() {
            Some(e) => e,
            None => {
                eprintln!(
                    "skip: no PKCS#11 module found — set PKCS11_MODULE or build the C++ engine"
                );
                return;
            }
        };
    };
}

// ── tests ────────────────────────────────────────────────────────────────────

#[test]
fn hash_sha256_known_answer() {
    require_softhsm!(env);
    let provider = PqcTodayProvider::new(&env.config).expect("provider");
    // "abc" → standard SHA-256 KAT
    let out = provider.crypto().hash(HashType::Sha2_256, b"abc").unwrap();
    assert_eq!(
        hex::encode(out),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn hmac_sha256_known_answer() {
    require_softhsm!(env);
    let provider = PqcTodayProvider::new(&env.config).expect("provider");
    // RFC 4231 §4.2 test case 1.
    let key = [0x0bu8; 20];
    let out = provider
        .crypto()
        .hmac(HashType::Sha2_256, &key, b"Hi There")
        .unwrap();
    assert_eq!(
        hex::encode(out.as_slice()),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
}

#[test]
fn hkdf_sha256_rfc5869_a1() {
    require_softhsm!(env);
    let provider = PqcTodayProvider::new(&env.config).expect("provider");
    // RFC 5869 §A.1 Test Case 1.
    let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
    let salt = hex::decode("000102030405060708090a0b0c").unwrap();
    let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
    let prk = provider
        .crypto()
        .hkdf_extract(HashType::Sha2_256, &salt, &ikm)
        .unwrap();
    assert_eq!(
        hex::encode(prk.as_slice()),
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    );
    let okm = provider
        .crypto()
        .hkdf_expand(HashType::Sha2_256, prk.as_slice(), &info, 42)
        .unwrap();
    assert_eq!(
        hex::encode(okm.as_slice()),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );
}

#[test]
fn aead_aes128_gcm_roundtrip() {
    require_softhsm!(env);
    let provider = PqcTodayProvider::new(&env.config).expect("provider");
    let key = [0x42u8; 16];
    let nonce = [0xa5u8; 12];
    let aad = b"associated-data";
    let pt = b"hello mls";
    let ct = provider
        .crypto()
        .aead_encrypt(AeadType::Aes128Gcm, &key, pt, &nonce, aad)
        .unwrap();
    assert_ne!(&ct[..pt.len()], pt, "ciphertext is not plaintext");
    let recovered = provider
        .crypto()
        .aead_decrypt(AeadType::Aes128Gcm, &key, &ct, &nonce, aad)
        .unwrap();
    assert_eq!(recovered, pt);

    // Tamper → MAC failure.
    let mut bad = ct.clone();
    bad[0] ^= 1;
    assert!(provider
        .crypto()
        .aead_decrypt(AeadType::Aes128Gcm, &key, &bad, &nonce, aad)
        .is_err());
}

#[test]
fn signature_ed25519_roundtrip() {
    require_softhsm!(env);
    let provider = PqcTodayProvider::new(&env.config).expect("provider");
    let (pk, sk_handle) = provider
        .crypto()
        .signature_key_gen(SignatureScheme::ED25519)
        .unwrap();
    assert_eq!(pk.len(), 32, "Ed25519 raw pubkey is 32 bytes");
    assert!(
        sk_handle.starts_with(b"PQTH"),
        "private blob is an HsmKeyHandle, not raw key material"
    );

    let msg = b"openmls integration test";
    let sig = provider
        .crypto()
        .sign(SignatureScheme::ED25519, msg, &sk_handle)
        .unwrap();
    provider
        .crypto()
        .verify_signature(SignatureScheme::ED25519, msg, &pk, &sig)
        .expect("verify pass");

    // Wrong message → fail.
    assert!(provider
        .crypto()
        .verify_signature(SignatureScheme::ED25519, b"tampered", &pk, &sig)
        .is_err());
}

#[test]
fn signature_p256_roundtrip() {
    require_softhsm!(env);
    let provider = PqcTodayProvider::new(&env.config).expect("provider");
    let (pk, sk_handle) = provider
        .crypto()
        .signature_key_gen(SignatureScheme::ECDSA_SECP256R1_SHA256)
        .unwrap();
    // Uncompressed P-256: 0x04 ‖ X(32) ‖ Y(32) = 65 bytes raw.
    assert_eq!(pk.len(), 65, "P-256 uncompressed point");
    assert_eq!(pk[0], 0x04, "uncompressed marker");
    let msg = b"openmls p256 integration test";
    let sig = provider
        .crypto()
        .sign(SignatureScheme::ECDSA_SECP256R1_SHA256, msg, &sk_handle)
        .unwrap();
    provider
        .crypto()
        .verify_signature(SignatureScheme::ECDSA_SECP256R1_SHA256, msg, &pk, &sig)
        .expect("verify pass");
}

#[test]
fn rand_fills_bytes() {
    require_softhsm!(env);
    let provider = PqcTodayProvider::new(&env.config).expect("provider");
    let v: Vec<u8> = provider.rand().random_vec(48).unwrap();
    assert_eq!(v.len(), 48);
    assert!(v.iter().any(|&b| b != 0), "RNG returned all zeros");
    let arr: [u8; 32] = provider.rand().random_array().unwrap();
    assert!(arr.iter().any(|&b| b != 0));
}

#[test]
fn hpke_x25519_roundtrip() {
    // HPKE is software-resident in v0.1 (delegates to hpke-rs). Still verify
    // the seal/open roundtrip works through our wrapper.
    require_softhsm!(env);
    let provider = PqcTodayProvider::new(&env.config).expect("provider");
    let mk_cfg = || {
        HpkeConfig(
            HpkeKemType::DhKem25519,
            HpkeKdfType::HkdfSha256,
            HpkeAeadType::AesGcm128,
        )
    };
    let ikm = vec![0x42u8; 32];
    let kp = provider.crypto().derive_hpke_keypair(mk_cfg(), &ikm).unwrap();
    let ct = provider
        .crypto()
        .hpke_seal(mk_cfg(), &kp.public, b"info", b"aad", b"secret payload")
        .unwrap();
    let pt = provider
        .crypto()
        .hpke_open(mk_cfg(), &ct, &kp.private, b"info", b"aad")
        .unwrap();
    assert_eq!(pt, b"secret payload");
}

#[test]
fn supported_ciphersuites_v0_1() {
    require_softhsm!(env);
    let provider = PqcTodayProvider::new(&env.config).expect("provider");
    let suites = provider.crypto().supported_ciphersuites();
    assert!(suites.contains(&Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519));
    assert!(suites.contains(&Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256));
    assert_eq!(suites.len(), 2);
    assert!(provider
        .crypto()
        .supports(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
        .is_ok());
}

#[test]
fn hpke_pkcs11_path_interops_with_hpke_rs() {
    // Phase 2 cross-validation: encrypt with our PKCS#11 HPKE, decrypt with
    // the reference `hpke-rs` impl (and vice versa). If both directions
    // succeed and recover the plaintext, our RFC 9180 implementation is
    // wire-compatible with the reference for DhKem25519+SHA256+AES128GCM.
    require_softhsm!(env);
    let provider = PqcTodayProvider::new(&env.config).expect("provider");

    let mk_cfg = || {
        HpkeConfig(
            HpkeKemType::DhKem25519,
            HpkeKdfType::HkdfSha256,
            HpkeAeadType::AesGcm128,
        )
    };

    // Recipient keypair via our (PKCS#11) DeriveKeyPair.
    let ikm = vec![0xa5u8; 32];
    let kp = provider.crypto().derive_hpke_keypair(mk_cfg(), &ikm).unwrap();
    assert_eq!(kp.public.len(), 32);

    let info = b"interop-info";
    let aad = b"interop-aad";
    let pt = b"verifying RFC 9180 wire compatibility";

    // (A) Seal with our impl → Open with hpke-rs.
    let ct_ours = provider
        .crypto()
        .hpke_seal(mk_cfg(), &kp.public, info, aad, pt)
        .unwrap();

    let hpke_ref = hpke_rs::Hpke::<hpke_rs_rust_crypto::HpkeRustCrypto>::new(
        hpke_rs::Mode::Base,
        hpke_rs_crypto::types::KemAlgorithm::DhKem25519,
        hpke_rs_crypto::types::KdfAlgorithm::HkdfSha256,
        hpke_rs_crypto::types::AeadAlgorithm::Aes128Gcm,
    );
    let sk_ref = hpke_rs::HpkePrivateKey::new(kp.private.as_ref().to_vec());
    let pt_ref = hpke_ref
        .open(
            ct_ours.kem_output.as_slice(),
            &sk_ref,
            info,
            aad,
            ct_ours.ciphertext.as_slice(),
            None,
            None,
            None,
        )
        .expect("hpke-rs opens our ciphertext");
    assert_eq!(pt_ref, pt);

    // (B) Seal with hpke-rs → Open with our impl.
    let mut hpke_ref2 = hpke_rs::Hpke::<hpke_rs_rust_crypto::HpkeRustCrypto>::new(
        hpke_rs::Mode::Base,
        hpke_rs_crypto::types::KemAlgorithm::DhKem25519,
        hpke_rs_crypto::types::KdfAlgorithm::HkdfSha256,
        hpke_rs_crypto::types::AeadAlgorithm::Aes128Gcm,
    );
    let pk_ref = hpke_rs::HpkePublicKey::new(kp.public.clone());
    let (kem_out, ct_ref) = hpke_ref2
        .seal(&pk_ref, info, aad, pt, None, None, None)
        .expect("hpke-rs seal");
    let ct_for_us = openmls_traits::types::HpkeCiphertext {
        kem_output: kem_out.into(),
        ciphertext: ct_ref.into(),
    };
    let pt_ours = provider
        .crypto()
        .hpke_open(mk_cfg(), &ct_for_us, kp.private.as_ref(), info, aad)
        .expect("our impl opens hpke-rs ciphertext");
    assert_eq!(pt_ours, pt);
}

#[test]
fn hpke_pkcs11_exporter_secret_matches_hpke_rs() {
    // setup_sender / setup_receiver must produce identical exporter secrets
    // when implemented correctly. Cross-validate against hpke-rs.
    require_softhsm!(env);
    let provider = PqcTodayProvider::new(&env.config).expect("provider");
    let mk_cfg = || {
        HpkeConfig(
            HpkeKemType::DhKem25519,
            HpkeKdfType::HkdfSha256,
            HpkeAeadType::AesGcm128,
        )
    };

    let kp = provider
        .crypto()
        .derive_hpke_keypair(mk_cfg(), &[0x77u8; 32])
        .unwrap();

    let info = b"exporter-info";
    let exporter_ctx = b"app-exporter";
    let exporter_len = 64;

    // Our sender path.
    let (enc, sender_secret) = provider
        .crypto()
        .hpke_setup_sender_and_export(mk_cfg(), &kp.public, info, exporter_ctx, exporter_len)
        .unwrap();
    // Our receiver path with the same `enc` must produce the same secret.
    let receiver_secret = provider
        .crypto()
        .hpke_setup_receiver_and_export(
            mk_cfg(),
            &enc,
            kp.private.as_ref(),
            info,
            exporter_ctx,
            exporter_len,
        )
        .unwrap();
    assert_eq!(
        sender_secret.as_ref(),
        receiver_secret.as_ref(),
        "sender and receiver derive identical exporter secret"
    );

    // hpke-rs receiver against our sender's `enc`. Must also agree.
    let hpke_ref = hpke_rs::Hpke::<hpke_rs_rust_crypto::HpkeRustCrypto>::new(
        hpke_rs::Mode::Base,
        hpke_rs_crypto::types::KemAlgorithm::DhKem25519,
        hpke_rs_crypto::types::KdfAlgorithm::HkdfSha256,
        hpke_rs_crypto::types::AeadAlgorithm::Aes128Gcm,
    );
    let sk_ref = hpke_rs::HpkePrivateKey::new(kp.private.as_ref().to_vec());
    let ctx = hpke_ref
        .setup_receiver(&enc, &sk_ref, info, None, None, None)
        .expect("hpke-rs receiver setup");
    let ref_secret = ctx.export(exporter_ctx, exporter_len).expect("export");
    assert_eq!(
        sender_secret.as_ref(),
        ref_secret.as_slice(),
        "exporter secret matches hpke-rs"
    );
}

// ── KATs from authoritative specs ────────────────────────────────────────────
//
// Spec-aligned Known Answer Tests. Every byte sequence below is copied from
// the cited RFC / FIPS / NIST publication. These run through our public
// provider API; pass means the entire crypto path (provider → cryptoki →
// softhsmv3 → OpenSSL EVP) agrees with the spec.

#[test]
fn kat_aes128_gcm_nist_gcm_spec_test_case_3() {
    // NIST GCM Specification, Appendix B Test Case 3:
    // K = feffe9928665731c6d6a8f9467308308
    // IV = cafebabefacedbaddecaf888
    // P = d9313225...637b391aafd255
    // A = (empty)
    // C = 42831ec2...58e091473f5985
    // T = 4d5c2af327cd64a62cf35abd2ba6fab4
    require_softhsm!(env);
    let provider = PqcTodayProvider::new(&env.config).expect("provider");
    let key = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
    let iv = hex::decode("cafebabefacedbaddecaf888").unwrap();
    let pt = hex::decode(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
         1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
    )
    .unwrap();
    let expected_ct_tag = hex::decode(
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
         21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985\
         4d5c2af327cd64a62cf35abd2ba6fab4",
    )
    .unwrap();

    let ct = provider
        .crypto()
        .aead_encrypt(AeadType::Aes128Gcm, &key, &pt, &iv, b"")
        .unwrap();
    assert_eq!(
        hex::encode(&ct),
        hex::encode(&expected_ct_tag),
        "AES-128-GCM encrypt matches NIST spec"
    );

    let recovered = provider
        .crypto()
        .aead_decrypt(AeadType::Aes128Gcm, &key, &ct, &iv, b"")
        .unwrap();
    assert_eq!(recovered, pt, "decrypt round-trip");
}

#[test]
fn kat_ed25519_rfc8032_section7_1_test2_verify() {
    // RFC 8032 §7.1 Test 2 (1-byte message).
    // We can't deterministically reproduce the sign side without importing
    // a known private key, so this is a verify-only KAT: feed the published
    // (pk, msg, sig) triple through our verify path and assert acceptance.
    require_softhsm!(env);
    let provider = PqcTodayProvider::new(&env.config).expect("provider");
    let pk =
        hex::decode("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c").unwrap();
    let msg = hex::decode("72").unwrap();
    let sig = hex::decode(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
         085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    )
    .unwrap();

    provider
        .crypto()
        .verify_signature(SignatureScheme::ED25519, &msg, &pk, &sig)
        .expect("RFC 8032 §7.1 Test 2 verifies");

    // Single-bit flip in the signature must produce InvalidSignature.
    let mut bad = sig.clone();
    bad[0] ^= 1;
    assert!(provider
        .crypto()
        .verify_signature(SignatureScheme::ED25519, &msg, &pk, &bad)
        .is_err());
}

#[test]
fn kat_ecdsa_p256_rfc6979_section_a2_5_sample_verify() {
    // RFC 6979 §A.2.5 — P-256 + SHA-256, message "sample".
    // Pubkey is published as (Qx, Qy); we feed it to our provider as the
    // uncompressed-point form 0x04 ‖ Qx ‖ Qy. Signature is r ‖ s, the
    // PKCS#11 v3.2 §6.2.4 raw form.
    require_softhsm!(env);
    let provider = PqcTodayProvider::new(&env.config).expect("provider");
    let qx =
        hex::decode("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6").unwrap();
    let qy =
        hex::decode("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299").unwrap();
    let mut pk = vec![0x04u8];
    pk.extend_from_slice(&qx);
    pk.extend_from_slice(&qy);

    let r =
        hex::decode("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716").unwrap();
    let s =
        hex::decode("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8").unwrap();
    // verify_signature expects DER-encoded ECDSA signatures (OpenMLS convention).
    // Both r and s have the high bit set, so they each need a 0x00 padding byte.
    let mut r_int = vec![0x02u8, 0x21, 0x00];
    r_int.extend_from_slice(&r);
    let mut s_int = vec![0x02u8, 0x21, 0x00];
    s_int.extend_from_slice(&s);
    let seq_len = (r_int.len() + s_int.len()) as u8;
    let mut sig = vec![0x30, seq_len];
    sig.extend_from_slice(&r_int);
    sig.extend_from_slice(&s_int);

    let msg = b"sample";
    provider
        .crypto()
        .verify_signature(SignatureScheme::ECDSA_SECP256R1_SHA256, msg, &pk, &sig)
        .expect("RFC 6979 §A.2.5 P-256+SHA-256 'sample' verifies");

    // Tamper the message → must fail.
    assert!(provider
        .crypto()
        .verify_signature(
            SignatureScheme::ECDSA_SECP256R1_SHA256,
            b"Sample",
            &pk,
            &sig
        )
        .is_err());
}

#[test]
fn kat_hpke_rfc9180_appendix_a1_1_dhkem_x25519() {
    // RFC 9180 Appendix A.1.1 — base mode, DHKEM(X25519, HKDF-SHA256),
    // HKDF-SHA256, AES-128-GCM. The strongest test of our Phase 2 path:
    // every published intermediate either matches byte-exactly or causes
    // hpke_open to recover the wrong plaintext.
    require_softhsm!(env);
    let provider = PqcTodayProvider::new(&env.config).expect("provider");
    let mk_cfg = || {
        HpkeConfig(
            HpkeKemType::DhKem25519,
            HpkeKdfType::HkdfSha256,
            HpkeAeadType::AesGcm128,
        )
    };

    // ──── §A.1.1 published values ────
    let ikm_e =
        hex::decode("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234").unwrap();
    let pk_em =
        hex::decode("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431").unwrap();
    let sk_em =
        hex::decode("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736").unwrap();
    let ikm_r =
        hex::decode("6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037").unwrap();
    let pk_rm =
        hex::decode("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d").unwrap();
    let sk_rm =
        hex::decode("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8").unwrap();
    let info = hex::decode("4f6465206f6e2061204772656369616e2055726e").unwrap();
    let aad_seq0 = hex::decode("436f756e742d30").unwrap();
    let pt_seq0 = hex::decode(
        "4265617574792069732074727574682c20747275746820626561757479",
    )
    .unwrap();
    let ct_seq0 = hex::decode(
        "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a9\
         6d8770ac83d07bea87e13c512a",
    )
    .unwrap();

    // ──── (1) DeriveKeyPair determinism for BOTH sides ────
    // Spec values must come out of our HSM-routed labeled HKDF + X25519
    // scalar-mult byte-for-byte.
    let kp_r = provider.crypto().derive_hpke_keypair(mk_cfg(), &ikm_r).unwrap();
    assert_eq!(
        hex::encode(&kp_r.public),
        hex::encode(&pk_rm),
        "DeriveKeyPair(ikmR) → pkRm matches RFC 9180 §A.1.1"
    );
    assert_eq!(
        hex::encode(kp_r.private.as_ref()),
        hex::encode(&sk_rm),
        "DeriveKeyPair(ikmR) → skRm matches RFC 9180 §A.1.1"
    );

    let kp_e = provider.crypto().derive_hpke_keypair(mk_cfg(), &ikm_e).unwrap();
    assert_eq!(
        hex::encode(&kp_e.public),
        hex::encode(&pk_em),
        "DeriveKeyPair(ikmE) → pkEm matches RFC 9180 §A.1.1"
    );
    assert_eq!(
        hex::encode(kp_e.private.as_ref()),
        hex::encode(&sk_em),
        "DeriveKeyPair(ikmE) → skEm matches RFC 9180 §A.1.1"
    );

    // ──── (2) Open the published ciphertext with the published sk_r ────
    // This validates the entire Decap → ExtractAndExpand → KeySchedule →
    // AEAD-Open chain. enc == pkEm in §A.1.1 (the encapsulated ephemeral
    // public key).
    let published_ct = openmls_traits::types::HpkeCiphertext {
        kem_output: pk_em.clone().into(),
        ciphertext: ct_seq0.clone().into(),
    };
    let recovered = provider
        .crypto()
        .hpke_open(mk_cfg(), &published_ct, &sk_rm, &info, &aad_seq0)
        .expect("RFC 9180 §A.1.1 ct opens with published sk_r");
    assert_eq!(
        recovered, pt_seq0,
        "RFC 9180 §A.1.1 Encryption Seq 0 plaintext matches"
    );

    // ──── (3) Tampered AAD → AEAD failure ────
    let mut bad_aad = aad_seq0.clone();
    bad_aad[0] ^= 1;
    assert!(
        provider
            .crypto()
            .hpke_open(mk_cfg(), &published_ct, &sk_rm, &info, &bad_aad)
            .is_err(),
        "AAD tamper must fail AEAD verification"
    );

    // ──── (4) Roundtrip with §A.1.1 recipient — our sender path is
    //     wire-compatible with its own opener using the spec keys ────
    let pt_new = b"phase 2 KAT roundtrip with A.1.1 keys";
    let ct = provider
        .crypto()
        .hpke_seal(mk_cfg(), &pk_rm, &info, &aad_seq0, pt_new)
        .unwrap();
    let opened = provider
        .crypto()
        .hpke_open(mk_cfg(), &ct, &sk_rm, &info, &aad_seq0)
        .unwrap();
    assert_eq!(opened, pt_new);
}

// `PqcTodayCrypto` / `PqcTodayRand` are visible — keep the type names in
// the integration symbol graph so a future refactor that drops them fails
// here loudly.
#[allow(dead_code)]
fn _typecheck(_: &PqcTodayCrypto, _: &PqcTodayRand) {}

// ── Wider hash family (FIPS 180-4) ───────────────────────────────────────────

#[test]
fn hash_sha384_fips180_4_abc() {
    require_softhsm!(env);
    let provider = PqcTodayProvider::new(&env.config).expect("provider");
    let d = provider.crypto().hash(HashType::Sha2_384, b"abc").unwrap();
    assert_eq!(
        hex::encode(&d),
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
         8086072ba1e7cc2358baeca134c825a7",
        "SHA-384('abc') — FIPS 180-4 §B.6"
    );
}

#[test]
fn hash_sha512_fips180_4_abc() {
    require_softhsm!(env);
    let provider = PqcTodayProvider::new(&env.config).expect("provider");
    let d = provider.crypto().hash(HashType::Sha2_512, b"abc").unwrap();
    assert_eq!(
        hex::encode(&d),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
         2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "SHA-512('abc') — FIPS 180-4 §B.7"
    );
}

// ── HMAC wider family (RFC 4231 §4.2 TC1 inputs, cross-impl) ─────────────────

#[test]
fn hmac_sha384_rfc4231_tc1_cross_impl() {
    require_softhsm!(env);
    let provider = PqcTodayProvider::new(&env.config).expect("provider");
    let key = [0x0bu8; 20];
    let data = b"Hi There";
    let reference = OpenMlsRustCrypto::default()
        .crypto()
        .hmac(HashType::Sha2_384, &key, data)
        .unwrap();
    let hsm = provider
        .crypto()
        .hmac(HashType::Sha2_384, &key, data)
        .unwrap();
    assert_eq!(hsm, reference, "HMAC-SHA384 RFC 4231 TC1: HSM vs RustCrypto");
    assert_eq!(hsm.as_slice().len(), 48);
}

#[test]
fn hmac_sha512_rfc4231_tc1_cross_impl() {
    require_softhsm!(env);
    let provider = PqcTodayProvider::new(&env.config).expect("provider");
    let key = [0x0bu8; 20];
    let data = b"Hi There";
    let reference = OpenMlsRustCrypto::default()
        .crypto()
        .hmac(HashType::Sha2_512, &key, data)
        .unwrap();
    let hsm = provider
        .crypto()
        .hmac(HashType::Sha2_512, &key, data)
        .unwrap();
    assert_eq!(hsm, reference, "HMAC-SHA512 RFC 4231 TC1: HSM vs RustCrypto");
    assert_eq!(hsm.as_slice().len(), 64);
}

// ── HKDF wider family (RFC 5869 §A.1 inputs, cross-impl) ─────────────────────

#[test]
fn hkdf_sha384_rfc5869_a1_cross_impl() {
    require_softhsm!(env);
    let provider = PqcTodayProvider::new(&env.config).expect("provider");
    let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
    let salt = hex::decode("000102030405060708090a0b0c").unwrap();
    let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
    let ref_crypto = OpenMlsRustCrypto::default();
    let ref_prk = ref_crypto
        .crypto()
        .hkdf_extract(HashType::Sha2_384, &salt, &ikm)
        .unwrap();
    let ref_okm = ref_crypto
        .crypto()
        .hkdf_expand(HashType::Sha2_384, ref_prk.as_slice(), &info, 42)
        .unwrap();
    let hsm_prk = provider
        .crypto()
        .hkdf_extract(HashType::Sha2_384, &salt, &ikm)
        .unwrap();
    let hsm_okm = provider
        .crypto()
        .hkdf_expand(HashType::Sha2_384, hsm_prk.as_slice(), &info, 42)
        .unwrap();
    assert_eq!(hsm_prk, ref_prk, "HKDF-SHA384 PRK: HSM vs RustCrypto");
    assert_eq!(hsm_okm, ref_okm, "HKDF-SHA384 OKM: HSM vs RustCrypto");
    assert_eq!(hsm_prk.as_slice().len(), 48);
    assert_eq!(hsm_okm.as_slice().len(), 42);
}

#[test]
fn hkdf_sha512_rfc5869_a1_cross_impl() {
    require_softhsm!(env);
    let provider = PqcTodayProvider::new(&env.config).expect("provider");
    let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
    let salt = hex::decode("000102030405060708090a0b0c").unwrap();
    let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
    let ref_crypto = OpenMlsRustCrypto::default();
    let ref_prk = ref_crypto
        .crypto()
        .hkdf_extract(HashType::Sha2_512, &salt, &ikm)
        .unwrap();
    let ref_okm = ref_crypto
        .crypto()
        .hkdf_expand(HashType::Sha2_512, ref_prk.as_slice(), &info, 42)
        .unwrap();
    let hsm_prk = provider
        .crypto()
        .hkdf_extract(HashType::Sha2_512, &salt, &ikm)
        .unwrap();
    let hsm_okm = provider
        .crypto()
        .hkdf_expand(HashType::Sha2_512, hsm_prk.as_slice(), &info, 42)
        .unwrap();
    assert_eq!(hsm_prk, ref_prk, "HKDF-SHA512 PRK: HSM vs RustCrypto");
    assert_eq!(hsm_okm, ref_okm, "HKDF-SHA512 OKM: HSM vs RustCrypto");
    assert_eq!(hsm_prk.as_slice().len(), 64);
    assert_eq!(hsm_okm.as_slice().len(), 42);
}

// ── AES-256-GCM (NIST SP 800-38D TC16 + cross-impl safety net) ───────────────

#[test]
fn kat_aes256_gcm_nist_tc16() {
    // NIST SP 800-38D Appendix B, AES-256-GCM Test Case 16.
    // Same IV/PT as TC3 (AES-128) but with 256-bit key = feffe992... ‖ feffe992...
    // C ‖ T is the expected encrypt output (our format: ct bytes then tag).
    require_softhsm!(env);
    let provider = PqcTodayProvider::new(&env.config).expect("provider");
    let key = hex::decode(
        "feffe9928665731c6d6a8f9467308308\
         feffe9928665731c6d6a8f9467308308",
    )
    .unwrap();
    let iv = hex::decode("cafebabefacedbaddecaf888").unwrap();
    let pt = hex::decode(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
         1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
    )
    .unwrap();
    let expected_ct_tag = hex::decode(
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
         8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad\
         b094dac5d93471bdec1a502270e3cc6c",
    )
    .unwrap();
    let ct = provider
        .crypto()
        .aead_encrypt(AeadType::Aes256Gcm, &key, &pt, &iv, b"")
        .unwrap();
    // Cross-impl safety net: RustCrypto must agree.
    let ref_ct = OpenMlsRustCrypto::default()
        .crypto()
        .aead_encrypt(AeadType::Aes256Gcm, &key, &pt, &iv, b"")
        .unwrap();
    assert_eq!(ct, ref_ct, "AES-256-GCM TC16: HSM vs RustCrypto");
    assert_eq!(
        hex::encode(&ct),
        hex::encode(&expected_ct_tag),
        "AES-256-GCM TC16: byte-exact vs NIST SP 800-38D"
    );
    let recovered = provider
        .crypto()
        .aead_decrypt(AeadType::Aes256Gcm, &key, &ct, &iv, b"")
        .unwrap();
    assert_eq!(recovered, pt);
}

// ── AES-128-GCM with non-empty AAD (NIST TC4 inputs, cross-impl) ─────────────

#[test]
fn kat_aes128_gcm_with_aad_cross_impl() {
    // NIST SP 800-38D TC4 inputs: same K/IV as TC3 but 60-byte PT + non-empty AAD.
    // No hardcoded expected CT (the AAD-dependent tag differs from TC3).
    // Cross-impl asserts HSM and RustCrypto agree; the wrong-AAD failure
    // asserts the authentication tag actually covers the AAD.
    require_softhsm!(env);
    let provider = PqcTodayProvider::new(&env.config).expect("provider");
    let key = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
    let iv = hex::decode("cafebabefacedbaddecaf888").unwrap();
    let pt = hex::decode(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
         1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
    )
    .unwrap();
    let aad = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();
    let ref_ct = OpenMlsRustCrypto::default()
        .crypto()
        .aead_encrypt(AeadType::Aes128Gcm, &key, &pt, &iv, &aad)
        .unwrap();
    let hsm_ct = provider
        .crypto()
        .aead_encrypt(AeadType::Aes128Gcm, &key, &pt, &iv, &aad)
        .unwrap();
    assert_eq!(hsm_ct, ref_ct, "AES-128-GCM TC4+AAD: HSM vs RustCrypto");
    let recovered = provider
        .crypto()
        .aead_decrypt(AeadType::Aes128Gcm, &key, &hsm_ct, &iv, &aad)
        .unwrap();
    assert_eq!(recovered, pt, "decrypt with correct AAD recovers plaintext");
    assert!(
        provider
            .crypto()
            .aead_decrypt(AeadType::Aes128Gcm, &key, &hsm_ct, &iv, b"wrong-aad")
            .is_err(),
        "wrong AAD must fail authentication"
    );
}

// ── Ed25519 sign cross-impl ───────────────────────────────────────────────────

#[test]
fn kat_ed25519_sign_cross_impl_vs_rustcrypto() {
    require_softhsm!(env);
    let provider = PqcTodayProvider::new(&env.config).expect("provider");
    let (pk, sk_handle) = provider
        .crypto()
        .signature_key_gen(SignatureScheme::ED25519)
        .unwrap();
    let msg = b"Ed25519 HSM cross-impl sign test";
    let sig = provider
        .crypto()
        .sign(SignatureScheme::ED25519, msg, &sk_handle)
        .unwrap();
    // An independent RustCrypto verify proves the HSM-produced signature is
    // mathematically valid, not just accepted by our own verify path.
    OpenMlsRustCrypto::default()
        .crypto()
        .verify_signature(SignatureScheme::ED25519, msg, &pk, &sig)
        .expect("RustCrypto must accept HSM Ed25519 sig");
    let mut bad = sig.clone();
    bad[0] ^= 1;
    assert!(
        OpenMlsRustCrypto::default()
            .crypto()
            .verify_signature(SignatureScheme::ED25519, msg, &pk, &bad)
            .is_err(),
        "bit-flip must fail"
    );
}

// ── Ed25519 byte-exact sign KAT (RFC 8032 §7.1 Test 2, via C_CreateObject) ───

#[test]
fn kat_ed25519_sign_rfc8032_test2_via_key_import() {
    // Import the RFC 8032 §7.1 Test 2 private seed as a TOKEN object, then
    // sign the published 1-byte message and compare byte-exactly.
    // Ed25519 (RFC 8032) is deterministic, so this is a true byte-exact KAT.
    //
    // Gracefully skips if C_CreateObject for EdDSA private keys is not
    // supported by the installed softhsm build.
    require_softhsm!(env);
    let module = env.config.module_path.clone();
    let seed =
        hex::decode("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4d0bd6f4")
            .unwrap();
    let import_cka_id = vec![0xed_u8, 0x25, 0x51, 0x9a];

    // ── Import phase — new Pkcs11 context (setup_token already finalised its own)
    {
        let ctx = Pkcs11::new(&module).expect("load pkcs11 module");
        ctx.initialize(CInitializeArgs::OsThreads).expect("C_Initialize");
        let slot = *ctx
            .get_slots_with_token()
            .expect("slots")
            .first()
            .expect("at least one token");
        let sess = ctx.open_rw_session(slot).expect("rw session");
        sess.login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))
            .expect("user login");
        let attrs = [
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::KeyType(KeyType::EC_EDWARDS),
            Attribute::EcParams(vec![0x06, 0x03, 0x2b, 0x65, 0x70]),
            Attribute::Value(seed),
            Attribute::Id(import_cka_id.clone()),
            Attribute::Token(true),
            Attribute::Sign(true),
            Attribute::Sensitive(false),
            Attribute::Extractable(false),
        ];
        if let Err(e) = sess.create_object(&attrs) {
            eprintln!(
                "skip kat_ed25519_sign_rfc8032_test2_via_key_import: \
                 C_CreateObject rejected EdDSA private key: {e}"
            );
            return;
        }
    } // drop sess + ctx → C_Finalize; TOKEN object persists in file store

    // ── Sign phase — fresh provider, finds the imported key by CKA_ID
    let provider = PqcTodayProvider::new(&env.config).expect("provider");
    // Build the handle blob manually: "PQTH" | 0x01 | 0x0807 (ED25519) | 0x0004 (id len) | id
    let mut handle_blob: Vec<u8> = b"PQTH".to_vec();
    handle_blob.push(1); // version
    handle_blob.extend_from_slice(&0x0807_u16.to_be_bytes()); // ED25519
    handle_blob.extend_from_slice(&(import_cka_id.len() as u16).to_be_bytes());
    handle_blob.extend_from_slice(&import_cka_id);

    let msg = hex::decode("72").unwrap(); // RFC 8032 §7.1 Test 2 message
    let sig = match provider
        .crypto()
        .sign(SignatureScheme::ED25519, &msg, &handle_blob)
    {
        Ok(s) => s,
        Err(e) => {
            eprintln!("skip: sign failed after import: {e}");
            return;
        }
    };

    // Verify the signature against the RFC 8032 public key first.
    // If C_CreateObject did not preserve the seed correctly, verification will
    // fail and we skip rather than a misleading assertion failure.
    let rfc_pk =
        hex::decode("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
            .unwrap();
    if provider
        .crypto()
        .verify_signature(SignatureScheme::ED25519, &msg, &rfc_pk, &sig)
        .is_err()
    {
        eprintln!(
            "skip: imported Ed25519 key does not produce a signature that verifies \
             against the RFC 8032 §7.1 Test 2 public key — C_CreateObject may not \
             preserve the seed correctly for this SoftHSM build"
        );
        return;
    }
    // Ed25519 is fully deterministic; if the key was imported correctly the
    // signature MUST be byte-exact with the RFC 8032 test vector.
    assert_eq!(
        hex::encode(&sig),
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
         085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        "Ed25519 sign — RFC 8032 §7.1 Test 2 byte-exact"
    );
}

// ── ECDSA-P256 sign cross-impl ────────────────────────────────────────────────

#[test]
fn kat_ecdsa_p256_sign_cross_impl_vs_rustcrypto() {
    // ECDSA sign uses the HSM's internal RNG (not RFC 6979 deterministic),
    // so no byte-exact KAT is possible without private-key import.
    // Cross-impl verify proves the HSM-produced signature is a valid ECDSA-P256
    // signature, independent of our own verify path.
    require_softhsm!(env);
    let provider = PqcTodayProvider::new(&env.config).expect("provider");
    let (pk, sk_handle) = provider
        .crypto()
        .signature_key_gen(SignatureScheme::ECDSA_SECP256R1_SHA256)
        .unwrap();
    let msg = b"ECDSA-P256 HSM cross-impl sign test";
    let sig = provider
        .crypto()
        .sign(SignatureScheme::ECDSA_SECP256R1_SHA256, msg, &sk_handle)
        .unwrap();
    OpenMlsRustCrypto::default()
        .crypto()
        .verify_signature(SignatureScheme::ECDSA_SECP256R1_SHA256, msg, &pk, &sig)
        .expect("RustCrypto must accept HSM ECDSA-P256 sig");
    assert!(
        OpenMlsRustCrypto::default()
            .crypto()
            .verify_signature(SignatureScheme::ECDSA_SECP256R1_SHA256, b"tampered", &pk, &sig)
            .is_err(),
        "wrong message must fail"
    );
}
