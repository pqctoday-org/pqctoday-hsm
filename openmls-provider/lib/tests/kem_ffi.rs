//! Integration tests for the raw PKCS#11 v3.2 KEM path (`kem_ffi`).
//!
//! These drive a REAL PKCS#11 module — there is no mock. The whole point of the
//! module is that `cryptoki` cannot express these calls, so a test that stubbed
//! the FFI would be testing the stub.
//!
//! Skipped unless `PKCS11_MODULE` is set, so `cargo test` stays green on a
//! machine with no HSM built. To run:
//!
//! ```sh
//! export SOFTHSM2_CONF=/path/to/softhsm.conf
//! export PKCS11_MODULE=/path/to/libsofthsmv3.dylib
//! export PKCS11_SLOT=<slot id>          # from `softhsm2-util --show-slots`
//! export PKCS11_PIN=1234
//! cargo test -p openmls_pqctoday_crypto --test kem_ffi -- --nocapture
//! ```

#![cfg(not(target_arch = "wasm32"))]

use openmls_pqctoday_crypto::kem_ffi::KemFfi;

/// ML-KEM-768 ciphertext length, FIPS 203 Table 3.
const MLKEM768_CT_LEN: usize = 1088;
/// ML-KEM shared-secret length, FIPS 203 §7.2.
const MLKEM_SS_LEN: usize = 32;

fn ffi() -> Option<KemFfi> {
    let module = std::env::var("PKCS11_MODULE").ok()?;
    let slot: u64 = std::env::var("PKCS11_SLOT")
        .ok()?
        .parse()
        .expect("PKCS11_SLOT must be a number");
    let pin = std::env::var("PKCS11_PIN").ok();
    Some(
        KemFfi::open(std::path::Path::new(&module), slot, pin.as_deref())
            .expect("failed to open the KEM FFI session"),
    )
}

macro_rules! hsm {
    () => {
        match ffi() {
            Some(f) => f,
            None => {
                eprintln!("SKIP: PKCS11_MODULE not set");
                return;
            }
        }
    };
}

/// SHA3-256 against known answers.
///
/// This is a KAT, not a round-trip: a stub returning a constant would pass a
/// round-trip test, and SHA3-256 is the one primitive X-Wing's combiner cannot
/// be wrong about. Values generated with `openssl dgst -sha3-256`, not recalled.
#[test]
fn sha3_256_matches_known_answers() {
    let f = hsm!();

    let empty = f.sha3_256(b"").expect("sha3-256 of empty input");
    assert_eq!(
        hex::encode(&empty),
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        "SHA3-256(\"\") mismatch"
    );

    let abc = f.sha3_256(b"abc").expect("sha3-256 of abc");
    assert_eq!(
        hex::encode(&abc),
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
        "SHA3-256(\"abc\") mismatch"
    );
}

/// SHAKE-256 as an XOF, against known answers.
///
/// This mechanism was added to the engine specifically so X-Wing's seed
/// expansion happens inside the HSM rather than in software. The 96-byte case
/// is the exact call X-Wing makes.
///
/// The second vector expands the X-Wing draft's own test seed, so a mismatch
/// here localises the fault to the XOF before any KEM work is involved.
/// Values generated with `openssl dgst -shake256 -xoflen`, not recalled.
#[test]
fn shake256_matches_known_answers() {
    let f = hsm!();

    let empty96 = f.shake256(b"", 96).expect("shake256 of empty input");
    assert_eq!(
        hex::encode(&empty96),
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f\
         d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be\
         141e96616fb13957692cc7edd0b45ae3dc07223c8e92937bef84bc0eab862853",
        "SHAKE256(\"\", 96) mismatch"
    );

    // The X-Wing draft's test-vector seed, expanded exactly as GenerateKeyPair
    // does: 32 bytes in, 96 out.
    let seed = hex::decode("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
        .expect("seed hex");
    let expanded = f.shake256(&seed, 96).expect("shake256 of the X-Wing seed");
    assert_eq!(
        hex::encode(&expanded),
        "c44829d2b269887f6150dfaee5a25a704cbc607e57d18a2ffc8734633333cff0\
         f0fc6fa4e4827531168087ef223e9b070c5a78a789fd46d4c604d69b1139d4da\
         cd3f2cce66ed130e5e73a0ebd454e15488885a2a1544252a20e0f58b6e8fc27b",
        "SHAKE256(X-Wing test seed, 96) mismatch"
    );
}

/// An XOF must actually extend — not emit its nominal 32-byte digest padded or
/// truncated. Guards the specific mistake of calling `EVP_DigestFinal_ex`
/// instead of `EVP_DigestFinalXOF`, which returns 32 bytes and silently ignores
/// the requested length.
#[test]
fn shake256_output_length_is_honoured() {
    let f = hsm!();
    for len in [16usize, 32, 64, 96, 200] {
        let out = f.shake256(b"length check", len).expect("shake256");
        assert_eq!(out.len(), len, "SHAKE256 returned the wrong length for {len}");
    }

    // A longer output must be a strict extension of a shorter one — that is the
    // defining property of an XOF, and it fails if the length is being folded
    // into the state rather than just squeezed.
    let short = f.shake256(b"prefix property", 32).unwrap();
    let long = f.shake256(b"prefix property", 96).unwrap();
    assert_eq!(&long[..32], &short[..], "SHAKE256 output is not a prefix-extension");
}

/// The core claim: ML-KEM encapsulation and decapsulation, through the HSM,
/// agree on a shared secret.
#[test]
fn ml_kem_768_encapsulate_decapsulate_agree() {
    let f = hsm!();

    let (h_pub, h_priv) = f.ml_kem_768_keygen().expect("ML-KEM-768 keygen");
    assert_ne!(h_pub, 0, "public key handle should not be null");
    assert_ne!(h_priv, 0, "private key handle should not be null");

    let (ct, ss_enc) = f.ml_kem_encapsulate(h_pub).expect("encapsulate");
    assert_eq!(
        ct.len(),
        MLKEM768_CT_LEN,
        "ML-KEM-768 ciphertext should be {MLKEM768_CT_LEN} bytes (FIPS 203 Table 3)"
    );
    assert_eq!(ss_enc.len(), MLKEM_SS_LEN, "shared secret should be 32 bytes");

    let ss_dec = f.ml_kem_decapsulate(h_priv, &ct).expect("decapsulate");
    assert_eq!(
        ss_enc, ss_dec,
        "encapsulated and decapsulated secrets must match"
    );

    // A secret of all zeroes would satisfy the equality above while meaning the
    // extraction silently returned an empty buffer. Check it is real.
    assert!(
        ss_enc.iter().any(|&b| b != 0),
        "shared secret is all zeroes — the value was probably not extracted"
    );
}

/// Two encapsulations against the same public key must differ.
///
/// Guards the failure mode where encapsulation ignores its randomness — which
/// would still round-trip perfectly and is exactly the kind of break that a
/// happy-path test cannot see.
#[test]
fn encapsulation_is_randomised() {
    let f = hsm!();
    let (h_pub, h_priv) = f.ml_kem_768_keygen().expect("keygen");

    let (ct1, ss1) = f.ml_kem_encapsulate(h_pub).expect("encapsulate 1");
    let (ct2, ss2) = f.ml_kem_encapsulate(h_pub).expect("encapsulate 2");

    assert_ne!(ct1, ct2, "two encapsulations produced identical ciphertexts");
    assert_ne!(ss1, ss2, "two encapsulations produced identical secrets");

    // Both must still decapsulate correctly to their own secret.
    assert_eq!(f.ml_kem_decapsulate(h_priv, &ct1).unwrap(), ss1);
    assert_eq!(f.ml_kem_decapsulate(h_priv, &ct2).unwrap(), ss2);
}

/// FIPS 203 §7.3: ML-KEM decapsulation never fails. A corrupted ciphertext
/// yields a different secret ("implicit rejection"), it does not error.
///
/// Asserting the *shape* of failure matters: code that returned an error here
/// would leak whether a ciphertext was valid.
#[test]
fn corrupted_ciphertext_implicitly_rejects() {
    let f = hsm!();
    let (h_pub, h_priv) = f.ml_kem_768_keygen().expect("keygen");
    let (mut ct, ss) = f.ml_kem_encapsulate(h_pub).expect("encapsulate");

    ct[0] ^= 0x01;
    let ss_bad = f
        .ml_kem_decapsulate(h_priv, &ct)
        .expect("decapsulation of a corrupted ciphertext must not error (FIPS 203 §7.3)");

    assert_eq!(ss_bad.len(), MLKEM_SS_LEN);
    assert_ne!(
        ss, ss_bad,
        "a corrupted ciphertext produced the original secret"
    );
}
