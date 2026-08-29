//! P2.5 — ML-KEM encapsulation/decapsulation through the KMIP **dispatcher
//! op surface**, plus AES-XTS functional status.
//!
//! ## PART A — ML-KEM through the dispatcher (not the engine bridge)
//!
//! The existing `native_bridge_e2e.rs::k9_register_ml_kem_768_encap_decap_roundtrip`
//! proves encap/decap by calling the `encrypt()` / `decrypt()` op functions
//! directly. This file proves the SAME round-trip the way a KMIP client
//! sees it: a `RequestMessage` carrying an `Encrypt` / `Decrypt` BatchItem
//! handed to `dispatcher::dispatch`, asserting the typed `ResponsePayload`.
//!
//! KMIP 3.0 has **no** dedicated `Encapsulate` op — this server models
//! ML-KEM encapsulation by overloading the `Encrypt` op when the target is
//! an ML-KEM public key (`C_EncapsulateKey` under the hood), and
//! decapsulation by overloading `Decrypt` against the ML-KEM private key
//! (`C_DecapsulateKey`). On the wire the shared secret rides the
//! `PQCToday-SharedSecret` vendor-extension tag `0x540001` (slice K10);
//! at the typed-payload layer it is `EncryptResponse.shared_secret`.
//!
//! Each round-trip asserts SUBSTANCE: the encap shared secret is recovered
//! byte-for-byte by decap. The negative case drives a short/tampered
//! ciphertext through `Decrypt` and asserts the spec-correct K1 CKR-mapping
//! result (`CKR_ARGUMENTS_BAD` → `InvalidField`), proving the server fails
//! honestly rather than returning a bogus secret.
//!
//! ## PART B — AES-XTS functional status (honest rejection)
//!
//! The engine (`softhsmrustv3`) defines **no** `CKM_AES_XTS` constant and
//! implements no XTS cipher (grep `CKM_AES_XTS` in `rust/src` — only a
//! comment noting two *other* constants once collided with the XTS
//! codepoint). KMIP `BlockCipherMode = XTS` (enum codepoint `0x0b`) is
//! therefore not in `aes_mechanism_for`'s map (CBC/ECB/CTR/GCM only), so a
//! KMIP `Encrypt` requesting XTS falls into the total-or-failing arm and is
//! rejected with `UnsupportedCryptographicParameters (0x3e)` — the K6
//! "fail, don't silently substitute GCM" behavior. The test below pins that
//! honest rejection through the dispatcher. AES-XTS is out of scope pending
//! engine support; if the engine grows `CKM_AES_XTS`, wire it into
//! `aes_mechanism_for` and flip this test to a round-trip.

use std::sync::Arc;

use ml_kem::{EncodedSizeUser, KemCore};
use time::OffsetDateTime;

use pqctoday_kmip::auditlog::{AuditSink, RingSink};
use pqctoday_kmip::dispatcher::dispatch;
use pqctoday_kmip::error::ResultReason;
use pqctoday_kmip::kmip30::{
    Attribute, CryptographicParameters, DecryptRequest, EncryptRequest, KeyBlock, KeyFormatType,
    KmipAlgorithm, ObjectType, Operation, RegisterRequest, RequestBatchItem, RequestHeader,
    RequestMessage, RequestPayload, ResponsePayload, ResultStatus, UsageMask,
};
use pqctoday_kmip::ops::{Deps, DepsConfig};
use pqctoday_kmip::policy::{load_from_str, Engine};
use pqctoday_kmip::store::MemoryStore;

// ── Harness (mirrors native_bridge_e2e.rs / op_coverage_e2e.rs) ──────────────

/// Serialise all engine-touching tests — the engine's `lazy_static!`
/// storage races during the bootstrap dance otherwise.
fn engine_test_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

const PERMISSIVE_POLICY: &str = r#"
schema_version: 1
metadata: { name: t, description: t, authority: t, effective: always }
rules: []
"#;

fn build_deps_with_real_engine() -> Deps {
    use softhsmrustv3::native::session;

    let _ = session::finalize();
    session::init().expect("engine init");
    let engine_session = session::bootstrap_default_token(0, "so-pin", "user-pin", "p2.5-e2e")
        .expect("bootstrap real engine session");

    let ring = Arc::new(RingSink::new(64));
    let sink: Arc<dyn AuditSink> = ring.clone();
    let policy_engine = Engine::with_global_sink(sink.clone());
    policy_engine
        .replace_all(load_from_str(PERMISSIVE_POLICY, std::path::Path::new("<p2.5>")).unwrap())
        .unwrap();

    Deps::new(policy_engine, Arc::new(MemoryStore::new()), sink, DepsConfig::default())
        .with_engine_session(engine_session)
}

/// Register a raw-format PQC key half through the **dispatcher** Register op
/// and return its server-assigned UID. Born Active (ActivationDate in the
/// past) so subsequent Encrypt/Decrypt aren't blocked by the lifecycle gate.
fn register_pqc_via_dispatcher(
    deps: &Deps,
    object_type: ObjectType,
    alg: KmipAlgorithm,
    key_bytes: Vec<u8>,
    usage: UsageMask,
) -> String {
    let len_bits = (key_bytes.len() * 8) as u32;
    let msg = RequestMessage {
        header: RequestHeader::v3(),
        batch_items: vec![RequestBatchItem {
            operation: Operation::Register,
            payload: RequestPayload::Register(RegisterRequest {
            secret_data_type: None,
                object_type,
                attributes: vec![
                    Attribute::CryptographicAlgorithm(alg),
                    Attribute::CryptographicLength(len_bits),
                    Attribute::CryptographicUsageMask(usage),
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
            }),
        }],
    };
    let resp = dispatch(deps, msg);
    assert_eq!(resp.batch_items.len(), 1);
    assert_eq!(
        resp.batch_items[0].result_status,
        ResultStatus::Success,
        "Register through dispatcher must succeed (reason={:?})",
        resp.batch_items[0].result_reason
    );
    match resp.batch_items[0].payload.as_ref().expect("Register payload") {
        ResponsePayload::Register(r) => r.uid.clone(),
        other => panic!("expected Register response, got {other:?}"),
    }
}

/// Drive an `Encrypt` BatchItem through the dispatcher and return the typed
/// `EncryptResponse`.
fn dispatch_encrypt(deps: &Deps, req: EncryptRequest) -> EncryptResult {
    let msg = RequestMessage {
        header: RequestHeader::v3(),
        batch_items: vec![RequestBatchItem {
            operation: Operation::Encrypt,
            payload: RequestPayload::Encrypt(req),
        }],
    };
    let resp = dispatch(deps, msg);
    assert_eq!(resp.batch_items.len(), 1);
    let item = &resp.batch_items[0];
    match item.result_status {
        ResultStatus::Success => match item.payload.as_ref().expect("Encrypt payload") {
            ResponsePayload::Encrypt(e) => EncryptResult::Ok(e.clone()),
            other => panic!("expected Encrypt response, got {other:?}"),
        },
        ResultStatus::OperationFailed => EncryptResult::Failed(item.result_reason),
        s => panic!("unexpected Encrypt status {s:?}"),
    }
}

/// Drive a `Decrypt` BatchItem through the dispatcher and return either the
/// typed `DecryptResponse` or the failure reason.
fn dispatch_decrypt(deps: &Deps, req: DecryptRequest) -> DecryptResult {
    let msg = RequestMessage {
        header: RequestHeader::v3(),
        batch_items: vec![RequestBatchItem {
            operation: Operation::Decrypt,
            payload: RequestPayload::Decrypt(req),
        }],
    };
    let resp = dispatch(deps, msg);
    assert_eq!(resp.batch_items.len(), 1);
    let item = &resp.batch_items[0];
    match item.result_status {
        ResultStatus::Success => match item.payload.as_ref().expect("Decrypt payload") {
            ResponsePayload::Decrypt(d) => DecryptResult::Ok(d.data.clone()),
            other => panic!("expected Decrypt response, got {other:?}"),
        },
        ResultStatus::OperationFailed => DecryptResult::Failed(item.result_reason),
        s => panic!("unexpected Decrypt status {s:?}"),
    }
}

enum EncryptResult {
    Ok(pqctoday_kmip::kmip30::EncryptResponse),
    Failed(Option<u32>),
}
enum DecryptResult {
    Ok(Vec<u8>),
    Failed(Option<u32>),
}

/// FIPS 203 §8 ML-KEM ciphertext sizes by parameter set.
fn ml_kem_ct_len(alg: KmipAlgorithm) -> usize {
    match alg {
        KmipAlgorithm::MlKem512 => 768,
        KmipAlgorithm::MlKem768 => 1088,
        KmipAlgorithm::MlKem1024 => 1568,
        other => panic!("not an ML-KEM param set: {other:?}"),
    }
}

// ── PART A — ML-KEM encap/decap THROUGH the dispatcher ───────────────────────

/// Round-trip helper shared by every parameter set. Registers a generated
/// keypair, then drives `Encrypt`(encapsulate) + `Decrypt`(decapsulate)
/// through `dispatcher::dispatch` and asserts the recovered shared secret
/// matches byte-for-byte. Also drives the negative tampered-ciphertext case.
fn ml_kem_dispatcher_roundtrip(alg: KmipAlgorithm, dk_bytes: Vec<u8>, ek_bytes: Vec<u8>) {
    let deps = build_deps_with_real_engine();

    let priv_uid = register_pqc_via_dispatcher(
        &deps,
        ObjectType::PrivateKey,
        alg,
        dk_bytes,
        UsageMask::DECRYPT,
    );
    let pub_uid = register_pqc_via_dispatcher(
        &deps,
        ObjectType::PublicKey,
        alg,
        ek_bytes,
        UsageMask::ENCRYPT,
    );

    // ── Encapsulate via the Encrypt op surface ──────────────────────────
    let enc = match dispatch_encrypt(
        &deps,
        EncryptRequest { uid: pub_uid, ..Default::default() },
    ) {
        EncryptResult::Ok(e) => e,
        EncryptResult::Failed(r) => panic!("encapsulate failed via dispatcher: reason={r:?}"),
    };
    let expected_ct = ml_kem_ct_len(alg);
    assert_eq!(
        enc.ciphertext.len(),
        expected_ct,
        "{alg:?} encapsulation ciphertext length (FIPS 203 §8)"
    );
    let shared_secret = enc
        .shared_secret
        .clone()
        .expect("encapsulate must return the derived shared secret on the vendor tag");
    assert_eq!(shared_secret.len(), 32, "ML-KEM shared secret is 32 bytes");

    // ── Decapsulate via the Decrypt op surface — recover the SAME secret ─
    let recovered = match dispatch_decrypt(
        &deps,
        DecryptRequest {
            uid: priv_uid.clone(),
            data: enc.ciphertext.clone(),
            iv: None,
            cryptographic_parameters: None,
            aad: None,
        },
    ) {
        DecryptResult::Ok(d) => d,
        DecryptResult::Failed(r) => panic!("decapsulate failed via dispatcher: reason={r:?}"),
    };
    assert_eq!(
        recovered, shared_secret,
        "{alg:?} decapsulation must recover the encapsulation shared secret byte-for-byte"
    );

    // ── NEGATIVE: short/tampered ciphertext → honest CKR-mapped failure ──
    // A wrong-length ciphertext is caught by the engine's length check
    // (`CKR_ARGUMENTS_BAD`), which the K1 CKR→KMIP map surfaces as
    // `InvalidField` — NOT a bogus shared secret.
    let mut short = enc.ciphertext.clone();
    short.truncate(short.len() - 1);
    match dispatch_decrypt(
        &deps,
        DecryptRequest {
            uid: priv_uid,
            data: short,
            iv: None,
            cryptographic_parameters: None,
            aad: None,
        },
    ) {
        DecryptResult::Failed(reason) => assert_eq!(
            reason,
            Some(ResultReason::InvalidField.to_wire_value()),
            "{alg:?} decap of a short ciphertext must fail with the K1 CKR-mapping \
             result (CKR_ARGUMENTS_BAD → InvalidField), not return a secret"
        ),
        DecryptResult::Ok(_) => {
            panic!("{alg:?} decap of a truncated ciphertext must NOT succeed")
        }
    }

    let _ = softhsmrustv3::native::session::finalize();
}

#[test]
fn ml_kem_768_encap_decap_through_dispatcher() {
    let _guard = engine_test_lock();
    let (dk, ek) = ml_kem::MlKem768::generate(&mut rand::rngs::OsRng);
    ml_kem_dispatcher_roundtrip(
        KmipAlgorithm::MlKem768,
        dk.as_bytes().as_slice().to_vec(),
        ek.as_bytes().as_slice().to_vec(),
    );
}

#[test]
fn ml_kem_512_encap_decap_through_dispatcher() {
    let _guard = engine_test_lock();
    let (dk, ek) = ml_kem::MlKem512::generate(&mut rand::rngs::OsRng);
    ml_kem_dispatcher_roundtrip(
        KmipAlgorithm::MlKem512,
        dk.as_bytes().as_slice().to_vec(),
        ek.as_bytes().as_slice().to_vec(),
    );
}

#[test]
fn ml_kem_1024_encap_decap_through_dispatcher() {
    let _guard = engine_test_lock();
    let (dk, ek) = ml_kem::MlKem1024::generate(&mut rand::rngs::OsRng);
    ml_kem_dispatcher_roundtrip(
        KmipAlgorithm::MlKem1024,
        dk.as_bytes().as_slice().to_vec(),
        ek.as_bytes().as_slice().to_vec(),
    );
}

/// FIPS 203 implicit-rejection property surfaced through the dispatcher:
/// a *correct-length* but corrupted ciphertext does NOT error (ML-KEM has
/// no explicit ciphertext rejection — §6.3 derives an implicit secret), so
/// decap succeeds with a DIFFERENT 32-byte secret. This pins that the
/// server forwards the engine's decap output faithfully rather than
/// asserting equality where the spec mandates divergence.
#[test]
fn ml_kem_768_corrupt_ciphertext_yields_different_secret_via_dispatcher() {
    let _guard = engine_test_lock();
    let deps = build_deps_with_real_engine();

    let (dk, ek) = ml_kem::MlKem768::generate(&mut rand::rngs::OsRng);
    let priv_uid = register_pqc_via_dispatcher(
        &deps,
        ObjectType::PrivateKey,
        KmipAlgorithm::MlKem768,
        dk.as_bytes().as_slice().to_vec(),
        UsageMask::DECRYPT,
    );
    let pub_uid = register_pqc_via_dispatcher(
        &deps,
        ObjectType::PublicKey,
        KmipAlgorithm::MlKem768,
        ek.as_bytes().as_slice().to_vec(),
        UsageMask::ENCRYPT,
    );

    let enc = match dispatch_encrypt(&deps, EncryptRequest { uid: pub_uid, ..Default::default() }) {
        EncryptResult::Ok(e) => e,
        EncryptResult::Failed(r) => panic!("encapsulate failed: {r:?}"),
    };
    let good_secret = enc.shared_secret.clone().expect("shared secret");

    // Flip one bit but keep the FIPS 203 §8 length intact.
    let mut corrupt = enc.ciphertext.clone();
    corrupt[0] ^= 0x01;
    assert_eq!(corrupt.len(), enc.ciphertext.len());

    let recovered = match dispatch_decrypt(
        &deps,
        DecryptRequest {
            uid: priv_uid,
            data: corrupt,
            iv: None,
            cryptographic_parameters: None,
            aad: None,
        },
    ) {
        DecryptResult::Ok(d) => d,
        DecryptResult::Failed(r) => {
            panic!("ML-KEM implicit rejection must not error on a correct-length ct: {r:?}")
        }
    };
    assert_eq!(recovered.len(), 32);
    assert_ne!(
        recovered, good_secret,
        "FIPS 203 implicit rejection: a corrupted ciphertext yields a different secret"
    );

    let _ = softhsmrustv3::native::session::finalize();
}

// ── PART B — AES-XTS functional status (honest rejection, no substitution) ───

/// The engine implements no AES-XTS. A KMIP `Encrypt` requesting
/// `BlockCipherMode = XTS` (enum codepoint `0x0b`, verified against
/// `spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json`) must therefore be
/// rejected with `UnsupportedCryptographicParameters (0x3e)` — the K6
/// "fail, don't silently substitute GCM" contract — NOT silently run under
/// some other mode. This drives it through the dispatcher and asserts the
/// honest rejection.
#[test]
fn aes_xts_encrypt_is_honestly_rejected_not_substituted() {
    let _guard = engine_test_lock();
    let deps = build_deps_with_real_engine();

    // Register an AES-256 key (born Active) with real key material so the
    // op reaches mechanism selection rather than a missing-material path.
    let key = vec![0x11u8; 32];
    let uid = register_aes_via_dispatcher(&deps, key);

    // KMIP BlockCipherMode enum: XTS = 0x0b.
    const XTS_BLOCK_CIPHER_MODE: u32 = 0x0b;
    let xts_cp = CryptographicParameters {
        block_cipher_mode: Some(XTS_BLOCK_CIPHER_MODE),
        ..Default::default()
    };

    match dispatch_encrypt(
        &deps,
        EncryptRequest {
            uid,
            data: b"sixteen byte blk".to_vec(),
            cryptographic_parameters: Some(xts_cp),
            ..Default::default()
        },
    ) {
        EncryptResult::Failed(reason) => assert_eq!(
            reason,
            Some(ResultReason::UnsupportedCryptographicParameters.to_wire_value()),
            "AES-XTS must be rejected 0x3e (engine has no CKM_AES_XTS), not substituted"
        ),
        EncryptResult::Ok(_) => panic!(
            "AES-XTS Encrypt must NOT silently succeed under a substituted mode \
             (K6 fail-don't-substitute)"
        ),
    }

    let _ = softhsmrustv3::native::session::finalize();
}

/// Register an AES symmetric key with raw material through the dispatcher.
fn register_aes_via_dispatcher(deps: &Deps, key: Vec<u8>) -> String {
    let len_bits = (key.len() * 8) as u32;
    let msg = RequestMessage {
        header: RequestHeader::v3(),
        batch_items: vec![RequestBatchItem {
            operation: Operation::Register,
            payload: RequestPayload::Register(RegisterRequest {
            secret_data_type: None,
                object_type: ObjectType::SymmetricKey,
                attributes: vec![
                    Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes),
                    Attribute::CryptographicLength(len_bits),
                    Attribute::CryptographicUsageMask(UsageMask::ENCRYPT | UsageMask::DECRYPT),
                    Attribute::ActivationDate(OffsetDateTime::now_utc().unix_timestamp() - 3600),
                ],
                managed_object: Some(KeyBlock {
                    key_format_type: KeyFormatType::Raw,
                    cryptographic_algorithm: KmipAlgorithm::Aes,
                    cryptographic_length: len_bits,
                    key_value: key,
                    key_wrapping_data: None,
                }),
                protection_storage_masks: None,
                certificate_payload: None,
            }),
        }],
    };
    let resp = dispatch(deps, msg);
    assert_eq!(resp.batch_items[0].result_status, ResultStatus::Success);
    match resp.batch_items[0].payload.as_ref().unwrap() {
        ResponsePayload::Register(r) => r.uid.clone(),
        other => panic!("expected Register response, got {other:?}"),
    }
}
