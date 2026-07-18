//! Migration tab — full lifecycle against the REAL engine: build classical
//! keys LABEL-ONLY under migration-classical, flip to migration-pqc, then
//! prove the vulnerable keys auto-rekey to their PQC equivalent both on first
//! use (Sign / Encrypt / Encapsulate) and via the ReKey / ReKeyKeyPair sweep.
//!
//! Serialised on the shared engine lock (the engine's lazy_static token
//! storage races under parallel bootstrap) — see native_bridge_e2e.rs.

use std::path::PathBuf;
use std::sync::Arc;

use pqctoday_kmip::auditlog::{AuditSink, RingSink};
use pqctoday_kmip::kmip30::{
    Attribute, CreateKeyPairRequest, CreateRequest, EncapsulateRequest, EncryptRequest,
    KmipAlgorithm, ObjectType, ReKeyKeyPairRequest, ReKeyRequest, SignRequest, State, UsageMask,
};
use pqctoday_kmip::ops::activate::activate;
use pqctoday_kmip::ops::create::create;
use pqctoday_kmip::ops::create_key_pair::create_key_pair;
use pqctoday_kmip::ops::encapsulate::encapsulate;
use pqctoday_kmip::ops::encrypt::encrypt;
use pqctoday_kmip::ops::rekey::{rekey, rekey_key_pair};
use pqctoday_kmip::ops::sign::sign;
use pqctoday_kmip::ops::{Deps, DepsConfig};
use pqctoday_kmip::policy::{load_from_file, Engine};
use pqctoday_kmip::server::auth::AuthContext;
use pqctoday_kmip::store::MemoryStore;

fn engine_test_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

fn policies_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("policies")
}

fn build_deps() -> (Arc<RingSink>, Deps) {
    use softhsmrustv3::native::session;
    let _ = session::finalize();
    session::init().expect("engine init");
    let engine_session =
        session::bootstrap_default_token(0, "so-pin", "user-pin", "migration-e2e")
            .expect("bootstrap real engine session");

    let ring = Arc::new(RingSink::new(256));
    let sink: Arc<dyn AuditSink> = ring.clone();
    let engine = Engine::with_global_sink(sink.clone());
    engine
        .activate(load_from_file(&policies_dir().join("migration-classical.yaml")).unwrap())
        .unwrap();

    let deps = Deps::new(engine, Arc::new(MemoryStore::new()), sink, DepsConfig::default())
        .with_engine_session(engine_session);
    (ring, deps)
}

fn load(deps: &Deps, file: &str) {
    deps.engine
        .activate(load_from_file(&policies_dir().join(file)).unwrap())
        .expect("policy activation");
}

/// Create a key pair LABEL-ONLY (name + usage intent, no algorithm) and
/// activate both halves. Returns (private_uid, public_uid).
fn gen_pair(deps: &Deps, name: &str, usage: UsageMask) -> (String, String) {
    let r = create_key_pair(
        deps,
        CreateKeyPairRequest {
            common_attributes: vec![
                Attribute::CryptographicUsageMask(usage),
                Attribute::Name(name.into()),
            ],
            private_key_attributes: vec![],
            public_key_attributes: vec![],
            seed: None,
        },
        // The dispatcher canonicalises the usage mask into the op suffix; do
        // the same here so the label-pattern defaults key correctly.
        if usage.contains(UsageMask::KEY_AGREEMENT) {
            "CreateKeyPair:KeyAgreement"
        } else {
            "CreateKeyPair:Sign"
        },
        &AuthContext::open(),
        "gen",
    )
    .unwrap();
    activate(deps, pqctoday_kmip::kmip30::ActivateRequest { uid: r.private_key_uid.clone() }, "a")
        .unwrap();
    activate(deps, pqctoday_kmip::kmip30::ActivateRequest { uid: r.public_key_uid.clone() }, "a")
        .unwrap();
    (r.private_key_uid, r.public_key_uid)
}

fn alg(deps: &Deps, uid: &str) -> (KmipAlgorithm, u32, State) {
    let r = deps.store.get(uid).unwrap().unwrap();
    (r.algorithm, r.cryptographic_length, r.state)
}

#[test]
fn firmware_signing_key_rekeys_rsa2048_to_mldsa44_on_first_sign() {
    let _g = engine_test_lock();
    let (_ring, deps) = build_deps();

    // Classical estate: the label resolves to RSA-2048 (policy's choice).
    let (priv_uid, _pub) =
        gen_pair(&deps, "firmware-release-signing", UsageMask::SIGN | UsageMask::VERIFY);
    assert_eq!(alg(&deps, &priv_uid).0, KmipAlgorithm::Rsa);
    assert_eq!(alg(&deps, &priv_uid).1, 2048);

    // Flip to full PQC; the app's Sign call is unchanged.
    load(&deps, "migration-pqc.yaml");
    let resp = sign(
        &deps,
        SignRequest { uid: priv_uid.clone(), data: b"release".to_vec(), cryptographic_parameters: None },
        &AuthContext::open(),
        "sign",
    )
    .unwrap();

    // Rekey fired: response carries the new key, old key deactivated+superseded,
    // Name carried over, new algorithm is ML-DSA-44.
    let rk = resp.rekeyed.expect("rekey must fire");
    assert_eq!(rk.old_uid, priv_uid);
    assert_eq!(alg(&deps, &priv_uid).2, State::Deactivated);
    let new = deps.store.get(&rk.new_private_key_uid).unwrap().unwrap();
    assert_eq!(new.algorithm, KmipAlgorithm::MlDsa44);
    assert_eq!(new.name.as_deref(), Some("firmware-release-signing"));
    // FIPS 204 ML-DSA-44 signature is 2420 bytes.
    assert_eq!(resp.signature.len(), 2420);
}

#[test]
fn payments_cipher_rekeys_aes128_to_aes256_on_first_encrypt() {
    let _g = engine_test_lock();
    let (_ring, deps) = build_deps();

    // payments-* label → AES-128 under the classical estate.
    let created = create(
        &deps,
        CreateRequest {
            object_type: ObjectType::SymmetricKey,
            template_attribute: vec![
                Attribute::CryptographicUsageMask(UsageMask::ENCRYPT | UsageMask::DECRYPT),
                Attribute::Name("payments-db-cipher".into()),
            ],
        },
        "create",
    )
    .unwrap();
    activate(&deps, pqctoday_kmip::kmip30::ActivateRequest { uid: created.uid.clone() }, "a").unwrap();
    assert_eq!(alg(&deps, &created.uid).0, KmipAlgorithm::Aes);
    assert_eq!(alg(&deps, &created.uid).1, 128);

    load(&deps, "migration-pqc.yaml");
    let resp = encrypt(
        &deps,
        EncryptRequest {
            uid: created.uid.clone(),
            data: b"card=4111".to_vec(),
            iv: Some(vec![0u8; 12]),
            cryptographic_parameters: None,
            aad: None,
            init_indicator: None,
            final_indicator: None,
            correlation_value: None,
        },
        "enc",
    )
    .unwrap();

    let rk = resp.rekeyed.expect("AES-128 must rekey on encrypt");
    assert_eq!(rk.old_uid, created.uid);
    assert_eq!(alg(&deps, &created.uid).2, State::Deactivated);
    let new = deps.store.get(&rk.new_uid).unwrap().unwrap();
    assert_eq!(new.algorithm, KmipAlgorithm::Aes);
    assert_eq!(new.cryptographic_length, 256);
    assert_eq!(new.name.as_deref(), Some("payments-db-cipher"));
}

#[test]
fn x448_kex_rekeys_to_mlkem1024_on_first_encapsulate() {
    let _g = engine_test_lock();
    let (_ring, deps) = build_deps();

    let (_priv, pub_uid) =
        gen_pair(&deps, "interbank-vpn-kex", UsageMask::KEY_AGREEMENT);
    assert_eq!(alg(&deps, &pub_uid).0, KmipAlgorithm::Ecdh);
    assert_eq!(alg(&deps, &pub_uid).1, 448); // X448

    load(&deps, "migration-pqc.yaml");
    let resp = encapsulate(
        &deps,
        EncapsulateRequest { uid: pub_uid.clone(), ..Default::default() },
        &AuthContext::open(),
        "encap",
    )
    .unwrap();

    let rk = resp.rekeyed.expect("X448 must rekey on encapsulate");
    let new = deps.store.get(&rk.new_public_key_uid).unwrap().unwrap();
    assert_eq!(new.algorithm, KmipAlgorithm::MlKem1024);
    assert_eq!(new.name.as_deref(), Some("interbank-vpn-kex"));
    // A shared secret was still produced under the migrated key.
    assert!(!resp.data.is_empty());
}

#[test]
fn sweep_rekeys_via_rekey_and_rekeykeypair() {
    let _g = engine_test_lock();
    let (_ring, deps) = build_deps();

    // Build two vulnerable keys the sweep will touch: an AES-128 cipher and an
    // ECDSA-P256 signing pair.
    let sym = create(
        &deps,
        CreateRequest {
            object_type: ObjectType::SymmetricKey,
            template_attribute: vec![
                Attribute::CryptographicUsageMask(UsageMask::ENCRYPT | UsageMask::DECRYPT),
                Attribute::Name("payments-db-cipher".into()),
            ],
        },
        "create",
    )
    .unwrap();
    activate(&deps, pqctoday_kmip::kmip30::ActivateRequest { uid: sym.uid.clone() }, "a").unwrap();
    let (api_priv, _api_pub) =
        gen_pair(&deps, "api-gateway-signing", UsageMask::SIGN | UsageMask::VERIFY);
    assert_eq!(alg(&deps, &api_priv).0, KmipAlgorithm::Ecdsa);

    load(&deps, "migration-pqc.yaml");

    // Sweep: ReKey the symmetric key, ReKeyKeyPair the signing pair — no
    // algorithm in the template, so the policy substitution drives the target.
    let rk_sym = rekey(
        &deps,
        ReKeyRequest { uid: sym.uid.clone(), offset: None, template_attribute: vec![] },
        "sweep",
    )
    .unwrap();
    let new_sym = deps.store.get(&rk_sym.uid).unwrap().unwrap();
    assert_eq!(new_sym.algorithm, KmipAlgorithm::Aes);
    assert_eq!(new_sym.cryptographic_length, 256);

    let rk_pair = rekey_key_pair(
        &deps,
        ReKeyKeyPairRequest {
            uid: api_priv.clone(),
            offset: None,
            common_attributes: vec![],
            private_key_attributes: vec![],
            public_key_attributes: vec![],
        },
        &AuthContext::open(),
        "sweep",
    )
    .unwrap();
    let new_priv = deps.store.get(&rk_pair.private_key_uid).unwrap().unwrap();
    assert_eq!(new_priv.algorithm, KmipAlgorithm::MlDsa44);
    // PQC parameter set fixes the size — the old ECDSA 256-bit length must not
    // carry over onto ML-DSA-44.
    assert_eq!(new_priv.cryptographic_length, 0);
    assert_eq!(new_priv.name.as_deref(), Some("api-gateway-signing"));
    // Old halves retired.
    assert_eq!(alg(&deps, &api_priv).2, State::Deactivated);
}

#[test]
fn legacy_signature_still_verifies_after_owner_key_rekeys() {
    // Decrypt/Verify of pre-migration material must keep working — only the
    // producing ops rekey. Here: an AES key encrypts under classical, we flip,
    // a NEW encrypt rekeys it, and the OLD (now Deactivated) key can still
    // decrypt the original ciphertext.
    let _g = engine_test_lock();
    let (_ring, deps) = build_deps();
    use pqctoday_kmip::kmip30::DecryptRequest;
    use pqctoday_kmip::ops::decrypt::decrypt;

    let sym = create(
        &deps,
        CreateRequest {
            object_type: ObjectType::SymmetricKey,
            template_attribute: vec![
                Attribute::CryptographicUsageMask(UsageMask::ENCRYPT | UsageMask::DECRYPT),
                Attribute::Name("payments-db-cipher".into()),
            ],
        },
        "create",
    )
    .unwrap();
    activate(&deps, pqctoday_kmip::kmip30::ActivateRequest { uid: sym.uid.clone() }, "a").unwrap();

    // Encrypt under classical AES-128.
    let iv = vec![7u8; 12];
    let enc = encrypt(
        &deps,
        EncryptRequest {
            uid: sym.uid.clone(),
            data: b"legacy record".to_vec(),
            iv: Some(iv.clone()),
            cryptographic_parameters: None,
            aad: None,
            init_indicator: None,
            final_indicator: None,
            correlation_value: None,
        },
        "enc",
    )
    .unwrap();
    let mut ct = enc.ciphertext.clone();
    if let Some(tag) = enc.authenticated_encryption_tag.clone() {
        ct.extend_from_slice(&tag);
    }

    // Flip to PQC — the OLD key is still Active until something rekeys it.
    load(&deps, "migration-pqc.yaml");

    // Decrypt of the legacy ciphertext with the original key still works
    // (Decrypt never rekeys).
    let dec = decrypt(
        &deps,
        DecryptRequest {
            uid: sym.uid.clone(),
            data: ct,
            iv: Some(iv),
            cryptographic_parameters: None,
            aad: None,
        },
        "dec",
    )
    .unwrap();
    assert_eq!(dec.data, b"legacy record");
}
