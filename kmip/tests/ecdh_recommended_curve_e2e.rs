//! X25519 / X448 through the standard KMIP `ECDH` + `Recommended Curve` path.
//!
//! KMIP 3.0 §4.16 models X25519/X448 key agreement as
//! `CryptographicAlgorithm = ECDH` with the curve carried in the
//! `Cryptographic Domain Parameters` structure attribute (NOT a standalone
//! algorithm). This exercises CreateKeyPair end-to-end against a REAL engine
//! session and confirms the engine actually produced a Montgomery (X25519/X448)
//! key, that the curve is reported back via GetAttributes, and that Get on the
//! private key is refused (non-extractable).

use std::sync::Arc;

use pqctoday_kmip::auditlog::{AuditSink, RingSink};
use pqctoday_kmip::kmip30::{
    ActivateRequest, Attribute, CreateKeyPairRequest, DeriveKeyRequest, DerivationMethod,
    DerivationParameters, GetAttributesRequest, GetRequest, KmipAlgorithm, ObjectType, UsageMask,
};
use pqctoday_kmip::ops::activate::activate;
use pqctoday_kmip::ops::create_key_pair::create_key_pair;
use pqctoday_kmip::ops::derive_key::derive_key;
use pqctoday_kmip::ops::get::get;
use pqctoday_kmip::ops::get_attributes::get_attributes;
use pqctoday_kmip::ops::{Deps, DepsConfig};
use pqctoday_kmip::policy::Engine;
use pqctoday_kmip::store::MemoryStore;

// KMIP Recommended Curve enum values (spec §4.16).
const CURVE25519: u32 = 0x45;
const CURVE448: u32 = 0x46;
const P_256: u32 = 0x07;

// The softhsmrustv3 engine is global (lazy_static Mutex state); serialize these
// tests so one test's finalize/init can't race another's session.
fn engine_lock() -> std::sync::MutexGuard<'static, ()> {
    static L: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    L.get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

fn deps() -> Deps {
    use softhsmrustv3::native::session;
    let _ = session::finalize();
    session::init().expect("engine init");
    let s = session::bootstrap_default_token(0, "so-pin", "user-pin", "ecdh-rc-e2e")
        .expect("bootstrap engine session");
    let ring = Arc::new(RingSink::new(64));
    let sink: Arc<dyn AuditSink> = ring;
    Deps::new(Engine::permissive(), Arc::new(MemoryStore::new()), sink, DepsConfig::default())
        .with_engine_session(s)
}

/// Resolve the engine PRIVATE-key handle for a KMIP object and return its
/// PKCS#11 CKA_KEY_TYPE — proves which curve family the engine really made.
fn engine_private_key_type(d: &Deps, cka_id: &[u8]) -> u32 {
    use softhsmrustv3::constants::{CKA_CLASS, CKA_KEY_TYPE, CKO_PRIVATE_KEY};
    let session = d.engine_session.unwrap();
    let handles = softhsmrustv3::native::find_all_by_cka_id(session, cka_id).expect("find handles");
    for h in handles {
        if softhsmrustv3::native::get_attribute_u32(session, h, CKA_CLASS) == Some(CKO_PRIVATE_KEY) {
            return softhsmrustv3::native::get_attribute_u32(session, h, CKA_KEY_TYPE).expect("key type");
        }
    }
    panic!("no private-key handle for cka_id");
}

fn create_ecdh(d: &Deps, curve: u32) -> String {
    let kp = create_key_pair(
        d,
        CreateKeyPairRequest {
            common_attributes: vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::Ecdh),
                Attribute::CryptographicUsageMask(UsageMask::KEY_AGREEMENT),
                Attribute::CryptographicDomainParameters {
                    qlength: None,
                    recommended_curve: Some(curve),
                },
            ],
            private_key_attributes: vec![],
            public_key_attributes: vec![],
            seed: None,
        },
        "CreateKeyPair:KeyAgreement",
        &pqctoday_kmip::server::auth::AuthContext::open(),
        "ckp",
    )
    .expect("ecdh keygen");
    kp.private_key_uid
}

/// Full CreateKeyPair returning (private_uid, public_uid).
fn create_ecdh_pair(d: &Deps, curve: u32) -> (String, String) {
    let kp = create_key_pair(
        d,
        CreateKeyPairRequest {
            common_attributes: vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::Ecdh),
                // DeriveKey (agreement) requires the DERIVE_KEY usage bit.
                Attribute::CryptographicUsageMask(UsageMask::KEY_AGREEMENT | UsageMask::DERIVE_KEY),
                Attribute::CryptographicDomainParameters {
                    qlength: None,
                    recommended_curve: Some(curve),
                },
            ],
            private_key_attributes: vec![],
            public_key_attributes: vec![],
            seed: None,
        },
        "CreateKeyPair:KeyAgreement",
        &pqctoday_kmip::server::auth::AuthContext::open(),
        "ckp",
    )
    .expect("ecdh keygen");
    (kp.private_key_uid, kp.public_key_uid)
}

/// Read the raw public point of an EC key from the engine (X25519 = 32-byte
/// CKA_VALUE) — the peer share a client would send as Derivation Data.
fn engine_public_value(d: &Deps, cka_id: &[u8]) -> Vec<u8> {
    use softhsmrustv3::constants::{CKA_CLASS, CKA_VALUE, CKO_PUBLIC_KEY};
    let session = d.engine_session.unwrap();
    let handles = softhsmrustv3::native::find_all_by_cka_id(session, cka_id).expect("find handles");
    for h in handles {
        if softhsmrustv3::native::get_attribute_u32(session, h, CKA_CLASS) == Some(CKO_PUBLIC_KEY) {
            return softhsmrustv3::native::get_attribute(session, h, CKA_VALUE).expect("public value");
        }
    }
    panic!("no public-key handle");
}

/// DeriveKey(AsymmetricKey): agree `priv_uid` against `peer_public`, returning
/// the derived SecretData's shared-secret bytes.
fn derive_agree(d: &Deps, priv_uid: &str, peer_public: &[u8]) -> Vec<u8> {
    let resp = derive_key(
        d,
        DeriveKeyRequest {
            object_type: ObjectType::SecretData,
            uids: vec![priv_uid.to_string()],
            derivation_method: DerivationMethod::AsymmetricKey,
            derivation_parameters: DerivationParameters {
                derivation_data: Some(peer_public.to_vec()),
                ..Default::default()
            },
            template_attribute: vec![Attribute::CryptographicLength(256)], // 32 bytes
        },
        "derive",
    )
    .expect("derive_key ecdh agreement");
    d.store.get(&resp.uid).unwrap().unwrap().key_material.expect("derived SS material")
}

#[test]
fn ecdh_curve25519_makes_x25519_and_reports_domain_params() {
    let _g = engine_lock();
    use softhsmrustv3::constants::CKK_EC_MONTGOMERY;
    let d = deps();
    let priv_uid = create_ecdh(&d, CURVE25519);

    let rec = d.store.get(&priv_uid).unwrap().unwrap();
    assert_eq!(rec.algorithm, KmipAlgorithm::Ecdh, "algorithm stays ECDH per spec");
    assert_eq!(rec.recommended_curve, Some(CURVE25519), "curve persisted");

    // The engine really produced a Montgomery (X25519) key, not a NIST curve.
    assert_eq!(
        engine_private_key_type(&d, &rec.pkcs11_cka_id),
        CKK_EC_MONTGOMERY,
        "engine key is CKK_EC_MONTGOMERY (X25519)"
    );

    // GetAttributes reports the standard Cryptographic Domain Parameters.
    let ga = get_attributes(
        &d,
        GetAttributesRequest { uid: priv_uid.clone(), attribute_references: vec![] },
        &pqctoday_kmip::server::auth::AuthContext::open(),
        "ga",
    )
    .expect("get_attributes");
    assert!(
        ga.attributes.iter().any(|a| matches!(
            a,
            Attribute::CryptographicDomainParameters { recommended_curve: Some(c), .. } if *c == CURVE25519
        )),
        "GetAttributes returns Cryptographic Domain Parameters with CURVE25519"
    );

    // Non-extractable: Get on the private key is refused.
    let got = get(
        &d,
        GetRequest { uid: priv_uid, key_format_type: None, key_wrapping_specification: None },
        &pqctoday_kmip::server::auth::AuthContext::open(),
        "get",
    );
    assert!(got.is_err(), "Get on the X25519 private key must be refused");
}

#[test]
fn ecdh_curve448_makes_x448() {
    let _g = engine_lock();
    use softhsmrustv3::constants::CKK_EC_MONTGOMERY;
    let d = deps();
    let priv_uid = create_ecdh(&d, CURVE448);
    let rec = d.store.get(&priv_uid).unwrap().unwrap();
    assert_eq!(rec.algorithm, KmipAlgorithm::Ecdh);
    assert_eq!(rec.recommended_curve, Some(CURVE448));
    assert_eq!(
        engine_private_key_type(&d, &rec.pkcs11_cka_id),
        CKK_EC_MONTGOMERY,
        "engine key is CKK_EC_MONTGOMERY (X448)"
    );
}

/// KMIP DeriveKey (DerivationMethod = Asymmetric Key) over two X25519 keys is
/// symmetric — A·agree(B_pub) == B·agree(A_pub) — with both private keys
/// staying non-extractable in the engine (§7.13, key agreement).
#[test]
fn x25519_derive_key_agreement_is_symmetric() {
    let _g = engine_lock();
    let d = deps();
    let (a_priv, _a_pub_uid) = create_ecdh_pair(&d, CURVE25519);
    let (b_priv, _b_pub_uid) = create_ecdh_pair(&d, CURVE25519);
    let a_rec = d.store.get(&a_priv).unwrap().unwrap();
    let b_rec = d.store.get(&b_priv).unwrap().unwrap();
    let a_pub = engine_public_value(&d, &a_rec.pkcs11_cka_id);
    let b_pub = engine_public_value(&d, &b_rec.pkcs11_cka_id);

    // DeriveKey requires the base key to be Active.
    for uid in [&a_priv, &b_priv] {
        activate(&d, ActivateRequest { uid: uid.clone() }, "act").expect("activate");
    }

    let ss_ab = derive_agree(&d, &a_priv, &b_pub);
    let ss_ba = derive_agree(&d, &b_priv, &a_pub);
    assert_eq!(ss_ab, ss_ba, "ECDH agreement must be symmetric");
    assert_eq!(ss_ab.len(), 32, "X25519 shared secret is 32 bytes");
    assert!(!ss_ab.iter().all(|&x| x == 0), "shared secret is non-trivial");
}

/// Back-compat: NIST ECDH still works via Recommended Curve, and the engine
/// produces a Weierstrass EC key (CKK_EC), not a Montgomery one.
#[test]
fn ecdh_p256_recommended_curve_makes_nist_ec() {
    let _g = engine_lock();
    use softhsmrustv3::constants::CKK_EC;
    let d = deps();
    let priv_uid = create_ecdh(&d, P_256);
    let rec = d.store.get(&priv_uid).unwrap().unwrap();
    assert_eq!(rec.recommended_curve, Some(P_256));
    assert_eq!(engine_private_key_type(&d, &rec.pkcs11_cka_id), CKK_EC, "NIST key is CKK_EC");
}
