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
    Attribute, CreateKeyPairRequest, GetAttributesRequest, GetRequest, KmipAlgorithm, UsageMask,
};
use pqctoday_kmip::ops::create_key_pair::create_key_pair;
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
        "ckp",
    )
    .expect("ecdh keygen");
    kp.private_key_uid
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
