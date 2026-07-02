//! K6 — end-to-end hybrid KEM through the KMIP op handlers.
//!
//! CreateKeyPair(hybrid) → Activate → Encapsulate(public) → Decapsulate(private)
//! and assert the encapsulator's and decapsulator's shared secrets match. The
//! hybrid path is composed in-process (no PKCS#11 engine session needed), so
//! this runs with a plain MemoryStore + permissive engine.

use std::sync::Arc;

use pqctoday_kmip::auditlog::{AuditSink, RingSink};
use pqctoday_kmip::kmip30::{
    ActivateRequest, Attribute, CreateKeyPairRequest, DecapsulateRequest, EncapsulateRequest,
    KmipAlgorithm, UsageMask,
};
use pqctoday_kmip::ops::create_key_pair::create_key_pair;
use pqctoday_kmip::ops::decapsulate::decapsulate;
use pqctoday_kmip::ops::encapsulate::encapsulate;
use pqctoday_kmip::ops::activate::activate;
use pqctoday_kmip::ops::{Deps, DepsConfig};
use pqctoday_kmip::policy::Engine;
use pqctoday_kmip::store::MemoryStore;

fn deps() -> Deps {
    let ring = Arc::new(RingSink::new(64));
    let sink: Arc<dyn AuditSink> = ring;
    Deps::new(Engine::permissive(), Arc::new(MemoryStore::new()), sink, DepsConfig::default())
}

fn round_trip(alg: KmipAlgorithm) {
    let d = deps();

    // CreateKeyPair (KeyAgreement intent → CreateKeyPair:KeyAgreement).
    let kp = create_key_pair(
        &d,
        CreateKeyPairRequest {
            common_attributes: vec![
                Attribute::CryptographicAlgorithm(alg),
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

    // Activate both halves so the crypto ops accept them.
    for uid in [&kp.private_key_uid, &kp.public_key_uid] {
        activate(&d, ActivateRequest { uid: uid.clone() }, "act").expect("activate");
    }

    // Encapsulate to the PUBLIC key → ciphertext + shared-secret object.
    let enc = encapsulate(
        &d,
        EncapsulateRequest {
            uid: kp.public_key_uid.clone(),
            input_key_material: None,
            cryptographic_parameters: None,
        },
        "encap",
    )
    .expect("encapsulate");
    assert!(!enc.data.is_empty(), "ciphertext is non-empty");

    // Decapsulate with the PRIVATE key and the ciphertext.
    let dec = decapsulate(
        &d,
        DecapsulateRequest {
            uid: kp.private_key_uid.clone(),
            data: enc.data.clone(),
            cryptographic_parameters: None,
        },
        "decap",
    )
    .expect("decapsulate");

    // The two shared-secret SecretData objects must hold identical bytes.
    let ss_enc = d.store.get(&enc.uid).unwrap().unwrap().key_material.expect("encap SS material");
    let ss_dec = d.store.get(&dec.uid).unwrap().unwrap().key_material.expect("decap SS material");
    assert_eq!(
        ss_enc, ss_dec,
        "{alg:?}: encapsulator and decapsulator must derive the same shared secret"
    );
    assert_eq!(ss_enc.len(), 64, "combined shared secret is 32 (ML-KEM) + 32 (ECDH)");
}

#[test]
fn x25519_mlkem768_kmip_round_trip() {
    round_trip(KmipAlgorithm::X25519MlKem768);
}

#[test]
fn secp256r1_mlkem768_kmip_round_trip() {
    round_trip(KmipAlgorithm::SecP256r1MlKem768);
}
