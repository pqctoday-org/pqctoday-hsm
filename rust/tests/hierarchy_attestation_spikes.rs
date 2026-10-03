//! K0A executable spikes for the HSM hierarchy/attestation plan.
//!
//! Nothing in this file allocates a vendor mechanism or a production OID.
//! The RATS draft still contains TBD OID arcs, so its codec test uses the
//! RFC 5612 documentation PEN (32473) and must never be shipped on the wire.

use std::str::FromStr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, UNIX_EPOCH};

use const_oid::AssociatedOid;
use der::asn1::{Any, BitString, OctetString, Utf8StringRef};
use der::oid::ObjectIdentifier;
use der::{Decode, Encode, Sequence};
use spki07::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages};
use x509_cert::ext::Extension;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};

use softhsmrustv3::constants::{
    CKA_PUBLIC_KEY_INFO, CKM_ML_DSA, CKP_ML_DSA_65, CKP_ML_KEM_768,
};
use softhsmrustv3::native;

const OID_ML_DSA_65: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");
const OID_ML_KEM_768: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.4.2");
const OID_EDUCATIONAL_RECOVERY_RECIPIENT: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.20261002.2.4");

fn engine_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
}

fn alg(oid: ObjectIdentifier) -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid,
        parameters: None,
    }
}

fn validity() -> Validity {
    // Fixed 2023-11-14 .. 2033-05-18 window: deterministic and valid on the
    // plan date. These are test certificates, never production credentials.
    let not_before = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let not_after = UNIX_EPOCH + Duration::from_secs(2_000_000_000);
    Validity {
        not_before: Time::try_from(not_before).expect("valid test notBefore"),
        not_after: Time::try_from(not_after).expect("valid test notAfter"),
    }
}

fn extension<T: AssociatedOid + Encode>(critical: bool, value: &T) -> Extension {
    Extension {
        extn_id: T::OID,
        critical,
        extn_value: OctetString::new(value.to_der().expect("extension DER"))
            .expect("extension OCTET STRING"),
    }
}

fn ca_extensions(path_len_constraint: u8) -> Vec<Extension> {
    vec![
        extension(
            true,
            &BasicConstraints {
                ca: true,
                path_len_constraint: Some(path_len_constraint),
            },
        ),
        extension(
            true,
            &KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign),
        ),
    ]
}

fn mlkem_leaf_extensions() -> Vec<Extension> {
    vec![
        extension(
            true,
            &BasicConstraints {
                ca: false,
                path_len_constraint: None,
            },
        ),
        // RFC 9935 §5: keyEncipherment MUST be the only bit when the
        // keyUsage extension is present on an ML-KEM certificate.
        extension(true, &KeyUsage(KeyUsages::KeyEncipherment.into())),
        extension(
            true,
            &ExtendedKeyUsage(vec![OID_EDUCATIONAL_RECOVERY_RECIPIENT]),
        ),
    ]
}

fn tbs(
    serial: u8,
    issuer: Name,
    subject: Name,
    spki: SubjectPublicKeyInfoOwned,
    extensions: Vec<Extension>,
) -> TbsCertificate {
    TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&[serial]).expect("test serial"),
        signature: alg(OID_ML_DSA_65),
        issuer,
        validity: validity(),
        subject,
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(extensions),
    }
}

fn certificate(tbs_certificate: TbsCertificate, signature: &[u8]) -> Certificate {
    Certificate {
        tbs_certificate,
        signature_algorithm: alg(OID_ML_DSA_65),
        signature: BitString::from_bytes(signature).expect("certificate signature BIT STRING"),
    }
}

#[test]
fn k0a_mldsa65_manufacturing_device_and_mlkem768_function_chain() {
    use fips204::traits::{SerDes, Signer, Verifier};
    let _guard = engine_test_lock();
    softhsmrustv3::ffi::reset_all_engine_state_for_test();

    // The test manufacturing CA is deliberately host-side: its private key
    // never enters the token. A fresh root is generated for this run.
    let (root_pk, root_sk) = fips204::ml_dsa_65::try_keygen().expect("test root keygen");
    let root_pk_bytes = root_pk.into_bytes();
    let root_spki = SubjectPublicKeyInfoOwned {
        algorithm: alg(OID_ML_DSA_65),
        subject_public_key: BitString::from_bytes(&root_pk_bytes).expect("root SPKI key"),
    };

    let root_name = Name::from_str("CN=PQCToday TEST Manufacturing Root").unwrap();
    let root_tbs = tbs(
        1,
        root_name.clone(),
        root_name.clone(),
        root_spki,
        ca_extensions(1),
    );
    let root_tbs_der = root_tbs.to_der().unwrap();
    let root_sig = root_sk.try_sign(&root_tbs_der, &[]).expect("root self-sign");
    let root_cert = certificate(root_tbs, &root_sig);

    let session = native::bootstrap_default_token(0, "test-so", "test-user", "hierarchy-spike")
        .expect("fresh test token");
    let (device_pub, device_private) = native::generate_ml_dsa_keypair(
        session,
        CKP_ML_DSA_65,
        b"device-issuer",
        "device issuer",
    )
    .expect("device keygen in token");
    let device_spki_der = native::get_attribute(session, device_pub, CKA_PUBLIC_KEY_INFO)
        .expect("device SPKI");
    let device_spki = SubjectPublicKeyInfoOwned::from_der(&device_spki_der).unwrap();

    let device_name = Name::from_str("CN=PQCToday TEST Device 1").unwrap();
    let device_tbs = tbs(
        2,
        root_name.clone(),
        device_name.clone(),
        device_spki,
        ca_extensions(0),
    );
    let device_tbs_der = device_tbs.to_der().unwrap();
    let device_sig = root_sk
        .try_sign(&device_tbs_der, &[])
        .expect("manufacturing root signs device certificate");
    let device_cert = certificate(device_tbs, &device_sig);

    let (recovery_pub, _) = native::generate_ml_kem_keypair(
        session,
        CKP_ML_KEM_768,
        b"recovery-recipient",
        "recovery recipient",
    )
    .expect("ML-KEM function keygen in token");
    let recovery_spki_der = native::get_attribute(session, recovery_pub, CKA_PUBLIC_KEY_INFO)
        .expect("recovery SPKI");
    let recovery_spki = SubjectPublicKeyInfoOwned::from_der(&recovery_spki_der).unwrap();
    assert_eq!(recovery_spki.algorithm.oid, OID_ML_KEM_768);
    assert!(recovery_spki.algorithm.parameters.is_none());

    let recovery_name = Name::from_str("CN=PQCToday TEST Recovery Recipient").unwrap();
    let recovery_tbs = tbs(
        3,
        device_name,
        recovery_name,
        recovery_spki,
        mlkem_leaf_extensions(),
    );
    let recovery_eku = recovery_tbs
        .extensions
        .as_ref()
        .and_then(|extensions| {
            extensions
                .iter()
                .find(|candidate| candidate.extn_id == ExtendedKeyUsage::OID)
        })
        .expect("educational recovery-recipient EKU");
    assert!(recovery_eku.critical);
    assert_eq!(
        ExtendedKeyUsage::from_der(recovery_eku.extn_value.as_bytes())
            .expect("educational EKU DER")
            .0,
        vec![OID_EDUCATIONAL_RECOVERY_RECIPIENT]
    );
    let recovery_tbs_der = recovery_tbs.to_der().unwrap();
    let recovery_sig = native::sign(session, device_private, CKM_ML_DSA, &recovery_tbs_der)
        .expect("device issuer signs function certificate inside token");
    let recovery_cert = certificate(recovery_tbs, &recovery_sig);

    // DER round-trip all three certificates and independently verify each
    // signature with the appropriate public key implementation.
    let root_cert_der = root_cert.to_der().unwrap();
    let device_cert_der = device_cert.to_der().unwrap();
    let recovery_cert_der = recovery_cert.to_der().unwrap();
    // These generous caps are K0A evidence for the later normative parser
    // limits. They are not the final F4 wire limits, which K0B must freeze.
    assert!(root_cert_der.len() <= 8 * 1024);
    assert!(device_cert_der.len() <= 8 * 1024);
    assert!(recovery_cert_der.len() <= 8 * 1024);
    eprintln!(
        "K0A DER sizes: root={} device={} recovery={}",
        root_cert_der.len(),
        device_cert_der.len(),
        recovery_cert_der.len()
    );
    let root_cert = Certificate::from_der(&root_cert_der).unwrap();
    let device_cert = Certificate::from_der(&device_cert_der).unwrap();
    let recovery_cert = Certificate::from_der(&recovery_cert_der).unwrap();
    let root_pk = fips204::ml_dsa_65::PublicKey::try_from_bytes(root_pk_bytes).unwrap();
    let root_sig: [u8; 3309] = root_cert.signature.raw_bytes().try_into().unwrap();
    assert!(root_pk.verify(
        &root_cert.tbs_certificate.to_der().unwrap(),
        &root_sig,
        &[],
    ));
    let device_sig: [u8; 3309] = device_cert.signature.raw_bytes().try_into().unwrap();
    assert!(root_pk.verify(
        &device_cert.tbs_certificate.to_der().unwrap(),
        &device_sig,
        &[],
    ));
    assert!(native::verify(
        session,
        device_pub,
        CKM_ML_DSA,
        &recovery_cert.tbs_certificate.to_der().unwrap(),
        recovery_cert.signature.raw_bytes(),
    )
    .unwrap());

    let (_, key_usage) = recovery_cert
        .tbs_certificate
        .get::<KeyUsage>()
        .unwrap()
        .expect("ML-KEM keyUsage");
    assert_eq!(key_usage, KeyUsage(KeyUsages::KeyEncipherment.into()));
    native::close_session(session).unwrap();
    native::finalize().unwrap();
}

// Exact draft-ietf-rats-pkix-key-attestation-07 §5/§8 container shape.
// Open-type claim values are held as ANY because the selected claim OID
// determines the ASN.1 value type.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct Evidence {
    tbs: TbsEvidence,
    signatures: Vec<SignatureBlock>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    intermediate_certificates: Option<Vec<Certificate>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct SignatureBlock {
    sid: SignerIdentifier,
    signature_algorithm: AlgorithmIdentifierOwned,
    signature_value: OctetString,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct SignerIdentifier {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    key_id: Option<OctetString>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    subject_public_key_info: Option<SubjectPublicKeyInfoOwned>,
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", optional = "true")]
    certificate: Option<Certificate>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct TbsEvidence {
    version: u8,
    reported_elements: Vec<ReportedElement>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct ReportedElement {
    element_type: ObjectIdentifier,
    claims: Vec<ReportedClaim>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct ReportedClaim {
    claim_type: ObjectIdentifier,
    #[asn1(optional = "true")]
    value: Option<Any>,
}

// RFC 5612 documentation PEN. These are disposable test identifiers only;
// the draft's id-evidence and id-kp-attestationKey arcs remain TBD in -07.
const DOC_EVIDENCE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.20261002.3");

fn doc_oid(suffix: &str) -> ObjectIdentifier {
    ObjectIdentifier::from_str(&format!("{DOC_EVIDENCE}.{suffix}"))
        .expect("static documentation OID")
}

fn claim(oid: ObjectIdentifier, value: Any) -> ReportedClaim {
    ReportedClaim {
        claim_type: oid,
        value: Some(value),
    }
}

#[test]
fn k0a_rats07_evidence_der_round_trip_and_misbinding_rejection() {
    let _guard = engine_test_lock();
    softhsmrustv3::ffi::reset_all_engine_state_for_test();
    let session = native::bootstrap_default_token(0, "rats-so", "rats-user", "rats-spike")
        .expect("fresh test token");
    let (attestation_pub, attestation_private) = native::generate_ml_dsa_keypair(
        session,
        CKP_ML_DSA_65,
        b"attestation-function",
        "attestation function",
    )
    .unwrap();
    let attestation_spki_der =
        native::get_attribute(session, attestation_pub, CKA_PUBLIC_KEY_INFO).unwrap();
    let attestation_spki = SubjectPublicKeyInfoOwned::from_der(&attestation_spki_der).unwrap();
    let nonce = OctetString::new(b"verifier-nonce-2026-10-02".to_vec()).unwrap();
    let key_id = Utf8StringRef::new("key-1234").unwrap();
    let key_spki = OctetString::new(attestation_spki_der.clone()).unwrap();

    let tbs = TbsEvidence {
        version: 1,
        reported_elements: vec![
            ReportedElement {
                element_type: doc_oid("0.0"), // transaction
                claims: vec![claim(doc_oid("1.0.0"), Any::encode_from(&nonce).unwrap())],
            },
            ReportedElement {
                element_type: doc_oid("0.2"), // key
                claims: vec![
                    claim(doc_oid("1.2.0"), Any::encode_from(&key_id).unwrap()),
                    claim(doc_oid("1.2.1"), Any::encode_from(&key_spki).unwrap()),
                    claim(doc_oid("1.2.2"), Any::encode_from(&false).unwrap()),
                    claim(doc_oid("1.2.3"), Any::encode_from(&true).unwrap()),
                    claim(doc_oid("1.2.4"), Any::encode_from(&true).unwrap()),
                    claim(doc_oid("1.2.5"), Any::encode_from(&true).unwrap()),
                ],
            },
        ],
    };
    let tbs_der = tbs.to_der().unwrap();
    let signature = native::sign(session, attestation_private, CKM_ML_DSA, &tbs_der).unwrap();
    let evidence = Evidence {
        tbs,
        signatures: vec![SignatureBlock {
            sid: SignerIdentifier {
                key_id: None,
                subject_public_key_info: Some(attestation_spki),
                certificate: None,
            },
            signature_algorithm: alg(OID_ML_DSA_65),
            signature_value: OctetString::new(signature).unwrap(),
        }],
        intermediate_certificates: None,
    };

    let evidence_der = evidence.to_der().unwrap();
    // K0A only: leave room for a certificate-bearing signer identifier and
    // additional standard claims. K0B must replace this with an exact cap.
    assert!(evidence_der.len() <= 16 * 1024);
    eprintln!(
        "K0A DER sizes: tbs-evidence={} evidence={}",
        tbs_der.len(),
        evidence_der.len()
    );
    let decoded = Evidence::from_der(&evidence_der).unwrap();
    assert_eq!(decoded.tbs.version, 1);
    assert_eq!(decoded.tbs.reported_elements.len(), 2);
    assert!(native::verify(
        session,
        attestation_pub,
        CKM_ML_DSA,
        &decoded.tbs.to_der().unwrap(),
        decoded.signatures[0].signature_value.as_bytes(),
    )
    .unwrap());

    let mut misbound = decoded.tbs.clone();
    misbound.reported_elements[0].claims[0].value = Some(
        Any::encode_from(&OctetString::new(b"different-nonce".to_vec()).unwrap()).unwrap(),
    );
    assert!(!native::verify(
        session,
        attestation_pub,
        CKM_ML_DSA,
        &misbound.to_der().unwrap(),
        decoded.signatures[0].signature_value.as_bytes(),
    )
    .unwrap());
    native::close_session(session).unwrap();
    native::finalize().unwrap();
}
