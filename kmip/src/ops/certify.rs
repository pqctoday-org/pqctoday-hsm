//! KMIP 3.0 §6.1.6 **Certify** + §6.1.50 **Re-certify** — the server as a
//! PQC-capable X.509 Certificate Authority.
//!
//! ## What this does
//!
//! Certify generates a `Certificate` object for a public key: it parses
//! the supplied PKCS#10 CSR (or certifies a stored PublicKey), builds an
//! X.509 `TBSCertificate`, signs it **in the engine** with the
//! server-configured CA private key, assembles the `Certificate`, stores
//! it as a `CKO_CERTIFICATE` managed object, sets the §11
//! `Certificate Link` / `Public Key Link` cross-references, and returns
//! the new UID. Re-certify renews an existing certificate with a new
//! validity window (`Offset`) and `Replaced` / `Replacement` links.
//!
//! ## Why not rcgen for issuance
//!
//! rcgen 0.13 can ISSUE RSA/ECDSA/Ed25519 certs, but its
//! `SignatureAlgorithm` table has no ML-DSA — it cannot emit a
//! PQC-signed cert. Since this slice REQUIRES ML-DSA issuance, every
//! algorithm goes through one uniform path: build the `TBSCertificate`
//! with [`x509_cert`] (which accepts ARBITRARY `AlgorithmIdentifier`
//! OIDs), sign the TBS DER in the engine via `native::sign`, and wrap the
//! signature into the X.509 `Certificate`. rcgen is used ONLY to parse +
//! verify the inbound PKCS#10 CSR (`Invalid CSR` on failure).
//!
//! ## Signature-format conversions (X.509 expects)
//!
//! - **RSA**: the raw PKCS#1 v1.5 signature as-is → BIT STRING.
//! - **ECDSA**: the engine/PKCS#11 produces raw `r || s`; X.509 wants a
//!   DER `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` — we
//!   DER-wrap it ([`ecdsa_raw_to_der`]).
//! - **ML-DSA**: the raw FIPS 204 signature as-is → BIT STRING.
//!
//! ## AlgorithmIdentifier OIDs (verified)
//!
//! - RSA-with-SHA256 = 1.2.840.113549.1.1.11 (RFC 8017 / PKCS#1 §A.2.4).
//! - ecdsa-with-SHA256/384/512 = 1.2.840.10045.4.3.{2,3,4} (RFC 5758 §3.2).
//! - id-ml-dsa-44/65/87 = 2.16.840.1.101.3.4.3.{17,18,19} — NIST CSOR
//!   arc + draft-ietf-lamps-dilithium-certificates; the same OID is the
//!   ML-DSA SubjectPublicKeyInfo alg OID. These match the engine's own
//!   `crypto::handlers::build_mldsa{44,65,87}_spki` byte encodings
//!   (`60 86 48 01 65 03 04 03 {11,12,13}`).

use std::str::FromStr;
use time::OffsetDateTime;

use der::asn1::{BitString, OctetString, UintRef};
use der::{Decode, Encode, Sequence};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages};
use x509_cert::ext::Extension;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};

use crate::auditlog::{AuditEvent, EventPayload, KmipOpResult, Plane};
use crate::error::{KmipError, Result, ResultReason};
use crate::kmip30::{
    CertificateRequestType, CertifyRequest, CertifyResponse, KmipAlgorithm, ObjectType,
    ReCertifyRequest, ReCertifyResponse, State, UsageMask,
};
use crate::store::ObjectRecord;

use super::deps::{CaKeyDesignation, Deps};

// ── AlgorithmIdentifier OIDs ────────────────────────────────────────────────

const OID_RSA_SHA256: &str = "1.2.840.113549.1.1.11";
const OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const OID_ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";
const OID_ECDSA_SHA512: &str = "1.2.840.10045.4.3.4";
const OID_ML_DSA_44: &str = "2.16.840.1.101.3.4.3.17";
const OID_ML_DSA_65: &str = "2.16.840.1.101.3.4.3.18";
const OID_ML_DSA_87: &str = "2.16.840.1.101.3.4.3.19";
// EC named curves (in the SPKI alg params of an ECDSA key).
const OID_EC_P256: &str = "1.2.840.10045.3.1.7";
const OID_EC_P384: &str = "1.3.132.0.34";
const OID_EC_P521: &str = "1.3.132.0.35";

/// Monotonic serial-number source (process-local). X.509 serials must be
/// positive, unique-per-issuer, ≤ 20 octets. A timestamp-derived counter
/// is unique enough for an emulator CA and keeps serials increasing.
fn next_serial() -> Vec<u8> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let now = OffsetDateTime::now_utc().unix_timestamp_nanos() as u64;
    let n = now.wrapping_add(COUNTER.fetch_add(1, Ordering::Relaxed));
    // Force the high bit clear so the DER INTEGER is positive (the
    // x509-cert SerialNumber encoder also normalises, but be explicit).
    let mut bytes = n.to_be_bytes().to_vec();
    bytes[0] &= 0x7f;
    bytes
}

/// `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` — RFC 3279
/// §2.2.3. The engine returns raw `r || s` (fixed-width, big-endian); we
/// split it in half and DER-encode the two INTEGERs.
#[derive(Sequence)]
struct EcdsaSigValue<'a> {
    r: UintRef<'a>,
    s: UintRef<'a>,
}

/// Convert a raw PKCS#11 ECDSA signature (`r || s`, each field-width
/// big-endian) into a DER `Ecdsa-Sig-Value`. Returns `InvalidField` if
/// the raw signature has an odd length (cannot be halved).
fn ecdsa_raw_to_der(raw: &[u8]) -> Result<Vec<u8>> {
    if raw.is_empty() || raw.len() % 2 != 0 {
        return Err(KmipError::failed(
            ResultReason::CryptographicFailure,
            format!("ECDSA raw signature length {} is not 2·field-width", raw.len()),
        ));
    }
    let (r, s) = raw.split_at(raw.len() / 2);
    // UintRef strips leading zero bytes and rejects an all-zero value as
    // empty; X.509 r/s are always nonzero in practice.
    let r = UintRef::new(r).map_err(der_err)?;
    let s = UintRef::new(s).map_err(der_err)?;
    EcdsaSigValue { r, s }.to_der().map_err(der_err)
}

fn der_err(e: der::Error) -> KmipError {
    KmipError::failed(ResultReason::CryptographicFailure, format!("DER encode: {e}"))
}

/// Resolve, for a CA key's `KmipAlgorithm` (and, for ECDSA, the curve OID
/// taken from the CA cert SPKI), the X.509 signature `AlgorithmIdentifier`
/// + the engine sign mechanism (`CKM_*`).
fn signature_alg_and_mech(
    ca_algorithm: KmipAlgorithm,
    ca_spki_curve_oid: Option<&str>,
) -> Result<(AlgorithmIdentifierOwned, u32)> {
    use softhsmrustv3::constants as c;
    let oid = |s: &str| der::oid::ObjectIdentifier::from_str(s).expect("static OID");
    Ok(match ca_algorithm {
        KmipAlgorithm::Rsa => (
            // RSA AlgorithmIdentifier has explicit NULL parameters.
            AlgorithmIdentifierOwned {
                oid: oid(OID_RSA_SHA256),
                parameters: Some(der::Any::null()),
            },
            c::CKM_SHA256_RSA_PKCS,
        ),
        KmipAlgorithm::Ecdsa => {
            // Match the hash to the curve (P-256→SHA-256, P-384→SHA-384,
            // P-521→SHA-512) per the common X.509 convention. ECDSA
            // AlgorithmIdentifier OMITS parameters (RFC 5758 §3.2).
            let (sig_oid, mech) = match ca_spki_curve_oid {
                Some(OID_EC_P384) => (OID_ECDSA_SHA384, c::CKM_ECDSA_SHA384),
                Some(OID_EC_P521) => (OID_ECDSA_SHA512, c::CKM_ECDSA_SHA512),
                // Default / P-256.
                _ => (OID_ECDSA_SHA256, c::CKM_ECDSA_SHA256),
            };
            (
                AlgorithmIdentifierOwned { oid: oid(sig_oid), parameters: None },
                mech,
            )
        }
        KmipAlgorithm::MlDsa44 | KmipAlgorithm::MlDsa65 | KmipAlgorithm::MlDsa87 => {
            // PQC AlgorithmIdentifier has ABSENT parameters (not NULL).
            let sig_oid = match ca_algorithm {
                KmipAlgorithm::MlDsa44 => OID_ML_DSA_44,
                KmipAlgorithm::MlDsa65 => OID_ML_DSA_65,
                _ => OID_ML_DSA_87,
            };
            (
                AlgorithmIdentifierOwned { oid: oid(sig_oid), parameters: None },
                c::CKM_ML_DSA,
            )
        }
        other => {
            return Err(KmipError::failed(
                ResultReason::OperationNotSupported,
                format!("algorithm {other:?} cannot be used as a Certify CA key"),
            ));
        }
    })
}

/// The CA's resolved signing context: the engine handle, the X.509
/// signature AlgorithmIdentifier, the engine mechanism, and the issuer
/// DN (from the CA certificate's subject).
struct CaContext {
    private_uid: String,
    signature_alg: AlgorithmIdentifierOwned,
    mechanism: u32,
    issuer: Name,
    private_record: ObjectRecord,
}

/// Resolve the designated CA: validate it is configured, the private key
/// exists and is a PrivateKey, and the CA cert exists and parses. The
/// issuer DN + (for ECDSA) the curve OID come from the CA cert SPKI.
fn resolve_ca(deps: &Deps, op: &str) -> Result<CaContext> {
    let CaKeyDesignation { private_key_uid, certificate_uid } =
        deps.config.ca_key.clone().ok_or_else(|| {
            KmipError::permission_denied(format!(
                "{op}: server is not configured as a Certificate Authority \
                 (no --ca-key designated)"
            ))
        })?;

    // The CA private key must exist and be a PrivateKey — the
    // authorisation gate: only the designated key may sign issuances.
    let private_record = deps
        .store
        .get(&private_key_uid)?
        .ok_or_else(|| KmipError::object_not_found(&private_key_uid))?;
    if private_record.object_type != ObjectType::PrivateKey {
        return Err(KmipError::invalid_object_type(format!(
            "{op}: designated CA key {private_key_uid:?} is a \
             {:?}, not a PrivateKey",
            private_record.object_type
        )));
    }

    // The CA certificate supplies the issuer DN + the public key (for
    // verification + ECDSA curve detection).
    let cert_record = deps
        .store
        .get(&certificate_uid)?
        .ok_or_else(|| KmipError::object_not_found(&certificate_uid))?;
    if cert_record.object_type != ObjectType::Certificate {
        return Err(KmipError::invalid_object_type(format!(
            "{op}: designated CA cert {certificate_uid:?} is a \
             {:?}, not a Certificate",
            cert_record.object_type
        )));
    }
    let ca_cert_der = cert_record
        .certificate_value
        .as_deref()
        .or(cert_record.key_material.as_deref())
        .ok_or_else(|| {
            KmipError::failed(
                ResultReason::KeyValueNotPresent,
                format!("{op}: CA certificate {certificate_uid:?} has no DER value"),
            )
        })?;
    let ca_cert = Certificate::from_der(ca_cert_der).map_err(|e| {
        KmipError::failed(
            ResultReason::GeneralFailure,
            format!("{op}: CA certificate {certificate_uid:?} DER is unparseable: {e}"),
        )
    })?;
    let issuer = ca_cert.tbs_certificate.subject.clone();
    let curve_oid = ec_curve_oid_of(&ca_cert.tbs_certificate.subject_public_key_info);

    let (signature_alg, mechanism) =
        signature_alg_and_mech(private_record.algorithm, curve_oid.as_deref())?;

    Ok(CaContext {
        private_uid: private_key_uid,
        signature_alg,
        mechanism,
        issuer,
        private_record,
    })
}

/// Extract the EC named-curve OID string from a SubjectPublicKeyInfo's
/// AlgorithmIdentifier parameters (for ECDSA keys). `None` for non-EC.
fn ec_curve_oid_of(spki: &SubjectPublicKeyInfoOwned) -> Option<String> {
    spki.algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.decode_as::<der::oid::ObjectIdentifier>().ok())
        .map(|o| o.to_string())
}

/// Parsed CSR / supplied-key inputs: the subject DN + the
/// SubjectPublicKeyInfo to certify.
struct SubjectInputs {
    subject: Name,
    spki: SubjectPublicKeyInfoOwned,
    /// UID of the stored PublicKey being certified, when known (sets the
    /// §11 Public Key Link / Certificate Link). `None` for a pure-CSR
    /// path where no PublicKey object exists.
    public_key_uid: Option<String>,
}

/// Resolve the subject DN + SPKI to certify, from a CSR (PKCS#10) or a
/// supplied stored PublicKey UID. CSR self-signature is verified
/// (`Invalid CSR` on failure).
fn resolve_subject(
    deps: &Deps,
    op: &str,
    uid: Option<&str>,
    csr_type: Option<CertificateRequestType>,
    csr: Option<&[u8]>,
) -> Result<SubjectInputs> {
    match (csr, csr_type) {
        (Some(csr_bytes), ty) => {
            // Only PKCS#10 is implemented for issuance; CRMF/PEM are
            // recognised codepoints but unsupported here.
            match ty {
                Some(CertificateRequestType::Pkcs10) | None => {}
                Some(other) => {
                    return Err(KmipError::failed(
                        ResultReason::OperationNotSupported,
                        format!("{op}: Certificate Request Type {other:?} not supported \
                                 (only PKCS#10)"),
                    ));
                }
            }
            parse_pkcs10_csr(op, csr_bytes)
        }
        (None, _) => {
            // No CSR — certify a stored PublicKey by UID. Its DER public
            // key info must be reachable; we read the §11 PublicKeyInfo
            // off the store record's key_material (SPKI DER).
            let uid = uid.ok_or_else(|| {
                KmipError::failed(
                    ResultReason::InvalidField,
                    format!("{op}: neither a Certificate Request nor a Unique Identifier supplied"),
                )
            })?;
            let rec = deps
                .store
                .get(uid)?
                .ok_or_else(|| KmipError::object_not_found(uid))?;
            if rec.object_type != ObjectType::PublicKey {
                return Err(KmipError::invalid_object_type(format!(
                    "{op}: {uid:?} is a {:?}, not a PublicKey to certify",
                    rec.object_type
                )));
            }
            let spki_der = rec.key_material.as_deref().ok_or_else(|| {
                KmipError::failed(
                    ResultReason::KeyValueNotPresent,
                    format!("{op}: PublicKey {uid:?} has no SubjectPublicKeyInfo DER"),
                )
            })?;
            let spki = SubjectPublicKeyInfoOwned::from_der(spki_der).map_err(|e| {
                KmipError::failed(
                    ResultReason::InvalidField,
                    format!("{op}: PublicKey {uid:?} value is not a valid SPKI DER: {e}"),
                )
            })?;
            // No subject DN on a bare public key — synthesise one from
            // the object's name (or UID).
            let cn = rec.name.clone().unwrap_or_else(|| uid.to_string());
            let subject = Name::from_str(&format!("CN={cn}")).map_err(|e| {
                KmipError::failed(ResultReason::InvalidField, format!("{op}: bad subject CN: {e}"))
            })?;
            Ok(SubjectInputs { subject, spki, public_key_uid: Some(uid.to_string()) })
        }
    }
}

/// Parse a PKCS#10 CSR via `x509-cert` (subject DN + SPKI) and verify its
/// self-signature via rcgen (`Invalid CSR` on failure).
fn parse_pkcs10_csr(op: &str, csr: &[u8]) -> Result<SubjectInputs> {
    // Verify the CSR self-signature (rcgen's parser checks it).
    // `CertificateSigningRequestDer` lives in `rustls-pki-types`, re-exported
    // by `rustls` (a direct dep) — rcgen does not re-export it.
    let csr_der: rustls::pki_types::CertificateSigningRequestDer<'static> = csr.to_vec().into();
    rcgen::CertificateSigningRequestParams::from_der(&csr_der).map_err(|e| {
        KmipError::invalid_csr(format!("{op}: PKCS#10 CSR rejected: {e}"))
    })?;
    // Decode subject DN + SPKI directly with x509-cert (gives us the
    // SubjectPublicKeyInfoOwned the TBSCertificate needs).
    let req = x509_cert::request::CertReq::from_der(csr).map_err(|e| {
        KmipError::invalid_csr(format!("{op}: PKCS#10 CSR DER unparseable: {e}"))
    })?;
    Ok(SubjectInputs {
        subject: req.info.subject.clone(),
        spki: req.info.public_key.clone(),
        public_key_uid: None,
    })
}

/// Validity window from the request attributes (Activation/Deactivation
/// Date), defaulting to now .. now+1y when unset. `offset` (seconds)
/// shifts the Activation Date relative to Initial Date (Re-certify).
fn validity_window(
    activation: Option<OffsetDateTime>,
    deactivation: Option<OffsetDateTime>,
    offset: Option<i64>,
) -> Result<(OffsetDateTime, OffsetDateTime)> {
    let now = OffsetDateTime::now_utc();
    let not_before = match (activation, offset) {
        (_, Some(off)) => now + time::Duration::seconds(off),
        (Some(a), None) => a,
        (None, None) => now,
    };
    let not_after = deactivation.unwrap_or(not_before + time::Duration::days(365));
    Ok((not_before, not_after))
}

/// Build the TBSCertificate, sign it in the engine, assemble the
/// `Certificate`, and return its DER. Shared by Certify + Re-certify.
fn issue_certificate(
    deps: &Deps,
    op: &str,
    correlation_id: &str,
    ca: &CaContext,
    subject_inputs: &SubjectInputs,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
) -> Result<Vec<u8>> {
    let serial = SerialNumber::new(&next_serial()).map_err(der_err)?;
    let validity = Validity {
        not_before: Time::try_from(std::time::SystemTime::from(not_before)).map_err(der_err)?,
        not_after: Time::try_from(std::time::SystemTime::from(not_after)).map_err(der_err)?,
    };

    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: serial,
        signature: ca.signature_alg.clone(),
        issuer: ca.issuer.clone(),
        validity,
        subject: subject_inputs.subject.clone(),
        subject_public_key_info: subject_inputs.spki.clone(),
        issuer_unique_id: None,
        subject_unique_id: None,
        // v0.1 — minimal cert: no extensions. (BasicConstraints / KeyUsage
        // / SKI / AKI can be layered later; the correctness assertion is
        // that the issued cert's signature verifies against the CA key.)
        extensions: None,
    };

    let tbs_der = tbs.to_der().map_err(der_err)?;

    // ── Engine: sign the TBS DER with the CA private key ─────────────
    let raw_sig = sign_tbs_in_engine(deps, op, correlation_id, ca, &tbs_der)?;

    // ── X.509 signature-format conversion ────────────────────────────
    let signature_bytes = match ca.private_record.algorithm {
        KmipAlgorithm::Ecdsa => ecdsa_raw_to_der(&raw_sig)?,
        // RSA PKCS#1 v1.5 + ML-DSA FIPS-204 signatures go in as-is.
        _ => raw_sig,
    };

    let cert = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: ca.signature_alg.clone(),
        signature: BitString::from_bytes(&signature_bytes).map_err(der_err)?,
    };
    cert.to_der().map_err(der_err)
}

/// Sign the TBS DER in the engine with the CA private key. Falls back to
/// a deterministic placeholder when no engine session is wired (unit
/// tests) — same convention as `ops::sign`.
fn sign_tbs_in_engine(
    deps: &Deps,
    op: &str,
    correlation_id: &str,
    ca: &CaContext,
    tbs_der: &[u8],
) -> Result<Vec<u8>> {
    match deps.engine_session {
        Some(session) => {
            let handle = super::helpers::find_handle_for_object(
                session,
                &ca.private_record.pkcs11_cka_id,
                ObjectType::PrivateKey,
            )
            .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, &format!("{op}:find")))?
            .ok_or_else(|| KmipError::object_not_found(&ca.private_uid))?;
            let r = softhsmrustv3::native::sign(session, handle, ca.mechanism, tbs_der);
            super::helpers::emit_pkcs11_result(
                deps,
                correlation_id,
                "native::sign(CA)",
                Some(ca.mechanism),
                &r,
            );
            r.map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, op))
        }
        None => {
            super::helpers::emit_pkcs11(
                deps,
                correlation_id,
                "soft::placeholder_ca_sign",
                Some(ca.mechanism),
                0,
                "CKR_OK",
            );
            // Deterministic placeholder so the unit-test surface (no
            // engine) can still build a structurally-valid Certificate.
            use sha2::{Digest, Sha256};
            Ok(Sha256::digest(tbs_der).to_vec())
        }
    }
}

/// Pull Activation / Deactivation Date out of the request attribute list.
fn dates_from_attributes(
    attributes: &[crate::kmip30::Attribute],
) -> (Option<OffsetDateTime>, Option<OffsetDateTime>) {
    use crate::kmip30::Attribute;
    let mut activation = None;
    let mut deactivation = None;
    let to_dt = |secs: i64| OffsetDateTime::from_unix_timestamp(secs).ok();
    for a in attributes {
        match a {
            Attribute::ActivationDate(d) => activation = to_dt(*d),
            Attribute::DeactivationDate(d) => deactivation = to_dt(*d),
            _ => {}
        }
    }
    (activation, deactivation)
}

/// Subject CN (best-effort) from a Name for the §11 CertificateSubjectCN.
fn subject_cn(der: &[u8]) -> Option<String> {
    super::der_x509::extract_subject_cn(der)
}

/// Build the X.509v3 extensions a self-signed **CA** certificate needs so
/// independent verifiers (e.g. `openssl verify`) will accept it as a chain
/// anchor for the certs it issues:
///
/// - **BasicConstraints** `cA:TRUE`, marked *critical* — RFC 5280 §4.2.1.9:
///   a CA cert MUST assert `cA = TRUE`, and the extension SHOULD be critical.
///   Without it, `openssl verify` rejects the issuer with
///   `invalid CA certificate`.
/// - **KeyUsage** `keyCertSign | cRLSign`, marked *critical* — RFC 5280
///   §4.2.1.3: a cert whose key signs other certs MUST set `keyCertSign`;
///   when KeyUsage is present it SHOULD be critical. `cRLSign` is included
///   so the same key may sign CRLs.
///
/// Both extension OIDs come from the types' `AssociatedOid` impls.
fn ca_extensions() -> Result<Vec<Extension>> {
    use const_oid::AssociatedOid;

    let basic = BasicConstraints { ca: true, path_len_constraint: None };
    let basic_der = basic.to_der().map_err(der_err)?;

    let key_usage = KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign);
    let ku_der = key_usage.to_der().map_err(der_err)?;

    Ok(vec![
        Extension {
            extn_id: BasicConstraints::OID,
            critical: true,
            extn_value: OctetString::new(basic_der).map_err(der_err)?,
        },
        Extension {
            extn_id: KeyUsage::OID,
            critical: true,
            extn_value: OctetString::new(ku_der).map_err(der_err)?,
        },
    ])
}

// ── CA bootstrap ─────────────────────────────────────────────────────────────

/// Build + store a self-signed CA certificate for a stored CA PrivateKey,
/// so the server can act as a root CA for §6.1.6 Certify. The CA private
/// key (`private_key_uid`, already in the store + engine) signs its own
/// TBSCertificate in the engine; the CA public key SPKI is read from the
/// engine (`CKA_PUBLIC_KEY_INFO`). Stores the result as a Certificate
/// object under `certificate_uid` with subject/issuer `CN={subject_cn}`.
///
/// This is the net-new CA infra: an operator generates a CA keypair
/// (CreateKeyPair), calls this to mint the root cert, then designates the
/// pair via `--ca-key` / `--ca-cert`. Returns the CA certificate DER.
pub fn bootstrap_ca_certificate(
    deps: &Deps,
    private_key_uid: &str,
    certificate_uid: &str,
    subject_cn: &str,
    validity_days: i64,
) -> Result<Vec<u8>> {
    use softhsmrustv3::constants as c;
    let session = deps.engine_session.ok_or_else(|| {
        KmipError::internal("bootstrap_ca_certificate requires an engine session")
    })?;
    let priv_rec = deps
        .store
        .get(private_key_uid)?
        .ok_or_else(|| KmipError::object_not_found(private_key_uid))?;
    if priv_rec.object_type != ObjectType::PrivateKey {
        return Err(KmipError::invalid_object_type(format!(
            "{private_key_uid:?} is not a PrivateKey"
        )));
    }
    // Resolve both halves (pub + prv) from the shared CKA_ID.
    let prv_h = super::helpers::find_handle_for_object(
        session, &priv_rec.pkcs11_cka_id, ObjectType::PrivateKey,
    )
    .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "bootstrap:find-priv"))?
    .ok_or_else(|| KmipError::object_not_found(private_key_uid))?;
    let pub_h = super::helpers::find_handle_for_object(
        session, &priv_rec.pkcs11_cka_id, ObjectType::PublicKey,
    )
    .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "bootstrap:find-pub"))?
    .ok_or_else(|| {
        KmipError::failed(
            ResultReason::KeyValueNotPresent,
            format!("CA public key for {private_key_uid:?} not found in engine"),
        )
    })?;
    let spki_der = softhsmrustv3::native::get_attribute(session, pub_h, c::CKA_PUBLIC_KEY_INFO)
        .ok_or_else(|| {
            KmipError::failed(
                ResultReason::KeyValueNotPresent,
                "CA public key has no CKA_PUBLIC_KEY_INFO".to_string(),
            )
        })?;
    let spki = SubjectPublicKeyInfoOwned::from_der(&spki_der).map_err(|e| {
        KmipError::failed(ResultReason::GeneralFailure, format!("CA SPKI DER unparseable: {e}"))
    })?;
    let curve = ec_curve_oid_of(&spki);
    let (sig_alg, mech) = signature_alg_and_mech(priv_rec.algorithm, curve.as_deref())?;

    let name = Name::from_str(&format!("CN={subject_cn}"))
        .map_err(|e| KmipError::invalid_field(format!("bad CA subject CN: {e}")))?;
    let now = OffsetDateTime::now_utc();
    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&next_serial()).map_err(der_err)?,
        signature: sig_alg.clone(),
        issuer: name.clone(),
        validity: Validity {
            not_before: Time::try_from(std::time::SystemTime::from(now - time::Duration::days(1)))
                .map_err(der_err)?,
            not_after: Time::try_from(std::time::SystemTime::from(
                now + time::Duration::days(validity_days),
            ))
            .map_err(der_err)?,
        },
        subject: name,
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        // A root CA cert MUST carry BasicConstraints CA:TRUE +
        // KeyUsage keyCertSign so chains it signs verify externally
        // (RFC 5280 §4.2.1.9 / §4.2.1.3).
        extensions: Some(ca_extensions()?),
    };
    let tbs_der = tbs.to_der().map_err(der_err)?;
    let raw = softhsmrustv3::native::sign(session, prv_h, mech, &tbs_der)
        .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "bootstrap:sign"))?;
    let sig = match priv_rec.algorithm {
        KmipAlgorithm::Ecdsa => ecdsa_raw_to_der(&raw)?,
        _ => raw,
    };
    let cert = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: sig_alg,
        signature: BitString::from_bytes(&sig).map_err(der_err)?,
    };
    let der = cert.to_der().map_err(der_err)?;

    deps.store.put(ObjectRecord {
        uid: certificate_uid.to_string(),
        object_type: ObjectType::Certificate,
        algorithm: priv_rec.algorithm,
        usage_mask: UsageMask::VERIFY,
        state: State::Active,
        key_material: Some(der.clone()),
        certificate_type: Some(0x01),
        certificate_value: Some(der.clone()),
        certificate_length: Some(der.len() as i32),
        certificate_subject_cn: Some(subject_cn.to_string()),
        ..ObjectRecord::default()
    })?;
    Ok(der)
}

// ── Certify (§6.1.6) ────────────────────────────────────────────────────────

pub fn certify(deps: &Deps, req: CertifyRequest, correlation_id: &str) -> Result<CertifyResponse> {
    let started = OffsetDateTime::now_utc();
    emit_request(deps, correlation_id, "Certify", format!(
        "csr={} uid={:?}",
        req.certificate_request.is_some(),
        req.uid
    ));

    let ca = resolve_ca(deps, "Certify").map_err(|e| fail(deps, correlation_id, "Certify", e))?;
    let subject_inputs = resolve_subject(
        deps,
        "Certify",
        req.uid.as_deref(),
        req.certificate_request_type,
        req.certificate_request.as_deref(),
    )
    .map_err(|e| fail(deps, correlation_id, "Certify", e))?;

    let (activation, deactivation) = dates_from_attributes(&req.attributes);
    let (not_before, not_after) = validity_window(activation, deactivation, None)
        .map_err(|e| fail(deps, correlation_id, "Certify", e))?;

    let cert_der = issue_certificate(
        deps, "Certify", correlation_id, &ca, &subject_inputs, not_before, not_after,
    )
    .map_err(|e| fail(deps, correlation_id, "Certify", e))?;

    let uid = store_certificate(
        deps,
        &cert_der,
        not_before,
        Some(not_after),
        subject_inputs.public_key_uid.as_deref(),
        None,
        None,
    )?;

    emit_success(deps, correlation_id, "Certify");
    let _ = started;
    Ok(CertifyResponse { uid })
}

// ── Re-certify (§6.1.50) ─────────────────────────────────────────────────────

pub fn recertify(
    deps: &Deps,
    req: ReCertifyRequest,
    correlation_id: &str,
) -> Result<ReCertifyResponse> {
    emit_request(deps, correlation_id, "Re-certify", format!("uid={}", req.uid));

    let ca =
        resolve_ca(deps, "Re-certify").map_err(|e| fail(deps, correlation_id, "Re-certify", e))?;

    // The existing certificate being renewed.
    let existing = deps
        .store
        .get(&req.uid)?
        .ok_or_else(|| fail(deps, correlation_id, "Re-certify", KmipError::object_not_found(&req.uid)))?;
    if existing.object_type != ObjectType::Certificate {
        return Err(fail(
            deps,
            correlation_id,
            "Re-certify",
            KmipError::invalid_object_type(format!(
                "Re-certify: {:?} is a {:?}, not a Certificate",
                req.uid, existing.object_type
            )),
        ));
    }
    let existing_der = existing
        .certificate_value
        .as_deref()
        .or(existing.key_material.as_deref())
        .ok_or_else(|| {
            fail(
                deps,
                correlation_id,
                "Re-certify",
                KmipError::failed(
                    ResultReason::KeyValueNotPresent,
                    format!("Re-certify: existing certificate {:?} has no DER", req.uid),
                ),
            )
        })?;
    let existing_cert = Certificate::from_der(existing_der).map_err(|e| {
        fail(
            deps,
            correlation_id,
            "Re-certify",
            KmipError::failed(
                ResultReason::GeneralFailure,
                format!("Re-certify: existing certificate DER unparseable: {e}"),
            ),
        )
    })?;

    // Re-certify renews the SAME key pair: reuse the existing cert's
    // subject DN + SPKI (a CSR may also be supplied, but the MVP renews
    // in place). The PublicKey link is carried over from the existing
    // certificate record if present.
    let subject_inputs = if let Some(csr) = req.certificate_request.as_deref() {
        parse_pkcs10_csr("Re-certify", csr)
            .map_err(|e| fail(deps, correlation_id, "Re-certify", e))?
    } else {
        SubjectInputs {
            subject: existing_cert.tbs_certificate.subject.clone(),
            spki: existing_cert.tbs_certificate.subject_public_key_info.clone(),
            public_key_uid: existing
                .links
                .get("PublicKeyLink")
                .cloned(),
        }
    };

    // §6.1.50 date table: with an Offset, AT2 = IT2 + Offset; otherwise
    // copy the existing window. IT2 = now.
    let (existing_activation, existing_deactivation) =
        (existing.activation_date, existing.deactivation_date);
    let (not_before, not_after) = match req.offset {
        Some(off) => {
            let it2 = OffsetDateTime::now_utc();
            let at2 = it2 + time::Duration::seconds(off);
            // DT2 = DT1 + (AT2 - AT1) when both dates exist; else AT2+1y.
            let dt2 = match (existing_activation, existing_deactivation) {
                (Some(at1), Some(dt1)) => dt1 + (at2 - at1),
                _ => at2 + time::Duration::days(365),
            };
            (at2, dt2)
        }
        None => {
            // Copy the existing window (default per §6.1.50).
            let nb = existing_activation.unwrap_or_else(OffsetDateTime::now_utc);
            let na = existing_deactivation.unwrap_or(nb + time::Duration::days(365));
            (nb, na)
        }
    };

    let cert_der = issue_certificate(
        deps, "Re-certify", correlation_id, &ca, &subject_inputs, not_before, not_after,
    )
    .map_err(|e| fail(deps, correlation_id, "Re-certify", e))?;

    // Store the new cert with a Replaced link → existing; carry the
    // existing cert's Name (§6.1.50: the new cert takes over the Name).
    let new_uid = store_certificate(
        deps,
        &cert_der,
        not_before,
        Some(not_after),
        subject_inputs.public_key_uid.as_deref(),
        Some(&req.uid),         // ReplacedObjectLink → existing
        existing.name.clone(),  // new cert takes over the Name
    )?;

    // Mutate the existing cert: Replacement link → new, remove Name,
    // deactivate it (§6.1.50 Attribute Requirements table).
    let mut existing_mut = existing.clone();
    existing_mut
        .links
        .insert("ReplacementObjectLink".to_string(), new_uid.clone());
    existing_mut.name = None;
    existing_mut.state = State::Deactivated;
    existing_mut.deactivation_date = Some(OffsetDateTime::now_utc());
    existing_mut.last_change_date = Some(OffsetDateTime::now_utc());
    deps.store.update(existing_mut)?;

    // Re-point the PublicKey's Certificate Link to the new cert.
    if let Some(pk_uid) = &subject_inputs.public_key_uid {
        if let Ok(Some(mut pk)) = deps.store.get(pk_uid) {
            pk.links
                .insert("CertificateLink".to_string(), new_uid.clone());
            let _ = deps.store.update(pk);
        }
    }

    emit_success(deps, correlation_id, "Re-certify");
    Ok(ReCertifyResponse { uid: new_uid })
}

/// Store an issued Certificate as a `CKO_CERTIFICATE` managed object,
/// deriving the §11 attributes from the DER. Sets the §11
/// Certificate/PublicKey cross-links. Returns the new UID.
fn store_certificate(
    deps: &Deps,
    cert_der: &[u8],
    not_before: OffsetDateTime,
    not_after: Option<OffsetDateTime>,
    public_key_uid: Option<&str>,
    replaced_uid: Option<&str>,
    name: Option<String>,
) -> Result<String> {
    use sha2::{Digest, Sha256};
    let uid = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    let now = OffsetDateTime::now_utc();

    let mut links = std::collections::HashMap::new();
    if let Some(pk) = public_key_uid {
        // §6.1.6: "For the generated certificate, the server SHALL create
        // a Public Key Link attribute pointing to the Public Key."
        links.insert("PublicKeyLink".to_string(), pk.to_string());
    }
    if let Some(replaced) = replaced_uid {
        links.insert("ReplacedObjectLink".to_string(), replaced.to_string());
    }

    deps.store.put(ObjectRecord {
        uid: uid.clone(),
        object_type: ObjectType::Certificate,
        // X.509 certificate object — the §11 surface treats the DER as
        // opaque; the §11 cert attributes below are server-derived.
        algorithm: KmipAlgorithm::Rsa, // placeholder; not used for certs
        usage_mask: UsageMask::VERIFY,
        state: State::Active,
        initial_date: now,
        activation_date: Some(not_before),
        deactivation_date: not_after,
        last_change_date: Some(now),
        original_creation_date: Some(now),
        name,
        links,
        // The DER is both the managed-object value (so Get returns it) and
        // the §11 Certificate Value.
        key_material: Some(cert_der.to_vec()),
        certificate_type: Some(0x01), // X.509
        certificate_value: Some(cert_der.to_vec()),
        certificate_length: Some(cert_der.len() as i32),
        certificate_subject_cn: subject_cn(cert_der),
        digest_value: Some(Sha256::digest(cert_der).to_vec()),
        ..ObjectRecord::default()
    })?;

    // §6.1.6: "For the public key, the server SHALL create a Certificate
    // Link attribute pointing to the generated certificate."
    if let Some(pk_uid) = public_key_uid {
        if let Ok(Some(mut pk)) = deps.store.get(pk_uid) {
            pk.links
                .insert("CertificateLink".to_string(), uid.clone());
            let _ = deps.store.update(pk);
        }
    }

    Ok(uid)
}

// ── Audit helpers (mirror ops::sign) ─────────────────────────────────────────

fn emit_request(deps: &Deps, correlation_id: &str, op: &str, summary: String) {
    deps.sink.emit(AuditEvent::at(
        OffsetDateTime::now_utc(),
        Plane::Kmip,
        correlation_id,
        EventPayload::KmipRequestReceived {
            op: op.into(),
            request_summary: summary,
            client_cn: None,
        },
    ));
}

fn emit_success(deps: &Deps, correlation_id: &str, op: &str) {
    deps.sink.emit(AuditEvent::at(
        OffsetDateTime::now_utc(),
        Plane::Kmip,
        correlation_id,
        EventPayload::KmipResponseSent { op: op.into(), result: KmipOpResult::Success, latency_ms: 0 },
    ));
}

fn fail(deps: &Deps, correlation_id: &str, op: &str, err: KmipError) -> KmipError {
    deps.sink.emit(AuditEvent::at(
        OffsetDateTime::now_utc(),
        Plane::Kmip,
        correlation_id,
        EventPayload::KmipResponseSent {
            op: op.into(),
            result: KmipOpResult::OperationFailed { reason: format!("{:?}", err.result_reason()) },
            latency_ms: 0,
        },
    ));
    err
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditlog::RingSink;
    use crate::store::MemoryStore;
    use std::sync::{Arc, Mutex, OnceLock};

    // ── No-engine unit tests (format conversions + negatives) ────────────

    fn deps_no_engine() -> Deps {
        let sink: Arc<dyn crate::auditlog::AuditSink> = Arc::new(RingSink::new(64));
        Deps::new(
            crate::policy::Engine::permissive(),
            Arc::new(MemoryStore::new()),
            sink,
            crate::ops::DepsConfig::default(),
        )
    }

    #[test]
    fn ecdsa_raw_to_der_wraps_r_s_into_sequence() {
        // r = 0x01.. (32 bytes), s = 0x02.. (32 bytes) → DER SEQUENCE of
        // two INTEGERs. Parse it back to confirm structure.
        let mut raw = vec![0u8; 64];
        raw[0] = 0x11; // r high byte (positive)
        raw[32] = 0x22; // s high byte
        let der = ecdsa_raw_to_der(&raw).unwrap();
        let parsed = EcdsaSigValue::from_der(&der).unwrap();
        assert_eq!(parsed.r.as_bytes()[0], 0x11);
        assert_eq!(parsed.s.as_bytes()[0], 0x22);
    }

    #[test]
    fn ecdsa_raw_to_der_rejects_odd_length() {
        assert!(ecdsa_raw_to_der(&[0u8; 63]).is_err());
    }

    #[test]
    fn certify_without_ca_configured_is_permission_denied() {
        let deps = deps_no_engine();
        let err = certify(&deps, CertifyRequest::default(), "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::PermissionDenied);
    }

    #[test]
    fn certify_ca_key_not_found_is_object_not_found() {
        let deps = deps_no_engine().with_ca_key("urn:nope-priv", "urn:nope-cert");
        let err = certify(&deps, CertifyRequest::default(), "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::ObjectNotFound);
    }

    #[test]
    fn certify_ca_key_not_a_private_key_is_invalid_object_type() {
        let deps = deps_no_engine().with_ca_key("urn:sym", "urn:cert");
        deps.store
            .put(ObjectRecord {
                uid: "urn:sym".into(),
                object_type: ObjectType::SymmetricKey,
                algorithm: KmipAlgorithm::Aes,
                state: State::Active,
                ..ObjectRecord::default()
            })
            .unwrap();
        let err = certify(&deps, CertifyRequest::default(), "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::InvalidObjectType);
    }

    #[test]
    fn certify_tampered_csr_is_invalid_csr() {
        // A real (rcgen) ECDSA CSR with a flipped byte → Invalid CSR.
        let kp = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["leaf.example".into()]).unwrap();
        params.distinguished_name.push(rcgen::DnType::CommonName, "leaf");
        let csr = params.serialize_request(&kp).unwrap();
        let mut csr_der = csr.der().to_vec();
        // Flip a byte inside the signature region (last bytes) to break
        // the self-signature without destroying the DER structure.
        let n = csr_der.len();
        csr_der[n - 5] ^= 0xFF;

        // Need a designated CA so we get past resolve_ca to the CSR parse.
        let (deps, _g) = ca_engine_deps(KmipAlgorithm::Ecdsa);
        let err = certify(
            &deps,
            CertifyRequest {
                certificate_request_type: Some(CertificateRequestType::Pkcs10),
                certificate_request: Some(csr_der),
                ..CertifyRequest::default()
            },
            "c",
        )
        .unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::InvalidCsr);
    }

    // ── Engine-backed issuance + verification (the high-assurance track) ──

    /// Serialise engine-touching tests (shared global session state).
    fn engine_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Generate a CA keypair of `algo` in the engine, read its SPKI, build
    /// a self-signed CA certificate (TBS signed in the engine), store the
    /// CA private key + CA cert, and hand back Deps designated with that
    /// CA. Returns the Deps plus the engine session + CA public handle so
    /// tests can verify issued signatures directly.
    struct CaFixture {
        deps: Deps,
        session: u32,
        ca_pub_handle: u32,
        ca_algo: KmipAlgorithm,
    }

    fn bootstrap_ca(algo: KmipAlgorithm) -> CaFixture {
        use softhsmrustv3::constants as c;
        use softhsmrustv3::native::{self, session, EccCurve};
        let _ = session::finalize();
        session::init().expect("engine init");
        let sess = session::bootstrap_default_token(0, "so-pin", "user-pin", "p2.3-ca")
            .expect("bootstrap session");

        let cka_id = b"ca-key-id".to_vec();
        let (pub_h, prv_h) = match algo {
            KmipAlgorithm::Rsa => native::generate_rsa_keypair(sess, 2048, &cka_id, "ca-rsa"),
            KmipAlgorithm::Ecdsa => {
                native::generate_ecdsa_keypair(sess, EccCurve::P256, &cka_id, "ca-ec")
            }
            KmipAlgorithm::MlDsa65 => {
                native::generate_ml_dsa_keypair(sess, c::CKP_ML_DSA_65, &cka_id, "ca-mldsa")
            }
            other => panic!("unsupported CA algo {other:?}"),
        }
        .expect("CA keygen");

        // SPKI of the CA public key (PKCS#11 v3.2 §4.14 CKA_PUBLIC_KEY_INFO).
        let ca_spki_der = native::get_attribute(sess, pub_h, c::CKA_PUBLIC_KEY_INFO)
            .expect("CA public key SPKI");

        // Store CA private + cert objects.
        let sink: Arc<dyn crate::auditlog::AuditSink> = Arc::new(RingSink::new(256));
        let deps = Deps::new(
            crate::policy::Engine::permissive(),
            Arc::new(MemoryStore::new()),
            sink,
            crate::ops::DepsConfig::default(),
        )
        .with_engine_session(sess)
        .with_ca_key("urn:ca-priv", "urn:ca-cert");

        let _ = prv_h;
        let _ = ca_spki_der;
        deps.store
            .put(ObjectRecord {
                uid: "urn:ca-priv".into(),
                object_type: ObjectType::PrivateKey,
                algorithm: algo,
                usage_mask: UsageMask::SIGN,
                state: State::Active,
                pkcs11_cka_id: cka_id.clone(),
                ..ObjectRecord::default()
            })
            .unwrap();

        // Mint the self-signed CA cert via the production bootstrap path.
        super::bootstrap_ca_certificate(&deps, "urn:ca-priv", "urn:ca-cert", "PQC Test CA", 3650)
            .expect("bootstrap CA cert");

        CaFixture { deps, session: sess, ca_pub_handle: pub_h, ca_algo: algo }
    }

    /// `bootstrap_ca` but holding the engine lock — for tests that only
    /// need a designated CA (e.g. the tampered-CSR negative).
    fn ca_engine_deps(algo: KmipAlgorithm) -> (Deps, std::sync::MutexGuard<'static, ()>) {
        let g = engine_lock();
        let f = bootstrap_ca(algo);
        (f.deps, g)
    }

    /// Mechanism to VERIFY an issued cert's signature against the CA
    /// public key in the engine, given the CA algorithm.
    fn verify_mech(algo: KmipAlgorithm, curve_oid: Option<&str>) -> u32 {
        let (_alg, mech) = signature_alg_and_mech(algo, curve_oid).unwrap();
        mech
    }

    /// Issue a cert from a fresh CSR and verify the issued cert's
    /// signature against the CA public key via the engine. The core
    /// correctness assertion for all three algorithms.
    fn issue_and_verify(algo: KmipAlgorithm) {
        let _g = engine_lock();
        let f = bootstrap_ca(algo);

        // Subject CSR (rcgen ECDSA — the subject key algorithm is
        // independent of the CA's signing algorithm).
        let subj_kp = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["leaf.example".into()]).unwrap();
        params.distinguished_name.push(rcgen::DnType::CommonName, "leaf");
        let csr = params.serialize_request(&subj_kp).unwrap();

        let resp = certify(
            &f.deps,
            CertifyRequest {
                certificate_request_type: Some(CertificateRequestType::Pkcs10),
                certificate_request: Some(csr.der().to_vec()),
                ..CertifyRequest::default()
            },
            "c-issue",
        )
        .unwrap();

        // The issued cert is stored + Get-able.
        let rec = f.deps.store.get(&resp.uid).unwrap().unwrap();
        assert_eq!(rec.object_type, ObjectType::Certificate);
        let issued_der = rec.certificate_value.clone().unwrap();

        // It parses as X.509.
        let issued = Certificate::from_der(&issued_der).unwrap();
        assert_eq!(issued.tbs_certificate.subject_public_key_info.algorithm.oid,
                   x509_cert::request::CertReq::from_der(csr.der()).unwrap().info.public_key.algorithm.oid,
                   "issued cert SPKI matches the CSR public key");

        // ── The real correctness assertion: the CA's signature over the
        // TBS verifies against the CA public key (in the engine). ──
        let tbs_der = issued.tbs_certificate.to_der().unwrap();
        let curve = ec_curve_oid_of(
            &Certificate::from_der(rec.certificate_value.as_ref().unwrap())
                .unwrap()
                .tbs_certificate
                .subject_public_key_info,
        );
        let mech = verify_mech(f.ca_algo, curve.as_deref());
        // Recover the raw signature for the engine verify: ECDSA must be
        // un-DER-wrapped back to r||s; RSA / ML-DSA go in as-is.
        let sig_bytes = issued.signature.as_bytes().expect("aligned BIT STRING");
        let raw_for_verify = match f.ca_algo {
            KmipAlgorithm::Ecdsa => {
                let v = EcdsaSigValue::from_der(sig_bytes).unwrap();
                let mut out = Vec::new();
                // left-pad each to 32 bytes (P-256 field width)
                let pad = |b: &[u8]| {
                    let mut p = vec![0u8; 32];
                    p[32 - b.len()..].copy_from_slice(b);
                    p
                };
                out.extend_from_slice(&pad(v.r.as_bytes()));
                out.extend_from_slice(&pad(v.s.as_bytes()));
                out
            }
            _ => sig_bytes.to_vec(),
        };
        let ok = softhsmrustv3::native::verify(
            f.session,
            f.ca_pub_handle,
            mech,
            &tbs_der,
            &raw_for_verify,
        )
        .expect("verify call");
        assert!(ok, "{:?}-issued certificate signature must verify against the CA key", algo);

        let _ = softhsmrustv3::native::session::finalize();
    }

    #[test]
    fn certify_rsa_issued_cert_verifies_against_ca() {
        issue_and_verify(KmipAlgorithm::Rsa);
    }

    #[test]
    fn certify_ecdsa_issued_cert_verifies_against_ca() {
        issue_and_verify(KmipAlgorithm::Ecdsa);
    }

    #[test]
    fn certify_ml_dsa_65_issued_cert_verifies_against_ca() {
        // The headline PQC assertion: an ML-DSA-65-signed X.509 cert,
        // issuable only via the x509-cert + engine path (rcgen can't),
        // and its FIPS-204 signature verifies in the engine.
        issue_and_verify(KmipAlgorithm::MlDsa65);
    }

    #[test]
    fn certify_supplied_public_key_no_csr() {
        let _g = engine_lock();
        let f = bootstrap_ca(KmipAlgorithm::Ecdsa);

        // Store a PublicKey object whose key_material is a valid SPKI
        // (reuse the CA's SPKI bytes — any valid SPKI works).
        let ca_cert = Certificate::from_der(
            f.deps.store.get("urn:ca-cert").unwrap().unwrap().certificate_value.as_ref().unwrap(),
        )
        .unwrap();
        let spki_der = ca_cert.tbs_certificate.subject_public_key_info.to_der().unwrap();
        f.deps
            .store
            .put(ObjectRecord {
                uid: "urn:subj-pub".into(),
                object_type: ObjectType::PublicKey,
                algorithm: KmipAlgorithm::Ecdsa,
                usage_mask: UsageMask::VERIFY,
                state: State::Active,
                name: Some("supplied-subject".into()),
                key_material: Some(spki_der),
                ..ObjectRecord::default()
            })
            .unwrap();

        let resp = certify(
            &f.deps,
            CertifyRequest { uid: Some("urn:subj-pub".into()), ..CertifyRequest::default() },
            "c-supplied",
        )
        .unwrap();

        // §6.1.6 links: cert→PublicKeyLink, pubkey→CertificateLink.
        let cert = f.deps.store.get(&resp.uid).unwrap().unwrap();
        assert_eq!(cert.links.get("PublicKeyLink").map(String::as_str), Some("urn:subj-pub"));
        let pk = f.deps.store.get("urn:subj-pub").unwrap().unwrap();
        assert_eq!(pk.links.get("CertificateLink"), Some(&resp.uid));

        let _ = softhsmrustv3::native::session::finalize();
    }

    #[test]
    fn recertify_new_window_links_and_old_retired() {
        let _g = engine_lock();
        let f = bootstrap_ca(KmipAlgorithm::Ecdsa);

        // First issue a cert from a CSR.
        let subj_kp = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["leaf.example".into()]).unwrap();
        params.distinguished_name.push(rcgen::DnType::CommonName, "renew-me");
        let csr = params.serialize_request(&subj_kp).unwrap();
        let issued = certify(
            &f.deps,
            CertifyRequest {
                certificate_request_type: Some(CertificateRequestType::Pkcs10),
                certificate_request: Some(csr.der().to_vec()),
                attributes: vec![
                    crate::kmip30::Attribute::ActivationDate(1_000),
                    crate::kmip30::Attribute::DeactivationDate(1_000 + 86_400),
                ],
                ..CertifyRequest::default()
            },
            "c-first",
        )
        .unwrap();

        // Re-certify with an Offset → new validity window + links.
        let renewed = recertify(
            &f.deps,
            ReCertifyRequest {
                uid: issued.uid.clone(),
                offset: Some(3600),
                ..ReCertifyRequest::default()
            },
            "c-renew",
        )
        .unwrap();
        assert_ne!(renewed.uid, issued.uid, "renewal mints a new UID");

        // New cert: ReplacedObjectLink → old; old: ReplacementObjectLink → new + Deactivated.
        let new_rec = f.deps.store.get(&renewed.uid).unwrap().unwrap();
        assert_eq!(new_rec.links.get("ReplacedObjectLink"), Some(&issued.uid));
        let old_rec = f.deps.store.get(&issued.uid).unwrap().unwrap();
        assert_eq!(old_rec.links.get("ReplacementObjectLink"), Some(&renewed.uid));
        assert_eq!(old_rec.state, State::Deactivated, "old cert retired per §6.1.50");

        // New activation date ≈ now + 3600s; differs from the old window.
        let new_cert = Certificate::from_der(new_rec.certificate_value.as_ref().unwrap()).unwrap();
        let old_cert = Certificate::from_der(
            f.deps.store.get(&issued.uid).unwrap().unwrap().certificate_value.as_ref().unwrap(),
        )
        .unwrap();
        assert_ne!(
            new_cert.tbs_certificate.validity.not_before.to_unix_duration(),
            old_cert.tbs_certificate.validity.not_before.to_unix_duration(),
            "Re-certify shifts the validity window"
        );

        let _ = softhsmrustv3::native::session::finalize();
    }
}
