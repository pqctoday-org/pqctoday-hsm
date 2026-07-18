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
//! ## Why not rcgen
//!
//! rcgen 0.13 can ISSUE RSA/ECDSA/Ed25519 certs, but its
//! `SignatureAlgorithm` table has no ML-DSA — it cannot emit a
//! PQC-signed cert. Since this slice REQUIRES ML-DSA issuance, every
//! algorithm goes through one uniform path: build the `TBSCertificate`
//! with [`x509_cert`] (which accepts ARBITRARY `AlgorithmIdentifier`
//! OIDs), sign the TBS DER in the engine via `native::sign`, and wrap the
//! signature into the X.509 `Certificate`. Inbound PKCS#10 CSRs are
//! parsed with [`x509_cert::request::CertReq`] and their self-signature
//! verified via `super::spki_verify::verify_with_spki` (the engine, not
//! rcgen) — for the same reason: rcgen's verifier inherits the same
//! ML-DSA gap and rejected genuinely-valid PQC-signed CSRs as
//! `Invalid CSR`. rcgen appears only in this file's own tests, as an
//! independent CSR/cert fixture generator.
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
// Pure SLH-DSA (FIPS 205), RFC 9909 §3 — NIST CSOR arc, same
// nistAlgorithms(4).sigAlgs(3) parent as ML-DSA above, contiguous from
// where it leaves off. Verified against the project's own downloaded RFC
// 9909 copy (hub `public/library/RFC_9909.html`, ASN.1 module in §3):
// `sigAlgs OBJECT IDENTIFIER ::= { nistAlgorithms 3 }`, then
// `id-slh-dsa-sha2-128s ::= { sigAlgs 20 }` counting up to
// `id-slh-dsa-shake-256f ::= { sigAlgs 31 }`. RFC 9909 §3/§4: the
// AlgorithmIdentifier `parameters` field MUST be absent for every one of
// these OIDs (same convention as ML-DSA, not RSA's explicit NULL).
const OID_SLH_DSA_SHA2_128S: &str = "2.16.840.1.101.3.4.3.20";
const OID_SLH_DSA_SHA2_128F: &str = "2.16.840.1.101.3.4.3.21";
const OID_SLH_DSA_SHA2_192S: &str = "2.16.840.1.101.3.4.3.22";
const OID_SLH_DSA_SHA2_192F: &str = "2.16.840.1.101.3.4.3.23";
const OID_SLH_DSA_SHA2_256S: &str = "2.16.840.1.101.3.4.3.24";
const OID_SLH_DSA_SHA2_256F: &str = "2.16.840.1.101.3.4.3.25";
const OID_SLH_DSA_SHAKE_128S: &str = "2.16.840.1.101.3.4.3.26";
const OID_SLH_DSA_SHAKE_128F: &str = "2.16.840.1.101.3.4.3.27";
const OID_SLH_DSA_SHAKE_192S: &str = "2.16.840.1.101.3.4.3.28";
const OID_SLH_DSA_SHAKE_192F: &str = "2.16.840.1.101.3.4.3.29";
const OID_SLH_DSA_SHAKE_256S: &str = "2.16.840.1.101.3.4.3.30";
const OID_SLH_DSA_SHAKE_256F: &str = "2.16.840.1.101.3.4.3.31";
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
pub(crate) fn ecdsa_raw_to_der(raw: &[u8]) -> Result<Vec<u8>> {
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
        KmipAlgorithm::SlhDsaSha2_128s
        | KmipAlgorithm::SlhDsaSha2_128f
        | KmipAlgorithm::SlhDsaSha2_192s
        | KmipAlgorithm::SlhDsaSha2_192f
        | KmipAlgorithm::SlhDsaSha2_256s
        | KmipAlgorithm::SlhDsaSha2_256f
        | KmipAlgorithm::SlhDsaShake128s
        | KmipAlgorithm::SlhDsaShake128f
        | KmipAlgorithm::SlhDsaShake192s
        | KmipAlgorithm::SlhDsaShake192f
        | KmipAlgorithm::SlhDsaShake256s
        | KmipAlgorithm::SlhDsaShake256f => {
            // RFC 9909 §3/§4 — ABSENT parameters, same convention as
            // ML-DSA. One sig_oid per parameter set (unlike ECDSA, the
            // parameter set is the WHOLE key identity, not derived from
            // a separate curve field) but a single engine mechanism —
            // CKM_SLH_DSA covers all 12 (CKA_PARAMETER_SET on the key
            // handle itself picks the variant, mirroring how CKM_ML_DSA
            // covers all 3 ML-DSA sizes).
            let sig_oid = match ca_algorithm {
                KmipAlgorithm::SlhDsaSha2_128s => OID_SLH_DSA_SHA2_128S,
                KmipAlgorithm::SlhDsaSha2_128f => OID_SLH_DSA_SHA2_128F,
                KmipAlgorithm::SlhDsaSha2_192s => OID_SLH_DSA_SHA2_192S,
                KmipAlgorithm::SlhDsaSha2_192f => OID_SLH_DSA_SHA2_192F,
                KmipAlgorithm::SlhDsaSha2_256s => OID_SLH_DSA_SHA2_256S,
                KmipAlgorithm::SlhDsaSha2_256f => OID_SLH_DSA_SHA2_256F,
                KmipAlgorithm::SlhDsaShake128s => OID_SLH_DSA_SHAKE_128S,
                KmipAlgorithm::SlhDsaShake128f => OID_SLH_DSA_SHAKE_128F,
                KmipAlgorithm::SlhDsaShake192s => OID_SLH_DSA_SHAKE_192S,
                KmipAlgorithm::SlhDsaShake192f => OID_SLH_DSA_SHAKE_192F,
                KmipAlgorithm::SlhDsaShake256s => OID_SLH_DSA_SHAKE_256S,
                _ => OID_SLH_DSA_SHAKE_256F,
            };
            (
                AlgorithmIdentifierOwned { oid: oid(sig_oid), parameters: None },
                c::CKM_SLH_DSA,
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

/// How to sign a TBSCertificate for the designated CA. `Single` is every
/// algorithm this port supported before composite work — one engine key,
/// one mechanism, unchanged. `Composite` is a LAMPS draft-19 composite:
/// two engine keys (the ML-DSA half's `CKA_ID` is the private record's
/// own `pkcs11_cka_id`; the classical half's lives in
/// `pkcs11_cka_id_secondary` — the SAME "two engine keys, one KMIP
/// object" field the K6 hybrid KEMs already use, not a new store column),
/// signed independently over the SAME message representative and
/// concatenated per draft-19 §4.3.
enum SigningPlan {
    Single { signature_alg: AlgorithmIdentifierOwned, mechanism: u32 },
    Composite { signature_alg: AlgorithmIdentifierOwned, profile: &'static super::composite_sig::CompositeSigProfile },
}

impl SigningPlan {
    fn signature_alg(&self) -> AlgorithmIdentifierOwned {
        match self {
            SigningPlan::Single { signature_alg, .. } => signature_alg.clone(),
            SigningPlan::Composite { signature_alg, .. } => signature_alg.clone(),
        }
    }
}

/// The CA's resolved signing context: the engine handle(s), the X.509
/// signature AlgorithmIdentifier, the signing plan, and the issuer DN
/// (from the CA certificate's subject).
struct CaContext {
    private_uid: String,
    plan: SigningPlan,
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

    let plan = match super::composite_sig::profile_for(private_record.algorithm) {
        Some(profile) => {
            let oid = der::oid::ObjectIdentifier::from_str(profile.oid).expect("static OID");
            SigningPlan::Composite {
                signature_alg: AlgorithmIdentifierOwned { oid, parameters: None },
                profile,
            }
        }
        None => {
            let curve_oid = ec_curve_oid_of(&ca_cert.tbs_certificate.subject_public_key_info);
            let (signature_alg, mechanism) =
                signature_alg_and_mech(private_record.algorithm, curve_oid.as_deref())?;
            SigningPlan::Single { signature_alg, mechanism }
        }
    };

    Ok(CaContext {
        private_uid: private_key_uid,
        plan,
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
            parse_pkcs10_csr(deps, op, csr_bytes)
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
            // WP-R/R1 — `CreateKeyPair` never populates `key_material` for
            // a non-hybrid-KEM PublicKey (its real SPKI lives only in the
            // engine; confirmed by reading `create_key_pair.rs` directly).
            // Try the store cache first (respects a `Register`'d/imported
            // key's client-supplied bytes, unchanged from before); on a
            // miss, fall back to a LIVE engine lookup instead of failing a
            // key this server itself just generated moments ago — mirrors
            // `bootstrap_ca_certificate`'s existing pattern exactly (see
            // `live_public_key_spki` below).
            //
            // WP-C6 — a hybrid-KEM PublicKey's `key_material` (when
            // present) is the raw draft-17 wire share
            // (`mlkemPK || tradPK`), NOT an SPKI DER — the SAME bytes
            // `Encapsulate` reads directly, so that storage format can't
            // change. Wrap it into a composite-KEM SPKI here, at
            // Certify-read-time only, instead of DER-parsing it as-is.
            let owned_spki_der;
            let spki_der: &[u8] = if let Some(hybrid) = rec.algorithm.hybrid_kem() {
                let wire_share = rec.key_material.as_deref().ok_or_else(|| {
                    KmipError::failed(
                        ResultReason::KeyValueNotPresent,
                        format!("{op}: hybrid-KEM PublicKey {uid:?} has no cached wire-share material"),
                    )
                })?;
                owned_spki_der = super::composite_kem::wrap_composite_kem_spki(hybrid, wire_share)?;
                &owned_spki_der
            } else {
                match rec.key_material.as_deref() {
                    Some(bytes) => bytes,
                    None => {
                        let session = deps.engine_session.ok_or_else(|| {
                            KmipError::failed(
                                ResultReason::KeyValueNotPresent,
                                format!(
                                    "{op}: PublicKey {uid:?} has no SubjectPublicKeyInfo DER on \
                                     record and no engine session to look it up live"
                                ),
                            )
                        })?;
                        owned_spki_der = live_public_key_spki(session, &rec.pkcs11_cka_id, uid)?;
                        &owned_spki_der
                    }
                }
            };
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

/// Resolve a PublicKey object's real SubjectPublicKeyInfo DER directly
/// from the engine, given its PKCS#11 `CKA_ID` — the live counterpart of
/// a stored `ObjectRecord`'s (possibly absent) `key_material` cache.
///
/// WP-R/R1 (cert-ops plan revision): shared by `resolve_subject`'s
/// stored-PublicKey-UID path (a `CreateKeyPair`-generated key, whose
/// `key_material` the store never caches) and `bootstrap_ca_certificate`
/// (a `PrivateKey` UID's paired public half) — both need "the real SPKI
/// bytes for a public key the engine holds, regardless of what the store
/// happens to have cached," and this is the one place that logic lives
/// now instead of being duplicated.
fn live_public_key_spki(session: u32, cka_id: &[u8], not_found_context: &str) -> Result<Vec<u8>> {
    use softhsmrustv3::constants as c;
    let pub_h = super::helpers::find_handle_for_object(session, cka_id, ObjectType::PublicKey)
        .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "live_public_key_spki:find"))?
        .ok_or_else(|| KmipError::object_not_found(not_found_context))?;
    softhsmrustv3::native::get_attribute(session, pub_h, c::CKA_PUBLIC_KEY_INFO).ok_or_else(|| {
        KmipError::failed(
            ResultReason::KeyValueNotPresent,
            format!("{not_found_context}: public key has no CKA_PUBLIC_KEY_INFO in the engine"),
        )
    })
}

/// The composite counterpart of [`live_public_key_spki`]: read BOTH
/// component public keys live from the engine (same `CKA_ID`-keyed
/// lookup, one call per half) and assemble the draft-19 §4.1 composite
/// SubjectPublicKeyInfo — `subjectPublicKey := mldsaPK || classicalPK`
/// (plain concatenation of the RAW key bytes, each half's own
/// AlgorithmIdentifier wrapper stripped), tagged with the profile's
/// composite OID. Mirrors `certBuilder.ts`'s `buildCompositeCertDraft19`
/// exactly (`compositeKeyBytes.set(mldsaPubKey, 0); .set(classicalPubKey,
/// mldsaPubKey.length)`).
pub(crate) fn live_composite_public_key_spki(
    session: u32,
    mldsa_cka_id: &[u8],
    classical_cka_id: &[u8],
    profile: &super::composite_sig::CompositeSigProfile,
    not_found_context: &str,
) -> Result<SubjectPublicKeyInfoOwned> {
    let mldsa_spki_der = live_public_key_spki(session, mldsa_cka_id, not_found_context)?;
    let classical_spki_der = live_public_key_spki(session, classical_cka_id, not_found_context)?;
    let mldsa_spki = SubjectPublicKeyInfoOwned::from_der(&mldsa_spki_der).map_err(|e| {
        KmipError::failed(ResultReason::GeneralFailure, format!("{not_found_context}: ML-DSA SPKI DER unparseable: {e}"))
    })?;
    let classical_spki = SubjectPublicKeyInfoOwned::from_der(&classical_spki_der).map_err(|e| {
        KmipError::failed(ResultReason::GeneralFailure, format!("{not_found_context}: classical SPKI DER unparseable: {e}"))
    })?;
    let mldsa_raw = mldsa_spki.subject_public_key.raw_bytes();
    let classical_raw = classical_spki.subject_public_key.raw_bytes();

    let mut composite_key_bytes = Vec::with_capacity(mldsa_raw.len() + classical_raw.len());
    composite_key_bytes.extend_from_slice(mldsa_raw);
    composite_key_bytes.extend_from_slice(classical_raw);

    let oid = der::oid::ObjectIdentifier::from_str(profile.oid).expect("static OID");
    Ok(SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned { oid, parameters: None },
        subject_public_key: BitString::from_bytes(&composite_key_bytes).map_err(der_err)?,
    })
}

/// Parse a PKCS#10 CSR via `x509-cert` (subject DN + SPKI) and verify its
/// self-signature via the engine (`Invalid CSR` on a bad or unverifiable
/// signature) — `super::spki_verify::verify_with_spki` on the CSR's own
/// `CertReqInfo` DER against its own `signature`/`algorithm` (RFC 2986
/// §4: "the CertificationRequestInfo ... is authenticated by the
/// subject's private key").
///
/// Replaces the earlier rcgen-backed check (`rcgen::
/// CertificateSigningRequestParams::from_der`): rcgen's `SignatureAlgorithm`
/// table has no ML-DSA (or any PQC algorithm), so a self-signed PQC CSR
/// was rejected as `Invalid CSR` even though the signature was genuinely
/// valid — an artifact of the checker's coverage, not the CSR. Going
/// through the same engine-backed verifier Certify/Validate use for
/// every other signature check removes that gap: any algorithm
/// `verify_with_spki` supports (RSA/ECDSA/ML-DSA/Ed25519) is now
/// checkable, PQC included.
fn parse_pkcs10_csr(deps: &Deps, op: &str, csr: &[u8]) -> Result<SubjectInputs> {
    let req = x509_cert::request::CertReq::from_der(csr).map_err(|e| {
        KmipError::invalid_csr(format!("{op}: PKCS#10 CSR DER unparseable: {e}"))
    })?;
    let signed_bytes = req.info.to_der().map_err(der_err)?;
    let verdict = super::spki_verify::verify_with_spki(
        deps,
        &req.info.public_key,
        &req.algorithm,
        &signed_bytes,
        req.signature.raw_bytes(),
    )?;
    match verdict {
        super::spki_verify::SpkiVerdict::Valid => {}
        super::spki_verify::SpkiVerdict::Invalid => {
            return Err(KmipError::invalid_csr(format!("{op}: CSR self-signature does not verify")));
        }
        super::spki_verify::SpkiVerdict::UnsupportedAlgorithm => {
            return Err(KmipError::invalid_csr(format!(
                "{op}: CSR signature algorithm {} has no verify mechanism — cannot confirm self-signature",
                req.algorithm.oid
            )));
        }
    }
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
        signature: ca.plan.signature_alg(),
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
    // For `SigningPlan::Composite`, `sign_tbs_in_engine` already returns
    // the FULLY ASSEMBLED `mldsaSig || classicalSig` bytes (including the
    // classical half's own DER conversion where needed) — the match below
    // correctly passes composite algorithms through unchanged (they're
    // never `KmipAlgorithm::Ecdsa`), same as it already does for RSA/
    // ML-DSA/SLH-DSA today.
    let raw_sig = sign_tbs_in_engine(deps, op, correlation_id, ca, &tbs_der)?;

    // ── X.509 signature-format conversion ────────────────────────────
    let signature_bytes = match ca.private_record.algorithm {
        KmipAlgorithm::Ecdsa => ecdsa_raw_to_der(&raw_sig)?,
        // RSA PKCS#1 v1.5, ML-DSA FIPS-204, and composite (already
        // fully assembled) signatures go in as-is.
        _ => raw_sig,
    };

    let cert = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: ca.plan.signature_alg(),
        signature: BitString::from_bytes(&signature_bytes).map_err(der_err)?,
    };
    cert.to_der().map_err(der_err)
}

/// Sign the TBS DER in the engine with the CA private key. Falls back to
/// a deterministic placeholder when no engine session is wired (unit
/// tests) — same convention as `ops::sign`. The placeholder path is
/// intentionally single-algorithm-only: a composite CA private key
/// cannot exist without a real engine session in the first place (its
/// two component keys are always generated in the engine, same as the
/// K6 hybrid KEMs — see WP-C5), so a composite `ca.plan` reaching this
/// function with `deps.engine_session = None` would be a caller bug, not
/// a supported test surface.
fn sign_tbs_in_engine(
    deps: &Deps,
    op: &str,
    correlation_id: &str,
    ca: &CaContext,
    tbs_der: &[u8],
) -> Result<Vec<u8>> {
    match deps.engine_session {
        Some(session) => sign_tbs_with_plan(deps, session, op, correlation_id, &ca.plan, &ca.private_record, &ca.private_uid, tbs_der),
        None => {
            // S-2 hardening: NO engine session ⇒ the CA private key is
            // unavailable, so we cannot produce a real certificate signature.
            // Production MUST fail rather than emit a SHA-256 stand-in that
            // looks like a signed cert but will never verify.
            #[cfg(not(test))]
            {
                return Err(KmipError::failed(
                    ResultReason::CryptographicFailure,
                    "no engine session — cannot sign certificate (CA key unavailable)",
                ));
            }
            #[cfg(test)]
            {
                let mechanism = match &ca.plan {
                    SigningPlan::Single { mechanism, .. } => *mechanism,
                    SigningPlan::Composite { .. } => {
                        return Err(KmipError::failed(
                            ResultReason::CryptographicFailure,
                            "sign_tbs_in_engine: composite CA reached the no-engine-session \
                             test placeholder — composite keys always require a real engine \
                             session (see this function's doc comment)",
                        ));
                    }
                };
                super::helpers::emit_pkcs11(
                    deps,
                    correlation_id,
                    "soft::placeholder_ca_sign",
                    Some(mechanism),
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
}

/// Sign `tbs_der` per `plan` — one engine key (existing single-algorithm
/// path, unchanged behavior) or a LAMPS composite (two engine keys, M'
/// construction, concatenated result per draft-19 §4.3). Shared by
/// `sign_tbs_in_engine` (Certify/Re-certify) and
/// `bootstrap_ca_certificate` (self-signed CA root) so the composite
/// signing logic exists in exactly one place, not duplicated per caller.
fn sign_tbs_with_plan(
    deps: &Deps,
    session: u32,
    op: &str,
    correlation_id: &str,
    plan: &SigningPlan,
    private_record: &ObjectRecord,
    private_uid: &str,
    tbs_der: &[u8],
) -> Result<Vec<u8>> {
    match plan {
        SigningPlan::Single { mechanism, .. } => {
            let handle = super::helpers::find_handle_for_object(
                session,
                &private_record.pkcs11_cka_id,
                ObjectType::PrivateKey,
            )
            .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, &format!("{op}:find")))?
            .ok_or_else(|| KmipError::object_not_found(private_uid))?;
            let r = softhsmrustv3::native::sign(session, handle, *mechanism, tbs_der);
            super::helpers::emit_pkcs11_result(deps, correlation_id, "native::sign(CA)", Some(*mechanism), &r);
            r.map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, op))
        }
        SigningPlan::Composite { profile, .. } => {
            let mldsa_handle = super::helpers::find_handle_for_object(
                session,
                &private_record.pkcs11_cka_id,
                ObjectType::PrivateKey,
            )
            .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, &format!("{op}:find-mldsa")))?
            .ok_or_else(|| KmipError::object_not_found(private_uid))?;
            let classical_cka_id = private_record.pkcs11_cka_id_secondary.as_deref().ok_or_else(|| {
                KmipError::failed(
                    ResultReason::GeneralFailure,
                    format!("{op}: composite CA {private_uid:?} has no secondary (classical) CKA_ID"),
                )
            })?;
            let classical_handle = super::helpers::find_handle_for_object(
                session,
                classical_cka_id,
                ObjectType::PrivateKey,
            )
            .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, &format!("{op}:find-classical")))?
            .ok_or_else(|| KmipError::object_not_found(private_uid))?;

            // Empty application context — no KMIP request surface for
            // composite Certify carries one yet (matches how the plain
            // `certify`/`bootstrap_ca_certificate` paths take no extra
            // signing parameters today either).
            let mprime = super::composite_sig::build_message_representative(profile, tbs_der, &[])?;

            let mldsa_mech = softhsmrustv3::constants::CKM_ML_DSA;
            let mldsa_sig = softhsmrustv3::native::sign_pqc(
                session,
                mldsa_handle,
                mldsa_mech,
                &mprime,
                profile.signature_label.as_bytes(),
                false, // deterministic — hedged, matching this engine's
                       // established ML-DSA default (cert-ops plan WP6-a).
                false, // internal
                false, // external_mu
                None,  // random — engine's own RNG hedge.
            );
            super::helpers::emit_pkcs11_result(deps, correlation_id, "native::sign_pqc(CA-composite-mldsa)", Some(mldsa_mech), &mldsa_sig);
            let mldsa_sig = mldsa_sig.map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, op))?;
            if mldsa_sig.len() != profile.mldsa_sig_bytes {
                return Err(KmipError::failed(
                    ResultReason::CryptographicFailure,
                    format!(
                        "{op}: engine returned a {}-byte ML-DSA signature for {}; FIPS 204 \
                         expects exactly {} — refusing to assemble a malformed composite \
                         signature",
                        mldsa_sig.len(),
                        profile.label,
                        profile.mldsa_sig_bytes
                    ),
                ));
            }

            let classical_raw =
                softhsmrustv3::native::sign(session, classical_handle, profile.classical_sign_mech, &mprime);
            super::helpers::emit_pkcs11_result(
                deps,
                correlation_id,
                "native::sign(CA-composite-classical)",
                Some(profile.classical_sign_mech),
                &classical_raw,
            );
            let classical_raw = classical_raw.map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, op))?;
            // The classical half keeps its own conventional X.509 wire
            // form inside the composite bytes (RFC 3279 §2.2.3 DER for
            // ECDSA; RSA-PSS signatures have no raw-vs-DER distinction —
            // same conversion rule `issue_certificate`'s single-algorithm
            // path already applies, reused here rather than reinvented.
            let classical_final = if profile.classical_sign_mech == softhsmrustv3::constants::CKM_ECDSA_SHA512 {
                ecdsa_raw_to_der(&classical_raw)?
            } else {
                classical_raw
            };

            let mut out = Vec::with_capacity(mldsa_sig.len() + classical_final.len());
            out.extend_from_slice(&mldsa_sig);
            out.extend_from_slice(&classical_final);
            Ok(out)
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
    // Resolve the signing plan + public SPKI. Composite CAs read BOTH
    // component public keys live from the engine and assemble a
    // composite SPKI; every other algorithm keeps the exact WP-R/R1
    // single-key live-lookup path `resolve_subject` also uses — same
    // "read this key's real SPKI off the engine" need either way.
    let plan = match super::composite_sig::profile_for(priv_rec.algorithm) {
        Some(profile) => {
            let oid = der::oid::ObjectIdentifier::from_str(profile.oid).expect("static OID");
            SigningPlan::Composite {
                signature_alg: AlgorithmIdentifierOwned { oid, parameters: None },
                profile,
            }
        }
        None => {
            let spki_der = live_public_key_spki(session, &priv_rec.pkcs11_cka_id, private_key_uid)?;
            let spki = SubjectPublicKeyInfoOwned::from_der(&spki_der).map_err(|e| {
                KmipError::failed(ResultReason::GeneralFailure, format!("CA SPKI DER unparseable: {e}"))
            })?;
            let curve = ec_curve_oid_of(&spki);
            let (signature_alg, mechanism) = signature_alg_and_mech(priv_rec.algorithm, curve.as_deref())?;
            SigningPlan::Single { signature_alg, mechanism }
        }
    };
    let spki = match &plan {
        SigningPlan::Composite { profile, .. } => {
            let classical_cka_id = priv_rec.pkcs11_cka_id_secondary.as_deref().ok_or_else(|| {
                KmipError::failed(
                    ResultReason::GeneralFailure,
                    format!("{private_key_uid:?}: composite CA has no secondary (classical) CKA_ID"),
                )
            })?;
            live_composite_public_key_spki(session, &priv_rec.pkcs11_cka_id, classical_cka_id, profile, private_key_uid)?
        }
        SigningPlan::Single { .. } => {
            let spki_der = live_public_key_spki(session, &priv_rec.pkcs11_cka_id, private_key_uid)?;
            SubjectPublicKeyInfoOwned::from_der(&spki_der).map_err(|e| {
                KmipError::failed(ResultReason::GeneralFailure, format!("CA SPKI DER unparseable: {e}"))
            })?
        }
    };

    let name = Name::from_str(&format!("CN={subject_cn}"))
        .map_err(|e| KmipError::invalid_field(format!("bad CA subject CN: {e}")))?;
    let now = OffsetDateTime::now_utc();
    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&next_serial()).map_err(der_err)?,
        signature: plan.signature_alg(),
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
    let raw = sign_tbs_with_plan(
        deps, session, "Bootstrap-CA", certificate_uid, &plan, &priv_rec, private_key_uid, &tbs_der,
    )?;
    let sig = match priv_rec.algorithm {
        KmipAlgorithm::Ecdsa => ecdsa_raw_to_der(&raw)?,
        // RSA/ML-DSA/SLH-DSA go in as-is; composite is already fully
        // assembled by `sign_tbs_with_plan` (never `KmipAlgorithm::Ecdsa`).
        _ => raw,
    };
    let cert = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: plan.signature_alg(),
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
        // Same CKA_ID as the CA key pair — see store_certificate's doc
        // comment on why (cert↔key matching, and Destroy lookup).
        pkcs11_cka_id: priv_rec.pkcs11_cka_id.clone(),
        ..ObjectRecord::default()
    })?;
    project_certificate_to_engine(
        deps,
        "bootstrap",
        "BootstrapCa",
        certificate_uid,
        &der,
        &priv_rec.pkcs11_cka_id,
        softhsmrustv3::constants::CK_CERTIFICATE_CATEGORY_AUTHORITY,
    );
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
        correlation_id,
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
        parse_pkcs10_csr(deps, "Re-certify", csr)
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

    // WP-3 remediation — `store_certificate` below reuses the linked
    // public key's CKA_ID for the new certificate (so a PKCS#11 client can
    // match cert-to-key), which is the SAME CKA_ID `existing`'s engine
    // object already carries. Destroy that old engine object now, BEFORE
    // the new one is created, so the two never coexist: once both share a
    // CKA_ID, `find_handle_for_object`'s class-aware lookup can no longer
    // tell them apart (it disambiguates across classes — pub/priv/cert —
    // not within one), so any later Destroy(old_uid) could resolve to
    // whichever the engine's HashMap iterates first, including the new,
    // still-active certificate. Best-effort: if the handle is already
    // gone, proceed anyway — the KMIP-side lifecycle transition below is
    // authoritative regardless.
    if let Some(session) = deps.engine_session {
        if let Ok(Some(handle)) = super::helpers::find_handle_for_object(
            session, &existing.pkcs11_cka_id, existing.object_type,
        ) {
            let r = softhsmrustv3::native::destroy_object(session, handle);
            super::helpers::emit_pkcs11_result(
                deps,
                correlation_id,
                "native::destroy_object(superseded certificate)",
                None,
                &r,
            );
        }
    }

    // Store the new cert with a Replaced link → existing; carry the
    // existing cert's Name (§6.1.50: the new cert takes over the Name).
    let new_uid = store_certificate(
        deps,
        correlation_id,
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
    // WP-3 remediation — the old record's engine object was just destroyed
    // above, and `store_certificate` may have reused its CKA_ID for the
    // NEW certificate (when linked to the same public key). Clear it here
    // so any future CKA_ID-based engine lookup against this now-retired
    // record (Destroy, Revoke, …) resolves to nothing instead of
    // colliding with — and potentially tearing down — the new
    // certificate's engine object, which now legitimately owns that
    // CKA_ID. The KMIP store record itself (certificate_value, links,
    // state) remains fully intact and Get/GetAttributes-able regardless.
    existing_mut.pkcs11_cka_id = Vec::new();
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
    correlation_id: &str,
    cert_der: &[u8],
    not_before: OffsetDateTime,
    not_after: Option<OffsetDateTime>,
    public_key_uid: Option<&str>,
    replaced_uid: Option<&str>,
    name: Option<String>,
) -> Result<String> {
    let uid = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    let now = OffsetDateTime::now_utc();

    let mut links = std::collections::HashMap::new();
    let mut linked_cka_id: Option<Vec<u8>> = None;
    if let Some(pk) = public_key_uid {
        // §6.1.6: "For the generated certificate, the server SHALL create
        // a Public Key Link attribute pointing to the Public Key."
        links.insert("PublicKeyLink".to_string(), pk.to_string());
        if let Ok(Some(pk_rec)) = deps.store.get(pk) {
            if !pk_rec.pkcs11_cka_id.is_empty() {
                linked_cka_id = Some(pk_rec.pkcs11_cka_id.clone());
            }
        }
    }
    if let Some(replaced) = replaced_uid {
        links.insert("ReplacedObjectLink".to_string(), replaced.to_string());
    }

    // PKCS#11 v3.2 §4.6.3 CKA_ID — reuse the linked key pair's CKA_ID when
    // known (this is what lets a strongSwan-style consumer match a
    // certificate to its private key), else a fresh one so the engine
    // projection is still independently addressable and destroyable.
    let cka_id = linked_cka_id.unwrap_or_else(|| uuid::Uuid::new_v4().as_bytes().to_vec());

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
        // WP7-d (cert-ops plan) — was a direct `sha2::Sha256::digest`
        // call; the §11 Digest attribute is still a hash (a crypto
        // primitive per this crate's invariant), so it goes through
        // the engine like everything else, not a local crypto crate.
        digest_value: Some(
            softhsmrustv3::native::digest(softhsmrustv3::constants::CKM_SHA256, cert_der)
                .map_err(|rv| super::helpers::ck_rv_to_kmip_error(rv, "store_certificate:digest"))?,
        ),
        // Recorded so Destroy can find (and remove) the engine projection
        // below by the same CKA_ID later — see ops::destroy (#141).
        pkcs11_cka_id: cka_id.clone(),
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

    project_certificate_to_engine(
        deps,
        correlation_id,
        "Certify",
        &uid,
        cert_der,
        &cka_id,
        softhsmrustv3::constants::CK_CERTIFICATE_CATEGORY_TOKEN_USER,
    );

    Ok(uid)
}

/// PKCS#11 v3.2 §4.6 — mirror a certificate onto the engine as a
/// `CKO_CERTIFICATE` object, so a raw PKCS#11 client (strongSwan, the
/// OpenSSL provider) can find what KMIP issued/registered. KMIP remains
/// authoritative for the certificate's lifecycle; this is a best-effort
/// projection — a failure here doesn't fail the KMIP operation (same
/// posture as the WP-A `CKA_ALLOWED_MECHANISMS` auto-restrict), since the
/// certificate is already correctly and durably stored in the KMIP record
/// either way. No engine session (e.g. crate unit tests) is a silent,
/// unaudited no-op — the common, expected case, not worth an audit event.
///
/// Moved to `cert_projection.rs` (2026-07) — this module is native-only, but
/// `register_import_export.rs` also needs to call this from a wasm32 build.
pub(crate) use super::cert_projection::project_certificate_to_engine;

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
pub(crate) mod tests {
    use super::*;
    use crate::auditlog::RingSink;
    use crate::server::auth::AuthContext;
    use crate::store::MemoryStore;
    use std::sync::Arc;

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

    /// Serialise engine-touching tests. Shared crate-wide (not a lock
    /// private to this file) — see `ops::helpers::engine_lock`'s doc for
    /// why a per-file lock isn't enough once more than one file's tests
    /// touch a real engine session (`spki_verify.rs` since WP1).
    use super::super::helpers::engine_lock;

    /// Generate a CA keypair of `algo` in the engine, read its SPKI, build
    /// a self-signed CA certificate (TBS signed in the engine), store the
    /// CA private key + CA cert, and hand back Deps designated with that
    /// CA. Returns the Deps plus the engine session + CA public handle so
    /// tests can verify issued signatures directly.
    // `pub(crate)` (not private) — WP-R/R2's Register test needs a real,
    // designated CA to Certify against, and this fixture is the one place
    // that setup lives; reusing it (instead of a second copy in
    // register_import_export.rs's test module) is the point.
    pub(crate) struct CaFixture {
        pub(crate) deps: Deps,
        session: u32,
        ca_pub_handle: u32,
        ca_algo: KmipAlgorithm,
    }

    pub(crate) fn bootstrap_ca(algo: KmipAlgorithm) -> CaFixture {
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
            slh @ (KmipAlgorithm::SlhDsaSha2_128s
            | KmipAlgorithm::SlhDsaSha2_128f
            | KmipAlgorithm::SlhDsaSha2_192s
            | KmipAlgorithm::SlhDsaSha2_192f
            | KmipAlgorithm::SlhDsaSha2_256s
            | KmipAlgorithm::SlhDsaSha2_256f
            | KmipAlgorithm::SlhDsaShake128s
            | KmipAlgorithm::SlhDsaShake128f
            | KmipAlgorithm::SlhDsaShake192s
            | KmipAlgorithm::SlhDsaShake192f
            | KmipAlgorithm::SlhDsaShake256s
            | KmipAlgorithm::SlhDsaShake256f) => {
                let param_set = super::super::helpers::native_parameter_set(slh)
                    .expect("every SLH-DSA KmipAlgorithm has a CKP_SLH_DSA_* mapping");
                native::generate_slh_dsa_keypair(sess, param_set, &cka_id, "ca-slhdsa")
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

        // WP6-a (cert-ops plan revision) — structural parity fields: not
        // byte-identical (serial + timestamp are wall-clock, ECDSA/ML-DSA/
        // SLH-DSA signatures are randomized by this engine's default —
        // confirmed empirically, see plan §"WP6-a"), but every field that
        // ISN'T inherently random must be pinned here so a native run and
        // a wasm (pkg_node) run of the identical sequence can each assert
        // the same facts independently. Deliberately NOT asserting serial
        // number, timestamps, or raw signature bytes.
        assert_eq!(
            issued.tbs_certificate.issuer.to_string(),
            "CN=PQC Test CA",
            "issuer DN must be the CA's own subject DN"
        );
        assert_eq!(
            issued.tbs_certificate.subject.to_string(),
            "CN=leaf",
            "subject DN must match the CSR"
        );
        let not_before: OffsetDateTime =
            std::time::SystemTime::from(issued.tbs_certificate.validity.not_before).into();
        let not_after: OffsetDateTime =
            std::time::SystemTime::from(issued.tbs_certificate.validity.not_after).into();
        assert_eq!(
            (not_after - not_before).whole_days(),
            365,
            "default validity window WIDTH (not the absolute stamps) is 365 days"
        );
        assert_eq!(
            issued.tbs_certificate.signature.oid,
            signature_alg_and_mech(f.ca_algo, curve.as_deref()).unwrap().0.oid,
            "TBS signature AlgorithmIdentifier OID must match what the CA algorithm resolves to"
        );
        assert!(
            issued.tbs_certificate.extensions.is_none(),
            "v0.1 leaf certs carry no extensions by design — a future change adding \
             extensions here should update this assertion deliberately"
        );

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

    /// Build a self-signed PKCS#10 CSR for `algo`, signed by a FRESH
    /// engine keypair — not rcgen, which cannot sign ML-DSA at all (no
    /// entry in its `SignatureAlgorithm` table). This is what a genuine
    /// PQC-capable client would submit: `CertReqInfo` built with
    /// `x509-cert`, signed in the engine, exactly mirroring how
    /// `issue_certificate`/`bootstrap_ca_certificate` self-sign a
    /// `TbsCertificate` — just shaped as a `CertReq` instead.
    fn build_engine_signed_csr(session: u32, algo: KmipAlgorithm, subject_cn: &str) -> Vec<u8> {
        use softhsmrustv3::constants as c;
        use softhsmrustv3::native::{self, EccCurve};
        use x509_cert::request::{CertReq, CertReqInfo, Version};

        let cka_id = format!("csr-subj-{subject_cn}").into_bytes();
        let (pub_h, prv_h) = match algo {
            KmipAlgorithm::Rsa => native::generate_rsa_keypair(session, 2048, &cka_id, "csr-rsa"),
            KmipAlgorithm::Ecdsa => {
                native::generate_ecdsa_keypair(session, EccCurve::P256, &cka_id, "csr-ec")
            }
            KmipAlgorithm::MlDsa65 => {
                native::generate_ml_dsa_keypair(session, c::CKP_ML_DSA_65, &cka_id, "csr-mldsa")
            }
            other => panic!("unsupported CSR subject algo {other:?}"),
        }
        .expect("CSR subject keygen");

        let spki_der = native::get_attribute(session, pub_h, c::CKA_PUBLIC_KEY_INFO)
            .expect("CSR subject SPKI");
        let spki = SubjectPublicKeyInfoOwned::from_der(&spki_der).unwrap();
        let curve = ec_curve_oid_of(&spki);
        let (sig_alg, mech) = signature_alg_and_mech(algo, curve.as_deref()).unwrap();

        let info = CertReqInfo {
            version: Version::V1,
            subject: Name::from_str(&format!("CN={subject_cn}")).unwrap(),
            public_key: spki,
            attributes: Default::default(),
        };
        let info_der = info.to_der().unwrap();
        let raw_sig = native::sign(session, prv_h, mech, &info_der).unwrap();
        let sig_bytes = match algo {
            KmipAlgorithm::Ecdsa => ecdsa_raw_to_der(&raw_sig).unwrap(),
            _ => raw_sig,
        };
        CertReq { info, algorithm: sig_alg, signature: BitString::from_bytes(&sig_bytes).unwrap() }
            .to_der()
            .unwrap()
    }

    /// The NEW capability this port unlocks: a self-signed ML-DSA-65 CSR
    /// — genuinely valid, but a shape rcgen/aws_lc_rs cannot even
    /// evaluate (no ML-DSA in its `SignatureAlgorithm` table) — used to
    /// be rejected as `Invalid CSR` regardless of its actual validity.
    /// The engine-backed `verify_with_spki` has no such gap.
    #[test]
    fn certify_ml_dsa_pqc_csr_is_accepted() {
        let (deps, _g) = ca_engine_deps(KmipAlgorithm::Ecdsa);
        let session = deps.engine_session.unwrap();
        let csr_der = build_engine_signed_csr(session, KmipAlgorithm::MlDsa65, "pqc-leaf");

        let resp = certify(
            &deps,
            CertifyRequest {
                certificate_request_type: Some(CertificateRequestType::Pkcs10),
                certificate_request: Some(csr_der),
                ..CertifyRequest::default()
            },
            "c-pqc-csr",
        )
        .expect("a genuinely self-signature-valid ML-DSA CSR must be accepted");
        assert_eq!(deps.store.get(&resp.uid).unwrap().unwrap().object_type, ObjectType::Certificate);
    }

    /// Negative control for the same new path: a tampered ML-DSA CSR
    /// signature must still be rejected — the new PQC coverage isn't a
    /// blanket accept.
    #[test]
    fn certify_ml_dsa_pqc_csr_tampered_is_invalid_csr() {
        let (deps, _g) = ca_engine_deps(KmipAlgorithm::Ecdsa);
        let session = deps.engine_session.unwrap();
        let mut csr_der = build_engine_signed_csr(session, KmipAlgorithm::MlDsa65, "pqc-leaf-bad");
        let n = csr_der.len();
        csr_der[n - 5] ^= 0xFF;

        let err = certify(
            &deps,
            CertifyRequest {
                certificate_request_type: Some(CertificateRequestType::Pkcs10),
                certificate_request: Some(csr_der),
                ..CertifyRequest::default()
            },
            "c-pqc-csr-bad",
        )
        .unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::InvalidCsr);
    }

    /// WP2b — every one of the 12 FIPS 205 parameter sets gets its own
    /// correct RFC 9909 OID and the shared `CKM_SLH_DSA` mechanism. A
    /// pure table check (no engine/keygen), so it's cheap enough to cover
    /// all 12 rather than sampling — the whole point is no OID typo in
    /// the table, and only an exhaustive check catches that.
    #[test]
    fn signature_alg_and_mech_covers_all_twelve_slh_dsa_parameter_sets() {
        use softhsmrustv3::constants::CKM_SLH_DSA;
        let cases = [
            (KmipAlgorithm::SlhDsaSha2_128s, OID_SLH_DSA_SHA2_128S),
            (KmipAlgorithm::SlhDsaSha2_128f, OID_SLH_DSA_SHA2_128F),
            (KmipAlgorithm::SlhDsaSha2_192s, OID_SLH_DSA_SHA2_192S),
            (KmipAlgorithm::SlhDsaSha2_192f, OID_SLH_DSA_SHA2_192F),
            (KmipAlgorithm::SlhDsaSha2_256s, OID_SLH_DSA_SHA2_256S),
            (KmipAlgorithm::SlhDsaSha2_256f, OID_SLH_DSA_SHA2_256F),
            (KmipAlgorithm::SlhDsaShake128s, OID_SLH_DSA_SHAKE_128S),
            (KmipAlgorithm::SlhDsaShake128f, OID_SLH_DSA_SHAKE_128F),
            (KmipAlgorithm::SlhDsaShake192s, OID_SLH_DSA_SHAKE_192S),
            (KmipAlgorithm::SlhDsaShake192f, OID_SLH_DSA_SHAKE_192F),
            (KmipAlgorithm::SlhDsaShake256s, OID_SLH_DSA_SHAKE_256S),
            (KmipAlgorithm::SlhDsaShake256f, OID_SLH_DSA_SHAKE_256F),
        ];
        let mut seen_oids = std::collections::HashSet::new();
        for (algo, expected_oid) in cases {
            let (alg_id, mech) = signature_alg_and_mech(algo, None).unwrap();
            assert_eq!(alg_id.oid.to_string(), expected_oid, "{algo:?}: wrong OID");
            assert!(alg_id.parameters.is_none(), "{algo:?}: RFC 9909 requires ABSENT parameters");
            assert_eq!(mech, CKM_SLH_DSA, "{algo:?}: wrong engine mechanism");
            assert!(seen_oids.insert(expected_oid), "duplicate OID {expected_oid} in the table");
        }
    }

    /// WP2b headline: a REAL SLH-DSA-signed X.509 certificate, issued via
    /// the engine (rcgen has no SLH-DSA support at all) and verified in
    /// the engine. SHA2-128f (a "fast-sign" parameter set) keeps the test
    /// affordable; the OID table itself is checked exhaustively above.
    #[test]
    fn certify_slh_dsa_128f_issued_cert_verifies_against_ca() {
        issue_and_verify(KmipAlgorithm::SlhDsaSha2_128f);
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

    /// WP-R/R1 (cert-ops plan revision) — the headline test the original
    /// draft of this work package was missing: certify a subject key
    /// straight off `CreateKeyPair`, with NO `Register` step and no
    /// manually-constructed `ObjectRecord.key_material` (unlike
    /// `certify_supplied_public_key_no_csr` above, which hand-sets
    /// `key_material` — exactly the store-cache path that does NOT exist
    /// for a real `CreateKeyPair` output). Runs for RSA, ECDSA, and
    /// ML-DSA — the three families whose Register support was assumed
    /// (not tested) to make this work; `resolve_subject`'s live-engine
    /// fallback (`live_public_key_spki`) is what actually makes it work
    /// now, for all three uniformly, without needing Register at all.
    fn certify_freshly_created_public_key_by_uid(algo: KmipAlgorithm) {
        use crate::kmip30::{Attribute, CreateKeyPairRequest};
        use crate::ops::create_key_pair::create_key_pair;

        let _g = engine_lock();
        let f = bootstrap_ca(KmipAlgorithm::Ecdsa);

        let subj = create_key_pair(
            &f.deps,
            CreateKeyPairRequest {
                common_attributes: vec![Attribute::CryptographicAlgorithm(algo)],
                private_key_attributes: vec![],
                public_key_attributes: vec![],
                seed: None,
            },
            "CreateKeyPair",
            &AuthContext::open(),
            "c-subj-fresh",
        )
        .unwrap();

        // The freshly-created PublicKey record must NOT have cached SPKI
        // bytes — if this ever starts failing, `create_key_pair.rs`
        // changed to populate `key_material` and this test should be
        // simplified (the live-engine fallback would no longer be
        // exercised by it).
        let pub_rec = f.deps.store.get(&subj.public_key_uid).unwrap().unwrap();
        assert!(
            pub_rec.key_material.is_none(),
            "{algo:?}: test assumption violated — CreateKeyPair now caches key_material; \
             this no longer exercises the live-engine fallback"
        );

        let resp = certify(
            &f.deps,
            CertifyRequest { uid: Some(subj.public_key_uid.clone()), ..CertifyRequest::default() },
            "c-fresh",
        )
        .unwrap_or_else(|e| panic!("{algo:?}: Certify a freshly-created PublicKey UID must \
                                     succeed via the live-engine SPKI fallback: {e:?}"));

        let cert = f.deps.store.get(&resp.uid).unwrap().unwrap();
        assert_eq!(cert.object_type, ObjectType::Certificate);
        assert_eq!(
            cert.links.get("PublicKeyLink").map(String::as_str),
            Some(subj.public_key_uid.as_str())
        );

        let _ = softhsmrustv3::native::session::finalize();
    }

    /// PKCS#11 v3.2 §4.6 — WP-C: Certify's issued certificate is mirrored
    /// onto the engine as a real `CKO_CERTIFICATE` object, byte-exact and
    /// independently findable — the whole point being that a raw PKCS#11
    /// client (strongSwan, the OpenSSL provider) can locate what KMIP
    /// issued without going through KMIP at all. Also exercises the
    /// destroy.rs class-aware-lookup fix: the CA's public key, private
    /// key, and certificate all share one CKA_ID (by design — that's what
    /// lets a cert be matched to its key), so a class-blind lookup would
    /// be ambiguous; this proves each resolves to ITS OWN distinct handle.
    #[test]
    fn certify_projects_engine_certificate_object_findable_by_strongswan_pattern() {
        use softhsmrustv3::constants as c;
        let _g = engine_lock();
        let f = bootstrap_ca(KmipAlgorithm::Ecdsa);

        // ── The CA's own bootstrap cert: AUTHORITY category, CKA_ID
        // shared with the CA key pair (by construction of bootstrap_ca /
        // bootstrap_ca_certificate). ──
        let ca_rec = f.deps.store.get("urn:ca-cert").unwrap().unwrap();
        let ca_der = ca_rec.certificate_value.clone().unwrap();
        assert!(!ca_rec.pkcs11_cka_id.is_empty(), "CA cert record must carry a CKA_ID");

        let ca_cert_handle = super::super::helpers::find_handle_for_object(
            f.session, &ca_rec.pkcs11_cka_id, ObjectType::Certificate,
        )
        .unwrap()
        .expect("CA certificate must be projected onto the engine");
        let ca_pub_via_lookup = super::super::helpers::find_handle_for_object(
            f.session, &ca_rec.pkcs11_cka_id, ObjectType::PublicKey,
        )
        .unwrap()
        .expect("CA public key still resolvable by the same CKA_ID");
        assert_ne!(
            ca_cert_handle, ca_pub_via_lookup,
            "cert and pubkey share a CKA_ID but must resolve to DISTINCT engine handles \
             (class-aware lookup, not the ambiguous class-blind one)"
        );

        assert_eq!(
            softhsmrustv3::native::get_attribute(f.session, ca_cert_handle, c::CKA_VALUE).unwrap(),
            ca_der,
            "engine CKA_VALUE must byte-equal the KMIP Certificate Value"
        );
        assert_eq!(
            softhsmrustv3::native::get_attribute_u32(f.session, ca_cert_handle, c::CKA_CERTIFICATE_TYPE),
            Some(c::CKC_X_509),
        );
        assert_eq!(
            softhsmrustv3::native::get_attribute_u32(f.session, ca_cert_handle, c::CKA_CERTIFICATE_CATEGORY),
            Some(c::CK_CERTIFICATE_CATEGORY_AUTHORITY),
            "the CA bootstrap path must mark its own cert AUTHORITY, not TOKEN_USER"
        );

        // ── A regularly-issued leaf cert: TOKEN_USER category, its own
        // fresh CKA_ID (no supplied public key to link to). ──
        let subj_kp = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["leaf.example".into()]).unwrap();
        params.distinguished_name.push(rcgen::DnType::CommonName, "wp-c-leaf");
        let csr = params.serialize_request(&subj_kp).unwrap();
        let resp = certify(
            &f.deps,
            CertifyRequest {
                certificate_request_type: Some(CertificateRequestType::Pkcs10),
                certificate_request: Some(csr.der().to_vec()),
                ..CertifyRequest::default()
            },
            "c-wpc-leaf",
        )
        .unwrap();
        let leaf_rec = f.deps.store.get(&resp.uid).unwrap().unwrap();
        let leaf_der = leaf_rec.certificate_value.clone().unwrap();

        let leaf_handle = super::super::helpers::find_handle_for_object(
            f.session, &leaf_rec.pkcs11_cka_id, ObjectType::Certificate,
        )
        .unwrap()
        .expect("issued leaf certificate must be projected onto the engine");
        assert_ne!(
            leaf_rec.pkcs11_cka_id, ca_rec.pkcs11_cka_id,
            "a CSR-issued leaf with no linked public key gets its own fresh CKA_ID"
        );
        assert_eq!(
            softhsmrustv3::native::get_attribute(f.session, leaf_handle, c::CKA_VALUE).unwrap(),
            leaf_der,
        );
        assert_eq!(
            softhsmrustv3::native::get_attribute_u32(f.session, leaf_handle, c::CKA_CERTIFICATE_CATEGORY),
            Some(c::CK_CERTIFICATE_CATEGORY_TOKEN_USER),
        );

        // ── KMIP Destroy on the leaf cert removes ONLY its own engine
        // object (WP-C lifecycle requirement) — the CA's cert/keys are
        // untouched. ──
        let leaf_cka_id = leaf_rec.pkcs11_cka_id.clone();
        let mut leaf_rec = leaf_rec;
        leaf_rec.state = crate::kmip30::State::Deactivated; // §3.x — Active can't go straight to Destroyed
        f.deps.store.update(leaf_rec).unwrap();
        super::super::destroy::destroy(
            &f.deps,
            crate::kmip30::DestroyRequest { uid: resp.uid.clone() },
            &AuthContext::open(),
            "c-wpc-destroy",
        )
        .unwrap();
        assert!(
            super::super::helpers::find_handle_for_object(
                f.session, &leaf_cka_id, ObjectType::Certificate,
            )
            .unwrap()
            .is_none(),
            "Destroy must remove the engine certificate projection"
        );
        // The CA cert (different CKA_ID entirely) is unaffected.
        assert!(softhsmrustv3::native::get_attribute(f.session, ca_cert_handle, c::CKA_VALUE).is_some());

        let _ = softhsmrustv3::native::session::finalize();
    }

    #[test]
    fn certify_freshly_created_rsa_public_key_by_uid() {
        certify_freshly_created_public_key_by_uid(KmipAlgorithm::Rsa);
    }

    #[test]
    fn certify_freshly_created_ecdsa_public_key_by_uid() {
        certify_freshly_created_public_key_by_uid(KmipAlgorithm::Ecdsa);
    }

    #[test]
    fn certify_freshly_created_ml_dsa_public_key_by_uid() {
        certify_freshly_created_public_key_by_uid(KmipAlgorithm::MlDsa65);
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

    /// WP-3 remediation — when the re-certified certificate is linked to a
    /// stored PublicKey (via `resolve_subject`'s uid-based path, `Certify`
    /// with no CSR), `store_certificate` reuses that key's CKA_ID for the
    /// new certificate — the SAME CKA_ID the OLD certificate's engine
    /// object already carries. Before the fix, Re-certify never destroyed
    /// the old engine object, so the engine ended up with TWO
    /// `CKO_CERTIFICATE` objects sharing one CKA_ID; because the engine's
    /// object map has no iteration-order guarantee, a later `Destroy` of
    /// the superseded UID could resolve to either one — including the new,
    /// still-Active certificate. Proves: exactly one engine object exists
    /// at the shared CKA_ID after Re-certify (the new one), and destroying
    /// the superseded UID afterward leaves it untouched.
    #[test]
    fn recertify_replaces_engine_object_sharing_linked_public_key_cka_id() {
        use softhsmrustv3::constants as c;
        use softhsmrustv3::native::{self, EccCurve};
        let _g = engine_lock();
        let f = bootstrap_ca(KmipAlgorithm::Ecdsa);

        // A leaf key pair, independent of the CA's, with its own CKA_ID —
        // stored as a KMIP PublicKey record so Certify(uid=...) can link it.
        let leaf_cka_id = b"leaf-key-id".to_vec();
        let (leaf_pub_h, _leaf_prv_h) =
            native::generate_ecdsa_keypair(f.session, EccCurve::P256, &leaf_cka_id, "leaf-ec")
                .expect("leaf keygen");
        let leaf_spki = native::get_attribute(f.session, leaf_pub_h, c::CKA_PUBLIC_KEY_INFO)
            .expect("leaf public key SPKI");
        f.deps
            .store
            .put(ObjectRecord {
                uid: "urn:leaf-pub".into(),
                object_type: ObjectType::PublicKey,
                algorithm: KmipAlgorithm::Ecdsa,
                usage_mask: UsageMask::VERIFY,
                state: State::Active,
                pkcs11_cka_id: leaf_cka_id.clone(),
                key_material: Some(leaf_spki),
                ..ObjectRecord::default()
            })
            .unwrap();

        // Certify the stored PublicKey by UID (no CSR) — links the new
        // cert to "urn:leaf-pub", so store_certificate reuses leaf_cka_id.
        let issued = certify(
            &f.deps,
            CertifyRequest { uid: Some("urn:leaf-pub".into()), ..CertifyRequest::default() },
            "c-initial",
        )
        .unwrap();
        let issued_rec = f.deps.store.get(&issued.uid).unwrap().unwrap();
        assert_eq!(
            issued_rec.pkcs11_cka_id, leaf_cka_id,
            "precondition: the issued cert must share the linked public key's CKA_ID"
        );

        let renewed = recertify(
            &f.deps,
            ReCertifyRequest { uid: issued.uid.clone(), ..ReCertifyRequest::default() },
            "c-renew",
        )
        .unwrap();
        let renewed_rec = f.deps.store.get(&renewed.uid).unwrap().unwrap();
        assert_eq!(
            renewed_rec.pkcs11_cka_id, leaf_cka_id,
            "the new cert must reuse the same CKA_ID — this is the collision precondition"
        );

        // Exactly one engine certificate object at that CKA_ID, and it's
        // the NEW certificate, not the superseded one.
        let handle = super::super::helpers::find_handle_for_object(
            f.session, &leaf_cka_id, ObjectType::Certificate,
        )
        .unwrap()
        .expect("exactly one engine certificate object must exist at the shared CKA_ID");
        let engine_der = native::get_attribute(f.session, handle, c::CKA_VALUE)
            .expect("engine certificate object must carry DER");
        assert_eq!(
            engine_der, *renewed_rec.certificate_value.as_ref().unwrap(),
            "the one live engine object must be the NEW certificate, not the superseded one"
        );

        // Destroying the OLD (already-Deactivated) cert must not remove
        // the new, still-Active one.
        super::super::destroy::destroy(
            &f.deps,
            crate::kmip30::DestroyRequest { uid: issued.uid.clone() },
            &AuthContext::open(),
            "c-destroy-old",
        )
        .unwrap();
        assert_eq!(
            native::get_attribute(f.session, handle, c::CKA_VALUE).as_deref(),
            Some(renewed_rec.certificate_value.as_ref().unwrap().as_slice()),
            "destroying the superseded certificate must not remove the new certificate's engine object"
        );

        let _ = softhsmrustv3::native::session::finalize();
    }

    // ── Composite signatures (LAMPS draft-19) ──────────────────────────────

    /// Bootstrap a composite CA (two real engine keypairs — ML-DSA half +
    /// classical half, tied to ONE PrivateKey record via `pkcs11_cka_id`
    /// / `pkcs11_cka_id_secondary`, the same two-key-one-object pattern
    /// the K6 hybrid KEMs already use) and mint its self-signed root via
    /// the production `bootstrap_ca_certificate` path — proves
    /// `SigningPlan::Composite` end to end: both component signatures
    /// independently verify against their own public keys, not just "the
    /// call didn't error."
    fn bootstrap_composite_ca_and_verify(
        profile: &'static super::super::composite_sig::CompositeSigProfile,
        algo: KmipAlgorithm,
    ) {
        use softhsmrustv3::constants as c;
        use softhsmrustv3::native::{self, session, EccCurve};
        let _g = engine_lock();
        let _ = session::finalize();
        session::init().expect("engine init");
        let sess = session::bootstrap_default_token(0, "so-pin", "user-pin", "composite-ca")
            .expect("bootstrap session");

        let mldsa_cka_id = b"composite-ca-mldsa".to_vec();
        let classical_cka_id = b"composite-ca-classical".to_vec();
        let (mldsa_pub_h, _mldsa_prv_h) =
            native::generate_ml_dsa_keypair(sess, profile.mldsa_param_set, &mldsa_cka_id, "ca-mldsa")
                .expect("ML-DSA half keygen");
        let curve = match profile.classical_ec_field_width {
            Some(32) => EccCurve::P256,
            Some(48) => EccCurve::P384,
            other => panic!("test only covers EC composite profiles, got field width {other:?}"),
        };
        let (classical_pub_h, _classical_prv_h) =
            native::generate_ecdsa_keypair(sess, curve, &classical_cka_id, "ca-classical")
                .expect("classical half keygen");

        let sink: Arc<dyn crate::auditlog::AuditSink> = Arc::new(RingSink::new(256));
        let deps = Deps::new(
            crate::policy::Engine::permissive(),
            Arc::new(MemoryStore::new()),
            sink,
            crate::ops::DepsConfig::default(),
        )
        .with_engine_session(sess)
        .with_ca_key("urn:composite-ca-priv", "urn:composite-ca-cert");

        deps.store
            .put(ObjectRecord {
                uid: "urn:composite-ca-priv".into(),
                object_type: ObjectType::PrivateKey,
                algorithm: algo,
                usage_mask: UsageMask::SIGN,
                state: State::Active,
                pkcs11_cka_id: mldsa_cka_id.clone(),
                pkcs11_cka_id_secondary: Some(classical_cka_id.clone()),
                ..ObjectRecord::default()
            })
            .unwrap();

        let der = super::bootstrap_ca_certificate(
            &deps, "urn:composite-ca-priv", "urn:composite-ca-cert", "Composite Test CA", 3650,
        )
        .expect("bootstrap composite CA cert");

        let cert = Certificate::from_der(&der).expect("composite cert parses as X.509");
        let composite_oid = der::oid::ObjectIdentifier::from_str(profile.oid).unwrap();
        assert_eq!(cert.tbs_certificate.signature.oid, composite_oid, "TBS signature OID is the composite OID");
        assert_eq!(cert.signature_algorithm.oid, composite_oid, "outer signatureAlgorithm OID is the composite OID");
        assert_eq!(
            cert.tbs_certificate.subject_public_key_info.algorithm.oid, composite_oid,
            "composite SPKI's own algorithm OID is the composite OID (no separate SPKI-vs-signature split, unlike RSA/ECDSA)"
        );

        // ── Structural: composite SPKI is exactly mldsaPub || classicalPub ──
        let mldsa_spki_der = native::get_attribute(sess, mldsa_pub_h, c::CKA_PUBLIC_KEY_INFO).unwrap();
        let mldsa_spki = SubjectPublicKeyInfoOwned::from_der(&mldsa_spki_der).unwrap();
        let mldsa_raw = mldsa_spki.subject_public_key.raw_bytes();
        let classical_spki_der = native::get_attribute(sess, classical_pub_h, c::CKA_PUBLIC_KEY_INFO).unwrap();
        let classical_spki = SubjectPublicKeyInfoOwned::from_der(&classical_spki_der).unwrap();
        let classical_raw = classical_spki.subject_public_key.raw_bytes();
        let composite_spki_raw = cert.tbs_certificate.subject_public_key_info.subject_public_key.raw_bytes();
        assert_eq!(composite_spki_raw.len(), mldsa_raw.len() + classical_raw.len());
        assert_eq!(&composite_spki_raw[..mldsa_raw.len()], mldsa_raw);
        assert_eq!(&composite_spki_raw[mldsa_raw.len()..], classical_raw);

        // ── Cryptographic: split the composite signature, verify BOTH
        // components independently against their own public keys — the
        // real proof, not just "a signature-shaped blob came back".
        let sig_bytes = cert.signature.as_bytes().expect("aligned BIT STRING");
        assert!(sig_bytes.len() > profile.mldsa_sig_bytes, "composite sig must carry a classical tail too");
        let (mldsa_sig, classical_sig_der) = sig_bytes.split_at(profile.mldsa_sig_bytes);

        let tbs_der = cert.tbs_certificate.to_der().unwrap();
        let mprime = super::super::composite_sig::build_message_representative(profile, &tbs_der, &[]).unwrap();

        native::verify_pqc(
            sess, mldsa_pub_h, c::CKM_ML_DSA, &mprime, mldsa_sig,
            profile.signature_label.as_bytes(), false, false,
        )
        .expect("ML-DSA half must independently verify against the ML-DSA public key");

        let field_width = profile.classical_ec_field_width.unwrap();
        let EcdsaSigValue { r, s } = EcdsaSigValue::from_der(classical_sig_der).expect("classical half is a valid Ecdsa-Sig-Value");
        let pad = |bytes: &[u8]| {
            let mut p = vec![0u8; field_width];
            p[field_width - bytes.len()..].copy_from_slice(bytes);
            p
        };
        let mut raw = pad(r.as_bytes());
        raw.extend(pad(s.as_bytes()));
        let ok = native::verify(sess, classical_pub_h, profile.classical_sign_mech, &mprime, &raw)
            .expect("classical verify call");
        assert!(ok, "classical half must independently verify against the classical public key");

        // A tampered ML-DSA byte must NOT verify — proves this is a real
        // check, not a call that always returns Ok/true.
        let mut tampered_mldsa = mldsa_sig.to_vec();
        let last = tampered_mldsa.len() - 1;
        tampered_mldsa[last] ^= 0xff;
        let tampered_ok = native::verify_pqc(
            sess, mldsa_pub_h, c::CKM_ML_DSA, &mprime, &tampered_mldsa,
            profile.signature_label.as_bytes(), false, false,
        );
        assert!(tampered_ok.is_err(), "a tampered ML-DSA half must not verify");

        let _ = session::finalize();
    }

    #[test]
    fn bootstrap_composite_mldsa65_ecdsa_p256_ca_both_halves_verify() {
        bootstrap_composite_ca_and_verify(
            &super::super::composite_sig::MLDSA65_ECDSA_P256_SHA512,
            KmipAlgorithm::CompositeMlDsa65EcdsaP256Sha512,
        );
    }

    #[test]
    fn bootstrap_composite_mldsa87_ecdsa_p384_ca_both_halves_verify() {
        bootstrap_composite_ca_and_verify(
            &super::super::composite_sig::MLDSA87_ECDSA_P384_SHA512,
            KmipAlgorithm::CompositeMlDsa87EcdsaP384Sha512,
        );
    }

    /// WP-C6 end to end: a hybrid-KEM key pair generated through the
    /// real `CreateKeyPair` handler (the K6 path, unchanged by this
    /// work), certified under a plain ML-DSA-65 CA — the "asymmetric
    /// pattern" `certBuilder.ts` names explicitly (KEM keys can't
    /// self-sign, so the issuer is a separate signing key). Proves
    /// `resolve_subject`'s new hybrid-KEM branch wraps the EXACT same
    /// wire-share bytes `CreateKeyPair` cached (no silent truncation or
    /// re-ordering), tags them with the verified draft-17 OID, and that
    /// the resulting certificate validates through the ordinary
    /// (unmodified) single-algorithm signature path in `validate.rs`.
    #[test]
    fn hybrid_kem_leaf_certifies_under_ml_dsa_ca_as_composite_kem() {
        use crate::kmip30::{Attribute, CreateKeyPairRequest, SignatureValidity};

        let (deps, _g) = ca_engine_deps(KmipAlgorithm::MlDsa65);

        let req = CreateKeyPairRequest {
            common_attributes: vec![Attribute::CryptographicAlgorithm(KmipAlgorithm::X25519MlKem768)],
            private_key_attributes: vec![],
            public_key_attributes: vec![],
            seed: None,
        };
        let resp = super::super::create_key_pair::create_key_pair(
            &deps, req, "CreateKeyPair:KeyAgreement", &AuthContext::open(), "corr-hybrid-leaf",
        )
        .expect("hybrid-KEM CreateKeyPair");
        let pub_record = deps.store.get(&resp.public_key_uid).unwrap().unwrap();
        let wire_share = pub_record.key_material.clone().expect("hybrid-KEM public wire share cached");
        assert_eq!(wire_share.len(), 1184 + 32, "X25519MlKem768 wire share must be mlkem768(1184) || x25519(32)");

        let certify_resp = certify(
            &deps,
            CertifyRequest {
                uid: Some(resp.public_key_uid.clone()),
                certificate_request_type: None,
                certificate_request: None,
                attributes: vec![],
            },
            "corr-certify-kem-leaf",
        )
        .expect("Certify the hybrid-KEM leaf under the ML-DSA CA");
        let leaf_cert_der = deps
            .store
            .get(&certify_resp.uid)
            .unwrap()
            .unwrap()
            .key_material
            .expect("Certify must store the issued certificate DER");

        // The stored certificate's SPKI must be the composite-KEM wrap
        // of exactly the same wire share, tagged with the draft-17 OID.
        let cert = Certificate::from_der(&leaf_cert_der).unwrap();
        let spki = &cert.tbs_certificate.subject_public_key_info;
        assert_eq!(spki.algorithm.oid.to_string(), super::super::composite_kem::MLKEM768_X25519_OID);
        assert_eq!(spki.subject_public_key.raw_bytes(), wire_share.as_slice());

        // And the whole chain validates through the ordinary
        // single-algorithm path in validate.rs — no new code exercised
        // there; confirms the composite-KEM SPKI sits correctly inside
        // an otherwise-normal, already-proven certificate.
        let ca_cert_der = deps.store.get("urn:ca-cert").unwrap().unwrap().key_material.unwrap();
        assert_eq!(
            super::super::validate::validate_chain(&deps, &[leaf_cert_der, ca_cert_der], OffsetDateTime::now_utc()),
            SignatureValidity::Valid,
            "a hybrid-KEM leaf certified by a plain ML-DSA CA must validate"
        );
    }

    /// The honest-degrade half of WP-C6: `SecP256r1MlKem768` has no
    /// verified draft-17 OID/byte-order reference (see
    /// `composite_kem.rs`'s module doc), so `Certify` must reject it
    /// with `OperationNotSupported` through the REAL request path — not
    /// just at the `composite_kem::wrap_composite_kem_spki` unit level.
    #[test]
    fn hybrid_kem_leaf_without_verified_oid_is_rejected_not_guessed() {
        use crate::kmip30::{Attribute, CreateKeyPairRequest};

        let (deps, _g) = ca_engine_deps(KmipAlgorithm::MlDsa65);

        let req = CreateKeyPairRequest {
            common_attributes: vec![Attribute::CryptographicAlgorithm(KmipAlgorithm::SecP256r1MlKem768)],
            private_key_attributes: vec![],
            public_key_attributes: vec![],
            seed: None,
        };
        let resp = super::super::create_key_pair::create_key_pair(
            &deps, req, "CreateKeyPair:KeyAgreement", &AuthContext::open(), "corr-hybrid-p256-leaf",
        )
        .expect("hybrid-KEM CreateKeyPair");

        let err = certify(
            &deps,
            CertifyRequest {
                uid: Some(resp.public_key_uid),
                certificate_request_type: None,
                certificate_request: None,
                attributes: vec![],
            },
            "corr-certify-kem-p256-leaf",
        )
        .unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::OperationNotSupported);
    }
}
