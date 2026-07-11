//! KMIP 3.0 §6.1.62 **Validate** operation — certificate-chain validation.
//!
//! > "This operation requests the server to validate a certificate chain
//! > and return information on its validity."
//!
//! Op codepoint `0x17` (verified — `Validate = 0x00000017`).
//!
//! ## KMIP design point
//!
//! Like Signature Verify, a *negative* result is **not** a KMIP error —
//! it returns a successful `Validate` response with a `Validity
//! Indicator` of `Invalid` or `Unknown`. KMIP errors (Object Not Found,
//! Invalid Object Type, …) are reserved for protocol-level failures:
//! a referenced UID that doesn't exist, or one that names a non-
//! Certificate object.
//!
//! ## Validation depth actually implemented
//!
//! The supplied `Certificate`s (inline DER) plus the DER of any
//! referenced stored Certificate objects together form one candidate
//! chain. This handler performs:
//!
//! 1. **Parse** every certificate — `x509-parser`, used here for PARSING
//!    ONLY (no `verify` feature, no `ring`/`aws-lc`; pure Rust,
//!    wasm32-clean). A certificate whose bytes don't parse makes the
//!    whole chain `Invalid`.
//! 2. **Validity-date** — each certificate must be valid at the request's
//!    `Validity Date` (or "now" when omitted, per §6.1.62). A cert that
//!    is expired / not-yet-valid at that instant → `Invalid`.
//! 3. **Chain-link + signature** — for every non-self-signed certificate
//!    in the set, find its issuer *within the supplied/stored set* by
//!    matching Issuer DN ⟷ Subject DN and verify the certificate's
//!    signature against that issuer's public key via
//!    `ops::spki_verify::verify_with_spki` — the SAME engine-backed
//!    verifier Certify's CSR check uses (WP1/WP2). A present-but-failing
//!    signature → `Invalid`.
//!
//! Since 0.14 (the pure-Rust cert-ops port) this replaced a `ring`-backed
//! `x509-parser::verify_signature` call, which only covered RSA-PKCS1v15
//! and ECDSA over SHA-256/384/512. `verify_with_spki` covers whatever the
//! engine covers — RSA, ECDSA, Ed25519, ML-DSA, and SLH-DSA chains all
//! verify now, not just classical ones.
//!
//! ### What returns `Unknown` (never a false `Valid`)
//!
//! - The chain does not terminate in a self-signed (root / trust-anchor)
//!   certificate within the supplied set — i.e. some certificate's issuer
//!   is **not present**, so the path to a trust anchor cannot be
//!   completed. The server holds no separate trust-anchor store, so it
//!   honestly cannot affirm such a chain.
//! - A signature uses an algorithm the engine has no mechanism for
//!   (`SpkiVerdict::UnsupportedAlgorithm`) — an honest "cannot evaluate",
//!   not an actually-bad signature.
//! - No engine session is wired at all — same honest-degrade, not a
//!   silent pass.
//!
//! `Valid` is returned **only** when every certificate parsed, every
//! certificate is within its validity window at the requested instant,
//! every non-root link's signature verified against an issuer in the
//! set, and the chain terminates in a self-signed certificate present in
//! the set. Anything that cannot be affirmatively checked degrades to
//! `Unknown`; anything that affirmatively fails is `Invalid`.
//!
//! This is intentionally *not* a full RFC 5280 path validation (no name
//! constraints, no basicConstraints/keyUsage/EKU enforcement, no
//! revocation, no external trust store) — those would over-promise given
//! the available crates. The depth is documented here so the result is
//! honest about its limits.

use std::str::FromStr;

use ::time::OffsetDateTime;
use der::Decode;
use x509_cert::TbsCertificate;
use x509_parser::prelude::*;

use crate::error::{KmipError, Result};
use crate::kmip30::{ObjectType, SignatureValidity, ValidateRequest, ValidateResponse};

use super::deps::Deps;
use super::helpers::{emit_request, emit_success, fail_err};
use super::spki_verify::{verify_with_spki, SpkiVerdict};

pub fn validate(
    deps: &Deps,
    req: ValidateRequest,
    correlation_id: &str,
) -> Result<ValidateResponse> {
    emit_request(
        deps,
        correlation_id,
        "Validate",
        format!(
            "inline_certs={} stored_uids={} validity_date={}",
            req.certificates.len(),
            req.uids.len(),
            req.validity_date.map(|t| t.to_string()).unwrap_or_else(|| "now".into()),
        ),
    );

    // Resolve every referenced stored Certificate object to its DER.
    // ObjectNotFound when a UID is absent; InvalidObjectType when the UID
    // names a non-Certificate object — both are protocol errors per
    // §6.1.62 Table 442 (Object Not Found / Invalid Object Type).
    let mut ders: Vec<Vec<u8>> = Vec::with_capacity(req.certificates.len() + req.uids.len());
    for uid in &req.uids {
        let obj = deps.store.get(uid)?.ok_or_else(|| {
            fail_err(deps, correlation_id, "Validate", KmipError::object_not_found(uid))
        })?;
        if obj.object_type != ObjectType::Certificate {
            return Err(fail_err(
                deps,
                correlation_id,
                "Validate",
                KmipError::invalid_object_type(format!(
                    "Validate: UID {uid} is {:?}, not a Certificate",
                    obj.object_type
                )),
            ));
        }
        // WP-2 remediation — `Certify` sets both `key_material` and
        // `certificate_value` identically, but `Register` only ever sets
        // `certificate_value`; a Register-created certificate used to
        // deterministically fail Validate here regardless of whether its
        // DER was actually valid. Prefer `certificate_value` (the
        // authoritative source for a Certificate object — see `Get`/
        // `GetAttributes`), falling back to `key_material` for any
        // pre-existing record that only has the latter populated.
        match obj.certificate_value.as_ref().or(obj.key_material.as_ref()) {
            Some(der) if !der.is_empty() => ders.push(der.clone()),
            _ => {
                // A Certificate object with no stored DER cannot be
                // validated — treat as an Invalid chain rather than a
                // protocol error (the object exists and is the right type).
                emit_success(deps, correlation_id, "Validate");
                return Ok(ValidateResponse { validity: SignatureValidity::Invalid });
            }
        }
    }
    // Inline certificate DER blobs from the request.
    ders.extend(req.certificates.iter().cloned());

    // An empty chain cannot be affirmed valid (§6.1.62 validates "a
    // certificate chain"); nothing to check → Unknown.
    if ders.is_empty() {
        emit_success(deps, correlation_id, "Validate");
        return Ok(ValidateResponse { validity: SignatureValidity::Unknown });
    }

    let validity =
        validate_chain(deps, &ders, req.validity_date.unwrap_or_else(OffsetDateTime::now_utc));
    emit_success(deps, correlation_id, "Validate");
    Ok(ValidateResponse { validity })
}

/// Core chain check. See the module doc for the exact Valid/Invalid/
/// Unknown contract. Takes `deps` (unlike the pre-port version) because
/// signature verification now goes through the engine via
/// `verify_with_spki`, not a self-contained `ring` call.
pub(crate) fn validate_chain(deps: &Deps, ders: &[Vec<u8>], at: OffsetDateTime) -> SignatureValidity {
    // 1. Parse every certificate. Any parse failure → Invalid.
    let mut certs: Vec<X509Certificate> = Vec::with_capacity(ders.len());
    for der in ders {
        match X509Certificate::from_der(der) {
            Ok((_, c)) => certs.push(c),
            Err(_) => return SignatureValidity::Invalid,
        }
    }

    // 2. Validity-date window for every certificate at `at`.
    let asn1_at = match ASN1Time::from_timestamp(at.unix_timestamp()) {
        Ok(t) => t,
        Err(_) => return SignatureValidity::Unknown,
    };
    for c in &certs {
        if !c.validity().is_valid_at(asn1_at) {
            return SignatureValidity::Invalid;
        }
    }

    // 3. Chain-link + signature. For each certificate, find an issuer in
    // the set (Issuer DN == some cert's Subject DN). Self-signed certs
    // (issuer == own subject) are candidate trust anchors.
    let mut degrade_unknown = false;
    let mut saw_self_signed_anchor = false;

    for (idx, c) in certs.iter().enumerate() {
        let self_signed = c.issuer() == c.subject();

        // Locate the issuer's public key within the supplied set.
        let issuer = if self_signed {
            Some(c)
        } else {
            certs.iter().find(|cand| cand.subject() == c.issuer())
        };

        match issuer {
            Some(iss) => {
                // Verify this cert's signature against the issuer key —
                // via the engine (`verify_with_spki`), not `ring`. Build
                // the inputs from x509-parser's own parsed fields (all
                // public accessors, no re-parsing):
                //   - issuer SPKI: `SubjectPublicKeyInfo.raw` is the full
                //     RFC 5280 §4.1.2.7 SPKI DER, decoded by `spki`'s
                //     OWN parser (independent of x509-parser's).
                //   - signature AlgorithmIdentifier: rebuilt from the
                //     OID string (`Oid::to_id_string()`) — `plan_for`
                //     only reads `.oid`, so parameters need not survive
                //     the crossing.
                //   - signed bytes: `TbsCertificate: AsRef<[u8]>` — the
                //     exact raw TBS DER, not a re-encoding.
                //   - signature bytes: `BitString.data` (DER signatures
                //     are always a whole number of octets, unused_bits=0).
                let issuer_spki =
                    match spki::SubjectPublicKeyInfoOwned::from_der(iss.public_key().raw) {
                        Ok(s) => s,
                        Err(_) => {
                            degrade_unknown = true;
                            continue;
                        }
                    };
                let sig_alg_oid = match der::oid::ObjectIdentifier::from_str(
                    &c.signature_algorithm.algorithm.to_id_string(),
                ) {
                    Ok(o) => o,
                    Err(_) => {
                        degrade_unknown = true;
                        continue;
                    }
                };
                let sig_alg =
                    spki::AlgorithmIdentifierOwned { oid: sig_alg_oid, parameters: None };
                let tbs_bytes: &[u8] = c.tbs_certificate.as_ref();
                let sig_bytes: &[u8] = c.signature_value.data.as_ref();

                // LAMPS composite signatures (draft-19) need two
                // independent component verifications, not one —
                // `verify_with_spki`'s single-algorithm OID table has no
                // entry for a composite OID and would otherwise (safely,
                // just less usefully) degrade every composite chain to
                // `Unknown`. Checked by OID before falling through to the
                // ordinary single-algorithm path below, exactly the way
                // `signature_alg_and_mech`/`profile_for` are checked
                // first on the issuance side (`certify.rs::resolve_ca`).
                let verdict = match super::composite_sig::profile_for_oid(&sig_alg.oid.to_string()) {
                    Some(profile) => super::composite_sig::verify_composite_signature(
                        deps, profile, &issuer_spki, tbs_bytes, sig_bytes,
                    ),
                    None => verify_with_spki(deps, &issuer_spki, &sig_alg, tbs_bytes, sig_bytes),
                };

                match verdict {
                    Ok(SpkiVerdict::Valid) => {
                        if self_signed {
                            saw_self_signed_anchor = true;
                        }
                    }
                    Ok(SpkiVerdict::Invalid) => {
                        // A signature that affirmatively fails → Invalid.
                        return SignatureValidity::Invalid;
                    }
                    Ok(SpkiVerdict::UnsupportedAlgorithm) | Err(_) => {
                        // Unsupported algorithm, or an engine-level error
                        // (including "no session wired") — cannot affirm,
                        // so degrade rather than silently pass or fail.
                        degrade_unknown = true;
                        continue;
                    }
                }

                // Re-parse `tbs_bytes` with `x509_cert` (a second,
                // independent parser from the `x509-parser` crate this
                // loop otherwise uses) once, shared by the Catalyst and
                // Chameleon checks below — both need a fully-typed
                // `TbsCertificate` for their extension/re-encode logic,
                // not raw byte access.
                match TbsCertificate::from_der(tbs_bytes) {
                    Ok(typed_tbs) => {
                        // ITU-T X.509 (2019) §9.8 Catalyst — an OPT-IN
                        // second, fully independent signature carried in
                        // extensions 2.5.29.72/73/74 (WP-C9). The primary
                        // signature above already verified; a Catalyst
                        // cert additionally demands its alt signature
                        // verify too (AND-verdict, same discipline WP-C4
                        // uses for composite-signature's two components).
                        match super::catalyst::extract_alt_sig_fields(&typed_tbs) {
                            Ok(None) => {} // not Catalyst-shaped — nothing more to check
                            Ok(Some(fields)) => {
                                let alt_verdict = super::catalyst::tbs_minus_alt_sig_value(&typed_tbs).and_then(
                                    |tbs_minus_alt| super::catalyst::verify_alt_signature(deps, &fields, &tbs_minus_alt),
                                );
                                match alt_verdict {
                                    Ok(SpkiVerdict::Valid) => {}
                                    Ok(SpkiVerdict::Invalid) => return SignatureValidity::Invalid,
                                    Ok(SpkiVerdict::UnsupportedAlgorithm) | Err(_) => degrade_unknown = true,
                                }
                            }
                            Err(_) => degrade_unknown = true, // present-but-malformed Catalyst extensions
                        }

                        // draft-bonnell-lamps-chameleon-certs-07 — an
                        // OPT-IN "delta" certificate reconstructed from
                        // the DeltaCertificateDescriptor extension
                        // (WP-C11, validation only — see chameleon.rs's
                        // module doc for why no issuance path exists).
                        // Same "only meaningful once the primary
                        // signature above is confirmed" reasoning.
                        match super::chameleon::reconstruct_delta(&typed_tbs) {
                            Ok(None) => {} // not Chameleon-shaped — nothing more to check
                            Ok(Some(delta)) => match super::chameleon::verify_delta_signature(deps, &delta) {
                                Ok(SpkiVerdict::Valid) => {}
                                Ok(SpkiVerdict::Invalid) => return SignatureValidity::Invalid,
                                Ok(SpkiVerdict::UnsupportedAlgorithm) | Err(_) => degrade_unknown = true,
                            },
                            Err(_) => degrade_unknown = true, // present-but-malformed descriptor
                        }
                    }
                    Err(_) => degrade_unknown = true, // couldn't re-parse via x509_cert
                }

                // RFC 9763 Related Certificates — another OPT-IN
                // extension (WP-C10), same "only meaningful once the
                // primary signature above is confirmed" reasoning as
                // Catalyst: the extension's claimed hash is otherwise
                // unauthenticated, attacker-controlled content.
                let related_cert_oid = x509_parser::oid_registry::Oid::from_str(super::related_certs::RELATED_CERT_OID)
                    .expect("static OID");
                match c.get_extension_unique(&related_cert_oid) {
                    Ok(None) => {} // no RelatedCertificate extension — nothing to check
                    Ok(Some(ext)) => match super::related_certs::extract_related_cert_claim(ext.value) {
                        Ok((hash_alg_oid, claimed_hash)) => match super::related_certs::resolve_related_cert(
                            deps, &hash_alg_oid, &claimed_hash, ders, idx,
                        ) {
                            Ok(super::related_certs::RelatedCertVerdict::Bound) => {}
                            Ok(super::related_certs::RelatedCertVerdict::Unknown) => degrade_unknown = true,
                            Ok(super::related_certs::RelatedCertVerdict::Invalid) => {
                                return SignatureValidity::Invalid
                            }
                            Err(_) => degrade_unknown = true,
                        },
                        Err(_) => degrade_unknown = true, // present-but-malformed extension
                    },
                    Err(_) => degrade_unknown = true, // multiple instances — malformed
                }
            }
            None => {
                // The issuer is not in the supplied/stored set, so the
                // path to a trust anchor cannot be completed here.
                degrade_unknown = true;
            }
        }
    }

    // A chain we couldn't fully resolve, or one that never reached a
    // self-signed anchor in the set, cannot be affirmed Valid.
    if degrade_unknown || !saw_self_signed_anchor {
        return SignatureValidity::Unknown;
    }
    SignatureValidity::Valid
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditlog::{AuditSink, RingSink};
    use crate::kmip30::{KmipAlgorithm, State, UsageMask};
    use crate::policy::Engine;
    use crate::store::{MemoryStore, ObjectRecord};
    use std::sync::Arc;

    fn deps_with() -> Deps {
        let ring = Arc::new(RingSink::new(64));
        let sink: Arc<dyn AuditSink> = ring.clone();
        Deps::new(
            Engine::permissive(),
            Arc::new(MemoryStore::new()),
            sink,
            super::super::deps::DepsConfig::default(),
        )
    }

    /// `deps_with` plus a real engine session — needed by every test that
    /// actually reaches the signature-verify step (`verify_with_spki`).
    /// Holds the crate-wide `engine_lock` for its lifetime — see
    /// `ops::helpers::engine_lock`'s doc for why a per-file lock isn't
    /// enough once more than one file's tests touch the engine.
    fn deps_with_session() -> (Deps, std::sync::MutexGuard<'static, ()>) {
        use softhsmrustv3::native::session::{bootstrap_default_token, finalize, init};
        let guard = super::super::helpers::engine_lock();
        let _ = finalize();
        init().expect("engine init");
        let session = bootstrap_default_token(0, "so", "user", "validate-test")
            .expect("bootstrap session");
        (deps_with().with_engine_session(session), guard)
    }

    /// rcgen `CertificateParams::new(SAN)` leaves the *distinguished
    /// name* empty, so issuer/subject DN comparison can't distinguish
    /// certs. Build params with an explicit CommonName so the chain-link
    /// matching in `validate_chain` (Issuer DN ⟷ Subject DN) is
    /// meaningful, plus an explicit validity window.
    fn params_with_cn(cn: &str) -> rcgen::CertificateParams {
        let mut p = rcgen::CertificateParams::new(vec![format!("{cn}.test")]).unwrap();
        p.distinguished_name.push(rcgen::DnType::CommonName, cn);
        // Valid roughly now ± a few years so the validity-date tests have
        // headroom on both sides.
        let now = OffsetDateTime::now_utc();
        p.not_before = now - ::time::Duration::days(1);
        p.not_after = now + ::time::Duration::days(365 * 5);
        p
    }

    /// A self-signed ECDSA-P256 CA with CN="root", valid now ± window.
    fn self_signed_der() -> Vec<u8> {
        let key = rcgen::KeyPair::generate().unwrap();
        params_with_cn("root").self_signed(&key).unwrap().der().to_vec()
    }

    fn put_cert(deps: &Deps, uid: &str, der: Vec<u8>) {
        deps.store
            .put(ObjectRecord {
                uid: uid.into(),
                object_type: ObjectType::Certificate,
                algorithm: KmipAlgorithm::Ecdsa,
                usage_mask: UsageMask::VERIFY,
                state: State::Active,
                key_material: Some(der),
                ..ObjectRecord::default()
            })
            .unwrap();
    }

    #[test]
    fn self_signed_cert_is_valid() {
        // A real engine session is required: this is an rcgen-produced
        // (independent, non-engine) ECDSA P-256 cert, verified via
        // `verify_with_spki` — the same cross-implementation shape as
        // the WP1a hub cross-check, just for the chain-validation path.
        let (deps, _g) = deps_with_session();
        let der = self_signed_der();
        assert_eq!(
            validate_chain(&deps, &[der], OffsetDateTime::now_utc()),
            SignatureValidity::Valid
        );
    }

    #[test]
    fn expired_cert_is_invalid() {
        // Validate the self-signed cert at an instant far in the future,
        // past its not_after — the validity-window check (step 2) fails
        // before any engine call, so a session-less Deps is fine.
        let deps = deps_with();
        let der = self_signed_der();
        let far_future = OffsetDateTime::now_utc() + ::time::Duration::days(365 * 100);
        assert_eq!(validate_chain(&deps, &[der], far_future), SignatureValidity::Invalid);
    }

    #[test]
    fn not_yet_valid_cert_is_invalid() {
        // Far in the past, before not_before — same step-2 early return.
        let deps = deps_with();
        let der = self_signed_der();
        let far_past = OffsetDateTime::from_unix_timestamp(0).unwrap();
        assert_eq!(validate_chain(&deps, &[der], far_past), SignatureValidity::Invalid);
    }

    #[test]
    fn missing_issuer_is_unknown() {
        // A leaf (non-self-signed) whose issuer isn't in the set →
        // Unknown, via the `None` (issuer not found) branch — no engine
        // call happens on that path, so a session-less Deps is fine.
        let deps = deps_with();
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_cert = params_with_cn("issuer-ca").self_signed(&ca_key).unwrap();

        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = params_with_cn("leaf").signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();

        // Leaf alone — issuer (CA) absent.
        assert_eq!(
            validate_chain(&deps, &[leaf.der().to_vec()], OffsetDateTime::now_utc()),
            SignatureValidity::Unknown
        );
    }

    #[test]
    fn leaf_with_ca_chain_is_valid() {
        let (deps, _g) = deps_with_session();
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_cert = params_with_cn("issuer-ca").self_signed(&ca_key).unwrap();

        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = params_with_cn("leaf").signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();

        // Leaf + its self-signed CA → full chain to a self-signed anchor.
        // Two DIFFERENT keys, two verify_with_spki calls (leaf-over-CA,
        // CA-over-itself) — proves chain-link verification, not just a
        // single self-signed check.
        assert_eq!(
            validate_chain(
                &deps,
                &[leaf.der().to_vec(), ca_cert.der().to_vec()],
                OffsetDateTime::now_utc()
            ),
            SignatureValidity::Valid
        );
    }

    #[test]
    fn broken_chain_wrong_issuer_signature_is_invalid() {
        // Two independent self-signed CAs with the SAME subject/issuer DN
        // would be needed to force a signature mismatch; instead, take a
        // leaf signed by CA-A but pair it with CA-B that happens to share
        // the issuer DN. Simpler: corrupt a byte in a self-signed cert's
        // signature region → parse-ok but signature fails.
        let (deps, _g) = deps_with_session();
        let mut der = self_signed_der();
        // Flip a bit late in the DER (within the signature BIT STRING).
        let n = der.len();
        der[n - 1] ^= 0x01;
        // Either the signature fails (Invalid) — the intended outcome.
        assert_eq!(
            validate_chain(&deps, &[der], OffsetDateTime::now_utc()),
            SignatureValidity::Invalid
        );
    }

    #[test]
    fn garbage_der_is_invalid() {
        // Fails at parse (step 1), before any engine call.
        let deps = deps_with();
        assert_eq!(
            validate_chain(&deps, &[vec![0xff, 0x00, 0x01]], OffsetDateTime::now_utc()),
            SignatureValidity::Invalid
        );
    }

    #[test]
    fn stored_uid_not_found_is_object_not_found() {
        let d = deps_with();
        let err = validate(
            &d,
            ValidateRequest { certificates: vec![], uids: vec!["nope".into()], validity_date: None },
            "c",
        )
        .unwrap_err();
        assert_eq!(err.result_reason(), crate::error::ResultReason::ObjectNotFound);
    }

    #[test]
    fn stored_uid_non_certificate_is_invalid_object_type() {
        let d = deps_with();
        d.store
            .put(ObjectRecord {
                uid: "sym".into(),
                object_type: ObjectType::SymmetricKey,
                algorithm: KmipAlgorithm::Aes,
                usage_mask: UsageMask::ENCRYPT,
                state: State::Active,
                ..ObjectRecord::default()
            })
            .unwrap();
        let err = validate(
            &d,
            ValidateRequest { certificates: vec![], uids: vec!["sym".into()], validity_date: None },
            "c",
        )
        .unwrap_err();
        assert_eq!(err.result_reason(), crate::error::ResultReason::InvalidObjectType);
    }

    #[test]
    fn stored_self_signed_uid_is_valid() {
        let (d, _g) = deps_with_session();
        put_cert(&d, "ca", self_signed_der());
        let r = validate(
            &d,
            ValidateRequest { certificates: vec![], uids: vec!["ca".into()], validity_date: None },
            "c",
        )
        .unwrap();
        assert_eq!(r.validity, SignatureValidity::Valid);
    }

    /// WP3 headline: a self-signed ML-DSA-65 chain now validates. The
    /// pre-port `ring`-backed `verify_signature` had no ML-DSA support at
    /// all — this exact chain would have degraded to `Unknown` before
    /// (an algorithm it couldn't evaluate), never `Valid`. Reuses the
    /// production `certify::bootstrap_ca_certificate` path (already
    /// covered by its own tests) rather than hand-building the cert, so
    /// this test is specifically about Validate's NEW coverage, not a
    /// second copy of Certify's issuance logic.
    #[test]
    fn self_signed_ml_dsa_chain_is_valid() {
        use softhsmrustv3::constants as c;
        use softhsmrustv3::native;

        let (deps, _g) = deps_with_session();
        let session = deps.engine_session.unwrap();
        let cka_id = b"validate-mldsa-root".to_vec();
        native::generate_ml_dsa_keypair(session, c::CKP_ML_DSA_65, &cka_id, "validate-mldsa")
            .expect("ML-DSA keygen");
        deps.store
            .put(ObjectRecord {
                uid: "urn:mldsa-root-priv".into(),
                object_type: ObjectType::PrivateKey,
                algorithm: KmipAlgorithm::MlDsa65,
                usage_mask: UsageMask::SIGN,
                state: State::Active,
                pkcs11_cka_id: cka_id,
                ..ObjectRecord::default()
            })
            .unwrap();

        let cert_der = super::super::certify::bootstrap_ca_certificate(
            &deps,
            "urn:mldsa-root-priv",
            "urn:mldsa-root-cert",
            "ML-DSA Validate Root",
            3650,
        )
        .expect("bootstrap ML-DSA CA cert");

        assert_eq!(
            validate_chain(&deps, &[cert_der], OffsetDateTime::now_utc()),
            SignatureValidity::Valid,
            "a self-signed ML-DSA chain must validate — ring never supported this"
        );
    }

    /// WP-2 remediation — a Register-created certificate only ever
    /// populates `certificate_value`, never `key_material` (`Certify`
    /// sets both identically). Before this fix, Validate keyed
    /// exclusively on `key_material` and so deterministically returned
    /// `Invalid` for every Register-created certificate regardless of
    /// whether its DER was actually valid — this pins the fix against
    /// exactly that storage shape.
    #[test]
    fn stored_self_signed_uid_with_only_certificate_value_is_valid() {
        let d = deps_with();
        let der = self_signed_der();
        d.store
            .put(ObjectRecord {
                uid: "ca-registered".into(),
                object_type: ObjectType::Certificate,
                algorithm: KmipAlgorithm::Ecdsa,
                usage_mask: UsageMask::VERIFY,
                state: State::Active,
                key_material: None,
                certificate_value: Some(der),
                ..ObjectRecord::default()
            })
            .unwrap();
        let r = validate(
            &d,
            ValidateRequest { certificates: vec![], uids: vec!["ca-registered".into()], validity_date: None },
            "c",
        )
        .unwrap();
        assert_eq!(r.validity, SignatureValidity::Valid);
    }

    /// A self-signed LAMPS composite (ML-DSA-65 + ECDSA-P256) chain of
    /// one must validate — the real end-to-end proof for
    /// `verify_composite_signature`, mirroring
    /// `self_signed_ml_dsa_chain_is_valid` above but with the two-engine-
    /// keypair composite CA setup `certify.rs`'s own composite bootstrap
    /// tests use. Then: flip one byte anywhere in the composite signature
    /// (ML-DSA half OR classical tail, doesn't matter which) and confirm
    /// it flips to `Invalid`, never a false `Valid`.
    #[test]
    fn self_signed_composite_chain_is_valid_and_tamper_detected() {
        use softhsmrustv3::native;

        let (deps, _g) = deps_with_session();
        let session = deps.engine_session.unwrap();
        let profile = &super::super::composite_sig::MLDSA65_ECDSA_P256_SHA512;
        let mldsa_cka_id = b"validate-composite-mldsa".to_vec();
        let classical_cka_id = b"validate-composite-classical".to_vec();
        native::generate_ml_dsa_keypair(session, profile.mldsa_param_set, &mldsa_cka_id, "validate-composite-mldsa")
            .expect("ML-DSA half keygen");
        native::generate_ecdsa_keypair(session, native::EccCurve::P256, &classical_cka_id, "validate-composite-classical")
            .expect("classical half keygen");
        deps.store
            .put(ObjectRecord {
                uid: "urn:composite-root-priv".into(),
                object_type: ObjectType::PrivateKey,
                algorithm: KmipAlgorithm::CompositeMlDsa65EcdsaP256Sha512,
                usage_mask: UsageMask::SIGN,
                state: State::Active,
                pkcs11_cka_id: mldsa_cka_id,
                pkcs11_cka_id_secondary: Some(classical_cka_id),
                ..ObjectRecord::default()
            })
            .unwrap();

        let cert_der = super::super::certify::bootstrap_ca_certificate(
            &deps, "urn:composite-root-priv", "urn:composite-root-cert", "Composite Validate Root", 3650,
        )
        .expect("bootstrap composite CA cert");

        assert_eq!(
            validate_chain(&deps, &[cert_der.clone()], OffsetDateTime::now_utc()),
            SignatureValidity::Valid,
            "a self-signed composite chain must validate — both components verify independently"
        );

        let mut tampered = cert_der;
        let last = tampered.len() - 1;
        tampered[last] ^= 0xff;
        assert_eq!(
            validate_chain(&deps, &[tampered], OffsetDateTime::now_utc()),
            SignatureValidity::Invalid,
            "a tampered composite signature must never come back Valid"
        );
    }

    /// WP-C9 end to end: `validate_chain`'s new Catalyst branch actually
    /// fires and AND-combines with the primary-signature check — not
    /// just that `catalyst.rs`'s own functions work in isolation
    /// (already proven by that module's 4 unit tests). Reuses
    /// `catalyst::tests::build_catalyst_tbs_and_sign` (a real
    /// self-signed ECDSA-primary / ML-DSA-alt certificate) rather than
    /// re-deriving the same fixture here.
    #[test]
    fn self_signed_catalyst_chain_is_valid_and_alt_tamper_detected() {
        let (deps, _g) = deps_with_session();
        let session = deps.engine_session.unwrap();

        let (valid_cert_der, _tbs) = super::super::catalyst::tests::build_catalyst_tbs_and_sign(session, false);
        assert_eq!(
            validate_chain(&deps, &[valid_cert_der], OffsetDateTime::now_utc()),
            SignatureValidity::Valid,
            "a self-signed Catalyst cert with a genuine alt signature must validate"
        );

        // A tampered ALT signature must invalidate the chain even though
        // the PRIMARY (ECDSA) signature is untouched and still verifies
        // — proves the AND-verdict, not just an OR that only checks
        // whichever signature happens to be examined first.
        let (tampered_alt_cert_der, _tbs2) = super::super::catalyst::tests::build_catalyst_tbs_and_sign(session, true);
        assert_eq!(
            validate_chain(&deps, &[tampered_alt_cert_der], OffsetDateTime::now_utc()),
            SignatureValidity::Invalid,
            "a tampered Catalyst alt signature must invalidate the chain even though the primary signature is untouched"
        );
    }

    /// WP-C10 end to end: `validate_chain`'s RelatedCertificate branch
    /// fires and produces the right 3-way verdict — `Bound` when the
    /// real companion is supplied alongside, `Unknown` when nothing
    /// else is supplied at all, `Invalid` when something else IS
    /// supplied but doesn't hash-match. Two plain self-signed certs
    /// (rcgen, same as every other test in this file) — cert A plain,
    /// cert B carrying a real `RelatedCertificate` extension built via
    /// `related_certs::tests::build_related_ext_der` pointing at cert
    /// A's actual `native::digest`-computed hash.
    #[test]
    fn related_certificate_binding_resolves_the_full_3_way_verdict() {
        let (deps, _g) = deps_with_session();

        let cert_a_der = params_with_cn("related-a").self_signed(&rcgen::KeyPair::generate().unwrap()).unwrap().der().to_vec();
        let real_hash_a =
            softhsmrustv3::native::digest(softhsmrustv3::constants::CKM_SHA256, &cert_a_der).unwrap();

        let mut params_b = params_with_cn("related-b");
        params_b.custom_extensions.push(rcgen::CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 5, 5, 7, 1, 36],
            super::super::related_certs::tests::build_related_ext_der(&real_hash_a),
        ));
        let cert_b_der = params_b.self_signed(&rcgen::KeyPair::generate().unwrap()).unwrap().der().to_vec();

        // Both companions supplied together — Bound, both self-signed,
        // both primary signatures verify → Valid overall.
        assert_eq!(
            validate_chain(&deps, &[cert_a_der.clone(), cert_b_der.clone()], OffsetDateTime::now_utc()),
            SignatureValidity::Valid,
            "cert B's real companion (cert A) supplied alongside it must bind and validate"
        );

        // Cert B alone — nothing else supplied to check the claim
        // against → Unknown, not Invalid (honest "can't confirm").
        assert_eq!(
            validate_chain(&deps, &[cert_b_der.clone()], OffsetDateTime::now_utc()),
            SignatureValidity::Unknown,
            "no companion supplied at all must degrade to Unknown, not guess Invalid"
        );

        // Cert B plus an UNRELATED third self-signed cert — something
        // else WAS supplied, but it doesn't hash-match the claim →
        // Invalid, a real checkable failure.
        let unrelated_der = params_with_cn("related-unrelated").self_signed(&rcgen::KeyPair::generate().unwrap()).unwrap().der().to_vec();
        assert_eq!(
            validate_chain(&deps, &[cert_b_der, unrelated_der], OffsetDateTime::now_utc()),
            SignatureValidity::Invalid,
            "an unrelated companion that doesn't hash-match the claim must be Invalid"
        );
    }

    /// WP-C11 end to end: `validate_chain`'s Chameleon branch actually
    /// fires and AND-combines with the primary-signature check. Reuses
    /// `chameleon::tests::build_chameleon_primary_tbs` (a real
    /// self-signed ML-DSA primary / ECDSA delta certificate) rather
    /// than re-deriving the same fixture here.
    #[test]
    fn self_signed_chameleon_chain_is_valid_and_delta_tamper_detected() {
        let (deps, _g) = deps_with_session();
        let session = deps.engine_session.unwrap();

        let (valid_cert_der, _tbs) = super::super::chameleon::tests::build_chameleon_primary_tbs(session, false);
        assert_eq!(
            validate_chain(&deps, &[valid_cert_der], OffsetDateTime::now_utc()),
            SignatureValidity::Valid,
            "a self-signed Chameleon cert with a genuine delta signature must validate"
        );

        // A tampered DELTA signature must invalidate the chain even
        // though the PRIMARY (ML-DSA) signature is untouched and still
        // verifies — proves the AND-verdict.
        let (tampered_delta_cert_der, _tbs2) =
            super::super::chameleon::tests::build_chameleon_primary_tbs(session, true);
        assert_eq!(
            validate_chain(&deps, &[tampered_delta_cert_der], OffsetDateTime::now_utc()),
            SignatureValidity::Invalid,
            "a tampered Chameleon delta signature must invalidate the chain even though the primary signature is untouched"
        );
    }
}
