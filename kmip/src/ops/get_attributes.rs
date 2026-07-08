//! KMIP 3.0 §6.1.21 **GetAttributes** operation.
//!
//! Returns one or more named attributes of a managed object. The
//! `attribute_references` field on the request names which attributes
//! the client wants; empty list means "every attribute the server can
//! surface".
//!
//! v0.1 surfaces the attributes derivable from `ObjectRecord`:
//!
//! - Unique Identifier
//! - Object Type
//! - Cryptographic Algorithm
//! - Cryptographic Length
//! - Cryptographic Usage Mask
//! - State
//! - Initial Date
//! - Activation Date (when set)
//!
//! Custom / Name attributes are surfaced once Wave 2 adds the
//! attribute-mutation ops (see `IMPLEMENTATION_PLAN.md`).

use std::collections::HashMap;
use time::OffsetDateTime;

use crate::error::{KmipError, Result};
use crate::kmip30::{Attribute, GetAttributesRequest, GetAttributesResponse, UsageMask};
use crate::policy::{Decision, PolicyRequest};
use crate::store::ObjectRecord;

use super::deps::Deps;
use super::helpers::{canonical_name, emit_request, emit_success, fail_err, state_name};

pub fn get_attributes(
    deps: &Deps,
    req: GetAttributesRequest,
    correlation_id: &str,
) -> Result<GetAttributesResponse> {
    let started = OffsetDateTime::now_utc();
    emit_request(
        deps,
        correlation_id,
        "GetAttributes",
        format!("uid={} refs={}", req.uid, req.attribute_references.len()),
    );

    let obj = deps.store.get(&req.uid)?.ok_or_else(|| {
        // OASIS corpus BL-M-20-30.xml pins ItemNotFound here (msg #7,
        // GetAttributes after Obliterate) — K2 keeps this site on the
        // generic reason; do NOT sweep to ObjectNotFound.
        fail_err(deps, correlation_id, "GetAttributes", KmipError::not_found(&req.uid))
    })?;

    // Plane-1 gate. Read-only — uncommon to deny but spec allows it.
    let empty: HashMap<String, String> = HashMap::new();
    let algo = canonical_name(obj.algorithm);
    let mut p_req = PolicyRequest::minimal(
        "GetAttributes",
        Some(&algo),
        started,
        correlation_id,
        &empty,
    );
    p_req.state = Some(state_name(obj.state));
    p_req.target_uid = Some(&req.uid);
    if let Decision::Deny { human, .. } = deps.engine.evaluate(&p_req) {
        return Err(fail_err(
            deps,
            correlation_id,
            "GetAttributes",
            KmipError::permission_denied(human),
        ));
    }

    let all = attributes_from_record(&obj);
    let attributes: Vec<Attribute> = if req.attribute_references.is_empty() {
        all
    } else {
        // Filter by the requested names.
        all.into_iter()
            .filter(|a| req.attribute_references.iter().any(|r| matches_name(a, r)))
            .collect()
    };

    emit_success(deps, correlation_id, "GetAttributes");
    Ok(GetAttributesResponse { uid: req.uid, attributes })
}

/// Project the `ObjectRecord` fields into a flat KMIP `Attribute` list.
///
/// Honours **KMIP Profiles v3.0 §5.1.2 (Baseline Server)** — every
/// attribute the profile mandates is surfaced if the record carries a
/// value for it. Optional fields are only emitted when populated so the
/// per-test count comparisons see meaningful counts (per §4.1.1 item 20
/// extras are allowed but we don't gratuitously inflate either).
fn attributes_from_record(r: &ObjectRecord) -> Vec<Attribute> {
    let mut out = vec![
        Attribute::UniqueIdentifier(r.uid.clone()),
        Attribute::ObjectType(r.object_type),
        Attribute::CryptographicAlgorithm(r.algorithm),
        Attribute::CryptographicUsageMask(r.usage_mask),
        Attribute::State(r.state),
        Attribute::InitialDate(r.initial_date.unix_timestamp()),
    ];
    if r.cryptographic_length > 0 {
        out.push(Attribute::CryptographicLength(r.cryptographic_length));
    }
    // KMIP 3.0 §4.16 — report the Recommended Curve inside the standard
    // Cryptographic Domain Parameters structure attribute (EC/ECDH keys).
    if let Some(rc) = r.recommended_curve {
        out.push(Attribute::CryptographicDomainParameters {
            qlength: None,
            recommended_curve: Some(rc),
        });
    }
    if let Some(n) = &r.name { out.push(Attribute::Name(n.clone())); }
    if let Some(d) = r.activation_date { out.push(Attribute::ActivationDate(d.unix_timestamp())); }
    if let Some(d) = r.deactivation_date { out.push(Attribute::DeactivationDate(d.unix_timestamp())); }
    if let Some(d) = r.destroy_date { out.push(Attribute::DestroyDate(d.unix_timestamp())); }
    if let Some(d) = r.compromise_date { out.push(Attribute::CompromiseDate(d.unix_timestamp())); }
    if let Some(d) = r.compromise_occurrence_date { out.push(Attribute::CompromiseOccurrenceDate(d.unix_timestamp())); }
    if let Some(d) = r.last_change_date { out.push(Attribute::LastChangeDate(d.unix_timestamp())); }
    if let Some(d) = r.original_creation_date { out.push(Attribute::OriginalCreationDate(d.unix_timestamp())); }
    if let Some(d) = r.process_start_date { out.push(Attribute::ProcessStartDate(d.unix_timestamp())); }
    if let Some(d) = r.protect_stop_date { out.push(Attribute::ProtectStopDate(d.unix_timestamp())); }
    if let Some(d) = r.rotate_date { out.push(Attribute::RotateDate(d.unix_timestamp())); }
    // KMIP 3.0 §11 attribute table — `Sensitive` / `Extractable` /
    // `AlwaysSensitive` / `NeverExtractable` are mandatory on every
    // managed object. The first pair is client-controllable; the
    // server-derived pair defaults to False when no prior history
    // exists. AKLC-O-1 / BL-M-14 / SKLC-O-1 pin all four on freshly
    // created keys.
    out.push(Attribute::Sensitive(r.sensitive.unwrap_or(false)));
    out.push(Attribute::Extractable(r.extractable.unwrap_or(true)));
    out.push(Attribute::AlwaysSensitive(r.always_sensitive.unwrap_or(false)));
    out.push(Attribute::NeverExtractable(r.never_extractable.unwrap_or(false)));
    // KMIP 3.0 §11 — `Fresh` is mandatory; True iff the object was
    // server-generated (Create / CreateKeyPair) AND has never been
    // exported. Register-imported objects are False. Default to
    // False until Phase 7c adds the generation-tracking flag.
    out.push(Attribute::Fresh(r.fresh.unwrap_or(false)));
    if let Some(b) = r.key_value_present { out.push(Attribute::KeyValuePresent(b)); }
    if let Some(b) = r.quantum_safe { out.push(Attribute::QuantumSafe(b)); }
    if let Some(b) = r.rotate_automatic { out.push(Attribute::RotateAutomatic(b)); }
    // KMIP §11 `Short Unique Identifier` — server-derived: a short
    // ByteString hash of the UID; honour the stored value when set,
    // otherwise generate a deterministic SHA-256 prefix.
    {
        use sha2::{Digest as _, Sha256};
        let sid = r.short_unique_identifier.clone().unwrap_or_else(|| {
            let hash = Sha256::digest(r.uid.as_bytes());
            hash[..8].iter().map(|b| format!("{b:02x}")).collect::<String>()
        });
        out.push(Attribute::ShortUniqueIdentifier(sid));
    }
    if let Some(s) = &r.alternative_name { out.push(Attribute::AlternativeName(s.clone())); }
    if let Some((ns, data)) = &r.application_specific_information {
        out.push(Attribute::ApplicationSpecificInformation { namespace: ns.clone(), data: data.clone() });
    }
    if let Some(s) = &r.comment { out.push(Attribute::Comment(s.clone())); }
    if let Some(s) = &r.description { out.push(Attribute::Description(s.clone())); }
    if let Some(s) = &r.contact_information { out.push(Attribute::ContactInformation(s.clone())); }
    // KMIP §11 `Object Class` — Baseline corpus expects `User` on
    // every test-created object; honour explicit record values.
    out.push(Attribute::ObjectClass(
        r.object_class.clone().unwrap_or_else(|| "User".into()),
    ));
    if let Some(s) = &r.key_value_location { out.push(Attribute::KeyValueLocation(s.clone())); }
    if let Some(s) = &r.x509_certificate_identifier { out.push(Attribute::X509CertificateIdentifier(s.clone())); }
    if let Some(s) = &r.x509_certificate_issuer { out.push(Attribute::X509CertificateIssuer(s.clone())); }
    if let Some(s) = &r.x509_certificate_subject { out.push(Attribute::X509CertificateSubject(s.clone())); }
    if let Some(s) = &r.rotate_name { out.push(Attribute::RotateName(s.clone())); }
    if let Some(v) = r.certificate_type { out.push(Attribute::CertificateType(v)); }
    if let Some(v) = r.digital_signature_algorithm { out.push(Attribute::DigitalSignatureAlgorithm(v)); }
    if let Some(v) = r.nist_key_type { out.push(Attribute::NistKeyType(v)); }
    if let Some(v) = r.protection_level { out.push(Attribute::ProtectionLevel(v)); }
    if let Some(v) = r.revocation_reason_code { out.push(Attribute::RevocationReasonCode(v)); }
    if let Some(v) = r.deactivation_reason_code { out.push(Attribute::DeactivationReasonCode(v)); }
    // KMIP 3.0 §11 — `Key Format Type` is mandatory on every managed
    // cryptographic object. For Create + CreateKeyPair (which don't
    // pass a KeyBlock), default to `Raw` (0x01) per §6.2 KeyFormatType
    // table. SKLC-O-1 step #3 pins this.
    out.push(Attribute::KeyFormatType(r.key_format_type.unwrap_or(0x01)));
    if let Some(n) = r.certificate_length { out.push(Attribute::CertificateLength(n)); }
    if let Some(s) = &r.certificate_subject_cn { out.push(Attribute::CertificateSubjectCN(s.clone())); }
    if let Some(b) = &r.certificate_value { out.push(Attribute::CertificateValue(b.clone())); }
    // KMIP §11 Lease Time — server default; OASIS Baseline corpus
    // pins 3600 seconds for newly-created keys (BL-M-14 / AKLC-O-1 /
    // SKLC-O-1). Honour an explicit record value when set.
    out.push(Attribute::LeaseTime(r.lease_time.unwrap_or(3600)));
    // KMIP §11 `Protection Storage Mask` — bit-flag Integer; the
    // Baseline corpus pins `Software` (0x01) on every test-created
    // managed object. BL-M-14 / SKLC-O-1 step #3 / AKLC-O-1 step #3.
    out.push(Attribute::ProtectionStorageMask(0x01));
    // KMIP §11 Link attributes — emit EVERY entry of the record's
    // `links` map (K-15), not a cherry-picked subset. Keys are the
    // canonical link-type names written by `create_key_pair`,
    // Register, and the attribute-mutation ops. Sorted for
    // deterministic output (HashMap iteration order is random).
    {
        let mut link_keys: Vec<&String> = r.links.keys().collect();
        link_keys.sort();
        for k in link_keys {
            let uid = r.links[k].clone();
            match k.as_str() {
                "PublicKeyLink"  => out.push(Attribute::PublicKeyLink(uid)),
                "PrivateKeyLink" => out.push(Attribute::PrivateKeyLink(uid)),
                "NextLink"       => out.push(Attribute::NextLink(uid)),
                "PreviousLink"   => out.push(Attribute::PreviousLink(uid)),
                "GroupLink"      => out.push(Attribute::GroupLink(uid)),
                // K20 — Derive Key link pair (§6.1.18 / §4.35.5).
                "DerivationBaseObjectLink" => {
                    out.push(Attribute::DerivationBaseObjectLink(uid))
                }
                "DerivedObjectLink" => out.push(Attribute::DerivedObjectLink(uid)),
                // K21 — Re-key link pair (§6.1.51 / §6.1.52).
                "ReplacedObjectLink" => out.push(Attribute::ReplacedObjectLink(uid)),
                "ReplacementObjectLink" => {
                    out.push(Attribute::ReplacementObjectLink(uid))
                }
                // Unknown link-type keys have no wire codepoint in the
                // Attribute enum yet — nothing stored writes them today.
                _ => {}
            }
        }
    }
    if let Some(n) = r.protection_period { out.push(Attribute::ProtectionPeriod(n)); }
    if let Some(n) = r.rotate_interval { out.push(Attribute::RotateInterval(n)); }
    if let Some(n) = r.rotate_offset { out.push(Attribute::RotateOffset(n)); }
    if let Some(n) = r.rotate_generation { out.push(Attribute::RotateGeneration(n)); }
    // KMIP §11 `Usage Limits` — full structure (K-15): Total budget,
    // remaining Count (decremented per protect-op by `encrypt.rs`),
    // and Unit. Unit defaults to Byte (0x01) when a budget exists
    // without an explicit unit — the engine's accounting deducts
    // bytes (CS-BC-M-7), so Byte is the truthful default.
    if let Some(total) = r.usage_limits_total {
        out.push(Attribute::UsageLimits {
            total,
            count: r.usage_limits_remaining,
            unit: Some(r.usage_limits_unit.unwrap_or(0x01)),
        });
    }
    // Custom attributes — surface each as Attribute::Custom.
    for (name, value) in &r.custom_attributes {
        out.push(Attribute::Custom { name: name.clone(), value: value.clone() });
    }

    // K3 — group membership is emitted as `Group Link` (0x4201b3, a Name
    // Reference), the STRICT KMIP 3.0 representation (§7.24 Table 485: the
    // Object Groups structure is a list of Group Link references). The
    // singular `Object Group` tag (0x420056) is RESERVED in KMIP 3.0 and is
    // never emitted. Multi-instance: one attribute per membership; empty → none.
    for g in &r.object_groups {
        out.push(Attribute::GroupLink(g.clone()));
    }

    // KMIP 3.0 §11 + Profiles v3.0 §4.1.1 item 10 — `Digest` is the
    // server-computed SHA-256 over the object's ACTUAL key material
    // (K-14): persisted at creation (`digest_value` — Register hashes
    // the supplied bytes, Create / CreateKeyPair hash the engine-held
    // CKA_VALUE via `native::get_value_digest_sha256`), with a
    // compute-on-read fallback for records carrying raw material.
    // When no material was ever available the attribute is OMITTED —
    // fabricating a digest from the UID string would violate §11
    // (Digest = hash of the Key Material bytes).
    if let Some(digest_bytes) = record_digest(r) {
        out.push(Attribute::Digest(crate::kmip30::DigestAttribute {
            hashing_algorithm: crate::kmip30::HashingAlgorithm::Sha256,
            digest_value: digest_bytes,
            key_format_type: r.key_format_type,
        }));
    }

    // KMIP 3.0 §11 + Profiles v3.0 §4.1 RV item 6 — `Random Number
    // Generator` structure. The engine sources all key material from
    // the OS entropy pool (`rand::rngs::OsRng` — see
    // `rust/src/native/keygen.rs`), not a managed DRBG, so the honest
    // RNGAlgorithm is `Unspecified` (0x01 per the spec's `RNG
    // Algorithm` enum). The OASIS fixtures show "ANSI X9.31 / AES-256"
    // but the replay harness treats the whole structure as opaque
    // (§4.1 RV item 6 — fields are variable), so honesty here is
    // corpus-safe. (The previous hardcoded 0x02 was doubly wrong:
    // 0x02 is "FIPS 186-2", not ANSI X9.31, and neither is what the
    // engine uses.)
    out.push(Attribute::RandomNumberGenerator(crate::kmip30::RngAttribute {
        rng_algorithm: 0x01, // Unspecified
        cryptographic_algorithm: None,
        cryptographic_length: None,
    }));

    let _ = UsageMask::empty(); // touch import so future expansion compiles cleanly
    out
}

/// K-14 — SHA-256 of the object's actual material, or `None` when the
/// server has never seen material for this object (engine-less unit
/// tests, value-less opaque objects). Order of preference: the digest
/// persisted at creation, then raw `key_material` bytes, then the
/// Certificate Value DER.
pub(crate) fn record_digest(r: &ObjectRecord) -> Option<Vec<u8>> {
    use sha2::{Digest as _, Sha256};
    r.digest_value
        .clone()
        .or_else(|| r.key_material.as_deref().map(|b| Sha256::digest(b).to_vec()))
        .or_else(|| r.certificate_value.as_deref().map(|b| Sha256::digest(b).to_vec()))
}

fn matches_name(attr: &Attribute, name: &str) -> bool {
    let canonical: String = name.chars().filter(|c| c.is_alphanumeric()).collect();
    canonical == canonical_attribute_name(attr)
}

/// Canonical alphanumeric-only attribute name matching the spec's tag
/// form. Used by the reference-filter logic in GetAttributes and the
/// GetAttributeList name surface.
pub(crate) fn canonical_attribute_name(attr: &Attribute) -> &'static str {
    match attr {
        Attribute::CryptographicAlgorithm(_) => "CryptographicAlgorithm",
        Attribute::CryptographicLength(_)    => "CryptographicLength",
        Attribute::CryptographicUsageMask(_) => "CryptographicUsageMask",
        Attribute::CryptographicDomainParameters { .. } => "CryptographicDomainParameters",
        Attribute::ObjectType(_)             => "ObjectType",
        Attribute::State(_)                  => "State",
        Attribute::UniqueIdentifier(_)       => "UniqueIdentifier",
        Attribute::Name(_)                   => "Name",
        Attribute::Custom { .. }             => "Custom",
        Attribute::InitialDate(_)            => "InitialDate",
        Attribute::ActivationDate(_)         => "ActivationDate",
        Attribute::DeactivationDate(_)       => "DeactivationDate",
        Attribute::DestroyDate(_)            => "DestroyDate",
        Attribute::CompromiseDate(_)         => "CompromiseDate",
        Attribute::CompromiseOccurrenceDate(_) => "CompromiseOccurrenceDate",
        Attribute::LastChangeDate(_)         => "LastChangeDate",
        Attribute::OriginalCreationDate(_)   => "OriginalCreationDate",
        Attribute::ProcessStartDate(_)       => "ProcessStartDate",
        Attribute::ProtectStopDate(_)        => "ProtectStopDate",
        Attribute::RotateDate(_)             => "RotateDate",
        Attribute::Sensitive(_)              => "Sensitive",
        Attribute::AlwaysSensitive(_)        => "AlwaysSensitive",
        Attribute::Extractable(_)            => "Extractable",
        Attribute::NeverExtractable(_)       => "NeverExtractable",
        Attribute::Fresh(_)                  => "Fresh",
        Attribute::KeyValuePresent(_)        => "KeyValuePresent",
        Attribute::QuantumSafe(_)            => "QuantumSafe",
        Attribute::RotateAutomatic(_)        => "RotateAutomatic",
        Attribute::ShortUniqueIdentifier(_)  => "ShortUniqueIdentifier",
        Attribute::AlternativeName(_)        => "AlternativeName",
        Attribute::Comment(_)                => "Comment",
        Attribute::Description(_)            => "Description",
        Attribute::ContactInformation(_)     => "ContactInformation",
        Attribute::ObjectClass(_)            => "ObjectClass",
        Attribute::KeyValueLocation(_)       => "KeyValueLocation",
        Attribute::X509CertificateIdentifier(_) => "X509CertificateIdentifier",
        Attribute::X509CertificateIssuer(_)  => "X509CertificateIssuer",
        Attribute::X509CertificateSubject(_) => "X509CertificateSubject",
        Attribute::RotateName(_)             => "RotateName",
        Attribute::CertificateType(_)        => "CertificateType",
        Attribute::CertificateValue(_)       => "CertificateValue",
        Attribute::CertificateSubjectCN(_)   => "CertificateSubjectCN",
        Attribute::ProtectionStorageMask(_)  => "ProtectionStorageMask",
        Attribute::PublicKeyLink(_)          => "PublicKeyLink",
        Attribute::PrivateKeyLink(_)         => "PrivateKeyLink",
        Attribute::NextLink(_)               => "NextLink",
        Attribute::PreviousLink(_)           => "PreviousLink",
        Attribute::GroupLink(_)              => "GroupLink",
        Attribute::ObjectGroup(_)            => "ObjectGroup",
        // K20 — Derive Key link pair (§6.1.18 / §4.35.5).
        Attribute::DerivationBaseObjectLink(_) => "DerivationBaseObjectLink",
        Attribute::DerivedObjectLink(_)      => "DerivedObjectLink",
        // K21 — Re-key link pair (§6.1.51 / §6.1.52).
        Attribute::ReplacedObjectLink(_)     => "ReplacedObjectLink",
        Attribute::ReplacementObjectLink(_)  => "ReplacementObjectLink",
        Attribute::ApplicationSpecificInformation { .. } => "ApplicationSpecificInformation",
        Attribute::DigitalSignatureAlgorithm(_) => "DigitalSignatureAlgorithm",
        Attribute::NistKeyType(_)            => "NistKeyType",
        Attribute::ProtectionLevel(_)        => "ProtectionLevel",
        Attribute::RevocationReasonCode(_)   => "RevocationReason",
        Attribute::DeactivationReasonCode(_) => "DeactivationReason",
        Attribute::KeyFormatType(_)          => "KeyFormatType",
        Attribute::CertificateLength(_)      => "CertificateLength",
        Attribute::LeaseTime(_)              => "LeaseTime",
        Attribute::ProtectionPeriod(_)       => "ProtectionPeriod",
        Attribute::RotateInterval(_)         => "RotateInterval",
        Attribute::RotateOffset(_)           => "RotateOffset",
        Attribute::RotateGeneration(_)       => "RotateGeneration",
        Attribute::UsageLimits { .. }        => "UsageLimits",
        Attribute::CryptographicParameters(_) => "CryptographicParameters",
        Attribute::Digest(_)                  => "Digest",
        Attribute::RandomNumberGenerator(_)   => "RandomNumberGenerator",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditlog::{AuditSink, RingSink};
    use crate::kmip30::{KmipAlgorithm, ObjectType, State, UsageMask};
    use crate::policy::{load_from_str, Engine};
    use crate::store::MemoryStore;
    use std::sync::Arc;

    fn deps_with() -> Deps {
        let ring = Arc::new(RingSink::new(64));
        let sink: Arc<dyn AuditSink> = ring.clone();
        let engine = Engine::with_global_sink(sink.clone());
        engine.activate(load_from_str(
            "schema_version: 1\nmetadata: {name: t, description: t, authority: t, effective: always}\nrules: []\n",
            std::path::Path::new("<t>"),
        ).unwrap()).unwrap();
        Deps::new(engine, Arc::new(MemoryStore::new()), sink, super::super::deps::DepsConfig::default())
    }

    fn put(d: &Deps, uid: &str) {
        d.store.put(ObjectRecord {
            uid: uid.into(),
            object_type: ObjectType::SymmetricKey,
            algorithm: KmipAlgorithm::Aes,
            cryptographic_length: 256,
            usage_mask: UsageMask::ENCRYPT | UsageMask::DECRYPT,
            state: State::Active,
            pkcs11_cka_id: vec![],
            pkcs11_slot: 0,
            initial_date: OffsetDateTime::UNIX_EPOCH,
            activation_date: Some(OffsetDateTime::UNIX_EPOCH),
            supersedes: None,
            name: None,

            links: std::collections::HashMap::new(),

            custom_attributes: std::collections::HashMap::new(),


            key_material: None,


            key_format_type: None,
        ..ObjectRecord::default()
}).unwrap();
    }

    /// K22 — §6.1.24.1 Error Handling – Get Attributes does NOT list
    /// `Object Archived`: an archived object's attributes remain
    /// readable (only the material is off-line — Get / crypto ops are
    /// the gated paths).
    #[test]
    fn archived_object_attributes_remain_readable() {
        let d = deps_with();
        put(&d, "u");
        let mut rec = d.store.get("u").unwrap().unwrap();
        rec.archived = true;
        d.store.update(rec).unwrap();
        let r = get_attributes(&d, GetAttributesRequest {
            uid: "u".into(),
            attribute_references: vec![],
        }, "c").unwrap();
        assert!(r.attributes.iter().any(|a| matches!(a, Attribute::CryptographicAlgorithm(_))));
    }

    #[test]
    fn empty_reference_list_returns_all_attributes() {
        let d = deps_with();
        put(&d, "u");
        let r = get_attributes(&d, GetAttributesRequest {
            uid: "u".into(),
            attribute_references: vec![],
        }, "c").unwrap();
        assert!(r.attributes.iter().any(|a| matches!(a, Attribute::CryptographicAlgorithm(_))));
        assert!(r.attributes.iter().any(|a| matches!(a, Attribute::CryptographicLength(_))));
        assert!(r.attributes.iter().any(|a| matches!(a, Attribute::State(_))));
    }

    #[test]
    fn specific_reference_filters_response() {
        let d = deps_with();
        put(&d, "u");
        let r = get_attributes(&d, GetAttributesRequest {
            uid: "u".into(),
            attribute_references: vec!["State".into()],
        }, "c").unwrap();
        assert_eq!(r.attributes.len(), 1);
        assert!(matches!(r.attributes[0], Attribute::State(_)));
    }

    /// K-14 — Digest must be the SHA-256 of the ACTUAL key material.
    #[test]
    fn digest_is_sha256_of_key_material() {
        use sha2::{Digest as _, Sha256};
        let d = deps_with();
        d.store.put(ObjectRecord {
            uid: "km".into(),
            algorithm: KmipAlgorithm::Aes,
            cryptographic_length: 256,
            usage_mask: UsageMask::ENCRYPT,
            state: State::Active,
            initial_date: OffsetDateTime::UNIX_EPOCH,
            key_material: Some(vec![0xAA; 32]),
            ..ObjectRecord::default()
        }).unwrap();
        let r = get_attributes(&d, GetAttributesRequest {
            uid: "km".into(),
            attribute_references: vec!["Digest".into()],
        }, "c").unwrap();
        assert_eq!(r.attributes.len(), 1);
        match &r.attributes[0] {
            Attribute::Digest(dg) => {
                assert_eq!(dg.digest_value, Sha256::digest(vec![0xAA; 32]).to_vec());
            }
            other => panic!("expected Digest, got {other:?}"),
        }
    }

    /// K-14 — a digest persisted at creation (engine-held material)
    /// takes precedence over compute-on-read.
    #[test]
    fn digest_prefers_persisted_value() {
        let d = deps_with();
        d.store.put(ObjectRecord {
            uid: "dv".into(),
            algorithm: KmipAlgorithm::Aes,
            cryptographic_length: 256,
            usage_mask: UsageMask::ENCRYPT,
            state: State::Active,
            initial_date: OffsetDateTime::UNIX_EPOCH,
            digest_value: Some(vec![0x42; 32]),
            ..ObjectRecord::default()
        }).unwrap();
        let r = get_attributes(&d, GetAttributesRequest {
            uid: "dv".into(),
            attribute_references: vec!["Digest".into()],
        }, "c").unwrap();
        match &r.attributes[0] {
            Attribute::Digest(dg) => assert_eq!(dg.digest_value, vec![0x42; 32]),
            other => panic!("expected Digest, got {other:?}"),
        }
    }

    /// K-14 — no material, no persisted digest → Digest is OMITTED,
    /// never fabricated from the UID string.
    #[test]
    fn digest_omitted_when_material_unavailable() {
        let d = deps_with();
        put(&d, "u"); // key_material: None, digest_value: None
        let r = get_attributes(&d, GetAttributesRequest {
            uid: "u".into(),
            attribute_references: vec![],
        }, "c").unwrap();
        assert!(
            !r.attributes.iter().any(|a| matches!(a, Attribute::Digest(_))),
            "Digest must be omitted when no material was ever available"
        );
    }

    /// K-15 — every entry of the links map is emitted, not a
    /// cherry-picked subset.
    #[test]
    fn all_stored_links_are_emitted() {
        let d = deps_with();
        let mut links = std::collections::HashMap::new();
        links.insert("PublicKeyLink".to_string(), "pub-1".to_string());
        links.insert("PrivateKeyLink".to_string(), "prv-1".to_string());
        links.insert("NextLink".to_string(), "next-1".to_string());
        links.insert("PreviousLink".to_string(), "prev-1".to_string());
        links.insert("GroupLink".to_string(), "grp-1".to_string());
        d.store.put(ObjectRecord {
            uid: "ln".into(),
            algorithm: KmipAlgorithm::Aes,
            cryptographic_length: 256,
            usage_mask: UsageMask::ENCRYPT,
            state: State::Active,
            initial_date: OffsetDateTime::UNIX_EPOCH,
            links,
            ..ObjectRecord::default()
        }).unwrap();
        let r = get_attributes(&d, GetAttributesRequest {
            uid: "ln".into(),
            attribute_references: vec![],
        }, "c").unwrap();
        assert!(r.attributes.iter().any(|a| matches!(a, Attribute::PublicKeyLink(u) if u == "pub-1")));
        assert!(r.attributes.iter().any(|a| matches!(a, Attribute::PrivateKeyLink(u) if u == "prv-1")));
        assert!(r.attributes.iter().any(|a| matches!(a, Attribute::NextLink(u) if u == "next-1")));
        assert!(r.attributes.iter().any(|a| matches!(a, Attribute::PreviousLink(u) if u == "prev-1")));
        assert!(r.attributes.iter().any(|a| matches!(a, Attribute::GroupLink(u) if u == "grp-1")));
    }

    /// K-15 — UsageLimits is emitted as the full structure: Total +
    /// remaining Count + Unit (Byte default for the byte-accounting
    /// engine).
    #[test]
    fn usage_limits_full_structure_emitted() {
        let d = deps_with();
        d.store.put(ObjectRecord {
            uid: "ul".into(),
            algorithm: KmipAlgorithm::Aes,
            cryptographic_length: 256,
            usage_mask: UsageMask::ENCRYPT,
            state: State::Active,
            initial_date: OffsetDateTime::UNIX_EPOCH,
            usage_limits_total: Some(16),
            usage_limits_remaining: Some(4),
            ..ObjectRecord::default()
        }).unwrap();
        let r = get_attributes(&d, GetAttributesRequest {
            uid: "ul".into(),
            attribute_references: vec!["UsageLimits".into()],
        }, "c").unwrap();
        assert_eq!(r.attributes.len(), 1);
        match &r.attributes[0] {
            Attribute::UsageLimits { total, count, unit } => {
                assert_eq!(*total, 16);
                assert_eq!(*count, Some(4));
                assert_eq!(*unit, Some(0x01)); // Byte
            }
            other => panic!("expected UsageLimits, got {other:?}"),
        }
    }

    /// RNG honesty — the engine draws from the OS entropy pool, so the
    /// attribute reports `Unspecified` (0x01), not a fabricated DRBG.
    #[test]
    fn rng_attribute_reports_unspecified() {
        let d = deps_with();
        put(&d, "u");
        let r = get_attributes(&d, GetAttributesRequest {
            uid: "u".into(),
            attribute_references: vec!["RandomNumberGenerator".into()],
        }, "c").unwrap();
        match &r.attributes[0] {
            Attribute::RandomNumberGenerator(rng) => {
                assert_eq!(rng.rng_algorithm, 0x01);
                assert_eq!(rng.cryptographic_algorithm, None);
                assert_eq!(rng.cryptographic_length, None);
            }
            other => panic!("expected RandomNumberGenerator, got {other:?}"),
        }
    }

    #[test]
    fn missing_object_returns_not_found() {
        let d = deps_with();
        let err = get_attributes(&d, GetAttributesRequest {
            uid: "missing".into(),
            attribute_references: vec![],
        }, "c").unwrap_err();
        // OASIS corpus BL-M-20-30.xml pins ItemNotFound for a missing
        // UID on GetAttributes (corpus is authoritative over the sweep).
        assert_eq!(err.result_reason(), crate::error::ResultReason::ItemNotFound);
    }
}
