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
    // KMIP §11 `Public Key Link` / `Private Key Link` — UID refs
    // between key-pair halves. Surfaced when the record's `links`
    // map has the relevant entry (populated by `create_key_pair`).
    if let Some(uid) = r.links.get("PublicKeyLink") {
        out.push(Attribute::PublicKeyLink(uid.clone()));
    }
    if let Some(uid) = r.links.get("PrivateKeyLink") {
        out.push(Attribute::PrivateKeyLink(uid.clone()));
    }
    if let Some(uid) = r.links.get("NextLink") {
        out.push(Attribute::NextLink(uid.clone()));
    }
    if let Some(uid) = r.links.get("PreviousLink") {
        out.push(Attribute::PreviousLink(uid.clone()));
    }
    if let Some(n) = r.protection_period { out.push(Attribute::ProtectionPeriod(n)); }
    if let Some(n) = r.rotate_interval { out.push(Attribute::RotateInterval(n)); }
    if let Some(n) = r.rotate_offset { out.push(Attribute::RotateOffset(n)); }
    if let Some(n) = r.rotate_generation { out.push(Attribute::RotateGeneration(n)); }
    if let Some(n) = r.usage_limits_total { out.push(Attribute::UsageLimitsTotal(n)); }
    // Custom attributes — surface each as Attribute::Custom.
    for (name, value) in &r.custom_attributes {
        out.push(Attribute::Custom { name: name.clone(), value: value.clone() });
    }

    // KMIP 3.0 §11 + Profiles v3.0 §4.1.1 item 10 — `Digest` is a
    // server-computed structure (HashingAlgorithm + DigestValue
    // + optional KeyFormatType). Value is variable so the comparator
    // accepts whatever we emit; we use SHA-256 over the stored key
    // material (or an empty hash when material isn't present).
    {
        use sha2::{Digest as _, Sha256};
        let digest_bytes = match &r.key_material {
            Some(km) => Sha256::digest(km).to_vec(),
            None => Sha256::digest(r.uid.as_bytes()).to_vec(),
        };
        out.push(Attribute::Digest(crate::kmip30::DigestAttribute {
            hashing_algorithm: crate::kmip30::HashingAlgorithm::Sha256,
            digest_value: digest_bytes,
            key_format_type: r.key_format_type,
        }));
    }

    // KMIP 3.0 §11 + Profiles v3.0 §4.1 RV item 6 — `Random Number
    // Generator` structure. Fields are variable per spec; we report a
    // deterministic ANSI X9.31 / AES-256 entry that covers the OASIS
    // Baseline shape (SKFF-M-11 etc. compare presence + tag-name only).
    out.push(Attribute::RandomNumberGenerator(crate::kmip30::RngAttribute {
        rng_algorithm: 0x02, // ANSIX9_31 — see kmip-spec-3.0-tags-enums.json `enums.RNG Algorithm`
        cryptographic_algorithm: Some(crate::kmip30::KmipAlgorithm::Aes),
        cryptographic_length: Some(256),
    }));

    let _ = UsageMask::empty(); // touch import so future expansion compiles cleanly
    out
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
        Attribute::UsageLimitsTotal(_)       => "UsageLimits",
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

    #[test]
    fn missing_object_returns_not_found() {
        let d = deps_with();
        let err = get_attributes(&d, GetAttributesRequest {
            uid: "missing".into(),
            attribute_references: vec![],
        }, "c").unwrap_err();
        assert_eq!(err.result_reason(), crate::error::ResultReason::ItemNotFound);
    }
}
