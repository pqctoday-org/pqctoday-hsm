//! KMIP 3.0 §6.1.26 **GetAttributes** operation.
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
use super::helpers::{authorize_object, canonical_name, emit_request, emit_success, fail_err, state_name};

pub fn get_attributes(
    deps: &Deps,
    req: GetAttributesRequest,
    auth: &crate::server::auth::AuthContext,
    correlation_id: &str,
) -> Result<GetAttributesResponse> {
    let started = OffsetDateTime::now_utc();
    emit_request(
        deps,
        correlation_id,
        "GetAttributes",
        format!("uid={} refs={}", req.uid, req.attribute_references.len()),
    );

    // Part F §F7.4 — owner-checked lookup (closes the gap
    // `ops::tenancy_e2e` documented empirically). Same ItemNotFound this
    // handler already used for a genuinely missing UID (OASIS corpus
    // BL-M-20-30.xml pins it — K2, do NOT sweep to ObjectNotFound) now
    // also covers "exists but belongs to a different tenant".
    let obj = authorize_object(deps, auth, &req.uid, || KmipError::not_found(&req.uid)).map_err(|e| {
        fail_err(deps, correlation_id, "GetAttributes", e)
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
    if let Decision::Deny { kmip_reason, human, .. } = deps.engine.evaluate(&p_req) {
        return Err(fail_err(
            deps,
            correlation_id,
            "GetAttributes",
            KmipError::failed(kmip_reason.to_result_reason(), human),
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
        // §4.67 transition 6 (G8) — a date may have moved this object since
        // it was last written. Report what the state actually IS now, not the
        // last explicitly-set value: an Active key past its Protect Stop Date
        // is Deactivated, and Encrypt/Decrypt already refuse it.
        Attribute::State(
            crate::store::lifecycle::effective_state_for(r, time::OffsetDateTime::now_utc())
                .map(|(st, _)| st)
                .unwrap_or(r.state),
        ),
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
    // §4.21 Deactivation Reason — when a date moved the object, say which one.
    if let Some((_, code)) =
        crate::store::lifecycle::effective_state_for(r, time::OffsetDateTime::now_utc())
    {
        out.push(Attribute::DeactivationReasonCode(code));
    }
    if let Some(x) = r.rotate_latest { out.push(Attribute::RotateLatest(x)); }
    if let Some(x) = r.archive_date { out.push(Attribute::ArchiveDate(x)); }
    if let Some(x) = r.nist_security_category { out.push(Attribute::NistSecurityCategory(x)); }
    if let Some(x) = r.otp_counter { out.push(Attribute::OtpCounter(x)); }
    if let Some(x) = &r.pkcs12_friendly_name { out.push(Attribute::Pkcs12FriendlyName(x.clone())); }
    if let Some(x) = r.certify_counter { out.push(Attribute::CertifyCounter(x)); }
    if let Some(x) = r.decrypt_counter { out.push(Attribute::DecryptCounter(x)); }
    if let Some(x) = r.encrypt_counter { out.push(Attribute::EncryptCounter(x)); }
    if let Some(x) = r.sign_counter { out.push(Attribute::SignCounter(x)); }
    if let Some(x) = r.signature_verify_counter { out.push(Attribute::SignatureVerifyCounter(x)); }
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
    if let Some(s) = &r.alternative_name {
        out.push(Attribute::AlternativeName {
            value: s.clone(),
            name_type: r.alternative_name_type.unwrap_or(1),
        });
    }
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
    push_certificate_names(&mut out, r);
    if let Some(b) = &r.certificate_value { out.push(Attribute::CertificateValue(b.clone())); }
    // KMIP §11 Lease Time — server default; OASIS Baseline corpus
    // pins 3600 seconds for newly-created keys (BL-M-14 / AKLC-O-1 /
    // SKLC-O-1). Honour an explicit record value when set.
    out.push(Attribute::LeaseTime(r.lease_time.unwrap_or(3600)));
    // Phase 3.3 — Split Key (§2.2.8/§4.29/§4.30/§4.63-4.66). `Some`
    // only on `ObjectType::SplitKey` share objects.
    if let Some(v) = r.split_key_method { out.push(Attribute::SplitKeyMethod(v)); }
    if let Some(n) = r.split_key_parts { out.push(Attribute::SplitKeyParts(n)); }
    if let Some(n) = r.split_key_threshold { out.push(Attribute::SplitKeyThreshold(n)); }
    if let Some(n) = r.key_part_identifier { out.push(Attribute::KeyPartIdentifier(n)); }
    if let Some(v) = r.split_key_polynomial { out.push(Attribute::SplitKeyPolynomial(v)); }
    // KMIP §11 `Protection Storage Mask` — bit-flag Integer; the mask
    // actually used, recorded at Create/Register (`r.protection_storage_mask`).
    // Every record this server has ever produced carries `Software` (0x01) —
    // the only storage class it has — so the fallback for pre-field records
    // is the same true value, not a fabricated default. BL-M-14 / SKLC-O-1
    // step #3 / AKLC-O-1 step #3 pin `Software`.
    out.push(Attribute::ProtectionStorageMask(
        r.protection_storage_mask.unwrap_or(0x01),
    ));
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
                // K20 — Derive Key link pair (§6.1.19 / §4.35.5).
                "DerivationBaseObjectLink" => {
                    out.push(Attribute::DerivationBaseObjectLink(uid))
                }
                "DerivedObjectLink" => out.push(Attribute::DerivedObjectLink(uid)),
                // K21 — Re-key link pair (§6.1.53 / §6.1.52).
                "ReplacedObjectLink" => out.push(Attribute::ReplacedObjectLink(uid)),
                "ReplacementObjectLink" => {
                    out.push(Attribute::ReplacementObjectLink(uid))
                }
                "CertificateLink" => out.push(Attribute::CertificateLink(uid)),
                "ChildLink" => out.push(Attribute::ChildLink(uid)),
                "ParentLink" => out.push(Attribute::ParentLink(uid)),
                "Pkcs12CertificateLink" => out.push(Attribute::Pkcs12CertificateLink(uid)),
                "Pkcs12PasswordLink" => out.push(Attribute::Pkcs12PasswordLink(uid)),
                "WrappingKeyLink" => out.push(Attribute::WrappingKeyLink(uid)),
                "CredentialLink" => out.push(Attribute::CredentialLink(uid)),
                "PasswordLink" => out.push(Attribute::PasswordLink(uid)),
                "SplitKeyBaseLink" => out.push(Attribute::SplitKeyBaseLink(uid)),
                "JoinedSplitKeyPartsLink" => out.push(Attribute::JoinedSplitKeyPartsLink(uid)),
                "CertificateRequestLink" => out.push(Attribute::CertificateRequestLink(uid)),
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
    for (key, value) in &r.custom_attributes {
        // The stored key carries the vendor, so read-back no longer has to
        // guess it. Before the pair key existed this said `vendor: None`,
        // which meant GetAttributes could not tell a client WHICH vendor's
        // attribute it was looking at — the storage half of the G9 defect.
        out.push(Attribute::Custom {
            vendor: Some(key.vendor().to_string()),
            name: key.name().to_string(),
            value: value.clone(),
        });
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
        Attribute::AlternativeName { .. }    => "AlternativeName",
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
        Attribute::CertificateSubjectO(_) => "CertificateSubjectO",
        Attribute::CertificateSubjectOU(_) => "CertificateSubjectOU",
        Attribute::CertificateSubjectEmail(_) => "CertificateSubjectEmail",
        Attribute::CertificateSubjectC(_) => "CertificateSubjectC",
        Attribute::CertificateSubjectST(_) => "CertificateSubjectST",
        Attribute::CertificateSubjectL(_) => "CertificateSubjectL",
        Attribute::CertificateSubjectUID(_) => "CertificateSubjectUID",
        Attribute::CertificateSubjectSerialNumber(_) => "CertificateSubjectSerialNumber",
        Attribute::CertificateSubjectTitle(_) => "CertificateSubjectTitle",
        Attribute::CertificateSubjectDC(_) => "CertificateSubjectDC",
        Attribute::CertificateSubjectDNQualifier(_) => "CertificateSubjectDNQualifier",
        Attribute::CertificateSubjectDN(_) => "CertificateSubjectDN",
        Attribute::CertificateIssuerCN(_) => "CertificateIssuerCN",
        Attribute::CertificateIssuerO(_) => "CertificateIssuerO",
        Attribute::CertificateIssuerOU(_) => "CertificateIssuerOU",
        Attribute::CertificateIssuerEmail(_) => "CertificateIssuerEmail",
        Attribute::CertificateIssuerC(_) => "CertificateIssuerC",
        Attribute::CertificateIssuerST(_) => "CertificateIssuerST",
        Attribute::CertificateIssuerL(_) => "CertificateIssuerL",
        Attribute::CertificateIssuerUID(_) => "CertificateIssuerUID",
        Attribute::CertificateIssuerSerialNumber(_) => "CertificateIssuerSerialNumber",
        Attribute::CertificateIssuerTitle(_) => "CertificateIssuerTitle",
        Attribute::CertificateIssuerDC(_) => "CertificateIssuerDC",
        Attribute::CertificateIssuerDNQualifier(_) => "CertificateIssuerDNQualifier",
        Attribute::CertificateIssuerDN(_) => "CertificateIssuerDN",
        Attribute::ProtectionStorageMask(_)  => "ProtectionStorageMask",
        Attribute::PublicKeyLink(_)          => "PublicKeyLink",
        Attribute::RotateLatest(_) => "RotateLatest",
        Attribute::ArchiveDate(_) => "ArchiveDate",
        Attribute::NistSecurityCategory(_) => "NistSecurityCategory",
        Attribute::OtpCounter(_) => "OtpCounter",
        Attribute::Pkcs12FriendlyName(_) => "Pkcs12FriendlyName",
        Attribute::CertifyCounter(_) => "CertifyCounter",
        Attribute::DecryptCounter(_) => "DecryptCounter",
        Attribute::EncryptCounter(_) => "EncryptCounter",
        Attribute::SignCounter(_) => "SignCounter",
        Attribute::SignatureVerifyCounter(_) => "SignatureVerifyCounter",
        Attribute::CertificateLink(_) => "CertificateLink",
        Attribute::ChildLink(_) => "ChildLink",
        Attribute::ParentLink(_) => "ParentLink",
        Attribute::Pkcs12CertificateLink(_) => "Pkcs12CertificateLink",
        Attribute::Pkcs12PasswordLink(_) => "Pkcs12PasswordLink",
        Attribute::WrappingKeyLink(_) => "WrappingKeyLink",
        Attribute::CredentialLink(_) => "CredentialLink",
        Attribute::PasswordLink(_) => "PasswordLink",
        Attribute::SplitKeyBaseLink(_) => "SplitKeyBaseLink",
        Attribute::JoinedSplitKeyPartsLink(_) => "JoinedSplitKeyPartsLink",
        Attribute::CertificateRequestLink(_) => "CertificateRequestLink",
        Attribute::PrivateKeyLink(_)         => "PrivateKeyLink",
        Attribute::NextLink(_)               => "NextLink",
        Attribute::PreviousLink(_)           => "PreviousLink",
        Attribute::GroupLink(_)              => "GroupLink",
        Attribute::ObjectGroup(_)            => "ObjectGroup",
        // K20 — Derive Key link pair (§6.1.19 / §4.35.5).
        Attribute::DerivationBaseObjectLink(_) => "DerivationBaseObjectLink",
        Attribute::DerivedObjectLink(_)      => "DerivedObjectLink",
        // K21 — Re-key link pair (§6.1.53 / §6.1.52).
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
        Attribute::SplitKeyMethod(_)         => "SplitKeyMethod",
        Attribute::SplitKeyParts(_)          => "SplitKeyParts",
        Attribute::SplitKeyThreshold(_)      => "SplitKeyThreshold",
        Attribute::KeyPartIdentifier(_)      => "KeyPartIdentifier",
        Attribute::SplitKeyPolynomial(_)     => "SplitKeyPolynomial",
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


/// Project the §4.6 Certificate Attributes.
///
/// Table 62 governs the shape twice over: "Multiple instances permitted: Yes"
/// means one attribute instance PER value, so a Subject with two `OU`s yields
/// two `Certificate Subject OU` attributes; and "SHALL always have a value:
/// No" means an absent RDN yields NO attribute at all, never an empty string.
/// An object that is not a certificate has neither Name and contributes
/// nothing.
fn push_certificate_names(out: &mut Vec<Attribute>, r: &ObjectRecord) {
    if let Some(n) = &r.certificate_subject {
        for v in &n.cn { out.push(Attribute::CertificateSubjectCN(v.clone())); }
        for v in &n.o { out.push(Attribute::CertificateSubjectO(v.clone())); }
        for v in &n.ou { out.push(Attribute::CertificateSubjectOU(v.clone())); }
        for v in &n.email { out.push(Attribute::CertificateSubjectEmail(v.clone())); }
        for v in &n.c { out.push(Attribute::CertificateSubjectC(v.clone())); }
        for v in &n.st { out.push(Attribute::CertificateSubjectST(v.clone())); }
        for v in &n.l { out.push(Attribute::CertificateSubjectL(v.clone())); }
        for v in &n.uid { out.push(Attribute::CertificateSubjectUID(v.clone())); }
        for v in &n.serial_number { out.push(Attribute::CertificateSubjectSerialNumber(v.clone())); }
        for v in &n.title { out.push(Attribute::CertificateSubjectTitle(v.clone())); }
        for v in &n.dc { out.push(Attribute::CertificateSubjectDC(v.clone())); }
        for v in &n.dn_qualifier { out.push(Attribute::CertificateSubjectDNQualifier(v.clone())); }
        if let Some(v) = &n.dn { out.push(Attribute::CertificateSubjectDN(v.clone())); }
    }
    if let Some(n) = &r.certificate_issuer {
        for v in &n.cn { out.push(Attribute::CertificateIssuerCN(v.clone())); }
        for v in &n.o { out.push(Attribute::CertificateIssuerO(v.clone())); }
        for v in &n.ou { out.push(Attribute::CertificateIssuerOU(v.clone())); }
        for v in &n.email { out.push(Attribute::CertificateIssuerEmail(v.clone())); }
        for v in &n.c { out.push(Attribute::CertificateIssuerC(v.clone())); }
        for v in &n.st { out.push(Attribute::CertificateIssuerST(v.clone())); }
        for v in &n.l { out.push(Attribute::CertificateIssuerL(v.clone())); }
        for v in &n.uid { out.push(Attribute::CertificateIssuerUID(v.clone())); }
        for v in &n.serial_number { out.push(Attribute::CertificateIssuerSerialNumber(v.clone())); }
        for v in &n.title { out.push(Attribute::CertificateIssuerTitle(v.clone())); }
        for v in &n.dc { out.push(Attribute::CertificateIssuerDC(v.clone())); }
        for v in &n.dn_qualifier { out.push(Attribute::CertificateIssuerDNQualifier(v.clone())); }
        if let Some(v) = &n.dn { out.push(Attribute::CertificateIssuerDN(v.clone())); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditlog::{AuditSink, RingSink};
    use crate::kmip30::{KmipAlgorithm, ObjectType, State, UsageMask};
    use crate::policy::{load_from_str, Engine};
    use crate::server::auth::AuthContext;
    use crate::store::MemoryStore;
    use std::sync::Arc;

    fn deps_with() -> Deps {
        let ring = Arc::new(RingSink::new(64));
        let sink: Arc<dyn AuditSink> = ring.clone();
        let engine = Engine::with_global_sink(sink.clone());
        engine.replace_all(load_from_str(
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

    /// K22 — §6.1.26.1 Error Handling – Get Attributes does NOT list
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
        }, &AuthContext::open(), "c").unwrap();
        assert!(r.attributes.iter().any(|a| matches!(a, Attribute::CryptographicAlgorithm(_))));
    }

    #[test]
    fn empty_reference_list_returns_all_attributes() {
        let d = deps_with();
        put(&d, "u");
        let r = get_attributes(&d, GetAttributesRequest {
            uid: "u".into(),
            attribute_references: vec![],
        }, &AuthContext::open(), "c").unwrap();
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
        }, &AuthContext::open(), "c").unwrap();
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
        }, &AuthContext::open(), "c").unwrap();
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
        }, &AuthContext::open(), "c").unwrap();
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
        }, &AuthContext::open(), "c").unwrap();
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
        }, &AuthContext::open(), "c").unwrap();
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
        }, &AuthContext::open(), "c").unwrap();
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
        }, &AuthContext::open(), "c").unwrap();
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
        }, &AuthContext::open(), "c").unwrap_err();
        // OASIS corpus BL-M-20-30.xml pins ItemNotFound for a missing
        // UID on GetAttributes (corpus is authoritative over the sweep).
        assert_eq!(err.result_reason(), crate::error::ResultReason::ItemNotFound);
    }

    /// Gap-remediation Phase H, Finding #11 — Register with
    /// `AlternativeNameType=URI(2)` must round-trip through
    /// GetAttributes, not silently collapse to the `1`
    /// (Uninterpreted Text String) default.
    #[test]
    fn register_alternative_name_type_round_trips_through_get_attributes() {
        use crate::kmip30::{KeyBlock, KeyFormatType, RegisterRequest};
        use crate::ops::register_import_export::register;

        let d = deps_with();
        let resp = register(&d, RegisterRequest {
            secret_data_type: None,
            object_type: ObjectType::SymmetricKey,
            attributes: vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes),
                Attribute::CryptographicLength(128),
                Attribute::CryptographicUsageMask(UsageMask::ENCRYPT),
                Attribute::AlternativeName { value: "https://example/asset/1".into(), name_type: 2 },
            ],
            managed_object: Some(KeyBlock {
                key_format_type: KeyFormatType::Raw,
                cryptographic_algorithm: KmipAlgorithm::Aes,
                cryptographic_length: 128,
                key_value: vec![0x11; 16],
                key_wrapping_data: None,
            }),
            protection_storage_masks: None,
            certificate_payload: None,
        }, &AuthContext::open(), "c").unwrap();

        let r = get_attributes(&d, GetAttributesRequest {
            uid: resp.uid,
            attribute_references: vec![],
        }, &AuthContext::open(), "c").unwrap();
        let found = r.attributes.iter().find_map(|a| match a {
            Attribute::AlternativeName { value, name_type } => Some((value.clone(), *name_type)),
            _ => None,
        });
        assert_eq!(found, Some(("https://example/asset/1".to_string(), 2)));
    }

    /// G2 (2026-09-06) — `Certify` writes a `CertificateLink` onto both the
    /// certificate and the public key (`ops/certify.rs`), but until the §4.35
    /// link set was completed there was no `Attribute::CertificateLink`, so
    /// `attributes_from_record`'s link loop hit its `_ => {}` arm and dropped
    /// it. The server stored a link it could never tell anyone about.
    ///
    /// This asserts the whole set survives the record → wire-attribute step.
    /// It fails if any of the eleven link types added in G2 loses its arm.
    #[test]
    fn every_completed_link_type_survives_the_record_to_attribute_step() {
        let mut rec = ObjectRecord::default();
        for k in [
            "CertificateLink", "ChildLink", "ParentLink", "Pkcs12CertificateLink",
            "Pkcs12PasswordLink", "WrappingKeyLink", "CredentialLink", "PasswordLink",
            "SplitKeyBaseLink", "JoinedSplitKeyPartsLink", "CertificateRequestLink",
        ] {
            rec.links.insert(k.to_string(), format!("urn:target-of-{k}"));
        }
        let attrs = attributes_from_record(&rec);

        let seen: Vec<&str> = attrs.iter().map(canonical_attribute_name).collect();
        for k in [
            "CertificateLink", "ChildLink", "ParentLink", "Pkcs12CertificateLink",
            "Pkcs12PasswordLink", "WrappingKeyLink", "CredentialLink", "PasswordLink",
            "SplitKeyBaseLink", "JoinedSplitKeyPartsLink", "CertificateRequestLink",
        ] {
            assert!(
                seen.contains(&k),
                "{k} was stored on the record but never emitted as an attribute \
                 — the link loop dropped it (this is the CertificateLink bug)",
            );
        }
    }

    /// §4.6 Table 62, end to end through the projection, in both directions.
    ///
    /// "Multiple instances permitted: Yes" — a Subject with two `OU`s must
    /// emit TWO `Certificate Subject OU` attributes, not one. The old
    /// `Option<String>` record field could not represent the second at all.
    ///
    /// "SHALL always have a value: No" — a component the certificate does not
    /// carry must emit NOTHING. Emitting an empty string would put a value on
    /// the wire that is not in the certificate, which is the mistake `Digest`
    /// is careful to avoid.
    #[test]
    fn certificate_attributes_repeat_per_value_and_stay_absent_when_unset() {
        let mut rec = ObjectRecord::default();
        rec.certificate_subject = Some(crate::kmip30::CertificateNames {
            cn: vec!["multi.example".into()],
            ou: vec!["Engineering".into(), "Cryptography".into()],
            dn: Some("CN=multi.example,OU=Cryptography,OU=Engineering".into()),
            ..Default::default()
        });
        rec.certificate_issuer = Some(crate::kmip30::CertificateNames {
            cn: vec!["Issuing CA".into()],
            ..Default::default()
        });

        let attrs = attributes_from_record(&rec);
        let names: Vec<&str> = attrs.iter().map(canonical_attribute_name).collect();

        assert_eq!(
            names.iter().filter(|n| **n == "CertificateSubjectOU").count(),
            2,
            "two OU values must yield two Certificate Subject OU attributes, not one"
        );
        assert_eq!(names.iter().filter(|n| **n == "CertificateSubjectCN").count(), 1);
        assert_eq!(names.iter().filter(|n| **n == "CertificateSubjectDN").count(), 1);
        assert_eq!(
            names.iter().filter(|n| **n == "CertificateIssuerCN").count(),
            1,
            "the Issuer side projects independently of the Subject side"
        );

        for absent in [
            "CertificateSubjectO", "CertificateSubjectEmail", "CertificateSubjectC",
            "CertificateSubjectST", "CertificateSubjectL", "CertificateSubjectUID",
            "CertificateSubjectSerialNumber", "CertificateSubjectTitle",
            "CertificateSubjectDC", "CertificateSubjectDNQualifier",
            "CertificateIssuerOU", "CertificateIssuerDN",
        ] {
            assert!(
                !names.contains(&absent),
                "{absent} is not in the certificate, so §4.6 says emit nothing — \
                 an empty value would be a fabricated attribute"
            );
        }

        // An object that is not a certificate contributes neither Name.
        let plain = attributes_from_record(&ObjectRecord::default());
        let plain_names: Vec<&str> = plain.iter().map(canonical_attribute_name).collect();
        assert!(
            !plain_names.iter().any(|n| n.starts_with("Certificate Subject")
                || n.starts_with("CertificateSubject")
                || n.starts_with("CertificateIssuer")),
            "a non-certificate object must project no §4.6 attributes at all"
        );
    }
}
