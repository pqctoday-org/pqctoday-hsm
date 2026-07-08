//! KMIP 3.0 §6.1.22 **GetAttributeList** operation.
//!
//! Enumerates the names of attributes available on an object without
//! returning their values. Mirrors `GetAttributes`'s attribute set —
//! see `get_attributes.rs::attributes_from_record`.

use std::collections::HashMap;
use time::OffsetDateTime;

use crate::error::{KmipError, Result};
use crate::kmip30::{GetAttributeListRequest, GetAttributeListResponse};
use crate::policy::{Decision, PolicyRequest};

use super::deps::Deps;
use super::helpers::{canonical_name, emit_request, emit_success, fail_err, state_name};

pub fn get_attribute_list(
    deps: &Deps,
    req: GetAttributeListRequest,
    correlation_id: &str,
) -> Result<GetAttributeListResponse> {
    let started = OffsetDateTime::now_utc();
    emit_request(
        deps,
        correlation_id,
        "GetAttributeList",
        format!("uid={}", req.uid),
    );

    let obj = deps.store.get(&req.uid)?.ok_or_else(|| {
        fail_err(deps, correlation_id, "GetAttributeList", KmipError::object_not_found(&req.uid))
    })?;

    let empty: HashMap<String, String> = HashMap::new();
    let algo = canonical_name(obj.algorithm);
    let mut p_req = PolicyRequest::minimal(
        "GetAttributeList",
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
            "GetAttributeList",
            KmipError::permission_denied(human),
        ));
    }

    // Names mirror what `attributes_from_record` returns. Per KMIP
    // Profiles v3.0 §4.1.2 item 5, order doesn't matter — clients must
    // accept any permutation.
    let mut names = vec![
        "Unique Identifier".to_string(),
        "Object Type".to_string(),
        "Cryptographic Algorithm".to_string(),
        "Cryptographic Usage Mask".to_string(),
        "State".to_string(),
        "Initial Date".to_string(),
    ];
    if obj.cryptographic_length > 0 {
        names.push("Cryptographic Length".into());
    }
    if obj.name.is_some()                          { names.push("Name".into()); }
    if obj.activation_date.is_some()               { names.push("Activation Date".into()); }
    if obj.deactivation_date.is_some()             { names.push("Deactivation Date".into()); }
    if obj.destroy_date.is_some()                  { names.push("Destroy Date".into()); }
    if obj.compromise_date.is_some()               { names.push("Compromise Date".into()); }
    if obj.compromise_occurrence_date.is_some()    { names.push("Compromise Occurrence Date".into()); }
    // Last Change Date + Original Creation Date are always emitted
    // below in the "always present" baseline section.
    if obj.process_start_date.is_some()            { names.push("Process Start Date".into()); }
    if obj.protect_stop_date.is_some()             { names.push("Protect Stop Date".into()); }
    if obj.rotate_date.is_some()                   { names.push("Rotate Date".into()); }
    // KMIP 3.0 §11 — Sensitive / Extractable / AlwaysSensitive /
    // NeverExtractable / Fresh are mandatory on every managed object
    // (defaulted in `get_attributes::attributes_from_record`); the
    // attribute-LIST surface must mirror what GetAttributes returns.
    names.push("Sensitive".into());
    names.push("Always Sensitive".into());
    names.push("Extractable".into());
    names.push("Never Extractable".into());
    names.push("Fresh".into());
    if obj.key_value_present.is_some()             { names.push("Key Value Present".into()); }
    if obj.quantum_safe.is_some()                  { names.push("Quantum Safe".into()); }
    if obj.rotate_automatic.is_some()              { names.push("Rotate Automatic".into()); }
    if obj.short_unique_identifier.is_some()       { names.push("Short Unique Identifier".into()); }
    if obj.alternative_name.is_some()              { names.push("Alternative Name".into()); }
    if obj.comment.is_some()                       { names.push("Comment".into()); }
    if obj.description.is_some()                   { names.push("Description".into()); }
    if obj.contact_information.is_some()           { names.push("Contact Information".into()); }
    // §4.9 — genuine omission found via the OASIS TL-M-3 conformance
    // transcript (Honest-Maximum Phase 2.1): ObjectRecord already tracks
    // this (`application_specific_information`, set at Create/Register
    // time), GetAttributes already surfaces it
    // (`get_attributes.rs::attributes_from_record`), but this
    // GetAttributeList name surface never checked for it.
    if obj.application_specific_information.is_some() { names.push("Application Specific Information".into()); }
    // Object Class / Lease Time / Key Format Type / Digest /
    // Random Number Generator / Last Change Date are always
    // surfaced by GetAttributes — mirror them here.
    names.push("Object Class".into());
    if obj.key_value_location.is_some()            { names.push("Key Value Location".into()); }
    if obj.x509_certificate_identifier.is_some()   { names.push("X.509 Certificate Identifier".into()); }
    if obj.x509_certificate_issuer.is_some()       { names.push("X.509 Certificate Issuer".into()); }
    if obj.x509_certificate_subject.is_some()      { names.push("X.509 Certificate Subject".into()); }
    if obj.rotate_name.is_some()                   { names.push("Rotate Name".into()); }
    if obj.certificate_type.is_some()              { names.push("Certificate Type".into()); }
    if obj.digital_signature_algorithm.is_some()   { names.push("Digital Signature Algorithm".into()); }
    if obj.nist_key_type.is_some()                 { names.push("NIST Key Type".into()); }
    if obj.protection_level.is_some()              { names.push("Protection Level".into()); }
    if obj.revocation_reason_code.is_some()        { names.push("Revocation Reason".into()); }
    if obj.deactivation_reason_code.is_some()      { names.push("Deactivation Reason".into()); }
    names.push("Key Format Type".into());
    // K-14 — `Digest` is only surfaced when the server actually holds
    // (or can compute) a digest of the real key material; mirrors the
    // GetAttributes omission rule.
    if super::get_attributes::record_digest(&obj).is_some() {
        names.push("Digest".into());
    }
    names.push("Random Number Generator".into());
    names.push("Last Change Date".into());
    names.push("Original Creation Date".into());
    names.push("Short Unique Identifier".into());
    names.push("Protection Storage Mask".into());
    if obj.certificate_length.is_some()            { names.push("Certificate Length".into()); }
    names.push("Lease Time".into());
    if obj.protection_period.is_some()             { names.push("Protection Period".into()); }
    if obj.rotate_interval.is_some()               { names.push("Rotate Interval".into()); }
    if obj.rotate_offset.is_some()                 { names.push("Rotate Offset".into()); }
    if obj.rotate_generation.is_some()             { names.push("Rotate Generation".into()); }
    if obj.usage_limits_total.is_some()            { names.push("Usage Limits".into()); }
    // K-15 — every stored link type appears in the name surface,
    // mirroring `attributes_from_record`'s full-links emission.
    {
        let mut link_keys: Vec<&String> = obj.links.keys().collect();
        link_keys.sort();
        for k in link_keys { names.push(k.clone()); }
    }
    for k in obj.custom_attributes.keys() { names.push(k.clone()); }

    emit_success(deps, correlation_id, "GetAttributeList");
    Ok(GetAttributeListResponse {
        uid: req.uid,
        attribute_references: names,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditlog::{AuditSink, RingSink};
    use crate::kmip30::{KmipAlgorithm, ObjectType, State, UsageMask};
    use crate::policy::{load_from_str, Engine};
    use crate::store::{MemoryStore, ObjectRecord};
    use std::sync::Arc;

    #[test]
    fn lists_standard_attributes() {
        let ring = Arc::new(RingSink::new(64));
        let sink: Arc<dyn AuditSink> = ring.clone();
        let engine = Engine::with_global_sink(sink.clone());
        engine.activate(load_from_str(
            "schema_version: 1\nmetadata: {name: t, description: t, authority: t, effective: always}\nrules: []\n",
            std::path::Path::new("<t>"),
        ).unwrap()).unwrap();
        let d = Deps::new(engine, Arc::new(MemoryStore::new()), sink, super::super::deps::DepsConfig::default());
        d.store.put(ObjectRecord {
            uid: "u".into(),
            object_type: ObjectType::SymmetricKey,
            algorithm: KmipAlgorithm::Aes,
            cryptographic_length: 128,
            usage_mask: UsageMask::ENCRYPT,
            state: State::Active,
            pkcs11_cka_id: vec![],
            pkcs11_slot: 0,
            initial_date: OffsetDateTime::UNIX_EPOCH,
            activation_date: None,
            supersedes: None,
            name: None,

            links: std::collections::HashMap::new(),

            custom_attributes: std::collections::HashMap::new(),


            key_material: None,


            key_format_type: None,
        ..ObjectRecord::default()
}).unwrap();

        let r = get_attribute_list(&d, GetAttributeListRequest { uid: "u".into() }, "c").unwrap();
        assert!(r.attribute_references.contains(&"Cryptographic Algorithm".to_string()));
        assert!(r.attribute_references.contains(&"State".to_string()));
        assert!(r.attribute_references.contains(&"Cryptographic Length".to_string()));
    }
}
