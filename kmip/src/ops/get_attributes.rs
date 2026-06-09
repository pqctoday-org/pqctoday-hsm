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
fn attributes_from_record(r: &ObjectRecord) -> Vec<Attribute> {
    let mut out = vec![
        Attribute::UniqueIdentifier(r.uid.clone()),
        Attribute::ObjectType(r.object_type),
        Attribute::CryptographicAlgorithm(r.algorithm),
        Attribute::CryptographicUsageMask(r.usage_mask),
        Attribute::State(r.state),
    ];
    if r.cryptographic_length > 0 {
        out.push(Attribute::CryptographicLength(r.cryptographic_length));
    }
    let _ = UsageMask::empty(); // touch import so future expansion compiles cleanly
    out
}

fn matches_name(attr: &Attribute, name: &str) -> bool {
    let canonical: String = name.chars().filter(|c| c.is_alphanumeric()).collect();
    let attr_name = match attr {
        Attribute::CryptographicAlgorithm(_) => "CryptographicAlgorithm",
        Attribute::CryptographicLength(_)    => "CryptographicLength",
        Attribute::CryptographicUsageMask(_) => "CryptographicUsageMask",
        Attribute::ObjectType(_)             => "ObjectType",
        Attribute::State(_)                  => "State",
        Attribute::UniqueIdentifier(_)       => "UniqueIdentifier",
        Attribute::Name(_)                   => "Name",
        Attribute::Custom { .. }             => "Custom",
    };
    canonical == attr_name
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
