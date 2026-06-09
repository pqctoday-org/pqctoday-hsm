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
        fail_err(deps, correlation_id, "GetAttributeList", KmipError::not_found(&req.uid))
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

    // Names mirror what `attributes_from_record` returns.
    let mut names = vec![
        "Unique Identifier".to_string(),
        "Object Type".to_string(),
        "Cryptographic Algorithm".to_string(),
        "Cryptographic Usage Mask".to_string(),
        "State".to_string(),
    ];
    if obj.cryptographic_length > 0 {
        names.push("Cryptographic Length".into());
    }

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
        }).unwrap();

        let r = get_attribute_list(&d, GetAttributeListRequest { uid: "u".into() }, "c").unwrap();
        assert!(r.attribute_references.contains(&"Cryptographic Algorithm".to_string()));
        assert!(r.attribute_references.contains(&"State".to_string()));
        assert!(r.attribute_references.contains(&"Cryptographic Length".to_string()));
    }
}
