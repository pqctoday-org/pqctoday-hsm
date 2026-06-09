//! KMIP 3.0 Group C: Register / Import / Export.
//!
//! Spec mapping:
//!
//! - Register §6.1.48 — register a managed object the client created
//!   elsewhere; server assigns a UID (or honors a client-supplied one
//!   if not already in use).
//! - Import   §6.1.29 — like Register but the client always specifies
//!   the UID; ReplaceExisting flag controls overwrite semantics.
//! - Export   §6.1.22 — return a managed object + all of its
//!   attributes (richer than Get, which omits the attribute set).
//!
//! All three honor the spec-mandated error reasons listed in their
//! respective Error Handling tables.

use std::collections::HashMap;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{KmipError, Result, ResultReason};
use crate::kmip30::{
    Attribute, ExportRequest, ExportResponse, ImportRequest, ImportResponse, KeyBlock,
    KeyFormatType, ObjectType, RegisterRequest, RegisterResponse, State, UsageMask,
};
use crate::policy::{Decision, PolicyRequest};
use crate::store::ObjectRecord;

use super::deps::Deps;
use super::helpers::{canonical_name, emit_request, emit_success, fail_err};

// ── Register ───────────────────────────────────────────────────────────────

pub fn register(
    deps: &Deps,
    req: RegisterRequest,
    correlation_id: &str,
) -> Result<RegisterResponse> {
    let started = OffsetDateTime::now_utc();
    emit_request(
        deps,
        correlation_id,
        "Register",
        format!("object_type={:?} attrs={}", req.object_type, req.attributes.len()),
    );

    // Per §6.1.48 Table 395: if the object is cryptographic, certain
    // attributes are REQUIRED. CryptographicAlgorithm + Length may be
    // omitted only if encapsulated in the KeyBlock. Our handler accepts
    // either form.
    let (algorithm, length, usage_mask, name, supplied_uid) = extract_attributes(&req.attributes);

    let key_block = req.managed_object.as_ref();
    let resolved_algorithm = algorithm.or(key_block.map(|kb| kb.cryptographic_algorithm));
    let resolved_length = length.or(key_block.map(|kb| kb.cryptographic_length));

    // Plane-1 policy gate. Treat Register as Create from a policy POV —
    // the engine evaluates Algorithm + UsageMask the same way.
    let empty: HashMap<String, String> = HashMap::new();
    let algo_str = resolved_algorithm.map(canonical_name);
    let mut p_req = PolicyRequest::minimal(
        "Register",
        algo_str.as_deref(),
        started,
        correlation_id,
        &empty,
    );
    p_req.key_length = resolved_length;
    p_req.usage_mask = usage_mask;
    if let Decision::Deny { human, .. } = deps.engine.evaluate(&p_req) {
        return Err(fail_err(deps, correlation_id, "Register", KmipError::permission_denied(human)));
    }

    let kmip_algorithm = resolved_algorithm.ok_or_else(|| {
        fail_err(deps, correlation_id, "Register", KmipError::failed(
            ResultReason::MissingData,
            "Register requires CryptographicAlgorithm (in Attributes or KeyBlock)".to_string(),
        ))
    })?;

    // Per §6.1.48: honor a client-supplied UniqueIdentifier (must be
    // unique) — else allocate one.
    let uid = if let Some(client_uid) = supplied_uid {
        if deps.store.get(&client_uid)?.is_some() {
            return Err(fail_err(deps, correlation_id, "Register", KmipError::failed(
                ResultReason::ObjectAlreadyExists,
                format!("UID {client_uid:?} already exists"),
            )));
        }
        client_uid
    } else {
        format!("urn:pqctoday:obj:{}", Uuid::new_v4())
    };

    // Initial Date SHALL be set to current time per §6.1.48.
    let now = OffsetDateTime::now_utc();
    let key_material = key_block.map(|kb| kb.key_value.clone());
    let key_format_type = key_block.map(|kb| kb.key_format_type as u32);

    deps.store.put(ObjectRecord {
        uid: uid.clone(),
        object_type: req.object_type,
        algorithm: kmip_algorithm,
        cryptographic_length: resolved_length.unwrap_or(0),
        usage_mask: usage_mask.unwrap_or_else(UsageMask::empty),
        // §6.1.48 doesn't speak to lifecycle state on Register; the
        // sensible default per §3.x is PreActive — client follows with
        // Activate when ready.
        state: State::PreActive,
        pkcs11_cka_id: Uuid::new_v4().as_bytes().to_vec(),
        pkcs11_slot: deps.config.pkcs11_slot,
        initial_date: now,
        activation_date: None,
        supersedes: None,
        name,
        links: HashMap::new(),
        custom_attributes: HashMap::new(),
        key_material,
        key_format_type,
        ..ObjectRecord::default()
    })?;

    emit_success(deps, correlation_id, "Register");
    Ok(RegisterResponse { uid })
}

// ── Import ─────────────────────────────────────────────────────────────────

pub fn import_object(
    deps: &Deps,
    req: ImportRequest,
    correlation_id: &str,
) -> Result<ImportResponse> {
    let started = OffsetDateTime::now_utc();
    emit_request(
        deps,
        correlation_id,
        "Import",
        format!(
            "uid={} object_type={:?} replace={}",
            req.uid, req.object_type, req.replace_existing
        ),
    );

    let (algorithm, length, usage_mask, name, _) = extract_attributes(&req.attributes);
    let key_block = req.managed_object.as_ref();
    let resolved_algorithm = algorithm.or(key_block.map(|kb| kb.cryptographic_algorithm));
    let resolved_length = length.or(key_block.map(|kb| kb.cryptographic_length));

    let empty: HashMap<String, String> = HashMap::new();
    let algo_str = resolved_algorithm.map(canonical_name);
    let mut p_req = PolicyRequest::minimal(
        "Import",
        algo_str.as_deref(),
        started,
        correlation_id,
        &empty,
    );
    p_req.key_length = resolved_length;
    p_req.usage_mask = usage_mask;
    if let Decision::Deny { human, .. } = deps.engine.evaluate(&p_req) {
        return Err(fail_err(deps, correlation_id, "Import", KmipError::permission_denied(human)));
    }

    let kmip_algorithm = resolved_algorithm.ok_or_else(|| {
        fail_err(deps, correlation_id, "Import", KmipError::failed(
            ResultReason::MissingData,
            "Import requires CryptographicAlgorithm".to_string(),
        ))
    })?;

    // Per §6.1.29: "If absent or false [for ReplaceExisting] and an
    // object exists with the same Unique Identifier then an error
    // SHALL be returned."
    let existing = deps.store.get(&req.uid)?;
    if existing.is_some() {
        if req.replace_existing {
            deps.store.remove(&req.uid)?;
        } else {
            return Err(fail_err(deps, correlation_id, "Import", KmipError::failed(
                ResultReason::ObjectAlreadyExists,
                format!("UID {:?} already exists and ReplaceExisting was not set", req.uid),
            )));
        }
    }

    let now = OffsetDateTime::now_utc();
    let key_material = key_block.map(|kb| kb.key_value.clone());
    let key_format_type = key_block.map(|kb| kb.key_format_type as u32);

    deps.store.put(ObjectRecord {
        uid: req.uid.clone(),
        object_type: req.object_type,
        algorithm: kmip_algorithm,
        cryptographic_length: resolved_length.unwrap_or(0),
        usage_mask: usage_mask.unwrap_or_else(UsageMask::empty),
        state: State::PreActive,
        pkcs11_cka_id: Uuid::new_v4().as_bytes().to_vec(),
        pkcs11_slot: deps.config.pkcs11_slot,
        initial_date: now,
        activation_date: None,
        supersedes: None,
        name,
        links: HashMap::new(),
        custom_attributes: HashMap::new(),
        key_material,
        key_format_type,
        ..ObjectRecord::default()
    })?;

    emit_success(deps, correlation_id, "Import");
    Ok(ImportResponse { uid: req.uid })
}

// ── Export ─────────────────────────────────────────────────────────────────

pub fn export(
    deps: &Deps,
    req: ExportRequest,
    correlation_id: &str,
) -> Result<ExportResponse> {
    emit_request(deps, correlation_id, "Export", format!("uid={}", req.uid));

    let obj = deps.store.get(&req.uid)?.ok_or_else(|| {
        fail_err(deps, correlation_id, "Export", KmipError::not_found(&req.uid))
    })?;

    // Per §6.1.22: "If the Managed Object has been Destroyed then the
    // key material for the specified managed object SHALL not be
    // returned in the response." We still return the attributes —
    // only the KeyBlock is suppressed.
    let key_material = if matches!(obj.state, State::Destroyed | State::DestroyedCompromised) {
        None
    } else {
        obj.key_material.clone()
    };

    // Build the Attributes set the same way GetAttributes does — keep
    // this in sync if either side adds new attribute surfaces.
    let mut attributes = vec![
        Attribute::UniqueIdentifier(obj.uid.clone()),
        Attribute::ObjectType(obj.object_type),
        Attribute::CryptographicAlgorithm(obj.algorithm),
        Attribute::CryptographicUsageMask(obj.usage_mask),
        Attribute::State(obj.state),
    ];
    if obj.cryptographic_length > 0 {
        attributes.push(Attribute::CryptographicLength(obj.cryptographic_length));
    }
    if let Some(name) = &obj.name {
        attributes.push(Attribute::Name(name.clone()));
    }

    let managed_object = key_material.map(|bytes| KeyBlock {
        key_format_type: match obj.key_format_type {
            Some(0x01) | None => KeyFormatType::Raw,
            Some(_)           => KeyFormatType::Raw,
        },
        cryptographic_algorithm: obj.algorithm,
        cryptographic_length: obj.cryptographic_length,
        key_value: bytes,
    });

    emit_success(deps, correlation_id, "Export");
    Ok(ExportResponse {
        object_type: obj.object_type,
        uid: req.uid,
        attributes,
        managed_object,
    })
}

// ── Helpers ────────────────────────────────────────────────────────────────

/// Pull algorithm / length / usage mask / name / UID out of the
/// request's Attributes block. Returned tuple ordering mirrors the
/// spec's Table 395 (Register Attribute Requirements).
fn extract_attributes(
    attrs: &[Attribute],
) -> (Option<crate::kmip30::KmipAlgorithm>, Option<u32>, Option<UsageMask>, Option<String>, Option<String>) {
    let mut algorithm = None;
    let mut length = None;
    let mut usage = None;
    let mut name = None;
    let mut uid = None;
    for a in attrs {
        match a {
            Attribute::CryptographicAlgorithm(alg) => algorithm = Some(*alg),
            Attribute::CryptographicLength(n)      => length = Some(*n),
            Attribute::CryptographicUsageMask(m)   => usage = Some(*m),
            Attribute::Name(n)                     => name = Some(n.clone()),
            Attribute::UniqueIdentifier(u)         => uid = Some(u.clone()),
            _ => {}
        }
    }
    (algorithm, length, usage, name, uid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditlog::{AuditSink, RingSink};
    use crate::kmip30::KmipAlgorithm;
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

    fn raw_aes128_kb() -> KeyBlock {
        KeyBlock {
            key_format_type: KeyFormatType::Raw,
            cryptographic_algorithm: KmipAlgorithm::Aes,
            cryptographic_length: 128,
            key_value: vec![0x01; 16],
        }
    }

    #[test]
    fn register_persists_record_with_uid_and_key_bytes() {
        let d = deps_with();
        let resp = register(&d, RegisterRequest {
            object_type: ObjectType::SymmetricKey,
            attributes: vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes),
                Attribute::CryptographicLength(128),
                Attribute::CryptographicUsageMask(UsageMask::ENCRYPT | UsageMask::DECRYPT),
                Attribute::Name("test".into()),
            ],
            managed_object: Some(raw_aes128_kb()),
            protection_storage_masks: None,
        }, "c").unwrap();
        let rec = d.store.get(&resp.uid).unwrap().unwrap();
        assert_eq!(rec.algorithm, KmipAlgorithm::Aes);
        assert_eq!(rec.cryptographic_length, 128);
        assert_eq!(rec.name.as_deref(), Some("test"));
        assert_eq!(rec.key_material.as_deref(), Some(&[0x01; 16][..]));
    }

    #[test]
    fn register_with_client_uid_rejects_duplicate() {
        let d = deps_with();
        let req = || RegisterRequest {
            object_type: ObjectType::SymmetricKey,
            attributes: vec![
                Attribute::UniqueIdentifier("urn:fixed".into()),
                Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes),
                Attribute::CryptographicLength(128),
                Attribute::CryptographicUsageMask(UsageMask::ENCRYPT),
            ],
            managed_object: Some(raw_aes128_kb()),
            protection_storage_masks: None,
        };
        let resp = register(&d, req(), "c").unwrap();
        assert_eq!(resp.uid, "urn:fixed");
        let err = register(&d, req(), "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::ObjectAlreadyExists);
    }

    #[test]
    fn import_rejects_existing_uid_without_replace() {
        let d = deps_with();
        // First create via Register.
        register(&d, RegisterRequest {
            object_type: ObjectType::SymmetricKey,
            attributes: vec![
                Attribute::UniqueIdentifier("u".into()),
                Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes),
                Attribute::CryptographicLength(128),
                Attribute::CryptographicUsageMask(UsageMask::ENCRYPT),
            ],
            managed_object: Some(raw_aes128_kb()),
            protection_storage_masks: None,
        }, "c").unwrap();

        let err = import_object(&d, ImportRequest {
            uid: "u".into(),
            object_type: ObjectType::SymmetricKey,
            replace_existing: false,
            key_wrap_type: None,
            attributes: vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes),
                Attribute::CryptographicUsageMask(UsageMask::ENCRYPT),
            ],
            managed_object: Some(raw_aes128_kb()),
        }, "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::ObjectAlreadyExists);
    }

    #[test]
    fn import_with_replace_overwrites_existing() {
        let d = deps_with();
        register(&d, RegisterRequest {
            object_type: ObjectType::SymmetricKey,
            attributes: vec![
                Attribute::UniqueIdentifier("u".into()),
                Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes),
                Attribute::CryptographicLength(128),
                Attribute::CryptographicUsageMask(UsageMask::ENCRYPT),
            ],
            managed_object: Some(raw_aes128_kb()),
            protection_storage_masks: None,
        }, "c").unwrap();

        let new_kb = KeyBlock { key_value: vec![0xAA; 16], ..raw_aes128_kb() };
        import_object(&d, ImportRequest {
            uid: "u".into(),
            object_type: ObjectType::SymmetricKey,
            replace_existing: true,
            key_wrap_type: None,
            attributes: vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes),
                Attribute::CryptographicUsageMask(UsageMask::ENCRYPT),
            ],
            managed_object: Some(new_kb),
        }, "c").unwrap();

        let rec = d.store.get("u").unwrap().unwrap();
        assert_eq!(rec.key_material.unwrap(), vec![0xAA; 16]);
    }

    #[test]
    fn export_returns_attributes_and_key_material() {
        let d = deps_with();
        let r = register(&d, RegisterRequest {
            object_type: ObjectType::SymmetricKey,
            attributes: vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes),
                Attribute::CryptographicLength(128),
                Attribute::CryptographicUsageMask(UsageMask::ENCRYPT),
                Attribute::Name("named".into()),
            ],
            managed_object: Some(raw_aes128_kb()),
            protection_storage_masks: None,
        }, "c").unwrap();
        let exp = export(&d, ExportRequest {
            uid: r.uid.clone(),
            key_format_type: None,
            key_wrap_type: None,
            key_compression_type: None,
        }, "c").unwrap();
        assert_eq!(exp.uid, r.uid);
        assert_eq!(exp.object_type, ObjectType::SymmetricKey);
        assert!(exp.attributes.iter().any(|a| matches!(a, Attribute::Name(n) if n == "named")));
        assert!(exp.managed_object.is_some());
    }

    #[test]
    fn export_on_destroyed_omits_key_material() {
        let d = deps_with();
        let r = register(&d, RegisterRequest {
            object_type: ObjectType::SymmetricKey,
            attributes: vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes),
                Attribute::CryptographicLength(128),
                Attribute::CryptographicUsageMask(UsageMask::ENCRYPT),
            ],
            managed_object: Some(raw_aes128_kb()),
            protection_storage_masks: None,
        }, "c").unwrap();
        // Force Destroyed state via store.
        let mut rec = d.store.get(&r.uid).unwrap().unwrap();
        rec.state = State::Destroyed;
        d.store.update(rec).unwrap();
        let exp = export(&d, ExportRequest {
            uid: r.uid,
            key_format_type: None,
            key_wrap_type: None,
            key_compression_type: None,
        }, "c").unwrap();
        assert!(exp.managed_object.is_none(), "Destroyed objects MUST NOT return key material");
    }
}
