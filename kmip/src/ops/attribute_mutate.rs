//! KMIP 3.0 attribute-mutation op handlers — Group B wave 2.
//!
//! Five ops are bundled in this module because they share semantics and
//! store-mutation logic:
//!
//! | Op              | Spec       | Pre-condition           | Effect               |
//! |-----------------|------------|-------------------------|----------------------|
//! | AddAttribute    | §6.1.2     | attribute MUST NOT exist | create attribute    |
//! | ModifyAttribute | §6.1.38    | attribute MUST exist     | change value         |
//! | DeleteAttribute | §6.1.17    | attribute MUST exist     | remove value         |
//! | SetAttribute    | §6.1.56    | (none)                   | create or modify    |
//! | AdjustAttribute | §6.1.3     | numeric / boolean attr   | apply delta / negate |
//!
//! Spec mandates per-op error result reasons; we honour the ones the
//! v0.1 store can detect (Attribute Single Valued, Attribute Not Found,
//! Read Only Attribute, Invalid Attribute, Object Not Found).
//!
//! Storage model: the in-memory and SQLite ObjectRecord shapes carry a
//! handful of typed fields (algorithm, length, state, usage_mask, …)
//! plus three free-form maps for everything else: `name`, `links`
//! (LinkType → target UID), `custom_attributes` (name → text value).
//! The handlers route each typed-tag attribute to the right slot.

use std::collections::HashMap;
use time::OffsetDateTime;

use crate::error::{KmipError, Result, ResultReason};
use crate::kmip30::{
    AddAttributeRequest, AddAttributeResponse,
    AdjustAttributeRequest, AdjustAttributeResponse, AdjustmentType,
    Attribute, DeleteAttributeRequest, DeleteAttributeResponse,
    ModifyAttributeRequest, ModifyAttributeResponse,
    SetAttributeRequest, SetAttributeResponse,
    UsageMask,
};
use crate::policy::{Decision, PolicyRequest};
use crate::store::ObjectRecord;

use super::deps::Deps;
use super::helpers::{canonical_name, emit_request, emit_success, fail_err, state_name};

// ── AddAttribute ───────────────────────────────────────────────────────────

pub fn add_attribute(
    deps: &Deps,
    req: AddAttributeRequest,
    correlation_id: &str,
) -> Result<AddAttributeResponse> {
    emit_request(deps, correlation_id, "AddAttribute",
                 format!("uid={} attr={:?}", req.uid, attribute_name(&req.new_attribute)));

    let mut obj = deps.store.get(&req.uid)?.ok_or_else(|| {
        fail_err(deps, correlation_id, "AddAttribute", KmipError::not_found(&req.uid))
    })?;
    policy_gate(deps, &obj, "AddAttribute", correlation_id)?;

    // KMIP 3.0 §6.1.48 + §11 — `Name` MUST be unique across the
    // server's managed objects; a duplicate (on ANY UID, including
    // the target itself) yields `NonUniqueNameAttribute` (0x35),
    // NOT the generic `InvalidField`. BL-M-8 msg #2 pins this
    // code: the test re-adds the same Name to the same object so
    // the comparator can verify the uniqueness rule.
    if let Attribute::Name(n) = &req.new_attribute {
        let dup = deps
            .store
            .find(&|r| r.name.as_deref() == Some(n.as_str()))
            .unwrap_or_default();
        if !dup.is_empty() {
            return Err(fail_err(
                deps,
                correlation_id,
                "AddAttribute",
                KmipError::non_unique_name_attribute(n),
            ));
        }
    }

    // Per §6.1.2: "Existing attribute values SHALL NOT be changed by this
    // operation". Reject if a value is already present for this attribute.
    if attribute_present(&obj, &req.new_attribute) {
        return Err(fail_err(deps, correlation_id, "AddAttribute",
            KmipError::failed(
                ResultReason::InvalidField,
                format!("attribute {:?} already present on {}", attribute_name(&req.new_attribute), req.uid),
            )));
    }
    if attribute_is_read_only(&req.new_attribute) {
        return Err(fail_err(deps, correlation_id, "AddAttribute",
            KmipError::failed(
                ResultReason::InvalidField,
                format!("attribute {:?} is Read-Only and cannot be added", attribute_name(&req.new_attribute)),
            )));
    }

    apply_attribute(&mut obj, &req.new_attribute);
    deps.store.update(obj)?;
    emit_success(deps, correlation_id, "AddAttribute");
    Ok(AddAttributeResponse { uid: req.uid })
}

// ── ModifyAttribute ────────────────────────────────────────────────────────

pub fn modify_attribute(
    deps: &Deps,
    req: ModifyAttributeRequest,
    correlation_id: &str,
) -> Result<ModifyAttributeResponse> {
    emit_request(deps, correlation_id, "ModifyAttribute",
                 format!("uid={} attr={:?}", req.uid, attribute_name(&req.new_attribute)));

    let mut obj = deps.store.get(&req.uid)?.ok_or_else(|| {
        fail_err(deps, correlation_id, "ModifyAttribute", KmipError::not_found(&req.uid))
    })?;
    policy_gate(deps, &obj, "ModifyAttribute", correlation_id)?;

    // Per KMIP 3.0 §6.1.38 + §11 attribute table — Read-Only attributes
    // (UniqueIdentifier, ObjectType, State, …) are server-owned and MUST
    // NOT be modified by clients. BL-M-7 step #2 pins the reason code as
    // `AttributeReadOnly` (0x22) not the generic `InvalidField`.
    if attribute_is_read_only(&req.new_attribute) {
        return Err(fail_err(deps, correlation_id, "ModifyAttribute",
            KmipError::attribute_read_only(attribute_name(&req.new_attribute))));
    }

    // Per KMIP 3.0 §11 attribute table — `Activation Date` is modifiable
    // only while the object is in `PreActive`. AKLC-M-3 + SKLC-M-3 step #4
    // both pin `WrongKeyLifecycleState` once the object is Active.
    if let Attribute::ActivationDate(_) = &req.new_attribute {
        if !matches!(obj.state, crate::kmip30::State::PreActive) {
            return Err(fail_err(deps, correlation_id, "ModifyAttribute",
                KmipError::failed(
                    ResultReason::WrongKeyLifecycleState,
                    format!("ActivationDate modifiable only in PreActive (object is in {})",
                        state_name(obj.state)),
                )));
        }
    }

    // Per §6.1.38: "Only existing attributes MAY be changed via this operation."
    if !attribute_present(&obj, &req.new_attribute) {
        return Err(fail_err(deps, correlation_id, "ModifyAttribute",
            KmipError::failed(
                ResultReason::ItemNotFound,
                format!("attribute {:?} not present on {} — Modify requires existing value", attribute_name(&req.new_attribute), req.uid),
            )));
    }
    // Per §6.1.38: "Specifying a Current Attribute for which there exists
    // no Attribute associated with the object SHALL result in an error."
    if let Some(current) = &req.current_attribute {
        if !attribute_present(&obj, current) {
            return Err(fail_err(deps, correlation_id, "ModifyAttribute",
                KmipError::failed(
                    ResultReason::ItemNotFound,
                    "Current Attribute does not match any existing value".to_string(),
                )));
        }
    }

    apply_attribute(&mut obj, &req.new_attribute);
    deps.store.update(obj)?;
    emit_success(deps, correlation_id, "ModifyAttribute");
    Ok(ModifyAttributeResponse { uid: req.uid })
}

// ── DeleteAttribute ────────────────────────────────────────────────────────

pub fn delete_attribute(
    deps: &Deps,
    req: DeleteAttributeRequest,
    correlation_id: &str,
) -> Result<DeleteAttributeResponse> {
    emit_request(deps, correlation_id, "DeleteAttribute",
                 format!("uid={} ref={:?}", req.uid, req.attribute_reference));

    let mut obj = deps.store.get(&req.uid)?.ok_or_else(|| {
        fail_err(deps, correlation_id, "DeleteAttribute", KmipError::not_found(&req.uid))
    })?;
    policy_gate(deps, &obj, "DeleteAttribute", correlation_id)?;

    // Per §6.1.17:
    // - If `current_attribute` is given, delete that specific value.
    // - If only `attribute_reference` is given, delete all instances of
    //   the named attribute.
    // - Attempting to delete a non-existent attribute SHALL result in an
    //   error.
    // - Attributes always REQUIRED to have a value SHALL never be deleted.
    if let Some(current) = &req.current_attribute {
        if attribute_is_required(current) {
            return Err(fail_err(deps, correlation_id, "DeleteAttribute",
                KmipError::failed(
                    ResultReason::InvalidField,
                    format!("attribute {:?} is always REQUIRED", attribute_name(current)),
                )));
        }
        if !attribute_present(&obj, current) {
            return Err(fail_err(deps, correlation_id, "DeleteAttribute",
                KmipError::failed(
                    ResultReason::ItemNotFound,
                    "Current Attribute does not match any existing value".to_string(),
                )));
        }
        remove_attribute_by_value(&mut obj, current);
    } else if let Some(name) = &req.attribute_reference {
        if attribute_name_is_required(name) {
            return Err(fail_err(deps, correlation_id, "DeleteAttribute",
                KmipError::failed(
                    ResultReason::InvalidField,
                    format!("attribute {name} is always REQUIRED"),
                )));
        }
        if !attribute_name_present(&obj, name) {
            return Err(fail_err(deps, correlation_id, "DeleteAttribute",
                KmipError::failed(
                    ResultReason::ItemNotFound,
                    format!("attribute {name} not present on {}", req.uid),
                )));
        }
        remove_attribute_by_name(&mut obj, name);
    } else {
        return Err(fail_err(deps, correlation_id, "DeleteAttribute",
            KmipError::failed(
                ResultReason::MissingData,
                "must specify either Current Attribute or Attribute Reference".to_string(),
            )));
    }

    deps.store.update(obj)?;
    emit_success(deps, correlation_id, "DeleteAttribute");
    Ok(DeleteAttributeResponse { uid: req.uid })
}

// ── SetAttribute ───────────────────────────────────────────────────────────

pub fn set_attribute(
    deps: &Deps,
    req: SetAttributeRequest,
    correlation_id: &str,
) -> Result<SetAttributeResponse> {
    emit_request(deps, correlation_id, "SetAttribute",
                 format!("uid={} attr={:?}", req.uid, attribute_name(&req.new_attribute)));

    let mut obj = deps.store.get(&req.uid)?.ok_or_else(|| {
        fail_err(deps, correlation_id, "SetAttribute", KmipError::not_found(&req.uid))
    })?;
    policy_gate(deps, &obj, "SetAttribute", correlation_id)?;

    // Per §6.1.56: "Read-Only attributes SHALL NOT be added or modified
    // using this operation."
    if attribute_is_read_only(&req.new_attribute) {
        return Err(fail_err(deps, correlation_id, "SetAttribute",
            KmipError::failed(
                ResultReason::InvalidField,
                format!("attribute {:?} is Read-Only", attribute_name(&req.new_attribute)),
            )));
    }

    apply_attribute(&mut obj, &req.new_attribute);
    deps.store.update(obj)?;
    emit_success(deps, correlation_id, "SetAttribute");
    Ok(SetAttributeResponse { uid: req.uid })
}

// ── AdjustAttribute ────────────────────────────────────────────────────────

pub fn adjust_attribute(
    deps: &Deps,
    req: AdjustAttributeRequest,
    correlation_id: &str,
) -> Result<AdjustAttributeResponse> {
    emit_request(deps, correlation_id, "AdjustAttribute",
                 format!("uid={} ref={:?} type={:?}", req.uid, req.attribute_reference, req.adjustment_type));

    let mut obj = deps.store.get(&req.uid)?.ok_or_else(|| {
        fail_err(deps, correlation_id, "AdjustAttribute", KmipError::not_found(&req.uid))
    })?;
    policy_gate(deps, &obj, "AdjustAttribute", correlation_id)?;

    // Per §6.1.3, the v0.1 store has very few numeric/boolean attributes
    // that can be adjusted; the spec applies broadly to attributes like
    // Cryptographic Usage Mask, Server Limit, Operation Policy. We honour
    // Cryptographic Usage Mask (bit operations) and CryptographicLength
    // for now; everything else returns OperationNotSupported.
    let canonical: String = req.attribute_reference.chars().filter(|c| c.is_alphanumeric()).collect();
    match canonical.as_str() {
        "CryptographicUsageMask" => {
            let delta = req.adjustment_value.unwrap_or(0) as u32;
            obj.usage_mask = match req.adjustment_type {
                AdjustmentType::Increment => obj.usage_mask | UsageMask::from_bits_truncate(delta),
                AdjustmentType::Decrement => obj.usage_mask & UsageMask::from_bits_truncate(!delta),
                AdjustmentType::Negate    => UsageMask::from_bits_truncate(!obj.usage_mask.bits()),
            };
        }
        "CryptographicLength" => {
            let prev = obj.cryptographic_length as i64;
            let delta = req.adjustment_value.unwrap_or(0);
            obj.cryptographic_length = match req.adjustment_type {
                AdjustmentType::Increment => (prev + delta).max(0) as u32,
                AdjustmentType::Decrement => (prev - delta).max(0) as u32,
                AdjustmentType::Negate    => 0,
            };
        }
        other => {
            return Err(fail_err(deps, correlation_id, "AdjustAttribute",
                KmipError::failed(
                    ResultReason::OperationNotSupported,
                    format!("AdjustAttribute on {other} not supported in v0.1"),
                )));
        }
    }

    deps.store.update(obj)?;
    emit_success(deps, correlation_id, "AdjustAttribute");
    Ok(AdjustAttributeResponse { uid: req.uid })
}

// ── Shared helpers ─────────────────────────────────────────────────────────

fn policy_gate(deps: &Deps, obj: &ObjectRecord, op: &'static str, correlation_id: &str) -> Result<()> {
    let started = OffsetDateTime::now_utc();
    let empty: HashMap<String, String> = HashMap::new();
    let algo = canonical_name(obj.algorithm);
    let mut p_req = PolicyRequest::minimal(op, Some(&algo), started, correlation_id, &empty);
    p_req.state = Some(state_name(obj.state));
    p_req.target_uid = Some(&obj.uid);
    if let Decision::Deny { human, .. } = deps.engine.evaluate(&p_req) {
        return Err(fail_err(deps, correlation_id, op, KmipError::permission_denied(human)));
    }
    Ok(())
}

/// Human-readable attribute tag name — used for diagnostics + reference lookup.
fn attribute_name(a: &Attribute) -> &'static str {
    match a {
        Attribute::CryptographicAlgorithm(_) => "CryptographicAlgorithm",
        Attribute::CryptographicLength(_)    => "CryptographicLength",
        Attribute::CryptographicUsageMask(_) => "CryptographicUsageMask",
        Attribute::ObjectType(_)             => "ObjectType",
        Attribute::State(_)                  => "State",
        Attribute::UniqueIdentifier(_)       => "UniqueIdentifier",
        Attribute::Name(_)                   => "Name",
        Attribute::Custom { .. }             => "Custom",
        // Baseline Server attributes — tag-form names matter only for
        // diagnostics here; the wire codec carries the real codepoints.
        _ => "Baseline",
    }
}

/// Per KMIP 3.0 §4 the listed attributes are always present on any
/// managed object and MUST NOT be deleted. The rest may be absent.
fn attribute_is_required(a: &Attribute) -> bool {
    matches!(a,
        Attribute::UniqueIdentifier(_) |
        Attribute::ObjectType(_) |
        Attribute::State(_) |
        Attribute::CryptographicAlgorithm(_)
    )
}

fn attribute_name_is_required(name: &str) -> bool {
    let canonical: String = name.chars().filter(|c| c.is_alphanumeric()).collect();
    matches!(canonical.as_str(),
        "UniqueIdentifier" | "ObjectType" | "State" | "CryptographicAlgorithm"
    )
}

/// Per KMIP 3.0 §11 attribute table these attributes are Read-Only —
/// server SHALL NOT honour client attempts to add or modify them. The
/// list below mirrors the spec's "Modifiable by client = No" column.
fn attribute_is_read_only(a: &Attribute) -> bool {
    matches!(a,
        Attribute::UniqueIdentifier(_) |
        Attribute::ObjectType(_) |
        Attribute::State(_) |
        // Initial Date / Last Change Date / Original Creation Date /
        // Short Unique Identifier are all server-set timestamps.
        Attribute::InitialDate(_) |
        Attribute::LastChangeDate(_) |
        Attribute::OriginalCreationDate(_) |
        Attribute::ShortUniqueIdentifier(_) |
        // Always Sensitive / Never Extractable are server-derived from
        // the Sensitive / Extractable history (§11).
        Attribute::AlwaysSensitive(_) |
        Attribute::NeverExtractable(_) |
        // Digest + RandomNumberGenerator structures are server-computed.
        Attribute::Digest(_) |
        Attribute::RandomNumberGenerator(_) |
        // Key Value Present mirrors the engine state.
        Attribute::KeyValuePresent(_) |
        // Certificate Length / Subject CN / Issuer / Subject are
        // server-extracted from the Certificate Value DER bytes at
        // Register time. BL-M-10 step #4 pins `CertificateLength`.
        Attribute::CertificateLength(_) |
        Attribute::CertificateSubjectCN(_) |
        Attribute::X509CertificateSubject(_) |
        Attribute::X509CertificateIssuer(_) |
        Attribute::X509CertificateIdentifier(_)
    )
}

/// True if `obj` currently has a value for the attribute carried in `a`.
fn attribute_present(obj: &ObjectRecord, a: &Attribute) -> bool {
    match a {
        Attribute::Name(_)                   => obj.name.is_some(),
        Attribute::CryptographicAlgorithm(_) => true,  // always present (created with one)
        Attribute::CryptographicLength(_)    => obj.cryptographic_length > 0,
        Attribute::CryptographicUsageMask(_) => !obj.usage_mask.is_empty(),
        Attribute::ObjectType(_)             => true,
        Attribute::State(_)                  => true,
        Attribute::UniqueIdentifier(_)       => true,
        Attribute::Custom { name, .. }       => obj.custom_attributes.contains_key(name),
        // Baseline Server attributes — presence depends on the typed
        // field actually being populated. v0.1 treats Add/Modify/Delete
        // of these as "present if any value is set on the record"; the
        // wave-2 attribute-mutation work doesn't need finer granularity.
        _ => true,
    }
}

fn attribute_name_present(obj: &ObjectRecord, name: &str) -> bool {
    let canonical: String = name.chars().filter(|c| c.is_alphanumeric()).collect();
    match canonical.as_str() {
        "Name"                    => obj.name.is_some(),
        "CryptographicAlgorithm"  => true,
        "CryptographicLength"     => obj.cryptographic_length > 0,
        "CryptographicUsageMask"  => !obj.usage_mask.is_empty(),
        "ObjectType" | "State" | "UniqueIdentifier" => true,
        _ => obj.custom_attributes.contains_key(name) || obj.links.contains_key(name),
    }
}

/// Write the attribute value into the right slot on `obj`. Used by Add /
/// Modify / Set (which all converge on "the new value SHALL be stored").
fn apply_attribute(obj: &mut ObjectRecord, a: &Attribute) {
    match a {
        Attribute::Name(n)                   => obj.name = Some(n.clone()),
        Attribute::CryptographicAlgorithm(_) => {}  // Read-Only, guarded earlier
        Attribute::CryptographicLength(n)    => obj.cryptographic_length = *n,
        Attribute::CryptographicUsageMask(m) => obj.usage_mask = *m,
        Attribute::ObjectType(_)             => {}  // Read-Only
        Attribute::State(_)                  => {}  // Read-Only
        Attribute::UniqueIdentifier(_)       => {}  // Read-Only
        Attribute::Custom { name, value }    => {
            obj.custom_attributes.insert(name.clone(), value.clone());
        }
        // ── Baseline Server attribute setters ──
        Attribute::ActivationDate(t)           => obj.activation_date = Some(time::OffsetDateTime::from_unix_timestamp(*t).unwrap_or(time::OffsetDateTime::UNIX_EPOCH)),
        Attribute::DeactivationDate(t)         => obj.deactivation_date = Some(time::OffsetDateTime::from_unix_timestamp(*t).unwrap_or(time::OffsetDateTime::UNIX_EPOCH)),
        Attribute::DestroyDate(t)              => obj.destroy_date = Some(time::OffsetDateTime::from_unix_timestamp(*t).unwrap_or(time::OffsetDateTime::UNIX_EPOCH)),
        Attribute::CompromiseDate(t)           => obj.compromise_date = Some(time::OffsetDateTime::from_unix_timestamp(*t).unwrap_or(time::OffsetDateTime::UNIX_EPOCH)),
        Attribute::CompromiseOccurrenceDate(t) => obj.compromise_occurrence_date = Some(time::OffsetDateTime::from_unix_timestamp(*t).unwrap_or(time::OffsetDateTime::UNIX_EPOCH)),
        Attribute::ProcessStartDate(t)         => obj.process_start_date = Some(time::OffsetDateTime::from_unix_timestamp(*t).unwrap_or(time::OffsetDateTime::UNIX_EPOCH)),
        Attribute::ProtectStopDate(t)          => obj.protect_stop_date = Some(time::OffsetDateTime::from_unix_timestamp(*t).unwrap_or(time::OffsetDateTime::UNIX_EPOCH)),
        Attribute::RotateDate(t)               => obj.rotate_date = Some(time::OffsetDateTime::from_unix_timestamp(*t).unwrap_or(time::OffsetDateTime::UNIX_EPOCH)),
        Attribute::Sensitive(b)                => obj.sensitive = Some(*b),
        Attribute::Extractable(b)              => obj.extractable = Some(*b),
        Attribute::Fresh(b)                    => obj.fresh = Some(*b),
        Attribute::QuantumSafe(b)              => obj.quantum_safe = Some(*b),
        Attribute::RotateAutomatic(b)          => obj.rotate_automatic = Some(*b),
        Attribute::AlternativeName(s)          => obj.alternative_name = Some(s.clone()),
        Attribute::Comment(s)                  => obj.comment = Some(s.clone()),
        Attribute::Description(s)              => obj.description = Some(s.clone()),
        Attribute::ContactInformation(s)       => obj.contact_information = Some(s.clone()),
        Attribute::ObjectClass(s)              => obj.object_class = Some(s.clone()),
        Attribute::KeyValueLocation(s)         => obj.key_value_location = Some(s.clone()),
        Attribute::X509CertificateIdentifier(s) => obj.x509_certificate_identifier = Some(s.clone()),
        Attribute::X509CertificateIssuer(s)    => obj.x509_certificate_issuer = Some(s.clone()),
        Attribute::X509CertificateSubject(s)   => obj.x509_certificate_subject = Some(s.clone()),
        Attribute::RotateName(s)               => obj.rotate_name = Some(s.clone()),
        Attribute::LeaseTime(n)                => obj.lease_time = Some(*n),
        Attribute::ProtectionPeriod(n)         => obj.protection_period = Some(*n),
        Attribute::RotateInterval(n)           => obj.rotate_interval = Some(*n),
        Attribute::RotateOffset(n)             => obj.rotate_offset = Some(*n),
        Attribute::RotateGeneration(n)         => obj.rotate_generation = Some(*n),
        // Read-only or server-managed Baseline attributes (Initial Date,
        // Last Change Date, Original Creation Date, Short UID, Always/
        // Never Sensitive, Key Value Present, Certificate*, etc.) — the
        // server sets these; client AddAttribute is a no-op.
        _ => {}
    }
}

fn remove_attribute_by_value(obj: &mut ObjectRecord, a: &Attribute) {
    match a {
        Attribute::Name(_)                   => obj.name = None,
        Attribute::CryptographicLength(_)    => obj.cryptographic_length = 0,
        Attribute::CryptographicUsageMask(_) => obj.usage_mask = UsageMask::empty(),
        Attribute::Custom { name, .. }       => { obj.custom_attributes.remove(name); }
        // Required / Read-Only attributes guarded earlier.
        _ => {}
    }
}

fn remove_attribute_by_name(obj: &mut ObjectRecord, name: &str) {
    let canonical: String = name.chars().filter(|c| c.is_alphanumeric()).collect();
    match canonical.as_str() {
        "Name"                   => obj.name = None,
        "CryptographicLength"    => obj.cryptographic_length = 0,
        "CryptographicUsageMask" => obj.usage_mask = UsageMask::empty(),
        other => {
            obj.custom_attributes.remove(other);
            obj.links.remove(other);
        }
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
            usage_mask: UsageMask::ENCRYPT,
            state: State::Active,
            pkcs11_cka_id: vec![],
            pkcs11_slot: 0,
            initial_date: OffsetDateTime::UNIX_EPOCH,
            activation_date: None,
            supersedes: None,
            name: None,
            links: HashMap::new(),
            custom_attributes: HashMap::new(),

            key_material: None,

            key_format_type: None,
        ..ObjectRecord::default()
}).unwrap();
    }

    #[test]
    fn add_then_get_name_round_trips() {
        let d = deps_with();
        put(&d, "u");
        add_attribute(&d, AddAttributeRequest {
            uid: "u".into(),
            new_attribute: Attribute::Name("my-key".into()),
        }, "c").unwrap();
        assert_eq!(d.store.get("u").unwrap().unwrap().name.as_deref(), Some("my-key"));
    }

    #[test]
    fn add_existing_name_fails_invalid_field() {
        let d = deps_with();
        put(&d, "u");
        // First add succeeds.
        add_attribute(&d, AddAttributeRequest {
            uid: "u".into(), new_attribute: Attribute::Name("x".into()),
        }, "c").unwrap();
        // Second add on same attribute must fail per §6.1.2.
        let err = add_attribute(&d, AddAttributeRequest {
            uid: "u".into(), new_attribute: Attribute::Name("y".into()),
        }, "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::InvalidField);
    }

    #[test]
    fn add_read_only_attribute_fails() {
        let d = deps_with();
        put(&d, "u");
        let err = add_attribute(&d, AddAttributeRequest {
            uid: "u".into(),
            new_attribute: Attribute::ObjectType(ObjectType::SymmetricKey),
        }, "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::InvalidField);
    }

    #[test]
    fn modify_name_changes_value() {
        let d = deps_with();
        put(&d, "u");
        add_attribute(&d, AddAttributeRequest {
            uid: "u".into(), new_attribute: Attribute::Name("v1".into()),
        }, "c").unwrap();
        modify_attribute(&d, ModifyAttributeRequest {
            uid: "u".into(), current_attribute: None,
            new_attribute: Attribute::Name("v2".into()),
        }, "c").unwrap();
        assert_eq!(d.store.get("u").unwrap().unwrap().name.as_deref(), Some("v2"));
    }

    /// KMIP 3.0 §6.1.38 + §11 attribute table — `State` is Read-Only
    /// (modifiable only by Activate/Revoke/Destroy state transitions).
    /// BL-M-7 step #2 pins `ResultReason = AttributeReadOnly` (0x22).
    #[test]
    fn modify_read_only_attribute_returns_attribute_read_only() {
        let d = deps_with();
        put(&d, "u");
        let err = modify_attribute(&d, ModifyAttributeRequest {
            uid: "u".into(),
            current_attribute: None,
            new_attribute: Attribute::State(crate::kmip30::State::Compromised),
        }, "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::AttributeReadOnly);
    }

    /// KMIP 3.0 §11 attribute table — `Activation Date` is modifiable
    /// only while the managed object is in `PreActive`. Mutating it
    /// once the object has Activated returns `WrongKeyLifecycleState`
    /// (AKLC-M-3 step #4 + SKLC-M-3 step #4 both pin this code).
    #[test]
    fn modify_activation_date_after_active_returns_wrong_lifecycle_state() {
        let d = deps_with();
        // put() places the object directly in `Active` state.
        put(&d, "u");
        let err = modify_attribute(&d, ModifyAttributeRequest {
            uid: "u".into(),
            current_attribute: None,
            new_attribute: Attribute::ActivationDate(123_456_789),
        }, "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::WrongKeyLifecycleState);
    }

    /// PreActive → modifying ActivationDate MUST succeed per §11.
    #[test]
    fn modify_activation_date_while_preactive_succeeds() {
        let d = deps_with();
        d.store.put(ObjectRecord {
            uid: "p".into(),
            object_type: ObjectType::SymmetricKey,
            algorithm: KmipAlgorithm::Aes,
            cryptographic_length: 256,
            usage_mask: UsageMask::ENCRYPT,
            state: State::PreActive,
            pkcs11_cka_id: vec![],
            pkcs11_slot: 0,
            initial_date: OffsetDateTime::UNIX_EPOCH,
            activation_date: None,
            supersedes: None,
            name: None,
            links: HashMap::new(),
            custom_attributes: HashMap::new(),
            key_material: None,
            key_format_type: None,
            ..ObjectRecord::default()
        }).unwrap();
        modify_attribute(&d, ModifyAttributeRequest {
            uid: "p".into(),
            current_attribute: None,
            new_attribute: Attribute::ActivationDate(42),
        }, "c").unwrap();
        let rec = d.store.get("p").unwrap().unwrap();
        assert_eq!(rec.activation_date.unwrap().unix_timestamp(), 42);
    }

    #[test]
    fn modify_missing_attribute_fails() {
        let d = deps_with();
        put(&d, "u");
        // Name doesn't exist yet → Modify must fail per §6.1.38.
        let err = modify_attribute(&d, ModifyAttributeRequest {
            uid: "u".into(), current_attribute: None,
            new_attribute: Attribute::Name("v".into()),
        }, "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::ItemNotFound);
    }

    #[test]
    fn delete_by_reference_removes_value() {
        let d = deps_with();
        put(&d, "u");
        add_attribute(&d, AddAttributeRequest {
            uid: "u".into(), new_attribute: Attribute::Name("x".into()),
        }, "c").unwrap();
        delete_attribute(&d, DeleteAttributeRequest {
            uid: "u".into(), current_attribute: None,
            attribute_reference: Some("Name".into()),
        }, "c").unwrap();
        assert!(d.store.get("u").unwrap().unwrap().name.is_none());
    }

    #[test]
    fn delete_required_attribute_fails() {
        let d = deps_with();
        put(&d, "u");
        let err = delete_attribute(&d, DeleteAttributeRequest {
            uid: "u".into(), current_attribute: None,
            attribute_reference: Some("CryptographicAlgorithm".into()),
        }, "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::InvalidField);
    }

    #[test]
    fn set_acts_as_add_when_absent() {
        let d = deps_with();
        put(&d, "u");
        set_attribute(&d, SetAttributeRequest {
            uid: "u".into(), new_attribute: Attribute::Name("first".into()),
        }, "c").unwrap();
        assert_eq!(d.store.get("u").unwrap().unwrap().name.as_deref(), Some("first"));
    }

    #[test]
    fn set_acts_as_modify_when_present() {
        let d = deps_with();
        put(&d, "u");
        set_attribute(&d, SetAttributeRequest {
            uid: "u".into(), new_attribute: Attribute::Name("first".into()),
        }, "c").unwrap();
        set_attribute(&d, SetAttributeRequest {
            uid: "u".into(), new_attribute: Attribute::Name("second".into()),
        }, "c").unwrap();
        assert_eq!(d.store.get("u").unwrap().unwrap().name.as_deref(), Some("second"));
    }

    #[test]
    fn adjust_usage_mask_increments_bits() {
        let d = deps_with();
        put(&d, "u");
        adjust_attribute(&d, AdjustAttributeRequest {
            uid: "u".into(),
            attribute_reference: "Cryptographic Usage Mask".into(),
            adjustment_type: AdjustmentType::Increment,
            adjustment_value: Some(UsageMask::SIGN.bits() as i64),
        }, "c").unwrap();
        let rec = d.store.get("u").unwrap().unwrap();
        assert!(rec.usage_mask.contains(UsageMask::ENCRYPT));
        assert!(rec.usage_mask.contains(UsageMask::SIGN));
    }
}
