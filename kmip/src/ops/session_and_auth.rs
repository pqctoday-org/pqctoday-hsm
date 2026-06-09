//! KMIP 3.0 Group F: session / auth ops.
//!
//! All six ops carry minimal semantics in v0.1 — we acknowledge the
//! request, allocate a UID where the spec requires one, and emit
//! audit events. Genuine credential storage + ticket-based session
//! enforcement is a Phase 12 (sandbox MVP) deliverable.
//!
//! Spec mapping:
//!
//! - CreateCredential §6.1.9  / Tbl 276
//! - CreateGroup      §6.1.10 / Tbl 279
//! - CreateUser       §6.1.13 / Tbl 289
//! - Log              §6.1.33 / Tbl 349
//! - Login            §6.1.34 / Tbl 352
//! - Logout           §6.1.35 / Tbl 355

use std::collections::HashMap;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{KmipError, Result, ResultReason};
use crate::kmip30::{
    Attribute, CreateCredentialRequest, CreateCredentialResponse, CreateGroupRequest,
    CreateGroupResponse, CreateUserRequest, CreateUserResponse, KmipAlgorithm, LogRequest,
    LogResponse, LoginRequest, LoginResponse, LogoutRequest, LogoutResponse, ObjectType, State,
    UsageMask,
};
use crate::store::ObjectRecord;

use super::deps::Deps;
use super::helpers::{emit_request, emit_success, fail_err};

// ── CreateCredential ───────────────────────────────────────────────────────

pub fn create_credential(
    deps: &Deps,
    req: CreateCredentialRequest,
    correlation_id: &str,
) -> Result<CreateCredentialResponse> {
    emit_request(
        deps,
        correlation_id,
        "CreateCredential",
        format!("type={:#x} attrs={}", req.credential_type, req.attributes.len()),
    );

    // KMIP 3.0 §11 Credential Type enum codepoints:
    //   0x01 Username and Password
    //   0x02 Device
    //   0x03 Attestation
    //   0x04 One Time Password
    //   0x05 Hashed Password
    //   0x06 Ticket
    // v0.1 honours UsernameAndPassword only.
    if req.credential_type != 0x01 {
        return Err(fail_err(deps, correlation_id, "CreateCredential",
            KmipError::failed(
                ResultReason::OperationNotSupported,
                format!("Credential Type {:#x} not supported (v0.1 = Username+Password)", req.credential_type),
            )));
    }
    let _cred = req.password_credential.ok_or_else(|| {
        fail_err(deps, correlation_id, "CreateCredential",
            KmipError::failed(
                ResultReason::MissingData,
                "Username+Password credential requires PasswordCredential structure".to_string(),
            ))
    })?;

    let uid = persist_simple_record(deps, ObjectType::SecretData, req.attributes)?;
    emit_success(deps, correlation_id, "CreateCredential");
    Ok(CreateCredentialResponse { uid })
}

// ── CreateGroup ────────────────────────────────────────────────────────────

pub fn create_group(
    deps: &Deps,
    req: CreateGroupRequest,
    correlation_id: &str,
) -> Result<CreateGroupResponse> {
    emit_request(deps, correlation_id, "CreateGroup", format!("attrs={}", req.attributes.len()));
    // KMIP doesn't define a Group object type in §3.x, so we persist
    // it as a SecretData-shaped record with Name + attributes.
    let uid = persist_simple_record(deps, ObjectType::SecretData, req.attributes)?;
    emit_success(deps, correlation_id, "CreateGroup");
    Ok(CreateGroupResponse { uid })
}

// ── CreateUser ─────────────────────────────────────────────────────────────

pub fn create_user(
    deps: &Deps,
    req: CreateUserRequest,
    correlation_id: &str,
) -> Result<CreateUserResponse> {
    emit_request(deps, correlation_id, "CreateUser", format!("attrs={}", req.attributes.len()));
    let uid = persist_simple_record(deps, ObjectType::SecretData, req.attributes)?;
    emit_success(deps, correlation_id, "CreateUser");
    Ok(CreateUserResponse { uid })
}

// ── Log ────────────────────────────────────────────────────────────────────

pub fn log(deps: &Deps, req: LogRequest, correlation_id: &str) -> Result<LogResponse> {
    // Per §6.1.33: forward the message to the server log. We emit an
    // audit event with the message — the ring buffer + JSONL sink
    // both capture it.
    emit_request(deps, correlation_id, "Log", format!("msg={:?}", req.message));
    emit_success(deps, correlation_id, "Log");
    Ok(LogResponse)
}

// ── Login / Logout ─────────────────────────────────────────────────────────

pub fn login(deps: &Deps, _req: LoginRequest, correlation_id: &str) -> Result<LoginResponse> {
    emit_request(deps, correlation_id, "Login", String::new());
    // Issue a fresh ticket. v0.1 doesn't enforce ticket presence on
    // subsequent ops; ticket validation lands when session enforcement
    // is wired (Phase 12 sandbox MVP).
    let ticket = format!("urn:pqctoday:ticket:{}", Uuid::new_v4());
    emit_success(deps, correlation_id, "Login");
    Ok(LoginResponse { ticket })
}

pub fn logout(deps: &Deps, _req: LogoutRequest, correlation_id: &str) -> Result<LogoutResponse> {
    emit_request(deps, correlation_id, "Logout", String::new());
    // No active session table in v0.1, so logout is a no-op.
    emit_success(deps, correlation_id, "Logout");
    Ok(LogoutResponse)
}

// ── Helpers ────────────────────────────────────────────────────────────────

/// Persist a User / Group / Credential record with whatever attributes
/// the client supplied. Returns the generated UID.
fn persist_simple_record(
    deps: &Deps,
    object_type: ObjectType,
    attrs: Vec<Attribute>,
) -> Result<String> {
    let uid = format!("urn:pqctoday:obj:{}", Uuid::new_v4());
    let now = OffsetDateTime::now_utc();
    let name = attrs.iter().find_map(|a| match a {
        Attribute::Name(n) => Some(n.clone()),
        _ => None,
    });
    deps.store.put(ObjectRecord {
        uid: uid.clone(),
        object_type,
        // No cryptographic algorithm for a User / Group / Credential —
        // we store a placeholder so the existing ObjectRecord fields
        // stay typed. The Algorithm attribute will reflect the same
        // value on GetAttributes.
        algorithm: KmipAlgorithm::Aes,
        cryptographic_length: 0,
        usage_mask: UsageMask::empty(),
        state: State::Active,
        pkcs11_cka_id: vec![],
        pkcs11_slot: 0,
        initial_date: now,
        activation_date: Some(now),
        supersedes: None,
        name,
        links: HashMap::new(),
        custom_attributes: HashMap::new(),
        key_material: None,
        key_format_type: None,
    })?;
    Ok(uid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditlog::{AuditSink, RingSink};
    use crate::kmip30::PasswordCredential;
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

    #[test]
    fn create_credential_with_password_succeeds() {
        let d = deps_with();
        let r = create_credential(&d, CreateCredentialRequest {
            credential_type: 0x01,
            attributes: vec![Attribute::Name("alice".into())],
            password_credential: Some(PasswordCredential {
                username: "alice".into(),
                password: Some("secret".into()),
            }),
        }, "c").unwrap();
        assert!(d.store.get(&r.uid).unwrap().is_some());
    }

    #[test]
    fn create_credential_without_password_fails() {
        let d = deps_with();
        let err = create_credential(&d, CreateCredentialRequest {
            credential_type: 0x01,
            attributes: vec![],
            password_credential: None,
        }, "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::MissingData);
    }

    #[test]
    fn create_credential_unsupported_type_fails() {
        let d = deps_with();
        let err = create_credential(&d, CreateCredentialRequest {
            credential_type: 0x02, // Device
            attributes: vec![],
            password_credential: None,
        }, "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::OperationNotSupported);
    }

    #[test]
    fn login_returns_ticket_string() {
        let d = deps_with();
        let r = login(&d, LoginRequest {
            lease_time: None, request_count: None, usage_limits: None,
        }, "c").unwrap();
        assert!(r.ticket.starts_with("urn:pqctoday:ticket:"));
    }

    #[test]
    fn create_group_persists_record() {
        let d = deps_with();
        let r = create_group(&d, CreateGroupRequest {
            attributes: vec![Attribute::Name("admins".into())],
        }, "c").unwrap();
        let rec = d.store.get(&r.uid).unwrap().unwrap();
        assert_eq!(rec.name.as_deref(), Some("admins"));
    }
}
