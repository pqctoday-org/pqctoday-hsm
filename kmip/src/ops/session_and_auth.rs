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
use crate::server::auth::AuthContext;
use crate::kmip30::{
    Attribute, CreateCredentialRequest, CreateCredentialResponse, CreateGroupRequest,
    CreateGroupResponse, CreateUserRequest, CreateUserResponse, KmipAlgorithm, LogRequest,
    LogResponse, LoginRequest, LoginResponse, LogoutRequest, LogoutResponse, ObjectType, State,
    UsageMask,
};
use crate::store::ObjectRecord;

use super::deps::Deps;
use super::helpers::{emit_request, emit_success, fail_err};

/// K4 — map a KMIP Credential Type (§11) to the matching Object Type credential
/// subtype (spec Object Type enum 0x0d–0x10), so a created credential reports
/// its true type instead of Secret Data. Types with no dedicated Object Type
/// (e.g. Certificate 0x08) fall back to the generic Password Credential.
fn credential_object_type(credential_type: u32) -> ObjectType {
    match credential_type {
        0x02 => ObjectType::DeviceCredential,             // Device
        0x04 => ObjectType::OneTimePasswordCredential,    // One Time Password
        0x05 => ObjectType::HashedPasswordCredential,     // Hashed Password
        // 0x01 Username&Password, 0x07 Password, 0x08 Certificate, … → generic.
        _ => ObjectType::PasswordCredential,
    }
}

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

    // KMIP 3.0 §11 Credential Type enum + §6.1.9 CreateCredential
    // table. The Baseline Server SHALL accept every type it advertises
    // in Query. We currently accept:
    //   0x01 Username and Password — PasswordCredential{Username,Password}
    //   0x02 Device                — DeviceCredential (passthrough)
    //   0x05 Hashed Password       — PasswordCredential{Password=hash}
    //   0x07 Password              — PasswordCredential{Password}
    //   0x08 Certificate           — CertificateCredential (passthrough)
    // Each maps to a SecretData record in the store; the credential
    // material itself is opaque to the engine, which only needs to
    // hold a UID for subsequent Login/Logout.
    let needs_password = matches!(req.credential_type, 0x01 | 0x05 | 0x07);
    if needs_password && req.password_credential.is_none() {
        return Err(fail_err(
            deps,
            correlation_id,
            "CreateCredential",
            KmipError::failed(
                ResultReason::MissingData,
                format!(
                    "CredentialType {:#x} requires PasswordCredential structure",
                    req.credential_type
                ),
            ),
        ));
    }
    let supported = matches!(req.credential_type, 0x01 | 0x02 | 0x05 | 0x07 | 0x08);
    if !supported {
        return Err(fail_err(
            deps,
            correlation_id,
            "CreateCredential",
            KmipError::failed(
                ResultReason::InvalidField,
                format!("Credential Type {:#x} unknown", req.credential_type),
            ),
        ));
    }

    // K4 — persist under the true Credential Object Type, not Secret Data.
    let uid =
        persist_simple_record(deps, credential_object_type(req.credential_type), req.attributes)?;
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
    // K4 — KMIP 3.0 Object Type enum defines Group (0x0c); persist under it so
    // GetAttributes/Locate report the true type (was Secret Data).
    let uid = persist_simple_record(deps, ObjectType::Group, req.attributes)?;
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
    // K4 — KMIP 3.0 Object Type enum defines User (0x0b); persist under it.
    let uid = persist_simple_record(deps, ObjectType::User, req.attributes)?;
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

pub fn login(
    deps: &Deps,
    _req: LoginRequest,
    auth: &AuthContext,
    correlation_id: &str,
) -> Result<LoginResponse> {
    emit_request(deps, correlation_id, "Login", String::new());
    // K14 — KMIP 3.0 §6.1.34: when a credential store is configured,
    // a ticket is only issued to a request that authenticated. The
    // KMIP 3.0 Login payload carries no Credential (Table 350 lists
    // only LeaseTime / RequestCount / UsageLimits) — the credential
    // travels in the §8.1.2 `Authentication` request-header field,
    // which the dispatcher verifies into `auth.identity`. The
    // dispatcher gate already fails unauthenticated requests wholesale
    // under configured auth; this check is defence-in-depth for
    // direct/in-process callers.
    if deps.config.auth_enabled() && auth.identity.is_none() {
        return Err(fail_err(
            deps,
            correlation_id,
            "Login",
            KmipError::failed(
                ResultReason::AuthenticationNotSuccessful,
                "Login requires a verified credential when authentication is configured",
            ),
        ));
    }
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
    ..ObjectRecord::default()
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
    fn k4_system_objects_persist_true_object_type() {
        // K4 — CreateUser/Group/Credential must store the true Object Type
        // (0x0b/0x0c/0x0d–0x10), not Secret Data, so GetAttributes/Locate report it.
        let d = deps_with();

        let u = create_user(&d, CreateUserRequest { attributes: vec![Attribute::Name("bob".into())] }, "u").unwrap();
        assert_eq!(d.store.get(&u.uid).unwrap().unwrap().object_type, ObjectType::User);

        let g = create_group(&d, CreateGroupRequest { attributes: vec![Attribute::Name("admins".into())] }, "g").unwrap();
        assert_eq!(d.store.get(&g.uid).unwrap().unwrap().object_type, ObjectType::Group);

        // Password/Username (0x01) → PasswordCredential; Device (0x02) → DeviceCredential;
        // Hashed (0x05) → HashedPasswordCredential.
        let c1 = create_credential(&d, CreateCredentialRequest {
            credential_type: 0x01, attributes: vec![],
            password_credential: Some(PasswordCredential { username: "a".into(), password: Some("p".into()) }),
        }, "c1").unwrap();
        assert_eq!(d.store.get(&c1.uid).unwrap().unwrap().object_type, ObjectType::PasswordCredential);

        let c2 = create_credential(&d, CreateCredentialRequest {
            credential_type: 0x02, attributes: vec![], password_credential: None,
        }, "c2").unwrap();
        assert_eq!(d.store.get(&c2.uid).unwrap().unwrap().object_type, ObjectType::DeviceCredential);

        let c5 = create_credential(&d, CreateCredentialRequest {
            credential_type: 0x05, attributes: vec![],
            password_credential: Some(PasswordCredential { username: "a".into(), password: Some("h".into()) }),
        }, "c5").unwrap();
        assert_eq!(d.store.get(&c5.uid).unwrap().unwrap().object_type, ObjectType::HashedPasswordCredential);
    }

    #[test]
    fn create_credential_device_type_succeeds() {
        // KMIP 3.0 §6.1.9 — Baseline accepts every CredentialType it
        // advertises in Query. Device (0x02) is one such type and now
        // succeeds (was OperationNotSupported under v0.1).
        let d = deps_with();
        let resp = create_credential(&d, CreateCredentialRequest {
            credential_type: 0x02, // Device
            attributes: vec![],
            password_credential: None,
        }, "c").unwrap();
        assert!(!resp.uid.is_empty());
    }

    #[test]
    fn create_credential_unknown_type_fails_with_invalid_field() {
        let d = deps_with();
        let err = create_credential(&d, CreateCredentialRequest {
            credential_type: 0xFF, // unassigned
            attributes: vec![],
            password_credential: None,
        }, "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::InvalidField);
    }

    #[test]
    fn login_returns_ticket_string() {
        let d = deps_with();
        let r = login(&d, LoginRequest {
            lease_time: None, request_count: None, usage_limits: None,
        }, &AuthContext::open(), "c").unwrap();
        assert!(r.ticket.starts_with("urn:pqctoday:ticket:"));
    }

    /// K14 — under configured auth, an unauthenticated Login is
    /// `Authentication Not Successful (0x03)`, not a free ticket.
    #[test]
    fn login_under_configured_auth_requires_verified_identity() {
        use crate::server::auth::{sha256_hex, AuthUser, Identity};
        let mut d = deps_with();
        d.config.auth_users = vec![AuthUser {
            username: "alice".into(),
            password_sha256: sha256_hex("pw"),
        }];
        let req = || LoginRequest { lease_time: None, request_count: None, usage_limits: None };
        // No verified identity → 0x03.
        let err = login(&d, req(), &AuthContext::open(), "c").unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::AuthenticationNotSuccessful);
        // Verified identity (dispatcher-authenticated header credential
        // or mTLS subject) → ticket issued.
        let ctx = AuthContext { identity: Some(Identity { username: "alice".into() }) };
        let r = login(&d, req(), &ctx, "c").unwrap();
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
