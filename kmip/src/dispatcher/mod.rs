//! Plane 2 — Request dispatcher.
//!
//! Routes decoded KMIP requests to `ops::*` handlers. Per-request
//! `correlation_id` ties every Plane-1 / Plane-2 / Plane-3 audit entry
//! together (see [`crate::auditlog`]).
//!
//! ## Per-batch-item flow
//!
//! 1. Allocate a fresh `correlation_id` (UUID v4) per batch item — every
//!    audit event the handler emits stamps this value.
//! 2. Call the op handler with the typed request payload + `&Deps` +
//!    `&correlation_id`.
//! 3. Convert the `Result<<Op>Response, KmipError>` into a
//!    [`ResponseBatchItem`]:
//!    - `Ok(r)` → `ResultStatus = Success`, payload populated.
//!    - `Err(e)` → `ResultStatus = OperationFailed`, `result_reason`
//!      carries the KMIP 3.0 §9.2 result-reason wire codepoint, payload
//!      omitted.
//!
//! KMIP 3.0 §8.1.3 / §8.2.3 — Batch items are positionally correlated
//! (no `Unique Batch Item ID` in v3.0). The dispatcher preserves order.

use uuid::Uuid;

use crate::error::KmipError;
use crate::kmip30::{
    ActivateRequest, CreateKeyPairRequest, CreateRequest, DecryptRequest, DestroyRequest,
    EncryptRequest, GetAttributeListRequest, GetAttributesRequest, GetRequest, InteropRequest,
    LocateRequest, QueryRequest, RequestBatchItem, RequestMessage,
    ResponseBatchItem, ResponseHeader, ResponseMessage, ResponsePayload, ResultStatus,
    RevokeRequest, SignRequest, SignatureVerifyRequest,
};
use crate::ops::{
    activate::activate,
    attribute_mutate::{add_attribute, adjust_attribute, delete_attribute, modify_attribute, set_attribute},
    create::create, create_key_pair::create_key_pair, decrypt::decrypt,
    destroy::destroy, encrypt::encrypt, get::get,
    get_attribute_list::get_attribute_list, get_attributes::get_attributes,
    interop::interop,
    lifecycle_and_protocol::{archive, check, deactivate, discover_versions, obliterate, ping, recover},
    locate::locate,
    mac_and_hash::{hash, mac, mac_verify},
    query::query,
    register_import_export::{export, import_object, register},
    revoke::revoke,
    session_and_auth::{create_credential, create_group, create_user, log, login, logout},
    sign::sign, signature_verify::signature_verify, Deps,
};

use crate::kmip30::RequestPayload;

/// Top-level entry: decoded inbound `RequestMessage` → encoded outbound
/// `ResponseMessage`.
pub fn dispatch(deps: &Deps, request: RequestMessage) -> ResponseMessage {
    let mut items: Vec<ResponseBatchItem> = Vec::with_capacity(request.batch_items.len());
    for item in request.batch_items {
        items.push(dispatch_one(deps, item));
    }
    ResponseMessage {
        header: ResponseHeader::v3_now(),
        batch_items: items,
    }
}

fn dispatch_one(deps: &Deps, item: RequestBatchItem) -> ResponseBatchItem {
    let correlation_id = Uuid::new_v4().to_string();
    let op = item.operation;
    let result = handle_payload(deps, item.payload, &correlation_id);
    match result {
        Ok(payload) => ResponseBatchItem {
            operation: Some(op),
            result_status: ResultStatus::Success,
            result_reason: None,
            result_message: None,
            payload: Some(payload),
        },
        Err(err) => ResponseBatchItem {
            operation: Some(op),
            result_status: ResultStatus::OperationFailed,
            result_reason: Some(err.result_reason().to_wire_value()),
            result_message: Some(err.to_string()),
            payload: None,
        },
    }
}

fn handle_payload(
    deps: &Deps,
    payload: RequestPayload,
    correlation_id: &str,
) -> Result<ResponsePayload, KmipError> {
    Ok(match payload {
        RequestPayload::Query(r) => ResponsePayload::Query(query(deps, r, correlation_id)?),
        RequestPayload::Create(r) => ResponsePayload::Create(create(deps, r, correlation_id)?),
        RequestPayload::CreateKeyPair(r) => {
            let op_canonical = canonical_create_key_pair_op(&r);
            ResponsePayload::CreateKeyPair(create_key_pair(deps, r, &op_canonical, correlation_id)?)
        }
        RequestPayload::Get(r) => ResponsePayload::Get(get(deps, r, correlation_id)?),
        RequestPayload::GetAttributes(r) => ResponsePayload::GetAttributes(get_attributes(deps, r, correlation_id)?),
        RequestPayload::GetAttributeList(r) => ResponsePayload::GetAttributeList(get_attribute_list(deps, r, correlation_id)?),
        RequestPayload::Locate(r) => ResponsePayload::Locate(locate(deps, r, correlation_id)?),
        RequestPayload::Activate(r) => ResponsePayload::Activate(activate(deps, r, correlation_id)?),
        RequestPayload::Revoke(r) => ResponsePayload::Revoke(revoke(deps, r, correlation_id)?),
        RequestPayload::Destroy(r) => ResponsePayload::Destroy(destroy(deps, r, correlation_id)?),
        RequestPayload::Encrypt(r) => ResponsePayload::Encrypt(encrypt(deps, r, correlation_id)?),
        RequestPayload::Decrypt(r) => ResponsePayload::Decrypt(decrypt(deps, r, correlation_id)?),
        RequestPayload::Sign(r) => ResponsePayload::Sign(sign(deps, r, correlation_id)?),
        RequestPayload::SignatureVerify(r) => {
            ResponsePayload::SignatureVerify(signature_verify(deps, r, correlation_id)?)
        }
        RequestPayload::Interop(r) => ResponsePayload::Interop(interop(deps, r, correlation_id)?),
        RequestPayload::AddAttribute(r) => ResponsePayload::AddAttribute(add_attribute(deps, r, correlation_id)?),
        RequestPayload::ModifyAttribute(r) => ResponsePayload::ModifyAttribute(modify_attribute(deps, r, correlation_id)?),
        RequestPayload::DeleteAttribute(r) => ResponsePayload::DeleteAttribute(delete_attribute(deps, r, correlation_id)?),
        RequestPayload::SetAttribute(r) => ResponsePayload::SetAttribute(set_attribute(deps, r, correlation_id)?),
        RequestPayload::AdjustAttribute(r) => ResponsePayload::AdjustAttribute(adjust_attribute(deps, r, correlation_id)?),
        RequestPayload::Register(r) => ResponsePayload::Register(register(deps, r, correlation_id)?),
        RequestPayload::Import(r) => ResponsePayload::Import(import_object(deps, r, correlation_id)?),
        RequestPayload::Export(r) => ResponsePayload::Export(export(deps, r, correlation_id)?),
        RequestPayload::Deactivate(r) => ResponsePayload::Deactivate(deactivate(deps, r, correlation_id)?),
        RequestPayload::Check(r) => ResponsePayload::Check(check(deps, r, correlation_id)?),
        RequestPayload::Archive(r) => ResponsePayload::Archive(archive(deps, r, correlation_id)?),
        RequestPayload::Recover(r) => ResponsePayload::Recover(recover(deps, r, correlation_id)?),
        RequestPayload::Obliterate(r) => ResponsePayload::Obliterate(obliterate(deps, r, correlation_id)?),
        RequestPayload::DiscoverVersions(r) => ResponsePayload::DiscoverVersions(discover_versions(deps, r, correlation_id)?),
        RequestPayload::Ping(r) => ResponsePayload::Ping(ping(deps, r, correlation_id)?),
        RequestPayload::Mac(r) => ResponsePayload::Mac(mac(deps, r, correlation_id)?),
        RequestPayload::MacVerify(r) => ResponsePayload::MacVerify(mac_verify(deps, r, correlation_id)?),
        RequestPayload::Hash(r) => ResponsePayload::Hash(hash(deps, r, correlation_id)?),
        RequestPayload::CreateCredential(r) => ResponsePayload::CreateCredential(create_credential(deps, r, correlation_id)?),
        RequestPayload::CreateGroup(r) => ResponsePayload::CreateGroup(create_group(deps, r, correlation_id)?),
        RequestPayload::CreateUser(r) => ResponsePayload::CreateUser(create_user(deps, r, correlation_id)?),
        RequestPayload::Log(r) => ResponsePayload::Log(log(deps, r, correlation_id)?),
        RequestPayload::Login(r) => ResponsePayload::Login(login(deps, r, correlation_id)?),
        RequestPayload::Logout(r) => ResponsePayload::Logout(logout(deps, r, correlation_id)?),
    })
}

/// KMIP `CreateKeyPair` is a single op but policy needs to discriminate
/// KEM vs signing vs encrypt intent. The dispatcher canonicalises into
/// `CreateKeyPair:<purpose>` based on `CryptographicUsageMask` in the
/// merged template (see `policies/README.md` "Op-name canonicalisation
/// convention").
fn canonical_create_key_pair_op(req: &CreateKeyPairRequest) -> String {
    use crate::kmip30::{Attribute, UsageMask};
    let mut mask = UsageMask::empty();
    for a in req
        .common_attributes
        .iter()
        .chain(req.private_key_attributes.iter())
        .chain(req.public_key_attributes.iter())
    {
        if let Attribute::CryptographicUsageMask(m) = a {
            mask |= *m;
        }
    }
    let suffix = if mask.contains(UsageMask::KEY_AGREEMENT) {
        "KeyAgreement"
    } else if mask.contains(UsageMask::SIGN) || mask.contains(UsageMask::VERIFY) {
        "Sign"
    } else if mask.contains(UsageMask::ENCRYPT) || mask.contains(UsageMask::DECRYPT) {
        "Encrypt"
    } else {
        // No mask hint — fall back to "Sign" so the policy's
        // `algorithm_default: CreateKeyPair:Sign` rule still matches.
        // Operators can require explicit masks via a policy gate.
        "Sign"
    };
    format!("CreateKeyPair:{suffix}")
}

// ── Convenience constructors for tests / external use ──────────────────────

/// Build a single-batch-item Request Message wrapping one op payload.
pub fn one_off_request(payload: RequestPayload) -> RequestMessage {
    let operation = payload.operation();
    RequestMessage {
        header: crate::kmip30::RequestHeader::v3(),
        batch_items: vec![RequestBatchItem { operation, payload }],
    }
}

// Suppress unused imports when downstream code consumes only some.
#[allow(dead_code)]
fn _suppress_unused_warnings() {
    let _ = (
        std::marker::PhantomData::<ActivateRequest>,
        std::marker::PhantomData::<CreateRequest>,
        std::marker::PhantomData::<DecryptRequest>,
        std::marker::PhantomData::<DestroyRequest>,
        std::marker::PhantomData::<EncryptRequest>,
        std::marker::PhantomData::<GetRequest>,
        std::marker::PhantomData::<LocateRequest>,
        std::marker::PhantomData::<QueryRequest>,
        std::marker::PhantomData::<RevokeRequest>,
        std::marker::PhantomData::<SignRequest>,
        std::marker::PhantomData::<SignatureVerifyRequest>,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditlog::{AuditSink, RingSink};
    use crate::kmip30::{QueryFunction, QueryRequest};
    use crate::ops::DepsConfig;
    use crate::policy::{load_from_str, Engine};
    use crate::store::MemoryStore;
    use std::sync::Arc;

    fn deps() -> Deps {
        let ring = Arc::new(RingSink::new(64));
        let sink: Arc<dyn AuditSink> = ring;
        let engine = Engine::with_global_sink(sink.clone());
        engine
            .activate(load_from_str(
                "schema_version: 1\nmetadata: {name: t, description: t, authority: t, effective: always}\nrules: []\n",
                std::path::Path::new("<t>"),
            ).unwrap())
            .unwrap();
        Deps::new(engine, Arc::new(MemoryStore::new()), sink, DepsConfig::default())
    }

    #[test]
    fn query_dispatches_and_returns_success() {
        let d = deps();
        let req = one_off_request(RequestPayload::Query(QueryRequest {
            functions: vec![QueryFunction::QueryOperations],
        }));
        let resp = dispatch(&d, req);
        assert_eq!(resp.batch_items.len(), 1);
        assert_eq!(resp.batch_items[0].result_status, ResultStatus::Success);
        assert!(matches!(resp.batch_items[0].payload, Some(ResponsePayload::Query(_))));
    }

    #[test]
    fn missing_uid_get_returns_operation_failed_with_reason() {
        let d = deps();
        let req = one_off_request(RequestPayload::Get(crate::kmip30::GetRequest { uid: "ghost".into() }));
        let resp = dispatch(&d, req);
        assert_eq!(resp.batch_items[0].result_status, ResultStatus::OperationFailed);
        assert_eq!(
            resp.batch_items[0].result_reason,
            Some(crate::error::ResultReason::ItemNotFound.to_wire_value())
        );
        assert!(resp.batch_items[0].payload.is_none());
    }

    #[test]
    fn canonical_op_picks_key_agreement_from_mask() {
        use crate::kmip30::{Attribute, UsageMask};
        let req = CreateKeyPairRequest {
            common_attributes: vec![Attribute::CryptographicUsageMask(UsageMask::KEY_AGREEMENT)],
            private_key_attributes: vec![],
            public_key_attributes: vec![],
        };
        assert_eq!(canonical_create_key_pair_op(&req), "CreateKeyPair:KeyAgreement");
    }

    #[test]
    fn canonical_op_picks_sign_from_mask() {
        use crate::kmip30::{Attribute, UsageMask};
        let req = CreateKeyPairRequest {
            common_attributes: vec![],
            private_key_attributes: vec![Attribute::CryptographicUsageMask(UsageMask::SIGN | UsageMask::VERIFY)],
            public_key_attributes: vec![],
        };
        assert_eq!(canonical_create_key_pair_op(&req), "CreateKeyPair:Sign");
    }
}
