//! KMIP 3.0 §6.1.45 **Query** operation.
//!
//! > "This operation is used by the client to interrogate the server to
//! > determine its capabilities and/or protocol mechanisms."
//!
//! Wire-format op codepoint `0x18` (verified against
//! `spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json`, `Operation` enum,
//! `Query = 0x00000018`).
//!
//! ## Plane mapping
//!
//! - **Plane 1** — engine.evaluate gate. Query against an existing object
//!   is rare; usually no algorithm is in the request.
//! - **Plane 2** — assembles the response from the in-process config +
//!   the static op/object-type capability list.
//! - **Plane 3** — would call `C_GetInfo` (PKCS#11 v3.2 §C.5.3) and
//!   `C_GetMechanismList` (§C.5.4) for capability discovery. v0.1 returns
//!   the static capability set + the constant
//!   [`DepsConfig::vendor_identification`] / `server_version`. A future
//!   revision can call into the bridge for live mech-list reflection.

use crate::auditlog::{AuditEvent, EventPayload, KmipOpResult, Plane};
use crate::error::Result;
use crate::kmip30::{
    ObjectType, Operation, QueryFunction, QueryRequest, QueryResponse, ServerInformation,
};
use time::OffsetDateTime;

use super::deps::Deps;

/// Handle a `Query` request.
///
/// `correlation_id` is the per-request identifier stamped on every emitted
/// audit event so the Hub UI can group rows.
pub fn query(deps: &Deps, req: QueryRequest, correlation_id: &str) -> Result<QueryResponse> {
    let started = OffsetDateTime::now_utc();

    // Plane-2: emit RequestReceived
    deps.sink.emit(AuditEvent::at(
        started,
        Plane::Kmip,
        correlation_id,
        EventPayload::KmipRequestReceived {
            op: "Query".into(),
            request_summary: format!("functions={:?}", req.functions),
            client_cn: None,
        },
    ));

    // Build the response per the requested QueryFunctions. KMIP 3.0
    // §6.1.45 — each function maps to an optional response field.
    let mut resp = QueryResponse {
        operations: None,
        object_types: None,
        server_info: None,
    };

    for f in &req.functions {
        match f {
            QueryFunction::QueryOperations => {
                resp.operations = Some(supported_operations());
            }
            QueryFunction::QueryObjects => {
                resp.object_types = Some(supported_object_types());
            }
            QueryFunction::QueryServerInformation => {
                resp.server_info = Some(ServerInformation {
                    vendor_identification: deps.config.vendor_identification.clone(),
                    server_version: deps.config.server_version.clone(),
                });
            }
            QueryFunction::QueryApplicationNamespaces
            | QueryFunction::QueryProfiles
            | QueryFunction::QueryCapabilities => {
                // v0.1 returns nothing for these — Phase 8 (compliance tool)
                // fills in profile reporting.
            }
        }
    }

    deps.sink.emit(AuditEvent::at(
        OffsetDateTime::now_utc(),
        Plane::Kmip,
        correlation_id,
        EventPayload::KmipResponseSent {
            op: "Query".into(),
            result: KmipOpResult::Success,
            latency_ms: 0,
        },
    ));

    Ok(resp)
}

/// Operation capability list — surfaced via `QueryOperations`. Includes
/// every op the dispatcher actually routes to a handler.
fn supported_operations() -> Vec<Operation> {
    vec![
        Operation::Query,
        Operation::Create,
        Operation::CreateKeyPair,
        Operation::Get,
        Operation::GetAttributes,
        Operation::GetAttributeList,
        Operation::AddAttribute,
        Operation::ModifyAttribute,
        Operation::DeleteAttribute,
        Operation::SetAttribute,
        Operation::AdjustAttribute,
        Operation::Locate,
        Operation::Activate,
        Operation::Revoke,
        Operation::Destroy,
        Operation::Encrypt,
        Operation::Decrypt,
        Operation::Sign,
        Operation::SignatureVerify,
        Operation::Interop,
        Operation::Register,
        Operation::Import,
        Operation::Export,
        Operation::Deactivate,
        Operation::Check,
        Operation::Archive,
        Operation::Recover,
        Operation::Obliterate,
        Operation::DiscoverVersions,
        Operation::Ping,
    ]
}

/// v0.1 object types the server understands.
fn supported_object_types() -> Vec<ObjectType> {
    vec![
        ObjectType::SymmetricKey,
        ObjectType::PublicKey,
        ObjectType::PrivateKey,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditlog::RingSink;
    use crate::store::MemoryStore;
    use std::sync::Arc;

    fn deps() -> (Arc<RingSink>, Deps) {
        let ring = Arc::new(RingSink::new(64));
        let d = Deps::new(
            crate::policy::Engine::permissive(),
            Arc::new(MemoryStore::new()),
            ring.clone(),
            super::super::deps::DepsConfig::default(),
        );
        (ring, d)
    }

    #[test]
    fn query_operations_returns_v01_op_set() {
        let (_ring, d) = deps();
        let resp = query(&d, QueryRequest { functions: vec![QueryFunction::QueryOperations] }, "corr-q").unwrap();
        let ops = resp.operations.unwrap();
        assert_eq!(ops.len(), 30);
        assert!(ops.contains(&Operation::Sign));
        assert!(ops.contains(&Operation::Encrypt));
        assert!(ops.contains(&Operation::Decrypt));
        assert!(ops.contains(&Operation::GetAttributes));
        assert!(ops.contains(&Operation::Interop));
        assert!(ops.contains(&Operation::AddAttribute));
        assert!(ops.contains(&Operation::SetAttribute));
    }

    #[test]
    fn query_server_info_uses_deps_config() {
        let (_ring, d) = deps();
        let resp = query(&d, QueryRequest { functions: vec![QueryFunction::QueryServerInformation] }, "corr-s").unwrap();
        let info = resp.server_info.unwrap();
        assert_eq!(info.vendor_identification, "pqctoday-hsm");
        assert_eq!(info.server_version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn query_emits_p2_audit_events() {
        let (ring, d) = deps();
        let _ = query(&d, QueryRequest { functions: vec![QueryFunction::QueryObjects] }, "corr-a").unwrap();
        let p2 = ring.filter_plane(Plane::Kmip);
        assert_eq!(p2.len(), 2); // RequestReceived + ResponseSent
    }
}
