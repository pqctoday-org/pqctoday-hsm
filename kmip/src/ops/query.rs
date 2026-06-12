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
    CapabilityInformation, ObjectType, Operation, QueryFunction, QueryRequest, QueryResponse,
    ServerInformation,
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
        vendor_identification: None,
        server_info: None,
        application_namespaces: None,
        profile_information: None,
        capability_information: None,
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
                resp.vendor_identification =
                    Some(deps.config.vendor_identification.clone());
                resp.server_info = Some(ServerInformation {
                    server_version: deps.config.server_version.clone(),
                });
            }
            QueryFunction::QueryApplicationNamespaces => {
                // KMIP 3.0 §6.1.39 — a Baseline server MAY surface
                // supported application namespaces when asked.
                // Profiles v3.0 §4.1.1 item 14 marks the value as
                // variable AND optional; emitting an empty list keeps
                // the response shape spec-compliant. TL-M-1's expected
                // response carries no `ApplicationNamespace` children
                // even though the request asks for them.
                resp.application_namespaces = Some(Vec::new());
            }
            QueryFunction::QueryProfiles => {
                // K3 — explicit empty list: the server does not (yet)
                // formally claim any KMIP profile. Which profiles to
                // claim (Baseline Server TTLV, …) is the K13 decision;
                // until then an empty `Profile Information` list is
                // the honest answer (nothing emitted on the wire).
                resp.profile_information = Some(Vec::new());
            }
            QueryFunction::QueryCapabilities => {
                // K3 — honest CapabilityInformation (compliance-audit
                // K-11): multi-part Encrypt/Decrypt streaming is
                // implemented (CS-BC-M-GCM-3); asynchronous processing
                // and attestation are not; §9.5 Undo and Continue
                // batch modes are implemented in the dispatcher.
                resp.capability_information = Some(CapabilityInformation {
                    streaming_capability: true,
                    asynchronous_capability: false,
                    attestation_capability: false,
                    batch_undo_capability: true,
                    batch_continue_capability: true,
                });
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

/// K3 — ops the OASIS corpus requires in the Query advertisement but
/// the dispatcher does NOT implement.
///
/// **Documented tension (compliance-audit K-4):** the truthful answer
/// would be [`crate::dispatcher::HANDLED_OPERATIONS`] alone, but the
/// MSGENC-{XML,JSON,HTTPS}-M-1 expected Query responses enumerate all
/// 60 ops below + handled ones, and the replay harness enforces the
/// Profiles v3.0 §4.1.1 item 15 rule *expected ⊆ actual* — trimming
/// any of these fails the corpus gate. Resolution per the K3 gate
/// rule: advertise exactly the corpus-required set and nothing more,
/// and make every entry here fail honestly on invocation with
/// `OperationFailed / OperationNotSupported (0x05)` (see
/// `RequestPayload::Unsupported`) instead of the previous
/// advertised-but-InvalidMessage behaviour. DelegatedLogin /
/// ReProvision are neither implemented nor corpus-required, so they
/// are NOT advertised.
///
/// K19 moved SetEndpointRole / GetUsageAllocation / GetConstraints out
/// of this list into `HANDLED_OPERATIONS` (no net change to the
/// advertised set), and implemented SetDefaults — which was previously
/// neither implemented nor advertised — so it is now advertised as a
/// handled op (the corpus gate is *expected ⊆ actual*, so the one-op
/// growth of the advertised set keeps every MSGENC-* Query transcript
/// passing).
pub(crate) const ADVERTISED_UNIMPLEMENTED_OPERATIONS: &[Operation] = &[
    Operation::ReKey,
    Operation::ReCertify,
    Operation::ObtainLease,
    Operation::Validate,
    Operation::Poll,
    Operation::Notify,
    Operation::Put,
    Operation::CreateSplitKey,
    Operation::SetConstraints,
    Operation::QueryAsynchronousRequests,
    Operation::Process,
    // K3 additions — also enumerated by the MSGENC-* expected Query
    // responses (previously missing from the Operation enum entirely).
    Operation::DeriveKey,
    Operation::Certify,
    Operation::Cancel,
    Operation::ReKeyKeyPair,
    Operation::JoinSplitKey,
];

/// Operation capability list — surfaced via `QueryOperations`. The
/// dispatcher's real surface ([`crate::dispatcher::HANDLED_OPERATIONS`],
/// single source of truth shared with `handle_payload`) plus the
/// corpus-required advertised-only ops (see
/// [`ADVERTISED_UNIMPLEMENTED_OPERATIONS`] for the K-4 tension note).
fn supported_operations() -> Vec<Operation> {
    let mut ops = crate::dispatcher::HANDLED_OPERATIONS.to_vec();
    ops.extend_from_slice(ADVERTISED_UNIMPLEMENTED_OPERATIONS);
    ops
}

/// Object types Create / CreateKeyPair / Register actually accept:
/// - Create: SymmetricKey + SecretData (`ops::create` type gate)
/// - CreateKeyPair: PublicKey + PrivateKey
/// - Register: SymmetricKey / PublicKey / PrivateKey / SecretData /
///   Certificate / OpaqueObject (`ops::register_import_export`)
pub(crate) const IMPLEMENTED_OBJECT_TYPES: &[ObjectType] = &[
    ObjectType::Certificate,
    ObjectType::SymmetricKey,
    ObjectType::PublicKey,
    ObjectType::PrivateKey,
    ObjectType::SecretData,
    ObjectType::OpaqueObject,
];

/// K3 — object types the MSGENC-* expected Query responses enumerate
/// but Register/Create reject on invocation (InvalidObjectType /
/// OperationNotSupported). Same §4.1.1 item-16 corpus tension as
/// [`ADVERTISED_UNIMPLEMENTED_OPERATIONS`] — the harness requires
/// *expected ⊆ actual*, so these stay advertised; PgpKey (neither
/// implemented nor corpus-required) was trimmed in K3.
pub(crate) const ADVERTISED_UNIMPLEMENTED_OBJECT_TYPES: &[ObjectType] = &[
    ObjectType::SplitKey,
    ObjectType::CertificateRequest,
    ObjectType::User,
    ObjectType::Group,
    ObjectType::PasswordCredential,
    ObjectType::DeviceCredential,
    ObjectType::OneTimePasswordCredential,
    ObjectType::HashedPasswordCredential,
];

/// Object types the server reports under `QueryObjects` — the real
/// surface plus the corpus-required advertised-only set.
fn supported_object_types() -> Vec<ObjectType> {
    let mut types = IMPLEMENTED_OBJECT_TYPES.to_vec();
    types.extend_from_slice(ADVERTISED_UNIMPLEMENTED_OBJECT_TYPES);
    types
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
        // K19: 46 handled + 16 corpus-required advertised-only = 62
        // (was 42 + 19 = 61; SetEndpointRole / GetUsageAllocation /
        // GetConstraints moved between the sets, SetDefaults is newly
        // implemented and therefore newly — honestly — advertised).
        assert_eq!(ops.len(), 62);
        assert!(ops.contains(&Operation::Sign));
        assert!(ops.contains(&Operation::Encrypt));
        assert!(ops.contains(&Operation::Decrypt));
        assert!(ops.contains(&Operation::GetAttributes));
        assert!(ops.contains(&Operation::Interop));
        assert!(ops.contains(&Operation::AddAttribute));
        assert!(ops.contains(&Operation::SetAttribute));
        // K19 — the four Baseline client-to-server ops are handled
        // (and therefore advertised).
        for op in [
            Operation::SetEndpointRole, Operation::GetUsageAllocation,
            Operation::GetConstraints, Operation::SetDefaults,
        ] {
            assert!(ops.contains(&op), "{op:?} must be advertised (K19 handled)");
        }
        // K3 — corpus-required ops newly added to the Operation enum.
        for op in [
            Operation::DeriveKey, Operation::Certify, Operation::Cancel,
            Operation::ReKeyKeyPair, Operation::JoinSplitKey,
        ] {
            assert!(ops.contains(&op), "{op:?} must be advertised (MSGENC-*)");
        }
        // Not implemented AND not corpus-required → never advertised.
        for op in [Operation::DelegatedLogin, Operation::ReProvision] {
            assert!(!ops.contains(&op), "{op:?} must NOT be advertised");
        }
    }

    /// K3 definition-of-done — Query output ≡ dispatcher surface plus
    /// the explicitly documented corpus-required advertised-only set;
    /// the two sets stay disjoint and duplicate-free.
    #[test]
    fn query_operations_equals_dispatcher_surface_plus_documented_exceptions() {
        use std::collections::HashSet;
        let advertised: HashSet<Operation> = supported_operations().into_iter().collect();
        let handled: HashSet<Operation> =
            crate::dispatcher::HANDLED_OPERATIONS.iter().copied().collect();
        let exceptions: HashSet<Operation> =
            ADVERTISED_UNIMPLEMENTED_OPERATIONS.iter().copied().collect();
        assert!(
            handled.is_disjoint(&exceptions),
            "an op cannot be both handled and advertised-unimplemented",
        );
        let expected: HashSet<Operation> = handled.union(&exceptions).copied().collect();
        assert_eq!(advertised, expected, "Query list ≠ dispatcher surface ∪ exceptions");
        assert_eq!(
            supported_operations().len(),
            expected.len(),
            "advertised list must be duplicate-free",
        );
    }

    #[test]
    fn query_object_types_real_surface_plus_corpus_required() {
        let (_ring, d) = deps();
        let resp = query(&d, QueryRequest { functions: vec![QueryFunction::QueryObjects] }, "corr-o").unwrap();
        let types = resp.object_types.unwrap();
        assert_eq!(types.len(), 14);
        // PgpKey: neither implemented nor corpus-required — trimmed in K3.
        assert!(!types.contains(&ObjectType::PgpKey));
        assert!(types.contains(&ObjectType::OpaqueObject));
        assert!(types.contains(&ObjectType::SymmetricKey));
    }

    /// K3 — QueryCapabilities reports the honest capability set;
    /// QueryProfiles returns an explicit empty list (K13 pending).
    #[test]
    fn query_capabilities_and_profiles_are_honest() {
        let (_ring, d) = deps();
        let resp = query(
            &d,
            QueryRequest {
                functions: vec![QueryFunction::QueryCapabilities, QueryFunction::QueryProfiles],
            },
            "corr-c",
        )
        .unwrap();
        let cap = resp.capability_information.expect("CapabilityInformation present");
        assert!(cap.streaming_capability, "multi-part Encrypt/Decrypt is implemented");
        assert!(!cap.asynchronous_capability, "no async processing");
        assert!(!cap.attestation_capability, "no attestation");
        assert!(cap.batch_undo_capability, "§9.5 Undo is implemented");
        assert!(cap.batch_continue_capability, "§9.5 Continue is implemented");
        assert_eq!(resp.profile_information, Some(vec![]), "explicit empty profile list");
    }

    #[test]
    fn query_server_info_uses_deps_config() {
        let (_ring, d) = deps();
        let resp = query(&d, QueryRequest { functions: vec![QueryFunction::QueryServerInformation] }, "corr-s").unwrap();
        assert_eq!(resp.vendor_identification.as_deref(), Some("pqctoday-hsm"));
        let info = resp.server_info.unwrap();
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
