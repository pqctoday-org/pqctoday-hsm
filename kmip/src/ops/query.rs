//! KMIP 3.0 §6.1.47 **Query** operation.
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
                // implemented (CS-BC-M-GCM-3); attestation is not.
                // §9.5 Undo and Continue batch modes are implemented
                // in the dispatcher. Phase 4 — asynchronous processing
                // is now real too (§6.1.43/§6.1.5/§6.1.44/§6.1.46 all
                // handled, backed by a genuine job store + executor —
                // see `dispatcher::enqueue_async_job`), flipped on only
                // after those handlers and their tests were green.
                resp.capability_information = Some(CapabilityInformation {
                    streaming_capability: true,
                    asynchronous_capability: true,
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

/// Phase 6 (6.1) — **empty.** Every op this server ever advertised is
/// now genuinely implemented in [`crate::dispatcher::HANDLED_OPERATIONS`]
/// (K19/K20/K21/P2.2/P2.3/Phase 3.1/Phase 3.3/Phase 4 each moved their
/// op(s) out of this list over the course of this codebase's history —
/// see git blame for the play-by-play). What's left un-advertised —
/// `Notify` / `Put` (§6.2.2/§6.2.3, Phase 5, parked: the spec itself
/// says they're delivered "via means outside the normal
/// request/response protocol, using unspecified configuration", so
/// there is no wire-protocol shape to honestly claim) and
/// `DelegatedLogin` / `ReProvision` (never implemented, never
/// corpus-required) — genuinely isn't supported, so it's genuinely
/// not advertised.
///
/// This used to be non-empty purely to satisfy the MSGENC-*
/// (Message-Encoding profile) fixtures' expected Query response,
/// under the replay harness's Profiles v3.0 §4.1.1 item 15 *expected ⊆
/// actual* comparator — those fixtures list Notify/Put alongside every
/// genuinely-implemented op because they were captured from a
/// reference server that also implements server-to-client delivery.
/// `conformance/harness/dispatcher_replay.py`'s `_compare_query_response_payload`
/// now exempts MSGENC-* from that capability-set check entirely
/// (Phase 6.1) — those transcripts test encoding fidelity, not
/// capability-list membership, so pretending to support Notify/Put
/// just to keep them green was never actually validating what they're
/// for.
pub(crate) const ADVERTISED_UNIMPLEMENTED_OPERATIONS: &[Operation] = &[];

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
/// - Phase 3.3: SplitKey, via the dedicated Create Split Key / Join
///   Split Key ops (`ops::split_key`) rather than plain Create/Register.
/// - Phase 6 (6.1) — User / Group / PasswordCredential /
///   DeviceCredential / OneTimePasswordCredential /
///   HashedPasswordCredential moved here from
///   [`ADVERTISED_UNIMPLEMENTED_OBJECT_TYPES`]: they were mislabeled
///   "unimplemented" — `CreateUser`/`CreateGroup`/`CreateCredential`
///   (`ops::session_and_auth`) genuinely persist each as its own
///   `ObjectRecord` with the matching `object_type` (see that module's
///   tests). Not PKCS#11-engine-backed, which is correct and expected
///   — they're login/identity metadata, not cryptographic key material.
pub(crate) const IMPLEMENTED_OBJECT_TYPES: &[ObjectType] = &[
    ObjectType::Certificate,
    ObjectType::SymmetricKey,
    ObjectType::PublicKey,
    ObjectType::PrivateKey,
    ObjectType::SecretData,
    ObjectType::OpaqueObject,
    ObjectType::SplitKey,
    ObjectType::User,
    ObjectType::Group,
    ObjectType::PasswordCredential,
    ObjectType::DeviceCredential,
    ObjectType::OneTimePasswordCredential,
    ObjectType::HashedPasswordCredential,
];

/// Phase 6 (6.1) — **empty.** `CertificateRequest` was the sole
/// remaining entry (PgpKey was trimmed in K3): `Certify`/`Re-certify`
/// (`ops::certify`) consume a client-supplied CSR's bytes inline via
/// `CertificateRequestType`/`CertificateRequestValue`, but never
/// persist a `CertificateRequest` as its own queryable managed object
/// — genuinely unimplemented, so honestly not advertised, per T3's
/// "implemented or dropped" rule. The MSGENC-* fixtures that used to
/// require advertising it are exempted from this capability-list
/// check entirely now (see `ADVERTISED_UNIMPLEMENTED_OPERATIONS`'s
/// doc comment).
pub(crate) const ADVERTISED_UNIMPLEMENTED_OBJECT_TYPES: &[ObjectType] = &[];

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
        // History: K19/K20/K21/P2.3/WD19 each moved ops between
        // handled and corpus-required-advertised-only, net unchanged
        // at 64 (54 handled + 10 advertised-only) — see git blame for
        // the full play-by-play. Phase 3.3 (Split Key) and Phase 4
        // (async subsystem) grew the HANDLED side by 6 (62 handled +
        // 2 advertised-only = 64, still unchanged net). Phase 6.1 is
        // the first REAL change: `ADVERTISED_UNIMPLEMENTED_OPERATIONS`
        // is now empty (Notify/Put were never implemented — see that
        // const's doc comment) → 62 handled + 0 advertised-only = 62.
        assert_eq!(ops.len(), 62);
        assert!(ops.contains(&Operation::Sign));
        assert!(ops.contains(&Operation::Encrypt));
        assert!(ops.contains(&Operation::Decrypt));
        // CSD02 — first-class ML-KEM KEM ops.
        assert!(ops.contains(&Operation::Encapsulate));
        assert!(ops.contains(&Operation::Decapsulate));
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
        // K3 — corpus-required ops newly added to the Operation enum
        // (K20: DeriveKey, K21: ReKey / ReKeyKeyPair are now
        // advertised as HANDLED ops instead).
        for op in [
            Operation::DeriveKey, Operation::Certify, Operation::Cancel,
            Operation::ReKey, Operation::ReKeyKeyPair, Operation::JoinSplitKey,
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
        // Phase 6.1: was 14 (7 implemented + 7 advertised-only, which
        // included the genuinely-unimplemented CertificateRequest).
        // User/Group/*Credential moved into IMPLEMENTED_OBJECT_TYPES
        // (they were mislabeled, not actually missing);
        // CertificateRequest was dropped (genuinely unimplemented) —
        // net 13 (all real now, 0 advertised-only).
        assert_eq!(types.len(), 13);
        // PgpKey: neither implemented nor corpus-required — trimmed in K3.
        assert!(!types.contains(&ObjectType::PgpKey));
        // CertificateRequest: genuinely unimplemented (Phase 6.1) —
        // see ADVERTISED_UNIMPLEMENTED_OBJECT_TYPES's doc comment.
        assert!(!types.contains(&ObjectType::CertificateRequest));
        assert!(types.contains(&ObjectType::OpaqueObject));
        assert!(types.contains(&ObjectType::SymmetricKey));
        assert!(types.contains(&ObjectType::User), "genuinely implemented — CreateUser persists it");
        assert!(types.contains(&ObjectType::Group), "genuinely implemented — CreateGroup persists it");
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
        assert!(cap.asynchronous_capability, "Phase 4 — asynchronous processing is real now");
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
