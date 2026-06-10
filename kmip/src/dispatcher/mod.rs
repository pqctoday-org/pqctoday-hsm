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
    rng_and_pkcs11::{pkcs11, rng_retrieve, rng_seed},
    session_and_auth::{create_credential, create_group, create_user, log, login, logout},
    sign::sign, signature_verify::signature_verify, Deps,
};

use crate::kmip30::RequestPayload;

/// Top-level entry: decoded inbound `RequestMessage` → encoded outbound
/// `ResponseMessage`.
///
/// Honours KMIP 3.0 §9.5 `Batch Error Continuation Option`:
/// - **Stop** (default): halt at first failure; later items are NOT
///   processed and NOT returned.
/// - **Continue**: process every item independently.
/// - **Undo**: deferred — see `R7 Phase 4`. Currently treated as
///   `Stop` for forward-compat (the test corpus needing Undo is
///   tracked in conformance/REPLAY_REPORT.md as BL-M-2).
///
/// Threads the §6.4 **ID Placeholder** through the batch: the
/// most-recently-produced UID is stashed in `BatchState` and any item
/// that references the placeholder sentinel
/// [`ID_PLACEHOLDER_SENTINEL`] gets it substituted on entry.
pub fn dispatch(deps: &Deps, request: RequestMessage) -> ResponseMessage {
    use crate::kmip30::BatchErrorContinuationOption;
    let mode = request
        .header
        .batch_error_continuation_option
        .unwrap_or(BatchErrorContinuationOption::Stop);
    let mut state = BatchState::default();
    let mut items: Vec<ResponseBatchItem> = Vec::with_capacity(request.batch_items.len());
    for item in request.batch_items {
        let response = dispatch_one(deps, item, &mut state);
        let failed = response.result_status == ResultStatus::OperationFailed;
        items.push(response);
        if failed {
            // Continue is the only mode that proceeds past a failure.
            // Stop halts. Undo halts and additionally rolls back the
            // earlier successful items (relabelled OperationUndone).
            // Per §9.5: "Responses to batch items that have not been
            // processed are not returned."
            if matches!(mode, BatchErrorContinuationOption::Continue) {
                continue;
            }
            if matches!(mode, BatchErrorContinuationOption::Undo) {
                undo_wave(deps, &mut state, &mut items);
            }
            break;
        }
    }
    ResponseMessage {
        header: ResponseHeader::v3_now(),
        batch_items: items,
    }
}

/// KMIP 3.0 §9.5 Undo — restore the store + engine state to its
/// pre-batch shape and relabel every previously-successful response
/// item as `OperationUndone`. The failed item (the last one in
/// `items`) keeps `OperationFailed`. Snapshots are replayed in
/// reverse order so that nested mutations roll back correctly.
fn undo_wave(deps: &Deps, state: &mut BatchState, items: &mut [ResponseBatchItem]) {
    // The last item is the failed one; relabel everything before it.
    let undone_count = items.len().saturating_sub(1);
    // Snapshots are aligned 1:1 with successful items (we only push
    // a snapshot bucket after `Ok(_)` in `dispatch_one`). Replay in
    // reverse to undo the most-recent change first.
    while let Some(bucket) = state.snapshots.pop() {
        for snap in bucket.0.into_iter().rev() {
            match snap.pre {
                Some(rec) => {
                    // Restore the pre-state by overwriting. We use
                    // `update` rather than `put` because the UID
                    // still exists in the store.
                    let _ = deps.store.update(rec);
                }
                None => {
                    // The UID didn't exist before the op — remove it
                    // and best-effort destroy any engine-resident
                    // handle the op had created.
                    if let Some(rec) = deps.store.get(&snap.uid).ok().flatten() {
                        if let Some(session) = deps.engine_session {
                            if let Ok(Some(handle)) = softhsmrustv3::native::find_by_cka_id(
                                session, &rec.pkcs11_cka_id,
                            ) {
                                let _ = softhsmrustv3::native::destroy_object(session, handle);
                            }
                        }
                    }
                    let _ = deps.store.remove(&snap.uid);
                }
            }
        }
    }
    for bi in items.iter_mut().take(undone_count) {
        bi.result_status = ResultStatus::OperationUndone;
        // Per spec, the response payload is still returned — the
        // status field is the only thing that changes.
    }
}

/// Per-batch transient state per KMIP 3.0 §6.4 — "a temporary variable
/// called the ID Placeholder. … only valid and preserved during the
/// execution of a single request. After execution, the variable is
/// discarded." Also tracks snapshot stacks for the §9.5 Undo wave.
#[derive(Default)]
struct BatchState {
    id_placeholder: Option<String>,
    /// R7 Phase 4 — every successful state-mutating op pushes one
    /// or more `UidSnapshot`s here. On failure under Undo mode the
    /// stack is replayed in reverse to restore the store + engine
    /// state to its pre-batch shape.
    snapshots: Vec<ItemSnapshots>,
}

/// All snapshots produced by a single BatchItem (most ops touch one
/// UID; CreateKeyPair touches two; AddAttribute might touch one).
#[derive(Default)]
struct ItemSnapshots(Vec<UidSnapshot>);

/// State of a single UID at the moment just before a BatchItem ran.
/// `pre = None` means the UID didn't exist before the op (so the
/// Undo wave will delete it); `pre = Some(rec)` means it did, and
/// the Undo wave will write the snapshot back over whatever the op
/// produced.
struct UidSnapshot {
    uid: String,
    pre: Option<crate::store::ObjectRecord>,
}

/// Sentinel the wire codec emits for `<UniqueIdentifier
/// type="Enumeration" value="IDPlaceholder"/>` (enum value `0x01`).
/// The dispatcher substitutes the live ID Placeholder before handing
/// the request to the handler.
pub const ID_PLACEHOLDER_SENTINEL: &str = "$IDPlaceholder";

fn dispatch_one(
    deps: &Deps,
    item: RequestBatchItem,
    state: &mut BatchState,
) -> ResponseBatchItem {
    let correlation_id = Uuid::new_v4().to_string();
    let op = item.operation;
    let payload = substitute_id_placeholder(item.payload, state);

    // R7 Phase 4 — snapshot every input UID BEFORE the handler runs
    // so the §9.5 Undo wave (if triggered later in this batch) can
    // restore the store to its pre-op shape. Output-only ops
    // (Create / CreateKeyPair / Register without explicit UID) get
    // their snapshots filled in post-hoc — we capture `pre = None`
    // for each newly-created UID after success.
    let pre_snapshots: Vec<UidSnapshot> = payload
        .touched_uids()
        .into_iter()
        .map(|uid| UidSnapshot {
            uid: uid.to_string(),
            pre: deps.store.get(uid).ok().flatten(),
        })
        .collect();

    let result = handle_payload(deps, payload, &correlation_id);
    match result {
        Ok(payload) => {
            // After every successful UID-producing op, refresh the ID
            // Placeholder for subsequent items in this batch.
            update_id_placeholder(state, &payload);
            // Stitch in any newly-created UIDs as "pre = None" so
            // the Undo wave knows to delete them rather than restore.
            let mut bucket = ItemSnapshots(pre_snapshots);
            for uid in newly_created_uids(&payload) {
                bucket.0.push(UidSnapshot { uid, pre: None });
            }
            state.snapshots.push(bucket);
            ResponseBatchItem {
                operation: Some(op),
                result_status: ResultStatus::Success,
                result_reason: None,
                result_message: None,
                payload: Some(payload),
            }
        }
        Err(err) => ResponseBatchItem {
            operation: Some(op),
            result_status: ResultStatus::OperationFailed,
            result_reason: Some(err.result_reason().to_wire_value()),
            result_message: Some(err.to_string()),
            payload: None,
        },
    }
}

/// UIDs that the op produced (and that therefore must be DELETED on
/// an Undo rollback, since they didn't exist before the op ran).
fn newly_created_uids(payload: &ResponsePayload) -> Vec<String> {
    match payload {
        ResponsePayload::Create(r) => vec![r.uid.clone()],
        ResponsePayload::CreateKeyPair(r) => {
            vec![r.private_key_uid.clone(), r.public_key_uid.clone()]
        }
        ResponsePayload::Register(r) => vec![r.uid.clone()],
        ResponsePayload::Import(r) => vec![r.uid.clone()],
        ResponsePayload::CreateCredential(r) => vec![r.uid.clone()],
        ResponsePayload::CreateGroup(r) => vec![r.uid.clone()],
        ResponsePayload::CreateUser(r) => vec![r.uid.clone()],
        _ => Vec::new(),
    }
}

/// Walk the request payload and replace any field equal to
/// [`ID_PLACEHOLDER_SENTINEL`] with the live ID Placeholder. Covers the
/// `uid` field on every payload that consumes a single UID; multi-UID
/// payloads (none of the OASIS Baseline tests use them so far) can be
/// added as the corpus grows.
fn substitute_id_placeholder(
    payload: RequestPayload,
    state: &BatchState,
) -> RequestPayload {
    let live = match &state.id_placeholder {
        Some(s) => s.clone(),
        None => return payload, // nothing to substitute against
    };
    fn fix(s: &mut String, live: &str) {
        if s == ID_PLACEHOLDER_SENTINEL {
            *s = live.to_string();
        }
    }
    let mut p = payload;
    match &mut p {
        RequestPayload::Get(r)             => fix(&mut r.uid, &live),
        RequestPayload::GetAttributes(r)   => fix(&mut r.uid, &live),
        RequestPayload::GetAttributeList(r)=> fix(&mut r.uid, &live),
        RequestPayload::Activate(r)        => fix(&mut r.uid, &live),
        RequestPayload::Revoke(r)          => fix(&mut r.uid, &live),
        RequestPayload::Destroy(r)         => fix(&mut r.uid, &live),
        RequestPayload::Encrypt(r)         => fix(&mut r.uid, &live),
        RequestPayload::Decrypt(r)         => fix(&mut r.uid, &live),
        RequestPayload::Sign(r)            => fix(&mut r.uid, &live),
        RequestPayload::SignatureVerify(r) => fix(&mut r.uid, &live),
        RequestPayload::AddAttribute(r)    => fix(&mut r.uid, &live),
        RequestPayload::ModifyAttribute(r) => fix(&mut r.uid, &live),
        RequestPayload::DeleteAttribute(r) => fix(&mut r.uid, &live),
        RequestPayload::SetAttribute(r)    => fix(&mut r.uid, &live),
        RequestPayload::AdjustAttribute(r) => fix(&mut r.uid, &live),
        RequestPayload::Export(r)          => fix(&mut r.uid, &live),
        RequestPayload::Deactivate(r)      => fix(&mut r.uid, &live),
        RequestPayload::Check(r)           => fix(&mut r.uid, &live),
        RequestPayload::Archive(r)         => fix(&mut r.uid, &live),
        RequestPayload::Recover(r)         => fix(&mut r.uid, &live),
        RequestPayload::Obliterate(r)      => fix(&mut r.uid, &live),
        RequestPayload::Mac(r)             => fix(&mut r.uid, &live),
        RequestPayload::MacVerify(r)       => fix(&mut r.uid, &live),
        // Ops that don't take a UID (Create, Locate, Query, …) skip.
        _ => {}
    }
    p
}

/// After a successful op, refresh the per-batch ID Placeholder with
/// the most-recently produced UID per KMIP 3.0 §6.4.
fn update_id_placeholder(state: &mut BatchState, payload: &ResponsePayload) {
    let uid: Option<&str> = match payload {
        ResponsePayload::Create(r)      => Some(&r.uid),
        ResponsePayload::CreateKeyPair(r) => Some(&r.private_key_uid),
        ResponsePayload::Register(r)    => Some(&r.uid),
        ResponsePayload::Import(r)      => Some(&r.uid),
        ResponsePayload::Activate(r)    => Some(&r.uid),
        ResponsePayload::Revoke(r)      => Some(&r.uid),
        ResponsePayload::Destroy(r)     => Some(&r.uid),
        ResponsePayload::Deactivate(r)  => Some(&r.uid),
        ResponsePayload::Get(r)         => Some(&r.uid),
        ResponsePayload::GetAttributes(r) => Some(&r.uid),
        ResponsePayload::GetAttributeList(r) => Some(&r.uid),
        ResponsePayload::Locate(r)      => r.uids.first().map(|s| s.as_str()),
        _ => None,
    };
    if let Some(u) = uid { state.id_placeholder = Some(u.to_string()); }
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
        RequestPayload::DecodeFailed { message, .. } => {
            // R7 Phase 1 — surface per-item decode failures as
            // `OperationFailed / InvalidMessage` per KMIP 3.0 §8.2.3.
            return Err(KmipError::failed(
                crate::error::ResultReason::InvalidMessage,
                message,
            ));
        }
        RequestPayload::RngRetrieve(r) => ResponsePayload::RngRetrieve(rng_retrieve(deps, r, correlation_id)?),
        RequestPayload::RngSeed(r) => ResponsePayload::RngSeed(rng_seed(deps, r, correlation_id)?),
        RequestPayload::Pkcs11(r) => ResponsePayload::Pkcs11(pkcs11(deps, r, correlation_id)?),
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
        let req = one_off_request(RequestPayload::Get(crate::kmip30::GetRequest { uid: "ghost".into(), key_wrapping_specification: None }));
        let resp = dispatch(&d, req);
        assert_eq!(resp.batch_items[0].result_status, ResultStatus::OperationFailed);
        assert_eq!(
            resp.batch_items[0].result_reason,
            Some(crate::error::ResultReason::ObjectNotFound.to_wire_value())
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

    // ── R7 multi-batch contracts ───────────────────────────────────────────
    //
    // These pin the spec-compliant behaviour for multi-item RequestMessage
    // dispatch per KMIP 3.0 §8.1.1 / §8.2.1 / §9.5 / §6.4. They MUST
    // continue to pass as the wire codec and dispatcher evolve.

    use crate::kmip30::{
        BatchErrorContinuationOption, CreateRequest, DestroyRequest, GetRequest, KmipAlgorithm,
        ObjectType, RequestHeader, RequestPayload as RP, Attribute, UsageMask,
    };

    /// §8.1.1 — a RequestMessage with three valid BatchItems produces
    /// three ResponseBatchItems (one per request item, in order). This
    /// regression-locks the existing multi-batch path.
    #[test]
    fn r7_phase1_three_valid_items_yield_three_responses() {
        let d = deps();
        let msg = crate::kmip30::RequestMessage {
            header: RequestHeader::v3(),
            batch_items: vec![
                RequestBatchItem {
                    operation: crate::kmip30::Operation::Query,
                    payload: RP::Query(crate::kmip30::QueryRequest {
                        functions: vec![crate::kmip30::QueryFunction::QueryOperations],
                    }),
                },
                RequestBatchItem {
                    operation: crate::kmip30::Operation::Query,
                    payload: RP::Query(crate::kmip30::QueryRequest {
                        functions: vec![crate::kmip30::QueryFunction::QueryObjects],
                    }),
                },
                RequestBatchItem {
                    operation: crate::kmip30::Operation::Query,
                    payload: RP::Query(crate::kmip30::QueryRequest { functions: vec![] }),
                },
            ],
        };
        let resp = dispatch(&d, msg);
        assert_eq!(resp.batch_items.len(), 3, "one response per request item");
        for (i, bi) in resp.batch_items.iter().enumerate() {
            assert_eq!(
                bi.result_status,
                ResultStatus::Success,
                "item {i} expected Success",
            );
        }
    }

    /// §9.5 — `BatchErrorContinuationOption = Stop` (the default). After
    /// the first OperationFailed the server SHALL NOT process subsequent
    /// items and their responses SHALL NOT be returned. The failed item
    /// IS returned.
    #[test]
    fn r7_phase2_stop_mode_halts_after_first_failure() {
        let d = deps();
        let msg = crate::kmip30::RequestMessage {
            header: RequestHeader {
                batch_error_continuation_option: Some(BatchErrorContinuationOption::Stop),
                ..RequestHeader::v3()
            },
            batch_items: vec![
                // Item 0: succeeds (Query).
                RequestBatchItem {
                    operation: crate::kmip30::Operation::Query,
                    payload: RP::Query(crate::kmip30::QueryRequest { functions: vec![] }),
                },
                // Item 1: fails (Get on unknown UID).
                RequestBatchItem {
                    operation: crate::kmip30::Operation::Get,
                    payload: RP::Get(GetRequest { uid: "urn:ghost".into(), key_wrapping_specification: None }),
                },
                // Item 2: should NOT be processed under Stop semantics.
                RequestBatchItem {
                    operation: crate::kmip30::Operation::Query,
                    payload: RP::Query(crate::kmip30::QueryRequest { functions: vec![] }),
                },
            ],
        };
        let resp = dispatch(&d, msg);
        assert_eq!(resp.batch_items.len(), 2, "Stop drops items after the failed one");
        assert_eq!(resp.batch_items[0].result_status, ResultStatus::Success);
        assert_eq!(resp.batch_items[1].result_status, ResultStatus::OperationFailed);
    }

    /// §9.5 — `BatchErrorContinuationOption = Continue`. Even after a
    /// failure the server SHALL keep processing subsequent items and
    /// MUST return a response for each of them.
    #[test]
    fn r7_phase2_continue_mode_processes_all_items() {
        let d = deps();
        let msg = crate::kmip30::RequestMessage {
            header: RequestHeader {
                batch_error_continuation_option: Some(BatchErrorContinuationOption::Continue),
                ..RequestHeader::v3()
            },
            batch_items: vec![
                RequestBatchItem {
                    operation: crate::kmip30::Operation::Get,
                    payload: RP::Get(GetRequest { uid: "urn:ghost-1".into(), key_wrapping_specification: None }),
                },
                RequestBatchItem {
                    operation: crate::kmip30::Operation::Get,
                    payload: RP::Get(GetRequest { uid: "urn:ghost-2".into(), key_wrapping_specification: None }),
                },
                RequestBatchItem {
                    operation: crate::kmip30::Operation::Query,
                    payload: RP::Query(crate::kmip30::QueryRequest { functions: vec![] }),
                },
            ],
        };
        let resp = dispatch(&d, msg);
        assert_eq!(resp.batch_items.len(), 3, "Continue keeps processing");
        assert_eq!(resp.batch_items[0].result_status, ResultStatus::OperationFailed);
        assert_eq!(resp.batch_items[1].result_status, ResultStatus::OperationFailed);
        assert_eq!(resp.batch_items[2].result_status, ResultStatus::Success);
    }

    /// §6.4 ID Placeholder — "a temporary variable… only valid and
    /// preserved during the execution of a single request." A
    /// subsequent BatchItem that uses `UniqueIdentifier =
    /// IDPlaceholder` (the well-known enum value `0x01`) MUST resolve
    /// to the UID produced by the most recent UID-producing op in the
    /// same batch.
    #[test]
    fn r7_phase3_id_placeholder_resolves_within_a_batch() {
        let d = deps();
        // Build a Create + Destroy pair. The Destroy references the
        // Create's UID via the `IDPlaceholder` sentinel rather than a
        // literal UID — the dispatcher MUST resolve that reference
        // against the per-batch ID Placeholder state.
        let msg = crate::kmip30::RequestMessage {
            header: RequestHeader::v3(),
            batch_items: vec![
                RequestBatchItem {
                    operation: crate::kmip30::Operation::Create,
                    payload: RP::Create(CreateRequest {
                        object_type: ObjectType::SymmetricKey,
                        template_attribute: vec![
                            Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes),
                            Attribute::CryptographicLength(128),
                            Attribute::CryptographicUsageMask(UsageMask::ENCRYPT),
                        ],
                    }),
                },
                RequestBatchItem {
                    operation: crate::kmip30::Operation::Destroy,
                    payload: RP::Destroy(DestroyRequest {
                        // ID Placeholder sentinel — Phase 3 resolves
                        // this to the UID Create just produced.
                        uid: ID_PLACEHOLDER_SENTINEL.to_string(),
                    }),
                },
            ],
        };
        let resp = dispatch(&d, msg);
        assert_eq!(resp.batch_items.len(), 2);
        assert_eq!(resp.batch_items[0].result_status, ResultStatus::Success);
        assert_eq!(
            resp.batch_items[1].result_status,
            ResultStatus::Success,
            "Destroy with IDPlaceholder must resolve to Create's UID",
        );
    }

    /// Sentinel string the wire codec emits when it sees
    /// `<UniqueIdentifier type="Enumeration" value="IDPlaceholder"/>`
    /// (enum value `0x00000001`). The dispatcher recognises it and
    /// substitutes the live ID Placeholder before handing the request
    /// to the handler.
    const ID_PLACEHOLDER_SENTINEL: &str = "$IDPlaceholder";

    // ── R7 Phase 4 — Undo rollback contracts ───────────────────────────────
    //
    // KMIP 3.0 §9.5: "If any operation in the request fails [under
    // Undo], then the server SHALL undo all the previous operations.
    // Responses to batch items that have already been processed are
    // returned normally." Combined with §9.x Result Status: those
    // already-completed items have their `ResultStatus` switched to
    // `Operation Undone` (codepoint `0x02`) — distinct from both
    // `Success` (0x00) and `OperationFailed` (0x01).

    use crate::store::ObjectRecord;
    use crate::kmip30::State;

    /// Item N fails ⇒ items 0..N-1 are reported with
    /// `OperationUndone`; the failed item keeps `OperationFailed`;
    /// items N+1.. are NOT returned (same Stop-like truncation, just
    /// with the prior items relabelled). Verifies the response shape.
    #[test]
    fn r7_phase4_undo_relabels_completed_items_as_undone() {
        let d = deps();
        // Seed a PreActive key so the Activate succeeds.
        d.store.put(ObjectRecord {
            uid: "k-a".into(),
            object_type: ObjectType::SymmetricKey,
            algorithm: KmipAlgorithm::Aes,
            cryptographic_length: 128,
            usage_mask: UsageMask::ENCRYPT,
            state: State::PreActive,
            initial_date: time::OffsetDateTime::UNIX_EPOCH,
            ..ObjectRecord::default()
        }).unwrap();
        let msg = crate::kmip30::RequestMessage {
            header: RequestHeader {
                batch_error_continuation_option: Some(BatchErrorContinuationOption::Undo),
                ..RequestHeader::v3()
            },
            batch_items: vec![
                RequestBatchItem {
                    operation: crate::kmip30::Operation::Activate,
                    payload: RP::Activate(crate::kmip30::ActivateRequest { uid: "k-a".into() }),
                },
                RequestBatchItem {
                    operation: crate::kmip30::Operation::Destroy,
                    payload: RP::Destroy(DestroyRequest { uid: "urn:ghost".into() }),
                },
                RequestBatchItem {
                    operation: crate::kmip30::Operation::Query,
                    payload: RP::Query(crate::kmip30::QueryRequest { functions: vec![] }),
                },
            ],
        };
        let resp = dispatch(&d, msg);
        assert_eq!(resp.batch_items.len(), 2, "Undo truncates after the failure");
        assert_eq!(
            resp.batch_items[0].result_status,
            ResultStatus::OperationUndone,
            "the successful Activate should be relabelled OperationUndone",
        );
        assert_eq!(
            resp.batch_items[1].result_status,
            ResultStatus::OperationFailed,
            "the failed Destroy keeps OperationFailed",
        );
    }

    /// Snapshot/restore: the Activate's state mutation (PreActive →
    /// Active) MUST be reversed by the Undo wave.
    #[test]
    fn r7_phase4_undo_restores_pre_op_object_record() {
        let d = deps();
        d.store.put(ObjectRecord {
            uid: "k-b".into(),
            object_type: ObjectType::SymmetricKey,
            algorithm: KmipAlgorithm::Aes,
            cryptographic_length: 128,
            usage_mask: UsageMask::ENCRYPT,
            state: State::PreActive,
            initial_date: time::OffsetDateTime::UNIX_EPOCH,
            ..ObjectRecord::default()
        }).unwrap();
        let msg = crate::kmip30::RequestMessage {
            header: RequestHeader {
                batch_error_continuation_option: Some(BatchErrorContinuationOption::Undo),
                ..RequestHeader::v3()
            },
            batch_items: vec![
                RequestBatchItem {
                    operation: crate::kmip30::Operation::Activate,
                    payload: RP::Activate(crate::kmip30::ActivateRequest { uid: "k-b".into() }),
                },
                RequestBatchItem {
                    operation: crate::kmip30::Operation::Destroy,
                    payload: RP::Destroy(DestroyRequest { uid: "urn:ghost".into() }),
                },
            ],
        };
        let _ = dispatch(&d, msg);
        let rec = d.store.get("k-b").unwrap().unwrap();
        assert_eq!(
            rec.state,
            State::PreActive,
            "Undo wave must restore the pre-Activate state",
        );
        assert!(
            rec.activation_date.is_none(),
            "Activate's activation_date side-effect must be reverted",
        );
    }

    /// Stop mode (the default) MUST NOT roll anything back. This
    /// guards against accidentally triggering the Undo wave when
    /// `BatchErrorContinuationOption` is absent or set to Stop.
    #[test]
    fn r7_phase4_stop_mode_preserves_completed_side_effects() {
        let d = deps();
        d.store.put(ObjectRecord {
            uid: "k-c".into(),
            object_type: ObjectType::SymmetricKey,
            algorithm: KmipAlgorithm::Aes,
            cryptographic_length: 128,
            usage_mask: UsageMask::ENCRYPT,
            state: State::PreActive,
            initial_date: time::OffsetDateTime::UNIX_EPOCH,
            ..ObjectRecord::default()
        }).unwrap();
        let msg = crate::kmip30::RequestMessage {
            header: RequestHeader {
                batch_error_continuation_option: Some(BatchErrorContinuationOption::Stop),
                ..RequestHeader::v3()
            },
            batch_items: vec![
                RequestBatchItem {
                    operation: crate::kmip30::Operation::Activate,
                    payload: RP::Activate(crate::kmip30::ActivateRequest { uid: "k-c".into() }),
                },
                RequestBatchItem {
                    operation: crate::kmip30::Operation::Destroy,
                    payload: RP::Destroy(DestroyRequest { uid: "urn:ghost".into() }),
                },
            ],
        };
        let resp = dispatch(&d, msg);
        assert_eq!(resp.batch_items[0].result_status, ResultStatus::Success);
        let rec = d.store.get("k-c").unwrap().unwrap();
        assert_eq!(
            rec.state,
            State::Active,
            "Stop mode preserves the Activate's effect",
        );
    }
}
