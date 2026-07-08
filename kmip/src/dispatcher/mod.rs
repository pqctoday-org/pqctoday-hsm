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

use std::sync::Arc;

use uuid::Uuid;

use crate::error::KmipError;
use crate::kmip30::{
    ActivateRequest, CreateKeyPairRequest, CreateRequest, DecryptRequest, DestroyRequest,
    EncryptRequest, GetRequest,
    LocateRequest, QueryRequest, RequestBatchItem, RequestMessage,
    ResponseBatchItem, ResponseHeader, ResponseMessage, ResponsePayload, ResultStatus,
    RevokeRequest, SignRequest, SignatureVerifyRequest,
};
use crate::ops::{
    activate::activate,
    allocation_and_config::{get_constraints, get_usage_allocation, set_constraints, set_defaults, set_endpoint_role},
    async_ops::{cancel, process, query_asynchronous_requests},
    attribute_mutate::{add_attribute, adjust_attribute, delete_attribute, modify_attribute, set_attribute},
    create::create, create_key_pair::create_key_pair, decrypt::decrypt,
    derive_key::derive_key,
    destroy::destroy, encrypt::encrypt, encapsulate::encapsulate, decapsulate::decapsulate, get::get,
    get_attribute_list::get_attribute_list, get_attributes::get_attributes,
    interop::interop,
    lifecycle_and_protocol::{archive, check, deactivate, discover_versions, obliterate, obtain_lease, ping, recover},
    locate::locate,
    mac_and_hash::{hash, mac, mac_verify},
    query::query,
    register_import_export::{export, import_object, register},
    rekey::{rekey, rekey_key_pair},
    revoke::revoke,
    rng_and_pkcs11::{pkcs11, rng_retrieve, rng_seed},
    session_and_auth::{create_credential, create_group, create_user, log, login, logout},
    sign::sign, signature_verify::signature_verify,
    split_key::{create_split_key, join_split_key},
    Deps,
};
// Certify / Re-certify / Validate handlers compile only in the `native`
// build (see `ops/mod.rs`); the wasm dispatcher answers those operations
// with `OperationNotSupported` via the `not(native)` match arms below.
#[cfg(feature = "native")]
use crate::ops::{validate::validate, certify::{certify, recertify}};

use crate::kmip30::RequestPayload;

/// Top-level entry: decoded inbound `RequestMessage` → encoded outbound
/// `ResponseMessage`.
///
/// Honours KMIP 3.0 §9.5 `Batch Error Continuation Option`:
/// - **Stop** (default): halt at first failure; later items are NOT
///   processed and NOT returned.
/// - **Continue**: process every item independently.
/// - **Undo**: halt at first failure and roll back the earlier
///   successful items, relabelling them `OperationUndone` (see
///   [`undo_wave`]).
///
/// Threads the §6.4 **ID Placeholder** through the batch: the
/// most-recently-produced UID is stashed in `BatchState` and any item
/// that references the placeholder sentinel
/// [`ID_PLACEHOLDER_SENTINEL`] gets it substituted on entry.
pub fn dispatch(deps: &Deps, request: RequestMessage) -> ResponseMessage {
    dispatch_with_transport_identity(deps, request, None)
}

/// [`dispatch`] with an optional transport-level identity — the mTLS
/// client-certificate subject CN the listener extracted after a
/// successful client-cert handshake (K14). `None` for plain-TLS
/// connections and in-process callers.
pub fn dispatch_with_transport_identity(
    deps: &Deps,
    request: RequestMessage,
    transport_identity: Option<crate::server::auth::Identity>,
) -> ResponseMessage {
    use crate::kmip30::BatchErrorContinuationOption;
    // K14 — KMIP 3.0 §8.1.2 `Authentication`. When a credential store
    // is configured, every request must authenticate (header
    // Credential verified, or mTLS-verified client identity); failure
    // fails every batch item with `Authentication Not Successful
    // (0x03)` — same per-item shape as the K4 async-indicator gate.
    // Open-auth mode (no users configured — the default, which the
    // hermetic replay harness relies on) skips enforcement entirely.
    let auth = match authenticate_request(deps, &request.header, transport_identity) {
        Ok(ctx) => ctx,
        Err(()) => {
            let items = request
                .batch_items
                .iter()
                .map(|item| ResponseBatchItem {
                    operation: Some(item.operation),
                    result_status: ResultStatus::OperationFailed,
                    result_reason: Some(
                        crate::error::ResultReason::AuthenticationNotSuccessful.to_wire_value(),
                    ),
                    result_message: Some("authentication not successful".into()),
                    payload: None,
                    asynchronous_correlation_value: None,
                })
                .collect();
            return ResponseMessage {
                header: ResponseHeader::v3_now(),
                batch_items: items,
            };
        }
    };
    // K4 / Phase 4 — KMIP 3.0 §8.1.2 `Asynchronous Indicator`. Handling
    // moved from a single whole-batch gate here into per-item logic in
    // `dispatch_one`: each batch item can be a different operation, and
    // Poll/Cancel/Process/Query Asynchronous Requests themselves can
    // never be asynchronous (§6.1.43/§6.1.5/§6.1.44 each say so
    // explicitly), so a blanket batch-level check was too coarse once
    // the server gained real asynchronous capability. `Optional` /
    // `Prohibited` / absent all proceed synchronously, unchanged.
    let mode = request
        .header
        .batch_error_continuation_option
        .unwrap_or(BatchErrorContinuationOption::Stop);
    let mut state = BatchState::default();
    let mut items: Vec<ResponseBatchItem> = Vec::with_capacity(request.batch_items.len());
    for item in request.batch_items {
        let response = dispatch_one(deps, item, &mut state, &auth, request.header.asynchronous_indicator);
        // D1 — KMIP request counter (operation × success/error). `native` only —
        // the wasm core has no Prometheus registry (`crate::metrics` is gated out).
        #[cfg(feature = "native")]
        if let Some(op) = response.operation {
            crate::metrics::record_kmip_request(
                op.metric_label(),
                response.result_status == ResultStatus::Success,
            );
        }
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

/// K14 — KMIP 3.0 §8.1.2 authentication gate.
///
/// - **Open-auth** (no configured users — the default): every request
///   passes; header `Authentication` content is ignored. A transport
///   identity (mTLS subject CN) is still carried for audit/Login use.
/// - **Configured auth**: the request authenticates iff
///   1. any header `Credential` verifies against the config-backed
///      store ([`ConfigVerifier`]), or
///   2. no header credential was offered AND the TLS layer verified a
///      client certificate (mTLS) — its subject CN is the identity.
///   A credential that was *offered but failed* is rejected even on an
///   mTLS connection (an explicitly-wrong credential must not silently
///   fall back).
fn authenticate_request(
    deps: &Deps,
    header: &crate::kmip30::RequestHeader,
    transport_identity: Option<crate::server::auth::Identity>,
) -> Result<crate::server::auth::AuthContext, ()> {
    use crate::kmip30::Credential;
    use crate::server::auth::{AuthContext, ConfigVerifier, CredentialVerifier};
    if !deps.config.auth_enabled() {
        // Open-auth — REQUIRED default for the hermetic replay harness.
        return Ok(AuthContext { identity: transport_identity });
    }
    // Phase 1.4 (K14, T4) — a Login-issued ticket authenticates a
    // request exactly like a verified Username/Password credential:
    // same header slot (§8.1.2 Authentication carries a `Credential`,
    // and Ticket (0x06) is one of the published Credential Types —
    // §9.9 Table 517), same all-or-nothing per-request re-check (no
    // separate "session" concept beyond "is this ticket live"). An
    // expired or unknown ticket falls through to the credential/mTLS
    // checks below rather than failing immediately, so a client that
    // sends a Ticket AND a fresh Username/Password isn't penalised for
    // the stale ticket.
    if let Some(identity) = header.authentication.iter().find_map(|c| match c {
        Credential::Ticket(t) => {
            let sessions = deps.sessions.lock().unwrap_or_else(|e| e.into_inner());
            let record = sessions.get(&t.ticket_value)?;
            if record.is_expired(time::OffsetDateTime::now_utc()) {
                None
            } else {
                Some(record.identity.clone())
            }
        }
        _ => None,
    }) {
        return Ok(AuthContext { identity: Some(identity) });
    }
    let verifier = ConfigVerifier::new(&deps.config.auth_users);
    if let Some(identity) = header
        .authentication
        .iter()
        .find_map(|c| verifier.verify(c).ok())
    {
        return Ok(AuthContext { identity: Some(identity) });
    }
    if header.authentication.is_empty() {
        if let Some(identity) = transport_identity {
            return Ok(AuthContext { identity: Some(identity) });
        }
    }
    Err(())
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
                    // Restore the pre-op snapshot. This is a SYSTEM rollback, not
                    // a client lifecycle op, so it may be a reverse transition the
                    // forward FSM legitimately rejects (e.g. Active→PreActive after
                    // undoing an Activate). Bypass the store-layer FSM gate (S-10)
                    // by remove + put rather than `update` (which now enforces it).
                    let _ = deps.store.remove(&rec.uid);
                    let _ = deps.store.put(rec);
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

/// K3 — the dispatcher's REAL operation surface: exactly the ops
/// `handle_payload` routes to an implemented handler (one entry per
/// non-marker `RequestPayload` match arm below — keep the two in
/// sync; `dispatcher_surface_matches_handled_operations` in tests
/// and `ops::query::supported_operations()` both consume this).
/// Any other recognized Operation decodes to
/// `RequestPayload::Unsupported` and fails its batch item with
/// `OperationNotSupported (0x05)`.
pub const HANDLED_OPERATIONS: &[crate::kmip30::Operation] = {
    use crate::kmip30::Operation as Op;
    &[
        Op::Query, Op::Create, Op::CreateKeyPair, Op::Get,
        Op::GetAttributes, Op::GetAttributeList,
        Op::AddAttribute, Op::ModifyAttribute, Op::DeleteAttribute,
        Op::SetAttribute, Op::AdjustAttribute,
        Op::Locate, Op::Activate, Op::Revoke, Op::Destroy,
        Op::Encrypt, Op::Decrypt, Op::Sign, Op::SignatureVerify,
        // KMIP 3.0 WD19 — first-class ML-KEM Encapsulate / Decapsulate.
        Op::Encapsulate, Op::Decapsulate,
        Op::Interop, Op::Register, Op::Import, Op::Export,
        Op::Deactivate, Op::Check, Op::ObtainLease, Op::Archive, Op::Recover,
        Op::CreateSplitKey, Op::JoinSplitKey,
        Op::Obliterate, Op::DiscoverVersions, Op::Ping,
        Op::MAC, Op::MACVerify, Op::Hash,
        Op::CreateCredential, Op::CreateGroup, Op::CreateUser,
        Op::Log, Op::Login, Op::Logout,
        Op::RNGRetrieve, Op::RNGSeed, Op::Pkcs11,
        // K19 — Baseline client-to-server ops (§6.1.26/27/58/59).
        Op::GetUsageAllocation, Op::GetConstraints, Op::SetConstraints,
        Op::SetDefaults, Op::SetEndpointRole,
        // K20 — §6.1.18 Derive Key.
        Op::DeriveKey,
        // K21 — §6.1.51 Re-key / §6.1.52 Re-key Key Pair.
        Op::ReKey, Op::ReKeyKeyPair,
        // P2.2 — §6.1.62 Validate (certificate-chain validation).
        Op::Validate,
        // P2.3 — §6.1.6 Certify / §6.1.50 Re-certify (PQC-capable CA).
        Op::Certify, Op::ReCertify,
        // Phase 4 — asynchronous subsystem (§6.1.43/§6.1.5/§6.1.44/§6.1.46).
        Op::Poll, Op::Cancel, Op::Process, Op::QueryAsynchronousRequests,
    ]
};

fn dispatch_one(
    deps: &Deps,
    item: RequestBatchItem,
    state: &mut BatchState,
    auth: &crate::server::auth::AuthContext,
    asynchronous_indicator: Option<crate::kmip30::AsynchronousIndicator>,
) -> ResponseBatchItem {
    let correlation_id = Uuid::new_v4().to_string();
    let op = item.operation;
    let payload = match substitute_id_placeholder(item.payload, state) {
        Ok(p) => p,
        Err(err) => {
            return ResponseBatchItem {
                operation: Some(op),
                result_status: ResultStatus::OperationFailed,
                result_reason: Some(err.result_reason().to_wire_value()),
                result_message: Some(err.to_string()),
                payload: None,
                asynchronous_correlation_value: None,
            };
        }
    };

    // Async subsystem — §6.1.43 `Poll` never runs through the normal
    // Success/Failed handler wrapping below: its response impersonates
    // whatever op it's polling for ("SHALL be identical to the response
    // that would have been sent if the operation had completed
    // synchronously"), which `handle_payload`'s uniform per-op wrapping
    // can't express. Handled first and returns early.
    if let RequestPayload::Poll(req) = &payload {
        return handle_poll(deps, req);
    }

    // Async subsystem — KMIP 3.0 §8.1.2 `Asynchronous Indicator =
    // Mandatory`. Poll/Cancel/Process/QueryAsynchronousRequests are
    // themselves never asynchronous (§6.1.5/§6.1.44/§6.1.46 all say so
    // explicitly) and Query/DiscoverVersions/Ping are trivial
    // negotiation ops not worth deferring — every other handled op is
    // eligible (`is_async_eligible`). An eligible op is enqueued as a
    // real job (§9.1 Asynchronous Correlation Value) instead of run
    // inline; the response is `OperationPending` with no payload, per
    // the same table row Poll's own "not yet complete" response uses.
    // An ineligible op fails just this item — `Optional` / `Prohibited`
    // / absent all proceed synchronously, unchanged.
    if asynchronous_indicator == Some(crate::kmip30::AsynchronousIndicator::Mandatory) {
        if is_async_eligible(op) {
            return enqueue_async_job(deps, op, payload, correlation_id, auth.clone());
        }
        return ResponseBatchItem {
            operation: Some(op),
            result_status: ResultStatus::OperationFailed,
            result_reason: Some(crate::error::ResultReason::OperationNotSupported.to_wire_value()),
            result_message: Some(format!("{op:?} is not eligible for asynchronous processing")),
            payload: None,
            asynchronous_correlation_value: None,
        };
    }

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

    let result = handle_payload(deps, payload, &correlation_id, auth);
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
                asynchronous_correlation_value: None,
            }
        }
        Err(err) => ResponseBatchItem {
            operation: Some(op),
            result_status: ResultStatus::OperationFailed,
            result_reason: Some(err.result_reason().to_wire_value()),
            result_message: Some(err.to_string()),
            payload: None,
            asynchronous_correlation_value: None,
        },
    }
}

/// Async subsystem — ops that MAY be processed asynchronously. Broad
/// by design (KMIP 3.0 §8.1.2: "any operation MAY be processed
/// asynchronously"), minus:
/// - the async-management ops themselves (`Poll`/`Cancel`/`Process`/
///   `QueryAsynchronousRequests`) — each explicitly documents its own
///   response as never asynchronous;
/// - `Query`/`DiscoverVersions`/`Ping` — trivial negotiation ops with
///   no realistic latency to hide behind polling.
/// Every other entry in [`HANDLED_OPERATIONS`] is eligible.
fn is_async_eligible(op: crate::kmip30::Operation) -> bool {
    use crate::kmip30::Operation as Op;
    HANDLED_OPERATIONS.contains(&op)
        && !matches!(
            op,
            Op::Poll
                | Op::Cancel
                | Op::Process
                | Op::QueryAsynchronousRequests
                | Op::Query
                | Op::DiscoverVersions
                | Op::Ping
        )
}

/// Async subsystem — enqueue `payload` as a new job and respond
/// `OperationPending` with a fresh Asynchronous Correlation Value. The
/// job itself starts executing via [`spawn_or_run_async_job`] before
/// this function returns; whether that means "on a detached thread,
/// concurrently" or "inline, right now" depends on whether `deps` has
/// a usable [`crate::ops::Deps::self_handle`] — either way, THIS
/// response never carries the payload.
fn enqueue_async_job(
    deps: &Deps,
    op: crate::kmip30::Operation,
    payload: RequestPayload,
    correlation_id: String,
    auth: crate::server::auth::AuthContext,
) -> ResponseBatchItem {
    let cv = deps.new_correlation_value();
    let job = crate::ops::AsyncJob::new(op);
    deps.async_jobs
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(cv.clone(), Arc::clone(&job));
    spawn_or_run_async_job(deps, job, payload, correlation_id, auth);
    ResponseBatchItem {
        operation: Some(op),
        result_status: ResultStatus::OperationPending,
        result_reason: None,
        result_message: None,
        payload: None,
        asynchronous_correlation_value: Some(cv),
    }
}

/// Async subsystem — native, with a `self_handle` installed (the
/// production server): run `job` on a real detached OS thread, so it
/// genuinely executes concurrently with whatever the client does next.
/// Every other configuration (any test building `Deps` via
/// `Deps::new`, or a non-`native` build with no OS threads at all)
/// falls back to running it inline before this call returns — see
/// [`crate::ops::Deps::self_handle`] for why that fallback is still
/// fully protocol-correct.
fn spawn_or_run_async_job(
    deps: &Deps,
    job: Arc<crate::ops::AsyncJob>,
    payload: RequestPayload,
    correlation_id: String,
    auth: crate::server::auth::AuthContext,
) {
    #[cfg(feature = "native")]
    if let Some(deps_arc) = deps.self_handle.get().and_then(|w| w.upgrade()) {
        // Clone the handle BEFORE moving one copy into the closure —
        // if `spawn` itself fails (OS resource exhaustion), the
        // closure (and everything it captured, including that moved
        // `Arc`) is dropped, not returned to us; we still need a
        // handle to mark the job failed instead of leaving it stuck
        // at `Submitted` forever.
        let job_for_thread = Arc::clone(&job);
        let spawned = std::thread::Builder::new()
            .name("kmip-async-job".into())
            .spawn(move || {
                job_for_thread.mark_in_process();
                let outcome = handle_payload(&deps_arc, payload, &correlation_id, &auth);
                job_for_thread.mark_completed(outcome);
            });
        if spawned.is_ok() {
            return;
        }
        job.mark_completed(Err(KmipError::internal(
            "failed to spawn background async-job thread",
        )));
        return;
    }
    run_async_job_eagerly(deps, job, payload, correlation_id, &auth);
}

/// Async subsystem — run `job` inline, synchronously, right now. Used
/// whenever genuine background execution isn't available (see
/// [`spawn_or_run_async_job`]). The job's `stage` still visits
/// `InProcess` (briefly, on this same thread) before `Completed`, so
/// `Poll`/`Cancel`/`Process` see a real, if instantaneous, state
/// machine — not a special-cased shortcut.
fn run_async_job_eagerly(
    deps: &Deps,
    job: Arc<crate::ops::AsyncJob>,
    payload: RequestPayload,
    correlation_id: String,
    auth: &crate::server::auth::AuthContext,
) {
    job.mark_in_process();
    let outcome = handle_payload(deps, payload, &correlation_id, auth);
    job.mark_completed(outcome);
}

/// Async subsystem — §6.1.43 `Poll`. Looks up the job by its
/// Asynchronous Correlation Value:
/// - unknown value → `OperationFailed / Invalid Asynchronous
///   Correlation Value`, echoing `Poll` itself as the operation.
/// - not yet `Completed` → `OperationPending`, no payload, echoing
///   `Poll` (the response IS to this Poll request).
/// - `Completed` → "identical to the response that would have been
///   sent if the operation had completed synchronously" (§6.1.43):
///   echoes the ORIGINAL polled operation + its real outcome, exactly
///   as `dispatch_one`'s normal Success/Failed wrapping would have.
fn handle_poll(deps: &Deps, req: &crate::kmip30::PollRequest) -> ResponseBatchItem {
    use crate::kmip30::{Operation, ProcessingStage};
    let job = {
        let jobs = deps.async_jobs.lock().unwrap_or_else(|e| e.into_inner());
        jobs.get(&req.asynchronous_correlation_value).cloned()
    };
    let Some(job) = job else {
        let err = KmipError::invalid_asynchronous_correlation_value();
        return ResponseBatchItem {
            operation: Some(Operation::Poll),
            result_status: ResultStatus::OperationFailed,
            result_reason: Some(err.result_reason().to_wire_value()),
            result_message: Some(err.to_string()),
            payload: None,
            asynchronous_correlation_value: None,
        };
    };
    let st = job.state.lock().unwrap_or_else(|e| e.into_inner());
    if st.stage != ProcessingStage::Completed {
        return ResponseBatchItem {
            operation: Some(Operation::Poll),
            result_status: ResultStatus::OperationPending,
            result_reason: None,
            result_message: None,
            payload: None,
            asynchronous_correlation_value: Some(req.asynchronous_correlation_value.clone()),
        };
    }
    match &st.outcome {
        Some(Ok(payload)) => ResponseBatchItem {
            operation: Some(st.operation),
            result_status: ResultStatus::Success,
            result_reason: None,
            result_message: None,
            payload: Some(payload.clone()),
            asynchronous_correlation_value: None,
        },
        Some(Err(err)) => ResponseBatchItem {
            operation: Some(st.operation),
            result_status: ResultStatus::OperationFailed,
            result_reason: Some(err.result_reason().to_wire_value()),
            result_message: Some(err.to_string()),
            payload: None,
            asynchronous_correlation_value: None,
        },
        None => unreachable!("AsyncJob::mark_completed always sets `outcome` before `stage = Completed`"),
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
        // K20 — the derived object is freshly minted (§6.1.18).
        ResponsePayload::DeriveKey(r) => vec![r.uid.clone()],
        // K21 — the replacement objects are freshly minted
        // (§6.1.51 / §6.1.52); Undo deletes them.
        ResponsePayload::ReKey(r) => vec![r.uid.clone()],
        ResponsePayload::ReKeyKeyPair(r) => {
            vec![r.private_key_uid.clone(), r.public_key_uid.clone()]
        }
        // P2.3 — the issued / renewed certificate is freshly minted
        // (§6.1.6 / §6.1.50); Undo deletes it.
        ResponsePayload::Certify(r) => vec![r.uid.clone()],
        ResponsePayload::ReCertify(r) => vec![r.uid.clone()],
        // R7 Phase 4 fix — a rekey-on-use policy can make Sign mint a whole
        // new key pair inline (`ops::sign::rekey_and_sign`); both halves
        // didn't exist before this batch item, so Undo must delete them.
        // `rekeyed` is `None` on the ordinary (ordinary Sign) path.
        ResponsePayload::Sign(r) => match &r.rekeyed {
            Some(info) => vec![info.new_private_key_uid.clone(), info.new_public_key_uid.clone()],
            None => Vec::new(),
        },
        _ => Vec::new(),
    }
}

/// Walk the request payload and replace any field equal to
/// [`ID_PLACEHOLDER_SENTINEL`] with the live ID Placeholder. Covers the
/// `uid` field on every payload that consumes a single UID; multi-UID
/// payloads (none of the OASIS Baseline tests use them so far) can be
/// added as the corpus grows.
///
/// Errs with [`KmipError::id_placeholder_unset`] when an item actually
/// references the sentinel but no live placeholder exists yet (typically
/// because the item that was supposed to produce one — e.g.
/// `CreateKeyPair` — failed earlier in this batch). Without this check the
/// sentinel string passed through unresolved and the downstream store
/// lookup failed with a confusing "UID \"$IDPlaceholder\" not found".
fn substitute_id_placeholder(
    payload: RequestPayload,
    state: &BatchState,
) -> Result<RequestPayload, KmipError> {
    let live = state.id_placeholder.as_deref();
    let mut missing = false;
    fn fix(s: &mut String, live: Option<&str>, missing: &mut bool) {
        if s == ID_PLACEHOLDER_SENTINEL {
            match live {
                Some(l) => *s = l.to_string(),
                None => *missing = true,
            }
        }
    }
    let mut p = payload;
    match &mut p {
        RequestPayload::Get(r)             => fix(&mut r.uid, live, &mut missing),
        RequestPayload::GetAttributes(r)   => fix(&mut r.uid, live, &mut missing),
        RequestPayload::GetAttributeList(r)=> fix(&mut r.uid, live, &mut missing),
        RequestPayload::Activate(r)        => fix(&mut r.uid, live, &mut missing),
        RequestPayload::Revoke(r)          => fix(&mut r.uid, live, &mut missing),
        RequestPayload::Destroy(r)         => fix(&mut r.uid, live, &mut missing),
        RequestPayload::Encrypt(r)         => fix(&mut r.uid, live, &mut missing),
        RequestPayload::Decrypt(r)         => fix(&mut r.uid, live, &mut missing),
        RequestPayload::Encapsulate(r)     => fix(&mut r.uid, live, &mut missing),
        RequestPayload::Decapsulate(r)     => fix(&mut r.uid, live, &mut missing),
        RequestPayload::Sign(r)            => fix(&mut r.uid, live, &mut missing),
        RequestPayload::SignatureVerify(r) => fix(&mut r.uid, live, &mut missing),
        // P2.2 — Validate carries a repeatable UID list (§6.1.62).
        RequestPayload::Validate(r) => {
            for uid in &mut r.uids { fix(uid, live, &mut missing); }
        }
        RequestPayload::AddAttribute(r)    => fix(&mut r.uid, live, &mut missing),
        RequestPayload::ModifyAttribute(r) => fix(&mut r.uid, live, &mut missing),
        RequestPayload::DeleteAttribute(r) => fix(&mut r.uid, live, &mut missing),
        RequestPayload::SetAttribute(r)    => fix(&mut r.uid, live, &mut missing),
        RequestPayload::AdjustAttribute(r) => fix(&mut r.uid, live, &mut missing),
        RequestPayload::Export(r)          => fix(&mut r.uid, live, &mut missing),
        RequestPayload::Deactivate(r)      => fix(&mut r.uid, live, &mut missing),
        RequestPayload::Check(r)           => fix(&mut r.uid, live, &mut missing),
        RequestPayload::Archive(r)         => fix(&mut r.uid, live, &mut missing),
        RequestPayload::Recover(r)         => fix(&mut r.uid, live, &mut missing),
        RequestPayload::Obliterate(r)      => fix(&mut r.uid, live, &mut missing),
        RequestPayload::Mac(r)             => fix(&mut r.uid, live, &mut missing),
        RequestPayload::MacVerify(r)       => fix(&mut r.uid, live, &mut missing),
        RequestPayload::GetUsageAllocation(r) => fix(&mut r.uid, live, &mut missing),
        // K20 — Derive Key carries a repeatable UID list (§6.1.18).
        RequestPayload::DeriveKey(r) => {
            for uid in &mut r.uids { fix(uid, live, &mut missing); }
        }
        // K21 — §6.1.51 / §6.1.52 Re-key targets.
        RequestPayload::ReKey(r)           => fix(&mut r.uid, live, &mut missing),
        RequestPayload::ReKeyKeyPair(r)    => fix(&mut r.uid, live, &mut missing),
        // P2.3 — Certify MAY name a PublicKey by UID (Option); Re-certify
        // always names the existing Certificate.
        RequestPayload::Certify(r)         => { if let Some(u) = &mut r.uid { fix(u, live, &mut missing); } }
        RequestPayload::ReCertify(r)       => fix(&mut r.uid, live, &mut missing),
        // Ops that don't take a UID (Create, Locate, Query, …) skip.
        _ => {}
    }
    if missing {
        return Err(KmipError::id_placeholder_unset());
    }
    Ok(p)
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
        // K20 — §6.4: Derive Key is one of the ops that "SHALL set the
        // ID Placeholder" to the newly derived object's UID.
        ResponsePayload::DeriveKey(r)   => Some(&r.uid),
        // K21 — §6.4: the replacement UID; for the pair, "the first
        // value in the response is the Unique Identifier value with
        // respect to ID Placeholder handling" → the Private Key
        // Unique Identifier (Table 411 lists it first).
        ResponsePayload::ReKey(r)        => Some(&r.uid),
        ResponsePayload::ReKeyKeyPair(r) => Some(&r.private_key_uid),
        // P2.3 — §6.4: the new Certificate's UID becomes the ID
        // Placeholder for the rest of the batch.
        ResponsePayload::Certify(r)      => Some(&r.uid),
        ResponsePayload::ReCertify(r)    => Some(&r.uid),
        _ => None,
    };
    if let Some(u) = uid { state.id_placeholder = Some(u.to_string()); }
}

fn handle_payload(
    deps: &Deps,
    payload: RequestPayload,
    correlation_id: &str,
    auth: &crate::server::auth::AuthContext,
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
        RequestPayload::Encapsulate(r) => {
            ResponsePayload::Encapsulate(encapsulate(deps, r, correlation_id)?)
        }
        RequestPayload::Decapsulate(r) => {
            ResponsePayload::Decapsulate(decapsulate(deps, r, correlation_id)?)
        }
        RequestPayload::Sign(r) => ResponsePayload::Sign(sign(deps, r, correlation_id)?),
        RequestPayload::SignatureVerify(r) => {
            ResponsePayload::SignatureVerify(signature_verify(deps, r, correlation_id)?)
        }
        #[cfg(feature = "native")]
        RequestPayload::Validate(r) => ResponsePayload::Validate(validate(deps, r, correlation_id)?),
        // P2.3 — §6.1.6 Certify / §6.1.50 Re-certify (PQC-capable CA).
        #[cfg(feature = "native")]
        RequestPayload::Certify(r) => ResponsePayload::Certify(certify(deps, r, correlation_id)?),
        #[cfg(feature = "native")]
        RequestPayload::ReCertify(r) => ResponsePayload::ReCertify(recertify(deps, r, correlation_id)?),
        // wasm core: the ring/rcgen-backed CA + chain-validation ops are not
        // compiled in. Answer them like any recognized-but-unhandled op.
        #[cfg(not(feature = "native"))]
        RequestPayload::Validate(_) | RequestPayload::Certify(_) | RequestPayload::ReCertify(_) => {
            return Err(KmipError::failed(
                crate::error::ResultReason::OperationNotSupported,
                "this build does not include certificate issuance / validation",
            ));
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
        RequestPayload::ObtainLease(r) => ResponsePayload::ObtainLease(obtain_lease(deps, r, correlation_id)?),
        RequestPayload::CreateSplitKey(r) => ResponsePayload::CreateSplitKey(create_split_key(deps, r, correlation_id)?),
        RequestPayload::JoinSplitKey(r) => ResponsePayload::JoinSplitKey(join_split_key(deps, r, correlation_id)?),
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
        RequestPayload::Login(r) => ResponsePayload::Login(login(deps, r, auth, correlation_id)?),
        RequestPayload::Logout(r) => ResponsePayload::Logout(logout(deps, r, correlation_id)?),
        RequestPayload::DecodeFailed { message, reason, .. } => {
            // R7 Phase 1 — surface per-item decode failures as
            // `OperationFailed` per KMIP 3.0 §8.2.3. The reason is
            // `InvalidMessage` for generic failures; K8 threads the
            // spec-named reason through when one applies (e.g.
            // `Key Format Type Not Supported (0x10)`).
            return Err(KmipError::failed(reason, message));
        }
        RequestPayload::Unsupported(op) => {
            // K3 — recognized KMIP 3.0 Operation with no handler:
            // per-batch-item `OperationFailed / OperationNotSupported
            // (0x05)` per §9.2, naming the op. The message stays
            // well-formed so Batch Error Continuation applies and
            // sibling items still process.
            return Err(KmipError::failed(
                crate::error::ResultReason::OperationNotSupported,
                format!("operation {op:?} is not supported by this server"),
            ));
        }
        RequestPayload::RngRetrieve(r) => ResponsePayload::RngRetrieve(rng_retrieve(deps, r, correlation_id)?),
        RequestPayload::RngSeed(r) => ResponsePayload::RngSeed(rng_seed(deps, r, correlation_id)?),
        RequestPayload::Pkcs11(r) => ResponsePayload::Pkcs11(pkcs11(deps, r, correlation_id)?),
        // K19 — Baseline client-to-server ops (§6.1.26/27/58/59).
        RequestPayload::GetUsageAllocation(r) => {
            ResponsePayload::GetUsageAllocation(get_usage_allocation(deps, r, correlation_id)?)
        }
        RequestPayload::GetConstraints(r) => {
            ResponsePayload::GetConstraints(get_constraints(deps, r, correlation_id)?)
        }
        RequestPayload::SetConstraints(r) => {
            ResponsePayload::SetConstraints(set_constraints(deps, r, correlation_id)?)
        }
        RequestPayload::SetDefaults(r) => {
            ResponsePayload::SetDefaults(set_defaults(deps, r, correlation_id)?)
        }
        RequestPayload::SetEndpointRole(r) => {
            ResponsePayload::SetEndpointRole(set_endpoint_role(deps, r, correlation_id)?)
        }
        RequestPayload::DeriveKey(r) => {
            ResponsePayload::DeriveKey(derive_key(deps, r, correlation_id)?)
        }
        // K21 — §6.1.51 Re-key / §6.1.52 Re-key Key Pair.
        RequestPayload::ReKey(r) => ResponsePayload::ReKey(rekey(deps, r, correlation_id)?),
        RequestPayload::ReKeyKeyPair(r) => {
            ResponsePayload::ReKeyKeyPair(rekey_key_pair(deps, r, correlation_id)?)
        }
        // Phase 4 — `Poll` never reaches here: `dispatch_one` intercepts
        // it before calling `handle_payload` (its response impersonates
        // the ORIGINAL polled operation, which this uniform per-op
        // wrapping can't express). This arm exists only so the match
        // stays exhaustive.
        RequestPayload::Poll(_) => {
            return Err(KmipError::internal(
                "Poll must be intercepted by dispatch_one before handle_payload",
            ));
        }
        RequestPayload::Cancel(r) => ResponsePayload::Cancel(cancel(deps, r, correlation_id)?),
        RequestPayload::Process(r) => ResponsePayload::Process(process(deps, r, correlation_id)?),
        RequestPayload::QueryAsynchronousRequests(r) => ResponsePayload::QueryAsynchronousRequests(
            query_asynchronous_requests(deps, r, correlation_id)?,
        ),
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
        let req = one_off_request(RequestPayload::Get(crate::kmip30::GetRequest { uid: "ghost".into(), key_format_type: None, key_wrapping_specification: None }));
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
            seed: None,
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
            seed: None,
        };
        assert_eq!(canonical_create_key_pair_op(&req), "CreateKeyPair:Sign");
    }

    // ── K3 — recognized-but-unsupported operations ─────────────────────────

    /// A recognized KMIP 3.0 op without a handler (e.g. Certify) fails
    /// its batch item with `OperationFailed / OperationNotSupported
    /// (0x05)` and a message naming the op — NOT a whole-message
    /// `InvalidMessage`.
    #[test]
    fn k3_unsupported_op_fails_item_with_operation_not_supported() {
        let d = deps();
        // K21 promoted ReKey to a real handler; Phase 3.1 promoted
        // ObtainLease — this matrix keeps shrinking as real handlers land.
        for op in [
            crate::kmip30::Operation::Certify,
            crate::kmip30::Operation::Cancel,
            crate::kmip30::Operation::DelegatedLogin,
        ] {
            let req = one_off_request(RequestPayload::Unsupported(op));
            let resp = dispatch(&d, req);
            let bi = &resp.batch_items[0];
            assert_eq!(bi.operation, Some(op), "Operation echo per §8.2.3");
            assert_eq!(bi.result_status, ResultStatus::OperationFailed);
            assert_eq!(
                bi.result_reason,
                Some(crate::error::ResultReason::OperationNotSupported.to_wire_value()),
                "{op:?} must map to OperationNotSupported (0x05)",
            );
            let msg = bi.result_message.as_deref().unwrap_or_default();
            assert!(
                msg.contains(&format!("{op:?}")),
                "result message must name the op: {msg:?}",
            );
            assert!(bi.payload.is_none());
        }
    }

    /// §9.5 Continue — an unsupported-op failure mid-batch does not
    /// poison the message: the following item still processes.
    #[test]
    fn k3_unsupported_op_respects_batch_continue() {
        let d = deps();
        let msg = crate::kmip30::RequestMessage {
            header: crate::kmip30::RequestHeader {
                batch_error_continuation_option:
                    Some(crate::kmip30::BatchErrorContinuationOption::Continue),
                ..crate::kmip30::RequestHeader::v3()
            },
            batch_items: vec![
                RequestBatchItem {
                    operation: crate::kmip30::Operation::Certify,
                    payload: RequestPayload::Unsupported(crate::kmip30::Operation::Certify),
                },
                RequestBatchItem {
                    operation: crate::kmip30::Operation::Query,
                    payload: RequestPayload::Query(QueryRequest { functions: vec![] }),
                },
            ],
        };
        let resp = dispatch(&d, msg);
        assert_eq!(resp.batch_items.len(), 2, "Continue keeps processing");
        assert_eq!(resp.batch_items[0].result_status, ResultStatus::OperationFailed);
        assert_eq!(resp.batch_items[1].result_status, ResultStatus::Success);
    }

    /// §9.5 Stop (the default) — the unsupported-op failure halts the
    /// batch; later items are not processed or returned.
    #[test]
    fn k3_unsupported_op_respects_batch_stop() {
        let d = deps();
        let msg = crate::kmip30::RequestMessage {
            header: crate::kmip30::RequestHeader::v3(),
            batch_items: vec![
                RequestBatchItem {
                    operation: crate::kmip30::Operation::Query,
                    payload: RequestPayload::Query(QueryRequest { functions: vec![] }),
                },
                RequestBatchItem {
                    operation: crate::kmip30::Operation::ObtainLease,
                    payload: RequestPayload::Unsupported(crate::kmip30::Operation::ObtainLease),
                },
                RequestBatchItem {
                    operation: crate::kmip30::Operation::Query,
                    payload: RequestPayload::Query(QueryRequest { functions: vec![] }),
                },
            ],
        };
        let resp = dispatch(&d, msg);
        assert_eq!(resp.batch_items.len(), 2, "Stop drops items after the failure");
        assert_eq!(resp.batch_items[0].result_status, ResultStatus::Success);
        assert_eq!(resp.batch_items[1].result_status, ResultStatus::OperationFailed);
    }

    // ── K4 — message-layer SHALLs (§8.1.2 Asynchronous Indicator /
    // §8.1.3 Message Extension) ────────────────────────────────────

    /// K4 wire helper — encode a RequestMessage with optional extra
    /// header fields and the given BatchItem frames, then decode it
    /// through the real wire path so the tests cover decoder +
    /// dispatcher end-to-end.
    fn k4_decode(
        header_extra: Vec<crate::codec::TtlvFrame>,
        items: Vec<crate::codec::TtlvFrame>,
    ) -> RequestMessage {
        use crate::codec::{encode, Tag, TtlvFrame, Value};
        use crate::kmip30::wire::tags;
        let mut header_children = vec![TtlvFrame::new(
            Tag(tags::ProtocolVersion),
            Value::Structure(vec![
                TtlvFrame::new(Tag(tags::ProtocolVersionMajor), Value::Integer(3)),
                TtlvFrame::new(Tag(tags::ProtocolVersionMinor), Value::Integer(0)),
            ]),
        )];
        header_children.extend(header_extra);
        let mut children = vec![TtlvFrame::new(
            Tag(tags::RequestHeader),
            Value::Structure(header_children),
        )];
        children.extend(items);
        let frame = TtlvFrame::new(Tag(tags::RequestMessage), Value::Structure(children));
        let mut buf = bytes::BytesMut::new();
        encode(&frame, &mut buf);
        crate::kmip30::decode_request_message(&buf).expect("decode")
    }

    fn k4_query_item(extension: Option<crate::codec::TtlvFrame>) -> crate::codec::TtlvFrame {
        use crate::codec::{Tag, TtlvFrame, Value};
        use crate::kmip30::wire::tags;
        let mut children = vec![
            TtlvFrame::new(
                Tag(tags::Operation),
                Value::Enumeration(crate::kmip30::Operation::Query.to_wire_value()),
            ),
            TtlvFrame::new(
                Tag(tags::RequestPayload),
                Value::Structure(vec![TtlvFrame::new(Tag(tags::QueryFunction), Value::Enumeration(1))]),
            ),
        ];
        if let Some(ext) = extension {
            children.push(ext);
        }
        TtlvFrame::new(Tag(tags::BatchItem), Value::Structure(children))
    }

    fn k4_message_extension(vendor: &str, critical: bool) -> crate::codec::TtlvFrame {
        use crate::codec::{Tag, TtlvFrame, Value};
        use crate::kmip30::wire::tags;
        TtlvFrame::new(
            Tag(tags::MessageExtension),
            Value::Structure(vec![
                TtlvFrame::new(Tag(tags::VendorIdentification), Value::TextString(vendor.into())),
                TtlvFrame::new(Tag(tags::CriticalityIndicator), Value::Boolean(critical)),
                TtlvFrame::new(Tag(tags::VendorExtension), Value::Structure(vec![])),
            ]),
        )
    }

    /// K4 / Phase 4 — §8.1.2 `Asynchronous Indicator = Mandatory`
    /// against `Query`, which is deliberately excluded from
    /// asynchronous eligibility (`dispatcher::is_async_eligible` — a
    /// trivial negotiation op, not worth deferring): every such item
    /// fails with `OperationFailed / OperationNotSupported (0x05)`
    /// instead of being silently processed synchronously OR silently
    /// enqueued. `Continue` mode is set explicitly so BOTH items are
    /// processed independently and both responses come back — the
    /// default `Stop` mode would (correctly, per §9.5) halt after the
    /// first failure and return only one, which is covered by
    /// `mandatory_ineligible_op_fails_only_that_item_not_the_whole_batch`
    /// in `tests/async_ops_e2e.rs`.
    #[test]
    fn k4_async_mandatory_fails_every_batch_item() {
        use crate::codec::{Tag, TtlvFrame, Value};
        use crate::kmip30::wire::tags;
        let d = deps();
        let msg = k4_decode(
            vec![
                TtlvFrame::new(Tag(tags::AsynchronousIndicator), Value::Enumeration(0x01)),
                TtlvFrame::new(Tag(tags::BatchErrorContinuationOption), Value::Enumeration(0x01)),
            ],
            vec![k4_query_item(None), k4_query_item(None)],
        );
        let resp = dispatch(&d, msg);
        assert_eq!(resp.batch_items.len(), 2, "Continue mode processes every batch item");
        for item in &resp.batch_items {
            assert_eq!(item.result_status, ResultStatus::OperationFailed);
            assert_eq!(
                item.result_reason,
                Some(crate::error::ResultReason::OperationNotSupported.to_wire_value()),
                "must be OperationNotSupported (0x05)",
            );
            assert_eq!(item.operation, Some(crate::kmip30::Operation::Query), "§8.2.3 echo");
        }
    }

    /// K4 — `Asynchronous Indicator = Optional` (and `Prohibited`) →
    /// the request processes synchronously exactly as without it.
    #[test]
    fn k4_async_optional_processes_synchronously() {
        use crate::codec::{Tag, TtlvFrame, Value};
        use crate::kmip30::wire::tags;
        for wire in [0x02u32 /* Optional */, 0x03 /* Prohibited */] {
            let d = deps();
            let msg = k4_decode(
                vec![TtlvFrame::new(Tag(tags::AsynchronousIndicator), Value::Enumeration(wire))],
                vec![k4_query_item(None)],
            );
            let resp = dispatch(&d, msg);
            assert_eq!(resp.batch_items.len(), 1);
            assert_eq!(
                resp.batch_items[0].result_status,
                ResultStatus::Success,
                "indicator {wire:#x} must process synchronously",
            );
        }
    }

    // ── K14 — §8.1.2 Authentication enforcement ────────────────────────

    /// Deps with a configured credential store (auth ENFORCED):
    /// alice / "correct horse".
    fn k14_deps_with_auth() -> Deps {
        use crate::server::auth::{sha256_hex, AuthUser};
        let mut d = deps();
        d.config.auth_users = vec![AuthUser {
            username: "alice".into(),
            password_sha256: sha256_hex("correct horse"),
        }];
        d
    }

    /// §8.1.2 `Authentication` header frame carrying one
    /// Username-and-Password Credential.
    fn k14_auth_header(username: &str, password: &str) -> Vec<crate::codec::TtlvFrame> {
        use crate::codec::{Tag, TtlvFrame, Value};
        use crate::kmip30::wire::tags;
        vec![TtlvFrame::new(
            Tag(tags::Authentication),
            Value::Structure(vec![TtlvFrame::new(
                Tag(tags::Credential),
                Value::Structure(vec![
                    TtlvFrame::new(Tag(tags::CredentialType), Value::Enumeration(0x01)),
                    TtlvFrame::new(
                        Tag(tags::CredentialValue),
                        Value::Structure(vec![
                            TtlvFrame::new(Tag(tags::Username), Value::TextString(username.into())),
                            TtlvFrame::new(Tag(tags::Password), Value::TextString(password.into())),
                        ]),
                    ),
                ]),
            )]),
        )]
    }

    /// K14 — auth configured + request without Authentication: EVERY
    /// batch item fails with `Authentication Not Successful (0x03)`,
    /// same per-item shape as the K4 async gate.
    #[test]
    fn k14_auth_configured_missing_credential_fails_every_item_0x03() {
        let d = k14_deps_with_auth();
        let msg = k4_decode(vec![], vec![k4_query_item(None), k4_query_item(None)]);
        let resp = dispatch(&d, msg);
        assert_eq!(resp.batch_items.len(), 2, "every batch item gets a response");
        for item in &resp.batch_items {
            assert_eq!(item.result_status, ResultStatus::OperationFailed);
            assert_eq!(
                item.result_reason,
                Some(crate::error::ResultReason::AuthenticationNotSuccessful.to_wire_value()),
                "must be AuthenticationNotSuccessful (0x03)",
            );
            assert_eq!(item.operation, Some(crate::kmip30::Operation::Query), "§8.2.3 echo");
            assert!(item.payload.is_none());
        }
    }

    /// K14 — auth configured + wrong password / unknown user → 0x03.
    #[test]
    fn k14_auth_configured_bad_credential_fails_0x03() {
        for (user, pass) in [("alice", "wrong"), ("mallory", "correct horse")] {
            let d = k14_deps_with_auth();
            let msg = k4_decode(k14_auth_header(user, pass), vec![k4_query_item(None)]);
            let resp = dispatch(&d, msg);
            assert_eq!(
                resp.batch_items[0].result_reason,
                Some(crate::error::ResultReason::AuthenticationNotSuccessful.to_wire_value()),
                "{user}/{pass} must fail with 0x03",
            );
        }
    }

    /// K14 — auth configured + valid credential → the request
    /// processes normally.
    #[test]
    fn k14_auth_configured_good_credential_succeeds() {
        let d = k14_deps_with_auth();
        let msg = k4_decode(k14_auth_header("alice", "correct horse"), vec![k4_query_item(None)]);
        let resp = dispatch(&d, msg);
        assert_eq!(resp.batch_items[0].result_status, ResultStatus::Success);
    }

    /// K14 replay-mode regression — auth NOT configured (the default):
    /// a credential-free request succeeds, and any Authentication
    /// content is ignored rather than verified. The hermetic OASIS
    /// replay harness depends on this default.
    #[test]
    fn k14_open_auth_default_passes_credential_free_requests() {
        let d = deps(); // DepsConfig::default() — no auth users
        assert!(!d.config.auth_enabled(), "default config must be open-auth");
        let msg = k4_decode(vec![], vec![k4_query_item(None)]);
        let resp = dispatch(&d, msg);
        assert_eq!(resp.batch_items[0].result_status, ResultStatus::Success);
        // Even a bogus credential is ignored in open-auth mode.
        let msg = k4_decode(k14_auth_header("mallory", "nope"), vec![k4_query_item(None)]);
        let resp = dispatch(&d, msg);
        assert_eq!(resp.batch_items[0].result_status, ResultStatus::Success);
    }

    /// K14 mTLS — a transport-verified client identity (subject CN)
    /// satisfies configured auth without a header credential.
    #[test]
    fn k14_mtls_transport_identity_satisfies_configured_auth() {
        use crate::server::auth::Identity;
        let d = k14_deps_with_auth();
        let msg = k4_decode(vec![], vec![k4_query_item(None)]);
        let resp = dispatch_with_transport_identity(
            &d,
            msg,
            Some(Identity { username: "kmip-client".into() }),
        );
        assert_eq!(resp.batch_items[0].result_status, ResultStatus::Success);
    }

    /// K14 — an explicitly-offered-but-invalid header credential is
    /// rejected even on an mTLS-verified connection (no silent
    /// fallback past a wrong credential).
    #[test]
    fn k14_bad_header_credential_not_rescued_by_transport_identity() {
        use crate::server::auth::Identity;
        let d = k14_deps_with_auth();
        let msg = k4_decode(k14_auth_header("alice", "wrong"), vec![k4_query_item(None)]);
        let resp = dispatch_with_transport_identity(
            &d,
            msg,
            Some(Identity { username: "kmip-client".into() }),
        );
        assert_eq!(
            resp.batch_items[0].result_reason,
            Some(crate::error::ResultReason::AuthenticationNotSuccessful.to_wire_value()),
        );
    }

    /// K4 — critical Message Extension under `Continue`: the carrying
    /// item fails with `InvalidMessage` naming the vendor; the sibling
    /// item still processes.
    #[test]
    fn k4_critical_message_extension_continue_spares_siblings() {
        use crate::codec::{Tag, TtlvFrame, Value};
        use crate::kmip30::wire::tags;
        let d = deps();
        let msg = k4_decode(
            vec![TtlvFrame::new(
                Tag(tags::BatchErrorContinuationOption),
                Value::Enumeration(BatchErrorContinuationOption::Continue.to_wire_value()),
            )],
            vec![
                k4_query_item(Some(k4_message_extension("acme-corp", true))),
                k4_query_item(None),
            ],
        );
        let resp = dispatch(&d, msg);
        assert_eq!(resp.batch_items.len(), 2, "Continue keeps processing");
        assert_eq!(resp.batch_items[0].result_status, ResultStatus::OperationFailed);
        assert_eq!(
            resp.batch_items[0].result_reason,
            Some(crate::error::ResultReason::InvalidMessage.to_wire_value()),
            "§9 reject rule → InvalidMessage (0x04)",
        );
        let message = resp.batch_items[0].result_message.as_deref().unwrap_or("");
        assert!(message.contains("acme-corp"), "names the vendor extension: {message}");
        assert_eq!(resp.batch_items[1].result_status, ResultStatus::Success, "sibling unaffected");
    }

    /// K4 — critical Message Extension under `Stop` (the default):
    /// the failure halts the batch, later items are not returned.
    #[test]
    fn k4_critical_message_extension_stop_halts_batch() {
        let d = deps();
        let msg = k4_decode(
            vec![], // no Batch Error Continuation Option → Stop default
            vec![
                k4_query_item(Some(k4_message_extension("acme-corp", true))),
                k4_query_item(None),
            ],
        );
        let resp = dispatch(&d, msg);
        assert_eq!(resp.batch_items.len(), 1, "Stop drops items after the failure");
        assert_eq!(resp.batch_items[0].result_status, ResultStatus::OperationFailed);
        assert_eq!(
            resp.batch_items[0].result_reason,
            Some(crate::error::ResultReason::InvalidMessage.to_wire_value()),
        );
    }

    /// K4 — non-critical Message Extension is skipped; the item
    /// processes normally.
    #[test]
    fn k4_non_critical_message_extension_ignored() {
        let d = deps();
        let msg = k4_decode(
            vec![],
            vec![k4_query_item(Some(k4_message_extension("acme-corp", false)))],
        );
        let resp = dispatch(&d, msg);
        assert_eq!(resp.batch_items.len(), 1);
        assert_eq!(resp.batch_items[0].result_status, ResultStatus::Success);
    }

    // ── K19 — Baseline client-to-server ops through real wire bytes ────

    /// K19 — Get Usage Allocation (§6.1.27) end-to-end: TTLV request
    /// bytes → decode → dispatch → the store's remaining Usage Limits
    /// budget is decremented by the granted allocation; the response
    /// echoes the UID and survives response encoding.
    #[test]
    fn k19_get_usage_allocation_via_wire_decrements_budget() {
        use crate::codec::{Tag, TtlvFrame, Value};
        use crate::kmip30::wire::tags;
        let d = deps();
        d.store.put(crate::store::ObjectRecord {
            uid: "k-usage".into(),
            object_type: ObjectType::SymmetricKey,
            algorithm: KmipAlgorithm::Aes,
            cryptographic_length: 256,
            usage_mask: UsageMask::ENCRYPT,
            state: crate::kmip30::State::Active,
            initial_date: time::OffsetDateTime::UNIX_EPOCH,
            usage_limits_total: Some(100),
            usage_limits_remaining: Some(100),
            usage_limits_unit: Some(0x01),
            ..crate::store::ObjectRecord::default()
        }).unwrap();
        let item = TtlvFrame::new(Tag(tags::BatchItem), Value::Structure(vec![
            TtlvFrame::new(
                Tag(tags::Operation),
                Value::Enumeration(crate::kmip30::Operation::GetUsageAllocation.to_wire_value()),
            ),
            TtlvFrame::new(Tag(tags::RequestPayload), Value::Structure(vec![
                TtlvFrame::new(Tag(tags::UniqueIdentifier), Value::TextString("k-usage".into())),
                TtlvFrame::new(Tag(tags::UsageLimitsCount), Value::LongInteger(25)),
            ])),
        ]));
        let resp = dispatch(&d, k4_decode(vec![], vec![item]));
        assert_eq!(resp.batch_items[0].result_status, ResultStatus::Success);
        match &resp.batch_items[0].payload {
            Some(ResponsePayload::GetUsageAllocation(r)) => assert_eq!(r.uid, "k-usage"),
            other => panic!("expected GetUsageAllocation payload, got {other:?}"),
        }
        assert_eq!(
            d.store.get("k-usage").unwrap().unwrap().usage_limits_remaining,
            Some(75),
            "the granted allocation is reserved against the remaining budget",
        );
        let bytes = crate::kmip30::encode_response_message(&resp);
        assert_eq!(bytes.len() % 8, 0, "§9.6 alignment");
    }

    /// K19 — Get Constraints (§6.1.26) end-to-end: empty request
    /// payload per Table 326; Success with a non-empty Constraints set.
    #[test]
    fn k19_get_constraints_via_wire_returns_constraint_table() {
        use crate::codec::{Tag, TtlvFrame, Value};
        use crate::kmip30::wire::tags;
        let d = deps();
        let item = TtlvFrame::new(Tag(tags::BatchItem), Value::Structure(vec![
            TtlvFrame::new(
                Tag(tags::Operation),
                Value::Enumeration(crate::kmip30::Operation::GetConstraints.to_wire_value()),
            ),
            TtlvFrame::new(Tag(tags::RequestPayload), Value::Structure(vec![])),
        ]));
        let resp = dispatch(&d, k4_decode(vec![], vec![item]));
        assert_eq!(resp.batch_items[0].result_status, ResultStatus::Success);
        match &resp.batch_items[0].payload {
            Some(ResponsePayload::GetConstraints(r)) => {
                assert!(!r.constraints.is_empty(), "Constraints REQUIRED per Table 327");
            }
            other => panic!("expected GetConstraints payload, got {other:?}"),
        }
        let bytes = crate::kmip30::encode_response_message(&resp);
        assert_eq!(bytes.len() % 8, 0, "§9.6 alignment");
    }

    /// K19 — Set Defaults (§6.1.58) end-to-end: the wire-decoded
    /// Object Defaults are stored and a subsequent Create that omits
    /// the defaulted attribute picks it up (a client-supplied value
    /// would win — pinned in `ops::allocation_and_config` tests).
    #[test]
    fn k19_set_defaults_via_wire_applies_on_subsequent_create() {
        use crate::codec::{Tag, TtlvFrame, Value};
        use crate::kmip30::wire::tags;
        let d = deps();
        let item = TtlvFrame::new(Tag(tags::BatchItem), Value::Structure(vec![
            TtlvFrame::new(
                Tag(tags::Operation),
                Value::Enumeration(crate::kmip30::Operation::SetDefaults.to_wire_value()),
            ),
            TtlvFrame::new(Tag(tags::RequestPayload), Value::Structure(vec![
                TtlvFrame::new(Tag(tags::DefaultsInformation), Value::Structure(vec![
                    TtlvFrame::new(Tag(tags::ObjectDefaults), Value::Structure(vec![
                        TtlvFrame::new(
                            Tag(tags::ObjectType),
                            Value::Enumeration(ObjectType::SymmetricKey.to_wire_value()),
                        ),
                        TtlvFrame::new(Tag(tags::Attributes), Value::Structure(vec![
                            TtlvFrame::new(
                                Tag(tags::CryptographicUsageMask),
                                Value::Integer((UsageMask::ENCRYPT | UsageMask::DECRYPT).bits() as i32),
                            ),
                        ])),
                    ])),
                ])),
            ])),
        ]));
        let resp = dispatch(&d, k4_decode(vec![], vec![item]));
        assert_eq!(resp.batch_items[0].result_status, ResultStatus::Success);
        assert!(matches!(
            resp.batch_items[0].payload,
            Some(ResponsePayload::SetDefaults(_)),
        ));
        // Subsequent Create omits the usage mask → the stored default
        // fills it.
        let create = one_off_request(RP::Create(CreateRequest {
            object_type: ObjectType::SymmetricKey,
            template_attribute: vec![
                Attribute::CryptographicAlgorithm(KmipAlgorithm::Aes),
                Attribute::CryptographicLength(128),
            ],
        }));
        let resp = dispatch(&d, create);
        assert_eq!(resp.batch_items[0].result_status, ResultStatus::Success);
        let uid = match &resp.batch_items[0].payload {
            Some(ResponsePayload::Create(r)) => r.uid.clone(),
            other => panic!("expected Create payload, got {other:?}"),
        };
        assert_eq!(
            d.store.get(&uid).unwrap().unwrap().usage_mask,
            UsageMask::ENCRYPT | UsageMask::DECRYPT,
            "Set Defaults mask applied when the client template omits one",
        );
    }

    /// K19 — Set Endpoint Role (§6.1.59) end-to-end: `Server` (the
    /// identity request) is acknowledged with the accepted role per
    /// Table 432; `Client` (the §6.2 role switch we don't support) is
    /// rejected with `Feature Not Supported (0x08)` per Table 433.
    #[test]
    fn k19_set_endpoint_role_via_wire() {
        use crate::codec::{Tag, TtlvFrame, Value};
        use crate::kmip30::wire::tags;
        let item = |role: u32| TtlvFrame::new(Tag(tags::BatchItem), Value::Structure(vec![
            TtlvFrame::new(
                Tag(tags::Operation),
                Value::Enumeration(crate::kmip30::Operation::SetEndpointRole.to_wire_value()),
            ),
            TtlvFrame::new(Tag(tags::RequestPayload), Value::Structure(vec![
                TtlvFrame::new(Tag(tags::EndpointRole), Value::Enumeration(role)),
            ])),
        ]));
        // Server (0x02) — accepted, role echoed.
        let d = deps();
        let resp = dispatch(&d, k4_decode(vec![], vec![item(0x02)]));
        assert_eq!(resp.batch_items[0].result_status, ResultStatus::Success);
        match &resp.batch_items[0].payload {
            Some(ResponsePayload::SetEndpointRole(r)) => {
                assert_eq!(r.endpoint_role, crate::kmip30::EndpointRole::Server);
            }
            other => panic!("expected SetEndpointRole payload, got {other:?}"),
        }
        let bytes = crate::kmip30::encode_response_message(&resp);
        assert_eq!(bytes.len() % 8, 0, "§9.6 alignment");
        // Client (0x01) — the unsupported role switch.
        let resp = dispatch(&d, k4_decode(vec![], vec![item(0x01)]));
        assert_eq!(resp.batch_items[0].result_status, ResultStatus::OperationFailed);
        assert_eq!(
            resp.batch_items[0].result_reason,
            Some(crate::error::ResultReason::FeatureNotSupported.to_wire_value()),
            "role switch must fail with Feature Not Supported (0x08)",
        );
    }

    /// K20 — Derive Key (§6.1.18) end-to-end over the wire: TTLV
    /// request (Object Type + UID + Derivation Method HMAC +
    /// Derivation Parameters + Attributes) → derived object with the
    /// §6.1.18 link pair, then a follow-up GetAttributes via the §6.4
    /// ID Placeholder (Derive Key SHALL set it to the new UID).
    #[test]
    fn k20_derive_key_via_wire_with_id_placeholder() {
        use crate::codec::{Tag, TtlvFrame, Value};
        use crate::kmip30::wire::tags;
        let d = deps();
        d.store.put(crate::store::ObjectRecord {
            uid: "base-1".into(),
            object_type: ObjectType::SymmetricKey,
            algorithm: KmipAlgorithm::HmacSha256,
            cryptographic_length: 32,
            usage_mask: UsageMask::DERIVE_KEY,
            state: crate::kmip30::State::Active,
            pkcs11_cka_id: vec![9],
            pkcs11_slot: 0,
            initial_date: time::OffsetDateTime::now_utc(),
            key_material: Some(b"Jefe".to_vec()),
            ..crate::store::ObjectRecord::default()
        }).unwrap();

        let derive_item = TtlvFrame::new(Tag(tags::BatchItem), Value::Structure(vec![
            TtlvFrame::new(
                Tag(tags::Operation),
                Value::Enumeration(crate::kmip30::Operation::DeriveKey.to_wire_value()),
            ),
            TtlvFrame::new(Tag(tags::RequestPayload), Value::Structure(vec![
                TtlvFrame::new(
                    Tag(tags::ObjectType),
                    Value::Enumeration(ObjectType::SymmetricKey.to_wire_value()),
                ),
                TtlvFrame::new(Tag(tags::UniqueIdentifier), Value::TextString("base-1".into())),
                TtlvFrame::new(
                    Tag(tags::DerivationMethod),
                    Value::Enumeration(crate::kmip30::DerivationMethod::Hmac.to_wire_value()),
                ),
                TtlvFrame::new(Tag(tags::DerivationParameters), Value::Structure(vec![
                    TtlvFrame::new(
                        Tag(tags::DerivationData),
                        Value::ByteString(b"what do ya want for nothing?".to_vec()),
                    ),
                ])),
                TtlvFrame::new(Tag(tags::Attributes), Value::Structure(vec![
                    TtlvFrame::new(
                        Tag(tags::CryptographicAlgorithm),
                        Value::Enumeration(KmipAlgorithm::Aes.to_wire_value()),
                    ),
                    TtlvFrame::new(Tag(tags::CryptographicLength), Value::Integer(256)),
                ])),
            ])),
        ]));
        // Second item — GetAttributes via `IDPlaceholder` (enum 0x01):
        // §6.4 Derive Key sets the placeholder to the derived UID.
        let ga_item = TtlvFrame::new(Tag(tags::BatchItem), Value::Structure(vec![
            TtlvFrame::new(
                Tag(tags::Operation),
                Value::Enumeration(crate::kmip30::Operation::GetAttributes.to_wire_value()),
            ),
            TtlvFrame::new(Tag(tags::RequestPayload), Value::Structure(vec![
                TtlvFrame::new(Tag(tags::UniqueIdentifier), Value::Enumeration(0x01)),
            ])),
        ]));

        let resp = dispatch(&d, k4_decode(vec![], vec![derive_item, ga_item]));
        assert_eq!(resp.batch_items[0].result_status, ResultStatus::Success,
                   "{:?}", resp.batch_items[0].result_message);
        let derived_uid = match &resp.batch_items[0].payload {
            Some(ResponsePayload::DeriveKey(r)) => r.uid.clone(),
            other => panic!("expected DeriveKey payload, got {other:?}"),
        };
        // RFC 4231 case 2 — HMAC-SHA-256("Jefe", "what do ya want for
        // nothing?") (PRF from the base key's attributes per §7.13).
        let rec = d.store.get(&derived_uid).unwrap().unwrap();
        assert_eq!(
            hex::encode(rec.key_material.as_deref().unwrap()),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // §6.1.18 link pair.
        assert_eq!(rec.links.get("DerivationBaseObjectLink").map(String::as_str), Some("base-1"));
        let base = d.store.get("base-1").unwrap().unwrap();
        assert_eq!(base.links.get("DerivedObjectLink"), Some(&derived_uid));
        // ID Placeholder resolved to the derived object.
        assert_eq!(resp.batch_items[1].result_status, ResultStatus::Success);
        match &resp.batch_items[1].payload {
            Some(ResponsePayload::GetAttributes(r)) => assert_eq!(r.uid, derived_uid),
            other => panic!("expected GetAttributes payload, got {other:?}"),
        }
        let bytes = crate::kmip30::encode_response_message(&resp);
        assert_eq!(bytes.len() % 8, 0, "§9.6 alignment");
    }

    /// K21 — Re-key (§6.1.51) end-to-end over the wire: TTLV request
    /// (UID + Offset Interval + Attributes override) → replacement
    /// object with the §6.1.51 link pair, then a follow-up
    /// GetAttributes via the §6.4 ID Placeholder (Re-key SHALL set it
    /// to the replacement UID). Pins the `Offset` tag decode
    /// (0x420058, Interval).
    #[test]
    fn k21_rekey_via_wire_with_offset_and_id_placeholder() {
        use crate::codec::{Tag, TtlvFrame, Value};
        use crate::kmip30::wire::tags;
        let d = deps();
        let now = time::OffsetDateTime::now_utc();
        d.store.put(crate::store::ObjectRecord {
            uid: "old-aes".into(),
            object_type: ObjectType::SymmetricKey,
            algorithm: KmipAlgorithm::Aes,
            cryptographic_length: 256,
            usage_mask: UsageMask::ENCRYPT,
            state: crate::kmip30::State::Active,
            pkcs11_cka_id: vec![5],
            pkcs11_slot: 0,
            initial_date: now - time::Duration::days(2),
            activation_date: Some(now - time::Duration::days(1)),
            name: Some("rotating".into()),
            ..crate::store::ObjectRecord::default()
        }).unwrap();

        let rekey_item = TtlvFrame::new(Tag(tags::BatchItem), Value::Structure(vec![
            TtlvFrame::new(
                Tag(tags::Operation),
                Value::Enumeration(crate::kmip30::Operation::ReKey.to_wire_value()),
            ),
            TtlvFrame::new(Tag(tags::RequestPayload), Value::Structure(vec![
                TtlvFrame::new(Tag(tags::UniqueIdentifier), Value::TextString("old-aes".into())),
                // Offset = 0 seconds → AT2 = now → replacement Active,
                // original Deactivated immediately.
                TtlvFrame::new(Tag(tags::Offset), Value::Interval(0)),
                TtlvFrame::new(Tag(tags::Attributes), Value::Structure(vec![
                    TtlvFrame::new(Tag(tags::CryptographicLength), Value::Integer(128)),
                ])),
            ])),
        ]));
        // §6.4 — Re-key sets the ID Placeholder to the replacement UID.
        let ga_item = TtlvFrame::new(Tag(tags::BatchItem), Value::Structure(vec![
            TtlvFrame::new(
                Tag(tags::Operation),
                Value::Enumeration(crate::kmip30::Operation::GetAttributes.to_wire_value()),
            ),
            TtlvFrame::new(Tag(tags::RequestPayload), Value::Structure(vec![
                TtlvFrame::new(Tag(tags::UniqueIdentifier), Value::Enumeration(0x01)),
            ])),
        ]));

        let resp = dispatch(&d, k4_decode(vec![], vec![rekey_item, ga_item]));
        assert_eq!(resp.batch_items[0].result_status, ResultStatus::Success,
                   "{:?}", resp.batch_items[0].result_message);
        let new_uid = match &resp.batch_items[0].payload {
            Some(ResponsePayload::ReKey(r)) => r.uid.clone(),
            other => panic!("expected ReKey payload, got {other:?}"),
        };
        let rec = d.store.get(&new_uid).unwrap().unwrap();
        // Inheritance + request override: algorithm copied, length
        // overridden by the request Attributes.
        assert_eq!(rec.algorithm, KmipAlgorithm::Aes);
        assert_eq!(rec.cryptographic_length, 128);
        assert_eq!(rec.name.as_deref(), Some("rotating"), "Name transfers");
        assert_eq!(rec.state, crate::kmip30::State::Active, "Offset 0 ⇒ AT2 = now");
        assert_eq!(rec.links.get("ReplacedObjectLink").map(String::as_str), Some("old-aes"));
        let old = d.store.get("old-aes").unwrap().unwrap();
        assert_eq!(old.links.get("ReplacementObjectLink"), Some(&new_uid));
        assert_eq!(old.state, crate::kmip30::State::Deactivated);
        assert_eq!(old.name, None);
        // ID Placeholder resolved to the replacement.
        assert_eq!(resp.batch_items[1].result_status, ResultStatus::Success);
        match &resp.batch_items[1].payload {
            Some(ResponsePayload::GetAttributes(r)) => assert_eq!(r.uid, new_uid),
            other => panic!("expected GetAttributes payload, got {other:?}"),
        }
        let bytes = crate::kmip30::encode_response_message(&resp);
        assert_eq!(bytes.len() % 8, 0, "§9.6 alignment");
    }

    /// K21 — Re-key Key Pair (§6.1.52) over the wire: response carries
    /// the two typed UID tags (Table 411) and the §6.4 placeholder is
    /// the PRIVATE half ("the first value in the response").
    #[test]
    fn k21_rekey_key_pair_via_wire_placeholder_is_private_half() {
        use crate::codec::{Tag, TtlvFrame, Value};
        use crate::kmip30::wire::tags;
        let d = deps();
        let now = time::OffsetDateTime::now_utc();
        for (uid, ty, link_k, link_v) in [
            ("kp-priv", ObjectType::PrivateKey, "PublicKeyLink", "kp-pub"),
            ("kp-pub", ObjectType::PublicKey, "PrivateKeyLink", "kp-priv"),
        ] {
            d.store.put(crate::store::ObjectRecord {
                uid: uid.into(),
                object_type: ty,
                algorithm: KmipAlgorithm::MlDsa65,
                cryptographic_length: 0,
                usage_mask: UsageMask::SIGN | UsageMask::VERIFY,
                state: crate::kmip30::State::Active,
                pkcs11_cka_id: vec![6],
                pkcs11_slot: 0,
                initial_date: now,
                activation_date: Some(now),
                links: {
                    let mut m = std::collections::HashMap::new();
                    m.insert(link_k.to_string(), link_v.to_string());
                    m
                },
                ..crate::store::ObjectRecord::default()
            }).unwrap();
        }

        let rekey_item = TtlvFrame::new(Tag(tags::BatchItem), Value::Structure(vec![
            TtlvFrame::new(
                Tag(tags::Operation),
                Value::Enumeration(crate::kmip30::Operation::ReKeyKeyPair.to_wire_value()),
            ),
            TtlvFrame::new(Tag(tags::RequestPayload), Value::Structure(vec![
                TtlvFrame::new(Tag(tags::UniqueIdentifier), Value::TextString("kp-priv".into())),
            ])),
        ]));
        let ga_item = TtlvFrame::new(Tag(tags::BatchItem), Value::Structure(vec![
            TtlvFrame::new(
                Tag(tags::Operation),
                Value::Enumeration(crate::kmip30::Operation::GetAttributes.to_wire_value()),
            ),
            TtlvFrame::new(Tag(tags::RequestPayload), Value::Structure(vec![
                TtlvFrame::new(Tag(tags::UniqueIdentifier), Value::Enumeration(0x01)),
            ])),
        ]));

        let resp = dispatch(&d, k4_decode(vec![], vec![rekey_item, ga_item]));
        assert_eq!(resp.batch_items[0].result_status, ResultStatus::Success,
                   "{:?}", resp.batch_items[0].result_message);
        let (new_priv, new_pub) = match &resp.batch_items[0].payload {
            Some(ResponsePayload::ReKeyKeyPair(r)) => {
                (r.private_key_uid.clone(), r.public_key_uid.clone())
            }
            other => panic!("expected ReKeyKeyPair payload, got {other:?}"),
        };
        // §6.4 — placeholder is the private (first) UID.
        match &resp.batch_items[1].payload {
            Some(ResponsePayload::GetAttributes(r)) => assert_eq!(r.uid, new_priv),
            other => panic!("expected GetAttributes payload, got {other:?}"),
        }
        // Both halves linked both directions.
        assert_eq!(
            d.store.get(&new_priv).unwrap().unwrap().links.get("ReplacedObjectLink").map(String::as_str),
            Some("kp-priv"),
        );
        assert_eq!(
            d.store.get("kp-pub").unwrap().unwrap().links.get("ReplacementObjectLink"),
            Some(&new_pub),
        );
        // Table 411 — wire response carries the two typed UID tags.
        let bytes = crate::kmip30::encode_response_message(&resp);
        assert_eq!(bytes.len() % 8, 0, "§9.6 alignment");
        let hex = hex::encode(&bytes);
        assert!(hex.contains("420066"), "PrivateKeyUniqueIdentifier tag on the wire");
        assert!(hex.contains("42006f"), "PublicKeyUniqueIdentifier tag on the wire");
    }

    /// `HANDLED_OPERATIONS` is duplicate-free and every entry routes
    /// to a real handler (i.e. its `RequestPayload` variant is not the
    /// `Unsupported` marker — pinned indirectly: each handled op must
    /// NOT appear in the query module's advertised-unimplemented set).
    #[test]
    fn k3_handled_operations_is_consistent() {
        use std::collections::HashSet;
        let set: HashSet<_> = HANDLED_OPERATIONS.iter().copied().collect();
        assert_eq!(set.len(), HANDLED_OPERATIONS.len(), "duplicates in HANDLED_OPERATIONS");
        for op in crate::ops::query::ADVERTISED_UNIMPLEMENTED_OPERATIONS {
            assert!(
                !set.contains(op),
                "{op:?} is advertised-unimplemented but listed as handled",
            );
        }
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
                    payload: RP::Get(GetRequest { uid: "urn:ghost".into(), key_format_type: None, key_wrapping_specification: None }),
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
                    payload: RP::Get(GetRequest { uid: "urn:ghost-1".into(), key_format_type: None, key_wrapping_specification: None }),
                },
                RequestBatchItem {
                    operation: crate::kmip30::Operation::Get,
                    payload: RP::Get(GetRequest { uid: "urn:ghost-2".into(), key_format_type: None, key_wrapping_specification: None }),
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

    /// If the item that was supposed to produce a UID never succeeds (here:
    /// a `Destroy` on a UID that was never created), a later item chained
    /// via `$IDPlaceholder` must fail with a clear explanation — not the
    /// raw sentinel leaking into a generic `UID "$IDPlaceholder" not
    /// found` (reported against the CACP KMIP playground's Batch tab: a
    /// denied `CreateKeyPair` cascaded into a confusing `ObjectNotFound`
    /// on the chained `Activate`/`Sign`).
    #[test]
    fn id_placeholder_unset_gives_clear_message_not_raw_sentinel() {
        let d = deps();
        let msg = crate::kmip30::RequestMessage {
            header: RequestHeader {
                batch_error_continuation_option: Some(BatchErrorContinuationOption::Continue),
                ..RequestHeader::v3()
            },
            batch_items: vec![
                RequestBatchItem {
                    operation: crate::kmip30::Operation::Destroy,
                    payload: RP::Destroy(DestroyRequest { uid: "urn:never-existed".into() }),
                },
                RequestBatchItem {
                    operation: crate::kmip30::Operation::Activate,
                    payload: RP::Activate(crate::kmip30::ActivateRequest {
                        uid: ID_PLACEHOLDER_SENTINEL.to_string(),
                    }),
                },
            ],
        };
        let resp = dispatch(&d, msg);
        assert_eq!(resp.batch_items.len(), 2, "Continue keeps processing");
        assert_eq!(resp.batch_items[0].result_status, ResultStatus::OperationFailed);
        let second = &resp.batch_items[1];
        assert_eq!(second.result_status, ResultStatus::OperationFailed);
        let text = second.result_message.as_deref().unwrap_or("");
        assert!(
            text.contains("ID Placeholder not set"),
            "expected a clear ID-Placeholder message, got: {text}"
        );
        assert!(
            !text.contains(ID_PLACEHOLDER_SENTINEL),
            "the raw sentinel must not leak into the user-facing message: {text}"
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
    // `Operation Undone` (codepoint `0x03`) — distinct from
    // `Success` (0x00), `OperationFailed` (0x01) and
    // `OperationPending` (0x02).

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

    // ── R7 Phase 4 fix — Undo must reverse a Sign-triggered rekey ──────────
    //
    // Regression test for the gap found during the CACP A-grade review
    // (2026-07-03): a rekey-on-use policy makes `Sign` mint a whole new key
    // pair inline (`ops::sign::rekey_and_sign`), but `touched_uids` /
    // `newly_created_uids` had no `Sign` arm, so under `Undo` the new key
    // pair was never deleted and the old key's Deactivated+supersede
    // mutation was never reverted. See `SignResponse::rekeyed`.

    fn deps_with_policy(yaml: &str) -> Deps {
        let ring = Arc::new(RingSink::new(64));
        let sink: Arc<dyn AuditSink> = ring;
        let engine = Engine::with_global_sink(sink.clone());
        engine
            .activate(load_from_str(yaml, std::path::Path::new("<t>")).unwrap())
            .unwrap();
        Deps::new(engine, Arc::new(MemoryStore::new()), sink, DepsConfig::default())
    }

    const REKEY_ON_USE_POLICY: &str = r#"
schema_version: 1
metadata: { name: rk, description: rekey, authority: t, effective: "always" }
rules:
  - type: algorithm_substitution
    ops: [Sign]
    from: ECDSA
    to: ML-DSA-87
    reason: "Upgrade signing"
"#;

    #[test]
    fn r7_phase4_undo_reverts_sign_triggered_rekey_inside_batch() {
        let d = deps_with_policy(REKEY_ON_USE_POLICY);
        d.store.put(ObjectRecord {
            uid: "urn:legacy".into(),
            object_type: ObjectType::PrivateKey,
            algorithm: KmipAlgorithm::Ecdsa,
            cryptographic_length: 0,
            usage_mask: UsageMask::SIGN | UsageMask::VERIFY,
            state: State::Active,
            activation_date: Some(time::OffsetDateTime::UNIX_EPOCH),
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
                    operation: crate::kmip30::Operation::Sign,
                    payload: RP::Sign(crate::kmip30::SignRequest {
                        uid: "urn:legacy".into(),
                        data: b"agility-lesson".to_vec(),
                        cryptographic_parameters: None,
                    }),
                },
                RequestBatchItem {
                    operation: crate::kmip30::Operation::Destroy,
                    payload: RP::Destroy(DestroyRequest { uid: "urn:ghost".into() }),
                },
            ],
        };

        let resp = dispatch(&d, msg);
        assert_eq!(resp.batch_items.len(), 2);
        assert_eq!(
            resp.batch_items[0].result_status,
            ResultStatus::OperationUndone,
            "the rekeying Sign must be relabelled OperationUndone",
        );
        assert_eq!(resp.batch_items[1].result_status, ResultStatus::OperationFailed);

        // The response payload is still returned per spec — only the status
        // changes — so we can recover exactly which UIDs the rekey minted.
        let (new_priv_uid, new_pub_uid) = match &resp.batch_items[0].payload {
            Some(ResponsePayload::Sign(r)) => {
                let info = r.rekeyed.as_ref().expect("Sign must report the rekey it performed");
                (info.new_private_key_uid.clone(), info.new_public_key_uid.clone())
            }
            other => panic!("expected a Sign payload, got {other:?}"),
        };
        assert_ne!(new_priv_uid, "urn:legacy");

        // The old key must be restored to exactly its pre-rekey shape.
        let old = d.store.get("urn:legacy").unwrap().unwrap();
        assert_eq!(old.state, State::Active, "Undo must restore the pre-rekey Active state");
        assert!(old.supersedes.is_none(), "Undo must clear the supersedes link the rekey set");
        assert!(!old.links.contains_key("x-pqctoday-supersedes"));

        // The freshly-minted replacement key pair must be gone entirely —
        // Undo deletes anything that didn't exist before the batch item ran.
        assert!(
            d.store.get(&new_priv_uid).unwrap().is_none(),
            "Undo must delete the newly-minted replacement private key",
        );
        assert!(
            d.store.get(&new_pub_uid).unwrap().is_none(),
            "Undo must delete the newly-minted replacement public key",
        );
    }

    // ── Phase 1.4 (K14) — ticket-based session auth ─────────────────────

    /// The real proof of T4: a Login-issued ticket authenticates a
    /// LATER, otherwise-credential-free request — through the actual
    /// `dispatch()` entry point, not just the `login`/`logout` op
    /// functions in isolation. Query is a harmless op to probe with.
    #[test]
    fn login_ticket_authenticates_a_later_request() {
        use crate::kmip30::{Credential, QueryFunction, QueryRequest, Ticket};
        use crate::server::auth::{sha256_hex, AuthUser};

        let mut d = deps();
        d.config.auth_users = vec![AuthUser { username: "alice".into(), password_sha256: sha256_hex("pw") }];

        // A request with no credential at all: rejected under configured auth.
        let bare_query = || one_off_request(RequestPayload::Query(QueryRequest {
            functions: vec![QueryFunction::QueryOperations],
        }));
        let resp = dispatch(&d, bare_query());
        assert_eq!(resp.batch_items[0].result_status, ResultStatus::OperationFailed);

        // Login with a real username/password credential in the header.
        let login_req = RequestMessage {
            header: crate::kmip30::RequestHeader {
                authentication: vec![Credential::UsernameAndPassword {
                    username: "alice".into(),
                    password: Some("pw".into()),
                }],
                ..crate::kmip30::RequestHeader::v3()
            },
            batch_items: vec![RequestBatchItem {
                operation: crate::kmip30::Operation::Login,
                payload: RequestPayload::Login(crate::kmip30::LoginRequest {
                    lease_time: None, request_count: None, usage_limits: None,
                }),
            }],
        };
        let login_resp = dispatch(&d, login_req);
        assert_eq!(login_resp.batch_items[0].result_status, ResultStatus::Success);
        let ticket = match &login_resp.batch_items[0].payload {
            Some(ResponsePayload::Login(r)) => r.ticket.clone(),
            other => panic!("expected Login response payload, got {other:?}"),
        };

        // A LATER, otherwise-bare Query — carrying ONLY the ticket, no
        // username/password — must now authenticate.
        let ticket_req = RequestMessage {
            header: crate::kmip30::RequestHeader {
                authentication: vec![Credential::Ticket(Ticket {
                    ticket_type: ticket.ticket_type,
                    ticket_value: ticket.ticket_value.clone(),
                })],
                ..crate::kmip30::RequestHeader::v3()
            },
            batch_items: vec![RequestBatchItem {
                operation: crate::kmip30::Operation::Query,
                payload: RequestPayload::Query(QueryRequest { functions: vec![QueryFunction::QueryOperations] }),
            }],
        };
        let resp = dispatch(&d, ticket_req);
        assert_eq!(
            resp.batch_items[0].result_status,
            ResultStatus::Success,
            "a live Login ticket must authenticate a later request on its own"
        );

        // A ticket with tampered bytes must NOT authenticate.
        let mut bad_ticket_value = ticket.ticket_value.clone();
        bad_ticket_value[0] ^= 0xFF;
        let bad_req = RequestMessage {
            header: crate::kmip30::RequestHeader {
                authentication: vec![Credential::Ticket(Ticket {
                    ticket_type: ticket.ticket_type,
                    ticket_value: bad_ticket_value,
                })],
                ..crate::kmip30::RequestHeader::v3()
            },
            batch_items: vec![RequestBatchItem {
                operation: crate::kmip30::Operation::Query,
                payload: RequestPayload::Query(QueryRequest { functions: vec![] }),
            }],
        };
        assert_eq!(dispatch(&d, bad_req).batch_items[0].result_status, ResultStatus::OperationFailed);

        // Logout invalidates the ticket; it stops working on a THIRD request.
        let logout_req = RequestMessage {
            header: crate::kmip30::RequestHeader {
                authentication: vec![Credential::Ticket(ticket.clone())],
                ..crate::kmip30::RequestHeader::v3()
            },
            batch_items: vec![RequestBatchItem {
                operation: crate::kmip30::Operation::Logout,
                payload: RequestPayload::Logout(crate::kmip30::LogoutRequest { ticket: ticket.clone() }),
            }],
        };
        assert_eq!(dispatch(&d, logout_req).batch_items[0].result_status, ResultStatus::Success);

        let ticket_req_again = RequestMessage {
            header: crate::kmip30::RequestHeader {
                authentication: vec![Credential::Ticket(ticket)],
                ..crate::kmip30::RequestHeader::v3()
            },
            batch_items: vec![RequestBatchItem {
                operation: crate::kmip30::Operation::Query,
                payload: RequestPayload::Query(QueryRequest { functions: vec![] }),
            }],
        };
        assert_eq!(
            dispatch(&d, ticket_req_again).batch_items[0].result_status,
            ResultStatus::OperationFailed,
            "a logged-out ticket must stop authenticating"
        );
    }
}
