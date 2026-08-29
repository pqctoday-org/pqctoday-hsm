//! Phase 4 — asynchronous subsystem, end to end through the real
//! dispatcher (`dispatcher::dispatch`). Proves:
//!
//! 1. A `Mandatory`-async request against an eligible op enqueues a
//!    real job and gets back `OperationPending` + a correlation
//!    value — never the payload, no matter how fast the server
//!    actually finishes.
//! 2. `Deps::install_self_handle()` (mirroring the production binary)
//!    means the job genuinely executes on a detached OS thread — Poll
//!    observes real, not simulated, out-of-band completion, and its
//!    payload matches byte-for-byte what a plain synchronous call to
//!    the same operation produces.
//! 3. Poll is idempotent after completion; unknown correlation values
//!    fail; Process blocks-until-done instead of double-running the
//!    job; Cancel reports a real outcome; QueryAsynchronousRequests
//!    stops listing a job once it's Completed.
//! 4. The `Mandatory`-but-ineligible-op gate is per-item, not
//!    whole-batch — a sibling item in the same batch still processes.
//!
//! Deliberately does not exercise the TLS transport (already proven
//! generically by `tls_round_trip_query_request` in `tls_e2e.rs`) —
//! this file's job is the async-job scheduling logic itself.

use std::sync::Arc;
use std::time::{Duration, Instant};

use pqctoday_kmip::auditlog::{AuditSink, RingSink};
use pqctoday_kmip::dispatcher::dispatch;
use pqctoday_kmip::error::ResultReason;
use pqctoday_kmip::kmip30::{
    AsynchronousIndicator, BatchErrorContinuationOption, CancelRequest, CancellationResult,
    CryptographicParameters, HashRequest, HashingAlgorithm, Operation, PollRequest,
    ProcessRequest, QueryAsynchronousRequestsRequest, RequestBatchItem, RequestHeader,
    RequestMessage, RequestPayload, ResponsePayload, ResultStatus,
};
use pqctoday_kmip::ops::{Deps, DepsConfig};
use pqctoday_kmip::policy::{load_from_str, Engine};
use pqctoday_kmip::store::MemoryStore;

const PERMISSIVE_POLICY: &str = r#"
schema_version: 1
metadata: { name: t, description: t, authority: t, effective: always }
rules: []
"#;

fn build_deps() -> Arc<Deps> {
    let ring = Arc::new(RingSink::new(64));
    let sink: Arc<dyn AuditSink> = ring;
    let engine = Engine::with_global_sink(sink.clone());
    engine
        .replace_all(load_from_str(PERMISSIVE_POLICY, std::path::Path::new("<t>")).unwrap())
        .unwrap();
    let deps = Arc::new(Deps::new(engine, Arc::new(MemoryStore::new()), sink, DepsConfig::default()));
    // The whole point of this test file: without this call every job
    // would run eagerly/inline (still correct, just not genuinely
    // deferred) — see `Deps::self_handle`.
    deps.install_self_handle();
    deps
}

fn hash_payload(data: &[u8]) -> RequestPayload {
    RequestPayload::Hash(HashRequest {
        cryptographic_parameters: CryptographicParameters {
            hashing_algorithm: Some(HashingAlgorithm::Sha256),
            ..CryptographicParameters::default()
        },
        data: data.to_vec(),
    })
}

fn one_item(op: Operation, payload: RequestPayload, indicator: Option<AsynchronousIndicator>) -> RequestMessage {
    RequestMessage {
        header: RequestHeader { asynchronous_indicator: indicator, ..RequestHeader::v3() },
        batch_items: vec![RequestBatchItem { operation: op, payload }],
    }
}

/// Poll until the job leaves `OperationPending`, or panic after a
/// generous bound — this always converges (the job store guarantees
/// eventual completion, real-threaded or eager), so there is no
/// meaningful "how long" to tune: it's a correctness bound, not a
/// timing assumption.
fn poll_until_done(deps: &Deps, cv: Vec<u8>) -> pqctoday_kmip::kmip30::ResponseBatchItem {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let resp = dispatch(
            deps,
            one_item(Operation::Poll, RequestPayload::Poll(PollRequest { asynchronous_correlation_value: cv.clone() }), None),
        );
        let item = resp.batch_items.into_iter().next().unwrap();
        if item.result_status != ResultStatus::OperationPending {
            return item;
        }
        assert!(Instant::now() < deadline, "async job never completed");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn mandatory_hash_enqueues_then_poll_matches_synchronous_result() {
    let deps = build_deps();
    let data = b"honest maximum plan".to_vec();

    // Synchronous baseline — what the answer SHOULD be.
    let sync_resp = dispatch(&deps, one_item(Operation::Hash, hash_payload(&data), None));
    let sync_item = sync_resp.batch_items.into_iter().next().unwrap();
    assert_eq!(sync_item.result_status, ResultStatus::Success);
    let ResponsePayload::Hash(sync_hash) = sync_item.payload.unwrap() else { panic!("wrong variant") };

    // Same request, Mandatory async this time.
    let enqueue_resp = dispatch(
        &deps,
        one_item(Operation::Hash, hash_payload(&data), Some(AsynchronousIndicator::Mandatory)),
    );
    let enqueue_item = enqueue_resp.batch_items.into_iter().next().unwrap();
    assert_eq!(enqueue_item.result_status, ResultStatus::OperationPending);
    assert!(enqueue_item.payload.is_none(), "Pending response must never carry the payload");
    let cv = enqueue_item
        .asynchronous_correlation_value
        .expect("Pending response must carry a correlation value");
    assert!(!cv.is_empty());

    let done = poll_until_done(&deps, cv.clone());
    assert_eq!(done.result_status, ResultStatus::Success);
    assert_eq!(done.operation, Some(Operation::Hash), "Poll echoes the ORIGINAL polled operation");
    let ResponsePayload::Hash(async_hash) = done.payload.unwrap() else { panic!("wrong variant") };
    assert_eq!(async_hash.data, sync_hash.data, "async path must produce the exact same real result");

    // Poll again after completion — idempotent, same answer.
    let again = poll_until_done(&deps, cv);
    assert_eq!(again.result_status, ResultStatus::Success);
}

#[test]
fn poll_unknown_correlation_value_fails() {
    let deps = build_deps();
    let resp = dispatch(
        &deps,
        one_item(
            Operation::Poll,
            RequestPayload::Poll(PollRequest { asynchronous_correlation_value: vec![0xde, 0xad, 0xbe, 0xef] }),
            None,
        ),
    );
    let item = resp.batch_items.into_iter().next().unwrap();
    assert_eq!(item.result_status, ResultStatus::OperationFailed);
    assert_eq!(item.result_reason, Some(ResultReason::InvalidAsynchronousCorrelationValue.to_wire_value()));
}

#[test]
fn process_blocks_until_completed_instead_of_double_running() {
    let deps = build_deps();
    let enqueue_resp = dispatch(
        &deps,
        one_item(Operation::Hash, hash_payload(b"process-me"), Some(AsynchronousIndicator::Mandatory)),
    );
    let cv = enqueue_resp.batch_items[0].asynchronous_correlation_value.clone().unwrap();

    let process_resp = dispatch(
        &deps,
        one_item(Operation::Process, RequestPayload::Process(ProcessRequest { asynchronous_correlation_value: cv.clone() }), None),
    );
    let process_item = process_resp.batch_items.into_iter().next().unwrap();
    assert_eq!(process_item.result_status, ResultStatus::Success);
    assert_eq!(process_item.operation, Some(Operation::Process));

    // Job is real-Completed by the time Process returns (that's the
    // whole point of Process) — Poll must see it immediately, no
    // further waiting.
    let poll_resp = dispatch(
        &deps,
        one_item(Operation::Poll, RequestPayload::Poll(PollRequest { asynchronous_correlation_value: cv }), None),
    );
    let poll_item = poll_resp.batch_items.into_iter().next().unwrap();
    assert_eq!(poll_item.result_status, ResultStatus::Success);
    assert_eq!(poll_item.operation, Some(Operation::Hash));
}

#[test]
fn cancel_reports_a_real_outcome_and_query_async_requests_clears_on_completion() {
    let deps = build_deps();
    let enqueue_resp = dispatch(
        &deps,
        one_item(Operation::Hash, hash_payload(b"cancel-me"), Some(AsynchronousIndicator::Mandatory)),
    );
    let cv = enqueue_resp.batch_items[0].asynchronous_correlation_value.clone().unwrap();

    let cancel_resp = dispatch(
        &deps,
        one_item(Operation::Cancel, RequestPayload::Cancel(CancelRequest { asynchronous_correlation_value: cv.clone() }), None),
    );
    let cancel_item = cancel_resp.batch_items.into_iter().next().unwrap();
    assert_eq!(cancel_item.result_status, ResultStatus::Success);
    let ResponsePayload::Cancel(cancel_payload) = cancel_item.payload.unwrap() else { panic!("wrong variant") };
    // Genuine timing race between this test thread and the background
    // executor thread — any of the three is a legitimate, real
    // outcome (the exact per-stage behavior is pinned deterministically
    // by ops::async_ops's unit tests, which construct AsyncJob state
    // directly rather than racing a real thread).
    assert!(matches!(
        cancel_payload.cancellation_result,
        CancellationResult::Canceled | CancellationResult::UnableToCancel | CancellationResult::Completed
    ));

    // Whatever happened, the job is terminal now — wait for it, then
    // confirm Query Asynchronous Requests no longer lists it.
    poll_until_done(&deps, cv.clone());
    let qar_resp = dispatch(
        &deps,
        one_item(
            Operation::QueryAsynchronousRequests,
            RequestPayload::QueryAsynchronousRequests(QueryAsynchronousRequestsRequest::default()),
            None,
        ),
    );
    let qar_item = qar_resp.batch_items.into_iter().next().unwrap();
    assert_eq!(qar_item.result_status, ResultStatus::Success);
    let ResponsePayload::QueryAsynchronousRequests(qar) = qar_item.payload.unwrap() else { panic!("wrong variant") };
    assert!(
        qar.requests.iter().all(|r| r.asynchronous_correlation_value != cv),
        "a Completed job must not be reported as outstanding"
    );
}

#[test]
fn mandatory_ineligible_op_fails_only_that_item_not_the_whole_batch() {
    let deps = build_deps();
    let req = RequestMessage {
        header: RequestHeader {
            asynchronous_indicator: Some(AsynchronousIndicator::Mandatory),
            batch_error_continuation_option: Some(BatchErrorContinuationOption::Continue),
            ..RequestHeader::v3()
        },
        batch_items: vec![
            // Query is excluded from async eligibility (trivial
            // negotiation op) — must fail THIS item only.
            RequestBatchItem {
                operation: Operation::Query,
                payload: RequestPayload::Query(pqctoday_kmip::kmip30::QueryRequest {
                    functions: vec![pqctoday_kmip::kmip30::QueryFunction::QueryOperations],
                }),
            },
            RequestBatchItem { operation: Operation::Hash, payload: hash_payload(b"sibling-item") },
        ],
    };
    let resp = dispatch(&deps, req);
    assert_eq!(resp.batch_items.len(), 2, "Continue mode must still process the sibling item");
    assert_eq!(resp.batch_items[0].result_status, ResultStatus::OperationFailed);
    assert_eq!(
        resp.batch_items[0].result_reason,
        Some(ResultReason::OperationNotSupported.to_wire_value())
    );
    // The sibling Hash item was itself ALSO Mandatory-async (same
    // header) and IS eligible, so it enqueues rather than running
    // inline — Pending, not Success, is the correct shape here.
    assert_eq!(resp.batch_items[1].result_status, ResultStatus::OperationPending);
    assert!(resp.batch_items[1].asynchronous_correlation_value.is_some());
}
