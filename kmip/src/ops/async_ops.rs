//! Phase 4 — the three asynchronous-management operations that DO run
//! through the normal `Result<Response, KmipError>` handler shape:
//!
//! - `Cancel` §6.1.5 — best-effort stop of a job that hasn't started
//!   executing yet.
//! - `Process` §6.1.46 — block until a job reaches `Completed`
//!   ("effectively changing the processing mode for that batch item to
//!   that resembling synchronous processing").
//! - `Query Asynchronous Requests` §6.1.48 — list outstanding jobs.
//!
//! `Poll` (§6.1.45) is deliberately NOT here — its successful response
//! impersonates whatever operation it's polling for, which this
//! module's normal per-op `ResponsePayload` wrapping can't express.
//! See `dispatcher::handle_poll`.
//!
//! The job store + executor themselves ([`crate::ops::AsyncJob`],
//! `dispatcher::enqueue_async_job`) live one layer down — this module
//! only reads/mutates jobs that already exist.

use crate::error::{KmipError, Result};
use crate::kmip30::{
    AsynchronousRequestInfo, CancelRequest, CancelResponse, CancellationResult, ProcessRequest,
    ProcessResponse, ProcessingStage, QueryAsynchronousRequestsRequest,
    QueryAsynchronousRequestsResponse,
};

use super::deps::Deps;
use super::helpers::{emit_request, emit_success, fail_err};

/// `Cancel` (KMIP 3.0 §6.1.5). The only case that stops real work is a
/// job still `Submitted` (never started) — `AsyncJob::try_cancel_if_submitted`
/// handles that atomically. A job already `InProcess` on a real
/// background thread cannot be safely preempted (no cooperative
/// cancellation checkpoints inside op handlers — interrupting
/// mid-`handle_payload` could leave the store half-mutated), so this
/// honestly reports `UnableToCancel` rather than pretending to stop
/// it. A job already `Completed` reports `Completed` (succeeded) or
/// `Failed` (the operation itself errored) — either way, too late to
/// cancel. `Unavailable` is never produced by this implementation.
pub fn cancel(
    deps: &Deps,
    req: CancelRequest,
    auth: &crate::server::auth::AuthContext,
    correlation_id: &str,
) -> Result<CancelResponse> {
    emit_request(
        deps,
        correlation_id,
        "Cancel",
        format!("correlation_value={} bytes", req.asynchronous_correlation_value.len()),
    );

    let requester = auth.identity.as_ref().map(|i| i.username.clone());
    let job = {
        let jobs = deps.async_jobs.lock().unwrap_or_else(|e| e.into_inner());
        jobs.get(&req.asynchronous_correlation_value).cloned()
    };
    // Part F §F7.5 — a foreign tenant's job is indistinguishable from a
    // nonexistent one (anti-oracle), same as Poll.
    let job = job
        .filter(|j| j.state.lock().unwrap_or_else(|e| e.into_inner()).owner == requester)
        .ok_or_else(|| {
            fail_err(deps, correlation_id, "Cancel", KmipError::invalid_asynchronous_correlation_value())
        })?;

    let cancellation_result = if job.try_cancel_if_submitted() {
        CancellationResult::Canceled
    } else {
        let st = job.state.lock().unwrap_or_else(|e| e.into_inner());
        match st.stage {
            ProcessingStage::InProcess => CancellationResult::UnableToCancel,
            ProcessingStage::Completed => match &st.outcome {
                Some(Ok(_)) => CancellationResult::Completed,
                Some(Err(_)) => CancellationResult::Failed,
                None => unreachable!(
                    "AsyncJob::mark_completed always sets `outcome` before `stage = Completed`"
                ),
            },
            ProcessingStage::Submitted => {
                unreachable!("try_cancel_if_submitted would have handled this")
            }
        }
    };

    emit_success(deps, correlation_id, "Cancel");
    Ok(CancelResponse {
        asynchronous_correlation_value: req.asynchronous_correlation_value,
        cancellation_result,
    })
}

/// `Process` (KMIP 3.0 §6.1.46) — blocks the calling thread until the
/// named job reaches `Completed`. Never re-runs the operation itself
/// (that would risk double-executing a side-effecting handler); it
/// only waits on the same `Condvar` the executor signals.
pub fn process(
    deps: &Deps,
    req: ProcessRequest,
    auth: &crate::server::auth::AuthContext,
    correlation_id: &str,
) -> Result<ProcessResponse> {
    emit_request(
        deps,
        correlation_id,
        "Process",
        format!("correlation_value={} bytes", req.asynchronous_correlation_value.len()),
    );

    let requester = auth.identity.as_ref().map(|i| i.username.clone());
    let job = {
        let jobs = deps.async_jobs.lock().unwrap_or_else(|e| e.into_inner());
        jobs.get(&req.asynchronous_correlation_value).cloned()
    };
    // Part F §F7.5 — foreign-tenant job indistinguishable from missing
    // (anti-oracle); Process otherwise blocks until it can read the
    // outcome, which is another tenant's result.
    let job = job
        .filter(|j| j.state.lock().unwrap_or_else(|e| e.into_inner()).owner == requester)
        .ok_or_else(|| {
            fail_err(deps, correlation_id, "Process", KmipError::invalid_asynchronous_correlation_value())
        })?;

    job.wait_until_completed();

    emit_success(deps, correlation_id, "Process");
    Ok(ProcessResponse {})
}

/// `Query Asynchronous Requests` (KMIP 3.0 §6.1.48). Reports jobs that
/// are still genuinely outstanding — this implementation treats
/// `stage == Completed` as "results obtained" (a `Poll` or `Cancel`
/// can retrieve them at any time after that point, so there is nothing
/// further this listing needs to surface) and excludes them, which is
/// a documented reading of "results not yet obtained" rather than
/// literally tracking whether a client already called `Poll`.
pub fn query_asynchronous_requests(
    deps: &Deps,
    req: QueryAsynchronousRequestsRequest,
    auth: &crate::server::auth::AuthContext,
    correlation_id: &str,
) -> Result<QueryAsynchronousRequestsResponse> {
    emit_request(
        deps,
        correlation_id,
        "QueryAsynchronousRequests",
        format!(
            "correlation_value_filter={} operation_filter={}",
            req.asynchronous_correlation_values.len(),
            req.operations.len()
        ),
    );

    let requester = auth.identity.as_ref().map(|i| i.username.clone());
    let jobs = deps.async_jobs.lock().unwrap_or_else(|e| e.into_inner());
    let mut requests = Vec::new();
    for (cv, job) in jobs.iter() {
        let st = job.state.lock().unwrap_or_else(|e| e.into_inner());
        // Part F §F7.5 — a tenant sees only its OWN outstanding jobs,
        // never another tenant's (which would leak that tenant's
        // operation types + submission times, and expose correlation
        // values to guess for a Poll).
        if st.owner != requester {
            continue;
        }
        if st.stage == ProcessingStage::Completed {
            continue;
        }
        if !req.asynchronous_correlation_values.is_empty()
            && !req.asynchronous_correlation_values.contains(cv)
        {
            continue;
        }
        if !req.operations.is_empty() && !req.operations.contains(&st.operation) {
            continue;
        }
        requests.push(AsynchronousRequestInfo {
            asynchronous_correlation_value: cv.clone(),
            operation: st.operation,
            submission_date: st.submitted_at.unix_timestamp(),
            processing_stage: st.stage,
        });
    }

    emit_success(deps, correlation_id, "QueryAsynchronousRequests");
    Ok(QueryAsynchronousRequestsResponse { requests })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditlog::{AuditSink, RingSink};
    use crate::kmip30::Operation;
    use crate::ops::{AsyncJob, DepsConfig};
    use crate::policy::{load_from_str, Engine};
    use crate::store::MemoryStore;
    use std::sync::Arc;

    fn deps() -> Deps {
        let ring = Arc::new(RingSink::new(64));
        let sink: Arc<dyn AuditSink> = ring;
        let engine = Engine::with_global_sink(sink.clone());
        engine
            .activate(
                load_from_str(
                    "schema_version: 1\nmetadata: {name: t, description: t, authority: t, effective: always}\nrules: []\n",
                    std::path::Path::new("<t>"),
                )
                .unwrap(),
            )
            .unwrap();
        Deps::new(engine, Arc::new(MemoryStore::new()), sink, DepsConfig::default())
    }

    fn insert_job(deps: &Deps, op: Operation) -> (Vec<u8>, Arc<AsyncJob>) {
        let cv = deps.new_correlation_value();
        let job = AsyncJob::new(op, None);
        deps.async_jobs.lock().unwrap().insert(cv.clone(), job.clone());
        (cv, job)
    }

    #[test]
    fn cancel_unknown_correlation_value_fails() {
        let deps = deps();
        let err = cancel(
            &deps,
            CancelRequest { asynchronous_correlation_value: vec![0xaa; 8] },
            &crate::server::auth::AuthContext::open(),
            "t",
        )
        .unwrap_err();
        assert_eq!(err.result_reason(), crate::error::ResultReason::InvalidAsynchronousCorrelationValue);
    }

    #[test]
    fn cancel_submitted_job_reports_canceled_and_poll_sees_the_cancellation() {
        let deps = deps();
        let (cv, job) = insert_job(&deps, Operation::Hash);
        let resp = cancel(&deps, CancelRequest { asynchronous_correlation_value: cv }, &crate::server::auth::AuthContext::open(), "t").unwrap();
        assert_eq!(resp.cancellation_result, CancellationResult::Canceled);
        let st = job.state.lock().unwrap();
        assert_eq!(st.stage, ProcessingStage::Completed);
        assert!(matches!(st.outcome, Some(Err(_))));
    }

    #[test]
    fn cancel_in_process_job_reports_unable_to_cancel() {
        let deps = deps();
        let (cv, job) = insert_job(&deps, Operation::Hash);
        job.mark_in_process();
        let resp = cancel(&deps, CancelRequest { asynchronous_correlation_value: cv }, &crate::server::auth::AuthContext::open(), "t").unwrap();
        assert_eq!(resp.cancellation_result, CancellationResult::UnableToCancel);
    }

    #[test]
    fn cancel_completed_job_reports_completed_or_failed_by_outcome() {
        let deps = deps();
        let (cv_ok, job_ok) = insert_job(&deps, Operation::Hash);
        job_ok.mark_completed(Ok(crate::kmip30::ResponsePayload::Process(ProcessResponse {})));
        let resp = cancel(&deps, CancelRequest { asynchronous_correlation_value: cv_ok }, &crate::server::auth::AuthContext::open(), "t").unwrap();
        assert_eq!(resp.cancellation_result, CancellationResult::Completed);

        let (cv_err, job_err) = insert_job(&deps, Operation::Hash);
        job_err.mark_completed(Err(KmipError::internal("boom")));
        let resp = cancel(&deps, CancelRequest { asynchronous_correlation_value: cv_err }, &crate::server::auth::AuthContext::open(), "t").unwrap();
        assert_eq!(resp.cancellation_result, CancellationResult::Failed);
    }

    #[test]
    fn process_blocks_until_completed_then_returns() {
        let deps = deps();
        let (cv, job) = insert_job(&deps, Operation::Hash);
        job.mark_completed(Ok(crate::kmip30::ResponsePayload::Process(ProcessResponse {})));
        process(&deps, ProcessRequest { asynchronous_correlation_value: cv }, &crate::server::auth::AuthContext::open(), "t").unwrap();
    }

    #[test]
    fn process_unknown_correlation_value_fails() {
        let deps = deps();
        let err = process(
            &deps,
            ProcessRequest { asynchronous_correlation_value: vec![0xbb; 8] },
            &crate::server::auth::AuthContext::open(),
            "t",
        )
        .unwrap_err();
        assert_eq!(err.result_reason(), crate::error::ResultReason::InvalidAsynchronousCorrelationValue);
    }

    #[test]
    fn query_asynchronous_requests_lists_only_outstanding_jobs_and_honors_filters() {
        let deps = deps();
        let (cv_hash, _) = insert_job(&deps, Operation::Hash);
        let (_cv_sign, job_sign) = insert_job(&deps, Operation::Sign);
        // Completed jobs are no longer "outstanding".
        job_sign.mark_completed(Ok(crate::kmip30::ResponsePayload::Process(ProcessResponse {})));

        let all = query_asynchronous_requests(&deps, QueryAsynchronousRequestsRequest::default(), &crate::server::auth::AuthContext::open(), "t")
            .unwrap();
        assert_eq!(all.requests.len(), 1);
        assert_eq!(all.requests[0].asynchronous_correlation_value, cv_hash);
        assert_eq!(all.requests[0].operation, Operation::Hash);
        assert_eq!(all.requests[0].processing_stage, ProcessingStage::Submitted);

        let filtered_out = query_asynchronous_requests(
            &deps,
            QueryAsynchronousRequestsRequest {
                asynchronous_correlation_values: vec![],
                operations: vec![Operation::Sign],
            },
            &crate::server::auth::AuthContext::open(),
            "t",
        )
        .unwrap();
        assert!(filtered_out.requests.is_empty());
    }
}
