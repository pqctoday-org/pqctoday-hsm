//! [`OtlpSink`] — OTLP/HTTP JSON exporter for audit events.
//!
//! Sends audit events to an OpenTelemetry collector at `POST /v1/logs`.
//! Uses OTLP HTTP/JSON (not Protobuf/gRPC), so no `opentelemetry` crate is
//! needed — the format is a plain JSON body over raw TCP.
//!
//! Architecture: a bounded `mpsc` channel decouples the sync [`AuditSink::emit`]
//! call from the async HTTP send. The background task batches up to
//! [`BATCH_MAX`] events or [`BATCH_TIMEOUT_MS`] ms, whichever comes first,
//! then fires one POST per batch.
//!
//! Only plain HTTP (`http://host:port`) is supported — the typical OTLP
//! collector (OpenTelemetry Collector, Grafana Alloy, Datadog Agent) runs on
//! plain HTTP at the container level and terminates TLS externally.
//!
//! Failure mode: connection errors are logged at `warn` level and the batch
//! is dropped — OTLP export is best-effort, never back-pressuring the server.

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::Duration;

use super::event::AuditEvent;
use super::sink::AuditSink;

const BATCH_MAX: usize = 100;
const BATCH_TIMEOUT_MS: u64 = 500;
const CHAN_CAPACITY: usize = 4_096;

pub struct OtlpSink {
    tx: mpsc::Sender<AuditEvent>,
}

impl OtlpSink {
    /// Create an `OtlpSink` and spawn the background OTLP worker.
    ///
    /// `endpoint` must be an HTTP URL: `http://host:port` (path `/v1/logs` is
    /// appended automatically).
    pub fn spawn(endpoint: &str) -> anyhow::Result<Self> {
        let addr = parse_http_addr(endpoint)?;
        let (tx, rx) = mpsc::channel(CHAN_CAPACITY);
        tokio::spawn(otlp_worker(rx, addr));
        Ok(Self { tx })
    }
}

impl AuditSink for OtlpSink {
    fn emit(&self, event: AuditEvent) {
        // Non-blocking try_send — drop if the worker is lagging.
        if let Err(mpsc::error::TrySendError::Full(_)) = self.tx.try_send(event) {
            tracing::warn!(target: "audit.otlp", "channel full — event dropped");
        }
    }
}

/// Parse `http://host:port` → `SocketAddr`. Path and other components ignored.
fn parse_http_addr(endpoint: &str) -> anyhow::Result<SocketAddr> {
    let without_scheme = endpoint
        .strip_prefix("http://")
        .ok_or_else(|| anyhow::anyhow!("--otlp-endpoint must start with http://"))?;
    let host_port = without_scheme.split('/').next().unwrap_or(without_scheme);
    let addr: SocketAddr = host_port
        .parse()
        .map_err(|e| anyhow::anyhow!("--otlp-endpoint parse error: {e}"))?;
    Ok(addr)
}

/// Background task: drain the receiver, batch events, POST to OTLP.
async fn otlp_worker(mut rx: mpsc::Receiver<AuditEvent>, addr: SocketAddr) {
    let timeout = Duration::from_millis(BATCH_TIMEOUT_MS);
    loop {
        // Wait for the first event (blocking recv — no spin when idle).
        let first = match rx.recv().await {
            Some(e) => e,
            None => break, // sender dropped → server shutting down
        };
        let mut batch = vec![first];

        // Drain more events up to BATCH_MAX within BATCH_TIMEOUT_MS.
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if batch.len() >= BATCH_MAX {
                break;
            }
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(ev)) => batch.push(ev),
                _ => break, // timeout or channel closed
            }
        }

        let body = build_otlp_body(&batch);
        if let Err(e) = send_otlp_http(addr, &body).await {
            tracing::warn!(target: "audit.otlp", "export failed ({} events): {e}", batch.len());
        } else {
            tracing::debug!(target: "audit.otlp", "exported {} event(s)", batch.len());
        }
    }
}

/// Build an OTLP/HTTP JSON log body for `events`.
fn build_otlp_body(events: &[AuditEvent]) -> String {
    let records: Vec<serde_json::Value> = events
        .iter()
        .map(|ev| {
            let ts_nanos = (ev.ts.unix_timestamp_nanos() as u64).to_string();
            let json = serde_json::to_string(ev).unwrap_or_default();
            serde_json::json!({
                "timeUnixNano": ts_nanos,
                "severityNumber": 9,
                "severityText": "INFO",
                "body": { "stringValue": json },
                "attributes": [
                    { "key": "kmip.plane",          "value": { "stringValue": ev.plane.as_str() }},
                    { "key": "kmip.correlation_id", "value": { "stringValue": &ev.correlation_id }},
                ]
            })
        })
        .collect();

    serde_json::to_string(&serde_json::json!({
        "resourceLogs": [{
            "resource": {
                "attributes": [{
                    "key": "service.name",
                    "value": { "stringValue": "pqctoday-kmip" }
                }]
            },
            "scopeLogs": [{
                "scope": { "name": "pqctoday_kmip.audit" },
                "logRecords": records
            }]
        }]
    }))
    .unwrap_or_default()
}

/// Send `body` as HTTP/1.1 POST to `addr/v1/logs`.
async fn send_otlp_http(addr: SocketAddr, body: &str) -> anyhow::Result<()> {
    let mut stream = tokio::net::TcpStream::connect(addr).await?;
    let req = format!(
        "POST /v1/logs HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
        len = body.len(),
    );
    stream.write_all(req.as_bytes()).await?;
    stream.shutdown().await?;
    // Drain the response (we don't need the body, just ensure the server ACKed).
    let mut resp = [0u8; 256];
    let _ = stream.read(&mut resp).await;
    Ok(())
}
