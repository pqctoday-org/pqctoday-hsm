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
//! S-9 — export is best-effort (never back-pressures the server), but losses are
//! **bounded and observable**: each batch is retried with backoff, the HTTP
//! status is checked, the endpoint may be a DNS hostname, and any event that is
//! ultimately dropped (channel-full or export-failed-after-retries) increments
//! [`OtlpSink::dropped`].

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::Duration;

use super::event::AuditEvent;
use super::sink::AuditSink;

const BATCH_MAX: usize = 100;
const BATCH_TIMEOUT_MS: u64 = 500;
const CHAN_CAPACITY: usize = 4_096;
/// S-9 — export attempts per batch before the batch is dropped + counted.
const RETRY_MAX: usize = 3;

pub struct OtlpSink {
    tx: mpsc::Sender<AuditEvent>,
    dropped: Arc<AtomicU64>,
}

impl OtlpSink {
    /// Create an `OtlpSink` and spawn the background OTLP worker.
    ///
    /// `endpoint` must be an HTTP URL: `http://host:port` (path `/v1/logs` is
    /// appended automatically). `host` may be a DNS name (resolved per connect).
    pub fn spawn(endpoint: &str) -> anyhow::Result<Self> {
        let target = parse_http_target(endpoint)?;
        let (tx, rx) = mpsc::channel(CHAN_CAPACITY);
        let dropped = Arc::new(AtomicU64::new(0));
        tokio::spawn(otlp_worker(rx, target, dropped.clone()));
        Ok(Self { tx, dropped })
    }

    /// S-9 — total audit events lost (channel-full, or export-failed after
    /// [`RETRY_MAX`] attempts). Non-zero ⇒ the collector has a GAP.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl AuditSink for OtlpSink {
    fn emit(&self, event: AuditEvent) {
        // Non-blocking try_send — drop (and COUNT) if the worker is lagging.
        if let Err(mpsc::error::TrySendError::Full(_)) = self.tx.try_send(event) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(target: "audit.otlp", "channel full — event dropped");
        }
    }
}

/// Validate `http://host:port[/...]` and return the `host:port` authority.
/// `host` may be a DNS name — resolution happens at connect time
/// (`TcpStream::connect` does DNS), so idiomatic `http://collector:4318` works.
fn parse_http_target(endpoint: &str) -> anyhow::Result<String> {
    let without_scheme = endpoint
        .strip_prefix("http://")
        .ok_or_else(|| anyhow::anyhow!("--otlp-endpoint must start with http://"))?;
    let host_port = without_scheme.split('/').next().unwrap_or(without_scheme);
    if host_port.is_empty() || !host_port.contains(':') {
        anyhow::bail!("--otlp-endpoint must be http://host:port (got {endpoint:?})");
    }
    Ok(host_port.to_string())
}

/// Background task: drain the receiver, batch events, POST to OTLP with retry.
async fn otlp_worker(mut rx: mpsc::Receiver<AuditEvent>, target: String, dropped: Arc<AtomicU64>) {
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
        // S-9 — bounded retry + exponential backoff before giving up, then COUNT
        // the loss (rather than silently discarding on the first connect error).
        let mut sent = false;
        let mut backoff = Duration::from_millis(100);
        for attempt in 1..=RETRY_MAX {
            match send_otlp_http(&target, &body).await {
                Ok(()) => {
                    sent = true;
                    break;
                }
                Err(e) => {
                    tracing::warn!(
                        target: "audit.otlp",
                        "export attempt {attempt}/{RETRY_MAX} failed ({} events): {e}",
                        batch.len()
                    );
                    if attempt < RETRY_MAX {
                        tokio::time::sleep(backoff).await;
                        backoff *= 2;
                    }
                }
            }
        }
        if sent {
            tracing::debug!(target: "audit.otlp", "exported {} event(s)", batch.len());
        } else {
            dropped.fetch_add(batch.len() as u64, Ordering::Relaxed);
            tracing::error!(
                target: "audit.otlp",
                "dropped {} audit event(s) after {RETRY_MAX} attempts",
                batch.len()
            );
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

/// Send `body` as an HTTP/1.1 POST to `target/v1/logs` and verify a 2xx status.
/// `target` is `host:port`; `TcpStream::connect` resolves DNS hostnames.
async fn send_otlp_http(target: &str, body: &str) -> anyhow::Result<()> {
    let mut stream = tokio::net::TcpStream::connect(target).await?;
    let req = format!(
        "POST /v1/logs HTTP/1.1\r\nHost: {target}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
        len = body.len(),
    );
    stream.write_all(req.as_bytes()).await?;
    stream.shutdown().await?; // half-close the write side; the server then responds

    // S-9 — actually CHECK the status line instead of treating any accepted TCP
    // connection as success (a 5xx from the collector is a real failure).
    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).await?;
    let head = String::from_utf8_lossy(&buf[..n]);
    let status_line = head.lines().next().unwrap_or("");
    let ok = status_line.starts_with("HTTP/1.1 2") || status_line.starts_with("HTTP/1.0 2");
    if !ok {
        anyhow::bail!(
            "OTLP collector returned non-2xx: {}",
            if status_line.is_empty() { "<no response>" } else { status_line }
        );
    }
    Ok(())
}
