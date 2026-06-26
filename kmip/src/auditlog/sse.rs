//! [`SseSink`] — broadcast audit events to Server-Sent Event subscribers.
//!
//! The admin facade subscribes per-connection via [`SseSink::subscribe`] and
//! streams events as `data: {json}\n\n` frames (SSE wire format). Slow
//! consumers are dropped from the broadcast ring — they receive a
//! `event: lag` comment on reconnect instead of crashing the server.
//!
//! Capacity: 1 024 events. At 1 000 events/s that's ~1 s of buffer.
//! Producers that fall behind by more than capacity receive `RecvError::Lagged`.

use tokio::sync::broadcast;

use super::event::AuditEvent;
use super::sink::AuditSink;

pub const SSE_BROADCAST_CAPACITY: usize = 1_024;

/// One-sender, many-receiver broadcast sink for the SSE stream.
pub struct SseSink {
    tx: broadcast::Sender<String>,
}

impl SseSink {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(SSE_BROADCAST_CAPACITY);
        Self { tx }
    }

    /// Subscribe a new SSE connection. Returns a receiver that gets pre-serialized
    /// event JSON (one line per event, no trailing newline).
    pub fn subscribe(&self) -> broadcast::Receiver<String> {
        self.tx.subscribe()
    }

    /// Number of active SSE subscribers.
    pub fn receiver_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

impl Default for SseSink {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditSink for SseSink {
    fn emit(&self, event: AuditEvent) {
        // Broadcast only when there are active subscribers — cheap no-op otherwise.
        if self.tx.receiver_count() == 0 {
            return;
        }
        match serde_json::to_string(&event) {
            Ok(json) => {
                // SendError means no receivers; that's fine — best-effort.
                let _ = self.tx.send(json);
            }
            Err(e) => {
                tracing::error!(target: "audit.sse", "serialise failed: {e}");
            }
        }
    }
}
