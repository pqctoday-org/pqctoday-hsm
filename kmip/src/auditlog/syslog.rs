//! [`SyslogSink`] — UDP syslog forwarder (RFC 5424 / BSD-syslog-compatible).
//!
//! Each audit event is emitted as a single UDP datagram with the RFC 5424
//! header followed by the raw JSON payload as the MSG part. Most syslog
//! daemons (rsyslog, syslog-ng, journald) accept RFC 5424 natively; the
//! structured-data (SD) part is empty (`-`) so the MSG is always readable
//! without SD-element parsing.
//!
//! Wire format (RFC 5424 §6):
//! ```text
//! <134>1 2026-06-20T12:34:56.789Z pqctoday-host pqctoday-kmip - - - {json}
//! ```
//!
//! Priority: `LOCAL0.INFO` (facility 16, severity 6 → encoded as 16*8+6 = 134).
//!
//! Failure mode: best-effort — a send error does not panic and the event
//! is still dropped (UDP has no retry story here), but per the
//! `AuditSink` trait's own "should log internally and drop" contract the
//! loss is no longer silent — see [`SyslogSink::dropped`].

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};

use super::event::AuditEvent;
use super::sink::AuditSink;

/// RFC 5424 `<priority>` for LOCAL0.INFO (facility=16, severity=6).
const SYSLOG_PRI: u8 = 16 * 8 + 6; // 134

pub struct SyslogSink {
    socket: UdpSocket,
    dest: SocketAddr,
    hostname: String,
    /// Gap-remediation Phase I — count of events dropped due to a send
    /// failure (serialise error or UDP `send_to` error). Every sibling
    /// sink (otlp/ring/jsonl) already logs+counts its losses; this one
    /// previously swallowed the error with no log line and no counter.
    dropped: AtomicU64,
}

impl SyslogSink {
    /// Bind a local UDP socket and target `dest` (e.g. `"127.0.0.1:514"`).
    pub fn open(dest: SocketAddr) -> std::io::Result<Self> {
        // Bind to any available local port; kernel picks the source port.
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_nonblocking(true)?;
        let hostname = hostname_str();
        Ok(Self { socket, dest, hostname, dropped: AtomicU64::new(0) })
    }

    /// Number of audit events dropped due to a serialise or UDP send
    /// failure.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl AuditSink for SyslogSink {
    fn emit(&self, event: AuditEvent) {
        let json = match serde_json::to_string(&event) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(target: "audit.syslog", "serialise failed: {e}");
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        // RFC 5424 §6 header: <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP SD MSG
        let ts = event.ts.format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| event.ts.to_string());
        let msg = format!(
            "<{PRI}>1 {ts} {host} pqctoday-kmip - - - {json}",
            PRI = SYSLOG_PRI,
            host = self.hostname,
        );
        // UDP is fire-and-forget; a full buffer or network error still
        // drops the event (no retry story here), but is now logged +
        // counted instead of silently swallowed.
        if let Err(e) = self.socket.send_to(msg.as_bytes(), self.dest) {
            tracing::warn!(target: "audit.syslog", "send failed: {e}");
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn hostname_str() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "pqctoday-kmip".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditlog::event::{DecisionSummary, EventPayload, Plane};

    /// Gap-remediation Phase I — `dropped()` exists and starts at 0; a
    /// normal local send (127.0.0.1 UDP is effectively always
    /// deliverable to the kernel's own loopback socket buffer) does not
    /// increment it.
    #[test]
    fn dropped_starts_at_zero_and_stays_zero_on_a_normal_send() {
        let sink = SyslogSink::open("127.0.0.1:514".parse().unwrap()).unwrap();
        assert_eq!(sink.dropped(), 0);
        sink.emit(AuditEvent::at(
            time::OffsetDateTime::now_utc(),
            Plane::Kmip,
            "c",
            EventPayload::PolicyDecided {
                op: "t".into(),
                algorithm: None,
                outcome: DecisionSummary::Allow { algorithm_override: None, substituted_by_rule: None },
                policy_fingerprint: "test".into(),
            },
        ));
        assert_eq!(sink.dropped(), 0);
    }
}
