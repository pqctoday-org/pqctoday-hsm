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
//! Failure mode: best-effort — any send error is silently ignored (same
//! contract as [`super::sink::AuditSink`]).

use std::net::{SocketAddr, UdpSocket};

use super::event::AuditEvent;
use super::sink::AuditSink;

/// RFC 5424 `<priority>` for LOCAL0.INFO (facility=16, severity=6).
const SYSLOG_PRI: u8 = 16 * 8 + 6; // 134

pub struct SyslogSink {
    socket: UdpSocket,
    dest: SocketAddr,
    hostname: String,
}

impl SyslogSink {
    /// Bind a local UDP socket and target `dest` (e.g. `"127.0.0.1:514"`).
    pub fn open(dest: SocketAddr) -> std::io::Result<Self> {
        // Bind to any available local port; kernel picks the source port.
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_nonblocking(true)?;
        let hostname = hostname_str();
        Ok(Self { socket, dest, hostname })
    }
}

impl AuditSink for SyslogSink {
    fn emit(&self, event: AuditEvent) {
        let json = match serde_json::to_string(&event) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(target: "audit.syslog", "serialise failed: {e}");
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
        // UDP is fire-and-forget; a full buffer or network error is silent.
        let _ = self.socket.send_to(msg.as_bytes(), self.dest);
    }
}

fn hostname_str() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "pqctoday-kmip".to_string())
}
