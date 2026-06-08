//! [`JsonlSink`] — append-only JSON-Lines file writer.
//!
//! One line per event, terminated with `\n`. Production sandbox runs wire
//! this alongside a [`super::RingSink`] (via [`super::CompositeSink`]) so
//! the Hub UI tails the ring while the JSONL accumulates durable history.
//!
//! Failure mode: any I/O error is logged via `tracing::error!` and the
//! event is silently dropped — audit MUST NEVER take down a production
//! request. The next event retries the write.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use super::event::AuditEvent;
use super::sink::AuditSink;

pub struct JsonlSink {
    path: PathBuf,
    file: Mutex<File>,
}

impl JsonlSink {
    /// Open or create `path` for append-write. Parent directory must exist.
    pub fn open(path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = path.into();
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        Ok(Self {
            path,
            file: Mutex::new(file),
        })
    }

    /// Underlying file path. Hub UI / operators reference this when
    /// downloading the durable forensic record.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl AuditSink for JsonlSink {
    fn emit(&self, event: AuditEvent) {
        let line = match serde_json::to_string(&event) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(target: "audit", "serialise failed: {e}");
                return;
            }
        };
        let mut file = match self.file.lock() {
            Ok(f) => f,
            Err(_) => {
                tracing::error!(target: "audit", "jsonl sink mutex poisoned");
                return;
            }
        };
        if let Err(e) = writeln!(file, "{line}") {
            tracing::error!(target: "audit", "jsonl write failed: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::event::{DecisionSummary, EventPayload, Plane};
    use time::OffsetDateTime;

    fn tmp_file(suffix: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "pqctoday-audit-{}-{}.jsonl",
            suffix,
            uuid::Uuid::new_v4()
        ))
    }

    #[test]
    fn writes_one_line_per_event() {
        let path = tmp_file("one-per-line");
        let sink = JsonlSink::open(&path).unwrap();
        for i in 0..3 {
            sink.emit(AuditEvent::at(
                OffsetDateTime::UNIX_EPOCH,
                Plane::Kmip,
                format!("c{i}"),
                EventPayload::PolicyDecided {
                    op: "Sign".into(),
                    algorithm: None,
                    outcome: DecisionSummary::Allow {
                        algorithm_override: None,
                        substituted_by_rule: None,
                    },
                    policy_fingerprint: "sha256:0".into(),
                },
            ));
        }
        drop(sink); // release file handle so we can read
        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 3);
        for line in &lines {
            let _back: AuditEvent = serde_json::from_str(line)
                .expect("each line must be valid JSON");
        }
        let _ = std::fs::remove_file(&path);
    }
}
