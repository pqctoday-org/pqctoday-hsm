//! [`RingSink`] — bounded in-memory audit ring.
//!
//! Default sink for sandbox / tests / the Hub UI's "recent activity"
//! panel. When the ring is full, the oldest event is evicted.
//!
//! Query API ([`Self::snapshot`], [`Self::filter_correlation_id`],
//! [`Self::filter_plane`]) is what the Phase-7 server's `GET /audit?...`
//! endpoint will wrap. Hub UI tails by polling `snapshot()` periodically
//! (or by subscribing to a future SSE wrapper, separate workstream).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use super::event::{AuditEvent, Plane};
use super::sink::AuditSink;

pub struct RingSink {
    inner: Mutex<VecDeque<AuditEvent>>,
    capacity: usize,
    /// S-9 — count of events silently evicted because the ring was full. A
    /// non-zero value means the audit trail has a GAP (a burst — possibly one
    /// masking a real event — overran the buffer). Surfaced via `dropped()` so
    /// the loss is observable instead of invisible.
    dropped: AtomicU64,
}

impl RingSink {
    /// Allocate a ring with `capacity` slots. Production default: 16 384.
    /// Tests typically use 64–256.
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(VecDeque::with_capacity(capacity.min(1024))),
            capacity,
            dropped: AtomicU64::new(0),
        }
    }

    /// S-9 — number of events evicted because the ring was full (an audit GAP).
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Snapshot the current ring. Cheap-ish — clones the deque.
    pub fn snapshot(&self) -> Vec<AuditEvent> {
        self.inner
            .lock()
            .expect("ring poisoned")
            .iter()
            .cloned()
            .collect()
    }

    /// Return all events sharing `correlation_id`, in insertion order.
    /// Used by the Hub UI to render the full three-plane trace for one
    /// request when the user clicks on a row.
    pub fn filter_correlation_id(&self, correlation_id: &str) -> Vec<AuditEvent> {
        self.inner
            .lock()
            .expect("ring poisoned")
            .iter()
            .filter(|e| e.correlation_id == correlation_id)
            .cloned()
            .collect()
    }

    /// Return all events from one plane, in insertion order.
    pub fn filter_plane(&self, plane: Plane) -> Vec<AuditEvent> {
        self.inner
            .lock()
            .expect("ring poisoned")
            .iter()
            .filter(|e| e.plane == plane)
            .cloned()
            .collect()
    }

    /// Drain the ring (used by tests that want a fresh state).
    pub fn clear(&self) {
        self.inner.lock().expect("ring poisoned").clear();
        self.dropped.store(0, Ordering::Relaxed);
    }

    /// Current size of the ring.
    pub fn len(&self) -> usize {
        self.inner.lock().expect("ring poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl AuditSink for RingSink {
    fn emit(&self, event: AuditEvent) {
        let mut q = self.inner.lock().expect("ring poisoned");
        if q.len() == self.capacity {
            q.pop_front();
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        q.push_back(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::event::{DecisionSummary, EventPayload};
    use time::OffsetDateTime;

    fn ev(plane: Plane, corr: &str) -> AuditEvent {
        AuditEvent::at(
            OffsetDateTime::UNIX_EPOCH,
            plane,
            corr,
            EventPayload::PolicyDecided {
                op: "Sign".into(),
                algorithm: Some("ML-DSA-87".into()),
                outcome: DecisionSummary::Allow {
                    algorithm_override: None,
                    substituted_by_rule: None,
                    cp_override: None,
                },
                policy_fingerprint: "sha256:0".into(),
            },
        )
    }

    #[test]
    fn ring_evicts_oldest_when_full() {
        let ring = RingSink::new(3);
        for i in 0..5 {
            ring.emit(ev(Plane::Agility, &format!("c{i}")));
        }
        let snap = ring.snapshot();
        assert_eq!(snap.len(), 3);
        // Oldest two evicted; remaining are c2, c3, c4.
        assert_eq!(snap[0].correlation_id, "c2");
        assert_eq!(snap[2].correlation_id, "c4");
    }

    #[test]
    fn filter_by_correlation_id() {
        let ring = RingSink::new(10);
        ring.emit(ev(Plane::Agility, "X"));
        ring.emit(ev(Plane::Kmip,    "Y"));
        ring.emit(ev(Plane::Pkcs11,  "X"));
        let x = ring.filter_correlation_id("X");
        assert_eq!(x.len(), 2);
        assert_eq!(x[0].plane, Plane::Agility);
        assert_eq!(x[1].plane, Plane::Pkcs11);
    }

    #[test]
    fn filter_by_plane() {
        let ring = RingSink::new(10);
        ring.emit(ev(Plane::Agility, "a"));
        ring.emit(ev(Plane::Agility, "b"));
        ring.emit(ev(Plane::Kmip, "c"));
        assert_eq!(ring.filter_plane(Plane::Agility).len(), 2);
        assert_eq!(ring.filter_plane(Plane::Kmip).len(), 1);
        assert_eq!(ring.filter_plane(Plane::Pkcs11).len(), 0);
    }
}
