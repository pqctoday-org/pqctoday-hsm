//! [`BehaviourSink`] — the audit-stream leg that feeds the behaviour ring.
//!
//! One more leg on the [`super::CompositeSink`] fan-out, next to the JSONL,
//! syslog and OTLP legs: every plane's events arrive here, and the ones that
//! describe a *transaction* become one 8-byte record in the shared ring the
//! appliance's behaviour monitor reads (`softhsmrustv3::behaviour`, the same
//! ring the PKCS#11 engines write into from their own call sites).
//!
//! What becomes a record:
//!
//! | event | record |
//! |-------|--------|
//! | `KmipResponseSent` | `SRC_KMIP_DATA`, op = the KMIP operation, alg / client stitched from the request's earlier events, result from the KMIP result, latency from `latency_ms` |
//! | `PolicyDecided { Deny }` | `SRC_POLICY`, op = deny (the response's own record then carries `RESULT_POLICY_DENY` too) |
//! | `PolicyDecided { Rekey }`, `RekeyPlanned` | `SRC_POLICY`, op = rekey-planned |
//! | `PolicyWarned` | `SRC_POLICY`, op = warn; the response's record carries `RESULT_WARN_REKEY` |
//! | `PolicyActivated` | `SRC_POLICY`, op = activated |
//!
//! Not a record: `KmipRequestReceived` (it only contributes the client bucket
//! to the response's record), `PolicyDecided { Allow }` (folded into the
//! response's result byte), `KmipObjectStateChanged`, `Pkcs11SessionLifecycle`,
//! and `Pkcs11Call` — the engine already writes that call's own record from
//! inside `softhsmrustv3::native`, in this same process, so a record here
//! would count every bridge call twice.
//!
//! The stitch table is bounded: a request that is received and never
//! answered (the dispatcher's own failure paths do answer, so this is a
//! defensive cap, not an expected path) is dropped once the table holds
//! [`PENDING_CAP`] entries. Losing an entry costs that one record its client
//! and algorithm bytes, nothing else.
//!
//! Zero cost when off: the server only builds this sink when
//! `PQC_BEHAVIOUR_RING` names a ring the process could map.

use std::collections::HashMap;
use std::sync::Mutex;

use softhsmrustv3::behaviour::{self, Record};

use super::event::{AuditEvent, DecisionSummary, EventPayload, KmipOpResult};
use super::sink::AuditSink;

/// Upper bound on requests awaiting their `KmipResponseSent`.
pub const PENDING_CAP: usize = 4096;

#[derive(Default, Clone, Copy)]
struct Pending {
    client: u8,
    alg: u8,
    warned: bool,
}

/// Audit-stream → behaviour-ring adapter. See the module doc.
#[derive(Default)]
pub struct BehaviourSink {
    pending: Mutex<HashMap<String, Pending>>,
}

impl BehaviourSink {
    /// The sink, if `PQC_BEHAVIOUR_RING` names a ring this process could map.
    pub fn from_env() -> Option<Self> {
        behaviour::enabled().then(Self::default)
    }

    fn with_pending<R>(&self, f: impl FnOnce(&mut HashMap<String, Pending>) -> R) -> R {
        let mut map = match self.pending.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        f(&mut map)
    }

    fn update(&self, correlation_id: &str, f: impl FnOnce(&mut Pending)) {
        self.with_pending(|map| {
            if !map.contains_key(correlation_id) && map.len() >= PENDING_CAP {
                map.clear();
            }
            f(map.entry(correlation_id.to_string()).or_default());
        });
    }

    fn take(&self, correlation_id: &str) -> Pending {
        self.with_pending(|map| map.remove(correlation_id).unwrap_or_default())
    }

    /// Pure mapping used by `emit`; separated so tests can assert the exact
    /// record for an event without a ring.
    fn record_for(&self, event: &AuditEvent) -> Option<Record> {
        use behaviour::*;
        let corr = event.correlation_id.as_str();
        match &event.event {
            EventPayload::KmipRequestReceived { client_cn, .. } => {
                let client = client_bucket(client_cn.as_deref().unwrap_or(""));
                self.update(corr, |p| p.client = client);
                None
            }
            EventPayload::PolicyDecided {
                algorithm, outcome, ..
            } => {
                let alg = alg_from_name(algorithm.as_deref().unwrap_or(""));
                let mut client = 0;
                self.update(corr, |p| {
                    p.alg = alg;
                    client = p.client;
                    if matches!(outcome, DecisionSummary::Rekey { .. }) {
                        p.warned = true;
                    }
                });
                match outcome {
                    DecisionSummary::Allow { .. } => None,
                    DecisionSummary::Deny { .. } => Some(
                        Record::new(SRC_POLICY, OP_POLICY_DENY, alg, RESULT_POLICY_DENY)
                            .client(client),
                    ),
                    DecisionSummary::Rekey { new_algorithm, .. } => Some(
                        Record::new(
                            SRC_POLICY,
                            OP_POLICY_REKEY_PLANNED,
                            alg_from_name(new_algorithm),
                            RESULT_WARN_REKEY,
                        )
                        .client(client),
                    ),
                }
            }
            EventPayload::PolicyWarned { .. } => {
                let mut client = 0;
                self.update(corr, |p| {
                    p.warned = true;
                    client = p.client;
                });
                Some(
                    Record::new(SRC_POLICY, OP_POLICY_WARN, ALG_NONE, RESULT_WARN_REKEY)
                        .client(client),
                )
            }
            EventPayload::RekeyPlanned { new_algorithm, .. } => Some(Record::new(
                SRC_POLICY,
                OP_POLICY_REKEY_PLANNED,
                alg_from_name(new_algorithm),
                RESULT_WARN_REKEY,
            )),
            EventPayload::PolicyActivated { .. } => Some(Record::new(
                SRC_POLICY,
                OP_POLICY_ACTIVATED,
                ALG_NONE,
                RESULT_OK,
            )),
            EventPayload::KmipResponseSent {
                op,
                result,
                latency_ms,
            } => {
                let p = self.take(corr);
                let result = match result {
                    KmipOpResult::Success if p.warned => RESULT_WARN_REKEY,
                    KmipOpResult::Success => RESULT_OK,
                    KmipOpResult::OperationFailed { reason } => {
                        result_from_kmip_reason(Some(reason))
                    }
                };
                // Handlers label some ops with their intent ("CreateKeyPair:Sign",
                // "CreateKeyPair:KeyAgreement"); the KMIP operation is the part
                // before the colon.
                let op_name = op.split(':').next().unwrap_or(op);
                Some(
                    Record::new(SRC_KMIP_DATA, op_kmip(op_name), p.alg, result)
                        .client(p.client)
                        .latency_us(u64::from(*latency_ms) * 1000),
                )
            }
            EventPayload::KmipObjectStateChanged { .. }
            | EventPayload::Pkcs11Call { .. }
            | EventPayload::Pkcs11SessionLifecycle { .. } => None,
        }
    }
}

impl AuditSink for BehaviourSink {
    fn emit(&self, event: AuditEvent) {
        if let Some(rec) = self.record_for(&event) {
            behaviour::emit(rec);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::event::Plane;
    use super::*;
    use softhsmrustv3::behaviour::*;
    use time::OffsetDateTime;

    fn ev(corr: &str, plane: Plane, payload: EventPayload) -> AuditEvent {
        AuditEvent::at(OffsetDateTime::UNIX_EPOCH, plane, corr, payload)
    }

    fn allow() -> DecisionSummary {
        DecisionSummary::Allow {
            algorithm_override: None,
            substituted_by_rule: None,
            cp_override: None,
        }
    }

    #[test]
    fn a_kmip_round_trip_becomes_one_record_with_client_alg_and_latency_stitched_in() {
        let sink = BehaviourSink::default();
        assert!(
            sink.record_for(&ev(
                "c1",
                Plane::Kmip,
                EventPayload::KmipRequestReceived {
                    op: "Sign".into(),
                    request_summary: "…".into(),
                    client_cn: Some("cn=learner-7".into()),
                },
            ))
            .is_none(),
            "the request itself is not a record"
        );
        assert!(
            sink.record_for(&ev(
                "c1",
                Plane::Agility,
                EventPayload::PolicyDecided {
                    op: "Sign".into(),
                    algorithm: Some("ML-DSA-65".into()),
                    outcome: allow(),
                    policy_fingerprint: "sha256:0".into(),
                },
            ))
            .is_none(),
            "an Allow is folded into the response's record"
        );
        let rec = sink
            .record_for(&ev(
                "c1",
                Plane::Kmip,
                EventPayload::KmipResponseSent {
                    op: "Sign".into(),
                    result: KmipOpResult::Success,
                    latency_ms: 12,
                },
            ))
            .expect("the response is the record");
        assert_eq!(rec.src, SRC_KMIP_DATA);
        assert_eq!(rec.op, op_kmip("Sign"));
        assert_eq!(rec.alg, ALG_ML_DSA_65);
        assert_eq!(rec.result, RESULT_OK);
        assert_eq!(rec.client, client_bucket("cn=learner-7"));
        assert_eq!(rec.latency, log2_bucket(12_000));
        assert_eq!(
            sink.with_pending(|m| m.len()),
            0,
            "the stitch entry is consumed"
        );
    }

    #[test]
    fn a_denied_request_yields_a_policy_record_and_a_denied_response_record() {
        let sink = BehaviourSink::default();
        sink.record_for(&ev(
            "c2",
            Plane::Kmip,
            EventPayload::KmipRequestReceived {
                op: "Create".into(),
                request_summary: "".into(),
                client_cn: None,
            },
        ));
        let deny = sink
            .record_for(&ev(
                "c2",
                Plane::Agility,
                EventPayload::PolicyDecided {
                    op: "Create".into(),
                    algorithm: Some("RSA".into()),
                    outcome: DecisionSummary::Deny {
                        reason: "no RSA".into(),
                        fired_rule_index: 3,
                    },
                    policy_fingerprint: "sha256:0".into(),
                },
            ))
            .expect("deny is its own record");
        assert_eq!(
            (deny.src, deny.op, deny.alg, deny.result),
            (SRC_POLICY, OP_POLICY_DENY, ALG_RSA, RESULT_POLICY_DENY)
        );
        assert_eq!(deny.client, 0, "no client identity on this request");
        let resp = sink
            .record_for(&ev(
                "c2",
                Plane::Kmip,
                EventPayload::KmipResponseSent {
                    op: "Create".into(),
                    result: KmipOpResult::OperationFailed {
                        reason: "PermissionDenied".into(),
                    },
                    latency_ms: 0,
                },
            ))
            .unwrap();
        assert_eq!(
            (resp.src, resp.op, resp.alg, resp.result),
            (
                SRC_KMIP_DATA,
                op_kmip("Create"),
                ALG_RSA,
                RESULT_POLICY_DENY
            )
        );
        assert_eq!(resp.latency, 0);
    }

    #[test]
    fn a_warned_request_marks_its_successful_response_as_warn() {
        let sink = BehaviourSink::default();
        let warn = sink
            .record_for(&ev(
                "c3",
                Plane::Agility,
                EventPayload::PolicyWarned {
                    rule_index: 1,
                    reason: "deprecated".into(),
                    policy: "p".into(),
                    policy_fingerprint: "sha256:0".into(),
                },
            ))
            .unwrap();
        assert_eq!(
            (warn.src, warn.op, warn.result),
            (SRC_POLICY, OP_POLICY_WARN, RESULT_WARN_REKEY)
        );
        let resp = sink
            .record_for(&ev(
                "c3",
                Plane::Kmip,
                EventPayload::KmipResponseSent {
                    op: "Encrypt".into(),
                    result: KmipOpResult::Success,
                    latency_ms: 1,
                },
            ))
            .unwrap();
        assert_eq!(resp.result, RESULT_WARN_REKEY);
    }

    #[test]
    fn an_intent_suffixed_op_label_still_resolves_to_the_kmip_operation() {
        let sink = BehaviourSink::default();
        let resp = sink
            .record_for(&ev(
                "c5",
                Plane::Kmip,
                EventPayload::KmipResponseSent {
                    op: "CreateKeyPair:Sign".into(),
                    result: KmipOpResult::Success,
                    latency_ms: 29,
                },
            ))
            .unwrap();
        assert_eq!(resp.op, op_kmip("CreateKeyPair"));
        assert_ne!(resp.op, 0);
    }

    #[test]
    fn failure_reasons_map_to_the_shared_result_classes() {
        let sink = BehaviourSink::default();
        for (reason, class) in [
            ("ItemNotFound", RESULT_CALLER_ERROR),
            ("AuthenticationNotSuccessful", RESULT_AUTH_FAIL),
            ("CryptographicFailure", RESULT_INTERNAL_ERROR),
            ("PermissionDenied", RESULT_POLICY_DENY),
        ] {
            let resp = sink
                .record_for(&ev(
                    reason,
                    Plane::Kmip,
                    EventPayload::KmipResponseSent {
                        op: "Get".into(),
                        result: KmipOpResult::OperationFailed {
                            reason: reason.into(),
                        },
                        latency_ms: 3,
                    },
                ))
                .unwrap();
            assert_eq!(resp.result, class, "{reason}");
        }
    }

    #[test]
    fn engine_level_and_lifecycle_events_are_not_records() {
        let sink = BehaviourSink::default();
        for payload in [
            EventPayload::Pkcs11Call {
                function: "C_Sign".into(),
                mechanism: Some("CKM_ML_DSA".into()),
                slot: Some(0),
                session: Some(1),
                rv: 0,
                rv_name: "CKR_OK".into(),
                latency_ms: 1,
            },
            EventPayload::Pkcs11SessionLifecycle {
                action: "open".into(),
                slot: 0,
                session: 1,
            },
            EventPayload::KmipObjectStateChanged {
                uid: "u".into(),
                from_state: "PreActive".into(),
                to_state: "Active".into(),
                reason: "Activate".into(),
            },
        ] {
            assert!(sink.record_for(&ev("c4", Plane::Pkcs11, payload)).is_none());
        }
    }

    #[test]
    fn the_stitch_table_is_bounded() {
        let sink = BehaviourSink::default();
        for i in 0..PENDING_CAP + 10 {
            sink.record_for(&ev(
                &format!("never-answered-{i}"),
                Plane::Kmip,
                EventPayload::KmipRequestReceived {
                    op: "Get".into(),
                    request_summary: "".into(),
                    client_cn: None,
                },
            ));
        }
        assert!(sink.with_pending(|m| m.len()) <= PENDING_CAP);
    }

    #[test]
    fn from_env_is_none_unless_a_ring_is_configured() {
        // This test binary never sets PQC_BEHAVIOUR_RING, so the process-wide
        // ring is absent and the sink must decline to exist.
        assert!(std::env::var_os(softhsmrustv3::behaviour::ENV_VAR).is_none());
        assert!(BehaviourSink::from_env().is_none());
    }
}
