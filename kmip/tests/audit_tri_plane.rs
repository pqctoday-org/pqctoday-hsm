//! Tri-plane correlated audit trace — demonstrates the Hub-UI view of one
//! request flowing through Plane 1 (agility engine) → Plane 2 (KMIP) →
//! Plane 3 (PKCS#11). Plane 2 + Plane 3 emissions are STUBBED here; the
//! wire format is what this test commits. Stub `Pkcs11Call` function
//! names follow the K15 convention the op handlers emit: the actual
//! native entry point (`native::sign`, `native::generate_ml_dsa_keypair`,
//! …) recorded AFTER the call with its real rv.
//!
//! Each plane writes to the same sink. The Hub UI reads from that sink
//! (in production: via a Phase-7 HTTP `GET /audit/tail` endpoint; in this
//! test: directly via `RingSink::filter_correlation_id`).

use std::collections::HashMap;
use std::sync::Arc;
use time::OffsetDateTime;

use pqctoday_kmip::auditlog::{
    AuditEvent, AuditSink, CompositeSink, EventPayload, JsonlSink, KmipOpResult, Plane, RingSink,
};
use pqctoday_kmip::policy::{load_from_str, Decision, Engine, PolicyRequest};

const PQC_POLICY: &str = r#"
schema_version: 1
metadata:
  name: tri-plane-demo
  description: PQC default + rekey on existing classical
  authority: test
  effective: "always"
rules:
  - type: algorithm_default
    ops: ["CreateKeyPair:Sign"]
    default_algorithm: ML-DSA-87
    reason: "PQC signing default"
  - type: algorithm_substitution
    ops: [Sign]
    from: ECDSA-P256
    to: ML-DSA-87
    reason: "Rekey classical signing key"
"#;

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_780_000_000).unwrap()
}

/// Production wiring pattern: hold `Arc<RingSink>` for queries alongside
/// `Arc<dyn AuditSink>` for emitter handoff — same allocation.
fn build_sink_pair() -> (Arc<RingSink>, Arc<dyn AuditSink>) {
    let ring = Arc::new(RingSink::new(64));
    let as_sink: Arc<dyn AuditSink> = ring.clone();
    (ring, as_sink)
}

// ── §1: all three planes fan into one sink, UI queries by correlation_id ────

#[test]
fn one_request_three_planes_one_correlation_id() {
    let (ring, sink) = build_sink_pair();
    let engine = Engine::with_global_sink(sink.clone());
    engine
        .replace_all(load_from_str(PQC_POLICY, std::path::Path::new("<test>")).unwrap())
        .unwrap();

    let correlation_id = "req-abc-123";
    let attrs = HashMap::new();

    // ── Plane 1 — agility engine ─────────────────────────────────────────
    let mut req = PolicyRequest::minimal("Sign", Some("ECDSA-P256"), now(), correlation_id, &attrs);
    req.current_object_algorithm = Some("ECDSA-P256");
    req.target_uid = Some("urn:pqctoday:obj:legacy-ecdsa");
    let decision = engine.evaluate(&req);
    assert!(matches!(decision, Decision::RekeyAndProceed { .. }));

    // ── Plane 2 — KMIP dispatcher (STUBBED — Phase 5 emits) ─────────────
    sink.emit(AuditEvent::at(
        now(),
        Plane::Kmip,
        correlation_id,
        EventPayload::KmipRequestReceived {
            op: "Sign".into(),
            request_summary: "Sign { uid: urn:pqctoday:obj:legacy-ecdsa }".into(),
            client_cn: Some("CN=demo-client".into()),
        },
    ));
    sink.emit(AuditEvent::at(
        now(),
        Plane::Kmip,
        correlation_id,
        EventPayload::KmipObjectStateChanged {
            uid: "urn:pqctoday:obj:legacy-ecdsa".into(),
            from_state: "Active".into(),
            to_state: "Deprecated".into(),
            reason: "rekey to ML-DSA-87 per Plane-1 policy".into(),
        },
    ));

    // ── Plane 3 — PKCS#11 bridge (STUBBED — Phase 5 emits) ──────────────
    sink.emit(AuditEvent::at(
        now(),
        Plane::Pkcs11,
        correlation_id,
        EventPayload::Pkcs11Call {
            function: "native::generate_ml_dsa_keypair".into(),
            mechanism: Some("CKM_ML_DSA_KEY_PAIR_GEN".into()),
            slot: Some(0),
            session: Some(42),
            rv: 0,
            rv_name: "CKR_OK".into(),
            latency_ms: 12,
        },
    ));
    sink.emit(AuditEvent::at(
        now(),
        Plane::Pkcs11,
        correlation_id,
        EventPayload::Pkcs11Call {
            function: "native::sign".into(),
            mechanism: Some("CKM_ML_DSA".into()),
            slot: Some(0),
            session: Some(42),
            rv: 0,
            rv_name: "CKR_OK".into(),
            latency_ms: 8,
        },
    ));

    // ── Plane 2 — KMIP response (STUBBED) ───────────────────────────────
    sink.emit(AuditEvent::at(
        now(),
        Plane::Kmip,
        correlation_id,
        EventPayload::KmipResponseSent {
            op: "Sign".into(),
            result: KmipOpResult::Success,
            latency_ms: 24,
        },
    ));

    // ── Hub UI query: give me everything for this correlation_id ────────
    let trace = ring.filter_correlation_id(correlation_id);

    // Expected: 2 P1 (Decided + RekeyPlanned) + 3 P2 (Req + StateChange + Resp)
    //         + 2 P3 (two Pkcs11Call) = 7
    assert_eq!(trace.len(), 7, "should have 7 correlated events");

    let planes: Vec<Plane> = trace.iter().map(|e| e.plane).collect();
    assert!(planes.contains(&Plane::Agility));
    assert!(planes.contains(&Plane::Kmip));
    assert!(planes.contains(&Plane::Pkcs11));

    let p1: Vec<&AuditEvent> = trace.iter().filter(|e| e.plane == Plane::Agility).collect();
    assert_eq!(p1.len(), 2);
    assert!(matches!(p1[0].event, EventPayload::PolicyDecided { .. }));
    assert!(matches!(p1[1].event, EventPayload::RekeyPlanned { .. }));
}

// ── §2: composite sink fans to ring + JSONL (durable forensic record) ──────

#[test]
fn composite_sink_writes_ring_plus_jsonl() {
    let ring = Arc::new(RingSink::new(64));
    let path = std::env::temp_dir().join(format!(
        "pqctoday-tri-plane-{}.jsonl",
        uuid::Uuid::new_v4()
    ));
    let jsonl = Arc::new(JsonlSink::open(&path).unwrap());
    let composite: Arc<dyn AuditSink> = Arc::new(CompositeSink::new(vec![
        ring.clone(),
        jsonl.clone(),
    ]));

    let engine = Engine::with_global_sink(composite);
    engine
        .replace_all(load_from_str(PQC_POLICY, std::path::Path::new("<test>")).unwrap())
        .unwrap();

    let attrs = HashMap::new();
    let req = PolicyRequest::minimal("CreateKeyPair:Sign", None, now(), "corr-2", &attrs);
    assert!(engine.evaluate(&req).is_allow());

    drop(jsonl); // release file handle
    let ring_events = ring.snapshot();
    assert!(ring_events.len() >= 2); // activation + decision
    let jsonl_text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(jsonl_text.lines().count(), ring_events.len());
    for line in jsonl_text.lines() {
        let _back: AuditEvent = serde_json::from_str(line).expect("each line valid JSON");
    }
    let _ = std::fs::remove_file(&path);
}

// ── §3: per-plane filtering for the Hub UI's per-plane panels ──────────────

#[test]
fn hub_ui_can_filter_per_plane() {
    let (ring, sink) = build_sink_pair();
    let engine = Engine::with_global_sink(sink.clone());
    engine
        .replace_all(load_from_str(PQC_POLICY, std::path::Path::new("<test>")).unwrap())
        .unwrap();

    let attrs = HashMap::new();
    for i in 0..3 {
        let corr = format!("corr-{i}");
        let req = PolicyRequest::minimal(
            "CreateKeyPair:Sign",
            None,
            now(),
            &corr,
            &attrs,
        );
        let _ = engine.evaluate(&req);
        sink.emit(AuditEvent::at(
            now(),
            Plane::Pkcs11,
            format!("corr-{i}"),
            EventPayload::Pkcs11Call {
                function: "native::generate_ml_dsa_keypair".into(),
                mechanism: Some("CKM_ML_DSA_KEY_PAIR_GEN".into()),
                slot: Some(0),
                session: Some(1),
                rv: 0,
                rv_name: "CKR_OK".into(),
                latency_ms: 10,
            },
        ));
    }

    // Plane-1: 1 activation + 3 decisions = 4 events.
    assert_eq!(ring.filter_plane(Plane::Agility).len(), 4);
    // Plane-3: 3 events.
    assert_eq!(ring.filter_plane(Plane::Pkcs11).len(), 3);
    // Plane-2: nothing emitted in this test.
    assert_eq!(ring.filter_plane(Plane::Kmip).len(), 0);
}

// ── §4: events serialise to stable JSON (wire format committed) ────────────

#[test]
fn event_payloads_serialise_to_committed_wire_format() {
    // Plane-1 PolicyDecided
    let p1 = AuditEvent::at(
        now(),
        Plane::Agility,
        "corr",
        EventPayload::PolicyDecided {
            op: "Sign".into(),
            algorithm: Some("ML-DSA-87".into()),
            outcome: pqctoday_kmip::auditlog::DecisionSummary::Allow {
                algorithm_override: Some("ML-DSA-87".into()),
                substituted_by_rule: Some(2),
                cp_override: None,
            },
            policy_fingerprint: "sha256:abc".into(),
        },
    );
    let json = serde_json::to_string(&p1).unwrap();
    assert!(json.contains("\"plane\":\"p1\""));
    assert!(json.contains("\"type\":\"PolicyDecided\""));
    assert!(json.contains("\"type\":\"Allow\""));

    // Plane-3 Pkcs11Call
    let p3 = AuditEvent::at(
        now(),
        Plane::Pkcs11,
        "corr",
        EventPayload::Pkcs11Call {
            function: "native::sign".into(),
            mechanism: Some("CKM_ML_DSA".into()),
            slot: Some(0),
            session: Some(42),
            rv: 0,
            rv_name: "CKR_OK".into(),
            latency_ms: 8,
        },
    );
    let json = serde_json::to_string(&p3).unwrap();
    assert!(json.contains("\"plane\":\"p3\""));
    assert!(json.contains("\"type\":\"Pkcs11Call\""));
    assert!(json.contains("\"function\":\"native::sign\""));
}
