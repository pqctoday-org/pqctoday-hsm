//! Behaviour ring, end to end through the real dispatcher with the real
//! engine: the P0 exit check of the appliance's behaviour-monitor plan,
//! run in-process instead of on the emulator.
//!
//! Three things have to line up for one request:
//!
//! 1. `audit.jsonl` (the `JsonlSink` leg) shows a **non-zero `latency_ms`**
//!    on `KmipResponseSent` — the figure was hard-coded 0 before this branch.
//! 2. The **behaviour ring** holds one `SRC_KMIP_DATA` record per response,
//!    and the per-operation counts decode to exactly what
//!    `cacp_kmip_requests_total{operation,status}` reports.
//! 3. The engine's own records (the KMIP bridge calls `softhsmrustv3::native`
//!    in this process) sit in the same ring, and the `PQCEV` evidence log
//!    carries `dur=` on them.
//!
//! One test in its own binary: the ring, the evidence log and the metrics
//! registry are all process-wide once-only state.

use std::collections::BTreeMap;
use std::sync::Arc;

use pqctoday_kmip::auditlog::{
    AuditEvent, AuditSink, BehaviourSink, CompositeSink, EventPayload, JsonlSink, RingSink,
};
use pqctoday_kmip::dispatcher::{dispatch, one_off_request};
use pqctoday_kmip::kmip30::{
    ActivateRequest, Attribute, CreateKeyPairRequest, GetRequest, KmipAlgorithm, QueryFunction,
    QueryRequest, RequestPayload, ResponsePayload, ResultStatus, SignRequest, UsageMask,
};
use pqctoday_kmip::ops::{Deps, DepsConfig};
use pqctoday_kmip::policy::{Engine, load_from_str};
use pqctoday_kmip::store::MemoryStore;
use softhsmrustv3::behaviour::{self, *};

const PERMISSIVE_POLICY: &str = r#"
schema_version: 1
metadata: { name: t, description: t, authority: t, effective: always }
rules: []
"#;

#[test]
fn dispatcher_latency_ring_and_metrics_agree() {
    let dir = std::env::temp_dir().join(format!("pqc-behaviour-kmip-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ring_path = dir.join("behaviour.ring");
    let audit_path = dir.join("audit.jsonl");
    let oplog_path = dir.join("hsm-ops.log");
    // SAFETY: single-threaded, before any engine or sink code has run.
    unsafe {
        std::env::set_var(behaviour::ENV_VAR, &ring_path);
        std::env::remove_var(behaviour::SRC_ENV_VAR);
        std::env::set_var(softhsmrustv3::oplog::ENV_VAR, &oplog_path);
    }
    pqctoday_kmip::metrics::init();

    // ── Real engine + the production sink shape ──────────────────────────
    use softhsmrustv3::native::session;
    let _ = session::finalize();
    session::init().expect("engine init");
    let engine_session = session::bootstrap_default_token(0, "so-pin", "user-pin", "behaviour-e2e")
        .expect("engine session");
    let mem = Arc::new(RingSink::new(256));
    let legs: Vec<Arc<dyn AuditSink>> = vec![
        mem.clone(),
        Arc::new(JsonlSink::open(&audit_path).expect("audit.jsonl")),
        Arc::new(BehaviourSink::from_env().expect("PQC_BEHAVIOUR_RING is set and mappable")),
    ];
    let sink: Arc<dyn AuditSink> = Arc::new(CompositeSink::new(legs));
    let policy_engine = Engine::with_global_sink(sink.clone());
    policy_engine
        .replace_all(load_from_str(PERMISSIVE_POLICY, std::path::Path::new("<e2e>")).unwrap())
        .unwrap();
    let deps = Deps::new(
        policy_engine,
        Arc::new(MemoryStore::new()),
        sink,
        DepsConfig::default(),
    )
    .with_engine_session(engine_session);

    // ── Traffic: 1 CreateKeyPair, 1 Activate, 3 Sign, 2 Query, 1 failing Get ─
    let resp = dispatch(
        &deps,
        one_off_request(RequestPayload::CreateKeyPair(CreateKeyPairRequest {
            common_attributes: vec![Attribute::CryptographicAlgorithm(KmipAlgorithm::MlDsa65)],
            private_key_attributes: vec![Attribute::CryptographicUsageMask(UsageMask::SIGN)],
            public_key_attributes: vec![Attribute::CryptographicUsageMask(UsageMask::VERIFY)],
            seed: None,
        })),
    );
    let item = &resp.batch_items[0];
    assert_eq!(
        item.result_status,
        ResultStatus::Success,
        "{:?}",
        item.result_reason
    );
    let priv_uid = match item.payload.as_ref().unwrap() {
        ResponsePayload::CreateKeyPair(r) => r.private_key_uid.clone(),
        other => panic!("{other:?}"),
    };
    let resp = dispatch(
        &deps,
        one_off_request(RequestPayload::Activate(ActivateRequest {
            uid: priv_uid.clone(),
        })),
    );
    assert_eq!(resp.batch_items[0].result_status, ResultStatus::Success);
    for i in 0..3u8 {
        let resp = dispatch(
            &deps,
            one_off_request(RequestPayload::Sign(SignRequest {
                uid: priv_uid.clone(),
                data: vec![i; 64],
                cryptographic_parameters: None,
                init_indicator: None,
                final_indicator: None,
                correlation_value: None,
            })),
        );
        assert_eq!(
            resp.batch_items[0].result_status,
            ResultStatus::Success,
            "sign {i}"
        );
    }
    for _ in 0..2 {
        let resp = dispatch(
            &deps,
            one_off_request(RequestPayload::Query(QueryRequest {
                functions: vec![QueryFunction::QueryOperations],
            })),
        );
        assert_eq!(resp.batch_items[0].result_status, ResultStatus::Success);
    }
    let resp = dispatch(
        &deps,
        one_off_request(RequestPayload::Get(GetRequest {
            uid: "no-such-object".into(),
            key_format_type: None,
            key_wrapping_specification: None,
        })),
    );
    assert_eq!(
        resp.batch_items[0].result_status,
        ResultStatus::OperationFailed
    );

    // ── 1. audit.jsonl carries real latency ───────────────────────────────
    let jsonl = std::fs::read_to_string(&audit_path).expect("audit.jsonl written");
    let responses: Vec<AuditEvent> = jsonl
        .lines()
        .map(|l| serde_json::from_str::<AuditEvent>(l).expect("audit line parses"))
        .filter(|e| matches!(e.event, EventPayload::KmipResponseSent { .. }))
        .collect();
    assert_eq!(responses.len(), 8, "one KmipResponseSent per request");
    let latency = |e: &AuditEvent| match &e.event {
        EventPayload::KmipResponseSent { op, latency_ms, .. } => (op.clone(), *latency_ms),
        _ => unreachable!(),
    };
    // The handler labels the audit op with its intent ("CreateKeyPair:Sign").
    let keygen_ms = responses
        .iter()
        .map(latency)
        .find(|(op, _)| op.starts_with("CreateKeyPair"))
        .unwrap()
        .1;
    assert!(
        keygen_ms > 0,
        "ML-DSA-65 keygen through the dispatcher must not report 0 ms"
    );
    let sign_ms: Vec<u32> = responses
        .iter()
        .map(latency)
        .filter(|(op, _)| op == "Sign")
        .map(|(_, ms)| ms)
        .collect();
    assert_eq!(sign_ms.len(), 3);
    // A debug-build ML-DSA-65 signature takes well over a millisecond; what
    // matters is that the figure is measured, not that it is small.
    assert!(
        sign_ms.iter().any(|&ms| ms > 0),
        "at least one Sign must show a measured latency: {sign_ms:?}"
    );
    // The in-memory ring saw the same figures (it is the same event).
    let mem_latencies: Vec<u32> = mem
        .snapshot()
        .into_iter()
        .filter_map(|e| match e.event {
            EventPayload::KmipResponseSent { op, latency_ms, .. }
                if op.starts_with("CreateKeyPair") =>
            {
                Some(latency_ms)
            }
            _ => None,
        })
        .collect();
    assert_eq!(mem_latencies, vec![keygen_ms]);

    // ── 2. ring KMIP records == metrics counters, per operation ───────────
    let snap = behaviour::read_all(&ring_path).expect("ring readable");
    assert_eq!(snap.lost, 0);
    let mut ring_counts: BTreeMap<(u8, bool), u64> = BTreeMap::new();
    for (_, r) in snap.records.iter().filter(|(_, r)| r.src == SRC_KMIP_DATA) {
        *ring_counts
            .entry((r.op, r.result == RESULT_OK))
            .or_default() += 1;
    }
    let mut metric_counts: BTreeMap<(u8, bool), u64> = BTreeMap::new();
    for line in pqctoday_kmip::metrics::render()
        .lines()
        .filter(|l| l.starts_with("cacp_kmip_requests_total{"))
    {
        let labels = line.split('{').nth(1).unwrap().split('}').next().unwrap();
        let mut op = "";
        let mut success = false;
        for kv in labels.split(',') {
            let (k, v) = kv.split_once('=').unwrap();
            let v = v.trim_matches('"');
            match k {
                "operation" => op = v,
                "status" => success = v == "success",
                _ => {}
            }
        }
        let n: f64 = line.rsplit(' ').next().unwrap().parse().unwrap();
        *metric_counts.entry((op_kmip(op), success)).or_default() += n as u64;
    }
    assert_eq!(
        ring_counts, metric_counts,
        "ring (left) vs cacp_kmip_requests_total (right)"
    );
    assert_eq!(ring_counts.get(&(op_kmip("Sign"), true)), Some(&3));
    assert_eq!(ring_counts.get(&(op_kmip("Query"), true)), Some(&2));
    assert_eq!(ring_counts.get(&(op_kmip("Get"), false)), Some(&1));
    assert_eq!(ring_counts.values().sum::<u64>(), 8);
    // Stitched fields: the Sign records know their algorithm and their latency.
    let signs: Vec<&Record> = snap
        .records
        .iter()
        .map(|(_, r)| r)
        .filter(|r| r.src == SRC_KMIP_DATA && r.op == op_kmip("Sign"))
        .collect();
    assert!(
        signs.iter().all(|r| r.alg == ALG_ML_DSA_65),
        "PolicyDecided's algorithm reaches the record"
    );
    assert!(signs.iter().any(|r| r.latency > 0));
    let get_fail = snap
        .records
        .iter()
        .map(|(_, r)| r)
        .find(|r| r.src == SRC_KMIP_DATA && r.op == op_kmip("Get"))
        .unwrap();
    assert_eq!(
        get_fail.result, RESULT_CALLER_ERROR,
        "ItemNotFound is a caller error"
    );

    // ── 3. the engine's own records share the ring, with dur= in PQCEV ────
    let engine: Vec<&Record> = snap
        .records
        .iter()
        .map(|(_, r)| r)
        .filter(|r| r.src == SRC_P11_LOCAL)
        .collect();
    assert!(
        !engine.is_empty(),
        "the KMIP bridge's native calls must land in the same ring"
    );
    assert!(
        engine
            .iter()
            .any(|r| r.op == OP_PKCS11_C_GENERATEKEYPAIR && r.alg == ALG_ML_DSA_65)
    );
    assert_eq!(
        engine.iter().filter(|r| r.op == OP_PKCS11_C_SIGN).count(),
        3
    );
    let oplog = std::fs::read_to_string(&oplog_path).expect("PQCEV log written");
    let sign_lines: Vec<&str> = oplog.lines().filter(|l| l.contains("op=C_Sign ")).collect();
    assert_eq!(sign_lines.len(), 3);
    assert!(
        sign_lines
            .iter()
            .all(|l| l.contains(" dur=") && !l.contains(" dur=0")),
        "{sign_lines:?}"
    );
    // Nothing else claims to be a producer here: no auth, tls or admin record.
    assert!(
        snap.records
            .iter()
            .all(|(_, r)| matches!(r.src, SRC_KMIP_DATA | SRC_P11_LOCAL | SRC_POLICY))
    );
}
