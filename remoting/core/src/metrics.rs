//! Prometheus metrics for PKCS#11 remoting (gRPC + REST).
//!
//! docs/remediation-plan-auth-visibility-evidence-log-09102026.md, Gap 1/Q3
//! (decided: build now, not deferred to the later general remoting-
//! performance work). Before this module, `remoting/` had **no** metrics
//! infrastructure at all — confirmed by grep across every crate under
//! `remoting/`. This is deliberately narrow: one counter, for
//! authentication-attempt visibility, not the fuller latency-histogram/
//! connection-gauge work that later effort still owns. That work extends
//! THIS registry rather than building a second, competing one.
//!
//! Shared by both `pqc-grpc-pkcs11` and `pqc-rest-pkcs11` (both already
//! depend on this crate) rather than duplicated per binary, and each binary
//! instantiates and serves its own registry on its own port — mirrors
//! `pqctoday-kmip`'s `metrics.rs` pattern (`kmip/src/metrics.rs`) closely
//! enough on purpose that a reader of one recognises the other.
//!
//! ## Usage
//!
//! Call [`init`] once at binary startup, then [`record_auth_failure`] from
//! the PIN-check call site in `service.rs`/`routes.rs`. Serve
//! [`serve_metrics_forever`] on a port the operator configures
//! (`--metrics-listen`, appliance-side port TBD — see the remediation
//! plan's sequencing item 5, `pqctoday-cacp` coordination).

use std::net::SocketAddr;
use std::sync::OnceLock;

use prometheus::{CounterVec, Encoder, Opts, Registry, TextEncoder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

struct Metrics {
    registry: Registry,
    auth_failures: CounterVec,
}

static METRICS: OnceLock<Metrics> = OnceLock::new();

/// Initialise the metrics registry. Must be called once at binary startup
/// before serving requests. Subsequent calls are no-ops.
pub fn init() {
    let _ = METRICS.get_or_init(|| {
        let registry = Registry::new();
        // `reason` is a short fixed token (currently just "pin-incorrect" —
        // see CkError::class() in this crate's error.rs, the "for
        // logging/metrics" hook this counter finally uses), never free
        // text: unbounded cardinality here would be the same Prometheus
        // mistake pqctoday-kmip's own record_admin_request doc already
        // warns against for its `route` label.
        let auth_failures = CounterVec::new(
            Opts::new("cacp_auth_failures_total", "Failed authentication attempts"),
            &["surface", "reason"],
        )
        .expect("auth_failures counter");
        registry.register(Box::new(auth_failures.clone())).expect("register auth_failures");
        Metrics { registry, auth_failures }
    });
}

/// Increment `cacp_auth_failures_total{surface="remoting-pin", reason}` AND
/// emit a `PQCAUTH` record via `softhsmrustv3::authlog` — same
/// one-call-covers-both pattern as `pqctoday-kmip`'s own
/// `record_auth_failure` (`kmip/src/metrics.rs`), for the same reason: a
/// call site should not have to remember to do both separately.
///
/// `reason` should be a short fixed token (e.g. `"pin-incorrect"`).
/// `peer`, when known, is `ip:port`.
pub fn record_auth_failure(reason: &str, peer: Option<&str>) {
    if let Some(m) = METRICS.get() {
        m.auth_failures.with_label_values(&["remoting-pin", reason]).inc();
    }
    softhsmrustv3::authlog::emit("remoting-pin", reason, peer);
}

fn render() -> String {
    let Some(m) = METRICS.get() else { return String::new() };
    let mut buf = Vec::new();
    TextEncoder::new().encode(&m.registry.gather(), &mut buf).ok();
    String::from_utf8(buf).unwrap_or_default()
}

/// Serve `GET /metrics` forever on plain HTTP (no TLS) — same shape as
/// `pqctoday-kmip::metrics::serve_metrics_forever`. Path/method are not
/// validated (single-endpoint scraper).
pub async fn serve_metrics_forever(addr: SocketAddr) {
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("metrics listener failed to bind {addr}: {e}");
            return;
        }
    };
    loop {
        let (mut stream, _peer) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => continue,
        };
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;
            let body = render();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body,
            );
            let _ = stream.write_all(resp.as_bytes()).await;
        });
    }
}
