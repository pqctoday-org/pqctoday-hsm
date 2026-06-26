//! D1 — Prometheus metrics for the CACP management plane.
//!
//! ## Metric families
//!
//! | Name | Type | Labels | Description |
//! |------|------|--------|-------------|
//! | `cacp_build_info` | gauge=1 | version, git_sha | Build provenance |
//! | `cacp_kmip_requests_total` | counter | operation, status | KMIP batch items |
//! | `cacp_tls_handshakes_total` | counter | listener | TLS handshakes (kmip, admin) |
//! | `cacp_admin_requests_total` | counter | method, route, status | Admin API requests |
//!
//! ## Usage
//!
//! Call `metrics::init()` once at binary startup before spawning any tasks.
//! Then call the `record_*` helpers from the hot paths. All helpers are
//! no-ops if `init()` was never called (safe in tests).
//!
//! The scrape endpoint is served by [`serve_metrics_forever`] on plain HTTP
//! (no TLS — scraper should be on the same pod/network-namespace or behind a
//! network policy). Standard port: 9095.

use std::net::SocketAddr;
use std::sync::OnceLock;

use prometheus::{CounterVec, GaugeVec, Opts, Registry, TextEncoder, Encoder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

struct Metrics {
    registry: Registry,
    build_info: GaugeVec,
    kmip_requests: CounterVec,
    tls_handshakes: CounterVec,
    admin_requests: CounterVec,
}

static METRICS: OnceLock<Metrics> = OnceLock::new();

/// Initialise the metrics registry. Must be called once at binary startup
/// before spawning connection tasks. Subsequent calls are no-ops.
pub fn init() {
    let _ = METRICS.get_or_init(|| {
        let registry = Registry::new();

        let build_info = GaugeVec::new(
            Opts::new("cacp_build_info", "Build provenance (always 1)"),
            &["version", "git_sha"],
        )
        .expect("build_info gauge");
        registry.register(Box::new(build_info.clone())).expect("register build_info");
        build_info
            .with_label_values(&[
                env!("CARGO_PKG_VERSION"),
                option_env!("GIT_SHA").unwrap_or("unknown"),
            ])
            .set(1.0);

        let kmip_requests = CounterVec::new(
            Opts::new("cacp_kmip_requests_total", "KMIP batch item requests processed"),
            &["operation", "status"],
        )
        .expect("kmip_requests counter");
        registry.register(Box::new(kmip_requests.clone())).expect("register kmip_requests");

        let tls_handshakes = CounterVec::new(
            Opts::new("cacp_tls_handshakes_total", "Successful TLS handshakes"),
            &["listener"],
        )
        .expect("tls_handshakes counter");
        registry.register(Box::new(tls_handshakes.clone())).expect("register tls_handshakes");

        let admin_requests = CounterVec::new(
            Opts::new("cacp_admin_requests_total", "Admin API (cryptopolicy-manager) requests"),
            &["method", "route", "status"],
        )
        .expect("admin_requests counter");
        registry.register(Box::new(admin_requests.clone())).expect("register admin_requests");

        Metrics { registry, build_info, kmip_requests, tls_handshakes, admin_requests }
    });
}

// ── Increment helpers ─────────────────────────────────────────────────────────

/// Increment `cacp_kmip_requests_total{operation, status}`.
/// `status` is `"success"` or `"error"`.
pub fn record_kmip_request(operation: &'static str, success: bool) {
    if let Some(m) = METRICS.get() {
        m.kmip_requests
            .with_label_values(&[operation, if success { "success" } else { "error" }])
            .inc();
    }
}

/// Increment `cacp_tls_handshakes_total{listener}`.
/// `listener` should be `"kmip"` or `"admin"`.
pub fn record_tls_handshake(listener: &'static str) {
    if let Some(m) = METRICS.get() {
        m.tls_handshakes.with_label_values(&[listener]).inc();
    }
}

/// Increment `cacp_admin_requests_total{method, route, status}`.
/// `route` must be a stable pattern (e.g. `"/api/v1/policies/{name}"`),
/// never a raw path — unbounded cardinality breaks Prometheus.
pub fn record_admin_request(method: &str, route: &'static str, status: u16) {
    if let Some(m) = METRICS.get() {
        m.admin_requests
            .with_label_values(&[method, route, &status.to_string()])
            .inc();
    }
}

// ── Scrape endpoint ───────────────────────────────────────────────────────────

fn render() -> String {
    let Some(m) = METRICS.get() else { return String::new() };
    let mut buf = Vec::new();
    TextEncoder::new().encode(&m.registry.gather(), &mut buf).ok();
    String::from_utf8(buf).unwrap_or_default()
}

/// Serve `GET /metrics` forever on plain HTTP (no TLS).
/// Prometheus standard port for CACP: 9095.
/// Any request is served with the full Prometheus text format 0.0.4;
/// the path and method are not validated (single-endpoint scraper).
pub async fn serve_metrics_forever(addr: SocketAddr) {
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("metrics listener failed to bind {addr}: {e}");
            return;
        }
    };
    tracing::info!("metrics scrape endpoint on http://{addr}/metrics (plain HTTP)");
    loop {
        let (mut stream, _peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("metrics accept error: {e}");
                continue;
            }
        };
        tokio::spawn(async move {
            // Drain the request headers (we don't validate method/path).
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
