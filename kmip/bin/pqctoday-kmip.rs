//! `pqctoday-kmip` — KMIP 3.0 server binary.
//!
//! Phase 7 entry point. Wires:
//!
//! - **Plane 1** — `policy::Engine` loaded from `--policy-dir` + a starting
//!   policy (resumed from the `.active` marker if present, otherwise from
//!   `--policy <name>`).
//! - **Plane 2** — `store::SqliteStore` at `--store <path>` (durable) or
//!   `--store-memory` (sandbox volatile).
//! - **Plane 3** — `softhsmrustv3` bridge (initialised lazily by the
//!   Phase-4 `Session` wrapper).
//! - **All planes** — `auditlog::CompositeSink(RingSink, JsonlSink)` at
//!   `--audit-log <path>`; `RingSink` only when `--audit-log` is omitted.
//! - **Network** — TLS listener on `--listen <addr>`. Cert from
//!   `--tls-cert / --tls-key`, or auto-generated self-signed for sandbox.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;

use pqctoday_kmip::auditlog::{AuditSink, CompositeSink, JsonlSink, RingSink};
use pqctoday_kmip::ops::{Deps, DepsConfig};
use pqctoday_kmip::policy::{load_from_str, Engine, PolicyStore};
use pqctoday_kmip::server::{serve, tls_from_pem, tls_self_signed};
use pqctoday_kmip::store::{KeyStore, MemoryStore, SqliteStore};

const PERMISSIVE_FALLBACK: &str = r#"
schema_version: 1
metadata: { name: built-in-permissive, description: "Fallback when no --policy is supplied", authority: pqctoday-kmip, effective: always }
rules: []
"#;

#[derive(Parser, Debug)]
#[command(name = "pqctoday-kmip", version, about = "KMIP 3.0 server with Plane-1 crypto-agility engine")]
struct Cli {
    /// Listen address, e.g. `127.0.0.1:5696` (KMIP IANA port).
    #[arg(long, default_value = "127.0.0.1:5696")]
    listen: SocketAddr,

    /// Directory containing `policies/*.yaml` files. Empty = use built-in permissive fallback.
    #[arg(long)]
    policy_dir: Option<PathBuf>,

    /// Activate this policy by name on startup (overrides the `.active` marker).
    #[arg(long)]
    policy: Option<String>,

    /// SQLite store path. If omitted, defaults to `--store-memory` (volatile).
    #[arg(long)]
    store: Option<PathBuf>,

    /// Use the volatile in-memory store (sandbox / dev).
    #[arg(long, conflicts_with = "store")]
    store_memory: bool,

    /// Append-only JSONL audit log. Combined with the in-memory ring via CompositeSink.
    #[arg(long)]
    audit_log: Option<PathBuf>,

    /// Server cert (PEM). If omitted with `--tls-key`, auto-generates self-signed for sandbox.
    #[arg(long, requires = "tls_key")]
    tls_cert: Option<PathBuf>,

    /// Server private key (PEM). Required with `--tls-cert`.
    #[arg(long, requires = "tls_cert")]
    tls_key: Option<PathBuf>,

    /// PKCS#11 slot (single-slot v0.1).
    #[arg(long, default_value_t = 0)]
    slot: u32,

    /// PKCS#11 user PIN.
    #[arg(long, default_value = "1234")]
    pin: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    // ── Audit sink ──────────────────────────────────────────────────────
    let ring = Arc::new(RingSink::new(16_384));
    let sink: Arc<dyn AuditSink> = if let Some(path) = cli.audit_log.as_ref() {
        let jsonl = Arc::new(JsonlSink::open(path)?);
        Arc::new(CompositeSink::new(vec![ring.clone(), jsonl]))
    } else {
        ring.clone()
    };

    // ── Engine + initial policy ─────────────────────────────────────────
    let engine = Engine::with_global_sink(sink.clone());
    if let Some(dir) = cli.policy_dir.as_ref() {
        let store = PolicyStore::new(dir);
        if let Some(name) = cli.policy.as_ref() {
            store.activate_with_engine(name, &engine)?;
            tracing::info!("activated policy {name:?} from {dir:?}");
        } else {
            match store.resume_active(&engine)? {
                Some(marker) => tracing::info!("resumed policy {:?} (fp={})", marker.name, marker.fingerprint),
                None => {
                    tracing::warn!("no --policy and no .active marker in {dir:?} — loading built-in permissive");
                    engine.activate(load_from_str(PERMISSIVE_FALLBACK, std::path::Path::new("<built-in>"))?)?;
                }
            }
        }
    } else {
        tracing::warn!("no --policy-dir — loading built-in permissive policy");
        engine.activate(load_from_str(PERMISSIVE_FALLBACK, std::path::Path::new("<built-in>"))?)?;
    }

    // ── Object store ────────────────────────────────────────────────────
    let store: Arc<dyn KeyStore> = if cli.store_memory || cli.store.is_none() {
        tracing::info!("using volatile MemoryStore (no --store path; restart loses KMIP metadata)");
        Arc::new(MemoryStore::new())
    } else {
        let path = cli.store.unwrap();
        tracing::info!("using durable SqliteStore at {path:?}");
        Arc::new(SqliteStore::open(&path).map_err(|e| anyhow::anyhow!("sqlite open: {e}"))?)
    };

    // ── Deps bundle ─────────────────────────────────────────────────────
    let config = DepsConfig {
        pkcs11_slot: cli.slot,
        pkcs11_pin: cli.pin,
        vendor_identification: "pqctoday-hsm".into(),
        server_version: env!("CARGO_PKG_VERSION").into(),
    };
    let deps = Arc::new(Deps::new(engine, store, sink, config));

    // ── TLS config ──────────────────────────────────────────────────────
    let tls_cfg = match (cli.tls_cert.as_ref(), cli.tls_key.as_ref()) {
        (Some(c), Some(k)) => {
            tracing::info!("loading TLS cert from {c:?} / key from {k:?}");
            tls_from_pem(c, k).map_err(|e| anyhow::anyhow!("TLS PEM load: {e}"))?
        }
        _ => {
            tracing::warn!("auto-generating self-signed TLS cert for sandbox — clients need verify=False or pin the printed fingerprint");
            let (cfg, pem) = tls_self_signed("kmip.pqctoday.local")
                .map_err(|e| anyhow::anyhow!("TLS self-signed: {e}"))?;
            tracing::info!("self-signed cert PEM (copy to client trust store):\n{pem}");
            cfg
        }
    };

    // ── Serve forever ───────────────────────────────────────────────────
    serve(cli.listen, tls_cfg, deps).await.map_err(|e| anyhow::anyhow!("server: {e}"))?;
    Ok(())
}
