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
use pqctoday_kmip::cert_init::init_certs_if_missing;
use pqctoday_kmip::ops::{Deps, DepsConfig};
use pqctoday_kmip::policy::{load_from_str, Engine, PolicyStore};
use pqctoday_kmip::server::{serve, tls_from_pem, tls_mtls, tls_self_signed, AuthUser};
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

    /// K14 mTLS — client CA bundle (PEM). When set (requires
    /// `--tls-cert`/`--tls-key`), the listener REQUIRES a client
    /// certificate signed by this CA and maps its subject CN to the
    /// KMIP identity.
    #[arg(long, requires = "tls_cert")]
    tls_client_ca: Option<PathBuf>,

    /// cryptopolicy-manager admin facade listen address (e.g.
    /// `127.0.0.1:5697`). When set, serves the out-of-band HTTP policy-admin
    /// API (list/load/validate/dry-run/save/activate) over **mTLS with the
    /// X25519MLKEM768 PQC hybrid key exchange**, sharing this server's live
    /// engine so an activation takes effect with no restart. Requires
    /// `--admin-tls-cert/key`, `--admin-client-ca`, and `--policy-dir`.
    #[arg(long)]
    admin_listen: Option<SocketAddr>,

    /// Admin facade server cert / key (PEM). Required with `--admin-listen`.
    #[arg(long, requires = "admin_listen")]
    admin_tls_cert: Option<PathBuf>,
    #[arg(long, requires = "admin_listen")]
    admin_tls_key: Option<PathBuf>,

    /// Admin facade client-CA bundle (PEM): admin mTLS client certs must be
    /// signed by it. Required with `--admin-listen`.
    #[arg(long, requires = "admin_listen")]
    admin_client_ca: Option<PathBuf>,

    /// C0 — generate admin mTLS certs into this directory on first boot (if
    /// `<dir>/ca.crt` is absent) and wire them into `--admin-tls-cert/key` +
    /// `--admin-client-ca` automatically. Replaces the `openssl`-CLI shelling
    /// in `kmip-entrypoint.sh`, enabling distroless / no-shell images.
    /// If the directory already contains certs, generation is skipped (idempotent).
    #[arg(long, value_name = "DIR")]
    init_certs: Option<PathBuf>,

    /// K14 auth — configured credential store entry, repeatable:
    /// `<username>:<sha256hex-of-password>` (e.g.
    /// `alice:$(printf %s 'pw' | shasum -a 256 | cut -d' ' -f1)`).
    /// Absent (default) = open-auth mode — every request passes and the
    /// KMIP `Authentication` header is ignored (replay harness relies
    /// on this). Present = requests must authenticate via the §8.1.2
    /// Authentication header (Username and Password credential) or an
    /// mTLS-verified client certificate.
    #[arg(long = "auth-user")]
    auth_user: Vec<String>,

    /// PKCS#11 slot (single-slot v0.1).
    #[arg(long, default_value_t = 0)]
    slot: u32,

    /// PKCS#11 user PIN.
    #[arg(long, default_value = "1234")]
    pin: String,

    /// P2.3 — designate the CA signing key for §6.1.6 Certify /
    /// §6.1.50 Re-certify: the UID of a stored PrivateKey (RSA / ECDSA /
    /// ML-DSA). Requires `--ca-cert`. Absent ⇒ the server is not a CA
    /// and every Certify request fails Permission Denied.
    #[arg(long = "ca-key", requires = "ca_cert")]
    ca_key: Option<String>,

    /// P2.3 — UID of the stored CA Certificate whose subject DN becomes
    /// the issuer DN of every issued certificate. Requires `--ca-key`.
    #[arg(long = "ca-cert", requires = "ca_key")]
    ca_cert: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let mut cli = Cli::parse();

    // ── C0: internalized cert minting ───────────────────────────────────────
    // If --init-certs <dir> is given, generate the admin mTLS CA + server +
    // client certs into that directory on first boot (idempotent). The returned
    // paths auto-populate --admin-tls-cert/key and --admin-client-ca so the
    // caller does not need to repeat them on the command line.
    if let Some(ref cert_dir) = cli.init_certs.clone() {
        let certs = init_certs_if_missing(cert_dir)?;
        if cli.admin_tls_cert.is_none() {
            cli.admin_tls_cert = Some(certs.server_cert);
        }
        if cli.admin_tls_key.is_none() {
            cli.admin_tls_key = Some(certs.server_key);
        }
        if cli.admin_client_ca.is_none() {
            cli.admin_client_ca = Some(certs.ca_cert);
        }
    }

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

    // ── Engine session (Phase 7b — real bridge to softhsmrustv3) ────────
    // Bootstrap a fresh token on `--slot` and open a long-lived user
    // session. The handle is shared across all per-connection tasks
    // (`softhsmrustv3` storage is Mutex-protected globals — safe across
    // threads, serialised internally).
    let engine_session = softhsmrustv3::native::session::bootstrap_default_token(
        cli.slot,
        "so-pin",
        &cli.pin,
        "pqctoday-kmip",
    )
    .map_err(|rv| anyhow::anyhow!("engine bootstrap failed: CK_RV=0x{rv:08x}"))?;
    tracing::info!(
        "engine session {} opened against slot {} — real bridge wired",
        engine_session,
        cli.slot
    );

    // ── Auth config (K14) ───────────────────────────────────────────────
    let auth_users = cli
        .auth_user
        .iter()
        .map(|s| AuthUser::parse_flag(s).map_err(|e| anyhow::anyhow!(e)))
        .collect::<anyhow::Result<Vec<_>>>()?;
    if auth_users.is_empty() {
        tracing::info!("no --auth-user entries — open-auth mode (Authentication header ignored)");
    } else {
        tracing::info!("authentication ENFORCED for {} configured user(s)", auth_users.len());
    }

    // ── cryptopolicy-manager admin facade (W4, optional) ───────────────
    // Spawn BEFORE `engine` is moved into Deps — `Engine` is Clone over a
    // shared `Arc<RwLock>`, so the facade's clone enforces activations on the
    // running dispatcher with no restart. mTLS + X25519MLKEM768 PQC KEX.
    if let Some(addr) = cli.admin_listen {
        let cert = cli.admin_tls_cert.clone().ok_or_else(|| anyhow::anyhow!("--admin-listen requires --admin-tls-cert"))?;
        let key = cli.admin_tls_key.clone().ok_or_else(|| anyhow::anyhow!("--admin-listen requires --admin-tls-key"))?;
        let ca = cli.admin_client_ca.clone().ok_or_else(|| anyhow::anyhow!("--admin-listen requires --admin-client-ca"))?;
        let policy_dir = cli.policy_dir.clone().ok_or_else(|| anyhow::anyhow!("--admin-listen requires --policy-dir (the policy store root)"))?;
        let tls = pqctoday_kmip::cryptopolicy_manager::pqc_mtls_config(
            &std::fs::read(&cert)?,
            &std::fs::read(&key)?,
            &std::fs::read(&ca)?,
        )
        .map_err(|e| anyhow::anyhow!("admin mTLS config: {e}"))?;
        let admin_engine = engine.clone();
        let admin_ring = ring.clone();
        tracing::info!("cryptopolicy-manager admin facade enabled on {addr} (mTLS, X25519MLKEM768)");
        tokio::spawn(async move {
            if let Err(e) = pqctoday_kmip::cryptopolicy_manager::serve_admin(
                addr,
                policy_dir,
                admin_engine,
                admin_ring,
                tls,
            )
            .await
            {
                tracing::error!("admin facade exited: {e}");
            }
        });
    }

    // ── Deps bundle ─────────────────────────────────────────────────────
    let ca_key = match (cli.ca_key.as_ref(), cli.ca_cert.as_ref()) {
        (Some(priv_uid), Some(cert_uid)) => {
            tracing::info!("CA configured: signing key {priv_uid:?}, issuer cert {cert_uid:?}");
            Some(pqctoday_kmip::ops::deps::CaKeyDesignation {
                private_key_uid: priv_uid.clone(),
                certificate_uid: cert_uid.clone(),
            })
        }
        _ => {
            tracing::info!("no --ca-key — Certify / Re-certify disabled (not a CA)");
            None
        }
    };
    let config = DepsConfig {
        pkcs11_slot: cli.slot,
        pkcs11_pin: cli.pin,
        vendor_identification: "pqctoday-hsm".into(),
        server_version: env!("CARGO_PKG_VERSION").into(),
        auth_users,
        ca_key,
    };
    let deps = Arc::new(
        Deps::new(engine, store, sink, config).with_engine_session(engine_session),
    );

    // ── TLS config ──────────────────────────────────────────────────────
    let tls_cfg = match (cli.tls_cert.as_ref(), cli.tls_key.as_ref()) {
        // K14 mTLS — client CA configured: require + verify client
        // certificates; the listener maps the subject CN to the KMIP
        // identity.
        (Some(c), Some(k)) if cli.tls_client_ca.is_some() => {
            let ca = cli.tls_client_ca.as_ref().unwrap();
            tracing::info!(
                "mTLS: loading server cert {c:?} / key {k:?}; requiring client certs signed by {ca:?}"
            );
            pqctoday_kmip::server::listener::install_crypto_provider();
            tls_mtls(
                &std::fs::read(c)?,
                &std::fs::read(k)?,
                &std::fs::read(ca)?,
            )
            .map_err(|e| anyhow::anyhow!("mTLS config: {e}"))?
        }
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
