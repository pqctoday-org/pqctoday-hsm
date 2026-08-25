//! gRPC PKCS#11 remoting service — sandbox-bench-transport-arms-plan-08242026.md
//! WP3. Unary RPCs over the `pqctoday.pkcs11remote.v1` schema (`remoting/proto`),
//! dispatching into `pqctoday-pkcs11-remote-core`'s verb layer.
//!
//! ## TLS
//!
//! One process = one posture (env `PKCS11_REMOTE_TLS_PROFILE`, matching the
//! `pqc-kmip`/`pqc-kmip-baseline` twin pattern). tonic's `ServerTlsConfig`
//! builds its rustls config from `ServerConfig::builder()`, which resolves
//! the PROCESS-DEFAULT `CryptoProvider` — there is no hook to inject an
//! explicit provider into tonic's built-in TLS. So this binary installs its
//! profile's provider as the process default at startup (spike-verified,
//! 2026-08-24: a real gRPC health call negotiated both `X25519MLKEM768` and
//! the custom `SecP384r1MLKEM1024`, and a classical-only client was
//! refused). This is safe here specifically because the process runs
//! exactly one posture for its whole lifetime — never race two profiles in
//! one binary.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use pqc_grpc_pkcs11::service;
use pqctoday_tls::TlsProfile;
use tonic::transport::{Identity, Server, ServerTlsConfig};

#[derive(Parser, Debug)]
#[command(name = "pqc-grpc-pkcs11")]
struct Cli {
    #[arg(long, env = "PKCS11_REMOTE_LISTEN", default_value = "0.0.0.0:5710")]
    listen: SocketAddr,

    #[arg(long = "tls-profile", env = "PKCS11_REMOTE_TLS_PROFILE", default_value = "permissive", value_parser = TlsProfile::parse)]
    tls_profile: TlsProfile,

    /// PEM cert; omitted ⇒ self-signed (sandbox/dev).
    #[arg(long, env = "PKCS11_REMOTE_TLS_CERT")]
    tls_cert: Option<PathBuf>,
    #[arg(long, env = "PKCS11_REMOTE_TLS_KEY")]
    tls_key: Option<PathBuf>,

    /// Client CA bundle — required to start under `quantum-safe` (mTLS),
    /// mirroring the KMIP server's §3.3.4 refuse-to-start-without-identity-source
    /// rule (`pqctoday-kmip/bin/pqctoday-kmip.rs:336-345`).
    #[arg(long, env = "PKCS11_REMOTE_TLS_CLIENT_CA")]
    tls_client_ca: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    if cli.tls_profile == TlsProfile::QuantumSafe && cli.tls_client_ca.is_none() {
        anyhow::bail!(
            "quantum-safe posture requires --tls-client-ca (mTLS identity source) — \
             refusing to start without one, mirroring the KMIP server's §3.3.4 rule"
        );
    }

    tracing::info!(
        profile = ?cli.tls_profile,
        posture = %pqctoday_tls::tls_profile_summary(cli.tls_profile),
        "starting pqc-grpc-pkcs11"
    );

    pqctoday_pkcs11_remote_core::verbs::bootstrap()?;

    // Install this process's ONE posture as the rustls default (see module
    // doc — required because tonic's ServerTlsConfig gives no other hook).
    pqctoday_tls::client_provider_for(cli.tls_profile)
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install {:?} crypto provider as default", cli.tls_profile))?;

    let identity = load_or_generate_identity(&cli)?;
    let mut tls = ServerTlsConfig::new().identity(identity);
    if let Some(ca_path) = &cli.tls_client_ca {
        let ca_pem = std::fs::read(ca_path)?;
        tls = tls.client_ca_root(tonic::transport::Certificate::from_pem(ca_pem));
        if cli.tls_profile != TlsProfile::QuantumSafe {
            // classical-baseline / permissive: CA configured but optional,
            // so a plain client-cert-less client can still connect for
            // local testing.
            tls = tls.client_auth_optional(true);
        }
    }

    let (health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<pqctoday_pkcs11_remote_proto::pkcs11_remote_server::Pkcs11RemoteServer<service::Pkcs11RemoteService>>()
        .await;

    let svc = pqctoday_pkcs11_remote_proto::pkcs11_remote_server::Pkcs11RemoteServer::new(
        service::Pkcs11RemoteService::default(),
    );

    tracing::info!(addr = %cli.listen, "pqc-grpc-pkcs11 listening");
    Server::builder()
        .tls_config(tls)?
        .add_service(health_service)
        .add_service(svc)
        .serve(cli.listen)
        .await?;
    Ok(())
}

fn load_or_generate_identity(cli: &Cli) -> anyhow::Result<Identity> {
    match (&cli.tls_cert, &cli.tls_key) {
        (Some(cert), Some(key)) => {
            let cert_pem = std::fs::read(cert)?;
            let key_pem = std::fs::read(key)?;
            Ok(Identity::from_pem(cert_pem, key_pem))
        }
        (None, None) => {
            tracing::warn!("no --tls-cert/--tls-key given — generating a self-signed identity (sandbox/dev only)");
            let cert = rcgen_self_signed()?;
            Ok(Identity::from_pem(cert.0, cert.1))
        }
        _ => anyhow::bail!("--tls-cert and --tls-key must be supplied together"),
    }
}

fn rcgen_self_signed() -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let names = vec![
        "pqc-grpc".to_string(),
        "pqc-grpc-baseline".to_string(),
        "localhost".to_string(),
    ];
    let cert = rcgen_lib::generate_simple_self_signed(names)?;
    Ok((cert.cert.pem().into_bytes(), cert.key_pair.serialize_pem().into_bytes()))
}

// Renamed import to avoid clashing with tonic's `Identity` type in scope above.
use rcgen as rcgen_lib;
