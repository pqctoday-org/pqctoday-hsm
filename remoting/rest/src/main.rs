//! REST PKCS#11 remoting service — sandbox-bench-transport-arms-plan-08242026.md
//! WP3. JSON+base64 over HTTP/1.1 keep-alive; **h2 deliberately disabled**
//! (ALPN restricted to `http/1.1` only) so a benchmark comparing this arm
//! against gRPC is comparing framing style, not accidentally comparing two
//! HTTP/2 stacks.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use pqc_rest_pkcs11::routes;
use pqctoday_tls::TlsProfile;

#[derive(Parser, Debug)]
#[command(name = "pqc-rest-pkcs11")]
struct Cli {
    #[arg(long, env = "PKCS11_REMOTE_LISTEN", default_value = "0.0.0.0:5720")]
    listen: SocketAddr,

    #[arg(long = "tls-profile", env = "PKCS11_REMOTE_TLS_PROFILE", default_value = "permissive", value_parser = TlsProfile::parse)]
    tls_profile: TlsProfile,

    #[arg(long, env = "PKCS11_REMOTE_TLS_CERT")]
    tls_cert: Option<PathBuf>,
    #[arg(long, env = "PKCS11_REMOTE_TLS_KEY")]
    tls_key: Option<PathBuf>,

    /// Client CA bundle. Required to start under `quantum-safe` (mTLS),
    /// mirroring the KMIP server's §3.3.4 refuse-to-start-without-identity-source
    /// rule. Under other profiles it is honored if given but not required.
    #[arg(long, env = "PKCS11_REMOTE_TLS_CLIENT_CA")]
    tls_client_ca: Option<PathBuf>,

    /// Enable destructive Pkcs11V32 RPCs — see the gRPC binary's flag of
    /// the same name. OFF by default (plan RW0 posture).
    #[arg(long = "enable-destructive", env = "PKCS11_REMOTE_ENABLE_DESTRUCTIVE", default_value_t = false)]
    enable_destructive: bool,
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
        "starting pqc-rest-pkcs11"
    );

    pqctoday_pkcs11_remote_core::verbs::bootstrap()?;

    let server_config = build_server_config(&cli)?;
    let rustls_config = RustlsConfig::from_config(Arc::new(server_config));

    // 16 MiB body limit, explicit: axum's 2 MB default (×1.33 base64) would
    // silently reject legitimate mirror payloads — plan RW0 rule 5.
    let app = routes::router_with(cli.enable_destructive)
        .layer(axum::extract::DefaultBodyLimit::max(16 * 1024 * 1024));
    tracing::info!(addr = %cli.listen, "pqc-rest-pkcs11 listening (HTTP/1.1 only)");
    axum_server::bind_rustls(cli.listen, rustls_config)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}

fn build_server_config(cli: &Cli) -> anyhow::Result<rustls::ServerConfig> {
    let builder =
        pqctoday_tls::server_config_builder(cli.tls_profile).map_err(|e| anyhow::anyhow!(e))?;

    let mut config = if let Some(ca_path) = &cli.tls_client_ca {
        let ca_pem = std::fs::read(ca_path)?;
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut &ca_pem[..]) {
            roots.add(cert?)?;
        }
        let provider = Arc::new(pqctoday_tls::client_provider_for(cli.tls_profile));
        let verifier = if cli.tls_profile == TlsProfile::QuantumSafe {
            rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider).build()?
        } else {
            rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
                .allow_unauthenticated()
                .build()?
        };
        let (certs, key) = load_or_generate_identity(cli)?;
        builder.with_client_cert_verifier(verifier).with_single_cert(certs, key)?
    } else {
        let (certs, key) = load_or_generate_identity(cli)?;
        builder.with_no_client_auth().with_single_cert(certs, key)?
    };

    // h2 disabled by construction (WP3 requirement) — ALPN offers only
    // http/1.1, so even an h2-capable client falls back to HTTP/1.1.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

fn load_or_generate_identity(
    cli: &Cli,
) -> anyhow::Result<(Vec<rustls::pki_types::CertificateDer<'static>>, rustls::pki_types::PrivateKeyDer<'static>)> {
    match (&cli.tls_cert, &cli.tls_key) {
        (Some(cert_path), Some(key_path)) => {
            let cert_pem = std::fs::read(cert_path)?;
            let key_pem = std::fs::read(key_path)?;
            let certs = rustls_pemfile::certs(&mut &cert_pem[..]).collect::<Result<Vec<_>, _>>()?;
            let key = rustls_pemfile::private_key(&mut &key_pem[..])?
                .ok_or_else(|| anyhow::anyhow!("no private key in {key_path:?}"))?;
            Ok((certs, key))
        }
        (None, None) => {
            tracing::warn!("no --tls-cert/--tls-key given — generating a self-signed identity (sandbox/dev only)");
            let names = vec!["pqc-rest".to_string(), "pqc-rest-baseline".to_string(), "localhost".to_string()];
            let cert = rcgen::generate_simple_self_signed(names)?;
            let cert_der = cert.cert.der().clone();
            let key_der = rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der())
                .map_err(|e| anyhow::anyhow!("key conversion: {e}"))?;
            Ok((vec![cert_der], key_der))
        }
        _ => anyhow::bail!("--tls-cert and --tls-key must be supplied together"),
    }
}
