//! gRPC / REST PKCS#11 remoting client arms — sandbox-bench-transport-arms-plan-08242026.md
//! WP4. Same measurement discipline as the KMIP arm (`kmip.rs`): fixed-duration
//! points via `measure::run_point`, `--repeats` + median + min/max spread,
//! `--compare-tls` interleaving (A,B,A,B… within one session so machine drift
//! hits both arms equally — see `kmip.rs`'s module doc for the measured
//! evidence that made interleaving mandatory here too).
//!
//! Three connection models, one per arm (decision 7 — every row states which):
//! - `persistent-channel` — one gRPC channel opened once, reused for the
//!   whole run (the idiomatic gRPC pattern).
//! - `per-request-channel` — a fresh gRPC channel per operation, inside the
//!   timed loop — the KMIP-comparable number: same framing, unamortized
//!   connection cost.
//! - `keep-alive` — one REST HTTP/1.1 client with a keep-alive pool, reused
//!   for the whole run.
//!
//! ## Why a shared tokio runtime for a blocking-thread harness
//!
//! `measure::run_point` spawns real OS threads running a tight `FnMut()`
//! loop (see `kmip.rs`'s own module doc for why blocking, not async, is the
//! right model here). gRPC is inherently async in tonic, so each worker
//! thread bridges via `Handle::block_on` on ONE shared multi-thread runtime
//! built once per process — calling `block_on` concurrently from multiple
//! external OS threads on the same handle is supported and is exactly the
//! bridge pattern this needs. The REST arm needs no bridge: `ureq` is
//! synchronous end to end.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use pqctoday_pkcs11_remote_proto::pkcs11_remote_client::Pkcs11RemoteClient;
use pqctoday_pkcs11_remote_proto::{self as pb};
use pqctoday_tls::TlsProfile;
use tonic::transport::{Channel, Endpoint, Uri};
use tonic::Request;

// ── shared TLS config (client side) ─────────────────────────────────────────

/// Which HTTP version this connection must speak — determines the ALPN
/// offer. Mixing this up is a real trap: the REST service pins its ALPN to
/// `http/1.1` only (h2 deliberately disabled, WP3), so a client offering
/// only `h2` gets a `NoApplicationProtocol` fatal alert with no useful
/// error beyond that. Found the hard way running this exact smoke test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AlpnProtocol {
    H2,
    Http11,
}

fn client_tls_config(
    profile: TlsProfile,
    alpn: AlpnProtocol,
    ca_pem: &[u8],
    client_cert_pem: Option<&[u8]>,
    client_key_pem: Option<&[u8]>,
) -> Result<Arc<rustls::ClientConfig>> {
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut &ca_pem[..]) {
        roots.add(c.context("parsing CA PEM")?).context("adding CA to trust store")?;
    }
    let client_auth = match (client_cert_pem, client_key_pem) {
        (Some(cert_pem), Some(key_pem)) => {
            let certs: Vec<_> =
                rustls_pemfile::certs(&mut &cert_pem[..]).collect::<std::result::Result<_, _>>()?;
            let key = rustls_pemfile::private_key(&mut &key_pem[..])?
                .ok_or_else(|| anyhow!("no private key in client key PEM"))?;
            Some((certs, key))
        }
        (None, None) => None,
        _ => return Err(anyhow!("client cert and key must be supplied together")),
    };
    let provider = pqctoday_tls::client_provider_for(profile);
    let versions: &[&'static rustls::SupportedProtocolVersion] = match profile {
        TlsProfile::Permissive => rustls::DEFAULT_VERSIONS,
        _ => &[&rustls::version::TLS13],
    };
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(versions)
        .context("client TLS setup")?
        .with_root_certificates(roots);
    let mut config = match client_auth {
        Some((certs, key)) => builder.with_client_auth_cert(certs, key).context("client cert rejected")?,
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = match alpn {
        AlpnProtocol::H2 => vec![b"h2".to_vec()],
        AlpnProtocol::Http11 => vec![b"http/1.1".to_vec()],
    };
    Ok(Arc::new(config))
}

// ── gRPC connect (spike-verified pattern: http:// URI + connect_with_connector) ─

async fn grpc_connect(host: &str, port: u16, server_name: &str, tls: Arc<rustls::ClientConfig>) -> Result<Channel> {
    let connector = tokio_rustls::TlsConnector::from(tls);
    let addr = format!("{host}:{port}");
    let server_name = rustls::pki_types::ServerName::try_from(server_name.to_string())
        .map_err(|e| anyhow!("invalid server name {server_name:?}: {e}"))?;
    // http:// (NOT https://) — the spike's load-bearing finding: an https://
    // URI makes tonic wrap ANOTHER TLS layer around this already-TLS stream
    // and fail with an opaque "transport error".
    let channel = Endpoint::from_shared(format!("http://{host}:{port}"))?
        .connect_timeout(Duration::from_secs(5))
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let connector = connector.clone();
            let server_name = server_name.clone();
            let addr = addr.clone();
            async move {
                let tcp = tokio::net::TcpStream::connect(&addr).await?;
                let tls = connector
                    .connect(server_name, tcp)
                    .await
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("tls: {e}")))?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(tls))
            }
        }))
        .await
        .context("gRPC connect")?;
    Ok(channel)
}

fn to_proto_algo(name: &str) -> Result<pb::Algorithm> {
    Ok(match name {
        "Ed25519" => pb::Algorithm::Ed25519,
        "ML-DSA-44" => pb::Algorithm::MlDsa44,
        "ML-DSA-65" => pb::Algorithm::MlDsa65,
        "ML-DSA-87" => pb::Algorithm::MlDsa87,
        "ML-KEM-512" => pb::Algorithm::MlKem512,
        "ML-KEM-768" => pb::Algorithm::MlKem768,
        "ML-KEM-1024" => pb::Algorithm::MlKem1024,
        other => return Err(anyhow!("unknown algorithm cell {other:?}")),
    })
}

// ── the RemoteTransport trait — one seam, three implementations ─────────────

/// The seven benchmark verbs, transport-agnostic (mirrors `remoting/core`'s
/// own verb layer signatures on the server side, so a case that passes
/// in-process and fails here is a remoting defect by construction).
pub trait RemoteTransport {
    fn open_session(&self, pin: &str) -> Result<u32>;
    fn generate_key_pair(&self, session: u32, algo: &str, cka_id: &[u8], label: &str) -> Result<(u32, u32)>;
    fn sign(&self, session: u32, key_handle: u32, algo: &str, data: &[u8]) -> Result<Vec<u8>>;
    fn verify(&self, session: u32, key_handle: u32, algo: &str, data: &[u8], sig: &[u8]) -> Result<bool>;
    fn encapsulate(&self, session: u32, key_handle: u32, algo: &str) -> Result<(Vec<u8>, Vec<u8>)>;
    fn decapsulate(&self, session: u32, key_handle: u32, algo: &str, ct: &[u8]) -> Result<Vec<u8>>;
}

// ── gRPC, persistent channel ─────────────────────────────────────────────────

pub struct GrpcPersistent {
    rt: Arc<tokio::runtime::Runtime>,
    client: Pkcs11RemoteClient<Channel>,
}

impl GrpcPersistent {
    pub fn connect(
        rt: Arc<tokio::runtime::Runtime>,
        host: &str,
        port: u16,
        server_name: &str,
        tls: Arc<rustls::ClientConfig>,
    ) -> Result<Self> {
        let channel = rt.block_on(grpc_connect(host, port, server_name, tls))?;
        Ok(Self { rt, client: Pkcs11RemoteClient::new(channel) })
    }
}

impl Clone for GrpcPersistent {
    fn clone(&self) -> Self {
        // Cheap: tonic's Channel clone shares the same multiplexed HTTP/2
        // connection — this is what makes "persistent" mean one real socket
        // shared by every worker thread, not one per thread.
        Self { rt: Arc::clone(&self.rt), client: self.client.clone() }
    }
}

impl RemoteTransport for GrpcPersistent {
    fn open_session(&self, pin: &str) -> Result<u32> {
        let mut c = self.client.clone();
        self.rt.block_on(async move {
            Ok(c.open_session(Request::new(pb::OpenSessionRequest { user_pin: pin.into() }))
                .await?
                .into_inner()
                .session_handle)
        })
    }

    fn generate_key_pair(&self, session: u32, algo: &str, cka_id: &[u8], label: &str) -> Result<(u32, u32)> {
        let algorithm = to_proto_algo(algo)? as i32;
        let mut c = self.client.clone();
        let (cka_id, label) = (cka_id.to_vec(), label.to_string());
        self.rt.block_on(async move {
            let r = c
                .generate_key_pair(Request::new(pb::GenerateKeyPairRequest {
                    session_handle: session,
                    algorithm,
                    cka_id,
                    label,
                }))
                .await?
                .into_inner();
            Ok((r.public_handle, r.private_handle))
        })
    }

    fn sign(&self, session: u32, key_handle: u32, algo: &str, data: &[u8]) -> Result<Vec<u8>> {
        let algorithm = to_proto_algo(algo)? as i32;
        let mut c = self.client.clone();
        let data = data.to_vec();
        self.rt.block_on(async move {
            Ok(c.sign(Request::new(pb::SignRequest { session_handle: session, private_handle: key_handle, algorithm, data }))
                .await?
                .into_inner()
                .signature)
        })
    }

    fn verify(&self, session: u32, key_handle: u32, algo: &str, data: &[u8], sig: &[u8]) -> Result<bool> {
        let algorithm = to_proto_algo(algo)? as i32;
        let mut c = self.client.clone();
        let (data, signature) = (data.to_vec(), sig.to_vec());
        self.rt.block_on(async move {
            Ok(c.verify(Request::new(pb::VerifyRequest {
                session_handle: session,
                public_handle: key_handle,
                algorithm,
                data,
                signature,
            }))
            .await?
            .into_inner()
            .valid)
        })
    }

    fn encapsulate(&self, session: u32, key_handle: u32, algo: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let algorithm = to_proto_algo(algo)? as i32;
        let mut c = self.client.clone();
        self.rt.block_on(async move {
            let r = c
                .encapsulate(Request::new(pb::EncapsulateRequest { session_handle: session, public_handle: key_handle, algorithm }))
                .await?
                .into_inner();
            Ok((r.ciphertext, r.shared_secret))
        })
    }

    fn decapsulate(&self, session: u32, key_handle: u32, algo: &str, ct: &[u8]) -> Result<Vec<u8>> {
        let algorithm = to_proto_algo(algo)? as i32;
        let mut c = self.client.clone();
        let ciphertext = ct.to_vec();
        self.rt.block_on(async move {
            Ok(c.decapsulate(Request::new(pb::DecapsulateRequest {
                session_handle: session,
                private_handle: key_handle,
                algorithm,
                ciphertext,
            }))
            .await?
            .into_inner()
            .shared_secret)
        })
    }
}

// ── gRPC, per-request channel (the KMIP-comparable arm) ──────────────────────

#[derive(Clone)]
pub struct GrpcPerRequest {
    rt: Arc<tokio::runtime::Runtime>,
    host: String,
    port: u16,
    server_name: String,
    tls: Arc<rustls::ClientConfig>,
}

impl GrpcPerRequest {
    pub fn new(rt: Arc<tokio::runtime::Runtime>, host: &str, port: u16, server_name: &str, tls: Arc<rustls::ClientConfig>) -> Self {
        Self { rt, host: host.to_string(), port, server_name: server_name.to_string(), tls }
    }

    /// Opens a fresh channel, sends exactly one call, drops the channel.
    /// This is what "per-request" costs on gRPC: a full TCP + TLS + HTTP/2
    /// preface for every single operation — the direct comparison point
    /// against the KMIP arm's per-request TTLV connection.
    fn call<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(Pkcs11RemoteClient<Channel>) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T>> + Send>>,
    {
        let (host, port, server_name, tls) = (self.host.clone(), self.port, self.server_name.clone(), Arc::clone(&self.tls));
        self.rt.block_on(async move {
            let channel = grpc_connect(&host, port, &server_name, tls).await?;
            f(Pkcs11RemoteClient::new(channel)).await
        })
    }
}

impl RemoteTransport for GrpcPerRequest {
    fn open_session(&self, pin: &str) -> Result<u32> {
        let pin = pin.to_string();
        self.call(move |mut c| {
            Box::pin(async move {
                Ok(c.open_session(Request::new(pb::OpenSessionRequest { user_pin: pin })).await?.into_inner().session_handle)
            })
        })
    }

    fn generate_key_pair(&self, session: u32, algo: &str, cka_id: &[u8], label: &str) -> Result<(u32, u32)> {
        let algorithm = to_proto_algo(algo)? as i32;
        let (cka_id, label) = (cka_id.to_vec(), label.to_string());
        self.call(move |mut c| {
            Box::pin(async move {
                let r = c
                    .generate_key_pair(Request::new(pb::GenerateKeyPairRequest { session_handle: session, algorithm, cka_id, label }))
                    .await?
                    .into_inner();
                Ok((r.public_handle, r.private_handle))
            })
        })
    }

    fn sign(&self, session: u32, key_handle: u32, algo: &str, data: &[u8]) -> Result<Vec<u8>> {
        let algorithm = to_proto_algo(algo)? as i32;
        let data = data.to_vec();
        self.call(move |mut c| {
            Box::pin(async move {
                Ok(c.sign(Request::new(pb::SignRequest { session_handle: session, private_handle: key_handle, algorithm, data }))
                    .await?
                    .into_inner()
                    .signature)
            })
        })
    }

    fn verify(&self, session: u32, key_handle: u32, algo: &str, data: &[u8], sig: &[u8]) -> Result<bool> {
        let algorithm = to_proto_algo(algo)? as i32;
        let (data, signature) = (data.to_vec(), sig.to_vec());
        self.call(move |mut c| {
            Box::pin(async move {
                Ok(c.verify(Request::new(pb::VerifyRequest { session_handle: session, public_handle: key_handle, algorithm, data, signature }))
                    .await?
                    .into_inner()
                    .valid)
            })
        })
    }

    fn encapsulate(&self, session: u32, key_handle: u32, algo: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let algorithm = to_proto_algo(algo)? as i32;
        self.call(move |mut c| {
            Box::pin(async move {
                let r = c
                    .encapsulate(Request::new(pb::EncapsulateRequest { session_handle: session, public_handle: key_handle, algorithm }))
                    .await?
                    .into_inner();
                Ok((r.ciphertext, r.shared_secret))
            })
        })
    }

    fn decapsulate(&self, session: u32, key_handle: u32, algo: &str, ct: &[u8]) -> Result<Vec<u8>> {
        let algorithm = to_proto_algo(algo)? as i32;
        let ciphertext = ct.to_vec();
        self.call(move |mut c| {
            Box::pin(async move {
                Ok(c.decapsulate(Request::new(pb::DecapsulateRequest { session_handle: session, private_handle: key_handle, algorithm, ciphertext }))
                    .await?
                    .into_inner()
                    .shared_secret)
            })
        })
    }
}

// ── REST, keep-alive ──────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct RestKeepAlive {
    agent: ureq::Agent,
    base: String,
}

impl RestKeepAlive {
    pub fn new(host: &str, port: u16, tls: Arc<rustls::ClientConfig>) -> Self {
        let agent = ureq::AgentBuilder::new().tls_config(tls).build();
        Self { agent, base: format!("https://{host}:{port}") }
    }

    fn post_json(&self, path: &str, body: serde_json::Value) -> Result<serde_json::Value> {
        let resp = self
            .agent
            .post(&format!("{}{}", self.base, path))
            .send_json(body)
            .map_err(|e| anyhow!("REST {path}: {e}"))?;
        Ok(resp.into_json()?)
    }
}

fn algo_kebab(name: &str) -> &'static str {
    match name {
        "Ed25519" => "ed25519",
        "ML-DSA-44" => "ml-dsa44",
        "ML-DSA-65" => "ml-dsa65",
        "ML-DSA-87" => "ml-dsa87",
        "ML-KEM-512" => "ml-kem512",
        "ML-KEM-768" => "ml-kem768",
        "ML-KEM-1024" => "ml-kem1024",
        other => panic!("unknown algorithm cell {other}"),
    }
}

impl RemoteTransport for RestKeepAlive {
    fn open_session(&self, pin: &str) -> Result<u32> {
        let v = self.post_json("/v1/sessions", serde_json::json!({ "user_pin": pin }))?;
        v["session_handle"].as_u64().map(|n| n as u32).ok_or_else(|| anyhow!("no session_handle in response"))
    }

    fn generate_key_pair(&self, session: u32, algo: &str, cka_id: &[u8], label: &str) -> Result<(u32, u32)> {
        let v = self.post_json(
            "/v1/keys",
            serde_json::json!({ "session_handle": session, "algorithm": algo_kebab(algo), "cka_id": B64.encode(cka_id), "label": label }),
        )?;
        let pub_h = v["public_handle"].as_u64().ok_or_else(|| anyhow!("no public_handle"))? as u32;
        let prv_h = v["private_handle"].as_u64().ok_or_else(|| anyhow!("no private_handle"))? as u32;
        Ok((pub_h, prv_h))
    }

    fn sign(&self, session: u32, key_handle: u32, algo: &str, data: &[u8]) -> Result<Vec<u8>> {
        let v = self.post_json(
            &format!("/v1/keys/{key_handle}/sign"),
            serde_json::json!({ "session_handle": session, "algorithm": algo_kebab(algo), "data": B64.encode(data) }),
        )?;
        let sig = v["signature"].as_str().ok_or_else(|| anyhow!("no signature"))?;
        Ok(B64.decode(sig)?)
    }

    fn verify(&self, session: u32, key_handle: u32, algo: &str, data: &[u8], sig: &[u8]) -> Result<bool> {
        let v = self.post_json(
            &format!("/v1/keys/{key_handle}/verify"),
            serde_json::json!({ "session_handle": session, "algorithm": algo_kebab(algo), "data": B64.encode(data), "signature": B64.encode(sig) }),
        )?;
        v["valid"].as_bool().ok_or_else(|| anyhow!("no valid field"))
    }

    fn encapsulate(&self, session: u32, key_handle: u32, algo: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let v = self.post_json(
            &format!("/v1/keys/{key_handle}/encapsulate"),
            serde_json::json!({ "session_handle": session, "algorithm": algo_kebab(algo) }),
        )?;
        let ct = B64.decode(v["ciphertext"].as_str().ok_or_else(|| anyhow!("no ciphertext"))?)?;
        let ss = B64.decode(v["shared_secret"].as_str().ok_or_else(|| anyhow!("no shared_secret"))?)?;
        Ok((ct, ss))
    }

    fn decapsulate(&self, session: u32, key_handle: u32, algo: &str, ct: &[u8]) -> Result<Vec<u8>> {
        let v = self.post_json(
            &format!("/v1/keys/{key_handle}/decapsulate"),
            serde_json::json!({ "session_handle": session, "algorithm": algo_kebab(algo), "ciphertext": B64.encode(ct) }),
        )?;
        Ok(B64.decode(v["shared_secret"].as_str().ok_or_else(|| anyhow!("no shared_secret"))?)?)
    }
}

// ── the representative cell matrix (same set as the KMIP arm) ────────────────

#[derive(Debug, Clone, Copy)]
pub struct Cell {
    pub label: &'static str,
    pub kem: bool,
}

pub const REPRESENTATIVE_CELLS: &[Cell] =
    &[Cell { label: "Ed25519", kem: false }, Cell { label: "ML-DSA-65", kem: false }, Cell { label: "ML-KEM-768", kem: true }];

// ── the `transport` subcommand ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Protocol {
    Grpc,
    GrpcPerRequest,
    Rest,
}

#[derive(Debug, clap::Args)]
pub struct TransportArgs {
    #[arg(long, value_enum)]
    pub protocol: Protocol,
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,
    #[arg(long)]
    pub port: Option<u16>,
    #[arg(long)]
    pub ca: String,
    #[arg(long, default_value = "localhost")]
    pub server_name: String,
    #[arg(long, default_value = "1234")]
    pub pin: String,
    #[arg(long)]
    pub client_cert: Option<String>,
    #[arg(long)]
    pub client_key: Option<String>,
    #[arg(long, default_value = "quantum-safe")]
    pub tls: String,
    #[arg(long, default_value_t = 2)]
    pub threads: u32,
    #[arg(long, default_value_t = 2.0)]
    pub duration_secs: f64,
    #[arg(long, default_value_t = 0.5)]
    pub warmup_secs: f64,
    /// Same "repeats, not a single sample" rule as the KMIP arm — see
    /// `KmipArgs::repeats`'s doc comment for the measured evidence.
    #[arg(long, default_value_t = 3)]
    pub repeats: u32,
    #[arg(long)]
    pub compare_tls: Option<String>,
    #[arg(long)]
    pub compare_host: Option<String>,
    #[arg(long)]
    pub compare_port: Option<u16>,
}

fn default_port(protocol: Protocol) -> u16 {
    match protocol {
        Protocol::Grpc | Protocol::GrpcPerRequest => 5710,
        Protocol::Rest => 5720,
    }
}

fn parse_tls(s: &str) -> Result<TlsProfile> {
    TlsProfile::parse(s).map_err(|e| anyhow!(e))
}

fn connection_model(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Grpc => "persistent-channel",
        Protocol::GrpcPerRequest => "per-request-channel",
        Protocol::Rest => "keep-alive",
    }
}

#[derive(serde::Serialize)]
struct TransportRow<'a> {
    access_path: &'a str,
    protocol: &'a str,
    connection_model: &'a str,
    tls: &'a str,
    algorithm: &'a str,
    category: &'a str,
    op: &'a str,
    threads: u32,
    ops_per_sec: f64,
    ops_per_sec_min: f64,
    ops_per_sec_max: f64,
    repeats: u32,
    interleaved: bool,
    p50_ms: f64,
    p99_ms: f64,
    duration_s: f64,
    total_ops: u64,
    round_trips_per_op: u32,
}

fn build_transport(
    rt: &Arc<tokio::runtime::Runtime>,
    protocol: Protocol,
    host: &str,
    port: u16,
    server_name: &str,
    ca_pem: &[u8],
    client_cert_pem: Option<&[u8]>,
    client_key_pem: Option<&[u8]>,
    tls_profile: TlsProfile,
) -> Result<Arc<dyn RemoteTransport + Send + Sync>> {
    let alpn = match protocol {
        Protocol::Grpc | Protocol::GrpcPerRequest => AlpnProtocol::H2,
        Protocol::Rest => AlpnProtocol::Http11,
    };
    let tls = client_tls_config(tls_profile, alpn, ca_pem, client_cert_pem, client_key_pem)?;
    Ok(match protocol {
        Protocol::Grpc => Arc::new(GrpcPersistent::connect(Arc::clone(rt), host, port, server_name, tls)?),
        Protocol::GrpcPerRequest => Arc::new(GrpcPerRequest::new(Arc::clone(rt), host, port, server_name, tls)),
        Protocol::Rest => Arc::new(RestKeepAlive::new(host, port, tls)),
    })
}

pub fn run(args: &TransportArgs) -> Result<()> {
    let tls = parse_tls(&args.tls)?;
    let port = args.port.unwrap_or_else(|| default_port(args.protocol));
    let ca_pem = std::fs::read(&args.ca).with_context(|| format!("reading --ca {}", args.ca))?;
    let client_cert_pem = args.client_cert.as_ref().map(std::fs::read).transpose()?;
    let client_key_pem = args.client_key.as_ref().map(std::fs::read).transpose()?;

    let rt = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(args.threads as usize + 2)
            .enable_all()
            .build()?,
    );

    let primary = build_transport(
        &rt,
        args.protocol,
        &args.host,
        port,
        &args.server_name,
        &ca_pem,
        client_cert_pem.as_deref(),
        client_key_pem.as_deref(),
        tls,
    )
    .context("connecting the primary arm")?;

    // Fail fast: one clear error beats a matrix of missing rows.
    primary.open_session(&args.pin).context("pre-run probe (open_session) failed")?;

    let compare: Option<(Arc<dyn RemoteTransport + Send + Sync>, &str)> = match &args.compare_tls {
        Some(label) => {
            let cmp_tls = parse_tls(label)?;
            let cmp_host = args.compare_host.clone().unwrap_or_else(|| args.host.clone());
            let cmp_port = args.compare_port.unwrap_or(port);
            if cmp_host == args.host && cmp_port == port {
                return Err(anyhow!(
                    "--compare-tls needs a DIFFERENT endpoint (--compare-host/--compare-port) — \
                     one server process serves one TLS posture, same as the KMIP arm's rule"
                ));
            }
            let t = build_transport(
                &rt,
                args.protocol,
                &cmp_host,
                cmp_port,
                &args.server_name,
                &ca_pem,
                client_cert_pem.as_deref(),
                client_key_pem.as_deref(),
                cmp_tls,
            )
            .context("connecting the --compare-tls arm")?;
            t.open_session(&args.pin).context("pre-run probe of the --compare-tls endpoint failed")?;
            Some((t, label.as_str()))
        }
        None => None,
    };

    let model = connection_model(args.protocol);
    let protocol_label = match args.protocol {
        Protocol::Grpc => "grpc",
        Protocol::GrpcPerRequest => "grpc",
        Protocol::Rest => "rest",
    };

    for cell in REPRESENTATIVE_CELLS {
        let (op, category, round_trips) = if cell.kem { ("encapsulate", "key_establishment", 1) } else { ("sign", "signature", 1) };

        let mut arms: Vec<(&str, Arc<dyn RemoteTransport + Send + Sync>, u32, u32)> = Vec::new();
        {
            let session = primary.open_session(&args.pin)?;
            let (pub_h, prv_h) = primary.generate_key_pair(session, cell.label, b"\x01", "transport-bench")?;
            arms.push((args.tls.as_str(), Arc::clone(&primary), if cell.kem { pub_h } else { prv_h }, session));
        }
        if let Some((cmp_t, cmp_label)) = &compare {
            let session = cmp_t.open_session(&args.pin)?;
            let (pub_h, prv_h) = cmp_t.generate_key_pair(session, cell.label, b"\x01", "transport-bench-cmp")?;
            arms.push((cmp_label, Arc::clone(cmp_t), if cell.kem { pub_h } else { prv_h }, session));
        }

        let mut samples: Vec<Vec<(f64, f64, f64, u64, f64)>> = vec![Vec::new(); arms.len()];
        for _ in 0..args.repeats.max(1) {
            for (i, (_, arm_t, key_handle, session)) in arms.iter().enumerate() {
                let workers: Vec<_> = (0..args.threads)
                    .map(|_| {
                        let t = Arc::clone(arm_t);
                        let (session, key_handle, kem, label) = (*session, *key_handle, cell.kem, cell.label);
                        move || -> Result<()> {
                            if kem {
                                t.encapsulate(session, key_handle, label).map(|_| ())
                            } else {
                                t.sign(session, key_handle, label, b"bench").map(|_| ())
                            }
                        }
                    })
                    .collect();
                let (total_ops, latencies, elapsed) =
                    crate::measure::run_point(args.duration_secs, args.warmup_secs, workers)?;
                let (p50, p99) = crate::measure::percentiles_ms(latencies);
                samples[i].push((total_ops as f64 / elapsed, p50, p99, total_ops, elapsed));
            }
        }

        for (i, (arm_label, _, _, _)) in arms.iter().enumerate() {
            let mut by_rate = samples[i].clone();
            by_rate.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
            let (ops_per_sec, p50, p99, total_ops, elapsed) = by_rate[by_rate.len() / 2];
            let row = TransportRow {
                access_path: "pkcs11-remote",
                protocol: protocol_label,
                connection_model: model,
                tls: arm_label,
                algorithm: cell.label,
                category,
                op,
                threads: args.threads,
                ops_per_sec,
                ops_per_sec_min: by_rate.first().unwrap().0,
                ops_per_sec_max: by_rate.last().unwrap().0,
                repeats: args.repeats.max(1),
                interleaved: arms.len() > 1,
                p50_ms: p50,
                p99_ms: p99,
                duration_s: elapsed,
                total_ops,
                round_trips_per_op: round_trips,
            };
            println!("{}", serde_json::to_string(&row)?);
        }
    }
    Ok(())
}
