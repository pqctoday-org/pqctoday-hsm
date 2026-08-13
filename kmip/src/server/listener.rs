//! TLS-terminated KMIP listener — Phase 7.
//!
//! Per-connection: TLS handshake → read one Request Message → dispatch →
//! write Response Message → close. v0.1 ships one-request-per-connection
//! semantics; KMIP-batch multi-op-per-connection deferred to v0.2.
//!
//! ## TLS bootstrap
//!
//! - **`--tls-cert <pem> --tls-key <pem>`** → load from disk (production).
//! - **omitted** → auto-generate a self-signed Ed25519 cert for sandbox/dev.
//!   Cert is in-memory only; never written to disk. Logged at startup so the
//!   operator can copy the fingerprint into a `verify=False` client config.
//!
//! ## Frame reading
//!
//! KMIP TTLV is self-describing: the first 8 bytes of any frame carry the
//! length (bytes 4-7, big-endian u32 = value length). We read 8 bytes,
//! parse the value length, then read `value_length` bytes + padding-to-8.
//! The full TTLV codec handles decode.

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use crate::dispatcher::dispatch_with_transport_identity;
use crate::kmip30::{decode_request_message, encode_response_message, WireError};
use crate::ops::Deps;

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS: {0}")]
    Tls(String),
    #[error("KMIP wire: {0}")]
    Wire(#[from] WireError),
    #[error("rcgen cert: {0}")]
    Rcgen(String),
}

/// Which TLS posture the listener enforces.
///
/// KMIP 3.0 Profiles §3.3 ("Quantum Safe Authentication Suite") is not a
/// preference — it is a set of SHALL / SHALL NOT clauses. [`TlsProfile::QuantumSafe`]
/// enforces them; [`TlsProfile::Permissive`] is the historical behaviour and
/// stays the default so existing callers (kms-proxy, sandbox scenario 22, the
/// wasm playground) are unaffected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsProfile {
    /// rustls defaults: TLS 1.2 + 1.3, the full default suite and group lists.
    #[default]
    Permissive,
    /// KMIP 3.0 Profiles §3.3 — TLS 1.3 only, §3.3.2 suites only, §3.3.3
    /// hybrid ML-KEM groups only. See [`quantum_safe_provider`] for the
    /// documented gap against §3.3.3.
    QuantumSafe,
    /// **Measurement baseline only — not a deployment posture.**
    ///
    /// Identical to [`TlsProfile::QuantumSafe`] in every respect except the
    /// key exchange groups: same aws-lc-rs provider, same TLS 1.3
    /// restriction, same two §3.3.2 cipher suites — but CLASSICAL groups
    /// instead of hybrid ML-KEM.
    ///
    /// It exists because comparing `Permissive` against `QuantumSafe` does
    /// not measure post-quantum key exchange: `Permissive` runs on `ring`
    /// and `QuantumSafe` on aws-lc-rs, so that comparison varies the crypto
    /// PROVIDER too. Measured 2026-08-09 it read as "PQC TLS is 46% faster
    /// than classical", which is a provider difference wearing a migration
    /// costume. Against this profile, the only thing that changes is the
    /// group — so the difference is the premium.
    ClassicalBaseline,
}

impl TlsProfile {
    /// Parse the `--tls-profile` CLI value. Kept here rather than in the
    /// binary so the accepted spellings live next to the enum they select.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "permissive" => Ok(Self::Permissive),
            "quantum-safe" | "quantum_safe" => Ok(Self::QuantumSafe),
            "classical-baseline" | "classical_baseline" => Ok(Self::ClassicalBaseline),
            other => Err(format!(
                "unknown TLS profile {other:?} (expected 'permissive', 'quantum-safe' \
                 or 'classical-baseline')"
            )),
        }
    }
}

/// The §3.3 crypto provider: aws-lc-rs restricted to exactly the cipher
/// suites and key exchange groups the Quantum Safe Authentication Suite
/// permits.
///
/// **aws-lc-rs, not `ring`.** `ring` has no ML-KEM at all, so under it no
/// hybrid group can be negotiated and §3.3.3 is unreachable. aws-lc-rs is
/// already linked (see `Cargo.toml`'s rustls features and rcgen's own
/// dependency), so this selects between providers already present rather
/// than adding one.
///
/// **§3.3.3 is met in full as of 2026-08-12.** The clause requires servers to
/// support `X25519MLKEM768`, `SecP256r1MLKEM768` *and* `SecP384r1MLKEM1024`,
/// and to offer nothing outside that list. rustls 0.23.40 ships only the first
/// two — `0x11ed` has no `NamedGroup` variant and the generic `Hybrid`
/// combinator is in a private module — so the third is composed downstream in
/// [`crate::server::secp384r1mlkem1024`] from the two halves rustls *does*
/// export publicly (`kx_group::SECP384R1`, `kx_group::MLKEM1024`) via the
/// public `hybrid_component()` seams. Its wire format and combiner order are
/// proven against OpenSSL 3.6 in `tests/secp384r1mlkem1024_interop.rs`, not
/// merely against itself. Classical groups are absent entirely, as the clause
/// requires — they are not merely deprioritised.
///
/// §3.3.2 is met in full: exactly `TLS13_CHACHA20_POLY1305_SHA256` and
/// `TLS13_AES_256_GCM_SHA384`. Note this deliberately drops
/// `TLS13_AES_128_GCM_SHA256`, which the clause forbids and which is
/// otherwise on by default.
pub fn quantum_safe_provider() -> rustls::crypto::CryptoProvider {
    use rustls::crypto::aws_lc_rs;
    rustls::crypto::CryptoProvider {
        cipher_suites: vec![
            aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
            aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
        ],
        kx_groups: vec![
            aws_lc_rs::kx_group::X25519MLKEM768,
            aws_lc_rs::kx_group::SECP256R1MLKEM768,
            crate::server::secp384r1mlkem1024::SECP384R1MLKEM1024,
        ],
        ..aws_lc_rs::default_provider()
    }
}

/// The measurement baseline's provider: [`quantum_safe_provider`] with the
/// hybrid groups swapped for classical ones. Everything else — provider,
/// suites — is deliberately identical, so a comparison isolates the group.
pub fn classical_baseline_provider() -> rustls::crypto::CryptoProvider {
    use rustls::crypto::aws_lc_rs;
    rustls::crypto::CryptoProvider {
        kx_groups: vec![aws_lc_rs::kx_group::X25519, aws_lc_rs::kx_group::SECP256R1],
        ..quantum_safe_provider()
    }
}

/// Human-readable summary of what a profile actually enforces, for the
/// startup log. An operator should be able to see the groups and suites in
/// force without reading this file.
pub fn tls_profile_summary(profile: TlsProfile) -> String {
    match profile {
        TlsProfile::Permissive => {
            "permissive (rustls defaults: TLS1.2+1.3, default suites and groups)".to_string()
        }
        TlsProfile::ClassicalBaseline => {
            "classical-baseline (MEASUREMENT ONLY, not a deployment posture): \
             TLS1.3 only; same suites and provider as quantum-safe; groups \
             X25519, SecP256r1 — exists so a PQC-TLS premium isolates the \
             key exchange group rather than the crypto provider"
                .to_string()
        }
        TlsProfile::QuantumSafe => {
            "quantum-safe (KMIP 3.0 §3.3): TLS1.3 only; suites \
             TLS13_CHACHA20_POLY1305_SHA256, TLS13_AES_256_GCM_SHA384; \
             groups X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024 \
             [all three §3.3.3 groups; SecP384r1MLKEM1024 composed locally, \
             OpenSSL-3.6-interop-proven]"
                .to_string()
        }
    }
}

/// The one place a `ServerConfig` builder is created, so every TLS entry
/// point below gets the same posture.
///
/// This function existing at all is the point: there are three public config
/// constructors ([`tls_from_pem`], [`tls_self_signed`], [`tls_mtls`]) and
/// which one runs depends on startup flags. Enforcing the profile in each of
/// them separately would mean a server that is quantum-safe or not depending
/// on how it was launched — an intermittent, configuration-dependent gap.
fn profile_builder(
    profile: TlsProfile,
) -> Result<rustls::ConfigBuilder<ServerConfig, rustls::WantsVerifier>, ServerError> {
    match profile {
        TlsProfile::Permissive => {
            install_crypto_provider();
            Ok(ServerConfig::builder())
        }
        TlsProfile::ClassicalBaseline => {
            ServerConfig::builder_with_provider(Arc::new(classical_baseline_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|e| ServerError::Tls(format!("classical-baseline TLS setup: {e}")))
        }
        TlsProfile::QuantumSafe => {
            // Explicit provider rather than the process-wide default: the
            // default may already have been installed as `ring` by another
            // code path, and install_default() is first-call-wins.
            ServerConfig::builder_with_provider(Arc::new(quantum_safe_provider()))
                // §3.3.1 — TLS 1.3 only. TLS 1.2 and below are a SHALL NOT,
                // so this is a restriction, not a minimum version.
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|e| ServerError::Tls(format!("quantum-safe TLS setup: {e}")))
        }
    }
}

/// Build a `rustls::ServerConfig` from on-disk PEM cert + key, under the
/// historical permissive posture. Prefer [`tls_from_pem_with_profile`].
pub fn tls_from_pem(cert_pem_path: &Path, key_pem_path: &Path) -> Result<Arc<ServerConfig>, ServerError> {
    tls_from_pem_with_profile(cert_pem_path, key_pem_path, TlsProfile::Permissive)
}

/// Build a `rustls::ServerConfig` from on-disk PEM cert + key.
pub fn tls_from_pem_with_profile(
    cert_pem_path: &Path,
    key_pem_path: &Path,
    profile: TlsProfile,
) -> Result<Arc<ServerConfig>, ServerError> {
    let cert_bytes = std::fs::read(cert_pem_path)?;
    let key_bytes = std::fs::read(key_pem_path)?;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &cert_bytes[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ServerError::Tls(format!("cert: {e}")))?;
    let key = rustls_pemfile::private_key(&mut &key_bytes[..])
        .map_err(|e| ServerError::Tls(format!("key: {e}")))?
        .ok_or_else(|| ServerError::Tls("no private key in PEM".into()))?;
    let config = profile_builder(profile)?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| ServerError::Tls(e.to_string()))?;
    Ok(Arc::new(config))
}

/// Install the `ring` crypto provider as rustls' default. Required when
/// multiple providers are linked (rcgen's `aws_lc_rs` + rustls' `ring`).
/// Idempotent — subsequent calls are no-ops.
///
/// Applies to [`TlsProfile::Permissive`] only. The quantum-safe profile
/// passes an aws-lc-rs provider explicitly instead of relying on this
/// process-wide default, because `ring` cannot negotiate ML-KEM hybrids at
/// all and `install_default()` is first-call-wins — whichever path ran first
/// would otherwise decide the posture.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Generate a self-signed Ed25519 server cert in memory and build a
/// `ServerConfig`. Sandbox / dev only — production should pass real PEM
/// via [`tls_from_pem`]. Returns the config + the PEM-encoded cert so the
/// caller can log the fingerprint for clients to pin.
pub fn tls_self_signed(common_name: &str) -> Result<(Arc<ServerConfig>, String), ServerError> {
    tls_self_signed_with_profile(common_name, TlsProfile::Permissive)
}

/// As [`tls_self_signed`], under an explicit TLS profile.
pub fn tls_self_signed_with_profile(
    common_name: &str,
    profile: TlsProfile,
) -> Result<(Arc<ServerConfig>, String), ServerError> {
    let subject_alt_names = vec![common_name.to_string(), "localhost".to_string()];
    let cert = rcgen::generate_simple_self_signed(subject_alt_names)
        .map_err(|e| ServerError::Rcgen(e.to_string()))?;
    let cert_pem = cert.cert.pem();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der: PrivateKeyDer<'static> =
        PrivateKeyDer::try_from(cert.key_pair.serialize_der())
            .map_err(|e| ServerError::Tls(format!("key: {e}")))?;
    let config = profile_builder(profile)?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|e| ServerError::Tls(e.to_string()))?;
    Ok((Arc::new(config), cert_pem))
}

/// Build a `ServerConfig` that requires client certificates signed by
/// the supplied CA bundle (mTLS). K14 wires this behind the
/// `--tls-client-ca <pem>` flag in `bin/pqctoday-kmip.rs`; when active,
/// [`handle_conn`] maps the verified client certificate's subject CN to
/// the KMIP [`super::auth::Identity`], which satisfies configured
/// authentication (see `dispatcher::authenticate_request`).
pub fn tls_mtls(
    server_cert_pem: &[u8],
    server_key_pem: &[u8],
    client_ca_pem: &[u8],
) -> Result<Arc<ServerConfig>, ServerError> {
    tls_mtls_with_profile(
        server_cert_pem,
        server_key_pem,
        client_ca_pem,
        TlsProfile::Permissive,
    )
}

/// As [`tls_mtls`], under an explicit TLS profile.
pub fn tls_mtls_with_profile(
    server_cert_pem: &[u8],
    server_key_pem: &[u8],
    client_ca_pem: &[u8],
    profile: TlsProfile,
) -> Result<Arc<ServerConfig>, ServerError> {
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &server_cert_pem[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ServerError::Tls(format!("server cert: {e}")))?;
    let key = rustls_pemfile::private_key(&mut &server_key_pem[..])
        .map_err(|e| ServerError::Tls(format!("server key: {e}")))?
        .ok_or_else(|| ServerError::Tls("no server private key".into()))?;
    let mut root_store = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut &client_ca_pem[..]) {
        root_store
            .add(cert.map_err(|e| ServerError::Tls(format!("client CA: {e}")))?)
            .map_err(|e| ServerError::Tls(format!("root store add: {e}")))?;
    }
    // `builder_with_provider`, NOT `builder`. The plain builder resolves the
    // PROCESS-LEVEL default provider and panics outright when it cannot
    // ("Could not automatically determine the process-level CryptoProvider")
    // — exactly what happens here, because the verifier is built BEFORE
    // `profile_builder` runs: the quantum-safe path never installs a process
    // default at all (it passes its provider explicitly), and the permissive
    // path installs one too late to help. Confirmed live: every mTLS start
    // aborted on this before the fix.
    //
    // Passing the profile's own provider also keeps client-certificate
    // verification on the same crypto as the handshake, rather than on
    // whichever provider happened to win the install_default() race.
    let verifier_provider = Arc::new(match profile {
        TlsProfile::Permissive => rustls::crypto::ring::default_provider(),
        TlsProfile::QuantumSafe => quantum_safe_provider(),
        TlsProfile::ClassicalBaseline => classical_baseline_provider(),
    });
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(root_store), verifier_provider)
            .build()
            .map_err(|e| ServerError::Tls(e.to_string()))?;
    let config = profile_builder(profile)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|e| ServerError::Tls(e.to_string()))?;
    Ok(Arc::new(config))
}

/// Bind a TLS listener on `addr` and serve forever. Each connection
/// reads one Request Message, dispatches, writes the Response Message,
/// closes.
pub async fn serve(addr: SocketAddr, tls: Arc<ServerConfig>, deps: Arc<Deps>) -> Result<(), ServerError> {
    let listener = TcpListener::bind(addr).await?;
    let acceptor = TlsAcceptor::from(tls);
    tracing::info!("KMIP server listening on {addr}");
    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let deps = Arc::clone(&deps);
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, acceptor, deps).await {
                tracing::warn!("conn {peer} closed with error: {e}");
            }
        });
    }
}

async fn handle_conn(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    deps: Arc<Deps>,
) -> Result<(), ServerError> {
    let mut tls_stream = acceptor.accept(stream).await.map_err(ServerError::Io)?;
    crate::metrics::record_tls_handshake("kmip");
    // K14 mTLS — when the ServerConfig was built by [`tls_mtls`], the
    // handshake above already verified the client certificate chain
    // against the configured CA. Map the leaf's subject CN to the KMIP
    // identity (reuses the §11 Certificate-attribute DER parser). A
    // CA-verified cert without a CN yields no identity — connection
    // still serves, but configured auth then requires a header
    // Credential. Plain-TLS configs have no peer certificates → `None`.
    let transport_identity = tls_stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first())
        .and_then(|der| crate::ops::der_x509::extract_subject_cn(der.as_ref()))
        .map(|cn| crate::server::auth::Identity { username: cn });
    let identity_for_push = transport_identity.clone();
    let frame_bytes = read_one_frame(&mut tls_stream).await?;
    // §9.10 `Maximum Response Size` enforcement now lives inside
    // `dispatch_with_transport_identity` itself (`enforce_max_response_size`,
    // transport-agnostic — the wasm `submit()` entry point applies the same
    // check), so the response coming back here is already correctly capped.
    let response = match decode_request_message(&frame_bytes) {
        Ok(request) => {
            // S-8 — the dispatch is synchronous and does real crypto (ML-DSA /
            // ML-KEM, plus the engine's global mutex). Run it on the blocking
            // pool so a slow op can't stall the tokio reactor and starve other
            // connections.
            let deps = Arc::clone(&deps);
            tokio::task::spawn_blocking(move || {
                dispatch_with_transport_identity(&deps, request, transport_identity)
            })
            .await
            .map_err(|e| ServerError::Io(std::io::Error::other(format!("dispatch task failed: {e}"))))?
        }
        // KMIP 3.0: a wire-decode failure (unknown tag, unknown enum value,
        // malformed length, etc.) must produce a structured
        // `OperationFailed` response with `ResultReason = InvalidMessage`
        // (see the Result Reason Enumeration's "Invalid Message" member,
        // used across the per-op Error Handling tables) — NOT a TCP/TLS
        // connection drop. Closing the socket without a response makes the
        // client see a transport error instead of a proper protocol-level
        // rejection (and breaks OASIS conformance). No single spec section
        // states this general policy explicitly under either the CSD01 or
        // WD19 baseline (checked both, 2026-07-23) — the "§6.4" citation
        // this comment used to carry didn't exist and was removed rather
        // than replaced with another guess.
        Err(e) => wire_error_response(&e),
    };
    // Did the client just hand us the server role on this channel? §6.1.61 says
    // the swap applies to "the current client-to-server communication channel"
    // and that it "remains as established" — so the decision is made from the
    // response we are about to send, and acted on right here rather than
    // through any global state.
    //
    // The auth gate lives in the op handler (which sees the verified identity);
    // reaching Success at all therefore means the caller was authenticated.
    let flip_to_push = endpoint_role_handed_over(&response);

    let response_bytes = encode_response_message(&response);
    tls_stream.write_all(&response_bytes).await?;

    if flip_to_push {
        // The identity whose objects we may talk about. Credential-authenticated
        // callers are covered by the op-handler gate; for the push scope we use
        // the transport identity when there is one, and otherwise the
        // credential the request carried.
        let owner = identity_for_push
            .map(|i| i.username)
            .or_else(|| credential_username(&frame_bytes));
        serve_pushes(&mut tls_stream, &deps, &owner).await?;
    }

    tls_stream.shutdown().await?;
    Ok(())
}

/// True when this response is a successful `Set Endpoint Role` that put the
/// SERVER into the client role — i.e. the point at which this connection
/// reverses direction.
fn endpoint_role_handed_over(response: &crate::kmip30::ResponseMessage) -> bool {
    use crate::kmip30::{EndpointRole, Operation, ResponsePayload, ResultStatus};
    response.batch_items.iter().any(|item| {
        item.operation == Some(Operation::SetEndpointRole)
            && item.result_status == ResultStatus::Success
            && matches!(
                &item.payload,
                Some(ResponsePayload::SetEndpointRole(r)) if r.endpoint_role == EndpointRole::Client
            )
    })
}

/// Recover the username from a request's §8.1.2 Authentication header, for
/// scoping pushes on a credential-authenticated (non-mTLS) connection.
fn credential_username(frame_bytes: &[u8]) -> Option<String> {
    use crate::kmip30::Credential;
    let request = decode_request_message(frame_bytes).ok()?;
    request.header.authentication.iter().find_map(|c| match c {
        Credential::UsernameAndPassword { username, .. } => Some(username.clone()),
        _ => None,
    })
}

/// Serve §6.2 server-to-client messages on a channel whose roles have been
/// swapped, until the queue drains or the peer goes away.
///
/// Each message is a REQUEST from the server, and §6.2.2/§6.2.3 both say the
/// client "SHALL send a response … containing no payload", so this reads that
/// acknowledgement before sending the next one. Draining without waiting would
/// make delivery unobservable and turn a dead peer into silent data loss.
async fn serve_pushes<S>(
    stream: &mut S,
    deps: &Arc<Deps>,
    owner: &Option<String>,
) -> Result<(), ServerError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let now = time::OffsetDateTime::now_utc().unix_timestamp();

    // ── Negotiate, once per swapped session ────────────────────────────────
    //
    // Three server-issued requests round-trip before the first push. Doing this
    // per notification would add three round trips to every attribute change,
    // which for a queue that is usually one or two deep would be a real
    // regression for no information gained — the answers cannot change mid
    // session.
    let endpoint = negotiate_push_endpoint(stream, now).await;

    if !endpoint.version_compatible {
        // Nothing we send can be parsed by this peer. Pushing anyway would be
        // writing bytes we know to be undecodable, which is worse than silence:
        // the queue would drain into a peer that cannot act on it.
        tracing::info!(target: "kmip::push",
            "push endpoint speaks no version this server does; not pushing");
        return Ok(());
    }

    let pending = deps.drain_notifications(owner);
    if pending.is_empty() {
        // Still hand the role back — the peer asked to receive, and "nothing for
        // you" is a better answer than a dropped connection.
        hand_role_back(stream, now).await;
        return Ok(());
    }

    for notify in pending {
        if !endpoint.supports(crate::kmip30::Operation::Notify) {
            tracing::debug!(target: "kmip::push", uid = %notify.unique_identifier,
                "endpoint does not advertise Notify; dropping without sending");
            continue;
        }
        let uid = notify.unique_identifier.clone();
        let bytes = crate::kmip30::wire::encode_notify_message(&notify, now);
        stream.write_all(&bytes).await?;
        // Read the client's acknowledgement. A peer that closes instead of
        // answering is not an error worth failing the connection over — it is
        // exactly the "prior knowledge that the client is not able to respond"
        // case §6.2.2 allows — but we stop pushing, because continuing to write
        // into a closed socket proves nothing.
        match read_one_frame(stream).await {
            Ok(_ack) => {
                tracing::debug!(target: "kmip::push", uid = %uid, "Notify acknowledged");
            }
            Err(e) => {
                tracing::debug!(target: "kmip::push", uid = %uid, error = %e,
                    "client did not acknowledge; stopping pushes on this channel");
                return Ok(());
            }
        }
    }

    hand_role_back(stream, now).await;
    Ok(())
}

/// What the peer at the far end of a swapped channel told us about itself.
#[derive(Debug)]
struct PushEndpoint {
    /// False only when the peer answered `Discover Versions` with a list that
    /// shares nothing with [`supported_versions`]. An unanswered question
    /// leaves this true — see [`negotiate_push_endpoint`].
    version_compatible: bool,
    /// `None` when the peer did not answer `Query`, which means "unknown", not
    /// "nothing".
    advertised_operations: Option<Vec<crate::kmip30::Operation>>,
}

impl PushEndpoint {
    /// Permissive on silence, restrictive on an actual answer.
    ///
    /// A peer that answers and omits an operation is telling us it cannot
    /// service it, and we believe it. A peer that says nothing may simply be an
    /// implementation of §6.2 alone — which is legal, since §6.2.2 contemplates
    /// clients that cannot respond at all — and denying it the notifications it
    /// *can* handle would be inventing a requirement the spec does not make.
    fn supports(&self, op: crate::kmip30::Operation) -> bool {
        match &self.advertised_operations {
            Some(ops) => ops.contains(&op),
            None => true,
        }
    }
}

/// Ask the peer what it speaks and what it can do (§6.1.21, §6.1.39, issued by
/// the server — two of item 10's five operations).
///
/// Both questions tolerate silence. A peer that treats our request as an opaque
/// push and returns the §6.2 empty acknowledgement, or that closes, is recorded
/// as "unknown" rather than "incapable": the alternative is to withhold
/// notifications from a conformant §6.2-only client on the strength of a
/// question it never agreed to answer.
async fn negotiate_push_endpoint<S>(stream: &mut S, now: i64) -> PushEndpoint
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use crate::kmip30::wire::ClientResponsePayload;

    let mut endpoint =
        PushEndpoint { version_compatible: true, advertised_operations: None };

    // §6.1.21 — an empty request list means "tell me everything you have".
    let ask = crate::kmip30::wire::encode_discover_versions_message(&[], now);
    if let Some(resp) = ask_endpoint(stream, &ask).await {
        if let ClientResponsePayload::DiscoverVersions(theirs) = resp.payload {
            let ours = crate::ops::lifecycle_and_protocol::supported_versions();
            endpoint.version_compatible = theirs.iter().any(|v| ours.contains(v));
            tracing::debug!(target: "kmip::push",
                theirs = ?theirs, compatible = endpoint.version_compatible,
                "push endpoint declared its protocol versions");
        }
    }
    if !endpoint.version_compatible {
        return endpoint;
    }

    // §6.1.39 — only the operation list bears on what we may push.
    let ask = crate::kmip30::wire::encode_query_message(
        &[crate::kmip30::QueryFunction::QueryOperations],
        now,
    );
    if let Some(resp) = ask_endpoint(stream, &ask).await {
        if let ClientResponsePayload::Query(ops) = resp.payload {
            tracing::debug!(target: "kmip::push", ops = ?ops,
                "push endpoint declared its operations");
            endpoint.advertised_operations = Some(ops);
        }
    }

    endpoint
}

/// Write one server-issued request and read the peer's answer, mapping any
/// transport or decode failure to `None` ("it did not tell us").
async fn ask_endpoint<S>(
    stream: &mut S,
    request: &[u8],
) -> Option<crate::kmip30::wire::ClientResponse>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    if stream.write_all(request).await.is_err() {
        return None;
    }
    let frame = read_one_frame(stream).await.ok()?;
    crate::kmip30::wire::decode_client_response(&frame).ok()
}

/// End the swapped session the way §6.1.61 began it, rather than by hanging up.
///
/// The field names the role the *recipient* is to apply, which is why both
/// directions carry `Client`: the client's original request put us into the
/// client role, and this one puts the peer back into it — leaving us the server
/// again. Failures are logged and swallowed: the session is over either way,
/// and the connection is about to be shut down.
async fn hand_role_back<S>(stream: &mut S, now: i64)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use crate::kmip30::EndpointRole;
    let bytes =
        crate::kmip30::wire::encode_set_endpoint_role_message(EndpointRole::Client, now);
    if stream.write_all(&bytes).await.is_err() {
        tracing::debug!(target: "kmip::push", "peer gone before the role could be handed back");
        return;
    }
    match read_one_frame(stream).await {
        Ok(_) => tracing::debug!(target: "kmip::push", "server role handed back; session closed"),
        Err(e) => tracing::debug!(target: "kmip::push", error = %e,
            "peer did not confirm the role handback"),
    }
}

/// Build a KMIP 3.0 error ResponseMessage for an unparseable request (see
/// `handle_conn`'s error arm above for why there's no single spec section
/// to cite here).
///
/// Used when our codec can't decode the inbound frame — e.g. unknown
/// algorithm enum value, missing required field, malformed Structure
/// length. The spec requires us to still respond on the same connection
/// so the client gets a `ResultReason` rather than a dangling socket.
fn wire_error_response(err: &WireError) -> crate::kmip30::ResponseMessage {
    use crate::error::ResultReason;
    use crate::kmip30::{ResponseBatchItem, ResponseHeader, ResponseMessage, ResultStatus};
    // KMIP 3.0 §11 — a recognisable-but-unsupported ProtocolVersion is
    // `Unsupported Protocol Version` (0x3f), not `Invalid Message` (0x04)
    // which is reserved for genuinely malformed frames (K1, finding K-3).
    let reason = match err {
        WireError::UnsupportedVersion { .. } => ResultReason::UnsupportedProtocolVersion,
        _ => ResultReason::InvalidMessage,
    };
    ResponseMessage {
        header: ResponseHeader::v3_now(),
        batch_items: vec![ResponseBatchItem {
            operation: None,
            result_status: ResultStatus::OperationFailed,
            result_reason: Some(reason as u32),
            result_message: Some(format!("KMIP wire decode failed: {err}")),
            payload: None,
            asynchronous_correlation_value: None,
        }],
    }
}

/// S-4 — upper bound on a single inbound TTLV frame. The 32-bit length prefix is
/// attacker-controlled and read BEFORE any TTLV validation, so without a cap a
/// single 8-byte header advertising ~4 GiB triggers a ~4 GiB pre-auth
/// allocation. 16 MiB comfortably covers real KMIP requests (key material /
/// certs are KB-scale) while bounding the amplification.
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

fn frame_too_large(length: usize) -> ServerError {
    ServerError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("KMIP frame length {length} exceeds {MAX_FRAME_BYTES}-byte cap"),
    ))
}

/// Read exactly one TTLV frame from `stream`. KMIP §9.6 frame layout:
///   bytes 0-2  : tag (3 BE bytes)
///   byte 3     : item type
///   bytes 4-7  : length (BE u32 = value bytes, NOT counting padding)
///   bytes 8+   : value bytes + zero-padding to 8-byte boundary
async fn read_one_frame<S>(stream: &mut S) -> Result<Vec<u8>, ServerError>
where
    S: AsyncReadExt + Unpin,
{
    let mut header = [0u8; 8];
    stream.read_exact(&mut header).await?;
    let length = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(frame_too_large(length));
    }
    let padded = (length + 7) & !7;
    let mut value = vec![0u8; padded];
    if padded > 0 {
        stream.read_exact(&mut value).await?;
    }
    let mut full = Vec::with_capacity(8 + padded);
    full.extend_from_slice(&header);
    full.extend_from_slice(&value);
    Ok(full)
}

// ── Sync read helper for synchronous-client testing ─────────────────────────

/// Read one TTLV frame from a synchronous stream. Used by the synchronous
/// integration-test harness; production servers use [`read_one_frame`].
pub fn read_one_frame_sync<R: Read>(reader: &mut R) -> Result<Vec<u8>, ServerError> {
    let mut header = [0u8; 8];
    reader.read_exact(&mut header)?;
    let length = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(frame_too_large(length));
    }
    let padded = (length + 7) & !7;
    let mut value = vec![0u8; padded];
    if padded > 0 {
        reader.read_exact(&mut value)?;
    }
    let mut full = Vec::with_capacity(8 + padded);
    full.extend_from_slice(&header);
    full.extend_from_slice(&value);
    Ok(full)
}

/// Write one TTLV frame to a synchronous stream.
pub fn write_frame_sync<W: Write>(writer: &mut W, frame: &[u8]) -> Result<(), ServerError> {
    writer.write_all(frame)?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// K14 — the mTLS ServerConfig builds from PEM inputs (server cert
    /// + key + client CA bundle) and requires client certificates.
    #[test]
    fn mtls_config_builds_with_client_ca() {
        install_crypto_provider();
        // Server identity (existing self-signed helper).
        let server = rcgen::generate_simple_self_signed(vec!["kmip.test".to_string()])
            .expect("server cert");
        let server_cert_pem = server.cert.pem();
        let server_key_pem = server.key_pair.serialize_pem();
        // Client CA (CA:TRUE so webpki accepts it as a trust anchor).
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().expect("ca key");
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");
        let cfg = tls_mtls(
            server_cert_pem.as_bytes(),
            server_key_pem.as_bytes(),
            ca_cert.pem().as_bytes(),
        )
        .expect("mTLS ServerConfig");
        assert!(Arc::strong_count(&cfg) >= 1);
    }

    /// K14 — the identity mapping reuses the §11 DER parser: a client
    /// cert's subject CN is what `handle_conn` turns into the KMIP
    /// `Identity`.
    #[test]
    fn mtls_client_cert_subject_cn_extracts_for_identity_mapping() {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "kmip-client-7");
        let key = rcgen::KeyPair::generate().expect("key");
        let cert = params.self_signed(&key).expect("cert");
        let cn = crate::ops::der_x509::extract_subject_cn(cert.der().as_ref());
        assert_eq!(cn.as_deref(), Some("kmip-client-7"));
    }

    #[test]
    fn self_signed_tls_config_builds() {
        let (cfg, pem) = tls_self_signed("kmip.test").expect("self-signed cert");
        assert!(pem.contains("BEGIN CERTIFICATE"));
        assert!(Arc::strong_count(&cfg) >= 1);
    }

    #[test]
    fn read_one_frame_sync_round_trips_known_ttlv() {
        use crate::codec::{encode, Tag, TtlvFrame, Value};
        use bytes::BytesMut;
        let frame = TtlvFrame::new(Tag(0x42_0001), Value::Integer(42));
        let mut buf = BytesMut::new();
        encode(&frame, &mut buf);
        let wire = buf.to_vec();
        let mut cursor = std::io::Cursor::new(wire.clone());
        let read_back = read_one_frame_sync(&mut cursor).unwrap();
        assert_eq!(read_back, wire);
    }

    /// K1 — protocol-version mismatch yields `Unsupported Protocol
    /// Version` (0x3f), while a malformed frame stays `Invalid
    /// Message` (0x04).
    #[test]
    fn wire_error_response_reason_codes() {
        use crate::error::ResultReason;
        let resp = wire_error_response(&WireError::UnsupportedVersion { major: 2, minor: 1 });
        assert_eq!(
            resp.batch_items[0].result_reason,
            Some(ResultReason::UnsupportedProtocolVersion as u32)
        );
        assert_eq!(
            resp.batch_items[0].result_reason,
            Some(0x0000_003f),
            "Unsupported Protocol Version codepoint per OASIS enums JSON"
        );
        let resp = wire_error_response(&WireError::Missing {
            tag: 0x42_0077,
            name: "Request Header",
        });
        assert_eq!(
            resp.batch_items[0].result_reason,
            Some(ResultReason::InvalidMessage as u32)
        );
    }
}
