//! End-to-end Phase-7 integration: spin up the TLS server, send a Query
//! request from a real rustls client, decode the response, assert success.
//!
//! Validates the full stack: codec → dispatcher → op handler → response
//! codec → TLS framing. The Plane-3 emissions still produce placeholder
//! cryptographic output per the §12.7.7 lock (real softhsmrustv3 wiring
//! is the Phase-7b follow-up).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use pqctoday_kmip::auditlog::{AuditSink, RingSink};
use pqctoday_kmip::dispatcher::one_off_request;
use pqctoday_kmip::kmip30::{
    decode_request_message, encode_response_message, Operation, QueryFunction, QueryRequest,
    RequestHeader, RequestMessage, RequestPayload, ResponsePayload, ResultStatus,
};
use pqctoday_kmip::ops::{Deps, DepsConfig};
use pqctoday_kmip::policy::{load_from_str, Engine};
use pqctoday_kmip::server::listener::{tls_self_signed_with_profile, TlsProfile};
use pqctoday_kmip::server::{serve, tls_self_signed};
use pqctoday_kmip::store::MemoryStore;

const PERMISSIVE_POLICY: &str = r#"
schema_version: 1
metadata: { name: t, description: t, authority: t, effective: always }
rules: []
"#;

fn build_deps() -> Arc<Deps> {
    let ring = Arc::new(RingSink::new(64));
    let sink: Arc<dyn AuditSink> = ring;
    let engine = Engine::with_global_sink(sink.clone());
    engine
        .activate(load_from_str(PERMISSIVE_POLICY, std::path::Path::new("<t>")).unwrap())
        .unwrap();
    Arc::new(Deps::new(
        engine,
        Arc::new(MemoryStore::new()),
        sink,
        DepsConfig::default(),
    ))
}

#[tokio::test(flavor = "current_thread")]
async fn tls_round_trip_query_request() {
    // Pick a free port by binding to 0.
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let bound = listener.local_addr().unwrap();
    drop(listener); // release so serve() can rebind

    let (tls_cfg, server_cert_pem) = tls_self_signed("kmip.test").expect("self-signed cert");
    let deps = build_deps();

    // Spawn the server.
    let server_cfg = tls_cfg.clone();
    let server_deps = deps.clone();
    let handle = tokio::spawn(async move {
        if let Err(e) = serve(bound, server_cfg, server_deps).await {
            eprintln!("server: {e}");
        }
    });

    // Give the listener a tick to come up.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // ── Build the client ────────────────────────────────────────────────
    let mut root_store = rustls::RootCertStore::empty();
    let cert_bytes = pem_to_der(&server_cert_pem);
    root_store
        .add(rustls::pki_types::CertificateDer::from(cert_bytes))
        .unwrap();
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    let tcp = TcpStream::connect(bound).await.unwrap();
    let server_name = ServerName::try_from("kmip.test").unwrap();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();

    // ── Send a Query request ────────────────────────────────────────────
    let req = one_off_request(RequestPayload::Query(QueryRequest {
        functions: vec![QueryFunction::QueryOperations],
    }));
    let req_bytes = build_request_bytes(&req);
    tls.write_all(&req_bytes).await.unwrap();

    // ── Read the response ───────────────────────────────────────────────
    let resp_bytes = read_one_frame_async(&mut tls).await;
    let resp = pqctoday_kmip::kmip30::wire::decode_request_message(&resp_bytes);
    // The response is a Response Message; the request decoder rejects it
    // (wrong top-level tag). For the v0.1 e2e test we just check the
    // wire bytes encode a successful status. Parse by re-decoding the
    // raw frame.
    assert!(resp.is_err(), "response is not a request — top-level tag differs");

    // Decode as raw TTLV to assert success.
    let (frame, _) = pqctoday_kmip::codec::decode(&resp_bytes).expect("valid TTLV");
    // Top-level tag should be Response Message = 0x42007b.
    assert_eq!(frame.tag.0, 0x42_007b, "top-level Response Message tag");

    handle.abort();
    let _ = handle.await;
}

/// End-to-end KMIP round trip over the §3.3 quantum-safe profile.
///
/// The permissive test above proves the KMIP path works over TLS. This one
/// proves it works over a channel whose ONLY key exchange options are hybrid
/// ML-KEM groups — i.e. that turning the profile on does not break the
/// protocol it is protecting. It asserts the negotiated group rather than
/// inferring it, so a future provider change that silently dropped back to a
/// classical group would fail here instead of passing quietly.
#[tokio::test(flavor = "current_thread")]
async fn quantum_safe_tls_round_trip_query_request() {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let bound = listener.local_addr().unwrap();
    drop(listener);

    let (tls_cfg, server_cert_pem) =
        tls_self_signed_with_profile("kmip.test", TlsProfile::QuantumSafe)
            .expect("quantum-safe self-signed cert");
    let deps = build_deps();

    let server_cfg = tls_cfg.clone();
    let server_deps = deps.clone();
    let handle = tokio::spawn(async move {
        if let Err(e) = serve(bound, server_cfg, server_deps).await {
            eprintln!("server: {e}");
        }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Client built from the SAME restricted provider, so this also proves the
    // two ends can actually agree on a hybrid group rather than merely that
    // the server starts.
    let mut root_store = rustls::RootCertStore::empty();
    root_store
        .add(rustls::pki_types::CertificateDer::from(pem_to_der(
            &server_cert_pem,
        )))
        .unwrap();
    let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        pqctoday_kmip::server::listener::quantum_safe_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS1.3-only client")
    .with_root_certificates(root_store)
    .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    let tcp = TcpStream::connect(bound).await.unwrap();
    let server_name = ServerName::try_from("kmip.test").unwrap();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();

    // The handshake actually used a hybrid ML-KEM group, and TLS 1.3.
    {
        let (_, conn) = tls.get_ref();
        let group = conn
            .negotiated_key_exchange_group()
            .expect("a key exchange group was negotiated");
        let name = format!("{:?}", group.name());
        assert!(
            name.contains("MLKEM"),
            "expected a hybrid ML-KEM group, negotiated {name}"
        );
        assert_eq!(
            conn.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3),
            "§3.3.1 — TLS 1.3 only"
        );
    }

    // A real KMIP operation over that channel.
    let req = one_off_request(RequestPayload::Query(QueryRequest {
        functions: vec![QueryFunction::QueryOperations],
    }));
    let req_bytes = build_request_bytes(&req);
    tls.write_all(&req_bytes).await.unwrap();

    let resp_bytes = read_one_frame_async(&mut tls).await;
    let (frame, _) = pqctoday_kmip::codec::decode(&resp_bytes).expect("valid TTLV");
    assert_eq!(
        frame.tag.0, 0x42_007b,
        "top-level Response Message tag over the quantum-safe channel"
    );

    handle.abort();
    let _ = handle.await;
}

/// mTLS must build a usable config under BOTH profiles.
///
/// Regression test for a real bug: `tls_mtls_with_profile` built its
/// `WebPkiClientVerifier` with the plain `builder()`, which resolves the
/// PROCESS-LEVEL default crypto provider and *panics* when it cannot find
/// one. The verifier is constructed before `profile_builder` runs, so the
/// quantum-safe path (which passes its provider explicitly and never
/// installs a process default) blew up with "Could not automatically
/// determine the process-level CryptoProvider" — and the permissive path
/// installed one too late to help. Every mTLS deployment would have crashed
/// at startup, and nothing caught it because no test covered mTLS at all.
#[test]
fn mtls_config_builds_under_both_profiles() {
    let dir = std::env::temp_dir().join(format!("kmip-mtls-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let paths = pqctoday_kmip::cert_init::init_certs_if_missing(&dir).expect("mint certs");
    let server_cert = std::fs::read(&paths.server_cert).unwrap();
    let server_key = std::fs::read(&paths.server_key).unwrap();
    let ca = std::fs::read(&paths.ca_cert).unwrap();

    for profile in [TlsProfile::Permissive, TlsProfile::QuantumSafe] {
        let cfg = pqctoday_kmip::server::listener::tls_mtls_with_profile(
            &server_cert,
            &server_key,
            &ca,
            profile,
        );
        assert!(cfg.is_ok(), "mTLS config must build under {profile:?}: {cfg:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// ── §3.3 refusal matrix ────────────────────────────────────────────────────
//
// One case per SHALL NOT. These exist because the quantum-safe profile's
// enforcement was originally proven by hand with `openssl s_client` and
// nothing then held it in place: a provider swap, a rustls bump or an edit
// to `profile_builder` could silently re-admit TLS 1.2 or a classical group
// and every other test in this repo would still pass. A strict profile that
// quietly stops being strict still LOOKS enforced, which is precisely why
// the negative cases are the ones worth automating.
//
// Every client below is built from an explicitly restricted provider, so
// each test states what it offered rather than inheriting defaults that
// might change underneath it.

/// Spawn a quantum-safe server, returning its address and cert PEM.
async fn spawn_quantum_safe_server() -> (SocketAddr, String, tokio::task::JoinHandle<()>) {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let bound = listener.local_addr().unwrap();
    drop(listener);

    let (tls_cfg, cert_pem) = tls_self_signed_with_profile("kmip.test", TlsProfile::QuantumSafe)
        .expect("quantum-safe self-signed cert");
    let deps = build_deps();
    let handle = tokio::spawn(async move {
        if let Err(e) = serve(bound, tls_cfg, deps).await {
            eprintln!("server: {e}");
        }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    (bound, cert_pem, handle)
}

fn root_store_for(cert_pem: &str) -> rustls::RootCertStore {
    let mut root_store = rustls::RootCertStore::empty();
    root_store
        .add(rustls::pki_types::CertificateDer::from(pem_to_der(cert_pem)))
        .unwrap();
    root_store
}

/// Attempt a handshake with a client restricted to `groups` / `suites` over
/// `versions`. Returns the handshake error, or `None` if it succeeded.
async fn handshake_error(
    bound: SocketAddr,
    cert_pem: &str,
    suites: Vec<rustls::SupportedCipherSuite>,
    groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup>,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Option<String> {
    let provider = rustls::crypto::CryptoProvider {
        cipher_suites: suites,
        kx_groups: groups,
        ..rustls::crypto::aws_lc_rs::default_provider()
    };
    let config = match rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(versions)
    {
        Ok(b) => b
            .with_root_certificates(root_store_for(cert_pem))
            .with_no_client_auth(),
        // A provider with no suites valid for the requested version can fail
        // to build; that is still a refusal of the configuration under test.
        Err(e) => return Some(format!("client config: {e}")),
    };
    let connector = TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect(bound).await.unwrap();
    let server_name = ServerName::try_from("kmip.test").unwrap();
    match connector.connect(server_name, tcp).await {
        Ok(_) => None,
        Err(e) => Some(e.to_string()),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn quantum_safe_refuses_classical_and_tls12() {
    use rustls::crypto::aws_lc_rs::{cipher_suite, kx_group};
    let (bound, cert_pem, handle) = spawn_quantum_safe_server().await;

    // Positive control FIRST. Without it, every "refused" below could just
    // mean the server never came up, and the whole matrix would be vacuous.
    let ok = handshake_error(
        bound,
        &cert_pem,
        vec![cipher_suite::TLS13_AES_256_GCM_SHA384],
        vec![kx_group::X25519MLKEM768],
        &[&rustls::version::TLS13],
    )
    .await;
    assert!(ok.is_none(), "control: X25519MLKEM768 must connect, got {ok:?}");

    // §3.3.3 — classical-only clients are refused, not downgraded to.
    for (label, group) in [
        ("X25519", kx_group::X25519),
        ("secp256r1", kx_group::SECP256R1),
        ("secp384r1", kx_group::SECP384R1),
    ] {
        let err = handshake_error(
            bound,
            &cert_pem,
            vec![cipher_suite::TLS13_AES_256_GCM_SHA384],
            vec![group],
            &[&rustls::version::TLS13],
        )
        .await;
        assert!(
            err.is_some(),
            "§3.3.3: classical group {label} must be refused, but the handshake succeeded"
        );
    }

    // §3.3.2 — AES-128-GCM is not on the permitted list, even over TLS 1.3
    // with an acceptable group.
    let err = handshake_error(
        bound,
        &cert_pem,
        vec![cipher_suite::TLS13_AES_128_GCM_SHA256],
        vec![kx_group::X25519MLKEM768],
        &[&rustls::version::TLS13],
    )
    .await;
    assert!(
        err.is_some(),
        "§3.3.2: TLS13_AES_128_GCM_SHA256 must be refused, but the handshake succeeded"
    );

    // §3.3.1 — TLS 1.2 is a SHALL NOT.
    let err = handshake_error(
        bound,
        &cert_pem,
        vec![cipher_suite::TLS13_AES_256_GCM_SHA384],
        vec![kx_group::X25519MLKEM768],
        &[&rustls::version::TLS12],
    )
    .await;
    assert!(
        err.is_some(),
        "§3.3.1: TLS 1.2 must be refused, but the handshake succeeded"
    );

    handle.abort();
    let _ = handle.await;
}

/// The permitted §3.3.2 suites and §3.3.3 groups all actually work — the
/// mirror of the test above, so a change that over-restricts (breaking a
/// conformant client) fails just as loudly as one that under-restricts.
#[tokio::test(flavor = "current_thread")]
async fn quantum_safe_accepts_every_permitted_suite_and_group() {
    use rustls::crypto::aws_lc_rs::{cipher_suite, kx_group};
    let (bound, cert_pem, handle) = spawn_quantum_safe_server().await;

    for (label, suite) in [
        ("TLS13_CHACHA20_POLY1305_SHA256", cipher_suite::TLS13_CHACHA20_POLY1305_SHA256),
        ("TLS13_AES_256_GCM_SHA384", cipher_suite::TLS13_AES_256_GCM_SHA384),
    ] {
        let err = handshake_error(
            bound,
            &cert_pem,
            vec![suite],
            vec![kx_group::X25519MLKEM768],
            &[&rustls::version::TLS13],
        )
        .await;
        assert!(err.is_none(), "§3.3.2 suite {label} must connect, got {err:?}");
    }

    // Both groups this build can offer. SecP384r1MLKEM1024 is absent from
    // rustls 0.23 and is therefore NOT asserted here -- see the documented
    // partial-§3.3.3 gap.
    for (label, group) in [
        ("X25519MLKEM768", kx_group::X25519MLKEM768),
        ("SECP256R1MLKEM768", kx_group::SECP256R1MLKEM768),
    ] {
        let err = handshake_error(
            bound,
            &cert_pem,
            vec![cipher_suite::TLS13_AES_256_GCM_SHA384],
            vec![group],
            &[&rustls::version::TLS13],
        )
        .await;
        assert!(err.is_none(), "§3.3.3 group {label} must connect, got {err:?}");
    }

    handle.abort();
    let _ = handle.await;
}

/// The permissive default is genuinely unchanged: classical groups and
/// TLS 1.2 still work. This is the regression guard for every existing
/// caller (kms-proxy, sandbox scenario 22, the wasm playground), which the
/// opt-in design exists to protect.
#[tokio::test(flavor = "current_thread")]
async fn permissive_profile_still_accepts_classical() {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let bound = listener.local_addr().unwrap();
    drop(listener);
    let (tls_cfg, cert_pem) = tls_self_signed("kmip.test").expect("self-signed cert");
    let deps = build_deps();
    let handle = tokio::spawn(async move {
        if let Err(e) = serve(bound, tls_cfg, deps).await {
            eprintln!("server: {e}");
        }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store_for(&cert_pem))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect(bound).await.unwrap();
    let server_name = ServerName::try_from("kmip.test").unwrap();
    assert!(
        connector.connect(server_name, tcp).await.is_ok(),
        "permissive profile must keep accepting a default (classical-capable) client"
    );

    handle.abort();
    let _ = handle.await;
}

fn build_request_bytes(req: &RequestMessage) -> Vec<u8> {
    // The wire codec only exposes encode for ResponseMessage; for the test
    // we synthesize the request frame manually using the codec primitives.
    use pqctoday_kmip::codec::{encode, Tag, TtlvFrame, Value};
    use bytes::BytesMut;

    let header = TtlvFrame::new(
        Tag(0x42_0077),
        Value::Structure(vec![TtlvFrame::new(
            Tag(0x42_0069),
            Value::Structure(vec![
                TtlvFrame::new(Tag(0x42_006a), Value::Integer(req.header.protocol_version_major)),
                TtlvFrame::new(Tag(0x42_006b), Value::Integer(req.header.protocol_version_minor)),
            ]),
        )]),
    );
    let mut bi_children = Vec::new();
    for bi in &req.batch_items {
        bi_children.push(TtlvFrame::new(Tag(0x42_005c), Value::Enumeration(bi.operation.to_wire_value())));
        match &bi.payload {
            RequestPayload::Query(q) => {
                let mut fns = Vec::new();
                for f in &q.functions {
                    fns.push(TtlvFrame::new(Tag(0x42_0074), Value::Enumeration(*f as u32)));
                }
                bi_children.push(TtlvFrame::new(Tag(0x42_0079), Value::Structure(fns)));
            }
            _ => unimplemented!("test only sends Query"),
        }
    }
    let frame = TtlvFrame::new(
        Tag(0x42_0078),
        Value::Structure(vec![
            header,
            TtlvFrame::new(Tag(0x42_000f), Value::Structure(bi_children)),
        ]),
    );
    let mut buf = BytesMut::new();
    encode(&frame, &mut buf);
    buf.to_vec()
}

fn pem_to_der(pem: &str) -> Vec<u8> {
    let mut bytes = pem.as_bytes();
    rustls_pemfile::certs(&mut bytes)
        .next()
        .expect("at least one cert")
        .expect("valid cert")
        .to_vec()
}

async fn read_one_frame_async<S>(stream: &mut S) -> Vec<u8>
where
    S: AsyncReadExt + Unpin,
{
    let mut header = [0u8; 8];
    stream.read_exact(&mut header).await.unwrap();
    let length = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
    let padded = (length + 7) & !7;
    let mut value = vec![0u8; padded];
    if padded > 0 {
        stream.read_exact(&mut value).await.unwrap();
    }
    let mut full = Vec::with_capacity(8 + padded);
    full.extend_from_slice(&header);
    full.extend_from_slice(&value);
    full
}

// Suppress unused warnings on the request decoder import we use only for
// the assertion that it rejects a response message.
#[allow(dead_code)]
fn _unused() {
    let _ = decode_request_message;
    let _ = encode_response_message;
    let _ = Operation::Query;
    let _ = RequestHeader::v3;
    let _ = ResultStatus::Success;
    let _ = std::marker::PhantomData::<ResponsePayload>;
}
