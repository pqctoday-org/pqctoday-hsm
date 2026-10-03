//! C1 / addendum §1.1 (A-05) — the KMIP listener creates one PKCS#11
//! application context per mTLS-authenticated connection, with immutable
//! connection metadata, and destroys it when the connection ends: after a
//! served request, and when the client drops the connection mid-request.
//! A plain-TLS connection gets no context.
//!
//! One `#[test]` only: the context registry is process-global.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use sha2::Digest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use pqctoday_kmip::auditlog::{AuditSink, RingSink};
use pqctoday_kmip::ops::{Deps, DepsConfig};
use pqctoday_kmip::policy::{load_from_str, Engine};
use pqctoday_kmip::server::listener::{tls_mtls_with_profile, TlsProfile};
use pqctoday_kmip::server::{serve, tls_self_signed};
use pqctoday_kmip::store::MemoryStore;
use softhsmrustv3::app_context;

const POLICY: &str = r#"
schema_version: 1
metadata: { name: t, description: t, authority: t, effective: always }
rules: []
"#;

fn deps() -> Arc<Deps> {
    let ring = Arc::new(RingSink::new(64));
    let sink: Arc<dyn AuditSink> = ring;
    let engine = Engine::with_global_sink(sink.clone());
    engine.replace_all(load_from_str(POLICY, std::path::Path::new("<t>")).unwrap()).unwrap();
    Arc::new(Deps::new(engine, Arc::new(MemoryStore::new()), sink, DepsConfig::default()))
}

async fn free_addr() -> SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    drop(l);
    a
}

async fn wait_for(count: usize) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if app_context::context_count() == count {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    app_context::context_count() == count
}

/// A minimal Query(QueryOperations) request frame.
fn query_frame() -> Vec<u8> {
    use bytes::BytesMut;
    use pqctoday_kmip::codec::{encode, Tag, TtlvFrame, Value};
    let header = TtlvFrame::new(
        Tag(0x42_0077),
        Value::Structure(vec![TtlvFrame::new(
            Tag(0x42_0069),
            Value::Structure(vec![
                TtlvFrame::new(Tag(0x42_006a), Value::Integer(3)),
                TtlvFrame::new(Tag(0x42_006b), Value::Integer(0)),
            ]),
        )]),
    );
    let batch = TtlvFrame::new(
        Tag(0x42_000f),
        Value::Structure(vec![
            TtlvFrame::new(Tag(0x42_005c), Value::Enumeration(0x18)), // Query
            TtlvFrame::new(
                Tag(0x42_0079),
                Value::Structure(vec![TtlvFrame::new(Tag(0x42_0074), Value::Enumeration(1))]),
            ),
        ]),
    );
    let frame = TtlvFrame::new(Tag(0x42_0078), Value::Structure(vec![header, batch]));
    let mut buf = BytesMut::new();
    encode(&frame, &mut buf);
    buf.to_vec()
}

async fn read_frame<S: AsyncReadExt + Unpin>(s: &mut S) -> Vec<u8> {
    let mut h = [0u8; 8];
    s.read_exact(&mut h).await.unwrap();
    let len = u32::from_be_bytes([h[4], h[5], h[6], h[7]]) as usize;
    let mut v = vec![0u8; (len + 7) & !7];
    s.read_exact(&mut v).await.unwrap();
    [h.to_vec(), v].concat()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mtls_connection_gets_one_context_destroyed_on_close_and_on_drop() {
    let dir = std::env::temp_dir().join(format!("kmip-c1-ctx-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let paths = pqctoday_kmip::cert_init::init_certs_if_missing(&dir).expect("mint certs");
    let server_cert = std::fs::read(&paths.server_cert).unwrap();
    let server_key = std::fs::read(&paths.server_key).unwrap();
    let ca = std::fs::read(&paths.ca_cert).unwrap();
    let client_cert_pem = std::fs::read(&paths.client_cert).unwrap();
    let client_key_pem = std::fs::read(&paths.client_key).unwrap();

    let server_cfg = tls_mtls_with_profile(&server_cert, &server_key, &ca, TlsProfile::Permissive).unwrap();
    let addr = free_addr().await;
    let server = tokio::spawn(serve(addr, server_cfg, deps()));
    tokio::time::sleep(Duration::from_millis(80)).await;

    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(&ca) {
        roots.add(c.unwrap()).unwrap();
    }
    let client_chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(&client_cert_pem).map(|c| c.unwrap()).collect();
    let leaf_sha: [u8; 32] = sha2::Sha256::digest(client_chain[0].as_ref()).into();
    let client_key = PrivateKeyDer::from_pem_slice(&client_key_pem).unwrap();
    let client_cfg = Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_client_auth_cert(client_chain, client_key)
            .unwrap(),
    );
    let connector = TlsConnector::from(client_cfg);
    let name = ServerName::try_from("localhost").unwrap();

    assert_eq!(app_context::context_count(), 0);

    // 1. A served request: one context while connected, none after.
    let mut tls = connector.connect(name.clone(), TcpStream::connect(addr).await.unwrap()).await.unwrap();
    assert!(wait_for(1).await, "one context per authenticated connection");
    let ids = app_context::context_ids();
    let meta = app_context::context_meta(ids[0]).expect("metadata");
    assert_eq!(meta.client_cert_sha256, leaf_sha, "client certificate SHA-256 attached at creation");
    assert_eq!(meta.listener, addr.to_string(), "listener address attached at creation");
    tls.write_all(&query_frame()).await.unwrap();
    let resp = read_frame(&mut tls).await;
    assert_eq!(&resp[..3], &[0x42, 0x00, 0x7b], "a Response Message came back");
    drop(tls);
    assert!(wait_for(0).await, "context destroyed after the connection closed");

    // 2. The client drops mid-request: the error path destroys it too.
    let mut tls = connector.connect(name.clone(), TcpStream::connect(addr).await.unwrap()).await.unwrap();
    assert!(wait_for(1).await);
    tls.write_all(&query_frame()[..5]).await.unwrap();
    drop(tls);
    assert!(wait_for(0).await, "context destroyed when the connection dropped mid-request");
    server.abort();

    // 3. Plain TLS (no client certificate): no context at all.
    let (plain_cfg, plain_pem) = tls_self_signed("kmip.test").unwrap();
    let plain_addr = free_addr().await;
    let plain = tokio::spawn(serve(plain_addr, plain_cfg, deps()));
    tokio::time::sleep(Duration::from_millis(80)).await;
    let mut proots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(plain_pem.as_bytes()) {
        proots.add(c.unwrap()).unwrap();
    }
    let pcfg = Arc::new(rustls::ClientConfig::builder().with_root_certificates(proots).with_no_client_auth());
    let mut ptls = TlsConnector::from(pcfg)
        .connect(ServerName::try_from("kmip.test").unwrap(), TcpStream::connect(plain_addr).await.unwrap())
        .await
        .unwrap();
    ptls.write_all(&query_frame()).await.unwrap();
    let _ = read_frame(&mut ptls).await;
    assert_eq!(app_context::context_count(), 0, "plain TLS creates no context");
    drop(ptls);
    plain.abort();
    let _ = std::fs::remove_dir_all(&dir);
}
