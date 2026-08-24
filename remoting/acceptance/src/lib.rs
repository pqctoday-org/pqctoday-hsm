//! WP5a harness plumbing: spin up real (no-TLS — TLS enforcement is
//! covered separately by the interop test + the live smoke tests recorded
//! in the plan; this suite is about CKR_* parity, not the handshake) gRPC
//! and REST servers in-process, bound to ephemeral ports, and return
//! clients pointed at them. Each test gets its own pair of servers so
//! tests can run in parallel without port collisions.

use std::net::SocketAddr;

use anyhow::Result;
use pqctoday_pkcs11_remote_proto::pkcs11_remote_client::Pkcs11RemoteClient;
use tonic::transport::{Channel, Server};

/// Starts a real `pqc-grpc-pkcs11` service on an ephemeral loopback port
/// (plaintext h2c — no TLS) and returns a connected client. The server
/// task is detached; it lives for the test process's lifetime, which is
/// fine for a short-lived test binary.
pub async fn spawn_grpc() -> Result<Pkcs11RemoteClient<Channel>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let svc = pqc_grpc_pkcs11::service::Pkcs11RemoteService::default();
    let server = pqctoday_pkcs11_remote_proto::pkcs11_remote_server::Pkcs11RemoteServer::new(svc);
    tokio::spawn(async move {
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        let _ = Server::builder().add_service(server).serve_with_incoming(incoming).await;
    });
    // Give the listener a moment to be accept()-ready.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let channel = Channel::from_shared(format!("http://{addr}"))?.connect().await?;
    Ok(Pkcs11RemoteClient::new(channel))
}

/// Starts a real `pqc-rest-pkcs11` router on an ephemeral loopback port
/// (plaintext HTTP — see [`spawn_grpc`]'s doc for why) and returns its
/// base URL.
pub async fn spawn_rest() -> Result<String> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr: SocketAddr = listener.local_addr()?;
    let app = pqc_rest_pkcs11::routes::router();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    Ok(format!("http://{addr}"))
}

/// Bootstraps the shared engine exactly once per test process — required
/// before either server (or the in-process control) can serve a real
/// request. `std::sync::Once` because the engine's token init is not
/// safe to call twice (see `remoting/core/src/verbs.rs`'s own doc).
pub fn bootstrap_once() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        pqctoday_pkcs11_remote_core::verbs::bootstrap().expect("engine bootstrap");
    });
}

/// The well-known benchmark PIN (see `remoting/core/src/verbs.rs`) — not a
/// secret, shared here so every test doesn't hardcode it separately.
pub const PIN: &str = "1234";
