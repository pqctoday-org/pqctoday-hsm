//! WP5a harness plumbing: spin up real (no-TLS — TLS enforcement is
//! covered separately by the interop test + the live smoke tests recorded
//! in the plan; this suite is about CKR_* parity, not the handshake) gRPC
//! and REST servers in-process, bound to ephemeral ports, and return
//! clients pointed at them. Each test gets its own pair of servers so
//! tests can run in parallel without port collisions.

use std::net::SocketAddr;

use anyhow::Result;
use pqctoday_pkcs11_remote_proto::pkcs11_remote_client::Pkcs11RemoteClient;
use pqctoday_pkcs11_remote_proto::pkcs11_v32_client::Pkcs11V32Client;
use tonic::transport::{Channel, Server};

/// Wait until a spawned service is genuinely serving, instead of assuming a
/// fixed delay is enough.
///
/// The four `spawn_*` helpers each used `sleep(50ms)` with the comment "give
/// the listener a moment to be accept()-ready". That is a timing assumption,
/// and timing assumptions fail under load: a gate run competing with other
/// container work can leave the spawned task unscheduled well past 50 ms.
///
/// Note the subtlety — `TcpListener::bind` has already bound AND listened, so
/// the kernel queues an inbound connection in the backlog whether or not the
/// task has reached `accept()`. A bare TCP connect therefore proves nothing.
/// What can still lag is the SERVICE: for gRPC the h2 handshake needs the
/// server task actually polling. So the readiness probe has to be the real
/// connect, retried.
///
/// Prompted by a single unreproduced 85/86 failure in this suite on
/// 2026-09-07 (six subsequent runs were clean). This is a plausible cause,
/// NOT a confirmed one — no reproduction was ever obtained. It is committed
/// because a bounded retry is strictly more robust than a fixed sleep, not
/// because the flake was diagnosed.
async fn retry_until_ready<T, F, Fut>(what: &str, mut attempt: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut delay = std::time::Duration::from_millis(5);
    loop {
        match attempt().await {
            Ok(v) => return Ok(v),
            Err(e) => {
                if std::time::Instant::now() >= deadline {
                    return Err(e.context(format!("{what} never became ready within 5s")));
                }
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(std::time::Duration::from_millis(100));
            }
        }
    }
}

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
    let channel = retry_until_ready("grpc service", || async move {
        Ok(Channel::from_shared(format!("http://{addr}"))?.connect().await?)
    })
    .await?;
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
    retry_until_ready("rest service", || async move {
        Ok(tokio::net::TcpStream::connect(addr).await.map(|_| ())?)
    })
    .await?;
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

/// Both mirror services on one ephemeral server (the `Pkcs11V32` C_*
/// mirror plus the legacy service, matching the real binary), with the
/// destructive flag ON — the parity suite must be able to validate
/// C_DestroyObject-dependent categories (plan: tests ON, deployed OFF).
/// Returns a connected `Pkcs11V32` client.
pub async fn spawn_grpc_v32() -> Result<Pkcs11V32Client<Channel>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let v32 = pqctoday_pkcs11_remote_proto::pkcs11_v32_server::Pkcs11V32Server::new(
        pqc_grpc_pkcs11::service_v32::Pkcs11V32Service { destructive: true },
    );
    tokio::spawn(async move {
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        let _ = Server::builder().add_service(v32).serve_with_incoming(incoming).await;
    });
    let channel = retry_until_ready("grpc v32 service", || async move {
        Ok(Channel::from_shared(format!("http://{addr}"))?.connect().await?)
    })
    .await?;
    Ok(Pkcs11V32Client::new(channel))
}

/// The `Pkcs11V32` REST router (destructive ON) on an ephemeral port;
/// returns its base URL. `/v32/...` routes.
pub async fn spawn_rest_v32() -> Result<String> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr: SocketAddr = listener.local_addr()?;
    let app = pqc_rest_pkcs11::routes::router_with(true);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });
    retry_until_ready("rest v32 service", || async move {
        Ok(tokio::net::TcpStream::connect(addr).await.map(|_| ())?)
    })
    .await?;
    Ok(format!("http://{addr}"))
}
