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

use crate::dispatcher::dispatch;
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

/// Build a `rustls::ServerConfig` from on-disk PEM cert + key.
pub fn tls_from_pem(cert_pem_path: &Path, key_pem_path: &Path) -> Result<Arc<ServerConfig>, ServerError> {
    install_crypto_provider();
    let cert_bytes = std::fs::read(cert_pem_path)?;
    let key_bytes = std::fs::read(key_pem_path)?;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &cert_bytes[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ServerError::Tls(format!("cert: {e}")))?;
    let key = rustls_pemfile::private_key(&mut &key_bytes[..])
        .map_err(|e| ServerError::Tls(format!("key: {e}")))?
        .ok_or_else(|| ServerError::Tls("no private key in PEM".into()))?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| ServerError::Tls(e.to_string()))?;
    Ok(Arc::new(config))
}

/// Install the `ring` crypto provider as rustls' default. Required when
/// multiple providers are linked (rcgen's `aws_lc_rs` + rustls' `ring`).
/// Idempotent — subsequent calls are no-ops.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Generate a self-signed Ed25519 server cert in memory and build a
/// `ServerConfig`. Sandbox / dev only — production should pass real PEM
/// via [`tls_from_pem`]. Returns the config + the PEM-encoded cert so the
/// caller can log the fingerprint for clients to pin.
pub fn tls_self_signed(common_name: &str) -> Result<(Arc<ServerConfig>, String), ServerError> {
    install_crypto_provider();
    let subject_alt_names = vec![common_name.to_string(), "localhost".to_string()];
    let cert = rcgen::generate_simple_self_signed(subject_alt_names)
        .map_err(|e| ServerError::Rcgen(e.to_string()))?;
    let cert_pem = cert.cert.pem();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der: PrivateKeyDer<'static> =
        PrivateKeyDer::try_from(cert.key_pair.serialize_der())
            .map_err(|e| ServerError::Tls(format!("key: {e}")))?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|e| ServerError::Tls(e.to_string()))?;
    Ok((Arc::new(config), cert_pem))
}

/// Convenience: build a `ServerConfig` that requires client certificates
/// signed by the supplied CA bundle (mTLS — KMIP §3.x). Phase 7b will
/// wire this; v0.1 only uses [`tls_self_signed`] / [`tls_from_pem`] with
/// no client auth.
#[allow(dead_code)]
pub fn tls_mtls(
    server_cert_pem: &[u8],
    server_key_pem: &[u8],
    client_ca_pem: &[u8],
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
    let verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .map_err(|e| ServerError::Tls(e.to_string()))?;
    let config = ServerConfig::builder()
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
    let frame_bytes = read_one_frame(&mut tls_stream).await?;
    let response = match decode_request_message(&frame_bytes) {
        Ok(request) => dispatch(&deps, request),
        // KMIP 3.0 §6.4: a wire-decode failure (unknown tag, unknown enum
        // value, malformed length, etc.) must produce a structured
        // `OperationFailed` response with `ResultReason = InvalidMessage`
        // — NOT a TCP/TLS connection drop. Closing the socket without a
        // response makes the client see a transport error instead of a
        // proper protocol-level rejection (and breaks OASIS conformance).
        Err(e) => wire_error_response(&e),
    };
    let response_bytes = encode_response_message(&response);
    tls_stream.write_all(&response_bytes).await?;
    tls_stream.shutdown().await?;
    Ok(())
}

/// Build a KMIP 3.0 §6.4 error ResponseMessage for an unparseable request.
///
/// Used when our codec can't decode the inbound frame — e.g. unknown
/// algorithm enum value, missing required field, malformed Structure
/// length. The spec requires us to still respond on the same connection
/// so the client gets a `ResultReason` rather than a dangling socket.
fn wire_error_response(err: &WireError) -> crate::kmip30::ResponseMessage {
    use crate::error::ResultReason;
    use crate::kmip30::{ResponseBatchItem, ResponseHeader, ResponseMessage, ResultStatus};
    ResponseMessage {
        header: ResponseHeader::v3_now(),
        batch_items: vec![ResponseBatchItem {
            operation: None,
            result_status: ResultStatus::OperationFailed,
            result_reason: Some(ResultReason::InvalidMessage as u32),
            result_message: Some(format!("KMIP wire decode failed: {err}")),
            payload: None,
        }],
    }
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
}
