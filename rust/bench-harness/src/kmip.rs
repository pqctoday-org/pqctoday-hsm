//! KMIP 3.0 client transport for the benchmark's KMIP arms (WS-D).
//!
//! A KMIP benchmark that is not driven by a real client measures a library,
//! not a protocol. This module is that client: TTLV over TLS to a live
//! `pqctoday-kmip`, using the same codec the server does.
//!
//! ## Why blocking I/O
//!
//! `measure::run_point` drives N OS threads each calling a `FnMut()` in a
//! tight loop. That model wants blocking sockets, so this uses
//! `rustls::StreamOwned` over `std::net::TcpStream` rather than the
//! server's tokio stack.
//!
//! ## One connection per request — deliberately
//!
//! The server reads exactly one Request Message per TCP connection and then
//! closes (`kmip/src/server/listener.rs`: "v0.1 ships one-request-per-
//! connection semantics"). So every operation here pays a full TCP + TLS
//! handshake. That is not an artefact to be optimised away: it is the real
//! cost of a KMIP call against this server, and under the quantum-safe
//! profile it is precisely the cost that ML-KEM keyshares grew. Pooling or
//! reusing connections would measure something the deployment cannot do.
//!
//! ## What is NOT decoded
//!
//! Responses are parsed with `codec::decode` into a generic TTLV frame and
//! inspected for the few fields an arm needs. There is no typed
//! `ResponseMessage` decoder in the codebase (only the encode direction),
//! and none is required — see the plan's QS-7, which was twice mis-scoped
//! before this was established.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};

use pqctoday_kmip::codec;
use pqctoday_kmip::dispatcher::one_off_request;
use pqctoday_kmip::kmip30::{
    wire::encode_request_message, Credential, QueryFunction, QueryRequest, RequestMessage,
    RequestPayload,
};

/// Which TLS posture the client demands of the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientTlsProfile {
    /// rustls defaults — classical groups permitted.
    Permissive,
    /// KMIP 3.0 Profiles §3.3: TLS 1.3 only, the two §3.3.2 suites, and
    /// ONLY hybrid ML-KEM groups.
    ///
    /// Unlike the Python client — which cannot pin its group list at all on
    /// Python 3.12 and has to prove the channel by exclusion — a rustls
    /// client CAN state what it offers. Under this profile a classical
    /// handshake is not merely unlikely, it is unofferable, so a completed
    /// connection is proof the exchange was hybrid.
    QuantumSafe,
}

/// Connection parameters for one KMIP endpoint.
#[derive(Debug, Clone)]
pub struct KmipEndpoint {
    pub host: String,
    pub port: u16,
    /// PEM trust anchor for the server's certificate.
    pub ca_pem: Vec<u8>,
    /// SNI / certificate name. Must match a SAN on the server cert.
    pub server_name: String,
    pub tls: ClientTlsProfile,
    /// §8.1.2 credentials. The server rejects every operation without them
    /// once `--auth-user` is configured.
    pub username: Option<String>,
    pub password: Option<String>,
}

impl KmipEndpoint {
    fn credentials(&self) -> Vec<Credential> {
        match (&self.username, &self.password) {
            (Some(u), p) => vec![Credential::UsernameAndPassword {
                username: u.clone(),
                password: p.clone(),
            }],
            _ => Vec::new(),
        }
    }

    fn tls_config(&self) -> Result<Arc<rustls::ClientConfig>> {
        let mut roots = rustls::RootCertStore::empty();
        let mut reader = &self.ca_pem[..];
        let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("parsing CA PEM")?;
        if certs.is_empty() {
            return Err(anyhow!("no certificates found in the supplied CA PEM"));
        }
        for c in certs {
            roots.add(c).context("adding CA to trust store")?;
        }

        let config = match self.tls {
            ClientTlsProfile::Permissive => rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
            ClientTlsProfile::QuantumSafe => {
                let provider = rustls::crypto::CryptoProvider {
                    cipher_suites: vec![
                        rustls::crypto::aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
                        rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
                    ],
                    kx_groups: vec![
                        rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768,
                        rustls::crypto::aws_lc_rs::kx_group::SECP256R1MLKEM768,
                    ],
                    ..rustls::crypto::aws_lc_rs::default_provider()
                };
                rustls::ClientConfig::builder_with_provider(Arc::new(provider))
                    .with_protocol_versions(&[&rustls::version::TLS13])
                    .context("quantum-safe client TLS setup")?
                    .with_root_certificates(roots)
                    .with_no_client_auth()
            }
        };
        Ok(Arc::new(config))
    }
}

/// One request/response exchange, including its transport cost.
pub struct Exchange {
    pub response: Vec<u8>,
    /// The key exchange group the handshake actually used, when rustls can
    /// name it. Recorded per exchange so a row can PROVE it was hybrid
    /// rather than assert it.
    pub kx_group: Option<String>,
}

/// Open a connection, send one Request Message, read the response, close.
///
/// Mirrors the server's real connection model exactly rather than
/// pretending a session exists.
pub fn exchange(endpoint: &KmipEndpoint, request: &RequestMessage) -> Result<Exchange> {
    let bytes = encode_request_message(request)
        .ok_or_else(|| anyhow!("request could not be encoded (unsupported payload?)"))?;

    let config = endpoint.tls_config()?;
    let server_name = rustls::pki_types::ServerName::try_from(endpoint.server_name.clone())
        .map_err(|e| anyhow!("invalid server name {:?}: {e}", endpoint.server_name))?;
    let conn = rustls::ClientConnection::new(config, server_name)
        .context("TLS client connection setup")?;
    let sock = TcpStream::connect((endpoint.host.as_str(), endpoint.port))
        .with_context(|| format!("connecting to {}:{}", endpoint.host, endpoint.port))?;
    let mut tls = rustls::StreamOwned::new(conn, sock);

    tls.write_all(&bytes).context("writing KMIP request")?;
    tls.flush().ok();

    // The server closes after one response, so read to EOF rather than
    // trying to frame — the TTLV length header would work too, but EOF is
    // exactly as authoritative here and cannot disagree with the sender.
    let mut response = Vec::new();
    match tls.read_to_end(&mut response) {
        Ok(_) => {}
        // A close_notify-less shutdown is normal for this server.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
        Err(e) => return Err(e).context("reading KMIP response"),
    }
    if response.is_empty() {
        return Err(anyhow!("server closed the connection without a response"));
    }

    let kx_group = tls
        .conn
        .negotiated_key_exchange_group()
        .map(|g| format!("{:?}", g.name()));

    Ok(Exchange { response, kx_group })
}

/// Decode a response frame and return its top-level tag plus the batch
/// item's Result Status, without a typed decoder.
pub fn response_status(response: &[u8]) -> Result<(u32, Option<i32>)> {
    let (frame, _) = codec::decode(response).context("decoding response TTLV")?;
    let mut status = None;
    if let codec::Value::Structure(children) = &frame.value {
        for c in children {
            if let codec::Value::Structure(items) = &c.value {
                for item in items {
                    // Result Status = 0x42007f
                    if item.tag.0 == 0x42_007f {
                        if let codec::Value::Enumeration(v) = &item.value {
                            status = Some(*v as i32);
                        }
                    }
                }
            }
        }
    }
    Ok((frame.tag.0, status))
}

/// Smallest useful round trip: a Query for supported operations.
///
/// Used as a liveness/credential probe before a run, so a misconfigured
/// endpoint fails with one clear error instead of N thousand timing rows.
pub fn query(endpoint: &KmipEndpoint) -> Result<Exchange> {
    let mut req = one_off_request(RequestPayload::Query(QueryRequest {
        functions: vec![QueryFunction::QueryOperations],
    }));
    req.header.authentication = endpoint.credentials();
    exchange(endpoint, &req)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Live round trip against a running server. SKIPS (passes trivially)
    /// unless KMIP_BENCH_HOST/PORT/CA are set, so an ordinary `cargo test`
    /// is unaffected — a skip here is not evidence of anything.
    ///
    ///   KMIP_BENCH_HOST=127.0.0.1 KMIP_BENCH_PORT=5696 \
    ///   KMIP_BENCH_CA=/path/ca.crt KMIP_BENCH_NAME=localhost \
    ///   KMIP_BENCH_USER=alice KMIP_BENCH_PASS=pw cargo test -p bench-harness
    #[test]
    fn live_query_round_trip() {
        let (host, port, ca) = match (
            std::env::var("KMIP_BENCH_HOST"),
            std::env::var("KMIP_BENCH_PORT"),
            std::env::var("KMIP_BENCH_CA"),
        ) {
            (Ok(h), Ok(p), Ok(c)) => (h, p, c),
            _ => {
                eprintln!("skipping: set KMIP_BENCH_HOST/PORT/CA for the live round trip");
                return;
            }
        };
        let endpoint = KmipEndpoint {
            host,
            port: port.parse().expect("KMIP_BENCH_PORT"),
            ca_pem: std::fs::read(&ca).expect("reading KMIP_BENCH_CA"),
            server_name: std::env::var("KMIP_BENCH_NAME").unwrap_or_else(|_| "localhost".into()),
            tls: ClientTlsProfile::QuantumSafe,
            username: std::env::var("KMIP_BENCH_USER").ok(),
            password: std::env::var("KMIP_BENCH_PASS").ok(),
        };

        let ex = query(&endpoint).expect("KMIP Query round trip");
        let (tag, status) = response_status(&ex.response).expect("decode response");
        assert_eq!(tag, 0x42_007b, "top-level Response Message tag");
        assert_eq!(status, Some(0), "Result Status must be Success (credentials?)");

        // Under the quantum-safe profile the client offers ONLY hybrid
        // groups, so a completed handshake is proof — but assert the name
        // anyway, since it is the number a benchmark row will carry.
        let group = ex.kx_group.expect("rustls should name the negotiated group");
        assert!(group.contains("MLKEM"), "expected a hybrid group, got {group}");
        eprintln!("live round trip OK — negotiated {group}, status {status:?}");
    }
}
