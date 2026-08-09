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

// ── the operation matrix ────────────────────────────────────────────────────
//
// Representative set, not the full 26: one classical and one post-quantum per
// operation class keeps a run short while the machinery settles. Widening is
// a table change, not a code change.
//
// Two mappings are NOT one-to-one with the PKCS#11 arm and must never be
// plotted against it:
//   * Encapsulate/Decapsulate return a UID for a new SecretData object, so
//     retrieving the shared secret needs a follow-up Get. Both round trips
//     are timed together and labelled as such.
//   * KMIP DeriveKey is KDF-based (HMAC/PBKDF2/SP800-108), not the ECDH key
//     agreement PKCS#11 calls "derive". It is deliberately absent here
//     rather than silently mapped onto the wrong primitive.

use pqctoday_kmip::kmip30::{
    ops::{
        ActivateRequest, CreateKeyPairRequest, DecapsulateRequest, EncapsulateRequest, GetRequest,
        SignRequest, SignatureVerifyRequest,
    },
    Attribute, KmipAlgorithm, UsageMask,
};

/// One (algorithm, operation-class) cell the KMIP arms can measure.
#[derive(Debug, Clone, Copy)]
pub struct KmipCell {
    pub label: &'static str,
    pub algorithm: KmipAlgorithm,
    pub class: KmipClass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KmipClass {
    /// CreateKeyPair + Activate + Sign + SignatureVerify
    Signature,
    /// CreateKeyPair + Activate + Encapsulate(+Get) + Decapsulate(+Get)
    Kem,
}

pub const REPRESENTATIVE_CELLS: &[KmipCell] = &[
    KmipCell { label: "Ed25519", algorithm: KmipAlgorithm::Ed25519, class: KmipClass::Signature },
    KmipCell { label: "ML-DSA-65", algorithm: KmipAlgorithm::MlDsa65, class: KmipClass::Signature },
    KmipCell { label: "ML-KEM-768", algorithm: KmipAlgorithm::MlKem768, class: KmipClass::Kem },
];

fn send(endpoint: &KmipEndpoint, payload: RequestPayload) -> Result<(Vec<u8>, Option<String>)> {
    let mut req = one_off_request(payload);
    req.header.authentication = endpoint.credentials();
    let ex = exchange(endpoint, &req)?;
    let (tag, status) = response_status(&ex.response)?;
    if tag != 0x42_007b {
        return Err(anyhow!("unexpected top-level tag {tag:#x}"));
    }
    // Result Status 0 = Success. Anything else is a protocol-level failure
    // and must abort the cell rather than be timed as if it worked.
    if status != Some(0) {
        return Err(anyhow!("KMIP operation failed, Result Status {status:?}"));
    }
    Ok((ex.response, ex.kx_group))
}

/// Pull the first TextString under a Response Payload with `tag`.
fn text_field(response: &[u8], tag: u32) -> Option<String> {
    fn walk(v: &codec::Value, tag: u32, out: &mut Option<String>) {
        if let codec::Value::Structure(children) = v {
            for c in children {
                if c.tag.0 == tag {
                    if let codec::Value::TextString(s) = &c.value {
                        if out.is_none() {
                            *out = Some(s.clone());
                        }
                    }
                }
                walk(&c.value, tag, out);
            }
        }
    }
    let (frame, _) = codec::decode(response).ok()?;
    let mut out = None;
    walk(&frame.value, tag, &mut out);
    out
}

fn bytes_field(response: &[u8], tag: u32) -> Option<Vec<u8>> {
    fn walk(v: &codec::Value, tag: u32, out: &mut Option<Vec<u8>>) {
        if let codec::Value::Structure(children) = v {
            for c in children {
                if c.tag.0 == tag {
                    if let codec::Value::ByteString(b) = &c.value {
                        if out.is_none() {
                            *out = Some(b.clone());
                        }
                    }
                }
                walk(&c.value, tag, out);
            }
        }
    }
    let (frame, _) = codec::decode(response).ok()?;
    let mut out = None;
    walk(&frame.value, tag, &mut out);
    out
}

const TAG_PRIVATE_KEY_UID: u32 = 0x42_0066;
const TAG_PUBLIC_KEY_UID: u32 = 0x42_006f;
const TAG_UNIQUE_IDENTIFIER: u32 = 0x42_0094;
const TAG_SIGNATURE_DATA: u32 = 0x42_00c3;
const TAG_VALIDITY_INDICATOR: u32 = 0x42_009b;

/// A created, activated key pair ready for the hot loop.
pub struct KeyPair {
    pub private_uid: String,
    pub public_uid: String,
}

/// CreateKeyPair + Activate on both halves.
///
/// Activation is not optional: the server rejects any operation on an object
/// whose state is still PreActive (KMIP 3.0 §11), so a pair created but not
/// activated fails every subsequent call.
pub fn create_and_activate(endpoint: &KmipEndpoint, cell: &KmipCell) -> Result<KeyPair> {
    let (usage_priv, usage_pub) = match cell.class {
        KmipClass::Signature => (UsageMask::SIGN, UsageMask::VERIFY),
        // A KEM pair encapsulates to the public half and decapsulates with
        // the private one.
        KmipClass::Kem => (UsageMask::DECRYPT, UsageMask::ENCRYPT),
    };
    let (resp, _) = send(
        endpoint,
        RequestPayload::CreateKeyPair(CreateKeyPairRequest {
            common_attributes: vec![Attribute::CryptographicAlgorithm(cell.algorithm)],
            private_key_attributes: vec![Attribute::CryptographicUsageMask(usage_priv)],
            public_key_attributes: vec![Attribute::CryptographicUsageMask(usage_pub)],
            seed: None,
        }),
    )
    .with_context(|| format!("CreateKeyPair({})", cell.label))?;

    let private_uid = text_field(&resp, TAG_PRIVATE_KEY_UID)
        .ok_or_else(|| anyhow!("CreateKeyPair response carried no Private Key UID"))?;
    let public_uid = text_field(&resp, TAG_PUBLIC_KEY_UID)
        .ok_or_else(|| anyhow!("CreateKeyPair response carried no Public Key UID"))?;

    for uid in [&private_uid, &public_uid] {
        send(
            endpoint,
            RequestPayload::Activate(ActivateRequest { uid: uid.clone() }),
        )
        .with_context(|| format!("Activate({uid})"))?;
    }
    Ok(KeyPair { private_uid, public_uid })
}

/// Sign, returning the signature bytes.
pub fn sign(endpoint: &KmipEndpoint, uid: &str, data: &[u8]) -> Result<Vec<u8>> {
    let (resp, _) = send(
        endpoint,
        RequestPayload::Sign(SignRequest {
            uid: uid.to_string(),
            data: data.to_vec(),
            cryptographic_parameters: None,
        }),
    )?;
    bytes_field(&resp, TAG_SIGNATURE_DATA)
        .ok_or_else(|| anyhow!("Sign response carried no Signature Data"))
}

/// SignatureVerify, returning the Validity Indicator.
///
/// **A failed verification is not a KMIP error.** The call returns Success
/// with `ValidityIndicator = Invalid` (2), so a harness that only checked
/// Result Status would score a forged signature as a passing verify.
pub fn signature_verify(
    endpoint: &KmipEndpoint,
    uid: &str,
    data: &[u8],
    signature: &[u8],
) -> Result<u32> {
    let (resp, _) = send(
        endpoint,
        RequestPayload::SignatureVerify(SignatureVerifyRequest {
            uid: uid.to_string(),
            data: data.to_vec(),
            signature: signature.to_vec(),
            cryptographic_parameters: None,
        }),
    )?;
    let (frame, _) = codec::decode(&resp)?;
    fn find_enum(v: &codec::Value, tag: u32, out: &mut Option<u32>) {
        if let codec::Value::Structure(children) = v {
            for c in children {
                if c.tag.0 == tag {
                    if let codec::Value::Enumeration(e) = &c.value {
                        if out.is_none() {
                            *out = Some(*e);
                        }
                    }
                }
                find_enum(&c.value, tag, out);
            }
        }
    }
    let mut out = None;
    find_enum(&frame.value, TAG_VALIDITY_INDICATOR, &mut out);
    out.ok_or_else(|| anyhow!("SignatureVerify response carried no Validity Indicator"))
}

/// Encapsulate, then Get the minted SecretData.
///
/// TWO round trips, timed together and labelled as such: Encapsulate returns
/// only a UID, so the shared secret needs the follow-up Get. Reporting just
/// the first call would understate a KEM operation's real cost.
pub fn encapsulate_and_get(endpoint: &KmipEndpoint, public_uid: &str) -> Result<Vec<u8>> {
    let (resp, _) = send(
        endpoint,
        RequestPayload::Encapsulate(EncapsulateRequest {
            uid: public_uid.to_string(),
            input_key_material: None,
            cryptographic_parameters: None,
        }),
    )?;
    let secret_uid = text_field(&resp, TAG_UNIQUE_IDENTIFIER)
        .ok_or_else(|| anyhow!("Encapsulate response carried no Unique Identifier"))?;
    let (get_resp, _) = send(
        endpoint,
        RequestPayload::Get(GetRequest { uid: secret_uid, key_format_type: None, key_wrapping_specification: None }),
    )?;
    Ok(get_resp)
}

/// Decapsulate a ciphertext, then Get the recovered secret — same two-round-
/// trip shape as [`encapsulate_and_get`].
pub fn decapsulate_and_get(
    endpoint: &KmipEndpoint,
    private_uid: &str,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let (resp, _) = send(
        endpoint,
        RequestPayload::Decapsulate(DecapsulateRequest {
            uid: private_uid.to_string(),
            data: ciphertext.to_vec(),
            cryptographic_parameters: None,
        }),
    )?;
    let secret_uid = text_field(&resp, TAG_UNIQUE_IDENTIFIER)
        .ok_or_else(|| anyhow!("Decapsulate response carried no Unique Identifier"))?;
    let (get_resp, _) = send(
        endpoint,
        RequestPayload::Get(GetRequest { uid: secret_uid, key_format_type: None, key_wrapping_specification: None }),
    )?;
    Ok(get_resp)
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

    fn endpoint_from_env() -> Option<KmipEndpoint> {
        let host = std::env::var("KMIP_BENCH_HOST").ok()?;
        let port = std::env::var("KMIP_BENCH_PORT").ok()?.parse().ok()?;
        let ca = std::env::var("KMIP_BENCH_CA").ok()?;
        Some(KmipEndpoint {
            host,
            port,
            ca_pem: std::fs::read(&ca).expect("reading KMIP_BENCH_CA"),
            server_name: std::env::var("KMIP_BENCH_NAME").unwrap_or_else(|_| "localhost".into()),
            tls: ClientTlsProfile::QuantumSafe,
            username: std::env::var("KMIP_BENCH_USER").ok(),
            password: std::env::var("KMIP_BENCH_PASS").ok(),
        })
    }

    /// Every cell in the representative set, through its full operation
    /// sequence, against a live server. This is the gate on the arms being
    /// buildable at all: if a cell cannot complete once here, timing it N
    /// thousand times would only produce confident nonsense.
    #[test]
    fn live_operation_matrix() {
        let Some(endpoint) = endpoint_from_env() else {
            eprintln!("skipping: set KMIP_BENCH_HOST/PORT/CA for the operation matrix");
            return;
        };

        for cell in REPRESENTATIVE_CELLS {
            let kp = create_and_activate(&endpoint, cell)
                .unwrap_or_else(|e| panic!("{}: create+activate failed: {e:#}", cell.label));

            match cell.class {
                KmipClass::Signature => {
                    let data = b"pqctoday kmip arm";
                    let sig = sign(&endpoint, &kp.private_uid, data)
                        .unwrap_or_else(|e| panic!("{}: sign failed: {e:#}", cell.label));
                    assert!(!sig.is_empty(), "{}: empty signature", cell.label);

                    let good = signature_verify(&endpoint, &kp.public_uid, data, &sig)
                        .unwrap_or_else(|e| panic!("{}: verify failed: {e:#}", cell.label));
                    assert_eq!(good, 1, "{}: a valid signature must verify", cell.label);

                    // The trap, asserted here too: a forged signature is a
                    // SUCCESSFUL call with Validity Indicator = Invalid (2).
                    // A harness reading only Result Status would time
                    // forgeries as passing verifies.
                    let mut forged = sig.clone();
                    let mid = forged.len() / 2;
                    forged[mid] ^= 0xFF;
                    let bad = signature_verify(&endpoint, &kp.public_uid, data, &forged)
                        .unwrap_or_else(|e| panic!("{}: forged verify errored: {e:#}", cell.label));
                    assert_eq!(bad, 2, "{}: a forged signature must be Invalid", cell.label);

                    eprintln!("  {:<11} sign {:>5} B · verify Valid · forged Invalid",
                              cell.label, sig.len());
                }
                KmipClass::Kem => {
                    let enc = encapsulate_and_get(&endpoint, &kp.public_uid)
                        .unwrap_or_else(|e| panic!("{}: encapsulate failed: {e:#}", cell.label));
                    assert!(!enc.is_empty(), "{}: empty encapsulate result", cell.label);
                    eprintln!("  {:<11} encapsulate+Get OK ({} B response)", cell.label, enc.len());
                }
            }
        }
    }
}
