//! Interop proof for `SecP384r1MLKEM1024` (`0x11ed`) against a real,
//! independent implementation — OpenSSL 3.6.
//!
//! **Why this test is the gate, and the unit tests are not.** The unit tests in
//! `src/server/secp384r1mlkem1024.rs` round-trip the group against itself. That
//! cannot catch the failure mode that actually matters here: if the combiner
//! order or the share layout is reversed, both sides reverse it identically and
//! agree perfectly — while every other implementation on earth disagrees. Only a
//! handshake against a peer that did NOT come from this codebase proves the wire
//! format. OpenSSL 3.6 has `SecP384r1MLKEM1024` natively, so it is that peer.
//!
//! **Venue: `#[ignore]`.** It needs an OpenSSL ≥ 3.6 binary that lists the
//! group, which the CI image does not have (the Rust container ships 3.5.6,
//! which has ML-KEM but not this hybrid). Run it from the local gate, or
//! directly:
//!
//! ```bash
//! # In a container/host with OpenSSL >= 3.6:
//! cargo test --test secp384r1mlkem1024_interop -- --ignored --nocapture
//!
//! # Point at a specific binary if the default `openssl` is older:
//! OPENSSL_BIN=/usr/local/openssl-3.6/bin/openssl \
//!   cargo test --test secp384r1mlkem1024_interop -- --ignored --nocapture
//! ```
//!
//! The test **fails** rather than silently passing if the tool is missing or
//! too old — a skipped interop test that reports success is exactly the kind of
//! evidence gap this whole exercise exists to close.

use std::io::Write;
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use pqctoday_kmip::server::secp384r1mlkem1024::SECP384R1MLKEM1024;

fn openssl_bin() -> String {
    std::env::var("OPENSSL_BIN").unwrap_or_else(|_| "openssl".to_string())
}

/// Assert the available OpenSSL actually offers the group, so a "PASS" can
/// never come from a client that quietly negotiated something else.
fn require_openssl_with_group() -> String {
    let bin = openssl_bin();
    let out = Command::new(&bin)
        .args(["list", "-tls-groups"])
        .output()
        .unwrap_or_else(|e| panic!("cannot run `{bin}`: {e}. Set OPENSSL_BIN to an OpenSSL >= 3.6"));
    let groups = String::from_utf8_lossy(&out.stdout).to_lowercase();
    assert!(
        groups.contains("secp384r1mlkem1024"),
        "`{bin}` does not offer SecP384r1MLKEM1024 (needs OpenSSL >= 3.6). \
         Groups reported: {groups}"
    );
    bin
}

/// A self-signed P-384 leaf, generated in-process, for the test server.
fn self_signed() -> (
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("self-signed cert");
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
    (cert.cert.der().clone(), key)
}

/// Serve exactly one TLS connection with the given kx groups, echoing a marker
/// once the handshake completes. Returns the port it is listening on.
fn spawn_server(kx_groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup>) -> u16 {
    let (cert, key) = self_signed();
    let provider = rustls::crypto::CryptoProvider {
        cipher_suites: vec![
            rustls::crypto::aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
            rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
        ],
        kx_groups,
        ..rustls::crypto::aws_lc_rs::default_provider()
    };
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("tls13 only")
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("server config");

    let listener = TcpListener::bind("0.0.0.0:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let config = Arc::new(config);

    thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let mut conn = rustls::ServerConnection::new(config).expect("server conn");
            match conn.complete_io(&mut sock) {
                Ok(_) => {
                    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
                    let _ = tls.write_all(b"HANDSHAKE-OK\n");
                    let _ = tls.flush();
                }
                Err(e) => eprintln!("[server] handshake failed: {e}"),
            }
        }
    });
    // Give the listener a moment to be accept()-ready before the client dials.
    thread::sleep(Duration::from_millis(150));
    port
}

/// What `s_client` actually told us, parsed from its output.
///
/// Deliberately NOT the process exit status. `s_client` exits non-zero for
/// reasons that have nothing to do with the key exchange — here, a self-signed
/// test certificate and the "unexpected eof" it reports when the server closes
/// after writing. Gating on the exit code made a handshake that demonstrably
/// negotiated `SecP384r1MLKEM1024` report as a failure. The negotiated-group
/// line is the ground truth.
struct HandshakeOutcome {
    established: bool,
    negotiated_group: Option<String>,
    output: String,
}

impl HandshakeOutcome {
    fn negotiated(&self, group: &str) -> bool {
        self.negotiated_group
            .as_deref()
            .is_some_and(|g| g.eq_ignore_ascii_case(group))
    }
}

/// Drive `openssl s_client` against the server, pinned to one group.
fn openssl_client(bin: &str, port: u16, groups: &str) -> HandshakeOutcome {
    let mut child = Command::new(bin)
        .args([
            "s_client",
            "-connect",
            &format!("127.0.0.1:{port}"),
            "-groups",
            groups,
            "-tls1_3",
            "-servername",
            "localhost",
            // No cert verification: the server uses a self-signed test leaf, and
            // what is under test is the KEY EXCHANGE, not PKI trust. Leaving
            // -verify_return_error on made every run fail with UnknownCA *after*
            // a successful key exchange — a PKI failure wearing a kx failure's
            // clothes. The group assertions below are what give this test teeth.
            "-brief",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn openssl s_client");

    // s_client exits as soon as its stdin closes. Closing it immediately raced
    // the server's post-handshake write: the handshake and group were correct
    // but the application data sometimes never got read. Hold the pipe open
    // briefly so the read can land, THEN close to let s_client exit.
    let stdin = child.stdin.take();
    thread::sleep(Duration::from_millis(400));
    drop(stdin);
    let out = child.wait_with_output().expect("s_client output");
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // `-brief` prints "Negotiated TLS1.3 group: <name>" on success.
    let negotiated_group = output
        .lines()
        .find_map(|l| l.trim().strip_prefix("Negotiated TLS1.3 group:"))
        .map(|g| g.trim().to_string());

    HandshakeOutcome {
        established: output.contains("CONNECTION ESTABLISHED"),
        negotiated_group,
        output,
    }
}

/// THE test: an independent implementation completes a handshake with our
/// locally-composed group. A reversed combiner or a mis-sized share fails here.
#[test]
#[ignore = "needs OpenSSL >= 3.6; run via scripts/local-gate.sh --tls-interop"]
fn openssl_36_completes_a_handshake_using_our_secp384r1mlkem1024() {
    let bin = require_openssl_with_group();
    let port = spawn_server(vec![SECP384R1MLKEM1024]);

    let r = openssl_client(&bin, port, "SecP384r1MLKEM1024");
    println!(
        "--- openssl s_client output ---\n{}\n-------------------------------",
        r.output
    );

    assert!(
        r.established,
        "OpenSSL 3.6 could NOT complete a handshake against our \
         SecP384r1MLKEM1024. This is the reversed-combiner / wrong-share-layout \
         failure the self-round-trip test cannot see.\n{}",
        r.output
    );
    // Require the group BY NAME, so falling back to the bare P-384
    // hybrid_component() can never masquerade as a pass.
    assert!(
        r.negotiated("SecP384r1MLKEM1024"),
        "handshake completed but NOT on SecP384r1MLKEM1024 (got {:?}) — it \
         likely fell back to the classical component.\n{}",
        r.negotiated_group,
        r.output
    );
    assert!(
        r.output.contains("HANDSHAKE-OK"),
        "group negotiated but the application data never arrived — the \
         connection did not actually reach the server's write, so the derived \
         keys may not match.\n{}",
        r.output
    );
}

/// Negative control: the same server, offered only a classical group by the
/// client, must FAIL. Without this, the test above could pass on a server that
/// accepts anything, proving nothing about enforcement.
#[test]
#[ignore = "needs OpenSSL >= 3.6; run via scripts/local-gate.sh --tls-interop"]
fn a_classical_only_client_is_refused_by_the_quantum_safe_group_set() {
    let bin = require_openssl_with_group();
    let port = spawn_server(vec![SECP384R1MLKEM1024]);

    let r = openssl_client(&bin, port, "secp384r1");
    println!(
        "--- classical-only s_client output ---\n{}\n----------------------",
        r.output
    );

    assert!(
        !r.established,
        "a classical-only client completed a handshake against a server \
         offering only SecP384r1MLKEM1024 — §3.3.3 requires classical groups to \
         be ABSENT, not merely deprioritised.\n{}",
        r.output
    );
    assert!(
        r.negotiated_group.is_none(),
        "no connection was established yet a group was negotiated ({:?}) — \
         the assertion above is not measuring what it claims.\n{}",
        r.negotiated_group,
        r.output
    );
}

/// The full §3.3.3 set, exactly as `quantum_safe_provider()` ships it: each of
/// the three mandated groups must independently negotiate.
#[test]
#[ignore = "needs OpenSSL >= 3.6; run via scripts/local-gate.sh --tls-interop"]
fn all_three_mandated_groups_negotiate_against_openssl() {
    let bin = require_openssl_with_group();

    for group in [
        "X25519MLKEM768",
        "SecP256r1MLKEM768",
        "SecP384r1MLKEM1024",
    ] {
        let provider = pqctoday_kmip::server::listener::quantum_safe_provider();
        let port = spawn_server(provider.kx_groups.clone());
        let r = openssl_client(&bin, port, group);
        assert!(
            r.established && r.negotiated(group) && r.output.contains("HANDSHAKE-OK"),
            "§3.3.3 group {group} failed to negotiate against OpenSSL \
             (established={}, negotiated={:?})\n{}",
            r.established,
            r.negotiated_group,
            r.output
        );
        println!("[interop] {group}: negotiated and carried application data");
    }
}

/// Guard: reading the server's own advertised set, all three §3.3.3 groups are
/// present and nothing outside the clause is. Cheap, no OpenSSL needed, so it
/// runs in the ordinary suite.
#[test]
fn quantum_safe_provider_offers_exactly_the_three_mandated_groups() {
    let provider = pqctoday_kmip::server::listener::quantum_safe_provider();
    let names: Vec<u16> = provider
        .kx_groups
        .iter()
        .map(|g| u16::from(g.name()))
        .collect();
    assert!(names.contains(&0x11ec), "X25519MLKEM768 (0x11ec) missing");
    assert!(names.contains(&0x11eb), "SecP256r1MLKEM768 (0x11eb) missing");
    assert!(
        names.contains(&0x11ed),
        "SecP384r1MLKEM1024 (0x11ed) missing — §3.3.3 requires all three"
    );
    assert_eq!(
        names.len(),
        3,
        "§3.3.3 says the server SHALL NOT offer groups outside the list; got {names:?}"
    );
}
