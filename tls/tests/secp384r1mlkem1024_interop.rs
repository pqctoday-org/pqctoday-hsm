//! Interop proof for `SecP384r1MLKEM1024` (`0x11ed`) against a real,
//! independent implementation — OpenSSL 3.6. Relocated verbatim from
//! `pqctoday-kmip/tests/` (2026-08-24, WP2) when the group's own crate moved
//! to `pqctoday-tls` — see that crate's module doc for why. Only the import
//! path changed (`pqctoday_kmip::server::*` → `pqctoday_tls::*`).
//!
//! **Why this test is the gate, and the unit tests are not.** The unit tests in
//! `src/secp384r1mlkem1024.rs` round-trip the group against itself. That
//! cannot catch the failure mode that actually matters here: if the combiner
//! order or the share layout is reversed, both sides reverse it identically and
//! agree perfectly — while every other implementation on earth disagrees. Only a
//! handshake against a peer that did NOT come from this codebase proves the wire
//! format. OpenSSL 3.6 has `SecP384r1MLKEM1024` natively, so it is that peer.
//!
//! **Venue: `#[ignore]`.** It needs an OpenSSL ≥ 3.6 binary that lists the
//! group. Run via `scripts/local-gate.sh --tls-interop`, or directly:
//!
//! ```bash
//! cargo test --test secp384r1mlkem1024_interop -- --ignored --nocapture
//! OPENSSL_BIN=/usr/local/openssl-3.6/bin/openssl \
//!   cargo test --test secp384r1mlkem1024_interop -- --ignored --nocapture
//! ```

use std::io::Write;
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use pqctoday_tls::SECP384R1MLKEM1024;

fn openssl_bin() -> String {
    std::env::var("OPENSSL_BIN").unwrap_or_else(|_| "openssl".to_string())
}

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

fn self_signed() -> (
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("self-signed cert");
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
    (cert.cert.der().clone(), key)
}

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
    thread::sleep(Duration::from_millis(150));
    port
}

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
            "-brief",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn openssl s_client");

    let stdin = child.stdin.take();
    thread::sleep(Duration::from_millis(400));
    drop(stdin);
    let out = child.wait_with_output().expect("s_client output");
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

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
         SecP384r1MLKEM1024.\n{}",
        r.output
    );
    assert!(
        r.negotiated("SecP384r1MLKEM1024"),
        "handshake completed but NOT on SecP384r1MLKEM1024 (got {:?})\n{}",
        r.negotiated_group,
        r.output
    );
    assert!(
        r.output.contains("HANDSHAKE-OK"),
        "group negotiated but application data never arrived\n{}",
        r.output
    );
}

#[test]
#[ignore = "needs OpenSSL >= 3.6; run via scripts/local-gate.sh --tls-interop"]
fn a_classical_only_client_is_refused_by_the_quantum_safe_group_set() {
    let bin = require_openssl_with_group();
    let port = spawn_server(vec![SECP384R1MLKEM1024]);

    let r = openssl_client(&bin, port, "secp384r1");
    assert!(
        !r.established,
        "a classical-only client completed a handshake against a server \
         offering only SecP384r1MLKEM1024\n{}",
        r.output
    );
    assert!(r.negotiated_group.is_none());
}

#[test]
#[ignore = "needs OpenSSL >= 3.6; run via scripts/local-gate.sh --tls-interop"]
fn all_three_mandated_groups_negotiate_against_openssl() {
    let bin = require_openssl_with_group();

    for group in ["X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"] {
        let provider = pqctoday_tls::quantum_safe_provider();
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
