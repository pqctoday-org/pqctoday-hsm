//! CLI-level guards for `--tls-profile` (RG-2).
//!
//! The §3.3.4 identity requirement is enforced in `bin/pqctoday-kmip.rs`, not
//! in the library, so no library test can reach it. It was verified once by
//! hand; these tests are what keep it verified.
//!
//! Why it matters: KMIP 3.0 Profiles §3.3.4 lets a server derive client
//! identity from mutual TLS **or** from an Authentication credential. It does
//! not permit neither. Open-auth mode ignores the Authentication header
//! entirely, so quantum-safe + open-auth + no client CA is a server that
//! transports quantum-safely and then accepts anyone — a posture that looks
//! enforced and isn't.

use std::process::{Command, Stdio};
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_pqctoday-kmip");

fn base_args(listen: &str) -> Vec<String> {
    vec![
        "--store-memory".into(),
        "--listen".into(),
        listen.into(),
    ]
}

/// SHA-256 of "pw", the form `--auth-user` expects.
fn pw_hash() -> String {
    use std::fmt::Write;
    // Avoid pulling a hashing dep into the test: shell out to the same
    // primitive the operator documentation tells users to run.
    let out = Command::new("sh")
        .arg("-c")
        .arg("printf %s 'pw' | shasum -a 256 | cut -d' ' -f1")
        .output()
        .expect("shasum");
    let mut s = String::new();
    write!(s, "{}", String::from_utf8_lossy(&out.stdout).trim()).unwrap();
    s
}

#[test]
fn quantum_safe_refuses_to_start_without_an_identity_source() {
    let out = Command::new(BIN)
        .args(base_args("127.0.0.1:0"))
        .args(["--tls-profile", "quantum-safe"])
        .output()
        .expect("spawn server");

    assert!(
        !out.status.success(),
        "quantum-safe with neither --auth-user nor --tls-client-ca must refuse to start"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("identity source") && combined.contains("3.3.4"),
        "the refusal must name the clause and the fix, got:\n{combined}"
    );
}

#[test]
fn quantum_safe_starts_with_a_credential_store() {
    let mut child = Command::new(BIN)
        .args(base_args("127.0.0.1:0"))
        .args(["--tls-profile", "quantum-safe"])
        .args(["--auth-user", &format!("alice:{}", pw_hash())])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn server");

    // Still running after a beat = it got past the guard and bound.
    std::thread::sleep(Duration::from_millis(2500));
    let alive = child.try_wait().expect("try_wait").is_none();
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        alive,
        "quantum-safe with --auth-user must start; it exited instead"
    );
}

/// The permissive default must remain startable with no credentials at all —
/// the historical behaviour every existing caller depends on.
#[test]
fn permissive_starts_without_any_identity_source() {
    let mut child = Command::new(BIN)
        .args(base_args("127.0.0.1:0"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn server");

    std::thread::sleep(Duration::from_millis(2500));
    let alive = child.try_wait().expect("try_wait").is_none();
    let _ = child.kill();
    let _ = child.wait();

    assert!(alive, "permissive must still start with no --auth-user");
}

#[test]
fn unknown_tls_profile_is_rejected() {
    let out = Command::new(BIN)
        .args(base_args("127.0.0.1:0"))
        .args(["--tls-profile", "not-a-profile"])
        .output()
        .expect("spawn server");

    assert!(!out.status.success(), "an unknown profile must be rejected");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("permissive") && combined.contains("quantum-safe"),
        "the error should name the valid profiles, got:\n{combined}"
    );
}
