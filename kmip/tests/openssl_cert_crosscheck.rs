//! External cross-check: validate KMIP-issued X.509 certificates with an
//! **independent** OpenSSL toolchain (≥3.5, with ML-DSA support).
//!
//! ## Why this exists
//!
//! P2.3's in-crate certify tests verify an issued cert's signature against
//! the CA public key *in our own engine* (self-consistent) and confirm the
//! OID/format against the hub playground. The remaining gap is an
//! INDEPENDENT parser/verifier: a different implementation, with a
//! different ASN.1 decoder and a different signature backend, that agrees
//! our DER is standards-conformant and the signatures we produced are
//! valid. OpenSSL 3.5+ (3.6 in CI) is that independent toolchain — it
//! knows `id-ml-dsa-44/65/87` (2.16.840.1.101.3.4.3.17/18/19) plus
//! RSA/ECDSA.
//!
//! ## What it does, per algorithm (RSA-2048, ECDSA-P256, ML-DSA-65)
//!
//! 1. Mint a CA keypair in the engine + a self-signed CA cert (now carrying
//!    BasicConstraints CA:TRUE + KeyUsage keyCertSign — see `certify.rs`),
//!    via the production `bootstrap_ca_certificate` path.
//! 2. Issue a leaf cert for a fresh CSR via the `Certify` op.
//! 3. **Parse**: `openssl x509 -text` must exit 0 (OpenSSL decodes our DER)
//!    and report the expected Signature/PublicKey AlgorithmIdentifier.
//! 4. **Verify**: `openssl verify -CAfile ca.pem leaf.pem` must exit 0 —
//!    an independent implementation confirms the CA signature our engine
//!    produced (incl. the FIPS-204 ML-DSA signature) is valid.
//!
//! ## OpenSSL discovery / skip policy
//!
//! Locates a suitable openssl via `$OPENSSL_ROOT_DIR/bin/openssl`, then the
//! common Homebrew `openssl@3` prefixes, then a PATH `openssl` ONLY if it
//! reports OpenSSL ≥3.5 (LibreSSL and OpenSSL <3.5 are rejected — macOS
//! `/usr/bin/openssl` is LibreSSL and lacks ML-DSA). It must also list
//! `ml-dsa` under `openssl list -signature-algorithms`. If none is found
//! the test prints a LOUD skip and returns without failing. The project
//! REQUIRES OpenSSL ≥3.5 to build and CI sets `OPENSSL_ROOT_DIR` to an
//! OpenSSL 3.6 build, so CI WILL run this cross-check.

use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use pqctoday_kmip::auditlog::{AuditSink, RingSink};
use pqctoday_kmip::kmip30::{
    CertificateRequestType, CertifyRequest, KmipAlgorithm, ObjectType, State, UsageMask,
};
use pqctoday_kmip::ops::certify::{bootstrap_ca_certificate, certify};
use pqctoday_kmip::ops::{Deps, DepsConfig};
use pqctoday_kmip::policy::Engine;
use pqctoday_kmip::server::auth::AuthContext;
use pqctoday_kmip::store::{MemoryStore, ObjectRecord};

use softhsmrustv3::constants as c;
use softhsmrustv3::native::{self, session, EccCurve};

// ── engine serialisation (mirrors the other engine-touching tests) ──────────

fn engine_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

// ── OpenSSL discovery ────────────────────────────────────────────────────────

/// A located OpenSSL binary known to be ≥3.5 with ML-DSA support.
struct OpenSsl {
    bin: PathBuf,
    version: String,
}

/// `true` iff `openssl version` output denotes OpenSSL (not LibreSSL/BoringSSL)
/// at version ≥3.5.
fn version_ok(version_line: &str) -> bool {
    // Expected form: "OpenSSL 3.6.2 7 Apr 2026 (...)". Reject LibreSSL.
    if !version_line.starts_with("OpenSSL ") {
        return false;
    }
    let rest = version_line.trim_start_matches("OpenSSL ").trim_start();
    let mut nums = rest.split('.');
    let major: u32 = nums.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor: u32 = nums
        .next()
        .map(|s| s.trim_matches(|ch: char| !ch.is_ascii_digit()))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    major > 3 || (major == 3 && minor >= 5)
}

/// Probe a candidate openssl path: must run, report OpenSSL ≥3.5, and list
/// an `ml-dsa` signature algorithm. Returns the version string on success.
fn probe(bin: &PathBuf) -> Option<String> {
    let ver = Command::new(bin).arg("version").output().ok()?;
    if !ver.status.success() {
        return None;
    }
    let version_line = String::from_utf8_lossy(&ver.stdout).trim().to_string();
    if !version_ok(&version_line) {
        return None;
    }
    // Must understand ML-DSA (rejects an OpenSSL 3.5 built without it).
    let algs = Command::new(bin)
        .args(["list", "-signature-algorithms"])
        .output()
        .ok()?;
    if !algs.status.success() {
        return None;
    }
    let listing = String::from_utf8_lossy(&algs.stdout).to_lowercase();
    if !listing.contains("ml-dsa") {
        return None;
    }
    Some(version_line)
}

/// Locate a suitable OpenSSL, in priority order:
/// 1. `$OPENSSL_ROOT_DIR/bin/openssl` (what CI sets)
/// 2. Homebrew `openssl@3` prefixes (arm64 + x86_64 defaults)
/// 3. a PATH `openssl` — accepted ONLY if it probes as OpenSSL ≥3.5 + ML-DSA
fn find_openssl() -> Option<OpenSsl> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(root) = std::env::var("OPENSSL_ROOT_DIR") {
        if !root.is_empty() {
            candidates.push(PathBuf::from(root).join("bin").join("openssl"));
        }
    }
    candidates.push(PathBuf::from("/opt/homebrew/opt/openssl@3/bin/openssl"));
    candidates.push(PathBuf::from("/usr/local/opt/openssl@3/bin/openssl"));
    // A PATH lookup, last (so an explicit/brew OpenSSL 3.6 wins over whatever
    // `openssl` resolves to). `probe` rejects LibreSSL / <3.5.
    candidates.push(PathBuf::from("openssl"));

    for bin in candidates {
        if let Some(version) = probe(&bin) {
            return Some(OpenSsl { bin, version });
        }
    }
    None
}

// ── engine + CA fixture (mirrors certify.rs::bootstrap_ca, via public API) ───

struct CaFixture {
    deps: Deps,
}

/// Generate a CA keypair of `algo` in the engine, mint a self-signed CA
/// cert, and return Deps designated with that CA. Reuses the production
/// `bootstrap_ca_certificate` path exactly like the in-crate P2.3 helper.
fn bootstrap_ca(algo: KmipAlgorithm) -> CaFixture {
    let _ = session::finalize();
    session::init().expect("engine init");
    let sess = session::bootstrap_default_token(0, "so-pin", "user-pin", "crosscheck-ca")
        .expect("bootstrap session");

    let cka_id = b"crosscheck-ca-id".to_vec();
    let _ = match algo {
        KmipAlgorithm::Rsa => native::generate_rsa_keypair(sess, 2048, &cka_id, "ca-rsa"),
        KmipAlgorithm::Ecdsa => {
            native::generate_ecdsa_keypair(sess, EccCurve::P256, &cka_id, "ca-ec")
        }
        KmipAlgorithm::MlDsa65 => {
            native::generate_ml_dsa_keypair(sess, c::CKP_ML_DSA_65, &cka_id, "ca-mldsa")
        }
        // WP6 — RFC 9909 SLH-DSA cross-check. `native_parameter_set` is the
        // same KmipAlgorithm -> CKP_SLH_DSA_* table certify.rs's own tests
        // use (`ops::helpers::native_parameter_set`, `pub(crate)` — not
        // reachable from this external test crate, so the four variants
        // this file exercises are mapped by hand instead).
        KmipAlgorithm::SlhDsaSha2_128s => {
            native::generate_slh_dsa_keypair(sess, c::CKP_SLH_DSA_SHA2_128S, &cka_id, "ca-slhdsa")
        }
        KmipAlgorithm::SlhDsaSha2_128f => {
            native::generate_slh_dsa_keypair(sess, c::CKP_SLH_DSA_SHA2_128F, &cka_id, "ca-slhdsa")
        }
        KmipAlgorithm::SlhDsaShake128s => {
            native::generate_slh_dsa_keypair(sess, c::CKP_SLH_DSA_SHAKE_128S, &cka_id, "ca-slhdsa")
        }
        KmipAlgorithm::SlhDsaShake128f => {
            native::generate_slh_dsa_keypair(sess, c::CKP_SLH_DSA_SHAKE_128F, &cka_id, "ca-slhdsa")
        }
        other => panic!("unsupported CA algo {other:?}"),
    }
    .expect("CA keygen");

    let sink: Arc<dyn AuditSink> = Arc::new(RingSink::new(256));
    let deps = Deps::new(
        Engine::permissive(),
        Arc::new(MemoryStore::new()),
        sink,
        DepsConfig::default(),
    )
    .with_engine_session(sess)
    .with_ca_key("urn:ca-priv", "urn:ca-cert");

    deps.store
        .put(ObjectRecord {
            uid: "urn:ca-priv".into(),
            object_type: ObjectType::PrivateKey,
            algorithm: algo,
            usage_mask: UsageMask::SIGN,
            state: State::Active,
            pkcs11_cka_id: cka_id.clone(),
            ..ObjectRecord::default()
        })
        .unwrap();

    bootstrap_ca_certificate(&deps, "urn:ca-priv", "urn:ca-cert", "PQC CrossCheck CA", 3650)
        .expect("bootstrap CA cert");

    CaFixture { deps }
}

/// Issue a leaf cert for a fresh CSR via the Certify op; return its DER.
fn issue_leaf(deps: &Deps) -> Vec<u8> {
    // Subject key is independent of the CA's signing algorithm; an ECDSA
    // subject key keeps the CSR small and fast to generate.
    let subj_kp = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["leaf.crosscheck.example".into()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "crosscheck-leaf");
    let csr = params.serialize_request(&subj_kp).unwrap();

    let resp = certify(
        deps,
        CertifyRequest {
            certificate_request_type: Some(CertificateRequestType::Pkcs10),
            certificate_request: Some(csr.der().to_vec()),
            ..CertifyRequest::default()
        },
        &AuthContext::open(),
        "crosscheck-issue",
    )
    .unwrap();

    deps.store
        .get(&resp.uid)
        .unwrap()
        .unwrap()
        .certificate_value
        .unwrap()
}

fn ca_cert_der(deps: &Deps) -> Vec<u8> {
    deps.store
        .get("urn:ca-cert")
        .unwrap()
        .unwrap()
        .certificate_value
        .unwrap()
}

// ── openssl invocation helpers ───────────────────────────────────────────────

/// Run `openssl <args>`; return (success, stdout, stderr).
fn run_openssl(ossl: &OpenSsl, args: &[&str]) -> (bool, String, String) {
    let out = Command::new(&ossl.bin)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn {:?}: {e}", ossl.bin));
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// Convert a DER cert file → PEM via `openssl x509`.
fn der_to_pem(ossl: &OpenSsl, der_path: &str, pem_path: &str) {
    let (ok, _out, err) = run_openssl(
        ossl,
        &["x509", "-inform", "DER", "-in", der_path, "-out", pem_path],
    );
    assert!(ok, "DER→PEM conversion of {der_path} failed:\n{err}");
}

// ── the cross-check, per algorithm ───────────────────────────────────────────

/// Expected `Signature Algorithm:` / `Public Key Algorithm:` substrings in
/// `openssl x509 -text` for a CA of `algo`.
fn expected_alg_strings(algo: KmipAlgorithm) -> (&'static str, &'static str) {
    match algo {
        // (signature-algorithm substring, public-key-algorithm substring)
        KmipAlgorithm::Rsa => ("sha256WithRSAEncryption", "rsaEncryption"),
        KmipAlgorithm::Ecdsa => ("ecdsa-with-SHA256", "id-ecPublicKey"),
        KmipAlgorithm::MlDsa65 => ("ML-DSA-65", "ML-DSA-65"),
        // Empirically confirmed against this OpenSSL 3.6.3 build: `openssl
        // req -x509 -newkey slh-dsa-sha2-128s ...` then `x509 -text` prints
        // `Signature Algorithm: SLH-DSA-SHA2-128s` (same string for both
        // the Signature and Public Key Algorithm lines — SLH-DSA uses one
        // OID for both, like ML-DSA).
        KmipAlgorithm::SlhDsaSha2_128s => ("SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128s"),
        KmipAlgorithm::SlhDsaSha2_128f => ("SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-128f"),
        KmipAlgorithm::SlhDsaShake128s => ("SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128s"),
        KmipAlgorithm::SlhDsaShake128f => ("SLH-DSA-SHAKE-128f", "SLH-DSA-SHAKE-128f"),
        other => panic!("no expected strings for {other:?}"),
    }
}

fn cross_check_algo(ossl: &OpenSsl, algo: KmipAlgorithm) {
    let _g = engine_lock();
    let f = bootstrap_ca(algo);
    let leaf_der = issue_leaf(&f.deps);
    let ca_der = ca_cert_der(&f.deps);
    // Drop the engine session for this fixture before the next algo runs.
    let _ = session::finalize();

    let dir = std::env::temp_dir().join(format!(
        "kmip-crosscheck-{:?}-{}",
        algo,
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let leaf_der_p = dir.join("leaf.der");
    let leaf_pem_p = dir.join("leaf.pem");
    let ca_der_p = dir.join("ca.der");
    let ca_pem_p = dir.join("ca.pem");
    std::fs::write(&leaf_der_p, &leaf_der).unwrap();
    std::fs::write(&ca_der_p, &ca_der).unwrap();

    let leaf_der_s = leaf_der_p.to_str().unwrap();
    let leaf_pem_s = leaf_pem_p.to_str().unwrap();
    let ca_der_s = ca_der_p.to_str().unwrap();
    let ca_pem_s = ca_pem_p.to_str().unwrap();

    // ── (a) PARSE: openssl decodes our DER and reports the AlgorithmIds ──
    let (parsed_ok, text, parse_err) =
        run_openssl(ossl, &["x509", "-inform", "DER", "-in", leaf_der_s, "-text", "-noout"]);
    assert!(
        parsed_ok,
        "[{algo:?}] `openssl x509 -text` failed to PARSE the KMIP-issued leaf DER \
         — possible real format defect.\nstderr:\n{parse_err}"
    );

    let (exp_sig, exp_pub) = expected_alg_strings(algo);
    // The Signature Algorithm line appears twice (TBS + outer); both must
    // be present. The Public Key Algorithm line is the leaf's subject key,
    // which is an rcgen ECDSA key — so we instead assert the SIGNATURE
    // algorithm (the CA's) here, which is what this cross-check covers.
    assert!(
        text.contains(exp_sig),
        "[{algo:?}] `openssl x509 -text` did not show expected Signature Algorithm \
         {exp_sig:?}.\nFull -text:\n{text}"
    );

    // Confirm the leaf's own Public Key Algorithm decodes (it is the rcgen
    // subject key: ECDSA). Always present for a parseable cert.
    assert!(
        text.contains("Public Key Algorithm:"),
        "[{algo:?}] `openssl x509 -text` is missing a Public Key Algorithm line.\n{text}"
    );

    // Cross-check the CA cert ITSELF too: it must show the CA's public-key
    // algorithm (this is the SPKI of the CA key, == `exp_pub`).
    let (ca_parsed_ok, ca_text, ca_parse_err) =
        run_openssl(ossl, &["x509", "-inform", "DER", "-in", ca_der_s, "-text", "-noout"]);
    assert!(
        ca_parsed_ok,
        "[{algo:?}] `openssl x509 -text` failed to PARSE the CA cert DER.\nstderr:\n{ca_parse_err}"
    );
    assert!(
        ca_text.contains(exp_sig) && ca_text.contains(exp_pub),
        "[{algo:?}] CA cert -text missing Signature {exp_sig:?} / PublicKey {exp_pub:?}.\n{ca_text}"
    );

    // ── (b) VERIFY: openssl independently checks the CA signature ──
    der_to_pem(ossl, leaf_der_s, leaf_pem_s);
    der_to_pem(ossl, ca_der_s, ca_pem_s);

    let (verified_ok, verify_out, verify_err) =
        run_openssl(ossl, &["verify", "-CAfile", ca_pem_s, "-no_check_time", leaf_pem_s]);
    assert!(
        verified_ok,
        "[{algo:?}] `openssl verify` REJECTED the KMIP-issued leaf — an independent \
         verifier could not confirm the CA signature our engine produced.\n\
         If this is a chain-policy nit (not a signature failure), fix the CA cert, \
         do not weaken the assertion.\nstdout:\n{verify_out}\nstderr:\n{verify_err}"
    );
    // `openssl verify` prints "<path>: OK" on success.
    assert!(
        verify_out.contains("OK"),
        "[{algo:?}] `openssl verify` exited 0 but did not print OK:\n{verify_out}"
    );

    eprintln!(
        "[{algo:?}] CROSS-CHECK PASS — Signature Algorithm: {exp_sig}; verify: {}",
        verify_out.trim()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn openssl_crosscheck_rsa_ecdsa_mldsa() {
    let ossl = match find_openssl() {
        Some(o) => o,
        None => {
            eprintln!(
                "SKIP: no OpenSSL >=3.5 with ML-DSA found — external cross-check not run. \
                 Set OPENSSL_ROOT_DIR to an OpenSSL >=3.5 build (CI does this with \
                 OpenSSL 3.6) or install Homebrew openssl@3. The macOS /usr/bin/openssl \
                 is LibreSSL and is intentionally rejected (no ML-DSA)."
            );
            return;
        }
    };
    eprintln!("Using OpenSSL: {} ({})", ossl.bin.display(), ossl.version);

    cross_check_algo(&ossl, KmipAlgorithm::Rsa);
    cross_check_algo(&ossl, KmipAlgorithm::Ecdsa);
    cross_check_algo(&ossl, KmipAlgorithm::MlDsa65);
}

/// WP6 cross-check ask: "at least 128s byte-cross-checked... and one s/f
/// pair per hash family through the OpenSSL crosscheck" — SHA2-128s/128f
/// and SHAKE-128s/128f (one s/f pair per SLH-DSA hash family), independent
/// of the RSA/ECDSA/ML-DSA test above so a slow "s"-variant CA keygen
/// doesn't block those faster checks from running/reporting first.
#[test]
fn openssl_crosscheck_slh_dsa() {
    let ossl = match find_openssl() {
        Some(o) => o,
        None => {
            eprintln!("SKIP: no OpenSSL >=3.5 with ML-DSA found (same gate as the RSA/ECDSA/ML-DSA cross-check).");
            return;
        }
    };
    eprintln!("Using OpenSSL: {} ({})", ossl.bin.display(), ossl.version);

    cross_check_algo(&ossl, KmipAlgorithm::SlhDsaSha2_128s);
    cross_check_algo(&ossl, KmipAlgorithm::SlhDsaSha2_128f);
    cross_check_algo(&ossl, KmipAlgorithm::SlhDsaShake128s);
    cross_check_algo(&ossl, KmipAlgorithm::SlhDsaShake128f);
}
