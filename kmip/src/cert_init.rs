//! C0 — internalized mTLS cert minting for the admin facade.
//!
//! Replaces the `openssl`-CLI shelling in `kmip-entrypoint.sh` so that the
//! binary can self-init in a distroless / no-shell image. Generates three
//! ECDSA P-256 roles on first boot; subsequent boots detect existing files and
//! skip generation (idempotent).
//!
//! ## Generated files
//!
//! ```text
//! <dir>/
//!   ca.key        CA private key (PEM, PKCS#8)
//!   ca.crt        CA self-signed cert (PEM)
//!   server.key    Admin-facade server key (PEM, PKCS#8)
//!   server.crt    Server cert signed by the CA (PEM); SANs: pqc-kmip, pqc-grpc,
//!                 pqc-rest, pqc-grpc-baseline, pqc-rest-baseline, localhost, 127.0.0.1
//!                 (the gRPC/REST PKCS#11 remoting services share this one mint —
//!                 sandbox-bench-transport-arms-plan-08242026.md WP2)
//!   client.key    kms-proxy client key (PEM, PKCS#8)
//!   client.crt    Client cert signed by the CA (PEM); CN=sandbox-kms-proxy
//! ```
//!
//! Cert lifetime: 825 days (within Apple/browser limits). ECDSA P-256 matches
//! what the shell script generated; quantum-safety is in the X25519MLKEM768 TLS
//! key exchange, not the cert signatures (rustls 0.23 has no ML-DSA cert support).

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
    Ia5String, IsCa, KeyPair, KeyUsagePurpose, SanType, PKCS_ECDSA_P256_SHA256,
};

/// Paths to the minted cert/key PEM files inside `dir`.
#[derive(Debug, Clone)]
pub struct AdminCertPaths {
    pub ca_cert: PathBuf,
    pub server_cert: PathBuf,
    pub server_key: PathBuf,
    pub client_cert: PathBuf,
    pub client_key: PathBuf,
}

impl AdminCertPaths {
    fn from_dir(dir: &Path) -> Self {
        Self {
            ca_cert: dir.join("ca.crt"),
            server_cert: dir.join("server.crt"),
            server_key: dir.join("server.key"),
            client_cert: dir.join("client.crt"),
            client_key: dir.join("client.key"),
        }
    }
}

/// Generate admin mTLS certs into `dir` if they do not already exist.
///
/// Idempotent: if `<dir>/ca.crt` is present the function returns immediately
/// with the existing paths. Callers should wire the returned paths into
/// `--admin-tls-cert / --admin-tls-key / --admin-client-ca`.
pub fn init_certs_if_missing(dir: &Path) -> anyhow::Result<AdminCertPaths> {
    let paths = AdminCertPaths::from_dir(dir);

    if paths.ca_cert.exists() {
        tracing::info!("admin mTLS certs already present in {dir:?} — skipping generation");
        return Ok(paths);
    }

    tracing::info!("admin mTLS certs not found in {dir:?} — generating CA + server + client");
    std::fs::create_dir_all(dir)?;

    let expiry = time::OffsetDateTime::now_utc() + time::Duration::days(825);

    // ── CA ───────────────────────────────────────────────────────────────────
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|e| anyhow::anyhow!("CA key gen: {e}"))?;
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.not_after = expiry;
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "pqctoday-admin-ca");
    ca_params.distinguished_name = ca_dn;
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .map_err(|e| anyhow::anyhow!("CA self-sign: {e}"))?;

    // ── Server cert (SANs: service DNS name + localhost + loopback IP) ───────
    let server_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|e| anyhow::anyhow!("server key gen: {e}"))?;
    let mut srv_params = CertificateParams::default();
    let mut srv_dn = DistinguishedName::new();
    srv_dn.push(DnType::CommonName, "pqc-kmip-admin");
    srv_params.distinguished_name = srv_dn;
    srv_params.key_usages =
        vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
    srv_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    // Shared mint: the gRPC/REST PKCS#11 remoting services (pqc-grpc, pqc-rest,
    // and their un-gated classical-baseline twins) mount the same admin-certs
    // volume as pqc-kmip, so this one mint's server cert must be valid for all
    // of them (sandbox-bench-transport-arms-plan-08242026.md WP2).
    const SERVICE_DNS_NAMES: &[&str] = &[
        "pqc-kmip",
        "pqc-grpc",
        "pqc-rest",
        "pqc-grpc-baseline",
        "pqc-rest-baseline",
        "localhost",
    ];
    let mut subject_alt_names: Vec<SanType> = SERVICE_DNS_NAMES
        .iter()
        .map(|name| {
            Ia5String::try_from(*name)
                .map(SanType::DnsName)
                .map_err(|e| anyhow::anyhow!("SAN {name}: {e}"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    subject_alt_names.push(SanType::IpAddress(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)));
    srv_params.subject_alt_names = subject_alt_names;
    srv_params.not_after = expiry;
    let server_cert = srv_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .map_err(|e| anyhow::anyhow!("server cert sign: {e}"))?;

    // ── Client cert (CN=sandbox-kms-proxy; clientAuth) ───────────────────────
    let client_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|e| anyhow::anyhow!("client key gen: {e}"))?;
    let mut cli_params = CertificateParams::default();
    let mut cli_dn = DistinguishedName::new();
    cli_dn.push(DnType::CommonName, "sandbox-kms-proxy");
    cli_params.distinguished_name = cli_dn;
    cli_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    cli_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    cli_params.not_after = expiry;
    let client_cert = cli_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .map_err(|e| anyhow::anyhow!("client cert sign: {e}"))?;

    // ── Write PEM files ───────────────────────────────────────────────────────
    std::fs::write(dir.join("ca.key"), ca_key.serialize_pem())?;
    std::fs::write(&paths.ca_cert, ca_cert.pem())?;
    std::fs::write(&paths.server_key, server_key.serialize_pem())?;
    std::fs::write(&paths.server_cert, server_cert.pem())?;
    std::fs::write(dir.join("client.key"), client_key.serialize_pem())?;
    std::fs::write(&paths.client_cert, client_cert.pem())?;

    tracing::info!(
        "admin mTLS certs written to {dir:?}: ca.crt, server.crt/key, client.crt/key"
    );
    Ok(paths)
}
