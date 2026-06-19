//! cryptopolicy-manager — in-process HTTP admin facade for the crypto-agility
//! policy plane (W4). Compiled into the `pqctoday-kmip` crate via a `#[path]`
//! module declaration in `lib.rs`; the server binary opts in with
//! `--admin-listen`.
//!
//! ## Why in-process
//! `activate` must mutate the **running** server's policy with no restart.
//! [`crate::policy::Engine`] is `Clone` over an inner `Arc<RwLock<…>>`, so the
//! admin facade holds a clone of the *same* engine the KMIP dispatcher uses —
//! an activation here is enforced on the very next KMIP request. There is no
//! KMIP operation that reboots/reloads a server (and inventing one would break
//! separation of duties), so this out-of-band HTTP surface is the path.
//!
//! ## Quantum-safe transport
//! mTLS with the **`X25519MLKEM768`** hybrid key-exchange group (ML-KEM-768 +
//! X25519) via the rustls aws-lc-rs provider — the session is PQC-protected
//! against harvest-now-decrypt-later. Client/server *certificates* stay
//! classical (ECDSA/Ed25519): rustls 0.23 has no ML-DSA certificate support
//! yet (see [`pqc_mtls_config`]). Client certs are required + verified (mTLS).
//!
//! ## Routes (A1 — versioned `/api/v1/`; RFC 7807 problem errors)
//! ```text
//! GET    /healthz                                       → {status:"ok"}
//! GET    /version                                       → {version, git_sha}
//! GET    /openapi.yaml                                  → OpenAPI 3.1 spec
//! GET    /api/v1/policies                               → {policies:[…]}
//! POST   /api/v1/policies      body=yaml               → 201 {saved}
//! GET    /api/v1/policies/{n}                           → {name, yaml}
//! PUT    /api/v1/policies/{n}  body=yaml               → {saved}
//! GET    /api/v1/active                                 → {name,fingerprint}|null
//! PUT    /api/v1/active        body={"name":"…"}       → {activated,fingerprint}
//! POST   /api/v1/validate      body=yaml               → {ok, name}
//! POST   /api/v1/dry-run       body={yaml,op,algo?}    → {decision}
//! GET    /api/v1/audit[?limit=N]                       → {events:[…], total}
//! ```
//!
//! Error shape — `Content-Type: application/problem+json` (RFC 7807):
//! `{"type":"urn:pqctoday:cacp:problem/<code>","title":"…","status":N,"detail":"…"}`

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use rustls::pki_types::CertificateDer;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::policy::{Decision, Engine, PolicyRequest, PolicyStore, StoreError};

/// Cap on a single admin request (headers + body). Policies are small YAML.
const MAX_REQUEST: usize = 1 << 20; // 1 MiB

/// OpenAPI 3.1 spec, embedded at compile time; served at `GET /openapi.yaml`.
const OPENAPI_YAML: &str = include_str!("openapi.yaml");

#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS: {0}")]
    Tls(String),
}

/// Build the quantum-safe mTLS `ServerConfig` for the admin listener:
/// `X25519MLKEM768`-only key exchange (TLS 1.3) + required client certs
/// signed by `client_ca_pem`. Uses the aws-lc-rs provider explicitly (the
/// KMIP listener's `ring` default is untouched).
pub fn pqc_mtls_config(
    server_cert_pem: &[u8],
    server_key_pem: &[u8],
    client_ca_pem: &[u8],
) -> Result<Arc<ServerConfig>, AdminError> {
    use rustls::crypto::aws_lc_rs;

    // Force the post-quantum hybrid KEM group. X25519MLKEM768 is TLS 1.3 only.
    let mut provider = aws_lc_rs::default_provider();
    provider.kx_groups = vec![aws_lc_rs::kx_group::X25519MLKEM768];
    let provider = Arc::new(provider);

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &server_cert_pem[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| AdminError::Tls(format!("server cert: {e}")))?;
    let key = rustls_pemfile::private_key(&mut &server_key_pem[..])
        .map_err(|e| AdminError::Tls(format!("server key: {e}")))?
        .ok_or_else(|| AdminError::Tls("no server private key in PEM".into()))?;

    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut &client_ca_pem[..]) {
        roots
            .add(cert.map_err(|e| AdminError::Tls(format!("client CA: {e}")))?)
            .map_err(|e| AdminError::Tls(format!("root store add: {e}")))?;
    }
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|e| AdminError::Tls(format!("client verifier: {e}")))?;

    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| AdminError::Tls(format!("TLS1.3 required for ML-KEM: {e}")))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|e| AdminError::Tls(e.to_string()))?;
    Ok(Arc::new(config))
}

/// Serve the admin facade forever. `engine` is a clone of the KMIP server's
/// live engine (shared `Arc<RwLock>` inside), so `activate` takes effect
/// immediately on the running dispatcher. `store_root` is the `--policy-dir`.
pub async fn serve_admin(
    addr: SocketAddr,
    store_root: PathBuf,
    engine: Engine,
    ring: Arc<crate::auditlog::RingSink>,
    tls: Arc<ServerConfig>,
) -> Result<(), AdminError> {
    let listener = TcpListener::bind(addr).await?;
    let acceptor = TlsAcceptor::from(tls);
    tracing::info!(
        "cryptopolicy-manager admin facade listening on {addr} (mTLS, X25519MLKEM768)"
    );
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("admin accept error: {e}");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let store_root = store_root.clone();
        let engine = engine.clone();
        let ring = ring.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(tcp, acceptor, store_root, engine, ring).await {
                tracing::warn!("admin conn from {peer} ended: {e}");
            }
        });
    }
}

async fn handle_conn(
    tcp: tokio::net::TcpStream,
    acceptor: TlsAcceptor,
    store_root: PathBuf,
    engine: Engine,
    ring: Arc<crate::auditlog::RingSink>,
) -> Result<(), AdminError> {
    let mut tls = acceptor.accept(tcp).await?;
    let client_cn = client_cert_cn(tls.get_ref().1);

    let (method, path, body) = match read_request(&mut tls).await {
        Ok(v) => v,
        Err(resp) => {
            tls.write_all(&resp).await?;
            tls.shutdown().await.ok();
            return Ok(());
        }
    };

    // Special: OpenAPI spec served as raw YAML (no JSON wrapper).
    if method == "GET" && path == "/openapi.yaml" {
        tls.write_all(&http_raw(200, "OK", "application/yaml", OPENAPI_YAML.as_bytes()))
            .await?;
        tls.shutdown().await.ok();
        return Ok(());
    }

    let store = PolicyStore::new(&store_root);
    let (status, value) =
        route(&store, &store_root, &engine, &ring, &method, &path, &body, client_cn.as_deref());
    let resp = http_json(status, &value);
    tls.write_all(&resp).await?;
    tls.shutdown().await.ok();
    Ok(())
}

/// Dispatch one request. Returns `(status, json)`.
/// Success responses use `application/json`; errors use `application/problem+json` (RFC 7807).
#[allow(clippy::too_many_arguments)]
fn route(
    store: &PolicyStore,
    store_root: &std::path::Path,
    engine: &Engine,
    ring: &crate::auditlog::RingSink,
    method: &str,
    path: &str,
    body: &[u8],
    client_cn: Option<&str>,
) -> (u16, Value) {
    // Strip query string for matching; keep full path for handlers that parse it.
    let path_base = path.split('?').next().unwrap_or(path);

    match (method, path_base) {
        // ── Infrastructure ───────────────────────────────────────────────────
        ("GET", "/healthz") => (200, json!({ "status": "ok" })),

        ("GET", "/version") => (200, json!({
            "version": env!("CARGO_PKG_VERSION"),
            "git_sha": option_env!("GIT_SHA").unwrap_or("unknown"),
        })),

        // ── Policy collection ────────────────────────────────────────────────
        ("GET", "/api/v1/policies") => match store.list() {
            Ok(names) => (200, json!({ "policies": names })),
            Err(e) => store_err(e),
        },

        // Create — policy name is derived from the YAML metadata.name field.
        ("POST", "/api/v1/policies") => match std::str::from_utf8(body) {
            Ok(yaml) => match store.validate_draft(yaml) {
                Ok(p) => {
                    let name = p.policy.metadata.name.clone();
                    match store.save(&name, yaml) {
                        Ok(()) => {
                            tracing::info!("admin: policy {name:?} created by cn={client_cn:?}");
                            (201, json!({ "saved": name }))
                        }
                        Err(e) => store_err(e),
                    }
                }
                Err(e) => store_err(e),
            },
            Err(_) => problem(400, "body is not valid UTF-8 YAML"),
        },

        // ── Policy item ──────────────────────────────────────────────────────
        ("GET", p) if p.starts_with("/api/v1/policies/") => {
            let name = &p["/api/v1/policies/".len()..];
            get_policy(store, store_root, name)
        }

        ("PUT", p) if p.starts_with("/api/v1/policies/") => {
            let name = &p["/api/v1/policies/".len()..];
            match std::str::from_utf8(body) {
                Ok(yaml) => match store.save(name, yaml) {
                    Ok(()) => {
                        tracing::info!("admin: policy {name:?} saved by cn={client_cn:?}");
                        (200, json!({ "saved": name }))
                    }
                    Err(e) => store_err(e),
                },
                Err(_) => problem(400, "body is not valid UTF-8 YAML"),
            }
        }

        // ── Active policy ────────────────────────────────────────────────────
        ("GET", "/api/v1/active") => match store.read_active() {
            Ok(Some(m)) => (200, json!({ "name": m.name, "fingerprint": m.fingerprint })),
            Ok(None) => (200, Value::Null),
            Err(e) => store_err(e),
        },

        // Activate — replaces POST /policies/{name}/activate.
        // Body: {"name": "<policy-name>"}
        // Security-critical: swaps the LIVE enforcement policy with no restart.
        ("PUT", "/api/v1/active") => {
            match serde_json::from_slice::<Value>(body) {
                Ok(req) => match req.get("name").and_then(Value::as_str).map(str::to_owned) {
                    Some(name) => match store.activate_with_engine(&name, engine) {
                        Ok(_prior) => {
                            let fp =
                                store.read_active().ok().flatten().map(|m| m.fingerprint);
                            tracing::warn!(
                                "admin: LIVE policy activated name={name:?} fp={fp:?} by cn={client_cn:?}"
                            );
                            (200, json!({ "activated": name, "fingerprint": fp }))
                        }
                        Err(e) => store_err(e),
                    },
                    None => problem(400, r#"missing "name" field"#),
                },
                Err(_) => problem(400, r#"body must be JSON {"name":"<policy-name>"}"#),
            }
        }

        // ── Validation & dry-run ─────────────────────────────────────────────
        ("POST", "/api/v1/validate") => match std::str::from_utf8(body) {
            Ok(yaml) => match store.validate_draft(yaml) {
                Ok(p) => (200, json!({ "ok": true, "name": p.policy.metadata.name })),
                Err(e) => store_err(e),
            },
            Err(_) => problem(400, "body is not valid UTF-8 YAML"),
        },

        ("POST", "/api/v1/dry-run") => dry_run(store, body),

        // ── Audit ────────────────────────────────────────────────────────────
        // Three-plane audit trail (p1 policy / p2 KMIP / p3 PKCS#11) from the
        // in-memory ring, newest events last. `?limit=N` caps the tail (max 2000).
        ("GET", "/api/v1/audit") => {
            let limit = path
                .split_once("limit=")
                .and_then(|(_, v)| v.split('&').next())
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(200)
                .min(2000);
            let all = ring.snapshot();
            let tail = &all[all.len().saturating_sub(limit)..];
            match serde_json::to_value(tail) {
                Ok(events) => (200, json!({ "events": events, "total": all.len() })),
                Err(e) => problem(500, &e.to_string()),
            }
        }

        _ => problem(404, &format!("no route for {method} {path}")),
    }
}

fn get_policy(store: &PolicyStore, root: &std::path::Path, name: &str) -> (u16, Value) {
    match store.load(name) {
        Ok(p) => {
            let yaml = std::fs::read_to_string(root.join(format!("{name}.yaml"))).ok();
            (200, json!({ "name": p.policy.metadata.name, "yaml": yaml }))
        }
        Err(e) => store_err(e),
    }
}

fn dry_run(store: &PolicyStore, body: &[u8]) -> (u16, Value) {
    let Ok(req): Result<Value, _> = serde_json::from_slice(body) else {
        return problem(400, r#"body must be JSON {"yaml":"…","op":"…","algorithm":"…"}"#);
    };
    let (Some(yaml), Some(op)) = (
        req.get("yaml").and_then(Value::as_str),
        req.get("op").and_then(Value::as_str),
    ) else {
        return problem(400, r#"missing required fields "yaml" and/or "op""#);
    };
    let algorithm = req.get("algorithm").and_then(Value::as_str);
    let empty = std::collections::HashMap::new();
    let now = time::OffsetDateTime::now_utc();
    let p_req = PolicyRequest::minimal(op, algorithm, now, "admin-dry-run", &empty);
    match store.dry_run(yaml, &p_req) {
        Ok(decision) => (200, json!({ "decision": decision_json(&decision) })),
        Err(e) => store_err(e),
    }
}

/// Decision has no `Serialize` impl; project it to a stable JSON shape for the UI.
fn decision_json(d: &Decision) -> Value {
    match d {
        Decision::Allow { .. } => json!({ "outcome": "allow" }),
        Decision::Deny { human, .. } => json!({ "outcome": "deny", "reason": human }),
        Decision::RekeyAndProceed { new_algorithm, .. } => {
            json!({ "outcome": "rekey", "new_algorithm": new_algorithm })
        }
    }
}

fn store_err(e: StoreError) -> (u16, Value) {
    let status = match &e {
        StoreError::Loader(_) | StoreError::BadName(_) => 400,
        _ => 500,
    };
    problem(status, &e.to_string())
}

// ── RFC 7807 problem helpers ─────────────────────────────────────────────────

fn problem(status: u16, detail: &str) -> (u16, Value) {
    (status, problem_value(status, detail))
}

fn problem_value(status: u16, detail: &str) -> Value {
    let (urn, title) = match status {
        400 => ("urn:pqctoday:cacp:problem/bad-request", "Bad Request"),
        404 => ("urn:pqctoday:cacp:problem/not-found", "Not Found"),
        405 => ("urn:pqctoday:cacp:problem/method-not-allowed", "Method Not Allowed"),
        413 => ("urn:pqctoday:cacp:problem/payload-too-large", "Payload Too Large"),
        _ => ("urn:pqctoday:cacp:problem/internal-error", "Internal Server Error"),
    };
    json!({ "type": urn, "title": title, "status": status, "detail": detail })
}

// ── Minimal HTTP/1.1 over the TLS stream ─────────────────────────────────────

/// Read one request: returns `(method, path, body)` or an error response to
/// send verbatim. `Connection: close` semantics — one request per connection.
async fn read_request<S>(tls: &mut S) -> Result<(String, String, Vec<u8>), Vec<u8>>
where
    S: AsyncReadExt + Unpin,
{
    let mut buf = Vec::with_capacity(2048);
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos;
        }
        if buf.len() > MAX_REQUEST {
            return Err(http_json(413, &problem_value(413, "request too large")));
        }
        match tls.read(&mut tmp).await {
            Ok(0) => {
                return Err(http_json(400, &problem_value(400, "connection closed mid-request")))
            }
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(_) => return Err(http_json(400, &problem_value(400, "read error"))),
        }
    };

    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    if method.is_empty() || path.is_empty() {
        return Err(http_json(400, &problem_value(400, "malformed request line")));
    }

    let content_len: usize = lines
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse().ok())
                .flatten()
        })
        .unwrap_or(0);
    if content_len > MAX_REQUEST {
        return Err(http_json(413, &problem_value(413, "body too large")));
    }

    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < content_len {
        match tls.read(&mut tmp).await {
            Ok(0) => break,
            Ok(n) => body.extend_from_slice(&tmp[..n]),
            Err(_) => return Err(http_json(400, &problem_value(400, "body read error"))),
        }
    }
    body.truncate(content_len);
    Ok((method, path, body))
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Serialize `value` as HTTP/1.1.
/// Uses `application/problem+json` for 4xx/5xx (RFC 7807), `application/json` for 2xx.
fn http_json(status: u16, value: &Value) -> Vec<u8> {
    let ct = if status >= 400 { "application/problem+json" } else { "application/json" };
    let body = serde_json::to_vec(value).unwrap_or_default();
    http_raw(status, http_reason(status), ct, &body)
}

fn http_raw(status: u16, reason: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

fn http_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        _ => "Status",
    }
}

/// Extract the leaf client certificate's subject CN (best-effort) for audit.
fn client_cert_cn(conn: &rustls::ServerConnection) -> Option<String> {
    let certs = conn.peer_certificates()?;
    let leaf = certs.first()?;
    let (_, parsed) = x509_parser::parse_x509_certificate(leaf.as_ref()).ok()?;
    parsed
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Engine;

    const VALID: &str =
        "schema_version: 1\nmetadata:\n  name: p\n  description: d\n  authority: a\n  effective: always\nrules: []\n";

    fn store_with(tag: &str) -> (PathBuf, PolicyStore) {
        let dir = std::env::temp_dir().join(format!("pqc-admin-test-{tag}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("p.yaml"), VALID).unwrap();
        let store = PolicyStore::new(&dir);
        (dir, store)
    }

    #[test]
    fn route_list_includes_policy() {
        let (dir, store) = store_with("list");
        let ring = crate::auditlog::RingSink::new(8);
        let (status, body) =
            route(&store, &dir, &Engine::deny_all(), &ring, "GET", "/api/v1/policies", b"", None);
        assert_eq!(status, 200);
        assert!(body["policies"].as_array().unwrap().iter().any(|v| v == "p"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn route_unknown_path_404() {
        let (dir, store) = store_with("404");
        let ring = crate::auditlog::RingSink::new(8);
        let (status, body) =
            route(&store, &dir, &Engine::deny_all(), &ring, "GET", "/nope", b"", None);
        assert_eq!(status, 404);
        assert_eq!(body["status"], 404);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn route_validate_rejects_bad_yaml_400() {
        let (dir, store) = store_with("validate");
        let ring = crate::auditlog::RingSink::new(8);
        let (status, body) = route(
            &store,
            &dir,
            &Engine::deny_all(),
            &ring,
            "POST",
            "/api/v1/validate",
            b"not: a policy",
            None,
        );
        assert_eq!(status, 400);
        assert!(body["detail"].is_string());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn route_active_none_is_null() {
        let (dir, store) = store_with("active");
        let ring = crate::auditlog::RingSink::new(8);
        let (status, body) =
            route(&store, &dir, &Engine::deny_all(), &ring, "GET", "/api/v1/active", b"", None);
        assert_eq!(status, 200);
        assert!(body.is_null());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn route_audit_empty_ring() {
        let (dir, store) = store_with("audit");
        let ring = crate::auditlog::RingSink::new(8);
        let (status, body) =
            route(&store, &dir, &Engine::deny_all(), &ring, "GET", "/api/v1/audit", b"", None);
        assert_eq!(status, 200);
        assert_eq!(body["total"], 0);
        assert!(body["events"].as_array().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn route_healthz() {
        let (dir, store) = store_with("healthz");
        let ring = crate::auditlog::RingSink::new(8);
        let (status, body) =
            route(&store, &dir, &Engine::deny_all(), &ring, "GET", "/healthz", b"", None);
        assert_eq!(status, 200);
        assert_eq!(body["status"], "ok");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn route_version_has_semver() {
        let (dir, store) = store_with("version");
        let ring = crate::auditlog::RingSink::new(8);
        let (status, body) =
            route(&store, &dir, &Engine::deny_all(), &ring, "GET", "/version", b"", None);
        assert_eq!(status, 200);
        assert!(body["version"].as_str().unwrap().contains('.'));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn route_activate_missing_name_400() {
        let (dir, store) = store_with("activate-bad");
        let ring = crate::auditlog::RingSink::new(8);
        let (status, body) = route(
            &store,
            &dir,
            &Engine::deny_all(),
            &ring,
            "PUT",
            "/api/v1/active",
            b"{}",
            None,
        );
        assert_eq!(status, 400);
        assert!(body["detail"].as_str().unwrap().contains("name"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn problem_shape_is_rfc7807() {
        let (status, v) = problem(404, "not here");
        assert_eq!(status, 404);
        assert_eq!(v["status"], 404);
        assert!(v["type"].as_str().unwrap().starts_with("urn:pqctoday:cacp:problem/"));
        assert!(v["title"].is_string());
        assert_eq!(v["detail"], "not here");
    }

    #[test]
    fn pqc_mtls_config_builds_with_x25519mlkem768() {
        let c = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_pem = c.cert.pem();
        let key_pem = c.key_pair.serialize_pem();
        let cfg = pqc_mtls_config(cert_pem.as_bytes(), key_pem.as_bytes(), cert_pem.as_bytes());
        assert!(cfg.is_ok(), "PQC mTLS config failed: {:?}", cfg.err());
    }
}
