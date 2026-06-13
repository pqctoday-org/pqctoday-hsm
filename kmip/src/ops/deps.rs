//! [`Deps`] — shared dependency bundle every op handler takes.
//!
//! The dispatcher constructs one `Deps` at startup; each op handler
//! borrows it. Components:
//!
//! - **`engine`** — Plane-1 [`Engine`] for the policy gate.
//! - **`store`** — Plane-2 [`KeyStore`] for KMIP object metadata.
//! - **`sink`** — Plane-1/2/3 audit fan-out target.
//! - **`config`** — runtime config (slot ID, PIN, vendor identification).
//!
//! Phase 5 (this) wires this together for the foundational ops + tests.
//! Phase 7 (TLS server) constructs `Deps` once at process start and
//! shares it across all per-connection tasks.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::auditlog::AuditSink;
use crate::policy::Engine;
use crate::store::KeyStore;

/// One in-flight multi-part cryptographic operation (KMIP 3.0 §6.1.21 /
/// §6.1.16 streaming: `Init Indicator` → [parts…] → `Final Indicator`,
/// chained by the server-issued `Correlation Value`).
pub struct StreamCtx {
    /// The engine streaming state (owns key schedule + GHASH/CBC chain).
    pub cipher: softhsmrustv3::crypto::multipart::MultipartCipher,
    /// UID the stream was initialised against — §6.1.21 requires every
    /// part to target the same key.
    pub uid: String,
}

/// Runtime configuration the op handlers need.
#[derive(Clone, Debug)]
pub struct DepsConfig {
    /// PKCS#11 slot the engine writes into. Single-slot in v0.1.
    pub pkcs11_slot: u32,
    /// User PIN passed to `C_Login`. Held in memory only; future phases
    /// will switch to a secret-store abstraction.
    pub pkcs11_pin: String,
    /// KMIP `Vendor Identification` for `Query → ServerInformation`.
    /// KMIP 3.0 §6.1.45 — free-form string identifying the implementation.
    pub vendor_identification: String,
    /// KMIP `Server Version` for `Query → ServerInformation`.
    pub server_version: String,
    /// K14 — configured credential store (`--auth-user
    /// <username>:<sha256hex>`, repeatable). **Empty (the default) ≡
    /// open-auth mode**: every request passes and the §8.1.2
    /// `Authentication` header is ignored — required so the hermetic
    /// OASIS replay harness (credential-free transcripts against the
    /// default config) is unaffected. Non-empty ⇒ the dispatcher
    /// enforces §8.1.2 authentication per batch item
    /// (`Authentication Not Successful (0x03)` on failure).
    pub auth_users: Vec<crate::server::auth::AuthUser>,

    /// P2.3 — the server-configured Certificate Authority used by the
    /// §6.1.6 Certify / §6.1.50 Re-certify operations. `None` (the
    /// default) means **the server is not configured as a CA**: every
    /// Certify request fails `Permission Denied` (there is no key
    /// authorised to sign issuances). Set via `--ca-key <PRIV_UID>
    /// --ca-cert <CERT_UID>` on the production binary, or
    /// [`Deps::with_ca_key`] in tests. See the module doc on
    /// [`CaKeyDesignation`] for the authorisation model.
    pub ca_key: Option<CaKeyDesignation>,
}

/// P2.3 — designates the single key/cert pair the server may use as a
/// Certificate Authority for §6.1.6 Certify / §6.1.50 Re-certify.
///
/// ## CA-key authorisation model (the net-new infra for this slice)
///
/// The pragmatic MVP is a *server-configured* CA, not a per-request CA
/// reference: the operator names exactly one stored PrivateKey UID
/// (`private_key_uid`) plus its companion CA Certificate UID
/// (`certificate_uid`). The Certify handler:
///
/// 1. resolves `private_key_uid` → the engine key handle and signs the
///    TBSCertificate **in the engine** (the CA private key never leaves
///    the cryptographic boundary);
/// 2. takes the issuer Distinguished Name from the stored CA
///    Certificate's subject (`certificate_uid`), so issued certs chain
///    to it;
/// 3. **authorisation gate** — only `private_key_uid` may sign an
///    issuance. A Certify request can name no other key; there is no
///    way to coerce an arbitrary stored private key into signing certs.
///    (The §6.1.6 spec also lets a client name a CA via an
///    `X.509 Certificate Issuer` attribute; that is a future extension —
///    the configured CA is the testable MVP.)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaKeyDesignation {
    /// UID of the stored **PrivateKey** object that signs issuances. Its
    /// `algorithm` (RSA / ECDSA / ML-DSA-*) selects the X.509 signature
    /// AlgorithmIdentifier + the engine sign mechanism.
    pub private_key_uid: String,
    /// UID of the stored **Certificate** object whose subject DN becomes
    /// the issuer DN of every certificate this CA issues.
    pub certificate_uid: String,
}

impl DepsConfig {
    /// `true` when a credential store is configured (auth enforced).
    pub fn auth_enabled(&self) -> bool {
        !self.auth_users.is_empty()
    }
}

impl Default for DepsConfig {
    fn default() -> Self {
        Self {
            pkcs11_slot: 0,
            pkcs11_pin: "1234".into(), // sandbox default; production overrides
            vendor_identification: "pqctoday-hsm".into(),
            server_version: env!("CARGO_PKG_VERSION").into(),
            auth_users: Vec::new(), // open-auth — replay harness depends on this
            ca_key: None,           // not a CA unless explicitly configured
        }
    }
}

/// Shared dependencies passed to every op handler.
pub struct Deps {
    pub engine: Engine,
    pub store: Arc<dyn KeyStore>,
    pub sink: Arc<dyn AuditSink>,
    pub config: DepsConfig,
    /// `softhsmrustv3::native` engine session handle (Phase 7b). When
    /// `Some`, op handlers route Plane-3 calls through the real bridge
    /// (real cryptographic output). When `None`, handlers use
    /// deterministic SHA-256 placeholder bytes — preserves the v0.1
    /// unit-test surface (185+ existing tests use `None`) so test
    /// fixtures don't need to bootstrap a real engine session per test.
    ///
    /// Production binary (`bin/pqctoday-kmip.rs`) initialises the
    /// engine and passes `Some(session)`. Closes the §12.7.7 lock from
    /// `IMPLEMENTATION_PLAN.md` once every op handler honours this branch.
    pub engine_session: Option<u32>,
    /// Active multi-part Encrypt/Decrypt streams, keyed by the
    /// server-issued `Correlation Value` (KMIP 3.0 §6.1.21). Lives on
    /// `Deps` so streams survive across requests on the same server.
    pub streams: Mutex<HashMap<Vec<u8>, StreamCtx>>,
    /// Monotonic source for fresh correlation values.
    pub next_correlation: std::sync::atomic::AtomicU64,
    /// K19 — KMIP 3.0 §6.1.58 `Set Defaults` state: per-Object-Type
    /// default attributes applied to factory operations (Create /
    /// CreateKeyPair / Register) beneath the client template (client
    /// template > Set Defaults > server hardcoded). In-memory only —
    /// server-config state, not a managed object, so it is not
    /// persisted in the object store and is reset on restart.
    pub object_defaults:
        Mutex<HashMap<crate::kmip30::ObjectType, Vec<crate::kmip30::Attribute>>>,
}

impl Deps {
    pub fn new(
        engine: Engine,
        store: Arc<dyn KeyStore>,
        sink: Arc<dyn AuditSink>,
        config: DepsConfig,
    ) -> Self {
        Self {
            engine,
            store,
            sink,
            config,
            engine_session: None,
            streams: Mutex::new(HashMap::new()),
            next_correlation: std::sync::atomic::AtomicU64::new(1),
            object_defaults: Mutex::new(HashMap::new()),
        }
    }

    /// Issue a fresh 8-byte correlation value for a new multi-part stream.
    pub fn new_correlation_value(&self) -> Vec<u8> {
        let n = self
            .next_correlation
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        n.to_be_bytes().to_vec()
    }

    /// Construct with an engine session for real bridge wiring. Used by
    /// the production binary.
    pub fn with_engine_session(mut self, session: u32) -> Self {
        self.engine_session = Some(session);
        self
    }

    /// P2.3 — designate the CA key/cert pair this server signs issuances
    /// with (see [`CaKeyDesignation`]). Used by tests and the production
    /// binary's `--ca-key` / `--ca-cert` flags.
    pub fn with_ca_key(mut self, private_key_uid: impl Into<String>, certificate_uid: impl Into<String>) -> Self {
        self.config.ca_key = Some(CaKeyDesignation {
            private_key_uid: private_key_uid.into(),
            certificate_uid: certificate_uid.into(),
        });
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditlog::RingSink;
    use crate::store::MemoryStore;

    #[test]
    fn deps_constructs_with_default_config() {
        let sink: Arc<dyn AuditSink> = Arc::new(RingSink::new(64));
        let _deps = Deps::new(
            Engine::permissive(),
            Arc::new(MemoryStore::new()),
            sink,
            DepsConfig::default(),
        );
    }

    #[test]
    fn default_config_carries_vendor_strings() {
        let c = DepsConfig::default();
        assert!(!c.vendor_identification.is_empty());
        assert!(!c.server_version.is_empty());
    }
}
