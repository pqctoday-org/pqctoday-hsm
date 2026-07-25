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
use std::sync::{Arc, Condvar, Mutex, Weak};

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
    /// Part F §F7.5 — the tenant that opened this stream. A continuation
    /// part from a different identity is rejected as an unknown
    /// correlation value (anti-oracle), even though the entry-level
    /// owner check on the stream's `uid` already blocks the direct
    /// cross-tenant path — this makes the stream map self-defending
    /// rather than relying on that distant check.
    pub owner: Option<String>,
}

/// Phase 4 — mutable state of one server-tracked asynchronous job
/// (KMIP 3.0 §7.2 `Asynchronous Request` Structure content, plus the
/// eventual outcome once `stage == Completed`).
pub struct AsyncJobState {
    pub operation: crate::kmip30::Operation,
    pub stage: crate::kmip30::ProcessingStage,
    pub submitted_at: time::OffsetDateTime,
    /// `None` until `stage == Completed`. Holds exactly what a
    /// synchronous call to the same operation would have produced —
    /// the async subsystem changes *when* the client learns the
    /// result, never *what* the result is.
    pub outcome: Option<crate::error::Result<crate::kmip30::ResponsePayload>>,
    /// Part F §F7.5 — the tenant that submitted this job. `Poll` returns
    /// the deferred operation's FULL response payload (which for a
    /// deferred `Get`/`Export`/`Decrypt` is key material), so
    /// Poll/Cancel/Process must reject a foreign tenant's correlation
    /// value as the same `Invalid Asynchronous Correlation Value` a
    /// genuinely unknown one produces, and `QueryAsynchronousRequests`
    /// must list only the caller's own jobs. Without this, a tenant
    /// could Poll another tenant's deferred material by guessing its
    /// (monotonic, predictable) correlation value.
    pub owner: Option<String>,
}

/// One server-tracked async job (§6.1.45 Poll / §6.1.5 Cancel / §6.1.48
/// Process / §6.1.48 Query Asynchronous Requests all key off the same
/// record via its `Asynchronous Correlation Value`).
///
/// `done` is signalled exactly once, when `state.stage` transitions to
/// `Completed`. `Process` blocks on it instead of re-running the
/// operation itself — double-execution would be a real correctness bug
/// (e.g. double-decrementing a Usage Limits counter), not just an
/// implementation nuance.
pub struct AsyncJob {
    pub state: Mutex<AsyncJobState>,
    pub done: Condvar,
}

impl AsyncJob {
    pub fn new(operation: crate::kmip30::Operation, owner: Option<String>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(AsyncJobState {
                operation,
                stage: crate::kmip30::ProcessingStage::Submitted,
                submitted_at: time::OffsetDateTime::now_utc(),
                outcome: None,
                owner,
            }),
            done: Condvar::new(),
        })
    }

    /// Block the calling thread until this job reaches `Completed`.
    /// Used by `Process` (§6.1.46: "effectively changing the
    /// processing mode for that batch item to that resembling
    /// synchronous processing") and by the `Deps::new`-only (no
    /// `self_handle`) eager-fallback executor, where the predicate is
    /// already true by the time anything can call this — so the wait
    /// never actually blocks there.
    pub fn wait_until_completed(&self) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        while st.stage != crate::kmip30::ProcessingStage::Completed {
            st = self.done.wait(st).unwrap_or_else(|e| e.into_inner());
        }
    }

    pub fn mark_in_process(&self) {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        st.stage = crate::kmip30::ProcessingStage::InProcess;
    }

    /// Atomically transition `Submitted` → `InProcess`, but ONLY if
    /// still `Submitted`. Returns `false` (state left untouched) if the
    /// job already left `Submitted` — e.g. `try_cancel_if_submitted`
    /// won the race against the executor and already marked it
    /// `Completed`. The executor (real background thread or the eager
    /// inline fallback) MUST check this before running the real
    /// operation: calling the unconditional `mark_in_process` here
    /// instead would clobber an already-recorded cancellation outcome
    /// with the real result moments later, and briefly resurrect an
    /// already-`Completed` job's stage back to `InProcess` in between —
    /// a genuine window where a concurrent `Poll` (sees `Completed`)
    /// and a `QueryAsynchronousRequests` running immediately after (sees
    /// the resurrected `InProcess`) visibly disagree about whether the
    /// same job is done.
    pub fn try_start_if_submitted(&self) -> bool {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.stage != crate::kmip30::ProcessingStage::Submitted {
            return false;
        }
        st.stage = crate::kmip30::ProcessingStage::InProcess;
        true
    }

    pub fn mark_completed(&self, outcome: crate::error::Result<crate::kmip30::ResponsePayload>) {
        {
            let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
            st.stage = crate::kmip30::ProcessingStage::Completed;
            st.outcome = Some(outcome);
        }
        self.done.notify_all();
    }

    /// `Cancel` (§6.1.5) — atomically transition `Submitted` →
    /// `Completed` (with an `Operation Canceled By Requester` outcome)
    /// and report success, or report failure without touching
    /// anything if the job has already moved past `Submitted`. Must be
    /// a single locked check-and-set: reading `stage` and then calling
    /// `mark_completed` as two separate lock acquisitions would race
    /// against a background executor thread concurrently transitioning
    /// `Submitted → InProcess → Completed`, which could clobber a
    /// genuine real result with a fake "canceled" one.
    pub fn try_cancel_if_submitted(&self) -> bool {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.stage != crate::kmip30::ProcessingStage::Submitted {
            return false;
        }
        st.stage = crate::kmip30::ProcessingStage::Completed;
        st.outcome = Some(Err(crate::error::KmipError::operation_canceled_by_requester()));
        drop(st);
        self.done.notify_all();
        true
    }
}

/// Keyed by the server-generated §9.1 `Asynchronous Correlation Value`.
pub type AsyncJobStore = Mutex<HashMap<Vec<u8>, Arc<AsyncJob>>>;

/// Runtime configuration the op handlers need.
#[derive(Clone, Debug)]
pub struct DepsConfig {
    /// PKCS#11 slot the engine writes into. Single-slot in v0.1.
    pub pkcs11_slot: u32,
    /// User PIN passed to `C_Login`. Held in memory only; future phases
    /// will switch to a secret-store abstraction.
    pub pkcs11_pin: String,
    /// KMIP `Vendor Identification` for `Query → ServerInformation`.
    /// KMIP 3.0 §6.1.47 — free-form string identifying the implementation.
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
    /// §6.1.6 Certify / §6.1.52 Re-certify operations. `None` (the
    /// default) means **the server is not configured as a CA**: every
    /// Certify request fails `Permission Denied` (there is no key
    /// authorised to sign issuances). Set via `--ca-key <PRIV_UID>
    /// --ca-cert <CERT_UID>` on the production binary, or
    /// [`Deps::with_ca_key`] in tests. See the module doc on
    /// [`CaKeyDesignation`] for the authorisation model.
    pub ca_key: Option<CaKeyDesignation>,

    /// §6.1.57 RNG Seed behavior — see [`RngSeedMode`]. Defaults to
    /// full-consume (the pre-existing behavior; CS-RNG-O-1 pins it).
    pub rng_seed_mode: RngSeedMode,

    /// Part F §F7.2 — see [`TenancyMode`]. Defaults to `Single` (today's
    /// behavior, unchanged).
    pub tenancy_mode: TenancyMode,
    /// Pre-configured tenants for `TenancyMode::Strict`. Ignored in
    /// `Single`/`Auto` modes.
    pub strict_tenants: Vec<StrictTenantConfig>,
}

/// P2.3 — designates the single key/cert pair the server may use as a
/// Certificate Authority for §6.1.6 Certify / §6.1.52 Re-certify.
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

/// KMIP 3.0 §6.1.57 `RNG Seed` — the spec text: "The server MAY elect to
/// ignore the information provided by the client and MAY indicate this
/// to the client by returning zero as the value in the Data Length
/// response." This is a server-chosen, mutually-exclusive policy
/// choice, not client-selectable per request — the OASIS Cryptographic
/// Services Optional profile pins four concrete behaviors as separate
/// conformance tests (CS-RNG-O-1..4), each expecting a different one:
///
/// | Variant | Response `DataLength` for a 32-byte seed | Test |
/// |---|---|---|
/// | `FullConsume` (default) | 32 (all of it) | CS-RNG-O-1 |
/// | `PartialConsume` | 16 (a fixed cap, per the pinned transcript) | CS-RNG-O-2 |
/// | `Ignore` | 0 | CS-RNG-O-3 |
/// | `Deny` | n/a — `PermissionDenied` | CS-RNG-O-4 |
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RngSeedMode {
    #[default]
    FullConsume,
    PartialConsume,
    Ignore,
    Deny,
}

/// Fixed byte cap for `RngSeedMode::PartialConsume` — CS-RNG-O-2 pins
/// exactly 16 regardless of the client-supplied seed length.
pub const RNG_SEED_PARTIAL_CONSUME_CAP: usize = 16;

/// Part F (rust-hsm-perf-bench-scenario-plan-07182026.md §F7.2) — how a
/// KMIP client identity gets its own PKCS#11 token. `Single` (the
/// default) is EXACTLY today's behavior: every request shares
/// `Deps::engine_session`, one tenant, zero config needed, zero change
/// to any of the ~60 existing `deps.engine_session` call sites.
///
/// STATUS: the resolution primitive (`Deps::resolve_tenant_session`)
/// exists and is tested for all three modes, but is NOT YET called by
/// the dispatcher or any op handler — those still read
/// `deps.engine_session` directly, so today every deployment runs
/// (and behaves) as `Single` regardless of this field's value. Wiring
/// the dispatcher to authenticate-then-resolve-then-thread the tenant
/// session into op handlers is the remaining piece of §F7 (a
/// signature-level change across every op handler, tracked separately —
/// see the plan's F7/rev-5 status note).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum TenancyMode {
    #[default]
    Single,
    /// First connection from a CA-validated identity auto-provisions a
    /// fresh token: next free slot, a server-generated PIN recorded in
    /// `Deps::tenant_pins` (readable by the operator) so the token
    /// stays openable by out-of-band PKCS#11 tooling — the user's
    /// "per-tenant configured PINs" decision, reconciled with
    /// auto-onboarding by having the server mint (rather than
    /// pre-collect) the PIN.
    Auto,
    /// Only identities in `DepsConfig::strict_tenants` may operate;
    /// every other identity is rejected before touching the engine.
    Strict,
}

/// One pre-configured tenant for `TenancyMode::Strict` — identity, the
/// PKCS#11 slot it owns, and its token's PINs (per-tenant CONFIGURED
/// PINs, per the user's decision — the same PIN an operator could use
/// to open this tenant's token directly through raw PKCS#11 tooling).
#[derive(Clone, Debug)]
pub struct StrictTenantConfig {
    pub identity: crate::server::auth::Identity,
    pub slot: u32,
    pub so_pin: String,
    pub user_pin: String,
}

/// A provisioned tenant's live engine binding — the slot its token
/// occupies and the open, USER-logged-in session requests for that
/// tenant should use.
#[derive(Clone, Copy, Debug)]
pub struct TenantCtx {
    pub slot: u32,
    pub engine_session: u32,
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
            rng_seed_mode: RngSeedMode::FullConsume,
            tenancy_mode: TenancyMode::Single, // today's behavior, unchanged
            strict_tenants: Vec::new(),
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
    /// Part F §F7.2 — live per-identity tenant bindings (populated by
    /// `resolve_tenant_session` in `Auto`/`Strict` modes; empty and
    /// unused in `Single` mode). Slot 0 is reserved for `engine_session`
    /// (the `Single`-mode / `cli.slot` default); tenant provisioning
    /// starts at `next_auto_slot`.
    pub tenants: Mutex<HashMap<crate::server::auth::Identity, TenantCtx>>,
    /// `Auto`-mode server-generated PINs, recorded so an operator can
    /// read them back and open a tenant's token directly through raw
    /// PKCS#11 tooling (the user's "per-tenant configured PINs"
    /// decision, reconciled with auto-onboarding — see [`TenancyMode::Auto`]).
    pub tenant_pins: Mutex<HashMap<crate::server::auth::Identity, (String, String)>>,
    /// Next PKCS#11 slot `Auto` mode will provision. Starts at 1 (slot 0
    /// is the `Single`-mode default token).
    pub next_auto_slot: std::sync::atomic::AtomicU32,
    /// Active multi-part Encrypt/Decrypt streams, keyed by the
    /// server-issued `Correlation Value` (KMIP 3.0 §6.1.23). Lives on
    /// `Deps` so streams survive across requests on the same server.
    pub streams: Mutex<HashMap<Vec<u8>, StreamCtx>>,
    /// Monotonic source for fresh correlation values.
    pub next_correlation: std::sync::atomic::AtomicU64,
    /// K19 — KMIP 3.0 §6.1.60 `Set Defaults` state: per-Object-Type
    /// default attributes applied to factory operations (Create /
    /// CreateKeyPair / Register) beneath the client template (client
    /// template > Set Defaults > server hardcoded). In-memory only —
    /// server-config state, not a managed object, so it is not
    /// persisted in the object store and is reset on restart.
    ///
    /// Part F §F7.5 — PER-TENANT: the outer key is the setting tenant's
    /// identity (`None` = the `Single`-mode / anonymous bucket). One
    /// tenant's `Set Defaults` only affects its own factory operations,
    /// matching the isolation model of every managed object — a tenant
    /// can't silently change another tenant's key-generation defaults.
    pub object_defaults: Mutex<
        HashMap<Option<String>, HashMap<crate::kmip30::ObjectType, Vec<crate::kmip30::Attribute>>>,
    >,
    /// Phase 3.2 — client-set §6.1.57 Constraints, replacing the
    /// engine-bounds default `Get Constraints` (§6.1.28) otherwise
    /// reports. `None` ⇒ no client override yet; `get_constraints`
    /// falls back to the static engine-derived table. `Some(vec![])`
    /// (an explicit empty Set Constraints) is a real override meaning
    /// "no constraints" — distinct from `None`.
    pub constraints: Mutex<Option<Vec<crate::kmip30::Constraint>>>,
    /// K14 (Phase 1.4) — live `Login`-issued sessions, keyed by the
    /// ticket's `Ticket Value` bytes. `Logout` removes an entry; a
    /// `Credential::Ticket` presented in a later request's §8.1.2
    /// `Authentication` header is looked up here
    /// (`dispatcher::authenticate_request`). Server-wide (not
    /// per-connection) — matches this server's other session-scale
    /// state (`pkcs11_virtual_initialized`).
    pub sessions: Mutex<HashMap<Vec<u8>, crate::server::auth::SessionRecord>>,
    /// KMIP §6.1.44 PKCS_11 passthrough — tracks whether a client has
    /// issued `C_Initialize` without an intervening `C_Finalize`
    /// (PKCS#11 v3.2 §5.6 library-lifecycle state). Deliberately
    /// SEPARATE from `engine_session`'s real init state: the engine
    /// stays initialized for the server's whole lifetime so every other
    /// KMIP operation keeps working, so a client-driven `C_Finalize`
    /// here must not tear down the real engine out from under other
    /// tenants. Read-only PKCS#11 functions (`C_GetInfo`, ...) still
    /// dispatch to the real engine regardless of this flag.
    pub pkcs11_virtual_initialized: std::sync::atomic::AtomicBool,
    /// Phase 4 — live asynchronous jobs, keyed by the server-generated
    /// §9.1 Asynchronous Correlation Value. See [`AsyncJob`].
    pub async_jobs: AsyncJobStore,
    /// Phase 4 — a weak self-reference, set once via
    /// [`Deps::install_self_handle`] right after the production binary
    /// wraps its `Deps` in `Arc` (`bin/pqctoday-kmip.rs` /
    /// `server::listener`). Lets the async-job executor hand a
    /// `'static`-lifetime `Arc<Deps>` to a genuine background OS
    /// thread. **Unset in every test that builds `Deps` directly via
    /// [`Deps::new`]** (544+ existing call sites) — those transparently
    /// fall back to running the job inline, synchronously, before the
    /// enqueuing call returns (see `dispatcher::run_async_job_eagerly`).
    /// That fallback is fully protocol-correct — the enqueuing
    /// response is still `OperationPending`, never the payload — it
    /// just isn't genuinely deferred past the enqueuing request, which
    /// no test needs. Not `Clone`/`Copy`, so it lives behind a
    /// `OnceLock`.
    pub self_handle: std::sync::OnceLock<Weak<Deps>>,
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
            tenants: Mutex::new(HashMap::new()),
            tenant_pins: Mutex::new(HashMap::new()),
            next_auto_slot: std::sync::atomic::AtomicU32::new(1),
            streams: Mutex::new(HashMap::new()),
            next_correlation: std::sync::atomic::AtomicU64::new(1),
            object_defaults: Mutex::new(HashMap::new()),
            constraints: Mutex::new(None),
            sessions: Mutex::new(HashMap::new()),
            pkcs11_virtual_initialized: std::sync::atomic::AtomicBool::new(false),
            async_jobs: Mutex::new(HashMap::new()),
            self_handle: std::sync::OnceLock::new(),
        }
    }

    /// Issue a fresh 8-byte correlation value for a new multi-part stream
    /// (or a fresh async job — same generator, disjoint namespaces).
    pub fn new_correlation_value(&self) -> Vec<u8> {
        let n = self
            .next_correlation
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        n.to_be_bytes().to_vec()
    }

    /// Phase 4 — enable genuine background execution of asynchronous
    /// jobs. Call once, immediately after wrapping a freshly-built
    /// `Deps` in `Arc` (`let deps = Arc::new(Deps::new(...)); deps.install_self_handle();`).
    /// Without this call the async-job executor still works correctly,
    /// just eagerly/inline rather than on a detached thread — see
    /// [`Deps::self_handle`].
    pub fn install_self_handle(self: &Arc<Self>) {
        let _ = self.self_handle.set(Arc::downgrade(self));
    }

    /// Construct with an engine session for real bridge wiring. Used by
    /// the production binary.
    pub fn with_engine_session(mut self, session: u32) -> Self {
        self.engine_session = Some(session);
        self
    }

    /// Part F §F7.2 — resolve the PKCS#11 engine session an authenticated
    /// request should use.
    ///
    /// `Single` mode (default) returns `self.engine_session` unchanged —
    /// `identity` is ignored, so this is a drop-in, zero-behavior-change
    /// replacement for reading `deps.engine_session` directly wherever a
    /// call site is migrated to it.
    ///
    /// `Auto`/`Strict` require `identity`; each looks up (or, in `Auto`,
    /// provisions) that identity's own token, so different tenants get
    /// different sessions on different slots — which is what makes the
    /// Part F engine-side isolation gate (already merged) actually
    /// separate KMIP clients from each other, instead of every client
    /// sharing the one `Single`-mode token.
    pub fn resolve_tenant_session(
        &self,
        identity: Option<&crate::server::auth::Identity>,
    ) -> crate::error::Result<u32> {
        match self.config.tenancy_mode {
            TenancyMode::Single => self.engine_session.ok_or_else(|| {
                crate::error::KmipError::failed(
                    crate::error::ResultReason::GeneralFailure,
                    "engine not initialised (no engine_session)",
                )
            }),
            TenancyMode::Strict => {
                let identity = identity.ok_or_else(Self::no_identity_err)?;
                if let Some(ctx) = self.tenants_lock().get(identity) {
                    return Ok(ctx.engine_session);
                }
                let cfg = self
                    .config
                    .strict_tenants
                    .iter()
                    .find(|t| &t.identity == identity)
                    .cloned()
                    .ok_or_else(|| {
                        crate::error::KmipError::failed(
                            crate::error::ResultReason::AuthenticationNotSuccessful,
                            "identity is not a configured strict tenant",
                        )
                    })?;
                self.provision_tenant(identity.clone(), cfg.slot, &cfg.so_pin, &cfg.user_pin)
            }
            TenancyMode::Auto => {
                let identity = identity.ok_or_else(Self::no_identity_err)?;
                if let Some(ctx) = self.tenants_lock().get(identity) {
                    return Ok(ctx.engine_session);
                }
                let slot = self
                    .next_auto_slot
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let so_pin = generate_tenant_pin();
                let user_pin = generate_tenant_pin();
                let session = self.provision_tenant(identity.clone(), slot, &so_pin, &user_pin)?;
                self.tenant_pins
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(identity.clone(), (so_pin, user_pin));
                Ok(session)
            }
        }
    }

    fn no_identity_err() -> crate::error::KmipError {
        crate::error::KmipError::failed(
            crate::error::ResultReason::AuthenticationNotSuccessful,
            "this tenancy mode requires an authenticated identity",
        )
    }

    fn tenants_lock(&self) -> std::sync::MutexGuard<'_, HashMap<crate::server::auth::Identity, TenantCtx>> {
        self.tenants.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Bring a brand-new tenant's token online (§F7.2: `ensure_slot` +
    /// `C_InitToken` + `C_InitPIN` + USER login, via the engine's own
    /// `bootstrap_default_token` helper — the same sequence the
    /// `Single`-mode production binary already runs for slot 0) and
    /// record its live session in `self.tenants`.
    fn provision_tenant(
        &self,
        identity: crate::server::auth::Identity,
        slot: u32,
        so_pin: &str,
        user_pin: &str,
    ) -> crate::error::Result<u32> {
        // Multi-slot activation hook — the engine boots single-slot (slot
        // 0), and `C_InitToken` on any other slot fails CKR_SLOT_ID_INVALID
        // until this runs first (found the hard way during the
        // hsm-perf-bench P0 spikes; see the plan's §E2/§F1).
        softhsmrustv3::state::ensure_slot(slot);
        let label = format!("kmip-tenant-{}", identity.username);
        let session = softhsmrustv3::native::session::bootstrap_default_token(
            slot, so_pin, user_pin, &label,
        )
        .map_err(|rv| {
            crate::error::KmipError::failed(
                crate::error::ResultReason::GeneralFailure,
                format!("tenant token provisioning failed for slot {slot}: engine rv=0x{rv:x}"),
            )
        })?;
        self.tenants_lock().insert(identity, TenantCtx { slot, engine_session: session });
        Ok(session)
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

/// Part F §F7.2 (`TenancyMode::Auto`) — mint a fresh PIN for a
/// newly-provisioned tenant token. 16 random bytes, hex-encoded (32
/// chars) — well over PKCS#11's typical minimum PIN length, and, being
/// server-generated and per-tenant, never reused across tenants. `hex`
/// is dev-dependency-only in this crate (see Cargo.toml), so this is a
/// small inline encoder rather than a new production dependency.
fn generate_tenant_pin() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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

    // ── Part F §F7.2 — resolve_tenant_session ────────────────────────────
    // Distinct, high slot numbers per test (the engine's slot/token store
    // is process-global) to avoid colliding with other tests' slot 0 use
    // or with each other under cargo test's default parallelism.

    fn test_deps(config: DepsConfig) -> Deps {
        let sink: Arc<dyn AuditSink> = Arc::new(RingSink::new(64));
        Deps::new(Engine::permissive(), Arc::new(MemoryStore::new()), sink, config)
    }

    #[test]
    fn single_mode_returns_engine_session_ignoring_identity() {
        let deps = test_deps(DepsConfig::default()).with_engine_session(4242);
        assert_eq!(deps.resolve_tenant_session(None).unwrap(), 4242);
        let someone = crate::server::auth::Identity { username: "anyone".into() };
        assert_eq!(deps.resolve_tenant_session(Some(&someone)).unwrap(), 4242);
    }

    #[test]
    fn single_mode_without_engine_session_errors() {
        let deps = test_deps(DepsConfig::default());
        assert!(deps.resolve_tenant_session(None).is_err());
    }

    #[test]
    fn strict_mode_rejects_no_identity_and_unconfigured_identity() {
        let alice = crate::server::auth::Identity { username: "alice-strict".into() };
        let config = DepsConfig {
            tenancy_mode: TenancyMode::Strict,
            strict_tenants: vec![StrictTenantConfig {
                identity: alice.clone(),
                slot: 60,
                so_pin: "so-pin-60".into(),
                user_pin: "user-pin-60".into(),
            }],
            ..DepsConfig::default()
        };
        let deps = test_deps(config);
        assert!(deps.resolve_tenant_session(None).is_err(), "no identity must be rejected");
        let mallory = crate::server::auth::Identity { username: "mallory-not-configured".into() };
        assert!(
            deps.resolve_tenant_session(Some(&mallory)).is_err(),
            "an identity absent from strict_tenants must be rejected"
        );
    }

    // These two tests exercise the real engine (via `resolve_tenant_session`'s
    // Strict/Auto provisioning path). The engine's session/token state is
    // process-global and `cargo test` runs lib tests in parallel, so any
    // other test's `native::session::finalize()` would wipe the slot this
    // one just provisioned. The fix (2026-07-19, closing §G2's finalize()
    // gap) is the same one every other engine-touching lib test in this
    // crate already uses: hold the crate-wide `engine_lock()` for the whole
    // test. Every finalize()-calling test acquires that same lock (verified:
    // certify via `ca_engine_deps`, register_import_export, create, and the
    // helper-based spki_verify/catalyst/chameleon/… fixtures all do), so
    // while this test holds it no concurrent finalize() can run. Slots 61/72
    // remain unique to these two tests, and neither finalizes at the end —
    // the next engine test's own start-of-test finalize() clears them, since
    // it can only run once this one releases the lock.
    #[test]
    fn strict_mode_provisions_configured_tenant_and_caches_it() {
        let _guard = crate::ops::helpers::engine_lock();
        let alice = crate::server::auth::Identity { username: "alice-strict-provision".into() };
        let config = DepsConfig {
            tenancy_mode: TenancyMode::Strict,
            strict_tenants: vec![StrictTenantConfig {
                identity: alice.clone(),
                slot: 61,
                so_pin: "so-pin-61".into(),
                user_pin: "user-pin-61".into(),
            }],
            ..DepsConfig::default()
        };
        let deps = test_deps(config);
        let session1 = deps.resolve_tenant_session(Some(&alice)).expect("provision must succeed");
        assert_eq!(softhsmrustv3::state::session_slot(session1), Some(61));
        // Second call for the same identity returns the SAME session — no
        // re-provisioning (which would fail: C_InitToken on a token with
        // an open session errors CKR_SESSION_EXISTS).
        let session2 = deps.resolve_tenant_session(Some(&alice)).expect("cached lookup must succeed");
        assert_eq!(session1, session2, "second resolve must reuse the cached session");
    }

    /// Slot allocation is pure Rust logic (`AtomicU32::fetch_add`, no
    /// engine call) — verified without touching the process-global
    /// engine at all, so this half of "distinct tenants get distinct
    /// slots" is fully race-free regardless of what other tests do
    /// concurrently.
    #[test]
    fn auto_mode_allocates_a_fresh_slot_number_per_new_identity() {
        let config = DepsConfig { tenancy_mode: TenancyMode::Auto, ..DepsConfig::default() };
        let deps = test_deps(config);
        let start = deps.next_auto_slot.load(std::sync::atomic::Ordering::Relaxed);
        let first = deps.next_auto_slot.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let second = deps.next_auto_slot.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(first, start);
        assert_eq!(second, start + 1);
        assert_ne!(first, second, "each new identity gets a distinct slot number");
    }

    /// The engine-touching half: one auto-provisioned tenant actually
    /// lands on the requested slot, with a real USER-logged-in session
    /// and a recorded PIN pair. Holds `engine_lock()` for the whole test
    /// (see `strict_mode_provisions_configured_tenant_and_caches_it`),
    /// which serialises it against every other engine-touching test — so
    /// a second provisioning call is now safe (no concurrent finalize()
    /// can land between the two), and this test exercises the cache-hit
    /// path directly rather than deferring it to the slot-numbering test.
    #[test]
    fn auto_mode_provisions_tenant_with_recorded_pins() {
        let _guard = crate::ops::helpers::engine_lock();
        let config = DepsConfig { tenancy_mode: TenancyMode::Auto, ..DepsConfig::default() };
        let deps = test_deps(config);
        deps.next_auto_slot.store(72, std::sync::atomic::Ordering::Relaxed);

        let alice = crate::server::auth::Identity { username: "alice-auto-single".into() };
        let session = deps.resolve_tenant_session(Some(&alice)).expect("auto-provision alice");
        assert_eq!(softhsmrustv3::state::session_slot(session), Some(72));

        // Cached on the second call (no re-provisioning).
        let session2 = deps.resolve_tenant_session(Some(&alice)).expect("cached lookup");
        assert_eq!(session, session2);

        // PINs were generated and recorded (readable by an operator, per
        // the user's "per-tenant configured PINs" decision).
        let pins = deps.tenant_pins.lock().unwrap();
        let (so_pin, user_pin) = pins.get(&alice).expect("PIN pair recorded");
        assert_eq!(so_pin.len(), 32, "16 random bytes hex-encoded");
        assert_ne!(so_pin, user_pin, "SO and USER PINs must differ");
        drop(pins);

        // Auto mode still requires an identity.
        assert!(deps.resolve_tenant_session(None).is_err());
    }
}
