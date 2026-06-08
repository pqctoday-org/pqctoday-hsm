//! Plane 1 — Crypto Agility Management Plane.
//!
//! The policy engine that sits between the application and KMIP. **Every**
//! KMIP request passes through [`Engine::evaluate`] before reaching the
//! Plane 2 dispatcher. The engine is what makes the agility story work:
//!
//! ```text
//!   application
//!       │
//!       ▼
//!   Plane 1 — agility engine (this module)
//!       │
//!       ▼
//!   Plane 2 — KMIP 3.0 dispatcher + op handlers
//!       │
//!       ▼
//!   Plane 3 — PKCS#11 bridge → softhsmrustv3
//! ```
//!
//! ## What the engine adds over plain KMIP 3.0
//!
//! KMIP 3.0 is a wire protocol — it carries algorithms but does not impose
//! crypto-agility policy on them. In particular, **KMIP 3.0 alone has no
//! mechanism for silently switching an application from classical to PQC**:
//! the closest spec primitive is `ReKey`, which still requires the caller
//! to know what algorithm they want.
//!
//! The Plane-1 engine fills that gap with three capabilities:
//!
//! 1. **Algorithm substitution** ([`Rule::AlgorithmSubstitution`]).
//!    Rewrites the incoming algorithm at the boundary. An application that
//!    asks for ECDSA-P256 gets ML-DSA-65 — no code change.
//!
//! 2. **Algorithm defaulting** ([`Rule::AlgorithmDefault`]). When the
//!    application sends `CreateKeyPair` with no algorithm specified, the
//!    engine supplies one from the active policy. Flipping the policy
//!    flips the default — the application sees only handles.
//!
//! 3. **Rekey orchestration** ([`Decision::RekeyAndProceed`]). When
//!    substitution fires against an *existing* stored key (not at create
//!    time), the engine emits a rekey plan instead of plain Allow. The
//!    Phase-5 dispatcher executes the rekey transaction: generate fresh
//!    PQC key, mark classical key `Deprecated`, link new ↔ old via
//!    `x-pqctoday-supersedes`, re-issue the original op.
//!
//! Together, these three primitives let the demo flip an application from
//! classical KEM/signature/encryption to PQC by editing one YAML file.
//!
//! ## KMIP 3.0 compatibility
//!
//! - Operation names ([`PolicyRequest::op`]) are the canonical KMIP 3.0
//!   op names. The dispatcher is responsible for canonicalisation (e.g.
//!   resolving the `Encrypt`/`Encapsulate` overload for ML-KEM).
//! - Algorithm strings are the canonical names from KMIP 3.0 §10.2.6
//!   `CryptographicAlgorithm`, with size suffixes for parameterised
//!   variants (`AES-256` rather than just `AES`).
//! - [`DenyReason`] variants map 1:1 to KMIP 3.0 §9.2 `ResultReason` codes.
//! - [`Decision::Allow`] / [`Decision::Deny`] are wire-compatible with
//!   `OperationResult` / `OperationFailed`. [`Decision::RekeyAndProceed`]
//!   is an internal-only signal — never crosses the KMIP wire.
//!
//! ## Hub UI integration
//!
//! [`PolicyStore`] exposes the operations the scenario UI needs:
//! `list`, `load`, `validate_draft`, `save`, `dry_run`. The store is a
//! pure-Rust library — the Hub-facing layer (HTTP API or WASM facade)
//! is a future workstream that wraps these calls.
//!
//! ## Security-officer editability
//!
//! Policies are YAML files in a configured directory. Security officers
//! edit them with any tool (text editor, Hub UI, `pqctoday-kmip-compliance
//! edit`). [`PolicyStore::save`] validates-then-renames so a broken edit
//! never leaves the directory in a half-applied state. [`Engine::activate`]
//! does an atomic swap — in-flight evaluations observe either the old or
//! the new policy, never a Frankenstein. Every activation is recorded in
//! [`PolicyAudit`] with the SHA-256 fingerprint of both prior and new YAML.

pub mod audit;
pub mod decision;
pub mod engine;
pub mod loader;
pub mod policy;
pub mod request;
pub mod rule;
pub mod store;

pub use audit::PolicyAudit;
pub use decision::{Decision, DenyReason};
pub use engine::{ActivePolicy, Engine};
pub use loader::{load_from_file, load_from_str, validate, LoadedPolicy, LoaderError};
pub use policy::{ComplianceMapping, Metadata, Policy};
pub use request::PolicyRequest;
pub use rule::{AttrPredicate, GatingDeny, Rule, Substitution, TimeBound};
pub use store::{PolicyStore, StoreError};
