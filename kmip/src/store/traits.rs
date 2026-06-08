//! [`KeyStore`] — minimal surface needed by Phase 5 op handlers.
//!
//! Phase 6 will implement the SQLite-backed concrete store with full
//! lifecycle FSM enforcement (per `docs/IMPLEMENTATION_PLAN.md` §3.4).
//! This trait defines just the operations the ops need to compile + test
//! against; the in-memory implementation in [`super::MemoryStore`]
//! satisfies it for Phase 5 unit tests.

use crate::error::Result;
use crate::kmip30::{KmipAlgorithm, ObjectType, State, UsageMask};
use time::OffsetDateTime;

/// KMIP `Unique Identifier` — KMIP 3.0 §4.x. We use a `urn:pqctoday:obj:<uuid>`
/// shape; the dispatcher allocates one per Create / CreateKeyPair.
pub type Uid = String;

/// One managed object as the store sees it. Key material itself stays in
/// `softhsmrustv3`; the store keeps the KMIP-level metadata + the stable
/// PKCS#11 `CKA_ID` we use to find the object back inside the token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectRecord {
    pub uid: Uid,
    pub object_type: ObjectType,
    pub algorithm: KmipAlgorithm,
    pub cryptographic_length: u32,
    pub usage_mask: UsageMask,
    pub state: State,
    /// PKCS#11 `CKA_ID` (bytes). The bridge uses this with `C_FindObjects`
    /// to recover the session-scoped `CK_OBJECT_HANDLE` for the object.
    pub pkcs11_cka_id: Vec<u8>,
    /// Slot the object lives in. v0.1 is single-slot but the field is
    /// here so Phase 6 can grow into multi-slot without an API change.
    pub pkcs11_slot: u32,
    /// KMIP `Initial Date` (§4.x).
    pub initial_date: OffsetDateTime,
    /// KMIP `Activation Date` (§4.x) — set on `Activate`.
    pub activation_date: Option<OffsetDateTime>,
    /// Linked predecessor when this object was created by a Plane-1
    /// `RekeyAndProceed`. KMIP `Link` attribute (§4.x); the dispatcher
    /// also surfaces this via the `x-pqctoday-supersedes` custom attr.
    pub supersedes: Option<Uid>,
}

/// Minimum surface the Phase-5 op handlers call.
pub trait KeyStore: Send + Sync {
    /// Insert a freshly-created object. Errors on duplicate UID.
    fn put(&self, record: ObjectRecord) -> Result<()>;

    /// Look up by UID. `Ok(None)` for "not present".
    fn get(&self, uid: &str) -> Result<Option<ObjectRecord>>;

    /// Replace an object (lifecycle transition, supersedes link, etc.).
    /// Errors if the UID is unknown.
    fn update(&self, record: ObjectRecord) -> Result<()>;

    /// Delete by UID. Idempotent — succeeds even if the UID was absent.
    fn remove(&self, uid: &str) -> Result<()>;

    /// List all objects matching `predicate` (KMIP `Locate` op).
    fn find(&self, predicate: &dyn Fn(&ObjectRecord) -> bool) -> Result<Vec<ObjectRecord>>;
}
