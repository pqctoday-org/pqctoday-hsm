//! [`SqliteStore`] — Phase-6 durable [`KeyStore`] backend.
//!
//! `rusqlite` + `rusqlite_migration` against the schema documented in
//! `docs/IMPLEMENTATION_PLAN.md` §3.3. Drop-in swap for
//! [`super::MemoryStore`]: same trait, same field shape, so every Phase-5
//! op handler keeps working unchanged.
//!
//! ## Schema (v1)
//!
//! ```sql
//! CREATE TABLE objects (
//!     uid                  TEXT PRIMARY KEY,
//!     pkcs11_cka_id        BLOB NOT NULL,
//!     pkcs11_slot          INTEGER NOT NULL,
//!     object_type          TEXT NOT NULL,
//!     algorithm            TEXT NOT NULL,
//!     cryptographic_length INTEGER NOT NULL,
//!     state                TEXT NOT NULL,
//!     usage_mask           INTEGER NOT NULL,
//!     supersedes           TEXT REFERENCES objects(uid),
//!     created_at           TEXT NOT NULL,
//!     activated_at         TEXT
//! );
//! CREATE INDEX idx_objects_state     ON objects(state);
//! CREATE INDEX idx_objects_algorithm ON objects(algorithm);
//! ```
//!
//! Additional tables from §3.3 (object_attributes, object_tags,
//! audit_log) are not in v1 — the Phase-5 [`KeyStore`] trait surface
//! doesn't need them yet. They land when Phase 8 (compliance) +
//! Phase 9 (audit CLI) require them.
//!
//! ## Lifecycle enforcement
//!
//! Every [`Self::update`] that changes `state` runs through
//! [`super::lifecycle::enforce_transition`] — defense-in-depth on top of
//! the handler-level FSM checks in Phase 5.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, Row};
use rusqlite_migration::{Migrations, M};
use time::OffsetDateTime;

use super::lifecycle::enforce_transition;
use super::traits::{KeyStore, ObjectRecord};
use crate::error::{KmipError, Result, ResultReason};
use crate::kmip30::{KmipAlgorithm, ObjectType, State, UsageMask};

/// Disk-backed object store. `Send + Sync` via interior `Mutex<Connection>`.
pub struct SqliteStore {
    conn: Mutex<Connection>,
}

impl SqliteStore {
    /// Open or create the database at `path`. Applies pending migrations.
    /// `path` may be `:memory:` for tests.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let mut conn = Connection::open(path).map_err(map_sqlite_err)?;
        Self::migrate(&mut conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// In-memory store — for unit tests and the v0.1 sandbox case where
    /// durability isn't required. Same code path as `open(":memory:")`.
    pub fn in_memory() -> Result<Self> {
        Self::open(":memory:")
    }

    fn migrate(conn: &mut Connection) -> Result<()> {
        let migrations = Migrations::new(vec![M::up(SCHEMA_V1)]);
        migrations
            .to_latest(conn)
            .map_err(|e| KmipError::internal(format!("schema migration failed: {e}")))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().expect("SqliteStore connection mutex poisoned")
    }
}

const SCHEMA_V1: &str = r#"
CREATE TABLE objects (
    uid                  TEXT PRIMARY KEY,
    pkcs11_cka_id        BLOB NOT NULL,
    pkcs11_slot          INTEGER NOT NULL,
    object_type          TEXT NOT NULL,
    algorithm            TEXT NOT NULL,
    cryptographic_length INTEGER NOT NULL,
    state                TEXT NOT NULL,
    usage_mask           INTEGER NOT NULL,
    supersedes           TEXT REFERENCES objects(uid),
    created_at           TEXT NOT NULL,
    activated_at         TEXT
);
CREATE INDEX idx_objects_state     ON objects(state);
CREATE INDEX idx_objects_algorithm ON objects(algorithm);
"#;

impl KeyStore for SqliteStore {
    fn put(&self, record: ObjectRecord) -> Result<()> {
        let conn = self.lock();
        let result = conn.execute(
            "INSERT INTO objects (uid, pkcs11_cka_id, pkcs11_slot, object_type, algorithm,
                 cryptographic_length, state, usage_mask, supersedes, created_at, activated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                record.uid,
                record.pkcs11_cka_id,
                record.pkcs11_slot,
                object_type_str(record.object_type),
                algorithm_str(record.algorithm),
                record.cryptographic_length,
                state_str(record.state),
                record.usage_mask.bits(),
                record.supersedes,
                fmt_ts(record.initial_date),
                record.activation_date.map(fmt_ts),
            ],
        );
        match result {
            Ok(_) => Ok(()),
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Err(KmipError::failed(
                    ResultReason::ObjectAlreadyExists,
                    format!("UID {:?} already exists", record.uid),
                ))
            }
            Err(e) => Err(map_sqlite_err(e)),
        }
    }

    fn get(&self, uid: &str) -> Result<Option<ObjectRecord>> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare(
                "SELECT uid, pkcs11_cka_id, pkcs11_slot, object_type, algorithm,
                        cryptographic_length, state, usage_mask, supersedes,
                        created_at, activated_at
                   FROM objects WHERE uid = ?1",
            )
            .map_err(map_sqlite_err)?;
        let row = stmt.query_row(params![uid], row_to_record);
        match row {
            Ok(r) => Ok(Some(r?)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(map_sqlite_err(e)),
        }
    }

    fn update(&self, record: ObjectRecord) -> Result<()> {
        let conn = self.lock();
        // Defence-in-depth: enforce the FSM at the store layer.
        let current: Option<String> = conn
            .query_row(
                "SELECT state FROM objects WHERE uid = ?1",
                params![record.uid],
                |r| r.get(0),
            )
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(map_sqlite_err(other)),
            })?;
        let current_state =
            current.ok_or_else(|| KmipError::not_found(&record.uid))?;
        let from = state_from_str(&current_state)
            .ok_or_else(|| KmipError::internal(format!("unknown stored state {current_state:?}")))?;
        enforce_transition(from, record.state)?;

        let n = conn
            .execute(
                "UPDATE objects SET
                     pkcs11_cka_id = ?2,
                     pkcs11_slot = ?3,
                     object_type = ?4,
                     algorithm = ?5,
                     cryptographic_length = ?6,
                     state = ?7,
                     usage_mask = ?8,
                     supersedes = ?9,
                     activated_at = ?10
                 WHERE uid = ?1",
                params![
                    record.uid,
                    record.pkcs11_cka_id,
                    record.pkcs11_slot,
                    object_type_str(record.object_type),
                    algorithm_str(record.algorithm),
                    record.cryptographic_length,
                    state_str(record.state),
                    record.usage_mask.bits(),
                    record.supersedes,
                    record.activation_date.map(fmt_ts),
                ],
            )
            .map_err(map_sqlite_err)?;
        if n == 0 {
            return Err(KmipError::not_found(&record.uid));
        }
        Ok(())
    }

    fn remove(&self, uid: &str) -> Result<()> {
        let conn = self.lock();
        conn.execute("DELETE FROM objects WHERE uid = ?1", params![uid])
            .map_err(map_sqlite_err)?;
        Ok(())
    }

    fn find(&self, predicate: &dyn Fn(&ObjectRecord) -> bool) -> Result<Vec<ObjectRecord>> {
        // For v1, scan all rows and filter in Rust. The trait surface
        // passes an opaque `Fn` we can't translate to SQL; the
        // bigger-than-MVP path is a typed predicate. Phase 8 (compliance)
        // can introduce that without breaking the trait.
        let conn = self.lock();
        let mut stmt = conn
            .prepare(
                "SELECT uid, pkcs11_cka_id, pkcs11_slot, object_type, algorithm,
                        cryptographic_length, state, usage_mask, supersedes,
                        created_at, activated_at FROM objects",
            )
            .map_err(map_sqlite_err)?;
        let rows = stmt
            .query_map([], row_to_record)
            .map_err(map_sqlite_err)?;
        let mut out = Vec::new();
        for row in rows {
            let record: ObjectRecord = row.map_err(map_sqlite_err)??;
            if predicate(&record) {
                out.push(record);
            }
        }
        Ok(out)
    }
}

// ── helpers ────────────────────────────────────────────────────────────────

fn map_sqlite_err(e: rusqlite::Error) -> KmipError {
    KmipError::internal(format!("sqlite: {e}"))
}

fn fmt_ts(t: OffsetDateTime) -> String {
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| String::from("1970-01-01T00:00:00Z"))
}

fn parse_ts(s: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()
}

fn row_to_record(row: &Row) -> rusqlite::Result<Result<ObjectRecord>> {
    let uid: String = row.get(0)?;
    let pkcs11_cka_id: Vec<u8> = row.get(1)?;
    let pkcs11_slot: u32 = row.get::<_, i64>(2)? as u32;
    let object_type_s: String = row.get(3)?;
    let algorithm_s: String = row.get(4)?;
    let cryptographic_length: u32 = row.get::<_, i64>(5)? as u32;
    let state_s: String = row.get(6)?;
    let usage_mask_bits: u32 = row.get::<_, i64>(7)? as u32;
    let supersedes: Option<String> = row.get(8)?;
    let created_s: String = row.get(9)?;
    let activated_s: Option<String> = row.get(10)?;

    Ok(decode_record(
        uid,
        pkcs11_cka_id,
        pkcs11_slot,
        &object_type_s,
        &algorithm_s,
        cryptographic_length,
        &state_s,
        usage_mask_bits,
        supersedes,
        &created_s,
        activated_s.as_deref(),
    ))
}

#[allow(clippy::too_many_arguments)]
fn decode_record(
    uid: String,
    pkcs11_cka_id: Vec<u8>,
    pkcs11_slot: u32,
    object_type_s: &str,
    algorithm_s: &str,
    cryptographic_length: u32,
    state_s: &str,
    usage_mask_bits: u32,
    supersedes: Option<String>,
    created_s: &str,
    activated_s: Option<&str>,
) -> Result<ObjectRecord> {
    let object_type = object_type_from_str(object_type_s)
        .ok_or_else(|| KmipError::internal(format!("unknown object_type {object_type_s:?}")))?;
    let algorithm = algorithm_from_str(algorithm_s)
        .ok_or_else(|| KmipError::internal(format!("unknown algorithm {algorithm_s:?}")))?;
    let state = state_from_str(state_s)
        .ok_or_else(|| KmipError::internal(format!("unknown state {state_s:?}")))?;
    let usage_mask = UsageMask::from_bits_truncate(usage_mask_bits);
    let initial_date = parse_ts(created_s)
        .ok_or_else(|| KmipError::internal(format!("malformed created_at {created_s:?}")))?;
    let activation_date = activated_s.and_then(parse_ts);
    Ok(ObjectRecord {
        uid,
        object_type,
        algorithm,
        cryptographic_length,
        usage_mask,
        state,
        pkcs11_cka_id,
        pkcs11_slot,
        initial_date,
        activation_date,
        supersedes,
        // KMIP 3.0 §4 `Name` attribute persistence lands in the
        // attribute-mutation wave (PR #82); for now SQLite doesn't
        // carry a Name column, so we always reconstruct as None.
        name: None,

        links: std::collections::HashMap::new(),

        custom_attributes: std::collections::HashMap::new(),


        key_material: None,


        key_format_type: None,
    ..ObjectRecord::default()
})
}

fn object_type_str(t: ObjectType) -> &'static str {
    match t {
        ObjectType::Certificate        => "Certificate",
        ObjectType::SymmetricKey       => "SymmetricKey",
        ObjectType::PublicKey          => "PublicKey",
        ObjectType::PrivateKey         => "PrivateKey",
        ObjectType::SplitKey           => "SplitKey",
        ObjectType::SecretData         => "SecretData",
        ObjectType::OpaqueObject       => "OpaqueObject",
        ObjectType::PgpKey             => "PgpKey",
        ObjectType::CertificateRequest => "CertificateRequest",
        ObjectType::User                      => "User",
        ObjectType::Group                     => "Group",
        ObjectType::PasswordCredential        => "PasswordCredential",
        ObjectType::DeviceCredential          => "DeviceCredential",
        ObjectType::OneTimePasswordCredential => "OneTimePasswordCredential",
        ObjectType::HashedPasswordCredential  => "HashedPasswordCredential",
    }
}

fn object_type_from_str(s: &str) -> Option<ObjectType> {
    match s {
        "Certificate" => Some(ObjectType::Certificate),
        "SymmetricKey" => Some(ObjectType::SymmetricKey),
        "PublicKey" => Some(ObjectType::PublicKey),
        "SplitKey" => Some(ObjectType::SplitKey),
        "OpaqueObject" => Some(ObjectType::OpaqueObject),
        "PgpKey" => Some(ObjectType::PgpKey),
        "CertificateRequest" => Some(ObjectType::CertificateRequest),
        "PrivateKey" => Some(ObjectType::PrivateKey),
        "SecretData" => Some(ObjectType::SecretData),
        _ => None,
    }
}

fn state_str(s: State) -> &'static str {
    match s {
        State::PreActive => "PreActive",
        State::Active => "Active",
        State::Deactivated => "Deactivated",
        State::Compromised => "Compromised",
        State::Destroyed => "Destroyed",
        State::DestroyedCompromised => "DestroyedCompromised",
    }
}

fn state_from_str(s: &str) -> Option<State> {
    match s {
        "PreActive" => Some(State::PreActive),
        "Active" => Some(State::Active),
        "Deactivated" => Some(State::Deactivated),
        "Compromised" => Some(State::Compromised),
        "Destroyed" => Some(State::Destroyed),
        "DestroyedCompromised" => Some(State::DestroyedCompromised),
        _ => None,
    }
}

/// Store the KmipAlgorithm by its OASIS wire codepoint as a hex string so
/// the persistence layer doesn't break when a new variant is added in
/// `kmip30::algos`. Round-trips via `from_wire_value`.
fn algorithm_str(a: KmipAlgorithm) -> String {
    format!("{:#010x}", a.to_wire_value())
}

fn algorithm_from_str(s: &str) -> Option<KmipAlgorithm> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    u32::from_str_radix(trimmed, 16).ok().and_then(KmipAlgorithm::from_wire_value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kmip30::{KmipAlgorithm, ObjectType, UsageMask};

    fn rec(uid: &str, state: State) -> ObjectRecord {
        ObjectRecord {
            uid: uid.into(),
            object_type: ObjectType::PrivateKey,
            algorithm: KmipAlgorithm::MlDsa87,
            cryptographic_length: 0,
            usage_mask: UsageMask::SIGN | UsageMask::VERIFY,
            state,
            pkcs11_cka_id: vec![1, 2, 3, 4],
            pkcs11_slot: 0,
            initial_date: OffsetDateTime::UNIX_EPOCH,
            activation_date: None,
            supersedes: None,
            name: None,

            links: std::collections::HashMap::new(),

            custom_attributes: std::collections::HashMap::new(),


            key_material: None,


            key_format_type: None,
        ..ObjectRecord::default()
}
    }

    #[test]
    fn schema_migrates_to_v1_on_open() {
        let _store = SqliteStore::in_memory().unwrap();
        // Open succeeds → migration ran. Subsequent ops will fail if the
        // schema is wrong; covered by the round-trip tests below.
    }

    #[test]
    fn put_then_get_round_trip() {
        let store = SqliteStore::in_memory().unwrap();
        store.put(rec("u1", State::PreActive)).unwrap();
        let r = store.get("u1").unwrap().unwrap();
        assert_eq!(r.uid, "u1");
        assert_eq!(r.algorithm, KmipAlgorithm::MlDsa87);
        assert_eq!(r.state, State::PreActive);
        assert_eq!(r.pkcs11_cka_id, vec![1, 2, 3, 4]);
        assert!(store.get("missing").unwrap().is_none());
    }

    #[test]
    fn put_duplicate_returns_already_exists() {
        let store = SqliteStore::in_memory().unwrap();
        store.put(rec("u1", State::PreActive)).unwrap();
        let err = store.put(rec("u1", State::PreActive)).unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::ObjectAlreadyExists);
    }

    #[test]
    fn update_requires_existing_record() {
        let store = SqliteStore::in_memory().unwrap();
        let err = store.update(rec("ghost", State::Active)).unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::ItemNotFound);
    }

    #[test]
    fn update_with_legal_transition_succeeds() {
        let store = SqliteStore::in_memory().unwrap();
        store.put(rec("u", State::PreActive)).unwrap();
        let mut updated = rec("u", State::Active);
        updated.activation_date = Some(OffsetDateTime::UNIX_EPOCH);
        store.update(updated).unwrap();
        let r = store.get("u").unwrap().unwrap();
        assert_eq!(r.state, State::Active);
        assert!(r.activation_date.is_some());
    }

    #[test]
    fn update_with_illegal_transition_denied() {
        let store = SqliteStore::in_memory().unwrap();
        store.put(rec("u", State::Active)).unwrap();
        // Active → PreActive not in FSM table; store rejects.
        let err = store.update(rec("u", State::PreActive)).unwrap_err();
        assert_eq!(err.result_reason(), ResultReason::PermissionDenied);
    }

    #[test]
    fn remove_then_get_returns_none() {
        let store = SqliteStore::in_memory().unwrap();
        store.put(rec("u", State::PreActive)).unwrap();
        store.remove("u").unwrap();
        assert!(store.get("u").unwrap().is_none());
        // Idempotent: remove of missing UID still Ok.
        store.remove("missing").unwrap();
    }

    #[test]
    fn find_filters_by_predicate() {
        let store = SqliteStore::in_memory().unwrap();
        store.put(rec("a", State::Active)).unwrap();
        store.put(rec("b", State::PreActive)).unwrap();
        let active = store.find(&|r| r.state == State::Active).unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].uid, "a");
    }

    #[test]
    fn algorithm_round_trips_through_wire_codepoint_string() {
        let store = SqliteStore::in_memory().unwrap();
        let mut r = rec("u", State::PreActive);
        r.algorithm = KmipAlgorithm::MlKem1024;
        store.put(r).unwrap();
        let got = store.get("u").unwrap().unwrap();
        assert_eq!(got.algorithm, KmipAlgorithm::MlKem1024);
    }

    #[test]
    fn usage_mask_bits_round_trip() {
        let store = SqliteStore::in_memory().unwrap();
        let mut r = rec("u", State::PreActive);
        r.usage_mask = UsageMask::ENCRYPT | UsageMask::DECRYPT | UsageMask::WRAP_KEY;
        store.put(r).unwrap();
        let got = store.get("u").unwrap().unwrap();
        assert!(got.usage_mask.contains(UsageMask::ENCRYPT));
        assert!(got.usage_mask.contains(UsageMask::DECRYPT));
        assert!(got.usage_mask.contains(UsageMask::WRAP_KEY));
        assert!(!got.usage_mask.contains(UsageMask::SIGN));
    }
}
