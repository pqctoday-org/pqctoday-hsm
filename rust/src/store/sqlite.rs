//! Native SQLite backend for [`super::TokenStore`] — one `.db` file per
//! slot (operational parity with the C++ engine's per-token database
//! granularity: a token can be backed up, moved, or deleted individually).
//!
//! PRAGMA choices mirror the KMIP crate's own `SqliteStore`
//! (`kmip/src/store/sqlite.rs`) — that file is not reusable code (its
//! `ObjectRecord` is KMIP-shaped, not PKCS#11-shaped), but its schema/
//! migration *pattern* is: `journal_mode=WAL`, `synchronous=NORMAL`,
//! `busy_timeout=5000`, `foreign_keys=ON`, `secure_delete=FAST` (the last
//! specifically so a destroyed private key's ciphertext isn't recoverable
//! from a freed SQLite page).
//!
//! Every attribute value on a private object (`object.private = 1`) is
//! already AES-256-GCM ciphertext by the time it reaches [`put_object`] —
//! this module only ever moves bytes, it makes no encryption decisions
//! itself (see `super::persist_object`).

use super::{PersistedToken, TokenStore};
use crate::crypto::handlers::Attributes;
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::Ordering;

pub struct SqliteStore {
    dir: PathBuf,
    conns: Mutex<HashMap<u32, Connection>>,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS token (
    slot                    INTEGER PRIMARY KEY,
    initialized             INTEGER NOT NULL,
    label                   BLOB NOT NULL,
    so_pin_salt             BLOB NOT NULL,
    so_pin_hash             BLOB NOT NULL,
    user_pin_salt           BLOB,
    user_pin_hash           BLOB,
    master_key_so_wrapped   BLOB,
    master_key_user_wrapped BLOB,
    next_handle             INTEGER NOT NULL DEFAULT 100,
    unique_id_counter       INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS object (
    handle  INTEGER PRIMARY KEY,
    private INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS attribute (
    handle INTEGER NOT NULL REFERENCES object(handle) ON DELETE CASCADE,
    type   INTEGER NOT NULL,
    value  BLOB NOT NULL,
    PRIMARY KEY (handle, type)
);
";

impl SqliteStore {
    /// `dir` is created if missing. Connections are opened lazily, one per
    /// slot, on first use — matching `state::ensure_slot`'s lazy-activation
    /// model rather than requiring every slot up front.
    pub fn open(dir: impl Into<PathBuf>) -> std::io::Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir, conns: Mutex::new(HashMap::new()) })
    }

    fn with_conn<R>(&self, slot: u32, f: impl FnOnce(&mut Connection) -> rusqlite::Result<R>) -> Option<R> {
        let mut conns = self.conns.lock().unwrap_or_else(|e| e.into_inner());
        let conn = match conns.entry(slot) {
            std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::hash_map::Entry::Vacant(e) => {
                let path = self.dir.join(format!("token-{slot}.db"));
                let conn = Connection::open(&path).ok()?;
                conn.execute_batch(
                    "PRAGMA journal_mode = WAL;
                     PRAGMA synchronous = NORMAL;
                     PRAGMA busy_timeout = 5000;
                     PRAGMA foreign_keys = ON;
                     PRAGMA secure_delete = FAST;",
                )
                .ok()?;
                conn.execute_batch(SCHEMA).ok()?;
                e.insert(conn)
            }
        };
        f(conn).ok()
    }
}

impl TokenStore for SqliteStore {
    fn is_persistent(&self) -> bool {
        true
    }

    fn put_token(&self, slot: u32, token: &PersistedToken) {
        self.with_conn(slot, |conn| {
            conn.execute(
                "INSERT INTO token (slot, initialized, label, so_pin_salt, so_pin_hash,
                                     user_pin_salt, user_pin_hash,
                                     master_key_so_wrapped, master_key_user_wrapped,
                                     next_handle, unique_id_counter)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                 ON CONFLICT(slot) DO UPDATE SET
                    initialized = excluded.initialized,
                    label = excluded.label,
                    so_pin_salt = excluded.so_pin_salt,
                    so_pin_hash = excluded.so_pin_hash,
                    user_pin_salt = excluded.user_pin_salt,
                    user_pin_hash = excluded.user_pin_hash,
                    master_key_so_wrapped = excluded.master_key_so_wrapped,
                    master_key_user_wrapped = excluded.master_key_user_wrapped,
                    next_handle = excluded.next_handle,
                    unique_id_counter = excluded.unique_id_counter",
                params![
                    slot,
                    token.initialized,
                    token.label.to_vec(),
                    token.so_pin_salt.to_vec(),
                    token.so_pin_hash.to_vec(),
                    token.user_pin_salt.map(|s| s.to_vec()),
                    token.user_pin_hash.map(|h| h.to_vec()),
                    token.master_key_so_wrapped,
                    token.master_key_user_wrapped,
                    crate::state::NEXT_HANDLE.load(Ordering::Relaxed),
                    crate::state::UNIQUE_ID_COUNTER.load(Ordering::Relaxed) as i64,
                ],
            )?;
            Ok(())
        });
    }

    fn get_token(&self, slot: u32) -> Option<PersistedToken> {
        self.with_conn(slot, |conn| {
            conn.query_row(
                "SELECT initialized, label, so_pin_salt, so_pin_hash,
                        user_pin_salt, user_pin_hash,
                        master_key_so_wrapped, master_key_user_wrapped,
                        next_handle, unique_id_counter
                 FROM token WHERE slot = ?1",
                params![slot],
                |row| {
                    let label: Vec<u8> = row.get(1)?;
                    let so_salt: Vec<u8> = row.get(2)?;
                    let so_hash: Vec<u8> = row.get(3)?;
                    let user_salt: Option<Vec<u8>> = row.get(4)?;
                    let user_hash: Option<Vec<u8>> = row.get(5)?;
                    Ok(PersistedToken {
                        initialized: row.get(0)?,
                        label: label.try_into().unwrap_or([0x20; 32]),
                        so_pin_salt: so_salt.try_into().unwrap_or([0u8; 16]),
                        so_pin_hash: so_hash.try_into().unwrap_or([0u8; 32]),
                        user_pin_salt: user_salt.and_then(|v| v.try_into().ok()),
                        user_pin_hash: user_hash.and_then(|v| v.try_into().ok()),
                        master_key_so_wrapped: row.get(6)?,
                        master_key_user_wrapped: row.get(7)?,
                        next_handle: row.get(8)?,
                        unique_id_counter: row.get::<_, i64>(9)? as u64,
                    })
                },
            )
            .optional()
        })
        .flatten()
    }

    fn put_object(&self, slot: u32, handle: u32, private: bool, attrs: &Attributes) {
        self.with_conn(slot, |conn| {
            let tx = conn.transaction()?;
            tx.execute(
                "INSERT INTO object (handle, private) VALUES (?1, ?2)
                 ON CONFLICT(handle) DO UPDATE SET private = excluded.private",
                params![handle, private],
            )?;
            tx.execute("DELETE FROM attribute WHERE handle = ?1", params![handle])?;
            {
                let mut stmt = tx.prepare(
                    "INSERT INTO attribute (handle, type, value) VALUES (?1, ?2, ?3)",
                )?;
                for (ty, val) in attrs {
                    stmt.execute(params![handle, ty, val])?;
                }
            }
            tx.execute(
                "UPDATE token SET next_handle = ?2, unique_id_counter = ?3 WHERE slot = ?1",
                params![
                    slot,
                    crate::state::NEXT_HANDLE.load(Ordering::Relaxed),
                    crate::state::UNIQUE_ID_COUNTER.load(Ordering::Relaxed) as i64,
                ],
            )?;
            tx.commit()
        });
    }

    fn delete_object(&self, slot: u32, handle: u32) {
        self.with_conn(slot, |conn| {
            conn.execute("DELETE FROM object WHERE handle = ?1", params![handle])
        });
    }

    fn load_objects(&self, slot: u32) -> Vec<(u32, bool, Attributes)> {
        self.with_conn(slot, |conn| {
            let mut stmt = conn.prepare("SELECT handle, private FROM object")?;
            let objects: Vec<(u32, bool)> = stmt
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                .filter_map(|r| r.ok())
                .collect();
            let mut out = Vec::with_capacity(objects.len());
            let mut attr_stmt = conn.prepare("SELECT type, value FROM attribute WHERE handle = ?1")?;
            for (handle, private) in objects {
                let attrs: Attributes = attr_stmt
                    .query_map(params![handle], |row| Ok((row.get::<_, u32>(0)?, row.get::<_, Vec<u8>>(1)?)))?
                    .filter_map(|r| r.ok())
                    .collect();
                out.push((handle, private, attrs));
            }
            Ok(out)
        })
        .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::TokenStore as _;

    fn tmp_store() -> SqliteStore {
        // A test-local counter, NOT `state::UNIQUE_ID_COUNTER` — these tests
        // never touch that (nothing here calls `allocate_handle`), so two
        // tests running in parallel (cargo test's default) could otherwise
        // read the same value and collide on the same `token-0.db` file,
        // each seeing the other's rows.
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("softhsmrustv3-store-test-{}-{n}", std::process::id()));
        SqliteStore::open(dir).unwrap()
    }

    #[test]
    fn object_round_trips() {
        let store = tmp_store();
        let mut attrs = Attributes::new();
        attrs.insert(1, vec![1, 2, 3]);
        attrs.insert(2, b"hello".to_vec());
        store.put_object(0, 42, false, &attrs);
        let loaded = store.load_objects(0);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].0, 42);
        assert!(!loaded[0].1);
        assert_eq!(loaded[0].2, attrs);
    }

    #[test]
    fn delete_removes_object_and_attributes() {
        let store = tmp_store();
        let mut attrs = Attributes::new();
        attrs.insert(1, vec![9]);
        store.put_object(0, 7, true, &attrs);
        store.delete_object(0, 7);
        assert!(store.load_objects(0).is_empty());
    }

    #[test]
    fn token_round_trips() {
        let store = tmp_store();
        let token = PersistedToken {
            initialized: true,
            label: [0x41; 32],
            so_pin_salt: [1u8; 16],
            so_pin_hash: [2u8; 32],
            user_pin_salt: Some([3u8; 16]),
            user_pin_hash: Some([4u8; 32]),
            master_key_so_wrapped: Some(vec![5, 6, 7]),
            master_key_user_wrapped: None,
            next_handle: 0,
            unique_id_counter: 0,
        };
        store.put_token(3, &token);
        let loaded = store.get_token(3).unwrap();
        assert_eq!(loaded.initialized, token.initialized);
        assert_eq!(loaded.label, token.label);
        assert_eq!(loaded.master_key_so_wrapped, token.master_key_so_wrapped);
        assert_eq!(loaded.master_key_user_wrapped, None);
    }
}
