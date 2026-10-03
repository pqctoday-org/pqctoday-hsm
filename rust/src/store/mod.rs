//! Native, encrypted-at-rest persistence for the PKCS#11 engine's own
//! slots/tokens/objects — separate from, and unrelated to, the KMIP crate's
//! `kmip/src/store/` (which persists KMIP-level metadata only). This is the
//! store for the actual key material.
//!
//! `wasm32-unknown-unknown` (the browser playground) and
//! `wasm32-unknown-emscripten` (the `openssl.wasm` staticlib, which keeps
//! its existing `state_snapshot.rs` blob mechanism, untouched by this
//! module) never link this module's SQLite backend — see the target gate
//! on `rusqlite` in `Cargo.toml` and on `pub mod sqlite` below. Both wasm
//! targets get [`MemoryStore`], matching today's behavior exactly.
//!
//! ## Design
//!
//! - Only `CKA_TOKEN == TRUE` objects are ever written through (session
//!   objects die with the session, as PKCS#11 §4.4 requires; callers check
//!   this before calling [`persist_object`]).
//! - Objects with `CKA_PRIVATE == TRUE` are encrypted wholesale (every
//!   attribute value, not a curated subset — see `crypto`'s module doc for
//!   why) under the token's master key; everything else persists in
//!   plaintext, matching the C++ engine's `SecureDataManager`/`DBObject`
//!   split exactly (`Token::encrypt`/`decrypt` wrap only private values).
//! - The master key never touches disk unwrapped. It is cached in-process,
//!   per slot, only after a successful login unwraps it — see
//!   [`unlocked_master_key`] / [`set_unlocked_master_key`] /
//!   [`clear_unlocked_master_key`].
//! - Rehydration on process start is split: public (non-private) objects
//!   load eagerly (no key needed); private objects load lazily, right
//!   after the login that unwraps the master key protecting them — so an
//!   unauthenticated session never has private object bytes anywhere in
//!   memory, for free, as a consequence of the split rather than an
//!   additional check.

pub mod crypto;
pub mod memory;
#[cfg(not(target_arch = "wasm32"))]
pub mod sqlite;

use crate::constants::CKA_PRIVATE;
use crate::crypto::handlers::Attributes;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};

pub use memory::MemoryStore;

/// Which PIN wraps the master key. Mirrors `state::LoginState`'s SO/User
/// split without depending on that enum (keeps this module decoupled from
/// `state.rs`'s login-session concerns — it only cares about wrap slots).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PinRole {
    So,
    User,
}

/// Everything about a token's own metadata this store persists — a
/// deliberately separate shape from `state::TokenState`, not a mirror of
/// it: `login_state` has no field here (sessions never persist, PKCS#11
/// §5.6), and the two master-key wrap blobs live only here, never on
/// `TokenState` (keeps `TokenState`'s seven existing struct-literal call
/// sites, and the emscripten snapshot format that also serializes it,
/// completely untouched by this work).
#[derive(Clone, Default)]
pub struct PersistedToken {
    pub initialized: bool,
    pub label: [u8; 32],
    pub so_pin_salt: [u8; 16],
    pub so_pin_hash: [u8; 32],
    pub user_pin_salt: Option<[u8; 16]>,
    pub user_pin_hash: Option<[u8; 32]>,
    pub master_key_so_wrapped: Option<Vec<u8>>,
    pub master_key_user_wrapped: Option<Vec<u8>>,
    pub next_handle: u32,
    pub unique_id_counter: u64,
}

pub trait TokenStore: Send + Sync {
    /// `false` for `MemoryStore` — every call site checks this first so the
    /// default (no store configured) path does zero PBKDF2/AES-GCM work.
    fn is_persistent(&self) -> bool {
        false
    }
    fn put_token(&self, _slot: u32, _token: &PersistedToken) {}
    fn get_token(&self, _slot: u32) -> Option<PersistedToken> {
        None
    }
    /// `attrs` are exactly the bytes to store — already encrypted by
    /// [`persist_object`] if the object is private. The trait impl never
    /// makes an encryption decision itself.
    fn put_object(&self, _slot: u32, _handle: u32, _private: bool, _attrs: &Attributes) {}
    fn delete_object(&self, _slot: u32, _handle: u32) {}
    /// All objects for a slot, as stored (private objects' values are
    /// still ciphertext — the caller decrypts after this call, once it has
    /// the master key).
    fn load_objects(&self, _slot: u32) -> Vec<(u32, bool, Attributes)> {
        Vec::new()
    }
    /// Write every `(handle, private, attrs)` row in ONE durable transaction:
    /// all of them land or none do. `false` on any failure.
    fn put_objects_atomic(&self, _slot: u32, _rows: &[(u32, bool, Attributes)]) -> bool {
        true
    }
    /// Move stored rows from old to new handles in ONE transaction (logout
    /// re-keying, `state::invalidate_private_handles_on_slot`).
    fn rehandle_objects(&self, _slot: u32, _moves: &[(u32, u32)]) {}
}

static ACTIVE_STORE: OnceLock<RwLock<Arc<dyn TokenStore>>> = OnceLock::new();

fn active_lock() -> &'static RwLock<Arc<dyn TokenStore>> {
    ACTIVE_STORE.get_or_init(|| RwLock::new(Arc::new(MemoryStore)))
}

/// The currently configured store. Defaults to [`MemoryStore`] — today's
/// behavior — until [`configure`] is called (native embedders only; the
/// wasm-bindgen playground never calls it).
pub fn active() -> Arc<dyn TokenStore> {
    active_lock().read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Point the engine at a durable store. Native-only in practice (there is
/// no `SqliteStore` to construct on a wasm target), but the function itself
/// compiles everywhere so callers don't need their own cfg-gating.
pub fn configure(store: Arc<dyn TokenStore>) {
    *active_lock().write().unwrap_or_else(|e| e.into_inner()) = store;
}

// ── Unlocked master-key cache ───────────────────────────────────────────
//
// Deliberately NOT part of `state::TokenState` / `TOKEN_STORE`: keeping the
// unwrapped key in its own map means it is never incidentally cloned by the
// existing `TOKEN_STORE.with(|ts| ts.borrow().get(&slot).cloned())` pattern
// used throughout `ffi.rs`, and it has one job — zeroize cleanly on
// logout/finalize.
static UNLOCKED_MASTER_KEYS: OnceLock<std::sync::Mutex<HashMap<u32, [u8; crypto::MASTER_KEY_LEN]>>> =
    OnceLock::new();

fn unlocked_lock() -> &'static std::sync::Mutex<HashMap<u32, [u8; crypto::MASTER_KEY_LEN]>> {
    UNLOCKED_MASTER_KEYS.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

pub fn unlocked_master_key(slot: u32) -> Option<[u8; crypto::MASTER_KEY_LEN]> {
    unlocked_lock().lock().unwrap_or_else(|e| e.into_inner()).get(&slot).copied()
}

pub fn set_unlocked_master_key(slot: u32, key: [u8; crypto::MASTER_KEY_LEN]) {
    unlocked_lock().lock().unwrap_or_else(|e| e.into_inner()).insert(slot, key);
}

pub fn clear_unlocked_master_key(slot: u32) {
    use zeroize::Zeroize;
    let mut map = unlocked_lock().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(mut key) = map.remove(&slot) {
        key.zeroize();
    }
}

pub fn clear_all_unlocked_master_keys() {
    use zeroize::Zeroize;
    let mut map = unlocked_lock().lock().unwrap_or_else(|e| e.into_inner());
    for (_, mut key) in map.drain() {
        key.zeroize();
    }
}

fn read_bool(attrs: &Attributes, ty: u32) -> bool {
    attrs.get(&ty).map(|v| v.first().copied().unwrap_or(0) != 0).unwrap_or(false)
}

/// Cheap check ("is any durable store configured") for call sites that
/// need to decide, BEFORE doing any work, whether it's worth cloning an
/// object's attribute map at all. `active()` itself is already cheap (an
/// uncontended `RwLock` read + an `Arc` clone — reads never block other
/// reads, so this never serializes concurrent PKCS#11 calls against each
/// other), but the point of checking first is to skip the much more
/// expensive `Attributes` clone entirely in memory-only mode, not to avoid
/// the lock.
pub fn is_persistent() -> bool {
    active().is_persistent()
}

/// Encrypt (if private) and write through one token object. No-op, cheap,
/// if no store is configured. Fail-safe on a private object with no
/// unlocked master key for its slot: the in-memory object is unaffected
/// (this store is a durability layer, not the source of truth for a live
/// process), but nothing is written to disk — writing plaintext private
/// key material because encryption wasn't available would be worse than
/// not persisting at all.
pub fn persist_object(slot: u32, handle: u32, attrs: &Attributes) {
    let store = active();
    if !store.is_persistent() {
        return;
    }
    let private = read_bool(attrs, CKA_PRIVATE);
    if !private {
        store.put_object(slot, handle, false, attrs);
        return;
    }
    match unlocked_master_key(slot) {
        Some(key) => {
            let mut encrypted = Attributes::with_capacity(attrs.len());
            let mut ok = true;
            for (ty, val) in attrs {
                match crypto::encrypt_attr(&key, val) {
                    Ok(ct) => {
                        encrypted.insert(*ty, ct);
                    }
                    Err(_) => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok {
                store.put_object(slot, handle, true, &encrypted);
            } else if crate::oplog::enabled() {
                crate::oplog::emit("STORE_ENCRYPT_FAILED", &format!("slot={slot} handle={handle}"));
            }
        }
        None => {
            // No session has unlocked this slot's master key in this
            // process yet. Normal PKCS#11 access control already requires
            // login before a CKA_PRIVATE object can be created, so this is
            // an unexpected/defensive path, not a routine one.
            if crate::oplog::enabled() {
                crate::oplog::emit("STORE_SKIP_NO_MASTER_KEY", &format!("slot={slot} handle={handle}"));
            }
        }
    }
}

/// Encrypt `attrs` for storage exactly as [`persist_object`] does. `None`
/// when the object is private and the slot's master key is not unlocked.
fn storable(slot: u32, attrs: &Attributes) -> Option<(bool, Attributes)> {
    let private = read_bool(attrs, CKA_PRIVATE);
    if !private {
        return Some((false, attrs.clone()));
    }
    let key = unlocked_master_key(slot)?;
    let mut encrypted = Attributes::with_capacity(attrs.len());
    for (ty, val) in attrs {
        encrypted.insert(*ty, crypto::encrypt_attr(&key, val).ok()?);
    }
    Some((true, encrypted))
}

/// Persist several objects of one slot atomically (K4 commit boundary,
/// review K0B-R2-03). Unlike [`persist_object`], a failure is REPORTED: the
/// caller must not apply the in-memory change. No-op `true` without a store.
pub fn persist_objects_atomic(slot: u32, objects: &[(u32, &Attributes)]) -> bool {
    let store = active();
    if !store.is_persistent() {
        return true;
    }
    let mut rows = Vec::with_capacity(objects.len());
    for (h, attrs) in objects {
        match storable(slot, attrs) {
            Some((private, stored)) => rows.push((*h, private, stored)),
            None => return false,
        }
    }
    store.put_objects_atomic(slot, &rows)
}

/// Follow a logout re-key in the durable store (review K0B-R2-02): without
/// this, the next login rehydrated every private token object a second
/// time under its old handle.
pub fn persist_rehandle(slot: u32, moves: &[(u32, u32)]) {
    let store = active();
    if store.is_persistent() && !moves.is_empty() {
        store.rehandle_objects(slot, moves);
    }
}

pub fn persist_delete(slot: u32, handle: u32) {
    let store = active();
    if store.is_persistent() {
        store.delete_object(slot, handle);
    }
}

/// Point the engine at a durable on-disk store AND rehydrate everything it
/// can without a PIN: every slot's token metadata (label, PIN hashes, the
/// wrapped master-key blobs — never unwrapped here) and every NON-private
/// object. Private objects are deliberately skipped — see the module doc
/// and [`rehydrate_private_objects`], which loads them right after the
/// login that can actually decrypt them.
///
/// Native only (there is no [`sqlite::SqliteStore`] to construct on a wasm
/// target). Call once, before any session opens — typically from the
/// embedder's own startup (e.g. `pqc-kmip`'s `--engine-store <dir>`).
#[cfg(not(target_arch = "wasm32"))]
pub fn configure_persistent_store(dir: impl AsRef<std::path::Path>) -> std::io::Result<()> {
    let dir = dir.as_ref();
    // Re-pointing this process (an embedder restart, or a test simulating
    // one): release any store it already holds, and with it that store's
    // exclusive lock, before opening — otherwise reopening the same
    // directory would refuse itself.
    configure(Arc::new(MemoryStore));
    let store = Arc::new(sqlite::SqliteStore::open(dir)?);

    // One `.db` file per slot (see sqlite.rs's module doc) — slots present
    // on disk are discovered from the directory listing rather than
    // requiring the caller to enumerate them up front.
    let mut slots = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if let Some(slot_str) = name.strip_prefix("token-").and_then(|s| s.strip_suffix(".db")) {
                    if let Ok(slot) = slot_str.parse::<u32>() {
                        slots.push(slot);
                    }
                }
            }
        }
    }

    configure(store.clone());

    // Order matters (found 2026-10-03 via the K4 store test): every stored
    // handle, across ALL slots and including private rows not yet
    // decryptable, must be reserved BEFORE anything allocates. Previously
    // `ensure_slot` ran first and minted this slot's CKO_PROFILE objects
    // from a fresh NEXT_HANDLE, which could equal handles already stored
    // for another slot (each slot's token row only records its own
    // next_handle). The profile object's persist then overwrote that stored
    // row, silently losing a token object on every multi-slot restart.
    let loaded: Vec<(u32, Option<PersistedToken>, Vec<(u32, bool, Attributes)>)> = slots
        .iter()
        .map(|&slot| (slot, store.get_token(slot), store.load_objects(slot)))
        .collect();
    let max_handle = loaded.iter().flat_map(|(_, _, objs)| objs.iter().map(|(h, _, _)| *h)).max().unwrap_or(0);
    crate::state::NEXT_HANDLE.fetch_max(max_handle.saturating_add(1), std::sync::atomic::Ordering::Relaxed);
    for (slot, token, _) in &loaded {
        if let Some(pt) = token {
            crate::state::rehydrate_token(*slot, pt);
        }
    }
    for (_, _, objs) in loaded.iter() {
        for (handle, private, attrs) in objs {
            if *private {
                continue; // loaded lazily by rehydrate_private_objects, on login
            }
            if let Some(plain) = decrypt_loaded(false, None, attrs.clone()) {
                crate::state::rehydrate_insert(*handle, plain);
            }
        }
    }
    // Only now, and only for a slot that has none on disk.
    for (slot, token, _) in &loaded {
        if token.is_some() {
            crate::state::ensure_profile_objects(*slot);
        }
    }
    Ok(())
}

/// Load `slot`'s private objects now that `master_key` (just unwrapped by a
/// successful login) can decrypt them. Called from `ffi::C_Login` after a
/// successful unlock. Idempotent — an object already in `OBJECTS` (e.g. a
/// second login within the same process) is left alone.
pub fn rehydrate_private_objects(slot: u32, master_key: &[u8; crypto::MASTER_KEY_LEN]) {
    let store = active();
    if !store.is_persistent() {
        return;
    }
    for (handle, private, attrs) in store.load_objects(slot) {
        if !private || crate::state::object_exists(handle) {
            continue;
        }
        if let Some(plain) = decrypt_loaded(true, Some(master_key), attrs) {
            crate::state::rehydrate_insert(handle, plain);
        } else if crate::oplog::enabled() {
            crate::oplog::emit("STORE_DECRYPT_FAILED", &format!("slot={slot} handle={handle}"));
        }
    }
}

/// Decrypt one loaded (possibly-encrypted) object's attributes back into
/// plaintext `Attributes` ready to insert into `OBJECTS`. `None` on any
/// decryption failure (wrong/rotated key, corrupted row) — callers should
/// skip the object and log, never insert a half-decrypted map.
pub fn decrypt_loaded(private: bool, key: Option<&[u8; crypto::MASTER_KEY_LEN]>, stored: Attributes) -> Option<Attributes> {
    if !private {
        return Some(stored);
    }
    let key = key?;
    let mut out = Attributes::with_capacity(stored.len());
    for (ty, ct) in stored {
        match crypto::decrypt_attr(key, &ct) {
            Ok(pt) => {
                out.insert(ty, pt);
            }
            Err(_) => return None,
        }
    }
    Some(out)
}
