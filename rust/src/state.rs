use rand_chacha::ChaCha20Rng;
use std::cell::RefCell;
use std::collections::HashMap;
use wasm_bindgen::prelude::*;

use crate::constants::*;
use crate::crypto::*;

use lazy_static::lazy_static;
use std::sync::{Mutex, MutexGuard};

pub struct GlobalState<T>(pub Mutex<T>);

impl<T> GlobalState<T> {
    pub const fn new_const(t: T) -> Self {
        Self(Mutex::new(t))
    }
    pub fn new(t: T) -> Self {
        Self(Mutex::new(t))
    }
    pub fn with<R, F: FnOnce(&GlobalState<T>) -> R>(&self, f: F) -> R {
        f(self)
    }
    #[track_caller]
    pub fn borrow_mut(&self) -> MutexGuard<'_, T> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
    #[track_caller]
    pub fn borrow(&self) -> MutexGuard<'_, T> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// PKCS#11 v3.2 §5.6 — library initialization state. Set by C_Initialize,
/// cleared by C_Finalize. Every Cryptoki function except C_Initialize and the
/// function-list/interface getters must return CKR_CRYPTOKI_NOT_INITIALIZED
/// when this is false.
pub static INITIALIZED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[inline]
pub fn is_initialized() -> bool {
    INITIALIZED.load(std::sync::atomic::Ordering::SeqCst)
}

#[inline]
pub fn set_initialized(v: bool) {
    INITIALIZED.store(v, std::sync::atomic::Ordering::SeqCst);
}

// PERF-BENCH FIX (2026-07-18, B4 step 1): these three were
// `GlobalState<u32>`/`GlobalState<u64>` (a `Mutex` behind `lazy_static!`),
// each guarding nothing but a single integer counter with a plain
// read-increment-write body. A `Mutex` here buys no correctness the
// hardware's own atomic RMW doesn't already give — converting to
// `AtomicU32`/`AtomicU64` removes three more global lock acquisitions
// from the handle/session/object-creation hot path (keygen, session open,
// every C_CreateObject) with no behavior change: NEXT_HANDLE keeps its
// saturate-at-MAX semantics (`fetch_update`, a safe CAS-retry loop, so
// concurrent callers can't race past u32::MAX), and the other two keep
// their plain wrapping-increment semantics (`fetch_add`, matching the
// original `u32`/`u64` release-mode wrapping arithmetic exactly).
// `AtomicU32::new`/`AtomicU64::new` are `const fn`, so these no longer
// need `lazy_static!` at all — a plain `pub static` suffices.
pub static NEXT_HANDLE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(100);
/// PKCS#11 v3.2 §4.4.1 — CKA_UNIQUE_ID source. Process-monotonic and never
/// reset (not even by C_Finalize) so identifiers stay unique across
/// initialize/finalize cycles within one process.
pub static UNIQUE_ID_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
pub static NEXT_SESSION_HANDLE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

lazy_static! {
    pub static ref OBJECTS: GlobalState<HashMap<u32, Attributes>> = GlobalState::new(HashMap::new());
    pub static ref SIGN_STATE: GlobalState<HashMap<u32, (u32, u32, Vec<u8>, bool)>> = GlobalState::new(HashMap::new());
    pub static ref VERIFY_STATE: GlobalState<HashMap<u32, (u32, u32, Vec<u8>, bool)>> = GlobalState::new(HashMap::new());
    pub static ref VERIFY_SIG_STATE: GlobalState<HashMap<u32, VerifySigCtx>> = GlobalState::new(HashMap::new());
    pub static ref ENCRYPT_STATE: GlobalState<HashMap<u32, EncryptCtx>> = GlobalState::new(HashMap::new());
    pub static ref DECRYPT_STATE: GlobalState<HashMap<u32, EncryptCtx>> = GlobalState::new(HashMap::new());
    pub static ref MESSAGE_ENCRYPT_STATE: GlobalState<HashMap<u32, MsgAeadCtx>> = GlobalState::new(HashMap::new());
    pub static ref MESSAGE_DECRYPT_STATE: GlobalState<HashMap<u32, MsgAeadCtx>> = GlobalState::new(HashMap::new());
    pub static ref DIGEST_STATE: GlobalState<HashMap<u32, DigestCtx>> = GlobalState::new(HashMap::new());
    /// Sessions whose digest op entered the multi-part phase (C_DigestUpdate
    /// called). PKCS#11 v3.2 §5.13 convention — the one-shot C_Digest is then
    /// CKR_OPERATION_ACTIVE until the op finishes. Maintained strictly in
    /// lockstep with DIGEST_STATE removal/clear sites.
    pub static ref DIGEST_MULTIPART: GlobalState<std::collections::HashSet<u32>> = GlobalState::new(std::collections::HashSet::new());
    /// C_SignMessageBegin/Next accumulator (message parts between Begin and the final Next).
    pub static ref MESSAGE_SIGN_ACC: GlobalState<HashMap<u32, Vec<u8>>> = GlobalState::new(HashMap::new());
    /// C_VerifyMessageBegin/Next accumulator.
    pub static ref MESSAGE_VERIFY_ACC: GlobalState<HashMap<u32, Vec<u8>>> = GlobalState::new(HashMap::new());
    /// T4 — C_SignUpdate accumulator. Presence of a session key marks the
    /// sign op as having entered its multi-part phase (the one-shot C_Sign is
    /// then CKR_OPERATION_ACTIVE until C_SignFinal — mirrors
    /// DIGEST_MULTIPART); the Vec carries the concatenated parts that
    /// C_SignFinal hands to the one-shot handler. Maintained strictly in
    /// lockstep with SIGN_STATE removal/clear sites. Follow-up (NOT this
    /// slice): stream the hash-composite mechanisms into an incremental
    /// digest to bound memory instead of accumulating the whole message.
    pub static ref SIGN_MULTIPART_ACC: GlobalState<HashMap<u32, Vec<u8>>> = GlobalState::new(HashMap::new());
    /// T4 — C_VerifyUpdate accumulator (see SIGN_MULTIPART_ACC).
    pub static ref VERIFY_MULTIPART_ACC: GlobalState<HashMap<u32, Vec<u8>>> = GlobalState::new(HashMap::new());
    pub static ref FIND_STATE: GlobalState<HashMap<u32, FindCtx>> = GlobalState::new(HashMap::new());
    /// Persistent ACVP deterministic RNG — created once in C_Initialize, advances
    /// across all operations, cleared in C_Finalize. Uses IETF ChaCha20 (RFC 8439)
    /// to match the C++ OpenSSL EVP_chacha20 implementation.
    pub static ref ACVP_RNG: GlobalState<Option<ChaCha20Rng>> = GlobalState::new(None);

    // PKCS#11 v3.2 token and session tracking
    pub static ref SESSIONS: GlobalState<HashMap<u32, SessionState>> = GlobalState::new(HashMap::new());
    pub static ref TOKEN_STORE: GlobalState<HashMap<u32, TokenState>> = GlobalState::new(HashMap::new());
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LoginState {
    Public,
    User,
    SO,
}

#[derive(Clone)]
pub struct TokenState {
    pub slot_id: u32,
    pub initialized: bool,
    pub label: [u8; 32],
    pub login_state: LoginState,
    pub so_pin_salt: [u8; 16],
    pub so_pin_hash: [u8; 32],
    pub user_pin_salt: Option<[u8; 16]>,
    pub user_pin_hash: Option<[u8; 32]>,
}

#[derive(Clone)]
pub struct SessionState {
    pub slot_id: u32,
    pub rw_session: bool,
}

/// PIN-at-rest hashing: salted PBKDF2-HMAC-SHA256, 10k iterations.
///
/// Caveat (consistent with the KMIP credential store, `kmip/src/server/
/// auth.rs`): a production credential store wants a memory-hard KDF
/// (argon2id) instead. This soft token holds session-scoped dev/test PINs
/// for an in-process engine — PBKDF2-SHA256 is the deliberate trade-off to
/// keep the wasm binary small and dependency-light.
pub fn hash_pin(pin: &[u8], salt: &[u8; 16]) -> [u8; 32] {
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;
    let mut hash = [0u8; 32];
    pbkdf2_hmac::<Sha256>(pin, salt, 10000, &mut hash);
    hash
}

/// Default CK_TOKEN_INFO label for the built-in slot-0 token. Embedders can
/// override it via `native::set_token_label` (or PKCS#11's own C_InitToken)
/// to distinguish engine instances.
pub const DEFAULT_TOKEN_LABEL: &str = "SoftHSM3-Rust";

/// Space-pad (and truncate) a UTF-8 label to PKCS#11 v3.2 §5.5's fixed
/// 32-byte, blank-padded CK_TOKEN_INFO.label encoding.
pub fn pad_label_32(label: &str) -> [u8; 32] {
    let mut out = [0x20u8; 32];
    let bytes = label.as_bytes();
    let n = bytes.len().min(32);
    out[..n].copy_from_slice(&bytes[..n]);
    out
}

pub fn init_token_store() {
    let empty = TOKEN_STORE.with(|ts| ts.borrow().is_empty());
    if empty {
        // Provide an initial uninitialized token in slot 0
        ensure_slot(0);
    }
}

/// Multi-slot activation hook: add an uninitialized token in `slot_id` if the
/// slot does not exist yet (no-op otherwise). The engine boots single-slot
/// (slot 0, the primary token); embedders and tests call this BEFORE
/// `C_InitToken` / `C_OpenSession` on the new slot to bring additional tokens
/// online. There is no config file in this crate — this function IS the
/// multi-slot configuration surface.
pub fn ensure_slot(slot_id: u32) {
    let is_new = TOKEN_STORE.with(|ts| {
        let mut store = ts.borrow_mut();
        if store.contains_key(&slot_id) {
            false
        } else {
            store.insert(
                slot_id,
                TokenState {
                    slot_id,
                    initialized: false,
                    label: pad_label_32(DEFAULT_TOKEN_LABEL),
                    login_state: LoginState::Public,
                    so_pin_salt: [0u8; 16],
                    so_pin_hash: [0u8; 32],
                    user_pin_salt: None,
                    user_pin_hash: None,
                },
            );
            true
        }
    });
    if is_new {
        init_profile_objects(slot_id);
    }
}

/// PKCS#11 Profiles v3.2 §3 — materialize this token's built-in `CKO_PROFILE`
/// object(s) at slot creation: token-resident, public (no CKA_PRIVATE, so
/// visible to C_FindObjects without login per can_access_object), and
/// read-only (CKA_MODIFIABLE/COPYABLE/DESTROYABLE all FALSE — apply_object_defaults
/// would otherwise default them to TRUE). Baseline Provider is the only
/// profile this engine currently claims conformance to; add further profile
/// objects here only after auditing every Profiles v3.2 requirement for
/// that profile (see rust/RUST_P11_V32_CONFORMANCE_REPORT.md).
fn init_profile_objects(slot_id: u32) {
    let mut attrs: Attributes = HashMap::new();
    attrs.insert(CKA_CLASS, CKO_PROFILE.to_le_bytes().to_vec());
    attrs.insert(CKA_PROFILE_ID, CKP_BASELINE_PROVIDER.to_le_bytes().to_vec());
    attrs.insert(CKA_TOKEN, vec![1]);
    attrs.insert(CKA_PRIV_SLOT_ID, slot_id.to_le_bytes().to_vec());
    store_bool(&mut attrs, CKA_MODIFIABLE, false);
    store_bool(&mut attrs, CKA_COPYABLE, false);
    store_bool(&mut attrs, CKA_DESTROYABLE, false);
    allocate_handle(attrs);
}

pub struct EncryptCtx {
    pub mech_type: u32,
    pub key_handle: u32,
    pub iv: Vec<u8>,
    pub aad: Vec<u8>,
    pub tag_bits: u32,
    /// Streaming state, built lazily on the first `C_EncryptUpdate` /
    /// `C_DecryptUpdate` (or `*Final`) call. `None` while the op is
    /// single-shot-only or untouched since Init.
    pub multipart: Option<crate::crypto::multipart::MultipartCipher>,
}

/// PKCS#11 v3.2 §5.15 message-based AEAD state (C_MessageEncryptInit …
/// C_MessageEncryptFinal, and the decrypt mirror). One ctx per session per
/// direction; `stream`/`plaintext_acc` are live only between
/// C_*MessageBegin and the CKF_END_OF_MESSAGE C_*MessageNext.
pub struct MsgAeadCtx {
    pub key: Vec<u8>,
    pub in_message: bool,
    /// CK_GCM_MESSAGE_PARAMS.ulTagBits from Begin — the tag is computed in
    /// full and truncated to this width at the final Next.
    pub tag_bits: u32,
    /// T5 — incremental GCM state (CTR keystream carry + running GHASH);
    /// AAD is folded in at Begin. Each C_*MessageNext is O(chunk).
    pub stream: Option<crate::crypto::multipart::GcmState>,
    /// Decrypt only: verify-then-release buffer. Plaintext produced by the
    /// parts is withheld here until the final part's tag verifies, then
    /// emitted in one piece (zeroized on mismatch) — an HSM must not hand
    /// out unauthenticated plaintext. Memory bound: one full message.
    pub plaintext_acc: Vec<u8>,
}

impl MsgAeadCtx {
    /// Zeroize everything sensitive before drop (key bytes, withheld
    /// plaintext; `GcmState`'s own `Drop` wipes its keystream/buffers).
    pub fn wipe(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
        self.plaintext_acc.zeroize();
        self.stream = None;
    }
}

#[derive(Clone)]
pub struct VerifySigCtx {
    pub mech_type: u32,
    pub key_handle: u32,
    pub signature: Vec<u8>,
    pub msg_acc: Vec<u8>,
    pub slh_ctx: Vec<u8>,
    pub slh_det: bool,
}

/// Set PKCS#11 v3.2 mandatory object-management attribute defaults on a key before it
/// is stored.  These are applied ONLY if the caller (or the engine) has not already set
/// a value, so template-provided overrides are respected.
///
/// * `CKA_MODIFIABLE`         (0x170) — default `TRUE`  (object may be modified after creation)
/// * `CKA_COPYABLE`           (0x171) — default `TRUE`  (object may be copied)
/// * `CKA_DESTROYABLE`        (0x172) — default `TRUE`  (object may be destroyed)
/// * `CKA_TRUSTED`            (0x086) — default `FALSE` — public keys and secret keys
/// * `CKA_WRAP_WITH_TRUSTED`  (0x210) — default `FALSE` — private keys and secret keys
/// * `CKA_ALWAYS_AUTHENTICATE`(0x202) — default `FALSE` — private keys only
fn apply_object_defaults(attrs: &mut Attributes) {
    if !attrs.contains_key(&CKA_MODIFIABLE) {
        store_bool(attrs, CKA_MODIFIABLE, true);
    }
    if !attrs.contains_key(&CKA_COPYABLE) {
        store_bool(attrs, CKA_COPYABLE, true);
    }
    if !attrs.contains_key(&CKA_DESTROYABLE) {
        store_bool(attrs, CKA_DESTROYABLE, true);
    }
    // PKCS#11 v3.2 class-specific defaults — read CKA_CLASS to determine which to set
    let obj_class = attrs.get(&CKA_CLASS).and_then(|v| {
        if v.len() >= 4 {
            Some(u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
        } else {
            None
        }
    });
    if let Some(class) = obj_class {
        // CKA_TRUSTED: public keys + secret keys (object is not trusted-marked by default)
        if (class == CKO_PUBLIC_KEY || class == CKO_SECRET_KEY) && !attrs.contains_key(&CKA_TRUSTED)
        {
            store_bool(attrs, CKA_TRUSTED, false);
        }
        // CKA_WRAP_WITH_TRUSTED: private + secret keys (no forced-trusted-wrap by default)
        if (class == CKO_PRIVATE_KEY || class == CKO_SECRET_KEY)
            && !attrs.contains_key(&CKA_WRAP_WITH_TRUSTED)
        {
            store_bool(attrs, CKA_WRAP_WITH_TRUSTED, false);
        }
        // CKA_ALWAYS_AUTHENTICATE: private keys only (no per-op re-auth by default)
        if class == CKO_PRIVATE_KEY && !attrs.contains_key(&CKA_ALWAYS_AUTHENTICATE) {
            store_bool(attrs, CKA_ALWAYS_AUTHENTICATE, false);
        }
    }
}

/// Return the slot id backing a session handle, if the session exists.
pub fn session_slot(h_session: u32) -> Option<u32> {
    SESSIONS.with(|s| s.borrow().get(&h_session).map(|ss| ss.slot_id))
}

/// True if a session handle refers to a live session.
pub fn session_exists(h_session: u32) -> bool {
    SESSIONS.with(|s| s.borrow().contains_key(&h_session))
}

/// True if the session is read/write (CKF_RW_SESSION). Returns false for an
/// unknown handle.
pub fn session_is_rw(h_session: u32) -> bool {
    SESSIONS.with(|s| {
        s.borrow()
            .get(&h_session)
            .map(|ss| ss.rw_session)
            .unwrap_or(false)
    })
}

/// True if the token backing `slot_id` is logged in (User or SO).
pub fn token_logged_in(slot_id: u32) -> bool {
    TOKEN_STORE.with(|ts| {
        ts.borrow()
            .get(&slot_id)
            .map(|t| t.login_state != LoginState::Public)
            .unwrap_or(false)
    })
}

/// PKCS#11 v3.2 §5.5 — single point of truth for CKF_TOKEN_INITIALIZED
/// (audit H-15). The engine ships a built-in soft token in slot 0, but it
/// starts UNinitialized: `C_Login` refuses with CKR_OPERATION_NOT_INITIALIZED
/// until `C_InitToken` has run. The flag therefore derives from the real
/// `TokenState::initialized` bit (set by C_InitToken, cleared only by
/// C_Finalize wiping the store) instead of being hardwired on — it must
/// tell the truth about what C_Login will enforce.
pub fn token_initialized(token: &TokenState) -> bool {
    token.initialized
}

/// PKCS#11 v3.2 §5.5 — single point of truth for CKF_USER_PIN_INITIALIZED.
/// True once an SO session has set the normal-user PIN via C_InitPIN
/// (salted PBKDF2 hash stored in `TokenState::user_pin_hash`). While unset,
/// `C_Login(CKU_USER, ..)` returns CKR_USER_PIN_NOT_INITIALIZED.
pub fn user_pin_initialized(token: &TokenState) -> bool {
    token.user_pin_hash.is_some()
}

/// PKCS#11 v3.2 §5.5 — compose CK_TOKEN_INFO.flags from real token state
/// (audit H-15; previously hardcoded 0x040D regardless of state).
///
/// * `CKF_RNG` — always: the engine has a real CSPRNG (getrandom/OsRng).
/// * `CKF_LOGIN_REQUIRED` — ALWAYS set, deliberately: `can_access_object`
///   gates CKA_PRIVATE=TRUE objects on `session_logged_in()`
///   unconditionally, i.e. login is required for private-object access
///   even before a user PIN exists (such objects are simply unreachable
///   until C_InitPIN + C_Login). The flag matches that enforcement.
/// * `CKF_TOKEN_INITIALIZED` — from [`token_initialized`].
/// * `CKF_USER_PIN_INITIALIZED` — from [`user_pin_initialized`].
/// * `CKF_WRITE_PROTECTED` — never set: the token is writable.
pub fn token_info_flags(token: &TokenState) -> u32 {
    let mut flags = CKF_RNG | CKF_LOGIN_REQUIRED;
    if token_initialized(token) {
        flags |= CKF_TOKEN_INITIALIZED;
    }
    if user_pin_initialized(token) {
        flags |= CKF_USER_PIN_INITIALIZED;
    }
    flags
}

/// Live (total, read-write) session counts for a slot, from the session
/// table — backs CK_TOKEN_INFO.ulSessionCount / ulRwSessionCount.
pub fn session_counts(slot_id: u32) -> (u32, u32) {
    SESSIONS.with(|s| {
        let store = s.borrow();
        let mut total = 0u32;
        let mut rw = 0u32;
        for ss in store.values().filter(|ss| ss.slot_id == slot_id) {
            total += 1;
            if ss.rw_session {
                rw += 1;
            }
        }
        (total, rw)
    })
}

/// True if the session's token is logged in (User or SO).
pub fn session_logged_in(h_session: u32) -> bool {
    match session_slot(h_session) {
        Some(slot) => token_logged_in(slot),
        None => false,
    }
}

/// True if the session is logged in specifically as SO (Security Officer).
/// PKCS#11 v3.2 §4.6 Table 19 footnote — `CKA_TRUSTED` on a certificate
/// "can only be set to CK_TRUE by the SO user".
pub fn session_is_so(h_session: u32) -> bool {
    match session_slot(h_session) {
        Some(slot) => TOKEN_STORE.with(|ts| {
            ts.borrow()
                .get(&slot)
                .map(|t| t.login_state == LoginState::SO)
                .unwrap_or(false)
        }),
        None => false,
    }
}

/// Slot id of the token owning an object record. Objects are stamped with
/// `CKA_PRIV_SLOT_ID` at creation ([`allocate_handle`]); records created
/// before that (or hand-built test fixtures) default to slot 0, the primary
/// token.
pub fn object_slot_of(attrs: &Attributes) -> u32 {
    attrs
        .get(&CKA_PRIV_SLOT_ID)
        .filter(|v| v.len() >= 4)
        .map(|v| u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
        .unwrap_or(0)
}

/// Stamp `attrs` with the slot backing `h_session` (slot 0 — the primary
/// token — when the session is unknown, e.g. library-scoped native/KMIP
/// creation before any session exists).
pub fn tag_object_slot(h_session: u32, attrs: &mut Attributes) {
    let slot = session_slot(h_session).unwrap_or(0);
    attrs.insert(CKA_PRIV_SLOT_ID, slot.to_le_bytes().to_vec());
}

/// PKCS#11 v3.2 §4.4 / §5.6 — a private object (CKA_PRIVATE=TRUE) may only be
/// accessed (found, read, used, destroyed) when the session's token is logged
/// in as User or SO. Public objects are always accessible. Objects that do not
/// set CKA_PRIVATE are treated as public (the engine's historical default).
///
/// T3 (audit: multi-slot FindObjects scoping) — additionally, object handles
/// are TOKEN-scoped per §2.4/§4.4: an object that belongs to another slot's
/// token is not visible to this session at all (its handle is treated as
/// invalid). Every FFI by-handle gate and the FindObjects enumeration route
/// through this predicate, so cross-token access uniformly fails with
/// CKR_OBJECT_HANDLE_INVALID (strict behavior, single choke point).
pub fn can_access_object(h_session: u32, attrs: &Attributes) -> bool {
    if object_slot_of(attrs) != session_slot(h_session).unwrap_or(0) {
        return false;
    }
    if !read_bool_attr(attrs, CKA_PRIVATE) {
        return true;
    }
    session_logged_in(h_session)
}

/// PKCS#11 v3.2 §4.8 Table 13 — `CKA_ALLOWED_MECHANISMS` restricts a key to
/// a caller-specified mechanism whitelist. Absent attribute (the common
/// case) means unrestricted, per the spec's default. Call AFTER key-handle
/// validation and BEFORE any mechanism-parameter-specific parsing, using
/// the caller's ORIGINAL requested mechanism (not an internal remap like
/// CKM_EDDSA → CKM_EDDSA_PH) — §5.1.6 `CKR_MECHANISM_INVALID` is the code
/// consumers (NSS, pkcs11-provider) expect for a disallowed mechanism.
/// Shared by both the FFI (`ffi.rs`) and native (`native/*.rs`) entry
/// points — KMIP calls the engine through the native surface, not FFI, so
/// this can't live only on one side.
pub fn check_mechanism_allowed(h_key: u32, mech_type: u32) -> Result<(), u32> {
    let allowed = OBJECTS.with(|o| {
        o.borrow()
            .get(&h_key)
            .and_then(|attrs| attrs.get(&CKA_ALLOWED_MECHANISMS).cloned())
    });
    match allowed {
        None => Ok(()),
        Some(bytes) => {
            let is_allowed = bytes
                .chunks_exact(4)
                .any(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]) == mech_type);
            if is_allowed {
                Ok(())
            } else {
                Err(CKR_MECHANISM_INVALID)
            }
        }
    }
}

/// Convenience: look up an object by handle and decide accessibility from the
/// given session. Returns false if the object does not exist.
pub fn can_access_handle(h_session: u32, handle: u32) -> bool {
    OBJECTS.with(|objs| {
        objs.borrow()
            .get(&handle)
            .map(|attrs| can_access_object(h_session, attrs))
            .unwrap_or(false)
    })
}

/// PKCS#11 v3.2 §4.9/§4.10 — CKA_VALUE of a private/secret key must not be
/// revealed when CKA_SENSITIVE=TRUE **or** CKA_EXTRACTABLE=FALSE. This single
/// predicate backs both `ffi::C_GetAttributeValue` and the native API
/// (`native::object::get_attribute`) so the two surfaces cannot drift.
pub fn value_is_blocked(attrs: &Attributes) -> bool {
    let class = attrs
        .get(&CKA_CLASS)
        .filter(|v| v.len() >= 4)
        .map(|v| u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
        .unwrap_or(CKO_PUBLIC_KEY);
    let is_private_or_secret = class == CKO_PRIVATE_KEY || class == CKO_SECRET_KEY;
    if !is_private_or_secret {
        return false;
    }
    let sensitive = read_bool_attr(attrs, CKA_SENSITIVE);
    let extractable = read_bool_attr(attrs, CKA_EXTRACTABLE);
    sensitive || !extractable
}

/// PKCS#11 v3.2 — attribute types that carry raw secret key material and share
/// CKA_VALUE's sensitivity gate (`value_is_blocked`). CKA_SEED (the
/// deterministic-keygen seed: ξ for ML-DSA, d‖z for ML-KEM) is footnoted
/// identically to CKA_VALUE in the v3.2 PQC key tables: it must never be
/// readable from a sensitive or unextractable key. Both
/// `ffi::C_GetAttributeValue` and `native::object::get_attribute` use this
/// predicate so the two surfaces cannot drift.
pub fn attr_is_sensitive_material(attr_type: u32) -> bool {
    // CKA_VALUE / CKA_SEED, plus the RSA private CRT components
    // (CKA_PRIVATE_EXPONENT 0x123 .. CKA_COEFFICIENT 0x128): on a sensitive or
    // unextractable key these read back as CKR_ATTRIBUTE_SENSITIVE, never in clear.
    attr_type == CKA_VALUE
        || attr_type == CKA_SEED
        || (CKA_PRIVATE_EXPONENT..=CKA_COEFFICIENT).contains(&attr_type)
}

/// T6 — pure modifiability check behind every attribute-mutation surface
/// (C ABI `C_SetAttributeValue`/`C_CopyObject` templates and the native
/// `set_attribute` path, via [`set_object_attr_checked`]). Validates one
/// proposed `(attr_type, value)` against the object's CURRENT attributes
/// without mutating anything, so callers can run an all-or-nothing
/// validate-then-apply pass (PKCS#11 v3.2 §4.1.3 modifiability table).
///
/// Policy:
/// * server-managed / token-computed attrs → CKR_ATTRIBUTE_READ_ONLY
///   (includes raw key material CKA_VALUE / CKA_SEED and CKA_PARAMETER_SET —
///   key material and its domain are fixed at creation);
/// * one-way transitions: CKA_SENSITIVE only FALSE→TRUE, CKA_EXTRACTABLE only
///   TRUE→FALSE (the reverse direction is CKR_ATTRIBUTE_READ_ONLY). Flipping
///   them does NOT touch CKA_ALWAYS_SENSITIVE / CKA_NEVER_EXTRACTABLE, which
///   record history;
/// * vendor stateful-key attrs (≥0x8000_0100) and engine-internal CKA_PRIV_*
///   (≥0xFFFF_0000) are the engine's own state channel and bypass the policy.
pub fn attr_mutation_allowed(attrs: &Attributes, attr_type: u32, value: &[u8]) -> Result<(), u32> {
    // engine-internal / vendor stateful channel — no policy
    if attr_type >= 0x8000_0000 {
        return Ok(());
    }
    const READ_ONLY: &[u32] = &[
        CKA_CLASS,
        CKA_KEY_TYPE,
        CKA_LOCAL,
        CKA_KEY_GEN_MECHANISM,
        CKA_ALWAYS_SENSITIVE,
        CKA_NEVER_EXTRACTABLE,
        CKA_CHECK_VALUE,
        // §4.4.1 — token-generated at creation, never client-mutable.
        CKA_UNIQUE_ID,
        // §4.1.1 Table 12 — CKA_TRUSTED may only be set by the SO. This crate
        // has no SO-session concept, so every caller set is rejected and the
        // FALSE default (apply_object_defaults) stands.
        CKA_TRUSTED,
        // T6 — key material and its domain are fixed at creation: CKA_VALUE /
        // CKA_SEED can never be swapped under an existing object's metadata,
        // and CKA_PARAMETER_SET is bound to the generated key.
        CKA_VALUE,
        CKA_SEED,
        CKA_PARAMETER_SET,
        CKA_MODULUS,
        CKA_PUBLIC_EXPONENT,
        CKA_EC_PARAMS,
        CKA_EC_POINT,
    ];
    if READ_ONLY.contains(&attr_type) {
        return Err(CKR_ATTRIBUTE_READ_ONLY);
    }
    // WP-6 remediation — §4.8 Table 13: CKA_ALLOWED_MECHANISMS is a packed
    // CK_MECHANISM_TYPE[] (u32 LE); mirrors validate_create_template's
    // identical check at creation time (ffi.rs), which this mutation path
    // never ran through. Without this, C_SetAttributeValue accepted any
    // byte length — including the exact malformed value C_CreateObject
    // would reject — and check_mechanism_allowed's chunks_exact(4) would
    // then silently drop a trailing partial chunk rather than erroring.
    if attr_type == CKA_ALLOWED_MECHANISMS && value.len() % 4 != 0 {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID);
    }
    if attr_type == CKA_SENSITIVE || attr_type == CKA_EXTRACTABLE {
        let new_val = value.first().copied().unwrap_or(0) != 0;
        let cur_val = read_bool_attr(attrs, attr_type);
        let legal = if attr_type == CKA_SENSITIVE {
            // FALSE→TRUE only
            !cur_val || new_val
        } else {
            // CKA_EXTRACTABLE: TRUE→FALSE only
            cur_val || !new_val
        };
        if !legal {
            return Err(CKR_ATTRIBUTE_READ_ONLY);
        }
    }
    Ok(())
}

/// Server-managed (read-only) attributes a mutation API must refuse to change,
/// plus the one-way transition rules (PKCS#11 v3.2 §4.1.1 Table 12) — see
/// [`attr_mutation_allowed`], the single source of truth this delegates to.
pub fn set_object_attr_checked(handle: u32, attr_type: u32, value: Vec<u8>) -> Result<(), u32> {
    let verdict = OBJECTS.with(|o| {
        o.borrow()
            .get(&handle)
            .map(|attrs| attr_mutation_allowed(attrs, attr_type, &value))
    });
    match verdict {
        None => Err(CKR_OBJECT_HANDLE_INVALID),
        Some(Err(rv)) => Err(rv),
        Some(Ok(())) => {
            if set_object_attr_bytes(handle, attr_type, value) {
                Ok(())
            } else {
                Err(CKR_OBJECT_HANDLE_INVALID)
            }
        }
    }
}

/// `allocate_handle` + owner-session tag (PKCS#11 §4.4 session objects).
/// The C-ABI object-creation paths use this; the native/KMIP surface keeps
/// plain `allocate_handle` (library scope — survives session churn).
pub fn allocate_handle_owned(owner_session: u32, mut attrs: Attributes) -> u32 {
    attrs.insert(
        CKA_PRIV_OWNER_SESSION,
        owner_session.to_le_bytes().to_vec(),
    );
    // T3 — the object belongs to the creating session's token (slot).
    tag_object_slot(owner_session, &mut attrs);
    allocate_handle(attrs)
}

/// §4.4 — destroy (zeroizing CKA_VALUE) every session object
/// (CKA_TOKEN=FALSE) owned by `h_session`. Token objects and library-scoped
/// (untagged) objects survive.
pub fn destroy_session_objects(h_session: u32) {
    use zeroize::Zeroize;
    OBJECTS.with(|objs| {
        let mut store = objs.borrow_mut();
        let doomed: Vec<u32> = store
            .iter()
            .filter(|(_, attrs)| {
                let owner = attrs
                    .get(&CKA_PRIV_OWNER_SESSION)
                    .filter(|v| v.len() >= 4)
                    .map(|v| u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
                    .unwrap_or(0);
                owner == h_session && owner != 0 && !read_bool_attr(attrs, CKA_TOKEN)
            })
            .map(|(h, _)| *h)
            .collect();
        for h in doomed {
            if let Some(mut attrs) = store.remove(&h) {
                if let Some(val) = attrs.get_mut(&CKA_VALUE) {
                    val.zeroize();
                }
            }
        }
    });
}

pub fn allocate_handle(mut attrs: Attributes) -> u32 {
    apply_object_defaults(&mut attrs);
    // T3 — every object records its owning token's slot. Callers with a
    // session context have already stamped it (allocate_handle_owned /
    // native keygen via tag_object_slot); anything else defaults to slot 0,
    // the primary token (KMIP's engine session and the wasm embedding both
    // live there).
    attrs
        .entry(CKA_PRIV_SLOT_ID)
        .or_insert_with(|| 0u32.to_le_bytes().to_vec());
    // PKCS#11 v3.2 §4.4.1 — every object gets a token-generated CKA_UNIQUE_ID
    // at creation. This is the single choke point through which all objects
    // enter OBJECTS, so the attribute is guaranteed on every surface (FFI,
    // native, KMIP). Unconditional insert: the attribute is read-only and any
    // caller-supplied value has already been rejected/skipped upstream.
    let uid = UNIQUE_ID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // §4.4.1 — render the monotonic counter as a canonical 36-char UUID
    // (8-4-4-4-12, v4 version/variant nibbles) so CKA_UNIQUE_ID is a portable,
    // fixed-width identifier. The KMIP store keeps its own UniqueIdentifier, so
    // this format is independent of the KMIP wire contract.
    let uuid = format!(
        "{:08x}-0000-4000-8000-{:012x}",
        (uid >> 48) as u32,
        uid & 0xffff_ffff_ffff,
    );
    attrs.insert(CKA_UNIQUE_ID, uuid.into_bytes());
    // Saturate at MAX rather than wrapping; callers get 0 as sentinel for
    // failure. `fetch_update` is a safe CAS-retry loop: concurrent callers
    // cannot race past u32::MAX the way a naive load-then-store could.
    let current = match NEXT_HANDLE.fetch_update(
        std::sync::atomic::Ordering::Relaxed,
        std::sync::atomic::Ordering::Relaxed,
        |h| if h == u32::MAX { None } else { Some(h + 1) },
    ) {
        Ok(prev) => prev,
        Err(_) => return 0,
    };
    OBJECTS.with(|objs| {
        objs.borrow_mut().insert(current, attrs);
    });
    current
}

pub(crate) fn get_object_value(handle: u32) -> Option<Vec<u8>> {
    OBJECTS.with(|objs| {
        objs.borrow()
            .get(&handle)
            .and_then(|attrs| attrs.get(&CKA_VALUE).cloned())
    })
}

/// Return the raw SEC1 point bytes for an EC public key object.
/// PKCS#11 v3.2: EC public key material lives in CKA_EC_POINT, encoded as a
/// DER OCTET STRING wrapping the uncompressed SEC1 point (04 || x || y).
/// Some internal paths (C_GenerateKeyPair) store the raw SEC1 bytes directly
/// without the DER header. This function handles both formats.
pub fn get_ec_point_sec1(handle: u32) -> Option<Vec<u8>> {
    OBJECTS
        .with(|objs| {
            objs.borrow()
                .get(&handle)
                .and_then(|attrs| attrs.get(&CKA_EC_POINT).cloned())
        })
        .map(|ec_point| {
            // CKA_EC_POINT stores a DER OCTET STRING wrapping the SEC1 point
            // (PKCS#11 v3.2 §2.3.3). Strip the header to return the raw SEC1
            // bytes. Two encodings exist:
            //   - Short form  : 0x04 <len ≤ 127> <data>            (len = data.len())
            //   - Long form 1B: 0x04 0x81 <len> <data>             (P-521 path — data=133)
            // P-256 / P-384 / secp256k1 fit short form (65 / 97 / 65 ≤ 127).
            // P-521's 133-byte SEC1 point requires long form.
            if ec_point.len() > 2 && ec_point[0] == 0x04 {
                if ec_point[1] as usize == ec_point.len() - 2 {
                    // Short form
                    return ec_point[2..].to_vec();
                }
                if ec_point.len() > 3
                    && ec_point[1] == 0x81
                    && ec_point[2] as usize == ec_point.len() - 3
                {
                    // Long form, 1-byte length (covers all SEC1 points up to 255 B)
                    return ec_point[3..].to_vec();
                }
            }
            ec_point
        })
}

/// Return (modulus, public_exponent) bytes for an RSA public key object.
/// PKCS#11 v3.2: RSA public key material is in CKA_MODULUS + CKA_PUBLIC_EXPONENT.
/// CKA_VALUE is NOT defined for CKO_PUBLIC_KEY/CKK_RSA objects.
pub fn get_rsa_public_components(handle: u32) -> Option<(Vec<u8>, Vec<u8>)> {
    OBJECTS.with(|objs| {
        let store = objs.borrow();
        let attrs = store.get(&handle)?;
        let n = attrs.get(&CKA_MODULUS)?.clone();
        let e = attrs.get(&CKA_PUBLIC_EXPONENT)?.clone();
        Some((n, e))
    })
}

pub fn get_object_param_set(handle: u32) -> u32 {
    OBJECTS.with(|objs| {
        objs.borrow()
            .get(&handle)
            .and_then(|attrs| attrs.get(&CKA_PRIV_PARAM_SET))
            .map(|v| {
                if v.len() >= 4 {
                    u32::from_le_bytes([v[0], v[1], v[2], v[3]])
                } else {
                    0
                }
            })
            .unwrap_or(0)
    })
}

pub fn get_object_algo_family(handle: u32) -> u32 {
    OBJECTS.with(|objs| {
        objs.borrow()
            .get(&handle)
            .and_then(|attrs| attrs.get(&CKA_PRIV_ALGO_FAMILY))
            .map(|v| {
                if v.len() >= 4 {
                    u32::from_le_bytes([v[0], v[1], v[2], v[3]])
                } else {
                    0
                }
            })
            .unwrap_or(0)
    })
}

/// Read an arbitrary attribute from an existing object in the store.
pub(crate) fn get_object_attr_bytes(handle: u32, attr_type: u32) -> Option<Vec<u8>> {
    OBJECTS.with(|objs| {
        objs.borrow()
            .get(&handle)
            .and_then(|attrs| attrs.get(&attr_type).cloned())
    })
}

/// Read a u32 attribute (4-byte LE) from an existing object in the store.
pub(crate) fn get_object_attr_u32(handle: u32, attr_type: u32) -> Option<u32> {
    get_object_attr_bytes(handle, attr_type).and_then(|v| {
        if v.len() >= 4 {
            Some(u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
        } else {
            None
        }
    })
}

/// Read a u64 attribute (8-byte LE) from an existing object in the store.
pub(crate) fn get_object_attr_u64(handle: u32, attr_type: u32) -> Option<u64> {
    get_object_attr_bytes(handle, attr_type).and_then(|v| {
        if v.len() >= 8 {
            Some(u64::from_le_bytes([
                v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7],
            ]))
        } else {
            None
        }
    })
}

/// Overwrite an attribute on an existing object in the store. Returns true on success.
pub(crate) fn set_object_attr_bytes(handle: u32, attr_type: u32, value: Vec<u8>) -> bool {
    OBJECTS.with(|objs| {
        let mut store = objs.borrow_mut();
        if let Some(attrs) = store.get_mut(&handle) {
            attrs.insert(attr_type, value);
            true
        } else {
            false
        }
    })
}

/// Store parameter set as a 4-byte LE value in the attributes map.
pub fn store_param_set(attrs: &mut Attributes, ps: u32) {
    attrs.insert(CKA_PRIV_PARAM_SET, ps.to_le_bytes().to_vec());
}

/// Store algorithm family identifier in the attributes map.
pub fn store_algo_family(attrs: &mut Attributes, algo: u32) {
    attrs.insert(CKA_PRIV_ALGO_FAMILY, algo.to_le_bytes().to_vec());
}

/// Store a CK_BBOOL attribute (1 byte: 0x01 = true, 0x00 = false).
pub fn store_bool(attrs: &mut Attributes, attr_type: u32, value: bool) {
    attrs.insert(attr_type, vec![if value { 0x01 } else { 0x00 }]);
}

/// Store a CK_ULONG attribute at native CK_ULONG width (4 bytes on wasm32,
/// 8 bytes on 64-bit native — `size_of::<usize>()`, matching the C-ABI
/// marshaling). This keeps generated objects byte-compatible with caller
/// templates: a `CKA_CLASS`/`CKA_KEY_TYPE` find-filter supplied as a native
/// CK_ULONG compares byte-exact in `C_FindObjects`, and the value reads back at
/// native width through `C_GetAttributeValue`. All map readers take the low
/// 4 bytes (`from_le_bytes([v[0..3]])`), so widening is backward-compatible.
pub fn store_ulong(attrs: &mut Attributes, attr_type: u32, value: u32) {
    attrs.insert(attr_type, (value as usize).to_le_bytes().to_vec());
}

/// Read a CK_BBOOL attribute back from an attrs HashMap (returns false if absent).
pub fn read_bool_attr(attrs: &Attributes, attr_type: u32) -> bool {
    attrs
        .get(&attr_type)
        .map(|v| v.first().copied().unwrap_or(0) != 0)
        .unwrap_or(false)
}

/// Compute and store CKA_CHECK_VALUE (KCV) — PKCS#11 v3.2 §4.10.2.
/// - AES secret keys: first 3 bytes of AES-ECB(key, zero_block)
/// - Generic secret (HMAC): first 3 bytes of SHA-256(key_value)
/// - Asymmetric keys (public/private): first 3 bytes of SHA-256(CKA_VALUE)
pub fn compute_kcv(attrs: &mut Attributes) {
    use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
    use sha2::{Digest, Sha256};

    let class = attrs
        .get(&CKA_CLASS)
        .filter(|v| v.len() >= 4)
        .map(|v| u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
        .unwrap_or(0);

    let key_value = match attrs.get(&CKA_VALUE) {
        Some(v) if !v.is_empty() => v.clone(),
        _ => return,
    };

    let kcv: Vec<u8> = match class {
        CKO_SECRET_KEY => {
            let key_type = attrs
                .get(&CKA_KEY_TYPE)
                .filter(|v| v.len() >= 4)
                .map(|v| u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
                .unwrap_or(0);
            match key_type {
                CKK_AES => {
                    // AES-ECB encrypt a 16-byte zero block, take first 3 bytes
                    let zero_block = GenericArray::default();
                    match key_value.len() {
                        16 => {
                            let cipher = aes::Aes128::new(GenericArray::from_slice(&key_value));
                            let mut block = zero_block;
                            cipher.encrypt_block(&mut block);
                            block[..3].to_vec()
                        }
                        24 => {
                            let cipher = aes::Aes192::new(GenericArray::from_slice(&key_value));
                            let mut block = zero_block;
                            cipher.encrypt_block(&mut block);
                            block[..3].to_vec()
                        }
                        32 => {
                            let cipher = aes::Aes256::new(GenericArray::from_slice(&key_value));
                            let mut block = zero_block;
                            cipher.encrypt_block(&mut block);
                            block[..3].to_vec()
                        }
                        _ => return,
                    }
                }
                CKK_GENERIC_SECRET => {
                    // PKCS#11 v3.2 §6.8.2 — generic-secret KCV is the first
                    // 3 bytes of SHA-1(value) (NOT SHA-256).
                    let hash = sha1::Sha1::digest(&key_value);
                    hash[..3].to_vec()
                }
                _ => return,
            }
        }
        CKO_PUBLIC_KEY | CKO_PRIVATE_KEY | CKO_CERTIFICATE => {
            // Asymmetric keys and certificates: SHA-256 of CKA_VALUE (the
            // DER cert bytes, for CKO_CERTIFICATE) → first 3 bytes. §4.6
            // Table 19 doesn't mandate a specific algorithm for
            // certificates (token-defined) — reusing the same convention
            // already used for public/private keys.
            let hash = Sha256::digest(&key_value);
            hash[..3].to_vec()
        }
        _ => return,
    };
    attrs.insert(CKA_CHECK_VALUE, kcv);
}

/// Derive and store CKA_ALWAYS_SENSITIVE and CKA_NEVER_EXTRACTABLE from the
/// final post-absorb values of CKA_SENSITIVE and CKA_EXTRACTABLE.
/// Must be called AFTER absorb_template_attrs so caller overrides are reflected.
pub fn finalize_private_key_attrs(attrs: &mut Attributes) {
    let sensitive = read_bool_attr(attrs, CKA_SENSITIVE);
    let extractable = read_bool_attr(attrs, CKA_EXTRACTABLE);
    store_bool(attrs, CKA_ALWAYS_SENSITIVE, sensitive);
    store_bool(attrs, CKA_NEVER_EXTRACTABLE, !extractable);
}

// ── Memory Management ────────────────────────────────────────────────────────

// ── Allocation size tracker ───────────────────────────────────────────────────
// Maps each live allocation pointer (as u32) → original size so that
// _free can reconstruct the exact Layout required by std::alloc::dealloc.
lazy_static! {
    pub static ref ALLOC_SIZES: GlobalState<HashMap<u32, u32>> = GlobalState::new(HashMap::new());
}

#[wasm_bindgen(js_name = _malloc)]
pub fn malloc(size: usize) -> *mut u8 {
    if size == 0 {
        // Return a stable non-null sentinel; caller must not dereference it.
        // We use address 4 (within the WASM reserved zero-page, never allocated).
        return 4 as *mut u8;
    }
    unsafe {
        // Align 8: callers build CK_ATTRIBUTE/CK_MECHANISM arrays in this memory
        // and the engine reads them as u32 words — align-1 allocations can land
        // odd addresses and trip Rust's misaligned-pointer check.
        let layout = std::alloc::Layout::from_size_align_unchecked(size, 8);
        let ptr = std::alloc::alloc(layout);
        if !ptr.is_null() {
            ALLOC_SIZES.with(|m| m.borrow_mut().insert(ptr as u32, size as u32));
        }
        ptr
    }
}

#[wasm_bindgen(js_name = _free)]
pub fn free(ptr: *mut u8, _js_size: usize) {
    if ptr.is_null() {
        return;
    }
    let addr = ptr as u32;
    if addr <= 8 {
        // sentinel or reserved-page pointer — nothing to deallocate
        return;
    }
    if let Some(size) = ALLOC_SIZES.with(|m| m.borrow_mut().remove(&addr)) {
        if size > 0 {
            unsafe {
                // Must match the align used in `malloc` above.
                let layout = std::alloc::Layout::from_size_align_unchecked(size as usize, 8);
                std::alloc::dealloc(ptr, layout);
            }
        }
    }
    // If addr not in ALLOC_SIZES, it was never allocated through our _malloc
    // (e.g. a wasm-bindgen internal pointer). Silently ignore.
}
