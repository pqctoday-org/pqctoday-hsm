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
    /// §5.13 sign/verify-WITH-RECOVERY state (2026-07-25 — RSA_PKCS/RSA_X_509
    /// only, single-part-only per spec; `(mech_type, h_key)`, no ctx/det
    /// fields needed since RSA sign-recover takes no additional params).
    /// Kept separate from SIGN_STATE/VERIFY_STATE rather than folding a
    /// "recover mode" flag into their 4-tuple: the two operation families
    /// are mutually exclusive per session (checked at *Init time) but have
    /// different single-part-only lifecycle rules, and this avoids touching
    /// every existing SIGN_STATE/VERIFY_STATE call site's tuple shape.
    pub static ref SIGN_RECOVER_STATE: GlobalState<HashMap<u32, (u32, u32)>> = GlobalState::new(HashMap::new());
    pub static ref VERIFY_RECOVER_STATE: GlobalState<HashMap<u32, (u32, u32)>> = GlobalState::new(HashMap::new());
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
    // store_ulong, NOT u32::to_le_bytes. §5.7.7 makes C_FindObjects "an exact
    // byte-for-byte match with all attributes in the template", so a four-byte
    // CKA_CLASS cannot match the eight-byte CK_OBJECT_CLASS an LP64 caller
    // supplies — which is why the differential harness saw Rust publish ZERO
    // findable CKO_PROFILE objects while C++ published two. The object existed
    // the whole time and was simply unfindable at native width; C_InitToken
    // never destroyed it (CKA_DESTROYABLE=FALSE already protects it, and
    // destroy_destroyable_objects_on_slot honours that). Every other object in
    // this engine goes through store_ulong; this one was the outlier.
    store_ulong(&mut attrs, CKA_CLASS, CKO_PROFILE);
    store_ulong(&mut attrs, CKA_PROFILE_ID, CKP_BASELINE_PROVIDER);
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
    /// W7 (2026-08-13) — `CK_CHACHA20_PARAMS.pBlockCounter`, the keystream
    /// block the operation STARTS at. §6.20: the counter "is exposed here"
    /// because "in certain settings (e.g. disk encryption) it is necessary to
    /// address these blocks in random order". The engine previously rejected
    /// any non-zero value, which defeated the field's entire purpose and made
    /// random-access ChaCha20 unusable. Zero for every other mechanism.
    pub block_counter: u64,
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
        // CKA_VERIFY_RECOVER / CKA_SIGN_RECOVER are COMMON key attributes —
        // Table 27 (public) and Table 28 (private) — so every public key
        // possesses the first and every private key the second, whatever the
        // token can actually do with them. This engine materialised neither,
        // and answered CKR_ATTRIBUTE_TYPE_INVALID for both on every key.
        //
        // Recorded backwards. The harness entry blamed C++ for "still
        // asserting" them after the recovery dispatch path was removed
        // (DEFECT-CPP-RECOVERY-ATTRIBUTES-STILL-ASSERTED, 68 observations).
        // The specification's own tables say otherwise: the attributes are
        // standard and their absence is the defect, so Rust was the wrong
        // side. Plan item C3 concerned the MECHANISM-INFO recovery FLAGS,
        // which are a different question and correctly stayed unadvertised.
        //
        // FALSE, because this engine implements no recovery mechanism —
        // materialising them as TRUE would be the advertise-without-dispatch
        // fault C3 exists to prevent. A caller's template still wins.
        if class == CKO_PUBLIC_KEY && !attrs.contains_key(&CKA_VERIFY_RECOVER) {
            store_bool(attrs, CKA_VERIFY_RECOVER, false);
        }
        if class == CKO_PRIVATE_KEY && !attrs.contains_key(&CKA_SIGN_RECOVER) {
            store_bool(attrs, CKA_SIGN_RECOVER, false);
        }
        // CKA_ALWAYS_SENSITIVE / CKA_NEVER_EXTRACTABLE — §4.10's history
        // attributes, defined for private and secret keys. Most generation
        // arms set them by hand and the XMSS and XMSS^MT arms did not, so
        // §6.66.4's "CKA_SENSITIVE MUST be true and CKA_EXTRACTABLE MUST be
        // false for this key" could not be checked on exactly the key type it
        // is written about (DEFECT-XMSS-PUBLIC-KEY-ATTRIBUTE-SPREAD).
        //
        // Derived rather than hard-coded, and only as a DEFAULT: every path
        // that knows better — C_CreateObject, C_UnwrapKey, C_DeriveKey — sets
        // both to false explicitly before the object is allocated, and
        // `contains_key` leaves those alone. The derivation is the definition:
        // a key that was generated in-token (CKA_LOCAL) has been whatever it
        // is now for its whole life.
        if class == CKO_PRIVATE_KEY || class == CKO_SECRET_KEY {
            let local = read_bool_attr(attrs, CKA_LOCAL);
            if !attrs.contains_key(&CKA_ALWAYS_SENSITIVE) {
                let v = local && read_bool_attr(attrs, CKA_SENSITIVE);
                store_bool(attrs, CKA_ALWAYS_SENSITIVE, v);
            }
            if !attrs.contains_key(&CKA_NEVER_EXTRACTABLE) {
                let v = local && !read_bool_attr(attrs, CKA_EXTRACTABLE);
                store_bool(attrs, CKA_NEVER_EXTRACTABLE, v);
            }
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

/// S8 (2026-08-13) — the predicate behind private-object access. §2.4: "Only
/// the normal user is allowed access to private objects." The Usage Guide's
/// R/W SO Functions state is explicit: "The application has read/write access
/// only to public objects on the token, **not to private objects**", and its
/// access matrix leaves the SO column blank for both private session and
/// private token objects.
///
/// This was `session_logged_in`, i.e. "logged in as EITHER role" — so an SO
/// session could read, find and use every private object on the token.
pub fn token_user_logged_in(slot_id: u32) -> bool {
    TOKEN_STORE.with(|ts| {
        ts.borrow()
            .get(&slot_id)
            .map(|t| t.login_state == LoginState::User)
            .unwrap_or(false)
    })
}

/// [`token_user_logged_in`] for a session handle.
pub fn session_user_logged_in(h_session: u32) -> bool {
    match session_slot(h_session) {
        Some(slot) => token_user_logged_in(slot),
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
    // S8 — the NORMAL USER role, not merely "logged in".
    session_user_logged_in(h_session)
}

// ─────────────────────────────────────────────────────────────────────────
// Isolation gate for `native::*` (rust-hsm-perf-bench-scenario-plan-07182026.md
// Part F, added 2026-07-18). `ffi::C_*` has enforced `can_access_object` at
// 8 call sites all along; `native::*` — the surface KMIP uses exclusively —
// never did. These are ADDITIVE: `can_access_object` above is untouched
// (zero risk to existing ffi behavior), and every native::* by-handle
// function is being migrated onto the primitives below.
//
// Design note: `can_access_object(h_session, attrs)` independently locks
// SESSIONS (via `session_slot`) and TOKEN_STORE (via `session_logged_in`)
// on every call. Native crypto ops call several by-handle accessors per
// operation (e.g. sign: usage check, mechanism check, value fetch, param
// fetch — 4 separate OBJECTS locks today), so re-deriving slot/login state
// from scratch inside each one would multiply SESSIONS/TOKEN_STORE lock
// traffic too. Instead: resolve the session's slot + login state ONCE
// per operation (`resolve_session_access`, one SESSIONS lock + one
// TOKEN_STORE lock), then fold the access check into the SAME OBJECTS
// borrow every accessor already needs (`with_object_checked[_mut]`,
// `take_object_checked`) — collapsing native sign's 4 OBJECTS locks to 1
// while adding the gate, not trading contention for correctness.
//
// Lock ordering (load-bearing — audited 2026-07-18 across every native/*
// call site that uses these primitives, see F5 in the plan): SESSIONS
// and/or TOKEN_STORE are always acquired and FULLY RELEASED (not nested)
// before OBJECTS is acquired — `resolve_session_access` runs to
// completion and returns an owned `SessionAccess` before
// `with_object_checked` et al. ever touch OBJECTS. This is stricter than
// `ffi.rs`'s existing pattern (e.g. `C_GetObjectSize`), which nests a
// `can_access_object` call — and its own SESSIONS/TOKEN_STORE locks —
// INSIDE an open OBJECTS borrow. That nested pattern is untouched and
// presumed safe (no reverse-order site was found), but new code should
// prefer this module's sequential resolve-then-access shape.

/// Pre-resolved session identity for the isolation gate — computed ONCE
/// per operation so the OBJECTS-locked accessors below never need to
/// touch SESSIONS or TOKEN_STORE.
#[derive(Clone, Copy)]
pub struct SessionAccess {
    pub slot: u32,
    /// S8 — true only for the NORMAL USER role. Named `logged_in` for the
    /// ~40 existing call sites; the SO role no longer sets it, mirroring
    /// `can_access_object`.
    pub logged_in: bool,
}

/// Resolve a session handle to the slot/login state the isolation gate
/// needs. `Err(CKR_SESSION_HANDLE_INVALID)` for an unknown handle — this
/// is new, correct validation for `native::*` callers (which today mostly
/// ignore their session parameter entirely and never reject a bogus
/// handle); it does not change any `ffi::*` behavior, since `ffi::*`
/// does not call this function.
pub fn resolve_session_access(h_session: u32) -> Result<SessionAccess, u32> {
    let slot = session_slot(h_session).ok_or(CKR_SESSION_HANDLE_INVALID)?;
    // S8 — kept in exact lockstep with can_access_object.
    let logged_in = session_user_logged_in(h_session);
    Ok(SessionAccess { slot, logged_in })
}

/// Same predicate as [`can_access_object`], evaluated against a
/// pre-resolved [`SessionAccess`] instead of re-locking SESSIONS/TOKEN_STORE.
/// Kept in exact lockstep with `can_access_object`'s logic.
pub fn can_access_object_with(access: &SessionAccess, attrs: &Attributes) -> bool {
    if object_slot_of(attrs) != access.slot {
        return false;
    }
    if !read_bool_attr(attrs, CKA_PRIVATE) {
        return true;
    }
    access.logged_in
}

/// Fetch `handle`'s attributes, apply the isolation gate, and run `f` over
/// the borrowed attributes — all under ONE `OBJECTS` lock acquisition.
/// `Err(CKR_OBJECT_HANDLE_INVALID)` uniformly for an unknown handle OR a
/// cross-slot / not-logged-in-for-private object (PKCS#11 v3.2 §2.4/§4.4 —
/// no existence oracle, same choke point `ffi::*` already uses).
pub fn with_object_checked<R>(
    access: &SessionAccess,
    handle: u32,
    f: impl FnOnce(&Attributes) -> R,
) -> Result<R, u32> {
    OBJECTS.with(|o| {
        let store = o.borrow();
        let attrs = store.get(&handle).ok_or(CKR_OBJECT_HANDLE_INVALID)?;
        if !can_access_object_with(access, attrs) {
            return Err(CKR_OBJECT_HANDLE_INVALID);
        }
        Ok(f(attrs))
    })
}

/// Mutable counterpart of [`with_object_checked`] — for in-place attribute
/// writes (e.g. HSS/XMSS stateful-key state advancement) under one
/// `OBJECTS` write-lock acquisition.
pub fn with_object_checked_mut<R>(
    access: &SessionAccess,
    handle: u32,
    f: impl FnOnce(&mut Attributes) -> R,
) -> Result<R, u32> {
    OBJECTS.with(|o| {
        let mut store = o.borrow_mut();
        let attrs = store.get_mut(&handle).ok_or(CKR_OBJECT_HANDLE_INVALID)?;
        if !can_access_object_with(access, attrs) {
            return Err(CKR_OBJECT_HANDLE_INVALID);
        }
        Ok(f(attrs))
    })
}

/// Gate-checked object removal (for `destroy_object`) — verifies access
/// BEFORE removing, under one `OBJECTS` write-lock acquisition, so a
/// failed check never mutates the map.
pub fn take_object_checked(access: &SessionAccess, handle: u32) -> Result<Attributes, u32> {
    OBJECTS.with(|o| {
        let mut store = o.borrow_mut();
        let attrs = store.get(&handle).ok_or(CKR_OBJECT_HANDLE_INVALID)?;
        if !can_access_object_with(access, attrs) {
            return Err(CKR_OBJECT_HANDLE_INVALID);
        }
        Ok(store.remove(&handle).expect("presence just confirmed under the same lock"))
    })
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
pub fn check_mechanism_allowed_from(attrs: &Attributes, mech_type: u32) -> Result<(), u32> {
    match attrs.get(&CKA_ALLOWED_MECHANISMS) {
        None => Ok(()),
        Some(bytes) => {
            let is_allowed = parse_allowed_mechanisms(bytes).contains(&mech_type);
            if is_allowed {
                Ok(())
            } else {
                Err(CKR_MECHANISM_INVALID)
            }
        }
    }
}

/// S12 (2026-08-13) — fetch a key's `CKA_VALUE` under the isolation gate AND
/// enforce `CKA_ALLOWED_MECHANISMS` for `mech_type`, both inside the ONE
/// `OBJECTS` borrow the caller already needs.
///
/// The lock was on the PKCS#11 door only: the mechanism check was called from
/// `native/sign.rs` and `native/encrypt.rs` but from NO site in
/// `native/derive.rs`, `native/agree.rs`, `native/hybrid.rs` or
/// `native/split_key.rs` — the surface KMIP uses exclusively
/// (`kmip/src/ops/derive_key.rs` calls `agree::ecdh_agree` directly). A key
/// carrying a mechanism restriction was therefore enforced over PKCS#11 and
/// unenforced over KMIP for derive, agreement, hybrid and split-key work.
/// Not a conformance violation (a native API is outside the Standard's
/// scope) — a product security gap with S9's exact consequence.
///
/// `not_found` is the caller's own vocabulary for a missing/inaccessible
/// handle, preserved so no existing error code changes.
pub fn checked_value_for_mech(
    access: &SessionAccess,
    handle: u32,
    mech_type: u32,
    not_found: u32,
) -> Result<Vec<u8>, u32> {
    let (allowed, value) = with_object_checked(access, handle, |attrs| {
        (
            check_mechanism_allowed_from(attrs, mech_type),
            get_object_value_from(attrs),
        )
    })
    .map_err(|_| not_found)?;
    allowed?;
    value.ok_or(not_found)
}

/// Attribute ids at or above this are the engine's OWN state channel: never
/// absorbed from a client template, never client-writable, and not part of
/// any published surface. Distinct from the vendor range (0x8000_0000), whose
/// mutability the spec deliberately leaves out of scope.
pub const ENGINE_PRIVATE_ATTR_BASE: u32 = 0xFFFF_0000;

/// PKCS#11 v3.2 §4.8 Table 13 — CKA_ALLOWED_MECHANISMS is "a pointer to a
/// CK_MECHANISM_TYPE array", and "the number of mechanisms in the array is
/// the ulValueLen component of the attribute divided by the size of
/// CK_MECHANISM_TYPE". CK_MECHANISM_TYPE is CK_ULONG, whose width is the
/// EXPORTED ABI's — 4 bytes on wasm32 (ILP32), 8 on a 64-bit native build.
///
/// S9 (2026-08-13): this was hardcoded to 4. On a 64-bit build an 8-byte
/// element list parsed as `{mech, 0, mech, 0, …}` — and mechanism 0 is
/// CKM_RSA_PKCS_KEY_PAIR_GEN, so every mechanism-restricted key silently
/// also permitted RSA key-pair generation. A fail-open parse of a security
/// control. wasm32 was correct by accident of its ABI, which is why the
/// browser playground never showed it. One constant now feeds the parser,
/// the length-shape check in `attr_mutation_allowed`, and `ffi`'s
/// creation-time validation, so the three cannot drift.
/// (`usize` is the exported CK_ULONG on every target this crate builds for —
/// `c_ulong` on the native `ck_abi` surface and 4 bytes on wasm32 — and is
/// already the width `store_ulong` marshals CK_ULONG attributes at.)
pub const MECHANISM_TYPE_SIZE: usize = std::mem::size_of::<usize>();

/// Decode a packed CK_MECHANISM_TYPE array at the exported ABI's element
/// width. A trailing partial element is IGNORED here; callers that can
/// reject it (template validation, `attr_mutation_allowed`) do so with
/// CKR_ATTRIBUTE_VALUE_INVALID before a value ever reaches this function.
pub fn parse_allowed_mechanisms(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks_exact(MECHANISM_TYPE_SIZE)
        // Only the low 32 bits are meaningful: every CKM_* codepoint this
        // engine knows fits in u32, and the C ABI zero-extends on the way in.
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

pub fn check_mechanism_allowed(h_key: u32, mech_type: u32) -> Result<(), u32> {
    match OBJECTS.with(|o| o.borrow().get(&h_key).map(|attrs| check_mechanism_allowed_from(attrs, mech_type))) {
        Some(result) => result,
        None => Ok(()), // unknown handle: preserve prior behavior (caller's later fetch fails closed)
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
    // S4 (2026-08-13) — the ENGINE-PRIVATE range is the engine's own state
    // channel and is never client-writable. Before this, the whole
    // ≥0x8000_0000 space (which includes 0xFFFF_00xx) bypassed the policy,
    // so a client could write the HBS leaf index / stateful key blob
    // directly and rewind a one-time-signature key. Reads are unaffected.
    if attr_type >= ENGINE_PRIVATE_ATTR_BASE {
        return Err(CKR_ATTRIBUTE_READ_ONLY);
    }
    // Genuine vendor attributes (0x8000_0000..0xFFFF_0000) stay outside
    // Cryptoki's mutability rules, exactly as the spec says they may.
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
        // S4 — §6.65/§6.66: the HSS remaining-signature counter is engine
        // truth about a one-time-signature key's exhaustion. It carries no
        // modify-after-creation footnote, and a client that could raise it
        // would be inviting the engine to reuse an exhausted key.
        CKA_HSS_KEYS_REMAINING,
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
    // S9 (2026-08-13) — the element width is sizeof(CK_MECHANISM_TYPE) on the
    // EXPORTED ABI, not a hardcoded 4. See MECHANISM_TYPE_SIZE.
    if attr_type == CKA_ALLOWED_MECHANISMS && value.len() % MECHANISM_TYPE_SIZE != 0 {
        return Err(CKR_ATTRIBUTE_VALUE_INVALID);
    }
    // One-way transitions. CKA_SENSITIVE FALSE→TRUE and CKA_EXTRACTABLE
    // TRUE→FALSE were already here; S3 and S10 add the two that were missing
    // and whose absence was directly exploitable:
    //   * CKA_WRAP_WITH_TRUSTED (footnote 11 — "cannot be changed once set to
    //     CK_TRUE") — clearing it lets the key be wrapped under an UNtrusted
    //     wrapping key and exfiltrated;
    //   * CKA_COPYABLE ("Can't be set to TRUE once it is set to FALSE") —
    //     re-enabling it lets §4.1.3's copy template re-open sensitivity,
    //     privacy and modifiability on the copy, laundering the original's
    //     restrictions.
    if attr_type == CKA_SENSITIVE
        || attr_type == CKA_EXTRACTABLE
        || attr_type == CKA_WRAP_WITH_TRUSTED
        || attr_type == CKA_COPYABLE
    {
        let new_val = value.first().copied().unwrap_or(0) != 0;
        // CKA_COPYABLE "Defaults to CK_TRUE" — an absent attribute must read
        // as TRUE here, or the very first FALSE→? comparison would be made
        // against a phantom FALSE. (apply_object_defaults stamps it on every
        // allocate path; this covers hand-built records.)
        let cur_val = if attr_type == CKA_COPYABLE {
            attrs
                .get(&attr_type)
                .map(|v| v.first().copied().unwrap_or(0) != 0)
                .unwrap_or(true)
        } else {
            read_bool_attr(attrs, attr_type)
        };
        let legal = match attr_type {
            // FALSE→TRUE only
            CKA_SENSITIVE | CKA_WRAP_WITH_TRUSTED => !cur_val || new_val,
            // TRUE→FALSE only
            _ => cur_val || !new_val,
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

/// PKCS#11 v3.2 §5.7.7 — the object-matching rule: "The matching criterion is
/// an exact byte-for-byte match with all attributes in the template."
/// An absent attribute on the candidate never matches (the §5.7.7 leniency for
/// nonexistent attributes yields a search matching NO objects).
///
/// Factored out of `C_FindObjectsInit` (2026-08-13, S2) because §5.18.3 says
/// the wrap-template comparison is done "according to the C_FindObject rules
/// of attribute matching" — a divergence between find-matching and
/// wrap-matching would itself be a defect, so both call this.
pub fn attrs_match_template(candidate: &Attributes, template: &[(u32, Vec<u8>)]) -> bool {
    template
        .iter()
        .all(|(ty, val)| candidate.get(ty) == Some(val))
}

/// §5.18.3 — compare a wrapping/unwrapping key's `CKA_WRAP_TEMPLATE` /
/// `CKA_UNWRAP_TEMPLATE` against a candidate attribute set. An ABSENT
/// template means "any" (`true`); an UNPARSEABLE stored template fails
/// closed, since the alternative is enforcing nothing.
pub fn key_template_permits(
    key_attrs: &Attributes,
    template_attr: u32,
    candidate: &Attributes,
) -> bool {
    match key_attrs.get(&template_attr) {
        None => true,
        Some(blob) => match crate::crypto::handlers::parse_flat_attr_array(blob) {
            Some(entries) => attrs_match_template(candidate, &entries),
            None => false,
        },
    }
}

/// S7 (2026-08-13) — §5.7.1: "Only session objects can be created during a
/// read-only session", §5.7.3 the same for destruction, and the Usage Guide's
/// access matrix: "a 'R/O User Functions' session cannot create or delete a
/// token object."
///
/// The gate existed inline at `C_CreateObject`, `C_SetAttributeValue`,
/// `C_InitPIN` and `C_SetPIN` only — `C_GenerateKey`, `C_GenerateKeyPair`,
/// `C_UnwrapKey`, `C_DeriveKey` and `C_DestroyObject` had none, so a R/O
/// session could mint and delete token objects. Five inline copies is how the
/// first four drifted from the other five; this is the single helper both
/// sides now call.
///
/// `wants_token` is the effective CKA_TOKEN of the object being created or
/// destroyed. Returns `Err(CKR_SESSION_READ_ONLY)` when a token object is
/// requested from a session that is not read/write.
pub fn check_rw_for_token_object(h_session: u32, wants_token: bool) -> Result<(), u32> {
    if wants_token && !session_is_rw(h_session) {
        return Err(CKR_SESSION_READ_ONLY);
    }
    Ok(())
}

/// S1 — §5.5.7: "When a token is initialized, all objects that can be
/// destroyed are destroyed." Scoped to one slot's token; CKA_DESTROYABLE=
/// FALSE records (the built-in `CKO_PROFILE`) survive, which is what "that
/// can be destroyed" means. CKA_VALUE is zeroized on the way out, matching
/// `C_DestroyObject`.
pub fn destroy_destroyable_objects_on_slot(slot_id: u32) {
    use zeroize::Zeroize;
    OBJECTS.with(|objs| {
        let mut store = objs.borrow_mut();
        let doomed: Vec<u32> = store
            .iter()
            .filter(|(_, attrs)| {
                object_slot_of(attrs) == slot_id
                    && attrs
                        .get(&CKA_DESTROYABLE)
                        .map(|v| v.first().copied().unwrap_or(0) != 0)
                        .unwrap_or(true)
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

/// S6 — §5.6.10: "When C_Logout successfully executes, any of the
/// application's handles to private objects become invalid (even if a user is
/// later logged back into the token, those handles remain invalid). In
/// addition, all private session objects from sessions belonging to the
/// application are destroyed."
///
/// Implementation: private SESSION objects on the slot are destroyed; private
/// TOKEN objects are RE-KEYED under a freshly minted handle. Re-keying is
/// what makes the old handle permanently invalid — including after a later
/// successful login — while keeping the object itself alive and findable, as
/// the spec requires (only the *session* objects die). Anything that merely
/// stamped a generation on the object would have made the surviving token
/// object invisible forever, which the spec does not say.
pub fn invalidate_private_handles_on_slot(slot_id: u32) {
    use zeroize::Zeroize;
    OBJECTS.with(|objs| {
        let mut store = objs.borrow_mut();
        let private_here: Vec<u32> = store
            .iter()
            .filter(|(_, attrs)| {
                object_slot_of(attrs) == slot_id && read_bool_attr(attrs, CKA_PRIVATE)
            })
            .map(|(h, _)| *h)
            .collect();
        for h in private_here {
            let Some(mut attrs) = store.remove(&h) else {
                continue;
            };
            if read_bool_attr(&attrs, CKA_TOKEN) {
                // Survives, under a handle the application has never seen.
                // NEXT_HANDLE is monotonic, so the new handle can never
                // collide with the retired one.
                let new_handle = match NEXT_HANDLE.fetch_update(
                    std::sync::atomic::Ordering::Relaxed,
                    std::sync::atomic::Ordering::Relaxed,
                    |v| if v == u32::MAX { None } else { Some(v + 1) },
                ) {
                    Ok(prev) => prev,
                    // Handle space exhausted: dropping the object would lose
                    // token state, so keep the old handle rather than
                    // silently destroying a token object.
                    Err(_) => h,
                };
                store.insert(new_handle, attrs);
            } else {
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

// ── `_from` pure variants (operate on an already-borrowed `&Attributes`,
// take no lock) — added alongside the isolation gate (Part F) so a
// gated `native::*` call can fetch several attributes inside the ONE
// `OBJECTS` borrow `with_object_checked` already holds, instead of each
// handle-taking accessor below re-locking OBJECTS on its own. Every
// handle-taking accessor is now a thin `OBJECTS.with(...)` wrapper over
// its `_from` twin — same signature, same behavior, zero call-site churn
// for the ~50+ existing (ungated) callers across the crate. ──────────────

pub fn get_object_value_from(attrs: &Attributes) -> Option<Vec<u8>> {
    attrs.get(&CKA_VALUE).cloned()
}

/// PKCS#11 v3.2 §2.3.3 — strip the DER OCTET STRING header some CKA_EC_POINT
/// values carry around the raw SEC1 point. See [`get_ec_point_sec1_from`].
fn strip_ec_point_der(ec_point: Vec<u8>) -> Vec<u8> {
    // Two encodings exist:
    //   - Short form  : 0x04 <len ≤ 127> <data>            (len = data.len())
    //   - Long form 1B: 0x04 0x81 <len> <data>             (P-521 path — data=133)
    // P-256 / P-384 / secp256k1 fit short form (65 / 97 / 65 ≤ 127).
    // P-521's 133-byte SEC1 point requires long form.
    if ec_point.len() > 2 && ec_point[0] == 0x04 {
        if ec_point[1] as usize == ec_point.len() - 2 {
            return ec_point[2..].to_vec();
        }
        if ec_point.len() > 3 && ec_point[1] == 0x81 && ec_point[2] as usize == ec_point.len() - 3
        {
            return ec_point[3..].to_vec();
        }
    }
    ec_point
}

/// E4 (2026-08-13) — the raw public-key MATERIAL of any key object,
/// whichever attribute the object's type puts it in.
///
/// Edwards and Montgomery PUBLIC keys no longer carry `CKA_VALUE` (the spec
/// defines none for them; their material is the bare little-endian bytes in
/// `CKA_EC_POINT`), so every internal reader that used to reach for
/// `CKA_VALUE` unconditionally must come through here or it will see an
/// absent attribute on exactly those keys. `CKA_VALUE` still wins where it
/// exists — private keys, secret keys, RSA, the PQC families — so this is a
/// strict superset of the old behaviour.
pub fn get_key_material_from(attrs: &Attributes) -> Option<Vec<u8>> {
    attrs
        .get(&CKA_VALUE)
        .cloned()
        .or_else(|| get_ec_point_sec1_from(attrs))
}

/// [`get_key_material_from`] by handle.
pub fn get_key_material(handle: u32) -> Option<Vec<u8>> {
    OBJECTS.with(|objs| objs.borrow().get(&handle).and_then(get_key_material_from))
}

/// Return the raw SEC1 point bytes for an EC public key object. Some
/// internal paths (C_GenerateKeyPair) store the raw SEC1 bytes directly
/// without the DER header — [`strip_ec_point_der`] handles both formats.
pub fn get_ec_point_sec1_from(attrs: &Attributes) -> Option<Vec<u8>> {
    attrs.get(&CKA_EC_POINT).cloned().map(strip_ec_point_der)
}

/// Return (modulus, public_exponent) bytes for an RSA public key object.
pub fn get_rsa_public_components_from(attrs: &Attributes) -> Option<(Vec<u8>, Vec<u8>)> {
    let n = attrs.get(&CKA_MODULUS)?.clone();
    let e = attrs.get(&CKA_PUBLIC_EXPONENT)?.clone();
    Some((n, e))
}

pub fn get_object_param_set_from(attrs: &Attributes) -> u32 {
    attrs
        .get(&CKA_PRIV_PARAM_SET)
        .map(|v| if v.len() >= 4 { u32::from_le_bytes([v[0], v[1], v[2], v[3]]) } else { 0 })
        .unwrap_or(0)
}

pub fn get_object_attr_bytes_from(attrs: &Attributes, attr_type: u32) -> Option<Vec<u8>> {
    attrs.get(&attr_type).cloned()
}

pub fn get_object_attr_u32_from(attrs: &Attributes, attr_type: u32) -> Option<u32> {
    get_object_attr_bytes_from(attrs, attr_type)
        .and_then(|v| if v.len() >= 4 { Some(u32::from_le_bytes([v[0], v[1], v[2], v[3]])) } else { None })
}

pub fn get_object_attr_u64_from(attrs: &Attributes, attr_type: u32) -> Option<u64> {
    get_object_attr_bytes_from(attrs, attr_type).and_then(|v| {
        if v.len() >= 8 {
            Some(u64::from_le_bytes([v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]]))
        } else {
            None
        }
    })
}

pub(crate) fn get_object_value(handle: u32) -> Option<Vec<u8>> {
    OBJECTS.with(|objs| objs.borrow().get(&handle).and_then(get_object_value_from))
}

/// Return the raw SEC1 point bytes for an EC public key object.
/// PKCS#11 v3.2: EC public key material lives in CKA_EC_POINT, encoded as a
/// DER OCTET STRING wrapping the uncompressed SEC1 point (04 || x || y).
/// Some internal paths (C_GenerateKeyPair) store the raw SEC1 bytes directly
/// without the DER header. This function handles both formats.
pub fn get_ec_point_sec1(handle: u32) -> Option<Vec<u8>> {
    OBJECTS.with(|objs| objs.borrow().get(&handle).and_then(get_ec_point_sec1_from))
}

/// Return (modulus, public_exponent) bytes for an RSA public key object.
/// PKCS#11 v3.2: RSA public key material is in CKA_MODULUS + CKA_PUBLIC_EXPONENT.
/// CKA_VALUE is NOT defined for CKO_PUBLIC_KEY/CKK_RSA objects.
pub fn get_rsa_public_components(handle: u32) -> Option<(Vec<u8>, Vec<u8>)> {
    OBJECTS.with(|objs| objs.borrow().get(&handle).and_then(get_rsa_public_components_from))
}

pub fn get_object_param_set(handle: u32) -> u32 {
    OBJECTS.with(|objs| objs.borrow().get(&handle).map(get_object_param_set_from).unwrap_or(0))
}

pub fn get_object_algo_family(handle: u32) -> u32 {
    OBJECTS.with(|objs| {
        objs.borrow()
            .get(&handle)
            .and_then(|attrs| get_object_attr_u32_from(attrs, CKA_PRIV_ALGO_FAMILY))
            .unwrap_or(0)
    })
}

/// Read an arbitrary attribute from an existing object in the store.
pub(crate) fn get_object_attr_bytes(handle: u32, attr_type: u32) -> Option<Vec<u8>> {
    OBJECTS.with(|objs| objs.borrow().get(&handle).and_then(|attrs| get_object_attr_bytes_from(attrs, attr_type)))
}

/// Read a u32 attribute (4-byte LE) from an existing object in the store.
pub(crate) fn get_object_attr_u32(handle: u32, attr_type: u32) -> Option<u32> {
    OBJECTS.with(|objs| objs.borrow().get(&handle).and_then(|attrs| get_object_attr_u32_from(attrs, attr_type)))
}

/// Read a u64 attribute (8-byte LE) from an existing object in the store.
pub(crate) fn get_object_attr_u64(handle: u32, attr_type: u32) -> Option<u64> {
    OBJECTS.with(|objs| objs.borrow().get(&handle).and_then(|attrs| get_object_attr_u64_from(attrs, attr_type)))
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
///
/// **`CK_UNAVAILABLE_INFORMATION` is widened, not zero-extended.** §3.1 makes
/// it `(~0UL)`, so on LP64 it is eight bytes of `0xFF`. The engine's internal
/// value is the 32-bit sentinel `0xFFFF_FFFF`, and `(0xFFFF_FFFF as
/// usize).to_le_bytes()` is `ff ff ff ff 00 00 00 00` — mechanism 4294967295,
/// which is not `CK_UNAVAILABLE_INFORMATION` and which a caller comparing
/// against the macro will never match. That is what the differential harness
/// recorded as DEFECT-RUST-KEY-GEN-MECHANISM-NARROWED on four objects
/// (imported, derived, unwrapped and unwrapped-private keys), against C++'s
/// `ffffffffffffffff`. `ck_abi::widen` already applies exactly this rule to
/// scalar out-parameters; applying it here makes one rule cover both surfaces.
/// Readers are unaffected — they take the low four bytes, which round-trip.
pub fn store_ulong(attrs: &mut Attributes, attr_type: u32, value: u32) {
    let native = if value == crate::constants::CK_UNAVAILABLE_INFORMATION {
        usize::MAX
    } else {
        value as usize
    };
    attrs.insert(attr_type, native.to_le_bytes().to_vec());
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
        // CERTIFICATES ONLY — public and private keys are NOT in this arm.
        //
        // §4.11 introduces the attribute as "the key check value (KCV)
        // attribute for SYMMETRIC KEY OBJECTS", and the tables agree: it is
        // listed in the Common Secret Key Attributes table and in §4.6's
        // certificate table (Table 19), and in NEITHER the common public-key
        // (Table 27) nor the common private-key (Table 28) table. A public key
        // has nothing to check, and a private key's checksum is not something
        // the specification defines.
        //
        // This arm used to include both, which is how an EC private key
        // recovered through C_UnwrapKey came back carrying a three-byte
        // checksum (DEFECT-CHECK-VALUE-ON-UNWRAPPED-PRIVATE-KEY). §4.6 does
        // not mandate an algorithm for certificates, so the SHA-256 convention
        // stays for that class.
        CKO_CERTIFICATE => {
            let hash = Sha256::digest(&key_value);
            hash[..3].to_vec()
        }
        _ => return,
    };
    attrs.insert(CKA_CHECK_VALUE, kcv);
}

/// S11 (2026-08-13) — PKCS#11 v3.2 §4.11, the complete CKA_CHECK_VALUE
/// contract for a newly created key:
///
/// * "regardless of how the key object is created or derived, the value of
///   the attribute is always supplied. It SHALL be supplied even if the
///   encryption operation for the key is forbidden" — so the engine computes
///   it by default;
/// * "If a value is supplied in the application template (allowed but never
///   necessary) then, if supported, it MUST match what the library calculates
///   it to be or the library returns a CKR_ATTRIBUTE_VALUE_INVALID" — so a
///   non-empty caller value is COMPARED, never dropped and never rejected out
///   of hand;
/// * "The generation of the KCV may be prevented by the application supplying
///   the attribute in the template as a no-value (0 length) entry."
///
/// This engine supports the attribute, so §4.11's "if the library does not
/// support the attribute then it should ignore it" escape is unavailable.
/// Both KEM directions previously computed nothing at all and dropped the
/// caller's entry as server-managed, which made the mandated comparison
/// unreachable AND closed off the suppression channel.
///
/// `caller` is the template entry: `None` absent, `Some(&[])` the zero-length
/// suppression form, `Some(v)` a value to check.
pub fn apply_check_value_policy(attrs: &mut Attributes, caller: Option<&[u8]>) -> Result<(), u32> {
    match caller {
        Some(v) if v.is_empty() => {
            attrs.remove(&CKA_CHECK_VALUE);
            Ok(())
        }
        Some(v) => {
            compute_kcv(attrs);
            match attrs.get(&CKA_CHECK_VALUE) {
                Some(computed) if computed.as_slice() == v => Ok(()),
                Some(_) => Err(CKR_ATTRIBUTE_VALUE_INVALID),
                // No KCV convention for this class/key type: nothing to
                // contradict, so the caller's value is simply not honoured.
                None => Ok(()),
            }
        }
        None => {
            compute_kcv(attrs);
            Ok(())
        }
    }
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
