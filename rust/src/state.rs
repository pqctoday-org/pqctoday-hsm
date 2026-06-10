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

lazy_static! {
    pub static ref OBJECTS: GlobalState<HashMap<u32, Attributes>> = GlobalState::new(HashMap::new());
    pub static ref NEXT_HANDLE: GlobalState<u32> = GlobalState::new(100);
    pub static ref NEXT_SESSION_HANDLE: GlobalState<u32> = GlobalState::new(1);
    pub static ref SIGN_STATE: GlobalState<HashMap<u32, (u32, u32, Vec<u8>, bool)>> = GlobalState::new(HashMap::new());
    pub static ref VERIFY_STATE: GlobalState<HashMap<u32, (u32, u32, Vec<u8>, bool)>> = GlobalState::new(HashMap::new());
    pub static ref VERIFY_SIG_STATE: GlobalState<HashMap<u32, VerifySigCtx>> = GlobalState::new(HashMap::new());
    pub static ref ENCRYPT_STATE: GlobalState<HashMap<u32, EncryptCtx>> = GlobalState::new(HashMap::new());
    pub static ref DECRYPT_STATE: GlobalState<HashMap<u32, EncryptCtx>> = GlobalState::new(HashMap::new());
    pub static ref MESSAGE_ENCRYPT_STATE: GlobalState<HashMap<u32, MsgAeadCtx>> = GlobalState::new(HashMap::new());
    pub static ref MESSAGE_DECRYPT_STATE: GlobalState<HashMap<u32, MsgAeadCtx>> = GlobalState::new(HashMap::new());
    pub static ref DIGEST_STATE: GlobalState<HashMap<u32, DigestCtx>> = GlobalState::new(HashMap::new());
    /// C_SignMessageBegin/Next accumulator (message parts between Begin and the final Next).
    pub static ref MESSAGE_SIGN_ACC: GlobalState<HashMap<u32, Vec<u8>>> = GlobalState::new(HashMap::new());
    /// C_VerifyMessageBegin/Next accumulator.
    pub static ref MESSAGE_VERIFY_ACC: GlobalState<HashMap<u32, Vec<u8>>> = GlobalState::new(HashMap::new());
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

pub fn hash_pin(pin: &[u8], salt: &[u8; 16]) -> [u8; 32] {
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;
    let mut hash = [0u8; 32];
    pbkdf2_hmac::<Sha256>(pin, salt, 10000, &mut hash);
    hash
}

pub fn init_token_store() {
    TOKEN_STORE.with(|ts| {
        let mut store = ts.borrow_mut();
        if store.is_empty() {
            // Provide an initial uninitialized token in slot 0
            store.insert(
                0,
                TokenState {
                    slot_id: 0,
                    initialized: false,
                    label: [0x20; 32],
                    login_state: LoginState::Public,
                    so_pin_salt: [0u8; 16],
                    so_pin_hash: [0u8; 32],
                    user_pin_salt: None,
                    user_pin_hash: None,
                },
            );
        }
    });
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

#[derive(Clone)]
pub struct MsgAeadCtx {
    pub key: Vec<u8>,
    pub in_message: bool,
    pub iv: Vec<u8>,
    pub aad: Vec<u8>,
    pub tag_bits: u32,
    pub payload_acc: Vec<u8>,
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

/// True if the session's token is logged in (User or SO).
pub fn session_logged_in(h_session: u32) -> bool {
    match session_slot(h_session) {
        Some(slot) => token_logged_in(slot),
        None => false,
    }
}

/// PKCS#11 v3.2 §4.4 / §5.6 — a private object (CKA_PRIVATE=TRUE) may only be
/// accessed (found, read, used, destroyed) when the session's token is logged
/// in as User or SO. Public objects are always accessible. Objects that do not
/// set CKA_PRIVATE are treated as public (the engine's historical default).
pub fn can_access_object(h_session: u32, attrs: &Attributes) -> bool {
    if !read_bool_attr(attrs, CKA_PRIVATE) {
        return true;
    }
    session_logged_in(h_session)
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

/// Server-managed (read-only) attributes a mutation API must refuse to change,
/// plus the one-way transition rules (PKCS#11 v3.2 §4.1.1 Table 12):
/// CKA_SENSITIVE may only go FALSE→TRUE; CKA_EXTRACTABLE only TRUE→FALSE.
/// Vendor stateful-key attrs (≥0x8000_0100) and engine-internal CKA_PRIV_*
/// (≥0xFFFF_0000) are the engine's own state channel and bypass the policy.
pub fn set_object_attr_checked(handle: u32, attr_type: u32, value: Vec<u8>) -> Result<(), u32> {
    // engine-internal / vendor stateful channel — no policy
    if attr_type >= 0x8000_0000 {
        if set_object_attr_bytes(handle, attr_type, value) {
            return Ok(());
        }
        return Err(CKR_OBJECT_HANDLE_INVALID);
    }
    const READ_ONLY: &[u32] = &[
        CKA_CLASS,
        CKA_KEY_TYPE,
        CKA_LOCAL,
        CKA_KEY_GEN_MECHANISM,
        CKA_ALWAYS_SENSITIVE,
        CKA_NEVER_EXTRACTABLE,
        CKA_CHECK_VALUE,
        CKA_MODULUS,
        CKA_PUBLIC_EXPONENT,
        CKA_EC_PARAMS,
        CKA_EC_POINT,
    ];
    if READ_ONLY.contains(&attr_type) {
        return Err(CKR_ATTRIBUTE_READ_ONLY);
    }
    if attr_type == CKA_SENSITIVE || attr_type == CKA_EXTRACTABLE {
        let new_val = value.first().copied().unwrap_or(0) != 0;
        let cur = OBJECTS.with(|o| {
            o.borrow()
                .get(&handle)
                .map(|attrs| read_bool_attr(attrs, attr_type))
        });
        match cur {
            None => return Err(CKR_OBJECT_HANDLE_INVALID),
            Some(cur_val) => {
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
        }
    }
    if set_object_attr_bytes(handle, attr_type, value) {
        Ok(())
    } else {
        Err(CKR_OBJECT_HANDLE_INVALID)
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
    NEXT_HANDLE.with(|h| {
        let mut handle = h.borrow_mut();
        if *handle == u32::MAX {
            // Saturate at MAX rather than wrapping; callers get 0 as sentinel for failure.
            return 0;
        }
        let current = *handle;
        *handle += 1;
        OBJECTS.with(|objs| {
            objs.borrow_mut().insert(current, attrs);
        });
        current
    })
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

/// Store a CK_ULONG attribute (4-byte little-endian).
pub fn store_ulong(attrs: &mut Attributes, attr_type: u32, value: u32) {
    attrs.insert(attr_type, value.to_le_bytes().to_vec());
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
                    // PKCS#11 v3.2: SHA-256 of key value, first 3 bytes
                    let hash = Sha256::digest(&key_value);
                    hash[..3].to_vec()
                }
                _ => return,
            }
        }
        CKO_PUBLIC_KEY | CKO_PRIVATE_KEY => {
            // Asymmetric keys: SHA-256 of CKA_VALUE → first 3 bytes
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
