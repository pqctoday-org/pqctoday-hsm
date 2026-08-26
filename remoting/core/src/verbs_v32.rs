//! `verbs_v32` — the transport-agnostic layer behind the `Pkcs11V32`
//! 1:1 C_* mirror service (docs/remoting-pkcs11-v32-full-coverage-plan-
//! 2026-08-26.md, RW0/RW1 + the first RW2/RW3 slices).
//!
//! ## Contract — deliberately different from `verbs.rs`
//!
//! Every function returns the raw `CK_RV` as a VALUE (plus outputs),
//! never a `Result<_, CkError>`: the mirror's whole point is that the
//! wire carries the C ABI's own return-code semantics untranslated, so
//! a parity test can assert `in_process == grpc == rest` on the exact
//! numeric code with zero mapping tables in between. `CKR_OK == 0`.
//!
//! ## Why this calls `ffi::C_*` directly (and why that is safe here)
//!
//! `native::*` exists because the ffi surface was ONCE wasm32-only in
//! its pointer marshalling. That has not been true since the `ck_param`
//! rework (see `rust/src/ck_param.rs`'s module doc): mechanism and
//! template reads go through an ABI-aware reader that computes offsets
//! at the TARGET's word width, and `C_GetAttributeValue`'s template
//! walk is `*mut usize` (native width). The cross-engine differential
//! harness (`tests/differential/p11_diff.cpp`) `dlopen`s this same
//! cdylib natively and drives these exact entry points across 49
//! scenarios on every gate run — the native C ABI path is load-bearing,
//! tested infrastructure, not a gamble. Calling it here (with structs
//! built at native layout, below) is what makes the mirror's behavior
//! THE ENGINE's behavior — template precedence rules, §5.7.5
//! consolidated codes, FSM mixing guards — rather than a re-
//! implementation that could drift.
//!
//! Engine state is process-global (`state::GlobalState` — a
//! `lazy_static Mutex` wearing a `.with()` API), so these calls are
//! thread-safe from tonic/axum workers, same as `verbs.rs`.

use softhsmrustv3::constants::CKR_ARGUMENTS_BAD;
use softhsmrustv3::ck_param::{self, F};
use softhsmrustv3::{constants, ffi};

/// Engine constants re-exported for transports and tests — single source
/// (`rust/src/constants.rs`, itself pinned to `pkcs11t.h`), never
/// re-declared here. Grep pkcs11t.h before ADDING to this list.
pub mod ck {
    pub use softhsmrustv3::constants::{
        CKF_RW_SESSION, CKF_SERIAL_SESSION, CKM_ML_DSA, CKM_SHA256, CKM_SHA384, CKM_SHA512,
        CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID,
        CKR_FUNCTION_NOT_SUPPORTED, CKR_OBJECT_HANDLE_INVALID, CKR_OK, CKR_OPERATION_ACTIVE,
        CKR_SESSION_HANDLE_INVALID, CKR_SIGNATURE_INVALID, CKU_SO, CKU_USER,
        SUPPORTED_MECHS,
    };
    // Not in every constants build the same way — resolved individually so a
    // missing one is a compile error here, not a silent wrong value.
    pub use softhsmrustv3::constants::CKA_CLASS;
    pub use softhsmrustv3::constants::CKA_VALUE;
    pub use softhsmrustv3::constants::CKR_PIN_INCORRECT;
    pub use softhsmrustv3::constants::CKR_RANDOM_SEED_NOT_SUPPORTED;
    pub use softhsmrustv3::constants::CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    pub use softhsmrustv3::constants::CKR_USER_ALREADY_LOGGED_IN;
    // RW2 additions.
    pub use softhsmrustv3::constants::CKA_KEY_TYPE;
    pub use softhsmrustv3::constants::CKA_PARAMETER_SET;
    pub use softhsmrustv3::constants::CKA_SIGN;
    pub use softhsmrustv3::constants::CKA_TOKEN;
    pub use softhsmrustv3::constants::CKA_VALUE_LEN;
    pub use softhsmrustv3::constants::CKA_VERIFY;
    pub use softhsmrustv3::constants::CKK_AES;
    pub use softhsmrustv3::constants::CKK_ML_DSA;
    pub use softhsmrustv3::constants::CKM_AES_KEY_GEN;
    pub use softhsmrustv3::constants::CKM_ML_DSA_KEY_PAIR_GEN;
    pub use softhsmrustv3::constants::CKO_PRIVATE_KEY;
    pub use softhsmrustv3::constants::CKO_PUBLIC_KEY;
    pub use softhsmrustv3::constants::CKO_SECRET_KEY;
    pub use softhsmrustv3::constants::CKP_ML_DSA_65;
    pub use softhsmrustv3::constants::CKR_OPERATION_NOT_INITIALIZED;
    pub use softhsmrustv3::constants::CKR_TEMPLATE_INCOMPLETE;
    pub use softhsmrustv3::constants::CKR_TEMPLATE_INCONSISTENT;
    // RW3 additions.
    pub use softhsmrustv3::constants::CKA_DECRYPT;
    pub use softhsmrustv3::constants::CKA_ENCRYPT;
    pub use softhsmrustv3::constants::CKM_AES_ECB;
    pub use softhsmrustv3::constants::CKR_DATA_LEN_RANGE;
    // RW6a additions.
    pub use softhsmrustv3::constants::CKF_DONT_BLOCK;
    pub use softhsmrustv3::constants::CKF_TOKEN_INITIALIZED;
    pub use softhsmrustv3::constants::CKR_FUNCTION_NOT_PARALLEL;
    pub use softhsmrustv3::constants::CKR_NO_EVENT;
    pub use softhsmrustv3::constants::CKR_PIN_LEN_RANGE;
    pub use softhsmrustv3::constants::CKM_AES_GCM;
    pub use softhsmrustv3::constants::CKR_MECHANISM_INVALID;
    pub use softhsmrustv3::constants::CKR_SESSION_EXISTS;
    // RW4 additions.
    pub use softhsmrustv3::constants::CKA_CHECK_VALUE;
    pub use softhsmrustv3::constants::CKA_DERIVE;
    pub use softhsmrustv3::constants::CKA_UNWRAP;
    pub use softhsmrustv3::constants::CKA_WRAP;
    pub use softhsmrustv3::constants::CKA_EXTRACTABLE;
    pub use softhsmrustv3::constants::CKK_GENERIC_SECRET;
    pub use softhsmrustv3::constants::CKM_AES_KEY_WRAP;
    pub use softhsmrustv3::constants::CKM_CONCATENATE_BASE_AND_KEY;
    pub use softhsmrustv3::constants::CKM_ECDH1_DERIVE;
    pub use softhsmrustv3::constants::CKM_GENERIC_SECRET_KEY_GEN;
    pub use softhsmrustv3::constants::CKM_HKDF_DERIVE;
    pub use softhsmrustv3::constants::CKM_PKCS5_PBKD2;
    pub use softhsmrustv3::constants::CKM_SHA256_KEY_DERIVATION;
    pub use softhsmrustv3::constants::CKM_SP800_108_COUNTER_KDF;
    pub use softhsmrustv3::constants::CKR_KEY_NOT_WRAPPABLE;
    pub use softhsmrustv3::constants::CKR_KEY_UNEXTRACTABLE;
    pub use softhsmrustv3::constants::CKR_WRAPPED_KEY_INVALID;
    pub use softhsmrustv3::constants::CKR_SESSION_READ_ONLY;
    pub use softhsmrustv3::constants::CKR_SLOT_ID_INVALID;
}

/// The bootstrap slot — same constant `verbs::bootstrap()` initializes.
pub const SLOT: u32 = 0;

/// DoS guard on C_GenerateRandom: a remote caller must not be able to ask
/// the server to allocate unbounded memory. 1 MiB is far above any
/// legitimate nonce/seed need; beyond it the mirror answers
/// CKR_ARGUMENTS_BAD locally (documented divergence: the in-process C ABI
/// has no such cap because the caller owns the buffer there).
pub const MAX_RANDOM_LEN: u32 = 1024 * 1024;

/// Native-layout `CK_MECHANISM` (LP64: three machine words). `ck_param`'s
/// reader computes offsets for exactly this layout on this target — see
/// `ck_param.rs`'s `mech()` and its `mech_reads_the_outer_struct_at_
/// native_width` test.
#[repr(C)]
struct CkMechanismNative {
    mechanism: usize,
    p_parameter: *const u8,
    ul_parameter_len: usize,
}

fn mech_native(mechanism: u64, parameter: &[u8]) -> CkMechanismNative {
    CkMechanismNative {
        mechanism: mechanism as usize,
        p_parameter: if parameter.is_empty() { core::ptr::null() } else { parameter.as_ptr() },
        ul_parameter_len: parameter.len(),
    }
}

/// One template entry over the wire: `(attribute_type, value_bytes)`.
/// Ulong-typed attribute VALUES (CKA_CLASS, CKA_KEY_TYPE, CKA_PARAMETER_SET,
/// ...) must be native `CK_ULONG` width (8 bytes LP64) — the same
/// convention `get_attribute_value`'s OUTPUT already uses, applied here on
/// the input side. `attr_ulong`/`attr_bool` below build entries correctly;
/// callers building entries by hand (transports) must match.
pub type AttrIn = (u64, Vec<u8>);

/// A ulong-valued template entry at native width.
pub fn attr_ulong(attr_type: u64, value: u32) -> AttrIn {
    (attr_type, (value as usize).to_le_bytes().to_vec())
}
/// A single-byte boolean template entry (CK_BBOOL: 0x00/0x01).
pub fn attr_bool(attr_type: u64, value: bool) -> AttrIn {
    (attr_type, vec![u8::from(value)])
}

/// Owns the native CK_ATTRIBUTE[] backing storage for the lifetime of one
/// FFI call: the three-word entries hold raw pointers into `values`, so
/// both must outlive the call. Built once, reused by every template-taking
/// verb below — the same `*mut usize` three-word-per-entry layout
/// `C_CreateObject`/`C_SetAttributeValue`/`C_CopyObject`/
/// `C_FindObjectsInit` all read (native-width-audited, see this module's
/// doc and the plan's §4).
struct NativeTemplate {
    entries: Vec<usize>,
    #[allow(dead_code)] // kept alive for entries' raw pointers to stay valid
    values: Vec<Vec<u8>>,
}

fn build_template(attrs: &[AttrIn]) -> NativeTemplate {
    let mut entries = vec![0usize; attrs.len() * 3];
    let mut values: Vec<Vec<u8>> = attrs.iter().map(|(_, v)| v.clone()).collect();
    for (i, (attr_type, _)) in attrs.iter().enumerate() {
        entries[i * 3] = *attr_type as usize;
        entries[i * 3 + 1] = if values[i].is_empty() { 0 } else { values[i].as_mut_ptr() as usize };
        entries[i * 3 + 2] = values[i].len();
    }
    NativeTemplate { entries, values }
}

/// `CK_GCM_MESSAGE_PARAMS` at native width (RW-P, RW6b's one prerequisite
/// variant): 6 `usize` words — `pIv@0, ulIvLen@1, ulIvBits@2 (unused by
/// this engine), ivGenerator@3, pTag@4, ulTagBits@5` (verified against
/// `ffi::parse_gcm_msg_params`'s own doc comment). Owns the IV and tag
/// buffers for the FFI call's lifetime, same pattern as `NativeTemplate`.
///
/// `pTag` is a genuine OUT field on ENCRYPT — `ffi::aes_gcm_exec` writes
/// `tag_bits/8` bytes into it — and a genuine IN field on DECRYPT, where
/// the engine reads the CALLER-supplied expected tag from it to verify
/// (auth failure zeroizes the plaintext before returning). Callers must
/// pass the expected tag as `tag_in` on decrypt; `tag()` after an encrypt
/// call returns what the engine wrote.
///
/// `iv_generator != 0` asks the engine to fill `pIv` with a fresh random
/// IV of the caller-requested length (`parse_gcm_msg_params` writes into
/// the SAME buffer the caller allocated) — `iv()` after the call returns
/// whatever IV was actually used, which the caller must have to decrypt
/// later. On `iv_generator == 0` the caller's `iv` bytes are used as-is
/// and never written.
struct GcmMessageParams {
    words: [usize; 6],
    iv: Vec<u8>,
    tag: Vec<u8>,
}

impl GcmMessageParams {
    fn new(iv: &[u8], iv_generator: u32, tag_bits: u32, tag_in: &[u8]) -> Self {
        let mut iv_buf = iv.to_vec();
        let tag_bytes = (tag_bits as usize) / 8;
        let mut tag_buf = tag_in.to_vec();
        tag_buf.resize(tag_bytes, 0);
        let words = [
            if iv_buf.is_empty() { 0 } else { iv_buf.as_mut_ptr() as usize },
            iv_buf.len(),
            0,
            iv_generator as usize,
            if tag_buf.is_empty() { 0 } else { tag_buf.as_mut_ptr() as usize },
            tag_bits as usize,
        ];
        Self { words, iv: iv_buf, tag: tag_buf }
    }
    fn as_ptr(&self) -> *mut u8 {
        &self.words as *const [usize; 6] as *mut u8
    }
    fn iv(&self) -> &[u8] {
        &self.iv
    }
    fn tag(&self) -> &[u8] {
        &self.tag
    }
}

/// Generic native-layout builder for any `ck_param`-declared struct (RW4's
/// RW-P slice: ECDH1/HKDF/PBKDF2/SP800-108/key-derivation-string-data).
/// Reuses `ck_param::offset_at`/`size_at` directly — the SAME source of
/// truth the engine's own reader walks — so this writer cannot drift from
/// it the way a hand-rolled word-offset table could. Every `set_*` call
/// mirrors one `ParamReader` accessor exactly: `set_ulong`/`ulong`,
/// `set_ptr`/`ptr`, `set_bbool`/`bbool` all write/read the same
/// native-endian bytes at the same ABI-computed offset.
///
/// Pointer-typed fields point into buffers owned by `self.owned` — pushed
/// there at `set_ptr` time so they outlive the FFI call the same way
/// `NativeTemplate`'s `values` and `GcmMessageParams`'s `iv`/`tag` do.
///
/// **Load-bearing:** every `derive_params::*` function returns the whole
/// `StructBuilder`, never just its `bytes` — extracting `.bytes` alone
/// would drop `.owned` and leave every pointer embedded in those bytes
/// dangling the instant the constructor returned. `as_slice()` borrows
/// `bytes` without separating it from the buffers it points into; the
/// caller keeps the returned `StructBuilder` alive (a named local) for
/// exactly as long as the FFI call that reads it, the same discipline
/// `GcmMessageParams` already follows by never being split apart either.
pub struct StructBuilder {
    bytes: Vec<u8>,
    fields: &'static [F],
    owned: Vec<Vec<u8>>,
}

impl StructBuilder {
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
    fn new(fields: &'static [F]) -> Self {
        Self { bytes: vec![0u8; ck_param::size_at(fields, ck_param::WORD)], fields, owned: Vec::new() }
    }
    fn set_ulong(&mut self, i: usize, value: usize) {
        debug_assert!(matches!(self.fields[i], F::Ulong));
        let off = ck_param::offset_at(self.fields, i, ck_param::WORD);
        self.bytes[off..off + ck_param::WORD].copy_from_slice(&value.to_ne_bytes());
    }
    fn set_bbool(&mut self, i: usize, value: bool) {
        debug_assert!(matches!(self.fields[i], F::Bbool));
        let off = ck_param::offset_at(self.fields, i, ck_param::WORD);
        self.bytes[off] = u8::from(value);
    }
    /// Stores `buf` (owned for the builder's lifetime) and writes its
    /// address into field `i` (must be `F::Ptr`).
    fn set_buf(&mut self, i: usize, buf: Vec<u8>) {
        debug_assert!(matches!(self.fields[i], F::Ptr));
        let off = ck_param::offset_at(self.fields, i, ck_param::WORD);
        let ptr = if buf.is_empty() { 0 } else { buf.as_ptr() as usize };
        self.bytes[off..off + ck_param::WORD].copy_from_slice(&ptr.to_ne_bytes());
        self.owned.push(buf);
    }
    /// The pointer-plus-length idiom (`P_SALT`/`UL_SALT_LEN`, ...): sets
    /// both fields from one byte slice.
    fn set_buf_pair(&mut self, ptr_field: usize, len_field: usize, data: &[u8]) {
        self.set_buf(ptr_field, data.to_vec());
        self.set_ulong(len_field, data.len());
    }
}

// ── sessions & login (RW1) ─────────────────────────────────────────────────

pub fn open_session(slot_id: u32, flags: u32) -> (u32, u32) {
    let mut handle: u32 = 0;
    let rv = ffi::C_OpenSession(
        slot_id,
        flags,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        &mut handle,
    );
    (rv, handle)
}

pub fn close_session(session: u32) -> u32 {
    ffi::C_CloseSession(session)
}

pub fn login(session: u32, user_type: u32, pin: &[u8]) -> u32 {
    // The engine reads, never writes, the PIN buffer; the *mut is C-ABI
    // signature shape only.
    ffi::C_Login(session, user_type, pin.as_ptr() as *mut u8, pin.len() as u32)
}

pub fn logout(session: u32) -> u32 {
    ffi::C_Logout(session)
}

pub struct SessionInfo {
    pub slot_id: u32,
    pub state: u32,
    pub flags: u32,
    pub device_error: u32,
}

pub fn get_session_info(session: u32) -> (u32, SessionInfo) {
    // ffi::C_GetSessionInfo writes exactly four u32s (see its body) — the
    // wasm32-era struct layout, byte-stable on every target.
    let mut buf = [0u32; 4];
    let rv = ffi::C_GetSessionInfo(session, buf.as_mut_ptr() as *mut u8);
    (
        rv,
        SessionInfo { slot_id: buf[0], state: buf[1], flags: buf[2], device_error: buf[3] },
    )
}

pub struct TokenInfo {
    pub label: String,
    pub manufacturer: String,
    pub model: String,
    pub serial_number: String,
    pub flags: u32,
    pub session_count: u32,
    pub rw_session_count: u32,
    pub max_pin_len: u32,
    pub min_pin_len: u32,
    pub hardware_version: (u8, u8),
    pub firmware_version: (u8, u8),
}

pub fn get_token_info(slot_id: u32) -> (u32, Option<TokenInfo>) {
    // 160-byte CK_TOKEN_INFO in the engine's fixed layout — offsets match
    // ffi::C_GetTokenInfo's own writes (label@0/32, manufacturer@32/32,
    // model@64/16, serial@80/16, u32 fields from @96, versions @140..144).
    let mut buf = [0u8; 160];
    let rv = ffi::C_GetTokenInfo(slot_id, buf.as_mut_ptr());
    if rv != 0 {
        return (rv, None);
    }
    let fixed_str = |range: core::ops::Range<usize>| {
        String::from_utf8_lossy(&buf[range]).trim_end_matches(' ').to_string()
    };
    let u32_at = |off: usize| u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
    (
        rv,
        Some(TokenInfo {
            label: fixed_str(0..32),
            manufacturer: fixed_str(32..64),
            model: fixed_str(64..80),
            serial_number: fixed_str(80..96),
            flags: u32_at(96),
            session_count: u32_at(104),
            rw_session_count: u32_at(112),
            max_pin_len: u32_at(116),
            min_pin_len: u32_at(120),
            hardware_version: (buf[140], buf[141]),
            firmware_version: (buf[142], buf[143]),
        }),
    )
}

// ── discovery (RW2 slice) ──────────────────────────────────────────────────

pub fn get_mechanism_list(slot_id: u32) -> (u32, Vec<u64>) {
    // Two-call convention against the real entry point (NOT a direct read
    // of SUPPORTED_MECHS) so slot validation and the §5.4 init gate behave
    // exactly as in-process callers see them.
    let mut count: u32 = 0;
    let rv = constants::C_GetMechanismList(slot_id, core::ptr::null_mut(), &mut count);
    if rv != 0 {
        return (rv, Vec::new());
    }
    let mut list = vec![0u32; count as usize];
    let rv = constants::C_GetMechanismList(slot_id, list.as_mut_ptr(), &mut count);
    (rv, list.into_iter().map(u64::from).collect())
}

pub fn get_mechanism_info(slot_id: u32, mechanism: u64) -> (u32, u32, u32, u32) {
    if mechanism > u64::from(u32::MAX) {
        // Engine mechanism space is u32; an out-of-range codepoint cannot
        // be a supported mechanism by construction.
        return (softhsmrustv3::constants::CKR_MECHANISM_INVALID, 0, 0, 0);
    }
    let mut buf = [0u32; 3];
    let rv = ffi::C_GetMechanismInfo(slot_id, mechanism as u32, buf.as_mut_ptr() as *mut u8);
    (rv, buf[0], buf[1], buf[2])
}

// ── random (RW3 slice) ─────────────────────────────────────────────────────

pub fn generate_random(session: u32, length: u32) -> (u32, Vec<u8>) {
    if length > MAX_RANDOM_LEN {
        return (CKR_ARGUMENTS_BAD, Vec::new());
    }
    let mut buf = vec![0u8; length as usize];
    let rv = ffi::C_GenerateRandom(session, buf.as_mut_ptr(), length);
    if rv != 0 {
        buf.clear();
    }
    (rv, buf)
}

pub fn seed_random(session: u32, seed: &[u8]) -> u32 {
    ffi::C_SeedRandom(session, seed.as_ptr() as *mut u8, seed.len() as u32)
}

// ── digest FSM + one-shot (RW3 slice) ──────────────────────────────────────

pub fn digest_init(session: u32, mechanism: u64, parameter: &[u8]) -> u32 {
    let mech = mech_native(mechanism, parameter);
    ffi::C_DigestInit(session, &mech as *const _ as *mut u8)
}

pub fn digest_update(session: u32, part: &[u8]) -> u32 {
    ffi::C_DigestUpdate(session, part.as_ptr() as *mut u8, part.len() as u32)
}

pub fn digest_final(session: u32) -> (u32, Vec<u8>) {
    two_call(|out, len| ffi::C_DigestFinal(session, out, len))
}

pub fn digest(session: u32, mechanism: u64, parameter: &[u8], data: &[u8]) -> (u32, Vec<u8>) {
    let rv = digest_init(session, mechanism, parameter);
    if rv != 0 {
        return (rv, Vec::new());
    }
    two_call(|out, len| {
        ffi::C_Digest(session, data.as_ptr() as *mut u8, data.len() as u32, out, len)
    })
}

// ── sign / verify FSM + one-shot (RW3 slice) ───────────────────────────────

pub fn sign_init(session: u32, mechanism: u64, parameter: &[u8], key: u32) -> u32 {
    let mech = mech_native(mechanism, parameter);
    ffi::C_SignInit(session, &mech as *const _ as *mut u8, key)
}

pub fn sign(session: u32, data: &[u8]) -> (u32, Vec<u8>) {
    two_call(|out, len| {
        ffi::C_Sign(session, data.as_ptr() as *mut u8, data.len() as u32, out, len)
    })
}

pub fn sign_update(session: u32, part: &[u8]) -> u32 {
    ffi::C_SignUpdate(session, part.as_ptr() as *mut u8, part.len() as u32)
}

pub fn sign_final(session: u32) -> (u32, Vec<u8>) {
    two_call(|out, len| ffi::C_SignFinal(session, out, len))
}

pub fn verify_init(session: u32, mechanism: u64, parameter: &[u8], key: u32) -> u32 {
    let mech = mech_native(mechanism, parameter);
    ffi::C_VerifyInit(session, &mech as *const _ as *mut u8, key)
}

pub fn verify(session: u32, data: &[u8], signature: &[u8]) -> u32 {
    ffi::C_Verify(
        session,
        data.as_ptr() as *mut u8,
        data.len() as u32,
        signature.as_ptr() as *mut u8,
        signature.len() as u32,
    )
}

pub fn verify_update(session: u32, part: &[u8]) -> u32 {
    ffi::C_VerifyUpdate(session, part.as_ptr() as *mut u8, part.len() as u32)
}

pub fn verify_final(session: u32, signature: &[u8]) -> u32 {
    ffi::C_VerifyFinal(session, signature.as_ptr() as *mut u8, signature.len() as u32)
}

// ── objects (RW2 slice) ────────────────────────────────────────────────────

pub struct AttrOut {
    pub attribute_type: u64,
    pub available: bool,
    pub value: Vec<u8>,
}

/// Multi-attribute C_GetAttributeValue with the engine's real §5.7.5
/// semantics: every entry processed, per-entry CK_UNAVAILABLE_INFORMATION,
/// one consolidated code (SENSITIVE > TYPE_INVALID > BUFFER_TOO_SMALL).
/// Two passes of the real entry point: lengths first, then values.
pub fn get_attribute_value(session: u32, object: u32, attribute_types: &[u64]) -> (u32, Vec<AttrOut>) {
    const UNAVAILABLE: usize = usize::MAX;
    let n = attribute_types.len();
    if n == 0 {
        // Zero-entry template: the engine returns CKR_OK having checked the
        // session/object gates — pass it through.
        let rv = ffi::C_GetAttributeValue(session, object, core::ptr::null_mut(), 0);
        return (rv, Vec::new());
    }
    if attribute_types.iter().any(|t| *t > u64::from(u32::MAX)) {
        return (CKR_ARGUMENTS_BAD, Vec::new());
    }

    // Native CK_ATTRIBUTE layout: [type, pValue, ulValueLen] machine words —
    // exactly the `*mut usize` walk C_GetAttributeValue does.
    let mut template = vec![0usize; n * 3];
    for (i, t) in attribute_types.iter().enumerate() {
        template[i * 3] = *t as usize;
        template[i * 3 + 1] = 0; // NULL pValue → length query
        template[i * 3 + 2] = 0;
    }
    let rv1 = ffi::C_GetAttributeValue(session, object, template.as_mut_ptr() as *mut u8, n as u32);
    if rv1 == ck::CKR_SESSION_HANDLE_INVALID || rv1 == ck::CKR_OBJECT_HANDLE_INVALID {
        return (rv1, Vec::new());
    }

    let mut buffers: Vec<Vec<u8>> = Vec::with_capacity(n);
    for i in 0..n {
        let len = template[i * 3 + 2];
        buffers.push(if len == UNAVAILABLE { Vec::new() } else { vec![0u8; len] });
    }
    for (i, buf) in buffers.iter_mut().enumerate() {
        template[i * 3 + 1] = if buf.is_empty() { 0 } else { buf.as_mut_ptr() as usize };
        template[i * 3 + 2] = buf.len();
    }
    let rv2 = ffi::C_GetAttributeValue(session, object, template.as_mut_ptr() as *mut u8, n as u32);

    let out = attribute_types
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let available = template[i * 3 + 2] != UNAVAILABLE;
            AttrOut {
                attribute_type: *t,
                available,
                value: if available { std::mem::take(&mut buffers[i]) } else { Vec::new() },
            }
        })
        .collect();
    (rv2, out)
}

pub fn destroy_object(session: u32, object: u32) -> u32 {
    ffi::C_DestroyObject(session, object)
}

// ── object & keygen templates (RW2 slice) ───────────────────────────────────
//
// Native-width audited (2026-08-26): C_GenerateKey, C_GenerateKeyPair,
// C_CreateObject, C_SetAttributeValue, C_CopyObject, C_FindObjectsInit all
// walk their CK_ATTRIBUTE templates as `*mut usize` three-word entries —
// the exact layout `build_template` produces and `get_attribute_value`
// above already relies on for its OUTPUT template. No engine-crate change
// needed for any of the nine functions below (plan §4/§5, RW2 notes).

pub fn generate_key(session: u32, mechanism: u64, parameter: &[u8], template: &[AttrIn]) -> (u32, u32) {
    let mech = mech_native(mechanism, parameter);
    let mut tmpl = build_template(template);
    let mut handle: u32 = 0;
    let rv = ffi::C_GenerateKey(
        session,
        &mech as *const CkMechanismNative as *mut u8,
        tmpl.entries.as_mut_ptr() as *mut u8,
        template.len() as u32,
        &mut handle,
    );
    (rv, handle)
}

pub fn generate_key_pair(
    session: u32,
    mechanism: u64,
    parameter: &[u8],
    public_template: &[AttrIn],
    private_template: &[AttrIn],
) -> (u32, u32, u32) {
    let mech = mech_native(mechanism, parameter);
    let mut pub_tmpl = build_template(public_template);
    let mut priv_tmpl = build_template(private_template);
    let mut pub_handle: u32 = 0;
    let mut priv_handle: u32 = 0;
    let rv = ffi::C_GenerateKeyPair(
        session,
        &mech as *const CkMechanismNative as *mut u8,
        pub_tmpl.entries.as_mut_ptr() as *mut u8,
        public_template.len() as u32,
        priv_tmpl.entries.as_mut_ptr() as *mut u8,
        private_template.len() as u32,
        &mut pub_handle,
        &mut priv_handle,
    );
    (rv, pub_handle, priv_handle)
}

pub fn create_object(session: u32, template: &[AttrIn]) -> (u32, u32) {
    let mut tmpl = build_template(template);
    let mut handle: u32 = 0;
    let rv = ffi::C_CreateObject(
        session,
        tmpl.entries.as_mut_ptr() as *mut u8,
        template.len() as u32,
        &mut handle,
    );
    (rv, handle)
}

/// Mutates a live object — gated by `--enable-destructive` at the transport
/// layer (default OFF in deployed containers, ON in tests/acceptance).
pub fn set_attribute_value(session: u32, object: u32, template: &[AttrIn]) -> u32 {
    let mut tmpl = build_template(template);
    ffi::C_SetAttributeValue(session, object, tmpl.entries.as_mut_ptr() as *mut u8, template.len() as u32)
}

pub fn copy_object(session: u32, object: u32, template: &[AttrIn]) -> (u32, u32) {
    let mut tmpl = build_template(template);
    let mut handle: u32 = 0;
    let rv = ffi::C_CopyObject(
        session,
        object,
        tmpl.entries.as_mut_ptr() as *mut u8,
        template.len() as u32,
        &mut handle,
    );
    (rv, handle)
}

pub fn get_object_size(session: u32, object: u32) -> (u32, u32) {
    let mut size: u32 = 0;
    let rv = ffi::C_GetObjectSize(session, object, &mut size);
    (rv, size)
}

pub fn find_objects_init(session: u32, template: &[AttrIn]) -> u32 {
    let mut tmpl = build_template(template);
    ffi::C_FindObjectsInit(session, tmpl.entries.as_mut_ptr() as *mut u8, template.len() as u32)
}

pub fn find_objects(session: u32, max_count: u32) -> (u32, Vec<u32>) {
    let mut handles = vec![0u32; max_count as usize];
    let mut found: u32 = 0;
    let rv = ffi::C_FindObjects(
        session,
        if handles.is_empty() { core::ptr::null_mut() } else { handles.as_mut_ptr() },
        max_count,
        &mut found,
    );
    handles.truncate(found as usize);
    (rv, handles)
}

pub fn find_objects_final(session: u32) -> u32 {
    ffi::C_FindObjectsFinal(session)
}

// ── encrypt / decrypt FSM + one-shot (RW3 slice) ────────────────────────────
//
// Native-width audited (2026-08-26): same shape as the sign/verify FSM
// above — `p_mechanism: *mut u8` read via `ck_param`, no CK_ATTRIBUTE
// templates involved. Cipher parameters (CK_GCM_PARAMS, CK_CTR_PARAMS,
// ...) travel as raw bytes in `parameter`, exactly like every other
// mechanism here — no new wire shape needed.

pub fn encrypt_init(session: u32, mechanism: u64, parameter: &[u8], key: u32) -> u32 {
    let mech = mech_native(mechanism, parameter);
    ffi::C_EncryptInit(session, &mech as *const _ as *mut u8, key)
}

pub fn encrypt(session: u32, data: &[u8]) -> (u32, Vec<u8>) {
    two_call(|out, len| {
        ffi::C_Encrypt(session, data.as_ptr() as *mut u8, data.len() as u32, out, len)
    })
}

pub fn encrypt_update(session: u32, part: &[u8]) -> (u32, Vec<u8>) {
    two_call(|out, len| {
        ffi::C_EncryptUpdate(session, part.as_ptr() as *mut u8, part.len() as u32, out, len)
    })
}

pub fn encrypt_final(session: u32) -> (u32, Vec<u8>) {
    two_call(|out, len| ffi::C_EncryptFinal(session, out, len))
}

pub fn decrypt_init(session: u32, mechanism: u64, parameter: &[u8], key: u32) -> u32 {
    let mech = mech_native(mechanism, parameter);
    ffi::C_DecryptInit(session, &mech as *const _ as *mut u8, key)
}

pub fn decrypt(session: u32, data: &[u8]) -> (u32, Vec<u8>) {
    two_call(|out, len| {
        ffi::C_Decrypt(session, data.as_ptr() as *mut u8, data.len() as u32, out, len)
    })
}

pub fn decrypt_update(session: u32, part: &[u8]) -> (u32, Vec<u8>) {
    two_call(|out, len| {
        ffi::C_DecryptUpdate(session, part.as_ptr() as *mut u8, part.len() as u32, out, len)
    })
}

pub fn decrypt_final(session: u32) -> (u32, Vec<u8>) {
    two_call(|out, len| ffi::C_DecryptFinal(session, out, len))
}

// ── admin / info (RW6a slice) ────────────────────────────────────────────
//
// CK_INFO (72 bytes) and CK_SLOT_INFO (104 bytes) travel as raw bytes —
// consistent with this mirror's "no enums, raw codepoints" convention
// rather than a one-off typed message for two fixed, documented layouts
// (offsets in `ffi::C_GetInfo`/`C_GetSlotInfo`'s own comments).

pub fn get_info() -> (u32, Vec<u8>) {
    let mut buf = vec![0u8; 72];
    let rv = ffi::C_GetInfo(buf.as_mut_ptr());
    (rv, buf)
}

pub fn get_slot_list(token_present: bool) -> (u32, Vec<u32>) {
    let mut count: u32 = 0;
    let rv = ffi::C_GetSlotList(u8::from(token_present), core::ptr::null_mut(), &mut count);
    if rv != 0 {
        return (rv, Vec::new());
    }
    let mut slots = vec![0u32; count as usize];
    let rv = ffi::C_GetSlotList(
        u8::from(token_present),
        if slots.is_empty() { core::ptr::null_mut() } else { slots.as_mut_ptr() },
        &mut count,
    );
    slots.truncate(count as usize);
    (rv, slots)
}

pub fn get_slot_info(slot_id: u32) -> (u32, Vec<u8>) {
    let mut buf = vec![0u8; 104];
    let rv = ffi::C_GetSlotInfo(slot_id, buf.as_mut_ptr());
    (rv, buf)
}

pub fn wait_for_slot_event(flags: u32) -> u32 {
    ffi::C_WaitForSlotEvent(flags, core::ptr::null_mut(), core::ptr::null_mut())
}

pub fn close_all_sessions(slot_id: u32) -> u32 {
    ffi::C_CloseAllSessions(slot_id)
}

pub fn session_cancel(session: u32, flags: u32) -> u32 {
    ffi::C_SessionCancel(session, flags)
}

pub fn login_user(session: u32, user_type: u32, pin: &[u8]) -> u32 {
    ffi::C_LoginUser(
        session,
        user_type,
        pin.as_ptr() as *mut u8,
        pin.len() as u32,
        core::ptr::null_mut(),
        0,
    )
}

// ── destructive-gated admin (RW6a slice) ─────────────────────────────────
// Gated by `--enable-destructive` at the transport layer, same posture as
// C_DestroyObject/C_SetAttributeValue.

/// `label` MUST be exactly 32 bytes: `ffi::C_InitToken` reads a fixed
/// `CK_UTF8CHAR label[32]` with no length parameter, so anything shorter
/// is an out-of-bounds read at the FFI boundary, not a PKCS#11 error code
/// — this is caught here, before the call, not left to the engine.
pub fn init_token(slot_id: u32, pin: &[u8], label: &[u8]) -> u32 {
    if label.len() != 32 {
        return CKR_ARGUMENTS_BAD;
    }
    ffi::C_InitToken(slot_id, pin.as_ptr() as *mut u8, pin.len() as u32, label.as_ptr() as *mut u8)
}

pub fn init_pin(session: u32, pin: &[u8]) -> u32 {
    ffi::C_InitPIN(session, pin.as_ptr() as *mut u8, pin.len() as u32)
}

pub fn set_pin(session: u32, old_pin: &[u8], new_pin: &[u8]) -> u32 {
    ffi::C_SetPIN(
        session,
        old_pin.as_ptr() as *mut u8,
        old_pin.len() as u32,
        new_pin.as_ptr() as *mut u8,
        new_pin.len() as u32,
    )
}

// ── honest-code stubs (RW6a slice) ───────────────────────────────────────
// PKCS#11 v3.2 §11.17-mandated entry points this engine does not
// implement. The CODE is the contract under test here — every one below
// always returns the same spec-legal value regardless of arguments.

pub fn digest_key(session: u32, key: u32) -> u32 {
    ffi::C_DigestKey(session, key)
}
pub fn get_operation_state(session: u32) -> u32 {
    ffi::C_GetOperationState(session, core::ptr::null_mut(), core::ptr::null_mut())
}
pub fn set_operation_state(session: u32) -> u32 {
    ffi::C_SetOperationState(session, core::ptr::null_mut(), 0, 0, 0)
}
pub fn get_function_status(session: u32) -> u32 {
    ffi::C_GetFunctionStatus(session)
}
pub fn cancel_function(session: u32) -> u32 {
    ffi::C_CancelFunction(session)
}
pub fn async_complete(session: u32) -> u32 {
    ffi::C_AsyncComplete(session, core::ptr::null_mut(), core::ptr::null_mut())
}
pub fn async_get_id(session: u32) -> u32 {
    let mut id: u32 = 0;
    ffi::C_AsyncGetID(session, core::ptr::null_mut(), &mut id)
}
pub fn async_join(session: u32, id: u32, data: &[u8]) -> u32 {
    ffi::C_AsyncJoin(session, core::ptr::null_mut(), id, data.as_ptr() as *mut u8, data.len() as u32)
}

// ── recover + verify-with-signature (RW6a slice) ─────────────────────────

pub fn sign_recover_init(session: u32, mechanism: u64, parameter: &[u8], key: u32) -> u32 {
    let mech = mech_native(mechanism, parameter);
    ffi::C_SignRecoverInit(session, &mech as *const _ as *mut u8, key)
}
pub fn sign_recover(session: u32, data: &[u8]) -> (u32, Vec<u8>) {
    two_call(|out, len| {
        ffi::C_SignRecover(session, data.as_ptr() as *mut u8, data.len() as u32, out, len)
    })
}
pub fn verify_recover_init(session: u32, mechanism: u64, parameter: &[u8], key: u32) -> u32 {
    let mech = mech_native(mechanism, parameter);
    ffi::C_VerifyRecoverInit(session, &mech as *const _ as *mut u8, key)
}
pub fn verify_recover(session: u32, signature: &[u8]) -> (u32, Vec<u8>) {
    two_call(|out, len| {
        ffi::C_VerifyRecover(session, signature.as_ptr() as *mut u8, signature.len() as u32, out, len)
    })
}
pub fn verify_signature_init(
    session: u32,
    mechanism: u64,
    parameter: &[u8],
    key: u32,
    signature: &[u8],
) -> u32 {
    let mech = mech_native(mechanism, parameter);
    ffi::C_VerifySignatureInit(
        session,
        &mech as *const _ as *mut u8,
        key,
        signature.as_ptr() as *mut u8,
        signature.len() as u32,
    )
}
pub fn verify_signature(session: u32, data: &[u8]) -> u32 {
    ffi::C_VerifySignature(session, data.as_ptr() as *mut u8, data.len() as u32)
}

// ── dual-function quartet (RW6a slice) ───────────────────────────────────

pub fn digest_encrypt_update(session: u32, part: &[u8]) -> (u32, Vec<u8>) {
    two_call(|out, len| {
        ffi::C_DigestEncryptUpdate(session, part.as_ptr() as *mut u8, part.len() as u32, out, len)
    })
}
pub fn decrypt_digest_update(session: u32, part: &[u8]) -> (u32, Vec<u8>) {
    two_call(|out, len| {
        ffi::C_DecryptDigestUpdate(session, part.as_ptr() as *mut u8, part.len() as u32, out, len)
    })
}
pub fn sign_encrypt_update(session: u32, part: &[u8]) -> (u32, Vec<u8>) {
    two_call(|out, len| {
        ffi::C_SignEncryptUpdate(session, part.as_ptr() as *mut u8, part.len() as u32, out, len)
    })
}
pub fn decrypt_verify_update(session: u32, part: &[u8]) -> (u32, Vec<u8>) {
    two_call(|out, len| {
        ffi::C_DecryptVerifyUpdate(session, part.as_ptr() as *mut u8, part.len() as u32, out, len)
    })
}

// ── message sign (RW6b slice) ────────────────────────────────────────────
// §5.14: pParam/ulParamLen are always ignored by this engine for sign
// mechanisms (verified against `ffi::C_SignMessage`/`C_SignMessageNext`'s
// own `_p_param` naming) — every call below passes NULL/0.

pub fn message_sign_init(session: u32, mechanism: u64, parameter: &[u8], key: u32) -> u32 {
    let mech = mech_native(mechanism, parameter);
    ffi::C_MessageSignInit(session, &mech as *const _ as *mut u8, key)
}
pub fn sign_message(session: u32, data: &[u8]) -> (u32, Vec<u8>) {
    two_call(|out, len| {
        ffi::C_SignMessage(session, core::ptr::null_mut(), 0, data.as_ptr() as *mut u8, data.len() as u32, out, len)
    })
}
pub fn message_sign_final(session: u32) -> u32 {
    ffi::C_MessageSignFinal(session)
}
pub fn sign_message_begin(session: u32) -> u32 {
    ffi::C_SignMessageBegin(session, core::ptr::null_mut(), 0)
}
/// `is_final = false`: accumulate `part`, return `(ck_rv, Vec::new())`.
/// `is_final = true`: assemble the accumulated message + `part`, sign, and
/// return the signature — the engine restores sign state across the
/// internal two-call length-query/produce pair itself (§5.14), so this is
/// exactly `two_call` over `C_SignMessageNext`'s final-part form.
pub fn sign_message_next(session: u32, part: &[u8], is_final: bool) -> (u32, Vec<u8>) {
    if !is_final {
        let rv = ffi::C_SignMessageNext(
            session,
            core::ptr::null_mut(),
            0,
            part.as_ptr() as *mut u8,
            part.len() as u32,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );
        return (rv, Vec::new());
    }
    two_call(|out, len| {
        ffi::C_SignMessageNext(session, core::ptr::null_mut(), 0, part.as_ptr() as *mut u8, part.len() as u32, out, len)
    })
}

// ── message verify (RW6b slice) ──────────────────────────────────────────

pub fn message_verify_init(session: u32, mechanism: u64, parameter: &[u8], key: u32) -> u32 {
    let mech = mech_native(mechanism, parameter);
    ffi::C_MessageVerifyInit(session, &mech as *const _ as *mut u8, key)
}
pub fn verify_message(session: u32, data: &[u8], signature: &[u8]) -> u32 {
    ffi::C_VerifyMessage(
        session,
        core::ptr::null_mut(),
        0,
        data.as_ptr() as *mut u8,
        data.len() as u32,
        signature.as_ptr() as *mut u8,
        signature.len() as u32,
    )
}
pub fn message_verify_final(session: u32) -> u32 {
    ffi::C_MessageVerifyFinal(session)
}
pub fn verify_message_begin(session: u32) -> u32 {
    ffi::C_VerifyMessageBegin(session, core::ptr::null_mut(), 0)
}
/// `signature: None` — accumulate `part` (non-final). `signature: Some(_)`
/// — assemble accumulated + `part` and verify against it (final).
pub fn verify_message_next(session: u32, part: &[u8], signature: Option<&[u8]>) -> u32 {
    match signature {
        None => ffi::C_VerifyMessageNext(
            session,
            core::ptr::null_mut(),
            0,
            part.as_ptr() as *mut u8,
            part.len() as u32,
            core::ptr::null_mut(),
            0,
        ),
        Some(sig) => ffi::C_VerifyMessageNext(
            session,
            core::ptr::null_mut(),
            0,
            part.as_ptr() as *mut u8,
            part.len() as u32,
            sig.as_ptr() as *mut u8,
            sig.len() as u32,
        ),
    }
}

// ── message encrypt (RW6b slice — GcmMessage, see `GcmMessageParams`) ────
// This engine supports exactly one message-AEAD mechanism, CKM_AES_GCM
// (`ffi::msg_encrypt_init_internal` hard-rejects anything else with
// CKR_MECHANISM_INVALID) — the RW-P "GcmMessage" variant is therefore the
// ONLY structured mechanism-parameter shape RW6b needs.

pub fn message_encrypt_init(session: u32, mechanism: u64, parameter: &[u8], key: u32) -> u32 {
    let mech = mech_native(mechanism, parameter);
    ffi::C_MessageEncryptInit(session, &mech as *const _ as *mut u8, key)
}

/// One-shot `C_EncryptMessage`. Returns `(ck_rv, ciphertext, tag, iv_used)`
/// — `iv_used` echoes back the caller's `iv` unchanged when
/// `iv_generator == 0`, or the engine-generated IV when it doesn't (the
/// caller needs it to decrypt later either way).
pub fn encrypt_message(
    session: u32,
    iv: &[u8],
    iv_generator: u32,
    aad: &[u8],
    plaintext: &[u8],
    tag_bits: u32,
) -> (u32, Vec<u8>, Vec<u8>, Vec<u8>) {
    let params = GcmMessageParams::new(iv, iv_generator, tag_bits, &[]);
    let (rv, ciphertext) = two_call(|out, len| {
        ffi::C_EncryptMessage(
            session,
            params.as_ptr(),
            0,
            aad.as_ptr(),
            aad.len() as u32,
            plaintext.as_ptr(),
            plaintext.len() as u32,
            out,
            len,
        )
    });
    (rv, ciphertext, params.tag().to_vec(), params.iv().to_vec())
}

pub fn message_encrypt_final(session: u32) -> u32 {
    ffi::C_MessageEncryptFinal(session)
}

/// `C_EncryptMessageBegin`. Returns `(ck_rv, iv_used)` — `tag_bits` is
/// carried through to the armed stream for the final `Next` call to use;
/// it is otherwise unread at Begin time (verified against
/// `ffi::C_EncryptMessageBegin`'s own `_p_tag` discard).
pub fn encrypt_message_begin(
    session: u32,
    iv: &[u8],
    iv_generator: u32,
    aad: &[u8],
    tag_bits: u32,
) -> (u32, Vec<u8>) {
    let params = GcmMessageParams::new(iv, iv_generator, tag_bits, &[]);
    let rv = ffi::C_EncryptMessageBegin(session, params.as_ptr(), 0, aad.as_ptr(), aad.len() as u32);
    (rv, params.iv().to_vec())
}

/// `C_EncryptMessageNext`. `is_final = false`: ordinary streamed part, no
/// mechanism-parameter struct needed (verified — the engine only
/// dereferences `pParameter` when `CKF_END_OF_MESSAGE` is set). `is_final
/// = true`: needs a `GcmMessageParams` whose `pTag` (word 4) is a real
/// writable buffer — only that one field is read at this call (verified
/// against the native-width offset comment in `ffi::C_EncryptMessageNext`
/// itself); the other words are unused here. Returns `(ck_rv,
/// ciphertext_part, tag_if_final)`.
pub fn encrypt_message_next(
    session: u32,
    plaintext_part: &[u8],
    is_final: bool,
    tag_bits: u32,
) -> (u32, Vec<u8>, Option<Vec<u8>>) {
    const CKF_END_OF_MESSAGE: u32 = 0x0000_0001;
    if !is_final {
        let (rv, ct) = two_call(|out, len| {
            ffi::C_EncryptMessageNext(
                session,
                core::ptr::null_mut(),
                0,
                plaintext_part.as_ptr(),
                plaintext_part.len() as u32,
                out,
                len,
                0,
            )
        });
        return (rv, ct, None);
    }
    let params = GcmMessageParams::new(&[], 0, tag_bits, &[]);
    let (rv, ct) = two_call(|out, len| {
        ffi::C_EncryptMessageNext(
            session,
            params.as_ptr(),
            0,
            plaintext_part.as_ptr(),
            plaintext_part.len() as u32,
            out,
            len,
            CKF_END_OF_MESSAGE,
        )
    });
    (rv, ct, Some(params.tag().to_vec()))
}

// ── message decrypt (RW6b slice) ─────────────────────────────────────────

pub fn message_decrypt_init(session: u32, mechanism: u64, parameter: &[u8], key: u32) -> u32 {
    let mech = mech_native(mechanism, parameter);
    ffi::C_MessageDecryptInit(session, &mech as *const _ as *mut u8, key)
}

/// One-shot `C_DecryptMessage`. `tag` is the CALLER-supplied expected tag
/// (the engine reads it to verify — auth failure zeroizes the plaintext
/// server-side before returning a non-OK code, per `ffi::aes_gcm_exec`).
pub fn decrypt_message(
    session: u32,
    iv: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag_bits: u32,
    tag: &[u8],
) -> (u32, Vec<u8>) {
    let params = GcmMessageParams::new(iv, 0, tag_bits, tag);
    two_call(|out, len| {
        ffi::C_DecryptMessage(
            session,
            params.as_ptr(),
            0,
            aad.as_ptr(),
            aad.len() as u32,
            ciphertext.as_ptr(),
            ciphertext.len() as u32,
            out,
            len,
        )
    })
}

pub fn message_decrypt_final(session: u32) -> u32 {
    ffi::C_MessageDecryptFinal(session)
}

pub fn decrypt_message_begin(session: u32, iv: &[u8], aad: &[u8], tag_bits: u32) -> u32 {
    let params = GcmMessageParams::new(iv, 0, tag_bits, &[]);
    ffi::C_DecryptMessageBegin(session, params.as_ptr(), 0, aad.as_ptr(), aad.len() as u32)
}

/// `is_final = true` needs the CALLER-supplied expected `tag` (see
/// `decrypt_message`'s doc) at word 4 — same one-field-only shape as
/// `encrypt_message_next`.
pub fn decrypt_message_next(
    session: u32,
    ciphertext_part: &[u8],
    is_final: bool,
    tag_bits: u32,
    tag: &[u8],
) -> (u32, Vec<u8>) {
    const CKF_END_OF_MESSAGE: u32 = 0x0000_0001;
    if !is_final {
        return two_call(|out, len| {
            ffi::C_DecryptMessageNext(
                session,
                core::ptr::null_mut(),
                0,
                ciphertext_part.as_ptr(),
                ciphertext_part.len() as u32,
                out,
                len,
                0,
            )
        });
    }
    let params = GcmMessageParams::new(&[], 0, tag_bits, tag);
    two_call(|out, len| {
        ffi::C_DecryptMessageNext(
            session,
            params.as_ptr(),
            0,
            ciphertext_part.as_ptr(),
            ciphertext_part.len() as u32,
            out,
            len,
            CKF_END_OF_MESSAGE,
        )
    })
}

// ── wrap / unwrap (RW4 slice) ────────────────────────────────────────────
// Native-width audited: same shape as every other keyed-mechanism verb.
// AES-KEY-WRAP/KWP and AES-CBC both take parameter-less-or-raw-IV bytes —
// already fully representable via the existing `V32Mechanism` raw
// `parameter` field, no RW-P struct needed here at all.

pub fn wrap_key(session: u32, mechanism: u64, parameter: &[u8], wrapping_key: u32, key: u32) -> (u32, Vec<u8>) {
    let mech = mech_native(mechanism, parameter);
    two_call(|out, len| {
        ffi::C_WrapKey(session, &mech as *const _ as *mut u8, wrapping_key, key, out, len)
    })
}

pub fn unwrap_key(
    session: u32,
    mechanism: u64,
    parameter: &[u8],
    unwrapping_key: u32,
    wrapped_key: &[u8],
    template: &[AttrIn],
) -> (u32, u32) {
    let mech = mech_native(mechanism, parameter);
    let mut tmpl = build_template(template);
    let mut handle: u32 = 0;
    let rv = ffi::C_UnwrapKey(
        session,
        &mech as *const _ as *mut u8,
        unwrapping_key,
        wrapped_key.as_ptr() as *mut u8,
        wrapped_key.len() as u32,
        tmpl.entries.as_mut_ptr() as *mut u8,
        template.len() as u32,
        &mut handle,
    );
    (rv, handle)
}

pub fn wrap_key_authenticated(
    session: u32,
    mechanism: u64,
    parameter: &[u8],
    wrapping_key: u32,
    key: u32,
    associated_data: &[u8],
) -> (u32, Vec<u8>) {
    let mech = mech_native(mechanism, parameter);
    two_call(|out, len| {
        ffi::C_WrapKeyAuthenticated(
            session,
            &mech as *const _ as *mut u8,
            wrapping_key,
            key,
            associated_data.as_ptr() as *mut u8,
            associated_data.len() as u32,
            out,
            len,
        )
    })
}

pub fn unwrap_key_authenticated(
    session: u32,
    mechanism: u64,
    parameter: &[u8],
    unwrapping_key: u32,
    wrapped_key: &[u8],
    template: &[AttrIn],
    associated_data: &[u8],
) -> (u32, u32) {
    let mech = mech_native(mechanism, parameter);
    let mut tmpl = build_template(template);
    let mut handle: u32 = 0;
    let rv = ffi::C_UnwrapKeyAuthenticated(
        session,
        &mech as *const _ as *mut u8,
        unwrapping_key,
        wrapped_key.as_ptr() as *mut u8,
        wrapped_key.len() as u32,
        tmpl.entries.as_mut_ptr() as *mut u8,
        template.len() as u32,
        associated_data.as_ptr() as *mut u8,
        associated_data.len() as u32,
        &mut handle,
    );
    (rv, handle)
}

// ── derive (RW4 slice — the RW-P derive-family variants) ────────────────
//
// `derive_key` itself is mechanism-agnostic: it takes pre-built mechanism
// parameter bytes (from `mech_native`'s raw form OR one of the
// `derive_params::*` builders below) and calls `ffi::C_DeriveKey`
// directly, exactly like every other verb in this module. The complexity
// lives entirely in constructing the RIGHT native bytes per mechanism —
// isolated in `derive_params` so `derive_key` itself stays a two-line
// audit-then-call function.

pub fn derive_key(
    session: u32,
    mechanism: u64,
    parameter: &[u8],
    base_key: u32,
    template: &[AttrIn],
) -> (u32, u32) {
    let mech = mech_native(mechanism, parameter);
    let mut tmpl = build_template(template);
    let mut handle: u32 = 0;
    let rv = ffi::C_DeriveKey(
        session,
        &mech as *const _ as *mut u8,
        base_key,
        tmpl.entries.as_mut_ptr() as *mut u8,
        template.len() as u32,
        &mut handle,
    );
    (rv, handle)
}

/// RW-P derive-family mechanism-parameter builders. Each returns the
/// native-layout bytes for one `CK_*_PARAMS` struct, built via
/// `StructBuilder` against `softhsmrustv3::ck_param`'s own declared
/// layouts — the same source of truth `ffi::C_DeriveKey`'s dispatch reads
/// from, so these cannot drift from the engine's own field offsets.
pub mod derive_params {
    use super::{ck_param, StructBuilder};

    /// `CK_ECDH1_DERIVE_PARAMS` (v3.2 §6.3.17). `kdf`: `CKD_NULL = 1` for
    /// the raw shared secret; see the spec for the X9.63 KDF codepoints.
    /// `public_data` is the peer's EC public key (raw SEC1 or DER-OCTET-
    /// STRING-wrapped — the engine accepts either, per its own comment).
    pub fn ecdh1(kdf: u32, shared_data: &[u8], public_data: &[u8]) -> StructBuilder {
        let mut b = StructBuilder::new(ck_param::ecdh1::LAYOUT.fields);
        b.set_ulong(ck_param::ecdh1::KDF, kdf as usize);
        b.set_buf_pair(ck_param::ecdh1::P_SHARED_DATA, ck_param::ecdh1::UL_SHARED_DATA_LEN, shared_data);
        b.set_buf_pair(ck_param::ecdh1::P_PUBLIC_DATA, ck_param::ecdh1::UL_PUBLIC_DATA_LEN, public_data);
        b
    }

    /// `CK_HKDF_PARAMS` (v3.2 §6.45). `salt`/`h_salt_key`: exactly one of
    /// these should be meaningful per `ul_salt_type`'s spec-defined values
    /// (`CKF_HKDF_SALT_DATA = 1`, `CKF_HKDF_SALT_KEY = 2`,
    /// `CKF_HKDF_SALT_NULL = 0`) — the caller picks which by what it fills
    /// in; both are always written for a fixed, predictable layout.
    #[allow(clippy::too_many_arguments)]
    pub fn hkdf(
        extract: bool,
        expand: bool,
        prf_hash_mechanism: u64,
        salt_type: u32,
        salt: &[u8],
        h_salt_key: u32,
        info: &[u8],
    ) -> StructBuilder {
        let mut b = StructBuilder::new(ck_param::hkdf::LAYOUT.fields);
        b.set_bbool(ck_param::hkdf::B_EXTRACT, extract);
        b.set_bbool(ck_param::hkdf::B_EXPAND, expand);
        b.set_ulong(ck_param::hkdf::PRF_HASH_MECHANISM, prf_hash_mechanism as usize);
        b.set_ulong(ck_param::hkdf::UL_SALT_TYPE, salt_type as usize);
        b.set_buf_pair(ck_param::hkdf::P_SALT, ck_param::hkdf::UL_SALT_LEN, salt);
        b.set_ulong(ck_param::hkdf::H_SALT_KEY, h_salt_key as usize);
        b.set_buf_pair(ck_param::hkdf::P_INFO, ck_param::hkdf::UL_INFO_LEN, info);
        b
    }

    /// `CK_PKCS5_PBKD2_PARAMS2` (v3.2 §6.38). `salt_source`:
    /// `CKZ_SALT_SPECIFIED = 1` is this spec's only defined value.
    #[allow(clippy::too_many_arguments)]
    pub fn pbkd2(
        salt_source: u32,
        salt_source_data: &[u8],
        iterations: u32,
        prf: u64,
        prf_data: &[u8],
        password: &[u8],
    ) -> StructBuilder {
        let mut b = StructBuilder::new(ck_param::pbkd2::LAYOUT.fields);
        b.set_ulong(ck_param::pbkd2::SALT_SOURCE, salt_source as usize);
        b.set_buf_pair(ck_param::pbkd2::P_SALT_SOURCE_DATA, ck_param::pbkd2::UL_SALT_SOURCE_DATA_LEN, salt_source_data);
        b.set_ulong(ck_param::pbkd2::ITERATIONS, iterations as usize);
        b.set_ulong(ck_param::pbkd2::PRF, prf as usize);
        b.set_buf_pair(ck_param::pbkd2::P_PRF_DATA, ck_param::pbkd2::UL_PRF_DATA_LEN, prf_data);
        b.set_buf_pair(ck_param::pbkd2::P_PASSWORD, ck_param::pbkd2::UL_PASSWORD_LEN, password);
        b
    }

    /// `CK_KEY_DERIVATION_STRING_DATA` (v3.2 §6.43.4) — the parameter for
    /// `CKM_CONCATENATE_BASE_AND_DATA`/`CKM_XOR_BASE_AND_DATA`.
    pub fn key_derivation_string_data(data: &[u8]) -> StructBuilder {
        let mut b = StructBuilder::new(ck_param::key_deriv_string::LAYOUT.fields);
        b.set_buf_pair(ck_param::key_deriv_string::P_DATA, ck_param::key_deriv_string::UL_LEN, data);
        b
    }

    /// `CK_SP800_108_COUNTER_FORMAT` (v3.2 §6.42) — one
    /// `CK_SP800_108_OPTIONAL_COUNTER` segment's own value bytes. Has no
    /// pointer fields (Bbool + Ulong only), so — unlike every other
    /// builder here — it is genuinely safe to return as a self-contained
    /// `Vec<u8>`: nothing in it points outside itself.
    pub fn counter_format(little_endian: bool, width_in_bits: u32) -> Vec<u8> {
        let mut b = StructBuilder::new(ck_param::counter_format::LAYOUT.fields);
        b.set_bbool(ck_param::counter_format::B_LITTLE_ENDIAN, little_endian);
        b.set_ulong(ck_param::counter_format::UL_WIDTH_IN_BITS, width_in_bits as usize);
        b.bytes
    }

    /// One SP800-108 data-parameter segment before it's packed into the
    /// array `sp800_108_counter`/`sp800_108_feedback` build. `prf_type`:
    /// the spec's `CK_SP800_108_*` codepoints
    /// (`CK_SP800_108_ITERATION_VARIABLE = 1`,
    /// `CK_SP800_108_OPTIONAL_COUNTER = 2`, `CK_SP800_108_DKM_LENGTH = 3`,
    /// `CK_SP800_108_BYTE_ARRAY = 4`). `value`: for
    /// `CK_SP800_108_OPTIONAL_COUNTER`, a `counter_format()` blob; for
    /// `CK_SP800_108_BYTE_ARRAY`, raw label/context bytes;
    /// `CK_SP800_108_ITERATION_VARIABLE` needs no value (pass `&[]`).
    pub struct Segment {
        pub prf_type: u32,
        pub value: Vec<u8>,
    }

    /// Packs `segments` into one `CK_PRF_DATA_PARAM[]` array INSIDE
    /// `owner` — every segment's `value` bytes are pushed into `owner`'s
    /// own `owned` list first (via `set_buf`, called once per segment on
    /// a throwaway single-field write, discarded — only its side effect
    /// of stashing the buffer in `owner.owned` matters), so their
    /// addresses are stable for `owner`'s entire lifetime before the
    /// array's `pValue` entries are computed from those SAME stored
    /// addresses. This is the two-phase "collect owned buffers, then
    /// take pointers into them" discipline `NativeTemplate`/
    /// `build_template` already established — a single-phase "take
    /// pointer, push, repeat" loop here would be equally sound (moving a
    /// `Vec<u8>` doesn't relocate its heap buffer), but keeping the two
    /// phases explicit makes that invariant obvious at the call site
    /// rather than relying on the reader knowing it.
    fn pack_prf_data_params(owner: &mut StructBuilder, segments: Vec<Segment>) -> Vec<u8> {
        let elem_fields = ck_param::prf_data_param::LAYOUT.fields;
        let elem_size = ck_param::size_at(elem_fields, ck_param::WORD);
        let type_off = ck_param::offset_at(elem_fields, ck_param::prf_data_param::TYPE, ck_param::WORD);
        let ptr_off = ck_param::offset_at(elem_fields, ck_param::prf_data_param::P_VALUE, ck_param::WORD);
        let len_off = ck_param::offset_at(elem_fields, ck_param::prf_data_param::UL_VALUE_LEN, ck_param::WORD);

        // Phase 1: stash every segment's value bytes in `owner.owned` —
        // stable addresses from this point on.
        let first_idx = owner.owned.len();
        for seg in &segments {
            owner.owned.push(seg.value.clone());
        }

        // Phase 2: write the array using addresses read back from those
        // now-stored buffers (never from `segments` itself).
        let mut array = vec![0u8; elem_size * segments.len()];
        for (i, seg) in segments.iter().enumerate() {
            let base = i * elem_size;
            array[base + type_off..base + type_off + ck_param::WORD]
                .copy_from_slice(&(seg.prf_type as usize).to_ne_bytes());
            let stored = &owner.owned[first_idx + i];
            let ptr = if stored.is_empty() { 0 } else { stored.as_ptr() as usize };
            array[base + ptr_off..base + ptr_off + ck_param::WORD].copy_from_slice(&ptr.to_ne_bytes());
            array[base + len_off..base + len_off + ck_param::WORD]
                .copy_from_slice(&stored.len().to_ne_bytes());
        }
        array
    }

    /// `CK_SP800_108_KDF_PARAMS` (v3.2 §6.42, counter-mode). This engine
    /// reads only the first three fields (`prf_type`,
    /// `ul_number_of_data_params`, `p_data_params`) — the
    /// additional-derived-key tail is not implemented, so it is written as
    /// zero (no additional keys requested).
    pub fn sp800_108_counter(prf_type: u64, segments: Vec<Segment>) -> StructBuilder {
        let mut b = StructBuilder::new(ck_param::sp800_108_kdf::LAYOUT.fields);
        b.set_ulong(ck_param::sp800_108_kdf::PRF_TYPE, prf_type as usize);
        b.set_ulong(ck_param::sp800_108_kdf::UL_NUMBER_OF_DATA_PARAMS, segments.len());
        let array = pack_prf_data_params(&mut b, segments);
        b.set_buf(ck_param::sp800_108_kdf::P_DATA_PARAMS, array);
        b.set_ulong(ck_param::sp800_108_kdf::UL_ADDITIONAL_DERIVED_KEYS, 0);
        b
    }

    /// `CK_SP800_108_FEEDBACK_KDF_PARAMS` (v3.2 §6.42) — same shape as
    /// counter-mode plus an IV; additional-derived-keys likewise zeroed.
    pub fn sp800_108_feedback(prf_type: u64, segments: Vec<Segment>, iv: &[u8]) -> StructBuilder {
        let mut b = StructBuilder::new(ck_param::sp800_108_feedback::LAYOUT.fields);
        b.set_ulong(ck_param::sp800_108_feedback::PRF_TYPE, prf_type as usize);
        b.set_ulong(ck_param::sp800_108_feedback::UL_NUMBER_OF_DATA_PARAMS, segments.len());
        let array = pack_prf_data_params(&mut b, segments);
        b.set_buf(ck_param::sp800_108_feedback::P_DATA_PARAMS, array);
        b.set_buf_pair(ck_param::sp800_108_feedback::P_IV, ck_param::sp800_108_feedback::UL_IV_LEN, iv);
        b.set_ulong(ck_param::sp800_108_feedback::UL_ADDITIONAL_DERIVED_KEYS, 0);
        b
    }
}

// ── helpers ────────────────────────────────────────────────────────────────

/// PKCS#11 §5.2 two-call convention driver: NULL query for the length,
/// allocate, then the real call. Passes through every non-OK code from
/// either call verbatim.
fn two_call(mut call: impl FnMut(*mut u8, *mut u32) -> u32) -> (u32, Vec<u8>) {
    let mut len: u32 = 0;
    let rv = call(core::ptr::null_mut(), &mut len);
    if rv != 0 {
        return (rv, Vec::new());
    }
    let mut buf = vec![0u8; len as usize];
    let rv = call(buf.as_mut_ptr(), &mut len);
    if rv != 0 {
        return (rv, Vec::new());
    }
    buf.truncate(len as usize);
    (rv, buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    #[serial]
    fn session_open_close_and_invalid_handle_codes_are_real() {
        crate::test_support::ensure_bootstrapped();
        let (rv, session) = open_session(SLOT, ck::CKF_SERIAL_SESSION | ck::CKF_RW_SESSION);
        assert_eq!(rv, 0);
        assert_eq!(close_session(session), 0);
        // Double close — the engine's own code, not a mapped one.
        assert_eq!(close_session(session), ck::CKR_SESSION_HANDLE_INVALID);
        // §5.6: CKF_SERIAL_SESSION is mandatory.
        let (rv, _) = open_session(SLOT, 0);
        assert_eq!(rv, ck::CKR_SESSION_PARALLEL_NOT_SUPPORTED);
    }

    #[test]
    #[serial]
    fn digest_matches_local_oracle_and_fsm_equals_one_shot() {
        crate::test_support::ensure_bootstrapped();
        let (rv, session) = open_session(SLOT, ck::CKF_SERIAL_SESSION | ck::CKF_RW_SESSION);
        assert_eq!(rv, 0);
        let data = b"v32 digest parity input";
        let (rv, one_shot) = digest(session, u64::from(ck::CKM_SHA256), &[], data);
        assert_eq!(rv, 0);
        // Independent oracle — sha2 crate, not the engine.
        use sha2::Digest as _;
        assert_eq!(one_shot, sha2::Sha256::digest(data).to_vec());
        // FSM path over two chunks equals the one-shot.
        assert_eq!(digest_init(session, u64::from(ck::CKM_SHA256), &[]), 0);
        assert_eq!(digest_update(session, &data[..5]), 0);
        assert_eq!(digest_update(session, &data[5..]), 0);
        let (rv, streamed) = digest_final(session);
        assert_eq!(rv, 0);
        assert_eq!(streamed, one_shot);
        close_session(session);
    }

    #[test]
    #[serial]
    fn ml_dsa_sign_fsm_and_one_shot_verify_with_real_signature_invalid_code() {
        crate::test_support::ensure_bootstrapped();
        let fixture = crate::test_support::fresh_session();
        let (_pub_h, prv_h) = crate::verbs::generate_key_pair(
            fixture,
            crate::Algorithm::MlDsa65,
            b"v32-mldsa",
            "v32-mldsa",
        )
        .expect("keygen fixture");
        let (rv, session) = open_session(SLOT, ck::CKF_SERIAL_SESSION | ck::CKF_RW_SESSION);
        assert_eq!(rv, 0);
        let msg = b"v32 mirror sign/verify";
        assert_eq!(sign_init(session, u64::from(ck::CKM_ML_DSA), &[], prv_h), 0);
        let (rv, sig) = sign(session, msg);
        assert_eq!(rv, 0);
        assert_eq!(sig.len(), 3309, "FIPS 204 ML-DSA-65 signature size");
        // Verify via the mirror too — and prove the REAL CKR_SIGNATURE_INVALID
        // comes back on tamper, as a return value, not an error mapping.
        let pub_h = _pub_h;
        assert_eq!(verify_init(session, u64::from(ck::CKM_ML_DSA), &[], pub_h), 0);
        assert_eq!(verify(session, msg, &sig), 0);
        let mut bad = sig.clone();
        bad[100] ^= 0xFF;
        assert_eq!(verify_init(session, u64::from(ck::CKM_ML_DSA), &[], pub_h), 0);
        assert_eq!(verify(session, msg, &bad), ck::CKR_SIGNATURE_INVALID);
        // Multipart sign equals one-shot semantics: its output verifies.
        assert_eq!(sign_init(session, u64::from(ck::CKM_ML_DSA), &[], prv_h), 0);
        assert_eq!(sign_update(session, &msg[..7]), 0);
        assert_eq!(sign_update(session, &msg[7..]), 0);
        let (rv, sig2) = sign_final(session);
        assert_eq!(rv, 0);
        assert_eq!(verify_init(session, u64::from(ck::CKM_ML_DSA), &[], pub_h), 0);
        assert_eq!(verify(session, msg, &sig2), 0);
        close_session(session);
        crate::verbs::close_session(fixture).ok();
    }

    #[test]
    #[serial]
    fn get_attribute_value_consolidated_codes_match_spec_5_7_5() {
        crate::test_support::ensure_bootstrapped();
        let fixture = crate::test_support::fresh_session();
        let (pub_h, prv_h) = crate::verbs::generate_key_pair(
            fixture,
            crate::Algorithm::MlDsa65,
            b"v32-attrs",
            "v32-attrs",
        )
        .expect("keygen fixture");
        let (rv, session) = open_session(SLOT, ck::CKF_SERIAL_SESSION | ck::CKF_RW_SESSION);
        assert_eq!(rv, 0);
        // CKA_CLASS on the public key: available, and decodes to
        // CKO_PUBLIC_KEY. NOTE (found live, first run): ulong-typed
        // attribute VALUES come back at native CK_ULONG width (8 bytes on
        // LP64), little-endian — the engine's storage convention, matching
        // how a native C caller would read them. Wire consumers decode the
        // low 4 bytes.
        let (rv, attrs) = get_attribute_value(session, pub_h, &[u64::from(ck::CKA_CLASS)]);
        assert_eq!(rv, 0);
        assert!(attrs[0].available && attrs[0].value.len() >= 4);
        let class = u32::from_le_bytes(attrs[0].value[..4].try_into().unwrap());
        assert_eq!(class, softhsmrustv3::constants::CKO_PUBLIC_KEY);
        // CKA_VALUE on the sensitive private key → consolidated SENSITIVE,
        // entry unavailable — the engine's real §5.7.5 behavior end to end.
        let (rv, attrs) =
            get_attribute_value(session, prv_h, &[u64::from(ck::CKA_VALUE), u64::from(ck::CKA_CLASS)]);
        assert_eq!(rv, ck::CKR_ATTRIBUTE_SENSITIVE);
        assert!(!attrs[0].available);
        assert!(attrs[1].available, "the non-sensitive entry is still filled per §5.7.5");
        // An attribute the object does not possess → TYPE_INVALID.
        let (rv, attrs) = get_attribute_value(session, pub_h, &[0x9999u64]);
        assert_eq!(rv, ck::CKR_ATTRIBUTE_TYPE_INVALID);
        assert!(!attrs[0].available);
        close_session(session);
        crate::verbs::close_session(fixture).ok();
    }

    #[test]
    #[serial]
    fn mechanism_list_and_info_match_the_engine_table() {
        crate::test_support::ensure_bootstrapped();
        let (rv, mechs) = get_mechanism_list(SLOT);
        assert_eq!(rv, 0);
        assert_eq!(mechs.len(), ck::SUPPORTED_MECHS.len());
        assert!(mechs.contains(&u64::from(ck::CKM_ML_DSA)));
        // ML-DSA key-size range — the same values the C++ compliance suite's
        // G2MechTable category pins (1312/2592).
        let (rv, min, max, flags) = get_mechanism_info(SLOT, u64::from(ck::CKM_ML_DSA));
        assert_eq!(rv, 0);
        assert_eq!((min, max), (1312, 2592));
        assert_ne!(flags, 0);
        // Invalid slot behaves per §5.5.6.
        let (rv, _) = get_mechanism_list(99);
        assert_eq!(rv, softhsmrustv3::constants::CKR_SLOT_ID_INVALID);
    }

    #[test]
    #[serial]
    fn random_and_seed_codes_are_the_engines_own() {
        crate::test_support::ensure_bootstrapped();
        let (rv, session) = open_session(SLOT, ck::CKF_SERIAL_SESSION | ck::CKF_RW_SESSION);
        assert_eq!(rv, 0);
        let (rv, a) = generate_random(session, 32);
        assert_eq!(rv, 0);
        let (rv, b) = generate_random(session, 32);
        assert_eq!(rv, 0);
        assert_ne!(a, b, "two draws must differ");
        assert_eq!(seed_random(session, b"seed"), ck::CKR_RANDOM_SEED_NOT_SUPPORTED);
        let (rv, _) = generate_random(session, MAX_RANDOM_LEN + 1);
        assert_eq!(rv, ck::CKR_ARGUMENTS_BAD);
        close_session(session);
    }

    #[test]
    #[serial]
    fn generate_key_pair_template_signs_and_verifies_round_trip() {
        crate::test_support::ensure_bootstrapped();
        let session = open_session(SLOT, ck::CKF_SERIAL_SESSION | ck::CKF_RW_SESSION).1;
        let public_template = [
            attr_ulong(u64::from(ck::CKA_CLASS), ck::CKO_PUBLIC_KEY),
            attr_ulong(u64::from(ck::CKA_KEY_TYPE), ck::CKK_ML_DSA),
            attr_ulong(u64::from(ck::CKA_PARAMETER_SET), ck::CKP_ML_DSA_65),
            attr_bool(u64::from(ck::CKA_VERIFY), true),
            attr_bool(u64::from(ck::CKA_TOKEN), false),
        ];
        let private_template = [
            attr_ulong(u64::from(ck::CKA_CLASS), ck::CKO_PRIVATE_KEY),
            attr_ulong(u64::from(ck::CKA_KEY_TYPE), ck::CKK_ML_DSA),
            attr_ulong(u64::from(ck::CKA_PARAMETER_SET), ck::CKP_ML_DSA_65),
            attr_bool(u64::from(ck::CKA_SIGN), true),
            attr_bool(u64::from(ck::CKA_TOKEN), false),
        ];
        let (rv, pub_h, prv_h) = generate_key_pair(
            session,
            u64::from(ck::CKM_ML_DSA_KEY_PAIR_GEN),
            &[],
            &public_template,
            &private_template,
        );
        assert_eq!(rv, 0);
        assert_ne!(pub_h, 0);
        assert_ne!(prv_h, 0);

        let msg = b"RW2 template keygen round trip";
        assert_eq!(sign_init(session, u64::from(ck::CKM_ML_DSA), &[], prv_h), 0);
        let (rv, sig) = sign(session, msg);
        assert_eq!(rv, 0);
        assert_eq!(verify_init(session, u64::from(ck::CKM_ML_DSA), &[], pub_h), 0);
        assert_eq!(verify(session, msg, &sig), 0);
        close_session(session);
    }

    #[test]
    #[serial]
    fn generate_key_pair_template_reports_inconsistent_and_incomplete() {
        crate::test_support::ensure_bootstrapped();
        let session = open_session(SLOT, ck::CKF_SERIAL_SESSION | ck::CKF_RW_SESSION).1;
        // §G3Keygen: mismatched key-type between the two halves.
        let public_template = [
            attr_ulong(u64::from(ck::CKA_CLASS), ck::CKO_PUBLIC_KEY),
            attr_ulong(u64::from(ck::CKA_KEY_TYPE), ck::CKK_ML_DSA),
            attr_ulong(u64::from(ck::CKA_PARAMETER_SET), ck::CKP_ML_DSA_65),
        ];
        let private_template_wrong_type = [
            attr_ulong(u64::from(ck::CKA_CLASS), ck::CKO_PRIVATE_KEY),
            attr_ulong(u64::from(ck::CKA_KEY_TYPE), ck::CKK_AES),
            attr_ulong(u64::from(ck::CKA_PARAMETER_SET), ck::CKP_ML_DSA_65),
        ];
        let (rv, _, _) = generate_key_pair(
            session,
            u64::from(ck::CKM_ML_DSA_KEY_PAIR_GEN),
            &[],
            &public_template,
            &private_template_wrong_type,
        );
        assert_eq!(rv, ck::CKR_TEMPLATE_INCONSISTENT);

        // §G3Keygen: CKA_PARAMETER_SET missing entirely.
        let public_template_incomplete =
            [attr_ulong(u64::from(ck::CKA_CLASS), ck::CKO_PUBLIC_KEY), attr_ulong(u64::from(ck::CKA_KEY_TYPE), ck::CKK_ML_DSA)];
        let private_template_incomplete =
            [attr_ulong(u64::from(ck::CKA_CLASS), ck::CKO_PRIVATE_KEY), attr_ulong(u64::from(ck::CKA_KEY_TYPE), ck::CKK_ML_DSA)];
        let (rv, _, _) = generate_key_pair(
            session,
            u64::from(ck::CKM_ML_DSA_KEY_PAIR_GEN),
            &[],
            &public_template_incomplete,
            &private_template_incomplete,
        );
        assert_eq!(rv, ck::CKR_TEMPLATE_INCOMPLETE);
        close_session(session);
    }

    #[test]
    #[serial]
    fn generate_key_aes_symmetric_and_object_size() {
        crate::test_support::ensure_bootstrapped();
        let session = open_session(SLOT, ck::CKF_SERIAL_SESSION | ck::CKF_RW_SESSION).1;
        let template = [
            attr_ulong(u64::from(ck::CKA_CLASS), ck::CKO_SECRET_KEY),
            attr_ulong(u64::from(ck::CKA_KEY_TYPE), ck::CKK_AES),
            attr_ulong(u64::from(ck::CKA_VALUE_LEN), 32),
            attr_bool(u64::from(ck::CKA_TOKEN), false),
        ];
        let (rv, handle) = generate_key(session, u64::from(ck::CKM_AES_KEY_GEN), &[], &template);
        assert_eq!(rv, 0);
        assert_ne!(handle, 0);
        let (rv, size) = get_object_size(session, handle);
        assert_eq!(rv, 0);
        assert!(size > 0);
        close_session(session);
    }

    #[test]
    #[serial]
    fn create_object_find_objects_and_copy_object_round_trip() {
        crate::test_support::ensure_bootstrapped();
        let session = open_session(SLOT, ck::CKF_SERIAL_SESSION | ck::CKF_RW_SESSION).1;
        let key_bytes = vec![0x11u8; 16];
        let template = [
            attr_ulong(u64::from(ck::CKA_CLASS), ck::CKO_SECRET_KEY),
            attr_ulong(u64::from(ck::CKA_KEY_TYPE), ck::CKK_AES),
            attr_bool(u64::from(ck::CKA_TOKEN), false),
            (u64::from(ck::CKA_VALUE), key_bytes),
        ];
        let (rv, handle) = create_object(session, &template);
        assert_eq!(rv, 0);
        assert_ne!(handle, 0);

        let find_template = [attr_ulong(u64::from(ck::CKA_CLASS), ck::CKO_SECRET_KEY)];
        assert_eq!(find_objects_init(session, &find_template), 0);
        let (rv, handles) = find_objects(session, 10);
        assert_eq!(rv, 0);
        assert!(handles.contains(&handle));
        assert_eq!(find_objects_final(session), 0);

        let (rv, copy_handle) = copy_object(session, handle, &[]);
        assert_eq!(rv, 0);
        assert_ne!(copy_handle, handle);
        let (rv, _) = get_object_size(session, copy_handle);
        assert_eq!(rv, 0);
        close_session(session);
    }

    #[test]
    #[serial]
    fn set_attribute_value_empty_template_ok_invalid_object_is_handle_invalid() {
        crate::test_support::ensure_bootstrapped();
        let session = open_session(SLOT, ck::CKF_SERIAL_SESSION | ck::CKF_RW_SESSION).1;
        let template = [
            attr_ulong(u64::from(ck::CKA_CLASS), ck::CKO_SECRET_KEY),
            attr_ulong(u64::from(ck::CKA_KEY_TYPE), ck::CKK_AES),
            attr_bool(u64::from(ck::CKA_TOKEN), false),
            (u64::from(ck::CKA_VALUE), vec![0x22u8; 16]),
        ];
        let (rv, handle) = create_object(session, &template);
        assert_eq!(rv, 0);
        assert_eq!(set_attribute_value(session, handle, &[]), 0);
        assert_eq!(set_attribute_value(session, 0xFFFF_FFFE, &[]), ck::CKR_OBJECT_HANDLE_INVALID);
        close_session(session);
    }

    #[test]
    #[serial]
    fn aes_ecb_encrypt_decrypt_round_trip_and_data_len_range() {
        crate::test_support::ensure_bootstrapped();
        let session = open_session(SLOT, ck::CKF_SERIAL_SESSION | ck::CKF_RW_SESSION).1;
        let template = [
            attr_ulong(u64::from(ck::CKA_CLASS), ck::CKO_SECRET_KEY),
            attr_ulong(u64::from(ck::CKA_KEY_TYPE), ck::CKK_AES),
            attr_ulong(u64::from(ck::CKA_VALUE_LEN), 32),
            attr_bool(u64::from(ck::CKA_ENCRYPT), true),
            attr_bool(u64::from(ck::CKA_DECRYPT), true),
            attr_bool(u64::from(ck::CKA_TOKEN), false),
        ];
        let (rv, key) = generate_key(session, u64::from(ck::CKM_AES_KEY_GEN), &[], &template);
        assert_eq!(rv, 0);

        let plaintext = vec![0x42u8; 32]; // two AES blocks — CKM_AES_ECB needs no IV/param
        assert_eq!(encrypt_init(session, u64::from(ck::CKM_AES_ECB), &[], key), 0);
        let (rv, ciphertext) = encrypt(session, &plaintext);
        assert_eq!(rv, 0);
        assert_eq!(ciphertext.len(), plaintext.len());
        assert_ne!(ciphertext, plaintext);

        assert_eq!(decrypt_init(session, u64::from(ck::CKM_AES_ECB), &[], key), 0);
        let (rv, roundtrip) = decrypt(session, &ciphertext);
        assert_eq!(rv, 0);
        assert_eq!(roundtrip, plaintext);

        // §5.2: ECB has no padding — a non-block-multiple length is a real
        // engine-reported error, not a wire-layer guess.
        assert_eq!(encrypt_init(session, u64::from(ck::CKM_AES_ECB), &[], key), 0);
        let (rv, _) = encrypt(session, &[0x01u8; 5]);
        assert_eq!(rv, ck::CKR_DATA_LEN_RANGE);
        close_session(session);
    }

    #[test]
    #[serial]
    fn admin_info_and_slot_functions_are_real() {
        crate::test_support::ensure_bootstrapped();
        let (rv, info) = get_info();
        assert_eq!(rv, 0);
        assert_eq!(info.len(), 72);
        assert_eq!(&info[0..2], &[3, 2], "cryptokiVersion major.minor per C_GetInfo's own doc");

        let (rv, slots) = get_slot_list(false);
        assert_eq!(rv, 0);
        assert!(slots.contains(&SLOT));

        let (rv, slot_info) = get_slot_info(SLOT);
        assert_eq!(rv, 0);
        assert_eq!(slot_info.len(), 104);
        let (rv, _) = get_slot_info(9999);
        assert_eq!(rv, ck::CKR_SLOT_ID_INVALID);

        // §5.5: non-blocking poll on a token with no events → CKR_NO_EVENT.
        assert_eq!(wait_for_slot_event(ck::CKF_DONT_BLOCK), ck::CKR_NO_EVENT);

        let session = open_session(SLOT, ck::CKF_SERIAL_SESSION | ck::CKF_RW_SESSION).1;
        assert_eq!(session_cancel(session, 0), 0);
        assert_eq!(close_all_sessions(SLOT), 0);
        // The session this test opened is gone — closing again is the
        // engine's own real invalid-handle code, not a mapped one.
        assert_eq!(close_session(session), ck::CKR_SESSION_HANDLE_INVALID);

        // §5.6.3: closing the LAST session on a slot resets the token's
        // login state to Public and invalidates every private-key handle
        // on it (`reset_login_state_if_no_sessions` /
        // `invalidate_private_handles_on_slot`, ffi.rs). This process's
        // ONE shared bootstrap ("keep-alive") session lives on this same
        // slot (`native::bootstrap_default_token` opens it, logs it in as
        // USER, and never closes it — see `verbs::bootstrap`'s own doc) —
        // so `close_all_sessions` above just closed it too, real and
        // correctly. Every OTHER test in this binary depends on that
        // keep-alive login surviving for the process's lifetime, so this
        // test — the only one that legitimately exercises
        // C_CloseAllSessions — must restore it exactly as bootstrap
        // itself does: a fresh session, logged in as USER, left open.
        let (rv, keepalive) = open_session(SLOT, ck::CKF_SERIAL_SESSION | ck::CKF_RW_SESSION);
        assert_eq!(rv, 0);
        assert_eq!(login(keepalive, ck::CKU_USER, b"1234"), 0);
    }

    #[test]
    #[serial]
    fn honest_code_stubs_return_spec_mandated_codes() {
        crate::test_support::ensure_bootstrapped();
        let session = open_session(SLOT, ck::CKF_SERIAL_SESSION | ck::CKF_RW_SESSION).1;
        assert_eq!(digest_key(session, 0), ck::CKR_FUNCTION_NOT_SUPPORTED);
        assert_eq!(get_operation_state(session), ck::CKR_FUNCTION_NOT_SUPPORTED);
        assert_eq!(set_operation_state(session), ck::CKR_FUNCTION_NOT_SUPPORTED);
        assert_eq!(get_function_status(session), ck::CKR_FUNCTION_NOT_PARALLEL);
        assert_eq!(cancel_function(session), ck::CKR_FUNCTION_NOT_PARALLEL);
        assert_eq!(async_complete(session), ck::CKR_FUNCTION_NOT_SUPPORTED);
        assert_eq!(async_get_id(session), ck::CKR_FUNCTION_NOT_SUPPORTED);
        assert_eq!(async_join(session, 0, &[]), ck::CKR_FUNCTION_NOT_SUPPORTED);
        close_session(session);
    }

    #[test]
    #[serial]
    fn verify_signature_matches_verify_and_recover_rejects_non_rsa() {
        crate::test_support::ensure_bootstrapped();
        let fixture = crate::test_support::fresh_session();
        let (pub_h, prv_h) = crate::verbs::generate_key_pair(
            fixture,
            crate::Algorithm::MlDsa65,
            b"rw6a",
            "rw6a",
        )
        .expect("keygen fixture");

        let session = open_session(SLOT, ck::CKF_SERIAL_SESSION | ck::CKF_RW_SESSION).1;
        assert_eq!(sign_init(session, u64::from(ck::CKM_ML_DSA), &[], prv_h), 0);
        let (rv, sig) = sign(session, b"verify-signature RW6a");
        assert_eq!(rv, 0);

        // C_VerifySignatureInit/C_VerifySignature — the signature travels at
        // Init time instead of Verify time; must agree with the plain
        // Verify path on both the good signature and a tampered one.
        assert_eq!(
            verify_signature_init(session, u64::from(ck::CKM_ML_DSA), &[], pub_h, &sig),
            0
        );
        assert_eq!(verify_signature(session, b"verify-signature RW6a"), 0);

        let mut bad = sig.clone();
        bad[5] ^= 0xFF;
        assert_eq!(
            verify_signature_init(session, u64::from(ck::CKM_ML_DSA), &[], pub_h, &bad),
            0
        );
        let rv_bad = verify_signature(session, b"verify-signature RW6a");
        assert_ne!(rv_bad, 0);
        assert_eq!(verify_init(session, u64::from(ck::CKM_ML_DSA), &[], pub_h), 0);
        assert_eq!(verify(session, b"verify-signature RW6a", &bad), rv_bad, "must match the plain-Verify code exactly");

        // §5.13: Sign/VerifyRecover are RSA-only on this engine — a non-RSA
        // mechanism is a real CKR_MECHANISM_INVALID, not a made-up code.
        assert_eq!(
            sign_recover_init(session, u64::from(ck::CKM_ML_DSA), &[], prv_h),
            ck::CKR_MECHANISM_INVALID
        );
        assert_eq!(
            verify_recover_init(session, u64::from(ck::CKM_ML_DSA), &[], pub_h),
            ck::CKR_MECHANISM_INVALID
        );

        close_session(session);
        crate::verbs::close_session(fixture).ok();
    }

    #[test]
    #[serial]
    fn dual_function_quartet_matches_separate_fsm_output() {
        crate::test_support::ensure_bootstrapped();
        let session = open_session(SLOT, ck::CKF_SERIAL_SESSION | ck::CKF_RW_SESSION).1;
        let key_template = [
            attr_ulong(u64::from(ck::CKA_CLASS), ck::CKO_SECRET_KEY),
            attr_ulong(u64::from(ck::CKA_KEY_TYPE), ck::CKK_AES),
            attr_ulong(u64::from(ck::CKA_VALUE_LEN), 32),
            attr_bool(u64::from(ck::CKA_ENCRYPT), true),
            attr_bool(u64::from(ck::CKA_TOKEN), false),
        ];
        let (rv, key) = generate_key(session, u64::from(ck::CKM_AES_KEY_GEN), &[], &key_template);
        assert_eq!(rv, 0);

        let part = vec![0x55u8; 16];

        // Separate FSMs, independently, as the oracle.
        assert_eq!(digest_init(session, u64::from(ck::CKM_SHA256), &[]), 0);
        assert_eq!(digest_update(session, &part), 0);
        let (rv, digest_expected) = digest_final(session);
        assert_eq!(rv, 0);
        assert_eq!(encrypt_init(session, u64::from(ck::CKM_AES_ECB), &[], key), 0);
        let (rv, cipher_expected) = encrypt(session, &part);
        assert_eq!(rv, 0);

        // C_DigestEncryptUpdate: one call, both effects.
        assert_eq!(digest_init(session, u64::from(ck::CKM_SHA256), &[]), 0);
        assert_eq!(encrypt_init(session, u64::from(ck::CKM_AES_ECB), &[], key), 0);
        let (rv, cipher_dual) = digest_encrypt_update(session, &part);
        assert_eq!(rv, 0);
        assert_eq!(cipher_dual, cipher_expected, "dual-function ciphertext must equal the separate-FSM oracle");
        let (rv, digest_dual) = digest_final(session);
        assert_eq!(rv, 0);
        assert_eq!(digest_dual, digest_expected, "dual-function digest must equal the separate-FSM oracle");
        let (rv, _) = encrypt_final(session);
        assert_eq!(rv, 0);

        close_session(session);
    }

    #[test]
    #[serial]
    fn message_sign_verify_one_shot_and_multipart_round_trip() {
        crate::test_support::ensure_bootstrapped();
        let fixture = crate::test_support::fresh_session();
        let (pub_h, prv_h) =
            crate::verbs::generate_key_pair(fixture, crate::Algorithm::MlDsa65, b"rw6b-msg", "rw6b-msg")
                .expect("keygen fixture");

        let session = open_session(SLOT, ck::CKF_SERIAL_SESSION | ck::CKF_RW_SESSION).1;
        assert_eq!(message_sign_init(session, u64::from(ck::CKM_ML_DSA), &[], prv_h), 0);
        let (rv, sig) = sign_message(session, b"one-shot message");
        assert_eq!(rv, 0);
        assert_eq!(message_verify_init(session, u64::from(ck::CKM_ML_DSA), &[], pub_h), 0);
        assert_eq!(verify_message(session, b"one-shot message", &sig), 0);
        assert_eq!(message_sign_final(session), 0);
        assert_eq!(message_verify_final(session), 0);

        // Multipart: Begin, two non-final Next accumulations, one final.
        assert_eq!(message_sign_init(session, u64::from(ck::CKM_ML_DSA), &[], prv_h), 0);
        assert_eq!(sign_message_begin(session), 0);
        let (rv, empty) = sign_message_next(session, b"part-one ", false);
        assert_eq!(rv, 0);
        assert!(empty.is_empty());
        let (rv, sig_multi) = sign_message_next(session, b"part-two", true);
        assert_eq!(rv, 0);
        assert_eq!(message_sign_final(session), 0);

        assert_eq!(message_verify_init(session, u64::from(ck::CKM_ML_DSA), &[], pub_h), 0);
        assert_eq!(verify_message(session, b"part-one part-two", &sig_multi), 0, "multipart-assembled signature must verify against the concatenated message");
        assert_eq!(message_verify_final(session), 0);

        // Multipart verify FSM, same shape.
        assert_eq!(message_sign_init(session, u64::from(ck::CKM_ML_DSA), &[], prv_h), 0);
        let (rv, sig2) = sign_message(session, b"verify-fsm message");
        assert_eq!(rv, 0);
        assert_eq!(message_sign_final(session), 0);
        assert_eq!(message_verify_init(session, u64::from(ck::CKM_ML_DSA), &[], pub_h), 0);
        assert_eq!(verify_message_begin(session), 0);
        assert_eq!(verify_message_next(session, b"verify-fsm ", None), 0);
        assert_eq!(verify_message_next(session, b"message", Some(&sig2)), 0);
        assert_eq!(message_verify_final(session), 0);

        close_session(session);
        crate::verbs::close_session(fixture).ok();
    }

    #[test]
    #[serial]
    fn message_encrypt_decrypt_one_shot_round_trip_and_tamper_detection() {
        crate::test_support::ensure_bootstrapped();
        let session = open_session(SLOT, ck::CKF_SERIAL_SESSION | ck::CKF_RW_SESSION).1;
        let key_template = [
            attr_ulong(u64::from(ck::CKA_CLASS), ck::CKO_SECRET_KEY),
            attr_ulong(u64::from(ck::CKA_KEY_TYPE), ck::CKK_AES),
            attr_ulong(u64::from(ck::CKA_VALUE_LEN), 32),
            attr_bool(u64::from(ck::CKA_ENCRYPT), true),
            attr_bool(u64::from(ck::CKA_DECRYPT), true),
            attr_bool(u64::from(ck::CKA_TOKEN), false),
        ];
        let (rv, key) = generate_key(session, u64::from(ck::CKM_AES_KEY_GEN), &[], &key_template);
        assert_eq!(rv, 0);

        let iv = vec![0x01u8; 12];
        let aad = b"aad-context";
        let plaintext = b"message-based AEAD round trip";

        assert_eq!(message_encrypt_init(session, u64::from(ck::CKM_AES_GCM), &[], key), 0);
        let (rv, ciphertext, tag, iv_used) = encrypt_message(session, &iv, 0, aad, plaintext, 128);
        assert_eq!(rv, 0);
        assert_eq!(iv_used, iv, "iv_generator=0 must echo the caller's IV unchanged");
        assert_eq!(tag.len(), 16);
        assert_eq!(message_encrypt_final(session), 0);

        assert_eq!(message_decrypt_init(session, u64::from(ck::CKM_AES_GCM), &[], key), 0);
        let (rv, recovered) = decrypt_message(session, &iv, aad, &ciphertext, 128, &tag);
        assert_eq!(rv, 0);
        assert_eq!(recovered, plaintext);
        assert_eq!(message_decrypt_final(session), 0);

        // A tampered tag must be rejected — a real engine auth failure.
        assert_eq!(message_decrypt_init(session, u64::from(ck::CKM_AES_GCM), &[], key), 0);
        let mut bad_tag = tag.clone();
        bad_tag[0] ^= 0xFF;
        let (rv, _) = decrypt_message(session, &iv, aad, &ciphertext, 128, &bad_tag);
        assert_ne!(rv, 0);
        assert_eq!(message_decrypt_final(session), 0);

        close_session(session);
    }

    #[test]
    #[serial]
    fn message_encrypt_generated_iv_and_multipart_matches_one_shot() {
        crate::test_support::ensure_bootstrapped();
        let session = open_session(SLOT, ck::CKF_SERIAL_SESSION | ck::CKF_RW_SESSION).1;
        let key_template = [
            attr_ulong(u64::from(ck::CKA_CLASS), ck::CKO_SECRET_KEY),
            attr_ulong(u64::from(ck::CKA_KEY_TYPE), ck::CKK_AES),
            attr_ulong(u64::from(ck::CKA_VALUE_LEN), 32),
            attr_bool(u64::from(ck::CKA_ENCRYPT), true),
            attr_bool(u64::from(ck::CKA_DECRYPT), true),
            attr_bool(u64::from(ck::CKA_TOKEN), false),
        ];
        let (rv, key) = generate_key(session, u64::from(ck::CKM_AES_KEY_GEN), &[], &key_template);
        assert_eq!(rv, 0);

        // iv_generator != 0 (any nonzero value — the engine does not
        // discriminate among CKG_GENERATE/_COUNTER/_RANDOM): the 12-byte
        // placeholder is overwritten in place with a fresh random IV.
        let placeholder_iv = vec![0u8; 12];
        assert_eq!(message_encrypt_init(session, u64::from(ck::CKM_AES_GCM), &[], key), 0);
        let (rv, ciphertext, tag, iv_used) = encrypt_message(session, &placeholder_iv, 1, b"", b"generated-iv test", 128);
        assert_eq!(rv, 0);
        assert_ne!(iv_used, placeholder_iv, "the engine must have written a fresh IV in place");
        assert_eq!(iv_used.len(), 12);
        assert_eq!(message_encrypt_final(session), 0);

        assert_eq!(message_decrypt_init(session, u64::from(ck::CKM_AES_GCM), &[], key), 0);
        let (rv, recovered) = decrypt_message(session, &iv_used, b"", &ciphertext, 128, &tag);
        assert_eq!(rv, 0);
        assert_eq!(recovered, b"generated-iv test");
        assert_eq!(message_decrypt_final(session), 0);

        // Multipart Begin/Next must produce byte-identical ciphertext+tag
        // to the one-shot call above (same key/iv/aad/plaintext — AES-GCM
        // is deterministic given those inputs).
        let iv = vec![0x02u8; 12];
        assert_eq!(message_encrypt_init(session, u64::from(ck::CKM_AES_GCM), &[], key), 0);
        let (rv, one_shot_ct, one_shot_tag, _) = encrypt_message(session, &iv, 0, b"aad", b"multipart-vs-one-shot!!", 128);
        assert_eq!(rv, 0);
        assert_eq!(message_encrypt_final(session), 0);

        assert_eq!(message_encrypt_init(session, u64::from(ck::CKM_AES_GCM), &[], key), 0);
        let (rv, _) = encrypt_message_begin(session, &iv, 0, b"aad", 128);
        assert_eq!(rv, 0);
        let (rv, ct1, tag1) = encrypt_message_next(session, b"multipart-vs-one-", false, 128);
        assert_eq!(rv, 0);
        assert!(tag1.is_none());
        let (rv, ct2, tag2) = encrypt_message_next(session, b"shot!!", true, 128);
        assert_eq!(rv, 0);
        let mut multipart_ct = ct1;
        multipart_ct.extend_from_slice(&ct2);
        assert_eq!(multipart_ct, one_shot_ct, "multipart ciphertext must equal the one-shot ciphertext byte-for-byte");
        assert_eq!(tag2.unwrap(), one_shot_tag, "multipart tag must equal the one-shot tag byte-for-byte");
        assert_eq!(message_encrypt_final(session), 0);

        // Multipart decrypt FSM, verifying the assembled ciphertext.
        assert_eq!(message_decrypt_init(session, u64::from(ck::CKM_AES_GCM), &[], key), 0);
        assert_eq!(decrypt_message_begin(session, &iv, b"aad", 128), 0);
        let (rv, pt1) = decrypt_message_next(session, &multipart_ct[..17], false, 128, &[]);
        assert_eq!(rv, 0);
        let (rv, pt2) = decrypt_message_next(session, &multipart_ct[17..], true, 128, &one_shot_tag);
        assert_eq!(rv, 0);
        let mut recovered = pt1;
        recovered.extend_from_slice(&pt2);
        assert_eq!(recovered, b"multipart-vs-one-shot!!");
        assert_eq!(message_decrypt_final(session), 0);

        close_session(session);
    }

    #[test]
    #[serial]
    fn aes_key_wrap_unwrap_round_trip_and_not_wrappable_negative() {
        crate::test_support::ensure_bootstrapped();
        let session = open_session(SLOT, ck::CKF_SERIAL_SESSION | ck::CKF_RW_SESSION).1;

        let wrapping_key_tmpl = [
            attr_ulong(u64::from(ck::CKA_CLASS), ck::CKO_SECRET_KEY),
            attr_ulong(u64::from(ck::CKA_KEY_TYPE), ck::CKK_AES),
            attr_ulong(u64::from(ck::CKA_VALUE_LEN), 32),
            attr_bool(u64::from(ck::CKA_WRAP), true),
            attr_bool(u64::from(ck::CKA_UNWRAP), true),
            attr_bool(u64::from(ck::CKA_TOKEN), false),
        ];
        let (rv, wrapping_key) = generate_key(session, u64::from(ck::CKM_AES_KEY_GEN), &[], &wrapping_key_tmpl);
        assert_eq!(rv, 0);

        let target_tmpl = [
            attr_ulong(u64::from(ck::CKA_CLASS), ck::CKO_SECRET_KEY),
            attr_ulong(u64::from(ck::CKA_KEY_TYPE), ck::CKK_AES),
            attr_ulong(u64::from(ck::CKA_VALUE_LEN), 16),
            attr_bool(u64::from(ck::CKA_EXTRACTABLE), true),
            attr_bool(u64::from(ck::CKA_TOKEN), false),
        ];
        let (rv, target_key) = generate_key(session, u64::from(ck::CKM_AES_KEY_GEN), &[], &target_tmpl);
        assert_eq!(rv, 0);
        let (rv_orig, orig_attrs) = get_attribute_value(session, target_key, &[u64::from(ck::CKA_VALUE)]);
        assert_eq!(rv_orig, 0);

        let (rv, wrapped) = wrap_key(session, u64::from(ck::CKM_AES_KEY_WRAP), &[], wrapping_key, target_key);
        assert_eq!(rv, 0);
        assert!(!wrapped.is_empty());

        let unwrap_tmpl = [
            attr_ulong(u64::from(ck::CKA_CLASS), ck::CKO_SECRET_KEY),
            attr_ulong(u64::from(ck::CKA_KEY_TYPE), ck::CKK_AES),
            attr_bool(u64::from(ck::CKA_EXTRACTABLE), true),
            attr_bool(u64::from(ck::CKA_TOKEN), false),
        ];
        let (rv, unwrapped_key) = unwrap_key(session, u64::from(ck::CKM_AES_KEY_WRAP), &[], wrapping_key, &wrapped, &unwrap_tmpl);
        assert_eq!(rv, 0);
        assert_ne!(unwrapped_key, 0);
        let (rv_rt, rt_attrs) = get_attribute_value(session, unwrapped_key, &[u64::from(ck::CKA_VALUE)]);
        assert_eq!(rv_rt, 0);
        assert_eq!(rt_attrs[0].value, orig_attrs[0].value, "unwrapped key material must equal the original");

        // A non-extractable key must be refused with the real spec code.
        let non_extractable_tmpl = [
            attr_ulong(u64::from(ck::CKA_CLASS), ck::CKO_SECRET_KEY),
            attr_ulong(u64::from(ck::CKA_KEY_TYPE), ck::CKK_AES),
            attr_ulong(u64::from(ck::CKA_VALUE_LEN), 16),
            attr_bool(u64::from(ck::CKA_EXTRACTABLE), false),
            attr_bool(u64::from(ck::CKA_TOKEN), false),
        ];
        let (rv, locked_key) = generate_key(session, u64::from(ck::CKM_AES_KEY_GEN), &[], &non_extractable_tmpl);
        assert_eq!(rv, 0);
        let (rv, _) = wrap_key(session, u64::from(ck::CKM_AES_KEY_WRAP), &[], wrapping_key, locked_key);
        assert_eq!(rv, ck::CKR_KEY_UNEXTRACTABLE, "CKA_EXTRACTABLE=false is a real CKR_KEY_UNEXTRACTABLE, distinct from the CKA_WRAP_WITH_TRUSTED policy code CKR_KEY_NOT_WRAPPABLE");

        // WrapKeyAuthenticated/UnwrapKeyAuthenticated are CKM_AES_GCM-only
        // on this engine (ffi::C_WrapKeyAuthenticated hard-rejects any
        // other mechanism) — a full authenticated round trip needs
        // CK_GCM_PARAMS marshaling, out of RW4's scope (not in the plan's
        // own RW4 test list). What's proven here instead: the wire reaches
        // the real entry point and gets the real engine's own rejection
        // code back, not a transport-layer stub.
        let (rv, _) = wrap_key_authenticated(session, u64::from(ck::CKM_AES_KEY_WRAP), &[], wrapping_key, target_key, b"aad");
        assert_eq!(rv, ck::CKR_MECHANISM_INVALID);
        let (rv, _) = unwrap_key_authenticated(session, u64::from(ck::CKM_AES_KEY_WRAP), &[], wrapping_key, &wrapped, &unwrap_tmpl, b"aad");
        assert_eq!(rv, ck::CKR_MECHANISM_INVALID);

        close_session(session);
    }

    #[test]
    #[serial]
    fn derive_key_concatenate_and_sha256_derivation() {
        crate::test_support::ensure_bootstrapped();
        let session = open_session(SLOT, ck::CKF_SERIAL_SESSION | ck::CKF_RW_SESSION).1;
        let base_tmpl = [
            attr_ulong(u64::from(ck::CKA_CLASS), ck::CKO_SECRET_KEY),
            attr_ulong(u64::from(ck::CKA_KEY_TYPE), ck::CKK_AES),
            attr_ulong(u64::from(ck::CKA_VALUE_LEN), 16),
            attr_bool(u64::from(ck::CKA_DERIVE), true),
            attr_bool(u64::from(ck::CKA_TOKEN), false),
        ];
        let (rv, base_key) = generate_key(session, u64::from(ck::CKM_AES_KEY_GEN), &[], &base_tmpl);
        assert_eq!(rv, 0);
        let (rv, second_key) = generate_key(session, u64::from(ck::CKM_AES_KEY_GEN), &[], &base_tmpl);
        assert_eq!(rv, 0);

        // CKM_CONCATENATE_BASE_AND_KEY — a bare CK_OBJECT_HANDLE parameter,
        // native-width ulong, already fully representable as raw bytes
        // (the RW1 ulong-width finding applied on the input side).
        let param = (second_key as usize).to_ne_bytes().to_vec();
        let out_tmpl = [
            attr_ulong(u64::from(ck::CKA_CLASS), ck::CKO_SECRET_KEY),
            attr_ulong(u64::from(ck::CKA_KEY_TYPE), ck::CKK_GENERIC_SECRET),
            attr_bool(u64::from(ck::CKA_TOKEN), false),
        ];
        let (rv, derived) = derive_key(session, u64::from(ck::CKM_CONCATENATE_BASE_AND_KEY), &param, base_key, &out_tmpl);
        assert_eq!(rv, 0);
        assert_ne!(derived, 0);
        let (rv, attrs) = get_attribute_value(session, derived, &[u64::from(ck::CKA_VALUE)]);
        assert_eq!(rv, 0);
        assert_eq!(attrs[0].value.len(), 32, "concatenation of two 16-byte keys must be 32 bytes");

        // CKM_SHA256_KEY_DERIVATION — no parameter at all.
        let (rv, derived2) = derive_key(session, u64::from(ck::CKM_SHA256_KEY_DERIVATION), &[], base_key, &out_tmpl);
        assert_eq!(rv, 0);
        assert_ne!(derived2, 0);
        let (rv, attrs2) = get_attribute_value(session, derived2, &[u64::from(ck::CKA_VALUE)]);
        assert_eq!(rv, 0);
        assert_eq!(attrs2[0].value.len(), 32, "SHA-256 output is 32 bytes");

        close_session(session);
    }

    #[test]
    #[serial]
    fn derive_key_hkdf_and_pbkdf2() {
        crate::test_support::ensure_bootstrapped();
        let session = open_session(SLOT, ck::CKF_SERIAL_SESSION | ck::CKF_RW_SESSION).1;
        let base_tmpl = [
            attr_ulong(u64::from(ck::CKA_CLASS), ck::CKO_SECRET_KEY),
            attr_ulong(u64::from(ck::CKA_KEY_TYPE), ck::CKK_GENERIC_SECRET),
            attr_ulong(u64::from(ck::CKA_VALUE_LEN), 32),
            attr_bool(u64::from(ck::CKA_DERIVE), true),
            attr_bool(u64::from(ck::CKA_TOKEN), false),
        ];
        let (rv, base_key) = generate_key(session, u64::from(ck::CKM_GENERIC_SECRET_KEY_GEN), &[], &base_tmpl);
        assert_eq!(rv, 0);

        let out_tmpl = [
            attr_ulong(u64::from(ck::CKA_CLASS), ck::CKO_SECRET_KEY),
            attr_ulong(u64::from(ck::CKA_KEY_TYPE), ck::CKK_GENERIC_SECRET),
            attr_ulong(u64::from(ck::CKA_VALUE_LEN), 32),
            attr_bool(u64::from(ck::CKA_TOKEN), false),
        ];

        // HKDF extract+expand, PRF SHA-256, raw salt, no salt-key.
        const CKM_SHA256_HMAC: u64 = 0x0000_0251;
        const CKF_HKDF_SALT_DATA: u32 = 0x0000_0002;
        let hkdf_params = derive_params::hkdf(true, true, CKM_SHA256_HMAC, CKF_HKDF_SALT_DATA, b"salt-bytes", 0, b"info-bytes");
        let (rv, derived) = derive_key(session, u64::from(ck::CKM_HKDF_DERIVE), hkdf_params.as_slice(), base_key, &out_tmpl);
        assert_eq!(rv, 0);
        assert_ne!(derived, 0);
        let (rv, attrs) = get_attribute_value(session, derived, &[u64::from(ck::CKA_VALUE)]);
        assert_eq!(rv, 0);
        assert_eq!(attrs[0].value.len(), 32);

        // PBKDF2 — h_base_key MUST be 0 (password lives in the params);
        // the engine explicitly skips the base-key check for this
        // mechanism (verified in ffi::C_DeriveKey's own comment). `prf`
        // is a `CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE` codepoint
        // (`CKP_PBKDF2_HMAC_SHA256 = 0x04`) — a DIFFERENT namespace from
        // the `CKM_*_HMAC` mechanism codes HKDF/SP800-108 use; the engine
        // also enforces a real minimum of 1000 iterations.
        const CKP_PBKDF2_HMAC_SHA256: u64 = 0x04;
        const CKZ_SALT_SPECIFIED: u32 = 1;
        let pbkdf2_params = derive_params::pbkd2(CKZ_SALT_SPECIFIED, b"pbkdf2-salt", 1000, CKP_PBKDF2_HMAC_SHA256, &[], b"correct horse battery staple");
        let (rv, derived_pw) = derive_key(session, u64::from(ck::CKM_PKCS5_PBKD2), pbkdf2_params.as_slice(), 0, &out_tmpl);
        assert_eq!(rv, 0);
        assert_ne!(derived_pw, 0);
        let (rv, attrs2) = get_attribute_value(session, derived_pw, &[u64::from(ck::CKA_VALUE)]);
        assert_eq!(rv, 0);
        assert_eq!(attrs2[0].value.len(), 32);

        // Below the engine's real 1000-iteration floor — a genuine
        // CKR_ARGUMENTS_BAD, not a made-up code.
        let pbkdf2_params_low = derive_params::pbkd2(CKZ_SALT_SPECIFIED, b"pbkdf2-salt", 999, CKP_PBKDF2_HMAC_SHA256, &[], b"correct horse battery staple");
        let (rv, _) = derive_key(session, u64::from(ck::CKM_PKCS5_PBKD2), pbkdf2_params_low.as_slice(), 0, &out_tmpl);
        assert_eq!(rv, CKR_ARGUMENTS_BAD);

        // Same password/salt/PRF, one MORE iteration than the first call —
        // must derive a DIFFERENT key (a real, meaningful check that
        // `iterations` actually reached the engine through the wire
        // struct, not a hardcoded default).
        let pbkdf2_params_diff = derive_params::pbkd2(CKZ_SALT_SPECIFIED, b"pbkdf2-salt", 1001, CKP_PBKDF2_HMAC_SHA256, &[], b"correct horse battery staple");
        let (rv, derived_pw2) = derive_key(session, u64::from(ck::CKM_PKCS5_PBKD2), pbkdf2_params_diff.as_slice(), 0, &out_tmpl);
        assert_eq!(rv, 0);
        let (rv, attrs3) = get_attribute_value(session, derived_pw2, &[u64::from(ck::CKA_VALUE)]);
        assert_eq!(rv, 0);
        assert_ne!(attrs3[0].value, attrs2[0].value, "different iteration counts must derive different keys");

        close_session(session);
    }

    #[test]
    #[serial]
    fn derive_key_sp800_108_counter_and_feedback() {
        crate::test_support::ensure_bootstrapped();
        let session = open_session(SLOT, ck::CKF_SERIAL_SESSION | ck::CKF_RW_SESSION).1;
        let base_tmpl = [
            attr_ulong(u64::from(ck::CKA_CLASS), ck::CKO_SECRET_KEY),
            attr_ulong(u64::from(ck::CKA_KEY_TYPE), ck::CKK_GENERIC_SECRET),
            attr_ulong(u64::from(ck::CKA_VALUE_LEN), 32),
            attr_bool(u64::from(ck::CKA_DERIVE), true),
            attr_bool(u64::from(ck::CKA_TOKEN), false),
        ];
        let (rv, base_key) = generate_key(session, u64::from(ck::CKM_GENERIC_SECRET_KEY_GEN), &[], &base_tmpl);
        assert_eq!(rv, 0);

        let out_tmpl = [
            attr_ulong(u64::from(ck::CKA_CLASS), ck::CKO_SECRET_KEY),
            attr_ulong(u64::from(ck::CKA_KEY_TYPE), ck::CKK_GENERIC_SECRET),
            attr_ulong(u64::from(ck::CKA_VALUE_LEN), 32),
            attr_bool(u64::from(ck::CKA_TOKEN), false),
        ];

        const CKM_SHA256_HMAC: u64 = 0x0000_0251;
        const CK_SP800_108_ITERATION_VARIABLE: u32 = 1;
        const CK_SP800_108_OPTIONAL_COUNTER: u32 = 2;
        const CK_SP800_108_BYTE_ARRAY: u32 = 4;

        // §Table 199: the engine rejects an explicit CK_SP800_108_COUNTER
        // (type 2) segment in Counter Mode — CK_SP800_108_ITERATION_VARIABLE
        // (type 1) IS the counter for this mode, and it carries the exact
        // same CK_SP800_108_COUNTER_FORMAT value (width/endianness), not
        // an empty one (verified against ffi::parse_sp800_108_segments's
        // own match arm for type 1).
        let counter_value = derive_params::counter_format(false, 8);
        let segments = vec![
            derive_params::Segment { prf_type: CK_SP800_108_ITERATION_VARIABLE, value: counter_value },
            derive_params::Segment { prf_type: CK_SP800_108_BYTE_ARRAY, value: b"label-context".to_vec() },
        ];
        let counter_params = derive_params::sp800_108_counter(CKM_SHA256_HMAC, segments);
        let (rv, derived) = derive_key(session, u64::from(ck::CKM_SP800_108_COUNTER_KDF), counter_params.as_slice(), base_key, &out_tmpl);
        assert_eq!(rv, 0, "SP800-108 counter-mode derive must succeed against the real engine");
        assert_ne!(derived, 0);
        let (rv, attrs) = get_attribute_value(session, derived, &[u64::from(ck::CKA_VALUE)]);
        assert_eq!(rv, 0);
        assert_eq!(attrs[0].value.len(), 32);

        // Feedback mode DOES allow the explicit CK_SP800_108_COUNTER
        // (type 2) segment (Table 200) — exercised here as the
        // counterpart to counter-mode's ITERATION_VARIABLE path above.
        const CKM_SP800_108_FEEDBACK_KDF: u64 = 0x0000_03ad;
        let counter_value2 = derive_params::counter_format(false, 8);
        let segments2 = vec![
            derive_params::Segment { prf_type: CK_SP800_108_OPTIONAL_COUNTER, value: counter_value2 },
        ];
        let feedback_params = derive_params::sp800_108_feedback(CKM_SHA256_HMAC, segments2, &[0xAAu8; 32]);
        let (rv, derived_fb) = derive_key(session, CKM_SP800_108_FEEDBACK_KDF, feedback_params.as_slice(), base_key, &out_tmpl);
        assert_eq!(rv, 0, "SP800-108 feedback-mode derive must succeed against the real engine");
        assert_ne!(derived_fb, 0);
        let (rv, attrs_fb) = get_attribute_value(session, derived_fb, &[u64::from(ck::CKA_VALUE)]);
        assert_eq!(rv, 0);
        assert_eq!(attrs_fb[0].value.len(), 32);
        assert_ne!(attrs_fb[0].value, attrs[0].value, "counter and feedback modes must derive different output");

        close_session(session);
    }

    #[test]
    #[serial]
    fn derive_key_ecdh1_p256() {
        crate::test_support::ensure_bootstrapped();
        let session = open_session(SLOT, ck::CKF_SERIAL_SESSION | ck::CKF_RW_SESSION).1;

        // NIST P-256 (secp256r1 / prime256v1) OID, DER-encoded: the
        // standard CKA_EC_PARAMS this engine's C_GenerateKeyPair(
        // CKM_EC_KEY_PAIR_GEN) dispatch decodes via `decode_ec_params`.
        const P256_EC_PARAMS: [u8; 10] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
        const CKM_EC_KEY_PAIR_GEN: u64 = 0x0000_1040;
        const CKA_EC_PARAMS: u64 = 0x0000_0180;
        const CKA_EC_POINT: u64 = 0x0000_0181;
        const CKK_EC: u32 = 0x0000_0003;

        let make_ec_pair = || {
            let public_tmpl = [
                attr_ulong(u64::from(ck::CKA_CLASS), ck::CKO_PUBLIC_KEY),
                attr_ulong(u64::from(ck::CKA_KEY_TYPE), CKK_EC),
                (CKA_EC_PARAMS, P256_EC_PARAMS.to_vec()),
                attr_bool(u64::from(ck::CKA_TOKEN), false),
            ];
            let private_tmpl = [
                attr_ulong(u64::from(ck::CKA_CLASS), ck::CKO_PRIVATE_KEY),
                attr_ulong(u64::from(ck::CKA_KEY_TYPE), CKK_EC),
                attr_bool(u64::from(ck::CKA_DERIVE), true),
                attr_bool(u64::from(ck::CKA_TOKEN), false),
            ];
            generate_key_pair(session, CKM_EC_KEY_PAIR_GEN, &[], &public_tmpl, &private_tmpl)
        };

        let (rv, _our_pub, our_prv) = make_ec_pair();
        assert_eq!(rv, 0, "EC P-256 keygen must succeed — a prerequisite for testing ECDH1_DERIVE at all");
        let (rv, peer_pub, _peer_prv) = make_ec_pair();
        assert_eq!(rv, 0);

        let (rv, peer_point_attrs) = get_attribute_value(session, peer_pub, &[CKA_EC_POINT]);
        assert_eq!(rv, 0);
        assert!(peer_point_attrs[0].available, "CKA_EC_POINT must be readable on a public key");

        const CKD_NULL: u32 = 1;
        let ecdh_params = derive_params::ecdh1(CKD_NULL, &[], &peer_point_attrs[0].value);
        let out_tmpl = [
            attr_ulong(u64::from(ck::CKA_CLASS), ck::CKO_SECRET_KEY),
            attr_ulong(u64::from(ck::CKA_KEY_TYPE), ck::CKK_GENERIC_SECRET),
            attr_bool(u64::from(ck::CKA_TOKEN), false),
        ];
        let (rv, shared) = derive_key(session, u64::from(ck::CKM_ECDH1_DERIVE), ecdh_params.as_slice(), our_prv, &out_tmpl);
        assert_eq!(rv, 0, "ECDH1_DERIVE against a real P-256 peer point must succeed");
        assert_ne!(shared, 0);
        let (rv, shared_attrs) = get_attribute_value(session, shared, &[u64::from(ck::CKA_VALUE)]);
        assert_eq!(rv, 0);
        assert_eq!(shared_attrs[0].value.len(), 32, "P-256 shared secret is 32 bytes");

        close_session(session);
    }
}
