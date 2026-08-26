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
}
