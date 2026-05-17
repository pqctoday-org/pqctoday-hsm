//! Phase 5 proof-of-concept: drive `softhsmrustv3` directly from a wasm32
//! Rust crate via its raw PKCS#11 `C_*` entry points.
//!
//! Goals:
//!
//! 1. Prove the sibling `pqctoday-hsm/rust/` crate links into another
//!    Rust crate compiled to `wasm32-unknown-unknown` (now that the
//!    sibling-project fips205-patched + `with_rng!` macro bugs are
//!    fixed — see openmls-provider/README.md §"Phase 5").
//! 2. Show the calling convention: how a Rust crate marshals
//!    `*mut u8` / `*mut u32` PKCS#11 buffers when both sides are the
//!    same Rust process inside one wasm module.
//! 3. Cover all 13 backend ops needed by the future `WasmPkcs11Backend`:
//!    hash, random, HMAC, create_object, find_objects, get_attributes,
//!    destroy_object, generate_key_pair, sign, verify, encrypt, decrypt.
//!
//! Run with `wasm-pack test --node wasm-smoke` from the workspace
//! root (Node 20+ required for the WebAssembly runtime).

#![cfg(target_arch = "wasm32")]

use softhsmrustv3::ffi::{
    C_CreateObject, C_Decrypt, C_DecryptInit, C_DestroyObject, C_Digest, C_DigestInit,
    C_Encrypt, C_EncryptInit, C_FindObjects, C_FindObjectsFinal, C_FindObjectsInit,
    C_GenerateKeyPair, C_GenerateRandom, C_GetAttributeValue, C_Initialize, C_OpenSession,
    C_Sign, C_SignInit, C_Verify, C_VerifyInit,
};
use softhsmrustv3::constants::{
    CKA_CLASS, CKA_DECRYPT, CKA_ENCRYPT, CKA_EXTRACTABLE, CKA_KEY_TYPE, CKA_SIGN, CKA_TOKEN,
    CKA_VALUE, CKF_RW_SESSION, CKF_SERIAL_SESSION, CKK_AES, CKK_GENERIC_SECRET, CKM_AES_GCM,
    CKM_EC_EDWARDS_KEY_PAIR_GEN, CKM_EDDSA, CKM_SHA256, CKM_SHA256_HMAC, CKO_SECRET_KEY, CKR_OK,
};

// CKO_DATA (= 0) is not in softhsmrustv3::constants — standard PKCS#11 §3.
const CKO_DATA: u32 = 0x0000_0000;

// ── PKCS#11 session management ───────────────────────────────────────────────

/// Call `C_Initialize` exactly once. Subsequent calls return
/// `CKR_CRYPTOKI_ALREADY_INITIALIZED` (0x191) which we treat as success.
fn pkcs11_init_idempotent() {
    let rv = C_Initialize(std::ptr::null_mut());
    assert!(
        rv == CKR_OK || rv == 0x191,
        "C_Initialize returned unexpected rv: 0x{:x}",
        rv
    );
}

/// Open a read/write session against slot 0. Returns the session handle.
fn pkcs11_open_session() -> u32 {
    let mut h_session: u32 = 0;
    let rv = C_OpenSession(
        0,
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        &mut h_session as *mut u32,
    );
    assert_eq!(rv, CKR_OK, "C_OpenSession failed: 0x{:x}", rv);
    h_session
}

// ── Attribute-template helpers ───────────────────────────────────────────────
//
// PKCS#11 CK_ATTRIBUTE on wasm32 is three u32s: [type, value_ptr, value_len].
// All value buffers MUST outlive the C_* call that uses the template.
//
// We build templates inline in each function so ownership is unambiguous.

/// Write a 4-byte little-endian u32 into `buf` and return a pointer to it.
/// `buf` must be live for the duration of the C_* call.
#[inline(always)]
fn u32_attr(buf: &mut [u8; 4], val: u32) -> *const u8 {
    buf.copy_from_slice(&val.to_le_bytes());
    buf.as_ptr()
}

/// Write a 1-byte boolean into `buf` and return a pointer to it.
#[inline(always)]
fn bool_attr(buf: &mut u8, val: bool) -> *const u8 {
    *buf = if val { 1 } else { 0 };
    buf as *const u8
}

// ── SHA-256 ──────────────────────────────────────────────────────────────────

/// Run a SHA-256 hash via softhsmrustv3's `C_DigestInit` + `C_Digest`.
/// Returns the 32-byte digest.
pub fn sha256_via_softhsm(data: &[u8]) -> Vec<u8> {
    pkcs11_init_idempotent();
    let h_sess = pkcs11_open_session();

    // CK_MECHANISM: mechanism_type (u32), pParameter (u32 ptr = null), ulParameterLen (u32)
    // For parameter-less mechanisms we pass a 4-byte buffer holding only the type.
    let mut mech: [u8; 4] = CKM_SHA256.to_ne_bytes();
    let rv = C_DigestInit(h_sess, mech.as_mut_ptr());
    assert_eq!(rv, CKR_OK, "C_DigestInit returned 0x{:x}", rv);

    let mut digest_buf = vec![0u8; 32];
    let mut digest_len: u32 = 32;
    let rv = C_Digest(
        h_sess,
        data.as_ptr() as *mut u8,
        data.len() as u32,
        digest_buf.as_mut_ptr(),
        &mut digest_len as *mut u32,
    );
    assert_eq!(rv, CKR_OK, "C_Digest returned 0x{:x}", rv);
    assert_eq!(digest_len, 32, "SHA-256 output is 32 bytes");
    digest_buf
}

// ── Random ───────────────────────────────────────────────────────────────────

/// Pull `n` bytes from softhsmrustv3's RNG.
pub fn random_via_softhsm(n: usize) -> Vec<u8> {
    pkcs11_init_idempotent();
    let h_sess = pkcs11_open_session();

    let mut buf = vec![0u8; n];
    let rv = C_GenerateRandom(h_sess, buf.as_mut_ptr(), n as u32);
    assert_eq!(rv, CKR_OK, "C_GenerateRandom returned 0x{:x}", rv);
    buf
}

// ── HMAC-SHA-256 ─────────────────────────────────────────────────────────────

/// Compute HMAC-SHA-256 via PKCS#11: C_CreateObject → C_SignInit → C_Sign.
///
/// Protocol:
///   1. Import `key` as a session-only CKO_SECRET_KEY / CKK_GENERIC_SECRET object
///      with CKA_SIGN=true.
///   2. C_SignInit(CKM_SHA256_HMAC, h_key) + C_Sign(data) → 32-byte MAC.
///   3. C_DestroyObject to free the session key.
pub fn hmac_sha256_via_softhsm(key: &[u8], data: &[u8]) -> Vec<u8> {
    pkcs11_init_idempotent();
    let h_sess = pkcs11_open_session();

    // Value buffers — must outlive the C_CreateObject call below.
    let mut class_buf = [0u8; 4];
    let mut key_type_buf = [0u8; 4];
    let mut sign_buf: u8 = 0;
    let mut token_buf: u8 = 0;

    let class_ptr = u32_attr(&mut class_buf, CKO_SECRET_KEY);
    let ktype_ptr = u32_attr(&mut key_type_buf, CKK_GENERIC_SECRET);
    let sign_ptr = bool_attr(&mut sign_buf, true);
    let token_ptr = bool_attr(&mut token_buf, false);

    // CK_ATTRIBUTE template: 5 attrs × [type(u32), ptr(u32), len(u32)]
    let mut tmpl: [u32; 15] = [
        CKA_CLASS,    class_ptr as u32, 4,
        CKA_KEY_TYPE, ktype_ptr as u32, 4,
        CKA_VALUE,    key.as_ptr() as u32, key.len() as u32,
        CKA_SIGN,     sign_ptr as u32, 1,
        CKA_TOKEN,    token_ptr as u32, 1,
    ];

    let mut h_key: u32 = 0;
    let rv = C_CreateObject(h_sess, tmpl.as_mut_ptr() as *mut u8, 5, &mut h_key);
    assert_eq!(rv, CKR_OK, "C_CreateObject HMAC key: 0x{:x}", rv);

    // CK_MECHANISM for CKM_SHA256_HMAC (no params): [mech_type, null, 0]
    let mut mech: [u32; 3] = [CKM_SHA256_HMAC, 0, 0];
    let rv = C_SignInit(h_sess, mech.as_mut_ptr() as *mut u8, h_key);
    assert_eq!(rv, CKR_OK, "C_SignInit HMAC: 0x{:x}", rv);

    let mut mac_buf = vec![0u8; 32];
    let mut mac_len: u32 = 32;
    let rv = C_Sign(
        h_sess,
        data.as_ptr() as *mut u8,
        data.len() as u32,
        mac_buf.as_mut_ptr(),
        &mut mac_len,
    );
    assert_eq!(rv, CKR_OK, "C_Sign HMAC: 0x{:x}", rv);
    assert_eq!(mac_len, 32, "HMAC-SHA-256 output is 32 bytes");

    C_DestroyObject(h_sess, h_key);
    mac_buf
}

// ── Ed25519 keygen + sign + verify ───────────────────────────────────────────

/// Generate an Ed25519 keypair, sign `msg`, and verify the signature.
/// Returns `(h_pub, h_priv, signature_bytes)` so the caller can also
/// test wrong-message rejection without regenerating the keypair.
///
/// Protocol:
///   1. C_GenerateKeyPair(CKM_EC_EDWARDS_KEY_PAIR_GEN) → h_pub, h_priv
///   2. C_SignInit(CKM_EDDSA, h_priv) + C_Sign(msg) → 64-byte signature
///   3. C_VerifyInit(CKM_EDDSA, h_pub) + C_Verify(msg, sig) → CKR_OK
pub fn ed25519_sign_verify_via_softhsm(msg: &[u8]) -> (u32, u32, Vec<u8>) {
    pkcs11_init_idempotent();
    let h_sess = pkcs11_open_session();

    // Generate keypair — no template attrs needed; defaults are correct.
    let mut mech_kpg: [u32; 3] = [CKM_EC_EDWARDS_KEY_PAIR_GEN, 0, 0];
    let mut h_pub: u32 = 0;
    let mut h_priv: u32 = 0;
    let rv = C_GenerateKeyPair(
        h_sess,
        mech_kpg.as_mut_ptr() as *mut u8,
        std::ptr::null_mut(), 0,
        std::ptr::null_mut(), 0,
        &mut h_pub,
        &mut h_priv,
    );
    assert_eq!(rv, CKR_OK, "C_GenerateKeyPair Ed25519: 0x{:x}", rv);

    // Sign
    let mut mech_sign: [u32; 3] = [CKM_EDDSA, 0, 0];
    let rv = C_SignInit(h_sess, mech_sign.as_mut_ptr() as *mut u8, h_priv);
    assert_eq!(rv, CKR_OK, "C_SignInit EDDSA: 0x{:x}", rv);

    let mut sig_buf = vec![0u8; 64];
    let mut sig_len: u32 = 64;
    let rv = C_Sign(
        h_sess,
        msg.as_ptr() as *mut u8,
        msg.len() as u32,
        sig_buf.as_mut_ptr(),
        &mut sig_len,
    );
    assert_eq!(rv, CKR_OK, "C_Sign EDDSA: 0x{:x}", rv);
    assert_eq!(sig_len, 64, "Ed25519 signature is always 64 bytes");

    // Verify — correct message
    let mut mech_ver: [u32; 3] = [CKM_EDDSA, 0, 0];
    let rv = C_VerifyInit(h_sess, mech_ver.as_mut_ptr() as *mut u8, h_pub);
    assert_eq!(rv, CKR_OK, "C_VerifyInit EDDSA: 0x{:x}", rv);

    let rv = C_Verify(
        h_sess,
        msg.as_ptr() as *mut u8,
        msg.len() as u32,
        sig_buf.as_ptr() as *mut u8,
        sig_len,
    );
    assert_eq!(rv, CKR_OK, "C_Verify EDDSA correct msg: 0x{:x}", rv);

    (h_pub, h_priv, sig_buf)
}

// ── AES-128-GCM ──────────────────────────────────────────────────────────────

/// Encrypt `pt` with AES-128-GCM using `key` (16 bytes) and `iv` (12 bytes).
/// Returns `ciphertext || 16-byte GCM tag` (pt.len() + 16 bytes total).
///
/// Protocol:
///   1. C_CreateObject(CKO_SECRET_KEY / CKK_AES, CKA_VALUE=key, CKA_ENCRYPT=true)
///   2. C_EncryptInit(CKM_AES_GCM, CK_GCM_PARAMS{iv, iv_len=12, tag_bits=128})
///   3. C_Encrypt(pt) → ct
pub fn aes128_gcm_encrypt_via_softhsm(key: &[u8], iv: &[u8], pt: &[u8]) -> Vec<u8> {
    pkcs11_init_idempotent();
    let h_sess = pkcs11_open_session();
    let h_key = create_aes_key(h_sess, key);
    let ct = aes_gcm_encrypt(h_sess, h_key, iv, pt);
    C_DestroyObject(h_sess, h_key);
    ct
}

/// Decrypt `ct` (ciphertext || 16-byte tag) with AES-128-GCM.
/// Returns the plaintext. Panics if the GCM tag fails.
pub fn aes128_gcm_decrypt_via_softhsm(key: &[u8], iv: &[u8], ct: &[u8]) -> Vec<u8> {
    pkcs11_init_idempotent();
    let h_sess = pkcs11_open_session();
    let h_key = create_aes_key(h_sess, key);
    let pt = aes_gcm_decrypt(h_sess, h_key, iv, ct);
    C_DestroyObject(h_sess, h_key);
    pt
}

/// Create a session AES key object and return its handle.
fn create_aes_key(h_sess: u32, key: &[u8]) -> u32 {
    let mut class_buf = [0u8; 4];
    let mut ktype_buf = [0u8; 4];
    let mut enc_buf: u8 = 0;
    let mut dec_buf: u8 = 0;
    let mut token_buf: u8 = 0;
    let mut extractable_buf: u8 = 0;

    let class_ptr = u32_attr(&mut class_buf, CKO_SECRET_KEY);
    let ktype_ptr = u32_attr(&mut ktype_buf, CKK_AES);
    let enc_ptr = bool_attr(&mut enc_buf, true);
    let dec_ptr = bool_attr(&mut dec_buf, true);
    let token_ptr = bool_attr(&mut token_buf, false);
    let ext_ptr = bool_attr(&mut extractable_buf, true);

    let mut tmpl: [u32; 21] = [
        CKA_CLASS,       class_ptr as u32, 4,
        CKA_KEY_TYPE,    ktype_ptr as u32, 4,
        CKA_VALUE,       key.as_ptr() as u32, key.len() as u32,
        CKA_ENCRYPT,     enc_ptr as u32, 1,
        CKA_DECRYPT,     dec_ptr as u32, 1,
        CKA_TOKEN,       token_ptr as u32, 1,
        CKA_EXTRACTABLE, ext_ptr as u32, 1,   // explicit to avoid sensitive default
    ];

    let mut h_key: u32 = 0;
    let rv = C_CreateObject(h_sess, tmpl.as_mut_ptr() as *mut u8, 7, &mut h_key);
    assert_eq!(rv, CKR_OK, "C_CreateObject AES key: 0x{:x}", rv);
    h_key
}

/// Run AES-GCM encrypt against an already-created key handle.
fn aes_gcm_encrypt(h_sess: u32, h_key: u32, iv: &[u8], pt: &[u8]) -> Vec<u8> {
    // CK_GCM_PARAMS (wasm32, 5 × u32 = 20 bytes):
    //   [0] pIv: *const u8
    //   [1] ulIvLen: u32 (must be 12)
    //   [2] ulIvBits: u32 (ignored by softhsmrustv3 but required for ≥ 20 byte check)
    //   [3] pAAD: u32 (null; AAD not used)
    //   [4] ulTagBits: u32 (128 = 16-byte tag)
    let gcm_params: [u32; 5] = [
        iv.as_ptr() as u32,
        iv.len() as u32,
        0,
        0,
        128,
    ];

    // CK_MECHANISM: [mech_type, pParameter, ulParameterLen]
    let mut mech: [u32; 3] = [
        CKM_AES_GCM,
        gcm_params.as_ptr() as u32,
        20, // sizeof(CK_GCM_PARAMS) on wasm32
    ];

    let rv = C_EncryptInit(h_sess, mech.as_mut_ptr() as *mut u8, h_key);
    assert_eq!(rv, CKR_OK, "C_EncryptInit AES-GCM: 0x{:x}", rv);

    // Output: pt.len() + 16-byte GCM tag
    let out_cap = pt.len() + 16;
    let mut ct_buf = vec![0u8; out_cap];
    let mut ct_len: u32 = out_cap as u32;
    let rv = C_Encrypt(
        h_sess,
        pt.as_ptr() as *mut u8,
        pt.len() as u32,
        ct_buf.as_mut_ptr(),
        &mut ct_len,
    );
    assert_eq!(rv, CKR_OK, "C_Encrypt AES-GCM: 0x{:x}", rv);
    ct_buf.truncate(ct_len as usize);
    ct_buf
}

/// Run AES-GCM decrypt against an already-created key handle.
fn aes_gcm_decrypt(h_sess: u32, h_key: u32, iv: &[u8], ct: &[u8]) -> Vec<u8> {
    let gcm_params: [u32; 5] = [iv.as_ptr() as u32, iv.len() as u32, 0, 0, 128];
    let mut mech: [u32; 3] = [CKM_AES_GCM, gcm_params.as_ptr() as u32, 20];

    let rv = C_DecryptInit(h_sess, mech.as_mut_ptr() as *mut u8, h_key);
    assert_eq!(rv, CKR_OK, "C_DecryptInit AES-GCM: 0x{:x}", rv);

    let mut pt_buf = vec![0u8; ct.len()]; // at most ct.len() bytes out
    let mut pt_len: u32 = ct.len() as u32;
    let rv = C_Decrypt(
        h_sess,
        ct.as_ptr() as *mut u8,
        ct.len() as u32,
        pt_buf.as_mut_ptr(),
        &mut pt_len,
    );
    assert_eq!(rv, CKR_OK, "C_Decrypt AES-GCM: 0x{:x}", rv);
    pt_buf.truncate(pt_len as usize);
    pt_buf
}

// ── Data object lifecycle ────────────────────────────────────────────────────

/// Exercise the full object lifecycle: C_CreateObject → C_FindObjectsInit →
/// C_FindObjects → C_FindObjectsFinal → C_GetAttributeValue → C_DestroyObject.
///
/// Creates a session CKO_DATA object with `CKA_VALUE = payload`, finds it by
/// class, reads the value back, and destroys it.  Returns the retrieved bytes.
pub fn data_object_lifecycle_via_softhsm(payload: &[u8]) -> Vec<u8> {
    pkcs11_init_idempotent();
    let h_sess = pkcs11_open_session();

    // ── Create CKO_DATA object ───────────────────────────────────────────
    let mut class_buf = [0u8; 4];
    let mut token_buf: u8 = 0;

    let class_ptr = u32_attr(&mut class_buf, CKO_DATA);
    let token_ptr = bool_attr(&mut token_buf, false);

    let mut create_tmpl: [u32; 9] = [
        CKA_CLASS, class_ptr as u32, 4,
        CKA_VALUE, payload.as_ptr() as u32, payload.len() as u32,
        CKA_TOKEN, token_ptr as u32, 1,
    ];

    let mut h_obj: u32 = 0;
    let rv = C_CreateObject(h_sess, create_tmpl.as_mut_ptr() as *mut u8, 3, &mut h_obj);
    assert_eq!(rv, CKR_OK, "C_CreateObject CKO_DATA: 0x{:x}", rv);
    assert_ne!(h_obj, 0, "object handle must be non-zero");

    // ── Find by class ────────────────────────────────────────────────────
    // We search by CKA_CLASS = CKO_DATA. The value stored internally is
    // 4-byte LE so our search template must match that exact encoding.
    let mut find_class_buf = [0u8; 4];
    let find_class_ptr = u32_attr(&mut find_class_buf, CKO_DATA);
    let mut find_tmpl: [u32; 3] = [CKA_CLASS, find_class_ptr as u32, 4];

    let rv = C_FindObjectsInit(h_sess, find_tmpl.as_mut_ptr() as *mut u8, 1);
    assert_eq!(rv, CKR_OK, "C_FindObjectsInit: 0x{:x}", rv);

    let mut found_handles = vec![0u32; 16];
    let mut found_count: u32 = 0;
    let rv = C_FindObjects(
        h_sess,
        found_handles.as_mut_ptr(),
        found_handles.len() as u32,
        &mut found_count,
    );
    assert_eq!(rv, CKR_OK, "C_FindObjects: 0x{:x}", rv);
    C_FindObjectsFinal(h_sess);

    found_handles.truncate(found_count as usize);
    assert!(
        found_handles.contains(&h_obj),
        "created object not found in FindObjects results"
    );

    // ── Read CKA_VALUE back ──────────────────────────────────────────────
    // Two-pass: first with null ptr to discover length, then allocate + read.
    let mut getattr_tmpl: [u32; 3] = [CKA_VALUE, 0, 0]; // ptr=null → size query
    C_GetAttributeValue(h_sess, h_obj, getattr_tmpl.as_mut_ptr() as *mut u8, 1);
    let attr_len = getattr_tmpl[2] as usize;
    assert_eq!(attr_len, payload.len(), "CKA_VALUE length mismatch");

    let mut val_buf = vec![0u8; attr_len];
    let mut getattr_tmpl2: [u32; 3] = [CKA_VALUE, val_buf.as_mut_ptr() as u32, attr_len as u32];
    let rv = C_GetAttributeValue(h_sess, h_obj, getattr_tmpl2.as_mut_ptr() as *mut u8, 1);
    assert_eq!(rv, CKR_OK, "C_GetAttributeValue: 0x{:x}", rv);

    // ── Destroy ─────────────────────────────────────────────────────────
    let rv = C_DestroyObject(h_sess, h_obj);
    assert_eq!(rv, CKR_OK, "C_DestroyObject: 0x{:x}", rv);

    // Verify it's gone: find again → should not contain h_obj
    let mut find2_tmpl: [u32; 3] = [CKA_CLASS, find_class_ptr as u32, 4];
    C_FindObjectsInit(h_sess, find2_tmpl.as_mut_ptr() as *mut u8, 1);
    let mut found2 = vec![0u32; 16];
    let mut found2_count: u32 = 0;
    C_FindObjects(h_sess, found2.as_mut_ptr(), 16, &mut found2_count);
    C_FindObjectsFinal(h_sess);
    found2.truncate(found2_count as usize);
    assert!(
        !found2.contains(&h_obj),
        "destroyed object still returned by FindObjects"
    );

    val_buf
}

// ── wasm-bindgen-test suite ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use softhsmrustv3::constants::CKR_SIGNATURE_INVALID;
    use wasm_bindgen_test::*;

    // wasm-bindgen-test runs in Node by default when invoked via
    // `wasm-pack test --node`.

    // ── SHA-256 KAT ──────────────────────────────────────────────────────────

    /// FIPS 180-4 §B.1 — SHA-256("abc") known-answer test.
    #[wasm_bindgen_test]
    fn sha256_known_answer() {
        let h = sha256_via_softhsm(b"abc");
        assert_eq!(
            hex::encode(&h),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "FIPS 180-4 §B.1 SHA-256(\"abc\") KAT"
        );
    }

    // ── RNG smoke ────────────────────────────────────────────────────────────

    #[wasm_bindgen_test]
    fn random_returns_nonzero_bytes() {
        let r = random_via_softhsm(48);
        assert_eq!(r.len(), 48);
        assert!(
            r.iter().any(|&b| b != 0),
            "softhsmrustv3 RNG returned all-zero — broken initialisation?"
        );
    }

    // ── HMAC-SHA-256 KAT ─────────────────────────────────────────────────────

    /// RFC 4231 §2 Test Case 1 — HMAC-SHA-256 known-answer test.
    ///
    /// Key  = 0x0b × 20 bytes
    /// Data = "Hi There"
    /// Expected MAC = b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
    #[wasm_bindgen_test]
    fn hmac_sha256_rfc4231_tc1() {
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let mac = hmac_sha256_via_softhsm(&key, data);
        assert_eq!(
            hex::encode(&mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            "RFC 4231 TC1 HMAC-SHA-256 KAT"
        );
    }

    // ── Ed25519 sign / verify ────────────────────────────────────────────────

    /// Roundtrip: a freshly generated Ed25519 keypair must produce a signature
    /// that verifies against the same message.
    #[wasm_bindgen_test]
    fn ed25519_sign_verify_roundtrip() {
        let msg = b"pqctoday MLS handshake test vector";
        let (h_pub, h_priv, _sig) = ed25519_sign_verify_via_softhsm(msg);
        // If we reach here without a panic, sign + verify both returned CKR_OK.
        C_DestroyObject(pkcs11_open_session(), h_pub);
        C_DestroyObject(pkcs11_open_session(), h_priv);
    }

    /// Negative: verifying with a different message must return CKR_SIGNATURE_INVALID.
    #[wasm_bindgen_test]
    fn ed25519_wrong_message_rejected() {
        let msg = b"correct message";
        let wrong_msg = b"tampered message";

        pkcs11_init_idempotent();
        let h_sess = pkcs11_open_session();

        // Generate keypair + sign "correct message"
        let mut mech_kpg: [u32; 3] = [CKM_EC_EDWARDS_KEY_PAIR_GEN, 0, 0];
        let mut h_pub: u32 = 0;
        let mut h_priv: u32 = 0;
        let rv = C_GenerateKeyPair(
            h_sess,
            mech_kpg.as_mut_ptr() as *mut u8,
            std::ptr::null_mut(), 0,
            std::ptr::null_mut(), 0,
            &mut h_pub, &mut h_priv,
        );
        assert_eq!(rv, CKR_OK, "C_GenerateKeyPair: 0x{:x}", rv);

        let mut mech_sign: [u32; 3] = [CKM_EDDSA, 0, 0];
        C_SignInit(h_sess, mech_sign.as_mut_ptr() as *mut u8, h_priv);
        let mut sig = vec![0u8; 64];
        let mut sig_len: u32 = 64;
        let rv = C_Sign(
            h_sess,
            msg.as_ptr() as *mut u8, msg.len() as u32,
            sig.as_mut_ptr(), &mut sig_len,
        );
        assert_eq!(rv, CKR_OK, "C_Sign: 0x{:x}", rv);

        // Verify against wrong message — must fail
        let mut mech_ver: [u32; 3] = [CKM_EDDSA, 0, 0];
        let rv = C_VerifyInit(h_sess, mech_ver.as_mut_ptr() as *mut u8, h_pub);
        assert_eq!(rv, CKR_OK, "C_VerifyInit: 0x{:x}", rv);

        let rv = C_Verify(
            h_sess,
            wrong_msg.as_ptr() as *mut u8, wrong_msg.len() as u32,
            sig.as_ptr() as *mut u8, sig_len,
        );
        assert_eq!(
            rv, CKR_SIGNATURE_INVALID,
            "wrong-message verify must return CKR_SIGNATURE_INVALID, got 0x{:x}", rv
        );

        C_DestroyObject(h_sess, h_pub);
        C_DestroyObject(h_sess, h_priv);
    }

    // ── AES-128-GCM KAT ─────────────────────────────────────────────────────

    /// NIST GCM Specification (McGrew-Viega) Appendix B Test Case 3.
    /// Same vector used by the provider's native `kat_aes128_gcm_nist_gcm_spec_test_case_3`.
    ///
    /// K = feffe9928665731c6d6a8f9467308308
    /// IV = cafebabefacedbaddecaf888
    /// P = d9313225...aafd255  (64 bytes, non-trivial)
    /// A = (empty)
    /// C||T = 42831ec2...b2fab4  (80 bytes = 64 ct + 16 tag)
    ///
    /// AES-GCM is deterministic: given fixed K, IV, and P the output is always
    /// identical. The test is a byte-exact KAT against the published vector.
    #[wasm_bindgen_test]
    fn aes128_gcm_nist_tc3_encrypt() {
        let key = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
        let iv = hex::decode("cafebabefacedbaddecaf888").unwrap();
        let pt = hex::decode(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        ).unwrap();
        let expected = hex::decode(
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
             21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985\
             4d5c2af327cd64a62cf35abd2ba6fab4",
        ).unwrap();
        let ct = aes128_gcm_encrypt_via_softhsm(&key, &iv, &pt);
        assert_eq!(ct.len(), 80, "64-byte plaintext + 16-byte tag = 80 bytes");
        assert_eq!(
            hex::encode(&ct),
            hex::encode(&expected),
            "NIST GCM Spec TC3 AES-128-GCM encrypt KAT"
        );
    }

    /// Decrypt the TC3 ciphertext and recover the known plaintext.
    #[wasm_bindgen_test]
    fn aes128_gcm_nist_tc3_decrypt() {
        let key = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
        let iv = hex::decode("cafebabefacedbaddecaf888").unwrap();
        let ct = hex::decode(
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
             21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985\
             4d5c2af327cd64a62cf35abd2ba6fab4",
        ).unwrap();
        let expected_pt = hex::decode(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        ).unwrap();
        let pt = aes128_gcm_decrypt_via_softhsm(&key, &iv, &ct);
        assert_eq!(pt, expected_pt, "NIST GCM Spec TC3 AES-128-GCM decrypt KAT");
    }

    // ── Data object lifecycle ────────────────────────────────────────────────

    /// Full lifecycle: C_CreateObject → FindObjects → GetAttributeValue →
    /// C_DestroyObject → verify gone.
    #[wasm_bindgen_test]
    fn data_object_create_find_read_destroy() {
        let payload = b"pqctoday-hsm-phase5-smoke";
        let retrieved = data_object_lifecycle_via_softhsm(payload);
        assert_eq!(retrieved, payload, "retrieved CKA_VALUE must match what was stored");
    }
}
