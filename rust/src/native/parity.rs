//! Cross-API parity tests — `ffi::C_*` vs `native::*` produce the
//! same cryptographic output against the same engine state.
//!
//! ## Why this exists
//!
//! `softhsmrustv3::ffi` (PKCS#11 C ABI, wasm32-targeted) and
//! `softhsmrustv3::native` (typed Rust API, native-targeted) are
//! **parallel surfaces over the same engine internals**
//! (`crypto::handlers::*` + `state::*`). The dual-API contract
//! documented in `docs/NATIVE_API.md` §5 says: any future engine
//! change MUST preserve byte-equivalent output across both surfaces
//! for the operations both expose.
//!
//! These tests lock that contract in.
//!
//! ## What we test (and what we deliberately skip)
//!
//! The C ABI's attribute-template marshalling uses **32-bit pointers**
//! (`pValue as u32 as usize as *const u8`). On native 64-bit, this
//! silently truncates pointers, so we **cannot** call `ffi::C_*`
//! functions that take `CK_ATTRIBUTE` templates from native code
//! (`C_CreateObject`, `C_GenerateKeyPair`, `C_GenerateKey`,
//! `C_FindObjectsInit`).
//!
//! The C ABI functions we CAN exercise from native — they take only
//! plain `*mut u8` data buffers + `*mut u32` length pointers, no
//! templates:
//!
//! - `C_SignInit` / `C_Sign` — mechanism struct has null `pParameter`
//!   for unparametrised algs (HMAC, ML-DSA, EdDSA basic)
//! - `C_VerifyInit` / `C_Verify` — same
//! - `C_EncryptInit` / `C_Encrypt` — for ML-KEM no params; AES-GCM
//!   needs `CK_GCM_PARAMS` (skipped — would need 32-bit-addressable
//!   params)
//! - `C_DecryptInit` / `C_Decrypt` — same
//! - `C_DestroyObject` — handle only, no template
//! - `C_Initialize` / `C_Finalize` / `C_OpenSession` / `C_Login` /
//!   `C_Logout` / `C_CloseSession` — already exercised by
//!   `native::session` (which wraps these).
//!
//! So this module focuses on the operations that **don't** need
//! template marshalling:
//!
//! 1. **HMAC byte-exact parity** — HMAC is deterministic. Same key,
//!    same data → byte-identical MAC from `native::sign` and
//!    `ffi::C_Sign`.
//! 2. **ML-DSA cross-verify** — ML-DSA signing is non-deterministic
//!    (random hedge), so the bytes differ between two `sign` calls.
//!    But: signatures from one API must verify against the other.
//!    Native sign → ffi verify and ffi sign → native verify both
//!    succeed.
//! 3. **destroy_object semantics** — `native::destroy_object` and
//!    `ffi::C_DestroyObject` produce the same final state (handle
//!    removed, sign-state cleaned up).
//!
//! ML-KEM encap/decap parity is **deferred to PR-side integration
//! testing** because `ffi::C_EncapsulateKey` / `C_DecapsulateKey`
//! both take attribute templates for the resulting shared-secret
//! object — calling them from native would hit the wasm32 ABI
//! mismatch. The parity that matters in production is exercised by
//! the headline KMIP demo (Phase 12 dev-sandbox MVP), not by these
//! unit tests.

#![cfg(test)]

use crate::constants::*;
use crate::native::keygen::{
    generate_generic_secret, generate_ml_dsa_keypair, generate_ml_dsa_keypair_from_seed,
    generate_ml_kem_keypair_from_seed, generate_slh_dsa_keypair_from_seed,
};
use crate::native::object::destroy_object;
use crate::native::session::{bootstrap_default_token, close_session, finalize, init};
use crate::native::sign::{sign, verify};
use crate::native::test_lock;

use crate::ffi as ffi;

fn fresh_session() -> u32 {
    let _ = finalize();
    init().unwrap();
    bootstrap_default_token(0, "so", "user", "parity-test").unwrap()
}

/// HMAC-SHA-256: deterministic — `native::sign` and `ffi::C_Sign`
/// against the same key and data MUST produce byte-identical MACs.
#[test]
fn hmac_sha256_byte_exact_parity() {
    let _guard = test_lock::acquire();
    let session = fresh_session();
    let key = generate_generic_secret(session, 256, b"hmac-parity", "hmac-parity").unwrap();
    let message = b"identical input on both APIs";

    // Native path.
    let mac_native = sign(session, key, CKM_SHA256_HMAC, message).unwrap();
    assert_eq!(mac_native.len(), 32);

    // FFI path: CK_MECHANISM { mech_type: CKM_SHA256_HMAC, p_param: 0, len: 0 }
    let mut mech: [usize; 3] = [CKM_SHA256_HMAC as usize, 0, 0];
    let rv = ffi::C_SignInit(session, mech.as_mut_ptr() as *mut u8, key);
    assert_eq!(rv, CKR_OK, "ffi::C_SignInit HMAC: 0x{rv:x}");

    let mut sig_buf = vec![0u8; 32];
    let mut sig_len: u32 = 32;
    let mut data_buf = message.to_vec();
    let rv = ffi::C_Sign(
        session,
        data_buf.as_mut_ptr(),
        data_buf.len() as u32,
        sig_buf.as_mut_ptr(),
        &mut sig_len,
    );
    assert_eq!(rv, CKR_OK, "ffi::C_Sign HMAC: 0x{rv:x}");
    assert_eq!(sig_len, 32);

    assert_eq!(mac_native, sig_buf, "HMAC MACs MUST be byte-equivalent");
    close_session(session).unwrap();
}

/// ML-DSA cross-verify: native sign → ffi verify succeeds.
///
/// ML-DSA is non-deterministic so we can't byte-compare signatures
/// directly, but a signature from one API must verify with the other.
#[test]
fn ml_dsa_65_native_sign_then_ffi_verify_succeeds() {
    let _guard = test_lock::acquire();
    let session = fresh_session();
    let (pub_h, prv_h) =
        generate_ml_dsa_keypair(session, CKP_ML_DSA_65, b"cross-1", "cross-verify").unwrap();
    let message = b"hello world";

    // Native sign.
    let sig = sign(session, prv_h, CKM_ML_DSA, message).unwrap();
    assert_eq!(sig.len(), 3309, "FIPS 204 §5 ML-DSA-65 sig = 3309 bytes");

    // FFI verify.
    let mut mech: [usize; 3] = [CKM_ML_DSA as usize, 0, 0];
    let rv = ffi::C_VerifyInit(session, mech.as_mut_ptr() as *mut u8, pub_h);
    assert_eq!(rv, CKR_OK, "ffi::C_VerifyInit: 0x{rv:x}");

    let mut data_buf = message.to_vec();
    let mut sig_buf = sig.clone();
    let rv = ffi::C_Verify(
        session,
        data_buf.as_mut_ptr(),
        data_buf.len() as u32,
        sig_buf.as_mut_ptr(),
        sig_buf.len() as u32,
    );
    assert_eq!(rv, CKR_OK, "ffi::C_Verify must accept native sig: 0x{rv:x}");
    close_session(session).unwrap();
}

/// ML-DSA cross-verify reverse direction: ffi sign → native verify.
#[test]
fn ml_dsa_65_ffi_sign_then_native_verify_succeeds() {
    let _guard = test_lock::acquire();
    let session = fresh_session();
    let (pub_h, prv_h) =
        generate_ml_dsa_keypair(session, CKP_ML_DSA_65, b"cross-2", "rev-verify").unwrap();
    let message = b"reverse direction";

    // FFI sign.
    let mut mech: [usize; 3] = [CKM_ML_DSA as usize, 0, 0];
    let rv = ffi::C_SignInit(session, mech.as_mut_ptr() as *mut u8, prv_h);
    assert_eq!(rv, CKR_OK);

    let mut sig_buf = vec![0u8; 3309];
    let mut sig_len: u32 = 3309;
    let mut data_buf = message.to_vec();
    let rv = ffi::C_Sign(
        session,
        data_buf.as_mut_ptr(),
        data_buf.len() as u32,
        sig_buf.as_mut_ptr(),
        &mut sig_len,
    );
    assert_eq!(rv, CKR_OK, "ffi::C_Sign ML-DSA: 0x{rv:x}");

    // Native verify.
    let valid = verify(session, pub_h, CKM_ML_DSA, message, &sig_buf).unwrap();
    assert!(valid, "native verify must accept ffi-produced ML-DSA sig");
    close_session(session).unwrap();
}

/// HMAC tampered tag — both APIs reject identically.
#[test]
fn hmac_tampered_tag_rejected_by_both_apis() {
    let _guard = test_lock::acquire();
    let session = fresh_session();
    let key = generate_generic_secret(session, 256, b"tamper-parity", "tamper").unwrap();
    let message = b"data";

    let mut mac = sign(session, key, CKM_SHA256_HMAC, message).unwrap();
    mac[0] ^= 0xFF;

    // Native: Ok(false) (KMIP ValidityIndicator semantics).
    assert_eq!(
        verify(session, key, CKM_SHA256_HMAC, message, &mac),
        Ok(false)
    );

    // FFI: returns CKR_SIGNATURE_INVALID.
    let mut mech: [usize; 3] = [CKM_SHA256_HMAC as usize, 0, 0];
    let rv = ffi::C_VerifyInit(session, mech.as_mut_ptr() as *mut u8, key);
    assert_eq!(rv, CKR_OK);
    let mut data_buf = message.to_vec();
    let mut mac_buf = mac.clone();
    let rv = ffi::C_Verify(
        session,
        data_buf.as_mut_ptr(),
        data_buf.len() as u32,
        mac_buf.as_mut_ptr(),
        mac_buf.len() as u32,
    );
    assert_eq!(rv, CKR_SIGNATURE_INVALID, "ffi tampered → CKR_SIGNATURE_INVALID");
    close_session(session).unwrap();
}

/// destroy_object: native and ffi produce the same final state —
/// handle removed, subsequent ffi::C_DestroyObject returns
/// CKR_OBJECT_HANDLE_INVALID, native::destroy_object returns the same.
#[test]
fn destroy_object_parity_native_then_ffi() {
    let _guard = test_lock::acquire();
    let session = fresh_session();
    let (_, prv_h) =
        generate_ml_dsa_keypair(session, CKP_ML_DSA_65, b"destroy-1", "destroy").unwrap();

    // Native destroys it.
    destroy_object(session, prv_h).unwrap();

    // FFI sees the same final state — handle is invalid.
    let rv = ffi::C_DestroyObject(session, prv_h);
    assert_eq!(rv, CKR_OBJECT_HANDLE_INVALID, "ffi sees handle gone");
    close_session(session).unwrap();
}

#[test]
fn destroy_object_parity_ffi_then_native() {
    let _guard = test_lock::acquire();
    let session = fresh_session();
    let (_, prv_h) =
        generate_ml_dsa_keypair(session, CKP_ML_DSA_65, b"destroy-2", "destroy").unwrap();

    let rv = ffi::C_DestroyObject(session, prv_h);
    assert_eq!(rv, CKR_OK);
    // Native sees the same final state.
    assert_eq!(
        destroy_object(session, prv_h).unwrap_err(),
        CKR_OBJECT_HANDLE_INVALID
    );
    close_session(session).unwrap();
}

/// After destroy, sign with the destroyed handle must fail through
/// both APIs. Proves the SIGN_STATE cleanup hook destroy_object
/// inherits from ffi::C_DestroyObject works through native too.
#[test]
fn sign_after_destroy_fails_in_both_apis() {
    let _guard = test_lock::acquire();
    let session = fresh_session();
    let (_, prv_h) =
        generate_ml_dsa_keypair(session, CKP_ML_DSA_65, b"\x01", "sign-after-destroy").unwrap();
    destroy_object(session, prv_h).unwrap();

    // Native sign on destroyed handle — get_object_value returns None
    // (object gone), so the gate is hit before reaching the sign primitive.
    let err = sign(session, prv_h, CKM_ML_DSA, b"data").unwrap_err();
    // The exact error depends on which check fires first
    // (CKA_SIGN gate or CKA_VALUE missing); both are valid failure modes.
    assert!(
        err == CKR_KEY_FUNCTION_NOT_PERMITTED || err == CKR_ARGUMENTS_BAD,
        "destroyed handle: got rv=0x{err:x}"
    );

    // FFI sign on destroyed handle — CKR_KEY_HANDLE_INVALID. PKCS#11 v3.2
    // §5.1 error priority: the object-handle check fires before any
    // attribute gate (CKA_SIGN), and a destroyed handle no longer exists.
    let mut mech: [usize; 3] = [CKM_ML_DSA as usize, 0, 0];
    let rv = ffi::C_SignInit(session, mech.as_mut_ptr() as *mut u8, prv_h);
    assert_eq!(rv, CKR_KEY_HANDLE_INVALID);
    close_session(session).unwrap();
}

/// S3 — CKA_SEED sensitive-class parity: on a sensitive private key the
/// seed is blocked through BOTH surfaces — `native::object::get_attribute`
/// returns None and `ffi::C_GetAttributeValue` returns
/// CKR_ATTRIBUTE_SENSITIVE (same shared predicate
/// `state::attr_is_sensitive_material` + `state::value_is_blocked`).
#[test]
fn seed_blocked_on_sensitive_key_in_both_apis() {
    use crate::native::object::get_attribute;
    let _guard = test_lock::acquire();
    let session = fresh_session();
    let (_, prv_h) =
        generate_ml_dsa_keypair(session, CKP_ML_DSA_65, b"\x01", "seed-parity").unwrap();
    // ML-DSA private keys are CKA_SENSITIVE=TRUE by keygen default.

    // Native path: blocked.
    assert!(
        get_attribute(session, prv_h, CKA_SEED).is_none(),
        "native CKA_SEED readback must be blocked on a sensitive key"
    );
    // CKA_VALUE blocked identically (control).
    assert!(get_attribute(session, prv_h, CKA_VALUE).is_none());

    // FFI path: CK_ATTRIBUTE { CKA_SEED, NULL, 0 } size query — blocked with
    // CKR_ATTRIBUTE_SENSITIVE and ulValueLen = CK_UNAVAILABLE_INFORMATION.
    let mut tmpl: [usize; 3] = [CKA_SEED as usize, 0, 0];
    let rv = ffi::C_GetAttributeValue(session, prv_h, tmpl.as_mut_ptr() as *mut u8, 1);
    assert_eq!(rv, CKR_ATTRIBUTE_SENSITIVE);
    assert_eq!(tmpl[2], usize::MAX);
    close_session(session).unwrap();
}

/// S3 × T7 — a CKA_SEED stored by **deterministic keygen** lands on the
/// private object engine-side AND is blocked through both readback surfaces
/// (`native::object::get_attribute` → None, `ffi::C_GetAttributeValue` →
/// CKR_ATTRIBUTE_SENSITIVE). Checked for all three PQC families.
#[test]
fn deterministic_keygen_seed_stored_but_blocked_in_both_apis() {
    use crate::native::object::get_attribute;
    let _guard = test_lock::acquire();
    let session = fresh_session();

    let xi = [0x11u8; 32];
    let dz = [0x22u8; 64];
    let slh = [0x33u8; 48];
    let (_, dsa_prv) =
        generate_ml_dsa_keypair_from_seed(session, CKP_ML_DSA_44, &xi, b"\x01", "t7").unwrap();
    let (_, kem_prv) =
        generate_ml_kem_keypair_from_seed(session, CKP_ML_KEM_512, &dz, b"\x02", "t7").unwrap();
    let (_, slh_prv) = generate_slh_dsa_keypair_from_seed(
        session,
        CKP_SLH_DSA_SHA2_128F,
        &slh,
        b"\x03",
        "t7",
    )
    .unwrap();

    for (prv_h, seed) in [
        (dsa_prv, &xi[..]),
        (kem_prv, &dz[..]),
        (slh_prv, &slh[..]),
    ] {
        // Engine-side: the seed IS stored on the private object…
        let stored = crate::state::OBJECTS
            .with(|o| o.borrow().get(&prv_h).and_then(|a| a.get(&CKA_SEED).cloned()));
        assert_eq!(stored.as_deref(), Some(seed), "seed stored engine-side");

        // …but is NOT exportable: native::get_attribute is blocked
        // (keygen'd private keys are CKA_SENSITIVE=TRUE / EXTRACTABLE=FALSE),
        assert!(
            get_attribute(session, prv_h, CKA_SEED).is_none(),
            "native CKA_SEED readback must be blocked (h={prv_h})"
        );
        // …and the C ABI size query reports CKR_ATTRIBUTE_SENSITIVE.
        let mut tmpl: [usize; 3] = [CKA_SEED as usize, 0, 0];
        let rv = ffi::C_GetAttributeValue(session, prv_h, tmpl.as_mut_ptr() as *mut u8, 1);
        assert_eq!(rv, CKR_ATTRIBUTE_SENSITIVE);
        assert_eq!(tmpl[2], usize::MAX);
    }
    close_session(session).unwrap();
}

/// S3 — CKA_UNIQUE_ID parity: objects created through the native surface
/// (keygen) carry token-generated unique ids readable from both APIs, and
/// the ids differ across objects.
#[test]
fn unique_id_present_and_distinct_on_generated_objects() {
    use crate::native::object::get_attribute;
    let _guard = test_lock::acquire();
    let session = fresh_session();
    let (pub_h, prv_h) =
        generate_ml_dsa_keypair(session, CKP_ML_DSA_65, b"\x01", "uid-parity").unwrap();

    // Native readback.
    let uid_pub = get_attribute(session, pub_h, CKA_UNIQUE_ID).expect("pub has CKA_UNIQUE_ID");
    let uid_prv = get_attribute(session, prv_h, CKA_UNIQUE_ID).expect("prv has CKA_UNIQUE_ID");
    assert_eq!(uid_pub.len(), 36, "CKA_UNIQUE_ID is a 36-char UUID");
    assert_eq!(uid_prv.len(), 36, "CKA_UNIQUE_ID is a 36-char UUID");
    assert_ne!(uid_pub, uid_prv, "unique ids must differ across objects");

    // FFI readback (size query): CKA_UNIQUE_ID is NOT sensitive-blocked even
    // on the sensitive private key — it is metadata, not key material.
    let mut tmpl: [usize; 3] = [CKA_UNIQUE_ID as usize, 0, 0];
    let rv = ffi::C_GetAttributeValue(session, prv_h, tmpl.as_mut_ptr() as *mut u8, 1);
    assert_eq!(rv, CKR_OK);
    assert_eq!(tmpl[2] as usize, uid_prv.len());

    // Read-only through the native set path.
    assert_eq!(
        crate::native::object::set_attribute(session, prv_h, CKA_UNIQUE_ID, b"forged".to_vec())
            .unwrap_err(),
        CKR_ATTRIBUTE_READ_ONLY
    );
    // CKA_TRUSTED equally refused (SO-only; no SO-session concept in-crate).
    assert_eq!(
        crate::native::object::set_attribute(session, pub_h, CKA_TRUSTED, vec![0x01])
            .unwrap_err(),
        CKR_ATTRIBUTE_READ_ONLY
    );
    close_session(session).unwrap();
}
