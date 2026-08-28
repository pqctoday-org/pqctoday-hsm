//! Object lifecycle + attribute queries — typed wrappers around the
//! engine's typed object storage (`state::*`, `OBJECTS`).
//!
//! The engine's storage layer is already typed Rust; this module just
//! exposes the operations KMIP needs as typed APIs (no CK_ATTRIBUTE
//! template marshalling).
//!
//! See [`super`] for the typed-vs-FFI architectural relationship.

use super::CkRv;
use super::keygen::CKA_ID;
use crate::constants::*;
use crate::state::{
    can_access_object_with, get_object_attr_bytes_from, resolve_session_access,
    take_object_checked, with_object_checked, OBJECTS,
};

/// Destroy an object by handle. Wraps `ffi::C_DestroyObject`'s engine
/// logic: removes the object from `OBJECTS`, zeroises `CKA_VALUE`,
/// and cleans up any in-flight sign / verify / encrypt / decrypt state
/// that referenced the handle.
///
/// After this call the handle is invalid; subsequent ops return
/// `CKR_OBJECT_HANDLE_INVALID`.
pub fn destroy_object(session: u32, handle: u32) -> Result<(), CkRv> {
    use crate::state::{DECRYPT_STATE, ENCRYPT_STATE, SIGN_STATE, VERIFY_STATE};
    use zeroize::Zeroize;

    // Isolation gate folded into the removal itself (take_object_checked
    // verifies access BEFORE removing, under one write-lock acquisition —
    // a failed check never mutates OBJECTS). Same error code
    // (CKR_OBJECT_HANDLE_INVALID) the un-gated version already returned
    // for a missing handle, now also covering cross-slot / not-logged-in.
    let access = resolve_session_access(session)?;
    let mut attrs = take_object_checked(&access, handle)?;
    // Persist the deletion BEFORE zeroising CKA_VALUE below — not that it
    // matters for correctness here (the delete doesn't read attribute
    // values), but keeping "was this ever a token object" checked against
    // the still-intact attrs is simpler than tracking it separately.
    if crate::state::read_bool_attr(&attrs, CKA_TOKEN) {
        crate::store::persist_delete(crate::state::object_slot_of(&attrs), handle);
    }
    // Zeroise key material before deallocation (RS-02 — matches
    // ffi::C_DestroyObject).
    if let Some(val) = attrs.get_mut(&CKA_VALUE) {
        val.zeroize();
    }

    // PKCS#11 v3.2 — clean up any active operation state referencing the
    // destroyed key. Without this, a session that called native::sign +
    // then native::destroy_object would hold a stale key handle in the
    // sign-state map.
    SIGN_STATE.with(|s| s.borrow_mut().retain(|_, v| v.1 != handle));
    VERIFY_STATE.with(|s| s.borrow_mut().retain(|_, v| v.1 != handle));
    ENCRYPT_STATE.with(|s| s.borrow_mut().retain(|_, ctx| ctx.key_handle != handle));
    DECRYPT_STATE.with(|s| s.borrow_mut().retain(|_, ctx| ctx.key_handle != handle));
    Ok(())
}

/// Look up an object handle by `CKA_ID`. Returns `Ok(None)` if no object
/// matches.
///
/// Used by the KMIP `MemoryStore` / `SqliteStore` layer to recover the
/// engine-scoped `CK_OBJECT_HANDLE` from the stable `CKA_ID` the KMIP
/// store persists per KMIP UID. If multiple objects share the same
/// `CKA_ID` (e.g. matched public + private keypair from
/// [`super::keygen::generate_ml_dsa_keypair`]), returns the first match —
/// callers needing per-class filtering should add a `class` arg or use
/// [`find_all_by_cka_id`].
pub fn find_by_cka_id(session: u32, cka_id: &[u8]) -> Result<Option<u32>, CkRv> {
    let handles = find_all_by_cka_id(session, cka_id)?;
    Ok(handles.first().copied())
}

/// Same as [`find_by_cka_id`] but returns ALL handles matching the
/// `CKA_ID`. Typical use: looking up both halves of a freshly-generated
/// keypair (pub + prv share the CKA_ID set at keygen time).
///
/// T3 (multi-slot scoping) — enumeration is TOKEN-scoped: only objects owned
/// by `session`'s slot match (PKCS#11 v3.2 §2.4 — tokens do not see each
/// other's objects).
///
/// CORRECTED 2026-07-18 (rust-hsm-perf-bench-scenario-plan-07182026.md
/// Part F): by-handle native accessors are NO LONGER handle-global — every
/// one gates through `state::can_access_object_with` (this function's own
/// filter predicate below), the same token-scoping `ffi::C_*` has always
/// enforced. An unknown session now errors (`CKR_SESSION_HANDLE_INVALID`)
/// instead of silently scoping to slot 0. The filter also gains the LOGIN
/// clause (`can_access_object_with`, not just a slot comparison), so
/// FindObjects parity with `ffi::C_FindObjects`'s enumeration gate
/// (ffi.rs ~5888) is exact: a private object on a not-logged-in token no
/// longer matches.
pub fn find_all_by_cka_id(session: u32, cka_id: &[u8]) -> Result<Vec<u32>, CkRv> {
    let access = resolve_session_access(session)?;
    let matches: Vec<u32> = OBJECTS.with(|o| {
        o.borrow()
            .iter()
            .filter_map(|(handle, attrs)| match attrs.get(&CKA_ID) {
                Some(v) if v == cka_id && can_access_object_with(&access, attrs) => Some(*handle),
                _ => None,
            })
            .collect()
    });
    Ok(matches)
}

/// Read a single attribute. Returns `None` if the attribute is absent OR
/// the object's policy marks it sensitive on a private/secret key
/// (`CKA_SENSITIVE = true` blocks access to `CKA_VALUE` — same rule
/// `ffi::C_GetAttributeValue` enforces per PKCS#11 v3.2 §4.7).
///
/// For known-sized scalar attrs the caller decodes the returned bytes as
/// LE u32 etc.; convenience wrappers [`get_attribute_u32`] and
/// [`get_attribute_bool`] do the decode.
pub fn get_attribute(session: u32, handle: u32, attr_type: u32) -> Option<Vec<u8>> {
    // Isolation gate + sensitivity policy, one borrow. Same predicates as
    // ffi::C_GetAttributeValue (state::value_is_blocked +
    // state::attr_is_sensitive_material): CKA_VALUE / CKA_SEED of
    // private/secret keys are blocked when CKA_SENSITIVE=TRUE **or**
    // CKA_EXTRACTABLE=FALSE (PKCS#11 v3.2 §4.9/§4.10; the v3.2 PQC key tables
    // footnote CKA_SEED identically to CKA_VALUE). Sharing the predicates
    // keeps the native and C-ABI surfaces from drifting. Gate failure (bad
    // session, unknown/cross-slot/not-logged-in handle) folds into `None`,
    // matching this function's existing "absent" contract.
    let access = resolve_session_access(session).ok()?;
    with_object_checked(&access, handle, |attrs| {
        if crate::state::attr_is_sensitive_material(attr_type) && crate::state::value_is_blocked(attrs) {
            return None;
        }
        get_object_attr_bytes_from(attrs, attr_type)
    })
    .ok()
    .flatten()
}

/// SHA-256 digest of an object's `CKA_VALUE` bytes, computed inside the
/// engine boundary. Unlike [`get_attribute`] this does NOT export the
/// material — only the 32-byte hash leaves the engine — so the
/// PKCS#11 sensitivity policy (`CKA_SENSITIVE` / `CKA_EXTRACTABLE`)
/// does not block it. Exists for the KMIP layer: KMIP 3.0 §11 requires
/// the server to surface a `Digest` attribute (hash of the actual key
/// material) on every managed cryptographic object, including
/// non-extractable private keys.
///
/// Returns `None` when the object has no `CKA_VALUE` (e.g. a destroyed
/// or value-less object).
pub fn get_value_digest_sha256(session: u32, handle: u32) -> Option<Vec<u8>> {
    use sha2::{Digest, Sha256};
    let access = resolve_session_access(session).ok()?;
    with_object_checked(&access, handle, |attrs| {
        get_object_attr_bytes_from(attrs, CKA_VALUE).map(|v| Sha256::digest(&v).to_vec())
    })
    .ok()
    .flatten()
}

/// Mutate an attribute, enforcing PKCS#11 v3.2 §4.1.1 policy: server-managed
/// attributes are CKR_ATTRIBUTE_READ_ONLY; CKA_SENSITIVE only FALSE→TRUE;
/// CKA_EXTRACTABLE only TRUE→FALSE. Vendor stateful-key attrs (≥0x8000_0000)
/// bypass the policy — they are the engine/KMIP internal state channel.
pub fn set_attribute(
    session: u32,
    handle: u32,
    attr_type: u32,
    value: Vec<u8>,
) -> Result<(), CkRv> {
    // Isolation gate first (separate lock — `set_object_attr_checked` is
    // shared with `ffi::C_SetAttributeValue`'s mutation-policy logic and
    // does its own locking; kept untouched rather than folded in, to
    // avoid touching a function ffi.rs also depends on).
    let access = resolve_session_access(session)?;
    with_object_checked(&access, handle, |_| ())?;
    crate::state::set_object_attr_checked(handle, attr_type, value)
}

/// Create a `CKO_CERTIFICATE` object (X.509 only, §4.6.3) as an engine
/// projection of a KMIP-managed certificate — see
/// [`super::keygen::register_rsa_public_key_der`] for the equivalent
/// key-registration pattern this mirrors. No DER parsing here: `subject`/
/// `issuer`/`serial_number` are pre-extracted by the caller (the KMIP crate
/// already links `x509_cert` for `Certify`; the engine stays parser-free).
///
/// `cka_id`, when non-empty, links the certificate to its key pair (KMIP's
/// Public Key Link) — the same CKA_ID a strongSwan-style consumer matches
/// a certificate to its private key with.
pub fn register_certificate(
    session: u32,
    der_value: &[u8],
    subject: &[u8],
    issuer: &[u8],
    serial_number: &[u8],
    category: u32,
    cka_id: &[u8],
    label: &str,
) -> Result<u32, CkRv> {
    use crate::state::{allocate_handle, compute_kcv, store_bool, store_ulong, tag_object_slot};

    // §4.6.1/§4.6.3 footnote 1 — CKA_CERTIFICATE_TYPE and CKA_SUBJECT are
    // mandatory; mirrors ffi::validate_create_template's C_CreateObject
    // rules so a KMIP-projected certificate is never laxer than one a raw
    // PKCS#11 caller could create directly.
    if der_value.is_empty() || subject.is_empty() {
        return Err(CKR_ARGUMENTS_BAD);
    }
    let mut attrs = std::collections::HashMap::new();
    store_ulong(&mut attrs, CKA_CLASS, CKO_CERTIFICATE);
    store_ulong(&mut attrs, CKA_CERTIFICATE_TYPE, CKC_X_509);
    store_ulong(&mut attrs, CKA_CERTIFICATE_CATEGORY, category);
    attrs.insert(CKA_VALUE, der_value.to_vec());
    attrs.insert(CKA_SUBJECT, subject.to_vec());
    if !issuer.is_empty() {
        attrs.insert(CKA_ISSUER, issuer.to_vec());
    }
    if !serial_number.is_empty() {
        attrs.insert(CKA_SERIAL_NUMBER, serial_number.to_vec());
    }
    if !cka_id.is_empty() {
        attrs.insert(CKA_ID, cka_id.to_vec());
    }
    if !label.is_empty() {
        attrs.insert(super::keygen::CKA_LABEL, label.as_bytes().to_vec());
    }
    // §4.6 — certificates are public, token objects.
    store_bool(&mut attrs, CKA_TOKEN, true);
    store_bool(&mut attrs, CKA_PRIVATE, false);
    compute_kcv(&mut attrs);
    tag_object_slot(session, &mut attrs);
    Ok(allocate_handle(attrs))
}

/// Read a `u32` attribute (4-byte little-endian — engine's storage
/// convention). Returns `None` if the attribute is absent or is
/// blocked by sensitivity policy.
pub fn get_attribute_u32(session: u32, handle: u32, attr_type: u32) -> Option<u32> {
    // Routes through the already-gated `get_attribute` (equivalent to the
    // prior "only sensitivity-check for sensitive material" logic: for
    // non-sensitive types `value_is_blocked` is never reached, so this is
    // the same bytes, now also isolation-gated).
    let bytes = get_attribute(session, handle, attr_type)?;
    if bytes.len() >= 4 {
        Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    } else {
        None
    }
}

/// Read a `CK_BBOOL` attribute (1 byte: 0x01 = true, 0x00 = false).
/// Returns `None` if the attribute is absent.
pub fn get_attribute_bool(session: u32, handle: u32, attr_type: u32) -> Option<bool> {
    let access = resolve_session_access(session).ok()?;
    with_object_checked(&access, handle, |attrs| {
        attrs.get(&attr_type).map(|v| !v.is_empty() && v[0] == 0x01)
    })
    .ok()
    .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::keygen::{generate_aes_key, generate_ml_dsa_keypair, generate_ml_kem_keypair};
    use crate::native::session::{bootstrap_default_token, close_session, finalize, init};
    use crate::native::test_lock;

    fn fresh_session() -> u32 {
        let _ = finalize();
        init().unwrap();
        bootstrap_default_token(0, "so", "user", "native-object-test").unwrap()
    }

    /// destroy_object removes the handle; subsequent
    /// get_attribute returns None.
    #[test]
    fn destroy_object_removes_handle() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let handle = generate_aes_key(session, 256, b"\x01", "destroy-me").unwrap();
        assert!(get_attribute_bool(session, handle, CKA_ENCRYPT).unwrap());
        destroy_object(session, handle).unwrap();
        // Handle no longer resolves.
        assert!(get_attribute_bool(session, handle, CKA_ENCRYPT).is_none());
        close_session(session).unwrap();
    }

    /// destroy_object on a stale handle returns CKR_OBJECT_HANDLE_INVALID.
    #[test]
    fn destroy_object_on_stale_handle_returns_err() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let err = destroy_object(session, 999_999).unwrap_err();
        assert_eq!(err, CKR_OBJECT_HANDLE_INVALID);
        close_session(session).unwrap();
    }

    /// destroy_object zeroises CKA_VALUE for symmetric keys. After
    /// destruction the bytes are wiped (and subsequent get_attribute
    /// returns None since the handle is gone).
    #[test]
    fn destroy_object_zeroises_value() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let handle = generate_aes_key(session, 256, b"\x01", "wipe-me").unwrap();
        destroy_object(session, handle).unwrap();
        // Handle gone — CKA_VALUE no longer fetchable.
        assert!(get_attribute(session, handle, CKA_VALUE).is_none());
        close_session(session).unwrap();
    }

    /// find_by_cka_id returns the public + private handles produced by
    /// a single keypair generation (both halves share the CKA_ID).
    #[test]
    fn find_by_cka_id_locates_keypair_handles() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let cka_id = b"\xde\xad\xbe\xef";
        let (pub_h, prv_h) =
            generate_ml_dsa_keypair(session, CKP_ML_DSA_65, cka_id, "found-me").unwrap();

        let all = find_all_by_cka_id(session, cka_id).unwrap();
        assert_eq!(all.len(), 2, "pub + prv share CKA_ID");
        assert!(all.contains(&pub_h));
        assert!(all.contains(&prv_h));

        let first = find_by_cka_id(session, cka_id).unwrap().unwrap();
        assert!(first == pub_h || first == prv_h);
        close_session(session).unwrap();
    }

    /// T3 — find_all_by_cka_id is token-scoped: keys created through a
    /// slot-1 session are invisible to a slot-0 session's CKA_ID search
    /// (and vice versa), even when both share the same CKA_ID. Slot 1 is
    /// brought online via the `state::ensure_slot` activation hook (the
    /// engine boots single-slot).
    ///
    /// FLIPPED 2026-07-18 (Part F, isolation gate): by-handle native
    /// access is no longer handle-global — a foreign-slot handle now
    /// correctly fails to resolve, same as `ffi::C_*` has always
    /// enforced. This test used to assert the opposite (a documented,
    /// intentional gap); see rust-hsm-perf-bench-scenario-plan-07182026.md
    /// §E2/§F for the history.
    #[test]
    fn find_by_cka_id_is_token_scoped() {
        let _guard = test_lock::acquire();
        let s0 = fresh_session();
        crate::state::ensure_slot(1);
        let s1 = bootstrap_default_token(1, "so", "user", "native-object-slot1").unwrap();

        let cka_id = b"shared-id";
        let h0 = generate_aes_key(s0, 256, cka_id, "slot0-key").unwrap();
        let h1 = generate_aes_key(s1, 256, cka_id, "slot1-key").unwrap();

        let found0 = find_all_by_cka_id(s0, cka_id).unwrap();
        assert_eq!(found0, vec![h0], "slot-0 search sees only slot-0's key");
        let found1 = find_all_by_cka_id(s1, cka_id).unwrap();
        assert_eq!(found1, vec![h1], "slot-1 search sees only slot-1's key");

        // Isolation gate now denies cross-tenant handle access: slot-0's
        // session cannot use slot-1's object handle at all.
        assert_eq!(
            get_attribute_u32(s0, h1, CKA_VALUE_LEN),
            None,
            "cross-slot handle access must now be denied"
        );
        // Each token's own session still works normally.
        assert_eq!(get_attribute_u32(s0, h0, CKA_VALUE_LEN), Some(32));
        assert_eq!(get_attribute_u32(s1, h1, CKA_VALUE_LEN), Some(32));

        close_session(s0).unwrap();
        close_session(s1).unwrap();
    }

    /// find_by_cka_id returns None when no object matches.
    #[test]
    fn find_by_cka_id_returns_none_when_absent() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        // No objects with this CKA_ID.
        let result = find_by_cka_id(session, b"nonexistent").unwrap();
        assert_eq!(result, None);
        close_session(session).unwrap();
    }

    /// find_by_cka_id discriminates between different CKA_IDs — two
    /// keypairs with different CKA_IDs return their own handles only.
    #[test]
    fn find_by_cka_id_discriminates_between_objects() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_a, prv_a) =
            generate_ml_dsa_keypair(session, CKP_ML_DSA_65, b"id-a", "keypair-a").unwrap();
        let (pub_b, prv_b) =
            generate_ml_kem_keypair(session, CKP_ML_KEM_768, b"id-b", "keypair-b").unwrap();

        let found_a = find_all_by_cka_id(session, b"id-a").unwrap();
        assert_eq!(found_a.len(), 2);
        assert!(found_a.contains(&pub_a) && found_a.contains(&prv_a));
        assert!(!found_a.contains(&pub_b) && !found_a.contains(&prv_b));

        let found_b = find_all_by_cka_id(session, b"id-b").unwrap();
        assert_eq!(found_b.len(), 2);
        assert!(found_b.contains(&pub_b) && found_b.contains(&prv_b));
        close_session(session).unwrap();
    }

    /// get_attribute returns the stored CKA_LABEL for a public key
    /// (no sensitivity gate on public objects).
    #[test]
    fn get_attribute_returns_stored_label() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, _) = generate_ml_dsa_keypair(session, CKP_ML_DSA_65, b"\x01", "my-label").unwrap();
        let label = get_attribute(session, pub_h, super::super::keygen::CKA_LABEL).unwrap();
        assert_eq!(label, b"my-label");
        close_session(session).unwrap();
    }

    /// get_attribute_u32 decodes CKA_VALUE_LEN on an AES key.
    #[test]
    fn get_attribute_u32_decodes_value_len() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let handle = generate_aes_key(session, 256, b"\x01", "aes-len").unwrap();
        assert_eq!(get_attribute_u32(session, handle, CKA_VALUE_LEN), Some(32));
        close_session(session).unwrap();
    }

    /// get_attribute_bool decodes CKA_ENCRYPT on an AES key (true).
    #[test]
    fn get_attribute_bool_decodes_flag() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let handle = generate_aes_key(session, 256, b"\x01", "aes-flag").unwrap();
        assert_eq!(get_attribute_bool(session, handle, CKA_ENCRYPT), Some(true));
        assert_eq!(get_attribute_bool(session, handle, CKA_SIGN), Some(false));
        close_session(session).unwrap();
    }

    /// get_attribute on CKA_VALUE for a private key with CKA_SENSITIVE
    /// = true (ML-DSA keygen default) returns None. PKCS#11 v3.2 §4.7
    /// sensitivity gate.
    #[test]
    fn get_attribute_blocks_value_on_sensitive_private_key() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (_, prv_h) = generate_ml_dsa_keypair(session, CKP_ML_DSA_65, b"\x01", "sensitive").unwrap();
        // CKA_SENSITIVE is true on PQC private keys by keygen default.
        assert_eq!(get_attribute_bool(session, prv_h, CKA_SENSITIVE), Some(true));
        // CKA_VALUE access is blocked.
        assert!(
            get_attribute(session, prv_h, CKA_VALUE).is_none(),
            "sensitive private-key CKA_VALUE must be blocked"
        );
        close_session(session).unwrap();
    }

    /// get_attribute on CKA_VALUE for a PUBLIC key returns the bytes
    /// (no sensitivity gate on public objects per PKCS#11 v3.2 §4.7).
    #[test]
    fn get_attribute_allows_value_on_public_key() {
        let _guard = test_lock::acquire();
        let session = fresh_session();
        let (pub_h, _) = generate_ml_dsa_keypair(session, CKP_ML_DSA_65, b"\x01", "public-ok").unwrap();
        let value = get_attribute(session, pub_h, CKA_VALUE).expect("public CKA_VALUE allowed");
        assert_eq!(value.len(), 1952, "ML-DSA-65 vk = 1952 bytes (FIPS 204 §5)");
        close_session(session).unwrap();
    }
}
