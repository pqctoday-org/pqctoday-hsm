//! PKCS#11 v3.2 conformance remediation suite (2026-08-13).
//!
//! Every test in this module was written and demonstrated FAILING against the
//! unfixed engine before its fix landed — see
//! `pkcs11-conformance-detailed-remediation-plan-08132026.md`. The item ids
//! (S1..S12, W1..W7, E1..E7, C2/C3) are that plan's.
//!
//! Included from `ffi.rs` (`#[path]`) so `use super::*` resolves to the FFI
//! module and its private helpers, matching the other `*_ffi_tests` modules.

use super::*;
use crate::native::test_lock;

// ── shared harness ───────────────────────────────────────────────────────

/// A live CK_ATTRIBUTE array plus the buffers its `pValue`s point into.
/// Keep the whole struct alive for the duration of the FFI call.
pub(crate) struct Tmpl {
    words: Vec<usize>,
    #[allow(dead_code)]
    bufs: Vec<Vec<u8>>,
}

impl Tmpl {
    pub(crate) fn new(entries: Vec<(u32, Vec<u8>)>) -> Self {
        let bufs: Vec<Vec<u8>> = entries.iter().map(|(_, v)| v.clone()).collect();
        let mut words = Vec::with_capacity(entries.len() * 3);
        for (i, (t, _)) in entries.iter().enumerate() {
            words.push(*t as usize);
            words.push(bufs[i].as_ptr() as usize);
            words.push(bufs[i].len());
        }
        Tmpl { words, bufs }
    }
    pub(crate) fn ptr(&mut self) -> *mut u8 {
        self.words.as_mut_ptr() as *mut u8
    }
    pub(crate) fn count(&self) -> u32 {
        (self.words.len() / 3) as u32
    }
}

/// CK_ULONG-width little-endian bytes (the engine's `store_ulong` width).
pub(crate) fn ulong(v: u32) -> Vec<u8> {
    (v as usize).to_le_bytes().to_vec()
}

pub(crate) fn bbool(v: bool) -> Vec<u8> {
    vec![if v { 1u8 } else { 0u8 }]
}

pub(crate) fn obj_attr(handle: u32, attr_type: u32) -> Option<Vec<u8>> {
    OBJECTS.with(|o| o.borrow().get(&handle).and_then(|a| a.get(&attr_type).cloned()))
}

pub(crate) fn obj_exists(handle: u32) -> bool {
    OBJECTS.with(|o| o.borrow().contains_key(&handle))
}

/// Register a session handle directly (the other ffi test modules' pattern —
/// avoids C_OpenSession's slot/flag plumbing where the test is not about it).
pub(crate) fn put_session(h: u32, slot: u32, rw: bool) {
    SESSIONS.with(|s| {
        s.borrow_mut()
            .insert(h, crate::state::SessionState { slot_id: slot, rw_session: rw });
    });
}

pub(crate) fn drop_session(h: u32) {
    SESSIONS.with(|s| {
        s.borrow_mut().remove(&h);
    });
}

/// Insert an object straight into the store on `slot`, bypassing the FFI —
/// used where the test's subject is a later call, not object creation.
pub(crate) fn put_object(slot: u32, entries: Vec<(u32, Vec<u8>)>) -> u32 {
    let mut attrs: Attributes = std::collections::HashMap::new();
    for (t, v) in entries {
        attrs.insert(t, v);
    }
    attrs.insert(CKA_PRIV_SLOT_ID, slot.to_le_bytes().to_vec());
    crate::state::allocate_handle(attrs)
}

// ─────────────────────────────────────────────────────────────────────────
// S1 — C_InitToken must authenticate the SO on re-initialisation, and must
//      destroy the token's destroyable objects on success (§5.5.7).
// ─────────────────────────────────────────────────────────────────────────

const S1_SLOT: u32 = 71;

#[test]
fn s1_reinit_without_the_existing_so_pin_is_refused() {
    let _guard = test_lock::acquire();
    crate::state::set_initialized(true);
    crate::state::ensure_slot(S1_SLOT);

    let mut label = *b"s1-token                        ";
    let mut pin_a = *b"1234";
    let mut pin_b = *b"9999";

    // Fresh (uninitialised) token — no PIN check applies.
    assert_eq!(
        C_InitToken(S1_SLOT, pin_a.as_mut_ptr(), 4, label.as_mut_ptr()),
        CKR_OK,
        "first C_InitToken on an uninitialised token must succeed"
    );

    // A token object that must survive a REFUSED re-initialisation.
    let survivor = put_object(
        S1_SLOT,
        vec![
            (CKA_CLASS, ulong(CKO_SECRET_KEY)),
            (CKA_KEY_TYPE, ulong(CKK_AES)),
            (CKA_TOKEN, bbool(true)),
            (CKA_VALUE, vec![0x11u8; 16]),
        ],
    );

    // §5.5.7 — "the pPin parameter is checked against the existing SO PIN".
    assert_eq!(
        C_InitToken(S1_SLOT, pin_b.as_mut_ptr(), 4, label.as_mut_ptr()),
        CKR_PIN_INCORRECT,
        "re-initialising an initialised token with the WRONG SO PIN must fail"
    );
    assert!(
        obj_exists(survivor),
        "a refused C_InitToken must not destroy any object"
    );
    // The SO PIN must still be the original one.
    let session = 0x5137_0001;
    put_session(session, S1_SLOT, true);
    assert_eq!(
        C_Login(session, CKU_SO, pin_a.as_mut_ptr(), 4),
        CKR_OK,
        "a refused C_InitToken must not have replaced the SO PIN"
    );
    assert_eq!(C_Logout(session), CKR_OK);
    drop_session(session);

    // Correct PIN: succeeds AND destroys the destroyable objects.
    assert_eq!(
        C_InitToken(S1_SLOT, pin_a.as_mut_ptr(), 4, label.as_mut_ptr()),
        CKR_OK,
        "re-initialising with the correct SO PIN must succeed"
    );
    assert!(
        !obj_exists(survivor),
        "§5.5.7 — \"all objects that can be destroyed are destroyed\""
    );
}

// ─────────────────────────────────────────────────────────────────────────
// S2 — CKA_WRAP_TEMPLATE / CKA_UNWRAP_TEMPLATE (§5.18.3).
// ─────────────────────────────────────────────────────────────────────────

const S2_SESSION: u32 = 0x5232_0001;

fn s2_setup() {
    crate::state::set_initialized(true);
    crate::state::ensure_slot(0);
    put_session(S2_SESSION, 0, true);
}

/// Build a nested CK_ATTRIBUTE array suitable as a CKA_WRAP_TEMPLATE value.
fn nested_template(entries: Vec<(u32, Vec<u8>)>) -> (Tmpl, usize) {
    let t = Tmpl::new(entries);
    let byte_len = t.words.len() * std::mem::size_of::<usize>();
    (t, byte_len)
}

#[test]
fn s2_wrap_template_partitions_the_wrapping_key() {
    let _guard = test_lock::acquire();
    s2_setup();

    // Wrapping key restricted to CKO_SECRET_KEY targets.
    let (mut inner, inner_len) = nested_template(vec![(CKA_CLASS, ulong(CKO_SECRET_KEY))]);
    let inner_ptr = inner.ptr() as usize;
    let mut kek_words: Vec<usize> = Vec::new();
    let kek_attrs: Vec<(u32, Vec<u8>)> = vec![
        (CKA_CLASS, ulong(CKO_SECRET_KEY)),
        (CKA_KEY_TYPE, ulong(CKK_AES)),
        (CKA_VALUE, vec![0x22u8; 32]),
        (CKA_WRAP, bbool(true)),
    ];
    let mut kek_tmpl = Tmpl::new(kek_attrs);
    kek_words.extend_from_slice(&kek_tmpl.words);
    // Append the array attribute by hand (its pValue is the nested array).
    kek_words.push(CKA_WRAP_TEMPLATE as usize);
    kek_words.push(inner_ptr);
    kek_words.push(inner_len);
    let kek_count = (kek_words.len() / 3) as u32;

    let mut h_kek: u32 = 0;
    assert_eq!(
        C_CreateObject(
            S2_SESSION,
            kek_words.as_mut_ptr() as *mut u8,
            kek_count,
            &mut h_kek
        ),
        CKR_OK,
        "creating an AES wrapping key with a CKA_WRAP_TEMPLATE must succeed"
    );
    assert!(
        obj_attr(h_kek, CKA_WRAP_TEMPLATE).is_some(),
        "CKA_WRAP_TEMPLATE must be STORED on the wrapping key, not dropped"
    );

    // Target 1 — a PRIVATE key: violates the template (class mismatch).
    let h_priv = put_object(
        0,
        vec![
            (CKA_CLASS, ulong(CKO_PRIVATE_KEY)),
            (CKA_KEY_TYPE, ulong(CKK_EC)),
            (CKA_EXTRACTABLE, bbool(true)),
            (CKA_VALUE, vec![0x33u8; 32]),
        ],
    );
    // Target 2 — a SECRET key: satisfies the template.
    let h_secret = put_object(
        0,
        vec![
            (CKA_CLASS, ulong(CKO_SECRET_KEY)),
            (CKA_KEY_TYPE, ulong(CKK_AES)),
            (CKA_EXTRACTABLE, bbool(true)),
            (CKA_VALUE, vec![0x44u8; 32]),
        ],
    );

    let mut mech = [0usize; 3];
    mech[0] = CKM_AES_KEY_WRAP as usize;
    let mut out = vec![0u8; 256];
    let mut out_len: u32 = out.len() as u32;

    // §5.18.3 — "If any attribute mismatch occurs … SHALL return
    // CKR_KEY_HANDLE_INVALID".
    let rv = C_WrapKey(
        S2_SESSION,
        mech.as_mut_ptr() as *mut u8,
        h_kek,
        h_priv,
        out.as_mut_ptr(),
        &mut out_len,
    );
    assert_eq!(
        rv, CKR_KEY_HANDLE_INVALID,
        "a wrap-template mismatch must be refused with CKR_KEY_HANDLE_INVALID"
    );

    let mut out_len2: u32 = out.len() as u32;
    assert_eq!(
        C_WrapKey(
            S2_SESSION,
            mech.as_mut_ptr() as *mut u8,
            h_kek,
            h_secret,
            out.as_mut_ptr(),
            &mut out_len2,
        ),
        CKR_OK,
        "a target matching the wrap template must still wrap"
    );
    drop(inner);
    drop(kek_tmpl);
}

#[test]
fn s2_unwrap_template_constrains_the_unwrapped_key() {
    let _guard = test_lock::acquire();
    s2_setup();

    // KEK restricted to producing CKK_AES keys on unwrap.
    let (mut inner, inner_len) = nested_template(vec![(CKA_KEY_TYPE, ulong(CKK_AES))]);
    let inner_ptr = inner.ptr() as usize;
    let mut kek_tmpl = Tmpl::new(vec![
        (CKA_CLASS, ulong(CKO_SECRET_KEY)),
        (CKA_KEY_TYPE, ulong(CKK_AES)),
        (CKA_VALUE, vec![0x22u8; 32]),
        (CKA_WRAP, bbool(true)),
        (CKA_UNWRAP, bbool(true)),
    ]);
    let mut kek_words = kek_tmpl.words.clone();
    kek_words.push(CKA_UNWRAP_TEMPLATE as usize);
    kek_words.push(inner_ptr);
    kek_words.push(inner_len);
    let kek_count = (kek_words.len() / 3) as u32;
    let mut h_kek: u32 = 0;
    assert_eq!(
        C_CreateObject(
            S2_SESSION,
            kek_words.as_mut_ptr() as *mut u8,
            kek_count,
            &mut h_kek
        ),
        CKR_OK
    );

    // Wrap a plain AES key so we have a valid blob to unwrap.
    let h_secret = put_object(
        0,
        vec![
            (CKA_CLASS, ulong(CKO_SECRET_KEY)),
            (CKA_KEY_TYPE, ulong(CKK_AES)),
            (CKA_EXTRACTABLE, bbool(true)),
            (CKA_VALUE, vec![0x44u8; 32]),
        ],
    );
    let mut mech = [0usize; 3];
    mech[0] = CKM_AES_KEY_WRAP as usize;
    let mut blob = vec![0u8; 256];
    let mut blob_len: u32 = blob.len() as u32;
    assert_eq!(
        C_WrapKey(
            S2_SESSION,
            mech.as_mut_ptr() as *mut u8,
            h_kek,
            h_secret,
            blob.as_mut_ptr(),
            &mut blob_len,
        ),
        CKR_OK
    );
    blob.truncate(blob_len as usize);

    // Unwrap asking for CKK_GENERIC_SECRET — contradicts CKA_UNWRAP_TEMPLATE.
    let mut bad = Tmpl::new(vec![
        (CKA_CLASS, ulong(CKO_SECRET_KEY)),
        (CKA_KEY_TYPE, ulong(CKK_GENERIC_SECRET)),
    ]);
    let bad_count = bad.count();
    let mut h_new: u32 = 0;
    let rv = C_UnwrapKey(
        S2_SESSION,
        mech.as_mut_ptr() as *mut u8,
        h_kek,
        blob.as_mut_ptr(),
        blob.len() as u32,
        bad.ptr(),
        bad_count,
        &mut h_new,
    );
    assert_eq!(
        rv, CKR_TEMPLATE_INCONSISTENT,
        "an unwrap template contradicting CKA_UNWRAP_TEMPLATE must be refused"
    );

    let mut good = Tmpl::new(vec![
        (CKA_CLASS, ulong(CKO_SECRET_KEY)),
        (CKA_KEY_TYPE, ulong(CKK_AES)),
    ]);
    let good_count = good.count();
    let mut h_ok: u32 = 0;
    assert_eq!(
        C_UnwrapKey(
            S2_SESSION,
            mech.as_mut_ptr() as *mut u8,
            h_kek,
            blob.as_mut_ptr(),
            blob.len() as u32,
            good.ptr(),
            good_count,
            &mut h_ok,
        ),
        CKR_OK,
        "a conforming unwrap template must still succeed"
    );
    drop(inner);
    drop(kek_tmpl);
}

// ─────────────────────────────────────────────────────────────────────────
// S3 / S10 — one-way attribute locks (CKA_WRAP_WITH_TRUSTED, CKA_COPYABLE).
// ─────────────────────────────────────────────────────────────────────────

const S3_SESSION: u32 = 0x5333_2001;

fn s3_setup() {
    crate::state::set_initialized(true);
    crate::state::ensure_slot(0);
    put_session(S3_SESSION, 0, true);
}

#[test]
fn s3_wrap_with_trusted_cannot_be_cleared() {
    let _guard = test_lock::acquire();
    s3_setup();
    let h = put_object(
        0,
        vec![
            (CKA_CLASS, ulong(CKO_SECRET_KEY)),
            (CKA_KEY_TYPE, ulong(CKK_AES)),
            (CKA_VALUE, vec![0x55u8; 16]),
            (CKA_WRAP_WITH_TRUSTED, bbool(true)),
            (CKA_MODIFIABLE, bbool(true)),
            (CKA_COPYABLE, bbool(true)),
        ],
    );

    // Attribute-table footnote 11 — "cannot be changed once set to CK_TRUE".
    assert_eq!(
        set_attribute_values_from_list(S3_SESSION, h, &[(CKA_WRAP_WITH_TRUSTED, vec![0u8])]),
        CKR_ATTRIBUTE_READ_ONLY,
        "CKA_WRAP_WITH_TRUSTED TRUE→FALSE must be refused"
    );

    // The same rule must hold through C_CopyObject's template.
    let mut tmpl: Attributes = std::collections::HashMap::new();
    tmpl.insert(CKA_WRAP_WITH_TRUSTED, vec![0u8]);
    assert_eq!(
        copy_object_from_attrs(S3_SESSION, h, tmpl),
        Err(CKR_ATTRIBUTE_READ_ONLY),
        "C_CopyObject must not launder CKA_WRAP_WITH_TRUSTED to FALSE"
    );

    // FALSE→TRUE stays legal.
    let h2 = put_object(
        0,
        vec![
            (CKA_CLASS, ulong(CKO_SECRET_KEY)),
            (CKA_KEY_TYPE, ulong(CKK_AES)),
            (CKA_VALUE, vec![0x55u8; 16]),
            (CKA_WRAP_WITH_TRUSTED, bbool(false)),
            (CKA_MODIFIABLE, bbool(true)),
        ],
    );
    assert_eq!(
        set_attribute_values_from_list(S3_SESSION, h2, &[(CKA_WRAP_WITH_TRUSTED, vec![1u8])]),
        CKR_OK
    );
}

#[test]
fn s10_copyable_cannot_be_re_enabled() {
    let _guard = test_lock::acquire();
    s3_setup();
    let h = put_object(
        0,
        vec![
            (CKA_CLASS, ulong(CKO_SECRET_KEY)),
            (CKA_KEY_TYPE, ulong(CKK_AES)),
            (CKA_VALUE, vec![0x66u8; 16]),
            (CKA_COPYABLE, bbool(true)),
            (CKA_MODIFIABLE, bbool(true)),
        ],
    );
    // TRUE→FALSE is legal.
    assert_eq!(
        set_attribute_values_from_list(S3_SESSION, h, &[(CKA_COPYABLE, vec![0u8])]),
        CKR_OK
    );
    // "Can't be set to TRUE once it is set to FALSE."
    assert_eq!(
        set_attribute_values_from_list(S3_SESSION, h, &[(CKA_COPYABLE, vec![1u8])]),
        CKR_ATTRIBUTE_READ_ONLY,
        "CKA_COPYABLE FALSE→TRUE must be refused"
    );
    // And the copy itself stays prohibited.
    assert_eq!(
        copy_object_from_attrs(S3_SESSION, h, std::collections::HashMap::new()),
        Err(CKR_ACTION_PROHIBITED)
    );
}

// ─────────────────────────────────────────────────────────────────────────
// S4 — stateful HBS key state must not be writable through Cryptoki.
// ─────────────────────────────────────────────────────────────────────────

const S4_SESSION: u32 = 0x5434_3001;

#[test]
fn s4_stateful_key_counters_are_not_client_writable() {
    let _guard = test_lock::acquire();
    crate::state::set_initialized(true);
    crate::state::ensure_slot(0);
    put_session(S4_SESSION, 0, true);

    let h = put_object(
        0,
        vec![
            (CKA_CLASS, ulong(CKO_PRIVATE_KEY)),
            (CKA_KEY_TYPE, ulong(CKK_XMSS)),
            (CKA_MODIFIABLE, bbool(true)),
            (CKA_PRIV_LEAF_INDEX, 7u64.to_le_bytes().to_vec()),
            (CKA_PRIV_STATEFUL_KEY_STATE, vec![0xAAu8; 32]),
            (CKA_PRIV_XMSS_KEYS_REMAINING, ulong(1017)),
        ],
    );

    // The rewind: writing the leaf index back to zero would permit one-time
    // key reuse and therefore signature forgery.
    assert_eq!(
        set_attribute_values_from_list(S4_SESSION, h, &[(CKA_PRIV_LEAF_INDEX, 0u64.to_le_bytes().to_vec())]),
        CKR_ATTRIBUTE_READ_ONLY,
        "the leaf index must not be writable through C_SetAttributeValue"
    );
    assert_eq!(
        obj_attr(h, CKA_PRIV_LEAF_INDEX).unwrap(),
        7u64.to_le_bytes().to_vec(),
        "a refused write must not have mutated the counter"
    );
    assert_eq!(
        set_attribute_values_from_list(
            S4_SESSION,
            h,
            &[(CKA_PRIV_STATEFUL_KEY_STATE, vec![0xBBu8; 32])]
        ),
        CKR_ATTRIBUTE_READ_ONLY,
        "the serialised stateful private key must not be writable"
    );
    assert_eq!(
        set_attribute_values_from_list(S4_SESSION, h, &[(CKA_PRIV_XMSS_KEYS_REMAINING, ulong(99999))]),
        CKR_ATTRIBUTE_READ_ONLY,
        "the remaining-signature counter must not be writable"
    );
    // The standard HSS counter is equally non-modifiable.
    let hss = put_object(
        0,
        vec![
            (CKA_CLASS, ulong(CKO_PRIVATE_KEY)),
            (CKA_KEY_TYPE, ulong(CKK_HSS)),
            (CKA_MODIFIABLE, bbool(true)),
            (CKA_HSS_KEYS_REMAINING, ulong(32)),
        ],
    );
    assert_eq!(
        set_attribute_values_from_list(S4_SESSION, hss, &[(CKA_HSS_KEYS_REMAINING, ulong(99999))]),
        CKR_ATTRIBUTE_READ_ONLY
    );
}

#[test]
fn s4_snapshot_format_bump_refuses_the_old_layout() {
    let _guard = test_lock::acquire();
    crate::state::set_initialized(true);
    // A round trip under the CURRENT format must work.
    let snap = crate::state_snapshot::serialize_token_state();
    assert_eq!(crate::state_snapshot::deserialize_token_state(&snap), Ok(()));
    // The pre-S4 layout stored the stateful counters under the mutable
    // vendor ids; a key written that way must fail loudly, never be
    // silently reinterpreted as a fresh key.
    let mut old = snap.clone();
    old[..8].copy_from_slice(b"SHR3SNP1");
    assert_eq!(
        crate::state_snapshot::deserialize_token_state(&old),
        Err(CKR_PQCTODAY_SNAPSHOT_FORMAT_UNSUPPORTED),
        "an old-format snapshot must be refused with a distinct, clear error"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// S6 — C_Logout invalidates private handles; close-all resets login state.
// ─────────────────────────────────────────────────────────────────────────

const S6_SLOT: u32 = 72;

fn s6_bring_up_token(slot: u32) {
    crate::state::set_initialized(true);
    crate::state::ensure_slot(slot);
    // C_InitToken refuses while sessions are open on the slot; a sibling
    // test in this binary may have left one registered.
    SESSIONS.with(|s| s.borrow_mut().retain(|_, ss| ss.slot_id != slot));
    let mut label = *b"s6-token                        ";
    let mut so = *b"1234";
    let mut user = *b"5678";
    // Force a clean, initialised token with a known user PIN.
    crate::state::TOKEN_STORE.with(|ts| {
        if let Some(t) = ts.borrow_mut().get_mut(&slot) {
            t.initialized = false;
            t.login_state = crate::state::LoginState::Public;
        }
    });
    assert_eq!(
        C_InitToken(slot, so.as_mut_ptr(), 4, label.as_mut_ptr()),
        CKR_OK
    );
    let s = 0x5636_9001;
    put_session(s, slot, true);
    assert_eq!(C_Login(s, CKU_SO, so.as_mut_ptr(), 4), CKR_OK);
    assert_eq!(C_InitPIN(s, user.as_mut_ptr(), 4), CKR_OK);
    assert_eq!(C_Logout(s), CKR_OK);
    drop_session(s);
}

#[test]
fn s6_logout_invalidates_private_handles_permanently() {
    let _guard = test_lock::acquire();
    s6_bring_up_token(S6_SLOT);
    let mut user = *b"5678";

    let s = 0x5636_9002;
    put_session(s, S6_SLOT, true);
    assert_eq!(C_Login(s, CKU_USER, user.as_mut_ptr(), 4), CKR_OK);

    // A private TOKEN object — it must survive logout as an OBJECT, while
    // the handle the application holds must not.
    let h_token = put_object(
        S6_SLOT,
        vec![
            (CKA_CLASS, ulong(CKO_SECRET_KEY)),
            (CKA_KEY_TYPE, ulong(CKK_AES)),
            (CKA_PRIVATE, bbool(true)),
            (CKA_TOKEN, bbool(true)),
            (CKA_VALUE, vec![0x77u8; 16]),
        ],
    );
    // A private SESSION object — §5.6.10 says it is DESTROYED.
    let mut sess_attrs: Attributes = std::collections::HashMap::new();
    sess_attrs.insert(CKA_CLASS, ulong(CKO_SECRET_KEY));
    sess_attrs.insert(CKA_KEY_TYPE, ulong(CKK_AES));
    sess_attrs.insert(CKA_PRIVATE, bbool(true));
    sess_attrs.insert(CKA_TOKEN, bbool(false));
    sess_attrs.insert(CKA_VALUE, vec![0x88u8; 16]);
    let h_sess = crate::state::allocate_handle_owned(s, sess_attrs);

    assert_eq!(C_Logout(s), CKR_OK);
    assert_eq!(C_Login(s, CKU_USER, user.as_mut_ptr(), 4), CKR_OK);

    // "any of the application's handles to private objects become invalid
    // (even if a user is later logged back into the token…)"
    let mut probe = Tmpl::new(vec![(CKA_CLASS, vec![0u8; 8])]);
    let probe_count = probe.count();
    assert_eq!(
        C_GetAttributeValue(s, h_token, probe.ptr(), probe_count),
        CKR_OBJECT_HANDLE_INVALID,
        "a private-object handle held across C_Logout must be permanently invalid"
    );
    // "all private session objects … are destroyed"
    assert!(
        !obj_exists(h_sess),
        "private session objects must be destroyed by C_Logout"
    );
    // The private TOKEN object itself survives — findable under a NEW handle.
    let mut find = Tmpl::new(vec![(CKA_VALUE, vec![0x77u8; 16])]);
    let find_count = find.count();
    assert_eq!(C_FindObjectsInit(s, find.ptr(), find_count), CKR_OK);
    let mut found = [0u32; 4];
    let mut n: u32 = 0;
    assert_eq!(C_FindObjects(s, found.as_mut_ptr(), 4, &mut n), CKR_OK);
    assert_eq!(C_FindObjectsFinal(s), CKR_OK);
    assert_eq!(n, 1, "the private token object must survive the logout");
    assert_ne!(
        found[0], h_token,
        "it must be reachable only under a freshly minted handle"
    );
    drop_session(s);
}

#[test]
fn s6_close_all_sessions_returns_the_token_to_public() {
    let _guard = test_lock::acquire();
    s6_bring_up_token(S6_SLOT + 1);
    let slot = S6_SLOT + 1;
    let mut user = *b"5678";

    let s = 0x5636_9003;
    put_session(s, slot, true);
    assert_eq!(C_Login(s, CKU_USER, user.as_mut_ptr(), 4), CKR_OK);
    assert!(crate::state::token_logged_in(slot));

    assert_eq!(C_CloseAllSessions(slot), CKR_OK);
    assert!(
        !crate::state::token_logged_in(slot),
        "§5.6.3 — close-all-sessions returns the login state to public"
    );

    // Same rule when the LAST session closes individually (§5.6.2).
    let s2 = 0x5636_9004;
    put_session(s2, slot, true);
    assert_eq!(C_Login(s2, CKU_USER, user.as_mut_ptr(), 4), CKR_OK);
    assert!(crate::state::token_logged_in(slot));
    assert_eq!(C_CloseSession(s2), CKR_OK);
    assert!(
        !crate::state::token_logged_in(slot),
        "§5.6.2 — closing the last session returns the login state to public"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// S7 — read-only sessions cannot create or destroy TOKEN objects.
// ─────────────────────────────────────────────────────────────────────────

const S7_RO: u32 = 0x5737_4001;
const S7_RW: u32 = 0x5737_4002;

fn s7_setup() {
    crate::state::set_initialized(true);
    crate::state::ensure_slot(0);
    put_session(S7_RO, 0, false);
    put_session(S7_RW, 0, true);
}

#[test]
fn s7_read_only_session_cannot_generate_token_keys() {
    let _guard = test_lock::acquire();
    s7_setup();

    let mut mech = [0usize; 3];
    mech[0] = CKM_AES_KEY_GEN as usize;
    let mut tok = Tmpl::new(vec![
        (CKA_CLASS, ulong(CKO_SECRET_KEY)),
        (CKA_KEY_TYPE, ulong(CKK_AES)),
        (CKA_VALUE_LEN, ulong(32)),
        (CKA_TOKEN, bbool(true)),
    ]);
    let tok_count = tok.count();
    let mut h: u32 = 0;
    assert_eq!(
        C_GenerateKey(S7_RO, mech.as_mut_ptr() as *mut u8, tok.ptr(), tok_count, &mut h),
        CKR_SESSION_READ_ONLY,
        "§5.7.1 — only session objects can be created during a read-only session"
    );

    // Session objects still work from the same R/O session.
    let mut sess = Tmpl::new(vec![
        (CKA_CLASS, ulong(CKO_SECRET_KEY)),
        (CKA_KEY_TYPE, ulong(CKK_AES)),
        (CKA_VALUE_LEN, ulong(32)),
        (CKA_TOKEN, bbool(false)),
    ]);
    let sess_count = sess.count();
    let mut h2: u32 = 0;
    assert_eq!(
        C_GenerateKey(S7_RO, mech.as_mut_ptr() as *mut u8, sess.ptr(), sess_count, &mut h2),
        CKR_OK
    );
}

#[test]
fn s7_read_only_session_cannot_generate_token_key_pairs() {
    let _guard = test_lock::acquire();
    s7_setup();
    let mut mech = [0usize; 3];
    mech[0] = CKM_EC_EDWARDS_KEY_PAIR_GEN as usize;
    let mut pub_t = Tmpl::new(vec![
        (CKA_TOKEN, bbool(true)),
        (CKA_EC_PARAMS, b"\x13\x0cedwards25519".to_vec()),
    ]);
    let pub_count = pub_t.count();
    let mut prv_t = Tmpl::new(vec![(CKA_TOKEN, bbool(true))]);
    let prv_count = prv_t.count();
    let (mut hp, mut hs) = (0u32, 0u32);
    assert_eq!(
        C_GenerateKeyPair_impl(
            S7_RO,
            mech.as_mut_ptr() as *mut u8,
            pub_t.ptr(),
            pub_count,
            prv_t.ptr(),
            prv_count,
            &mut hp,
            &mut hs,
        ),
        CKR_SESSION_READ_ONLY
    );
}

#[test]
fn s7_read_only_session_cannot_derive_token_keys() {
    let _guard = test_lock::acquire();
    s7_setup();
    let base = put_object(
        0,
        vec![
            (CKA_CLASS, ulong(CKO_SECRET_KEY)),
            (CKA_KEY_TYPE, ulong(CKK_GENERIC_SECRET)),
            (CKA_DERIVE, bbool(true)),
            (CKA_VALUE, vec![0x99u8; 32]),
        ],
    );
    let mut mech = [0usize; 3];
    mech[0] = CKM_SHA256_KEY_DERIVATION as usize;
    let mut tmpl = Tmpl::new(vec![
        (CKA_CLASS, ulong(CKO_SECRET_KEY)),
        (CKA_KEY_TYPE, ulong(CKK_GENERIC_SECRET)),
        (CKA_TOKEN, bbool(true)),
    ]);
    let count = tmpl.count();
    let mut h: u32 = 0;
    assert_eq!(
        C_DeriveKey(S7_RO, mech.as_mut_ptr() as *mut u8, base, tmpl.ptr(), count, &mut h),
        CKR_SESSION_READ_ONLY
    );
}

#[test]
fn s7_read_only_session_cannot_unwrap_token_keys() {
    let _guard = test_lock::acquire();
    s7_setup();
    let kek = put_object(
        0,
        vec![
            (CKA_CLASS, ulong(CKO_SECRET_KEY)),
            (CKA_KEY_TYPE, ulong(CKK_AES)),
            (CKA_UNWRAP, bbool(true)),
            (CKA_VALUE, vec![0xAAu8; 32]),
        ],
    );
    let mut mech = [0usize; 3];
    mech[0] = CKM_AES_KEY_WRAP as usize;
    let mut tmpl = Tmpl::new(vec![
        (CKA_CLASS, ulong(CKO_SECRET_KEY)),
        (CKA_KEY_TYPE, ulong(CKK_AES)),
        (CKA_TOKEN, bbool(true)),
    ]);
    let count = tmpl.count();
    let mut blob = vec![0u8; 40];
    let mut h: u32 = 0;
    assert_eq!(
        C_UnwrapKey(
            S7_RO,
            mech.as_mut_ptr() as *mut u8,
            kek,
            blob.as_mut_ptr(),
            blob.len() as u32,
            tmpl.ptr(),
            count,
            &mut h,
        ),
        CKR_SESSION_READ_ONLY,
        "the read-only gate must precede any unwrap work"
    );
}

#[test]
fn s7_read_only_session_cannot_destroy_token_objects() {
    let _guard = test_lock::acquire();
    s7_setup();
    let h = put_object(
        0,
        vec![
            (CKA_CLASS, ulong(CKO_SECRET_KEY)),
            (CKA_KEY_TYPE, ulong(CKK_AES)),
            (CKA_TOKEN, bbool(true)),
            (CKA_DESTROYABLE, bbool(true)),
            (CKA_VALUE, vec![0xBBu8; 16]),
        ],
    );
    assert_eq!(
        C_DestroyObject(S7_RO, h),
        CKR_SESSION_READ_ONLY,
        "§5.7.3 — a R/O session cannot delete a token object"
    );
    assert!(obj_exists(h), "the refused destroy must not have removed it");
    assert_eq!(C_DestroyObject(S7_RW, h), CKR_OK);
}

// ─────────────────────────────────────────────────────────────────────────
// S8 — SO sessions have no access to private objects (Usage Guide §2.4).
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn s8_security_officer_cannot_reach_private_objects() {
    let _guard = test_lock::acquire();
    let slot = 74u32;
    s6_bring_up_token(slot);
    let mut so = *b"1234";

    let priv_obj = put_object(
        slot,
        vec![
            (CKA_CLASS, ulong(CKO_SECRET_KEY)),
            (CKA_KEY_TYPE, ulong(CKK_AES)),
            (CKA_PRIVATE, bbool(true)),
            (CKA_TOKEN, bbool(true)),
            (CKA_VALUE, vec![0xCCu8; 16]),
        ],
    );
    let pub_obj = put_object(
        slot,
        vec![
            (CKA_CLASS, ulong(CKO_SECRET_KEY)),
            (CKA_KEY_TYPE, ulong(CKK_AES)),
            (CKA_PRIVATE, bbool(false)),
            (CKA_TOKEN, bbool(true)),
            (CKA_VALUE, vec![0xDDu8; 16]),
        ],
    );

    let s = 0x5838_5001;
    put_session(s, slot, true);
    assert_eq!(C_Login(s, CKU_SO, so.as_mut_ptr(), 4), CKR_OK);

    let mut probe = Tmpl::new(vec![(CKA_CLASS, vec![0u8; 8])]);
    let probe_count = probe.count();
    assert_eq!(
        C_GetAttributeValue(s, priv_obj, probe.ptr(), probe_count),
        CKR_OBJECT_HANDLE_INVALID,
        "\"The application has read/write access only to public objects on the \
         token, not to private objects.\""
    );
    // The SO still reaches public objects.
    let mut probe2 = Tmpl::new(vec![(CKA_CLASS, vec![0u8; 8])]);
    let probe2_count = probe2.count();
    assert_eq!(
        C_GetAttributeValue(s, pub_obj, probe2.ptr(), probe2_count),
        CKR_OK
    );

    // And find-objects must not enumerate the private one.
    let mut find = Tmpl::new(vec![(CKA_KEY_TYPE, ulong(CKK_AES))]);
    let find_count = find.count();
    assert_eq!(C_FindObjectsInit(s, find.ptr(), find_count), CKR_OK);
    let mut found = [0u32; 16];
    let mut n: u32 = 0;
    assert_eq!(C_FindObjects(s, found.as_mut_ptr(), 16, &mut n), CKR_OK);
    assert_eq!(C_FindObjectsFinal(s), CKR_OK);
    assert!(
        !found[..n as usize].contains(&priv_obj),
        "an SO session must not enumerate private objects"
    );
    drop_session(s);
}

// ─────────────────────────────────────────────────────────────────────────
// S9 — CKA_ALLOWED_MECHANISMS element width == sizeof(CK_MECHANISM_TYPE).
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn s9_allowed_mechanisms_parses_at_the_exported_abi_width() {
    let _guard = test_lock::acquire();
    crate::state::set_initialized(true);

    // The restriction as a real CK_MECHANISM_TYPE array: AES key generation
    // only. On LP64 each element is 8 bytes.
    let list: Vec<u8> = [CKM_AES_KEY_GEN]
        .iter()
        .flat_map(|m| (*m as usize).to_le_bytes())
        .collect();
    let mut attrs: Attributes = std::collections::HashMap::new();
    attrs.insert(CKA_ALLOWED_MECHANISMS, list);

    assert_eq!(
        crate::state::check_mechanism_allowed_from(&attrs, CKM_AES_KEY_GEN),
        Ok(()),
        "the listed mechanism must be allowed"
    );
    // CKM_RSA_PKCS_KEY_PAIR_GEN is 0 — the exact value a 4-byte parse of an
    // 8-byte element list manufactures out of every element's high half.
    assert_eq!(
        crate::state::check_mechanism_allowed_from(&attrs, CKM_RSA_PKCS_KEY_PAIR_GEN),
        Err(CKR_MECHANISM_INVALID),
        "a fail-open parse of the mechanism list silently permits mechanism 0"
    );

    // A length that is not a whole number of elements is invalid.
    let mut ragged: Attributes = std::collections::HashMap::new();
    ragged.insert(CKA_ALLOWED_MECHANISMS, vec![0u8; std::mem::size_of::<usize>() + 1]);
    assert_eq!(
        crate::state::attr_mutation_allowed(
            &ragged,
            CKA_ALLOWED_MECHANISMS,
            &vec![0u8; std::mem::size_of::<usize>() + 1]
        ),
        Err(CKR_ATTRIBUTE_VALUE_INVALID),
        "a ragged CKA_ALLOWED_MECHANISMS length must be CKR_ATTRIBUTE_VALUE_INVALID"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// S11 — key check values on encapsulation / decapsulation outputs (§4.11).
// ─────────────────────────────────────────────────────────────────────────

const S11_SESSION: u32 = 0x5B3B_6001;

/// S8 made private-object access require the NORMAL USER role, so any test
/// touching a private key must actually log in — previously "not logged in"
/// and "logged in as SO" were both accepted.
fn s11_setup() {
    let slot = 76u32;
    s6_bring_up_token(slot);
    let mut user = *b"5678";
    put_session(S11_SESSION, slot, true);
    assert_eq!(C_Login(S11_SESSION, CKU_USER, user.as_mut_ptr(), 4), CKR_OK);
}

fn s11_ml_kem_keypair() -> (u32, u32) {
    let mut mech = [0usize; 3];
    mech[0] = CKM_ML_KEM_KEY_PAIR_GEN as usize;
    let ps = CKP_ML_KEM_768 as usize;
    let mut pub_t: Vec<usize> = vec![
        CKA_PARAMETER_SET as usize,
        (&ps as *const usize) as usize,
        std::mem::size_of::<usize>(),
    ];
    let (mut hp, mut hs) = (0u32, 0u32);
    let rv = unsafe {
        C_GenerateKeyPair_impl(
            S11_SESSION,
            mech.as_mut_ptr() as *mut u8,
            pub_t.as_mut_ptr() as *mut u8,
            1,
            std::ptr::null_mut(),
            0,
            &mut hp,
            &mut hs,
        )
    };
    assert_eq!(rv, CKR_OK, "ML-KEM-768 keygen must succeed");
    (hp, hs)
}

fn sha1_kcv(value: &[u8]) -> Vec<u8> {
    use sha1::Digest;
    sha1::Sha1::digest(value)[..3].to_vec()
}

#[test]
fn s11_encapsulated_key_carries_a_check_value() {
    let _guard = test_lock::acquire();
    s11_setup();
    let (hp, _hs) = s11_ml_kem_keypair();

    let mut mech = [0usize; 3];
    mech[0] = CKM_ML_KEM as usize;
    let mut ct = vec![0u8; 4096];
    let mut ct_len: u32 = ct.len() as u32;
    let mut h_ss: u32 = 0;
    let rv = unsafe {
        C_EncapsulateKey_impl(
            S11_SESSION,
            mech.as_mut_ptr() as *mut u8,
            hp,
            std::ptr::null_mut(),
            0,
            ct.as_mut_ptr(),
            &mut ct_len,
            &mut h_ss,
        )
    };
    assert_eq!(rv, CKR_OK);
    let ss = obj_attr(h_ss, CKA_VALUE).expect("shared secret must be readable");
    let kcv = obj_attr(h_ss, CKA_CHECK_VALUE)
        .expect("§4.11 — the check value SHALL be supplied on every created key");
    assert_eq!(
        kcv,
        sha1_kcv(&ss),
        "the check value must be the first three bytes of SHA-1(secret)"
    );
}

#[test]
fn s11_caller_supplied_check_value_is_compared_not_dropped() {
    let _guard = test_lock::acquire();
    s11_setup();
    let (hp, hs) = s11_ml_kem_keypair();

    let mut mech = [0usize; 3];
    mech[0] = CKM_ML_KEM as usize;

    // Round 1 — learn the true secret so we can build a correct KCV.
    let mut ct = vec![0u8; 4096];
    let mut ct_len: u32 = ct.len() as u32;
    let mut h0: u32 = 0;
    assert_eq!(
        unsafe {
            C_EncapsulateKey_impl(
                S11_SESSION,
                mech.as_mut_ptr() as *mut u8,
                hp,
                std::ptr::null_mut(),
                0,
                ct.as_mut_ptr(),
                &mut ct_len,
                &mut h0,
            )
        },
        CKR_OK
    );
    let ct_bytes = ct[..ct_len as usize].to_vec();
    let true_ss = obj_attr(h0, CKA_VALUE).unwrap();
    let good = sha1_kcv(&true_ss);

    // Decapsulation with the CORRECT caller-supplied check value: accepted.
    let mut ok_t = Tmpl::new(vec![(CKA_CHECK_VALUE, good.clone())]);
    let ok_count = ok_t.count();
    let mut h_ok: u32 = 0;
    let mut ctb = ct_bytes.clone();
    assert_eq!(
        unsafe {
            C_DecapsulateKey_impl(
                S11_SESSION,
                mech.as_mut_ptr() as *mut u8,
                hs,
                ok_t.ptr(),
                ok_count,
                ctb.as_mut_ptr(),
                ctb.len() as u32,
                &mut h_ok,
            )
        },
        CKR_OK,
        "§4.11 — a correct caller-supplied check value MUST be accepted"
    );
    assert_eq!(obj_attr(h_ok, CKA_CHECK_VALUE).unwrap(), good);

    // A WRONG value is CKR_ATTRIBUTE_VALUE_INVALID.
    let mut bad_t = Tmpl::new(vec![(CKA_CHECK_VALUE, vec![0xDE, 0xAD, 0xBE])]);
    let bad_count = bad_t.count();
    let mut h_bad: u32 = 0;
    let mut ctb2 = ct_bytes.clone();
    assert_eq!(
        unsafe {
            C_DecapsulateKey_impl(
                S11_SESSION,
                mech.as_mut_ptr() as *mut u8,
                hs,
                bad_t.ptr(),
                bad_count,
                ctb2.as_mut_ptr(),
                ctb2.len() as u32,
                &mut h_bad,
            )
        },
        CKR_ATTRIBUTE_VALUE_INVALID,
        "§4.11 — a mismatching check value MUST return CKR_ATTRIBUTE_VALUE_INVALID"
    );

    // A zero-length entry SUPPRESSES generation.
    let mut zero_words: Vec<usize> = vec![CKA_CHECK_VALUE as usize, 0usize, 0usize];
    let mut h_zero: u32 = 0;
    let mut ctb3 = ct_bytes.clone();
    assert_eq!(
        unsafe {
            C_DecapsulateKey_impl(
                S11_SESSION,
                mech.as_mut_ptr() as *mut u8,
                hs,
                zero_words.as_mut_ptr() as *mut u8,
                1,
                ctb3.as_mut_ptr(),
                ctb3.len() as u32,
                &mut h_zero,
            )
        },
        CKR_OK
    );
    assert!(
        obj_attr(h_zero, CKA_CHECK_VALUE).is_none(),
        "a zero-length CKA_CHECK_VALUE template entry must suppress generation"
    );
}

// ─────────────────────────────────────────────────────────────────────────
// S12 — the KMIP seam: CKA_ALLOWED_MECHANISMS over the NATIVE surface.
// ─────────────────────────────────────────────────────────────────────────

#[test]
fn s12_native_derive_and_agree_enforce_allowed_mechanisms() {
    let _guard = test_lock::acquire();
    let slot = 77u32;
    s6_bring_up_token(slot);
    let mut user = *b"5678";
    let s = 0x5C3C_7001;
    put_session(s, slot, true);
    assert_eq!(C_Login(s, CKU_USER, user.as_mut_ptr(), 4), CKR_OK);

    // A restriction naming only AES key generation.
    let restriction: Vec<u8> = (CKM_AES_KEY_GEN as usize).to_le_bytes().to_vec();

    // native::derive — CKM_SHA256_KEY_DERIVATION off a restricted base key.
    let base = put_object(
        slot,
        vec![
            (CKA_CLASS, ulong(CKO_SECRET_KEY)),
            (CKA_KEY_TYPE, ulong(CKK_GENERIC_SECRET)),
            (CKA_DERIVE, bbool(true)),
            (CKA_VALUE, vec![0x5Au8; 32]),
            (CKA_ALLOWED_MECHANISMS, restriction.clone()),
        ],
    );
    assert_eq!(
        crate::native::derive::digest_key_derivation(s, base, CKM_SHA256_KEY_DERIVATION, None)
            .err(),
        Some(CKR_MECHANISM_INVALID),
        "a mechanism-restricted key must be refused over the native derive surface"
    );
    // …and the concatenation combiners on the same surface.
    assert_eq!(
        crate::native::derive::concatenate_data(s, base, &[0u8; 8]).err(),
        Some(CKR_MECHANISM_INVALID),
        "CKM_CONCATENATE_BASE_AND_DATA must honour the restriction too"
    );

    // native::agree — ECDH off a restricted private key.
    let (pub_h, prv_h) = crate::native::keygen::generate_ecdh_keypair(
        s,
        crate::native::keygen::EccCurve::P256,
        b"s12",
        "s12",
    )
    .expect("P-256 keygen");
    crate::state::set_object_attr_bytes(prv_h, CKA_ALLOWED_MECHANISMS, restriction.clone());
    let peer = crate::state::get_ec_point_sec1(pub_h).expect("peer point");
    assert_eq!(
        crate::native::agree::ecdh_agree(s, prv_h, &peer).err(),
        Some(CKR_MECHANISM_INVALID),
        "a mechanism-restricted key must be refused over the native agreement surface"
    );

    // native::split_key — the KMIP Split Key path.
    let secret = put_object(
        slot,
        vec![
            (CKA_CLASS, ulong(CKO_SECRET_KEY)),
            (CKA_KEY_TYPE, ulong(CKK_GENERIC_SECRET)),
            (CKA_VALUE, vec![0x6Bu8; 32]),
            (CKA_ALLOWED_MECHANISMS, restriction.clone()),
        ],
    );
    assert_eq!(
        crate::native::split_key::split(
            s,
            secret,
            3,
            2,
            crate::crypto::split_key::SplitKeyMethod::Xor,
            None,
            b"s12",
            "s12",
        )
        .err(),
        Some(CKR_MECHANISM_INVALID),
        "a mechanism-restricted key must be refused over the native split-key surface"
    );
}
