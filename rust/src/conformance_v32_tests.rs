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

// ═════════════════════════════════════════════════════════════════════════
// PHASE 2 — silent wrong results
// ═════════════════════════════════════════════════════════════════════════

const W_SESSION: u32 = 0x5721_0001;

fn w_setup() {
    crate::state::set_initialized(true);
    crate::state::ensure_slot(0);
    put_session(W_SESSION, 0, true);
}

/// DER OBJECT IDENTIFIER for a named curve.
fn oid(body: &[u8]) -> Vec<u8> {
    let mut v = vec![0x06, body.len() as u8];
    v.extend_from_slice(body);
    v
}

/// DER PrintableString curve name.
fn curve_name(name: &str) -> Vec<u8> {
    let mut v = vec![0x13, name.len() as u8];
    v.extend_from_slice(name.as_bytes());
    v
}

fn gen_ec(params: Option<Vec<u8>>, mech: u32) -> (u32, u32, u32) {
    let mut m = [0usize; 3];
    m[0] = mech as usize;
    let entries = match params {
        Some(p) => vec![(CKA_EC_PARAMS, p)],
        None => vec![],
    };
    let mut pub_t = Tmpl::new(entries);
    let count = pub_t.count();
    let (mut hp, mut hs) = (0u32, 0u32);
    let rv = unsafe {
        C_GenerateKeyPair_impl(
            W_SESSION,
            m.as_mut_ptr() as *mut u8,
            pub_t.ptr(),
            count,
            std::ptr::null_mut(),
            0,
            &mut hp,
            &mut hs,
        )
    };
    (rv, hp, hs)
}

// ── W1 — unsupported curves must NOT silently become P-256 ──────────────

#[test]
fn w1_ec_params_are_decoded_never_defaulted() {
    let _guard = test_lock::acquire();
    w_setup();

    // brainpoolP256r1 — 1.3.36.3.3.2.8.1.1.7. A well-formed OID this token
    // does not implement. It previously produced a P-256 key, stamped P-256,
    // returning success.
    let brainpool = oid(&[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07]);
    let (rv, _, _) = gen_ec(Some(brainpool), CKM_EC_KEY_PAIR_GEN);
    assert_eq!(
        rv, CKR_CURVE_NOT_SUPPORTED,
        "an unimplemented curve must be refused, not silently substituted"
    );

    // P-384 must be a genuine P-384 key.
    let (rv, hp, hs) = gen_ec(Some(oid(&[0x2b, 0x81, 0x04, 0x00, 0x22])), CKM_EC_KEY_PAIR_GEN);
    assert_eq!(rv, CKR_OK);
    assert_eq!(
        obj_attr(hs, CKA_VALUE).unwrap().len(),
        48,
        "P-384 private scalar is 48 bytes — a substituted P-256 key would be 32"
    );
    assert!(obj_attr(hp, CKA_EC_POINT).is_some());

    // Absent attribute — mandatory at generation (§6.3.9).
    let (rv, _, _) = gen_ec(None, CKM_EC_KEY_PAIR_GEN);
    assert_eq!(
        rv, CKR_TEMPLATE_INCOMPLETE,
        "CKA_EC_PARAMS is mandatory at key-pair generation"
    );

    // The curveName form the spec RECOMMENDS was never recognised before.
    let (rv, _, hs) = gen_ec(Some(curve_name("P-256")), CKM_EC_KEY_PAIR_GEN);
    assert_eq!(rv, CKR_OK, "the curveName CHOICE arm must be accepted");
    assert_eq!(obj_attr(hs, CKA_VALUE).unwrap().len(), 32);

    // Undecodable representation.
    let (rv, _, _) = gen_ec(Some(vec![0x05, 0x00]), CKM_EC_KEY_PAIR_GEN);
    assert_eq!(
        rv, CKR_DOMAIN_PARAMS_INVALID,
        "implicitCA is forbidden — an invalid representation, not a curve"
    );

    // Last-byte collision: 1.3.36.3.3.2.8.1.1.10 ends in 0x0a, the byte the
    // old code read as "secp256k1".
    let collide = oid(&[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0a]);
    let (rv, _, _) = gen_ec(Some(collide), CKM_EC_KEY_PAIR_GEN);
    assert_eq!(
        rv, CKR_CURVE_NOT_SUPPORTED,
        "last-byte matching is collision-prone across the OID space"
    );
}

// ── W2 — Ed448 must not silently yield Ed25519 ──────────────────────────
//
// Originally asserted Ed448 keygen failed cleanly (CKR_CURVE_NOT_SUPPORTED)
// rather than silently substituting an Ed25519 key — §6.3.14 permits
// supporting only one of the two curves, and this engine chose Ed25519-only
// at the time. Ed448 is now genuinely implemented (2026-08-27,
// `ed448-goldilocks`, already a transitive dep via `x448` below for its
// Montgomery arm), so the assertion flips: an Ed448 request must now
// SUCCEED and produce a real, distinctly-Ed448-shaped key (57-byte private
// scalar / 57-byte public point, not 32), not fail and not silently return
// an Ed25519 key either. The "not silently yield Ed25519" guarantee this
// test protects is unchanged — only which outcome satisfies it.

#[test]
fn w2_edwards_keygen_reads_ec_params() {
    let _guard = test_lock::acquire();
    w_setup();

    // Ed448 — 1.3.101.113. Both legal CKA_EC_PARAMS forms must produce a
    // genuine Ed448 key, not an Ed25519 substitute and not a clean failure.
    let (rv, hp, hs) = gen_ec(Some(oid(&[0x2b, 0x65, 0x71])), CKM_EC_EDWARDS_KEY_PAIR_GEN);
    assert_eq!(rv, CKR_OK, "an Ed448 request must succeed now that it's implemented");
    assert_eq!(
        obj_attr(hs, CKA_VALUE).unwrap().len(),
        57,
        "a substituted Ed25519 key would be 32 bytes, not Ed448's 57"
    );
    assert_eq!(obj_attr(hp, CKA_EC_POINT).unwrap().len(), 57);
    let (rv, _, hs) = gen_ec(
        Some(curve_name("edwards448")),
        CKM_EC_EDWARDS_KEY_PAIR_GEN,
    );
    assert_eq!(rv, CKR_OK, "…in the curveName form too");
    assert_eq!(obj_attr(hs, CKA_VALUE).unwrap().len(), 57);

    // Ed25519 in both legal forms still works, and is unaffected by Ed448
    // now sharing this arm (distinguished by length, not a separate mech).
    let (rv, _, hs) = gen_ec(Some(oid(&[0x2b, 0x65, 0x70])), CKM_EC_EDWARDS_KEY_PAIR_GEN);
    assert_eq!(rv, CKR_OK);
    assert_eq!(obj_attr(hs, CKA_VALUE).unwrap().len(), 32);
    let (rv, _, _) = gen_ec(
        Some(curve_name("edwards25519")),
        CKM_EC_EDWARDS_KEY_PAIR_GEN,
    );
    assert_eq!(rv, CKR_OK, "the curveName form must be accepted on input");

    // Absent attribute.
    let (rv, _, _) = gen_ec(None, CKM_EC_EDWARDS_KEY_PAIR_GEN);
    assert_eq!(rv, CKR_TEMPLATE_INCOMPLETE);
}

// ── Ed448 sign/verify round trip, plus mixed-curve non-interference ─────

#[test]
fn ed448_sign_verify_round_trip_and_curves_do_not_cross_contaminate() {
    let _guard = test_lock::acquire();
    w_setup();
    // The generated private keys are CKA_PRIVATE=TRUE (§4.4/§5.6), so
    // C_SignInit requires the session's token to be logged in as User —
    // poke TOKEN_STORE directly rather than the full C_InitToken/C_Login
    // PIN dance, mirroring how s6_bring_up_token's own setup pokes
    // `login_state` directly elsewhere in this file.
    crate::state::TOKEN_STORE.with(|ts| {
        if let Some(t) = ts.borrow_mut().get_mut(&0) {
            t.login_state = crate::state::LoginState::User;
        }
    });

    let (rv, hp448, hs448) =
        gen_ec(Some(oid(&[0x2b, 0x65, 0x71])), CKM_EC_EDWARDS_KEY_PAIR_GEN);
    assert_eq!(rv, CKR_OK);
    let (rv, hp25519, hs25519) =
        gen_ec(Some(oid(&[0x2b, 0x65, 0x70])), CKM_EC_EDWARDS_KEY_PAIR_GEN);
    assert_eq!(rv, CKR_OK);

    let msg = b"W2 follow-up: Ed448 is now real, not just rejected cleanly";
    let mut m: [usize; 3] = [CKM_EDDSA as usize, 0, 0];

    // Ed448 signs and verifies against its own key.
    assert_eq!(C_SignInit(W_SESSION, m.as_mut_ptr() as *mut u8, hs448), CKR_OK);
    let mut sig = vec![0u8; 1024];
    let mut sig_len: u32 = 1024;
    let rv = C_Sign(
        W_SESSION,
        msg.as_ptr() as *mut u8,
        msg.len() as u32,
        sig.as_mut_ptr(),
        &mut sig_len,
    );
    assert_eq!(rv, CKR_OK);
    sig.truncate(sig_len as usize);
    assert_eq!(sig.len(), 114, "Ed448 signatures are 114 bytes, not Ed25519's 64");

    assert_eq!(C_VerifyInit(W_SESSION, m.as_mut_ptr() as *mut u8, hp448), CKR_OK);
    let rv = C_Verify(
        W_SESSION,
        msg.as_ptr() as *mut u8,
        msg.len() as u32,
        sig.as_ptr() as *mut u8,
        sig.len() as u32,
    );
    assert_eq!(rv, CKR_OK, "a genuine Ed448 signature must verify against its own Ed448 key");

    // The Ed448 signature must NOT verify under the unrelated Ed25519 key
    // (proves the two curves aren't cross-wired through the shared 32-vs-57
    // length dispatch in sign_eddsa/verify_eddsa).
    assert_eq!(C_VerifyInit(W_SESSION, m.as_mut_ptr() as *mut u8, hp25519), CKR_OK);
    let rv = C_Verify(
        W_SESSION,
        msg.as_ptr() as *mut u8,
        msg.len() as u32,
        sig.as_ptr() as *mut u8,
        sig.len() as u32,
    );
    assert_ne!(rv, CKR_OK, "an Ed448 signature must not verify under an Ed25519 key");

    // Ed25519 still signs/verifies correctly on its own, unaffected.
    assert_eq!(C_SignInit(W_SESSION, m.as_mut_ptr() as *mut u8, hs25519), CKR_OK);
    let mut sig25519 = vec![0u8; 1024];
    let mut sig25519_len: u32 = 1024;
    let rv = C_Sign(
        W_SESSION,
        msg.as_ptr() as *mut u8,
        msg.len() as u32,
        sig25519.as_mut_ptr(),
        &mut sig25519_len,
    );
    assert_eq!(rv, CKR_OK);
    sig25519.truncate(sig25519_len as usize);
    assert_eq!(sig25519.len(), 64);

    assert_eq!(C_VerifyInit(W_SESSION, m.as_mut_ptr() as *mut u8, hp25519), CKR_OK);
    let rv = C_Verify(
        W_SESSION,
        msg.as_ptr() as *mut u8,
        msg.len() as u32,
        sig25519.as_ptr() as *mut u8,
        sig25519.len() as u32,
    );
    assert_eq!(rv, CKR_OK);
}

// ── W3 — XMSS sign/verify source the STANDARD parameter set ─────────────

#[test]
fn w3_xmss_parameter_set_comes_from_the_standard_attribute() {
    let _guard = test_lock::acquire();
    w_setup();

    // A key carrying ONLY the standard attribute — what an import via
    // C_CreateObject produces. The vendor attribute is absent, so the old
    // code fell through to its default parameter set and signed under it.
    let h = put_object(
        0,
        vec![
            (CKA_CLASS, ulong(CKO_PRIVATE_KEY)),
            (CKA_KEY_TYPE, ulong(CKK_XMSS)),
            (CKA_PARAMETER_SET, ulong(CKP_XMSS_SHA2_16_256)),
        ],
    );
    assert_eq!(
        xmss_param_set_of(h, false),
        Some(CKP_XMSS_SHA2_16_256),
        "the standard CKA_PARAMETER_SET must be the source of truth"
    );

    // The standard attribute WINS over a stale vendor one.
    let h2 = put_object(
        0,
        vec![
            (CKA_CLASS, ulong(CKO_PRIVATE_KEY)),
            (CKA_KEY_TYPE, ulong(CKK_XMSS)),
            (CKA_PARAMETER_SET, ulong(CKP_XMSS_SHA2_16_256)),
            (CKA_XMSS_PARAM_SET, ulong(CKP_XMSS_SHA2_10_256)),
        ],
    );
    assert_eq!(xmss_param_set_of(h2, false), Some(CKP_XMSS_SHA2_16_256));

    // Neither present ⇒ no silent default.
    let h3 = put_object(
        0,
        vec![
            (CKA_CLASS, ulong(CKO_PRIVATE_KEY)),
            (CKA_KEY_TYPE, ulong(CKK_XMSS)),
        ],
    );
    assert_eq!(xmss_param_set_of(h3, false), None);
}

// ── W5 — object search must never silently widen ────────────────────────

#[test]
fn w5_find_objects_never_silently_widens() {
    let _guard = test_lock::acquire();
    w_setup();
    let _a = put_object(
        0,
        vec![
            (CKA_CLASS, ulong(CKO_SECRET_KEY)),
            (CKA_KEY_TYPE, ulong(CKK_AES)),
            (CKA_VALUE, vec![0x01u8; 16]),
        ],
    );

    // §5.7.7 — "To find all objects, set ulCount to 0." A NULL template with
    // a non-zero count is a malformed request, not a find-all.
    assert_eq!(
        C_FindObjectsInit(W_SESSION, std::ptr::null_mut(), 5),
        CKR_ARGUMENTS_BAD,
        "a NULL template with a non-zero count must not become a find-all"
    );
    // An over-limit count must not silently drop the filter either.
    let mut t = Tmpl::new(vec![(CKA_CLASS, ulong(CKO_SECRET_KEY))]);
    assert_eq!(
        C_FindObjectsInit(W_SESSION, t.ptr(), 70000),
        CKR_ARGUMENTS_BAD
    );
    // Count 0 IS the sanctioned find-all.
    assert_eq!(C_FindObjectsInit(W_SESSION, std::ptr::null_mut(), 0), CKR_OK);
    assert_eq!(C_FindObjectsFinal(W_SESSION), CKR_OK);
}

// ── W6 — the slot argument must be honoured ─────────────────────────────

#[test]
fn w6_slot_id_is_validated() {
    let _guard = test_lock::acquire();
    w_setup();
    let mut info = [0u8; 64];
    assert_eq!(
        C_GetMechanismInfo(9999, CKM_AES_KEY_GEN, info.as_mut_ptr()),
        CKR_SLOT_ID_INVALID,
        "§5.5.6 — slotID is the ID of the token's slot; 9999 has no token"
    );
    assert_eq!(
        C_GetMechanismInfo(0, CKM_AES_KEY_GEN, info.as_mut_ptr()),
        CKR_OK
    );
    // Sibling entry point audited alongside (W6's "audit the siblings").
    let mut slot_info = [0u8; 104];
    assert_eq!(
        C_GetSlotInfo(9999, slot_info.as_mut_ptr()),
        CKR_SLOT_ID_INVALID
    );
    assert_eq!(C_GetSlotInfo(0, slot_info.as_mut_ptr()), CKR_OK);
}

// ── W7 — ChaCha20 counter width and random access ───────────────────────

#[test]
fn w7_chacha20_honours_a_non_zero_start_counter() {
    let _guard = test_lock::acquire();
    let key = [0x42u8; 32];
    let nonce = [0x07u8; 12];

    // Two blocks of zeros from counter 0 …
    let long = crate::native::encrypt::chacha20_encrypt_at(&key, &nonce, &[0u8; 128], 0)
        .expect("counter 0");
    // … and one block from counter 1 must equal the SECOND block of it.
    // §6.20: the counter exists so blocks can be addressed in random order.
    let second = crate::native::encrypt::chacha20_encrypt_at(&key, &nonce, &[0u8; 64], 1)
        .expect("counter 1");
    assert_eq!(
        second,
        long[64..128].to_vec(),
        "a non-zero start counter must seek the keystream, not be refused"
    );
    assert_ne!(second, long[0..64].to_vec());
}

#[test]
fn w7_chacha20_counter_width_must_be_32_or_64() {
    let _guard = test_lock::acquire();
    // CK_CHACHA20_PARAMS: pBlockCounter, blockCounterBits, pNonce, ulNonceBits
    let counter: u64 = 1;
    let nonce12 = [0x07u8; 12];
    let nonce8 = [0x07u8; 8];

    let mk = |ctr_bits: usize, nonce: &[u8], nonce_bits: usize| -> [usize; 4] {
        [
            (&counter as *const u64) as usize,
            ctr_bits,
            nonce.as_ptr() as usize,
            nonce_bits,
        ]
    };

    // §6.20 — "can be either 32 or 64". 48 is neither.
    let mut bad = mk(48, &nonce12, 96);
    assert_eq!(
        unsafe { parse_chacha20_params(bad.as_mut_ptr() as *const u8, 32) },
        Err(CKR_MECHANISM_PARAM_INVALID),
        "a counter width outside {{32, 64}} must be refused"
    );
    let mut bad2 = mk(16, &nonce8, 64);
    assert_eq!(
        unsafe { parse_chacha20_params(bad2.as_mut_ptr() as *const u8, 32) },
        Err(CKR_MECHANISM_PARAM_INVALID)
    );

    // The IETF variant: 96-bit nonce with a 32-bit counter.
    let mut ietf = mk(32, &nonce12, 96);
    assert_eq!(
        unsafe { parse_chacha20_params(ietf.as_mut_ptr() as *const u8, 32) },
        Ok((nonce12.to_vec(), 1)),
        "a non-zero start counter must be RETURNED, not rejected"
    );
    // The original variant: 64-bit nonce with a 64-bit counter.
    let mut legacy = mk(64, &nonce8, 64);
    assert_eq!(
        unsafe { parse_chacha20_params(legacy.as_mut_ptr() as *const u8, 32) },
        Ok((nonce8.to_vec(), 1))
    );
    // Mismatched pair.
    let mut mixed = mk(64, &nonce12, 96);
    assert_eq!(
        unsafe { parse_chacha20_params(mixed.as_mut_ptr() as *const u8, 32) },
        Err(CKR_MECHANISM_PARAM_INVALID),
        "the nonce/counter pair must match one of the defined variants"
    );
}

// ═════════════════════════════════════════════════════════════════════════
// PHASE 3 — spec-defined encodings
// ═════════════════════════════════════════════════════════════════════════

const E_SESSION: u32 = 0x5E33_0001;

/// S8 made private-object access require the NORMAL USER role, and EC /
/// Edwards private keys are generated CKA_PRIVATE=TRUE — so these tests have
/// to actually log in.
fn e_setup() {
    let slot = 78u32;
    s6_bring_up_token(slot);
    let mut user = *b"5678";
    put_session(E_SESSION, slot, true);
    assert_eq!(C_Login(E_SESSION, CKU_USER, user.as_mut_ptr(), 4), CKR_OK);
}

fn gen_pair(mech: u32, pub_entries: Vec<(u32, Vec<u8>)>) -> (u32, u32, u32) {
    let mut m = [0usize; 3];
    m[0] = mech as usize;
    let mut t = Tmpl::new(pub_entries);
    let count = t.count();
    let (mut hp, mut hs) = (0u32, 0u32);
    let rv = unsafe {
        C_GenerateKeyPair_impl(
            E_SESSION,
            m.as_mut_ptr() as *mut u8,
            t.ptr(),
            count,
            std::ptr::null_mut(),
            0,
            &mut hp,
            &mut hs,
        )
    };
    (rv, hp, hs)
}

// ── E1 — the ECDH-KEM ciphertext is the RAW ephemeral public key ────────

#[test]
fn e1_ecdh_kem_ciphertext_is_the_raw_ephemeral_point() {
    let _guard = test_lock::acquire();
    e_setup();
    let (rv, hp, hs) = gen_pair(
        CKM_EC_KEY_PAIR_GEN,
        vec![(
            CKA_EC_PARAMS,
            vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
        )],
    );
    assert_eq!(rv, CKR_OK);
    // The KEM path needs CKA_ENCAPSULATE / CKA_DECAPSULATE.
    crate::state::set_object_attr_bytes(hp, CKA_ENCAPSULATE, vec![1]);
    crate::state::set_object_attr_bytes(hs, CKA_DECAPSULATE, vec![1]);

    let mut mech = [0usize; 3];
    mech[0] = CKM_ECDH1_DERIVE as usize;
    let mut ct = vec![0u8; 512];
    let mut ct_len: u32 = ct.len() as u32;
    let mut h_ss: u32 = 0;
    assert_eq!(
        unsafe {
            C_EncapsulateKey_impl(
                E_SESSION,
                mech.as_mut_ptr() as *mut u8,
                hp,
                std::ptr::null_mut(),
                0,
                ct.as_mut_ptr(),
                &mut ct_len,
                &mut h_ss,
            )
        },
        CKR_OK
    );
    // §6.3.17 — "The value of the generated public key is returned as the
    // ciphertext", and that value is a RAW octet string. 65 bytes for P-256,
    // not the 67 a DER OCTET STRING wrapper produces.
    assert_eq!(ct_len, 65, "P-256 ECDH-KEM ciphertext must be exactly 65 bytes");
    assert_eq!(
        ct[0], 0x04,
        "the first byte must be SEC1's uncompressed marker, not a DER tag"
    );

    // The tolerant reader on decapsulation is KEPT: both the raw form and the
    // historical DER-wrapped form must still decapsulate to the same secret.
    let raw_ct = ct[..65].to_vec();
    let mut der_ct = vec![0x04u8, 65u8];
    der_ct.extend_from_slice(&raw_ct);

    let mut decap = |bytes: &[u8]| -> Vec<u8> {
        let mut b = bytes.to_vec();
        let mut h: u32 = 0;
        assert_eq!(
            unsafe {
                C_DecapsulateKey_impl(
                    E_SESSION,
                    mech.as_mut_ptr() as *mut u8,
                    hs,
                    std::ptr::null_mut(),
                    0,
                    b.as_mut_ptr(),
                    b.len() as u32,
                    &mut h,
                )
            },
            CKR_OK
        );
        obj_attr(h, CKA_VALUE).unwrap()
    };
    let from_raw = decap(&raw_ct);
    let from_der = decap(&der_ct);
    assert_eq!(
        from_raw, from_der,
        "decapsulation must stay tolerant of the old DER-wrapped form"
    );
    assert_eq!(
        from_raw,
        obj_attr(h_ss, CKA_VALUE).unwrap(),
        "encapsulated and decapsulated secrets must agree"
    );
}

// ── E2 — CKA_EC_PARAMS on BOTH halves at EC keygen ──────────────────────

#[test]
fn e2_ec_keygen_writes_domain_parameters_on_both_halves() {
    let _guard = test_lock::acquire();
    e_setup();
    let p256 = vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    let (rv, hp, hs) = gen_pair(CKM_EC_KEY_PAIR_GEN, vec![(CKA_EC_PARAMS, p256.clone())]);
    assert_eq!(rv, CKR_OK);
    // §6.3.9 — "the mechanism contributes the CKA_CLASS, CKA_KEY_TYPE,
    // CKA_EC_PARAMS and CKA_VALUE attributes to the new private key".
    assert_eq!(
        obj_attr(hs, CKA_EC_PARAMS),
        Some(p256.clone()),
        "the PRIVATE half must carry the domain parameters"
    );
    assert_eq!(obj_attr(hp, CKA_EC_PARAMS), Some(p256));

    // P-384 — and the value must be the P-384 OID, not an echo of the caller.
    let (rv, hp, hs) = gen_pair(
        CKM_EC_KEY_PAIR_GEN,
        vec![(CKA_EC_PARAMS, curve_name("P-384"))],
    );
    assert_eq!(rv, CKR_OK);
    let expected = vec![0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
    assert_eq!(obj_attr(hp, CKA_EC_PARAMS), Some(expected.clone()));
    assert_eq!(obj_attr(hs, CKA_EC_PARAMS), Some(expected));
}

// ── E4 — Edwards / Montgomery public-key encoding ───────────────────────

#[test]
fn e4_edwards_and_montgomery_public_keys_are_bare_little_endian() {
    let _guard = test_lock::acquire();
    e_setup();

    // Ed25519 — the table says "Public key bytes in little endian order as
    // defined in [RFC 8032]", not the Weierstrass table's DER ECPoint.
    let (rv, hp, _) = gen_pair(
        CKM_EC_EDWARDS_KEY_PAIR_GEN,
        vec![(CKA_EC_PARAMS, oid(&[0x2b, 0x65, 0x70]))],
    );
    assert_eq!(rv, CKR_OK);
    let pt = obj_attr(hp, CKA_EC_POINT).expect("Edwards public key must carry CKA_EC_POINT");
    assert_eq!(pt.len(), 32, "bare 32 bytes — no DER wrapper");
    assert_ne!(pt[0], 0x04, "…and therefore no OCTET STRING tag");
    assert!(
        obj_attr(hp, CKA_EC_PARAMS).is_some(),
        "the parameters attribute must be present"
    );
    assert!(
        obj_attr(hp, CKA_VALUE).is_none(),
        "no CKA_VALUE is defined for an Edwards PUBLIC key"
    );

    // X25519 — same rule (RFC 7748).
    let (rv, hp, _) = gen_pair(
        CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
        vec![(CKA_EC_PARAMS, oid(&[0x2b, 0x65, 0x6e]))],
    );
    assert_eq!(rv, CKR_OK);
    let pt = obj_attr(hp, CKA_EC_POINT).expect("Montgomery public key must carry CKA_EC_POINT");
    assert_eq!(pt.len(), 32);
    assert!(obj_attr(hp, CKA_VALUE).is_none());

    // …and the curveName form is accepted on input (the interop note).
    let (rv, _, _) = gen_pair(
        CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
        vec![(CKA_EC_PARAMS, curve_name("curve25519"))],
    );
    assert_eq!(rv, CKR_OK, "both CHOICE forms must be accepted on input");
}

// ── E5 — RSA private keys expose the private exponent (and CRT set) ─────

#[test]
fn e5_rsa_private_key_exposes_the_private_exponent() {
    let _guard = test_lock::acquire();
    e_setup();
    let bits: usize = 2048;
    let mut m = [0usize; 3];
    m[0] = CKM_RSA_PKCS_KEY_PAIR_GEN as usize;
    let mut pub_tmpl: Vec<usize> = vec![
        CKA_MODULUS_BITS as usize,
        (&bits as *const usize) as usize,
        std::mem::size_of::<usize>(),
    ];
    let (mut hp, mut hs) = (0u32, 0u32);
    assert_eq!(
        unsafe {
            C_GenerateKeyPair_impl(
                E_SESSION,
                m.as_mut_ptr() as *mut u8,
                pub_tmpl.as_mut_ptr() as *mut u8,
                1,
                std::ptr::null_mut(),
                0,
                &mut hp,
                &mut hs,
            )
        },
        CKR_OK
    );
    // §6.1.3 — "The only attributes from Table 38 for which a Cryptoki
    // implementation is required to be able to return values are
    // CKA_MODULUS, CKA_PUBLIC_EXPONENT and CKA_PRIVATE_EXPONENT."
    let d = obj_attr(hs, CKA_PRIVATE_EXPONENT)
        .expect("CKA_PRIVATE_EXPONENT is required to be returnable");
    assert!(!d.is_empty());
    // The full CRT set — §6.7 forbids preparing a key for wrapping without it.
    for (attr, name) in [
        (CKA_PRIME_1, "CKA_PRIME_1"),
        (CKA_PRIME_2, "CKA_PRIME_2"),
        (CKA_EXPONENT_1, "CKA_EXPONENT_1"),
        (CKA_EXPONENT_2, "CKA_EXPONENT_2"),
        (CKA_COEFFICIENT, "CKA_COEFFICIENT"),
    ] {
        assert!(
            obj_attr(hs, attr).is_some_and(|v| !v.is_empty()),
            "{name} must be written at generation"
        );
    }
}

// ── E6 — wrapped private keys are PKCS#8 PrivateKeyInfo ─────────────────

#[test]
fn e6_wrapped_private_keys_are_pkcs8_and_public_keys_are_refused() {
    let _guard = test_lock::acquire();
    e_setup();

    let kek = put_object(
        78,
        vec![
            (CKA_CLASS, ulong(CKO_SECRET_KEY)),
            (CKA_KEY_TYPE, ulong(CKK_AES)),
            (CKA_WRAP, bbool(true)),
            (CKA_VALUE, vec![0x31u8; 32]),
        ],
    );
    let (rv, hp, hs) = gen_pair(
        CKM_EC_KEY_PAIR_GEN,
        vec![(
            CKA_EC_PARAMS,
            vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
        )],
    );
    assert_eq!(rv, CKR_OK);
    // EC private keys are generated CKA_EXTRACTABLE=FALSE; the point of this
    // test is the ENCODING, so make it wrappable.
    crate::state::set_object_attr_bytes(hs, CKA_EXTRACTABLE, vec![1]);

    // AES-KWP (RFC 5649), not plain AES-KW: a PKCS#8 PrivateKeyInfo is not a
    // whole number of 8-byte semiblocks, which is exactly why the padded
    // variant exists.
    let mut mech = [0usize; 3];
    mech[0] = CKM_AES_KEY_WRAP_KWP as usize;
    let mut out = vec![0u8; 512];
    let mut out_len: u32 = out.len() as u32;
    assert_eq!(
        C_WrapKey(
            E_SESSION,
            mech.as_mut_ptr() as *mut u8,
            kek,
            hs,
            out.as_mut_ptr(),
            &mut out_len,
        ),
        CKR_OK
    );
    // Unwrap it back to check the plaintext structure the engine produced.
    let mut blob = out[..out_len as usize].to_vec();
    let mut want = Tmpl::new(vec![
        (CKA_CLASS, ulong(CKO_SECRET_KEY)),
        (CKA_KEY_TYPE, ulong(CKK_GENERIC_SECRET)),
    ]);
    let want_count = want.count();
    let mut h_round: u32 = 0;
    let kek_unwrap = put_object(
        78,
        vec![
            (CKA_CLASS, ulong(CKO_SECRET_KEY)),
            (CKA_KEY_TYPE, ulong(CKK_AES)),
            (CKA_UNWRAP, bbool(true)),
            (CKA_VALUE, vec![0x31u8; 32]),
        ],
    );
    assert_eq!(
        C_UnwrapKey(
            E_SESSION,
            mech.as_mut_ptr() as *mut u8,
            kek_unwrap,
            blob.as_mut_ptr(),
            blob.len() as u32,
            want.ptr(),
            want_count,
            &mut h_round,
        ),
        CKR_OK
    );
    let plain = obj_attr(h_round, CKA_VALUE).unwrap();
    // §6.7 — "a private key is BER-encoded according to [PKCS #8]
    // PrivateKeyInfo ASN.1 type". Previously an EC private key came out as
    // the 32 raw scalar bytes.
    assert_eq!(plain[0], 0x30, "PrivateKeyInfo is a DER SEQUENCE");
    assert!(
        plain.len() > 32,
        "a bare 32-byte scalar is not a PrivateKeyInfo (got {} bytes)",
        plain.len()
    );
    // version INTEGER 0 immediately inside the SEQUENCE.
    let body_off = if plain[1] & 0x80 == 0 { 2 } else { 2 + (plain[1] & 0x7f) as usize };
    assert_eq!(&plain[body_off..body_off + 3], &[0x02, 0x01, 0x00]);

    // §5.18.3 class check — a PUBLIC key is not a wrappable object.
    crate::state::set_object_attr_bytes(hp, CKA_EXTRACTABLE, vec![1]);
    let mut out2 = vec![0u8; 512];
    let mut out2_len: u32 = out2.len() as u32;
    assert_eq!(
        C_WrapKey(
            E_SESSION,
            mech.as_mut_ptr() as *mut u8,
            kek,
            hp,
            out2.as_mut_ptr(),
            &mut out2_len,
        ),
        CKR_KEY_NOT_WRAPPABLE,
        "C_WrapKey wraps a private or secret key — not a public one"
    );
}

// ── E7 — CKA_SEED is not defined for SLH-DSA ────────────────────────────

#[test]
fn e7_slh_dsa_does_not_persist_a_seed() {
    let _guard = test_lock::acquire();
    e_setup();
    let seed = vec![0x5Au8; 48]; // 3n for the 128-bit parameter sets (n = 16)
    let mut m = [0usize; 3];
    m[0] = CKM_SLH_DSA_KEY_PAIR_GEN as usize;
    let ps = CKP_SLH_DSA_SHA2_128S as usize;
    let mut words: Vec<usize> = vec![
        CKA_PARAMETER_SET as usize,
        (&ps as *const usize) as usize,
        std::mem::size_of::<usize>(),
        CKA_SEED as usize,
        seed.as_ptr() as usize,
        seed.len(),
    ];
    let (mut hp, mut hs) = (0u32, 0u32);
    let rv = unsafe {
        C_GenerateKeyPair_impl(
            E_SESSION,
            m.as_mut_ptr() as *mut u8,
            words.as_mut_ptr() as *mut u8,
            2,
            std::ptr::null_mut(),
            0,
            &mut hp,
            &mut hs,
        )
    };
    assert_eq!(rv, CKR_OK, "deterministic SLH-DSA keygen must still work");
    // §6.69.4 does NOT list CKA_SEED among the attributes the mechanism
    // contributes, and the SLH-DSA private-key table defines no such
    // attribute. The seed is CONSUMED, not stored.
    assert!(
        obj_attr(hs, CKA_SEED).is_none(),
        "CKA_SEED is undefined for SLH-DSA and must not be persisted"
    );
    // ML-DSA, where §6.67.4 DOES list it, is unchanged.
    let ps2 = CKP_ML_DSA_44 as usize;
    let seed2 = vec![0x11u8; 32];
    let mut words2: Vec<usize> = vec![
        CKA_PARAMETER_SET as usize,
        (&ps2 as *const usize) as usize,
        std::mem::size_of::<usize>(),
        CKA_SEED as usize,
        seed2.as_ptr() as usize,
        seed2.len(),
    ];
    let mut m2 = [0usize; 3];
    m2[0] = CKM_ML_DSA_KEY_PAIR_GEN as usize;
    let (mut hp2, mut hs2) = (0u32, 0u32);
    assert_eq!(
        unsafe {
            C_GenerateKeyPair_impl(
                E_SESSION,
                m2.as_mut_ptr() as *mut u8,
                words2.as_mut_ptr() as *mut u8,
                2,
                std::ptr::null_mut(),
                0,
                &mut hp2,
                &mut hs2,
            )
        },
        CKR_OK
    );
    assert_eq!(
        obj_attr(hs2, CKA_SEED),
        Some(seed2),
        "§6.67.4 DOES list CKA_SEED for ML-DSA — that must not regress"
    );
}

// ═════════════════════════════════════════════════════════════════════════
// PHASE 4 — conformance posture, error codes, advertised capabilities
// ═════════════════════════════════════════════════════════════════════════

const C_SESSION: u32 = 0x5C44_0001;

fn c_setup() {
    crate::state::set_initialized(true);
    crate::state::ensure_slot(0);
    put_session(C_SESSION, 0, true);
}

// ── C3 — advertised capabilities must equal dispatch ────────────────────

#[test]
fn c3_every_ec_mechanism_advertises_the_mandated_flags() {
    let _guard = test_lock::acquire();
    // §6.3.3 says three times that a library performing EC mechanisms "must
    // set" the field type, the CKA_EC_PARAMS encodings and the point forms
    // on EACH EC mechanism. Values come from the pinned canonical OASIS
    // header (docs/refs/pkcs11t-canonical-v3.2.h), not a PDF rendering.
    assert_eq!(CKF_EC_F_P, 0x0010_0000);
    assert_eq!(CKF_EC_OID, 0x0080_0000);
    assert_eq!(CKF_EC_CURVENAME, 0x0400_0000);
    assert_eq!(CKF_EC_UNCOMPRESS, 0x0100_0000);

    let ec_mechs = [
        CKM_EC_KEY_PAIR_GEN,
        CKM_ECDSA,
        CKM_ECDSA_SHA256,
        CKM_ECDSA_SHA384,
        CKM_ECDSA_SHA512,
        CKM_ECDSA_SHA3_224,
        CKM_ECDSA_SHA3_256,
        CKM_ECDSA_SHA3_384,
        CKM_ECDSA_SHA3_512,
        CKM_ECDH1_DERIVE,
        CKM_ECDH1_COFACTOR_DERIVE,
        CKM_EC_EDWARDS_KEY_PAIR_GEN,
        CKM_EDDSA,
        CKM_EDDSA_PH,
        CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
        CKM_EC_MONTGOMERY_KEY_DERIVE,
        CKM_X25519,
        CKM_X448,
    ];
    for m in ec_mechs {
        let (_, _, flags) = mechanism_info(m)
            .unwrap_or_else(|| panic!("mechanism {m:#06x} must have a C_GetMechanismInfo arm"));
        assert_ne!(
            flags & CKF_EC_F_P,
            0,
            "{m:#06x} must set the field-type flag (this engine does prime curves)"
        );
        assert_ne!(
            flags & (CKF_EC_OID | CKF_EC_CURVENAME),
            0,
            "{m:#06x} must state which CKA_EC_PARAMS encodings it accepts"
        );
        assert_ne!(
            flags & CKF_EC_UNCOMPRESS,
            0,
            "{m:#06x} must state which point forms it accepts"
        );
        // Accurate NEGATIVES matter as much: this engine has no binary-field
        // curves, rejects explicit parameters, and does not do compressed points.
        assert_eq!(flags & CKF_EC_F_2M, 0, "{m:#06x} must not claim F_2^m");
        assert_eq!(
            flags & CKF_EC_ECPARAMETERS,
            0,
            "{m:#06x} must not claim explicit ECParameters — decode_ec_params refuses them"
        );
        assert_eq!(flags & CKF_EC_COMPRESS, 0, "{m:#06x} must not claim compressed points");
    }
}

#[test]
fn c3_wrap_capable_mechanisms_advertise_wrap() {
    let _guard = test_lock::acquire();
    // A mechanism flag is DEFINED as "the mechanism can be used with
    // function F". C_WrapKey / C_UnwrapKey accept all three of these.
    for m in [CKM_RSA_PKCS_OAEP, CKM_AES_CBC, CKM_AES_CBC_PAD] {
        let (_, _, flags) = mechanism_info(m).unwrap();
        assert_ne!(flags & CKF_WRAP, 0, "{m:#06x} is accepted by C_WrapKey");
        assert_ne!(flags & CKF_UNWRAP, 0, "{m:#06x} is accepted by C_UnwrapKey");
    }
    // …and CKM_AES_ECB, which the wrap path does NOT accept, must not claim it.
    let (_, _, ecb) = mechanism_info(CKM_AES_ECB).unwrap();
    assert_eq!(ecb & (CKF_WRAP | CKF_UNWRAP), 0);
}

// ── C2 — error codes ────────────────────────────────────────────────────

#[test]
fn c2_null_mechanism_cancels_the_active_operation() {
    let _guard = test_lock::acquire();
    c_setup();
    let key = put_object(
        0,
        vec![
            (CKA_CLASS, ulong(CKO_SECRET_KEY)),
            (CKA_KEY_TYPE, ulong(CKK_AES)),
            (CKA_ENCRYPT, bbool(true)),
            (CKA_DECRYPT, bbool(true)),
            (CKA_VALUE, vec![0x21u8; 32]),
        ],
    );
    // Start a real encryption operation…
    let iv = [0u8; 16];
    let mut mech: Vec<usize> = vec![
        CKM_AES_CBC as usize,
        iv.as_ptr() as usize,
        iv.len(),
    ];
    assert_eq!(
        C_EncryptInit(C_SESSION, mech.as_mut_ptr() as *mut u8, key),
        CKR_OK
    );
    // …and cancel it with the NULL-mechanism form. §5.11: "C_EncryptInit can
    // be called with pMechanism set to NULL_PTR to terminate an active
    // encryption operation." CKR_ARGUMENTS_BAD was an inapplicable code.
    assert_eq!(
        C_EncryptInit(C_SESSION, std::ptr::null_mut(), key),
        CKR_OK,
        "the NULL-mechanism cancel form must succeed"
    );
    // The operation really is gone: a fresh Init must not see it as active.
    assert_eq!(
        C_EncryptInit(C_SESSION, mech.as_mut_ptr() as *mut u8, key),
        CKR_OK
    );
    assert_eq!(C_EncryptInit(C_SESSION, std::ptr::null_mut(), key), CKR_OK);

    // Same shape for the other families.
    assert_eq!(C_DigestInit(C_SESSION, std::ptr::null_mut()), CKR_OK);
    assert_eq!(
        C_DecryptInit(C_SESSION, std::ptr::null_mut(), key),
        CKR_OK
    );
    assert_eq!(C_VerifyInit(C_SESSION, std::ptr::null_mut(), key), CKR_OK);
    assert_eq!(C_SignInit(C_SESSION, std::ptr::null_mut(), key), CKR_OK);
    assert_eq!(
        C_SignRecoverInit(C_SESSION, std::ptr::null_mut(), key),
        CKR_OK
    );
    assert_eq!(
        C_VerifyRecoverInit(C_SESSION, std::ptr::null_mut(), key),
        CKR_OK
    );
}

#[test]
fn c2_session_handle_takes_precedence_over_argument_codes() {
    let _guard = test_lock::acquire();
    c_setup();
    const BOGUS: u32 = 0x0BAD_5E55;
    // §5.2 — the session-handle class takes MANDATORY precedence. Each of
    // these previously returned an argument/operation code first, so an
    // application debugging a stale handle was told the wrong thing.
    let mut info = [0u8; 64];
    assert_eq!(
        C_GetSessionValidationFlags(BOGUS, 0, info.as_mut_ptr() as *mut u32),
        CKR_SESSION_HANDLE_INVALID
    );
    assert_eq!(
        C_GenerateRandom(BOGUS, std::ptr::null_mut(), 0),
        CKR_SESSION_HANDLE_INVALID
    );
    assert_eq!(
        C_CreateObject(BOGUS, std::ptr::null_mut(), 3, std::ptr::null_mut()),
        CKR_SESSION_HANDLE_INVALID
    );
    assert_eq!(
        C_GetAttributeValue(BOGUS, 0, std::ptr::null_mut(), 3),
        CKR_SESSION_HANDLE_INVALID
    );
    assert_eq!(
        C_CopyObject(BOGUS, 0, std::ptr::null_mut(), 3, std::ptr::null_mut()),
        CKR_SESSION_HANDLE_INVALID
    );
    assert_eq!(
        C_SetAttributeValue(BOGUS, 0, std::ptr::null_mut(), 3),
        CKR_SESSION_HANDLE_INVALID
    );
    assert_eq!(
        C_DeriveKey(BOGUS, std::ptr::null_mut(), 0, std::ptr::null_mut(), 0, std::ptr::null_mut()),
        CKR_SESSION_HANDLE_INVALID
    );
    assert_eq!(
        C_WrapKey(BOGUS, std::ptr::null_mut(), 0, 0, std::ptr::null_mut(), std::ptr::null_mut()),
        CKR_SESSION_HANDLE_INVALID
    );
    assert_eq!(
        C_DigestUpdate(BOGUS, std::ptr::null_mut(), 0),
        CKR_SESSION_HANDLE_INVALID
    );
    assert_eq!(
        C_SignUpdate(BOGUS, std::ptr::null_mut(), 0),
        CKR_SESSION_HANDLE_INVALID
    );
    assert_eq!(
        C_VerifyUpdate(BOGUS, std::ptr::null_mut(), 0),
        CKR_SESSION_HANDLE_INVALID
    );
    assert_eq!(
        C_FindObjectsInit(BOGUS, std::ptr::null_mut(), 5),
        CKR_SESSION_HANDLE_INVALID
    );
    // And a NULL-mechanism cancel on a bogus session is still a bad handle.
    assert_eq!(
        C_EncryptInit(BOGUS, std::ptr::null_mut(), 0),
        CKR_SESSION_HANDLE_INVALID
    );
}

#[test]
fn c2_context_specific_login_is_a_valid_user_type() {
    let _guard = test_lock::acquire();
    let slot = 79u32;
    s6_bring_up_token(slot);
    let s = 0x5C44_9001;
    put_session(s, slot, true);
    let mut pin = *b"5678";
    // CKU_CONTEXT_SPECIFIC is one of the three VALID CK_USER_TYPE values.
    // Answering CKR_USER_TYPE_INVALID claimed it does not exist; with no
    // re-authentication pending the correct answer is
    // CKR_OPERATION_NOT_INITIALIZED.
    assert_eq!(
        C_Login(s, CKU_CONTEXT_SPECIFIC, pin.as_mut_ptr(), 4),
        CKR_OPERATION_NOT_INITIALIZED
    );
    // A genuinely undefined user type is still CKR_USER_TYPE_INVALID.
    assert_eq!(
        C_Login(s, 99, pin.as_mut_ptr(), 4),
        CKR_USER_TYPE_INVALID
    );
    drop_session(s);
}

#[test]
fn c2_unsupported_xmss_parameter_set_has_its_own_code() {
    let _guard = test_lock::acquire();
    c_setup();
    let mut m = [0usize; 3];
    m[0] = CKM_XMSS_KEY_PAIR_GEN as usize;
    let bogus: usize = 0xdead;
    let mut words: Vec<usize> = vec![
        CKA_PARAMETER_SET as usize,
        (&bogus as *const usize) as usize,
        std::mem::size_of::<usize>(),
    ];
    let (mut hp, mut hs) = (0u32, 0u32);
    let rv = unsafe {
        C_GenerateKeyPair_impl(
            C_SESSION,
            m.as_mut_ptr() as *mut u8,
            words.as_mut_ptr() as *mut u8,
            1,
            std::ptr::null_mut(),
            0,
            &mut hp,
            &mut hs,
        )
    };
    // §5.1.6 Table 6 — "This parameter set is not supported by this token."
    // The engine already uses this code correctly for ML-DSA / ML-KEM /
    // SLH-DSA; CKR_FUNCTION_FAILED said nothing about why.
    assert_eq!(rv, CKR_PARAMETER_SET_NOT_SUPPORTED);
}

// ── V-09 — CKK_EC_MONTGOMERY under encapsulate / decapsulate ────────────

#[test]
fn v09_montgomery_keys_are_accepted_by_the_kem_entry_points() {
    let _guard = test_lock::acquire();
    e_setup();
    let (rv, hp, hs) = gen_pair(
        CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
        vec![(CKA_EC_PARAMS, oid(&[0x2b, 0x65, 0x6e]))],
    );
    assert_eq!(rv, CKR_OK);
    crate::state::set_object_attr_bytes(hp, CKA_ENCAPSULATE, vec![1]);
    crate::state::set_object_attr_bytes(hs, CKA_DECAPSULATE, vec![1]);

    let mut mech = [0usize; 3];
    mech[0] = CKM_ECDH1_DERIVE as usize;
    let mut ct = vec![0u8; 256];
    let mut ct_len: u32 = ct.len() as u32;
    let mut h_ss: u32 = 0;
    // Table 78 lists CKK_EC_MONTGOMERY for this mechanism; the engine
    // advertised CKF_ENCAPSULATE on CKM_ECDH1_DERIVE but accepted only
    // CKK_EC, so the advertised capability was partly untrue.
    assert_eq!(
        unsafe {
            C_EncapsulateKey_impl(
                E_SESSION,
                mech.as_mut_ptr() as *mut u8,
                hp,
                std::ptr::null_mut(),
                0,
                ct.as_mut_ptr(),
                &mut ct_len,
                &mut h_ss,
            )
        },
        CKR_OK
    );
    // E1 — X25519's ciphertext is the bare 32-byte little-endian point.
    assert_eq!(ct_len, 32, "X25519 ECDH-KEM ciphertext must be exactly 32 bytes");
    let mut ctb = ct[..32].to_vec();
    let mut h_out: u32 = 0;
    assert_eq!(
        unsafe {
            C_DecapsulateKey_impl(
                E_SESSION,
                mech.as_mut_ptr() as *mut u8,
                hs,
                std::ptr::null_mut(),
                0,
                ctb.as_mut_ptr(),
                ctb.len() as u32,
                &mut h_out,
            )
        },
        CKR_OK
    );
    assert_eq!(
        obj_attr(h_out, CKA_VALUE).unwrap(),
        obj_attr(h_ss, CKA_VALUE).unwrap(),
        "both ends must derive the same shared secret"
    );
}
