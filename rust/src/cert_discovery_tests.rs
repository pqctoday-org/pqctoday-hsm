//! Slot and certificate discovery remediation suite (2026-10-02).
//!
//! Each test pins one finding of the black-box discovery audit
//! (`docs/remediation-plan-rust-cert-discovery-10022026.md`, items R1-R6)
//! and was run against the unfixed engine first, where it failed.
//!
//! Included from `ffi.rs` (`#[path]`), so `use super::*` resolves to the FFI
//! module and its private helpers.

use super::conformance_v32_tests::{bbool, drop_session, put_session, ulong, Tmpl};
use super::*;
use crate::native::keygen::{CKA_ID, CKA_LABEL};
use crate::native::test_lock;

/// Slots 2000+ are this module's own, so nothing another test creates on
/// slot 0 can leak into a slot-scoped search here.
const SLOT: u32 = 2000;

fn setup(session: u32) {
    crate::state::set_initialized(true);
    crate::state::ensure_slot(SLOT);
    put_session(session, SLOT, true);
}

fn set_login(slot: u32, state: LoginState) {
    TOKEN_STORE.with(|ts| ts.borrow_mut().get_mut(&slot).unwrap().login_state = state);
}

fn unhex(h: &str) -> Vec<u8> {
    (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}

/// Session-object X.509 certificate with the minimum template §4.6 allows,
/// plus `extra` attributes.
fn create_cert(session: u32, extra: Vec<(u32, Vec<u8>)>) -> u32 {
    let mut entries = vec![
        (CKA_CLASS, ulong(CKO_CERTIFICATE)),
        (CKA_CERTIFICATE_TYPE, ulong(CKC_X_509)),
        (CKA_TOKEN, bbool(false)),
        (CKA_SUBJECT, vec![0x30, 0x00]),
        (CKA_VALUE, vec![0x30, 0x03, 0x02, 0x01, 0x00]),
    ];
    entries.extend(extra);
    let mut t = Tmpl::new(entries);
    let mut h = 0u32;
    assert_eq!(C_CreateObject(session, t.ptr(), t.count(), &mut h), CKR_OK);
    h
}

/// `C_GetAttributeValue` length query for one attribute: (rv, ulValueLen).
fn len_of(session: u32, obj: u32, attr: u32) -> (u32, usize) {
    let mut words: [usize; 3] = [attr as usize, 0, 0];
    let rv = C_GetAttributeValue(session, obj, words.as_mut_ptr() as *mut u8, 1);
    (rv, words[2])
}

fn value_of(session: u32, obj: u32, attr: u32) -> Vec<u8> {
    let (rv, len) = len_of(session, obj, attr);
    assert_eq!(rv, CKR_OK, "attr 0x{attr:x}");
    let mut buf = vec![0u8; len];
    let mut words: [usize; 3] = [attr as usize, buf.as_mut_ptr() as usize, len];
    assert_eq!(C_GetAttributeValue(session, obj, words.as_mut_ptr() as *mut u8, 1), CKR_OK);
    buf
}

fn find_all(session: u32, words: &mut [usize]) -> Result<Vec<u32>, u32> {
    let rv = C_FindObjectsInit(session, words.as_mut_ptr() as *mut u8, (words.len() / 3) as u32);
    if rv != CKR_OK {
        return Err(rv);
    }
    let mut out = vec![0u32; 256];
    let mut n = 0u32;
    assert_eq!(C_FindObjects(session, out.as_mut_ptr(), 256, &mut n), CKR_OK);
    assert_eq!(C_FindObjectsFinal(session), CKR_OK);
    out.truncate(n as usize);
    Ok(out)
}

fn remove_objects(handles: &[u32]) {
    OBJECTS.with(|o| {
        let mut store = o.borrow_mut();
        for h in handles {
            store.remove(h);
        }
    });
}

// ── R1: attributes with a spec default are possessed (§4, Tables 19/21/22/26) ──
// CKA_TRUSTED (no default in Table 21) and CKA_NAME_HASH_ALGORITHM (Table 22:
// may be absent) are deliberately NOT asserted.

#[test]
fn r1_minimal_certificate_possesses_every_defaulted_attribute() {
    let _g = test_lock::acquire();
    let s = 0x2000_0001;
    setup(s);
    let c = create_cert(s, vec![]);

    // Empty-default byte arrays: CKR_OK with length 0.
    for attr in [
        CKA_LABEL,
        CKA_ID,
        CKA_ISSUER,
        CKA_SERIAL_NUMBER,
        CKA_URL,
        CKA_HASH_OF_SUBJECT_PUBLIC_KEY,
        CKA_HASH_OF_ISSUER_PUBLIC_KEY,
        CKA_START_DATE,
        CKA_END_DATE,
        CKA_PUBLIC_KEY_INFO,
    ] {
        assert_eq!(len_of(s, c, attr), (CKR_OK, 0), "attr 0x{attr:x} must default to empty");
    }
    // Defaulted scalars.
    assert_eq!(value_of(s, c, CKA_PRIVATE), bbool(false), "CKA_PRIVATE");
    assert_eq!(
        value_of(s, c, CKA_CERTIFICATE_CATEGORY),
        ulong(CK_CERTIFICATE_CATEGORY_UNSPECIFIED),
        "CKA_CERTIFICATE_CATEGORY"
    );
    assert_eq!(
        value_of(s, c, CKA_JAVA_MIDP_SECURITY_DOMAIN),
        ulong(CK_SECURITY_DOMAIN_UNSPECIFIED),
        "CKA_JAVA_MIDP_SECURITY_DOMAIN"
    );

    // The listing template from the audit, in one call.
    let mut words: [usize; 9] = [
        CKA_LABEL as usize, 0, 0,
        CKA_SUBJECT as usize, 0, 0,
        CKA_ID as usize, 0, 0,
    ];
    assert_eq!(C_GetAttributeValue(s, c, words.as_mut_ptr() as *mut u8, 3), CKR_OK);
    assert_eq!((words[2], words[5], words[8]), (0, 2, 0));

    remove_objects(&[c]);
    drop_session(s);
}

#[test]
fn r1_caller_values_are_not_overwritten_by_defaults() {
    let _g = test_lock::acquire();
    let s = 0x2000_0002;
    setup(s);
    let c = create_cert(s, vec![(CKA_LABEL, b"mine".to_vec()), (CKA_ID, vec![7, 7])]);
    assert_eq!(value_of(s, c, CKA_LABEL), b"mine".to_vec());
    assert_eq!(value_of(s, c, CKA_ID), vec![7, 7]);
    remove_objects(&[c]);
    drop_session(s);
}

#[test]
fn r1_keys_and_data_objects_possess_empty_label_and_id() {
    let _g = test_lock::acquire();
    let s = 0x2000_0003;
    setup(s);
    // Secret keys and data objects default to private (R7), so create them
    // in a user session.
    set_login(SLOT, LoginState::User);
    let mut key = Tmpl::new(vec![
        (CKA_CLASS, ulong(CKO_SECRET_KEY)),
        (CKA_KEY_TYPE, ulong(CKK_AES)),
        (CKA_TOKEN, bbool(false)),
        (CKA_VALUE, vec![0x42; 16]),
    ]);
    let mut k = 0u32;
    assert_eq!(C_CreateObject(s, key.ptr(), key.count(), &mut k), CKR_OK);
    assert_eq!(len_of(s, k, CKA_LABEL), (CKR_OK, 0), "secret key CKA_LABEL (Table 19)");
    assert_eq!(len_of(s, k, CKA_ID), (CKR_OK, 0), "secret key CKA_ID (Table 26)");

    let mut data = Tmpl::new(vec![
        (CKA_CLASS, ulong(CKO_DATA)),
        (CKA_TOKEN, bbool(false)),
        (CKA_VALUE, b"x".to_vec()),
    ]);
    let mut d = 0u32;
    assert_eq!(C_CreateObject(s, data.ptr(), data.count(), &mut d), CKR_OK);
    assert_eq!(len_of(s, d, CKA_LABEL), (CKR_OK, 0), "data object CKA_LABEL (Table 19)");

    remove_objects(&[k, d]);
    set_login(SLOT, LoginState::Public);
    drop_session(s);
}

#[test]
fn r1_trust_objects_possess_empty_label() {
    // v3.3 object_classification.md "Storage Objects" lists CKO_TRUST, which
    // resolves v3.2's ambiguity (§4.4 vs Figure 1) — see is_storage_class.
    let _g = test_lock::acquire();
    crate::state::set_initialized(true);
    let mut attrs: Attributes = std::collections::HashMap::new();
    crate::state::store_ulong(&mut attrs, CKA_CLASS, CKO_TRUST);
    attrs.insert(CKA_PRIV_SLOT_ID, SLOT.to_le_bytes().to_vec());
    let h = crate::state::allocate_handle(attrs);
    assert_eq!(super::conformance_v32_tests::obj_attr(h, CKA_LABEL), Some(Vec::new()));
    remove_objects(&[h]);
}

#[test]
fn r1_objects_loaded_from_the_store_are_backfilled() {
    let _g = test_lock::acquire();
    let s = 0x2000_0004;
    setup(s);
    // An object as an older build persisted it: no CKA_LABEL / CKA_ID.
    let mut attrs: Attributes = std::collections::HashMap::new();
    crate::state::store_ulong(&mut attrs, CKA_CLASS, CKO_CERTIFICATE);
    crate::state::store_ulong(&mut attrs, CKA_CERTIFICATE_TYPE, CKC_X_509);
    attrs.insert(CKA_TOKEN, bbool(true));
    attrs.insert(CKA_SUBJECT, vec![0x30, 0x00]);
    attrs.insert(CKA_VALUE, vec![0x30, 0x03, 0x02, 0x01, 0x00]);
    attrs.insert(CKA_PRIV_SLOT_ID, SLOT.to_le_bytes().to_vec());
    let h = 0x2000_0F00;
    crate::state::rehydrate_insert(h, attrs.clone());
    assert_eq!(len_of(s, h, CKA_LABEL), (CKR_OK, 0), "SQLite rehydrate path");
    assert_eq!(len_of(s, h, CKA_ID), (CKR_OK, 0), "SQLite rehydrate path");

    // Snapshot path: strip the defaults again, round-trip the token state.
    OBJECTS.with(|o| {
        let mut store = o.borrow_mut();
        let a = store.get_mut(&h).unwrap();
        a.remove(&CKA_LABEL);
        a.remove(&CKA_ID);
    });
    let blob = crate::state_snapshot::serialize_token_state();
    crate::state_snapshot::deserialize_token_state(&blob).unwrap();
    put_session(s, SLOT, true);
    assert_eq!(len_of(s, h, CKA_LABEL), (CKR_OK, 0), "snapshot load path");
    assert_eq!(len_of(s, h, CKA_ID), (CKR_OK, 0), "snapshot load path");

    remove_objects(&[h]);
    drop_session(s);
}

// ── R2: every slot carries its CKO_PROFILE objects (Profiles §5.1 c4, §5.5 c5b) ──

fn profile_count(slot: u32) -> usize {
    OBJECTS.with(|o| {
        o.borrow()
            .values()
            .filter(|a| {
                crate::state::get_object_attr_u32_from(a, CKA_CLASS) == Some(CKO_PROFILE)
                    && a.get(&CKA_PRIV_SLOT_ID).map(|v| v.as_slice()) == Some(&slot.to_le_bytes()[..])
            })
            .count()
    })
}

fn objects_on(slots: &[u32]) -> Vec<u32> {
    OBJECTS.with(|o| {
        o.borrow()
            .iter()
            .filter(|(_, a)| {
                a.get(&CKA_PRIV_SLOT_ID)
                    .is_some_and(|v| slots.iter().any(|s| v.as_slice() == &s.to_le_bytes()[..]))
            })
            .map(|(h, _)| *h)
            .collect()
    })
}

#[test]
fn r2_spare_slot_from_get_slot_list_has_profile_objects() {
    let _g = test_lock::acquire();
    crate::state::set_initialized(true);
    let saved = TOKEN_STORE.with(|ts| std::mem::take(&mut *ts.borrow_mut()));

    // One slot, initialized: the size query must add a spare slot 5001.
    crate::state::ensure_slot(5000);
    TOKEN_STORE.with(|ts| ts.borrow_mut().get_mut(&5000).unwrap().initialized = true);
    let mut n = 0u32;
    assert_eq!(C_GetSlotList(0, std::ptr::null_mut(), &mut n), CKR_OK);
    assert_eq!(n, 2, "spare slot added");
    let spare = profile_count(5001);

    remove_objects(&objects_on(&[5000, 5001]));
    TOKEN_STORE.with(|ts| *ts.borrow_mut() = saved);
    assert!(spare >= 1, "spare slot 5001 has {spare} CKO_PROFILE objects; slot 5000 has them via ensure_slot");
}

#[test]
fn r2_snapshot_load_gives_profile_objects_to_slots_without_them() {
    let _g = test_lock::acquire();
    crate::state::set_initialized(true);
    let saved = TOKEN_STORE.with(|ts| ts.borrow().clone());

    // A slot as an older build persisted it: token metadata, no profiles.
    // TOKEN_STORE is a Mutex: never call ensure_slot while holding it.
    crate::state::ensure_slot(0);
    let mut t = TOKEN_STORE.with(|ts| ts.borrow().get(&0).cloned().unwrap());
    t.slot_id = 6000;
    TOKEN_STORE.with(|ts| ts.borrow_mut().insert(6000, t));
    assert_eq!(profile_count(6000), 0);
    let blob = crate::state_snapshot::serialize_token_state();
    crate::state_snapshot::deserialize_token_state(&blob).unwrap();
    let after = profile_count(6000);

    remove_objects(&objects_on(&[6000]));
    TOKEN_STORE.with(|ts| *ts.borrow_mut() = saved);
    assert!(after >= 1, "slot 6000 got {after} CKO_PROFILE objects on load");
}

// ── R3: an empty template value is a filter, not a wildcard (§5.7.7) ──

#[test]
fn r3_empty_template_value_matches_only_empty_attribute() {
    let _g = test_lock::acquire();
    let s = 0x2000_0005;
    setup(s);
    let with_id = create_cert(s, vec![(CKA_ID, vec![1]), (CKA_LABEL, b"a".to_vec())]);
    let without_id = create_cert(s, vec![]);
    let class = ulong(CKO_CERTIFICATE);
    let empty: Vec<u8> = Vec::new();

    // Zero-length, non-NULL pValue.
    let mut w = [
        CKA_CLASS as usize, class.as_ptr() as usize, class.len(),
        CKA_ID as usize, empty.as_ptr() as usize, 0,
    ];
    let found = find_all(s, &mut w).unwrap();
    assert!(found.contains(&without_id) && !found.contains(&with_id), "CKA_ID=<empty>: {found:?}");

    // Zero-length, NULL pValue — the same empty value.
    let mut w = [
        CKA_CLASS as usize, class.as_ptr() as usize, class.len(),
        CKA_LABEL as usize, 0, 0,
    ];
    let found = find_all(s, &mut w).unwrap();
    assert!(found.contains(&without_id) && !found.contains(&with_id), "CKA_LABEL=<empty>: {found:?}");

    // NULL pValue with a non-zero length cannot be honoured: refuse, never widen.
    let mut w = [CKA_CLASS as usize, class.as_ptr() as usize, class.len(), CKA_ID as usize, 0, 2];
    assert_eq!(find_all(s, &mut w), Err(CKR_ARGUMENTS_BAD));

    remove_objects(&[with_id, without_id]);
    drop_session(s);
}

// ── R4: §5.7.5 case 5 ──

#[test]
fn r4_short_buffer_reports_unavailable_information() {
    let _g = test_lock::acquire();
    let s = 0x2000_0006;
    setup(s);
    let c = create_cert(s, vec![(CKA_LABEL, b"abcdef".to_vec())]);
    let mut buf = [0u8; 2];
    let mut words: [usize; 6] = [
        CKA_LABEL as usize, buf.as_mut_ptr() as usize, 2,
        CKA_SUBJECT as usize, 0, 0,
    ];
    assert_eq!(C_GetAttributeValue(s, c, words.as_mut_ptr() as *mut u8, 2), CKR_BUFFER_TOO_SMALL);
    assert_eq!(words[2], usize::MAX, "case 5: ulValueLen = CK_UNAVAILABLE_INFORMATION");
    assert_eq!(words[5], 2, "the other entry is still processed");
    remove_objects(&[c]);
    drop_session(s);
}

// ── R6 (owner decision, not a v3.2 rule): serial = slot ID + 1 ──

#[test]
fn r6_token_serial_numbers_are_distinct_per_slot() {
    let _g = test_lock::acquire();
    crate::state::set_initialized(true);
    crate::state::ensure_slot(0);
    crate::state::ensure_slot(SLOT);
    let serial = |slot: u32| {
        let mut info = [0u8; 160];
        assert_eq!(C_GetTokenInfo(slot, info.as_mut_ptr()), CKR_OK);
        info[80..96].to_vec()
    };
    assert_eq!(&serial(0)[..], b"0001            ", "slot 0 keeps its historical serial");
    assert_eq!(&serial(SLOT)[..], b"2001            ", "slot {SLOT} reports slot ID + 1");
}

// ── R7 (owner decision 2026-10-02): C++-parity CKA_PRIVATE defaults on the
//    C_* creation paths, and Usage Guide Table 3 — no private object outside
//    a user session. ──

#[test]
fn r7_private_by_default_classes_need_a_user_session() {
    let _g = test_lock::acquire();
    let s = 0x2000_0007;
    setup(s);
    set_login(SLOT, LoginState::Public);
    let aes = || {
        vec![
            (CKA_CLASS, ulong(CKO_SECRET_KEY)),
            (CKA_KEY_TYPE, ulong(CKK_AES)),
            (CKA_TOKEN, bbool(false)),
            (CKA_VALUE, vec![0x42; 16]),
        ]
    };
    let data = || vec![(CKA_CLASS, ulong(CKO_DATA)), (CKA_TOKEN, bbool(false)), (CKA_VALUE, b"x".to_vec())];
    let mut h = 0u32;

    // Public session: secret key and data object default to private -> refused.
    for t in [aes(), data()] {
        let mut t = Tmpl::new(t);
        assert_eq!(C_CreateObject(s, t.ptr(), t.count(), &mut h), CKR_USER_NOT_LOGGED_IN);
    }
    // ... unless the template asks for a public object.
    let mut t = aes();
    t.push((CKA_PRIVATE, bbool(false)));
    let mut t = Tmpl::new(t);
    assert_eq!(C_CreateObject(s, t.ptr(), t.count(), &mut h), CKR_OK);
    assert_eq!(value_of(s, h, CKA_PRIVATE), bbool(false));
    let public_aes = h;
    // C_GenerateKey takes the same default.
    let len = ulong(32);
    let mut gt = Tmpl::new(vec![(CKA_TOKEN, bbool(false)), (CKA_VALUE_LEN, len)]);
    let mut mech: [usize; 3] = [CKM_AES_KEY_GEN as usize, 0, 0];
    assert_eq!(
        C_GenerateKey(s, mech.as_mut_ptr() as *mut u8, gt.ptr(), gt.count(), &mut h),
        CKR_USER_NOT_LOGGED_IN
    );

    // User session: same templates succeed and report CKA_PRIVATE = TRUE.
    set_login(SLOT, LoginState::User);
    let mut t = Tmpl::new(aes());
    assert_eq!(C_CreateObject(s, t.ptr(), t.count(), &mut h), CKR_OK);
    assert_eq!(value_of(s, h, CKA_PRIVATE), bbool(true));
    let private_aes = h;
    let mut t = Tmpl::new(data());
    assert_eq!(C_CreateObject(s, t.ptr(), t.count(), &mut h), CKR_OK);
    assert_eq!(value_of(s, h, CKA_PRIVATE), bbool(true));
    let private_data = h;

    // Certificates stay public by default, even in a public session.
    set_login(SLOT, LoginState::Public);
    let c = create_cert(s, vec![]);
    assert_eq!(value_of(s, c, CKA_PRIVATE), bbool(false));

    remove_objects(&[public_aes, private_aes, private_data, c]);
    drop_session(s);
}

#[test]
fn r7_objects_loaded_without_cka_private_stay_public() {
    let _g = test_lock::acquire();
    let s = 0x2000_0008;
    setup(s);
    set_login(SLOT, LoginState::Public);
    // A secret key as an older build stored it: no CKA_PRIVATE.
    let mut attrs: Attributes = std::collections::HashMap::new();
    crate::state::store_ulong(&mut attrs, CKA_CLASS, CKO_SECRET_KEY);
    crate::state::store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_AES);
    attrs.insert(CKA_TOKEN, bbool(true));
    attrs.insert(CKA_VALUE, vec![0x11; 16]);
    attrs.insert(CKA_PRIV_SLOT_ID, SLOT.to_le_bytes().to_vec());
    let h = 0x2000_0F01;
    crate::state::rehydrate_insert(h, attrs);
    assert_eq!(value_of(s, h, CKA_PRIVATE), bbool(false), "load records the historical public value");
    remove_objects(&[h]);
    drop_session(s);
}

// ── R8 (owner decision 2026-10-02): SOFTHSMRUST_SLOTS=N ──

#[test]
fn r8_softhsmrust_slots_brings_n_slots_online_at_initialize() {
    let _g = test_lock::acquire();
    crate::state::set_initialized(false);
    // SAFETY: nextest runs each test in its own process; nothing else reads
    // the environment concurrently.
    unsafe { std::env::set_var("SOFTHSMRUST_SLOTS", "4") };
    let rv = C_Initialize(std::ptr::null_mut());
    unsafe { std::env::remove_var("SOFTHSMRUST_SLOTS") };
    assert_eq!(rv, CKR_OK);
    for slot in 0..4u32 {
        let mut info = [0u8; 104];
        assert_eq!(C_GetSlotInfo(slot, info.as_mut_ptr()), CKR_OK, "slot {slot}");
        let profiles = OBJECTS.with(|o| {
            o.borrow()
                .values()
                .filter(|a| {
                    crate::state::get_object_attr_u32_from(a, CKA_CLASS) == Some(CKO_PROFILE)
                        && crate::state::object_slot_of(a) == slot
                })
                .count()
        });
        assert!(profiles >= 1, "slot {slot} has its CKO_PROFILE objects");
    }

    // A malformed value fails C_Initialize instead of being ignored.
    crate::state::set_initialized(false);
    unsafe { std::env::set_var("SOFTHSMRUST_SLOTS", "four") };
    let rv = C_Initialize(std::ptr::null_mut());
    unsafe { std::env::remove_var("SOFTHSMRUST_SLOTS") };
    assert_eq!(rv, CKR_FUNCTION_FAILED);
    crate::state::set_initialized(true);
}

// ── R9 (owner decision 2026-10-02): slotDescription + slot manufacturerID ──

#[test]
fn r9_slot_description_text() {
    let _g = test_lock::acquire();
    crate::state::set_initialized(true);
    crate::state::ensure_slot(SLOT);
    let mut info = [0u8; 104];
    assert_eq!(C_GetSlotInfo(SLOT, info.as_mut_ptr()), CKR_OK);
    let mut want = [b' '; 64];
    want[..25].copy_from_slice(b"PQCToday HSM Virtual Slot");
    assert_eq!(&info[..64], &want[..]);
    let mut mfr = [b' '; 32];
    mfr[..8].copy_from_slice(b"PQCToday");
    assert_eq!(&info[64..96], &mfr[..], "slot manufacturerID");
}

// ── R10 (§4.6.2 recommendation): CKA_PUBLIC_KEY_INFO from the certificate ──

const PKI_TEST_CERT: &str = "3082017c30820121a00302010202147a94dfa253fbb600a41897063e72b4f923f7e4a3300a06082a8648ce3d04030230133111300f06035504030c08706b692d74657374301e170d3236313030323136333535365a170d3336303932393136333535365a30133111300f06035504030c08706b692d746573743059301306072a8648ce3d020106082a8648ce3d030107034200042165f11fd0765bee4b8b602a2182f8e7d8047be2e4c50c0955b2b50441354bdd482624d9750442485669646dc32b294379f645476401e97550acc459a473e8afa3533051301d0603551d0e041604146a61598030180246bc3914d87c29e86bfd739e95301f0603551d230418301680146a61598030180246bc3914d87c29e86bfd739e95300f0603551d130101ff040530030101ff300a06082a8648ce3d0403020349003046022100d318961fb24f44fdd560c476268be3216b8e595dc6fc96c262230a92ae5b35f9022100dae2f5ca6b4ca776e74effb592166bffb63911e3e9a920bf5fbc761158408ad6";
/// `openssl x509 -pubkey | openssl pkey -pubin -outform DER` of the cert above.
const PKI_TEST_SPKI: &str = "3059301306072a8648ce3d020106082a8648ce3d030107034200042165f11fd0765bee4b8b602a2182f8e7d8047be2e4c50c0955b2b50441354bdd482624d9750442485669646dc32b294379f645476401e97550acc459a473e8af";

#[test]
fn r10_certificate_public_key_info_is_extracted_from_the_certificate() {
    let _g = test_lock::acquire();
    let s = 0x2000_0009;
    setup(s);
    let mut t = Tmpl::new(vec![
        (CKA_CLASS, ulong(CKO_CERTIFICATE)),
        (CKA_CERTIFICATE_TYPE, ulong(CKC_X_509)),
        (CKA_TOKEN, bbool(false)),
        (CKA_SUBJECT, vec![0x30, 0x00]),
        (CKA_VALUE, unhex(PKI_TEST_CERT)),
    ]);
    let mut c = 0u32;
    assert_eq!(C_CreateObject(s, t.ptr(), t.count(), &mut c), CKR_OK);
    assert_eq!(value_of(s, c, CKA_PUBLIC_KEY_INFO), unhex(PKI_TEST_SPKI), "matches OpenSSL's SPKI");

    // A caller-supplied value wins; an unparseable certificate keeps the
    // empty Table 21 default.
    let supplied = create_cert(s, vec![(CKA_PUBLIC_KEY_INFO, vec![0x30, 0x00])]);
    assert_eq!(value_of(s, supplied, CKA_PUBLIC_KEY_INFO), vec![0x30, 0x00]);
    let junk = create_cert(s, vec![]);
    assert_eq!(len_of(s, junk, CKA_PUBLIC_KEY_INFO), (CKR_OK, 0));

    remove_objects(&[c, supplied, junk]);
    drop_session(s);
}
