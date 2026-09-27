//! A3 (AES acceleration plan, 2026-09-27): per-session operation state and
//! the Init-time AES key-schedule cache.
//!
//! The per-session tables moved from one `Mutex<HashMap>` each to 64 shards
//! keyed by session handle, and one-shot AES C_Encrypt / C_Decrypt may use a
//! key schedule cached at Init. These tests pin the behaviour that must NOT
//! change: operation-state error codes, the §5.2 size query, cleanup on
//! C_CloseSession / C_CloseAllSessions / C_Finalize, isolation between
//! sessions running on different threads, and that a key destroyed or
//! changed after Init is never served from the cache.

use super::*;
use crate::native::test_lock;

/// High fixed handles, disjoint from every other ffi test module.
const SLOT: u32 = 0;
const S_A: u32 = 0xA300_0001;
const S_B: u32 = 0xA300_0002;
const KEY_A: u32 = 0xA300_1001;
const KEY_B: u32 = 0xA300_1002;
const IV: [u8; 16] = [0x24; 16];

fn put_aes_key(handle: u32, value: &[u8]) {
    let mut attrs = Attributes::new();
    attrs.insert(CKA_VALUE, value.to_vec());
    store_ulong(&mut attrs, CKA_CLASS, CKO_SECRET_KEY);
    store_ulong(&mut attrs, CKA_KEY_TYPE, CKK_AES);
    store_ulong(&mut attrs, CKA_VALUE_LEN, value.len() as u32);
    store_bool(&mut attrs, CKA_PRIVATE, false);
    for a in [CKA_ENCRYPT, CKA_DECRYPT] {
        store_bool(&mut attrs, a, true);
    }
    OBJECTS.with(|o| o.borrow_mut().insert(handle, attrs));
}

fn open(h: u32) {
    SESSIONS.insert(h, crate::state::SessionState { slot_id: SLOT, rw_session: true });
}

fn setup() {
    crate::state::set_initialized(true);
    crate::state::ensure_slot(SLOT);
    open(S_A);
    open(S_B);
    put_aes_key(KEY_A, &[0x11; 16]);
    put_aes_key(KEY_B, &[0x22; 32]);
}

/// CK_MECHANISM at native width; `iv` must outlive the call.
fn cbc(iv: &[u8; 16]) -> [usize; 3] {
    [CKM_AES_CBC as usize, iv.as_ptr() as usize, 16]
}

fn enc_init(s: u32, key: u32) -> u32 {
    let mut m = cbc(&IV);
    C_EncryptInit(s, m.as_mut_ptr() as *mut u8, key)
}

fn dec_init(s: u32, key: u32) -> u32 {
    let mut m = cbc(&IV);
    C_DecryptInit(s, m.as_mut_ptr() as *mut u8, key)
}

/// One-shot encrypt into a caller buffer; `Err(rv)` on failure.
fn encrypt(s: u32, data: &[u8]) -> Result<Vec<u8>, u32> {
    let mut input = data.to_vec();
    let mut out = vec![0u8; data.len() + 16];
    let mut len = out.len() as u32;
    let rv = C_Encrypt(s, input.as_mut_ptr(), input.len() as u32, out.as_mut_ptr(), &mut len);
    if rv != CKR_OK {
        return Err(rv);
    }
    out.truncate(len as usize);
    Ok(out)
}

fn decrypt(s: u32, data: &[u8]) -> Result<Vec<u8>, u32> {
    let mut input = data.to_vec();
    let mut out = vec![0u8; data.len() + 16];
    let mut len = out.len() as u32;
    let rv = C_Decrypt(s, input.as_mut_ptr(), input.len() as u32, out.as_mut_ptr(), &mut len);
    if rv != CKR_OK {
        return Err(rv);
    }
    out.truncate(len as usize);
    Ok(out)
}

fn multipart_encrypt(s: u32, data: &[u8], split: usize) -> Result<Vec<u8>, u32> {
    let mut out = Vec::new();
    for part in [&data[..split], &data[split..]] {
        let mut p = part.to_vec();
        let mut buf = vec![0u8; part.len() + 32];
        let mut len = buf.len() as u32;
        let rv = C_EncryptUpdate(s, p.as_mut_ptr(), p.len() as u32, buf.as_mut_ptr(), &mut len);
        if rv != CKR_OK {
            return Err(rv);
        }
        out.extend_from_slice(&buf[..len as usize]);
    }
    let mut buf = vec![0u8; 32];
    let mut len = buf.len() as u32;
    let rv = C_EncryptFinal(s, buf.as_mut_ptr(), &mut len);
    if rv != CKR_OK {
        return Err(rv);
    }
    out.extend_from_slice(&buf[..len as usize]);
    Ok(out)
}

fn sha256(s: u32, data: &[u8]) -> Result<Vec<u8>, u32> {
    let mut m: [usize; 3] = [CKM_SHA256 as usize, 0, 0];
    let rv = C_DigestInit(s, m.as_mut_ptr() as *mut u8);
    if rv != CKR_OK {
        return Err(rv);
    }
    let mut input = data.to_vec();
    let mut out = [0u8; 32];
    let mut len = 32u32;
    let rv = C_Digest(s, input.as_mut_ptr(), input.len() as u32, out.as_mut_ptr(), &mut len);
    if rv != CKR_OK {
        return Err(rv);
    }
    Ok(out[..len as usize].to_vec())
}

const DATA: [u8; 64] = [0x5A; 64];

// ── condition 1: operation-state semantics, per session ─────────────────

#[test]
fn operation_state_error_codes_are_unchanged() {
    let _guard = test_lock::acquire();
    setup();
    // No active op.
    assert_eq!(encrypt(S_A, &DATA), Err(CKR_OPERATION_NOT_INITIALIZED));
    // Init, then a second Init on the same session.
    assert_eq!(enc_init(S_A, KEY_A), CKR_OK);
    assert_eq!(enc_init(S_A, KEY_A), CKR_OPERATION_ACTIVE);
    // The §5.2 size query keeps the operation.
    let mut input = DATA.to_vec();
    let mut need = 0u32;
    assert_eq!(C_Encrypt(S_A, input.as_mut_ptr(), 64, std::ptr::null_mut(), &mut need), CKR_OK);
    assert_eq!(need, 64);
    // CKR_BUFFER_TOO_SMALL keeps it too.
    let mut small = [0u8; 8];
    let mut len = 8u32;
    assert_eq!(C_Encrypt(S_A, input.as_mut_ptr(), 64, small.as_mut_ptr(), &mut len), CKR_BUFFER_TOO_SMALL);
    // The real call consumes it.
    let ct = encrypt(S_A, &DATA).expect("encrypt");
    assert_eq!(ct.len(), 64);
    assert_eq!(encrypt(S_A, &DATA), Err(CKR_OPERATION_NOT_INITIALIZED));
    // A one-shot C_Encrypt after C_EncryptUpdate is CKR_OPERATION_ACTIVE and
    // leaves the streaming op usable.
    assert_eq!(enc_init(S_A, KEY_A), CKR_OK);
    let mut part = DATA[..16].to_vec();
    let mut buf = [0u8; 64];
    let mut blen = 64u32;
    assert_eq!(C_EncryptUpdate(S_A, part.as_mut_ptr(), 16, buf.as_mut_ptr(), &mut blen), CKR_OK);
    assert_eq!(encrypt(S_A, &DATA), Err(CKR_OPERATION_ACTIVE));
    let mut fin = [0u8; 32];
    let mut flen = 32u32;
    assert_eq!(C_EncryptFinal(S_A, fin.as_mut_ptr(), &mut flen), CKR_OK);
    // Round trip through decrypt.
    assert_eq!(dec_init(S_A, KEY_A), CKR_OK);
    assert_eq!(decrypt(S_A, &ct), Ok(DATA.to_vec()));
}

#[test]
fn one_sessions_operation_is_invisible_to_another() {
    let _guard = test_lock::acquire();
    setup();
    assert_eq!(enc_init(S_A, KEY_A), CKR_OK);
    assert_eq!(encrypt(S_B, &DATA), Err(CKR_OPERATION_NOT_INITIALIZED));
    assert_eq!(enc_init(S_B, KEY_B), CKR_OK);
    let a = encrypt(S_A, &DATA).unwrap();
    let b = encrypt(S_B, &DATA).unwrap();
    assert_ne!(a, b, "different keys must give different ciphertexts");
    // Consuming A's op left B's alone and vice versa.
    assert_eq!(encrypt(S_A, &DATA), Err(CKR_OPERATION_NOT_INITIALIZED));
    assert_eq!(encrypt(S_B, &DATA), Err(CKR_OPERATION_NOT_INITIALIZED));
}

#[test]
fn close_session_clears_only_that_sessions_state() {
    let _guard = test_lock::acquire();
    setup();
    assert_eq!(enc_init(S_A, KEY_A), CKR_OK);
    assert_eq!(enc_init(S_B, KEY_B), CKR_OK);
    assert_eq!(C_CloseSession(S_A), CKR_OK);
    assert!(!ENCRYPT_STATE.shard(S_A).contains_key(&S_A));
    assert!(ENCRYPT_STATE.shard(S_B).contains_key(&S_B), "B's op must survive A's close");
    assert!(encrypt(S_B, &DATA).is_ok());
    assert_eq!(encrypt(S_A, &DATA), Err(CKR_SESSION_HANDLE_INVALID));
}

#[test]
fn close_all_sessions_clears_every_session_on_the_slot() {
    let _guard = test_lock::acquire();
    setup();
    // Enough sessions to land in many different shards.
    let many: Vec<u32> = (0..200u32).map(|i| 0xA310_0000 + i).collect();
    for &h in &many {
        open(h);
        assert_eq!(enc_init(h, KEY_A), CKR_OK);
        assert_eq!(sha256_init(h), CKR_OK);
    }
    assert_eq!(C_CloseAllSessions(SLOT), CKR_OK);
    for &h in &many {
        assert!(!SESSIONS.shard(h).contains_key(&h));
        assert!(!ENCRYPT_STATE.shard(h).contains_key(&h));
        assert!(!DIGEST_STATE.shard(h).contains_key(&h));
    }
    assert!(!SESSIONS.any(|_, ss| ss.slot_id == SLOT), "no session may remain on the slot");
}

fn sha256_init(s: u32) -> u32 {
    let mut m: [usize; 3] = [CKM_SHA256 as usize, 0, 0];
    C_DigestInit(s, m.as_mut_ptr() as *mut u8)
}

#[test]
fn finalize_clears_every_table() {
    let _guard = test_lock::acquire();
    setup();
    for h in [S_A, S_B] {
        assert_eq!(enc_init(h, KEY_A), CKR_OK);
        assert_eq!(dec_init(h, KEY_A), CKR_OK);
        assert_eq!(sha256_init(h), CKR_OK);
    }
    assert_eq!(C_Finalize(std::ptr::null_mut()), CKR_OK);
    assert_eq!(SESSIONS.len(), 0);
    assert_eq!(ENCRYPT_STATE.len(), 0);
    assert_eq!(DECRYPT_STATE.len(), 0);
    assert_eq!(DIGEST_STATE.len(), 0);
    crate::state::set_initialized(true);
}

// ── condition 2: isolation and stress across threads ────────────────────

/// Two sessions on two threads, different keys, many interleaved
/// Init + op pairs: each thread must always get exactly its own result.
#[test]
fn two_sessions_on_two_threads_never_see_each_others_state() {
    let _guard = test_lock::acquire();
    setup();
    assert_eq!(enc_init(S_A, KEY_A), CKR_OK);
    let want_a = encrypt(S_A, &DATA).unwrap();
    assert_eq!(enc_init(S_B, KEY_B), CKR_OK);
    let want_b = encrypt(S_B, &DATA).unwrap();
    let run = |s: u32, key: u32, want: Vec<u8>| {
        std::thread::spawn(move || {
            for i in 0..2000 {
                assert_eq!(enc_init(s, key), CKR_OK, "init {i}");
                assert_eq!(encrypt(s, &DATA).as_deref(), Ok(&want[..]), "iteration {i}");
            }
        })
    };
    let ta = run(S_A, KEY_A, want_a);
    let tb = run(S_B, KEY_B, want_b);
    ta.join().expect("thread A");
    tb.join().expect("thread B");
}

/// N threads × M sessions, each session interleaving one-shot encrypt,
/// multipart encrypt, digest and close/reopen, for 50 rounds. Every result is
/// compared with a single-threaded reference, and every error code must be
/// one the sequence allows.
#[test]
fn stress_threads_by_sessions_interleaved_ops_and_close_50_rounds() {
    let _guard = test_lock::acquire();
    setup();
    const THREADS: u32 = 8;
    const SESSIONS_PER: u32 = 4;
    // References, single-threaded.
    assert_eq!(enc_init(S_A, KEY_A), CKR_OK);
    let one_shot = encrypt(S_A, &DATA).unwrap();
    assert_eq!(enc_init(S_A, KEY_A), CKR_OK);
    let multi = multipart_encrypt(S_A, &DATA, 16).unwrap();
    assert_eq!(multi, one_shot, "multipart and one-shot CBC agree");
    let digest = sha256(S_A, &DATA).unwrap();
    for round in 0..50 {
        let handles: Vec<_> = (0..THREADS)
            .map(|t| {
                let (one_shot, digest) = (one_shot.clone(), digest.clone());
                std::thread::spawn(move || {
                    let sessions: Vec<u32> =
                        (0..SESSIONS_PER).map(|k| 0xA320_0000 + t * 256 + k).collect();
                    for &s in &sessions {
                        open(s);
                    }
                    for step in 0..40u32 {
                        for &s in &sessions {
                            match (step + s) % 4 {
                                0 => {
                                    assert_eq!(enc_init(s, KEY_A), CKR_OK);
                                    assert_eq!(encrypt(s, &DATA).as_deref(), Ok(&one_shot[..]));
                                }
                                1 => {
                                    assert_eq!(enc_init(s, KEY_A), CKR_OK);
                                    assert_eq!(multipart_encrypt(s, &DATA, 32).as_deref(), Ok(&one_shot[..]));
                                }
                                2 => assert_eq!(sha256(s, &DATA).as_deref(), Ok(&digest[..])),
                                _ => {
                                    // Close with an operation in flight, then reopen.
                                    assert_eq!(enc_init(s, KEY_A), CKR_OK);
                                    assert_eq!(C_CloseSession(s), CKR_OK);
                                    assert_eq!(encrypt(s, &DATA), Err(CKR_SESSION_HANDLE_INVALID));
                                    open(s);
                                    assert_eq!(encrypt(s, &DATA), Err(CKR_OPERATION_NOT_INITIALIZED));
                                }
                            }
                        }
                    }
                    for &s in &sessions {
                        assert_eq!(C_CloseSession(s), CKR_OK);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap_or_else(|_| panic!("a worker panicked in round {round}"));
        }
    }
}

// ── condition 3: the key-schedule cache is never stale ─────────────────

#[test]
fn a_key_destroyed_after_init_is_not_served_from_the_cache() {
    let _guard = test_lock::acquire();
    setup();
    const K: u32 = 0xA300_1003;
    put_aes_key(K, &[0x33; 16]);
    assert_eq!(enc_init(S_A, K), CKR_OK);
    OBJECTS.with(|o| o.borrow_mut().remove(&K));
    // Same answer as before the cache existed: the key is re-read and gone.
    assert_eq!(encrypt(S_A, &DATA), Err(CKR_ARGUMENTS_BAD));
}

#[test]
fn a_key_changed_after_init_encrypts_under_the_new_value() {
    let _guard = test_lock::acquire();
    setup();
    const K: u32 = 0xA300_1004;
    put_aes_key(K, &[0x44; 16]);
    assert_eq!(enc_init(S_A, K), CKR_OK);
    let old = encrypt(S_A, &DATA).unwrap();
    assert_eq!(enc_init(S_A, K), CKR_OK);
    // Change the key value after Init (a write to the object table).
    put_aes_key(K, &[0x55; 16]);
    let after = encrypt(S_A, &DATA).unwrap();
    assert_ne!(after, old, "the operation must not use the schedule cached from the old value");
    assert_eq!(enc_init(S_A, K), CKR_OK);
    assert_eq!(encrypt(S_A, &DATA).unwrap(), after, "and must match a fresh Init under the new value");
}

#[test]
fn any_object_write_bumps_the_epoch_and_reads_do_not() {
    let _guard = test_lock::acquire();
    setup();
    let e0 = crate::state::object_epoch();
    let _ = get_object_value(KEY_A);
    assert_eq!(crate::state::object_epoch(), e0, "a read must not invalidate caches");
    put_aes_key(0xA300_1005, &[0x66; 16]);
    assert!(crate::state::object_epoch() > e0, "a write must invalidate every cache");
}

#[test]
fn the_cache_is_used_when_nothing_changed() {
    let _guard = test_lock::acquire();
    setup();
    assert_eq!(enc_init(S_A, KEY_A), CKR_OK);
    let cached = ENCRYPT_STATE
        .shard(S_A)
        .get(&S_A)
        .map(|c| c.aes_key.as_ref().map(|(e, _)| *e));
    assert_eq!(cached, Some(Some(crate::state::object_epoch())), "Init cached the schedule at the current epoch");
    // The key bytes are then not needed: the op succeeds and matches a
    // non-cached run (CKM_AES_CBC_PAD is uncached; compare via decrypt).
    let ct = encrypt(S_A, &DATA).unwrap();
    assert_eq!(dec_init(S_A, KEY_A), CKR_OK);
    assert_eq!(decrypt(S_A, &ct), Ok(DATA.to_vec()));
}

// ── A3 part 2: the per-thread object read cache ─────────────────────────

/// A write on thread A must be visible to thread B's next lookup, although B
/// has the old attributes cached.
#[test]
fn a_write_on_one_thread_invalidates_another_threads_cached_attributes() {
    let _guard = test_lock::acquire();
    setup();
    const K: u32 = 0xA300_1101;
    put_aes_key(K, &[0x61; 16]);
    let (to_b, b_rx) = std::sync::mpsc::channel::<()>();
    let (to_main, main_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let b = std::thread::spawn(move || {
        // Warm this thread's cache with the old value.
        to_main.send(get_object_value(K).unwrap()).unwrap();
        b_rx.recv().unwrap(); // wait for the write on the main thread
        to_main.send(get_object_value(K).unwrap()).unwrap();
    });
    assert_eq!(main_rx.recv().unwrap(), vec![0x61; 16]);
    put_aes_key(K, &[0x62; 16]); // write on this thread
    to_b.send(()).unwrap();
    assert_eq!(main_rx.recv().unwrap(), vec![0x62; 16], "B must not serve its cached old value");
    b.join().unwrap();
}

/// An object destroyed while cached is gone on every thread's next lookup,
/// and an operation using it fails exactly as before.
#[test]
fn an_object_destroyed_while_cached_is_gone_everywhere() {
    let _guard = test_lock::acquire();
    setup();
    const K: u32 = 0xA300_1102;
    put_aes_key(K, &[0x71; 16]);
    assert!(get_object_value(K).is_some()); // cached on this thread
    let other = std::thread::spawn(move || get_object_value(K).is_some());
    assert!(other.join().unwrap(), "cached on the other thread too");
    OBJECTS.with(|o| o.borrow_mut().remove(&K));
    assert!(get_object_value(K).is_none(), "this thread's cache must not serve a destroyed key");
    let other = std::thread::spawn(move || get_object_value(K).is_none());
    assert!(other.join().unwrap());
    assert_eq!(enc_init(S_A, K), CKR_KEY_HANDLE_INVALID);
}

/// The cache holds at most OBJ_CACHE_MAX entries per thread.
#[test]
fn the_object_cache_is_bounded_per_thread() {
    let _guard = test_lock::acquire();
    setup();
    let base = 0xA310_5000u32;
    let n = (crate::state::OBJ_CACHE_MAX * 3) as u32;
    for i in 0..n {
        put_aes_key(base + i, &[(i % 251) as u8; 16]);
    }
    std::thread::spawn(move || {
        for i in 0..n {
            assert_eq!(get_object_value(base + i).unwrap(), vec![(i % 251) as u8; 16]);
            assert!(crate::state::object_cache_len() <= crate::state::OBJ_CACHE_MAX);
        }
    })
    .join()
    .unwrap();
    OBJECTS.with(|o| {
        let mut m = o.borrow_mut();
        for i in 0..n {
            m.remove(&(base + i));
        }
    });
}

/// Reads alone keep the cache warm: repeated lookups do not touch the lock
/// (the epoch stays put) and return the same value.
#[test]
fn repeated_reads_are_served_without_a_write() {
    let _guard = test_lock::acquire();
    setup();
    let e = crate::state::object_epoch();
    for _ in 0..1000 {
        assert_eq!(get_object_attr_u32(KEY_A, CKA_KEY_TYPE), Some(CKK_AES));
    }
    assert_eq!(crate::state::object_epoch(), e);
    assert!(crate::state::object_cache_len() >= 1);
}

/// A handle looked up while missing is cached as missing; creating it on
/// another thread (a write) makes it visible here on the next lookup.
#[test]
fn a_create_on_another_thread_is_seen_past_a_cached_miss() {
    let _guard = test_lock::acquire();
    setup();
    const K: u32 = 0xA300_1103;
    OBJECTS.with(|o| o.borrow_mut().remove(&K));
    assert!(get_object_attr_u32(K, CKA_KEY_TYPE).is_none()); // cached miss
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let b2 = barrier.clone();
    let t = std::thread::spawn(move || {
        put_aes_key(K, &[0x81; 16]);
        b2.wait();
    });
    barrier.wait();
    t.join().unwrap();
    assert_eq!(get_object_attr_u32(K, CKA_KEY_TYPE), Some(CKK_AES));
}

/// No secret attribute ever enters the per-thread cache, while the secret
/// getters still return the value (read under the lock).
#[test]
fn secrets_never_enter_the_thread_cache() {
    let _guard = test_lock::acquire();
    setup();
    assert_eq!(get_object_attr_u32(KEY_A, CKA_KEY_TYPE), Some(CKK_AES)); // populate
    assert_eq!(crate::state::object_cache_has_attr(KEY_A, CKA_KEY_TYPE), Some(true));
    assert_eq!(crate::state::object_cache_has_attr(KEY_A, CKA_VALUE), Some(false), "CKA_VALUE must be stripped");
    assert_eq!(get_object_value(KEY_A), Some(vec![0x11; 16]), "the value still reads, under the lock");
    assert_eq!(get_object_attr_bytes(KEY_A, CKA_VALUE), Some(vec![0x11; 16]));
    assert!(crate::state::is_secret_attr(CKA_PRIVATE_EXPONENT) && crate::state::is_secret_attr(CKA_SEED));
    assert!(crate::state::is_secret_attr(CKA_BIP32_CHAIN_CODE));
    assert!(crate::state::is_secret_attr(CKA_PRIV_STATEFUL_KEY_STATE));
    assert!(!crate::state::is_secret_attr(CKA_PRIV_PARAM_SET), "public vendor attributes stay cacheable");
}

/// Login, logout and C_Finalize invalidate every epoch cache.
#[test]
fn login_logout_and_finalize_bump_the_epoch() {
    let _guard = test_lock::acquire();
    setup();
    let e = crate::state::object_epoch();
    let mut pin = *b"000000";
    let _ = C_Login(S_A, CKU_USER, pin.as_mut_ptr(), 6);
    let e1 = crate::state::object_epoch();
    assert!(e1 > e, "C_Login must bump");
    let _ = C_Logout(S_A);
    let e2 = crate::state::object_epoch();
    assert!(e2 > e1, "C_Logout must bump");
    assert_eq!(C_Finalize(std::ptr::null_mut()), CKR_OK);
    assert!(crate::state::object_epoch() > e2, "C_Finalize must bump and never reset");
    crate::state::set_initialized(true);
}

/// A long-lived worker thread keeps no stale view across C_Finalize and a
/// re-initialised token that reuses the handle.
#[test]
fn finalize_and_reinit_are_seen_by_a_persistent_thread() {
    let _guard = test_lock::acquire();
    setup();
    const K: u32 = 0xA300_1104;
    put_aes_key(K, &[0x91; 16]);
    let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
    let (res_tx, res_rx) = std::sync::mpsc::channel::<Option<u32>>();
    let worker = std::thread::spawn(move || {
        res_tx.send(get_object_attr_u32(K, CKA_VALUE_LEN)).unwrap();
        go_rx.recv().unwrap();
        res_tx.send(get_object_attr_u32(K, CKA_VALUE_LEN)).unwrap();
    });
    assert_eq!(res_rx.recv().unwrap(), Some(16));
    assert_eq!(C_Finalize(std::ptr::null_mut()), CKR_OK);
    setup();
    put_aes_key(K, &[0x92; 32]); // same handle, new object
    go_tx.send(()).unwrap();
    assert_eq!(res_rx.recv().unwrap(), Some(32), "the worker must see the re-created object");
    worker.join().unwrap();
}

/// At a saturated epoch every epoch cache is off: nothing is cached and the
/// Init-time key schedule is not used, so correctness can't depend on an
/// epoch that no longer moves.
#[test]
fn a_saturated_epoch_disables_every_cache() {
    let _guard = test_lock::acquire();
    setup();
    let before = crate::state::object_epoch();
    crate::state::set_object_epoch_for_test(u64::MAX - 1);
    put_aes_key(0xA300_1105, &[0xA1; 16]); // write → MAX
    assert_eq!(crate::state::object_epoch(), u64::MAX);
    put_aes_key(0xA300_1106, &[0xA2; 16]); // checked increment: stays at MAX
    assert_eq!(crate::state::object_epoch(), u64::MAX);
    assert_eq!(get_object_attr_u32(0xA300_1105, CKA_KEY_TYPE), Some(CKK_AES));
    assert_eq!(crate::state::object_cache_has_attr(0xA300_1105, CKA_KEY_TYPE), None, "nothing cached at MAX");
    assert_eq!(enc_init(S_A, KEY_A), CKR_OK);
    let cached = ENCRYPT_STATE.shard(S_A).get(&S_A).map(|c| c.aes_key.is_some());
    assert_eq!(cached, Some(false), "no Init-time key schedule at MAX");
    assert!(encrypt(S_A, &DATA).is_ok());
    // Leave a fresh epoch above everything used before for later tests.
    crate::state::set_object_epoch_for_test(before + 1_000_000);
}

/// LRU: the most recently used entry survives eviction.
#[test]
fn the_object_cache_evicts_least_recently_used() {
    let _guard = test_lock::acquire();
    setup();
    let base = 0xA310_6000u32;
    let n = crate::state::OBJ_CACHE_MAX as u32;
    for i in 0..=n {
        put_aes_key(base + i, &[1; 16]);
    }
    std::thread::spawn(move || {
        for i in 0..n {
            assert!(get_object_attr_u32(base + i, CKA_KEY_TYPE).is_some()); // fill: base..base+n-1
        }
        assert!(get_object_attr_u32(base, CKA_KEY_TYPE).is_some()); // touch the oldest
        assert!(get_object_attr_u32(base + n, CKA_KEY_TYPE).is_some()); // forces one eviction
        assert_eq!(crate::state::object_cache_len(), crate::state::OBJ_CACHE_MAX);
        assert!(crate::state::object_cache_has_attr(base, CKA_KEY_TYPE).is_some(), "recently used survives");
        assert!(crate::state::object_cache_has_attr(base + 1, CKA_KEY_TYPE).is_none(), "least recently used evicted");
    })
    .join()
    .unwrap();
    OBJECTS.with(|o| {
        let mut m = o.borrow_mut();
        for i in 0..=n {
            m.remove(&(base + i));
        }
    });
}
