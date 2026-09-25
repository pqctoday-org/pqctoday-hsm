//! Expanded ML-DSA private-key cache for the signing path.
//!
//! ## Why
//!
//! `C_Sign` receives the private key as its FIPS 204 encoding. Before this
//! cache every ML-DSA signature decoded it (`skDecode` plus seventeen NTTs
//! for ML-DSA-65) and expanded the public matrix `Â = ExpandA(ρ)` (thirty
//! SHAKE128 rejection samplings) — work that depends on the key alone.
//! Measured in the `pqc-rust` container (opt-level s, the build the KV260 ran
//! on 2026-09-19), one ML-DSA-65 `C_SignInit` + 2× `C_Sign` with the
//! whole-signature accelerator simulated spent 36 µs decoding and 76 µs in
//! `ExpandA` out of 151 µs of host time; CPU-only signing spends the same
//! 112 µs of its 518 µs. Scaled to the A53 that is ~1.8 ms per signature.
//! See `examples/mldsa_hostpath_profile.rs`.
//!
//! ## What the key is
//!
//! Entries are keyed by SHA-256 over a domain tag, the parameter set and the
//! private-key encoding the caller passed — the same design as
//! `crypto::awslc_keycache`, for the same reasons:
//!
//! * the ML-DSA entry points receive key BYTES, not handles, from the
//!   PKCS#11 C ABI, `native::sign` and the KMIP server alike;
//! * it cannot become an access-control bypass: a hit requires already
//!   holding the private-key bytes, which requires having passed the
//!   engine's session/token isolation gate that produced them. Nothing is
//!   reachable through this map that was not already reachable by the
//!   caller, so session and tenant isolation are exactly what they were;
//! * two handles holding the same key share one expanded key, which is
//!   correct: same key, same expansion.
//!
//! Hashing the 4,032-byte ML-DSA-65 encoding costs a few microseconds on the
//! A53 (ARMv8 SHA-2 instructions) against the ~1.8 ms it saves.
//!
//! ## Lifetime and bound
//!
//! Entries hold decoded secret material (`s1`, `s2`, `t0` in the NTT
//! domain, `K`, `tr`) next to the public `Â`. They are zeroized when dropped
//! (`ExpandedPrivateKey` is `ZeroizeOnDrop`; an entry still in use by a
//! concurrent signature is zeroized when that signature releases it), and
//! the map is emptied wholesale:
//!
//! * on every PKCS#11 lifecycle event that ends a key's accessibility —
//!   `C_Finalize`, `C_Logout`, `C_CloseSession`, `C_CloseAllSessions`,
//!   `C_InitToken`, `C_DestroyObject`, `C_SetAttributeValue` and
//!   `native::object`'s destroy/set-attribute paths (the same call sites as
//!   the AWS-LC cache, through `ffi::drop_key_caches`);
//! * at process exit (and at unload of this library), from an `atexit`
//!   handler registered with the first entry.
//!
//! Correctness never depends on invalidation — only hygiene does.
//!
//! Size is bounded at [`MAX_ENTRIES`] with FIFO eviction: at most 32 keys,
//! i.e. at most ~1.5 MB for ML-DSA-65 (47 KB per key: 17 KB decoded secret +
//! 30 KB `Â`) and ~2.6 MB for ML-DSA-87 (81 KB per key).
//!
//! Signatures are byte-identical with or without the cache (fips204
//! `ExpandedPrivateKey` runs the same `Sign_internal` with `Â` supplied).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use fips204::traits::SerDes;
use sha2::{Digest, Sha256};

use crate::constants::{CKP_ML_DSA_44, CKP_ML_DSA_65, CKP_ML_DSA_87, CKR_KEY_TYPE_INCONSISTENT};

type KeyId = [u8; 32];

/// One expanded private key, per parameter set.
pub enum Expanded {
    P44(Box<fips204::ml_dsa_44::ExpandedPrivateKey>),
    P65(Box<fips204::ml_dsa_65::ExpandedPrivateKey>),
    P87(Box<fips204::ml_dsa_87::ExpandedPrivateKey>),
}

/// Resident expanded keys; past this, the oldest is dropped (and zeroized).
pub const MAX_ENTRIES: usize = 32;

struct Cache {
    map: HashMap<KeyId, Arc<Expanded>>,
    /// Insertion order, oldest first (FIFO: a safety bound, not a tuning knob).
    order: Vec<KeyId>,
}

fn cache() -> &'static Mutex<Cache> {
    static C: OnceLock<Mutex<Cache>> = OnceLock::new();
    C.get_or_init(|| {
        Mutex::new(Cache {
            map: HashMap::new(),
            order: Vec::new(),
        })
    })
}

fn locked() -> std::sync::MutexGuard<'static, Cache> {
    cache().lock().unwrap_or_else(|e| e.into_inner())
}

static HITS: AtomicU64 = AtomicU64::new(0);
static MISSES: AtomicU64 = AtomicU64::new(0);

/// `(hits, misses)` since process start (tests prove the cache is on the path).
pub fn stats() -> (u64, u64) {
    (HITS.load(Ordering::Relaxed), MISSES.load(Ordering::Relaxed))
}

fn key_id(ps: u32, sk: &[u8]) -> KeyId {
    let mut h = Sha256::new();
    h.update(b"pqctoday/mldsa-keycache/v1");
    h.update(ps.to_le_bytes());
    h.update(sk);
    h.finalize().into()
}

fn build(ps: u32, sk: &[u8]) -> Result<Expanded, u32> {
    macro_rules! expand {
        ($m:ident, $variant:ident) => {{
            let arr: &<fips204::$m::PrivateKey as SerDes>::ByteArray =
                sk.try_into().map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            let decoded = <fips204::$m::PrivateKey as SerDes>::try_from_bytes(*arr)
                .map_err(|_| CKR_KEY_TYPE_INCONSISTENT)?;
            Ok(Expanded::$variant(Box::new(fips204::$m::ExpandedPrivateKey::new(decoded))))
        }};
    }
    match ps {
        CKP_ML_DSA_44 => expand!(ml_dsa_44, P44),
        CKP_ML_DSA_65 | 0 => expand!(ml_dsa_65, P65),
        CKP_ML_DSA_87 => expand!(ml_dsa_87, P87),
        _ => Err(CKR_KEY_TYPE_INCONSISTENT),
    }
}

/// The expanded key for `(ps, sk)`, built on a miss. A malformed key is an
/// error and is never cached.
///
/// The build runs OUTSIDE the lock (hundreds of microseconds on the A53);
/// two threads racing the same cold key both build and one insert wins,
/// which wastes one expansion and is otherwise harmless.
pub fn get(ps: u32, sk: &[u8]) -> Result<Arc<Expanded>, u32> {
    #[cfg(all(feature = "hw-accel", target_os = "linux", target_arch = "aarch64"))]
    let started = pqc_hw::stage::start();
    let id = key_id(ps, sk);
    let hit = locked().map.get(&id).cloned();
    #[cfg(all(feature = "hw-accel", target_os = "linux", target_arch = "aarch64"))]
    pqc_hw::stage::end(pqc_hw::stage::Stage::ContextLookup, started);
    if let Some(hit) = hit {
        HITS.fetch_add(1, Ordering::Relaxed);
        return Ok(hit);
    }
    MISSES.fetch_add(1, Ordering::Relaxed);
    let built = Arc::new(build(ps, sk)?);
    register_exit_hook();
    let mut c = locked();
    if let Some(existing) = c.map.get(&id) {
        return Ok(Arc::clone(existing));
    }
    while c.order.len() >= MAX_ENTRIES {
        let oldest = c.order.remove(0);
        c.map.remove(&oldest);
    }
    c.order.push(id);
    c.map.insert(id, Arc::clone(&built));
    Ok(built)
}

/// Drop (and zeroize) every expanded key. Called from each PKCS#11 lifecycle
/// event that ends a key's accessibility — see the module doc. Idempotent.
pub fn clear() {
    let mut c = locked();
    c.map.clear();
    c.order.clear();
}

/// True when `(ps, sk)` is resident. Tests only.
pub fn contains(ps: u32, sk: &[u8]) -> bool {
    locked().map.contains_key(&key_id(ps, sk))
}

/// Number of resident keys. Tests only.
pub fn len() -> usize {
    locked().map.len()
}

fn register_exit_hook() {
    static REGISTERED: AtomicBool = AtomicBool::new(false);
    if !REGISTERED.swap(true, Ordering::SeqCst) {
        // SAFETY: registering a plain `extern "C" fn()` with libc's atexit;
        // inside a shared library glibc runs it at exit or at dlclose.
        unsafe {
            libc::atexit(clear_at_exit);
        }
    }
}

extern "C" fn clear_at_exit() {
    // Never block or unwind at exit: another thread may be mid-signature
    // holding the lock; its entries are then zeroized when they drop.
    let _ = std::panic::catch_unwind(|| {
        if let Ok(mut c) = cache().try_lock() {
            c.map.clear();
            c.order.clear();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use fips204::traits::{KeyGen, Signer};

    // The cache is process-global and other tests sign ML-DSA concurrently,
    // so each property is proved by allocation identity (`Arc::ptr_eq`) on a
    // key no other test uses, never by `len()`/`stats()` deltas — except the
    // eviction bound, which runs on a private `Cache`.

    fn a_key(seed: u8) -> Vec<u8> {
        let (_pk, sk) = fips204::ml_dsa_65::KG::keygen_from_seed(&[seed; 32]);
        sk.into_bytes().to_vec()
    }

    #[test]
    fn second_lookup_reuses_the_expanded_key() {
        let sk = a_key(201);
        let first = get(CKP_ML_DSA_65, &sk).unwrap();
        let second = get(CKP_ML_DSA_65, &sk).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn distinct_keys_and_parameter_sets_do_not_alias() {
        let (a, b) = (a_key(202), a_key(203));
        let ka = get(CKP_ML_DSA_65, &a).unwrap();
        let kb = get(CKP_ML_DSA_65, &b).unwrap();
        assert!(!Arc::ptr_eq(&ka, &kb));
        // The same bytes under another parameter set are not a valid key.
        assert_eq!(get(CKP_ML_DSA_44, &a).err(), Some(CKR_KEY_TYPE_INCONSISTENT));
    }

    #[test]
    fn clear_forces_a_rebuild() {
        let sk = a_key(204);
        let before = get(CKP_ML_DSA_65, &sk).unwrap();
        clear();
        let after = get(CKP_ML_DSA_65, &sk).unwrap();
        assert!(!Arc::ptr_eq(&before, &after));
    }

    #[test]
    fn malformed_keys_are_rejected_and_not_cached() {
        assert!(get(CKP_ML_DSA_65, &[0u8; 10]).is_err());
        assert!(get(CKP_ML_DSA_65, &[0u8; 10]).is_err());
        assert!(get(0xdead, &a_key(205)).is_err());
    }

    #[test]
    fn eviction_bounds_the_map() {
        let mut c = Cache { map: HashMap::new(), order: Vec::new() };
        let entry = Arc::new(build(CKP_ML_DSA_44, &{
            let (_pk, sk) = fips204::ml_dsa_44::KG::keygen_from_seed(&[1; 32]);
            sk.into_bytes().to_vec()
        })
        .unwrap());
        for i in 0..(MAX_ENTRIES + 5) {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            while c.order.len() >= MAX_ENTRIES {
                let oldest = c.order.remove(0);
                c.map.remove(&oldest);
            }
            c.order.push(id);
            c.map.insert(id, Arc::clone(&entry));
        }
        assert_eq!(c.map.len(), MAX_ENTRIES);
        assert_eq!(c.order.len(), MAX_ENTRIES);
    }

    /// Hygiene through the PKCS#11 lifecycle: a key signed through the C
    /// ABI is resident, and C_DestroyObject / C_Finalize drop it.
    #[test]
    fn destroy_and_finalize_drop_the_expanded_key() {
        use crate::constants::{CKM_ML_DSA, CKR_OK};
        use crate::ffi;
        use crate::native::{self, test_lock};
        let _guard = test_lock::acquire();
        let _ = native::finalize();
        native::init().unwrap();
        let session = native::bootstrap_default_token(0, "so", "user", "mldsa-cache").unwrap();
        // Deterministic signing: that variant always runs on fips204 (the
        // AWS-LC CPU path in crypto::awslc_pq takes hedged pure ML-DSA and
        // has its own key cache), so this test exercises this cache whether
        // or not the awslc-pq feature is on.
        // CK_SIGN_ADDITIONAL_CONTEXT { hedgeVariant, pContext, ulContextLen }.
        let param: [usize; 3] = [crate::constants::CKH_DETERMINISTIC_REQUIRED as usize, 0, 0];
        let sign = |handle: u32| {
            let mut mech: [usize; 3] = [
                CKM_ML_DSA as usize,
                param.as_ptr() as usize,
                std::mem::size_of_val(&param),
            ];
            assert_eq!(ffi::C_SignInit(session, mech.as_mut_ptr() as *mut u8, handle), CKR_OK);
            let mut data = b"lifecycle".to_vec();
            let mut signature = vec![0u8; 3309];
            let mut len = 3309u32;
            let rv = ffi::C_Sign(session, data.as_mut_ptr(), data.len() as u32, signature.as_mut_ptr(), &mut len);
            assert_eq!(rv, CKR_OK);
        };

        let (_pub_a, key_a) =
            native::generate_ml_dsa_keypair(session, CKP_ML_DSA_65, b"cache-a", "cache-a").unwrap();
        let bytes_a = crate::state::get_object_value(key_a).unwrap();
        sign(key_a);
        assert!(contains(CKP_ML_DSA_65, &bytes_a), "signing made the key resident");
        assert_eq!(ffi::C_DestroyObject(session, key_a), CKR_OK);
        assert!(!contains(CKP_ML_DSA_65, &bytes_a), "C_DestroyObject dropped it");

        let (_pub_b, key_b) =
            native::generate_ml_dsa_keypair(session, CKP_ML_DSA_65, b"cache-b", "cache-b").unwrap();
        let bytes_b = crate::state::get_object_value(key_b).unwrap();
        sign(key_b);
        assert!(contains(CKP_ML_DSA_65, &bytes_b));
        assert_eq!(ffi::C_Finalize(std::ptr::null_mut()), CKR_OK);
        assert!(!contains(CKP_ML_DSA_65, &bytes_b), "C_Finalize dropped it");
        let _ = native::init();
    }

    /// Zeroization: an expanded key is `ZeroizeOnDrop`, and after `clear()`
    /// the cache holds no reference, so the key is dropped (and zeroized) as
    /// soon as the last signer releases it — here, at once.
    #[test]
    fn clear_releases_the_key_so_it_is_zeroized() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<fips204::ml_dsa_65::ExpandedPrivateKey>();
        assert_zeroize_on_drop::<fips204::ml_dsa_44::ExpandedPrivateKey>();
        assert_zeroize_on_drop::<fips204::ml_dsa_87::ExpandedPrivateKey>();
        let sk = a_key(207);
        let entry = get(CKP_ML_DSA_65, &sk).unwrap();
        let weak = Arc::downgrade(&entry);
        drop(entry);
        assert!(weak.upgrade().is_some(), "resident while cached");
        clear();
        assert!(weak.upgrade().is_none(), "dropped (and zeroized) once cleared");
    }

    /// The cache changes speed and nothing else: an expanded key signs
    /// exactly as a freshly decoded one (deterministic variant).
    #[test]
    fn cached_and_fresh_keys_sign_identically() {
        let sk = a_key(206);
        let cached = get(CKP_ML_DSA_65, &sk).unwrap();
        let Expanded::P65(expanded) = &*cached else { panic!("ML-DSA-65") };
        let fresh = fips204::ml_dsa_65::PrivateKey::try_from_bytes(sk.try_into().unwrap()).unwrap();
        let a = fresh.try_sign_with_seed(&[0u8; 32], b"m", b"c").unwrap();
        let b = expanded.try_sign_with_seed(&[0u8; 32], b"m", b"c").unwrap();
        assert_eq!(a, b);
    }
}
