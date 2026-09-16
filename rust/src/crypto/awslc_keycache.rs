//! Parsed-private-key cache for the AWS-LC fast path (`crypto::awslc`).
//!
//! ## Why
//!
//! Every RSA private-key operation in `crypto::awslc` used to call
//! `from_pkcs8` on the caller's DER. Inside AWS-LC that is not a parse: it
//! also runs `RSA_check_key` (recomputing `n = p*q` and the CRT
//! relationships), builds three `BN_MONT_CTX`s for `n`, `p` and `q`, and
//! creates a fresh blinding factor — a modular inverse plus a modular
//! exponentiation — and then frees all of it again. OpenSSL's `speed`, and
//! every other HSM, keep the key object alive instead, so their blinding is
//! rebuilt once per 32 operations rather than once per operation.
//!
//! Measured on the FRDM-IMX95 (Cortex-A55 @ 1.8 GHz, one pinned core,
//! 2026-09-16), RSA-2048 PKCS#1 v1.5 sign, aws-lc-rs 1.18.0:
//!
//! | build | key parsed once | `from_pkcs8` per call | ratio |
//! |---|---|---|---|
//! | AWS-LC as shipped | 137.7 /s | 101.4 /s | 1.36x |
//! | AWS-LC on the scalar Montgomery path | 177.5 /s | 122.1 /s | 1.45x |
//!
//! The ratio grows as the kernel gets faster, because the per-call setup is
//! a fixed cost against a shrinking operation.
//!
//! ## What the key is
//!
//! Entries are keyed by SHA-256 of the PKCS#8 DER the caller passed, NOT by
//! object handle. That is deliberate:
//!
//! * The engine's RSA entry points (`crypto::handlers::sign_rsa` and the
//!   decrypt/unwrap helpers) receive key BYTES, not handles, and they are
//!   reached from the PKCS#11 C ABI, from `native::sign`, and from the KMIP
//!   server. Keying on the material caches all three without threading a
//!   handle through every call site.
//! * It cannot become an access-control bypass. A cache hit requires already
//!   holding the private-key bytes, which requires having passed the
//!   isolation gate that produced them. Nothing is reachable through this
//!   map that was not already reachable by the caller.
//! * Two handles holding the same key (a re-imported or copied object) share
//!   one parsed key, which is correct: same key, same Montgomery state.
//!
//! Hashing ~1.2 kB of DER costs about a microsecond on this core against a
//! ~5.6 ms signature, i.e. under 0.02 %.
//!
//! ## Lifetime
//!
//! The map holds private key material, so it is emptied wholesale on every
//! PKCS#11 lifecycle event that ends a key's accessibility: `C_Finalize`,
//! `C_Logout`, `C_CloseSession`, `C_CloseAllSessions`, `C_InitToken`,
//! `C_DestroyObject`, `C_SetAttributeValue`, and `native::object`'s own
//! destroy/set-attribute paths. Clearing everything rather than one entry
//! keeps the invalidation argument trivially auditable; these events are
//! rare next to signatures. Correctness never depends on invalidation (see
//! above) — only hygiene does.
//!
//! Size is bounded at [`MAX_ENTRIES`] with FIFO eviction, so a workload that
//! streams distinct keys cannot grow the process without limit.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use aws_lc_rs::rsa;
use sha2::{Digest, Sha256};

/// SHA-256 of the caller's PKCS#8 DER, domain-separated.
type KeyId = [u8; 32];

/// The three AWS-LC private-key views the fast path uses. Each is built on
/// first use of that operation, so a sign-only key never constructs a
/// decrypting view and vice versa.
#[derive(Default)]
struct Entry {
    signer: Option<Arc<rsa::KeyPair>>,
    oaep: Option<Arc<rsa::OaepPrivateDecryptingKey>>,
    pkcs1: Option<Arc<rsa::Pkcs1PrivateDecryptingKey>>,
}

/// Resident parsed keys. 64 RSA keys is a few hundred kB and far more than
/// any tenant count this engine serves; past it, the oldest is dropped.
pub const MAX_ENTRIES: usize = 64;

struct Cache {
    map: HashMap<KeyId, Entry>,
    /// Insertion order, oldest first. FIFO rather than true LRU: eviction is
    /// a safety bound, not a tuning knob, and a real LRU would need a touch
    /// on every hit (a write lock on the hot path) to buy nothing here.
    order: Vec<KeyId>,
}

impl Cache {
    fn ensure_slot(&mut self, id: KeyId) {
        if self.map.contains_key(&id) {
            return;
        }
        while self.order.len() >= MAX_ENTRIES {
            let oldest = self.order.remove(0);
            self.map.remove(&oldest);
        }
        self.order.push(id);
        self.map.insert(id, Entry::default());
    }
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

/// Lock helper matching `state::GlobalState`'s poisoning policy: a panic in
/// one thread must not wedge the engine's crypto for every other thread.
fn locked() -> std::sync::MutexGuard<'static, Cache> {
    cache().lock().unwrap_or_else(|e| e.into_inner())
}

static HITS: AtomicU64 = AtomicU64::new(0);
static MISSES: AtomicU64 = AtomicU64::new(0);

/// `(hits, misses)` since process start — used by the tests to prove the
/// cache is actually on the path rather than silently missing every time.
pub fn stats() -> (u64, u64) {
    (HITS.load(Ordering::Relaxed), MISSES.load(Ordering::Relaxed))
}

fn key_id(sk_pkcs8: &[u8]) -> KeyId {
    let mut h = Sha256::new();
    h.update(b"pqctoday/awslc-keycache/v1");
    h.update(sk_pkcs8);
    h.finalize().into()
}

/// Generate `fn $name(sk_pkcs8) -> Option<Arc<$ty>>` that returns the cached
/// view, building it with `$build` on a miss.
///
/// The build runs OUTSIDE the lock: constructing an RSA private key is
/// milliseconds, and holding a global mutex across it would serialise the
/// first touch of every key across all threads. Two threads racing the same
/// cold key both build and the second insert wins; that wastes one parse and
/// is otherwise harmless, which is the usual trade for this pattern.
macro_rules! cached_view {
    ($name:ident, $field:ident, $ty:ty, $build:expr) => {
        pub fn $name(sk_pkcs8: &[u8]) -> Option<Arc<$ty>> {
            let id = key_id(sk_pkcs8);
            if let Some(hit) = locked().map.get(&id).and_then(|e| e.$field.clone()) {
                HITS.fetch_add(1, Ordering::Relaxed);
                return Some(hit);
            }
            MISSES.fetch_add(1, Ordering::Relaxed);
            let built: Arc<$ty> = Arc::new($build(sk_pkcs8)?);
            let mut c = locked();
            c.ensure_slot(id);
            if let Some(e) = c.map.get_mut(&id) {
                e.$field = Some(Arc::clone(&built));
            }
            Some(built)
        }
    };
}

cached_view!(signer, signer, rsa::KeyPair, |b| rsa::KeyPair::from_pkcs8(b).ok());

cached_view!(oaep, oaep, rsa::OaepPrivateDecryptingKey, |b| {
    rsa::PrivateDecryptingKey::from_pkcs8(b)
        .ok()
        .and_then(|k| rsa::OaepPrivateDecryptingKey::new(k).ok())
});

cached_view!(pkcs1, pkcs1, rsa::Pkcs1PrivateDecryptingKey, |b| {
    rsa::PrivateDecryptingKey::from_pkcs8(b)
        .ok()
        .and_then(|k| rsa::Pkcs1PrivateDecryptingKey::new(k).ok())
});

/// Drop every parsed key. Called from each PKCS#11 lifecycle event that ends
/// a key's accessibility — see the module doc. Cheap and idempotent.
pub fn clear() {
    let mut c = locked();
    c.map.clear();
    c.order.clear();
}

/// Number of resident keys. Tests only.
pub fn len() -> usize {
    locked().map.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE ON TEST DESIGN: the cache is process-global and `cargo test` runs
    // these in parallel with every other test that signs or decrypts RSA, so
    // any assertion on `len()` or on `stats()` deltas is inherently racy.
    // Every property below is therefore proved by ALLOCATION IDENTITY
    // (`Arc::ptr_eq`): if two lookups return the same allocation the second
    // one came from the map, and if they return different allocations it was
    // rebuilt. That is exactly the property under test and it cannot be
    // perturbed by a concurrent test touching a different key.

    fn a_key() -> Vec<u8> {
        use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
        let kp = rsa::KeyPair::generate(rsa::KeySize::Rsa2048).expect("keygen");
        AsDer::<Pkcs8V1Der>::as_der(&kp).expect("der").as_ref().to_vec()
    }

    /// The whole point: a second lookup of the same key must reuse the parsed
    /// object rather than running `RSA_check_key` and rebuilding the blinding.
    #[test]
    fn second_lookup_of_the_same_key_reuses_the_parsed_object() {
        let der = a_key();
        let first = signer(&der).expect("first build");
        let second = signer(&der).expect("second lookup");
        assert!(Arc::ptr_eq(&first, &second), "second lookup must hit the cache");
    }

    /// Each view is cached independently but under one key entry, and each is
    /// stable across lookups.
    #[test]
    fn every_view_is_cached_independently() {
        let der = a_key();
        let s1 = signer(&der).expect("signer");
        let o1 = oaep(&der).expect("oaep");
        let p1 = pkcs1(&der).expect("pkcs1");
        assert!(Arc::ptr_eq(&s1, &signer(&der).unwrap()), "signer view cached");
        assert!(Arc::ptr_eq(&o1, &oaep(&der).unwrap()), "oaep view cached");
        assert!(Arc::ptr_eq(&p1, &pkcs1(&der).unwrap()), "pkcs1 view cached");
    }

    /// Distinct keys must not alias — this is the property that makes keying
    /// on the key material (rather than on an object handle) safe.
    #[test]
    fn distinct_keys_do_not_alias() {
        let (a, b) = (a_key(), a_key());
        assert_ne!(a, b, "two generated keys differ");
        let ka = signer(&a).expect("a");
        let kb = signer(&b).expect("b");
        assert!(!Arc::ptr_eq(&ka, &kb), "different keys must not share an entry");
        assert!(Arc::ptr_eq(&ka, &signer(&a).unwrap()), "a still maps to a");
        assert!(Arc::ptr_eq(&kb, &signer(&b).unwrap()), "b still maps to b");
    }

    /// Hygiene: after a lifecycle event the key material must be gone, so the
    /// next use has to rebuild it from the caller's bytes.
    #[test]
    fn clear_forces_a_rebuild() {
        let der = a_key();
        let before = signer(&der).expect("build");
        clear();
        let after = signer(&der).expect("rebuild");
        assert!(!Arc::ptr_eq(&before, &after), "clear() must drop the parsed key");
    }

    /// A malformed key must not be cached and must keep reporting failure; a
    /// remembered failure would turn a transient into a permanent error.
    #[test]
    fn garbage_is_not_cached() {
        let junk = vec![0x30u8, 0x03, 0x02, 0x01, 0x00];
        assert!(signer(&junk).is_none());
        assert!(signer(&junk).is_none(), "still fails on the second call");
        assert!(oaep(&junk).is_none());
        assert!(pkcs1(&junk).is_none());
    }

    /// The size bound must actually bind, or a workload that streams distinct
    /// keys grows the process without limit. Exercised on a private `Cache`
    /// so the assertion is immune to concurrent tests, and with synthetic ids
    /// because `ensure_slot` is the code under test, not the DER parser.
    #[test]
    fn eviction_bounds_the_map() {
        let mut c = Cache { map: HashMap::new(), order: Vec::new() };
        let id_of = |i: usize| {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            id
        };
        for i in 0..(MAX_ENTRIES + 10) {
            c.ensure_slot(id_of(i));
        }
        assert_eq!(c.map.len(), MAX_ENTRIES, "map is capped");
        assert_eq!(c.order.len(), MAX_ENTRIES, "order tracks the map");
        assert!(!c.map.contains_key(&id_of(0)), "oldest entry was evicted");
        assert!(c.map.contains_key(&id_of(MAX_ENTRIES + 9)), "newest entry is resident");
        // Re-touching a resident id must not duplicate it in the order list.
        let n = c.order.len();
        c.ensure_slot(id_of(MAX_ENTRIES + 9));
        assert_eq!(c.order.len(), n, "re-touch does not re-insert");
    }

    /// One parsed key shared across threads is the concurrency contract the
    /// PKCS#11 C ABI needs: aws-lc-rs marks these types Send+Sync and AWS-LC
    /// locks its own blinding cache internally.
    #[test]
    fn cached_key_signs_concurrently() {
        use aws_lc_rs::rand::SystemRandom;
        use aws_lc_rs::signature::RSA_PKCS1_SHA256;
        let der = a_key();
        let kp = signer(&der).expect("build");
        let threads: Vec<_> = (0..4)
            .map(|i| {
                let kp = Arc::clone(&kp);
                std::thread::spawn(move || {
                    let mut sig = vec![0u8; kp.public_modulus_len()];
                    for _ in 0..3 {
                        kp.sign(&RSA_PKCS1_SHA256, &SystemRandom::new(), &[i as u8], &mut sig)
                            .expect("sign");
                    }
                    sig
                })
            })
            .collect();
        for t in threads {
            let sig = t.join().expect("thread");
            assert!(sig.iter().any(|&b| b != 0));
        }
    }

    /// A cached key must produce signatures a fresh parse verifies, i.e. the
    /// cache changes speed and nothing else.
    #[test]
    fn cached_and_freshly_parsed_keys_agree() {
        use aws_lc_rs::rand::SystemRandom;
        use aws_lc_rs::signature::{self, KeyPair as _, RSA_PKCS1_SHA256};
        let der = a_key();
        let kp = signer(&der).expect("cached");
        let mut sig = vec![0u8; kp.public_modulus_len()];
        kp.sign(&RSA_PKCS1_SHA256, &SystemRandom::new(), b"msg", &mut sig).expect("sign");
        let fresh = rsa::KeyPair::from_pkcs8(&der).expect("fresh parse");
        let pk = signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            fresh.public_key().as_ref(),
        );
        pk.verify(b"msg", &sig).expect("a cached key signs exactly like a fresh one");
    }
}
