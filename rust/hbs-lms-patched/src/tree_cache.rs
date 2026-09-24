//! In-memory, per-tree LMS node cache (pqctoday-hsm addition, feature `tree-cache`).
//!
//! Upstream signs without auxiliary data, and then `get_tree_element` recomputes every
//! authentication-path node from its leaves: each LMS signature costs a full tree build
//! (2^h LM-OTS public keys), and every HSS signature additionally rebuilds every lower
//! level's tree to recompute that level's public key. This module memoises, per tree, every
//! node at height `>= low(h)`; `get_tree_element` consults it before recursing and fills it
//! as nodes are computed.
//!
//! * **Output is unchanged**: a node is a pure function of (LMS type, LM-OTS type, I,
//!   SEED, node number r); the cache only returns values upstream would have computed.
//! * **Nothing is persisted.** The private-key format, the aux-data format and the state
//!   order are untouched: `hss_sign` still calls the caller's update function with the
//!   advanced key before it returns the signature.
//! * **Identity**: SHA-256 over both type codes, I and SEED. Lower HSS levels have their own
//!   I and SEED, so each tree has its own entry.
//! * **Invalidation**: node values never change when the key's state advances. A lower HSS
//!   tree that its parent has moved past is never looked up again and ages out of the LRU.
//!   (No "last leaf" release as in xmss-patched: HSS re-signs the current child's public
//!   key with the parent's CURRENT leaf on every call, so a tree's last leaf is used over
//!   and over.)
//! * **Memory**: an entry holds slots for the nodes r < 2^(h−k+1), i.e. heights k..h, with
//!   k = low(h) = min(h, max(4, h − 16)), at n + 1 bytes each. n = 32: H5 132 B, H10 4.2 KiB,
//!   H15 135 KiB, H20 4.3 MiB, H25 4.3 MiB (k = 9); n = 24 about three quarters. A signature
//!   then recomputes at most the 2^k leaves below its height-k ancestor (16; 512 for H25).
//!   The whole cache is capped at [`CAP_BYTES`] (64 MiB) with least-recently-used eviction.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::vec::Vec;

use sha2::{Digest, Sha256};
use tinyvec::ArrayVec;

use crate::constants::MAX_HASH_SIZE;
use crate::hasher::HashChain;
use crate::lms::definitions::LmsPrivateKey;

/// Upper bound on the bytes held by all entries together.
pub(crate) const CAP_BYTES: usize = 64 << 20;

static ENABLED: AtomicBool = AtomicBool::new(true);

struct Entry {
    nodes: Vec<u8>,
    present: Vec<bool>,
    n: usize,
    last_used: u64,
}

struct Cache {
    map: HashMap<[u8; 32], Entry>,
    bytes: usize,
    tick: u64,
}

static CACHE: Mutex<Option<Cache>> = Mutex::new(None);

fn with_cache<T>(f: impl FnOnce(&mut Cache) -> T) -> T {
    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let cache = guard.get_or_insert_with(|| Cache { map: HashMap::new(), bytes: 0, tick: 0 });
    f(cache)
}

/// Lowest cached height for a tree of height `h`.
fn low(h: u32) -> u32 {
    4u32.max(h.saturating_sub(16)).min(h)
}

/// Node number r (RFC 8554: root 1, leaves 2^h..2^(h+1)−1) is cached iff its height
/// `h − floor(log2 r)` is at least `low(h)`, i.e. r < 2^(h − low(h) + 1).
fn slots(h: u32) -> usize {
    1usize << (h - low(h) + 1)
}

fn key_of<H: HashChain>(sk: &LmsPrivateKey<H>) -> [u8; 32] {
    let mut d = Sha256::new();
    d.update(b"pqctoday lms tree cache v1");
    d.update(sk.lms_parameter.get_type_id().to_be_bytes());
    d.update(sk.lmots_parameter.get_type_id().to_be_bytes());
    d.update(sk.lms_tree_identifier);
    d.update(sk.seed.as_slice());
    d.finalize().into()
}

/// The cached value of node `index` of `sk`'s tree, if present.
pub(crate) fn lookup<H: HashChain>(
    sk: &LmsPrivateKey<H>,
    index: usize,
) -> Option<ArrayVec<[u8; MAX_HASH_SIZE]>> {
    let h = u32::from(sk.lms_parameter.get_tree_height());
    if index == 0 || index >= slots(h) || !ENABLED.load(Ordering::Relaxed) {
        return None;
    }
    let key = key_of(sk);
    with_cache(|c| {
        c.tick += 1;
        let tick = c.tick;
        let e = c.map.get_mut(&key)?;
        e.last_used = tick;
        if !e.present[index] {
            return None;
        }
        let mut out = ArrayVec::new();
        out.extend_from_slice(&e.nodes[index * e.n..(index + 1) * e.n]);
        Some(out)
    })
}

/// Records node `index` of `sk`'s tree (no-op for nodes below the cached heights).
pub(crate) fn store<H: HashChain>(sk: &LmsPrivateKey<H>, index: usize, node: &[u8]) {
    let h = u32::from(sk.lms_parameter.get_tree_height());
    if index == 0 || index >= slots(h) || !ENABLED.load(Ordering::Relaxed) {
        return;
    }
    let n = node.len();
    let size = slots(h) * (n + 1);
    if size > CAP_BYTES {
        return;
    }
    let key = key_of(sk);
    with_cache(|c| {
        c.tick += 1;
        let tick = c.tick;
        if !c.map.contains_key(&key) {
            while c.bytes + size > CAP_BYTES {
                let Some(victim) = c.map.iter().min_by_key(|(_, e)| e.last_used).map(|(k, _)| *k)
                else {
                    break;
                };
                if let Some(e) = c.map.remove(&victim) {
                    c.bytes -= e.nodes.len() + e.present.len();
                }
            }
            let _ = c.map.insert(
                key,
                Entry { nodes: vec![0u8; slots(h) * n], present: vec![false; slots(h)], n, last_used: tick },
            );
            c.bytes += size;
        }
        if let Some(e) = c.map.get_mut(&key) {
            if e.n == n {
                e.nodes[index * n..(index + 1) * n].copy_from_slice(node);
                e.present[index] = true;
                e.last_used = tick;
            }
        }
    });
}

/// Number of trees and bytes currently cached (diagnostics and tests).
#[doc(hidden)]
pub fn cache_stats() -> (usize, usize) {
    with_cache(|c| (c.map.len(), c.bytes))
}

/// Drops every cached tree (diagnostics and tests).
#[doc(hidden)]
pub fn cache_clear() {
    with_cache(|c| {
        c.map.clear();
        c.bytes = 0;
    });
}

/// Turns the cache off (upstream behaviour) or back on; for tests that compare the two.
#[doc(hidden)]
pub fn cache_set_enabled(on: bool) {
    ENABLED.store(on, Ordering::Relaxed);
}
