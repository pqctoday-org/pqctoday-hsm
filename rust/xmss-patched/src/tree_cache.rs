//! In-memory, per-key XMSS subtree cache (pqctoday-hsm addition).
//!
//! Upstream `xmss_core::xmssmt_core_sign` runs `treehash` over all `2^h′` leaves of every
//! layer's subtree for every signature (the parameter sets' `bds_k` is never used), so an
//! XMSS_16 signature costs as much as key generation. This module keeps, per subtree, every
//! node at height `>= LOW` in memory. A signature then recomputes only the height-`LOW`
//! subtree that contains its leaf (`2^LOW` WOTS+ leaves) and reads the upper part of the
//! authentication path and the root from the cache.
//!
//! * **Output is unchanged.** Every node is produced by the same leaf/hash functions, with
//!   the same addresses, as upstream `treehash` (see [`walk`]); the cache only memoises
//!   values that are a pure function of (parameter set, SK_SEED, PUB_SEED, layer, tree).
//! * **Nothing is persisted.** The key format and the state handling are untouched: the
//!   index is still read from, advanced in and zeroed in the caller's secret-key bytes, and
//!   the engine still persists that updated key before releasing the signature. The cache
//!   is per process and is rebuilt from the key on first use.
//! * **Identity.** Entries are keyed by SHA-256 over the parameter set, SK_SEED, PUB_SEED,
//!   layer and tree address, so two keys (or two subtrees of one key) never share an entry.
//! * **Invalidation.** Node values never change while a key's index advances. An entry is
//!   dropped when the signature that used the LAST leaf of its subtree has been produced
//!   (the index moves past it for good), and otherwise ages out through the LRU below.
//! * **Memory.** An entry holds `2^(h′−LOW+1) − 1` nodes of `n` bytes. With `LOW = 3` and
//!   n = 32: h′=10 → 8 KiB, h′=16 → 512 KiB, h′=20 → 8 MiB (n = 24: three quarters of that).
//!   The whole cache is capped at [`CAP_BYTES`] (64 MiB) with least-recently-used eviction;
//!   an entry larger than the cap is used for its signature and not kept.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};

use crate::error::XmssResult;
use crate::hash::thash_h;
use crate::hash_address::*;
use crate::params::XmssParams;
use crate::xmss_commons::gen_leaf_wots;

/// Levels below this are recomputed for every signature (`2^LOW` leaves).
const LOW: u32 = 3;
/// Upper bound on the bytes held by all entries together.
pub(crate) const CAP_BYTES: usize = 64 << 20;

struct Entry {
    nodes: Arc<Vec<u8>>,
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

/// Lowest cached level for a subtree of height `h`.
fn low(h: u32) -> u32 {
    LOW.min(h)
}

/// Byte offset of level `z` (`low(h) <= z <= h`) in an entry's node array.
fn level_offset(h: u32, z: u32, n: usize) -> usize {
    // nodes at level j: 2^(h−j); levels low..z-1 precede level z
    let nodes: u64 = (low(h)..z).map(|j| 1u64 << (h - j)).sum();
    nodes as usize * n
}

fn entry_len(h: u32, n: usize) -> usize {
    level_offset(h, h + 1, n)
}

pub(crate) fn key_of(params: &XmssParams, sk_seed: &[u8], pub_seed: &[u8], subtree_addr: &[u32; 8]) -> [u8; 32] {
    let mut d = Sha256::new();
    d.update(b"pqctoday xmss subtree cache v1");
    for v in [
        params.func,
        params.n,
        params.padding_len,
        params.wots_w,
        params.tree_height,
        params.full_height,
        params.d,
        subtree_addr[0],
        subtree_addr[1],
        subtree_addr[2],
    ] {
        d.update(v.to_be_bytes());
    }
    // Callers pass SK_SEED/PUB_SEED as slices that may run on into the rest of the key
    // (keygen hands `&sk[idx_bytes..]`, as upstream treehash does); only n bytes count.
    let n = params.n as usize;
    d.update(&sk_seed[..n]);
    d.update(&pub_seed[..n]);
    d.finalize().into()
}

/// Upstream `treehash`'s node computation, generalised to the `2^t` leaves starting at
/// `start` (a multiple of `2^t`) of the subtree at `subtree_addr`. Calls `on_node(height,
/// index, node)` for every leaf and every inner node, with the same leaf/ltree/node
/// addresses upstream uses (`tree_idx = idx >> (height + 1)` is the global index).
fn walk(
    params: &XmssParams,
    sk_seed: &[u8],
    pub_seed: &[u8],
    subtree_addr: &[u32; 8],
    start: u32,
    t: u32,
    on_node: &mut dyn FnMut(u32, u32, &[u8]),
) -> XmssResult<()> {
    let n = params.n as usize;
    let t_us = t as usize;
    let mut stack = vec![0u8; (t_us + 1) * n];
    let mut heights = vec![0u32; t_us + 1];
    let mut offset: usize = 0;

    let mut ots_addr = [0u32; 8];
    let mut ltree_addr = [0u32; 8];
    let mut node_addr = [0u32; 8];

    copy_subtree_addr(&mut ots_addr, subtree_addr);
    copy_subtree_addr(&mut ltree_addr, subtree_addr);
    copy_subtree_addr(&mut node_addr, subtree_addr);

    set_type(&mut ots_addr, XMSS_ADDR_TYPE_OTS);
    set_type(&mut ltree_addr, XMSS_ADDR_TYPE_LTREE);
    set_type(&mut node_addr, XMSS_ADDR_TYPE_HASHTREE);

    for idx in start..start + (1u32 << t) {
        set_ltree_addr(&mut ltree_addr, idx);
        set_ots_addr(&mut ots_addr, idx);
        gen_leaf_wots(
            params,
            &mut stack[offset * n..(offset + 1) * n],
            sk_seed,
            pub_seed,
            &mut ltree_addr,
            &mut ots_addr,
        )?;
        offset += 1;
        heights[offset - 1] = 0;
        on_node(0, idx, &stack[(offset - 1) * n..offset * n]);

        while offset >= 2 && heights[offset - 1] == heights[offset - 2] {
            let tree_idx = idx >> (heights[offset - 1] + 1);

            set_tree_height(&mut node_addr, heights[offset - 1]);
            set_tree_index(&mut node_addr, tree_idx);
            let tmp = stack[(offset - 2) * n..offset * n].to_vec();
            thash_h(
                params,
                &mut stack[(offset - 2) * n..(offset - 1) * n],
                &tmp,
                pub_seed,
                &mut node_addr,
            )?;
            offset -= 1;
            heights[offset - 1] += 1;
            on_node(heights[offset - 1], tree_idx, &stack[(offset - 1) * n..offset * n]);
        }
    }
    Ok(())
}

/// Every node at height `>= low(h)` of the subtree at `subtree_addr`, in [`level_offset`]
/// layout: one full treehash, as upstream does for every signature.
fn build_entry(
    params: &XmssParams,
    sk_seed: &[u8],
    pub_seed: &[u8],
    subtree_addr: &[u32; 8],
) -> XmssResult<Vec<u8>> {
    let n = params.n as usize;
    let h = params.tree_height;
    let lo = low(h);
    let mut nodes = vec![0u8; entry_len(h, n)];
    walk(params, sk_seed, pub_seed, subtree_addr, 0, h, &mut |z, i, node| {
        if z >= lo {
            let at = level_offset(h, z, n) + i as usize * n;
            nodes[at..at + n].copy_from_slice(node);
        }
    })?;
    Ok(nodes)
}

/// Same outputs as upstream `treehash(params, root, auth_path, sk_seed, pub_seed, leaf_idx,
/// subtree_addr)`: the subtree root and the authentication path of `leaf_idx`, served from
/// the cache (built on first use). `release` drops the entry afterwards: the caller sets it
/// when this was the last leaf of the subtree the key will ever use.
pub(crate) fn root_and_auth(
    params: &XmssParams,
    root: &mut [u8],
    auth_path: &mut [u8],
    sk_seed: &[u8],
    pub_seed: &[u8],
    leaf_idx: u32,
    subtree_addr: &[u32; 8],
    release: bool,
) -> XmssResult<()> {
    let n = params.n as usize;
    let h = params.tree_height;
    let lo = low(h);
    let key = key_of(params, sk_seed, pub_seed, subtree_addr);

    let cached = with_cache(|c| {
        c.tick += 1;
        let tick = c.tick;
        c.map.get_mut(&key).map(|e| {
            e.last_used = tick;
            Arc::clone(&e.nodes)
        })
    });
    let nodes = match cached {
        Some(nodes) => nodes,
        None => {
            // Built outside the lock; a concurrent builder of the same entry computes the
            // same bytes, so whichever insert lands last is equally correct.
            let nodes = Arc::new(build_entry(params, sk_seed, pub_seed, subtree_addr)?);
            if !release {
                insert(key, Arc::clone(&nodes));
            }
            nodes
        }
    };

    // Levels >= lo, and the root, straight from the cache.
    for j in lo..h {
        let sibling = ((leaf_idx >> j) ^ 1) as usize;
        let at = level_offset(h, j, n) + sibling * n;
        auth_path[j as usize * n..(j as usize + 1) * n].copy_from_slice(&nodes[at..at + n]);
    }
    let top = level_offset(h, h, n);
    root[..n].copy_from_slice(&nodes[top..top + n]);

    // Levels < lo: rebuild the height-lo subtree that contains the leaf.
    if lo > 0 {
        let start = (leaf_idx >> lo) << lo;
        walk(params, sk_seed, pub_seed, subtree_addr, start, lo, &mut |z, i, node| {
            if z < lo && i == (leaf_idx >> z) ^ 1 {
                auth_path[z as usize * n..(z as usize + 1) * n].copy_from_slice(node);
            }
        })?;
    }

    if release {
        with_cache(|c| {
            if let Some(e) = c.map.remove(&key) {
                c.bytes -= e.nodes.len();
            }
        });
    }
    Ok(())
}

/// Stores an entry, evicting least-recently-used ones to stay within [`CAP_BYTES`].
fn insert(key: [u8; 32], nodes: Arc<Vec<u8>>) {
    let len = nodes.len();
    if len > CAP_BYTES {
        return;
    }
    with_cache(|c| {
        if let Some(old) = c.map.remove(&key) {
            c.bytes -= old.nodes.len();
        }
        while c.bytes + len > CAP_BYTES {
            let Some(victim) = c.map.iter().min_by_key(|(_, e)| e.last_used).map(|(k, _)| *k) else {
                break;
            };
            if let Some(e) = c.map.remove(&victim) {
                c.bytes -= e.nodes.len();
            }
        }
        c.tick += 1;
        let last_used = c.tick;
        let _ = c.map.insert(key, Entry { nodes, last_used });
        c.bytes += len;
    });
}

/// Number of entries and bytes currently cached (diagnostics and tests).
#[doc(hidden)]
pub fn cache_stats() -> (usize, usize) {
    with_cache(|c| (c.map.len(), c.bytes))
}

/// Drops every cached subtree (diagnostics and tests).
#[doc(hidden)]
pub fn cache_clear() {
    with_cache(|c| {
        c.map.clear();
        c.bytes = 0;
    });
}

#[cfg(test)]
pub(crate) fn contains(key: &[u8; 32]) -> bool {
    with_cache(|c| c.map.contains_key(key))
}
