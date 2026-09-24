//! pqctoday-hsm: optional, process-wide hooks for the `hashsig` FPGA engine's
//! `MERKLE_SUBTREE` command on XMSS / XMSS^MT trees (pqctoday-cacp
//! `fpga/hashsig/ABI.md` §6.3, §7.3).
//!
//! Every XMSS tree (height h′ = h/d) is served from the in-memory subtree
//! cache (`tree_cache.rs`): keygen and signing call `root_and_auth`, which on
//! a miss builds the cache entry — every node at height ≥ low(h′) — and then
//! reads the root and the upper authentication path from it, rebuilding only
//! the 2^low(h′) leaves around the signed leaf. The engine plugs into that
//! miss: [`build_entry`] asks it for every height-low(h′) node (the roots of
//! 2^(h′−low) subtrees, sent as request tables) and hashes the levels above
//! on the CPU with the same addresses as upstream `treehash`. The entry is
//! byte-identical to the one the CPU builds, it is cached and released
//! exactly as before, and later signatures hit it without the engine.
//!
//! The engine never sees the index; WOTS+ signing, the per-signature leaf
//! rebuild and the index update stay on the CPU, and the caller still
//! receives (and persists) the advanced key together with the signature.

use crate::hash::thash_h;
use crate::hash_address::{
    copy_subtree_addr, set_layer_addr, set_tree_addr, set_tree_height, set_tree_index, set_type,
    XMSS_ADDR_TYPE_HASHTREE,
};
use crate::params::{XmssOid, XmssParams};
use crate::tree_cache::{entry_len, level_offset, low, walk};
use std::cell::Cell;
use std::sync::OnceLock;

/// `(raw_oid, SK_SEED, PUB_SEED, k, leaf_starts, layer, tree_address)` → the
/// root (n bytes) of the height-`k` subtree at each leaf start of the tree at
/// (`layer`, `tree_address`), in order, or `None` to build them on the CPU.
/// `raw_oid` is this crate's encoding: `0x0000_00XX` for an XMSS OID,
/// `0x0001_00XX` for an XMSS^MT OID (the ABI's XMSS `param_set` low bits).
pub type XmssSubtreeHook = fn(u32, &[u8], &[u8], u32, &[u32], u32, u64) -> Option<Vec<Vec<u8>>>;

/// `(raw_oid, k, subtrees)` → whether the engine would take that many
/// height-`k` subtrees in one call. Cheap and lock-free.
pub type XmssWantsHook = fn(u32, u32, usize) -> bool;

static HOOKS: OnceLock<(XmssSubtreeHook, XmssWantsHook)> = OnceLock::new();

std::thread_local! {
    /// Set while a software reference is computed, so it never uses the hook.
    static BYPASS: Cell<bool> = const { Cell::new(false) };
}

/// Installs the process-wide XMSS subtree hooks. Returns `false` when hooks
/// were already installed.
pub fn set_xmss_subtree_hook(compute: XmssSubtreeHook, wants: XmssWantsHook) -> bool {
    HOOKS.set((compute, wants)).is_ok()
}

/// The raw OID whose parameters are `params`.
fn raw_oid(params: &XmssParams) -> Option<u32> {
    (0x01..=0x15u32)
        .chain((0x01..=0x38u32).map(|raw| 0x0001_0000 | raw))
        .find(|&candidate| {
            let mut candidate_params = XmssParams::default();
            XmssOid::try_from(candidate)
                .and_then(|oid| oid.initialize(&mut candidate_params))
                .is_ok()
                && candidate_params == *params
        })
}

/// The subtree-cache entry of the tree at `subtree_addr` (every node at
/// height ≥ low(h′), in `tree_cache` layout), with the height-low(h′) nodes
/// computed on the engine. `None` builds it on the CPU.
pub(crate) fn build_entry(
    params: &XmssParams,
    sk_seed: &[u8],
    pub_seed: &[u8],
    subtree_addr: &[u32; 8],
) -> Option<Vec<u8>> {
    if BYPASS.with(Cell::get) {
        return None;
    }
    let &(compute, wants) = HOOKS.get()?;
    let oid = raw_oid(params)?;
    let n = params.n as usize;
    let h = params.tree_height;
    let lo = low(h);
    let count = 1usize << (h - lo);
    if !wants(oid, lo, count) {
        return None;
    }
    let starts: Vec<u32> = (0..count as u32).map(|i| i << lo).collect();
    let tree_address = (u64::from(subtree_addr[1]) << 32) | u64::from(subtree_addr[2]);
    let roots = compute(
        oid,
        &sk_seed[..n],
        &pub_seed[..n],
        lo,
        &starts,
        subtree_addr[0],
        tree_address,
    )?;
    if roots.len() != count || roots.iter().any(|root| root.len() != n) {
        return None;
    }
    let mut nodes = vec![0u8; entry_len(h, n)];
    let base = level_offset(h, lo, n);
    for (i, root) in roots.iter().enumerate() {
        nodes[base + i * n..base + (i + 1) * n].copy_from_slice(root);
    }
    // Levels lo+1..=h′: node (z, i) = H(node(z−1, 2i) ‖ node(z−1, 2i+1)) with the
    // hash-tree address upstream `treehash` uses (tree height z−1, index i).
    let mut node_addr = [0u32; 8];
    copy_subtree_addr(&mut node_addr, subtree_addr);
    set_type(&mut node_addr, XMSS_ADDR_TYPE_HASHTREE);
    for z in lo + 1..=h {
        let (below, here) = (level_offset(h, z - 1, n), level_offset(h, z, n));
        for i in 0..1usize << (h - z) {
            set_tree_height(&mut node_addr, z - 1);
            set_tree_index(&mut node_addr, i as u32);
            let children = nodes[below + 2 * i * n..below + (2 * i + 2) * n].to_vec();
            thash_h(
                params,
                &mut nodes[here + i * n..here + (i + 1) * n],
                &children,
                &pub_seed[..n],
                &mut node_addr,
            )
            .ok()?;
        }
    }
    Some(nodes)
}

/// What the engine's `MERKLE_SUBTREE` must return for an XMSS / XMSS^MT
/// tree: the root of the height-`k` subtree starting at `leaf_start`, then
/// `auth[0..k]` for `auth_leaf` (zero when `None`), each n bytes, for the
/// tree at (`layer`, `tree_address`). Computed on the CPU with upstream's
/// node functions, without the hooks and without the cache. `None` for an
/// unknown OID, wrong seed sizes or out-of-range positions.
#[allow(clippy::too_many_arguments)]
pub fn reference_merkle_subtree(
    raw_oid: u32,
    sk_seed: &[u8],
    pub_seed: &[u8],
    k: u32,
    leaf_start: u32,
    auth_leaf: Option<u32>,
    layer: u32,
    tree_address: u64,
) -> Option<Vec<u8>> {
    let mut params = XmssParams::default();
    XmssOid::try_from(raw_oid)
        .and_then(|oid| oid.initialize(&mut params))
        .ok()?;
    let n = params.n as usize;
    let height = params.tree_height;
    let span = 1u64.checked_shl(k)?;
    let start = u64::from(leaf_start);
    if sk_seed.len() != n
        || pub_seed.len() != n
        || k > height
        || start % span != 0
        || start + span > 1u64 << height
        || layer >= params.d
        || auth_leaf.is_some_and(|leaf| u64::from(leaf) < start || u64::from(leaf) >= start + span)
    {
        return None;
    }

    struct Bypass;
    impl Drop for Bypass {
        fn drop(&mut self) {
            BYPASS.with(|b| b.set(false));
        }
    }
    BYPASS.with(|b| b.set(true));
    let _bypass = Bypass;

    let mut subtree_addr = [0u32; 8];
    set_layer_addr(&mut subtree_addr, layer);
    set_tree_addr(&mut subtree_addr, tree_address);
    let mut out = vec![0u8; n * (k as usize + 1)];
    let (root, auth) = out.split_at_mut(n);
    walk(&params, sk_seed, pub_seed, &subtree_addr, leaf_start, k, &mut |z, i, node| {
        if z == k {
            root.copy_from_slice(node);
        } else if auth_leaf.is_some_and(|leaf| i == (leaf >> z) ^ 1) {
            auth[z as usize * n..(z as usize + 1) * n].copy_from_slice(node);
        }
    })
    .ok()?;
    Some(out)
}
