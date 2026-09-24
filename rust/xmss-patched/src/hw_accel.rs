//! pqctoday-hsm: optional, process-wide hook for the `hashsig` FPGA engine's
//! `MERKLE_SUBTREE` command on XMSS / XMSS^MT trees (pqctoday-cacp
//! `fpga/hashsig/ABI.md` §6.3, §7.3).
//!
//! `treehash` computes one whole XMSS tree (height h/d) and the
//! authentication path of one leaf, for keygen (the top tree) and for every
//! layer of a signature. The hook is offered exactly that: SK_SEED,
//! PUB_SEED, k = h/d, leaf_start = 0, auth_leaf = the leaf, and the layer and
//! tree address of the tree. It returns root ‖ auth\[0..k\] or `None`; on
//! `None` the tree is built here exactly as before, so output is
//! byte-identical. The WOTS+ signature of the leaf stays on the CPU, the
//! engine never sees the index, and the caller still receives (and
//! persists) the advanced key together with the signature, as before.

use crate::hash::thash_h;
use crate::hash_address::{
    copy_subtree_addr, set_layer_addr, set_ltree_addr, set_ots_addr, set_tree_addr,
    set_tree_height, set_tree_index, set_type, XMSS_ADDR_TYPE_HASHTREE, XMSS_ADDR_TYPE_LTREE,
    XMSS_ADDR_TYPE_OTS,
};
use crate::params::{XmssOid, XmssParams};
use crate::xmss_commons::gen_leaf_wots;
use std::cell::Cell;
use std::sync::OnceLock;

/// `(raw_oid, SK_SEED, PUB_SEED, k, leaf_start, auth_leaf, layer, tree_address)`
/// → root ‖ auth\[0..k\] (n bytes each), or `None` to build the tree on the
/// CPU. `raw_oid` is this crate's encoding: `0x0000_00XX` for an XMSS OID,
/// `0x0001_00XX` for an XMSS^MT OID.
pub type XmssSubtreeHook = fn(u32, &[u8], &[u8], u32, u32, u32, u32, u64) -> Option<Vec<u8>>;

static HOOK: OnceLock<XmssSubtreeHook> = OnceLock::new();

std::thread_local! {
    /// Set while a software reference is computed, so it never uses the hook.
    static BYPASS: Cell<bool> = const { Cell::new(false) };
}

/// Installs the process-wide XMSS subtree hook. Returns `false` when a hook
/// was already installed.
pub fn set_xmss_subtree_hook(hook: XmssSubtreeHook) -> bool {
    HOOK.set(hook).is_ok()
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

/// `treehash` on the hook. Fills `root` and `auth_path` and returns `true`,
/// or returns `false` (nothing written) to build the tree on the CPU.
pub(crate) fn treehash(
    params: &XmssParams,
    root: &mut [u8],
    auth_path: &mut [u8],
    sk_seed: &[u8],
    pub_seed: &[u8],
    leaf_idx: u32,
    subtree_addr: &[u32; 8],
) -> bool {
    let Some(hook) = HOOK.get() else {
        return false;
    };
    if BYPASS.with(Cell::get) {
        return false;
    }
    let Some(oid) = raw_oid(params) else {
        return false;
    };
    let n = params.n as usize;
    let k = params.tree_height;
    let tree_address = (u64::from(subtree_addr[1]) << 32) | u64::from(subtree_addr[2]);
    let Some(payload) = hook(
        oid,
        &sk_seed[..n],
        &pub_seed[..n],
        k,
        0,
        leaf_idx,
        subtree_addr[0],
        tree_address,
    ) else {
        return false;
    };
    if payload.len() != n * (k as usize + 1) {
        return false;
    }
    root[..n].copy_from_slice(&payload[..n]);
    auth_path[..k as usize * n].copy_from_slice(&payload[n..]);
    true
}

/// What the engine's `MERKLE_SUBTREE` must return for an XMSS / XMSS^MT
/// tree: the root of the height-`k` subtree starting at `leaf_start`, then
/// `auth[0..k]` for `auth_leaf` (zero when `None`), each n bytes, for the
/// tree at (`layer`, `tree_address`). Computed on the CPU without the hook.
/// `None` for an unknown OID, wrong seed sizes or out-of-range positions.
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
    subtree_hash(
        &params,
        root,
        auth,
        sk_seed,
        pub_seed,
        leaf_start,
        k,
        auth_leaf,
        &subtree_addr,
    )
    .ok()?;
    Some(out)
}

/// `xmss_core::treehash` generalised to the subtree of height `k` starting at
/// `leaf_start` (leaf and node addresses stay those of the whole tree).
#[allow(clippy::too_many_arguments)]
fn subtree_hash(
    params: &XmssParams,
    root: &mut [u8],
    auth_path: &mut [u8],
    sk_seed: &[u8],
    pub_seed: &[u8],
    leaf_start: u32,
    k: u32,
    auth_leaf: Option<u32>,
    subtree_addr: &[u32; 8],
) -> crate::error::XmssResult<()> {
    let n = params.n as usize;
    let mut stack = vec![0u8; (k as usize + 1) * n];
    let mut heights = vec![0u32; k as usize + 1];
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

    for idx in leaf_start..leaf_start + (1u32 << k) {
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
        if auth_leaf.is_some_and(|leaf| (leaf ^ 0x1) == idx) {
            auth_path[..n].copy_from_slice(&stack[(offset - 1) * n..offset * n]);
        }
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
            if let Some(leaf) = auth_leaf {
                let h = heights[offset - 1];
                if h < k && ((leaf >> h) ^ 0x1) == tree_idx {
                    let h = h as usize;
                    auth_path[h * n..(h + 1) * n]
                        .copy_from_slice(&stack[(offset - 1) * n..offset * n]);
                }
            }
        }
    }
    root[..n].copy_from_slice(&stack[..n]);
    Ok(())
}
