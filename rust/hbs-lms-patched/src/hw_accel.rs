//! pqctoday-hsm: optional, process-wide hooks for the `hashsig` FPGA engine's
//! `MERKLE_SUBTREE` command (pqctoday-cacp `fpga/hashsig/ABI.md` §6.3).
//!
//! Node T[r] of an LMS tree of height H is the root of the subtree of height
//! k = H − ⌊log2 r⌋ whose leftmost leaf is (r << k) − 2^H, which is exactly
//! what the engine computes. `get_tree_element` consults, in order, the
//! auxiliary data, the in-memory node cache (`tree_cache`, when enabled), then
//! [`node`] here, then its own recursion; every value it returns is the same
//! pure function of (types, I, SEED, r), so output is byte-identical.
//!
//! * **Cache on** (the engine's configuration): a node at or above the
//!   cache's lowest height L is never fetched alone. The first time one is
//!   needed, every missing height-L node below it is computed on the engine
//!   in request tables and stored in the cache; the unchanged recursion then
//!   combines them from the cache (storing the upper nodes itself). So keygen
//!   and the first signature fill the cache exactly as the software path
//!   does, and later signatures hit it.
//! * **Cache off** / below L: the node itself is one `MERKLE_SUBTREE` of
//!   height k when the engine takes it.
//!
//! Keygen (T[1]) and every authentication-path node go through
//! `get_tree_element`. The engine never sees the leaf index being signed, and
//! `hss_sign_core` still persists the advanced key through the caller's update
//! function before a signature is returned. The hooks are skipped while
//! auxiliary data is in use, so its contents stay those of the software path.

use crate::constants::{LmsTreeIdentifier, MAX_HASH_SIZE};
use crate::hasher::HashChain;
use crate::lm_ots::parameters::LmotsAlgorithm;
use crate::lms::definitions::LmsPrivateKey;
use crate::lms::parameters::LmsAlgorithm;
use crate::{Seed, Sha256_192, Sha256_256, Shake256_192, Shake256_256};
use core::convert::TryFrom;
use std::cell::Cell;
use std::sync::OnceLock;
use std::vec::Vec;
use tinyvec::ArrayVec;

/// `(lms_type, lmots_type, SEED, I, k, leaf_starts)` → the root (n bytes) of
/// the height-`k` subtree at each leaf start, in order, or `None` to compute
/// them all on the CPU. Type codes are the IANA LMS / LM-OTS typecodes.
pub type MerkleSubtreeHook = fn(u32, u32, &[u8], &[u8], u32, &[u32]) -> Option<Vec<Vec<u8>>>;

/// `(lms_type, lmots_type, k, subtrees)` → whether the engine would take
/// that many height-`k` subtrees in one call. Cheap and lock-free; lets the
/// cache fill skip its bookkeeping when the answer is no.
pub type MerkleWantsHook = fn(u32, u32, u32, usize) -> bool;

static HOOKS: OnceLock<(MerkleSubtreeHook, MerkleWantsHook)> = OnceLock::new();

std::thread_local! {
    /// Set while a software reference is computed, so it never uses the hook.
    static BYPASS: Cell<bool> = const { Cell::new(false) };
}

/// Installs the process-wide subtree hooks. Returns `false` when hooks were
/// already installed.
pub fn set_merkle_subtree_hook(compute: MerkleSubtreeHook, wants: MerkleWantsHook) -> bool {
    HOOKS.set((compute, wants)).is_ok()
}

fn hooks() -> Option<&'static (MerkleSubtreeHook, MerkleWantsHook)> {
    if BYPASS.with(Cell::get) {
        return None;
    }
    HOOKS.get()
}

/// The engine's value of tree node `index` (RFC 8554 numbering, root = 1),
/// or `None` to let `get_tree_element` continue (cache prefilled, or CPU).
pub(crate) fn node<H: HashChain>(
    index: usize,
    private_key: &LmsPrivateKey<H>,
) -> Option<ArrayVec<[u8; MAX_HASH_SIZE]>> {
    let &(compute, wants) = hooks()?;
    let height = u32::from(private_key.lms_parameter.get_tree_height());
    let index = index as u64;
    if index == 0 || height > 31 || index >> (height + 1) != 0 {
        return None;
    }
    let k = height - (63 - index.leading_zeros());
    let types = (
        private_key.lms_parameter.get_type_id(),
        private_key.lmots_parameter.get_type_id(),
    );

    #[cfg(feature = "tree-cache")]
    if let Some(floor) = crate::tree_cache::floor(private_key) {
        if k > floor {
            prefill(compute, wants, private_key, types, height, index, k, floor);
            return None;
        }
    }

    if !wants(types.0, types.1, k, 1) {
        return None;
    }
    let leaf_start = u32::try_from((index << k) - (1u64 << height)).ok()?;
    let roots = compute(
        types.0,
        types.1,
        private_key.seed.as_slice(),
        &private_key.lms_tree_identifier,
        k,
        &[leaf_start],
    )?;
    let root = roots.first()?;
    if roots.len() != 1 || root.len() != usize::from(H::OUTPUT_SIZE) {
        return None;
    }
    ArrayVec::try_from(root.as_slice()).ok()
}

/// Stores in the node cache every missing height-`floor` node below `index`
/// (height `k`), computed on the engine. Does nothing when the engine does
/// not take them; the recursion then computes them on the CPU.
#[cfg(feature = "tree-cache")]
#[allow(clippy::too_many_arguments)]
fn prefill<H: HashChain>(
    compute: MerkleSubtreeHook,
    wants: MerkleWantsHook,
    private_key: &LmsPrivateKey<H>,
    types: (u32, u32),
    height: u32,
    index: u64,
    k: u32,
    floor: u32,
) {
    let below = 1usize << (k - floor);
    if !wants(types.0, types.1, floor, below) {
        return;
    }
    let first = index << (k - floor);
    let missing: Vec<u64> = (first..first + below as u64)
        .filter(|&r| crate::tree_cache::lookup(private_key, r as usize).is_none())
        .collect();
    if missing.is_empty() {
        return;
    }
    let Ok(starts) = missing
        .iter()
        .map(|&r| u32::try_from((r << floor) - (1u64 << height)))
        .collect::<Result<Vec<u32>, _>>()
    else {
        return;
    };
    let Some(roots) = compute(
        types.0,
        types.1,
        private_key.seed.as_slice(),
        &private_key.lms_tree_identifier,
        floor,
        &starts,
    ) else {
        return;
    };
    let n = usize::from(H::OUTPUT_SIZE);
    if roots.len() != missing.len() || roots.iter().any(|root| root.len() != n) {
        return;
    }
    for (r, root) in missing.iter().zip(&roots) {
        crate::tree_cache::store(private_key, *r as usize, root);
    }
}

/// What the engine's `MERKLE_SUBTREE` must return for an LMS tree: the root
/// of the height-`k` subtree at `leaf_start`, then `auth[0..k]` for
/// `auth_leaf` (all zero when `auth_leaf` is `None`), each n bytes. Computed
/// on the CPU without the hooks (it may read and fill the node cache, which
/// only ever holds these same values). `None` for unknown or mismatched
/// typecodes, wrong field sizes or out-of-range positions.
pub fn reference_merkle_subtree(
    lms_type: u32,
    lmots_type: u32,
    seed: &[u8],
    identifier: &[u8],
    k: u32,
    leaf_start: u32,
    auth_leaf: Option<u32>,
) -> Option<Vec<u8>> {
    let args = (lms_type, lmots_type, seed, identifier, k, leaf_start, auth_leaf);
    match lms_type {
        0x05..=0x09 => reference::<Sha256_256>(args),
        0x0A..=0x0E => reference::<Sha256_192>(args),
        0x0F..=0x13 => reference::<Shake256_256>(args),
        0x14..=0x18 => reference::<Shake256_192>(args),
        _ => None,
    }
}

type ReferenceArgs<'a> = (u32, u32, &'a [u8], &'a [u8], u32, u32, Option<u32>);

fn reference<H: HashChain>(
    (lms_type, lmots_type, seed, identifier, k, leaf_start, auth_leaf): ReferenceArgs<'_>,
) -> Option<Vec<u8>> {
    let lms_parameter = LmsAlgorithm::get_from_type::<H>(lms_type)?;
    let lmots_parameter = LmotsAlgorithm::get_from_type::<H>(lmots_type)?;
    let height = u32::from(lms_parameter.get_tree_height());
    let span = 1u64.checked_shl(k)?;
    let (start, leaves) = (u64::from(leaf_start), 1u64 << height);
    if k > height || start % span != 0 || start + span > leaves {
        return None;
    }
    if auth_leaf.is_some_and(|leaf| u64::from(leaf) < start || u64::from(leaf) >= start + span) {
        return None;
    }
    let mut tree_seed = Seed::<H>::default();
    if seed.len() != tree_seed.len() {
        return None;
    }
    tree_seed.as_mut_slice().copy_from_slice(seed);
    let identifier = LmsTreeIdentifier::try_from(identifier).ok()?;
    let private_key = LmsPrivateKey::new(tree_seed, identifier, 0, lmots_parameter, lms_parameter);

    struct Bypass;
    impl Drop for Bypass {
        fn drop(&mut self) {
            BYPASS.with(|b| b.set(false));
        }
    }
    BYPASS.with(|b| b.set(true));
    let _bypass = Bypass;

    let n = usize::from(H::OUTPUT_SIZE);
    let mut out = Vec::with_capacity(n * (k as usize + 1));
    let root = ((leaves + start) >> k) as usize;
    out.extend_from_slice(crate::lms::helper::get_tree_element(root, &private_key, &mut None).as_slice());
    for level in 0..k {
        match auth_leaf {
            Some(leaf) => {
                let sibling = (((leaves + u64::from(leaf)) >> level) ^ 1) as usize;
                out.extend_from_slice(
                    crate::lms::helper::get_tree_element(sibling, &private_key, &mut None).as_slice(),
                );
            }
            None => out.resize(out.len() + n, 0),
        }
    }
    Some(out)
}
