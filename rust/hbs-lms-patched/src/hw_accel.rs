//! pqctoday-hsm: optional, process-wide hook for the `hashsig` FPGA engine's
//! `MERKLE_SUBTREE` command (pqctoday-cacp `fpga/hashsig/ABI.md` §6.3).
//!
//! `get_tree_element` asks the hook for any node it has to compute: the node
//! T[r] of an LMS tree of height H is the root of the subtree of height
//! k = H − ⌊log2 r⌋ whose leftmost leaf is (r << k) − 2^H. The hook returns
//! that root (n bytes) or `None`, and on `None` the node is computed here
//! exactly as before. Keygen (T[1]) and every authentication-path node of a
//! signature go through this one function, so both use the engine whenever it
//! claims the parameter set. The engine never sees the leaf index being
//! signed, and the index is still reserved and persisted by the caller's
//! update function before any signature is returned (`hss_sign_core`).
//!
//! Nodes the caller reads from auxiliary data never reach the hook, and the
//! hook is skipped whenever auxiliary data is in use, so the auxiliary-data
//! contents stay exactly what the software path writes.

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

/// `(lms_type, lmots_type, SEED, I, k, leaf_start)` → the root of the
/// height-k subtree starting at `leaf_start` (n bytes), or `None` to compute
/// it on the CPU. Type codes are the IANA LMS / LM-OTS typecodes.
pub type MerkleSubtreeHook = fn(u32, u32, &[u8], &[u8], u32, u32) -> Option<Vec<u8>>;

static HOOK: OnceLock<MerkleSubtreeHook> = OnceLock::new();

std::thread_local! {
    /// Set while a software reference is computed, so it never uses the hook.
    static BYPASS: Cell<bool> = const { Cell::new(false) };
}

/// Installs the process-wide subtree hook. Returns `false` when a hook was
/// already installed.
pub fn set_merkle_subtree_hook(hook: MerkleSubtreeHook) -> bool {
    HOOK.set(hook).is_ok()
}

/// The hook's answer for tree node `index` (RFC 8554 numbering, root = 1).
pub(crate) fn subtree_root<H: HashChain>(
    index: usize,
    private_key: &LmsPrivateKey<H>,
) -> Option<ArrayVec<[u8; MAX_HASH_SIZE]>> {
    let hook = HOOK.get()?;
    if BYPASS.with(Cell::get) {
        return None;
    }
    let height = u32::from(private_key.lms_parameter.get_tree_height());
    let index = index as u64;
    if index == 0 || height > 31 || index >> (height + 1) != 0 {
        return None;
    }
    let k = height - (63 - index.leading_zeros());
    let leaf_start = u32::try_from((index << k) - (1u64 << height)).ok()?;
    let root = hook(
        private_key.lms_parameter.get_type_id(),
        private_key.lmots_parameter.get_type_id(),
        private_key.seed.as_slice(),
        &private_key.lms_tree_identifier,
        k,
        leaf_start,
    )?;
    if root.len() != usize::from(H::OUTPUT_SIZE) {
        return None;
    }
    ArrayVec::try_from(root.as_slice()).ok()
}

/// What the engine's `MERKLE_SUBTREE` must return for an LMS tree: the root
/// of the height-`k` subtree at `leaf_start`, then `auth[0..k]` for
/// `auth_leaf` (all zero when `auth_leaf` is `None`), each n bytes. Computed
/// on the CPU without the hook. `None` for unknown or mismatched typecodes,
/// wrong field sizes or out-of-range positions.
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
