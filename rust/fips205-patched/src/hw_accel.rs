//! pqctoday-hsm: optional, process-wide hooks for the `hashsig` FPGA engine.
//!
//! The engine (pqctoday-cacp `fpga/hashsig/ABI.md` §6.1–§6.2) computes the
//! tree work of FIPS 205 and nothing that touches the message:
//!
//! * `SLH_SIGN`: Algorithm 19 lines 11–18 — `SIG_FORS ‖ SIG_HT` for the
//!   digest-derived `md`, `idx_tree`, `idx_leaf`. R = `PRF_msg` and `H_msg` stay
//!   here, so `SK.prf` and the message never leave the CPU.
//! * `SLH_KEYGEN`: Algorithm 18 line 3 — the top-layer XMSS root.
//!
//! A hook returns `None` whenever the operation should run on the CPU (no
//! engine, parameter set not claimed, routed to the CPU, engine busy or in
//! error), and the caller then runs its unchanged software path. A returned
//! signature is checked here, before it is used: `SIG_FORS` and `SIG_HT` must
//! reproduce `PK.root` from `md` (the engine's own root check cannot see a fault
//! in a lower hypertree layer, ABI.md §6.1). A failed check calls the reject
//! hook and signs on the CPU. The output is therefore byte-identical with the
//! hooks installed or not.
//!
//! The `reference_*` functions compute exactly what the engine must return,
//! in software, without consulting any hook. They back the engine's
//! known-answer test and the register simulator.

use crate::hashers::{Hashers, PkSeed};
use crate::types::{Adrs, Auth, ForsSig, HtSig, WotsSig, XmssSig, FORS_TREE};
use crate::{fors, hypertree, slh};
use std::sync::OnceLock;
use std::vec::Vec;

/// `SLH_SIGN`: `(param, SK.seed, PK.seed, PK.root, md, idx_tree, idx_leaf)` →
/// `SIG_FORS ‖ SIG_HT`. `param` is the FIPS 205 Table 2 row (1..=12). `None`
/// means "sign on the CPU".
pub type SlhSignHook = fn(u32, &[u8], &[u8], &[u8], &[u8], u64, u32) -> Option<Vec<u8>>;

/// `SLH_KEYGEN`: `(param, SK.seed, PK.seed)` → `PK.root`. `None` means "on the CPU".
pub type SlhKeygenHook = fn(u32, &[u8], &[u8]) -> Option<Vec<u8>>;

/// Called when a signature returned by the sign hook failed the check against
/// `PK.root`, so the caller can take its engine out of service.
pub type SlhRejectHook = fn(u32);

static SIGN_HOOK: OnceLock<SlhSignHook> = OnceLock::new();
static KEYGEN_HOOK: OnceLock<SlhKeygenHook> = OnceLock::new();
static REJECT_HOOK: OnceLock<SlhRejectHook> = OnceLock::new();

/// Installs the process-wide SLH-DSA tree-signing hook.
/// Returns `false` when a hook was already installed.
pub fn set_slh_sign_hook(hook: SlhSignHook) -> bool {
    SIGN_HOOK.set(hook).is_ok()
}

/// Installs the process-wide SLH-DSA top-root hook.
/// Returns `false` when a hook was already installed.
pub fn set_slh_keygen_hook(hook: SlhKeygenHook) -> bool {
    KEYGEN_HOOK.set(hook).is_ok()
}

/// Installs the process-wide rejected-output hook.
/// Returns `false` when a hook was already installed.
pub fn set_slh_reject_hook(hook: SlhRejectHook) -> bool {
    REJECT_HOOK.set(hook).is_ok()
}

/// Why a reference computation produced no payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceError {
    /// Unknown or not compiled-in parameter set, or a field of the wrong size
    /// or out of range.
    InvalidInput,
    /// The top-layer root computed from `SK.seed` and `PK.seed` is not `PK.root`.
    RootMismatch,
}

/// `SIG_FORS ‖ SIG_HT` on the hook, verified against `PK.root`; `None` → CPU.
#[allow(clippy::too_many_arguments)]
pub(crate) fn tree_sign<
    const A: usize,
    const D: usize,
    const HP: usize,
    const K: usize,
    const LEN: usize,
    const M: usize,
    const N: usize,
>(
    hashers: &Hashers<K, LEN, M, N>, md: &[u8], sk_seed: &[u8; N], seed: &PkSeed<N>,
    pk_root: &[u8; N], adrs: &Adrs, idx_tree: u64, idx_leaf: u32,
) -> Option<(ForsSig<A, K, N>, HtSig<D, HP, LEN, N>)> {
    let hook = SIGN_HOOK.get()?;
    let payload = hook(hashers.hw_param, sk_seed, &seed.bytes, pk_root, md, idx_tree, idx_leaf)?;
    let parsed = parse_payload::<A, D, HP, K, LEN, N>(&payload);
    let verified = parsed.as_ref().is_some_and(|(fors_sig, ht_sig)| {
        let pk_fors = fors::fors_pk_from_sig::<A, K, LEN, M, N>(hashers, fors_sig, md, seed, adrs);
        hypertree::ht_verify::<D, HP, K, LEN, M, N>(
            hashers,
            &pk_fors.key,
            ht_sig,
            seed,
            idx_tree,
            idx_leaf,
            pk_root,
        )
    });
    if !verified {
        if let Some(reject) = REJECT_HOOK.get() {
            reject(hashers.hw_param);
        }
        return None;
    }
    parsed
}

/// `PK.root` on the hook; `None` → CPU.
pub(crate) fn keygen_root<const K: usize, const LEN: usize, const M: usize, const N: usize>(
    hashers: &Hashers<K, LEN, M, N>, sk_seed: &[u8; N], pk_seed: &[u8; N],
) -> Option<[u8; N]> {
    let hook = KEYGEN_HOOK.get()?;
    hook(hashers.hw_param, sk_seed, pk_seed)?.try_into().ok()
}

/// `SIG_FORS ‖ SIG_HT` in signature byte order (FIPS 205 Figures 14 and 13).
fn parse_payload<
    const A: usize,
    const D: usize,
    const HP: usize,
    const K: usize,
    const LEN: usize,
    const N: usize,
>(
    payload: &[u8],
) -> Option<(ForsSig<A, K, N>, HtSig<D, HP, LEN, N>)> {
    if payload.len() != (K * (1 + A) + D * (HP + LEN)) * N {
        return None;
    }
    let mut chunks = payload.chunks_exact(N).map(|c| {
        let mut node = [0u8; N];
        node.copy_from_slice(c);
        node
    });
    let mut next = || chunks.next().expect("length checked");
    let mut fors_sig = ForsSig {
        private_key_value: [[0u8; N]; K],
        auth: core::array::from_fn(|_| Auth { tree: [[0u8; N]; A] }),
    };
    for k in 0..K {
        fors_sig.private_key_value[k] = next();
        for a in 0..A {
            fors_sig.auth[k].tree[a] = next();
        }
    }
    let mut ht_sig = HtSig {
        xmss_sigs: core::array::from_fn(|_| XmssSig {
            sig_wots: WotsSig { data: [[0u8; N]; LEN] },
            auth: [[0u8; N]; HP],
        }),
    };
    for d in 0..D {
        for len in 0..LEN {
            ht_sig.xmss_sigs[d].sig_wots.data[len] = next();
        }
        for hp in 0..HP {
            ht_sig.xmss_sigs[d].auth[hp] = next();
        }
    }
    Some((fors_sig, ht_sig))
}

fn payload_bytes<
    const A: usize,
    const D: usize,
    const HP: usize,
    const K: usize,
    const LEN: usize,
    const N: usize,
>(
    fors_sig: &ForsSig<A, K, N>, ht_sig: &HtSig<D, HP, LEN, N>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity((K * (1 + A) + D * (HP + LEN)) * N);
    for k in 0..K {
        out.extend_from_slice(&fors_sig.private_key_value[k]);
        for a in 0..A {
            out.extend_from_slice(&fors_sig.auth[k].tree[a]);
        }
    }
    for d in 0..D {
        for len in 0..LEN {
            out.extend_from_slice(&ht_sig.xmss_sigs[d].sig_wots.data[len]);
        }
        for hp in 0..HP {
            out.extend_from_slice(&ht_sig.xmss_sigs[d].auth[hp]);
        }
    }
    out
}

fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], ReferenceError> {
    bytes.try_into().map_err(|_| ReferenceError::InvalidInput)
}

/// What `SLH_SIGN` must return, computed on the CPU without any hook.
#[allow(clippy::too_many_arguments)]
pub(crate) fn reference_sign<
    const A: usize,
    const D: usize,
    const H: usize,
    const HP: usize,
    const K: usize,
    const LEN: usize,
    const M: usize,
    const N: usize,
>(
    hashers: &Hashers<K, LEN, M, N>, sk_seed: &[u8], pk_seed: &[u8], pk_root: &[u8], md: &[u8],
    idx_tree: u64, idx_leaf: u32,
) -> Result<Vec<u8>, ReferenceError> {
    let sk_seed = zeroize::Zeroizing::new(array::<N>(sk_seed)?);
    let pk_seed = array::<N>(pk_seed)?;
    let pk_root = array::<N>(pk_root)?;
    if md.len() != (K * A + 7) / 8
        || idx_tree >> (H - HP) != 0
        || u64::from(idx_leaf) >> HP != 0
    {
        return Err(ReferenceError::InvalidInput);
    }
    // Algorithm 19 lines 11-13.
    let mut adrs = Adrs::default();
    adrs.set_tree_address(idx_tree);
    adrs.set_type_and_clear(FORS_TREE);
    adrs.set_key_pair_address(idx_leaf);
    let seed = (hashers.pk_seed)(&pk_seed);
    let (fors_sig, ht_sig) = slh::tree_sign::<A, D, H, HP, K, LEN, M, N>(
        hashers, md, &sk_seed, &seed, &pk_root, &adrs, idx_tree, idx_leaf,
    )
    .map_err(|_| ReferenceError::RootMismatch)?;
    Ok(payload_bytes(&fors_sig, &ht_sig))
}

/// What `SLH_KEYGEN` must return, computed on the CPU without any hook.
pub(crate) fn reference_root<
    const D: usize,
    const H: usize,
    const HP: usize,
    const K: usize,
    const LEN: usize,
    const M: usize,
    const N: usize,
>(
    hashers: &Hashers<K, LEN, M, N>, sk_seed: &[u8], pk_seed: &[u8],
) -> Result<Vec<u8>, ReferenceError> {
    let sk_seed = zeroize::Zeroizing::new(array::<N>(sk_seed)?);
    let pk_seed = array::<N>(pk_seed)?;
    let mut adrs = Adrs::default();
    adrs.set_layer_address(u32::try_from(D).map_err(|_| ReferenceError::InvalidInput)? - 1);
    let seed = (hashers.pk_seed)(&pk_seed);
    Ok(slh::top_root::<D, H, HP, K, LEN, M, N>(hashers, &sk_seed, &seed, &adrs).to_vec())
}

macro_rules! by_param {
    ($param:expr, $function:ident ( $($arg:expr),* )) => {
        match $param {
            #[cfg(feature = "slh_dsa_sha2_128s")]
            1 => crate::slh_dsa_sha2_128s::$function($($arg),*),
            #[cfg(feature = "slh_dsa_shake_128s")]
            2 => crate::slh_dsa_shake_128s::$function($($arg),*),
            #[cfg(feature = "slh_dsa_sha2_128f")]
            3 => crate::slh_dsa_sha2_128f::$function($($arg),*),
            #[cfg(feature = "slh_dsa_shake_128f")]
            4 => crate::slh_dsa_shake_128f::$function($($arg),*),
            #[cfg(feature = "slh_dsa_sha2_192s")]
            5 => crate::slh_dsa_sha2_192s::$function($($arg),*),
            #[cfg(feature = "slh_dsa_shake_192s")]
            6 => crate::slh_dsa_shake_192s::$function($($arg),*),
            #[cfg(feature = "slh_dsa_sha2_192f")]
            7 => crate::slh_dsa_sha2_192f::$function($($arg),*),
            #[cfg(feature = "slh_dsa_shake_192f")]
            8 => crate::slh_dsa_shake_192f::$function($($arg),*),
            #[cfg(feature = "slh_dsa_sha2_256s")]
            9 => crate::slh_dsa_sha2_256s::$function($($arg),*),
            #[cfg(feature = "slh_dsa_shake_256s")]
            10 => crate::slh_dsa_shake_256s::$function($($arg),*),
            #[cfg(feature = "slh_dsa_sha2_256f")]
            11 => crate::slh_dsa_sha2_256f::$function($($arg),*),
            #[cfg(feature = "slh_dsa_shake_256f")]
            12 => crate::slh_dsa_shake_256f::$function($($arg),*),
            _ => Err(ReferenceError::InvalidInput),
        }
    };
}

/// `SIG_FORS ‖ SIG_HT` that the engine's `SLH_SIGN` must return for these
/// inputs (`param` = FIPS 205 Table 2 row), computed on the CPU.
///
/// # Errors
/// [`ReferenceError::InvalidInput`] for an unknown set or a malformed field;
/// [`ReferenceError::RootMismatch`] when `PK.root` does not belong to `SK.seed`/`PK.seed`.
pub fn reference_slh_sign_payload(
    param: u32, sk_seed: &[u8], pk_seed: &[u8], pk_root: &[u8], md: &[u8], idx_tree: u64,
    idx_leaf: u32,
) -> Result<Vec<u8>, ReferenceError> {
    by_param!(param, hw_reference_sign(sk_seed, pk_seed, pk_root, md, idx_tree, idx_leaf))
}

/// `PK.root` that the engine's `SLH_KEYGEN` must return, computed on the CPU.
///
/// # Errors
/// [`ReferenceError::InvalidInput`] for an unknown set or a malformed field.
pub fn reference_slh_keygen_root(
    param: u32, sk_seed: &[u8], pk_seed: &[u8],
) -> Result<Vec<u8>, ReferenceError> {
    by_param!(param, hw_reference_root(sk_seed, pk_seed))
}
