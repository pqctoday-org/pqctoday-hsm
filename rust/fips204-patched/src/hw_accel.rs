//! Optional, process-wide hardware hook for the public-seed `ExpandA` operation.

use std::sync::OnceLock;
use std::vec::Vec;

/// Computes SHAKE128 output for each 34-byte `ExpandA` seed.
///
/// Returning `None`, the wrong number of outputs, or a short output makes the
/// caller use the constant software implementation for the complete matrix.
pub type ExpandAHook = fn(&[[u8; 34]], usize) -> Option<Vec<Vec<u8>>>;

/// Computes `invNTT(A_hat * NTT(vector))` for ML-DSA-65 using flattened,
/// row-major coefficients. Invalid results make the caller use software.
pub type Mldsa65MatVecHook = fn(&[i32], &[i32]) -> Option<Vec<i32>>;

static EXPAND_A_HOOK: OnceLock<ExpandAHook> = OnceLock::new();
static MLDSA65_MATVEC_HOOK: OnceLock<Mldsa65MatVecHook> = OnceLock::new();

/// Installs the process-wide `ExpandA` hardware hook.
///
/// Returns `false` when another hook was already installed.
pub fn set_expand_a_hook(hook: ExpandAHook) -> bool {
    EXPAND_A_HOOK.set(hook).is_ok()
}

/// Installs the process-wide ML-DSA-65 matrix/vector hardware hook.
/// Returns `false` when another hook was already installed.
pub fn set_mldsa65_matvec_hook(hook: Mldsa65MatVecHook) -> bool {
    MLDSA65_MATVEC_HOOK.set(hook).is_ok()
}

pub(crate) fn expand_a(inputs: &[[u8; 34]], output_len: usize) -> Option<Vec<Vec<u8>>> {
    EXPAND_A_HOOK.get().and_then(|hook| hook(inputs, output_len))
}

pub(crate) fn mldsa65_matvec(matrix: &[i32], vector: &[i32]) -> Option<Vec<i32>> {
    MLDSA65_MATVEC_HOOK.get().and_then(|hook| hook(matrix, vector))
}
