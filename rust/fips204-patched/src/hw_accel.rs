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

/// Signs one complete ML-DSA-65 operation with a resident public matrix and
/// pre-transformed secret polynomials. Returning `None` makes the caller run
/// the complete rejection loop in software.
pub type Mldsa65SignHook =
    fn(&[i32], &[i32], &[i32], &[i32], &[u8; 64], &[u8; 64], bool) -> Option<Vec<u8>>;

/// Host-path stages of an ML-DSA signature, reported to the stage hook.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MldsaStage {
    /// `skDecode` and the NTTs of `s1`, `s2`, `t0` (`PrivateKey::try_from_bytes`).
    KeyDecode,
    /// `ExpandA(rho)` on the CPU.
    ExpandA,
    /// `mu` and `rho'`.
    MessageHash,
    /// Flattening the matrix and secrets into vectors for the accelerator.
    Flatten,
    /// The whole-signature accelerator hook call.
    Accelerator,
    /// The rejection loop in software.
    SoftwareLoop,
}

/// Receives one stage duration in nanoseconds.
pub type MldsaStageHook = fn(MldsaStage, u64);

static EXPAND_A_HOOK: OnceLock<ExpandAHook> = OnceLock::new();
static STAGE_HOOK: OnceLock<MldsaStageHook> = OnceLock::new();
static MLDSA65_MATVEC_HOOK: OnceLock<Mldsa65MatVecHook> = OnceLock::new();
static MLDSA65_SIGN_HOOK: OnceLock<Mldsa65SignHook> = OnceLock::new();

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

/// Installs the process-wide whole-operation ML-DSA-65 signing hook.
/// Returns `false` when another hook was already installed.
pub fn set_mldsa65_sign_hook(hook: Mldsa65SignHook) -> bool {
    MLDSA65_SIGN_HOOK.set(hook).is_ok()
}

/// Installs the process-wide stage-timing hook (diagnostics only; unset,
/// no clock is read). Returns `false` when a hook was already installed.
pub fn set_mldsa_stage_hook(hook: MldsaStageHook) -> bool {
    STAGE_HOOK.set(hook).is_ok()
}

pub(crate) fn stage_start() -> Option<std::time::Instant> {
    STAGE_HOOK.get().map(|_| std::time::Instant::now())
}

pub(crate) fn stage_end(stage: MldsaStage, started: Option<std::time::Instant>) {
    if let (Some(hook), Some(started)) = (STAGE_HOOK.get(), started) {
        hook(stage, u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX));
    }
}

pub(crate) fn expand_a(inputs: &[[u8; 34]], output_len: usize) -> Option<Vec<Vec<u8>>> {
    EXPAND_A_HOOK.get().and_then(|hook| hook(inputs, output_len))
}

pub(crate) fn mldsa65_matvec(matrix: &[i32], vector: &[i32]) -> Option<Vec<i32>> {
    MLDSA65_MATVEC_HOOK.get().and_then(|hook| hook(matrix, vector))
}

pub(crate) fn mldsa65_sign(
    matrix: &[i32], s1: &[i32], s2: &[i32], t0: &[i32], mu: &[u8; 64], rho_prime: &[u8; 64],
    randomized: bool,
) -> Option<Vec<u8>> {
    MLDSA65_SIGN_HOOK
        .get()
        .and_then(|hook| hook(matrix, s1, s2, t0, mu, rho_prime, randomized))
}
