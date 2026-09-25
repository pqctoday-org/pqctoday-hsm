//! Optional, process-wide hardware hook for the public-seed `ExpandA` operation.

use crate::types::T;
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

/// Signs one complete ML-DSA-65 operation (the rejection loop and the
/// signature encoding) from borrowed inputs, writing the 3,309-byte
/// signature into the output slice. Returning `false` makes the caller run
/// the complete rejection loop in software; the output is then ignored.
pub type Mldsa65SignHook = fn(&Mldsa65SignInput<'_>, &mut [u8]) -> bool;

/// The inputs of one ML-DSA-65 signature, borrowed from the signer: the
/// expanded matrix `Â`, the NTT-domain Montgomery-form `s1`, `s2`, `t0`,
/// `mu` and `rho'`. An accelerator writes them straight into its own
/// buffers (little-endian `i32` coefficients) — nothing is copied or
/// flattened on the way.
pub struct Mldsa65SignInput<'a> {
    pub(crate) rho: &'a [u8; 32],
    pub(crate) matrix: &'a [T],
    pub(crate) s1: &'a [T],
    pub(crate) s2: &'a [T],
    pub(crate) t0: &'a [T],
    pub(crate) mu: &'a [u8; 64],
    pub(crate) rho_prime: &'a [u8; 64],
    pub(crate) randomized: bool,
}

impl Mldsa65SignInput<'_> {
    /// Bytes of `Â` (30 polynomials).
    pub const MATRIX_BYTES: usize = 30 * 256 * 4;
    /// Bytes of `s1 ‖ s2 ‖ t0` (17 polynomials).
    pub const SECRET_POLY_BYTES: usize = 17 * 256 * 4;

    /// Identifies the public matrix: `Â = ExpandA(ρ)` depends on `ρ` alone,
    /// so two inputs with the same `ρ` have the same `Â`.
    #[must_use]
    pub fn matrix_id(&self) -> &[u8; 32] {
        self.rho
    }

    /// `mu`, the message representative.
    #[must_use]
    pub fn mu(&self) -> &[u8; 64] {
        self.mu
    }

    /// `rho'`, the private per-signature seed.
    #[must_use]
    pub fn rho_prime(&self) -> &[u8; 64] {
        self.rho_prime
    }

    /// `true` for hedged signing (non-zero `rnd`).
    #[must_use]
    pub fn randomized(&self) -> bool {
        self.randomized
    }

    /// Writes `Â` row-major as little-endian `i32`. `false` if `out` is
    /// not exactly [`Self::MATRIX_BYTES`] long.
    pub fn write_matrix(&self, out: &mut [u8]) -> bool {
        write_polys(out, &[self.matrix])
    }

    /// Writes `s1 ‖ s2 ‖ t0` as little-endian `i32`. `false` if `out` is
    /// not exactly [`Self::SECRET_POLY_BYTES`] long.
    pub fn write_secret_polys(&self, out: &mut [u8]) -> bool {
        write_polys(out, &[self.s1, self.s2, self.t0])
    }
}

fn write_polys(out: &mut [u8], groups: &[&[T]]) -> bool {
    let total: usize = groups.iter().map(|g| g.len() * 1024).sum();
    if out.len() != total {
        return false;
    }
    let mut chunks = out.chunks_exact_mut(1024);
    for poly in groups.iter().flat_map(|g| g.iter()) {
        let chunk = chunks.next().expect("length checked");
        for (bytes, coefficient) in chunk.chunks_exact_mut(4).zip(poly.0.iter()) {
            bytes.copy_from_slice(&coefficient.to_le_bytes());
        }
    }
    true
}

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

pub(crate) fn has_mldsa65_matvec_hook() -> bool {
    MLDSA65_MATVEC_HOOK.get().is_some()
}

pub(crate) fn has_mldsa65_sign_hook() -> bool {
    MLDSA65_SIGN_HOOK.get().is_some()
}

pub(crate) fn mldsa65_sign(input: &Mldsa65SignInput<'_>, signature: &mut [u8]) -> bool {
    MLDSA65_SIGN_HOOK.get().is_some_and(|hook| hook(input, signature))
}
