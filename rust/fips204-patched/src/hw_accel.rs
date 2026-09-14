//! Optional, process-wide hardware hook for the public-seed `ExpandA` operation.

use std::sync::OnceLock;
use std::vec::Vec;

/// Computes SHAKE128 output for each 34-byte `ExpandA` seed.
///
/// Returning `None`, the wrong number of outputs, or a short output makes the
/// caller use the constant software implementation for the complete matrix.
pub type ExpandAHook = fn(&[[u8; 34]], usize) -> Option<Vec<Vec<u8>>>;

static EXPAND_A_HOOK: OnceLock<ExpandAHook> = OnceLock::new();

/// Installs the process-wide `ExpandA` hardware hook.
///
/// Returns `false` when another hook was already installed.
pub fn set_expand_a_hook(hook: ExpandAHook) -> bool {
    EXPAND_A_HOOK.set(hook).is_ok()
}

pub(crate) fn expand_a(inputs: &[[u8; 34]], output_len: usize) -> Option<Vec<Vec<u8>>> {
    EXPAND_A_HOOK.get().and_then(|hook| hook(inputs, output_len))
}
