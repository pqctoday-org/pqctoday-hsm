//! AES (GCM/CBC/KeyWrap), SHA/HMAC, and session management.

#![allow(non_snake_case)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![allow(clippy::too_many_arguments)]
// Edition 2024 promoted `unsafe_op_in_unsafe_fn` to a lint-on-by-default,
// which requires every unsafe op inside an `unsafe fn` to be wrapped in
// its own `unsafe { … }` block. softhsmrustv3's PKCS#11 surface uses the
// pre-2024 convention (the whole fn is `unsafe`, ops inside are bare).
// Allowing the legacy convention keeps the diff against the upstream
// SoftHSMv2 C bindings minimal.
#![allow(unsafe_op_in_unsafe_fn)]

/// Native pkcs11.h-conformant C ABI (CK_FUNCTION_LIST + adapter shims).
/// wasm32 keeps the documented JS-shim function table instead — exported
/// C function pointers cannot cross wasm-bindgen (audit H-1 residual).
#[cfg(not(target_arch = "wasm32"))]
pub mod ck_abi;
pub mod constants;
pub mod crypto;
pub mod ffi;
pub mod native;
pub mod state;

pub use ffi::*;
