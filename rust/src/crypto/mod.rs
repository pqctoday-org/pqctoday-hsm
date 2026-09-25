pub mod bip32;
// Native-only AWS-LC fast path; see its module doc for the dispatch rule.
#[cfg(not(target_arch = "wasm32"))]
pub mod awslc;
// Parsed-private-key cache for the AWS-LC fast path; same cfg as `awslc`.
#[cfg(not(target_arch = "wasm32"))]
pub mod awslc_keycache;
pub mod handlers;
// Expanded ML-DSA private keys for repeated signing (native only, like the
// AWS-LC cache: the wasm bundle keeps decoding per call).
#[cfg(not(target_arch = "wasm32"))]
pub mod mldsa_keycache;
pub mod keccak;
pub mod lms;
pub mod multipart;
pub mod split_key;

pub use bip32::*;
pub use handlers::*;
pub mod xmss_bridge;
