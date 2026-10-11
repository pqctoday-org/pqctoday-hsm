//! Streamed CKKS key custody (EDUCATIONAL; plan
//! pqctoday-fhe docs/ckks/ckks-streamed-evaluation-keys-plan-2026-10-10.md).
//!
//! The FHE seed regenerates the CKKS secret inside the token. The public key
//! and the GB-sized bootstrapping evaluation-key set leave as bounded,
//! deterministic chunks through `CKM_PQCTODAY_FHE_DERIVE_PUBLIC` (parameter
//! version 2); the token never holds the set. Decryption of a level-0
//! ciphertext runs under the seed's typed decryption policy.

pub mod mech;
pub mod params;
pub mod params_gen;
pub mod ring;
pub mod spec;
