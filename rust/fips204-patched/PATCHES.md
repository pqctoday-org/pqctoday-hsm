# Changes to this copy of `fips204` 0.4.6

This folder is a changed copy of the crates.io `fips204` 0.4.6 crate
(https://github.com/integritychain/fips204, MIT OR Apache-2.0), used through
`[patch.crates-io]` in `rust/Cargo.toml`. Its `CHANGELOG.md` is upstream's.
Changes are by PQC Today, LLC. Compare with the crates.io 0.4.6 source to see
every line.

Licence: the upstream licence files (`LICENSE-MIT`, `LICENSE-APACHE`) are kept
unchanged; these changes are offered under the same terms. Every changed or
added `.rs` file carries a one-line "Modified by PQC Today, LLC" or "Added by
PQC Today, LLC" comment at the top (Apache-2.0 section 4(b)). `git log -- <this
folder>` gives the full history.

| Date | File | Change | Why |
|---|---|---|---|
| 2026-04-15 | `src/hashing.rs`, `src/traits.rs`, `src/types.rs`, `src/lib.rs`, `src/ml_dsa.rs`, `tests/integration.rs` | HashML-DSA pre-hash variants SHA-224, SHA-384, SHA3-224/256/384/512 and SHAKE in addition to upstream's SHA-256/SHA-512/SHAKE128 | PKCS#11 v3.2 section 6.67.7 hash-specific HashML-DSA mechanisms |
| 2026-06-13 | `src/lib.rs`, `src/ml_dsa.rs` | External-mu signing and verification (caller supplies the 64-byte mu); unchanged output when not used | Reproduce the OASIS KMIP 3.0 PQC interop vectors byte for byte |
| 2026-08-26 | `src/traits.rs`, `src/hashing.rs`, `src/lib.rs` | Sign and verify over a caller-supplied, already-hashed PHM | PKCS#11 v3.2 section 6.67.6 generic CKM_HASH_ML_DSA takes a hash, not a message (the engine hashed twice) |
| 2026-09-13 | `src/encodings.rs`, `src/hashing.rs`, `src/helpers.rs`, `src/lib.rs`, `src/ml_dsa.rs`, `src/ntt.rs`, `Cargo.toml` | Optional `phase-profile` feature: timing spans per phase (off by default, no effect when off) | Performance diagnosis |
| 2026-09-13 to 2026-09-24 | `src/hw_accel.rs` (new), `src/hashing.rs`, `src/lib.rs`, `src/ml_dsa.rs`, `Cargo.toml` | Optional `hw-accel` feature: process-wide hook for Keccak/ExpandA and resident matrix-vector signing on an FPGA, with a software fallback | Hardware acceleration research (K26 board) |
| 2026-09-24 | `src/ml_dsa.rs`, `src/lib.rs`, `src/types.rs`, `tests/integration.rs` | Per-key expanded signing context (decode and ExpandA once per key), zeroised on drop | Signing speed |
| 2026-09-30 | `src/encodings.rs` | `sk_decode` rejects s1/s2 coefficients outside [-eta, eta] | FIPS 204 Algorithm 25; found by Project Wycheproof ML-DSA vectors |
| 2026-10-03 | `src/hashing.rs:145` | In the second `debug_assert!` of `sample_in_ball`, `tau.try_into()` became `i32::try_from(tau)`. No behaviour change. | With TFHE-rs's `integer-client-js-wasm-api` feature on wasm32 (FHE browser build), wasm-bindgen's comparison impls enter the dependency graph and the untyped `try_into()` no longer infers. See `docs/fhe-browser-matrix-plan-2026-10-03.md`. |
