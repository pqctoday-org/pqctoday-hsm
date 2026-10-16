# Changes to this copy of `ml-kem` 0.2.3

This folder is a changed copy of the crates.io `ml-kem` 0.2.3 crate
(https://github.com/RustCrypto/KEMs, Apache-2.0 OR MIT), used through
`[patch.crates-io]` in `rust/Cargo.toml`. Its `CHANGELOG.md` is upstream's.
Changes are by PQC Today, LLC. Compare with the crates.io 0.2.3 source to see
every line.

Licence: the upstream licence files (`LICENSE-MIT`, `LICENSE-APACHE`) are kept
unchanged; these changes are offered under the same terms. Every changed or
added `.rs` file carries a one-line "Modified by PQC Today, LLC" or "Added by
PQC Today, LLC" comment at the top (Apache-2.0 section 4(b)). `git log -- <this
folder>` gives the full history.

| Date | File | Change | Why |
|---|---|---|---|
| 2026-09-13 | `src/lib.rs`, `src/kem.rs`, `src/algebra.rs`, `src/crypto.rs`, `src/encode.rs`, `Cargo.toml` | Optional `phase-profile` feature: timing spans for key generation, encapsulation, decapsulation and their phases. Off by default; with it off the code is the same as upstream. The decapsulation comparison is wrapped in a block for the span; it stays constant time | Performance diagnosis |
