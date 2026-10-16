# Changes to this copy of `hbs-lms` 0.1.1

This folder is a changed copy of the crates.io `hbs-lms` 0.1.1 crate
(https://github.com/Fraunhofer-AISEC/hbs-lms-rust, Apache-2.0), used through
`[patch.crates-io]` in `rust/Cargo.toml`. Changes are by PQC Today, LLC.
Compare with the crates.io 0.1.1 source to see every line. The packaging-only
upstream files `.cargo/`, `.github/`, `.gitlab-ci.yml`, `Makefile` and
`Cargo.lock` are not copied.

Licence: the upstream licence files (`LICENSE-MIT`, `LICENSE-APACHE`) are kept
unchanged; these changes are offered under the same terms. Every changed or
added `.rs` file carries a one-line "Modified by PQC Today, LLC" or "Added by
PQC Today, LLC" comment at the top (Apache-2.0 section 4(b)). `git log -- <this
folder>` gives the full history.

| Date | File | Change | Why |
|---|---|---|---|
| 2026-06-10 | `src/constants.rs`, `src/hasher/*.rs`, `src/hss/*.rs`, `src/lm_ots/*.rs`, `src/lms/*.rs`, `src/util/helper.rs`, `tests/shake_roundtrip.rs` (new) | Per-hash-family type identifiers (SHA-256 and SHAKE-256, n = 32 and 24) in keys and signatures, with the private-key format kept compatible; bounds-checked parsing of key and signature bytes (no panic on corrupt input) | Upstream wrote SHA-256 type codes for SHAKE-256 keys, so SP 800-208 SHAKE vectors could not be parsed; corrupt input aborted the WebAssembly instance |
| 2026-09-24 | `src/tree_cache.rs` (new), `src/lib.rs`, `src/lms/helper.rs`, `tests/tree_cache.rs` (new), `Cargo.toml` | Optional `tree-cache` feature: in-memory node cache per LMS tree | Signing speed; signatures unchanged |
| 2026-09-24 | `src/hw_accel.rs` (new), `src/lib.rs`, `src/lms/helper.rs`, `src/lms/mod.rs` | Hardware hook for MERKLE_SUBTREE whose results fill the node cache | Hardware acceleration research |
| 2026-09-27 | `src/constants.rs`, `src/lm_ots/parameters.rs` | LM-OTS checksum left shift computed from w and n (RFC 8554 section 4.1) | n = 24, w = 1 signed and verified wrongly |
