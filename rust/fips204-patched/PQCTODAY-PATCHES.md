# Local changes to this vendored `fips204` 0.4.6

This directory is a patched copy of the crates.io `fips204` 0.4.6 crate,
wired in through `[patch.crates-io]` in `rust/Cargo.toml`. Its `CHANGELOG.md`
is upstream's. This file records local divergences from upstream, starting
2026-10-03. Changes made before that date are not listed here; diff against
the crates.io 0.4.6 source to see them.

| Date | File | Change | Why |
|---|---|---|---|
| 2026-10-03 | `src/hashing.rs:145` | In the second `debug_assert!` of `sample_in_ball`, `tau.try_into()` became `i32::try_from(tau)`. No behaviour change. | With TFHE-rs's `integer-client-js-wasm-api` feature on wasm32 (FHE browser build), wasm-bindgen's comparison impls enter the dependency graph and the untyped `try_into()` no longer infers. See `docs/fhe-browser-matrix-plan-2026-10-03.md`. |
