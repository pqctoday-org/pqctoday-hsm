# xmss-patched — provenance

Vendored copy of the `xmss` crate, **0.1.0-pre.0**, from crates.io
(RustCrypto `signatures` repository, `path_in_vcs = "xmss"`, commit
`6fa072682f4e8338d41b00ddb21f39ad20b6a1f5` per `.cargo_vcs_info.json`).
The `.crate` file's SHA-256 is
`5715f4f20c87b0d3f8e70ff92e15d1fe405183b493e39f79e77c81545a3b4d4b`, the
checksum `rust/Cargo.lock` pinned before the vendoring. The first commit adding
this directory is the unmodified package contents (minus `.cargo-ok` and the
package's own `Cargo.lock`); every later change is a separate commit.

Licence: MIT OR Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`, unchanged).

Used through `[patch.crates-io] xmss = { path = ... }` in every build root that
builds softhsmrustv3 (rust/, kmip/, remoting/, wasm/), like fips204/fips205/
hbs-lms-patched: the package name and public API stay the same.

## pqctoday-hsm changes

1. **In-memory per-key subtree cache** (`src/tree_cache.rs`, owner decision
   2026-09-24). Upstream `xmssmt_core_sign` rebuilt every layer's whole subtree
   (`treehash` over 2^h′ leaves) for every signature; `bds_k` is unused. The cache
   keeps every node at height ≥ 3 per (parameter set, SK_SEED, PUB_SEED, layer,
   tree); a signature recomputes only its leaf's height-3 subtree. Key generation
   seeds the cache. Signatures and updated keys are byte-identical to upstream
   (`xmss_core::cache_tests` signs sequences both ways, across subtree
   boundaries); the key format and the index handling are unchanged. Memory,
   invalidation and the 64 MiB LRU cap are documented at the top of the file.
   `cache_stats`/`cache_clear` are doc(hidden) diagnostics.
