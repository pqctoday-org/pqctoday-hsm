# Changes to this copy of `fips205` 0.4.1

This folder is a changed copy of the crates.io `fips205` 0.4.1 crate
(https://github.com/integritychain/fips205, MIT OR Apache-2.0), used through
`[patch.crates-io]` in `rust/Cargo.toml`. Its `CHANGELOG.md` is upstream's.
Changes are by PQC Today, LLC. Compare with the crates.io 0.4.1 source to see
every line.

Licence: the upstream licence files (`LICENSE-MIT`, `LICENSE-APACHE`) are kept
unchanged; these changes are offered under the same terms. Every changed or
added `.rs` file carries a one-line "Modified by PQC Today, LLC" or "Added by
PQC Today, LLC" comment at the top (Apache-2.0 section 4(b)). `git log -- <this
folder>` gives the full history.

| Date | File | Change | Why |
|---|---|---|---|
| 2026-04-15 | `src/hashers.rs`, `src/traits.rs`, `src/types.rs`, `src/lib.rs`, `src/slh.rs` | HashSLH-DSA pre-hash variants SHA-224, SHA-384, SHA3-224/256/384/512 in addition to upstream's | PKCS#11 v3.2 section 6.69.7 hash-specific HashSLH-DSA mechanisms |
| 2026-05-17 | `src/hashers.rs` | Pre-hash `update` calls written as `<H as Digest>::update`; no behaviour change | The wasm32 build had an ambiguous `update` method |
| 2026-08-26 | `src/traits.rs`, `src/hashers.rs`, `src/lib.rs` | Sign and verify over a caller-supplied, already-hashed PHM | PKCS#11 v3.2 section 6.69.6 generic CKM_HASH_SLH_DSA takes a hash (the engine hashed twice) |
| 2026-09-13 | `src/fors.rs`, `src/hashers.rs`, `src/hypertree.rs`, `src/lib.rs`, `src/slh.rs`, `src/wots.rs`, `src/xmss.rs`, `Cargo.toml` | Optional `phase-profile` feature: timing spans per phase (off by default) | Performance diagnosis |
| 2026-09-23 | `src/lib.rs`, `src/slh.rs`, `src/hypertree.rs` | `PrivateKey::from_bytes_unchecked`; the top-layer root is checked during signing instead of rebuilt on every signature | About 14% less signing work for the "s" sets; the root check moves to key import |
| 2026-09-23 | `src/hashers.rs`, `src/fors.rs`, `src/wots.rs`, `src/xmss.rs`, `src/hypertree.rs` | The PK.seed block is hashed once per operation, not per F call | Signing speed; output unchanged |
| 2026-09-23 to 2026-09-24 | `src/par.rs` (new), `src/fors.rs`, `src/xmss.rs`, `src/lib.rs`, `src/slh.rs`, `tests/parallel_budget.rs` (new), `Cargo.toml` | Optional `parallel` feature: independent subtrees on several cores under one process-wide core budget | Signing and key generation speed (native only) |
| 2026-09-24 | `src/hw_accel.rs` (new), `src/hashers.rs`, `src/lib.rs`, `src/slh.rs` | Hardware hook for SLH_SIGN and SLH_KEYGEN with software reference, counted against the core budget | Hardware acceleration research |
