# classic-mceliece-multi

A fork of [`classic-mceliece-rust`](https://github.com/Colfenor/classic-mceliece-rust)
3.1.0 (upstream commit `6e5ce0cbba807e5288b677cee07224a8e30a0876`), rewritten to
compile **all 10** Classic McEliece parameter sets into one build instead of exactly
one selected by a Cargo feature. Pure Rust, `#![no_std]`, `#![forbid(unsafe_code)]`.

Unlike the other vendored forks in this workspace (`../fips204-patched/`,
`../fips205-patched/`, `../hbs-lms-patched/`), this one is **not** a small patch on
top of an otherwise-untouched upstream tree — the whole crate is restructured, so
this README describes that structure directly rather than carrying upstream's own
(now-inapplicable, single-feature-per-build) usage text verbatim. The upstream
license (`LICENSE.txt`, MIT) is unmodified; `UPSTREAM-CHANGELOG.md` is upstream's own
`CHANGELOG.md`, kept for provenance.

## Why fork, not depend

`classic-mceliece-rust`'s Cargo features gate real algorithm code, not just sizes —
field arithmetic (12-bit vs 13-bit GF, four distinct reduction-polynomial tap sets),
the Beneš network (a different `apply_benes` per field width), error-vector
sampling, syndrome computation, and the `f` (semi-systematic) keygen path all differ
by parameter set. `build.rs` panics if two size features are selected at once — a
hard, deliberate one-set-per-build constraint. See
`docs/implementation-plan-classic-mceliece-all-parameter-sets-2026-09-08.md` (in the
parent `pqctoday-hsm` repo) §4.0 for the full inventory this fork's structure is
built from.

## Structure

```
src/
  lib.rs           — PublicKey<N>/SecretKey<N>/Ciphertext<N>/SharedSecret (const-
                      generic over byte length — proven on stable Rust; see lib.rs's
                      own doc comment), ParameterSet enum
  shared/          — code genuinely shared across most or all 10 variants: field
                      arithmetic (gf.rs, narrow/wide/4-way split), Beneš network
                      (benes.rs, narrow/wide), control bits (fully shared),
                      error-vector generation and syndrome computation (encrypt.rs,
                      two independent 2-way axes), secret-key polynomial generation
                      (sk_gen.rs, 4-way — matches gf.rs's reduction split), public-
                      key generation and KEM orchestration (pk_gen.rs,
                      operations.rs — the axis with real per-family logic, not just
                      sizes: plain / 6960119 / f / f_6960119f)
  mceliece348864/  — one directory per parameter set: literal GFBITS/SYS_N/SYS_T,
  mceliece348864f/   the three CRYPTO_*BYTES constants (verified against the
  mceliece460896/    official Round-4 KAT vectors — see
  ...                `kmip/kat/classic-mceliece/` in the parent repo), and the
  mceliece8192128f/  three public entry points: keypair_boxed / encapsulate_boxed /
                      decapsulate_boxed
```

Every parameter-set module is a thin, mechanical binding of `shared/`'s functions to
that variant's literal sizes and family choice — see any one of them (`mceliece348864/
mod.rs` is the smallest) for the pattern.

## Const generics on stable Rust — what does and doesn't work here

A trait associated const reached through a still-generic type parameter cannot size
an array on stable Rust (`error: generic parameters may not be used in const
operations`) — nor can an expression of a bare const-generic parameter (`N+1`,
`2*N`, etc.), confirmed directly against `rustc` while building this fork, not just
assumed from documentation. Two consequences visible throughout `shared/`:

- The outer API (`PublicKey<N>`, etc.) uses a **bare** `const N: usize` — legal,
  and the mechanism `lib.rs` and every parameter-set module's type aliases rely on.
- Internal algorithm functions take runtime **slices** (`&[u16]`, `&mut [u8]`) with
  `debug_assert!` length checks, not `[T; SYS_N]`-shaped fixed arrays — because
  `SYS_N`/`SYS_T`/`GFBITS`-derived array lengths (`SYS_T+1`, `2*SYS_T`, `SYS_N/8`,
  …) cannot be expressed as a function's own const-generic parameter either. Fixed
  local scratch buffers are sized to the crate-wide maximum across all 10 variants
  (`MAX_SYS_T = 128`, `MAX_SYS_N = 8192`, etc.) rather than to a generic parameter.

## Testing

Each parameter-set module carries a `sizes_match_the_official_table` test (always
run) and a `keygen_encaps_decaps_round_trip` test (`#[ignore]`d — keygen is slow in
unoptimized builds; run with `--release` or under this crate's own
`[profile.dev]`/`[profile.test]` `opt-level = 3` override). KAT tests against the
official Round-4 vectors (`kmip/kat/classic-mceliece/`) are wired at the parent
repo's `kmip/tests/classic_mceliece_kat.rs`, not in this crate — see the
implementation plan §4.1 (step 5) for why.

## Upstreaming

Intended to be proposed back to `Colfenor/classic-mceliece-rust` once this fork
ships and its KATs pass (implementation plan §8, O-4) — the vendored copy here is
the shipping source regardless of upstream's response.
