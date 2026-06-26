# mlxpqc — provenance & licensing

This directory contains a from-scratch Apple-Metal (GPU) implementation and
benchmarking of post-quantum cryptography (ML-DSA-65 / FIPS-204), with all
operations validated bit-exact against a public reference.

## Components and their licenses

| Path | Origin | License |
|------|--------|---------|
| `*.swift`, `bench/`, `*.md`, charts | Original work (this project) | Same as the parent repository (BSD-2-Clause) |
| `mldsa/ref/` | Forked from [pq-crystals/dilithium](https://github.com/pq-crystals/dilithium) reference | Public Domain (CC0) **or** Apache-2.0 **or** GPL-2.0 — see `mldsa/ref/LICENSE` |

The GPU kernels in `mldsa/gpu/` were **translated from the pq-crystals reference**
(public domain) and original work. They are not derived from any proprietary code.

## What is intentionally NOT in this repository

- **Apple corecrypto** is **not included** and must never be committed. Its license
  ("Apple Inc.'s Internal Use License Agreement") permits use only to *verify*
  correctness and **forbids redistribution**. During development it was used solely
  as a local, read-only correctness oracle — never copied into the source here.
  It is excluded via `.gitignore` (`/arm/`).
- **Academic papers** (`papers/`) referenced in the analysis are not redistributed;
  they are available from their original sources (IACR ePrint / arXiv).

## Standards & patents

ML-DSA is the NIST FIPS-204 standard and is patent-unencumbered; implementing and
sharing it carries no known patent obligations.

## Attribution

If you use `mldsa/ref/`, retain the pq-crystals copyright/license notice in
`mldsa/ref/LICENSE` per its terms.
