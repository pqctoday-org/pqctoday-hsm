# mlxpqc — GPU-accelerating PQC on Apple Silicon (Metal)

A **research subproject** exploring a Metal (Apple GPU) implementation of
lattice PQC — ML-KEM (FIPS 203) and ML-DSA (FIPS 204) — by porting the
acceleration principles from the CUDA GPU-PQC literature to Apple Silicon.

> Not a PKCS#11 wrapper. mlxpqc does not integrate with the softhsmv3 module;
> it is a standalone acceleration study with its own build and benchmarks.

## Contents

| Path | What |
|---|---|
| [`ANALYSIS.md`](ANALYSIS.md) | The design analysis — mapping generic GPU-PQC acceleration principles to Metal |
| [`TEST_PLAN.md`](TEST_PLAN.md) | Correctness/validation plan (bit-exact vs pq-crystals reference) |
| [`NOTICE.md`](NOTICE.md) | Licensing note (Apple corecrypto is **not** included; used only as a local read-only oracle) |
| [`bench/`](bench/README.md) | Microbenchmarks — `bench/run.sh` |
| [`mldsa/`](mldsa/README.md) | ML-DSA Metal kernels — `swiftc -O gpu/MLDSANTT.swift` |
| `papers/` | Reference literature |

## Status

Early-stage. The forward NTT Metal kernel for ML-DSA is implemented and
**validated bit-exact** vs the pq-crystals reference (2026-06-13), beating all
CPU cores 8–31× for batched NTT. INTT, Montgomery reduction, SHAKE, and
rejection sampling are TODO — see the live checklist in
[`mldsa/README.md`](mldsa/README.md).

## Requirements

Apple Silicon Mac with Xcode/Swift toolchain (Metal). corecrypto, if you want
to reproduce the corecrypto oracle path, must be downloaded separately per
[`NOTICE.md`](NOTICE.md).
