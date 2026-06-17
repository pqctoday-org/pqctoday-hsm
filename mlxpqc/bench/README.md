# mlxpqc/bench — Metal acceleration test tool

Standalone micro-benchmarks for each acceleration mechanism in
[../TEST_PLAN.md](../TEST_PLAN.md). **Tests the mechanisms in isolation** — none of
the kernels depend on the full ML-KEM/ML-DSA algorithm, so you can characterize
each GPU pattern *before* wiring it into the crypto. Metrics go to **stdout and a
timestamped log file**; the log starts with full machine info (chip, **GPU core
count**, Metal family, unified memory, threadgroup limits).

## Build & run

```sh
./run.sh                # all mechanism micro-benchmarks
./run.sh --scale        # GPU core-scaling study (see below)
./run.sh --only M1,M5   # a subset
./run.sh --list         # list mechanisms / modes
```

Or manually:
```sh
swiftc -O MetalPQCBench.swift -o mlxpqc_bench -framework Metal -framework Foundation
./mlxpqc_bench --scale
```

Requires Xcode command-line tools (`swiftc`) and an Apple-silicon Metal GPU. No
pip/network dependencies. Logs are written to `bench/logs/`.

## Two modes

### 1. Mechanism micro-benchmarks (default)
One benchmark per mechanism, each comparing a **naive baseline** vs the
**optimized Metal pattern**, gated by a correctness check:

| ID  | Mechanism | Baseline vs optimized | Correctness gate |
|-----|-----------|-----------------------|------------------|
| M1  | SIMD-group task parallelism | scalar 1-thread/task vs 32-lane coalesced | outputs identical |
| M2  | NTT barrier reduction | 8 full barriers vs 5 simdgroup barriers | merged == naive |
| M3  | Threadgroup bank-conflict probe | latency vs stride 1..33 | reveals bank period |
| M4  | Modular reduction | hardware `%` vs Barrett | both == `x % q` |
| M5  | Keccak-f[1600] (SHAKE core) | GPU-batched scalar | FIPS-202 zero vector |
| M6  | Rejection sampling | scalar loop vs ballot+prefix-sum | same accepted set |
| M8  | Unified memory | private+blit vs shared zero-copy | output correct |
| M9  | simdgroup_matrix (ConvKyber) | fp32 matrix throughput | feasibility (float) |
| M10 | Tail-occupancy scheduler | static dispatch vs work-queue | outputs identical |
| M7  | On-the-fly matrix + fusion | (doc-only — needs full pipeline) | — |

### 2. Core-scaling study (`--scale`)
Answers **"how much does adding GPU cores speed up computation?"**

Metal has no API to pin N cores, so the tool uses the standard proxy: **one
threadgroup runs on one GPU core**, so it sweeps the number of dispatched
threadgroups (1, 2, 4, … past the die's core count) over a *fixed total problem*
and reports time / throughput / **speedup / parallel-efficiency** at each level.
The knee where efficiency drops ≈ the number of cores that actually help.

It runs the sweep on two contrasting workloads so the lesson is visible:
- **compute-bound** (Keccak-f permutations) → speedup tracks core count, then
  flattens → *adding cores helps* (this is where NTT / Keccak / rejection live).
- **memory-bound** (streaming touch) → saturates well before core count
  (bandwidth-limited) → *more cores don't help; cut memory traffic instead.*

Run `--scale` on both the **M4 Pro** and the **M5 Max** and compare the knees:
the higher-core M5 Max should keep scaling further on the compute-bound curve,
and the gap tells you how much of each mechanism is core-limited vs
bandwidth-limited on each machine.

## Notes & honesty

- M2/M4 arithmetic uses the Kyber prime q=3329 as a *representative* modulus; the
  point measured is the memory/barrier/ALU pattern, not spec-exact NTT.
- M5 validates the permutation against the real FIPS-202 vector, but only the
  scalar GPU-batched baseline is implemented; the cooperative 25-lane SHAKE is the
  next optimization (TEST_PLAN M5).
- M9 proves fp32 matrix throughput; **integer mod-q viability on the matrix units
  is the open research question** (TEST_PLAN M9).
- Paper-reported speedups are NVIDIA numbers (directional targets); these
  benchmarks produce the actual Apple numbers.
- "GPU cores (used)" in the header is the device core count (Metal uses all
  cores); the `--scale` mode is where you vary effective cores engaged.
