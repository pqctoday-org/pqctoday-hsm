# mlxpqc/mldsa — ML-DSA (Dilithium / FIPS-204) GPU port

Forking the **pq-crystals/dilithium** reference and translating it to Metal, guided
by the validated findings in [../bench/](../bench/) and [../TEST_PLAN.md](../TEST_PLAN.md).

## Legal basis (important)

- **Base = `ref/`** — pq-crystals/dilithium reference C, **Public Domain (CC0) /
  Apache-2.0 / GPL-2.0**. Freely forkable, modifiable, redistributable. This is the
  implementation FIPS-204 is built on.
- **Apple corecrypto (`../../arm/`) is NOT in this repository** (gitignored; license
  forbids redistribution — download from <https://github.com/apple/corecrypto>, branch
  `2026-05`, to use it as a local oracle). See [../NOTICE.md](../NOTICE.md). It is NOT forked: its license permits reading
  *only to verify correctness*; redistribution / derivative works are forbidden.
  It is used solely as a read-only correctness oracle (KAT comparison).
- You do **not** "recompile C for GPU" — you translate the reference algorithm into
  Metal kernels. The C is the blueprint + a CPU oracle; the kernels are a rewrite.

## Layout

- `ref/` — forked pq-crystals reference C (the blueprint + CPU oracle).
- `gpu/MLDSANTT.swift` — **first kernel: forward NTT**, validated bit-exact vs `ref/`,
  with CPU-1core / CPU-allcore / GPU crossover timing. Build: `swiftc -O MLDSANTT.swift
  -o mldsa_ntt -framework Metal -framework Foundation`.

## Validated design decisions (from ../bench on M5 Max)

| Dilithium component | ref file | GPU approach (validated) |
|---|---|---|
| SHAKE / Keccak (sampling, H) | fips202.c | **scalar per-thread** — cooperative loses ~9× on Apple (no 64-bit simd_shuffle) |
| NTT / INTT | ntt.c | merged/threadgroup, **register-resident**; barrier reduction gave little (M2) |
| modular reduction | reduce.c | Montgomery (reduce.c constants); Barrett ≈ hw-divide on M5 (M4) — keep it simple, constant-time |
| poly / polyvec layout | poly*.c | SIMD-group coalesced batch (M1, ~2.7×) |
| rejection sampling (rej_uniform/eta) | poly.c | ballot + prefix-sum (M6, ~1.5×) + early-abort ordering |
| matrix expand + multiply | poly.c/polyvec.c | on-the-fly column-major + fusion (M7, to build) |
| batch I/O | — | unified memory, zero-copy (M8, 2×); no host blit |
| sign rejection-loop scheduling | sign.c | **static dispatch** — GPU work-queue lost (M10) at tested skew |

## Status

- [x] Fork legal base (pq-crystals/dilithium)
- [x] **Forward NTT in Metal — validated bit-exact vs reference (2026-06-13)**
      → GPU beats all 18 CPU cores 8–31× for batched NTT; crossover immediate (≥256).
- [ ] INTT (invntt_tomont) + pointwise multiply
- [ ] Montgomery reduce / reduce32 / caddq as shared device fns
- [ ] SHAKE256/128 scalar kernel (reuse validated Keccak from ../bench)
- [ ] Rejection sampling (rej_uniform / rej_eta) — ballot+prefix
- [ ] poly pack/unpack, power2round, decompose, makehint
- [ ] Assemble keygen → sign → verify; validate vs NIST ACVP / corecrypto KATs
- [ ] Constant-time review (ISA inspection)
- [ ] Re-run crossover on M4 Pro

## Method

Every kernel is validated **bit-exact against `ref/`** (faithful CPU port) before any
perf claim, and ultimately against the NIST ACVP vectors and the corecrypto oracle.
Build incrementally: one building block at a time, each validated, then composed.
