# mlxpqc — GPU-Accelerating ML-KEM / ML-DSA on Apple Silicon (Metal)

> **Implementation update (2026-09-01):** the "Status: research / feasibility
> analysis (no code yet)" line below and the §5 prototype roadmap now
> describe a *completed* prototype, not a plan — all four roadmap steps
> (SIMD-group Keccak/SHAKE, depth-first NTT, ballot+prefix-sum rejection
> sampling, and the full keygen/sign/verify assembly) are implemented as
> Metal kernels in [`mldsa/`](mldsa/) and validated bit-exact against the
> pq-crystals reference — see [`mldsa/README.md`](mldsa/README.md)'s
> checklist for current status per kernel. This document's technique-mapping
> analysis (§§1–4) remains accurate engineering rationale for *why* each
> choice was made; only its framing as pre-implementation planning is dated.
> Validation against corecrypto/NIST ACVP KATs (vs. the pq-crystals
> reference used so far) is still open.

> **Note:** Apple corecrypto (`../arm/`) is **not included in this repository** — its
> license forbids redistribution. References to `../arm/` below describe a *local,
> read-only correctness oracle*; to reproduce that validation, download corecrypto
> yourself from <https://github.com/apple/corecrypto> (branch `2026-05`). The shipped
> implementation is validated against the public pq-crystals reference instead. See
> [NOTICE.md](NOTICE.md).

**Goal:** assess and plan a Metal (Apple GPU) implementation of post-quantum
lattice cryptography (ML-KEM / FIPS-203, ML-DSA / FIPS-204), by distilling the
*generic* acceleration principles from the CUDA GPU-PQC literature and mapping
each to Apple's Metal execution model.

**Date:** 2026-06-13 · **Status:** research / feasibility analysis (no code yet).

---

## 0. Why this is a reimplementation, not a port

- **NVIDIA cuPQC** is a closed, precompiled binary (NVIDIA SM ISA, nvcc + device
  LTO). There is no source to translate, and its core feature — fusing crypto
  into a caller's CUDA kernel — has no Metal equivalent.
- **Apple corecrypto** (open-sourced 2026-05-22, in [`../arm/`](../arm/)) is the
  *reference and correctness oracle*, but it is **CPU-only** — portable C plus
  hand-written ARM64/NEON assembly, formally verified against the FIPS specs. It
  contains **zero GPU code**.

So a Metal PQC effort is greenfield. corecrypto gives us a formally-verified
functional reference and KAT vectors to validate against; the CUDA papers give
us the GPU algorithmic blueprint. This document fuses the two.

The literature is ~100% CUDA. **No published PQC-on-Apple-GPU baseline exists**
(closest Metal crypto work is ZK/elliptic-curve MSM, not lattices). That is both
the opportunity and the cost: novel work, but no Metal reference to crib.

---

## 1. The single biggest structural difference: unified memory

A large fraction of the CUDA papers' "system-level" optimization exists purely to
hide the **PCIe host↔device transfer**: async `memcpy`, multiple CUDA streams,
pinned memory pools aligned to the L2 cache line, dynamic host-side schedulers
that refill the device.

On **Apple Silicon the CPU and GPU share one physical memory pool**, so:

- host↔device copies **disappear** — the multi-stream / async-memcpy machinery is
  largely unnecessary;
- the "memory pool aligned to 256-byte L2 sectors" tuning becomes an Apple
  cache-line re-tune of much smaller importance;
- you keep the *data-layout discipline* (contiguous byte streams ordered to match
  the hash flow) because it still aids coalescing — but not the transfer plumbing.

This is the one place where the Apple target is **simpler** than CUDA.

---

## 2. The two GPU properties the designs depend on — both present on Apple

| Property the CUDA designs lean on | Apple GPU equivalent | Match |
|---|---|---|
| 32-thread **warp** (lock-step SIMD) | **SIMD-group**, 32 lanes wide | exact |
| **Shared memory** (fast banked scratchpad) | **threadgroup memory** | close (smaller, bank geometry differs) |
| Thread **block** → grid | **threadgroup** → grid | exact |
| Warp shuffle / ballot / vote primitives | `simd_shuffle` / `simd_ballot` / `simd_prefix_inclusive_sum` / `simd_broadcast` | full set present |

Because the SIMD width is **identically 32**, the per-lane data partitioning in
the papers (a 256-coefficient polynomial → 8 coeffs/lane "single-warp" or
2 coeffs/lane "quad-warp") carries over with no re-derivation.

---

## 3. Principle-by-principle: CUDA technique → Metal mapping

Primary source for the detail below: **High-Throughput GPU Dilithium**
([eprint 2024/1365](papers/2024-1365_High-Throughput-GPU-Dilithium.pdf)), with
cross-checks from **cuML-DSA** ([2023/1522](papers/2023-1522_cuML-DSA_server-signing.pdf))
and **HI-Kyber** ([2023/1194](papers/2023-1194_HI-Kyber_GPU.pdf)).

### 3.1 One signature = one warp (parallelization granularity)
Each keygen/sign/verify is a single task owned by **one warp (32 threads)**; many
warps batch as independent blocks. Two variants:
- **SWarp** — 1 warp/block, 8 coeffs/lane in registers, more registers, ~33% max occupancy.
- **QWarp** — 4 warps/block, 2 coeffs/lane, 100% theoretical occupancy, fewer registers.

→ **Metal: direct.** One task per **SIMD-group**; a threadgroup holds 1 (SWarp)
or N (QWarp) SIMD-groups. The register/occupancy trade-off is real on Apple too
and **must be re-tuned** to Apple's occupancy curve.

### 3.2 NTT/INTT: depth-first, register-resident, merged-radix
- Keep coefficients in **registers across NTT levels**; only touch scratchpad at
  level boundaries. SWarp does a **merged radix-8 (3-level)** butterfly.
- **Convergence trick:** the last 5 NTT levels (first 5 of INTT) keep all
  coefficients inside one warp → **drop synchronization**, exchange via registers.
- **Cache the twiddle/root table** in shared memory for batched NTTs.
- HI-Kyber generalizes this as three traversal strategies — **SLM** (sliced layer
  merging), **SDFS-NTT** and **EDFS-NTT** (sliced / entire depth-first search) —
  giving +7.5% / +28.5% / +41.6% over a naïve per-level NTT. The lesson: maximize
  register residency / minimize scratchpad round-trips via depth-first traversal.

→ **Metal: direct, and the convergence trick is *cheaper*.** Registers +
threadgroup memory map 1:1; within a Metal SIMD-group execution is convergent, so
the barrier-free last-levels become pure `simd_shuffle` register exchange — no
`simdgroup_barrier` at all. Twiddles → `threadgroup` or `constant` (free constant cache).

### 3.3 Bank-conflict padding in the NTT exchange  ⚠️ **re-tune**
Strided scratchpad writes between NTT levels cause 8-way (SWarp) / 2-way (QWarp)
**bank conflicts** across 32 banks; fixed by **padding** (e.g. 4 units / 32 coeffs,
1 unit / 8 coeffs) so each lane hits a distinct bank.

→ **Metal: keep the technique, re-derive the constants.** Apple threadgroup
memory is banked, but the **bank count/width is undocumented** and not necessarily
32 — measure empirically (ref: philipturner/metal-benchmarks). *This is the most
Metal-specific unknown in the whole project.*

### 3.4 Modular reduction — Montgomery + Barrett
Constant-time, 32-bit integer intrinsics (`mulhi`, bit-ops).
→ **Metal: direct.** MSL has the full 32-bit integer ALU. Constant-timeness must
be **re-audited** on Apple's ALU (the corecrypto guarantee does not transfer to a GPU rewrite).

### 3.5 SHAKE / Keccak as a warp-cooperative permutation  ★ highest value
The throughput bottleneck. Design: the 25-lane Keccak state spread across
**25 threads, one 64-bit lane each in registers**; **warp-shuffle** exchanges
state every round; round constants in **constant memory**; **wide aligned 8-byte**
loads instead of byte-wise; branch-flattening to kill divergence in absorb/squeeze padding.

→ **Metal: direct, port this first.** `simd_shuffle`/`simd_broadcast` replace
`__shfl_sync`; constants → `constant` address space; wide-load and branch-flatten
are architecture-neutral. SHAKE dominates ML-DSA/ML-KEM cost, so this is where
most of the speedup lives.

### 3.6 Rejection sampling via ballot + prefix-sum  ★ the "impossible" one
Parallelizes the inherently-sequential compare→compact→count without a
precomputed reject-position LUT:
- each lane compares its candidate to the bound → predicate;
- `__ballot_sync` collects 32 predicates into a mask;
- all-accept fast path → write 32, `ctr += 32`;
- reject path → mask lower lanes, `__popc` → write offset (warp prefix-sum
  compaction), `__shfl` broadcasts the running counter from lane 31.

cuML-DSA adds **earlier / rejection-prioritized checking**: reorder the validity
checks so the cheapest, most-likely-to-fail test runs first → abort sooner, less
wasted work; plus "vertical + horizontal" parallelism and early evaluation.

→ **Metal: direct — every primitive exists.** `simd_ballot`,
`simd_prefix_inclusive_sum` / `popcount`, `simd_broadcast`. The data-dependent
control flow people *assume* won't port is fully supported. The
rejection-prioritized reordering is pure algorithm and portable verbatim.

### 3.7 On-the-fly matrix + kernel fusion
Matrix Â generated **column-major on the fly** (never fully materialized);
sampling/packing/unpacking **fused** into the multiply-accumulate so intermediates
stay in registers/scratchpad. Fusion granularity tuned to avoid blowing occupancy
(keep SHAKE-heavy and arithmetic-heavy kernels separate where it helps).

→ **Metal: direct.** Metal compute kernels fuse identically; the "don't over-fuse"
occupancy balance applies, just re-tuned.

### 3.8 Batching, occupancy tail, scheduling
Rejection makes signature cost variable (avg ~4 rounds, worst-case dozens) →
**occupancy collapses at the tail** as most blocks finish and a few stragglers run
alone. CUDA fix: dynamic host-side scheduler refilling idle slots + multi-stream overlap.

→ **Metal: problem remains, solution is lighter.** The straggler/tail problem is
intrinsic to rejection sampling and stays; address it with a persistent-threadgroup
/ refill scheduler via Metal command buffers / indirect command buffers. But the
**transfer-overlap half evaporates thanks to unified memory** (§1).

---

## 4. Summary table

| Technique | Ports to Metal? | Metal mechanism |
|---|---|---|
| Warp-per-task (SWarp/QWarp) | ✅ direct | SIMD-group per task; 1/N per threadgroup |
| Depth-first register-resident NTT | ✅ direct | registers + threadgroup memory |
| Barrier-free last-levels exchange | ✅ *better* | `simd_shuffle`, convergent SIMD-group |
| Bank-conflict padding | ⚠️ re-tune | padding works; bank geometry undocumented |
| Montgomery / Barrett | ✅ direct | MSL 32-bit integer ALU |
| Warp-cooperative Keccak/SHAKE | ✅ direct | `simd_shuffle` + `constant` constants |
| Rejection: ballot + prefix-sum | ✅ direct | `simd_ballot`, `simd_prefix_inclusive_sum`, `simd_broadcast` |
| Rejection-prioritized early abort | ✅ direct | pure algorithm |
| On-the-fly matrix + fusion | ✅ direct | fused compute kernels |
| Memory pool / 256B L2 align | ⚠️ partial | keep stream ordering; drop L2-sector constant |
| Async memcpy / multi-stream | ❎ mostly N/A | **unified memory removes host↔device copies** |
| Dynamic scheduler (tail occupancy) | ✅ needed | command buffers / indirect command buffers |
| Constant-time / side-channel proof | ❎ re-do | corecrypto's proof is CPU-only; re-audit on GPU |

---

## 5. Prototype roadmap

1. **SIMD-group Keccak/SHAKE** — dominant cost, fully portable, validates the
   warp→SIMD-group mapping. Check against corecrypto KATs (`../arm/ccmlkem`, `../arm/ccmldsa`).
2. **Depth-first merged-radix NTT** with empirical bank-padding re-tune — the
   other hot kernel; start from HI-Kyber's EDFS-NTT idea.
3. **Ballot + prefix-sum rejection sampler** (ML-DSA) — proves data-dependent
   control flow on Metal; add cuML-DSA rejection-prioritized ordering.
4. **Batching + tail scheduler** — lean on unified memory; skip the CUDA transfer plumbing.

Validate every kernel for functional equivalence against the formally-verified
corecrypto reference and its KAT vectors before optimizing.

---

## 6. Assets in this repo

- [`../arm/`](../arm/) — Apple corecrypto reference impl (branch `2026-05`):
  `ccmlkem/` (ML-KEM), `ccmldsa/` (ML-DSA), plus `corecrypto_verify/` formal-verification
  material. Portable C + ARM64 asm + KAT vectors. **Correctness oracle.**
- [`papers/`](papers/) — GPU-PQC reference literature (below).

## 7. Sources

| File | Paper | Note |
|---|---|---|
| [2024-1365](papers/2024-1365_High-Throughput-GPU-Dilithium.pdf) | High-Throughput GPU Dilithium (eprint 2024/1365 / arXiv 2211.12265) | primary — full technique set; up to 111×/69× vs 1-core CPU |
| [2023-1522](papers/2023-1522_cuML-DSA_server-signing.pdf) | cuML-DSA (eprint 2023/1522) | server-centric ML-DSA signing; rejection-prioritized; 170–294× |
| [2023-1194](papers/2023-1194_HI-Kyber_GPU.pdf) | HI-Kyber (eprint 2023/1194) | three NTT traversal strategies (SLM/SDFS/EDFS) |
| [2024-095](papers/2024-095_ConvKyber_TensorCore.pdf) | ConvKyber (eprint 2024/095) | Kyber on AI/tensor accelerators (relevant to Apple AMX/ANE angle) |
| [2025-1596](papers/2025-1596_On-GPU-Acceleration-of-PQC.pdf) | On GPU Acceleration of PQC (eprint 2025/1596) | survey + realistic batched throughput numbers |

Apple corecrypto: <https://github.com/apple/corecrypto> (branch `2026-05`) ·
formal-verification blog: <https://security.apple.com/blog/formal-verification-corecrypto/>
