# mlxpqc — Metal Acceleration Test Plan (ML-KEM / ML-DSA)

> **Note:** Apple corecrypto (`../arm/`) is **not included in this repository** (its
> license forbids redistribution). `../arm/` references below describe a *local,
> read-only oracle*; download corecrypto yourself from
> <https://github.com/apple/corecrypto> (branch `2026-05`) to reproduce that path.
> The shipped code is validated against the public pq-crystals reference. See
> [NOTICE.md](NOTICE.md).

Companion to [ANALYSIS.md](ANALYSIS.md). This plan turns each acceleration
principle distilled from the CUDA GPU-PQC literature into a **buildable,
measurable Metal experiment**. Every mechanism gets the same seven fields:

> **Mechanism** · **Metal features** · **White-paper reference** · **Baseline** ·
> **Expected acceleration** · **Implementation plan** · **Test plan**

**Status:** test design (no kernels written yet) · **Date:** 2026-06-13.

---

## 0. Common measurement methodology

So every per-mechanism number means the same thing, all sections share two
baselines and one harness.

**Hardware targets** — both machines are first-class test platforms; every
mechanism is measured and reported on each.
- **M5 Max (128 GB)** — highest-capability GPU; the upper-bound / primary
  acceleration target. Note the M5 generation adds per-core GPU neural
  accelerators (matrix units) — directly relevant to **M9**.
- **M4 Pro (48 GB)** — the broad-deployment target; a substantially larger GPU
  than the base M4, so a meaningful second data point rather than just a
  lower-bound.
- The two are likely **different `MTLGPUFamily` generations**, so cross-machine
  divergence is an expected output, not noise — especially for **M3** (bank
  geometry) and **M9** (matrix-unit viability).
- Record `threadExecutionWidth` (expected 32), `maxTotalThreadsPerThreadgroup`,
  threadgroup-memory size, GPU core count, and `MTLGPUFamily` per machine before
  any run.

**Two baselines (used by every section)**
- **CPU-REF** — Apple corecrypto single-thread (portable C + ARM64/NEON) from
  [`../arm/ccmlkem`](../arm/ccmlkem/), [`../arm/ccmldsa`](../arm/ccmldsa/), built
  release, pinned to a P-core. Gives amortized latency + ops/s per primitive.
  This is also the **functional oracle** (its KATs gate every kernel).
- **GPU-NAIVE** — the simplest *correct* Metal kernel for the mechanism under
  test (e.g. one thread per task, per-level NTT, byte-wise Keccak). Isolates the
  contribution of the optimization from the contribution of "being on a GPU."

**Reporting rule** — per-mechanism micro-optimizations are reported **vs
GPU-NAIVE** (isolates the trick); end-to-end KEM/DSA throughput is reported **vs
CPU-REF** (the number that matters to a user). Paper figures are NVIDIA-measured
and quoted as **directional targets only** — Apple results are the deliverable.

**Harness & profiling**
- Timing: `MTLCommandBuffer.GPUStartTime/GPUEndTime` for wall-clock; warm-up
  ≥3 dispatches, report median of ≥50, batch sizes {1, 256, 4 K, 64 K}.
- Counters: `MTLCounterSampleBuffer` (occupancy, ALU vs memory-limited),
  Instruments "Metal System Trace", Xcode GPU capture — the Nsight-Compute analog.
- Prototyping harness: **MLX `mx.fast.metal_kernel`** to JIT custom Metal source
  from Python (fast iteration on the M5 Max MLX stack) before committing kernels
  to a standalone `.metallib`.
- Correctness: bit-exact vs corecrypto KAT vectors ([`../arm/.../kat/`](../arm/))
  on every kernel, every batch size, both machines. No perf number is valid
  until the KAT passes.

---

## M1. SIMD-group task parallelism (one operation = one SIMD-group)

**Mechanism.** Map each keygen/encaps/decaps/sign/verify to a single **32-lane
SIMD-group**, and batch thousands as independent threadgroups. A 256-coefficient
polynomial is partitioned across the 32 lanes (8 coeffs/lane "single-group" or
2 coeffs/lane "quad-group"). This yields coalesced memory access, intra-group
register sharing for the sequential steps, and massive batch parallelism.

**Metal features.** SIMD-group as the unit of work (`threadExecutionWidth == 32`
matches the warp exactly); threadgroup sized to 1 SIMD-group (SWarp-equiv) or
4 (QWarp-equiv); `[[thread_index_in_simdgroup]]`, `[[simdgroup_index_in_threadgroup]]`;
function constants to specialize per parameter set (512/768/1024, 44/65/87).

**White-paper reference.** [2024-1365](papers/2024-1365_High-Throughput-GPU-Dilithium.pdf)
§3 (warp-per-task, SWarp vs QWarp, occupancy analysis).

**Baseline.** GPU-NAIVE = one *thread* per task (scalar, no lane cooperation) —
the layout prior work showed to be uncoalesced and IO-bound.

**Expected acceleration.** Directional: the warp-level layout is the foundation
of the papers' 69–294× end-to-end gains. Isolated, expect the SIMD-group layout
to beat one-thread-per-task by a **large multiple at batch ≥4 K** (memory
coalescing + occupancy). Deliverable: the SWarp/QWarp occupancy curve **measured
on Apple**, since register pressure differs from sm_86.

**Implementation plan.**
1. Define the lane↔coefficient mapping for both 8/lane and 2/lane variants.
2. Build a no-op "transport" kernel (load → lane-distribute → store) to measure
   pure coalescing/occupancy without arithmetic.
3. Sweep threadgroup = {1,2,3,4} SIMD-groups × parameter sets; capture occupancy
   and register count from counters.

**Test plan.** Throughput vs batch {1,256,4 K,64 K} for both variants on M4 Pro / M5 Max;
plot occupancy vs registers-per-thread; pick SWarp/QWarp crossover point per
parameter set. Pass = SIMD-group layout ≥ GPU-NAIVE at every batch ≥256 and the
occupancy table is reproduced on both machines.

---

## M2. Register-resident depth-first NTT / INTT

**Mechanism.** The NTT is the arithmetic hot loop. Keep coefficients in
**registers across multiple butterfly levels** (merged radix-8 / depth-first
traversal), touching the scratchpad only at level boundaries; cache the twiddle
table. Exploit that the last 5 NTT levels (first 5 of INTT) keep all coefficients
inside one SIMD-group → exchange via shuffle with **no barrier**.

**Metal features.** Per-lane registers for the merged butterflies; `simd_shuffle`
/ `simd_shuffle_xor` for the barrier-free intra-group levels; `threadgroup` memory
for cross-group level exchange; twiddles in `constant` (free constant cache) or
`threadgroup`; `simdgroup_barrier(mem_flags::mem_threadgroup)` only where groups cross.

**White-paper reference.** [2024-1365](papers/2024-1365_High-Throughput-GPU-Dilithium.pdf)
§3.2 (merged-radix, last-5-levels barrier-free); [2023-1194 HI-Kyber](papers/2023-1194_HI-Kyber_GPU.pdf)
§ NTT (SLM / SDFS-NTT / EDFS-NTT traversal strategies).

**Baseline.** GPU-NAIVE = textbook per-level NTT, full threadgroup-memory
round-trip + barrier between every level (HI-Kyber's "native NTT").

**Expected acceleration.** HI-Kyber reports, over native NTT: **SLM +7.5%,
SDFS-NTT +28.5%, EDFS-NTT +41.6%**. Target on Apple: reproduce the *ordering*
(EDFS > SDFS > SLM > naive) and aim for ≥25% over GPU-NAIVE; the barrier-free
last-5-levels should show up directly as fewer `simdgroup_barrier`s in the trace.

**Implementation plan.**
1. Implement native (M2-naive), then SLM, SDFS, EDFS variants behind a function constant.
2. Replace last-5-level threadgroup exchange with `simd_shuffle` register exchange.
3. Move twiddles to `constant`; verify constant-cache hit in counters.

**Test plan.** Standalone NTT/INTT micro-benchmark (kops/s) for all four variants
× both machines; verify round-trip `INTT(NTT(x)) == x` and match corecrypto's
NTT intermediate values. Capture barrier count and ALU/mem ratio. Pass = EDFS ≥25%
over naive and the variant ordering matches the paper.

---

## M3. Bank-conflict-free threadgroup-memory layout

**Mechanism.** Strided polynomial writes between NTT levels collide on
shared-memory banks (8-way / 2-way conflicts), stalling the memory pipeline. Fix
by **padding** the layout so each lane in a SIMD-group lands in a distinct bank.

**Metal features.** `threadgroup` array padding; profiling via memory-pipeline
counters. **Caveat:** Apple's threadgroup-memory bank count/width is *undocumented*
and not assumed to be 32 — the padding constants must be **measured, not copied**.

**White-paper reference.** [2024-1365](papers/2024-1365_High-Throughput-GPU-Dilithium.pdf)
§3.2 Fig.2 (pad 4 units/32 coeffs and 1 unit/8 coeffs in SWarp; 8/16-unit pads in QWarp).

**Baseline.** GPU-NAIVE = M2 EDFS-NTT with **no padding** (conflicts present).

**Expected acceleration.** On NVIDIA this is folded into the NTT speedups above
(removes the pipeline stalls that otherwise cap memory throughput). Apple-specific
deliverable: a **measured conflict map** + the padding stride that flattens it;
expect a measurable memory-pipeline-stall drop and a few-percent-to-double-digit
NTT throughput recovery once conflicts are removed.

**Implementation plan.**
1. Micro-probe: a kernel doing only strided threadgroup access at stride
   s ∈ {1..33}; sweep to reverse-engineer Apple's bank structure (ref
   philipturner/metal-benchmarks method).
2. Derive padding stride; apply to M2; re-measure.

**Test plan.** Plot threadgroup-access latency vs stride to expose the bank
period; confirm NTT memory-stall counter drops after padding; A/B NTT throughput
padded vs unpadded on M4 Pro and M5 Max (bank structure may differ across GPU
families — record both). Pass = stalls measurably reduced and no correctness change.

---

## M4. Constant-time vectorized modular reduction

**Mechanism.** Every butterfly/point-mult needs fast modular reduction mod q
(Montgomery + Barrett), branch-free and data-independent (constant-time).

**Metal features.** MSL 32-bit integer ALU (`mulhi`, shifts, masks); `uint`/`int`
per-lane scalars; no branches on secret data. Note: GPU constant-timeness is **not
inherited** from corecrypto's CPU proof and must be argued separately.

**White-paper reference.** [2024-1365](papers/2024-1365_High-Throughput-GPU-Dilithium.pdf)
§ background (Montgomery/Barrett, constant-time); corecrypto C as the reference
arithmetic ([`../arm/ccmlkem/src/ccmlkem_ntt.c`](../arm/ccmlkem/src/ccmlkem_ntt.c),
[`../arm/ccmldsa/src/ccmldsa_ntt.c`](../arm/ccmldsa/src/ccmldsa_ntt.c)).

**Baseline.** GPU-NAIVE = `%`/`/` operator reduction (correct but slow, possibly
variable-latency).

**Expected acceleration.** Montgomery/Barrett vs hardware modulo is typically a
**several-× per-reduction** win and removes a divider dependency; the real payoff
is that it unblocks M2 (NTT becomes ALU-bound, not divide-bound).

**Implementation plan.** Implement Montgomery and Barrett as `inline` device
functions; specialize q per scheme via function constants; unit-test each against
corecrypto reduction over the full residue range.

**Test plan.** Exhaustive/structured correctness vs corecrypto for all inputs in
range; micro-benchmark reductions/s vs operator-modulo; inspect generated ISA
(Xcode) for absence of secret-dependent branches. Pass = bit-exact + no
divider/branch on the secret path.

---

## M5. SIMD-cooperative Keccak / SHAKE (the XOF, dominant cost)

**Mechanism.** SHAKE128/256 is the throughput bottleneck (sampling, hashing).
Spread the 25-lane Keccak state across **25 lanes (one 64-bit word each, in
registers)**; exchange state every round via shuffle; wide aligned 8-byte
loads/stores; flatten the absorb/squeeze padding branches to kill divergence;
round constants in constant memory.

**Metal features.** `simd_shuffle` / `simd_broadcast` for per-round state
exchange (replaces `__shfl_sync`); `constant` for round constants; `ulong`
(64-bit) lane state; vectorized `packed_uint2`/aligned loads instead of byte-wise;
branchless padding.

**White-paper reference.** [2024-1365](papers/2024-1365_High-Throughput-GPU-Dilithium.pdf)
§3.3 (25-thread warp-shuffle Keccak, wide aligned IO, branch-flattening);
[2023-1194](papers/2023-1194_HI-Kyber_GPU.pdf) (Keccak in the Kyber pipeline).

**Baseline.** GPU-NAIVE = one-thread-per-Keccak, byte-wise IO, full 1600-bit
state in local memory (the design the paper explicitly improves on).

**Expected acceleration.** This is the highest-value kernel: in the paper SHAKE
is the largest resource consumer, and the cooperative design is what makes the
end-to-end 69–294× possible. Target: SIMD-cooperative SHAKE **multiple-× over
GPU-NAIVE** and a sharp drop in register spill + memory-pipeline pressure.

**Implementation plan.**
1. Implement the 25-lane permutation with per-round `simd_shuffle`.
2. Add absorb/squeeze with wide aligned IO + branchless padding.
3. Expose SHAKE128/256 and the ML-KEM/ML-DSA-specific XOF call shapes.

**Test plan.** KAT against FIPS-202 / corecrypto SHAKE vectors at many output
lengths; throughput (bytes/s and XOF-calls/s) vs GPU-NAIVE at batch {256,4 K,64 K};
counters for register spill + MIO pressure. Pass = KAT-exact and clearly beats
GPU-NAIVE on both machines. **Prioritize this section first.**

---

## M6. Parallel rejection sampling (ballot + prefix-sum) with early abort

**Mechanism.** Rejection sampling and norm-checks are inherently sequential
(compare→compact→count, each step depends on the last). Parallelize across the
SIMD-group: each lane tests its candidate; a ballot collects all 32 predicates;
all-accept → write 32; reject → prefix-popcount gives each survivor its compacted
write offset, and the running counter is broadcast from the last lane.
**Rejection-prioritized ordering** runs the cheapest/most-likely-to-fail check
first to abort earlier.

**Metal features.** `simd_ballot` (→ vote mask), `simd_prefix_inclusive_sum` /
`popcount` (stream-compaction offsets), `simd_broadcast` (counter handoff),
`simd_all`/`simd_any` (fast path). All present in MSL.

**White-paper reference.** [2024-1365](papers/2024-1365_High-Throughput-GPU-Dilithium.pdf)
§3.4 + Alg.4 (ballot/popc/shfl rejection); [2023-1522 cuML-DSA](papers/2023-1522_cuML-DSA_server-signing.pdf)
§ "earlier rejection" / rejection-prioritized checking order + vertical/horizontal parallelism.

**Baseline.** GPU-NAIVE = scalar single-lane rejection loop with a serial counter
(or the LUT-precompute approach, noting its bandwidth cost).

**Expected acceleration.** cuML-DSA attributes its **170–294×** server signing
largely to rejection optimization + early abort. Isolated target: the SIMD
ballot/prefix-sum compaction should remove the serialization and divergence;
early-abort ordering cuts average wasted rounds (avg ≈4, worst-case dozens).

**Implementation plan.**
1. Implement `ExpandA`/`ExpandS` rejection with ballot + `simd_prefix_inclusive_sum`.
2. Add ML-DSA signing norm-checks in rejection-prioritized order (cheapest first).
3. Measure average rounds-to-accept and divergence.

**Test plan.** Distribution test — sampled coefficients must match corecrypto's
uniform output bit-for-bit given the same XOF stream; benchmark vs scalar baseline;
record average rejection rounds and SIMD divergence counter with/without
prioritized ordering. Pass = identical samples to corecrypto + measured divergence
reduction.

---

## M7. On-the-fly matrix expansion + kernel fusion

**Mechanism.** Generate the public matrix Â **column-major on the fly** (never
materialize the whole matrix) and **fuse** sampling/packing/unpacking into the
matrix-vector multiply-accumulate, keeping intermediates in registers/threadgroup
memory. Tune fusion granularity so SHAKE-heavy stages don't crush arithmetic occupancy.

**Metal features.** Single fused compute kernel chaining XOF→sample→NTT→pointwise
→accumulate; register/`threadgroup` residency for intermediates; function
constants to switch row-major (sign) vs column-major (keygen/verify) flows.

**White-paper reference.** [2024-1365](papers/2024-1365_High-Throughput-GPU-Dilithium.pdf)
§3.5–§4.2 (on-the-fly inner product, finely-tuned fusing strategy).

**Baseline.** GPU-NAIVE = separate kernels per stage with full Â materialized in
device memory (extra allocation + global-memory traffic + launch overhead).

**Expected acceleration.** Removes Â storage and inter-kernel global traffic; the
paper shows fusion is what keeps the hot data in registers/SMEM. Target: lower
device-memory footprint (no full Â) and reduced global-memory bytes/op; net
end-to-end throughput gain on top of M2/M5.

**Implementation plan.**
1. Build fused keygen (column-major, on-the-fly Â) and fused sign rejection loop.
2. Sweep fusion granularity (how many stages per kernel) for occupancy.

**Test plan.** End-to-end keygen/sign/verify KAT vs corecrypto; compare
device-memory high-water-mark and global-memory bytes (counters) fused vs
unfused; throughput at batch {4 K,64 K}. Pass = KAT-exact, lower memory traffic,
no occupancy regression.

---

## M8. Unified-memory zero-copy batching

**Mechanism.** On Apple Silicon CPU and GPU share physical memory, so the
host↔device staging/copy that dominates CUDA "system-level" tuning (pinned pools,
async memcpy, multi-stream overlap) is **eliminated**. Inputs/outputs are written
and read in place; keep the contiguous stream ordering for coalescing.

**Metal features.** `MTLResourceStorageModeShared` (zero-copy on Apple Silicon);
in-place CPU fill / GPU consume with no blit; persistent reusable buffers (avoid
per-batch alloc); `MTLHeap` for pooling. Keep the paper's stream-ordering layout,
drop the 256-byte/L2-sector constant (re-tune to Apple cache line).

**White-paper reference.** [2024-1365](papers/2024-1365_High-Throughput-GPU-Dilithium.pdf)
§3.6 + §4.3 (memory pool, async memcpy, streams) — here as the **work we delete**;
[2025-1596](papers/2025-1596_On-GPU-Acceleration-of-PQC.pdf) (batched throughput
context, ~18× at batch 60 K).

**Baseline.** GPU-EXPLICIT = a deliberately CUDA-style path using
`StorageModePrivate` + explicit blit copies, to **quantify the copy cost Apple avoids**.

**Expected acceleration.** Expect the shared-mode path to remove the entire
transfer term — measure it as the delta vs GPU-EXPLICIT (the copy time that simply
vanishes), and confirm batched end-to-end approaches the survey's ~18× CPU-REF
order at large batch.

**Implementation plan.** Allocate shared persistent IO buffers; lay seeds/streams
contiguously per task; run a full batched sign/verify with no blits; A/B against
the explicit-copy path.

**Test plan.** Measure end-to-end latency incl. IO for shared vs explicit-copy at
batch {4 K,64 K} on M4 Pro / M5 Max; confirm zero blit time in the trace for shared
mode; end-to-end throughput vs CPU-REF. Pass = shared mode ≥ explicit-copy at all
batches and copy term ≈0 in trace.

---

## M9. Matrix-unit polynomial multiply (exploratory: ConvKyber → simdgroup_matrix / MLX)

**Mechanism.** ConvKyber recasts Kyber's polynomial arithmetic to exploit
**tensor/matrix accelerators** (treating NTT/point-mult as small matmuls). Apple
GPUs expose SIMD-group matrix multiply units; MLX already drives them for ML.
Worth a feasibility spike: can the polynomial multiply beat the M2 NTT path on
Apple's matrix units?

**Metal features.** `simdgroup_matrix<T,8,8>` load/multiply/store (Apple GPU
matrix ops); MLX matmul primitives via `mx.fast.metal_kernel` for rapid trials.
Integer-vs-float feasibility must be checked (matrix units are float-centric;
Kyber/Dilithium are integer mod q) — this is the open risk.

**White-paper reference.** [2024-095 ConvKyber](papers/2024-095_ConvKyber_TensorCore.pdf)
(1.2–3.6× over prior tensor-core Kyber for polyvec_ntt/KeyGen/Enc/Dec).

**Baseline.** The M2 EDFS-NTT SIMD-ALU path (best non-matrix NTT).

**Expected acceleration.** ConvKyber reports up to 3.55× (Dec, Kyber-1024) over
prior tensor-core work — but that is float tensor cores; on Apple the **first
question is correctness/viability for integer mod-q**, then any speedup over M2.
Treat as research, not a committed target.

**Implementation plan.** Prototype a single polyvec point-multiply as a
`simdgroup_matrix` op in MLX; check exactness mod q; if viable, compare to M2.

**Test plan.** Correctness mod q vs corecrypto first (gate); only if exact, A/B
throughput vs M2 EDFS-NTT. Pass = exact and faster than M2, else documented as
not viable on current Apple matrix units.

---

## M10. GPU-driven batch scheduling for the rejection tail

**Mechanism.** Variable rejection rounds (avg ≈4, worst-case dozens) cause an
**occupancy collapse at the tail**: most tasks finish, a few stragglers run a
near-empty GPU. Refill idle slots with fresh tasks (the role of CUDA's dynamic
scheduler) — but driven on-GPU since unified memory removes the host round-trip.

**Metal features.** Indirect Command Buffers (`MTLIndirectCommandBuffer`) for
GPU-encoded relaunch; persistent-threadgroup pattern with an atomic work-queue
counter (`atomic_uint` in device memory) so finished SIMD-groups pull the next task.

**White-paper reference.** [2024-1365](papers/2024-1365_High-Throughput-GPU-Dilithium.pdf)
§4 Fig.6 & Fig.8 (SM occupancy decay in the rejection loop; dynamic task scheduler).

**Baseline.** Static batch dispatch (one task per SIMD-group, no refill) — exhibits
the tail idle.

**Expected acceleration.** Recovers the wasted tail occupancy; expected to matter
most at large batch where the straggler tail is proportionally cheap to refill.
Target: higher sustained occupancy and shorter batch completion vs static dispatch.

**Implementation plan.** Add an atomic task-queue; persistent threadgroups loop
pulling tasks until the queue drains; optional ICB relaunch for multi-wave batches.

**Test plan.** Occupancy-over-time trace static vs work-queue at batch {4 K,64 K};
batch completion time; verify no double-processing/lost tasks via output count.
Pass = flatter occupancy tail + faster completion, identical outputs.

---

## 11. Cross-cutting acceptance criteria

- **Correctness gates everything:** no perf number is recorded until the kernel is
  bit-exact vs corecrypto KATs (`../arm/.../kat/`) for the relevant parameter set.
- **Two machines:** every result reproduced on M4 Pro and M5 Max; divergences (esp.
  M3 bank geometry, M9 matrix viability) documented per GPU family.
- **Constant-time review** (M4, M5, M6): inspect ISA for secret-dependent branches/
  addressing; corecrypto's CPU proof does **not** carry to the GPU.
- **Report card** per mechanism: baseline, achieved speedup, occupancy, ALU/mem
  ratio, and whether the paper's directional target was met on Apple.

## 12. Suggested sequencing

1. **M1** (layout) + **M4** (reduction) — foundation everything else needs.
2. **M5** (SHAKE) — biggest single win; validates SIMD-cooperative pattern.
3. **M2 + M3** (NTT + bank padding) — second hot kernel + the one Apple unknown.
4. **M6** (rejection) — unblocks ML-DSA signing.
5. **M7 + M8** (fusion + zero-copy) — end-to-end throughput.
6. **M10** (tail scheduler), then **M9** (matrix-unit) as research spikes.

## 13. References

All papers in [`papers/`](papers/); reference implementation + KATs in
[`../arm/`](../arm/). See [ANALYSIS.md](ANALYSIS.md) for the full principle→Metal
mapping and the unified-memory rationale.
