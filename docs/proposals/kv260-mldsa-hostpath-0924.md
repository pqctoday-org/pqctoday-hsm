# KV260 `mldsa` profile: ML-DSA-65 host-path work, model and board plan (2026-09-24)

Branch `feat/mldsa-hostpath-0924`. The objective was to bring the `mldsa`
FPGA profile (bitstream `92490c8b…`, two whole-signature ML-DSA-65 signer
lanes at 250 MHz) close to "about 1,300 signatures/s" through software only.
**Every number below that is not a board measurement is a model** (the
`pqc-rust` container, scaled to the A53). No board was touched.

## 1. What the 522.5 sig/s bench operation is

`pqc-fpga-bench` = `rust/bench-harness` (+ the cacp raw-samples patch). The
timed `sign` closure (`bench-harness/src/main.rs`) is

    C_SignInit(CKM_ML_DSA, no parameter)   -> hedged, empty context
    C_Sign(p_signature = NULL)             -> length query
    C_Sign(buffer)                         -> the signature

on a per-worker session, the same message every call. **No verify is in the
timed loop**, and the engine's `C_Sign` does not verify after signing
(`src/ffi.rs` `C_Sign_impl`). Verify is a separate measured point (1,727
verify/s in the FPGA-enabled 09-19 run); "sign with verification" in the
09-19 JSON means the harness also ran that point and a one-off
sign+verify per tenant during provisioning. `--threads 8` gives four worker
sessions per tenant window; the two tenant windows run one after the other,
so four signing threads are active at a time.

## 2. The hardware ceiling is ~870 sig/s at the mean attempt count, not 1,316

The 1,316 sig/s figure is two lanes x 658/s, from the **three-attempt**
co-simulation fixture (379,819 cycles). The signer's time grows with the
rejection-loop attempts:

| evidence | cycles |
|---|---:|
| 3-attempt fixture, 300 MHz signer (`mldsa65-context-sign-300-hls-summary-20260917.json`) | 379,819 |
| 5-attempt case, dual-signer 300 MHz co-sim (`kv260-mldsa65-dual-signer300-offline-summary-20260917.json`: min 15,780 = LOAD, max 565,275 = SIGN, average 290,527 = their mean) | 565,275 |
| per extra attempt | 92,728 |

ML-DSA-65 needs 5.1 attempts on average (4,000 hedged signatures through
fips204's loop in the container: mean 5.18; 3,000: 5.05; the 09-14 board
phase trace: 4.99; geometric, 20% accepted at the first attempt). At 5.1:
194,363 + 92,728 x 4.1 = 574,548 cycles = **2.30 ms at 250 MHz = 435/s per
lane, 870/s for two lanes**, before the DMA DISPATCH/PUBLISH phases and any
host time. With the DMA phases the lanes top out at 761/s (DMA 0.35 ms per
signature) to 578/s (1.2 ms). Reaching ~1,300/s therefore needs the A53
cores to sign on the CPU **at the same time** as both lanes run.

## 3. Method

* `pqc_hw::mldsa_sign_sim` simulates a signer lane as the HLS sources define
  it (DISPATCH validation, output clear, secret copy + input clear, LOAD
  generation binding, PUBLISH completion + signature + bank scrub, ABORT),
  with a modelled latency and no cryptography on the caller's thread (or,
  for tests, fips204's own loop as the reference backend).
* `examples/mldsa_hostpath_profile.rs` runs the real engine path above
  against it with per-stage timing (`pqc_hw::stage`, fips204 stage hook).
  `both` mode alternates blocks of simulated-FPGA and CPU-only signatures
  over one deterministic message sequence (5.245 attempts on average) in one
  process: on this shared, heavily loaded Mac the absolute times drift, so
  the **ratio host path / CPU-only signature** is what carries to the board.
* A53 scaling: the board's CPU-only signature at the 09-19 build (opt-level
  s) is 8.52 ms (09-16, one worker, 117.4/s), i.e. ~8.69 ms at 5.245
  attempts; the container's median CPU-only signature at the same flags was
  549.5 µs: **factor 15.8**. Opt-level-3 A53 figures assume the container's
  opt-3/opt-s CPU-only ratio (0.63-0.73) carries over: an assumption.

## 4. Stage breakdown per FPGA signature (model, A53-scaled, opt-level s)

Container µs (median run of 5) x 15.8. Device time (DISPATCH, SIGN,
PUBLISH) is hardware and not in this table.

| stage | before (`89f0e1a2`) | after (`HEAD`) |
|---|---:|---:|
| PKCS#11 entry (C_SignInit + 2 x C_Sign, object lookup) | 0.16 ms | 0.03 ms |
| private-key decode (skDecode + 17 NTTs) + zeroize on drop | 0.56 ms | - (cached) |
| expanded-key cache lookup (SHA-256 of 4,032 B) | - | 0.02 ms |
| ExpandA | 1.19 ms | - (cached) |
| mu, rho' | 0.02 ms | 0.02 ms |
| flatten Â/s1/s2/t0 into Vecs | 0.32 ms | - |
| 30 KB matrix compare / id compare | 0.013 ms | ~0 |
| encode into DMA buffer | 0.025 ms | 0.022 ms |
| cache syncs | 2 x (3 sysfs open/write/close), 36,205 B cleaned | 2 x 1 ioctl, 17,792 B cleaned |
| wait for DISPATCH + SIGN + PUBLISH | **spinning: the core is busy for all of it** | 20 µs spin, then blocked on the UIO interrupt |
| **host CPU per FPGA signature (excl. syncs)** | **2.33 ms** | **0.12 ms** |

Opt-level 3 (the appliance flags since 09-23): before 0.256 x CPU-only,
after 0.023 x CPU-only; ~7 µs of container time either way, ~0.11 ms on the
A53. Measured ratios, median (5 runs): opt-s 0.269 -> 0.085 (key cache) ->
0.0135 (direct DMA) -> 0.0138 (final); opt-3 0.256 -> 0.044 -> 0.022 ->
0.023. Thread CPU per FPGA signature with a modelled 250 MHz signer, one
worker, container time (two runs on the loaded host): 3,188 / 3,468 µs
spinning (the whole device time), 206 / 355 µs with the interrupt wait. The
container cannot measure the wake-up latency the interrupt adds (its timers
overshoot by milliseconds under the host's load); the board A/B must.

## 5. Throughput model

Discrete-time model (a scratch script, not committed; parameters below): workers loop prelude (CPU) -> try a free lane (never
wait) -> lane: host CPU + DMA device time D + signer time F(attempts)
(spinning or blocked) | no lane: CPU rejection loop; processor-shared over
4 cores; 4-core contention factor 1.16 (CPU-only 1 -> 4 workers on the
board).

Validation against the board:

| run | board | model |
|---|---:|---:|
| CPU-only, 1 worker (calibration) | 117.4 | 117.6 |
| CPU-only, 4 workers (calibration) | 404.4 | 413.1 |
| 09-16 one lane 300 MHz, 1 worker (calibrates D + syncs = 0.49 ms) | 205.2 | 207.5 |
| 09-16 one lane 300 MHz, 4 workers (**independent**) | 535.1 | 526.1 |
| 09-19 two lanes 250 MHz, 4 workers, D = 0.35 ms (clock-scaled) | 522.5 | 590.0 |
| same, D = 1.2 ms (fitted) | 522.5 | 525.2 |

The dual-lane point is only reproduced with ~1.2 ms of DMA device time per
signature (both lanes' DMA share the HPC0 SmartConnect), or with other
unmodelled losses; D is the largest unknown and is bracketed below.

Predictions, 4 workers (the bench), sig/s:

| configuration | D = 0.35 ms | D = 1.2 ms |
|---|---:|---:|
| before, opt-s (09-19 as built) | 590 | 525 |
| before code, opt-3 flags only | 714 | 641 |
| after, opt-s, spin | 994 | 829 |
| after, opt-s, interrupt (50 / 200 µs wake) | 982 | 803 |
| after, opt-3, spin | 1,087 | 934 |
| after, opt-3, interrupt (50 / 200 µs wake) | 1,075 | 899 |
| after, opt-3, interrupt, **6 workers** | 1,408 | 1,248 |
| after, opt-3, interrupt, 8 workers | 1,391 | - |
| after, opt-3, spin, 6 workers | 1,189 | - |
| two lanes alone, zero host cost | 761 | 578 |
| CPU-only, opt-3 + key cache | 775 | 775 |

**Prediction for the 4-worker bench: 900-1,090 sig/s (1.7-2.1x the 522.5
measured), medium-low confidence.** The lanes now run at 93-95% of their
hardware + DMA capacity; host code is no longer what limits them. The gap to
~1,300 at 4 workers is CPU capacity: two of the four threads hold lanes, so
only two cores sign on the CPU. With 6 workers per window and interrupt
waits the model reaches 1,250-1,410. Unmeasured inputs, in order of weight:
D, the opt-3 A53 speed-up, the interrupt wake-up latency, the ioctl sync
cost.

## 6. What changed (commits on `feat/mldsa-hostpath-0924`)

1. `pqc-hw`: transport-generic `SignLane`, the lane simulator, stage profiler.
2. Profile harness, fips204 stage hook and reference loop, engine lane pool
   (device or simulated lanes), `PQC_HW_STAGE_PROFILE=1` report at `C_Finalize`.
3. Per-key expanded signing context (`fips204::ExpandedPrivateKey`,
   `crypto::mldsa_keycache`): decode + ExpandA once per key; zeroized on
   drop, on every key-lifecycle PKCS#11 call and at exit; <= 32 keys.
4. Inputs written straight into the DMA buffer; lanes track the resident
   matrix by ρ and keys prefer the lane holding their matrix; only the
   device-read bytes are cleaned; no output zero-fill (the DMA controller
   clears it; completions are matched by request id).
5. One u-dma-buf ioctl per sync instead of three sysfs writes.
6. Interrupt-driven completion (UIO) with spin-first, lazy arming, and a
   fallback to sleep-polling for a line that never fires.

Signatures stay byte-identical: FIPS 204 ACVP sigGen/keyGen/sigVer vectors
(fips204, with and without hw-accel), the 20 ML-DSA-65 sigGen vectors
through the simulated device, hook on/off (ML-DSA, HashML-DSA, hedged with
fixed rnd), expanded vs decoded keys for all parameter sets.

Not done, and why: pipelining the next request into a lane while it signs
(the lane's idle gap is now the worker's 0.1 ms prelude, ~4% of a lane
cycle, and at 4 workers a second FPGA-bound request costs a CPU signer);
PKCS#11 trimming (0.03 ms per signature left).

## 7. Proposals

Software (not implemented):

* **More concurrent callers than cores.** The 4-worker window caps the
  appliance at 2 CPU signers while both lanes are busy. With interrupt waits
  the model gives 1,250-1,410 sig/s at 6 workers. Bench change only
  (`--threads 12`).
* **Parallel speculative rejection attempts on idle cores** for CPU signing:
  attempts are independent functions of κ, so helpers can evaluate κ+1, κ+2
  while the caller evaluates κ and the lowest accepted κ wins
  (byte-identical). At 4 workers with interrupt waits two cores sit idle;
  2-way speculation cuts a CPU signature's rounds from 5.1 to 2.83 (+11%
  work) and the model gives ~+250 sig/s, i.e. ~1,300 at 4 workers. It must
  draw helpers from the one process-wide core budget fips205 already uses
  (owner decision 2026-09-24), which today lives inside fips205.

Bitstream / overlay (not implemented, need a new build):

* **DMA controller bursts.** `mldsa65_dma_controller.cpp` reads and clears
  the 17.5 KB secret input and writes the signature through a `volatile
  uint32_t*` m_axi port; Vitis HLS does not infer bursts on volatile
  pointers, so these are likely single-beat 32-bit transactions (the 09-13
  Keccak driver review suspected the same beat-bound pattern there; neither
  is confirmed from a synthesis report). The model needs ~1.2 ms of
  DMA time per signature to reproduce the 09-19 result. Check `csynth.rpt`
  burst inference; drop `volatile`, use `memcpy`-style bursts and a 64/128-bit
  port. Up to +30% lane throughput if D is near 1.2 ms.
* **Per-lane secret residency.** Load s1/s2/t0 with the matrix (LOAD) and
  send only mu and rho' (128 B) per signature: removes the 17.5 KB read and
  clear from every DISPATCH and the host encode. Needs 17 KB BRAM per lane
  and scrub-on-context-change; ABI v3.
* **Coherent DMA** (HPC port with snooping AxCACHE/AxPROT + `dma-coherent`
  on the u-dma-buf nodes): removes both cache syncs. After the ioctl change
  this is worth tens of µs per signature (<2%); low priority.
* The only ways to raise the 870/s FPGA-only ceiling: close 300 MHz (+20%),
  fewer cycles per attempt, or a third lane (BRAM is at 95% with the TCN).

## 8. What to measure on the board

Build the engine from this branch at opt-level 3 with `hw-accel` (no new
crates: `crates.inc` unchanged), `mldsa` profile, TCN service on as on
09-19.

1. `PQC_HW_STAGE_PROFILE=1 PQC_HW_DIAGNOSTICS=1 pqc-fpga-bench --library
   /usr/lib/softhsm/libsofthsmrustv3.so --algorithms ML-DSA-65 --threads 8
   --duration-secs 10 --warmup-secs 1` -> stderr at `C_Finalize`: `PQC_HW_STAGE` means of
   `dispatch` + `publish` (= **D**), `signer_wait` (F + wake-up; compare with
   2.30 ms at 5.1 attempts), `sync_for_device`/`sync_for_cpu` (ioctl cost),
   `encode`, `context_lookup`; `PQC_HW_LANE` `mean_attempts`, `interrupts`
   vs `missed_interrupts` (**IRQ wiring check**: misses > 0 with 0
   interrupts means the lines do not fire and the lane fell back to sleep).
2. Throughput, 2 x 10 s windows each, same image:
   `--threads 8` and `--threads 12`, each with `PQC_HW_MLDSA_WAIT=irq`
   (default) and `=spin`; plus `PQC_HW_DMA_SYNC=sysfs` once.
   Record sig/s, p50/p99, the FPGA share (lane `signs` / total), `mpstat`
   per-core utilisation, SoC temperature.
3. CPU-only baseline on the same image: `PQC_HW_DISABLE=1`, `--threads 8`
   (validates the opt-3 + key-cache CPU rate, model 775 sig/s).
4. Byte identity on the board: a deterministic (`CKH_DETERMINISTIC_REQUIRED`)
   ML-DSA-65 signature with `PQC_HW_DISABLE=1` and without must match.
5. Feed D, the attempts, the wake-up and the CPU-only rate back into the
   model; the 4-worker prediction above is 900-1,090 sig/s.
