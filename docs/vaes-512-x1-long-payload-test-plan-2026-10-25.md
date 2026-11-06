# X1 VAES-512 AES-GCM long-payload test plan

## Decision

Determine whether the X1 Pro's VAES-512 path improves the current PKCS#11
AES-GCM workload at **64 KiB and 1 MiB** payload sizes, compared with the
normally dispatched AES-NI build.  Do not replace the deployed provider or
publish a VAES gain unless this experiment supplies comparable correctness,
compiled-code, dispatch-condition, and throughput evidence.

This is deliberately a new experiment for the AES-GCM migration profile at
HSM revision `b5dd4d6f`.  It is not a presumption that VAES is faster.

## Why this needs a controlled retest

The X1 VM exposes `avx2`, `avx512f`, `avx512ifma`, `vaes`, and `sha_ni`.
The AES-GCM path is RustCrypto `aes` 0.9, not the AWS-LC path used by some
classical and PQC mechanisms.  Its normal x86-64 runtime dispatch selects
AES-NI.  Its VAES-512 backend is compiled only with the documented
`aes_backend="avx512"` configuration.

An earlier X1 VAES candidate was correct but slower at 16 KiB.  That result is
valuable negative evidence, but is not sufficient to answer the migration
question: the current profile uses AES-GCM with 64 KiB and 1 MiB inputs and a
new HSM/harness revision.  The test must therefore isolate VAES from all other
build differences and include long payloads.

## Frozen inputs and guardrails

1. Record the candidate source commit, `Cargo.lock` SHA-256, Rust version,
   build-image digest, VM kernel, and the exact CPU flags before building.
2. Build natively on the X1 build host, using the existing X1
   container image.  Do not cross-build on an Apple host.
3. Preserve the deployed provider, its harness, and existing benchmark
   outputs.  Write candidates only below a new versioned directory such as
   `<perf-root>/aes-vaes512-b5dd4d6f/` under the benchmark root on the build host.
4. Do not alter the X1 OS, its production container, or its global Rust tool
   chain.  Every build runs in `docker run --rm`.
5. The candidate and control must use the identical source snapshot,
   dependency versions, release profile, `AWS_LC_SYS_SMALL=0`, and benchmark
   arguments.  The only intended difference is the RustCrypto AES backend
   selector.

## Phase 1 — make the build reproducible without relying on a live registry

The X1's fresh build currently cannot resolve the complete Cargo index offline,
and its attempted network download timed out.  Resolve this before testing;
do not silently substitute a different dependency set.

Preferred method:

1. From the locked current source, create a Cargo vendor bundle and its source
   replacement configuration on a trusted build host.
2. Hash the bundle manifest and transfer it to the X1 alongside the frozen
   source snapshot.
3. Build with `--locked --offline` and the vendor source replacement.  Save
   the Cargo configuration and build log with the artifacts.

Fallback method, only if a vendor bundle cannot be made:

1. Repair the X1 registry/network path.
2. Build with `--locked`; capture the registry endpoint, command, and complete
   log.
3. Record this as lower-reproducibility evidence and subsequently materialize
   a vendor bundle from the resolved lockfile before promotion.

Acceptance: both control and VAES candidate compile from the same locked
dependency graph, and their harnesses list exactly the 24 AES migration cells
(eight profiles times keygen/encrypt/decrypt).

## Phase 2 — build matched X1 control and VAES candidates

Create two separate release outputs.  Both use native X1 compilation and the
same optimisation level.

| Artifact | Required Rust flags | Purpose |
|---|---|---|
| `native-default` control | `-C target-cpu=native` | Measures the current AES-NI runtime-dispatch route under the same native compilation conditions. |
| `vaes512` candidate | `-C target-cpu=native --cfg aes_backend="avx512"` | Enables RustCrypto's VAES-512 implementation; runtime CPUID still verifies that VAES and AVX-512F are present before selection. |

For each output, copy the provider and harness to the isolated evidence
directory and record SHA-256 values.  Never compare the VAES candidate to an
artifact built with different source or a different dependency lockfile.

## Phase 3 — prove what was built and can dispatch

Before timing either variant, collect these three independent facts:

1. **VM capability:** `/proc/cpuinfo` includes `aes`, `avx2`, `avx512f`, and
   `vaes`.  `avx512ifma` and `sha_ni` are recorded but are not required for
   AES-GCM's VAES path.
2. **Compiled candidate code:** use the build container's disassembler to show
   `vaesenc` or `vaesenclast` in the candidate provider.  Confirm that the
   default control does not contain the VAES backend symbols/instructions.
3. **Selection condition:** retain the RustCrypto `aes` 0.9 source and the
   effective flags in evidence.  Its `aes_backend="avx512"` dispatch requires
   both `vaes` and `avx512f`; the captured X1 flags satisfy that condition.

These facts demonstrate a valid VAES-capable path.  Throughput remains the
separate proof of whether it helps this workload.

## Phase 4 — correctness and isolation gate

For each variant, run the AES migration matrix with one worker and one tenant:

- AES-128-GCM and AES-256-GCM;
- 16 B, 1 KiB, 64 KiB, and 1 MiB;
- encrypt and authenticated decrypt; and
- the harness's normal key ownership, round-trip, and cleanup checks.

Reject the candidate immediately on an initialization, round-trip,
authentication, tenant-isolation, or finalization failure.  Do not run a
whole-board test for a failed candidate.

## Phase 5 — long-payload performance A/B

Run each accepted variant three times with identical conditions:

```text
--threads 1 --tenants 1 --warmup-secs 2 --duration-secs 10
--min-ops 100 --max-secs 30
```

The primary decision rows are AES-128-GCM and AES-256-GCM encrypt/decrypt at
64 KiB and 1 MiB.  Keep 16 B and 1 KiB rows to show whether fixed PKCS#11
overhead changes the conclusion, but do not use them to claim a bulk-data
gain.

For every row publish the median operations/s, p50/p99 latency, and derived
GiB/s.  Calculate the VAES effect as:

```text
VAES change (%) = (median VAES throughput / median native-default throughput - 1) × 100
```

Only if the one-worker long-payload gate passes, repeat the same three-run
matrix at 12 workers (the X1 VM's available vCPU count) to show whether the
benefit survives saturation.

## Phase 6 — decision and publication gates

Promote no global provider solely because it wins one microbenchmark.

| Outcome | Decision |
|---|---|
| VAES fails correctness or isolation | Reject; preserve logs and hashes. |
| VAES has no repeatable long-payload win, or regresses a primary 64 KiB/1 MiB row | Retain AES-NI default; record the negative result. |
| VAES improves all primary one-worker rows but loses at 12 workers | Keep as an X1 low-concurrency/profile-specific candidate; do not replace the whole-board dashboard baseline. |
| VAES improves the primary rows at one worker and 12 workers without material small-payload regression | Open a separate promotion change, rerun the complete classical/PQC/hybrid matrix, then update the dashboard. |

Treat a result as repeatable only when all three runs point in the same
direction and the median improvement is larger than normal run-to-run
variation.  A practical promotion threshold is at least 5% on every primary
long-payload row, with no correctness failure and no more than a 3% regression
in the 16 B/1 KiB rows.  The threshold is a decision rule, not a claim that
5% is cryptographically meaningful.

## Evidence and reporting

Save per-run JSONL, command lines, build logs, SHA-256 values, capability
capture, disassembly excerpts, and a short failure register under the
versioned candidate directory.  The dashboard must clearly label:

- **AES-NI baseline** versus **X1-only VAES-512 candidate**;
- one-worker versus 12-worker results;
- 64 KiB and 1 MiB as the primary data-migration measurements; and
- any rejected VAES candidate as negative evidence, not as a supported
  deployment configuration.

No other board's result changes in this experiment.  ARM boards, M4 Pro, and
M5 Max remain on their own native AES-extension paths and must not be compared
as if they used x86 VAES.

## Execution record — 2026-10-26

### Reproducible native builds

The X1's incomplete local Cargo registry was bypassed with a locked vendor
bundle made from this revision's `Cargo.lock` (SHA-256
`d48baea03a7e22d8d4937af4ece0a3a7ad8c21c277f22623a1c24d08f886db66`).
Both providers and harnesses were compiled natively on the X1 build host, from the
same read-only source snapshot and vendor bundle, in separate output paths:

| Artifact | Provider SHA-256 | Harness SHA-256 |
|---|---|---|
| `native-default` (`-C target-cpu=native`) | `5b2913e23b0c097054410297c9fd6d16cbb52d651ab5b0b5e97d0510d580d741` | `68b2f8b8ca1a929743a5c6630fd040e6ae893bbfd52064be2b3a864cfb2151fc` |
| `vaes512` (`-C target-cpu=native --cfg aes_backend="avx512"`) | `7c52270e8c698c4e20b1730be38e5914406819093aeac6d061f1b63c577c6a7d` | `b72650d1a614efbe5a687c0cf05193d3442035f04004a61c6c05073c1eca1855` |

The X1 VM advertised the required `aes`, `avx2`, `avx512f`, and `vaes` CPU
flags.  The candidate compiler invocation carried the explicit
`aes_backend="avx512"` setting.  Both provider binaries also contain VAES
instructions; some originate from AWS-LC in either build, so instruction
presence alone is not used as a performance claim.

### Correctness gate

Both artifacts completed the full eight-profile AES-GCM migration smoke matrix
(AES-128/256 GCM at 16 B, 1 KiB, 64 KiB, and 1 MiB) with key ownership,
round-trip, authenticated-decrypt, isolation, and finalization checks.  Each
produced all 24 expected rows and finalized cleanly.

### One-worker long-payload A/B result

Each result below is the median of three isolated runs on one X1 worker, using
one tenant, a two-second warm-up, and a ten-second measured window.  The
primary long-payload set comprises 64 KiB and 1 MiB AES-GCM encrypt/decrypt;
each run emitted all 12 expected rows and finalized cleanly.

| Operation | Native-default median ops/s | VAES-512 median ops/s | VAES change |
|---|---:|---:|---:|
| AES-128-GCM 64 KiB encrypt | 39,991 | 40,307 | +0.8% |
| AES-128-GCM 64 KiB decrypt | 22,235 | 22,170 | -0.3% |
| AES-128-GCM 1 MiB encrypt | 2,619 | 2,631 | +0.4% |
| AES-128-GCM 1 MiB decrypt | 1,410 | 1,413 | +0.2% |
| AES-256-GCM 64 KiB encrypt | 37,710 | 37,701 | -0.0% |
| AES-256-GCM 64 KiB decrypt | 21,428 | 21,398 | -0.1% |
| AES-256-GCM 1 MiB encrypt | 2,464 | 2,466 | +0.1% |
| AES-256-GCM 1 MiB decrypt | 1,364 | 1,365 | +0.1% |

**Decision:** VAES-512 does not clear the one-worker promotion gate.  The
largest measured change is +0.8%, while the rule requires a repeatable gain of
at least 5% on every primary long-payload row.  The 12-worker test, broad
classical/PQC rerun, deployment replacement, and dashboard update are
therefore intentionally skipped.  Retain the AES-NI/default route and these
candidate artifacts as reproducible negative evidence.
