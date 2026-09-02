# Issue: Two intermittent test failures observed under heavy parallel load

## Component
`rust/src/ffi.rs` (ECDH cofactor FFI tests) and `remoting/` (three-transport
parity suite)

## Status
Open — **not reproduced on demand**, root cause unknown for both. Recorded here
so the next person to hit a red build can recognise them in seconds instead of
re-deriving the investigation. Neither has been "fixed"; nothing has been
papered over.

## Why this file exists

Both failures cost several hours of investigation on 2026-09-02. Everything
below is the *negative* result of that work — the hypotheses that were checked
and eliminated. That is the expensive part to reproduce, so it is written down
deliberately, even though it names no culprit.

**Do not "fix" either test speculatively.** Both pass on re-run against an
identical tree; a change that makes a green run greener proves nothing, and a
retry-loop would hide a real regression if one ever appears here.

---

## 1. `ffi::ecdh_cofactor_ffi_tests::cofactor_derive_still_works_for_p256_key`

### Symptom
`C_DeriveKey` with `CKM_ECDH1_COFACTOR_DERIVE` on a P-256 key returns
`CKR_ARGUMENTS_BAD` (7) instead of `CKR_OK` (0):

```
panicked at src/ffi.rs:20250:
assertion `left == right` failed: cofactor mode must remain valid for CKK_EC (P-256)
  left: 7
 right: 0
```

### Frequency
Observed **once** on GitHub CI (ubuntu-24.04). Passed on an immediate re-run of
the byte-identical tree, and has never reproduced locally — including three
full cold-cache gate runs on an 18-core machine.

### Ruled out (with evidence)

| Hypothesis | Why it is not this |
|---|---|
| The `LD_LIBRARY_PATH` / OpenSSL 3.6 CI change made the same day | The `rust` crate has **zero** OpenSSL dependencies — `grep openssl rust/Cargo.toml` and `Cargo.lock` both come back empty. A library path cannot reach it. |
| Commit `6270b732`'s `CKK_EC_MONTGOMERY` rejection gate over-rejecting P-256 | That gate returns `CKR_KEY_TYPE_INCONSISTENT`, a different code from the observed `CKR_ARGUMENTS_BAD`. |
| Test-isolation gap — some test mutating global state without the lock | All 474 `#[test]` fns in `rust/src` take `native::test_lock::acquire()`, directly or through a helper. Three separate scans found five candidates; **all five were false positives** on inspection (helpers acquire the lock; scan windows had spilled into adjacent tests). |
| Stale token/PIN state leaking between tests | `reset_all_engine_state_for_test()` — called *inside* `test_lock::acquire()` — clears `OBJECTS`, `SESSIONS` **and** `TOKEN_STORE`. |
| Malformed SEC1 encoding of the peer public key | `native::keygen` uses `to_encoded_point(false)`, the `p256` crate's fixed-width encoder. No leading-zero truncation is possible. |
| `strip_ec_point_der` corrupting the point | Real bug, but a *different* path — see `rust/src/state.rs`. Engine-generated keys are always DER-wrapped and unwrap deterministically; only **imported** raw points were affected, and that is now fixed. |

### Remaining plausible direction
Resource/timing pressure on a small CI runner (4 cores vs 18 locally); the run
took 493 s with heavy PQC suites in flight. Unproven.

---

## 2. One unnamed test in the `remoting` three-transport parity suite

### Symptom
The gate's step 6 reports `85 passed, 1 failed` where a healthy run reports
`86 passed, 0 failed`. The failing test's **name is not captured**, because the
step runs `cargo test --quiet` and pipes through `grep`.

### Frequency
Observed **once**, on the `fix/ws3-g6-openpgp-ed448` gate, while three gates ran
concurrently on one machine.

### Ruled out (with evidence)

| Hypothesis | Why it is not this |
|---|---|
| A genuine defect on that branch | The same suite re-ran **86/86 clean** on that exact branch minutes later, and plain `main` passed the identical step (`86 passed, 0 failed`) under the same cold-cache conditions. |
| Fixed-port collision between concurrent gate runs | The remoting tests bind `127.0.0.1:0` — OS-assigned ephemeral ports. There is no fixed port to contend for. |

### Remaining plausible direction
These tests start real gRPC/REST servers and use async timeouts. Under a
saturated machine (three concurrent gates on 18 cores) a timing-sensitive test
can lose a race. Unproven, but it fits: the failure has only ever been seen
under three-way parallel load.

### Diagnostic gap worth closing
Step 6 in `scripts/local-gate.sh` discards the failing test's identity. Anyone
investigating this should first re-run `cd remoting && cargo test` **without**
`--quiet` to capture the name — the current gate output cannot tell you which
of the 86 failed.

---

## Recommended handling if you hit either

1. **Re-run once.** Both have passed on re-run against an identical tree.
2. If it recurs, capture the failing test's **name** and the machine's
   concurrent load, and add it here — a second data point is worth far more
   than another pass through the eliminations above.
3. Resist adding a retry wrapper. These are the two known-unreliable tests in
   the repo; masking them would also mask a genuine regression arriving in the
   same place.

## History
Both surfaced on 2026-09-02 during a cold-cache re-verification campaign that
was itself prompted by a *different*, now-fixed defect: every git worktree
shared one cargo build directory with no locking between concurrent runs, which
made cargo reuse a wrong-feature-variant artefact and produce a phantom
compile error. See `scripts/local-gate.sh`'s `CARGO_TARGET_DIR_FOR_RUN` block.
That one was root-caused and fixed; these two were not, and saying so plainly
is the point of this file.
