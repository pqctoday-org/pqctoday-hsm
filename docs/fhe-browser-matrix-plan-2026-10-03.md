# FHE browser matrix — plan and first result (2026-10-03)

Closes the "desktop browser matrix (§7)" item left open in the FHE plan
(`implementation-plan-fhe-wrapper-pkcs11-vendor-2026-10-02.md` §5.5 and §7;
phases P0A and P3). The question is whether the **token's own** TFHE code, as
built for the Hub's browser engine, behaves the same in each desktop browser,
and what it costs there.

## What runs

- **Bundle.** `scripts/build-fhe-browser-kat.sh` builds `softhsmrustv3` for
  `wasm32-unknown-unknown` with `educational-fhe`, as a wasm-bindgen `web`
  module, into `rust/pkg-fhe-web/` (ignored). It is test-only; no shipped
  bundle enables `educational-fhe`.
- **Exports.** `rust/src/wasm_fhe_kat.rs` calls the same functions the
  PKCS#11 mechanisms use (`replication::fhe_tfhe::derive_tfhe_seed`,
  `client_key_for`). Only fixed public test seeds go in. Only a hash, a derived
  test seed or a decrypted test value comes out.
- **Runner.** `tests/browser/fhe-kat/run.mjs` serves the bundle locally, drives
  each browser headless with Playwright and prints one JSON line per browser.
  Playwright 1.63.0 is a pinned devDependency.

```
bash scripts/build-fhe-browser-kat.sh
npm ci && npx playwright install chromium webkit firefox
node tests/browser/fhe-kat/run.mjs --browsers chromium,webkit,firefox [--add | --memory]
```

## Checks per browser

| Check | Expected | Source |
|---|---|---|
| Derived TFHE seed for seed `00..1f` | `f6eb1c9a88a4442c8a7449536c3d12dc` | §5.5 `client-key-kat-v1` |
| Client key, safe-serialized | 24,087 B, SHA-256 `9f5d847e…5a55b77b` | same; identical on macOS arm64, Linux arm64/x86-64, Node wasm32 |
| `--add`: `FheUint8` 200 + 55 under a fresh server key | 255 | exercises server-key generation and one bootstrapped operation |
| Recorded | module init, KDF, client-key and add times; JS heap where the browser exposes it | §7 budgets |

## Results (M5 Max, macOS, headless, single-threaded)

All three desktop engines pass the KAT and the homomorphic add. Times are the
median of three runs (`--add`), taken at 17:10–17:15 CDT on 2026-10-03.

| Browser | KAT | Add 200 + 55 | Module init | Client key | Server key + add + decrypt |
|---|---|---|---|---|---|
| Chromium 153.0.8010.12 | PASS | 255 | 32 ms | 2 ms | 5.68 s |
| WebKit 26.6 (Safari engine) | PASS | 255 | 93 ms | 3 ms | 5.50 s |
| Firefox 155.0 | PASS | 255 | 96 ms | 1 ms | 5.67 s |

Runs varied by less than 5% after the first. Chromium's first run took 6.16 s.
The machine was not idle: its 1-minute load average was 10–16 on 18 cores,
because other sessions' jobs were running. Treat these as upper bounds, not
frozen budgets. The JS heap figure is only exposed by Chromium and stays at
its quantized 10 MB floor; it does not see WASM linear memory, so peak memory
needs the §6.6 measurement below.

## Memory and worker recovery (§6.6 P0A spike)

`run.mjs --memory` runs the bundle inside a dedicated module worker
(`worker.js`), the disposable-worker model of §6.6. It records the WASM
linear-memory size after each step. That size only grows, so each value is
the peak so far. `fhePublicExport` builds the same blobs as the token's
`CKM_PQCTODAY_FHE_DERIVE_PUBLIC` (`fhe_tfhe::derive_public`), under the same
64 MiB limit, and returns one owned buffer: exactly one copy crosses into
JavaScript.

| Step (M5 Max, 17:25 CDT) | Chromium 153 | WebKit 26.6 | Firefox 155 |
|---|---|---|---|
| Module init in the worker | 34 ms, 8.2 MB | 64 ms, 8.2 MB | 72 ms, 8.2 MB |
| Client-key KAT | PASS, 8.4 MB | PASS, 8.4 MB | PASS, 8.4 MB |
| Compact public key export | 33,034 B, 8.5 MB | same | same |
| Compressed server key export | 30,147,061 B in 2.51 s | 2.41 s | 2.59 s |
| Peak WASM memory | 101.5 MB | 101.5 MB | 101.5 MB |
| Kill the worker 1 s into an add, start a new one | recovered in 32 ms, KAT PASS | 78 ms | 38 ms |

What this settles and what it does not:

- **The export.** The real export is 30.1 MB, not the ~29 MB estimated
  earlier. Producing it peaks at about 3.4 times its size in WASM memory: the
  key, its compressed form and the serialized buffer coexist. A 128 MB
  per-worker ceiling would fit with about 25% headroom.
- **Termination.** `Worker.terminate()` returns at once in all three engines,
  and a fresh worker reinitializes and reproduces the KAT in under 80 ms. A
  killed worker leaves nothing behind for the next one, because each worker
  owns its own memory. As §6.6 says, this ends the emulator instance; it is
  not cancellation of one PKCS#11 call.
- **Not measured yet.** The JavaScript side of the copy (the 30 MB
  `Uint8Array` in the page).

### Token-state recovery after a kill

The worker is disposable, so persistence belongs to the page.
`run.mjs --snapshot` (page `snap.html`) does the whole path with the token's
own snapshot code (`state_snapshot`, magic `SHR3SNP3`):

1. Worker A builds a fixed token state (slot 0 initialized and logged in as
   User; one AES-256 token key with a fixed value; one session object) and
   returns `serialize_token_state()`: 283 bytes.
2. The page stores those bytes in IndexedDB, starts a long add in A, and
   terminates A one second in.
3. Worker B starts fresh, the page reads the bytes back from IndexedDB, and B
   restores them. A truncated copy goes to a third fresh worker.

Result, identical in Chromium 153, WebKit 26.6 and Firefox 155: the key comes
back under the same handle (100) with the same value (SHA-256 matches the
expected constant), the session object is gone, login is reset to Public, the
handle counter is past the key's handle (no collision with new objects), the
four built-in `CKO_PROFILE` objects are re-created, and the truncated
snapshot is refused (`CKR_ARGUMENTS_BAD`). Restore takes 17 ms in Chromium,
78 ms in WebKit and 42 ms in Firefox, including module start. The gate now runs it.

This shows the snapshot survives a kill when the page keeps it. It does not
cover a kill *during* a snapshot write (the page should write the new blob
only after the worker has returned it whole) or a snapshot held only inside
the worker (lost with the worker, by design).

### Low-memory cap

No browser exposes a memory limit to Playwright, so `run.mjs --cap-mb 64,96,...`
serves a copy of the bundle whose WASM memory declares a maximum of that many
MiB (the memory section of the `.wasm` is rewritten on the fly; the file on
disk is untouched). It is a controlled stand-in for a memory-starved tab: the
module cannot grow past the cap, which is the condition a browser creates when
it refuses a grow. Each cap runs the init, KAT, compact-key and server-key
steps in a worker, then starts a fresh uncapped worker and checks the KAT.

| Cap | Chromium 153 | WebKit 26.6 | Firefox 155 |
|---|---|---|---|
| 64, 96, 100 MiB | init, KAT and compact key pass; server-key export fails with a catchable trap | same | same |
| 102, 104, 128 MiB | all steps pass, peak 101.5 MiB | same | same |
| New worker after a failed step | KAT PASS in 34-38 ms | PASS in 84-91 ms | PASS in 37-42 ms |

- **The cliff is sharp and the same everywhere.** The server-key export
  needs 101.5 MiB; 100 MiB fails and 102 MiB passes, in all three engines. The
  compact public key (33,034 B) and the client key need only 8.5 MiB.
- **Failure is a trap, not a crash.** An allocation that cannot grow aborts
  with a `RuntimeError` (`unreachable`, in each engine's wording) that the
  worker catches and reports. No tab, worker or page died, and nothing hung.
- **A trapped instance is not reused.** Recovery is a new worker, as §6.6
  already plans; it reproduces the KAT in under 100 ms.
- **Implication for the budget.** A per-worker ceiling below ~102 MiB cannot
  produce the server key, so the client should treat that failure as "this
  device cannot run the full flow" and fall back, not retry.
- **Limit of this test.** A WASM cap models the grow refusal, not a mobile OS
  killing the whole tab; that needs a device and stays evidence-only.

## Quiet-machine measurements on the M4 Pro (2026-10-04)

The first results above were taken while other jobs loaded the M5 Max. These
were taken on the M4 Pro (Apple M4 Pro, 14 cores, macOS 26.6.2, Node 24.11.1)
with the bundle built by the 28-step gate at commit `608cd5e8`
(`softhsmrustv3_bg.wasm` SHA-256 `a4bb96d0ecc6e7c2…`), 13:11–13:15 CDT.

**How quiet the machine was.** It is the owner's daily machine, so "quiet" is
not "exclusive". Before each run `uptime` and `docker ps` were recorded. The
1-minute load average was 1.1 to 2.5 on 14 cores (0.08 to 0.18 per core).
Two containers were up (`pqc-rust`, `pqc-bench-arm64`), with no job running in
either; the busiest process outside the test was the ssh session (9% of one
core). Nothing else heavy was observed. These are the "quiet" numbers the
earlier tables lacked, not guaranteed-idle ones. The M5 Max has not been
re-measured: it was loaded at the time and then reserved for another job.

**Timing (`--add`, median of 5 runs; min to max in brackets).**

| Browser | Module init | Client key | Server key + add + decrypt (`addMs`) | KAT / add |
|---|---|---|---|---|
| Chromium 153.0.8010.12 | 19 ms [19-20] | 1.7 ms | 6.49 s [6.03-6.59] | PASS / 255 |
| WebKit 26.6 | 102 ms [93-119] | 2 ms | 5.85 s [5.70-6.25] | PASS / 255 |
| Firefox 155.0 | 61 ms [60-63] | 1 ms | 5.96 s [5.82-6.51] | PASS / 255 |

**Memory and recovery (`--memory`, 3 runs).**

| | Chromium | WebKit | Firefox |
|---|---|---|---|
| Compressed server key export (30,147,061 B in every run) | 2.68-2.70 s | 2.54-2.57 s | 2.76 s |
| Peak WASM memory | 106,430,464 B (101.5 MiB) in every run, every engine | same | same |
| New worker after a kill, KAT PASS | 16 ms | 98-100 ms | 30-31 ms |

**Cap cliff re-check (`--cap-mb 100,102`).** 100 MiB: the server-key export
traps in all three engines (catchable, nothing hung) and a fresh worker then
passes the KAT. 102 MiB: every step passes. Same cliff as on the M5 Max.

**Bundle size (`client.bundleBytes`).** 6,356,732 B wasm (1,566,989 B with
`gzip -9`, 1,054,159 B with brotli) plus 115,800 B of JavaScript glue.

### What can be frozen now and what cannot

The requirements contract (`fhe-hsm-scenarios.v1.json` in the Hub, scenario 1)
defines the budget *metrics* but leaves every numeric value `null`. The plan
(§7) says the user-experience ceilings come from that contract and that a
budget must not be chosen merely because it matches a slow implementation.
So this section records measurements against each metric and separates what is
exact from what needs a decision.

| Metric (scenario 1) | Measured | Can it be frozen from measurement alone? |
|---|---|---|
| `hsm.serverKeyExportBytes` | 30,147,061 B, identical in every run and engine | Yes, as an exact size |
| `hsm.peakRssMb` | 101.5 MiB of WASM linear memory, identical everywhere; process RSS not measured | The memory floor is exact: a per-worker ceiling below 102 MiB cannot run the flow. The ceiling to publish is a decision (the earlier analysis suggested 128 MiB for about 25% headroom) |
| `client.bundleBytes` | 6.36 MB wasm, 1.05 MB brotli | The size is exact for this build; the ceiling is a decision |
| `hsm.clientKeyGenMs` | 1 to 2 ms in all engines | Time ceiling is a decision |
| `hsm.serverKeyGenMs` | Not timed on its own; server key + add + decrypt together take 5.7 to 6.5 s | Needs a separate timing first |
| `hsm.decryptMs` | Not timed on its own | Needs a separate timing first |

Proposal, for the owner or coordinator to accept or change: freeze the exact
sizes and the 102 MiB memory floor now; treat the timings as a regression
guard (fail a gate run that is more than 1.5 times the median on the same
host class) rather than as a user-experience promise; and keep every browser
"evidence-only" in Hub text until the user-experience ceilings are written
into the contract. All three desktop engines pass every functional, memory,
snapshot and recovery check, so none is failing a budget today; none can be
called "supported" until the ceilings exist. Mobile stays evidence-only.

Still open for this item: an M5 Max run when that machine is free, and
separate timings for server-key generation and decrypt.

## Defect found and fixed by the first run

The `educational-fhe` browser build compiled but **panicked on first use**
(`ShortintEngine::new`, `Option::expect`). On `wasm32-unknown-unknown`,
TFHE-rs 1.8.1 has an entropy seeder only with its `__wasm_api` feature
(`tfhe/src/core_crypto/seeders.rs`). The engine pinned `features = ["integer"]`
only. The KDF itself already matched in both browsers.

- `rust/Cargo.toml`: a wasm32-unknown-unknown-only `tfhe` entry adds
  `integer-client-js-wasm-api`, at the same exact pin. Native builds are
  unchanged. The lockfile gains three wasm-only crates
  (`console_error_panic_hook`, `serde-wasm-bindgen`, `wasm-bindgen-futures`).
- `rust/fips204-patched/src/hashing.rs`: one `debug_assert!` comparison now
  names its type (`i32::try_from(tau)`). With wasm-bindgen's comparison impls
  in the dependency graph, the untyped `try_into()` became ambiguous. No
  behaviour change.
  Recorded in `rust/fips204-patched/PQCTODAY-PATCHES.md`.
- **No leak into native builds**, checked with
  `cargo tree -e features -i tfhe --features educational-fhe`: on the host
  target, `tfhe` carries no `integer-client-js-wasm-api` or `__wasm_api`
  feature. With `--target wasm32-unknown-unknown`, both appear.

No shipped Hub bundle was affected: `educational-fhe` is non-default and no
Hub, wasm or release build enables it.

## Next steps (P0A → P3)

1. **Quiet-machine timings.** M4 Pro done (2026-10-04, see above); M5 Max
   still to do when it is free. Separate timings for server-key generation
   and decrypt are also missing.
2. **Memory and recovery, remaining part.** The JavaScript-side copy of the
   30 MB export. (The low-memory cap and snapshot recovery are measured: see
   above.)
3. **Threaded mode.** Cross-origin-isolated build (COOP/COEP) with
   `parallel-wasm-api`, measured against single-threaded.
4. **Freeze budgets.** Exact sizes and the 102 MiB memory floor can be frozen
   now; the time and memory ceilings need the user-experience ceilings to be
   written into the requirements contract first (see the table above). Then
   mark each browser supported or evidence-only (§7). Mobile stays
   evidence-only.
5. **Gate lane: done.** `scripts/local-gate.sh` builds the bundle and runs
   the KAT and `--memory` in Chromium, WebKit and Firefox on every gate.
   Playwright 1.63.0 is pinned in `package.json`; the browsers download once
   per gate host.
