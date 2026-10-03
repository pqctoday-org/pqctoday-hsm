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
  Playwright is not an hsm dependency: point `PLAYWRIGHT_MODULE` at an
  installed copy.

```
bash scripts/build-fhe-browser-kat.sh
PLAYWRIGHT_MODULE=<path>/node_modules/playwright \
  node tests/browser/fhe-kat/run.mjs --browsers chromium,webkit,firefox [--add]
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

1. **Idle-machine timings** on the M4 Pro and M5 Max, to freeze budgets (the
   runs above were under load).
2. **Memory and recovery.** Peak memory for the ~29 MB public export (§6.6
   P0A spike), worker termination and restart, low-memory behaviour.
3. **Threaded mode.** Cross-origin-isolated build (COOP/COEP) with
   `parallel-wasm-api`, measured against single-threaded.
4. **Freeze budgets** from idle-machine runs, then mark each browser
   supported or evidence-only (§7). Mobile stays evidence-only.
5. **Gate lane.** Once the runner has a pinned Playwright, add the KAT run to
   `scripts/local-gate.sh` as a host step.
