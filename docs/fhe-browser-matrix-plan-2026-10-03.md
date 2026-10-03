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

## First result (M5 Max, macOS, headless)

| Browser | KAT | Init | Client key |
|---|---|---|---|
| Chromium 153.0.8010.12 | PASS | 586 ms | 3 ms |
| WebKit 26.6 (Safari engine) | PASS | 110 ms | 8 ms |
| Firefox | not run: not in the local Playwright cache | — | — |

Timings were taken while another release gate was running on the same machine,
so they are indicative only. Budgets are not frozen from them.

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

No shipped Hub bundle was affected: `educational-fhe` is non-default and no
Hub, wasm or release build enables it.

## Next steps (P0A → P3)

1. **Firefox.** Install the Playwright Firefox build and add it to the run.
2. **`--add` timings** on an idle M4 Pro and M5 Max: server-key generation and
   one bootstrapped operation in each browser, single-threaded.
3. **Memory and recovery.** Peak memory for the ~29 MB public export (§6.6
   P0A spike), worker termination and restart, low-memory behaviour.
4. **Threaded mode.** Cross-origin-isolated build (COOP/COEP) with
   `parallel-wasm-api`, measured against single-threaded.
5. **Freeze budgets** from idle-machine runs, then mark each browser
   supported or evidence-only (§7). Mobile stays evidence-only.
6. **Gate lane.** Once the runner has a pinned Playwright, add the KAT run to
   `scripts/local-gate.sh` as a host step.
