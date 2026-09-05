# softhsmrustv3 — the Rust PKCS#11 engine

`softhsmrustv3` is the second crypto engine in this repository (alongside the
C++ engine in `../src/`). It is:

- the **WASM crypto path** for the in-browser HSM (`../wasm/`), and
- the **production backend for the KMIP server and CACP policy engine**
  (`../kmip/`).

It implements the PKCS#11 v3.2 surface — ML-KEM, ML-DSA, SLH-DSA, stateful
HSS/LMS, XMSS/XMSS-MT, AES/HMAC, RSA/ECDSA/EdDSA, SP800-108 KBKDF — plus a set
of Rust-engine-only vendor mechanisms (BIP32, Keccak-256, FrodoKEM, Classic
McEliece, Split Key Sharing, and `CKM_HPKE`/`CKM_HPKE_KEM_KEY_PAIR_GEN` — full
RFC 9180 HPKE + a PQ/T hybrid KEM combiner, driven through
`C_EncapsulateKey`/`C_DecapsulateKey`; provisional codepoints, not part of
PKCS#11 v3.2, this engine only — see `src/native/hpke.rs`) — and carries its
own checked-in conformance evidence. For the full mechanism-by-mechanism
inventory and algorithm parity vs the C++ engine, see
[`../docs/rust-engine.md`](../docs/rust-engine.md); this file stays a
crate-local build/test quick reference.

The crate's own SemVer version (`Cargo.toml`, currently `0.17.0`) is
independent of the repository's overall release version tracked at the top of
`../CHANGELOG.md` — don't conflate the two.

## Workspace layout

`rust/` is itself the crate root (`Cargo.toml`'s `[package] name =
"softhsmrustv3"`) and a two-member Cargo workspace:

| Path | What it is |
|---|---|
| `src/` | The engine: `ffi.rs` (wasm-bindgen `_C_*` exports), `ck_abi.rs` (native `CK_FUNCTION_LIST` C ABI), `state.rs`/`state_snapshot.rs` (session/object state), `constants.rs`, `crypto/` (algorithm handlers, XMSS/LMS bridges, BIP32, split-key), `native/` (typed Rust API consumed directly by the KMIP server — HPKE, hybrid KEM, keygen, sign, session, etc.), `store/`, `bin/` |
| `fips204-patched/`, `fips205-patched/`, `hbs-lms-patched/` | Vendored upstream crates (ML-DSA, SLH-DSA, HSS/LMS) carrying local patches via `[patch.crates-io]` below — see [Patched crates](#patched-crates) |
| `bench-harness/` | The other workspace member — a perf-benchmarking binary that `dlopen`s a **built** engine `.dylib`/`.so` and drives it through its real `CK_*` function-pointer table (never calls this crate's functions directly), so all engine state lives in the one loaded instance a real PKCS#11 application would use |
| `docs/NATIVE_API.md` | The native Rust API (`native::*`) for non-wasm consumers, e.g. the KMIP server |
| `kat/` | Checked-in NIST/ACVP known-answer-test vector JSON consumed by the crate's own tests |
| `build-wasm-bundle.sh` | Builds the packaged WASM bundle — see [Build](#build) |
| `RUST_P11_V32_CONFORMANCE_REPORT.md` | Live, harness-regenerated PKCS#11 v3.2 conformance evidence for this engine |
| `CK_ABI_NATIVE_COMPLIANCE_PLAN.md` | Historical native-ABI remediation plan, **superseded 2026-08-23** — see [Testing & conformance](#testing--conformance) |
| `test_p11_conformance.js`, `test_kat_parity.js`, `test_r36_paramset.js`, `test_xmss_release.js` | Node test harnesses against the built WASM bundle — see [Testing & conformance](#testing--conformance) |
| `pkg/`, `pkg-release/`, `pkg_bundler/` | `wasm-pack`/`wasm-bindgen` build output directories — see [Build output directories](#build-output-directories) |
| `patch_export_table.py` | Post-build step (invoked by `build-wasm-bundle.sh`) that re-adds the `__indirect_function_table` export `wasm-bindgen-cli` strips; `C_GetFunctionList` needs it |
| `fix_crypto.py`, `fix_literals.py`, `fix_state.py`, `cpp_funcs.txt`, `cpp_funcs2.txt`, `rust_funcs.txt`, `pkcs11_all_funcs.txt`, `output.txt`, `test_xmss.rs`, `test_harness.js` | Tracked but incidental — one-off developer scripts/text dumps from earlier mechanical refactors and investigations, not part of the maintained build or test workflow |
| `target/` | `cargo` build output (gitignored) |

A few other `wasm-pack` output-style directories (`pkg-release-acvp/`,
`pkg_nomod/`) may exist locally on a given checkout; they are not produced by
any script currently checked into this repo, so treat them as incidental
rather than documented deliverables.

## Build

```bash
# Native library + tests
cd rust
cargo build --release
cargo test                     # engine unit/integration tests

# WASM bundle (bundler target, dev profile) — the ACVP feature enables the
# conformance KATs. Runs in the OrbStack/Docker `pqc-rust` container if cargo
# isn't on PATH.
RUSTFLAGS="-C link-arg=-zstack-size=2097152" \
  wasm-pack build --target bundler --out-dir pkg --dev -- --features acvp
```

`build-wasm-bundle.sh` wraps the packaged-bundle build and is the one to use
for anything beyond a quick native check:

```bash
cd rust
./build-wasm-bundle.sh            # release profile → pkg-release/, then
                                   # refreshes the tracked pkg_bundler/
./build-wasm-bundle.sh --dev      # dev profile → pkg/, for the Node harnesses
```

Both invocations pass `--features acvp` (required — without it,
`C_Initialize` rejects the non-null `pReserved` the harnesses use to seed
deterministic KATs) and the extra `RUSTFLAGS` the script needs for wasm shadow
stack size and table export; see the script's own header comments for why.
The `acvp` Cargo feature itself is opt-in and **off** in every shipped
artifact (the `pqctoday-kmip` server binary, the in-browser playground WASM
bundle, this crate's plain `cdylib`) — enabling it is a deliberate PKCS#11
v3.2 §5.6 deviation, needed only for KAT reproducibility.

### Build output directories

`pkg/` and `pkg-release/` are both `wasm-pack --out-dir` staging locations,
gitignored in full (`*` in each directory's own `.gitignore`) and not part of
git history — they exist only on a machine that has built them. The
distinction is the Cargo profile, not the content shape:

| Directory | Produced by | Profile | Who actually reads it |
|---|---|---|---|
| `pkg/` | `wasm-pack build --dev` (or `build-wasm-bundle.sh --dev`) | dev — unoptimized, larger binary | `test_p11_conformance.js`, `test_kat_parity.js`, `test_r36_paramset.js` all `require('./pkg/...')` directly; this is the build the Node conformance/KAT harnesses need |
| `pkg-release/` | `wasm-pack build` without `--dev` (or `build-wasm-bundle.sh`, no flags) | release — `opt-level = "s"`, `lto = true` per `Cargo.toml`'s `[profile.release]` | `test_xmss_release.js` (see below); its three build outputs also get copied into `pkg_bundler/` by `build-wasm-bundle.sh` when run without `--dev` |

The difference is not cosmetic: XMSS/XMSS-MT keygen+sign measured roughly
**18x faster** against the release build (~2.3s) than the dev build (~42s) —
see `test_xmss_release.js`'s own header for the measurements and why the
default conformance harness (`test_p11_conformance.js`) skips those two
mechanisms rather than eating that cost on every run against `pkg/`.

`pkg_bundler/` is different from the two above: it **is** tracked in git, and
it is the real deliverable — the release build's `softhsmrustv3.js`,
`softhsmrustv3_bg.js` and `softhsmrustv3_bg.wasm` are copied there by
`build-wasm-bundle.sh`, and that directory is what `../wasm/`'s
`pqctoday-kmip-wasm` crate and the hub playground actually consume. `pkg/`
and `pkg-release/` READMEs in this repo are the automatic result of a
`wasm-pack` implementation detail: `wasm-pack` copies whatever `README.md`
sits next to the crate's `Cargo.toml` (i.e. this file) into every `--out-dir`
it produces as that output's own npm-package README. That is why
`rust/pkg/README.md` and `rust/pkg-release/README.md` currently read
identically to this file — it is not a mistake to fix by hand-diverging them,
since the next real build overwrites both with a fresh copy of whatever this
file says. Keep this file accurate and the copies follow.

## Testing & conformance

| Harness | What it checks |
|---|---|
| `cargo test` | Engine unit + integration tests |
| `node test_p11_conformance.js` | **PKCS#11 v3.2 conformance** — 999 checks / 51 sections, exact `CKR_*` codes in spec priority order, PQC keygen/param-set, SP800-108 KBKDF, message-based crypto. Requires `pkg/` (dev build, `--features acvp`) |
| `node test_kat_parity.js` | KAT parity vs the C++ engine. Requires `pkg/` |
| `node test_r36_paramset.js` | R3.6 parameter-set coverage. Requires `pkg/` |
| `node test_xmss_release.js` | XMSS/XMSS-MT keygen+sign+verify round trip against the **release** build — the two mechanisms `test_p11_conformance.js` skips for cost reasons. Requires `pkg-release/` (build with `./build-wasm-bundle.sh`, no flags). Opt-in step of `../scripts/local-gate.sh` (`--release-xmss` / `--all`), not part of its default run |

Regenerate the conformance report by running the Rust PKCS#11 v3.2
conformance step of `../scripts/local-gate.sh` — that step now runs by
default (it was opt-in behind `--rust-p11` until 2026-08-23; the flag is
still accepted but is a no-op today, kept only for muscle memory). The
harness itself writes the report file on every run — see `writeReport()` in
`test_p11_conformance.js`. Full results and the exact procedure live in
[`RUST_P11_V32_CONFORMANCE_REPORT.md`](RUST_P11_V32_CONFORMANCE_REPORT.md)
(**999 passed / 0 failed** as of that report's last regeneration — the file
records its own exact engine commit and generation timestamp; treat any
number quoted here as a snapshot to reverify against the live file, not a
permanent guarantee). The native Rust API is described in
[`docs/NATIVE_API.md`](docs/NATIVE_API.md).

[`CK_ABI_NATIVE_COMPLIANCE_PLAN.md`](CK_ABI_NATIVE_COMPLIANCE_PLAN.md) is a
**historical** plan document, explicitly marked superseded as of 2026-08-23 —
its own banner says not to cite its "315/0/0" figure as current, since it
predates two full remediation waves and the conformance suite growing well
past that snapshot. `RUST_P11_V32_CONFORMANCE_REPORT.md` above is the live
number.

**Cross-engine differential testing** (this engine vs the C++ one, driven
through identical PKCS#11 call sequences with every legal divergence recorded
and everything else failing the run) lives one level up, since it exercises
both engines from a single harness — see
[`../tests/differential/README.md`](../tests/differential/README.md) and run
via `../scripts/run-differential-harness.sh`. That is also where to add a new
scenario when a change here alters this engine's observable behavior.

## Patched crates

FIPS reference crates carrying local patches live alongside the engine:
`fips204-patched/` (ML-DSA), `fips205-patched/` (SLH-DSA),
`hbs-lms-patched/` (stateful HSS/LMS), wired in via this crate's
`[patch.crates-io]` in `Cargo.toml`. Each is a vendored copy of the real
upstream crate (`.cargo_vcs_info.json` in each records the exact upstream
commit), and each directory's own `README.md`/`CHANGELOG.md` is left as
upstream wrote it — those files describe the *unpatched* crate and are not
maintained by this project. **The patches themselves, what they change and
why, are documented in this repository's own `../CHANGELOG.md`**, not in the
vendored READMEs — search it for `fips204-patched`, `fips205-patched`, or
`hbs-lms-patched` for the specific fixes (e.g. the added `Ph` hash-variant
support for full PKCS#11 v3.2 §6.67.7/§6.69.7 coverage, and the SP 800-208
SHAKE-256 type-ID fix in `hbs-lms-patched`). The actual source diffs are the
`src/` trees in each of those three directories against their recorded
upstream commit — there is no separate `.patch`/`patches/` file here.
