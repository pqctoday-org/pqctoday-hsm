# Contributing to SoftHSMv3

Thank you for your interest in contributing. SoftHSMv3 is a security-critical
library — please read this guide before opening a pull request.

## Code of Conduct

All participants must follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## Ways to Contribute

- **Bug reports** — open a GitHub Issue with reproduction steps
- **Security vulnerabilities** — follow [SECURITY.md](SECURITY.md), do **not** file a public issue
- **Documentation** — typos, clarifications, and new examples are always welcome
- **Code** — see the process below

## Development Setup

Once, after cloning: `bash scripts/install-hooks.sh` — installs the
pre-push hook that enforces the local gate described in step 4 below.

### Prerequisites

| Tool | Minimum version |
|------|----------------|
| CMake | 3.16 |
| OpenSSL | 3.5.0 (native + WASM builds, enforced by `CMakeLists.txt` line 97; also linked by `p11_v32_compliance_test` as an independent oracle) |
| Emscripten | 3.1.x (WASM build) |
| C++ compiler | C++17 (GCC 10+, Clang 14+, MSVC 2022+) |
| CppUnit | 1.15+ (only needed for the legacy upstream test suite under `src/lib/*/test/`) |

On macOS the Homebrew OpenSSL is not on the default search path; pass `-DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)` to every `cmake` invocation below.

### Native build

```bash
cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_TESTS=ON \
  -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)   # macOS only
cmake --build build -j$(nproc)
```

A full `cmake --build build` with `BUILD_TESTS=ON` builds everything: the shared library (`libsofthsmv3.dylib`), the modern `p11_v32_compliance_test` binary, and the legacy CppUnit-based upstream test targets under `src/lib/*/test/`. Earlier in 2026-06-01 the legacy targets failed with `fatal error: 'cppunit/extensions/HelperMacros.h' file not found` because the `CPPUNIT_INCLUDES` variable was not propagated to the per-sub-target `INCLUDE_DIRS` lists; that has since been fixed (`CPPUNIT_INCLUDES` is now included in every sub-target's `INCLUDE_DIRS`, e.g. `src/lib/crypto/test/CMakeLists.txt`) and CI now builds every target cleanly.

### Compliance-test-only workflow (recommended)

For the modern PKCS#11 v3.2 compliance suite — used in CI and the only one that's spec-aligned today:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_TESTS=ON \
  -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)   # macOS only
cmake --build build --target softhsmv3 p11_v32_compliance_test -j$(nproc)

# Run the full suite:
./build/p11_v32_compliance_test \
  --engine ./build/src/lib/libsofthsmv3.dylib \
  --report compliance_report

# Or one category at a time (faster iteration):
./build/p11_v32_compliance_test --engine ./build/src/lib/libsofthsmv3.dylib --category kcv
```

A representative subset of `--category` values (the suite has grown well past this list — run `./build/p11_v32_compliance_test --help` for the current full set, which also includes dated one-off categories like `gap-2026-08-24`): `all`, `discovery`, `attr`, `pqc-kem`, `pqc-dsa`, `pqc-slh`, `v32-adv`, `classical`, `negative`, `fips`, `session`, `cka-id`, `authwrap`, `kcv`. The `kcv` category covers PKCS#11 v3.2 §4.11 mandatory KCV population across `C_GenerateKey`, `C_UnwrapKey`, and `C_DeriveKey` (HKDF) with byte-exact comparison against an independent OpenSSL oracle.

Reports land in `compliance_report.json` and `compliance_report.md`.

### Legacy CppUnit suite

`ctest --test-dir build --output-on-failure` runs the upstream SoftHSMv2 CppUnit suite. Individual targets live under `src/lib/{crypto,data_mgr,session_mgr,slot_mgr,object_store,handle_mgr}/test/` and can be built one at a time via `cmake --build build --target cryptotest` etc.

### WASM build

```bash
bash scripts/build-wasm.sh
node tests/smoke-wasm.mjs
```

### Sanitizer build (strongly recommended before submitting crypto-touching PRs)

```bash
cmake -B build-asan \
  -DCMAKE_BUILD_TYPE=Debug \
  -DENABLE_ASAN=ON \
  -DENABLE_UBSAN=ON \
  -DBUILD_TESTS=ON \
  -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)   # macOS only
cmake --build build-asan --target softhsmv3 p11_v32_compliance_test -j$(nproc)
./build-asan/p11_v32_compliance_test \
  --engine ./build-asan/src/lib/libsofthsmv3.dylib \
  --category kcv   # or 'all' for the full sweep
```

## Pull Request Process

1. **Branch from `main`** — name your branch `feat/<topic>`, `fix/<topic>`, or `docs/<topic>`.
2. **One logical change per PR** — reviewers should be able to understand the purpose in one sentence.
3. **Add or update tests** — new code paths must have an automated assertion. For PKCS#11 attribute / mechanism / lifecycle behavior, add a case to `p11_v32_compliance_test.cpp` under the appropriate `--category` (preferred — uses the OpenSSL independent oracle and runs in CI). For internal C++ helpers (crypto primitives, byte-string handling, etc.) add a CppUnit case under `src/lib/.../test/` once the upstream CppUnit infra is repaired. Crypto-touching tests must reference the normative spec section (PKCS#11 v3.2, FIPS 203/204/205, RFC #) in a comment.
4. **Pass the local gate before pushing** — this project's validation loop is
   local-first (directive 2026-07-01): GitHub is release-only, not a test
   platform. Run `bash scripts/local-gate.sh` (core steps: kmip + rust + kmip
   local-only suites, OASIS KMIP 3.0 replay with provenance + baseline +
   staleness checks, the cross-engine PKCS#11 differential harness, the Rust
   engine's PKCS#11 v3.2 conformance matrix, wasm smoke) before every push.
   Add `--cpp` for the C++ `ctest` suite (incl. `p11_v32_compliance_test`),
   `--acvp-wasm` for the 20-suite ACVP harness, `--tls-interop` for the
   §3.3.3 hybrid-TLS-vs-OpenSSL proof, or `--all` for everything — required
   before cutting a release (see `RELEASING.md`). A passing run writes
   `.gate-ok-<HEAD-sha>`; the installed pre-push hook (`bash
   scripts/install-hooks.sh`, one-time setup) refuses to push a commit
   without a current marker. **Separately, GitHub CI still runs on every
   push/PR** as a second, independent check: `build` (C++ `ctest`, incl. the
   v3.2 compliance harness), `constants-gate` (PKCS#11 constant parity),
   `rust-test` (kmip + rust `cargo test`, non-`#[ignore]` subset only),
   `kmip-conformance` (OASIS replay + staleness guard), `kmip-pqc-conformance`
   (PQC corpus replay), `deprecated-api-check`, and `python-client`. There is
   no separate lint job and no separate E2E-smoke job in CI today — treat
   this list, not the phrase "build → lint → unit tests → E2E smoke test",
   as authoritative.
5. **Sign your commits** — by submitting you certify that you wrote the code and have the right to submit it under the BSD-2-Clause license.
6. **Update CHANGELOG.md** — add a line under `[Unreleased]` describing your change.

## Code Style

- **C++17** — no C++20 features (WASM toolchain constraint)
- **Indentation** — tabs, matching the existing source
- **Error handling** — use `ERROR_MSG(...)` for all error paths; return `CKR_*` codes from PKCS#11 functions
- **No `assert()` in production code** — use defensive checks with `ERROR_MSG` + `return CKR_GENERAL_ERROR`
- **Memory** — prefer `ByteString` and RAII; call `CryptoFactory::i()->recycle*()` at every exit path when holding crypto objects
- **No shared mutable state** — per-call local crypto algorithm instances (see `SecureDataManager` for the pattern)

## Roadmap

The original PKCS#11-engine roadmap (Phases 0–19, all complete, tracked
against GitHub Issues) is described in [README.md](README.md) and closed
out at v0.4.24. Feature work since then — KMIP 3.0, CACP, hybrid KEMs, the
Rust engine, and everything currently in progress — is tracked directly in
[CHANGELOG.md](CHANGELOG.md) rather than by phase number; see its
`[Unreleased]` section for what's currently active.

## License

By contributing, you agree that your contributions will be licensed under the
[BSD 2-Clause License](LICENSE).
