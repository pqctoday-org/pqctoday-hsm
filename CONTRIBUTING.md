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

### Prerequisites

| Tool | Minimum version |
|------|----------------|
| CMake | 3.16 |
| OpenSSL | 3.5.0 (native + WASM builds, enforced by `CMakeLists.txt` line 93; also linked by `p11_v32_compliance_test` as an independent oracle) |
| Emscripten | 3.1.x (WASM build) |
| C++ compiler | C++17 (GCC 10+, Clang 14+, MSVC 2022+) |
| CppUnit | 1.15+ (only needed for the legacy upstream test suite — currently blocked, see warning below) |

On macOS the Homebrew OpenSSL is not on the default search path; pass `-DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)` to every `cmake` invocation below.

### Native build

```bash
cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_TESTS=ON \
  -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)   # macOS only
cmake --build build -j$(nproc)
```

> ⚠️ **Known issue (as of 2026-06-01):** a full `cmake --build build` with `BUILD_TESTS=ON` currently fails inside the legacy CppUnit-based upstream test targets under `src/lib/*/test/` with `fatal error: 'cppunit/extensions/HelperMacros.h' file not found`. The CppUnit include path is not propagated to those sub-targets. The failures are unrelated to library code; the shared library itself (`libsofthsmv3.dylib`) and the `p11_v32_compliance_test` binary both build cleanly. Use one of the targeted-build workflows below until the upstream-test infra is repaired. Tracked in a follow-up; do not block your PR on it.

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

Supported `--category` values: `all`, `init`, `discovery`, `attr`, `pqc-kem`, `pqc-dsa`, `pqc-slh`, `v32-adv`, `classical`, `negative`, `fips`, `session`, `cka-id`, `authwrap`, `kcv`. The `kcv` category covers PKCS#11 v3.2 §4.11 mandatory KCV population across `C_GenerateKey`, `C_UnwrapKey`, and `C_DeriveKey` (HKDF) with byte-exact comparison against an independent OpenSSL oracle.

Reports land in `compliance_report.json` and `compliance_report.md`.

### Legacy CppUnit suite (currently blocked)

`ctest --test-dir build --output-on-failure` cannot run end-to-end while the CppUnit include propagation is broken. If you need to run a specific legacy test target after that's fixed, the targets live under `src/lib/{crypto,data_mgr,session_mgr,slot_mgr,object_store}/test/`.

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
4. **Pass CI** — the PR must pass: build → lint → unit tests → E2E smoke test.
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

Feature work follows the phase roadmap tracked in GitHub Issues:

- Phase 0–6 are described in [README.md](README.md)
- New PQC algorithm support lands in Phase 2+
- WASM-specific changes go in Phase 4–5

## License

By contributing, you agree that your contributions will be licensed under the
[BSD 2-Clause License](LICENSE).
