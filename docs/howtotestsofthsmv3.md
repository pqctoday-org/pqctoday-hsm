# How to Test SoftHSMv3

This guide covers the C++ engine's native testing workflow in depth:
building the library, running the CppUnit p11test suite, and running the
standalone `pqc_validate` program that exercises every PKCS#11 v3.2
mechanism supported by OpenSSL. That is only part of this repository's test
surface, though — it also ships a second engine (Rust, with its own test
suite and checked-in PKCS#11 v3.2 conformance evidence), a cross-engine
differential harness, WASM/Node.js suites, and a live-OpenSSL-provider
coverage harness. [§10, "Other Test Suites in This Repository"](#10-other-test-suites-in-this-repository)
covers all of those and how they fit together with what CI actually runs.

---

## Contents

1. [Prerequisites](#1-prerequisites)
2. [Build](#2-build)
3. [Initialize a Test Token](#3-initialize-a-test-token)
4. [CppUnit p11test Suite](#4-cppunit-p11test-suite)
5. [pqc_validate — Algorithm Validation](#5-pqc_validate--algorithm-validation)
6. [JSON Result Files](#6-json-result-files)
7. [Phase-by-Phase Expectations](#7-phase-by-phase-expectations)
8. [Debugging Tips](#8-debugging-tips)
9. [CI Integration](#9-ci-integration)
10. [Other Test Suites in This Repository](#10-other-test-suites-in-this-repository)

---

## 1. Prerequisites

### macOS

```bash
brew install openssl@3 cmake cppunit
export OPENSSL_ROOT_DIR=$(brew --prefix openssl@3)
export PATH="$OPENSSL_ROOT_DIR/bin:$PATH"
```

### Linux (Debian/Ubuntu)

```bash
sudo apt-get install build-essential cmake libssl-dev libcppunit-dev
```

> Ubuntu 24.04's `libssl-dev` is OpenSSL 3.0.13 — below the 3.5.0 floor CMake
> enforces. If `apt`'s OpenSSL is too old, build one from source (real CI
> pins and builds 3.6.3 this way — see `.github/workflows/ci.yml`) and pass
> `-DOPENSSL_ROOT_DIR=/path/to/that/prefix`.

### Minimum versions

| Dependency | Minimum | Notes |
|---|---|---|
| CMake | 3.16 | |
| OpenSSL | 3.5.0 | CMake enforces this floor with `FATAL_ERROR`; 3.6.2+ is needed for `CKA_SEED` deterministic keygen, and CI is pinned to 3.6.3 |
| CppUnit | 1.15 | For p11test only |
| C++ compiler | C++17 | g++ 11+ or clang++ 14+ |

Check your versions:

```bash
cmake --version
openssl version
```

---

## 2. Build

All commands run from the **softhsmv3 repository root**.

### Debug build (recommended for testing)

```bash
cmake -B build \
    -DCMAKE_BUILD_TYPE=Debug \
    -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)   # macOS only

cmake --build build -j$(nproc || sysctl -n hw.logicalcpu)
```

### Release build

```bash
cmake -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)

cmake --build build -j$(nproc || sysctl -n hw.logicalcpu)
```

### Build output locations

| Artifact | Path |
|---|---|
| Shared library (macOS) | `build/src/lib/libsofthsmv3.dylib` |
| Shared library (Linux) | `build/src/lib/libsofthsmv3.so` |
| Static library | `build/src/lib/libsofthsmv3-static.a` |
| softhsm2-util CLI | `build/src/bin/util/softhsm2-util` |

> **Note**: The library is named `libsofthsmv3` (not `libsofthsm2`).
> Replace `.dylib` with `.so` on Linux throughout this document.

---

## 3. Initialize a Test Token

Before running either test suite you need a token slot with known PINs.

```bash
# Create a token named "pqctest" in slot 0
./build/src/bin/util/softhsm2-util \
    --init-token --slot 0 \
    --label "pqctest" \
    --so-pin 1234 \
    --pin 5678
```

Verify it was created:

```bash
./build/src/bin/util/softhsm2-util --show-slots
```

You should see a slot with label `pqctest` and status `Token is initialized`.

### Token directory

By default, SoftHSMv3 stores token data in the directory specified by
`softhsmv3.conf` (or the env var `SOFTHSM2_CONF`). The test suites set
this automatically. For manual testing, set:

```bash
export SOFTHSM2_CONF=/path/to/your/softhsmv3.conf
```

---

## 4. CppUnit p11test Suite

The CppUnit suite (`src/lib/test/`) tests the full PKCS#11 interface through
static linkage or a shared library. It exercises sessions, objects, tokens,
key generation, and cryptographic operations.

### Build p11test

```bash
# Rebuild with tests enabled
cmake -B build \
    -DCMAKE_BUILD_TYPE=Debug \
    -DBUILD_TESTS=ON \
    -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)

cmake --build build -j$(nproc || sysctl -n hw.logicalcpu)
```

### Run all tests

CMake's Makefile generator has no `check` target here (that's an autotools
convention SoftHSM2 used, not carried over) — use `ctest`, which is what real
CI runs (`.github/workflows/ci.yml`):

```bash
cd build
ctest --output-on-failure
```

With `-DBUILD_TESTS=ON`, `ctest` registers exactly **two** tests (verified
against the root and `src/lib/test/` `CMakeLists.txt`): the CppUnit `p11test`
suite below, and `p11_v32_compliance` (the standalone
`p11_v32_compliance_test` binary, driven against the freshly built engine —
891/0/48 as of the checked-in `cpp_compliance_report.md`; see
[§10](#10-other-test-suites-in-this-repository) for how it and the differential
harness relate). The same build also produces roughly a dozen small **probe
binaries** (`composite_sig_probe`, `aead_probe`, `aead_edge_probe`,
`aes_wrap_probe`, `aes_xts_probe`, `skey_flow_probe`, `shake_sign_probe`,
`generic_hash_mldsa_probe`, `hash_pqc_crosscheck`, `hash_pqc_provider_probe`,
`mu_gen_probe`, `dump_int_param`, `lms_xdr_verify`, `hss_pubkey_dump`, …) —
these are **not** registered under `ctest`; they exist to be invoked
individually by `scripts/test-openssl-provider.sh` (§10) against the OpenSSL
provider. `ctest --output-on-failure` will not run them, and their absence
from a `ctest` run is expected, not a build gap.

Or run the test binary directly:

```bash
cd build/src/lib/test
./p11test
```

Output is written to both stdout and `test-results.xml` (CppUnit XML format).

### Run a specific test class

```bash
./p11test SignVerifyTests
./p11test DigestTests
./p11test SymmetricAlgorithmTests
```

### Run a single test case

```bash
./p11test SignVerifyTests::testSignVerifyRSA
./p11test ObjectTests::testArrayAttribute
```

### Test against a shared library (external p11 module)

To test the built `.dylib`/`.so` as an external PKCS#11 module instead of
using static linkage:

```bash
# From build/src/lib/test/
make p11test_DEPENDENCIES= p11test_LDADD= \
    CPPFLAGS="-DP11_SHARED_LIBRARY=\\\"$(pwd)/../../lib/libsofthsmv3.dylib\\\"" \
    p11test
./p11test
```

### Available test classes

| Class | What it tests |
|---|---|
| `InitTests` | `C_Initialize`, `C_Finalize`, `C_GetInfo` |
| `InfoTests` | `C_GetSlotList`, `C_GetSlotInfo`, `C_GetTokenInfo` |
| `SessionTests` | `C_OpenSession`, `C_CloseSession`, session states |
| `TokenTests` | Token init, PIN management |
| `UserTests` | `C_Login`, `C_Logout`, PIN changes |
| `ObjectTests` | Object create/destroy/find, attribute get/set |
| `DigestTests` | SHA-1/224/256/384/512 + SHA3 variants |
| `SymmetricAlgorithmTests` | AES-ECB/CBC/GCM/CTR/CMAC, HMAC |
| `SignVerifyTests` | RSA PKCS#1v1.5/PSS, ECDSA, EdDSA, ML-DSA, SLH-DSA |
| `AsymEncryptDecryptTests` | RSA OAEP, ML-KEM |
| `AsymWrapUnwrapTests` | RSA wrap/unwrap, AES key wrap |
| `DeriveTests` | ECDH, X25519, X448 |
| `RandomTests` | `C_GenerateRandom` |
| `ForkTests` | Behavior across `fork()` (Linux only) |

---

## 5. pqc_validate — Algorithm Validation

`pqc_validate` is a standalone C++17 program (in `tests/`) that runs every
OpenSSL 3.6.0-supported mechanism through the PKCS#11 v3.2 interface, logs
structured results to JSON, and performs symmetric round-trip verification
with negative tamper tests on each operation.

### 5.1 Download nlohmann/json

```bash
curl -L https://raw.githubusercontent.com/nlohmann/json/v3.11.3/single_include/nlohmann/json.hpp \
     -o tests/json.hpp
```

### 5.2 Compile

```bash
# From softhsmv3 root:
g++ -o pqc_validate tests/pqc_validate.cpp \
    -ldl -std=c++17 \
    -I src/lib/pkcs11 \
    -I tests/
```

On macOS with Homebrew OpenSSL:

```bash
g++ -o pqc_validate tests/pqc_validate.cpp \
    -ldl -std=c++17 \
    -I src/lib/pkcs11 \
    -I tests/ \
    -I$(brew --prefix openssl@3)/include
```

### 5.3 Run

```bash
# Minimal — auto-detects or initializes token
./pqc_validate ./build/src/lib/libsofthsmv3.dylib

# Linux
./pqc_validate ./build/src/lib/libsofthsmv3.so

# With explicit PINs and verbose hex output
./pqc_validate ./build/src/lib/libsofthsmv3.dylib \
    --so-pin 1234 --user-pin 5678 --verbose

# Custom ops file, results into /tmp
./pqc_validate ./build/src/lib/libsofthsmv3.dylib \
    --ops-file tests/pqc_validate_ops.json \
    --output-dir /tmp
```

### 5.4 Command-line options

| Option | Default | Description |
|---|---|---|
| `<library>` | (required) | Path to `libsofthsmv3.dylib` / `.so` |
| `--so-pin PIN` | `1234` | Security Officer PIN |
| `--user-pin PIN` | `5678` | User (application) PIN |
| `--ops-file PATH` | `tests/pqc_validate_ops.json` | Operations template |
| `--output-dir PATH` | `.` (cwd) | Directory for result JSON |
| `--verbose` | off | Print hex inputs/outputs per operation |

### 5.5 Console output

```
╔══ SoftHSMv3 PKCS#11 v3.2 Algorithm Validator ══╗
  Library:    ./build/src/lib/libsofthsmv3.dylib
  Ops file:   tests/pqc_validate_ops.json
  Output:     ./pqc_validate_03022026.json

══ rng-001 — C_GenerateRandom — 32 bytes ══
  ✓ C_GenerateRandom 32 bytes

══ hash-sha256-001 — SHA-256 Digest — NIST vector ("abc") ══
  ✓ SHA-256 Digest — NIST vector ("abc")

══ ml-kem-512-001 — ML-KEM-512 — encapsulate/decapsulate round-trip ══
  ✓ ML-KEM-512 encapsulate/decapsulate round-trip

> **Note (v0.8.0):** ML-KEM, ML-DSA and SLH-DSA are now fully implemented and
> pass on both engines. A `SKIP: not yet implemented` for any of these is no
> longer expected — it now indicates a build/link problem or a regression, not
> normal output. The phase tables in §7 are retained for historical context.

╔══ Summary ══╗
  Total:   15
  Passed:  15
  Failed:  0
  Skipped: 0
  Output:  ./pqc_validate_07042026.json
```

(That is the shipped 15-case default ops file — all pass against a v0.8.0 token.
A non-zero *Skipped* now means a mechanism is missing from the loaded module,
and any *Failed* is a real regression.)

### 5.6 Exit codes

| Code | Meaning |
|---|---|
| `0` | All tests passed or skipped; no failures |
| `1` | One or more tests failed |
| `2` | Bad arguments or cannot open library / ops file |

---

## 6. JSON Result Files

Each `pqc_validate` run produces one dated JSON file:

```
pqc_validate_03022026.json       ← first run on 2026-03-02
pqc_validate_03022026_r1.json    ← second run same day
pqc_validate_03022026_r2.json    ← third run, etc.
```

### Top-level structure

```json
{
  "schema_version": "1.0",
  "run_metadata": {
    "run_id": "pqc_validate_03022026",
    "started_at": "2026-03-02T10:23:44Z",
    "completed_at": "2026-03-02T10:25:01Z",
    "library_path": "./build/src/lib/libsofthsmv3.dylib",
    "token_slot": 0,
    "summary": { "total": 70, "passed": 52, "failed": 0, "skipped": 18 }
  },
  "operations": [
    {
      "id": "ml-kem-512-001",
      "category": "ML-KEM",
      "name": "ML-KEM-512 — encapsulate/decapsulate round-trip + tamper test",
      "result": {
        "status": "PASS",
        "timestamp": "2026-03-02T10:24:10.456Z",
        "duration_ms": 14,
        "inputs": {
          "parameter_set": "CKP_ML_KEM_512",
          "parameter_set_id": "0x00000001"
        },
        "outputs": {
          "ciphertext_len": 768,
          "secrets_match": true,
          "negative_tamper_ok": true
        },
        "error": null
      }
    }
  ]
}
```

### Status values

| Status | Meaning |
|---|---|
| `PASS` | Round-trip verified; negative test confirmed |
| `FAIL` | Test failed; inspect `error` field |
| `SKIP` | Mechanism returned `CKR_MECHANISM_INVALID` or `CKR_FUNCTION_NOT_SUPPORTED` |

SKIPs are expected and **do not count as failures** (exit code `0`).

---

## 7. Phase-by-Phase Expectations

> **Current status (v0.8.0):** all phases below are complete. Classical, ML-DSA,
> ML-KEM and SLH-DSA all **PASS** on both the C++ and Rust engines. The tables
> are kept as a historical map of how the suite grew; today the expected result
> is the bottom row (everything PASS). A PQC `SKIP` now signals a regression.

### p11test (CppUnit)

| Phase | Tests expected to pass |
|---|---|
| Phase 0 | InitTests, InfoTests, SessionTests, TokenTests, UserTests, ObjectTests |
| Phase 1 | + DigestTests, RandomTests, SymmetricAlgorithmTests, AsymWrapUnwrapTests, DeriveTests, SignVerifyTests (RSA/ECDSA/EdDSA), AsymEncryptDecryptTests (RSA) |
| Phase 2 | + SignVerifyTests (ML-DSA) |
| Phase 3 | + AsymEncryptDecryptTests (ML-KEM) |
| Phase 4+ | + SLH-DSA variants |

### pqc_validate

| Phase | Classical | ML-DSA | ML-KEM | SLH-DSA | Expected exit |
|---|---|---|---|---|---|
| Phase 1 (EVP migration) | PASS | SKIP | SKIP | SKIP | `0` |
| Phase 2 (ML-DSA) | PASS | **PASS** | SKIP | SKIP | `0` |
| Phase 3 (ML-KEM) | PASS | PASS | **PASS** | SKIP | `0` |
| Phase 4+ (SLH-DSA) | PASS | PASS | PASS | **PASS** | `0` |

A transition from SKIP → PASS signals that the phase implementation is complete.
A FAIL in any previously-passing category signals a regression.

---

## 8. Debugging Tips

### Check which mechanisms are registered

```bash
./build/src/bin/util/softhsm2-util --show-slots --verbose
```

This lists all available slots and token info, but not mechanisms directly.
Use `pqc_validate --verbose` to see which mechanisms return
`CKR_MECHANISM_INVALID` vs. `CKR_OK`.

### CKR_MECHANISM_INVALID on a classical algorithm

Means the mechanism was not registered in `SoftHSM::prepareSupportedMechanisms()`.
Check `src/lib/SoftHSM.cpp` around that function and verify the
`CKM_*` constant is listed.

### Token not found / CKR_TOKEN_NOT_PRESENT

The token directory may be missing or pointing to the wrong path.
Check your `SOFTHSM2_CONF` environment variable:

```bash
echo $SOFTHSM2_CONF
./build/src/bin/util/softhsm2-util --show-slots
```

Re-initialize if needed (destructive — deletes existing tokens):

```bash
rm -rf /path/to/tokens/*
./build/src/bin/util/softhsm2-util \
    --init-token --slot 0 --label "pqctest" --so-pin 1234 --pin 5678
```

### ML-KEM SKIP — `C_EncapsulateKey not found`

`pqc_validate` loads `C_EncapsulateKey` and `C_DecapsulateKey` via `dlsym`.
If the warning appears, the symbols are not exported from the library:

```bash
# Check exported symbols
nm -gD build/src/lib/libsofthsmv3.dylib | grep -i encapsulate
```

If the function is absent, Phase 3 (ML-KEM) is not yet implemented.

### Shared secret mismatch in ECDH / ML-KEM

This usually means the EC point format is wrapped in a DER OCTET STRING.
The `pqc_validate` `stripEcPointWrapper()` helper handles this
automatically, but if you see `CKR_ARGUMENTS_BAD` from `C_DeriveKey`,
inspect the raw `CKA_EC_POINT` byte content:

```bash
./pqc_validate ./build/src/lib/libsofthsmv3.dylib --verbose 2>&1 | grep -A5 "ECDH"
```

### OpenSSL version mismatch

```bash
# Verify the library was linked against the expected OpenSSL
otool -L build/src/lib/libsofthsmv3.dylib | grep ssl   # macOS
ldd build/src/lib/libsofthsmv3.so | grep ssl           # Linux
```

### Enable debug logging

Set the log level in your `softhsmv3.conf`:

```ini
log.level = DEBUG
```

Or at CMake configure time:

```bash
cmake -B build -DDEFAULT_LOG_LEVEL=DEBUG ...
```

---

## 9. CI Integration

> Real CI (`.github/workflows/ci.yml`) builds OpenSSL 3.6.3 from source
> (Ubuntu 24.04's `libssl-dev` is 3.0.13, below the 3.5.0 floor) and runs
> `ctest --output-on-failure` — it does not build or run `pqc_validate`. The
> snippet below is illustrative for a project that wants to add the
> `pqc_validate` JSON artifact on top of that; adjust the OpenSSL install
> step for your distro.

### Minimal CI snippet (GitHub Actions)

```yaml
- name: Install dependencies
  run: |
    sudo apt-get install -y cmake libssl-dev libcppunit-dev
    # libssl-dev on Ubuntu 24.04 is 3.0.13 — too old (CMake requires >= 3.5.0).
    # Build/install a newer OpenSSL first, or point -DOPENSSL_ROOT_DIR at one.

- name: Build
  run: |
    cmake -B build -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=ON
    cmake --build build -j$(nproc)

- name: Run CppUnit tests
  run: cd build && ctest --output-on-failure

- name: Download json.hpp
  run: |
    curl -L https://raw.githubusercontent.com/nlohmann/json/v3.11.3/single_include/nlohmann/json.hpp \
         -o tests/json.hpp

- name: Build pqc_validate
  run: |
    g++ -o pqc_validate tests/pqc_validate.cpp \
        -ldl -std=c++17 -I src/lib/pkcs11 -I tests/

- name: Run pqc_validate
  run: |
    ./build/src/bin/util/softhsm2-util \
        --init-token --slot 0 --label "pqctest" --so-pin 1234 --pin 5678
    ./pqc_validate ./build/src/lib/libsofthsmv3.so \
        --so-pin 1234 --user-pin 5678

- name: Upload result JSON
  uses: actions/upload-artifact@v4
  with:
    name: pqc-validate-results
    path: pqc_validate_*.json
```

### Interpreting CI results

- Current expectation (v0.8.0+, per §7): exit code `0` with **every** case —
  classical and PQC — PASS. A SKIP now indicates a missing mechanism/build
  problem, not a normal phase-in-progress result.
- Any FAIL → regression; check the `error` field in the JSON artifact.
- Upload the JSON artifact so a genuine SKIP or FAIL is easy to diff against
  a prior green run.

---

## 10. Other Test Suites in This Repository

The p11test/pqc_validate workflow above is the C++ engine's own native test
surface. The rest of this repository's test coverage lives in several other
places; each has its own README with full detail, but a tester should at
least know they exist and roughly when to reach for each one.

### The Rust engine's own test suite

The Rust engine (`rust/`, `softhsmrustv3`) is not exercised by anything
above — it has an independent unit-test suite and its own checked-in PKCS#11
v3.2 conformance evidence:

```bash
cd rust
cargo test                      # native unit + FFI-dispatch tests
node test_p11_conformance.js    # regenerates rust/RUST_P11_V32_CONFORMANCE_REPORT.md
                                 # from a real run — 999/0 as of the last checked-in report
```

`test_p11_conformance.js` drives the engine through its real wasm-bindgen
`_C_*` ABI (a `--features acvp` build), not a Rust-internal shortcut, and
writes the Markdown report itself — the report is machine-generated, not
hand-edited. See `rust/README.md` and `rust/RUST_P11_V32_CONFORMANCE_REPORT.md`.

### Cross-engine differential harness (`tests/differential/`)

Two independent engines that are supposed to agree wherever the spec says
what the behavior is invites exactly the kind of prose-drift bug this repo
has hit twice before (a 2026-08-13 audit found 24 documentation statements
about C++/Rust parity that were simply wrong). `tests/differential/` replaces
prose with a harness: it `dlopen`s both engines into one process, drives them
through 49 identical scenarios, and diffs every observable output field by
field. Legal differences (the spec is silent, or a product decision) live in
`tests/differential/exceptions.json` with a citation; anything not listed
there fails the run.

```bash
./scripts/run-differential-harness.sh                 # build both engines, run everything
./scripts/run-differential-harness.sh --list          # list the scenarios
./scripts/run-differential-harness.sh --only bytes.   # one scenario group
./scripts/run-differential-harness.sh --verbose       # print the covered divergences too
```

Reports land in `build_union/p11_diff_report.{md,json}`. See
`tests/differential/README.md` for the full design rationale (why one
process rather than two, what it deliberately does not cover — the Rust
*native* API the KMIP server calls directly, on-disk persistence, threading —
and how to add a scenario).

### WASM / Node.js suites (`tests/`)

`pqc_validate` (§5 above) is native-only. The WASM builds of both engines are
exercised by Node.js harnesses driven from the repo-root `package.json`:

| Command | Runs | What it does |
|---|---|---|
| `npm test` | `tests/smoke-wasm.mjs` | Full PKCS#11 v3.2 lifecycle smoke test against the C++ WASM module (`C_Initialize` → token init → ML-KEM-768 keygen/encap/decap → ML-DSA-65 keygen/sign/verify → `C_Finalize`). Requires `wasm/softhsm.{js,wasm}` (`npm run build` first). |
| `npm run test:acvp` | `tests/acvp-wasm.mjs` | 20 ACVP test suites against the C++ and/or Rust WASM engines via raw PKCS#11 calls, using the vectors in `tests/acvp/`. `--engine=cpp\|rust\|both`, `--verbose`, `--json`. |

Also present and runnable directly with `node` (not wired into
`package.json`): `tests/parity-wasm.mjs` (cross-engine C++ vs Rust behavioral
spot-check), `tests/c-get-function-list.mjs` (Rust-only WASM
indirect-function-table coverage), `tests/test-ecdsa-sha512.mjs` (focused
`CKM_ECDSA_SHA512`/P-256 unit test), and `tests/test_acvp_lms_sigver.py`
(NIST ACVP LMS sigVer vectors against `hss_validate_signature()` directly,
bypassing PKCS#11). See `tests/README.md` for the complete file-by-file map.

### OpenSSL provider coverage harness (`scripts/test-openssl-provider.sh`)

This is the harness referenced in §4 above for the probe binaries `ctest`
does not run. It exercises the vendored `pkcs11-provider`
(`src/vendor/pkcs11-provider/`) against **both** PKCS#11 engines under a real
OpenSSL 3.6.3 build — every result is cross-checked against the *other*
implementation (provider-sign → software-verify, software-encap →
provider-decap), never self-verified. Design record and the full T-case list:
`docs/openssl-provider-coverage-audit-2026-08-25.md`.

```bash
bash scripts/test-openssl-provider.sh
```

Key environment overrides (defaults target the project's own dev container —
override for a local run): `OPENSSL_BIN` (must be OpenSSL ≥ 3.6, default
`/usr/local/ssl/bin/openssl`), `HSM_ROOT` (defaults to this script's own repo
root — always overridable, and self-locating so a `git worktree` checkout
tests itself rather than silently loading the main tree's binaries),
`PROVIDER_SO`, `CPP_ENGINE_SO`, `RUST_ENGINE_SO`, `SOFTHSM_UTIL`. It prints a
single greppable summary line: `OPENSSL-PROVIDER-HARNESS: PASS=<n> FAIL=0
XFAIL=<m> XPASS=0` — an `XPASS` (a documented-gap case unexpectedly passing)
fails the run just as loudly as a real `FAIL`, so a remediation that closes a
gap must also flip its expectation in the harness, not just land the fix.
Runs on both Linux and macOS (the composite-signature probe and several
`stat`/`grep` portability issues were fixed for macOS in 2026-09).

### The real pre-push gate: `scripts/local-gate.sh`

None of the suites above run in GitHub CI by project directive (2026-07-01)
— "new test suites run locally, never in GitHub CI." `scripts/local-gate.sh`
is the single script that runs them all before a push: KMIP/CACP Rust tests,
the Rust engine's own test suite, the OASIS KMIP 3.0 replay harness, the
Rust PKCS#11 v3.2 conformance regeneration, and the cross-engine
differential harness, by default; `--cpp` adds the C++ `ctest` run from this
guide, `--openssl-provider` adds the harness above, and several other flags
gate slower or environment-specific suites (`--acvp-wasm`, `--release-xmss`,
`--tls-interop`, `--javajce`, `--javajce-remote`). `--all` runs everything —
see `RELEASING.md` for when a full `--all` run is required. Read the script's
own header comment for the authoritative, current step list; it changes more
often than this doc does.

```bash
bash scripts/local-gate.sh              # core gate
bash scripts/local-gate.sh --cpp --openssl-provider   # + this guide's ctest run + the provider harness
bash scripts/local-gate.sh --all        # everything (pre-release)
```

---

## 11. Key Template Requirements

> **Spec reference**: PKCS#11 v3.2, ratified OASIS Standard (03 June 2026) — `docs/refs/pkcs11-spec-v3.2-os.pdf`
> (page/section/table numbers below are unchanged from the earlier CSD01 draft, verified against the ratified text)
> §6.67 ML-DSA (p. 447) — Tables 280, 281; §6.67.4 key pair generation |
> §6.68 ML-KEM (p. 453) — Tables 287, 288; §6.68.4 key pair generation; §6.68.5 Key Agreement |
> §6.69 SLH-DSA (p. 456) — Tables 290, 291; §6.69.4 key pair generation

---

### SoftHSMv3 attribute check flags (P11Attributes.h)

These flags govern which attributes are mandatory, forbidden, or auto-set for each
PKCS#11 creation operation. They are a SoftHSMv3 implementation detail (not in the spec).

| Flag | Value | Meaning |
| --- | --- | --- |
| `ck1` | 1 | MUST be specified when object is created with `C_CreateObject` |
| `ck2` | 2 | MUST NOT be specified when object is created with `C_CreateObject` |
| `ck3` | 4 | MUST be specified when object is generated with `C_GenerateKey` / `C_GenerateKeyPair` |
| `ck4` | 8 | MUST NOT be specified when object is generated with `C_GenerateKey` / `C_GenerateKeyPair` (set internally instead) |
| `ck6` | 32 | MUST NOT be specified on `C_UnwrapKey` |

`CreateObject` with `OBJECT_OP_GENERATE` enforces **ck3**: if the attribute is not in the
caller's template, it returns `CKR_TEMPLATE_INCOMPLETE`.

Source: `src/lib/P11Objects.cpp` lines 261–282 (the per-op check loop), `src/lib/P11Attributes.h` lines 74–79 (flag definitions).

---

### ML-KEM key object attributes (spec §6.68, Tables 287–288)

**Public key** (`CKO_PUBLIC_KEY`, `CKK_ML_KEM`):

| Attribute | Type | Required on C_CreateObject | Contributed by C_GenerateKeyPair |
| --- | --- | --- | --- |
| `CKA_PARAMETER_SET` | `CK_ML_KEM_PARAMETER_SET_TYPE` | Yes | Caller supplies in pub template |
| `CKA_VALUE` | Byte array (ek) | Yes | Mechanism writes |

**Private key** (`CKO_PRIVATE_KEY`, `CKK_ML_KEM`):

| Attribute | Type | Required on C_CreateObject | Notes |
| --- | --- | --- | --- |
| `CKA_PARAMETER_SET` | `CK_ML_KEM_PARAMETER_SET_TYPE` | Yes | NOT in keygen private template (see below) |
| `CKA_SEED` | Byte array (d\|\|z) | At least one of SEED/VALUE | Mechanism writes |
| `CKA_VALUE` | Byte array (dk) | At least one of SEED/VALUE | Mechanism writes |

Parameter sets: `CKP_ML_KEM_512`, `CKP_ML_KEM_768`, `CKP_ML_KEM_1024`

---

### ML-DSA key object attributes (spec §6.67, Tables 280–281)

**Public key** (`CKO_PUBLIC_KEY`, `CKK_ML_DSA`):

| Attribute | Type | Required on C_CreateObject | Contributed by C_GenerateKeyPair |
| --- | --- | --- | --- |
| `CKA_PARAMETER_SET` | `CK_ML_DSA_PARAMETER_SET_TYPE` | Yes | Caller supplies in pub template |
| `CKA_VALUE` | Byte array (vk) | Yes | Mechanism writes |

**Private key** (`CKO_PRIVATE_KEY`, `CKK_ML_DSA`):

| Attribute | Type | Required on C_CreateObject | Notes |
| --- | --- | --- | --- |
| `CKA_PARAMETER_SET` | `CK_ML_DSA_PARAMETER_SET_TYPE` | Yes | NOT in keygen private template (see below) |
| `CKA_SEED` | Byte array (ξ) | At least one of SEED/VALUE | Mechanism writes |
| `CKA_VALUE` | Byte array (sk) | At least one of SEED/VALUE | Mechanism writes |

Parameter sets: `CKP_ML_DSA_44`, `CKP_ML_DSA_65`, `CKP_ML_DSA_87`

---

### SLH-DSA key object attributes (spec §6.69, Tables 290–291)

**Public key** (`CKO_PUBLIC_KEY`, `CKK_SLH_DSA`):

| Attribute | Type | Required on C_CreateObject | Contributed by C_GenerateKeyPair |
| --- | --- | --- | --- |
| `CKA_PARAMETER_SET` | `CK_SLH_DSA_PARAMETER_SET_TYPE` | Yes | Caller supplies in pub template |
| `CKA_VALUE` | Byte array | Yes | Mechanism writes |

**Private key** (`CKO_PRIVATE_KEY`, `CKK_SLH_DSA`):

| Attribute | Type | Required on C_CreateObject | Notes |
| --- | --- | --- | --- |
| `CKA_PARAMETER_SET` | `CK_SLH_DSA_PARAMETER_SET_TYPE` | Yes | NOT in keygen private template (see below) |
| `CKA_VALUE` | Byte array | Yes | Mechanism writes; no CKA_SEED for SLH-DSA |

Parameter sets: `CKP_SLH_DSA_SHA2_128S/F`, `CKP_SLH_DSA_SHAKE_128S/F`, `CKP_SLH_DSA_SHA2_192S/F`, `CKP_SLH_DSA_SHAKE_192S/F`, `CKP_SLH_DSA_SHA2_256S/F`, `CKP_SLH_DSA_SHAKE_256S`

---

### C_GenerateKeyPair — ML-KEM key templates

Source: spec §6.68.4. Key-pair generation for every key type (RSA, EC, ML-DSA,
ML-KEM, SLH-DSA, HSS, XMSS, XMSS-MT) is handled by one shared function,
`SoftHSM::generateKeyPairImpl` in `src/lib/SoftHSM_keygen.cpp` — not
`SoftHSM_kem.cpp`, which holds only `C_EncapsulateKey`/`C_DecapsulateKey` —
dispatching on `CKM_ML_KEM_KEY_PAIR_GEN`.

> **Spec rule**: `CKA_PARAMETER_SET` is specified in the **public key** template only.
> It MUST NOT be in the private key template for `C_GenerateKeyPair` (spec §6.68.4:
> *"ML-KEM private keys are only generated as part of a key pair, and the parameter
> set is specified in the template for the ML-KEM public key"*).

```c
// Public key — CKA_PARAMETER_SET MUST be here (specifies which variant to generate)
CK_ATTRIBUTE pubTpl[] = {
    { CKA_CLASS,         &pubClass,    sizeof(pubClass)    },
    { CKA_KEY_TYPE,      &kkMlKem,     sizeof(kkMlKem)     },
    { CKA_PARAMETER_SET, &paramSet512, sizeof(paramSet512) }, // CKP_ML_KEM_512/768/1024
    { CKA_ENCAPSULATE,   &bTrue,       sizeof(bTrue)       },
};
// Private key — NO CKA_PARAMETER_SET (inherited from public key template per spec)
CK_ATTRIBUTE privTpl[] = {
    { CKA_CLASS,       &privClass, sizeof(privClass) },
    { CKA_KEY_TYPE,    &kkMlKem,   sizeof(kkMlKem)   },
    { CKA_SENSITIVE,   &bTrue,     sizeof(bTrue)     },
    { CKA_DECAPSULATE, &bTrue,     sizeof(bTrue)     },
};
```

The mechanism contributes `CKA_CLASS`, `CKA_KEY_TYPE`, `CKA_VALUE` to the public key;
`CKA_CLASS`, `CKA_KEY_TYPE`, `CKA_PARAMETER_SET`, `CKA_SEED`, `CKA_VALUE` to the private key.

### C_GenerateKeyPair — ML-DSA key templates

Source: spec §6.67.4; the same shared `SoftHSM::generateKeyPairImpl` in
`src/lib/SoftHSM_keygen.cpp` described above (not `SoftHSM_sign.cpp` — that
file holds the `C_Sign`/`C_Verify` operations only, not key generation),
dispatching on `CKM_ML_DSA_KEY_PAIR_GEN`.

Same rule: `CKA_PARAMETER_SET` in public key template only.

```c
// Public key
CK_ATTRIBUTE pubTpl[] = {
    { CKA_CLASS,         &pubClass,   sizeof(pubClass)   },
    { CKA_KEY_TYPE,      &kkMlDsa,    sizeof(kkMlDsa)    },
    { CKA_PARAMETER_SET, &paramSet44, sizeof(paramSet44) }, // CKP_ML_DSA_44/65/87
    { CKA_VERIFY,        &bTrue,      sizeof(bTrue)      },
};
// Private key — NO CKA_PARAMETER_SET
CK_ATTRIBUTE privTpl[] = {
    { CKA_CLASS,     &privClass, sizeof(privClass) },
    { CKA_KEY_TYPE,  &kkMlDsa,   sizeof(kkMlDsa)   },
    { CKA_SENSITIVE, &bTrue,     sizeof(bTrue)     },
    { CKA_SIGN,      &bTrue,     sizeof(bTrue)     },
};
```

---

### C_EncapsulateKey / C_DecapsulateKey — output secret key template

Source: spec §6.68.5; `src/lib/SoftHSM_kem.cpp` — `SoftHSM::encapsulateKeyImpl`
(starts ~line 172, default-attribute merge via `extractObjectInformation(...,
true)` ~line 305) and `SoftHSM::decapsulateKeyImpl` (starts ~line 505, same
merge ~line 617).

The spec (§6.68.5) states: *"The mechanism contributes the result as the CKA_VALUE attribute
of the new key; other attributes required by the key type must be specified in the template."*

**Default values applied before caller template is merged (SoftHSMv3 bImplicit = true):**

| Attribute | Default | Notes |
| --- | --- | --- |
| `CKA_CLASS` | `CKO_SECRET_KEY` | Hardcoded; must equal `CKO_SECRET_KEY` if supplied |
| `CKA_TOKEN` | `CK_FALSE` | Session object (not persisted to disk) |
| `CKA_PRIVATE` | `CK_TRUE` | Value is encrypted-at-rest in the token |
| `CKA_KEY_TYPE` | `CKK_GENERIC_SECRET` | Hardcoded; caller override stripped |

**Attributes stripped from the caller template (SoftHSMv3 implementation detail):**
`CKA_CLASS`, `CKA_TOKEN`, `CKA_PRIVATE`, `CKA_KEY_TYPE`, `CKA_VALUE`

**SoftHSMv3 mandatory attribute — `CKA_VALUE_LEN` (0x00000161):**

`P11AttrValueLen`'s constructor defaults to `ck2|ck3`
(`src/lib/P11Attributes.h` line 1251), and `P11GenericSecretKeyObj::init()`
(`src/lib/P11Objects.cpp` line 1665) constructs it with that default. Because
`CreateObject` is called with `OBJECT_OP_GENERATE`, the `ck3` check fires and
returns `CKR_TEMPLATE_INCOMPLETE` if `CKA_VALUE_LEN` is absent.

> **Note**: The PKCS#11 v3.2 spec example (§5.18.8) uses `CKK_AES` and does not include
> `CKA_VALUE_LEN`. The requirement is a SoftHSMv3 implementation constraint enforced by
> the `ck3` flag for `CKK_GENERIC_SECRET`, not a universal spec mandate for all implementations.

For ML-KEM, the shared secret is **always 32 bytes** for all parameter sets
(ML-KEM-512, -768, -1024) per FIPS 203 §7. Always supply:

```c
CK_ULONG valueLen = 32;
CK_ATTRIBUTE tpl[] = {
    { CKA_CLASS,       &secretClass, sizeof(secretClass) },
    { CKA_VALUE_LEN,   &valueLen,    sizeof(valueLen)    },  // MANDATORY in SoftHSMv3
    { CKA_SENSITIVE,   &bFalse,      sizeof(bFalse)      },  // optional
    { CKA_EXTRACTABLE, &bTrue,       sizeof(bTrue)        },  // optional
};
C_EncapsulateKey(hSession, &mech, hPubKey, tpl, 4, pCiphertext, &ctLen, &hSecret);
```

Omitting `CKA_VALUE_LEN` → `CKR_TEMPLATE_INCOMPLETE (0x000000d0)`.

**Attributes written internally by SoftHSMv3 (do NOT include in template):**

| Attribute | Flag | Written by |
| --- | --- | --- |
| `CKA_VALUE` | ck4 | Injected post-`CreateObject` with actual shared secret bytes |
| `CKA_LOCAL` | ck4 | Set to `false` (key imported from external operation) |
| `CKA_ALWAYS_SENSITIVE` | ck4 | Set to `false` |
| `CKA_NEVER_EXTRACTABLE` | ck4 | Set to `false` |

---

## Related Files

| File | Description |
|---|---|
| `tests/pqc_validate.cpp` | Standalone validation program |
| `tests/pqc_validate_ops.json` | Operations template (shipped; 15-case runnable subset — round-trips + NIST/RFC KAT, extensible) |
| `tests/README.md` | Build + run quick-reference |
| `src/lib/test/` | CppUnit p11test suite |
| `src/lib/pkcs11/pkcs11t.h` | All `CKM_*`, `CKK_*`, `CKA_*`, `CKP_*` constants |
| `src/lib/pkcs11/pkcs11f.h` | `C_EncapsulateKey` / `C_DecapsulateKey` signatures |
| `docs/gap-analysis-pkcs11-v3.2.md` | PKCS#11 v3.2 gap analysis |
| `rust/` , `rust/RUST_P11_V32_CONFORMANCE_REPORT.md` | Rust engine + its own checked-in PKCS#11 v3.2 conformance evidence — see [§10](#10-other-test-suites-in-this-repository) |
| `tests/differential/` | Cross-engine differential harness (C++ vs Rust) — see [§10](#10-other-test-suites-in-this-repository) |
| `scripts/test-openssl-provider.sh` | Vendored OpenSSL provider vs both engines, live — see [§10](#10-other-test-suites-in-this-repository) |
| `scripts/local-gate.sh` | The pre-push gate that runs all of the above — see [§10](#10-other-test-suites-in-this-repository) |
| `cpp_compliance_report.md` / `.json` | Checked-in `p11_v32_compliance_test` output (891/0/48 as of this writing) |
