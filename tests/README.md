# SoftHSMv3 PKCS#11 v3.2 Algorithm Validation

`pqc_validate` is a standalone C++17 program that exercises every mechanism
supported by OpenSSL 3.6.0 through the SoftHSMv3 PKCS#11 v3.2 interface.

Each test performs a **symmetric round-trip** (Sign→Verify, Encrypt→Decrypt,
Encapsulate→Decapsulate) and includes **negative tamper tests** where
applicable. Results are written to a dated JSON file that doubles as both an
ops template and a result store.

---

## Prerequisites

| Item | Minimum version |
|---|---|
| Compiler | g++ or clang++ with C++17 support |
| OpenSSL | 3.3+ (3.6.0 for SLH-DSA) |
| SoftHSMv3 | built with `cmake --build build` |
| nlohmann/json | v3.11.3 (downloaded below) |

---

## Build

```bash
# 1. From the softhsmv3 root — download the single-header JSON library
curl -L https://raw.githubusercontent.com/nlohmann/json/v3.11.3/single_include/nlohmann/json.hpp \
     -o tests/json.hpp

# 2. Compile
g++ -o pqc_validate tests/pqc_validate.cpp \
    -ldl -std=c++17 \
    -I src/lib/pkcs11 \
    -I tests/

# macOS (if needed)
g++ -o pqc_validate tests/pqc_validate.cpp \
    -ldl -std=c++17 \
    -I src/lib/pkcs11 \
    -I tests/ \
    -framework CoreFoundation
```

---

## Initialize Token (first run only)

```bash
./build/src/bin/util/softhsm2-util \
    --init-token --slot 0 \
    --label "pqcvalidate" \
    --so-pin 1234 --pin 5678
```

If no token is present, `pqc_validate` will attempt to initialize one
automatically using the supplied `--so-pin` and `--user-pin` values.

---

## Run

```bash
# Basic
./pqc_validate ./build/src/lib/libsofthsmv3.so

# Custom PINs and verbose output
./pqc_validate ./build/src/lib/libsofthsmv3.so \
    --so-pin 1234 --user-pin 5678 --verbose

# Custom ops file and output directory
./pqc_validate ./build/src/lib/libsofthsmv3.so \
    --ops-file tests/pqc_validate_ops.json \
    --output-dir /tmp/pqc-results
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--so-pin PIN` | `1234` | Security Officer PIN |
| `--user-pin PIN` | `5678` | User PIN |
| `--ops-file PATH` | `tests/pqc_validate_ops.json` | Operations template |
| `--output-dir PATH` | `.` (cwd) | Directory for result JSON |
| `--verbose` | off | Print hex inputs/outputs |

---

## Output

Each run produces one dated JSON file:

```
pqc_validate_03022026.json       ← first run on 2026-03-02
pqc_validate_03022026_r1.json    ← second run same day
pqc_validate_03022026_r2.json    ← third run, etc.
```

The file contains:
- `run_metadata` — timestamps, library path, slot, pass/fail/skip summary
- `operations[]` — each op from the template, now with a `result` object:

```json
{
  "id": "ml-kem-512-001",
  "result": {
    "status": "PASS",
    "timestamp": "2026-03-02T10:23:45.123Z",
    "duration_ms": 12,
    "inputs": { "parameter_set": "CKP_ML_KEM_512" },
    "outputs": {
      "ciphertext_len": 768,
      "secrets_match": true,
      "negative_tamper_ok": true
    },
    "error": null
  }
}
```

Status values:
- **PASS** — test passed (round-trip verified, negative test confirmed)
- **FAIL** — test failed; `error` field explains why
- **SKIP** — mechanism returned `CKR_MECHANISM_INVALID` or
  `CKR_FUNCTION_NOT_SUPPORTED`; counted separately, not a failure

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | All tests passed or skipped; no failures |
| `1` | One or more tests failed |
| `2` | Bad arguments or could not open library/ops file |

---

## Phase-by-Phase Expectations

| Phase | Classical | ML-DSA | ML-KEM | SLH-DSA |
|---|---|---|---|---|
| Phase 1 (EVP migration) | PASS | SKIP | SKIP | SKIP |
| Phase 2 (ML-DSA) | PASS | **PASS** | SKIP | SKIP |
| Phase 3 (ML-KEM) | PASS | PASS | **PASS** | SKIP |
| Phase 4+ (SLH-DSA) | PASS | PASS | PASS | **PASS** |

Exit code `0` is expected in all phases — SKIPs do not count as failures.

---

## Mechanism Coverage

The shipped default `pqc_validate_ops.json` is a **15-case runnable subset**
(RNG, SHA-2 KAT, HMAC KAT, AES-GCM, ECDSA, EdDSA, ML-KEM ×3, ML-DSA ×3,
SLH-DSA) — enough to validate the token from a clean checkout. The tool itself
supports the fuller matrix below; extend the ops file to reach it.

| Category | Count | Notes |
|---|---|---|
| RNG | 2 | 32 and 64 bytes |
| Hash | 9 | SHA-1/224/256/384/512, SHA3-224/256/384/512 |
| HMAC | 5 | SHA-1/224/256/384/512; RFC 2202/4231 vectors |
| AES | 14 | ECB/CBC/CBC-PAD/CTR/GCM/CMAC/KEY-WRAP × 128+256 |
| RSA-Sign | 5 | 2048/3072/4096 PKCS#1v1.5; 2048 PSS-SHA256/SHA512 |
| RSA-Encrypt | 3 | 2048/3072/4096 OAEP-SHA256 |
| ECDSA | 3 | P-256/SHA-256, P-384/SHA-384, P-521/SHA-512 |
| EdDSA | 2 | Ed25519, Ed448 |
| ECDH | 3 | P-256, P-384, P-521 (Alice+Bob agree) |
| XDH | 2 | X25519, X448 (Alice+Bob agree) |
| ML-KEM | 3 | 512, 768, 1024 (encap+decap+tamper) |
| ML-DSA | 3 | 44, 65, 87 (sign+verify+tamper) |
| SLH-DSA | 12 | All 12 FIPS 205 parameter sets |

---

## Files

```
tests/
├── pqc_validate.cpp          Main validation program
├── pqc_validate_ops.json     Operations template (shipped) — 15 self-validating
│                             round-trips + NIST/RFC known-answer vectors; the
│                             default --ops-file. Extend with more cases as needed.
├── json.hpp                  nlohmann/json v3.11.3 (download via curl)
└── README.md                 This file
```
