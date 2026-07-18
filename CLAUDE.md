# CLAUDE.md — softhsmv3

PQC-enabled fork of SoftHSM2 v2.7.0. OpenSSL-only backend, PKCS#11 v3.2,
ML-DSA (FIPS 204) + ML-KEM (FIPS 203), targeting Emscripten WASM for
in-browser HSM emulation in the PQC Timeline App.

## Build

```bash
# Native build (macOS/Linux)
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)
cmake --build build -j$(nproc)

# Run tests
cd build && make check

# Emscripten WASM build (Phase 4)
emcmake cmake -B build-wasm -DCMAKE_BUILD_TYPE=Release
cmake --build build-wasm
```

Requirements: OpenSSL >= 3.5, CMake >= 3.16, C++17 compiler.

## Architecture

**Single backend: OpenSSL EVP-only.** No Botan, no ENGINE-based APIs.

```
src/lib/
  crypto/           # Crypto implementations (OSSL* + abstract bases)
  pkcs11/           # PKCS#11 v3.2 headers (pkcs11.h, pkcs11f.h, pkcs11t.h)
  SoftHSM.cpp/h     # Main PKCS#11 dispatch + mechanism table
  common/           # Utilities (logging, config, byte strings)
  data_mgr/         # Secure data management
  object_store/     # Token + session object store
  session_mgr/      # Session lifecycle
  slot_mgr/         # Slot and token management
  handle_mgr/       # Handle allocation
src/bin/
  softhsm2-util/    # CLI tool
  softhsm2-keyconv/ # Key conversion utility
```

**Retained algorithms**: RSA, ECDSA, ECDH, EdDSA, AES, SHA-1/224/256/384/512, HMAC, CMAC.

**PQC additions**: ML-DSA-44/65/87, ML-KEM-512/768/1024, SLH-DSA (SHA2/SHAKE × 12
param sets), stateful HSS/LMS and XMSS/XMSS-MT, and hybrid KEMs
(X25519MLKEM768 / SecP256r1MLKEM768, exposed via KMIP/CACP).

**Second engine**: a Rust engine (`softhsmrustv3`, in `rust/`) provides the WASM
crypto path and is the production backend for the KMIP server and CACP policy
engine. It has its own checked-in PKCS#11 v3.2 conformance evidence
(`rust/RUST_P11_V32_CONFORMANCE_REPORT.md`).

**Beyond the PKCS#11 core**: a KMIP 3.0 server + crypto-agility policy engine
(`kmip/`, CACP), and protocol wrappers (`openssh-pkcs11/`, `openpgp/`,
`openmls-provider/`, `strongswan-pkcs11/`, `JavaJCE/`).

## Coding Conventions

- **C++17 only** — use structured bindings, `std::optional`, `[[nodiscard]]` where appropriate
- **EVP-only OpenSSL API** — never use deprecated `RSA_*`, `EC_KEY_*`, `ENGINE_*` functions
- Use `EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL)` pattern for all key operations
- New PQC algorithms follow the EdDSA file pattern: `OSSLMLxxx.cpp/h`, `OSSLMLxxxKeyPair.cpp/h`, `OSSLMLxxxPublicKey.cpp/h`, `OSSLMLxxxPrivateKey.cpp/h`
- All error paths must call `CryptoFactory::logError()` or use the existing `ERROR_MSG()` macro
- PKCS#11 function implementations live in `src/lib/SoftHSM.cpp`
- New mechanisms registered in `SoftHSM::prepareSupportedMechanisms()`
- New key types registered in `OSSLCryptoFactory::getAsymmetricAlgorithm()`

## Status

The original Phase 0–6 roadmap (import + strip legacy, OpenSSL 3.x EVP
migration, ML-DSA, ML-KEM, Emscripten WASM, npm package, app integration) is
**complete**, as is the later hardening/conformance work. Current release is
tracked in `CHANGELOG.md` (**0.15.0**, 2026-07-18). Recent programs: composite/
hybrid certificate formats (LAMPS, Catalyst, RFC 9763, Chameleon), KMIP 3.0
§9.10 Maximum Response Size enforcement, PKCS#11 v3.2 conformance evidence
(real Split Key + asynchronous processing, honest `Query`), a follow-up
gap-remediation audit (13 findings across both crates — silently-dropped
errors, stub behavior — all fixed), the CACP crypto-agility policy engine
(with its fail-open enforcement seams closed),
and hybrid KEMs. See `CHANGELOG.md` for the authoritative per-release history
rather than this file.

## Key PKCS#11 v3.2 Constants (PQC)

```c
CKK_ML_KEM              = 0x00000049
CKK_ML_DSA              = 0x0000004a
CKM_ML_KEM              = 0x00000017
CKM_ML_DSA_KEY_PAIR_GEN = 0x0000001c
CKM_ML_DSA              = 0x0000001d
CKA_PARAMETER_SET       = 0x0000061d  // CKP_ML_DSA_44/65/87, CKP_ML_KEM_512/768/1024
CKA_ENCAPSULATE         = 0x00000633
CKA_DECAPSULATE         = 0x00000634
CKA_SEED                = 0x00000637  // deterministic seed: ξ for ML-DSA, d||z for ML-KEM
```

Values verified from `src/lib/pkcs11/pkcs11t.h` and PKCS#11 v3.2 CSD01 spec
(`docs/refs/pkcs11-spec-v3.2-csd01.pdf`).

New functions in pkcs11f.h:
- `C_EncapsulateKey` — ML-KEM encapsulation
- `C_DecapsulateKey` — ML-KEM decapsulation

## Source of Truth — PKCS#11 Constants

**The PKCS#11 v3.2 spec and its normative header `pkcs11t.h` are the ONLY reference for all `CK*` constant values.**

- Canonical `pkcs11t.h`: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/include/pkcs11-v3.2/pkcs11t.h
- Local copy: `src/lib/pkcs11/pkcs11t.h` (kept in sync with the spec)

When editing `constants.js` or any file with `CK*` values, **grep `src/lib/pkcs11/pkcs11t.h` first** — do not guess or infer from secondary sources. If a value in any JS/TS file disagrees with `pkcs11t.h`, `pkcs11t.h` wins.

Key PQC type values for quick reference (as of v3.2):

| Constant | Value |
|---|---|
| `CKK_HSS` | `0x46` |
| `CKK_XMSS` | `0x47` |
| `CKK_XMSSMT` | `0x48` |
| `CKK_ML_KEM` | `0x49` |
| `CKK_ML_DSA` | `0x4a` |
| `CKK_SLH_DSA` | `0x4b` |

## References

- [SoftHSM2 upstream](https://github.com/softhsm/SoftHSMv2)
- [PKCS#11 v3.2 spec](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html)
- [PKCS#11 v3.2 pkcs11t.h](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/include/pkcs11-v3.2/pkcs11t.h)
- [FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final)
- [OpenSSL EVP_PKEY-ML-DSA](https://docs.openssl.org/3.5/man7/EVP_PKEY-ML-DSA/)
- [OpenSSL EVP_PKEY-ML-KEM](https://docs.openssl.org/3.5/man7/EVP_PKEY-ML-KEM/)
