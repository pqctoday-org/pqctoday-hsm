# SoftHSMv3 Developer Guide

## Contents

1. [What softhsmv3 is](#1-what-softhsmv3-is)
2. [Key types and mechanisms](#2-key-types-and-mechanisms)
3. [Known limitations](#3-known-limitations)
4. [Building](#4-building)
5. [Writing a C++ client](#5-writing-a-c-client)
   - [5.1 Loading the library](#51-loading-the-library)
   - [5.2 Initialize and open a token](#52-initialize-and-open-a-token)
   - [5.3 ML-DSA sign / verify walkthrough](#53-ml-dsa-sign--verify-walkthrough)
   - [5.4 ML-KEM encapsulate / decapsulate walkthrough](#54-ml-kem-encapsulate--decapsulate-walkthrough)
   - [5.5 Multi-message sign session (C_SignMessageBegin / C_SignMessageNext)](#55-multi-message-sign-session)
   - [5.6 Authenticated key wrap / unwrap (AES-GCM)](#56-authenticated-key-wrap--unwrap-aes-gcm)
   - [5.7 Pre-bound signature verification](#57-pre-bound-signature-verification)
6. [Error handling conventions](#6-error-handling-conventions)
7. [SLH-DSA Parameter Sets](#7-slh-dsa-parameter-sets)
8. [Pre-Hash Encoding Reference](#8-pre-hash-encoding-reference)
9. [StrongSwan IKEv2 Adapter](#9-strongswan-ikev2-adapter-strongswan-pkcs11)
   - [9.1 ML-KEM key exchange](#91-ml-kem-key-exchange)
   - [9.2 ML-DSA signing constants](#92-ml-dsa-signing-constants)
10. [Java JCE Integration](#10-java-jce-integration-javajce)
    - [10.1 Architecture](#101-architecture)
    - [10.2 Registration](#102-registration)
    - [10.3 ML-DSA signing / ML-KEM key exchange](#103-ml-dsa-signing--ml-kem-key-exchange)
    - [10.4 Build and test](#104-build-and-test)

---

## 1. What softhsmv3 is

SoftHSMv3 is a fork of [SoftHSM2 v2.7.0](https://github.com/softhsm/SoftHSMv2) with three
major extensions:

| Dimension | SoftHSM2 | softhsmv3 |
| --- | --- | --- |
| Crypto backend | OpenSSL 1.x / Botan | OpenSSL ≥ 3.5 only (EVP API exclusively — no ENGINE, no legacy provider) |
| PKCS#11 version | 3.0 | **3.2 (ratified OASIS Standard, 03 June 2026)** |
| PQC algorithms | None | ML-KEM-512/768/1024, ML-DSA-44/65/87, SLH-DSA-SHA2/SHAKE × 4 variants × 3 security levels |
| Build targets | Shared library | Shared library **+ Emscripten WASM** (`@pqctoday/softhsm-wasm` npm package) |

**Architecture notes:**

- **Single compilation unit per feature area** — `SoftHSM_sign.cpp`, `SoftHSM_cipher.cpp`,
  `SoftHSM_keygen.cpp`, `SoftHSM_kem.cpp`, `SoftHSM_slots.cpp` each handle one concern.
  `SoftHSM.cpp` holds shared helpers (e.g. `acquireSessionTokenKey`).
- **Dual-Model Storage Architecture** (the module is `libsofthsmv3`, not `libsofthsm2`):
  - **Native (persistent) model:** A native `.so`/`.dylib` build persists tokens to disk. The backend is chosen by `objectstore.backend` in the config file (pointed to by `SOFTHSM2_CONF`): `file` (default — a flat‑file store under `directories.tokendir`, default `/var/lib/softhsmv3/tokens/`) or `db` (SQLite, requires building with `-DWITH_OBJECTSTORE_BACKEND_DB=ON`). Token state survives process exit. There is no `-DWITH_FILE_STORE=ON` flag; the file backend is always built.
  - **WASM (memory) model:** The Emscripten build runs on an in‑memory FS with no host disk, so token state lives purely in RAM and does not survive teardown unless the embedding page adds an IndexedDB persistence layer. This is optimized for zero‑FS browser and serverless sandbox execution.
- **Single-threaded WASM target** — the Emscripten build has no SharedArrayBuffer worker pool.
  The native build is thread-safe.
- **No ENGINE, no deprecated API** — every crypto operation goes through `EVP_PKEY_*` or
  `EVP_CIPHER_*`. This is a hard requirement for OpenSSL 3.x FIPS provider compatibility.

---

## 2. Key types and mechanisms

### 2.1 PQC key types (`CKK_*`)

| Constant | Value | Algorithm family |
| --- | --- | --- |
| `CKK_HSS` | `0x46` | HSS / LMS (RFC 8554, SP 800-208) — stateful, hash-based |
| `CKK_XMSS` | `0x47` | XMSS (RFC 8391, SP 800-208) — stateful, hash-based |
| `CKK_XMSSMT` | `0x48` | XMSS^MT (RFC 8391, SP 800-208) — stateful, hash-based, C++ engine only |
| `CKK_ML_KEM` | `0x49` | ML-KEM (FIPS 203) |
| `CKK_ML_DSA` | `0x4a` | ML-DSA (FIPS 204) |
| `CKK_SLH_DSA` | `0x4b` | SLH-DSA (FIPS 205) |

> HSS/XMSS/XMSS-MT are **stateful** signatures: each private key holds a
> bounded number of one-time-signature leaves, and reusing a leaf breaks the
> scheme's security. PKCS#11 v3.2 §6.65.3/§6.66.4-5 require `CKA_COPYABLE`
> forced `FALSE` on these private keys for exactly this reason — both engines
> enforce it (see §3 below and `CHANGELOG.md`'s 0.28.2 entry for a real defect
> this caught in the Rust engine).

### 2.2 PQC parameter sets (`CKA_PARAMETER_SET` / `CKP_*`)

#### ML-KEM

| Constant | Value | Variant |
| --- | --- | --- |
| `CKP_ML_KEM_512` | `0x01` | ML-KEM-512 |
| `CKP_ML_KEM_768` | `0x02` | ML-KEM-768 |
| `CKP_ML_KEM_1024` | `0x03` | ML-KEM-1024 |

#### ML-DSA

| Constant | Value | Variant |
| --- | --- | --- |
| `CKP_ML_DSA_44` | `0x01` | ML-DSA-44 |
| `CKP_ML_DSA_65` | `0x02` | ML-DSA-65 |
| `CKP_ML_DSA_87` | `0x03` | ML-DSA-87 |

#### SLH-DSA

| Constant | Value | Variant |
| --- | --- | --- |
| `CKP_SLH_DSA_SHA2_128S` | `0x01` | SLH-DSA-SHA2-128s |
| `CKP_SLH_DSA_SHAKE_128S` | `0x02` | SLH-DSA-SHAKE-128s |
| `CKP_SLH_DSA_SHA2_128F` | `0x03` | SLH-DSA-SHA2-128f |
| `CKP_SLH_DSA_SHAKE_128F` | `0x04` | SLH-DSA-SHAKE-128f |
| `CKP_SLH_DSA_SHA2_192S` | `0x05` | SLH-DSA-SHA2-192s |
| `CKP_SLH_DSA_SHAKE_192S` | `0x06` | SLH-DSA-SHAKE-192s |
| `CKP_SLH_DSA_SHA2_192F` | `0x07` | SLH-DSA-SHA2-192f |
| `CKP_SLH_DSA_SHAKE_192F` | `0x08` | SLH-DSA-SHAKE-192f |
| `CKP_SLH_DSA_SHA2_256S` | `0x09` | SLH-DSA-SHA2-256s |
| `CKP_SLH_DSA_SHAKE_256S` | `0x0a` | SLH-DSA-SHAKE-256s |
| `CKP_SLH_DSA_SHA2_256F` | `0x0b` | SLH-DSA-SHA2-256f |
| `CKP_SLH_DSA_SHAKE_256F` | `0x0c` | SLH-DSA-SHAKE-256f |

### 2.3 Mechanisms (`CKM_*`)

| Mechanism | Value | Operation |
| --- | --- | --- |
| `CKM_EDDSA` | `0x00001057` | EdDSA sign / verify (pure) |
| `CKM_EDDSA_PH` | `0x80001057` | Ed25519ph pre-hash sign / verify |
| `CKM_ML_KEM_KEY_PAIR_GEN` | `0x0f` | Generate ML-KEM key pair |
| `CKM_ML_KEM` | `0x17` | `C_EncapsulateKey` / `C_DecapsulateKey` |
| `CKM_ML_DSA_KEY_PAIR_GEN` | `0x1c` | Generate ML-DSA key pair |
| `CKM_ML_DSA` | `0x1d` | Pure ML-DSA sign / verify |
| `CKM_HASH_ML_DSA` | `0x1f` | Pre-hash ML-DSA (algorithm from context param) |
| `CKM_HASH_ML_DSA_SHA{224,256,384,512}` | `0x23–0x26` | Pre-hash ML-DSA with fixed hash |
| `CKM_HASH_ML_DSA_SHA3_{224,256,384,512}` | `0x27–0x2a` | Pre-hash ML-DSA with SHA-3 |
| `CKM_HASH_ML_DSA_SHAKE{128,256}` | `0x2b–0x2c` | Pre-hash ML-DSA with SHAKE |
| `CKM_SLH_DSA_KEY_PAIR_GEN` | `0x2d` | Generate SLH-DSA key pair |
| `CKM_SLH_DSA` | `0x2e` | Pure SLH-DSA sign / verify |
| `CKM_HASH_SLH_DSA` | `0x34` | Pre-hash SLH-DSA (algorithm from context param) |
| `CKM_HASH_SLH_DSA_SHA{224,256,384,512}` | `0x36–0x39` | Pre-hash SLH-DSA with fixed hash |
| `CKM_HASH_SLH_DSA_SHA3_{224,256,384,512}` | `0x3a–0x3d` | Pre-hash SLH-DSA with SHA-3 |
| `CKM_HASH_SLH_DSA_SHAKE{128,256}` | `0x3e–0x3f` | Pre-hash SLH-DSA with SHAKE |
| `CKM_HKDF_DERIVE` | `0x0000402a` | HMAC-based KDF (RFC 5869) — extract + expand; `C_DeriveKey` |
| `CKM_SP800_108_COUNTER_KDF` | `0x000003ac` | NIST SP 800-108 counter mode KBKDF; `C_DeriveKey` |
| `CKM_SP800_108_FEEDBACK_KDF` | `0x000003ad` | NIST SP 800-108 feedback mode KBKDF (optional IV); `C_DeriveKey` |
| `CKM_ECDH1_COFACTOR_DERIVE` | `0x00001051` | Cofactor ECDH (NIST SP 800-56A §5.7.1.2); `C_DeriveKey` |
| `CKM_HSS_KEY_PAIR_GEN` | `0x4032` | Generate an HSS (multi-level LMS) key pair |
| `CKM_HSS` | `0x4033` | HSS sign / verify — key exhaustion returns `CKR_KEY_EXHAUSTED` |
| `CKM_XMSS_KEY_PAIR_GEN` | `0x4034` | Generate an XMSS key pair |
| `CKM_XMSSMT_KEY_PAIR_GEN` | `0x4035` | Generate an XMSS^MT key pair (C++ engine only) |
| `CKM_XMSS` | `0x4036` | XMSS sign / verify |
| `CKM_XMSSMT` | `0x4037` | XMSS^MT sign / verify (C++ engine only) |

#### HSS key template attributes (spec §6.65, verified against `src/lib/pkcs11/pkcs11t.h`)

| Constant | Value | Meaning |
| --- | --- | --- |
| `CKA_HSS_LEVELS` | `0x617` | Number of LMS levels in the hierarchy |
| `CKA_HSS_LMS_TYPE` | `0x618` | LMS type ID of the top-level tree |
| `CKA_HSS_LMOTS_TYPE` | `0x619` | LMOTS type ID of the top-level tree |
| `CKA_HSS_LMS_TYPES` | `0x61a` | Per-level LMS type IDs (multi-value, generated keys only) |
| `CKA_HSS_LMOTS_TYPES` | `0x61b` | Per-level LMOTS type IDs (multi-value, generated keys only) |
| `CKA_HSS_KEYS_REMAINING` | `0x61c` | Remaining one-time-signature slots (read-only) |

There is **no** `CKA_LMS_PARAM_SET` / `CKA_LMOTS_PARAM_SET` and no
`CKP_LMS_*` / `CKP_LMOTS_*` named constants in the v3.2 header — `CK_LMS_TYPE`
and `CK_LMOTS_TYPE` are plain `CK_ULONG`s carrying the raw IANA-registered
numeric type identifiers from RFC 8554 / RFC 9708, not a SoftHSMv3-defined
enum. Both engines were fixed (2026-09-03) to source these values from that
registry rather than SP 800-208's own (different) table — see
`CHANGELOG.md`'s stateful-hash entries around that date if a value looks
unfamiliar.

### 2.4 Classic algorithms (retained from SoftHSM2)

RSA (1024–4096 bit), ECDSA (P-256/P-384/P-521/Ed25519/Ed448), ECDH (X25519/X448),
AES-CBC/GCM/CTR (128/192/256 bit), HMAC-{SHA1,SHA256,SHA384,SHA512},
SHA-{1,224,256,384,512} digest.

**Key derivation additions**: `CKM_HKDF_DERIVE` (RFC 5869), `CKM_SP800_108_COUNTER_KDF`,
`CKM_SP800_108_FEEDBACK_KDF` (NIST SP 800-108 counter and feedback KBKDF), and
`CKM_ECDH1_COFACTOR_DERIVE` (cofactor ECDH per NIST SP 800-56A §5.7.1.2) are supported
via `C_DeriveKey`. All use OpenSSL EVP KDF / `EVP_PKEY_CTX` APIs — no legacy provider required.

**Removed from SoftHSM2**: GOST, 3DES/DES, DSA, DH, Camellia.

---

## 3. Known limitations

- **Stateful hash-based signatures (HSS/LMS, XMSS, XMSS-MT) are fully implemented** in the C++
  engine via embedded reference libraries (`stateful/hash-sigs/` for HSS/LMS,
  `stateful/xmss-reference/` for XMSS and XMSS-MT). The Rust WASM engine supports HSS/LMS
  (via `hbs-lms` and a custom verifier for SP 800-208 SHAKE IDs `0x0F-0x18`) and **both
  single-tree XMSS and multi-tree XMSS-MT** — all 56 RFC 8391 XMSS-MT parameter sets
  (SHA2/SHAKE × 256/512/192-bit × heights 20/40/60 with 2–12 layers) via the `xmss` crate
  (`rust/src/crypto/xmss_bridge.rs`); XMSS-MT is no longer a Rust-engine gap. As of 2026-09-03
  the Rust engine's **single-tree** XMSS also covers all 18 SP 800-208 parameter sets
  (SHA-256 and SHAKE-256 × N=24/32 × heights 10/16/20) — 9 of the 18 were previously missing
  or silently non-functional (a hardcoded 96-byte keygen seed instead of the per-parameter-set
  `SEED_LEN = 3×n`), fixed together with pinning the 6 new `CKP_*` ids the fix introduced.

  Key exhaustion: once all one-time signing slots are consumed, `C_Sign` returns
  `CKR_KEY_EXHAUSTED`. The remaining-use counter is tracked in `CKA_HSS_KEYS_REMAINING`
  (`0x61c`). On a native build this attribute is **persisted** across process boundaries to the configured object store (`file` or `db` backend), so the remaining‑use count survives a crash. In memory-only environments (e.g. WASM without IndexedDB backing), state is destroyed on exit — never drive production stateful signing from an ephemeral token.

- **Single-threaded WASM build.** The Emscripten target does not use a SharedArrayBuffer worker
  pool. Crypto-intensive operations (especially SLH-DSA-SHA2-256s key generation and signing)
  may block the main thread for several seconds on constrained hardware.

- **Non-persistent token (WASM memory model).** In the WASM build all token state (objects, PIN, label) lives strictly in RAM, so reloading the
  module loses all objects. Callers that need persistence in the browser must serialize objects with `C_GetAttributeValue(CKA_VALUE)` and re-import on next session, or wire an IndexedDB backing store. (Native builds persist automatically via the `file`/`db` object store.)

- **`C_CreateObject` for PQC keys is not yet implemented.** Importing raw key material via
  `C_CreateObject` works for AES and RSA; PQC (ML-KEM/ML-DSA/SLH-DSA/HSS/XMSS) private-key
  import is not. `C_CopyObject` itself is implemented in both engines for ordinary keys, but
  is **refused by design** for HSS/XMSS/XMSS-MT private keys specifically (PKCS#11 v3.2
  §6.65.3/§6.66.4-5 mandate `CKA_COPYABLE=FALSE` for these stateful one-time-signature key
  types — duplicating one would let two copies independently advance/replay the same leaf,
  a forgery hazard, not an accident to work around).

---

## 4. Building

### 4.1 Prerequisites

| Tool | Minimum | Notes |
| --- | --- | --- |
| CMake | 3.16 | |
| OpenSSL | 3.5.0 | CMake enforces this floor with `FATAL_ERROR`; 3.6.2+ is needed for `CKA_SEED` deterministic ML-DSA/ML-KEM/SLH-DSA keygen (OpenSSL's seed `OSSL_PARAM` support), and CI is pinned to 3.6.3 |
| C++ compiler | C++17 | g++ 11+ or clang++ 14+ |
| Emscripten (WASM) | 3.1.50+ | WASM target only |

**macOS:**
```bash
brew install openssl@3 cmake
export OPENSSL_ROOT_DIR=$(brew --prefix openssl@3)
```

**Linux (Debian/Ubuntu):**
```bash
# OpenSSL 3.5+ must be built from source if your distro ships an older version.
sudo apt-get install build-essential cmake
```

### 4.2 Native build

```bash
# From the softhsmv3 repository root.
# PQC (ML-KEM/ML-DSA/SLH-DSA) is always compiled in with the openssl backend —
# there are no -DENABLE_MLKEM / -DENABLE_MLDSA flags, and WITH_CRYPTO_BACKEND
# is hardcoded to "openssl" in CMakeLists.txt (no other backend is selectable).
# Add -DBUILD_TESTS=ON to build p11test, and -DWITH_OBJECTSTORE_BACKEND_DB=ON
# for the SQLite backend.
cmake -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTS=ON \
    -DOPENSSL_ROOT_DIR="$OPENSSL_ROOT_DIR"   # macOS only

cmake --build build -j$(nproc 2>/dev/null || sysctl -n hw.logicalcpu)
```

The shared library is produced at `build/src/lib/libsofthsmv3.so` (Linux) or
`build/src/lib/libsofthsmv3.dylib` (macOS).

### 4.3 Running the test suite

```bash
# Requires the -DBUILD_TESTS=ON from §4.2 (p11test is off by default)
cmake --build build --target p11test
./build/src/lib/test/p11test
```

See `docs/howtotestsofthsmv3.md` for the full testing workflow including the
`pqc_validate` validation suite.

### 4.4 WASM build

The easiest path is the packaged script, which also cross-compiles OpenSSL for
wasm32 (into `deps/openssl-wasm/`) before configuring softhsmv3 itself:

```bash
# Requires emcc 3.x+ in PATH (source your Emscripten SDK's emsdk_env.sh first)
bash scripts/build-wasm.sh
# SKIP_OPENSSL=1 bash scripts/build-wasm.sh   # if deps/openssl-wasm is already built
```

That produces `wasm/softhsm.js` + `wasm/softhsm.wasm`. To configure by hand
(what the script does under the hood), use the project's own toolchain file —
not the raw Emscripten SDK one — and point `OPENSSL_ROOT_DIR` at a wasm32
OpenSSL build (see `scripts/build-openssl-wasm.sh`):

```bash
source /path/to/emsdk/emsdk_env.sh

emcmake cmake -B build-wasm \
    -DCMAKE_TOOLCHAIN_FILE="cmake/toolchain/emscripten.cmake" \
    -DOPENSSL_ROOT_DIR="deps/openssl-wasm" \
    -DOPENSSL_INCLUDE_DIR="deps/openssl-wasm/include" \
    -DOPENSSL_CRYPTO_LIBRARY="deps/openssl-wasm/lib/libcrypto.a" \
    -DOPENSSL_SSL_LIBRARY="deps/openssl-wasm/lib/libssl.a" \
    -DBUILD_TESTS=OFF -DENABLE_STATIC=OFF

emmake cmake --build build-wasm --target softhsmv3 -j$(nproc 2>/dev/null || sysctl -n hw.logicalcpu)
```

---

## 5. Writing a C++ client

### 5.1 Loading the library

softhsmv3 is a standard PKCS#11 shared library. Load it with `dlopen` and resolve the
`C_GetFunctionList` entry point to obtain a `CK_FUNCTION_LIST_PTR`.

```cpp
/* Required platform macros before including cryptoki.h */
#define CK_PTR *
#define CK_DECLARE_FUNCTION(ret, name)         ret name
#define CK_DECLARE_FUNCTION_POINTER(ret, name) ret (* name)
#define CK_CALLBACK_FUNCTION(ret, name)        ret (* name)
#ifndef NULL_PTR
#  define NULL_PTR 0
#endif

#include "cryptoki.h"   /* PKCS#11 v3.2 headers — src/lib/pkcs11/ */
#include <dlfcn.h>
#include <cassert>
#include <cstdio>

int main() {
    /* Load the shared library */
    void* lib = dlopen("./libsofthsmv3.so", RTLD_LAZY);
    assert(lib && "dlopen failed");

    /* Resolve C_GetFunctionList */
    typedef CK_RV (*GetFunctionList_t)(CK_FUNCTION_LIST_PTR_PTR);
    auto gfl = reinterpret_cast<GetFunctionList_t>(dlsym(lib, "C_GetFunctionList"));
    assert(gfl && "C_GetFunctionList not found");

    CK_FUNCTION_LIST_PTR p11;
    CK_RV rv = gfl(&p11);
    assert(rv == CKR_OK);

    /* From here, use p11->C_Initialize, p11->C_OpenSession, etc. */

    p11->C_Finalize(NULL_PTR);
    dlclose(lib);
    return 0;
}
```

> **v3.2 functions** (`C_EncapsulateKey`, `C_DecapsulateKey`, `C_WrapKeyAuthenticated`,
> `C_UnwrapKeyAuthenticated`, `C_VerifySignatureInit`, `C_VerifySignature*`,
> `C_SignMessageBegin`, `C_SignMessageNext`, `C_VerifyMessageBegin`, `C_VerifyMessageNext`)
> are not in the v3.0 `CK_FUNCTION_LIST` struct. Resolve them individually with `dlsym`:
>
> ```cpp
> typedef CK_RV (*FnEncapsulate)(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
>     CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG,
>     CK_BYTE_PTR, CK_ULONG_PTR, CK_OBJECT_HANDLE_PTR);
> auto C_EncapsulateKey = reinterpret_cast<FnEncapsulate>(dlsym(lib, "C_EncapsulateKey"));
> ```

### 5.2 Initialize and open a token

```cpp
/* Initialize the library */
p11->C_Initialize(NULL_PTR);

/* Find an uninitialized slot */
CK_ULONG slotCount = 0;
p11->C_GetSlotList(CK_FALSE, NULL_PTR, &slotCount);
std::vector<CK_SLOT_ID> slots(slotCount);
p11->C_GetSlotList(CK_FALSE, slots.data(), &slotCount);

CK_SLOT_ID slot = slots[0];

/* Initialize token (space-padded 32-byte label, SO PIN) */
CK_UTF8CHAR label[32];
memset(label, ' ', sizeof(label));
memcpy(label, "MyToken", 7);
CK_UTF8CHAR soPin[] = "12345678";
p11->C_InitToken(slot, soPin, 8, label);

/* Re-enumerate: InitToken may change the slot ID */
p11->C_GetSlotList(CK_TRUE, NULL_PTR, &slotCount);
slots.resize(slotCount);
p11->C_GetSlotList(CK_TRUE, slots.data(), &slotCount);
slot = slots[0];

/* Open a read-write session */
CK_SESSION_HANDLE hSession;
p11->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
    NULL_PTR, NULL_PTR, &hSession);

/* Set User PIN (while logged in as SO) */
p11->C_Login(hSession, CKU_SO, soPin, 8);
CK_UTF8CHAR userPin[] = "userpin1";
p11->C_InitPIN(hSession, userPin, 8);
p11->C_Logout(hSession);

/* Log in as the normal user */
p11->C_Login(hSession, CKU_USER, userPin, 8);
```

### 5.3 ML-DSA sign / verify walkthrough

```cpp
/* ── 1. Generate an ML-DSA-65 key pair ─────────────────────────────────── */
CK_BBOOL ckTrue  = CK_TRUE;
CK_BBOOL ckFalse = CK_FALSE;
CK_ULONG paramSet = CKP_ML_DSA_65;   /* 0x02 */

CK_ATTRIBUTE pubTemplate[] = {
    { CKA_TOKEN,         &ckFalse,  sizeof(ckFalse) },
    { CKA_VERIFY,        &ckTrue,   sizeof(ckTrue)  },
    { CKA_PARAMETER_SET, &paramSet, sizeof(paramSet) },
};
CK_ATTRIBUTE privTemplate[] = {
    { CKA_TOKEN,         &ckFalse,  sizeof(ckFalse) },
    { CKA_SENSITIVE,     &ckTrue,   sizeof(ckTrue)  },
    { CKA_SIGN,          &ckTrue,   sizeof(ckTrue)  },
    { CKA_PARAMETER_SET, &paramSet, sizeof(paramSet) },
};

CK_OBJECT_HANDLE hPub, hPriv;
CK_MECHANISM genMech = { CKM_ML_DSA_KEY_PAIR_GEN, NULL_PTR, 0 };
rv = p11->C_GenerateKeyPair(hSession, &genMech,
    pubTemplate,  sizeof(pubTemplate)  / sizeof(pubTemplate[0]),
    privTemplate, sizeof(privTemplate) / sizeof(privTemplate[0]),
    &hPub, &hPriv);
assert(rv == CKR_OK);

/* ── 2. Sign a message ──────────────────────────────────────────────────── */
/* For pure ML-DSA (CKM_ML_DSA) the pParameter is a CK_ML_DSA_PARAMS struct.
 * A zero-filled struct selects the default (no context, no pre-hash, hedged). */
CK_ML_DSA_PARAMS signParams = {};   /* context="" len=0, hedging=CK_ML_DSA_HEDGE_PREFERRED */
CK_MECHANISM signMech = { CKM_ML_DSA, &signParams, sizeof(signParams) };

rv = p11->C_SignInit(hSession, &signMech, hPriv);
assert(rv == CKR_OK);

CK_BYTE message[] = "Hello PQC World";
CK_ULONG msgLen   = sizeof(message) - 1;

/* Size query */
CK_ULONG sigLen = 0;
rv = p11->C_Sign(hSession, message, msgLen, NULL_PTR, &sigLen);
assert(rv == CKR_OK);

std::vector<CK_BYTE> signature(sigLen);
rv = p11->C_Sign(hSession, message, msgLen, signature.data(), &sigLen);
assert(rv == CKR_OK);
signature.resize(sigLen);

/* ── 3. Verify the signature ────────────────────────────────────────────── */
CK_MECHANISM verifyMech = { CKM_ML_DSA, &signParams, sizeof(signParams) };
rv = p11->C_VerifyInit(hSession, &verifyMech, hPub);
assert(rv == CKR_OK);

rv = p11->C_Verify(hSession, message, msgLen, signature.data(), sigLen);
assert(rv == CKR_OK);   /* CKR_SIGNATURE_INVALID on mismatch */
```

### 5.4 ML-KEM encapsulate / decapsulate walkthrough

```cpp
/* ── 1. Generate an ML-KEM-768 key pair ─────────────────────────────────── */
CK_ULONG kemParam = CKP_ML_KEM_768;   /* 0x02 */

CK_ATTRIBUTE kemPubTpl[] = {
    { CKA_TOKEN,         &ckFalse,  sizeof(ckFalse)  },
    { CKA_ENCAPSULATE,   &ckTrue,   sizeof(ckTrue)   },
    { CKA_PARAMETER_SET, &kemParam, sizeof(kemParam) },
};
CK_ATTRIBUTE kemPrivTpl[] = {
    { CKA_TOKEN,         &ckFalse,  sizeof(ckFalse)  },
    { CKA_SENSITIVE,     &ckTrue,   sizeof(ckTrue)   },
    { CKA_DECAPSULATE,   &ckTrue,   sizeof(ckTrue)   },
    { CKA_PARAMETER_SET, &kemParam, sizeof(kemParam) },
};

CK_OBJECT_HANDLE hKEMPub, hKEMPriv;
CK_MECHANISM kemGenMech = { CKM_ML_KEM_KEY_PAIR_GEN, NULL_PTR, 0 };
rv = p11->C_GenerateKeyPair(hSession, &kemGenMech,
    kemPubTpl,  sizeof(kemPubTpl)  / sizeof(kemPubTpl[0]),
    kemPrivTpl, sizeof(kemPrivTpl) / sizeof(kemPrivTpl[0]),
    &hKEMPub, &hKEMPriv);
assert(rv == CKR_OK);

/* ── 2. Load v3.2 function pointers ─────────────────────────────────────── */
typedef CK_RV (*FnEncap)(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG,
    CK_BYTE_PTR, CK_ULONG_PTR, CK_OBJECT_HANDLE_PTR);
typedef CK_RV (*FnDecap)(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG,
    CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);

auto C_EncapsulateKey = reinterpret_cast<FnEncap>(dlsym(lib, "C_EncapsulateKey"));
auto C_DecapsulateKey = reinterpret_cast<FnDecap>(dlsym(lib, "C_DecapsulateKey"));

/* ── 3. Encapsulate (sender side) ────────────────────────────────────────── */
/* The derived shared secret will be a CKK_GENERIC_SECRET key object. */
CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
CK_KEY_TYPE secretKeyType   = CKK_GENERIC_SECRET;
CK_ULONG secretValueLen     = 32;   /* ML-KEM always produces 32-byte shared secrets */

CK_ATTRIBUTE sharedSecretTpl[] = {
    { CKA_CLASS,     &secretClass,   sizeof(secretClass)   },
    { CKA_KEY_TYPE,  &secretKeyType, sizeof(secretKeyType) },
    { CKA_VALUE_LEN, &secretValueLen, sizeof(secretValueLen) },
    { CKA_ENCRYPT,   &ckTrue,        sizeof(ckTrue)        },
};

CK_MECHANISM kemMech = { CKM_ML_KEM, NULL_PTR, 0 };

/* Size query for ciphertext */
CK_ULONG ctLen = 0;
CK_OBJECT_HANDLE hSenderSharedKey;
rv = C_EncapsulateKey(hSession, &kemMech, hKEMPub,
    sharedSecretTpl, sizeof(sharedSecretTpl) / sizeof(sharedSecretTpl[0]),
    NULL_PTR, &ctLen, &hSenderSharedKey);
assert(rv == CKR_OK);

std::vector<CK_BYTE> ciphertext(ctLen);
rv = C_EncapsulateKey(hSession, &kemMech, hKEMPub,
    sharedSecretTpl, sizeof(sharedSecretTpl) / sizeof(sharedSecretTpl[0]),
    ciphertext.data(), &ctLen, &hSenderSharedKey);
assert(rv == CKR_OK);

/* ── 4. Decapsulate (recipient side) ─────────────────────────────────────── */
CK_ATTRIBUTE recipientSecretTpl[] = {
    { CKA_CLASS,     &secretClass,    sizeof(secretClass)   },
    { CKA_KEY_TYPE,  &secretKeyType,  sizeof(secretKeyType) },
    { CKA_VALUE_LEN, &secretValueLen, sizeof(secretValueLen) },
    { CKA_DECRYPT,   &ckTrue,         sizeof(ckTrue)        },
};

CK_OBJECT_HANDLE hRecipientSharedKey;
rv = C_DecapsulateKey(hSession, &kemMech, hKEMPriv,
    recipientSecretTpl, sizeof(recipientSecretTpl) / sizeof(recipientSecretTpl[0]),
    ciphertext.data(), ctLen, &hRecipientSharedKey);
assert(rv == CKR_OK);

/* Both hSenderSharedKey and hRecipientSharedKey now hold the same 32-byte secret.
 * Retrieve and compare with C_GetAttributeValue(CKA_VALUE) to verify. */
```

### 5.5 Multi-message sign session

The PKCS#11 v3.2 message API allows a single sign session to sign many messages
without re-loading the key. There are two patterns: one-shot (`C_SignMessage`) and
two-step commit-then-sign (`C_SignMessageBegin` / `C_SignMessageNext`).

```cpp
typedef CK_RV (*FnMsgSignInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
typedef CK_RV (*FnSignMsg)(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG,
    CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
typedef CK_RV (*FnSignBegin)(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG);
typedef CK_RV (*FnSignNext)(CK_SESSION_HANDLE, CK_VOID_PTR, CK_ULONG,
    CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
typedef CK_RV (*FnMsgSignFinal)(CK_SESSION_HANDLE);

auto C_MessageSignInit  = reinterpret_cast<FnMsgSignInit >(dlsym(lib, "C_MessageSignInit"));
auto C_SignMessage       = reinterpret_cast<FnSignMsg     >(dlsym(lib, "C_SignMessage"));
auto C_SignMessageBegin  = reinterpret_cast<FnSignBegin   >(dlsym(lib, "C_SignMessageBegin"));
auto C_SignMessageNext   = reinterpret_cast<FnSignNext    >(dlsym(lib, "C_SignMessageNext"));
auto C_MessageSignFinal  = reinterpret_cast<FnMsgSignFinal>(dlsym(lib, "C_MessageSignFinal"));

/* Open a message-sign session on hPriv (ML-DSA-65) */
CK_ML_DSA_PARAMS msParams = {};
CK_MECHANISM msMech = { CKM_ML_DSA, &msParams, sizeof(msParams) };
rv = C_MessageSignInit(hSession, &msMech, hPriv);
assert(rv == CKR_OK);

/* ── Pattern A: one-shot per message (C_SignMessage) ─────────────────────── */
for (const auto& [msgBuf, msgLen] : messages) {
    /* size query */
    CK_ULONG sigLen = 0;
    rv = C_SignMessage(hSession, NULL_PTR, 0,
        (CK_BYTE_PTR)msgBuf, msgLen, NULL_PTR, &sigLen);
    assert(rv == CKR_OK);

    std::vector<CK_BYTE> sig(sigLen);
    rv = C_SignMessage(hSession, NULL_PTR, 0,
        (CK_BYTE_PTR)msgBuf, msgLen, sig.data(), &sigLen);
    assert(rv == CKR_OK);
    /* process sig … */
}

/* ── Pattern B: two-step (Begin then Next) ───────────────────────────────── */
for (const auto& [msgBuf, msgLen] : messages) {
    /* Commit per-message parameters (e.g. a context string override). */
    /* Passing NULL here keeps the init-time parameters unchanged.     */
    rv = C_SignMessageBegin(hSession, NULL_PTR, 0);
    assert(rv == CKR_OK);

    /* size query — session stays in MESSAGE_SIGN_BEGIN */
    CK_ULONG sigLen = 0;
    rv = C_SignMessageNext(hSession, NULL_PTR, 0,
        (CK_BYTE_PTR)msgBuf, msgLen, NULL_PTR, &sigLen);
    assert(rv == CKR_OK);

    std::vector<CK_BYTE> sig(sigLen);
    rv = C_SignMessageNext(hSession, NULL_PTR, 0,
        (CK_BYTE_PTR)msgBuf, msgLen, sig.data(), &sigLen);
    assert(rv == CKR_OK);
    /* process sig … */
    /* Session is now back in MESSAGE_SIGN — ready for the next Begin/Next. */
}

/* Close the message-sign session */
rv = C_MessageSignFinal(hSession);
assert(rv == CKR_OK);
```

### 5.6 Authenticated key wrap / unwrap (AES-GCM)

`C_WrapKeyAuthenticated` and `C_UnwrapKeyAuthenticated` provide AES-GCM key wrapping.
This is the recommended path for wrapping PQC private keys, which are too large for
RSA-OAEP key transport.

```cpp
typedef CK_RV (*FnWrapAuth)(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE, CK_OBJECT_HANDLE,
    CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
typedef CK_RV (*FnUnwrapAuth)(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG,
    CK_ATTRIBUTE_PTR, CK_ULONG,
    CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);

auto C_WrapKeyAuthenticated   = reinterpret_cast<FnWrapAuth  >(dlsym(lib, "C_WrapKeyAuthenticated"));
auto C_UnwrapKeyAuthenticated = reinterpret_cast<FnUnwrapAuth>(dlsym(lib, "C_UnwrapKeyAuthenticated"));

/* Generate a 256-bit AES wrapping key */
CK_ULONG aesLen = 32;
CK_ATTRIBUTE aesTpl[] = {
    { CKA_TOKEN,     &ckFalse, sizeof(ckFalse) },
    { CKA_VALUE_LEN, &aesLen,  sizeof(aesLen)  },
    { CKA_WRAP,      &ckTrue,  sizeof(ckTrue)  },
    { CKA_UNWRAP,    &ckTrue,  sizeof(ckTrue)  },
};
CK_MECHANISM aesGenMech = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
CK_OBJECT_HANDLE hWrapKey;
rv = p11->C_GenerateKey(hSession, &aesGenMech, aesTpl,
    sizeof(aesTpl) / sizeof(aesTpl[0]), &hWrapKey);
assert(rv == CKR_OK);

/* AES-GCM params: 12-byte IV, 128-bit tag, no AAD */
CK_BYTE iv[12];
p11->C_GenerateRandom(hSession, iv, sizeof(iv));
CK_GCM_PARAMS gcmParams = { iv, sizeof(iv), 128 /* tagBits */ };
CK_MECHANISM gcmMech = { CKM_AES_GCM, &gcmParams, sizeof(gcmParams) };

/* Wrap hPriv (ML-DSA private key) — no associated data */
CK_ULONG wrappedLen = 0;
rv = C_WrapKeyAuthenticated(hSession, &gcmMech, hWrapKey, hPriv,
    NULL_PTR, 0,           /* pAssociatedData, ulAssociatedDataLen */
    NULL_PTR, &wrappedLen);
assert(rv == CKR_OK);

std::vector<CK_BYTE> wrappedKey(wrappedLen);
rv = C_WrapKeyAuthenticated(hSession, &gcmMech, hWrapKey, hPriv,
    NULL_PTR, 0,
    wrappedKey.data(), &wrappedLen);
assert(rv == CKR_OK);

/* Unwrap into a new private key object */
CK_ULONG keyType  = CKK_ML_DSA;
CK_ULONG objClass = CKO_PRIVATE_KEY;
CK_ULONG ps65     = CKP_ML_DSA_65;
CK_ATTRIBUTE unwrapTpl[] = {
    { CKA_CLASS,         &objClass, sizeof(objClass) },
    { CKA_KEY_TYPE,      &keyType,  sizeof(keyType)  },
    { CKA_SENSITIVE,     &ckTrue,   sizeof(ckTrue)   },
    { CKA_SIGN,          &ckTrue,   sizeof(ckTrue)   },
    { CKA_PARAMETER_SET, &ps65,     sizeof(ps65)     },
};
CK_OBJECT_HANDLE hRestoredPriv;
rv = C_UnwrapKeyAuthenticated(hSession, &gcmMech, hWrapKey,
    wrappedKey.data(), wrappedLen,
    unwrapTpl, sizeof(unwrapTpl) / sizeof(unwrapTpl[0]),
    NULL_PTR, 0,    /* pAssociatedData, ulAssociatedDataLen */
    &hRestoredPriv);
assert(rv == CKR_OK);
```

### 5.7 Pre-bound signature verification

`C_VerifySignatureInit` binds a signature and key to the session before the message
data is available — the "signature-first" pattern used in streaming protocols.

```cpp
typedef CK_RV (*FnVSInit)(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
    CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG);
typedef CK_RV (*FnVS)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
typedef CK_RV (*FnVSUpdate)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
typedef CK_RV (*FnVSFinal)(CK_SESSION_HANDLE);

auto C_VerifySignatureInit   = reinterpret_cast<FnVSInit  >(dlsym(lib, "C_VerifySignatureInit"));
auto C_VerifySignature       = reinterpret_cast<FnVS      >(dlsym(lib, "C_VerifySignature"));
auto C_VerifySignatureUpdate = reinterpret_cast<FnVSUpdate>(dlsym(lib, "C_VerifySignatureUpdate"));
auto C_VerifySignatureFinal  = reinterpret_cast<FnVSFinal >(dlsym(lib, "C_VerifySignatureFinal"));

CK_MECHANISM vsMech = { CKM_ML_DSA, &signParams, sizeof(signParams) };

/* One-shot: bind signature, then provide message */
rv = C_VerifySignatureInit(hSession, &vsMech, hPub,
    signature.data(), sigLen);
assert(rv == CKR_OK);

rv = C_VerifySignature(hSession, message, msgLen);
assert(rv == CKR_OK);   /* CKR_SIGNATURE_INVALID on mismatch */

/* Multi-part: bind signature, stream message in chunks */
rv = C_VerifySignatureInit(hSession, &vsMech, hPub,
    signature.data(), sigLen);
assert(rv == CKR_OK);

for (const auto& chunk : messageChunks)
    C_VerifySignatureUpdate(hSession, chunk.data(), chunk.size());

rv = C_VerifySignatureFinal(hSession);
assert(rv == CKR_OK);
```

---

## 6. Error handling conventions

### 6.1 Return values used by softhsmv3

| `CK_RV` constant | When returned |
| --- | --- |
| `CKR_OK` (`0x00`) | Success |
| `CKR_CRYPTOKI_NOT_INITIALIZED` | Any call before `C_Initialize` |
| `CKR_SESSION_HANDLE_INVALID` | Unknown or closed session handle |
| `CKR_OPERATION_NOT_INITIALIZED` | Operation function called without `*Init` |
| `CKR_OPERATION_ACTIVE` | `*Init` called while another operation is active on the session |
| `CKR_KEY_FUNCTION_NOT_PERMITTED` | Key missing required usage attribute (e.g., `CKA_SIGN=FALSE`) |
| `CKR_KEY_TYPE_INCONSISTENT` | Key type does not match mechanism (e.g., RSA key with `CKM_ML_DSA`) |
| `CKR_MECHANISM_INVALID` | Mechanism not supported or not registered for this key type |
| `CKR_MECHANISM_PARAM_INVALID` | Mechanism parameter struct is malformed or contains invalid values |
| `CKR_BUFFER_TOO_SMALL` | Output buffer provided but too short; retry with the returned length |
| `CKR_ARGUMENTS_BAD` | Required pointer argument is `NULL_PTR` |
| `CKR_SIGNATURE_INVALID` | Signature verification failed (tampered data or wrong key) |
| `CKR_SIGNATURE_LEN_RANGE` | Signature buffer is the wrong size for the mechanism |
| `CKR_TEMPLATE_INCOMPLETE` | Required attribute missing from key generation template |
| `CKR_TEMPLATE_INCONSISTENT` | Attribute combination is not permitted |
| `CKR_USER_NOT_LOGGED_IN` | Token-resident key operations require `C_Login` |
| `CKR_ENCRYPTED_DATA_INVALID` | AES-GCM authentication tag failed (wrong key or tampered ciphertext) |
| `CKR_GENERAL_ERROR` | Unexpected internal error (OpenSSL EVP layer failure) |

### 6.2 Size-query pattern

Any function that writes variable-length output (`pOutput`, `pSignature`, `pWrappedKey`,
`pCiphertext`) follows the standard PKCS#11 two-call pattern:

```cpp
/* Call 1: pass NULL output pointer → get required length */
CK_ULONG outLen = 0;
rv = p11->C_Sign(hSession, data, dataLen, NULL_PTR, &outLen);
assert(rv == CKR_OK);

/* Call 2: allocate and pass buffer of returned length */
std::vector<CK_BYTE> out(outLen);
rv = p11->C_Sign(hSession, data, dataLen, out.data(), &outLen);
assert(rv == CKR_OK);
out.resize(outLen);  /* actual bytes written (may be ≤ allocated) */
```

If the buffer you allocate is too small, `CKR_BUFFER_TOO_SMALL` is returned and
`*pulLen` is updated to the required size. The session operation remains active so
you can retry with a correctly-sized buffer.

### 6.3 Session operation state after errors

| Scenario | Session op-type after error |
| --- | --- |
| `*Init` fails | Unchanged (still `SESSION_OP_NONE`) |
| `C_Sign` / `C_Verify` fails (other than `CKR_BUFFER_TOO_SMALL`) | `SESSION_OP_NONE` — must reinitialize |
| `C_Sign` / `C_Verify` returns `CKR_BUFFER_TOO_SMALL` | Unchanged — operation still active, may retry |
| `C_SignMessageNext` returns `CKR_BUFFER_TOO_SMALL` | `SESSION_OP_MESSAGE_SIGN_BEGIN` — may retry with correct size |
| `C_SignMessageNext` returns any other error | `SESSION_OP_NONE` — multi-message session terminated |
| `C_VerifySignatureFinal` returns `CKR_SIGNATURE_INVALID` | `SESSION_OP_NONE` — no re-use possible |

### 6.4 Cleanup on error

Always destroy sensitive key objects when they are no longer needed:

```cpp
if (hPriv != CK_INVALID_HANDLE)
    p11->C_DestroyObject(hSession, hPriv);
```

And always close the session and finalize the library on exit, even after errors:

```cpp
p11->C_Logout(hSession);
p11->C_CloseSession(hSession);
p11->C_Finalize(NULL_PTR);
dlclose(lib);
```

---

## 7. SLH-DSA Parameter Sets

softhsmv3 exposes all 12 NIST-standardised SLH-DSA parameter sets via OpenSSL's `EVP_PKEY` interface. The parameter set is selected by `CKA_SLH_DSA_PARAMETER_SET` on the key template:

| Parameter set string | Security level | Small-fast | Signature size (approx.) |
|----------------------|---------------|-----------|--------------------------|
| `"SLH-DSA-SHA2-128s"` | 128-bit      | Small      | 7,856 bytes              |
| `"SLH-DSA-SHA2-128f"` | 128-bit      | Fast       | 17,088 bytes             |
| `"SLH-DSA-SHA2-192s"` | 192-bit      | Small      | 16,224 bytes             |
| `"SLH-DSA-SHA2-192f"` | 192-bit      | Fast       | 35,664 bytes             |
| `"SLH-DSA-SHA2-256s"` | 256-bit      | Small      | 29,792 bytes             |
| `"SLH-DSA-SHA2-256f"` | 256-bit      | Fast       | 49,856 bytes             |
| `"SLH-DSA-SHAKE-128s"`| 128-bit      | Small      | 7,856 bytes              |
| `"SLH-DSA-SHAKE-128f"`| 128-bit      | Fast       | 17,088 bytes             |
| `"SLH-DSA-SHAKE-192s"`| 192-bit      | Small      | 16,224 bytes             |
| `"SLH-DSA-SHAKE-192f"`| 192-bit      | Fast       | 35,664 bytes             |
| `"SLH-DSA-SHAKE-256s"`| 256-bit      | Small      | 29,792 bytes             |
| `"SLH-DSA-SHAKE-256f"`| 256-bit      | Fast       | 49,856 bytes             |

SLH-DSA signing is always probabilistic (randomised). The `hedgeVariant` field in `CK_SIGN_ADDITIONAL_CONTEXT` is accepted but has no effect on SLH-DSA operations.

---

## 8. Pre-Hash Encoding Reference

When a `CKM_HASH_ML_DSA_*` or `CKM_HASH_SLH_DSA_*` mechanism is used, softhsmv3 constructs the pre-hash message encoding internally before passing it to OpenSSL's EVP signer. The encoding follows FIPS 204 §5.4 (ML-DSA) and FIPS 205 §10.1 (SLH-DSA):

```
M' = domain_separator || len(ctx) || ctx || AlgId_DER || H(M)
```

Where:
- `domain_separator` = `0x01` (one byte)
- `len(ctx)` = context length in bytes (one byte, 0–255)
- `ctx` = context bytes (up to 255 bytes)
- `AlgId_DER` = DER-encoded `AlgorithmIdentifier` for the hash algorithm
- `H(M)` = hash of the original message under the specified hash algorithm

This encoding is transparent to callers — pass the raw message to `C_Sign` or `C_SignMessage` and softhsmv3 handles the pre-hash construction.

---

## 9. StrongSwan IKEv2 Adapter (`strongswan-pkcs11/`)

The `strongswan-pkcs11/` directory provides a strongSwan-compatible PKCS#11 plugin adapter. It exposes softhsmv3 ML-KEM key exchange (all three sizes) and ML-DSA (44/65/87), SLH-DSA-SHA2 (128s/192s/256s), Ed448, and Ed25519 authentication to the IKEv2 key-exchange and AUTH-payload layers without modifying strongSwan core — see `strongswan-pkcs11/README.md` for the full algorithm-to-file map; ML-DSA is walked through below as the representative example.

### 9.1 ML-KEM key exchange

The adapter implements `pkcs11_kem_t` using the PKCS#11 v3.2 KEM API:

```c
#include "strongswan-pkcs11/pkcs11_kem.h"

// Find a token that supports CKM_ML_KEM, generate keypair
pkcs11_kem_t *kem = pkcs11_kem_create(pkcs11_lib, ML_KEM_768);

// Initiator: export public key → send to peer
chunk_t pubkey = kem->get_public_key(kem);

// Responder: receives pubkey, encapsulates shared secret via C_EncapsulateKey
kem->set_public_key(kem, peer_pubkey);
chunk_t shared_secret = kem->get_shared_secret(kem);

// Initiator: receives ciphertext, decapsulates via C_DecapsulateKey
kem->set_public_key(kem, ciphertext_from_responder);
chunk_t shared_secret = kem->get_shared_secret(kem);
```

Both paths call into softhsmv3's `C_EncapsulateKey` / `C_DecapsulateKey` (PKCS#11 v3.2 §5.17).

### 9.2 ML-DSA signing constants

`strongswan-pkcs11/pkcs11.h` adds the PKCS#11 v3.2 ML-DSA constants needed for the IKEv2 AUTH payload. (SLH-DSA-SHA2 and Ed448/Ed25519 authentication go through the same plugin via the existing `CKM_SLH_DSA` / `CKM_EDDSA` mechanisms — this walkthrough uses ML-DSA as the representative example, not because it's the only one supported.)

```c
#define CKK_ML_DSA              (0x0000004aUL)  // key type
#define CKM_ML_DSA_KEY_PAIR_GEN (0x0000001cUL)  // key generation
#define CKM_ML_DSA              (0x0000001dUL)  // sign / verify
```

Pass `CKM_ML_DSA_KEY_PAIR_GEN` in the mechanism during `C_GenerateKeyPair`, set `CKA_PARAMETER_SET` to `CKP_ML_DSA_44`, `CKP_ML_DSA_65`, or `CKP_ML_DSA_87`, then sign IKEv2 AUTH payloads with `CKM_ML_DSA` via the standard `C_SignInit` / `C_Sign` path.

---

## 10. Java JCE Integration (`JavaJCE/`)

> **This section describes the current provider.** An earlier `JavaJCE/` module
> (package `org.softhsmv3.jce`, class `SoftHSMJCEProvider`/`MLDSASignatureSpi`,
> a patched-SunPKCS11-JNI design) never actually worked — an August 2026 audit
> found its ML-DSA signer returned a hardcoded 2-byte array and its ML-KEM
> `KeyAgreement` SPI never ran an encapsulation. It was removed and replaced
> outright (see `CHANGELOG.md`, "Removed"/"Added" for that release). Nothing
> below describes that removed module.

The `JavaJCE/` module (package `com.pqctoday.hsm.jce`, `pom.xml`-built with
Maven) lets JCA/JCE-based applications (Hyperledger Besu, Spring Security, any
JCA consumer) call softhsmv3 through the standard Java `Signature`,
`KeyPairGenerator`, `KEM`, `Cipher`, `KeyAgreement`, `KeyStore`, and related
APIs. It is FFM-based (`java.lang.foreign`, JEP 454) — no JNI, no
`sun.security.pkcs11.wrapper` internals, and no patched JRE/JNI to build.
Every operation routes to the token; the provider never computes a signature,
hash, key, or derived secret on the JVM side. See `JavaJCE/README.md` for the
full algorithm coverage table and known limitations.

### 10.1 Architecture

```
Application code
    │ Signature.getInstance("ML-DSA-65", provider)
    ▼
SoftHSMv3Provider (JavaJCE/src/main/java/com/pqctoday/hsm/jce/…)
    │ looks up registered Service
    ▼
P11PureSigSignatureSpi (ML-DSA/SLH-DSA/EdDSA/ECDSA/RSA all share this SPI)
    │ translates to CKM_ML_DSA (0x0000001d) via java.lang.foreign (FFM)
    ▼
libsofthsmv3.so — C_SignInit / C_Sign
```

### 10.2 Registration

```java
import java.security.Security;
import com.pqctoday.hsm.jce.SoftHSMv3Provider;

// Env-var driven (PKCS11_MODULE / PKCS11_PIN):
Security.addProvider(new SoftHSMv3Provider());

// Or explicit:
SoftHSMv3Provider p =
    new SoftHSMv3Provider("/usr/local/lib/softhsm/libsofthsmv3.so", "1234");
```

### 10.3 ML-DSA signing / ML-KEM key exchange

ML-DSA/SLH-DSA/EC/RSA all go through the standard `KeyPairGenerator` +
`Signature` pair — there is no dedicated `MLDSASignatureSpi`:

```java
KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-65", p);
KeyPair kp = kpg.generateKeyPair();

Signature sig = Signature.getInstance("ML-DSA-65", p);
sig.initSign(kp.getPrivate());
sig.update("hello".getBytes());
byte[] signature = sig.sign();

Signature ver = Signature.getInstance("ML-DSA-65", p);
ver.initVerify(kp.getPublic());
ver.update("hello".getBytes());
boolean valid = ver.verify(signature);
```

ML-KEM is exposed through JDK 24+'s `javax.crypto.KEM` API (JEP 452), **not**
`KeyAgreement` — `KeyAgreement` in this provider is registered for classical
ECDH only:

```java
KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-768", p);
KeyPair kp = kpg.generateKeyPair();

KEM kem = KEM.getInstance("ML-KEM-768", p);
KEM.Encapsulator enc = kem.newEncapsulator(kp.getPublic());
KEM.Encapsulated encapsulated = enc.encapsulate();
byte[] ciphertext = encapsulated.encapsulation();

KEM.Decapsulator dec = kem.newDecapsulator(kp.getPrivate());
SecretKey sharedSecret = dec.decapsulate(ciphertext);
```

ML-KEM is also registered under the bare family name `"ML-KEM"` — the exact
string JDK 27's own JEP 527 hybrid-TLS path requests.

### 10.4 Build and test

```bash
JAVA_HOME=/path/to/jdk-27 mvn test
```

No Docker step and no patched-JRE compile are required — this is an ordinary
Maven build. Every test runs live against the real engine (`PKCS11_MODULE`/
`PKCS11_PIN` env vars, defaulting to `/usr/local/lib/softhsm/libsofthsmv3.so`
/ `1234`); nothing is mocked. Add the built JAR to your application's
classpath; no further configuration is required once `SoftHSMv3Provider` is
registered.

---

*Repository: [https://github.com/pqctoday/softhsmv3](https://github.com/pqctoday/softhsmv3)*
