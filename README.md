# SoftHSMv3 / `@pqctoday/softhsm-wasm`

A modernized fork of [SoftHSM2](https://github.com/softhsm/SoftHSMv2) with **OpenSSL 3.x**, **PKCS#11 v3.2**, and **post-quantum cryptography** support — compiled to WebAssembly for use in browsers and Node.js.

SoftHSMv3 ships two WASM engines with identical PKCS#11 APIs: a **C++/Emscripten** engine (OpenSSL 3.6 backend) and a **pure-Rust** engine (RustCrypto backend, ~1.4 MB). Both produce the same `_C_*` function exports and are drop-in interchangeable.

## Installation

```bash
npm install @pqctoday/softhsm-wasm
```

## Quick Start

```js
// CJS
const createSoftHSMModule = require('@pqctoday/softhsm-wasm')
const { CK } = require('@pqctoday/softhsm-wasm')

// ESM dynamic import
const { default: createSoftHSMModule, CK } = await import('@pqctoday/softhsm-wasm')

// Named import
const { createSoftHSMModule, CK } = require('@pqctoday/softhsm-wasm')

// ── ML-KEM-768 key encapsulation example ──────────────────────────────────
const M = await createSoftHSMModule()

// Allocate helper
const writeStr = (s) => {
  const len = M.lengthBytesUTF8(s) + 1
  const ptr = M._malloc(len)
  M.stringToUTF8(s, ptr, len)
  return ptr
}

// Initialize + open token
M._C_Initialize(0)
const slotPtr = M._malloc(4)
const slotCountPtr = M._malloc(4)
M._C_GetSlotList(0, slotPtr, slotCountPtr)
const slot = M.getValue(slotPtr, 'i32')

const labelPtr = M._malloc(32)
M.HEAPU8.fill(0x20, labelPtr, labelPtr + 32)   // blank-pad label
M.stringToUTF8('MyToken', labelPtr, 8)
const soPinPtr = writeStr('12345678')
M._C_InitToken(slot, soPinPtr, 8, labelPtr)
M._free(soPinPtr); M._free(labelPtr); M._free(slotPtr); M._free(slotCountPtr)

// Open session, generate ML-KEM-768 key pair, encapsulate, decapsulate
// See tests/smoke-wasm.mjs for the complete lifecycle example.
```

**TypeScript** types are included — import from `'@pqctoday/softhsm-wasm'` for full
`SoftHSMModule` intellisense. Constants are available separately:

```ts
import CK from '@pqctoday/softhsm-wasm/constants'
// CK.CKM_ML_KEM, CK.CKP_ML_KEM_768, CK.CKR_OK, CK.CK_ATTRIBUTE_SIZE, …
```

---

## Documentation & components

The npm package above is the PKCS#11 WASM engine. This repository also contains a
networked KMIP server, a crypto-agility policy engine, and several protocol
wrappers — each with its own README.

**Guides (start here):**

| Audience | Guide |
| --- | --- |
| Developer — build + write a client | [`docs/softhsmv3devguide.md`](docs/softhsmv3devguide.md) |
| Ops / integrator — deploy + integrate | [`docs/softhsmv3opsguide.md`](docs/softhsmv3opsguide.md) |
| Anyone — build and **test** the token | [`docs/howtotestsofthsmv3.md`](docs/howtotestsofthsmv3.md) |

**Components:**

| Component | Path | What |
| --- | --- | --- |
| PKCS#11 engines (C++ + Rust) | `src/`, [`rust/`](rust/README.md) | The token; two interchangeable engines. Rust also has a 257/0 [PKCS#11 v3.2 conformance report](rust/RUST_P11_V32_CONFORMANCE_REPORT.md) |
| KMIP 3.0 server + CACP policy engine | [`kmip/`](kmip/README.md) | Networked key management + crypto-agility policies; ML-KEM/ML-DSA/SLH-DSA + **hybrid KEMs** (X25519MLKEM768 / SecP256r1MLKEM768 / SecP384r1MLKEM1024, **OpenSSL-3.5-interop-verified**); X25519/X448 key agreement as standard KMIP ECDH + Recommended Curve |
| Wrappers | see the [Integration Interfaces](#integration-interfaces) table | OpenSSL provider, OpenSSH, OpenPGP, MLS, strongSwan, JavaJCE, WebRPC |

---

## What's New vs SoftHSM2

| Feature | SoftHSM2 (v2.7.0) | SoftHSMv3 |
| --- | --- | --- |
| OpenSSL backend | 1.x (deprecated APIs) | 3.6 (EVP-only) |
| PKCS#11 version | 3.0 | **3.2** (CSD01, April 2025) |
| ML-KEM (FIPS 203) | Not supported | **ML-KEM-512/768/1024** |
| ML-DSA (FIPS 204) | PR only (#809) | **ML-DSA-44/65/87** |
| SLH-DSA (FIPS 205) | Not supported | **SLH-DSA-SHA2/SHAKE variants** |
| C_EncapsulateKey | Not supported | **Implemented** |
| C_DecapsulateKey | Not supported | **Implemented** |
| C_SignMessage / C_VerifyMessage | Not supported | **Implemented** (v3.0 one-shot + streaming) |
| Message Encrypt/Decrypt API | Not supported | **Implemented** (AES-GCM per-message AEAD, both engines) |
| C_VerifySignatureInit / C_VerifySignature | Not supported | **Implemented** (v3.2 pre-bound verify, both engines) |
| C_VerifySignatureUpdate / C_VerifySignatureFinal | Not supported | **Implemented** (v3.2 streaming pre-bound verify — Rust engine) |
| C_SignRecover / C_VerifyRecover | Stub (CKR_FUNCTION_NOT_SUPPORTED) | **Implemented** (RSA PKCS#1 + raw X.509 recovery) |
| C_WrapKeyAuthenticated / C_UnwrapKeyAuthenticated | Not supported | **Implemented** (v3.2 AES-GCM key wrap) |
| CKA_UNIQUE_ID | Not supported | **Auto-generated UUID v4** (PKCS#11 v3.0 §4.4, read-only) |
| CKA_PROFILE_ID | Not supported | **Implemented** (PKCS#11 v3.0 §4.5, default 0) |
| Key derivation (HKDF, KBKDF, cofactor ECDH) | Not supported | **`CKM_HKDF_DERIVE`, `CKM_SP800_108_COUNTER_KDF`, `CKM_SP800_108_FEEDBACK_KDF`, `CKM_ECDH1_COFACTOR_DERIVE`** |
| PBKDF2 (`CKM_PKCS5_PBKD2`) | Not supported | **Implemented** — HMAC-SHA{1/224/256/384/512} PRF; BIP39 / SLIP-0010 seed derivation |
| ECDH1 with KDF (`CKD_SHA*_KDF`) | Not supported | **Implemented** — X9.63 SHA{1/256/384/512} KDF on `CKM_ECDH1_DERIVE`; 5G SUCI deconcealment (TS 33.501 §6.12.2) |
| LMS/HSS (SP 800-208) | Not supported | **SHA-256 + SHAKE-256** (N32/N24); all 80 NIST parameter combinations; C++↔Rust cross-engine verified |
| XMSS / XMSS^MT (RFC 8391) | Not supported | **Both engines** (XMSS-MT: C++ only); all SHA2/SHAKE-256 param sets |
| SHA-3 signature variants | Not supported | **C++:** `CKM_ECDSA_SHA3_224/256/384/512`, `CKM_RSA_SHA3_224/256/384/512_PKCS/_PKCS_PSS` — **Rust:** `CKM_ECDSA_SHA3_224/256/384/512` + `CKM_ECDSA_SHA512` (native for P-521; FIPS 186-5 §6.4 truncation for P-256/P-384) |
| GOST/DES/DSA/DH | Included | Removed (focused codebase) |
| WASM build | Not supported | **Emscripten + Rust `wasm32-unknown-unknown`** |
| Rust WASM engine | N/A | **Pure Rust (~1.4 MB), drop-in parity** |
| npm package | N/A | **@pqctoday/softhsm-wasm** |
| StrongSwan IKEv2 ML-DSA | Not supported | **`strongswan-pkcs11/` adapter** — `CKK_ML_DSA` (0x4a), `CKM_ML_DSA_KEY_PAIR_GEN` (0x1c), `CKM_ML_DSA` (0x1d) |
| Java JCE / Besu integration | Not supported | **`JavaJCE/` layer** — routes JCA `ML-DSA-65` and `ML-KEM-768` requests to softhsmv3 via patched SunPKCS11 |
| OpenSSH ML-DSA-65 signing | Not supported | **`openssh-pkcs11/` connector** — `ssh-mldsa-65` key type (draft-sfluhrer-ssh-mldsa-06) with signing via `CKM_ML_DSA` (0x1d); WASM client + privsep-free server |

## PQC Algorithms

### ML-KEM (Key Encapsulation Mechanism) — FIPS 203

| Variant | Public Key | Private Key | Ciphertext | Shared Secret | NIST Level |
| --- | --- | --- | --- | --- | --- |
| ML-KEM-512 | 800 B | 1,632 B | 768 B | 32 B | 1 |
| ML-KEM-768 | 1,184 B | 2,400 B | 1,088 B | 32 B | 3 |
| ML-KEM-1024 | 1,568 B | 3,168 B | 1,568 B | 32 B | 5 |

### ML-DSA (Digital Signature Algorithm) — FIPS 204

| Variant | Public Key | Private Key | Signature | NIST Level |
| --- | --- | --- | --- | --- |
| ML-DSA-44 | 1,312 B | 2,560 B | 2,420 B | 2 |
| ML-DSA-65 | 1,952 B | 4,032 B | 3,293 B | 3 |
| ML-DSA-87 | 2,592 B | 4,896 B | 4,627 B | 5 |

### SLH-DSA (Stateless Hash-Based Signature) — FIPS 205

| Variant | Public Key | Private Key | Signature | NIST Level |
| --- | --- | --- | --- | --- |
| SLH-DSA-SHA2-128s | 32 B | 64 B | 7,856 B | 1 (small) |
| SLH-DSA-SHA2-128f | 32 B | 64 B | 17,088 B | 1 (fast) |
| SLH-DSA-SHA2-192s | 48 B | 96 B | 16,224 B | 3 (small) |
| SLH-DSA-SHA2-192f | 48 B | 96 B | 35,664 B | 3 (fast) |
| SLH-DSA-SHA2-256s | 64 B | 128 B | 29,792 B | 5 (small) |
| SLH-DSA-SHA2-256f | 64 B | 128 B | 49,856 B | 5 (fast) |
| SLH-DSA-SHAKE-128s/f | 32 B | 64 B | 7,856/17,088 B | 1 |
| SLH-DSA-SHAKE-192s/f | 48 B | 96 B | 16,224/35,664 B | 3 |
| SLH-DSA-SHAKE-256s/f | 64 B | 128 B | 29,792/49,856 B | 5 |

### LMS / HSS (Leighton-Micali Signatures) — SP 800-208 / RFC 8554

Stateful hash-based signatures. Available in both C++ and Rust engines with all 80 NIST parameter combinations (SHA-256 and SHAKE-256, N32 and N24 output sizes, tree heights H5/10/15/20/25, Winternitz W1/2/4/8). Validated against all 320 NIST ACVP LMS sigVer demo vectors.

| LMS Hash Family | Tree Heights | Output Size | LMOTS Variants |
| --- | --- | --- | --- |
| SHA-256 N32 | H5, H10, H15, H20, H25 | 32 B | W1, W2, W4, W8 |
| SHA-256 N24 | H5, H10, H15, H20, H25 | 24 B | W1, W2, W4, W8 |
| SHAKE-256 N32 | H5, H10, H15, H20, H25 | 32 B | W1, W2, W4, W8 |
| SHAKE-256 N24 | H5, H10, H15, H20, H25 | 24 B | W1, W2, W4, W8 |

HSS multi-level trees (up to 8 levels) use `CKM_HSS_KEY_PAIR_GEN` / `CKM_HSS`. Key exhaustion returns `CKR_KEY_EXHAUSTED`. Remaining-use counter exposed via `CKA_HSS_KEYS_REMAINING`.

### XMSS / XMSS^MT (eXtended Merkle Signature Scheme) — RFC 8391 / SP 800-208

Stateful hash-based signatures. Available in both C++ and Rust engines with all parameter sets (SHA2-256, SHAKE-256). XMSS-MT available in C++ engine only.

| Variant | Public Key | Private Key | Signature | NIST Level |
| --- | --- | --- | --- | --- |
| XMSS_SHA2_10_256 | 68 B | 136 B | 2,500 B | 5 |
| XMSSMT_SHA2_20/2_256 | 68 B | 136 B | 4,963 B | 5 |

## PKCS#11 v3.2 Mechanisms

### Key Encapsulation

```c
CKM_ML_KEM_KEY_PAIR_GEN  // Key pair generation
CKM_ML_KEM               // Encapsulate / Decapsulate
C_EncapsulateKey()        // KEM encapsulation (v3.2)
C_DecapsulateKey()        // KEM decapsulation (v3.2)
```

### Digital Signatures — ML-DSA

```c
CKM_ML_DSA_KEY_PAIR_GEN  // Key pair generation
CKM_ML_DSA               // Pure ML-DSA sign/verify (one-shot and message-session)
CKM_HASH_ML_DSA          // HashML-DSA — hash function chosen by mechanism param
CKM_HASH_ML_DSA_SHA224   // HashML-DSA pre-hash variants (10 specific)
CKM_HASH_ML_DSA_SHA256
CKM_HASH_ML_DSA_SHA384
CKM_HASH_ML_DSA_SHA512
CKM_HASH_ML_DSA_SHA3_224
CKM_HASH_ML_DSA_SHA3_256
CKM_HASH_ML_DSA_SHA3_384
CKM_HASH_ML_DSA_SHA3_512
CKM_HASH_ML_DSA_SHAKE128
CKM_HASH_ML_DSA_SHAKE256
```

### Digital Signatures — SLH-DSA

```c
CKM_SLH_DSA_KEY_PAIR_GEN // Key pair generation
CKM_SLH_DSA              // Pure SLH-DSA sign/verify
CKM_HASH_SLH_DSA         // HashSLH-DSA — hash function chosen by mechanism param
CKM_HASH_SLH_DSA_SHA224  // HashSLH-DSA pre-hash variants (10 specific)
CKM_HASH_SLH_DSA_SHA256
CKM_HASH_SLH_DSA_SHA384
CKM_HASH_SLH_DSA_SHA512
CKM_HASH_SLH_DSA_SHA3_224
CKM_HASH_SLH_DSA_SHA3_256
CKM_HASH_SLH_DSA_SHA3_384
CKM_HASH_SLH_DSA_SHA3_512
CKM_HASH_SLH_DSA_SHAKE128
CKM_HASH_SLH_DSA_SHAKE256
```

### Digital Signatures — XMSS & XMSS^MT (Stateful HBS)

```c
CKM_XMSS_KEY_PAIR_GEN    // Key pair generation
CKM_XMSS                 // Pure XMSS sign / verify
CKM_XMSSMT_KEY_PAIR_GEN  // Key pair generation MT
CKM_XMSSMT               // Pure XMSSMT sign / verify
```

### Stateful HBS — LMS / HSS (SP 800-208)

```c
CKM_HSS_KEY_PAIR_GEN     // HSS key pair generation
CKM_HSS                  // HSS sign / verify (multi-level LMS)

// Key template attributes
CKA_LMS_PARAM_SET        // LMS parameter set (e.g. CKP_LMS_SHA256_N32_H10)
CKA_LMOTS_PARAM_SET      // LMOTS one-time-signature parameter (e.g. CKP_LMOTS_SHA256_N32_W4)
CKA_HSS_KEYS_REMAINING   // Remaining one-time signature slots (read-only)
```

### Message Signing API (v3.0)

```c
// One-shot per-message signing within a message session
C_MessageSignInit()       // Open a message-signing session
C_SignMessage()           // Sign one message (one-shot)
C_SignMessageBegin()      // Begin a two-step message sign
C_SignMessageNext()       // Complete the sign (or size-query)
C_MessageSignFinal()      // Close the session

// Symmetric (verify side)
C_MessageVerifyInit()
C_VerifyMessage()
C_VerifyMessageBegin()
C_VerifyMessageNext()
C_MessageVerifyFinal()
```

### Per-Message AEAD (v3.0)

```c
// AES-GCM encrypt/decrypt with per-message IV generation
C_MessageEncryptInit()    // Open an encrypt-message session
C_EncryptMessage()        // Encrypt one message (one-shot)
C_EncryptMessageBegin()   // Begin streaming encrypt
C_EncryptMessageNext()    // Stream plaintext chunk / finalize
C_MessageEncryptFinal()   // Close the session

C_MessageDecryptInit()
C_DecryptMessage()
C_DecryptMessageBegin()
C_DecryptMessageNext()
C_MessageDecryptFinal()
```

### ChaCha20-Poly1305 AEAD (RFC 7539 / v3.2)

```c
// ChaCha20-Poly1305 symmetric encryption with AAD validation
CKM_CHACHA20_KEY_GEN     // Secret key generation
CKM_CHACHA20_POLY1305    // Authenticated encryption and decryption
```

### Sign/Verify Recover (RSA)

```c
// RSA signature recovery — recovers plaintext from signature (CKM_RSA_PKCS, CKM_RSA_X_509)
C_SignRecoverInit()       // Initialize sign-recover with RSA private key
C_SignRecover()           // Produce recoverable signature (single-part)
C_VerifyRecoverInit()     // Initialize verify-recover with RSA public key
C_VerifyRecover()         // Recover data from signature (single-part)
```

### Pre-Bound Signature Verification (v3.2)

```c
// Verify a signature against data received afterwards (signature-first pattern)
C_VerifySignatureInit()   // Bind signature and algorithm to session
C_VerifySignature()       // Verify against data (one-shot)
C_VerifySignatureUpdate() // Stream message data (multi-part)
C_VerifySignatureFinal()  // Complete multi-part pre-bound verify
```

### Authenticated Key Wrap/Unwrap (v3.2)

```c
// AES-GCM authenticated key wrapping (replaces C_WrapKey for PQC key sizes)
C_WrapKeyAuthenticated()
C_UnwrapKeyAuthenticated()
```

### Classical Signatures — ECDSA

```c
// ECDSA raw (pre-hashed) — PKCS#11 v3.2 §6.3.12 — caller supplies digest, token does not hash
// Supported by both C++ and Rust engines; required for Bitcoin/secp256k1 workflows
CKM_ECDSA                  = 0x00001041  // P-256, P-384, P-521, secp256k1 (K-256)

// ECDSA with SHA-2/SHA-3 pre-hash (C++ and Rust engines)
CKM_ECDSA_SHA256           = 0x00001044
CKM_ECDSA_SHA384           = 0x00001045
CKM_ECDSA_SHA512           = 0x00001046  // Rust: native SHA-512 for P-521; FIPS 186-5 §6.4 truncation for P-256/P-384
CKM_ECDSA_SHA3_224         = 0x00001047
CKM_ECDSA_SHA3_256         = 0x00001048
CKM_ECDSA_SHA3_384         = 0x00001049
CKM_ECDSA_SHA3_512         = 0x0000104a

// EdDSA — pure and pre-hash (RFC 8032; PKCS#11 v3.2 §6.3.15)
CKM_EDDSA                  = 0x00001057  // Ed25519 pure signing
CKM_EDDSA_PH               = 0x80001057  // Ed25519ph pre-hash mode (vendor-defined)

// RSA PKCS#1 v1.5 with SHA-3 (C++ engine)
CKM_RSA_SHA3_224_PKCS      = 0x0000004f
CKM_RSA_SHA3_256_PKCS      = 0x00000050
CKM_RSA_SHA3_384_PKCS      = 0x00000051
CKM_RSA_SHA3_512_PKCS      = 0x00000052

// RSA-PSS with SHA-3 (C++ engine)
CKM_RSA_SHA3_224_PKCS_PSS  = 0x00000053
CKM_RSA_SHA3_256_PKCS_PSS  = 0x00000054
CKM_RSA_SHA3_384_PKCS_PSS  = 0x00000055
CKM_RSA_SHA3_512_PKCS_PSS  = 0x00000056
```

### Key Derivation

```c
// PBKDF2 (RFC 2898) — password-based key derivation (PKCS#11 v3.2 §5.7.3.1)
// PRFs: CKP_PKCS5_PBKD2_HMAC_{SHA1, SHA224, SHA256, SHA384, SHA512}
// Typical use: BIP39 mnemonic → 64-byte seed, SLIP-0010 child keys
// pPassword in CK_PKCS5_PBKD2_PARAMS2; hBaseKey must be 0
CKM_PKCS5_PBKD2            = 0x000003b0

// ECDH1 with X9.63 KDF variants — SharedInfo passed as OSSL_KDF_PARAM_INFO
// Used for 5G SUCI deconcealment (Profile A: X25519, Profile B: P-256)
CKM_ECDH1_DERIVE           = 0x00001050  // + CKD_SHA{1,256,384,512}_KDF

// HKDF (RFC 5869) — extract + expand (PKCS#11 v3.2 §2.41)
CKM_HKDF_DERIVE            = 0x0000402a

// NIST SP 800-108 Counter mode KBKDF — K(i) = PRF(K, i ∥ Label ∥ Context)
CKM_SP800_108_COUNTER_KDF  = 0x000003ac

// NIST SP 800-108 Feedback mode KBKDF — K(i) = PRF(K, K(i−1) ∥ Label ∥ Context)
CKM_SP800_108_FEEDBACK_KDF = 0x000003ad

// Cofactor ECDH — multiplies shared secret by curve cofactor before KDF
// Eliminates small-subgroup attacks per NIST SP 800-56A §5.7.1.2
CKM_ECDH1_COFACTOR_DERIVE  = 0x00001051
```

### Digest & MAC

```c
// RIPEMD (registered; returns CKR_MECHANISM_INVALID — OpenSSL legacy provider disabled)
CKM_RIPEMD160              = 0x00000240  // RIPEMD-160 digest (strict audit only)
CKM_RIPEMD160_HMAC         = 0x00000241  // HMAC-RIPEMD-160

// SHA-2 (C++ and Rust engines)
CKM_SHA256                 = 0x00000250  // SHA-256 digest
CKM_SHA384                 = 0x00000260  // SHA-384 digest
CKM_SHA512                 = 0x00000270  // SHA-512 digest

// SHA-3 (FIPS 202)
CKM_SHA3_256               = 0x000002b0  // SHA3-256 digest
CKM_SHA3_256_HMAC          = 0x000002b1  // HMAC-SHA3-256

// KMAC (FIPS 202 / SP 800-185) — keyed MAC using KECCAK-based XOF
CKM_KMAC_128               = 0x80000100  // KMAC-128 (vendor-defined range)
CKM_KMAC_256               = 0x80000101  // KMAC-256 (vendor-defined range)
```

## Validation & Compliance Status

The `softhsmv3` implementations maintain strict compliance with current ACVP test vectors and the PKCS#11 v3.2 specification:

- **ACVP Testing (v0.4.21+)**: Both the C++ and Rust engines pass all ACVP algorithm test vectors with **zero failures and zero skips** across all implemented mechanisms in dual HSM mode. The test suite covers: ML-KEM (Decapsulate KAT + Round-Trip, all 3 variants), ML-DSA (SigVer KAT + Functional, all 3 variants), HashML-DSA (SHA-256/SHA-512, 3 variants), SLH-DSA (Functional 2 param sets + SigGen KAT), HashSLH-DSA (SHA2-128f-SHA256, SHA2-256f-SHA512), LMS/HSS SHA-256 + SHAKE-256 (sign+verify round-trips; NIST ACVP LMS sigVer KAT, 20 SHAKE groups per engine — newly passing on both engines as of v0.4.21), AES-GCM/CBC/CTR/KW/KWP, HMAC-SHA256/384/512, RSA-PSS, ECDSA P-256/P-384, EdDSA Ed25519, **Ed25519ph / `CKM_EDDSA_PH` (C++ + Rust, both engines as of v0.4.21)**, SHA-256 (3 vectors), SHA3-256 (empty-string vector), PBKDF2, and HKDF. C++↔Rust cross-engine HSS signing verification available in dual mode.
- **NIST ACVP LMS sigVer**: **320/320** official NIST ACVP demo vectors validated against `lm_validate_signature()` — all 80 SP 800-208 parameter combinations (SHA-256 M32/M24 + SHAKE-256 M32/M24 × 5 tree heights × 4 Winternitz params). Source: [usnistgov/ACVP-Server](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/LMS-sigVer-1.0).
- **PKCS#11 v3.2 Semantics (C++)**: The standalone C++ compliance validator (`p11_v32_compliance_test`) passes **193 / 0 / 1** (193 pass, 0 fail, 1 documented skip — the legacy RIPEMD-160 case), covering PQC round-trips, classical algorithms (ECDSA, EdDSA, ECDH, RSA), KDFs (PBKDF2, HKDF, SP800-108), negative boundary paths (policy violation, extraction constraint, template completeness, signature forgery), and v3.2 session/message APIs against the compiled `libsofthsmv3.dylib`. Full report: [`cpp_compliance_report.md`](cpp_compliance_report.md).
- **PKCS#11 v3.2 Conformance (Rust)**: The Rust engine carries its own checked-in evidence — **257/257** checks across 40 sections (exact `CKR_*` codes in spec priority order, PQC keygen/param-set, SP800-108 KBKDF, message-based crypto, `CKA_ALLOWED_MECHANISMS` and `CKO_CERTIFICATE`). See [`rust/RUST_P11_V32_CONFORMANCE_REPORT.md`](rust/RUST_P11_V32_CONFORMANCE_REPORT.md); regenerate with `scripts/local-gate.sh --rust-p11`.
- **KMIP 3.0 Conformance**: The KMIP server is validated by the Rust integration suite (`kmip/ cargo test` — TLS e2e, hybrid KEM, OASIS codec, interop KATs) and the OASIS replay harness (`kmip/conformance/harness/dispatcher_replay.py`). See [`kmip/docs/CONFORMANCE_REPORT.md`](kmip/docs/CONFORMANCE_REPORT.md) and the deprecated-algorithm skip rationale in [`kmip/DEPRECATED.md`](kmip/DEPRECATED.md).
- **Playground E2E**: End-to-end token integration and ACVP matrix execution are verified via automated Playwright continuous integration (`playground-softhsm-acvp.spec.ts`) in dual HSM mode.
- **Security Audit (March 2026)**: Full remediation of all HIGH and MEDIUM findings. See [`docs/security_audit_03222026.md`](docs/security_audit_03222026.md).

## Security

A formal security audit was conducted in March 2026 covering C++ memory safety, PKCS#11 API validation, cryptographic implementation, WASM/JS bindings, Rust PKCS#11, and build/supply chain. A subsequent hardening sweep occurred in April 2026 focusing on bounds control.

**As of the v0.4.24 hardening sweep (April 2026): all HIGH and MEDIUM findings resolved, remaining LOW findings patched.** Security-relevant work since then is recorded in `CHANGELOG.md` (through v0.10.0), plus subsequent gap-remediation audit rounds tracked via GitHub release tags (`v0.13.0` and later).

| Severity | Original | Fixed in v0.4.24 | Remaining |
| --- | --- | --- | --- |
| Critical | 3 | 3 | 0 |
| High | 10 | 10 | 0 |
| Medium | 14 | 14 | 0 |
| Low | 5 | 2 | 3 (accepted / architectural) |
| Info | 5 | 0 | 5 (documentation / inherent) |

Key fixes: RSA X.509 underflow guard, AES-CBC IV enforcement, ML-KEM secret zeroization, HMAC/KMAC constant-time comparison (`subtle::ConstantTimeEq`), symlink/path-traversal rejection, Handle randomization, SLH-DSA pure-mode parameter validation, Rust NULL output pointer guards, CWE-400 WASM engine panics, and CWE-120 bounds checks.

Full reports: [`docs/security_audit_03222026.md`](docs/security_audit_03222026.md) and [`docs/security_audit_04132026.md`](docs/security_audit_04132026.md)

## Rust WASM Engine (`rust/`)

The Rust engine is a pure-Rust reimplementation of the SoftHSMv3 PKCS#11 surface, compiled to `wasm32-unknown-unknown` via `wasm-bindgen`. It replaces the entire OpenSSL backend with native RustCrypto crates, producing a standalone ~1.4 MB `.wasm` binary with zero C dependencies.

### Why Two Engines?

| | C++/Emscripten | Rust |
| --- | --- | --- |
| Crypto backend | OpenSSL 3.6 (EVP) | RustCrypto (`ml-kem`, `ml-dsa`, `slh-dsa`, `rsa`, `p256`, `p384`, `aes`, `sha2`, `sha3`) |
| Build toolchain | Emscripten SDK + CMake + cross-compiled OpenSSL | `cargo build --target wasm32-unknown-unknown` |
| WASM size | ~2.3 MB (OpenSSL linked) | **~1.4 MB** |
| C FFI | Native | None (pure Rust) |
| Pre-hash ML-DSA/SLH-DSA | Full (10 variants each) | Full (10 variants each) |

### API Parity — The "Disguise" Technique

Existing JavaScript consumers written against the C++ Emscripten build work without changing a single line of code. The Rust module uses `wasm-bindgen` with `js_name` to export functions with the same `_C_*` prefix that Emscripten generates:

```rust
#[wasm_bindgen(js_name = _C_GenerateKeyPair)]
pub fn C_GenerateKeyPair(
    _hSession: u32,
    _pMechanism: *mut u8,
    // ...
) -> u32 { /* native Rust implementation */ }
```

Memory management (`_malloc`, `_free`), `HEAPU8`, `setValue`, and `getValue` are all provided by a thin JS shim that mirrors the Emscripten API surface.

### Supported PKCS#11 Functions

The Rust engine exports 85 PKCS#11 functions (63 fully implemented, 8 multi-part stubs, 11 stubs, plus `set_kat_seed`):

| Category | Functions |
| --- | --- |
| Info / Slot | `C_GetInfo`, `C_GetSlotList`, `C_GetSlotInfo`, `C_GetTokenInfo`, `C_GetMechanismList`, `C_GetMechanismInfo` |
| Session | `C_Initialize`, `C_Finalize`, `C_InitToken`, `C_OpenSession`, `C_CloseSession`, `C_Login`, `C_Logout`, `C_InitPIN`, `C_GetSessionInfo` |
| Key Generation | `C_GenerateKeyPair`, `C_GenerateKey` |
| KEM | `C_EncapsulateKey`, `C_DecapsulateKey` |
| Sign/Verify | `C_SignInit`, `C_Sign`, `C_VerifyInit`, `C_Verify` |
| Pre-Bound Verify (v3.2) | `C_VerifySignatureInit`, `C_VerifySignature`, `C_VerifySignatureUpdate`, `C_VerifySignatureFinal` |
| Message Sign/Verify | `C_MessageSignInit`, `C_SignMessage`, `C_MessageSignFinal`, `C_MessageVerifyInit`, `C_VerifyMessage`, `C_MessageVerifyFinal` |
| Message Encrypt/Decrypt | `C_MessageEncryptInit`, `C_EncryptMessage`, `C_EncryptMessageBegin`, `C_EncryptMessageNext`, `C_MessageEncryptFinal`, `C_MessageDecryptInit`, `C_DecryptMessage`, `C_DecryptMessageBegin`, `C_DecryptMessageNext`, `C_MessageDecryptFinal` |
| Encrypt/Decrypt | `C_EncryptInit`, `C_Encrypt`, `C_DecryptInit`, `C_Decrypt` |
| Digest | `C_DigestInit`, `C_DigestUpdate`, `C_DigestFinal`, `C_Digest` |
| Object | `C_CreateObject`, `C_DestroyObject`, `C_GetAttributeValue`, `C_FindObjectsInit`, `C_FindObjects`, `C_FindObjectsFinal` |
| Key Management | `C_DeriveKey`, `C_WrapKey`, `C_UnwrapKey`, `C_WrapKeyAuthenticated`, `C_UnwrapKeyAuthenticated` |
| Utility | `C_GenerateRandom` |
| Multi-part (stubs) | `C_SignUpdate`, `C_SignFinal`, `C_VerifyUpdate`, `C_VerifyFinal`, `C_EncryptUpdate`, `C_EncryptFinal`, `C_DecryptUpdate`, `C_DecryptFinal` |
| Admin (stubs) | `C_SetPIN`, `C_CopyObject`, `C_GetObjectSize`, `C_SetAttributeValue`, `C_DigestKey`, `C_GetOperationState`, `C_SetOperationState`, `C_SeedRandom` |
| v3.2 Async (stubs) | `C_GetSessionValidationFlags`, `C_AsyncComplete`, `C_AsyncGetID` |

Multi-part, admin, and async stubs return `CKR_FUNCTION_NOT_SUPPORTED`. The browser playground uses single-shot operations only.

### Supported Algorithms

**Post-Quantum:**

- ML-KEM-512/768/1024 (keygen, encapsulate, decapsulate)
- ML-DSA-44/65/87 (keygen, sign, verify)
- SLH-DSA — all 12 parameter sets: SHA2/SHAKE x 128/192/256 x s/f (keygen, sign, verify)

**Classical:**

- RSA (PKCS#1 v1.5, OAEP, PSS — keygen + sign/verify)
- ECDSA P-256/P-384/P-521 + secp256k1 (keygen, sign, verify) — including ECDSA-SHA512 (native for P-521; FIPS 186-5 §6.4 truncation for P-256/P-384) and ECDSA-SHA3-224/256/384/512
- Ed25519 (keygen, sign, verify) — pure (`CKM_EDDSA`) and pre-hash (`CKM_EDDSA_PH`, Ed25519ph)
- ECDH P-256/P-384/P-521 + X25519/X448 (key agreement via `C_DeriveKey`)
- AES-128/256 (GCM, CBC-PAD, CTR, Key Wrap, Key Wrap with Padding, Authenticated Wrap/Unwrap)
- SHA-256/384/512, SHA3-256/512 (digest); SHA3-256 (`CKM_SHA3_256`) validated against FIPS 202 empty-string KAT
- HMAC-SHA256/384/512, HMAC-SHA3-256/512, HMAC-SHA3-256 (`CKM_SHA3_256_HMAC`)
- KMAC-128/256 (`CKM_KMAC_128`, `CKM_KMAC_256`) — FIPS 202 / SP 800-185
- HKDF (RFC 5869), PBKDF2 (`CKM_PKCS5_PBKD2`), SP 800-108 Counter/Feedback KDF

> **Note:** RSA-SHA3 variants (`CKM_RSA_SHA3_*_PKCS`, `CKM_RSA_SHA3_*_PKCS_PSS`) and ECDH1 with X9.63 KDF are C++ engine only.

**70 mechanisms** registered in `C_GetMechanismList` — 100% have implementations. (Added: `CKM_HASH_ML_DSA`, `CKM_HASH_SLH_DSA`, `CKM_EDDSA_PH`, `CKM_SHA3_256`, `CKM_SHA3_256_HMAC`, `CKM_KMAC_128`, `CKM_KMAC_256`.)

### PKCS#11 v3.2 Compliance Enforcement

The Rust engine enforces PKCS#11 v3.2 capability attributes on all operations:

| Check | Return Code | Enforcement Point |
| --- | --- | --- |
| `CKA_SIGN` on private key | `CKR_KEY_FUNCTION_NOT_PERMITTED` | `C_SignInit` |
| `CKA_VERIFY` on public key | `CKR_KEY_FUNCTION_NOT_PERMITTED` | `C_VerifyInit` |
| `CKA_ENCRYPT` on key | `CKR_KEY_FUNCTION_NOT_PERMITTED` | `C_EncryptInit` |
| `CKA_DECRYPT` on key | `CKR_KEY_FUNCTION_NOT_PERMITTED` | `C_DecryptInit` |
| `CKA_WRAP` on wrapping key | `CKR_KEY_FUNCTION_NOT_PERMITTED` | `C_WrapKey` |
| `CKA_UNWRAP` on unwrapping key | `CKR_KEY_FUNCTION_NOT_PERMITTED` | `C_UnwrapKey` |
| `CKA_DERIVE` on base key | `CKR_KEY_FUNCTION_NOT_PERMITTED` | `C_DeriveKey` |
| `CKA_EXTRACTABLE` on wrapped key | `CKR_KEY_UNEXTRACTABLE` | `C_WrapKey` |
| `CKA_SENSITIVE` / `!CKA_EXTRACTABLE` | `CK_UNAVAILABLE_INFORMATION` | `C_GetAttributeValue` (blocks `CKA_VALUE`) |

Generated private keys default to `CKA_SENSITIVE=true`. `C_DestroyObject` cleans up stale operation state to prevent use-after-free on destroyed keys.

### Rust Crate Dependencies

From `rust/Cargo.toml`:

| Crate | Purpose |
| --- | --- |
| `ml-kem` 0.2.3 | FIPS 203 key encapsulation |
| `ml-dsa` =0.1.0-rc.7 | FIPS 204 digital signatures |
| `slh-dsa` =0.2.0-rc.4 | FIPS 205 hash-based signatures |
| `rsa` 0.9 | RSA PKCS#1 / OAEP / PSS |
| `p256`, `p384`, `p521` 0.13 | NIST curve ECDSA + ECDH (P-256, P-384, P-521) |
| `ed25519-dalek` 2.1 | Ed25519 signatures |
| `x25519-dalek` 2.0 | X25519 key agreement |
| `aes` + `aes-gcm` + `cbc` + `aes-kw` | AES modes |
| `sha2`, `sha3`, `hmac` | Digest and MAC |
| `wasm-bindgen` 0.2.117 | WASM ↔ JS bridge |
| `getrandom` 0.2 (js feature) | Browser-compatible CSPRNG |

### Building the Rust Engine

```bash
# Prerequisites: Rust toolchain + wasm-pack
rustup target add wasm32-unknown-unknown
cargo install wasm-pack

# Build
cd rust
wasm-pack build --target web --release

# Output: rust/pkg/
#   softhsmrustv3_bg.wasm  (~1.4 MB)
#   softhsmrustv3.js       (JS bindings)
#   softhsmrustv3.d.ts     (TypeScript types)
```

> **Note:** `wasm-opt` is disabled in `Cargo.toml` because the PQC crates use bulk-memory WebAssembly instructions (`memory.copy`, `memory.fill`) that `wasm-opt` does not yet support. V8 (Chrome/Node.js) handles these natively.

### Testing

```bash
# Unit test (native, not WASM)
cd rust
cargo test

# Integration test — Rust engine standalone
node rust/test_harness.js

# Parity test — C++ vs Rust cross-engine verification
# Generates keys in one engine, operates in the other, verifies match
node tests/parity-wasm.mjs
```

The parity test (`tests/parity-wasm.mjs`) performs cross-engine verification:

1. **ML-KEM:** Rust generates keypair -> C++ encapsulates -> Rust decapsulates -> shared secrets must match
2. **ML-DSA:** C++ generates keypair + signs message -> Rust imports public key + verifies signature

### Architecture

```text
rust/
  Cargo.toml           # Dependencies, wasm-pack config, release profile
  src/
    lib.rs             # All PKCS#11 functions (~3,900 lines)
  pkg/                 # wasm-pack output (generated)
    softhsmrustv3_bg.wasm
    softhsmrustv3.js
    softhsmrustv3.d.ts
  test_harness.js      # Standalone integration test
tests/
  parity-wasm.mjs      # Cross-engine C++ ↔ Rust parity verification
softhsmrustv3design.md  # Detailed architecture design document
```

Internal state uses thread-local `RefCell<HashMap<u32, HashMap<u32, Vec<u8>>>>` for the object store (handle → attribute map), with monotonically incrementing `AtomicU32` handles returned to JS callers. Session handles are also unique via an atomic counter. All cryptographic operations execute entirely within WASM linear memory, isolated from the JavaScript heap.

## Token Storage & Persistence

SoftHSMv3 introduces a **Tri-Mode Storage Architecture** to support ephemeral, file-based, and relational database workloads cleanly without branching the API:

1. **Memory Model (WASM Default / Native Optional):** Total in-memory `ObjectStore`. Token state does not survive a module reload or process exit. Extremely fast execution with zero filesystem dependencies. Required for Browser and Sandbox embedding.
2. **File-Based Model (Native Default):** A filesystem-backed ObjectStore mapping directly to `/var/lib/softhsm/tokens` (configured via `softhsm2.conf` using `objectstore.backend = file`). This is the default Native backend granting full persistence of Keys and Pins across process restarts.
3. **SQLite3 Database Model:** A relational persistent store (configured via `objectstore.backend = db`). This stores all token material safely inside an `sqlite3.db` instance, providing robust transactional isolation during highly concurrent native IT implementations (OpenSSL, OpenVPN, NGINX).

*Note: The native File and SQLite models compile out of the WASM pipeline to keep the JavaScript distribution lightweight.*

## Known Limitations

- **Stateful hash-based signatures**: HSS/LMS (keygen, sign, verify) and XMSS/XMSS^MT (keygen, sign, verify) are implemented in both C++ and Rust engines. All SP 800-208 parameter sets supported (SHA-256 N32/N24, SHAKE-256 N32/N24). Validated against 320 NIST ACVP LMS sigVer demo vectors. State persistence is in-memory per session — the host application must manage durable state for production use if using the memory model.
- **Single-threaded**: The WASM target is single-threaded (no SharedArrayBuffer worker pool).

## Roadmap (PKCS#11 engine, Phases 0–19)

The phase checklist below tracked the PKCS#11 engine build through **v0.4.24**
(April 2026). The later program — v0.5.0–v0.8.0: the KMIP 3.0 server, CACP
crypto-agility policy engine, hybrid KEMs, and the Rust native API — is recorded
in **`CHANGELOG.md`**, not here.

- [x] Phase 0: Import SoftHSM2 + PKCS#11 v3.2 headers + strip legacy ([#1](https://github.com/pqctoday-org/pqctoday-hsm/issues/1))
- [x] Phase 1: OpenSSL 3.x API migration ([#2](https://github.com/pqctoday-org/pqctoday-hsm/issues/2))
- [x] Phase 2: ML-DSA support ([#3](https://github.com/pqctoday-org/pqctoday-hsm/issues/3))
- [x] Phase 3: ML-KEM + C_EncapsulateKey/C_DecapsulateKey ([#4](https://github.com/pqctoday-org/pqctoday-hsm/issues/4))
- [x] Phase 4: Emscripten WASM build ([#5](https://github.com/pqctoday-org/pqctoday-hsm/issues/5))
- [x] Phase 5: npm package `@pqctoday/softhsm-wasm` ([#6](https://github.com/pqctoday-org/pqctoday-hsm/issues/6))
- [x] Phase 6: PQC Timeline App integration ([#7](https://github.com/pqctoday-org/pqctoday-hsm/issues/7))
- [x] Phase 7: PKCS#11 v3.2 compliance gaps
  - [x] `C_GetInterfaceList` / `C_GetInterface` ([#8](https://github.com/pqctoday-org/pqctoday-hsm/issues/8))
  - [x] `CKK_ML_DSA` + `CKM_ML_DSA*` mechanisms ([#12](https://github.com/pqctoday-org/pqctoday-hsm/issues/12))
  - [x] `CKA_PARAMETER_SET` — PQC variant selection ([#11](https://github.com/pqctoday-org/pqctoday-hsm/issues/11))
  - [x] `C_SignMessage` / `C_VerifyMessage` one-shot message signing ([#10](https://github.com/pqctoday-org/pqctoday-hsm/issues/10))
  - [x] `CKK_SLH_DSA` + `CKM_SLH_DSA*` mechanisms ([#13](https://github.com/pqctoday-org/pqctoday-hsm/issues/13))
  - [x] `CKK_ML_KEM` + `CKM_ML_KEM*` mechanisms ([#14](https://github.com/pqctoday-org/pqctoday-hsm/issues/14))
  - [x] `CKA_ENCAPSULATE` / `CKA_DECAPSULATE` attributes ([#15](https://github.com/pqctoday-org/pqctoday-hsm/issues/15))
  - [x] `CKM_HASH_SLH_DSA*` — 11 pre-hash SLH-DSA variants ([#16](https://github.com/pqctoday-org/pqctoday-hsm/issues/16))
  - [x] `C_SignMessageBegin` / `C_SignMessageNext` / `C_VerifyMessageBegin` / `C_VerifyMessageNext` ([#17](https://github.com/pqctoday-org/pqctoday-hsm/issues/17))
  - [x] Message Encrypt/Decrypt API — AES-GCM per-message AEAD (10 functions) ([#18](https://github.com/pqctoday-org/pqctoday-hsm/issues/18))
  - [x] `C_VerifySignatureInit` / `C_VerifySignature` — pre-bound verification ([#19](https://github.com/pqctoday-org/pqctoday-hsm/issues/19))
  - [x] `C_WrapKeyAuthenticated` / `C_UnwrapKeyAuthenticated` ([#20](https://github.com/pqctoday-org/pqctoday-hsm/issues/20))
  - [x] `C_LoginUser` / `C_SessionCancel` — v3.0 session management ([#21](https://github.com/pqctoday-org/pqctoday-hsm/issues/21))
  - [x] `C_VerifySignatureFinal` / `C_VerifySignatureUpdate` multi-part pre-bound verify ([#22](https://github.com/pqctoday-org/pqctoday-hsm/issues/22))
  - [x] `CKM_HKDF_DERIVE` — HMAC-based KDF (RFC 5869) via OpenSSL EVP HKDF
  - [x] `CKM_SP800_108_COUNTER_KDF` / `CKM_SP800_108_FEEDBACK_KDF` — NIST SP 800-108 counter and feedback KBKDF
  - [x] `CKM_ECDH1_COFACTOR_DERIVE` — cofactor ECDH via `EVP_PKEY_CTX_set_ecdh_cofactor_mode`
- [x] Phase 8: Pure-Rust WASM engine (`rust/`) — drop-in parity with C++ Emscripten build
- [x] Phase 9: PKCS#11 v3.2 compliance audit — C++ and Rust engines
  - [x] C++: `CKA_ENCAPSULATE`/`CKA_DECAPSULATE` defaults fixed (Table 18); explicit set in `C_GenerateKeyPair`
  - [x] Rust: `SUPPORTED_MECHS` expanded 31→62; `CKA_SIGN/VERIFY/ENCRYPT/DECRYPT` enforcement in `*Init`
  - [x] Rust: `AtomicU32` unique session handles; `CKA_SENSITIVE=true` for private keys
  - [x] Rust: `C_DestroyObject` state cleanup; `C_DeriveKey` `CKA_DERIVE` check
  - [x] Rust: output keys from KEM/derive carry proper attributes (`CKA_EXTRACTABLE`, `CKA_CLASS`, etc.)
  - [x] Rust: 10 admin function stubs + 8 multi-part stubs (63 total exports)
  - [x] Rust: `CKA_EC_PARAMS` + `CKA_EC_POINT` stored on generated X25519/X448 keys (PKCS#11 v3.2 §6.7 — OID DER + `04 <len> <raw pubkey>`)
  - [x] Rust: stale SP 800-108 early-dispatch path removed from `C_DeriveKey` — `CKM_SP800_108_COUNTER_KDF` / `CKM_SP800_108_FEEDBACK_KDF` now always reach the correct handler
- [x] Phase 19: April 2026 Hardening (v0.4.24)
  - [x] Rust: Resolved CWE-400 WASM `.unwrap()` panics during FFI boundaries (`ffi.rs`, `state.rs`) by integrating safe Error mapping closures.
  - [x] C++: Refactored CWE-120 out-of-bounds `strncpy` arrays into deterministic `memcpy` blocks within `softhsm2-util.cpp`.
  - [x] C++: Hardened `C_SessionCancel` (PKCS#11 v3.2 §5.6.7) with exact bitmask flag mappings across Thread operations for File, Memory, and DB configurations.
- [x] Phase 18: PKCS#11 v3.0 attributes + RSA recovery + compliance hardening (v0.4.24)
  - [x] C++: `CKA_UNIQUE_ID` — auto-generated UUID v4, read-only, all objects; type value corrected to `0x00000017`
  - [x] C++: `CKA_PROFILE_ID` — token profile identifier, default 0; type value corrected to `0x00000104`
  - [x] C++: `C_SignRecover` / `C_VerifyRecover` — full RSA implementation (CKM_RSA_PKCS + CKM_RSA_X_509)
  - [x] C++: `CKA_PUBLIC_KEY_INFO` persistence fix — resolved 12 PQC keygen failures with `CKA_TOKEN=true`
  - [x] C++: Ed25519ph corrected to use `OSSL_PARAM` instance selection (OpenSSL 3.x)
  - [x] C++: SLH-DSA raw private key import via `EVP_PKEY_fromdata()` for FIPS 205 key sizes
  - [x] C++: `C_GetSessionValidationFlags` returns `CKR_OK` (software token, no constraints)
  - [x] C++: `CKM_RIPEMD160` / `CKM_RIPEMD160_HMAC` mechanism registration handling fallback
  - [x] Compliance suite: 127 PASS / 0 FAIL / 0 SKIP (RIPEMD160 cleanly gracefully aborted)
- [x] Phase 11: Security hardening (v0.4.0) — full remediation of March 2026 audit
  - [x] RSA X.509 integer underflow guard (sign + verify paths)
  - [x] AES-CBC IV length enforcement (exactly 16 bytes)
  - [x] WrapKeySym/UnwrapKeySym mode variable fix (AES-CBC/CBC-PAD)
  - [x] pValue NULL dereference guards (CKA_CLASS/KEY_TYPE/CERT_TYPE/TOKEN/PRIVATE)
  - [x] GcmMsgCtx param zeroization before free in Session::resetOp
  - [x] File::readString 64 MiB OOM cap
  - [x] Path traversal + symlink rejection in Directory::refresh
  - [x] ML-KEM shared secret and stored value wiped after encapsulate/decapsulate
  - [x] RSA-PSS salt length bounded to 512 bytes at all PSS parameter sites
  - [x] HandleManager counter seeded with random offset (non-predictable handles)
  - [x] CKM_SLH_DSA pure mode: reject non-NULL parameters
  - [x] Rust NULL output pointer guards (C_GetSlotList, C_OpenSession, C_GenerateKeyPair, C_GenerateKey, C_EncapsulateKey, C_DecapsulateKey)
  - [x] HMAC constant-time comparison via `subtle::ConstantTimeEq`
  - [x] KMAC constant-time comparison via `subtle::ConstantTimeEq`
  - [x] SymDecryptUpdate integer overflow guard
  - [x] IV ByteString zeroization on OSSLEVPSymmetricAlgorithm error paths
  - [x] Release build by default, compiler hardening flags, optional GPG verify for OpenSSL, cargo-audit CI
- [x] Phase 10: SHA-3 variants, PBKDF2, 5G KDF, key wrapping completeness
  - [x] C++: `CKM_ECDSA_SHA3_224/256/384/512` — ECDSA with SHA-3 hash
  - [x] C++: `CKM_RSA_SHA3_224/256/384/512_PKCS` and `_PKCS_PSS` — RSA PKCS#1 v1.5 and PSS with SHA-3
  - [x] C++ + Rust: `CKM_PKCS5_PBKD2` — PBKDF2 key derivation; HMAC-SHA{1/224/256/384/512} PRF; BIP39 / SLIP-0010
  - [x] C++: `CKD_SHA{1,256,384,512}_KDF` on `CKM_ECDH1_DERIVE` — X9.63 KDF for 5G SUCI deconcealment (TS 33.501 §6.12.2)
  - [x] C++: `CKM_AES_KEY_WRAP_PAD` registered in `prepareSupportedMechanisms()`
  - [x] Rust: `C_WrapKeyAuthenticated` / `C_UnwrapKeyAuthenticated` — AES-GCM authenticated key wrap (PKCS#11 v3.2 §5.18.6–7)
  - [x] Rust: `C_WrapKey` extended to accept `CKM_RSA_PKCS_OAEP` for indirect RSA+KEK wrapping
  - [x] Rust: `CKM_AES_KEY_WRAP_KWP` case added to `C_GetMechanismInfo`
  - [x] Rust: 65 total PKCS#11 exports (49 implemented, 8 multi-part stubs, 8 admin stubs)
- [x] Phase 12: SP 800-208 full parameter coverage + NIST ACVP LMS validation (v0.4.7)
  - [x] C++: `StatefulVerifyInit` / `StatefulVerify` — HSS/LMS/XMSS/XMSS^MT signature verification via PKCS#11 `C_VerifyInit`/`C_Verify`
  - [x] C++: XMSS keygen buffer overflow fix (OID prefix accounting)
  - [x] C++: XMSS `C_Sign` output compliance — return signature only, not `sig||msg`
  - [x] C++: SHAKE-256 hash type added to hash-sigs library (OpenSSL EVP)
  - [x] C++: All 20 LMS + 16 LMOTS SP 800-208 parameter sets (SHA-256 N32/N24, SHAKE-256 N32/N24)
  - [x] C++ + Rust: CKP_ constants corrected to IANA registry type IDs (RFC 8554 + SP 800-208)
  - [x] C++ + Rust: XMSS/XMSS^MT registered in `C_GetMechanismInfo` with `CKF_SIGN | CKF_VERIFY`
  - [x] Rust: `Sha256_192`, `Shake256_256`, `Shake256_192` hash type dispatch in LMS keygen
  - [x] NIST ACVP LMS sigVer: 320/320 demo vectors validated (all 80 parameter combinations)
  - [x] Rust + C++: XMSS and XMSS^MT DRBG Parity verification with identical vectors against NIST RNG specs!
- [x] Phase 17: ChaCha20-Poly1305 AEAD Integration (v0.4.14)
  - [x] Rust + C++: `CKM_CHACHA20_POLY1305` and `CKM_CHACHA20_KEY_GEN` implementation
  - [x] C++: `CKK_CHACHA20` KCV fixes within `C_CreateObject` (proxying SHA-256 verification internally)
  - [x] Rust: Validated byte-exact matching utilizing RFC 7539 parity tests
- [x] Phase 16: BIP32 child derive params layout fix for Ed25519/SLIP-0010 (v0.4.13)
  - [x] Rust: `C_DeriveKey` BIP32 child branch now reads `flags` from offset 0 and `index` from offset 4 (matches TS `buildBIP32ChildDeriveParams` layout)
  - [x] Previous off-by-one read (offset 4/8) caused Ed25519 non-hardened check to misfire → `CKR_MECHANISM_PARAM_INVALID` on first Solana child derive
  - [x] All 4 Solana SLIP-0010 path segments now derive correctly; addresses match JS reference
- [x] Phase 15: BIP32 `CKA_EXTRACTABLE` template compliance (v0.4.12)
  - [x] Rust: `C_DeriveKey` BIP32 dispatch now reads `CKA_EXTRACTABLE` from caller's template (per §5.18.5 general rules)
  - [x] Rust: Derived keys honour caller-specified extractability instead of hardcoding `sensitive=true`
  - [x] HD Wallet flows can now extract derived key bytes for address derivation without `CKR_ATTRIBUTE_SENSITIVE`
- [x] Phase 14: CKM_ECDSA raw (pre-hashed) Rust engine parity (v0.4.11)
  - [x] Rust: `CKM_ECDSA` (0x1041) constant + `SUPPORTED_MECHS` entry — PKCS#11 v3.2 §6.3.12
  - [x] Rust: `sign_ecdsa` — `PrehashSigner` arms for P-256 (`CURVE_P256`), P-384 (`CURVE_P384`), secp256k1 (`CURVE_K256`)
  - [x] Rust: `verify_ecdsa` — `PrehashVerifier` arms for P-256, P-384, secp256k1
  - [x] Rust: `C_Sign` and `C_Verify` dispatch extended to include `CKM_ECDSA`
  - [x] Rust engine at full parity with C++ engine for raw ECDSA (64 total PKCS#11 mechanisms)
- [x] Phase 13: PKCS#11 v3.2 attribute compliance audit + Rust engine API completeness (v0.4.10)
  - [x] Rust: `CKM_ECDSA_SHA512` (0x1046) — FIPS 186-5 §6.4 prehash truncation for P-256/P-384
  - [x] Rust: Message Encrypt/Decrypt API — 10 functions (`C_MessageEncryptInit` through `C_MessageDecryptFinal`), AES-GCM per-message AEAD
  - [x] Rust: `C_VerifySignatureUpdate` / `C_VerifySignatureFinal` — streaming pre-bound verify (completes v3.2 §11.15 surface)
  - [x] Rust: `C_GetSessionValidationFlags`, `C_AsyncComplete`, `C_AsyncGetID` — v3.2 async stubs (85 total PKCS#11 exports)
  - [x] C++: G-ATTR1a/b/c — `CKA_VALUE ck1|ck4` on ML-DSA, SLH-DSA, ML-KEM public key objects (spec Tables 280, 287, 290)
  - [x] C++: `CKA_PARAMETER_SET` corrected to `ck1|ck3` on ML-DSA/SLH-DSA/ML-KEM/XMSS/XMSS-MT public keys; `ck1|ck4|ck6` on private keys
  - [x] C++: HSS public key `CKA_HSS_LEVELS/LMS_TYPE/LMOTS_TYPE/LMS_TYPES/LMOTS_TYPES` corrected to `ck2|ck4` (MUST NOT for create and generate)
  - [x] C++: HSS/XMSS private key `CKA_VALUE` corrected to `ck1|ck4|ck6|ck7`
  - [x] C++: `P11AttrParameterSet` and HSS attribute base constructors — removed erroneous hardcoded `ck1`; flags now set exclusively at call site
  - [x] C++: `Slot::isTokenPresent()` returns `token->isInitialized()` — uninitialized slots excluded from `C_GetSlotList(tokenPresent=TRUE)`

## Integration Interfaces

SoftHSMv3 exposes integration interfaces that cover the full stack from browser WASM to enterprise infrastructure. Each wrapper has its own README with build + test steps:

| Interface | Location | Use case |
| --- | --- | --- |
| **Direct PKCS#11** | `libsofthsmv3.so` / npm | Native C/C++ / Node.js — load via `dlopen` + `C_GetFunctionList` |
| **OpenSSL 3.x Provider** | `src/vendor/pkcs11-provider/` | Transparent routing from any `openssl` CLI or linked app |
| **KMIP 3.0 server + CACP** | [`kmip/`](kmip/README.md) | Networked key management (TTLV/TLS) + crypto-agility policy engine; ML-KEM/ML-DSA/SLH-DSA + hybrid KEMs (3 ECDHE-MLKEM groups, OpenSSL-interop-verified); X25519/X448 ECDH + key agreement |
| **StrongSwan Adapter** | [`strongswan-pkcs11/`](strongswan-pkcs11/README.md) | IKEv2 VPN — ML-KEM-768 key exchange + ML-DSA signing |
| **Java JCE Layer** | [`JavaJCE/`](JavaJCE/JavaJCESofthsmv3.md) | Hyperledger Besu and JCA-based apps — ML-DSA-65 / ML-KEM-768 |
| **OpenSSH Connector** | [`openssh-pkcs11/`](openssh-pkcs11/README.md) | ML-DSA-65 ssh / sshd (draft-sfluhrer-ssh-mldsa-06); WASM build runs a real PQ SSH handshake |
| **OpenPGP Connector** | [`openpgp/`](openpgp/README.md) | OpenPGP signing / decryption with keys held on the token (ML-DSA / ML-KEM) |
| **MLS Provider** | [`openmls-provider/`](openmls-provider/README.md) | OpenMLS crypto provider backed by the token |
| **WebRPC** | [`webrpc/`](webrpc/README.md) | Roadmap — REST gateway to the module (not yet extracted) |

---

## OpenSSL 3 Provider (`pkcs11-provider`)

SoftHSMv3 vendors and ships a heavily-modified fork of the [Latchset `pkcs11-provider`](https://github.com/latchset/pkcs11-provider) (`src/vendor/latchset/`) to guarantee zero-configuration native OpenSSL 3.6 interoperability. This grants standard OpenSSL CLI operations (`genpkey`, `pkeyutl`, `req`, `x509`) transparent hardware-accelerated access to the internal PKCS#11 v3.2 boundaries without complex configuration wiring.

Key upgrades made to the integrated provider:

- **ML-KEM Operations**: Full `OSSL_OP_KEM` dispatch bindings allowing `pkeyutl -encap` and `-decap` routines to successfully flow down to the hardware `C_EncapsulateKey` implementations.
- **ML-DSA Signatures**: Native routing for FIPS 204 Parameter Sets (`ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`) linking `OSSL_OP_SIGNATURE` seamlessly to the HSM via robust Context mappings.
- **Asynchronous Mode Simulation**: Bypasses synchronous blocking failures by transparently asserting `CKF_ASYNC_SESSION` support during instantiation and reliably emitting `CKR_OPERATION_NOT_INITIALIZED` on all async polls, fully unblocking strictly asynchronous networking gateways.

### Build option: `openssl_modulesdir`

The vendored provider adds a meson option to override the OpenSSL provider module install path:

```bash
cd src/vendor/pkcs11-provider
meson setup build -Dopenssl_modulesdir=/opt/openssl-3.6/lib/ossl-modules
ninja -C build install
```

This is required when using a custom or non-system OpenSSL build whose `modulesdir` is not reflected in pkg-config (common in Emscripten cross-compile environments and Docker sandboxes).

---

## StrongSwan IKEv2 Adapter (`strongswan-pkcs11/`)

The `strongswan-pkcs11/` adapter extends strongSwan's native PKCS#11 plugin to support PKCS#11 v3.2 post-quantum operations for IKEv2.

### ML-KEM Key Exchange

The adapter implements `pkcs11_kem_t` using `C_EncapsulateKey` / `C_DecapsulateKey` (PKCS#11 v3.2 §5.17):

```c
// Initiator side — generates ML-KEM-768 keypair, returns public key
pkcs11_kem_t *kem = pkcs11_kem_create(module, ML_KEM_768);
chunk_t pubkey = kem->get_public_key(kem);    // sends to responder

// Responder side — encapsulates shared secret against initiator pubkey
kem->set_public_key(kem, pubkey_from_initiator);
chunk_t ciphertext = ...;                      // from C_EncapsulateKey
chunk_t shared_secret = kem->get_shared_secret(kem);

// Initiator side — decapsulates received ciphertext
kem->set_public_key(kem, ciphertext_from_responder);
chunk_t shared_secret = kem->get_shared_secret(kem); // from C_DecapsulateKey
```

### ML-DSA Signing

ML-DSA PKCS#11 v3.2 constants are defined in `strongswan-pkcs11/pkcs11.h`:

```c
#define CKK_ML_DSA              (0x0000004aUL)  // Key type
#define CKM_ML_DSA_KEY_PAIR_GEN (0x0000001cUL)  // Key generation
#define CKM_ML_DSA              (0x0000001dUL)  // Sign / Verify
```

These map directly to the softhsmv3 `C_SignInit` / `C_Sign` / `C_VerifyInit` / `C_Verify` dispatch for `CKM_ML_DSA`. Use the standard `CKA_PARAMETER_SET` attribute (`CKP_ML_DSA_44/65/87`) during key generation to select the security level.

### Sandbox Integration Coverage

The `softhsmv3_compatibility_report.md` documents integration pathways for all tools in the PQCToday sandbox:

| Status | Tools |
| --- | --- |
| **Full** (via OpenSSL Provider or direct PKCS#11) | `openssl` CLI, strongSwan VPN, Easy-RSA, Nginx, ldnsutils, S/MIME, `pkcs11-tool` |
| **Partial** (with workarounds) | OpenSSH (hardcoded KEM list — requires `ssh-agent` patch), QKD Toolkit, `testssl.sh` (passive) |
| **Not compatible** (different runtime) | Sequoia (Rust native), IOTA identity.rs (Rust WASM), Geth Clef (Go Cgo), ns-3, SeQUeNCe |

---

## Java JCE Provider (`JavaJCE/`)

The `JavaJCE/` module is a lightweight Java Security Provider that bridges JCA-based applications — including Hyperledger Besu — to softhsmv3 PKCS#11 v3.2 ML-DSA signing and ML-KEM key exchange.

### Why it is needed

Standard Java lacks frontend translation logic to convert high-level strings like `"ML-DSA-65"` into the `CKM_ML_DSA` (0x1d) integer used by the patched SunPKCS11 JNI. The `JavaJCE/` module intercepts JCA requests and performs that translation.

### Components

| File | Role |
| --- | --- |
| `SoftHSMJCEProvider.java` | Registers the provider with the JCA `Security` framework |
| `MLDSASignatureSpi.java` | Intercepts `Signature.getInstance("ML-DSA-65")`, translates to `CKM_ML_DSA` (0x1d) + `C_SignInit` |
| `MLKEMKeyAgreementSpi.java` | Intercepts `KeyAgreement.getInstance("ML-KEM-768")`, routes to `C_EncapsulateKey` / `C_DecapsulateKey` |
| `PKCS11IntegrationTest.java` | Integration test validating round-trips against the compiled `libsofthsmv3.so` |

### Usage

```java
// Register the provider (typically in app bootstrap or Dockerfile entrypoint)
Security.addProvider(new SoftHSMJCEProvider());

// Standard JCA call — no PKCS#11 plumbing visible to application code
Signature sig = Signature.getInstance("ML-DSA-65");
sig.initSign(mlDsaPrivateKey);
sig.update(message);
byte[] signature = sig.sign();
```

### Deployment (Docker)

The module is compiled inside `Dockerfile.physics` (the `playground-physics` sandbox container) using the patched JRE that holds the `CKM_ML_DSA` constants:

```dockerfile
COPY JavaJCE /JavaJCE
RUN javac -cp /opt/jre/lib/ext/sunpkcs11.jar -d /build/javajce /JavaJCE/src/**/*.java \
 && jar -cf /opt/besu/lib/javajce-softhsm.jar -C /build/javajce .
```

The resulting JAR is added to the Besu classpath so all `Signature`/`KeyAgreement` calls transparently route through softhsmv3.

---

## OpenSSH PKCS#11 Connector (`openssh-pkcs11/`)

The `openssh-pkcs11/` connector patches `openssh-portable` with the
[`ssh-mldsa-65`](https://datatracker.ietf.org/doc/draft-sfluhrer-ssh-mldsa/)
key type (draft-sfluhrer-ssh-mldsa-06, NIST Category 3, FIPS 204) and compiles
the client and a privsep-free server to WebAssembly. All ML-DSA signing is
delegated to softhsmv3 via `CKM_ML_DSA` (0x1d) over PKCS#11 v3.2.

### Layout

| File | Role |
| --- | --- |
| `patches/ssh-mldsa.c` | New OpenSSH key-type module — raw 1,952-byte ML-DSA-65 pubkey; signing is PKCS#11-only |
| `patches/apply_mldsa_patches.py` | Python driver that applies source-tree patches to an extracted `openssh-portable` tree (`sshkey.c`, `ssh-pkcs11.c`, `Makefile.in`, …) |
| `wasm-shims/sshd_wasm_main.c` | Privsep-free `sshd` entry point for the WASM build — replaces `fork()` / PAM / PTY / `setuid()` with a single-transport handshake |
| `wasm-shims/pkcs11_static.c` | Static `C_GetFunctionList` linkage against softhsmv3 so the WASM bundle ships self-contained without `dlopen` |
| `wasm-shims/{posix_stubs,socket_wasm}.c` | POSIX / networking stubs for Emscripten, bridging OpenSSH's file-descriptor I/O to the browser's SharedArrayBuffer transport |
| `scripts/build-wasm.sh` | End-to-end Emscripten build producing `openssh-{client,server}.{js,wasm}` |
| `scripts/copy-to-hub.sh` | Deploys built WASM bundles into the `pqctoday-hub` repo |

### Build

Run from the `pqctoday-hsm/` root after the softhsmv3 static archive and
OpenSSL WASM prefix are already built:

```bash
bash openssh-pkcs11/scripts/build-wasm.sh
bash openssh-pkcs11/scripts/copy-to-hub.sh   # deploys to ../pqctoday-hub/public/wasm/
```

See `openssh-pkcs11/README.md` for details and environment overrides
(`OPENSSL_WASM`, `SOFTHSM_WASM`, `HUB`).

---

## Building (Native)

```bash
# Requires OpenSSL >= 3.5 (for ML-KEM/ML-DSA/SLH-DSA EVP support; 3.5.0 enforced)
mkdir build && cd build
cmake .. -DWITH_CRYPTO_BACKEND=openssl -DENABLE_MLKEM=ON -DENABLE_MLDSA=ON
make
make check
```

### Building the OpenSSL Provider (optional, native only)

```bash
# Build and install the vendored pkcs11-provider against your system OpenSSL
cd src/vendor/pkcs11-provider
meson setup build
ninja -C build
ninja -C build install

# If OpenSSL is installed to a non-standard prefix, override the module directory:
meson setup build -Dopenssl_modulesdir=/opt/openssl-3.6/lib/ossl-modules
ninja -C build install
```

## Building (WASM — C++/Emscripten)

```bash
# Requires Emscripten SDK + OpenSSL >= 3.5 cross-compiled for WASM
mkdir build-wasm && cd build-wasm
emcmake cmake .. -DWITH_CRYPTO_BACKEND=openssl -DENABLE_MLKEM=ON -DENABLE_MLDSA=ON
emmake make
```

## Building (WASM — Rust)

```bash
# Requires Rust toolchain + wasm-pack
rustup target add wasm32-unknown-unknown
cargo install wasm-pack

cd rust
wasm-pack build --target web --release
# Output: rust/pkg/softhsmrustv3_bg.wasm (~1.4 MB)
```

## References

- [PKCS#11 v3.2 Specification](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html)
- [PKCS#11 v3.2 pkcs11t.h](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/include/pkcs11-v3.2/pkcs11t.h) — canonical constant values
- [FIPS 203: ML-KEM Standard](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204: ML-DSA Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 205: SLH-DSA Standard](https://csrc.nist.gov/pubs/fips/205/final)
- [OpenSSL 3.6 ML-KEM Documentation](https://docs.openssl.org/3.6/man7/EVP_PKEY-ML-KEM/)
- [OpenSSL 3.6 ML-DSA Documentation](https://docs.openssl.org/3.6/man7/EVP_PKEY-ML-DSA/)
- [RustCrypto Organization](https://github.com/RustCrypto) — `ml-kem`, `ml-dsa`, `slh-dsa`, `rsa`, `aes` crates
- [wasm-bindgen](https://rustwasm.github.io/docs/wasm-bindgen/) — Rust ↔ JS WASM bridge
- [Original SoftHSM2](https://github.com/softhsm/SoftHSMv2)

## License

BSD-2-Clause (same as SoftHSM2). See [LICENSE](LICENSE). See [Terms of Service](TERMS.md) for usage terms, export compliance (ECCN 5D002), and sanctions restrictions.

## Acknowledgments

This project is a fork of [SoftHSM2](https://github.com/softhsm/SoftHSMv2) by the OpenDNSSEC project. PQC implementation references Mozilla NSS (Bug 1965329).

Maintained by [PQC Today](https://pqctoday.com).
