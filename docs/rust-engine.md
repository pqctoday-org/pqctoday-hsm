# softhsmrustv3 — Rust WASM Engine

**Updated:** 2026-09-01 (adds `CKM_HPKE`; fixes stale function-count, crate-name, and Known Limitations claims)
**Package:** `softhsmrustv3` (Rust crate, `cdylib` → `softhsmrustv3_bg.wasm`)
**Companion:** [softhsmv3devguide.md](softhsmv3devguide.md) (C++ engine), [gap-analysis-pkcs11-v3.2.md](gap-analysis-pkcs11-v3.2.md) (compliance)

---

## Overview

`softhsmrustv3` is a pure-Rust WebAssembly implementation of the PKCS#11 v3.2 interface,
built as a parallel engine to the C++ `softhsmv3` Emscripten build. Both engines expose
the same `_C_*` function surface and are interchangeable via the `engineMode` flag in
`pqc-timeline-app/src/wasm/softhsm.ts`.

The Rust engine exists for two reasons:

1. **Cross-engine parity verification** — the PQC Today Playground's `dual` mode runs the
   same operation on both engines and compares outputs (shared secrets, signatures) byte-by-byte.
   This validates that the ML-KEM and ML-DSA implementations are interoperable across two
   completely independent code paths.

2. **Pure-Rust reference implementation** — demonstrates that PKCS#11 v3.2 PQC operations
   can be implemented without OpenSSL, using only the Rust crypto ecosystem.

---

## Technology Stack

All cryptography uses pure-Rust crates from the [RustCrypto](https://github.com/RustCrypto)
ecosystem. No OpenSSL, no system libraries, no native bindings.

| Crate | Version | Algorithms |
|---|---|---|
| `ml-kem` | 0.2.3 | ML-KEM-512, ML-KEM-768, ML-KEM-1024 (FIPS 203) |
| `fips204` (patched fork, `fips204-patched/`) | 0.4.6 | ML-DSA-44, ML-DSA-65, ML-DSA-87 (FIPS 204), incl. HashML-DSA pre-hash `Ph` variants — corrected 2026-09-01; this table previously named the unrelated, no-longer-used `ml-dsa` RustCrypto crate |
| `fips205` (patched fork, `fips205-patched/`) | 0.4.1 | All 12 SLH-DSA parameter sets (FIPS 205), incl. HashSLH-DSA pre-hash `Ph` variants — corrected 2026-09-01; this table previously named the unrelated, no-longer-used `slh-dsa` RustCrypto crate |
| `rsa` | 0.9 (sha2) | RSA-2048, RSA-3072, RSA-4096 (PKCS#1 v2.2) |
| `p256` | 0.13 (ecdsa, ecdh) | ECDSA P-256, ECDH P-256 |
| `p384` | 0.13 (ecdsa, ecdh) | ECDSA P-384, ECDH P-384 |
| `p521` | 0.13 (ecdsa, ecdh) | ECDSA P-521, ECDH P-521 |
| `ed25519-dalek` | 2.1 (rand_core, digest) | Ed25519 signatures (RFC 8032) |
| `x25519-dalek` | 2.0 (static_secrets) | X25519 key agreement |
| `aes` | 0.8.3 | AES-128, AES-256 block cipher |
| `aes-gcm` | 0.10.3 | AES-128-GCM, AES-256-GCM (AEAD) |
| `aes-kw` | 0.2 (alloc) | AES Key Wrap (RFC 3394) |
| `cbc` | 0.1.2 | AES-CBC |
| `ctr` | 0.9.2 | AES-CTR |
| `hmac` | 0.12.1 | HMAC-SHA-256/384/512 |
| `hkdf` | 0.12 | HKDF (RFC 5869) |
| `pbkdf2` | 0.12 | PBKDF2 (BIP39 derivation) |
| `sha2` | 0.10.8 | SHA-256, SHA-384, SHA-512 |
| `sha3` | 0.10.8 | SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256 |
| `pkcs8` | 0.11.0-rc.11 (alloc) | PKCS#8 key encoding/decoding |
| `spki` | 0.8.0-rc.4 (alloc) | SubjectPublicKeyInfo (X.509 public keys) |
| `signature` | 3.0.0-rc.10 | Signature traits |
| `getrandom` | 0.2.17 (js) | WASM-compatible CSPRNG (uses browser `crypto.getRandomValues`) |
| `zeroize` | 1 | Secure memory zeroization |
| `wasm-bindgen` | 0.2.117 | JS/WASM bridge |

---

## Build

The Rust engine is built with `wasm-pack` targeting the `web` profile:

```bash
cd softhsmv3/rust
wasm-pack build --target web --release
# Output: pkg/softhsmrustv3_bg.wasm + pkg/softhsmrustv3.js + pkg/softhsmrustv3.d.ts
```

WASM binary is optimized for size (`opt-level = "s"`, `lto = true`).
Output is copied to `pqc-timeline-app/public/wasm/rust/softhsmrustv3_bg.wasm`
and `pqc-timeline-app/src/wasm/softhsmrustv3.{js,d.ts}`.

---

## PKCS#11 Surface — Implemented Functions

The Rust WASM binary exports 104 `_C_*` functions via `wasm-bindgen` (count
corrected 2026-09-01 — this document said "45" long after the surface grew,
then "102" as of a 2026-08-13 correction that itself undercounted by one:
`_C_GetMechanismList`'s `#[wasm_bindgen]` export lives in `constants.rs`, not
`ffi.rs`, and was missed by that count), and `rust/src/ck_abi.rs` additionally
provides the native C ABI (`CK_FUNCTION_LIST`-shaped, 104 `C_*` functions) for
non-wasm consumers. The
TypeScript wrapper (`softhsm.ts: getSoftHSMRustModule()`) bridges all PKCS#11
calls and adds JS-side stubs for functions not yet in the Rust binary.

### Fully Implemented (native Rust WASM)

| Category | Functions |
|---|---|
| **Lifecycle** | `C_Initialize`, `C_Finalize` |
| **Session** | `C_OpenSession`, `C_CloseSession`, `C_Login`, `C_Logout`, `C_GetSessionInfo` |
| **Slot / Token** | `C_GetSlotList`, `C_GetTokenInfo`, `C_GetMechanismList`, `C_GetMechanismInfo`, `C_InitToken`, `C_InitPIN` |
| **Object** | `C_CreateObject`, `C_DestroyObject`, `C_FindObjectsInit`, `C_FindObjects`, `C_FindObjectsFinal`, `C_GetAttributeValue` |
| **Key generation** | `C_GenerateKey` (AES-128/256), `C_GenerateKeyPair` (ML-KEM, ML-DSA, SLH-DSA, RSA, ECDSA P-256/P-384/P-521, Ed25519, `CKM_HPKE_KEM_KEY_PAIR_GEN` — vendor mechanism, Rust engine only) |
| **KEM** | `C_EncapsulateKey`, `C_DecapsulateKey` (ML-KEM-512/768/1024; also `CKM_HPKE` — RFC 9180 HPKE, vendor mechanism, Rust engine only) |
| **Encrypt / Decrypt** | `C_EncryptInit` + `C_Encrypt` (one-shot), `C_DecryptInit` + `C_Decrypt` (one-shot); mechanisms: AES-GCM, AES-CBC, AES-KW, RSA-OAEP; multipart `C_EncryptUpdate`/`C_EncryptFinal`, `C_DecryptUpdate`/`C_DecryptFinal` |
| **Sign / Verify** | `C_SignInit` + `C_Sign` (one-shot), `C_VerifyInit` + `C_Verify` (one-shot), `C_SignMessage` (one-shot), `C_VerifyMessage` (one-shot); algorithms: ML-DSA-44/65/87, SLH-DSA (all 12), RSA-PKCS, RSA-PSS, ECDSA P-256/P-384/P-521, Ed25519; multipart `C_SignUpdate`/`C_SignFinal`, `C_VerifyUpdate`/`C_VerifyFinal`; pre-bound `C_VerifySignatureInit`/`C_VerifySignature` (+ multipart `C_VerifySignatureUpdate`/`C_VerifySignatureFinal`); recover `C_SignRecoverInit`/`C_SignRecover`, `C_VerifyRecoverInit`/`C_VerifyRecover` |
| **Message API** | `C_MessageSignInit` + `C_MessageSignFinal` (one-shot envelope, + multipart `C_SignMessageBegin`/`C_SignMessageNext`), `C_MessageVerifyInit` + `C_MessageVerifyFinal` (one-shot envelope, + multipart `C_VerifyMessageBegin`/`C_VerifyMessageNext`), `C_MessageEncryptInit`/`C_EncryptMessage` (+ multipart `C_EncryptMessageBegin`/`C_EncryptMessageNext`), `C_MessageDecryptInit`/`C_DecryptMessage` (+ multipart `C_DecryptMessageBegin`/`C_DecryptMessageNext`) |
| **Digest** | `C_DigestInit`, `C_Digest`, `C_DigestUpdate`, `C_DigestFinal`; SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512, HMAC |
| **Dual-function** | `C_DigestEncryptUpdate`, `C_DecryptDigestUpdate`, `C_SignEncryptUpdate`, `C_DecryptVerifyUpdate` (composed from the single-function ops above) |
| **Key wrap / unwrap** | `C_WrapKey`, `C_UnwrapKey` (AES-KW, AES-GCM wrap, RSA-OAEP wrap), `C_WrapKeyAuthenticated`/`C_UnwrapKeyAuthenticated` (AES-GCM), `C_DeriveKey` (ECDH, HKDF, PBKDF2) |
| **Object mgmt** | `C_CopyObject`, `C_GetObjectSize`, `C_SetAttributeValue` |
| **Random** | `C_GenerateRandom` (browser CSPRNG via `getrandom::js`) |

### Stubbed — `CKR_FUNCTION_NOT_SUPPORTED`

**Corrected 2026-09-01**: every function this table previously listed except the
three below is now fully implemented (moved into the table above) — verified
directly against each function's body in `rust/src/ffi.rs`. Streaming
sign/verify/encrypt/decrypt, the message streaming and message encrypt/decrypt
API, authenticated wrap/unwrap, recovery ops, and the dual-function verbs were
all stale here, contradicting the Algorithm Parity table below (itself already
corrected 2026-08-13). Only these three remain genuine stubs:

| Category | Stubbed Functions |
|---|---|
| **Object mgmt** | `C_DigestKey` |
| **Session state** | `C_GetOperationState`, `C_SetOperationState` |

---

## Session Handling — Important Differences from C++

The Rust engine has a simplified session model suited to single-session educational use:

- **`C_OpenSession` always returns handle `1`** — session handle is constant.
  All operations that take `h_session` accept any value; the Rust WASM prefixes the parameter
  with underscore (`_h_session`) to signal it is intentionally unused.
- **`C_SignInit` / `C_VerifyInit` / `C_EncryptInit` / `C_DigestInit` USE `h_session`** as a
  HashMap key to store operation state between `Init` and the corresponding `Sign`/`Verify`/etc.
  call. This is the exception — these four init functions do read the session handle.
- **Non-persistent** — all key handles and operation state are lost when the WASM module is
  garbage-collected. This matches the C++ engine's educational-demo design.
- **Single-threaded** — WASM runs on the main thread; keygen for large SLH-DSA variants
  (~200ms) will briefly block the UI. Use Web Workers for production integrations.

> **Cross-check implication:** The PQC Today Playground's dual-engine cross-check passes
> C++ session handles directly to Rust operations (e.g., after `C_OpenSession` on C++,
> it calls `_C_EncapsulateKey` on the Rust module with the same handle value). This works
> correctly because `C_EncapsulateKey` and `C_DecapsulateKey` in the Rust engine ignore
> `_h_session` entirely.

---

## Dual-Engine Cross-Check Architecture

The cross-check runs automatically in `dual` mode in the PQC Today Playground:

```
HsmKemPanel (ML-KEM):
  C++ C_GenerateKeyPair → pubkey exported via CKA_VALUE
  Rust C_EncapsulateKey(cpp_pubkey) → rust_ciphertext + rust_secret
  C++ C_DecapsulateKey(rust_ciphertext) → cpp_secret
  Assert: rust_secret === cpp_secret (byte-for-byte)

HsmSignPanel (ML-DSA):
  C++ C_Sign(message) → cpp_signature
  C++ C_GetAttributeValue(pubkey, CKA_VALUE) → cpp_pubkey_bytes
  Rust C_CreateObject(cpp_pubkey_bytes) → rust_pubkey_handle
  Rust C_Verify(rust_pubkey, cpp_signature, message) → CKR_OK
```

Parity success/failure is logged to the unified PKCS#11 call log as
`Dual-Engine Parity / SUCCESS` or `Dual-Engine Parity / FAIL`.

**Code locations:**
- `KemOpsTab.tsx:41` — ML-KEM cross-check (Rust encapsulates with C++ pubkey → C++ decapsulates)
- `SignVerifyTab.tsx:106` — ML-DSA cross-check (C++ signs → Rust imports pubkey → Rust verifies)
- Guard: `engineMode === 'dual' && crossCheckModuleRef.current !== null`

---

## Loading — Integration in pqc-timeline-app

The Rust engine is loaded as a lazy singleton via `getSoftHSMRustModule()`:

```typescript
// src/wasm/softhsm.ts
export const getSoftHSMRustModule = async (): Promise<SoftHSMModule> => {
  if (!rustModulePromise) {
    rustModulePromise = (async () => {
      const rustShim = await import('./softhsmrustv3.js')        // wasm-bindgen JS shim
      const wasmExports = await rustShim.default('/wasm/rust/softhsmrustv3_bg.wasm')
      return buildRustModule(wasmExports)   // wraps exports + adds stubs
    })()
  }
  return rustModulePromise
}
```

`HsmContext.tsx` stores the loaded module in `crossCheckModuleRef` (dual mode) or
`moduleRef` (rust-only mode). `HsmSetupPanel` initializes both modules in dual mode.

---

## Algorithm Parity vs C++ Engine

| Algorithm | C++ (softhsmv3) | Rust (softhsmrustv3) | Notes |
|---|---|---|---|
| ML-KEM-512/768/1024 | ✅ | ✅ | Cross-check verified |
| ML-DSA-44/65/87 (pure) | ✅ | ✅ | Cross-check verified |
| ML-DSA pre-hash (10 variants) | ✅ | ✅ | Implemented (hash-specific + generic `CKM_HASH_ML_DSA` with param remap); the old "crate lacks pre-hash API" note was stale (corrected 2026-08-13) |
| SLH-DSA (all 12 param sets, pure) | ✅ | ✅ | |
| SLH-DSA pre-hash | ✅ | ✅ | Implemented (hash-specific + generic `CKM_HASH_SLH_DSA`); stale "pending" note corrected 2026-08-13 |
| HSS/LMS (SP 800-208) | ✅ | ✅ | Rust via `hbs-lms` crate |
| XMSS single-tree (RFC 8391) | ✅ | ✅ | Rust via `xmss` crate; 2026-08-13: SHAKE param ids realigned to the RFC/SP 800-208 registry (0x07-0x09 SHAKE128, 0x11-0x13 SHAKE256 — implemented) |
| XMSS-MT | ✅ | ✅ | Implemented (all 56 RFC 8391 + SP 800-208 param sets via the `xmss` crate); the "crate lacks multi-tree support" note was stale (corrected 2026-08-13) |
| RSA-2048/3072/4096 | ✅ | ✅ | |
| ECDSA P-256, P-384 | ✅ | ✅ | |
| ECDSA P-521 | ✅ | ✅ | Added in Unreleased; `CKM_ECDSA_SHA512` + prehash + ECDH |
| Ed25519 | ✅ | ✅ | |
| X25519 (ECDH) | ✅ | ✅ | DeriveKey |
| AES-GCM, AES-CBC, AES-KW, AES-CTR | ✅ | ✅ | |
| RSA-OAEP wrap/encrypt | ✅ | ✅ | |
| HMAC-SHA-256/384/512 | ✅ | ✅ | |
| SHA-256/384/512 digest | ✅ | ✅ | |
| SHA3-256/512 digest | ✅ | ✅ | |
| HKDF | ✅ | ✅ | DeriveKey |
| PBKDF2 | ✅ | ✅ | DeriveKey |
| ECDSA-SHA3 variants | ✅ | ✅ | `CKM_ECDSA_SHA3_224/256/384/512` for P-256/P-384/P-521 |
| ECDH cofactor | ✅ | ✅ | `CKM_ECDH1_COFACTOR_DERIVE` dispatched for the NIST prime curves (CKK_EC only, per §6.3.18 Table 79); stale row corrected 2026-08-13 |
| ECDH-as-KEM (`CKM_ECDH1_DERIVE` under C_Encapsulate/DecapsulateKey) | ✅ | ✅ | Implemented 2026-08-13 for P-256/P-384/P-521, wire-compatible with the C++ engine (DER-wrapped ephemeral point ct, raw X-coordinate secret) |
| SP 800-108 Counter/Feedback KDF | ✅ | ✅ | `CKM_SP800_108_COUNTER_KDF` / `CKM_SP800_108_FEEDBACK_KDF` under C_DeriveKey; stale row corrected 2026-08-13 |
| Authenticated key wrap | ✅ | ✅ | Real implementation (no longer a stub); stale row corrected 2026-08-13 |
| Streaming sign/verify/encrypt | ✅ | ✅ | Multipart Update/Final implemented (sign, verify, digest, encrypt/decrypt incl. AES-GCM/CBC-PAD); stale row corrected 2026-08-13 |
| Message encrypt/decrypt API | ✅ | ✅ | `C_MessageEncrypt*` / `C_MessageDecrypt*` implemented incl. multipart GCM; stale row corrected 2026-08-13 |
| HPKE (RFC 9180, `CKM_HPKE`) | ❌ | ✅ | Added 2026-09-01. Vendor mechanism, Rust engine only — not in PKCS#11 v3.2 (v3.3's draft `CKM_COMP_KEM` targets a different, composite-KEM spec); all 4 HPKE modes + PQ/T hybrid KEM combiner (MLKEM768-X25519, MLKEM768-P256, MLKEM1024-P384) via `C_GenerateKeyPair`/`C_EncapsulateKey`/`C_DecapsulateKey`; C++ parity is a separately gated follow-on. See `docs/proposals/pkcs11-ckm-hpke-mechanism-proposal.md` |

---

## Known Limitations

- **Single session handle** — `C_OpenSession` always returns handle `1`. Multi-session
  applications must use separate WASM module instances.

**Corrected 2026-09-01**: this section previously listed "no ML-DSA/SLH-DSA pre-hash",
"XMSS-MT not supported", and "no SP 800-108 KDFs or ECDH cofactor" as Rust-engine
limitations. All three are stale and directly contradicted the Algorithm Parity table
above (itself already corrected 2026-08-13) — verified against `rust/src/crypto/handlers.rs`
(`CKM_HASH_ML_DSA`/`CKM_HASH_SLH_DSA` pre-hash dispatch), `rust/src/crypto/xmss_bridge.rs`
(`xmssmt_keygen`/`xmssmt_sign`/`xmssmt_verify`), and `rust/src/ffi.rs`
(`CKM_SP800_108_COUNTER_KDF`/`CKM_SP800_108_FEEDBACK_KDF`/`CKM_ECDH1_COFACTOR_DERIVE`
dispatch) — all four are implemented in the Rust engine today. Removed rather than
left stale.
