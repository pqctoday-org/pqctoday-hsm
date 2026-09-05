# softhsmrustv3 — Rust WASM Engine

**Updated:** 2026-09-04 (adds the crate's full vendor/BSI/blockchain mechanism surface —
ChaCha20(-Poly1305), AES-XTS, AES-CMAC, Ed448/X448, BIP32, Keccak-256, FrodoKEM,
Classic McEliece, Split Key Sharing — that had never been documented here; adds a
Testing & Conformance section; adds the 2026-09-04 `CKA_COPYABLE` security-fix section
and the 2026-09-04 full-SP-800-208-param-set XMSS fix note; corrects the Build section
against `rust/README.md` and `rust/build-wasm-bundle.sh`, including a real discrepancy
found between `Cargo.toml`'s `acvp`-feature doc comment and what `build-wasm-bundle.sh`
actually ships; and corrects every `pqc-timeline-app` reference — that repo no longer
exists in this workspace, the integration lives in `pqctoday-hub` today (verified
directly against that sibling repo, including exact file paths and current line
numbers for the two cross-check components))
**Package:** `softhsmrustv3` (Rust crate, `cdylib` → `softhsmrustv3_bg.wasm`; also builds as
a native `rlib`/`staticlib` — see `rust/Cargo.toml`'s `crate-type`)
**Companion:** [softhsmv3devguide.md](softhsmv3devguide.md) (C++ engine), [gap-analysis-pkcs11-v3.2.md](gap-analysis-pkcs11-v3.2.md) (compliance), `rust/README.md` (crate-local build/test quick reference), `rust/docs/NATIVE_API.md` (native Rust API for non-wasm callers, e.g. the KMIP server), `rust/RUST_P11_V32_CONFORMANCE_REPORT.md` (live conformance evidence)

> **Beyond WASM:** despite this doc's historical title, `softhsmrustv3` is also the
> **production backend for the KMIP server and CACP policy engine** (`kmip/`) on
> native targets — not only a browser WASM engine. See `rust/README.md`.

---

## Overview

`softhsmrustv3` is a pure-Rust WebAssembly implementation of the PKCS#11 v3.2 interface,
built as a parallel engine to the C++ `softhsmv3` Emscripten build. Both engines expose
the same `_C_*` function surface and are interchangeable via the `engineMode` flag in
`pqctoday-hub/src/wasm/softhsm.ts` (**corrected 2026-09-04** — this doc previously said
`pqc-timeline-app`; no repo by that name exists in this workspace, the integration
lives in the sibling `pqctoday-hub` repo today, confirmed directly against its
source — see the Loading section below).

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
| `rsa` | 0.9 (sha2, hazmat — corrected 2026-09-04; `hazmat` backs `C_SignRecover`/`C_VerifyRecover`'s raw RSASP1/RSAVP1 primitives) | RSA-2048, RSA-3072, RSA-4096 (PKCS#1 v2.2) |
| `p256` | 0.13 (ecdsa, ecdh) | ECDSA P-256, ECDH P-256 |
| `p384` | 0.13 (ecdsa, ecdh) | ECDSA P-384, ECDH P-384 |
| `p521` | 0.13 (ecdsa, ecdh) | ECDSA P-521, ECDH P-521 |
| `ed25519-dalek` | 2.1 (rand_core, digest, hazmat — corrected 2026-09-04; `hazmat` exposes `ExpandedSecretKey`, used for the Ed25519ctx construction alongside `curve25519-dalek` below) | Ed25519 signatures (RFC 8032) |
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
| `sha3` | 0.10.8 (`oid` feature — corrected 2026-09-04; backs `CKM_SHA3_384_RSA_PKCS`'s `AssociatedOid`) | SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256 |
| `pkcs8` | 0.11.0-rc.11 (alloc) | PKCS#8 key encoding/decoding |
| `spki` | 0.8.0-rc.4 (alloc) | SubjectPublicKeyInfo (X.509 public keys) |
| `signature` | 3.0.0-rc.10 | Signature traits |
| `getrandom` | 0.2.17 (js) | WASM-compatible CSPRNG (uses browser `crypto.getRandomValues`) |
| `zeroize` | 1 | Secure memory zeroization |
| `wasm-bindgen` | 0.2.117 | JS/WASM bridge |

**Added 2026-09-04 — previously missing from this table** (verified against `rust/Cargo.toml`):

| Crate | Version | Algorithms |
|---|---|---|
| `chacha20poly1305` | 0.10 | ChaCha20-Poly1305 AEAD (`CKM_CHACHA20_POLY1305`) |
| `chacha20` | 0.9 | Plain ChaCha20 stream cipher (`CKM_CHACHA20`, PKCS#11 v3.2 §6.20) |
| `xts-mode` | 0.5 | AES-XTS (`CKM_AES_XTS`, §6.15) |
| `cmac` | 0.7 | AES-CMAC (`CKM_AES_CMAC`, §6.44; also an SP 800-108 KBKDF PRF) |
| `ghash` | 0.5 | Incremental GHASH — backs multi-part `C_EncryptUpdate`/`C_DecryptUpdate` for `CKM_AES_GCM` (the one-shot `aes-gcm` crate alone can't stream) |
| `sha1` | 0.10 | SHA-1 — used **only** for `CKA_CHECK_VALUE` on generic-secret keys (§6.8.2: first 3 bytes of SHA-1(value)), not a signing primitive |
| `ripemd` | 0.1 | RIPEMD-160 digest + HMAC |
| `k256` | 0.13 (ecdsa, ecdh) | secp256k1 — backs BIP32 key derivation, not registered as a standalone PKCS#11 EC curve |
| `curve25519-dalek` | 4.1.3 (digest) | Ed25519ctx (RFC 8032 §5.1) — `ed25519-dalek` 2.1 has no public API for this context-string mode |
| `ed448-goldilocks` | 0.14.0-pre.11 (alloc, signing) | Ed448 (RFC 8032 §5.2) |
| `x448` | 0.14.0-pre.8 (static_secrets) | X448 key agreement (`CKM_X448`, vendor mechanism `0x8000_1059`) |
| `hbs-lms` (patched fork, `hbs-lms-patched/`) | 0.1.1 | Stateful HSS/LMS (SP 800-208 SHAKE-256 type-ID fix over upstream) |
| `xmss` | 0.1.0-pre.0 | XMSS + XMSS-MT (RFC 8391), all 18 SP 800-208 parameter sets as of the 2026-09-04 fix (see Known Limitations) |
| `tiny-keccak` | 2.0 (keccak) | Keccak-256 digest — vendor mechanism `CKM_KECCAK_256` (`0x8000_0010`), for Ethereum-style address derivation |
| `num-bigint` | 0.4 | Modular arithmetic for `CKM_PQCTODAY_SPLIT_KEY` (Polynomial GF(256) secret sharing, KMIP 3.0 §13.1) |
| `frodo-kem` | 0.1 (frodo640/976/1344 × aes/shake) | FrodoKEM — BSI TR-02102-1 conservative KEM, vendor mechanisms `CKM_PQCTODAY_FRODOKEM_KEY_PAIR_GEN`/`_ENCAPSULATE` (`0x8000_0001`/`0x8000_0002`) |
| `classic-mceliece-rust` | 3 (mceliece6688128, alloc, zeroize) | Classic McEliece — BSI-recommended KEM, vendor mechanisms `CKM_PQCTODAY_CLASSIC_MCELIECE_KEY_PAIR_GEN`/`_ENCAPSULATE` (`0x8000_0003`/`0x8000_0004`); only the Category-5 `mceliece6688128` parameter set is enabled |
| `rusqlite` | 0.32 (bundled) | Native-only object store backend (`store::sqlite`); target-gated **out** of both wasm32 targets, mirroring the C++ engine's own `WITH_OBJECTSTORE_BACKEND_DB=OFF` decision for its WASM build |

None of these vendor/BSI/blockchain mechanisms are part of PKCS#11 v3.2 — they use
vendor codepoints in the `CKM_VENDOR_DEFINED` range and are Rust-engine only, same
disposition as `CKM_HPKE` below.

---

## Build

**Corrected 2026-09-04** — this section previously showed only a bare `wasm-pack
build --target web --release` invocation; `rust/README.md` (crate-local, more current)
and `rust/build-wasm-bundle.sh` show the real, current build paths, which differ by
consumer:

```bash
cd rust

# Native library + tests (used by the KMIP server / CACP policy engine, and by
# developers running the engine's own test suite)
cargo build --release
cargo test

# WASM bundle (bundler target, dev profile, ACVP KATs enabled) — runs in the
# OrbStack/Docker `pqc-rust` container if cargo isn't on PATH locally.
RUSTFLAGS="-C link-arg=-zstack-size=2097152" \
  wasm-pack build --target bundler --out-dir pkg --dev -- --features acvp
```

The `acvp` Cargo feature (default OFF in `Cargo.toml`) lets `C_Initialize` seed a
deterministic ChaCha20 RNG via `CK_C_INITIALIZE_ARGS.pReserved` for known-answer-test
reproducibility — a deliberate PKCS#11 v3.2 §5.6 deviation (the spec requires
`pReserved == NULL`). `Cargo.toml`'s own `[features]` doc comment states every
**shipped** artifact (the `pqctoday-kmip` server binary, the in-browser playground
WASM bundle, this crate's plain `cdylib`) should build **without** it and be
§5.6-conformant by default.

**Corrected 2026-09-04 — real discrepancy found, flagged rather than resolved:**
`rust/build-wasm-bundle.sh`, read directly, does not honor that. It always passes
`--features acvp` to `wasm-pack`, for both of its modes — `./build-wasm-bundle.sh`
(release, `--out-dir pkg-release`) and `./build-wasm-bundle.sh --dev` (`--out-dir
pkg`). On the release path the script then copies `pkg-release/`'s three build
artifacts straight into `pkg_bundler/`, which its own header comment names as "the
tracked rust/pkg_bundler artifacts the @pqctoday/softhsm-wasm package vendors into
the hub playground." So the artifact this script hands to the hub playground appears
to carry the `acvp` feature, contradicting `Cargo.toml`'s comment above. This doc
cannot determine which file reflects the intended behavior — surfacing the conflict
for whoever owns the release pipeline to confirm, not asserting a verdict.

`rust/` also contains `pkg-release-acvp/` and `pkg_nomod/` directories. Neither is
produced by `build-wasm-bundle.sh`, nor by any other script found in this repo
(checked via `grep -rln` for both names across `*.sh`/`*.md`/`*.json`/`*.toml`/`*.yml`)
— both are stale (last modified Jun 2026, versus Sep 2026 for `pkg/`, `pkg-release/`,
and `pkg_bundler/`, which are actively regenerated). Treat them as leftover from an
earlier build process, not part of the current build path.

WASM binaries are optimized for size (`opt-level = "s"`, `lto = true`, per
`rust/Cargo.toml`'s `[profile.release]`).

**Corrected 2026-09-04:** the copy destination into a consuming app is verifiable
after all, against the sibling `pqctoday-hub` repo — `build-wasm-bundle.sh`'s own
comments name `pqctoday-hub/src/wasm/softhsmrustv3_bg.wasm` as the hub loader's path,
and that exact file (plus `public/wasm/rust/softhsmrustv3_bg.wasm` and
`src/wasm/softhsmrustv3.{js,d.ts}`) exists there today. `pqc-timeline-app`, this
section's previous name for that app, does not exist anywhere in this workspace.

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
| **Info / Interface** | `C_GetInfo`, `C_GetFunctionList`, `C_GetInterface`, `C_GetInterfaceList`, `C_GetFunctionStatus` |
| **Session** | `C_OpenSession`, `C_CloseSession`, `C_CloseAllSessions`, `C_Login`, `C_LoginUser`, `C_Logout`, `C_GetSessionInfo`, `C_GetSessionValidationFlags` (v3.2), `C_SessionCancel` (v3.2 — clears in-flight Encrypt/Decrypt operation state per the `flags` bitmask) |
| **Slot / Token** | `C_GetSlotList`, `C_GetSlotInfo`, `C_GetTokenInfo`, `C_GetMechanismList`, `C_GetMechanismInfo`, `C_InitToken`, `C_InitPIN`, `C_SetPIN` |
| **Object** | `C_CreateObject`, `C_DestroyObject`, `C_FindObjectsInit`, `C_FindObjects`, `C_FindObjectsFinal`, `C_GetAttributeValue` |
| **Key generation** | `C_GenerateKey` (AES-128/256), `C_GenerateKeyPair` (ML-KEM, ML-DSA, SLH-DSA, RSA, ECDSA P-256/P-384/P-521, Ed25519, `CKM_HPKE_KEM_KEY_PAIR_GEN` — vendor mechanism, Rust engine only) |
| **KEM** | `C_EncapsulateKey`, `C_DecapsulateKey` (ML-KEM-512/768/1024; also `CKM_HPKE` — RFC 9180 HPKE, vendor mechanism, Rust engine only) |
| **Encrypt / Decrypt** | `C_EncryptInit` + `C_Encrypt` (one-shot), `C_DecryptInit` + `C_Decrypt` (one-shot); mechanisms: AES-GCM, AES-CBC, AES-KW, RSA-OAEP; multipart `C_EncryptUpdate`/`C_EncryptFinal`, `C_DecryptUpdate`/`C_DecryptFinal` |
| **Sign / Verify** | `C_SignInit` + `C_Sign` (one-shot), `C_VerifyInit` + `C_Verify` (one-shot), `C_SignMessage` (one-shot), `C_VerifyMessage` (one-shot); algorithms: ML-DSA-44/65/87, SLH-DSA (all 12), RSA-PKCS, RSA-PSS, ECDSA P-256/P-384/P-521, Ed25519; multipart `C_SignUpdate`/`C_SignFinal`, `C_VerifyUpdate`/`C_VerifyFinal`; pre-bound `C_VerifySignatureInit`/`C_VerifySignature` (+ multipart `C_VerifySignatureUpdate`/`C_VerifySignatureFinal`); recover `C_SignRecoverInit`/`C_SignRecover`, `C_VerifyRecoverInit`/`C_VerifyRecover` |
| **Message API** | `C_MessageSignInit` + `C_MessageSignFinal` (one-shot envelope, + multipart `C_SignMessageBegin`/`C_SignMessageNext`), `C_MessageVerifyInit` + `C_MessageVerifyFinal` (one-shot envelope, + multipart `C_VerifyMessageBegin`/`C_VerifyMessageNext`), `C_MessageEncryptInit`/`C_EncryptMessage`/`C_MessageEncryptFinal` (+ multipart `C_EncryptMessageBegin`/`C_EncryptMessageNext`), `C_MessageDecryptInit`/`C_DecryptMessage`/`C_MessageDecryptFinal` (+ multipart `C_DecryptMessageBegin`/`C_DecryptMessageNext`) |
| **Digest** | `C_DigestInit`, `C_Digest`, `C_DigestUpdate`, `C_DigestFinal`; SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512, HMAC |
| **Dual-function** | `C_DigestEncryptUpdate`, `C_DecryptDigestUpdate`, `C_SignEncryptUpdate`, `C_DecryptVerifyUpdate` (composed from the single-function ops above) |
| **Key wrap / unwrap** | `C_WrapKey`, `C_UnwrapKey` (AES-KW, AES-GCM wrap, RSA-OAEP wrap), `C_WrapKeyAuthenticated`/`C_UnwrapKeyAuthenticated` (AES-GCM), `C_DeriveKey` (ECDH, HKDF, PBKDF2) |
| **Object mgmt** | `C_CopyObject`, `C_GetObjectSize`, `C_SetAttributeValue` |
| **Random** | `C_GenerateRandom` (browser CSPRNG via `getrandom::js`), `C_SeedRandom` (also corrected 2026-09-01 — was `CKR_FUNCTION_NOT_SUPPORTED` before, per its own code comment) |

**Corrected 2026-09-02**: the table above previously enumerated ~85 of the
engine's real 104 `_C_*` exports (`grep -oE 'js_name = _C_[A-Za-z]+' rust/src/ffi.rs
rust/src/constants.rs | sort -u` — this exact command is the freshness check;
re-run it and diff against the two tables here if this ever drifts again). The
19 gaps found were all either basic info/interface getters or session-lifecycle
functions with no exotic behavior — verified against each one's body, not
assumed from the function name.

### Stubbed — `CKR_FUNCTION_NOT_SUPPORTED`

**Corrected 2026-09-01/02**: every function this table previously listed except the
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
| **v3.2 Async / Cancel** | `C_AsyncComplete`, `C_AsyncGetID`, `C_AsyncJoin` (found 2026-09-02 — genuinely still `CKR_FUNCTION_NOT_SUPPORTED`, unlike the previous round's corrections); `C_CancelFunction` (**corrected 2026-09-04** — returns `CKR_FUNCTION_NOT_PARALLEL`, not `CKR_FUNCTION_NOT_SUPPORTED`, verified against its body in `rust/src/ffi.rs`; arguably spec-correct rather than a stub, since these engines are single-threaded and no function ever runs in parallel to cancel); `C_WaitForSlotEvent` (**corrected 2026-09-04** — returns `CKR_NO_EVENT` when called with `CKF_DONT_BLOCK` set, `CKR_FUNCTION_NOT_SUPPORTED` only for the blocking form) |

---

## Testing & Conformance

*Added 2026-09-04 — this section did not previously exist; a system engineer/operator
verifying a build, or a developer extending the engine, needs to know these exist.
Verified against `rust/README.md` and the harness files it names.*

| Harness | What it checks |
|---|---|
| `cargo test` (from `rust/`) | Engine unit + integration tests |
| `node rust/test_p11_conformance.js` | PKCS#11 v3.2 conformance — exact `CKR_*` codes in spec priority order, PQC keygen/param-set coverage, SP 800-108 KBKDF, message-based crypto. Per `rust/README.md`: 999 checks / 51 sections, 999 passed / 0 failed as of engine commit `7018794a9504` — **treat that pass count as a point-in-time snapshot to re-verify, not a permanently current number**, since it is regenerated by the harness itself |
| `node rust/test_kat_parity.js` | KAT parity vs the C++ engine |
| `node rust/test_r36_paramset.js` | R3.6 parameter-set coverage |

Regenerate the conformance report with `scripts/local-gate.sh --rust-p11` (the harness
writes the report file itself). Full results and procedure:
`rust/RUST_P11_V32_CONFORMANCE_REPORT.md`. The native `CK_*` C-ABI compliance plan
(`rust/CK_ABI_NATIVE_COMPLIANCE_PLAN.md`) is explicitly marked **superseded** by that
same report as of 2026-08-23 — don't cite its own "315/0/0" figure as current; it
predates two remediation waves.

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

HsmSignCombinedPanel (ML-DSA, in `SignVerifyTab.tsx`):
  C++ C_Sign(message) → cpp_signature
  C++ C_GetAttributeValue(pubkey, CKA_VALUE) → cpp_pubkey_bytes
  Rust C_CreateObject(cpp_pubkey_bytes) → rust_pubkey_handle
  Rust C_Verify(rust_pubkey, cpp_signature, message) → CKR_OK
```

Parity success/failure is logged to the unified PKCS#11 call log as
`Dual-Engine Parity / SUCCESS` or `Dual-Engine Parity / FAIL`.

**Code locations** (**corrected 2026-09-04** — this doc previously pointed at a
`pqc-timeline-app` repo that does not exist in this workspace, with line numbers that
had drifted. Re-verified directly against the sibling `pqctoday-hub` repo's
`src/components/Playground/tabs/{KemOpsTab,SignVerifyTab}.tsx`):
- `KemOpsTab.tsx` — `export const HsmKemPanel`. ML-KEM cross-check, gated both
  directions on `engineMode === 'dual' && crossCheckModuleRef.current`: encapsulate
  side ~line 137 (Rust encapsulates with the C++ pubkey → C++ decapsulates),
  decapsulate side ~line 198 (reverse direction — a fresh Rust keypair is generated
  here because ML-KEM private keys are non-extractable, so the encapsulate side's
  Rust keypair can't be reused)
- `SignVerifyTab.tsx` — `export const HsmSignCombinedPanel` (**not** `HsmSignPanel`
  — that name doesn't exist in the current component). ML-DSA cross-check: sign side
  ~line 232 (C++ signs → Rust imports pubkey → Rust verifies), verify side ~line 288
  (same check, entered from the Verify button instead of Sign)
- Guard: `engineMode === 'dual' && crossCheckModuleRef.current !== null`

---

## Loading — Integration in pqctoday-hub

**Corrected 2026-09-04:** this section previously titled itself "Integration in
pqc-timeline-app" — no repo by that name exists in this workspace. Everything below
lives in the sibling `pqctoday-hub` repo (verified directly: every path named here
exists there; `pqc-timeline-app` appears nowhere in that repo except one unrelated
`LICENSES.md` credit; a hub commit titled "Rust WASM migration" is when this
integration landed).

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
`moduleRef` (rust-only mode). **Corrected 2026-09-04:** the previous sentence here —
"`HsmSetupPanel` initializes both modules in dual mode" — describes a component that
does not exist in `pqctoday-hub` today. Both modules are loaded and `C_Initialize`d
directly inside `HsmContext.tsx`'s own `autoInitImpl` callback (`getSoftHSMCppModule()`
+ `getSoftHSMRustModule()` when `engineMode === 'dual'`), not a separate setup-panel
component.

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
| XMSS single-tree (RFC 8391) | ✅ | ✅ | Rust via `xmss` crate; 2026-08-13: SHAKE param ids realigned to the RFC/SP 800-208 registry (0x07-0x09 SHAKE128, 0x11-0x13 SHAKE256 — implemented). **Corrected 2026-09-04 (CHANGELOG 0.28.1)** — the fix below was previously (mis)attached to the XMSS-MT row; it is single-tree (`CKM_XMSS`/`xmss_keygen`/`xmss_sign`/`xmss_verify` in `rust/src/crypto/xmss_bridge.rs`, not the `xmssmt_*` functions): 9 of 18 SP 800-208 XMSS parameter sets were missing or silently broken (SHAKE256/256 Table 14 missing its 10-tree id; SHAKE256/192 Table 16 missing its 16-/20-tree ids and shipping a dispatched-but-nonfunctional 10-tree id; SHA-256/192 Table 12 entirely absent) — root cause was a hardcoded 96-byte keygen seed buffer instead of the per-type `SEED_LEN = 3×n` (n=24 for the `_192` sets needs 72 bytes). All 9 are now fixed and wired into keygen/sign/verify/max-signatures dispatch and the `CKM_XMSS` signature-length estimator |
| XMSS-MT | ✅ | ✅ | Implemented via the `xmss` crate; the "crate lacks multi-tree support" note was stale (corrected 2026-08-13). **Flagged 2026-09-04, unresolved — possible real gap, not in CHANGELOG:** `xmssmt_keygen` in `rust/src/crypto/xmss_bridge.rs` still hardcodes the same `let mut seed = [0u8; 96];` pattern that 0.28.1 fixed for single-tree XMSS, for all 16 of its `_192` (n=24) dispatch arms (`XmssMtSha2_*_192`, `XmssMtShake256_*_192`). A quick read of the `xmss` crate's own `xmssmt_core_seed_keypair` (which the shared `KeyPair::from_seed` call reaches for both single- and multi-tree) shows it only consumes the seed's first `3×n` bytes and ignores any excess, which would make the oversized 96-byte buffer harmless for keygen specifically — but this doc has not run the test harnesses to confirm MT `_192` sign/verify are unaffected, and the mechanism that made single-tree `_192` "dispatched but non-functional" per CHANGELOG 0.28.1 isn't fully explained by seed truncation alone. Re-check before relying on XMSS-MT `_192` in production; not asserting either a defect or a clean bill of health here |
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
| Ed448 / X448 | ✅ | ✅ | Ed448 pure + pre-hash sign/verify, X448 key agreement (`CKM_X448`, vendor `0x8000_1059`) — real Rust-engine support added per CHANGELOG (previously the one documented gap against C++) |
| ChaCha20 / ChaCha20-Poly1305 | ✅ | ✅ | `CKM_CHACHA20` stream cipher + `CKM_CHACHA20_POLY1305` AEAD |
| AES-XTS | ✅ | ✅ | `CKM_AES_XTS`, multi-part path fixed per CHANGELOG 0.28.0 |
| AES-CMAC | ✅ | ✅ | `CKM_AES_CMAC` — sign/verify and SP 800-108 KBKDF PRF |
| RIPEMD-160 | ✅ | ✅ | Digest + HMAC |
| SHA-1 (`CKA_CHECK_VALUE` only) | ✅ | ✅ | Not exposed as a general digest mechanism in either engine — used only to compute the 3-byte key check value (§6.8.2) |
| BIP32 master/child key derivation (vendor, `CKM_BIP32_MASTER_DERIVE`/`_CHILD_DERIVE`) | ❌ | ✅ | Rust engine only; secp256k1 via `k256`, `C_DeriveKey`. Not a PKCS#11 v3.2 mechanism |
| Keccak-256 digest (vendor, `CKM_KECCAK_256`) | ❌ | ✅ | Rust engine only; Ethereum-style address derivation. Not a PKCS#11 v3.2 mechanism |
| FrodoKEM (vendor, BSI TR-02102-1) | ❌ | ✅ | Rust engine only; all 6 parameter sets (640/976/1344 × AES/SHAKE) via `CKM_PQCTODAY_FRODOKEM_KEY_PAIR_GEN`/`_ENCAPSULATE`. Not a PKCS#11 v3.2 or NIST-standardized mechanism |
| Classic McEliece (vendor, BSI-recommended) | ❌ | ✅ | Rust engine only; Category-5 `mceliece6688128` parameter set only, via `CKM_PQCTODAY_CLASSIC_MCELIECE_KEY_PAIR_GEN`/`_ENCAPSULATE`. Not a PKCS#11 v3.2 or NIST-standardized mechanism |
| Split Key Sharing (vendor, `CKM_PQCTODAY_SPLIT_KEY`) | ❌ | ✅ | Rust engine only; Polynomial GF(256) secret sharing per KMIP 3.0 §13.1 — PKCS#11 v3.2 has no secret-sharing mechanism to build on |

The last six rows above are Rust-engine-only vendor mechanisms — none are part of the
core Algorithm Parity comparison against C++ in the strict sense (there is nothing in
C++ to have parity with); listed here because this table is the closest thing to a
complete algorithm inventory for the Rust engine and previous versions of this doc
omitted them entirely.

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

**2026-09-04 — stateful-key hardening (not a limitation, a fixed security gap worth
knowing about if you're on an older build):** `CKA_COPYABLE` was never forced `FALSE`
for HSS/XMSS/XMSS-MT private keys, and a caller's own `C_GenerateKeyPair`/
`C_CreateObject` template could silently override the engine's `CKA_SENSITIVE`/
`CKA_EXTRACTABLE` defaults for these key types with no rejection — since these keys
hold hash-based one-time-signature state, a copyable or extractable private key lets
the same OTS leaf sign twice, a real forgery hazard. Fixed (CHANGELOG 0.28.2):
`CKA_SENSITIVE`/`CKA_EXTRACTABLE`/`CKA_COPYABLE` are now enforced at every creation
path for these three key types — a template may restate the mandated values but never
override them (`CKR_ATTRIBUTE_VALUE_INVALID` otherwise), verified against
`rust/src/state.rs`. The same release also aligned the Rust engine's HSS default
LMOTS one-time-signature parameter (`W4`, when a caller omits an explicit
`CK_HSS_KEY_PAIR_GEN_PARAMS`) — the C++ engine previously defaulted to `W8`; C++ was
changed to match Rust, since neither PKCS#11 v3.2 nor RFC 8554 mandates a default.
