> **SUPERSEDED (2026-08-23).** This is a historical plan document from
> 2026-06-15, kept for context. Its "315/0/0, identical to C++" figure
> predates two full remediation waves (2026-08-13 security/wrong-result/
> encoding/capability fixes) and the suite has since grown 15 report
> categories. **Do not cite this file's numbers as current** — the live
> report is `rust/RUST_P11_V32_CONFORMANCE_REPORT.md`.

# softhsmrustv3 — native PKCS#11 v3.2 C-ABI compliance plan (166 → 315)

**Branch:** `feat/cabi-native-64bit` (isolated; `main`/validated engine untouched).
**Target:** `p11_v32_compliance_test -c all` → **315 / 0 / 0** on native, with the
1452 KMIP interop + KAT replay staying **15/15 green** as the merge gate.

## FINAL STATUS — 315 PASS / 0 FAIL / 0 SKIP (was 28 PASS) — IDENTICAL to the C++ engine

`p11_v32_compliance_test -c all` is **315/0/0 for both** the Rust
(`libsofthsmrustv3.dylib`) and C++ (`libsofthsmv3.dylib`) engines, and the two
reports are **byte-for-byte identical per test** (diff of the 315 result lines is
empty). `cargo test --lib` is green again (201/0). All `CK*` constant values
added in this work were verified against `src/lib/pkcs11/pkcs11t.h` (the spec
source of truth), not guessed.

All width-fix and feature groups landed, each gated (interop 8+2+5 = 15/15, no
crash) and committed on `feat/cabi-native-64bit`:

| Commit | What | PASS |
|---|---|---|
| (earlier) | templates u32→usize | 28→139 |
| (earlier) | mech params, crash fixed | 139→166 |
| `3683125` | Group A — nested param structs | 166→169 |
| `000e5f5` | Group C — keytype/SPKI/UUID | 169→177 |
| `376d131` | Group D.1 — async-reject + CKA_ID find (store_ulong width) | 177→182 |
| `c68ecb0` | Group D.2 — SHA3-384-RSA + RSA-PSS param width | 182→190 |
| `77a852c` | Group D.3 — dual-function ops | 190→204 |
| `f59407f` | Group D.4 — ML-DSA/SLH-DSA/EdDSA multipart | 204→220 |
| `3afebbc` | Group B — X25519/X448 ECDH derive | 220→226 |
| `8cce381` | GCM IV + SP800-108 (CMAC PRF) + generic-secret KCV (SHA-1) | 226→235 |
| `3ca83b9` | AES-CBC key wrap + ChaCha20 keygen | 235→239 |
| `8d7d6a4` | RIPEMD-160 digest + HMAC | 239→244 |
| `9c3be35` | export v3.2 fns + auth-wrap width + GSVF | 244→291 |
| `7c3b010` | V4 keytype check for HSS/XMSS/XMSSMT | 291→294 |
| `367ce64` | HSS keygen defaults + XMSS^MT keygen/sign/verify (**0 FAIL**) | 294→301 |
| `d6d038c` | RSA-1024 + raw CKM_RSA_PKCS sign/verify + private-component sensitivity | 301→305 |
| `924b6ee` | v3.0 message-based API (C_MessageSign/Encrypt) + GCM-msg guard removed | 305→314 |
| `c8eedb3` | native-width lib-test scaffolding (cargo test --lib green, test-only) | 314 |

### 0 FAIL — stateful HBS (HSS/LMS + XMSS^MT) now fully wired
The native crypto already existed (`crypto::lms`, `crypto::xmss_bridge`); the
C ABI just needed: HSS keygen defaulting to a single-level LMS when no params
are supplied; CKM_XMSSMT_KEY_PAIR_GEN keygen + sign/verify dispatch; and a
workaround for an `xmss` 0.1.0-pre.0 round-trip bug (the serialized MT key's
RFC OID collides with the single-tree namespace, so the OID prefix is rewritten
to the crate's internal XMSSMT repr at keygen). HSS sign decrements
CKA_HSS_KEYS_REMAINING; XMSS^MT sign/verify round-trips byte-exact.

### 0 SKIP — full parity with the C++ engine
The last divergence was `C_LoginUser` with a username: the C++ engine ignores
the advisory `pUsername` (no distinct-named-user concept) and logs in, while
Rust hard-rejected it with CKR_FUNCTION_NOT_SUPPORTED (→ test SKIP). Rust now
ignores the username and delegates to C_Login (commit after `c8eedb3`), so the
two engines produce **byte-for-byte identical** per-test results: 315/0/0.

**Merge note:** nothing is merged to `main`. The user runs their full validation
before merge. The `rust/` tree in the validated checkout stayed at 0 changes.

---

## Original plan (history)
**State:** `f5fe09a` (templates, 28→139) + `52040fc` (mech params, 139→166, crash fixed).

## Method (unchanged — proven)
- **Width fix pattern:** marshaled blobs/structs are 32-bit (WASM) shaped; widen
  reads to `usize` (== u32 on wasm32, u64 on native). For nested C structs, read
  fields at `size_of::<usize>()`-based offsets so the same code is correct on both.
- **Gate after every group:** `cargo test -p pqctoday-kmip --test kat_replay
  --test interop_kat --test pqc_interop_engine` must stay 15/15 (pre-build first to
  avoid the concurrent-compile flake), `-c all` must not crash, PASS must climb.
- **Crash debugging:** ASAN is unusable here (rejection-sampling keygen goes
  runaway under it). Use `lldb --batch -o run -k 'register read x1 x3 lr' -k 'bt'`
  — the on-crash hook unwinds via the link register where the plain segfault can't.
- **Blueprint:** the C++ engine's round-4/5 remediation (`docs/compliance-audit-cpp-pkcs11-v3.2-2026-06-12.md`)
  is the conformance checklist; port each behavior.

## The remaining 60 FAIL, grouped (current `-c all`)

### Group A — remaining nested param structs (same width fix; LOW risk, crash-free now) — ~8 tests
The corruptor class is fixed; these are the leftover 32-bit reads, each now a clean
fail not a crash:
- **ChaCha20** `C_EncryptInit` RV=113 + keytype (`ffi.rs:4111,4534` nonce ptr truncation; `G2ChaCha20` keygen). 
- **GCM** valid-IV `EncryptInit` RV=113 + message params (`ffi.rs:7687-7691` pIv/ulIvLen/pTag at WASM offsets; `8153,8314` offset-16 truncations).
- **PBKDF2** salt (`ffi.rs:5716` `*p_param.add(n) as *const u8` truncation) → `KDF`/`KCV` RV=7.
- **SP800-108** counter/DKM nested format (`ffi.rs:5126,5145` `val_ptr.add(4/8)` → `size_of::<usize>()` offsets) + the COUNTER/FEEDBACK callers; **AES-CMAC PRF** path RV=113 → `KDF`/`KCV`.
**Fix:** read each struct as `*const usize` / `size_of::<usize>()` offsets (as done for HKDF). **Effort: M.**

### Group B — missing native primitives (net-new crypto) — ~7 tests
WASM is parked, so any native crate is fine:
- **X25519 / X448 derive** (`ECDH` Derive_X25519/_Cofactor RV=7, `G2Derive` RV=112, `G2MechTable` advertised) — wire `x25519-dalek`/`x448` into `C_DeriveKey` (the crate deps are already present: `libx25519_dalek`, `libx448`, `libed448_goldilocks`).
- **EdDSA multipart** (`MultiPart_EdDSA` C_SignUpdate RV=145) — streaming wrapper over the existing Ed25519/Ed448 (pure keygen/sign already pass).
**Fix:** add `native::derive_x25519/x448`, dispatch in `C_DeriveKey`. **Effort: M–L.**

### Group C — keygen template validation + attribute exposure — ~16 tests
- **G3Keygen V4** (9): wrong `CKA_KEY_TYPE` in a keygen template must return
  `CKR_TEMPLATE_INCONSISTENT` (currently RV=0 accepts, or RV=112/113). Add a
  keytype-vs-mechanism consistency check in each `C_GenerateKey(Pair)` arm. (C++ V-4.)
- **Attributes** SPKI-on-private (5): `CKA_PUBLIC_KEY_INFO` must be exposed on
  **private** ML-DSA/ML-KEM/SLH-DSA objects too — compute the SPKI and store it on
  the private attribute map (currently only the public half gets it).
- **G5Attrs** (2): `CKA_UNIQUE_ID` must remain **readable** on sensitive/private
  keys (it's an identifier, not secret material) — exclude it from the
  sensitive-readback block in `C_GetAttributeValue`.
**Fix:** keygen-template validation + 2 attribute-exposure tweaks. **Effort: M.** (highest test/effort ratio)

### Group D — dual-function, multipart, async, SHA3-RSA, PSS — ~18 tests
- **G8Dual** (10): implement the 4 combined ops `C_DigestEncryptUpdate`,
  `C_DecryptDigestUpdate`, `C_SignEncryptUpdate`, `C_DecryptVerifyUpdate`
  (currently RV=84 NOT_SUPPORTED). (C++ R5-2.)
- **G7Sha3Rsa** (5): `CKM_SHA3_384_RSA_PKCS{,_PSS}` sign/verify + the RSA-PSS
  hashAlg validation (RV=112). (C++ R5-1.)
- **MultiPart** ML-DSA (1) C_SignUpdate RV=145 — wire ML-DSA multipart streaming.
- **GAsync** (1): reject `CKF_ASYNC_SESSION` with `CKR_SESSION_ASYNC_NOT_SUPPORTED`(0x205). (C++ R5-3.)
- **CkaIdRetrieval** (4) + default-CKA_PRIVATE-on-pubkey: fix `C_FindObjects`
  CKA_ID+CKA_CLASS filtering + the public-key default `CKA_PRIVATE=false`.
**Effort: M–L.**

### Group E — Historical / stateful (decide scope) — ~11 tests
- **RIPEMD-160** (`G-DA-X` 2, `G2MechTable` 2): Historical. C++ left it WASM-off by
  design; native can legacy-gate it. **Recommend: out-of-scope** unless required (no PQC need).
- **HSS/XMSS** (`G3Keygen` some, `Attributes` CKA_HSS_KEYS_REMAINING, `G1Security` HSS): stateful HBS — complex, separate effort.
- **KMAC** (`KMAC` SignInit RV=144, 1): implement or defer.
**Effort: variable; some intentionally deferred (document in the report, like C++).**

## Sequencing
1. **Group A** (nested params) — fastest, lowest risk, same proven fix → ~174.
2. **Group C** (keygen validation + attrs) — best ratio, no new crypto → ~190.
3. **Group D** (dual/multipart/async/SHA3-RSA/find) — port C++ behaviors → ~208.
4. **Group B** (X25519/X448 + EdDSA multipart) — net-new crypto → ~215.
5. **Group E** — decide RIPEMD/HSS/KMAC scope; document intentional deferrals; close to 315 minus documented exclusions.

Gate after each group. Each lands as its own commit on `feat/cabi-native-64bit`.
Nothing merges to `main` until the user runs their full validation and it's green.

## Effort
A: M · C: M · D: M–L · B: M–L · E: variable. Front-loaded: A+C alone (~24 tests,
low risk) take 166 → ~190 with no new crypto and the proven width fix.
