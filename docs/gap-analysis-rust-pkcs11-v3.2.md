# PKCS#11 v3.2 Compliance Gap Analysis — softhsmrustv3 (Rust/WASM engine)

> **Remediation status (2026-06-10).** Phases **R1 (complete)**, **R2 (complete
> except H-4)**, the high-value subset of **R3**, and **R6.1** are implemented on
> branch `feat/kmip-conformance-round-2`. The crate builds clean on
> `wasm32-unknown-unknown` and the full `rust/test_kat_parity.js` suite (XMSS
> stateful sign, ChaCha20-Poly1305, X25519/X448, SP800-108) passes. See the
> **Remediation Status** ledger at the bottom for per-item detail and what remains.
>
> Build note: `cargo`/`rustc` must come from the rustup toolchain, not Homebrew —
> Homebrew's rustc lacks the wasm32 sysroot. Use
> `RUSTC=~/.rustup/toolchains/stable-aarch64-apple-darwin/bin/rustc` plus the
> matching toolchain `cargo`/`wasm-pack`.

**Date:** 2026-06-10 (v1)
**Scope:** `rust/src/` (`softhsmrustv3` v0.5.0) — constants, FFI surface (`ffi.rs`), crypto
mechanisms (`crypto/`, `native/`), session/object/attribute model (`state.rs`, `native/`).
**Source of truth:** OASIS PKCS#11 v3.2 specification (CSD01,
`docs/refs/pkcs11-spec-v3.2-csd01.pdf`) and its normative header
`src/lib/pkcs11/pkcs11t.h` / `pkcs11f.h`. Where any other artifact (vendor manifest,
constants.js, C++ code) disagrees, the OASIS spec wins.
**Out of scope (by request):** multipart *encryption* paths — `C_EncryptUpdate` /
`C_EncryptFinal` / `C_DecryptUpdate` / `C_DecryptFinal`, `rust/src/crypto/multipart.rs`,
and the message-based streaming encrypt/decrypt (`C_EncryptMessageBegin/Next`,
`C_DecryptMessageBegin/Next`) — currently under active rework. Findings touching only
those paths are listed in Appendix B for hand-off to that effort, not in the remediation plan.

Line numbers refer to the working tree at audit time (branch
`feat/kmip-conformance-round-2`, base 573a2b0 + uncommitted changes).

---

## Executive Summary

| Severity | Count | Themes |
|---|---|---|
| CRITICAL | 5 | Access-control bypass, missing init gate, 3 wrong mechanism IDs, GCM zero-IV fallback, AAD discarded in authenticated wrap |
| HIGH | 18 | Session-handle validation, two-call convention violations, stateful-key leaf burn, missing mandatory entry points, template/attribute enforcement, PQC mechanism parameter gaps |
| MEDIUM | ~25 | Return-code precision, key-provenance attributes, KDF format fields, token-info accuracy |
| LOW | ~12 | Naming drift, stubs vs. absent functions, minor inconsistencies |

Positives confirmed against the spec: the PQC constant surface (CKK/CKM/CKA/CKP for
ML-KEM, ML-DSA, SLH-DSA, HSS, XMSS) is value-exact (206/300 constants match `pkcs11t.h`
exactly); ML-KEM encapsulate/decapsulate output-key attributes follow §5.18.8/9 including
FIPS 203 implicit rejection; ECDSA emits raw `r‖s` per §6.3.12; key generation uses
`OsRng`/`getrandom` (CSPRNG) throughout; per-op usage checks (CKA_SIGN/VERIFY/ENCRYPT/
DECRYPT/DERIVE/WRAP/UNWRAP) are in place; lock poisoning is handled safely across FFI.

---

## 1. CRITICAL

### C-1. Login state never gates object access (spec §4.4, §5.6)
`login_state` is consulted only by C_Login/C_Logout/C_GetSessionInfo/C_InitPIN/
C_OpenSession. Objects with `CKA_PRIVATE=TRUE` are findable (`ffi.rs:3254-3264`),
readable (`ffi.rs:1851`), usable, and destroyable from a public (not-logged-in) session,
even though C_GetTokenInfo advertises `CKF_LOGIN_REQUIRED`. C_Logout does not revoke
private-object handles. **Impact:** the Public/User/SO access model is fully bypassed.

### C-2. No initialization gate — CKR_CRYPTOKI_NOT_INITIALIZED unreachable (§5.4, §5.6)
There is no initialized flag anywhere in `rust/src/`. Every function succeeds before
C_Initialize and after C_Finalize; double C_Initialize returns CKR_OK instead of
`CKR_CRYPTOKI_ALREADY_INITIALIZED` (`ffi.rs:53-76`). C_Finalize ignores `pReserved`
(must be NULL → else `CKR_ARGUMENTS_BAD`, `ffi.rs:79`). C_Initialize dereferences
`pReserved` as a vendor ACVP-seed struct with no bounds validation (`ffi.rs:55-71`)
where the spec mandates `CKR_ARGUMENTS_BAD` for non-NULL `pReserved`.

### C-3. Three mechanism constants have wrong spec values (`constants.rs`)
| Constant | Rust value | OASIS v3.2 value | Collision |
|---|---|---|---|
| `CKM_CHACHA20` (`constants.rs:241`) | `0x1071` | `0x1226` | `0x1071` = CKM_AES_XTS |
| `CKM_CHACHA20_POLY1305` (`constants.rs:244`) | `0x1093` | `0x4021` | `0x1093` = CKM_TWOFISH_CBC |
| `CKM_AES_KEY_WRAP_KWP` (`constants.rs:234`) | `0x210A` | `0x210B` | `0x210A` = CKM_AES_KEY_WRAP_PAD |

A conformant client requesting AES-XTS gets ChaCha20; requesting spec ChaCha20 gets
CKR_MECHANISM_INVALID. Worse, `ffi.rs:2665/2824` match the *correct* raw literal
`0x4021` for ChaCha20-Poly1305 on some paths — the same mechanism has two IDs depending
on API path. Dispatch sites: `native/encrypt.rs:195-371`, `ffi.rs:507,3977,4127`.

### C-4. AES-GCM substitutes an all-zero 12-byte IV when pIv is NULL/empty (§6.27.7, SP 800-38D §8)
`ffi.rs:2628, 2949, 4392, 4504` (C_EncryptInit, C_DecryptInit, C_WrapKeyAuthenticated,
C_UnwrapKeyAuthenticated): `else { vec![0u8; 12] }`. A fixed zero nonce across
encryptions under the same key is catastrophic nonce reuse (keystream + GHASH-key
recovery). Spec requires `CKR_MECHANISM_PARAM_INVALID`.

### C-5. C_WrapKeyAuthenticated / C_UnwrapKeyAuthenticated discard associated data (§5.18.6/7)
`ffi.rs:4361-4395, 4474-4540`: `_p_associated_data` is never fed to the AEAD; the GCM
tag does not bind the caller's AAD. Authenticated wrap provides no integrity over the
associated data.

---

## 2. HIGH

### API surface & entry points
- **H-1. Missing mandatory entry points (§5.4/§5.5):** `C_GetFunctionList`,
  `C_GetInterfaceList`, `C_GetInterface` absent. Tolerable only for the wasm-bindgen JS
  shim; blocks any native/conformant embedding and 3.0/3.2 interface negotiation.
- **H-2. `C_CloseAllSessions` missing** (needed by InitToken flows) and
  **`C_SessionCancel` missing** — with CKR_OPERATION_ACTIVE guards now present on
  Encrypt/DecryptInit there is no spec way to abandon an active operation short of
  closing the session.
- **H-3. Message-based sign/verify surface inconsistent:** `C_SignMessageBegin/Next`,
  `C_VerifyMessageBegin/Next` missing while Init/Final halves exist (`ffi.rs:2368-2444`).
  `C_MessageSignFinal` has a 5-arg shape vs. the 1-arg `pkcs11f.h` declaration and
  returns CKR_OK with no active operation.

### Two-call buffer convention (§5.2) — operation must survive CKR_BUFFER_TOO_SMALL
- **H-4. C_Encrypt / C_Decrypt (single-shot):** state is removed at entry
  (`ffi.rs:2722, 3017`); the NULL-buffer length-query path re-inserts it but the
  CKR_BUFFER_TOO_SMALL path does not (`ffi.rs:2894-2897, 3159-3162`) — retry gets
  CKR_OPERATION_NOT_INITIALIZED.
- **H-5. Stateful-signature leaf burned before buffer validation:** in the HSS/XMSS
  C_Sign path the leaf index is advanced and HSS_KEYS_REMAINING decremented
  (`ffi.rs:2120-2160`) *before* the output buffer check; CKR_BUFFER_TOO_SMALL
  (`ffi.rs:2163-2168`) terminates the op and irreversibly burns a one-time leaf without
  returning a signature. Must validate buffer first (also a §5.2 violation).
- **H-6. C_DigestFinal / C_Digest:** digest context consumed before the buffer check
  (`ffi.rs:3247-3268`); BUFFER_TOO_SMALL kills the operation.

### Session & object enforcement
- **H-7. Session handles never validated** on ~12 functions (C_GenerateKey(Pair),
  C_CreateObject, C_GetAttributeValue, C_DestroyObject, C_DeriveKey, C_Wrap/UnwrapKey,
  C_Encapsulate/DecapsulateKey, C_FindObjectsInit, C_GenerateRandom) — a closed/bogus
  handle returns CKR_OK; `CKR_SESSION_HANDLE_INVALID` unreachable there. Crypto-op
  functions check operation state *before* session validity (wrong error priority, §5.12).
- **H-8. R/O sessions are not write-protected:** `rw_session` (`state.rs:77-80`) only
  gates SO-login/InitPIN; RO sessions can create/generate/destroy objects.
  `CKR_SESSION_READ_ONLY` never returned. `CKF_SERIAL_SESSION` not enforced on
  C_OpenSession (must return `CKR_SESSION_PARALLEL_NOT_SUPPORTED`).
- **H-9. C_CreateObject performs zero template validation** (`ffi.rs:1905-1969`):
  CKR_TEMPLATE_INCOMPLETE / ATTRIBUTE_VALUE_INVALID / TEMPLATE_INCONSISTENT unreachable.
  An object created without CKA_CLASS defaults to CKO_PUBLIC_KEY in the sensitivity
  gate (`ffi.rs:1860`) — a secret key imported without CKA_CLASS has CKA_VALUE readable
  even with CKA_SENSITIVE=TRUE.
- **H-10. Read-only attributes overridable via template:** `absorb_template_attrs`
  (`handlers.rs:100-118`) accepts CKA_LOCAL, CKA_KEY_GEN_MECHANISM, CKA_CLASS,
  CKA_KEY_TYPE, CKA_PARAMETER_SET, and CKA_TRUSTED (no SO check, §4.9/4.10) on all
  generate/derive/encapsulate paths.
- **H-11. CKR_ATTRIBUTE_SENSITIVE never returned (§5.7.5):** C_GetAttributeValue masks
  sensitive CKA_VALUE with CK_UNAVAILABLE_INFORMATION but returns CKR_OK
  (`ffi.rs:1872-1875`); clients cannot distinguish protected from absent. Also returns
  immediately on first too-small attribute instead of completing the template pass.
- **H-12. Native-API sensitivity bypass:** `native::object::get_attribute`
  (`object.rs:96-118`) ignores CKA_EXTRACTABLE=FALSE, and `state::get_object_value` /
  `get_object_attr_bytes` (`state.rs:204-210, 295-301`) are `pub` with no gate —
  violates the documented native/FFI parity contract for the security-relevant path.
- **H-13. ALWAYS_SENSITIVE / NEVER_EXTRACTABLE falsified for imported keys (§4.9/4.10):**
  `finalize_private_key_attrs` runs on C_CreateObject and import paths
  (`ffi.rs:1961-1963`, `keygen.rs:482,542`), so imported keys can report
  CKA_ALWAYS_SENSITIVE=TRUE / CKA_NEVER_EXTRACTABLE=TRUE. C_UnwrapKey omits both
  attributes entirely (`ffi.rs:4243-4260`; spec requires explicit CK_FALSE).
- **H-14. C_Encapsulate/DecapsulateKey perform no usage check (§5.18):**
  CKA_ENCAPSULATE/CKA_DECAPSULATE are stored at keygen but never consumed
  (`ffi.rs:1675-1845`). Also: objects with no parameter set silently default to
  ML-KEM-768 (`ffi.rs:1699,1755,1789,1840`) regardless of CKA_KEY_TYPE.

### Token/slot info
- **H-15. C_GetTokenInfo flags hardcoded to `0x0004040D`** (`ffi.rs:459`) — includes
  **CKF_USER_PIN_LOCKED (0x40000)**; conformant clients will refuse login. Static
  regardless of token state; ignores slot_id; label hardcoded.
- **H-16. GetMechanismList / GetMechanismInfo inconsistent:** ~10 advertised mechanisms
  (CKM_ECDSA, CKM_HASH_ML_DSA, CKM_HASH_SLH_DSA, CKM_EDDSA_PH, CKM_HSS*, CKM_XMSS*,
  CKM_KECCAK_256) have no GetMechanismInfo arm → CKR_MECHANISM_INVALID
  (`constants.rs:300-392` vs `ffi.rs:479-543`). `CKM_EDDSA_PH` is exported as
  `0xFFFF1057` while the repo's normative header defines `0x80001057`.

### Mechanism parameters (single-shot paths)
- **H-17. ML-DSA ignores context string and hedge variant (§6.67, FIPS 204 §5.2):**
  `sign_ml_dsa` (`handlers.rs:488-547`) hard-codes empty context;
  CK_SIGN_ADDITIONAL_CONTEXT is parsed only for CKM_SLH_DSA (`ffi.rs:2030-2034`);
  CKH_HEDGE_* never honored. A caller-supplied context yields a signature that fails
  against conformant verifiers. Related (M): context >255 bytes is silently dropped to
  empty (`ffi.rs:2058-2062`) instead of CKR_MECHANISM_PARAM_INVALID.
- **H-18. RSA-PSS parameters not honored (§6.4.5):** CK_RSA_PKCS_PSS_PARAMS
  (hashAlg/mgf/sLen) never parsed; verify trial-guesses two salt lengths
  (`handlers.rs:1255-1278`); hash hard-wired SHA-256. — Also:
  **GCM ulTagBits ignored in single-shot** (always 128-bit tag, no {32,64,96..128}
  validation; `ffi.rs:2621/2942, 2724-2743, 2983-3001`); **CK_AES_CTR_PARAMS
  ulCounterBits ignored** (always full-128-bit wrap; must wrap within ulCounterBits and
  reject 0/>128; `ffi.rs:2650-2655, 2970-2975`); **ECDSA SHA-3 pre-hash arms don't
  truncate digests to curve size** (FIPS 186-5 §6.4; `handlers.rs:799-829, 1351-1383`
  — SHA-512 arms do it correctly).

---

## 3. MEDIUM

1. **Return-code precision:** uninitialized-token login → CKR_OPERATION_NOT_INITIALIZED
   (`ffi.rs:284`); InitPIN RO session → CKR_SESSION_READ_ONLY_EXISTS instead of
   CKR_SESSION_READ_ONLY (`ffi.rs:378`); nonexistent key handle →
   CKR_KEY_FUNCTION_NOT_PERMITTED instead of CKR_KEY_HANDLE_INVALID (`ffi.rs:2009-2017`
   and peers); bad object handle → CKR_ARGUMENTS_BAD instead of
   CKR_OBJECT_HANDLE_INVALID (`ffi.rs:1900`); wrong-length signature →
   CKR_SIGNATURE_INVALID instead of CKR_SIGNATURE_LEN_RANGE (`handlers.rs:211,1252,1296`);
   bad mechanism params mostly CKR_ARGUMENTS_BAD instead of CKR_MECHANISM_PARAM_INVALID.
2. **Operation-state inconsistencies:** C_SignInit/VerifyInit/DigestInit/FindObjectsInit
   silently overwrite active ops (no CKR_OPERATION_ACTIVE; `ffi.rs:2035-2038, 3265-3273`);
   C_FindObjectsFinal without init returns CKR_OK; C_Digest after C_DigestUpdate silently
   appends instead of failing.
3. **State/zeroization leaks:** C_CloseSession/C_Finalize clear neither
   VERIFY_SIG_STATE nor MESSAGE_ENCRYPT/DECRYPT_STATE; `MsgAeadCtx.key` (`state.rs:126`)
   holds raw key bytes that survive C_Finalize un-zeroized (violates the engine's own
   zeroization rule and §5.6 close-terminates-ops).
4. **Session objects never destroyed at session close** (§4.4); objects not scoped to
   slot/token (single global map, `state.rs:35`); CKA_TOKEN=TRUE silently volatile
   (neither CKR_TOKEN_WRITE_PROTECTED nor CKF_WRITE_PROTECTED) — data-loss trap.
5. **C_SetAttributeValue/C_CopyObject/C_GetObjectSize are stubs** (legal), but
   `state::set_object_attr_bytes` (`state.rs:328-338`) lets the KMIP layer overwrite any
   attribute — CKA_SENSITIVE TRUE→FALSE and CKA_EXTRACTABLE FALSE→TRUE one-way rules
   violable through the crate API.
6. **PQC keygen:** CKA_PARAMETER_SET not required (silent defaults ML-KEM-768 /
   ML-DSA-65 / SLH-DSA-SHA2-128F; spec: CKR_TEMPLATE_INCOMPLETE; `ffi.rs:575-580,
   675-680, 806-811`); template CKA_SEED ignored by keygen yet absorbed and readable
   back (not in sensitivity gate); CKA_SEED (0x637) constant not even defined.
7. **Derived keys marked CKA_LOCAL=TRUE + KEY_GEN_MECHANISM=<derive mech>**
   (`ffi.rs:3949-3950`); spec table 13: LOCAL=FALSE, KEY_GEN_MECHANISM=
   CK_UNAVAILABLE_INFORMATION. (Encap/decap paths are correct.)
8. **CKA_WRAP_WITH_TRUSTED / CKA_ALWAYS_AUTHENTICATE stored but never enforced.**
9. **RSA-OAEP via C ABI reads only hashAlg** — mgf and pSource/label dropped
   (`ffi.rs:2660-2662, 2933-2939, 4089-4093, 4225-4229`); typed native path supports
   them. OAEP decrypt failure leaks CKR_FUNCTION_FAILED vs CKR_ENCRYPTED_DATA_INVALID
   inconsistently (mild padding-oracle surface).
10. **SP800-108 KDF ignores CK_SP800_108_COUNTER_FORMAT width and DKM_LENGTH_FORMAT**
    (hard-wired 32-bit BE counter; `ffi.rs:3825-3930`) — derived keys diverge from
    conformant peers for non-default formats.
11. **HMAC `_GENERAL` mechanisms and KMAC customization string / variable output
    unimplemented** (`handlers.rs:658-714, 948-950`).
12. **GCM IV restricted to exactly 12 bytes** with CKR_ARGUMENTS_BAD; ulIvBits never
    read. Acceptable as a documented restriction only if mechanism info says so, and
    the error should be CKR_MECHANISM_PARAM_INVALID.
13. **Unchecked raw-pointer dereferences across older FFI paths** (`p_data`,
    `pul_*_len`, `ph_object`, templates — e.g. `ffi.rs:570, 1966, 2085, 2096, 3365-3368,
    1875`); newer code null-checks. In WASM this reads/writes memory[0] instead of
    faulting. `static mut KAT_SEED` write (`ffi.rs:5790-5800`) is UB under future
    threading.
14. **ACVP deterministic-RNG hook** armed via C_Initialize pReserved with no
    release-build guard (`ffi.rs:27-70`) — compile out or feature-gate.
15. **Vendor constants squatting spec space:** `CKM_AES_KEY_WRAP_PAD_LEGACY=0x108B`
    collides with CKM_AES_CMAC_GENERAL; `CKM_EC_MONTGOMERY_KEY_DERIVE=0x1058` sits in
    unassigned spec-reserved range. Both must move to ≥0x80000000.
16. **C_OpenSession succeeds on uninitialized token** (CKR_TOKEN_NOT_RECOGNIZED expected).

## 4. LOW

- C_WaitForSlotEvent / C_GetFunctionStatus / C_CancelFunction / recover ops /
  dual-function digest ops absent rather than stubbed with the spec-mandated codes.
- No CKR_SLOT_ID_INVALID anywhere (slot args ignored).
- `CKM_UNAVAILABLE_INFORMATION` / `CKP_PBKDF2_HMAC_SHA*` naming drift (values correct).
- CKF_MESSAGE_* flags absent from mechanism info despite message-based ops implemented.
- FindObjects zero-length attribute values skipped instead of matched-as-empty;
  `allocate_handle` exhaustion returns handle 0 with CKR_OK.
- AES-192 accepted by native keygen, rejected by C_GenerateKey, advertised by
  GetMechanismInfo — three-way disagreement.
- CKA_CHECK_VALUE computed for public/private keys (spec defines KCV for secret keys).
- `C_VerifySignatureFinal` fabricates a dangling `4 as *mut u8` pointer for the
  empty-message case (UB-adjacent).
- 74 `CKP_LMS_*/LMOTS_*/XMSS_*` values match IANA registries (correct; CKP_ prefix is a
  local invention — document it).

---

## Appendix A — Verified-conformant highlights

- PQC constants value-exact vs `pkcs11t.h`: CKK 0x46–0x4b; CKM_ML_KEM(_KEY_PAIR_GEN),
  CKM_ML_DSA(_KEY_PAIR_GEN), all 10+10 CKM_HASH_ML_DSA_*/CKM_HASH_SLH_DSA_* variants;
  CKA_PARAMETER_SET 0x61d, CKA_ENCAPSULATE/DECAPSULATE 0x633/0x634; all CKP_ML_*,
  CKP_SLH_DSA_*; CKR_KEY_EXHAUSTED 0x203; CKM_HSS/XMSS 0x4032–0x4037.
- ML-KEM: ciphertext lengths 768/1088/1568, ss=32, implicit rejection per FIPS 203,
  §5.18.8/9 output-key attributes (LOCAL/ALWAYS_SENSITIVE/NEVER_EXTRACTABLE=FALSE).
- ECDSA raw r‖s; EC point validation on ECDH (`from_sec1_bytes`); X448 low-order
  rejection; CKD_NULL/X9.63 SHA-2/SHA-3 KDF values correct.
- SHA-3 vs Keccak correctly distinguished; AES-KW/KWP wrap-length floors per
  RFC 3394/5649; CSPRNG (`OsRng`/getrandom) for all keygen; Mutex poison recovery.
- wasm32 ABI (CK_ULONG=4) applied consistently across all parsed parameter structs.

## Appendix B — Findings deferred to the in-flight multipart-encryption rework

(Not in the remediation plan; hand to whoever owns the `multipart.rs` work.)
- C_Encrypt after C_EncryptUpdate silently discards streaming state and one-shots the
  new data (spec requires failure); same for C_Decrypt.
- `GcmState::new` clamps tag length to 4..=16 bytes silently instead of validating the
  SP 800-38D set; align with the Init-time validation once H-18's tag-bits fix lands.
- `aes_gcm_exec` truncated-tag decrypt (tag_bits<128) always fails — appends tag_bytes
  but the AEAD expects 16.
- Message-based encrypt streaming is O(n²) (re-runs GCM over the accumulated payload
  per chunk) and releases unauthenticated plaintext chunks (§5.15 caveat).
- Lock-ordering note: multipart Update/Final hold ENCRYPT/DECRYPT_STATE while locking
  OBJECTS — document the ENCRYPT_STATE→OBJECTS ordering invariant.

---

# Remediation Plan

Phased so each phase is independently shippable and testable. Effort is rough
(S < ½ day, M ≈ 1–2 days, L ≈ 3–5 days). Every fix must cite the OASIS v3.2 spec
section in its commit message; constants verified against `pkcs11t.h` only.

## Phase R1 — Critical security & interop (target: immediately)
| Item | Fixes | Effort |
|---|---|---|
| R1.1 | Constants: CKM_CHACHA20→0x1226, CKM_CHACHA20_POLY1305→0x4021 (collapse the dual-ID dispatch in ffi.rs/native/encrypt.rs), CKM_AES_KEY_WRAP_KWP→0x210B; move CKM_AES_KEY_WRAP_PAD_LEGACY + CKM_EC_MONTGOMERY_KEY_DERIVE to vendor range; align CKM_EDDSA_PH with header (0x80001057) (C-3, M-15, H-16 part) | M |
| R1.2 | Global `INITIALIZED` flag: CKR_CRYPTOKI_NOT_INITIALIZED on every function pre-init, CKR_CRYPTOKI_ALREADY_INITIALIZED on double-init, C_Finalize pReserved check; feature-gate the ACVP pReserved seed hook out of release builds (C-2, M-14) | M |
| R1.3 | Login/visibility gate: central `can_access_object(session, obj)` enforcing CKA_PRIVATE × login_state in FindObjects, GetAttributeValue, DestroyObject, and every key-use lookup; C_Logout invalidates private-object handles (C-1) | L |
| R1.4 | GCM: reject NULL/empty IV with CKR_MECHANISM_PARAM_INVALID at all four Init/Wrap sites (C-4) | S |
| R1.5 | Bind pAssociatedData into the AEAD in C_Wrap/UnwrapKeyAuthenticated (C-5) | S |

## Phase R2 — Session & error-code conformance
| Item | Fixes | Effort |
|---|---|---|
| R2.1 | Session-handle validation helper applied to all ~12 unguarded functions; error priority session→key→operation (H-7) | M |
| R2.2 | R/O write protection (CKR_SESSION_READ_ONLY on create/generate/destroy), CKF_SERIAL_SESSION check, uninitialized-token OpenSession/Login codes (H-8, M-16) | M |
| R2.3 | Two-call convention: preserve op state on CKR_BUFFER_TOO_SMALL in single-shot C_Encrypt/C_Decrypt, C_Digest(Final); HSS/XMSS C_Sign validates buffer **before** advancing stateful-key state (H-4/5/6) | M |
| R2.4 | Return-code precision sweep (M-1): KEY_HANDLE_INVALID, OBJECT_HANDLE_INVALID, SIGNATURE_LEN_RANGE, MECHANISM_PARAM_INVALID, SESSION_READ_ONLY, ATTRIBUTE_SENSITIVE (with full-template pass per §5.7.5 — H-11) | M |
| R2.5 | Operation-state hygiene: CKR_OPERATION_ACTIVE on re-init (Sign/Verify/Digest/Find), FindObjectsFinal w/o init → OPERATION_NOT_INITIALIZED; clear+zeroize VERIFY_SIG/MESSAGE_* state on CloseSession/Finalize (M-2, M-3) | M |

## Phase R3 — Object model & attribute enforcement
| Item | Fixes | Effort |
|---|---|---|
| R3.1 | C_CreateObject template validation: required attrs per class (TEMPLATE_INCOMPLETE), type/length checks (ATTRIBUTE_VALUE_INVALID), consistency (TEMPLATE_INCONSISTENT); null ph_object check (H-9) | L |
| R3.2 | Read-only attribute filter in `absorb_template_attrs` (CKA_LOCAL, KEY_GEN_MECHANISM, CLASS, KEY_TYPE, ALWAYS_SENSITIVE, NEVER_EXTRACTABLE; CKA_TRUSTED requires SO) → CKR_ATTRIBUTE_READ_ONLY (H-10) | M |
| R3.3 | Provenance attributes: ALWAYS_SENSITIVE/NEVER_EXTRACTABLE=FALSE on create/import/unwrap (explicitly stored); derived keys LOCAL=FALSE + KEY_GEN_MECHANISM=CK_UNAVAILABLE_INFORMATION; import paths get full storage-attr defaults (H-13, M-7) | M |
| R3.4 | Native-API parity: gate `native::get_attribute` on EXTRACTABLE too; un-`pub` or gate `state::get_object_value`/`get_object_attr_bytes`/`set_object_attr_bytes`; enforce one-way SENSITIVE/EXTRACTABLE transitions in `set_object_attr_bytes` (H-12, M-5) | M |
| R3.5 | Usage enforcement: CKA_ENCAPSULATE/DECAPSULATE checks in C_Encapsulate/DecapsulateKey + drop the silent ML-KEM-768 fallback (CKR_KEY_TYPE_INCONSISTENT); enforce WRAP_WITH_TRUSTED (H-14, M-8) | M |
| R3.6 | PQC keygen: require CKA_PARAMETER_SET (TEMPLATE_INCOMPLETE); add CKA_SEED=0x637 constant; either implement seed-deterministic keygen per FIPS 203/204 or reject CKA_SEED — never absorb it readable (M-6) | M |
| R3.7 | Session-object lifecycle: tag objects with creating session, destroy at CloseSession; decide CKA_TOKEN policy (reject with TOKEN_WRITE_PROTECTED or implement persistence) and reflect in token flags (M-4) | L |

## Phase R4 — API surface completion
| Item | Fixes | Effort |
|---|---|---|
| R4.1 | C_GetFunctionList / C_GetInterfaceList / C_GetInterface returning the 3.2 function table (H-1) | M |
| R4.2 | C_CloseAllSessions, C_SessionCancel (now required given OPERATION_ACTIVE guards), C_LoginUser (H-2) | M |
| R4.3 | C_SignMessageBegin/Next, C_VerifyMessageBegin/Next; fix C_MessageSignFinal signature + no-op CKR_OK (H-3) | M |
| R4.4 | Stub the absent legacy/dual-function/recover entry points with spec-mandated codes (CKR_FUNCTION_NOT_PARALLEL, CKR_NO_EVENT, CKR_FUNCTION_NOT_SUPPORTED) (LOW batch) | S |
| R4.5 | Null-check sweep for all raw out-pointers (ARGUMENTS_BAD); replace `static mut KAT_SEED` with OnceCell/Mutex; fix the dangling-pointer empty-message hack in C_VerifySignatureFinal (M-13) | M |

## Phase R5 — Mechanism parameter compliance (single-shot)
| Item | Fixes | Effort |
|---|---|---|
| R5.1 | ML-DSA: parse CK_SIGN_ADDITIONAL_CONTEXT for CKM_ML_DSA + all CKM_HASH_ML_DSA_*; honor context (≤255 else MECHANISM_PARAM_INVALID — also fix the SLH-DSA silent-drop) and CKH_HEDGE_PREFERRED/REQUIRED/DETERMINISTIC_REQUIRED; same hedge handling for SLH-DSA sign path (H-17) | L |
| R5.2 | RSA-PSS: parse CK_RSA_PKCS_PSS_PARAMS (hashAlg/mgf/sLen), validate consistency, honor on sign and verify (no salt trial) (H-18) | M |
| R5.3 | GCM ulTagBits: validate {32,64,96,104,112,120,128}, honor in single-shot encrypt/decrypt; ulIvBits read; non-12-byte IV → either implement J0 derivation or MECHANISM_PARAM_INVALID + document restriction (H-18, M-12) | M |
| R5.4 | AES-CTR ulCounterBits: validate 1..=128, wrap counter within the low N bits (H-18) | M |
| R5.5 | ECDSA SHA-3 pre-hash: truncate digest to curve size per FIPS 186-5 §6.4 (H-18) | S |
| R5.6 | OAEP mgf+label plumbing through C ABI; uniform CKR_ENCRYPTED_DATA_INVALID on decode failure (M-9) | M |
| R5.7 | SP800-108 counter-format width + DKM length format segments (M-10); HMAC *_GENERAL mechanisms + KMAC customization/length (M-11) | L |

## Phase R6 — Token/slot truth & mechanism table
| Item | Fixes | Effort |
|---|---|---|
| R6.1 | C_GetTokenInfo computed from TOKEN_STORE (drop CKF_USER_PIN_LOCKED; flags reflect actual init/PIN state; real label); CKR_SLOT_ID_INVALID checks (H-15) | M |
| R6.2 | Reconcile SUPPORTED_MECHS ↔ GetMechanismInfo (every listed mechanism answerable; add CKF_MESSAGE_* flags where message ops exist; resolve AES-192 three-way disagreement) (H-16) | M |
| R6.3 | Naming cleanups: CK_UNAVAILABLE_INFORMATION, CKP_PKCS5_PBKD2_HMAC_*; document IANA-sourced CKP_LMS/XMSS values (LOW batch) | S |

## Verification strategy
1. **Constants:** scripted diff of `constants.rs` against `pkcs11t.h` added as a CI test
   (parse both, compare name/value pairs) — prevents regression of C-3-class bugs.
2. **Conformance tests:** port the C++ `p11_v32_compliance_test` cases (120 PASS suite)
   to the Rust engine via the existing `test_harness.js` / wasm-bindgen tests; add
   targeted regression tests per finding ID (e.g., R1.3 login-gating, R2.3 two-call,
   R5.1 ML-DSA context vectors from FIPS 204 KATs).
3. **Negative-path matrix:** table-driven tests asserting exact CKR_* codes for the §5
   error-priority order (not-initialized → session → key → operation → buffer).
4. **Cross-engine parity:** run the same vectors through the C++ engine and diff RVs —
   the C++ side already passed this class of audit (see `docs/gap-analysis-pkcs11-v3.2.md`).

---

# Remediation Status Ledger (2026-06-10)

Implemented on `feat/kmip-conformance-round-2`. Build green on wasm32; full
`test_kat_parity.js` suite passing after every phase.

## DONE

### Encryption revisit (2026-06-10, after the multipart rework landed)
- **H-4** — single-shot `C_Encrypt`/`C_Decrypt` now preserve operation state on
  `CKR_BUFFER_TOO_SMALL` (re-insert `EncryptCtx`), matching the NULL-buffer length-query
  path, so a retry with an adequate buffer succeeds instead of getting
  `CKR_OPERATION_NOT_INITIALIZED` (§5.2).
- **One-shot-after-update mixing (Appendix B)** — `C_Encrypt`/`C_Decrypt` now detect an
  in-flight multipart op (`ctx.multipart.is_some()`), preserve it, and return
  `CKR_OPERATION_ACTIVE` instead of silently discarding the streaming state.
- GCM truncatable-tag handling left as-is: `GcmState` honors `tag_len` (the intentional
  KMIP `CS-BC-M-GCM-1` feature, commit a08b0ff); strict SP 800-38D tag-set validation is
  deferred to R5.3 to avoid regressing that feature.

### R3.6 — CKA_PARAMETER_SET now required for PQC keygen
- **Engine:** `C_GenerateKeyPair` for `CKM_ML_KEM/ML_DSA/SLH_DSA_KEY_PAIR_GEN` returns
  `CKR_TEMPLATE_INCOMPLETE` when `CKA_PARAMETER_SET` is absent from the public-key template
  (no more silent ML-KEM-768 / ML-DSA-65 / SLH-DSA-SHA2-128F default). Verified by
  `rust/test_r36_paramset.js` (present→CKR_OK, absent→0xD0).
- **Cross-layer fix:** corrected `pqctoday-hub/src/wasm/softhsm.worker.ts:108`
  `CKA_PARAMETER_SET` 0x1d9→**0x61d** (the only wrong copy; `softhsm.ts`,
  `softhsm/constants.ts`, `pqcCryptoBridge.ts`, vendor `constants.js` were already 0x61d).
  All hub keygen paths place the attribute in the **public** template, so enforcement is safe.

### Phase R1 — Critical (all 5)
- **C-3 / R1.1** — `constants.rs`: `CKM_CHACHA20` 0x1071→**0x1226**, `CKM_CHACHA20_POLY1305`
  0x1093→**0x4021** (raw-literal dual-ID dispatch in `ffi.rs` collapsed to the named
  constant), `CKM_AES_KEY_WRAP_KWP` 0x210A→**0x210B**; de-squatted the legacy pad
  (renamed `CKM_AES_KEY_WRAP_PAD_LEGACY`→`CKM_AES_KEY_WRAP_PAD`=**0x210A**, freeing
  CKM_AES_CMAC_GENERAL 0x108b); `CKM_EC_MONTGOMERY_KEY_DERIVE` 0x1058→**0x80000011**
  (vendor range); `CKM_EDDSA_PH` 0xFFFF1057→**0x80001057** (matches pkcs11t.h).
- **C-2 / R1.2** — global `INITIALIZED` flag (`state.rs`); `require_init!()` on all 80
  entry points → `CKR_CRYPTOKI_NOT_INITIALIZED`; double-init →
  `CKR_CRYPTOKI_ALREADY_INITIALIZED`; `C_Finalize(pReserved!=NULL)`→`CKR_ARGUMENTS_BAD`;
  ACVP `pReserved` seed hook now behind a default-on `acvp` cargo feature (release builds
  use `--no-default-features` → spec-correct `CKR_ARGUMENTS_BAD`).
- **C-1 / R1.3** — `can_access_object()` gate on CKA_PRIVATE × login state in
  `C_FindObjectsInit` (filter), `C_GetAttributeValue` (→OBJECT_HANDLE_INVALID),
  `C_DestroyObject`; key-use private gating folded into `check_key_usage` (R2.4). C_Logout
  already resets to Public (dynamic checks satisfy "handles become invalid").
- **C-4 / R1.4** — AES-GCM NULL/empty IV → `CKR_MECHANISM_PARAM_INVALID` at all four
  Init/Wrap sites (no more zero-nonce fallback).
- **C-5 / R1.5** — `C_Wrap/UnwrapKeyAuthenticated` now bind `pAssociatedData` into the GCM
  tag via `aead::Payload`; unwrap auth failure → `CKR_ENCRYPTED_DATA_INVALID`.

### Phase R2 — Session & error-code conformance
- **R2.1 (H-7)** — `require_session!()` on the ~24 functions that ignored the session
  handle → `CKR_SESSION_HANDLE_INVALID`, ordered after init / before key+op checks.
- **R2.2 (H-8)** — `CKF_SERIAL_SESSION` enforced in `C_OpenSession`
  (→`CKR_SESSION_PARALLEL_NOT_SUPPORTED`); token-object (CKA_TOKEN=TRUE) creation in a R/O
  session → `CKR_SESSION_READ_ONLY`. (`test_kat_parity.js` updated to pass 0x06.)
- **R2.3 (H-5, H-6)** — HSS/XMSS `C_Sign` now validates the output buffer **before**
  advancing/persisting the one-time-key state (no more burned leaf on
  `CKR_BUFFER_TOO_SMALL`; op stays active for retry); `C_DigestFinal` checks length before
  consuming the context.
- **R2.4 (M-1, H-11)** — `check_key_usage()` distinguishes `CKR_KEY_HANDLE_INVALID` from
  `CKR_KEY_FUNCTION_NOT_PERMITTED` across the 5 main crypto Init paths; `C_GetAttributeValue`
  full §5.7.5 pass → `CKR_ATTRIBUTE_SENSITIVE` / `CKR_OBJECT_HANDLE_INVALID`; `C_InitPIN`
  R/O → `CKR_SESSION_READ_ONLY`.
- **R2.5 (M-2, M-3)** — `CKR_OPERATION_ACTIVE` on re-init for Sign/Verify/Digest/Find;
  `C_FindObjectsFinal` w/o init → `CKR_OPERATION_NOT_INITIALIZED`; `C_CloseSession` &
  `C_Finalize` now clear+zeroize `VERIFY_SIG_STATE` and `MESSAGE_ENCRYPT/DECRYPT_STATE`
  (raw key bytes).

### Phase R3 (high-value subset) + R6.1
- **R3.5 (H-14)** — `CKA_ENCAPSULATE`/`CKA_DECAPSULATE` usage checks in
  `C_Encapsulate/DecapsulateKey`.
- **R3.3 (H-13, M-7)** — `C_DeriveKey`, `C_UnwrapKey`, `C_UnwrapKeyAuthenticated` now set
  `CKA_LOCAL=FALSE`, `KEY_GEN_MECHANISM=CK_UNAVAILABLE_INFORMATION`,
  `ALWAYS_SENSITIVE=FALSE`, `NEVER_EXTRACTABLE=FALSE` (no provenance forgery).
- **R3.2 (H-10)** — `absorb_template_attrs` skips server-managed read-only attrs
  (CKA_CLASS/KEY_TYPE/LOCAL/KEY_GEN_MECHANISM/ALWAYS_SENSITIVE/NEVER_EXTRACTABLE/CHECK_VALUE).
- **R3.6 (partial)** — `CKA_SEED`=0x637 constant added; **enforcement deferred** (see below).
- **R6.1 (H-15)** — `C_GetTokenInfo` drops `CKF_USER_PIN_LOCKED` (0x40000) from the token
  flags and validates the slot.

## DEFERRED / NOT YET DONE

> Detailed implementation plan for everything in this section:
> `docs/implementation-plan-rust-pkcs11-deferred.md` (9 PR slices, sequencing,
> risks, acceptance criteria).

- **R3.1** — full `C_CreateObject` template validation (TEMPLATE_INCOMPLETE / ATTRIBUTE_*
  / TEMPLATE_INCONSISTENT).
- **R3.4** — native-API parity (gate `native::get_attribute` on EXTRACTABLE; un-`pub`/gate
  `state::get_object_value`/`get_object_attr_bytes`/`set_object_attr_bytes`; one-way
  SENSITIVE/EXTRACTABLE transitions).
- **R3.7** — session-object lifecycle (destroy session objects at CloseSession; slot/token
  object scoping; CKA_TOKEN=TRUE persistence policy).
- **Phase R4** — `C_GetFunctionList`/`C_GetInterface(List)`, `C_CloseAllSessions`,
  `C_SessionCancel`, `C_LoginUser`, `C_SignMessageBegin/Next`+`VerifyMessageBegin/Next`,
  stub the absent legacy/dual-function/recover entry points, null-check sweep,
  `static mut KAT_SEED`→OnceCell.
- **Phase R5** — ML-DSA context string + hedge variant; RSA-PSS param parsing;
  GCM `ulTagBits`/`ulIvBits`; AES-CTR `ulCounterBits`; ECDSA SHA-3 prehash truncation;
  OAEP mgf+label via C ABI; SP800-108 counter/DKM formats; HMAC `_GENERAL`/KMAC custom.
  `CKR_SIGNATURE_LEN_RANGE` (M-1 remainder) also belongs here.
- **R6.2 / R6.3** — reconcile `SUPPORTED_MECHS` ↔ `C_GetMechanismInfo` (≈10 advertised
  mechanisms have no info arm); CKF_MESSAGE_* flags; AES-192 three-way disagreement;
  naming cleanups; CI constants-diff test vs `pkcs11t.h`.

## Cross-layer follow-ups (outside the Rust crate)
1. ~~**`CKA_PARAMETER_SET` ID** — hub TS worker used 0x1d9~~ — **FIXED** to 0x61d in
   `softhsm.worker.ts:108`.
2. **ChaCha20 / ChaCha20-Poly1305 / KWP mechanism IDs** — any JS/TS `constants.js` copy must
   adopt the corrected spec values (0x1226 / 0x4021 / 0x210B) to match the engine. (The hub
   `softhsm.ts`/vendor `constants.js` should be spot-checked; the engine is now authoritative.)
