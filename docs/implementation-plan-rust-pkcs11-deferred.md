> **Historical record (2026-06).** The deferred work planned here has shipped
> (through v0.8.0; see `../rust/RUST_P11_V32_CONFORMANCE_REPORT.md`). Kept for
> provenance, not an open to-do list.

# Implementation Plan — softhsmrustv3 PKCS#11 v3.2 Deferred Work

**Date:** 2026-06-10
**Branch baseline:** `feat/kmip-conformance-round-2` (post R1/R2/R3-subset/R6.1 + H-4 + R3.6)
**Scope:** R3.1, R3.4, R3.7, Phase R4 (entry points), Phase R5 (mechanism parameters,
incl. GCM tag-set validation), R6.2/R6.3 — the remaining items from
`docs/gap-analysis-rust-pkcs11-v3.2.md`.
**Source of truth:** OASIS PKCS#11 v3.2 CSD01 (`docs/refs/pkcs11-spec-v3.2-csd01.pdf`)
+ normative `src/lib/pkcs11/pkcs11t.h` / `pkcs11f.h`. Every CK* value is grepped from
`pkcs11t.h` before use; commit messages cite the spec section.

Effort scale: S < ½ day, M ≈ 1–2 days, L ≈ 3–5 days.
Build/check loop: `RUSTC=~/.rustup/toolchains/stable-aarch64-apple-darwin/bin/rustc
…/cargo check --target wasm32-unknown-unknown`, then `wasm-pack build --target bundler
--out-dir pkg --dev` + `node test_kat_parity.js` + `node test_r36_paramset.js`.

---

## Milestone 0 — Conformance test harness (prerequisite, M)

Everything below needs a regression net beyond the 4 KAT suites. Generalize
`rust/test_r36_paramset.js` into **`rust/test_p11_conformance.js`**:

- Shared helpers: `buildTpl` (wasm32 12-byte CK_ATTRIBUTE), `buildMech` (12-byte
  CK_MECHANISM with param struct support), `checkRV(expected, actual, label)`,
  init/open-session/login fixtures.
- Table-driven negative-path matrix asserting **exact** CKR_* codes in spec priority
  order: not-initialized → session → key → operation → buffer (§5.4/§5.12).
- Seed it with tests for everything already fixed (R1–R3.6, H-4, mixing guard) so the
  deferred work can't regress prior fixes: double-init, pre-init call, bad session,
  private-object invisibility, BUFFER_TOO_SMALL retry on C_Sign/C_Encrypt/C_DigestFinal,
  GCM empty-IV reject, AAD round-trip on authenticated wrap, param-set enforcement.
- Wire into CI alongside the constants diff (Milestone F2). Exit non-zero on any
  mismatch; run after every milestone below.

**Acceptance:** harness runs green on current HEAD before any new work lands.

---

## Workstream A — R3.1: C_CreateObject template validation (L)

`ffi.rs::C_CreateObject` currently accepts any template. Add a validation pass
(`fn validate_create_template(&Attributes) -> Result<(), CK_RV>`) executed after
template parse, before defaults:

1. **Required attributes per class** (§4.x object tables) → `CKR_TEMPLATE_INCOMPLETE`:
   - All objects: `CKA_CLASS` (no more silent CKO_PUBLIC_KEY default — this also closes
     the H-9 sensitivity-bypass corollary).
   - `CKO_SECRET_KEY`: `CKA_KEY_TYPE`, `CKA_VALUE`.
   - `CKO_PRIVATE_KEY` / `CKO_PUBLIC_KEY`: `CKA_KEY_TYPE` + per-type material —
     RSA: `CKA_MODULUS`(+`CKA_PUBLIC_EXPONENT` pub / PKCS#8 `CKA_VALUE` priv);
     EC/EdDSA: `CKA_EC_PARAMS` + (`CKA_EC_POINT` pub / `CKA_VALUE` priv);
     ML-KEM/ML-DSA/SLH-DSA/HSS/XMSS: `CKA_PARAMETER_SET` (Table 273: ck1 for
     C_CreateObject) + `CKA_VALUE`.
2. **Value validation** → `CKR_ATTRIBUTE_VALUE_INVALID`: bool attrs len==1 and ∈{0,1};
   ulong attrs len==4; `CKA_CLASS`/`CKA_KEY_TYPE`/`CKA_PARAMETER_SET` values from the
   known sets; AES `CKA_VALUE` len ∈ {16,24,32}; PQC `CKA_VALUE` len consistent with
   the parameter set (reuse the existing per-set size tables in `native/keygen.rs`).
3. **Consistency** → `CKR_TEMPLATE_INCONSISTENT`: `CKA_KEY_TYPE` vs `CKA_CLASS`
   (e.g. CKK_AES only under CKO_SECRET_KEY); usage flags vs class (CKA_SIGN on a
   public key, CKA_ENCAPSULATE on a private key, etc.).
4. **Unknown attribute type** (not in pkcs11t.h, not vendor ≥0x80000000) →
   `CKR_ATTRIBUTE_TYPE_INVALID`.
5. **Read-only attrs in template** (`is_server_managed_attr`, already in
   `crypto/handlers.rs`) → `CKR_ATTRIBUTE_READ_ONLY` (stricter than the silent-skip
   used on the generate paths — §5.7.1 mandates the error for C_CreateObject).
6. Null `ph_object` → `CKR_ARGUMENTS_BAD` before any allocation.

**Compat gate:** before enabling, inventory every C_CreateObject call site in
`pqctoday-hub/src/wasm/softhsm.ts` (incl. XMSS import at ~5938) and the KMIP
`register_import_export.rs` path; extend templates where they'd now fail. Land engine
+ caller changes in the same PR.

**Tests:** matrix per class × {missing-required, bad-value, inconsistent, read-only}.

---

## Workstream B — R3.4: native-API parity & one-way transitions (M)

The `native::` module is the KMIP crate's sanctioned API (`kmip` imports
`softhsmrustv3::{native, constants}` only); `state::` accessors are the leak.

1. **Visibility:** demote `state::get_object_value`, `get_object_attr_bytes`,
   `get_object_attr_u32/u64`, `set_object_attr_bytes` from `pub` to `pub(crate)`.
   Verify with `cargo check -p kmip` that nothing outside the crate breaks (current
   grep shows kmip uses only `native::*`).
2. **`native::object::get_attribute`:** extend the CKA_VALUE gate to also block when
   `CKA_EXTRACTABLE=FALSE` on private/secret keys (mirror
   `ffi::C_GetAttributeValue`'s `sensitive || !extractable` predicate — factor the
   predicate into one shared `state::value_is_blocked(&Attributes) -> bool` so the two
   surfaces cannot drift).
3. **One-way transitions:** introduce `state::set_object_attr_checked(handle, type,
   value) -> Result<(), CK_RV>` enforcing: `CKA_SENSITIVE` FALSE→TRUE only,
   `CKA_EXTRACTABLE` TRUE→FALSE only, server-managed attrs immutable
   (`CKR_ATTRIBUTE_READ_ONLY`). Route every `native::` mutation through it.
   **Carve-out:** vendor stateful-key attrs (`CKA_STATEFUL_KEY_STATE`,
   `CKA_LEAF_INDEX`, `CKA_*_KEYS_REMAINING`, ≥0x80000100) and `CKA_PRIV_*`
   (≥0xFFFF0000) bypass the policy — they ARE the engine's internal state channel
   (ffi.rs stateful sign path depends on it).
4. **Import defaults (M-6 remainder):** `native/keygen.rs::register_rsa_private_key_pkcs8`
   and `register_generic_secret_bytes` get full storage defaults
   (TOKEN/PRIVATE/SENSITIVE/EXTRACTABLE explicit, LOCAL=FALSE,
   KEY_GEN_MECHANISM=CK_UNAVAILABLE_INFORMATION, ALWAYS_SENSITIVE/NEVER_EXTRACTABLE=FALSE
   — stop calling `finalize_private_key_attrs` on import paths).

**Tests:** Rust unit tests in `native/parity.rs` (the parity contract file):
blocked-VALUE equivalence native↔ffi, one-way transition rejects, carve-out accepts.

---

## Workstream C — R3.7: session-object lifecycle & token policy (L)

**Policy decision (recommended, encode in plan):** this is an ephemeral in-memory soft
token. Token objects (`CKA_TOKEN=TRUE`) live for the library lifetime (until
C_Finalize) — acceptable for a soft token with no durable storage. Session objects
(`CKA_TOKEN=FALSE`) must die with their creating session (§4.4 — currently violated).

1. **Owner tagging:** store creating session under a new internal attr
   `CKA_PRIV_OWNER_SESSION (0xFFFF_0003)` on every object-creation path
   (CreateObject, GenerateKey(Pair), Derive, Unwrap×2, Encapsulate/Decapsulate,
   native registrations — native paths tag with session 0 = "no session/library
   scope" so KMIP-registered objects survive).
2. **C_CloseSession / C_CloseAllSessions:** destroy (zeroize CKA_VALUE) all objects
   where `CKA_TOKEN=FALSE` and owner == closed session. Keep handle invalidation.
3. **Slot scoping:** add `CKA_PRIV_SLOT (0xFFFF_0004)` tagged from the session's slot;
   `C_FindObjectsInit` filters to the session's slot. (Single-slot deployments see no
   behavior change; multi-slot stops leaking cross-slot objects.)
4. **Token flags truth:** with the policy above, no `CKF_WRITE_PROTECTED`; document
   the ephemeral-token semantics in the module docs and TERMS for the playground.

**Compat risk (must verify before merge):** the hub flow opens a session, generates
keys (`CKA_TOKEN:false` everywhere), closes sessions between operations? If
`softhsm.worker.ts`/`softhsm.ts` close the session and later use the key handles, step
2 breaks them. Inventory `_C_CloseSession` call ordering in the hub first; if handles
must survive, hub switches those templates to `CKA_TOKEN:true` (correct modeling) in
the same PR.

**Tests:** session-object dies on close; token object survives; cross-session find;
slot filter; KMIP-registered object survives session churn.

---

## Workstream D — Phase R4: API surface completion

### D1. Interface negotiation — C_GetInterfaceList / C_GetInterface / C_GetFunctionList (M)
wasm-bindgen exports are not addressable as C function pointers in linear memory, so a
true `CK_FUNCTION_LIST` cannot be built Rust-side. Split by consumer:
- **Rust/wasm exports:** `_C_GetInterfaceList` / `_C_GetInterface` returning
  CK_INTERFACE records (wasm32 layout: pInterfaceName ptr, pFunctionList ptr, flags)
  for interface "PKCS 11" version 3.2; the pFunctionList points to a linear-memory
  struct containing the **version header only** plus a sentinel table populated by the
  JS shim (next bullet). Honor the two-call convention.
- **JS shim (`pkg/` wrapper, mirrored into `pqctoday-hub/src/wasm/softhsmrustv3.js`):**
  export `C_GetFunctionList()` returning a JS object mapping the 3.2 function set to
  the wasm exports — the practical equivalent for every real consumer of this engine.
- Native `rlib` consumers (kmip) call Rust fns directly — explicitly out of scope.
Document the design decision in the module header.

### D2. Session management functions (M)
Per `pkcs11f.h` signatures:
- **`C_CloseAllSessions(slotID)`** — validate slot (`CKR_SLOT_ID_INVALID`), close every
  session on it via the same path as C_CloseSession (op-state cleanup + session-object
  destruction from Workstream C). Call it from `C_InitToken` (spec requires no open
  sessions / closes them depending on profile — return `CKR_SESSION_EXISTS` if any
  remain is the stricter v3.2 InitToken rule; pick `CKR_SESSION_EXISTS`).
- **`C_SessionCancel(hSession, flags)`** — clear the op-state maps selected by flags
  (CKF_ENCRYPT→ENCRYPT_STATE, CKF_DECRYPT, CKF_DIGEST, CKF_SIGN, CKF_VERIFY,
  CKF_FIND_OBJECTS, CKF_MESSAGE_* → MESSAGE_*_STATE incl. key zeroize); flags==0 per
  spec cancels nothing, returns CKR_OK. This is now REQUIRED ergonomics given the
  OPERATION_ACTIVE guards added in R2.5.
- **`C_LoginUser(hSession, userType, pPin, ulPinLen, pUsername, ulUsernameLen)`** —
  delegate to the C_Login logic; non-empty username → `CKR_OPERATION_NOT_SUPPORTED`
  (single-user token).

### D3. Message-based sign/verify multipart + shape fix (M)
- **`C_SignMessageBegin(hSession, pParameter, ulParameterLen)`** /
  **`C_SignMessageNext(hSession, pParameter, ulParameterLen, pPart, ulPartLen,
  pSignature, pulSignatureLen)`** (NULL pSignature on non-final parts accumulates;
  non-NULL finalizes) and the Verify twins. Back them with an accumulator in
  SIGN_STATE/VERIFY_STATE keyed off the existing MessageSignInit context — one-shot
  algorithms (ML-DSA/SLH-DSA/EdDSA) buffer and sign at final; HMAC streams.
- **Fix `C_MessageSignFinal`** to the 1-arg pkcs11f.h shape (currently 5 args) and
  return `CKR_OPERATION_NOT_INITIALIZED` when no message-sign op is active (same for
  `C_MessageVerifyFinal`). **Coordinate JS shim regeneration** (wasm-bindgen signature
  change is ABI-breaking for the worker).

### D4. Spec-mandated stubs (S)
Export with exact pkcs11f.h shapes returning the spec-required codes:
`C_GetFunctionStatus`/`C_CancelFunction` → `CKR_FUNCTION_NOT_PARALLEL`;
`C_WaitForSlotEvent` → `CKR_NO_EVENT` (CKF_DONT_BLOCK) / `CKR_FUNCTION_NOT_SUPPORTED`;
`C_SignRecoverInit`/`C_SignRecover`/`C_VerifyRecoverInit`/`C_VerifyRecover`,
`C_DigestEncryptUpdate`/`C_DecryptDigestUpdate`/`C_SignEncryptUpdate`/
`C_DecryptVerifyUpdate` → `CKR_FUNCTION_NOT_SUPPORTED`. All behind `require_init!()`.

### D5. FFI hardening sweep (M)
- Null-check every out-pointer/in-pointer before deref (`CKR_ARGUMENTS_BAD`):
  audit list from the FFI agent — `C_Sign(p_data, pul_signature_len)`,
  `C_GetAttributeValue(p_template)`, `C_CreateObject(ph_object)` (done in A),
  `C_FindObjects(ph_object, pul_object_count)`, `C_DecapsulateKey(p_ciphertext)`,
  `C_GenerateKeyPair(p_mechanism)`, plus a grep for `from_raw_parts` /
  `*p` derefs not preceded by `.is_null()`.
- Replace `static mut KAT_SEED` (`crypto/xmss_bridge.rs`, written from
  `ffi.rs::set_kat_seed`) with `OnceCell`/`Mutex<Option<[u8;96]>>`.
- Replace the dangling `4 as *mut u8` empty-message hack in `C_VerifySignatureFinal`
  with a zero-len slice path.

---

## Workstream E — Phase R5: mechanism parameter compliance

### E1. ML-DSA context string + hedge variant (L) — biggest interop win
The patched `fips204` crate already supports both knobs:
`try_sign(msg, ctx)` (hedged) and `try_sign_with_rng(rng, msg, ctx)` (zero-RNG ⇒
deterministic per FIPS 204 §5.2 note).
- Generalize `parse_slh_dsa_ctx` → `parse_sign_additional_ctx(p_mechanism) ->
  Result<(Vec<u8>, HedgeMode), CK_RV>`; apply to `CKM_ML_DSA` and all
  `CKM_HASH_ML_DSA_*` in C_SignInit / C_VerifyInit / C_VerifySignatureInit /
  C_MessageSignInit (SIGN_STATE tuple already carries `(ctx, bool)` — widen bool to a
  3-state `HedgeMode { Preferred, Required, DeterministicRequired }`).
- Thread ctx into `sign_ml_dsa`/`verify_ml_dsa` (currently hard-coded `b""`,
  `handlers.rs:488-547`); deterministic mode uses a local zero-`CryptoRngCore`
  (fips204's `DummyRng` is private — replicate 10 lines).
- **Fix the silent-drop bug (M-1):** ctx_len > 255 → `CKR_MECHANISM_PARAM_INVALID`
  (currently silently treated as empty — applies to the SLH-DSA path too).
- SLH-DSA sign path: honor `CKH_HEDGE_REQUIRED` explicitly (today only
  DETERMINISTIC_REQUIRED is distinguished); `native/sign.rs` gets ctx plumbed
  (currently hard-codes empty for SLH-DSA there).
- **Tests:** FIPS 204 KAT vectors with non-empty ctx; deterministic-mode repeatability;
  ctx>255 reject; cross-context verify failure.

### E2. RSA-PSS parameter plumbing (M)
- Parse `CK_RSA_PKCS_PSS_PARAMS` (wasm32: hashAlg u32, mgf u32, sLen u32) at
  C_SignInit/C_VerifyInit for `CKM_SHA256_RSA_PKCS_PSS`; validate hashAlg==CKM_SHA256
  matches the mechanism, mgf==CKG_MGF1_SHA256 (grep CKG_* from pkcs11t.h), else
  `CKR_MECHANISM_PARAM_INVALID`. Store sLen in the op state (extend SIGN_STATE tuple
  or move PSS params into a small struct).
- Sign: `rsa::pss::SigningKey::new_with_salt_len(sk, sLen)`; Verify:
  `VerifyingKey::new_with_salt_len` with the caller's sLen ONLY (delete the two-salt
  trial loop at `handlers.rs:1281-1296`); absent params → default sLen = hashLen
  (documented v2.x behavior).
- Defer SHA-384/512 PSS variants until the mechanisms exist (only the SHA-256
  mechanism is advertised) — note in code.

### E3. GCM ulTagBits + ulIvBits (M) — preserves KMIP CS-BC-M-GCM-1
- At all four GCM Init/Wrap parse sites: validate
  `tag_bits ∈ {0, 32, 64, 96, 104, 112, 120, 128}` (0 ⇒ 128) else
  `CKR_MECHANISM_PARAM_INVALID` (SP 800-38D §5.2.1.2 set; 32/64 kept for the KMIP
  truncatable-tag feature — `GcmState`'s clamp then never engages and can become a
  debug_assert).
- Single-shot GCM encrypt: truncate the emitted tag to tag_bits/8 (use
  `native/encrypt.rs`'s tag-aware helpers); single-shot decrypt: split ct/tag at
  tag_bits/8 and verify via the same path as `GcmState` (fixes the
  `aes_gcm_exec`-style full-16-byte assumption).
- Read `ulIvBits` (offset 8) and ignore it when consistent with ulIvLen, reject when
  contradictory; keep the 12-byte-IV-only restriction but return
  `CKR_MECHANISM_PARAM_INVALID` (not ARGUMENTS_BAD) and document the restriction in
  C_GetMechanismInfo docs. (Full J0 derivation for ≠96-bit IVs: out of scope, noted.)
- **Tests:** NIST GCM vectors at 96/104/112/120-bit tags one-shot + multipart parity;
  reject 8/24/136.

### E4. AES-CTR ulCounterBits (M)
- Parse `ulCounterBits` (offset 0 of CK_AES_CTR_PARAMS); validate 1..=128 else
  `CKR_MECHANISM_PARAM_INVALID`.
- `multipart.rs` already has a width-parameterized counter (`inc_be(.., width)`);
  thread the value through `EncryptCtx` (new field) into both the single-shot path
  (replace `ctr::Ctr128BE` with the multipart `CtrState` for width≠128) and
  `build_multipart_cipher`.
- **Tests:** RFC 3686-style vectors (32-bit counter), wrap-around at the width
  boundary, single-shot ↔ multipart parity.

### E5. ECDSA SHA-3 prehash truncation (S)
`handlers.rs` SHA-3 arms (sign ~799-829, verify ~1351-1383): truncate the digest to
the curve field size before `sign_prehash`/`verify_prehash` (leftmost ⌈log2 n⌉ bits,
FIPS 186-5 §6.4) — copy the pattern from the SHA-512 arms which already do it.
**Tests:** SHA3-512 on P-256/P-384 sign/verify round-trip + cross-check with a
known-good vector.

### E6. RSA-OAEP mgf + label via C ABI (M)
Extend the OAEP param parse (4 sites: C_EncryptInit/C_DecryptInit/C_WrapKey/
C_UnwrapKey) from hashAlg-only to the full CK_RSA_PKCS_OAEP_PARAMS (wasm32:
hashAlg, mgf, source, pSourceData, ulSourceDataLen = 20 bytes): map to
`native/encrypt.rs::oaep_for` (already supports independent hash/MGF/label);
mgf hash ≠ OAEP hash supported; non-CKZ_DATA_SPECIFIED source →
`CKR_MECHANISM_PARAM_INVALID`. Unify decrypt failure to `CKR_ENCRYPTED_DATA_INVALID`
(currently CKR_FUNCTION_FAILED on the ffi path — padding-oracle hygiene).
**Tests:** OAEP SHA-256/MGF1-SHA-1 (the classic mismatch pair) + label round-trip.

### E7. SP800-108 format fields (M)
Parse `CK_SP800_108_COUNTER_FORMAT` (ulWidthInBits ∈ {8,16,24,32}) and
`CK_SP800_108_DKM_LENGTH_FORMAT` (method, littleEndian, widthInBits) data params in
the COUNTER/FEEDBACK KDF arms (`ffi.rs` ~3825-3930): emit the counter at the
caller-specified width/position and inject the [L]₂ field per the format. Default to
current behavior (32-bit BE counter, no L) when the format params are absent.
**Tests:** NIST CAVP KBKDF vectors at 8- and 16-bit counter widths.

### E8. HMAC `_GENERAL` + KMAC customization (M)
- Add `CKM_SHA{256,384,512}_HMAC_GENERAL` (0x252/0x262/0x272) and
  `CKM_SHA3_{256,512}_HMAC_GENERAL` (0x2b2/0x2d2) to constants + SUPPORTED_MECHS +
  GetMechanismInfo + sign/verify dispatch: param = CK_MAC_GENERAL_PARAMS (u32
  ulMacLength), validate 1..=digest_len else `CKR_MECHANISM_PARAM_INVALID`; truncate
  output; verify compares constant-time (`subtle::ConstantTimeEq`) on the truncated
  length.
- KMAC: accept an optional vendor param struct {pCustomization, ulLen, ulOutputLen}
  feeding `sp800-185`'s customization string + variable output (keep current defaults
  when absent).
- **Tests:** truncated-HMAC vectors; KMAC customization vectors from SP 800-185.

### E9. CKR_SIGNATURE_LEN_RANGE sweep (S)
In every `verify_*` handler, distinguish wrong-length signature
(`CKR_SIGNATURE_LEN_RANGE`) from well-formed-but-invalid (`CKR_SIGNATURE_INVALID`):
length check against the per-mechanism expected size (`get_sig_len` already computes
it) before the crypto call. **Tests:** one truncated-sig case per family.

---

## Workstream F — R6.2/R6.3: mechanism table truth + CI guard

### F1. Reconcile SUPPORTED_MECHS ↔ C_GetMechanismInfo (M)
Current diff (verified 2026-06-10): **11 advertised mechanisms have no info arm** —
`CKM_ECDSA`, `CKM_EDDSA_PH`, `CKM_HASH_ML_DSA`, `CKM_HASH_SLH_DSA`, `CKM_HSS`,
`CKM_HSS_KEY_PAIR_GEN`, `CKM_XMSS`, `CKM_XMSS_KEY_PAIR_GEN`, `CKM_XMSSMT`,
`CKM_XMSSMT_KEY_PAIR_GEN`, `CKM_KECCAK_256`. Add arms:
ECDSA (256–521, SIGN|VERIFY); EDDSA_PH (255, SIGN|VERIFY); HASH_ML_DSA /
HASH_SLH_DSA (same as their families); HSS/XMSS/XMSSMT keygen (GENERATE_KEY_PAIR) and
sign (SIGN|VERIFY — sign only on the stateful private key); KECCAK_256 (DIGEST).
Then add a **unit test that iterates SUPPORTED_MECHS and asserts
C_GetMechanismInfo != CKR_MECHANISM_INVALID for every entry** — this is the
structural fix; the list never drifts again.
- Add `CKF_MESSAGE_SIGN`/`CKF_MESSAGE_VERIFY` (pkcs11t.h values) to ML-DSA/SLH-DSA/
  HMAC info, `CKF_MESSAGE_ENCRYPT`/`CKF_MESSAGE_DECRYPT` to AES-GCM (message-based
  ops exist for these).
- Resolve AES-192: native keygen accepts it, `C_GenerateKey` rejects it, info
  advertises 16–32. Decision: support it in `C_GenerateKey` (the cipher arms already
  match on key length 16/24/32 in several places; extend the few 16|32-only matches).

### F2. CI constants guard + naming cleanups (S)
- **Script `scripts/check_pkcs11_constants.py`** (CI + pre-commit): parse
  `rust/src/constants.rs` name/value pairs, parse `src/lib/pkcs11/pkcs11t.h`
  `#define`s (resolving `CKM_VENDOR_DEFINED|x` expressions), diff; whitelist file for
  intentional vendor constants (CKM_KECCAK_256, CKA_STATEFUL_*, CKA_PRIV_*,
  CKM_EC_MONTGOMERY_KEY_DERIVE, CKP_LMS/XMSS IANA sets). Fail on any spec-name
  value mismatch — prevents the C-3 class permanently. Optionally extend to
  `pqctoday-hub/src/wasm/softhsm.ts` exported constants (catches the 0x1d9-class
  cross-layer drift).
- Rename `CKM_UNAVAILABLE_INFORMATION` → `CK_UNAVAILABLE_INFORMATION` and
  `CKP_PBKDF2_HMAC_SHA*` → `CKP_PKCS5_PBKD2_HMAC_SHA*` (keep deprecated aliases one
  release); document the IANA-sourced CKP_LMS/LMOTS/XMSS naming in constants.rs
  header.

---

## Sequencing & dependencies

```
M0 harness ──┬─► A (R3.1 templates)───┐
             ├─► B (R3.4 native)      ├─► C (R3.7 lifecycle: needs A's class rules,
             ├─► F1+F2 (R6 table+CI)  │      D2's CloseAllSessions lands with it)
             ├─► D4+D5 (stubs+harden) │
             ├─► E5+E9 (S items)      │
             ├─► E1 (ML-DSA ctx) ─► E2..E8 (independent of each other)
             └─► D1..D3 (entry points; D3 last — ABI break needs shim regen)
```

Suggested PR slices (each: build + KAT + conformance harness green):
1. **PR-1:** M0 + F2 (harness + CI guard) — pure additive.
2. **PR-2:** F1 + D4 + E5 + E9 (mechanism table, stubs, small correctness) — low risk.
3. **PR-3:** E1 (ML-DSA/SLH-DSA context + hedge) — highest interop value.
4. **PR-4:** B + D5 (native parity + hardening).
5. **PR-5:** A (template validation) — co-landed with hub/KMIP template fixes.
6. **PR-6:** E3 + E4 (GCM/CTR params) — touches the multipart owner's area; coordinate.
7. **PR-7:** E2 + E6 + E7 + E8 (RSA-PSS/OAEP/KDF/MAC params).
8. **PR-8:** C + D2 (lifecycle + CloseAllSessions/SessionCancel) — behavioral, hub-coordinated.
9. **PR-9:** D1 + D3 (interface negotiation + message multipart; shim regen).

Total effort: ≈ 18–24 dev-days. Independent tracks (E-series vs A/B/C vs D) can be
parallelized across sessions/agents.

## Risk register

| Risk | Mitigation |
|---|---|
| A or C breaks hub playground flows | Caller inventory before each; co-land template/flow fixes; conformance harness runs the hub's exact call shapes |
| D3 wasm-bindgen signature change breaks worker ABI | Regenerate `pkg/` + copy to hub `src/wasm/` in same change; version-bump crate |
| E3 regresses KMIP CS-BC-M-GCM-1 truncatable tags | Keep 32/64 in the accepted set; rerun the KMIP conformance harness (`kmip/` suite) in PR-6 |
| B's `pub(crate)` demotion breaks an unseen consumer | `cargo check` workspace-wide incl. `kmip`, `openmls-provider` before merge |
| E1 changes existing ML-DSA signatures (hedged default unchanged) | Empty-ctx hedged path must remain byte-compatible in tests vs current pkg |
| F1 AES-192 enablement hits a 16/32-only cipher arm | grep all `key_bytes.len()` matches; add 24 arms or reject consistently |

## Acceptance criteria (workstream-level)

- A: invalid templates rejected with the exact spec code; all hub/KMIP flows green.
- B: no `pub` state mutators; native↔ffi gate equivalence test passes.
- C: session objects die on close; KMIP objects + token objects survive; hub green.
- D: every pkcs11f.h v3.2 function exported (implemented or spec-correct stub);
  zero unchecked pointer derefs (grep-clean); no `static mut`.
- E: each item has KAT/CAVP-vector tests; ctx/hedge interop verified against the C++
  engine's outputs (cross-engine parity run).
- F: SUPPORTED_MECHS↔GetMechanismInfo unit test green; CI constants diff green and
  wired into the pipeline.

---

# EXECUTION STATUS (2026-06-10) — plan executed

All nine PR slices implemented on `feat/kmip-conformance-round-2`.
Validation at completion: **121/121** `test_p11_conformance.js`, **4/4**
`test_kat_parity.js`, `test_harness.js` pass, **2/2** `test_r36_paramset.js`,
**80** native `cargo test --lib`, **328/328** `scripts/check_pkcs11_constants.py`,
`kmip` crate checks clean. Release shim rebuilt and synced to
`pqctoday-hub/src/wasm/`.

| Slice | Status | Notes |
|---|---|---|
| PR-1 M0+F2 | ✅ | Harness found 2 real bugs day-one: `get_attr_ulong` misaligned-pointer panic on legal templates (fixed via `read_unaligned`) and `_malloc` align-1 layout (now align-8, `free` matched) |
| PR-2 F1+D4+E5+E9 | ✅ | 11 mechanism-info arms added + `supported_mechs_all_have_info` unit test; 10 spec stubs; SHA3-512-on-P-384 truncation (sign+verify); SIGNATURE_LEN_RANGE for fixed-size mechs. Harness FUNCTION_NOT_PARALLEL constant fixed (0x51, was wrongly 0x55) |
| PR-3 E1 | ✅ | `parse_sign_additional_ctx` (ML-DSA + SLH-DSA, pure+prehash, all 3 init sites); ctx≤255 enforced (silent-drop fixed); CKH hedge variants validated; deterministic via ZeroRng; ctx threaded through sign/verify_ml_dsa; tests: ctx round-trip, cross-ctx fail, deterministic repeatability, hedged uniqueness |
| PR-4 B+D5 | ✅ | 5 state accessors → `pub(crate)`; shared `value_is_blocked` (adds EXTRACTABLE gate to native); `set_object_attr_checked` one-way transitions + vendor carve-out; `native::object::set_attribute`; import-path provenance defaults; symmetric keygen EXTRACTABLE default flipped to true (KMIP Get compat); `static mut KAT_SEED`→Mutex; dangling-ptr fix; null-check sweep (Sign/Verify/GetAttributeValue/FindObjects/DecapsulateKey/GenerateKeyPair) |
| PR-5 A | ✅ | `validate_create_template`: CKA_CLASS required (closes the CKO_PUBLIC_KEY-default sensitivity bypass), KEY_TYPE required, class↔type consistency, material requirements per class, AES length check. Found+fixed `test_kat_parity.js` template bug (CKA_CLASS=3 vs commented SECRET_KEY=4) |
| PR-6 E3+E4 | ✅ | GCM ulTagBits validated {0,32,64,96,104,112,120,128} + honored in single-shot (routed through GcmState — single-shot ≡ multipart); ulIvBits consistency; CTR ulCounterBits validated (byte-granular) + width-parameterized `CtrState` in single-shot and multipart; tests incl. counter-wrap divergence and truncated-tag round-trip/corruption |
| PR-7 E2+E6+E7+E8 | ✅ | PSS params parsed/validated (sLen pinned when supplied; legacy two-candidate accept kept for the param-less native/KMIP path); OAEP full params (hash×MGF matrix + UTF-8 label) across Encrypt/Decrypt/Wrap/Unwrap, decode failures → ENCRYPTED_DATA_INVALID; SP800-108 ordered segments (counter width/endianness, [L] field, byte arrays) for counter+feedback KDFs; 5 HMAC `_GENERAL` mechanisms end-to-end; KMAC customization+output-length (`sign_kmac_ext`) |
| PR-8 C+D2 | ✅ | `CKA_PRIV_OWNER_SESSION` tag on all 27 FFI creation sites (`allocate_handle_owned`); session objects destroyed (zeroized) at CloseSession, token + native/KMIP objects survive; `C_CloseAllSessions`, `C_SessionCancel` (flag-selected op cancellation incl. message-state zeroize), `C_LoginUser`. Hub verified safe (closes only the SO bootstrap + teardown sessions) |
| PR-9 D1+D3 | ✅ | `C_GetInterfaceList`/`C_GetInterface` ("PKCS 11" v3.2, two-call convention; wasm function-pointer constraint documented — JS shim is the function table); `C_SignMessageBegin/Next`, `C_VerifyMessageBegin/Next` (accumulator model, §5.2-preserving final); `C_MessageSignFinal` fixed to 1-arg pkcs11f.h shape + OPERATION_NOT_INITIALIZED; hub TS updated (4 call sites + worker decl + real Begin/Next bindings); release shim synced to hub |

## Deviations from plan (documented choices)
- **R3.7 slot-scoping of FindObjects**: deferred — single-slot deployment; owner-session
  scoping covers the spec-mandated lifecycle. Tracked for a multi-slot future.
- **PSS verify**: kept the two-candidate salt acceptance when NO params are supplied
  (KMIP conformance suite depends on `saltlen:auto` signatures); params supplied = pinned.
- **GCM tag set includes 32/64** (SP 800-38D special-application lengths) to preserve
  KMIP CS-BC-M-GCM-1 truncatable tags.
- **CTR ulCounterBits**: byte-granular widths only (8,16,…,128); non-multiples of 8 →
  MECHANISM_PARAM_INVALID (documented engine restriction).
- **OAEP labels**: UTF-8 only (rsa-crate constraint); non-UTF-8 → MECHANISM_PARAM_INVALID.

## New/changed test assets
- `rust/test_p11_conformance.js` — 121 checks (the Rust-engine compliance suite)
- `scripts/check_pkcs11_constants.py` — 328/328 constants vs pkcs11t.h (CI guard)
- `rust/test_kat_parity.js` — fixed: session flags 0x06; ChaCha template class 4
- Engine unit test `ffi::mechanism_table_tests::supported_mechs_all_have_info`

## Cross-layer flag (outside scope, surfaced during PR-9)
`pqctoday-hub/src/wasm/softhsm.worker.ts` declares `CKO_PUBLIC_KEY = 3` /
`CKO_PRIVATE_KEY = 4` (spec: 2/3) — this worker drives the **C++** Emscripten
engine, so it was not fixed here; the C++ engine apparently tolerates it.
Recommend correcting alongside a C++-side template-validation pass.
