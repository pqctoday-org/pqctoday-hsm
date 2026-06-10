# Fix Plan — softhsmrustv3 PKCS#11 v3.2 Compliance

**Date**: 2026-06-10 · **Base branch**: `feat/kmip-conformance-round-2` (HEAD `7142333`)
**Source audit**: `docs/compliance-audit-kmip30-pkcs11v32-2026-06-10.md` (findings `P-*`,
plus the engine-side halves of bridge findings `B-2` and `B-6`)
**Companion plan**: `kmip/docs/COMPLIANCE_FIX_PLAN.md` (consumes S6/S7 below)

Seven PR slices, ordered so that each lands independently and the KMIP-side
plan's dependencies (S6, S7) are unblocked early. Effort: S = ≤½ day,
M = 1–2 days.

## Standing acceptance gates (every slice)

1. `cargo test` in `rust/` — including `native/parity.rs` suite and
   `supported_mechs_all_have_info`
2. `scripts/check_pkcs11_constants.py` — 329/329 (extend the manifest when a
   slice adds constants; never shrink)
3. KAT parity: `node rust/test_kat_parity.js` (rustup RUSTC for wasm targets —
   see memory note; Homebrew rustc lacks wasm32 std)
4. wasm build remains green (`wasm-pack`/bundler path used by `pkg/`)
5. KMIP replay harness still 92/92 (the kmip crate links `softhsmrustv3` —
   return-code changes here surface in bridge mapping)

---

## S1 — Mechanism table corrections (S)

**Findings**: P-1, P-12, P-15 (ECDSA size inconsistency)

| Change | File | Detail |
|---|---|---|
| PQC key sizes in **bytes** (spec §6.67–6.69: public-key sizes) | `rust/src/ffi.rs:697-704` | `CKM_ML_DSA{,_KEY_PAIR_GEN}` `(44,87)` → `(1312, 2592)`; `CKM_ML_KEM{,_KEY_PAIR_GEN}` `(512,1024)` → `(800, 1568)`; `CKM_SLH_DSA{,_KEY_PAIR_GEN}` `(128,256)` → `(32, 64)` |
| Advertise ChaCha20 / ChaCha20-Poly1305 | `rust/src/constants.rs:346-446` (`SUPPORTED_MECHS`) + `ffi.rs` `mechanism_info` | `CKM_CHACHA20` `(32,32)` CKF_ENCRYPT\|CKF_DECRYPT; `CKM_CHACHA20_POLY1305` `(32,32)` same flags (+CKF_MESSAGE_\* only if the message family accepts it — it currently does not; leave off) |
| Advertise `CKM_BIP32_*` derive mechs | same | flags CKF_DERIVE; key sizes per BIP32 (32-byte seeds) |
| ECDSA range consistency | `rust/src/ffi.rs:715-718, 760-762, 772` | engine supports P-521 (`native/keygen.rs:387-394`) → unify `CKM_EC_KEY_PAIR_GEN` and `CKM_ECDSA_SHA*` to `(256, 521)` |

**Tests**: extend the mechanism-info unit test to assert FIPS 203/204/205
public-key byte lengths literally; assert every mech accepted by
`C_EncryptInit`/`C_DeriveKey` dispatch arms appears in `SUPPORTED_MECHS`
(closes the "implemented but not advertised" class structurally).

## S2 — ABI hygiene: pre-init surface + null sweep (S)

**Findings**: P-2, P-7, P-11, P-13

| Change | File | Detail |
|---|---|---|
| Remove `require_init!` from `C_GetInterfaceList` / `C_GetInterface` | `rust/src/ffi.rs:6264, 6295` | spec §5.4: callable pre-init; `CKR_CRYPTOKI_NOT_INITIALIZED` not in their return lists |
| Gate + harden `C_GetMechanismList` | `rust/src/constants.rs:449-465` | add `require_init!`; null `pul_count` → `CKR_ARGUMENTS_BAD`; bad `slotID` → `CKR_SLOT_ID_INVALID` (mirror `C_GetTokenInfo`) |
| Finish null-check sweep | `ffi.rs:4499-4504` (`C_FindObjects` `ph_object`/`pul_object_count`), `ffi.rs:3784` (`C_Encrypt` `p_data`), `ffi.rs:5499, 5639` (`C_UnwrapKey`), `ffi.rs:1868` (`C_GenerateKey` `p_mechanism`) | introduce a `nonnull!(ptr)` macro → `CKR_ARGUMENTS_BAD`; in wasm these currently read/write address 0 |
| `C_SessionCancel` message-op flags | `ffi.rs:382-424` | add `CKF_MESSAGE_SIGN` (0x8) → clear `MESSAGE_SIGN_ACC`, `CKF_MESSAGE_VERIFY` (0x10) → clear `MESSAGE_VERIFY_ACC` (CloseSession at `ffi.rs:349-351` is the model; the doc comment already promises this) |

**Tests**: pre-init call test for both interface functions; null-pointer test
per swept function; SessionCancel test that begins a message-sign op, cancels
with 0x8, and asserts `C_SignMessageNext` → `CKR_OPERATION_NOT_INITIALIZED`.
Add a CI grep guard: any `*p_`/`*ph_` deref in `ffi.rs` without a `nonnull!`
within the function fails review checklist (script under `scripts/`).

## S3 — Object attribute integrity (M)

**Findings**: P-6, P-8, P-9, P-14

| Change | File | Detail |
|---|---|---|
| Stop falsifying provenance on import | `rust/src/ffi.rs:2369-2371`, `state.rs:645-650` | `C_CreateObject` must store explicit `CKA_ALWAYS_SENSITIVE=FALSE`, `CKA_NEVER_EXTRACTABLE=FALSE` (spec §4.9/4.10) instead of conditionally calling `finalize_private_key_attrs`; mirror the `C_UnwrapKey` path (`ffi.rs:5617-5621`) |
| `CKA_SEED` = sensitive-class | `state.rs:277-290` (`value_is_blocked`), `crypto/handlers.rs:121-141` (template skip-list) | block readback alongside `CKA_VALUE` (`CKR_ATTRIBUTE_SENSITIVE`); reject absorption from create/generate templates (v3.2 PQC key tables footnote CKA_SEED identically to CKA_VALUE); native parity via shared `state::value_is_blocked` — also covers `native/object.rs:101` |
| `CKA_UNIQUE_ID` | `state.rs` object-creation path | assign token-generated unique string (monotonic counter + token id; no `Date.now` analogues needed) on **every** object at creation; expose read-only; caller-supplied value → `CKR_ATTRIBUTE_READ_ONLY`; add to `is_server_managed_attr` (`crypto/handlers.rs:103-114`) |
| `CKA_TRUSTED` SO-only | `crypto/handlers.rs:103-114` | add to server-managed list; non-SO set → `CKR_ATTRIBUTE_READ_ONLY` (§4.1.1 Table 12) |
| Enforce `CKA_WRAP_WITH_TRUSTED` | `ffi.rs` `C_WrapKey` | target has `WRAP_WITH_TRUSTED=TRUE` and wrapping key lacks `CKA_TRUSTED=TRUE` → `CKR_KEY_NOT_WRAPPABLE` |
| Reject caller `CKA_KEY_GEN_MECHANISM` | `ffi.rs:2361-2367` | `C_CreateObject` → `CKR_ATTRIBUTE_READ_ONLY` |

**Tests**: import-then-GetAttributeValue asserts ALWAYS_SENSITIVE=FALSE;
CKA_SEED inject + readback both fail; UNIQUE_ID present, unique across two
objects, immutable; wrap-with-trusted matrix (4 combinations); parity tests in
`native/parity.rs` for the SEED block.

## S4 — Return-code precision (M)

**Findings**: P-3, P-4, P-5, P-15 (code-precision residuals)

| Change | File | Detail |
|---|---|---|
| Wrap-family handle codes | `ffi.rs:5334-5353` (`C_WrapKey`), `5484-5493` (`C_UnwrapKey`), `4704-4713` (`C_DeriveKey`) | split `.unwrap_or(false)` into exists → access → permission: missing wrapping key → `CKR_WRAPPING_KEY_HANDLE_INVALID` (0x113) / `CKR_UNWRAPPING_KEY_HANDLE_INVALID` (0x114); missing target → `CKR_KEY_HANDLE_INVALID`; route through `check_key_usage` parameterized on the handle-invalid code so the login gate applies (these paths currently skip `can_access_object`) |
| AES-KW unwrap codes | `ffi.rs:5528-5566` | integrity failure → `CKR_WRAPPED_KEY_INVALID` (0x110); short input → `CKR_WRAPPED_KEY_LEN_RANGE` (0x112) |
| Operate-stage session validation | `C_Sign`/`C_Verify`/`C_Encrypt`/`C_Decrypt`/`C_Digest*`/`C_FindObjects` (+ their `Update`/`Final`) | add `require_session!` at top — §5.2 error priority puts `CKR_SESSION_HANDLE_INVALID` above `CKR_OPERATION_NOT_INITIALIZED`; macro exists, mechanical |
| Minor precision | `ffi.rs:1910` generic-secret bad length → `CKR_ATTRIBUTE_VALUE_INVALID`; `ffi.rs:1871-1872` AES keygen missing `CKA_VALUE_LEN` → `CKR_TEMPLATE_INCOMPLETE` (§6.27.2; **breaking** for callers relying on the 16-byte default — grep kmip crate + JS shims first and fix call sites in the same change); `ffi.rs:907` invalid `CKA_PARAMETER_SET` value → `CKR_ATTRIBUTE_VALUE_INVALID`; `ffi.rs:2083-2085` decap wrong ct length → `CKR_ENCRYPTED_DATA_INVALID` |
| `C_Digest` after `C_DigestUpdate` | `ffi.rs:4427-4431` | → `CKR_OPERATION_ACTIVE`-class failure per §5.13 (M-2 residual): fail instead of silently appending |

**Coordination**: this slice changes CKRs that `kmip/src/ops/helpers.rs`
(`ck_rv_to_kmip_error`) sees — land **before or together with** KMIP plan
PR K1 (full CKR table) so new codes don't fall into the catch-all.

**Tests**: per-function bad-handle tests (wrap/unwrap/derive ×
{missing-wrapping-key, missing-target, logged-out}); AES-KW tamper test
asserting 0x110; session-handle-invalid test on each operate-stage call.

## S5 — ML-KEM strictness (S)

**Findings**: P-10 (R3.5 second half)

| Change | File | Detail |
|---|---|---|
| Drop silent ML-KEM-768 default | `ffi.rs:1983, 2079, 2133` and `native/encrypt.rs:66, 110` | key without `CKA_PARAMETER_SET` → `CKR_TEMPLATE_INCOMPLETE`; remove the `\| 0` / param-set-0 fallback in both ABI and native paths |
| Key-type check | same sites | object's `CKA_KEY_TYPE != CKK_ML_KEM` → `CKR_KEY_TYPE_INCONSISTENT` before encap/decap |

**Tests**: encapsulate against an AES key → `CKR_KEY_TYPE_INCONSISTENT`;
hand-built object without param set → `CKR_TEMPLATE_INCOMPLETE`. Note: since
S3 keygen always stores a param set, only imported/legacy objects can hit
this — test via direct object construction.

## S6 — Engine enabler for bridge B-2: RSA hash-variant mechanisms (M)

**Consumed by**: KMIP plan PR K6 (honor KMIP `HashingAlgorithm` on Sign)

| Change | File | Detail |
|---|---|---|
| Add constants | `rust/src/constants.rs` | `CKM_SHA384_RSA_PKCS = 0x41`, `CKM_SHA512_RSA_PKCS = 0x42`, `CKM_SHA384_RSA_PKCS_PSS = 0x44`, `CKM_SHA512_RSA_PKCS_PSS = 0x45` (grep `src/lib/pkcs11/pkcs11t.h` before committing — source-of-truth rule) |
| Dispatch | `ffi.rs` sign/verify arms (model: existing `CKM_SHA256_RSA_PKCS{,_PSS}` at `ffi.rs:2767+`) + `crypto/handlers.rs` | hash-then-sign with SHA-384/512; PSS salt length = hash length per §6.2 defaults, overridable via `CK_RSA_PKCS_PSS_PARAMS` where the params path exists |
| Advertise | `SUPPORTED_MECHS` + `mechanism_info` | `(2048, 4096)`, CKF_SIGN\|CKF_VERIFY |
| Manifest | `scripts/check_pkcs11_constants.py` data | extend; keep 100% green |

ECDSA needs nothing — `CKM_ECDSA_SHA384/512` already implemented (`ffi.rs:2767, 2927-2928`).

**Tests**: sign/verify round-trip per new mech; KAT cross-check against
OpenSSL-generated vectors (add to `rust/tests/`); wrong-hash verify fails.

## S7 — Engine enabler for bridge B-6: PQC key import (M)

**Consumed by**: KMIP plan PR K9 (Register of ML-DSA/ML-KEM/SLH-DSA keys)

| Change | File | Detail |
|---|---|---|
| `register_ml_dsa_private_key` / `_public_key` | `rust/src/native/keygen.rs` (model: `register_rsa_private_key_pkcs8` at `:468`) | accept raw FIPS 204 key bytes + `CKP_ML_DSA_*` param set; validate length against param set; store with `CKA_KEY_TYPE=CKK_ML_DSA`, `CKA_PARAMETER_SET`, usage attrs; **per §4.9/4.10 and S3: `ALWAYS_SENSITIVE=FALSE`, `NEVER_EXTRACTABLE=FALSE`** (the existing import fns at `keygen.rs:491-492, 561-562` already do this — keep the pattern) |
| `register_ml_kem_private_key` / `_public_key` | same | FIPS 203 lengths; set `CKA_DECAPSULATE`/`CKA_ENCAPSULATE` defaults consistent with keygen (`ffi.rs:867, 886`) |
| `register_slh_dsa_private_key` / `_public_key` | same | FIPS 205 lengths per the 12 param sets |
| Length validation table | shared helper | param set → expected sk/pk byte length; mismatch → `CKR_ATTRIBUTE_VALUE_INVALID` |

**Tests**: import KAT keypair → sign/verify (ML-DSA, SLH-DSA) and
encap/decap (ML-KEM) round-trips against generated-key behavior; wrong-length
rejection per param set; imported key reports ALWAYS_SENSITIVE=FALSE.

---

## Sequencing

```
S1 ──┐
S2 ──┼─ independent, land in any order, this week
S3 ──┘
S4 ─── land with/before KMIP PR K1 (CKR mapping table)
S5 ─── after S3 (keygen guarantees param set)
S6 ─── unblocks KMIP K6 step 2 (B-2 full fix)
S7 ─── unblocks KMIP K9 (B-6 full fix)
```

## Deferred (tracked, not in this plan)

- Message-encrypt O(n²) accumulate-and-re-run-GCM design (`ffi.rs:6857-6975`,
  Appendix B of `gap-analysis-rust-pkcs11-v3.2.md`) — owned by the
  multipart-rework effort.
- H-15: dynamic TokenInfo flags/label (`ffi.rs:643-655`).
- Multi-slot FindObjects scoping (global `OBJECTS` map, `ffi.rs:4459-4471`).
- Seed-deterministic keygen via `CKA_SEED` (blocked-attr handling lands in S3;
  the generation feature itself is roadmap).

## Doc updates in the final slice

- Mark C-1…C-5, H-4/5/6/7/11/12/14, R2.x, R3.x, R5.x, R6.1 **FIXED** in
  `docs/gap-analysis-rust-pkcs11-v3.2.md` (currently reads as if open) and
  link each S-slice to the findings it closes.
- Bump crate version; CHANGELOG entries per slice.
