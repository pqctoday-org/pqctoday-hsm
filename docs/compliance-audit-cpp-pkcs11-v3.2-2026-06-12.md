# C++ SoftHSM Engine — PKCS#11 v3.2 Compliance Audit

**Date**: 2026-06-12 · **Branch**: `feat/wasm-vpn-frag-multike-childsa` (post round-3, `main`-merged compliance baseline)
**Scope**: `src/lib/` C++ engine — the engine round 1–3 deliberately scoped OUT (rust was the focus).
**Reference**: canonical OASIS v3.2 (`src/lib/pkcs11/pkcs11{t,f}.h`, canonical-synced commit `2e65832`; pin `docs/refs/pkcs11t-canonical-v3.2.h`) + spec PDF `docs/refs/pkcs11-spec-v3.2-csd01.pdf`.
**Method**: four parallel read-only audits (API/lifecycle, mechanism table, object/attribute, crypto/return-codes), benchmarked against every bug class the rust engine fixed in rounds 1–3.

This audit supersedes the intentional-omission claims (G7/G8/G9) in
`docs/gap-analysis-pkcs11-v3.2.md` v16 (2026-04-14) — all three were found stale.

## Verdict

The C++ engine is **structurally strong** where the rust engine was weakest:
full v2.40/3.0/3.2 interface structs, init gate everywhere, §5.2 error
priority, two-call convention, real 20-function message API with streaming
encrypt + verify-then-release decrypt, ML-DSA/SLH-DSA context+hedge honored,
stateful burn-after-buffer-validation, AES `CKA_VALUE_LEN` strictness,
WRAP_WITH_TRUSTED enforcement, SP800-108 PRF fix already in tree. **But** it
carries several bugs the rust engine never had — two security-critical — plus
the same PQC-mechanism-size and template-validation classes round 1–3 fixed
in rust.

## CRITICAL (security)

| ID | Finding | Location |
|---|---|---|
| C++C-1 | **GCM/ChaCha20 zero-IV substitution** — `ulIvLen==0` accepted at the PKCS#11 layer; OSSL layer substitutes a fixed all-zero block-size IV (`iv.wipe(getBlockSize())`). Fixed zero nonce across encryptions = catastrophic reuse. Spec: `ulIvLen`≥1 → `CKR_MECHANISM_PARAM_INVALID`. Exact rust C-4 class. | `SoftHSM_cipher.cpp:163-177,200-218,824+`; `crypto/OSSLEVPSymmetricAlgorithm.cpp:129-138,329-338` |
| C++C-2 | **`EVP_CTRL_GCM/AEAD_SET_IVLEN` return ignored** — out-of-range ChaCha20-Poly1305 nonce silently falls back to OpenSSL's 12-byte default reading wrong bytes; no error. No 12-byte nonce rule enforced. | `crypto/OSSLEVPSymmetricAlgorithm.cpp:177,375` |
| C++C-3 | **XMSS/XMSSMT stack-buffer overflow** — `unsigned char sig[8000]`; `xmss_sign` writes `signature‖message` of length `sig_bytes+ulDataLen` with no bound. C_Sign with large data smashes the stack. (HSS path is bounded.) | `SoftHSM_sign.cpp:1345,1380,1388` |
| C++C-4 | **RIPEMD160 → SHA-1 silent substitution** — `case CKM_RIPEMD160:` comment says "fall through to CKR_MECHANISM_INVALID" but actually falls into `case CKM_SHA_1:`. `C_DigestInit(CKM_RIPEMD160)` produces SHA-1 digests labeled RIPEMD-160. | `SoftHSM_digest.cpp:64-69` |

## VIOLATIONS (spec SHALL broken)

| ID | Finding | Location |
|---|---|---|
| V-1 | **ML-DSA mechanism-info sizes 128/256, must be public-key bytes 1312/2592** (all `CKM_ML_DSA*` incl. HASH variants). Rust P-1 class. | `SoftHSM_slots.cpp:928-948` |
| V-2 | **SLH-DSA sizes 128/256, must be 32/64 bytes**. (ML-KEM 800/1568 already correct.) | `SoftHSM_slots.cpp:950-970` |
| V-3 | **Silent `CKA_PARAMETER_SET` defaults** for ML-DSA (→44), SLH-DSA (→128S), ML-KEM (→768); present-but-wrong-size silently ignored. Spec: missing → `CKR_TEMPLATE_INCOMPLETE`. Rust F4 class. | `SoftHSM_keygen.cpp:4641,4866,6710` |
| V-4 | **Keygen template `CKA_KEY_TYPE` not validated** for ML-KEM/EC/HSS/XMSS — wrong type returns CKR_OK not `CKR_TEMPLATE_INCONSISTENT`. The proven F4 case (CKK_XMSSMT in ML-KEM template). | `SoftHSM_keygen.cpp:360-392`; `C_GenerateKey` `:251-256` |
| V-5 | **AES-CBC wrap is secretly AES-KW**; the mandatory 16-byte IV is discarded; C_UnwrapKey has no CKM_AES_CBC case → never round-trips. | `SoftHSM_keygen.cpp:803-806`; `crypto/OSSLAES.cpp:107-132` |
| V-6 | **AES-CBC-PAD wrap = KWP(PKCS7(key))** — double padding; unwrap strips only the KWP layer, leaving 1–16 PKCS#7 pad bytes in the round-tripped `CKA_VALUE`. | `SoftHSM_keygen.cpp:810-813,1357-1362` |
| V-7 | **AES-KW/KWP & RSA unwrap integrity failure → `CKR_GENERAL_ERROR`**, must be `CKR_WRAPPED_KEY_INVALID` (0x110). Rust P-4 class. | `SoftHSM_keygen.cpp:1393-1394,1456-1457` |
| V-8 | **XMSSMT keygen unreachable** — advertised (0x4035) but no case in the keygen switch; the implementation at `:474,529-543` is dead code. | `SoftHSM_keygen.cpp:314-349` |
| V-9 | **XMSSMT sign unreachable** — `StatefulSignInit` maps `0x00004036` (mislabeled "CKM_XMSS_MT"; 0x4036 is CKM_XMSS, XMSSMT is 0x4037). C_SignInit(CKM_XMSSMT)→CKR_MECHANISM_INVALID while verify works. Rust stale-literal class. | `SoftHSM_sign.cpp:1161-1162,1182-1184` |
| V-10 | **CKM_CHACHA20 advertised, zero dispatch** — `C_EncryptInit(CKM_CHACHA20)`→CKR_MECHANISM_INVALID. Mirror of the rust hidden-ChaCha20 bug. | `SoftHSM_slots.cpp:437`; dispatch `SoftHSM_cipher.cpp:56-61` |
| V-11 | **CKM_RIPEMD160_HMAC advertised, rejected by every Init** (absent from `isMacMechanism`). | `SoftHSM_slots.cpp:374`; `SoftHSM_sign.cpp:77-95` |
| V-12 | **ChaCha20 keygen mislabeled as AES** — `CKM_CHACHA20_KEY_GEN`→`generateAES`, stored with `CKK_AES` + `CKM_AES_KEY_GEN`. | `SoftHSM_keygen.cpp:272-275,3702-3747` |
| V-13 | **HSS/XMSS private CKA_VALUE stored in plaintext**, bypassing token encryption (unlike every other private key type). | `SoftHSM_keygen.cpp:681`; read `SoftHSM_sign.cpp:1343` |
| V-14 | **CKA_UNIQUE_ID duplicated on C_CopyObject** — clone copies the attribute; init() sees it exists, doesn't regenerate. Original and copy share one ID. | `SoftHSM_objects.cpp:401-435,454` |
| V-15 | **CKA_UNIQUE_ID settable via C_DeriveKey template** — no DERIVE-op guard; base update() stores the caller's value. Token-assigned-only broken. | `P11Attributes.cpp:496-500`; `SoftHSM_keygen.cpp:5260-5285` |
| V-16 | **C_SessionCancel**: flags==0 treated as cancel-all (spec: no-op + CKR_OK); no active op → CKR_OPERATION_CANCEL_FAILED (spec: ignore unmatched, CKR_OK); `CKF_MESSAGE_*`/`CKF_FIND_OBJECTS` never tested. | `SoftHSM_sessions.cpp:250-297` |
| V-17 | **One-shot-after-Update → `CKR_OPERATION_NOT_INITIALIZED` (and destroys op)**, must be `CKR_OPERATION_ACTIVE`; `C_Digest` has no single-part guard at all (digests update‖data silently). | `SoftHSM_sign.cpp:1193,1254,2659,2708`; `SoftHSM_cipher.cpp:360,440,1027,1099`; `SoftHSM_digest.cpp:119-180` |
| V-18 | **C_WrapKeyAuthenticated breaks two-call convention** — CKR_BUFFER_TOO_SMALL path doesn't set `*pulWrappedKeyLen`. | `SoftHSM_keygen.cpp:2098` |
| V-19 | **C_GetSessionValidationFlags bypasses init gate + session validation** — returns CKR_OK/*pFlags=0 pre-init and for bad handles; ignores `type`. | `main.cpp:1802-1809` |
| V-20 | **C_Initialize dereferences non-NULL `pReserved`≥4096 as an ACVP-seed struct** — spec: non-NULL → CKR_ARGUMENTS_BAD; crash/UB on garbage. | `SoftHSM_slots.cpp:78-103` |
| V-21 | **CKA_HSS_KEYS_REMAINING hardcoded to 32** regardless of LMS tree height — wrong for every param set whose 2^h≠32. | `SoftHSM_keygen.cpp:488,672-688` |
| V-22 | **C_EncapsulateKey/C_DecapsulateKey shims lack the try/catch firewall** — only two entry points where a C++ exception escaping the C ABI is UB. | `main.cpp:1742-1760` |

## GAPS (missing / incomplete)

- **CKA_SEED entirely absent** (object §4.3, crypto 5.6): zero references outside the header — no ξ/d‖z/3-seed deterministic PQC keygen; v3.2 PQC private-key table attribute unimplemented. (Rust now supports it via T7.)
- **CKF_MESSAGE_* flags not advertised** on AES-GCM / sign mechs despite the message API dispatching them (mech G1/G2).
- **CKM_CHACHA20_POLY1305 message API missing** (AES-GCM only); **CKM_SHA3_384_RSA_PKCS{,_PSS}** one-family hole; **MD5 / raw-PSS / Keccak-256 / X25519 / X448 / BIP32 advertise↔dispatch mismatches** (mech G3-G8) — X25519/X448/BIP32 derive is **dead** (advertised path rejected by `isMechanismPermitted`).
- **Stateful-sig: no key-level locking** — two sessions signing one HSS/XMSS key both read CKA_VALUE before either commits → leaf reuse (API C++V5); signature released before transaction commit (failure → leaf reuse).
- **EncapsulateKey handle codes**: invalid pub→CKR_OBJECT_HANDLE_INVALID (spec §5.18.8 CKR_KEY_HANDLE_INVALID); invalid priv (spec CKR_UNWRAPPING_KEY_HANDLE_INVALID) (crypto 2.4).
- **Return-code precision batch**: CKM_RSA_PKCS unwrap len check promised-never-done (1.6), C_DeriveKey bad base→CKR_OBJECT_HANDLE_INVALID (spec CKR_KEY_HANDLE_INVALID, 6.5), StatefulVerify no len pre-check (4.6), StatefulSign conflates all failures to CKR_KEY_EXHAUSTED (4.5).
- **gap-analysis v16 G7/G8/G9 all stale**: async fns return CKR_OPERATION_NOT_INITIALIZED not FUNCTION_NOT_SUPPORTED; C_SignRecover/C_VerifyRecover now fully implemented (only 4 dual-function ops remain stubs); C_GetSessionValidationFlags is the defective V-19.
- **HandleManager cross-token reach** (object §6 OBS): a handle minted on token A is usable from a session on token B (upstream-inherited).
- **0x17→0x4 store migration** (object 1.4): pre-existing tokens hold the unique id under 0x17; after the F1 header fix, init() mints a *new* UUID on first touch — every pre-existing object's "immutable" id silently changes. No migration shim.

## Verified-conformant highlights (regression anchors)

Init gate (99 checks), all three interface structs + pre-init callability, §5.2
error priority, two-call convention (Sign/Encrypt/Decrypt/Digest/Encap/
VerifyRecover/message-finals), full streaming message API (no O(n²), no pre-auth
plaintext release), C_VerifySignature* family, R/O write protection +
ACTION_PROHIBITED, lifecycle teardown + handle invalidation on logout/close,
wrap-handle/unextractable ordering, KEM usage-attribute + key-type enforcement,
ML-DSA/SLH-DSA context+hedge honored (rust H-17 absent), stateful
burn-after-buffer-validation, AES CKA_VALUE_LEN strictness, WRAP_WITH_TRUSTED,
provenance attrs on create/generate/unwrap/derive, sensitive-attribute
protection (ck7) + §5.7.5 full-template semantics, CKA_UNIQUE_ID assignment +
read-only-on-set, SP800-108 PRF fix (commit 250994d), PSS sLen end-to-end,
raw r‖s ECDSA, ECDH/HKDF KDFs.

## Suggested remediation grouping (round 4, if C++ remains a deliverable)

- **G1 security (must-fix)**: C++C-1, C++C-2 (zero-IV/IVLEN), C++C-3 (stack overflow), C++C-4 (RIPEMD160→SHA-1), V-13 (plaintext HSS/XMSS key), stateful-sig locking.
- **G2 mechanism table (mirror rust S1/T1)**: V-1, V-2 (PQC sizes), V-10/V-11 (ChaCha20/RIPEMD160_HMAC advertise↔dispatch), V-12 (ChaCha20 keytype), mech G1-G8.
- **G3 keygen/template (mirror rust S3/S5/F4)**: V-3, V-4 (param-set/keytype validation), V-8/V-9/V-21 (XMSSMT keygen+sign+keys-remaining), V-5/V-6 (AES-CBC wrap).
- **G4 return-code precision (mirror rust S4)**: V-7, V-16, V-17, V-18, V-19, V-20, V-22 + the GAP batch.
- **G5 attributes/feature (mirror rust S3/T6/T7)**: V-14/V-15 (UNIQUE_ID copy/derive), CKA_SEED, 0x17→0x4 migration shim.
- Refresh `docs/gap-analysis-pkcs11-v3.2.md` G7/G8/G9.
