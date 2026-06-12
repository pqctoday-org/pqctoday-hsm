# PKCS#11 v3.2 Compliance Report

**Engine:** `./build-f1/src/lib/libsofthsmv3.dylib`
**Engine commit:** `ac480db`
**Date:** 2026-06-12 18:03:12 CDT

> Reproduce with: `cd build-f1 && ctest -R p11_v32_compliance` (or run
> `p11_v32_compliance_test --engine <libsofthsmv3> --workdir <scratch> --report <base>`).
> This report supersedes the former `compliance_report.{md,json}` (stale May 2026
> partial run against an old engine build; deleted in the F4 test-integrity slice).

## Summary
- **Total PASS:** 191
- **Total FAIL:** 0
- **Total SKIP:** 1
- **Total XFAIL (known engine bugs, documented in-line):** 2

Status legend: PASS = spec-conformant behavior for an advertised feature; FAIL = unexpected non-conformance; SKIP = feature not advertised by the token (v3.2 mandates no particular mechanism set); XFAIL = known, pre-existing engine non-conformance reported here but outside this suite's scope to fix.

### AES-CTR

| Test | Status | Details |
|---|---|---|
| EncryptInit | ✅ PASS | RV=0 |

### Attributes

| Test | Status | Details |
|---|---|---|
| CKA_VALUE_Pub | ✅ PASS | §1.21 G-ATTR1 check |
| CKA_PUBLIC_KEY_INFO_Pub | ✅ PASS | Required for all PQC keys |
| CKA_PUBLIC_KEY_INFO_Priv | ✅ PASS | Required to be exposed on private objects |
| CKA_HSS_KEYS_REMAINING_Gen | ✅ PASS | Remaining=32 |
| CKA_HSS_KEYS_REMAINING_Consume | ✅ PASS | Count decreased correctly |
| ML_KEM_512_CKA_VALUE_Pub | ✅ PASS | §1.21 G-ATTR1 check |
| ML_KEM_512_CKA_PUBLIC_KEY_INFO_Pub | ✅ PASS | SPKI exposed |
| ML_KEM_512_CKA_PUBLIC_KEY_INFO_Priv | ✅ PASS | SPKI exposed on private |
| ML_KEM_512_CKA_ENCAPSULATE | ✅ PASS |  |
| ML_KEM_512_CKA_DECAPSULATE | ✅ PASS |  |
| ML_KEM_768_CKA_VALUE_Pub | ✅ PASS | §1.21 G-ATTR1 check |
| ML_KEM_768_CKA_PUBLIC_KEY_INFO_Pub | ✅ PASS | SPKI exposed |
| ML_KEM_768_CKA_PUBLIC_KEY_INFO_Priv | ✅ PASS | SPKI exposed on private |
| ML_KEM_768_CKA_ENCAPSULATE | ✅ PASS |  |
| ML_KEM_768_CKA_DECAPSULATE | ✅ PASS |  |
| ML_KEM_1024_CKA_VALUE_Pub | ✅ PASS | §1.21 G-ATTR1 check |
| ML_KEM_1024_CKA_PUBLIC_KEY_INFO_Pub | ✅ PASS | SPKI exposed |
| ML_KEM_1024_CKA_PUBLIC_KEY_INFO_Priv | ✅ PASS | SPKI exposed on private |
| ML_KEM_1024_CKA_ENCAPSULATE | ✅ PASS |  |
| ML_KEM_1024_CKA_DECAPSULATE | ✅ PASS |  |
| ML_DSA_44_CKA_VALUE_Pub | ✅ PASS | §1.21 G-ATTR1 check |
| ML_DSA_44_CKA_PUBLIC_KEY_INFO_Pub | ✅ PASS | SPKI exposed |
| ML_DSA_44_CKA_PUBLIC_KEY_INFO_Priv | ✅ PASS | SPKI exposed on private |
| ML_DSA_44_CKA_VERIFY | ✅ PASS |  |
| ML_DSA_44_CKA_SIGN | ✅ PASS |  |
| ML_DSA_65_CKA_VALUE_Pub | ✅ PASS | §1.21 G-ATTR1 check |
| ML_DSA_65_CKA_PUBLIC_KEY_INFO_Pub | ✅ PASS | SPKI exposed |
| ML_DSA_65_CKA_PUBLIC_KEY_INFO_Priv | ✅ PASS | SPKI exposed on private |
| ML_DSA_65_CKA_VERIFY | ✅ PASS |  |
| ML_DSA_65_CKA_SIGN | ✅ PASS |  |
| ML_DSA_87_CKA_VALUE_Pub | ✅ PASS | §1.21 G-ATTR1 check |
| ML_DSA_87_CKA_PUBLIC_KEY_INFO_Pub | ✅ PASS | SPKI exposed |
| ML_DSA_87_CKA_PUBLIC_KEY_INFO_Priv | ✅ PASS | SPKI exposed on private |
| ML_DSA_87_CKA_VERIFY | ✅ PASS |  |
| ML_DSA_87_CKA_SIGN | ✅ PASS |  |

### AuthWrap

| Test | Status | Details |
|---|---|---|
| C_WrapKeyAuthenticated | ✅ PASS | RV=0 |
| C_UnwrapKeyAuthenticated | ✅ PASS | RV=0 |
| Value_Match | ✅ PASS | Unwrapped keys perfectly match |
| NIST_SP800_38D_KAT | ✅ PASS | Unwrapped GCM payload perfectly matches NIST Test Case 4 PT |

### ChaCha20

| Test | Status | Details |
|---|---|---|
| C_CreateObject | ✅ PASS | Created CKK_CHACHA20 Secret Key |
| C_Encrypt | ✅ PASS | Generated properly with 16 byte MAC tag |

### CkaIdRetrieval

| Test | Status | Details |
|---|---|---|
| Setup_KeyGen | ✅ PASS | ML-DSA-65 keypair generated with explicit CKA_ID + CKA_PRIVATE=false on pubkey |
| FindByCkaId_Pubkey_LoggedIn | ✅ PASS | C_FindObjects(CKA_CLASS=PUBLIC,CKA_ID) returned 1 object(s) |
| FindByCkaId_Privkey_LoggedIn | ✅ PASS | C_FindObjects(CKA_CLASS=PRIVATE,CKA_ID) returned 1 object(s) |
| FindByCkaId_Pubkey_NoLogin | ✅ PASS | C_FindObjects(public RO,CKA_CLASS=PUBLIC,CKA_ID) returned 1 object(s); CKA_PRIVATE on hit = 0 |
| Default_CkaPrivate_Pubkey | ✅ PASS | PKCS#11 v3.2 §4.5: pubkey CKA_PRIVATE default expected FALSE; got 0 |
| Default_CkaPrivate_Pubkey_NoLoginFind | ✅ PASS | Default-CKA_PRIVATE pubkey findable from no-login session: count=1 |

### Classical

| Test | Status | Details |
|---|---|---|
| Generate_RSA_2048 | ✅ PASS | RV=0 |
| C_Sign_RSA_SHA256 | ✅ PASS | RV=0 |

### DSA

| Test | Status | Details |
|---|---|---|
| Generate_ML_DSA_44 | ✅ PASS | Gen ML-DSA-44 |
| C_Sign_44_Pure | ✅ PASS | RV=0 |
| C_Verify_44_Pure | ✅ PASS | RV=0 |
| C_Sign_44_PreHash_SHA512 | ✅ PASS | RV=0 |
| C_Verify_44_PreHash_SHA512 | ✅ PASS | RV=0 |
| C_Sign_44_PreHash_SHA3_512 | ✅ PASS | RV=0 |
| C_Verify_44_PreHash_SHA3_512 | ✅ PASS | RV=0 |
| Generate_ML_DSA_65 | ✅ PASS | Gen ML-DSA-65 |
| C_Sign_65_Pure | ✅ PASS | RV=0 |
| C_Verify_65_Pure | ✅ PASS | RV=0 |
| C_Sign_65_PreHash_SHA512 | ✅ PASS | RV=0 |
| C_Verify_65_PreHash_SHA512 | ✅ PASS | RV=0 |
| C_Sign_65_PreHash_SHA3_512 | ✅ PASS | RV=0 |
| C_Verify_65_PreHash_SHA3_512 | ✅ PASS | RV=0 |
| Generate_ML_DSA_87 | ✅ PASS | Gen ML-DSA-87 |
| C_Sign_87_Pure | ✅ PASS | RV=0 |
| C_Verify_87_Pure | ✅ PASS | RV=0 |
| C_Sign_87_PreHash_SHA512 | ✅ PASS | RV=0 |
| C_Verify_87_PreHash_SHA512 | ✅ PASS | RV=0 |
| C_Sign_87_PreHash_SHA3_512 | ✅ PASS | RV=0 |
| C_Verify_87_PreHash_SHA3_512 | ✅ PASS | RV=0 |

### DSA-CTX

| Test | Status | Details |
|---|---|---|
| Setup_KeyGen_MLDSA65 | ✅ PASS | ML-DSA-65 keypair generated |
| Sign_ctxA | ✅ PASS | siglen=3309 |
| Verify_ctxA_matching | ✅ PASS | expected CKR_OK got RV=0 |
| Verify_ctxB_should_fail | ✅ PASS | binding works; RV=192 |
| Verify_noctx_should_fail | ✅ PASS | binding enforced; RV=192 |
| Deterministic_byte_equal | ✅ PASS | deterministic mode produces identical signatures (FIPS 204) |
| Hedge_non_deterministic | ✅ PASS | hedged mode produces distinct signatures (probabilistic) |

### Discovery

| Test | Status | Details |
|---|---|---|
| CKM_ML_KEM | ✅ PASS | PQC KEM support advertised |
| CKM_ML_DSA | ✅ PASS | PQC DSA support advertised |
| CKM_SLH_DSA | ✅ PASS | PQC SLH-DSA support advertised |
| CKM_XMSS | ✅ PASS | PQC XMSS support advertised |
| CKM_AES_CTR | ✅ PASS | AES CTR support (v3.2/5G) advertised |
| CKM_CHACHA20_POLY1305 | ✅ PASS | ChaCha20 support (RFC 7539) advertised |
| CKM_HKDF_DERIVE | ✅ PASS | HKDF support (v3.0/5G) advertised |
| CKM_RIPEMD160 | ✅ PASS | RIPEMD160 support advertised |

### ECDH

| Test | Status | Details |
|---|---|---|
| Generate_X25519 | ✅ PASS | RV=0 |
| Derive_X25519 | ✅ PASS | RV=0 |
| Derive_X25519_Cofactor | ✅ PASS | RV=0 |

### ECDSA

| Test | Status | Details |
|---|---|---|
| Generate_P256 | ✅ PASS | RV=0 |
| Sign_P256 | ✅ PASS | RV=0 |
| Generate_P521 | ✅ PASS | RV=0 |
| Sign_P521 | ✅ PASS | RV=0 |
| Generate_secp256k1 | ✅ PASS | RV=0 |
| Sign_secp256k1 | ✅ PASS | RV=0 |
| Generate_P256_SHA3_256 | ✅ PASS | RV=0 |
| Sign_P256_SHA3_256 | ✅ PASS | RV=0 |
| Generate_P521_SHA3_512 | ✅ PASS | RV=0 |
| Sign_P521_SHA3_512 | ✅ PASS | RV=0 |

### EdDSA

| Test | Status | Details |
|---|---|---|
| Generate_Ed25519 | ✅ PASS | RV=0 |
| Sign_Ed25519 | ✅ PASS | RV=0 |
| Generate_Ed448 | ✅ PASS | RV=0 |
| Sign_Ed448 | ✅ PASS | RV=0 |

### FIPS

| Test | Status | Details |
|---|---|---|
| ML-KEM_Truncated_CT | ✅ PASS | RV=274 |
| ML-KEM_Implicit_Rejection | ✅ PASS | Yielded deterministic random secret per FIPS 203 |
| ML-DSA_Oversized_Ctx | ✅ PASS | ctx>255 must be rejected, RV=7 |

### Init

| Test | Status | Details |
|---|---|---|
| TokenSetup | ✅ PASS | Initialized token and session |

### KCV

| Test | Status | Details |
|---|---|---|
| AES_Generate_KCV_Present | ✅ PASS | 3 bytes: 9005E5 |
| AES_Generate_KCV_Equals_OracleEcbZeroBlock | ✅ PASS | HSM=9005E5 == oracle=9005E5 |
| AES_Unwrap_KCV_Present | ✅ PASS | 3 bytes: EB0E41 |
| AES_Unwrap_KCV_Equals_Original | ✅ PASS | original=EB0E41 unwrapped=EB0E41 |
| AES_Unwrap_KCV_Equals_OracleEcbZeroBlock | ✅ PASS | matches AES-ECB(zero block)[0:3] oracle |
| HKDF_Derive_KCV_Present | ✅ PASS | 3 bytes: BEEF61 |
| HKDF_Derive_KCV_Equals_OracleSha1 | ✅ PASS | HSM=BEEF61 == oracle=BEEF61 |
| PBKD2_Derive_KCV_Present | ✅ PASS | 3 bytes: 89AE12 |
| PBKD2_Derive_KCV_Equals_OracleSha1 | ✅ PASS | HSM=89AE12 == oracle=89AE12 |
| SP800_108_Counter_Derive_KCV_Present | ✅ PASS | 3 bytes: C2450B |
| SP800_108_Counter_Derive_KCV_Equals_OracleSha1 | ✅ PASS | HSM=C2450B == oracle=C2450B |
| SP800_108_Feedback_Derive_KCV_Present | ✅ PASS | 3 bytes: 4A4E69 |
| SP800_108_Feedback_Derive_KCV_Equals_OracleSha1 | ✅ PASS | HSM=4A4E69 == oracle=4A4E69 |

### KDF

| Test | Status | Details |
|---|---|---|
| CKM_PKCS5_PBKD2 | ✅ PASS | RV=0 |
| CKM_SP800_108_COUNTER_KDF | ❌(known) XFAIL | ENGINE BUG: spec PRF CKM_SHA256_HMAC rejected, RV=113 (engine only accepts bare-hash PRF identifiers) |
| SP800_108_BareHash_PRF_Rejected | ❌(known) XFAIL | ENGINE BUG: bare CKM_SHA256 accepted as PRF (RV=0); spec requires a keyed MAC mechanism |
| CKM_SP800_108_COUNTER_KDF_CMAC | ✅ PASS | AES-CMAC PRF, RV=0 |
| CKM_SP800_108_FEEDBACK_KDF | ✅ PASS | AES-CMAC PRF, RV=0 |
| CKM_HKDF_DERIVE | ✅ PASS | RV=0 |

### KEM

| Test | Status | Details |
|---|---|---|
| Generate_ML_KEM_512 | ✅ PASS | Gen ML-KEM-512 |
| C_EncapsulateKey_512 | ✅ PASS | CT len=768 |
| C_DecapsulateKey_512 | ✅ PASS | SS matched |
| Generate_ML_KEM_768 | ✅ PASS | Gen ML-KEM-768 |
| C_EncapsulateKey_768 | ✅ PASS | CT len=1088 |
| C_DecapsulateKey_768 | ✅ PASS | SS matched |
| Generate_ML_KEM_1024 | ✅ PASS | Gen ML-KEM-1024 |
| C_EncapsulateKey_1024 | ✅ PASS | CT len=1568 |
| C_DecapsulateKey_1024 | ✅ PASS | SS matched |

### MsgCrypt

| Test | Status | Details |
|---|---|---|
| C_MessageEncryptInit | ✅ PASS | RV=0 |
| C_EncryptMessageBegin_IV12 | ✅ PASS | RV=0 |
| C_EncryptMessageBegin_IV16 | ✅ PASS | RV=0 |
| C_EncryptMessageBegin_IV8 | ✅ PASS | RV=0 |

### MsgSign

| Test | Status | Details |
|---|---|---|
| C_MessageSignInit | ✅ PASS | RV=0 |
| C_SignMessageBegin | ✅ PASS | RV=0 |
| C_SignMessageNext | ✅ PASS | RV=0 SigLen=128 |
| C_MessageSignInit_RSA_RejectsSignCtxParam | ✅ PASS | expected CKR_MECHANISM_PARAM_INVALID, got RV=113 |

### MultiPart

| Test | Status | Details |
|---|---|---|
| Setup_KeyGen | ✅ PASS | ML-DSA-65 key pair generated |
| C_SignInit | ✅ PASS | PKCS#11 v3.2 §5.2 — RV=0 |
| C_SignUpdate_chunk1 | ✅ PASS | RV=0 |
| C_SignUpdate_chunk2 | ✅ PASS | RV=0 |
| C_SignFinal | ✅ PASS | SigLen=3309 RV=0 |
| C_VerifyInit | ✅ PASS | RV=0 |
| C_VerifyUpdate_chunk1 | ✅ PASS | RV=0 |
| C_VerifyUpdate_chunk2 | ✅ PASS | RV=0 |
| C_VerifyFinal | ✅ PASS | PKCS#11 v3.2 §5.2 round-trip — RV=0 |
| C_Verify_oneshot_xcheck | ✅ PASS | Multi-part sig matches one-shot verify — RV=0 |

### MultiPart_ECDSA

| Test | Status | Details |
|---|---|---|
| Setup_KeyGen | ✅ PASS | P-256 key pair generated |
| C_SignInit | ✅ PASS | CKM_ECDSA_SHA256 — RV=0 |
| C_SignUpdate_chunk1 | ✅ PASS | RV=0 |
| C_SignUpdate_chunk2 | ✅ PASS | RV=0 |
| C_SignFinal | ✅ PASS | SigLen=64 RV=0 |
| C_VerifyInit | ✅ PASS | RV=0 |
| C_VerifyUpdate_chunk1 | ✅ PASS | RV=0 |
| C_VerifyUpdate_chunk2 | ✅ PASS | RV=0 |
| C_VerifyFinal | ✅ PASS | PKCS#11 v3.2 §5.2 P-256 round-trip — RV=0 |
| C_Verify_oneshot_xcheck | ✅ PASS | Multi-part sig matches one-shot verify — RV=0 |

### MultiPart_EdDSA

| Test | Status | Details |
|---|---|---|
| Setup_KeyGen | ✅ PASS | Ed25519 key pair generated |
| C_SignInit | ✅ PASS | CKM_EDDSA — RV=0 |
| C_SignUpdate_chunk1 | ✅ PASS | RV=0 |
| C_SignUpdate_chunk2 | ✅ PASS | RV=0 |
| C_SignFinal | ✅ PASS | SigLen=64 RV=0 |
| C_VerifyInit | ✅ PASS | RV=0 |
| C_VerifyUpdate_chunk1 | ✅ PASS | RV=0 |
| C_VerifyUpdate_chunk2 | ✅ PASS | RV=0 |
| C_VerifyFinal | ✅ PASS | PKCS#11 v3.2 §5.2 Ed25519 round-trip — RV=0 |
| C_Verify_oneshot_xcheck | ✅ PASS | Multi-part sig matches one-shot verify — RV=0 |

### Negative

| Test | Status | Details |
|---|---|---|
| Sign_With_KEM_Key | ✅ PASS | Expected CKR_KEY_FUNCTION_NOT_PERMITTED, got 99 |
| Boolean_Policy_Violation | ✅ PASS | Expected CKR_KEY_FUNCTION_NOT_PERMITTED, got 104 |
| Extraction_Constraint | ✅ PASS | Expected CKR_ATTRIBUTE_SENSITIVE, got 17 |
| Template_Incomplete_Create | ✅ PASS | Expected CKR_TEMPLATE_INCOMPLETE, got 208 |
| Signature_Len_Range | ✅ PASS | Expected CKR_SIGNATURE_LEN_RANGE, got 193 |
| Signature_Forgery_Invalid | ✅ PASS | Expected CKR_SIGNATURE_INVALID, got 192 |

### SHA-3

| Test | Status | Details |
|---|---|---|
| DigestInit_256 | ✅ PASS | RV=0 |

### SLHDSA

| Test | Status | Details |
|---|---|---|
| Generate_SLH_DSA_SHA2_128S | ✅ PASS | Gen SLH-DSA-SHA2_128S |
| C_Sign_SHA2_128S_Deterministic_Ctx | ✅ PASS | RV=0 |
| Generate_SLH_DSA_SHA2_128F | ✅ PASS | Gen SLH-DSA-SHA2_128F |
| C_Sign_SHA2_128F_Deterministic_Ctx | ✅ PASS | RV=0 |
| Generate_SLH_DSA_SHA2_256F | ✅ PASS | Gen SLH-DSA-SHA2_256F |
| C_Sign_SHA2_256F_Deterministic_Ctx | ✅ PASS | RV=0 |

### Session

| Test | Status | Details |
|---|---|---|
| C_OpenSession_InvalidSlot | ✅ PASS | RV=3 |
| C_SetAttributeValue_RO | ✅ PASS | RV=181 |
| Session_Object_CrossVisibility | ✅ PASS | Visible (Compliant) |
| C_SessionCancel | ✅ PASS | cancel OK; post-cancel C_Sign expected CKR_OPERATION_NOT_INITIALIZED, got RV=145 |
| C_LoginUser | ✅ PASS | RV=256 |

### XMSS

| Test | Status | Details |
|---|---|---|
| Generate_XMSS_SHA2_10_256 | ✅ PASS | Gen XMSS_SHA2_10_256 |
| C_Sign_XMSS_SHA2_10_256 | ✅ PASS | RV=0 |
| Generate_XMSSMT_SHA2_20_2_256 | ⚠️ SKIP | Mech unavailable |

