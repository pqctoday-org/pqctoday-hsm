# PKCS#11 v3.2 Compliance Report

**Engine:** `./build/src/lib/libsofthsmv3.dylib`
**Timestamp:** Generated automatically

## Summary
- **Total PASS:** 46
- **Total FAIL:** 1
- **Total SKIP:** 0

### Attributes

| Test | Status | Details |
|---|---|---|
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

### Init

| Test | Status | Details |
|---|---|---|
| TokenSetup | ✅ PASS | Initialized token and session |

### MultiPart

| Test | Status | Details |
|---|---|---|
| Setup_KeyGen | ✅ PASS | ML-DSA-65 key pair generated |
| C_SignInit | ✅ PASS | PKCS#11 v3.2 §5.2 — RV=0 |
| C_SignUpdate_chunk1 | ❌ FAIL | RV=145 |

