# PKCS#11 v3.2 Compliance Report

**Engine:** `/Users/pqctoday/Antigravity/.worktrees/pqctoday-hsm-pkcs11-parity/build/src/lib/libsofthsmv3.dylib`
**Date:** 2026-07-25 13:46:22 CDT

## Summary
- **Total PASS:** 324
- **Total FAIL:** 0
- **Total SKIP:** 0
- **Total XFAIL (known engine bugs, documented in-line):** 0

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
| Derive_X25519_Cofactor_Rejected | ✅ PASS | RV=99 |

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

### G-DA-X

| Test | Status | Details |
|---|---|---|
| RIPEMD160_digest_KAT | ✅ PASS | RIPEMD-160(abc) matches KAT, distinct from SHA-1 |
| RIPEMD160_HMAC_roundtrip | ✅ PASS | HMAC-RIPEMD-160 sign/verify round-trip OK (20-byte MAC) |

### G1Security

| Test | Status | Details |
|---|---|---|
| GCM_zeroIV_EncryptInit_rejected | ✅ PASS | C++C-1 expect CKR_MECHANISM_PARAM_INVALID, RV=113 |
| GCM_zeroIV_DecryptInit_rejected | ✅ PASS | C++C-1 expect CKR_MECHANISM_PARAM_INVALID, RV=113 |
| GCM_validIV_EncryptInit_accepted | ✅ PASS | valid 12-byte IV must still work, RV=0 |
| ChaCha_wrongNonce_rejected | ✅ PASS | C++C-2 expect CKR_MECHANISM_PARAM_INVALID for 8-byte nonce, RV=113 |
| ChaCha_zeroNonce_rejected | ✅ PASS | C++C-1/2 expect CKR_MECHANISM_PARAM_INVALID for 0-byte nonce, RV=113 |
| XMSS_largeMsg_sign | ✅ PASS | C++C-3 64KiB message sign, RV=0 |
| HSS_private_roundtrip | ✅ PASS | V-13 keygen→sign→verify, verify RV=0 |

### G2ChaCha20

| Test | Status | Details |
|---|---|---|
| Keygen_KeyType | ✅ PASS | CKA_KEY_TYPE=0x51 want CKK_CHACHA20(0x33) |
| Keygen_GenMech | ✅ PASS | CKA_KEY_GEN_MECHANISM=0x4645 |
| Encrypt | ✅ PASS | ctLen=38 |
| RoundTrip | ✅ PASS | decrypt matched plaintext |

### G2Derive

| Test | Status | Details |
|---|---|---|
| X25519_Reachable | ✅ PASS | C_DeriveKey RV=5 (must not be CKR_MECHANISM_INVALID) |
| BIP32_Reachable | ✅ PASS | C_DeriveKey RV=7 (must not be CKR_MECHANISM_INVALID) |

### G2MechTable

| Test | Status | Details |
|---|---|---|
| Size_ML_DSA_KEY_PAIR_GEN | ✅ PASS | min=1312 max=2592 expected 1312/2592 |
| Size_ML_DSA | ✅ PASS | min=1312 max=2592 expected 1312/2592 |
| Size_SLH_DSA_KEY_PAIR_GEN | ✅ PASS | min=32 max=64 expected 32/64 |
| Size_SLH_DSA | ✅ PASS | min=32 max=64 expected 32/64 |
| Advertised_CKM_RIPEMD160 | ✅ PASS | RIPEMD-160 digest dispatched (legacy provider) |
| Advertised_CKM_RIPEMD160_HMAC | ✅ PASS | HMAC-RIPEMD-160 dispatched (legacy provider) |
| NotAdvertised_CKM_KECCAK_256 | ✅ PASS | correctly absent from C_GetMechanismList |
| Advertised_CKM_CHACHA20 | ✅ PASS | bare ChaCha20 stream dispatched |
| Advertised_CKM_X25519 | ✅ PASS | X25519 derive |
| Advertised_CKM_X448 | ✅ PASS | X448 derive |
| Advertised_CKM_BIP32_MASTER_DERIVE | ✅ PASS | BIP32 derive |
| Advertised_CKM_RSA_PKCS_PSS | ✅ PASS | raw RSA-PSS |
| Flag_AES_GCM_MESSAGE | ✅ PASS | flags=0x774 want 0x6 |
| Flag_ML_DSA_MESSAGE | ✅ PASS | flags=0x10264 want 0x24 |
| Flag_SLH_DSA_MESSAGE | ✅ PASS | flags=0x10264 want 0x24 |
| AdvertiseSubsetDispatch | ✅ PASS | 126 advertised, 0 rejected by C_GetMechanismInfo |

### G3Keygen

| Test | Status | Details |
|---|---|---|
| V4_wrongKeyType_ML_KEM_vs_XMSSMT | ✅ PASS | expect CKR_TEMPLATE_INCONSISTENT, RV=209 |
| V4_wrongKeyType_EC_vs_ML_KEM | ✅ PASS | expect CKR_TEMPLATE_INCONSISTENT, RV=209 |
| V4_wrongKeyType_HSS_vs_XMSS | ✅ PASS | expect CKR_TEMPLATE_INCONSISTENT, RV=209 |
| V4_wrongKeyType_XMSS_vs_HSS | ✅ PASS | expect CKR_TEMPLATE_INCONSISTENT, RV=209 |
| V4_wrongKeyType_XMSSMT_vs_XMSS | ✅ PASS | expect CKR_TEMPLATE_INCONSISTENT, RV=209 |
| V4_wrongKeyType_ChaCha20_vs_AES | ✅ PASS | expect CKR_TEMPLATE_INCONSISTENT, RV=209 |
| V3_missingParamSet_ML_DSA | ✅ PASS | expect CKR_TEMPLATE_INCOMPLETE, RV=208 |
| V3_missingParamSet_ML_KEM | ✅ PASS | expect CKR_TEMPLATE_INCOMPLETE, RV=208 |
| V3_missingParamSet_SLH_DSA | ✅ PASS | expect CKR_TEMPLATE_INCOMPLETE, RV=208 |
| V8_XMSSMT_keygen | ✅ PASS | XMSSMT key generated |
| V9_XMSSMT_sign_verify_roundtrip | ✅ PASS | Verify RV=0 |
| V21_HSS_keys_remaining | ✅ PASS | expect 2^5=32 for default LMS_SHA256_N32_H5, got 32 (RV=0) |
| V5V6_AES_CBC_wrap_unwrap | ✅ PASS | round-trip byte-exact; recoveredLen=32 expected=32 (RV=0) |
| V5V6_AES_CBC_PAD_wrap_unwrap | ✅ PASS | round-trip byte-exact; recoveredLen=20 expected=20 (RV=0) |

### G4Retcodes

| Test | Status | Details |
|---|---|---|
| V19_GSVF_pre_init | ✅ PASS | expect CKR_CRYPTOKI_NOT_INITIALIZED, RV=400 |
| GA_AsyncComplete_pre_init | ✅ PASS | expect CKR_CRYPTOKI_NOT_INITIALIZED, RV=400 |
| GA_AsyncGetID_pre_init | ✅ PASS | expect CKR_CRYPTOKI_NOT_INITIALIZED, RV=400 |
| GA_AsyncJoin_pre_init | ✅ PASS | expect CKR_CRYPTOKI_NOT_INITIALIZED, RV=400 |
| V20_Initialize_pReserved_nonNULL | ✅ PASS | expect CKR_ARGUMENTS_BAD(0x7), RV=7 |
| V7_AESKW_tampered_unwrap | ✅ PASS | expect CKR_WRAPPED_KEY_INVALID(0x110), RV=272 |
| V16_SessionCancel_flags0_noop | ✅ PASS | flags==0 expect CKR_OK no-op, RV=0 |
| V16_SessionCancel_unmatched_ignored | ✅ PASS | unmatched flag expect CKR_OK ignore, RV=0 |
| V16_SessionCancel_unmatched_keeps_op | ✅ PASS | sign op survives unmatched cancel, RV=0 |
| V16_SessionCancel_CKF_MESSAGE_SIGN | ✅ PASS | cancel active message-sign expect CKR_OK, RV=0 |
| V17_Digest_after_DigestUpdate | ✅ PASS | expect CKR_OPERATION_ACTIVE(0x90), RV=144 |
| V17_Digest_op_survives | ✅ PASS | C_DigestFinal after rejected one-shot, RV=0 |
| V17_Sign_after_SignUpdate | ✅ PASS | expect CKR_OPERATION_ACTIVE(0x90), RV=144 |
| V17_Sign_op_survives | ✅ PASS | C_SignFinal after rejected one-shot, RV=0 |
| V18_WrapAuth_buffer_too_small_sets_len | ✅ PASS | expect CKR_BUFFER_TOO_SMALL + outLen==48, got RV=336 outLen=48 |
| V19_GSVF_bad_handle | ✅ PASS | expect CKR_SESSION_HANDLE_INVALID, RV=179 |
| V19_GSVF_valid | ✅ PASS | expect CKR_OK + flags=0, RV=0 flags=0 |
| V19_GSVF_bad_type | ✅ PASS | expect CKR_ARGUMENTS_BAD, RV=7 |
| GAP24_Encap_bad_pubkey | ✅ PASS | expect CKR_KEY_HANDLE_INVALID(0x60), RV=96 |
| GAP65_DeriveKey_bad_base | ✅ PASS | expect CKR_KEY_HANDLE_INVALID(0x60), RV=96 |

### G5Attrs

| Test | Status | Details |
|---|---|---|
| UniqueId_readable_on_private_key | ✅ PASS | CKA_UNIQUE_ID on a PRIVATE/SENSITIVE key must read in clear (36-byte UUID), expect RV=CKR_OK; got RV=0 len=36 |
| UniqueId_readable_on_sensitive_secret | ✅ PASS | CKA_UNIQUE_ID on a SENSITIVE secret key must read in clear (36-byte UUID), expect RV=CKR_OK; got RV=0 len=36 |
| V14_CopyObject_freshUniqueId | ✅ PASS | src and copy must each have a distinct CKA_UNIQUE_ID (src len=36 copy len=36 distinct=yes) |
| V15_CreateObject_uniqueId_readonly | ✅ PASS | caller-supplied CKA_UNIQUE_ID must be rejected, expect CKR_ATTRIBUTE_READ_ONLY(0x10) RV=16 |
| V15_DeriveKey_uniqueId_tokenAssigned | ✅ PASS | forged CKA_UNIQUE_ID rejected with CKR_ATTRIBUTE_READ_ONLY |
| CKA_SEED_deterministic_ML_DSA_44 | ✅ PASS | same seed must yield identical public key (lenA=1312 lenB=1312) |
| CKA_SEED_sensitive_ML_DSA_44 | ✅ PASS | seed on a sensitive key must not leak, expect CKR_ATTRIBUTE_SENSITIVE(0x11) RV=17 |
| CKA_SEED_wronglen_ML_DSA_44 | ✅ PASS | wrong seed length must be rejected, expect CKR_ATTRIBUTE_VALUE_INVALID(0x13) RV=19 |
| CKA_SEED_deterministic_ML_KEM_768 | ✅ PASS | same seed must yield identical public key (lenA=1184 lenB=1184) |
| CKA_SEED_sensitive_ML_KEM_768 | ✅ PASS | seed on a sensitive key must not leak, expect CKR_ATTRIBUTE_SENSITIVE(0x11) RV=17 |
| CKA_SEED_wronglen_ML_KEM_768 | ✅ PASS | wrong seed length must be rejected, expect CKR_ATTRIBUTE_VALUE_INVALID(0x13) RV=19 |
| CKA_SEED_deterministic_SLH_DSA_128s | ✅ PASS | same seed must yield identical public key (lenA=32 lenB=32) |
| CKA_SEED_sensitive_SLH_DSA_128s | ✅ PASS | seed on a sensitive key must not leak, expect CKR_ATTRIBUTE_SENSITIVE(0x11) RV=17 |
| CKA_SEED_wronglen_SLH_DSA_128s | ✅ PASS | wrong seed length must be rejected, expect CKR_ATTRIBUTE_VALUE_INVALID(0x13) RV=19 |

### G7Sha3Rsa

| Test | Status | Details |
|---|---|---|
| Advertised_CKM_SHA3_384_RSA_PKCS | ✅ PASS | SHA3-384 RSA PKCS#1 v1.5 |
| Advertised_CKM_SHA3_384_RSA_PKCS_PSS | ✅ PASS | SHA3-384 RSA-PSS |
| Generate_RSA_2048 | ✅ PASS | RV=0 |
| C_SignInit_PKCS | ✅ PASS | RV=0 |
| C_Sign_PKCS | ✅ PASS | RV=0 |
| C_Verify_PKCS | ✅ PASS | RV=0 |
| C_SignInit_PSS | ✅ PASS | RV=0 |
| C_Sign_PSS | ✅ PASS | RV=0 |
| C_Verify_PSS | ✅ PASS | RV=0 |
| C_SignInit_PSS_wrong_hashAlg | ✅ PASS | expected ARGUMENTS_BAD/MECHANISM_PARAM_INVALID, RV=7 |

### G8Dual

| Test | Status | Details |
|---|---|---|
| DigestEncrypt_dual_init | ✅ PASS | DigestInit+EncryptInit must coexist (§5.13) RV=0 |
| DigestEncrypt_ciphertext_matches | ✅ PASS | dual ciphertext == standalone encrypt, RV=0 |
| DigestEncrypt_digest_matches | ✅ PASS | dual digest == standalone SHA-256, RV=0 |
| DecryptDigest_dual_init | ✅ PASS | DecryptInit+DigestInit must coexist (§5.13) RV=0 |
| DecryptDigest_digest_roundtrip | ✅ PASS | digest of decrypted plaintext == original digest, RV=0 |
| SignEncrypt_dual_init | ✅ PASS | SignInit+EncryptInit must coexist (§5.13) RV=0 |
| SignEncrypt_ciphertext_matches | ✅ PASS | dual ciphertext == standalone encrypt, RV=0 |
| SignEncrypt_signature_verifies | ✅ PASS | ECDSA signature over streamed data verifies RV=0 |
| DecryptVerify_dual_init | ✅ PASS | DecryptInit+VerifyInit must coexist (§5.13) RV=0 |
| DecryptVerify_roundtrip | ✅ PASS | verify of decrypted plaintext succeeds RV=0 |
| DigestEncrypt_missing_digest_rejected | ✅ PASS | expect CKR_OPERATION_NOT_INITIALIZED(0x91) RV=145 |
| DigestFinal_then_DigestUpdate_safe | ✅ PASS | freed digest half: C_DigestUpdate must return 0x91, not crash, RV=145 |
| DigestFinal_then_Digest_safe | ✅ PASS | freed digest half: one-shot C_Digest must return 0x91, not crash, RV=145 |
| DigestFinal_then_EncryptFinal_correct | ✅ PASS | surviving cipher half finalises to correct ciphertext after digest ended, RV=0 |
| EncryptFinal_then_DigestFinal_correct | ✅ PASS | reverse-order finalise: cipher then digest both correct, RV=0 |

### GAsync

| Test | Status | Details |
|---|---|---|
| TokenInfo_no_async_support | ✅ PASS | CKF_ASYNC_SESSION_SUPPORTED must not be set, flags=0x1069 |
| OpenSession_async_rejected | ✅ PASS | expect CKR_SESSION_ASYNC_NOT_SUPPORTED(0x205), RV=517 |
| OpenSession_sync_ok | ✅ PASS | expect CKR_OK, RV=0 |
| C_AsyncComplete_not_supported | ✅ PASS | expect CKR_FUNCTION_NOT_SUPPORTED(0x54), RV=84 |
| C_AsyncGetID_not_supported | ✅ PASS | expect CKR_FUNCTION_NOT_SUPPORTED(0x54), RV=84 |
| C_AsyncJoin_not_supported | ✅ PASS | expect CKR_FUNCTION_NOT_SUPPORTED(0x54), RV=84 |

### GIsolation

| Test | Status | Details |
|---|---|---|
| InitTokenB | ✅ PASS | second token initialized on slot 1 |
| CreateTokenObjectA | ✅ PASS | token object handle minted on token A |
| SameToken_CrossSession_resolves | ✅ PASS | token object must be visible to all sessions on token A, RV=0 |
| CrossToken_GetAttributeValue_rejected | ✅ PASS | §2.4 expect CKR_OBJECT_HANDLE_INVALID, RV=130 |
| CrossToken_SetAttributeValue_rejected | ✅ PASS | §2.4 expect CKR_OBJECT_HANDLE_INVALID, RV=130 |
| CrossToken_AsKeyHandle_rejected | ✅ PASS | §2.4 key-use must be rejected (engine returns OBJECT_HANDLE_INVALID), RV=130 |
| CrossToken_DestroyObject_rejected | ✅ PASS | §2.4 expect CKR_OBJECT_HANDLE_INVALID, RV=130 |
| CrossToken_Destroy_didNotAffectA | ✅ PASS | A's object must survive a rejected cross-token destroy, RV=0 |

### HybridKEM

| Test | Status | Details |
|---|---|---|
| Generate_X25519 | ✅ PASS |  |
| Generate_ML_KEM_768 | ✅ PASS |  |
| Encapsulate_X25519_half | ✅ PASS | ephemeral pubkey len=34 |
| Encapsulate_MLKEM_half | ✅ PASS | ct len=1088 |
| Combine_send | ✅ PASS |  |
| Decapsulate_X25519_half | ✅ PASS |  |
| Decapsulate_MLKEM_half | ✅ PASS |  |
| Combine_recv | ✅ PASS |  |
| X25519MLKEM768_round_trip | ✅ PASS | combined secret len=64 (32 ss_mlkem || 32 ss_x25519) |

### Init

| Test | Status | Details |
|---|---|---|
| TokenSetup | ✅ PASS | Initialized token and session |

### KCV

| Test | Status | Details |
|---|---|---|
| AES_Generate_KCV_Present | ✅ PASS | 3 bytes: B44E1B |
| AES_Generate_KCV_Equals_OracleEcbZeroBlock | ✅ PASS | HSM=B44E1B == oracle=B44E1B |
| AES_Unwrap_KCV_Present | ✅ PASS | 3 bytes: A451B8 |
| AES_Unwrap_KCV_Equals_Original | ✅ PASS | original=A451B8 unwrapped=A451B8 |
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
| CKM_SP800_108_COUNTER_KDF | ✅ PASS | HMAC-SHA256 PRF, RV=0 |
| SP800_108_BareHash_PRF_Rejected | ✅ PASS | bare CKM_SHA256 PRF correctly rejected, RV=113 |
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
| StatefulSign_size_query_idempotent | ✅ PASS | two C_Sign(NULL) → same size 2500 RV1=0 RV2=0 |
| StatefulSign_buffer_too_small | ✅ PASS | too-small buffer → CKR_BUFFER_TOO_SMALL(0x150), size echoed, RV=336 |
| StatefulSign_signs_after_queries | ✅ PASS | real C_Sign after queries verifies (leaf not burned) signRV=0 verifyRV=0 |
| Generate_XMSSMT_SHA2_20_2_256 | ✅ PASS | Gen XMSSMT_SHA2_20_2_256 |

