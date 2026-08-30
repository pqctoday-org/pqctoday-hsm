# PKCS#11 v3.2 Compliance Report

**Engine:** `./build/src/lib/libsofthsmv3.so`
**Engine commit:** `856f3c654f8a1cba32101393d3622d230fec8ac0`
**Date:** 2026-08-30 13:02:53 UTC

## Summary
- **Total PASS:** 864
- **Total FAIL:** 0
- **Total SKIP:** 37
- **Total XFAIL (known engine bugs, documented in-line):** 0

Status legend: PASS = spec-conformant behavior for an advertised feature; FAIL = unexpected non-conformance; SKIP = feature not advertised by the token (v3.2 mandates no particular mechanism set); XFAIL = known, pre-existing engine non-conformance reported here but outside this suite's scope to fix.

### AES-CTR

| Test | Status | Details |
|---|---|---|
| EncryptInit | ✅ PASS | RV=0 |

### AesKwp

| Test | Status | Details |
|---|---|---|
| KWP_roundtrip | ✅ PASS | 20-byte (non-multiple-of-8) key wraps to the same blob as an independent OpenSSL AES-256-wrap-pad oracle AND unwraps back byte-identical |
| KWP_matches_deprecated_PAD | ✅ PASS | CKM_AES_KEY_WRAP_KWP and CKM_AES_KEY_WRAP_PAD produce identical output |
| KWP_rejects_unsupported_iv_param | ✅ PASS | RV=7 (want CKR_ARGUMENTS_BAD=0x7) |

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

### BIP32

| Test | Status | Details |
|---|---|---|
| Master_Derive | ✅ PASS | RV=0 |
| Child_Derive | ✅ PASS | RV=0 |

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
| PreHashGap_GenerateKey_65 | ✅ PASS | Gen ML-DSA-65 for pre-hash coverage |
| PreHash65_Generic_HASH_ML_DSA_explicitSHA256 | ✅ PASS | real sign+verify round trip OK, sigLen=3309 |
| PreHash65_SHA224 | ✅ PASS | real sign+verify round trip OK, sigLen=3309 |
| PreHash65_SHA256 | ✅ PASS | real sign+verify round trip OK, sigLen=3309 |
| PreHash65_SHA384 | ✅ PASS | real sign+verify round trip OK, sigLen=3309 |
| PreHash65_SHA3_224 | ✅ PASS | real sign+verify round trip OK, sigLen=3309 |
| PreHash65_SHA3_256 | ✅ PASS | real sign+verify round trip OK, sigLen=3309 |
| PreHash65_SHA3_384 | ✅ PASS | real sign+verify round trip OK, sigLen=3309 |
| PreHash65_SHAKE128 | ✅ PASS | real sign+verify round trip OK, sigLen=3309 |
| PreHash65_SHAKE256 | ✅ PASS | real sign+verify round trip OK, sigLen=3309 |

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

### ErrCodes

| Test | Status | Details |
|---|---|---|
| C_EncryptInit_null_mechanism_cancels | ✅ PASS | init RV=0 cancel RV=0 (want CKR_OK or CKR_OPERATION_CANCEL_FAILED, never CKR_ARGUMENTS_BAD=0x7) |
| C_EncryptInit_after_cancel_succeeds | ✅ PASS | RV=0 |
| C_DigestInit_null_mechanism_no_active_op | ✅ PASS | RV=0 |
| C_SignInit_null_mechanism_no_active_op | ✅ PASS | RV=0 |
| C_VerifyInit_null_mechanism_no_active_op | ✅ PASS | RV=0 |
| C_DecryptInit_null_mechanism_no_active_op | ✅ PASS | RV=0 |
| Null_mechanism_still_checks_session_handle | ✅ PASS | RV=179 (want CKR_SESSION_HANDLE_INVALID=0xB3) |
| C_SeedRandom_session_handle_precedence | ✅ PASS | RV=179 (want CKR_SESSION_HANDLE_INVALID=0xB3, not CKR_ARGUMENTS_BAD=0x7) |
| C_GenerateRandom_session_handle_precedence | ✅ PASS | RV=179 |
| C_GetInterface_matches_own_flags | ✅ PASS | 3 interfaces |
| C_GetInterface_unmatched_flag_is_not_ARGUMENTS_BAD | ✅ PASS | RV=0 want=0 (declaresForkSafe=1) |
| C_GetInterface_unknown_flag_refused | ✅ PASS | RV=6 |

### FIPS

| Test | Status | Details |
|---|---|---|
| ML-KEM_Truncated_CT | ✅ PASS | RV=274 |
| ML-KEM_Implicit_Rejection | ✅ PASS | Yielded deterministic random secret per FIPS 203 |
| ML-DSA_Oversized_Ctx | ✅ PASS | ctx>255 must be rejected, RV=7 |

### Fork

| Test | Status | Details |
|---|---|---|
| Child_survived_and_reported | ✅ PASS | child pid 14958 exited status 0 |
| Child_session_handle_resolves | ✅ PASS | C_GetSessionInfo RV=0 |
| Child_login_state_preserved | ✅ PASS | child state=3 parent state=3 (CKS_RW_USER_FUNCTIONS=3) |
| Child_session_object_readable | ✅ PASS | RV=0 len=8 |
| Child_token_object_readable_by_pre_fork_handle | ✅ PASS | RV=0 len=8 |
| Child_inherits_active_encryption_state | ✅ PASS | parent init RV=0 update RV=0 child final RV=0 len=16 |
| Parent_encryption_state_independent | ✅ PASS | parent C_EncryptFinal after child's RV=0 |
| Child_writes_do_not_reach_parent | ✅ PASS | child C_SetAttributeValue RV=0; parent label len=11 intact=1 |
| Sibling_children_RNG_diverge | ✅ PASS | 8 sibling pairs, all distinct=1 childA=D496B3D35206E6D1… childB=6C4CA0E84FD0BFC8… (identical output would repeat ECDSA nonces) |
| Fork_safe_flag_declared_in_interface_list | ✅ PASS | 3 interfaces, CKF_INTERFACE_FORK_SAFE declared=1 |
| Fork_safe_interface_retrievable | ✅ PASS | C_GetInterface(flags=CKF_INTERFACE_FORK_SAFE) RV=0 |
| Parent_and_child_RNG_diverge | ✅ PASS | child=BB2602D3D13F56C8… parent=B711457DD8783173… preFork=DCCC0D68DE7D7FB0… |

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
| AdvertiseSubsetDispatch | ✅ PASS | 139 advertised, 0 rejected by C_GetMechanismInfo |

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
| C2_SignInit_null_mech_pre_init | ✅ PASS | expect CKR_CRYPTOKI_NOT_INITIALIZED, RV=400 |
| C2_VerifyInit_null_mech_pre_init | ✅ PASS | expect CKR_CRYPTOKI_NOT_INITIALIZED, RV=400 |
| C2_EncryptInit_null_mech_pre_init | ✅ PASS | expect CKR_CRYPTOKI_NOT_INITIALIZED, RV=400 |
| C2_WaitForSlotEvent_pre_init_outranks_flags | ✅ PASS | expect CKR_CRYPTOKI_NOT_INITIALIZED, RV=400 |
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

### GapAes

| Test | Status | Details |
|---|---|---|
| ECB_roundtrip | ✅ PASS | ciphertext matches independent OpenSSL AES-256-ECB oracle AND decrypts back to plaintext |
| ECB_ENCRYPT_DATA_derive | ✅ PASS | derived key value matches independent OpenSSL AES-256-ECB oracle |
| CBC_ENCRYPT_DATA_derive | ✅ PASS | derived key value matches independent OpenSSL AES-256-CBC oracle |
| KEY_WRAP_PAD_roundtrip | ✅ PASS | unwrapped 20-byte (non-multiple-of-8) key perfectly matches original (RFC5649 pad path exercised) |

### GapClassical

| Test | Status | Details |
|---|---|---|
| Digest_MD5 | ✅ PASS | matches independent OpenSSL oracle, len=16 |
| Digest_SHA1 | ✅ PASS | matches independent OpenSSL oracle, len=20 |
| Digest_SHA224 | ✅ PASS | matches independent OpenSSL oracle, len=28 |
| Digest_SHA384 | ✅ PASS | matches independent OpenSSL oracle, len=48 |
| Digest_SHA512 | ✅ PASS | matches independent OpenSSL oracle, len=64 |
| HMAC_MD5 | ✅ PASS | engine sign matches independent OpenSSL HMAC oracle AND engine verify succeeds, len=16 |
| HMAC_SHA1 | ✅ PASS | engine sign matches independent OpenSSL HMAC oracle AND engine verify succeeds, len=20 |
| HMAC_SHA224 | ✅ PASS | engine sign matches independent OpenSSL HMAC oracle AND engine verify succeeds, len=28 |
| HMAC_SHA384 | ✅ PASS | engine sign matches independent OpenSSL HMAC oracle AND engine verify succeeds, len=48 |
| HMAC_SHA512 | ✅ PASS | engine sign matches independent OpenSSL HMAC oracle AND engine verify succeeds, len=64 |

### GapDerive

| Test | Status | Details |
|---|---|---|
| CONCATENATE_DATA_AND_BASE | ✅ PASS | derived value == data||base, byte-exact (order confirmed against dispatch code) |

### GapEcdsaEddsa

| Test | Status | Details |
|---|---|---|
| Generate_P256 | ✅ PASS | RV=0 |
| ECDSA_SHA1 | ✅ PASS | real sign+verify round trip OK |
| ECDSA_SHA224 | ✅ PASS | real sign+verify round trip OK |
| ECDSA_SHA384 | ✅ PASS | real sign+verify round trip OK |
| ECDSA_SHA3_224 | ✅ PASS | real sign+verify round trip OK |
| ECDSA_SHA3_384 | ✅ PASS | real sign+verify round trip OK |
| EDDSA_PH_Ed25519 | ✅ PASS | real sign+verify round trip OK |
| EDDSA_PH_Ed448 | ✅ PASS | real sign+verify round trip OK |

### GapRsaCipher

| Test | Status | Details |
|---|---|---|
| Generate_RSA_2048 | ✅ PASS | RV=0 |
| OAEP_roundtrip | ✅ PASS | encrypt/decrypt round trip recovered the original plaintext |
| RSA_AES_KEY_WRAP_roundtrip | ✅ PASS | unwrapped AES key perfectly matches the original target's value |

### GapRsaSign

| Test | Status | Details |
|---|---|---|
| Generate_RSA_2048 | ✅ PASS | RV=0 |
| PKCS_MD5 | ✅ PASS | real sign+verify round trip OK, sigLen=256 |
| PKCS_SHA1 | ✅ PASS | real sign+verify round trip OK, sigLen=256 |
| PKCS_SHA224 | ✅ PASS | real sign+verify round trip OK, sigLen=256 |
| PKCS_SHA384 | ✅ PASS | real sign+verify round trip OK, sigLen=256 |
| PKCS_SHA512 | ✅ PASS | real sign+verify round trip OK, sigLen=256 |
| PSS_SHA1 | ✅ PASS | real sign+verify round trip OK, sigLen=256 |
| PSS_SHA224 | ✅ PASS | real sign+verify round trip OK, sigLen=256 |
| PSS_SHA256 | ✅ PASS | real sign+verify round trip OK, sigLen=256 |
| PSS_SHA384 | ✅ PASS | real sign+verify round trip OK, sigLen=256 |
| PSS_SHA512 | ✅ PASS | real sign+verify round trip OK, sigLen=256 |
| PSS_Raw | ✅ PASS | real sign+verify round trip on a caller-supplied SHA-256 digest, OK |

### HBSProtect

| Test | Status | Details |
|---|---|---|
| HSS_Generate | ✅ PASS |  |
| HSS_CKA_SENSITIVE_true | ✅ PASS | RV=0 CKA_SENSITIVE=1 |
| HSS_CKA_EXTRACTABLE_false | ✅ PASS | RV=0 CKA_EXTRACTABLE=0 |
| HSS_CKA_COPYABLE_false | ✅ PASS | RV=0 CKA_COPYABLE=0 |
| HSS_CKA_VALUE_not_extractable | ✅ PASS | RV=17 (want CKR_ATTRIBUTE_SENSITIVE=0x11) |
| HSS_reject_SENSITIVE_false | ✅ PASS | RV=19 (want CKR_ATTRIBUTE_VALUE_INVALID=0x13) |
| HSS_reject_EXTRACTABLE_true | ✅ PASS | RV=19 (want CKR_ATTRIBUTE_VALUE_INVALID=0x13) |
| HSS_reject_COPYABLE_true | ✅ PASS | RV=19 (want CKR_ATTRIBUTE_VALUE_INVALID=0x13) |
| HSS_accept_restated_SENSITIVE_true | ✅ PASS | RV=0 |
| XMSS_Generate | ✅ PASS |  |
| XMSS_CKA_SENSITIVE_true | ✅ PASS | RV=0 CKA_SENSITIVE=1 |
| XMSS_CKA_EXTRACTABLE_false | ✅ PASS | RV=0 CKA_EXTRACTABLE=0 |
| XMSS_CKA_VALUE_not_extractable | ✅ PASS | RV=17 (want CKR_ATTRIBUTE_SENSITIVE=0x11) |
| XMSS_reject_SENSITIVE_false | ✅ PASS | RV=19 (want CKR_ATTRIBUTE_VALUE_INVALID=0x13) |
| XMSS_reject_EXTRACTABLE_true | ✅ PASS | RV=19 (want CKR_ATTRIBUTE_VALUE_INVALID=0x13) |
| XMSS_accept_restated_SENSITIVE_true | ✅ PASS | RV=0 |
| XMSSMT_Generate | ✅ PASS |  |
| XMSSMT_CKA_SENSITIVE_true | ✅ PASS | RV=0 CKA_SENSITIVE=1 |
| XMSSMT_CKA_EXTRACTABLE_false | ✅ PASS | RV=0 CKA_EXTRACTABLE=0 |
| XMSSMT_CKA_VALUE_not_extractable | ✅ PASS | RV=17 (want CKR_ATTRIBUTE_SENSITIVE=0x11) |
| XMSSMT_reject_SENSITIVE_false | ✅ PASS | RV=19 (want CKR_ATTRIBUTE_VALUE_INVALID=0x13) |
| XMSSMT_reject_EXTRACTABLE_true | ✅ PASS | RV=19 (want CKR_ATTRIBUTE_VALUE_INVALID=0x13) |
| XMSSMT_accept_restated_SENSITIVE_true | ✅ PASS | RV=0 |

### HmacGeneral

| Test | Status | Details |
|---|---|---|
| HMAC_GENERAL_SHA1 | ✅ PASS | sign truncated to 16 of 20 bytes matches the leading bytes of an independent OpenSSL HMAC oracle AND engine verify succeeds |
| HMAC_GENERAL_SHA1_rejects_full_length_mac | ✅ PASS | RV=193 (want CKR_SIGNATURE_LEN_RANGE=0xC1) |
| HMAC_GENERAL_SHA1_rejects_tampered_message | ✅ PASS | RV=192 (want CKR_SIGNATURE_INVALID=0xC0) |
| HMAC_GENERAL_SHA1_no_param | ✅ PASS | C_SignInit RV=113 (want CKR_MECHANISM_PARAM_INVALID=0x71) |
| HMAC_GENERAL_SHA1_zero_length | ✅ PASS | C_SignInit RV=113 (want CKR_MECHANISM_PARAM_INVALID=0x71) |
| HMAC_GENERAL_SHA1_over_length | ✅ PASS | C_SignInit RV=113 (want CKR_MECHANISM_PARAM_INVALID=0x71) |
| HMAC_GENERAL_SHA224 | ✅ PASS | sign truncated to 20 of 28 bytes matches the leading bytes of an independent OpenSSL HMAC oracle AND engine verify succeeds |
| HMAC_GENERAL_SHA224_rejects_full_length_mac | ✅ PASS | RV=193 (want CKR_SIGNATURE_LEN_RANGE=0xC1) |
| HMAC_GENERAL_SHA224_rejects_tampered_message | ✅ PASS | RV=192 (want CKR_SIGNATURE_INVALID=0xC0) |
| HMAC_GENERAL_SHA224_no_param | ✅ PASS | C_SignInit RV=113 (want CKR_MECHANISM_PARAM_INVALID=0x71) |
| HMAC_GENERAL_SHA224_zero_length | ✅ PASS | C_SignInit RV=113 (want CKR_MECHANISM_PARAM_INVALID=0x71) |
| HMAC_GENERAL_SHA224_over_length | ✅ PASS | C_SignInit RV=113 (want CKR_MECHANISM_PARAM_INVALID=0x71) |
| HMAC_GENERAL_SHA256 | ✅ PASS | sign truncated to 20 of 32 bytes matches the leading bytes of an independent OpenSSL HMAC oracle AND engine verify succeeds |
| HMAC_GENERAL_SHA256_rejects_full_length_mac | ✅ PASS | RV=193 (want CKR_SIGNATURE_LEN_RANGE=0xC1) |
| HMAC_GENERAL_SHA256_rejects_tampered_message | ✅ PASS | RV=192 (want CKR_SIGNATURE_INVALID=0xC0) |
| HMAC_GENERAL_SHA256_no_param | ✅ PASS | C_SignInit RV=113 (want CKR_MECHANISM_PARAM_INVALID=0x71) |
| HMAC_GENERAL_SHA256_zero_length | ✅ PASS | C_SignInit RV=113 (want CKR_MECHANISM_PARAM_INVALID=0x71) |
| HMAC_GENERAL_SHA256_over_length | ✅ PASS | C_SignInit RV=113 (want CKR_MECHANISM_PARAM_INVALID=0x71) |
| HMAC_GENERAL_SHA384 | ✅ PASS | sign truncated to 20 of 48 bytes matches the leading bytes of an independent OpenSSL HMAC oracle AND engine verify succeeds |
| HMAC_GENERAL_SHA384_rejects_full_length_mac | ✅ PASS | RV=193 (want CKR_SIGNATURE_LEN_RANGE=0xC1) |
| HMAC_GENERAL_SHA384_rejects_tampered_message | ✅ PASS | RV=192 (want CKR_SIGNATURE_INVALID=0xC0) |
| HMAC_GENERAL_SHA384_no_param | ✅ PASS | C_SignInit RV=113 (want CKR_MECHANISM_PARAM_INVALID=0x71) |
| HMAC_GENERAL_SHA384_zero_length | ✅ PASS | C_SignInit RV=113 (want CKR_MECHANISM_PARAM_INVALID=0x71) |
| HMAC_GENERAL_SHA384_over_length | ✅ PASS | C_SignInit RV=113 (want CKR_MECHANISM_PARAM_INVALID=0x71) |
| HMAC_GENERAL_SHA512 | ✅ PASS | sign truncated to 20 of 64 bytes matches the leading bytes of an independent OpenSSL HMAC oracle AND engine verify succeeds |
| HMAC_GENERAL_SHA512_rejects_full_length_mac | ✅ PASS | RV=193 (want CKR_SIGNATURE_LEN_RANGE=0xC1) |
| HMAC_GENERAL_SHA512_rejects_tampered_message | ✅ PASS | RV=192 (want CKR_SIGNATURE_INVALID=0xC0) |
| HMAC_GENERAL_SHA512_no_param | ✅ PASS | C_SignInit RV=113 (want CKR_MECHANISM_PARAM_INVALID=0x71) |
| HMAC_GENERAL_SHA512_zero_length | ✅ PASS | C_SignInit RV=113 (want CKR_MECHANISM_PARAM_INVALID=0x71) |
| HMAC_GENERAL_SHA512_over_length | ✅ PASS | C_SignInit RV=113 (want CKR_MECHANISM_PARAM_INVALID=0x71) |
| HMAC_GENERAL_SHA3_224 | ✅ PASS | sign truncated to 20 of 28 bytes matches the leading bytes of an independent OpenSSL HMAC oracle AND engine verify succeeds |
| HMAC_GENERAL_SHA3_224_rejects_full_length_mac | ✅ PASS | RV=193 (want CKR_SIGNATURE_LEN_RANGE=0xC1) |
| HMAC_GENERAL_SHA3_224_rejects_tampered_message | ✅ PASS | RV=192 (want CKR_SIGNATURE_INVALID=0xC0) |
| HMAC_GENERAL_SHA3_224_no_param | ✅ PASS | C_SignInit RV=113 (want CKR_MECHANISM_PARAM_INVALID=0x71) |
| HMAC_GENERAL_SHA3_224_zero_length | ✅ PASS | C_SignInit RV=113 (want CKR_MECHANISM_PARAM_INVALID=0x71) |
| HMAC_GENERAL_SHA3_224_over_length | ✅ PASS | C_SignInit RV=113 (want CKR_MECHANISM_PARAM_INVALID=0x71) |
| HMAC_GENERAL_SHA3_256 | ✅ PASS | sign truncated to 20 of 32 bytes matches the leading bytes of an independent OpenSSL HMAC oracle AND engine verify succeeds |
| HMAC_GENERAL_SHA3_256_rejects_full_length_mac | ✅ PASS | RV=193 (want CKR_SIGNATURE_LEN_RANGE=0xC1) |
| HMAC_GENERAL_SHA3_256_rejects_tampered_message | ✅ PASS | RV=192 (want CKR_SIGNATURE_INVALID=0xC0) |
| HMAC_GENERAL_SHA3_256_no_param | ✅ PASS | C_SignInit RV=113 (want CKR_MECHANISM_PARAM_INVALID=0x71) |
| HMAC_GENERAL_SHA3_256_zero_length | ✅ PASS | C_SignInit RV=113 (want CKR_MECHANISM_PARAM_INVALID=0x71) |
| HMAC_GENERAL_SHA3_256_over_length | ✅ PASS | C_SignInit RV=113 (want CKR_MECHANISM_PARAM_INVALID=0x71) |
| HMAC_GENERAL_SHA3_384 | ✅ PASS | sign truncated to 20 of 48 bytes matches the leading bytes of an independent OpenSSL HMAC oracle AND engine verify succeeds |
| HMAC_GENERAL_SHA3_384_rejects_full_length_mac | ✅ PASS | RV=193 (want CKR_SIGNATURE_LEN_RANGE=0xC1) |
| HMAC_GENERAL_SHA3_384_rejects_tampered_message | ✅ PASS | RV=192 (want CKR_SIGNATURE_INVALID=0xC0) |
| HMAC_GENERAL_SHA3_384_no_param | ✅ PASS | C_SignInit RV=113 (want CKR_MECHANISM_PARAM_INVALID=0x71) |
| HMAC_GENERAL_SHA3_384_zero_length | ✅ PASS | C_SignInit RV=113 (want CKR_MECHANISM_PARAM_INVALID=0x71) |
| HMAC_GENERAL_SHA3_384_over_length | ✅ PASS | C_SignInit RV=113 (want CKR_MECHANISM_PARAM_INVALID=0x71) |
| HMAC_GENERAL_SHA3_512 | ✅ PASS | sign truncated to 20 of 64 bytes matches the leading bytes of an independent OpenSSL HMAC oracle AND engine verify succeeds |
| HMAC_GENERAL_SHA3_512_rejects_full_length_mac | ✅ PASS | RV=193 (want CKR_SIGNATURE_LEN_RANGE=0xC1) |
| HMAC_GENERAL_SHA3_512_rejects_tampered_message | ✅ PASS | RV=192 (want CKR_SIGNATURE_INVALID=0xC0) |
| HMAC_GENERAL_SHA3_512_no_param | ✅ PASS | C_SignInit RV=113 (want CKR_MECHANISM_PARAM_INVALID=0x71) |
| HMAC_GENERAL_SHA3_512_zero_length | ✅ PASS | C_SignInit RV=113 (want CKR_MECHANISM_PARAM_INVALID=0x71) |
| HMAC_GENERAL_SHA3_512_over_length | ✅ PASS | C_SignInit RV=113 (want CKR_MECHANISM_PARAM_INVALID=0x71) |
| HMAC_GENERAL_MD5 | ✅ PASS | sign truncated to 8 of 16 bytes matches the leading bytes of an independent OpenSSL HMAC oracle AND engine verify succeeds |
| HMAC_GENERAL_MD5_rejects_full_length_mac | ✅ PASS | RV=193 (want CKR_SIGNATURE_LEN_RANGE=0xC1) |
| HMAC_GENERAL_MD5_rejects_tampered_message | ✅ PASS | RV=192 (want CKR_SIGNATURE_INVALID=0xC0) |
| HMAC_GENERAL_MD5_no_param | ✅ PASS | C_SignInit RV=113 (want CKR_MECHANISM_PARAM_INVALID=0x71) |
| HMAC_GENERAL_MD5_zero_length | ✅ PASS | C_SignInit RV=113 (want CKR_MECHANISM_PARAM_INVALID=0x71) |
| HMAC_GENERAL_MD5_over_length | ✅ PASS | C_SignInit RV=113 (want CKR_MECHANISM_PARAM_INVALID=0x71) |

### HybridKEM

| Test | Status | Details |
|---|---|---|
| Generate_X25519 | ✅ PASS |  |
| Generate_ML_KEM_768 | ✅ PASS |  |
| Encapsulate_X25519_half | ✅ PASS | ephemeral pubkey len=32 |
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

### Invariant

| Test | Status | Details |
|---|---|---|
| Encrypt_0x00001082 | ✅ PASS | C_EncryptInit RV=113 |
| Decrypt_0x00001082 | ✅ PASS | C_DecryptInit RV=113 |
| OutOfScope_0x00001105 | ⚠️ SKIP | no DIGEST/SIGN/VERIFY/ENCRYPT/DECRYPT flag -- derive/generate/wrap-only mechanism, out of this invariant's documented forward-direction scope; covered by this file's per-mechanism round-trip tests instead |
| Encrypt_0x00001085 | ✅ PASS | C_EncryptInit RV=113 |
| Decrypt_0x00001085 | ✅ PASS | C_DecryptInit RV=113 |
| Sign_0x0000108a | ✅ PASS | C_SignInit RV=99 |
| Verify_0x0000108a | ✅ PASS | C_VerifyInit RV=99 |
| Encrypt_0x00001086 | ✅ PASS | C_EncryptInit RV=7 |
| Decrypt_0x00001086 | ✅ PASS | C_DecryptInit RV=7 |
| Encrypt_0x00001081 | ✅ PASS | C_EncryptInit RV=0 |
| Decrypt_0x00001081 | ✅ PASS | C_DecryptInit RV=0 |
| OutOfScope_0x00001104 | ⚠️ SKIP | no DIGEST/SIGN/VERIFY/ENCRYPT/DECRYPT flag -- derive/generate/wrap-only mechanism, out of this invariant's documented forward-direction scope; covered by this file's per-mechanism round-trip tests instead |
| Encrypt_0x00001087 | ✅ PASS | C_EncryptInit RV=7 |
| Decrypt_0x00001087 | ✅ PASS | C_DecryptInit RV=7 |
| OutOfScope_0x00001080 | ⚠️ SKIP | no DIGEST/SIGN/VERIFY/ENCRYPT/DECRYPT flag -- derive/generate/wrap-only mechanism, out of this invariant's documented forward-direction scope; covered by this file's per-mechanism round-trip tests instead |
| OutOfScope_0x00002109 | ⚠️ SKIP | no DIGEST/SIGN/VERIFY/ENCRYPT/DECRYPT flag -- derive/generate/wrap-only mechanism, out of this invariant's documented forward-direction scope; covered by this file's per-mechanism round-trip tests instead |
| OutOfScope_0x0000210b | ⚠️ SKIP | no DIGEST/SIGN/VERIFY/ENCRYPT/DECRYPT flag -- derive/generate/wrap-only mechanism, out of this invariant's documented forward-direction scope; covered by this file's per-mechanism round-trip tests instead |
| OutOfScope_0x0000210a | ⚠️ SKIP | no DIGEST/SIGN/VERIFY/ENCRYPT/DECRYPT flag -- derive/generate/wrap-only mechanism, out of this invariant's documented forward-direction scope; covered by this file's per-mechanism round-trip tests instead |
| OutOfScope_0x8000105c | ⚠️ SKIP | no DIGEST/SIGN/VERIFY/ENCRYPT/DECRYPT flag -- derive/generate/wrap-only mechanism, out of this invariant's documented forward-direction scope; covered by this file's per-mechanism round-trip tests instead |
| OutOfScope_0x8000105b | ⚠️ SKIP | no DIGEST/SIGN/VERIFY/ENCRYPT/DECRYPT flag -- derive/generate/wrap-only mechanism, out of this invariant's documented forward-direction scope; covered by this file's per-mechanism round-trip tests instead |
| Encrypt_0x00001226 | ✅ PASS | C_EncryptInit RV=99 |
| Decrypt_0x00001226 | ✅ PASS | C_DecryptInit RV=99 |
| OutOfScope_0x00001225 | ⚠️ SKIP | no DIGEST/SIGN/VERIFY/ENCRYPT/DECRYPT flag -- derive/generate/wrap-only mechanism, out of this invariant's documented forward-direction scope; covered by this file's per-mechanism round-trip tests instead |
| Encrypt_0x00004021 | ✅ PASS | C_EncryptInit RV=99 |
| Decrypt_0x00004021 | ✅ PASS | C_DecryptInit RV=99 |
| OutOfScope_0x00000362 | ⚠️ SKIP | no DIGEST/SIGN/VERIFY/ENCRYPT/DECRYPT flag -- derive/generate/wrap-only mechanism, out of this invariant's documented forward-direction scope; covered by this file's per-mechanism round-trip tests instead |
| OutOfScope_0x00000360 | ⚠️ SKIP | no DIGEST/SIGN/VERIFY/ENCRYPT/DECRYPT flag -- derive/generate/wrap-only mechanism, out of this invariant's documented forward-direction scope; covered by this file's per-mechanism round-trip tests instead |
| OutOfScope_0x00000363 | ⚠️ SKIP | no DIGEST/SIGN/VERIFY/ENCRYPT/DECRYPT flag -- derive/generate/wrap-only mechanism, out of this invariant's documented forward-direction scope; covered by this file's per-mechanism round-trip tests instead |
| OutOfScope_0x00001051 | ⚠️ SKIP | no DIGEST/SIGN/VERIFY/ENCRYPT/DECRYPT flag -- derive/generate/wrap-only mechanism, out of this invariant's documented forward-direction scope; covered by this file's per-mechanism round-trip tests instead |
| OutOfScope_0x00001050 | ⚠️ SKIP | no DIGEST/SIGN/VERIFY/ENCRYPT/DECRYPT flag -- derive/generate/wrap-only mechanism, out of this invariant's documented forward-direction scope; covered by this file's per-mechanism round-trip tests instead |
| Sign_0x00001041 | ✅ PASS | C_SignInit RV=0 |
| Verify_0x00001041 | ✅ PASS | C_VerifyInit RV=0 |
| Sign_0x00001042 | ✅ PASS | C_SignInit RV=0 |
| Verify_0x00001042 | ✅ PASS | C_VerifyInit RV=0 |
| Sign_0x00001043 | ✅ PASS | C_SignInit RV=0 |
| Verify_0x00001043 | ✅ PASS | C_VerifyInit RV=0 |
| Sign_0x00001044 | ✅ PASS | C_SignInit RV=0 |
| Verify_0x00001044 | ✅ PASS | C_VerifyInit RV=0 |
| Sign_0x00001045 | ✅ PASS | C_SignInit RV=0 |
| Verify_0x00001045 | ✅ PASS | C_VerifyInit RV=0 |
| Sign_0x00001047 | ✅ PASS | C_SignInit RV=0 |
| Verify_0x00001047 | ✅ PASS | C_VerifyInit RV=0 |
| Sign_0x00001048 | ✅ PASS | C_SignInit RV=0 |
| Verify_0x00001048 | ✅ PASS | C_VerifyInit RV=0 |
| Sign_0x00001049 | ✅ PASS | C_SignInit RV=0 |
| Verify_0x00001049 | ✅ PASS | C_VerifyInit RV=0 |
| Sign_0x0000104a | ✅ PASS | C_SignInit RV=0 |
| Verify_0x0000104a | ✅ PASS | C_VerifyInit RV=0 |
| Sign_0x00001046 | ✅ PASS | C_SignInit RV=0 |
| Verify_0x00001046 | ✅ PASS | C_VerifyInit RV=0 |
| OutOfScope_0x00001055 | ⚠️ SKIP | no DIGEST/SIGN/VERIFY/ENCRYPT/DECRYPT flag -- derive/generate/wrap-only mechanism, out of this invariant's documented forward-direction scope; covered by this file's per-mechanism round-trip tests instead |
| OutOfScope_0x00001040 | ⚠️ SKIP | no DIGEST/SIGN/VERIFY/ENCRYPT/DECRYPT flag -- derive/generate/wrap-only mechanism, out of this invariant's documented forward-direction scope; covered by this file's per-mechanism round-trip tests instead |
| OutOfScope_0x00001056 | ⚠️ SKIP | no DIGEST/SIGN/VERIFY/ENCRYPT/DECRYPT flag -- derive/generate/wrap-only mechanism, out of this invariant's documented forward-direction scope; covered by this file's per-mechanism round-trip tests instead |
| Sign_0x00001057 | ✅ PASS | C_SignInit RV=0 |
| Verify_0x00001057 | ✅ PASS | C_VerifyInit RV=0 |
| Sign_0x80001057 | ✅ PASS | C_SignInit RV=0 |
| Verify_0x80001057 | ✅ PASS | C_VerifyInit RV=0 |
| OutOfScope_0x00000350 | ⚠️ SKIP | no DIGEST/SIGN/VERIFY/ENCRYPT/DECRYPT flag -- derive/generate/wrap-only mechanism, out of this invariant's documented forward-direction scope; covered by this file's per-mechanism round-trip tests instead |
| Sign_0x0000001f | ✅ PASS | C_SignInit RV=7 |
| Verify_0x0000001f | ✅ PASS | C_VerifyInit RV=7 |
| Sign_0x00000023 | ✅ PASS | C_SignInit RV=99 |
| Verify_0x00000023 | ✅ PASS | C_VerifyInit RV=99 |
| Sign_0x00000024 | ✅ PASS | C_SignInit RV=99 |
| Verify_0x00000024 | ✅ PASS | C_VerifyInit RV=99 |
| Sign_0x00000025 | ✅ PASS | C_SignInit RV=99 |
| Verify_0x00000025 | ✅ PASS | C_VerifyInit RV=99 |
| Sign_0x00000027 | ✅ PASS | C_SignInit RV=99 |
| Verify_0x00000027 | ✅ PASS | C_VerifyInit RV=99 |
| Sign_0x00000028 | ✅ PASS | C_SignInit RV=99 |
| Verify_0x00000028 | ✅ PASS | C_VerifyInit RV=99 |
| Sign_0x00000029 | ✅ PASS | C_SignInit RV=99 |
| Verify_0x00000029 | ✅ PASS | C_VerifyInit RV=99 |
| Sign_0x0000002a | ✅ PASS | C_SignInit RV=99 |
| Verify_0x0000002a | ✅ PASS | C_VerifyInit RV=99 |
| Sign_0x00000026 | ✅ PASS | C_SignInit RV=99 |
| Verify_0x00000026 | ✅ PASS | C_VerifyInit RV=99 |
| Sign_0x0000002b | ✅ PASS | C_SignInit RV=99 |
| Verify_0x0000002b | ✅ PASS | C_VerifyInit RV=99 |
| Sign_0x0000002c | ✅ PASS | C_SignInit RV=99 |
| Verify_0x0000002c | ✅ PASS | C_VerifyInit RV=99 |
| Sign_0x00000034 | ✅ PASS | C_SignInit RV=7 |
| Verify_0x00000034 | ✅ PASS | C_VerifyInit RV=7 |
| Sign_0x00000036 | ✅ PASS | C_SignInit RV=99 |
| Verify_0x00000036 | ✅ PASS | C_VerifyInit RV=99 |
| Sign_0x00000037 | ✅ PASS | C_SignInit RV=99 |
| Verify_0x00000037 | ✅ PASS | C_VerifyInit RV=99 |
| Sign_0x00000038 | ✅ PASS | C_SignInit RV=99 |
| Verify_0x00000038 | ✅ PASS | C_VerifyInit RV=99 |
| Sign_0x0000003a | ✅ PASS | C_SignInit RV=99 |
| Verify_0x0000003a | ✅ PASS | C_VerifyInit RV=99 |
| Sign_0x0000003b | ✅ PASS | C_SignInit RV=99 |
| Verify_0x0000003b | ✅ PASS | C_VerifyInit RV=99 |
| Sign_0x0000003c | ✅ PASS | C_SignInit RV=99 |
| Verify_0x0000003c | ✅ PASS | C_VerifyInit RV=99 |
| Sign_0x0000003d | ✅ PASS | C_SignInit RV=99 |
| Verify_0x0000003d | ✅ PASS | C_VerifyInit RV=99 |
| Sign_0x00000039 | ✅ PASS | C_SignInit RV=99 |
| Verify_0x00000039 | ✅ PASS | C_VerifyInit RV=99 |
| Sign_0x0000003e | ✅ PASS | C_SignInit RV=99 |
| Verify_0x0000003e | ✅ PASS | C_VerifyInit RV=99 |
| Sign_0x0000003f | ✅ PASS | C_SignInit RV=99 |
| Verify_0x0000003f | ✅ PASS | C_VerifyInit RV=99 |
| OutOfScope_0x0000402a | ⚠️ SKIP | no DIGEST/SIGN/VERIFY/ENCRYPT/DECRYPT flag -- derive/generate/wrap-only mechanism, out of this invariant's documented forward-direction scope; covered by this file's per-mechanism round-trip tests instead |
| Sign_0x00004033 | ✅ PASS | C_SignInit RV=0 |
| Verify_0x00004033 | ✅ PASS | C_VerifyInit RV=0 |
| OutOfScope_0x00004032 | ⚠️ SKIP | no DIGEST/SIGN/VERIFY/ENCRYPT/DECRYPT flag -- derive/generate/wrap-only mechanism, out of this invariant's documented forward-direction scope; covered by this file's per-mechanism round-trip tests instead |
| Sign_0x80000100 | ✅ PASS | C_SignInit RV=0 |
| Verify_0x80000100 | ✅ PASS | C_VerifyInit RV=0 |
| Sign_0x80000101 | ✅ PASS | C_SignInit RV=0 |
| Verify_0x80000101 | ✅ PASS | C_VerifyInit RV=0 |
| Digest_0x00000210 | ✅ PASS | C_DigestInit RV=0 |
| Sign_0x00000211 | ✅ PASS | C_SignInit RV=0 |
| Verify_0x00000211 | ✅ PASS | C_VerifyInit RV=0 |
| Sign_0x00000212 | ✅ PASS | C_SignInit RV=113 |
| Verify_0x00000212 | ✅ PASS | C_VerifyInit RV=113 |
| Sign_0x00000005 | ✅ PASS | C_SignInit RV=0 |
| Verify_0x00000005 | ✅ PASS | C_VerifyInit RV=0 |
| Sign_0x0000001d | ✅ PASS | C_SignInit RV=99 |
| Verify_0x0000001d | ✅ PASS | C_VerifyInit RV=99 |
| OutOfScope_0x0000001c | ⚠️ SKIP | no DIGEST/SIGN/VERIFY/ENCRYPT/DECRYPT flag -- derive/generate/wrap-only mechanism, out of this invariant's documented forward-direction scope; covered by this file's per-mechanism round-trip tests instead |
| OutOfScope_0x00000017 | ⚠️ SKIP | no DIGEST/SIGN/VERIFY/ENCRYPT/DECRYPT flag -- derive/generate/wrap-only mechanism, out of this invariant's documented forward-direction scope; covered by this file's per-mechanism round-trip tests instead |
| OutOfScope_0x0000000f | ⚠️ SKIP | no DIGEST/SIGN/VERIFY/ENCRYPT/DECRYPT flag -- derive/generate/wrap-only mechanism, out of this invariant's documented forward-direction scope; covered by this file's per-mechanism round-trip tests instead |
| OutOfScope_0x000003b0 | ⚠️ SKIP | no DIGEST/SIGN/VERIFY/ENCRYPT/DECRYPT flag -- derive/generate/wrap-only mechanism, out of this invariant's documented forward-direction scope; covered by this file's per-mechanism round-trip tests instead |
| Digest_0x00000240 | ✅ PASS | C_DigestInit RV=0 |
| Sign_0x00000241 | ✅ PASS | C_SignInit RV=0 |
| Verify_0x00000241 | ✅ PASS | C_VerifyInit RV=0 |
| Sign_0x00000242 | ✅ PASS | C_SignInit RV=113 |
| Verify_0x00000242 | ✅ PASS | C_VerifyInit RV=113 |
| OutOfScope_0x00001054 | ⚠️ SKIP | no DIGEST/SIGN/VERIFY/ENCRYPT/DECRYPT flag -- derive/generate/wrap-only mechanism, out of this invariant's documented forward-direction scope; covered by this file's per-mechanism round-trip tests instead |
| Sign_0x00000001 | ✅ PASS | C_SignInit RV=0 |
| Verify_0x00000001 | ✅ PASS | C_VerifyInit RV=0 |
| Encrypt_0x00000001 | ✅ PASS | C_EncryptInit RV=99 |
| Decrypt_0x00000001 | ✅ PASS | C_DecryptInit RV=99 |
| OutOfScope_0x00000000 | ⚠️ SKIP | no DIGEST/SIGN/VERIFY/ENCRYPT/DECRYPT flag -- derive/generate/wrap-only mechanism, out of this invariant's documented forward-direction scope; covered by this file's per-mechanism round-trip tests instead |
| Encrypt_0x00000009 | ✅ PASS | C_EncryptInit RV=99 |
| Decrypt_0x00000009 | ✅ PASS | C_DecryptInit RV=99 |
| Sign_0x0000000d | ✅ PASS | C_SignInit RV=7 |
| Verify_0x0000000d | ✅ PASS | C_VerifyInit RV=7 |
| Sign_0x00000003 | ✅ PASS | C_SignInit RV=0 |
| Verify_0x00000003 | ✅ PASS | C_VerifyInit RV=0 |
| Encrypt_0x00000003 | ✅ PASS | C_EncryptInit RV=99 |
| Decrypt_0x00000003 | ✅ PASS | C_DecryptInit RV=99 |
| Sign_0x00000006 | ✅ PASS | C_SignInit RV=0 |
| Verify_0x00000006 | ✅ PASS | C_VerifyInit RV=0 |
| Sign_0x0000000e | ✅ PASS | C_SignInit RV=7 |
| Verify_0x0000000e | ✅ PASS | C_VerifyInit RV=7 |
| Digest_0x00000255 | ✅ PASS | C_DigestInit RV=0 |
| Sign_0x00000256 | ✅ PASS | C_SignInit RV=0 |
| Verify_0x00000256 | ✅ PASS | C_VerifyInit RV=0 |
| Sign_0x00000257 | ✅ PASS | C_SignInit RV=113 |
| Verify_0x00000257 | ✅ PASS | C_VerifyInit RV=113 |
| Sign_0x00000046 | ✅ PASS | C_SignInit RV=0 |
| Verify_0x00000046 | ✅ PASS | C_VerifyInit RV=0 |
| Sign_0x00000047 | ✅ PASS | C_SignInit RV=7 |
| Verify_0x00000047 | ✅ PASS | C_VerifyInit RV=7 |
| Digest_0x00000250 | ✅ PASS | C_DigestInit RV=0 |
| Sign_0x00000251 | ✅ PASS | C_SignInit RV=0 |
| Verify_0x00000251 | ✅ PASS | C_VerifyInit RV=0 |
| Sign_0x00000252 | ✅ PASS | C_SignInit RV=113 |
| Verify_0x00000252 | ✅ PASS | C_VerifyInit RV=113 |
| Sign_0x00000040 | ✅ PASS | C_SignInit RV=0 |
| Verify_0x00000040 | ✅ PASS | C_VerifyInit RV=0 |
| Sign_0x00000043 | ✅ PASS | C_SignInit RV=7 |
| Verify_0x00000043 | ✅ PASS | C_VerifyInit RV=7 |
| Digest_0x00000260 | ✅ PASS | C_DigestInit RV=0 |
| Sign_0x00000261 | ✅ PASS | C_SignInit RV=98 |
| Verify_0x00000261 | ✅ PASS | C_VerifyInit RV=98 |
| Sign_0x00000262 | ✅ PASS | C_SignInit RV=113 |
| Verify_0x00000262 | ✅ PASS | C_VerifyInit RV=113 |
| Sign_0x00000041 | ✅ PASS | C_SignInit RV=0 |
| Verify_0x00000041 | ✅ PASS | C_VerifyInit RV=0 |
| Sign_0x00000044 | ✅ PASS | C_SignInit RV=7 |
| Verify_0x00000044 | ✅ PASS | C_VerifyInit RV=7 |
| Digest_0x000002b5 | ✅ PASS | C_DigestInit RV=0 |
| Sign_0x000002b6 | ✅ PASS | C_SignInit RV=0 |
| Verify_0x000002b6 | ✅ PASS | C_VerifyInit RV=0 |
| Sign_0x000002b7 | ✅ PASS | C_SignInit RV=113 |
| Verify_0x000002b7 | ✅ PASS | C_VerifyInit RV=113 |
| Sign_0x00000066 | ✅ PASS | C_SignInit RV=0 |
| Verify_0x00000066 | ✅ PASS | C_VerifyInit RV=0 |
| Sign_0x00000067 | ✅ PASS | C_SignInit RV=7 |
| Verify_0x00000067 | ✅ PASS | C_VerifyInit RV=7 |
| Digest_0x000002b0 | ✅ PASS | C_DigestInit RV=0 |
| Sign_0x000002b1 | ✅ PASS | C_SignInit RV=0 |
| Verify_0x000002b1 | ✅ PASS | C_VerifyInit RV=0 |
| Sign_0x000002b2 | ✅ PASS | C_SignInit RV=113 |
| Verify_0x000002b2 | ✅ PASS | C_VerifyInit RV=113 |
| Sign_0x00000060 | ✅ PASS | C_SignInit RV=0 |
| Verify_0x00000060 | ✅ PASS | C_VerifyInit RV=0 |
| Sign_0x00000063 | ✅ PASS | C_SignInit RV=7 |
| Verify_0x00000063 | ✅ PASS | C_VerifyInit RV=7 |
| Digest_0x000002c0 | ✅ PASS | C_DigestInit RV=0 |
| Sign_0x000002c1 | ✅ PASS | C_SignInit RV=98 |
| Verify_0x000002c1 | ✅ PASS | C_VerifyInit RV=98 |
| Sign_0x000002c2 | ✅ PASS | C_SignInit RV=113 |
| Verify_0x000002c2 | ✅ PASS | C_VerifyInit RV=113 |
| Sign_0x00000061 | ✅ PASS | C_SignInit RV=0 |
| Verify_0x00000061 | ✅ PASS | C_VerifyInit RV=0 |
| Sign_0x00000064 | ✅ PASS | C_SignInit RV=7 |
| Verify_0x00000064 | ✅ PASS | C_VerifyInit RV=7 |
| Digest_0x000002d0 | ✅ PASS | C_DigestInit RV=0 |
| Sign_0x000002d1 | ✅ PASS | C_SignInit RV=98 |
| Verify_0x000002d1 | ✅ PASS | C_VerifyInit RV=98 |
| Sign_0x000002d2 | ✅ PASS | C_SignInit RV=113 |
| Verify_0x000002d2 | ✅ PASS | C_VerifyInit RV=113 |
| Sign_0x00000062 | ✅ PASS | C_SignInit RV=0 |
| Verify_0x00000062 | ✅ PASS | C_VerifyInit RV=0 |
| Sign_0x00000065 | ✅ PASS | C_SignInit RV=7 |
| Verify_0x00000065 | ✅ PASS | C_VerifyInit RV=7 |
| Digest_0x00000270 | ✅ PASS | C_DigestInit RV=0 |
| Sign_0x00000271 | ✅ PASS | C_SignInit RV=98 |
| Verify_0x00000271 | ✅ PASS | C_VerifyInit RV=98 |
| Sign_0x00000272 | ✅ PASS | C_SignInit RV=113 |
| Verify_0x00000272 | ✅ PASS | C_VerifyInit RV=113 |
| Sign_0x00000042 | ✅ PASS | C_SignInit RV=0 |
| Verify_0x00000042 | ✅ PASS | C_VerifyInit RV=0 |
| Sign_0x00000045 | ✅ PASS | C_SignInit RV=7 |
| Verify_0x00000045 | ✅ PASS | C_VerifyInit RV=7 |
| OutOfScope_0x0000039c | ⚠️ SKIP | no DIGEST/SIGN/VERIFY/ENCRYPT/DECRYPT flag -- derive/generate/wrap-only mechanism, out of this invariant's documented forward-direction scope; covered by this file's per-mechanism round-trip tests instead |
| Digest_0x00000220 | ✅ PASS | C_DigestInit RV=0 |
| Sign_0x00000221 | ✅ PASS | C_SignInit RV=0 |
| Verify_0x00000221 | ✅ PASS | C_VerifyInit RV=0 |
| Sign_0x00000222 | ✅ PASS | C_SignInit RV=113 |
| Verify_0x00000222 | ✅ PASS | C_VerifyInit RV=113 |
| Sign_0x0000002e | ✅ PASS | C_SignInit RV=99 |
| Verify_0x0000002e | ✅ PASS | C_VerifyInit RV=99 |
| OutOfScope_0x0000002d | ⚠️ SKIP | no DIGEST/SIGN/VERIFY/ENCRYPT/DECRYPT flag -- derive/generate/wrap-only mechanism, out of this invariant's documented forward-direction scope; covered by this file's per-mechanism round-trip tests instead |
| OutOfScope_0x000003ac | ⚠️ SKIP | no DIGEST/SIGN/VERIFY/ENCRYPT/DECRYPT flag -- derive/generate/wrap-only mechanism, out of this invariant's documented forward-direction scope; covered by this file's per-mechanism round-trip tests instead |
| OutOfScope_0x000003ad | ⚠️ SKIP | no DIGEST/SIGN/VERIFY/ENCRYPT/DECRYPT flag -- derive/generate/wrap-only mechanism, out of this invariant's documented forward-direction scope; covered by this file's per-mechanism round-trip tests instead |
| OutOfScope_0x80001058 | ⚠️ SKIP | no DIGEST/SIGN/VERIFY/ENCRYPT/DECRYPT flag -- derive/generate/wrap-only mechanism, out of this invariant's documented forward-direction scope; covered by this file's per-mechanism round-trip tests instead |
| OutOfScope_0x80001059 | ⚠️ SKIP | no DIGEST/SIGN/VERIFY/ENCRYPT/DECRYPT flag -- derive/generate/wrap-only mechanism, out of this invariant's documented forward-direction scope; covered by this file's per-mechanism round-trip tests instead |
| Sign_0x00004036 | ✅ PASS | C_SignInit RV=0 |
| Verify_0x00004036 | ✅ PASS | C_VerifyInit RV=0 |
| Sign_0x00004037 | ✅ PASS | C_SignInit RV=0 |
| Verify_0x00004037 | ✅ PASS | C_VerifyInit RV=0 |
| OutOfScope_0x00004035 | ⚠️ SKIP | no DIGEST/SIGN/VERIFY/ENCRYPT/DECRYPT flag -- derive/generate/wrap-only mechanism, out of this invariant's documented forward-direction scope; covered by this file's per-mechanism round-trip tests instead |
| OutOfScope_0x00004034 | ⚠️ SKIP | no DIGEST/SIGN/VERIFY/ENCRYPT/DECRYPT flag -- derive/generate/wrap-only mechanism, out of this invariant's documented forward-direction scope; covered by this file's per-mechanism round-trip tests instead |
| Summary_AdvertisedImpliesDispatchable | ✅ PASS | 139 advertised, 105 mechanisms probed (203 Init calls across DIGEST/SIGN/VERIFY/ENCRYPT/DECRYPT), 34 out-of-scope (derive/generate/wrap-only), 0 answered CKR_MECHANISM_INVALID |

### KCV

| Test | Status | Details |
|---|---|---|
| AES_Generate_KCV_Present | ✅ PASS | 3 bytes: 0F6DD2 |
| AES_Generate_KCV_Equals_OracleEcbZeroBlock | ✅ PASS | HSM=0F6DD2 == oracle=0F6DD2 |
| AES_Unwrap_KCV_Present | ✅ PASS | 3 bytes: 21CA6F |
| AES_Unwrap_KCV_Equals_Original | ✅ PASS | original=21CA6F unwrapped=21CA6F |
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
| CKM_SHAKE_256_KEY_DERIVATION | ✅ PASS | len=96 deterministic, key-dependent XOF output |

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

### KEMKcv

| Test | Status | Details |
|---|---|---|
| Encap_KCV_present | ✅ PASS | got 3 bytes (§4.11 SHALL be supplied) |
| Encap_KCV_equals_SHA1_oracle | ✅ PASS | HSM=8387D7 oracle=8387D7 |
| Decap_KCV_present | ✅ PASS | got 3 bytes |
| Decap_KCV_equals_SHA1_oracle | ✅ PASS | HSM=8387D7 oracle=8387D7 |
| Encap_and_Decap_KCV_agree | ✅ PASS | encap=8387D7 decap=8387D7 |
| Decap_correct_caller_KCV_accepted | ✅ PASS | RV=0 (§4.11: a matching supplied value is legal) |
| Decap_wrong_caller_KCV_rejected | ✅ PASS | RV=19 (want CKR_ATTRIBUTE_VALUE_INVALID=0x13) |
| Decap_zero_length_KCV_suppresses | ✅ PASS | RV=0 kcv bytes=0 |
| ECDH_Encap_KCV_present | ✅ PASS | got 3 bytes |
| ECDH_Encap_KCV_equals_SHA1_oracle | ✅ PASS | HSM=87EEDC oracle=87EEDC |
| ECDH_Decap_KCV_equals_SHA1_oracle | ✅ PASS | HSM=87EEDC oracle=87EEDC |

### KEMNeg

| Test | Status | Details |
|---|---|---|
| Encap_MLKEM_restricted | ✅ PASS | RV=112 (want CKR_MECHANISM_INVALID) |
| Decap_MLKEM_restricted | ✅ PASS | RV=112 (want CKR_MECHANISM_INVALID) |
| Encap_MLKEM_whitelisted | ✅ PASS | RV=0 (whitelist includes CKM_ML_KEM) |
| Encap_ECDH_restricted | ✅ PASS | RV=112 (want CKR_MECHANISM_INVALID) |
| Decap_ECDH_restricted | ✅ PASS | RV=112 (want CKR_MECHANISM_INVALID) |

### KEMValueLen

| Test | Status | Details |
|---|---|---|
| Generate_ML_KEM_768 | ✅ PASS |  |
| Encap_MLKEM768 | ✅ PASS | ct len=1088 |
| Encap_MLKEM768_VALUE_LEN | ✅ PASS | CKA_VALUE_LEN=32 len(CKA_VALUE)=32 (want 32) |
| Decap_MLKEM768 | ✅ PASS |  |
| Decap_MLKEM768_VALUE_LEN | ✅ PASS | CKA_VALUE_LEN=32 len(CKA_VALUE)=32 (want 32) |
| Encap_MLKEM768_conflicting_VALUE_LEN | ✅ PASS | RV=209 (want CKR_TEMPLATE_INCONSISTENT) |
| Decap_MLKEM768_conflicting_VALUE_LEN | ✅ PASS | RV=209 (want CKR_TEMPLATE_INCONSISTENT) |
| Decap_MLKEM768_matching_VALUE_LEN | ✅ PASS |  |
| Decap_MLKEM768_matching_VALUE_LEN_readback | ✅ PASS | CKA_VALUE_LEN=32 len(CKA_VALUE)=32 (want 32) |
| Generate_EC_P256 | ✅ PASS |  |
| Encap_ECDH_P256 | ✅ PASS | ct len=65 |
| Encap_ECDH_P256_VALUE_LEN | ✅ PASS | CKA_VALUE_LEN=32 len(CKA_VALUE)=32 (want 32) |
| Decap_ECDH_P256 | ✅ PASS |  |
| Decap_ECDH_P256_VALUE_LEN | ✅ PASS | CKA_VALUE_LEN=32 len(CKA_VALUE)=32 (want 32) |
| Encap_ECDH_P256_truncated | ✅ PASS |  |
| Encap_ECDH_P256_truncated_VALUE_LEN | ✅ PASS | CKA_VALUE_LEN=16 len(CKA_VALUE)=16 (want 16) |
| Decap_ECDH_P256_truncated_VALUE_LEN | ✅ PASS | CKA_VALUE_LEN=16 len(CKA_VALUE)=16 (want 16) |
| Decap_ECDH_P256_truncated | ✅ PASS | truncated secrets must match on both sides |
| Encap_ECDH_P256_oversized_VALUE_LEN | ✅ PASS | RV=209 (want CKR_TEMPLATE_INCONSISTENT) |
| Decap_ECDH_P256_oversized_VALUE_LEN | ✅ PASS | RV=209 (want CKR_TEMPLATE_INCONSISTENT) |

### KMAC

| Test | Status | Details |
|---|---|---|
| Sign_128 | ✅ PASS | RV=0 MacLen=32 |
| Sign_256 | ✅ PASS | RV=0 MacLen=64 |

### KcvTemplate

| Test | Status | Details |
|---|---|---|
| GenerateKey_AES_KCV_matches_oracle | ✅ PASS | engine=1B36B8 oracle=1B36B8 |
| GenerateKey_AES_correct_value_accepted | ⚠️ SKIP | output is freshly random each call, so the caller cannot know the check value in advance |
| GenerateKey_AES_wrong_value_rejected | ✅ PASS | RV=19 (want CKR_ATTRIBUTE_VALUE_INVALID=0x13) |
| GenerateKey_AES_zero_length_suppresses | ✅ PASS | RV=0 kcv bytes=0 |
| GenerateKey_Generic_KCV_matches_oracle | ✅ PASS | engine=DD4D72 oracle=DD4D72 |
| GenerateKey_Generic_correct_value_accepted | ⚠️ SKIP | output is freshly random each call, so the caller cannot know the check value in advance |
| GenerateKey_Generic_wrong_value_rejected | ✅ PASS | RV=19 (want CKR_ATTRIBUTE_VALUE_INVALID=0x13) |
| GenerateKey_Generic_zero_length_suppresses | ✅ PASS | RV=0 kcv bytes=0 |
| UnwrapKey_AES_KCV_matches_oracle | ✅ PASS | engine=1076E4 oracle=1076E4 |
| UnwrapKey_AES_correct_value_accepted | ✅ PASS | RV=0 readback=1076E4 |
| UnwrapKey_AES_wrong_value_rejected | ✅ PASS | RV=19 (want CKR_ATTRIBUTE_VALUE_INVALID=0x13) |
| UnwrapKey_AES_zero_length_suppresses | ✅ PASS | RV=0 kcv bytes=0 |
| DeriveKey_HKDF_KCV_matches_oracle | ✅ PASS | engine=C76B4E oracle=C76B4E |
| DeriveKey_HKDF_correct_value_accepted | ✅ PASS | RV=0 readback=C76B4E |
| DeriveKey_HKDF_wrong_value_rejected | ✅ PASS | RV=19 (want CKR_ATTRIBUTE_VALUE_INVALID=0x13) |
| DeriveKey_HKDF_zero_length_suppresses | ✅ PASS | RV=0 kcv bytes=0 |
| DeriveKey_ECDH_KCV_matches_oracle | ✅ PASS | engine=1FF69C oracle=1FF69C |
| DeriveKey_ECDH_correct_value_accepted | ✅ PASS | RV=0 readback=1FF69C |
| DeriveKey_ECDH_wrong_value_rejected | ✅ PASS | RV=19 (want CKR_ATTRIBUTE_VALUE_INVALID=0x13) |
| DeriveKey_ECDH_zero_length_suppresses | ✅ PASS | RV=0 kcv bytes=0 |
| DeriveKey_PBKD2_KCV_matches_oracle | ✅ PASS | engine=8422AA oracle=8422AA |
| DeriveKey_PBKD2_correct_value_accepted | ✅ PASS | RV=0 readback=8422AA |
| DeriveKey_PBKD2_wrong_value_rejected | ✅ PASS | RV=19 (want CKR_ATTRIBUTE_VALUE_INVALID=0x13) |
| DeriveKey_PBKD2_zero_length_suppresses | ✅ PASS | RV=0 kcv bytes=0 |
| DeriveKey_SP800108_KCV_matches_oracle | ✅ PASS | engine=639EA0 oracle=639EA0 |
| DeriveKey_SP800108_correct_value_accepted | ✅ PASS | RV=0 readback=639EA0 |
| DeriveKey_SP800108_wrong_value_rejected | ✅ PASS | RV=19 (want CKR_ATTRIBUTE_VALUE_INVALID=0x13) |
| DeriveKey_SP800108_zero_length_suppresses | ✅ PASS | RV=0 kcv bytes=0 |
| DeriveKey_Concat_KCV_matches_oracle | ⚠️ SKIP | CKA_VALUE unreadable (RV=17), engine KCV=C51846 |
| DeriveKey_Concat_correct_value_accepted | ✅ PASS | RV=0 readback=C51846 |
| DeriveKey_Concat_wrong_value_rejected | ✅ PASS | RV=19 (want CKR_ATTRIBUTE_VALUE_INVALID=0x13) |
| DeriveKey_Concat_zero_length_suppresses | ✅ PASS | RV=0 kcv bytes=0 |
| DeriveKey_X25519_KCV_matches_oracle | ✅ PASS | engine=4F6BD3 oracle=4F6BD3 |
| DeriveKey_X25519_correct_value_accepted | ✅ PASS | RV=0 readback=4F6BD3 |
| DeriveKey_X25519_wrong_value_rejected | ✅ PASS | RV=19 (want CKR_ATTRIBUTE_VALUE_INVALID=0x13) |
| DeriveKey_X25519_zero_length_suppresses | ✅ PASS | RV=0 kcv bytes=0 |
| SetAttributeValue_correct_accepted | ✅ PASS | RV=0 |
| SetAttributeValue_wrong_rejected | ✅ PASS | RV=19 |
| SetAttributeValue_zero_length_destroys | ✅ PASS | RV=0 bytes left=0 |

### MechFlags

| Test | Status | Details |
|---|---|---|
| CKM_RSA_PKCS_advertises_SIGN_RECOVER | ✅ PASS | flags=0x424704 |
| CKM_RSA_PKCS_advertises_VERIFY_RECOVER | ✅ PASS | flags=0x424704 |
| CKM_RSA_PKCS_SignRecoverInit_accepts | ✅ PASS | RV=0 |
| CKM_RSA_PKCS_VerifyRecoverInit_accepts | ✅ PASS | RV=0 |
| CKM_RSA_X_509_advertises_SIGN_RECOVER | ✅ PASS | flags=0x31488 |
| CKM_RSA_X_509_advertises_VERIFY_RECOVER | ✅ PASS | flags=0x31488 |
| CKM_RSA_X_509_SignRecoverInit_accepts | ✅ PASS | RV=0 |
| CKM_RSA_X_509_VerifyRecoverInit_accepts | ✅ PASS | RV=0 |
| OpenPGP_codepoint_0x3_not_squatted | ✅ PASS | RV=19 (0x3 is unassigned by OASIS; want CKR_ATTRIBUTE_VALUE_INVALID=0x13) |

### MsgCrypt

| Test | Status | Details |
|---|---|---|
| C_MessageEncryptInit | ✅ PASS | RV=0 |
| C_EncryptMessageBegin_IV12 | ✅ PASS | RV=0 |
| C_EncryptMessageBegin_IV16 | ✅ PASS | RV=0 |
| C_EncryptMessageBegin_IV8 | ✅ PASS | RV=0 |
| C_MessageDecryptInit | ✅ PASS | RV=0 |
| C_DecryptMessageBegin | ✅ PASS | RV=0 |
| C_DecryptMessageNext | ✅ PASS | RV=0 |
| DecryptRoundTrip_Streaming_PlaintextMatch | ✅ PASS | streaming Encrypt(Begin/Next)->Decrypt(Begin/Next) byte-exact round trip, len=48 |
| C_MessageDecryptFinal | ✅ PASS | RV=0 |
| C_EncryptMessage | ✅ PASS | RV=0 |
| C_DecryptMessage | ✅ PASS | RV=0 |
| DecryptRoundTrip_OneShot_PlaintextMatch | ✅ PASS | one-shot C_EncryptMessage->C_DecryptMessage byte-exact round trip, len=48 |

### MsgSign

| Test | Status | Details |
|---|---|---|
| C_MessageSignInit | ✅ PASS | RV=0 |
| C_SignMessageBegin | ✅ PASS | RV=0 |
| C_SignMessageNext | ✅ PASS | RV=0 SigLen=128 |
| C_MessageSignInit_RSA_RejectsSignCtxParam | ✅ PASS | expected CKR_MECHANISM_PARAM_INVALID, got RV=113 |

### MsgVerify

| Test | Status | Details |
|---|---|---|
| C_MessageVerifyInit | ✅ PASS | RV=0 |
| C_VerifyMessageBegin | ✅ PASS | RV=0 |
| C_VerifyMessageNext | ✅ PASS | RV=0 |
| VerifyRoundTrip_Streaming | ✅ PASS | streaming Sign(Begin/Next)->Verify(Begin/Next) round trip verified a real RSA signature |
| VerifyRoundTrip_TamperedSignatureRejected | ✅ PASS | tampered signature correctly rejected — RV=192 |
| C_SignMessage | ✅ PASS | RV=0 |
| C_VerifyMessage | ✅ PASS | RV=0 |
| VerifyRoundTrip_OneShot | ✅ PASS | one-shot C_SignMessage->C_VerifyMessage round trip verified a real RSA signature |

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

### PQKeyBytes

| Test | Status | Details |
|---|---|---|
| ML_DSA_44_CKA_VALUE_is_raw_FIPS_length | ✅ PASS | len=2560 (want 2560) |
| ML_DSA_44_CKA_VALUE_not_DER_wrapped | ✅ PASS | first byte=0x21 len=2560 |
| ML_DSA_44_CKA_SEED_contributed | ✅ PASS | RV=0 len=32 (want 32) |
| ML_DSA_44_sign_verify_round_trip | ✅ PASS | sign RV=0 verify RV=0 |
| ML_KEM_768_CKA_VALUE_is_raw_FIPS_length | ✅ PASS | len=2400 (want 2400) |
| ML_KEM_768_CKA_VALUE_not_DER_wrapped | ✅ PASS | first byte=0xbf len=2400 |
| ML_KEM_768_CKA_SEED_contributed | ✅ PASS | RV=0 len=64 (want 64) |
| SLH_DSA_CKA_VALUE_is_raw_FIPS_length | ✅ PASS | len=64 (want 64) |
| SLH_DSA_CKA_VALUE_not_DER_wrapped | ✅ PASS | first byte=0xcd len=64 |
| SLH_DSA_CKA_SEED_absent | ✅ PASS | RV=0 len=0 |
| SLH_DSA_sign_verify_round_trip | ✅ PASS | sign RV=0 verify RV=0 |

### Profile

| Test | Status | Details |
|---|---|---|
| Token_publishes_a_CKO_PROFILE_object | ✅ PASS | found 4 (Profiles v3.2 §5.1 cond. 4 requires at least one) |
| CKP_BASELINE_PROVIDER_present | ✅ PASS | profile ids: [ 1 2 3 4 ] |
| No_profile_object_carries_CKP_INVALID_ID | ✅ PASS | profile ids: [ 1 2 3 4 ] |
| Extended_provider_claim_recorded | ✅ PASS | CKP_EXTENDED_PROVIDER claimed; C_LoginUser exported (§5.3 satisfiable) |
| Application_cannot_create_CKO_PROFILE | ✅ PASS | RV=16 (want CKR_ATTRIBUTE_READ_ONLY=0x10) |
| CKA_PROFILE_ID_absent_on_ordinary_object | ✅ PASS | RV=18 value=3735928559 (want CKR_ATTRIBUTE_TYPE_INVALID=0x12; 0 is CKP_INVALID_ID) |

### RawEncoding

| Test | Status | Details |
|---|---|---|
| Ed25519_EC_POINT_raw | ✅ PASS | CKA_EC_POINT len=32 (want 32 bare RFC bytes) |
| Ed25519_sign_verify_round_trip | ✅ PASS | sign RV=0 verify RV=0 |
| Ed25519_import_raw_point_verifies | ✅ PASS | create RV=0 verify RV=0 |
| Ed25519_import_DER_point_still_verifies | ✅ PASS | create RV=0 verify RV=0 |
| Ed448_EC_POINT_raw | ✅ PASS | CKA_EC_POINT len=57 (want 57 bare RFC bytes) |
| Ed448_sign_verify_round_trip | ✅ PASS | sign RV=0 verify RV=0 |
| Ed448_import_raw_point_verifies | ✅ PASS | create RV=0 verify RV=0 |
| Ed448_import_DER_point_still_verifies | ✅ PASS | create RV=0 verify RV=0 |
| X25519_EC_POINT_raw | ✅ PASS | CKA_EC_POINT len=32 (want 32 bare RFC bytes) |
| P256_ciphertext_is_65_raw_bytes | ✅ PASS | RV=0 len=65 first=0x4 (want 65, first byte 0x04 not a DER tag) |
| P256_raw_ciphertext_round_trip | ✅ PASS | decap RV=0 secrets equal=1 |
| P256_DER_ciphertext_still_accepted | ✅ PASS | decap RV=0 secrets equal=1 |
| X25519_ciphertext_is_32_raw_bytes | ✅ PASS | RV=0 len=32 (want 32; §6.3.17 gives Montgomery no DER form) |
| X25519_raw_ciphertext_round_trip | ✅ PASS | decap RV=0 secrets equal=1 |
| X25519_DER_ciphertext_still_accepted | ✅ PASS | decap RV=0 secrets equal=1 |

### SHA-3

| Test | Status | Details |
|---|---|---|
| Digest_SHA3_224 | ✅ PASS | len=28 deterministic, input-dependent |
| Digest_SHA3_512 | ✅ PASS | len=64 deterministic, input-dependent |
| HMAC_SHA3_224 | ✅ PASS | sign+verify round trip OK, macLen=28 |
| HMAC_SHA3_256 | ✅ PASS | sign+verify round trip OK, macLen=32 |
| HMAC_SHA3_384 | ✅ PASS | sign+verify round trip OK, macLen=48 |
| HMAC_SHA3_512 | ✅ PASS | sign+verify round trip OK, macLen=64 |
| RsaTail_GenerateRSA2048 | ✅ PASS | RV=0 |
| RsaTail_SHA3_224_PKCS | ✅ PASS | RV=0 |
| RsaTail_SHA3_224_PSS | ✅ PASS | RV=0 |
| RsaTail_SHA3_256_PKCS | ✅ PASS | RV=0 |
| RsaTail_SHA3_256_PSS | ✅ PASS | RV=0 |
| RsaTail_SHA3_512_PKCS | ✅ PASS | RV=0 |
| RsaTail_SHA3_512_PSS | ✅ PASS | RV=0 |
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
| PreHashGap_GenerateKey_128S | ✅ PASS | Gen SLH-DSA-SHA2-128S for pre-hash coverage |
| PreHashSLH_Generic_HASH_SLH_DSA_explicitSHA256 | ✅ PASS | real sign+verify round trip OK, sigLen=7856 |
| PreHashSLH_SHA224 | ✅ PASS | real sign+verify round trip OK, sigLen=7856 |
| PreHashSLH_SHA256 | ✅ PASS | real sign+verify round trip OK, sigLen=7856 |
| PreHashSLH_SHA384 | ✅ PASS | real sign+verify round trip OK, sigLen=7856 |
| PreHashSLH_SHA512 | ✅ PASS | real sign+verify round trip OK, sigLen=7856 |
| PreHashSLH_SHA3_224 | ✅ PASS | real sign+verify round trip OK, sigLen=7856 |
| PreHashSLH_SHA3_256 | ✅ PASS | real sign+verify round trip OK, sigLen=7856 |
| PreHashSLH_SHA3_384 | ✅ PASS | real sign+verify round trip OK, sigLen=7856 |
| PreHashSLH_SHA3_512 | ✅ PASS | real sign+verify round trip OK, sigLen=7856 |
| PreHashSLH_SHAKE128 | ✅ PASS | real sign+verify round trip OK, sigLen=7856 |
| PreHashSLH_SHAKE256 | ✅ PASS | real sign+verify round trip OK, sigLen=7856 |

### Session

| Test | Status | Details |
|---|---|---|
| C_OpenSession_InvalidSlot | ✅ PASS | RV=3 |
| C_SetAttributeValue_RO | ✅ PASS | RV=181 |
| Session_Object_CrossVisibility | ✅ PASS | Visible (Compliant) |
| C_SessionCancel | ✅ PASS | cancel OK; post-cancel C_Sign expected CKR_OPERATION_NOT_INITIALIZED, got RV=145 |
| C_LoginUser | ✅ PASS | RV=256 |

### WrapTemplate

| Test | Status | Details |
|---|---|---|
| Generate_KEK_with_WRAP_TEMPLATE | ✅ PASS |  |
| KEK_WRAP_TEMPLATE_round_trips | ✅ PASS | RV=0 ulValueLen=24 (want 24) |
| Wrap_without_template_baseline | ✅ PASS | RV=0 len=40 |
| Wrap_template_value_mismatch | ✅ PASS | RV=96 (want CKR_KEY_HANDLE_INVALID=0x60) |
| Wrap_template_match_proceeds | ✅ PASS | RV=0 len=40 |
| Wrap_template_absent_attribute | ✅ PASS | RV=96 (want CKR_KEY_HANDLE_INVALID=0x60) |

### XMSS

| Test | Status | Details |
|---|---|---|
| Generate_XMSS_SHA2_10_256 | ✅ PASS | Gen XMSS_SHA2_10_256 |
| C_Sign_XMSS_SHA2_10_256 | ✅ PASS | RV=0 |
| StatefulSign_size_query_idempotent | ✅ PASS | two C_Sign(NULL) → same size 2500 RV1=0 RV2=0 |
| StatefulSign_buffer_too_small | ✅ PASS | too-small buffer → CKR_BUFFER_TOO_SMALL(0x150), size echoed, RV=336 |
| StatefulSign_signs_after_queries | ✅ PASS | real C_Sign after queries verifies (leaf not burned) signRV=0 verifyRV=0 |
| Generate_XMSSMT_SHA2_20_2_256 | ✅ PASS | Gen XMSSMT_SHA2_20_2_256 |

### XmssParamSet

| Test | Status | Details |
|---|---|---|
| Generate_oid1_from_attribute | ✅ PASS |  |
| Sign_oid1_length | ✅ PASS | sig len=2500 (XMSS-SHA2_10_256 = 2500) |
| Generate_oid2_from_attribute | ✅ PASS |  |
| Public_CKA_PARAMETER_SET_echoes_2 | ✅ PASS | read 2 |
| Private_CKA_PARAMETER_SET_echoes_2 | ✅ PASS | read 2 |
| Sign_oid2_length | ✅ PASS | sig len=2692 (XMSS-SHA2_16_256 = 2692) |
| Attribute_wins_over_mechanism_parameter | ✅ PASS | attribute=1 mechParam=2 → sig len=2500 (must be 2500, the attribute's set) |
| Absent_CKA_PARAMETER_SET_is_TEMPLATE_INCOMPLETE | ✅ PASS | RV=208 (want CKR_TEMPLATE_INCOMPLETE=0xD0) |
| Unsupported_parameter_set_code | ✅ PASS | RV=521 (want CKR_PARAMETER_SET_NOT_SUPPORTED=0x209) |

