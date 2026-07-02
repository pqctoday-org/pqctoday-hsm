# softhsmrustv3 — PKCS#11 v3.2 Conformance Report (Rust engine)

**Engine:** softhsmrustv3 (Rust), wasm32 build with `--features acvp`
**Harness:** `rust/test_p11_conformance.js` (table-driven negative-path + KAT
matrix asserting exact `CKR_*` codes in spec priority order §5.4/§5.12, plus
PQC keygen/param-set, SP800-108 KBKDF, and message-based-crypto checks).
**Engine commit:** `f06f53f` · **Generated:** 2026-07-02
**Regenerate:** `scripts/local-gate.sh --rust-p11` (see below), or manually:
```
docker exec pqc-rust bash -c 'cd /ag/pqctoday-hsm/rust && \
  RUSTFLAGS="-C link-arg=-zstack-size=2097152" \
  wasm-pack build --target bundler --out-dir pkg --dev -- --features acvp'
cd rust && node test_p11_conformance.js
```

## Result

**188 passed / 0 failed** across 36 sections.

This is the Rust engine's OWN conformance evidence. Previously the only checked-in
compliance artifact (`cpp_compliance_report.md`) targeted the **C++** engine,
while CACP (the KMIP server + wasm playground) ships the **Rust** engine — so
Rust conformance rested on prose (report gap P2/T1). This report closes that gap:
the actual Rust engine, exercised through its real PKCS#11 ABI (wasm-bindgen
`_C_*` exports), passes the full v3.2 negative-path + KAT matrix.

## Sections covered

- R1.2 — initialization gate (§5.4/§5.6)
- Token init (fixture — before any session, §5.7 C_InitToken)
- T7 — TokenInfo flags BEFORE C_InitPIN (§5.5, round-2 regression)
- R2.2 — session flags (§5.6)
- Login fixture — SO sets user PIN, then User login (§4.4)
- R2.1 — session-handle validation (§5.12 priority)
- R2.4 — key-handle vs permission codes (§5.12.4)
- R3.6 — CKA_PARAMETER_SET required for PQC keygen (§6.67.2)
- R1.4 — GCM IV validation (§6.27.7)
- H-4 — single-shot two-call convention (§5.2)
- Mixing guard — one-shot after Update → OPERATION_ACTIVE (§5.2)
- R2.5 — operation-active on re-init / find FSM (§5.10/§5.12)
- H-5 — stateful sign / digest two-call (§5.2)
- R1.3 — private-object visibility (§4.4)
- H-11 — CKR_ATTRIBUTE_SENSITIVE (§5.7.5)
- R1.5 — authenticated wrap AAD binding (§5.18.6/7)
- ML-KEM — encap/decap usage + provenance (§5.18.8/9)
- E1 — ML-DSA context string + hedge variant (§6.67, FIPS 204 §5.2)
- E9 — CKR_SIGNATURE_LEN_RANGE (§5.12.6)
- D4 — spec-mandated stubs
- F1 — mechanism table reconciliation (R6.2)
- R3.1 — C_CreateObject template validation (§4.1.1)
- E3 — GCM ulTagBits honored + validated (§6.27.7 / SP 800-38D §5.2.1.2)
- E4 — AES-CTR ulCounterBits (§6.27.6)
- E8 — HMAC general-length (§6.x CK_MAC_GENERAL_PARAMS)
- E2 — RSA-PSS params validated (§6.4.5)
- R3.7/D2 — session-object lifecycle + SessionCancel (§4.4/§5.6)
- Round-2 — keygen template + RNG codes (§5.16/§5.14)
- Round-2 — wrap/unwrap role-specific handle codes (§5.18)
- Round-2 — operate-stage session-handle gate (§5.12.1)
- Round-2 — T6 object management (Set/GetAttr, size, copy, §4.4.1/§5.7)
- Round-2 — dynamic TokenInfo (§5.5, T7)
- Round-2 — C_SignUpdate/Final ≡ one-shot C_Sign (CKM_SHA256_HMAC)
- Round-2 — mechanism table contents + FIPS ranges (F2/T8)
- Round-2 — T5 message API ≡ one-shot GCM (§5.19)
- Round-2 — SP800-108 KBKDF PRF must be a keyed-MAC mechanism (§6.26)

## Full transcript

```

── R1.2 — initialization gate (§5.4/§5.6) ──
  ✅ C_GetSlotList before C_Initialize → CRYPTOKI_NOT_INITIALIZED
  ✅ C_Finalize before C_Initialize → CRYPTOKI_NOT_INITIALIZED
  ✅ C_Initialize → OK
  ✅ double C_Initialize → CRYPTOKI_ALREADY_INITIALIZED

── Token init (fixture — before any session, §5.7 C_InitToken) ──
  ✅ C_InitToken → OK

── T7 — TokenInfo flags BEFORE C_InitPIN (§5.5, round-2 regression) ──
  ✅ C_GetTokenInfo → OK
  ✅ CKF_TOKEN_INITIALIZED set after InitToken
  ✅ CKF_USER_PIN_INITIALIZED still clear before InitPIN

── R2.2 — session flags (§5.6) ──
  ✅ C_OpenSession without CKF_SERIAL_SESSION → SESSION_PARALLEL_NOT_SUPPORTED
  ✅ C_OpenSession(RW|SERIAL) → OK

── Login fixture — SO sets user PIN, then User login (§4.4) ──
  ✅ C_Login(SO) → OK
  ✅ C_InitPIN(user) → OK
  ✅ C_Logout → OK
  ✅ C_Login(USER) → OK

── R2.1 — session-handle validation (§5.12 priority) ──
  ✅ C_GenerateKey with bogus session → SESSION_HANDLE_INVALID
  ✅ C_SignInit with bogus session → SESSION_HANDLE_INVALID
  ✅ C_GenerateRandom with bogus session → SESSION_HANDLE_INVALID

── R2.4 — key-handle vs permission codes (§5.12.4) ──
  ✅ C_GenerateKey(AES-256) → OK
  ✅ C_SignInit with nonexistent key → KEY_HANDLE_INVALID
  ✅ C_SignInit on AES key without CKA_SIGN → KEY_FUNCTION_NOT_PERMITTED

── R3.6 — CKA_PARAMETER_SET required for PQC keygen (§6.67.2) ──
  ✅ ML-DSA keygen WITH param set → OK
  ✅ ML-DSA keygen WITHOUT param set → TEMPLATE_INCOMPLETE

── R1.4 — GCM IV validation (§6.27.7) ──
  ✅ C_EncryptInit GCM with NULL/empty IV → MECHANISM_PARAM_INVALID

── H-4 — single-shot two-call convention (§5.2) ──
  ✅ C_EncryptInit GCM → OK
  ✅ C_Encrypt NULL-buffer length query → OK
  ✅ C_Encrypt with too-small buffer → BUFFER_TOO_SMALL
  ✅ C_Encrypt retry after BUFFER_TOO_SMALL → OK (op preserved)
  ✅ C_Encrypt after completion → OPERATION_NOT_INITIALIZED

── Mixing guard — one-shot after Update → OPERATION_ACTIVE (§5.2) ──
  ✅ C_EncryptInit CBC_PAD → OK
  ✅ C_EncryptUpdate → OK
  ✅ C_Encrypt after C_EncryptUpdate → OPERATION_ACTIVE
  ✅ C_EncryptFinal still works → OK

── R2.5 — operation-active on re-init / find FSM (§5.10/§5.12) ──
  ✅ C_SignInit(ML-DSA) → OK
  ✅ second C_SignInit while active → OPERATION_ACTIVE
  ✅ C_Sign drains op → OK
  ✅ C_FindObjectsFinal without init → OPERATION_NOT_INITIALIZED

── H-5 — stateful sign / digest two-call (§5.2) ──
  ✅ C_DigestInit(SHA-256) → OK
  ✅ C_DigestFinal too-small → BUFFER_TOO_SMALL
  ✅ C_DigestFinal retry → OK (op preserved)

── R1.3 — private-object visibility (§4.4) ──
  ✅ C_CreateObject(private secret) → OK
  ✅ C_GetAttributeValue on private obj w/o login → OBJECT_HANDLE_INVALID
  ✅ C_DestroyObject on private obj w/o login → OBJECT_HANDLE_INVALID
  ✅ re-Login(USER) → OK

── H-11 — CKR_ATTRIBUTE_SENSITIVE (§5.7.5) ──
  ✅ C_CreateObject(sensitive secret) → OK
  ✅ C_GetAttributeValue(CKA_VALUE) on sensitive → ATTRIBUTE_SENSITIVE

── R1.5 — authenticated wrap AAD binding (§5.18.6/7) ──
  ✅ C_WrapKeyAuthenticated length query → OK
  ✅ C_WrapKeyAuthenticated → OK
  ✅ C_UnwrapKeyAuthenticated with SAME AAD → OK
  ✅ C_UnwrapKeyAuthenticated with WRONG AAD → ENCRYPTED_DATA_INVALID

── ML-KEM — encap/decap usage + provenance (§5.18.8/9) ──
  ✅ ML-KEM keygen → OK
  ✅ C_EncapsulateKey length query → OK
  ✅ C_EncapsulateKey → OK
  ✅ C_EncapsulateKey with private key → KEY_FUNCTION_NOT_PERMITTED

── E1 — ML-DSA context string + hedge variant (§6.67, FIPS 204 §5.2) ──
  ✅ sign with context A → OK
  ✅ verify with context A → OK
  ✅ verify with EMPTY context → SIGNATURE_INVALID
  ✅ verify with context B → SIGNATURE_INVALID
  ✅ deterministic sign #1 → OK
  ✅ deterministic signatures identical → true
  ✅ deterministic sig verifies → OK
  ✅ hedged signatures differ → true
  ✅ context >255 bytes → MECHANISM_PARAM_INVALID
  ✅ bad hedge variant → MECHANISM_PARAM_INVALID

── E9 — CKR_SIGNATURE_LEN_RANGE (§5.12.6) ──
  ✅ VerifyInit → OK
  ✅ C_Verify with truncated signature → SIGNATURE_LEN_RANGE

── D4 — spec-mandated stubs ──
  ✅ C_GetFunctionStatus → FUNCTION_NOT_PARALLEL
  ✅ C_CancelFunction → FUNCTION_NOT_PARALLEL
  ✅ C_WaitForSlotEvent(DONT_BLOCK) → NO_EVENT
  ✅ C_WaitForSlotEvent(blocking) → FUNCTION_NOT_SUPPORTED
  ✅ C_SignRecoverInit → FUNCTION_NOT_SUPPORTED
  ✅ C_DigestEncryptUpdate (no active ops) → OPERATION_NOT_INITIALIZED

── F1 — mechanism table reconciliation (R6.2) ──
  ✅ all 103 advertised mechanisms answerable → 0 missing

── R3.1 — C_CreateObject template validation (§4.1.1) ──
  ✅ no CKA_CLASS → TEMPLATE_INCOMPLETE
  ✅ key class without CKA_KEY_TYPE → TEMPLATE_INCOMPLETE
  ✅ secret key without CKA_VALUE → TEMPLATE_INCOMPLETE
  ✅ AES key with 17-byte value → ATTRIBUTE_VALUE_INVALID
  ✅ CKK_AES under CKO_PUBLIC_KEY → TEMPLATE_INCONSISTENT
  ✅ valid AES import → OK
  ✅ null ph_object → ARGUMENTS_BAD

── E3 — GCM ulTagBits honored + validated (§6.27.7 / SP 800-38D §5.2.1.2) ──
  ✅ EncryptInit GCM tag=96 → OK
  ✅ length query → OK
  ✅ ct length honors 96-bit tag (20+12)
  ✅ Encrypt(tag=96) → OK
  ✅ DecryptInit GCM tag=96 → OK
  ✅ Decrypt(tag=96) round-trip → OK
  ✅ plaintext length 20
  ✅ DecryptInit again → OK
  ✅ Decrypt with corrupted truncated tag → ENCRYPTED_DATA_INVALID
  ✅ EncryptInit GCM tag=24 → MECHANISM_PARAM_INVALID
  ✅ GCM ulIvBits≠ulIvLen*8 → MECHANISM_PARAM_INVALID

── E4 — AES-CTR ulCounterBits (§6.27.6) ──
  ✅ EncryptInit CTR counterBits=32 → OK
  ✅ Encrypt(ctr32) → OK
  ✅ EncryptInit CTR counterBits=128 → OK
  ✅ Encrypt(ctr128) → OK
  ✅ block 1 identical across widths
  ✅ post-wrap blocks DIFFER between 32/128-bit widths
  ✅ DecryptInit CTR counterBits=32 → OK
  ✅ Decrypt(ctr32) round-trip → OK
  ✅ round-trip matches plaintext
  ✅ CTR counterBits=0 → MECHANISM_PARAM_INVALID
  ✅ CTR counterBits=129 → MECHANISM_PARAM_INVALID

── E8 — HMAC general-length (§6.x CK_MAC_GENERAL_PARAMS) ──
  ✅ import HMAC key → OK
  ✅ SignInit SHA256_HMAC_GENERAL(16) → OK
  ✅ length query → OK
  ✅ mac length = 16
  ✅ Sign → OK
  ✅ VerifyInit GENERAL(16) → OK
  ✅ Verify truncated MAC → OK
  ✅ VerifyInit again → OK
  ✅ Verify with wrong length (8) → SIGNATURE_LEN_RANGE
  ✅ ulMacLength=33 > digest → MECHANISM_PARAM_INVALID

── E2 — RSA-PSS params validated (§6.4.5) ──
  ✅ PSS params with bad MGF → MECHANISM_PARAM_INVALID

── R3.7/D2 — session-object lifecycle + SessionCancel (§4.4/§5.6) ──
  ✅ second session opens → OK
  ✅ create SESSION object in s2 → OK
  ✅ create TOKEN object in s2 → OK
  ✅ close s2 → OK
  ✅ session object gone after close → OBJECT_HANDLE_INVALID
  ✅ token object survives close → OK
  ✅ DigestInit → OK
  ✅ SessionCancel(CKF_DIGEST) → OK
  ✅ DigestFinal after cancel → OPERATION_NOT_INITIALIZED
  ✅ SessionCancel(flags=0) → OK (cancels nothing)
  ✅ SessionCancel bad session → SESSION_HANDLE_INVALID
  ✅ CloseAllSessions bad slot → SLOT_ID_INVALID

── Round-2 — keygen template + RNG codes (§5.16/§5.14) ──
  ✅ C_GenerateKey(AES) without CKA_VALUE_LEN → TEMPLATE_INCOMPLETE
  ✅ C_SeedRandom → RANDOM_SEED_NOT_SUPPORTED

── Round-2 — wrap/unwrap role-specific handle codes (§5.18) ──
  ✅ fixture: target AES key → OK
  ✅ C_WrapKey with bogus wrapping key → WRAPPING_KEY_HANDLE_INVALID
  ✅ C_UnwrapKey with bogus unwrapping key → UNWRAPPING_KEY_HANDLE_INVALID

── Round-2 — operate-stage session-handle gate (§5.12.1) ──
  ✅ C_Sign with bogus session → SESSION_HANDLE_INVALID
  ✅ C_Encrypt with bogus session → SESSION_HANDLE_INVALID
  ✅ C_FindObjects with bogus session → SESSION_HANDLE_INVALID

── Round-2 — T6 object management (Set/GetAttr, size, copy, §4.4.1/§5.7) ──
  ✅ fixture: AES key → OK
  ✅ C_SetAttributeValue(CKA_LABEL) → OK
  ✅ read back CKA_LABEL → OK
  ✅ CKA_LABEL round-trips byte-exact
  ✅ C_SetAttributeValue(CKA_CLASS) → ATTRIBUTE_READ_ONLY
  ✅ C_GetObjectSize → OK
  ✅ object size > 0
  ✅ CKA_UNIQUE_ID readable via attribute type 0x4 → OK
  ✅ CKA_UNIQUE_ID non-empty
  ✅ C_CopyObject → OK
  ✅ copy is a live object → OK
  ✅ copy CKA_UNIQUE_ID readable → OK
  ✅ copy received a FRESH CKA_UNIQUE_ID

── Round-2 — dynamic TokenInfo (§5.5, T7) ──
  ✅ C_GetTokenInfo → OK
  ✅ label matches C_InitToken value
  ✅ CKF_USER_PIN_INITIALIZED set after InitPIN
  ✅ CKF_TOKEN_INITIALIZED set
  ✅ ulSessionCount nonzero while a session is open
  ✅ ulRwSessionCount nonzero (hS is R/W)

── Round-2 — C_SignUpdate/Final ≡ one-shot C_Sign (CKM_SHA256_HMAC) ──
  ✅ import HMAC key → OK
  ✅ SignInit (one-shot) → OK
  ✅ C_Sign (one-shot) → OK
  ✅ SignInit (multipart) → OK
  ✅ C_SignUpdate part 1 → OK
  ✅ C_SignUpdate part 2 → OK
  ✅ C_SignFinal → OK
  ✅ multipart HMAC byte-equals one-shot

── Round-2 — mechanism table contents + FIPS ranges (F2/T8) ──
  ✅ C_GetMechanismList count query → OK
  ✅ C_GetMechanismList → OK
  ✅ mechanism list contains CKM_SHA384_RSA_PKCS 0x41
  ✅ mechanism list contains CKM_SHA512_RSA_PKCS 0x42
  ✅ mechanism list contains CKM_SHA384_RSA_PKCS_PSS 0x44
  ✅ mechanism list contains CKM_SHA512_RSA_PKCS_PSS 0x45
  ✅ mechanism list contains CKM_CHACHA20 0x1226
  ✅ mechanism list contains CKM_CHACHA20_POLY1305 0x4021
  ✅ C_GetMechanismInfo(CKM_ML_KEM) → OK
  ✅ ML-KEM ulMinKeySize = 800 (FIPS 203)
  ✅ ML-KEM ulMaxKeySize = 1568 (FIPS 203)

── Round-2 — T5 message API ≡ one-shot GCM (§5.19) ──
  ✅ fixture: AES key → OK
  ✅ C_EncryptInit GCM (reference) → OK
  ✅ C_Encrypt (reference) → OK
  ✅ reference output is ct(20)+tag(16)
  ✅ C_MessageEncryptInit GCM → OK
  ✅ C_EncryptMessageBegin → OK
  ✅ C_EncryptMessageNext part 1 (12 B) → OK
  ✅ C_EncryptMessageNext part 2 (8 B, END_OF_MESSAGE) → OK
  ✅ C_MessageEncryptFinal → OK
  ✅ streamed ct+tag byte-equals one-shot GCM

── Round-2 — SP800-108 KBKDF PRF must be a keyed-MAC mechanism (§6.26) ──
  ✅ import KBKDF base key → OK
  ✅ C_DeriveKey SP800-108 with bare CKM_SHA256 PRF → MECHANISM_PARAM_INVALID
  ✅ C_DeriveKey SP800-108 with CKM_SHA384_HMAC PRF → OK
  ✅ read SHA384-PRF derived CKA_VALUE → OK
  ✅ SHA384-PRF KBKDF byte-equals Node-crypto counter-mode reference
  ✅ C_DeriveKey SP800-108 with CKM_SHA256_HMAC PRF → OK
  ✅ read SHA256-PRF derived CKA_VALUE → OK
  ✅ SHA384-PRF output differs from SHA256-PRF output (no silent default)

════════ RESULT: 188 passed, 0 failed ════════
```
