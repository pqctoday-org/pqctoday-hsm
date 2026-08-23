# softhsmrustv3 — PKCS#11 v3.2 Conformance Report (Rust engine)

**Engine:** softhsmrustv3 (Rust), wasm32 build with `--features acvp`
**Harness:** `rust/test_p11_conformance.js` (table-driven negative-path + KAT
matrix asserting exact `CKR_*` codes in spec priority order §5.4/§5.12, plus
PQC keygen/param-set, SP800-108 KBKDF, and message-based-crypto checks).
**Engine commit:** `5a107b2898f6` · **Generated:** 2026-08-23T21:58:02.681Z — machine-written
by this harness itself (`writeReport()` in `test_p11_conformance.js`) at the
end of every run, not hand-edited.
**Regenerate:** `scripts/local-gate.sh --rust-p11` (see below), or manually:
```
docker exec pqc-rust bash -c 'cd /ag/pqctoday-hsm/rust && \
  RUSTFLAGS="-C link-arg=-zstack-size=2097152" \
  wasm-pack build --target bundler --out-dir pkg --dev -- --features acvp'
cd rust && node test_p11_conformance.js
```

## Result

**256 passed / 1 failed** across 40 sections in this JS harness.

⚠️ **This run has 1 real failure(s)** — see "Full transcript" below
for the exact check(s) and `got`/`expected` codes. The hand-authored
narrative preserved below was written for an earlier, fully-passing run and
may describe (or claim) an all-green state that does not hold for this run —
trust the count above and the transcript, not prose written for a prior run.

This is the Rust engine's OWN conformance evidence. Previously the only checked-in
compliance artifact (`cpp_compliance_report.md`) targeted the **C++** engine,
while CACP (the KMIP server + wasm playground) ships the **Rust** engine — so
Rust conformance rested on prose (report gap P2/T1). This report closes that gap:
the actual Rust engine, exercised through its real PKCS#11 ABI (wasm-bindgen
`_C_*` exports), passes the full v3.2 negative-path + KAT matrix.

Up from 222/38 (2026-07-10, commit f5b253d): the two new sections close the
remaining two gaps from `pkcs11-v32-allowedmech-certobjects-remediation-plan-07102026.md`
— `CKA_ALLOWED_MECHANISMS` (§4.8 Table 13) engine-side enforcement across
every operation that binds a key to a mechanism, and `CKO_CERTIFICATE`
(§4.6, X.509 only). A third work package in that same plan — projecting
KMIP-issued/registered certificates onto the engine as real
`CKO_CERTIFICATE` objects — is verified by the **KMIP crate's own test
suite** (521 tests), not this wasm harness, since it's a KMIP-server-side
integration rather than a raw PKCS#11 ABI behavior; see that plan's WP-C
and the commit that shipped it for the evidence.

## 2026-07-17 — PKCS#11 Profiles v3.2 Baseline Provider + generic pre-hash mechanisms

Two gaps closed on `feat/pkcs11-v32-profile-and-hash-mechs` (branched from
this commit, `a113611`):

**Baseline Provider profile claim.** Every normative requirement from
[PKCS#11 Profiles v3.2 §5.1](https://docs.oasis-open.org/pkcs11/pkcs11-profiles/v3.2/pkcs11-profiles-v3.2.html)
is now met — verified item by item against the fetched spec text, not assumed:

| Requirement (§5.1) | Status |
|---|---|
| Data types (CK_VERSION, CK_INFO, … CK_PROFILE_ID, CK_FUNCTION_LIST, CK_INTERFACE, CK_C_INITIALIZE_ARGS) | Already present (standard ABI) |
| Attributes: CKA_CLASS, CKA_TOKEN, CKA_VALUE, CKA_ID, CKA_PRIVATE, CKA_MODIFIABLE, CKA_LABEL, CKA_UNIQUE_ID, CKA_PROFILE_ID | Already present + CKA_PROFILE_ID added this pass |
| Object: `CKO_PROFILE` with `CKA_PROFILE_ID = CKP_BASELINE_PROVIDER` | **Added** — `state::init_profile_objects`, materialized at slot creation, public/read-only |
| Functions: C_GetFunctionList, C_GetInterfaceList, C_GetInterface, C_Initialize, C_Finalize, C_GetInfo, C_GetSlotList, C_GetSlotInfo, C_GetTokenInfo, C_OpenSession, C_CloseSession, C_GetSessionInfo, C_FindObjectsInit, C_FindObjects, C_FindObjectsFinal, C_GetAttributeValue | Already present |
| Mechanisms | None specified — no gate |

Extended Provider is deliberately **not** claimed — its requirement list was
not audited this pass; a second `CKO_PROFILE` object should only be added
after every Extended item is checked the same way, not on assumption.

Covered by `ffi::profile_object_ffi_tests` (3 tests): the profile object is
public/findable pre-login, a client cannot create its own `CKO_PROFILE`
(`validate_create_template`), and the object is immutable/non-copyable/
non-destroyable (`CKA_MODIFIABLE`/`CKA_COPYABLE`/`CKA_DESTROYABLE` all
FALSE — the last of these required adding general `CKA_DESTROYABLE`
enforcement to `C_DestroyObject`, previously defined but unenforced).

**Generic pre-hash mechanisms (§6.67.7/§6.69.7).** `CKM_HASH_ML_DSA` (0x1F)
and `CKM_HASH_SLH_DSA` (0x34) are now advertised and implemented:
`ffi::remap_generic_hash_mech` parses `CK_HASH_SIGN_ADDITIONAL_CONTEXT.hash`
in `C_SignInit`/`C_VerifyInit`/`C_VerifySignatureInit` and remaps onto the
matching hash-specific mechanism (`crypto::handlers::map_generic_hash_mech`),
the same idiom already used for the `CKM_EDDSA` → `CKM_EDDSA_PH` phFlag
remap. SHAKE128/256 remain reachable only via their own dedicated
`CKM_HASH_{ML,SLH}_DSA_SHAKE128/256` mechanisms — the v3.2 header defines no
standalone SHAKE digest `CKM_` identifier, so they cannot be named through
the generic `hash` param.

Covered by `ffi::mechanism_table_tests::p2_map_generic_hash_mech_matrix` (all
8 real digest mappings + SHAKE/garbage rejection) and
`ffi::generic_prehash_mech_ffi_tests` (4 tests: real ML-DSA-65 keypair,
full `C_SignInit`→`C_Sign`→`C_VerifyInit`→`C_Verify` round trip through the
generic mechanism, cross-verification against the specific mechanism name,
and the missing-param / unknown-hash / SHAKE-as-hash negative cases).

All constants verified against both the vendored `src/lib/pkcs11/pkcs11t.h`
and a live fetch of `docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/include/
pkcs11-v3.2/pkcs11t.h` — no value taken from memory.

## 2026-07-18 — `native::*` token-scoping isolation gate (§2.4/§4.4)

`ffi::C_*` (the wasm-bindgen ABI this report's harness exercises) has always
enforced `state::can_access_object` — token-scoped handles, §2.4/§4.4 — at 8
call sites. The typed `native::*` surface (no wasm32 pointer marshalling;
what the KMIP server calls exclusively) did not: found and closed on
`feat/hsm-perf-bench` (see `rust-hsm-perf-bench-scenario-plan-07182026.md`
Part F in the workspace root for the full design/audit trail). Every
by-handle `native::*` function (sign/verify, encrypt/decrypt,
encapsulate/decapsulate, ECDH agree, get/set attribute, destroy, split/join,
hybrid) now routes through the same predicate via new `state::`
primitives (`resolve_session_access`, `with_object_checked[_mut]`,
`take_object_checked`), so a handle from another token uniformly fails
with `CKR_OBJECT_HANDLE_INVALID` on **both** surfaces — no PKCS#11-visible
behavior change on `ffi::*`, `native::*` now conformant where it previously
was not (native has no ABI/wasm harness of its own; verified by
`tests/multitenant_concurrency.rs` and `native::object::tests::
find_by_cka_id_is_token_scoped`, plus the unmodified `cargo test` suites of
both this crate — 309/309 — and the KMIP crate — 655+ lib tests, all
integration suites — confirming zero behavior change for existing
single-tenant callers).

Found and fixed in the same pass: a TOCTOU race in `ffi::C_Login` where the
per-token login-exclusivity check (§5.6 — only one login wins) read a stale
snapshot before the state write, letting concurrent logins on one token
silently double-succeed. Regression test:
`tests/multitenant_concurrency.rs::login_exclusivity_holds_under_concurrent_attempts`.

## Sections covered

- R1.2 — initialization gate (§5.4/§5.6) (4 passed / 0 failed)
- Token init (fixture — before any session, §5.7 C_InitToken) (1 passed / 0 failed)
- T7 — TokenInfo flags BEFORE C_InitPIN (§5.5, round-2 regression) (3 passed / 0 failed)
- R2.2 — session flags (§5.6) (2 passed / 0 failed)
- Login fixture — SO sets user PIN, then User login (§4.4) (4 passed / 0 failed)
- R2.1 — session-handle validation (§5.12 priority) (3 passed / 0 failed)
- R2.4 — key-handle vs permission codes (§5.12.4) (3 passed / 0 failed)
- R3.6 — CKA_PARAMETER_SET required for PQC keygen (§6.67.2) (2 passed / 0 failed)
- R1.4 — GCM IV validation (§6.27.7) (1 passed / 0 failed)
- H-4 — single-shot two-call convention (§5.2) (5 passed / 0 failed)
- Mixing guard — one-shot after Update → OPERATION_ACTIVE (§5.2) (4 passed / 0 failed)
- R2.5 — operation-active on re-init / find FSM (§5.10/§5.12) (4 passed / 0 failed)
- H-5 — stateful sign / digest two-call (§5.2) (3 passed / 0 failed)
- R1.3 — private-object visibility (§4.4) (4 passed / 0 failed)
- H-11 — CKR_ATTRIBUTE_SENSITIVE (§5.7.5) (2 passed / 0 failed)
- R1.5 — authenticated wrap AAD binding (§5.18.6/7) (4 passed / 0 failed)
- ML-KEM — encap/decap usage + provenance (§5.18.8/9) (4 passed / 0 failed)
- E1 — ML-DSA context string + hedge variant (§6.67, FIPS 204 §5.2) (10 passed / 0 failed)
- E9 — CKR_SIGNATURE_LEN_RANGE (§5.12.6) (2 passed / 0 failed)
- D4 — spec-mandated stubs (5 passed / 1 failed)
- F1 — mechanism table reconciliation (R6.2) (1 passed / 0 failed)
- R3.1 — C_CreateObject template validation (§4.1.1) (7 passed / 0 failed)
- E3 — GCM ulTagBits honored + validated (§6.27.7 / SP 800-38D §5.2.1.2) (11 passed / 0 failed)
- E4 — AES-CTR ulCounterBits (§6.27.6) (11 passed / 0 failed)
- E8 — HMAC general-length (§6.x CK_MAC_GENERAL_PARAMS) (10 passed / 0 failed)
- E2 — RSA-PSS params validated (§6.4.5) (1 passed / 0 failed)
- R3.7/D2 — session-object lifecycle + SessionCancel (§4.4/§5.6) (12 passed / 0 failed)
- Round-2 — keygen template + RNG codes (§5.16/§5.14) (2 passed / 0 failed)
- Round-2 — wrap/unwrap role-specific handle codes (§5.18) (3 passed / 0 failed)
- Round-2 — operate-stage session-handle gate (§5.12.1) (3 passed / 0 failed)
- Round-2 — T6 object management (Set/GetAttr, size, copy, §4.4.1/§5.7) (13 passed / 0 failed)
- Round-2 — dynamic TokenInfo (§5.5, T7) (6 passed / 0 failed)
- Round-2 — C_SignUpdate/Final ≡ one-shot C_Sign (CKM_SHA256_HMAC) (8 passed / 0 failed)
- Round-2 — mechanism table contents + FIPS ranges (F2/T8) (11 passed / 0 failed)
- Round-2 — T5 message API ≡ one-shot GCM (§5.19) (10 passed / 0 failed)
- Round-2 — SP800-108 KBKDF PRF must be a keyed-MAC mechanism (§6.26) (8 passed / 0 failed)
- Round-2 — SP800-108 CK_PRF_DATA_TYPE completeness (COUNTER, KEY_HANDLE, SUM_OF_SEGMENTS) (17 passed / 0 failed)
- WP4a — CKO_TRUST object lifecycle (§4.7 Table 25) (17 passed / 0 failed)
- WP-A — CKA_ALLOWED_MECHANISMS enforcement (§4.8 Table 13) (9 passed / 0 failed)
- WP-B — CKO_CERTIFICATE object lifecycle, X.509 only (§4.6 Tables 19-20) (26 passed / 0 failed)

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
  ❌ C_SignRecoverInit → FUNCTION_NOT_SUPPORTED: got 0x0, expected 0x54
  ✅ C_DigestEncryptUpdate (no active ops) → OPERATION_NOT_INITIALIZED

── F1 — mechanism table reconciliation (R6.2) ──
  ✅ all 116 advertised mechanisms answerable → 0 missing

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

── Round-2 — SP800-108 CK_PRF_DATA_TYPE completeness (COUNTER, KEY_HANDLE, SUM_OF_SEGMENTS) ──
  ✅ import secret key → OK
  ✅ Counter Mode + CK_SP800_108_COUNTER field → MECHANISM_PARAM_INVALID (Table 199)
  ✅ Feedback Mode without CK_SP800_108_COUNTER → OK
  ✅ Feedback Mode with CK_SP800_108_COUNTER → OK (Table 200)
  ✅ CK_SP800_108_COUNTER changes Feedback Mode output (not silently ignored)
  ✅ import secret key → OK
  ✅ import secret key → OK
  ✅ Counter Mode + CK_SP800_108_KEY_HANDLE → OK
  ✅ CK_SP800_108_KEY_HANDLE byte-equals Node-crypto reference (splices CKA_VALUE)
  ✅ CK_SP800_108_KEY_HANDLE with a different key → OK
  ✅ different KEY_HANDLE key values produce different derived output
  ✅ CK_SP800_108_KEY_HANDLE with a bogus handle → KEY_HANDLE_INVALID
  ✅ SUM_OF_KEYS DKM_LENGTH → OK
  ✅ SUM_OF_SEGMENTS DKM_LENGTH → OK
  ✅ SUM_OF_SEGMENTS output differs from SUM_OF_KEYS (L value actually rounds up)
  ✅ SUM_OF_KEYS byte-equals Node-crypto reference (L=160 bits)
  ✅ SUM_OF_SEGMENTS byte-equals Node-crypto reference (L=256 bits, rounded up)

── WP4a — CKO_TRUST object lifecycle (§4.7 Table 25) ──
  ✅ C_CreateObject(CKO_TRUST) → OK
  ✅ C_GetAttributeValue(CKA_ISSUER) → OK
  ✅ CKA_ISSUER round-trips byte-exact
  ✅ C_GetAttributeValue(CKA_TRUST_SERVER_AUTH) → OK
  ✅ CKA_TRUST_SERVER_AUTH round-trips as CKT_TRUSTED
  ✅ C_GetAttributeValue(unset CKA_TRUST_OCSP_SIGNING) → ATTRIBUTE_TYPE_INVALID
  ✅ unset CKA_TRUST_OCSP_SIGNING → CK_UNAVAILABLE_INFORMATION length
  ✅ C_SetAttributeValue(CKA_TRUST_OCSP_SIGNING) → OK (CKA_MODIFIABLE defaults TRUE)
  ✅ C_FindObjectsInit(CKA_CLASS=CKO_TRUST) → OK
  ✅ C_FindObjects → OK
  ✅ C_FindObjects locates the CKO_TRUST object
  ✅ C_FindObjects returns the correct handle
  ✅ C_FindObjectsFinal → OK
  ✅ C_CopyObject(CKO_TRUST) → OK
  ✅ C_DestroyObject(copy) → OK
  ✅ C_DestroyObject(CKO_TRUST) → OK
  ✅ destroyed CKO_TRUST object is gone → OBJECT_HANDLE_INVALID

── WP-A — CKA_ALLOWED_MECHANISMS enforcement (§4.8 Table 13) ──
  ✅ C_GenerateKey(AES, CKA_ALLOWED_MECHANISMS=[AES_GCM]) → OK
  ✅ C_EncryptInit(CKM_AES_GCM) on a GCM-restricted key → OK
  ✅ C_EncryptInit(CKM_AES_CBC) on a GCM-restricted key → MECHANISM_INVALID
  ✅ fixture: unrestricted AES key → OK
  ✅ C_EncryptInit(CKM_AES_CBC) on an unrestricted key → OK
  ✅ C_CreateObject with malformed CKA_ALLOWED_MECHANISMS length → ATTRIBUTE_VALUE_INVALID
  ✅ C_GenerateKeyPair(ML-DSA, private CKA_ALLOWED_MECHANISMS=[ML_DSA]) → OK
  ✅ C_SignInit(CKM_ML_DSA) on an ML_DSA-restricted key → OK
  ✅ C_SignInit(CKM_HASH_ML_DSA_SHA256) on an ML_DSA-only-restricted key → MECHANISM_INVALID

── WP-B — CKO_CERTIFICATE object lifecycle, X.509 only (§4.6 Tables 19-20) ──
  ✅ C_CreateObject(cert, no CKA_CERTIFICATE_TYPE) → TEMPLATE_INCOMPLETE
  ✅ C_CreateObject(cert, no CKA_SUBJECT) → TEMPLATE_INCOMPLETE
  ✅ C_CreateObject(cert, no CKA_VALUE and no CKA_URL) → TEMPLATE_INCOMPLETE
  ✅ C_CreateObject(cert, CKC_WTLS) → ATTRIBUTE_VALUE_INVALID (X.509 only)
  ✅ C_CreateObject(CKO_CERTIFICATE, CKC_X_509) → OK
  ✅ C_GetAttributeValue(CKA_SUBJECT) → OK
  ✅ CKA_SUBJECT round-trips byte-exact
  ✅ C_GetAttributeValue(CKA_VALUE) → OK
  ✅ CKA_VALUE round-trips byte-exact
  ✅ C_GetAttributeValue(CKA_ISSUER) → OK
  ✅ CKA_ISSUER round-trips byte-exact
  ✅ C_GetAttributeValue(CKA_CHECK_VALUE) → OK
  ✅ CKA_CHECK_VALUE = SHA-256(CKA_VALUE)[..3]
  ✅ C_FindObjectsInit({CLASS,ISSUER,SERIAL_NUMBER}) → OK
  ✅ C_FindObjects → OK
  ✅ C_FindObjects locates the certificate
  ✅ C_FindObjects returns the correct handle
  ✅ C_FindObjectsFinal → OK
  ✅ C_CreateObject(cert, CKA_TRUSTED=true) as USER → ATTRIBUTE_READ_ONLY
  ✅ C_Logout (leaving USER) → OK
  ✅ C_Login(SO) → OK
  ✅ C_CreateObject(cert, CKA_TRUSTED=true) as SO → OK
  ✅ C_GetAttributeValue(CKA_TRUSTED) → OK
  ✅ CKA_TRUSTED set by SO reads back TRUE
  ✅ C_Logout (leaving SO) → OK
  ✅ re-Login(USER) → OK

════════ RESULT: 256 passed, 1 failed ════════
```
