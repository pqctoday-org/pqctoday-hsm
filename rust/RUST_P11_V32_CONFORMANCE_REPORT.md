# softhsmrustv3 — PKCS#11 v3.2 Conformance Report (Rust engine)

**Engine:** softhsmrustv3 (Rust), wasm32 build with `--features acvp`
**Harness:** `rust/test_p11_conformance.js` (table-driven negative-path + KAT
matrix asserting exact `CKR_*` codes in spec priority order §5.4/§5.12, plus
PQC keygen/param-set, SP800-108 KBKDF, and message-based-crypto checks).
**Engine commit:** `f341ddfe20d7` · **Generated:** 2026-08-30T19:56:11.063Z — machine-written
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

**980 passed / 0 failed** across 51 sections in this JS harness.

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
- D4 — spec-mandated stubs (5 passed / 0 failed)
- D4b — C_SignRecover / C_VerifyRecover round-trip (RSA only, §5.13) (17 passed / 0 failed)
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
- G1 — message-based decrypt/verify round trip (§5.19) (45 passed / 0 failed)
- Round-2 — SP800-108 KBKDF PRF must be a keyed-MAC mechanism (§6.26) (8 passed / 0 failed)
- Round-2 — SP800-108 CK_PRF_DATA_TYPE completeness (COUNTER, KEY_HANDLE, SUM_OF_SEGMENTS) (17 passed / 0 failed)
- WP4a — CKO_TRUST object lifecycle (§4.7 Table 25) (17 passed / 0 failed)
- WP-A — CKA_ALLOWED_MECHANISMS enforcement (§4.8 Table 13) (9 passed / 0 failed)
- WP-B — CKO_CERTIFICATE object lifecycle, X.509 only (§4.6 Tables 19-20) (26 passed / 0 failed)
- G2a — SLH-DSA baseline + v3.2 pre-hash ML-DSA/SLH-DSA round trips (§6.67.7/§6.69.7) (94 passed / 0 failed)
- G2b — SHA-3 digest/HMAC/HMAC-general + KDF-tail round trips (§6.29x/§6.45) (80 passed / 0 failed)
- G3 — RSA-OAEP / RSA-PSS / hash-then-RSA family (§6.4) (91 passed / 0 failed)
- G4 — ECDSA / EC-derive / EdDSA / Montgomery family (§6.3/§6.7) (81 passed / 0 failed)
- G5 — AES-ECB / AES-KeyWrap variants / ChaCha20 family (§6.11/§6.20/§6.21/§6.31) (44 passed / 0 failed)
- G6 — RIPEMD160 / bare SHA384_HMAC+SHA512_HMAC / GENERIC_SECRET / CONCATENATE / PBKDF2 (39 passed / 0 failed)
- G7 — stateful hash-based signatures: HSS (§6.14) (7 passed / 0 failed)
- G8 — vendor-defined mechanisms: FrodoKEM / Keccak-256 / KMAC / BIP32 (≥ CKM_VENDOR_DEFINED) (29 passed / 0 failed)
- G9 — advertise-vs-dispatch invariant: every advertised mechanism has a real dispatch path (new) (197 passed / 0 failed)

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
  ✅ C_SignRecoverInit with NULL mechanism (cancel form, nothing active) → OK

── D4b — C_SignRecover / C_VerifyRecover round-trip (RSA only, §5.13) ──
  ✅ CKM_RSA_X_509 (raw): keygen → OK
  ✅ CKM_RSA_X_509 (raw): SignRecoverInit → OK
  ✅ CKM_RSA_X_509 (raw): SignRecover → OK
  ✅ CKM_RSA_X_509 (raw): VerifyRecoverInit → OK
  ✅ CKM_RSA_X_509 (raw): VerifyRecover → OK
  ✅ CKM_RSA_X_509 (raw): recovered message matches (tail)
  ✅ CKM_RSA_X_509 (raw): VerifyRecoverInit (2nd) → OK
  ✅ CKM_RSA_X_509 (raw): tampered signature never recovers the original message
  ✅ CKM_RSA_PKCS: keygen → OK
  ✅ CKM_RSA_PKCS: SignRecoverInit → OK
  ✅ CKM_RSA_PKCS: SignRecover → OK
  ✅ CKM_RSA_PKCS: VerifyRecoverInit → OK
  ✅ CKM_RSA_PKCS: VerifyRecover → OK
  ✅ CKM_RSA_PKCS: recovered message matches (tail)
  ✅ CKM_RSA_PKCS: VerifyRecoverInit (2nd) → OK
  ✅ CKM_RSA_PKCS: tampered signature never recovers the original message
  ✅ C_DigestEncryptUpdate (no active ops) → OPERATION_NOT_INITIALIZED

── F1 — mechanism table reconciliation (R6.2) ──
  ✅ all 117 advertised mechanisms answerable → 0 missing

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

── G1 — message-based decrypt/verify round trip (§5.19) ──
  ✅ fixture: AES key → OK
  ✅ C_MessageEncryptInit (one-shot fixture) → OK
  ✅ C_EncryptMessage length query = plaintext length (tag travels out-of-band)
  ✅ C_EncryptMessage (one-shot, previously untested) → OK
  ✅ C_MessageEncryptFinal → OK
  ✅ C_MessageDecryptInit → OK
  ✅ C_DecryptMessage length query = ciphertext length
  ✅ C_DecryptMessage (one-shot, previously untested) → OK
  ✅ one-shot message-encrypt → message-decrypt recovers the ORIGINAL plaintext (real SEAM)
  ✅ C_MessageDecryptFinal → OK
  ✅ C_MessageDecryptInit (tamper control) → OK
  ✅ C_DecryptMessage with tampered tag → ENCRYPTED_DATA_INVALID
  ✅ C_MessageDecryptFinal (after failed decrypt) → OK
  ✅ C_MessageEncryptInit (streaming fixture) → OK
  ✅ C_EncryptMessageBegin (streaming fixture) → OK
  ✅ C_EncryptMessageNext part 1 (streaming fixture) → OK
  ✅ C_EncryptMessageNext part 2 END_OF_MESSAGE (streaming fixture) → OK
  ✅ C_MessageEncryptFinal (streaming fixture) → OK
  ✅ C_MessageDecryptInit (streaming, previously untested) → OK
  ✅ C_DecryptMessageBegin (previously untested) → OK
  ✅ C_DecryptMessageNext part 1, intermediate (previously untested) → OK
  ✅ intermediate part releases 0 bytes (plaintext withheld until tag verifies, §5.15)
  ✅ C_DecryptMessageNext part 2 END_OF_MESSAGE (previously untested) → OK
  ✅ streaming message-encrypt → message-decrypt recovers the ORIGINAL plaintext (real SEAM)
  ✅ C_MessageDecryptFinal (streaming, previously untested) → OK
  ✅ import HMAC key (message sign/verify fixture) → OK
  ✅ C_MessageSignInit (one-shot fixture) → OK
  ✅ C_SignMessage (one-shot, previously untested) → OK
  ✅ C_MessageSignFinal → OK
  ✅ C_MessageVerifyInit (one-shot, previously untested) → OK
  ✅ C_VerifyMessage (one-shot, previously untested) validates the REAL signature → OK
  ✅ C_MessageVerifyFinal → OK
  ✅ C_MessageVerifyInit (tamper control) → OK
  ✅ C_VerifyMessage with tampered signature → SIGNATURE_INVALID
  ✅ C_MessageVerifyFinal (after tamper) → OK
  ✅ C_MessageSignInit (streaming, previously untested) → OK
  ✅ C_SignMessageBegin (previously untested) → OK
  ✅ C_SignMessageNext part 1, non-final (previously untested) → OK
  ✅ C_SignMessageNext part 2, final (previously untested) → OK
  ✅ C_MessageSignFinal (streaming, previously untested) → OK
  ✅ C_MessageVerifyInit (streaming, previously untested) → OK
  ✅ C_VerifyMessageBegin (previously untested) → OK
  ✅ C_VerifyMessageNext part 1, non-final (previously untested) → OK
  ✅ C_VerifyMessageNext part 2, final — validates the REAL streamed signature (real SEAM) → OK
  ✅ C_MessageVerifyFinal (streaming, previously untested) → OK

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

── G2a — SLH-DSA baseline + v3.2 pre-hash ML-DSA/SLH-DSA round trips (§6.67.7/§6.69.7) ──
  ✅ CKM_SLH_DSA_KEY_PAIR_GEN (SHA2-128f, previously untested) → OK
  ✅ SignInit(CKM_SLH_DSA, previously untested) → OK
  ✅ Sign(CKM_SLH_DSA) → OK
  ✅ VerifyInit(CKM_SLH_DSA, previously untested) → OK
  ✅ Verify(CKM_SLH_DSA) round trip → OK
  ✅ VerifyInit(CKM_SLH_DSA) (2nd) → OK
  ✅ Verify(CKM_SLH_DSA) tampered message → SIGNATURE_INVALID
  ✅ fixture: ML-DSA-65 keypair → OK
  ✅ CKM_HASH_ML_DSA_SHA224: SignInit (previously untested) → OK
  ✅ CKM_HASH_ML_DSA_SHA224: Sign → OK
  ✅ CKM_HASH_ML_DSA_SHA224: VerifyInit (previously untested) → OK
  ✅ CKM_HASH_ML_DSA_SHA224: Verify round trip → OK
  ✅ CKM_HASH_ML_DSA_SHA384: SignInit (previously untested) → OK
  ✅ CKM_HASH_ML_DSA_SHA384: Sign → OK
  ✅ CKM_HASH_ML_DSA_SHA384: VerifyInit (previously untested) → OK
  ✅ CKM_HASH_ML_DSA_SHA384: Verify round trip → OK
  ✅ CKM_HASH_ML_DSA_SHA512: SignInit (previously untested) → OK
  ✅ CKM_HASH_ML_DSA_SHA512: Sign → OK
  ✅ CKM_HASH_ML_DSA_SHA512: VerifyInit (previously untested) → OK
  ✅ CKM_HASH_ML_DSA_SHA512: Verify round trip → OK
  ✅ CKM_HASH_ML_DSA_SHA3_224: SignInit (previously untested) → OK
  ✅ CKM_HASH_ML_DSA_SHA3_224: Sign → OK
  ✅ CKM_HASH_ML_DSA_SHA3_224: VerifyInit (previously untested) → OK
  ✅ CKM_HASH_ML_DSA_SHA3_224: Verify round trip → OK
  ✅ CKM_HASH_ML_DSA_SHA3_256: SignInit (previously untested) → OK
  ✅ CKM_HASH_ML_DSA_SHA3_256: Sign → OK
  ✅ CKM_HASH_ML_DSA_SHA3_256: VerifyInit (previously untested) → OK
  ✅ CKM_HASH_ML_DSA_SHA3_256: Verify round trip → OK
  ✅ CKM_HASH_ML_DSA_SHA3_384: SignInit (previously untested) → OK
  ✅ CKM_HASH_ML_DSA_SHA3_384: Sign → OK
  ✅ CKM_HASH_ML_DSA_SHA3_384: VerifyInit (previously untested) → OK
  ✅ CKM_HASH_ML_DSA_SHA3_384: Verify round trip → OK
  ✅ CKM_HASH_ML_DSA_SHA3_512: SignInit (previously untested) → OK
  ✅ CKM_HASH_ML_DSA_SHA3_512: Sign → OK
  ✅ CKM_HASH_ML_DSA_SHA3_512: VerifyInit (previously untested) → OK
  ✅ CKM_HASH_ML_DSA_SHA3_512: Verify round trip → OK
  ✅ CKM_HASH_ML_DSA_SHAKE128: SignInit (previously untested) → OK
  ✅ CKM_HASH_ML_DSA_SHAKE128: Sign → OK
  ✅ CKM_HASH_ML_DSA_SHAKE128: VerifyInit (previously untested) → OK
  ✅ CKM_HASH_ML_DSA_SHAKE128: Verify round trip → OK
  ✅ CKM_HASH_ML_DSA_SHAKE256: SignInit (previously untested) → OK
  ✅ CKM_HASH_ML_DSA_SHAKE256: Sign → OK
  ✅ CKM_HASH_ML_DSA_SHAKE256: VerifyInit (previously untested) → OK
  ✅ CKM_HASH_ML_DSA_SHAKE256: Verify round trip → OK
  ✅ CKM_HASH_SLH_DSA_SHA224: SignInit (previously untested) → OK
  ✅ CKM_HASH_SLH_DSA_SHA224: Sign → OK
  ✅ CKM_HASH_SLH_DSA_SHA224: VerifyInit (previously untested) → OK
  ✅ CKM_HASH_SLH_DSA_SHA224: Verify round trip → OK
  ✅ CKM_HASH_SLH_DSA_SHA256: SignInit (previously untested) → OK
  ✅ CKM_HASH_SLH_DSA_SHA256: Sign → OK
  ✅ CKM_HASH_SLH_DSA_SHA256: VerifyInit (previously untested) → OK
  ✅ CKM_HASH_SLH_DSA_SHA256: Verify round trip → OK
  ✅ CKM_HASH_SLH_DSA_SHA384: SignInit (previously untested) → OK
  ✅ CKM_HASH_SLH_DSA_SHA384: Sign → OK
  ✅ CKM_HASH_SLH_DSA_SHA384: VerifyInit (previously untested) → OK
  ✅ CKM_HASH_SLH_DSA_SHA384: Verify round trip → OK
  ✅ CKM_HASH_SLH_DSA_SHA512: SignInit (previously untested) → OK
  ✅ CKM_HASH_SLH_DSA_SHA512: Sign → OK
  ✅ CKM_HASH_SLH_DSA_SHA512: VerifyInit (previously untested) → OK
  ✅ CKM_HASH_SLH_DSA_SHA512: Verify round trip → OK
  ✅ CKM_HASH_SLH_DSA_SHA3_224: SignInit (previously untested) → OK
  ✅ CKM_HASH_SLH_DSA_SHA3_224: Sign → OK
  ✅ CKM_HASH_SLH_DSA_SHA3_224: VerifyInit (previously untested) → OK
  ✅ CKM_HASH_SLH_DSA_SHA3_224: Verify round trip → OK
  ✅ CKM_HASH_SLH_DSA_SHA3_256: SignInit (previously untested) → OK
  ✅ CKM_HASH_SLH_DSA_SHA3_256: Sign → OK
  ✅ CKM_HASH_SLH_DSA_SHA3_256: VerifyInit (previously untested) → OK
  ✅ CKM_HASH_SLH_DSA_SHA3_256: Verify round trip → OK
  ✅ CKM_HASH_SLH_DSA_SHA3_384: SignInit (previously untested) → OK
  ✅ CKM_HASH_SLH_DSA_SHA3_384: Sign → OK
  ✅ CKM_HASH_SLH_DSA_SHA3_384: VerifyInit (previously untested) → OK
  ✅ CKM_HASH_SLH_DSA_SHA3_384: Verify round trip → OK
  ✅ CKM_HASH_SLH_DSA_SHA3_512: SignInit (previously untested) → OK
  ✅ CKM_HASH_SLH_DSA_SHA3_512: Sign → OK
  ✅ CKM_HASH_SLH_DSA_SHA3_512: VerifyInit (previously untested) → OK
  ✅ CKM_HASH_SLH_DSA_SHA3_512: Verify round trip → OK
  ✅ CKM_HASH_SLH_DSA_SHAKE128: SignInit (previously untested) → OK
  ✅ CKM_HASH_SLH_DSA_SHAKE128: Sign → OK
  ✅ CKM_HASH_SLH_DSA_SHAKE128: VerifyInit (previously untested) → OK
  ✅ CKM_HASH_SLH_DSA_SHAKE128: Verify round trip → OK
  ✅ CKM_HASH_SLH_DSA_SHAKE256: SignInit (previously untested) → OK
  ✅ CKM_HASH_SLH_DSA_SHAKE256: Sign → OK
  ✅ CKM_HASH_SLH_DSA_SHAKE256: VerifyInit (previously untested) → OK
  ✅ CKM_HASH_SLH_DSA_SHAKE256: Verify round trip → OK
  ✅ SignInit(CKM_HASH_ML_DSA generic, hash=SHA256, previously untested) → OK
  ✅ Sign(CKM_HASH_ML_DSA generic) → OK
  ✅ VerifyInit(CKM_HASH_ML_DSA generic, hash=SHA256) → OK
  ✅ Verify(CKM_HASH_ML_DSA generic) round trip → OK
  ✅ generic-form signature ALSO verifies under CKM_HASH_ML_DSA_SHA256 → OK
  ✅ SignInit(CKM_HASH_SLH_DSA generic, hash=SHA256, previously untested) → OK
  ✅ Sign(CKM_HASH_SLH_DSA generic) → OK
  ✅ VerifyInit(CKM_HASH_SLH_DSA generic, hash=SHA256) → OK
  ✅ Verify(CKM_HASH_SLH_DSA generic) round trip → OK
  ✅ generic-form signature ALSO verifies under CKM_HASH_SLH_DSA_SHA256 → OK

── G2b — SHA-3 digest/HMAC/HMAC-general + KDF-tail round trips (§6.29x/§6.45) ──
  ✅ CKM_SHA384: DigestInit (previously untested) → OK
  ✅ CKM_SHA384: Digest → OK
  ✅ CKM_SHA384: byte-equals independent Node crypto digest
  ✅ CKM_SHA512: DigestInit (previously untested) → OK
  ✅ CKM_SHA512: Digest → OK
  ✅ CKM_SHA512: byte-equals independent Node crypto digest
  ✅ CKM_SHA3_256: DigestInit (previously untested) → OK
  ✅ CKM_SHA3_256: Digest → OK
  ✅ CKM_SHA3_256: byte-equals independent Node crypto digest
  ✅ CKM_SHA3_512: DigestInit (previously untested) → OK
  ✅ CKM_SHA3_512: Digest → OK
  ✅ CKM_SHA3_512: byte-equals independent Node crypto digest
  ✅ CKM_SHA3_256_HMAC: import key → OK
  ✅ CKM_SHA3_256_HMAC: SignInit (previously untested) → OK
  ✅ CKM_SHA3_256_HMAC: Sign → OK
  ✅ CKM_SHA3_256_HMAC: byte-equals independent Node HMAC
  ✅ CKM_SHA3_256_HMAC: VerifyInit (previously untested) → OK
  ✅ CKM_SHA3_256_HMAC: Verify round trip → OK
  ✅ CKM_SHA3_512_HMAC: import key → OK
  ✅ CKM_SHA3_512_HMAC: SignInit (previously untested) → OK
  ✅ CKM_SHA3_512_HMAC: Sign → OK
  ✅ CKM_SHA3_512_HMAC: byte-equals independent Node HMAC
  ✅ CKM_SHA3_512_HMAC: VerifyInit (previously untested) → OK
  ✅ CKM_SHA3_512_HMAC: Verify round trip → OK
  ✅ CKM_SHA384_HMAC_GENERAL: import key → OK
  ✅ CKM_SHA384_HMAC_GENERAL: SignInit(len=20, previously untested) → OK
  ✅ CKM_SHA384_HMAC_GENERAL: mac length = 20
  ✅ CKM_SHA384_HMAC_GENERAL: Sign → OK
  ✅ CKM_SHA384_HMAC_GENERAL: truncated MAC byte-equals first 20 bytes of independent Node HMAC
  ✅ CKM_SHA384_HMAC_GENERAL: VerifyInit(len=20, previously untested) → OK
  ✅ CKM_SHA384_HMAC_GENERAL: Verify round trip → OK
  ✅ CKM_SHA512_HMAC_GENERAL: import key → OK
  ✅ CKM_SHA512_HMAC_GENERAL: SignInit(len=20, previously untested) → OK
  ✅ CKM_SHA512_HMAC_GENERAL: mac length = 20
  ✅ CKM_SHA512_HMAC_GENERAL: Sign → OK
  ✅ CKM_SHA512_HMAC_GENERAL: truncated MAC byte-equals first 20 bytes of independent Node HMAC
  ✅ CKM_SHA512_HMAC_GENERAL: VerifyInit(len=20, previously untested) → OK
  ✅ CKM_SHA512_HMAC_GENERAL: Verify round trip → OK
  ✅ CKM_SHA3_256_HMAC_GENERAL: import key → OK
  ✅ CKM_SHA3_256_HMAC_GENERAL: SignInit(len=20, previously untested) → OK
  ✅ CKM_SHA3_256_HMAC_GENERAL: mac length = 20
  ✅ CKM_SHA3_256_HMAC_GENERAL: Sign → OK
  ✅ CKM_SHA3_256_HMAC_GENERAL: truncated MAC byte-equals first 20 bytes of independent Node HMAC
  ✅ CKM_SHA3_256_HMAC_GENERAL: VerifyInit(len=20, previously untested) → OK
  ✅ CKM_SHA3_256_HMAC_GENERAL: Verify round trip → OK
  ✅ CKM_SHA3_512_HMAC_GENERAL: import key → OK
  ✅ CKM_SHA3_512_HMAC_GENERAL: SignInit(len=20, previously untested) → OK
  ✅ CKM_SHA3_512_HMAC_GENERAL: mac length = 20
  ✅ CKM_SHA3_512_HMAC_GENERAL: Sign → OK
  ✅ CKM_SHA3_512_HMAC_GENERAL: truncated MAC byte-equals first 20 bytes of independent Node HMAC
  ✅ CKM_SHA3_512_HMAC_GENERAL: VerifyInit(len=20, previously untested) → OK
  ✅ CKM_SHA3_512_HMAC_GENERAL: Verify round trip → OK
  ✅ CKM_SHA256_KEY_DERIVATION: import base key → OK
  ✅ CKM_SHA256_KEY_DERIVATION: DeriveKey (previously untested) → OK
  ✅ CKM_SHA256_KEY_DERIVATION: GetAttributeValue(derived) → OK
  ✅ CKM_SHA256_KEY_DERIVATION: derived value byte-equals independent Node digest of the base key
  ✅ CKM_SHA384_KEY_DERIVATION: import base key → OK
  ✅ CKM_SHA384_KEY_DERIVATION: DeriveKey (previously untested) → OK
  ✅ CKM_SHA384_KEY_DERIVATION: GetAttributeValue(derived) → OK
  ✅ CKM_SHA384_KEY_DERIVATION: derived value byte-equals independent Node digest of the base key
  ✅ CKM_SHA512_KEY_DERIVATION: import base key → OK
  ✅ CKM_SHA512_KEY_DERIVATION: DeriveKey (previously untested) → OK
  ✅ CKM_SHA512_KEY_DERIVATION: GetAttributeValue(derived) → OK
  ✅ CKM_SHA512_KEY_DERIVATION: derived value byte-equals independent Node digest of the base key
  ✅ CKM_SHA3_256_KEY_DERIVATION: import base key → OK
  ✅ CKM_SHA3_256_KEY_DERIVATION: DeriveKey (previously untested) → OK
  ✅ CKM_SHA3_256_KEY_DERIVATION: GetAttributeValue(derived) → OK
  ✅ CKM_SHA3_256_KEY_DERIVATION: derived value byte-equals independent Node digest of the base key
  ✅ CKM_SHA3_384_KEY_DERIVATION: import base key → OK
  ✅ CKM_SHA3_384_KEY_DERIVATION: DeriveKey (previously untested) → OK
  ✅ CKM_SHA3_384_KEY_DERIVATION: GetAttributeValue(derived) → OK
  ✅ CKM_SHA3_384_KEY_DERIVATION: derived value byte-equals independent Node digest of the base key
  ✅ CKM_SHA3_512_KEY_DERIVATION: import base key → OK
  ✅ CKM_SHA3_512_KEY_DERIVATION: DeriveKey (previously untested) → OK
  ✅ CKM_SHA3_512_KEY_DERIVATION: GetAttributeValue(derived) → OK
  ✅ CKM_SHA3_512_KEY_DERIVATION: derived value byte-equals independent Node digest of the base key
  ✅ CKM_HKDF_DERIVE: import IKM key → OK
  ✅ CKM_HKDF_DERIVE: DeriveKey (previously untested) → OK
  ✅ CKM_HKDF_DERIVE: GetAttributeValue(derived) → OK
  ✅ CKM_HKDF_DERIVE: byte-equals independent Node crypto.hkdfSync

── G3 — RSA-OAEP / RSA-PSS / hash-then-RSA family (§6.4) ──
  ✅ fixture: RSA-2048 keypair (ENCRYPT/DECRYPT/SIGN/VERIFY) → OK
  ✅ fixture: read RSA CKA_MODULUS/CKA_PUBLIC_EXPONENT → OK
  ✅ EncryptInit(CKM_RSA_PKCS_OAEP, previously untested) → OK
  ✅ Encrypt(CKM_RSA_PKCS_OAEP) → OK
  ✅ DecryptInit(CKM_RSA_PKCS_OAEP) → OK
  ✅ Decrypt(CKM_RSA_PKCS_OAEP) → OK
  ✅ RSA-OAEP encrypt(pub) → decrypt(priv) recovers the ORIGINAL plaintext (real SEAM)
  ✅ DecryptInit (tamper control) → OK
  ✅ tampered OAEP ciphertext never decrypts to the original plaintext
  ✅ CKM_RSA_PKCS: DecryptInit (R-2 fix) → OK
  ✅ CKM_RSA_PKCS: Decrypt(engine) of Node-produced ciphertext → OK (dispatch reached, not MECHANISM_INVALID)
  ✅ CKM_RSA_PKCS: independent oracle (Node crypto.publicEncrypt) → engine C_Decrypt recovers the ORIGINAL plaintext EXACTLY
  ✅ CKM_RSA_PKCS: EncryptInit (R-2 fix) → OK
  ✅ CKM_RSA_PKCS: Encrypt(engine) → OK (dispatch reached, not MECHANISM_INVALID)
  ✅ CKM_RSA_PKCS: DecryptInit (engine round trip) → OK
  ✅ CKM_RSA_PKCS: Decrypt(engine) → OK
  ✅ CKM_RSA_PKCS: encrypt(pub) → decrypt(priv) recovers the ORIGINAL plaintext (real SEAM)
  ✅ CKM_RSA_PKCS: DecryptInit (tamper control) → OK
  ✅ CKM_RSA_PKCS: tampered ciphertext never decrypts to the original plaintext
  ✅ bare CKM_RSA_PKCS_PSS (SHA-256): SignInit (R-1 fix) → OK
  ✅ bare CKM_RSA_PKCS_PSS (SHA-256): Sign(digest) → OK (dispatch reached, not MECHANISM_INVALID)
  ✅ bare CKM_RSA_PKCS_PSS (SHA-256): VerifyInit → OK
  ✅ bare CKM_RSA_PKCS_PSS (SHA-256): Verify round trip → OK (real SEAM)
  ✅ bare CKM_RSA_PKCS_PSS (SHA-256): independent oracle (Node crypto.verify, RSA-PSS) confirms the SAME signature is valid
  ✅ bare CKM_RSA_PKCS_PSS (SHA-256): VerifyInit (tamper control) → OK
  ✅ bare CKM_RSA_PKCS_PSS (SHA-256): Verify with tampered signature → SIGNATURE_INVALID
  ✅ bare CKM_RSA_PKCS_PSS (SHA-256): independent oracle also rejects the tampered signature
  ✅ bare CKM_RSA_PKCS_PSS (SHA-384): SignInit (R-1 fix) → OK
  ✅ bare CKM_RSA_PKCS_PSS (SHA-384): Sign(digest) → OK (dispatch reached, not MECHANISM_INVALID)
  ✅ bare CKM_RSA_PKCS_PSS (SHA-384): VerifyInit → OK
  ✅ bare CKM_RSA_PKCS_PSS (SHA-384): Verify round trip → OK (real SEAM)
  ✅ bare CKM_RSA_PKCS_PSS (SHA-384): independent oracle (Node crypto.verify, RSA-PSS) confirms the SAME signature is valid
  ✅ bare CKM_RSA_PKCS_PSS (SHA-384): VerifyInit (tamper control) → OK
  ✅ bare CKM_RSA_PKCS_PSS (SHA-384): Verify with tampered signature → SIGNATURE_INVALID
  ✅ bare CKM_RSA_PKCS_PSS (SHA-384): independent oracle also rejects the tampered signature
  ✅ bare CKM_RSA_PKCS_PSS (SHA-512): SignInit (R-1 fix) → OK
  ✅ bare CKM_RSA_PKCS_PSS (SHA-512): Sign(digest) → OK (dispatch reached, not MECHANISM_INVALID)
  ✅ bare CKM_RSA_PKCS_PSS (SHA-512): VerifyInit → OK
  ✅ bare CKM_RSA_PKCS_PSS (SHA-512): Verify round trip → OK (real SEAM)
  ✅ bare CKM_RSA_PKCS_PSS (SHA-512): independent oracle (Node crypto.verify, RSA-PSS) confirms the SAME signature is valid
  ✅ bare CKM_RSA_PKCS_PSS (SHA-512): VerifyInit (tamper control) → OK
  ✅ bare CKM_RSA_PKCS_PSS (SHA-512): Verify with tampered signature → SIGNATURE_INVALID
  ✅ bare CKM_RSA_PKCS_PSS (SHA-512): independent oracle also rejects the tampered signature
  ✅ CKM_SHA256_RSA_PKCS: SignInit (previously untested) → OK
  ✅ CKM_SHA256_RSA_PKCS: Sign → OK
  ✅ CKM_SHA256_RSA_PKCS: VerifyInit (previously untested) → OK
  ✅ CKM_SHA256_RSA_PKCS: Verify round trip → OK
  ✅ CKM_SHA256_RSA_PKCS: VerifyInit (tamper control) → OK
  ✅ CKM_SHA256_RSA_PKCS: Verify with tampered signature → SIGNATURE_INVALID
  ✅ CKM_SHA384_RSA_PKCS: SignInit (previously untested) → OK
  ✅ CKM_SHA384_RSA_PKCS: Sign → OK
  ✅ CKM_SHA384_RSA_PKCS: VerifyInit (previously untested) → OK
  ✅ CKM_SHA384_RSA_PKCS: Verify round trip → OK
  ✅ CKM_SHA384_RSA_PKCS: VerifyInit (tamper control) → OK
  ✅ CKM_SHA384_RSA_PKCS: Verify with tampered signature → SIGNATURE_INVALID
  ✅ CKM_SHA512_RSA_PKCS: SignInit (previously untested) → OK
  ✅ CKM_SHA512_RSA_PKCS: Sign → OK
  ✅ CKM_SHA512_RSA_PKCS: VerifyInit (previously untested) → OK
  ✅ CKM_SHA512_RSA_PKCS: Verify round trip → OK
  ✅ CKM_SHA512_RSA_PKCS: VerifyInit (tamper control) → OK
  ✅ CKM_SHA512_RSA_PKCS: Verify with tampered signature → SIGNATURE_INVALID
  ✅ CKM_SHA3_384_RSA_PKCS: SignInit (previously untested) → OK
  ✅ CKM_SHA3_384_RSA_PKCS: Sign → OK
  ✅ CKM_SHA3_384_RSA_PKCS: VerifyInit (previously untested) → OK
  ✅ CKM_SHA3_384_RSA_PKCS: Verify round trip → OK
  ✅ CKM_SHA3_384_RSA_PKCS: VerifyInit (tamper control) → OK
  ✅ CKM_SHA3_384_RSA_PKCS: Verify with tampered signature → SIGNATURE_INVALID
  ✅ CKM_SHA256_RSA_PKCS_PSS: SignInit (previously untested) → OK
  ✅ CKM_SHA256_RSA_PKCS_PSS: Sign → OK
  ✅ CKM_SHA256_RSA_PKCS_PSS: VerifyInit (previously untested) → OK
  ✅ CKM_SHA256_RSA_PKCS_PSS: Verify round trip → OK
  ✅ CKM_SHA256_RSA_PKCS_PSS: VerifyInit (tamper control) → OK
  ✅ CKM_SHA256_RSA_PKCS_PSS: Verify with tampered signature → SIGNATURE_INVALID
  ✅ CKM_SHA384_RSA_PKCS_PSS: SignInit (previously untested) → OK
  ✅ CKM_SHA384_RSA_PKCS_PSS: Sign → OK
  ✅ CKM_SHA384_RSA_PKCS_PSS: VerifyInit (previously untested) → OK
  ✅ CKM_SHA384_RSA_PKCS_PSS: Verify round trip → OK
  ✅ CKM_SHA384_RSA_PKCS_PSS: VerifyInit (tamper control) → OK
  ✅ CKM_SHA384_RSA_PKCS_PSS: Verify with tampered signature → SIGNATURE_INVALID
  ✅ CKM_SHA512_RSA_PKCS_PSS: SignInit (previously untested) → OK
  ✅ CKM_SHA512_RSA_PKCS_PSS: Sign → OK
  ✅ CKM_SHA512_RSA_PKCS_PSS: VerifyInit (previously untested) → OK
  ✅ CKM_SHA512_RSA_PKCS_PSS: Verify round trip → OK
  ✅ CKM_SHA512_RSA_PKCS_PSS: VerifyInit (tamper control) → OK
  ✅ CKM_SHA512_RSA_PKCS_PSS: Verify with tampered signature → SIGNATURE_INVALID
  ✅ CKM_SHA3_384_RSA_PKCS_PSS: SignInit (previously untested) → OK
  ✅ CKM_SHA3_384_RSA_PKCS_PSS: Sign → OK
  ✅ CKM_SHA3_384_RSA_PKCS_PSS: VerifyInit (previously untested) → OK
  ✅ CKM_SHA3_384_RSA_PKCS_PSS: Verify round trip → OK
  ✅ CKM_SHA3_384_RSA_PKCS_PSS: VerifyInit (tamper control) → OK
  ✅ CKM_SHA3_384_RSA_PKCS_PSS: Verify with tampered signature → SIGNATURE_INVALID

── G4 — ECDSA / EC-derive / EdDSA / Montgomery family (§6.3/§6.7) ──
  ✅ CKM_EC_KEY_PAIR_GEN (P-256, previously untested) → OK
  ✅ SignInit(CKM_ECDSA, previously untested) → OK
  ✅ Sign(CKM_ECDSA) → OK
  ✅ VerifyInit(CKM_ECDSA, previously untested) → OK
  ✅ Verify(CKM_ECDSA) round trip → OK
  ✅ VerifyInit(CKM_ECDSA) (tamper control) → OK
  ✅ Verify(CKM_ECDSA) tampered digest → SIGNATURE_INVALID
  ✅ CKM_ECDSA_SHA256: SignInit (previously untested) → OK
  ✅ CKM_ECDSA_SHA256: Sign → OK
  ✅ CKM_ECDSA_SHA256: VerifyInit (previously untested) → OK
  ✅ CKM_ECDSA_SHA256: Verify round trip → OK
  ✅ CKM_ECDSA_SHA384: SignInit (previously untested) → OK
  ✅ CKM_ECDSA_SHA384: Sign → OK
  ✅ CKM_ECDSA_SHA384: VerifyInit (previously untested) → OK
  ✅ CKM_ECDSA_SHA384: Verify round trip → OK
  ✅ CKM_ECDSA_SHA512: SignInit (previously untested) → OK
  ✅ CKM_ECDSA_SHA512: Sign → OK
  ✅ CKM_ECDSA_SHA512: VerifyInit (previously untested) → OK
  ✅ CKM_ECDSA_SHA512: Verify round trip → OK
  ✅ CKM_ECDSA_SHA3_224: SignInit (previously untested) → OK
  ✅ CKM_ECDSA_SHA3_224: Sign → OK
  ✅ CKM_ECDSA_SHA3_224: VerifyInit (previously untested) → OK
  ✅ CKM_ECDSA_SHA3_224: Verify round trip → OK
  ✅ CKM_ECDSA_SHA3_256: SignInit (previously untested) → OK
  ✅ CKM_ECDSA_SHA3_256: Sign → OK
  ✅ CKM_ECDSA_SHA3_256: VerifyInit (previously untested) → OK
  ✅ CKM_ECDSA_SHA3_256: Verify round trip → OK
  ✅ CKM_ECDSA_SHA3_384: SignInit (previously untested) → OK
  ✅ CKM_ECDSA_SHA3_384: Sign → OK
  ✅ CKM_ECDSA_SHA3_384: VerifyInit (previously untested) → OK
  ✅ CKM_ECDSA_SHA3_384: Verify round trip → OK
  ✅ CKM_ECDSA_SHA3_512: SignInit (previously untested) → OK
  ✅ CKM_ECDSA_SHA3_512: Sign → OK
  ✅ CKM_ECDSA_SHA3_512: VerifyInit (previously untested) → OK
  ✅ CKM_ECDSA_SHA3_512: Verify round trip → OK
  ✅ CKM_ECDH1_DERIVE: fixture Alice keypair → OK
  ✅ CKM_ECDH1_DERIVE: fixture Bob keypair → OK
  ✅ CKM_ECDH1_DERIVE: read Alice CKA_EC_POINT → OK
  ✅ CKM_ECDH1_DERIVE: read Bob CKA_EC_POINT → OK
  ✅ CKM_ECDH1_DERIVE: Alice DeriveKey (previously untested) → OK
  ✅ CKM_ECDH1_DERIVE: Bob DeriveKey → OK
  ✅ CKM_ECDH1_DERIVE: both sides agree on the SAME shared secret (real SEAM)
  ✅ CKM_ECDH1_COFACTOR_DERIVE: fixture Alice keypair → OK
  ✅ CKM_ECDH1_COFACTOR_DERIVE: fixture Bob keypair → OK
  ✅ CKM_ECDH1_COFACTOR_DERIVE: read Alice CKA_EC_POINT → OK
  ✅ CKM_ECDH1_COFACTOR_DERIVE: read Bob CKA_EC_POINT → OK
  ✅ CKM_ECDH1_COFACTOR_DERIVE: Alice DeriveKey (previously untested) → OK
  ✅ CKM_ECDH1_COFACTOR_DERIVE: Bob DeriveKey → OK
  ✅ CKM_ECDH1_COFACTOR_DERIVE: both sides agree on the SAME shared secret (real SEAM)
  ✅ CKM_EC_EDWARDS_KEY_PAIR_GEN (Ed25519, previously untested) → OK
  ✅ SignInit(CKM_EDDSA, pure, previously untested) → OK
  ✅ Sign(CKM_EDDSA, pure) → OK
  ✅ VerifyInit(CKM_EDDSA, pure, previously untested) → OK
  ✅ Verify(CKM_EDDSA, pure) round trip → OK
  ✅ VerifyInit(CKM_EDDSA) (tamper control) → OK
  ✅ Verify(CKM_EDDSA) tampered signature → SIGNATURE_INVALID
  ✅ SignInit(CKM_EDDSA, phFlag=true → internally CKM_EDDSA_PH, previously untested) → OK
  ✅ Sign(CKM_EDDSA_PH via phFlag) → OK
  ✅ VerifyInit(CKM_EDDSA, phFlag=true) → OK
  ✅ Verify(CKM_EDDSA_PH via phFlag) round trip → OK
  ✅ CKM_X25519: fixture Alice X25519 keypair (previously untested keygen) → OK
  ✅ CKM_X25519: fixture Bob X25519 keypair → OK
  ✅ CKM_X25519: read Alice CKA_EC_POINT (32 B, bare little-endian) → OK
  ✅ CKM_X25519: read Bob CKA_EC_POINT → OK
  ✅ CKM_X25519: Alice DeriveKey (previously untested) → OK
  ✅ CKM_X25519: Bob DeriveKey → OK
  ✅ CKM_X25519: both sides agree on the SAME shared secret (real SEAM)
  ✅ CKM_EC_MONTGOMERY_KEY_DERIVE: fixture Alice X25519 keypair (previously untested keygen) → OK
  ✅ CKM_EC_MONTGOMERY_KEY_DERIVE: fixture Bob X25519 keypair → OK
  ✅ CKM_EC_MONTGOMERY_KEY_DERIVE: read Alice CKA_EC_POINT (32 B, bare little-endian) → OK
  ✅ CKM_EC_MONTGOMERY_KEY_DERIVE: read Bob CKA_EC_POINT → OK
  ✅ CKM_EC_MONTGOMERY_KEY_DERIVE: Alice DeriveKey (previously untested) → OK
  ✅ CKM_EC_MONTGOMERY_KEY_DERIVE: Bob DeriveKey → OK
  ✅ CKM_EC_MONTGOMERY_KEY_DERIVE: both sides agree on the SAME shared secret (real SEAM)
  ✅ CKM_X448: fixture Alice X448 keypair (previously untested keygen) → OK
  ✅ CKM_X448: fixture Bob X448 keypair → OK
  ✅ CKM_X448: read Alice CKA_EC_POINT (56 B) → OK
  ✅ CKM_X448: read Bob CKA_EC_POINT → OK
  ✅ CKM_X448: Alice DeriveKey (previously untested) → OK
  ✅ CKM_X448: Bob DeriveKey → OK
  ✅ CKM_X448: both sides agree on the SAME shared secret (real SEAM)

── G5 — AES-ECB / AES-KeyWrap variants / ChaCha20 family (§6.11/§6.20/§6.21/§6.31) ──
  ✅ fixture: AES key → OK
  ✅ EncryptInit(CKM_AES_ECB, previously untested) → OK
  ✅ Encrypt(CKM_AES_ECB) → OK
  ✅ ECB ciphertext length = plaintext length (no padding, no IV)
  ✅ ECB: identical plaintext blocks → identical ciphertext blocks (real mode property)
  ✅ DecryptInit(CKM_AES_ECB) → OK
  ✅ Decrypt(CKM_AES_ECB) round trip → OK
  ✅ ECB encrypt → decrypt recovers the ORIGINAL plaintext (real SEAM)
  ✅ CKM_AES_KEY_WRAP: fixture KEK → OK
  ✅ CKM_AES_KEY_WRAP: fixture target key → OK
  ✅ CKM_AES_KEY_WRAP: read target CKA_VALUE (pre-wrap) → OK
  ✅ CKM_AES_KEY_WRAP: WrapKey (previously untested) → OK
  ✅ CKM_AES_KEY_WRAP: UnwrapKey (previously untested) → OK
  ✅ CKM_AES_KEY_WRAP: read unwrapped CKA_VALUE → OK
  ✅ CKM_AES_KEY_WRAP: wrap → unwrap recovers the ORIGINAL key bytes (real SEAM)
  ✅ CKM_AES_KEY_WRAP_PAD: fixture KEK → OK
  ✅ CKM_AES_KEY_WRAP_PAD: fixture target key → OK
  ✅ CKM_AES_KEY_WRAP_PAD: read target CKA_VALUE (pre-wrap) → OK
  ✅ CKM_AES_KEY_WRAP_PAD: WrapKey (previously untested) → OK
  ✅ CKM_AES_KEY_WRAP_PAD: UnwrapKey (previously untested) → OK
  ✅ CKM_AES_KEY_WRAP_PAD: read unwrapped CKA_VALUE → OK
  ✅ CKM_AES_KEY_WRAP_PAD: wrap → unwrap recovers the ORIGINAL key bytes (real SEAM)
  ✅ CKM_AES_KEY_WRAP_KWP: fixture KEK → OK
  ✅ CKM_AES_KEY_WRAP_KWP: fixture target key → OK
  ✅ CKM_AES_KEY_WRAP_KWP: read target CKA_VALUE (pre-wrap) → OK
  ✅ CKM_AES_KEY_WRAP_KWP: WrapKey (previously untested) → OK
  ✅ CKM_AES_KEY_WRAP_KWP: UnwrapKey (previously untested) → OK
  ✅ CKM_AES_KEY_WRAP_KWP: read unwrapped CKA_VALUE → OK
  ✅ CKM_AES_KEY_WRAP_KWP: wrap → unwrap recovers the ORIGINAL key bytes (real SEAM)
  ✅ CKM_CHACHA20_KEY_GEN (previously untested) → OK
  ✅ EncryptInit(CKM_CHACHA20, previously untested) → OK
  ✅ Encrypt(CKM_CHACHA20) → OK
  ✅ CHACHA20: ciphertext differs from plaintext
  ✅ DecryptInit(CKM_CHACHA20) → OK
  ✅ Decrypt(CKM_CHACHA20) round trip → OK
  ✅ CHACHA20 encrypt → decrypt recovers the ORIGINAL plaintext (real SEAM)
  ✅ EncryptInit(CKM_CHACHA20_POLY1305, previously untested) → OK
  ✅ CHACHA20_POLY1305 ciphertext = plaintext + 16-byte tag
  ✅ Encrypt(CKM_CHACHA20_POLY1305) → OK
  ✅ DecryptInit(CKM_CHACHA20_POLY1305) → OK
  ✅ Decrypt(CKM_CHACHA20_POLY1305) round trip → OK
  ✅ CHACHA20_POLY1305 encrypt → decrypt recovers the ORIGINAL plaintext (real SEAM)
  ✅ DecryptInit (tamper control) → OK
  ✅ Decrypt with tampered Poly1305 tag → ENCRYPTED_DATA_INVALID

── G6 — RIPEMD160 / bare SHA384_HMAC+SHA512_HMAC / GENERIC_SECRET / CONCATENATE / PBKDF2 ──
  ✅ DigestInit(CKM_RIPEMD160, previously untested) → OK
  ✅ Digest(CKM_RIPEMD160) → OK
  ✅ CKM_RIPEMD160: byte-equals independent Node crypto digest
  ✅ CKM_RIPEMD160_HMAC: import key → OK
  ✅ CKM_RIPEMD160_HMAC: SignInit (previously untested) → OK
  ✅ CKM_RIPEMD160_HMAC: Sign → OK
  ✅ CKM_RIPEMD160_HMAC: byte-equals independent Node HMAC
  ✅ CKM_RIPEMD160_HMAC: VerifyInit (previously untested) → OK
  ✅ CKM_RIPEMD160_HMAC: Verify round trip → OK
  ✅ CKM_SHA384_HMAC: import key → OK
  ✅ CKM_SHA384_HMAC: SignInit (previously untested) → OK
  ✅ CKM_SHA384_HMAC: Sign → OK
  ✅ CKM_SHA384_HMAC: byte-equals independent Node HMAC
  ✅ CKM_SHA384_HMAC: VerifyInit (previously untested) → OK
  ✅ CKM_SHA384_HMAC: Verify round trip → OK
  ✅ CKM_SHA512_HMAC: import key → OK
  ✅ CKM_SHA512_HMAC: SignInit (previously untested) → OK
  ✅ CKM_SHA512_HMAC: Sign → OK
  ✅ CKM_SHA512_HMAC: byte-equals independent Node HMAC
  ✅ CKM_SHA512_HMAC: VerifyInit (previously untested) → OK
  ✅ CKM_SHA512_HMAC: Verify round trip → OK
  ✅ C_GenerateKey(CKM_GENERIC_SECRET_KEY_GEN, previously untested) → OK
  ✅ generated key CKA_VALUE readable (32 B requested) → OK
  ✅ generated key length = 32
  ✅ SignInit(SHA256_HMAC) with generated key → OK
  ✅ Sign with generated key → OK
  ✅ VerifyInit with generated key → OK
  ✅ generated key: real HMAC round trip verifies → OK
  ✅ CONCATENATE_BASE_AND_KEY: fixture base key → OK
  ✅ CONCATENATE_BASE_AND_KEY: fixture second key → OK
  ✅ DeriveKey(CKM_CONCATENATE_BASE_AND_KEY, previously untested) → OK
  ✅ read derived CKA_VALUE → OK
  ✅ CONCATENATE_BASE_AND_KEY: derived value = base‖second (self-computed reference)
  ✅ DeriveKey(CKM_CONCATENATE_BASE_AND_DATA, previously untested) → OK
  ✅ read derived CKA_VALUE → OK
  ✅ CONCATENATE_BASE_AND_DATA: derived value = base‖data (self-computed reference)
  ✅ DeriveKey(CKM_PKCS5_PBKD2, previously untested) → OK
  ✅ read derived CKA_VALUE → OK
  ✅ CKM_PKCS5_PBKD2: byte-equals independent Node crypto.pbkdf2Sync

── G7 — stateful hash-based signatures: HSS (§6.14) ──
  ✅ CKM_HSS_KEY_PAIR_GEN (default param set, previously untested) → OK
  ✅ SignInit(CKM_HSS, previously untested) → OK
  ✅ Sign(CKM_HSS) → OK
  ✅ VerifyInit(CKM_HSS, previously untested) → OK
  ✅ Verify(CKM_HSS) round trip → OK
  ✅ VerifyInit(CKM_HSS) (tamper control) → OK
  ✅ Verify(CKM_HSS) tampered message → SIGNATURE_INVALID

── G8 — vendor-defined mechanisms: FrodoKEM / Keccak-256 / KMAC / BIP32 (≥ CKM_VENDOR_DEFINED) ──
  ✅ CKM_PQCTODAY_FRODOKEM_KEY_PAIR_GEN (640-AES, previously untested) → OK
  ✅ C_EncapsulateKey(CKM_PQCTODAY_FRODOKEM_ENCAPSULATE, previously untested) → OK
  ✅ read encapsulator shared-secret CKA_VALUE → OK
  ✅ C_DecapsulateKey(CKM_PQCTODAY_FRODOKEM_ENCAPSULATE, previously untested) → OK
  ✅ read decapsulator shared-secret CKA_VALUE → OK
  ✅ FrodoKEM: encapsulate → decapsulate agree on the SAME shared secret (real SEAM)
  ✅ DigestInit(CKM_KECCAK_256, previously untested) → OK
  ✅ Digest(CKM_KECCAK_256, empty input) → OK
  ✅ CKM_KECCAK_256: Keccak-256("") byte-equals the well-known canonical KAT
  ✅ KMAC: import key → OK
  ✅ CKM_KMAC_128: SignInit (previously untested) → OK
  ✅ CKM_KMAC_128: Sign → OK
  ✅ CKM_KMAC_128: byte-equals independent pycryptodome KAT
  ✅ CKM_KMAC_128: VerifyInit (previously untested) → OK
  ✅ CKM_KMAC_128: Verify round trip → OK
  ✅ CKM_KMAC_256: SignInit (previously untested) → OK
  ✅ CKM_KMAC_256: Sign → OK
  ✅ CKM_KMAC_256: byte-equals independent pycryptodome KAT
  ✅ CKM_KMAC_256: VerifyInit (previously untested) → OK
  ✅ CKM_KMAC_256: Verify round trip → OK
  ✅ BIP32: import seed key → OK
  ✅ DeriveKey(CKM_BIP32_MASTER_DERIVE, previously untested) → OK
  ✅ read master CKA_VALUE → OK
  ✅ read master CKA_BIP32_CHAIN_CODE → OK
  ✅ BIP32 master derive: priv key byte-equals independent HMAC-SHA512("Bitcoin seed", seed)[0:32]
  ✅ BIP32 master derive: chain code byte-equals independent HMAC-SHA512(...)[32:64]
  ✅ DeriveKey(CKM_BIP32_CHILD_DERIVE, hardened index 0, previously untested) → OK
  ✅ read child CKA_VALUE → OK
  ✅ BIP32 child derive (hardened): byte-equals independent HMAC-SHA512 + mod-n scalar addition

── G9 — advertise-vs-dispatch invariant: every advertised mechanism has a real dispatch path (new) ──
  ✅ fixture: live advertised mechanism count → 117
  ✅ 0x0 GenerateKeyPair: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x9 EncryptInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x9 DecryptInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x9 WrapKey: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x63
  ✅ 0x9 UnwrapKey: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x63
  ✅ 0x40 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x40 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x41 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x41 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x42 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x42 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x43 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x43 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x44 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x44 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x45 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x45 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x1 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x1 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x1 EncryptInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x1 DecryptInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x1 WrapKey: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x63
  ✅ 0x1 UnwrapKey: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x63
  ✅ 0xd SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x71
  ✅ 0xd VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x71
  ✅ 0x61 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x61 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x64 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x64 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0xf GenerateKeyPair: dispatch reached (not CKR_MECHANISM_INVALID) → got 0xd0
  ✅ 0x80000001 GenerateKeyPair: dispatch reached (not CKR_MECHANISM_INVALID) → got 0xd0
  ✅ 0x80000003 GenerateKeyPair: dispatch reached (not CKR_MECHANISM_INVALID) → got 0xd0
  ✅ 0x1c GenerateKeyPair: dispatch reached (not CKR_MECHANISM_INVALID) → got 0xd0
  ✅ 0x1d SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x1d VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x1f SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x71
  ✅ 0x1f VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x71
  ✅ 0x23 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x23 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x24 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x24 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x25 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x25 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x26 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x26 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x27 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x27 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x28 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x28 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x29 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x29 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x2a SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x2a VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x2b SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x2b VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x2c SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x2c VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x2d GenerateKeyPair: dispatch reached (not CKR_MECHANISM_INVALID) → got 0xd0
  ✅ 0x2e SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x2e VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x34 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x71
  ✅ 0x34 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x71
  ✅ 0x36 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x36 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x37 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x37 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x38 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x38 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x39 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x39 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x3a SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x3a VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x3b SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x3b VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x3c SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x3c VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x3d SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x3d VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x3e SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x3e VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x3f SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x3f VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x250 DigestInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x260 DigestInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x270 DigestInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x2b0 DigestInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x2d0 DigestInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x240 DigestInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x251 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x251 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x261 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x261 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x271 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x271 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x2b1 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x2b1 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x2d1 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x2d1 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x241 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x241 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x252 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x71
  ✅ 0x252 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x71
  ✅ 0x262 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x71
  ✅ 0x262 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x71
  ✅ 0x272 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x71
  ✅ 0x272 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x71
  ✅ 0x2b2 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x71
  ✅ 0x2b2 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x71
  ✅ 0x2d2 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x71
  ✅ 0x2d2 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x71
  ✅ 0x80000100 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x80000100 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x80000101 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x80000101 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x350 GenerateKey: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x1040 GenerateKeyPair: dispatch reached (not CKR_MECHANISM_INVALID) → got 0xd0
  ✅ 0x1041 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x1041 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x1044 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x1044 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x1045 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x1045 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x1046 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x1046 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x1047 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x1047 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x1048 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x1048 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x1049 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x1049 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x104a SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x104a VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x1050 DeriveKey: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x7
  ✅ 0x1051 DeriveKey: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x7
  ✅ 0x1055 GenerateKeyPair: dispatch reached (not CKR_MECHANISM_INVALID) → got 0xd0
  ✅ 0x1056 GenerateKeyPair: dispatch reached (not CKR_MECHANISM_INVALID) → got 0xd0
  ✅ 0x80000011 DeriveKey: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x7
  ✅ 0x80001058 DeriveKey: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x7
  ✅ 0x80001059 DeriveKey: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x7
  ✅ 0x1057 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x1057 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x80001057 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x80001057 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x1080 GenerateKey: dispatch reached (not CKR_MECHANISM_INVALID) → got 0xd0
  ✅ 0x1081 EncryptInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x1081 DecryptInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x1082 EncryptInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x7
  ✅ 0x1082 DecryptInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x7
  ✅ 0x1082 WrapKey: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x71
  ✅ 0x1082 UnwrapKey: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x71
  ✅ 0x1085 EncryptInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x7
  ✅ 0x1085 DecryptInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x7
  ✅ 0x1085 WrapKey: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x71
  ✅ 0x1085 UnwrapKey: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x71
  ✅ 0x1086 EncryptInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x71
  ✅ 0x1086 DecryptInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x71
  ✅ 0x1087 EncryptInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x7
  ✅ 0x1087 DecryptInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x7
  ✅ 0x108e SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x71
  ✅ 0x108e VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x71
  ✅ 0x2109 WrapKey: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x2109 UnwrapKey: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x110
  ✅ 0x210b WrapKey: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x210b UnwrapKey: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x110
  ✅ 0x210a WrapKey: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x210a UnwrapKey: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x110
  ✅ 0x1226 EncryptInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x7
  ✅ 0x1226 DecryptInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x7
  ✅ 0x1225 GenerateKey: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x4021 EncryptInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x7
  ✅ 0x4021 DecryptInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x7
  ✅ 0x3b0 DeriveKey: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x7
  ✅ 0x402a DeriveKey: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x7
  ✅ 0x3ac DeriveKey: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x7
  ✅ 0x3ad DeriveKey: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x7
  ✅ 0x360 DeriveKey: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x7
  ✅ 0x362 DeriveKey: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x7
  ✅ 0x393 DeriveKey: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x394 DeriveKey: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x395 DeriveKey: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x397 DeriveKey: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x399 DeriveKey: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x39a DeriveKey: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x8000105b DeriveKey: dispatch reached (not CKR_MECHANISM_INVALID) → got 0xd1
  ✅ 0x8000105c DeriveKey: dispatch reached (not CKR_MECHANISM_INVALID) → got 0xd1
  ✅ 0x4032 GenerateKeyPair: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x4033 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x4033 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x4034 GenerateKeyPair: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x209
  ✅ 0x4036 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x4036 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x4035 GenerateKeyPair: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x209
  ✅ 0x4037 SignInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x4037 VerifyInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ 0x80000010 DigestInit: dispatch reached (not CKR_MECHANISM_INVALID) → got 0x0
  ✅ G9: probed at least one real operation for every flag-bearing advertised mechanism (195 probes total)

════════ RESULT: 980 passed, 0 failed ════════
```
