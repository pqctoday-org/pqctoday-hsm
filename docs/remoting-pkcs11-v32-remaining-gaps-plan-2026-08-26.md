# Remoting v3.2 mirror — remaining-gaps remediation plan (2026-08-26)

Detailed, execution-ready plan for everything still open after RW0–RW3 of
`docs/remoting-pkcs11-v32-full-coverage-plan-2026-08-26.md` (the master
plan; its §3 category matrix and §9 definition-of-done remain normative).
This document supersedes the master plan's §5 rows for RW4/RW5/RW6 and its
"Per-workstream execution notes" for those workstreams.

## 0. Decisions locked with the user (2026-08-26, second round)

| Decision | Choice |
|---|---|
| Engine-crate work delivery | Same branch (`feat/remoting-v32-mirror`), separate clearly-scoped commits — **but see Finding F1: probably none is needed at all** |
| Sequencing | **RW6 first**, then RW4, then RW5; ledger/report/docs land after the final workstream (now a distinct terminal phase, RW-T) |
| Ledger ratchet | Failing gate step inside the existing `remoting gRPC+REST services + three-transport parity` step in `scripts/local-gate.sh` |
| RW5 scope | Full: KEM key-object form + hybrid cells + SLH-DSA/XMSS/HSS sign cells + deterministic-seed KAT parity |

Standing decisions carried forward unchanged: full parity with N/A-local
markings; 1:1 `C_*` mirror; `ck_rv` as a response field; extend
`v32_parity.rs`; destructive ops ON in tests / OFF deployed; branch stays
local until the user says push.

## 1. Where we are (measured)

41 of the 104 `pkcs11f.h` functions are mirrored and three-transport
parity-tested (RW1: 24, RW2: 9, RW3: 8). Whole remoting workspace green:
21 core + 7 legacy + 10 v32-parity + 2 posture. Commits `ee2b97c`,
`e996d81`, `9cf0e7b` on `feat/remoting-v32-mirror` (worktree
`.worktrees/hsm-remoting-v32`), not pushed.

## 2. Two findings from this planning sweep that reshape the work

### F1 — BOTH assumed engine prerequisites have evaporated

The master plan carried two "genuine engine-crate work" items. Under the
ffi-direct calling pattern RW1 established (and RW2/RW3 confirmed), both
turn out to already exist at the ffi layer:

- **RW4 (PBKDF2/SP800-108):** `ffi::C_DeriveKey` (`ffi.rs:7766`) already
  dispatches `CKM_PKCS5_PBKD2`, `CKM_HKDF_DERIVE`,
  `CKM_SP800_108_COUNTER_KDF`, `CKM_SP800_108_FEEDBACK_KDF`,
  `CKM_ECDH1_DERIVE`(+cofactor/Montgomery), concatenate variants,
  SHA-derive, and BIP32 — all reading their parameter structs through the
  ABI-aware `ck_param` layouts (`pbkd2`, `hkdf`, `sp800_108_*` modules all
  present in `ck_param.rs`). The old sweep fact "PBKDF2/SP800-108 have no
  `native::` surface" was true but is now irrelevant: we don't go through
  `native::`.
- **RW5 (key-object KEM form):** `ffi::C_EncapsulateKey` (`ffi.rs:16980`)
  and `ffi::C_DecapsulateKey` (`ffi.rs:17038`) already exist with the full
  v3.2 signatures — mechanism + key handle + CK_ATTRIBUTE template +
  ciphertext buffer + out key handle. The "no native path — add one" note
  referred to `native::encapsulate` (bytes-only), which we simply won't
  use.

Consequence: **the entire remaining program is audit-then-call — zero
engine-crate commits expected.** The "same branch, separate commits"
decision stays as policy in case an audit still surfaces a real gap, but
nothing currently known triggers it.

### F2 — the real unpriced problem: pointer-bearing mechanism parameters

`V32Mechanism.parameter` (raw bytes) works only for parameter structs with
no embedded pointers. A remote client cannot author server-address
pointers, so raw bytes cover:

- ✅ no parameter at all (ML-DSA, ML-KEM, AES-ECB, SHA-*)
- ✅ plain byte-array params (AES-CBC IV, AES-KW optional IV)
- ✅ pointer-free structs (`CK_AES_CTR_PARAMS` — `{ulCounterBits, cb[16]}`;
  `CK_MAC_GENERAL_PARAMS` — bare ulong; bare `CK_OBJECT_HANDLE` for
  `CKM_CONCATENATE_BASE_AND_KEY`)

and do NOT cover anything the remaining workstreams need:

| Struct | Used by | Pointer fields |
|---|---|---|
| `CK_GCM_PARAMS` | RW3 follow-up (GCM one-shot/FSM) | pIv, pAAD |
| `CK_RSA_PKCS_OAEP_PARAMS` | RW3 follow-up | pSourceData |
| `CK_ECDH1_DERIVE_PARAMS` | RW4 | pSharedData, pPublicData |
| `CK_HKDF_PARAMS` | RW4 | pSalt, pInfo (+hSaltKey handle) |
| `CK_PKCS5_PBKD2_PARAMS2` | RW4 | pSaltSourceData, pPassword, ... |
| `CK_SP800_108_KDF_PARAMS` | RW4 | pDataParams → array of `CK_PRF_DATA_PARAM`, each with its own pValue pointer |
| `CK_KEY_DERIVATION_STRING_DATA` | RW4 (concat-with-data) | pData |
| `CK_GCM_MESSAGE_PARAMS` | RW6 (message encrypt/decrypt) | pIv, **pTag (OUT — server writes it)** |

**Design (workstream RW-P, a prerequisite slice):**

1. `verbs_v32.rs` gains a `MechParam` enum:
   `None | Raw(Vec<u8>) | Gcm{iv,aad,tag_bits} | Oaep{hash_alg,mgf,source,source_data} |
   Ecdh1{kdf,shared_data,public_data} | Hkdf{extract,expand,prf,salt_type,salt,salt_key,info} |
   Pbkd2{salt_source,salt,iterations,prf,password} |
   Sp800_108Counter{prf,segments,…} | Sp800_108Feedback{…} |
   DerivationStringData{data} | GcmMessage{iv,iv_fixed_bits,iv_generator,tag_bits}`
   plus a `NativeParam` builder that owns the native-layout struct AND all
   pointed-to buffers for the duration of one FFI call — the exact
   ownership pattern `build_template`/`NativeTemplate` already proved in
   RW2. Layouts are transcribed from `ck_param.rs`'s own `ck_struct!`
   definitions (single source, pinned to `pkcs11t.h`).
2. Proto: `V32Mechanism` keeps `parameter` (raw bytes, pointer-free cases)
   and gains an optional `oneof structured` with one small message per
   struct above. REST: an optional `params` JSON object alongside
   `parameter`, same field names.
3. `CK_GCM_MESSAGE_PARAMS.pTag` is an OUT field: the verb allocates the
   tag buffer server-side (size from `tag_bits`) and the response message
   carries `tag` bytes back. The engine already reads/writes it at native
   width (`ffi.rs:11108/11583/11745`).
4. In-process parity controls build the identical native structs through
   the same `MechParam` builder, so exact-CKR and exact-bytes parity
   assertions keep working unchanged.

RW-P is *scoped to demand*: build each variant in the workstream that
first needs it (GcmMessage in RW6, the derive family in RW4). Do not
build speculative variants.

## 3. Workstream detail (execution order)

### RW6 — message API + remaining "flat" functions (next; no engine work)

Split into two slices, committed separately.

**RW6a — flat/trivial functions (28 RPCs, no RW-P needed).**
All audit-then-call or honest-code passthroughs; shapes verified in
`ffi.rs` this sweep:

- Admin/info: `C_GetInfo` (72-byte CK_INFO — parse to a typed response),
  `C_GetSlotList`, `C_GetSlotInfo`, `C_WaitForSlotEvent` (engine returns
  `CKR_NO_EVENT` non-blocking / `CKR_FUNCTION_NOT_SUPPORTED` blocking —
  pass both through), `C_CloseAllSessions`, `C_SessionCancel(flags)`,
  `C_LoginUser`.
- Destructive-gated (join `C_DestroyObject`/`C_SetAttributeValue` behind
  `--enable-destructive`, per the flag's own doc comment which already
  names them): `C_InitToken`†, `C_InitPIN`†, `C_SetPIN`†.
- Honest-code stubs (parity of the CODE itself is the test):
  `C_DigestKey`, `C_GetOperationState`, `C_SetOperationState` →
  `CKR_FUNCTION_NOT_SUPPORTED`; `C_GetFunctionStatus`, `C_CancelFunction`
  → `CKR_FUNCTION_NOT_PARALLEL`; `C_AsyncComplete`, `C_AsyncGetID`,
  `C_AsyncJoin` → `CKR_FUNCTION_NOT_SUPPORTED` (all verified at
  `ffi.rs:10065-10087`, `10288-10310`, `11061-11090`).
- Recover + v3.2 verify-with-signature: `C_SignRecoverInit`/`C_SignRecover`
  (two_call), `C_VerifyRecoverInit`/`C_VerifyRecover` (two_call),
  `C_VerifySignatureInit` (takes the signature at init — new request
  message), `C_VerifySignature`.
- Dual-function quartet: `C_DigestEncryptUpdate`, `C_DecryptDigestUpdate`,
  `C_SignEncryptUpdate`, `C_DecryptVerifyUpdate` — all
  session+bytes→bytes, reuse `V32DataRequest`/`V32BytesResponse`.

Parity tests: one flat-codes test (all honest-code RPCs equal control),
one dual-function pipeline test (digest+encrypt in one pass — outputs
byte-equal to running the two FSMs separately, all three transports), one
recover round-trip test, one destructive-posture extension (InitPIN OFF ⇒
`CKR_FUNCTION_NOT_SUPPORTED`).

**RW6b — message-based API (20 RPCs; needs RW-P's GcmMessage only).**
Five families, engine-verified shapes:

- Sign: `C_MessageSignInit`, `C_SignMessage`, `C_SignMessageBegin`,
  `C_SignMessageNext`, `C_MessageSignFinal`. The engine IGNORES `pParam`
  for its supported sign mechanisms (`_p_param` at `ffi.rs:5571/5630`) —
  wire carries optional raw param bytes, documented as ignored today.
- Verify: same five, same shape (`ffi.rs:5710-5786`).
- Encrypt: `C_MessageEncryptInit`, `C_EncryptMessage` (param + AAD +
  plaintext → ciphertext + **tag out**), `C_EncryptMessageBegin`,
  `C_EncryptMessageNext` (`flags` carries CKF_END_OF_MESSAGE),
  `C_MessageEncryptFinal`. Uses `MechParam::GcmMessage`; response carries
  the server-written tag.
- Decrypt: mirror of encrypt; the client SUPPLIES the expected tag
  (becomes the pTag buffer content server-side).
- Parity: AES-GCM message encrypt→decrypt round trip with a shared key
  handle — ciphertext AND tag byte-identical across transports; tamper
  the tag → the engine's real `CKR_SIGNATURE_INVALID`/`CKR_ENCRYPTED_DATA_INVALID`
  code equal three ways; multipart Begin/Next(END_OF_MESSAGE) equals
  one-shot bytes.

### RW4 — wrap/unwrap + derive (5 RPCs; needs RW-P derive-family variants)

Functions (signatures verified): `C_WrapKey` (`ffi.rs:8818`, two_call),
`C_UnwrapKey` (`9034`, template → new handle), `C_WrapKeyAuthenticated`
(`9278`, + AAD), `C_UnwrapKeyAuthenticated` (`9432`), `C_DeriveKey`
(`7766`, template → new handle). All reuse `V32AttributeIn` templates from
RW2 and `MechParam` from RW-P.

Mechanism coverage in parity tests (all engine-dispatched today):
- AES-KW wrap→unwrap round trip (raw-bytes param, no RW-P), wrapped bytes
  byte-identical across transports for the same key pair of handles.
- `CKM_CONCATENATE_BASE_AND_KEY` (bare handle param) and
  `CKM_SHA256_KEY_DERIVATION` (no param) — cheapest derive positives.
- HKDF and PBKDF2 via `MechParam` — derive then read `CKA_VALUE`
  (session key, non-sensitive template) and assert byte-equal three ways;
  PBKDF2 also asserts a wrong-iterations negative produces the engine's
  own code.
- SP800-108 counter KDF with one iteration/counter segment (the engine's
  supported PRF set: SHA-256/384/512-HMAC, SHA3, AES-CMAC).
- KCV composition: derive → `C_GetAttributeValue(CKA_CHECK_VALUE)` parity
  (KcvTemplate category, composes RW1+RW4 — no new surface).

### RW5 — KEM key-object form + algorithm-cell sweep (2 RPCs + test breadth)

- `c_encapsulate_key` / `c_decapsulate_key` verbs over the existing ffi
  entry points — named apart from the legacy bytes-form `encapsulate` verb
  (which stays frozen on the legacy service). Request: mechanism + key
  handle + `V32AttributeIn` template; response: `ck_rv` + ciphertext (out
  bytes via two_call on `pul_ciphertext_len`) + new key handle.
- Positive parity: ML-KEM-768 encapsulate on one transport, decapsulate
  the ciphertext on ANOTHER transport against the same private-key handle,
  then read both derived keys' `CKA_VALUE` (non-sensitive session
  template) — byte-equal, and equal to the in-process control. This is a
  stronger cross-transport assertion than same-transport round-trips.
- Deterministic-seed KAT parity: keygen with `CKA_SEED` in the template
  (the engine's documented deterministic path) — identical ciphertext and
  key bytes across transports where the engine exposes determinism;
  otherwise fall back to the cross-transport decapsulate above.
- Algorithm-cell sweep (test code only, zero new RPCs): extend
  `v32_parity.rs` with sign/verify cells for SLH-DSA (one SHA2 + one SHAKE
  set), XMSS, HSS, and hybrid KEM cells through the generic
  ECDH-as-KEM + `CKM_CONCATENATE_BASE_AND_KEY` composition the CLAUDE.md
  documents — each asserting exact-CKR parity and, where deterministic,
  exact bytes.

### RW-T — terminal: ledger, ratchet, reports, docs (after RW5)

1. `remoting/coverage_ledger.json` — one row per master-plan §3 category:
   `{disposition: RPC | N/A-local | N/A-engine | SUITE-GAP, case_ids: [...],
   justification}`. Hand-authored, machine-checked.
2. Ratchet script (`remoting/scripts/check_coverage_ledger.py` or a Rust
   test — pick whichever the existing gate step can run without new
   toolchain deps): fails if (a) any category in the C++ compliance
   report is missing a ledger row, (b) any `RPC` row names a `case_id`
   that doesn't exist in `v32_parity.rs`, (c) any rpc in the proto's
   `Pkcs11V32` service has no ledger reference. Wired into the EXISTING
   `remoting gRPC+REST services + three-transport parity` step in
   `scripts/local-gate.sh` (per the locked decision — grow that step, do
   not add a new one).
3. Generated `remoting/REMOTE_P11_V32_COVERAGE.md` from the ledger —
   **normalize any randomly-varying content (KCVs, RNG samples, handles)
   from day one** (the v0.25.0 freshness-checker lesson).
4. Regenerate `docs/PKCS11_REMOTING.md`'s applicability table; note the
   legacy 9-verb service as frozen/bench-only.
5. N/A-local rows (no RPC, ledgered with justification): `C_Initialize`/
   `C_Finalize` (server process lifecycle), `C_GetFunctionList`/
   `C_GetInterfaceList`/`C_GetInterface` (function-pointer tables are
   meaningless over a wire), blocking `C_WaitForSlotEvent`, fork
   semantics (its intent is covered by the two-sessions-distinct-RNG
   parity case, per the master plan).

## 4. Cross-cutting constraints (unchanged but re-affirmed)

- Legacy `Pkcs11Remote` service stays byte-frozen; `verbs.rs` untouched.
- Every proto change reshapes JavaJCE-remote's generated stubs — run its
  gate step against a live `pqc-grpc` after RW6a, RW6b, RW4, RW5 (not
  once at the end).
- Never hardcode a CKR in a parity test — capture the in-process control.
- `spawn_blocking` on gRPC remains unbenchmarked; REST doesn't use it.
  Still an open verification item — out of scope here, tracked in the
  master plan §7.
- Commit cadence: one commit per slice (RW6a, RW6b, RW4, RW5, RW-T), each
  ending with the whole remoting workspace green. Same-branch engine
  commits only if an audit finds a real ffi gap (none expected per F1).

## 5. Effort & RPC accounting

| Slice | New RPCs | RW-P variants | Est. effort |
|---|---|---|---|
| RW6a | 28 | — | M (bulk is mechanical; the honest-code and admin shapes are trivial) |
| RW6b | 20 | GcmMessage | M (the tag-out design is the only novelty) |
| RW4 | 5 | Ecdh1, Hkdf, Pbkd2, Sp800-108, DerivationStringData | M (RW-P variants dominate) |
| RW5 | 2 | — | M (test breadth dominates) |
| RW-T | 0 | — | M (ledger authoring + two generators + ratchet) |

End state: 41 + 55 = **96 of 104 functions carried as live RPCs**, the
remaining 8 ledgered N/A-local with justifications — full-parity per the
locked coverage decision.

## 6. Risks

1. **SP800-108 wire mapping** is the hardest RW-P variant (array of
   pointer-bearing segment structs). Mitigation: mirror only the segment
   types the engine's `sp800_108_counter_kbkdf`/`_feedback_kbkdf` actually
   consume; reject others with `CKR_MECHANISM_PARAM_INVALID` — honest,
   ledgered.
2. **Message-API session state interleaving** (message ops share
   `SIGN_STATE` etc. with the plain FSMs): parity tests must assert the
   engine's own mixing-guard codes, not assume independence.
3. **Deterministic-seed KAT availability**: if `CKA_SEED`-based
   deterministic keygen isn't reachable through `C_GenerateKeyPair`
   templates, the KAT downgrade path (cross-transport decapsulate) is
   already specified above — no re-plan needed.
4. **Ledger ratchet false-greens**: check (b)/(c) above exist precisely so
   the ledger can't drift from the test file or the proto (row-level
   ratchets hiding gaps is a known failure mode in this workspace).
