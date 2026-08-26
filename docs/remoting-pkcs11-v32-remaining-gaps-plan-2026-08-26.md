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

## Execution log

### 2026-08-26 — RW6a (flat/trivial functions)

Shipped, all live-verified. 28 new RPCs: admin/info (7), destructive-gated
admin (3), honest-code stubs (8), recover + verify-with-signature (6),
dual-function quartet (4). Zero engine-crate changes, as predicted.

**core:** `get_info`/`get_slot_list`/`get_slot_info` return raw CK_INFO/
CK_SLOT_INFO bytes (not typed messages — a deliberate call, consistent
with this mirror's existing "no enums, raw codepoints" convention, cheaper
than one-off typed messages for two fixed documented layouts).
`init_token` rejects any `label` that isn't exactly 32 bytes with
`CKR_ARGUMENTS_BAD` BEFORE calling `ffi::C_InitToken` — a real
native-width-audit finding: that entry point reads a fixed
`CK_UTF8CHAR label[32]` with no length parameter, so a shorter wire
payload would be an out-of-bounds read at the FFI boundary, not a
PKCS#11-level error. 5 new unit tests (25/25 core green).

**A real, load-bearing test-isolation finding**, not hypothetical:
`C_CloseAllSessions` closing the LAST session on a slot triggers §5.6.3's
login-state reset AND `invalidate_private_handles_on_slot` (ffi.rs) —
genuinely destructive, process-wide. This process's ONE shared bootstrap
"keep-alive" session (`native::bootstrap_default_token` opens it, logs it
in as USER, and deliberately never closes it) lives on the same slot every
test uses. Two different fixes were needed for the two different test
harnesses in this repo:
- **core crate** (`#[serial]`, one test at a time): the admin unit test
  restores the keep-alive invariant itself (open + login) immediately
  after exercising the destructive call, so every later serial test still
  sees a logged-in token.
- **acceptance crate** (true parallel execution by design — see this
  file's own module doc): no safe moment exists to run the real
  destructive path at all, since concurrently-running parity tests would
  already observe the corruption before any restore could land. V12 was
  redesigned to cover only the real `CKR_SLOT_ID_INVALID` negative path
  (touches no shared state); the positive path stays covered by the core
  crate's serialized test only.

**gRPC + REST:** all 28 RPCs/routes wired; `C_InitToken`/`C_InitPIN`/
`C_SetPIN` gated by `--enable-destructive`, same posture as
`C_DestroyObject`/`C_SetAttributeValue`.

**Validation:** 5 new three-transport parity tests (V11-V15): admin/info +
session lifecycle, close-all-sessions negative path, honest-code stubs (8
codes, 3 transports), verify-with-signature-matches-verify +
Sign/VerifyRecover's real `CKR_MECHANISM_INVALID` on a non-RSA mechanism,
and the dual-function quartet (`C_DigestEncryptUpdate` ciphertext
byte-identical to running Digest+Encrypt as separate FSMs). **Whole
remoting workspace green: 25 core + 7 legacy-parity (no regression) + 15
v32-parity + 2 posture.**

**Not yet done:** the JavaJCE-remote cross-repo gate step (`--javajce-remote`
in `local-gate.sh`) needs a live `pqc-grpc` + `pqc-dev-sandbox` and a Maven
toolchain not present in this environment — flagged per the plan's own
cross-cutting constraint, deferred to whoever runs the full gate before
merging. RW6b (message API) is next.

### 2026-08-26 — RW6b (message-based API)

Shipped, all live-verified. 20 new RPCs: message sign (5), message verify
(5), message encrypt (5), message decrypt (5). Zero engine-crate changes.
Confirms F1's "audit-then-call" prediction AND scopes RW-P down further
than planned: `ffi::msg_encrypt_init_internal` hard-rejects every
mechanism except `CKM_AES_GCM`, so `GcmMessageParams` — the ONE RW-P
variant this workstream needed — is also the ONLY structured
mechanism-parameter shape the entire message API will ever need on this
engine.

**core:** `GcmMessageParams` — a 6-`usize`-word native `CK_GCM_MESSAGE_
PARAMS` builder (`pIv@0, ulIvLen@1, ulIvBits@2 (unused), ivGenerator@3,
pTag@4, ulTagBits@5`, verified byte-for-byte against `ffi::
parse_gcm_msg_params`'s own doc comment), owning the IV and tag buffers
for one FFI call's lifetime — the same ownership pattern RW2's
`NativeTemplate` established, extended to a field-typed struct instead of
a repeated triplet. `pTag` is a real OUT field on encrypt (the engine
writes `tag_bits/8` bytes into it) and a real IN field on decrypt (the
engine reads the caller's expected tag to verify, zeroizing the plaintext
server-side on mismatch) — both directions verified against `ffi::
aes_gcm_exec`'s own body, not assumed. `ivGenerator != 0` (server-
generated IV) is fully supported: the engine writes the fresh IV in place
into the SAME buffer the caller sized, and the verb layer reads it back
out so the caller can decrypt later. 20 new verbs (10 sign/verify, 10
encrypt/decrypt including full Begin/Next multipart FSMs) + 4 new unit
tests (28/28 core green): sign/verify one-shot AND multipart round trip;
encrypt/decrypt one-shot round trip plus real tag-tamper rejection;
generated-IV round trip; and — the strongest correctness check in this
slice — multipart `EncryptMessageBegin`/`EncryptMessageNext` ciphertext
and tag proven byte-IDENTICAL to the one-shot `EncryptMessage` call for
the same key/iv/aad/plaintext (AES-GCM's own determinism as the oracle),
then decrypted back through the multipart `DecryptMessageBegin`/`Next`
FSM.

**Proto:** 15 new messages (mostly per-call request/response shapes for
the encrypt/decrypt family; sign/verify reuse RW1/RW2's `V32DataRequest`/
`V32VerifyRequest`/`V32KeyedInitRequest`/`V32StatusResponse` entirely — no
new messages needed there at all), 20 new RPCs.

**gRPC + REST:** all 20 RPCs/routes wired, calling the core verbs
directly.

**Validation:** 2 new three-transport parity tests. V16: message
sign/verify one-shot round trip + tamper detection, ML-DSA, shared keypair
across transports. V17: message encrypt/decrypt one-shot, shared AES key
— ciphertext AND tag proven byte-identical across in-process/gRPC/REST
(KAT-grade, like V2's digest case and V10's AES-ECB case), then decrypted
back on each transport to recover the original plaintext. **Whole
remoting workspace green: 28 core + 7 legacy-parity (no regression) + 17
v32-parity + 2 posture.**

**Cumulative RPC count after RW1+RW2+RW3+RW6a+RW6b: 89 of 104
`pkcs11f.h` functions live.** RW4 (wrap/derive) is next — the first
workstream that touches genuinely new RW-P territory (the derive-family
mechanism-parameter variants: ECDH1, HKDF, PBKDF2, SP800-108,
key-derivation-string-data) and the first point in the remaining program
where a real engine-crate PR was ever predicted, though F1 already found
the crypto itself pre-existing — RW4 should confirm or refute that for
wrap/unwrap specifically.

### 2026-08-26 — RW4 (wrap/derive)

Shipped, all live-verified. 5 new RPCs: `C_WrapKey`, `C_UnwrapKey`,
`C_WrapKeyAuthenticated`, `C_UnwrapKeyAuthenticated`, `C_DeriveKey`. F1
confirmed again for wrap/unwrap (audit-then-call, no engine change) — but
RW4 is where the RW-P slice finally got real: 5 structured
`CK_*_PARAMS` variants (ECDH1, HKDF, PBKDF2, SP800-108 counter + feedback)
plus the SP800-108 data-parameter ARRAY (a struct-of-structs, each with
its own embedded pointer), the deepest native-layout work in the whole
program.

**A real, load-bearing memory-safety bug was caught and fixed before
anything ran**, not after: the first draft of every `derive_params::*`
builder returned only `StructBuilder.bytes`, discarding
`StructBuilder.owned` (the Vec of buffers each struct's embedded pointers
point into) — which would have dropped those buffers the instant the
constructor returned, leaving every pointer in the "returned" bytes
dangling before any FFI call ever read them. Caught by re-deriving the
ownership chain from first principles before compiling, not by a crash:
`StructBuilder` was made to own the invariant instead — every
`derive_params::*` function now returns the WHOLE `StructBuilder` (never
just its bytes), with a `.as_slice()` accessor that borrows without
separating bytes from the buffers they point into. The gRPC and REST
handlers each needed the identical discipline for the `oneof`/DTO
resolution step (a `DeriveParamBytes` enum holding either the raw bytes or
a live `StructBuilder`) — a second draft of THAT code independently made
the exact same mistake (`.as_slice().to_vec()`, which copies the outer
struct's bytes, embedded pointer VALUES included, without copying what
those pointers point to) and was caught the same way before it shipped.

**core:** a generic `StructBuilder` (RW-P's real foundation) reuses
`ck_param::offset_at`/`size_at` directly — the SAME const fns the
engine's own `ParamReader` walks — so field offsets for
Bbool/Ulong/Ptr-mixed structs (HKDF's two adjacent `CK_BBOOL`s, etc.)
cannot drift from the engine's own layout the way a hand-written offset
table could. `derive_params::{ecdh1, hkdf, pbkd2, sp800_108_counter,
sp800_108_feedback, counter_format}` build the six derive-family structs;
`wrap_key`/`unwrap_key`/`wrap_key_authenticated`/`unwrap_key_authenticated`/
`derive_key` themselves stayed exactly as mechanical as every prior
audit-then-call verb. 5 new unit tests (33/33 core green), each one
correcting a real assumption against the live engine on first run rather
than confirming a guess: `CKR_KEY_UNEXTRACTABLE` (not
`CKR_KEY_NOT_WRAPPABLE`, which is the CKA_WRAP_WITH_TRUSTED-specific
code) for a non-extractable key; `CKP_PBKDF2_HMAC_SHA256=0x04` is a
DIFFERENT namespace from the `CKM_*_HMAC` mechanism codes HKDF/SP800-108
use, and the engine enforces a real 1000-iteration floor;
`CK_SP800_108_ITERATION_VARIABLE` (not a separate `OPTIONAL_COUNTER`
segment) IS counter-mode's counter and needs a real `CK_SP800_108_
COUNTER_FORMAT` value, while the explicit `COUNTER` segment type is
legal only in feedback mode; `C_WrapKeyAuthenticated` is
`CKM_AES_GCM`-only, scoped out of this pass's positive test per the
plan's own stated RW4 scope (not required) in favor of proving the wire
reaches the real engine's own rejection code. ECDH1 — the one variant NOT
in the plan's explicit test list — got a full live test anyway (real
P-256 keygen via `C_GenerateKeyPair(CKM_EC_KEY_PAIR_GEN)`, real
`CKA_EC_POINT` exchange, real `CKD_NULL` shared-secret derivation) and
passed on the first run, the strongest validation the `StructBuilder`
design got in this workstream.

**gRPC + REST:** all 5 RPCs/routes wired. `DeriveKey`'s structured
parameters travel as a proto `oneof` (`V32Ecdh1Params` /
`V32HkdfParams` / `V32Pbkdf2Params` / `V32Sp800108CounterParams` /
`V32Sp800108FeedbackParams`) alongside a `raw_parameter` fallback for
parameterless/already-raw mechanisms — REST mirrors it as five optional
DTO fields, exactly one populated per call.

**Validation:** 2 new three-transport parity tests. V18: AES-KW
wrap→unwrap round trip (wrapped bytes byte-identical across transports)
plus the real `CKR_KEY_UNEXTRACTABLE` negative. V19: `DeriveKey` via both
the raw-parameter path (`CKM_CONCATENATE_BASE_AND_KEY`) and the
structured `oneof` path (HKDF) — derived key material byte-identical
across all three transports for both. **Whole remoting workspace green:
33 core + 7 legacy-parity (no regression) + 19 v32-parity + 2 posture.**

**A second real finding, this one in test infrastructure rather than
product code:** adding V18/V19 (which create several more `CKO_SECRET_KEY`
objects) made the pre-existing V8 test (RW2, `C_CreateObject`/
`FindObjects` round trip) flaky — 4 of 5 runs failed. `C_FindObjectsInit
(CKA_CLASS=CKO_SECRET_KEY)` searches the WHOLE TOKEN, not the calling
session, and this suite's tests run in true parallel sharing one
process-wide object store (this file's own module doc). V8's original
`max_object_count: 10` was an implicit "only a few secret keys will exist
concurrently" assumption that held when the suite was smaller and quietly
stopped holding as RW3/RW6b/RW4 each added more secret-key-creating
tests. Fixed by raising it to 1000 across all three transports (a
one-line, low-risk fix) — confirmed stable across 8 consecutive runs
afterward. Documented in the test file itself so the NEXT workstream
that adds secret-key-creating tests doesn't have to rediscover this.

**Cumulative RPC count after RW1+RW2+RW3+RW4+RW6a+RW6b: 94 of 104
`pkcs11f.h` functions live.** RW5 (KEM key-object form + algorithm-cell
sweep) is next.
