# Remoting full PKCS#11 v3.2 coverage plan — gRPC + REST C_* mirror (2026-08-26)

**Status: RW0 + RW1 + RW2 EXECUTED and green (2026-08-26). RW3-RW6 remain
planned. See the "Execution log" at the end for exactly what shipped.**

Decisions locked with the user (2026-08-26):

| Decision | Choice |
|---|---|
| Coverage target | **Full parity with the compliance suite** — every category either remotely validatable or an explicit, justified N/A |
| Wire API shape | **Mirror PKCS#11 C_* functions 1:1** (incl. Init/Update/Final multipart with server-held operation state) — not more high-level verbs |
| Validation harness | **Extend `remoting/acceptance/tests/three_way_parity.rs`** — one suite, three transports (in-process / gRPC / REST), exact-CKR parity |
| Gate wiring | Grow the acceptance step — see §8's correction: that step does not actually exist in the gate yet and must be added first |

Reference coverage baseline (verified against the current artifacts, not
remembered figures): `cpp_compliance_report.md` — **779 PASS / 0 FAIL /
36 SKIP = 815 checks across 62 categories** (63 `###` headings), driving
**87 distinct C_* entry points** — plus `rust/RUST_P11_V32_CONFORMANCE_REPORT.md`
— **976 checks across 51 sections** against the Rust engine (the engine
this remoting stack actually fronts), driving **77 distinct C_* entry
points**. Union: **93 of the 104 `pkcs11f.h` functions** are validated by
at least one suite. The full per-category → C_* function mapping from the
source sweep is the input to the RW0 ledger.

---

## 1. Current state (measured, not assumed)

The wire surface today is **9 one-shot verbs** (`Health`, `OpenSession`,
`CloseSession`, `GenerateKeyPair`, `Sign`, `Verify`, `Encapsulate`,
`Decapsulate`, `GetSelfSignedCertificate`) over 7 algorithm cells
(Ed25519, ML-DSA-44/65/87, ML-KEM-512/768/1024). It calls **13 of the
engine's ~90 `native::` entry points**. `docs/PKCS11_REMOTING.md`'s own
40-row applicability table already marks most of v3.2 N/A with reasons
like "No AES-GCM verb", "No wrap/unwrap verb", "No KDF verb", "No
CreateObject verb", "No multi-part operation state machine exposed".

Hygiene notes to fix in passing (all found in the source sweep):
- Four contradictory verb counts in-tree (proto=9 RPCs, `verbs.rs` doc
  says "eight", `docs/PKCS11_REMOTING.md` says "Seven… then lists eight",
  bench-harness says "seven" for a 6-method trait).
- Three different wire spellings of every algorithm name (proto
  `ML_DSA_65`, core `"ML-DSA-65"`, REST kebab `"ml-dsa65"`) plus a fourth
  matcher in bench-harness.
- gRPC carries `raw_ck_rv` by **string-formatting it into the Status
  message** and clients parse it with `find("raw_ck_rv=0x")` — the
  structured `Pkcs11ErrorDetail` proto message exists but is never sent.
- `verbs::sign`/`verify`/`encapsulate`/`decapsulate` **panic** on an
  algorithm-family mismatch instead of returning a CKR.
- The three-way parity suite is **developer-run only** — no local-gate
  step runs the remoting workspace's `cargo test` at all today (the
  JavaJCE-remote gate step exercises the proto indirectly, nothing more).

## 2. Target architecture — a parallel `Pkcs11V32` service, old verbs frozen

The existing 9-verb service is a **compatibility surface**: the
bench-harness (`bench-harness transport`, its `RemoteTransport` trait and
its JSON row schema) and `JavaJCE-remote` consume it. It stays byte-for-
byte untouched. The C_* mirror is a **second gRPC service in the same
proto package and the same two binaries** (`pqc-grpc-pkcs11`,
`pqc-rest-pkcs11`), sharing listeners, TLS profiles, and bootstrap:

```
service Pkcs11Remote { … 9 existing rpcs, frozen … }
service Pkcs11V32   { … C_* mirror rpcs, this plan … }
```

Key design rules (each one closes a defect found in the current stack):

1. **Unary-only is PRESERVED.** A 1:1 C_* mirror needs no streaming:
   `C_SignInit`, `C_SignUpdate`, `C_SignFinal` are each their own unary
   RPC; the operation state lives server-side keyed by session handle —
   exactly where the engine already keeps it (`SIGN_STATE` et al. in
   `rust/src/state.rs`). The phase-1 "unary RPCs only" decision is not
   revisited, it is satisfied.
2. **Raw CK types on the wire, no enums.** Mechanisms travel as
   `uint64 mechanism` + `bytes parameter` (CKM_* codepoints verbatim);
   templates as `repeated Attribute { uint64 type; bytes value; }`
   (CKA_* verbatim); return codes as CKR_* verbatim. This eliminates the
   triple-spelling problem for the new surface entirely and means adding
   an algorithm/mechanism is a server-side capability, not a proto change.
3. **`ck_rv` is a response FIELD, not a transport error.** Every
   `Pkcs11V32` response message carries `uint32 ck_rv` (0 = CKR_OK) plus
   its outputs; gRPC Status/HTTP status are reserved for transport
   failures only. This mirrors the C ABI exactly, makes exact-CKR parity
   assertions trivial on both wires, and retires the string-parsing hack
   and the 11-code triple-table for the new surface (the old surface
   keeps its contract).
4. **Session semantics become real.** The mirror exposes
   `C_OpenSession` / `C_Login` / `C_Logout` / `C_CloseSession` /
   `C_GetSessionInfo` faithfully (login state per-token, session flags,
   `CKR_USER_ALREADY_LOGGED_IN` reachable and assertable). The current
   verb layer's app-layer PIN compare stays quarantined in the old
   service.
5. **Explicit message-size limits.** tonic decode/encode limits and
   axum `DefaultBodyLimit` set to 16 MiB in both binaries (today both run
   implicit defaults — 4 MiB/2 MB — which large `C_Encrypt` payloads,
   Classic McEliece public keys (~1 MB), or `C_FindObjects` result pages
   would hit silently; REST base64 inflation ×1.33 counted in).
6. **Destructive-verb guard.** There is currently **zero per-request
   authorization** — any authenticated caller can use any handle. The
   mirror adds one blunt, honest control: a server flag
   `--enable-destructive` (default OFF) gating `C_DestroyObject`,
   `C_SetAttributeValue`, `C_InitToken`, `C_InitPIN`. Without it those
   RPCs return `CKR_FUNCTION_NOT_SUPPORTED`. Real caller identity /
   authorization stays out of scope, documented as such.

## 3. Coverage matrix — all 63 compliance categories → disposition

Legend: **RPC** = remotely validatable through the C_* mirror (workstream
in §5); **N/A-local** = inherently in-process semantics, justified,
listed in the parity suite's ledger as such; **N/A-engine** = the C++
suite validates a C++-engine capability the Rust engine (which remoting
fronts) does not advertise — tracked, not silently dropped.

| Category | Disposition | Carried by / justification |
|---|---|---|
| AES-CTR, GapAes, ChaCha20, G2ChaCha20 | RPC | `C_EncryptInit/Update/Final`, `C_DecryptInit/…`, one-shot `C_Encrypt/Decrypt` (RW3) |
| Attributes, G5Attrs, KcvTemplate, PQKeyBytes, RawEncoding | RPC | `C_GetAttributeValue`/`C_SetAttributeValue` incl. sensitivity gates + KCV attributes (RW2) |
| AuthWrap, WrapTemplate | RPC | `C_WrapKey`/`C_UnwrapKey` + authenticated variants (RW4) |
| BIP32 | RPC | `C_DeriveKey` with BIP32 mechanisms (RW4) |
| CkaIdRetrieval, Discovery, MechFlags, G2MechTable, Profile | RPC | `C_FindObjectsInit/FindObjects/Final`, `C_GetMechanismList/Info`, `C_GetTokenInfo`, profile objects (RW2, RW6) |
| Classical, DSA, DSA-CTX, ECDSA, EdDSA, G7Sha3Rsa, GapClassical, GapEcdsaEddsa, GapRsaSign, SLHDSA, XMSS, XmssParamSet, HBSProtect | RPC | `C_GenerateKeyPair` (template form) + `C_SignInit/Sign/Update/Final` + `C_VerifyInit/…` across the full mechanism set; context-string params via mechanism `parameter` bytes (RW3, RW5) |
| ECDH, G2Derive, GapDerive, KDF | RPC | `C_DeriveKey` (ECDH1, HKDF, PBKDF2, SP800-108, concat, SHA*-derivation) (RW4) |
| GapRsaCipher | RPC | `C_EncryptInit`(RSA-OAEP)/`C_Decrypt` (RW3) |
| ErrCodes, G4Retcodes, Negative, Invariant | RPC | the negative-path table ports directly: exact CKR codes are first-class response fields (RW3–RW6, asserted three-transport) |
| G1Security, GIsolation | RPC (partial) | sensitive-attribute blocking, login gating remotely assertable; process/memory isolation aspects → N/A-local, itemized per check during RW1 |
| G3Keygen, KEM, KEMKcv, KEMNeg, KEMValueLen, HybridKEM | RPC | `C_GenerateKey`/`C_GenerateKeyPair` template forms, v3.2 `C_EncapsulateKey`/`C_DecapsulateKey` (key-object + template form, not the current bytes form), hybrid via existing engine combiner (RW5) |
| G8Dual | RPC | `C_DigestEncryptUpdate` dual-function (RW6) |
| GAsync | RPC | The C++ category asserts an HONEST not-supported surface (async open → `CKR_SESSION_ASYNC_NOT_SUPPORTED` 517; `C_Async*` → `CKR_FUNCTION_NOT_SUPPORTED` 84) — pure return-code checks, fully assertable over the wire (RW6). |
| KCV | RPC | KCV attribute reads post-keygen/unwrap/derive (RW2/RW4) |
| KMAC, G-DA-X, SHA-3 | RPC | `C_SignInit`(KMAC)/`C_DigestInit/Update/Final` FSM (RW3) — note SHA-3 digest one-shot exists engine-side; FSM + KMAC need native wrappers (§4) |
| MsgCrypt, MsgSign, MsgVerify | RPC | v3.2 §5.20 message-based API — each C_Message* call is its own unary RPC with server-held message state (RW6) |
| MultiPart, MultiPart_ECDSA, MultiPart_EdDSA | RPC | the Init/Update/Final FSMs themselves, incl. `CKR_OPERATION_ACTIVE` mixing guards — the exact checks today marked "N/A one-shot by construction" flip to validatable (RW3) |
| FIPS | RPC (partial) | self-test/POST surface where the engine exposes it; process-startup aspects N/A-local |
| Fork | **N/A-local** | fork(2) semantics cannot exist across a network boundary. The category's *intent* (no shared RNG state between independent clients) gets a remote analogue: two concurrent sessions' randomness divergence (RW6). |
| Init, Session | Split | `C_Initialize`/`C_Finalize` lifecycle → N/A-local (server bootstrap owns process lifecycle, documented); session open/close/login/info checks → RPC (RW1) |

Additional ledger rows beyond the report categories:
- **Split Key** — exercised by NEITHER harness today (it lives in separate
  engine cargo tests). Ledger disposition: RPC via `native::split/join`
  (already public) in RW5, with its first-ever harness-grade cases.
- **The 11 v3.2 functions no local suite touches at all** (`C_GetInfo`,
  `C_GetSlotInfo`, `C_SetPIN`, `C_GetOperationState`/`C_SetOperationState`,
  `C_DecryptUpdate`, `C_DigestKey`, and the four `C_VerifySignature*`):
  the mirror's contract is parity **with the suite**, so these are ledgered
  as SUITE-GAP — honest bookkeeping that "full coverage vs our compliance
  script" is not "full coverage vs all 104 functions". Closing them is a
  local-suite work item first, remote second; RW6 includes the cheap ones
  (`C_GetInfo`, `C_GetSlotInfo`, `C_DecryptUpdate`, `C_DigestKey`) on both
  sides where the engine implements them.

Execution rule: during RW1, every individual check inside the split/partial
categories gets a one-line disposition in a machine-readable ledger
(`remoting/acceptance/coverage_ledger.json`), and the parity suite fails
if a compliance-report category exists with no ledger entry — the same
"no silent gaps" ratchet the row-level-ratchet feedback taught.

## 4. Engine prerequisites — REVISED after RW0/RW1 execution (2026-08-26)

**The original framing of this section was pessimistic and is now
corrected by hard evidence.** It assumed every `ffi::C_*` entry point is
"wasm-ABI, pointer-based, unsafe on 64-bit hosts" and therefore each verb
needs a new `native::` wrapper added to the `rust/` crate first. RW0/RW1
proved otherwise: `verbs_v32` calls `ffi::C_DigestInit/Update/Final`,
`C_Sign*`, `C_Verify*`, `C_GetAttributeValue`, `C_GetMechanismList/Info`,
`C_GetSessionInfo/TokenInfo`, `C_GenerateRandom`, `C_OpenSession` **directly
at native width** and every three-transport parity case passed. The reason:
the `ck_param` rework (see `rust/src/ck_param.rs`'s module doc) already
made mechanism-parameter reads ABI-width-correct, and `C_GetAttributeValue`
walks its template as `*mut usize` (native width). The differential harness
`dlopen`s these same symbols natively on every gate run — the native C ABI
path is tested, load-bearing infrastructure, not a hazard.

**So the real per-function gate is a NATIVE-WIDTH AUDIT, not a wrapper
rewrite.** For each not-yet-mirrored `C_*`, before wiring a verb:

1. Read the entry point's parameter reads. If every caller-pointer read
   goes through `ck_param` (mechanisms, param structs) or an explicit
   `*mut usize` walk (attribute templates), the verb calls it **directly**
   — zero engine-crate change. This was true for the entire RW0/RW1 slice.
2. If any read is a raw `*(p as *const u32)` cast of a `CK_ULONG`/pointer
   field, that entry point is width-buggy on LP64 and MUST NOT be called
   natively as-is. Two options, in preference order: (a) fix the read to
   go through `ck_param` in the `rust/` crate (a real engine bug fix,
   gated by the rust-engine test step — the `ck_param` module doc lists
   four such fixes already made, so this is a known, bounded activity), or
   (b) if the fix is out of scope for this program, add a thin typed
   `native::` wrapper that marshals correctly and call THAT. Prefer (a):
   it fixes the bug for every caller, not just remoting.

**Genuinely still FFI-private (no native OR safe ABI-clean path yet)** —
these need engine-crate work regardless, and are the true prerequisites:
- **PBKDF2 + SP800-108 KBKDF**: only inside `C_DeriveKey`'s private helpers
  (`rust/src/ffi.rs:7711/7736/7769`), no `native::` surface at all. RW4
  blocker.
- **v3.2 `C_EncapsulateKey`/`C_DecapsulateKey` key-OBJECT form**
  (`ffi.rs:17086/17144`): `native::encapsulate` returns raw `(ct, ss)`
  bytes; there is no native path that mints a keyed object from a template.
  RW5 blocker (the current legacy Encapsulate/Decapsulate verbs are the
  bytes form and stay frozen).

**Everything else the original list called a "needed wrapper" is actually
a native-width audit away from a direct call** — digest FSM (done), sign/
verify FSM (done), template `C_GenerateKey`/`C_CreateObject`/`C_GetAttributeValue`
(get-attr done; the two keygen/create ones write a `CK_ATTRIBUTE` template
the same `*mut usize` way get-attr reads one — audit then call), handle
`C_WrapKey`/`C_UnwrapKey`, the message-based family, `C_FindObjects`. The
audit is cheap (read one function) and usually passes; budget it as the
first task of each workstream, not a separate engine sub-project.

## 5. Workstreams (execute in order; each ends with three-transport parity tests green + ledger updated + docs row flipped)

| WS | Status | Scope | True prereq | New RPCs (≈) | Effort |
|---|---|---|---|---|---|
| **RW0** | ✅ DONE | Foundations (service, ck_rv-as-field, size limits, flag, gate step, scaffolding) | — | 0 | done |
| **RW1** | ✅ DONE | Sessions/login/info + discovery + random + digest FSM + sign/verify FSM + get-attr + destroy (24 RPCs) | none — all native-width-clean | 24 | done |
| **RW2** | ✅ DONE | Object & keygen templates: `C_GenerateKey`, template `C_GenerateKeyPair`, `C_CreateObject`, `C_SetAttributeValue`†, `C_CopyObject`, `C_GetObjectSize`, `C_FindObjectsInit/FindObjects/FindObjectsFinal` | none — confirmed native-width-clean (writes CK_ATTRIBUTE the same `*mut usize` way get-attr already reads it) | 9 | done |
| **RW3** | next | Encrypt/decrypt: `C_EncryptInit/Encrypt/Update/Final`, `C_Decrypt*` incl. GCM/CTR/OAEP params (CK_GCM_PARAMS etc. via `ck_param`) | native-width audit of the cipher entry points | ~8 | L |
| **RW4** | after RW3 | Wrap + derive: `C_WrapKey`/`C_UnwrapKey`(+authenticated), `C_DeriveKey` (ECDH1/HKDF/concat/BIP32/SHA-derive **now**; PBKDF2/SP800-108 **after** the engine wrapper lands) | **PBKDF2/SP800-108 native wrapper (real engine work)**; wrap/unwrap audit | ~5 | L |
| **RW5** | after RW4 | v3.2 KEM key-object form: `C_EncapsulateKey`/`C_DecapsulateKey` (template form) + hybrid cells + SLH-DSA/XMSS/HSS sign cells + seeded-keygen KAT parity | **key-object EncapsulateKey native wrapper (real engine work)** | ~4 | M–L |
| **RW6** | after RW5 | Message API §5.19/§5.20 (20 `C_Message*` RPCs), dual-function, `C_SignRecover`/`C_VerifyRecover`, async honest-not-supported codes, profile objects, cheap SUITE-GAP closures; **then** the ledger + report + docs regeneration | audit only — engine passes all of §G1 locally (45 checks) | ~24 | L |

† behind `--enable-destructive` (default OFF → `CKR_FUNCTION_NOT_SUPPORTED`).

**Two — and only two — genuine engine-crate prerequisites remain**
(PBKDF2/SP800-108 in RW4, key-object EncapsulateKey in RW5). Everything
else is a native-width audit + the mechanical per-RPC checklist below.
This is the material change from the pre-execution plan, which over-
counted engine work across every workstream.

Per-RPC mechanical checklist (unchanged, now battle-tested across 24 RPCs):
proto messages + rpc → codegen is automatic **but reshapes JavaJCE-remote's
generated stubs too** (run its gate step against a live `pqc-grpc` after
any proto change — this is the one cross-repo blast-radius edge) →
`verbs_v32.rs` fn returning raw `CK_RV` (never extend the frozen `verbs.rs`)
→ gRPC handler in `service_v32.rs` (tonic's trait is exhaustive — the build
won't compile until every rpc is implemented, so nothing is silently
forgotten) → REST DTO in `dto_v32.rs` + route in `routes_v32.rs` (flat
`/v32/<c-fn>`, session handle in body, base64 bytes) → three-transport
parity case in `v32_parity.rs` (capture the in-process `ck_rv`, assert
gRPC == REST == it; never hardcode a CKR) → ledger entry → docs row.

### Per-workstream execution notes (concrete, for whoever picks this up)

**RW2 — templates are the unlock.** The one new shape is the CK_ATTRIBUTE
template on the *input* side (`C_GenerateKey`/`C_CreateObject` READ a
template; RW1's get-attr WROTE lengths into one). Same `*mut usize`
three-word layout, built from a `repeated V32Attribute {type,value}` proto
field. Watch: value bytes for ulong-typed attributes must be written at
native `CK_ULONG` width (the RW1 finding, in reverse) — the wire carries
whatever bytes the caller sent, so the DTO must document "ulong attribute
values are 8-byte LE on this LP64 server". Parity KATs to reuse verbatim
from the compliance suite: G3Keygen's `CKR_TEMPLATE_INCONSISTENT` on
mismatched key-type, `CKR_TEMPLATE_INCOMPLETE` on missing CKA_PARAMETER_SET
— assert those exact codes three ways. FindObjects is a 3-RPC FSM
(Init/Find/Final) with server-held search state keyed by session, exactly
like the digest FSM already shipped.

**RW3 — cipher params travel as bytes.** Reuse the existing `V32Mechanism
{mechanism, parameter}` message unchanged: CK_GCM_PARAMS / CK_CTR_PARAMS /
CK_RSA_PKCS_OAEP_PARAMS go in `parameter` as native-layout bytes and
`ck_param` reads them (its module doc lists these as already-handled). The
Encrypt/Decrypt Init/Update/Final FSM is the digest FSM's shape with a key
handle — near-mechanical given RW1. Positive parity: GCM tag-length honored
(conformance E3, 11 checks); negative: zero-IV → `CKR_MECHANISM_PARAM_INVALID`.

**RW4 — the first real engine task.** Steps: (1) add
`native::pbkdf2_derive` + `native::sp800_108_derive` to the `rust/` crate
wrapping the private helpers at `ffi.rs:7711/7736/7769` (gated by the
rust-engine test step); (2) the wrap/unwrap verbs are audit-then-call.
`C_WrapKey`'s output is bytes; the KCV-on-result categories (KcvTemplate,
39 checks) need `C_GetAttributeValue(CKA_CHECK_VALUE)` on the unwrapped
handle — already have that verb, so those parity cases compose from RW1+RW4.

**RW5 — the second real engine task, and a naming trap.** `native::
encapsulate` (bytes) already exists and is what the FROZEN legacy verb
uses; the v3.2 key-object form (`C_EncapsulateKey` producing a keyed
object + template) has NO native path — add one. Keep the two clearly
named apart in `verbs_v32` (`c_encapsulate_key` vs the legacy
`encapsulate`) so nobody wires the wrong one. Deterministic-KEM coins
(`native::encapsulate_deterministic`, `ffi/encrypt.rs:154`) enable
KAT-grade POSITIVE parity — assert identical ciphertext bytes three ways,
not just matching secrets.

**RW6 — biggest RPC count, smallest risk.** The engine passes all 20
message-based functions locally (conformance §G1, 45 checks green), so
every verb is audit-then-call. Do the 20 C_Message* as five FSM families
(EncryptMessage/DecryptMessage/SignMessage/VerifyMessage each Init/Begin/
Next/Final + one-shot). Async is three trivial honest-not-supported RPCs
(`CKR_FUNCTION_NOT_SUPPORTED`/`CKR_SESSION_ASYNC_NOT_SUPPORTED` — pure
code parity). Fork has no network analogue: its ledger row is N/A-local,
but its *intent* (independent clients' RNG diverges) becomes a real
parity-adjacent case — two sessions, `C_GenerateRandom` on each, assert
distinct. **RW6 ends the program**: only after its verbs land do the
ledger ratchet, the generated `REMOTE_P11_V32_COVERAGE.md`, and the
`docs/PKCS11_REMOTING.md` applicability-table regeneration get built — they
must describe the finished surface, not a moving one.

## 6. Validation & evidence

- `remoting/acceptance/tests/v32_parity.rs` (built in RW1) is the single
  source of parity truth. Every RW adds cases there; positive paths assert
  outputs byte-equal across transports where deterministic (SHA-256 digest
  already does; deterministic-KEM coins and seeded keygen make KAT-grade
  positive parity possible in RW2/RW5 — use them), negative paths assert
  exact `ck_rv` equality with the control captured in-process, never a
  hardcoded codepoint.
- **The `coverage_ledger.json` + generated report land in RW6, NOT
  incrementally.** Rationale corrected from the original plan: a ledger
  that ratchets ("fail the suite if a compliance category has no entry")
  is only meaningful once the surface is complete — building it mid-program
  would either block every intermediate commit or encode a moving target.
  Until RW6, coverage is tracked in this doc's execution log (category →
  RW that covers it). RW6 builds: (a) `coverage_ledger.json` — one row per
  compliance category with `{disposition: RPC|N/A-local|N/A-engine|SUITE-GAP,
  case_ids: [...], justification: "..."}`; (b) a check that fails if any
  `cpp_compliance_report.md` category is missing a row (the ratchet);
  (c) a generated `remoting/REMOTE_P11_V32_COVERAGE.md` rendered from it;
  (d) freshness discipline copying `check_pkcs11_reports_fresh.py`
  **including its nondeterminism allowlist lesson** — the ML-DSA/ML-KEM
  random-key-byte and KCV fields that broke the C++ report's own freshness
  check will appear here too; normalize them from the first commit, do not
  rediscover the same bug.
- Gate: the remoting `cargo test` step added in RW0 runs the whole suite
  on every gate invocation (fast — in-process servers on ephemeral ports,
  no docker). The JavaJCE-remote live step continues to catch proto
  regressions against a real container.

### Effort & sequencing (revised post-RW1)

RW0+RW1 (done) removed the biggest unknown — the architecture and the
native-width reality are proven, so RW2/RW3/RW6 are now "mechanical at
volume" (audit + checklist × N functions), and only RW4/RW5 carry genuine
engine-crate work (two wrappers total). Suggested order and gating:
- **RW2 → RW3 → RW6** can run back-to-back with no engine changes (pure
  remoting-crate + audit). Largest RPC volume, lowest risk.
- **RW4, RW5** each begin with a `rust/`-crate PR (the wrapper), gated by
  the rust-engine test step, BEFORE the remoting verbs — keep those two
  engine changes small, reviewed, and separately committed from the
  transport work so a wrapper bug is not tangled with a proto change.
- Every workstream is independently shippable (its parity cases green, the
  frozen legacy surface + bench JSON + JavaJCE-remote untouched), so the
  program can pause cleanly after any RW.

## 7. Risks / constraints carried from the source sweep

1. **Server-held FSM state + concurrent clients**: engine op-state is
   keyed by session handle; the mirror must reject cross-session misuse
   with the spec's own CKR codes (that's a feature — it's what MultiPart
   categories test) and document that one session's FSM is single-caller.
2. **spawn_blocking**: DONE for the `Pkcs11V32` gRPC handlers in RW1
   (the legacy service is unchanged — its verbs are short and the bench
   measures it, so its behavior stays frozen). **Not yet measured**: the
   RW1 claim that spawn_blocking is net-beneficial under FSM call volume
   is asserted, not benchmarked — an open verification item, run the bench
   harness before/after once RW3's multi-call FSMs exist (its JSON schema
   is a compatibility surface and must not change). REST handlers do NOT
   use spawn_blocking (axum/ureq path); revisit if a REST-arm latency
   regression shows up.
3. **Single-tenant trust model is unchanged** — bare u32 handles, no
   per-request identity. The `--enable-destructive` flag is a tripwire,
   not an authorization system. Stated in docs and in the plan's own
   scope: real authz is out of scope.
4. **Cross-workspace builds**: engine wrappers land in `rust/` (own gate
   step), remoting in its standalone workspace (new gate step), and the
   `[patch.crates-io]` block must stay duplicated in `remoting/Cargo.toml`.
5. **The C++ 779-check suite validates the C++ engine; remoting fronts
   the Rust engine.** Category checks whose mechanisms the Rust engine
   does not advertise (e.g. RIPEMD/SHA-1 families, CMAC — see the
   differential harness's `LEGAL-MECHANISM-SET` adjudications) are
   **N/A-engine** in the ledger, mirroring `exceptions.json` rather than
   inventing new adjudications.

## 8. Corrections to the locked decisions (surfaced by the sweep, need no re-decision)

- "Grow the existing acceptance gate step" — there is **no** such step
  today; the parity suite is developer-run only. RW0 creates the step;
  from then on it grows exactly as decided.
- The v3.2 `C_EncapsulateKey`/`C_DecapsulateKey` in the compliance suite
  are the **key-object + template** form; the existing `Encapsulate`/
  `Decapsulate` verbs (raw bytes out) are NOT that and stay untouched —
  RW5 adds the real thing alongside.

## 9. Definition of done

Every one of the 63 categories has a ledger disposition; every RPC
disposition is backed by at least one three-transport parity case
asserting exact `ck_rv`/output equality; the coverage report generates
from the ledger and is committed fresh; the gate runs the whole suite;
`docs/PKCS11_REMOTING.md`'s applicability table contains zero rows whose
N/A reason is "no verb exists" (each is either a real RPC now or a
justified N/A-local/N/A-engine); the 9 legacy verbs, bench-harness JSON
schema, and `JavaJCE-remote` behavior are byte-identical to v0.25.0.


---

## Execution log

### 2026-08-26 — RW0 + RW1 + first RW2/RW3 slices (branch feat/remoting-v32-mirror off v0.25.0)

Shipped, all live-verified (no mocks — every test drives the real engine
through the real transports):

**Proto:** new `Pkcs11V32` service alongside the frozen `Pkcs11Remote`
(purely additive — `git diff` shows zero removed lines from the legacy
block). `ck_rv` is a response field on every message; mechanisms/attributes
travel as raw `uint64` codepoints + parameter bytes; 24 C_* RPCs declared.

**core (`verbs_v32.rs`):** raw-`CK_RV`-returning layer over the engine's
native-width `ffi::C_*` entry points (proven natively callable — the
differential harness dlopens these same symbols). Implemented: C_OpenSession/
CloseSession/Login/Logout/GetSessionInfo/GetTokenInfo/GetMechanismList/
GetMechanismInfo/GenerateRandom/SeedRandom, the Digest FSM + one-shot, the
Sign/Verify FSM + one-shot, multi-attr C_GetAttributeValue (real §5.7.5
consolidated codes), C_DestroyObject. 6 new unit tests (15/15 core green).
One live finding baked in: ulong attribute VALUES come back at native
CK_ULONG width (8 bytes LP64) — documented, wire consumers read the low 4.

**gRPC + REST:** full `Pkcs11V32` service on both transports, mounted in the
existing binaries (16 MiB message limits set explicitly, retiring the silent
4 MiB/2 MB defaults). `--enable-destructive` flag (default OFF → C_DestroyObject
answers CKR_FUNCTION_NOT_SUPPORTED); acceptance/gate run it ON. gRPC handlers
dispatch through `spawn_blocking`.

**Validation:** `remoting/acceptance/tests/v32_parity.rs` — 6 three-transport
parity cases (session lifecycle + double-close CKR, SHA-256 digest byte
equality, ML-DSA sign→verify + real CKR_SIGNATURE_INVALID on tamper,
C_GetAttributeValue §5.7.5 sensitive-code parity, mechanism list/info parity,
C_DestroyObject parity) — control captured in-process, never hardcoded,
asserted equal across in-process/gRPC/REST. Plus a destructive-OFF posture
unit test in the grpc crate. **Whole remoting workspace green: 15 core + 7
legacy-parity (no regression) + 6 v32-parity + 1 posture.**

**Gate (RW0's key fix):** added the `remoting gRPC+REST services +
three-transport parity` step to `scripts/local-gate.sh` — the remoting
workspace ran in NO gate step before today.

### 2026-08-26 — RW2 (object & keygen templates)

Shipped, all live-verified. Confirms §4's revised prediction: zero
engine-crate changes needed — a native-width audit of all nine ffi entry
points (all walk `CK_ATTRIBUTE` templates as the same `*mut usize`
three-word layout RW1's get-attr already relies on) was the entire
prerequisite.

**core (`verbs_v32.rs`):** added `AttrIn`/`attr_ulong`/`attr_bool` and a
`build_template` helper (owns the native `*mut usize` backing storage +
value buffers for the lifetime of one FFI call — the input-side mirror of
RW1's output-side template walk). Nine new verbs: `generate_key`,
`generate_key_pair` (template form), `create_object`,
`set_attribute_value`, `copy_object`, `get_object_size`,
`find_objects_init/find_objects/find_objects_final`. 5 new unit tests
(20/20 core green), including the real §G3Keygen `CKR_TEMPLATE_INCONSISTENT`
(mismatched key-type) and `CKR_TEMPLATE_INCOMPLETE` (missing
CKA_PARAMETER_SET) codes, asserted against the live engine on first run.

**Proto:** `V32AttributeIn` + 8 new request/response messages, 9 new RPCs
on `Pkcs11V32` — purely additive.

**gRPC + REST:** all nine RPCs/routes wired, calling the core verbs
directly (same pattern as RW1). `C_SetAttributeValue` gated by
`--enable-destructive` on both transports (mirrors `C_DestroyObject`'s
posture: OFF ⇒ `CKR_FUNCTION_NOT_SUPPORTED`), with its own OFF-posture
unit test in the grpc crate.

**Validation:** 3 new three-transport parity tests in `v32_parity.rs` —
template `C_GenerateKeyPair` positive round-trip + `TEMPLATE_INCONSISTENT`
negative (V7), `C_CreateObject`/FindObjects FSM/`C_CopyObject`/
`C_GetObjectSize` round trip (V8), `C_GenerateKey` (AES) +
`C_SetAttributeValue` with destructive ON (V9). **Whole remoting workspace
green: 20 core + 7 legacy-parity (no regression) + 9 v32-parity + 2
posture.**

### Still planned (RW3 → RW6)

See §4 (revised prerequisites) and §5's per-workstream execution notes —
refined 2026-08-26 after RW0/RW1 shipped, confirmed again by RW2. Headline:
only **two** genuine engine-crate prerequisites remain (PBKDF2/SP800-108
for RW4, key-object EncapsulateKey for RW5); everything else is a
native-width audit + the proven per-RPC checklist. RW3→RW6 need no engine
changes and can run back-to-back; the ledger/report/docs-regeneration are
RW6-terminal, not incremental.
