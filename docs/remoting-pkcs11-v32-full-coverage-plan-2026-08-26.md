# Remoting full PKCS#11 v3.2 coverage plan — gRPC + REST C_* mirror (2026-08-26)

**Status: PLAN, ready to execute. Nothing below is built yet.**

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

## 4. Engine prerequisites (the real cost driver)

The engine's `native::` layer (safe, handle-based) covers much of the
need; the rest exists only behind the wasm-ABI `ffi::C_*` entry points
(pointer-based, unsafe on 64-bit hosts) and needs thin `native::`
wrappers added in the `rust/` workspace **first** (its own gate step
already covers them):

Already available (wrap directly): object destroy/find/get/set-attribute,
AES + generic-secret keygen, full asymmetric keygen incl. seeded variants,
the entire key-import/register family, encrypt/decrypt (GCM/ECB/CBC/CTR/
ChaCha20(-Poly1305)/RSA-OAEP), raw-KEK AES key wrap/unwrap, deterministic
KEM, digest one-shot (SHA-256/384/512), concat/digest-derivation/combiner,
ECDH agree, hybrid KEM, split-key, session lifecycle incl. login/logout,
PSS-salt and full-knob PQC sign variants, `SUPPORTED_MECHS` (public const).

Needs new `native::` wrappers (ordered by how many categories they
unblock): **(a)** generic `C_DeriveKey` incl. PBKDF2 + SP800-108 (today
FFI-private) and public HKDF; **(b)** digest FSM + SHA-3/KMAC surface;
**(c)** sign/verify/encrypt/decrypt Init/Update/Final FSMs (state
machinery exists in `rust/src/state.rs`, needs safe entry points);
**(d)** template-form `C_GenerateKey`/`C_CreateObject`/
`C_GetAttributeValue` (multi-attr); **(e)** handle-based
`C_WrapKey`/`C_UnwrapKey` (+authenticated); **(f)** v3.2
`C_EncapsulateKey`/`C_DecapsulateKey` (key-object+template form);
**(g)** message-based §5.20 family; **(h)** `C_GenerateRandom` (trivial);
**(i)** `C_GetMechanismInfo`, token/session info getters.

## 5. Workstreams (execute in order; each ends with three-transport parity tests green + ledger updated + docs row flipped)

| WS | Scope | Engine prereq | New RPCs (≈) | Effort |
|---|---|---|---|---|
| **RW0** | Foundations: `Pkcs11V32` proto service + `ck_rv`-as-field convention; Attribute/Mechanism passthrough types; 16 MiB size limits both stacks; `--enable-destructive` flag; **add the remoting-workspace `cargo test` step to the core local gate** (it's missing today); fix the verb-count/doc drift; parity-suite scaffolding for the new service + `coverage_ledger.json` ratchet | — | 0 | S–M |
| **RW1** | Sessions & login: OpenSession/CloseSession/Login/Logout/GetSessionInfo/GetTokenInfo(+SlotInfo); Session/Init category ledger split | session.rs wrappers exist; info getters (i) | ~7 | M |
| **RW2** | Objects & discovery: CreateObject, DestroyObject†, GetAttributeValue (multi-attr), SetAttributeValue†, FindObjects trio, GenerateKey, template-form GenerateKeyPair (full mechanism set), GetMechanismList/Info; KCV + attribute categories | (d), (h), (i) | ~10 | L |
| **RW3** | Core crypto FSMs: Encrypt/Decrypt Init/Update/Final + one-shot; Digest FSM (+SHA-3, DigestKey); Sign/Verify FSM (+Recover where engine advertises); GenerateRandom; OPERATION_ACTIVE mixing-guard checks | (b), (c), (h) | ~18 | L–XL |
| **RW4** | Wrap/derive: WrapKey/UnwrapKey (+authenticated), DeriveKey (ECDH1/HKDF/PBKDF2/SP800-108/concat/BIP32/SHA*-derive) | (a), (e) | ~5 | L |
| **RW5** | v3.2 KEM proper + PQC breadth: EncapsulateKey/DecapsulateKey (template form), hybrid-KEM cells, SLH-DSA/XMSS/HSS sign cells with parameter/context passthrough, seeded-keygen KAT support | (f) | ~4 | M–L |
| **RW6** | Message-based §5.19/§5.20 (all 20 C_Message* calls as unary RPCs), dual-function, async honest-not-supported codes, Fork-analogue randomness checks, profile objects, cheap SUITE-GAP closures; final ledger sweep + regenerate `docs/PKCS11_REMOTING.md` applicability table from the ledger. Risk is LOWER than it looks: the Rust engine already implements and passes the full 20-function message surface locally (conformance §G1, 45 checks green) — prerequisite (g) is thin safe wrappers, not new crypto | (g) | ~24 | L |

† behind `--enable-destructive`.

Per-RPC mechanical checklist (from the source sweep — applies to every
row above): proto messages + rpc → codegen is automatic but **reshapes
`JavaJCE-remote`'s generated stubs too** (its gate step runs against a
live `pqc-grpc`; run it after every proto change) → `verbs_v32.rs`
function (new module; never extend the frozen `verbs.rs`) → gRPC handler
(tonic trait is exhaustive — the build breaks until every rpc is
implemented, which is our friend) → REST DTO + route (convention: session
handle in body, primary object handle in path, everything base64) →
three-transport parity case: in-process control first, capture its exact
`ck_rv`, assert both wires equal it (never hardcode CKR values —
established rule) → ledger entry → docs table row.

## 6. Validation & evidence

- The extended `three_way_parity.rs` remains the single source of parity
  truth. Every RW adds its cases there; positive paths assert outputs
  byte-equal across transports where deterministic (deterministic-KEM
  coins, seeded keygen make KAT-grade positive parity possible — use
  them), negative paths assert exact `ck_rv` equality.
- A generated **remote conformance report**
  (`remoting/REMOTE_P11_V32_COVERAGE.md`) rendered from
  `coverage_ledger.json`: per compliance category — covered-by-RPC (with
  case ids) / N/A-local (with justification) / N/A-engine. The freshness
  discipline copies `check_pkcs11_reports_fresh.py` **including its
  nondeterminism allowlist lesson** — normalize any run-varying fields
  from day one.
- Gate: the remoting `cargo test` step added in RW0 runs the whole suite
  on every gate invocation (it is fast: in-process servers on ephemeral
  ports, no docker). The JavaJCE-remote live step continues to catch
  proto regressions against a real container.

## 7. Risks / constraints carried from the source sweep

1. **Server-held FSM state + concurrent clients**: engine op-state is
   keyed by session handle; the mirror must reject cross-session misuse
   with the spec's own CKR codes (that's a feature — it's what MultiPart
   categories test) and document that one session's FSM is single-caller.
2. **No spawn_blocking today**: long engine ops block tokio workers.
   With FSM verbs multiplying call counts, RW0 wraps verb dispatch in
   `spawn_blocking` for both services (measured, not assumed, via the
   bench harness before/after — its JSON schema is a compatibility
   surface and must not change).
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
