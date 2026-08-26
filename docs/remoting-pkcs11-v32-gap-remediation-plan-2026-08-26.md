# Remoting v3.2 mirror — gap remediation plan (2026-08-26, post-program)

**G1 EXECUTED and green (2026-08-26).** See "Execution log" at the end.

Execution-ready plan for every gap left open at the close of the
remoting v3.2 coverage program (RW0–RW-T, 11 commits on
`feat/remoting-v32-mirror`). Source of truth for what the gaps ARE:
`remoting/coverage_ledger.json` + the "report remaining gaps" audit that
followed RW-T. This document is the third in the plan series; the two
predecessors (`remoting-pkcs11-v32-full-coverage-plan-2026-08-26.md`,
`remoting-pkcs11-v32-remaining-gaps-plan-2026-08-26.md`) are COMPLETE and
stay frozen as records — nothing here reopens them.

Standing decisions carried forward unchanged from the locked rounds:
same branch (`feat/remoting-v32-mirror`), local-only until the user says
push, one commit per slice ending with the whole remoting workspace
green, destructive ops ON in tests / OFF deployed, never hardcode a CKR
(capture the in-process control), ledger + generated report updated in
the same commit as the code they describe (the ratchet enforces this
mechanically).

## 0. A correction found while grounding this plan

**KMAC needs NO engine work.** The prior gap report repeated the master
plan's §3 note ("KMAC needs a native wrapper"). That note predates the
F1 finding and is stale: `ffi::C_SignInit` already dispatches
`CKM_KMAC_128`/`CKM_KMAC_256` (`ffi.rs:5186`), reading the vendor
`CK_PQCTODAY_KMAC_PARAMS` through `ck_param::kmac` — and the params are
**optional** (`opt_params`: absent ⇒ defaults, `ffi.rs:4901`). Under the
ffi-direct pattern the existing `sign_init`/`sign` verbs already carry
KMAC with zero new wire code for the default path. KMAC therefore moves
from "deferred engine capability" to the mechanism-cell sweep (G3
below), with an optional RW-P builder only for the customization-string
form. This is the third time grounding a plan against the source has
shrunk the assumed engine work (F1 did it twice); the pattern holds.

## 1. Gap inventory → slices

| # | Gap | Class | Slice |
|---|---|---|---|
| 1 | AES-GCM authenticated wrap positive path (`CK_GCM_PARAMS` RW-P builder missing) — AuthWrap's `NIST_SP800_38D_KAT` check | Functional, zero positive coverage | **G1** |
| 2 | RSA-OAEP encrypt/decrypt (`CK_RSA_PKCS_OAEP_PARAMS` RW-P builder missing) — GapRsaCipher | Functional, zero positive coverage | **G1** |
| 3 | Split Key — dropped from RW5's scope in the plan rewrite; no remoting path of any kind | Scope decision needed | **G2** |
| 4 | ~23 ledger categories with an empty `case_ids` (mechanism proven for a sibling, not for THIS mechanism) | Test coverage | **G3** |
| 5 | Fork's cross-session RNG-divergence analogue never built as its own case | Test coverage | **G3** |
| 6 | V21 wholly `#[ignore]`d — including SLH-DSA, which is NOT slow | Gate posture | **G4** |
| 7 | JavaJCE-remote never rebuilt against the ~90-RPC-larger proto | Process / cross-repo | **G5** |
| 8 | `spawn_blocking` vs REST unbenchmarked (plan §7 risk 2) | Process / benchmarking | **G5** |
| 9 | No live smoke test of the real binaries (everything was in-process/loopback `cargo test`) | Process / verification | **G5** |
| 10 | Branch unpushed, unreviewed, no CI run | User decision | **G6** |

## 2. G1 — the two missing RW-P builders (closes the only functional gaps)

Both `ck_param` layouts already exist (single source of truth, pinned to
`pkcs11t.h`); both builders are mechanical `StructBuilder` reuse, the
exact pattern RW4's five derive-family builders proved. Verified field
lists:

- **`ck_param::gcm`** — `P_IV`(ptr), `UL_IV_LEN`, `UL_IV_BITS`,
  `P_AAD`(ptr), `UL_AAD_LEN`, `UL_TAG_BITS`. Two pointer fields, same
  shape as `ecdh1`.
- **`ck_param::oaep`** — `HASH_ALG`, `MGF`, `SOURCE`,
  `P_SOURCE_DATA`(ptr), `UL_SOURCE_DATA_LEN`. One pointer field.

Work:

1. `verbs_v32::cipher_params` module (sibling of `derive_params`, same
   ownership contract: return the whole `StructBuilder`, never bare
   bytes): `gcm(iv, aad, tag_bits)` and
   `oaep(hash_alg, mgf, source, source_data)`.
2. Wire shape: extend the DERIVE pattern, not the mechanism message —
   add a `structured` oneof (`V32GcmParams`, `V32OaepParams`) alongside
   the raw `parameter` bytes wherever a mechanism travels. Two options,
   pick at execution: (a) new optional fields on `V32Mechanism` itself
   (one edit covers every mechanism-taking RPC — encrypt, wrap, message
   ops), or (b) per-RPC oneofs like `V32DeriveKeyRequest`'s. Prefer
   (a): `V32Mechanism` is already `Option<>` everywhere and a
   `oneof structured` inside it is backward-compatible; document that
   `parameter` and `structured` are mutually exclusive.
3. Tests (the actual point):
   - **AuthWrap positive**: AES-GCM `wrap_key_authenticated` →
     `unwrap_key_authenticated` round trip with AAD; tamper the AAD →
     the engine's real auth-failure code; unwrapped `CKA_VALUE` equal to
     the original (the ledger row's `NIST_SP800_38D_KAT` intent). Core
     unit test + one three-transport parity case (V23).
   - **GapRsaCipher positive**: `CKM_RSA_PKCS_KEY_PAIR_GEN` (engine
     dispatch confirmed at `ffi.rs:2045`, 1024–4096 bit) →
     OAEP encrypt → decrypt round trip, plaintext recovered; MGF/hash
     variation asserted to change the ciphertext. Core unit test + fold
     into V23 or its own case.
   - **Bonus closed by the same builder**: AES-GCM one-shot/FSM
     `C_EncryptInit(CKM_AES_GCM)` positive (currently the AES family is
     only ECB-cased) — one extra assertion block, cheap.
4. Ledger: fill `AuthWrap` and `GapRsaCipher` `case_ids`, delete their
   "genuinely not covered" clauses; regenerate the report. The ratchet's
   check (b) verifies the new case names automatically.

Effort: S–M. One commit.

## 3. G2 — Split Key: decide, then (probably) two vendor RPCs

Facts: `native::split`/`native::join` are public, typed, isolation-gated
functions (`native/split_key.rs:48/131`) covering all four KMIP §11.54
methods. There is **no** `C_*` entry point for them — no
`CKM_PQCTODAY_SPLIT_KEY` arm in `C_DeriveKey`'s dispatch — so they
cannot ride the 1:1 mirror. Split Key is also NOT one of the 63
compliance-report categories (it was an "additional ledger row" promise
in the original master plan §3), so the ratchet does not currently force
the question.

Recommendation (decide at execution, no user round-trip needed —
"Recommended" defaults were taken all program): **add two explicitly
vendor-labeled RPCs** `SplitKey`/`JoinKey` on the `Pkcs11V32` service —
documented in the proto as "vendor extension, not part of pkcs11f.h,
mirrors `native::split/join` for KMIP parity" — rather than inventing a
fake `C_` name or forcing it through `C_DeriveKey`. Wire shape: method +
parts + threshold + optional polynomial in, `repeated {handle,
key_part_identifier}` out (the identifier is not recoverable from the
handle — the native API's own doc says so). Tests: split → join round
trip recovering the secret for XOR and one threshold method; a
below-threshold join → the real error code. Add a `SplitKey` ledger row
(disposition `RPC`, flagged vendor-extension) so it can never silently
drop out of scope again — that is exactly how it got lost the first
time.

Fallback if the vendor-RPC shape is unwanted: a ledger row with
disposition `N/A-engine` ("no C_* surface exists; KMIP is the split-key
transport") — honest, cheap, and visible. The one WRONG outcome is the
status quo: absent from the ledger entirely.

Effort: S (either way). One commit.

## 4. G3 — mechanism-cell sweep (empties the empty `case_ids` rows)

One commit, almost entirely test code, exercising already-shipped verbs
with mechanisms nobody has run through them. Grouped by what each cell
actually needs (verified against the engine's dispatch arms):

**Zero new wire code — raw bytes or no parameter:**
- `AES-CTR`/`GapAes`: `CK_AES_CTR_PARAMS` is pointer-free
  (`{ulCounterBits, cb[16]}`) — build as native bytes client-side
  (`StructBuilder` without owned buffers). Encrypt/decrypt round trip.
- `AES-CBC`: raw 16-byte IV as `parameter` (`ffi.rs:6127` reads it
  directly). Round trip incl. `CBC_PAD`.
- `Classical`/`DSA`/`ECDSA`/`GapClassical`/`GapEcdsaEddsa`/`GapRsaSign`
  (positive half): RSA-PKCS sign/verify (no param), `CKM_ECDSA` raw
  sign/verify (no param) over the P-256 keygen G1/RW4 already use.
  Also the RSA-positive `C_SignRecover` round trip (RSA keygen makes it
  possible now — RW6a could only test the non-RSA rejection).
- `EdDSA`: plain `CKM_EDDSA` (no param needed when not using phFlag)
  over `CKM_EC_EDWARDS_KEY_PAIR_GEN` — verify the keygen mechanism name
  in `ffi.rs` first (audit-then-call, as always).
- `SHA-3`/`G-DA-X`/`G7Sha3Rsa`: `CKM_SHA3_256` digest one-shot + FSM
  equality (constant confirmed: `0x2B0`).
- `KMAC` (per §0): `sign_init(CKM_KMAC_128, &[], key)` default-params
  path — generic-secret key, sign, length-check the MAC. Customization
  form only if the optional `kmac` RW-P builder is thrown in (cheap —
  one pointer field — but optional).
- `KCV`/`KcvTemplate`/`KEMKcv`: read `CKA_CHECK_VALUE` (0x90) after
  AES keygen, after unwrap, and after KEM decapsulate — engine computes
  it on every secret-key creation (`compute_kcv`), so this is pure
  get-attr assertions.
- `Profile`: `find_objects_init(CKA_CLASS=CKO_PROFILE)` → the built-in
  profile objects (they survive token init by design, `ffi.rs:427`) →
  read `CKA_PROFILE_ID`. Pure existing-verb composition.
- `RawEncoding`/`PQKeyBytes` residue: assert `CKA_VALUE`/`CKA_EC_POINT`
  encodings on cells already generated in other tests.
- `MultiPart_ECDSA`/`MultiPart_EdDSA`: Update/Final FSM equality vs
  one-shot for those two mechanisms specifically.
- `Fork` analogue: TWO sessions, `generate_random` on each, assert the
  draws differ — the dedicated cross-session case the ledger row admits
  is missing.
- `BIP32`: `C_DeriveKey(CKM_BIP32_MASTER_DERIVE)` with the
  template-carried params (`CKA_EC_PARAMS` etc. — read the dispatch arm
  at `ffi.rs:7814` for the exact required attrs before writing the
  test).
- `DSA-CTX`: ML-DSA context-string via `CK_SIGN_ADDITIONAL_CONTEXT` —
  pointer-bearing, so EITHER add the (tiny, 3-field) `sign_ctx` RW-P
  builder or defer with an honest ledger note. Include the builder: it
  also unlocks the hedge-variant knob the old 7-verb service documented
  as "a future widening".
- `ChaCha20`/`G2ChaCha20`: `CK_CHACHA20_PARAMS` has two pointers →
  needs a small RW-P builder (4 fields). Include it here rather than
  G1 — same file, same pattern, and it closes both ChaCha rows.
- `FIPS`/`Invariant`/`G4Retcodes`: no new surface — retag these rows'
  justifications to point at the nearest real cases (they are
  design-level rows; decide row-by-row whether a dedicated case adds
  anything or the justification should simply name existing cases).

Per-cell budget discipline: every cell is an assertion block inside at
most 2–3 new `#[serial]` core tests + 1–2 parity cases — NOT one test
per cell (the suite's per-test session setup would dominate). Watch the
two known suite hazards: token-wide `FindObjects` counts (use 1000) and
the shared keep-alive session (never `close_all_sessions` in the
parallel suite).

Exit criterion: `python3 -c "..."` count of empty-`case_ids` RPC rows
drops from 27 to ≤ 5, and every remaining empty row's justification
names the sibling case that proves its verb. Regenerate the report.

Effort: M (the biggest slice — it is breadth, not depth). One commit.

## 5. G4 — V21 gate posture: split fast cells from slow ones

The 326s is XMSS/HSS Merkle keygen; SLH-DSA-128S keygen is fast. Split
V21 into:
- `v21a_slh_dsa_sign_verify_parity` — routine suite (measure first;
  keep only if the whole test stays under ~10s, SLH-DSA *sign* at 128s
  is not instant either).
- `v21b_xmss_hss_sign_verify_parity` — keeps `#[ignore]` + the timing
  doc comment.

Also add the measured V21b runtime to the gate-step comment in
`local-gate.sh` so nobody "fixes" the ignore without seeing the cost.
Effort: XS. Folded into the G3 commit.

## 6. G5 — process gaps (verification, not code)

Ordered by what this environment can actually do:

1. **Live smoke test (doable here)**: build and run the two real
   binaries (`pqc-grpc-pkcs11`, `pqc-rest-pkcs11`) on loopback ports,
   drive one session→keygen→sign→verify sequence against each via
   `grpcurl`/`curl` (REST is plain JSON; gRPC has reflection or use a
   tiny Rust client), then shut down. This is the "run the app, not the
   test suite" check the program never did. If it works first try it's
   ten minutes; whatever it surfaces was invisible to `cargo test`.
   One-off verification, not a new gate step (the acceptance suite
   already covers the logic; this covers the BINARIES — arg parsing,
   `--enable-destructive` flag plumbing, port binding, TLS-off paths).
2. **JavaJCE-remote stub regeneration (blocked here, unblock-able)**:
   needs Maven + a live `pqc-grpc`. Two routes: (i) the user runs
   `bash scripts/local-gate.sh --javajce-remote` on the host with the
   sandbox up — the existing opt-in step, zero new work; (ii) cheaper
   pre-check doable here: `protoc`-compile the proto with the Java
   plugin if available, proving the schema at least still codegens for
   Java. Route (i) is the real gate; record it as a pre-merge checklist
   item in the PR description rather than pretending it ran.
3. **`spawn_blocking` vs REST benchmark**: do NOT build a bespoke
   harness — fold into the EXISTING transport-arms bench program
   (hsm PR #178 / sandbox v0.11.3, whose whole purpose is comparing
   these transports). Concretely: one bench scenario driving
   `C_Sign`(ML-DSA-87, large message) at high concurrency through the
   v32 gRPC path (spawn_blocking) and the v32 REST path (no
   spawn_blocking), watching p99 under a saturated worker pool. Until
   that program picks it up, the honest state remains "unbenchmarked"
   — keep the risk line in the plan docs, do not delete it.

Effort: S here (item 1 + the checklist wiring); items 2(i) and 3 are
homework for the environments that have the tools.

## 7. G6 — push/review (user decision, prerequisites listed)

Not executed without an explicit go-ahead (standing push-gate rule).
When asked, the pre-push checklist is:
1. `bash scripts/local-gate.sh` end-to-end in the worktree
   (`AG_CONTAINER_ROOT` override per the known worktree gotcha) — the
   full gate, not the remoting subset this program ran per-commit.
2. JavaJCE-remote step (G5 item 2) on a machine with Maven.
3. Rebase onto current `main` (the parallel JDK-27 session may have
   moved it) — verify with `git -C`, re-run the remoting tests
   post-rebase.
4. PR base = `origin/main`; body lists the two honest open items
   (bench, and whatever G1–G3 slices haven't landed yet if pushed
   early).

## 8. Sequencing & effort summary

| Slice | Contents | Effort | Commit |
|---|---|---|---|
| G1 | GCM + OAEP RW-P builders, AuthWrap/GapRsaCipher/AES-GCM positives | S–M | 1 |
| G2 | Split Key vendor RPCs (or explicit N/A-engine row) | S | 1 |
| G3+G4 | Mechanism-cell sweep (+ ChaCha20/sign-ctx builders), V21 split | M | 1 |
| G5 | Live binary smoke + pre-merge checklist wiring | S | 1 (docs/scripts only) |
| G6 | Push/review | — | user-gated |

G1 → G3 ordering matters (G3's AES-GCM cells reuse G1's builder). G2 is
independent — can run any time. Ledger + generated report are updated in
every slice's own commit; the ratchet makes forgetting impossible for
categories and case_ids, and the `pkcs11f_h_function_count` block must
be bumped by hand in G2 if the vendor RPCs land (they are deliberately
NOT `C_*`-named, so check (c) won't see them — add them to the
`$schema_note` instead so the ledger stays self-describing).

## 9. What this plan deliberately does NOT do

- No new engine-crate work anywhere (G1/G3's builders are remoting-side;
  §0 retired the last claimed engine prerequisite).
- No reopening of the frozen legacy `Pkcs11Remote` service or its
  coverage table.
- No new gate steps — everything lands inside the existing remoting
  step, keeping gate wall-time flat (the V21 split may even help).
- No push, no CI, no deploy — G6 stays behind the user's explicit gate.

## Execution log

### 2026-08-26 — G1 (GCM + OAEP RW-P builders)

Shipped, all live-verified. Closes AuthWrap's and GapRsaCipher's
functional gaps for real, plus a bonus: AES-GCM one-shot/FSM joins
AES-ECB in the GapAes/AES-CTR row.

**Wire shape, exactly as decided**: `oneof structured { V32GcmParams gcm;
V32OaepParams oaep; }` added directly to `V32Mechanism` itself — one
proto edit reached every mechanism-taking RPC. `V32MechanismDto` grew the
matching `gcm`/`oaep` optional fields for REST.

**core:** `cipher_params::gcm`/`oaep` — same `StructBuilder` discipline
as `derive_params`, built from `ck_param::gcm`/`ck_param::oaep`'s
already-existing layouts. `verbs_v32`'s own signatures (`encrypt_init`,
`wrap_key_authenticated`, etc.) needed ZERO changes — they already took
`parameter: &[u8]`; only the callers changed what they pass. 3 new unit
tests (40/40 core green): AES-GCM one-shot round trip + FSM byte-equality
against the one-shot + real tag-tamper rejection; RSA-2048 OAEP round
trip + OAEP's own re-randomization property (same plaintext, same
params, twice → different ciphertexts, both still decrypt); AES-GCM
authenticated wrap/unwrap round trip + real AAD-tamper rejection — the
compliance suite's own `NIST_SP800_38D_KAT` check, finally exercised.

**gRPC + REST — the widest mechanical refactor in the whole program, and
the cleanest**: `mech_parts` (gRPC) and a new `mech_param_bytes` (REST)
now resolve the oneof into a `MechParamBytes` enum (`Raw(Vec<u8>)` |
`Structured(StructBuilder)`) — same ownership contract as `DeriveKey`'s
existing `DeriveParamBytes`, independently re-derived for REST rather
than shared across crates (the DTO and proto types differ). 21 call
sites in EACH crate needed `&param`/`&r.mechanism.parameter` changed to
`.as_slice()` — done via `perl -pi -e` (macOS `sed`'s `\b` doesn't match
GNU's), then verified by grep that zero old-pattern occurrences
remained. Both crates compiled clean on the FIRST build after the
mechanical pass — the uniform call-site pattern (proven by grep before
touching anything) made the blanket edit safe.

**Test file fallout, expected and mechanical**: adding a `oneof` field
to a prost message makes it non-`Default`-constructible via plain struct
literals without every field named. 26 pre-existing `V32Mechanism { ...
}` literals across `v32_parity.rs` needed `, structured: None` appended
— one `perl` pass, verified by grep that every match legitimately
belonged to a `V32Mechanism` literal (not a coincidentally-similar
struct) before running it.

**Validation:** 3 new three-transport parity cases. V23: AES-GCM via the
structured oneof, ciphertext byte-identical across all three transports
(KAT-grade, shared key). V24: RSA-OAEP via the structured oneof — OAEP
re-randomizes its seed every call, so each transport's own ciphertext is
independently verified to decrypt back to the original plaintext (not
byte-equality with a control, which would be the wrong assertion for a
randomized scheme). V25: AES-GCM authenticated wrap/unwrap, wrapped
bytes byte-identical across all three transports, unwrapped key material
equal to the original. **Whole remoting workspace green: 40 core + 7
legacy-parity (no regression) + 24 v32-parity (1 still `#[ignore]`d) + 2
posture.** RSA-2048 keygen (2 core tests, 1 parity test) adds real but
modest time to the suite (whole-workspace runs now 1.6–8.4s, driven
mostly by RSA keygen variance) — nowhere near XMSS's 326s, no `#[ignore]`
warranted.

**Ledger**: `AuthWrap` and `GapRsaCipher` now carry real `case_ids` and
updated justifications; `GapAes` gained the AES-GCM cases alongside its
existing AES-ECB ones. Regenerated `REMOTE_P11_V32_COVERAGE.md`. Ratchet
green: 63 categories, 99 RPCs (unchanged — G1 added zero new RPCs, only
new parameter shapes on existing ones).

G2 (Split Key) is next — independent of G1, no ordering dependency.

### 2026-08-26 — G2 (Split Key vendor RPCs)

Shipped, all live-verified. Adds `SplitKey`/`JoinKey` to `Pkcs11V32` —
explicitly labeled a VENDOR EXTENSION in the proto, gRPC, REST, and
ledger, since there is no `CKM_PQCTODAY_SPLIT_KEY` `C_*` dispatch arm
anywhere in the engine to mirror (confirmed again this slice, same
finding as §0). Per the user's locked answer, this is real coverage, not
the `N/A-engine` fallback row.

**Wire shape, exactly as decided**: method + parts + threshold +
optional polynomial in, `repeated {key_part_identifier, object_handle}`
out. `method`/`polynomial` use the KMIP 3.0 §11.54/§11.55 enumeration
codepoints VERBATIM — the same mapping `kmip/src/ops/split_key.rs`'s own
Create/Join Split Key handlers already use (re-derived locally in each
of the three new call sites since those KMIP-crate conversion fns are
private to that crate, not shared — but the codepoints themselves are
identical, so a caller driving both the KMIP and this remoting surface
sees one consistent vocabulary, not two independently-numbered ones).

**core:** new `verbs_v32::split_key` module — the first (and, per §0,
likely only) verb pair in this whole mirror that calls
`softhsmrustv3::native::{split,join}` directly instead of `ffi::C_*`,
because no `C_*` entry point exists for it. Kept the same "(rv, T)"
value-carrying convention as every `ffi::C_*`-backed verb regardless —
`native::split`/`join`'s own `Result<_, CkRv>` (`CkRv = u32 == CK_RV`)
maps onto it directly, so callers don't need to know this verb pair took
a different path internally. 4 new core unit tests (44/44 core green):
XOR split→join round trip; GF(2^8) 5-part/3-threshold split joined with
only a 3-of-5 SUBSET (the actual threshold property — RW4's hybrid test
already established the pattern of testing the meaningful case, not
just a trivial full-set round trip); a below-threshold join rejected
with the real `CKR_ARGUMENTS_BAD`; XOR's `parts == threshold` constraint
(§13.1) rejected when violated; two wire-layer-only checks (undefined
method/polynomial codepoints rejected before any engine call).

**Real finding this slice**: XOR reconstruction (`native::join`'s XOR
arm, itself a thin call to `crypto::split_key::join_xor`) has NO
per-share-count check — it XORs whatever shares it is given, full stop.
The `parts == threshold` invariant for XOR is enforced only at SPLIT
time (§13.1: "[XOR Threshold] SHALL be identical to Split Key Parts");
a JOIN given fewer than the original share count doesn't error, it
silently reconstructs the WRONG secret. This is real, faithfully-mirrored
engine behavior, not a remoting bug — discovered when the acceptance
test's below-threshold assertion (written expecting XOR to reject a
2-of-4 join, mirroring the polynomial methods' behavior) failed with
`rv == 0` on the first live run. Fixed by reading `join_xor`'s source
directly rather than guessing, then rewriting that one assertion to use
the GF256 method (which DOES enforce a real threshold check via
`crypto::split_key::join_gf256`) — the same method the core crate's own
negative test already used for exactly this reason.

**gRPC + REST**: straight handler pairs, no shared-enum ownership
puzzle this time (unlike G1's `MechParamBytes`) — `split`/`join`'s
inputs are plain scalars/bytes/strings, no embedded-pointer native
struct involved. `V32SplitKeyShare` reused as both request and response
element type (proto) and both request and response DTO (REST), keeping
the "shares" shape identical on the way in and out. `join_key` reuses
the pre-existing `V32ObjectHandleResponse`/`ObjectHandleResp` types —
no new response type needed for JoinKey specifically.

**Validation:** V26, a new three-transport parity case. Unlike G1's
V23/V25 (KAT-grade, byte-identical ciphertext across transports), this
is NOT a byte-identical check: XOR sharing draws its shares from
`OsRng` (confirmed by reading `split_xor`'s source), so each transport
produces different share bytes for the same secret by design. V26
instead proves, independently per transport (matching V24's OAEP
precedent for randomized operations): split → join round trip recovers
the exact original secret. Plus a below-threshold negative case (GF256,
for the reason above) proven on control and gRPC with the real error
code compared directly, not just checked non-zero.

**Ledger**: new `SplitKey` row — NOT sourced from
`cpp_compliance_report.json` (this is a vendor capability, not a
pkcs11f.h category), documented anyway per the standing "no record
without proof, but also no unproven claim of scope" principle. `$schema_
note` extended to explain why the ratchet's check (c) — which regexes
for `rpc C_*(` — can never see `SplitKey`/`JoinKey` by construction, so
their absence from that specific count is by design, not a silent gap;
the ledger row is what keeps them from disappearing from view entirely.
Ratchet green: **64 categories, 99 RPCs** (unchanged, exactly as
predicted — `SplitKey`/`JoinKey` are invisible to the `C_*`-only RPC
count by design).

**Whole workspace green, 3 consecutive runs**: 2 posture + 7 legacy-
parity + 26 v32-parity (1 `#[ignore]`d) + 44 core = **78 passed, 0
failed** every time (times ranged 6.7s–13.1s across the three runs,
core-crate RSA-2048 keygen still the dominant variance source, same as
G1's note).

G3+G4 (mechanism-cell sweep + V21 split) is next.
