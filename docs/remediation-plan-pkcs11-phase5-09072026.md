# PKCS#11 — Phase 5 remediation plan (remaining gaps)

**Date:** 2026-09-07
**Branch:** `fix/pkcs11-d2-pkcs8-wire-format` — 41 commits unpushed · PR #226 open, unreviewed
**Governing rule:** v3.2 is the baseline; v3.3 governs where v3.2 has a gap or a plain error (`CLAUDE.md`)
**Inputs:** phase-4 plan (`remediation-plan-pkcs11-phase4-09072026.md`), gap sweep (`pkcs11-v32-vs-v33-gap-sweep-09072026.md`), persistence plan (`remediation-plan-persistence-encoding-09072026.md`)

---

## 0. State

| | Measured |
|---|---|
| Differential harness | **68 scenarios / 12,293 observations / 0 uncovered / PASS** |
| `exceptions.json` | **38 entries, all `status: legal`.** Zero defects outstanding |
| Mechanism ledger | 488 rows · 473 canonical-header mechanisms · C++ 166 advertised, Rust 172, **`cpp_only` empty** |
| C++ ctest | 8/8 · Rust `cargo test` 515/0 · constants gate 0 failures · 0 build warnings |

Every behaviour item from phases 2–4 has landed or been proven unnecessary. What follows is genuinely all that is left, and **two phase-4 items are closed here rather than carried**, because measurement showed there was nothing to do.

### 0.1 Two carried items are void — do not re-open them

**Phase-4 §5 (`CKA_PUBLIC_KEY_INFO` SPKI gaps) is closed.** The seven remaining divergences were described as "no SPKI builder exists for these families". Measured: for all seven — HSS, XMSS, XMSS-MT on both halves, plus the unwrap path — **C++ returns the attribute with length zero**. It is materialising the class-table default empty, exactly as it does for `CKA_ID` and `CKA_LABEL`. Table 27 explicitly permits this (*"MAY be empty"*). Building an SPKI encoder for Rust would **create** a divergence (`cpp len=0` vs `rust len=N`), not close one. Recorded in full on `LEGAL-OPTIONAL-ATTR-PUBLIC-KEY-INFO`.

**Phase-4 §2 (ML-DSA multi-part) is closed** — both engines already permit it and produce verifying signatures; the reported divergence was a truncated `awk` window.

---

## 1. HSS/XMSS multi-part verify via `C_VerifySignatureInit`

**Effort: M. Decided D-2 (implement, overriding my recommendation to defer). The only behaviour change left.**

v3.2's own footnote for the stateful-hash rows restricts *verification*: single-part, **or** multi-part when the `C_VerifySignatureInit` interface is used. v3.3 keeps the same clause. Both engines refuse today.

### 1.1 The phase-4 step list was wrong about C++ — this is not a flag flip

Phase-4 §3 said to "permit multi-part only under `SESSION_OP_VERIFY_SIGNATURE`", implying `SoftHSM_sign.cpp:3207`'s `setAllowMultiPartOp(false)` is the whole obstacle. It is not. Traced:

- `C_VerifyInit` routes `CKM_HSS` / `CKM_XMSS` / `CKM_XMSSMT` to **`StatefulVerifyInit`** (`SoftHSM_sign.cpp:3317`), which is where line 3207 lives.
- `C_VerifySignatureInit` (`:4031`) reuses **`AsymVerifyInit`** (`:2403`) to validate the mechanism and load the key — *not* `StatefulVerifyInit`.

So a stateful mechanism never reaches the pre-bound path at all; it is rejected by `AsymVerifyInit`'s mechanism switch before any flag is consulted. **The work is routing, not a flag.** Flipping line 3207 alone would enable multi-part under plain `C_VerifyInit` — which is exactly what the spec does *not* permit, and the opposite of the intent.

### 1.2 Rust may already accept it — measure before assuming asymmetry

`C_VerifySignatureInit` (`rust/src/ffi.rs:7730`) is **mechanism-agnostic at init**: it checks the key handle, `CKA_VERIFY`, and `CKA_ALLOWED_MECHANISMS`, remaps generic pre-hash mechanisms, then stores `{mech_type, key_handle, signature, msg_acc}` in `VERIFY_SIG_STATE`. There is no mechanism allow-list. Whether `…Update` / `…Final` then reach a stateful verifier is the open question.

Phase 4 asserted "Rust has no such path". That may be false in the same way §0.1's claims were false. **Probe both engines first.**

### 1.3 Steps

1. **Scenario first** (§4.1) — `verify.stateful_multipart_prebound`, recording what both engines do *today*, before either changes.
2. **C++:** route the three stateful mechanisms through `C_VerifySignatureInit` to a stateful-aware init that sets `allowMultiPartOp = true`; accumulate into `msgBuffer`; assemble and call the existing one-shot verifier at Final. `StatefulVerifyInit`'s `false` stays untouched — plain `C_VerifyInit` must keep refusing.
3. **Rust:** whatever §1.2 measures. If it already works, that is the phase-4 §2 outcome again — record it and move on.
4. Assert the **negative**: `C_VerifyInit` + `C_VerifyUpdate` on `CKM_HSS` must still fail on both engines. A permissive implementation passes any positive-only test.

**Risk:** the assembled input for these verifiers is `[signature || message]`, which is why the pre-bound interface is the one the spec permits. Getting the assembly order wrong yields a verifier that rejects everything — visible — or, worse, one that accepts on a truncated message. Test a tampered final chunk.

---

## 2. Pin the mechanism-info ranges in the ledger

**Effort: S. Closes a known, self-documented hole in the harness.**

`LEGAL-MECHANISM-INFO-KEY-SIZE-RANGES` excuses 86 mechanisms' `ulMinKeySize`/`ulMaxKeySize` differences by **path, not value** — its own text records the consequence: *"a FUTURE change to either engine's ranges is also excused"*. That is how `CKM_AES_CMAC` advertised a 64-byte maximum in Rust against C++'s 32 for weeks.

Ledger rows today carry `{value, cpp, rust}` (488 rows, `docs/pkcs11-mechanism-ledger.json`). Add `cpp_min` / `cpp_max` / `rust_min` / `rust_max`, populated from the harness's own `env.mechanism_info_all` output rather than a hand-copied table, so a change shows as a reviewable diff. Then narrow the exception to *"differences are policy; the values are pinned in the ledger"*.

**Do not narrow the exception before the ledger checker actually fails on a changed value** — sabotage-test it on a copy of the tree. An exception narrowed against a check that cannot fail is worse than the exception it replaced.

---

## 3. `CK_ULONG` 32-bit cap — the one real audit finding

**Effort: S to fix, but it needs a decision first.**

v3.3 (`introduction.md:303`) caps every `CK_ULONG` at `0x7FFFFFFF`. C++ defines:

```c
// SoftHSMHelpers.h:47
static constexpr CK_ULONG UNLIMITED_KEY_SIZE = 0x80000000UL;   // 2^31 — one over the cap
```

reported as `ulMaxKeySize` at five sites in `SoftHSM_slots.cpp` (`:1023, :1092, :1101, :1126, :1131`), all AES key-wrap mechanisms. Rust reports 16–32 for the same mechanisms, reading "key size" as the wrapping AES key rather than the payload.

v3.2 does not state the cap, so this is a v3.3 gap-fill under the standing rule. Three ways out, and they are not equivalent:

| Option | Effect |
|---|---|
| **A** — `0x7FFFFFFF` | Minimal, keeps C++'s "payload size" reading, satisfies the cap. **Recommended.** |
| **B** — adopt Rust's reading (16/32) | Removes a real cross-engine disagreement, but changes what C++ advertises about a mechanism it has advertised for years |
| **C** — leave it | The value is one over a cap only an unpublished draft states, and no caller has complained |

Sequenced **after §2**, so whichever value is chosen is pinned by the ledger the same day it changes.

---

## 4. Harness

### 4.1 Scenarios

- `verify.stateful_multipart_prebound` — §1.1, **before** any engine change.
- Non-storage object creation (§5.1) — assert both engines refuse `CKO_VALIDATION` / `CKO_PROFILE` / `CKO_MECHANISM` from `C_CreateObject`. The code exists on both sides; nothing proves they agree on the **return code**.

### 4.2 The gate's stale-engine false green *(carried from phase-4 §8.3 — still open)*

`--javajce` runs `mvn` against the container's installed `/usr/local/lib/softhsm/libsofthsmv3.so`, dated **2026-09-01**. It validates today's Java against a week-old native engine and stays green as the two drift. Commit `d0c0b280` fixed this for one step; confirm it covers the whole `--javajce` path before the landing gate is trusted.

---

## 5. Record-only — audits that came back closed

These were carried as open questions. Both are already answered by the code; they need a line in the record, not a change.

### 5.1 Non-storage classification — **already implemented on both engines**

v3.3 `object_classification.md` makes `CKO_VALIDATION` / `CKO_PROFILE` / `CKO_MECHANISM` non-storage. Both engines already refuse to create them:

- C++ `SoftHSM_objects.cpp:1204-1215` — with `CKO_VALIDATION` called out as the sharpest case
- Rust `ffi.rs:5569-5584` — the same four classes, same reasoning

C++'s note there is dated 2026-09-07, so this landed inside this programme. Only §4.1's scenario is outstanding, to prove the two agree on the return code.

### 5.2 `CKA_OBJECT_VALIDATION_FLAGS` footnote 12 — **record-only, as predicted**

D-3 decided to follow v3.3 and drop the read-only latch, with the caveat *"check what the engines do first: if neither implements the latch this is a record-only change"*. Checked: `CKA_OBJECT_VALIDATION_FLAGS` appears **once in the entire tree**, at `src/lib/pkcs11/pkcs11t.h:645` — the constant definition. Zero hits in `src/lib/*.cpp` or `rust/src/`. Neither engine implements the attribute, so neither implements the latch. **No code. Record the decision and close it.**

---

## 6. Comment-staleness sweep — the H2 defect class, now twice-burned

**Effort: M. No behaviour change, and the highest-value item on this list.**

H2 swept the `justification` prose in `exceptions.json` for claims about code. **Code comments were never swept**, and they are the same hazard: a spec citation is wrong from the day it is written, but a code claim starts true and decays silently.

It has cost real work twice today:

- `ffi.rs:353` claimed the Rust snapshot was plaintext at rest — false since `crate::store` landed. It produced a wrong finding, a wrong urgency, and a half-built duplicate key hierarchy (a second KEK and wrap/unwrap parallel to one that already existed and was better).
- `LEGAL-USAGE-FLAG-DEFAULT-RECOVER` claimed C3 removed a recovery path that is fully implemented.

Scale, measured:

| Where | Cross-engine claims |
|---|---|
| `rust/src/**` | **144** |
| — of which `rust/src/ffi.rs` | 51 |
| `src/lib/**` | 13 |

**Prioritise claims about the *other* engine.** A comment describing its own function is checked by every reader of that function; a comment asserting what the C++ engine does, sitting in Rust, is checked by nobody and rots fastest. That is precisely the shape of both failures above.

Method: for each claim, open the file it describes and confirm or correct **in place**. Deleting a stale claim is acceptable; leaving it is not. Do not batch-rewrite — each one is a separate factual check.

---

## 7. Upstream TC list — record in the repo

**Effort: S, no code.** D-4: record it; sending stays your call. No such document exists yet.

Create `docs/pkcs11-v33-upstream-questions-09072026.md` from phase-4 §10, each item citing `file:line` plus the snapshot commit `2b25dd8`:

1. Why were the FIPS 186-4 subsections deleted? (We keep the v3.2 constraints.)
2. `CK_MU_GEN_PARAMS` (`ml_dsa.md:119-130`) — trailing comma on the first member; does not compile.
3. `comp_kem.md:96` — private key objects said to hold `CKK_ML_KEM`; should be `CKK_COMP_KEM`.
4. `aes.md` — mechanism table says `CKM_AES_EC`; definitions and prose say `CKM_AES_ECB`.
5. `slh-dsa.md:85,87` — v3.2's copy/paste bug carried forward: `CKP_SLH_DSA_SHAKE_256S` twice, `..._256F` missing.
6. `elliptic_curves.md:992` — dangling `^1^` whose footnote text exists nowhere in the snapshot.
7. `CKO_MECHANISM`'s two new attributes have no allocated value, even in the draft's own header.
8. `CKA_OBJECT_VALIDATION_FLAGS` footnote 12 — deliberate erratum or editing slip?

---

## 8. wasm snapshot threat model

**Effort: S, document only.** This is the narrowed remainder of the void P-1.

Both native stores are encrypted at rest (C++ `SecureDataManager`; Rust `crate::store` — per-token AES-256 master key, wrapped under both PINs, PBKDF2-HMAC-SHA256 at 210,000 iterations, AES-256-GCM). The **wasm/emscripten snapshot blob** (`SHR3SNP2`, `state_snapshot.rs`) is plaintext.

That is a different target and a different threat model — the host already holds the blob, there is no filesystem in the browser case, and on native it is reachable only through an opt-in `SOFTHSMRUST_STATE_FILE`. Write it down as a deliberate scope boundary with the reasoning above, so the next reader does not rediscover it as a finding. **No code.**

---

## 9. Deferred behind the landing

**Persistence interchange format, phases 2–5** (`remediation-plan-persistence-encoding-09072026.md`). Decided 2026-09-07: the format work waits until the PKCS#11 queue is finished and this branch has landed. P-2 (interchange, each engine keeps its own store) and P-4 (when C++ adopts it, it *replaces* the SoftHSM2 store) together make a token converter and `softhsm2-util` support **blocking** at that point, not follow-up.

---

## 10. Sequencing

1. **§4.1 scenarios** — before any engine change.
2. **§1** HSS/XMSS multi-part verify — the only behaviour item; measure Rust before assuming asymmetry.
3. **§2** ledger range pinning, then **§3** `CK_ULONG` cap — in that order, so the new value is pinned as it changes.
4. **§6** comment sweep — no behaviour risk, runs alongside anything.
5. **§5, §7, §8** record-only — any time; none blocks code.
6. **§4.2**, then the landing gate.

---

## 11. Verification standard (unchanged, plus one addition)

- A regression test that **fails on the pre-fix binary**.
- Assert against an **independent** oracle, never the engine against itself.
- Every `exceptions.json` edit quotes the sentence it relies on, with `file:line` — and, since phase 3, the same applies to claims about *code*.
- **When in doubt, read BOTH specs.** v3.2 alone would have had us signing HSS/XMSS over a pre-computed hash; v3.3 alone would have had us dropping the FIPS 186-4 constraints on the authority of an unpublished draft.
- Section and table numbers come from `docs/refs/pkcs11-spec-v3.2-os.pdf`. Quote v3.3 by `file:line` plus the snapshot commit.
- Sabotage-test any new gate check on a **copy** of the tree.
- **Read the engines before reasoning from the spec alone.**
- **When a grep defines the finding, show the whole range.** A truncated window is indistinguishable from an absence — added after §0.1's phantom ML-DSA divergence.
- **NEW: a comment is not evidence.** Phase-4 §5 and the persistence P-1 were both built on prose that was true when written. Verify the code the comment describes, then cite the code — this is §6's rationale and the reason it ranks where it does.

---

## 12. Landing

Unchanged: **PR #226 is reviewed and merged first**, then one PR for the phase-2/3/4/5 work on top. 41 commits unpushed. Nothing is pushed without explicit confirmation.

Before proposing a push: `bash scripts/local-gate.sh --cpp --javajce --openssl-provider`, with `AG_CONTAINER_ROOT=/ag/pqctoday-hsm/.worktrees/pkcs11-d2` set on **every** run. Note §4.2 — until that is confirmed, the JavaJCE step's green is weaker than it looks.

---

## 13. Decisions requested

| Ref | Question | Recommendation |
|---|---|---|
| **E-1** | §3 — which reading for `UNLIMITED_KEY_SIZE`? | **Option A** (`0x7FFFFFFF`). Satisfies the cap, keeps C++'s long-standing "payload size" reading, one-line change. Option B is more correct but changes an advertised capability on the authority of a draft. |
| **E-2** | §6 — sweep all 157 cross-engine claims, or only the 51 in `ffi.rs`? | **All 157.** The two failures today were both in Rust, but the 13 in `src/lib` are the same class and the total is small enough to finish. |
| **E-3** | §1 — if Rust's `C_VerifySignatureInit` already handles the stateful mechanisms, do we still change C++? | **Yes.** A divergence where Rust is right and C++ refuses is still a divergence, and C++'s refusal is the non-conformant half. |
| **E-4** | Does anything here block the landing, or do §5/§7/§8 (record-only) land with it? | Land the record-only items **with** the branch. They are documentation of decisions already taken; holding them back leaves the record incomplete for a reviewer. |

---

## 14. Decisions taken (2026-09-07)

| Ref | Decision | Note |
|---|---|---|
| **E-1** | **Adopt Rust's reading** of `ulMaxKeySize` | *Overrides the recommendation to clamp to `0x7FFFFFFF`.* "Key size" means the key the mechanism uses, not the payload it may process. See §14.1 — the decision applies cleanly to two of the five sites and needs one follow-up for the rest |
| **E-2** | Sweep **all 157** cross-engine comment claims | Default taken; `src/lib`'s 13 are the same defect class |
| **E-3** | **Fix C++ regardless** of what Rust turns out to do | Default taken; C++'s refusal is the non-conformant half either way |
| **E-4** | Record-only items (§5, §7, §8) **land with the branch** | Default taken; a reviewer should see the reasoning alongside the code |

### 14.1 Correction — the five sites are not "the AES key-wrap mechanisms"

E-1 was posed on my description of the five `UNLIMITED_KEY_SIZE` sites as "all AES key-wrap mechanisms". **That is wrong**, and I inherited it from `LEGAL-MECHANISM-INFO-KEY-SIZE-RANGES`, which says the same thing. Only two of the five are. Read from `SoftHSM_slots.cpp` against `ffi.rs:1503-1558`:

| Mechanism | C++ today | Rust today | Does E-1's rationale apply? |
|---|---|---|---|
| `CKM_AES_KEY_WRAP` (`:1092`) | 16 – 2³¹ | 16 – 32 | **Yes.** The payload-vs-key ambiguity is exactly here |
| `CKM_AES_KEY_WRAP_PAD` / `_KWP` (`:1101`) | 1 – 2³¹ | 16 – 32 | **Yes.** Same construction (RFC 5649) |
| `CKM_GENERIC_SECRET_KEY_GEN` (`:1023`) | 1 – 2³¹ | 1 – 512 | **No.** There is no ambiguity — the value *is* the size of the secret generated. Adopting 512 would make C++ under-advertise a capability it has |
| `CKM_KMAC_128` (`:1126`) | 16 – 2³¹ | 16 – 64 | **No.** SP 800-185 places no upper bound on a KMAC key; 64 is Rust's own policy, not a reading of the spec |
| `CKM_KMAC_256` (`:1131`) | 32 – 2³¹ | 16 – 64 | **No**, and note the minimum also differs (32 vs 16) |

So E-1 as decided resolves the two key-wrap rows to `16 – 32`. The other three are a **different question**: they have no payload-vs-key ambiguity, and their maximum is genuinely "unbounded" in the sense C++ means it. For those, the choice is between clamping to `0x7FFFFFFF` (truthful, satisfies the cap) and adopting Rust's policy ceilings (closes the divergence, but under-advertises).

**E-1a is open.** Nothing changes on those three rows until it is answered. The two key-wrap rows proceed as decided.

This is the same failure the plan's own verification standard warns about — I described a set of code sites from a summary (the exception's prose) instead of reading them, and posed a decision on the description. The exception text needs the same correction.
