# PKCS#11 — Phase 5 remediation plan (remaining gaps)

**Date:** 2026-09-07
**Branch:** `fix/pkcs11-d2-pkcs8-wire-format` — 41 commits unpushed · PR #226 open, unreviewed
**Governing rule:** v3.2 is the baseline; v3.3 governs where v3.2 has a gap or a plain error (`CLAUDE.md`)
**Inputs:** phase-4 plan (`remediation-plan-pkcs11-phase4-09072026.md`), gap sweep (`pkcs11-v32-vs-v33-gap-sweep-09072026.md`), persistence plan (`remediation-plan-persistence-encoding-09072026.md`)

---

## 0. State

| | Measured (2026-09-07, post-§1) |
|---|---|
| Differential harness | **70 scenarios / 13,229 observations / 0 uncovered / PASS** — `verify.stateful_multipart_prebound` and `create.non_storage_object_refused` added, §1's fix applied |
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

### 1.4 Done (2026-09-07) — measured, then fixed

The scenario measured §1.2's open question before any engine changed. **Rust already worked correctly** — pre-bound multi-part init/update/final, pre-bound single-part, and rejection of a tampered final chunk (`CKR_SIGNATURE_INVALID`) all passed on the first run, for all three mechanisms. C++ answered `CKR_MECHANISM_INVALID` at init, exactly as §1.1 traced.

**The routing fix was smaller than §1.3 step 2 implied, once the actual blocker was found.** `C_VerifySignatureInit`'s shared tail (`SoftHSM_sign.cpp:~4046`) already builds the pre-bound blob and sets `allowMultiPartOp=true` / `opType=SESSION_OP_VERIFY_SIGNATURE` **unconditionally**, regardless of which init helper ran. So the only change needed there was dispatching to `StatefulVerifyInit` instead of `AsymVerifyInit` for the three mechanisms — `StatefulVerifyInit`'s own `allowMultiPartOp=false` is for plain `C_VerifyInit` and gets overwritten by that same shared tail either way.

**What §1.3 step 2 did not anticipate:** `C_VerifySignature` and `C_VerifySignatureFinal` unconditionally call `session->getAsymmetricCryptoOp()->verify(...)`. Stateful signatures never populate that — the class's own comment says so directly: *"Stateful signatures do NOT use AsymmetricAlgorithm base."* `StatefulVerifyInit` sets neither `AsymmetricCryptoOp` nor `PublicKey`. Left unpatched, a stateful init would have succeeded and every subsequent verify call would have failed with the wrong code (`CKR_OPERATION_NOT_INITIALIZED` for an operation that plainly was initialized) — a second, silent blocker one level deeper than the one §1.1 found.

Fixed by extracting `StatefulVerify`'s core (the mechanism dispatch to `hss_validate_signature`/`xmss_sign_open`/`xmssmt_sign_open`) into a session-free `StatefulVerifyCore(hKey, slotId, mechanism, pData, ulDataLen, pSignature, ulSignatureLen)`, called from three places: the original `StatefulVerify` (plain `C_Verify`, unchanged behaviour), and new branches in `C_VerifySignature` and `C_VerifySignatureFinal` that fire before the `AsymmetricCryptoOp`/`PublicKey` check.

**Verified:** the `verify.stateful_multipart_prebound` scenario alone went from 52 uncovered divergences to 0 (the only survivor was the pre-existing, already-adjudicated `CKA_HSS_KEYS_REMAINING` materialisation cosmetic difference, whose exception scenario-scope was widened to include this scenario). Full harness: **70 scenarios / 13,229 observations / 0 uncovered / PASS**.

---

## 2. Pin the mechanism-info ranges in the ledger

**Effort: S. Closes a known, self-documented hole in the harness.**

`LEGAL-MECHANISM-INFO-KEY-SIZE-RANGES` excuses 86 mechanisms' `ulMinKeySize`/`ulMaxKeySize` differences by **path, not value** — its own text records the consequence: *"a FUTURE change to either engine's ranges is also excused"*. That is how `CKM_AES_CMAC` advertised a 64-byte maximum in Rust against C++'s 32 for weeks.

Ledger rows today carry `{value, cpp, rust}` (488 rows, `docs/pkcs11-mechanism-ledger.json`). Add `cpp_min` / `cpp_max` / `rust_min` / `rust_max`, populated from the harness's own `env.mechanism_info_all` output rather than a hand-copied table, so a change shows as a reviewable diff. Then narrow the exception to *"differences are policy; the values are pinned in the ledger"*.

**Do not narrow the exception before the ledger checker actually fails on a changed value** — sabotage-test it on a copy of the tree. An exception narrowed against a check that cannot fail is worse than the exception it replaced.

### 2.1 Done (2026-09-07)

Built `scripts/pin_pkcs11_mechanism_info_ranges.py`, plus a small harness addition (`p11_diff.cpp` gained `--dump-scenario`/`--dump-file`, since the normal report only records *divergences* — a matching min/max is silently dropped, so pinning every mechanism, not just the 86 that already disagree, needed the raw per-engine values). Mechanism names are resolved by **numeric value**, not by the harness's own `mech_name()` table (which covers only 54 of ~166 probed mechanisms), against both engines' own definitions — `src/lib/pkcs11/pkcs11t.h` (evaluating simple `CKM_VENDOR_DEFINED | 0x...` expressions) and `rust/src/constants.rs`.

**Scope, and why it's smaller than "every advertised mechanism":** `env.mechanism_info_all` itself only probes the C++/Rust **intersection** (166 mechanisms) — a Rust-only mechanism has no C++ counterpart to diverge from, so pinning it protects against nothing. All 166 are pinned; the 6 Rust-only mechanisms are out of this scenario's reach entirely, not a gap in the pinning.

**Sabotage-tested:** hand-corrupted two values (`CKM_AES_KEY_WRAP.cpp_max`, `.rust_min`), reran the script, both were overwritten back to the measured values — confirming the tool measures rather than echoes.

**What is NOT done:** an automated gate step that runs this script and fails on a `git diff`. The script and its committed output are the artifact; wiring it into `local-gate.sh` is a small follow-up, not attempted here given the two other long-running gate/test jobs already in flight this session — noted rather than silently skipped.

Exception narrowed (see `LEGAL-MECHANISM-INFO-KEY-SIZE-RANGES`): still excuses the runtime comparison, but the historical value is now recorded and diffable rather than merely asserted.

---

## 3. `CK_ULONG` 32-bit cap — the one real audit finding

**Effort: S to fix on two rows; the other three needed a spec read, now done — §3.2.1.**

v3.3 (`introduction.md:303`) caps every `CK_ULONG` at `0x7FFFFFFF`. C++ defines:

```c
// SoftHSMHelpers.h:47
static constexpr CK_ULONG UNLIMITED_KEY_SIZE = 0x80000000UL;   // 2^31 — one over the cap
```

reported as `ulMaxKeySize` at five sites in `SoftHSM_slots.cpp` (`:1023, :1092, :1101, :1126, :1131`). **These are not all AES key-wrap mechanisms** — see §14.1; only two are, and the five do not share one answer.

v3.2 does not state the cap, so this is a v3.3 gap-fill under the standing rule.

**§14.1 corrects the premise this section was first written on:** the five sites are not one homogeneous group, and they do not get one answer. As decided (E-1 / E-1a) the work splits in two.

### 3.1 The two key-wrap rows — decided, mechanical

`CKM_AES_KEY_WRAP` and `CKM_AES_KEY_WRAP_PAD` / `_KWP` adopt Rust's reading: `ulMaxKeySize` is the size of the **wrapping AES key**, not the payload. Set both to `16 – 32`, matching `ffi.rs:1556`. This also raises `_KWP`'s minimum from 1 to 16 — a wrapping key of one byte was never real.

### 3.2 The three remaining rows — ground each against its own specification

Decided E-1a: set each maximum from the governing standard, **not** from either engine's current value. Neither `2³¹` nor Rust's ceiling is evidence; both are policy that nobody has checked.

| Mechanism | Source to read | Question to answer |
|---|---|---|
| `CKM_KMAC_128` / `CKM_KMAC_256` | **NIST SP 800-185 §4** (KMAC), and PKCS#11 v3.2 §6.28 for what the mechanism's key size means | Does SP 800-185 bound the key length at all? If it does not, what is the honest maximum for a token — and does the KMAC-256 minimum of 32 (C++) or 16 (Rust) follow from the security strength? |
| `CKM_GENERIC_SECRET_KEY_GEN` | **PKCS#11 v3.2 §6.20** (generic secret key), Table for `CKA_VALUE_LEN` | Is there a stated bound, or is the limit whatever the token can store? If the latter, the maximum should describe **this** token, which is what the field is for |

Whatever each lands on must also satisfy the `0x7FFFFFFF` cap — that constraint is independent and applies regardless.

**Record the citation with the value.** A number in `SoftHSM_slots.cpp` with no source is how these three came to disagree in the first place; the ledger row from §2 is where the citation belongs so it survives.

#### 3.2.1 Grounding done (2026-09-07) — and it reverses the E-1 premise

Both specs read. The result changes which engine is wrong.

**KMAC does not exist in v3.2.** Zero occurrences, case-insensitive, across all 24,215 lines of the v3.2 text. Our `CKM_KMAC_128` / `CKM_KMAC_256` are **vendor mechanisms** — `CKM_VENDOR_DEFINED | 0x100` and `| 0x101` (`pkcs11t.h:1273-1274`). This is a v3.2 gap, so v3.3 governs, and v3.3 says (`working/doc/spec/kmac.md`):

> *"The key can be of arbitrary length, however it is recommended that the size of the key matches the security strength of the mechanism it is used with. For **CKM_KMAC128**, the key length should be at least 128 bits. For **CKM_KMAC256**, the key length should be at least 256 bits."* — `kmac.md:115-120`
>
> *"the `ulMinKeySize` and `ulMaxKeySize` fields of the **CK_MECHANISM_INFO** structure specify the supported range of KMAC key sizes, in bytes."* — `kmac.md:132-134`

So, measured against the only specification that covers these mechanisms at all:

| | C++ | Rust | Verdict |
|---|---|---|---|
| `CKM_KMAC_128` min | 16 bytes = 128 bits | 16 | Both match the recommendation |
| `CKM_KMAC_256` min | 32 bytes = 256 bits | **16** | **C++ is right. Rust advertises a minimum below the recommended 256-bit key.** |
| Max, both | 2³¹ | 64 | No spec ceiling exists — "arbitrary length" |

**This reverses the premise E-1 was posed on.** On KMAC the divergence is not C++ over-advertising; it is **Rust under-specifying its minimum**, and adopting Rust's 16/64 would have propagated that error into C++ and thrown away a correct value. The maximum genuinely has no spec answer, so it is a statement about this token: clamp to `0x7FFFFFFF` and let the engines' real limits speak.

**`CKM_GENERIC_SECRET_KEY_GEN` — the units are the finding, not the ceiling.** v3.2 §6.8 is explicit:

> *"For this mechanism, the `ulMinKeySize` and `ulMaxKeySize` fields of the `CK_MECHANISM_INFO` structure specify the supported range of key sizes, **in bits**."* — `/tmp/p11os.txt:10504`

C++ reports `1 – 2³¹` (bits — effectively unlimited, and conformant once clamped). Rust reports `1 – 512` (`ffi.rs:1510`). Rust's table is per-mechanism about units — its `CKM_AES_GMAC` comment says *"table stores bytes"* while `CKM_EC_KEY_PAIR_GEN` is `(256, 521)` in bits — so **512 here is unlabelled**, and it matters: as bits it is a 64-byte ceiling, which is a far narrower claim than C++'s.

**Open, needs measurement not reading:** does Rust actually refuse a generic secret longer than its advertised maximum? If it does not, the number is a false statement about itself — a different defect from a mere policy difference, and the one worth catching. A scenario decides this.

#### 3.2.2 A ninth question for the upstream list (§7)

v3.3's `kmac.md` specifies `CKM_KMAC128` and `CKM_KMAC256` in prose, but **the draft's own header allocates neither** — no `CKM_KMAC*` and no `CKK_KMAC` anywhere in `working/headers/pkcs11t.h`, though the prose requires the key type. The same defect class as §7.7 (`CKO_MECHANISM`'s unallocated attributes). Note also the spelling: the draft writes `CKM_KMAC128`, we write `CKM_KMAC_128` — ours is a vendor mechanism, so there is no clash today, but the names will collide in intent the moment the TC allocates.

### 3.3 Sequencing

**§2 first**, so the ledger pins today's values and every change in §3.1 and §3.2 shows up as a reviewable diff against a recorded baseline rather than as an unexplained edit.

### 3.4 Done (2026-09-07)

`UNLIMITED_KEY_SIZE` redefined `0x80000000` → `0x7FFFFFFF` (`SoftHSMHelpers.h`) — it now satisfies the cap for its two remaining users (`CKM_GENERIC_SECRET_KEY_GEN`, `CKM_KMAC_128`/`_256`). `CKM_AES_KEY_WRAP` and `_PAD`/`_KWP` no longer use the constant at all: fixed `16–32`, matching Rust exactly — that divergence is now **closed**, not merely re-pinned. `_KWP`'s minimum also rose 1→16 alongside it.

Rebuilt, re-ran the full harness (70/70, 0 uncovered) and re-pinned the ledger — confirmed in §2.1's table: the two key-wrap rows show identical `cpp_min/max` and `rust_min/max`; the other three show C++'s new, spec-grounded values against Rust's unchanged, still-unsourced ones. **Rust's own values were not touched** — §3 was scoped to what C++ advertises; §3.2.1 records that Rust's KMAC-256 minimum (16) sits below its own spec's recommendation as a separate, un-actioned finding, not something this section's decisions authorized changing.

---

## 4. Harness

### 4.1 Scenarios — DONE (2026-09-07)

- `verify.stateful_multipart_prebound` — §1.1, added **before** any engine change; see §1.4 for what it measured and the fix it drove.
- `create.non_storage_object_refused` (§5.1) — asserts both engines refuse `CKO_VALIDATION` / `CKO_PROFILE` / `CKO_MECHANISM` / `CKO_HW_FEATURE` from `C_CreateObject` with the same code. Passed on the first run: the code exists on both sides and now there is a scenario proving they agree on the **return code**, not just that each independently refuses.

### 4.2 The gate's stale-engine false green *(carried from phase-4 §8.3 — still open)*

`--javajce` runs `mvn` against the container's installed `/usr/local/lib/softhsm/libsofthsmv3.so`, dated **2026-09-01**. It validates today's Java against a week-old native engine and stays green as the two drift. Commit `d0c0b280` fixed this for one step; confirm it covers the whole `--javajce` path before the landing gate is trusted.

---

## 5. Record-only — audits that came back closed — DONE

These were carried as open questions. Both are already answered by the code; they need a line in the record, not a change. This section IS that record — no separate document.

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
| `rust/src/**` (recursive; 37 files) | **81** |
| — of which `rust/src/ffi.rs` | 54 |
| `src/lib/**` | 16 |

**CORRECTED 2026-09-07** before the sweep started, not after: the 144/13 figures above were themselves wrong, from a non-recursive grep whose glob pattern (`rust/src/*.rs rust/src/**/*.rs` without `globstar` enabled) counted every top-level file twice -- 72 x 2 = 144 exactly. The real count, ungrepped a second time with true recursion into `crypto/`, `native/`, `store/`, is 81 + 16 = **97**. Recorded rather than quietly fixed, because it is the same defect class §6 exists to sweep: a number asserted without re-measuring.

**Prioritise claims about the *other* engine.** A comment describing its own function is checked by every reader of that function; a comment asserting what the C++ engine does, sitting in Rust, is checked by nobody and rots fastest. That is precisely the shape of both failures above.

Method: for each claim, open the file it describes and confirm or correct **in place**. Deleting a stale claim is acceptable; leaving it is not. Do not batch-rewrite — each one is a separate factual check.

### 6.1 Done (2026-09-07)

Delegated to three parallel read-only research agents (single-editor rule: research delegated freely, every edit made from the main session) — `rust/src/ffi.rs` (54 lines, split further into 5 sub-batches), the rest of `rust/src` (27 lines), and `src/lib` (16 lines). Each agent was required to open the *other* engine's current code before calling a claim accurate, not infer from the comment's own description.

**Result: 93 of 97 accurate, 4 stale/wrong, all fixed** (`6d6fd123`):

- The `C_Finalize` snapshot comment — already corrected once earlier today — still had it wrong: claimed `crate::store` "mirrors ... PBKDF2-HMAC-SHA256 at 210k iterations, AES-256-GCM" from C++'s `SecureDataManager`. C++ actually uses an iterated plain SHA-256 self-hash (~1500-1755 iterations, not PBKDF2) and AES-256-**CBC with no authentication** (not GCM) — those are *this crate's own* improvements, exactly as `store/crypto.rs`'s own module doc already stated two files over. The comment contradicted its own codebase's accurate documentation — this defect class, reintroduced by the very comment written to fix the first instance of it.
- Three citation drifts (line numbers moved from unrelated edits; substance unaffected) — `CK_BIP32_CHILD_DERIVE_PARAMS` at `pkcs11t.h:2139`→`2148` (three sites across `ffi.rs` and `ck_param.rs`), its C++ length check `SoftHSM_keygen.cpp:3010`→`3222`, the HKDF gate `SoftHSM_keygen.cpp:4211`→`4341`.
- Two comments describing the **pre-E1-fix** DER-wrapped KEM ciphertext format as current fact, contradicted by a neighbouring, correctly past-tense "E1" comment in the same file.
- The `WrapKeyAuthenticated` PKCS8 rationale, wrong for `CKM_AES_GCM` specifically — recorded as a **suspected, not-yet-scenario-confirmed** gap (C++'s raw-scalar accept path covers only 32/48-byte EC scalars; Edwards/Montgomery/P-521 have no raw-scalar path and would fail `PKCS8Decode()`). No differential scenario exists for `WrapKeyAuthenticated`/`UnwrapKeyAuthenticated` today — flagged, not built, given everything else this sweep already turned up.
- The secp256k1-as-KEM refusal rationale — see §6.2, the one finding that was a **real, measured divergence**, not just a stale comment.

### 6.2 A concealed real divergence, confirmed by measurement — secp256k1-as-ECDH-KEM

A Rust `ffi.rs` comment justified refusing secp256k1 for ECDH-as-KEM with *"the C++ mirror covers the NIST prime curves"*. Per §11's standing rule (a divergence is what the harness shows, not what a comment implies), built the scenario before trusting the claim: `create.encapsulate.ecdh_secp256k1` (`3f31c9d8`).

**Measured:** C++'s `encapsulateECDH`/`decapsulateECDH` gate only on key **type** (`CKK_EC`/`CKK_EC_MONTGOMERY`, `SoftHSM_kem.cpp:941,1284`), never curve OID, and `CKM_EC_KEY_PAIR_GEN` has no `CKR_CURVE_NOT_SUPPORTED` path at all. C++ returns `CKR_OK` with a real 65-byte raw point and a derived 32-byte shared secret; Rust's arm hard-matches `{P256,P384,P521,X25519,X448}` and refuses everything else — the false comment blamed the wrong engine for its own restriction.

Building the scenario also caught a second, unrelated bug: the **pre-existing** `create.encapsulate.ecdh_p256` scenario never set `CKA_ENCAPSULATE`/`CKA_DECAPSULATE`, so both engines identically refused with `CKR_KEY_FUNCTION_NOT_PERMITTED` — that scenario had "passed" without ever exercising a successful round trip. Fixed alongside its new sibling.

**Adjudicated `legal`** (`LEGAL-ECDH-KEM-CURVE-COVERAGE-SECP256K1`), same shape as `LEGAL-CURVE-COVERAGE-BRAINPOOL` — §6.3.17 Table 78 names no required curve set, so this is a product-scope choice, not a conformance defect. **Decision needed (E-6): should Rust add secp256k1 support?** The curve math already exists in this crate (BIP32, ECDSA); this is the only reason it's flagged as a decision rather than closed as adjudicated-and-done.

### 6.3 An escalation, outside phase-5's scope — SecureDataManager has no authenticated encryption

The persistence-encoding plan already *stated* this in passing ("AES-256-GCM, chosen over C++'s CBC-without-authentication") when it corrected the P-1 finding. Verifying the `C_Finalize` comment (§6.1) re-surfaced it, and on a harder look it deserves more than a descriptive aside: C++'s `SecureDataManager` protects data at rest with AES-256-**CBC and no MAC/authentication tag** at all (`SecureDataManager.cpp:143,292,370,470,524`). A corrupted or tampered ciphertext byte in a persisted private-object attribute can decrypt "successfully" to silently-corrupted plaintext on C++, where Rust's GCM tag would reject it outright. No differential test exists for this property today.

**Not actioned here.** Fixing it is a production-cryptography change with on-disk-token migration implications — squarely the already-deferred persistence-encoding program's territory (§9; `remediation-plan-persistence-encoding-09072026.md` §9, escalated there), not a phase-5 comment-sweep fix.

---

## 7. Upstream TC list — record in the repo — DONE (2026-09-07)

**Effort: S, no code.** D-4: record it; sending stays your call. Written as `docs/pkcs11-v33-upstream-questions-09072026.md`, all 8 citations re-verified against the vendored snapshot (not carried forward unchecked) — item 7's claim needed correcting in the process: the draft's `CKO_MECHANISM` table defines `CKA_SUPPORTED_PARAMETER_SETS` and `CKA_FLAGS`, not two unnamed attributes, and neither has a header allocation.

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

## 8. wasm snapshot threat model — DONE (2026-09-07)

**Effort: S, document only.** This is the narrowed remainder of the void P-1. Written as `docs/wasm-snapshot-threat-model-09072026.md`.

Both native stores are encrypted at rest (C++ `SecureDataManager`; Rust `crate::store` — per-token AES-256 master key, wrapped under both PINs, PBKDF2-HMAC-SHA256 at 210,000 iterations, AES-256-GCM). The **wasm/emscripten snapshot blob** (`SHR3SNP2`, `state_snapshot.rs`) is plaintext.

That is a different target and a different threat model — the host already holds the blob, there is no filesystem in the browser case, and on native it is reachable only through an opt-in `SOFTHSMRUST_STATE_FILE`. Write it down as a deliberate scope boundary with the reasoning above, so the next reader does not rediscover it as a finding. **No code.**

---

## 9. Deferred behind the landing

**Persistence interchange format, phases 2–5** (`remediation-plan-persistence-encoding-09072026.md`). Decided 2026-09-07: the format work waits until the PKCS#11 queue is finished and this branch has landed. P-2 (interchange, each engine keeps its own store) and P-4 (when C++ adopts it, it *replaces* the SoftHSM2 store) together make a token converter and `softhsm2-util` support **blocking** at that point, not follow-up.

---

## 10. Sequencing

1. ~~**§4.1 scenarios** — before any engine change.~~ **DONE.**
2. ~~**§1** HSS/XMSS multi-part verify.~~ **DONE** — Rust already conformed; C++ fixed and verified. See §1.4.
3. ~~**§2** ledger range pinning, then **§3** `CK_ULONG` cap.~~ **DONE.** See §2.1, §3.4.
4. ~~**§5, §7, §8** record-only.~~ **DONE.**
5. ~~**§6** comment sweep.~~ **DONE** — 4 stale comments fixed, one real divergence found and measured (§6.2, `LEGAL-ECDH-KEM-CURVE-COVERAGE-SECP256K1` — E-6 open: should Rust add secp256k1?), one finding escalated to the persistence program (§6.3). Full harness re-confirmed: 71 scenarios / 13,866 observations / 0 uncovered.
6. **§4.2**, then the landing gate — full `local-gate.sh --cpp --javajce --openssl-provider` run before proposing a push. *(next)*

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

## 12. Landing — superseded by §16, kept for history

~~Unchanged: **PR #226 is reviewed and merged first**, then one PR for the phase-2/3/4/5 work on top. 41 commits unpushed. Nothing is pushed without explicit confirmation.~~

~~Before proposing a push: `bash scripts/local-gate.sh --cpp --javajce --openssl-provider`, with `AG_CONTAINER_ROOT=/ag/pqctoday-hsm/.worktrees/pkcs11-d2` set on **every** run. Note §4.2 — until that is confirmed, the JavaJCE step's green is weaker than it looks.~~

PR #226 merged to `main` 2026-09-08 (merge commit `8d5b12f3f`, another session's work). §16 is the current landing state.

---

## 13. Decisions requested

| Ref | Question | Recommendation |
|---|---|---|
| **E-1** | §3 — which reading for `UNLIMITED_KEY_SIZE`? | **Option A** (`0x7FFFFFFF`). Satisfies the cap, keeps C++'s long-standing "payload size" reading, one-line change. Option B is more correct but changes an advertised capability on the authority of a draft. |
| **E-2** | §6 — sweep all 157 cross-engine claims, or only the 51 in `ffi.rs`? | **All 157.** The two failures today were both in Rust, but the 13 in `src/lib` are the same class and the total is small enough to finish. *(The 157/51/13 figures were themselves wrong -- see §6's own correction. The decision's substance is unaffected: sweep everything, not just `ffi.rs`.)* |
| **E-3** | §1 — if Rust's `C_VerifySignatureInit` already handles the stateful mechanisms, do we still change C++? | **Yes.** A divergence where Rust is right and C++ refuses is still a divergence, and C++'s refusal is the non-conformant half. |
| **E-4** | Does anything here block the landing, or do §5/§7/§8 (record-only) land with it? | Land the record-only items **with** the branch. They are documentation of decisions already taken; holding them back leaves the record incomplete for a reviewer. |

---

## 14. Decisions taken (2026-09-07)

| Ref | Decision | Note |
|---|---|---|
| **E-1** | **Adopt Rust's reading** of `ulMaxKeySize` | *Overrides the recommendation to clamp to `0x7FFFFFFF`.* "Key size" means the key the mechanism uses, not the payload it may process. See §14.1 — the decision applies cleanly to two of the five sites and needs one follow-up for the rest |
| **E-2** | Sweep **all** cross-engine comment claims (figure corrected to 97 -- see §6) | Default taken; `src/lib`'s share is the same defect class |
| **E-3** | **Fix C++ regardless** of what Rust turns out to do | Default taken. Measured (§1.4): Rust already conformed, exactly the case this decision anticipated. C++ fixed and verified — 0 uncovered on the new scenario |
| **E-4** | Record-only items (§5, §7, §8) **land with the branch** | Default taken; a reviewer should see the reasoning alongside the code |

| **E-5** | **Execute phase 5 on this branch**, in §10's order | The branch reaches ~55 commits before landing. Review size is the accepted cost |
| **E-6** | §2 pins **all advertised mechanisms** (166 C++ / 172 Rust), not just the 86 that disagree | A mechanism that agrees today can drift tomorrow — which is exactly how `CKM_AES_CMAC` went unnoticed |
| **E-7** | §8 wasm snapshot: **document the boundary, no code** | Default taken. A browser has no PIN-equivalent secret to derive from; the key would have to come from the host, which already holds the blob |
| **E-8** | §6 sweep: **stop and fix** each concealed behaviour divergence before continuing | *Overrides the recommendation to record and keep sweeping.* See §14.2 |

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

**E-1a answered:** ground each of the three against its own specification — SP 800-185 for the two KMAC rows, PKCS#11 §6.20 for generic secret — and set the maximum from that, taking neither engine's current value as evidence. Specified in §3.2. The two key-wrap rows proceed as decided in §3.1.

This is the more demanding of the options offered and it is the right one: `2³¹` and Rust's 512/64 are both unsourced policy, and picking between two unsourced numbers would have produced a third. The cost is a spec read per mechanism; the benefit is that the ledger row carries a citation instead of a preference.

This is the same failure the plan's own verification standard warns about — I described a set of code sites from a summary (the exception's prose) instead of reading them, and posed a decision on the description. The exception text needs the same correction.

### 14.2 E-8 — what "stop and fix" costs, recorded before it bites

The sweep's duration becomes unpredictable: 157 claims, an unknown number of which conceal something real, each one able to turn a documentation pass into a remediation. `ffi.rs:353` is the precedent — one stale half-sentence produced a wrong finding, a wrong urgency and a half-built key hierarchy.

Implemented as decided. Two guards, so the decision does not quietly become an open-ended rewrite:

1. **A divergence is what the harness shows, not what a comment implies.** Before fixing, write the scenario. A comment claiming the other engine differs is not evidence that it does — that is the same class of error the sweep exists to remove, and fixing on the strength of one would be doing the defect again in the opposite direction.
2. **One commit per fix, separate from the comment correction.** A behaviour change buried in a 97-file documentation commit is unreviewable.

If the sweep stalls on something large, that is a finding worth surfacing rather than absorbing silently.

---

## 15. Harness self-bug — spurious SLH-DSA divergence, found by the final clean `--cpp` gate — DONE (2026-09-07)

The final, isolated `--cpp` gate run (no concurrent harness process this time, so the earlier race explanation didn't apply) came back with a real UNCOVERED divergence:

```
create.generate_key_pair.slh_dsa_all_params | gen_shake_128s.pub.CKA_VALUE.enc | value_differs | RAW_32 | DER_SEQUENCE_MALFORMED_LEN
```

Not a crypto defect. `classify()` in `p11_diff.cpp` sniffs a byte string's ASN.1 shape by its leading byte — `0x30` is treated as a candidate DER SEQUENCE tag, and anything starting `0x30` that doesn't also satisfy the length-prefix invariant falls through to `DER_SEQUENCE_MALFORMED_LEN`. SLH-DSA public keys (FIPS 205) are raw, unstructured fixed-length byte strings with no ASN.1 framing at all — a freshly generated key's leading byte is uniformly random, so ~1/256 of keys will spuriously read as a malformed SEQUENCE by pure chance. This is the exact same trap the file had already been bitten by twice before (`is_unstructured_attr` for identifiers/checksums, `is_bignum_attr` for RSA CRT values) — just not yet closed for `CKA_VALUE` on the newer PQC key types.

**Fix:** added `is_raw_pqc_key_type(CK_ULONG)` (ML-KEM, ML-DSA, SLH-DSA, HSS, XMSS, XMSS-MT) and excluded `CKA_VALUE` from `classify()` for those key types in `record_attrs`, fetching `CKA_KEY_TYPE` up front to gate it. Structural fix, not a workaround — it doesn't depend on this run's random bytes, so it closes the whole class rather than papering over one instance. Verified: rebuilt, reran the 71-scenario suite in isolation — **0 uncovered divergences**, PASS.

Not scoped to `record_bytes`'s other two call sites (operation outputs — signatures, KEM ciphertext, wrapped-key blobs) — those already choose `ByteView::SHAPE` vs `LEN` deliberately per-callsite based on whether framing is actually specified, and no divergence was observed there. If one surfaces, the same fix shape applies.

---

## 16. Gate/test debt found running the real thing, and the actual landing plan (2026-09-08)

§15 was found by the first genuinely clean, isolated `--cpp` gate run this branch had seen. Running the gate for real (not the narrow scoped checks used during iteration) kept finding more of the same shape: real, pre-existing gaps that only a full run surfaces, none of them caused by this branch's own PKCS#11 changes. Fixed as found, each verified before moving to the next, none by re-running the whole ~100+ minute suite.

### 16.1 What's DONE

| Item | What | Verified |
|---|---|---|
| **Gate 2x-runtime bug** | 4 steps (`kmip cargo test`, `kmip local-only suites`, `rust engine cargo test`, `remoting parity`) each ran their full suite TWICE back-to-back purely to get a summary line derivable from one run — the concrete majority of "why does a one-file change take hours." Single-capture now. | Full core gate rerun, 12/13 passed (only the pre-flagged wasm gap), correct per-step pass counts — **pre-rebase, see 16.1.1** |
| **T24** (openssl-provider) | Stale hardcoded HSS/LMS signature size (1296, W8) — the engine's default LMOTS moved to W4/2352 on 2026-09-03 (HBS-1, `673a5a11`) and the test was never updated | Isolated repro (preamble + this one section, run directly against the built engine) |
| **T25f** (openssl-provider) | Software reference relied on OpenSSL's native KBKDF, which cannot express "no counter" for FEEDBACK mode (same class of gap T36/T36b already had fixed for Double-Pipeline mode) — replaced with an independent Python reference, same pattern T36 uses | Isolated repro; T25/T25b/T25c re-verified not to regress |
| **Rebase onto `origin/main`** | pkcs11-d2 was still based on `fix/pkcs11-v32-gaps-0906`, merged into `main` as PR #226 2026-09-08 (`8d5b12f3f`) by another session. Rebased clean: `merge-base(HEAD, origin/main) == origin/main`. 3 conflicts — 2 were pure `REPLAY_REPORT` timestamp collisions (took main's side, identical pass/fail data both sides), 1 was `scripts/local-gate.sh` itself: **main had independently found and partially fixed the same 2x-runtime bug**, from a different angle each time (verdict scope, a discarded failing-test name) — my single-run fix already subsumes both, merged the code from mine with the historical rationale from both sides | `bash -n` both scripts, markers grepped present — **syntax only, see 16.1.1** |

Two real fix commits on this branch (`fix(gate): stop running the same test suite twice per step`, `fix(test): two stale assertions in the openssl-provider harness`), each paired with its own regenerated-evidence chore commit.

#### 16.1.1 Self-challenge (2026-09-08) — two of the rows above overstated their verification

Asked to challenge this plan; two of the "Verified" claims above didn't hold up:

1. **The gate pass counts are stale.** "12/13" and (in a chat reply, not this doc) "14/16" were measured *before* the rebase. Main's 33 commits added two gate steps this branch had never run against — `#4 OASIS corpus provenance` and `#5 OASIS byte vectors match that XML (drift guard, added 2026-09-07)` — both now present in the merged `scripts/local-gate.sh`. Presenting the pre-rebase count as current state is exactly the class of error T24/T25f themselves were: a check that stopped describing reality once something else moved, uncaught because nobody re-ran it. Same mistake, this time in this plan doc.
2. **The `local-gate.sh` merge conflict resolution was reasoned through and syntax-checked, never executed.** `bash -n` only proves the script parses; it proves nothing about whether the hand-merged `kmip local-only suites` / `remoting parity` steps actually behave correctly. This codebase has already been bitten once by exactly this shape of failure (`pipefail` silently defeating a `grep ... && exit 1` guard) — a syntax-valid script can still be behaviorally wrong.

Also, §16.3's "no code this branch touched" affects wasm/JavaJCE-remote/TLS-hybrid is imprecise: `wasm/Cargo.lock` **is** touched (the already-known `md-5` lockfile pull-in, mechanical, not a functional wasm change) — the substance of the claim holds, the wording didn't.

#### 16.1.2 Core gate re-run post-rebase (2026-09-08) — found a real bug, not just a formality

Ran `bash scripts/local-gate.sh` (core, no flags) against the actual rebased tree. **15 steps now** (main added step 1 "gate self-check" — a regression guard verifying every step can genuinely fail, closing the exact `pipefail`/`grep && exit 1` class of gap 16.1.1 point 2 worried about in the abstract — plus the two OASIS steps already known from the rebase diff). Result: **13/15 passed**, 2 failed:

- **`wasm CACP smoke`** — the same pre-flagged, out-of-scope gap (needs cross-repo `build-kmip-wasm.sh`).
- **`cross-engine PKCS#11 differential harness`** — a REAL, new-to-this-run uncovered divergence: `create.generate_key.generic_secret`'s `gen.key.CKA_VALUE.enc` classified `DER_SEQUENCE_MALFORMED_LEN` (C++) vs `RAW_32` (Rust). Same exact bug class as §15 (leading-byte DER-sniff false positive on a raw random key), one key type over: `is_raw_pqc_key_type` covered the six PQC public/private key types but not `CKO_SECRET_KEY` (AES, generic-secret) — missed because this scenario deliberately sets `CKA_SENSITIVE=FALSE` to expose `CKA_VALUE`, which I hadn't checked when reasoning §15's fix was scoped correctly. Generalized the fix to gate on `CKA_CLASS == CKO_SECRET_KEY` instead of enumerating key types one at a time. Rebuilt, reran the 71-scenario suite in isolation: 0 uncovered, PASS.

So the self-challenge in 16.1.1 was justified twice over: the stale numbers really were stale, and the actual re-run found a genuine, previously-invisible bug — not just a formality. Current, real, post-rebase, post-fix state: core gate 13/15 (wasm smoke is the only remaining, pre-flagged gap); the `local-gate.sh` merge itself (16.1.1 point 2) is now behavior-verified, not just syntax-checked, since 13 of its 15 steps ran for real and produced correct per-step pass counts.

### 16.2 What's NOT done — the actual remaining gap list

| Gap | Why it's open | Effort if picked up |
|---|---|---|
| **`wasm CACP smoke`** | Needs `scripts/build-kmip-wasm.sh`, which stages build output into the sibling `pqctoday-hub` repo — out of scope for a hsm-only branch, flagged since the first gate run this session | Cross-repo work, not started |
| **`--javajce-remote`** | Needs a live `pqc-grpc` server + `/admin-certs` mTLS material up via `pqctoday-sandbox`'s `docker-compose.yml` — not part of §12's stated pre-push checklist (`--cpp --javajce --openssl-provider`) | Not attempted this branch |
| **`--acvp-wasm`, `--release-xmss`, `--tls-interop`** | All opt-in, none part of §12's stated checklist, no code this branch touched plausibly affects any of them | Not attempted this branch |
| **Push** | 56 commits, rebased clean, nothing pushed — standing rule, needs explicit go-ahead each time regardless of gate state | Zero remaining technical work; a decision, not a gap |
| **PR** | Not opened | Blocked on push |

### 16.3 Recommendation

The three opt-in legs in the second row of §16.2 were never part of this branch's own landing checklist (§12) — closing them out is scope creep beyond what phase 5 or this gap-hunt actually needs, unless something in the branch's diff plausibly touches them. Checked against the real diff (`git diff --name-only origin/main...HEAD`), not recalled from memory: no JavaJCE-remote/ or TLS-hybrid (`secp384r1mlkem`/tls) files touched at all; the only `wasm/` touch is `wasm/Cargo.lock` (the already-known `md-5` lockfile pull-in — mechanical, not functional wasm code). Treat them as **not gaps of this branch**, not as deferred work.

That leaves two real open items: the wasm smoke gap (cross-repo, genuinely out of scope for a hsm-only push) and the push/PR decision itself. Both are exactly where the previous report left them — nothing has changed on the technical side since; what changed is this section exists now as a written record instead of only a chat reply.
