# PKCS#11 — Phase 4 remediation plan

**Date:** 2026-09-07
**Branch:** `fix/pkcs11-d2-pkcs8-wire-format` (26 commits, unpushed) · PR #226 open, unreviewed
**Governing rule:** v3.2 is the baseline; the v3.3 working tree governs where v3.2 has a gap or a plain error (`CLAUDE.md`)
**Inputs:** `pkcs11-v32-vs-v33-gap-sweep-09072026.md` (both sweeps, decisions in §7), `remediation-plan-pkcs11-v32-phase3-09072026.md` (§12 execution log)

---

## 0. State

The differential harness runs **66 scenarios / 12,073 observations / 0 uncovered**. Three known-defect divergences remain, all one item. The mechanism ledger is consistent, C++-only set empty. Rust 515/0, JavaJCE 274 + 8.

Four v3.3 items were adopted. **Two needed no code** — verified by reading the engines, not assumed: HSS/XMSS already take the message, and both engines already mint `CKA_UNIQUE_ID` for every object class. What follows is what is genuinely left.

### 0.1 A live cross-engine divergence the harness cannot currently see

Grounding §2 turned up something not previously recorded: **the two engines already disagree about multi-part ML-DSA.**

- **C++ permits it** — `SoftHSM_sign.cpp:1144` and `:2852` set `bAllowMultiPartOp = true` for `CKM_ML_DSA`.
- **Rust refuses it** — `CKM_ML_DSA` is absent from `sign_mech_supports_multipart` (`ffi.rs:12716-12760`), so `C_SignUpdate` answers `CKR_OPERATION_NOT_INITIALIZED`.

No scenario exercises multi-part ML-DSA, so the harness has never compared them. Under v3.2 ("single-part operations only") **C++ is the non-conformant one**; under v3.3, Rust is. The adopted decision resolves it in C++'s favour, but the divergence exists today and is untested either way. **A scenario must be added regardless of which way this lands** — that is the real lesson, and it belongs in §8.

---

## 1. KEM encapsulate/decapsulate template enforcement

**Effort: M. The cleanest gap-fill in the sweep, and the item most likely to matter to a real caller.**

v3.2 defines `CKA_ENCAPSULATE_TEMPLATE` and `CKA_DECAPSULATE_TEMPLATE` in the header and then never mentions them again — no table row, zero hits in the spec text. v3.3 supplies the rows and **SHALL**-level enforcement:

- `key_management_functions.md:762-771` — the encapsulation template partitions which keys a key may encapsulate; on conflict `C_EncapsulateKey` **SHALL** return `CKR_KEY_HANDLE_INVALID`.
- `key_management_functions.md:868-878` — the decapsulation template is applied to the new key's attributes *before* the caller's own template; on conflict, **SHALL** return `CKR_TEMPLATE_INCONSISTENT`.

Entry points: C++ `SoftHSM_kem.cpp:126` / `:484`; Rust `ffi.rs:22940` / `:22998`.

1. Accept and store both attributes on key creation. They are array attributes — the `CKF_ARRAY_ATTRIBUTE` correction is already applied, so the type values are right.
2. `C_EncapsulateKey`: match the encapsulating key's template against the target using `C_FindObject` matching semantics; refuse with `CKR_KEY_HANDLE_INVALID`.
3. `C_DecapsulateKey`: apply the template to the new key's attributes first, then the caller's `pTemplate`; refuse conflicts with `CKR_TEMPLATE_INCONSISTENT`.
4. Differential scenario `create.kem_template_enforcement`: a key with a restrictive template, one encapsulation that satisfies it and one that does not, on both engines. **The negative case is the test** — a permissive implementation passes any positive-only test.

**Decision needed (D-1): storage without enforcement is worse than nothing.** If only part of this lands, a caller could set a template, see it stored, read it back, and reasonably believe it is being enforced. Either both halves land together, or neither does.

---

## 2. ML-DSA multi-part

**Effort: S for Rust, zero for C++ — but see §0.1.**

Add `CKM_ML_DSA` (and, for consistency, `CKM_ML_DSA_EXTERNAL_MU`) to Rust's `sign_mech_supports_multipart`. Rust already has the accumulate-then-sign machinery (`SIGN_MULTIPART_ACC`); C++ uses exactly that shape and its own comment at `SoftHSM_sign.cpp:1230-1232` notes it "needed no engine-side change beyond the flag".

Verify with a real round trip, not a flag read: sign a message in three `C_SignUpdate` chunks and verify the signature against the same message signed single-part. Add the scenario in §8.1 **first**, so the divergence is visible before it is closed.

---

## 3. HSS/XMSS multi-part verify via `C_VerifySignatureInit`

**Effort: M, and the riskiest of the three adopted behaviour items.**

v3.3 permits multi-part verify for the stateful-hash mechanisms *only* when the `C_VerifySignatureInit` interface is used. Both engines currently refuse: C++ `SoftHSM_sign.cpp:3207` sets `setAllowMultiPartOp(false)`; Rust has no such path.

C++ already implements `C_VerifySignatureInit` (`:4031`), which binds the signature to the session before data arrives — exactly the shape this needs, since the stateful verifiers want `[signature || message]` assembled.

1. Permit multi-part **only** under `SESSION_OP_VERIFY_SIGNATURE`, never under plain `C_VerifyInit`. The distinction is the whole of what v3.3 allows.
2. Accumulate parts, then assemble and call the existing verifier.
3. Confirm Rust implements `C_VerifySignatureInit` for these mechanisms at all before assuming parity is reachable.

**Note the asymmetry v3.3 creates:** ML-DSA loses its single-part restriction while SLH-DSA keeps it, so a shared verify path must now diverge by mechanism. Do not "simplify" that away.

---

## 4. Stateful-hash `CKA_VALUE` — the last known defect

**Effort: M. Three divergences, and the only `status: defect` entry left.**

C++ answers `CKR_ATTRIBUTE_SENSITIVE` for `CKA_VALUE` on HSS/XMSS/XMSS-MT private keys — correct, since §6.65/§6.66 define the attribute with footnote 7. Rust answers `CKR_ATTRIBUTE_TYPE_INVALID`, denying an attribute the specification defines.

Rust is *truthful about its own storage*: per `LEGAL-XMSS-STATE-REPRESENTATION` it keeps stateful-hash state in engine-private vendor attributes, not under `CKA_VALUE`. So the fix is to **materialise** the attribute and gate it as sensitive — a representation change, not a filter, and it interacts with that adjudication.

1. Materialise `CKA_VALUE` for the three key types from the vendor attributes.
2. Ensure the existing sensitivity gate then produces `CKR_ATTRIBUTE_SENSITIVE`, matching C++.
3. **Do not let the value leak.** These keys are mandated `CKA_SENSITIVE`; the test must assert the value is *never* returned, only the code.
4. Update or delete `LEGAL-XMSS-STATE-REPRESENTATION`, which currently says the two engines store state differently and that no probe can see it. After this, one half of that is no longer true.

---

## 5. Remaining `CKA_PUBLIC_KEY_INFO` gaps

**Effort: M.** Seven divergences left after the mirror landed (14 → 7).

- **HSS / XMSS / XMSS-MT** (6): no SPKI builder exists for these families, on either half. Needs a real encoder. `reference_stateful_hash_standards_facts` records that IANA/RFC 9858 owns the LMS values, not SP 800-208 — read that before choosing an OID.
- **Unwrap path** (1): `encoding.wrap_private_key_pkcs8` — the unwrapped private key carries no SPKI because the public key must be *derived* from the unwrapped private one. `ec_public_point_from_scalar` already exists from D-2 and covers the EC case.

---

## 6. H2 — verify the `justification` prose

**Effort: S, no code.** H1 verified all 31 citations and corrected 16; it did **not** read the free prose, and that prose is wrong in at least one place (`LEGAL-USAGE-FLAG-DEFAULT-RECOVER` claims C3 removed a recovery path that is fully implemented, and that flags "correctly stay unadvertised" when both engines advertise them).

Read every `justification` for claims **about this repository's code** and check each against the source. Those are the ones that rot: a wrong spec citation is wrong from the day it is written, but a code claim starts true and decays.

---

## 7. R1 — build warnings

**Effort: S.** 43 warnings. Chasing four of them found a real defect this programme (`CKM_ECDSA_SHA1` on P-256 could never verify).

- `der_wrap_ec_point` is reported dead but has a call site at `ffi.rs:23026` behind a `cfg` the default build excludes. Determine which, then gate or remove — do not silence with `#[allow]` before knowing.
- Confirm each unused import is genuinely unused in its module rather than mass-applying `cargo fix`.
- Consider `#![deny(unreachable_patterns)]`. That lint is what surfaced the SHA-1 defect.

---

## 8. Harness and gate hardening

### 8.1 Scenarios for the untested surfaces *(do this first — see §0.1)*

Multi-part signing is not exercised for any PQC mechanism, which is why a live C++/Rust disagreement about ML-DSA went unrecorded. Add scenarios **before** changing either engine, so the divergence is observed, then closed:

- multi-part sign for `CKM_ML_DSA` (and `CKM_SLH_DSA`, which must stay single-part under both versions)
- multi-part verify via `C_VerifySignatureInit` for the stateful-hash mechanisms
- `C_EncapsulateKey` / `C_DecapsulateKey` template enforcement (§1.4)

### 8.2 Pin the mechanism-info ranges

`LEGAL-MECHANISM-INFO-KEY-SIZE-RANGES` matches by **path, not value**, so a future change to either engine's key-size ranges is silently excused. Its own text records this. Move the values into `docs/pkcs11-mechanism-ledger.json`, where each mechanism has a row and a change shows as a diff, and narrow the exception to "differences are policy, values are pinned in the ledger".

### 8.3 The gate's stale-engine false green

`--javajce` runs `mvn` against the container's installed `/usr/local/lib/softhsm/libsofthsmv3.so`, dated **2026-09-01**. It validates today's Java against a months-old native engine and will keep reporting green as the two drift. Any engine-side change is invisible to it — this is not specific to X1.

Fix: build the engine inside `pqc-dev-sandbox` as part of the step and point `PKCS11_MODULE` at it. The container has cmake, g++ and OpenSSL 3.6.3; this was done by hand during phase 3 and took one build. Cache the build directory so repeat runs stay cheap.

---

## 9. Audits — read before deciding, no code yet

| Item | Question |
|---|---|
| **`CK_ULONG` 32-bit cap** (v3.3 `introduction.md:303`) | Every `CK_ULONG` capped at `0x7FFFFFFF`. C++ reports `UNLIMITED_KEY_SIZE` = 2³¹ as `ulMaxKeySize` for the AES key-wrap mechanisms — **one over the cap**. Audit lengths, counts, handles and flags. |
| **Template deep-copy MUST** (v3.3 `key_objects.md:67-135`) | A token MUST NOT store the caller's `CK_ATTRIBUTE` array verbatim. Read both engines' `CKA_WRAP_TEMPLATE` handling before claiming either way. Directly relevant to §1. |
| **Non-storage classification** (v3.3 `object_classification.md`) | `CKO_VALIDATION` / `CKO_PROFILE` / `CKO_MECHANISM` are explicitly non-storage. Do we template them as storage objects? |
| **`CKA_OBJECT_VALIDATION_FLAGS` footnote 12** | v3.3 drops the read-only latch. A **rule** change, not a constant, so it has no place in `V33_CORRECTIONS` as that table is written. Decide separately. |

---

## 10. Upstream question list

Compile and send to the OASIS PKCS 11 TC. **Not** implementation work, but it is how the draft defects stop being our problem:

1. **Why were the FIPS 186-4 subsections deleted?** (§2.5 — we are keeping the v3.2 constraints.) They were the only text constraining FIPS-mode moduli and curves, and the snapshot gives no rationale.
2. `CK_MU_GEN_PARAMS` (`ml_dsa.md:119-130`) — first member ends in a comma; does not compile.
3. `comp_kem.md:96` — private key objects said to hold `CKK_ML_KEM`; should be `CKK_COMP_KEM`.
4. `aes.md` — mechanism table says `CKM_AES_EC`; definitions and prose say `CKM_AES_ECB`.
5. `slh-dsa.md:85,87` — v3.2's copy/paste bug carried forward: `CKP_SLH_DSA_SHAKE_256S` twice, `..._256F` missing.
6. `elliptic_curves.md:992` — dangling `^1^` whose footnote text exists nowhere in the snapshot.
7. `CKO_MECHANISM`'s two new attributes have no allocated value, even in the draft's own header.
8. `CKA_OBJECT_VALIDATION_FLAGS` footnote 12 — deliberate erratum or editing slip?

---

## 11. Sequencing

1. **§8.1 scenarios** — before any engine change, so §0.1's divergence is observed rather than asserted.
2. **§2 ML-DSA multi-part** (Rust) — small, and closes the divergence §8.1 just exposed.
3. **§6 H2** — no code, removes a phantom worklist item.
4. **§4 stateful-hash `CKA_VALUE`** — the last open defect.
5. **§1 KEM templates** — the substantive gap-fill.
6. **§3 HSS/XMSS multi-part verify** — riskiest; after §8.1 has a scenario for it.
7. **§5 SPKI gaps**, **§7 warnings**, **§8.2/8.3 hardening**.
8. **§9 audits**, **§10 upstream list** — any time; neither blocks code.

---

## 12. Verification standard (unchanged)

- A regression test that **fails on the pre-fix binary**. It has caught real self-deception three times in this programme.
- Assert against an **independent** oracle, never the engine against itself.
- Every `exceptions.json` edit quotes the sentence it relies on, with `file:line` — and, since phase 3, the same applies to claims about *code*.
- **When in doubt, read BOTH specs.** Consult v3.2 for the baseline requirement *and* v3.3 for whether it fills a gap or corrects an error, before concluding anything. This programme has repeatedly found that one version alone gives the wrong answer: v3.2 alone would have had us signing HSS/XMSS over a pre-computed hash (non-interoperable), and v3.3 alone would have had us dropping the FIPS 186-4 modulus and curve constraints on the authority of an unpublished draft. The two together, plus the code, is what has actually been reliable.
- Section and table numbers come from `docs/refs/pkcs11-spec-v3.2-os.pdf` — the v3.3 markdown is prose only and carries no section numbers. Quote v3.3 by `file:line` plus the snapshot commit.
- Sabotage-test any new gate check on a **copy** of the tree.
- **Read the engines before reasoning from the spec alone.** Twice in phase 3 a conclusion drawn from spec text alone was wrong in the opposite direction once the code was read (§2.1 HSS input, §2.4 `CKA_UNIQUE_ID`).

---

## 13. Landing

Per the phase-3 decision: **PR #226 is reviewed and merged first**, then one PR for the phase-2/3/4 work on top. Nothing is pushed without explicit confirmation.

Before proposing a push: `bash scripts/local-gate.sh --cpp --javajce --openssl-provider`, with `AG_CONTAINER_ROOT=/ag/pqctoday-hsm/.worktrees/pkcs11-d2` set on every run. Note §8.3 — until that is fixed, the JavaJCE step's green is weaker than it looks.

---

## 14. Decisions requested

| Ref | Question | Recommendation |
|---|---|---|
| **D-1** | §1 — land template storage and enforcement together, or storage first? | **Together.** Storage without enforcement invites a caller to believe a restriction is being applied when it is not. |
| **D-2** | §3 — is multi-part verify for stateful-hash mechanisms worth the risk, given no caller has asked? | Lowest value of the three adopted behaviour items. Reasonable to defer without reopening the decision. |
| **D-3** | §9 `CKA_OBJECT_VALIDATION_FLAGS` footnote 12 — follow v3.3 and drop the read-only latch? | Ask the TC first (§10.8). It looks like an erratum, but dropping a read-only latch on the strength of an inference is the wrong direction to guess in. |
| **D-4** | §10 — do you want the upstream list actually sent, or just recorded? | Record it here; sending is your call and your name on it. |


---

## 15. Decisions taken (2026-09-07)

| Ref | Decision | Note |
|---|---|---|
| **Scope** | Follow §11's sequence | Scenarios → ML-DSA multi-part → prose sweep → stateful-hash `CKA_VALUE` → KEM templates |
| **D-1** | Storage and enforcement land **together** | Default taken; storage alone would let a caller believe an unenforced restriction is active |
| **D-2** | **Implement** §3 HSS/XMSS multi-part verify | *Overrides the recommendation to defer.* Proceed as originally adopted |
| **D-3** | **Follow v3.3 — drop the read-only latch** on `CKA_OBJECT_VALIDATION_FLAGS` | *Overrides the recommendation to keep it and ask the TC.* Check what the engines do first: if neither implements the latch this is a record-only change |
| **D-4** | Record the upstream list in the repo; sending stays the user's call | No draft message |

Two decisions went against my recommendation (D-2, D-3). Both are recorded as the user's call and implemented as decided; the reasoning I offered against each stays above, unedited, so a later reader sees the trade-off that was accepted rather than a plan rewritten to look unanimous.


---

## 16. Correction — §0.1's "live divergence" does not exist, and §2 is a no-op

**§0.1 is wrong.** I claimed the engines disagreed about multi-part ML-DSA, on the strength of `CKM_ML_DSA` being absent from Rust's `sign_mech_supports_multipart`. It is not absent — it is at `ffi.rs:12774`, alongside `CKM_ML_DSA_EXTERNAL_MU`, `CKM_SLH_DSA` and `CKM_EDDSA`. My `awk` window stopped at line 12762, twelve lines short, and I reported the truncation as a finding.

The scenario was written first anyway, which is what caught it. Measured on both engines, every step returns `CKR_OK` and the signatures verify:

| | C++ | Rust |
|---|---|---|
| `ml_dsa_65` update ×3 → final → verify | `CKR_OK`, sig 3309 B | `CKR_OK`, sig 3309 B |
| `slh_dsa` update ×3 → final → verify | `CKR_OK`, sig 7856 B | `CKR_OK`, sig 7856 B |

**§2 (ML-DSA multi-part) is therefore already done on both engines. No work.**

### And the apparent SLH-DSA defect is not one either

The dump showed both engines permitting multi-part *signing* for bare `CKM_SLH_DSA`, which the sweep had reported as "single-part only" in both spec versions. Checked before asserting a defect — and the sweep's summary was imprecise. **v3.2's own footnote** for that row (`/tmp/p11os.txt:16946`) reads:

> "Verification is only for single part verifications or multipart verifications when the `C_VerifySignatureInit` interface is used"

That is **identical to v3.3's**, and it restricts **verification**, not signing. Multi-part signing is unrestricted in both versions. Both engines are conformant; nothing to fix.

This does sharpen §3: the HSS/XMSS wording genuinely *did* change (v3.2 "Single-part operations only" → v3.3's `C_VerifySignatureInit` clause), so that item stands as decided. SLH-DSA never had the restriction the sweep attributed to it.

### What the scenario bought

No defect, but real coverage: multi-part signing for PQC mechanisms was previously untested on either engine, and is now compared across 21 observations. Harness: **67 scenarios / 12,094 observations / 0 uncovered**.

### The lesson, again

This is the third time in this programme that a conclusion drawn from reading *about* the code or the spec — rather than measuring — was wrong. The verification standard already says "read the engines before reasoning from spec text alone". It now needs a companion: **when a grep defines the finding, show the whole range.** A truncated window is indistinguishable from an absence.
