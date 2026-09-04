# PKCS#11 v3.2 Profile Traceability

> **Staleness note (added 2026-09-01).** This matrix's citations were
> confirmed against commit `a158095` (2026-08-23). Since then:
> `rust/src/ffi.rs` has taken **27 commits** and grown from 18,233 to 21,737
> lines — every line number this document cites in that file has drifted
> (e.g. §3 condition 4's `profile_object_ffi_tests` module, cited here at
> `rust/src/ffi.rs:15981-16088`, is now at `rust/src/ffi.rs:18997-19125`,
> confirmed by direct grep — `baseline_profile_object_is_public_and_findable`,
> `client_cannot_create_profile_object`, and `profile_object_is_fully_read_only`
> still exist under those names, just at different lines).
> `p11_v32_compliance_test.cpp` has taken 3 commits (10,482 → 10,814 lines);
> `rust/src/state.rs` 4 commits (1,614 → 1,780 lines);
> `src/lib/SoftHSM_objects.cpp` 2 commits (1,364 → 1,447 lines);
> `rust/test_p11_conformance.js` 3 commits (3,226 → 3,396 lines); and
> `tests/differential/scenarios.inc` + `tests/differential/exceptions.json`
> 4 commits combined. This matrix has not been regenerated to reflect any
> of this drift.
>
> **One of those changes is substantive, not line drift, and directly
> contradicts §1 and §4 below.** Commit `dea9bfa1` ("WS-11 v3.2 conformance
> gaps — token-wipe, profile claims, RESTORE_KEY flag, C++ find-order
> (#188)", 2026-08-29 — six days after this matrix's `a158095` pin) made
> both engines claim profiles this document says they don't, or doesn't
> cover at all:
> - **Rust now also claims `CKP_EXTENDED_PROVIDER`**
>   (`rust/src/state.rs`'s `supported_profiles()`, currently lines 268-275),
>   directly contradicting §1's table ("Rust... **Not** claimed") and §4's
>   header ("Extended Provider (§5.3) — C++ engine only") and opening line
>   ("Rust does not claim this profile"). Verified: `git show
>   a158095:rust/src/state.rs` shows `init_profile_objects()` publishing only
>   `CKP_BASELINE_PROVIDER` at the pin commit; the current file's
>   `supported_profiles()` returns `[CKP_BASELINE_PROVIDER,
>   CKP_EXTENDED_PROVIDER, CKP_AUTHENTICATION_TOKEN,
>   CKP_PUBLIC_CERTIFICATES_TOKEN]`, and `init_profile_objects()` genuinely
>   publishes one `CKO_PROFILE` object per entry at slot creation — not
>   just an unused constant.
> - **Both engines now additionally claim Authentication Token (§5.4) and
>   Public Certificates Token (§5.5)** — confirmed the same way for the C++
>   engine's `computeSupportedProfiles()` (`src/lib/SoftHSM_objects.cpp`,
>   currently lines 1012-1076, was lines 949-991 at the pin commit with no
>   such claims). Neither profile is discussed anywhere in this document;
>   §5.4 and §5.5 have zero traceability rows.
>
> None of these three claims (Rust's new Extended Provider claim, and both
> engines' new Authentication Token / Public Certificates Token claims)
> have any test-traceability coverage in this document. Regenerating the
> matrix for them is out of scope for this maintenance pass — flagged here
> rather than left silently looking current.
>
> Checked and found NOT relevant to this specific profile-*conditions*
> matrix: the new Rust-only `CKM_HPKE` mechanism family (added 2026-09-01)
> and the `remoting/` gRPC+REST service. Every profile in scope here
> specifies "no mechanisms" (condition 6/7), so a new mechanism does not
> change any claim this document traces, and `remoting/` wraps the engines
> rather than adding a third profile-claiming implementation.

> **Second update (2026-09-04).** This pass re-verified every citation in
> §1–§6 directly against HEAD (`8f4deb6e`), fixed the drift and the one
> genuinely wrong claim the 2026-09-01 note above had only flagged (not
> corrected), and added §4B/§4C plus a new §6 covering PQC mechanism
> implementation status (out of scope for the original conditions-only
> matrix, added because the profile conditions alone say nothing about
> whether this fork's actual reason for existing — ML-KEM/ML-DSA/SLH-DSA/
> HSS/XMSS/XMSS-MT — works). Specifically:
> - **§1's table and prose were wrong.** Rust's `supported_profiles()`
>   (`rust/src/state.rs:268-275`, unchanged since the first staleness
>   note) returns **four** profile IDs, not one — `CKP_BASELINE_PROVIDER`,
>   `CKP_EXTENDED_PROVIDER`, `CKP_AUTHENTICATION_TOKEN`,
>   `CKP_PUBLIC_CERTIFICATES_TOKEN` — and `init_profile_objects()` publishes
>   one `CKO_PROFILE` object per entry, confirmed both by the function body
>   and by a passing test that asserts exactly this
>   (`rust/src/ffi.rs`'s `baseline_profile_object_is_public_and_findable`,
>   now at line 20270 — see §4B). The claim "Rust does **not** claim
>   Extended or Complete Provider" was true when this document was
>   originally written and has been false since WS-11 Phase 1 (commit
>   `dea9bfa1`, 2026-08-29); this pass fixes it rather than re-flagging it.
> - **`rust/src/ffi.rs` drifted further**: 21,737 → 23,660 lines since the
>   first note. `profile_object_ffi_tests` is now at
>   `rust/src/ffi.rs:20220-20341` (was cited there as 18997-19125, before
>   that 15981-16088); the three test names inside it are unchanged.
> - **`p11_v32_compliance_test.cpp` did NOT drift further** despite the
>   file growing to 10,814 lines — `test_profile_objects()` (line 1425),
>   `CKP_BASELINE_PROVIDER_present` (1469), and
>   `Extended_provider_claim_recorded` (1489/1495) are all at the exact
>   lines this document already cited. Re-confirmed directly, not assumed.
> - **`SoftHSM::computeSupportedProfiles()`** is confirmed at
>   `src/lib/SoftHSM_objects.cpp:1012-1076` (the commit `dea9bfa1` location
>   the first note already gave), and now has line-level citations for its
>   Authentication Token (1053-1060) and Public Certificates Token
>   (1062-1069) blocks in §4C below, which the first note left unquoted.

**Purpose.** This document maps every PKCS#11 v3.2 profile condition either
engine in this repository actually *claims* to satisfy — the C++ engine
(`softhsmv3`) and the Rust engine (`softhsmrustv3`) — to the specific,
currently-existing test(s) that prove it. Every citation below (file, line
number, test/check name) was confirmed by directly reading or grepping the
source at commit `a158095` on `fix/pkcs11-residual-mechanism-coverage-0824`
on 2026-08-24. Nothing here is copied from a prior audit or gap-analysis
report — those drift stale the moment a test is renamed, moved, or deleted,
which is exactly the failure mode this document exists to prevent.

**Why this exists.** The 2026-08-23/08-24 compliance-testing remediation
found that the Extended Provider profile's function-pointer check in
`p11_v32_compliance_test.cpp` had been an **unconditional PASS with no way to
fail** — a row in the pass column that could never fail, regardless of
whether the underlying claim held. That specific defect is now fixed (see
`Extended_provider_claim_recorded`, §3 below), but the general risk — a
profile claim published in source with no test that could actually catch its
absence — is exactly what a traceability table catches at a glance, without
re-deriving the whole chain from scratch on every audit.

**Source of truth.** The condition lists quoted below are transcribed
verbatim from `docs/refs/pkcs11-profiles-v3.2-os.pdf` (PKCS #11 Profiles
Version 3.2, OASIS Standard, 03 June 2026 — the authoritative document per
`docs/refs/README.md`), Section 5 ("Base Profiles"). **These are the PKCS#11
Profiles v3.2 §5.1/§5.2/§5.3 Baseline/Complete/Extended *Provider*
conditions — not to be confused with KMIP's unrelated "Baseline Server"
profile** (a different OASIS standard, documented in
`kmip/docs/CONFORMANCE_REPORT.md` §5.1, with its own differently-numbered
13-item condition list). The two profiles share adjective vocabulary
("Baseline") by coincidence, not by relationship; this document only ever
means the PKCS#11 Profiles v3.2 document when it says "condition."

Neither engine is a PKCS#11 *consumer*, so the Baseline Consumer (§5.7) and
Extended Consumer (§5.8) profiles are out of scope — they describe
applications that call into a provider, not providers themselves.

---

## 1. Who claims what, and where

**C++ (`softhsmv3`)** computes its profile set at runtime rather than
hard-coding it — `SoftHSM::computeSupportedProfiles()`,
[`src/lib/SoftHSM_objects.cpp:1012-1076`](../src/lib/SoftHSM_objects.cpp#L1012-L1076)
(moved here from 949-993 by commit `dea9bfa1`, 2026-08-29 — confirmed
against current HEAD, not carried forward from the prior pin). It checks the
live `CK_FUNCTION_LIST_3_2` for 16 non-NULL function pointers and, if all are
present, claims **`CKP_BASELINE_PROVIDER`**
([line 1040](../src/lib/SoftHSM_objects.cpp#L1040)); if 5 further pointers
are also present, it additionally claims **`CKP_EXTENDED_PROVIDER`**
([line 1049](../src/lib/SoftHSM_objects.cpp#L1049)); it then
unconditionally also claims **`CKP_AUTHENTICATION_TOKEN`** (conditioned on
`C_Login`/`C_LoginUser`/`C_Logout`/`C_SignInit`+`C_Sign`-or-streaming being
present — [line 1060](../src/lib/SoftHSM_objects.cpp#L1060)) and
**`CKP_PUBLIC_CERTIFICATES_TOKEN`** unconditionally
([line 1069](../src/lib/SoftHSM_objects.cpp#L1069)). See §4C for both. It
never computes or claims `CKP_COMPLETE_PROVIDER` — see §5 below for the
exact rationale, quoted from source.

**Rust (`softhsmrustv3`)** also computes a **four-profile** list, not one —
`supported_profiles()`,
[`rust/src/state.rs:268-275`](../rust/src/state.rs#L268-L275), returns
`[CKP_BASELINE_PROVIDER, CKP_EXTENDED_PROVIDER, CKP_AUTHENTICATION_TOKEN,
CKP_PUBLIC_CERTIFICATES_TOKEN]`, and `init_profile_objects()`
([lines 285-304](../rust/src/state.rs#L285-L304)) publishes one
`CKO_PROFILE` object per entry. **This corrects a wrong claim this
document itself made** in an earlier revision (pinned to commit `a158095`,
2026-08-23) — at that commit Rust genuinely did hard-code a single Baseline
Provider entry, and the function's doc comment (quoted in the previous
revision) said so explicitly. WS-11 Phase 1 (commit `dea9bfa1`, six days
later) widened the claim to all four profiles on both engines, and the doc
comment at [`rust/src/state.rs:277-284`](../rust/src/state.rs#L277-L284)
was updated accordingly ("WS-11 Phase 1 widened this from Baseline-only
after auditing Extended/Authentication/Public-Certificates against every
condition in Profiles v3.2 §5.3/§5.4/§5.5"). Neither engine claims Complete
Provider. See §4B and §4C.

| Profile | C++ (`softhsmv3`) | Rust (`softhsmrustv3`) |
|---|---|---|
| Baseline Provider (§5.1) | Claimed | Claimed |
| Complete Provider (§5.2) | **Not** claimed (deliberate) | **Not** claimed (deliberate) |
| Extended Provider (§5.3) | Claimed (conditionally, computed) | Claimed (hard-coded in the fixed list) |
| Authentication Token (§5.4) | Claimed (conditionally, computed) | Claimed (hard-coded in the fixed list) |
| Public Certificates Token (§5.5) | Claimed (unconditionally) | Claimed (hard-coded in the fixed list) |

---

## 2. Baseline Provider (§5.1) — C++ engine

> "An implementation conforms to this specification as a Baseline Provider if
> it meets the following conditions:" — Profiles v3.2 §5.1

| # | Condition text (verbatim) | Claimed? | Proving test(s) | Notes |
|---|---|---|---|---|
| 1 | "Supports the conditions required by the PKCS#11 Provider Implementation Conformance clauses [PKCS11_Spec]" | Yes | No dedicated test — this is a meta-clause (§7.2) satisfied by the sum of conditions 2-9 | Self-referential by design; not independently testable |
| 2 | "Supports the following data types [PKCS11_Spec]: a. CK_VERSION b. CK_INFO c. CK_SLOT_ID d. CK_SLOT_INFO e. CK_TOKEN_INFO f. CK_SESSION_HANDLE g. CK_USER_TYPE h. CK_SESSION_INFO i. CK_OBJECT_HANDLE j. CK_OBJECT_CLASS k. CK_ATTRIBUTE_TYPE l. CK_ATTRIBUTE m. CK_PROFILE_ID n. CK_RV o. CK_FUNCTION_LIST p. CK_INTERFACE q. CK_C_INITIALIZE_ARGS" | Yes | No runtime test — structural, satisfied by compiling against the canonical `src/lib/pkcs11/pkcs11t.h`/`pkcs11.h` | Every one of these types is exercised as a parameter or return type at thousands of call sites across `p11_v32_compliance_test.cpp`; there is no test that would fail if one were missing (a missing type is a compile error, not a runtime finding) |
| 3 | "Supports the following attributes [PKCS11_Spec]: a. CKA_CLASS b. CKA_TOKEN c. CKA_VALUE d. CKA_ID e. CKA_PRIVATE f. CKA_MODIFIABLE g. CKA_LABEL h. CKA_UNIQUE_IDENTIFIER i. CKA_PROFILE_ID" | Yes | (a)-(g): exercised pervasively (thousands of call sites, every object-creation test in the suite). (h) `CKA_UNIQUE_ID` [pkcs11t.h defines it as `CKA_UNIQUE_ID`, not `CKA_UNIQUE_IDENTIFIER` — the Profiles document uses the prose name; `src/lib/pkcs11/pkcs11t.h:498`]: `test_g5_attrs()`, category `G5Attrs` — `UniqueId_readable_on_private_key` ([line 9425](../p11_v32_compliance_test.cpp#L9425)), `UniqueId_readable_on_sensitive_secret` ([line 9463](../p11_v32_compliance_test.cpp#L9463)), `V14_CopyObject_freshUniqueId` ([line 9504](../p11_v32_compliance_test.cpp#L9504)), `V15_CreateObject_uniqueId_readonly` ([line 9529](../p11_v32_compliance_test.cpp#L9529)). (i) `CKA_PROFILE_ID`: `test_profile_objects()`, category `Profile` — `CKP_BASELINE_PROVIDER_present` ([line 1469](../p11_v32_compliance_test.cpp#L1469)), `No_profile_object_carries_CKP_INVALID_ID` ([line 1472](../p11_v32_compliance_test.cpp#L1472)), `CKA_PROFILE_ID_absent_on_ordinary_object` ([line 1537](../p11_v32_compliance_test.cpp#L1537)) | Every named attribute has real coverage; (a)-(g) are not profile-specific tests but are exhaustively covered as ordinary object attributes throughout the suite |
| 4 | "Supports the following objects [PKCS11_Spec]: a. CKO_PROFILE with value CKP_BASELINE_PROVIDER" | Yes | `test_profile_objects()`, category `Profile` — `Token_publishes_a_CKO_PROFILE_object` ([line 1453](../p11_v32_compliance_test.cpp#L1453)), `CKP_BASELINE_PROVIDER_present` ([line 1469](../p11_v32_compliance_test.cpp#L1469)); cross-engine: differential scenario `env.profile_objects`, [`tests/differential/scenarios.inc:194-215`](../tests/differential/scenarios.inc#L194-L215); also `Application_cannot_create_CKO_PROFILE` ([line 1511](../p11_v32_compliance_test.cpp#L1511)) proves the object is token-computed, not application-forgeable | Wired into the default run — `main()` runs `test_profile_objects()` under `opt_category == "all"` at [line 10316](../p11_v32_compliance_test.cpp#L10316), and `opt_category` defaults to `"all"` ([line 128](../p11_v32_compliance_test.cpp#L128)) |
| 5 | "Supports the following functions [PKCS11_Spec]: a. C_GetFunctionList b. C_GetInterfaceList c. C_GetInterface d. C_Initialize e. C_Finalize f. C_GetInfo g. C_GetSlotList h. C_GetSlotInfo i. C_GetTokenInfo j. C_OpenSession k. C_CloseSession l. C_GetSessionInfo m. C_FindObjectsInit n. C_FindObjects o. C_FindObjectsFinal p. C_GetAttributeValue" | Yes | All 16 are called by `init_token()` ([lines 229-413](../p11_v32_compliance_test.cpp#L229-L413)) as harness scaffolding — a failure of any of them aborts the entire ~10,000-line test run (e.g. `C_OpenSession` FAIL path at [line 398](../p11_v32_compliance_test.cpp#L398)). `C_FindObjectsInit`/`C_FindObjects`/`C_FindObjectsFinal`/`C_GetAttributeValue` are additionally exercised directly by `test_profile_objects()` itself ([lines 1444-1460](../p11_v32_compliance_test.cpp#L1444-L1460)) | **No test emits a dedicated named PASS/FAIL row per function** — success is proven only by "the rest of the suite ran at all," not by an explicit assertion against each function individually. This is real coverage but not row-level traceability; flagged here rather than hidden |
| 6 | "Supports the following mechanisms: a. None specified" | Yes (trivially) | N/A | No mechanism is mandated, so there is nothing to test |
| 7 | "Supports Error Handling [PKCS11_Spec] for any supported object, function or mechanism" | Yes | Broad, not profile-specific: categories `ErrCodes` (`test_c2_error_codes()`) and `G4Retcodes` (`test_g4_retcodes()`) exercise return-code correctness across dozens of call paths | General suite coverage, not a Baseline-Provider-labeled test |
| 8 | "Optionally supports any clause within [PKCS11_Spec] that is not listed above" | N/A | — | Optional clause; nothing to prove |
| 9 | "Optionally supports extensions outside the scope of this standard ... that do not contradict any PKCS #11 requirements" | N/A | — | Optional clause; nothing to prove |

**Wiring check (step 6):** `test_profile_objects()` is defined at
[line 1425](../p11_v32_compliance_test.cpp#L1425), is not `#ifdef`-gated out
(the only `#ifndef` guards in the function are fallback constant
definitions, not test skips), and is invoked unconditionally under the
default `opt_category == "all"` at
[line 10316](../p11_v32_compliance_test.cpp#L10316). `test_g5_attrs()` is
wired the same way at
[lines 10391-10392](../p11_v32_compliance_test.cpp#L10391-L10392).

---

## 3. Baseline Provider (§5.1) — Rust engine

The **same condition list** as §2 above (Profiles v3.2 defines one Baseline
Provider profile; both engines are audited against it). The proving tests
differ.

| # | Condition text (verbatim) | Claimed? | Proving test(s) | Notes |
|---|---|---|---|---|
| 1 | "Supports the conditions required by the PKCS#11 Provider Implementation Conformance clauses [PKCS11_Spec]" | Yes | No dedicated test — meta-clause | Same as C++ |
| 2 | Data types (a-q, same list as §2) | Yes | No runtime test — structural, via `rust/src/ck_abi.rs` / `constants.rs` type definitions | Same caveat as C++: compile-time only |
| 3 | Attributes (a-i, same list as §2) | Yes | (a)-(g): pervasive, thousands of call sites in `rust/test_p11_conformance.js`. (h) `CKA_UNIQUE_ID`: `rust/test_p11_conformance.js`, section "Round-2 — T6 object management" ([line 943](../rust/test_p11_conformance.js#L943)) — checks `'CKA_UNIQUE_ID readable via attribute type 0x4 → OK'` ([line 982](../rust/test_p11_conformance.js#L982)), `'CKA_UNIQUE_ID non-empty'` ([line 983](../rust/test_p11_conformance.js#L983)), `'copy CKA_UNIQUE_ID readable → OK'` ([line 992](../rust/test_p11_conformance.js#L992)), `'copy received a FRESH CKA_UNIQUE_ID'` ([line 993](../rust/test_p11_conformance.js#L993)). (i) `CKA_PROFILE_ID`: see condition 4 below | `rust/test_p11_conformance.js` has no `#ifdef`-equivalent gating — the file runs top-to-bottom unconditionally (confirmed: no `process.argv`-based section skipping exists in the file; `grep` for CLI gating returned nothing) |
| 4 | "Supports the following objects [PKCS11_Spec]: a. CKO_PROFILE with value CKP_BASELINE_PROVIDER" | Yes | **`rust/test_p11_conformance.js` has NO test of `CKO_PROFILE`/`CKA_PROFILE_ID` at all** — confirmed by exhaustive grep, zero hits, still true at HEAD. The real proof is a Rust-native `#[cfg(test)]` unit-test module, `profile_object_ffi_tests`, now at [`rust/src/ffi.rs:20220-20341`](../rust/src/ffi.rs#L20220-L20341) (moved from 15981-16088, then 18997-19125, as the file grew to 23,660 lines — reconfirmed directly at HEAD `8f4deb6e`, not carried forward). `baseline_profile_object_is_public_and_findable` ([line 20270](../rust/src/ffi.rs#L20270)) now asserts **exactly four** `CKO_PROFILE` objects (`assert_eq!(found.len(), 4, ...)`) — WS-11 Phase 1 (2026-08-29) widened both the claim and this test together — findable via `C_FindObjectsInit`/`C_FindObjects` in a session that never logged in, and carrying the sorted id set `[CKP_BASELINE_PROVIDER, CKP_EXTENDED_PROVIDER, CKP_AUTHENTICATION_TOKEN, CKP_PUBLIC_CERTIFICATES_TOKEN]`. Also `client_cannot_create_profile_object` ([line 20302](../rust/src/ffi.rs#L20302)) and `profile_object_is_fully_read_only` ([line 20316](../rust/src/ffi.rs#L20316)). **Cross-engine corroboration has changed**: the differential scenario `env.profile_objects` ([`tests/differential/scenarios.inc:194-215`](../tests/differential/scenarios.inc#L194-L215)) still exists and still records a sorted `profile_ids` string, but the `LEGAL-PROFILE-SET-CLAIMED` exception this document previously cited (C++="1,2", Rust="1") **no longer exists in `tests/differential/exceptions.json`** — confirmed by exhaustive grep for `PROFILE`, zero hits. That is expected, not a regression: once Rust's claim widened to match C++'s four-profile set, the divergence the exception excused stopped occurring, so there is nothing left to except | The framing that made this "the single most important finding" — a search scoped to `rust/test_p11_conformance.js` would wrongly conclude Rust's claim is untested — still holds; the real proof still lives only in `rust/src/ffi.rs`'s native `cargo test` suite |
| 5 | Functions (a-p, same list as §2) | Yes | Exercised as harness scaffolding throughout `rust/test_p11_conformance.js` (every section depends on `C_Initialize`/`C_OpenSession`/etc. succeeding) and throughout `rust/src/ffi.rs`'s broader `#[cfg(test)]` suite | Same caveat as C++: no dedicated named row per function |
| 6 | "Supports the following mechanisms: a. None specified" | Yes (trivially) | N/A | Nothing to test |
| 7 | Error Handling | Yes | Broad coverage across `rust/test_p11_conformance.js`'s many `check()` calls asserting specific `CKR_*` codes | General suite coverage, not profile-specific |
| 8, 9 | Optional clauses | N/A | — | Nothing to prove |

---

## 4. Extended Provider (§5.3) — C++ engine

**Correction (2026-09-04): this section's header used to read "C++ engine
only" and stated Rust does not claim this profile — that was true at the
`a158095` pin (2026-08-23) but has been false since WS-11 Phase 1
(`dea9bfa1`, 2026-08-29).** Rust now claims Extended Provider as part of its
hard-coded four-profile list (`rust/src/state.rs:268-275`, see §1). The
per-condition table below was written for and remains accurate for the
**C++** engine; §4B gives the equivalent (much shorter, since Rust hard-codes
rather than computes) analysis for **Rust**.

> "An implementation conforms to this specification as an Extended Provider
> if it meets the following conditions:" — Profiles v3.2 §5.3

| # | Condition text (verbatim) | Claimed? | Proving test(s) | Notes |
|---|---|---|---|---|
| 1 | "Supports the conditions required by the PKCS #11 conformance clauses ([PKCS11_Spec] Section 7 (PKCS#11 Implementation Conformance)" | Yes | No dedicated test — meta-clause | — |
| 2 | "Supports the conditions required by the PKCS #11 Baseline Provider clauses section5.1" | Yes | See §2 above (Baseline Provider table) | Inherited, not re-tested independently |
| 3 | "Supports the following data types [PKCS11_Spec]: a. CK_MECHANISM_TYPE b. CK_MECHANISM" | Yes | No runtime test — structural, via `pkcs11t.h`; used as literal types at ~2,000+ mechanism-dispatch call sites across the suite | Compile-time only |
| 4 | "Supports the following attributes [PKCS11_Spec]: a. None specified" | Yes (trivially) | N/A | Nothing to test |
| 5 | "Supports the following objects [PKCS11_Spec]: a. CKO_PROFILE with value CKP_EXTENDED_PROVIDER" | Yes (conditionally — computed by `computeSupportedProfiles()`, [lines 1044-1049](../src/lib/SoftHSM_objects.cpp#L1044-L1049), corrected from the stale 981-986 citation) | **No dedicated PASS/FAIL row asserts `CKP_EXTENDED_PROVIDER` presence by name.** `test_profile_objects()` computes an internal `haveExtended` boolean from the same `C_FindObjects` result used for condition 4 above ([line 1489](../p11_v32_compliance_test.cpp#L1489), corrected from 1485 — re-confirmed against HEAD), but only uses it to gate whether `Extended_provider_claim_recorded` runs (PASS/FAIL) or is skipped — it never independently asserts "id 2 was found." **This differential exception no longer exists**: `tests/differential/exceptions.json` has zero hits for `PROFILE` at HEAD (confirmed by exhaustive grep) — the `LEGAL-PROFILE-SET-CLAIMED` entry this row previously cited (justifying C++="1,2" vs Rust="1" as a legal divergence) was for a divergence that stopped occurring once Rust's claim widened to match C++'s (see §1, §3 row 4); the `env.profile_objects` scenario itself is unchanged and still runs | A real, if indirect, gap: the presence of the `CKP_EXTENDED_PROVIDER` object is *observed* but never the subject of its own named assertion the way `CKP_BASELINE_PROVIDER_present` is for condition 4 of Baseline. Unlike the prior revision, there is no longer a differential-exception citation corroborating the observation at all — see §4C for the identical, now also-untested-by-name, gap for Authentication Token / Public Certificates Token |
| 6 | "Supports the following functions [PKCS11_Spec]: a. C_GetMechanismList b. C_GetMechanismInfo c. C_Login d. C_LoginUser e. C_Logout" | Yes | **(a),(b),(c),(e)** — not independently checked at the profile-claim site; the code comment explains why: *"C_GetMechanismList, C_GetMechanismInfo, C_Login, C_Logout (all baseline v2.40 — always present in `fl` if the engine loaded at all, so checking them adds no signal)"*. **Correction: this comment lives in `p11_v32_compliance_test.cpp:1475-1478`, not `SoftHSM_objects.cpp:1475-1478` as the previous revision cited** — the file name was wrong (the near-identical line numbers across two different files is almost certainly how the mistake happened; re-verified directly by grepping the quoted text — zero hits in `SoftHSM_objects.cpp`, exact match in `p11_v32_compliance_test.cpp`). They ARE exercised elsewhere in the suite: `C_GetMechanismList` in `test_mechanism_discovery()` ([line 418](../p11_v32_compliance_test.cpp#L418), confirmed current); `C_GetMechanismInfo` at, e.g., [line 1707](../p11_v32_compliance_test.cpp#L1707) and [line 8636](../p11_v32_compliance_test.cpp#L8636) (both confirmed current); `C_Login`/`C_Logout` in `init_token()` ([lines 402-405](../p11_v32_compliance_test.cpp#L402-L405), confirmed current). **(d) `C_LoginUser`** — this is "the one function whose absence would make a claimed Extended Provider condition false" per the code's own comment ([line 1480](../p11_v32_compliance_test.cpp#L1480), confirmed current, same file correction as above) and is checked **two ways**: (i) `Extended_provider_claim_recorded`, `test_profile_objects()` [lines 1489-1495](../p11_v32_compliance_test.cpp#L1489-L1495) (corrected from 1486-1496) — `dlopen`s the engine and `dlsym`s `"C_LoginUser"`, PASS iff the symbol resolves non-NULL; (ii) a genuine functional call, `test_v30_session()`, category `Session`, check name `"C_LoginUser"` [lines 5372-5373](../p11_v32_compliance_test.cpp#L5372-L5373) (re-confirmed present in that function, exact sub-range not independently re-derived beyond confirming the surrounding function body is unchanged) — actually invokes `C_LoginUser` and asserts the return code is `CKR_USER_ALREADY_LOGGED_IN` or `CKR_OK` | This is the check the 2026-08-23 fix made genuinely conditional. **What it verifies:** the `C_LoginUser` symbol is exported from the loaded shared library (dlsym succeeds) — i.e., the claim is *satisfiable*. **What it does NOT verify:** that `C_GetMechanismList`, `C_GetMechanismInfo`, `C_Login`, or `C_Logout` export/behave correctly *as part of the Extended Provider claim check itself* (though all four are exercised elsewhere, as cited) |
| 7 | "Supports the following mechanisms: a. None specified" | Yes (trivially) | N/A | Nothing to test |
| 8 | "Supports Error Handling [PKCS11_Spec] for any supported object, function or mechanism" | Yes | Same general `ErrCodes`/`G4Retcodes` coverage as Baseline condition 7 | Not profile-specific |
| 9, 10 | Optional clauses | N/A | — | Nothing to prove |

**Wiring check:** `Extended_provider_claim_recorded` is inside
`test_profile_objects()`, confirmed wired in at
[line 10316](../p11_v32_compliance_test.cpp#L10316) (same call site as the
Baseline test — both run from one function invocation). Not `#ifdef`-gated:
the `if (haveExtended)` branch is a runtime condition, not a compile-time
exclusion, so the row always executes (as PASS/FAIL or SKIP) whenever the
category runs.

---

## 4B. Extended Provider (§5.3) — Rust engine (new, 2026-09-04)

Not present in any prior revision of this document — added because §1's
"Rust does not claim Extended Provider" statement was wrong (see the
correction note in §4). The condition list is identical to §4's C++ table;
Rust's proof shape differs because the claim is hard-coded rather than
computed from live function pointers.

Conditions 1-4, 7-10 are identical in kind to §3's Baseline-Provider
analysis for Rust (meta-clause / structural / trivial — no dedicated test
possible or needed). The two conditions worth stating explicitly:

- **Condition 5 (object, `CKO_PROFILE` with `CKP_EXTENDED_PROVIDER`):**
  proven by the same test as §3 row 4 —
  `baseline_profile_object_is_public_and_findable`
  ([`rust/src/ffi.rs:20270`](../rust/src/ffi.rs#L20270)) asserts the full
  4-id set, `CKP_EXTENDED_PROVIDER` included, by name (`assert_eq!(ids,
  vec![CKP_BASELINE_PROVIDER, CKP_EXTENDED_PROVIDER,
  CKP_AUTHENTICATION_TOKEN, CKP_PUBLIC_CERTIFICATES_TOKEN])`). **This is
  stronger than the C++ engine's coverage of the same condition** (§4 row 5
  above): C++ observes `CKP_EXTENDED_PROVIDER`'s presence but never asserts
  it by name; Rust's test does assert it by name, as one element of an
  exact-set equality check.
- **Condition 6 (functions — `C_GetMechanismList`, `C_GetMechanismInfo`,
  `C_Login`, `C_LoginUser`, `C_Logout`):** unlike C++, Rust's claim is not
  gated on any live function-pointer check at all — `supported_profiles()`
  ([`rust/src/state.rs:268-275`](../rust/src/state.rs#L268-L275)) is a fixed
  array, so the claim is unconditionally true by construction rather than
  computed. There is consequently no equivalent of C++'s
  `Extended_provider_claim_recorded` `dlsym` check — **not because Rust has
  weaker coverage of whether the five functions actually exist (they are
  exercised as ordinary harness scaffolding throughout
  `rust/test_p11_conformance.js` and `rust/src/ffi.rs`'s broader test
  suite, same as §3 condition 5), but because the claim itself does not
  depend on a runtime check that could fail** the way C++'s conditional
  `computeSupportedProfiles()` does. This is a genuine asymmetry, not a
  test gap: it is a structural consequence of Rust hard-coding rather than
  computing its profile set, unchanged since this document's original
  Baseline-Provider analysis of the same design choice in §1.

---

## 4C. Authentication Token (§5.4) and Public Certificates Token (§5.5) — both engines (new, 2026-09-04)

**Not discussed anywhere in the prior revision of this document** — the
2026-09-01 staleness note flagged their existence as an unaddressed gap;
this revision closes it. Both engines claim both profiles as of WS-11 Phase
1 (`dea9bfa1`, 2026-08-29):

- **C++**: `computeSupportedProfiles()` claims `CKP_AUTHENTICATION_TOKEN`
  conditionally — `C_Login`, `C_LoginUser`, `C_Logout`, `C_SignInit`, and
  (`C_Sign` or `C_SignUpdate`+`C_SignFinal`) must all be non-NULL
  ([`src/lib/SoftHSM_objects.cpp:1055-1060`](../src/lib/SoftHSM_objects.cpp#L1055-L1060))
  — and claims `CKP_PUBLIC_CERTIFICATES_TOKEN` **unconditionally**
  ([`src/lib/SoftHSM_objects.cpp:1062-1069`](../src/lib/SoftHSM_objects.cpp#L1062-L1069)),
  with the code comment's own rationale: `CKO_CERTIFICATE` creation is not
  gated by any `WITH_*` build flag the way mechanisms are, so the claim
  "needs no runtime probe beyond Baseline itself."
- **Rust**: both are part of the same hard-coded four-entry
  `supported_profiles()` array as Extended Provider (§4B) — unconditional
  by construction, same asymmetry noted there.

**Test coverage, verified directly rather than assumed:**

- **C++**: `grep -n "CKP_AUTHENTICATION_TOKEN\|CKP_PUBLIC_CERTIFICATES_TOKEN"
  p11_v32_compliance_test.cpp` returns **zero hits**. `test_profile_objects()`
  ([line 1425](../p11_v32_compliance_test.cpp#L1425)) only ever names
  `P_BASELINE`/`P_EXTENDED` as local constants
  ([lines 1438-1439](../p11_v32_compliance_test.cpp#L1438-L1439)) — the ids
  found for Authentication Token (3) and Public Certificates Token (4) flow
  into the `idList` string embedded in other rows' PASS messages (so a
  human reading test output can see "profile ids: [ 1 2 3 4 ]"), but
  **no row asserts their presence by name or fails if either is absent**.
  This is the same category of gap as §4 row 5 (`CKP_EXTENDED_PROVIDER`
  unasserted-by-name), now affecting two more profiles, and with no
  differential-exception citation to fall back on either (see §4 row 5's
  correction).
- **Rust**: covered, by name, as part of the same exact-set assertion
  described in §4B —
  `baseline_profile_object_is_public_and_findable`
  ([`rust/src/ffi.rs:20270`](../rust/src/ffi.rs#L20270)) would fail if
  either id were missing from the token's published set. **This makes
  Rust's traceability for these two profiles' object condition strictly
  better than C++'s** — the reverse of the general pattern elsewhere in
  this document, where C++'s `p11_v32_compliance_test.cpp` is usually the
  more thoroughly-instrumented suite.
- **Neither engine's function conditions** (§5.4's `C_SignInit`+`C_Sign`
  requirement, §5.5's implicit `CKO_CERTIFICATE`-creation requirement) have
  any dedicated named test at the profile-claim site in either engine —
  consistent with the same "exercised elsewhere as harness scaffolding,
  not asserted at the claim site" pattern already documented for Baseline
  condition 5 and Extended condition 6 above.

**Bottom line:** both new claims are real (the code genuinely computes or
hard-codes them) but under-tested by name on the C++ side specifically —
this is a traceability gap to flag, not a false claim to correct. No
fabrication: this section states only what was directly confirmed by
reading the cited source at HEAD `8f4deb6e`.

---

## 5. Complete Provider (§5.2) — deliberately not claimed by either engine

> "An implementation conforms to this specification as a Complete Provider
> if it meets the following conditions: ... 6. Supports all mechanisms
> [PKCS11_Spec] Section 6." — Profiles v3.2 §5.2

Neither engine computes or publishes `CKP_COMPLETE_PROVIDER`. This is
deliberate and documented at the exact point the claim would otherwise be
generated.

**C++ source comment**, `SoftHSM::computeSupportedProfiles()`,
[`src/lib/SoftHSM_objects.cpp:988-991`](../src/lib/SoftHSM_objects.cpp#L988-L991)
(quoted verbatim):

> ```
> // CKP_COMPLETE_PROVIDER is deliberately NOT claimed: §5.2 requires support
> // for ALL mechanisms in [PKCS11_Spec] section 6, which this build does not
> // have (its mechanism list is trimmed by WITH_* build flags). Claiming it
> // would turn this fix into a fresh conformance violation.
> ```

**Rust source comment**, `init_profile_objects()`,
[`rust/src/state.rs:223-226`](../rust/src/state.rs#L223-L226) (quoted
verbatim, same rationale by inheritance — Rust hard-codes a single-item
profile list and has never added Complete or Extended):

> ```
> /// read-only (CKA_MODIFIABLE/COPYABLE/DESTROYABLE all FALSE — apply_object_defaults
> /// would otherwise default them to TRUE). Baseline Provider is the only
> /// profile this engine currently claims conformance to; add further profile
> /// objects here only after auditing every Profiles v3.2 requirement for
> /// that profile (see rust/RUST_P11_V32_CONFORMANCE_REPORT.md).
> ```

**Audit trail — this was once a false claim, corrected.** `CHANGELOG.md`
[lines 130-140](../CHANGELOG.md#L130-L140), under the `[0.23.0]` entry,
documents that an earlier version of this repository's own reasoning
asserted "no profile mandates any mechanism" — which was wrong — and was
corrected:

> "*Corrected 2026-08-14: an earlier wording claimed no profile mandates any
> mechanism. That is wrong — Complete Provider (§5.2 condition 6) requires
> "Supports all mechanisms [PKCS11_Spec] Section 6", and under that profile
> these divergences WOULD be defects. Neither engine claims it,
> deliberately.*"

The correcting commit is `git log --oneline` entry `3f64964`: *"Correct a
published false claim: Complete Provider does mandate every mechanism
(#174)."* Both engines' mechanism lists are trimmed by build-time feature
flags (`WITH_*` in C++; Cargo feature flags in Rust) and neither implements
every mechanism in [PKCS11_Spec] §6, so claiming `CKP_COMPLETE_PROVIDER`
today would itself be a fresh conformance violation of exactly the kind this
whole programme exists to eliminate — which is why it is not claimed by
either.

---

## 6. PQC mechanism implementation status — C++ engine (new, 2026-09-04)

**Why this section exists, and why it is scoped differently from §1-§5
above.** Everything above this line traces PKCS#11 Profiles v3.2 §5
*profile conditions* — data types, attributes, objects, functions, error
handling. None of the profiles either engine claims (Baseline, Extended,
Authentication Token, Public Certificates Token) mandates support for any
specific mechanism (each says, verbatim, "Supports the following
mechanisms: a. None specified" — condition 6/7 throughout §2-§4C). Complete
Provider is the *only* profile that mandates mechanism support (§5
condition 6, "Supports all mechanisms"), and neither engine claims it,
deliberately (§5). **Strictly by the profile-conditions logic above, this
document could stop at §5 and every claim it makes would still be fully
accurate.** But this repository's entire purpose (per its own `CLAUDE.md`)
is PQC — ML-DSA, ML-KEM, SLH-DSA, and stateful HSS/XMSS/XMSS-MT — and a
"PKCS#11 profile traceability" document that never says whether *those*
mechanisms actually work would be misleading by omission, whatever the
profile-conditions technicality says. This section closes that gap.
**Everything below was verified directly against dispatch code at HEAD
`8f4deb6e`** — grepping `case CKM_...`/`CKR_MECHANISM_INVALID` in
`SoftHSM_sign.cpp`, `SoftHSM_keygen.cpp`, `SoftHSM_kem.cpp`, and the
crypto-backend `OSSL*.cpp` files, plus `SoftHSM::prepareSupportedMechanisms()`
([`src/lib/SoftHSM_slots.cpp:419-670`](../src/lib/SoftHSM_slots.cpp#L419-L670))
for what is actually *advertised* via `C_GetMechanismList` — not copied from
any prior gap-analysis document (several exist under `docs/`, e.g.
`gap-analysis-pkcs11-v3.2.md`, but that one explicitly marks itself
"historical... kept for provenance," 2026-06, and this section does not
rely on it for any claim below).

**For three different readers:**
- **End users** (want to know: can I actually use algorithm X here?): every
  row marked **IMPLEMENTED** below has real dispatch code that calls a real
  cryptographic backend — not a stub that returns success without doing
  anything, and not advertised-but-rejected. Rows marked otherwise say so
  explicitly.
- **System engineers / operators** (want to know: what's stable enough to
  deploy on?): the one row that needs a caveat is **ML-DSA external-µ**
  (`CKM_ML_DSA_EXTERNAL_MU`/`_GEN`) — real, dispatched code, but its
  codepoints come from the **PKCS#11 v3.3 working draft**, not the ratified
  v3.2 standard this document is otherwise about, and the draft's own
  status is "proposed," not final. Treat it as pre-standard.
- **Developers** (want to know: where's the code?): every row below cites
  the dispatch file:line and the crypto-backend file(s).

| PQC mechanism family | Standard | Key `CKM_`/`CKK_` values | Status | Evidence |
|---|---|---|---|---|
| **ML-KEM** | FIPS 203 | `CKM_ML_KEM_KEY_PAIR_GEN` (`0x0f`), `CKM_ML_KEM` (`0x17`), `CKK_ML_KEM` (`0x49`) | **IMPLEMENTED** | Keygen dispatch: [`SoftHSM_keygen.cpp:566,710`](../src/lib/SoftHSM_keygen.cpp#L566). Encapsulate/decapsulate: `C_EncapsulateKey` at [`SoftHSM_kem.cpp:126`](../src/lib/SoftHSM_kem.cpp#L126) (impl `encapsulateKeyImpl` at [172](../src/lib/SoftHSM_kem.cpp#L172)), `C_DecapsulateKey` at [461](../src/lib/SoftHSM_kem.cpp#L461) (impl `decapsulateKeyImpl` at [505](../src/lib/SoftHSM_kem.cpp#L505)) — real, only `CKM_ML_KEM` and `CKM_ECDH1_DERIVE` are accepted, everything else returns `CKR_MECHANISM_INVALID` ([line 194-197](../src/lib/SoftHSM_kem.cpp#L194-L197)); the classical `CKM_ECDH1_DERIVE`-as-KEM arms are separate functions, `encapsulateECDH`/`decapsulateECDH` at [773](../src/lib/SoftHSM_kem.cpp#L773)/[1089](../src/lib/SoftHSM_kem.cpp#L1089) (see the Hybrid/composite row below). Backend: `OSSLMLKEM.cpp`, `OSSLMLKEMKeyPair.cpp`, `OSSLMLKEMPrivateKey.cpp`, `OSSLMLKEMPublicKey.cpp` (all present under `src/lib/crypto/`) |
| **ML-DSA** | FIPS 204 | `CKM_ML_DSA_KEY_PAIR_GEN` (`0x1c`), `CKM_ML_DSA` (`0x1d`), `CKM_HASH_ML_DSA` + 9 typed hash variants (`0x1f`, `0x23`-`0x2c`), `CKK_ML_DSA` (`0x4a`) | **IMPLEMENTED** | Sign dispatch: [`SoftHSM_sign.cpp:1141-1215`](../src/lib/SoftHSM_sign.cpp#L1141-L1215); mirrored verify dispatch: [`SoftHSM_sign.cpp:2849-2918`](../src/lib/SoftHSM_sign.cpp#L2849-L2918). Keygen: [`SoftHSM_keygen.cpp:560,599,690`](../src/lib/SoftHSM_keygen.cpp#L560). Backend: `OSSLMLDSA.cpp`, `OSSLMLDSAKeyPair.cpp`, `OSSLMLDSAPrivateKey.cpp`, `OSSLMLDSAPublicKey.cpp` |
| **ML-DSA external-µ** | PKCS#11 **v3.3 draft** (not v3.2) | `CKM_ML_DSA_EXTERNAL_MU` (`0x403c`), `CKM_ML_DSA_EXTERNAL_MU_GEN` (`0x403b`) | **IMPLEMENTED, pre-ratification** | Codepoints defined in [`src/lib/vendor_mechanisms.h:54,81`](../src/lib/vendor_mechanisms.h#L54), whose own header comment calls them "the v3.3 draft's own name and codepoint... same 'proposed', not-yet-ratified caveat." **Confirmed absent from `pkcs11t.h`** (zero grep hits for either name) — they are real, dispatched mechanisms but not part of the ratified v3.2 standard the rest of this document traces. Sign dispatch: [`SoftHSM_sign.cpp:1217-1247`](../src/lib/SoftHSM_sign.cpp#L1217-L1247), verify: [`2920-2950`](../src/lib/SoftHSM_sign.cpp#L2920-L2950) |
| **SLH-DSA** | FIPS 205 | `CKM_SLH_DSA_KEY_PAIR_GEN` (`0x2d`), `CKM_SLH_DSA` (`0x2e`), `CKM_HASH_SLH_DSA` + 9 typed hash variants (`0x34`, `0x36`-`0x3f`), `CKK_SLH_DSA` (`0x4b`) | **IMPLEMENTED** | Sign dispatch: [`SoftHSM_sign.cpp:1248-1321`](../src/lib/SoftHSM_sign.cpp#L1248-L1321); verify: [`2951-3024`](../src/lib/SoftHSM_sign.cpp#L2951-L3024). Keygen: [`SoftHSM_keygen.cpp:563,601,700`](../src/lib/SoftHSM_keygen.cpp#L563). Backend: `OSSLSLHDSA.cpp`, `OSSLSLHDSAKeyPair.cpp`, `OSSLSLHDSAPrivateKey.cpp`, `OSSLSLHDSAPublicKey.cpp` |
| **HSS** (stateful hash-based) | RFC 8554, PKCS#11 v3.2 §6.65 | `CKM_HSS_KEY_PAIR_GEN` (`0x4032`), `CKM_HSS` (`0x4033`), `CKK_HSS` (`0x46`) | **IMPLEMENTED** | Sign-init dispatch `StatefulSignInit`: [`SoftHSM_sign.cpp:1500`](../src/lib/SoftHSM_sign.cpp#L1500), routed from `C_SignInit` at [line 1540](../src/lib/SoftHSM_sign.cpp#L1540); verify-side equivalent at [line 3196](../src/lib/SoftHSM_sign.cpp#L3196)/[3315](../src/lib/SoftHSM_sign.cpp#L3315). Keygen: [`SoftHSM_keygen.cpp:569,607,723-840`](../src/lib/SoftHSM_keygen.cpp#L569). Backend: vendored `src/lib/crypto/stateful/hash-sigs/` (28 files, RFC 8554 reference implementation) |
| **XMSS / XMSS-MT** (stateful hash-based) | RFC 8391, NIST SP 800-208, PKCS#11 v3.2 §6.66 | `CKM_XMSS(_KEY_PAIR_GEN)` (`0x4036`/`0x4034`), `CKM_XMSSMT(_KEY_PAIR_GEN)` (`0x4037`/`0x4035`), `CKK_XMSS`/`CKK_XMSSMT` (`0x47`/`0x48`) | **IMPLEMENTED** | Codepoints are hardcoded as literal hex in `SoftHSM_slots.cpp` rather than via the `CKM_*` macro names, but the literals exactly match `pkcs11t.h`'s definitions ([`pkcs11t.h:1207-1210`](../src/lib/pkcs11/pkcs11t.h#L1207-L1210)) — confirmed byte-for-byte, not a vendor-range value (a header comment nearby, [`pkcs11t.h:1258-1271`](../src/lib/pkcs11/pkcs11t.h#L1258-L1271), warns these specific codepoints were once squatted on by an unrelated mechanism and must never be reused — current values are the correct, final OASIS assignment). Sign/verify dispatch: same `StatefulSignInit`/`StatefulVerify` machinery as HSS above ([`SoftHSM_sign.cpp:1502,1504,1541`](../src/lib/SoftHSM_sign.cpp#L1502)/[3198,3200,3316](../src/lib/SoftHSM_sign.cpp#L3198)). Keygen: [`SoftHSM_keygen.cpp:572,575,609,611,753-840`](../src/lib/SoftHSM_keygen.cpp#L572). Backend: vendored `src/lib/crypto/stateful/xmss-reference/` (RFC 8391 reference implementation). **Not affected** by the 9-parameter-set XMSS bug `CHANGELOG.md` [0.28.1] fixed — that entry is explicit it was Rust-only, and names the C++ engine's "independent RFC 8391 implementation" as the correctness oracle used to find the Rust bug |
| **One-time-signature key protection** (`CKA_SENSITIVE`/`CKA_EXTRACTABLE`/`CKA_COPYABLE`) | PKCS#11 v3.2 §6.65.3/§6.66.4-5 | Applies to `CKO_PRIVATE_KEY` objects of type `CKK_HSS`/`CKK_XMSS`/`CKK_XMSSMT` | **IMPLEMENTED** (closed 2026-09-03, shipped as `CHANGELOG.md` [0.28.2]) | [`SoftHSM_objects.cpp:1196-1290`](../src/lib/SoftHSM_objects.cpp#L1196-L1290) — forces `CKA_SENSITIVE=TRUE`, `CKA_EXTRACTABLE=FALSE`, `CKA_COPYABLE=FALSE` at every object-creation path (`C_CreateObject` and `C_GenerateKeyPair` both route through this one function) for **all three** key types; a template may restate the value, never contradict it (`CKR_ATTRIBUTE_VALUE_INVALID` otherwise). **This corrects a real prior gap**: before this fix, only `CKA_COPYABLE` for HSS was forced (§6.65.3 names it explicitly); XMSS/XMSS-MT had no enforcement because §6.66.4-5 don't repeat that sentence, even though the underlying one-time-leaf-reuse forgery hazard is identical — the C++ half of the same fix the Rust engine needed more of (Rust additionally lacked `CKA_SENSITIVE`/`CKA_EXTRACTABLE` enforcement entirely; C++ already had those two). Test: `test_hbs_key_protection()`, [`p11_v32_compliance_test.cpp:1289`](../p11_v32_compliance_test.cpp#L1289), wired into the default run at [line 10639](../p11_v32_compliance_test.cpp#L10639) |
| **Hybrid / composite KEM** (e.g. X25519MLKEM768, SecP256r1MLKEM768) | draft-ietf-tls-hybrid-design and similar; no PKCS#11 v3.2 mechanism exists for this | n/a — no dedicated `CKM_` codepoint in this engine | **NOT IMPLEMENTED AS A SINGLE MECHANISM — BY DESIGN, documented, not a gap** | Per this repo's own `CLAUDE.md`: the named hybrid-KEM combiner is "a Rust-engine + KMIP feature" (`rust/src/native/hybrid.rs`), exposed via KMIP/CACP. The C++ engine's role is the generic classical-KEM building block — `CKM_ECDH1_DERIVE` reachable through `C_EncapsulateKey`/`C_DecapsulateKey` ([`SoftHSM_kem.cpp:190,524`](../src/lib/SoftHSM_kem.cpp#L190)) — which a caller combines with `CKM_ML_KEM` and `CKM_CONCATENATE_BASE_AND_KEY` themselves to build the same construction one KDF step at a time. `CKM_SHAKE_256_KEY_DERIVATION` was added specifically to support this kind of construction (X-Wing's 96-byte expansion), per its own comment at [`SoftHSM_slots.cpp:503`](../src/lib/SoftHSM_slots.cpp#L503). The Rust engine's native `CKM_HPKE` mechanism (a real single-call hybrid-KEM+AEAD combiner, added per `CHANGELOG.md` `[0.28.0]`) is **explicitly not** extended to C++: that entry states "Rust engine only; C++ engine parity is a separately gated follow-on" |

**What this section deliberately does NOT cover** (out of scope, not
overlooked): classical mechanisms (RSA, ECDSA, ECDH, EdDSA, AES, HMAC,
etc.) — those aren't this fork's differentiator and aren't what "PQC
mechanisms are the whole point of this fork" refers to. Two specific
CHANGELOG items worth a one-line disposition since they're recent and
sound C++-adjacent: **`CKM_AES_CCM`/`CKM_AES_XTS`/`CKM_AES_GMAC`
multi-part-streaming fixes and the widened HMAC-digest set in
`CHANGELOG.md` `[0.28.0]` are both explicitly Rust-engine-only** (each
entry is headed "Rust engine:" and the HKDF entry in the same release
states outright "The C++ engine's equivalent path was already correct —
this was Rust-only") — **no correction to this document was needed for
either**, because this document never claimed otherwise and the C++
dispatch code for those three AEAD mechanisms was independently confirmed
present and unmodified by this pass.

---

## 7. Summary

| Profile | Total conditions | Directly proven by a named test | Structural / meta / trivial (no test needed) | Documented gap |
|---|---|---|---|---|
| Baseline Provider — C++ | 9 | 4 (attributes, objects) | 4 (data types, mechanisms, optional×2) | 1 (functions — no per-function named row; scaffolding-only proof) |
| Baseline Provider — Rust | 9 | 4 (attributes, objects — via `rust/src/ffi.rs`, NOT `test_p11_conformance.js`) | 4 | 1 (functions — same as C++) |
| Extended Provider — C++ | 10 | 2 (functions [C_LoginUser only, twice], inherited Baseline) | 5 (inherited meta, data types, attributes, mechanisms, optional×2) | 1 (objects — CKP_EXTENDED_PROVIDER presence observed but never independently asserted by name, and the differential-exception citation that used to corroborate it is now gone — see §4 row 5); 4 of condition 6's 5 named functions not checked at the claim site itself (though exercised elsewhere) |
| Extended Provider — Rust (new, §4B) | 10 | 3 (attributes, objects — asserted **by name** as part of the 4-id exact-set check, unlike C++; inherited Baseline) | 5 (inherited meta, data types, attributes, mechanisms, optional×2) | 0 for the object condition (stronger than C++ here); the functions condition has no dedicated check at all, but as a structural consequence of the claim being hard-coded rather than computed — not a coverage gap |
| Authentication Token — both engines (new, §4C) | Not enumerated per-condition in this document | 0 named — object presence flows into other rows' output text (C++) or the same exact-set assertion (Rust), function condition (C_SignInit+C_Sign) untested at claim site on both | — | Object condition: C++ untested-by-name (same category as Extended Provider); Rust tested-by-name. Function condition: untested at claim site on both engines |
| Public Certificates Token — both engines (new, §4C) | Not enumerated per-condition in this document | Same pattern as Authentication Token | — | Same as Authentication Token |
| Complete Provider — both | 8 | N/A — not claimed | — | N/A — deliberately not claimed, rationale quoted in §5 |
| **PQC mechanisms — C++ (new, §6)** | 6 families + 1 protection property | All 6 mechanism families confirmed **IMPLEMENTED** with real dispatch + backend code (ML-KEM, ML-DSA, ML-DSA external-µ [pre-ratification], SLH-DSA, HSS, XMSS/XMSS-MT); key-protection property confirmed IMPLEMENTED (closed 2026-09-03) | — | Hybrid/composite KEM has no single dedicated mechanism — by design (Rust-engine + KMIP feature), not a C++ gap |

**The one condition this document could NOT find a real test for, full
stop:** none — every numbered condition in §2-§4C has either a real test, a
structural/meta/trivial reason no test is possible, or an explicitly
documented partial-coverage gap (the object-presence gaps for Extended
Provider [C++], Authentication Token, and Public Certificates Token; the
"functions" conditions across every profile lacking a per-function named
assertion at the claim site). The most significant finding, unchanged since
the original revision of this document, is not an untested condition but a
**misdirected search target**: `rust/test_p11_conformance.js` — the file
most likely to be checked first — has zero coverage of the Rust engine's
`CKO_PROFILE` claim for *any* of its four profiles; the real proof lives in
`rust/src/ffi.rs`'s native `cargo test` suite instead. A future auditor who
checks only the JS file would wrongly conclude Rust's profile claims are
untested. **This 2026-09-04 revision's own most significant finding**:
the previous revision's §1 and §4 made a claim ("Rust does not claim
Extended Provider") that was simply wrong at HEAD — not stale, wrong — a
reminder that even a document whose stated purpose is re-deriving every
claim from source on every audit will still go wrong the moment code
changes between audits and the document isn't re-verified. §6 adds the one
dimension the profile-conditions analysis structurally cannot see: whether
this fork's actual PQC mechanisms work. They do, C++-engine-side, with one
pre-ratification caveat (ML-DSA external-µ) and one by-design absence
(single-mechanism hybrid KEM) — both documented, neither fabricated.
