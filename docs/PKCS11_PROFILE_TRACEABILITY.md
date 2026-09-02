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
[`src/lib/SoftHSM_objects.cpp:949-993`](../src/lib/SoftHSM_objects.cpp#L949-L993).
It checks the live `CK_FUNCTION_LIST_3_2` for 16 non-NULL function pointers
and, if all are present, claims **`CKP_BASELINE_PROVIDER`**
([line 977](../src/lib/SoftHSM_objects.cpp#L977)); if 5 further pointers are
also present, it additionally claims **`CKP_EXTENDED_PROVIDER`**
([line 986](../src/lib/SoftHSM_objects.cpp#L986)). It never computes or
claims `CKP_COMPLETE_PROVIDER` — see §4 below for the exact rationale, quoted
from source.

**Rust (`softhsmrustv3`)** hard-codes its claim — `init_profile_objects()`,
[`rust/src/state.rs:227-246`](../rust/src/state.rs#L227-L246) — publishing
exactly one `CKO_PROFILE` object carrying **`CKP_BASELINE_PROVIDER`**
([line 239](../rust/src/state.rs#L239)). The function's own doc comment is
explicit: *"Baseline Provider is the only profile this engine currently
claims conformance to; add further profile objects here only after auditing
every Profiles v3.2 requirement for that profile"*
([lines 223-226](../rust/src/state.rs#L223-L226)). Rust does **not** claim
Extended or Complete Provider.

| Profile | C++ (`softhsmv3`) | Rust (`softhsmrustv3`) |
|---|---|---|
| Baseline Provider (§5.1) | Claimed | Claimed |
| Complete Provider (§5.2) | **Not** claimed (deliberate) | **Not** claimed (deliberate) |
| Extended Provider (§5.3) | Claimed (conditionally, computed) | **Not** claimed |

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
| 4 | "Supports the following objects [PKCS11_Spec]: a. CKO_PROFILE with value CKP_BASELINE_PROVIDER" | Yes | **`rust/test_p11_conformance.js` has NO test of `CKO_PROFILE`/`CKA_PROFILE_ID` at all** — confirmed by exhaustive grep, zero hits. The real proof is a Rust-native `#[cfg(test)]` unit-test module, `profile_object_ffi_tests`, [`rust/src/ffi.rs:15981-16088`](../rust/src/ffi.rs#L15981-L16088): `baseline_profile_object_is_public_and_findable` ([line 16031](../rust/src/ffi.rs#L16031)) — asserts exactly one `CKO_PROFILE` object exists, is findable via `C_FindObjectsInit`/`C_FindObjects` in a session that never logged in (`setup()`, [line 15990](../rust/src/ffi.rs#L15990), does not call any login function — so "findable without login" is genuinely exercised, not just asserted in a comment), and carries `CKA_PROFILE_ID == CKP_BASELINE_PROVIDER`. Also `client_cannot_create_profile_object` ([line 16049](../rust/src/ffi.rs#L16049)) and `profile_object_is_fully_read_only` ([line 16063](../rust/src/ffi.rs#L16063)). Cross-engine corroboration (comparative, not independent): differential scenario `env.profile_objects`, [`tests/differential/scenarios.inc:194-215`](../tests/differential/scenarios.inc#L194-L215), whose captured divergence (`profile_ids`: C++ = "1,2", Rust = "1") is adjudicated `legal` in [`tests/differential/exceptions.json:92-99`](../tests/differential/exceptions.json#L92-L99) | **This is the single most important finding in this document.** The file the task brief pointed at (`rust/test_p11_conformance.js`) contains zero coverage of the Rust engine's core profile-conformance claim; the real proof lives in a different file (`rust/src/ffi.rs`, native `cargo test`) that a search scoped only to `test_p11_conformance.js` would miss entirely. `cargo test` run from `rust/` exercises this package's own test suite unmodified (per `rust/Cargo.toml`'s own comment, [line 12-ish](../rust/Cargo.toml)) — not feature-gated, runs by default |
| 5 | Functions (a-p, same list as §2) | Yes | Exercised as harness scaffolding throughout `rust/test_p11_conformance.js` (every section depends on `C_Initialize`/`C_OpenSession`/etc. succeeding) and throughout `rust/src/ffi.rs`'s broader `#[cfg(test)]` suite | Same caveat as C++: no dedicated named row per function |
| 6 | "Supports the following mechanisms: a. None specified" | Yes (trivially) | N/A | Nothing to test |
| 7 | Error Handling | Yes | Broad coverage across `rust/test_p11_conformance.js`'s many `check()` calls asserting specific `CKR_*` codes | General suite coverage, not profile-specific |
| 8, 9 | Optional clauses | N/A | — | Nothing to prove |

---

## 4. Extended Provider (§5.3) — C++ engine only

Rust does not claim this profile — `constants.rs` defines
`CKP_EXTENDED_PROVIDER` but `state.rs`'s `init_profile_objects()` never
pushes it, and no other Rust source path claims it (confirmed: the only
other appearance of `CKP_EXTENDED_PROVIDER` anywhere under `rust/src/` is as
an arbitrary forged-attribute test value inside
`client_cannot_create_profile_object`,
[`rust/src/ffi.rs:16054`](../rust/src/ffi.rs#L16054) — not a claim).

> "An implementation conforms to this specification as an Extended Provider
> if it meets the following conditions:" — Profiles v3.2 §5.3

| # | Condition text (verbatim) | Claimed? | Proving test(s) | Notes |
|---|---|---|---|---|
| 1 | "Supports the conditions required by the PKCS #11 conformance clauses ([PKCS11_Spec] Section 7 (PKCS#11 Implementation Conformance)" | Yes | No dedicated test — meta-clause | — |
| 2 | "Supports the conditions required by the PKCS #11 Baseline Provider clauses section5.1" | Yes | See §2 above (Baseline Provider table) | Inherited, not re-tested independently |
| 3 | "Supports the following data types [PKCS11_Spec]: a. CK_MECHANISM_TYPE b. CK_MECHANISM" | Yes | No runtime test — structural, via `pkcs11t.h`; used as literal types at ~2,000+ mechanism-dispatch call sites across the suite | Compile-time only |
| 4 | "Supports the following attributes [PKCS11_Spec]: a. None specified" | Yes (trivially) | N/A | Nothing to test |
| 5 | "Supports the following objects [PKCS11_Spec]: a. CKO_PROFILE with value CKP_EXTENDED_PROVIDER" | Yes (conditionally — computed by `computeSupportedProfiles()`, [line 981-986](../src/lib/SoftHSM_objects.cpp#L981-L986)) | **No dedicated PASS/FAIL row asserts `CKP_EXTENDED_PROVIDER` presence by name.** `test_profile_objects()` computes an internal `haveExtended` boolean from the same `C_FindObjects` result used for condition 4 above ([line 1485](../p11_v32_compliance_test.cpp#L1485)), but only uses it to gate whether `Extended_provider_claim_recorded` runs (PASS/FAIL) or is skipped — it never independently asserts "id 2 was found." The differential harness's `env.profile_objects` scenario *does* capture the actual `profile_ids` string (which includes "2" for C++) and that fact is recorded — as prose, not an assertion — in the `LEGAL-PROFILE-SET-CLAIMED` exception justification, [`tests/differential/exceptions.json:97`](../tests/differential/exceptions.json#L97): *"C++ publishes CKO_PROFILE ids 1 and 2 (Baseline Provider and Extended Provider)."* | A real, if indirect, gap: the presence of the `CKP_EXTENDED_PROVIDER` object is *observed* (twice) but never the subject of its own named assertion the way `CKP_BASELINE_PROVIDER_present` is for condition 4 of Baseline |
| 6 | "Supports the following functions [PKCS11_Spec]: a. C_GetMechanismList b. C_GetMechanismInfo c. C_Login d. C_LoginUser e. C_Logout" | Yes | **(a),(b),(c),(e)** — not independently checked at the profile-claim site; the code comment explains why: *"C_GetMechanismList, C_GetMechanismInfo, C_Login, C_Logout (all baseline v2.40 — always present in `fl` if the engine loaded at all, so checking them adds no signal)"* ([`SoftHSM_objects.cpp:1475-1478`](../src/lib/SoftHSM_objects.cpp#L1475-L1478)). They ARE exercised elsewhere in the suite: `C_GetMechanismList` in `test_mechanism_discovery()` ([line 418](../p11_v32_compliance_test.cpp#L418)); `C_GetMechanismInfo` at, e.g., [line 1707](../p11_v32_compliance_test.cpp#L1707) and [line 8636](../p11_v32_compliance_test.cpp#L8636); `C_Login`/`C_Logout` in `init_token()` ([lines 402-405](../p11_v32_compliance_test.cpp#L402-L405)). **(d) `C_LoginUser`** — this is "the one function whose absence would make a claimed Extended Provider condition false" per the code's own comment ([line 1480](../p11_v32_compliance_test.cpp#L1480)) and is checked **two ways**: (i) `Extended_provider_claim_recorded`, `test_profile_objects()` [lines 1486-1496](../p11_v32_compliance_test.cpp#L1486-L1496) — `dlopen`s the engine and `dlsym`s `"C_LoginUser"`, PASS iff the symbol resolves non-NULL; (ii) a genuine functional call, `test_v30_session()`, category `Session`, check name `"C_LoginUser"` [lines 5367-5382](../p11_v32_compliance_test.cpp#L5367-L5382) — actually invokes `C_LoginUser` and asserts the return code is `CKR_USER_ALREADY_LOGGED_IN` or `CKR_OK` | This is the check the 2026-08-23 fix made genuinely conditional. **What it verifies:** the `C_LoginUser` symbol is exported from the loaded shared library (dlsym succeeds) — i.e., the claim is *satisfiable*. **What it does NOT verify:** that `C_GetMechanismList`, `C_GetMechanismInfo`, `C_Login`, or `C_Logout` export/behave correctly *as part of the Extended Provider claim check itself* (though all four are exercised elsewhere, as cited) |
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

## 6. Summary

| Profile | Total conditions | Directly proven by a named test | Structural / meta / trivial (no test needed) | Documented gap |
|---|---|---|---|---|
| Baseline Provider — C++ | 9 | 4 (attributes, objects) | 4 (data types, mechanisms, optional×2) | 1 (functions — no per-function named row; scaffolding-only proof) |
| Baseline Provider — Rust | 9 | 4 (attributes, objects — via `rust/src/ffi.rs`, NOT `test_p11_conformance.js`) | 4 | 1 (functions — same as C++) |
| Extended Provider — C++ | 10 | 2 (functions [C_LoginUser only, twice], inherited Baseline) | 5 (inherited meta, data types, attributes, mechanisms, optional×2) | 1 (objects — CKP_EXTENDED_PROVIDER presence observed but never independently asserted by name); 4 of condition 6's 5 named functions not checked at the claim site itself (though exercised elsewhere) |
| Complete Provider — both | 8 | N/A — not claimed | — | N/A — deliberately not claimed, rationale quoted in §5 |

**The one condition this document could NOT find a real test for, full
stop:** none — every numbered condition has either a real test, a
structural/meta/trivial reason no test is possible, or an explicitly
documented partial-coverage gap (Extended Provider condition 5's object
presence, and both profiles' condition 5/6 "functions" conditions lacking a
per-function named assertion at the claim site). The most significant
finding is not an untested condition but a **misdirected search target**:
`rust/test_p11_conformance.js` — the file most likely to be checked first —
has zero coverage of the Rust engine's `CKO_PROFILE` claim; the real proof
lives in `rust/src/ffi.rs`'s native `cargo test` suite instead. A future
auditor who checks only the JS file, as this task's own step 3 initially
suggested doing, would wrongly conclude Rust's Baseline Provider claim is
untested.
