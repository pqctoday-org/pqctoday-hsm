# KMIP 3.0 "Honest Maximum" — Implementation Plan

> **Status:** ✅ EXECUTED — all in-scope phases (0-4, 6, 7) complete 2026-07-08; Phase 5
> (server-to-client) remains deliberately parked, as planned. · **Authored:** 2026-07-07
> **Scope target:** 100% of the non-deprecated OASIS corpus (**97/102**), **zero faked operations**,
> **HSS/LMS signing wired**, **broad asynchronous operations**, and **all Baseline Server profile
> conditions except item 10 (server-to-client), which is deliberately parked.**
> **Honest conformance claim after completion:** *"OASIS KMIP 3.0 (CSD01 corpus) + WD19 PQC
> extensions — Baseline Server profile except the parked server-to-client operations (item 10).
> Drafts, not a ratified Standard."*

**Anchor:** the OASIS KMIP 3.0 specification documents in `../spec/oasis-kmip-3.0/`
(`kmip-spec-v3.0.{pdf,docx,html}` = CSD01, 23 Aug 2024; `kmip-spec-v3.0-wd19-clean.pdf` = WD19,
14 Feb 2025) and `kmip-profiles-v3.0` (Baseline Server conditions). Every § below was verified
against the spec text; every `file:line` was verified against the current tree. The repo's own
extraction JSON and prose docs are treated as claims, not authority.

---

## 0. Decisions folded into this plan

| # | Decision | Consequence |
|---|---|---|
| D1 | **HSS must be supported — wire the existing Rust engine capability** | Phase 1.5 = engine-layer sign wiring (no KMIP-side state). |
| D2 | **Asynchronous operations: broad, per the spec** | Phase 4 implements the full async model (§8.1.2), not a narrow subset. |
| D3 | **Server-to-client channel (Notify/Put): parked** | Phase 5 deferred → the claim is *"Baseline except item 10"*, **not full Baseline** (see §Accepted facts). |
| D4 | **DES / 3DES / DSA: declined by security policy** | The 5 deprecated corpus tests stay declined (NIST-cited), not implemented. |

### Two spec-grounded facts accepted by choosing this scope

1. **Not full Baseline.** `kmip-profiles-v3.0` lists **item 10 "Supports Server-to-Client Operations:
   Discover Versions, Notify, Put, Query"** as a *numbered mandatory* Baseline Server condition.
   Parking Notify/Put therefore caps the claim at *"Baseline Server profile except item 10."*
   Unparking = Phase 5.
2. **The PQC surface is draft-only and un-vectored.** Encapsulate/Decapsulate + hybrid-KEM live in
   **WD19**, not the published CSD01; the CSD01 conformance corpus contains **zero** PQC test cases.
   PQC correctness rests on WD19 text + third-party interop + self-authored KATs — labeled as such.

---

## 1. Verified spec citations (the operations/attributes this plan touches)

| Item | § | Notes |
|---|---|---|
| Check | 6.1.7 | Sub-checks: Usage Limits Count, Cryptographic Usage Mask, Lease Time |
| Cancel | 6.1.5 | req: Asynchronous Correlation Value → resp: + Cancellation Result (enum) |
| Create Credential | 6.1.9 | (auth) |
| Create Group | 6.1.10 | (auth) |
| Create Split Key | 6.1.12 | attrs Split Key Parts/Threshold/Method (§4.64–4.66) |
| Create User | 6.1.13 | (auth) |
| Get Constraints | 6.1.26 | (implemented) |
| Join Split Key | 6.1.31 | SHALL supply ≥ Split Key Threshold identifiers |
| Log | 6.1.33 | (auth) |
| Login | 6.1.34 | (auth) |
| Logout | 6.1.35 | (auth) |
| Obtain Lease | 6.1.40 | returns Lease Time + Last Change Date |
| PKCS#11 | 6.1.42 | passthrough |
| Poll | 6.1.43 | req: Asynchronous Correlation Value → Pending (no payload) or completed op payload |
| Process | 6.1.44 | flips a pending async request so next Poll ≠ pending |
| Query Asynchronous Requests | 6.1.46 | optional correlation-value / operations filter |
| RNG Seed | 6.1.55 | server MAY consume/partial/ignore/deny |
| Set Constraints | 6.1.57 | req: Constraints set |
| Notify (server→client) | 6.2.2 | delivered "outside the normal request/response protocol, unspecified configuration" |
| Put (server→client) | 6.2.3 | as above |
| Protection Storage Mask | 4.50 | records the mask *actually used* |
| Encapsulate / Decapsulate | WD19 6.1.22 / 6.1.15 | ops 0x41 / 0x42; KEM Algorithm enum §11.26 (0x4201C3) |
| Asynchronous Indicator | 8.1.2 | request-header enum; ResultStatus Pending = 0x02 |
| Split Key Method enum | 11.54 | XOR=0x01, Poly GF(2¹⁶)=0x02, Poly Prime Field=0x03, Poly GF(2⁸)=0x04 |
| Split Key Polynomial enum | 11.55 | Polynomial-283=0x01, Polynomial-285=0x02 |

---

## 2. Grounded code seams

| Seam | Location (verified) | Used by |
|---|---|---|
| Object store trait | `src/store/traits.rs` (`KeyStore`: put/get/update/remove, `ObjectRecord`) | lease, constraints, sessions, async jobs |
| Store backends | `src/store/memory.rs` (harness) · `src/store/sqlite.rs` (durable) | persistence |
| Op dispatch loop | `src/dispatcher/mod.rs::handle` (per-`batch_items` loop; async currently **fails every item**, ~:123) | Phase 4 hook |
| Advertised surface | `src/dispatcher/mod.rs::HANDLED_OPERATIONS`; padding in `src/ops/query.rs:155` (`ADVERTISED_UNIMPLEMENTED_OPERATIONS`) / `:211` (object types) | Phase 6 |
| KMIP Sign handler | `src/ops/sign.rs:37` (policy `evaluate` :137 → `native::sign_pqc`/`sign_with_pss_salt`) | Phase 1.5 |
| Engine native sign | `rust/src/native/sign.rs::sign` (:77) / `sign_pqc` (:227) — **no HSS arm**, falls to `CKR_MECHANISM_INVALID` | Phase 1.5 |
| Engine FFI sign (has HSS) | `rust/src/ffi.rs::C_Sign` :3271–3360 (`update_fn` → `hss_sign` → advance+persist `CKA_LEAF_INDEX`) | Phase 1.5 source of truth |
| HBS crypto | `rust/src/crypto/lms.rs` (`lms_sign`:108, `hss_sign`:178, verifies) | Phase 1.5 |
| Replay harness | `conformance/harness/dispatcher_replay.py` (restart-per-test ~:142; Query comparator `_compare_query_response_payload`:717, subset semantics) | Phases 2.1, 6.1 |
| Report gates | `conformance/assert_replay_report.py`, `check_report_fresh.py`; CI jobs `rust-test`/`kmip-conformance`/`kmip-pqc-conformance` | Phase 7 |

---

## 3. Phases

Effort S/M/L · Risk L/M/H · each task carries its own exit test.

### Phase 0 — Truth & labeling  *(S / L)*
- **0.1** Relabel the claim (CONFORMANCE_REPORT:10, README, CHANGELOG): "CSD01 corpus + WD19 PQC (drafts); Baseline Server profile **except item 10 (parked)**." *Exit:* no ratified-standard / full-Baseline claim remains.
- **0.2** Version-qualify the stale strings (`KMIP_3_0_DELTA.md §5`, `vendor_tags.rs:17` "KMIP 3.0 has no Encapsulate"); fix DELTA op-count 50→64; mark `KMIP_LAYER_GAPS_PLAN.md` historical; fix `decision.rs:132` "Deprecated" → `Deactivated`; point to `spec/crossref/kem-encapsulate-decapsulate.yaml`. *Exit:* `grep -ri "no Encapsulate operation"` returns only version-qualified text.
- **0.3** ~~Remove~~ **CORRECTED, not removed:** `SecP384r1MlKem1024=0x8000005e` (`algos.rs:195`) is
  **not** an invented codepoint — KMIP 3.0's own §11.12 Table 543 (Cryptographic Algorithm
  Enumeration) lists `Extensions: 8XXXXXXX` as a valid entry (confirmed present in 60 enum tables
  across the spec), and `0x8000005e`'s high byte is `0x80`. This is spec's own sanctioned
  vendor-extension convention for enum values, just not (yet) an OASIS-assigned standard value. The
  original audit finding calling this "invented, no spec basis" was **wrong**; corrected the code
  comment to cite §11.12 instead of deleting working, wired functionality. **Executed:** rename
  test-only `BATCH_COUNT` (a genuinely Reserved-in-3.0 codepoint per §11.57, "Batch Count" appears
  0 times in the spec) → `SYNTHETIC_TEST_TAG` in `codec/tag.rs:93` + its 5 call sites; the checked-in
  KAT filename (`01-integer-batch-count-1.bin`) and its manifest entry were left as-is (renaming a
  binary fixture + generator script + manifest for a cosmetic filename was judged not worth the
  blast radius — noted in each renamed call site's comment instead). *Exit:* no symbol names a
  Reserved tag; the vendor-extension codepoint is correctly documented, not removed.

### Phase 1 — De-fake the surface

**1.1 Real PKCS#11 passthrough** — §6.1.42 · *(M / M)*. `rng_and_pkcs11.rs:60-89` returns canned `CKR_OK`.
- T1 map each exercised PKCS#11 function code to a `softhsmrustv3::native` entry.
- T2 replace blanket-OK with a real dispatch returning the true `CKR_*` + output parameters; correlation value stays the §6.1.42 wrapper only.
- T3 unsupported function → real `CKR_FUNCTION_NOT_SUPPORTED`.
- *Exit:* `PKCS11-M-1` passes via a real side-effect; a bogus function returns a real error.
- *Confidence:* shape grounded; exact function set to confirm at build.
- **Done (2026-07-07):** real dispatch for `C_Initialize`/`C_Finalize`/`C_GetInfo`, the
  only functions PKCS11-M-1 exercises. Function ordinals grounded in KMIP 3.0 §11.39
  ("1-based offset count... in `CK_FUNCTION_LIST_3_0`") verified against this repo's own
  `pkcs11f.h`, not assumed. `C_Initialize`/`C_Finalize` track a new KMIP-server-side
  virtual Cryptoki-lifecycle flag (`Deps.pkcs11_virtual_initialized`) rather than the
  real engine's global init state (which must stay up for every other KMIP client).
  `C_GetInfo` calls the real engine for genuine `CK_INFO` bytes. 6 new unit tests;
  corpus unchanged 97/0/5.
- **Deferred — full PKCS#11 transparent-mode scope (separate future item, explicitly
  requested to pick up after the current plan finishes):** per Profiles v3.0 §5.18.1,
  the `PKCS_11` operation's encoding rules are function-agnostic and cover the *entire*
  PKCS#11 v3.x parameter-marshalling problem (session ops, object/attribute ops,
  crypto ops — e.g. `C_OpenSession`, `C_Login`, `C_GetAttributeValue`, `C_Encrypt` are
  all in-scope per the profile's own worked examples, §5.18.3). Server conformance
  itself only requires supporting the operation + the one mandatory test (`PKCS11-M-1`,
  §5.18.6.1) — there is no enumerated required-function checklist, so this is a real
  but *optional* scope expansion, not a conformance gap. Explicit spec exclusions to
  respect when scoping it: `C_GetFunctionList`, `C_GetInterface`, `C_WaitForSlotEvent`,
  and callback pointers (e.g. `C_OpenSession`'s `Notify` param) are never passed
  through (§5.18.1) — a local PKCS#11 stub answers those itself. Scoping this properly
  needs: (a) which functions to expose (a deliberate product/security decision — every
  exposed function is server-side attack surface), (b) the byte-level parameter
  marshalling per function per §5.18.1 (structures inlined, variable-length
  two-call-pattern, attribute templates with value/count indicator flags, mechanism
  parameter encoding), (c) a decision on per-KMIP-client PKCS#11 session-state
  isolation (today's virtual-init flag is server-global; real `C_OpenSession`/
  `C_CloseSession` would need session-handle bookkeeping scoped correctly for a
  multi-tenant KMIP server).

**1.2 `Check` full enforcement** — §6.1.7 · *(S–M / L)*. `lifecycle_and_protocol.rs:78-111` = mask only.
- T1 wire Usage-Limits-Count to tracked `usage_limits_remaining` (`allocation_and_config.rs:113`).
- T2 wire Lease-Time sub-check to the lease manager (dep: 3.1).
- T3 return §6.1.7 result (UID if allowed, else failing attribute + usable/failed date).
- *Exit:* over-budget usage-count or expired lease fails with correct reason; `BL-M-2` green.

**Outcome (2026-07-08):** Done together with 3.1 (real dependency, not
just planned sequencing). Usage Limits Count now compares against
`usage_limits_remaining` (objects with no tracked budget — e.g.
asymmetric keys — pass, nothing to deny against). Lease Time compares
against the object's real §4.34 cap (`ObjectRecord.lease_time`, now set
at Create/CreateKeyPair/Register/DeriveKey instead of a get_attributes.rs
read-time fallback with nothing behind it) — per spec Table 269 this is
a hypothetical "would this be granted" check, not "is my current lease
still valid," so it does not consult `lease_expiry`. T3's richer
denial-response shape (echoing the specific rejected attribute) was
scoped out — this server's `KmipError` failure model doesn't carry a
response payload on error, matching how the pre-existing Cryptographic
Usage Mask check already works (fails with the reason code, no echoed
value); extending that would be a separate, larger response-model
change, not a Check-specific gap. 6 new unit tests; `BL-M-2` unaffected
(mask-only in the OASIS corpus, still green).

**1.3 Truthful Protection Storage Mask** — §4.50 · *(S / L)*. `get_attributes.rs:190` hardcodes `0x01`.
- T1 record the mask actually used at create/register on `ObjectRecord`; emit that. *Exit:* value tracks the request.

**1.4 Real auth/session** — Login §6.1.34 / Logout §6.1.35 / Create Credential §6.1.9 / Create User §6.1.13 / Create Group §6.1.10 / Log §6.1.33; Credential §9.9 · *(M / M)*. `session_and_auth.rs` acknowledge-only; verifier exists (`server/auth.rs`, mTLS CN→`Identity`).
- T1 session/ticket store (ticket → `Identity`).
- T2 Create Credential/User/Group persist real objects (these also back the object types Query advertises → feeds 6.1).
- T3 Login verifies a §9.9 Credential via `CredentialVerifier`, issues a ticket; Logout invalidates; Log → audit sink.
- T4 under *configured* auth, enforce ticket/identity on subsequent ops; **open-auth unchanged** for the harness.
- *Exit:* Login issues a real ticket; unauth mutating op under configured-auth → `PermissionDenied`; `SASED-M-1/2`, `QS-*` green in open-auth.
- *Confidence:* shape grounded; session-integration seam to trace at build.

**Outcome (2026-07-08):** T2 and most of T3 were already real going in
(`persist_simple_record` genuinely stores User/Group/Credential objects;
Login already checked `AuthContext.identity`, itself correctly verified
from the §8.1.2 header per §9.9, not an in-payload field — KMIP 3.0's
Login request has no Credential slot, Table 352 only lists
LeaseTime/RequestCount/UsageLimits). What was fake: the returned
"ticket" was a display string nobody ever stored or checked again, and
Logout was a hardcoded no-op.
- Found and fixed a **real wire-format bug** while implementing this:
  `Ticket` (§7.40 Table 494) is a `Structure{TicketType, TicketValue}`,
  but the encoder emitted a bare `TextString` and the decoder expected
  one to match — spec-non-conformant on both sides, for both Login's
  response and Logout's request. Fixed with shared
  `encode_ticket_frame`/`decode_ticket_structure` helpers.
- T1: `Deps.sessions: Mutex<HashMap<Vec<u8>, SessionRecord>>` — a real
  ticket → Identity (+ optional expiry from Login's `Lease Time`) store.
- Login now generates real random ticket bytes (UUID v4), records the
  session, returns a spec-correct `Ticket` structure.
- Logout removes the session for real; an unknown/already-used ticket
  fails `Invalid Ticket` (0x19, added to `ResultReason` — verified
  against the spec's §6.1.35 error table) instead of silently
  succeeding.
- T4: added `Credential::Ticket` (Credential Type 0x06, §9.9 Table 517)
  end to end — wire codec, and a new check in
  `dispatcher::authenticate_request` that looks a presented ticket up
  in the session store (checking expiry) before falling through to the
  username/password verifier. A live ticket now authenticates a LATER
  request on its own, with no credentials resent — proven by a
  dispatcher-level test that Logins once, then Queries with ONLY the
  ticket, then confirms a tampered ticket fails and a post-Logout reuse
  fails. Open-auth mode (the harness default) is unchanged — the new
  ticket check only engages when auth is configured, same gate as the
  rest of §8.1.2 enforcement.
- `cargo test`: 535 lib tests + all integration binaries green. Corpus
  unchanged 97/0/5 (no OASIS transcript exercises configured auth).

**1.5 Wire HSS/LMS signing** — RFC 8554 / HSS · *(M / Low — revised down from L/High)*.
**The engine already manages HBS state; the KMIP layer manages none of it.** `ffi.rs::C_Sign` (:3271–3360) already implements HSS: an `update_fn` captures the advanced private state, `crypto::lms::hss_sign` drives it, and the new `CKA_LEAF_INDEX` is atomically read-advance-persisted onto the key object. But `native/sign.rs` (the path the KMIP server uses) **omits** the HSS arm and falls to `CKR_MECHANISM_INVALID`.
- T1 **extract** the HSS/LMS sign-and-advance core out of `ffi.rs::C_Sign` into **one shared engine helper** (single source of truth for leaf-index persistence — where drift = key reuse).
- T2 **call it from both** `ffi::C_Sign` and `native/sign.rs::sign`/`sign_pqc` (replaces C_Sign's inline copy; adds the missing native arm — the actual "wire it").
- T3 **KMIP dispatch:** `ops/sign.rs` routes an HSS/LMS-keyed Sign to the native HSS path by the stored key's algorithm/param set; surface `CKR_KEY_EXHAUSTED` as the KMIP `ResultReason`. No state handling here.
- T4 **verify (not build):** confirm HBS keys are backed by a **durable** token store in the deployment (leaf-index write must survive a crash) — an engine object-store property; note in the deployment doc.
- *Exit:* KMIP Sign on an HSS key → signature `hss_verify` accepts; leaf advances+persists via the shared helper; second sign consumes a new leaf (unit test: distinct indices + persisted counter); exhaustion → clean error; FFI and native paths byte-identical.

**Outcome (2026-07-07) — done, scope expanded mid-flight to full KMIP-wire support:**
T1–T3 as planned, PLUS: KMIP 3.0's `Cryptographic Algorithm` enum (§11.12
Table 545) turned out to have **no HSS entry at all** (verified directly
against the spec text, both CSD01 and the WD19 PQC draft — only `XMSS` is
listed, a genuine spec gap). Explicitly re-scoped with the user to full
KMIP-wire support rather than engine-only:
- rust engine: new `native::hbs` module (the single shared prepare/commit
  leaf-advance-and-persist core), `ffi::C_Sign`'s HSS branch refactored to
  call it (XMSS/XMSSMT untouched), `native::sign`/`verify` gained real
  `CKM_HSS` arms, `native::keygen` gained `register_hss_private_key` /
  `register_hss_public_key` (Register-import only — v0.1 fixes one LMS/
  LM-OTS parameter combination, `CKP_LMS_SHA256_M32_H5` /
  `CKP_LMOTS_SHA256_N32_W4`, the engine's own unparametrised default).
  8 new tests incl. a real 32-signature exhaustion test (not mocked) and
  an ffi-vs-native leaf-advance parity test. `cargo test --lib`: 251/251.
- KMIP layer: `KmipAlgorithm::Hss` added at `0x8000005f`, the same
  spec-sanctioned `8XXXXXXX` vendor-extension convention already used for
  `SecP384r1MlKem1024`. `native_parameter_set` deliberately has NO `Hss`
  arm (HSS keygen isn't supported, only import, so `CreateKeyPair` on Hss
  correctly stays `OperationNotSupported`); Register gets its own
  dedicated HSS arm instead of the generic PQC-family one.
  `native_sign_mech_with_params` resolves `Hss → CKM_HSS`; `Sign`'s
  existing generic dispatch needed no changes beyond that. New KMIP-level
  e2e test: Register → Sign → SignatureVerify twice (proving two signs
  consume distinct leaves through the full KMIP wire path, not just at
  the engine level) + a tampered-signature check.
- Corpus unaffected (97/0/5 — no OASIS test exercises HSS). Full kmip
  `cargo test`: 530+ lib tests / all integration binaries green.

### Phase 2 — Corpus closure → 97/102

**2.1 Stateful Locate** — `SASED-M-3`, `TL-M-3` · *(S / L, harness)*. Filters already implemented (`locate.rs:205-216`).
- T1 replay the paired transcripts (M-2→M-3) against **one** server instance (no per-test wipe, `dispatcher_replay.py:142`); keep all else hermetic. **DONE** — `_CHAINED_TEST_GROUPS` mechanism added to `dispatcher_replay.py`; `run_test` now accepts a shared `Bindings`.
- T2 add Rust unit tests for Locate-by-GroupLink + Locate-by-ApplicationSpecificInformation (currently inspection-only). **Not yet done** — deferred alongside T3 below.
- T3 reclassify both to expected-PASS in `assert_replay_report.py`. **Both done** — SASED and TL-M genuinely PASS/PASS via the chain.
- *Exit:* both PASS as real cross-request Locate. **Met — corpus is 97 PASS / 0 FAIL / 5 SKIP_DEPRECATED.**

**Outcome (2026-07-07):**
- **`SASED-M-2`→`SASED-M-3` fully closed** — both PASS for real via the chained-transcript mechanism. Locate-by-GroupLink genuinely round-trips end to end.
- **`TL-M-2`→`TL-M-3`: the chain mechanism works and surfaced 3 real, independently-confirmed spec-conformance bugs, all fixed and verified (full `cargo test` still 518/518 + all integration suites green after each):**
  1. **`encode_get_attribute_list_resp` silently dropped every custom/vendor attribute name** from `GetAttributeList` responses (§4.1.2 item 5 violation) — it had its own inline, incomplete encode logic instead of reusing the already-correct `attribute_reference_frame` helper (which handles both the Enumeration and `Structure{AttributeName}` shapes). Fixed by reusing that helper (`wire.rs`).
  2. **`ApplicationSpecificInformation` was never checked** in `get_attribute_list.rs`'s name surface, despite `ObjectRecord` tracking it and `GetAttributes` already surfacing it. A genuine omission, not a wire bug. Fixed (`get_attribute_list.rs`).
  3. **`Attribute::AlternativeName` decode expected a bare `TextString`**, but KMIP 3.0 §4.5 defines it as `Structure{AlternativeNameValue, AlternativeNameType}` — every real client-set AlternativeName silently decoded to `Ok(None)` and was dropped. Also found the extraction pipeline (`ExtractedAttrs`/`extract_attrs`) had no field for it at all — systemic, affecting Create AND Register. Fixed all three layers (`wire.rs` decode + 2 new tag constants `AlternativeNameValue`/`AlternativeNameType`; `ExtractedAttrs` struct + `extract_attrs`; wired into both `create.rs` and `register_import_export.rs`'s `ObjectRecord` construction).
- **`TL-M-3` fully closed (2026-07-07), 3 more real bugs found and fixed:**
  4. **Typed custom/vendor attribute values were flattened to strings.** `TL-M-3`'s `GetAttributes` step round-trips the *values* of 5 custom/vendor attributes TL-M-2 set, including `VendorAttribute2` (Integer) and `VendorAttribute3` (DateTime). The old `Attribute::Custom { name, value: String }` model — and `ObjectRecord.custom_attributes: HashMap<String, String>` — only ever stored a **string**; `decode_attribute_v3`'s generic vendor-`Attribute` arm only extracted `AttributeValue` when it was a `TextString`, silently dropping Integer/DateTime/Boolean typed values (stored as `""`). Fixed by introducing `CustomAttributeValue` (Text/Integer/DateTime/Boolean), threaded through the wire codec (both decode and encode), the `Attribute` enum, and `ObjectRecord.custom_attributes` — the ~12 external policy-matching call sites (`strip_x_prefixes` callers in `sign.rs`, `encrypt.rs`, etc.) needed **zero changes**, since `strip_x_prefixes` still returns `HashMap<String, String>` via a new `.as_policy_string()` method on the enum. Verified via `cargo test` (522/522 pass) plus direct empirical server probing of the actual TL-M-3 wire exchange.
  5. **`GetAttributes` never surfaced `ApplicationSpecificInformation`'s value**, only its *name* (via `get_attribute_list.rs`, fixed in bug 2 above) — `attributes_from_record()` in `get_attributes.rs` had no arm for it at all, despite `ObjectRecord.application_specific_information` being populated at Create/Register. Fixed (`get_attributes.rs`).
  6. **`Fresh` never flipped to `false` after a Get.** KMIP 3.0 §11 defines `Fresh` as True only until the object's material is exported once; `create.rs` sets `fresh: Some(true)` at creation but nothing ever cleared it, so `TL-M-2`'s Create→Get sequence left the flag permanently `true`, contradicting `TL-M-3`'s expected `false`. Fixed by flipping `fresh` to `false` and persisting via `store.update()` on the first successful `Get` (`get.rs`).
- **Corpus result: 97 PASS / 0 FAIL / 5 SKIP_DEPRECATED** (up from 93/1/8 at audit start) — the Phase 2 target is met.

**2.2 RNG-seed variants** — §6.1.55 · *(M / L)*. `rng_and_pkcs11.rs:47-53` full-consume only.
- T1 implement partial-consume, ignore (`DataLength=0`), deny (`PermissionDenied`).
- T2 make the behavior selectable by a CACP seed-handling policy (`src/policy/`); harness drives each variant.
- T3 reclassify `CS-RNG-O-2/3/4` to expected-PASS.
- *Exit:* all four §6.1.55 behaviors real; the 3 tests PASS.

*→ 97 pass / 5 declined (deprecated, NIST-cited) / 0 fake.*

### Phase 3 — Feasible advertised ops (no new subsystems)

**3.1 Lease manager + Obtain Lease** — §6.1.40, §4.34 · *(S–M / L)*.
- T1 add lease_expiry + last_change to `ObjectRecord`; a per-object max-lease policy (server-set, client read-only per §4.34).
- T2 implement Obtain Lease (issue/renew Lease Time + Last Change Date); stop faking `LeaseTime(3600)` (`get_attributes.rs:186`) — derive from the record.
- T3 expose expiry to Check (1.2-T2).
- *Exit:* real, renewable lease; expiry observable.

**Outcome (2026-07-08):** `ObjectRecord.lease_expiry: Option<OffsetDateTime>`
added; `ObtainLease` wired end to end (new `ObtainLeaseRequest`/
`ObtainLeaseResponse` types, wire codec, dispatcher entry, moved from
`ADVERTISED_UNIMPLEMENTED_OPERATIONS` to `HANDLED_OPERATIONS`) — grants
the object's real Lease Time cap, sets `lease_expiry = now + cap`,
stamps `last_change_date`, returns both per §6.1.40 Table 371.
Renewable: a second Obtain Lease call advances the expiry further
(tested). Every object-creation site (Create/CreateKeyPair/Register/
DeriveKey) now sets a real `lease_time: Some(3600)` instead of relying
on `get_attributes.rs`'s read-time fallback. 9 new unit tests
(grant/renew/unknown-uid + Check's two new sub-checks, done together —
see 1.2). `cargo test`: 541 lib tests + all integration binaries green.
Corpus unchanged 97/0/5.

**3.2 Set Constraints** — §6.1.57 (pairs Get §6.1.26) · *(S–M / L)*.
- T1 back `server_constraints()` (`allocation_and_config.rs:152`) with a mutable store.
- T2 implement Set Constraints writing that store; Get reads it back.
- *Exit:* Set→Get round-trips.

**Outcome (2026-07-08):** `SetConstraintsRequest`/`Response` added (new
wire codec — Set Constraints previously had no request-side decode at
all, only Get's response-side encode existed), `Deps.constraints:
Mutex<Option<Vec<Constraint>>>` backs it. `None` (never Set) falls back
to the real engine-bounds `server_constraints()` default; `Some(v)`
(including an explicit empty Set — a genuine "no constraints" override,
distinct from never calling Set) replaces it entirely, and a later Set
replaces rather than merges. Moved from `ADVERTISED_UNIMPLEMENTED_OPERATIONS`
to `HANDLED_OPERATIONS`. 3 new unit tests. `cargo test`: 544 lib tests +
all integration binaries green. Corpus unchanged 97/0/5.

**3.3 Create / Join Split Key** — §6.1.12 / §6.1.31; attrs §4.64–4.66; enums §11.54/§11.55 · *(M–L / M)*.
Types exist (`attrs.rs:64` SplitKey=0x05; `ops.rs:115/134`) → route to Unsupported. **Engine has no secret-sharing primitive — implement from spec.**
- T1 implement the **four §11.54 methods**: XOR (0x01), Polynomial Sharing GF(2¹⁶) (0x02), Polynomial Sharing Prime Field (0x03), Polynomial Sharing GF(2⁸) (0x04); with the §11.55 polynomials (Polynomial-283, Polynomial-285) for the GF variants (Shamir threshold sharing).
- T2 Create Split Key (§6.1.12): generate key, split into `Split Key Parts` (§4.65) with `Split Key Threshold` (§4.66) + `Split Key Method` (§4.64), register each share as a `SplitKey` object.
- T3 Join Split Key (§6.1.31): require ≥ threshold identifiers (SHALL), reconstruct, register the joined object.
- T4 remove `SplitKey` from `ADVERTISED_UNIMPLEMENTED_OBJECT_TYPES` (`query.rs:212`).
- *Exit:* Create N shares; Join of ≥threshold reconstructs the exact key; fewer-than-threshold fails (§6.1.31); KATs per method.

**Outcome (2026-07-08):** All four §11.54 methods implemented from spec
in a new engine-side (`rust/`) primitive, not `kmip/` — secret-sharing
math is genuinely reusable at the PKCS#11 level (e.g. digital-asset key
custody), and `kmip/` never touches raw key bytes, matching every other
`native::*` bridge in this codebase. New engine vendor mechanism
`CKM_PQCTODAY_SPLIT_KEY` (`0x8000_0012`) — verified against the local
PKCS#11 v3.2 CSD01 spec text directly (not just the header) that no
standard mechanism covers secret sharing at all, so this is honestly
vendor-only, unlike e.g. HSS which does map to a real PKCS#11 mechanism.
`rust/src/crypto/split_key.rs`: XOR, Polynomial Sharing GF(2⁸) (both
irreducible polynomials 283/285 per §11.55), Polynomial Sharing Prime
Field (Shamir over the fixed 2^521−1 Mersenne prime, `num-bigint`),
Polynomial Sharing GF(2¹⁶) (`y²=y+m` algebraic extension of GF(2⁸)).
**Found and fixed a genuine bug in the KMIP 3.0 draft's own printed
GF(2¹⁶) multiplication formula** (§13.1): the constant term's `m` factor
is on the wrong product term (`ru+svm` as printed vs. the algebraically
correct `rum+sv`, re-derived from the defining relation and
cross-verified against the spec's own inverse formula, which is only
consistent with the corrected multiply). All 18 crypto-layer unit tests
green, including split→join round trips, FIPS-197 cross-check, and
genuine below-threshold-does-not-recover-secret checks.
`rust/src/native/split_key.rs` wraps this as a handle-in/handle-out API
(`split(session, secret_handle, ...) -> Vec<(key_part_identifier,
handle)>`, `join(session, shares: &[(u32,u32)], ...) -> handle`) —
`kmip/` only ever sees opaque engine object handles, never secret bytes,
per this codebase's standing security model (confirmed with the user
before writing any KMIP-layer code). Each share/joined result is
registered as a real `CKO_SECRET_KEY` engine object.
KMIP layer: `Create Split Key` (§6.1.12, both the "split an existing
key" and "generate a fresh key" paths) and `Join Split Key` (§6.1.31,
rejects fewer-than-threshold identifiers and mismatched
method/threshold/polynomial across the supplied shares) — new
`ops/split_key.rs` handler, wire codec (`SplitKeyStructure` +
`SplitKeyMethod`/`SplitKeyParts`/`SplitKeyThreshold`/
`KeyPartIdentifier`/`PrimeFieldSize`/`SplitKeyPolynomial` tags per
§11.61), 5 new `ObjectRecord` fields, dispatcher wiring, moved from
`ADVERTISED_UNIMPLEMENTED_OPERATIONS` to `HANDLED_OPERATIONS`. T4 done:
`SplitKey` moved from `ADVERTISED_UNIMPLEMENTED_OBJECT_TYPES` to
`IMPLEMENTED_OBJECT_TYPES` in `query.rs` — it's a real, fully-functional
object type now, not just advertised. New e2e test
`create_split_key_then_join_threshold_subset_reconstructs_via_real_engine`
(`native_bridge_e2e.rs`) drives Create Split Key with no source UID
(fresh-key-generation path) through 5-way GF(2⁸) split, threshold 3,
Get on every real share, Join of a 3-share subset, and confirms the
fewer-than-threshold case fails `InvalidField` instead of silently
reconstructing garbage. `cargo test`: 544 lib tests + all integration
binaries green (was 544/545 before this test existed — the 545th, the
op-coverage assertion, is now satisfied). Corpus unchanged 97/0/5 (no
OASIS transcript exercises Split Key).

### Phase 4 — Asynchronous subsystem (broad, §8.1.2)  *(L / H — the biggest new work)*
Grounded: indicator parsed (`message.rs:73-77`, `wire.rs:558`); `ResultStatus::OperationPending=0x02`; dispatcher **fails every batch item when async is requested** (`mod.rs:~123`) — that rejection is the seam we replace.

**4.1 Async core.**
- T1 async-job store behind the store trait — key = server-generated `Asynchronous Correlation Value`; value = {op, request snapshot, status(pending/complete/cancelled), result-or-error, submit-time}. Durable via `SqliteStore`; memory for the harness.
- T2 bounded background executor runs the queued op through the same handlers, writes the result back; guard `KeyStore` concurrency.
- T3 dispatch hook: when `asynchronous_indicator=true` and the op is async-eligible, enqueue → respond `OperationPending` + correlation value (§8.1.2); sync path unchanged.
- T4 broad eligibility (any long-running op MAY be async) + a cap on outstanding jobs + result TTL; document eligible ops.
- *Exit:* async-flagged request → Pending + correlation value; job completes out-of-band.

**4.2 Async ops.**
- Poll §6.1.43: by correlation value → *Pending (no payload)* or the completed op's payload.
- Cancel §6.1.5: abort → response = correlation value + `Cancellation Result` enum.
- Process §6.1.44: mark a pending job so the next Poll ≠ pending.
- Query Asynchronous Requests §6.1.46: optional correlation-values/operations filter → list outstanding.
- Move these four out of `ADVERTISED_UNIMPLEMENTED_OPERATIONS` (`query.rs:160-176`).
- *Exit:* Pending→Poll→result; Cancel/Process/QueryAsync operate on live jobs.

**4.3 Advertise capability.** Set `Asynchronous Capability = true` (tag `0x4200f0`) **only after 4.1–4.2 pass.** *Exit:* QS reports async true and it's real.

**Outcome (2026-07-08):** Full async subsystem shipped, with two
scope calls made explicit rather than silently simplified:

- **Job store lives on `Deps`, not behind the `KeyStore` trait.**
  A job's data (submitted request snapshot, stage, result-or-error,
  submit time) isn't a KMIP *Managed Object* — no UID, no lifecycle
  FSM, no attributes — routing it through `KeyStore` would be a
  category error. `Deps::async_jobs: Mutex<HashMap<CorrelationValue,
  Arc<AsyncJob>>>`, in-memory only (matches every other server-scale,
  non-object state already on `Deps` — `sessions`, `constraints`,
  `object_defaults`).
- **Genuine background execution requires an owned `Arc<Deps>`; the
  entire codebase (500+ tests) threads `Deps` as a plain `&Deps`
  borrow.** Rather than a crate-wide refactor, `Deps` grew a
  `self_handle: OnceLock<Weak<Deps>>`, set once via
  `Deps::install_self_handle()` right after the production binary
  wraps its `Deps` in `Arc` (`bin/pqctoday-kmip.rs`). When present, the
  async executor spawns a real `std::thread` and hands it a `'static`
  `Arc<Deps>` upgraded from the weak handle — genuine, concurrent,
  out-of-band execution, exactly like the production server. When
  absent (every one of the 551 pre-existing tests, which build `Deps`
  directly via `Deps::new`, and any non-`native` build with no OS
  threads at all) the same job runs inline, synchronously, before the
  enqueuing call returns. Both paths are fully protocol-correct — the
  enqueuing response is `OperationPending` with no payload either way,
  a client MUST `Poll` regardless of how fast the server actually
  finished — only the *when* differs, and it's documented rather than
  silently pretended to be the threaded path.

`Cancel`/`Process` needed one real correctness fix beyond the naive
design: `Cancel` on a `Submitted` job and the background thread's own
`Submitted → InProcess` transition are a genuine race (two threads,
one job). `AsyncJob::try_cancel_if_submitted` closes it with a single
locked check-and-set instead of separate read-then-write lock
acquisitions, which could otherwise clobber a real in-flight result
with a fake "canceled" one. `Process` blocks on the job's `Condvar`
rather than re-running the operation — re-running would risk
double-executing a side-effecting handler (e.g. double-decrementing a
Usage Limits counter).

`Poll` (§6.1.43) doesn't get its own `ResponsePayload` variant —
per spec its completed response is "identical to the response that
would have been sent if the operation had completed synchronously",
so `dispatcher::handle_poll` splices in the ORIGINAL polled
operation's real `Operation` + outcome; its not-yet-complete response
echoes `Poll` itself with no payload, per the same table row every
async-triggering operation's immediate acknowledgment uses (§9.1).
`Query Asynchronous Requests` reports jobs with `stage != Completed`
as "outstanding" — a documented reading of "results not yet obtained"
(the alternative, tracking whether a client's `Poll` literally already
retrieved a `Completed` job's result, needs a fourth state dimension
for a narrow window with no behavioral consequence).

Eligibility is broad per T4: every `HANDLED_OPERATIONS` entry except
the async-management ops themselves (`Poll`/`Cancel`/`Process`/
`QueryAsynchronousRequests` — each explicitly says its own response is
never asynchronous) and `Query`/`DiscoverVersions`/`Ping` (trivial
negotiation ops). The `Mandatory`-but-ineligible-op gate moved from a
whole-*batch* rejection (the pre-existing K4 seam) to a per-*item*
check inside `dispatch_one` — batch items can be different operations,
and the old behavior violated §9.5 Batch Error Continuation by always
returning one response per item regardless of `Stop`/`Continue`/`Undo`.

Two new `ResultReason` codepoints added (verified against
`kmip-spec-3.0-tags-enums.json`): `Invalid Asynchronous Correlation
Value` (0x2b) and `Operation Canceled By Requester` (0x09, the exact
outcome a successful early-`Cancel` leaves behind for a later `Poll`).
Six new wire tags (`Asynchronous Correlation Value`, `Cancellation
Result`, `Asynchronous Request`, `Submission Date`, `Processing
Stage`, `Asynchronous Correlation Values`, `Operations`). New
`ResponseBatchItem.asynchronous_correlation_value` field threaded
through every existing construction site.

Tests: 7 new unit tests in `ops::async_ops` pin the exact per-stage
Cancel/Process/QueryAsynchronousRequests behavior deterministically
(constructing `AsyncJob` state directly, no timing dependency); 5 new
e2e tests in `tests/async_ops_e2e.rs` drive the real dispatcher with a
genuine `Arc<Deps>` + `install_self_handle()` — Mandatory-Hash
enqueue → poll-until-done loop (bounded, always converges, no fixed
sleep) → byte-exact match against a synchronous baseline; unknown
correlation value; Process-blocks-don't-double-run; Cancel against a
real timing race (asserts one of the three legitimate outcomes, since
exact interleaving is inherently non-deterministic — the unit tests
pin exact behavior per stage); and the per-item (not whole-batch)
eligibility gate. One pre-existing test (`k4_async_mandatory_fails_
every_batch_item`) updated to explicitly request `Continue` mode,
since its "every item fails independently" intent now needs that
explicit — the previous whole-batch shortcut bypassed Batch Error
Continuation entirely, which was itself the bug this phase fixed.
`cargo test`: 551 lib tests + all integration binaries green. Corpus
unchanged 97/0/5 (no OASIS transcript exercises the async header).
`Asynchronous Capability` flipped to `true` in Query only after all of
the above was green (4.3's stated gate).

### Phase 5 — Server-to-client (Notify §6.2.2 / Put §6.2.3) — PARKED (D3)
Spec: delivered "via means **outside** the normal request/response protocol, using **unspecified**
configuration" (transport spec-undefined; profiles: server behaves as an HTTPS *client*).
**Baseline item 10 mandates them** → parking caps the claim at "Baseline-minus-item-10."
- **Deferred; no tasks executed.** Unpark design (later): outbound HTTPS-client channel reusing the
  1.4 mTLS identity; Notify (attribute-change push) + Put (object push); client registration/config;
  delivery + retry semantics. Warrants its own mini-spec before build.

### Phase 6 — Query honesty + conformance statement

**6.1 MSGENC comparator fix + honest Query** — §6.1.47 · *(M / M — required by the park)*.
The OASIS MSGENC-* fixtures' expected Query responses list Notify/Put/async ops, and the harness
gate is `expected ⊆ actual` (`dispatcher_replay.py:717`). With server-to-client parked, honest Query
would drop those → break MSGENC unless the comparator is corrected.
- T1 change `_compare_query_response_payload` so **MSGENC-*** validates **message-encoding fidelity**
  (the Message-Encoding profile's actual purpose) rather than Query capability-set membership.
- T2 empty `ADVERTISED_UNIMPLEMENTED_OPERATIONS` / `…_OBJECT_TYPES` (`query.rs:155,211`) — everything
  left is genuinely implemented (async P4, Split Key/Lease/Constraints P3, User/Group/Credential
  types P1.4); parked Notify/Put/server-to-client Discover-Versions/Query are **not advertised**.
- T3 confirm any residual advertised-but-unimpl (e.g. `CertificateRequest` object type) is implemented or dropped.
- *Exit:* Query lists only supported ops/types (§6.1.47); MSGENC-* green on encoding.

**6.2 Conformance report rewrite** — *(S / L)*. Restate: 97/102, 5 deprecated declined, PQC=WD19,
Query §6.1.47-truthful, all Baseline conditions met **except item 10 (parked)**, HSS/LMS + broad
async real. *Exit:* report matches measured reality.

**Outcome (2026-07-08):** Both sub-phases done together (6.2 turned
out to be a direct consequence of 6.1, not separate work).

6.1: `_compare_query_response_payload` in `dispatcher_replay.py` now
reads a module-level `_CURRENT_TEST_NAME` (set once per test at the
top of `run_test`; the harness runs strictly sequentially, so this is
safe without a contextvar) and skips the Operation/ObjectType
superset check entirely for MSGENC-*, instead of requiring our
capability set to be a superset of the reference server's — which
would have meant re-lying about Notify/Put forever, since our
capability set can never legitimately exceed a server that also does
server-to-client delivery. Every other field in the Query
ResponsePayload still compares normally for MSGENC-*, which is what
actually exercises message-encoding fidelity (its stated purpose).

`ADVERTISED_UNIMPLEMENTED_OPERATIONS` and
`ADVERTISED_UNIMPLEMENTED_OBJECT_TYPES` are now both **empty consts**
(`&[]`) — not just smaller. T3 surfaced a genuine pre-existing bug
along the way: `User`/`Group`/`PasswordCredential`/`DeviceCredential`/
`OneTimePasswordCredential`/`HashedPasswordCredential` were sitting in
the *unimplemented* list despite `CreateUser`/`CreateGroup`/
`CreateCredential` (`ops::session_and_auth`) genuinely persisting each
as its own `ObjectRecord` with the matching `object_type` — a stale
doc-comment label from before those handlers existed, never corrected
when they landed. Moved to `IMPLEMENTED_OBJECT_TYPES` (13 entries now,
was 7). `CertificateRequest` is the one type that's genuinely
unimplemented (`Certify`/`Re-certify` consume a CSR's bytes inline but
never persist a `CertificateRequest` managed object) — dropped
entirely per T3's "implemented or dropped" rule, not advertised.
`Notify`/`Put` (Phase 5, parked — §6.2.2/§6.2.3's transport is
spec-undefined) are the only two ops genuinely unimplemented, also
dropped from advertisement. Verified against the actual corpus fixture
content, not assumption: grepped every transcript for Notify/Put/
CertificateRequest/credential-type references — only the 3 MSGENC-*
files touch them (confirming the exemption is exactly right-sized) and
QS-M-1/QS-M-2 (the other Query-exercising transcripts) don't reference
any of them at all, so they were never at risk.

`cargo test`: 551 lib tests + all integration binaries green (2 stale
hardcoded counts fixed: Operations 64→62, ObjectTypes 14→13, both
in `ops::query`'s own tests). Corpus unchanged 97/0/5, MSGENC-*
verified still genuinely PASS under the new honest, much-smaller
capability set — the whole point.

6.2: `docs/CONFORMANCE_REPORT.md` rewritten end to end against the
KMIP 3.0 profiles spec's actual §5.1.2 13-item Baseline Server list
(extracted from `kmip-profiles-v3.0.pdf` directly, not approximated) —
found and corrected a genuine inaccuracy in the *previous* revision of
this report along the way: it claimed the async ops
(`Poll`/`Cancel`/`Process`/`Query Asynchronous Requests`) were somehow
entangled with item 10's server-to-client gap. They aren't — §5.1.2
item 9 (32 named client-to-server ops) and item 10 (5 named
server-to-client ops) don't name the async ops at all; they're
covered separately as message-layer plumbing under item 11.a
(`Asynchronous Indicator`). Phase 4 proved them fully independent of
Phase 5 (server-to-client remains parked; async ships regardless).
New sections cite HSS/LMS (§4.3), the async subsystem (§4.4), and
Split Key (§4.5) as real, each with its own proof citation (corpus
doesn't exercise any of the three, so each cites the specific
non-corpus test suite that does). `docs/REPLAY_REPORT_ANALYSIS.md`'s
"current standing" banner (already correctly marked historical/
superseded) updated from the stale 92/0/10 to 97/0/5; the other
historical planning docs (`COMPLIANCE_FIX_PLAN.md`,
`COVERAGE_GAP_PLAN.md`, `IMPLEMENTATION_PLAN.md`,
`REMEDIATION_PLAN.md`) already correctly defer to
`CONFORMANCE_REPORT.md` for current numbers rather than embedding
their own, so none of them needed editing.

### Phase 7 — Verification & CI
- **7.1** Update `assert_replay_report.py` → **97 PASS / 5 SKIP_DEPRECATED / 0 fail / 0 SKIP_OP** + explicit declined set; keep `check_report_fresh.py`. *(S)*
- **7.2** New coverage: HSS/LMS sign + **state-advance/no-reuse** (critical), async round-trip + Cancel/Process/QueryAsync, Split Key create/join per method (threshold), real auth ticket, PKCS#11 real proxy, 2 stateful-Locate filters, 4 RNG-seed behaviors. *(M)*
- **7.3** Regenerate `REPLAY_REPORT.{md,json}`, `CONFORMANCE_REPORT.md`, crossref YAMLs; ensure the 3 CI jobs gate the new expectations. *(S)*

**Outcome (2026-07-08):**

7.1: `assert_replay_report.py` rewritten to the honest exact baseline —
`EXPECT_PASS = 97` (was `MIN_PASS = 92`, a floor rather than an exact
figure) and `EXPECTED_SKIP` now `{skip_deprecated: 5, everything else:
0}` (was `{5, 2, 3, 0, 0}` = 10). `check_report_fresh.py` needed no
changes — it's generic (diffs the working-tree report against `HEAD`
modulo the timestamp field, no hardcoded numbers) and still passes.
`.github/workflows/ci.yml`'s `kmip-conformance` job step name/comment
("Assert replay baseline (92 PASS / 0 FAIL / 10 SKIP)") was also stale
— fixed to 97/0/5, the actual behavior it was already correctly
gating.

7.2: audited the checklist against actual test coverage before writing
anything — 4 of the 7 items were **already closed**: HSS/LMS
exhaustion (`e935284`, this session, before the summarized portion),
the async subsystem (Phase 4, this session), Locate's stateful filters
(Storage Status Mask has 3 dedicated unit tests; Object Group /
Application Specific Information are corpus-covered via
SASED-M-3/TL-M-3), and all 4 RNG-seed behaviors (already 4 dedicated
unit tests, one per mode). Three were genuine gaps, closed with real
tests against a real engine session, not stubs:
- **Split Key per method** — the existing e2e test only ever exercised
  §11.54 method 4 (GF(2^8)). New
  `create_split_key_then_join_covers_every_11_54_method_via_real_engine`
  (`tests/native_bridge_e2e.rs`) drives all four methods through the
  actual KMIP wire-level plumbing, including XOR's Parts==Threshold
  constraint and the second §11.55 polynomial (285). Caught a real
  test-design bug while writing it: Prime Field shares are field
  elements mod a ~521-bit prime, not the original secret's length —
  asserting all shares are exactly 32 bytes is only true for the other
  three methods; fixed the assertion, not the implementation.
- **Real auth ticket** — the existing Login/Logout test proved a
  session record exists in `deps.sessions` but never actually
  presented the ticket back through `dispatcher::dispatch` as a
  `Credential::Ticket`, so `authenticate_request`'s ticket-lookup
  branch was implemented but never exercised by an end-to-end test.
  New `login_ticket_authenticates_a_later_dispatched_request`
  (`tests/op_coverage_e2e.rs`) proves: a valid ticket authenticates a
  real dispatched request; the identical request with no credential
  fails (auth is genuinely enforced, not open); a forged ticket value
  fails; a logged-out ticket fails.
- **PKCS#11 real proxy** — every existing `C_GetInfo` test built
  `Deps` with `engine_session: None`, exercising only the honest "no
  real engine, don't fabricate" fallback, never the real branch the
  handler's own doc comment claims exists. New
  `pkcs11_get_info_returns_real_ck_info_bytes_against_real_engine`
  (`tests/op_coverage_e2e.rs`) proves it: against a real bootstrapped
  engine session, `C_GetInfo` returns actual non-empty 72-byte CK_INFO,
  not the fallback's `None`.

7.3: `REPLAY_REPORT.{md,json}` and `CONFORMANCE_REPORT.md` were
already regenerated/rewritten in Phase 6.2; re-verified fresh after
7.2's new tests (behavior-neutral — they only add coverage, corpus
replay is byte-identical). `spec/crossref/*.yaml` — checked; the one
existing file (`kem-encapsulate-decapsulate.yaml`) is a different,
unrelated topic (classical/hybrid/PQC KEM support) and needed no
changes; no new crossref file was warranted for this phase's work
(nothing here rests on a disputed spec-fact worth its own hand-curated
sheet beyond what's already inline in code comments and this plan
doc). All 3 CI jobs (`rust-test`, `kmip-conformance`,
`kmip-pqc-conformance`) already gate the current behavior correctly —
only the `kmip-conformance` step's stale display text needed fixing
(done in 7.1).

`cargo test`: 551 lib tests (unchanged — all 3 new tests are
integration-level) + all integration binaries green, +4 tests total
(`native_bridge_e2e` 25→26, `op_coverage_e2e` 19→21). Corpus unchanged
97/0/5, both CI gate scripts pass locally. **Definition of done (§6)
verified line by line: 97/102 with 5 documented deprecated declines
and 0 SKIP_OP; 0 fake handler; HSS/LMS real with engine-managed
crash-safe state; broad async real with `Asynchronous Capability =
true`; Query truthful (§6.1.47, no padding); honest label stated
verbatim in `CONFORMANCE_REPORT.md` §5.1 — all met.**

---

## 4. Sequencing & dependencies

```
0 ─ labeling, anytime
2 ─ 2.1 harness · 2.2 RNG ─────────────► 97/102 early
1 ─ 1.1 · 1.3 · 1.4 · 1.5(HSS) independent │ 1.2 Check ─waits→ 3.1 lease
3 ─ 3.1 lease → unblocks 1.2 · 3.2 · 3.3 split-key
4 ─ 4.1 core → 4.2 ops → 4.3 advertise
6 ─ 6.1 REQUIRES 1.4 + 3 + 4 (everything advertised must be real) → 6.2
7 ─ continuous; finalized last
5 ─ PARKED
```
**Recommended order:** 0 → 2 → 1.1/1.3/1.4/1.5 → 3 → 1.2 → 4 → 6 → 7.

## 5. Effort / risk

| Tier | Work packages |
|---|---|
| S / low | 0.x, 1.3, 2.1, 3.1, 3.2, 4.3, 6.2, 7.1, 7.3 |
| M | 1.1, 1.2, 1.4, 2.2, 4.2, 6.1, 7.2 |
| M–L | 3.3 (secret-sharing crypto) |
| **L / high** | **4.1 async core** |

*(1.5 HSS is M/Low after the correction — reuse of proven engine state code, no KMIP-side state.)*

## 6. Definition of done
- **97/102** (5 deprecated declined, documented, NIST-cited); **0 SKIP_OP; 0 fake handler.**
- **HSS/LMS signing real**, engine-managed crash-safe one-time state (no KMIP state).
- **Broad async real** (`Asynchronous Capability=true`).
- **Query truthful** (§6.1.47, no padding).
- Honest label: *"Baseline Server profile except the parked server-to-client operations (item 10); CSD01 corpus + WD19 PQC; drafts, not ratified."*

## 7. Evidence appendix (grounding)

- **Encapsulate/Decapsulate absent from CSD01** — verified: 0 "decapsulate" hits, 6 "encapsulate" all prose/bibliography in `kmip-spec-v3.0.html`; WD19 adds ops 0x41/0x42 + KEM enum §11.26. (self-verified 2026-07-07)
- **PQC codepoints present & correct in CSD01** — ML-KEM 0x39–0x3b, ML-DSA 0x3c–0x3e, SLH-DSA 0x3f–0x4a, matching `algos.rs`. (self-verified + wire/codec agent)
- **Baseline Server item 10 mandatory** — profiles PDF numbered conditions include "10. Supports Server-to-Client Operations: Discover Versions, Notify, Put, Query." (self-verified)
- **HSS engine capability** — `crypto/lms.rs` `hss_sign`/`lms_sign` real; `ffi.rs::C_Sign:3271-3360` state-managed; `native/sign.rs` missing the arm. (self-verified)
- **Split Key methods** — §11.54: XOR/Poly GF(2¹⁶)/Poly Prime Field/Poly GF(2⁸); §11.55 polynomials. Engine has no secret-sharing primitive. (self-verified)
- **Query over-advertising** — `query.rs:155-228` pads 10 ops + 8 object types the MSGENC fixtures expect; comparator `expected ⊆ actual`. (op-completeness agent + self-verified)
- **CACP fail-closed + real enforcement** — `policy/engine.rs`, 24 op call-sites; unconfigured server defaults permissive (`bin/pqctoday-kmip.rs:227`) — the one deployment fail-open (out of this plan's scope; tracked separately). (CACP agent)
- **Build/tests real & CI-gated** — codec 124/124 + 1234/1234 reproduce; replay 92/0/10 gated with anti-staleness; 0 stubs/panics/TODOs in the hot path. (build/test agent)

## 8. Out of scope (tracked, not silent)
- Server-to-client channel (Phase 5, parked) — required for *full* Baseline.
- DES/3DES/DSA (D4) — 5 deprecated corpus tests declined by policy.
- CACP unconfigured-permissive default — a separate CACP hardening item.
- XMSS/XMSS-MT signing — same wiring pattern as HSS (1.5); follow-on, not required by this scope.
- Ed448, Split-Key edge object types (PGPKey), full CertificateRequest — niche, documented.
