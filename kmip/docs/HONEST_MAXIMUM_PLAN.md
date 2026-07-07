# KMIP 3.0 "Honest Maximum" — Implementation Plan

> **Status:** PLAN (not yet executed) · **Authored:** 2026-07-07
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
- **0.3** Remove non-spec wire artifacts: drop / explicit-vendor-gate `SecP384r1MlKem1024=0x8000005e` (`algos.rs:195`); rename test-only `BATCH_COUNT=0x42000d` (Reserved in 3.0, `codec/tag.rs:93`). *Exit:* no non-spec `CryptographicAlgorithm` value can ride the wire; no symbol names a Reserved tag.

### Phase 1 — De-fake the surface

**1.1 Real PKCS#11 passthrough** — §6.1.42 · *(M / M)*. `rng_and_pkcs11.rs:60-89` returns canned `CKR_OK`.
- T1 map each exercised PKCS#11 function code to a `softhsmrustv3::native` entry.
- T2 replace blanket-OK with a real dispatch returning the true `CKR_*` + output parameters; correlation value stays the §6.1.42 wrapper only.
- T3 unsupported function → real `CKR_FUNCTION_NOT_SUPPORTED`.
- *Exit:* `PKCS11-M-1` passes via a real side-effect; a bogus function returns a real error.
- *Confidence:* shape grounded; exact function set to confirm at build.

**1.2 `Check` full enforcement** — §6.1.7 · *(S–M / L)*. `lifecycle_and_protocol.rs:78-111` = mask only.
- T1 wire Usage-Limits-Count to tracked `usage_limits_remaining` (`allocation_and_config.rs:113`).
- T2 wire Lease-Time sub-check to the lease manager (dep: 3.1).
- T3 return §6.1.7 result (UID if allowed, else failing attribute + usable/failed date).
- *Exit:* over-budget usage-count or expired lease fails with correct reason; `BL-M-2` green.

**1.3 Truthful Protection Storage Mask** — §4.50 · *(S / L)*. `get_attributes.rs:190` hardcodes `0x01`.
- T1 record the mask actually used at create/register on `ObjectRecord`; emit that. *Exit:* value tracks the request.

**1.4 Real auth/session** — Login §6.1.34 / Logout §6.1.35 / Create Credential §6.1.9 / Create User §6.1.13 / Create Group §6.1.10 / Log §6.1.33; Credential §9.9 · *(M / M)*. `session_and_auth.rs` acknowledge-only; verifier exists (`server/auth.rs`, mTLS CN→`Identity`).
- T1 session/ticket store (ticket → `Identity`).
- T2 Create Credential/User/Group persist real objects (these also back the object types Query advertises → feeds 6.1).
- T3 Login verifies a §9.9 Credential via `CredentialVerifier`, issues a ticket; Logout invalidates; Log → audit sink.
- T4 under *configured* auth, enforce ticket/identity on subsequent ops; **open-auth unchanged** for the harness.
- *Exit:* Login issues a real ticket; unauth mutating op under configured-auth → `PermissionDenied`; `SASED-M-1/2`, `QS-*` green in open-auth.
- *Confidence:* shape grounded; session-integration seam to trace at build.

**1.5 Wire HSS/LMS signing** — RFC 8554 / HSS · *(M / Low — revised down from L/High)*.
**The engine already manages HBS state; the KMIP layer manages none of it.** `ffi.rs::C_Sign` (:3271–3360) already implements HSS: an `update_fn` captures the advanced private state, `crypto::lms::hss_sign` drives it, and the new `CKA_LEAF_INDEX` is atomically read-advance-persisted onto the key object. But `native/sign.rs` (the path the KMIP server uses) **omits** the HSS arm and falls to `CKR_MECHANISM_INVALID`.
- T1 **extract** the HSS/LMS sign-and-advance core out of `ffi.rs::C_Sign` into **one shared engine helper** (single source of truth for leaf-index persistence — where drift = key reuse).
- T2 **call it from both** `ffi::C_Sign` and `native/sign.rs::sign`/`sign_pqc` (replaces C_Sign's inline copy; adds the missing native arm — the actual "wire it").
- T3 **KMIP dispatch:** `ops/sign.rs` routes an HSS/LMS-keyed Sign to the native HSS path by the stored key's algorithm/param set; surface `CKR_KEY_EXHAUSTED` as the KMIP `ResultReason`. No state handling here.
- T4 **verify (not build):** confirm HBS keys are backed by a **durable** token store in the deployment (leaf-index write must survive a crash) — an engine object-store property; note in the deployment doc.
- *Exit:* KMIP Sign on an HSS key → signature `hss_verify` accepts; leaf advances+persists via the shared helper; second sign consumes a new leaf (unit test: distinct indices + persisted counter); exhaustion → clean error; FFI and native paths byte-identical.

### Phase 2 — Corpus closure → 97/102

**2.1 Stateful Locate** — `SASED-M-3`, `TL-M-3` · *(S / L, harness)*. Filters already implemented (`locate.rs:205-216`).
- T1 replay the paired transcripts (M-2→M-3) against **one** server instance (no per-test wipe, `dispatcher_replay.py:142`); keep all else hermetic.
- T2 add Rust unit tests for Locate-by-GroupLink + Locate-by-ApplicationSpecificInformation (currently inspection-only).
- T3 reclassify both to expected-PASS in `assert_replay_report.py`.
- *Exit:* both PASS as real cross-request Locate.

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

**3.2 Set Constraints** — §6.1.57 (pairs Get §6.1.26) · *(S–M / L)*.
- T1 back `server_constraints()` (`allocation_and_config.rs:152`) with a mutable store.
- T2 implement Set Constraints writing that store; Get reads it back.
- *Exit:* Set→Get round-trips.

**3.3 Create / Join Split Key** — §6.1.12 / §6.1.31; attrs §4.64–4.66; enums §11.54/§11.55 · *(M–L / M)*.
Types exist (`attrs.rs:64` SplitKey=0x05; `ops.rs:115/134`) → route to Unsupported. **Engine has no secret-sharing primitive — implement from spec.**
- T1 implement the **four §11.54 methods**: XOR (0x01), Polynomial Sharing GF(2¹⁶) (0x02), Polynomial Sharing Prime Field (0x03), Polynomial Sharing GF(2⁸) (0x04); with the §11.55 polynomials (Polynomial-283, Polynomial-285) for the GF variants (Shamir threshold sharing).
- T2 Create Split Key (§6.1.12): generate key, split into `Split Key Parts` (§4.65) with `Split Key Threshold` (§4.66) + `Split Key Method` (§4.64), register each share as a `SplitKey` object.
- T3 Join Split Key (§6.1.31): require ≥ threshold identifiers (SHALL), reconstruct, register the joined object.
- T4 remove `SplitKey` from `ADVERTISED_UNIMPLEMENTED_OBJECT_TYPES` (`query.rs:212`).
- *Exit:* Create N shares; Join of ≥threshold reconstructs the exact key; fewer-than-threshold fails (§6.1.31); KATs per method.

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

### Phase 7 — Verification & CI
- **7.1** Update `assert_replay_report.py` → **97 PASS / 5 SKIP_DEPRECATED / 0 fail / 0 SKIP_OP** + explicit declined set; keep `check_report_fresh.py`. *(S)*
- **7.2** New coverage: HSS/LMS sign + **state-advance/no-reuse** (critical), async round-trip + Cancel/Process/QueryAsync, Split Key create/join per method (threshold), real auth ticket, PKCS#11 real proxy, 2 stateful-Locate filters, 4 RNG-seed behaviors. *(M)*
- **7.3** Regenerate `REPLAY_REPORT.{md,json}`, `CONFORMANCE_REPORT.md`, crossref YAMLs; ensure the 3 CI jobs gate the new expectations. *(S)*

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
