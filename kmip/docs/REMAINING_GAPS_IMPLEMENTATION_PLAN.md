# Remaining Gaps — Implementation Plan

Covers the gaps open after: engine reproduces all 1452 OASIS PQC interop KATs
byte-exact (PR #102); KMIP server-side PQC ops — keygen-seed (#104), Sign/Verify
flags (#102), Encapsulate/Decapsulate (#105); crypto-policy mechanism dimension
(PR #106). **Date**: 2026-06-14.

> **Source-of-truth rule (unchanged):** every KMIP tag/enum from
> `spec/oasis-kmip-3.0/…` (+ WD19 PDF for PQC); every `CK*` from
> `src/lib/pkcs11/pkcs11t.h` (mirror: `rust/src/constants.rs`). No guessed values.

Priority order: **W1** (the real interop claim) > **W2** (policy completeness,
mostly quick) > **W4** (operability) > **W3** (alternate backend, large/optional).

---

## W1 — Full KMIP transcript replay of the 1452 set  *(highest value, largest)*

**Goal:** drive the 1452 OASIS transcripts as live KMIP request/response
exchanges through the TLS server and pass them — turning "every component
produces the right bytes" into "the server passes the OASIS 1452 protocol set."

**Why it's big:** the comparison is tree-wise with placeholder binding
(`conformance/harness/dispatcher_replay.py`), and the transcripts carry *literal*
expected crypto. A transcript passes only when (a) the crypto bytes match —
**proven** — and (b) the server's **response structure** matches. (b) is the
open-ended bulk.

- **R1 — Python codec: teach `oasis_codec.py` the WD19 codepoints.** Add the PQC
  tags (`0x4201C3–CA`) to the tag table and the op enums (`Encapsulate 0x41`,
  `Decapsulate 0x42`) via the existing `_SPEC_EXTRACT_PATCHES`/tag-table seam
  (values already in `kmip-spec-v3.0-wd19-clean.pdf`, vendored, + this repo's
  memory). *Small.*
- **R2 — Corpus wiring.** Point a replay run at the PQC corpus
  (re-downloadable: kmip-interop.org → `…/72593/kmip-3-0-pqc-tests-03.zip`),
  strip leading `#` annotation lines, and bind the PQC placeholders
  (`$UNIQUE_IDENTIFIER_n`, `$NOW`, `$KEY_MATERIAL`, …) the same way the 3.0
  corpus does. *Small–medium.*
- **R3 — keygen/encap full-sequence support.** keygen `Seed` is wired (#104);
  ensure the keygen response emits the `SeedPrivateKey` KeyBlock the transcript
  expects; thread encap `InputKeyMaterial` through the real Encapsulate op
  (depends on R-of-W2 passthrough/Encapsulate maturity). *Medium.*
- **R4 — Per-category response-structure alignment (the bulk).** For each of
  keygen/siggen/sigver/encap/decap, make the server's `ResponsePayload` shape
  match the transcript (tags, nesting, KeyBlock format) so the tree comparator
  passes with placeholders bound. Drive this empirically: replay one transcript
  per category, diff, fix, repeat. *Large, iterative.*
- **R5 — CI gate + report.** Add a small PQC replay subset to CI (mirror the
  existing `dispatcher_replay` gate at 92/0/10); regenerate the full report on
  demand. Keep the slow SLH-"s" cases out of per-push CI (as today).

**Verify:** `dispatcher_replay.py` over the PQC corpus → PASS/FAIL per transcript;
target 0 FAIL on the actionable set. **Sizing:** R1–R3 days; R4 the long pole
(structure alignment across 5 categories).

---

## W2 — Crypto-policy completeness  *(mostly quick wins; on top of PR #106)*

- **W2.1 — Encrypt mechanism-param forcing.** Apply `Decision.cp_override` in
  `ops/encrypt.rs` (mirror `ops/sign.rs`): capture `forced_cp` at the decision,
  `merge_cp_override` into the effective CP before `aes_mechanism_for` /
  `encrypt_ml_kem`. Thread it into `encrypt_classical`/`encrypt_ml_kem`
  (the sub-functions compute their own CP today). *Small–medium.* Test: a
  policy forcing AES-GCM makes an app-requested CBC run as GCM.
- **W2.2 — Standalone `Hash` op gating.** Populate `PolicyRequest.mechanism`
  in `ops/mac_and_hash.rs::hash` (the keyless Hash op) so
  `hash_algorithm_allowlist` gates it. *Small.*
- **W2.3 — Expand `ckm_name_to_code`.** Grow the curated map in
  `policy/rule.rs` toward the full PKCS#11 v3.2 mechanism set the engine
  supports (AES-KWP, ChaCha20-Poly1305, prehash sig variants, the KDFs), each
  value referenced from `constants.rs`. *Small, mechanical.*
- **W2.4 — Verify the `CKM_KMAC` codepoint upstream.** Local `pkcs11t.h` +
  `constants.rs` agree (`0x80000100`, vendor-defined) — self-consistent. Check
  the canonical OASIS PKCS#11 v3.2 header
  (`docs.oasis-open.org/pkcs11/.../pkcs11t.h`): if v3.2 standardizes KMAC at a
  non-vendor codepoint, re-sync `pkcs11t.h` + `constants.rs` (and the JS/TS
  mirror per the cross-layer-constants memory). *Small; verification-first.*
- **W2.5 — Phase-gated (track, don't force now):**
  - `MaxKeyAgeDays` rule — needs the Phase-6 object store to expose
    `activated_at`; un-stub then.
  - Full `RekeyAndProceed` transaction (state→Deprecated, supersedes-link,
    re-issue) — Phase 6 store + lifecycle FSM.
  - Composite/hybrid signature **wire format** (`HybridDualSignRequirement`
    enforces; encoding deferred) — Phase 7 / LAMPS draft-19.
  - `ComplianceProfileGate` — keep documentational until the Phase-8
    compliance tool consumes it.

**Verify:** policy unit + integration suites stay green; new tests per item.

---

## W4 — Policy management facade  *(operability; unblocks the Hub UI)*

The enforcement plane is KMIP (done); the management plane is the Rust
`PolicyStore` API + YAML files only. Add a thin HTTP and/or WASM facade over the
existing `PolicyStore` primitives (`list/load/validate_draft/dry_run/save/
activate_with_engine/resume_active`) so the Hub UI can author, dry-run, and
activate policies. **No new KMIP surface** — policy admin stays out-of-band
(separation of duties). *Medium; design + a thin transport, no new logic.*

---

## W3 — Option C: C++ SoftHSM + OpenSSL 3.6 as an alternate KMIP backend  *(large, optional)*

Per the earlier `CRYPTO_BACKEND_ARCHITECTURE.md`: a `trait CryptoBackend`
abstraction with `SofthsmRustV3Backend` (current) and a `Pkcs11Backend`
(KMIP → C++ SoftHSM → OpenSSL 3.6 via the PKCS#11 C ABI), then dual-backend
1452 cross-validation (native only; WASM stays Rust). Shared blocker noted
there — encaps-with-coins — is now resolved on the Rust side
(`encapsulate_deterministic`); the C++/OpenSSL path exposes it via
`CKH_*`/`C_EncapsulateKey`. *Large, multi-week; start only if a second backend
is a product requirement.*

---

## Cross-cutting
- **CI economy:** one CI run per logical PR (not per commit); local `cargo test`
  + the policy/interop suites are the gate. Keep slow SLH-"s" vectors out of
  per-push CI; full 1452 runs on demand / nightly.
- **Suggested PR cuts:** [W2.1+W2.2+W2.3+W2.4] (one "policy completeness" PR) →
  [W1 R1–R3] → [W1 R4] (likely several) → [W4] → [W3] (its own track).
- **Recommended next:** W2 quick wins (fast, closes the policy asymmetries),
  then W1 (the real interop claim).
