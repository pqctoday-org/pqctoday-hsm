# KMIP 3.0 Coverage-Gap Implementation & Test Plan

**Date**: 2026-06-13 · **Base**: `main` @ `03bd0b6` (post compliance rounds + PR #97 Locate fix)
**Driver**: the KMIP 3.0 spec-coverage audit (2026-06-13) — two parallel passes
(spec-surface matrix + test-depth inventory) against
`kmip/spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json` and current code.

## Current coverage (baseline this plan improves on)

| Dimension | Spec | Implemented | Tested | Ratio |
|---|---|---|---|---|
| Operations | 64 | 49 | 31 corpus / 49 unit | 48% functional |
| Object types | 15 | ~10 | ~9 | 60% |
| Attributes | ~70 | ~50 | ~35 | ~50% |
| State machine | 6 / 9 transitions | 9/9 | 9/9 | 100% |
| Result reasons | 78 | 33 | 32 | 41% |
| Crypto algorithms | 74 | ~30 (rest legacy) | ~30 | 41% raw / ~100% in-scope |
| Message-layer | 10 | 10 | 10 | 100% |
| Profiles (corpus) | 102 | — | 92 PASS | 90% |

**Scope philosophy** (unchanged): deprecated mechanisms (DES/3DES/DSA) stay
out by design (`kmip/DEPRECATED.md`, NIST-cited). This plan does NOT add them.
It closes (a) test-rigor gaps on what's already implemented and (b) the
implementable spec-surface gaps that have real value.

## Phasing

Three phases, value-first. **Phase 1 (test rigor) should land before Phase 2/3**
— it builds the safety net that proves the new implementation work doesn't
regress conformance, and it closes the process gap (no CI gate) that already
let one regression ship.

Effort key: S ≤ ½ day · M 1–2 days · L multi-day.

---

# Phase 1 — Test rigor & regression safety net (highest value, lowest risk)

No production behavior changes; pure coverage + CI. These would each have
caught a real defect already shipped (the Locate regression, the orphaned KATs).

## P1.1 — CI-gate the OASIS conformance replay (S–M) — TOP PRIORITY

**Gap**: `dispatcher_replay.py` (the only true protocol-conformance check) is
manual; `REPLAY_REPORT.md` is a checked-in artifact. CI runs only `cargo test`.
This is how the 92→89 Locate regression shipped to `main` unnoticed.

**Implementation**:
- Add a CI job in `.github/workflows/ci.yml` (mirror the existing `rust-test`
  job style): build the release server (`cd kmip && cargo build --release`),
  run `python3 conformance/harness/dispatcher_replay.py`, and **assert the
  result**: parse `conformance/REPLAY_REPORT.json` and fail the job if
  `FAIL > 0` or `PASS < 92` (the harness already exits non-zero on FAIL — verify
  and rely on exit code first; add the JSON assertion as belt-and-suspenders).
- Pin the skip set: fail if the SKIP count or categories drift from the
  documented 10 (5 deprecated + 2 precondition + 3 policy-variant) — a new skip
  silently appearing is a coverage regression.
- Make the harness hermetic in CI: it needs the TLS server + Python; ensure the
  workflow installs python3 and the server's test cert path resolves in the CI
  workdir (the harness spawns `target/release/pqctoday-kmip --store-memory`).
- **Stop committing REPLAY_REPORT.md as the source of truth** — either
  regenerate-and-diff in CI (fail if the committed report is stale) or mark it
  generated and have CI produce it as an artifact. Prefer: CI regenerates and
  fails if `git diff` shows the committed report is stale, so the checked-in
  report can never again lie (it was stale at 1 test when the regression hit).

**Tests/gates**: the job itself is the gate. Verify it goes red on a seeded
regression (temporarily break one op, confirm CI fails, revert).

## P1.2 — Wire the orphaned NIST/ACVP KAT vectors (M) — TOP PRIORITY

**Gap**: `kat/{aes,ecdsa,hmac,ml-dsa,ml-kem,rsa,sha,slh-dsa}/*-acvp.json` (~26
vector files) are checked in and hashed in `kat/manifest.sha256`, but
`kat/README.md` claims `tests/acvp_roundtrip.rs` consumes them — **that file
does not exist**. Crypto correctness today is self-consistency round-trips only
(sign↔verify, encap↔decap), never "matches the published NIST answer."

**Implementation**:
- Create `kmip/tests/acvp_roundtrip.rs`. For each vector family, parse the ACVP
  JSON (the standard NIST ACVP structure: testGroups → tests with hex inputs +
  expected outputs) and drive the **KMIP op path** (or the engine bridge) with
  the vector's inputs, asserting the output equals the vector's expected bytes:
  - AES (CBC/CTR/GCM): encrypt KAT — ct == expected; decrypt KAT — pt == expected.
  - HMAC-SHA256/384/512: MAC == expected.
  - SHA/SHA3: digest == expected.
  - RSA (PKCS1v1.5, PSS, OAEP): sigVer/decrypt KATs (deterministic ones byte-exact;
    PSS via verify-of-known-good).
  - ECDSA: sigVer KATs.
  - ML-KEM (FIPS 203): keyGen (d‖z → ek/dk), encapsulation (ek + m → ct/ss),
    decapsulation (dk + ct → ss) — byte-exact against ACVP.
  - ML-DSA (FIPS 204): keyGen (ξ), sigGen (deterministic), sigVer.
  - SLH-DSA (FIPS 205): keyGen, sigVer (sigGen is huge/slow — sigVer + a few
    sigGen).
- Verify the vectors against `kat/manifest.sha256` at test start (so a corrupted
  vector file fails loudly, not silently).
- Where a KMIP op can't take raw deterministic inputs (e.g. IV/nonce is
  server-generated), drive the **engine bridge directly** (`softhsmrustv3::native`)
  for the KAT — the goal is golden-vector correctness of the crypto the KMIP
  layer dispatches to, not necessarily through the full TTLV path.
- Fix `kat/README.md` to match reality (it currently documents a non-existent
  file).

**Tests/gates**: the new test file IS the coverage. Must run under `cargo test`
(so it's CI-gated via the existing `rust-test` job). Report per-family vector
counts so coverage is visible. Gate: every manifest vector either executes or is
explicitly listed as skipped-with-reason (no silent orphans).

## P1.3 — Corpus/e2e coverage for the 11 implemented-but-uncovered ops (M)

**Gap**: AdjustAttribute, Archive, Deactivate, DiscoverVersions, Export, Import,
Login, Logout, Ping, Recover, SetAttribute are implemented and unit-tested but
exercised by **no OASIS transcript** — never proven through the full
TLS+wire+dispatcher round-trip. Same for the K20/K21 ops (DeriveKey, ReKey,
ReKeyKeyPair, GetUsageAllocation, GetConstraints, SetDefaults, SetEndpointRole).

**Implementation**:
- These ops aren't in the OASIS corpus (the corpus is fixed/official), so add
  **rust e2e tests in `tests/native_bridge_e2e.rs`** (or a new
  `tests/kmip_op_e2e.rs`) that drive each through the real dispatcher with a real
  engine session and assert the full response shape + a meaningful outcome
  (not just CKR_OK):
  - Archive→Get fails ObjectArchived→Recover→Get succeeds (round-trip).
  - Deactivate transitions Active→Deactivated (assert State attr).
  - Import then Get recovers the imported material; Export round-trips it.
  - DeriveKey produces a usable key (derive then encrypt with it).
  - ReKey/ReKeyKeyPair: replacement links + original deactivation asserted.
  - Login/Logout gate private-object access (assert a private op fails logged-out).
  - SetAttribute/AdjustAttribute: set→GetAttributes reflects it; read-only rejected.
- Each test runs under `cargo test` → CI-gated.

**Tests/gates**: per-op e2e with a real outcome assertion. Coverage target: every
op in `HANDLED_OPERATIONS` has at least one full-round-trip e2e test.

## P1.4 — Exhaustive state-machine transition matrix (S)

**Gap**: `store/lifecycle.rs` tests are selective (identity diagonal looped, the
rest spot-checked). Several cells (Compromised→Active, Active→PreActive) are only
implicitly covered.

**Implementation**: add one table-driven test enumerating all 6×6 (from,to) ×
{the transition-triggering ops} pairs against `State::can_transition_to` /
`enforce_transition`, asserting allowed vs `WrongKeyLifecycleState` for every
cell per the §3 state diagram. ~30 lines, pins the FSM exhaustively.

**Tests/gates**: the matrix test; cross-check against the spec §3 diagram in a
comment.

---

# Phase 2 — Implementable spec-surface gaps (real value)

Operations and features with genuine utility that are currently unimplemented.
Each follows the established slice pattern: ops.rs handler + wire codec +
dispatcher arm + HANDLED_OPERATIONS + unit tests + e2e + replay stays 92/0/10.

## P2.1 — Object Group / group-membership Locate (M) — closes 2 skips

**Gap**: Object Group attribute + Locate-by-group is unimplemented; this is the
direct cause of the 2 `SKIP_PRECONDITION` transcripts (SASED-M-3, TL-M-3) — they
Register an object into a group in transcript N, then Locate-by-group in N+1.

**Implementation**:
- Store the Object Group attribute on the record (it may already be storable as
  a generic attr — verify in `attrs.rs`/store schema).
- Implement Locate filtering by Object Group / GroupLink.
- The 2 skipped transcripts require **cross-transcript state** which the hermetic
  harness wipes — so this won't un-skip them in the replay (that's a harness
  isolation property, not an impl gap). Add **rust e2e** proving
  Register-into-group → Locate-by-group within one session works. Document that
  the 2 skips remain harness-isolation artifacts, now with the underlying
  capability actually implemented + tested.

**Tests**: e2e group-membership Locate; unit tests for the group filter.

## P2.2 — Validate operation (M)

**Gap**: Validate (certificate-chain validation) unimplemented. Baseline-adjacent.

**Implementation**: Validate request (list of Certificate UIDs / a chain) →
validate the chain via the engine's X.509 path (OpenSSL); return ValidityIndicator.
Scope to what the engine can actually verify (path building, expiry, signature);
document what's not checked (revocation/OCSP if absent).

**Tests**: e2e — valid chain → Valid; broken/expired → Invalid; unit error paths.

## P2.3 — Certify / Re-certify (L)

**Gap**: CA operations unimplemented. Higher effort — needs a CSR path + a
signing-CA key + certificate issuance.

**Implementation**: Certify (CSR + CA key → issued Certificate object). Requires
CertificateRequest object-type handling (currently partial). Re-certify =
re-issue with a new validity window. Gate on whether the engine exposes X.509
issuance; if not, this may need an OpenSSL cert-builder in the KMIP layer.
**Assess feasibility first**; if the engine can't issue certs, document as a
larger track rather than forcing it.

**Tests**: e2e CSR→Certify→Validate round-trip.

## P2.4 — Result-reason emit paths for the high-value unmapped reasons (S–M)

**Gap**: 45/78 spec reasons have no emit path. Most are for unimplemented
features, but several are reachable today and currently surface as a generic
reason:
- **MissingInitializationVector (0x34)** — an AEAD/CBC op missing its IV should
  emit this, not a generic InvalidField. Wire it in the encrypt/decrypt IV check.
- **Wrapping Object Archived/Destroyed/Not Found (0x40–0x42)** — Get-with-wrapping
  or Register-wrapped where the KEK is archived/destroyed/absent. Wire into the
  K16/K17 wrap/unwrap KEK-resolution paths.
- **Circular Link Error (0x4d)** — Add/Modify a Link that creates a cycle.
- **Constraint Violation (0x4b)** — when a Set Defaults / Get Constraints bound
  is violated (ties to the K19 constraints work).

**Implementation**: add the variants to `error.rs`, emit at the right sites,
each with a negative-path unit test asserting the specific reason.

**Tests**: one negative test per newly-emitted reason.

## P2.5 — ML-KEM encapsulation via a KMIP transcript path + AES-XTS functional (S–M)

**Gap**: ML-KEM encap/decap is e2e-tested (`k9_*`) but never via a KMIP
Encrypt/Encapsulate transcript; AES-XTS passes at codec level but XTS isn't in
the block-cipher-mode→mechanism map (`helpers.rs` maps CBC/ECB/CTR/GCM only —
verify XTS actually encrypts vs failing 0x3e).

**Implementation**: confirm/extend the KMIP-level encap path; add XTS to the mode
map if the engine supports it (else confirm it correctly returns
UnsupportedCryptographicParameters and document XTS as out-of-scope).

**Tests**: e2e ML-KEM through the KMIP op surface + negative (bad ciphertext);
XTS encrypt/decrypt or explicit-rejection test.

---

# Phase 3 — Lower-priority / optional-by-spec (defer unless needed)

These are spec-optional or legacy; implement only if a consumer needs them.
Document the decision either way (don't leave them as silent gaps).

- **Async family** (Poll, Cancel, Query Asynchronous Requests, Notify, Put,
  Process) — the server advertises `Asynchronous Capability = false`; these are
  consistently unimplemented and honestly rejected (OperationNotSupported). Keep
  as documented out-of-scope unless async is a product requirement (it's a large
  architectural addition — a server-initiated channel).
- **Split Key** (Create/Join Split Key + SplitKey object type) — niche; implement
  only if Shamir-split key escrow is needed.
- **PGPKey, CertificateRequest** object types — partial register plumbing exists;
  finish only if a consumer registers them.
- **Obtain Lease, Re-Provision, Delegated Login, Set Constraints** — legacy/
  optional; document as out-of-scope.

---

# Cross-cutting: doc hygiene (S)

- `kmip/docs/CONFORMANCE_REPORT.md` — predates K20/K21; refresh the op list and
  the coverage matrix to the current 49-op surface, and add this plan's coverage
  ratios so the report distinguishes "corpus pass-rate" from "spec coverage."
- `kmip/conformance/harness/dispatcher_replay.py` — its inline comment says "12
  ops implemented" and `IMPLEMENTED_OPS` omits the K19–K21 additions; sync it.
- `kat/README.md` — fix the reference to the (now-created in P1.2)
  `acvp_roundtrip.rs`.

---

# Sequencing & definition of done

```
Phase 1 (do first — the safety net):
  P1.1 CI-gate replay ──┐
  P1.2 ACVP KATs        ├─ independent, land together; both close shipped-defect classes
  P1.3 op e2e coverage  │
  P1.4 FSM matrix       ┘
Phase 2 (after the net is in place, so regressions are caught):
  P2.4 result reasons (S) → P2.1 object-group (M) → P2.5 encap/XTS (M)
  → P2.2 Validate (M) → P2.3 Certify (L, feasibility-gated)
Phase 3: per-need, document decisions.
```

**Standing gates for every slice** (Phase 2/3): `cargo test` green; OASIS replay
**92 PASS / 0 FAIL / 10 SKIP** (now CI-gated after P1.1); `cargo build --release`;
the new ACVP KAT suite green; no new compiler warnings in touched files.

**Definition of done for the program:**
- OASIS replay is CI-gated and the committed report can't go stale (P1.1).
- Every KMIP-dispatched algorithm has a golden-vector NIST/ACVP KAT that
  executes in CI (P1.2) — crypto correctness is "matches NIST," not just
  round-trip.
- Every `HANDLED_OPERATIONS` op has a full-round-trip e2e test (P1.3).
- The state machine is exhaustively matrix-tested (P1.4).
- Object-group Locate, Validate, the high-value result reasons, and ML-KEM/XTS
  KMIP-path coverage are implemented + tested (Phase 2).
- Every remaining unimplemented spec op is either implemented or **explicitly
  documented as out-of-scope with a rationale** — no silent gaps.

**Estimated effort**: Phase 1 ≈ 4–6 days (highest value), Phase 2 ≈ 5–8 days,
Phase 3 per-need. Phase 1 alone moves the project from "strong in-scope coverage,
manually verified" to "strong in-scope coverage, CI-enforced with golden-vector
crypto correctness."
