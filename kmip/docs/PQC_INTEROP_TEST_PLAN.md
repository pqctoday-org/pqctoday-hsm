# KMIP 3.0 PQC Interop Test Set — Implementation Plan (the "1452" tests)

**Date**: 2026-06-13 · **Base**: `main` (after Phase 1 #98 merged; should build on Phase 2 #99 once merged)
**Goal**: run and pass the **1452-case KMIP 3.0 PQC interoperability test set** from
the 2025 OASIS PQC plugfest (kmip-interop.org), against our server, through the
existing replay harness — turning self-contained ACVP KATs into
NIST-known-answer validation **across the full KMIP wire + operation surface**.

## Crypto backend constraint (non-negotiable)

**All cryptography exercised by these tests MUST be performed by the
`softhsmrustv3` Rust engine** (`rust/`), via the KMIP server's existing
`Deps::engine_session` → `softhsmrustv3::native::*` bridge. This is already the
KMIP server's only crypto path (Plane-3): CreateKeyPair, Sign, SignatureVerify,
Encrypt(encapsulate), Decrypt(decapsulate) all dispatch into
`softhsmrustv3::native`. Concretely, for this plan:

- **keygen** → `native::generate_{ml_dsa,ml_kem,slh_dsa}_keypair_from_seed`
  (T7, in `softhsmrustv3`).
- **siggen / sigver** → `native::sign` / `native::verify` with deterministic
  mode (`softhsmrustv3` ML-DSA/SLH-DSA).
- **decap** → `native::decapsulate`; **encap** → `native::encapsulate`
  (or a new `softhsmrustv3` deterministic-coins entry point — I5).

Hard rules: do NOT use OpenSSL, `ring`, `x509-cert`, `rcgen`, the C++ engine, or
any non-`softhsmrustv3` crate to produce a key, signature, shared secret, or
ciphertext that a transcript's expected value is compared against. Those crates
may appear ONLY as **independent external verifiers** in a separate cross-check
(as in P2.3's OpenSSL cross-check), never as the engine under test. If a
deterministic primitive the interop set needs is missing, it is added to /
patched into `softhsmrustv3` (precedent: the fips204/fips205 deterministic
keygen and hbs-lms patches already vendored in `rust/`), not worked around in
the KMIP layer. The whole point is to prove **softhsmrustv3** is
NIST-ACVP-correct through the KMIP surface.

## Provenance & ground truth (verified)

- **Source**: `https://groups.oasis-open.org/higherlogic/ws/public/download/72593/kmip-3-0-pqc-tests-03.zip`
  (32 MB, 1452 `.xml` transcripts, dated 2025-02-26). Individual files also at
  `https://kmip-interop.org/test-xml/`. Used in the March 3–7 2025 plugfest
  (Cryptsoft, NetApp, Project 6 Research; >1M messages exchanged).
- **Format**: OASIS KMIP XML transcripts — **same notation as our
  `conformance/oasis_corpus`** (`<KMIP>` → `<RequestMessage>`/`<ResponseMessage>`)
  EXCEPT each file has `#`-prefixed annotation lines (`# ML-DSA-44-keygen-1-30.xml`,
  `# ... note uses seed so answer is fixed value`) that are NOT valid XML — our
  harness rejects them at parse (verified: SKIP_PARSE "not well-formed line 1").
- **Concrete values, not placeholders** (verified): keygen transcripts carry
  `<Seed value="4BE7…">` + the exact expected `<KeyMaterial value="ADB0…">`;
  siggen carries `<Deterministic value="true"/>` + `<Data>` + the exact expected
  signature; encapsulation registers concrete keys. So the harness's **byte-exact
  comparison genuinely validates the NIST answer** (unlike the profiles corpus,
  where crypto outputs are `$`-placeholder-bound and not checked).

## Category inventory (1452 total)

| Category | Count | Mechanism for a fixed answer | Server capability needed |
|---|---|---|---|
| **keygen** (ML-DSA 75, ML-KEM 75, SLH-DSA 120) | **270** | `<Seed>` → deterministic keygen | `CreateKeyPair` threads `Seed` → engine `generate_*_keypair_from_seed` (engine **has** this, T7; KMIP layer must wire it) |
| **sigver** (ML-DSA 135, SLH-DSA 336) | **471** | provided key+sig+data → Valid/Invalid | `SignatureVerify` (already real verification) + Register-public-key |
| **siggen** (ML-DSA 270, SLH-DSA 336) | **606** | `<Deterministic value="true"/>` → deterministic signature | `Sign` threads the `Deterministic` param → engine deterministic ML-DSA/SLH-DSA signing (engine supports hedge/deterministic) |
| **decapsulation** (ML-KEM 30) | **30** | provided dk + ct → exact shared secret | `Decrypt`(decapsulate) (deterministic; P2.5 proved the round-trip) |
| **encapsulation** (ML-KEM 75) | **75** | exact ct from provided coins `m` | encaps with **caller-supplied coins** — engine generates its own randomness today; **needs investigation / likely engine work** |

**Reachability**: keygen + sigver + siggen + decap = **1377 (95%)** are reachable
by threading deterministic capabilities the engine already has. **encapsulation
(75, 5%)** is the one category that may need a new engine entry point
(ML-KEM.Encaps_internal(ek, m) with provided coins).

## Phasing

Six slices. I1 is the enabler; I2–I3 prove the deterministic-seed/verify path
fast (the high-confidence 771); I4 is the bulk (siggen, deterministic-sign
threading); I5 is the one uncertain category (encaps) — feasibility-gated; I6
gates + documents. Effort: S ≤½d · M 1–2d · L multi-day.

### I1 — Corpus ingestion + harness adaptation (S–M) — ENABLER

1. **Vendor the corpus**: extract the 1452 transcripts into
   `kmip/conformance/pqc_interop_corpus/` (mirror how `oasis_corpus` is vendored)
   with a `README.md` documenting provenance (URL, plugfest, date) + a
   `sha256` manifest of all files. ~32 MB — confirm repo-size acceptability;
   if too large, a fetch-script + checksum alternative (but vendoring matches
   the existing `oasis_corpus` precedent and keeps CI hermetic).
2. **Harness `#`-strip**: in `dispatcher_replay.py`, strip leading-`#` lines
   before XML parse (a 2-line preprocessor in the file loader). Verify it doesn't
   affect the profiles corpus (no `#` lines there).
3. **Second corpus dir**: parameterize the harness to run either corpus — add a
   `--corpus pqc_interop` flag (or a sibling entry point
   `pqc_interop_replay.py` reusing the same machinery) so the profiles replay
   (the CI-gated 92/0/10) stays separate and unchanged.
4. **Baseline run**: run all 1452 as-is and record the **honest starting pass
   count** (most will FAIL until I2–I5 thread determinism — that's the baseline
   we improve). Produce `PQC_INTEROP_REPORT.{md,json}` (same shape as
   REPLAY_REPORT) with per-category PASS/FAIL.

**Gate**: harness parses all 1452 (0 SKIP_PARSE); baseline report generated;
profiles replay still 92/0/10.

### I2 — keygen (270): deterministic keygen from Seed (M)

The KMIP `CreateKeyPair` (and `Create` for symmetric, N/A here) must extract the
`Seed` attribute from the request and call the engine's deterministic keygen.
- Verify the `Seed` tag/attribute the transcripts use (it appears as
  `<Seed type="ByteString">` in the KeyBlock/template — map to `CKA_SEED` 0x637).
- Thread it: `ops/create_key_pair.rs` → when `Seed` present, call
  `native::generate_ml_dsa_keypair_from_seed` / `_ml_kem_` / `_slh_dsa_` (T7
  entry points) instead of the random path. Validate seed length per
  family/param-set (ξ=32 ML-DSA; d‖z=64 ML-KEM; 3n SLH-DSA).
- The transcript then `Get`s the key and expects the exact `KeyMaterial` — our
  deterministic key must reproduce it byte-for-byte. The KeyFormatType/SPKI
  encoding the transcript expects must match what we emit (verify the public-key
  serialization aligns — tie to the engine SPKI builders + the P2.5/Get path).
- **Tests**: run the 270 keygen transcripts → target 270/270. Where the
  expected KeyMaterial encoding differs from ours, reconcile the serialization
  (this is where most real fixes will be — raw vs SPKI vs the exact byte layout
  the interop set expects).

**Gate**: keygen category pass count reported (target 270/270); profiles replay
unchanged; `cargo test` green.

### I3 — sigver (471) + decap (30): verification paths (M)

- **sigver**: the transcript Registers a public key + supplies sig + data, calls
  `SignatureVerify`, expects `ValidityIndicator`. We already do real
  verification (P2.x). Ensure: public-key Register accepts the transcript's key
  format; the Sign/Verify mechanism + the `Deterministic`/hashing params are
  honored; the ValidityIndicator matches (Valid for good sigs, Invalid for the
  negative vectors). Run the 471 → target 471/471.
- **decap**: Register dk, `Decrypt`(decapsulate) with provided ct, expect the
  exact shared secret. P2.5 proved decap recovers the secret; here the secret is
  a fixed ACVP value — confirm byte-exact. Run the 30 → target 30/30.

**Gate**: sigver + decap pass counts reported; profiles replay unchanged.

### I4 — siggen (606): deterministic signing (M–L)

The Sign request carries `<Deterministic value="true"/>` (verified) + the data;
the transcript expects the **exact** ML-DSA/SLH-DSA signature.
- Thread the KMIP `Deterministic` parameter through `ops/sign.rs` → the engine's
  deterministic signing mode (ML-DSA `rnd=0` / the `CKH_DETERMINISTIC` hedge
  variant; SLH-DSA deterministic). The engine already honors context+hedge
  (audit H-17 confirmed present) — verify it produces the FIPS-204/205
  deterministic signature byte-for-byte.
- ML-DSA deterministic signing with `rnd=0` is reproducible; confirm the
  engine's deterministic path matches the ACVP `siggen` deterministic answers
  (the P1.2 ACVP work already validated ML-DSA sigVer; siggen byte-exact was
  deferred there for hedged mode — deterministic mode is the reproducible one,
  so this should now be reachable).
- SLH-DSA deterministic siggen: the P1.2 work noted the engine's deterministic
  SLH-DSA output didn't byte-match one generator's vectors (generator-specific
  `opt_rand`/addrnd). RE-VERIFY against the INTEROP set's deterministic vectors
  specifically — if the interop set uses pure deterministic (addrnd=0) and the
  engine matches, great; if there's a generator-specific divergence, document
  precisely which SLH-DSA siggen transcripts can't byte-match and why (do not
  fake — report the real number).

**Gate**: siggen pass count reported (target 606, or the honest reachable
subset with documented SLH-DSA caveats); profiles replay unchanged.

### I5 — encapsulation (75): deterministic encaps with provided coins (L, feasibility-gated)

The only category needing possibly-new engine support. ML-KEM encapsulation is
randomized (the responder picks coins `m`); a FIXED ct requires using the
ACVP-provided `m`. Assess:
- How does the transcript supply `m`? (inspect the encapsulation transcripts —
  it may be a `Seed`/random attribute on the Encrypt request, or a separate
  field). Document the mechanism.
- Does the engine expose `ML-KEM.Encaps_internal(ek, m)` (deterministic encaps
  with provided coins)? The `ml-kem` crate's public `encapsulate` takes an RNG;
  internal/deterministic encaps may need the crate's `..._internal` API or a
  patch (precedent: the fips204/fips205 deterministic keygen the engine already
  uses). If the crate exposes it → wire a `native::encapsulate_deterministic`
  and thread the KMIP encap path to use the provided coins. If NOT exposed →
  this is a fork-patch (like hbs-lms/fips20x) — assess cost.
- If genuinely infeasible without significant engine work, DEFER encapsulation
  with the specific blocker documented, and report the 1452-minus-75 = **1377**
  as the achieved set. Do NOT fake encaps passes.

**Gate**: encapsulation pass count (target 75 if feasible, else documented
deferral with the engine blocker); profiles replay unchanged.

### I6 — CI gate + report + docs (S)

- **CI**: add a `kmip-pqc-interop` job (or extend `kmip-conformance`) running the
  1452-set replay and asserting the pass count == the achieved number (with the
  documented deferrals pinned, like the profiles skip-set guard). Note: 1452 ×
  ~0.5 s server-restart ≈ 12 min — consider a faster mode (batch transcripts
  per server instance where state allows, or a separate slower nightly job) so
  it doesn't bloat every PR. Decide PR-gate vs nightly.
- **Report**: commit `PQC_INTEROP_REPORT.{md,json}` with per-category counts +
  the staleness guard (reuse P1.1's `check_report_fresh.py` pattern).
- **Docs**: update `CONFORMANCE_REPORT.md` to distinguish the profiles corpus
  (92/102 protocol conformance) from the PQC interop set (N/1452 NIST-KAT-through-
  KMIP), and `COVERAGE_GAP_PLAN.md`. State the honest headline: "X of 1452 PQC
  interop transcripts pass" with the per-category breakdown and any deferral.

## Sequencing & definition of done

```
I1 (enabler: ingest + #-strip + baseline) ──►
  I2 keygen (Seed threading) ─┐
  I3 sigver + decap           ├─ the high-confidence 771; can run in parallel after I1
  I4 siggen (deterministic)   ┘
  I5 encapsulation (feasibility-gated; may defer 75)
  I6 CI gate + report + docs
```

**Honest reporting throughout** (the rule this whole effort has followed): every
run reports the REAL pass count; no placeholder-masked passes (the values are
concrete, so the harness genuinely checks them); any transcript we can't pass is
listed with its specific reason (encaps engine gap / SLH-DSA generator-specific
siggen / format mismatch), never hidden.

**Definition of done**:
- All 1452 transcripts PARSE and run through the harness (I1).
- keygen + sigver + siggen + decap (1377) pass byte-exact, or each failure is a
  documented, specific gap.
- encapsulation (75) either passes or is deferred with the engine blocker named.
- The achieved count is CI-gated and can't regress, with a fresh committed report.
- `CONFORMANCE_REPORT` states the result honestly: "we pass X/1452 of the OASIS
  KMIP 3.0 PQC interop set" — distinct from the 92/102 profiles conformance and
  from true multi-vendor interop (which additionally needs a peer server and
  remains out of scope here).

## What this does and does NOT prove

- **Proves**: our server produces NIST-ACVP-correct PQC outputs (keys,
  signatures, shared secrets) through the real KMIP wire + operation surface,
  matching the exact answers the 2025 plugfest used — strong PQC conformance.
- **Does NOT prove**: live multi-vendor interoperability (exchanging messages
  with Cryptsoft's/NetApp's independent servers). That requires a peer and is a
  separate effort; passing the published test set is the necessary precondition
  for, but not equivalent to, a plugfest pass.

## Estimated effort
I1 S–M · I2 M · I3 M · I4 M–L · I5 L (feasibility-gated) · I6 S.
Roughly: the high-confidence 1377 across I1–I4 is ~1–1.5 weeks; encapsulation
(I5) depends on the engine-coins assessment. Phase 1's CI-gated harness + P1.2's
ACVP KAT scaffolding + T7's deterministic keygen + P2.5's ML-KEM-via-KMIP are
direct foundations — much of the engine capability already exists; the work is
threading it through the KMIP op layer and reconciling exact byte encodings.
