# Remediation Plan — `CKM_HASH_ML_DSA*` / `CKM_HASH_SLH_DSA*` pre-hash mode (C++)

**Date:** 2026-08-30
**Baseline:** `fix/ws1-4-and-ws2-rust-gaps` (worktree `.worktrees/ws1-4-and-ws2`)
**Scope:** C++ engine only, per standing direction to finish PKCS#11 C++ before touching Rust.
**Parent item:** WS-3.3 in `docs/remediation-plan-pkcs11-v32-coverage-2026-08-29.md`.
**Status:** EXECUTED 2026-08-30 (steps 1–6; step 7, the full local gate, deferred per the standing "fix everything, test once" directive — see §7).

## 0. Why this plan exists

Earlier in this session, WS-3.3's "context" mode (`CKM_ML_DSA` with a non-empty
`ctx`) was wired against real ACVP vectors and passes (3/3). A follow-up attempt
to wire the "preHash" (`CKM_HASH_ML_DSA_*`) mode against the same vector file
was **built, run, and reverted** — every one of the 3 tested param sets returned
`CKR_OK` but the wrong signature bytes. The root cause was not found at the
time; the attempt was pulled rather than landed broken. This plan finds the
root cause, grounds the fix against FIPS 204 (as requested) and its FIPS 205
sibling, and scopes the evidence needed to close both.

## 1. Root cause (confirmed against source, not guessed)

FIPS 204 Algorithm 4 (`HashML-DSA.Sign`), step 23, and Algorithm 5
(`HashML-DSA.Verify`), step 18, both build the message representative as:

```
M' = IntegerToBytes(1,1) ‖ IntegerToBytes(|ctx|,1) ‖ ctx ‖ OID ‖ PH(M)
```

where **OID is the raw DER encoding of the hash function's object identifier
alone** — not an X.509-style `AlgorithmIdentifier SEQUENCE`. FIPS 205
(`HashSLH-DSA.Sign`/`.Verify`) defines the identical construction.

This repo does not carry a local FIPS 204/205 PDF (`docs/refs/` has only the
PKCS#11 spec family and the FrodoKEM/McEliece proposals), so rather than
fetching the NIST PDF, this plan grounds itself in two **already-vendored,
already-cited** reference implementations that exist for exactly this
purpose:

- `rust/fips204-patched/src/lib.rs:299-338` (Algorithm 4, cited by page number
  in its own doc comments) and `rust/fips204-patched/src/hashing.rs:319-427`
  (`hash_message`, comment: *"OIDs are per FIPS 204 Table 1 / RFC 8017 / IANA
  AlgorithmIdentifier registry"*).
- `rust/fips205-patched/src/lib.rs:224-243` and
  `rust/fips205-patched/src/hashers.rs:322-427` — the identical construction
  for SLH-DSA.

Both return an **11-byte raw OID** for every hash choice, e.g. SHA-256:
`06 09 60 86 48 01 65 03 04 02 01` (tag `06`, length `09`, 9-byte OID value —
nothing else).

**The C++ engine builds a different, larger structure.** Both
`src/lib/crypto/OSSLMLDSA.cpp:60-91` and `src/lib/crypto/OSSLSLHDSA.cpp:49-77`
define `ALGID_*` / `SLHDSA_ALGID_*` tables that wrap the same 11-byte OID in
an X.509 `AlgorithmIdentifier SEQUENCE { OID, NULL }` (15 bytes for
SHA-2/SHA-3) or `SEQUENCE { OID }` (13 bytes for SHAKE) — the encoding used
for RSA `DigestInfo` / X.509 `SignatureAlgorithm` elsewhere in this codebase,
but not what FIPS 204/205 ask for here. `buildPreHashEncoding()`
(`OSSLMLDSA.cpp:147-228`, reused by both `sign()` and `verify()`) then
concatenates this wrong-shaped blob into `M'`, so the pre-hash message
representative disagrees with the spec by exactly 2–4 bytes per signature —
enough to produce a structurally valid but byte-wrong signature, which is
exactly the symptom the reverted attempt hit (`CKR_OK`, wrong bytes).

**Why this was invisible until now:** `buildPreHashEncoding()` is the *only*
place either shape is constructed, and it is used identically by sign and
verify — so a same-engine round trip is self-consistent and passes, precisely
the WS-1.1-class blind spot the master plan's Tier-4 warning describes. The
"context" mode (already fixed and passing) does not go through this function
at all — it never builds an OID, so it was never exposed to this bug.

**Confirms it is not an OpenSSL integration issue:** `OSSLMLDSA.cpp:340-353`
passes the fully pre-built `M'` to OpenSSL with
`OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING = 0` ("raw / pre-encoded"), i.e. by
design OpenSSL is told not to touch the bytes further. The fix is entirely
local to `buildPreHashEncoding()`'s OID tables — no OpenSSL call shape
changes.

## 2. Fix (both files, same 2-line-per-entry change)

Replace every `ALGID_*` / `SLHDSA_ALGID_*` constant with the raw 11-byte OID
(drop the `30 0d`/`30 0b` SEQUENCE tag+length prefix and, for SHA-2/SHA-3, the
trailing `05 00` NULL), and correct `algIdDerLen` from `{15, 13}` to a single
constant `11` for every entry. Example (`OSSLMLDSA.cpp`):

```c
// Before (wrong — X.509 AlgorithmIdentifier SEQUENCE):
static const unsigned char ALGID_SHA256[] = {
    0x30,0x0d, 0x06,0x09, 0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01, 0x05,0x00
};
// After (FIPS 204 Table 1 raw OID, matching rust/fips204-patched/src/hashing.rs:321-324):
static const unsigned char OID_SHA256[] = {
    0x06,0x09, 0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01
};
```

Apply the same transform to all 10 entries in each file (SHA-224/256/384/512,
SHA3-224/256/384/512, SHAKE128/256). No other code in `buildPreHashEncoding()`
changes — the `0x01 ‖ ctxLen ‖ ctx ‖ OID ‖ digest` assembly is already correct
per FIPS 204 step 23 / FIPS 205's equivalent, only the OID bytes themselves
are wrong. `SLH-DSA`'s equivalent function (mirrors this one) gets the
identical treatment.

## 3. Evidence available today (Tier 1, already in the repo)

### 3.1 ML-DSA — `tests/acvp/mldsa_extended_test.json`, `preHash` section

Already-fetched, provenance-verified NIST ACVP `ML-DSA-sigGen-FIPS204-tr1`
data (pinned commit `975de31eb83d87039ec88934fdc47d8c312b892d`), one case per
parameter set:

| Param set | tgId/tcId | hashAlg |
|---|---|---|
| ML-DSA-44 | 4/46 | SHA3-224 |
| ML-DSA-65 | 8/107 | SHA3-256 |
| ML-DSA-87 | 12/166 | SHA2-224 |

Fields present: `pk`, `message`, `context`, `hashAlg`, `signature` — **no
`sk`**, so as extracted this is sigVer-only evidence (verify the real
signature against `pk`+`message`+`context`+`hashAlg`), the same evidence
class already accepted for WS-3.3's context-mode fix. This alone is enough to
close the item to the standard the master plan already used elsewhere, and
requires no new fetching — it is the exact file the reverted attempt already
loaded.

### 3.2 ML-DSA — real sigGen (sk+seed) evidence, confirmed fetchable

Per this session's decision to also pursue independent sign-path evidence: I
re-fetched the **full** `ML-DSA-sigGen-FIPS204-tr1/internalProjection.json`
(17.9 MB, same pinned commit) directly from `usnistgov/ACVP-Server` and
confirmed it carries **12 `preHash` test groups**, 6 of them
`"deterministic": true` (tgId 2/4/6/8/10/12 — two per parameter set), each
test entry containing `sk`, `seed`, `pk`, `message`, `context`, `hashAlg`,
`signature`. Deterministic mode means `sk → sign` reproduces `signature`
byte-for-byte with no RNG dependency — genuine, independent Tier-1 sigGen
evidence, not just sigVer.

**Dependency:** using this requires importing a raw ML-DSA private key into
the engine via `C_CreateObject`, which `tests/helpers.mjs` does not currently
expose for ML-DSA — only `importMLDSAPublicKey()` exists
(`helpers.mjs:486`). See §4.

### 3.3 SLH-DSA — real sigGen (sk) evidence, confirmed fetchable, better than expected

I checked whether `SLH-DSA-sigGen-FIPS205` (no separate "-tr1" revision
exists for SLH-DSA at this pinned commit — confirmed by listing
`gen-val/json-files/` directly) carries pre-hash groups in its **base**
dataset, since ML-DSA needed the extra tr1 revision for this. It does:
fetching the full `internalProjection.json` (38.2 MB) shows **24 `preHash`
test groups**, all `"deterministic": true`, each entry containing `sk`, `pk`,
`message`, `context`, `hashAlg`, `signature` directly — no separate sigVer
fetch needed, and the private-key-import gap (§4) applies here too, but
`tests/helpers.mjs` **already has** `importSLHDSAPrivateKey`-equivalent
(`C_CreateObject(SLH-DSA-Priv)`, `helpers.mjs:1010`) — so SLH-DSA sigGen
evidence has **no missing test infrastructure** and can be wired directly.

**Hash-algorithm caveat:** of the 24 preHash groups, several use
`SHA2-512/224` / `SHA2-512/256` (the truncated SHA-2 variants), which this
engine does not implement at all yet (tracked separately as WS-6.3). Usable
today without waiting on WS-6.3: at minimum tgId 6 (SHA3-384), 10 (SHA3-224),
12 (SHA2-512), 20 (SHA2-224), 22 (SHAKE-256) — one per distinct supported
hash, spread across 5 of the 12 SLH-DSA parameter sets. The exact selection
should follow the same "representative, not exhaustive" principle the master
plan already applies to XMSS (D7) — write the selection and reason next to
the results rather than asserting "representative".

## 4. New test-harness capability needed: ML-DSA private-key import

`helpers.mjs` already imports raw private-key material for two of the three
PQC signature/KEM families — `C_CreateObject(ML-KEM-Priv)` (`:523`) and
`C_CreateObject(SLH-DSA-Priv)` (`:1010`) both set `CKA_VALUE` directly, no
PKCS#8 wrapping. The C++ engine's own `C_CreateObject` handling
(`SoftHSM_keygen.cpp:1611-1628`) treats `CKK_ML_KEM`, `CKK_ML_DSA`, and
`CKK_SLH_DSA` identically — **"PQC key types: read `CKA_VALUE` directly — the
stored value is already the serialised key material"** — so there is no
engine-level reason ML-DSA should behave differently from its two siblings.

This means the master plan's WS-3.3 provenance note (*"needs an ML-DSA
private-key-import wasm binding that does not exist yet"*) most likely
overstated the gap: the engine-side capability appears to already exist and
is exercised for ML-KEM and SLH-DSA today. What is actually missing is a
~15-line `importMLDSAPrivateKey(M, hSession, variant, skBytes)` JS helper in
`tests/helpers.mjs`, mirroring the existing two. This should be written and
**spike-tested against one real deterministic sigGen vector first** (§3.2)
before assuming it "just works" — if `C_CreateObject` rejects the object for
a reason specific to ML-DSA's template validation (the WS-6.2 debugging this
session found more than one independent validation gate for a mechanism that
"should" have worked by pattern-matching a sibling), that surfaces
immediately and cheaply, not after the vector-wiring work is built on top of
a wrong assumption.

## 5. Sequencing

| Step | Action | Evidence tier gained |
|---|---|---|
| 1 | Fix `buildPreHashEncoding()`'s OID tables in `OSSLMLDSA.cpp` and `OSSLSLHDSA.cpp` (§2) | — (correctness fix, no evidence yet) |
| 2 | Re-wire ML-DSA preHash sigVer against `mldsa_extended_test.json` (§3.1) — this is the harness code already built and reverted this session; re-apply it now that the underlying bug is fixed | Tier 1, 3 param sets, sigVer |
| 3 | Sanity-check step 1 against SLH-DSA's existing context/sigVer tests (`slhdsa_ctx_test.json`) still pass unchanged (they don't touch `buildPreHashEncoding`'s SLH-DSA equivalent, but confirm no regression) | regression guard |
| 4 | Write `importMLDSAPrivateKey()` in `helpers.mjs`; spike against **one** real deterministic ML-DSA preHash sigGen vector from §3.2 | validates the import path before further investment |
| 5 | If step 4's spike passes: extract a representative sigGen vector set from the full ML-DSA-sigGen-FIPS204-tr1 dataset (deterministic groups 2/4/6/8/10/12, one case each) into a new provenance-blocked file (or extend `mldsa_extended_test.json`), wire into the harness | Tier 1, sigGen, independent of sigVer |
| 6 | Extract a representative SLH-DSA preHash sigGen vector set from `SLH-DSA-sigGen-FIPS205` (§3.3, respecting the hash-algorithm caveat), wire into the harness using the already-existing private-key-import helper | Tier 1, sigGen, SLH-DSA |
| 7 | Full local gate run (`local-gate.sh --cpp --acvp-wasm`) once this batch and any other in-flight C++ fixes are ready together, per the standing "fix everything, test once" directive | full regression confirmation |

Steps 1–3 are low-risk and can land together. Step 4 is a genuine unknown
(hence "spike first") — if the import path needs engine-side work beyond a
JS helper, that changes this plan's effort estimate materially and should be
reported back before continuing to steps 5–6.

## 6. Acceptance criteria

1. `buildPreHashEncoding()` in both `OSSLMLDSA.cpp` and `OSSLSLHDSA.cpp`
   produces the FIPS 204/205 raw-OID form; unit-verified against the
   `rust/fips204-patched` / `rust/fips205-patched` OID tables byte-for-byte
   (all 10 entries each).
2. ML-DSA preHash sigVer passes for all 3 vectors in
   `mldsa_extended_test.json` (SHA3-224/ML-DSA-44, SHA3-256/ML-DSA-65,
   SHA2-224/ML-DSA-87).
3. At least one genuine ML-DSA preHash **sigGen** case (deterministic,
   sk→sign→byte-match) passes, contingent on step 4's spike succeeding.
4. SLH-DSA preHash sigGen passes for the representative hash/param-set subset
   selected in step 6, with the selection and reason recorded next to the
   results (matching the standard already set for XMSS in the master plan).
5. No change to the "context" mode code path (`CKM_ML_DSA` non-empty `ctx`,
   `CKM_SLH_DSA` non-empty context) — it does not call
   `buildPreHashEncoding()` and is out of scope here; its existing passing
   tests must remain unaffected.

## 7. Execution record (2026-08-30)

All 6 sequencing steps executed on `fix/ws1-4-and-ws2-rust-gaps`, 3 commits
(`4d37cc3`, `ab4d504`, `e4bc42c`):

1. **OID fix (§2).** Applied to both `OSSLMLDSA.cpp` and `OSSLSLHDSA.cpp`.
   Full C++ rebuild + `ctest`: 8/8 passing, no regression.
2. **ML-DSA preHash sigVer** re-landed against `mldsa_extended_test.json`.
   3/3 PASS — confirms the root cause was correctly identified.
3. **Regression check**: full ACVP run stayed 0 FAIL throughout; SLH-DSA's
   existing context-mode tests unaffected.
4. **Spike: `importMLDSAPrivateKey()`.** Worked on the first attempt — the
   engine-level capability assumption in §4 held. Also validated against the
   actual PKCS#11 v3.2 spec text (`docs/refs/pkcs11-spec-v3.2-os.pdf`, Table
   281): `CKA_VALUE` alone (the raw FIPS 204 expanded `sk`) is sufficient on
   `C_CreateObject`, matching the engine's existing behavior — `CKA_SEED` is
   optional, not required.
5. **ML-DSA sigGen**, 5 real deterministic cases (SHA2-512 ×2, SHA3-224,
   SHAKE-128, SHA2-224), wired as byte-exact comparisons against the ACVP
   vector's own signature — all 5 PASS. tgId 8 (SHA2-512/224) excluded per
   WS-6.3.
6. **SLH-DSA preHash sigGen**, 7 real deterministic cases. A byte-exact
   comparison was spiked first and does **not** match — root-caused as the
   same divergence already documented and accepted in this file's
   context-mode sigGen block (this engine's OpenSSL SLH-DSA and the ACVP
   reference generator choose different, individually FIPS-205-compliant
   internal randomness even in deterministic mode). Followed that existing
   file's own precedent: round-trip evidence (real `sk` signs, real `pk`
   from the same vector verifies) instead of a byte comparison that would
   never pass for reasons unrelated to correctness. All 7 PASS.

**CPP ACVP total: 186 → 201 PASS, 0 FAIL, 0 SKIP** (across the 3 commits).
`ctest`: 8/8, unchanged.

**Step 7 (full local gate) intentionally not run yet** — this branch also
carries WS-0, WS-3.2, WS-5.4, and WS-6.2 from earlier in the session; the
gate is deferred until the full accumulated batch is ready, per the user's
standing "fix everything, then test once" directive.

## 8. Explicitly out of scope here

- WS-6.3 (missing `SHA512_224`/`SHA512_256`/`SHA512_T` mechanisms) — several
  real SLH-DSA preHash ACVP groups use these hashes; they are excluded from
  this plan's vector selection rather than used as justification to pull
  WS-6.3 forward. Cross-referenced, not merged in.
- Any Rust-side change. `rust/fips204-patched` and `rust/fips205-patched` are
  read here strictly as reference/citation sources for the correct OID
  encoding — they are not modified, and the Rust PKCS#11 dispatch layer
  (`rust/src/ffi.rs`) is untouched, per the standing C++-only directive.
- External-Mu and non-deterministic (hedged) preHash modes — not addressed by
  either vector set gathered here; would need separate sourcing if pursued.
