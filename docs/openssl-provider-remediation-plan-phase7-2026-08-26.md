# OpenSSL provider remediation plan — phase 7 (R34–R36)

Date: 2026-08-26. Companion to
`docs/openssl-provider-coverage-audit-2026-08-25.md` (gap matrix and
per-phase narratives) and successor to
`docs/openssl-provider-remediation-plan-phase6-2026-08-26.md` (R28–R32,
all five active items executed and committed; R33/R27 parked).

Phase 7 exists because a user-driven re-audit of F36-6 ("external mu
should be supported") overturned that row's "structurally unfixable"
claim and surfaced two adjacent findings. Everything below was
re-grounded against the current source tree and primary sources (the
**ratified** PKCS#11 v3.2 OASIS Standard text, OpenSSL 3.6.3's own
source and man pages, the OASIS TC's public v3.3 roadmap) while writing
this plan — and that grounding itself found one genuinely new,
previously untracked cross-engine spec-conformance question (see R35's
grounding, item 3).

## Ground rules (carried forward from phases 4–6, unchanged)

- **Live-trace-confirm before fixing**: reproduce every suspected
  behavior via `PKCS11_PROVIDER_DEBUG` / engine logs before writing a
  fix; never patch from static reading alone.
- **R13 discipline**: every positive proof needs engine-log evidence of
  real token participation plus a negative-control twin. Hard
  propqueries (`provider=pkcs11`) for any algorithm whose name collides
  with a default-provider name.
- **`pkcs11-module-load-behavior = early`** in every new arena that
  fetches before creating a key object (WART-4).
- **Verify standards facts against the ratified text** (`docs/refs/
  pkcs11-spec-v3.2-os.pdf`, 03 June 2026), never the csd01 draft and
  never from memory — this phase exists because a draft-era claim
  ("not fixable") survived two document generations unchallenged.
- **Sabotage-test every new proof**; full regression (C++ CTest,
  harness, Rust `cargo test --release` when `rust/` is touched) before
  each commit; one commit per R-item; append-only execution updates in
  this doc and the coverage audit.
- No push without explicit confirmation.

## Summary table

| # | Item | Origin | Effort | Type |
|---|---|---|---|---|
| R34 | ML-DSA external-µ vendor extension (`CKM_PQCTODAY_ML_DSA_MU`), tagged for deletion at PKCS#11 v3.3 | F36-6 correction; scope doc already written | M | feature (stopgap, removal-tagged) |
| R35 | HashML-DSA provider surface + engine PHM-conformance decision | found while correcting F36-6; new grounding finding | M | feature + conformance fix |
| R36 | HashSLH-DSA twin of R35 | same sweep; both engines already implement it | S–M | feature (pattern reuse) |
| R33 (PARKED) | OP-3 parity tier: ML-KEM SPKI/text public-key encoders | unchanged | S–M | sketch only |
| R27 (PARKED) | XMSS/XMSS-MT | unchanged | — | see phase-5 plan |

**Recommended order: R34 → R35 → R36.** R34 is the item the user
explicitly asked for and is fully scoped already. R35 must precede R36
because R36 is a pattern-copy of R35's provider wiring and inherits
whatever the R35 PHM-conformance decision turns out to be. R35's
engine-side conformance question must be settled BEFORE its provider
wiring is written — the provider's job is to send whatever the token
expects, so the token's contract has to be fixed first.

**Step 0 (before R34):** commit the two currently-uncommitted phase-7
precursors sitting in the working tree — the external-µ scope document
(`docs/openssl-provider-ml-dsa-external-mu-vendor-ext-2026-08-26.md`)
and the F36-6 row correction in the coverage audit — as one doc-only
commit. They are this plan's own foundation and should land before any
code does.

---

### R34 — ML-DSA external-µ vendor extension — effort M

**Grounding: complete.** The full design already exists as its own
scope document, written and source-verified on 2026-08-26:
`docs/openssl-provider-ml-dsa-external-mu-vendor-ext-2026-08-26.md`.
This plan entry does not repeat it — the scope doc is the authoritative
design. Summary of what it establishes:

- PKCS#11 v3.2 (ratified) has no field for a caller-supplied µ —
  confirmed by full-text search of the OS text, zero hits for "mu".
- PKCS#11 v3.3 will add it natively (OASIS tracking issue
  [oasis-tcs/pkcs11#58](https://github.com/oasis-tcs/pkcs11/issues/58);
  publicly stated at IETF 123 LAMPS; IACR eprint 2026/617 confirms
  "external-µ ... will be specified in version 3.3").
- External-µ preserves pure ML-DSA's security assumptions (FIPS 204
  Algorithm 7/8 + NIST's own FAQ addendum) — it is a two-module split
  of the same computation, not a weakening. A vendor-private stopgap is
  industry-precedented (Thales `PQC_external_hash`).
- Both engines already have the primitive: OpenSSL's
  `OSSL_SIGNATURE_PARAM_MU` (C++ engine signs through EVP already);
  `fips204-patched`'s `ext_mu: Option<[u8; 64]>` (internal-only today —
  needs a public trait entry point, the one genuinely new-code part).

**Work (per the scope doc's §3–§4, in this order):**

1. `vendor_mechanisms.h`: `CKM_PQCTODAY_ML_DSA_MU` (`0x80000013`, next
   free slot) + fixed-size `CK_PQCTODAY_ML_DSA_MU_PARAMS { hedgeVariant;
   mu[64] }`. Every touched site carries the literal removal tag
   `PQCTODAY-VENDOR-EXT-MU`.
2. C++ engine: mechanism-table + `SoftHSM_sign.cpp` dispatch +
   `OSSLMLDSA.cpp` branch parallel to the existing `preHash` branch,
   setting `OSSL_SIGNATURE_PARAM_MU=1` and passing the 64-byte µ as the
   sign/verify data. Smallest-risk component — reuses a working pattern
   in the same file.
3. Rust engine: mirror the constant in `constants.rs`; add public
   `sign_with_mu`/`verify_with_mu` entry points to `fips204-patched`
   (thread the existing internal `ext_mu` through `traits.rs`); new
   dispatch arm in `ffi.rs`/`handlers.rs`.
4. Provider (`sig/mldsa.c`): narrow the existing `mu != 0` rejection in
   `p11prov_mldsa_set_ctx_params` — accept `mu=1`, validate the data
   buffer is exactly 64 bytes at operate time, route to
   `CKM_PQCTODAY_ML_DSA_MU`. The `message-encoding != 1` rejection is
   untouched. No new OpenSSL-facing API: `OSSL_SIGNATURE_PARAM_MU` is
   already the standard param name — this makes an already-standard
   OpenSSL knob work instead of erroring.

**Proof plan (scope doc §6):** new raw-PKCS#11 tool computes µ
independently in software per FIPS 204 Eq. (1)–(2); the resulting
µ-signed signature must verify BOTH via the same mechanism's own
`C_Verify` AND — the real cross-implementation proof — via OpenSSL's
native `EVP_PKEY-ML-DSA` verify against the ORIGINAL raw message,
proving byte-equivalence with a direct pure-ML-DSA signature. Sabotage:
flipped µ byte fails both paths; wrong-length µ fails loudly. Both
arms (C++ + Rust). Full regression incl. `cargo test --release`
(crate touched).

**Removal path:** `grep -rn PQCTODAY-VENDOR-EXT-MU` finds every touch
point when v3.3 ratifies and this project adopts it. The provider-side
change is additive (widens a rejection), so removal is a clean revert.

---

### R35 — HashML-DSA provider surface + engine PHM-conformance decision — effort M

**Grounding (all verified against source while writing this plan):**

1. **The mechanism family is fully standard and fully implemented in
   BOTH engines, and the provider registers none of it.** Ratified spec
   §6.67.6: `CKM_HASH_ML_DSA` (generic, digest selected via
   `CK_HASH_SIGN_ADDITIONAL_CONTEXT.hash`) plus ten hash-specific
   codepoints (`0x23`–`0x2c`). C++ engine: `isMLDSAMechanism()` in
   `OSSLMLDSA.cpp` accepts all 11; `SoftHSM_sign.cpp` sets
   `mldsaSignParam.preHash = true` for them. Rust engine:
   `constants.rs:762-772` lists all 11 in the supported-mechanism
   table; `ffi.rs`'s `remap_generic_hash_mech` maps generic→specific;
   `handlers.rs:445-455` maps each to `fips204::Ph`. Provider:
   `PQC_MECHS` (`provider.c:867`) contains only
   `CKM_ML_DSA`/`CKM_SLH_DSA`/`CKM_HSS` + keygens — zero
   `CKM_HASH_*`; repo-wide grep of `src/vendor/pkcs11-provider/`
   confirms not a single reference.

2. **The OpenSSL-facing hook already exists and is currently a silent
   no-op.** `p11prov_sig_op_init` (`sig/signature.c:276-282`) parses a
   caller-supplied digest name into `sigctx->digest` — but
   `p11prov_mldsa_set_mechanism` (`sig/mldsa.c:42`) unconditionally
   sets `CKM_ML_DSA` and never reads it. So a caller doing
   `EVP_DigestSignInit(ctx, "SHA256", …)` against an ML-DSA pkcs11 key
   today apparently gets pure ML-DSA over the raw message with the
   digest silently ignored — **confirm live as step 1** (it may error
   somewhere else downstream; do not trust this static read). Whatever
   the confirmed behavior is, it is wrong: either silently-ignored
   (worst) or an unexplained error (merely unhelpful). Note OpenSSL's
   own default provider REJECTS a digest for ML-DSA ("OpenSSL
   explicitly does not implement pre-hash HashML-DSA" — audit §1), so
   there is no name-collision or interop hazard in giving the digest
   real meaning here: any caller passing one against a pkcs11 ML-DSA
   key is already off the default provider's map.

3. **NEW FINDING — both engines deviate identically from the ratified
   spec's input contract, and nothing has ever caught it because all
   existing tests are cross-engine.** Spec §6.67.6 is unambiguous:
   *"The data passed in is an already hashed message PHM."* But:
   - C++: `buildPreHashEncoding()` (`OSSLMLDSA.cpp:145-230`) takes the
     incoming data as the RAW message and **hashes it itself**
     (`EVP_Digest(message…)`) before building
     `M' = 0x01 ‖ ctxlen ‖ ctx ‖ OID ‖ PH(M)`.
   - Rust: `handlers.rs` maps to `fips204::Ph` and calls the crate's
     `try_hash_sign(message, ctx, ph)` — whose own doc comment reads
     *"Attempt to sign the **hash of the given message**"*: it also
     takes the raw message and hashes internally.
   A spec-conforming caller sending a 32-byte PHM would have that PHM
   hashed AGAIN — producing a signature no conforming implementation
   can verify. The deviation is symmetric across both engines, so every
   cross-engine test passes while both are wrong against the standard.
   (Same failure-mode class as the audit's own "LLM verdicts /
   row-level ratchet" lessons: mutually-consistent implementations
   proving each other correct.) The SLH-DSA arms (`OSSLSLHDSA.cpp:304`,
   `fips205::Ph`) share the identical shape — handled in R36, decided
   here.

**Work, in order:**

1. **Live-confirm grounding item 2**: what actually happens today when
   an OpenSSL caller passes a digest name for a pkcs11 ML-DSA key
   (sign AND verify, one-shot AND update/final). Record it before
   changing it.
2. **Settle the PHM conformance question — decision point, likely
   AskUserQuestion material.** Options:
   - (a) **Fix both engines to spec**: `CKM_HASH_ML_DSA*` input becomes
     PHM (already-hashed); engines stop hashing internally (C++: build
     M' from the incoming bytes directly; Rust: needs a
     `fips204-patched` entry that accepts PHM — the crate's internal
     Eq. 6c path takes `phm` directly, so this is the same
     thread-it-through shape as R34's `ext_mu`). Spec-correct,
     matches what any third-party PKCS#11 client will send, and is the
     whole point of the mechanism (short input to the token). Risk:
     breaks any EXISTING consumer of these mechanisms via KMIP/wasm —
     inventory first (`grep` KMIP server + hub wasm surface for
     `CKM_HASH_ML_DSA`/`HASH_MLDSA` usage; if nothing consumes them
     yet, the fix is free).
   - (b) Keep engine behavior, document the deviation. Rejected-by-
     default: it makes the token wire-incompatible with every
     conforming PKCS#11 client for these codepoints, forever.
   Recommendation: (a), gated on the consumer inventory coming back
   empty or migratable.
3. **Provider wiring** (after 2 lands): in
   `p11prov_mldsa_set_mechanism`, when `sigctx->digest != 0` select the
   matching hash-specific mechanism (`CKM_SHA256`→
   `CKM_HASH_ML_DSA_SHA256`, …, SHAKE included; unmappable digest →
   loud `CKR_MECHANISM_INVALID`, never silent fallback to pure).
   Parameter: `CK_SIGN_ADDITIONAL_CONTEXT` as today (spec: the
   hash-specific mechanisms take the same optional param; only generic
   `CKM_HASH_ML_DSA` needs `CK_HASH_SIGN_ADDITIONAL_CONTEXT` — using
   the specific codepoints avoids the second struct entirely). Data
   flow per the digest paths: provider hashes the streamed message in
   software (public data — same precedent as the existing
   `fallback_digest` path) and sends the PHM in a single `C_Sign`,
   exactly the accumulate-then-single-call shape `sig/hss.c` already
   established. Add the 11 mechanisms to `PQC_MECHS` gated the same
   way everything else is (present only if the token advertises them).
4. **Registration surface**: no new OpenSSL algorithm names. The
   existing `ML-DSA-44/65/87` signature registrations gain real
   digest-parameter support — reachable via the standard
   `EVP_DigestSignInit(ctx, "SHA256", …)` /
   `pkeyutl -digest sha256`-style API with `provider=pkcs11` pinned.
   Document in the provider README that this selects HashML-DSA
   (FIPS 204 §5.4) semantics, which the default provider deliberately
   does not implement.

**Proof plan:** the PHM fix (step 2a) gets KAT-grade verification:
ACVP/NIST HashML-DSA vectors exist — verify at least one
(param-set, digest) pair against official vectors in BOTH engines, not
just cross-engine (the exact blind spot grounding item 3 exposed).
Provider path: new harness case — token HashML-DSA sign via
`EVP_DigestSign` → verify via the provider AND cross-check the M'
construction independently (script recomputes M' + verifies with the
engine's raw `C_Verify` on a second arena). Sabotage twins: tampered
PHM, wrong digest at verify, context mismatch. Negative control:
default provider (no propquery) must REJECT the same digest-ML-DSA
call — proving the harness case genuinely exercises pkcs11.
Regression: full harness, CTest, `cargo test --release`.

---

### R36 — HashSLH-DSA twin — effort S–M

**Grounding:** identical shape to R35, verified: ratified spec defines
`CKM_HASH_SLH_DSA` (generic, `0x34`) + ten specific codepoints
(`0x36`–`0x3f`); both engines implement all of it
(`OSSLSLHDSA.cpp:304/429` `preHash` branches; `constants.rs:776-787` +
`fips205::Ph` mapping in `handlers.rs:462+`); provider has zero
references; OpenSSL's default provider likewise does not implement
pre-hash SLH-DSA, so the digest hook is free here too. Both engines
share R35's same hash-internally deviation (the `Ph` pattern is
literally the same code shape), so **R35's step-2 decision is binding
here** — do not re-litigate it, apply it.

**Work:** pattern-copy of R35 steps 2–4 onto `sig/slhdsa.c` and the
SLH-DSA arms of both engines (12 parameter sets × the digest map;
`sig/slhdsa.c` already follows `mldsa.c`'s structure from R1, so the
diff shape is known). KAT verification for at least one
(param-set, digest) pair from official vectors, both engines. Same
proof plan and controls as R35, SLH-DSA-flavored (7856-byte /
SHA2-128s baseline sizes already proven in T12sign).

**Why after R35 and not merged into it:** one commit per R-item, and
R35 carries the conformance decision + first-of-pattern risk; R36
should be a low-surprise replay. If R35's consumer inventory or KAT
work surfaces anything structural, R36 absorbs it for free instead of
duplicating the churn.

---

### R33 (PARKED) — OP-3 parity tier: ML-KEM public SPKI/text encoders

Unchanged from phase 6. Parked until a `DISALLOW_EXPORT_PUBLIC`-style
configuration actually appears in this project.

### R27 (PARKED) — XMSS/XMSS-MT

Unchanged; see the phase-5 plan's sketch and phase-6's added
reuse-`sig/hss.c` note. Nothing in phase 7 alters its calculus.
(R34's vendor-extension pattern would, however, be the template if a
consumer ever wants the Thales-style external-hash interface for
XMSS/LMS — noted for that future trigger, not scoped.)

---

## Explicitly out of scope (documented limitations, unchanged)

- **F36-6 residual**: `message-encoding=0` for arbitrary caller M'
  under plain `CKM_ML_DSA` — no well-defined shape to accept; stays
  rejected. (External-µ is R34; well-formed pre-hash is R35. Between
  them they cover every legitimate use the two OpenSSL params serve.)
- **ALG-5 residual**, **WART-5**, **WART-6**: as listed in the
  phase-5/6 plans.
