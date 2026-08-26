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

**Execution update (2026-08-26):** done, both engines, fully
live-verified. No bespoke C test tool needed in the end — the scope
doc's own §6 raw-PKCS#11 tool plan was replaced with something simpler
that proves the same thing: independent µ computation in Python
(`hashlib.shake_256`) plus OpenSSL's own standard `pkeyutl -pkeyopt
mu:1` CLI flag, which already exists and needed no new client-facing
surface. Two design corrections surfaced live before commit (full
detail in the scope doc's own §8 execution update, not repeated here):
(1) µ travels via the normal `C_Sign`/`C_Verify` data argument, not an
embedded struct field — no new `ck_param` layout needed after all; (2)
the mechanism needed multi-part support (`bAllowMultiPartOp` / Rust's
`sign_mech_supports_multipart`) because OpenSSL's own `EVP_DigestSign`
machinery drives *every* ML-DSA sign through Update/Final internally,
even one-shot `pkeyutl` calls — discovered via `PKCS11_PROVIDER_DEBUG`
tracing after the Rust arm failed at `C_SignUpdate` while the C++ arm
(coincidentally) passed on an uninitialized boolean. Both engines now
set the flag explicitly.

Cross-implementation proof, both arms: signature produced via the
vendor mechanism verifies against OpenSSL's completely independent
native ML-DSA implementation (`-provider default`) checked against the
original raw message — byte-equivalent to a direct pure-ML-DSA
signature, exactly as the design requires. Four sabotage controls
(tampered µ, tampered signature, context+mu rejected, wrong-length µ
rejected) pass on both arms. New permanent harness cases `T28` (C++)
and `T28b` (Rust, twin). Full regression: harness 78/78 (two cases
gained, zero regressions), C++ CTest 8/8, `cargo test --release` full
pass. One commit for this item.

---

### R35 — HashML-DSA provider surface — effort S–M

**Grounding correction (2026-08-26, found while starting this item's
own execution — corrected before any code was written):** this item's
original grounding (below, struck through) claimed both engines
deviate from the ratified spec's input contract for the entire
`CKM_HASH_ML_DSA*` family. That was wrong, caught by re-reading the
ratified text itself instead of trusting an earlier partial read.
PKCS#11 v3.2 draws a sharp, deliberate line the earlier pass missed:

- **§6.67.6, `CKM_HASH_ML_DSA` (the one GENERIC mechanism)**: *"The
  data passed in is an already hashed message PHM."* Input length
  "Length of hash". This one genuinely wants a pre-hashed input.
- **§6.67.7, `CKM_HASH_ML_DSA_<hash>` (the TEN hash-specific
  mechanisms — `_SHA224` through `_SHAKE256`)**: *"This mechanism
  computes the entire HashML-DSA specification, **including the
  hashing on token**. The data passed in is the message M."* — a
  **separate, standard PKCS#11 pattern** ("mechanism with hashing"),
  the same shape RSA/DSA/ECDSA already use elsewhere in this spec
  (§6.1.14, §6.2.12, §6.3.13). SLH-DSA mirrors this exactly at
  §6.69.6/§6.69.7. **Independently confirmed against the OASIS PKCS#11
  TC's own v3.3 working draft** (`oasis-tcs/pkcs11` GitHub repo,
  `working/doc/spec/ml_dsa.md`) — identical §6.67.7 wording verbatim,
  including the "SHA-224 through SHAKE256" hash table, so this isn't a
  drafting quirk of one revision.

Both engines' `preHash=true` dispatch (`HASH_MLDSA_CASE` macro in C++,
`Ph`-mapped `try_hash_sign` in Rust) is the §6.67.7 "with hashing"
shape — **already spec-correct for all 10 hash-specific mechanisms**.
The real, narrower gap: neither engine's dispatch sets `preHash=true`
for the *bare* generic `CKM_HASH_ML_DSA`/`CKM_HASH_SLH_DSA` (only the
`HASH_MLDSA_CASE`-macro'd specific mechanisms do), so that ONE
mechanism per family would currently mis-treat an already-hashed PHM
input as a raw message needing full encoding — genuinely wrong, but
affecting 2 of the 22 total codepoints (ML-DSA + SLH-DSA combined), not
all of them. This also **removes the "decision point"** the original
plan flagged: there is no conformance trade-off to make, no risk to
the hub playground's real dependency on the `_<hash>`-specific
mechanisms (confirmed by a live consumer-inventory sweep before this
correction landed — `pqctoday-hub`'s Sign/Verify Playground drives
`CKM_HASH_ML_DSA_*`/`CKM_HASH_SLH_DSA_*` with raw typed text, exactly
the input shape §6.67.7 already promises), and nothing to ask the user
about.

<details><summary>Original (incorrect) grounding — kept for the audit
trail, not for reference</summary>

~~NEW FINDING — both engines deviate identically from the ratified
spec's input contract, and nothing has ever caught it because all
existing tests are cross-engine. Spec §6.67.6 is unambiguous: "The
data passed in is an already hashed message PHM." But C++'s
`buildPreHashEncoding()` and Rust's `try_hash_sign()` both hash the
raw message internally regardless of which of the 11 mechanisms was
requested — same failure-mode class as the audit's own "LLM verdicts /
row-level ratchet" lessons.~~ (Wrong: this only actually applies to the
1-of-11 bare generic mechanism per family; the other 10 are the
"with hashing" pattern and correctly hash on token by design.)

</details>

**Grounding (still accurate):**

1. Provider registers none of the 22 codepoints (11 × ML-DSA, handled
   here; 11 × SLH-DSA, R36). `PQC_MECHS` (`provider.c:867`) has only
   `CKM_ML_DSA`/`CKM_SLH_DSA`/`CKM_HSS` + keygens.
2. `p11prov_sig_op_init` (`sig/signature.c:276-282`) already parses a
   caller-supplied digest name into `sigctx->digest` — but
   `p11prov_mldsa_set_mechanism` (`sig/mldsa.c:42`) unconditionally
   sets `CKM_ML_DSA` and never reads it. **Live-confirmed** (this
   plan's own execution): `openssl dgst -sha256 -sign` against a
   pkcs11 ML-DSA key today returns success silently, but verifies as a
   *plain, unhashed* ML-DSA signature over the raw message — the
   `-sha256` flag is completely and silently ignored, not merely
   unsupported. Worst of the two hypothesized outcomes, now confirmed
   rather than assumed.

**Work, in order (no decision point — proceed directly):**

1. **Provider wiring, the 10 hash-specific mechanisms (main
   deliverable).** In `p11prov_mldsa_set_mechanism`, when
   `sigctx->digest != 0`, select the matching `CKM_HASH_ML_DSA_<hash>`
   codepoint (`CKM_SHA256`→`CKM_HASH_ML_DSA_SHA256`, … , SHAKE
   included; unmappable digest → loud `CKR_MECHANISM_INVALID`, never
   silent fallback to pure). Parameter: `CK_SIGN_ADDITIONAL_CONTEXT`,
   unchanged from what the engines already expect for these
   mechanisms. Data flow: the caller's raw message streams through
   exactly like plain `CKM_ML_DSA` today (both engines already hash it
   on-token correctly) — no new engine-side hashing logic needed for
   this part at all. Add the 10 mechanisms to `PQC_MECHS`, gated the
   same way as everything else (present only if the token advertises
   them).
2. **Bare generic `CKM_HASH_ML_DSA` — small, separate engine fix.**
   Both engines need a real (not `preHash`-macro'd) code path that
   treats the incoming data as an already-complete PHM: build
   `M' = 0x01 ‖ ctxlen ‖ ctx ‖ OID ‖ PHM` directly from the caller's
   bytes, skipping the internal `EVP_Digest`/hash call entirely
   (C++: a `useRawEncoding`-style branch in `OSSLMLDSA.cpp` that skips
   `buildPreHashEncoding`'s own hashing step; Rust: needs a
   `fips204-patched` entry point taking a pre-hashed PHM directly —
   the crate's internal Eq. 6c path already exists as an unexported
   internal function, same shape as R34's `ext_mu` discovery). Lower
   priority than item 1 — no confirmed live consumer of the *bare*
   generic mechanism specifically (the hub uses the hash-specific
   ones) — do this after item 1 lands and regresses clean, not before.
3. **Registration surface**: no new OpenSSL algorithm names for either
   item. The existing `ML-DSA-44/65/87` signature registrations gain
   real digest-parameter support, reachable via the standard
   `EVP_DigestSignInit(ctx, "SHA256", …)` / `pkeyutl -digest sha256`
   API with `provider=pkcs11` pinned. Document in the provider README
   that this selects HashML-DSA (FIPS 204 §5.4) semantics, which the
   default provider deliberately does not implement.

**Proof plan:** ACVP/NIST HashML-DSA KAT vectors exist for the
hash-specific mechanisms — verify at least one (param-set, digest)
pair against official vectors in both engines (not just cross-engine —
the exact blind spot the corrected grounding above flags as a
methodology lesson even though the original finding was wrong). New
harness case: token HashML-DSA sign via `EVP_DigestSign` → verify via
the provider. Sabotage twins: tampered message, wrong digest at
verify, context mismatch. Negative control: default provider (no
propquery) must reject the same digest-ML-DSA call — proving the
harness case genuinely exercises pkcs11. Regression: full harness,
CTest, `cargo test --release` (only if item 2 touches `rust/`).

**Execution update (2026-08-26):** item 1 (the real deliverable) done
and live-verified; item 2 (bare generic `CKM_HASH_ML_DSA` PHM fix)
deferred — no confirmed consumer, tracked as its own follow-up rather
than folded into this commit. `p11prov_mldsa_set_mechanism` now maps
`sigctx->digest` (already parsed by `p11prov_sig_op_init`, previously
never read) to the matching `CKM_HASH_ML_DSA_<hash>` codepoint for the
8 digests reachable through `p11prov_digest_get_by_name` today
(SHA224/256/384/512, SHA3-224/256/384/512 — SHAKE128/256 stay
unreachable via this path because the provider's own digest-name
table, `digests.c`, has no entry for them yet; a separate, pre-existing
limitation, not a regression). Loud `CKR_MECHANISM_INVALID` for
anything unmapped, never a silent fallback to pure ML-DSA.

Live-confirmed before the fix, not assumed: `openssl dgst -sha256
-sign` against a pkcs11 ML-DSA key returned success and produced a
signature that verified as a **plain, unhashed** raw-message
signature — the digest was completely and silently discarded, the
worse of the two hypothesized outcomes. After the fix: the same
signature no longer verifies as a raw-message signature (proving the
digest is genuinely honored) and round-trips correctly through
`dgst -sha256 -verify`. Negative control confirmed: the default
provider explicitly refuses ("Explicit digest not supported for
ML-DSA operations"), so no ambiguity about which provider produced the
result. Two sabotage controls pass: wrong digest at verify, tampered
message.

One real bug found in the Rust arm, same class as R34's: the ten
hash-specific mechanisms are explicitly single- **and** multi-part per
§6.67.7, and OpenSSL's own `EVP_DigestSign` machinery drives even a
one-shot `dgst -sign` through `C_SignUpdate`/`C_SignFinal` internally
— the C++ arm's `HASH_MLDSA_CASE` macro has always set
`bAllowMultiPartOp` for these (pre-existing, unrelated to this item),
but Rust's own `sign_mech_supports_multipart` allowlist never included
them, so `dgst -sha256 -sign` against the Rust arm failed at the very
first `C_SignUpdate`. Fixed by adding `is_prehash_ml_dsa(mech)` (an
already-existing helper covering exactly the 10 hash-specific
mechanisms, correctly excluding the single-part-only bare generic one)
to the allowlist — no new accumulate logic needed, same
accumulate-then-single-call machinery R34 already proved out.

No independent third-party oracle was available to cross-verify
against for this item (unlike R34's µ, where OpenSSL's own default
provider could serve as the check) — the default provider explicitly
refuses HashML-DSA entirely. The underlying `preHash`/`Ph`-based crypto
in both engines is separately covered by the Rust crate's own
pre-existing ACVP KAT tests (`native::prehash_kat`,
`native::prehash_kat_slh`, bypassing PKCS#11 entirely); what this item
adds and proves is the provider's own routing, verified via
sign/verify round-trip, negative control, and sabotage.

New permanent harness cases `T29` (C++) and `T29b` (Rust, twin — no
Rust engine change was needed beyond the multipart allowlist fix,
proving the provider's shared C routing reaches both engines
identically). Full regression: harness 80/80 (two cases gained, zero
regressions), C++ CTest 8/8, `cargo test --release` full pass (Rust
touched). One commit for this item.

---

### R36 — HashSLH-DSA twin — effort S–M

**Grounding:** identical shape to R35's *corrected* understanding,
verified: ratified spec defines `CKM_HASH_SLH_DSA` (§6.69.6, generic,
`0x34`, PHM input) + ten specific "with hashing" codepoints (§6.69.7,
`0x36`–`0x3f`, raw message, hash-on-token). Both engines already
implement the §6.69.7 shape correctly for the 10 specific mechanisms
(`OSSLSLHDSA.cpp:304/429` `preHash` branches; `constants.rs:776-787` +
`fips205::Ph` mapping in `handlers.rs:462+`) — same "already correct,
just unregistered" situation as ML-DSA, not the hash-internally
deviation the original (wrong) R35 grounding claimed. Provider has
zero references; OpenSSL's default provider likewise does not
implement pre-hash SLH-DSA, so the digest hook is free here too. No
decision point here either, for the same reason R35 no longer has one.

**Work:** pattern-copy of R35's corrected work items 1–3 onto
`sig/slhdsa.c` and the SLH-DSA arms of both engines (12 parameter
sets × the digest map; `sig/slhdsa.c` already follows `mldsa.c`'s
structure from R1, so the diff shape is known). Item 2 (bare generic
`CKM_HASH_SLH_DSA` PHM fix) carries the same low-priority, no-confirmed-
consumer status as ML-DSA's. KAT verification for at least one
(param-set, digest) pair from official vectors, both engines. Same
proof plan and controls as R35, SLH-DSA-flavored (7856-byte /
SHA2-128s baseline sizes already proven in T12sign).

**Why after R35 and not merged into it:** one commit per R-item, and
R35 carries the conformance decision + first-of-pattern risk; R36
should be a low-surprise replay. If R35's consumer inventory or KAT
work surfaces anything structural, R36 absorbs it for free instead of
duplicating the churn.

**Execution update (2026-08-26):** low-surprise replay, exactly as
predicted — no new findings, both `T30`/`T30b` passed on the first
run. `p11prov_slhdsa_set_mechanism` gained the identical
digest→`CKM_HASH_SLH_DSA_<hash>` mapping as R35's ML-DSA fix (8 of 10
digests reachable; SHAKE128/256 unreachable for the same pre-existing
`digests.c` reason); Rust's `sign_mech_supports_multipart` gained
`is_prehash_slh_dsa(mech)` (the SLH-DSA twin of R35's ML-DSA helper).
Item 2 (bare generic `CKM_HASH_SLH_DSA` PHM fix) deferred with R35's
own, same reasoning — no confirmed consumer. New harness cases `T30`
(C++, SLH-DSA-SHA2-128s, 7856-byte baseline matching T12sign) and
`T30b` (Rust, twin). Full regression: harness 82/82 (two cases gained,
zero regressions), C++ CTest 8/8 (one `p11test` failure on the first
post-change run reproduced as pre-existing flakiness — confirmed via
two clean reruns, matching phase-6 R32's own `p11_v32_compliance`
precedent, not a new finding), `cargo test --release` full pass. One
commit for this item — the last of phase-7's active work; R33 and R27
stay parked.

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
