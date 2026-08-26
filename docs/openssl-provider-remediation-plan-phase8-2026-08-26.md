# OpenSSL provider remediation plan — phase 8 (R37–R41): close the remainder

Date: 2026-08-26. Companion to
`docs/openssl-provider-coverage-audit-2026-08-25.md` and successor to
`docs/openssl-provider-remediation-plan-phase7-2026-08-26.md` (R34–R36,
all three active items executed and committed).

Phase 8 is the **closure-of-everything phase**: it takes every gap the
post-phase-7 "remaining gaps" report listed as open or parked —
including the two long-parked items (R27/XMSS, R33/ML-KEM encoders)
that previous phases deliberately left on the shelf — and sequences
them for execution. After phase 8, the only remaining entries in the
audit are the four permanent, documented limitations restated in the
final section, which are structurally not closeable from this codebase
(spec-shape, OpenSSL-core, or deliberate-posture reasons, per item).

Every claim below was re-grounded against the current source tree while
writing this plan. Grounding for this phase surfaced one NEW finding
(R37's cross-engine divergence — see that item) beyond what the
remaining-gaps report already knew.

## Ground rules (carried forward from phases 4–7, unchanged)

- **Live-trace-confirm before fixing**: reproduce every suspected
  behavior via `PKCS11_PROVIDER_DEBUG` / engine logs / raw-PKCS#11
  probes before writing a fix; never patch from static reading alone.
- **R13 discipline**: every positive proof needs engine-log or
  negative-control evidence of real token participation. Hard
  propqueries for any algorithm name that collides with a
  default-provider name.
- **`pkcs11-module-load-behavior = early`** in every new arena that
  fetches before creating a key object (WART-4).
- **Verify standards facts against the ratified text**
  (`docs/refs/pkcs11-spec-v3.2-os.pdf`) and, where a mechanism tracks
  the in-progress v3.3, against the OASIS TC working tree
  (`oasis-tcs/pkcs11`, `working/doc/spec/`) — the R35 lesson: a partial
  earlier read survived two document generations before the ratified
  text was re-read in full.
- **Multi-part first**: OpenSSL's `EVP_DigestSign` machinery drives
  every sign through `C_SignUpdate`/`C_SignFinal` internally, even
  one-shot CLI calls — learned independently in R34 AND R35. Any new
  sign-capable mechanism must be checked against BOTH engines'
  multi-part gates (`bAllowMultiPartOp` / `sign_mech_supports_multipart`)
  before its first test run, not after.
- **Sabotage-test every new proof**; full regression (C++ CTest,
  harness, `cargo test --release` when `rust/` is touched) before each
  commit; one commit per R-item; append-only execution updates in this
  doc and the coverage audit. Known flaky CTest suites
  (`p11test`, `p11_v32_compliance`) get two clean reruns before a
  failure is treated as real.
- Vendor mechanisms tied to the external-µ story carry the literal
  `PQCTODAY-VENDOR-EXT-MU` removal tag; new vendor codepoints allocate
  sequentially in `vendor_mechanisms.h` / `constants.rs`.
- No push without explicit confirmation.

## Summary table

| # | Item | Origin | Effort | Type |
|---|---|---|---|---|
| R37 | Bare generic `CKM_HASH_ML_DSA` / `CKM_HASH_SLH_DSA` PHM conformance — both engines, which currently disagree with the spec AND each other | deferred by R35/R36; divergence found grounding this plan | M | conformance fix |
| R38 | SHAKE128/256 reachability for `CKM_HASH_*_SHAKE*` routing | pre-existing `digests.c` limitation, surfaced by R35 | S | provider routing |
| R39 | `CKM_PQCTODAY_ML_DSA_MU_GEN` — token-side µ computation (v3.3-draft-aligned) | v3.3 draft's second external-µ half, not built by R34 | M | feature (stopgap, removal-tagged) |
| R40 | ML-KEM public SPKI/text encoders (un-parks R33) | OP-3's deliberate parity-tier deferral | S–M | parity feature |
| R41 | XMSS/XMSS-MT provider surface (un-parks R27 / closes ALG-2) | the last algorithm-family gap in the matrix | L | feature |

**Recommended order: R38 → R37 → R39 → R40 → R41.** Cheapest and most
self-contained first; R38+R37 complete the Hash*-DSA story R35/R36
started; R39 completes the external-µ story R34 started; R40 is an
independent small parity item usable as a breather; R41 is the largest
and riskiest and goes last so every pattern it reuses (stateful-sign
shape, KAT discipline, multi-part gates, five-gap registration
checklist) is warm. R41 is also the only item plausibly worth its own
session — if time-boxing, cut between R40 and R41.

---

### R38 — SHAKE128/256 reachability for HashML-DSA/HashSLH-DSA — effort S

**Grounding:** R35/R36's digest→mechanism maps in
`p11prov_mldsa_set_mechanism` / `p11prov_slhdsa_set_mechanism` have
`CKM_HASH_*_SHAKE128/256` arms designed but unreachable: the digest
name a caller passes to `EVP_DigestSignInit` resolves through
`p11prov_digest_get_by_name` (`digests.c`), whose `digest_map` has no
SHAKE entries at all — so `sigctx->digest` can never hold a SHAKE
value today. PKCS#11 itself defines no SHAKE *digest* mechanism
codepoint (only `CKM_SHAKE_128/256_KEY_DERIVATION`, `0x39B/0x39C`), so
there is no obviously-correct standard value to map the names onto —
this is why the gap exists.

**Design decision (make at execution, options pre-scoped):**

- **(a) Recommended — sentinel routing inside the two sig files.**
  Intercept the digest names `"SHAKE128"`/`"SHAKE-128"`/`"SHAKE256"`/
  `"SHAKE-256"` in `p11prov_mldsa_digest_sign_init` (and the verify /
  slhdsa twins) BEFORE the shared `p11prov_sig_op_init` name lookup,
  storing `CKM_SHAKE_128_KEY_DERIVATION`/`_256_` in `sigctx->digest`
  as carrier values, matched by the existing (currently-dead) SHAKE
  arms of the two `set_mechanism` maps. Zero impact on any other
  algorithm's digest handling and zero change to `digest_map` (which
  also feeds `p11prov_digest_get_digest_size` consumers that assume
  fixed-length digests — a SHAKE XOF entry there would need a length
  convention that only makes sense per-context: FIPS 204 uses 32 bytes
  for SHAKE128 and 64 for SHAKE256 in pre-hash, and nothing else in
  the provider shares that convention).
- (b) Add SHAKE rows to `digest_map` with the FIPS 204 pre-hash output
  lengths. Rejected-by-default: pollutes a shared table with a
  context-specific XOF length convention, and risks the KDF/MAC
  consumers of `digest_get_digest_size` silently accepting SHAKE where
  they never did before.

**Work:** implement (a); un-dead the SHAKE arms in both
`set_mechanism` switches (replace the `default:`-documented
"unreachable today" comments with real routing); confirm OpenSSL's
`dgst`/`EVP_DigestSignInit` actually accepts `-shake128`-style digest
names end-to-end (if the CLI won't pass an XOF name through, the
EVP-API path via a small probe or `pkeyutl -digest` is the test
surface — establish which, live, before writing the harness case).

**Proof plan:** harness case `T31` (+`T31b` Rust twin) mirroring
T29/T30's structure with `SHAKE256` (64-byte PHM — the variant FIPS 205
also uses, maximizing overlap): sign, round-trip verify, raw-verify
must fail (digest honored, not dropped), tampered-message sabotage.
Regression: full harness, CTest; `cargo test` only if `rust/` is
touched (expected: not).

**Execution update (2026-08-26):** done, both engines, option (a) as
recommended. Live-confirmed before coding: *neither* CLI surface can
drive a SHAKE prehash signature at all, for reasons unrelated to this
provider — `dgst -shake128/-256 -sign` reaches the provider's
`digest_sign_init` fine but `apps/dgst.c` itself hard-refuses
("Signing key cannot be specified for XOF"); `pkeyutl -sign -digest
shakeNNN` refuses earlier still ("-digest (prehash) is not supported
with ML-DSA-65"). Built `scripts/shake-sign-probe.c` (new CMake target
`shake_sign_probe`, alongside the project's other bespoke EVP-API
probes) to drive `EVP_DigestSign*`/`EVP_DigestVerify*` directly and
bypass both app-level gates — this became the harness's own T31/T31b
mechanism, not just a throwaway probe. `mldsa.c`/`slhdsa.c` each gained
a `*_shake_sentinel()` helper recognizing SHAKE128/256 digest names in
`digest_sign_init`/`digest_verify_init`, routing around
`p11prov_sig_op_init`'s digest_map lookup entirely (calls it with
`digest=NULL`, sets `sigctx->digest` to the
`CKM_SHAKE_128/256_KEY_DERIVATION` sentinel afterward) and matched by
two new `case` arms in each existing `set_mechanism` switch. T31
covers both algorithm families in one case (ML-DSA-65/SHAKE256,
SLH-DSA-SHAKE-128s/SHAKE128, each on its own arena — a bare
`type=private`/`type=public` URI is ambiguous once two keypairs share a
token, mk_arena's own documented hazard); engine-log confirmed
mechanism `0x2b` (`CKM_HASH_ML_DSA_SHAKE128`) genuinely dispatched, not
a coincidental fallback. No Rust source change needed (both
`CKM_HASH_*_SHAKE128/256` arms already existed from R35/R36) — T31b
proves the shared routing fix reaches both engines identically. Full
regression: harness 84/84 (two new cases, zero regressions), C++ CTest
8/8; `cargo test` correctly not re-run (no `rust/` change).

---

### R37 — bare generic `CKM_HASH_ML_DSA` / `CKM_HASH_SLH_DSA` PHM conformance — effort M

**Grounding — NEW finding beyond the remaining-gaps report:** the
report said both engines "mis-handle" the bare generic mechanism the
same way. Re-grounding for this plan shows they mis-handle it
**differently**, which is worse — the two engines are
wire-incompatible with the spec AND with each other on these two
codepoints:

- **C++**: `AsymSignInit`'s `case CKM_HASH_ML_DSA` sets
  `mldsaSignParam.hashAlg` from `CK_HASH_SIGN_ADDITIONAL_CONTEXT.hash`
  but — unlike the `HASH_MLDSA_CASE` macro right below it — **never
  sets `preHash = true`** (verified line-by-line, `SoftHSM_sign.cpp:902-935`).
  `OSSLMLDSA::sign()` therefore takes the *pure* path: the caller's
  PHM bytes get signed as a raw pure-ML-DSA message, with no
  `0x01‖ctx‖OID‖PHM` encoding at all. Not §6.67.6 semantics, not
  §6.67.7 semantics — a third, accidental behavior.
- **Rust**: `remap_generic_hash_mech` (`ffi.rs:4852`) maps the generic
  mechanism onto the matching hash-SPECIFIC mechanism, whose handler
  hashes its input — so the caller's already-hashed PHM gets **hashed
  a second time** before the M′ encoding.

Spec (§6.67.6/§6.69.6, ratified, confirmed identical in the v3.3
working draft): input IS the PHM ("Length of hash"), single-part only,
parameter `CK_HASH_SIGN_ADDITIONAL_CONTEXT`. A conforming caller gets
a wrong (and different-per-engine) signature from both engines today.
No consumer exists (the hub playground and every internal caller use
the hash-specific mechanisms) — which is why this stayed deferrable —
but two spec-divergent, mutually-incompatible codepoints should not
ship indefinitely.

**Work, in order:**

1. **Live-confirm both divergences first** with a raw-PKCS#11 probe
   (neither is reachable through OpenSSL's digest API — sign with the
   bare generic mechanism + a known PHM on each engine, check what
   each output actually verifies as). The C++ read in particular is
   static-only so far; the probe also becomes the regression fixture.
2. **C++ fix**: in the generic-mechanism cases (sign AND verify init,
   both `AsymSignInit`/`AsymVerifyInit`), set a new
   `phmInput` flag on `MLDSA_SIGN_PARAMS`/`SLHDSA_SIGN_PARAMS`
   (alongside `preHash`, not overloading it); in
   `OSSLMLDSA`/`OSSLSLHDSA` `sign()/verify()`, when `phmInput` is set,
   build `M′ = 0x01‖ctxlen‖ctx‖OID‖PHM` **directly from the caller's
   bytes** (reuse `buildPreHashEncoding`'s encoding tail, skipping its
   own `EVP_Digest` step) and validate the input length equals the
   `hashAlg`'s digest length ("Length of hash", loud
   `CKR_DATA_LEN_RANGE` otherwise, never truncate/pad). Enforce
   single-part (`bAllowMultiPartOp = false` — genuinely correct here,
   unlike R34's wrong first attempt: the caller's input is a fixed-size
   PHM, and the OpenSSL Update/Final concern doesn't apply to a
   mechanism unreachable via OpenSSL).
3. **Rust fix**: stop remapping the generic mechanism in
   `remap_generic_hash_mech`; give it its own dispatch arm calling new
   `fips204-patched`/`fips205`-side entry points that accept the PHM
   directly. The crate's internal sign already takes `phm` as an
   argument (`lib.rs:337` — public `try_hash_sign` computes
   `(oid, phm)` from the message and passes them down), so this is the
   same thread-it-through shape as R34's `ext_mu`: a new public
   `try_hash_sign_phm(phm, ph, ctx)`-style fn per crate that computes
   the OID from `ph` and forwards the caller's PHM. Same PHM-length
   validation, same single-part-only enforcement (the generic
   mechanisms must NOT be added to `sign_mech_supports_multipart` —
   `is_prehash_ml_dsa`/`_slh_dsa` already correctly exclude them).
4. Keep the provider untouched (nothing routes to the bare generic
   mechanisms from OpenSSL, by design — R35/R36 route to the
   hash-specific ones).

**Proof plan:** the step-1 probe, promoted to a permanent harness (or
CTest/cargo-test) fixture, run against BOTH engines with the SAME
(PHM, key, context) inputs: post-fix, each engine's generic-mechanism
signature must verify under the OTHER engine's generic-mechanism
verify (cross-engine, previously impossible) AND under the same
engine's hash-specific mechanism fed the raw message (the two
mechanisms are defined to produce interchangeable signatures for
`PHM = H(M)` — this equivalence is the strongest available oracle,
since OpenSSL has no HashML-DSA at all). Wrong-length PHM rejected
loudly on both engines. ACVP HashML-DSA/HashSLH-DSA vectors where a
(param-set, digest) pair exists in the already-vendored KAT sets
(`native::prehash_kat*` shows the vector plumbing). Regression: full
harness, CTest, `cargo test --release` (crates touched).

---

### R39 — `CKM_PQCTODAY_ML_DSA_MU_GEN`: token-side µ computation — effort M

**Grounding:** R34 shipped the *consume* half of external-µ (sign a
caller-computed µ). The v3.3 working draft defines a second mechanism,
`CKM_ML_DSA_EXTERNAL_MU_GEN`: a **digest-type** mechanism
(`C_Digest`/`C_DigestUpdate`/`C_DigestFinal`, multi-part allowed)
producing the 64-byte µ on the token, taking `CK_MU_GEN_PARAMS`
supplying *either* a public-key handle *or* a precomputed 64-byte TR,
plus an optional context string. Its point is the memory/bandwidth
story from the Strenzke analysis: a caller streams an arbitrarily
large message through `C_DigestUpdate` and gets back a 64-byte µ to
feed `CKM_ML_DSA_EXTERNAL_MU` (our `CKM_PQCTODAY_ML_DSA_MU`) — without
ever needing the message in one buffer, and without the caller
implementing SHAKE256/`tr` derivation itself.

**Scope decision (made here): engines only, no OpenSSL-provider
wiring.** An OpenSSL caller by definition holds the public key and can
compute µ in software trivially (T28's own Python does it in five
lines); the mechanism's value is for raw-PKCS#11/KMIP/wasm callers on
the other side of a narrow pipe. Wiring it into the OpenSSL provider
would add surface with no consumer. Revisit only if one appears.

**Work:**

1. `vendor_mechanisms.h`: `CKM_PQCTODAY_ML_DSA_MU_GEN` (`0x80000014`,
   next free slot) + `CK_PQCTODAY_MU_GEN_PARAMS { hKey; tr[64];
   bTrPresent; pContext; ulContextLen }` mirroring the draft's
   `CK_MU_GEN_PARAMS` semantics (handle empty ⇒ TR expected). Tag
   every site `PQCTODAY-VENDOR-EXT-MU` — this mechanism is deleted
   together with R34's when v3.3 ratifies, replaced by the native
   codepoints.
2. C++ engine: digest-op dispatch case (`SoftHSM_digest.cpp` path):
   init = resolve TR (from the handle's `CKA_VALUE` via
   `SHAKE256(pk, 64)`, or the caller's precomputed TR), seed the
   incremental SHAKE256 state with `tr‖0x00‖len(ctx)‖ctx`; update =
   stream message bytes; final = squeeze 64 bytes. This is exactly
   `ossl_ml_dsa_mu_init/update/finalize`'s decomposition (OpenSSL's
   own `ml_dsa_sign.c`), reachable through EVP XOF APIs the engine
   already links.
3. Rust engine: same shape in the `C_Digest*` dispatch; `ck_param`
   layout for the new params struct (with both-ABI offset rows in the
   test table, per that module's own discipline); the `sha3` crate's
   incremental `Shake256` the `fips204-patched` crate already uses
   provides the primitive.
4. Advertise via `C_GetMechanismList`/`GetMechanismInfo`
   (`CKF_DIGEST`), both engines.

**Proof plan:** unit/integration tests in both engines: µ produced by
the mechanism for a (key, ctx, message) triple must be byte-identical
to an independently computed
`SHAKE256(SHAKE256(pk,64)‖0x00‖len(ctx)‖ctx‖M, 64)` — and, the
end-to-end proof, feeding that µ into `CKM_PQCTODAY_ML_DSA_MU` must
yield a signature OpenSSL's native ML-DSA verifies against the
original message (extends T28/T28b's existing chain: replaces its
Python µ step with the token's own). Multi-part digest (2+ updates)
must equal one-shot. TR-supplied and handle-supplied paths both
covered; handle-and-TR-both-absent rejected loudly. Regression: full
harness, CTest, `cargo test --release`.

---

### R40 — ML-KEM public SPKI/text encoders (un-parks R33) — effort S–M

**Grounding:** OP-3's deliberately-deferred parity tier. Public-key
output for ML-KEM already works via the keymgmt EXPORT bridge into the
default provider; the dedicated encoders only matter under a
`DISALLOW_EXPORT_PUBLIC`-style configuration (which blocks that
bridge) and for `-text` cosmetic parity with every other PQC family in
this fork. The pattern is fully established:
`p11prov_mldsa_encoder_spki_der_*` (`encoder.c:1208-1270`) and the
ML-DSA text encoder (`encoder.c:1312+`).

**Work:** mirror the ML-DSA SPKI-DER + text encoder pair for the three
ML-KEM variants (`encoder.c`), register them in `provider.c`'s encoder
table alongside the existing ML-KEM PrivateKeyInfo encoders (R3).
ML-KEM OIDs are already in the codebase (the R2 decoders and keymgmt
use them — reuse, don't re-derive).

**Proof plan:** harness case: `pkey -pubout` / `storeutl -text` on an
ML-KEM token key with the provider's own encoders selected (verify via
`PKCS11_PROVIDER_DEBUG` that the provider encoder ran, not the
default-provider bridge — otherwise this case would vacuously pass
today); DER output must be byte-identical to what the bridge produces
for the same key (the bridge IS the oracle); decode-back via the R2
decoder round-trips to a working encapsulation. Regression: full
harness, CTest.

---

### R41 — XMSS/XMSS-MT provider surface (un-parks R27, closes ALG-2) — effort L

**Grounding (all verified against source):** the last
algorithm-family gap in the matrix. Both engines are ready:

- **Keygen**: C++ `SoftHSM_keygen.cpp:511+` (`CKM_XMSS_KEY_PAIR_GEN` /
  `CKM_XMSSMT_KEY_PAIR_GEN` → `CKK_XMSS`/`CKK_XMSSMT`); Rust
  `ffi.rs:1232/2818+` (same, with `CKA_PARAMETER_SET` resolution).
- **Sign/verify**: C++ §6.14 stateful path; Rust `ffi.rs:5129`
  (`CKM_XMSS`/`CKM_XMSSMT` arm over `CKA_PRIV_STATEFUL_KEY_STATE`).
- **Provider prerequisites already banked by earlier phases**:
  `cache_key()` already skips `CKK_XMSS`/`CKK_XMSSMT` (R29 added the
  guard pre-emptively — the leaf-reuse hazard is pre-solved);
  `sig/hss.c` is the proven template for the accumulate-then-single-
  `C_Sign` stateful shape; `CKK_XMSS`/`CKK_XMSSMT` constants exist in
  the provider's `pkcs11.h`.
- **No OpenSSL-side anything**: 3.6 has no XMSS names, OIDs, or verify
  support (unlike LMS) — custom algorithm names (`XMSS`, `XMSSMT`)
  reachable only by propquery-aware callers, and no
  OpenSSL-native-verify oracle exists.

**Work (expect the R1/R4 "five-gap" registration sequence — every new
key family so far has hit missing cases in the same places):**

1. `sig/xmss.c`: REUSE `sig/hss.c`'s shape directly (the phase-6 note
   on R27 already mandates reuse over copy — factor shared stateful
   helpers if the diff wants to copy). Signature-size logic from
   `CKA_PARAMETER_SET` (the Rust engine's own `get_sig_len` XMSS arm,
   `handlers.rs:1857+`, is the reference formula:
   `4 + n + (len+h)·n`, with the SP 800-208 n=24 sets handled).
   Single-part accumulate (stateful; NOT added to multi-part gates'
   exclusion — check both engines' actual C_SignUpdate acceptance for
   CKM_XMSS live first; HSS precedent says the provider must
   accumulate and single-shot `C_Sign`).
2. `keymgmt.c`: XMSS/XMSSMT keymgmt with GEN support
   (`CKA_PARAMETER_SET` mandatory on the public template, mirroring
   ML-KEM's R3b pattern); `p11prov_common_gen_set_params` type-switch
   case (the R5 lesson — TLS-style callers hit it even when CLI
   doesn't).
3. `objects.c` + `store.c`: `CKK_XMSS`/`CKK_XMSSMT` cases in fetch,
   export, import/store-dispatch, and naming switches (the exact
   five-gap checklist from R1/R4 — grep every `case CKK_ML_DSA:` and
   `case CKK_HSS:` site and mirror).
4. `provider.c`: `PQC_MECHS` additions + `ADD_ALGO_EXT(XMSS, …)` /
   `(XMSSMT, …)` registrations gated on token advertisement; encoders:
   URI-PEM PrivateKeyInfo only (the `encode_pkey_as_pk11_uri` block —
   no SPKI/OID story exists for XMSS in X.509).
5. Both engines: confirm `C_GetMechanismInfo` arms exist and advertise
   `CKF_SIGN|CKF_VERIFY` correctly (Rust's unit test that iterates
   `SUPPORTED_MECHS` enforces this on its side).

**Proof plan (the weakest-oracle item in the phase — compensate with
layers):** (1) RFC 8391 / NIST SP 800-208 KAT vectors verified
in-provider for at least one XMSS and one XMSS-MT parameter set —
strongest external anchor available; (2) cross-engine: C++-signed
verifies on Rust and vice versa, through the provider both ways;
(3) the stateful-counter proof, mirroring T24e: two separate
processes, same key, XMSS `idx` (leading 4 bytes of the signature)
must advance 0→1, first signature still verifies after the second —
this is the test class that caught the provider-level leaf-reuse bug
in R29, and XMSS must clear the same bar; (4) sabotage twins
throughout. Regression: full harness both arms, CTest,
`cargo test --release`.

---

## Explicitly NOT in this phase — permanent, documented limitations

Restated so "close all the remaining gaps" has a precise boundary.
These are not closeable from this codebase, and each already carries
its documentation:

- **F36-6 residual, `message-encoding=0`** (arbitrary caller M′ under
  plain `CKM_ML_DSA`): no well-defined input shape exists to accept —
  spec-structural. R34 (µ) + R35/R37 (PHM) between them cover every
  legitimate use the OpenSSL params serve.
- **ALG-5 residual** (Montgomery derive vs foreign peer with OpenSSL
  peer-validation enabled): OpenSSL-core legacy EC_KEY-path
  interaction; this provider's derive is proven correct. Documented at
  T16.
- **WART-5** (RSA-OAEP SHA-1 defaults rejected): deliberate FIPS
  posture; documented workaround shipped in the provider README.
- **WART-6** (benign ASN.1 error-queue noise during provider-active
  TLS): cosmetic, root-caused, documented interop caveat.

## Phase-8 exit criteria

Every gap-matrix row RESOLVED/CLOSED except the four limitations
above; harness grown by ≥8 cases (T31/T31b, R37's cross-engine
fixture, R39's chain extension, R40's encoder case, R41's
KAT/cross-engine/stateful trio), zero XFAILs remaining; both parked
items (R27, R33) formally closed in the audit with their rows updated;
the audit's "remaining gaps" answer becomes: *"the four documented
limitations only."*
