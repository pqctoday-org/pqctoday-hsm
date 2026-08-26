# OpenSSL provider remediation plan, phase 4 (2026-08-26) — the complete remaining-gap closure

Scope: everything still open after phase 3 closed R12–R17 in full
(branch `feat/jdk27-jca-provider`, commit `8f3fb8e`, unpushed; harness
`PASS=31 FAIL=0 XFAIL=0 XPASS=0`). This plan covers three families of
gaps:

1. the **R7–R11 tail** carried forward twice already (phase-2 doc
   §"Priority 2 tail", never started);
2. **new findings surfaced during phase 3** that were flagged but
   deliberately not chased (EC/ECDH `SET_PARAMS`, three items of
   proof-debt, residual ASN.1 noise);
3. the **never-scoped low-priority residue** from the audit's gap
   matrix (OP-4, ALG-6, ALG-7, F36-5, F36-6, WART-1/3/5, ENV-1,
   ENV-3) plus two hygiene findings made while writing THIS plan.

Numbering: R7–R11 keep their original identities (third carry — this
time with full execution scoping, not a pointer). New items are
R18–R21. Nothing in this plan renumbers or rewrites a prior plan's
section, per the append-only convention.

**Baseline / branch warning (read before executing):** this plan was
drafted while the shared worktree sat on `main` (`65c6cd9`, v0.25.0)
— another session had switched branches, a known hazard of this
repo's single shared tree. All file:line references below were read
from `feat/jdk27-jca-provider` via `git show`, NOT from the checkout.
**Execution must happen on top of `feat/jdk27-jca-provider`
(`8f3fb8e`)** — every item below assumes phase 3's code is present
(R15's `SET_PARAMS` precedent, R16's encoders, the 31-case harness).
First execution step of any item: confirm `git -C ~/Antigravity/pqctoday-hsm
branch --show-current` and check out / rebase as needed, committing
fast per the shared-tree discipline.

This plan was written with fresh source investigation: every
file:line cited was read from the feature branch in this planning
session, and two of the phase-2 tail's own facts were corrected in
the process (R7's KAT-vector path was stale; a stray-debug-output
finding in `composite.c` is new). Where a prior doc's premise was NOT
re-verified, the item says so and starts with a verification step —
phase 3 hit stale premises twice (R16's SPKI half, R17 entirely), so
**every carried item here opens with a "re-verify the premise"
step**.

---

## Standing discipline (binding on every item, carried from phases 2–3)

1. **Confirm before fixing.** Reproduce the gap live and trace the
   mechanism before writing the fix. A signal that pattern-matches a
   known failure may have a different cause; a premise written in an
   earlier phase may have silently expired (proven twice in phase 3).
2. **Sabotage-test every new proof.** Break the fix in a copy (never
   on write paths), confirm the new case — and only that case —
   fails; restore, confirm green. A proof that can't fail proves
   nothing.
3. **No silent software fallback (R13).** Every case that could be
   satisfied by the default provider must either pin
   `-propquery "?provider=pkcs11"` and assert engine-log evidence, or
   ship a negative-control twin. The engine-log marker must be
   op-specific (T15's "64 into 80" lesson: a generic marker that also
   fires for unrelated token activity proves nothing).
4. **Report at true confidence.** A fix applied for consistency but
   not independently proven necessary is documented as exactly that.
5. **Strip all temporary instrumentation before commit**; run both
   engines' full suites (C++ `ctest` 8/8, Rust `cargo test --lib`
   410/410) plus the full harness before every commit; one commit per
   R-item (or explicitly-paired items, as R16+R17 were).
6. **No push without explicit user confirmation.**
7. **PKCS#11 facts come from `src/lib/pkcs11/pkcs11t.h` and the
   ratified v3.2 spec text; OpenSSL facts from the staged 3.6.3
   source/docs** — never from memory.

---

## Priority 1 — correctness risk and proof-debt

### R18 — EC/ECDH/Edwards generic `SET_PARAMS` gap (latent server-role bug) — effort S–M, investigate-first

**The finding (R15, 2026-08-26):** before R15, *no* keymgmt in this
provider registered the generic `OSSL_FUNC_KEYMGMT_SET_PARAMS` /
`SETTABLE_PARAMS` pair. R15 added it for ML-KEM only (the three
tables in `kem/mlkem.c`, currently the sole three `SET_PARAMS`
registrations in the whole provider — verified this session:
`keymgmt.c` has zero). TLS 1.3's server-side key_share processing
installs the peer's public share via exactly this dispatch
(`EVP_PKEY_set1_encoded_public_key` →
`EVP_PKEY_set_octet_string_param(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY)`
→ keymgmt `SET_PARAMS` — traced against real 3.6.3 source in R15,
not inferred). Therefore a TLS server whose *classical* ephemeral
group keygen is pinned to this provider (`s_server -propquery
"?provider=pkcs11"` with `-groups X25519` / `-groups
prime256v1` / X448) should fail to install the client's share — the
same failure class R15 fixed for ML-KEM, in mainstream algorithms.

**Step 1 — reproduce (this is the whole gate for whether a fix is
needed):** clone T15's arena shape with a plain RSA or EC token
certificate and run the handshake once per group: `prime256v1`,
`X25519`, `X448`, server propquery pinned. Expected failure modes:
gen_init selection rejection (R15 bug #1's EC analog — check
`p11prov_ec_gen_init`/`p11prov_montgomery_gen_init_int` accept
`0x84`) and/or missing `SET_PARAMS`. If all three groups handshake
cleanly, trace WHY (the default provider silently winning the keygen
fetch is the known false-pass hazard — check engine logs per R13
before believing a green result) and close the item as
does-not-reproduce with a T17-style permanent harness case.

**Step 2 — fix (only what step 1 proves broken):** EC already has
`p11prov_obj_set_ec_encoded_public_key` (`objects.c`, used by the
existing exchange path) and `mock_pub_ec_key` — so the likely fix is
a thin `set_params` wrapper per EC-family keymgmt that locates
`OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY` and calls the existing helper,
plus `settable_params`, registered in the EC / Edwards / montgomery
tables in `keymgmt.c`. Model on
`p11prov_mlkem_keymgmt_set_params_fn` (`kem/mlkem.c`, R15). Do NOT
copy the ML-KEM attr-population body — EC objects carry
`CKA_EC_POINT`/`CKA_EC_PARAMS`, not `CKA_VALUE`+`CKA_PARAMETER_SET`.

**Proof:** one new harness case per fixed group (T18/T18b/T18c as
needed), each the T15 pattern: full handshake, op-specific engine-log
marker, negative-control twin. Sabotage: remove one group's
`SET_PARAMS` registration in a copy → only that group's case fails.

### R19 — phase-3 proof-debt closure — effort S, three independent sub-items

Closes the three "reported at true confidence, not proven" items
phase 3 left explicitly open. Each is small; all three land as one
commit.

**R19a — decapsulate `CKA_PRIVATE` fix, independent proof.** R15
applied the explicit `CKA_PRIVATE = CK_FALSE` template entry to
`p11prov_kem_decapsulate` for consistency with the sabotage-proven
encapsulate fix, but never independently proved the decap half.
Attempt to construct the observable scenario: a fresh process where
`C_DecapsulateKey` runs without any prior login-establishing
operation (the latent bug only bites when the session is public and
the output-secret template defaults to private). Candidate shape: a
token whose ML-KEM private key was created `CKA_PRIVATE=false`
(login-free access), loaded by URI in a fresh process, straight to
`pkeyutl -decap`. If constructible: sabotage the decap template in a
copy, confirm the failure, restore, add the harness assertion. If NOT
constructible through any real entry path, write that down in the
audit as the finding ("fix kept; unobservable through this provider's
call graph because every decap path forces login first") and close —
do not manufacture an artificial entry point just to claim a proof.

**R19b — ML-KEM SPKI encoder: observable or inert?** R16's SPKI-DER
encoder is currently redundant (the default provider's generic path
already answers `-pubout`; confirmed by revert-and-retest). One
config could make it load-bearing: the provider's export-blocking
setting (`p11prov_ctx_allow_export` / `DISALLOW_EXPORT_PUBLIC`, the
same gate `p11prov_montgomery_export` checks). Investigate: with
public-key export disallowed in the provider config, does `-pubout`
on a token ML-KEM key (a) fail entirely, (b) succeed via the new
encoder, or (c) succeed via the generic path anyway? If (b), add a
harness case with that config and sabotage-test the encoder — it
gains a real proof. If (a) or (c), record the answer in the audit and
leave the encoder as documented parity. Note: the new encoder itself
calls `p11prov_obj_export_public_key`, which may honor the same gate
— outcome (a) is genuinely possible; the point is to *know*.

**R19c — residual ASN.1 error-queue noise (R12 leftover).** A
`asn1_check_tlen`/`PKCS8_PRIV_KEY_INFO` error remains on the client's
queue during a *passing* PQC handshake; absent in a no-provider
control; believed to be R2's decoders probing and correctly rejecting
the peer's certificate. Confirm: rerun with `PKCS11_PROVIDER_DEBUG`
plus an `ERR_print_errors` tap (or `openssl s_client -trace`),
identify exactly which registered decoder pushes the error and
against which input. If it is the expected probe-and-reject pattern,
document it in the audit's WART list (interop caveat: callers that
treat a non-empty error queue as failure will misbehave) and stop. If
a decoder `does_selection` is over-claiming (accepting inputs it then
fails on, instead of declining), tighten it — that is a real fix with
a real assertion (error queue empty after handshake).

---

## Priority 2 — coverage expansion (the substantive tail)

### R8 — `OSSL_OP_MAC`: token HMAC/CMAC/KMAC — effort M

**Premise re-verified this session:** `provider.c`'s operation map
names `OSSL_OP_MAC` ("mac", line ~1739) but `p11prov_query_operation`
has no `op_mac` table — nothing to return; every `EVP_MAC` fetch
falls through to software. Both engines advertise the mechanisms (45
HMAC/CMAC/KMAC hits in `SoftHSM_slots.cpp`).

**Phase one (this item, complete in itself):** bytes-in mode only —
no SKEYMGMT dependency (confirmed in phase-2 scoping C5). New
`mac.c`: `newctx/freectx/dupctx/init/update/final/get_params/
set_ctx_params` over `CKM_SHA*_HMAC`, `CKM_AES_CMAC`, `CKM_KMAC_128/
256`; `OSSL_MAC_PARAM_KEY` becomes an ephemeral session secret-key
object (`C_CreateObject` — **explicit `CKA_PRIVATE = CK_FALSE` in the
template**, the R15 lesson: the C++ engine defaults it private and
demands a login the session may not have) → `C_SignInit`/`C_Sign*`.
Mech-gated registration like every other operation table; new
`op_mac` arm in `p11prov_query_operation`. Mind R15's dupctx lesson:
if OpenSSL duplicates in-flight MAC contexts (it does for some
callers), `C_GetOperationState` will fail on this engine — reuse the
`digests.c` shadow-buffer fallback pattern outright rather than
rediscovering it.

**Deferred explicitly:** `EVP_MAC_init_SKEY` opaque-token-key mode —
that is R10's `EVP_SKEY` probe's business, not this item's.

**Proof:** `openssl mac -propquery "?provider=pkcs11"` output
byte-equal to software HMAC over identical key bytes (same
cross-check pattern as T3a-c), one case per family (HMAC-SHA256,
AES-CMAC, KMAC128), each with engine-log evidence + R13 negative
twin. Sabotage one mechanism's registration → only its case fails.

### R7 — composite profiles 4–8 — effort M–L, verification-first

**Premise re-verified this session, with one correction:** registry
(`composite.c:96` on the feature branch) still has exactly 3 of 8
(.37/.45/.49); the five missing still include all four
§10.4-recommended. **Correction:** the KAT vectors the phase-2 doc
points at live at `kmip/kat/composite-sigs/external-composite-vectors.json`
— NOT `rust/kat/...` (that path no longer exists; probably moved when
the KMIP tree reorganized). Update the phase-2 pointer when landing.

**Order of work:**
1. **M′ pin for Ed25519 profiles first** (the C8 gate): pure vs
   prehashed decided against the KMIP implementation
   (`kmip/src/ops/composite_sig.rs`) AND the external vectors file —
   both must agree before any signing code. A wrong guess signs
   well-formed, wrong composites only KATs catch.
2. Registry rows for the five profiles (OIDs .38/.39/.40/.44/.47
   per draft-lamps-19 — **verify each OID against the KMIP tree's
   `kmip/src/kmip30/algos.rs` constants AND the draft itself before
   committing**; do not trust this plan's digits).
3. Classical-half dispatch: the current `composite.c` sub-sigctx
   selection branches only RSA-PSS vs ECDSA (`pre_hash_nid ==
   NID_sha256 ? CKM_RSA_PKCS_PSS : CKM_ECDSA` — read live this
   session); Ed25519 profiles need a third branch (`CKM_EDDSA`) and
   MLDSA65-RSA3072-PSS needs the PSS branch parameterized by key
   size, not assumed 2048.
4. `tls.c` TLS-SIGALG entries following the existing `0xFEB0+`
   private-range pattern (`TLS_SIGALG_ENTRY` macro, line ~352).

**Proof per profile:** token sign → M′ KAT check against the
external vectors → software cross-verify → one harness COMPSIG case;
sabotage one profile's OID constant → only its case fails. Note
while in this file: it currently contains 33 committed
`fprintf(stderr, "[composite-sig-...]")` debug lines — do NOT add
more; their removal is R21's business, keep the diffs separable.

### R10 — KDF widening + `EVP_SKEY` probes — effort S probe + S–M scoped, probe-first

**Premise re-verified:** `kdf.c` implements HKDF (+TLS13-KDF via the
same context; `CKM_HKDF_DERIVE`/`CKM_HKDF_DATA`) and nothing else.
The C++ engine advertises `CKM_PKCS5_PBKD2` and
`CKM_SP800_108_COUNTER_KDF`/`_FEEDBACK_KDF`
(`SoftHSM_slots.cpp:464-471`, dispatch at 1174-1176).

**Probes first, write-ups appended to the audit BEFORE any scoped
work** (unchanged from phase 2, now with concrete shapes):
- (a) PBKDF2/KBKDF fetch-priority probe: fresh-process arena (T9
  pattern, `load-behavior=early`), `openssl kdf -propquery
  "?provider=pkcs11" -kdfopt ...` for PBKDF2 and KBKDF — determine
  whether OpenSSL's standard fetch names resolve to a provider KDF at
  all and what parameter names arrive.
- (b) `EVP_KDF_derive_SKEY` opaque-handoff viability: can a
  token-resident secret chain into an OpenSSL KDF without export?
  `kdf.c` already carries `set_skey`/`derive_skey` dispatch stubs
  (lines 43-44) — probe what OpenSSL actually calls.

**Then scope:** implement only what the probes show is reachable and
useful; PBKDF2 first (highest caller demand), SP800-108 second.
Proof: derived bytes equal to software derivation with identical
inputs, R13 twins, sabotage per mechanism.

---

## Priority 3 — environment-gated, hygiene, and small surface

### R9 — LMS/HSS token-sign / OpenSSL-verify — effort M, gated on ENV-1

**Step 0 is ENV-1 itself:** rebuild the staged oracle
(`/usr/local/ssl` in the `pqc-rust` container) from
`/ag/pqctoday-hub/openssl-3.6.3-src` with `enable-lms` added to the
existing config line, then re-run the FULL harness against the
rebuilt oracle before any LMS work (a rebuilt oracle is a changed
test substrate — prove 31/31 still green first). Keep the build
recipe in the audit so the container stays reproducible.

**Then:** token HSS sign + XDR public-key export → native `pkeyutl
-verify` (3.6 LMS is verify-only; the split is the whole point).
Multi-process stateful-counter test rides on R14's now-working Rust
CLI flow (`SOFTHSMRUST_STATE_FILE`): sign twice across two processes,
assert the leaf counter advanced and the first signature still
verifies. Proof + sabotage per the standard pattern.

### R20 — small-surface tier — effort S total, five independent micro-items

One commit, five separable diffs; each gets a one-line audit update,
harness assertions only where marked:

1. **OP-4** — KEM `SET_CTX_PARAMS`/`SETTABLE_CTX_PARAMS`: currently
   absent from `kem/mlkem.c`'s KEM dispatch. Add the pair (accepting
   at minimum the CMS `OSSL_KEM_PARAM_OPERATION` name so `cms
   -encrypt` to an ML-KEM cert works — check what F36-4's existing
   `CMS_RECIPINFO_KEM` plumbing expects before choosing params).
   Harness: extend the CMS case or add a `-encap` ctx-param probe.
2. **F36-5** — NIST security-category PKEY param: add
   `OSSL_PKEY_PARAM_SECURITY_CATEGORY` to ML-DSA/ML-KEM/SLH-DSA
   keymgmt `get_params` (values 1/2/3/5 by parameter set — from FIPS
   203/204/205, cite in the commit). Assert via `pkey -text` or a
   param dump in one existing case.
3. **F36-6** — ML-DSA signature-param parity probe: compare
   `deterministic`/`mu`/`message-encoding` behavior vs software
   provider; fix or document divergences. Probe-first; write-up
   mandatory, fix only if a divergence is real.
4. **ALG-6** — ECDH-as-KEM: investigate whether OpenSSL 3.6 has a
   standard fetch surface this maps onto (DHKEM-style); if none,
   record "no consumer, deliberately unexposed" in the audit and
   close without code.
5. **ALG-7** — ChaCha20/ChaCha20-Poly1305 in the cipher table:
   straightforward mech-gated addition mirroring the AES entries;
   probe first that both engines really advertise it natively (the
   audit says so; re-verify — this is a carried premise).

### R21 — hygiene tier — effort S–M total

1. **Stray debug output in `composite.c` (NEW finding, this
   session):** 33 committed `fprintf(stderr, "[composite-sig-...]")`
   lines fire on every composite operation — on `main` AND the
   feature branch, so this predates phase 3 and violates the
   no-shipped-instrumentation rule retroactively. Convert to
   `P11PROV_debug` (not delete — the trace points are useful), one
   mechanical commit, full harness after.
2. **WART-1** — engine log spam (`ObjectFile.cpp(181): The attribute
   is not a byte string: 0x0/...` on every token scan): root-cause
   which provider attribute-fetch template queries non-byte-string
   attributes with byte-string entries (`util.c`'s
   `p11prov_fetch_attributes` path); fix the template types
   provider-side rather than silencing the engine — the engine's
   warning is correct. Assert: one clean provider operation produces
   zero such lines at DEBUG level.
3. **WART-3** — gitignored WASM `src/config.h` leaking into the
   native CMake build (PACKAGE_MAJOR redefinition; provider
   self-reports 1.1 vs CMake's 0.4.0): fix include-order/exclusion in
   the provider's CMakeLists so the native build never sees it;
   assert the live `list -providers` version matches CMake.
4. **WART-5** — document (not fix) the engine's SHA-1-OAEP rejection
   as deliberate FIPS posture in `docs/softhsmv3opsguide.md`, with
   the working `-pkeyopt` incantation from T5.
5. **ENV-3** — dead test assets: delete `test_openssl_integration.sh`
   and `openssl_test.cnf` (superseded by
   `scripts/test-openssl-provider.sh`; the .cnf hardcodes another
   developer's absolute paths — verify nothing references either
   file first, including `pqctoday-admin`, per the orphan-script
   rule). The dormant vendored meson suite (30 tests): decide
   wire-or-document — recommendation: document as intentionally
   unwired (upstream's suite, superseded by ours) rather than
   maintaining a second harness; record the decision in the audit.

### R11 — XMSS/XMSS-MT — demand-driven, LAST, unchanged

No native OpenSSL counterpart, no consumer. Do not execute in this
phase unless a consumer materializes; R9's stateful groundwork is the
prerequisite base. Kept on the books so the audit's ALG-2 row has an
owner.

---

## Sequencing and dependencies

```
R18 (EC SET_PARAMS)  ──────────┐  independent; highest correctness risk
R19 (proof-debt a/b/c) ────────┤  independent; cheap; do alongside R18
                               ▼
R8  (OSSL_OP_MAC, bytes-in) ── reuses R15's dupctx + CKA_PRIVATE lessons
R7  (composites 4-8) ───────── independent of R8; M′ gate first
R10 (KDF probes → scoped work)─ probes any time; scoped work after write-ups
                               ▼
ENV-1 oracle rebuild ── R9 (LMS/HSS) ── needs R14 (done) + rebuilt oracle
R20 (small-surface ×5) ──────── any time; batch late to avoid churn
R21 (hygiene ×5) ────────────── any time; composite-fprintf BEFORE R7 lands
                                (or R7's diffs drown in the cleanup)
R11 (XMSS) ─────────────────── demand-driven, not scheduled
```

Recommended execution order: **R18 → R19 → R21.1 → R8 → R7 → R10
probes → R20 → R21 (rest) → [ENV-1 → R9] → R10 scoped work**, with
R11 explicitly parked. Rationale: correctness and honesty debt first;
the composite-fprintf cleanup (R21.1) lands before R7 touches the
same file; the oracle rebuild is the only step that mutates the
shared test substrate, so it goes late and re-proves the whole
harness immediately after.

Estimated effort: P1 ≈ 1 session; R8+R7 ≈ 1–2 sessions; R10+R20+R21
≈ 1 session; ENV-1+R9 ≈ 1 session. Total ≈ 4–5 focused sessions.

---

## Exit criteria for phase 4

- Every gap-matrix row in the audit either RESOLVED, or carrying a
  documented decision (documented-as-deliberate counts: WART-5,
  ALG-6-if-no-consumer, meson-suite-if-documented, R11-parked).
- Harness grown by one sabotage-tested case per fixed gap; zero
  XFAIL; both engines' suites green.
- The three phase-3 proof-debt items each closed with a definitive
  answer (proven, or proven-unobservable-and-documented).
- Audit doc §4 tables updated row-by-row as items land (same
  strikethrough convention as phases 2–3); this plan's own sections
  left as written, results appended to the audit only.
- All commits on `feat/jdk27-jca-provider` (or its successor), no
  push without explicit confirmation.
