# OpenSSL provider remediation plan, phase 3 (2026-08-25) — R12/R13/R14 EXECUTED, R15-R17 still plan-only

**Execution update (2026-08-25/26):** R12, R13, and R14 have been
executed and landed — see
`docs/openssl-provider-coverage-audit-2026-08-25.md` §6's "R12 (TLS13-
KDF root cause + fix) and R13" and "R14 (Rust `C_GetSlotList` root
cause + fix)" entries for the full mechanism of each. R12's own written
hypothesis (missing `CKM_HKDF_DATA` support) turned out to be only the
first of four layered bugs, not the whole picture; R14's own written
hypothesis correctly named two candidate defects but did not know which
one (or both) actually mattered until sabotage-testing settled it (one
did, one didn't but was kept as a real hardening) — the plan's own
"confirm before fixing" rule is exactly why neither wrong or incomplete
first hypothesis shipped unverified. R12/R13/R14's own sections below
are left as originally written (the plan, not the result) per this
project's append-only convention; do not edit them to match the
outcome. **Harness: `PASS=27 FAIL=0 XFAIL=0 XPASS=0` — zero remaining
known gaps.** R15–R17 remain plan-only, not executed.

Scope: the gaps that remain **after** the phase-2 execution run
(commits `97420e8` R3-core, `1e6576b` R2, `493d354` R4, `183e775`
R5-partial, `962a59f` R6-partial; harness `PASS=25 FAIL=0 XFAIL=1
XPASS=0`, sole XFAIL = T15b). Branch `feat/jdk27-jca-provider`,
nothing pushed.

This plan was written with fresh source investigation, not from
memory: every file:line cited below was read in this planning session.
Two of the phase-2 "root cause not yet nailed down" items now carry a
**concrete primary hypothesis with source evidence** (R12, R14) —
each still gets an instrumentation-first confirmation step before any
fix, per the standing discipline (a signal that pattern-matches a
known failure may have a different cause).

Numbering continues from phase 2 (R2–R11). New items: R12–R17.
R7–R11 are carried forward unchanged (see phase-2 doc §"Priority 2
tail").

**Decisions confirmed with the user (2026-08-25), binding on
execution:** (1) execution scope is the full R12→R17 sequence in one
run; (2) R12's `CKM_HKDF_DATA` lands in **both** engines (C++ and
Rust), keeping mechanism parity; (3) R15's gate is a **fully
token-backed server** — token-resident ML-DSA certificate key AND
token-performed encapsulation, not the minimal encap-only proof.

---

## R12 — TLS13-KDF: root-cause and fix, completing R5 phase 1 — Priority 1, effort S–M

**The blocker restated:** with `-propquery "?provider=pkcs11"`, a real
TLS 1.3 handshake negotiates `MLKEM768` with the token doing the
client KEM work (engine log: 6 objects created), then dies in
`tls13_generate_secret` because OpenSSL's `EVP_KDF_fetch` also honors
the propquery and lands on **this provider's own `TLS13_KDF`**
(`kdf.c`).

**New evidence, gathered for this plan (changes the phase-2 framing):**

The phase-2 doc guessed the KDF "wasn't designed for plain
octet-string secrets." That guess is **wrong** — it handles them fine:
`p11prov_hkdf_set_ctx_params` takes `OSSL_KDF_PARAM_KEY` as an octet
string and wraps it into an ephemeral session `CKO_SECRET_KEY` object
via `inner_pkcs11_key` → `p11prov_create_secret_key`
(`src/vendor/pkcs11-provider/src/kdf.c:769-786`, `110-135`). The
design is sound. The real fault line is one mechanism constant:

1. The byte-output derive path — exactly what `tls13_generate_secret`
   calls — hard-codes **`CKM_HKDF_DATA`** for both modes:
   `p11prov_tls13_kdf_derive` passes it at `kdf.c:601` (expand) and
   `kdf.c:609` (extract), and `inner_derive_key` then asks the token
   for a `CKO_DATA` result object (`kdf.c:187-189`).
2. Registration of `TLS13_KDF` is gated only on **`CKM_HKDF_DERIVE`**
   (`provider.c:1164-1168`) — which both engines advertise, so the KDF
   registers and gets fetched.
3. **Neither engine implements `CKM_HKDF_DATA` (0x402b).** The C++
   engine's full HKDF handler covers only `CKM_HKDF_DERIVE`
   (`src/lib/SoftHSM_keygen.cpp:3705ff`; zero matches for `HKDF_DATA`
   anywhere in `src/lib/` outside pkcs11t.h). The Rust engine likewise
   dispatches only `CKM_HKDF_DERIVE` (`rust/src/ffi.rs:8360ff`;
   `CKM_HKDF_DATA` absent even from `rust/src/constants.rs`).

So the provider advertises a KDF whose gate mechanism the token has,
then executes it with a sibling mechanism the token lacks. The
"ASN.1/PKCS8 parse error" observed in phase 2 is presumed to be the
downstream error-stack rendering of that failed `C_DeriveKey`, not a
parse problem — this presumption is exactly what step 1 verifies.

**Step 1 — confirm before fixing (mandatory).** Re-run the phase-2
handshake with the C++ engine's DEBUG log on and a temporary trace in
`p11prov_tls13_kdf_derive`. Expected confirmation: `C_DeriveKey` is
reached with mechanism `0x402b` and the engine rejects it
(`CKR_MECHANISM_INVALID`). If the failure is instead earlier
(`p11prov_create_secret_key`) or different, STOP and re-plan this item
— do not proceed on the hypothesis anyway.

**Step 2 — fix in the engines, not the vendor provider.** Implement
`CKM_HKDF_DATA` as a thin alias of the existing HKDF computation in
both engines (root-cause fix, spec-defined mechanism — PKCS#11 v3.0+
§2.43 defines the `_DATA` variant as the same derivation emitting a
`CKO_DATA` object):

- **C++** (`SoftHSM_keygen.cpp`): accept `CKM_HKDF_DATA` alongside
  `CKM_HKDF_DERIVE` in the handler; when it's the `_DATA` variant,
  the output object is `CKO_DATA` (the provider's template is just
  CLASS/TOKEN/VALUE_LEN, `kdf.c:173-189`) with the derived bytes in
  `CKA_VALUE`. Check the surrounding template-validation/dispatch code
  for class assumptions (`CKO_SECRET_KEY` may be hard-assumed).
  Register the mechanism in `SoftHSM_slots.cpp` (both the `t[]` name
  map at ~:467 and the mechanism-list switch at ~:1175) and in
  `prepareSupportedMechanisms()`.
- **Rust** (`rust/src/ffi.rs` + `rust/src/constants.rs`): add the
  constant, add the dispatch arm reusing the existing HKDF code path
  (`ffi.rs:8360ff`), emit a data object, extend the mechanism list
  (`ffi.rs:~1180`, `~13743`).
- **Vendor code untouched** unless step 1 disproves the hypothesis.

**Step 3 — prove, with the anti-false-pass rules of R13 already
applied.** The phase-2 manual handshake becomes harness case T13:
software `s_server` (`OPENSSL_CONF=/dev/null`) + `s_client -groups
MLKEM768 -propquery "?provider=pkcs11"`; PASS requires (a) handshake
completes, exit code read directly; (b) the engine DEBUG log shows
both the KEM ops AND `CKM_HKDF_DATA` derives — log evidence is the
arbiter of who did the work, per the confirmed silent-fallback hazard;
(c) negative control: same setup, `-groups X25519` → no ML-KEM op in
the log. Sabotage on a copy: break the group entry in `tls.c` →
negotiation must not pick MLKEM768; break the new engine `_DATA` arm →
handshake must fail again (proves the fix carries the pass, both
directions).

**Risks / open ends, stated up front:** even with `CKM_HKDF_DATA`
landed, `p11prov_tls13_derive_secret`'s extract-side path (zerokey
creation, salt-as-handle variants) may hit a second engine gap — keep
the instrumentation in place until the full handshake passes, and
scope any second gap as its own confirmed finding rather than folding
silent extra fixes into this one. Engine unit tests
(`src/lib/test/DeriveTests.cpp` HKDF cases, Rust suite currently 410
green) must stay green — the alias must not perturb `CKM_HKDF_DERIVE`.

---

## R13 — kill the silent-software-fallback false pass — Priority 1, effort S

Phase 2 confirmed empirically: without the propquery, the identical
`-groups MLKEM768` handshake **succeeds with zero token objects** —
the default provider serves the whole group in software. Any green
handshake without log evidence proves nothing. This item makes that
rule mechanical instead of remembered:

1. **Harness rule:** every TLS-path test (T13 and successors, R15's
   server case) must assert token participation from the engine DEBUG
   log (op/object counts), not just exit codes. Add a tiny shared
   helper (count occurrences of the relevant mechanism in the log
   between markers) so future cases can't skip it out of convenience.
2. **Negative-control twin:** each TLS positive case gets the
   fallback twin run — same command, no propquery — asserted to
   succeed with **zero** token KEM ops, permanently documenting the
   hazard as an executable fact rather than prose.
3. **Documentation:** a short "deploying this provider for TLS"
   section in the coverage audit: the propquery (or config
   `default_properties`) is load-bearing; without it the token is
   silently bypassed; with it, the whole SSL_CTX's fetches route here
   (which is exactly why R12's KDF must work). Revisit narrower
   scoping (pinning only pkey/KEM fetches, app-side explicit fetch)
   only after R12 lands — if the KDF works, the broad propquery
   becomes acceptable rather than a hazard.

No engine or provider code in this item; it is harness + docs.

---

## R14 — Rust `C_GetSlotList` fix, then finish R6 persistence — Priority 2, effort M

**The blocker restated:** `softhsm2-util --init-token` fails against
the Rust engine ("Could not get the slot list"), pre-existing
(reproduced on the pre-R6 binary), blocking the end-to-end proof of
the already-landed `SOFTHSMRUST_STATE_FILE` persistence. T15b — the
sole remaining XFAIL — was never testing persistence at all; it was
absorbing this failure.

**New evidence:** `rust/src/ffi.rs:334-388` read in full. Two distinct
defect candidates, both visible in source:

1. **"present" is conflated with "initialized"** (`ffi.rs:367`): the
   `token_present` filter keeps only `t.initialized` slots. SoftHSM
   semantics (and the C++ engine's) are that a slot **always** has a
   token present — initialized or not; `C_GetSlotList(CK_TRUE)` must
   include uninitialized tokens. Under the current code a fresh store
   yields 0 slots for a `CK_TRUE` caller, which matches the observed
   first-call count of 0.
2. **State mutation on every call** (`ffi.rs:343-362`): the
   auto-advance ("always keep one uninitialized slot") runs inside
   `C_GetSlotList` itself, on both the size call and the fill call.
   The standard two-call pattern (NULL buffer for count, then
   allocated buffer) is only correct if the slot set is stable between
   the calls; a getter that inserts slots can legitimately disagree
   with its own previous answer — which matches the observed 0-then-1
   trace.

**Step 1 — confirm which defect bites (mandatory).** Temporary trace
logging, per call: the `token_present` argument, the store's
slot/initialized set before and after the auto-advance, and the
returned count. Run `softhsm2-util --init-token --free …` once. This
distinguishes: (a) filter-semantics bug, (b) two-call instability,
(c) both. (The 0-then-1 trace from phase 2 recorded outcomes only,
not inputs — do not assume it was the same `token_present` value on
both calls.)

**Step 2 — fix to spec semantics, minimally:**
- Token-present filter: a slot with a token — initialized or not — is
  "present" for this soft token. The filter should keep all slots (or
  be removed), matching SoftHSM v2 behavior that `softhsm2-util`
  is written against.
- Auto-advance: make it idempotent and observation-safe — top up the
  one spare uninitialized slot **only when none exists** (its current
  condition already implies this; verify no path inserts more than
  one), and confirm the invariant "a size call followed by a fill
  call returns the same set" holds by construction afterwards. If the
  auto-advance genuinely must not run in `C_GetSlotList` at all to
  guarantee that, move it to `C_Initialize`/`C_InitToken` — decide on
  evidence from step 1, not preference.
- Check the WASM/browser arm and the KMIP server for reliance on the
  old filter semantics before changing it (`initialized`-only counts
  may be load-bearing somewhere; grep callers and the JS shim).

**Step 3 — finish R6 exactly as scoped in phase 2:** once
`--init-token` works, rewrite T15b as the real multi-process proof —
process A (`SOFTHSMRUST_STATE_FILE` set) generates a key, process B
(same env) loads and uses it. Flip XFAIL→PASS only on the live
round-trip. Sabotage both directions on copies: env var unset → flow
fails (the variable carries the persistence); corrupt the `SHR3SNP2`
magic → next init refuses loudly, no half-load. Then extend the Rust
arm beyond the stub: store enumeration, ML-DSA sign round-trip,
ML-KEM keygen (mirror T2/T3b/T4x). Rust unit suite (410) must stay
green throughout.

Harness end-state for this item: `XFAIL=0` for the first time.

---

## R15 — R5 server role: token as the encapsulating TLS server — Priority 2, effort M

Carried from phase 2, unchanged in scope, now sequenced **after R12**
(a server-side proof is meaningless while the shared KDF path still
kills every token-participating handshake).

In a TLS 1.3 KEM group the client generates the keypair and the
**server encapsulates against the client's public share** — so the
server side needs peer-share import into a usable object, which is
exactly the gap: `EVP_PKEY_set1_encoded_public_key` →
set_params/import path, ML-KEM keymgmt IMPORT/IMPORT_TYPES for the
KEM operation path (absent — distinct from the keymgmt IMPORT that
URI-PEM decode uses, which works, R2's proof), the
`p11prov_obj_import_key` type gate (currently
`CKK_ML_DSA || CKK_SLH_DSA` only), and an import yielding a real
handle `C_EncapsulateKey` can consume.

**Proof (user decision 2026-08-25: fully token-backed server is the
gate, not a stretch goal):** `s_server` running with the provider
(propquery pinned), where BOTH server-side asymmetric roles run on
the token: (a) the server certificate's private key is a
token-resident ML-DSA key (certificate generated via the existing
proven token-signing path; the URI-PEM file handed to `s_server -key`
— which also exercises R2's decoder chain under a real TLS load for
the first time), and (b) the KEM encapsulation against the software
`s_client -groups MLKEM768` peer share happens on the token.
Handshake completes; the engine log must show **both** the
CertificateVerify signature op and the encapsulation (R13 helper
asserts each separately, so a partial regression is attributable);
negative-control twin per R13. If the token-backed certificate half
fails for reasons unrelated to the peer-share-import gap this item
exists to fix, report it as its own finding — do not silently
downgrade the gate to encap-only.

---

## R16 — encoder parity tier — Priority 3, effort S

Two leftovers from R3/R4, cosmetic-to-useful but not blocking any
flow:

1. **ML-KEM SPKI + text encoders** (R3 parity tier, scoped in phase
   2): public-key PEM output and `-text` rendering to match what
   ML-DSA already has. Proof: `pkey -pubout` and `-text` on a token
   ML-KEM key; round-trip the SPKI through the software provider.
2. **X25519/X448 URI-PEM encoders:** today `genpkey -out` for
   montgomery token keys errors (no encoder), which is why T16/T16b
   deliberately do not gate on genpkey's exit code. Add the URI-PEM
   private-key encoders following the exact R3 ML-KEM pattern
   (`encoder.c` write-pem wrapper + dispatch table + `encoder.h`
   extern + `provider.c` registration in the
   encode-pkey-as-pk11-uri block). Then **re-gate T16/T16b on the
   genpkey exit code** and assert the URI label + no `PRIVATE KEY`
   block, same as T4x_encode.

Both are same-shape-as-done-work items; sabotage each new encoder in
a copy (break the keytype constant → its test fails, neighbors don't).

---

## R17 — montgomery software-peer interop — Priority 3, effort S–M, investigate-first

Open finding from R4: token-to-token X25519/X448 derives agree
(T16/T16b PASS), but deriving against a **software** peer fails —
`OSSL_PARAM_get_BN "param of incompatible type"` from
`EVP_PKEY_public_check`'s legacy path assuming Weierstrass X/Y
coordinates. The provider's derive is proven correct; this is an
interop/export-shape issue.

Investigate-first (no fix scoping until traced): reproduce, get the
exact OpenSSL frame that calls `OSSL_PARAM_get_BN`, and determine
what triggers the legacy Weierstrass assumption — most likely the
montgomery keymgmt advertising/answering an export shape (group/point
params) that routes key-check down the EC legacy path instead of the
raw-`ENCODED_PUBLIC_KEY` path native X25519 uses. Candidate fixes,
**to be chosen on evidence**: montgomery-specific
export/export_types that emit only what native X25519 keymgmt emits;
or answering the check-relevant get_params so the modern path is
taken. Proof: derive token↔software both directions, secrets equal
(non-empty guard, per the phase-2 lesson), plus the reverse pairing.

---

## Carried forward unchanged — R7–R11

See the phase-2 doc §"Priority 2 tail" for full scoping; unchanged by
anything in this plan:

- **R7** remaining composite profiles (M′-verification-first, KATs
  from the KMIP tree).
- **R8** `OSSL_OP_MAC` (bytes-in mode first; no SKEYMGMT dependency).
- **R9** LMS/HSS (gated on ENV-1 oracle rebuild with `enable-lms`;
  run after R14 so stateful counters survive multi-process tests —
  note the dependency tightened from "preferably after R6" to "after
  R14", since R14 is what actually makes the Rust CLI flow work).
- **R10** KDF widening + EVP_SKEY probes (probe-first, writeups to
  the audit before any scoped work). R12's findings feed this
  directly: the `TLS13_KDF`/`HKDF` byte-path vs `_SKEY`-path split in
  `kdf.c` is now well understood.
- **R11** XMSS/XMSS-MT (demand-driven, last).

---

## Sequencing and dependencies

```
R12 (TLS13-KDF fix)  ──►  R13 (anti-false-pass harness rules)
        │                        (same test surface — land together
        ▼                         or R13 immediately after)
R15 (server role)

R14 (C_GetSlotList + R6 finish)  — independent of R12/R13/R15;
                                    prerequisite for R9's Rust arm
R16, R17 — independent, any time, low risk
R7, R8, R10 — demand-driven;  R9 after ENV-1 + R14;  R11 last
```

Recommended order for a single execution session:
**R12 → R13 → R14 → R15 → R16 → R17**, with the standing rule that a
disproved step-1 hypothesis (R12, R14 each have one) stops that item
for re-planning rather than improvising a different fix in-flight.

## Standing discipline (unchanged from phase 2, restated because every
item above depends on it)

- Instrumentation/confirmation **before** fixing; a disproved
  hypothesis stops the item.
- Exit codes read directly, never through pipes; never trust
  `openssl list` for this provider.
- Engine DEBUG log is the arbiter of who performed an operation
  (R13 makes this mechanical for TLS).
- Sabotage-test both directions, always on a copy, function-scoped
  via the brace-depth method (regex and naive replace both failed in
  phase 2); watch for shared assertion lines across test functions.
- Harness flips land in the same commit as the code they prove; docs
  updated append-only.
- Engine unit suites (C++ `make check`, Rust 410) green before any
  commit that touches an engine.
- No push without explicit confirmation. Parallel-session commits
  left untouched.
