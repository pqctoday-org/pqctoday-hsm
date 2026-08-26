# OpenSSL provider remediation plan — phase 6 (R28–R33)

Date: 2026-08-26. Companion to
`docs/openssl-provider-coverage-audit-2026-08-25.md` (the gap matrix and
per-phase narratives) and successor to
`docs/openssl-provider-remediation-plan-phase5-2026-08-26.md` (R22–R27,
all five active items executed; R27/XMSS parked by standing decision).

Phase 6 is a **closure phase**: after phases 3–5, 27 of the 28 tracked
gap-matrix items are RESOLVED or CLOSED. What remains is not new
algorithm surface — it is the tail: loose threads left inside
otherwise-resolved items, two stale rows in the audit document itself,
one unexplained investigation, and a disposition decision for
mechanisms that turned out to have no engine behind them. Every item
below was re-grounded against the current source tree while writing
this plan, not carried forward from prior summaries — and that
grounding itself corrected two claims the previous session-end gap
report made (see R28 and R32).

## Ground rules (carried forward from phases 4–5, unchanged)

- **Live-trace-confirm before fixing**: reproduce every suspected
  behavior via `PKCS11_PROVIDER_DEBUG` / engine logs before writing a
  fix; never patch from static reading alone.
- **R13 discipline**: every positive proof needs engine-log evidence of
  real token participation plus a negative-control twin. Hard
  propqueries (`provider=pkcs11`) for any algorithm whose name collides
  with a default-provider name (the R22/R26 lesson, learned twice).
- **`pkcs11-module-load-behavior = early`** in every new arena that
  fetches before creating a key object (WART-4; forgotten once per
  phase so far — check it first when a new case fails with
  `inner_evp_generic_fetch:unsupported`).
- **Sabotage-test every new proof**; full regression (C++ CTest,
  harness, Rust `cargo test` when `rust/` is touched) before each
  commit; one commit per R-item; append-only execution updates in this
  doc and the coverage audit.
- No push without explicit confirmation.

## Summary table

| # | Item | Origin | Effort | Type |
|---|---|---|---|---|
| R28 | Stale audit rows: F36-1 (R15 "unbuilt") + F36-3 (INIT_SKEY "still open") | doc drift, found while grounding this plan | S | doc-only |
| R29 | HSS follow-up bundle: Rust-arm harness twin, multi-process stateful-counter test, no-attrs fallback fixture | R9 parked halves, unblocked by R25 | M | tests (+ fixes if surfaced) |
| R30 | AEAD edge-case proofs: over-ceiling decrypt, AAD-only / empty-plaintext | R26's own "not done" list | S–M | tests (+ fixes if surfaced) |
| R31 | TLS13-KDF `derive_SKEY` mode-routing anomaly — bounded root-cause attempt | R24, investigated-not-root-caused | S–M | investigation |
| R32 | AES-CCM / OFB / CFB* disposition: no engine support exists — record, annotate dead provider code | R26's "not done" list + new grounding finding | S | disposition |
| R33 (PARKED) | OP-3 parity tier: ML-KEM SPKI/text public-key encoders | OP-3's own deliberate deferral | S–M | sketch only |
| R27 (PARKED) | XMSS/XMSS-MT | unchanged | — | see phase-5 plan |

Recommended execution order: **R28 → R30 → R29 → R31 → R32** (docs
first since they misinform anyone reading the audit today; then the
cheap tests guarding the newest code; then the HSS bundle; the
investigation and the disposition last since neither blocks anything).

---

### R28 — stale audit rows (F36-1, F36-3) — effort S

**Grounding (2026-08-26, this plan pass):** two gap-matrix rows in
`docs/openssl-provider-coverage-audit-2026-08-25.md` now contradict the
same document's own later narratives — both misled the previous
session-end gap report, which is how they were caught:

1. **F36-1** still says "server role (R15) remains unbuilt — tracked
   separately" (twice, including in its severity cell). R15 was fully
   executed in phase 4: `objects.c:4501`'s peer-share import,
   `keymgmt.c:3171/3264`'s parameters-only selection handling, and
   harness **T15** ("fully token-backed server: token-resident ML-DSA
   cert signs CertificateVerify AND token performs the ML-KEM
   encapsulation, both independently engine-log verified") all exist
   and pass today. The row predates R15's landing and was never
   updated.
2. **F36-3** still describes `mac.c`'s missing
   `OSSL_FUNC_MAC_INIT_SKEY` as "a separate, still-open gap … handed to
   R23". R23 executed (commit `26aeb98`): all three MAC families
   register `INIT_SKEY`, and harness **T26d** re-runs R24's own probe
   proving the previously-failing consume step now passes end to end.
   The row's own severity cell ("Low (consume-side gap tracked under
   R23)") is likewise stale.

**Work:** update both rows to their true current state, strikethrough
convention matching every other resolved row; F36-1's severity cell
drops its "(server role is R15)" qualifier; F36-3's drops the tracked-
gap qualifier. Doc-only — no code, no tests. This is the third
occurrence of the stale-row pattern (the first batch was fixed by
explicit user instruction on 2026-08-26); consider whether each future
R-item's checklist should include "grep the gap matrix for rows that
name this item" as a landing step — recorded here as a process
suggestion, not mandated.

**Proof plan:** none needed beyond re-reading the two rows against T15
and T26d in the current harness output.

---

### R29 — HSS follow-up bundle — effort M

Everything here was explicitly left open by R25's own execution update
and R9's original plan text; R25 removed the blocker (the provider now
reads the key's real parameter set instead of assuming the C++
default), so these are now pure test-wiring work — unless they surface
real bugs, which HSS items have done every single time so far.

**Grounding:** the Rust engine's HSS arm (`ffi.rs`
`CKM_HSS_KEY_PAIR_GEN` / `CKM_HSS`) generates with default
`CKP_LMOTS_SHA256_N32_W4` (2352-byte signatures), stores the official
`CKA_HSS_LEVELS`/`LMS_TYPE`/`LMOTS_TYPE` attrs since R25, and the
provider's `hss_sig_size_for_key()` computes W4's size correctly (the
same formula T24c already proves live against the C++ engine's
explicit-W4 keygen). The harness's Rust arm (`mk_rust_cnf`, T15a/T15b)
already shows the pattern for driving `libsofthsmrustv3.so` +
`SOFTHSMRUST_STATE_FILE` across processes.

**Work, in order:**

1. **T24d — Rust-arm HSS sign/verify twin.** Same shape as T24 but
   over `libsofthsmrustv3.so`: `genpkey -algorithm HSS`, sign with
   `-rawin`, assert size **2352** (Rust's own W4 default — the size
   assert is the point: it proves the provider read the real parameter
   set rather than assuming the C++ default's 1296), verify, both
   sabotage controls, then cross-implementation verify via
   `lms_xdr_verify` + a Rust-arm `hss_pubkey_dump` invocation. Note
   the test IDs: the phase-4/5 plans' own text called these "T24b/T24c"
   but both IDs are long taken (R24's EVP_SKEY guard, R25's W4 case) —
   use T24d/T24e, as R25's execution update already directed.
2. **T24e — multi-process stateful-counter test** (R9's original
   goal): with `SOFTHSMRUST_STATE_FILE` pointing at one state file,
   sign in two SEPARATE processes; assert the LMS leaf counter `q`
   advanced 0→1 (bytes 4–8 of the bare LMS signature, i.e. after
   stripping the 4-byte HSS `Nspk` prefix — the same strip
   `lms-xdr-verify.c` documents); assert the FIRST signature still
   verifies after the second signing. This is the one test that proves
   the stateful property that makes HSS dangerous to get wrong —
   nothing anywhere in the provider-facing test surface exercises
   state persistence across processes for HSS today.
3. **Fallback-path fixture test.** R25's fallback chain (official
   attrs → parse public `CKA_VALUE` → 1296 constant) has its first leg
   proven but the parse-from-`CKA_VALUE` leg only code-read. R25
   skipped it for want of a pre-standardization token fixture; build
   the fixture instead of waiting for one: a small extension of the
   raw-PKCS#11 tooling that `C_CreateObject`s a public HSS key object
   with `CKA_VALUE` = real exported pubkey bytes but WITHOUT the three
   official attrs, then verify a signature through the provider against
   it and (via debug trace or a size probe) confirm the size came from
   the parsed wire format, not the attrs. If `C_CreateObject` of a
   bare `CKK_HSS` public object hits engine template validation
   surprises, that is itself a finding — trace, don't force.
4. **(PARKED sub-item) multi-level L>1.** Both engines' keygen
   *accepts* L up to 8 (`ulLevels` validation in both), but nothing in
   this codebase has ever generated or signed with an L>1 key, and
   `hss_sig_size()`'s multi-level term — and, more importantly, both
   engines' own multi-level signing — is unexercised. Cross-
   implementation verification is also structurally harder at L>1
   (OpenSSL's native verifier is bare-LMS only; verifying the chain
   means parsing out intermediate signed pubkeys). Park with this
   sketch unless a consumer appears; do NOT silently extend T24d/e to
   L>1 without that verification story.

**Proof plan:** each new case follows T24/T24c's own structure (own
arena, sabotage twins, cross-implementation verify where reachable).
Regression: full harness both arms; `cargo test --release` if any
`rust/` source ends up touched (expected: none — but every prior HSS
item said that too).

**Execution update (2026-08-26):** all three items done, T24d/T24e/T24f
now permanent harness cases; the parked L>1 sub-item stays parked. Two
genuine, unrelated bugs surfaced along the way, plus one real bug this
work exists to find:

- **Test-infra bug 1 — `mk_rust_cnf` never actually set `SOFTHSM2_CONF`.**
  `softhsm2-util --init-token` is a C++-linked CLI binary that needs a
  real `SOFTHSM2_CONF` to complete its own config-loading startup,
  independent of which engine `.so` `--module` points it at. T15a/T15b
  only ever worked because, in a full harness run, an earlier C++-arm
  `use_arena()` call had left a real `SOFTHSM2_CONF` exported and never
  cleared — order-dependent and accidental, and it broke the moment
  T24d/T24e ran standalone. Fixed: `mk_rust_cnf` now also writes a real
  `softhsm2.conf`; every `softhsm2-util` invocation in `t15b`/`t24d`/`t24e`
  exports it explicitly.
- **Test-infra bug 2 — stale debug build of the Rust engine.** The
  harness's own `RUST_ENGINE_SO` auto-discovery prefers
  `/cargo-target/debug/libsofthsmrustv3.so` over the release build; only
  `cargo build --release` had been run after R25's own source fix, so
  the debug `.so` silently predated it and every default-discovery test
  was exercising pre-R25 Rust code. A plain `cargo build` (debug
  profile) picked up the fix; T24d passed immediately after.
- **Real bug — R29's own actual find, in `src/vendor/pkcs11-provider`,
  affects BOTH engines.** T24e (two signs in two separate processes,
  bridged only by `SOFTHSMRUST_STATE_FILE`) kept producing byte-identical
  signatures — `q1=0`, `q2=0` — even after both test-infra bugs above
  were fixed. Root cause, found by tracing `hbs::sign_commit` (confirmed
  it correctly advances `CKA_PRIV_LEAF_INDEX` on whatever handle it's
  given) and then `objects.c`'s `cache_key()`/`p11prov_obj_ref`: the
  vendored provider opportunistically caches a `CKA_TOKEN=FALSE`
  `C_CopyObject` clone of a token key the first time a session uses it
  (`cache_key`, `objects.c:368`), and every operation against that
  `P11PROV_OBJ` — including `C_Sign` — then targets the clone, not the
  original token object. For an ordinary key this is harmless (the copy
  is cryptographically identical and signing is idempotent). For a
  one-time-signature scheme it is not: the leaf-index advance-and-persist
  a stateful sign performs lands on the clone, which is session-scoped
  and vanishes with the session/process, never written back to the real
  token object. Every new process that re-resolves the same key by URI
  gets a fresh, still-unadvanced original and reuses the same leaf. This
  is provider-side, engine-agnostic code — confirmed it applies equally
  to the C++ engine (its own `C_CopyObject`, `SoftHSM_objects.cpp`, mints
  a fresh `CKA_UNIQUE_ID` session-object copy the same way) — it was
  simply never caught before because no test in this codebase, for
  either engine, had ever signed the same stateful key twice and checked
  the leaf actually advanced. R9's original goal (this exact proof) was
  never actually achieved for either engine until this item. Confirmed
  the OUID-generation mechanism itself is sound and consistent between
  engines (both correctly mint a fresh `CKA_UNIQUE_ID` on copy, per spec)
  — the defect is entirely in choosing to cache/sign against the copy at
  all for a stateful key type. Fix: `cache_key()` now skips caching for
  `CKK_HSS`/`CKK_XMSS`/`CKK_XMSSMT` (the latter two guarded pre-emptively;
  XMSS remains unimplemented per R27), so `C_Sign` always targets the
  real token object directly. Verified live: manual two-process repro
  now gives `q1=0`, `q2=1`, first signature still verifies after the
  second. Full regression after the fix: harness 76/76 (both arms,
  T24d/T24e/T24f all new and passing), C++ CTest 8/8, `cargo test
  --release` 410+ passed/0 failed. One commit for this item.

---

### R30 — AEAD edge-case proofs — effort S–M

Both items are from R26's own honest "not done" list; both guard
against exactly the class of silent misbehavior R26's four found-live
bugs exemplified. Test-first: write the probe, observe, fix only if it
fails.

**Work:**

1. **Over-ceiling decrypt fails cleanly.** `AEAD_DECRYPT_MAX_MSG_LEN`
   (65536, `cipher.h`) is asserted-from-reading only. Extend
   `aead-probe.c` (or add a flag) to encrypt a >65536-byte message
   (encrypt has no ceiling and must succeed), then attempt decrypt and
   assert it fails with a clean error — NOT a truncated-but-
   "successful" plaintext, NOT a crash. Also probe just-under and
   exactly-at the boundary (65535 / 65536 / 65537 plaintext bytes) —
   off-by-one in the interaction between the ceiling, the released-
   bytes split in `p11prov_cipher_aead_decrypt_final`, and the
   engine's own withheld-tail accounting is precisely where a bug
   would live. Run for both AES-256-GCM and ChaCha20-Poly1305.
2. **AAD-only and empty-plaintext.** The `final()`-with-no-session
   path (`ensure_session` invoked from `final()` when zero real
   `update()` calls happened) was written for this case but never
   executed. Probe: (a) empty plaintext + nonempty AAD, (b) empty
   plaintext + empty AAD, encrypt→decrypt→tag-tamper, both mechanisms.
   The engine side has its own opinion here too
   (`OSSLEVPSymmetricAlgorithm`'s AEAD buffering) — if the engine
   rejects zero-length single-shot AEAD, document that as the
   behavior and make the provider fail loudly rather than "fixing" the
   provider to fabricate something the token didn't authenticate.

**Proof plan:** new harness case(s) T27e (edges, both mechanisms —
one case, multiple sub-asserts, matching t25_case's parameterized
style). Sabotage where applicable. No doc-row changes (ALG-7 stays
RESOLVED; these are hardening proofs, and the audit's R26 narrative
already discloses the gaps — append the outcome there).

**Execution update (2026-08-26):** R30 executed and landed — see
`docs/openssl-provider-coverage-audit-2026-08-25.md`'s "Phase 6, R30"
entry for the full mechanism. Found the bug this section's own
"test-first" framing anticipated might exist, on the FIRST probe run:
a message at exactly the promised 65536-byte ceiling failed to
decrypt. Root cause: `AEAD_DECRYPT_MAX_MSG_LEN` was being used as both
the declared block_size and the promised usable ceiling, but both
mechanisms' own decrypt need one tag's worth (+16 bytes) of headroom
beyond the promise -- traced live via PKCS#11's own two-pass
CKR_BUFFER_TOO_SMALL convention, confirmed for both mechanisms (which
turned out to have genuinely different internal release shapes --
ChaCha20-Poly1305 releases at the tag-carrying DecryptUpdate,
AES-256-GCM at DecryptFinal instead -- same root cause, worth tracing
both rather than assuming). Fixed by splitting the constant into the
promise (`AEAD_DECRYPT_MAX_PLAINTEXT_LEN`, unchanged at 65536) and the
declared block_size (`+64` margin). New tool `aead-edge-probe.c`
(built once with AddressSanitizer -- found incompatible with the
provider's own RTLD_DEEPBIND dlopen flag for the engine .so, a known
sanitizer limitation, not a provider bug; fell back to the plain
build). New harness case T27e. Full regression: C++ CTest 8/8, Rust
not re-run (no rust/ touched), harness `PASS=73 FAIL=0` (one case
gained, zero regressions).

---

### R31 — TLS13-KDF `derive_SKEY` mode-routing anomaly — effort S–M (timeboxed)

**Grounding (unchanged from R24's write-up):** setting
`OSSL_KDF_PARAM_MODE` to `"EXTRACT_ONLY"` on a TLS13-KDF ctx reached
`p11prov_tls13_expand_label` (the EXPAND_ONLY branch) per live debug
trace; `EVP_KDF_derive_SKEY`'s core source was read to rule out param
reordering (params arrive unmodified). Root cause not found within
R24's probe-first budget; deliberately not chased because HKDF's
complete proof answered R24's actual question.

**Why revisit at all:** it is the only *unexplained* behavior left in
the provider. Unexplained ≠ unimportant: if the mode param is being
ignored, any future consumer of TLS13-KDF-via-SKEY would silently get
expand-label semantics regardless of what it asked for.

**Work (strictly bounded — one session-slice, then stop):**

1. Instrument `p11prov_tls13_set_ctx_params`'s mode-string branch and
   the derive dispatch with temporary `P11PROV_debug` lines (the R26
   DIAG pattern — added, used, stripped before commit); re-run R24's
   probe. The two leading hypotheses to kill first, cheapest first:
   (a) the probe's own params array ordering/lifetime (the R23/R26
   lesson: suspect the test before the provider), (b) the mode string
   being parsed into the ctx correctly but the derive path reading a
   different field than set_ctx_params wrote (the classic split-brain
   ctx bug, same family as R26's IVLEN chicken-and-egg).
2. If root-caused: fix, extend `skey-flow-probe.c`'s TLS13-KDF check
   from existence-only to mode-verified, note in F36-3's row.
3. If NOT root-caused within the timebox: append the additional
   evidence to the audit's existing "investigated, not pursued" entry
   and close the item as documented-unexplained. Do not let it absorb
   a second session — precedent: ALG-6/R17.

**Execution update (2026-08-26):** root-caused within the first probe
pass — there was never a mode-routing bug. `P11PROV_debug` tracing
added at `p11prov_tls13_kdf_derive_skey`'s mode switch (kdf.c:676)
showed `hkdfctx->mode` correctly read `EXTRACT_ONLY` and the switch
correctly took the `EXTRACT_ONLY` case — hypothesis (b), a split-brain
ctx bug, is dead. But the live trace then showed
`p11prov_tls13_expand_label` being called anyway, immediately followed
by `EVP_KDF_derive_SKEY` returning NULL. Reading
`p11prov_tls13_derive_secret()` (the `EXTRACT_ONLY` implementation)
explains why: TLS 1.3's own Derive-Secret construction (RFC 8446 §7.1)
is *itself* built from HKDF-Expand-Label — the function legitimately
calls `p11prov_tls13_expand_label()` internally to turn the caller's
salt into a derivation key, regardless of which top-level mode the
caller requested. R24's original read of "reached
`p11prov_tls13_expand_label`, the EXPAND_ONLY branch" (line 292-293 of
this item's own grounding, above) mistook this legitimate internal
sub-call for evidence of the wrong top-level branch running — the two
are unrelated. Hypothesis (a) from the work list was the real one, but
not quite as framed: not the probe's params array ordering/lifetime,
but a genuine **missing** param. `p11prov_tls13_expand_label()`
unconditionally requires a non-empty prefix+label pair (part of the
RFC 8446 `HkdfLabel` wire format) and `skey-flow-probe.c`'s own
TLS13-KDF params never supplied `OSSL_KDF_PARAM_PREFIX`/
`OSSL_KDF_PARAM_LABEL` — its own header comment explicitly (and,
per this finding, wrongly) claimed `EXTRACT_ONLY` didn't need them.
**No provider fix needed — the provider's rejection of a NULL
prefix/label was correct behavior.** Fixed the probe instead: added
TLS 1.3's own real "tls13 " prefix and "derived" label (the exact pair
used between the Early and Handshake Secret stages of the actual key
schedule), which took check 3 from "derive_SKEY returns NULL" all the
way to a full derive → token-resident-key → `EVP_MAC_init_SKEY` chain,
genuinely mode-verified now rather than existence-only. F36-3's row
gets its own correction below (the item was never really a routing
bug, so there is nothing to leave open). Regression: harness 76/76,
C++ CTest 8/8; no `rust/` source touched, `cargo test` not re-run.
Stayed well inside the timebox — root cause found in the first
instrumented run, no second session needed.

---

### R32 — AES-CCM / OFB / CFB* disposition — effort S

**New grounding finding (2026-08-26, this plan pass) — this reframes
the item entirely:** the previous session-end gap report listed
"AES-CCM still unregistered" and "AES-OFB/CFB* still a TODO stub" as
if they were provider work waiting to happen. Checked against both
engines: **neither engine implements any of them.**
`SoftHSM_cipher.cpp`'s symmetric dispatch handles exactly
ECB/CBC/CBC_PAD/CTR/GCM/CHACHA20/CHACHA20_POLY1305 — no
`CKM_AES_CCM`, `CKM_AES_OFB`, or `CKM_AES_CFB*` anywhere in the C++
engine; the Rust engine has no trace of them either. A provider
registration would route to `CKR_MECHANISM_INVALID`. The provider's
"gaps" here are therefore *honest*: the OFB/CFB `/* TODO */` stub and
CCM's unreachable dispatch tables front mechanisms that do not exist
behind them.

**Work (disposition, not implementation):**

1. Record the finding in the coverage audit (a short addendum row or
   note in section B: "CCM/OFB/CFB — no engine support in either
   engine; provider stub/dead-tables are honest; implementing would be
   an ENGINE feature request first, provider second").
2. Annotate the two provider sites so the next reader doesn't repeat
   this plan's own initial mistake: the OFB/CFB* `/* TODO */` case in
   `p11prov_cipher_prep_mech` gains a comment saying the engines don't
   implement these (so finishing the stub is pointless without engine
   work), and CCM's `DISPATCH_TABLE_CIPHER_FN(aes, *, ccm, ...)` block
   gains the same note. **Recommendation: annotate, don't delete** —
   stripping the dead CCM tables/`case` arms would churn vendored code
   for zero behavior change and create upstream-diff noise; the
   comments carry the knowledge at near-zero risk. (If the user
   prefers deletion, it is mechanical: the three CCM dispatch tables,
   their `cipher.h` externs, the `provider.c` case, and the
   `p11prov_aes_settable_ctx_params` CCM arm.)
3. If anyone ever wants these for real: the correct sequencing is
   engine first (both engines, with the engine's own test suites),
   provider second reusing R26's now-proven shared AEAD machinery for
   CCM — noting CCM's extra wrinkle that PKCS#11's `CK_CCM_PARAMS`
   needs the total data length up front, which collides with the
   streaming EVP API even harder than GCM's AAD timing did.

**Proof plan:** none (no behavior change). Regression run anyway
before commit, per ground rules, since comments touch compiled files.

**Execution update (2026-08-26):** disposition confirmed by the user
(asked via the plan's own recommendation — "Annotate, don't delete") —
executed as written, no deviation. Annotated both provider sites in
`cipher.c`: the OFB/CFB* `/* TODO */` case in `p11prov_cipher_prep_mech`
now states neither engine implements these mechanisms; the three CCM
`DISPATCH_TABLE_CIPHER_FN` entries get the same note plus the
`CK_CCM_PARAMS`/streaming-API wrinkle for any future implementer.
Coverage audit's own "What remains" note (R26's section) and F-row
narrative updated to point at this item rather than describing CCM/
OFB/CFB* as open provider work. No behavior change — comment-only.
Regression: harness 76/76; C++ CTest 8/8 (one `p11_v32_compliance`
failure on the first post-edit run reproduced as pre-existing test
flakiness, not a regression — a comment-only diff cannot change
runtime behavior, and two clean reruns both came back 8/8). No `rust/`
source touched. One commit for this item — the last of phase-6's
active work; R33 and R27 stay parked per the plan.

---

### R33 (PARKED) — OP-3 parity tier: ML-KEM public SPKI/text encoders — sketch only

OP-3's core (private-key URI-PEM encoder) landed in phase 3; the row
itself deliberately scoped out "SPKI/text encoders for public keys"
as a non-functional parity tier: public-key output already works via
the keymgmt EXPORT bridge into the default provider. The parity tier
would only matter in a `DISALLOW_EXPORT_PUBLIC`-style configuration
(where the bridge is blocked) or for cosmetic `-text` parity with the
other PQC families. No consumer needs it today. If picked up: mirror
`encoder.c`'s ML-DSA public SPKI/text encoder pair for the three
ML-KEM variants — the pattern is established, effort S–M, risk low.
Parked until a configuration that blocks the bridge actually appears
in this project.

---

### R27 (PARKED) — XMSS/XMSS-MT

Unchanged; see the phase-5 plan's own R27 sketch. Nothing in phase 6
alters its calculus, except one addition from R26's experience: if it
is ever triggered, the shared-cipher-machinery lesson applies —
budget for `sig/xmss.c` to REUSE `sig/hss.c`'s accumulate-then-
single-C_Sign shape directly rather than copying it, the same way
`chacha.c` reuses `cipher.c`'s entry points, so the two stateful-
signature families can't drift.
