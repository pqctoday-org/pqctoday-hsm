# Provider-Layer Coverage Remediation Plan — JavaJCE + OpenSSL provider

**Date:** 2026-08-30 (revised same day — see §0 and §3 for what changed and why)
**Supersedes/extends:** WS-10 in `docs/remediation-plan-pkcs11-v32-coverage-2026-08-29.md`, which checked both providers against only 4 engine-level fixes. This document re-verifies those 4 and adds 7 new items surfaced by today's Rust WS-8 mechanism work.
**Status:** PLAN ONLY — nothing in this document has been executed. The *engine-side* work it depends on (`fix/ws1-4-and-ws2-rust-gaps`) is now fully committed locally (HEAD `fe88c79`, includes a CHANGELOG entry and `docs/remediation-plan-rust-pkcs11-v32-gaps-2026-08-30.md` as evidence) — stable and unpushed, ready to be a merge input whenever Q-0 below happens, but still not merged anywhere.

## 0. Branch topology — read this before touching anything

Provider-layer gaps here are computed across **three branches that have each diverged from a common ancestor in a different direction**, not one working tree, and not a simple two-line "engine vs. providers" split. An earlier draft of this document got this wrong (see §3) — the corrected picture:

| Branch (all local, unpushed except `main`) | What's actually current there |
|---|---|
| `main` (published baseline) | Has `85f0cd8` (#189: `CKM_*_HMAC_GENERAL`, `CKM_AES_KEY_WRAP_KWP` engine dispatch) and `7a8b4d7` (#190: RSA-OAEP hash selection, `CK_EDDSA_PARAMS` context/prehash, private-key sensitivity) already merged. Does **not** have WS-8 (GMAC/CCM/XTS/OFB/CFB/Double-Pipeline-KDF/EC-extra-bits) at all, in either engine. |
| `fix/ws1-4-and-ws2-rust-gaps` (this worktree, HEAD `fe88c79`) | `main`'s baseline **plus** today's WS-0 through WS-8 execution: C++ gained GMAC/CCM/XTS/OFB/CFB/Double-Pipeline-KDF first (commits `35cc156`/`0763e59`/`bec7ada`, 13:57–14:19 today), then the Rust engine was brought to parity with those *same-day* C++ additions, plus `CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS` (Rust-only), plus the exhaustive FIPS 203/204/205 cross-engine differential verification. **Every WS-8 mechanism on this list exists on this one branch only** — confirmed via `git log -S` and `git branch --contains` — not on `main`, not on `feat/jdk27-jca-provider`, not anywhere else. |
| `feat/jdk27-jca-provider` (63 commits ahead of an *older* `main` snapshot, but **2 behind current `main` — missing exactly `85f0cd8`/`7a8b4d7`**) | The real, current JavaJCE provider (WS-A–D) and the real, current OpenSSL provider (phase-7/8, items R8–R41), built on a C++ engine that **predates #189/#190**. Confirmed directly: `git show feat/jdk27-jca-provider:src/lib/SoftHSM_sign.cpp` has zero `OAEP`, zero `phFlag`/`contextData`, zero `HMAC_GENERAL` hits, and `CKM_AES_KEY_WRAP_KWP` exists only as an unused header `#define`. See §3.2 — this means two of this document's "already done" verdicts are provider-complete but engine-incomplete *on this exact branch as it stands*. **This worktree's own `JavaJCE/` and `src/vendor/pkcs11-provider/` directories are stale, older-`main`-level copies** — every provider-layer finding below was read via `git show feat/jdk27-jca-provider:<path>`, not the working tree. |

**No branch has the newest engine mechanisms, the `main`-baseline engine fixes, and the newest provider code all together.** `feat/jdk27-jca-provider` needs at minimum a rebase onto current `main` before its own §1 "done" verdicts are true end-to-end — independent of ever picking up WS-8. Picking up WS-8 itself is a second, separate merge (`fix/ws1-4-and-ws2-rust-gaps` onto whatever `feat/jdk27-jca-provider` becomes after that rebase). A provider patch written against this worktree's stale `JavaJCE`/`pkcs11-provider` copies would silently regress WS-A–D and R8–R41.

Both providers are engine-agnostic at the code level (JavaJCE loads whichever `.so`/`.dylib` `PKCS11_MODULE` points at; the OpenSSL provider is a generic PKCS#11-backed OpenSSL provider) — a mechanism gap is a JCA/OpenSSL registration question, independent of which of the two engines a given deployment runs, *provided* the engine it's actually pointed at has the mechanism. §3.2 is exactly a case where that proviso fails.

---

## 1. Re-verification of WS-10's original 4 items

| Mechanism | JavaJCE (`feat/jdk27-jca-provider`) | OpenSSL provider (`feat/jdk27-jca-provider`) |
|---|---|---|
| `CKM_*_HMAC_GENERAL` | **Still open.** `P11MacSpi.engineInit` throws on any non-null param (`P11MacSpi.java:44-48`); only 8 fixed-length `Hmac*` `Mac` services registered (`SoftHSMv3Provider.java:801-808`). | **Fixed since** (item R8, commit `514e1dc`) — real `mac.c`, `case OSSL_OP_MAC:` at `provider.c:1955`. R23 (`26aeb98`) extended the same file to CMAC and KMAC-128/256. |
| `CKM_AES_KEY_WRAP_KWP` | **Still open.** Only `"AESWrap"`/`"AESWrapPad"` registered (`SoftHSMv3Provider.java:786-787`); `P11Constants.java:54-55` has no `_KWP` constant. | **Still open, untracked.** `CKM_AES_KEY_WRAP_KWP` exists only as a `pkcs11.h` `#define` and a `debug.c` log-name string — zero hits in `checklist[]`, `cipher.c`, or `skeymgmt.c`. |
| `CK_EDDSA_PARAMS` (context/prehash) | **Still open**, and confirmed unrelated to WS-D's "pre-hash ML-DSA/SLH-DSA disposition" commit — that commit's own javadoc scope never mentions EdDSA. `P11PureSigSignatureSpi.engineSetParameter` throws on any non-null param (`:112-116`). | **Provider code done, engine underneath it isn't — see §3.2.** `sig/eddsa.c:261-277,328-336` builds `phFlag`/`pContextData` from real `OSSL_SIGNATURE_PARAM_CONTEXT_STRING`, but `feat/jdk27-jca-provider`'s own C++ engine has zero `phFlag`/`contextData` dispatch to receive it. |
| RSA-OAEP hash selection | **Never was a gap.** 6 `registerRSAOAEP` calls, SHA-256/384/512 + SHA3-256/384/512 (`SoftHSMv3Provider.java:751-756`). | **Provider code done, engine underneath it isn't — see §3.2.** Fully dynamic both directions (`asymmetric_cipher.c:526-536,642-654`), but `feat/jdk27-jca-provider`'s own C++ engine has zero `OAEP` hits in `SoftHSM_sign.cpp` to act on it. |

---

## 2. New gaps — WS-8 mechanism parity (all same-day, single-branch work; both providers lag an engine state that itself doesn't exist anywhere else yet)

**Correction from this document's first draft:** these six mechanisms are not long-standing C++ features. All six were added to the C++ engine *earlier today* (commits `35cc156`/`0763e59`/`bec7ada`, 13:57–14:19), on this one branch, and Rust was brought to parity with them roughly an hour later the same day — see §3.1. Neither provider has ever had a chance to expose any of them; there is no live regression here, because nothing outside `fix/ws1-4-and-ws2-rust-gaps` has ever been able to see these mechanisms. This changes the urgency framing (§5) but not the registration facts below, which were independently grounded against the actual `feat/jdk27-jca-provider` provider source.

| # | Mechanism | JavaJCE | OpenSSL provider |
|---|---|---|---|
| 1 | `CKM_AES_GMAC` (bare MAC) | **Not registered.** Zero "GMAC" hits across all JavaJCE sources; `Mac` services are `Hmac*`/`KMAC128/256`/`AESCMAC` only. | **Not implemented.** `mac.c`'s `MAC_ALGO_*` enum has HMAC/CMAC/KMAC128/256 only; not in `checklist[]`. Engine side is real as of today (`OSSLGMAC.cpp`) — this is a live, currently-reachable gap. |
| 2 | `CKM_AES_CCM` | **Not registered.** `P11AESCipherSpi.Mode` enum has `{GCM, CBC, CBC_PAD, CTR}` only; no `CK_CCM_PARAMS` builder. | **Dead registration.** `CKM_AES_CCM` is absent from `AES_MECHS` (`provider.c:873-882`) so its `ADD_ALGO` block (`:1471-1475`) can never fire; even if reached, `p11prov_cipher_prep_mech()` has no `CKM_AES_CCM` case at all. R32's inline comment ("neither engine implements CCM") is **stale** — C++ gained real `CK_CCM_PARAMS` handling today (`SoftHSM_cipher.cpp:229-266,1050-1086`). |
| 3 | `CKM_AES_XTS` / `CKM_AES_XTS_KEY_GEN` | **Not registered, full stack absent.** No `CKK_AES_XTS` constant; `P11AESKeyGeneratorSpi` hardcodes 128/192/256-bit sizes and `CKK_AES` — structurally cannot produce a double-width XTS key. | **Not implemented.** `CKM_AES_XTS`/`_KEY_GEN`/`CKK_AES_XTS` exist only as constants/debug strings; zero hits in `checklist[]`, `cipher.c`, `keymgmt.c`, `skeymgmt.c` (which only imports `CKK_AES`). |
| 4 | `CKM_AES_OFB`/`CFB8`/`CFB128`/`CFB1` | **Not registered**, all 4. Same `Mode` enum gap as CCM. Cheapest of the AES gaps — IV handling JavaJCE already has for CBC/CTR is mode-agnostic. | **Registered but explicitly stubbed.** In `checklist[]`/`AES_MECHS` and `operations_init()`'s dispatch — but `p11prov_cipher_prep_mech()` explicitly `return CKR_MECHANISM_INVALID` for all four, citing the same now-stale "neither engine implements this" premise. C++ gained real OFB/CFB1/CFB8/CFB128 today (`SoftHSM_cipher.cpp:62-65,197-227,1018-1044`). |
| 5 | `CKM_SP800_108_DOUBLE_PIPELINE_KDF` | **Not registered.** `P11SP800108SecretKeyFactorySpi`'s mode selector is a 2-way `boolean feedback` field — no third state; only `"SP800-108-Counter"`/`"-Feedback"` registered. | **Not implemented — and see §3 below.** `kdf.c`'s mode-string switch has `COUNTER`/`FEEDBACK` only; an explicit `else` branch rejects `DOUBLE_PIPELINE`. |
| 6 | `CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS` (Rust-only — FIPS 186-5 App. A.2.2, P-256/384/521; confirmed zero hits in `src/lib/` outside `pkcs11t.h`) | **Not registered.** `P11ECKeyPairGeneratorSpi.generateKeyPair()` hardcodes plain `CKM_EC_KEY_PAIR_GEN`; no alternate mechanism path exists. | **Not implemented.** Not in `checklist[]`; `p11prov_ec_gen_init()` hardcodes plain `CKM_EC_KEY_PAIR_GEN` (`keymgmt.c:1327`). |

### Item 7 (JavaJCE only) — HMAC PRF coverage for HKDF/SP800-108

Rust's HKDF/SP800-108 dispatch fix (today) added honest recognition (reject instead of silently substituting SHA-256) for `CKM_SHA_1_HMAC`, `CKM_SHA224_HMAC`, `CKM_SHA512_224_HMAC`, `CKM_SHA512_256_HMAC`, `CKM_SHA3_224_HMAC`, `CKM_SHA3_384_HMAC` as PRF selectors. JavaJCE's SP800-108 `PRF_NAMES` map has `HmacSHA224/256/384/512` + SHA3-224/256/384/512 + AESCMAC — **missing `HmacSHA1`, `HmacSHA512/224`, `HmacSHA512/256`** (3 of the 6). The underlying `CKM_SHA_1_HMAC`/`CKM_SHA512_224_HMAC`/`CKM_SHA512_256_HMAC` constants don't exist in `P11Constants.java` at all. HKDF's own 3-name limit (`HKDF-SHA256/384/512`) is a JDK 27 `javax.crypto.KDF` API ceiling (JEP 478), not a JavaJCE-side omission — noted for context, not counted as the same class of gap.

### Item 8 — exhaustive ML-KEM/ML-DSA/SLH-DSA parameter-set coverage

**Clean bill of health on both providers.** JavaJCE registers all 3 ML-DSA, all 12 SLH-DSA, all 3 ML-KEM parameter sets as distinct `KeyPairGenerator`/`Signature`/`KEM` services (`SoftHSMv3Provider.java:609-624,695-721,1025-1040`). The OpenSSL provider likewise wires all 3+12+3 through `keymgmt`/`sig`/KEM-op/encoder-decoder (`provider.c:1305-1392,1802-1882`). No parameter set is missing on either side.

---

## 3. Two corrections made to this document's own first draft

Both were caught by independently re-verifying claims against `git log`/`git blame`/`git show` instead of trusting a single grep or a provider's own inline comment. Recorded here in full, retraction included, rather than silently fixed, because both are exactly the kind of error that compounds if carried forward unflagged.

### 3.1 — the Double-Pipeline "correction" in the first draft was itself wrong, and backwards

The first draft of this document overruled the OpenSSL-provider sub-agent's finding that `kdf.c`'s comment — "the engine implements only Counter and Feedback" — was honest and current. The overrule was based on grepping `src/lib/SoftHSM_keygen.cpp` **in this worktree** and finding a real `CKM_SP800_108_DOUBLE_PIPELINE_KDF` implementation (`:2862`, `:3884-4113`), and concluding the provider's comment must be stale.

That grep was real, but the conclusion drawn from it wasn't checked against *which branch* introduced that code. Re-verified with `git log --oneline --all -S "CKM_SP800_108_DOUBLE_PIPELINE_KDF" -- src/lib/SoftHSM_keygen.cpp` and `git branch --all --contains <that commit>`:

```
35cc156  2026-08-30 13:57  Close SP800-108/HKDF gaps with real evidence; add 5 WS-8 cipher mechanisms
  → exists on fix/ws1-4-and-ws2-rust-gaps ONLY
```

`git show main:src/lib/SoftHSM_keygen.cpp | grep -c CKM_SP800_108_DOUBLE_PIPELINE_KDF` → **0**. `git show feat/jdk27-jca-provider:src/lib/SoftHSM_keygen.cpp | grep CKM_SP800_108_DOUBLE_PIPELINE_KDF` → **0 matches**. The same is true of GMAC/CCM/XTS/OFB/CFB (`OSSLGMAC.cpp`/`.h` are new files with an empty diff between `main` and `feat/jdk27-jca-provider`, but 182/40 new lines between `main` and this branch).

**Retraction:** the provider's `kdf.c` comment was accurate for any codebase state anyone besides this one branch could actually see. The first draft's "correction" had it backwards — it mistook same-day, single-branch work for an established feature the provider had simply neglected. §2's mechanism table and §5's phase ordering have been updated to reflect this (Double-Pipeline is no longer "no engine work needed" with elevated urgency — see §5, Q-2 is now correctly scoped).

### 3.2 — a real gap this document's first draft missed entirely: `feat/jdk27-jca-provider` predates `main`'s own #189/#190

Checking whether `feat/jdk27-jca-provider` is fully caught up to `main` (it isn't — 2 commits behind) surfaced that the 2 missing commits are exactly `85f0cd8` (#189: `CKM_*_HMAC_GENERAL`, `CKM_AES_KEY_WRAP_KWP`) and `7a8b4d7` (#190: RSA-OAEP hash selection, `CK_EDDSA_PARAMS`, private-key sensitivity). Direct confirmation against `feat/jdk27-jca-provider`'s own C++ source:

```
git show feat/jdk27-jca-provider:src/lib/SoftHSM_sign.cpp | grep -n OAEP                    → 0 hits
git show feat/jdk27-jca-provider:src/lib/SoftHSM_sign.cpp | grep -n "phFlag\|contextData"    → 0 hits
git show feat/jdk27-jca-provider:src/lib/SoftHSM_sign.cpp | grep -n HMAC_GENERAL             → 0 hits
CKM_AES_KEY_WRAP_KWP on that branch                                                          → header #define only, no dispatch anywhere in src/lib/
```

The OpenSSL provider's own code (`asymmetric_cipher.c`, `eddsa.c`) is real and complete, as §1 already documents — but on `feat/jdk27-jca-provider` as it currently stands, that code has no engine dispatch to act on. Sending a non-default OAEP hash or an EdDSA context string to *that branch's own C++ build* would hit an engine that never receives or honors those params. §1's table now marks both rows accordingly instead of "nothing to do."

---

## 4. Fix sketches (no code written — sizing only)

| Item | JavaJCE | OpenSSL provider |
|---|---|---|
| HMAC_GENERAL | Reuse the parameterized-mechanism path already proven for RSA-PSS (`P11Library.java:481`) with a `CK_MAC_GENERAL_PARAMS`-shaped param object; extend `P11MacSpi.engineInit` to accept it. Small–moderate. | — (already done) |
| AES_KEY_WRAP_KWP | Add constant + one `registerAESWrap(...)` call. Trivial. | Add to `checklist[]` + a `skeymgmt.c` wrap/unwrap path. Not yet sized upstream — no R-item exists for it; needs one. |
| `CK_EDDSA_PARAMS` | New params class (JDK has no standard one), new Ed25519ph/ctx/Ed448ph signature variants, wire through the existing parameterized-mechanism path. The one genuinely architectural JavaJCE item. | — (already done) |
| `CKM_AES_GMAC` | Register a `Mac` service on `P11MacSpi`'s existing single-shot pattern (mirrors `"AESCMAC"`); extend `engineInit`'s param handling for the IV, shared with HMAC_GENERAL's fix. | Add `checklist[]` entry + `MAC_ALGO_GMAC` in `mac.c` binding OpenSSL's `EVP_MAC` "GMAC" (cipher+IV, no plaintext); `ADD_ALGO(GMAC, gmac, mac, prop)`. |
| `CKM_AES_CCM` | Add constant + `CK_CCM_PARAMS` builder in `P11Library` (same shape as the GCM/RSA-PSS builders); new `Mode.CCM` case; register `"AES/CCM/NoPadding"`. | Add to `AES_MECHS`; real `case CKM_AES_CCM:` in `p11prov_cipher_prep_mech()` building `CK_CCM_PARAMS` from `OSSL_PARAMS` — note CCM needs total-length-up-front, unlike GCM's streaming AAD. |
| `CKM_AES_XTS`/`_KEY_GEN` | Add `CKK_AES_XTS`/mechanism constants; extend or fork the AES `KeyGenerator` to accept 256/512-bit sizes tagged `CKK_AES_XTS`; new `Mode.XTS` with a tweak/IV param. | Add to `checklist[]`/`AES_MECHS`; cipher dispatch mirroring the CTR pattern; `skeymgmt.c` double-length key import path. |
| `CKM_AES_OFB`/`CFB*` | 4 mechanism constants, 4 `Mode` values + matching builders in `P11Library` (mirror `mechCbc`/`mechCtr`), 4 `registerAESCipher` calls. Cheapest item in the set. | Remove the `CKR_MECHANISM_INVALID` stub; add real per-mode 16-byte-IV cases — dispatch tables already exist, only `prep_mech`'s param construction is missing. Second-cheapest item (registration already done). |
| `CKM_SP800_108_DOUBLE_PIPELINE_KDF` | Add constant + third `mechSp800108DoublePipeline` builder (mirrors the counter/feedback builders at `P11Library.java:952-980`); widen the 2-way boolean to a 3-way selector. | Extend `kdf.c`'s mode-string switch (`:1533`) with a `DOUBLE_PIPELINE` branch + matching `CK_SP800_108_*_PARAMS` construction (pattern already at `:1762`+ for Feedback). No engine work needed — §3 correction. |
| `CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS` | New JavaJCE-specific marker `AlgorithmParameterSpec` (wrapping `ECGenParameterSpec` + a flag), recognized in `initialize()`, routed to a mechanism-selection branch. | Add to `checklist[]`; branch `p11prov_ec_gen_init()` on a new settable param (P-256/384/521 + extra-bits request). |
| HMAC PRF coverage (item 7) | Add 3 constants (`CKM_SHA_1_HMAC`, `CKM_SHA512_224_HMAC`, `CKM_SHA512_256_HMAC`) + 3 `PRF_NAMES` map entries. Trivial — JavaJCE's own javadoc already notes this factory has no standard JCA name to hang off, so it's freely extensible. | Not separately raised by the OpenSSL-provider audit; same-shaped fix if pursued (extend whatever PRF-name table `kdf.c`'s Counter/Feedback paths already use). |

---

## 5. Recommended execution order

| Phase | Contents | Rationale |
|---|---|---|
| **Q-0a** | Rebase `feat/jdk27-jca-provider` onto current `main` (picks up `85f0cd8`/`7a8b4d7`). | Required before §1's RSA-OAEP-hash and `CK_EDDSA_PARAMS` "done" verdicts are true end-to-end — see §3.2. Independent of WS-8; do this even if WS-8 is deferred. |
| **Q-0b** | Merge or rebase `fix/ws1-4-and-ws2-rust-gaps` onto the result of Q-0a. | Nothing in §2 can be built otherwise — see §0. `fix/ws1-4-and-ws2-rust-gaps` is the only place any WS-8 mechanism exists, in either engine. |
| **Q-1** | Correct the stale `kdf.c`/`cipher.c` inline comments (R32's CCM/OFB/CFB annotations, and `kdf.c`'s Double-Pipeline comment, per §3.1) to reflect the engine's actual current state **after Q-0b**, not before. | Cheap, prevents the same staleness from propagating into whoever picks up Q-2 — and per §3.1, these comments are accurate until Q-0b actually lands. |
| **Q-2** | OpenSSL provider: `CKM_AES_OFB`/`CFB*` (registration already exists, only `prep_mech` is missing) and `CKM_SP800_108_DOUBLE_PIPELINE_KDF` (engine work already done, on the branch Q-0b brings in). | Cheapest real fixes once Q-0b lands — dispatch scaffolding already in place on both, and neither needs new engine work beyond the merge itself. |
| **Q-3** | JavaJCE: `CKM_AES_OFB`/`CFB*`, HMAC PRF coverage (item 7), `CKM_AES_KEY_WRAP_KWP`. | Small, mechanical, reuse existing patterns 1:1. |
| **Q-4** | Both providers: `CKM_AES_GMAC`, `CKM_AES_CCM`. | Moderate — real AEAD/MAC param-block construction, but existing GCM/CMAC code is a close structural template on both sides. |
| **Q-5** | Both providers: `CKM_AES_XTS`/`_KEY_GEN`. | Largest of the AES items — needs new key-generation shape (double-width key), not just cipher dispatch. |
| **Q-6** | Both providers: `CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS`. | Rust-only engine feature; lowest urgency since it has no C++ counterpart to create asymmetric provider/engine coverage today. |
| **Q-7** | JavaJCE: `CKM_*_HMAC_GENERAL`, `CK_EDDSA_PARAMS` context/prehash. | The two carried-forward WS-10 items still open on JavaJCE; `CK_EDDSA_PARAMS` is the one genuinely architectural item in the whole plan (new params class, no JDK standard to reuse). |
| **Q-8** | OpenSSL provider: `CKM_AES_KEY_WRAP_KWP`. | Carried-forward WS-10 item, still untracked upstream — needs its own R-item opened, not just code. |

---

## 6. Acceptance criteria

- Every item in §2 and the still-open rows of §1 has either a registered JCA `Service` (JavaJCE) or a `checklist[]` entry with real (non-stub) dispatch (OpenSSL provider), verified by the same kind of file:line evidence this document cites — not by trusting either provider's own inline comments without independently re-checking the engine source, per §3.
- Whichever merge/rebase resolves §0 must re-run both providers' existing test suites (JavaJCE's live-TLS and zeroization tests from WS-B/C; the OpenSSL provider's `tests/`) plus the cross-engine differential harness (`scripts/run-differential-harness.sh`) before any item here is marked done, so a provider fix built against one engine is confirmed reachable through the other too.
