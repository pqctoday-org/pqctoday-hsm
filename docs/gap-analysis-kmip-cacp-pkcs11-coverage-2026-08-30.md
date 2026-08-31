# KMIP / TTLV / CACP coverage vs. the latest PKCS#11 C++ and Rust work — gap analysis (2026-08-30)

Read-only audit. No code changed. Verified against source, not against any
prior doc's prose.

**Question asked:** does the KMIP 3.0 server (protocol ops + TTLV wire
encoding) and the CACP crypto-agility policy engine actually *cover* — can
represent, dispatch, and gate — the mechanisms the PKCS#11 C++ and Rust
engines have most recently gained or fixed?

## 0. What "latest PKCS#11 update" means here

Two generations of recent engine work, confirmed against git history, not
memory:

- **Already merged to `origin/main`** (`e2a644f`, via PR #191 which itself
  is docs-only): PR #187 (CACP modular policies, `ee7f9aa`), #188 (WS-11
  v3.2 conformance gaps, `dea9bfa`), #189 (`CKM_*_HMAC_GENERAL` × 11 on C++
  / × 5 on Rust, `CKM_AES_KEY_WRAP_KWP` on C++, `85f0cd8`), #190 (RSA-OAEP
  hash selection, EdDSA `CK_EDDSA_PARAMS` context/prehash, private-key
  sensitivity check, `7a8b4d7`).
- **Real code, committed but not pushed/merged**, on branch
  `fix/ws1-4-and-ws2-rust-gaps` (worktree `.worktrees/ws1-4-and-ws2`,
  merge-base `7a8b4d7`): the WS-8 mechanism set on **both** engines —
  `CKM_AES_GMAC`, `CKM_AES_CCM`, `CKM_AES_XTS`(+`_KEY_GEN`/`CKK_AES_XTS`),
  `CKM_AES_OFB`, `CKM_AES_CFB128/8/1`, `CKM_SP800_108_DOUBLE_PIPELINE_KDF`,
  plus a Rust-only `CKM_HKDF_DERIVE` silent-SHA-256-substitution fix and
  `CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS` (Rust only; not yet done on C++ on this
  branch). `CKM_ECMQV_DERIVE` is deliberately held on both engines pending
  MQV-combiner assurance beyond KAT-passing.
- Separately, branch `fix/acvp-hmac-general-aes-kwp` (pushed to origin, not
  merged) is confirmed to be the pre-squash source already absorbed as
  PR #189 — mentioned only because it's easy to mistake for unmerged work.

**Update, 2026-08-30 (same day, later):** `fix/ws1-4-and-ws2-rust-gaps` is
now feature-complete and closed out with a final changelog commit
(`fe88c79`) — 44 commits vs. `main` (worktree `.worktrees/ws1-4-and-ws2`),
not merged to `main` or pushed. It turns out to be the **full** WS-0
through WS-8 remediation, not just the WS-8 mechanism subset this document
originally scoped — it also absorbs `fix/ws0-evidence-integrity`'s commits
and adds WS-6.2/6.3 (C++ catching up to mechanisms Rust already had):
`CKM_SHA{256,384,512,3_256,3_384,3_512}_KEY_DERIVATION` (6 mechanisms) and
`CKM_SHA512_224`/`CKM_SHA512_256` digests. A quick check (grepped
`kmip/src/` on this worktree) found these are **also** completely absent
from the KMIP crate — zero hits for `KEY_DERIVATION`, `SHA512_224`, or
`SHA512_256` anywhere in `kmip/src/kmip30/algos.rs`, `kmip/src/ops/*.rs`,
or `kmip/src/policy/rule.rs`. Same failure shape as item 6 below. Added as
items 10-11.

This document treats **all of the above as "the latest update"** regardless
of merge status, because the whole point of the audit is to check whether
KMIP/CACP keeps pace — and the answer for item 6 below (already merged for
weeks) shows what happens when it doesn't.

## 1. Master coverage table

Reachability through the full stack a KMIP/CACP client actually depends on:
**Engine → TTLV wire → KMIP ops dispatch → CACP policy**. A mechanism is
only genuinely *usable* end-to-end if every column is Yes.

| # | Mechanism | Engine (C++/Rust) | TTLV wire | KMIP ops dispatch | CACP policy registry | End-to-end via KMIP? |
|---|---|---|---|---|---|---|
| 1 | `CKM_AES_GMAC` | unmerged branch, both engines | **No codepoint at all** — KMIP's Block Cipher Mode enum has no GMAC value, standard or vendor | No — no `(Aes, Mac)` arm anywhere | No — absent from `ckm_name_to_code`, no policy references it | **No — unrepresentable at the protocol level**, not just unwired |
| 2 | `CKM_AES_CCM` | unmerged branch, both engines | Yes — real codepoint `0x08`, decodes | No — `aes_mechanism_for` explicitly rejects, unit-tested | **Trap**: absent from CKM registry (load fails if named as a mechanism), but "CCM" **is** a known Block-Cipher-Mode *name* — a policy can reference it and load cleanly while gating nothing | No |
| 3 | `CKM_AES_XTS` (+`CKK_AES_XTS`) | unmerged branch, both engines (Rust uses an unaudited 3rd-party `xts-mode` crate) | Codepoint decodes, but no algorithm/key-type identity exists in `KmipAlgorithm` | No — same rejection path | Same trap as CCM for the mode name; **`CKK_*` key types have zero presence anywhere in CACP** — structurally inexpressible regardless of name | No |
| 4 | `CKM_AES_OFB`, `CKM_AES_CFB128/8/1` | unmerged branch, both engines | Generic OFB/CFB codepoints exist, but **KMIP's own enum has one CFB value** — the 1/8/128-bit width distinction cannot be wire-expressed even in principle | No — explicit rejection, unit-tested ("must fail, not silently substitute") | Same trap ("CFB"/"OFB" known as inert mode names) | No |
| 5 | `CKM_SP800_108_DOUBLE_PIPELINE_KDF` | unmerged branch, both engines | **Yes, fully** — `DerivationMethod::Nist800_108Dpi = 0x07` already a real, spec-matched Rust enum variant | No — `derive_key.rs` explicitly returns `OperationNotSupported` | No — only Counter/Feedback KDF names known | No — but this is the cheapest item to close once the engine branch lands |
| 6 | `CKM_SHA{256,384,512}_HMAC_GENERAL`, `CKM_SHA3_{256,512}_HMAC_GENERAL` | **merged to main weeks ago** (PR #189) | No — `MacRequest` has no length field; `tag_length` exists but is Encrypt/AEAD-only and never read by the MAC path; `KmipAlgorithm` also lacks `HmacSha3_256/512` variants despite real spec codepoints | No — `engine_hmac_target` hardcodes only the fixed-length (non-GENERAL) forms | No — `ckm_name_to_code` only has the non-GENERAL names | **No — a mechanism live in production PKCS#11 has zero path through the product's own crypto-agility control plane** |
| 7 | `CKM_AES_KEY_WRAP_KWP` | **merged to main, both engines** (C++ via PR #189; Rust independently confirmed present — `rust/src/ffi.rs:1433,9223,9483`, `constants.rs:608`, a fact an earlier pass of this audit under-credited to C++ only) | Yes — `AESKeyWrapPadding = 0x0c` is a distinct, real codepoint from plain `NISTKeyWrap = 0x0d`, decodes cleanly | **No** — `wrap_key_value`/`unwrap_key_value` hard-reject any mode but `0x0d` before ever reaching the engine, even though the engine-side dispatch for KWP already exists | **Known, correctly registered** (`rule.rs:1467`) and would gate correctly — but zero shipped policy references it, and it gates an operation that can never actually execute | No — every registry "knows the name," the engine can do it, only the KMIP op's own hard-reject stands in the way |
| 8 | RSA-OAEP hash selection | **merged to main** (PR #190, C++) | Yes, complete | **Yes** — `oaep_params_for` threads `hashing_algorithm` correctly for Encrypt/Decrypt, rejects unsupported hashes loudly | **Yes** — `mechanism_params_from_cp` populates this for Encrypt too (a `policies/README.md` doc claim that this is "Sign/Verify only" undersells the actual code) | **Yes — this one is genuinely closed** |
| 9a | EdDSA prehash (`CKM_EDDSA_PH`) | Rust: **pre-existing**, not new — `sign_with_pss_salt` already dispatches `CKM_EDDSA_PH` to a real `sign_eddsa_ph()` (`rust/src/native/sign.rs:64-137`, `crypto/handlers.rs:1810`; confirmed via `git log -S`, this predates PR #190 by several commits). C++: PR #190 (`CK_EDDSA_PARAMS.phFlag`) — C++ was catching up to a capability Rust already had. | Parameter field exists generically | **No, but the gap is smaller than it looks** — `kmip/src/ops/helpers.rs::native_sign_mech_with_params` never selects `CKM_EDDSA_PH`; it only maps 15 PQC prehash selectors. The engine call KMIP already makes (`sign_with_pss_salt`) would handle it correctly today if only the right `native_mech` were passed in. | **Trap** — `CKM_EDDSA_PH` is a known, correctly-registered mechanism name (`rule.rs:1461`) that a policy can allow/deny, but the op layer has no way to honor the distinction it's gating | No, but cheap to close (§1.3a below) |
| 9b | EdDSA context-string | Rust: **genuinely absent** — checked both `sign_eddsa_ph(sk_bytes, msg)` and `sign_with_pss_salt(session, key_handle, mechanism, data, pss_salt_len)`; neither signature carries a context-byte-string parameter anywhere. C++: PR #190 (`pContextData`). | Yes — `context_string`, tag `0x4201C5`, fully wired generically | **No** — `is_pqc_sign_mech` gate aside, there is no engine call for KMIP to route to even if the gate were fixed; this needs new/extended native signing code, not just a KMIP-side dispatch fix | **No field exists at all** — `MechanismParams` has no `context_string`; structurally invisible to policy even in principle | No — the harder of the two EdDSA items, don't conflate with 9a |

| 10 | `CKM_SHA{256,384,512,3_256,3_384,3_512}_KEY_DERIVATION` (6 mechanisms) | Rust: pre-existing; C++: `fix/ws1-4-and-ws2-rust-gaps`, WS-6.2, catching up | Not checked in depth — likely no `DerivationMethod` variant for "derive by digest" (KMIP models KDFs, not raw-digest derivation, as a first-class concept); needs its own wire check before scoping a fix | No — zero hits for `KEY_DERIVATION` anywhere in `kmip/src/ops/derive_key.rs` | No — zero hits in `ckm_name_to_code` | No |
| 11 | `CKM_SHA512_224`, `CKM_SHA512_256` (digests) | Rust: pre-existing; C++: `fix/ws1-4-and-ws2-rust-gaps`, WS-6.3, catching up | `HashingAlgorithm` enum likely already covers these generically (same family as item 8's OAEP hash list) — not independently re-verified here, check before assuming | Depends on whether `engine_hmac_target`/hash-dispatch helpers include these two hash IDs — not checked | No — `ckm_name_to_code` not re-checked for these two specifically | Unknown — lower confidence than items 1-9, flagged for a follow-up pass rather than asserted |

## 2. TTLV / wire-layer gaps, standalone

- **`CKM_AES_GMAC` has no KMIP wire representation, full stop.** This is a
  genuine protocol-modeling gap in the KMIP 3.0 spec itself (confirmed
  against the vendored spec JSON), not an implementation shortfall — closing
  it needs either a vendor-extension tag or an explicit "GMAC is
  unreachable via KMIP, PKCS#11-direct only" decision, not a code fix.
- **CFB1/CFB8/CFB128 collapse to one generic `CFB` value in the KMIP spec.**
  Even a fully-wired KMIP client could never select the width — this caps
  what item 4 can ever become without a vendor extension.
- Two mechanisms decode cleanly today with **no whitelist at the wire
  layer** (`CryptographicParameters.block_cipher_mode` is a raw
  `Option<u32>`, no closed enum) — CCM and XTS's raw codepoints pass through
  fine; the block is entirely at the ops-dispatch layer next.
- `KmipAlgorithm` (the crate's own enum, `kmip/src/kmip30/algos.rs`) is
  missing real spec codepoints that already exist in the wire tag tables:
  `HmacSha3_256`/`HmacSha3_512` (item 6) and `Ed448 = 0x38` (pre-existing,
  known gap, noted here because it's adjacent to item 9's EdDSA findings —
  Ed448 signing doesn't exist in either engine either, so this one is
  correctly out of scope for this pass, not a new finding).

## 3. KMIP ops/dispatch gaps, standalone

- `aes_mechanism_for()` (`kmip/src/ops/helpers.rs:537-562`) is the single
  choke point for items 2, 3, 4: it only ever selects CBC / CBC_PAD / ECB /
  CTR / GCM. Every new AES mode needs one new match arm here, in addition to
  the engine actually implementing the mechanism (already true, once
  `fix/ws1-4-and-ws2-rust-gaps` lands).
- `derive_key.rs`'s `other` arm (item 5) is a one-line addition once the
  engine supports Double-Pipeline — this is the cheapest of the five
  pending-engine items precisely because the wire layer already has the
  enum value.
- `engine_hmac_target()` (item 6) and `wrap_key_value`/`unwrap_key_value`
  (item 7) gate mechanisms that **already exist in the shipped engine** —
  these are pure KMIP-crate fixes with zero engine dependency, and the
  highest-value items to close first because nothing else is blocking them.
- `is_pqc_sign_mech()` (items 9a/9b) is the reason EdDSA's newly-fixed
  context/prehash support is invisible through KMIP — the check needs a
  third arm (or a rename to something like `supports_sign_params`) covering
  `CKM_EDDSA`/`CKM_EDDSA_PH`, not just the PQC signature family.
- PR #187 (CACP modular policies) is confirmed **orthogonal** to all of the
  above — its only `kmip/src/ops/` touches are 1-2 line API-rename
  mechanicals (`activate` → `replace_all`), not mechanism coverage.

## 4. CACP policy-layer gaps, standalone

- **The `ckm_name_to_code()` registry (`kmip/src/policy/rule.rs:1410-1489`)
  is the authoritative gate for mechanism names, and unknown names are
  fatal for *both* allow- and deny-lists** (no allow/deny leniency split
  applies to this dialect specifically — confirmed by
  `unknown_mechanism_is_always_fatal`). A policy author who tries to
  reference any of items 1-6 by its `CKM_*` name today gets an outright
  **load failure** for the whole file, which is at least loud and honest.
- **The quieter problem is the "known-name trap"**: `CCM`, `XTS`, `CFB`,
  `OFB` are already valid names in the *separate*
  `block_cipher_mode_name_to_code()` dialect (used by
  `mechanism_parameter_constraint`/`default` rules), so a policy referencing
  them there loads cleanly and *looks* like it's gating something — but
  `aes_mechanism_for()` never reaches those modes, so the rule is inert.
  Same pattern for `CKM_EDDSA_PH` in the primary CKM registry (item 9a): a
  correctly-registered name gating an op-layer distinction that doesn't
  exist yet. This is a documentation/audit-trail risk more than a security
  hole (nothing gets allowed that shouldn't be — the engine fails closed
  regardless of policy), but it means a compliance policy can claim to
  enforce a control that is not actually reachable, and a future PR that
  *does* wire up one of these modes could silently start honoring an old,
  never-reviewed rule.
- **`CKM_AES_KEY_WRAP_KWP` (item 7) is the one mechanism where every
  registry — CACP's own CKM list, and `algos.rs`'s
  `usage_mask_to_allowed_mechanisms` `CKA_ALLOWED_MECHANISMS` builder —
  already "knows about it" correctly**, but the actual Wrap/Unwrap
  dispatch never calls it. This is the inverse of the trap above: the
  registries are right and the op is wrong, rather than the other way
  round.
- **Structural gap, not mechanism-specific**: CACP's rule grammar has no
  key-type (`CKK_*`) dimension at all. `CKK_AES_XTS` (item 3) can't be
  expressed in any rule type today, independent of the mechanism-name fix.
- **Structural gap, not mechanism-specific**: `MechanismParams` carries no
  `context_string` field (item 9b) — even a fully-wired ops layer would
  still leave this parameter invisible to policy.
- Two duplicate, independently hand-maintained tables exist for the same
  KMIP Block Cipher Mode enum: `rule.rs:1335-1364`'s
  `block_cipher_mode_name_to_code`/`_code_to_name` and
  `kmip/src/ops/helpers.rs:501-523`'s `block_cipher_mode_name` — a drift
  risk of the same shape `algos.rs`'s own code comments say has already
  caused two real bugs (a drifted ChaCha20 codepoint, a dropped
  `CKM_AES_KEY_WRAP_KWP` from a stride bug).
- `algos.rs` defines its own local `CKM_*` constants rather than importing
  `softhsmrustv3::constants` — the single largest drift-risk surface in this
  audit, by the crate's own documented history.
- `pkcs11-mechanism-lockdown.yaml` was **not** migrated to the modular
  schema-v3 split during PR #187 — it's the one policy file still purely
  monolithic (`scopes: [global]`), unlike fips-only/cnsa-2.0/
  bsi-tr-02102/classical/pqc/migration-*, which all gained per-scope
  siblings. Not a functional gap, but an inconsistency worth closing for
  the same reason the others were split.
- `policies/README.md:271` describes `hash_algorithm_allowlist` as
  "Sign/Verify only" — the code (`mechanism_params_from_cp`) already covers
  Encrypt too (item 8). Doc bug, not a code gap; flagged since it would
  otherwise mislead whoever picks up this remediation plan into thinking
  item 8 needs code work it doesn't.

## 4a. Registry checked and cleared (not silently skipped)

`wasm/src/lib.rs::alg_from_name()` (`:1431-1467`) is a fourth,
independent mechanism/algorithm-name registry — the wasm-playground's
KMIP algorithm spec-name → `KmipAlgorithm` enum mapping, used for the
`algorithm` field of dry-run/execute specs. It is **not** implicated by
any of the nine items in this audit: every item here is a *mode*, *KDF
sub-variant*, or *HMAC-length* variant of an algorithm the playground
already names correctly (AES, HMAC, EdDSA) — none introduce a new
top-level algorithm identity. Recorded here explicitly so this registry
reads as checked-and-cleared, not forgotten. It would need revisiting if a
future mechanism (e.g. Ed448 signing, or a genuinely new PQC scheme) adds a
new top-level algorithm rather than a new mode of an existing one.

## 5. What is NOT a gap (confirmed working, stated plainly)

- RSA-OAEP hash selection (item 8) — fully wired end-to-end, wire → ops →
  CACP, including the ability to force a specific OAEP hash via policy.
- `CKM_ECDH1_COFACTOR_DERIVE`, RSA sign/verify-with-recovery
  (`CKM_RSA_X_509`), and the hybrid-KEM by-design KMIP-only routing —
  reconfirmed still correct, unrelated to this audit's mechanism set.

## 6. Severity ranking

1. **Highest — item 6** (`*_HMAC_GENERAL`/SHA3-HMAC) **and items 10-11**
   (`*_KEY_DERIVATION` family, `SHA512_224/256`): all in production
   PKCS#11 (Rust side pre-existing for 10-11; C++ caught up on
   `fix/ws1-4-and-ws2-rust-gaps`), zero KMIP/CACP path. No engine
   dependency; pure KMIP-crate + CACP-registry fixes. Items 10-11 were
   found via a quick grep pass, not the same file:line-verified depth as
   items 1-9 — confirm the exact dispatch/wire gap shape before scoping
   implementation work, the "No" verdicts are directionally solid (zero
   hits is zero hits) but the *why* wasn't traced as precisely.
2. **High — item 7** (`CKM_AES_KEY_WRAP_KWP`): registries agree it exists,
   the one op that would use it doesn't. No engine dependency.
3. **High — items 9a/9b** (EdDSA prehash/context): engine fix already
   shipped, silently inert through KMIP. No engine dependency.
4. **Medium — items 2-5** (CCM/XTS/OFB-CFB/Double-Pipeline KDF): correctly
   gated on the engine branch (`fix/ws1-4-and-ws2-rust-gaps`) landing first;
   flagged now so the KMIP/CACP wiring is done in the *same* pass as the
   engine merge rather than repeating item 6's multi-week invisibility gap.
   Double-Pipeline KDF (item 5) is the cheapest of this group — wire layer
   is already spec-complete for it.
5. **Medium — item 1** (`CKM_AES_GMAC`): needs a protocol-level decision
   (vendor extension vs. accepted permanent gap), not just code.
6. **Low / hygiene**: the two duplicate block-cipher-mode tables, `algos.rs`
   local constant redefinition, the unsplit lockdown policy file, the
   `policies/README.md` doc inaccuracy, and the Rust-vs-C++ HMAC_GENERAL
   breadth asymmetry (11 C++ variants vs. 5 Rust — a PKCS#11-layer parity
   question, not a KMIP/CACP coverage gap, noted for completeness).

Remediation plan: [remediation-plan-kmip-cacp-pkcs11-coverage-2026-08-30.md](remediation-plan-kmip-cacp-pkcs11-coverage-2026-08-30.md).
