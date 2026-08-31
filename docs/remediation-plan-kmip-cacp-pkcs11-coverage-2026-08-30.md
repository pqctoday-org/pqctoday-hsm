# Remediation plan — KMIP / TTLV / CACP coverage of the latest PKCS#11 work (2026-08-30)

**Status: not executed.** This document proposes a plan only, based on
[gap-analysis-kmip-cacp-pkcs11-coverage-2026-08-30.md](gap-analysis-kmip-cacp-pkcs11-coverage-2026-08-30.md).
Nothing here has been implemented, tested, or committed as code.

## Update, 2026-08-30 (same day, later) — engine work is now complete

All PKCS#11 remediation work is committed locally on
`fix/ws1-4-and-ws2-rust-gaps` (worktree `.worktrees/ws1-4-and-ws2`, tip
`fe88c79`, 44 commits vs. `main`) — this is the full WS-0 through WS-8
remediation, not just the WS-8 subset this plan originally scoped around,
and it's closed out with a final changelog commit, not left mid-flight.
**This changes Phase 2 below**: it was written assuming the engine side was
still in flux and gated on a future merge. It isn't anymore — the mechanism
set is stable and done. The only thing "not yet merged to `main`" means
here is that KMIP/CACP work should target the worktree's code directly
rather than waiting on a merge/push decision, which is a separate,
unrelated call for you to make on its own timeline. Phase 2's individual
items are updated below to drop the "wait for the branch" framing.

This also surfaced two more gaps outside the original WS-8 scope — WS-6.2/
6.3's `CKM_SHA*_KEY_DERIVATION` family and `CKM_SHA512_224/256` — added as
Phase 1.4, same no-engine-dependency shape as 1.1/1.2, but lower confidence
(found via a quick grep pass, not independently file:line-traced the way
items 1-9 were — verify the exact dispatch shape before estimating effort).
**Confirmed same day, not previously scoped: Rust is missing 2 of C++'s 8
`*_KEY_DERIVATION` variants outright** —
`CKM_SHA512_224_KEY_DERIVATION`/`CKM_SHA512_256_KEY_DERIVATION` have zero
presence in `rust/src/constants.rs`/`ffi.rs` even though the raw
SHA-512/224/256 digests are already there. This is a genuine engine-level
blocker for 2 of Phase 1.4's 8 mechanisms specifically — no KMIP/CACP fix
can close those two without Rust engine work first; the other 6 are
unaffected.

## Update, 2026-08-30 (same evening, ~22:00) — a third source branch

A separate worktree, `.worktrees/openssl-provider-remediation`
(branch `feat/jdk27-jca-provider`), landed two commits in the last hour
(`0d33f59`, `a39fc95`) closing PKCS#11 mechanism gaps in the OpenSSL 3.x
provider and the JavaJCE provider against the merged engine surface. This
is provider-layer work, not KMIP/CACP-relevant on its own — except for one
piece that touches the core Rust/C++ engines directly: an early adoption of
PKCS#11 v3.3 working-draft naming for the ML-DSA External-Mu mechanism
(`CKM_PQCTODAY_ML_DSA_MU` → `CKM_ML_DSA_EXTERNAL_MU`, OASIS status
"proposed," not balloted). Checked for KMIP/CACP fallout — see the new
§1.5 below. Also corrected §1.3 (EdDSA): the provider work independently
established that `CKM_EDDSA_PH` is the wrong target mechanism for KMIP's
fix, superseding this plan's original 1.3a instruction.

## Update, 2026-08-30 (later still) — independent re-verification pass, no scope changes

This plan and its companion gap-analysis were independently re-checked
against source in a separate review (not by the author of the above two
updates). Two things worth recording; neither changes any Phase or item
below.

**§1.3's `CKM_EDDSA_PH`-is-legacy-shorthand finding is now confirmed
three separate times, independently**: by the `openssl-provider-remediation`
OpenSSL-provider fix itself (`0d33f59`), by the JavaJCE agent that read that
fix and the engine's `SoftHSM_sign.cpp` directly (`a39fc95`), and now by
this KMIP plan's own independent read of the same engine source. Three
unrelated investigations reaching the same conclusion from the same
primary source is strong confirmation — §1.3's unified engine+KMIP
approach (route everything through plain `CKM_EDDSA` + `CK_EDDSA_PARAMS`,
never select `CKM_EDDSA_PH`) should be treated as settled, not merely
"the current best guess."

**Phase 1.4's lower-confidence Rust-gap claim was independently
re-verified and holds exactly as stated**: re-grepped
`fix/ws1-4-and-ws2-rust-gaps`'s `rust/src/constants.rs` directly — exactly
6 of 8 `*_KEY_DERIVATION` mechanisms present (`SHA256`/`384`/`512`/
`3_256`/`3_384`/`3_512`), zero hits for `SHA512_224_KEY_DERIVATION` or
`SHA512_256_KEY_DERIVATION` anywhere in `constants.rs` or `ffi.rs`. The
"genuine engine-level blocker for 2 of 8" framing is correct as written —
no change needed, just upgraded from "lower confidence, verify before
estimating" to independently confirmed.

**Source-branch currency, informational only**: `openssl-provider-remediation`
has advanced past the two commits cited above — `a39fc95` was followed by
`e36ddd6` (JavaJCE: AES-XTS + `CKK_AES_XTS`, AES-OFB/CFB128/8/1,
SHA-512/224+256 MessageDigest/Mac coverage, and several SHA-224/SHA3-224
signature registrations), and a further OpenSSL-provider pass (AES Key
Wrap + AES-XTS ciphers) has landed uncommitted on top of that. All of this
is JavaJCE- and OpenSSL-C-provider-layer work — none of it touches
`kmip/`, `rust/src/`, or changes any conclusion in this plan. One point of
incidental interest: that OpenSSL-provider pass discovered the vendored
provider had **zero** `C_WrapKey`/`C_UnwrapKey` wrapper functions of any
kind before today (AES-Wrap could not ride the existing `C_Encrypt`-shaped
cipher path at all — it needed genuine key-object wrap/unwrap semantics
added from scratch). This is consistent with, not contradictory to, this
plan's own §1.2: KMIP's Rust-side `wrap_key_value`/`unwrap_key_value`
already use the correct `C_WrapKey`/`C_UnwrapKey`-shaped call, and §1.2's
fix remains exactly as scoped (add one branch for `CKM_AES_KEY_WRAP_KWP`,
no architecture change needed on the KMIP side).

## Ordering principle

Split into what can be fixed **today, with zero engine dependency** (Phase
1) versus what is correctly **gated on `fix/ws1-4-and-ws2-rust-gaps`
merging first** (Phase 2), plus a **Phase 0** hygiene pass and a **Phase 3**
open protocol question. Phase 1 is the highest-value work: it closes gaps on
mechanisms that have already been in production for weeks with zero
KMIP/CACP visibility — exactly the failure mode Phase 2 is designed to
prevent from recurring.

---

## Note on "severity" vs. priority

Every gap in the companion gap-analysis document fails closed or fails
loud — verified during this plan's own re-check pass (item 7's rejection
path errors rather than silently substituting; item 4's rejection is
unit-tested specifically to prevent silent substitution). **None of these
are security holes.** The gap-analysis doc's "severity ranking" is really a
capability-completeness ranking — read it as priority-to-close, not
risk-to-exploit.

## Phase 0 — hygiene / drift-risk reduction (recommended before Phase 1, not a hard blocker)

Only item 0.1 plausibly touches code Phase 1/2 will also edit, and even
that's an ordering convenience, not a real dependency — Phase 1 items can
proceed against the current (duplicated-constant) pattern if there's
schedule pressure, with 0.1 cleaning up after.

| # | Item | Files | Why first |
|---|---|---|---|
| 0.1 | Make `kmip/src/kmip30/algos.rs` import `CKM_*`/`CKA_*` constants from `softhsmrustv3::constants` instead of redefining them locally | `algos.rs:150-172` | This is the crate's own documented root cause of two real prior bugs (drifted ChaCha20 codepoint, dropped KWP from a stride bug). Every mechanism fix below adds another constant to this file — fix the pattern before adding to it. |
| 0.2 | Collapse the two independent block-cipher-mode name tables into one | `kmip/src/policy/rule.rs:1335-1364` (`block_cipher_mode_name_to_code`/`_code_to_name`) and `kmip/src/ops/helpers.rs:501-523` (`block_cipher_mode_name`) | Phase 1/2 work touches block-cipher-mode dispatch directly; fixing the duplication first means later phases edit one table, not two. |
| 0.3 | Fix `policies/README.md:271`'s "Sign/Verify only" claim for `hash_algorithm_allowlist` (already covers Encrypt) | `policies/README.md` | Doc-only; prevents a future reader from "fixing" something that already works. |
| 0.4 | Decide and document the disposition of the CCM/XTS/OFB/CFB/`CKM_EDDSA_PH` "known-name trap" rules: either strip them from `block_cipher_mode_name_to_code`/`ckm_name_to_code` until the op layer actually reaches them, or add a loader-time warning when a policy references a name that resolves but has no live dispatch path | `rule.rs`, `loader.rs` | A compliance policy today can claim to gate a mode that cannot execute. Cheap to close now; expensive to notice later once a real policy has been authored around the assumption. |

## Phase 1 — close gaps on mechanisms already merged to `origin/main` (no engine dependency)

### 1.1 `CKM_*_HMAC_GENERAL` / SHA3-HMAC (gap-analysis item 6) — highest priority

- Add `CKM_SHA256_HMAC_GENERAL`, `CKM_SHA384_HMAC_GENERAL`,
  `CKM_SHA512_HMAC_GENERAL`, `CKM_SHA3_256_HMAC_GENERAL`,
  `CKM_SHA3_512_HMAC_GENERAL` to `ckm_name_to_code()`
  (`kmip/src/policy/rule.rs:1410-1489`).
- Add a MAC output-length field to the wire layer: extend `MacRequest`
  (`kmip/src/kmip30/ops.rs:1292-1300`) with an optional length, or repurpose
  `CryptographicParameters.tag_length` for the MAC path (currently
  Encrypt/AEAD-only, `ops.rs` ~1374-1375) — needs a design call on which is
  more spec-faithful; the GENERAL mechanisms exist precisely to let a caller
  request a truncated tag, so the field has to reach `engine_hmac_target`.
- Extend `engine_hmac_target()` (`kmip/src/ops/mac_and_hash.rs:261-291`) to
  select the GENERAL variant when a length is present and route it through
  to the engine (already implemented there — `rust/src/constants.rs:726`
  `SUPPORTED_MECHS`).
- Add `HmacSha3_256`/`HmacSha3_512` to `KmipAlgorithm`
  (`kmip/src/kmip30/algos.rs:213-410`) — the wire codepoints already exist
  in the spec table; the crate's enum just never picked them up.
- **Effort: medium.** Mostly additive; the only real design question is
  where the truncation-length parameter lives on the wire.

### 1.2 `CKM_AES_KEY_WRAP_KWP` (item 7)

- **Re-verified 2026-08-30: no open risk here.** The Rust engine already
  fully implements this mechanism on `main` today —
  `rust/src/constants.rs:608` defines the constant, and `rust/src/ffi.rs`
  has real `is_kwp` dispatch branches in both the wrap path (`:9223`) and
  unwrap path (`:9483`), plus the top-level mechanism match at `:1433`. An
  earlier pass of this audit under-credited this mechanism to C++ only —
  that was incomplete, not the Rust engine.
- `wrap_key_value`/`unwrap_key_value` (`kmip/src/ops/helpers.rs:1302-1347`,
  `1454-1500`) currently hard-reject any `block_cipher_mode != 0x0d`
  (`NISTKeyWrap`) before ever reaching the engine. Add a branch for `0x0c`
  (`AESKeyWrapPadding`) that passes `mech_type = CKM_AES_KEY_WRAP_KWP`
  through to the same engine call already used for plain KEY_WRAP — the
  engine-side dispatch on that constant already exists, confirmed above.
- No CACP or wire changes needed — both already correctly recognize this
  mechanism (`rule.rs:1467`, `WrappingMethod::AESKeyWrapPadding` decodes
  fine). This is purely an `ops/helpers.rs` fix.
- Add at least one policy example referencing `CKM_AES_KEY_WRAP_KWP` (e.g.
  in `pkcs11-mechanism-lockdown.yaml`) once the op works, so the
  already-correct registry entry has a real consumer.
- **Effort: low, unconditionally** — no remaining unknowns.

### 1.3 EdDSA prehash + context-string (items 9a/9b), unified — revised 2026-08-30 to match the now-established provider convention

Two commits landed within the hour on `.worktrees/openssl-provider-remediation`
(branch `feat/jdk27-jca-provider`, not yet on `main`): `0d33f59` (OpenSSL
provider) and `a39fc95` (JavaJCE), both independently closing EdDSA
prehash/context gaps against the same merged PKCS#11 surface this plan
targets. Both concluded, from reading the engine's own `SoftHSM_sign.cpp`,
that **`CKM_EDDSA_PH` is a parameterless legacy/vendor shorthand — the real
RFC 8032 mode selection (prehash *and* context) goes through `CKM_EDDSA`
with `CK_EDDSA_PARAMS` (`phFlag` + `pContextData` together)**. This
supersedes the plan's original instruction to select `CKM_EDDSA_PH` as a
distinct mechanism, and — checked directly against
`rust/src/native/sign.rs`'s current `CKM_EDDSA` arm (`sign_eddsa(&sk_bytes,
data)`, no context/phFlag parameter) — confirms the real remaining gap was
never mechanism *selection* at all. It's that **no Rust engine function
accepts an EdDSA parameters struct**, regardless of which `CKM_*` name is
used. `sign_eddsa_ph()` (`rust/src/crypto/handlers.rs:1810`) exists as a
separate hardcoded function, not a parameterized one — it's what
`CKM_EDDSA_PH` calls today, and it's exactly the shorthand the provider
work says to stop treating as the real interface.

This unifies 9a and 9b into **one** engine change plus **one** KMIP change:

1. **Engine (prerequisite, do first)**: check whether the underlying
   signing crate (`ed25519-dalek` / `ed448-goldilocks`, whichever this
   engine depends on) exposes a context-string-aware signing API at all —
   RFC 8032 Ed25519ctx/Ed25519ph are the same construction with different
   parameters, so a crate that supports one likely supports both. If it
   does, extend `sign_with_pss_salt`'s `CKM_EDDSA` arm (or add a sibling
   function) to accept `Option<(bool /* phFlag */, &[u8] /* context */)>`
   and route both prehash and context through it — this is real,
   non-trivial engine work either way, not just a KMIP-crate fix.
2. **KMIP**: add `context_string: Option<Vec<u8>>` to `MechanismParams`
   (`kmip/src/policy/request.rs`), populate it in
   `mechanism_params_from_cp()` (`kmip/src/ops/helpers.rs:918-935`), and
   thread it — along with however prehash intent is signaled (confirm the
   KMIP 3.0 wire vocabulary for this before writing code; it may not be a
   distinct `CryptographicAlgorithm` selector the way PQC prehash is) —
   into the extended engine call from step 1. `native_mech` should always
   resolve to `CKM_EDDSA`, never `CKM_EDDSA_PH`, matching the provider
   convention. No `is_pqc_sign_mech` gate change needed — this is a new,
   parallel EdDSA-specific parameter path, not an extension of the PQC one.

- **Effort: medium-high, single item now** (was two items at low/
  medium-high separately) — gated entirely on step 1's crate-capability
  check; don't estimate further without it. The original "1.3a is cheap"
  read was wrong — it mistook an already-correct-looking dispatch arm
  (`CKM_EDDSA_PH` existing and working) for the real interface, when the
  provider work shows that arm is exactly what's being deprecated in
  favor of the unified approach this section now describes.

### 1.5 `CKM_ML_DSA_EXTERNAL_MU` / `_MU_GEN` keygen mechanism — new, from the provider-layer work

The same `0d33f59` commit renamed vendor `CKM_PQCTODAY_ML_DSA_MU`/`_MU_GEN`
to spec-aligned `CKM_ML_DSA_EXTERNAL_MU` (0x403c) / `_MU_GEN` (0x403b) in
both C++ and Rust engines (`rust/src/constants.rs`, `ck_param.rs`,
`crypto/handlers.rs`, `ffi.rs` — confirmed no `kmip/` files touched in that
commit). Checked whether this needs KMIP/CACP follow-up:

- **No regression on `main` or the engine branch** — confirmed zero
  references to the old vendor name anywhere in `kmip/src/` or `rust/src/`
  on either. The rename is currently isolated to the provider worktree.
- **KMIP's existing External-Mu support is a different operation and is
  unaffected either way.** `kmip/src/kmip30/ops.rs:1404`
  (`external_mu: Option<bool>`) and `kmip/src/ops/sign.rs:238` thread a
  semantic boolean flag straight into `native::sign_pqc(...)` — that's the
  Sign-time "use an externally-supplied mu value" feature, and it never
  referenced the raw `CKM_*` constant name, so the provider-layer rename
  doesn't touch it.
- **Genuinely new finding, not previously scoped**: `CKM_ML_DSA_EXTERNAL_MU_GEN`
  is a distinct **key-generation**-time mechanism (generating a key that
  produces/consumes externally-supplied mu values), separate from the
  Sign-time boolean above. Confirmed **zero** presence anywhere in
  `kmip/src/ops/create_key_pair.rs` or `kmip/src/kmip30/algos.rs`, and
  **zero** presence in CACP's `ckm_name_to_code` — this keygen mechanism
  has no KMIP/CACP path at all, old name or new. Not previously part of
  this audit's item list; scope and effort not yet assessed — needs its
  own pass (does KMIP's `CreateKeyPair` op even have a place to route a
  Mu-Gen-specific keygen request today, or does this need new op-level
  plumbing, not just a registry addition?) before estimating.
- **Standards-status note, worth preserving**: these codepoints are OASIS
  status "proposed" (PKCS#11 v3.3 working draft), not through final ballot.
  The engine commit documents this explicitly as a deliberate early-adopt
  decision. Any future KMIP/CACP work here should carry the same caveat —
  don't describe External-Mu keygen coverage as "spec-conformant" without
  that qualifier.

### 1.4 `CKM_SHA*_KEY_DERIVATION` family + `CKM_SHA512_224/256` (items 10-11) — lower confidence, verify before estimating

- Confirmed absent from `kmip/src/` entirely (zero hits for
  `KEY_DERIVATION`/`SHA512_224`/`SHA512_256` across `algos.rs`,
  `ops/*.rs`, `policy/rule.rs`). Not yet traced to the same file:line depth
  as items 1-9 — before scoping, check: (a) whether `HashingAlgorithm`
  already covers SHA-512/224/256 generically for the algorithms that use
  it (item 8's OAEP hash list is the obvious place to check first), and
  (b) whether KMIP's `DerivationMethod` enum has any concept of "derive by
  raw digest" that these 6 mechanisms would map onto, or whether this needs
  new wire vocabulary the same way item 6 needed a MAC-length field.
- Add all 8 names (6 `*_KEY_DERIVATION` + 2 digests) to `ckm_name_to_code`
  regardless of the above — that part is unconditionally correct and
  low-risk, matching the Phase 1 pattern.
- **Effort: unknown, verify first** — could be as cheap as 1.1/1.2 (pure
  registry + dispatch additions) or could need new wire vocabulary like
  1.3b if `DerivationMethod` has no raw-digest concept.

---

## Phase 2 — wire up the WS-8 mechanism set (items 1-5) — engine work is done, no longer gated

**Updated 2026-08-30**: originally written as "wait for the branch to
merge" — that's no longer the constraint. The engine side is committed and
stable on `fix/ws1-4-and-ws2-rust-gaps` (worktree `.worktrees/ws1-4-and-ws2`);
KMIP/CACP wiring can start now, targeting that worktree's code. Whether/when
that branch merges to `main` is a separate, unrelated decision — don't let
this phase's scheduling wait on it. Since KMIP/CACP only ever calls into
the **Rust** engine (per this repo's `CLAUDE.md` — the Rust engine is "the
production backend for the KMIP server and CACP policy engine"), only the
Rust-side commits on that branch are actually relevant here — the C++ side
is for direct PKCS#11 callers, orthogonal to this phase.

**Unverified assumption carried into every row below, flag before
estimating further**: this phase's effort estimates assume the new
`native::` entry points on that branch (for CCM/XTS/OFB/CFB/Double-Pipeline)
slot into `encrypt.rs`/`decrypt.rs`/`derive_key.rs` the same way the
existing CBC/GCM/Counter-KDF calls do. That was not checked in this audit —
if the branch's new functions have a different signature shape (e.g. needing
a tweak/sector-index parameter for XTS that CBC/GCM calls don't carry), the
"one new match arm" framing below understates the work. Given the branch is
now finalized and not going to change shape further, this is a cheap check
to do directly against `.worktrees/ws1-4-and-ws2/rust/src/native/` before
starting any row below.

| # | Item | KMIP-side work | CACP-side work | Notes |
|---|---|---|---|---|
| 2.1 | `CKM_SP800_108_DOUBLE_PIPELINE_KDF` | One new arm in `derive_key.rs`'s `other` match (currently returns `OperationNotSupported` for `Nist800_108Dpi`, `derive_key.rs:433-443`) | Add the name to `ckm_name_to_code`, alongside existing Counter/Feedback KDF entries (`rule.rs:1471-1472`) | Cheapest item in this phase — wire enum (`DerivationMethod::Nist800_108Dpi = 0x07`) is already spec-complete and decodes today. |
| 2.2 | `CKM_AES_CCM` | New arm in `aes_mechanism_for()` (`helpers.rs:537-562`) for `bcm == 8` | Add `CKM_AES_CCM` to `ckm_name_to_code`; **also revisit the Phase 0.4 decision** — once this lands, the existing "known but inert" CCM block-cipher-mode name becomes live, so any policy authored against the old inert assumption needs re-review | Straightforward once the engine supports it. |
| 2.3 | `CKM_AES_XTS` (+`CKK_AES_XTS`) | New arm in `aes_mechanism_for()` for `bcm == 0x0b`; **also requires adding a key-type dimension to the CACP rule grammar**, since `CKK_*` doesn't exist anywhere in it today | Add `CKM_AES_XTS`/`CKM_AES_XTS_KEY_GEN` to `ckm_name_to_code`; design and add the key-type field to whichever rule types need it (likely `MechanismAllowlist`/`Denylist` and any keygen-gating rule) | The largest scope item in this phase — the key-type grammar gap is structural, not a one-line fix. Consider scoping this as its own sub-plan if it grows. |
| 2.4 | `CKM_AES_OFB`, `CKM_AES_CFB128/8/1` | New arms in `aes_mechanism_for()` for `bcm ∈ {OFB, CFB}` — **note the wire-layer ceiling**: KMIP's spec enum cannot distinguish CFB1/8/128, so even after this fix a KMIP client can only request generic "CFB," not pick the width. Decide whether the engine should default to CFB128 (most common) or require a vendor-extension attribute to pick the width, before writing dispatch code | Add `CKM_AES_OFB`/`CKM_AES_CFB128`/`_CFB8`/`_CFB1` to `ckm_name_to_code` for policy-gating purposes even though KMIP can only ever *request* generic CFB — the policy layer can still usefully allow/deny the underlying PKCS#11 mechanism for non-KMIP callers | Needs a design decision before implementation, not just a coding task. |

## Phase 3 — open protocol question: `CKM_AES_GMAC` (item 1)

Not schedulable as ordinary engineering work — KMIP 3.0 has no wire
representation for GMAC at all. Two options, needing an explicit go/no-go:

1. **Vendor-extension tag** (KMIP's tag space reserves ranges for exactly
   this) to carry a GMAC-mode selector, following whatever precedent this
   codebase already has for vendor extensions (check for one before
   inventing a new pattern).
2. **Accept as a permanent, documented KMIP-unreachable mechanism** —
   available via raw PKCS#11 only, same posture as any other engine feature
   deliberately kept outside the KMIP surface (c.f. the CLAUDE.md's existing
   framing of the hybrid-KEM split between engine-level and KMIP-level
   surfaces).

Recommend a real decision here rather than leaving it implicitly unresolved
— it's cheap to decide, and left undecided it will keep resurfacing in
every future coverage audit.

---

## Sequencing summary

1. Phase 0 (hygiene) — recommended first, not a hard blocker (see note
   above).
2. Phase 1 (already-merged/already-stable mechanisms) — start now, no
   blockers, except:
   - **1.3 (EdDSA prehash + context, unified)** is gated on confirming the
     signing crate's context-string capability first — do that check
     before scheduling the rest of this item.
   - **1.4 (`*_KEY_DERIVATION` family + SHA-512/224/256)** — 6 of 8
     mechanisms are unblocked; `SHA512_224/256_KEY_DERIVATION`
     specifically need Rust engine work first (confirmed absent from
     `rust/src/constants.rs`/`ffi.rs`) — scope those two out of this pass
     or route them to whoever owns the engine branch.
   - **1.5 (External-Mu keygen, `CKM_ML_DSA_EXTERNAL_MU_GEN`)** — new,
     not yet scoped for effort; needs its own investigation pass (does
     `CreateKeyPair` have anywhere to route this at all?) before it can be
     scheduled like the others.
3. **Phase 2 (WS-8 set) — no longer gated on a merge.** The engine work is
   committed and finalized on `fix/ws1-4-and-ws2-rust-gaps`; start this
   phase whenever capacity allows, targeting that worktree directly. Only
   genuinely wait if you want the KMIP/CACP commits to land in the same PR
   as an eventual `main` merge of the engine branch — a sequencing
   preference, not a technical requirement anymore.
4. Phase 3 (GMAC) — a decision, not an implementation task; can happen in
   parallel with anything else.
5. **Cross-cutting reminder for 1.5 and any future item touching PKCS#11
   v3.3-draft codepoints**: don't describe the resulting KMIP/CACP coverage
   as spec-conformant without the same "proposed, not balloted" caveat the
   engine commit itself carries — this is the first item in this whole
   audit resting on a non-final spec.

## Process recommendation (not a code item)

The single clearest pattern in this audit is that **a mechanism landing in
the PKCS#11 engine creates no automatic signal that KMIP/CACP needs to
catch up** — item 6 sat merged and fully invisible through the product's
own control plane for weeks with nothing to flag it. Consider adding a
checklist line to whatever PR template or review process governs engine-
level PKCS#11 changes: "does this mechanism need a corresponding
`ckm_name_to_code` / `aes_mechanism_for` / dispatch entry in `kmip/`?" —
even an explicit "no, and here's why" is better than the silent gap this
audit found.
