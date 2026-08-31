# Remediation plan — PKCS#11 engine-level gaps (C++ / Rust), 2026-08-30

**Status: not executed.** Narrowly scoped to the *engine* changes surfaced
while integrating KMIP/CACP with the latest PKCS#11 work. This document
covers only what needs to change in the PKCS#11 engines themselves
(`src/lib/` C++, `rust/src/` Rust) — KMIP-crate and CACP-policy wiring is
out of scope here.

**Revision note (2026-08-30, later same day)**: this plan's original §2 was
independently re-verified against the actual branch this worktree is built
on (`fix/kmip-cacp-pkcs11-coverage`, merge-base `6ec2726` — i.e. `main` as
of PR #192) and found materially wrong: both its C++ and Rust "already
done" claims describe a *different, unmerged* branch, not this one. See §2
below for the corrected finding. §1 and §3 were re-checked and confirmed
accurate as written; §3's own branch-dependency framing turned out to be
the right model for §2 too. The two companion documents this plan
originally linked (`gap-analysis-kmip-cacp-pkcs11-coverage-2026-08-30.md`,
`remediation-plan-kmip-cacp-pkcs11-coverage-2026-08-30.md`) do not exist
anywhere in this worktree, tracked or untracked — those links are broken,
flagged here rather than silently dropped. This plan document itself was
also uncommitted (`git status` shows it untracked) at the time of this
review.

## Headline: this is now two branch-integration questions and one small
## piece of genuinely new code (Ed448 context strings).

Every item below was independently re-verified against source in this
session, including exact file/line citations and, for the two pinned Rust
crates, the actual extracted crate source (not just documentation).

---

## 1. EdDSA context-string (`CK_EDDSA_PARAMS.pContextData`) — Rust only

**Confirmed accurate as originally written.**

**C++ is done.** `src/lib/SoftHSM_sign.cpp` (around line 383) genuinely
validates `ulContextDataLen` (0–255 per §6.3.16) and `memcpy`s the context
bytes through before signing. No C++ work needed.

**Rust does not read `pContextData` at all**, at any layer — verified
precisely: `rust/src/ck_param.rs`'s `eddsa` struct layout (line 453) *does*
declare `UL_CONTEXT_DATA_LEN`/`P_CONTEXT_DATA` fields, and the generic
parser is capable of reading them (`r.buffer(eddsa::P_CONTEXT_DATA,
eddsa::UL_CONTEXT_DATA_LEN)`) — but that call exists *only* in a
doc-comment example and this module's own unit test (`ck_param.rs:995`).
Grepping the entire `rust/src` tree for `P_CONTEXT_DATA`/
`UL_CONTEXT_DATA_LEN` outside `ck_param.rs` returns zero hits. The real
dispatch function, `eddsa_ph_flag()` (`rust/src/ffi.rs:5196`), extracts
only the one-byte `phFlag` and never touches the context fields. So: the
parsing *capability* exists, but is genuinely dead code as far as the real
`C_SignInit`/`C_VerifyInit` path is concerned — a real gap, not an
artifact of KMIP bypassing something the engine already has.

**The two RFC 8032 context-string cases split sharply by crate readiness**
— verified directly against the extracted pinned crate sources inside the
`pqc-rust` container (`/usr/local/cargo/registry/src/.../ed448-goldilocks-
0.14.0-pre.15` and `.../ed25519-dalek-2.2.0`), not documentation:

- **Ed448 — cheap, confirmed.** `ed448-goldilocks 0.14.0-pre.15`'s
  `SigningKey::sign_ctx(&self, context: &[u8], message: &[u8]) ->
  Result<Signature, Error>` exists verbatim at `sign/signing_key.rs:446`.
  Wiring this up is mechanical: add a `sign_eddsa_ctx` variant, extend the
  FFI-layer parameter parsing to actually extract `pContextData`/
  `ulContextDataLen`.
- **Ed25519 — genuinely harder, confirmed no drop-in exists.** Read
  `ed25519-dalek 2.2.0`'s `signing.rs` and `hazmat.rs` directly: `sign()`
  is pure Ed25519 (no context param at all), `sign_prehashed()` is
  Ed25519ph. The crate *does* have a `Context`/`with_context` API
  (`src/context.rs`) — but its own doc comment states explicitly: **"Ed25519
  contexts as used by Ed25519ph"**, and its only usage example pairs it
  with `Sha512`-prehashing via `sign_digest`/`DigestSigner`. This is
  Ed25519ph-with-context, not RFC 8032's separate, non-prehashed
  Ed25519ctx mode. `hazmat::raw_sign<CtxDigest>`'s `CtxDigest` type
  parameter is confirmed (via its own doc comment) to mean "the digest
  used to calculate the pseudorandomness needed for signing... `CtxDigest
  = Sha512`" — an internal RNG-domain digest, not an RFC 8032 context
  string. There is genuinely no drop-in method for pure, non-prehashed
  Ed25519ctx in this crate at its pinned version.
  Closing this requires one of:
  1. Check whether a newer `ed25519-dalek` release added real Ed25519ctx
     support since 2.2.0.
  2. Hand-roll Ed25519ctx on top of `hazmat` primitives per RFC 8032
     §5.1 — the crate's own warning on `raw_sign` ("Do NOT use this
     function unless you absolutely must... can leak your signing key")
     makes this a real correctness/security risk, not a mechanical task.
     **Recommend treating this the same way `CKM_ECMQV_DERIVE` was held**
     — don't implement without an explicit go/no-go and a second
     independent reference to cross-check output against.
- **Recommendation, unchanged**: ship Ed448 context-string support on its
  own — low-risk, crate-ready. Scope Ed25519ctx as a separate, explicitly-
  flagged decision, not bundled into the same PR.

---

## 2. `CKM_SHA512_224_KEY_DERIVATION` / `CKM_SHA512_256_KEY_DERIVATION`

**Corrected — this is a branch-integration question, not a small coding
task, and it affects BOTH engines, not just Rust.**

The original claim ("C++ is done... Rust has 6 of 8... small, mechanical")
was checked against the wrong branch state. Re-verified directly on
`fix/kmip-cacp-pkcs11-coverage`'s actual merge-base (`6ec2726`, i.e.
`main` as of PR #192 — this worktree's real starting point):

- **C++ has NONE of the 8 SHA2/SHA3-family `*_KEY_DERIVATION` mechanisms
  on this branch** — not just the two SHA-512-truncated ones. Grepping
  `src/lib/SoftHSM_slots.cpp` and `SoftHSM_keygen.cpp` for
  `SHA256_KEY_DERIVATION`/`SHA3_224_KEY_DERIVATION`/
  `SHA512_224_KEY_DERIVATION`/etc. returns zero hits; the *only*
  `*_KEY_DERIVATION` mechanism present anywhere in this branch's C++ is
  the pre-existing `CKM_SHAKE_256_KEY_DERIVATION`. The original plan's
  citation (`SoftHSM_keygen.cpp:2880-2881`) points at unrelated
  `CKM_PKCS5_PBKD2` PRF-selection code on this branch — not a stale line
  number from later edits, a citation of the wrong branch entirely.
- **Rust genuinely has 6 of 8 on this branch** (this half of the original
  claim holds): `rust/src/constants.rs` defines
  `CKM_SHA{256,384,512,3_256,3_384,3_512}_KEY_DERIVATION` and all six
  appear in the mechanism-support list. But the claim that "the underlying
  SHA-512/224 and SHA-512/256 digests already exist in Rust... used today
  by the HKDF path" does **not** hold on this branch: grepping the entire
  `rust/src` tree for `Sha512_224`/`Sha512_256`/`Sha512Trunc224/256`
  (the real `sha2` crate type names) returns zero hits outside test code,
  and `CKM_SHA512_224`/`CKM_SHA512_256` (the plain digest mechanisms, not
  the KEY_DERIVATION variants) aren't defined in `constants.rs` at all on
  this branch. The digest support the original plan pointed to genuinely
  exists — but on the same unmerged branch as everything else below, not
  here, and via the **SP800-108 Double-Pipeline KDF path**
  (`Hmac<sha2::Sha512_224>`/`Hmac<sha2::Sha512_256>` in
  `rust/src/ffi.rs`), not the HKDF path as originally cited.

**Where this work actually lives**: both the full 8-mechanism C++
`*_KEY_DERIVATION` family and the Rust `Sha512_224`/`Sha512_256` digest
support are real, working, and already verified — on
`fix/ws1-4-and-ws2-rust-gaps` (46 commits ahead of `main`, not yet merged;
confirmed directly in `.worktrees/ws1-4-and-ws2`) and its downstream
combination in `.worktrees/openssl-provider-remediation`
(`feat/jdk27-jca-provider`, currently at commit `e36ddd6` and still
receiving active work as of this review).

**This means §2 is the identical branch-sequencing situation as §3, not a
smaller, independent coding task**: either port the relevant
`fix/ws1-4-and-ws2-rust-gaps` commits into whichever branch this KMIP/CACP
work ultimately builds on, or wait for that branch to merge. There is no
"cheap, mechanical, do it now on this branch" version of this item — the
mechanical part (wiring 2 more digests into an existing 6-mechanism
dispatch) is real and accurately described, but only once the other 6
mechanisms and the underlying digest support exist here at all, which
they currently don't.

---

## 3. `CKM_ML_DSA_EXTERNAL_MU_GEN` (keygen) — availability, not invention

**Confirmed accurate, with an update: the branch has moved further.**

Both C++ and Rust already implement this — but only on the same
not-yet-merged lineage as §2 above
(`fix/ws1-4-and-ws2-rust-gaps` → `feat/jdk27-jca-provider`, worktree
`.worktrees/openssl-provider-remediation`). The original plan cited commit
`0d33f59`; that worktree has since advanced to `e36ddd6` (two more commits
of JavaJCE-side work, unrelated to this engine question) and has
further uncommitted work in progress at time of this review. The
underlying engine-side mu-rename/keygen availability this section
describes has not changed since `0d33f59`.

**Standards-status caveat, unchanged, carry forward into any future
work**: `CKM_ML_DSA_EXTERNAL_MU` (0x403c) / `_MU_GEN` (0x403b) are OASIS
status "proposed" — a PKCS#11 v3.3 working-draft value, not through final
ballot. Don't describe downstream coverage of this mechanism as
spec-conformant without that qualifier.

---

## What's explicitly NOT in scope here

- **EdDSA prehash mode itself** (`phFlag` → `CKM_EDDSA_PH`) — already fully
  functional in both engines at the raw PKCS#11 layer on this branch.
  Note: on the separate `feat/jdk27-jca-provider` lineage referenced in §2
  and §3, the OpenSSL-provider-side handling of this exact mechanism has
  since changed (a real gating bypass was found and closed there,
  commit `0d33f59`) — not relevant to this engine-only document, but worth
  knowing if this plan's scope ever widens to provider-layer work.
- **`CKM_AES_GMAC`'s KMIP reachability** — already decided as a permanent,
  documented KMIP-unreachable mechanism; the engine itself already has
  GMAC on `fix/ws1-4-and-ws2-rust-gaps`.
- The broader C++/Rust `*_HMAC_GENERAL` breadth asymmetry and other
  pre-existing engine-parity items — out of scope for this document.

## Priority order (revised)

1. **Ed448 context-string (§1)** — the only item that's genuinely cheap,
   crate-ready, buildable on this branch today, and needs no decision
   beyond implementing it.
2. **Branch-integration decision for §2 and §3 together** — both now
   depend on the same unmerged `fix/ws1-4-and-ws2-rust-gaps` /
   `feat/jdk27-jca-provider` lineage. This is one decision (when/how that
   lineage lands relative to this KMIP/CACP branch), not two separate
   engineering tasks — resolve it once, and both §2's 8-mechanism
   KEY_DERIVATION family and §3's external-mu keygen availability follow
   automatically.
3. **Ed25519ctx (§1)** — needs an explicit go/no-go and a cross-check
   reference before any code is written, independent of the branch
   question above.

## Open items for whoever picks this up

- Locate or recreate the two companion documents this plan references
  (`gap-analysis-kmip-cacp-pkcs11-coverage-2026-08-30.md`,
  `remediation-plan-kmip-cacp-pkcs11-coverage-2026-08-30.md`) — neither
  exists in this worktree as of this review.
- Commit this plan document itself — it was untracked at review time.
