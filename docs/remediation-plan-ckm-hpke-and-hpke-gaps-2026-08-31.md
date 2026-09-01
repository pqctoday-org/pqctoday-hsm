# Remediation plan — CKM_HPKE and HPKE gaps (2026-08-31)

**Status:** PLAN — not executed. Companion to
`docs/proposal-plan-ckm-hpke-mechanism-2026-08-31.md` and
`docs/proposals/pkcs11-ckm-hpke-mechanism-proposal.md`.
**Scope:** cross-repo — `pqctoday-hsm` (Rust engine), `pqctoday-hub` (JS/WASM
binding + Learn module), `pqctoday-priv` (library catalog).
**Source:** the gap report delivered this session, itself grounded in real
test runs, `git status`, and primary-source reads (RFC 9180) — not
speculative.

## Ordering rationale

R1 → R2 are sequenced first because they're the credibility gate: nothing
downstream ("the mechanism works") is trustworthy until the FFI boundary
itself has been exercised, not just the native Rust logic under it — the
exact class of bug this session already found twice. R3–R6 are independent
and can run in any order, or in parallel with R1/R2. **R7 (commits) is
explicitly last and gated separately** — per standing project convention,
committing is never bundled into "execute the plan"; it needs its own
explicit go-ahead, and only once the tree is in a state actually worth
freezing.

---

## R1 — FFI-level test coverage for CKM_HPKE

**Problem:** all 8 existing tests (`native/hpke.rs`) call
`native::hpke::{keygen,encapsulate,decapsulate}` directly. None exercise
`ck_param::mech(p_mechanism).params(...)`, the raw `CK_HPKE_PARAMS` pointer
reads, `hpke_read_derived_key_template`'s raw pointer walk, or the
`pCiphertext`/`pulCiphertextLen` query-then-fill dance in `ffi.rs`. Two real
marshaling bugs this session (HKDF salt-key byte index; encapsulate/
decapsulate template-count 4-vs-5) both lived exactly in this un-exercised
layer.

**Fix:** add a `#[cfg(test)] mod tests` block in `ffi.rs` (or a new
`ffi_hpke_tests.rs` included from it) that drives `C_GenerateKeyPair` /
`C_EncapsulateKey` / `C_DecapsulateKey` directly, building a raw
`CK_HPKE_PARAMS` byte buffer by hand — mirroring the existing raw-mechanism-
param test idiom already used for `CKM_HKDF_DERIVE`
(`hkdf_salt_as_key_equals_salt_as_data`) and `CKM_CONCATENATE_BASE_AND_KEY`
(`concatenate_base_and_key_ffi_produces_summed_length`). Minimum coverage,
not a full 54-case duplication (that's what R2's native-level suite is for):

1. One classical suite, Base mode, full round trip through the real FFI
   entry points, asserting on returned handles + `pBaseNonce` bytes.
2. One hybrid suite, Base mode, same.
3. `pExporterKey` non-null — proves the nested `CK_DERIVED_KEY` pointer walk.
4. `aeadId = CKA_HPKE_AEAD_EXPORT_ONLY` — proves the `phKey`-becomes-exporter
   fallback.
5. A short-`ulParameterLen` case — proves `ParamErr::TooShort` is reached,
   not silently under-read (the failure mode `ck_param`'s own module doc
   exists to make unrepresentable).
6. Auth mode with `hSenderStaticKey` / `pSenderPk` populated — the two
   sender-key fields that only exist in the params struct, never touched by
   the native-level tests' direct-argument calling convention.

**Acceptance:** `cargo test --lib ffi::` (or wherever these land) green,
plus full `cargo test --lib` regression (currently 443/443) unaffected.

**Effort:** moderate — the raw-pointer test boilerplate is the main cost;
the crypto itself is already proven correct at the native layer.

---

## R2 — JS/WASM binding + hub-side FFI validation

**Problem:** no `hsm_*Hpke*` wrapper exists in `pqctoday-hub/src/wasm/
softhsm.ts`. The mechanism is unreachable from the browser in any form —
not "no UI," genuinely no code path at all.

**Fix:**
1. Add `hsm_generateHpkeKeyPair`, `hsm_hpkeEncapsulate`,
   `hsm_hpkeDecapsulate` to `softhsm.ts`, following the file's own established
   pattern (`buildMech`/`buildTemplate`/`checkRV`, matching `hsm_hkdfToHandle`'s
   recent precedent for a non-extracting output). The `CK_HPKE_PARAMS` field
   offsets MUST be re-derived independently from `ck_param.rs`'s
   `hpke_params` layout, not copy-adjusted — get this wrong and R1 passing
   proves nothing about it.
2. Extend `hpkeService.test.ts` (or a new file) with a vitest suite that
   calls these new bindings directly against the real WASM build, covering
   the same 54-case hybrid matrix `native/hpke.rs`'s Rust test already
   proves at the native layer — this time proving the marshaling survives
   the actual WASM/JS boundary a real caller crosses.
3. Only after 1–2 are green: decide whether/how to surface this as a
   workshop UI toggle ("native `CKM_HPKE`" vs. "composed from primitives") —
   a separate, smaller decision once the binding itself is proven.

**Acceptance:** new vitest suite green; `npx tsc -b` and `npx eslint` clean;
full existing hub HybridCrypto/wasm suites (currently 393/394, 1 unrelated
pre-existing `todo`) still clean; WASM rebuilt via
`build-wasm-bundle.sh` and re-synced to all four vendored hub copies after
any further Rust-side change this uncovers.

**Effort:** moderate-to-large — this is genuinely new code, not a rewire.

---

## R3 — Fix `hpkeService.ts`'s DHKEM-P521 `Ndh` bug

**Problem:** `EC_NDH_LEN['P-521']` is `64`; RFC 9180 states 66
(`https://www.rfc-editor.org/rfc/rfc9180.html`, "the size Ndh of the
Diffie-Hellman shared secret is equal to 32, 48, and 66" for P-256/384/521).
Silently wrong today because DHKEM-P521 has no byte-exact vector in the
tested set (only the P-256 A.3 vectors are vendored).

**Fix:** one-line change (`64` → `66`), plus a regression test that actually
exercises the P-521 DHKEM path end-to-end (round-trip is sufficient — no
byte-exact P-521 vector is vendored here either) so this can't silently
regress again.

**Acceptance:** new P-521 test green; full `hpkeService.test.ts` suite
(currently 152/152) stays green.

**Effort:** trivial fix, small test addition.

---

## R4 — Classical DHKEM path: non-extracting, or explicitly declared out of scope

**Problem:** the non-extracting rewrite covers only the hybrid KEM path.
`dhSecret`/`labeledExtract`/`labeledExpand`/`keySchedule`/`seal`/`open` for
all 5 classical suites still pull `ss_T`, the PRK, and the AEAD key through
JS as plaintext — an asymmetry in the same file, for the same underlying
security property.

**This item needs a decision before a fix, not just effort — flagging
here, not resolving it:**

- **Option A — leave as-is, document the asymmetry.** The classical path's
  extraction exists specifically to support byte-exact RFC 9180 Appendix A.3
  verification (`hpkeService.test.ts`'s primary correctness anchor for this
  whole module) — a real, load-bearing reason, not an oversight. Cheapest,
  matches current shipped behavior.
- **Option B — dual path.** Add non-extracting `dhSecretHandle`/
  `keyScheduleSecureClassical`/etc. mirroring what already exists for
  hybrid, used by the *workshop* at runtime; keep the existing extractable
  functions *only* for the `hpkeService.test.ts` A.3 conformance tests. Real
  security improvement for anyone actually using the workshop; roughly
  doubles the classical-path surface area in the file.
- **Option C — extractable-by-template-flag.** Add an `extractable: boolean`
  parameter threaded through the existing classical functions (default
  `true`, tests pass `true`, workshop runtime passes `false`), rather than
  parallel functions. Smaller diff than B, but mixes two different call
  shapes into one function signature.

No default recommendation stated here deliberately — this is a real
scope/cost tradeoff for the workshop's actual security posture, not a bug
fix, and belongs to the same kind of decision the original hybrid-path work
was explicitly asked about before implementation.

---

## R5 — Add the two companion-spec library rows

**Problem:** `draft-irtf-cfrg-hybrid-kems-12` and
`draft-irtf-cfrg-concrete-hybrid-kems-03` are cited in `hpkeService.ts`'s
own header comment but never landed in any library CSV. Blocked all session
by `pqctoday-priv/maintenance/maintenance.lock`; **that lock is now clear**
(reconfirmed at the time of the gap report).

**Fix:** run, via the `add-catalog-row` skill (per its documented
`--source library` invocation):

```bash
cd pqctoday-priv/maintenance
python3 add_row.py --source library \
  --url "https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hybrid-kems-12" \
  --title "Hybrid PQ/T Key Encapsulation Mechanisms" \
  --note "Generic combiner framework (CG: C2PRICombiner + nominal Group) that draft-ietf-hpke-pq's PQ/T hybrid HPKE KEM IDs delegate to; implemented directly in HybridCrypto's hpkeService.ts."
python3 add_row.py --source library \
  --url "https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-concrete-hybrid-kems-03" \
  --title "Concrete Hybrid PQ/T Key Encapsulation Mechanisms" \
  --note "Concrete instantiation of the CG framework (labels, component order) for MLKEM768-X25519/MLKEM768-P256/MLKEM1024-P384; implemented directly in HybridCrypto's hpkeService.ts."
```

then the matching `/update-library` skill for enrichment, per the skill's
own documented handoff (this step never runs enrichment itself).

**Acceptance:** two new stub rows in a fresh dated `library_MMDDYYYY.csv`;
`hpkeService.ts`'s header comment's citations now resolve to real catalog
entries.

**Effort:** trivial — mechanical, already-scoped process.

---

## R6 — CHANGELOG.md entries

**Problem:** `pqctoday-hsm/CHANGELOG.md` was never updated for either the
`Hkdf::from_prk` HKDF-expand-only fix or the new `CKM_HPKE` mechanism family.

**Fix:** two entries under the top (unreleased) section, per the file's own
existing format — one for the HKDF fix (cite the real bug: silent
re-extraction in `CKM_HKDF_DERIVE`'s expand-only mode, found via RFC 9180
A.3 cross-check), one for `CKM_HPKE` (cite the proposal doc + provisional
vendor codepoints).

**Effort:** trivial.

---

## R7 — Commit and push (gated, last)

**Not started; requires explicit confirmation separate from this plan's
approval**, per standing project convention (commits are never bundled into
"execute the plan," and pushing to `pqctoday-hub`/`pqctoday-hsm` main lines
needs the local-CI-green gate this session's memory record documents).

Once R1–R6 (or whichever subset is approved) land and are green:

1. **pqctoday-hsm**: stage `rust/src/{ck_param.rs,constants.rs,ffi.rs,
   native/mod.rs,native/hpke.rs}`, `docs/proposal-plan-*.md`,
   `docs/proposals/`, `CHANGELOG.md`. **Do not** stage
   `kmip/conformance/REPLAY_REPORT.{json,md}` or
   `rust/RUST_P11_V32_CONFORMANCE_REPORT.md` without first confirming their
   origin — not modified by this session's work.
2. **pqctoday-hub**: stage the HPKE feature set + WASM binaries across all
   four vendored copies (`src/wasm/`, `src/vendor/softhsm-wasm/wasm/`,
   `public/wasm/rust/`; `dist/` is a build artifact, regenerate via
   `npm run build` rather than hand-staging it) + `content.ts`/`index.tsx`/
   `manifest.ts`/`HybridCryptoIntroduction.tsx`/`Pkcs11LogPanel.tsx`.
3. **pqctoday-priv**: stage `docs/platform/data/pkcs11-vendor-mech-
   allocation.md` + R5's fresh dated library CSV (via its own commit flow,
   per `sync-private.sh`). **Do not** stage `maintenance/*checkpoint*.json`
   or `maintenance/runs/*` — those belong to the concurrent `update_run.py`
   process, not this work.

No push to any remote without a further, separate explicit "push"/"deploy"
instruction — staging + local commit only, per this plan.

---

## Explicitly not in scope here (already gated separately)

- **Phase 2** (`CKM_HPKE` C++ engine parity) and **Phase 3** (OASIS TC
  submission) from the companion implementation plan — both remain gated on
  their own separate approval, unaffected by this remediation plan.
