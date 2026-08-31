# Remediation plan — everything still open after tonight's provider/playground pass (2026-08-31)

**Status (updated 2026-08-31, later same night): Parts 1 and 2 fully
executed and committed.** Originally written as four kinds of "remaining
work" — real unfixed defects, smaller flagged follow-ups, items with no
real fix currently available, and process/pipeline items that aren't code
fixes at all — Parts 1 and 2 are now done; see each item below for its
commit. Part 3 (no real fix available) and Part 4 (process/sequencing)
are unchanged in kind, Part 4 updated with tonight's status. A fifth
category — a genuine out-of-scope defect found as a side effect of Part 1
— is new; see Part 1.5.

**What's already landed tonight** (context, not part of this plan):
`pqctoday-hsm` `feat/jdk27-jca-provider` — `0d33f59`, `a39fc95`,
`e36ddd6`, `68de804`, `1986134`, `9ecb72b`, `1582567` (mu rename, OpenSSL
provider + JavaJCE mechanism gaps, openssh-pkcs11 full ML-DSA + 8/12
SLH-DSA coverage, strongswan-pkcs11 ML-KEM breadth + MODP DH
deregistration + v2 tree deletion), then `ace93f5c`, `73ca71e`, `5cf7492c`,
`58be5cb4` (Part 1 + Part 1.5, below). `pqctoday-hub`
`feat/hsm-playground-pqc-coverage-refresh` — `b1a9699d7`, `8b1bf9b17`,
`451570bbe`, `c4c681d4f`, `995dab870`, `ba9adabc7` (SSH/VPN/TLS playground
panels rebuilt and verified against the above, then Part 2's follow-ups).
Nothing pushed anywhere.

---

## Part 1 — Real, unfixed defects (highest priority) — DONE

Both items from `docs/remediation-plan-provider-wrapper-coverage-gaps-2026-08-31.md`
executed once the shared `pqc-rust` container freed up.

### 1.1 `openmls-provider` — false HSM-dispatch claims — fixed, `5cf7492c`

Was: `crypto.rs:64-67` and `integration.rs:317-320` claimed X-Wing's
SHAKE-256/SHA3-256 combiner and the MLS record-layer ChaCha20-Poly1305 AEAD
ran inside the HSM; `backend.rs:451-463`'s `sha3_256`/`shake256` called the
`sha3` crate directly, in-process, and `crypto.rs:157-189`'s AEAD routed
through `sw_chacha20_encrypt`/`_decrypt` (`crypto.rs:381-403`), also
software.

Fix: `xwing_combine()` now calls a new `PkcsOps::xwing_combine` trait
method, backed by `softhsmrustv3::native::derive::run_combiner` (the
engine's already-tested combiner). `PkcsOps::sha3_256` deleted entirely
(its one caller no longer existed). `shake256` now calls a new
`softhsmrustv3::native::derive::shake256_xof` instead of the bare crate.
The AEAD arms route through `self.ops.chacha20_poly1305`, matching the
`AesGcm128`/`256` arms; `sw_chacha20_encrypt`/`_decrypt` deleted, along with
the now-unused `sha3`/`chacha20poly1305` crate deps.

Verified: new `xwing_combine_matches_run_combiner_and_kat` test (checked
against `tests/fixtures/xwing_kat.json`); two new real 2-member `MlsGroup`
round-trip tests on suite 3 and the X-Wing suite (can only pass through the
real dispatch now, since the software fallback no longer exists in
source); full existing suite reran clean, zero regressions. Also found —
not part of this item, see Part 1.5 — 6 pre-existing HMAC/HKDF-over-HSM
test failures, unrelated to this diff.

### 1.2 `openpgp` — two half-finished composite algorithm extensions — fixed, `ace93f5c`

Was: `MLDSA87_Ed448` sign dispatch existed (`signer.rs:139-161`) but was
unreachable (no `CompositeAlgo` variant, no upload path, no CLI option);
`MLKEM1024_X448` decrypt dispatch was entirely absent from `decryptor.rs`'s
match. Fix: added both `CompositeAlgo::MlDsa87Ed448`/`MlKem1024X448`
variants, full provisioning + decrypt dispatch, bridge-layer only (C++
engine already supported both parameter sets). Found and fixed in passing:
a stale locally-built `libsofthsmv3.so` that predated `0d33f59`'s
`CK_EDDSA_PARAMS` fix, causing an unrelated Ed448 signing failure —
rebuilt, no source change needed.

---

## Part 1.5 — New: out-of-scope engine defect found via Part 1.1

Not part of any prior plan — surfaced as a side effect of 1.1's new
integration tests, which are the first tests in this repo to drive
HMAC/HKDF-over-HSM with an RFC 4231 §4.2-style short key. Real, unrelated
to the openmls-provider diff (confirmed via `software_kats.rs`'s pure-
software equivalents passing).

### 1.5.1 HMAC `minKeyBytes` floor rejected RFC 4231's own test vector — fixed, `58be5cb4`

Root cause: `src/lib/SoftHSM_sign.cpp`'s `kMacMechTable` set `minKeyBytes`
for every plain-digest HMAC mechanism (`CKM_SHA{1,224,256,384,512,
512_224,512_256,3_224,3_256,3_384,3_512}_HMAC`, `CKM_MD5_HMAC`) equal to
that digest's output length, so `MacSignInit`/`MacVerifyInit` rejected any
shorter key with `CKR_KEY_SIZE_RANGE`. RFC 2104 places no lower bound on
an HMAC key; RFC 4231 §4.2 Test Case 1 deliberately uses a 20-byte key
against SHA-384/512 specifically to exercise "key shorter than hash
output" — the engine was rejecting the standard's own canonical vector.
NIST SP 800-107's "key length ≥ hash output" is a recommendation for
callers *choosing* a key, not a requirement a verifier may enforce on a
key it didn't choose.

Traced to commit `529821a5` (2026-08-23), not `35cc156` as initially
hypothesized (`35cc156` was confirmed a red herring by reading its actual
diff — it never touches the HMAC/HKDF path). `openmls-provider`'s
`hkdf_extract`/`hkdf_expand` implement RFC 5869 in terms of raw PKCS#11
HMAC (cryptoki 0.10 has no typed `CK_HKDF_PARAMS`), and `hkdf_extract`
uses the RFC 5869 §A.1 13-byte salt as the HMAC key — also under the old
floor — so this one bug broke both HMAC and HKDF KATs (6 failing tests:
HMAC × 3 hash sizes, HKDF × 3 hash sizes).

Fix: zeroed `minKeyBytes` for the affected rows (the table's own existing
"0 = no PKCS#11 minimum" convention). `KMAC_128/256` (real NIST SP 800-185
minimums) and `CMAC`/`GMAC` (AES-key-type constrained) left untouched.
Verified twice via this worktree's local, non-container macOS build
(`build-native/`): stashed the fix and reproduced all 6 failures, restored
it and reconfirmed all pass; full `openmls-provider` suite (27 tests) and
native `ctest` suite both clean.

### 1.5.2 ACVP wasm harness had no short-key HMAC coverage — source-level work done, verification pending

The bug in 1.5.1 went undetected by the existing ACVP wasm harness
(`tests/acvp-wasm.mjs`, part of `local-gate.sh --acvp-wasm`/`--all`)
because its HMAC vectors (`tests/acvp/hmac*.json`) are each a single
curated NIST ACVP-Server sample with a 228-byte key — far above the
digest output length, so never short enough to trip the bug. A genuine,
separate coverage gap, not a mistake in 1.5.1's fix.

Added: `tests/acvp/hmac_shortkey_rfc4231_test.json` (11 test groups, RFC
4231 §4.2 TC1's key/message; SHA2-224/256/384/512 use the RFC's own
published MACs, the remaining 7 mechanisms extend the identical
construction, computed via Python `hmac`/`hashlib` and cross-checked
against a from-scratch HMAC build — the SHA-256 value matches
`openmls-provider`'s own hardcoded KAT byte-for-byte). New block "14.5"
in `tests/acvp-wasm.mjs` wired to verify it. Also fixed a stale comment in
`hmac_sha384_test.json` that documented the old 48-byte floor as a real
engine constraint.

**Not yet verified or committed** — build/test needs either the shared
`pqc-rust` container or this worktree's local build, and both are on hold
pending `antigravity-a7`'s requested exclusive container window (started
tonight, ~30-40 min, no ping yet as of this writing). Once cleared: rebuild,
run the new cases (expect PASS), then a regression-catch pass (stash
`58be5cb4`, rebuild, expect the new cases to FAIL, restore, reconfirm
PASS) before committing — the same discipline 1.5.1 itself used.

---

## Part 2 — Follow-ups flagged during tonight's execution — DONE

Smaller, more contained items, all executed.

### 2.1 SSH playground: no SLH-DSA UI exposure — fixed, hub `c4c681d4f`

Was: `SshSimulationPanel.tsx`/`openssh.ts`'s `SSH_HOST_KEY_OPTIONS` had no
SLH-DSA entries despite the connector supporting 8 parameter sets. Fixed:
real SLH-DSA UI wiring on branch `feat/hsm-playground-pqc-coverage-refresh`.
Found/fixed along the way: `quantum_safe` flag only checked
`.includes('mldsa')` (would have silently misreported SLH-DSA);
`SshComparisonPanel.tsx` had hardcoded "ML-DSA-65 / 3,309 B" text.

### 2.2 VPN playground: no KEM-size selector — fixed, hub `ba9adabc7`

Was: `VpnSimulationPanel.tsx` hardcoded to ML-KEM-768 in its UI. Fixed: a
real KEM-size axis (512/768/1024) orthogonal to the existing
classical/pure-pqc/hybrid mode selector, with the hardcoded proposal
strings/byte-size assertions/labels audited and updated, plus a new
`e2e/vpn-kem-size-selector.spec.ts`. Went through a real cross-session
collision during execution (a mistaken fresh `Agent()` "resume" instead
of `SendMessage`, caught and self-corrected with no data loss — see this
plan's git history if the detail matters later).

### 2.3 VPN playground: stale duplicate `CKA_PARAMETER_SET` attribute — fixed, hub `995dab870`

Was: the panel's `PANEL_PKCS11` RPC handler unconditionally injected a
hardcoded `CKA_PARAMETER_SET=CKP_ML_KEM_768` attribute alongside the real,
group-derived one — confirmed harmless (softhsmv3's `extractParameterSet()`
takes the first matching attribute) but a real drift risk. Fixed: the
duplicate injection removed.

### 2.4 `JavaJCE-remote`: ML-DSA external-mu has no wire path — fixed, `73ca71e`

Was: local `JavaJCE`'s new `ML-DSA-{44,65,87}-ExternalMu` Signature support
had no remote-proto equivalent. Fixed: real end-to-end wire support — new
`bool external_mu` fields on `SignRequest`/`VerifyRequest`
(`pkcs11_remote.proto`), matching the Rust engine's own existing parameter
shape rather than inventing a new convention; 13 files touched across
`remoting/{core,grpc,rest,acceptance}` and `JavaJCE-remote`. Verified via a
real Docker-image swap into the live `pqc-grpc` container — 19/19 live
tests pass.

### 2.5 TLS playground: architectural mismatch, not a bug — confirmed, no action taken

None of tonight's 7 OpenSSL-provider mechanism fixes are reachable
through `tls_simulation_hsm.c`'s handshake path — it only ever routes
plain `CKM_ML_DSA` through the provider for `CertificateVerify`. This
isn't a defect to fix; it's a scope mismatch between what this simulator
demonstrates (a TLS 1.3 handshake) and what tonight's fixes were
(cipher/KDF/wrap/pre-hash mechanisms TLS doesn't use). No action needed
unless the TLS simulator's own scope is deliberately expanded to
demonstrate something like HashML-DSA-signed certificates — a product
decision, not a remediation item.

### 2.6 `pqctoday-sandbox` has stale, un-synced SSH patch copies — re-synced, uncommitted

`pqctoday-sandbox/docker/ssh-mldsa.c`/`ssh-slhdsa.c`/`apply_mldsa_patches.py`
are plain file copies (not symlinks, no sync script) of
`openssh-pkcs11/patches/` — confirmed byte-identical before tonight's fix,
diverged after. Did the one-time manual re-copy (option 1 of the two
listed originally) — `git status` in `pqctoday-sandbox` shows all 3 files
modified but **not yet committed**. The durable-sync-mechanism option (2)
is still open if this file pair turns out to change with any regularity;
not pursued tonight.

---

## Part 3 — Deliberately deferred, no real fix currently available

Not remediation targets in the normal sense — these were investigated
tonight and found to have no real JDK 27 / OpenSSL 4.0 standard name to
build against on either provider. Recorded here so they don't get
silently re-proposed as "still open" without this context, and so a
future reviewer sees the reasoning rather than just an absence.

- Digest-based `*_KEY_DERIVATION` family (both OpenSSL provider and
  JavaJCE) — no SSKDF/digest-derivation name in either platform's real
  KDF API (`javax.crypto.KDF` only standardizes HKDF; OpenSSL's KDF
  provider interface has no equivalent).
- Concatenation KDFs (OpenSSL provider) — same reasoning.
- BIP32 derive (OpenSSL provider) — vendor-range PKCS#11 mechanism, not
  even a standard mechanism to begin with; no platform precedent exists
  by definition.
- `CKM_RSA_AES_KEY_WRAP` (both) — confirmed via `provider-cipher(7)` on
  both OpenSSL 3.6 and 4.0: no hybrid RSA+AES wrap concept exists in
  OpenSSL's cipher interface at all. Structural mismatch, not a naming
  gap.

**If any of these become worth doing later**, the earlier session already
established the fallback pattern (a plain
`#define P11PROV_NAMES_<TAG> "<Name>"` bespoke registration, matching
this file's own `KBKDF`/`COMPOSITE_*` precedent) — revisit that decision
explicitly rather than defaulting back into it.

---

## Part 4 — Process and pipeline, not code fixes

Listed for completeness since they were part of tonight's "remaining
gaps" picture, but these need different handling than the above — no code
to write, just sequencing decisions.

### 4.1 `fix/ws1-4-and-ws2-rust-gaps` validation

Never independently confirmed green on this end — three separate gate-run
attempts tonight each hit a different process problem (wrong container
path, poisoned shared build cache, a collision with the peer's own run).
Riding entirely on `antigravity-a7`'s consolidated `--all` gate run.

Status as of this update: their first full `--all` run found and fixed 2
real issues (a stale HKDF-PRF test constant in `remoting/core/src/verbs.rs`,
a stale `libsofthsmv3.so` causing a T28b false failure) and confirmed
89/89 on the OpenSSL-provider harness plus a clean 49-scenario/9,409-
observation cross-engine differential run. A second full `--all` run then
found 3 more: a second stale HKDF-PRF constant (same class, different
file, `remoting/core/src/verbs_v32.rs` — fixed, committed), an OpenSSL-
provider T16b flake (confirmed via 5/5 clean re-runs, matches this test
family's documented flake history), and a `kmip` compile-error report that
turned out to point at **this worktree's** copy of `rust/src/native/sign.rs`
— cross-worktree shared-`/cargo-target`-cache confusion, not a real bug
on either branch (manually re-run clean once the container was idle). All
3 resolved; nothing indicates a real defect on `fix/ws1-4-and-ws2-rust-gaps`.
Peer has requested one more fully exclusive container window (~30-40 min,
no other build/cargo activity from this side at all) for a final clean
confirmation — in progress as of this writing, no ping yet.

### 4.2 Nothing pushed

Every commit made tonight, in both repos, is local-only. Pushing (and
opening PRs) needs explicit confirmation before it happens, per this
session's standing practice — not blocked on anything technical, just
hasn't been asked for yet.

### 4.3 Version release cut

Deferred from very early in tonight's session (before the provider work
took over) — `RELEASING.md`'s stricter checklist (full `--all` gate,
evidence regeneration in the release commit, `CHANGELOG.md` version-cut,
git tag) hasn't been touched. Only makes sense after 4.1/4.2 resolve.

### 4.4 `cargo-nextest` adoption

Validated earlier tonight as a genuine 2.4x speedup with byte-identical
correctness, in an isolated experiment — deliberately not wired into the
real `scripts/local-gate.sh`/`pqc-rust` container yet, per explicit
decision to queue it until after the engine branches settle.

### 4.5 Stale local branch/worktree cleanup

Once 4.1 resolves and whatever needs merging has merged, the usual
cleanup (remove merged worktrees, delete local branches) applies — not
started, low priority until there's something to actually clean up after.
