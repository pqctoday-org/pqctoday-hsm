# Remediation plan — protocol-wrapper coverage gaps (2026-08-31)

**Status: not executed.** Based on five independent, read-only, parallel
audits run the same night against `feat/jdk27-jca-provider` (all provider
directories are ordinary repo paths, not worktree-specific, so these
findings apply regardless of which branch eventually carries the fix).
Scope: the five protocol wrappers beyond the OpenSSL C provider and local
JavaJCE that this repo maintains — `openmls-provider/`, `openssh-pkcs11/`,
`strongswan-pkcs11/` (+ its wasm-shims siblings), `openpgp/`, and
`JavaJCE-remote/`. Nothing here has been implemented, tested, or committed.

## Priority order and why

1. **`openmls-provider`** — highest. Not just an incompleteness gap: the
   code's own comments and integration tests **assert** two primitives run
   inside the HSM when they demonstrably don't. That's a false capability
   claim in a Messaging Layer Security (RFC 9420) crypto provider — the
   exact kind of claim a security review would reasonably rely on.
2. **`openpgp`** — bridge-layer-only fixes, engine already supports both
   missing parameter sets, no open design questions. Cheapest real fix in
   this plan.
3. **`openssh-pkcs11`** — real, large capability gap (SLH-DSA: 1 of 12
   engine-supported parameter sets exposed) plus a documentation gap severe
   enough that the module's own README doesn't disclose SLH-DSA support
   exists at all.
4. **`strongswan-pkcs11`** — real ML-KEM gap plus one item that isn't a
   capability gap so much as a correctness problem: a dead, non-functional
   mechanism registration (MODP DH) that silently fails at runtime against
   this engine.
5. **`JavaJCE-remote`** — lowest. Two doc-accuracy items, no code gap; the
   module's narrow scope is a real, correct proto-contract boundary.

---

## 1. `openmls-provider` — false HSM-dispatch claims

### 1.1 X-Wing combiner (SHAKE-256 / SHA3-256) — claimed HSM, actually software

`openmls-provider/lib/src/crypto.rs:64-67` states outright that X-Wing's
"KEM, SHAKE-256 expansion, SHA3-256 combiner and ChaCha20-Poly1305 all run
inside the HSM" — repeated at `openmls-provider/lib/tests/integration.rs:317-320`.
False for two of the four: `CryptokiBackend`'s `PkcsOps::shake256`/`sha3_256`
(`openmls-provider/lib/src/backend.rs:451-463`) call the `sha3` crate
directly, in-process — no session, no `pq_session()`, no
`softhsmrustv3::native::*` call — unlike every neighboring PQ method in the
same `impl` block (`ml_kem_768_keygen_from_seed`, `ml_kem_decapsulate`,
`ml_kem_encapsulate_to`, `chacha20_poly1305`), which do genuinely dispatch.
Worse: `xwing_expand()` (`openmls-provider/lib/src/hpke.rs:261-275`) feeds
the X-Wing **private key** through this software path — the one place in
this file that treats secret material differently from how HKDF-derived
secrets are handled everywhere else (real HSM HMAC).

**The fix already exists and is tested, just unused.** The engine has a
PKCS#11-shaped native combiner implementing this exact X-Wing recipe:
`rust/src/native/derive.rs`'s `run_combiner` (`Combiner::Concat` +
`FinalizeStep::Digest`/`ConcatData`), proven correct by
`rust/src/native/derive.rs:490-521`
(`run_combiner_xwing_sha3_256_recipe_matches_direct`). Fix:
- Rewrite `xwing_combine()` (`hpke.rs:243-257`) to call `run_combiner`
  instead of hand-rolling the concatenation-then-hash in Rust.
- Either remove `PkcsOps::shake256`/`sha3_256`'s bare-crate implementation
  or route it through the same combiner/native path so no caller of this
  trait can silently get a software-only digest.
- Update `crypto.rs:64-67` and `integration.rs:317-320`'s claims to match
  reality once fixed (or now, if the fix is deferred — an accurate comment
  is a prerequisite either way).

**Effort: low-medium.** The correctness work is done and tested on the
engine side; this is a call-site rewire, not new crypto.

### 1.2 MLS record-layer AEAD (ChaCha20-Poly1305) — claimed HSM, actually software

`crypto.rs:157-189`'s `aead_encrypt`/`aead_decrypt` — the AEAD protecting
every actual MLS Commit/Application message, not just HPKE's inner
Welcome-message AEAD — routes `AeadType::ChaCha20Poly1305` to
`sw_chacha20_encrypt`/`sw_chacha20_decrypt` (`crypto.rs:381-403`, the
`chacha20poly1305` crate directly), on both suites that declare this AEAD
(suite 3 and the X-Wing suite). Meanwhile `PkcsOps::chacha20_poly1305`
(`backend.rs:465-498`, dispatching to `CKM_CHACHA20_POLY1305` = 0x4021 via
`softhsmrustv3::native::encrypt`) genuinely works and is already used for
HPKE's own inner AEAD (`hpke.rs:411-424,426-439`). This reads as an
oversight — the trait method postdates the software fallback — not a
fundamental limitation.

Fix: route `crypto.rs`'s `ChaCha20Poly1305` arm through
`self.ops.chacha20_poly1305` the same way the `AesGcm128`/`AesGcm256` arms
already do. Remove `sw_chacha20_encrypt`/`_decrypt` once nothing calls them,
or keep them only as an explicit, clearly-labeled non-HSM fallback path if
one is still needed for a software-only test mode.

**Effort: low.** The HSM-backed function already exists and is already
proven correct elsewhere in this same file.

### 1.3 Documentation and testing hygiene (do alongside 1.1/1.2, not blocking)

- `README.md:48-56,144-152` — "Supported ciphersuites (v0.1)" table and the
  Phase 4 section both claim PQ ciphersuites are waiting on upstream
  OpenMLS registry entries. False as of this branch — X-Wing was wired
  2026-08-10. Rewrite to list all four ciphersuites `crypto.rs:59-80`
  actually declares, and add the missing "What runs in the HSM" row for
  suite 3 and X-Wing.
- No cross-vendor interop coverage for the PQ suite:
  `openmls-provider/interop/run-gating-tests.sh:88` hardcodes
  `SUITES="${SUITES:-1 2 3}"`; the script's own comment admits suite 4 is
  "the whole point of the engine underneath it" and isn't tested this way.
  Add a `cs4` interop report alongside the existing `cs1`/`cs2`/`cs3`.
- Cosmetic only, low priority: stale comments referencing a deleted
  `src/kem_ffi.rs` remain in `Cargo.toml` (~L56, ~L74), `error.rs:42`,
  `session.rs:75-77` — the file no longer exists (superseded by the direct
  `softhsmrustv3` rlib dependency). Delete the stale comments whenever
  those files are next touched for another reason.

### Verification for 1.1/1.2

Real round trip through the fixed paths: an MLS group operation (Commit or
Application message) on suite 3 and on the X-Wing suite, confirming the
AEAD ciphertext now comes from the engine (e.g. by asserting a live PKCS#11
session/call trace, not just a passing KAT); an X-Wing key-establishment
round trip confirming `xwing_combine`'s output matches both the existing
KAT fixture (`openmls-provider/lib/tests/fixtures/xwing_kat.json`) and the
engine's own `run_combiner`-based result byte-for-byte.

---

## 2. `openpgp` — two half-finished composite algorithm extensions

Both gaps are bridge-layer only — the C++ engine (`libsofthsmv3`, confirmed
this is what `openpgp/` links against, not the Rust engine) already fully
implements ML-DSA-87 and ML-KEM-1024 key generation and operations
(`src/lib/SoftHSM_keygen.cpp:5998,8326`). No engine work needed for either
item below.

### 2.1 `MLDSA87_Ed448` (composite algorithm ID 31) — sign dispatch exists, unreachable

Real sign logic already exists and looks functional:
`openpgp/lib/src/signer.rs:139-161`. But nothing in this bridge can ever
create such a key: no `CompositeAlgo::MlDsa87Ed448` variant
(`openpgp/lib/src/lib.rs:66-72` only has `MlDsa65Ed25519`/`MlKem768X25519`),
`upload_composite_private`'s match has no arm for it and hits a hard-error
catch-all (`openpgp/lib/src/upload.rs:253-307`, error at :304-306), and the
CLI has no `GenAlgo` variant either (`openpgp/cli/src/bin/opgpkcs11.rs:27-33`).
No test exercises it anywhere.

Fix: add the `CompositeAlgo` variant, the `upload_composite_private` match
arm (mirroring the existing `MlDsa65Ed25519` arm's shape), and the CLI
`GenAlgo` variant. `keypair()`'s handle-resolution code already recognizes
this composite type correctly (`lib.rs:376-379,417-424,535-538`) — only the
provisioning path is missing.

### 2.2 `MLKEM1024_X448` (composite algorithm ID 36) — decrypt dispatch entirely absent

A step further than 2.1: `decryptor.rs`'s `decrypt()` match has **no arm at
all** for this algorithm — any such ciphertext falls to the catch-all
`Err("Unexpected Ciphertext type.")` (`openpgp/lib/src/decryptor.rs:146-149`).
Even a hand-provisioned key (if 2.1's provisioning pattern were extended
here too) would fail to decrypt.

Fix: add the missing `decryptor.rs` match arm, following the existing
`MlKem768X25519` arm's shape (`decryptor.rs:106-144`) — the composite KEM
combiner this bridge already implements
(`openpgp/lib/src/decryptor.rs:298-316`, verified byte-for-byte identical
to Sequoia's own unexported `multi_key_combine` reference) generalizes
directly; it isn't specific to the 768/X25519 size. Then extend
`CompositeAlgo`, `upload_composite_private`, and the CLI `GenAlgo` the same
way as 2.1 (both composite additions can reasonably ship together, or in
either order — 2.2 has no dependency on 2.1 being done first).

### 2.3 Documentation

`openpgp/docs/PQC_PGP_IMPLEMENTATION_PLAN.md:19` explicitly scopes this
bridge to algorithms 30/35 only — accurate as of today, but the plan's own
§4 dispatch snippet (`:242`) has a placeholder comment for `MLDSA87_Ed448`
that appears to have been turned into real `signer.rs` code without a
corresponding plan update. Once 2.1/2.2 land, update this doc's stated
scope to include algorithms 31/36 rather than leaving it describing a
narrower system than what ships.

### Verification for 2.1/2.2

Real key generation → OpenPGP v6 packet emission → Sequoia-side
verification/decryption round trip for both new composite types, matching
the existing `live_composite_tests` module's shape
(`openpgp/lib/src/lib.rs:643-1379`) for the two already-working algorithms.
Confirm rejection behavior is unchanged for genuinely unsupported inputs
(no regression on the catch-all error paths for anything still out of
scope, e.g. pure non-composite ML-DSA/ML-KEM, which the spec itself has no
codepoint for and should stay unimplemented).

---

## 3. `openssh-pkcs11` — 1-of-N parameter set coverage on both PQC signature families

### 3.1 ML-DSA: 1 of 3 parameter sets

`draft-sfluhrer-ssh-mldsa` (confirmed against the live draft, currently
`-08`; the module cites `-06` but the 3-parameter-set definition in §3 is
unchanged between the two, so no functional drift, just a stale version
citation) defines `ssh-mldsa-44`, `ssh-mldsa-65`, `ssh-mldsa-87`. The
engine supports all three (`SoftHSM_slots.cpp:630-649,1209-1245`). The
module hardcodes only `ssh-mldsa-65` throughout `patches/ssh-mldsa.c`
(literal sizes/strings, e.g. lines 8-9, 104, 121, 161, 208-210) and
`patches/apply_mldsa_patches.py` (only ever inserts `KEY_MLDSA_65`).

This matches the module's own README, which only ever claims ML-DSA-65 —
so this is a documented scope boundary, not silent staleness. Still listed
as a real gap because the engine and the real draft both already support
the other two parameter sets with no additional design work needed.

Fix: generalize `ssh-mldsa.c`/`apply_mldsa_patches.py` to parametrize on
key size instead of hardcoding 65's constants, adding `ssh-mldsa-44` and
`ssh-mldsa-87` key/signature types following the same pattern.

### 3.2 SLH-DSA: 1 of ~12+ parameter sets, and undocumented

`draft-josefsson-ssh-sphincs-02` (fetched live) defines names for
essentially the full SLH-DSA family (SHA2/SHAKE × 128/192/256 × s/f, plus
`-24`-suffixed and EdDSA-hybrid variants). The engine supports all 12
standard NIST parameter sets (`SoftHSM_slots.cpp:652-664,1252-1273`). The
module hardcodes only `ssh-slh-dsa-sha2-128s`
(`patches/ssh-slhdsa.c`, `apply_mldsa_patches.py`'s `KEY_SLH_DSA_SHA2_128S`
insertion only).

**This one is also a documentation gap, separately from the code gap**:
`README.md` never mentions SLH-DSA at all — still describes this connector
as purely "ML-DSA-65 patches" (`README.md:3,8,20`) and its own Layout table
omits `ssh-slhdsa.c`, even though it's been wired in and runtime-verified
since 2026-07-27/07-29 (`CHANGELOG.md:10-59`). `STATUS.md` is dated
2026-06-27 and predates the SLH-DSA work entirely.

Fix, in order:
1. **Cheap, do first**: update `README.md` and `STATUS.md` to disclose
   SLH-DSA-SHA2-128s support already exists and is verified — this is pure
   documentation catch-up, zero code risk.
2. **Larger**: generalize `ssh-slhdsa.c`/`apply_mldsa_patches.py` the same
   way as 3.1, to cover additional SLH-DSA parameter sets. Given the size
   of the real parameter-set space (12+ engine-supported, more in the
   draft including hybrids), scope this as its own follow-on decision
   about how many/which parameter sets are worth exposing over SSH host
   keys in practice — don't default to "all of them" without checking
   real-world demand, since SSH host key algorithm lists have practical
   negotiation-overhead considerations the OpenPGP/engine side doesn't.

### 3.3 Minor: missing citation, not a functional gap

`README.md`/`CHANGELOG.md` never cite `draft-ietf-sshm-mlkem-hybrid-kex-10`
(WG-adopted, near-RFC) even though the module's own smoke tests exercise
exactly the `mlkem768x25519-sha256` method it defines — this KEX is stock
upstream OpenSSH behavior, not something this module patches in, so there's
no code gap, just a missing attribution given how prominently
`STATUS.md:31-34` advertises it.

### Verification

Real SSH handshake + auth round trip (native, and via `wasm-shims/` given
it's confirmed functionally real, not scaffolding) for each newly-added
ML-DSA/SLH-DSA parameter set, using the same KAT-length assertions the
existing smoke harnesses already use (`sm1-smoke.cjs`, `sm5-slhdsa-smoke.cjs`)
extended to the new sizes.

---

## 4. `strongswan-pkcs11` — ML-KEM coverage gap + one dead registration

### 4.1 ML-KEM: only 768 wired, despite scaffolded-but-unfinished 512/1024 support

`pkcs11_kem_create()` hardcodes `if (group == ML_KEM_768) {...} else return
NULL;` (`strongswan-pkcs11/pkcs11_kem.c:506-523`); `pkcs11_plugin.c:224`
only provides `PLUGIN_PROVIDE(KE, ML_KEM_768)`. But
`pkcs11_kem_verify_pubkey`/`kem_ciphertext_size` already have complete
512/768/1024 switch-case coverage (`pkcs11_kem.c:178-186,364-372`) — dead
code, never reached. A code comment even admits the limitation
(`pkcs11_kem.c:127-130`). The engine supports the full range
(`SoftHSM_slots.cpp:1276-1284`).

Fix: extend `pkcs11_kem_create()`'s group check and `pkcs11_plugin.c`'s
`PLUGIN_PROVIDE` registration to cover `ML_KEM_512`/`ML_KEM_1024` the same
way the (already-correct) helper functions do — this looks like the
smallest, most mechanical item in this whole plan, since the hard parts
(size tables, pubkey verification) are already written and just
unreachable.

### 4.2 MODP DH: registered but non-functional against this engine

`pkcs11_plugin.c:199-213` registers MODP DH groups, but the engine has
**zero** `CKM_DH_PKCS*` mechanisms (confirmed via direct grep of
`SoftHSM_slots.cpp` — no hits). `find_token()`
(`pkcs11_dh.c:312`) will never find a matching mechanism, so every MODP
group silently fails to construct at runtime — a correctness problem
(a caller can select a "registered" algorithm that then simply doesn't
work), not a missing-feature gap.

Fix — pick one:
1. Have the engine actually implement `CKM_DH_PKCS*` (separate engine-level
   work, out of scope for this plugin-only plan; only worth doing if MODP
   DH is a real interop requirement for someone using this plugin against
   legacy IKEv2 peers).
2. **Recommended, cheaper**: stop registering MODP DH from this plugin
   against this specific engine — either gate the `PLUGIN_PROVIDE` calls on
   a runtime mechanism-availability check (matching how a real PKCS#11
   client should behave against an arbitrary token) or explicitly document
   that MODP DH is advertised but non-functional against softhsmv3
   specifically, so nobody selects it expecting it to work.

### 4.3 Documentation: RFC 9370 hybrid mode is real but undersold

The plugin correctly rides strongSwan's own unmodified RFC 9370 machinery
(IKE_INTERMEDIATE, ADDKE1-7 transform types) — verified real and working,
but only demonstrated in `strongswan-wasm-shims/wasm_backend.c:162-169`
(`"aes256-sha256-mlkem768-ke1_ecp256"`), never in `strongswan-pkcs11/`'s
own README or ops-guide, which only show non-hybrid, PQC-replaces-classical
negotiation. Fix: add a documented, tested hybrid-KE example to
`strongswan-pkcs11/README.md`/`docs/softhsmv3opsguide.md` once 4.1 lands
(hybrid with all three ML-KEM sizes is a more complete demonstration than
today's 768-only option would allow).

### 4.4 `strongswan-wasm-v2-shims/` — confirmed stale, consider archiving

Both `strongswan-wasm-v2-shims/README.md:3-10` and
`strongswan-wasm-shims/STATUS.md:1-10` already self-declare v1 as the
actively-maintained tree; v2's last functional commit predates v1's real
feature work (RFC 7383 fragmentation, RFC 9370 multi-KE, CHILD_SA) that
landed afterward, only in v1. v2 carries an 11.75 MB frozen prebuilt
artifact (`dist/strongswan-v2-boot.wasm`) reflecting its pre-RFC-9370
state. Not a functional risk as-is (nothing points at it), but genuine dead
weight. Recommend either deleting `strongswan-wasm-v2-shims/` outright or
converting it to a short pointer doc explaining why it was superseded and
linking to v1, rather than keeping a full stale parallel tree — a decision
for whoever owns this module, not something to do silently as part of the
ML-KEM/DH fixes above.

### Verification for 4.1/4.2

Real IKEv2 SA negotiation (native, via `strongswan-wasm-shims/`) for
ML-KEM-512 and ML-KEM-1024 standalone KE, plus a hybrid negotiation using
each of the three sizes as the ADDKE1 round. For 4.2's chosen fix, confirm
MODP DH either genuinely works end-to-end (if engine work is done) or is
no longer offered/selectable at all (if deregistered) — no third state
where it's offered and silently fails.

---

## 5. `JavaJCE-remote` — documentation only, no code gap

The narrow algorithm scope (Ed25519/ML-DSA/ML-KEM only) is a real,
confirmed proto-contract boundary (`remoting/proto/proto/pkcs11_remote.proto:19-27`'s
`Algorithm` enum has exactly these 7 values) — not staleness, and not
something to "fix" by widening scope without a corresponding proto change.
Two real documentation issues:

### 5.1 ML-DSA external-mu has no wire-level path

Local `JavaJCE` gained `ML-DSA-{44,65,87}-ExternalMu` Signature support
tonight (`registerMLDSAExternalMu`,
`JavaJCE/src/main/java/com/pqctoday/hsm/jce/SoftHSMv3Provider.java:1204-1216`).
`JavaJCE-remote` has no way to request this — not because of a missed
registration, but because `SignRequest`
(`remoting/proto/proto/pkcs11_remote.proto:87-92`) has no
mechanism-variant field at all, only `algorithm`. Widening the `Algorithm`
enum (the pattern used for the SLH-DSA/EC/RSA/symmetric follow-on
mentioned in `docs/implementation-plan-jca-remaining-gaps-2026-08-25.md`
§7 E5) won't work here — external-mu needs a new field or verb on the
existing three algorithms, not a new algorithm identity. Scope this as its
own small proto-design task if remote external-mu signing is wanted;
otherwise, just note the gap in `JavaJCE-remote/README.md` so it doesn't
read as an oversight later.

### 5.2 README overclaims `KeyFactory` parity

`JavaJCE-remote/README.md:20` states
`"KeyPairGenerator`/`KeyFactory`: Ed25519, ML-DSA-44/65/87, ML-KEM-512/768/1024"`,
implying `KeyFactory` service parity with local `JavaJCE` for these three
families. The code registers **zero** `KeyFactory` services
(`SoftHSMv3RemoteProvider.java:125-152`, verified via
`grep putService`). This is consistent with the architecture note in
`docs/implementation-plan-jca-remaining-gaps-2026-08-25.md` §7 E1
(self-contained flows only, not "export this key for an external peer") —
the README line is simply wrong, not describing an intentionally-deferred
feature. Fix: correct the README line to name only `KeyPairGenerator`/
`Signature`/`KeyAgreement`/`KEM` as applicable, dropping the `KeyFactory`
claim (or implement it, if the E1 architecture decision is ever revisited
— but that's a bigger call than a doc fix and shouldn't be bundled here).

### Effort

Both items are doc-only edits. No verification beyond re-reading the
corrected text against the actual registered service list.

---

## Summary effort/risk table

| Item | Engine work needed? | Design decision needed? | Relative effort |
|---|---|---|---|
| 1.1 openmls X-Wing combiner | No (fix exists, tested) | No | Low-medium |
| 1.2 openmls record AEAD | No (fix exists, tested) | No | Low |
| 2.1 openpgp MLDSA87_Ed448 | No | No | Low-medium |
| 2.2 openpgp MLKEM1024_X448 | No | No | Low-medium |
| 3.1 openssh ML-DSA 44/87 | No | No | Medium |
| 3.2 openssh SLH-DSA breadth | No | Yes — how many param sets to expose | Medium (docs) / Large (code, scope-dependent) |
| 4.1 strongswan ML-KEM 512/1024 | No (dead code already scaffolded) | No | Low |
| 4.2 strongswan MODP DH | Only if choosing option 1 | Yes — implement vs. deregister | Low (deregister) / engine-scale (implement) |
| 4.4 wasm-v2-shims | No | Yes — delete vs. redirect-doc | Trivial |
| 5.1/5.2 JavaJCE-remote docs | No | No | Trivial |
