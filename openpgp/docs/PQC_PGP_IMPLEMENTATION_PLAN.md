# PQC OpenPGP — Build-Validated Implementation Plan

Standards-compliant **PQC OpenPGP** for the `openpgp-pkcs11-sequoia` bridge
(sandbox scenario 05), built on Sequoia's `pqc` branch + RFC 9580 v6 packets +
HSM-backed key custody via softhsmv3 / PKCS#11.

This document **supersedes** the scoping note in
[`SEQUOIA_PQC_MIGRATION.md`](./SEQUOIA_PQC_MIGRATION.md). Where the two differ,
**this doc wins** — it is grounded in an executed feasibility spike, a real
trial compile, and a source-level read of the actual upstream APIs (the older
doc was written before any code was run and several of its specifics turned out
to be wrong; the corrections are called out inline).

| Field | Value |
| --- | --- |
| Plan ID | `P0-SEQUOIA-PQC-05` |
| Status | 🟩 **Validated** (spike PROVEN; build-grounded; execution still pending) |
| Target standard | `draft-ietf-openpgp-pqc` **v17 (2026-01-13)** on RFC 9580 v6 packets |
| Scheme | Composite: `MLDSA65_Ed25519` (algo **30**), `MLDSA87_Ed448` (algo **31**), `MLKEM768_X25519` (algo **35**), `MLKEM1024_X448` (algo **36**); LibrePGP variant out of scope |
| Base impl | Sequoia `sequoia-openpgp` **2.2.0-pqc.1**, upstream `pqc` branch |
| Sourcing | **Path B** — pinned git dep (commit SHA). Fork **not** required (see §6) |
| Effort | **6–9 PD** (was estimated 2–3 PD; that estimate was wrong — see §9) |
| Validation done | cargo/spike only — no Docker, per scope |

---

## 1. Spike results — PROVEN

A throwaway crate `openpgp/spike-pqc/` (own `[workspace]`, excluded from the
bridge workspace) depends on the upstream `pqc` branch by **pinned commit** and
generates a composite key in software, signs, and asserts the on-the-wire
algorithm ID.

**Exact versions used**

| Item | Value |
| --- | --- |
| Crate | `sequoia-openpgp` **2.2.0-pqc.1** |
| Source | `git+https://gitlab.com/sequoia-pgp/sequoia` |
| Pinned rev | `3d05138bf1536e63886e7a079fa50aeb080ab573` (branch `pqc` HEAD, 2026-06-14) |
| Backend | `crypto-openssl` (Sequoia default Nettle has **no** ML-DSA/ML-KEM) |
| OpenSSL | 3.6.2 (need >= 3.5 for ML-DSA/ML-KEM) |
| `ossl` crate | 1.5.1 |
| rustc | 1.95.0 |

The git branch fetched and built cleanly on the **first** attempt — no fallback
to the `=2.2.0-pqc.1` crates.io preview was needed (though that preview resolves
to the same crate version, so it is a viable Plan-A fallback if the branch ever
goes erratic).

**Assertion output (captured 2026-06-14):**

```
=== P0-SEQUOIA-PQC-05 feasibility spike ===
[1] generating MLDSA65_Ed25519 v6 cert (software)...
    primary key pk_algo = MLDSA65_Ed25519 (id 30)
[2] producing a detached signature...
    signing key pk_algo = MLDSA65_Ed25519 (id 30)
[4] signature packet: version=6, pk_algo=MLDSA65_Ed25519 (id 30)
[5] de-armored binary signature, first 16 bytes (hex):
    c2 cc c5 06 00 1e 0a 00 00 00 29 05 82 6a 2f 71
    -> algorithm-ID octet 0x1e (30) present on the wire at offset 5
=== ASSERTION ===
PASS: signature public-key-algorithm == 30 (MLDSA65_Ed25519, draft-ietf-openpgp-pqc v17)
```

**Wire-byte decode** of the de-armored Signature packet header:

| Byte | Value | Meaning |
| --- | --- | --- |
| 0 | `c2` | New-format packet, tag 2 (Signature) |
| 1–2 | `cc c5` | packet length |
| 3 | `06` | **version 6** (RFC 9580) |
| 4 | `00` | signature type (binary) |
| 5 | `1e` | **0x1e = 30 = `MLDSA65_Ed25519`** ← the proof |
| 6 | `0a` | hash algorithm |

> **One non-obvious gotcha found by the spike:** the PQC cipher suites are
> rejected on a v4 key (`InvalidOperation: can't use algorithms for v4 keys`).
> You **must** select the v6 profile first:
> `CertBuilder::new().set_profile(Profile::RFC9580)?.set_cipher_suite(CipherSuite::MLDSA65_Ed25519)`.
> The default profile is v4 in this build. This directly informs §4 (drop the
> "only v4 keys" restriction — it has to become "PQC requires v6").

**Verdict: the plan's core assumption is PROVEN.** Upstream Sequoia `pqc`
emits algorithm ID 30 on a v6 packet, byte-exact, with no patching.

> Cross-check via `sq packet dump`: deferred. `sq` is not installed and building
> it from the `pqc` branch is a large compile with no marginal evidentiary
> value — the programmatic `Signature::pk_algo()` read **plus** the raw
> de-armored wire byte (`0x1e` at the spec-defined offset) are strictly stronger
> than a CLI pretty-printer. The `sq packet dump` check is folded into the
> acceptance criteria (§8) for the execution phase, where `sq` gets rebuilt
> anyway.

---

## 2. Dependency surgery

### 2.1 `openpgp/lib/Cargo.toml`

```diff
-sequoia-openpgp = "1.21"
+sequoia-openpgp = { git = "https://gitlab.com/sequoia-pgp/sequoia", rev = "3d05138bf1536e63886e7a079fa50aeb080ab573", default-features = false, features = ["crypto-openssl", "compression"] }
-cryptoki = "0.4"
+cryptoki = "0.12"
-openpgp-x509-sequoia = "0.2"
+# removed — see §2.3 (inlined)
```

`crypto-openssl` is **mandatory** (PQC is not in the Nettle backend). This also
means the build host needs OpenSSL >= 3.5 dev headers — already true on our
softhsmv3 toolchain (CLAUDE.md mandates OpenSSL >= 3.5).

### 2.2 `openpgp/cli/Cargo.toml`

```diff
-sequoia-openpgp = "1"
+sequoia-openpgp = { git = "https://gitlab.com/sequoia-pgp/sequoia", rev = "3d05138bf1536e63886e7a079fa50aeb080ab573", default-features = false, features = ["crypto-openssl", "compression"] }
-cryptoki = "0.4"
+cryptoki = "0.12"
-openpgp-x509-sequoia = "0.2"
+# removed — see §2.3
```

Both crates **must** resolve to the *same* git source + rev so the workspace has
a single `sequoia-openpgp` in the graph. Pin the resolved commit in
`openpgp/Cargo.lock` (committed) for reproducibility; refresh deliberately, not
per-CI-run.

### 2.3 The `openpgp-x509-sequoia` dual-version conflict — **RESOLVED: inline (option B.2)**

`openpgp-x509-sequoia` is **abandoned**: its newest release is **0.2.0 (June
2023)** and it hard-pins sequoia **1.x**. There is no 2.x-compatible release and
none is coming. It cannot coexist with our sequoia 2.x dep — cargo would pull
**two** incompatible `sequoia-openpgp` majors into the graph, and the bridge
passes sequoia `Key`/`mpi` types across the boundary, so two majors will not
type-check.

The bridge uses these symbols from it:

| Symbol | Used in | What it is |
| --- | --- | --- |
| `types::PgpKeyType` | `lib.rs`, `util.rs`, `cli` | trivial 3-variant enum (Sign/Auth/Encrypt) |
| `types::{PublicKeyInfo, AlgorithmId}` | `upload.rs` | RSA/ECC descriptor enums |
| `generate_x509`, `self_sign_x509` | `lib.rs`, `upload.rs` | build + self-sign a TBS X.509 cert |
| `find_key_by_x509cert` | `lib.rs` | match an X.509 cert back to a PGP `Cert` |
| `experimental::{extension_fingerprint, extension_kdf_kek}` | `lib.rs` | read custom X.509 extensions |

**Decision: inline (B.2), do NOT fork (B.1).** Rationale: the crate is dead, so
forking it just to re-pin a dep we'd have to keep alive ourselves is worse than
absorbing the ~400 LOC we actually use. We already vendor crates this way
(`rust/fips204-patched/`, `rust/hbs-lms-patched/`), so the pattern is
established. Inlining also lets us **extend** these helpers for PQC key types
(the X.509 path currently only knows RSA/ECC; composite PQC keys need new
`AlgorithmId`/`PublicKeyInfo` arms — a fork would need the same edits anyway).

Concretely: create `openpgp/lib/src/x509.rs` carrying the five helpers above,
sourced from the openpgp-x509-sequoia 0.2.0 code (LGPL-2.0 — compatible with the
bridge's own LGPL-2.0-or-later), ported to sequoia 2.x types, and drop the
external dep from all three Cargo.tomls.

> The old doc preferred B.2 "if `generate_x509` is short". Confirmed short and
> self-contained — B.2 it is.

---

## 3. API migration — the REAL breaks (trial-compiled, not guessed)

A trial crate (`/tmp/bridge-trial`, throwaway) compiled the two
sequoia-touching files **`signer.rs` + `decryptor.rs`** against the pinned `pqc`
branch with a minimal `Op11KeyPair` stub (x509 dep removed so sequoia breaks are
isolated). These are the **observed** compiler errors, not the old doc's
speculative table — which was partly wrong (it listed several breaks the current
source had *already* worked around, and missed the ones below).

| # | Error | File:line | Fix |
| --- | --- | --- | --- |
| 1 | `E0061` `ecdh::decrypt_unwrap` takes **4** args, 3 supplied — missing `_plaintext_len: Option<usize>` | `decryptor.rs:78` | add a 4th arg (`None` or the plaintext-len hint) |
| 2 | `E0049` `DecryptionHelper::decrypt` has **0** type params in 2.x; bridge declares `decrypt<D>` | `decryptor.rs:119` | drop the `<D>` generic; signature becomes `fn decrypt(&mut self, pkesks, skesks, sym_algo: Option<SymmetricAlgorithm>, decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool) -> Result<Option<Cert>>` |
| 3 | `E0308` closure arg type — `decrypt(algo, …)` passes `SymmetricAlgorithm` where 2.x wants `Option<SymmetricAlgorithm>` | `decryptor.rs:137` | pass the `Option` straight through (the closure is now `FnMut(Option<…>, …)`) |
| 4 | return type — `DecryptionHelper::decrypt` returns `Result<Option<Cert>>` in 2.x, bridge returns `Result<Option<Fingerprint>>` | `decryptor.rs:125` | change return type to `Result<Option<Cert>>`; return `Ok(None)` or the recipient `Cert` |
| 5 | `E0599` `Signer::hash_algo` now returns `Result<Self>` | `signer.rs:90` | `signer.hash_algo(SHA512)?` |
| 6 | `E0599` `Signer::detached` chained on a `Result` | `signer.rs:91` | apply `?` first: `signer?.detached().build()?` |

Errors 2–4 are **not** "mechanical" the way the old doc implied — the bridge's
current `DecryptionHelper` impl was written against a hybrid/aspirational API
that never matched real 2.x, so the whole trait impl is rewritten, not nudged.

Files **not** in the trial (compile after the x509 inline lands; expect a
similar small crop of `Result`-returning-builder and `Key4`-vs-v6 fixes):

- `lib.rs` — `NullPolicy::new()` is now `unsafe` (2.x safety hardening) →
  `unsafe { NullPolicy::new() }` with an invariant comment; `Cert`/`Fingerprint`
  flows through the inlined x509 helpers.
- `util.rs` — uses `Key4::import_public_rsa` / `Key4::new`. `Key4` is the **v4**
  key constructor; PQC keys are **v6**. For the classical RSA/ECC import path
  `Key4` still works (those stay v4-capable), but any PQC public-key
  reconstruction must use the v6 `Key6` / generic `Key` builders. Surface the
  exact names during execution.
- `upload.rs` — `PublicKeyInfo`/`AlgorithmId` come from the inlined x509 module;
  add composite-PQC arms (§5).

---

## 4. Native PQC dispatch — replace the EdDSA disguise

The current `signer.rs` maps `EdDSA → Mechanism::Ecdsa` and tags ML-DSA output
as an ECDSA `Signature` MPI (algorithm 22). That entire block is deleted.

**The composite shape (found by reading the pqc branch `crypto/mpi.rs`) is the
load-bearing design fact the old doc missed entirely:** a `MLDSA65_Ed25519`
signature is **not one signature** — it is a struct of **two**:

```rust
// sequoia pqc branch, crypto/mpi.rs — the Signature this sign() must RETURN:
mpi::Signature::MLDSA65_Ed25519 {
    eddsa: Box<[u8; 64]>,    // Ed25519 signature
    mldsa: Box<[u8; 3309]>,  // ML-DSA-65 signature
}
// and the public key carries both components too:
mpi::PublicKey::MLDSA65_Ed25519 { eddsa: Box<[u8;32]>, mldsa: Box<[u8;1952]> }
```

So `Signer::sign` for a composite key must perform **two** signing operations
and assemble both halves. For the HSM-backed case that is **two PKCS#11
`C_Sign` calls** against **two** private-key objects (one Ed25519, one
ML-DSA-65) sharing the message hash, per draft-ietf-openpgp-pqc's composite
construction. New dispatch (illustrative):

```rust
match v6.pk_algo() {
    PublicKeyAlgorithm::RSAEncryptSign => /* RsaPkcs, unchanged */,
    PublicKeyAlgorithm::ECDSA          => /* Ecdsa,  unchanged */,
    PublicKeyAlgorithm::EdDSA          => /* real Ed25519 via CKM_EDDSA (no more disguise) */,
    PublicKeyAlgorithm::MLDSA65_Ed25519 => {
        let eddsa = session.sign(&Mechanism::Eddsa, self.eddsa_handle, hash)?;       // 64 B
        let ctx   = SignAdditionalContext::new(HedgeType::Preferred, Some(&[]));     // empty ctx
        let mldsa = session.sign(&Mechanism::MlDsa(ctx), self.mldsa_handle, hash)?;  // 3309 B
        Ok(mpi::Signature::MLDSA65_Ed25519 { eddsa: boxed64(eddsa), mldsa: boxed3309(mldsa) })
    }
    PublicKeyAlgorithm::MLDSA87_Ed448  => /* Ed448 + CKM_ML_DSA(87), same shape */,
    // SLH-DSA standalone: single CKM_SLH_DSA call.
}
```

(This snippet is illustrative design narration from the original planning pass;
the `MLDSA87_Ed448` arm shown above as a placeholder is now real, shipped code
— see `signer.rs`'s actual `sign()` match — and the same two-call shape now
also has a real `MLKEM1024_X448` decrypt arm in `decryptor.rs`, closing out
remediation plan §2/Fix 1 and Fix 2.)

`decryptor.rs` gets the symmetric ML-KEM treatment: `MLKEM768_X25519` decap is
an X25519 ECDH op **plus** an ML-KEM-768 decapsulation (`CKM_ML_KEM`,
`0x17`), combined per the draft's KEM combiner. `MLKEM1024_X448` decap follows
the identical shape, sized up (X448 ECDH + ML-KEM-1024 decapsulation).

Implication for `Op11KeyPair`: a composite keypair references **two** PKCS#11
`ObjectHandle`s, not one. This is a structural change to the type (§5).

---

## 5. HSM-backed key custody — the must-resolve item: **RESOLVED**

### 5.1 Verdict

**The `cryptoki` crate CAN dispatch softhsmv3's ML-DSA — natively, no vendor
hack — but ONLY after upgrading `cryptoki 0.4 → 0.12`.** The current pin (0.4.1)
**cannot** do it at all.

### 5.2 Evidence (read from the cargo-cached crate sources)

| Question | Finding |
| --- | --- |
| Does softhsmv3 use the vendor codepoints the task brief cited (`0x4035`/`0x4036`/`0x4037`)? | **No — those are RETIRED.** `kmip/pkcs11-mech-manifest.json` shows the `CKM_PQCTODAY_*` block was retired 2026-06-10 (K5) because `0x4035`/`0x4036`/`0x4037` collided with OASIS `CKM_XMSSMT_KEY_PAIR_GEN`/`CKM_XMSS`/`CKM_XMSSMT`. softhsmv3 now emits the **standard** PKCS#11 v3.2 codepoints: `CKM_ML_DSA = 0x1D`, `CKM_ML_DSA_KEY_PAIR_GEN = 0x1C`, `CKM_ML_KEM = 0x17`, `CKM_SLH_DSA = 0x2E`. Confirmed in `src/lib/pkcs11/pkcs11t.h` (lines 1216–1234) and `rust/src/constants.rs` (`CKM_ML_DSA = 0x1D`). **The brief's premise is stale; the plan uses the standard codepoints.** |
| `cryptoki 0.4.1` ML-DSA support? | **None.** Its `Mechanism` enum (`mechanism/mod.rs:544`) ends at the RSA-PSS variants — no ML-DSA, **no `Custom`/vendor variant at all**. The old doc's `Mechanism::Custom(0x40xx)` plan is **impossible on 0.4** (that API does not exist). |
| `cryptoki 0.10.0` ML-DSA support? | Still no native ML-DSA. It *does* add `Mechanism::VendorDefined` + `MechanismType::new_vendor_defined(val)` — **but that rejects any `val < CKM_VENDOR_DEFINED` (0x80000000)** (`mechanism/mod.rs:362`). Since `CKM_ML_DSA = 0x1D` is far below the threshold, the vendor escape hatch **cannot** express it either. Dead end. |
| `cryptoki 0.12.0` (latest, 2026-01-22) ML-DSA support? | **Native and exact.** `Mechanism::MlDsa(dsa::SignAdditionalContext)` → `MechanismType::ML_DSA` → `cryptoki-sys 0.5.0 CKM_ML_DSA = 29 = 0x1D` — the *same* codepoint softhsmv3 exposes. Also `MlDsaKeyPairGen`, `MlKem`, `MlKemKeyPairGen`, `SlhDsa`, and `HashMlDsa*` variants. `SignAdditionalContext::new(hedge: HedgeType, context: Option<&[u8]>)` carries the FIPS-204 context string (empty for OpenPGP composites) and the hedge mode. |

### 5.3 The path

1. Bump `cryptoki = "0.12"` in `lib` + `cli` (§2). This is the single change
   that unlocks HSM PQC.
2. Dispatch via the **native** variant — `Mechanism::MlDsa(SignAdditionalContext::new(HedgeType::Preferred, Some(&[])))`
   for ML-DSA-65 sign, `Mechanism::MlKem` for ML-KEM decap, `Mechanism::Eddsa`
   for the Ed25519 half. **No `Mechanism::Custom`, no vendor codepoints, no raw
   `C_*` FFI.**
3. The cryptoki 0.4 → 0.12 jump spans six minor releases and is itself a
   migration (the `Mechanism` enum, `Session` API, and error types all moved).
   Budget for it explicitly (§9) — this is the bridge's *other* big upgrade
   beyond sequoia.

### 5.4 Residual risk + fallback

- **Param-struct interop:** softhsmv3 must accept `CKM_ML_DSA` with the
  `CK_SIGN_ADDITIONAL_CONTEXT` parameter that cryptoki 0.12 sends (context +
  hedge). softhsmv3's ML-DSA sign was proven via the **KMIP** path, not via a
  cryptoki client sending that exact param block — so this needs a live smoke
  test (a 10-line cryptoki program: open softhsmv3 slot, `C_Sign` with
  `Mechanism::MlDsa`). **This is the one thing the spike could not prove**
  (spike was software-only by design) and is the first task of execution.
- **Fallback if softhsmv3 rejects the param struct:** send
  `Mechanism::MlDsa(SignAdditionalContext::new(HedgeType::default, None))` (null
  param) — softhsmv3 may want a bare `CKM_ML_DSA` with no parameter. If even
  that fails, the *true* last resort is raw `C_SignInit`/`C_Sign` FFI through
  `cryptoki-sys` with a hand-built `CK_MECHANISM { mechanism: 0x1D, pParameter:
  null, ulParameterLen: 0 }` — but 0.12's native variant should make this
  unnecessary. (Note this fallback would mean a **softhsmv3** param-handling fix,
  not a cryptoki one.)

---

## 6. Fork decision — **NOT necessary**

Default holds: **git-dep, no fork.** The spike built the upstream `pqc` branch
unmodified and it emits correct wire format; the trial compile shows our bridge
needs *our* edits, not *upstream* patches. None of the required changes
(§3/§4/§5) live in sequoia — they are all in our bridge, in cryptoki (a clean
crates.io bump), or in the dead x509 helper (which we inline, §2.3).

A `pqctoday-org` fork of Sequoia would only become necessary if we needed to
patch sequoia's PQC internals (we don't) or if the branch were unbuildable (it
isn't). **No GitHub repo is to be created** — this is a human action and is not
warranted by the evidence.

The only thing we "fork" is the abandoned `openpgp-x509-sequoia`, and we don't
even fork it — we inline the ~400 LOC we use (§2.3). The reproducibility lever is
the pinned commit SHA in `openpgp/Cargo.lock`.

---

## 7. Sandbox wiring (deferred — specified here, executed in the sandbox repo)

- `pqctoday-sandbox/tests/05_*` — drive real PQC `sq` operations:
  `sq sign` / `sq verify` (detached + inline) and `sq encrypt` / `sq decrypt`
  using a `MLDSA65_Ed25519` + `MLKEM768_X25519` v6 key whose private halves live
  in softhsmv3. The CLI flag surface for PQC suites lands with the `sq` rebuild
  (`--profile rfc9580` + cipher-suite selection; confirm the exact flag spelling
  against the rebuilt `sq --help`).
- `pqctoday-sandbox/docker/Dockerfile.network` — rebuild `sq` from source
  against the migrated bridge, with `crypto-openssl` (needs OpenSSL >= 3.5 in the
  image) and `cryptoki 0.12`. **(Image build itself is out of scope for this
  plan's validation — cargo only.)**
- JSON output for scenario 05: set `_simulated: false`, add
  `algorithm_id: 30`, `packet_version: "v6"`, `wire_format: "rfc-9580"`,
  `draft: "draft-ietf-openpgp-pqc-17"`, and an `interop_target` field. Remove the
  `architectural_deviation` / disguise notes.

---

## 8. Acceptance criteria

- [ ] `cargo build --workspace` in `openpgp/` green (sequoia 2.x + cryptoki 0.12,
      `crypto-openssl`).
- [ ] `cargo test --workspace` in `openpgp/` green.
- [ ] No "ABI Disguise" / EdDSA-disguise comments remain in `openpgp/lib/src/`.
- [ ] **Live HSM smoke test (the §5.4 gate):** a cryptoki-0.12 client performs
      `C_Sign` with `Mechanism::MlDsa` against softhsmv3 and gets a valid
      3309-byte ML-DSA-65 signature back. This is the make-or-break integration
      check the spike could not cover.
- [ ] `sq sign` with the composite suite over an HSM-backed key produces a
      message whose signature packet is **v6, algorithm ID 30**, verified by
      `sq packet dump` (the deferred cross-check from §1).
- [ ] The composite signature decomposes into a 64-byte Ed25519 + 3309-byte
      ML-DSA-65 component (sanity on the §4 assembly).
- [ ] **Cross-implementation interop:** a *second* PQC-aware OpenPGP impl
      verifies our signed message. Primary target: a stock `sq` built from the
      same `pqc` branch (proves round-trip). Stronger target if available: GnuPG
      2.5+/RNP PQC or an independent draft-17 implementation reports
      "signature verified". If no independent impl is reachable (the ecosystem
      is nascent), the second-`sq` check is the soft gate and the independent
      check is logged as deferred.
- [ ] ML-KEM encrypt/decrypt round-trips through the HSM (`CKM_ML_KEM`, 0x17).
- [ ] Sandbox scenario 05 emits `_simulated: false` with the §7 fields.
- [ ] Dependabot: CVE-2025-67897 alerts auto-close (the sequoia bump carries the
      `2.1.0` fix as a side effect).

---

## 9. Effort estimate

**6–9 PD** (the old doc's 2–3 PD was wrong — it assumed a mechanical sequoia
bump and a one-line `Mechanism::Custom` HSM change; both turned out far deeper).

| Workstream | PD |
| --- | --- |
| Dependency surgery: git dep + Cargo.lock pin, `crypto-openssl` plumbing | 0.5 |
| Inline `openpgp-x509-sequoia` (§2.3), port to sequoia 2.x, + PQC `AlgorithmId` arms | 1.5 |
| `cryptoki 0.4 → 0.12` migration (enum/Session/error churn across all files) | 1.0 |
| sequoia 1.x → 2.x API breaks (§3) across `signer`/`decryptor`/`lib`/`util`/`upload` | 1.0 |
| **Composite PQC dispatch** (§4): two-handle keypair, two-sign assembly, ML-KEM combiner, v6 plumbing | 2.0 |
| **Live HSM smoke + param-struct interop** (§5.4), incl. any softhsmv3 param fix | 1.0 |
| Cross-impl interop test + acceptance hardening | 0.5–1.5 |
| Sandbox scenario 05 wiring (sandbox repo; image build excluded) | 0.5 |

Risk-weighted toward the high end if softhsmv3 rejects the cryptoki ML-DSA param
struct (§5.4) or if the composite two-key custody model needs object-store
changes.

---

## 10. Risks

| Risk | Severity | Mitigation |
| --- | --- | --- |
| softhsmv3 rejects cryptoki-0.12's `CK_SIGN_ADDITIONAL_CONTEXT` param for `CKM_ML_DSA` | **High** | First execution task is the §5.4 smoke test; fallbacks: null param, then raw `cryptoki-sys` `CK_MECHANISM`. Worst case = a small softhsmv3 param-handling patch (in-house, we own the HSM). |
| Composite custody: each PQC key = two HSM private objects (Ed25519 + ML-DSA); object-store / upload assumes one handle | **High** | `Op11KeyPair` gains a second `ObjectHandle`; `upload_key` stores both halves; `key()` reassembles the composite public MPI. Budgeted in §9. |
| `pqc` branch force-pushes/rebases | Med | Pinned `rev` SHA in `Cargo.lock`; refresh deliberately. Plan-A fallback: `=2.2.0-pqc.1` crates.io preview (same crate version). |
| `cryptoki 0.12` minor API differs again on a future bump | Med | Pin `=0.12.x`; verify on bump. |
| draft-ietf-openpgp-pqc codepoints shift before RFC | Low | v17 (2026-01) keeps 30/35 stable across many drafts; if they move, re-pin + re-test (the spike makes re-validation a 1-minute job). |
| No independent PQC OpenPGP impl reachable for interop | Med | Second-`sq` round-trip is the soft gate; independent-impl check logged as deferred (§8). |
| `crypto-openssl` runtime needs OpenSSL >= 3.5 in the sandbox image | Low | softhsmv3 toolchain already mandates >= 3.5; ensure the network image ships it (sandbox repo, image build out of scope here). |

---

## 11. Decision log

| Date | Note |
| --- | --- |
| 2026-06-07 | Original scoping note (`SEQUOIA_PQC_MIGRATION.md`). 2–3 PD, Path B, `Mechanism::Custom(0x40xx)` HSM plan. |
| 2026-06-14 | **This plan.** Spike PROVEN (algo ID 30, sequoia 2.2.0-pqc.1 @ `3d05138`, OpenSSL 3.6.2). HSM verdict: cryptoki **0.12** native `Mechanism::MlDsa` → standard `CKM_ML_DSA = 0x1D` (the `0x4035/6/7` vendor codepoints were retired 2026-06-10; brief premise stale). Fork NOT needed. `openpgp-x509-sequoia` inlined (dead upstream). Composite signature = two component sigs (64 B Ed25519 + 3309 B ML-DSA-65) ⇒ two-handle custody — a complexity the original doc missed; effort revised to **6–9 PD**. No GitHub repo created (human action). |

---

## 12. References

- draft-ietf-openpgp-pqc **v17** (2026-01-13): <https://datatracker.ietf.org/doc/draft-ietf-openpgp-pqc/17/>
- RFC 9580: <https://www.rfc-editor.org/rfc/rfc9580>
- Sequoia `pqc` branch: <https://gitlab.com/sequoia-pgp/sequoia/-/tree/pqc> (HEAD `3d05138`, 2026-06-14)
- `sequoia-openpgp 2.2.0-pqc.1`: <https://crates.io/crates/sequoia-openpgp/2.2.0-pqc.1>
- `cryptoki 0.12.0` (native ML-DSA/ML-KEM/SLH-DSA): <https://crates.io/crates/cryptoki/0.12.0>
- `kmip/pkcs11-mech-manifest.json` — standard PKCS#11 v3.2 codepoints softhsmv3 emits (and the retired `0x40xx` block).
- `src/lib/pkcs11/pkcs11t.h` — `CKM_ML_DSA = 0x1D` source of truth.
- The spike: [`../spike-pqc/`](../spike-pqc/) (run `cargo run`; PASS line == proven).
