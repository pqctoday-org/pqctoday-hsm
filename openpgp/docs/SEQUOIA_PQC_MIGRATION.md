# Sequoia 1.x → 2.x PQC Migration

Scoping document for migrating the `openpgp-pkcs11-sequoia` bridge from
classical-only Sequoia 1.x to PQC-capable Sequoia 2.x, retiring the
current EdDSA-disguise hack and unblocking real RFC 9580 + draft-ietf-openpgp-pqc
wire-format interop. Drafted 2026-06-07 as a planning artifact; no code
changes in this document.

| Field | Value |
| --- | --- |
| Plan ID | `P0-SEQUOIA-PQC-05` |
| Status | 🟦 **Not Started** (scoping doc; execution deferred to a dedicated session) |
| Priority | P0 (PQC mission-critical for scenario 05) |
| Scenarios touched | sandbox scenario 05 (Sequoia PQC OpenPGP) |
| Subsystem | `pqctoday-hsm/openpgp/{lib,cli}` |
| Effort | **2–3 PD** |
| Image rebuild needed | yes — `pqc-network` (sandbox scenario 05) |
| License | unchanged (LGPL-2.0-or-later via sequoia-openpgp; CC0 for our crates) |
| Closes Dependabot alerts | **#7, #4** (CVE-2025-67897, `sequoia-openpgp < 2.1.0` aes_key_unwrap subtraction overflow) — as a side effect |
| Tracked in | `pqctoday-sandbox/tasks/IMPL_PLANS_INDEX.md` |

## 1. Why this matters

`openpgp-pkcs11-sequoia` is pqctoday-hsm's OpenPGP bridge — it lets Sequoia
(`sq`) drive PQC operations against softhsmv3 via PKCS#11. **The current
implementation can produce ML-DSA signature bytes but cannot produce a
wire-correct PQC OpenPGP message.** The bridge has been honest about this
in code comments since the start; see `lib/src/signer.rs:24`:

> ```rust
> PublicKeyAlgorithm::EdDSA => {
>     // PQC Sandbox ML-DSA ABI Disguise (FIPS 204 Native offloading via Softhsmv3 proxy)
>     // We theoretically intercept EdDSA and map it to CKM_ML_DSA (0x00004030).
>     // Since cryptoki v0.4 lacks CKM_ML_DSA natively we route it through EdDSA
>     // and allow the internal HSM shim to catch the ML-DSA struct ID.
>     Mechanism::Ecdsa
> },
> ```

And `lib/src/signer.rs:33`:

> ```rust
> _ => return Err(anyhow::anyhow!(
>     "Only v4 keys are supported (FIPS 204 natively requires V6)"
> )),
> ```

What that means in practice:

- The OpenPGP packet that goes over the wire is tagged `EdDSA` (algorithm ID
  `22`), not `MLDSA65_Ed25519` (algorithm ID `30` per draft-ietf-openpgp-pqc).
- A real RFC 9580 PQC-aware OpenPGP client receiving the message has no way
  to know it's actually ML-DSA.
- Cross-vendor PQC OpenPGP interop is impossible today.
- Sandbox scenario 05 is a "demo via the HSM disguise" — useful pedagogically,
  but not real PQC OpenPGP.

Sequoia 2.x with PQC support changes all of that: native enum variants for
the draft-ietf-openpgp-pqc codepoints, RFC 9580 v6 packet format, and a
clean API to dispatch ML-KEM / ML-DSA / SLH-DSA operations through any
backend (including our PKCS#11 bridge).

The CVE-2025-67897 closure rides along as a side effect; it is the smaller
half of the value here.

## 2. Upstream evidence (probed 2026-06-07)

### 2.1 PQC variants in the upstream `pqc` branch

Maintainer **Neal H. Walfield** (sequoia core), last commit 2025-11-14 to
`gitlab.com/sequoia-pgp/sequoia` `pqc` branch. The `PublicKeyAlgorithm`
enum on that branch (`openpgp/src/crypto/types/public_key_algorithm.rs`):

```rust
pub enum PublicKeyAlgorithm {
    RSAEncryptSign,     // 1
    // ... classical variants ...
    Ed25519,            // 27
    Ed448,              // 28
    MLDSA65_Ed25519,    // 30   ← composite ML-DSA-65 + Ed25519 signature
    MLDSA87_Ed448,      // 31   ← composite ML-DSA-87 + Ed448 signature
    SLHDSA128s,         // 32   ← SLH-DSA-SHA2-128s standalone
    SLHDSA128f,         // 33   ← SLH-DSA-SHA2-128f standalone
    SLHDSA256s,         // 34   ← SLH-DSA-SHA2-256s standalone
    MLKEM768_X25519,    // 35   ← composite ML-KEM-768 + X25519 KEM
    MLKEM1024_X448,     // 36   ← composite ML-KEM-1024 + X448 KEM
    Private(u8),
    Unknown(u8),
}
```

These exactly match the
[draft-ietf-openpgp-pqc](https://datatracker.ietf.org/doc/draft-ietf-openpgp-pqc/)
wire-format codepoints. The composite design (PQC + classical hybrid) is
the IETF working group's chosen direction; no standalone Dilithium or
Falcon variants exist in this enum (consistent with the draft).

### 2.2 Active development trail (8 branches)

| Branch | Last commit | Author |
| --- | --- | --- |
| `pqc` | 2025-11-14 | Neal H. Walfield (sequoia core) |
| `justus/pqc` | 2025-10-28 | Malte Meiboom |
| `justus/pqc-frontend` | 2025-06-25 | Justus Winter (sequoia core) |
| `justus/pqc-ossl` | 2025-08-27 | Justus Winter |
| `jjelen/pqc-ossl` | 2025-10-01 | Jakub Jelen (Red Hat) |
| **`malte/integrate-pqc-nist-bp`** | **2026-05-05** | Malte Meiboom (most recent integration branch) |
| `ngg1/pqc` + `ngg1/rust-pqc` | 2026-04-18 | Gergely Nagy |

### 2.3 One published preview release

`sequoia-openpgp 2.2.0-pqc.1` — published to crates.io 2025-11-12 (not yanked,
verified via `cargo info sequoia-openpgp@2.2.0-pqc.1`). Two days before the
`pqc` branch's last commit. Testable preview of the enum above.

### 2.4 NOT yet in stable

Stable `main` (and therefore `2.3.0` published 2026-05-11) does **not** include
PQC. Confirmed: the upstream `openpgp/NEWS` changelog has zero mentions of
PQC / ML-KEM / ML-DSA / SLH-DSA across all versions 1.x → 2.3.0. The May 2026
`malte/integrate-pqc-nist-bp` branch suggests integration toward main is in
flight, but there is no published roadmap date.

## 3. Three sourcing paths

| Path | Sequoia source | Pros | Cons |
| --- | --- | --- | --- |
| **A — Pin to `2.2.0-pqc.1` preview** | `sequoia-openpgp = "=2.2.0-pqc.1"` from crates.io | Stable point release; published; no git dep. CVE-2025-67897 closed (the fix is in `2.1.0`). | Frozen at 2025-11-12; misses any fixes between 2.2.0-pqc.1 and merge-to-main. |
| **B — Track the `pqc` branch directly via git** | `sequoia-openpgp = { git = "https://gitlab.com/sequoia-pgp/sequoia", branch = "pqc" }` | Bleeding-edge; gets fixes between 2.2.0-pqc.1 and merge-to-main; matches what other sequoia-PQC early adopters do. CVE-2025-67897 closed. | Branch can move under us; reproducibility relies on `Cargo.lock`'s pinned commit SHA. |
| **C — Wait for stable** | (no change) | Zero risk. | Indefinite block on scenario 05's real PQC mission. Disguise hack stays. CVE-2025-67897 stays open. |

**Recommendation: Path B** with a pinned commit-SHA in Cargo.lock for
reproducibility. Re-evaluate quarterly. Fall back to (A) if `pqc` branch
becomes erratic. Switch to crates.io stable when PQC merges to main.

## 4. Work breakdown (Path B execution)

### 4.1 Dependency surgery (~0.5 PD)

- [ ] Bump `openpgp/lib/Cargo.toml`: `sequoia-openpgp = "1.21"` → git dep on
  `pqc` branch (with a `rev = "<commit-sha>"` pin in Cargo.lock).
- [ ] Bump `openpgp/cli/Cargo.toml`: `sequoia-openpgp = "1"` → same git dep.
- [ ] Workspace-level dedup: both crates should resolve to the **same** git
  source so we don't end up with two sequoia versions in the graph.
- [ ] Resolve the `openpgp-x509-sequoia 0.2.0` dual-version conflict. Two
  sub-options:
  - **B.1** Fork `openpgp-x509-sequoia` into `pqctoday-hsm/openpgp-x509-sequoia-patched/`
    (similar to `rust/fips204-patched/`); bump its sequoia dep to match ours;
    use `[patch.crates-io]`. Estimated: 0.5 PD.
  - **B.2** Inline the `generate_x509` body into our own `lib.rs` using
    sequoia 2's `Cert` builder + `x509-certificate` directly; drop the
    `openpgp-x509-sequoia` dependency. Estimated: 1.0 PD (depends on
    complexity of `generate_x509`). Reduces our dep count by 1.
  - Prefer **B.2** if `generate_x509` is short and self-contained; **B.1**
    otherwise.

### 4.2 Migrate our code to sequoia 2.x APIs (~0.5–1 PD)

11 errors observed in the trial bump, all mechanical and documented in
upstream sequoia changelog:

| File:line | Old (1.x) | New (2.x) | Notes |
| --- | --- | --- | --- |
| `decryptor.rs:78` | `ecdh::decrypt_unwrap(pub, secret, ct)` | `ecdh::decrypt_unwrap(pub, secret, ct, Option<usize>)` | 4th arg = session-key-length hint; `decrypt_unwrap2` (deprecation hint in 1.x) was the rename foreshadowing |
| `decryptor.rs:119` | `fn decrypt(&self, ...)` | `fn decrypt<T>(&self, ...)` | Trait gained a type parameter |
| `decryptor.rs:137` | `pkesks[0].decrypt(...) → SymmetricAlgorithm` | `… → Option<SymmetricAlgorithm>` | Nullable result; needs `.expect()` or `?` handling |
| `signer.rs:90,91` | `Signer::new(...).hash_algo(h).detached()` | `Signer::new(...).hash_algo(h)?.detached()?` | Builder steps now `Result`-returning |
| `lib.rs:180` | (Fingerprint type) | (Fingerprint type) | Function signature changed — likely `?` propagation needed |
| `lib.rs:210` | (1-arg function call) | (2-arg function call) | API added a parameter; check changelog for what |
| `lib.rs:295` | `NullPolicy::new()` | `unsafe { NullPolicy::new() }` | Intentional safety hardening; document the `unsafe` block's invariants |
| `lib.rs:346` | (Key type) | (Key type) | Resolves once `openpgp-x509-sequoia` issue (§4.1) is fixed |
| `decryptor.rs` (other) | | | Mop-up for cascade |

### 4.3 Replace the EdDSA-disguise hack with native PQC dispatch (~0.5 PD)

- [ ] `signer.rs`: replace the `EdDSA → Mechanism::Ecdsa` disguise with a
  proper `match` arm:
  ```rust
  PublicKeyAlgorithm::MLDSA65_Ed25519 => Mechanism::Custom(CKM_PQCTODAY_ML_DSA_SIGN_VERIFY),
  PublicKeyAlgorithm::MLDSA87_Ed448  => Mechanism::Custom(CKM_PQCTODAY_ML_DSA_SIGN_VERIFY),
  PublicKeyAlgorithm::SLHDSA128s     => Mechanism::Custom(CKM_PQCTODAY_SLH_DSA_SIGN_VERIFY),
  // ... etc.
  ```
  using the authoritative vendor mech codepoints from
  `kmip/pkcs11-mech-manifest.json` (0x4035/0x4036 for ML-DSA, 0x4033 for SLH-DSA).
- [ ] Same shape for `decryptor.rs` ML-KEM ops: add `MLKEM768_X25519` /
  `MLKEM1024_X448` arms dispatching to `CKM_PQCTODAY_ML_KEM_ENCAPSULATE`
  (0x4037).
- [ ] Drop the V4-only restriction once V6 packets are supported by the
  sequoia 2.x APIs we hit.
- [ ] Update `signer.rs` and `decryptor.rs` comments — remove the "ABI
  Disguise" block; document the real dispatch.

### 4.4 Update cryptoki binding (if needed) (~0.25 PD)

The current code's comment notes `cryptoki v0.4 lacks CKM_ML_DSA natively`.
Verify whether cryptoki has since added the constants, or whether we need to
extend the cryptoki binding with a custom-mech wrapper. Decision matrix:

- If cryptoki ≥ a recent version now exports `CKM_ML_DSA` etc.: bump.
- Otherwise: use the `Mechanism::Custom(u64)` pattern with our vendor
  codepoints from `kmip/pkcs11-mech-manifest.json`.

### 4.5 Sandbox scenario 05 update (~0.5 PD, sandbox repo)

- [ ] `pqctoday-sandbox/tests/05_test_*.sh` — drive `sq sign / sq verify` /
  `sq encrypt / sq decrypt` with **explicit PQC algorithm flags** (whatever
  CLI surface sequoia 2.x ships for `--algorithm mldsa65-ed25519` etc.).
- [ ] JSON output gains `algorithm_id`, `packet_version: "v6"`,
  `wire_format: "rfc-9580"`, and an `interop_target` field describing
  expected behaviour against other PQC-aware clients.
- [ ] Drop `_simulated: true` and the `architectural_deviation` field if
  present — scenario 05 becomes a real PQC OpenPGP demo.
- [ ] `pqctoday-sandbox/docker/Dockerfile.network`: rebuild `sq` from
  source against the migrated `openpgp-pkcs11-sequoia` lib.

## 5. Acceptance criteria

- [ ] `cargo build --workspace` in `openpgp/` green.
- [ ] `cargo test --workspace` in `openpgp/` green.
- [ ] No remaining "ABI Disguise" comments in `openpgp/lib/src/`.
- [ ] `sq sign --algorithm mldsa65-ed25519 ...` produces an OpenPGP message
  whose first PKESK / signature packet has algorithm ID `30`
  (`MLDSA65_Ed25519`) per draft-ietf-openpgp-pqc, verified by `sq
  packet dump`.
- [ ] At least one cross-implementation verification: produce a signed
  message with our bridge, verify it with an unrelated PQC-aware OpenPGP
  implementation (e.g. RNP, GoPGP-Native PQC, or a separate sequoia
  build). Acceptance gate is "the other implementation reports
  signature-verified."
- [ ] Sandbox scenario 05 emits `_simulated: false` with the real PQC fields.
- [ ] CVE-2025-67897 Dependabot alerts #7 and #4 auto-close after merge.

## 6. Risks

| Risk | Mitigation |
| --- | --- |
| `pqc` branch force-pushes or rebases under us | Pin `rev = "<sha>"` in `Cargo.lock`; refresh deliberately, not on every CI run |
| Sequoia merges PQC to main with breaking changes vs. the `pqc` branch | Sequoia uses semver; a major sequoia 3.x is more likely than silent breakage of the `pqc` shape. Track upstream MRs against the `pqc` branch quarterly |
| `openpgp-x509-sequoia` becomes maintained / publishes 0.3 that supports sequoia 2.x | Drop our fork or inline implementation in favour of upstream; minor cleanup PR |
| `cryptoki` crate's `Mechanism::Custom(u64)` surface changes between versions | Pin a known-good cryptoki version; verify on bump |
| Cross-implementation interop test target unavailable (other PQC OpenPGP impls are also nascent) | Fall back to "second sequoia instance reads our output" as a soft acceptance; mark the strong acceptance as a deferred check |
| draft-ietf-openpgp-pqc codepoint reshuffling before it reaches RFC | The composites at 30–36 have been stable for several drafts; if codepoints change before RFC, we re-pin and re-test. Track the draft state |

## 7. Decision log

| Date | Note |
| --- | --- |
| 2026-06-07 | Scoping doc written. Path B (track `pqc` branch via git dep) recommended. Execution deferred to a dedicated session. Tracked under `P0-SEQUOIA-PQC-05` in `pqctoday-sandbox/tasks/IMPL_PLANS_INDEX.md`. Dependabot mediums #7 and #4 acknowledged as part of this scope; not separately dismissed. The mediums #5 and #6 (rsa Marvin Attack) are unrelated — those require either upstream patch (none yet) or rsa-crate replacement, tracked separately. |

## 8. References

- draft-ietf-openpgp-pqc: <https://datatracker.ietf.org/doc/draft-ietf-openpgp-pqc/>
- RFC 9580 (OpenPGP Crypto Refresh): <https://www.rfc-editor.org/rfc/rfc9580>
- Sequoia repository: <https://gitlab.com/sequoia-pgp/sequoia>
- Sequoia `pqc` branch (HEAD 2025-11-14): <https://gitlab.com/sequoia-pgp/sequoia/-/tree/pqc>
- Sequoia 2.2.0-pqc.1 preview on crates.io: <https://crates.io/crates/sequoia-openpgp/2.2.0-pqc.1>
- CVE-2025-67897 (aes_key_unwrap subtraction overflow): <https://github.com/pqctoday-org/pqctoday-hsm/security/dependabot/7>
- `pqctoday-hsm/kmip/pkcs11-mech-manifest.json` — authoritative vendor mech codepoints used by §4.3.
