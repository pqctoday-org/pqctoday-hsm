# Remediation plan — Rust engine (softhsmrustv3) PKCS#11 v3.2 gaps (2026-08-30)

**Status:** Execution complete. Every item in this plan is implemented,
verified against real ACVP vectors (or, where ACVP structurally can't
cover a step, independent hand/Python cross-checks plus end-to-end
integration tests), and committed locally on branch
`fix/ws1-4-and-ws2-rust-gaps` (not pushed) — except §4's
`CKM_ECMQV_DERIVE`, deliberately held per explicit user decision. Full
regression suite (`rust/test_p11_conformance.js`) went from 978/0 at the
start of this session's Rust work to **995/0**, with no step introducing
a regression anywhere else. Commits, in order:

| Item | Commit | Evidence |
|---|---|---|
| §2 HKDF silent-substitution fix | `b0f9887` | 21/21 ACVP |
| §3 SP800-108 Counter/Feedback missing PRFs | `b0f9887`, `f341ddf` | 28/28 ACVP |
| §1 AES-GMAC | `0c6a858` | 3/3 ACVP (incl. the 15-byte-IV sign case) |
| §1 SP800-108 Double-Pipeline KDF | `34796e0` | 14/14 ACVP |
| §1 AES-OFB/CFB128/CFB8/CFB1 | `90185be` | 12/12 ACVP + hand-verified multipart streaming |
| §1 AES-CCM | `a8a6d4a` | 8/8 ACVP incl. tampered-tag rejection |
| §1 AES-XTS + CKM_AES_XTS_KEY_GEN | `400950f` | 4/4 ACVP incl. a 5909-byte ciphertext-stealing case |
| §4 CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS | `fed7689` | 3 unit tests (reduction math) + end-to-end sign/verify smoke test, P-256/384/521 |

**Dependency additions**: `xts-mode = "0.5"` (XTS ciphertext stealing —
deliberately used the crate rather than hand-rolling, unlike GMAC/CCM,
since it has no compile-time generic-size friction and the algorithm is
easy to get subtly wrong by hand). Everything else built on zero new
dependencies, using primitives already in `Cargo.toml`
(`AesKey`/`GcmState` from this engine's own `crypto/multipart.rs`,
`num-bigint` for the EC-extra-bits reduction).

**Scope note on `CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS`**: implemented for
P-256/P-384/P-521 only — the NIST prime curves this engine supports that
also have real ACVP evidence for this generation mode. `secp256k1` stays
on plain `CKM_EC_KEY_PAIR_GEN` (FIPS 186-5 doesn't govern that curve at
all, so "extra bits" evidence for it doesn't exist).

**Scope and trigger.** This session closed the C++ engine's "WS-8" gap set
(AES-GMAC, AES-CCM, AES-XTS, AES-OFB/CFB1/CFB8/CFB128, SP800-108
Double-Pipeline KDF) plus real correctness fixes to HKDF and SP800-108
Counter/Feedback KDF, all with real ACVP evidence — see
`docs/remediation-plan-pkcs11-v32-coverage-2026-08-29.md`. This document
checks whether the **Rust engine** (`rust/`, `softhsmrustv3`, pure-Rust WASM,
no OpenSSL — the production backend for the KMIP server and CACP policy
engine, per the repo's `CLAUDE.md`) has the same gaps, using the same
evidence bar: a gap only counts as closeable now if real ACVP vectors exist
**and** a clean backend path exists (a RustCrypto crate here, in place of
"an OpenSSL EVP primitive" for the C++ side).

**Report-only.** Nothing in this document has been implemented. It records
findings and a proposed priority order for a future execution pass.

---

## 0. Summary

| Finding | Class | Priority |
|---|---|---|
| 7 WS-8-equivalent mechanisms entirely absent from Rust (§1) | Missing mechanism | High (2 near-free, rest low-risk) |
| `CKM_SP800_108_DOUBLE_PIPELINE_KDF` absent from Rust (§1) | Missing mechanism | High (near-free) |
| `CKM_HKDF_DERIVE` silently substitutes SHA-256 for any unrecognized PRF (§2) | **Silent wrong answer**, not a missing-mechanism gap | **Highest** — confirmed by real ACVP KAT |
| SP800-108 Counter/Feedback KDF missing SHA-1/SHA-224/SHA3-224/SHA-512-224/256 PRFs (§3) | Missing coverage, fails safely | Medium |
| `CKM_ECMQV_DERIVE` — Rust re-assessment (§4) | Missing mechanism, protocol-risk gated | Hold (same reasoning as C++, independent of language) |
| `CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS` — Rust re-assessment (§4) | Missing mechanism | Medium — easier in Rust than in C++ |
| Broader bidirectional C++/Rust parity (§5) | Informational | Out of scope here — flagged for a follow-up pass |

---

## 1. WS-8-equivalent mechanisms — absent from Rust

Confirmed by grep across `rust/src/ffi.rs` (~19,400 lines, ~193 `CKM_*` match
arms) — zero hits for any of the tokens below — and by inspecting
`rust/Cargo.toml` / `rust/Cargo.lock`, which carry none of the crates that
would be needed even transitively. Cross-checked against
`docs/remediation-plan-cpp-rust-pkcs11-parity-2026-07-25.md` (covers ECDH
cofactor, RSA sign/verify-recovery, hybrid KEMs, FrodoKEM/McEliece — none of
these mechanisms) and `docs/gap-analysis-rust-pkcs11-v3.2.md` (2026-07-10,
predates this set entirely) — every item below is a genuinely new finding,
not a re-report.

| Mechanism | Rust status | ACVP vectors | RustCrypto backend | Priority |
|---|---|---|---|---|
| `CKM_AES_GMAC` | absent | yes (`tests/acvp/aes_gmac_test.json`) | **Zero new deps** — `aes-gcm 0.10.3` already a direct dependency (`rust/Cargo.toml`); GMAC = GCM's tag-only path with empty plaintext, same trick the C++ engine used against `EVP_MAC` GMAC | Highest — near-free |
| `CKM_SP800_108_DOUBLE_PIPELINE_KDF` | absent — confirmed both by grep (not in the mechanism-info table, `ffi.rs` ~1467-1469) and empirically: `C_DeriveKey` returns `CKR_MECHANISM_INVALID` (0x70) | yes (`tests/acvp/sp800_108_double_pipeline_test.json`) | **Zero new deps** — pure construction over the already-present `hmac`/`cmac` crates, mirroring the existing Counter/Feedback KDF code shape | Highest — near-free |
| `CKM_AES_CCM` | absent | yes (`tests/acvp/aes_ccm_test.json`) | `ccm` crate (RustCrypto/AEADs), compatible with the pinned `aes 0.8.4` | High |
| `CKM_AES_XTS` (+ `CKM_AES_XTS_KEY_GEN`, `CKK_AES_XTS`) | absent (no constant even defined — the one `CKM_AES_XTS` grep hit in `rust/src/constants.rs:612` is an unrelated comment about a different vendor-mechanism value collision) | yes (`tests/acvp/aes_xts_test.json`) | `xts-mode` crate, builds directly on `aes 0.8`'s `BlockEncrypt`/`BlockDecrypt` traits | High |
| `CKM_AES_OFB` | absent | yes (`tests/acvp/aes_ofb_test.json`) | `ofb` crate (RustCrypto/stream-ciphers) | High |
| `CKM_AES_CFB128` | absent | yes (`tests/acvp/aes_cfb128_test.json`) | `cfb-mode` crate | High |
| `CKM_AES_CFB8` | absent | yes (`tests/acvp/aes_cfb8_test.json`) | dedicated `cfb8` crate | High |
| `CKM_AES_CFB1` | absent | yes (`tests/acvp/aes_cfb1_test.json`) | **No published crate** — RustCrypto/stream-ciphers has no `cfb1`; would need a small hand-rolled 1-bit-feedback shift register (mechanical, same shape as the other CFB variants, just no drop-in wrapper) | Medium |

**Recommended execution order:** GMAC and Double-Pipeline KDF first (zero new
dependencies, mirrors code already in the file), then CCM/XTS/OFB/CFB128/CFB8
(one new crate each), then CFB1 last (only one needing hand-rolled logic).

---

## 2. `CKM_HKDF_DERIVE` — suspected silent wrong-answer bug

**Location:** `rust/src/ffi.rs`, the `CKM_HKDF_DERIVE` arm (~lines
8715-8814), both the Expand path (~8762) and Extract-only path (~8797).

**What the code does today:**

```rust
match prf {
    CKM_SHA384 => { /* real SHA-384 HKDF */ }
    CKM_SHA512 => { /* real SHA-512 HKDF */ }
    CKM_SHA3_256 => { /* real SHA3-256 HKDF */ }
    CKM_SHA3_512 => { /* real SHA3-512 HKDF */ }
    _ => {
        // CKM_SHA256 default
        /* runs SHA-256 HKDF regardless of what `prf` actually was */
    }
}
```

**Why this is worse than a missing-mechanism gap.** Every other gap in this
document fails loudly — the caller gets a `CKR_*` error and knows the
mechanism isn't supported. This one doesn't: a caller requesting
`CKM_SHA_1`, `CKM_SHA224`, `CKM_SHA3_224`, `CKM_SHA512_224`,
`CKM_SHA512_256` (or any typo'd/unsupported value) as the HKDF PRF gets
`CKR_OK` back with key material silently derived under SHA-256 instead. This
is the exact bug class the C++ engine's `ckmToDigestName()` had this
session (missing `CKM_SHA224`/`CKM_SHA512_224`/`CKM_SHA512_256`/`CKM_SHA3_224`
cases) — except the C++ version failed the build/dispatch cleanly, while this
one silently substitutes.

**Verification status: CONFIRMED, empirically.** Built the Rust wasm engine
with `--features acvp` (unmodified source — see build note below) and ran
the real `tests/acvp/kda_hkdf_sp800_56cr1_test.json` vectors end-to-end,
plus a direct isolated probe.

- **Direct probe:** `C_DeriveKey(CKM_HKDF_DERIVE, prf=CKM_SHA_1)` on a known
  IKM/salt/info returns `CKR_OK` with output `b010d4e9...fa79749c` — this is
  **byte-identical** to an independent Node `crypto.hkdfSync('sha256', ...)`
  reference on the same inputs, and different from the real HKDF-SHA1
  reference (`2bf97566...`). The engine reports success while silently
  computing under the wrong hash.
- **Full ACVP run (21 groups, AFT+VAL):** PASS for SHA2-256, SHA2-384,
  SHA2-512, SHA3-256, SHA3-512 (11/21 — including the one deliberate
  `testPassed:false` negative case, correctly flagged as a mismatch).
  **Confirmed silent SHA-256 substitution**, each byte-verified against an
  independent SHA-256 HKDF computation, for every group requesting
  SHA2-224, SHA2-512/224, SHA2-512/256, SHA3-224, or SHA3-384 as the PRF
  (10/21).

Handler locations: Expand-path switch at `ffi.rs:8762`, its silent default
arm at `ffi.rs:8788-8794`; Extract-only switch at `ffi.rs:8805`, its silent
default arm at `ffi.rs:8810`.

*Build note:* run inside the `pqc-rust` container with `AG_CONTAINER_ROOT`
pointed at the worktree path (`/ag/pqctoday-hsm/.worktrees/ws1-4-and-ws2`
— the full `~/Antigravity` tree is bind-mounted at `/ag`, so the worktree is
reachable without extra setup), and `wasm-pack` invoked directly at
`/cargo-target/release/wasm-pack` since it isn't on the container `$PATH`.
Mirrors `scripts/local-gate.sh`'s `--rust-p11` step. Verification script
(throwaway, not committed):
`scratchpad/rust_hkdf_kbkdf_acvp_check.js`.

**Proposed fix (not yet implemented):** replace the catch-all `_ =>` arms in
both the Expand and Extract-only branches with the full explicit hash set
already used elsewhere this session (`SHA1`, `SHA224`, `SHA256`, `SHA384`,
`SHA512`, `SHA512_224`, `SHA512_256`, `SHA3_224`, `SHA3_256`, `SHA3_384`,
`SHA3_512`), returning `CKR_MECHANISM_PARAM_INVALID` for anything truly
unrecognized — mirroring the honest-failure pattern already used correctly
in `sp800_108_counter_kbkdf`/`sp800_108_feedback_kbkdf` (§3 below).

---

## 3. SP800-108 Counter/Feedback KDF — PRF coverage gap (fails safely)

**Location:** `sp800_108_counter_kbkdf` (`rust/src/ffi.rs:8091`),
`sp800_108_feedback_kbkdf` (`rust/src/ffi.rs:8120`).

Both dispatch on `prf_type` and cover `CKM_SHA256_HMAC`, `CKM_SHA384_HMAC`,
`CKM_SHA512_HMAC`, `CKM_SHA3_256_HMAC`, `CKM_SHA3_512_HMAC`, and
`CKM_AES_CMAC` (keyed by base-key length). Unlike HKDF, the fallthrough arm
is `_ => Err(CKR_MECHANISM_PARAM_INVALID)` — an honest, loud rejection. The
gap is real but low-risk: `CKM_SHA_1_HMAC`, `CKM_SHA512_224_HMAC`, and
`CKM_SHA512_256_HMAC` are not wired (matching exactly the coverage the C++
engine was also missing before this session's fix on that side). Adding them
is a small, mechanical extension of the existing `match` arms — no new
dependency, `hmac`/`sha2` already cover all three.

**ACVP evidence — confirmed by the same verification run as §2.** Ran the
real `tests/acvp/sp800_108_kbkdf_test.json` (28 groups) against both
functions: PASS for HMAC-SHA2-256/384/512, HMAC-SHA3-256/512, and
CMAC-AES-128/192/256 across both Counter and Feedback mode (16/28). Every
group requesting HMAC-SHA-1, HMAC-SHA2-224, HMAC-SHA2-512/224,
HMAC-SHA2-512/256, or HMAC-SHA3-224 (12/28) correctly returns
`CKR_MECHANISM_PARAM_INVALID` (0x71) via the `_ => Err(...)` arms at
`ffi.rs:8115` and `ffi.rs:8151` — zero silent mishandling observed, exactly
the honest-failure contrast with §2's HKDF bug. The same vector file can be
reused as-is once the missing PRF arms are added.

**Cross-engine behavioral difference worth preserving, not "fixing."** The
C++/OpenSSL engine hardwires counter-before-fixed-data placement regardless
of the caller's `CK_PRF_DATA_PARAM` segment order (a genuine, documented
OpenSSL `KBKDF` provider limitation noted in this session's C++ work). This
Rust engine instead honors literal segment order — a caller must place
`ITERATION_VARIABLE` before `BYTE_ARRAY` in its data-params array to get
"before fixed data" placement. This is more spec-flexible than the C++
engine, not a bug; flagged here only so a future parity pass doesn't
mistake it for a discrepancy to reconcile.

---

## 4. `CKM_ECMQV_DERIVE` and `CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS` — Rust-specific re-assessment

Both mechanisms were investigated for the C++ engine this session and found
to have real ACVP vectors (`KAS-ECC-1.0` fullMqv/onePassMqv for ECMQV;
`ECDSA-KeyGen-FIPS186-5` with `secretGenerationMode: "extra bits"`) but no
usable OpenSSL primitive, and were deliberately left unimplemented there.
Because the Rust engine has a completely different (RustCrypto) backend,
each was re-checked independently rather than assumed to inherit the same
verdict.

**`CKM_ECMQV_DERIVE`.** The primitive-availability picture is genuinely
better in Rust: the `elliptic-curve` crate (pinned transitively at 0.13.8,
underlying `p256`/`p384`/`p521`/`k256`) exposes `Scalar<C>` arithmetic that
is mod-curve-order by construction (no manual modulus bookkeeping the way
OpenSSL's raw `BN_*` calls require), direct operator-overloaded point
addition/scalar multiplication, and `MulByGenerator`/`LinearCombination`
traits that map closely onto MQV's associate-value-function combiner and
shared-point computation. That closes the "no primitive exists" blocker.
**It does not close the reason ECMQV was actually shelved**: the risk was
never library availability, it was that a subtly-wrong MQV combiner (role
asymmetry between U/V, associate-value edge cases, point-at-infinity
handling) can pass every KAT while being cryptographically unsound — a
protocol-correctness risk that's independent of which library supplies the
arithmetic. Recommendation: keep this on hold, same as the C++ side, until
there's appetite for the extra scrutiny a hand-rolled protocol combiner
needs beyond KAT-passing (e.g. a second, independent implementation to
cross-check against, or an existing audited reference to diff against).

**`CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS`.** Meaningfully easier in Rust than the
C++ investigation found for OpenSSL. `elliptic-curve` is built on
`crypto-bigint` (confirmed pinned at 0.5.5 in `rust/Cargo.lock`), which
exposes const-time arbitrary-width integer arithmetic directly, plus a
`Reduce<Uint>` trait already used internally for ECDSA hash-to-scalar
reduction — FIPS 186-5 Appendix A.2.2's "extra bits" method (generate n+64
random bits, reduce mod (order−1), add 1) maps almost directly onto that
existing trait plus one big-integer decrement/compare, with no OpenSSL-style
manual `BN_rand`/`BN_mod`/`BN_add` + `EVP_PKEY_fromdata` workaround needed.
This is a small, mechanical, well-understood gap in Rust — a reasonable
candidate for implementation once the WS-8-equivalent set (§1) is done.

---

## 5. Broader bidirectional parity — flagged, not scoped here

A raw mechanism-list diff (Rust `ffi.rs` dispatch vs. C++
`SoftHSM_slots.cpp::prepareSupportedMechanisms()`) also surfaced items
outside this document's WS-8/ECMQV focus:

- **C++-only, Rust-missing** (beyond §1-§4): the MD5/SHA-1 legacy digest/HMAC
  family, SHA-512/224, SHA-512/256, `CKM_SHAKE_256_KEY_DERIVATION`,
  `CKM_RSA_AES_KEY_WRAP`, the `CKM_*_ENCRYPT_DATA` wrap-with-encrypt family.
- **Rust-only, C++-missing** beyond the already-documented FrodoKEM/Classic
  McEliece gate (§4 of the 2026-07-25 parity doc): Keccak-256,
  `CKM_BIP32_*_LEGACY` aliases, `CKM_RSA_PKCS_RAW`.

These are informational, not evaluated for ACVP/backend feasibility here —
worth a dedicated follow-up pass if full bidirectional parity becomes a
goal, but out of scope for this document, which was scoped to the WS-8 set
plus HKDF/SP800-108 correctness.

---

## 6. Proposed priority order

1. **Fix the HKDF silent-substitution bug (§2)** — highest priority
   regardless of everything else in this document: it's a live correctness
   bug in a mechanism already shipping, not an absent feature.
2. **AES-GMAC and SP800-108 Double-Pipeline KDF (§1)** — zero new
   dependencies, same shape as existing code.
3. **AES-CCM, AES-XTS, AES-OFB, AES-CFB128, AES-CFB8 (§1)** — one new
   RustCrypto crate each, low risk.
4. **SP800-108 Counter/Feedback missing PRFs (§3)** — small, mechanical,
   already has reusable ACVP evidence.
5. **AES-CFB1 (§1)** — small hand-rolled bit-feedback logic, no crate to lean
   on.
6. **`CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS` (§4)** — mechanical but nontrivial;
   do after the above is stable.
7. **`CKM_ECMQV_DERIVE` (§4)** — hold, pending a decision on how to get
   assurance beyond KAT-passing for a hand-rolled protocol combiner.
