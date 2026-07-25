# Remediation plan — closing the C++/Rust PKCS#11 coverage gaps (2026-07-25)

**Execution status (2026-07-25, branch `fix/pkcs11-v32-parity-remediation-0725`,
committed locally, not pushed):** Items 1–3 EXECUTED and verified; item 4
still gated on the go/no-go this doc always said it needed.

- **Item 1 (ECDH cofactor, both engines)** — done as planned. C++:
  `SoftHSM::deriveEDDSA` now rejects `CKM_ECDH1_COFACTOR_DERIVE` for
  `CKK_EC_MONTGOMERY`/`CKK_EC_EDWARDS`; Rust: same gate in `ffi.rs`. Full
  compliance suite green on the C++ side; 312/312 → 319/319 (adds this
  item's 3 new tests) on the Rust side.
- **Item 2 (RSA sign/verify-recovery, Rust)** — done as planned, including
  wiring the real ACVP `RSA-SignaturePrimitive-2.0` vectors in as
  `rust/kat/rsa-signature-primitive-acvp.json`. 78/78 + 12/12 negative cases
  byte-exact, plus round-trip/gate tests. Rust suite: 319/319.
- **Item 3 (hybrid KEM, C++)** — **pivoted during implementation**, with an
  explicit check-in: building turned up that Rust's own hybrid KEM has no
  PKCS#11-level mechanism to mirror (it's KMIP-layer orchestration over two
  ordinary KEMs), and that this engine's `C_EncapsulateKey`/
  `C_DecapsulateKey` hard-rejected everything except `CKM_ML_KEM` — so
  `CKM_ECDH1_DERIVE` (spec-legal there per Table 78) was simply missing.
  Closed that instead of building a new `OSSLHybridKEM` mechanism nobody
  asked for once the premise changed. New `SoftHSM::encapsulateECDH`/
  `decapsulateECDH`, plus a real attribute-registration gap found along the
  way (`CKA_ENCAPSULATE`/`CKA_DECAPSULATE` were ML-KEM-object-only). Proved
  via a new end-to-end `test_hybrid_kem()` — full X25519MLKEM768-shaped
  round trip through real PKCS#11 calls, sender/receiver reconstruct an
  identical 64-byte secret. Full compliance suite: 324/324, 0 regressions.
  Full technical detail in this file's §3 update below and the commit
  message (`feat(cpp): ECDH-as-KEM under C_EncapsulateKey/C_DecapsulateKey`).
- **Item 4 (FrodoKEM/McEliece, C++)** — not started; still needs the
  go/no-go this doc's §4 always flagged before any work begins.

Everything below is the ORIGINAL plan text, left intact for the record
except where a status note like the one above marks what actually
happened. Every mechanism-level claim below is
validated against the ratified OASIS PKCS#11 v3.2 Standard text
(`docs/refs/pkcs11-spec-v3.2-os.pdf`, the final version — not the older CSD01
draft this repo also carries), with inline section citations; see §5 for the
full validation table. That pass corrected the original framing of item 1 —
it started as "two Rust gaps, two C++ gaps" but item 1 turned out to be a
conformance gap in **both** engines, not a Rust-only catch-up item. A
follow-up pass sourced real Known-Answer Test vectors for each item (each
section now has a "Test vectors" note) — items 1 and 2 have authoritative
NIST ACVP sources with confirmed repo paths; item 3 confirmed **no**
authoritative vector exists yet anywhere for the combined hybrid construct,
making its cross-engine test not just good practice but the only available
proof; item 4 already has its KAT fully sourced and sitting in this repo
(`kmip/kat/frodokem/raw/`), reusable as-is.

## Priority order

| # | Item | Direction | Effort | Why this order |
|---|---|---|---|---|
| 1 | ECDH cofactor mode | **Both engines** (see below) | Low | A real spec conformance gap in both, not just a Rust-honesty issue — cheap to close |
| 2 | RSA sign/verify-with-recovery | Rust gap | Medium | Self-contained, reuses existing RSA plumbing, closes a real functional gap |
| 3 | Hybrid KEMs | C++ gap | Medium | No new dependency — OpenSSL already has every primitive needed |
| 4 | FrodoKEM + Classic McEliece | C++ gap | High | New external dependency + WASM risk; **needs a go/no-go decision first**, see §4 |

---

## 1. ECDH cofactor mode (Rust gap — corrected after spec validation, see §5)

**Current state, verified in source**: Rust advertises `CKM_ECDH1_COFACTOR_DERIVE`
(`rust/src/constants.rs:467`, mechanism table `rust/src/ffi.rs:1136`), but the
actual derive dispatch (`rust/src/ffi.rs:6558`) routes it into the **identical**
code path as `CKM_ECDH1_DERIVE`/`CKM_EC_MONTGOMERY_KEY_DERIVE`/`CKM_X25519`/
`CKM_X448` — no cofactor-multiplication branch exists anywhere in
`rust/src/native/agree.rs`, and no key-type check distinguishes them either.
C++'s equivalent (`OSSLECDH::deriveKeyWithCofactor`, `src/lib/crypto/OSSLECDH.cpp:245`,
called from `SoftHSM_keygen.cpp:5591-5596`) does call OpenSSL's
`EVP_PKEY_CTX_set_ecdh_cofactor_mode` — a real, distinct code path — but,
confirmed by reading `SoftHSM_keygen.cpp:5548-5586`, applies it to whatever EC
key it's given via the generic `ECPrivateKey`/`ECPublicKey` accessors, with no
check on the specific EC key subtype.

**Spec validation finding (this changes the original framing)**: the OASIS
PKCS#11 v3.2 Standard (`docs/refs/pkcs11-spec-v3.2-os.pdf`, §6.3.18,
"Table 79, ECDH with cofactor: Allowed Key Types") restricts
`CKM_ECDH1_COFACTOR_DERIVE` to **`CKK_EC` only**. This is a real, narrower
restriction than the plain-ECDH mechanism next to it — §6.3.17's Table 78
("ECDH: Allowed Key Types") explicitly allows both `CKK_EC` **and**
`CKK_EC_MONTGOMERY`. In other words, the spec treats cofactor-mode ECDH as
Weierstrass-curve-only; `CKK_EC_MONTGOMERY` (X25519/X448) is not a valid key
type for this mechanism at all, regardless of what cofactor value X25519
happens to use internally.

C++'s own compliance report (`cpp_compliance_report.md:157`) has a test named
`Derive_X25519_Cofactor` that returns `RV=0` (success) — meaning **C++
currently accepts `CKM_ECDH1_COFACTOR_DERIVE` against an X25519 key**, which
Table 79 says should be rejected (the correct behavior is
`CKR_KEY_TYPE_INCONSISTENT` or equivalent). This was previously read as "C++
is the correct reference, Rust just needs a cofactor branch" — that framing
was wrong. **Both engines currently over-accept `CKK_EC_MONTGOMERY` under
this mechanism; C++'s existing "pass" for this test is itself non-conformant,
not a target to match.**

**Why the underlying math still isn't a live wrong-answer bug**: for every
Weierstrass curve either engine supports (P-256/P-384/P-521, secp256k1),
cofactor h=1, so cofactor-mode and standard-mode ECDH produce byte-identical
output there. The X25519/X448 case is different in kind, not degree — it's
not "harmless cofactor math," it's an invalid key type for the mechanism per
spec, which happens to still produce a usable (if spec-incorrect) shared
secret because RFC 7748 clamping does its own cofactor clearing regardless of
which PKCS#11 mechanism name was used to invoke it.

**Revised recommended fix**:
1. **C++ first**: add the Table-79 key-type check to `SoftHSM_keygen.cpp`'s
   `CKM_ECDH1_COFACTOR_DERIVE` path — reject `CKK_EC_MONTGOMERY` base keys
   with `CKR_KEY_TYPE_INCONSISTENT`. Update `cpp_compliance_report.md`'s
   `Derive_X25519_Cofactor` test to assert the rejection instead of a
   successful derive (or rename/repurpose it as a negative test).
2. **Rust**: add the same `CKK_EC`-only gate before dispatching to
   `CKM_ECDH1_COFACTOR_DERIVE` specifically (the shared match arm at
   `ffi.rs:6558` can stay shared for the derive math itself, since that part
   IS spec-correct for `CKK_EC`; the gate just needs to run first and only
   for the cofactor variant).
3. For the `CKK_EC` case itself (P-256/P-384/P-521, secp256k1), Rust's
   current "route cofactor to the same handler as standard derive" is
   spec-safe as-is (h=1 everywhere → identical output) — no new
   multiplication logic needed there, matching the original (correct) part
   of this analysis. Add the unit test asserting cofactor-mode output equals
   standard-mode output for `CKK_EC` keys specifically, now that
   `CKK_EC_MONTGOMERY` is excluded by the new gate.
4. Correct `rust/RUST_P11_V32_CONFORMANCE_REPORT.md`'s framing accordingly.

**Effort**: still a few hours, now split across both engines instead of
Rust-only — the C++ fix (add a rejection) is smaller than the Rust fix
(add the same rejection, keep the existing math for the valid case).
**Files**: `src/lib/SoftHSM_keygen.cpp`, `cpp_compliance_report.md`,
`rust/src/ffi.rs`, `rust/RUST_P11_V32_CONFORMANCE_REPORT.md`, new/extended
test modules on both sides.

**Test vectors, confirmed real and fetchable**: NIST's ACVP has a dedicated
algorithm for exactly this primitive — `KAS-ECC`, mode `CDH-Component`,
revision `Sp800-56Ar3` (the direct successor to legacy CAVP's `ECC_CDHVS`) —
**not** a flag on the general-purpose KAS-ECC scheme, its own standalone
algorithm/mode. Source: `github.com/usnistgov/ACVP-Server`,
`gen-val/json-files/KAS-ECC-CDH-Component-Sp800-56Ar3/` (`prompt.json` +
`expectedResults.json`); capability spec at
`github.com/usnistgov/ACVP/blob/master/src/kas/sp800-56ar3/ecc/sections/08-ecc-cdh-comp.adoc`.
Its `curve` capability list is `P-224, P-256, P-384, P-521, K-233, K-283,
K-409, K-571, B-233, B-283, B-409, B-571` — **Curve25519 (the curve X25519
is defined over, RFC 7748 — same underlying object, not a separate one) is
not in that list at all**, an independent third-party
confirmation (on top of the spec's own Table 79) that `CKM_ECDH1_COFACTOR_DERIVE`
was never meant to apply to `CKK_EC_MONTGOMERY` keys. Each test case gives
`publicServerX/Y` and expects back `publicIutX/Y` + `z` (the shared secret,
= the cofactor CDH primitive per SP 800-56A Rev.3 §5.7.1.2 — exactly this
mechanism's definition). Caveat: for P-256/384/521 specifically (h=1), the
resulting `z` is numerically identical to what a plain-ECDH KAT would give,
so this vector set proves provenance/documentation-correctness more than it
catches a cofactor-multiplication bug on these particular curves — consistent
with §1's finding that no *behavioral* difference exists for the curves in
scope here.

---

## 2. RSA sign/verify-with-recovery (Rust gap)

**Current state, verified in source**: C++ has a real implementation, RSA-only
(`CKM_RSA_PKCS`/`CKM_RSA_X_509`), single-part-only
(`src/lib/SoftHSM_sign.cpp:1823-1877` for `C_SignRecoverInit`, continuing
through `C_SignRecover`/`C_VerifyRecoverInit`/`C_VerifyRecover`). Rust's
equivalent is a hard stub, always `CKR_FUNCTION_NOT_SUPPORTED`
(`rust/src/ffi.rs:8525-8557`).

**Why this is tractable**: Rust already has the underlying primitive wired.
The existing `CKM_RSA_PKCS` regular-sign path is already a raw, digest-less
PKCS#1v1.5 private-key operation (`rust/src/ffi.rs:13193`, comment: "raw,
digest-less"), using the `rsa` crate (`rust/Cargo.toml:98`, `rsa = "0.9"`,
already in use for keygen/OAEP/PKCS8 elsewhere in `ffi.rs`). Sign-recover is
the same private-key operation; the difference is entirely at the PKCS#11
session-state layer (single-part-only, paired with a recovery-capable verify)
and at verify time, where the public-key operation must return the recovered
padded/unpadded message instead of a boolean match.

**Plan**:
1. Add `C_SignRecoverInit`/`C_SignRecover` to `rust/src/ck_abi.rs` +
   `rust/src/ffi.rs`, mirroring the existing `C_SignInit`/`C_Sign` plumbing but
   restricted to `CKM_RSA_PKCS`/`CKM_RSA_X_509` (matching C++'s restriction —
   don't generalize beyond what C++ supports, or the engines diverge again)
   and marked single-part-only in session state (matching C++'s
   `setAllowMultiPartOp(false)`).
2. Add `C_VerifyRecoverInit`/`C_VerifyRecover`: run the RSA public-key raw
   operation (RSAVP1) and return the recovered message bytes (padding
   stripped for `CKM_RSA_PKCS`, raw for `CKM_RSA_X_509`) rather than
   comparing against a caller-supplied expected value.
3. **Open technical decision**: the `rsa` crate's high-level API
   (`Pkcs1v15Sign`) is verify-or-fail, not verify-and-recover — recovering the
   padded message requires either the crate's lower-level `hazmat` primitives
   (explicitly flagged by RustCrypto as no-automatic-padding-validation, caller
   must get the padding-check logic right) or a hand-rolled modexp using
   `rsa::BigUint` (already imported elsewhere in `ffi.rs`, e.g. line 5201).
   Recommend the `hazmat` path for correctness/maintainability, but flag the
   padding-validation responsibility explicitly in code review — this is the
   one place in this plan where a subtle implementation bug could produce a
   real crypto vulnerability (a recovery function that doesn't correctly
   validate PKCS#1v1.5 padding is a known bug class). Do not ship without a
   negative-path test (malformed padding must be rejected, not silently
   returned).
4. **Tests**: keygen → SignRecover → VerifyRecover round trip for both
   mechanisms; cross-engine byte-exact test (sign in C++, VerifyRecover in
   Rust and vice versa) — matches this repo's existing dual-engine
   parity-verification pattern (`docs/rust-engine.md`'s stated purpose for
   having two engines at all); negative-path test for corrupted signatures
   and wrong-padding data.

**Effort**: medium, roughly 150-250 LOC plus tests. **Files**:
`rust/src/ck_abi.rs`, `rust/src/ffi.rs` (new functions near the existing stub
at 8525), a new or extended test module, `rust/RUST_P11_V32_CONFORMANCE_REPORT.md`.

**Spec validation note**: the OASIS v3.2 Standard actually permits
sign/verify-recovery on **three** RSA mechanisms — `CKM_RSA_PKCS` (Table 39),
`CKM_RSA_9796`/ISO-IEC-9796 (Table 44), and `CKM_RSA_X_509` (Table 45), each
confirmed by direct spec read (`docs/refs/pkcs11-spec-v3.2-os.pdf`, §6.1).
C++ only implements the first and third (`SoftHSM_sign.cpp`'s explicit
`!= CKM_RSA_PKCS && != CKM_RSA_X_509` rejection) — `CKM_RSA_9796` recovery is
unimplemented in **both** engines. This plan scopes Rust to match C++'s two
mechanisms, matching the original intent (engine parity); `CKM_RSA_9796` is a
separate, lower-priority, spec-permitted-but-neither-engine-has-it gap, not
included here.

**Test vectors, confirmed real and fetchable — asymmetric coverage**:

- **`C_SignRecover` (RSASP1, private-key primitive)**: current ACVP has a
  dedicated algorithm, `RSA-SignaturePrimitive-2.0` (`algorithm: "RSA"`,
  `mode: "signaturePrimitive"`), confirmed via
  `github.com/usnistgov/ACVP-Server`, `gen-val/json-files/RSA-SignaturePrimitive-2.0/`.
  90 real test cases (`modulo` 2048/3072/4096, `keyFormat` standard + CRT):
  each gives the full private key (`n,e,d,p,q` or CRT form) and a `message`,
  and `expectedResults.json` gives the true `signature` — 12 of the 90 are
  deliberate negative cases (`testPassed: false`, message representative ≥
  modulus). Direct successor of legacy CAVP's `RSASP1VS`
  (`RSA2SP1testvectors.zip`, same primitive, corroborating source).
- **`C_VerifyRecover` (RSAVP1, public-key primitive)**: confirmed absent
  from both current ACVP and legacy CAVP — NIST's component-testing page
  lists ECC CDH, ECDSA SigGen, KDFs, RSADP, and RSASP1 only; no RSAVP1/RSAEP
  ("verification primitive") mode exists anywhere in the ACVP RSA spec.
  RFC 8017 (PKCS#1 v2.2) defines RSAVP1 algorithmically (§5.2.2) but ships
  **zero** worked numeric examples in any appendix. **Practical KAT for this
  side, stronger than a bare round trip**: the `RSA-SignaturePrimitive-2.0`
  vectors already carry `n`, `e` (public exponent), `message`, and NIST's
  own precomputed `signature` — feed `signature` + `(n,e)` into
  `C_VerifyRecover` and assert the recovered value equals `message` exactly.
  This checks the public-key recovery path against a value NIST computed
  independently (via the private-key `d`-side operation), not against your
  own engine's self-produced signature — real cross-validation, not just
  internal consistency, despite there being no vector set with RSAVP1 in its
  name.

---

## 3. Hybrid KEMs (C++ gap)

**Current state, verified in source**: Rust implements all three
IANA-registered `draft-ietf-tls-ecdhe-mlkem` groups
(`rust/src/native/hybrid.rs`) as two ordinary non-extractable engine keypairs
(a classical X25519/ECDH-P256/ECDH-P384 keypair + an ML-KEM keypair) combined
by **pure concatenation** (`CKM_CONCATENATE_BASE_AND_KEY`, no KDF) in an
exact, per-variant, load-bearing byte order documented in that file's header:

- `X25519MLKEM768` (group 0x11EC): `ss_mlkem ‖ ss_x25519`
- `SecP256r1MLKEM768` (group 0x11EB): `ss_p256 ‖ ss_mlkem`
- `SecP384r1MLKEM1024` (group 0x11ED): `ss_p384 ‖ ss_mlkem`

C++ has zero code for any of this — confirmed by an exhaustive grep across
`src/lib/` for `X25519MLKEM`/`Hybrid`, no hits.

**Why this is tractable without a new dependency**: every primitive needed
already exists in the OpenSSL 3.6 backend C++ already links —
`EVP_PKEY-ML-KEM` and native X25519/EC-P256/EC-P384 `EVP_PKEY` support are
both already referenced in this repo's own root `CLAUDE.md`. The only missing
piece is the mechanism-layer glue: run two independent `EVP_PKEY` operations
and concatenate their outputs in the exact order above. No new crypto math.

**Spec validation**: confirmed by direct read (`docs/refs/pkcs11-spec-v3.2-os.pdf`,
§6.43.3) that PKCS#11 v3.2 has **no dedicated mechanism for classical+PQC
hybrid KEMs** — a full-text search for "hybrid" in the spec turns up only the
unrelated `CKM_X9_42_DH_HYBRID_DERIVE` (classical DH, §6.4.15) and an RNG-type
constant. So building this from generic building blocks
(`CKM_CONCATENATE_BASE_AND_KEY` over two independently-derived secrets) is not
a workaround — it's the only spec-compliant path, and it's the same path
Rust already takes. `CKM_CONCATENATE_BASE_AND_KEY` itself is confirmed
(§6.43.3) to do exactly what Rust's doc comment claims: given a base key
(passed as the `C_DeriveKey` handle) and another key (passed as the
mechanism's `CK_OBJECT_HANDLE` parameter), it produces `base_value ‖
other_value` — pure concatenation, base first, no KDF. This means getting the
per-variant byte order right in C++ is purely about **which secret gets
passed as "base" vs. as the mechanism parameter** — e.g. for
`X25519MLKEM768` (`ss_mlkem ‖ ss_x25519`), the ML-KEM shared secret must be
the `C_DeriveKey` base-key handle and the X25519 shared secret must be the
mechanism's other-key parameter, not the reverse.

**Plan**:
1. **Before writing any code**: read the exact numeric mechanism/group values
   Rust uses for these three (`rust/src/constants.rs`) and reuse them
   verbatim in C++. Do not allocate new codepoints — if the two engines use
   different `CKM_*` values for the "same" mechanism, they're not actually
   interoperable regardless of what the crypto does. If these ride on
   vendor-space codepoints (`0x80000000 | n`), confirm the allocation
   currently lives in the `pqctoday-priv` authority file (per precedent from
   the FrodoKEM/McEliece work, `cacp-frodokem-mceliece-softhsm-kmip-policy-plan-07062026.md`
   §0.1/0.2) and record C++'s adoption of the same values there. Note: the
   spec itself (§7.2/§7.3, the `CKM_VENDOR_DEFINED`/`CKK_VENDOR_DEFINED`
   definitions) says vendors "should register their mechanism/key types
   through the PKCS process" for cross-vendor interoperability — this repo
   already deliberately deviates from that (self-managed authority file
   instead of an OASIS submission), a decision made and documented in the
   prior FrodoKEM/McEliece plan, not something this item reopens.
2. Add `OSSLHybridKEM.cpp/h` (+ `OSSLHybridKEMKeyPair`/`PublicKey`/`PrivateKey`,
   following the existing `OSSLMLxxx` file-naming convention this repo's
   `CLAUDE.md` documents for new PQC algorithms) implementing:
   - Keygen: an X25519/EC keypair + an ML-KEM keypair, each via existing
     `EVP_PKEY_CTX_new_from_name` patterns already used elsewhere in this
     codebase (`OSSLMLKEM.cpp`, `OSSLECDH.cpp`).
   - Encapsulate: ephemeral-static ECDH(E) against the peer's classical
     public key + ML-KEM encapsulate against the peer's ML-KEM public key,
     concatenated per the table above. **Spec-mandated output-key
     attributes** (§5.18.8, `C_EncapsulateKey`): the new secret-key object
     MUST have `CKA_ALWAYS_SENSITIVE=FALSE`, `CKA_NEVER_EXTRACTABLE=FALSE`,
     `CKA_LOCAL=FALSE`, `CKA_EXTRACTABLE` from the caller's template
     (default `TRUE` if omitted) — these are fixed by the spec, not this
     implementation's choice, and must match however the existing
     single-algorithm `C_EncapsulateKey` paths (ML-KEM's own) already set
     them, for consistency. Also confirm the public key's `CKA_ENCAPSULATE`
     is `TRUE` before allowing the operation, per the same section — the
     existing ML-KEM path already enforces this pattern; reuse it rather
     than re-deriving it.
   - Decapsulate: mirror, using the static private halves.
3. Register the three mechanisms in `SoftHSM::prepareSupportedMechanisms`
   and the key type in `OSSLCryptoFactory::getAsymmetricAlgorithm`, per the
   conventions `CLAUDE.md` already documents.
4. **Cross-engine test, written first (red-first)**: generate a keypair in
   one engine, encapsulate in the other, decapsulate back in the first,
   assert the shared secret matches byte-for-byte — for all three groups,
   both directions. This is the test that actually proves the concatenation
   order was copied correctly; don't consider this item done without it.

**Effort**: medium — no new external dependency, but real risk of a subtle
byte-order mismatch against Rust if the cross-engine test isn't written and
run before considering this complete.

**Files**: new `src/lib/crypto/OSSLHybridKEM.{cpp,h}` (+ KeyPair/PublicKey/
PrivateKey siblings), `src/lib/SoftHSM.cpp` (mechanism table),
`src/lib/crypto/OSSLCryptoFactory.cpp`, a new cross-engine test (natural home:
alongside the existing `p11_v32_compliance_test.cpp` or a new
`test_hybrid_kem_cross_engine.cpp`), `CLAUDE.md` update once shipped (currently
mis-attributes hybrid KEMs to C++ — see the companion gap-analysis doc §5).

**Test vectors — checked thoroughly, none exist yet; the cross-engine test
above is not optional, it's the only proof available.** Fetched
`draft-ietf-tls-ecdhe-mlkem-05` directly (current version, IESG-approved) —
its only appendix is a change log, no test-vectors section. Checked every
major reference implementation for committed fixed-answer vectors on the
*combined* construct: BoringSSL, AWS-LC, Go's `crypto/tls` (production
X25519MLKEM768 support), CIRCL, and liboqs/oqs-provider — all implement the
combiner but test it only with live/randomized round trips, none ship a
fixed expected-output KAT for any of the three groups. This confirmed one
useful, previously-undocumented fact: **the per-group byte order is not
uniform** — verified directly from the draft text and cross-checked against
Go's production `key_schedule.go` (which cites the same draft section
inline): `X25519MLKEM768` really is ML-KEM-first (`ss_mlkem ‖ ss_x25519`,
matching Rust's implementation exactly), but `SecP256r1MLKEM768` and
`SecP384r1MLKEM1024` are ECDH-first (`ss_ecdh ‖ ss_mlkem`) — also matching
what's already documented in `rust/src/native/hybrid.rs`, so this is an
independent confirmation of the existing order, not a new correction. IANA's
raw TLS-parameters registry (`iana.org/assignments/tls-parameters/tls-parameters-8.csv`,
fetched directly to avoid a stale-HTML transcription error caught mid-check)
confirms group IDs `0x11EC/0x11EB/0x11ED` are current and marks only
`X25519MLKEM768` as `Recommended: Y` — the other two are `N`, a reasonable
tiebreaker for sequencing within this item if it's split into sub-steps
(implement/test X25519MLKEM768 first).

Since no third-party oracle exists, two supplementary (not substitute)
options: (a) validate the combiner's plumbing in isolation using RFC 7748's
own real, fetchable X25519 test vectors (`rfc-editor.org/rfc/rfc7748.html`
§5.2 — confirmed present, e.g. scalar `a546e36bf05...` → output `c3da5537...`)
composed with the existing ML-KEM ACVP vectors already in this repo
(`kmip/kat/ml-kem/ml-kem-acvp.json`) — proves byte-ordering/length logic is
right, but is not itself a hybrid KAT since nobody has published the joint
output for these specific inputs; (b) longer-term, capture a real wire
transcript from a live TLS 1.3 handshake against Go 1.23+ (`crypto/tls`
enables `X25519MLKEM768` by default) or a BoringSSL/AWS-LC build, and adopt
that transcript as this project's own first committed KAT for the construct
— worth doing once, but not a blocker for this remediation pass.

---

## 4. FrodoKEM + Classic McEliece (C++ gap) — needs a decision before starting

**Current state, verified in source**: Rust implements both via pure-Rust
crates — `frodo-kem` (6 standard param sets, RustCrypto/KEMs, its own README
states "never independently audited") and `classic-mceliece-rust` v3.1.0
(scoped to `mceliece6688128` only; the crate can only compile **one**
parameter set per binary — a real architectural limit, not a scoping choice).
Both have real KAT coverage: 600 official FrodoKEM vectors (Microsoft's
reference implementation) all passing, and bidirectional `liboqs`
cross-validation for McEliece (no independent static KAT file exists for it).
Full detail in `cacp-frodokem-mceliece-softhsm-kmip-policy-plan-07062026.md`
(workspace root) — that plan's own title is "SoftHSMv3 **Rust** → KMIP →
Crypto Policy"; C++ was never in scope.

C++ has neither algorithm, and — unlike hybrid KEMs above — **cannot get them
from OpenSSL**: neither FrodoKEM nor Classic McEliece is NIST-selected or in
OpenSSL's algorithm set; both are BSI TR-02102-1 recommendations only. This
means a genuinely new dependency, not glue code.

### Decision needed before any implementation work

This item is materially different from the other three: it requires vendoring
a new C library, and the strategic direction visible across the rest of this
audit points toward Rust, not C++, as the forward path — KMIP/CACP already
run exclusively on Rust, and the active `feat/rust-pkcs11-emscripten-staticlib`
work is specifically *replacing* C++ with Rust in the OpenSSL Studio
integration because C++'s OpenSSL dependency made it circular there. Investing
high effort to bring C++ up to parity on two BSI-only, non-audited-crate
algorithms may not be worth it if C++'s role keeps shrinking. **Recommend
confirming intent (full parity vs. accept this as a permanent, documented
Rust-only asymmetry) before starting implementation.**

### If parity is confirmed, the plan:

1. **Dependency**: vendor `liboqs` (the C reference library) under `deps/`,
   matching the existing `deps/openssl-src` pattern (submodule or CMake
   `FetchContent`). License is MIT, compatible. This is not a new trust
   decision — `liboqs` already serves as Rust's own cross-validation oracle
   for these exact algorithms (`kmip/tests/pqc_interop_liboqs.rs` per the
   prior plan's Phase 0.9), so its correctness is already being relied on
   indirectly.
2. Implement via `liboqs`'s C API directly (`OQS_KEM_new`/`keypair`/
   `encaps`/`decaps`) — not through OpenSSL EVP, since `liboqs` is a
   standalone library in this build, not a registered OpenSSL provider here.
   New `OSSLFrodoKEM.cpp/h` + `OSSLClassicMcEliece.cpp/h` (or a shared base
   class, since both just wrap `liboqs` calls).
3. **Reuse Rust's exact vendor codepoints** (`CKM_PQCTODAY_FRODOKEM_*`,
   `CKM_PQCTODAY_CLASSIC_MCELIECE_*`, `0x80000000 | n` range) from the
   `pqctoday-priv` authority file — same reasoning as hybrid KEMs, §3 step 1.
4. **Scope to what Rust already ships** — 6 FrodoKEM variants,
   `mceliece6688128` only — to keep the two engines aligned by default.
   Note: `liboqs` selects McEliece parameter sets at runtime (no
   single-parameter-set restriction the way `classic-mceliece-rust` has), so
   C++ *could* ship more McEliece variants than Rust here. Flag as a
   possible follow-up asymmetry, not part of this pass — parity means
   matching Rust's current surface, not exceeding it.
5. **Reuse Rust's KAT evidence directly — already in this repo, confirmed
   present, no new sourcing needed**: `kmip/kat/frodokem/raw/` already has
   all 600 official FrodoKEM vectors (100 each × 6 variants, NIST `.rsp`
   format, `seed`/`pk`/`sk`/`ct`/`ss` fields), sourced and provenance-documented
   in `kmip/kat/frodokem/README.md` — from `microsoft/PQCrypto-LWEKE`
   (frodokem.org's own cited reference implementation), confirmed salted
   (current-spec) variant, pinned in `kmip/kat/manifest.sha256`. Point a new
   C++ test (`test_frodokem_mceliece_kat.cpp`) at this exact directory rather
   than re-fetching — both engines then verify against the identical bytes,
   not independently re-derived copies. For Classic McEliece, there is
   deliberately **no static KAT file** (confirmed: neither
   `classic-mceliece-rust`'s own harness nor PQClean ships one — both
   generate vectors at test time, and using the crate's own generator to
   validate this engine would be circular) — the established, already-proven
   pattern is bidirectional `liboqs` cross-validation instead (`kmip/tests/pqc_interop_liboqs.rs`
   for the Rust side); port the same directional-swap pattern (encaps with
   `liboqs`/decaps with the engine, and the reverse) into the new C++ test.
6. **Cross-engine round-trip test** (keygen/encapsulate in one engine,
   decapsulate in the other, both directions), matching the pattern in §3.
7. **WASM build risk — the real open question**: `deps/openssl-wasm`
   already shows this repo can cross-compile OpenSSL under Emscripten, but
   `softhsmrustv3design.md` explicitly states pure-Rust was chosen for the
   Rust engine's WASM path *specifically to avoid* C-toolchain WASM
   complexity. Adding `liboqs` to the C++ Emscripten build reintroduces
   exactly that class of problem. If it proves too costly, scope this item
   to the **native C++ build only** and explicitly document FrodoKEM/McEliece
   as staying Rust-only in the browser — an intentional, documented
   asymmetry rather than a silent gap.

**Effort**: high — new external C dependency, new build-system integration
(native + a real WASM cross-compilation risk), two new algorithm families end
to end, full KAT/cross-validation suite. Larger than items 1–3 combined.

**Files**: `deps/liboqs/` (new), `CMakeLists.txt`, new `src/lib/crypto/OSSLFrodoKEM.{cpp,h}`
and `OSSLClassicMcEliece.{cpp,h}`, `src/lib/SoftHSM.cpp`, a new KAT test file,
`docs/README.md` (if scoped native-only, document that explicitly).

---

## 5. Spec validation pass (2026-07-25)

Every mechanism-level claim in this plan was checked against the ratified
OASIS Standard text, not the earlier CSD01 draft or any secondary doc —
`docs/refs/pkcs11-spec-v3.2-os.pdf` (both files present in this repo;
`-os` is the final, ratified version, added 2026-07-23, and is the one used
here per this repo's own `CLAUDE.md` sourcing rule for `CK*` values).

| Claim | Verdict | Evidence |
|---|---|---|
| `CKM_ECDH1_COFACTOR_DERIVE` is a distinct, spec-legal optional mechanism | Confirmed | §6.3.18 |
| Cofactor mode is behaviorally a no-op for h=1 curves | Confirmed (math) | — |
| Cofactor mode is valid for X25519/X448 (`CKK_EC_MONTGOMERY`) | **Wrong — corrected** | §6.3.18 Table 79 restricts this mechanism to `CKK_EC` only, unlike plain ECDH's Table 78 which allows both. Both engines currently over-accept `CKK_EC_MONTGOMERY` here; C++'s existing passing test for this is itself non-conformant. See revised §1. |
| `C_SignRecover`/`C_VerifyRecover` are optional (§5.13) | Confirmed | §5.13.5/5.13.6 |
| RSA is the only key family with recovery semantics defined | Confirmed, with a gap noted | Tables 39/44/45 (§6.1) — `CKM_RSA_PKCS`, `CKM_RSA_9796`, `CKM_RSA_X_509`. Neither engine implements `CKM_RSA_9796` recovery; out of scope here, noted in §2. |
| `CKM_CONCATENATE_BASE_AND_KEY` does pure `base‖other` concatenation, no KDF | Confirmed | §6.43.3 |
| No PKCS#11 v3.2 mechanism exists for classical+PQC hybrid KEMs | Confirmed | full-text search, only unrelated hits (§6.4.15 X9.42 DH hybrid; an RNG type constant) |
| `CKM_VENDOR_DEFINED`/`CKK_VENDOR_DEFINED` = `0x80000000` | Confirmed | §7.2 (spec) and `src/lib/pkcs11/pkcs11t.h:444,1250` (local header, matches) |
| `C_EncapsulateKey`'s output secret-key object has spec-fixed attribute defaults (`CKA_ALWAYS_SENSITIVE=FALSE`, `CKA_NEVER_EXTRACTABLE=FALSE`, `CKA_LOCAL=FALSE`, `CKA_EXTRACTABLE` from template) and requires `CKA_ENCAPSULATE=TRUE` on the public key | Confirmed | §5.18.8 |
| Vendors "should register" new mechanism/key types "through the PKCS process" for interoperability | Confirmed, and this repo knowingly deviates | §7.2/§7.3. This repo uses a self-managed internal authority file instead (decided in the prior FrodoKEM/McEliece plan) — not reopened by this plan, just noted as the spec's stated preference vs. actual practice here. |

**Net effect on the plan**: items 2–4 held up as originally written, with
added footnotes (§2: `CKM_RSA_9796` is a third spec-permitted recovery
mechanism neither engine has; §3: `C_EncapsulateKey`'s fixed output-attribute
requirements and the vendor-registration-process note, cross-referenced from
§4). Item 1 required a real correction — the original framing treated C++ as
the spec-correct reference Rust needed to catch up to; validation shows C++
itself has a Table-79 conformance gap for X25519/X448 under cofactor mode, so
§1 now fixes both engines instead of just Rust.

## Cross-cutting notes for whoever picks this up

- Every item above should ship with a **cross-engine byte-exact test**, not
  just an in-engine round trip — the whole point of two engines existing is
  verified interop, and every gap found in the original audit was caught by
  reading source, not by trusting either engine's own self-reported
  conformance doc.
- Items 1–3 don't require any decision beyond normal code review. Item 4
  does — get an explicit go/no-go before starting, given the effort size and
  the visible strategic drift toward Rust elsewhere in this repo.
- None of this has been implemented. This file and the companion gap-analysis
  doc are the full output of this audit+plan pass.
