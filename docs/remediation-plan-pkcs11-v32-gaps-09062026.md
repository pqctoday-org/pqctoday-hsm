# Remediation Plan — PKCS#11 v3.2 Coverage Gaps (2026-09-06, rev 3)

**Date:** 2026-09-06 (rev 3 — see §0 for what each revision changed)
**Baseline:** `origin/main` @ `1e8db083` (v0.28.1/0.28.2)
**Source:** [pkcs11-hsm-v32-compliance-audit-09062026.md](../../pkcs11-hsm-v32-compliance-audit-09062026.md) (workspace-root audit, incl. Errata) + two challenge passes recorded in §0.
**Status:** PARTIALLY EXECUTED — see §9. Phase 1 (C1, C3, R3, D-4, D-1, R1′, R2′a) is implemented, verified and committed locally on branch `fix/pkcs11-v32-gaps-0906`; Phases 2–4 are not started. Nothing is pushed. Push/merge stays gated on explicit user go-ahead (real CI + required review on `main`).
**Spec text:** primary citations are `file:line` into the vendored OASIS markdown under `docs/refs/pkcs11-v3.3-draft-git-snapshot-20260828/working/doc/spec/` (`spec/` below). Section numbers follow the v3.2 CSD01 PDF table of contents (`docs/refs/pkcs11-spec-v3.2-csd01.pdf`); rev 2 had several wrong (§0.2) — confirm against the PDF before a section number goes into a commit message or the ledger.

## 0. Revision log

### 0.1 rev 1 → rev 2 (re-grounding in spec + code + the repo's own ledger)

| Rev 1 item | Verdict |
|---|---|
| C1 `CKA_EXTRACTABLE` on `C_UnwrapKey` | Confirmed and broadened to four functions. |
| R1 PKCS#8-wrapped EdDSA import can't sign | Retracted as a bug — diagnosis predates PR #212 which refuted it; caller passes raw scalars as the spec requires. |
| C2 `CKO_TRUST` missing in C++ | Confirmed; Rust also under-implemented (no §4.7 MUST rules). |
| R2 HMAC_GENERAL 13 vs 5 | Mis-framed; whole hash family; MD5/SHA-1/SHA-224 already adjudicated. |
| X1 `EC_KEY_PAIR_GEN_W_EXTRA_BITS` absent everywhere | Wrong on Rust (implemented). No parameter exists. |
| X2 Signal mechanisms | Out of declared scope; real gap is the absence of a mechanism ledger. |
| R3 `CKO_VALIDATION` creation | Confirmed real. |
| — | Missed: 3 tracked `DEFECT-RUST-*` ledger entries; ledger citation quality. |

### 0.2 rev 2 → rev 3 (two independent adversarial reviews of rev 2, C++/cross-cutting and Rust)

| Rev 2 claim | Verdict | Rev 3 |
|---|---|---|
| C1 fix = "append `CKA_EXTRACTABLE=TRUE` at six call sites" | **Holds** (template wins over class default: `P11Attribute::init` calls `setDefault()` only when absent, [P11Attributes.cpp:114-116](../src/lib/P11Attributes.cpp#L114); `saveTemplate` applies template values after). **But** the callers use fixed `secretAttribs[32]` arrays with an overflow guard — an appended entry can overrun a full template. | C1: reserve a slot. |
| C1 "also confirm ALWAYS_SENSITIVE/NEVER_EXTRACTABLE/LOCAL" | Already forced FALSE post-create at all six sites ([keygen:2413-2417](../src/lib/SoftHSM_keygen.cpp#L2413), `:2800-2802`; [kem:412-414](../src/lib/SoftHSM_kem.cpp#L412), `:716-718`, `:1048-1050`, `:1298-1300`). | Dropped. |
| C1 "every existing scenario sets it explicitly" | **Wrong.** `encoding.wrap_private_key_pkcs8`'s unwrap template omits it ([scenarios.inc:758-762](../tests/differential/scenarios.inc#L758)) — that is the divergence the ledger entry masks. Deleting the entry *is* the pre-fix-failing `C_UnwrapKey` regression. | C1 tests. |
| C1 downstream-risk list (hub files) | **Misdirected.** Hub routes unwrap/KEM to the Rust shim ([pqctoday-hub `softhsm.ts:179-251`]); JavaJCE, OpenSSL provider, strongswan all set the flag explicitly. Downstream risk is nil. | C1 corrected. |
| C1 cites `C_UnwrapKeyAuthenticated` as §5.18.4 | CSD01 TOC: §5.18.7. | Fixed. |
| C2 Rust MUST-rule fix | **Breaks WP4a as written** — its template has trust attrs but no `CKA_HASH_OF_CERTIFICATE` (footnote ²). | C2: WP4a rewrite is part of the item. |
| C2 footnote ³ "open question" | **Settled**: absence is a legitimate state (`spec/object_mgmt_functions.md:314-316`); today's Rust behaviour is spec-consistent. `CKA_PRIVATE=FALSE` default genuinely missing. | D6 records it. |
| R3 normative hook = "read only, token objects" | **Wrong hook.** The mandate is `spec/creating_objects.md:26-29` + the "Other Objects" table (`spec/object_classification.md:21-26`): `CKO_HW_FEATURE`, `CKO_MECHANISM`, `CKO_PROFILE`, `CKO_VALIDATION` are non-storage. Rust has no constants for the first two and will create `CKA_CLASS=0x5/0x7`. | R3 widened to all four. |
| D-1 "`DEFECT-RUST-WRAPPED-PRIVATE-KEY-NOT-PKCS8` probably stale" | **Wrong — it is worse than recorded.** `pkcs8_private_key_info` puts the raw scalar directly in the `privateKey` OCTET STRING ([ffi.rs:10959-10963](../rust/src/ffi.rs#L10959)); RFC 5915 requires an `ECPrivateKey` SEQUENCE there, RFC 8410 a nested `CurvePrivateKey` OCTET STRING. 60 B → 72 B after KWP is exactly the ledger's number; C++/OpenSSL cannot parse it. Same-engine round-trip is broken too ([ffi.rs:11446-11449](../rust/src/ffi.rs#L11446)). | D-2 re-scoped: encoder **and** decoder, effort L. |
| D-2 "inverse of `pkcs8_private_key_info`" | Would parse the malformed shape and reject C++'s correct one. | D-2 parses the standard shape (reuse the `unwrap_pqc_pkcs8_private_key` walker, [ffi.rs:5500](../rust/src/ffi.rs#L5500)). |
| R1′ "PKCS#8 in `CKA_VALUE` is a caller error" | **Inconsistent** with PR #212, which made the engine accept and normalise PKCS#8 for ML-DSA/ML-KEM. Existing test `b5_eddsa_import_rejects_wrong_length_value` ([ffi.rs:23624-23660](../rust/src/ffi.rs#L23624)) accepts either outcome. `validate_create_template` does not require `CKA_EC_PARAMS` for Edwards. | D5 + R1′ rewritten. |
| R2′ inventory | **Wrong in three places.** `CKM_SHA512_224/512_256/SHA3_224/SHA3_384_HMAC` are already dispatched in `sign_hmac` ([handlers.rs:1628-1657](../rust/src/crypto/handlers.rs#L1628), 2026-09-02) but absent from `C_Sign`, mechanism-info and the advertised list — implemented-but-unreachable. `CKM_ECDSA_SHA3_224/384` already exist. Missing RSA: `SHA3_256/512_RSA_PKCS(_PSS)` despite their digests existing. SHA-224 is compiled in for KBKDF/pre-hash ([ffi.rs:9741](../rust/src/ffi.rs#L9741), `handlers.rs:495/510`), so the ledger's "omitted deliberately" is false in spirit. Rust ships `CKM_RIPEMD160` labelled "historical". | R2′ split a/b/c; D2 widened. |
| X1 C++ "`EVP_PKEY_fromdata` with the private scalar" | Must compute the public point explicitly (existing pattern does `EC_POINT_mul` + `OSSL_PKEY_PARAM_PUB_KEY`, [OSSLECPrivateKey.cpp:189-202](../src/lib/crypto/OSSLECPrivateKey.cpp#L189)); crypto layer has no mechanism input ([AsymmetricAlgorithm.h:260](../src/lib/crypto/AsymmetricAlgorithm.h#L260)); keygen routing hard-codes at `keygen:548/605/636/669`, `:5641/:5726`. Still M. | X1 updated. |
| X2′ "nothing records mechanism status" | Premise holds; but `remoting/coverage_ledger.json` + `remoting/scripts/check_coverage_ledger.py` is exactly the shape needed, and `env.mechanism_set` already dumps per-engine sets. | X2′ extends that pattern. |
| H1 "other citations may be wrong" | **Substantiated.** `LEGAL-KEY-GEN-MECHANISM-ON-ENCAPSULATED-KEY` is wrong (see D-4). § numbering drift in rev 2 (§4.9 is *public* key objects; Table 28→29; Tables 66/68 are *public* Edwards/Montgomery, private are 67/69). | H1 expanded; numbers fixed here. |
| §8 "verify prior work by `merge-base --is-ancestor`" | **Misleading for squash merges**: #212 is a squash of the b5 branch; ancestry says "unmerged" while the diff is identical and all five test names are on main. | §8: verify by diff / test presence. |
| — | **New C++ conformance defect**: `CKM_CONCATENATE_BASE_AND_KEY` writes the NEVER_EXTRACTABLE result into `CKA_ALWAYS_SENSITIVE` (clobbering it) and never writes `CKA_NEVER_EXTRACTABLE`. | C3 (new). |
| — | **New Rust conformance defect**: KEM shared-secret keys carry `CKA_KEY_GEN_MECHANISM=<mech>` with `CKA_LOCAL=FALSE`; spec says `CK_UNAVAILABLE_INFORMATION`. Ledger calls it legal. | D-4 (new). |

Everything the engines claim is **Baseline Provider** (Profiles v3.2 §5.1: "Supports the following mechanisms: a. None specified"); `exceptions.json`'s `LEGAL-MECHANISM-SET` adjudicates cross-engine mechanism-set divergence as a product decision. So the **conformance defects are C1, C3, R3, D-2, D-4, and C2's MUST-rules**; the rest is parity, import-policy consistency, or hygiene.

## 1. Decisions required before execution

| # | Decision | Recommendation |
|---|---|---|
| **D1** | C++ `CKA_EXTRACTABLE` default where the spec mandates `CK_TRUE` — `C_UnwrapKey` (§5.18.4), `C_UnwrapKeyAuthenticated` (§5.18.7), `C_EncapsulateKey` (§5.18.8), `C_DecapsulateKey` (§5.18.9). Ledger records the current `CK_FALSE` as "the more conservative" policy, mis-cited as spec-permitted. | **Conform.** The material already exists outside the token in all four cases (Rust's rationale, [ffi.rs:5742-5759](../rust/src/ffi.rs#L5742)); no project doc argues for FALSE. If FALSE is kept, the ledger entry must say "deliberate non-conformance". |
| **D1b** | `C_CreateObject` default — spec token-specific (§4.8 common key attributes footnote). C++ FALSE, Rust TRUE since PR #222 ([ffi.rs:5770](../rust/src/ffi.rs#L5770)). Legal, unrecorded. | Record as a `LEGAL-*` entry, or align C++ to Rust. Don't leave it unrecorded. |
| **D2** | Hash-family scope. Ledger `LEGAL-WEAK-PRIMITIVES-ABSENT-IN-RUST` says "MD5, SHA-1 and SHA-224 … deliberately"; `CLAUDE.md` (C++ architecture section) lists SHA-1/224 as retained; Rust already compiles SHA-224 for KBKDF and pre-hash, and ships RIPEMD-160 as "historical". | Decide **per hash, explicitly**: MD5 out, SHA-1 out, SHA-224 **in** (not weak; already linked), RIPEMD-160 — pick one (recommend: keep, but label consistently). Rewrite the ledger sentence to match; fix `CLAUDE.md`. |
| **D3** | E5 (Rust stores asymmetric keys as an engine-internal blob under `CKA_VALUE`) — schedule or defer? | **Defer E5; do D-2 now.** D-2 fixes the PKCS#8 *wire* format both directions without changing storage. |
| **D4** | `CKO_TRUST` on both engines vs Rust-only fix? | **Both** — a class on one engine can never be differentially tested. |
| **D5** | Import-shape policy for `CKA_VALUE` on private keys: PR #212 accepts + normalises PKCS#8 for ML-DSA/ML-KEM; the spec defines raw bytes for every private key type. Strict everywhere would break #212's real caller (OpenPGP hands PKCS#8 for the PQC halves). | **Uniform leniency with fail-fast**: raw at the known size → accept; a recognised PKCS#8 shape → normalise (extend to Edwards/Montgomery via RFC 8410); anything else → `CKR_ATTRIBUTE_VALUE_INVALID` at create. Record in the ledger as a deliberate extension. |
| **D6** | Reading of `CKO_TRUST` footnote ³ ("missing CKA_TRUST_XXX attributes are treated as CKT_TRUST_UNKNOWN"). | Absence stays a legitimate object state; `C_GetAttributeValue` on an unset one returns `CKR_ATTRIBUTE_TYPE_INVALID` + `CK_UNAVAILABLE_INFORMATION` (`spec/object_mgmt_functions.md:314-316`, today's Rust). Apply to both engines; record. |

## 2. Summary

| # | Item | Class | Engine(s) | Severity | Effort |
|---|---|---|---|---|---|
| C1 | `CKA_EXTRACTABLE` default `CK_TRUE` on unwrap / unwrap-auth / encapsulate / decapsulate | **defect** | C++ | Medium | S |
| C3 | `CKM_CONCATENATE_BASE_AND_KEY` clobbers `CKA_ALWAYS_SENSITIVE`, never sets `CKA_NEVER_EXTRACTABLE` | **defect** | C++ | Medium | XS |
| R3 | Non-storage classes (`CKO_HW_FEATURE`, `CKO_MECHANISM`, `CKO_VALIDATION`) creatable via `C_CreateObject` | **defect** | Rust (+ C++ return code) | Low | XS |
| D-4 | KEM keys carry `CKA_KEY_GEN_MECHANISM` with `CKA_LOCAL=FALSE` | **defect** | Rust | Low | XS |
| D-2 | PKCS#8 `PrivateKeyInfo` wire format: `C_WrapKey` emits a malformed one for EC/Edwards; `C_UnwrapKey` never parses one | **defect** (§6.7, §6.3.10) | Rust | Medium-High | L |
| C2 | `CKO_TRUST` §4.7: MUST-rules + defaults (Rust), class (C++) | **defect** (Rust rules) + parity | both | Low-Medium | Rust S, C++ M |
| R1′ | Import-shape policy (D5): normalise Edwards/Montgomery PKCS#8, fail fast otherwise, require `CKA_EC_PARAMS` | consistency | Rust (check C++) | Low | S |
| R2′a | Advertise + route the four already-implemented HMAC variants | drift | Rust | Low | S |
| R2′b | Digests SHA-512/224, SHA-512/256, SHA3-224, SHA3-384 + `_HMAC_GENERAL`; `RIPEMD160_HMAC_GENERAL`; SHA-224 family per D2 | parity | Rust | Low | M |
| R2′c | `CKM_SHA3_256/512_RSA_PKCS(_PSS)` | parity | Rust | Low | S |
| X1 | `CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS` — C++, then JavaJCE + OpenSSL provider | parity / tracked TODO | C++, providers | Low | C++ M, providers S |
| D-1 | Re-run differential harness; correct/retire ledger entries | hygiene | — | — | XS |
| X2′ | Per-`CKM_*` header-vs-engine ledger (extend the remoting ledger pattern) | hygiene (structural) | both | — | M |
| H1 | Re-verify all ledger citations; § numbering; stale plan-doc status; `CLAUDE.md`; branch cleanup | hygiene | — | — | S |

Effort scale as in `docs/fix-plan-rust-pkcs11-v3.2-compliance.md`: XS < S (≤½ day) < M (1–2 days) < L (multi-day).

---

## 3. Track C++

### C1 — `CKA_EXTRACTABLE` default — *D1*

**Spec.** `spec/key_management_functions.md:301` (`C_UnwrapKey`) and `:623` (`C_UnwrapKeyAuthenticated`): "The **CKA_EXTRACTABLE** attribute is by default set to CK_TRUE." `:751-752` (`C_EncapsulateKey`) and `:857-858` (`C_DecapsulateKey`): "set to the value of the input template with a default of CK_TRUE if not provided".

**Code.** `P11AttrExtractable::setDefault()` hard-codes `CK_FALSE` ([P11Attributes.cpp:1972](../src/lib/P11Attributes.cpp#L1972)); `setDefault()` has no operation argument ([P11Attributes.h:129](../src/lib/P11Attributes.h#L129)). Affected call sites: [SoftHSM_keygen.cpp:2398](../src/lib/SoftHSM_keygen.cpp#L2398) (unwrap), `:2789` (unwrap-auth), [SoftHSM_kem.cpp:400](../src/lib/SoftHSM_kem.cpp#L400), `:704`, `:1036`, `:1286` (KEM; none sets the attribute). A template-supplied value wins over the class default (`init` defaults only when absent, `saveTemplate` applies the template afterwards; `OBJECT_OP_DERIVE`/`UNWRAP` permitted at [P11Attributes.cpp:518](../src/lib/P11Attributes.cpp#L518)). `CKA_LOCAL`/`ALWAYS_SENSITIVE`/`NEVER_EXTRACTABLE` are already forced FALSE post-create at all six sites.

**Fix.** At each site, if the caller's template omits `CKA_EXTRACTABLE`, add `CKA_EXTRACTABLE = CK_TRUE` to the array passed to `CreateObject`. Two traps: (1) the arrays are fixed-size (`secretAttribs[32]`) with a guard `ulCount > maxAttribs - secretAttribsCount` ([keygen:2279-2302](../src/lib/SoftHSM_keygen.cpp#L2279), [kem:320-335](../src/lib/SoftHSM_kem.cpp#L320)) — reserve a slot the way the HBS path reserves `maxAttribs - 3` ([SoftHSM_objects.cpp:1249](../src/lib/SoftHSM_objects.cpp#L1249)); (2) in the unwrap paths, add it after the `CKA_UNWRAP_TEMPLATE` presence check (`keygen:2329-2369`). Do **not** key on `OBJECT_OP_DERIVE` — `C_DeriveKey` uses it too (`keygen:3244, 6784, 7203, 7879`) and there the default is token-specific / inherited (`spec/diffie-hellman.md:400-412`).

**Tests / gate.** Delete `LEGAL-UNWRAPPED-KEY-EXTRACTABLE-DEFAULT` ([exceptions.json:84-89](../tests/differential/exceptions.json#L84)) — the existing `encoding.wrap_private_key_pkcs8` unwrap template already omits the attribute, so the harness fails pre-fix and passes post-fix for `C_UnwrapKey` with no new scenario. Add scenarios for `C_UnwrapKeyAuthenticated` and `C_EncapsulateKey`+`C_DecapsulateKey` that omit it and probe `CKA_EXTRACTABLE` on both engines. Same assertions in the C++ conformance suite (`p11_v32_compliance_test.cpp`, the `CMakeLists.txt:175-180` target); regenerate `cpp_compliance_report.md`. Downstream: none — hub routes unwrap/KEM to the Rust shim; JavaJCE (`P11AESWrapCipherSpi.java:154/185`, `P11MLKEMSpi.java:117/154`, `P11HKDFKDFSpi.java`), the OpenSSL provider (`kem/mlkem.c:155/259`) and strongswan (`pkcs11_kem.c:319/460`) all set the flag explicitly.

### C3 — `CKM_CONCATENATE_BASE_AND_KEY` attribute clobber (new)

**Spec.** `spec/miscellaneous_simple_key_derivation_mechanisms.md:120-125`: derived key's `CKA_ALWAYS_SENSITIVE` = TRUE iff both originals are; `CKA_NEVER_EXTRACTABLE` = TRUE iff both originals are.

**Code.** [SoftHSM_keygen.cpp:7919](../src/lib/SoftHSM_keygen.cpp#L7919) sets `CKA_ALWAYS_SENSITIVE` correctly, then `:7925` writes the *NEVER_EXTRACTABLE* result into `CKA_ALWAYS_SENSITIVE` again (copy-paste), so `CKA_ALWAYS_SENSITIVE` ends up wrong whenever the two results differ, and `CKA_NEVER_EXTRACTABLE` is never written — it keeps the class default **TRUE** ([P11Attributes.cpp:1901-1905](../src/lib/P11Attributes.cpp#L1901)) or whatever `:2008` chose. A derived key can therefore report `NEVER_EXTRACTABLE=TRUE` while being extractable — a false security claim.

**Fix.** One-token change at `:7925` (`CKA_NEVER_EXTRACTABLE`). Audit the sibling branches (`CONCATENATE_BASE_AND_DATA`, `DATA_AND_BASE`, XOR, `EXTRACT_KEY_FROM_KEY`) for the same pattern while there.

**Tests / gate.** No CONCATENATE scenario exists in the differential harness and the C++ suite has zero `CKA_NEVER_EXTRACTABLE` assertions — add one scenario deriving from (a) two never-extractable keys and (b) one extractable key, probing both attributes on both engines. Failing pre-fix by construction.

### C2 (C++ half) — `CKO_TRUST` class — *D4, D6*

**Spec** (`spec/trust_objects.md:30-51`): `CKA_ISSUER`, `CKA_SERIAL_NUMBER` (¹ MUST at creation); `CKA_HASH_OF_CERTIFICATE`, `CKA_NAME_HASH_ALGORITHM` (² MUST unless every trust attribute is `CKT_TRUST_UNKNOWN`/`CKT_NOT_TRUSTED`; algorithm defaults to SHA-1); seven `CKA_TRUST_*` of type `CK_TRUST` with the five `CKT_*` values; `CKA_MODIFIABLE` defaults TRUE, `CKA_PRIVATE` defaults FALSE. Header: [pkcs11t-canonical-v3.2.h:336, 661-667, 2749-2755](../docs/refs/pkcs11t-canonical-v3.2.h#L336).

**Code.** No `CKO_TRUST` case in `newP11Object()` → `default: CKR_ATTRIBUTE_VALUE_INVALID` ([SoftHSM_objects.cpp:172](../src/lib/SoftHSM_objects.cpp#L172)). `P11AttrIssuer/SerialNumber/NameHashAlgorithm` already exist ([P11Objects.cpp:588-595](../src/lib/P11Objects.cpp#L588)).

**Fix.** New `P11TrustObj` (storage-object parent; model on the ~70-line certificate class, `P11Objects.cpp:571-639`), 8 new attribute classes (`CKA_HASH_OF_CERTIFICATE` + seven `CK_TRUST` with domain validation), a `newP11Object` case, and custom creation-time logic for footnote ² (conditional MUST — not expressible with the existing `ck1` flag). `C_FindObjects` needs nothing. Effort M confirmed.

**Tests / gate.** Shared differential scenarios with the Rust half (below).

### X1 (C++ half) — `CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS`

**Spec** (`spec/elliptic_curves.md:591-595`): FIPS 186-4 B.4.1 ("extra random bits"); **no mechanism parameter**. Rust: `(r mod (n−1)) + 1` over n+64 random bits ([ffi.rs:1965-1991](../rust/src/ffi.rs#L1965), dispatch `:2943`), with the reduction split out for testing.

**Code.** Zero references in `src/lib/`; tracked as `LEGAL-EC-EXTRA-BITS-CPP-UNIMPLEMENTED` ([exceptions.json:300](../tests/differential/exceptions.json#L300)).

**Fix.** (1) Register in `SoftHSM::prepareSupportedMechanisms()` with `CKM_EC_KEY_PAIR_GEN`'s flags/size range. (2) The crypto layer's keygen has no mechanism input ([AsymmetricAlgorithm.h:260](../src/lib/crypto/AsymmetricAlgorithm.h#L260); `ECParameters` is curve-only) — add a generation-method flag to the parameters or a sibling entry point, and route from the keygen dispatch (hard-coded mechanism checks at `keygen:548/605/636/669` and `:5641/:5726`). (3) Generate the scalar per B.4.1 mirroring Rust's reduction (port its unit vectors), **compute the public point explicitly** (`EC_POINT_mul` → `OSSL_PKEY_PARAM_PUB_KEY`, the existing pattern at [OSSLECPrivateKey.cpp:189-202](../src/lib/crypto/OSSLECPrivateKey.cpp#L189); OpenSSL 3.6 `EVP_PKEY_fromdata` does not derive the public key from a bare scalar), then `EVP_PKEY_fromdata`. (4) Set `CKA_KEY_GEN_MECHANISM` to the new mechanism.

**Tests / gate.** Rust's reduction vectors; the existing scenario `create.generate_key_pair.ec_extra_bits` starts passing on both engines → delete the ledger entry; sign/verify round-trip.

---

## 4. Track Rust

### R3 — refuse `C_CreateObject` for non-storage classes

**Spec.** `spec/creating_objects.md:26-29`: "only objects that are considered Storage Objects … can be created on a token, other kinds of object are generally built-in and attempting to create new objects of those kinds will result in an error." `spec/object_classification.md:21-26` "Other Objects": `CKO_HW_FEATURE`, `CKO_MECHANISM`, `CKO_PROFILE`, `CKO_VALIDATION`. (`spec/validation_objects.md:11-12` adds that validation objects are "read only, token objects".)

**Code.** `validate_create_template` refuses `CKO_PROFILE` only ([ffi.rs:5296-5299](../rust/src/ffi.rs#L5296)); `CKO_VALIDATION` falls through and is created; `CKO_HW_FEATURE`/`CKO_MECHANISM` have no constants anywhere in `rust/src/` and `CKA_CLASS=0x5/0x7` are created as generic objects. C++: `newP11Object()` rejects unknown classes with `CKR_ATTRIBUTE_VALUE_INVALID`, and refuses `CKO_PROFILE` with `CKR_ATTRIBUTE_READ_ONLY` ([SoftHSM_objects.cpp:1193-1194](../src/lib/SoftHSM_objects.cpp#L1193), chosen as "the better code").

**Fix.** Rust: add the two constants; refuse all four classes in the `CKO_PROFILE` arm with `CKR_ATTRIBUTE_READ_ONLY` (in `C_CreateObject`'s return list, `spec/object_mgmt_functions.md:37`; consistent with the existing precedent). C++: explicit case for the same three alongside `CKO_PROFILE`, so both engines return the same code. The engine still never *materialises* a validation object (§6).

**Tests / gate.** Differential scenario: `C_CreateObject` for each of the four classes → `CKR_ATTRIBUTE_READ_ONLY` on both. Rust conformance section.

### C2 (Rust half) — `CKO_TRUST` MUST-rules and defaults — *D4, D6*

**Code.** All `CKO_TRUST` support is constants ([constants.rs:117, 275-290](../rust/src/constants.rs#L117)); no arm in `validate_create_template`; `apply_object_defaults` ([state.rs:422](../rust/src/state.rs#L422)) sets `CKA_MODIFIABLE=TRUE` but never `CKA_PRIVATE`. Conformance section WP4a ([test_p11_conformance.js:1517-1580](../rust/test_p11_conformance.js#L1517)) creates with issuer + serial + two trust attributes and **no `CKA_HASH_OF_CERTIFICATE`** — a template footnote ² forbids.

**Fix.** `CKO_TRUST` arm: `CKA_ISSUER` + `CKA_SERIAL_NUMBER` required (`CKR_TEMPLATE_INCOMPLETE`); `CKA_HASH_OF_CERTIFICATE` required unless every trust attribute is absent/`UNKNOWN`/`NOT_TRUSTED`; every `CKA_TRUST_*` ∈ the five `CKT_*` (`CKR_ATTRIBUTE_VALUE_INVALID`); `CKA_PRIVATE=FALSE` default for this class; unset trust attribute reads per D6 (unchanged). **Rewrite WP4a** to supply `CKA_HASH_OF_CERTIFICATE`, and add negative cases (missing issuer, missing hash with `CKT_TRUSTED`, bad `CKT_` value).

**Tests / gate (both halves).** Differential scenarios for the happy path, each MUST violation, unset-attribute read (D6), `C_FindObjects` by class, `C_SetAttributeValue` under default `CKA_MODIFIABLE`.

### D-2 — PKCS#8 `PrivateKeyInfo` wire format, both directions — *D3*

**Spec.** §6.7 (`spec/rsa.md:200` and the general wrap rule): "For wrapping, a private key is BER-encoded according to [PKCS #8] PrivateKeyInfo"; §6.3.10 EC unwrap (`spec/elliptic_curves.md:629-631`): "the mechanism contributes the CKA_CLASS, CKA_KEY_TYPE, CKA_EC_PARAMS and CKA_VALUE attributes to the new private key". The `privateKey` OCTET STRING of a `PrivateKeyInfo` holds an RFC 5915 `ECPrivateKey` SEQUENCE for `id-ecPublicKey`, and an RFC 8410 `CurvePrivateKey` (nested OCTET STRING) for Ed25519/Ed448/X25519/X448.

**Code.** *Encoder:* `pkcs8_private_key_info` ([ffi.rs:10900-10963](../rust/src/ffi.rs#L10900)) builds `SEQ{v0, AlgorithmIdentifier, OCTET STRING(raw scalar)}` — for EC/Edwards the inner structure is missing, so the output is not a valid `PrivateKeyInfo` (60 B → 72 B after KWP, the ledger's own number; C++ produces a parseable 152 B). *Decoder:* `C_UnwrapKey` stores the decrypted bytes verbatim as `CKA_VALUE` ([ffi.rs:11433](../rust/src/ffi.rs#L11433)), defaults `CKA_KEY_TYPE` to `CKK_AES` (`:11439-11440`), never stamps `CKA_EC_PARAMS`, and its only PKCS#8 parsing is of the RSA *unwrapping* key (`:11335`, `:11352`). Consequences: C++→Rust unwrap yields an opaque blob; Rust→Rust EC round-trip stores the 60-byte blob and cannot sign ([ffi.rs:11446-11449](../rust/src/ffi.rs#L11446)). The ledger entries `DEFECT-RUST-WRAPPED-PRIVATE-KEY-NOT-PKCS8` and `DEFECT-RUST-EC-PARAMS-ABSENT-ON-UNWRAPPED-PRIVATE` describe this; the first one's justification ("72 bytes cannot contain one") is wrong about *why* but right that it's a defect.

**Fix.** (1) Encoder: emit the standard inner structures (RFC 5915 `ECPrivateKey` with `[1] publicKey` optional; RFC 8410 nested OCTET STRING; PQC per the same OID table the SPKI builders use; RSA passes through its stored PKCS#8 until E5). (2) Decoder: when the unwrap target is `CKO_PRIVATE_KEY`, parse the standard `PrivateKeyInfo` — reuse the generic walker `unwrap_pqc_pkcs8_private_key` ([ffi.rs:5500](../rust/src/ffi.rs#L5500)) — map OID → `CKA_KEY_TYPE` (+ `CKA_EC_PARAMS` / `CKA_PARAMETER_SET`), extract the raw private value into the engine's storage shape, and reject a template whose `CKA_KEY_TYPE` contradicts the OID (`CKR_TEMPLATE_INCONSISTENT`). Independent of E5: storage stays raw. Effort **L** (encoder + decoder + EC/Edwards/Montgomery/PQC arms + cross-engine tests).

**Tests / gate.** Byte-exact comparison of Rust's wrapped `PrivateKeyInfo` against OpenSSL's `PKCS8_PRIV_KEY_INFO` for the same key (all families); C++→Rust and Rust→C++ wrap/unwrap → sign/verify; Rust→Rust round-trip; `encoding.wrap_private_key_pkcs8` agrees on `wrapped.len` and `*CKA_EC_PARAMS*` → delete both ledger entries.

### D-4 — `CKA_KEY_GEN_MECHANISM` on KEM shared-secret keys (new)

**Spec.** `spec/key_objects.md:62-65`: `CKA_KEY_GEN_MECHANISM` "contains a valid value only if the **CKA_LOCAL** attribute has the value CK_TRUE. If **CKA_LOCAL** has the value CK_FALSE, the value of the attribute is CK_UNAVAILABLE_INFORMATION." §5.18.8/9 mandate `CKA_LOCAL = CK_FALSE` for encapsulated/decapsulated keys (`spec/key_management_functions.md:753`, `:859`).

**Code.** All five KEM arms store `CKA_LOCAL=false` **and** `CKA_KEY_GEN_MECHANISM=<mech>` ([ffi.rs:4443-4444](../rust/src/ffi.rs#L4443), `:4623-4624`, `:4716-4717`, `:4912-4913`, `:5055-5056`). C++ is correct. The ledger's `LEGAL-KEY-GEN-MECHANISM-ON-ENCAPSULATED-KEY` ([exceptions.json:118-125](../tests/differential/exceptions.json#L118)) adjudicates this divergence as legal — it is not.

**Fix.** Drop the `store_ulong(CKA_KEY_GEN_MECHANISM, …)` in the five arms (or store `CK_UNAVAILABLE_INFORMATION`, whichever the read path expects — check what `C_GetAttributeValue` returns for an absent ulong). Re-label the ledger entry as `defect` until fixed, then delete it. Also check the BIP32 derive path, which sets the attribute with `CKA_LOCAL=false` on a vendor mechanism (`keygen:3256-3257` in C++) — same rule applies.

**Tests / gate.** The existing KEM differential scenario's `*CKA_KEY_GEN_MECHANISM*` path agrees after the fix; Rust conformance assertion.

### R1′ — import-shape policy for Edwards/Montgomery `CKA_VALUE` — *D5*

**Spec.** Private-key `CKA_VALUE` for Edwards (Table 67, `spec/elliptic_curves.md:410`) and Montgomery (Table 69, `:530`): raw little-endian bytes per RFC 8032 / RFC 7748.

**Code.** `validate_create_template` length-checks `CKA_VALUE` only for `CKK_AES`/`CKK_AES_XTS` ([ffi.rs:5391-5401](../rust/src/ffi.rs#L5391)) and does not require `CKA_EC_PARAMS` for Edwards/Montgomery private keys; `normalize_pqc_pkcs8_import` ([ffi.rs:5557](../rust/src/ffi.rs#L5557)) normalises PKCS#8 only for ML-DSA/ML-KEM; a wrong-shape Edwards value is stored and fails later in `sign_eddsa` ([handlers.rs:2020](../rust/src/crypto/handlers.rs#L2020)) as `CKR_KEY_TYPE_INCONSISTENT`. The raw path itself works (PR #212 tests; `live_composite_*_upload_sign_verify`, whose caller passes raw scalars, [upload.rs:250](../openpgp/lib/src/upload.rs#L250)). C++'s `P11AttrValue::updateAttr` ([P11Attributes.cpp:1107-1135](../src/lib/P11Attributes.cpp#L1107)) has no length check either.

**Fix (per D5).** Extend the normaliser to `CKK_EC_EDWARDS`/`CKK_EC_MONTGOMERY` (RFC 8410 `CurvePrivateKey`; expected sizes 32/57 and 32/56 from `CKA_EC_PARAMS`); require `CKA_EC_PARAMS` for those key types; reject any other shape at create with `CKR_ATTRIBUTE_VALUE_INVALID`. Mirror the length check in C++. The existing `b5_eddsa_import_rejects_wrong_length_value` ([ffi.rs:23624-23660](../rust/src/ffi.rs#L23624)) accepts either outcome and must be tightened to assert the create-time rejection.

### R2′ — hash-family parity — *D2*

**a. Route what already exists (S).** `sign_hmac` dispatches `CKM_SHA512_224_HMAC`, `CKM_SHA512_256_HMAC`, `CKM_SHA3_224_HMAC`, `CKM_SHA3_384_HMAC` ([handlers.rs:1628-1657](../rust/src/crypto/handlers.rs#L1628)) but `C_Sign` (`ffi.rs:6596`), mechanism-info (`:1457`) and `SUPPORTED_MECHANISMS` ([constants.rs:885-902](../rust/src/constants.rs#L885)) omit them — unreachable through the PKCS#11 surface. Wire all three; this is the drift X2′ exists to catch.

**b. Add the rest (M).** Digests `CKM_SHA512_224`, `CKM_SHA512_256`, `CKM_SHA3_224`, `CKM_SHA3_384` (crates present: `sha2 0.10.8`, `sha3 0.10.8`) and their `_HMAC_GENERAL`; `CKM_RIPEMD160_HMAC_GENERAL` (Rust has the digest and plain HMAC). SHA-224 digest/HMAC/GENERAL per D2. Dispatch is per-arm across ≥8 sites (`DigestCtx` ×6, `hmac_general_base`, `C_Sign`/`C_Verify`, mech-info, `SUPPORTED`) — budget accordingly.

**c. Signature mechanisms (S).** `CKM_SHA3_256_RSA_PKCS`, `CKM_SHA3_512_RSA_PKCS` and their `_PSS` forms: C++ has them, Rust has only the SHA3-384 pair despite both digests existing. (MD5/SHA-1/SHA-224 RSA variants follow D2.)

**Tests / gate.** NIST CAVP vectors per added mechanism in `rust/test_p11_conformance.js`; differential parity on shared key/message.

---

## 5. Cross-cutting

### X1 (provider half) — after C++ lands
JavaJCE hard-codes `CKM_EC_KEY_PAIR_GEN` at [P11ECKeyPairGeneratorSpi.java:106](../JavaJCE/src/main/java/com/pqctoday/hsm/jce/P11ECKeyPairGeneratorSpi.java#L106) and [SoftHSMv3Provider.java:465](../JavaJCE/src/main/java/com/pqctoday/hsm/jce/SoftHSMv3Provider.java#L465); OpenSSL provider at [keymgmt.c:1327](../src/vendor/pkcs11-provider/src/keymgmt.c#L1327). Add the constant and a selectable path (follow whatever the PQC generators use for algorithm variants); keygen + sign/verify smoke test each. Closes Q-6 of `docs/remediation-plan-provider-layer-gaps-2026-08-30.md:119`.

### D-1 — harness re-run and ledger corrections
Run `scripts/local-gate.sh` step 7 on current `main` and reconcile: `LEGAL-UNWRAPPED-KEY-EXTRACTABLE-DEFAULT` (delete with C1); `LEGAL-KEY-GEN-MECHANISM-ON-ENCAPSULATED-KEY` (→ `defect`, then delete with D-4); `DEFECT-RUST-WRAPPED-PRIVATE-KEY-NOT-PKCS8` (correct the justification: malformed encoding, not "cannot contain one"); `DEFECT-RUST-EC-PARAMS-ABSENT-ON-UNWRAPPED-PRIVATE` (stays until D-2); `DEFECT-RUST-CKA_VALUE-ON-ASYMMETRIC-KEYS` (stays, E5); `LEGAL-WEAK-PRIMITIVES-ABSENT-IN-RUST` (rewrite per D2); add a `LEGAL-*` for D1b.

### X2′ — per-`CKM_*` mechanism ledger
Nothing today records header-vs-engine mechanism status: `scripts/check_pkcs11_constants.py` is values-only, docs hold ≤25-row tables, `exceptions.json` adjudicates cross-engine differences only. **Extend the existing remoting pattern** — `remoting/coverage_ledger.json` + `remoting/scripts/check_coverage_ledger.py` (row / disposition / justification + ratchet) — into `docs/pkcs11-mechanism-ledger.json` + `scripts/check_pkcs11_mechanism_ledger.py`: one row per `CKM_*` in `docs/refs/pkcs11t-canonical-v3.2.h` with `{cpp, rust}` ∈ `implemented | excluded-by-scope(reason) | deferred(plan-ref) | tracked-todo(ledger-id)`; fail on any header mechanism without a row; fail when a row says `implemented` but the engine's advertised list (the `env.mechanism_set` dump, `tests/differential/README.md:121`) disagrees — which would have caught R2′a. Wire into `local-gate.sh`; CI wiring is the user's call. Seed rows: ECMQV (deferred, 2026-08-30 decision), the Signal family and legacy ciphers (excluded-by-scope), D2's hash decisions, X1 (tracked-todo).

### H1 — hygiene
1. Re-verify every `citation` in `exceptions.json` against the vendored text (two of the handful checked were wrong: C1's and D-4's); record the pass date in the file header.
2. Fix section-number drift wherever this plan's rev 2 numbers were copied (§4.8 common key / §4.9 public / §4.10 private / §4.11 secret; Table 29 common private; Tables 67/69 private Edwards/Montgomery; §5.18.7 unwrap-auth).
3. Refresh stale status lines in `docs/remediation-plan-rust-pkcs11-v32-gaps-2026-08-30.md`, `docs/remediation-plan-provider-layer-gaps-2026-08-30.md`, `docs/remediation-plan-kmip-cacp-pkcs11-coverage-2026-08-30.md` (work shipped as PRs #193, #212, #217, #222).
4. Correct `CLAUDE.md`'s retained-algorithm sentence per D2 and add the declared-out-of-scope families.
5. Delete local branch `fix/b5-eddsa-key-import-cka-value` — its content is on `main` as squash commit #212 (`713052e7`, identical 783/19 diff footprint; all five B5 test names present). Note `git merge-base --is-ancestor` reports it unmerged: squash merges defeat ancestry checks.

---

## 6. Explicitly out of scope (deliberate, re-confirmed)

- **`CKM_ECMQV_DERIVE`** — held on both engines (`docs/remediation-plan-pkcs11-v32-coverage-2026-08-29.md:482-506`): no safe OpenSSL MQV primitive; hand-rolled combiner too risky.
- **`CKO_VALIDATION` self-materialisation** — no real FIPS 140-3/CC validation to describe. (R3 is about refusing *client* creation.)
- **MD5 and SHA-1 families in Rust** — deliberate weak-primitive exclusion; SHA-224 and RIPEMD-160 are D2.
- **Signal-protocol mechanism family, legacy ciphers** — outside declared scope; recorded via X2′, not built.
- **E5 (Rust asymmetric-key storage model)** — deferred under D3; D-2 removes its wire-format symptoms without touching storage.

## 7. Sequencing

Independent tracks; nothing below depends on another item landing first.

1. **Decisions D1–D6** (one round).
2. **Phase 1 — defects, ≤ S:** C1, C3, R3, D-4, D-1 (harness re-run + ledger edits), R1′, R2′a.
3. **Phase 2 — defects, larger:** D-2 (L), C2 (Rust half, then C++ half).
4. **Phase 3 — parity:** R2′b, R2′c, X1 (C++ then providers).
5. **Phase 4 — structural hygiene:** X2′, H1. (H1.1 can run at any time; it needs no code.)

Each item regenerates its engine's report and re-runs the differential harness as its own acceptance; never batch report regeneration across items.

## 8. Verification standard (every item)

- A regression test that **fails on the pre-fix binary** and passes post-fix — a test that only passes does not count (R1′'s existing test is the cautionary example).
- Any `exceptions.json` edit quotes the spec sentence it relies on, from the vendored text, with file:line, and the CSD01 section number checked against the PDF.
- "Already landed" claims are verified by **diff or test-name presence on `origin/main`**, not by `merge-base --is-ancestor` alone — this repo squash-merges, and ancestry then reports shipped work as unmerged.
- OpenSSL 3.6.3+ only; the differential harness and both conformance harnesses run from `scripts/local-gate.sh` before any push is proposed.

---

## 9. Execution log (2026-09-06)

Worktree `.worktrees/pkcs11-v32-gaps-0906`, branch `fix/pkcs11-v32-gaps-0906`
off `origin/main@1e8db083`. The shared main checkout was left untouched
throughout (it carries an unrelated dirty tree from a concurrent session).
Three commits, **not pushed**.

| Commit | Items |
|---|---|
| `8ee501a4` `fix(cpp)` | C1, C3, R3 (C++ half) + regenerated `cpp_compliance_report.{md,json}` |
| `3b05f905` `fix(rust)` | D-4, R3 (Rust half), R1′, R2′a + tests |
| `6ac81b2b` `fix(differential)` | D-1 ledger corrections + CHANGELOG |

### Decisions taken (§1)
D1 **conform** (default `CK_TRUE`) · D2 **full parity with C++** · D3 **defer
E5**, fix the symptom · D4 **both engines** · D5 **uniform lenient normalise**
· D6 absence stays a legitimate state. D2 is the one that overrode the
recommendation in this plan: it makes `LEGAL-WEAK-PRIMITIVES-ABSENT-IN-RUST`
false as written, so that entry must be rewritten or deleted when R2′b lands
(not yet done — R2′b is not started).

### What changed versus the plan as written
- **C1** was implemented in each site's existing **post-create attribute
  block**, not by appending `CKA_EXTRACTABLE` to the template array as §3
  proposed. The red-team was right that the arrays are fixed
  `CK_ATTRIBUTE secretAttribs[32]` buffers whose guard already admits a full
  28-entry caller template; appending would overflow. The post-create block is
  also where `CKA_LOCAL`/`ALWAYS_SENSITIVE`/`NEVER_EXTRACTABLE` are already
  forced, so the fix sits with its siblings. The "did the template supply it"
  test scans the **effective** template (caller entries plus anything merged
  from `CKA_UNWRAP_TEMPLATE`), so an explicit `CK_FALSE` from either source
  still wins.
- **D-4** turned out to be **six** sites, not five: the decapsulate ML-KEM arm
  was missed by the review.
- **R3** widened from `CKO_VALIDATION` alone to all four non-storage classes;
  `CKO_HW_FEATURE`/`CKO_MECHANISM` had no Rust constants at all.
- **R1′** needed a real DER change, not just a length check:
  `unwrap_pqc_pkcs8_private_key` did not understand RFC 8410 §7's
  `CurvePrivateKey` (privateKey's content is itself an OCTET STRING), which is
  why an Edwards PKCS#8 blob matched neither existing branch.
- **D-1**: deleting `LEGAL-UNWRAPPED-KEY-EXTRACTABLE-DEFAULT` also required
  updating the `note` on `DEFECT-RUST-CKA_VALUE-ON-ASYMMETRIC-KEYS`, which
  cited it as the standing explanation for what
  `encoding.wrap_private_key_pkcs8` observes.

### Evidence
- **C++ compliance suite**: 891 PASS / 0 FAIL / 0 XFAIL / 48 SKIP — unchanged,
  which is itself the finding: that suite never exercised any of C1/C3/R3.
- **C++ `ctest`**: 8/8 passed, including `p11test`.
- **Cross-engine differential harness**: 64 scenarios, 9,897 observations,
  2,366 legal / 24 known-defect / **0 UNCOVERED**, exit 0 — with both deleted
  exceptions gone. This is the real evidence for C1 and D-4: those entries
  existed *because* the engines diverged on exactly these paths.
- **Rust crate suite**: 500 passed / 0 failed / 14 ignored.
- **Fails-pre-fix, verified for real** (§8): the engine fixes were temporarily
  reverted in the worktree and the four new/tightened tests re-run — all four
  FAILED, each on its own assertion (`CKA_VALUE must be normalised…`,
  `CKA_LOCAL=FALSE ⇒ CKA_KEY_GEN_MECHANISM must be CK_UNAVAILABLE_INFORMATION`,
  the non-storage refusal, the HMAC advertisement) — then restored via
  `git checkout` and re-run green.

### Not started
R2′b/R2′c (D2 full parity — 38 hash-family mechanisms; `sha1` and `ripemd` are
already dependencies, only MD5 would need a new crate), C2 (`CKO_TRUST`, both
engines), D-2 (PKCS#8 wire format, L), X1 (C++ extra-bits + providers), X2′
(mechanism ledger), H1 (citation sweep, doc refresh, branch cleanup).

One measurement worth carrying forward: C++ advertises **161** mechanisms,
Rust **129**; the C++-only set is 38 hash-family plus 5 others
(`CKM_AES_CMAC`, `CKM_AES_CBC_ENCRYPT_DATA`, `CKM_AES_ECB_ENCRYPT_DATA`,
`CKM_CONCATENATE_DATA_AND_BASE`, `CKM_RSA_AES_KEY_WRAP`). Those 5 are outside
D2's question and remain a separate parity decision.

Also noted for H1: the harness's own "EXCEPTION ENTRIES THAT MATCHED NOTHING"
report is **per-shard only** in a `--parallel` run, so the authoritative stale
-entry list needs one serial run.
