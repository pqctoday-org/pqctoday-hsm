# Remediation Plan — PKCS#11 v3.2, Phase 2 (2026-09-07)

**Date:** 2026-09-07
**Baseline:** branch `fix/pkcs11-v32-gaps-0906` @ `9fd47d5f` (4 commits over `origin/main@1e8db083`)
**Predecessor:** [remediation-plan-pkcs11-v32-gaps-09062026.md](remediation-plan-pkcs11-v32-gaps-09062026.md) — its §0 records two adversarial review passes and §9 the Phase 1 execution log. Phase 1 (C1, C3, R3, D-4, D-1, R1′, R2′a) is done, verified and committed.
**Status:** PLAN ONLY. Nothing here is implemented. Push/merge stays gated on explicit go-ahead.
**Spec text:** `file:line` citations point into the vendored OASIS markdown under `docs/refs/pkcs11-v3.3-draft-git-snapshot-20260828/working/doc/spec/` (`spec/` below). Section numbers follow the v3.2 CSD01 PDF — the predecessor plan had several wrong, so confirm against the PDF before a number goes into a commit message or the ledger.

## 0. Decisions already taken (binding)

| # | Decision | Consequence for this plan |
|---|---|---|
| **D2** | **Full mechanism parity with C++, including MD5 and SHA-1.** | §3 is now 39 mechanisms, not the 12 the predecessor scoped. Forces deleting `LEGAL-WEAK-PRIMITIVES-ABSENT-IN-RUST` and correcting `CLAUDE.md`. Adds one dependency (`md-5`). |
| **D3** | Defer E5 (Rust's asymmetric-key storage model). | §1 fixes the PKCS#8 *wire* format only; storage stays raw. |
| **D4** | `CKO_TRUST` on **both** engines. | §2 covers C++ and Rust. |
| **D5** | Uniform lenient import: raw, or a recognised PKCS#8, else reject at create. | Already implemented (R1′); §1's decoder must stay consistent with it. |
| **D6** | An absent attribute stays absent (`CKR_ATTRIBUTE_TYPE_INVALID`), not materialised. | §2's `CKA_TRUST_*` read behaviour. |
| — | The 5 non-hash C++-only mechanisms are to be **added** to Rust. | §3 Wave 4. |
| — | Next item is **§1 (D-2)**. | Sequencing in §7. |

## 1. D-2 — PKCS#8 `PrivateKeyInfo` is malformed in both directions (Rust)

**Severity: the highest remaining.** It breaks cross-engine key wrapping *and* same-engine EC unwrap-then-sign. **Effort: L.**

### 1.1 Ground truth (measured 2026-09-07 against OpenSSL 3.6.3, not inferred)

The C++ engine delegates to OpenSSL (`privateKey->PKCS8Encode()`, [SoftHSM_keygen.cpp:1732](../src/lib/SoftHSM_keygen.cpp#L1732)), so OpenSSL's output **is** the reference C++ already matches.

| Key | Canonical PKCS#8 | Size |
|---|---|---|
| P-256 | `SEQUENCE { INTEGER 0, AlgId{ id-ecPublicKey, prime256v1 }, OCTET STRING( ECPrivateKey ) }` | 138 B |
| P-384 / P-521 | same shape | 185 B / 241 B |
| Ed25519 / X25519 | `SEQUENCE { INTEGER 0, AlgId{ OID }, OCTET STRING( OCTET STRING( raw ) ) }` | 48 B |

where, per RFC 5915:

```
ECPrivateKey ::= SEQUENCE {
  version        INTEGER (1),
  privateKey     OCTET STRING,              -- fixed-width scalar (32/48/66)
  parameters [0] ECParameters OPTIONAL,     -- OMITTED: the curve is in the outer AlgId
  publicKey  [1] BIT STRING OPTIONAL        -- PRESENT: 0x00 || uncompressed point
}
```

An encoder built to exactly this spec was prototyped and reproduces OpenSSL's bytes **exactly** for P-256, Ed25519 and X25519 — so the shape below is confirmed, not assumed.

### 1.2 What the engine does today

- **Encoder** `pkcs8_private_key_info` ([rust/src/ffi.rs:10900](../rust/src/ffi.rs#L10900)): every `AlgorithmIdentifier` is correct; the single defect is the last line, which wraps the raw stored value directly (`body.extend_from_slice(&der_octet_string(&raw))`) for every key type. For EC that yields a 60-byte blob → 72 after AES-KWP, versus C++'s 152. The ledger's `DEFECT-RUST-WRAPPED-PRIVATE-KEY-NOT-PKCS8` records those numbers; its stated reason ("72 bytes cannot contain one") is wrong — the size is a symptom, the missing inner structure is the cause.
- **Decoder** `C_UnwrapKey` ([rust/src/ffi.rs:11253](../rust/src/ffi.rs#L11253)): stores the decrypted bytes verbatim as `CKA_VALUE`, defaults `CKA_KEY_TYPE` to `CKK_AES` when the template omits it, and never stamps `CKA_EC_PARAMS` (`DEFECT-RUST-EC-PARAMS-ABSENT-ON-UNWRAPPED-PRIVATE`). Its only PKCS#8 parsing is of the RSA *unwrapping* key, not the payload.

### 1.3 Work

**Encoder.**
1. `CKK_EC` — build the RFC 5915 `ECPrivateKey`. The private object stores only `CKA_EC_PARAMS` and the scalar (**confirmed: no `CKA_EC_POINT` on the private half**), so the public point must be derived from the scalar via the curve crate already in use (`p256`/`p384`/`p521`/`k256` `SecretKey::public_key()`), selected by the decoded curve. This is what OpenSSL does internally. Omitting `[1] publicKey` is legal but would leave Rust at a different length from C++ and the divergence would persist — so include it.
2. `CKK_EC_EDWARDS` / `CKK_EC_MONTGOMERY` — wrap the raw scalar in the nested OCTET STRING (RFC 8410 §7 `CurvePrivateKey`). One line; the matching *decoder* half already landed in R1′.
3. `CKK_RSA` — unchanged (the engine already stores PKCS#8 and returns it as-is).
4. Scalar width: use the curve's fixed width, left-padded — never a trimmed big-endian integer.

**Decoder.** When the unwrap target is `CKO_PRIVATE_KEY`, parse the `PrivateKeyInfo`:
1. Read the `AlgorithmIdentifier` OID → key type + parameters. Reuse `decode_ec_params` ([rust/src/crypto/handlers.rs:65](../rust/src/crypto/handlers.rs#L65)) for the curve arm and the inverse of `pqc_alg_id_from_spki` for PQC, so the encode and decode tables cannot disagree.
2. Extract the raw scalar from the inner structure — extend the existing walker `unwrap_pqc_pkcs8_private_key` ([rust/src/ffi.rs:5500](../rust/src/ffi.rs#L5500)), which R1′ already taught RFC 8410, rather than writing a second parser.
3. Stamp `CKA_KEY_TYPE` (from the OID, instead of defaulting `CKK_AES`), `CKA_EC_PARAMS` / `CKA_PARAMETER_SET`, and the normalised `CKA_VALUE`.
4. A template `CKA_KEY_TYPE` that contradicts the OID → `CKR_TEMPLATE_INCONSISTENT`.
5. Keep D5's policy: a payload that is neither a recognised `PrivateKeyInfo` nor already the raw shape is refused, not stored.

### 1.4 Explicitly out of scope, and why

**PQC private keys (`CKK_ML_DSA` / `ML_KEM` / `SLH_DSA` / `HSS` / `XMSS` / `XMSSMT`) keep their current encoding.** I have no reference proving the raw-in-OCTET-STRING form wrong for these, the relevant LAMPS drafts are still moving, and both tracked ledger defects are EC-shaped. Changing it would put the ML-DSA/ML-KEM import path that PR #212 fixed — and OpenPGP's BYOK flow on top of it — at risk for no evidenced gain. **Open question O-1** below.

### 1.5 Acceptance

- Byte-exact equality with OpenSSL fixtures for P-256/384/521, Ed25519, Ed448, X25519, X448 — generated by `openssl pkcs8 -topk8 -nocrypt`, checked in as fixtures so the assertion is against a third party, not against the engine's own output.
- Cross-engine: C++ wrap → Rust unwrap → sign → verify, and Rust wrap → C++ unwrap → sign → verify.
- Same-engine: Rust wrap → Rust unwrap → sign (broken today).
- Differential harness `encoding.wrap_private_key_pkcs8`: `wrapped.len` moves **72 → 152** (matching C++ exactly: 8 + roundup(138,8)), and `*CKA_EC_PARAMS*` converges → **delete both `DEFECT-RUST-*` entries**.
- `DEFECT-RUST-CKA_VALUE-ON-ASYMMETRIC-KEYS` stays (E5, deferred).

## 2. C2 — `CKO_TRUST` (§4.7) on both engines

**Effort: Rust S, C++ M.**

**Rust** — everything is constants ([rust/src/constants.rs:117](../rust/src/constants.rs#L117), `:275-290`); `validate_create_template` has no arm, so a trust object is created with *any* attribute set. Add: `CKA_ISSUER` + `CKA_SERIAL_NUMBER` required (`CKR_TEMPLATE_INCOMPLETE`); `CKA_HASH_OF_CERTIFICATE` required unless every trust attribute is absent/`CKT_TRUST_UNKNOWN`/`CKT_NOT_TRUSTED` (footnote ²); every `CKA_TRUST_*` value ∈ the five `CKT_*` (`CKR_ATTRIBUTE_VALUE_INVALID`); `CKA_PRIVATE=FALSE` default for this class (`apply_object_defaults` at [rust/src/state.rs:422](../rust/src/state.rs#L422) sets `CKA_MODIFIABLE` but not this).

**C++** — no `CKO_TRUST` case in `newP11Object()`, so it falls to `CKR_ATTRIBUTE_VALUE_INVALID`. Add a `P11TrustObj` (model on the ~70-line certificate class, [P11Objects.cpp:571-639](../src/lib/P11Objects.cpp#L571)) plus 8 attribute classes — `CKA_ISSUER`/`CKA_SERIAL_NUMBER`/`CKA_NAME_HASH_ALGORITHM` already exist. Footnote ²'s conditional MUST is not expressible with the existing `ck*` flags and needs explicit creation-time logic.

**Trap:** the existing conformance section WP4a ([rust/test_p11_conformance.js:1517](../rust/test_p11_conformance.js#L1517)) creates a trust object with two `CKA_TRUST_*` values and **no** `CKA_HASH_OF_CERTIFICATE` — a template footnote ² forbids. The fix turns that test red. **Rewriting WP4a is part of this item, not a follow-up**, and it needs negative cases added (missing issuer, missing hash with `CKT_TRUSTED`, out-of-domain `CKT_` value).

Per D6, an unset `CKA_TRUST_*` keeps returning `CKR_ATTRIBUTE_TYPE_INVALID` + `CK_UNAVAILABLE_INFORMATION` on both engines; record that once in the ledger so it stops being re-litigated.

## 3. Full mechanism parity (D2) — 39 mechanisms

C++ advertises **161**, Rust **129**. R2′a closed 4; **39 remain** (34 hash-family + 5 other). Sequenced so the cheap, uncontroversial ones land first and the dependency-adding one is isolated.

**Wave 1 — no new dependency (`sha2`, `sha3`, `ripemd` already present).**
Digests `CKM_SHA224`, `CKM_SHA512_224`, `CKM_SHA512_256`, `CKM_SHA3_224`, `CKM_SHA3_384`; their `_HMAC` (SHA-224 only — the other four HMACs landed in R2′a) and all five `_HMAC_GENERAL`; `CKM_RIPEMD160_HMAC_GENERAL`; key derivations `CKM_SHA512_224_KEY_DERIVATION`, `CKM_SHA512_256_KEY_DERIVATION`, `CKM_SHAKE_256_KEY_DERIVATION`; RSA signature combos `CKM_SHA224_RSA_PKCS(_PSS)`, `CKM_SHA3_224_RSA_PKCS(_PSS)`, `CKM_SHA3_256_RSA_PKCS(_PSS)`, `CKM_SHA3_512_RSA_PKCS(_PSS)`; `CKM_ECDSA_SHA224`.

> Note an inconsistency R2′a left behind, and fix it here: the **HMAC** forms of SHA-512/224, SHA-512/256, SHA3-224 and SHA3-384 are now reachable, but the **plain digests** are not. A caller can HMAC with SHA3-384 and not digest with it.

**Wave 2 — SHA-1 family (`sha1` already a dependency).** `CKM_SHA_1`, `CKM_SHA_1_HMAC`, `CKM_SHA_1_HMAC_GENERAL`, `CKM_SHA1_RSA_PKCS`, `CKM_SHA1_RSA_PKCS_PSS`, `CKM_ECDSA_SHA1`.

**Wave 3 — MD5 family (needs a new `md-5` crate).** `CKM_MD5`, `CKM_MD5_HMAC`, `CKM_MD5_HMAC_GENERAL`, `CKM_MD5_RSA_PKCS`. Isolated in its own wave precisely because it is the only item that adds a dependency and the only one that puts a broken primitive into a post-quantum engine — so it can be dropped without disturbing Waves 1–2 if that is reconsidered.

**Wave 4 — the 5 non-hash mechanisms.** `CKM_AES_CMAC` (check whether `cmac` is already a dependency), `CKM_RSA_AES_KEY_WRAP`, `CKM_AES_CBC_ENCRYPT_DATA`, `CKM_AES_ECB_ENCRYPT_DATA`, `CKM_CONCATENATE_DATA_AND_BASE`. `CKM_AES_CMAC` and `CKM_RSA_AES_KEY_WRAP` are the two a real caller is most likely to want; the `ENCRYPT_DATA` derivations are legacy.

**Per-mechanism wiring checklist** (R2′a proved a partial job is invisible — four mechanisms were implemented but unreachable for weeks). Each addition must touch **all** of: `SUPPORTED_MECHS`, `C_GetMechanismInfo`, the `C_Sign`/`C_Verify` (or digest/derive) dispatch arms, the fixed-signature-length rule, the multipart-capable set, and the MAC/digest length map.

**Ledger and doc consequences — part of this item, not optional.**
- Delete `LEGAL-WEAK-PRIMITIVES-ABSENT-IN-RUST`: under D2 its claim is false.
- Correct `CLAUDE.md`'s "Retained algorithms" line, and state the MD5/SHA-1 decision explicitly so it reads as deliberate.
- `LEGAL-MECHANISM-SET` should shrink or go once the sets converge; re-run the harness to see what it still covers.

**Verification:** NIST CAVP/ACVP vectors per mechanism where they exist; otherwise a cross-check against the RustCrypto reference (the pattern R2′a used), never the engine against itself.

## 4. X1 — `CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS` (C++ + both providers)

**Effort: C++ M, providers S.** Rust already implements it ([rust/src/ffi.rs:1957](../rust/src/ffi.rs#L1957), FIPS 186-5 A.2.2 — n+64 random bits, reduce mod (n−1), add 1); the mechanism takes **no parameter**.

C++ needs: registration in `prepareSupportedMechanisms()`; a generation-method input the crypto layer does not currently have ([AsymmetricAlgorithm.h:260](../src/lib/crypto/AsymmetricAlgorithm.h#L260) — `ECParameters` carries only the curve), routed from the keygen dispatch's hard-coded mechanism checks; the scalar generated per B.4.1 mirroring Rust's reduction (port its unit vectors); and the public point computed explicitly via `EC_POINT_mul` + `OSSL_PKEY_PARAM_PUB_KEY` (the pattern at [OSSLECPrivateKey.cpp:189-202](../src/lib/crypto/OSSLECPrivateKey.cpp#L189)) — OpenSSL 3.6 will not derive it from a bare scalar.

Providers afterwards: JavaJCE hard-codes `CKM_EC_KEY_PAIR_GEN` ([P11ECKeyPairGeneratorSpi.java:106](../JavaJCE/src/main/java/com/pqctoday/hsm/jce/P11ECKeyPairGeneratorSpi.java#L106), [SoftHSMv3Provider.java:465](../JavaJCE/src/main/java/com/pqctoday/hsm/jce/SoftHSMv3Provider.java#L465)); the OpenSSL provider at [keymgmt.c:1327](../src/vendor/pkcs11-provider/src/keymgmt.c#L1327). Closes Q-6 of `docs/remediation-plan-provider-layer-gaps-2026-08-30.md`.

Existing harness scenario `create.generate_key_pair.ec_extra_bits` starts passing → delete `LEGAL-EC-EXTRA-BITS-CPP-UNIMPLEMENTED`.

## 5. X2′ — header-vs-engine mechanism ledger

**Effort: M. This is the item that stops the others recurring.** Nothing today records, per `CKM_*`, whether each engine implements it: `check_pkcs11_constants.py` validates *values* only, `exceptions.json` adjudicates cross-engine *differences*, and the docs hold small hand-written tables. That is why three separate audits each re-discovered `CKM_ECMQV_DERIVE`, and why R2′a's four mechanisms sat implemented-but-unreachable.

Extend the proven `remoting/coverage_ledger.json` + `remoting/scripts/check_coverage_ledger.py` pattern into `docs/pkcs11-mechanism-ledger.json` + `scripts/check_pkcs11_mechanism_ledger.py`: one row per `CKM_*` in `docs/refs/pkcs11t-canonical-v3.2.h`, `{cpp, rust}` ∈ `implemented | excluded-by-scope(reason) | deferred(plan-ref) | tracked-todo(id)`. Fail when a header mechanism has no row, and — the part that matters — when a row says `implemented` but the engine's advertised list disagrees. Seed from the harness's own `env.mechanism_set` dump plus the existing exception entries and the ECMQV decision. Wire into `local-gate.sh`; **do not add a CI job** (standing directive).

## 6. H1 — ledger and documentation hygiene

**Effort: S, no code.** Two of the handful of citations checked so far were provably wrong, and both excused a real defect — so the remaining 33 cannot be presumed sound.

1. Re-verify every `citation` in `exceptions.json` against the vendored spec text; fix or delete; stamp the pass date in the file header.
2. Fix the section-number drift the predecessor plan's §0.2 lists (§4.8 common key / §4.9 public / §4.10 private; Tables 67/69 for private Edwards/Montgomery; §5.18.7 for `C_UnwrapKeyAuthenticated`).
3. Refresh the stale status lines in `docs/remediation-plan-rust-pkcs11-v32-gaps-2026-08-30.md`, `...provider-layer-gaps-2026-08-30.md`, `...kmip-cacp-pkcs11-coverage-2026-08-30.md` — the work they describe shipped as PRs #193/#212/#217/#222.
4. Delete the stale local branch `fix/b5-eddsa-key-import-cka-value` (squash-merged as #212; ancestry checks report it unmerged — verify by diff, not `merge-base`).
5. Run the differential harness **serially once** to obtain the authoritative "EXCEPTION ENTRIES THAT MATCHED NOTHING" list — that section is per-shard only under `--parallel`, so the stale-entry sweep needs one non-parallel run.

## 7. Sequencing

1. **§1 D-2** — highest severity, retires two tracked defects. Encoder → decoder → cross-engine tests.
2. **§2 C2** — includes the WP4a rewrite.
3. **§3 Waves 1 → 2 → 3 → 4** — Wave 3 (MD5) last of the hash waves so it stays droppable.
4. **§4 X1** — C++ engine, then providers.
5. **§5 X2′** — best landed after §3, when the ledger's initial rows reflect the converged sets.
6. **§6 H1** — any time; needs no code and improves every later audit.

## 8. Verification standard (unchanged, and it earned its keep)

- A regression test that **fails on the pre-fix binary** and passes after. Phase 1 proved this catches self-deception: the existing `b5_eddsa_import_rejects_wrong_length_value` accepted either outcome and so could never have failed.
- Assert against an **independent** oracle — OpenSSL, RustCrypto, a published vector — never the engine against itself.
- Any `exceptions.json` edit quotes the spec sentence it relies on, with `file:line`.
- "Already landed" is verified by diff or test-name presence, never by `git merge-base --is-ancestor` alone (this repo squash-merges).
- OpenSSL 3.6.3+ only. Full `scripts/local-gate.sh` before any push is proposed; for a worktree, `AG_CONTAINER_ROOT=/ag/pqctoday-hsm/.worktrees/<name>`.

## 9. Open questions

- **O-1 — PQC private-key PKCS#8 inner encoding.** Is the current raw-in-OCTET-STRING form correct for ML-DSA/ML-KEM/SLH-DSA, or should the privateKey wrap a seed/expandedKey structure? OpenSSL's `private_key_to_pkcs8()` produced a nested `SEQUENCE{seed, expandedKey}` for ML-DSA-65 (observed during the PR #212 work), which suggests the engine's form may diverge from OpenSSL for PQC exactly as it does for EC. Needs a reference check against OpenSSL 3.6.3 and the current LAMPS drafts before anything changes; §1 deliberately leaves it alone.
- **O-2 — MD5/SHA-1 exposure.** D2 says add them. Worth one explicit confirmation before Wave 3 lands, since it is the only irreversible-feeling piece (a new dependency plus broken primitives advertised by a PQC engine) and Waves 1–2 deliver most of the practical parity without it.
- **O-3 — `LEGAL-MECHANISM-SET` after §3.** Once the sets converge, does the entry disappear entirely, or does a residual (build-flag-varying mechanisms) remain? Determined by re-running the harness, not by prediction.
