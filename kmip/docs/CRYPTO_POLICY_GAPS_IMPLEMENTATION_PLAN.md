> **Historical record.** These policy-layer gaps were addressed in the 0.8.0
> CACP remediation — see `../policies/README.md` and the root `CHANGELOG.md`.
> Kept for provenance, not an open to-do list.

# Crypto-Policy Gaps — Implementation Plan

**Goal**: extend the Plane-1 crypto-agility policy engine (`kmip/src/policy/`) so
**encryption, signing, KEM, and hashing** are abstracted and policy-updatable
across the **full PKCS#11 v3.2 mechanism surface**, leveraging **KMIP 3.0
`CryptographicParameters`** — closing gaps G1–G4 from `CRYPTO_POLICY_STATUS.md`.

**Architecture decision (locked):** policies are **authored in KMIP 3.0 terms**
(CryptographicAlgorithm + CryptographicParameters), but **enforced on a
canonical PKCS#11 `CKM_*` mechanism identity**, so the KMIP **PKCS#11 passthrough**
op (KMIP 3.0 §6.1.42, `ops.rs:1035`) cannot bypass KMIP-layer rules.

> **Source-of-truth rule (non-negotiable):** every KMIP enum/tag value comes
> from `kmip/spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json` (PQC additions:
> `kmip-spec-v3.0-wd19-clean.pdf`); every `CK*` value comes from
> `src/lib/pkcs11/pkcs11t.h` (mirrored in `rust/src/constants.rs`). **No value
> is invented.** Tables below cite verified values; any marked ⚠ must be
> re-confirmed against `pkcs11t.h` before coding.

---

## Verified parameter inventory (the vocabulary the policy will speak)

### KMIP 3.0 — authoring enums (verified from the spec tags-enums JSON)

| Enum (tag) | Values (name = codepoint) |
|---|---|
| **Hashing Algorithm** (`0x420038`) | SHA-1=0x04, SHA-224=0x05, SHA-256=0x06, SHA-384=0x07, SHA-512=0x08, SHA-512/224=0x0c, SHA-512/256=0x0d, SHA3-224=0x0e, SHA3-256=0x0f, SHA3-384=0x10, SHA3-512=0x11 (also MD2/4/5, RIPEMD-160, Tiger, Whirlpool — deprecated) |
| **Block Cipher Mode** (`0x420013`) | CBC=0x01, ECB=0x02, CFB=0x04, OFB=0x05, CTR=0x06, CMAC=0x07, CCM=0x08, GCM=0x09, CBC-MAC=0x0a, XTS=0x0b, AESKeyWrapPadding=0x0c, NISTKeyWrap=0x0d, AEAD=0x12 |
| **Padding Method** (`0x42005f`) | None=0x01, OAEP=0x02, PKCS5=0x03, Zeros=0x05, ANSI-X9.23=0x06, ISO-10126=0x07, PKCS1-v1.5=0x08, X9.31=0x09, PSS=0x0a |
| **Mask Generator** (`0x420054`) | MGF1=0x01 (+ `MaskGeneratorHashingAlgorithm` tag `0x420055` = a Hashing Algorithm enum) |
| **Cryptographic Algorithm** (`0x420028`) | 74 values incl. AES=0x03, RSA=0x04, ECDSA=0x06, HMAC-SHA256=0x09, ChaCha20Poly1305=0x1e, SHA3-256=0x20, SHAKE-256=0x28, Ed25519=0x37, ML-KEM-512..1024=0x39..3b, ML-DSA-44..87=0x3c..3e, SLH-DSA-*=0x3f..4a. **No KMAC.** |
| **CryptographicParameters scalar tags** | TagLength `0x4200ce` (Integer), SaltLength `0x420100` (Integer), RandomIV `0x4200c5` (Boolean) |
| **WD19 PQC (already decoded in I4)** | Deterministic `0x4201C4`, ContextString `0x4201C5`, Internal `0x4201C8`, ExternalMu `0x4201C9`, Seed `0x4201C6`, InputKeyMaterial `0x4201C7` (Bool/ByteString per WD19) |

### PKCS#11 v3.2 — canonical enforcement mechanisms (from `rust/src/constants.rs`, mirror of `pkcs11t.h`)

| Family | `CKM_*` = value |
|---|---|
| Hash | SHA256=0x250, SHA384=0x260, SHA512=0x270, SHA3_256=0x2B0, SHA3_512=0x2D0 |
| HMAC | SHA256_HMAC=0x251, SHA384_HMAC=0x261, SHA512_HMAC=0x271, SHA3_256_HMAC=0x2B1, SHA3_512_HMAC=0x2D1 |
| KMAC ⚠ | KMAC_128=0x80000100, KMAC_256=0x80000101 — **in vendor range; re-verify vs pkcs11t.h before relying on the value** |
| AES modes | ECB=0x1081, CBC=0x1082, CBC_PAD=0x1085, CTR=0x1086, GCM=0x1087 |
| RSA | RSA_PKCS_OAEP=0x09, SHA256_RSA_PKCS=0x40, SHA256_RSA_PKCS_PSS=0x43 (384/512 = 0x41/0x42, 0x44/0x45) |
| ECDSA | ECDSA=0x1041 (raw), ECDSA_SHA256=0x1044, SHA384=0x1045, SHA512=0x1046, SHA3-*=0x1047..104a |
| EdDSA | EDDSA=0x1057, EDDSA_PH=0x80001057 ⚠ (vendor range — re-verify) |
| PQC | ML_KEM=0x17, ML_DSA=0x1D, SLH_DSA=0x2E |
| KDF | PKCS5_PBKD2=0x3b0, SP800_108_COUNTER=0x3ac, HKDF_DERIVE=0x402a |

**Existing mapping reused as the single resolver:** `KmipAlgorithm::to_pkcs11_mech(PkcsOp)`
(`kmip/src/kmip30/algos.rs:254`) + the parameter-aware AES path in
`ops/helpers.rs:283–292` already turn *(KMIP algorithm + mode/padding)* into a
concrete `CKM_*`. This function becomes the policy's canonicalizer.

---

## Phase plan

### P0 — Canonical mechanism resolver (foundation, no behavior change)
Make one function the **single** "request → canonical `CKM_*`" resolver, covering
algorithm **and** CryptographicParameters (mode/padding/hash). Extend
`to_pkcs11_mech` / the helper so it accepts the full effective CP, returning the
exact mechanism (e.g. RSA + OAEP + SHA-256 → distinguish from RSA + PKCS1).
- **Files:** `kmip/src/kmip30/algos.rs`, `kmip/src/ops/helpers.rs`.
- **Tests:** table-driven (KMIP algo+params) → expected `CKM_*`, asserting every
  combination the verified enums above can form. No policy yet.
- **Accept:** every standard-op mechanism the server supports has exactly one
  canonical `CKM_*`; values match `constants.rs`.

### P1 — Extend `PolicyRequest` with the mechanism dimension
Add fields (all `Option`, populated from the *effective* CryptographicParameters
the Sign/Encrypt/MAC handlers already compute):
`hashing_algorithm`, `block_cipher_mode`, `padding_method`, `mask_generator`,
`mask_generator_hashing_algorithm`, `tag_length`, `salt_length`,
`deterministic`/`internal`/`external_mu`, and a computed `canonical_mech: Option<u32>`
(from P0). Thread them through every `evaluate()` call site.
- **Files:** `kmip/src/policy/request.rs`; op call-sites in `kmip/src/ops/{sign,signature_verify,encrypt,decrypt,mac_and_hash,derive_key}.rs`.
- **Tests:** request-builder tests asserting CP fields land in `PolicyRequest`.
- **Accept:** policy sees the mechanism, not just the key algorithm.

### P2 — Mechanism/param rule types (closes **G1 hashing**, **G2 params**, **G4 symmetric**)
New `Rule` variants, authored in KMIP enum terms, enforced on canonical `CKM_*`:
- `HashAlgorithmDefault` / `HashAlgorithmSubstitution` / `HashAlgorithmAllowlist`
  — over the **Hashing Algorithm** enum (SHA-2 ↔ SHA-3). *G1.*
- `MechanismParameterConstraint` — require/forbid `block_cipher_mode`,
  `padding_method`, `mask_generator`(+hash), `tag_length`, `salt_length` per op.
  e.g. "AES Encrypt ⇒ mode ∈ {GCM, CCM}", "RSA Encrypt ⇒ padding = OAEP & MGF1-SHA256",
  "RSA Sign ⇒ padding = PSS", "ML-DSA Sign ⇒ deterministic = true". *G2 + G4.*
- `MacMechanismPolicy` — gate the MAC family. **HMAC** maps from KMIP
  HMAC-SHA* algorithms; **CMAC** maps from BlockCipherMode=CMAC; **KMAC** has
  **no KMIP codification** → addressable only via the `CKM_*` dialect (P4). *G1.*
- **Files:** `kmip/src/policy/rule.rs` (variants + pass1/pass2), `loader.rs` (YAML).
- **Tests:** per-rule positive/negative/boundary, mirroring the existing 12-rule
  test style; one e2e proving a hash substitution + a mode constraint fire.
- **Accept:** hashing is policy-controllable; mechanism params gateable.

### P3 — `Decision::Allow` carries a CryptographicParameters override
Parallel to today's `algorithm_override`: let a policy **force** a mechanism
(not just gate it). `Decision::Allow { algorithm_override, cp_override: Option<CryptographicParameters>, .. }`.
Op handlers already accept an effective CP (Sign `sign.rs:204`, Encrypt) → apply
the override before the native call. Enables transparent "force AES-GCM /
RSA-OAEP-SHA256 / deterministic ML-DSA" with zero app change.
- **Files:** `kmip/src/policy/decision.rs`, `kmip/src/policy/rule.rs` (emit), op handlers.
- **Tests:** policy forces GCM on an app that asked for CBC → engine runs GCM.
- **Accept:** policy can *set*, not just *reject*, mechanism parameters.

### P4 — PKCS#11 passthrough gating + `CKM_*` rule dialect (closes **G3**, prevents bypass)
- Resolve the KMIP **PKCS#11** op's (§6.1.42, `ops.rs:1035`) raw `CKM_*` to the
  **same canonical identity** as standard ops, and run the same rules. This
  closes the bypass (denied AES-CBC at KMIP ⇒ also denied via raw `CKM_AES_CBC`).
- Add a `MechanismAllowlist`/`MechanismDenylist` keyed directly on `CKM_*`
  (source: `pkcs11t.h`) for mechanisms with **no KMIP codification** — KMAC,
  HKDF/SP800-108/PBKDF2, prehash-sig variants (`CKM_*ECDSA_SHA3*`, `CKM_EDDSA_PH`).
- **Files:** new `kmip/src/ops/pkcs11_passthrough.rs` policy hook (or extend the
  existing passthrough handler), `kmip/src/policy/rule.rs`.
- **Tests:** passthrough of a `CKM_*` denied by an equivalent KMIP rule is
  rejected; a KMAC-only `CKM_*` rule fires.
- **Accept:** full PKCS#11 v3.2 mechanism surface is policy-addressable; no
  passthrough bypass.

### P5 — Config, examples, tests, docs
- Extend the YAML schema (`schema_version` bump) + `loader.rs` validation for the
  new rule types; line-aware errors preserved.
- Example policies: `fips-hashing.yaml` (SHA-2/3 only), `aead-only.yaml`
  (AES⇒GCM/CCM, RSA⇒OAEP), `deterministic-signing.yaml` (ML-DSA deterministic).
- Update `CRYPTO_POLICY_STATUS.md` (close G1–G4), `CONFORMANCE_REPORT.md`.
- **Accept:** the four categories read **signing ✅ · KEM ✅ · encryption ✅ ·
  hashing ✅**, all PKCS#11 v3.2 mechanisms reachable through policy.

---

## Cross-cutting constraints
- **No guessed values.** Each new enum/mechanism constant is grepped from
  `pkcs11t.h` / the spec JSON and cited in the code comment, per CLAUDE.md.
- **Authoring vs enforcement separation.** YAML uses KMIP names; the engine
  canonicalizes to `CKM_*` (P0) for every gate, so a rule means the same thing
  whether the request arrived via a standard op or the passthrough.
- **Backward compatible.** New `PolicyRequest`/`Decision` fields are `Option`;
  existing key-algorithm rules and the merged classical↔PQC demo are unaffected
  (regression-gated by the existing `policy_*` test suites).
- **Stubs untouched here:** `MaxKeyAgeDays`, `ComplianceProfileGate`, rekey-txn
  completion remain their own Phase-6 items.

## Sequencing & verification
P0 → P1 are prerequisites; P2/P3 deliver G1/G2/G4; P4 delivers G3 + bypass
closure; P5 ships. Each phase: `cargo test` locally (policy unit + `policy_*`
integration suites) as the gate; **one** CI run per logical PR (not per step).
Suggested PR cuts: [P0+P1], [P2+P3], [P4], [P5].
