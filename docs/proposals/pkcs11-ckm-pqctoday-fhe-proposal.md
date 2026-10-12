# PQCToday FHE custody mechanisms (CKM_PQCTODAY_FHE_*): normative specification

Status: **P0B working specification, revision 3: review amendments A1–A5, the §11 answers and implementation amendment I-1 from the FHE P1/P2 implementer (session 7f) are applied. Educational, not a production interface**
Date: 2026-10-03
Engine scope: `softhsmrustv3` only

**Sources.**
- FHE wrapper plan v7 (`docs/implementation-plan-fhe-wrapper-pkcs11-vendor-2026-10-02.md`): §5, §6.2, §6.3 (owner-approved 2026-10-03), §6.6, §6.7.
- HSM key-hierarchy plan v5 and the [Key Replication Interface 1.0](pqctoday-key-replication-interface-1.0.md).
- Allocation authority `pqctoday-priv/docs/platform/data/pkcs11-vendor-mech-allocation.md` §1.4.5 (priv PR #148, merged `b80c856b`).
- The FHE P1 implementation on `feat/fhe-p1-1003` at `f48a040d`.
- Reference evidence in the private repo `pqctoday-org/pqctoday-fhe` at `ebda5c3d` (`reference-runs/tfhe-custody`).

**Owner approvals (2026-10-03, relayed by the coordinator session).** FHE plan P1–P2 approved ("Approve P1-P2 (Recommended)"). The §6.3 typed-decrypt text approved ("Yes to all three (Recommended)").

Where this document and the P1 code at `f48a040d` agree, the code is the reference. Where this document adds behaviour P1 does not yet have (the four mechanisms, the KDF, the output encoding), P2 implements it as written here, or a review amendment changes this text first.

## 1. Design invariants

1. The FHE seed (`CKK_PQCTODAY_FHE`) is `CKA_SENSITIVE=true`, `CKA_EXTRACTABLE=false`, `CKA_COPYABLE=false` and `CKA_MODIFIABLE=false` for its whole life. `C_WrapKey`, `C_WrapKeyAuthenticated`, `C_CopyObject` and `C_GetAttributeValue(CKA_VALUE)` refuse it. It leaves the token only through the Key Replication Interface 1.0, carrying the recovery descriptor of §7 as its type-specific extension.
2. The four mechanisms below are the only operations that use the seed. The caller-visible KDFs (`CKM_SP800_108_*`, `CKM_HKDF_*`, `CKM_*_KEY_DERIVATION`) are never in its `CKA_ALLOWED_MECHANISMS`. The seed's allowlist is a subset of {`CKM_PQCTODAY_FHE_DERIVE_PUBLIC`, `CKM_PQCTODAY_FHE_DECRYPT`}.
3. Only the client key is ever regenerated from the seed. Server keys and public keys are generated fresh on each derivation and are not reproducible (FHE plan D9; measured in `reference-runs/tfhe-custody` check C3).
4. No caller supplies cryptographic parameters. Parameter sets come from the allowlisted registry of §4.
5. Every decryption passes the typed policy of §6, which is SO-enrolled, immutable, and bound to the seed at creation. The HSM cannot verify which computation produced a submitted ciphertext; the policy limits what is released, not what was computed.
6. This is an educational emulator, and its claims are scoped as in FHE plan §1.2. The browser emulator and native software token give no hardware custody and no rollback resistance against the host. Evidence uses the label "software token on <board>" until HSM plan K6.

## 2. Definitions (authority §1.4.5)

| Codepoint | Symbol | Kind | Notes |
|---|---|---|---|
| `0x80000010` | `CKK_PQCTODAY_FHE` | key type | Seed-backed FHE secret, `CKO_SECRET_KEY` |
| `0x80000011` | `CKK_PQCTODAY_FHE_PUBLIC` | key type | Derived public FHE material, `CKO_PUBLIC_KEY` |
| `0x80000018` | `CKM_PQCTODAY_FHE_KEY_GEN` | mechanism | `C_GenerateKey`, §5.1 |
| `0x80000019` | `CKM_PQCTODAY_FHE_DERIVE_PUBLIC` | mechanism | `C_DeriveKey`, §5.2 |
| `0x8000001A` | `CKM_PQCTODAY_FHE_DECRYPT` | mechanism | `C_Decrypt`, single-part only, §5.3 |
| `0x8000001B` | `CKM_PQCTODAY_FHE_ENCRYPT` | mechanism | `C_Encrypt`, test builds only, §5.4 |

Attributes. Every one is engine-computed or creation-only and immutable: `attr_mutation_allowed` refuses every write, and templates never set them. That is the P1 rule.

| Codepoint | Symbol | Type | Value |
|---|---|---|---|
| `0x8000010C` | `CKA_PQCTODAY_FHE_SCHEME` | UTF-8 bytes | `tfhe-rs` (the only scheme in version 1) |
| `0x8000010D` | `CKA_PQCTODAY_FHE_PARAM_SET` | `CK_ULONG` | Registry ID (§4) |
| `0x8000010E` | `CKA_PQCTODAY_FHE_PARAM_HASH` | 48 bytes | SHA-384 of the canonical parameter encoding (§4) |
| `0x8000010F` | `CKA_PQCTODAY_FHE_LIBRARY` | UTF-8 bytes | Backend identifier, e.g. `tfhe-rs 1.8.1 187fc0b9` |
| `0x80000110` | `CKA_PQCTODAY_FHE_LINEAGE_ID` | 32 bytes | Random recovery identity, generated with the original seed and preserved across replication |
| `0x80000111` | `CKA_PQCTODAY_FHE_PUBLIC_KIND` | `CK_ULONG` | On `CKK_PQCTODAY_FHE_PUBLIC` objects only: `1` compressed server key, `2` compact public key |
| `0x80000112` | `CKA_PQCTODAY_FHE_DECRYPT_POLICY` | 48 bytes | SHA-384 of the enrolled policy DER (§6) |

The decrypt counter of §6.4 lives in the engine-private range (`>= 0xFFFF0000`), so it is never client-writable. It is not a vendor attribute and needs no allocation.

## 3. Seed object

| Attribute | Value |
|---|---|
| `CKA_CLASS` / `CKA_KEY_TYPE` | `CKO_SECRET_KEY` / `CKK_PQCTODAY_FHE` |
| `CKA_VALUE_LEN` | 32 (the seed; `CKA_VALUE` is never readable) |
| `CKA_TOKEN`, `CKA_PRIVATE`, `CKA_SENSITIVE` | true |
| `CKA_EXTRACTABLE`, `CKA_COPYABLE`, `CKA_MODIFIABLE`, `CKA_TRUSTED` | false |
| `CKA_DERIVE`, `CKA_DECRYPT` | true |
| `CKA_ALLOWED_MECHANISMS` | Exactly the replication policy's allowed mechanisms, which must be a subset of {`DERIVE_PUBLIC`, `DECRYPT`} |
| `CKA_DERIVE_TEMPLATE` | `{CKA_CLASS=CKO_PUBLIC_KEY, CKA_KEY_TYPE=CKK_PQCTODAY_FHE_PUBLIC, CKA_TOKEN=false, CKA_PRIVATE=false}` (F3 enforces it). It is a fixed profile constant, never caller-supplied. The engine sets it at `KEY_GEN` **and re-sets it when installing a replication package**, because packages do not carry restriction templates (A1). The descriptor's generator version (§7) implies it, so a replica can never lose it |
| Replication binding | The Key Replication Interface policy whose `typeConstraintHash` equals the FHE profile hash (P1 `profile_constraint_hash`) |
| History | Created by `KEY_GEN`: `CKA_LOCAL=true`, `CKA_KEY_GEN_MECHANISM=CKM_PQCTODAY_FHE_KEY_GEN`, `CKA_ALWAYS_SENSITIVE`/`CKA_NEVER_EXTRACTABLE=true`. Installed from a package: imported plus provenance (HSM plan decision 1) |

## 4. Parameter registry and canonical encoding

Version 1 has exactly one entry.

| ID | Name | Library | Config |
|---|---|---|---|
| 1 | `PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128` | TFHE-rs 1.8.1, commit `187fc0b95ab35352422deec6c027d0bd8743b6db`, features `integer` | `ConfigBuilder::default().use_dedicated_oprf_key(false)` (custody configuration, owner decision 2026-10-02) |

Measured for ID 1: n = 918, N = 2048, k = 1, KS level 4, `encryption_key_choice: Big`, log2 p_fail = −129.58.

**Canonical parameter encoding (P2).** This is the DER of `FheParamSetV1 ::= SEQUENCE { id INTEGER, library UTF8String, version UTF8String, commit OCTET STRING (SIZE(20)), paramName UTF8String, config UTF8String, kdf UTF8String }`, with the ID 1 values above and `kdf = "sp800-108-ctr-hmac-sha384/v1"`. `CKA_PQCTODAY_FHE_PARAM_HASH` is SHA-384 of that DER.

P1's placeholder hash (SHA-384 of the display name, `f48a040d` `param_hash`) is replaced in P2. Objects created under the placeholder are P1 test fixtures, so they are not migrated; P2 rejects them on import with `CKR_ENCRYPTED_DATA_INVALID`, the descriptor-mismatch code.

## 5. Mechanisms

All parameter structures use fixed-width fields, carry no pointers inside nested data, and start with `ulVersion` = 1. An unknown version, a wrong length or a non-null reserved field returns `CKR_MECHANISM_PARAM_INVALID`.

### 5.1 `CKM_PQCTODAY_FHE_KEY_GEN` (`C_GenerateKey`)

```c
typedef struct CK_PQCTODAY_FHE_KEY_GEN_PARAMS {
    CK_ULONG    ulVersion;            /* 1 */
    CK_ULONG    ulParamSet;           /* registry ID, §4 */
    CK_BYTE     replicationPolicyId[48]; /* SHA-384 of an enrolled replication policy (FHE profile) */
    CK_BYTE     decryptPolicyId[48];     /* SHA-384 of an enrolled FHE decryption policy, §6 */
} CK_PQCTODAY_FHE_KEY_GEN_PARAMS;
```

- **Session.** User role only, R/W session. The SO gets `CKR_USER_TYPE_INVALID`.
- **Template.** It may set only `CKA_LABEL`, `CKA_ID` and `CKA_TOKEN=true`. Anything else, or a value conflicting with §3, returns `CKR_TEMPLATE_INCONSISTENT`.
- **Generation.** The engine draws 32 seed bytes and 32 lineage bytes from its DRBG, and stamps §2's attributes from the registry and the two policies.
- **Policy checks.** An unknown parameter set, a replication policy without the FHE profile hash, or an unknown decryption policy returns `CKR_TEMPLATE_INCONSISTENT`, the P1 fixture's code.
- **Atomicity.** The object commits atomically or not at all.

### 5.2 `CKM_PQCTODAY_FHE_DERIVE_PUBLIC` (`C_DeriveKey`)

```c
typedef struct CK_PQCTODAY_FHE_DERIVE_PUBLIC_PARAMS {
    CK_ULONG    ulVersion;            /* 1 */
    CK_ULONG    ulPublicKind;         /* 1 compressed server key, 2 compact public key */
} CK_PQCTODAY_FHE_DERIVE_PUBLIC_PARAMS;
```

**Base key.** A `CKK_PQCTODAY_FHE` seed with this mechanism in its allowlist.

**Steps inside the mechanism:**
1. Derive the TFHE seed with §5.5.
2. Regenerate the client key with `ClientKey::generate_with_seed`.
3. Generate the requested public material with fresh randomness: `CompressedServerKey::new(&ClientKey)` or `CompactPublicKey::new(&ClientKey)`.
4. Serialize it with `tfhe::safe_serialization::safe_serialize`.
5. Zeroize the client key and the derived seed.

**Output.** A `CKO_PUBLIC_KEY` / `CKK_PQCTODAY_FHE_PUBLIC` **session** object with:
- `CKA_VALUE` = the serialized bytes;
- `CKA_PQCTODAY_FHE_PUBLIC_KIND`;
- `CKA_PQCTODAY_FHE_PARAM_HASH` and `CKA_PQCTODAY_FHE_LINEAGE_ID`, copied from the seed;
- `CKA_TOKEN=false` and `CKA_PRIVATE=false`, set explicitly, because derived objects default to private since R7.

A template asking for `CKA_TOKEN=true`, or any secret-key attribute, returns `CKR_TEMPLATE_INCONSISTENT`. A large object is never persisted (FHE plan §6.6, F10). The caller reads `CKA_VALUE` with the normal two-call `C_GetAttributeValue`.

**Sizes for ID 1 (measured).**

| Kind | Size |
|---|---|
| Compressed server key | 30,147,061 B |
| Compact public key | 33,034 B |

The per-object cap is 64 MiB. The output size is computed before allocation, and exceeding the session quota returns `CKR_DEVICE_MEMORY`.

**Authenticity.** The token does not sign the blob itself. The application signs a manifest with a standard `C_Sign(CKM_ML_DSA)` call using an ML-DSA-65 key. That key **must be token-resident and non-extractable**, and the compute server verifies it through K3 `attest_key` evidence (device chain plus lineage) before trusting the manifest. So no new vendor operation is needed. The manifest is the DER of `FhePublicManifestV1 ::= SEQUENCE { lineage OCTET STRING (SIZE(32)), paramHash OCTET STRING (SIZE(48)), kind INTEGER, valueSha384 OCTET STRING (SIZE(48)) }`. It never buffers the blob as signature input (F4). The KV260 compute server verifies the manifest before decompressing.

### 5.3 `CKM_PQCTODAY_FHE_DECRYPT` (`C_Decrypt`)

```c
typedef struct CK_PQCTODAY_FHE_DECRYPT_PARAMS {
    CK_ULONG    ulVersion;            /* 1 */
    CK_BYTE     recipient[48];        /* all-zero = owner; else SHA-384 of an enrolled recipient's
                                         ML-KEM-768 certificate SPKI (policy `recipients`) */
} CK_PQCTODAY_FHE_DECRYPT_PARAMS;
```

- **Single-part only.** `C_DecryptUpdate`/`C_DecryptFinal` return `CKR_FUNCTION_NOT_SUPPORTED` for this mechanism.
- **Input.** One TFHE-rs `safe_serialize` blob of a high-level `FheBool` or `FheUint*`, at most 4 MiB. **Version 1 refuses compressed ciphertext lists.** `FheType.compressed_allowed` must be false, and the policy parser refuses `true` (P2 change to the P1 parser).
- **Order of checks.** These run in a fixed order, so that errors cannot be used as an oracle. They extend §9 of the replication interface:
  1. **Rule 4, requester binding.** Session, login and role must be the owning user. The SO and public sessions get the standard role errors.
  2. **Mechanism allowed.** It must be in the base key's allowlist, else `CKR_KEY_FUNCTION_NOT_PERMITTED`.
  3. **Size query.** If `pData == NULL`, run only the rule 1 type gate and return the output length of the matched type, **without decrypting and without consuming the counter**. The type gate looks only at the ciphertext's shape (type, width, block count, parameters), which the submitter already knows, so the size query leaks nothing that depends on the plaintext (A5). A size query of a non-conforming input returns the same `CKR_ACTION_PROHIBITED` as a real call.
  4. **Counter.** Reserve one unit of the decrypt counter durably (§6.4). If exhausted, return `CKR_ACTION_PROHIBITED`. From here on, every refusal still consumes the unit.
  5. **Rule 5, recipient.** An all-zero recipient is allowed only if `recipient_only` is false. A non-zero recipient must be in the policy `recipients`. Otherwise return `CKR_ACTION_PROHIBITED`. This check does not depend on the plaintext, so it runs before any decryption work, and the refusal still consumes the counter unit (A3).
  6. **Rule 1, conformance-checked type gate.** For each policy `allowed_output_types` entry in order, call `safe_deserialize_conformant` with that type's conformance parameters (block count, moduli, LWE dimension, atomic pattern) and the 4 MiB cap. The first conforming type is the matched type. If none conforms, return `CKR_ACTION_PROHIBITED`.
  7. **Rule 2, input types.** If the matched type equals a `never_release` entry, return `CKR_ACTION_PROHIBITED`. P1's parser already forbids overlap, so this check is defensive.
  8. **Decryption.** Derive the seed (§5.5), regenerate the client key, decrypt, and zeroize.
  9. **Rule 3, post-decrypt predicates.** Each policy predicate (`MaxValue`/`MinValue` on the unsigned value) must hold. Otherwise return `CKR_ACTION_PROHIBITED`.
  10. **Release and audit.**
- **Every policy refusal returns the same `CKR_ACTION_PROHIBITED`.** The reason goes only to the audit log, so the token never says which rule failed. Refusal and release take the same code path up to the final output step.
- **Output to the owner.** One byte for the type (`0` = `FheBool`, `1` = `FheUint`), then a 2-byte big-endian width in bits, then the value as unsigned little-endian bytes of width ⌈bits/8⌉ (`FheBool` is 1 byte, 0 or 1).
- **Output to a recipient.** The owner-output bytes (3-byte type header plus value), sealed inside the token with HPKE to the recipient's ML-KEM-768 certificate. The suite is the Key Replication Interface's: KEM `0x0041`, HKDF-SHA384, AES-256-GCM.
  - `info` and `aad` are both the DER of `FheReleaseInfo ::= SEQUENCE { lineage OCTET STRING (SIZE(32)), decryptPolicyId OCTET STRING (SIZE(48)), recipient OCTET STRING (SIZE(48)), counter INTEGER }`.
  - The type header is inside the authenticated plaintext, not in `aad`: a recipient cannot know it before opening, but it can rebuild `FheReleaseInfo` from the signed release (I-1, found while implementing P2).
  - Encapsulation randomness is engine-generated, and test hooks are absent in shipped builds (F5).
- **The sealed release is signed (A2).** HPKE base mode does not authenticate the sender, so on its own a recipient could not tell the plaintext came from this token under this policy. The token therefore signs the release with its existing internal **receipt-signing function key** (ML-DSA-65; no allocation, because it is an internal function key).
  - The signed bytes are `"PQCToday FHE Release 1.0" ‖ 0x00 ‖ DER{lineage, decryptPolicyId, recipient, counter, SHA-384(enc ‖ ciphertext)}`.
  - The output is the DER of `FheSealedReleaseV1 ::= SEQUENCE { enc OCTET STRING, ciphertext OCTET STRING, counter INTEGER, signature OCTET STRING, signerChain SEQUENCE OF Certificate }`. The signer chain is the device and receipt-signer certificates, as in the replication receipt.
- **Limits the policy cannot remove, stated in every claim.** A requester can re-slice an input into an allowed width (rule 2 bounds bits per call, not provenance). Release-or-refuse leaks one bit per call (rule 3). Both are bounded only by the counter.

### 5.4 `CKM_PQCTODAY_FHE_ENCRYPT` (`C_Encrypt`)

This mechanism exists only in builds with the `test-support` feature, for known-answer vectors. It is not advertised by `C_GetMechanismList` in shipped artefacts, and `C_GetMechanismInfo` returns `CKR_MECHANISM_INVALID` there. Its input is the owner-output format of §5.3. It encrypts under the regenerated client key and returns the `safe_serialize` blob.

### 5.5 Seed derivation (normative; generator version 1)

```
TFHE seed (u128) = first 16 bytes, big-endian, of
  HMAC-SHA-384(K = 32-byte seed,
    [1]_32BE || "pqctoday-fhe/tfhe-client-key-seed" || 0x00 || Context || [128]_32BE)
Context = LP("TFHE") || LP(paramName) || LP("cfg:no-dedicated-oprf") || LP("client") || LP("v1")
LP(x)   = [len(x)]_32BE || x
```

This is NIST SP 800-108r1 counter mode with one block, and it runs only inside §5.2 and §5.3. The derived seed and the regenerated client key are zeroized after use, and no sub-seed object exists.

**Known-answer vector.** Fixture `client-key-kat-v1`, mirrored in the Hub contract `fhe-hsm-scenarios.v1.json`.

| Item | Value |
|---|---|
| Input seed | `00 01 02 … 1f` |
| Derived seed | `0xf6eb1c9a88a4442c8a7449536c3d12dc` |
| SHA-256 of `safe_serialize(ClientKey)` | `9f5d847e4d1121eef9d75fcc473e89ee5306523f9cb140384eba5aa85a55b77b` (24,087 B) |

The vector is identical on macOS arm64, Linux arm64, Linux x86-64 and wasm32. P2 must reproduce it in a native test and in the WASM build.

## 6. Typed decryption policy

### 6.1 Encoding

The policy is the DER of the P1 `FheDecryptPolicy` structure (`f48a040d` `rust/src/replication/fhe.rs`):

```asn1
FheType ::= SEQUENCE { typeName UTF8String, widthBits INTEGER (1..256), paramSet INTEGER,
                       serializationVersion INTEGER, compressedAllowed BOOLEAN }
Predicate ::= SEQUENCE { kind ENUMERATED { maxValue(0), minValue(1) }, bound INTEGER }
FheDecryptPolicy ::= SEQUENCE {
    version INTEGER (1),
    allowedOutputTypes SEQUENCE (SIZE(1..32)) OF FheType,   -- strictly sorted, unique
    neverRelease SEQUENCE (SIZE(0..32)) OF FheType,         -- strictly sorted, unique, disjoint
    predicates SEQUENCE (SIZE(0..8)) OF Predicate,          -- kinds strictly increasing
    recipients SEQUENCE (SIZE(0..16)) OF OCTET STRING (SIZE(48)),  -- sorted
    recipientOnly BOOLEAN DEFAULT FALSE,                    -- requires recipients
    maxDecrypts INTEGER (1..MAX) }
```

The policy ID is SHA-384 of the DER. The parser rejects anything else with `CKR_DATA_INVALID`, and every `paramSet` must be in the registry.

### 6.2 Enrollment

The SO enrolls a policy in a record with role 13, as P1 does. Enrolling identical DER again is idempotent, and there are at most 64 policies per slot.

Over KMIP (programme stage 2), policy enrollment is a signed SO update. Root and trust-anchor enrollment stays board-local (owner decision, 2026-10-03).

### 6.3 Replication

A destination installs a replicated seed only under an enrolled policy that is equal or stricter (P1 `is_equal_or_stricter_than`):
- a subset of output types and recipients;
- a superset of never-release types;
- predicates at least as strict;
- `recipientOnly` preserved;
- `maxDecrypts` not larger.

A streamed-CKKS seed adds one rule: the destination's replication policy must have the same `maxReplicas` as the
source's policy (refusal reason "CKKS seed replica must keep the source policy's maxReplicas"). Every copy then
computes the same lineage-wide q for its decryption flooding (§6.6). The FHE replica already keeps the source's
decryption policy unchanged (§7), so `maxDecrypts` is the same on every copy.

### 6.4 Counter

The counter is a per-object count of decrypt calls, released or refused, kept in an engine-private attribute. It is reserved durably before any decryption work, in the same atomic snapshot commit as the audit record.

A replicated object starts its own counter at 0, so clones do not share a global budget (HSM plan §3). The bound across a lineage is therefore **total releases ≤ (maxReplicas + 1) × maxDecrypts**, where `maxReplicas` is the replication policy's replica limit (A4). The budget rule of the Key Replication Interface (each export costs one, a backup carries at most one onward restore, and source plus descendants never exceed the source's budget) keeps the copies of a lineage to at most `maxReplicas` + 1. Streamed-CKKS flooding uses this bound as q (§6.6). The counter resists reuse within the current state, but cannot resist the host rolling the whole token snapshot back; that is disclosed.

### 6.5 Profile hash changes and re-enrolment (streamed CKKS)

A replication policy governs FHE seeds only when its `typeConstraintHash` equals the seed scheme's profile hash
(§3, "Replication binding"). The streamed-CKKS profile constraint is
`FheProfileConstraint { version 1, scheme "ckks-stream", paramSets }`, and `paramSets` lists every registered CKKS
parameter set in registry order (`fhe::ckks_profile_constraint_der`). Registering a parameter set therefore changes the
CKKS profile hash. The TFHE profile hash is separate and does not change.

**The changes so far.** Registry ID 3 (2026-10-11) changed `paramSets` from `[2, 0x8002]` to `[2, 0x8002, 3]`. The
earlier hash existed only in engine builds made while the CKKS work was in progress (HSM PR #351, before commit
`c61a5139`); no release carried it. A token initialised with such a build may still hold policies enrolled under it.
Registry ID 4 (2026-10-12, §6.8) changed it again, from `[2, 0x8002, 3]` to `[2, 0x8002, 3, 4]`. Unlike the first
change, the `[2, 0x8002, 3]` hash may exist on tokens that ran the build with ID 3 (HSM `main` at `d6b23452` and
later): those tokens' CKKS replication policies need the same re-enrolment, with the same steps below.

**What the engine does with a policy under an earlier hash.**
- `enroll_policy` refuses it (`CKR_DATA_INVALID`): the hash is no longer an FHE profile hash.
- An already enrolled copy stays on the token, but `CKM_PQCTODAY_FHE_KEY_GEN` refuses to bind a new seed to it
  (`CKR_TEMPLATE_INCONSISTENT`).
- A seed already bound to it can no longer be replicated: the source refuses to build a package because the policy's
  hash does not match the seed's profile. The seed itself keeps working on its own token: `DERIVE_PUBLIC` and
  `DECRYPT` do not consult the replication policy.

**Who re-enrols, and how.**
1. The Security Officer of each token that must replicate CKKS seeds, on the source and on every destination (a
   destination accepts only an equal or stricter policy, which requires an equal `typeConstraintHash`), enrols the
   policy again with every field unchanged except `typeConstraintHash`, set to the current
   `fhe::ckks_profile_constraint_hash()`. Locally this is `enroll_policy`; over KMIP it is the signed SO policy update
   (§6.2).
2. The policy ID is the SHA-384 of the policy DER, so the re-enrolled policy has a new ID. Users name the new ID when
   they generate CKKS seeds.
3. A seed bound to the old policy cannot be rebound. To make its data replicable, generate a new seed under the
   re-enrolled policy and move the stored ciphertexts to it with the SO-only rotation key (`DERIVE_PUBLIC` parameter
   version 3), then retire the old seed. Rotation does not check the replication policy; it needs the same parameter
   set and an equal or stricter decryption policy. This route is described, not yet covered by a test.

**How it is checked.** `enroll_policy` returns the new ID, and a seed generated under it carries that ID in
`CKA_PQCTODAY_REPLICATION_POLICY_ID`. The test
`ckks_policy_under_earlier_profile_hashes_refused_reenrolled_accepted` (`rust/tests/replication_fhe_ckks.rs`) computes
the earlier hashes from the pre-ID-3 and pre-ID-4 registries through the same encoding
(`fhe::ckks_profile_constraint_der_for(&[2, 0x8002])` and `(&[2, 0x8002, 3])`). It checks that enrolment refuses both,
that a policy an earlier build enrolled under the pre-ID-4 hash refuses `KEY_GEN` for IDs 2, 0x8002, 3 and 4, and that
the re-enrolled policy is accepted.

**Future registrations.** Adding a CKKS parameter set changes the hash again. Each such change says so in
`CHANGELOG.md` and repeats the steps above for every token that holds CKKS replication policies. The generator freeze
(gate V, `rust/src/replication/fhe_ckks/freeze.rs`) does not stop new sets from being registered: a new set is
appended to the frozen table with its own known-answer file.

### 6.6 Streamed CKKS: the flood sampler (owner decision 2026-10-11)

A CKKS release that the policy floods (`floodRecipients`, by default for every release that is not the owner's) adds
one noise value to each coefficient of the decrypted plaintext before it is decoded
(`rust/src/replication/fhe_ckks/mech.rs`, `flood`). This section records how wide the noise is, how it is drawn and
what that means.

- **Width (corrected 2026-10-11).** The width follows Li, Micciancio, Schultz and Sorrell (CRYPTO 2022, ePrint
  2022/816). Definition 18: "S-CKKS_σ.Dec_sk(ct) = CKKS.Dec_sk(ct.c) + N_{Z^n}(0, σ²·ct.t²·I_n)". Corollary 2: "Let
  σ = √(24qn)·2^{s/2}. If CKKS is (c + log₂ 24)-bit IND-CPA-secure, then S-CKKS_σ is (c, s)-bit q-IND-CPA^D-secure."
  The proof bounds the ℓ2 norm of the error by √n times its ∞-norm bound ct.t. The token therefore adds noise of
  standard deviation σ·t, with

  `flood_sigma_log2` = λ_s/2 + ½·log₂(24·q·n) + log₂ B,

  where s = λ_s (`statSecurityBits`), n is the set's ring degree, t = B is the registry's bound on the release-level
  error (`params::noise_bound_log2`), and q = (maxReplicas + 1) × maxDecrypts (§6.4, `lineage_releases`), with
  `maxReplicas` read from the seed's bound replication policy. B is measured as the largest absolute coefficient
  error (an ∞-norm in the coefficient domain, the domain the noise is added in), so ‖e‖₂ ≤ √n·B holds as the proof
  needs. A flooded release whose replication policy is not enrolled is refused.
  The previous width, λ_s/2 + ½·log₂(maxDecrypts) + log₂ B, omitted √24 and √n (½·log₂(24·n) = 10.29 bits at
  n = 2^16) and counted one copy only. For the test policy (λ_s = 30, maxDecrypts = 10,000, maxReplicas = 4,
  q = 50,000):

  | Set | n | log₂ B | Previous log₂ σ | Corollary 2 log₂ σ | Cap |
  |---|---|---|---|---|---|
  | 3 (two primes, scale 2^90) | 2^16 | 36 | 57.64 | 69.10 | 80 |
  | 2 (one prime) | 2^16 | 10 | 31.64 | 43.10 | 62 |
  | 0x8002 (test ring) | 2^10 | 12 | 33.64 | 42.10 | 62 |

  Corollary 2 also requires CKKS itself to be (c + log₂ 24)-bit IND-CPA-secure; that is a property of the parameter
  set, not of the flooding. The table in the paper's §4.5 fixes n = 2^15, so it does not apply to n = 2^16 directly.
- **Cap.** The token refuses a width above 2^62 for one-prime releases (unchanged) and above 2^80 for two-prime
  releases (registry ID 3, q0·q1 ≈ 2^105). At 2^80 every draw is below 2^83.2, about 20 bits under q0·q1/2, and the
  decoded slot noise (about σ·√n·4.5) already equals the scale 2^90, so a wider width would only release noise.
- **Distribution.** The noise is a rounded continuous Gaussian: Box–Muller on the token DRBG (an AES-256-CTR stream
  keyed from the operating system's random source), with the platform's `ln` and `cos`, rounded to an integer. Above
  σ = 2^45 (registry ID 3, σ = 2^69.10 under the test policy) each value is the sum of two independent rounded draws
  (σ_f = 2^44 and σ_c = √(σ² − σ_f²)), so the low bits of the sum are not left on the coarse grid of a single double
  (2^20 at σ = 2^69, 2^31 at the cap; both well below σ_f).
- **Per-value timing is not constant.** The time of one draw depends on the value drawn, through the `cos` code path
  of the C library. Measured on the MX95 Pro (Cortex-A55, glibc 2.43): when the Box–Muller angle is below 0.855 rad, a
  draw is about 21 ns faster than average, out of about 230 ns per draw for one rounded draw and about 390 ns for the
  split draw of registry ID 3. The angle range reveals the sign of the value and a bound on its size relative to the
  radius. Seeing this signal needs fine-grained timing of single draws, for example by code running on the token's
  CPU.
- **Whole-release timing showed no measurable dependence.** Over 2,000–4,000 releases of 2^14 coefficients on the
  MX95 Pro and on an M5 Max (Linux container), the time of a release did not correlate with the noise drawn
  (|r| ≤ 0.04, not significant): per-draw differences of a few nanoseconds average out under 18–48 µs of
  call-to-call variation. This is what a recipient that only sees release times can observe.
- **The published analysis assumes a different distribution.** The flooding analysis for CKKS (Li, Micciancio,
  Schultz and Sorrell, CRYPTO 2022, ePrint 2022/816, Definition 18 and Corollary 2) adds a *discrete* Gaussian and
  bounds the leakage in KL divergence. It does not analyse a rounded continuous Gaussian, and no source found bounds
  the distance between this sampler's output and a discrete Gaussian at these widths. The security argument of the
  published analysis therefore does not apply to this sampler as it stands.
- **Not implemented.** A constant-time discrete Gaussian sampler, for example the convolution sampler of Micciancio
  and Walter (CRYPTO 2017, ePrint 2017/259) over a constant-time table sampler, would address both points. The owner
  decided on 2026-10-11 not to build it for now and to document the sampler as it is. OpenFHE v1.6.0 floods with an
  exact discrete Gaussian that its own header says may be vulnerable to timing attacks; Lattigo v6.2.0 rounds CKKS
  results and does not flood them.

Source of the measurements and the method: pqctoday-fhe `docs/ckks/ckks-flood-sampler-timing-note-2026-10-11.md`
and `reference-runs/ckks-sampler-timing/`.

### 6.7 Streamed CKKS: key rotation records, replicas and an open question

Key rotation (`CKM_PQCTODAY_FHE_DERIVE_PUBLIC` parameter version 3, SO only) is specified in the module comment of
`rust/src/replication/fhe_ckks/rotation.rs`. Three points are recorded here.

**Retirement is recorded in the token's retirement ledger.** `retire_old_seed` acts only on a seed whose rotation
manifest was signed. Before it destroys the old seed, it commits a retirement record: a public, immutable token object
(`CKO_DATA`, not modifiable, copyable or destroyable) whose `CKA_VALUE` is the DER of `CkksSignedRotationRetirementV1`.
The record names both lineages, the parameter hash, the token time of retirement and the SHA-256 of the rotation
descriptor. That hash is the `rotationDescriptorHash` of the signed rotation manifest, so the record links to the
manifest a receiver already holds. It is signed with the receipt-signing key under its own domain
(`"PQCToday CKKS Rotation Retirement 1.0"`) and checked with `verify_ckks_rotation_retirement`. The rotation manifest
itself is unchanged: it is signed before re-encryption starts, so it cannot also record the retirement. Retirement
records are not generator output, and the frozen generator bytes (§5.5, `freeze.rs`) do not change. The audit log
entry `fhe_ckks_rotation_old_seed_destroyed` now also carries the record's SHA-256. Tests:
`rotation_retirement_record_signed_in_ledger` (`rust/tests/replication_fhe_ckks_rotation.rs`).

**A replica is never the new seed (decision D3, 2026-10-11: keep refusing).** The new seed of a rotation must have
been generated by this token (`CKA_LOCAL` true and `CKA_KEY_GEN_MECHANISM` = `CKM_PQCTODAY_FHE_KEY_GEN`). A seed
received through the Key Replication Interface is refused as the target, even when another token generated it,
because replication of a rotation is not designed: the replica's secret also exists on its source and on any other
replica, and the rotation rules of this token (one target, never back, retirement of the old seed) do not reach those
copies. A replica may still be the *old* seed. Test: `rotation_refuses_replica_of_token_made_seed_as_new`.

**Open question: can a holder of the old secret read a switched ciphertext without the original?** Not established.

- What is known. A switched ciphertext is c′ = (c₀ + ⌊⟨D(c₁), b⟩/P⌉, ⌊⟨D(c₁), a⟩/P⌉), where D is the RNS gadget
  decomposition and (b, a) is the rotation key, b = −a·s_new + w·P·s_old + e (Lattigo v6.2.0
  `core/rlwe/evaluator_evaluationkey.go` `applyEvaluationKey` and `evaluator_gadget_product.go` `GadgetProduct`).
  Key switching there adds no fresh randomness: c′₁ is a deterministic function of c₁ and the key.
- Whoever holds s_old *and* the rotation key can turn the key into RLWE samples of s_new (b − w·P·s_old = −a·s_new +
  e). If they could also recover the digits D(c₁) from c′₁ = ⌊⟨D(c₁), a⟩/P⌉, they could rebuild c₁ and then c₀,
  and decrypt with s_old. The RNS digits are not small (each is a residue modulo its group of primes), so this is not
  an ordinary short-solution problem, and no source found states how hard it is.
- Lattigo's own documents describe an evaluation key as enabling "the public and non interactive re-encryption of
  any ciphertext encrypted under skIn to a new ciphertext encrypted under skOut" and claim IND-CPA only
  (`SECURITY.md`); they say nothing about a party that holds skIn. Lattigo's *multiparty* key-switching protocols, in
  which parties hold shares of the input key, add smudging noise to the output for this kind of reason
  (`multiparty/README.md`, `multiparty/keyswitch_sk.go`); single-party key switching does not.
- What would settle it. Either (1) a published reduction showing that, given s_old and the rotation key, a switched
  ciphertext is indistinguishable from a fresh encryption under s_new; or (2) a change that makes the question moot:
  after switching, the server adds a fresh public-key encryption of zero under s_new (and, to be safe, smudging
  noise). Under RLWE the added encryption of zero is pseudorandom, so the result no longer reveals c′₁, and its
  secrecy rests on RLWE for the new key set, as for any fresh ciphertext. Option (2) is our reasoning, not a sourced result, and is not built.
- Until then, the rule stands that the server deletes the rotation key after use and the SO retires the old seed once
  re-encryption is confirmed. Rotation does not protect ciphertexts that someone holding s_old has already copied.

### 6.8 Streamed CKKS: registry ID 4, OpenFHE v1.6.0 `match128` (owner release only)

Registry ID 4, `CKKS_N16QP1720H192H32_OPENFHE_V1_6_0_MATCH128`, makes the token's own key export usable in OpenFHE
v1.6.0. Its moduli, digit layout and key list are those OpenFHE builds for the settings in the pqctoday-fhe note
`docs/ckks/ckks-openfhe-registry-entry-spec-2026-10-12.md` (N = 2^16; a 60-bit first prime and twenty-five primes of
52 bits; six 60-bit key-switching primes; five digits; 128-bit security checked by OpenFHE at log QP = 1720; main
secret Hamming weight 192, sparse secret 32). The key list is OpenFHE's closed bootstrapping list: the
relinearization key, 75 rotation keys, the conjugation key and OpenFHE's two sparse-secret keys, 79 keys in all
(13.09 GB with the `a` halves, 6.54 GB of `b` halves streamed). It holds no rotation key for a user's own use.

- **One new key kind, additive.** OpenFHE's dense-to-sparse key is a one-digit key over the bottom prime and two
  auxiliary 33-bit primes P′, not over the set's P. Key kind 6 (`KIND_DENSE_TO_SPARSE_AUX`) has the same equation as
  kind 3 over `Q[0] ‖ aux_p`. The sparse-to-dense key is an ordinary hybrid key (kind 4). The new fields `aux_p` and
  `aux_p_roots` are empty for IDs 2, 3 and 0x8002 and are hashed into `param_hash` only when present, so those sets'
  hashes, key lists and known answers are byte-identical. Generator version 1 stays; the freeze table gains a row.
- **Owner release only.** No flood bound has been measured for ID 4: its refresh runs in OpenFHE, and a bound measured
  through Lattigo's refresh says nothing about it. A set without a measured bound (`params::owner_release_only`)
  therefore releases to its owner only, unflooded, rounded to the policy's precision. The policy parser refuses a
  policy that lists a third-party recipient, or floods the owner release, for such a set
  (`CKR_DATA_INVALID`); the decrypt path refuses both again (`mech::release_gate`, the same `CKR_ACTION_PROHIBITED` as
  every other refusal) for a policy that predates the set's registration. IDs 2, 3 and 0x8002 have a bound and keep
  their behaviour. Adding a bound to `noise_bound_log2` is what turns a set into one that may flood.
- **Release.** One prime (serialization version 2, `PQCKKS02`, release type `CkksPlaintextQ0`), the default scale
  2^52. OpenFHE's ciphertexts at a level have a scale within about 7.4·10^-9 (relative) of 2^52, so a release read at
  2^52 carries that relative error, far below the 2^-20 rounding.
- **Re-enrolment.** The CKKS profile hash changes (§6.5).
- **Tests.** `kat_registry_4_matches_reference_spec` and the ignored `kat_registry_4_all_keys`
  (`rust/tests/replication_fhe_ckks_flood.rs`), `registry_4_is_owner_release_only` in the same file, and the unit
  tests in `params.rs` and `mech.rs`.

## 7. Recovery descriptor (replication type extension)

The descriptor is the DER of P1's `FheRecoveryDescriptor`: `{ version 1, scheme, paramSet, paramHash, library, generatorVersion, lineageId, decryptPolicy }`. The engine recomputes it from the seed's immutable attributes, and it travels as the Key Replication Interface's `typeExtension`, bound by `typeExtensionHash` under the package signature.

`generatorVersion = 1` means the derivation of §5.5 plus `ClientKey::generate_with_seed` of the §4 library and config.

On import, the destination rejects the package with `CKR_ENCRYPTED_DATA_INVALID` (as P1 does) if any of these fail:
- the version, scheme or generator version is unknown;
- `paramHash` does not equal the registry hash for `paramSet`;
- the lineage does not equal the signed header's lineage;
- the policy ID is not 48 bytes.

A future TFHE-rs version that changes `generate_with_seed` output needs a new generator version, with the old one kept, or a specified migration. Re-encrypting the seed is not a migration (FHE plan §5). `reference-runs/tfhe-custody` is re-run for each TFHE-rs tag against the KAT of §5.5.

## 8. Bounds and mechanism info

| Item | Maximum |
|---|---:|
| Seed | 32 B (exact) |
| Decrypt input blob | 4 MiB |
| Derived public object | 64 MiB |
| Policy DER / policies per slot | 8 KiB / 64 |
| Recovery descriptor DER | 4 KiB |
| Allowed output types / never-release types / predicates / recipients | 32 / 32 / 8 / 16 |

| Mechanism | `ulMinKeySize` / `ulMaxKeySize` | Flags |
|---|---|---|
| `KEY_GEN` | 32 / 32 (bytes) | `CKF_GENERATE` |
| `DERIVE_PUBLIC` | 32 / 32 | `CKF_DERIVE` |
| `DECRYPT` | 32 / 32 | `CKF_DECRYPT` |
| `ENCRYPT` (test builds only) | 32 / 32 | `CKF_ENCRYPT` |

None of the four is advertised by a normal release build until the gates of §10 close.

## 9. Return codes

| Condition | Code |
|---|---|
| Bad structure, version, length or reserved field | `CKR_MECHANISM_PARAM_INVALID` |
| Mechanism not in the seed's allowlist, or a wrong key type | `CKR_KEY_FUNCTION_NOT_PERMITTED` / `CKR_KEY_TYPE_INCONSISTENT` |
| Template conflicts with §3 or §5.2 | `CKR_TEMPLATE_INCONSISTENT` |
| Unknown parameter set or policy at `KEY_GEN` | `CKR_TEMPLATE_INCONSISTENT` |
| Malformed policy DER at enrollment | `CKR_DATA_INVALID` |
| Any decrypt policy refusal: type gate, never-release, predicate, recipient, counter exhausted | `CKR_ACTION_PROHIBITED` (one code; the reason goes to the audit log only) |
| Output buffer too small | `CKR_BUFFER_TOO_SMALL`, with the length |
| Over a size cap or quota | `CKR_DEVICE_MEMORY` |
| Descriptor or package inconsistency on import | `CKR_ENCRYPTED_DATA_INVALID` |
| Multi-part decrypt | `CKR_FUNCTION_NOT_SUPPORTED` |

Every error path zeroizes transient secrets and leaves no partial object.

## 10. Gates before advertising

1. P1 exit (already on `feat/fhe-p1-1003`): both replication flows pass for the opaque fixture, including descriptor tamper and unsupported-generator refusals.
2. P2 implements §5 against TFHE-rs 1.8.1 and reproduces the KAT of §5.5, natively and in WASM.
3. Tests from FHE plan §6.3. These must include:
   - each allowed type is released;
   - a disallowed width and an oversized input are refused before decryption;
   - a raw never-release input is refused, while a re-sliced 4-block slice is **released** (the documented limit);
   - every predicate failure looks identical to the caller, and refusals consume the counter;
   - SO, public and foreign-token sessions are refused;
   - recipient-only never returns plaintext to the owner.
4. The repository gates of FHE plan §10.1: the vendor-constant manifest, the mechanism ledger with `excluded-by-scope:` on C++ rows, conformance-report freshness, vector reachability, and the full local gate.
5. The owner's separate approval to advertise.

## 11. Review decisions (rev 2)

1. **Owner output format:** the 3-byte type header plus little-endian value stays. DER adds nothing for a scalar.
2. **Compressed ciphertext lists:** refused in version 1 (§5.3).
3. **Server-key manifest signer:** an application ML-DSA-65 key that is token-resident, non-extractable and attested through K3 (§5.2).
4. **P1 placeholder parameter hash:** retired in P2. P1 fixtures are test-only and are not migrated (§4).

## 12. Revision history

| Rev | Date | Change |
|---|---|---|
| 1 | 2026-10-03 | First normative draft, aligned with authority §1.4.5 and FHE P1 at `f48a040d` |
| 3 | 2026-10-03 | Implementation amendment I-1 from session 7f: the recipient release uses `info = aad = DER(FheReleaseInfo)`, and the 3-byte type header moves inside the authenticated plaintext. 7f's P2 build reproduces the §5.5 KAT exactly (derived seed `0xf6eb…12dc`, client key `9f5d847e…b77b`, 24,087 B) |
| 2 | 2026-10-03 | Review amendments from session 7f: A1 derive template re-set on install; A2 signed sealed release; A3 recipient check before decryption; A4 lineage-wide release bound; A5 size query leaks only shape. §11 resolved: header format kept, compressed lists refused, attested manifest key, placeholder hash retired |
| 4 | 2026-10-11 | §6.5: the streamed-CKKS profile hash lists every registered CKKS set; re-enrolment after registry ID 3 changed it, and its test |
| 5 | 2026-10-11 | §6.6: the CKKS flood sampler as built (rounded continuous Gaussian, per-value timing measured, owner decision not to build a constant-time discrete sampler). §6.7: signed rotation retirement record in the token's retirement ledger, replicas refused as the new rotation seed (D3), and the open question on old-secret holders |
| 6 | 2026-10-11 | §6.6: flood width corrected to LMSS22 Corollary 2 (√(24·q·n), q = lineage total), two-prime cap 2^80; §6.3: a CKKS replica keeps the source's `maxReplicas`; §6.4: lineage bound used as q |
