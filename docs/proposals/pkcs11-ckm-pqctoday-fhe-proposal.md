# PQCToday FHE custody mechanisms (CKM_PQCTODAY_FHE_*): normative specification

Status: **P0B working specification, revision 1, for review by the FHE P1/P2 implementer; educational, not a production interface**
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
| `CKA_DERIVE_TEMPLATE` | `{CKA_CLASS=CKO_PUBLIC_KEY, CKA_KEY_TYPE=CKK_PQCTODAY_FHE_PUBLIC, CKA_TOKEN=false, CKA_PRIVATE=false}` (F3 enforces it) |
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

**Authenticity.** The token does not sign the blob itself. The application signs a manifest with a standard `C_Sign(CKM_ML_DSA)` call using an ML-DSA-65 key. The manifest is the DER of `FhePublicManifestV1 ::= SEQUENCE { lineage OCTET STRING (SIZE(32)), paramHash OCTET STRING (SIZE(48)), kind INTEGER, valueSha384 OCTET STRING (SIZE(48)) }`. It never buffers the blob as signature input (F4). The KV260 compute server verifies the manifest before decompressing.

### 5.3 `CKM_PQCTODAY_FHE_DECRYPT` (`C_Decrypt`)

```c
typedef struct CK_PQCTODAY_FHE_DECRYPT_PARAMS {
    CK_ULONG    ulVersion;            /* 1 */
    CK_BYTE     recipient[48];        /* all-zero = owner; else SHA-384 of an enrolled recipient's
                                         ML-KEM-768 certificate SPKI (policy `recipients`) */
} CK_PQCTODAY_FHE_DECRYPT_PARAMS;
```

- **Single-part only.** `C_DecryptUpdate`/`C_DecryptFinal` return `CKR_FUNCTION_NOT_SUPPORTED` for this mechanism.
- **Input.** One TFHE-rs `safe_serialize` blob of a high-level `FheBool` or `FheUint*`, at most 4 MiB. Version 1 does not accept compressed ciphertext lists unless the policy type sets `compressed_allowed`.
- **Order of checks.** These run in a fixed order, so that errors cannot be used as an oracle. They extend §9 of the replication interface:
  1. **Rule 4, requester binding.** Session, login and role must be the owning user. The SO and public sessions get the standard role errors.
  2. **Mechanism allowed.** It must be in the base key's allowlist, else `CKR_KEY_FUNCTION_NOT_PERMITTED`.
  3. **Size query.** If `pData == NULL`, return the output length computed from the matched type (rule 1 below) **without decrypting and without consuming the counter**. A size query of a non-conforming input returns the same `CKR_ACTION_PROHIBITED` as a real call.
  4. **Counter.** Reserve one unit of the decrypt counter durably (§6.4). If exhausted, return `CKR_ACTION_PROHIBITED`. From here on, every refusal still consumes the unit.
  5. **Rule 1, conformance-checked type gate.** For each policy `allowed_output_types` entry in order, call `safe_deserialize_conformant` with that type's conformance parameters (block count, moduli, LWE dimension, atomic pattern) and the 4 MiB cap. The first conforming type is the matched type. If none conforms, return `CKR_ACTION_PROHIBITED`.
  6. **Rule 2, input types.** If the matched type equals a `never_release` entry, return `CKR_ACTION_PROHIBITED`. P1's parser already forbids overlap, so this check is defensive.
  7. **Decryption.** Derive the seed (§5.5), regenerate the client key, decrypt, and zeroize.
  8. **Rule 3, post-decrypt predicates.** Each policy predicate (`MaxValue`/`MinValue` on the unsigned value) must hold. Otherwise return `CKR_ACTION_PROHIBITED`.
  9. **Rule 5, recipient.** An all-zero recipient is allowed only if `recipient_only` is false. A non-zero recipient must be in the policy `recipients`. Otherwise return `CKR_ACTION_PROHIBITED`.
  10. **Release and audit.**
- **Every policy refusal returns the same `CKR_ACTION_PROHIBITED`.** The reason goes only to the audit log, so the token never says which rule failed. Refusal and release take the same code path up to the final output step.
- **Output to the owner.** One byte for the type (`0` = `FheBool`, `1` = `FheUint`), then a 2-byte big-endian width in bits, then the value as unsigned little-endian bytes of width ⌈bits/8⌉ (`FheBool` is 1 byte, 0 or 1).
- **Output to a recipient.** The same plaintext, sealed inside the token with HPKE to the recipient's ML-KEM-768 certificate. The suite is the Key Replication Interface's: KEM `0x0041`, HKDF-SHA384, AES-256-GCM. `info` is the DER of `{lineage, decryptPolicyId, recipient, transactionCounter}`, and `aad` is the 3-byte type header. Output is `enc ‖ ciphertext`. Encapsulation randomness is engine-generated, and test hooks are absent in shipped builds (F5).
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

### 6.4 Counter

The counter is a per-object count of decrypt calls, released or refused, kept in an engine-private attribute. It is reserved durably before any decryption work, in the same atomic snapshot commit as the audit record.

A replicated object starts its own counter at 0, so clones do not share a global budget (HSM plan §3). It resists reuse within the current state, but cannot resist the host rolling the whole token snapshot back; that is disclosed.

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

## 11. Open points for review

- **Output encoding.** Is §5.3's 3-byte header plus little-endian value the right owner format, or should it be DER for symmetry with the policy?
- **Compressed lists.** Should version 1 refuse compressed ciphertext lists outright (simpler type gate), or keep them policy-gated as P1's `FheType.compressed_allowed` allows?
- **Server-key manifest.** Who signs it (§5.2)? The proposal is an application ML-DSA-65 key through `C_Sign`. The alternative is the HSM plan's package-signing function key through a vendor operation, which would need its own allocation.
- **Retiring the P1 placeholder hash.** P1 fixtures become unimportable in P2 (§4). Confirm that is acceptable, since they are test-only.

## 12. Revision history

| Rev | Date | Change |
|---|---|---|
| 1 | 2026-10-03 | First normative draft, aligned with authority §1.4.5 and FHE P1 at `f48a040d` |
