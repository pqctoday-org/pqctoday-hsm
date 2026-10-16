# FHE key custody over KMIP: interface `PQCTODAY_FHE_1_0`

Plan D02387 (pqctoday-plan), work package B. Source: `src/ops/fhe_bridge.rs`. Python client:
`python-client/src/pqctoday_kmip/fhe.py`.

## What it is

A named PKCS#11 interface carried by KMIP 3.0 Operation PKCS_11 (0x33), the same pattern as the replication
interfaces (`src/ops/replication_bridge.rs`). **One KMIP function is one PKCS#11 call** (owner decision
2026-10-15): this is PKCS#11 over TTLV; a KMIP-level abstraction is a later step.

The default engine build carries **CKKS custody only**. TFHE seeds need an engine built with `educational-fhe`
(TFHE-rs 1.8.1: **non-commercial use only**; owner decision F10).

## Enabling it

Every native server build compiles the interface (`fhe-custody` is part of the `native` feature). It is served only
when the server starts with:

```sh
pqctoday-kmip --fhe-custody --engine-store <dir> [--fhe-so-pin-file <root-only file>] ...
```

`--fhe-custody` selects the engine's replication profile, whose identifiers are the RFC 5612 documentation OIDs
(owner decision F11: this profile may ship). Without `--fhe-so-pin-file` the two security-officer functions are
refused.

## Roles: the PKCS#11 v3.2 security model, as for every other key

| Who | May call | How the server runs it |
|---|---|---|
| any client the server accepts for other key operations | functions 1 to 6 | in the PKCS#11 **normal user** session the server holds for that client (`resolve_tenant_session`), exactly like KMIP Create or Decrypt on other keys |
| the token's security officer: client certificate CN `replication-admin` (one SO identity for the replication admin interface and this one) | functions 7 and 8 only | in a fresh application context with a real SO login (`--fhe-so-pin-file`) |

There is no FHE-specific user role (owner decision 2026-10-15). What one key allows is set by its attributes and by
the policies the security officer enrolled:

- FHE seeds are `CKA_PRIVATE`, `CKA_SENSITIVE`, not extractable, not copyable, not modifiable and **not destroyable**
  (`CKA_DESTROYABLE = FALSE`): the token refuses `C_DestroyObject` on a seed for every caller. The security officer's
  signed `[7] destroyFheSeed` is the only way to remove one (owner decision 2026-10-15).
- The decryption policy (enrolled by the SO, signed `[5] enrollFheDecryptPolicy`) limits the output types, the number
  of decryptions and the release recipients (`[6] enrollFheRecipient`). The engine enforces it in `C_Decrypt`.

## Functions

`Function` is the KMIP PKCS#11 Function value: the **1-based** offset (KMIP 3.0 §11.39). Every DER input is decoded
strictly (canonical re-encoding, nothing trailing). Objects are named by `CKA_UNIQUE_ID` (36 bytes).

| Function | PKCS#11 call | Input | Output |
|---|---|---|---|
| 1 | `C_GenerateKey(CKM_PQCTODAY_FHE_KEY_GEN)` | `GenerateKeyV1` | the new seed's unique ID |
| 2 | `C_DeriveKey(CKM_PQCTODAY_FHE_DERIVE_PUBLIC)` | `DeriveKeyV1` | the new public session object's unique ID |
| 3 | `C_GetAttributeValue` | `GetAttributeValueV1` | `AttributesV1`, with the engine's return code |
| 4 | `C_DestroyObject` | unique ID | empty |
| 5 | `C_DecryptInit(CKM_PQCTODAY_FHE_DECRYPT)` | `DecryptInitV1` | empty |
| 6 | `C_Decrypt` (single part) | `DecryptV1` | the data; for a size query, its length as a DER INTEGER |
| 7 | `C_PQCTODAY_AdminIssueNonce` | empty | 32-byte nonce |
| 8 | `C_PQCTODAY_AdminExecute` | `AdminSignedRequest` carrying `[5] enrollFheDecryptPolicy`, `[6] enrollFheRecipient` or `[7] destroyFheSeed` | `AdminReceipt` |

```asn1
GenerateKeyV1 ::= SEQUENCE {
  paramSet INTEGER,                          -- CKKS registry ID (2-4; 0x8002 test), TFHE 1 (opt-in builds)
  replicationPolicyId OCTET STRING (SIZE(48)),
  decryptPolicyId OCTET STRING (SIZE(48)),
  label OCTET STRING (SIZE(0..256)),         -- CKA_LABEL; empty = not set
  id OCTET STRING (SIZE(0..256)) }           -- CKA_ID; empty = not set

DeriveKeyV1 ::= SEQUENCE {
  baseKey UTF8String (SIZE(36)),             -- the seed
  version INTEGER (1 | 2),                   -- CKM_PQCTODAY_FHE_DERIVE_PUBLIC parameter version
  kind INTEGER, key INTEGER, digit INTEGER,
  fromLimb INTEGER, toLimb INTEGER }         -- version 1 (TFHE) uses kind only; the rest must be 0

GetAttributeValueV1 ::= SEQUENCE {
  object UTF8String (SIZE(36)),
  types SEQUENCE SIZE(1..16) OF INTEGER }

AttributesV1 ::= SEQUENCE OF SEQUENCE {
  type INTEGER,
  value OCTET STRING OPTIONAL }              -- absent = CK_UNAVAILABLE_INFORMATION (sensitive, or no such attribute)

DecryptInitV1 ::= SEQUENCE {
  key UTF8String (SIZE(36)),
  recipient OCTET STRING (SIZE(48)) }        -- enrolled recipient ID; 48 zero bytes = owner release

DecryptV1 ::= SEQUENCE {
  ciphertext OCTET STRING,                   -- at most 4 MiB
  outputLen INTEGER }                        -- the caller's buffer size; 0 = size query (pData == NULL)
```

`AdminSignedRequest` and `AdminReceipt` are the replication admin structures (`rust/src/replication/admin.rs`); the
security officer builds and signs requests with `replication::admin_host` and checks receipts with
`replication::host_verify::verify_admin_receipt`. `destroyFheSeed` names the seed by its lineage
(`CKA_PQCTODAY_FHE_LINEAGE_ID`, 32 bytes); its receipt's output is that lineage.

## The usual sequences

- **Export one piece of public material:** 2 `C_DeriveKey` → 3 `C_GetAttributeValue(CKA_VALUE)` → 4
  `C_DestroyObject`. A CKKS key set is exported piece by piece and closed by the token-signed manifest (version 2,
  kind 6). A TFHE export is kind 1 (compressed server key) and kind 2 (compact public key), then kind 3 (version 1):
  the token-signed manifest over the SHA-256 of the two objects this session exported, signed by the device's
  receipt-signing key with its chain (`replication::fhe_tfhe::verify_tfhe_manifest` checks it against the
  manufacturing root).
- **Decrypt one ciphertext** (PKCS#11 single-part; owner decision 2026-10-15): 5 `C_DecryptInit` → 6 `C_Decrypt` with
  `outputLen` 0 (size query; nothing is decrypted or counted) → 6 `C_Decrypt` with that size. A buffer that is too
  small gets `CKR_BUFFER_TOO_SMALL` and the operation stays active; any other outcome ends it. Ciphertexts are
  16 KB (TFHE boolean) to 2 MB (CKKS registry 3), so one message always carries one. `C_DecryptUpdate` /
  `C_DecryptFinal` are not offered for this mechanism.

## What the bridge adds because operation state spans KMIP requests

KMIP closes the connection after each request, and in the default tenancy mode every client shares one engine
session. So the bridge:

- binds a pending decryption to the client that started it (TLS client-certificate hash, else its authenticated
  name): another client gets `CKR_OPERATION_ACTIVE` from `C_DecryptInit` and `CKR_OPERATION_NOT_INITIALIZED` from
  `C_Decrypt`, as if it were another session;
- cancels a pending decryption after **2 minutes** (owner decision 2026-10-15);
- destroys a public object created by `C_DeriveKey` and not destroyed within **10 minutes** (owner decision
  2026-10-15);
- serialises all calls on the interface.

## Bounds

- An incoming request frame is at most 16 MiB (listener cap). Replies may be larger: `C_GetAttributeValue` and
  `C_Decrypt` refuse an output above 48 MiB with `CKR_DATA_LEN_RANGE` (the TFHE compressed server key is about
  29 MiB and is read in one call; owner decision 2026-10-15).
- At most 16 attribute types per `C_GetAttributeValue`.

## Return codes added by the bridge

| Code | When |
|---|---|
| `CKR_FUNCTION_NOT_SUPPORTED` | the server was not started with `--fhe-custody`; or function 8 carries a non-FHE admin operation |
| `CKR_ARGUMENTS_BAD` | function value 0 or above 8; a unique ID that is not 36 bytes; an unexpected input on 7 or 8 |
| `CKR_DATA_INVALID` | input not strict DER, wrong field sizes, input over the bound |
| `CKR_USER_TYPE_INVALID` | an SO function from another identity, or a user function from the SO identity |
| `CKR_USER_NOT_LOGGED_IN` | no engine session for the client; or no SO PIN file configured (functions 7 and 8) |
| `CKR_OPERATION_ACTIVE` / `CKR_OPERATION_NOT_INITIALIZED` | a decryption pending for another client (see above) |
| `CKR_DATA_LEN_RANGE` | an output above 48 MiB |

Every other code comes from the engine.
