# PQCToday Key Replication Interface 1.0

Status: **K0B working specification, revision 3 (review amendments E-01…E-14 and R2-01…R2-12, see §14);
educational OID profile defined; not a production interface**
Date: 2026-10-02
Engine scope: `softhsmrustv3` only

This document specifies the proposed `PQCTODAY_KEY_REPLICATION_1_0` interface selected by owner
decision 10 in the HSM hierarchy plan. It is deliberately separate from the OASIS
`CK_FUNCTION_LIST_3_2`. It does not claim that PKCS #11 standardizes cloning, and it never changes
the meaning of `CKA_EXTRACTABLE` or the standard wrapping functions.

The interface must not be advertised by a normal release build until the allocation and review
gates in §12 close. Test implementations may compile it behind an explicit non-default educational
feature and must identify every resulting artefact as educational and non-production.

## 1. Design invariants

1. A replicated source key remains `CKA_SENSITIVE=true`, `CKA_EXTRACTABLE=false`,
   `CKA_COPYABLE=false` and `CKA_MODIFIABLE=false` throughout the operation.
2. Replication is opt-in at key creation/import through an immutable policy binding. Existing keys
   cannot be made replicable later.
3. `C_WrapKey`, `C_WrapKeyAuthenticated`, `C_CopyObject` and `C_DeriveKey` do not implement or
   bypass this protocol.
4. Only AES secret keys and the private halves of ML-KEM-768 and ML-DSA-65 key pairs are eligible in
   version 1. Stateful signature keys, device/function identity keys and threshold shares are
   excluded.
5. Package creation and import are the normative primitives. `CloneKey` is only a same-module
   convenience call over those primitives.
6. Source and destination authenticate a pure-PQC manufacturing → device → function hierarchy.
   ML-DSA-65 signs credentials, evidence, packages and receipts; ML-KEM-768 establishes the package
   protection key; AES-256-GCM protects the payload.
7. A package is recipient-, policy-, operation- and transaction-bound and is single-use at its
   destination. There is no silent replay-ledger eviction.
8. No raw key material, plaintext payload, function private key or transport secret crosses the
   interface.

## 2. Discovery and function list

The exact, NUL-terminated interface name is:

```text
PQCTODAY_KEY_REPLICATION_1_0
```

`C_GetInterfaceList` returns the standard PKCS #11 interfaces followed by this interface when, and
only when, the complete production feature is enabled. `C_GetInterface` requires the exact name,
version `{1,0}` and supported flags. A NULL name continues to select the highest standard
`PKCS 11` interface, never this vendor interface.

The `CK_INTERFACE.pFunctionList` member points to this native-layout structure:

```c
typedef struct PQCTODAY_KEY_REPLICATION_FUNCTION_LIST_1_0 {
    CK_VERSION version; /* { 1, 0 } */
    CK_RV (*C_PQCTODAY_CreateReplicationPackage)(
        CK_SESSION_HANDLE hSourceSession,
        CK_OBJECT_HANDLE hSourceKey,
        CK_BYTE_PTR pRequest,
        CK_ULONG ulRequestLen,
        CK_BYTE_PTR pPackage,
        CK_ULONG_PTR pulPackageLen);
    CK_RV (*C_PQCTODAY_ImportReplicationPackage)(
        CK_SESSION_HANDLE hDestinationSession,
        CK_BYTE_PTR pPackage,
        CK_ULONG ulPackageLen,
        CK_ATTRIBUTE_PTR pTemplate,
        CK_ULONG ulAttributeCount,
        CK_OBJECT_HANDLE_PTR phInstalledKey,
        CK_BYTE_PTR pReceipt,
        CK_ULONG_PTR pulReceiptLen);
    CK_RV (*C_PQCTODAY_CloneKey)(
        CK_SESSION_HANDLE hSourceSession,
        CK_OBJECT_HANDLE hSourceKey,
        CK_SESSION_HANDLE hDestinationSession,
        CK_BYTE_PTR pRequest,
        CK_ULONG ulRequestLen,
        CK_ATTRIBUTE_PTR pTemplate,
        CK_ULONG ulAttributeCount,
        CK_OBJECT_HANDLE_PTR phInstalledKey,
        CK_BYTE_PTR pReceipt,
        CK_ULONG_PTR pulReceiptLen);
} PQCTODAY_KEY_REPLICATION_FUNCTION_LIST_1_0;
```

The structure is naturally aligned exactly as this repository's native PKCS #11 ABI is. No
structure pointer is serialized into a request, package or receipt. WASM exports the three calls as
JS-shim functions and exposes the same version header convention used by its standard interface.

Directly exported C symbols are optional aliases. Discovery through `C_GetInterface*` is normative.

## 3. Operation semantics

### 3.1 CreateReplicationPackage

The request is bounded DER defined in §5. It includes the destination recovery certificate chain,
fresh destination evidence, two challenges, operation, transaction identifier and requested policy.
The source engine:

1. validates the session, user role, source visibility and supported key class;
2. verifies immutable replication eligibility and the operation against the enrolled policy;
3. verifies the destination chain, purpose, domain, evidence, challenges, validity and revocation;
4. proves the requested destination policy is equal to or stricter than the source policy;
5. serializes the allowlisted key attributes and required paired public value;
6. HPKE-seals the payload to the destination ML-KEM-768 recovery key;
7. signs the canonical package with the source package-signing ML-DSA-65 function key; and
8. returns only the DER package.

With `pPackage == NULL`, the call validates pointer/length syntax and computes the exact encoded
length without randomness, cryptographic operation, authorization consumption or ledger mutation.
It writes that length to `*pulPackageLen`. A non-NULL buffer smaller than the exact length returns
`CKR_BUFFER_TOO_SMALL` and performs no cryptography. The first call with a sufficient buffer creates
and caches the package by transaction ID within the source slot (E-07). A retry with the
byte-identical request and the same source key returns the byte-identical cached package. A
different request, or a different source key, under the same transaction ID is refused. The
same successful commit consumes the source challenge reservation (§5.1) and debits the source
key's replica budget (§8).

### 3.2 ImportReplicationPackage

The destination engine:

1. parses all DER under the limits in §10 before allocation;
2. verifies its recipient binding, transaction ID and operation;
3. verifies the source hierarchy, function purpose, evidence, package signature, time and
   revocation policy before decapsulation;
4. checks the package policy and caller template are equal to or stricter than the source policy,
   which must itself be enrolled at the destination (R2-05);
5. rejects an already consumed transaction or conflicting in-progress transaction;
6. reserves the transaction durably, decapsulates and decrypts inside the engine;
7. validates the decrypted key type, public association and authenticated attributes;
8. atomically installs one protected private/secret key and its paired public object when required;
9. commits consumption and a signed receipt in the same durable transaction; and
10. returns the new private/secret handle and receipt.

With `pReceipt == NULL`, the function reports the exact fixed receipt length and creates no object,
consumption record or cryptographic output. `phInstalledKey` must be NULL on this sizing call and
non-NULL on the execution call. A too-small receipt buffer fails before reservation.

The ledger entry has two states (E-09). **Reserved** is written durably before decapsulation, and
an exact retry of a reserved transaction re-runs the whole import from step 1. **Committed** is
written in the same atomic commit that installs the key and stores the receipt. So a crash before
the commit leaves the package importable, and a crash after it leaves a recoverable receipt. A
reserved entry blocks any different package for that transaction ID. Committed entries and their
receipts are retained independently of the installed object; deleting the replica makes a later
retry terminal, never re-importable.

The recipient binding (step 2) accepts the token's current recovery key or a retained, rotated-out
one, so a package sealed before a recovery-key rotation still imports (§10a). For ML-KEM-768 and
ML-DSA-65 the installed private key has a public partner. It is a token object with the same
`CKA_ID`, label and lineage, installed in the same commit (E-11).

An exact retry of a package whose transaction already committed is the recovery operation: it
returns the existing installed object's current-session handle and the byte-identical stored
receipt without decapsulation, decryption or a second install. A different package with the same
transaction ID, or a committed ledger entry whose object/receipt cannot be authenticated, returns a
terminal error and never clears consumption.

### 3.3 CloneKey

`CloneKey` is available only when one loaded module can address both sessions. It performs the same
create/import protocol in memory, verifies the returned receipt, and returns the installed handle
and receipt. Its externally observable installed attributes, provenance, transaction consumption and
receipt are identical to explicit create/import. It defines no second wire format and does not copy
an object directly in the object table. The receipt is verified after the destination commit, so a
verification failure is reported as `CKR_DEVICE_ERROR` with the replica already installed (R2-08).

Sizing and buffer rules match the import call. A source and destination session for the same slot is
allowed only if the policy explicitly permits same-device redundancy; otherwise it is refused.

## 4. Role and object model

- The SO enrolls manufacturing roots, signed revocation state, domain membership, peer allowlists
  and immutable replication policies. The SO cannot use a user's private key.
- A logged-in user creates/imports an eligible key under a pre-enrolled policy and authorizes each
  create/import/clone operation.
- Trust anchors, policies and revocation data are public token objects but SO-created,
  `CKA_MODIFIABLE=false`, `CKA_COPYABLE=false` and `CKA_DESTROYABLE=false` except through the
  separately specified rotation ceremony.
- Device-issuer, peer-authentication, attestation, package-signing, recovery-recipient and
  receipt-signing keys are non-replicable function keys with one immutable purpose each. Their
  mechanism allowlists contain only that purpose.
- An installed clone receives a fresh `CKA_UNIQUE_ID`. Standard history attributes report import,
  not local generation. Read-only vendor provenance records the source lineage and transaction.

The following public vendor attributes were reserved by the private authority in local commit
`36340f93` (not yet on its `origin/main`):

| Value | Symbol | Applies to | Meaning |
|---|---|---|---|
| `0x80000108` | `CKA_PQCTODAY_REPLICATION_POLICY_ID` | eligible key | immutable 48-byte SHA-384 digest of enrolled canonical policy DER |
| `0x80000109` | `CKA_PQCTODAY_REPLICATION_LINEAGE_ID` | eligible/restored key | immutable lineage shared by protected replicas |
| `0x8000010A` | `CKA_PQCTODAY_REPLICATION_PROVENANCE` | restored key | engine-produced source/device/transaction record |
| `0x8000010B` | `CKA_PQCTODAY_FUNCTION_PURPOSE` | function key/certificate | device issuance, peer authentication, key attestation, package signing, recovery recipient or receipt signing |

The same authority commit reserves these constrained public mechanisms. They remain absent from the
engine mechanism list until their implementing phase lands:

| Value | Symbol | Phase | Constraint |
|---|---|---|---|
| `0x80000016` | `CKM_PQCTODAY_ISSUE_FUNCTION_CERTIFICATE` | K2 | device issuer validates the approved function-certificate profile before ML-DSA-65 signing |
| `0x80000017` | `CKM_PQCTODAY_SIGN_KEY_ATTESTATION` | K3 | attestation function recomputes engine-owned claims and challenge before ML-DSA-65 signing |

The reservations do not authorize advertisement or production use. Constants and fixtures must pin
the authority commit that lands upstream and remain behind the K2–K4 gates.
The allocation request is `docs/proposals/pqctoday-key-replication-allocation-request.md`.

### 4.1 OID profiles

The selected local educational profile uses the RFC 5612 documentation PEN. Its fixed root is
`1.3.6.1.4.1.32473.20261002`; suite OID is `.1.1`, and function-purpose OIDs are `.2.1` through
`.2.6` in this order: device issuer, key attestation, package signing, recovery recipient, peer
authentication and receipt signing. The authoritative full values are recorded in
`pqctoday-priv/docs/platform/data/oid-allocation-registry.md` at
`f2e5cfa175dba803dfafbe8fd1c78946658e9db0`.

These identifiers are deliberately fake. The educational profile must be selected explicitly,
must not install a root in an external trust store or use a network peer, and must label adjacent
UI/export metadata `PQCTODAY EDUCATIONAL TEST ONLY`. Selecting a profile is configuration, never an
inference from an input OID. Every non-educational validator rejects the complete
`1.3.6.1.4.1.32473` subtree before certificate or evidence trust evaluation. Production OIDs remain
unassigned and cannot be aliased to these values.

### 4.2 Certificate and revocation profile

Every signature certificate uses ML-DSA-65 with absent `AlgorithmIdentifier.parameters` per RFC
9881. The ML-KEM recovery certificate uses ML-KEM-768 with absent parameters and RFC 9935 key-usage
rules. Serial numbers are non-zero, positive, unpredictable 128-bit values. Chains carried by the
protocol contain the function leaf followed by its device issuer; they exclude the already enrolled
manufacturing trust anchor.

| Certificate | Basic constraints | Critical key usage | Critical extended purpose |
|---|---|---|---|
| Test manufacturing root | `cA=TRUE`, `pathLenConstraint=1` | `keyCertSign`, `cRLSign` | none |
| Device issuer | `cA=TRUE`, `pathLenConstraint=0` | `keyCertSign`, `cRLSign` | none; the token object carries function purpose 1 |
| Peer authentication | `cA=FALSE` | `digitalSignature` only | peer-authentication OID |
| Key attestation | `cA=FALSE` | `digitalSignature` only | the final standards OID when assigned, otherwise the authority-allocated attestation OID |
| Package signing | `cA=FALSE` | `digitalSignature` only | package-signing OID |
| Recovery recipient | `cA=FALSE` | `keyEncipherment` only | recovery-recipient OID |
| Receipt signing | `cA=FALSE` | `digitalSignature` only | receipt-signing OID |

All function leaves also carry the matching immutable `CKA_PQCTODAY_FUNCTION_PURPOSE`; a valid EKU
without the matching token attribute, or vice versa, is refused. Unrecognized critical extensions,
mixed classical/PQC chains, a CA bit on a function leaf, and any extra key-usage bit are refused.

Revocation follows X.509 issuer boundaries. The test manufacturing root publishes an ML-DSA-65
CRL for device certificates; each device issuer publishes an ML-DSA-65 CRL for its function
certificates. Both require `thisUpdate`, `nextUpdate`, monotonically increasing `CRLNumber`, matching
issuer/authority identifiers and a valid signature. Verification uses the owner-approved host clock
and fails closed when the applicable current CRL, time, chain or trust anchor is unavailable. This
software-token profile makes no secure-time or rollback-resistance claim.

## 5. DER request and suite registry

All structures use DER with definite lengths and the smallest legal INTEGER encoding. Strings are
UTF8String and identifiers are fixed-size OCTET STRINGs. Duplicate or unknown critical fields are
rejected. Version 1 has one suite and no algorithm agility inside a suite.

```asn1
ReplicationRequest ::= SEQUENCE {
  version             INTEGER (1),
  operation           ENUMERATED { liveClone(0), offlineBackup(1), restore(2) },
  suite               OBJECT IDENTIFIER,       -- selected profile's suite OID
  transactionID       OCTET STRING (SIZE(32)),
  sourceChallenge     OCTET STRING (SIZE(32)),
  destinationChallenge OCTET STRING (SIZE(32)),
  domainID            OCTET STRING (SIZE(32)),
  requestedPolicy     OCTET STRING (SIZE(48)), -- SHA-384 digest
  recipientChain      SEQUENCE SIZE(2) OF Certificate,
  recipientEvidence   Evidence
}
```

The request is produced by the **destination** engine (E-04/E-07). The destination generates the
uniformly random 32-byte `transactionID` and `destinationChallenge`, reserves both durably, and
signs `recipientEvidence`. The source treats every field as untrusted until §3.1 step 3 verifies
it.

The suite fixes ML-KEM-768, HKDF-SHA384, AES-256-GCM and ML-DSA-65. Downgrade, alternate suite or
hybrid/classical fallback is refused. The local educational profile uses
`1.3.6.1.4.1.32473.20261002.1.1`. A production profile requires a separately allocated OID; no
validator may treat the educational and production suite identifiers as aliases.

### 5.1 Challenge and evidence ceremony

Each challenge is issued and durably **reserved** by the engine that will verify it (E-04), never by
the peer that signs it:

- the source issues `sourceChallenge` (one use, five-minute lifetime); and
- the destination issues `destinationChallenge` together with the transaction ID, bound to the
  operation and the requested policy.

A destination reservation's lifetime is the freshness bound applied at import (E-14). It is five
minutes for `liveClone` and `restore`, and the requested policy's `notAfter` for `offlineBackup`,
whose package is imported later. A verifier refuses a challenge it has no unconsumed, unexpired
reservation for. Plain `C_GenerateRandom` output is not a valid challenge. In the educational
implementation these issuance calls are engine-level operations outside the three-function vendor
list.

Destination evidence in the request binds, at minimum, the destination device identity, recovery
recipient SPKI, domain ID, transaction ID, requested policy digest and `sourceChallenge`. Source
evidence placed in the protected header binds, at minimum, the source device identity, source key
unique ID and SPKI/type, lineage ID, source policy digest, transaction ID and
`destinationChallenge`. Each engine recomputes its engine-owned claims and byte-compares the
challenge before its purpose-constrained attestation key signs the canonical evidence.

Evidence is signed over (E-01):

```text
"PQCToday Key Replication Evidence 1.0" || 0x00 || role || DER(TbsEvidence)
```

with an empty ML-DSA context, where `role` is one octet: source 0, destination 1, general key
attestation 2. Evidence verified in one role never verifies in another. The claim set is the fixed
profile in `docs/k2-k4-replication-implementation-notes-2026-10-02.md` §E (E-02). There are three
elements in fixed order with typed claims in fixed order, and absent optional claims are omitted.
Verifiers decode strict DER, require the received TBS bytes to equal the canonical re-encoding of
the decoded claims, and verify the signature over those exact bytes.

`deviceID` is SHA-256 over the DER `SubjectPublicKeyInfo` of the device-issuer certificate (E-03).
Every device claim must equal the device of the chain that signed it. Within one transaction, the
recovery-recipient chain and the destination evidence must name the same device, as must the
package-signing chain and the source evidence.

Production evidence uses one signature block. Its signer identifier carries the attestation
function certificate, and the evidence `intermediateCertificates` field carries exactly its device
issuer certificate; the enrolled manufacturing root is excluded. A bare SPKI signer identifier is
permitted only in documentation-OID K0A fixtures, never in production evidence.

The verifier rejects an all-zero challenge, a challenge used by another transaction, evidence
outside its configured freshness window, and any evidence whose transaction, domain, policy or key
binding differs from the request/package. Successful create/import durably associate the verified
challenge with the transaction; exact retries use the cached result, while cross-transaction reuse
is refused. The software-token rollback limitation in the parent plan remains explicit: without K6
hardware-backed monotonic state, a host administrator can roll back both the challenge ledger and
token storage.

## 6. Package, signed bytes and HPKE binding

```asn1
ReplicationProtectedHeader ::= SEQUENCE {
  version           INTEGER (1),
  operation         ENUMERATED,
  suite             OBJECT IDENTIFIER,
  transactionID     OCTET STRING (SIZE(32)),
  domainID          OCTET STRING (SIZE(32)),
  sourceUniqueID    UTF8String (SIZE(36)),
  lineageID         OCTET STRING (SIZE(32)),
  sourcePolicy      OCTET STRING (SIZE(48)),
  destinationPolicy OCTET STRING (SIZE(48)),
  recipientKeyHash  OCTET STRING (SIZE(48)),
  transferredBudget INTEGER (0..65535),        -- E-12, see §8
  sourceChain       SEQUENCE SIZE(2) OF Certificate,
  sourceEvidence    Evidence,
  typeExtensionHash OCTET STRING (SIZE(48))
}

ReplicationPackageTBS ::= SEQUENCE {
  header       ReplicationProtectedHeader,
  encapsulated OCTET STRING,
  ciphertext   OCTET STRING
}

ReplicationPackage ::= SEQUENCE {
  tbs          ReplicationPackageTBS,
  signatureAlgorithm AlgorithmIdentifier,
  signature    BIT STRING
}

ReplicatedAttribute ::= SEQUENCE {
  type          INTEGER (0..4294967295),
  value         OCTET STRING
}

ReplicatedKeyPayload ::= SEQUENCE {
  version       INTEGER (1),
  keyClass      ENUMERATED { secretKey(0), privateKey(1) },
  keyType       INTEGER (0..4294967295),
  protectedValue OCTET STRING,
  pairedPublic  [0] EXPLICIT OCTET STRING OPTIONAL,
  attributes    SEQUENCE SIZE(1..64) OF ReplicatedAttribute,
  typeExtension [1] EXPLICIT OCTET STRING OPTIONAL
}
```

Let `H = DER(ReplicationProtectedHeader)`. HPKE uses:

```text
info = "PQCToday Key Replication 1.0" || 0x00 || SHA-384(H)
aad  = H
```

HPKE runs in base mode with the draft-ietf-hpke-pq-05 identifiers KEM `0x0041` (ML-KEM-768),
KDF `0x0002` (HKDF-SHA384) and AEAD `0x0002` (AES-256-GCM), sequence number 0 (E-06). The importer
refuses an `encapsulated` value that is not exactly 1,088 bytes, and a `ciphertext` shorter than 16
bytes or longer than the plaintext bound plus 16, before any cryptographic operation.

The exact ML-DSA-65 input is:

```text
"PQCToday Key Replication Package 1.0" || 0x00 || DER(ReplicationPackageTBS)
```

ML-DSA context is empty. AlgorithmIdentifier parameters are absent as required by RFC 9881. The
signature covers the encapsulation and ciphertext as well as every routing/security field.

`recipientKeyHash` is SHA-384 over the recipient recovery certificate's DER
`SubjectPublicKeyInfo`. `typeExtensionHash` is SHA-384 over the exact
`typeExtension` OCTET STRING contents, or SHA-384 of the empty string when the field is absent.

The HPKE plaintext is exactly `DER(ReplicatedKeyPayload)`. Attribute entries are strictly increasing
by unsigned `type`, unique, and drawn from the per-key-class allowlist; caller-supplied order is
irrelevant. The payload never contains `CKA_UNIQUE_ID`, standard history attributes, replication
provenance, device/function private keys or engine-private state. For ML-KEM-768 and ML-DSA-65,
`pairedPublic` is mandatory and contains the algorithm's canonical raw public-key encoding; for AES
it is absent. `protectedValue` contains the engine's canonical private/secret encoding and exists
only inside the authenticated ciphertext. The destination reconstructs all server-managed and
history attributes rather than accepting them from this sequence.

Version 1 accepts exactly these payload encodings:

| Key | `protectedValue` | `pairedPublic` |
|---|---:|---:|
| AES-128/192/256 | raw 16/24/32-byte key | absent |
| ML-KEM-768 | FIPS 203 2,400-byte decapsulation key | FIPS 203 1,184-byte encapsulation key |
| ML-DSA-65 | FIPS 204 4,032-byte signing key | FIPS 204 1,952-byte verification key |

The importer performs the engine's full private/public consistency checks before installation.
The installed replica carries `CKA_PQCTODAY_REPLICATION_PROVENANCE` (E-12):

```asn1
ReplicationProvenance ::= SEQUENCE {
  version           INTEGER (1),
  operation         ENUMERATED { liveClone(0), offlineBackup(1), restore(2) },
  sourceDeviceID    OCTET STRING (SIZE(32)),
  sourceUniqueID    UTF8String (SIZE(36)),
  lineageID         OCTET STRING (SIZE(32)),
  transactionID     OCTET STRING (SIZE(32)),
  packageHash       OCTET STRING (SIZE(48)),
  committedAt       GeneralizedTime
}
```

Its standard history is `CKA_LOCAL`, `CKA_ALWAYS_SENSITIVE` and `CKA_NEVER_EXTRACTABLE` false, and
`CKA_KEY_GEN_MECHANISM` = `CK_UNAVAILABLE_INFORMATION`.
`CKA_SEED`, even when the source object retained one, is not replicated: the canonical expanded
private key above is sufficient and avoids creating a second accepted payload representation.

## 7. Receipt

The destination function key signs:

```asn1
ReplicationReceiptTBS ::= SEQUENCE {
  version             INTEGER (1),
  suite               OBJECT IDENTIFIER,
  transactionID       OCTET STRING (SIZE(32)),
  packageHash         OCTET STRING (SIZE(48)),
  destinationDeviceID OCTET STRING (SIZE(32)),
  installedUniqueID   UTF8String (SIZE(36)),
  lineageID           OCTET STRING (SIZE(32)),
  installedPolicy     OCTET STRING (SIZE(48)),
  committedAt         GeneralizedTime,
  receiptSignerChain  SEQUENCE SIZE(2) OF Certificate
}

ReplicationReceipt ::= SEQUENCE {
  tbs                 ReplicationReceiptTBS,
  signatureAlgorithm  AlgorithmIdentifier,
  signature            BIT STRING
}
```

The signature input is
`"PQCToday Key Replication Receipt 1.0" || 0x00 || DER(ReplicationReceiptTBS)`.
The receipt container uses the same AlgorithmIdentifier/signature shape as the package. Receipts are
retained with the consumption ledger according to the configured audit-retention policy.
`packageHash` is SHA-384 over the complete `DER(ReplicationPackage)` received by the destination.
`receiptSignerChain` contains the destination receipt-signing function leaf followed by its device
issuer and excludes the enrolled manufacturing root. `destinationDeviceID` is derived as in §5.1,
and a verifier refuses a receipt whose `destinationDeviceID` differs from the device of
`receiptSignerChain` (E-03). The verifier is also given the request the package answered. It
requires the signer's device to be the request's recipient device, with a recipient key hash equal to
the package's, and the receipt's transaction, lineage and `installedPolicy` to equal the package
header's `transactionID`, `lineageID` and `destinationPolicy` (R2-09). The verifier checks the chain, critical
receipt-signing purpose, validity and applicable CRLs before accepting the receipt signature.

## 8. Policy ordering and templates

```asn1
ReplicationPolicy ::= SEQUENCE {
  version             INTEGER (1),
  domainID            OCTET STRING (SIZE(32)),
  operations          BIT STRING (SIZE(3)), -- liveClone, offlineBackup, restore
  allowedPeerDeviceIDs SEQUENCE SIZE(1..64) OF OCTET STRING (SIZE(32)),
  notBefore           GeneralizedTime,
  notAfter            GeneralizedTime,
  maxReplicas         INTEGER (1..65535),
  allowedMechanisms   SEQUENCE SIZE(0..64) OF INTEGER (0..4294967295),
  allowSameDevice     BOOLEAN DEFAULT FALSE,
  typeConstraintHash  OCTET STRING (SIZE(48))
}
```

Device IDs and mechanism IDs are strictly increasing unsigned byte/numeric order respectively,
with no duplicates. Times are DER canonical UTC `GeneralizedTime` values with seconds and no
fraction. An empty `allowedMechanisms` sequence permits no ordinary key operation; it never means
“all.” `typeConstraintHash` is SHA-384 over the per-key profile's canonical constraint DER, or
SHA-384 of the empty string when that profile defines no extra constraint. The policy identifier is
`SHA-384(DER(ReplicationPolicy))`.

Policy equality is digest equality over canonical policy DER. “Stricter” is a fieldwise partial
order: the destination may remove operations/peers/mechanisms, shorten validity and lower
`maxReplicas`; it may not add operations/peers/mechanisms, lengthen validity, increase quotas, make
the object extractable/copyable/modifiable, or remove a source restriction. Incomparable policies
are refused.

Concretely, a destination policy is equal or stricter only when its domain and
`typeConstraintHash` are equal, its operations/peer/mechanism sets are subsets, its validity
interval is contained within the source interval, `maxReplicas` is no greater, and
`allowSameDevice=TRUE` only when the source also permits it. Consumption counters are durable state
outside the immutable policy and cannot be reset by selecting another equal policy.

`maxReplicas` is a lineage-wide bound, enforced by conserving budget rather than by global
coordination (E-12). A key bound at generation starts with budget `maxReplicas`. An export needs
budget ≥ 1. It transfers `t` to the copy in the signed `transferredBudget` field and leaves the
source with `budget − 1 − t`. The destination chooses the requested policy, so it must not choose
`t` (R2-10). Version 1 fixes `t = min(1, destinationPolicy.maxReplicas, budget − 1)` for
`offlineBackup`, so the backup HSM can restore onward, and `t = 0` for `liveClone` and `restore`. The importer refuses a
`transferredBudget` above its policy's `maxReplicas`. A lineage therefore never holds more than the
original key plus `maxReplicas` copies, however the copies are forwarded.

A key that carries a restriction attribute the payload cannot carry (`CKA_WRAP_TEMPLATE`,
`CKA_UNWRAP_TEMPLATE`, `CKA_DERIVE_TEMPLATE`, `CKA_ENCAPSULATE_TEMPLATE`, `CKA_DECAPSULATE_TEMPLATE`,
`CKA_WRAP_WITH_TRUSTED`, on either half of the pair) is not eligible in version 1. Otherwise its
replica would silently be less restricted than the source (R2-01).

The import template may set only ordinary labels/application metadata and restrictions allowed by
the source policy. It cannot set value, unique ID, local/history, lineage, provenance, policy binding,
class, key type, paired public value or engine-private attributes. Conflicting entries return
`CKR_TEMPLATE_INCONSISTENT` before decapsulation.

Every eligible key has `CKA_DERIVE=false` unless its ordinary application role needs derivation. If
derivation is allowed, its immutable `CKA_ALLOWED_MECHANISMS` and `CKA_DERIVE_TEMPLATE` must prevent
readable/extractable outputs. Replication itself is never placed in that mechanism allowlist.

## 9. Return-code precedence

Checks occur in this order so callers cannot use errors as a key/trust oracle:

1. uninitialized library → `CKR_CRYPTOKI_NOT_INITIALIZED`;
2. malformed/null ABI arguments → `CKR_ARGUMENTS_BAD`;
3. invalid session → `CKR_SESSION_HANDLE_INVALID`; a read-only session for any mutating
   replication call → `CKR_SESSION_READ_ONLY` (R2-06);
4. wrong login/role → `CKR_USER_NOT_LOGGED_IN` or `CKR_USER_TYPE_INVALID`;
5. invisible/missing source key → `CKR_KEY_HANDLE_INVALID`;
6. unsupported/excluded key or operation → `CKR_KEY_FUNCTION_NOT_PERMITTED`;
7. malformed/oversized DER or unsupported version/suite → `CKR_DATA_INVALID`;
8. insufficient output buffer → `CKR_BUFFER_TOO_SMALL` with required length;
9–10. every certificate, evidence, signature, challenge, recipient, identity, policy, budget or
    non-identical-replay failure after DER parsing → `CKR_ACTION_PROHIBITED` (E-13; the detailed
    reason goes to the audit log only, so callers cannot probe which trust stage accepted their
    input). An exact committed retry follows §3.2 recovery and returns `CKR_OK`. A template that
    sets a forbidden or weakening attribute → `CKR_TEMPLATE_INCONSISTENT` (§8);
11. HPKE authentication/decryption failure → `CKR_ENCRYPTED_DATA_INVALID`;
12. durable ledger capacity exhausted → `CKR_DEVICE_MEMORY`;
13. internal atomic-commit failure → `CKR_DEVICE_ERROR`.

All error paths zeroize transient plaintext/key material and leave no partial object. No error
reveals whether an inaccessible key handle exists.

## 10. Bounds

These are hard parser/allocation limits for version 1, informed by K0A measurements:

| Item | Maximum |
|---|---:|
| One DER certificate | 8 KiB |
| Certificate chain | 16 KiB / exactly 2 certificates in v1 |
| Evidence object | 32 KiB (includes attestation leaf and device issuer certificates) |
| Request | 64 KiB |
| Type-specific extension | 64 KiB |
| Canonical plaintext | 128 KiB |
| Package | 256 KiB |
| Receipt | 32 KiB (includes the two-certificate receipt-signer chain) |
| Outstanding cached source packages per slot | 256 |
| Consumed destination transactions per slot | 4096 |
| Policy DER / enrolled policies per slot | 8 KiB / 64 |
| One CRL / CRLs per slot / entries per CRL | 64 KiB / 64 / 1024 |
| Open challenge reservations per slot | 1024 |

The consumption ledger refuses new imports when full. Compaction/epoch rollover is a separate,
cryptographically reviewed protocol; version 1 never evicts entries silently.

## 10a. Rotation and backup lifetime

Recovery-key rotation issues a new recovery-recipient key and certificate under the same device
issuer; that chain is the continuity proof. The previous key is retained (retired) so packages
already sealed to it still import. Revoking its certificate is a separate, explicit CRL step.

**Version 1 has no archival validation (review K0B-R-14, accepted limitation).** Import validates
the source chain and CRLs at the current host time and fails closed. An offline backup is therefore
restorable only while the source's function certificates are valid and current CRLs for each issuer
are enrolled. Operators must restore, or re-back-up to a fresh package, before then. Archival-time
validation is a future protocol revision and needs its own review.

## 11. Persistence, cache and audit

Device identity, function keys/certificates, roots, policies, revocation state, cached packages,
transaction reservations, consumption entries and receipts are part of the token's durable state:
the snapshot and the SQLite store. **The educational snapshot is not authenticated** (R2-12).
Whoever can supply a snapshot can forge bindings, budgets and the ledger, so it is trusted only as
far as the host is. The durable store writes every row of one commit in a single transaction (R2-03).

Retention (R2-04): a source keeps a created package for byte-identical retry for one hour, then
prunes it. That is far past the live reservation and evidence windows, so the pruned transaction ID
cannot be replayed into a new package. Consumed or expired challenge reservations are pruned. An
unconsumed destination reservation with no ledger entry can be cancelled explicitly. Ledger entries
are never pruned.
Adding them requires a snapshot format bump. Old snapshots migrate with empty hierarchy/replication
state and therefore cannot replicate pre-existing keys. Unknown future formats return the allocated
snapshot-format error.

Object installation and transaction consumption share one commit boundary. Successful writes bump
the object epoch so thread-local and AWS-LC/ML-DSA caches cannot return stale objects.

Enrollment, evidence generation, package creation, import, clone, replay refusal, capacity refusal,
rotation and receipt recovery emit `oplog` events containing public identifiers/digests only. No key
material, plaintext or PIN is logged.

## 12. Mandatory gates before advertisement

The interface remains unavailable in non-educational release builds until all of the following are
true. Educational fixtures do not waive any cryptographic, parser, replay or release-quality test;
they waive only the production-OID allocation requirement and remain local/non-networked:

- the four vendor attributes in §4 and the suite/function-purpose OIDs are allocated by their
  respective authorities; no documentation/test OID is reused;
- the exact DER modules and package composition receive independent cryptographic/protocol review;
- fresh-chain, expiry, revocation, purpose, nonce, downgrade, substitution and parser-negative
  vectors pass;
- AES, ML-KEM-768 and ML-DSA-65 pass live clone and source-loss offline restore, including crash
  points around reservation/install/commit;
- `CloneKey` and explicit create/import yield equivalent installed attributes and receipts;
- standard `CK_FUNCTION_LIST_3_2` layout/entries are byte-for-byte unchanged;
- unknown interface name/version/flags are refused and the standard remoting ledger does not claim
  vendor-interface coverage;
- normal native and WASM artifacts reject deterministic RNG hooks;
- the full Rust test suite and `scripts/local-gate.sh` pass; and
- no generated WASM bundle is committed except through the separately approved provenance re-pin.

## 13. Current unresolved external inputs

Private-authority local commit `36340f93` reserves the §4 attributes and the two constrained signing
mechanisms (`0x80000016` and `0x80000017`). Local commit `f2e5cfa` records the fixed educational
profile. Neither has landed on authority `origin/main`. Production OIDs remain symbolically recorded
and blocked because no verified PQCToday-controlled enterprise arc is recorded. The owner chose not
to apply for one now. The pinned RATS evidence draft also still contains TBD production OIDs. These
remain production prerequisites, not values this repository may guess; educational builds use only
the explicitly fenced RFC 5612 profile.

## 14. Revision history

| Rev | Date | Change |
|---|---|---|
| 1 | 2026-10-02 | K0B working specification |
| 2 | 2026-10-02 | Amendments E-01…E-14 from the K0B review (`docs/k0b-protocol-review-codex-2026-10-02.md`), approved by the owner for the spec. They cover evidence domain separation and claim profile (E-01/E-02), the device-ID derivation and same-device chain binding (E-03), engine-issued reserved challenges and a destination-generated transaction ID (E-04/E-07), HPKE identifiers and length checks (E-06), reserved/committed ledger states (E-09), the installed public partner (E-11), budget conservation and the provenance DER (E-12), a unified trust-failure code (E-13), and reservation lifetime as the freshness bound (E-14). R-14 is recorded as an accepted version-1 limitation (§10a). Implemented and tested in the Rust engine's `educational-replication` feature |
| 3 | 2026-10-03 | Fixes from the second independent review (Claude, fresh context, `docs/k0b-protocol-review-claude-2026-10-03.md`): restricted keys are ineligible (R2-01); the store-durable commit and logout re-key (R2-02/03, engine-level); retention, pruning and reservation cancel (R2-04); source-policy re-check at import (R2-05); read-only sessions refused (R2-06); precedence fixes (R2-08); receipts bound to the request and package (R2-09); the source, not the requester, fixes the transferred budget (R2-10); the snapshot stated as unauthenticated (R2-12) |
