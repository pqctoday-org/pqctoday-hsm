# PQCToday Key Replication — Admin and Ceremony Interfaces 1.0 (addendum)

Status: **DRAFT 3.2 — OWNER-APPROVED 2026-10-03** (owner answer in session 1c: "Yes, approve it"; dispositions by 1c + 7f). Not yet allocated or implemented. (2026-10-03; second independent review B-01…B-06 applied, `gpt-5.6-terra`, record `docs/k0b-admin-addendum-review2-codex-2026-10-03.md`). Draft 3.1 had 7f's engine review applied (B1, B2, T1–T4, EKU sub-arc). Applies all 18 findings of the independent Codex review
(`gpt-5.6-sol`, `docs/k0b-admin-addendum-review-codex-2026-10-03.md`, dispositions agreed by 1c and 7f).
Engine-owner (7f) reviewed drafts 0–2. Not allocated, not implemented, not advertised.
Date: 2026-10-03 · Base: `docs/proposals/pqctoday-key-replication-interface-1.0.md` revision 3
(the "base spec") at `5c3b3ed5`. Engine scope: `softhsmrustv3`, feature `educational-replication`.
Changes from draft 2 are tagged with their finding ID (A-NN).

This addendum defines two new, separately discoverable vendor interfaces, so that the replication
ceremony can run between two HSMs over KMIP on an isolated crypto network:

- `PQCTODAY_KEY_REPLICATION_ADMIN_1_0`: SO-only, signed and replay-protected administration; and
- `PQCTODAY_KEY_REPLICATION_CEREMONY_1_0`: the user-level ceremony calls that the frozen
  `PQCTODAY_KEY_REPLICATION_1_0` list does not contain.

`PQCTODAY_KEY_REPLICATION_1_0` (the "v1 interface") is **frozen and unchanged**. Nothing here adds,
reorders or reinterprets a v1 function, structure, signed-bytes prefix or return code.

**Version immutability (A-17).** The 1.0 operation set of both new interfaces is immutable. Any new
operation requires a new interface name/version, a new TBS `version`, a new signature-domain prefix
and a new allocation entry. No extension of the `AdminOperation` CHOICE under `ADMIN_1_0`.

## 0. Owner decisions this addendum implements (2026-10-03)

| # | Decision (relayed verbatim by the coordinator) | Effect here |
|---|---|---|
| O1 | Courier: "Crypto network only" | §6 |
| O2 | Phase-2 surface: "kmip with ttlv pkcs11" | §6 |
| O3 | "New official vendor numbers", then "1: SO admin over KMIP too" | §2, §3, §9 |
| O4 | "Yes, root enrollment board-local" (re-confirmed: "Board-local root, rest over KMIP") | §1, §3.3 |
| O5 | Security bar: SO-authenticated sessions only, separate from user calls; signed requests; replay/nonce protection; crypto network only; audit records | §3–§7 |
| O6 | Multi-role login: approved **C1**, per-connection application contexts, own engine PR after #316 | §1.1 |
| O7 | SO PIN: "Root-only local file + signed requests" | §1.1, §6 |
| O8 | Safeguard: "Allow crypto-network KMIP only" | §7.1 |

## 1. Trust bootstrap (board-local, never on the network)

Run **once per board, locally, as SO**, through a board-local CLI built only with the feature
(`rust/src/bin/repl_edu_board.rs` in the pre-ABI test build), with file input and output:

1. device enrollment: CSR out → manufacturing root, device certificate and root CRL in;
2. first function-certificate issuance; and
3. **admin-authority enrollment**: the SO enrolls one ML-DSA-65 **admin-authority certificate**, a
   leaf directly under the enrolled manufacturing root: `cA=FALSE`, key usage `digitalSignature`
   only, critical EKU `.2.7` (§9.2), AKI = root SKI, revoked through the root CRL. Its private key is
   held on the operator host next to the test CA, never on a board. One admin-authority certificate
   administers **every board enrolled under that root**; this is intended.

The admin-authority certificate is an SO-created trust object (`CKA_MODIFIABLE`, `CKA_COPYABLE`,
`CKA_DESTROYABLE` false) with a durable sequence counter initialised to 0 and
`CKA_PQCTODAY_FUNCTION_PURPOSE` = 7. At most **one** admin authority is active per slot. Replacing it
is a board-local step only, never an admin-interface operation, so a stolen admin key cannot enroll
its own successor. Replacement resets the counter for the new authority; committed receipts of the
old one stay recoverable **while retained in the ledger** (§3.5).

The bootstrap is the root of trust for everything in §3. Any step that installs or replaces a root,
the device identity or the admin authority **is not reachable through either new interface.**

### 1.1 SO authentication: application contexts + signed requests (O6, O7)

A token has one login state **per application** (PKCS#11 v3.2). C1 gives the engine per-connection
**application contexts**: login state and handle invalidation are tracked per (slot, context);
native C callers keep today's one-context behaviour; each context obeys the v3.2 rules.

**Context lifecycle (A-05).** The KMIP server creates a context only **after** a successful mTLS
handshake on the crypto-plane listener, opens and logs in sessions only inside that context, and
closes all its sessions and destroys the context on disconnect, TLS error or server shutdown.
Session handles and context identifiers are never accepted from the wire. A context is bound to
exactly one connection and one role. Advertisement is gated on tests proving that one connection
cannot use, observe or outlive another's sessions or handles.

An admin call is authorized by **all** of:

1. the `replication-admin` role, derived **only** from immutable connection metadata (§6.3, A-04);
2. a real **SO login** in that connection's context, with the SO PIN read by the server from a
   board-local root-only file (never from the network or a KMIP Credential);
3. a valid ML-DSA-65 signature from the enrolled admin authority over the request; and
4. the engine's current nonce and `sequence == stored + 1`.

Items 3–4 stop a stolen KMIP credential; items 1–2 bound who may submit one. User work in other
contexts continues during admin calls. **Before C1 lands, the admin interface is not served over
KMIP at all.**

## 2. Discovery and function lists

Both interfaces are discovered only through `C_GetInterface` with the exact NUL-terminated name,
version `{1,0}` and supported flags, under the same conditions as v1 (feature compiled **and**
educational profile selected). A NULL name still selects the standard `PKCS 11` interface.

**Ordinals (A-06).** Ordinals below are the 0-based positions in each function list. On the KMIP
wire, `PKCS#11 Function` is **1-based** (KMIP 3.0 §11.39): wire value = ordinal + 1, and wire value 0
is refused with `CKR_ARGUMENTS_BAD`.

### 2.1 Admin function list

```c
typedef struct PQCTODAY_KEY_REPLICATION_ADMIN_FUNCTION_LIST_1_0 {
    CK_VERSION version; /* { 1, 0 } */
    CK_RV (*C_PQCTODAY_AdminIssueNonce)(          /* ordinal 0, KMIP 1 */
        CK_SESSION_HANDLE hSOSession,
        CK_BYTE_PTR pNonce, CK_ULONG_PTR pulNonceLen);            /* exactly 32 */
    CK_RV (*C_PQCTODAY_AdminExecute)(             /* ordinal 1, KMIP 2 */
        CK_SESSION_HANDLE hSOSession,
        CK_BYTE_PTR pSignedRequest, CK_ULONG ulSignedRequestLen,  /* DER AdminSignedRequest */
        CK_BYTE_PTR pReceipt, CK_ULONG_PTR pulReceiptLen);        /* DER AdminReceipt */
} PQCTODAY_KEY_REPLICATION_ADMIN_FUNCTION_LIST_1_0;
```

The operation is selected inside the signed request (§3.1), so the signed surface stays two calls.

### 2.2 Ceremony function list

```c
typedef struct PQCTODAY_KEY_REPLICATION_CEREMONY_FUNCTION_LIST_1_0 {
    CK_VERSION version; /* { 1, 0 } */
    CK_RV (*C_PQCTODAY_IssueSourceChallenge)(     /* ordinal 0, KMIP 1 */
        CK_SESSION_HANDLE hUserSession,
        CK_BYTE_PTR pChallenge, CK_ULONG_PTR pulChallengeLen);    /* exactly 32 */
    CK_RV (*C_PQCTODAY_BeginReceive)(             /* ordinal 1, KMIP 2 */
        CK_SESSION_HANDLE hUserSession,
        CK_BYTE_PTR pBeginReceive, CK_ULONG ulBeginReceiveLen,    /* DER BeginReceive */
        CK_BYTE_PTR pRequest, CK_ULONG_PTR pulRequestLen);        /* DER ReplicationRequest (base §5) */
    CK_RV (*C_PQCTODAY_CancelReceive)(            /* ordinal 2, KMIP 3 */
        CK_SESSION_HANDLE hUserSession,
        CK_BYTE_PTR pTransactionID, CK_ULONG ulTransactionIDLen); /* exactly 32 */
    CK_RV (*C_PQCTODAY_AttestKey)(                /* ordinal 3, KMIP 4 */
        CK_SESSION_HANDLE hUserSession,
        CK_OBJECT_HANDLE hKey,
        CK_BYTE_PTR pChallenge, CK_ULONG ulChallengeLen,          /* exactly 32 */
        CK_BYTE_PTR pEvidence, CK_ULONG_PTR pulEvidenceLen);      /* DER Evidence, role 2 */
} PQCTODAY_KEY_REPLICATION_CEREMONY_FUNCTION_LIST_1_0;
```

These wrap the existing engine functions; semantics, reservations, lifetimes and refusals are base
§5.1's. Sizing follows base §3 (NULL output → exact length, no randomness, reservation or
mutation). `IssueSourceChallenge` and `CancelReceive` are fixed-size; `BeginReceive` sizing needs a
new engine length function (7f).

**Separation.** Admin calls need an SO-logged-in context plus the signed request; ceremony and v1
calls need a USER R/W session. Enforced by the login role and one role per connection (§6.3).

## 3. Admin requests

### 3.1 ASN.1 module (A-09)

```asn1
PQCTodayReplicationAdmin-1-0 DEFINITIONS EXPLICIT TAGS ::= BEGIN

FunctionPurpose ::= ENUMERATED {   -- values = engine oids.rs Purpose = OID order .2.1–.2.6 (7f B1)
  keyAttestation(2), packageSigning(3), recoveryRecipient(4),
  peerAuthentication(5), receiptSigning(6) }
  -- deviceIssuer(1) and adminAuthority(7) are NOT revocable through this interface;
  -- any other value is refused before cryptography.

BeginReceive ::= SEQUENCE {
  version          INTEGER (1),
  operation        ENUMERATED { liveClone(0), offlineBackup(1), restore(2) },
  sourceChallenge  OCTET STRING (SIZE(32)),
  domainID         OCTET STRING (SIZE(32)),
  requestedPolicy  OCTET STRING (SIZE(48)) }

KeyCall ::= SEQUENCE {                       -- KMIP binding only (§6.8)
  keyUniqueID  UTF8String (SIZE(36)),
  payload      OCTET STRING (SIZE(0..262144)) }

AdminTbsRequest ::= SEQUENCE {
  version      INTEGER (1),
  deviceID     OCTET STRING (SIZE(32)),     -- target device (base §5.1)
  adminKeyID   OCTET STRING (SIZE(32)),     -- SHA-256(DER SPKI of the admin-authority cert)
  nonce        OCTET STRING (SIZE(32)),     -- the engine's current admin nonce (§3.3)
  sequence     INTEGER (1..9223372036854775807), -- MUST equal stored + 1 (A-08)
  issuedAt     GeneralizedTime,             -- audit only, never checked
  operation    AdminOperation }

AdminOperation ::= CHOICE {
  enrollCrl          [0] SEQUENCE { crl OCTET STRING (SIZE(1..65536)),
                                    issuerDeviceCert OCTET STRING (SIZE(1..8192)) OPTIONAL },
  enrollPolicy       [1] SEQUENCE { policy OCTET STRING (SIZE(1..8192)) },
  rotateRecoveryKey  [2] NULL,
  issueFunctionCerts [3] NULL,
  issueDeviceCrl     [4] SEQUENCE {
       revoke          SEQUENCE SIZE(0..5)  OF FunctionPurpose,       -- ascending, unique
       retiredToRevoke SEQUENCE SIZE(0..64) OF OCTET STRING (SIZE(1..8192)), -- ascending by bytes, unique
       validitySeconds INTEGER (60..2592000) } }

AdminSignedRequest ::= SEQUENCE {
  tbs                 AdminTbsRequest,
  signatureAlgorithm  AlgorithmIdentifier,   -- exactly id-ml-dsa-65, parameters absent (RFC 9881)
  signature           BIT STRING }           -- exactly 3309 octets, 0 unused bits (B-05)

AdminTbsReceipt ::= SEQUENCE {
  version             INTEGER (1),
  deviceID            OCTET STRING (SIZE(32)),
  requestHash         OCTET STRING (SIZE(48)), -- SHA-384(DER AdminSignedRequest)
  sequence            INTEGER (1..9223372036854775807),
  resultDigest        OCTET STRING (SIZE(48)), -- per operation, §3.6
  output              OCTET STRING (SIZE(1..65536)) OPTIONAL, -- policy ID or device-CRL DER
  committedAt         GeneralizedTime,
  receiptSignerChain  SEQUENCE SIZE(2) OF Certificate }       -- receipt leaf, device issuer (A-01)

AdminReceipt ::= SEQUENCE {
  tbs                 AdminTbsReceipt,
  signatureAlgorithm  AlgorithmIdentifier,   -- exactly id-ml-dsa-65, parameters absent (B-05)
  signature           BIT STRING }           -- exactly 3309 octets, 0 unused bits
END
```

Lists that the module marks ascending/unique are refused if unsorted or duplicated, before any
cryptography. DER nesting depth is capped at 8.

Signed bytes, each with an empty ML-DSA context:

```text
request: "PQCToday Replication Admin 1.0"         || 0x00 || DER(AdminTbsRequest)
receipt: "PQCToday Replication Admin Receipt 1.0" || 0x00 || DER(AdminTbsReceipt)
```

Both prefixes differ from every base-spec prefix.

### 3.2 Verification order (all inside the engine)

1. R/W session SO-logged-in in its context; educational profile selected (base §9 steps 1–4).
2. Strict DER under §8 bounds; re-encoding must byte-equal the input; lists ordered and unique.
3. **Committed-retry lookup first (A-07):** if the admin replay ledger (§3.5) holds an entry whose
   request hash matches and whose stored request is byte-equal, return its stored receipt and stop.
   No freshness, nonce or sequence check applies, and this works after the admin authority has been
   rotated or revoked (it mutates nothing).
4. `deviceID` equals this device; `adminKeyID` names the enrolled, active admin authority.
5. The admin-authority certificate chains to the enrolled root, is unexpired, and the **current**
   root CRL does not list it (fail closed). **Root-CRL renewal (7f B2, option a):** if the operation
   is `enrollCrl` and its CRL is issued by the enrolled root, that CRL is verified first (root
   signature, `CRLNumber` greater than the stored one, `thisUpdate` ≤ now < `nextUpdate`) and step 5
   is then evaluated **against the new CRL**, so the admin certificate must not appear in it. This
   avoids the deadlock where an expired root CRL blocks the only call that renews it, with no bypass:
   the new CRL must be root-signed and fresher.
6. ML-DSA-65 signature over the request's signed bytes.
7. Freshness: `nonce` equals the current unexpired admin nonce (§3.3); `sequence == stored + 1`
   (A-08). Overflow is impossible within the declared range and is refused.
8. Operation-specific validation by the engine's **stage** function (A-03; §3.4).
9. **One atomic commit (A-03):** the staged objects/updates, nonce consumption, the new sequence, the
   replay-ledger entry, the receipt and **a durable audit record**, in a single durable transaction;
   the `oplog` line is derived from that audit record after the commit (7f T3). No stage
   function writes state or audit on its own. A crash before the commit leaves nothing changed and
   the nonce still current (unless the process restarted, §3.3); after it, step 3 recovers the receipt.

### 3.3 Admin nonce (A-12)

`AdminIssueNonce` is served only to the `replication-admin` role. It returns a uniformly random,
non-zero 256-bit value from the engine CSPRNG, held **in memory only** as the slot's **single current
nonce**, with a 60-second lifetime measured on the engine's **monotonic** clock (7f T4). A restart
invalidates it: the committed case is recovered by §3.2 step 3, and the uncommitted case simply
retries with a new nonce. No store write per issuance, and no wall-clock dependence on boards. A new call **replaces** the current nonce and does not
extend the old one's lifetime. There is no occupancy table, so it cannot be exhausted. The KMIP layer
rate-limits issuance per connection (one per second, burst 4). **Residual (accepted):** a stolen admin
transport credential can force the legitimate operator to retry (availability only); it cannot make a
request succeed without the admin signing key.

### 3.4 Operations (engine stage + common commit)

| Operation | Engine stage function (7f, `admin.rs`) | Rules |
|---|---|---|
| `enrollCrl` | `stage_enroll_crl` | root or peer-device CRL; CRL numbers strictly increase per issuer |
| `enrollPolicy` | `stage_enroll_policy` | output = 48-byte policy ID |
| `rotateRecoveryKey` | `stage_rotate_recovery_key` | base §10a continuity; a **single-purpose generation bump** under the same per-purpose generation counter as re-issuance, so "highest active generation" stays deterministic when the two interleave (7f T1) |
| `issueFunctionCerts` | `stage_reissue_function_certificates` (new) | **Generations (A-14):** each re-issuance creates generation g+1 for all five purposes atomically; exactly one active triple (private key, public key, certificate) per purpose; retired private keys are unusable for new operations **except** the retired recovery-recipient key, which still opens packages already sealed to it (base §10a; 7f T1), so re-issuance has the same rotation effect on purpose 4 as `rotateRecoveryKey`; retired certificates remain available for verification; accessors select the highest active generation deterministically. **Device-CRL numbering (7f T2):** re-issuance continues the slot's device-CRL number (never restarts at 1), so peers accept the next device CRL under the strictly-increasing rule |
| `issueDeviceCrl` | `stage_issue_device_crl` | `retiredToRevoke` entries must **byte-match a retained retired certificate of this slot** with valid issuer, signature and purpose; active or foreign certificates are refused; serials deduplicated (A-15). `revoke` must not include `receiptSigning(6)` for the **active** receipt-signing leaf (B-01): rotate it first with `issueFunctionCerts`, whose receipt the outgoing key signs before retirement. Output = CRL DER |

The existing public functions become stage + commit, so local callers see no behaviour change.

**Out of scope, board-local only (O4):** root and trust-anchor enrollment, device enrollment,
admin-authority enrollment and replacement. **Not provided at all:** destroying or modifying a trust
object, reading any private value, changing a key's replication eligibility.

### 3.5 Admin replay ledger (A-10)

Each committed admin request writes one durable ledger entry: request hash, full request DER,
receipt DER, sequence, admin key ID and commit time. Capacity: 1,024 entries **and** 64 MiB per slot.
When either limit is reached, `AdminExecute` returns `CKR_DEVICE_MEMORY`; entries are never evicted
silently. Retention: entries older than 30 days **and** below the current sequence for their admin
key may be pruned only by an explicit board-local maintenance step, which keeps a tombstone (hash +
sequence + admin key ID) so a pruned request can never re-execute. A request matching a tombstone
is a **terminal refusal** (`CKR_ACTION_PROHIBITED`); its receipt is **not** recoverable after pruning
(B-03). A ledger entry that fails integrity checks
returns `CKR_DEVICE_ERROR` and is never treated as absent.

### 3.6 Admin receipt (A-01)

`resultDigest` per operation:

| Operation | `resultDigest` |
|---|---|
| `enrollCrl` | SHA-384(CRL DER) |
| `enrollPolicy` | the 48-byte policy ID |
| `rotateRecoveryKey` | SHA-384(new recovery-recipient certificate DER) |
| `issueFunctionCerts` | SHA-384 over the 5 new leaf DERs concatenated in purpose order |
| `issueDeviceCrl` | SHA-384(CRL DER); the CRL is also in `output` |

The receipt is signed by the device's current **receipt-signing** function key (no separate purpose).
Receipts are verified against **current** CRLs: a receipt whose signer is listed fails, whatever
`committedAt` says, because `committedAt` is asserted by the very key being judged and device-CRL
entries carry no reason code (7f, B-01). Operators verify receipts when they receive them.
Re-issuance only retires the old receipt key, so its receipts stay verifiable until the operator
lists that certificate via `retiredToRevoke`. As-of-time semantics need CRL reason codes
(superseded vs keyCompromise) and are a v1.1 item. A verifier MUST: validate `receiptSignerChain` (leaf profile = receipt signing, issuer = device
issuer) against the enrolled root and current CRLs; require `deviceID` == SHA-256 of the chain's
device-issuer SPKI; require `requestHash`/`sequence` to match the request it sent; and verify the
signature over the receipt's signed bytes. `host_verify` gains `verify_admin_receipt` with the same
core as base receipts.

## 4. Return codes

Same precedence as base §9, with these placements:

- step 4: an SO session on a ceremony or v1 call, or a USER session on an admin call →
  `CKR_USER_TYPE_INVALID`;
- malformed or oversized DER, unknown version, operation or purpose, unsorted/duplicate lists, and
  any **syntactic** failure of an embedded payload (policy DER, CRL DER, certificate DER) →
  `CKR_DATA_INVALID`, checked before any trust validation (B-06). Enrollment-state and other base §9
  preconditions (§3.2 step 1) still come **before** payload parsing;
- every **syntactically valid** device, admin-key, chain, CRL, signature, nonce, sequence or
  operation-specific trust/authorization failure → `CKR_ACTION_PROHIBITED` (E-13; the reason goes to `oplog` only);
- replay ledger full → `CKR_DEVICE_MEMORY`; ledger integrity failure or commit failure →
  `CKR_DEVICE_ERROR`;
- KMIP wire function value 0, or a function value with no ordinal → `CKR_ARGUMENTS_BAD`.

## 5. Audit (A-16)

The KMIP layer attaches **authenticated connection metadata** (role, client-certificate SHA-256,
listener address, KMIP correlation value) to the application context when it is created. The engine
reads it from the context, never from call parameters, and writes it into the same durable commit as
the operation.

| Call | Mandatory `oplog` fields | Optional |
|---|---|---|
| `AdminIssueNonce` | interface, ordinal, connection metadata, result | — |
| `AdminExecute` (accepted or refused after DER parse) | interface, ordinal, connection metadata, `requestHash`, result | `adminKeyID`, `sequence`, operation (when parsed) |
| Ceremony calls | interface, ordinal, connection metadata, result | transaction ID, key unique ID |
| v1 calls over KMIP | as base §11, plus connection metadata | — |

Never key material, PINs, or a nonce value before it is consumed.

## 6. KMIP transport binding (crypto network only)

**6.0 Status of the current bridge (B-02).** The bridge on branch `feat/hsm-replication-kmip-admin-1003`
(`kmip/src/ops/replication_bridge.rs`) is a **pre-ceremony-ABI lab test build** and does **not**
conform to this section: it uses a test interface name, returns only the receipt from Import,
ignores templates, and runs in the single-tenant engine session without C1 contexts or transport-EKU
roles. It is feature-gated, serves only user-level operations (no admin interface), and is used only
for the two-board lab run. It is replaced by the conforming binding before the branch merges anywhere.

Carried by the KMIP 3.0 **PKCS#11 operation** (`0x33`):

| KMIP field | Value |
|---|---|
| `PKCS#11 Interface` (0x420159) | exact interface name |
| `PKCS#11 Function` (0x42015a) | ordinal + 1 (A-06) |
| `PKCS#11 Input Parameters` | the envelope in §6.9 for that (interface, function) |
| `PKCS#11 Output Parameters` | the envelope in §6.9; absent on error |
| `PKCS#11 Return Code` | the engine's CK_RV, unchanged |

Rules for the KMIP layer:

1. Compiled only with `educational-replication`; absent from the default and release binary. Other
   builds return `CKR_FUNCTION_NOT_SUPPORTED`.
2. **Listener:** only the crypto-plane listener (`PQC_CRYPTO_IP:5696`); any other listener is refused
   before the engine.
3. **Role from transport only (A-04).** The role is derived solely from the mTLS client certificate,
   issued by a dedicated replication client CA configured for this listener, with exactly one of two
   critical EKUs (educational arc, §9.2): `replication-admin` (`.4.1`) or `replication-user` (`.4.2`).
   A certificate with both, neither, or any other EKU is refused at handshake. **Path validation
   (B-04)**, all before context creation: trust only explicitly pinned replication-client CA root(s)
   configured for this listener (never the system trust store); chain = leaf issued directly by a
   pinned root; leaf valid at handshake time; the EKU extension critical with exactly one of the two
   EKUs; if a client-CA CRL is configured it must be current and must not list the leaf. Without a
   configured CRL there is no client revocation (stated educational residual). KMIP header
   Credentials, tickets and `Authentication` structures **cannot set, change or upgrade** the role;
   for these interfaces they are ignored for authorization (still logged). One connection = one role.
4. **SO PIN** from a board-local root-only file (O7); never from the network.
5. **Policy:** CACP sees these as `PKCS_11:<interface>:<ordinal>`; the test policy module allows
   them explicitly; default deny unchanged.
6. **No re-parsing** of engine DER beyond the envelope; logging only by hash.
7. Coverage ledgers must **not** list these interfaces as vendor-interface coverage (plan §9.2).
8. **Key references (A-13).** Keys are referenced by `CKA_UNIQUE_ID` in a `KeyCall`, never a handle
   or label. The server resolves inside the caller's context with per-call predicates and requires
   exactly one match, else `CKR_KEY_HANDLE_INVALID`:
   - v1 create: class secret or private key, `CKA_PQCTODAY_REPLICATION_POLICY_ID` present;
   - `AttestKey`: class secret or private key.
   The engine's own source-key and attestation checks still run afterwards.
9. **Envelopes (A-02).**

   | Interface · function | Input Parameters | Output Parameters |
   |---|---|---|
   | v1 · Create (1) | `KeyCall { uid, ReplicationRequest DER }` | package DER |
   | v1 · Import (2) | `ImportCall ::= SEQUENCE { package OCTET STRING, template SEQUENCE SIZE(0..16) OF Attr }` | `ImportResult ::= SEQUENCE { installedUniqueID UTF8String (SIZE(36)), receipt OCTET STRING }` |
   | v1 · Clone (3) | — | refused: `CKR_FUNCTION_NOT_SUPPORTED` (same-module only) |
   | ceremony · IssueSourceChallenge (1) | empty | 32 bytes |
   | ceremony · BeginReceive (2) | `BeginReceive` DER | `ReplicationRequest` DER |
   | ceremony · CancelReceive (3) | 32-byte transaction ID | empty |
   | ceremony · AttestKey (4) | `KeyCall { uid, 32-byte challenge }` | Evidence DER |
   | admin · AdminIssueNonce (1) | empty | 32 bytes |
   | admin · AdminExecute (2) | `AdminSignedRequest` DER | `AdminReceipt` DER |

   `Attr ::= SEQUENCE { type INTEGER (0..4294967295), value OCTET STRING (SIZE(0..1024)) }`, sorted by
   `type`, unique. Only attributes base §8 allows on import are accepted; anything else →
   `CKR_TEMPLATE_INCONSISTENT`. Handles never appear in any output.
10. **Batches and async (A-11).** A Request Message carrying any of these interfaces must contain
    exactly one batch item, with no Batch Error Continuation Option `Undo` and no asynchronous
    indicator; otherwise the server returns `Operation Failed` with reason `Invalid Message` before
    the engine is called. Execution is synchronous; a committed result is reported as committed.
11. **Transport limits (A-18).** Enforced while decoding lengths, before allocation: TTLV frame
    ≤ 320 KiB; one batch item; Input Parameters ≤ 262,208 B (256 KiB + wrapper); Output Parameters
    ≤ 256 KiB.

## 7. Threat-model note: replication over KMIP (educational)

| Threat | Control | Residual (educational) |
|---|---|---|
| Stolen `replication-user` certificate | Ceremony/v1 protocol checks still bind recipient, domain, policy, evidence | Can run ceremonies for keys already eligible under an enrolled policy |
| Stolen `replication-admin` certificate | Every admin op also needs the host-held admin signing key, nonce and sequence | Availability: can force nonce re-issue (§3.3) |
| Stolen admin signing key | Cannot touch roots, the device or the admin authority (§1); every use audited with its key ID | Can enroll CRLs/policies and rotate keys until revoked by the root CRL (a board-local step) |
| Replay / reordering | Single current nonce + `sequence == stored + 1` + replay ledger | Snapshot rollback resets them (base §11: unauthenticated snapshot) |
| Header credential upgrade | Role only from transport EKU (§6.3) | — |
| Cross-connection session use | Connection-scoped contexts (§1.1) | Depends on C1 isolation tests |
| Network path | Crypto VLAN only; TLS 1.3 hybrid ML-KEM; packages already signed and HPKE-sealed | Lab network only; no internet route |
| Error oracle | `CKR_ACTION_PROHIBITED` collapse; reasons only in `oplog` | Timing not equalised |
| Confusion with production | Educational profile, documentation OIDs, labels | As base spec |

### 7.1 Safeguard amendment (O8, approved)

Base spec §4.1 and the priv OID registry §3 forbid networking for the educational profile. They are
narrowed, not ignored:

> The educational profile must not use a network peer, **except** the KMIP crypto-plane binding of
> the replication admin and ceremony interfaces between explicitly enrolled lab devices on an
> isolated segment with no route to the internet. External trust-store installation stays
> prohibited without exception.

It lands as a separate priv commit from the allocations.

## 8. Bounds

| Item | Maximum |
|---|---:|
| `AdminSignedRequest` | 96 KiB |
| `AdminReceipt` | 96 KiB |
| `BeginReceive` | 256 B |
| `ImportCall` template | 16 attributes, 1 KiB each |
| Admin replay ledger | 1,024 entries and 64 MiB per slot |
| Current admin nonces | 1 per slot |
| DER nesting depth | 8 |
| KMIP limits | §6.11 |

All other bounds are base §10's. Bounds are checked before allocation or signature work.

## 9. Allocation request (priv authority, against `origin/main`)

### 9.1 Interface registry

| Interface name | Version | Ordinal (KMIP value): function |
|---|---|---|
| `PQCTODAY_KEY_REPLICATION_1_0` | 1.0 | 0 (1) Create · 1 (2) Import · 2 (3) CloneKey — frozen |
| `PQCTODAY_KEY_REPLICATION_ADMIN_1_0` | 1.0 | 0 (1) AdminIssueNonce · 1 (2) AdminExecute |
| `PQCTODAY_KEY_REPLICATION_CEREMONY_1_0` | 1.0 | 0 (1) IssueSourceChallenge · 1 (2) BeginReceive · 2 (3) CancelReceive · 3 (4) AttestKey |

`AdminOperation` CHOICE tags are part of the signed format, versioned with this document, not
authority codepoints.

### 9.2 Educational OIDs (documentation arc, never production)

| Name | OID |
|---|---|
| `id-pqctoday-function-purpose-replication-admin-authority` | `1.3.6.1.4.1.32473.20261002.2.7` |
| `id-pqctoday-eku-replication-admin-client` | `1.3.6.1.4.1.32473.20261002.4.1` |
| `id-pqctoday-eku-replication-user-client` | `1.3.6.1.4.1.32473.20261002.4.2` |

`.4` is a new sub-arc for **transport** client-certificate EKUs, kept apart from the `.2`
function-purpose arc so a purpose parser never sees them (7f nit). `CKA_PQCTODAY_FUNCTION_PURPOSE`
values, pinned in engine order (= OID order): 1 device issuer, 2 key attestation, 3 package signing,
4 recovery recipient, 5 peer authentication, 6 receipt signing, **7 replication admin authority**
(new). No new
numeric PKCS#11 mechanism, attribute or return code.

## 10. Gates before advertisement

Base §12, plus: a second independent review of this draft (it changed materially); engine tests for
every §3.2 step, refusal and stage/commit crash window (A-03); C1 context-isolation tests (A-05);
KMIP tests for listener, transport-role derivation and header-credential non-upgrade (A-04), batch
and async refusal (A-11), and frame limits (A-18); published wire vectors for every (interface,
function) envelope (A-06, A-02); the two-board run; and the §7.1 amendment landed in both places.

## 11. Review record

| Source | Disposition |
|---|---|
| 7f review of drafts 0–1 | Receipt signer reused; `issuedAt` audit-only; device-CRL ordering left to the operator; per-op `resultDigest`; engine-side re-issuance and admin-authority enrollment; `sequence` u64; one admin cert per root; `BeginReceive` sizing function; separation by role |
| Owner (O6/O7) | C1 contexts; SO PIN from a root-only local file |
| 7f (key reference) | `CKA_UNIQUE_ID` in `KeyCall`, exactly one match |
| Codex `gpt-5.6-terra` B-01…B-06 (second review) | All adopted (B-01 active receipt signer not revocable; receipts verified against current CRLs, as-of semantics deferred to v1.1; B-02 bridge status stated; B-03 tombstones terminal; B-04 client path validation; B-05 receipt AlgorithmIdentifier; B-06 syntactic → DATA_INVALID) |
| 7f review of draft 3 | B1 purpose numbering fixed to engine order; B2 root-CRL renewal verified against the new CRL; T1 recovery-key exemption + rotation as a generation bump; T2 device-CRL numbering continues; T3 audit record in commit, oplog derived; T4 in-memory monotonic nonce; EKUs moved to `.4` |
| Codex `gpt-5.6-sol` A-01…A-18 | All adopted; see the review record's disposition table; reflected in §1.1, §2, §3.1–§3.6, §4, §5, §6.3, §6.8–§6.11, §8, §9 |
