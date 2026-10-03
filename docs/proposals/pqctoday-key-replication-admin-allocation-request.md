# Allocation request: replication admin and ceremony interfaces

Status: **Landed in the authority on 2026-10-03: `pqctoday-priv` PR #151, merge `220ed99e0f1fca412cc2e4224a108e992b3f6436`** (commits `ec846cb6` allocations, `2b54e0ac` safeguard narrowing; owner: "Merge both commits"). Reviewed by 7f against `origin/main` `62044042`/`fe07dcc3`. Reservations only; nothing ships or is advertised.
Date: 2026-10-03
Accompanies: `pqctoday-key-replication-admin-interface-1.0.md` (DRAFT 3.1).
**Changed after 7f's approval (needs 7f re-check):** §3 adds the two client-certificate EKU OIDs required by review A-04 in a new `.4` transport sub-arc (`.4.1`, `.4.2`; 7f nit), §1 states the 1-based KMIP value (A-06), and §2 pins all seven purpose values in engine order (see the discrepancy note).
Authority targets, checked against `pqctoday-priv` `origin/main` at `62044042` (PR #147 merge):
`docs/platform/data/pkcs11-vendor-mech-allocation.md` and
`docs/platform/data/oid-allocation-registry.md`.

The HSM repository proposes values here; the authority decides them, as with PR #147. Pushes and
merges in either repository need the owner's words.

## 1. Vendor interface registry (new subsection, proposed §1.4.4)

The authority today records only that `PQCTODAY_KEY_REPLICATION_1_0` "has no numeric PKCS #11
codepoint". Named interfaces have no codepoint, but their **name, version and function ordinals**
are the interoperable surface. The owner asked for official numbers, so this request registers
them in one table:

| Interface name (exact, NUL-terminated) | Version | Ordinal (KMIP wire value) → function | Status |
|---|---|---|---|
| `PQCTODAY_KEY_REPLICATION_1_0` | 1.0 | 0 (1) CreateReplicationPackage · 1 (2) ImportReplicationPackage · 2 (3) CloneKey | existing, **frozen**; recorded for completeness |
| `PQCTODAY_KEY_REPLICATION_ADMIN_1_0` | 1.0 | 0 (1) AdminIssueNonce · 1 (2) AdminExecute | new, reserved |
| `PQCTODAY_KEY_REPLICATION_CEREMONY_1_0` | 1.0 | 0 (1) IssueSourceChallenge · 1 (2) BeginReceive · 2 (3) CancelReceive · 3 (4) AttestKey | new, reserved |

Ordinals are 0-based positions in the native function list. The KMIP 3.0 `PKCS#11 Function` value is
**1-based** (KMIP 3.0 §11.39): wire value = ordinal + 1; wire value 0 is invalid.

Mutation rule (proposed, matching the existing mechanism policy): an ordinal, once allocated, is never
reassigned or reordered. A change in meaning requires a new interface version.

**Not authority codepoints:** the `AdminOperation` CHOICE tags `[0]`–`[4]` (enrollCrl, enrollPolicy,
rotateRecoveryKey, issueFunctionCerts, issueDeviceCrl) are part of the **signed DER format**. They are
defined in the HSM addendum and versioned with it, and are not registered here. Adding an operation
changes the addendum version, not this registry.

The KMIP 3.0 binding uses these values unchanged: the interface name in `PKCS#11 Interface`
(0x420159) and the ordinal in `PKCS#11 Function` (0x42015a).

## 2. Function-purpose enumeration value

Within the existing `CKA_PQCTODAY_FUNCTION_PURPOSE` (`0x8000010B`):

```text
1 = device issuer
2 = key attestation
3 = replication package signing
4 = recovery recipient
5 = peer authentication
6 = replication receipt signing
7 = replication admin authority   (new; the enrolled host-held admin signing certificate)
```

**Discrepancy found 2026-10-03 (please pin):** the authority entry for `0x8000010B` records no
enumeration values. The earlier HSM request (`pqctoday-key-replication-allocation-request.md`) listed
2 = peer authentication, 3 = key attestation, 4 = package signing, 5 = recovery recipient. That does
**not** match the engine (`rust/src/replication/oids.rs` `Purpose`), the base spec §4.1, or the OID
order `.2.1`–`.2.6`, which all use the table above. The engine is shipped-in-branch behaviour and the
OID order is published, so this request pins the engine order. The earlier request's table was corrected on
#316 by 7f: commit `7cff4fb37688d58b27832ca9efbdb421f335827a`, #316's head (pushed, gated 24/24). No new attribute, mechanism or return code is requested.

## 3. Educational OID (documentation arc, never production)

| Name | OID | Use |
|---|---|---|
| `id-pqctoday-function-purpose-replication-admin-authority` | `1.3.6.1.4.1.32473.20261002.2.7` | Critical EKU of the admin-authority certificate |
| `id-pqctoday-education-transport-eku-arc` | `1.3.6.1.4.1.32473.20261002.4` | **New sub-arc** (register the arc itself): transport client-certificate EKUs, never function purposes |
| `id-pqctoday-eku-replication-admin-client` | `1.3.6.1.4.1.32473.20261002.4.1` | KMIP mTLS client certificate EKU: `replication-admin` role (review A-04) |
| `id-pqctoday-eku-replication-user-client` | `1.3.6.1.4.1.32473.20261002.4.2` | KMIP mTLS client certificate EKU: `replication-user` role (review A-04) |

`.2.7` is the next unused value under `.2` (function purposes) on `origin/main`. `.4` is a new
sub-arc for **transport** client-certificate EKUs, kept apart from `.2` so a purpose parser never
sees them; `.3` stays reserved for RATS evidence/claim fixtures. The `.1`/`.2`/`.3` branch layout is
unchanged.

## 4. Safeguard amendment (owner approval required; SEPARATE commit)

`oid-allocation-registry.md` §3 currently requires consumers to "disable networking and external
trust-store installation for the educational profile". Proposed replacement for that bullet:

> disable networking for the educational profile, except the KMIP crypto-plane binding of the
> replication admin and ceremony interfaces between explicitly enrolled lab devices on an isolated
> segment with no route to the internet; never install an educational root in an external trust store.

The same narrowing applies to HSM base spec §4.1. This change implements the owner's
"crypto network only" + "kmip with ttlv pkcs11" decisions and must be approved as a safeguard
change, not slipped in with the allocations. In the priv PR it is a **separate commit** from §1–§3,
so the owner can approve or reject it independently of the numbers.

## 5. Acceptance evidence to record when landed

The same pattern as PR #147: authority commit SHA, allocation-file SHA-256, and the HSM-side pin in
`scripts/check_pkcs11_constants.py` and the manifest `active` block, marked "not yet upstream" until
the authority merge lands.
