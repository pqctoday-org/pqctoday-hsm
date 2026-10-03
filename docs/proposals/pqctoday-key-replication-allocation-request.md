# Allocation request: HSM hierarchy, attestation and protected-key replication

Status: **Landed in the authority on 2026-10-03: `pqctoday-priv` PR #147, merge `62044042`. PKCS #11 values are commit `7c497c34` and the educational OID profile is commit `5165c313`, rebased from local `36340f93`/`f2e5cfa`.**
Date: 2026-10-02
Authority targets: `pqctoday-priv/docs/platform/data/pkcs11-vendor-mech-allocation.md` and
`pqctoday-priv/docs/platform/data/oid-allocation-registry.md`

This request accompanies `pqctoday-key-replication-interface-1.0.md`. The HSM repository did not
choose numeric values. The private authority allocated them on branch
`docs/hsm-replication-allocations-1002` at commit
`36340f93f882bfa9a2de2b32e2305a3d299185ce`; the allocation-file SHA-256 is
`6d79b9479f0968585980d8dce7f98b86aadba2aa91fa3d63d0f99a5be4b7daf3`. The authority
change has since landed upstream (see Status). Advertisement still waits for its own release
gates, and production use still needs real OIDs.

## PKCS #11 attribute allocations

| Allocated value | Symbol | Encoding | Security property |
|---|---|---|---|
| `0x80000108` | `CKA_PQCTODAY_REPLICATION_POLICY_ID` | 48-byte SHA-384 digest of canonical policy DER | immutable; present only from key creation/import; selects an SO-enrolled policy |
| `0x80000109` | `CKA_PQCTODAY_REPLICATION_LINEAGE_ID` | 32-byte random identifier | immutable; engine-created for original keys and authenticated across protected replicas |
| `0x8000010A` | `CKA_PQCTODAY_REPLICATION_PROVENANCE` | bounded DER provenance record | engine-produced and read-only; never caller-set |
| `0x8000010B` | `CKA_PQCTODAY_FUNCTION_PURPOSE` | native `CK_ULONG` enumeration | immutable; constrains a function key to one purpose |

Requested function-purpose values within the last attribute are:

```text
1 = device issuer
2 = peer authentication
3 = key attestation
4 = replication package signing
5 = recovery recipient
6 = replication receipt signing
```

The authority deliberately skipped the documented unused `0x80000106` and used the collision-free
contiguous block after the existing `0x80000107` allocation. The HSM constants, manifest/checkers
and immutable-attribute tests land with their implementing K2/K4 phases; a reservation is not a
claim that the attributes ship.

## PKCS #11 mechanism allocations

| Allocated value | Symbol | Standard entry point | Purpose |
|---|---|---|---|
| `0x80000016` | `CKM_PQCTODAY_ISSUE_FUNCTION_CERTIFICATE` | `C_Sign` | device issuer validates a constrained function-certificate TBSCertificate and signs only an allowed purpose/profile |
| `0x80000017` | `CKM_PQCTODAY_SIGN_KEY_ATTESTATION` | `C_Sign` | attestation key recomputes and byte-compares engine-owned claims and challenge before signing canonical RATS evidence |

Package and receipt signing happen inside the named replication interface and do not require public
mechanism allocations. The requested mechanisms need the normal manifest, mechanism-ledger,
C++-excluded-by-scope and differential-exception updates when allocated.

## OID authority requests

The following need production OIDs from PQCToday's controlled enterprise arc, or final IETF OIDs if
the relevant drafts assign them before implementation:

- the `PQCTODAY-KEY-REPLICATION-1` algorithm suite;
- EKUs/purposes for device issuer, peer authentication, key attestation, replication package
  signing, recovery recipient and replication receipt signing where no standardized EKU exists;
- replication-policy digest, lineage and provenance claims when carried in evidence/certificates;
- any RATS HSM-evidence module/claim identifiers still marked TBD in the pinned draft.

OID allocations belong in the project's OID authority, not in the PKCS #11 numeric registry.
Private-authority commit `36340f93` created the OID ledger and recorded production requests
symbolically. Commit `f2e5cfa175dba803dfafbe8fd1c78946658e9db0` then recorded the owner's
decision to use the fake educational root `1.3.6.1.4.1.32473.20261002` for now. Its OID-registry
SHA-256 is `815eca7edd96f47cef4b5ffde1aaedd6ab5e996e5c0e948a38477f00c53e6f72`.

PEN `32473` is reserved by RFC 5612 for documentation. It is not owned by PQCToday and can appear
only in disposable fixtures or an explicitly enabled, local, non-networked educational profile.
All other profiles reject the entire `1.3.6.1.4.1.32473` subtree. Production requests remain
`pending`; the owner explicitly declined a PEN application for now, and no personal application
details are collected or stored.

## Authority acceptance evidence

- The six PKCS #11 values were collision-scanned against the authority, HSM Rust/C++ constants,
  manifest, proposals and prior retired/reserved values before reservation.
- All are Rust-only because the approved implementation scope is `softhsmrustv3`; no C++, KMIP,
  CACP or wrapper support is implied.
- The authority identifies each value as reserved/not shipped and states that allocation does not
  imply protocol approval or production readiness.
- The authority structural hook passed 41 tests with 2 environment-independent skips on the final
  local commit.
- Seven fake educational OIDs are recorded beneath RFC 5612 PEN `32473`, while the seven production
  requests remain symbolic and blocked. The dummy values do not imply ownership or production use.
