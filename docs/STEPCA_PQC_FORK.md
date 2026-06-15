# step-ca PQC Fork — ML-DSA-65 Certificate Issuance (Sandbox Scenario 18)

> SCAFFOLD — populated incrementally. See `step-ca-pqc.patch`.

## Status

| Milestone | State |
|-----------|-------|
| Upstream pinned | v0.30.2 (rev `6e8ec61405239cf3f37b2bbf260a587b7d2e4e31`) |
| Patch drafted | pending |
| Builds | pending |
| ML-DSA issuance proven | pending |
| Finish plan written | pending |

## Pinned Version

- Upstream: `github.com/smallstep/certificates`
- Tag: `v0.30.2`
- Rev: `6e8ec61405239cf3f37b2bbf260a587b7d2e4e31`
- Sandbox baseline: `docker/Dockerfile.network` clones `--depth 1` HEAD of `master` (unpinned);
  this fork pins the latest stable tag instead and records it here.

## Goal (validated slice)

step-ca issues an X.509 leaf certificate signed with ML-DSA-65 (FIPS 204),
OID `2.16.840.1.101.3.4.3.18`. Signing backend for the slice: `cloudflare/circl`
ML-DSA (pure Go). HSM-backed custody (softhsmv3 via `miekg/pkcs11`, `CKM_ML_DSA` 0x1D)
is the lead finish-plan item.
