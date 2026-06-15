# cosign PQC Fork — ML-DSA-65 Artifact Signing (Scenario 34)

> STATUS: SCAFFOLD. Filled in incrementally as the validated slice is built.
> strongSwan-pattern fork: minimal diff against a pinned upstream tag, validated locally,
> shipped as a `.patch` + finish plan. No push, no PR, no GitHub repo.

## 1. Goal

A cosign that signs a blob with **ML-DSA-65 (FIPS 204)** and verifies it, proving the
sign+verify round-trip locally. CIRCL (`cloudflare/circl`) is the backend for the
validated slice; **HSM-backed (softhsmv3 via `miekg/pkcs11`)** is the lead finish-plan item.

## 2. Pinned upstream

- Repo: `github.com/sigstore/cosign`
- Tag / rev: _TBD (recorded after clone)_
- Go toolchain: _TBD_

## 3. Patch surface

_TBD — list of files touched and why._

## 4. Validated slice — evidence

_TBD — verbatim build + sign + verify output proving ML-DSA-65._

## 5. Rekor / transparency-log implications

_TBD — does Rekor accept ML-DSA? Honest assessment._

## 6. HSM path (finish-plan lead item)

_TBD — softhsmv3 via miekg/pkcs11; ML-DSA mech codepoint; never extract key._

## 7. Sandbox wiring

_TBD — Dockerfile.network swap + tests/34 changes (described, not applied to sandbox repo)._

## 8. Remaining work + effort

_TBD._
