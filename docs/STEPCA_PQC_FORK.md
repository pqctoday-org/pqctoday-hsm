# step-ca PQC Fork — ML-DSA-65 Certificate Issuance (Sandbox Scenario 18)

Strong-style patch fork of `smallstep/certificates` (step-ca) that makes the CA
issue X.509 certificates **signed with ML-DSA-65** (FIPS 204). Companion patch:
[`../step-ca-pqc.patch`](../step-ca-pqc.patch).

## Status

| Milestone | State |
|-----------|-------|
| Upstream pinned | ✅ v0.30.2 (rev `6e8ec61405239cf3f37b2bbf260a587b7d2e4e31`) |
| Patch drafted | ✅ `step-ca-pqc.patch` (6 files, +416) |
| Builds | ✅ `go build ./cas/softcas/...` green |
| ML-DSA issuance proven | ✅ unit test + demo issuer + openssl-confirmed (see §3) |
| Finish plan written | ✅ this doc |

## 1. Pinned version

- Upstream: `github.com/smallstep/certificates`
- Tag: `v0.30.2`, rev `6e8ec61405239cf3f37b2bbf260a587b7d2e4e31`
- ML-DSA backend (slice): `cloudflare/circl v1.6.3` (`sign/mldsa/mldsa65`, pure Go)
- Built/verified with Go (darwin/arm64) against OpenSSL 3.6 (for the openssl cert check only)
- Sandbox baseline: `pqctoday-sandbox/docker/Dockerfile.network` currently clones
  `smallstep/certificates` `--depth 1` at **HEAD of `master` (unpinned)`; this fork
  pins **v0.30.2** and records the rev for reproducibility.

## 2. Patch surface (`step-ca-pqc.patch`, 6 files, +416)

| File | Change |
|------|--------|
| `cas/softcas/mldsa.go` (NEW) | ML-DSA-65 signer over `cloudflare/circl`; builds + self-signs/leaf-signs a `*x509.Certificate` by hand-assembling the TBS + ML-DSA `signatureAlgorithm` (OID `2.16.840.1.101.3.4.3.18`), bypassing Go's `x509` algorithm whitelist (Go has no ML-DSA OID yet) |
| `cas/softcas/mldsa_test.go` (NEW) | `TestSoftCAS_CreateCertificate_MLDSA65` — issues a leaf, asserts the signature-algorithm OID + the 3309-byte signature length |
| `cas/softcas/softcas.go` | ~6-line dispatch: when the CA signer is an ML-DSA key, route `CreateCertificate` through the new ML-DSA path instead of Go's stdlib `x509.CreateCertificate` |
| `cmd/mldsa-issue/main.go` (NEW) | standalone demo: builds an ML-DSA-65 CA via softcas, issues a leaf, writes the PEM — the validated-slice harness |
| `go.mod` / `go.sum` | add `github.com/cloudflare/circl v1.6.3` |

Classic RSA/EC/Ed25519 issuance paths are untouched.

## 3. Validated-slice evidence (verbatim, re-run from a clean v0.30.2 clone)

```
$ go build ./cas/softcas/...
BUILD OK

$ go test ./cas/softcas/ -run MLDSA -v
=== RUN   TestSoftCAS_CreateCertificate_MLDSA65
    mldsa_test.go:80: issued leaf CN="leaf.pqc.test" serial=1234567890
    mldsa_test.go:81: signatureAlgorithm OID = 2.16.840.1.101.3.4.3.18 (ML-DSA-65)
    mldsa_test.go:82: signature length = 3309 bytes
--- PASS: TestSoftCAS_CreateCertificate_MLDSA65 (0.00s)
ok  github.com/smallstep/certificates/cas/softcas

$ go run ./cmd/mldsa-issue/
issued leaf CN="leaf.pqc.test" ...
wrote /tmp/stepca-mldsa-leaf.pem

$ openssl x509 -in /tmp/stepca-mldsa-leaf.pem -text -noout | grep 'Signature Algorithm'
        Signature Algorithm: ML-DSA-65
    Signature Algorithm: ML-DSA-65
```

3309 bytes is the exact FIPS 204 ML-DSA-65 signature size, and an **independent
OpenSSL 3.6** parse of the emitted cert confirms `Signature Algorithm: ML-DSA-65`.

> **Scope nuance (not a gap):** the slice proves ML-DSA **issuance** — the CA
> *signs* the leaf with its ML-DSA-65 key. The leaf's *own* subject key in the
> demo is EC/P-256 (`id-ecPublicKey`). Issuing certs whose **subject key** is
> ML-DSA is a finish item (§5), independent of the signing proof.

## 4. HSM-backing path (lead finish item)

The slice signs in-process with `cloudflare/circl`. The HSM-backed target keeps
the CA's ML-DSA private key in **softhsmv3** (the platform's HSM-first directive):

- step-ca already has a `kms` abstraction with a **PKCS#11** provider; the CA
  signer is a `crypto.Signer`. Replace the in-software circl signer with a
  PKCS#11-backed ML-DSA signer that calls softhsmv3 `CKM_ML_DSA` (**0x1D**) via
  `miekg/pkcs11` (softhsmv3 already implements ML-DSA-65 — no HSM-side crypto work).
- The same Go-`x509`-has-no-ML-DSA-OID bypass used in the slice (hand-assembled
  `signatureAlgorithm`) carries over; only the signing call changes from circl to
  the PKCS#11 `C_Sign`.
- Estimate: ~3–5 d (the `miekg/pkcs11` ML-DSA mechanism plumbing in step-ca's
  pkcs11 kms wrapper is the bulk; mirrors the cosign HSM finish item).

## 5. Sandbox wiring (scenario 18)

**Today's gap (confirmed):** `pqctoday-sandbox/tests/18_test_stepca.sh` fakes the
PQC path — it builds the CA cert and leaf with raw `openssl genpkey -algorithm
mldsa65` + `openssl req -x509`/`openssl x509 -req`, and only *mentions*
`step ca init --key-type` in the `config_applied` string. **step-ca is built in
the image but never performs the ML-DSA issuance.** This fork makes it real.

Steps to flip scenario 18 to `_simulated:false`:
1. `docker/Dockerfile.network` — pin the step-ca clone to **v0.30.2** and apply
   `pqctoday-hsm/step-ca-pqc.patch` (strongSwan-style: COPY patch + `git apply`)
   before `make build`. (Go build already present in the image.)
2. `tests/18_test_stepca.sh` — drive **real step-ca** ML-DSA issuance (the
   `cmd/mldsa-issue` path, or `step ca` proper once the kms/provisioner surface
   accepts ML-DSA) instead of the openssl simulation; verify the issued cert's
   `signatureAlgorithm` is ML-DSA-65 via openssl; emit `_simulated:false`,
   `signature_algo:"ML-DSA-65"`, `ca_engine:"step-ca (forked)"`.
3. README scenario-18 row + `docs/18-*.md` — describe real step-ca ML-DSA issuance.

## 6. Standardization caveat

ML-DSA in X.509 certificates is governed by the emerging IETF LAMPS work
(`draft-ietf-lamps-dilithium-certificates` and the PKIX algorithm-identifier
drafts). The OID `2.16.840.1.101.3.4.3.18` (NIST CSOR, ML-DSA-65) is stable, but
broad client/library support (incl. Go's `crypto/x509`) is still landing — hence
the hand-assembled signatureAlgorithm. This fork is forward-looking; it proves
the CA tooling + crypto are ready.

## 7. Remaining work to fully close scenario 18

| Item | Effort |
|------|--------|
| HSM-backed CA signer (softhsmv3 via `miekg/pkcs11`, `CKM_ML_DSA` 0x1D) — §4 | 3–5 d |
| ML-DSA **subject-key** issuance (not just ML-DSA-signed) + CSR path | 1–2 d |
| Wire the `step ca` / provisioner surface (vs the demo `cmd/mldsa-issue`) to accept ML-DSA | 1–2 d |
| Sandbox: Dockerfile pin+patch, `tests/18` rewrite, README/docs — §5 | 1–2 d |
| **Total** | **~L (6–11 d)** — aligns with the master plan's "L" estimate |

## 8. Status

Validated slice committed; patch verified to apply cleanly to a pristine v0.30.2
clone and to build + issue an ML-DSA-65-signed cert (openssl-confirmed). No push,
no PR, no `pqctoday-org` repo. Sandbox wiring is deferred (§5).
