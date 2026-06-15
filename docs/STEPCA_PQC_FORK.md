# step-ca PQC Fork — HSM-backed ML-DSA-65 CA (Sandbox Scenario 18)

strongSwan-style patch fork of `smallstep/certificates` (step-ca) that makes the
CA issue a **fully post-quantum X.509 chain** — a self-signed **ML-DSA-65 root**
(FIPS 204) issuing **ML-DSA-65 leaves** — with the root key held in (and never
leaving) a **softhsmv3 PKCS#11 token**. Companion patch:
[`../step-ca-pqc.patch`](../step-ca-pqc.patch).

## Status

| Milestone | State |
|-----------|-------|
| Upstream pinned | ✅ v0.30.2 (rev `6e8ec61405239cf3f37b2bbf260a587b7d2e4e31`) |
| Patch | ✅ `step-ca-pqc.patch` (8 files, +749) |
| Builds (CGO=0 step-ca + CGO=1 mldsa-issue) | ✅ from a pristine v0.30.2 clone |
| ML-DSA issuance proven | ✅ unit test + `openssl verify` of a full ML-DSA chain (§3) |
| Fully-PQC chain (ML-DSA subject key + sig) | ✅ root **and** leaf are ML-DSA-65 |
| **HSM-backed CA key (softhsmv3, non-extractable)** | ✅ verified against the native module (§4) |
| Sandbox wired (`tests/18` + Dockerfile) | ✅ real forked step-ca, HSM-first (§5) |
| `step ca` ACME/provisioner ML-DSA surface | ⬜ remaining finish item (§7) |

## 1. Pinned version

- Upstream: `github.com/smallstep/certificates`, tag `v0.30.2`, rev `6e8ec61…`
- Software ML-DSA backend: `cloudflare/circl v1.6.3` (`sign/mldsa/mldsa65`, pure Go)
- HSM ML-DSA backend: `miekg/pkcs11 v1.1.2` → softhsmv3 (`CKM_ML_DSA`). step-ca
  already links `miekg/pkcs11` via its PKCS#11 KMS, so CGO was already required.
- Built/verified with go1.26.4 (darwin/arm64) against OpenSSL 3.6 and the native
  `libsofthsmv3` module.
- Sandbox baseline before this fork: `Dockerfile.network` cloned step-ca
  `--depth 1` at **HEAD of `master` (unpinned)** and `tests/18_test_stepca.sh`
  faked PQC with raw `openssl` — step-ca was built but **never issued anything**.

## 2. Patch surface (`step-ca-pqc.patch`, 8 files, +749)

| File | Change |
|------|--------|
| `cas/softcas/softcas.go` | 6-line dispatch: when the issuer signer's **public key** is ML-DSA-65, route `CreateCertificate` through `createMLDSACertificate` instead of Go's `x509.CreateCertificate`. Keying on the public-key type means software and HSM signers share the path. |
| `cas/softcas/mldsa.go` (NEW) | Hand-assembles the RFC 5280 TBSCertificate with the ML-DSA-65 `AlgorithmIdentifier` (OID `2.16.840.1.101.3.4.3.18`, no params per RFC 9881), signs the TBS through a `crypto.Signer` (pure ML-DSA, empty context). `subjectPublicKeyInfo()` also hand-encodes an ML-DSA-65 `SubjectPublicKeyInfo` (Go's `MarshalPKIXPublicKey` can't), enabling a fully-PQC chain. `CreateMLDSACertificate` exported for root self-issuance. |
| `cas/softcas/pkcs11mldsa.go` (NEW, `//go:build cgo`) | `PKCS11MLDSASigner`: a `crypto.Signer` whose ML-DSA-65 key is generated on a PKCS#11 token as `CKA_SENSITIVE` + `CKA_EXTRACTABLE=false`; `Sign` is `C_Sign(CKM_ML_DSA=0x1D)` inside the module. Keygen template (`CKM_ML_DSA_KEY_PAIR_GEN=0x1C`, `CKA_PARAMETER_SET=CKP_ML_DSA_65`) mirrors the platform's verified PyKCS11 path (`tests/_ssh_seed.sh`). |
| `cas/softcas/pkcs11mldsa_nocgo.go` (NEW, `//go:build !cgo`) | Stub so `cas/softcas` compiles under step-ca's default `CGO_ENABLED=0 make build`; `NewPKCS11MLDSASigner` returns a clear "requires cgo" error. |
| `cas/softcas/mldsa_test.go` (NEW) | `TestSoftCAS_CreateCertificate_MLDSA65` — drives SoftCAS end-to-end, asserts the OID + ML-DSA signature verify. |
| `cmd/mldsa-issue/main.go` (NEW, demo only) | Self-signs an ML-DSA-65 root and issues a leaf via the real SoftCAS engine, writing both PEMs (`-ca-out`/`-out`). `-hsm` keeps the CA key in softhsmv3; `-algo ec` exercises the classical path. Drives sandbox scenario 18. |
| `go.mod` / `go.sum` | add `cloudflare/circl v1.6.3` + `miekg/pkcs11 v1.1.2` (minimal; no other module perturbed). |

Classical RSA/EC/Ed25519 issuance paths are untouched (the dispatch only diverts
ML-DSA issuers).

## 3. Validated-slice evidence (verbatim, from a clean v0.30.2 clone, no `go mod tidy`)

```console
$ git apply step-ca-pqc.patch && make build            # step-ca, CGO_ENABLED=0
Build Complete!
$ go test ./cas/softcas/ -run MLDSA
ok  github.com/smallstep/certificates/cas/softcas

$ CGO_ENABLED=1 go build -o mldsa-issue ./cmd/mldsa-issue
$ ./mldsa-issue -algo mldsa65 -ca-out ca.pem -out leaf.pem
algo=mldsa65 root_ca="PQC ML-DSA-65 Root CA" leaf="leaf.pqc.test" ...
$ openssl x509 -in ca.pem   -noout -text | grep -m1 'Public Key Algorithm'   # ML-DSA-65
$ openssl x509 -in leaf.pem -noout -text | grep -m1 'Signature Algorithm'    # ML-DSA-65
$ openssl verify -CAfile ca.pem leaf.pem
leaf.pem: OK
```

The root CA's **subject key and signature are both ML-DSA-65**, the leaf is
ML-DSA-65-signed, and an **independent OpenSSL 3.6** verifies the whole chain.

## 4. HSM-backed CA key — verified

The CA's ML-DSA-65 private key is generated in, and never leaves, a softhsmv3
PKCS#11 token. Verified against the **native `libsofthsmv3`** module + an
initialized token:

```console
$ softhsm2-util --module libsofthsmv3.* --init-token --slot 0 \
    --label pqc-playground --so-pin 123456 --pin 1234
$ ./mldsa-issue -hsm -module libsofthsmv3.* -token pqc-playground -pin 1234 \
    -ca-out ca.pem -out leaf.pem
ca_key_custody=PKCS#11 token "pqc-playground" ... (CKM_ML_DSA, non-extractable)
$ openssl verify -CAfile ca.pem leaf.pem
leaf.pem: OK
```

- **Token residency proof:** a second `-hsm` run produces the *identical* CA
  public key (same SHA-256) — the key persists on the token (`CKA_TOKEN=true`)
  and is reused, not regenerated.
- **Non-extractable:** generated with `CKA_SENSITIVE=true`, `CKA_EXTRACTABLE=false`
  (softhsmv3 enforces these; the private key value cannot be read out).
- **Signing happens in the HSM:** every cert signature is a `C_Sign(CKM_ML_DSA)`
  call into the module; only TBS assembly happens in-process.
- softhsmv3 already implements ML-DSA-65 (`OSSLMLDSA.cpp`, `SoftHSM_sign.cpp`
  `CKM_ML_DSA` → `AsymMech::MLDSA`) — no HSM-side crypto work was needed.

## 5. Sandbox wiring (scenario 18) — done

- `docker/Dockerfile.network`: step-ca clone pinned to **v0.30.2**, applies
  `pqctoday-hsm/step-ca-pqc.patch` (COPY + `git apply`), `make build`, and builds
  `mldsa-issue` with `CGO_ENABLED=1`. The token `pqc-playground` (PIN `1234`) is
  already initialized earlier in the image, and the module installs at
  `/usr/local/lib/softhsm/libsofthsmv3.so` — exactly the defaults `mldsa-issue`
  uses, so `-hsm` works in-image with no extra config.
- `tests/18_test_stepca.sh`: layered, honest issuance —
  1. **pqc** → `mldsa-issue -hsm` (HSM-backed ML-DSA-65 chain) → `hsm_backed:true`,
     `_simulated:false`;
  2. if the token is unavailable → in-software forked step-ca (`hsm_backed:false`,
     still `_simulated:false`, custody note says "software fallback");
  3. **classical** → `mldsa-issue -algo ec` (EC P-256, step-ca's default);
  4. if `mldsa-issue` is absent (image not rebuilt) → openssl fallback, honestly
     `_simulated:true` (does **not** claim step-ca did the work).
  Every path verifies the chain with `openssl verify` and emits `ca_engine`,
  `issuance_path`, `key_custody`, `hsm_backed`.

## 6. Standardization caveat

ML-DSA in X.509 is governed by emerging IETF LAMPS work
(`draft-ietf-lamps-dilithium-certificates` + PKIX algorithm-id drafts). The OID
`2.16.840.1.101.3.4.3.18` (NIST CSOR, ML-DSA-65) is stable, but broad
client/library support — incl. Go's `crypto/x509` — is still landing, hence the
hand-assembled `signatureAlgorithm`/SPKI (same approach as the strongSwan PQC
patch). OpenSSL 3.6 verifies the emitted chains today.

## 7. Remaining work

| Item | Effort |
|------|--------|
| Wire the running `step ca` server / provisioner + ACME to **select** ML-DSA (vs the `cmd/mldsa-issue` SoftCAS harness) | 1–2 d |
| ML-DSA-44/87 parameter sets | 0.5 d |
| CSR-driven leaf issuance (subject CSR path) through the HSM signer | 1 d |
| `docker build` of the full pqc-network image + in-container scenario-18 run (verified here by replaying the build steps on a pristine clone + against the native module; full image build not yet run) | 0.5 d |

## 8. Status

Patch verified to apply cleanly to a pristine v0.30.2 clone and to build
(`make build` CGO=0 for step-ca; `CGO_ENABLED=1` for `mldsa-issue`), pass the
unit test, and issue a **fully post-quantum, HSM-backed** ML-DSA-65 chain that
OpenSSL 3.6 verifies. Sandbox scenario 18 is wired to it (HSM-first, honest
fallbacks). No push, no PR, no `pqctoday-org` repo; full image build deferred.
