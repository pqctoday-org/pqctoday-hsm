# step-ca PQC Fork — HSM-backed ML-DSA CA + running server (Sandbox Scenario 18)

strongSwan-style patch fork of `smallstep/certificates` (step-ca) that makes the
CA issue a **fully post-quantum X.509 chain** — a self-signed **ML-DSA root**
(FIPS 204, **ML-DSA-44/65/87**) issuing **ML-DSA leaves** — with the issuing key
held in (and never leaving) a **softhsmv3 PKCS#11 token**, and a **running
`step-ca` server** that boots on that HSM-backed ML-DSA CA and serves HTTPS +
ACME. The leaf subject-key algorithm is selectable independently of the CA
(any ML-DSA parameter set or classical EC). Companion patch:
[`../step-ca-pqc.patch`](../step-ca-pqc.patch).

## Status

| Milestone | State |
|-----------|-------|
| Upstream pinned | ✅ v0.30.2 (rev `6e8ec61405239cf3f37b2bbf260a587b7d2e4e31`) |
| Patch | ✅ `step-ca-pqc.patch` (10 files, +1135) |
| Builds (CGO=0 step-ca + CGO=1 mldsa-issue; CGO=1 step-ca for the server) | ✅ from a pristine v0.30.2 clone |
| ML-DSA-44/65/87 issuance | ✅ all three; software + HSM, each `openssl verify` OK (§3) |
| Leaf subject-key selection (any ML-DSA set or EC, independent of CA) | ✅ verified (e.g. ML-DSA-87 CA → EC leaf; ML-DSA-65 CA → ML-DSA-44 leaf) |
| Fully-PQC chain (ML-DSA subject key + sig) | ✅ root **and** leaf are ML-DSA |
| **HSM-backed CA key (softhsmv3, non-extractable)** | ✅ verified against the native module (§4) |
| **Running `step-ca` server (HSM ML-DSA CA, HTTPS + ACME)** | ✅ boots + issues; openssl-verified (§6) |
| Sandbox wired (`tests/18` + Dockerfile) | ✅ real forked step-ca, HSM-first (§5) |
| ML-DSA-capable external client (step CLI / lego) | ⬜ Go/LibreSSL can't verify ML-DSA chains (§7 boundary) |

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

## 2. Patch surface (`step-ca-pqc.patch`, 10 files, +992)

| File | Change |
|------|--------|
| `cas/softcas/softcas.go` | 6-line dispatch: when the issuer signer's **public key** is ML-DSA-65, route `CreateCertificate` through `createMLDSACertificate` instead of Go's `x509.CreateCertificate`. Keying on the public-key type means software and HSM signers share the path. |
| `cas/softcas/mldsa.go` (NEW) | Hand-assembles the RFC 5280 TBSCertificate with the ML-DSA-65 `AlgorithmIdentifier` (OID `2.16.840.1.101.3.4.3.18`, no params per RFC 9881), signs the TBS through a `crypto.Signer` (pure ML-DSA, empty context), and generates a random serial when the template leaves it nil (step-ca's `GetTLSCertificate` does). `subjectPublicKeyInfo()` hand-encodes an ML-DSA-65 `SubjectPublicKeyInfo` (Go's `MarshalPKIXPublicKey` can't), enabling a fully-PQC chain. `CreateMLDSACertificate` exported for root self-issuance. |
| `cas/softcas/pkcs11mldsa.go` (NEW, `//go:build cgo`) | `PKCS11MLDSASigner`: a `crypto.Signer` whose ML-DSA-65 key is generated on a PKCS#11 token as `CKA_SENSITIVE` + `CKA_EXTRACTABLE=false`; `Sign` is `C_Sign(CKM_ML_DSA=0x1D)` inside the module. Keygen template (`CKM_ML_DSA_KEY_PAIR_GEN=0x1C`, `CKA_PARAMETER_SET=CKP_ML_DSA_65`) mirrors the platform's verified PyKCS11 path (`tests/_ssh_seed.sh`). Tolerates a module already `C_Initialize`'d in-process. |
| `cas/softcas/pkcs11mldsa_nocgo.go` (NEW, `//go:build !cgo`) | Stub so `cas/softcas` compiles under a `CGO_ENABLED=0` build; `NewPKCS11MLDSASigner` returns a clear "requires cgo" error. |
| `kms/mldsahsm/mldsahsm.go` (NEW) | In-repo step-ca KMS (type `mldsahsm`) that returns the `PKCS11MLDSASigner`, so a **running** `step-ca` server can load an ML-DSA-65 issuing CA whose key lives in the HSM — `softkms` can't load an ML-DSA key and the upstream PKCS#11 KMS doesn't recognize `CKK_ML_DSA`. |
| `cmd/step-ca/main.go` | +1 blank import to register the `mldsahsm` KMS. |
| `cas/softcas/mldsa_test.go` (NEW) | `TestSoftCAS_CreateCertificate_MLDSA65` — drives SoftCAS end-to-end, asserts the OID + ML-DSA signature verify. |
| `cmd/mldsa-issue/main.go` (NEW, demo only) | Issues a full ML-DSA-65 chain via the real SoftCAS engine (`-ca-out`/`-out`); `-hsm` keeps the CA key in softhsmv3; `-bootstrap-ca` builds a step-ca PKI (software ML-DSA root signing an HSM-keyed ML-DSA intermediate); `-algo ec` exercises the classical path. Drives sandbox scenario 18. |
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
  `pqctoday-hsm/step-ca-pqc.patch` (COPY + `git apply`), `make build GOFLAGS=""`
  (CGO=1 — step-ca's official PKCS#11 switch, so the installed `step-ca` can also
  run as an HSM server, §6), and builds `mldsa-issue` with `CGO_ENABLED=1`. The
  token `pqc-playground` (PIN `1234`) is already initialized earlier in the image,
  and the module installs at `/usr/local/lib/softhsm/libsofthsmv3.so` — exactly the
  defaults `mldsa-issue`/`mldsahsm` use, so `-hsm` works in-image with no config.
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

## 6. Running step-ca server (HSM-backed ML-DSA CA + ACME) — verified

A *running* `step-ca` can use an ML-DSA-65 issuing CA whose key lives in the HSM.
Two pieces make this work: the `mldsahsm` KMS (loads the HSM ML-DSA signer at
boot — `softkms` can't), and the random-serial fix (step-ca's `GetTLSCertificate`
leaves the serial nil for the CAS to fill). `step-ca` must be built with cgo —
the same requirement as its upstream PKCS#11 KMS — via `make build GOFLAGS=""`.

```console
# Bootstrap a PKI: software ML-DSA-65 root signing an HSM-keyed ML-DSA-65 intermediate
$ mldsa-issue -bootstrap-ca -token pqc-playground -pin 1234 -key-label stepca-int \
    -ca-out root.crt -int-out intermediate.crt

# ca.json: kms.type=mldsahsm, key=mldsahsm:object=stepca-int;..., crt=intermediate.crt
$ step-ca ca.json
... Building new tls configuration using step-ca x509 Signer Interface
... Serving HTTPS on 127.0.0.1:9443 ...

# OpenSSL 3.6 verifies the live server's chain (its own API leaf, ML-DSA-65-signed)
$ openssl s_client -connect 127.0.0.1:9443 -CAfile root.crt </dev/null
  subject=CN=Step Online CA
  issuer=CN=PQC ML-DSA-65 Intermediate CA (HSM)
  Verify return code: 0 (ok)            # leaf -> ML-DSA int (HSM) -> ML-DSA root
# leaf Signature Algorithm: ML-DSA-65 ; leaf subject key: id-ecPublicKey
# ACME directory live: GET /acme/acme/directory -> {"newNonce":...,"newOrder":...}
```

- The server mints its **own API TLS leaf through the real issuance path**
  (`GetTLSCertificate` → `x509CAService.CreateCertificate` → the ML-DSA dispatch →
  `C_Sign(CKM_ML_DSA)` in the HSM) — i.e. the server *is already issuing* ML-DSA-65
  certs. The leaf's **subject key is EC P-256** (`keyutil.GenerateDefaultKey`), so
  Go's TLS stack can serve it; it is **ML-DSA-65-signed** by the HSM intermediate.
- The `/1.0/sign` (JWK) and ACME-finalize paths call the **same**
  `x509CAService.CreateCertificate`, so they issue ML-DSA-65 leaves identically;
  the provisioner layer is pure authorization.
- Verified end-to-end from a **pristine v0.30.2 clone** (`make build GOFLAGS=""`).

## 7. Clients (ecosystem note)

ML-DSA chain *verification* needs OpenSSL ≥ 3.5. The **pqc-network image ships
`curl 8.5.0` linked against the custom OpenSSL 3.6.2** (`libssl.so.3 =>
/usr/local/ssl/lib`), so **plain `curl --cacert root.crt https://…` verifies the
ML-DSA chain in-container** (confirmed against the live server, §6). What does
*not* work: Go's `crypto/tls`+`crypto/x509` (the `step` CLI, `lego`) and LibreSSL
(e.g. the macOS system curl) — they can't verify ML-DSA chains. This is purely a
client-side ecosystem gap; the server issues correctly regardless. The
hand-assembled `signatureAlgorithm`/SPKI (same approach as the strongSwan PQC
patch) exists because the Go stdlib has no ML-DSA support; ML-DSA in X.509 is
still landing in IETF LAMPS (`draft-ietf-lamps-dilithium-certificates`), though
the OIDs `2.16.840.1.101.3.4.3.17/18/19` (NIST CSOR) are stable.

## 8. Remaining work

| Item | Status |
|------|--------|
| ML-DSA-44/87 parameter sets | ✅ done (§3); verified in-container |
| Selectable leaf **subject-key** algorithm (CSR key selection) | ✅ done — `-leaf-algo`; any ML-DSA set or EC |
| In-sandbox server-mode demo (`tests/18b_test_stepca_server.sh` + `/api/run/stepca-server`) | ✅ done; in-container chain verified by **curl (OpenSSL 3.6.2)** |
| Full pqc-network `docker build` + in-container scenario run | ✅ done (see §9) |
| Issuing leaves whose subject key is ML-DSA **from an externally-submitted CSR** | ⬜ blocked: Go can't parse an ML-DSA CSR SPKI (we self-generate the leaf key; classical CSRs work) |

## 9. Status — validated in the production Linux image

Built the full `pqc-network` image (`docker compose build`, Debian/aarch64,
step-ca via `make build GOFLAGS=""`). In-container results:

- **Scenario 18 (issuance):** `mldsa-issue -hsm` → `hsm_backed:true`,
  `chain_verified:true`, `_simulated:false`, ML-DSA-65 from the softhsmv3 token;
  classical mode → ECDSA-P256, verified.
- **Scenario 18b (live server):** the forked `step-ca` boots on the HSM-backed
  ML-DSA CA via the `mldsahsm` KMS and serves HTTPS + ACME; the chain is verified
  by **`curl (OpenSSL 3.6.2)`** in-container — `server_boot:true`,
  `chain_verified:true`, `acme_directory_ok:true` — for both ML-DSA-65 and
  ML-DSA-87 issuing CAs.

Also verified from a pristine v0.30.2 clone (apply → build both CGO modes → unit
test → openssl-verified chains, software + HSM). No push, no PR, no `pqctoday-org`
repo.
