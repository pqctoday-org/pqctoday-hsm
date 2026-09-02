# cosign PQC Fork — ML-DSA-65 Artifact Signing (Scenario 34)

strongSwan-pattern fork of `sigstore/cosign`: a minimal diff against a pinned
upstream tag, shipped as a `.patch` (`cosign-pqc.patch`) plus this finish plan.
No push, no PR, no GitHub repo. Master plan reference:
`pqctoday-sandbox/tasks/scenario-claims-fix-plan-06032026.md` §P2-COSIGN.

**Status: complete + validated in the production Linux image (§10).** The real
`cosign sign-blob`/`verify-blob` CLI signs OCI manifests and SBOMs with ML-DSA-65
(FIPS 204), with the signing key held in **softhsmv3** (HSM-resident,
non-extractable) via the `mldsa-pkcs11:` scheme, or in-process via CIRCL.

## 1. Goal

A cosign that signs a blob with **ML-DSA-65 (FIPS 204)** and verifies it, on the
real binary. ML-DSA plugs into cosign's `signature.SignerVerifier` interface —
the exact seam cosign uses for ECDSA/RSA/Ed25519 — with two backends: pure-Go
`cloudflare/circl` (file key) and **HSM-resident `softhsmv3` via `miekg/pkcs11`**
(`C_Sign(CKM_ML_DSA)`, key never leaves the token).

## 2. Pinned upstream

| Field | Value |
|---|---|
| Repo | `github.com/sigstore/cosign` (module `github.com/sigstore/cosign/v3`) |
| Tag | `v3.0.6` |
| Rev (HEAD) | `f1ad3ee952313be5d74a49d67ba0aa8d0d5e351f` |
| go.mod toolchain | `go 1.25.7` |
| Built/tested with | `go1.26.4 darwin/arm64` |
| PQC backend dep | `github.com/cloudflare/circl v1.6.3` |

> Master plan targets v3.0.6 (sandbox currently ships the cosign v2.4.3 binary
> download in `docker/Dockerfile.network`). v3.0.6 confirmed available + builds.

## 3. Patch surface (`cosign-pqc.patch`)

9 files, +810/-4 lines (`git apply --stat`) — the CIRCL signer, the binary-CLI
wiring (§7/§8), and the in-tree PKCS#11/HSM backend (§6/§8) are all in this one
patch now:

| File | Change |
|---|---|
| `go.mod` | `+ github.com/cloudflare/circl v1.6.3` (tidy promotes to direct require) |
| `go.sum` | `+` two circl checksum lines |
| `pkg/signature/mldsa/mldsa65.go` | **NEW** — `SignerVerifier` implementing sigstore's `signature.Signer` + `Verifier` + `SignerVerifier` over CIRCL `mldsa65`; PEM marshal/load + `IsPrivateKeyPEM`/`IsPublicKeyPEM` branch helpers |
| `pkg/signature/mldsa/mldsa65_test.go` | **NEW** — sign→verify round-trip, tamper-rejection, PEM-load tests |
| `pkg/signature/mldsa/pkcs11.go` | **NEW** (`//go:build cgo`) — `PKCS11SignerVerifier`: HSM-resident ML-DSA-65 signing over the `mldsa-pkcs11:` key-ref scheme, `C_Sign(CKM_ML_DSA)` inside the token (§6) |
| `pkg/signature/mldsa/pkcs11_nocgo.go` | **NEW** (`//go:build !cgo`) — stub `PKCS11SignerVerifier` that errors clearly on a `CGO_ENABLED=0` build |
| `pkg/signature/keys.go` | ML-DSA branches in `VerifierForKeyRef` (incl. the `mldsa-pkcs11:` scheme), `loadKey`, and `PublicKeyPem` (§7) |
| `internal/key/svkeypair.go` | ML-DSA branch in `NewSignerVerifierKeypair` (+ `GetHashAlgorithm`/`GetPublicKeyPem`) so the keypair adapter handles a non-x509-marshalable key (§7) |
| `cmd/cosign/cli/generate/generate_key_pair.go` | `COSIGN_KEY_ALGORITHM=ml-dsa-65` keygen branch (§7) |

### Design decisions

- **Interface seam, not algorithm fork.** ML-DSA-65 is a drop-in
  `signature.SignerVerifier`. cosign's `pkg/signature/keys.go` loaders
  (`SignerVerifierFromKeyRef`, `VerifierForKeyRef`) already return that
  interface; the CLI wiring added one branch each (done — see §7/§8).
- **Pure ML-DSA (no pre-hash).** `SignMessage` consumes the whole message and
  calls `mldsa65.SignTo` (FIPS 204 hashes internally). Empty signing context,
  matching cosign's context-free blob signing. Randomized (hedged) signing per
  FIPS 204 recommendation.
- **Custom PEM types** (`ML-DSA-65 PRIVATE KEY` / `ML-DSA-65 PUBLIC KEY`)
  carrying raw FIPS 204 packed bytes — because Go 1.26 `crypto/x509` has **no
  ML-DSA OID support** (no `ParsePKCS8PrivateKey` / `MarshalPKIXPublicKey`
  path). This is the same reason the binary CLI needed dedicated ML-DSA
  branches (done — §7/§8).
- ML-DSA-65 sizes (FIPS 204): public key 1952 B, private key 4032 B,
  **signature 3309 B** (confirmed by the test, §4).

## 4. Validated slice — evidence (verbatim)

Reproduce from a clean checkout:

```
git clone --depth 1 --branch v3.0.6 https://github.com/sigstore/cosign.git
cd cosign
git apply /path/to/cosign-pqc.patch
go mod tidy
go test -v -count=1 ./pkg/signature/mldsa/
```

Output (fresh `v3.0.6` tree, patch applied, `go1.26.4 darwin/arm64`):

```
=== RUN   TestSignVerifyRoundTrip
    mldsa65_test.go:47: ML-DSA-65 signature: 3309 bytes (FIPS 204 SignatureSize=3309)
    mldsa65_test.go:52: verify OK: ML-DSA-65 sign->verify round-trip succeeded
--- PASS: TestSignVerifyRoundTrip (0.00s)
=== RUN   TestTamperedMessageFails
    mldsa65_test.go:70: verify correctly rejected tampered message
--- PASS: TestTamperedMessageFails (0.00s)
=== RUN   TestPEMRoundTrip
    mldsa65_test.go:113: verify OK: PEM marshal/load round-trip, pub-only key verified signer's signature
--- PASS: TestPEMRoundTrip (0.00s)
PASS
ok  	github.com/sigstore/cosign/v3/pkg/signature/mldsa	0.213s
```

This proves the slice goal: ML-DSA-65 **sign a blob → verify** succeeds,
verification **rejects tampering**, and a key survives **PEM marshal → load**
with the public-only key verifying the signer's signature — all through the
`signature.SignerVerifier` interface cosign consumes.

## 5. Rekor / transparency-log implications (honest assessment)

**Rekor does not accept ML-DSA today.** Concretely:

- Rekor's `hashedrekord` (v0.0.1 / v0.0.2) entry types validate the embedded
  public key and signature via `sigstore/sigstore`'s signature package, whose
  **algorithm registry has no ML-DSA entry** (verified: no `ML-DSA`/`mldsa`
  match in `sigstore@v1.10.5/pkg/signature/algorithm_registry.go`). The public
  key is expected to PEM/DER-decode to an `ecdsa`/`rsa`/`ed25519` key via
  `cryptoutils.UnmarshalPEMToPublicKey` → `x509`, which **cannot represent
  ML-DSA** (Go 1.26 has no ML-DSA OID).
- Rekor's server-side type validation would therefore reject an ML-DSA
  `hashedrekord` entry; the log's own signed-entry-timestamp and Merkle
  inclusion are algorithm-agnostic, but the *entry* never passes type checks.

**Consequence for the fork:** for the validated slice and the sandbox, sign and
verify **without a transparency-log upload** (`cosign sign-blob --tlog-upload=false`
/ `cosign verify-blob --insecure-ignore-tlog`). This is an honest, documented
gap, not a workaround that fakes a log entry. Options for later, in order of
preference:

1. **Wait for upstream** Rekor/sigstore ML-DSA support (the registry + x509 OID
   work is the real blocker; PQC signature types are on the sigstore roadmap but
   not shipped as of these pins). Cheapest; zero fork maintenance.
2. **Run a patched Rekor** in the sandbox that registers ML-DSA in the algorithm
   registry and accepts a raw-bytes public-key encoding. Large, separate fork —
   out of scope for scenario 34's slice.
3. **Keyless/Fulcio is not viable** for ML-DSA (Fulcio issues X.509 certs; same
   x509-OID blocker, plus CA-side policy). Skip.

Recommendation: ship the keypair (`--key`) path with tlog disabled; label the
transparency-log step "pending upstream PQC support" in the sandbox README.

## 6. HSM path (finish-plan lead item — preferred per master plan)

> **Shipped, via a different route than sketched below** (see §8's note). The
> patch does **not** modify the sigstore-vendored `pkcs11key` wrapper described
> in this section; it adds an in-tree `mldsa-pkcs11:` `SignerVerifier`
> (`pkg/signature/mldsa/pkcs11.go`, §3) at the same interface seam. The
> original design reasoning is kept below for context.

The master-plan directive is **HSM-first**: route ML-DSA bytes through
`pqctoday-hsm/softhsmv3` via `miekg/pkcs11`, never extracting the key.

- cosign already has a PKCS#11 path: `pkg/signature/keys.go` →
  `pkcs11key.GetKeyWithURIConfig` → `sk.SignerVerifier()` for `pkcs11:` key
  URIs. That returns a `signature.SignerVerifier` — the **same interface** this
  slice implements.
- cosign's bundled `pkcs11key` wrapper (`github.com/sigstore/sigstore/pkg/signature/pkcs11`,
  on `miekg/pkcs11`) currently maps token keys to ECDSA/RSA only. To reach
  softhsmv3 ML-DSA, the wrapper's `SignerVerifier()` must:
  1. Read `CKA_KEY_TYPE` and recognize `CKK_ML_DSA = 0x4a` with
     `CKA_PARAMETER_SET = CKP_ML_DSA_65` (softhsmv3 vendor mech codepoint
     `0x4036` per master plan; native PKCS#11 v3.2 `CKM_ML_DSA = 0x1d`).
  2. `C_SignInit(CKM_ML_DSA)` / `C_Sign` for signing; `C_Verify` (or local CIRCL
     verify of the exported public key) for verification.
  3. Return a `SignerVerifier` shaped exactly like §3's, but backed by
     `C_Sign` instead of `mldsa65.SignTo`.
- softhsmv3 already implements ML-DSA-44/65/87 (CLAUDE.md "PQC additions"), so
  the HSM side needs no new crypto — only the Go `miekg/pkcs11` mechanism
  plumbing. Validation: softhsmv3 audit log shows the `CKM_ML_DSA` sign call.

This is the bulk of remaining effort (§8) and is where the production fork
should land per the HSM-first preference; the CIRCL slice is the
keypair/`--key file:` fallback documented as acceptable in the master plan.

## 7. Sandbox wiring (described — NOT applied to the sandbox repo)

Per the rules, the sandbox repo is left untouched. When the fork is ready:

- **`docker/Dockerfile.network`** (line ~245): replace the `cosign` binary
  download with a build of this patched source (or a `pqctoday-org/cosign`
  release artifact `v3.0.6+pqctoday`).
- **`tests/34_test_supply_chain_signing.sh`**: drop the OpenSSL fallback; use
  the ML-DSA-65 keypair path. For the slice (tlog-disabled, per §5):
  ```
  cosign sign-blob   --key cosign-mldsa.key --tlog-upload=false \
                     --output-signature blob.sig --yes artifact.tar
  cosign verify-blob --key cosign-mldsa.pub --insecure-ignore-tlog \
                     --signature blob.sig artifact.tar
  ```
  For the HSM path (shipped as the in-tree `mldsa-pkcs11:` scheme, §3/§6, not
  the sigstore-vendored `pkcs11:` scheme):
  `--key 'mldsa-pkcs11:module-path=/usr/local/lib/softhsm/libsofthsmv3.so;token=pqc-playground;object=oci-signer;param-set=65?pin-value=1234'`.

**Binary-CLI wiring — done (§8).** v3.0.6's sign-blob runs through an
`internal/key.SignerVerifierKeypair` adapter (`internal/key/svkeypair.go`)
that, for any key, calls:
- `x509.MarshalPKIXPublicKey(pubKey)` — **fails for ML-DSA** (no x509 OID);
- a `keyAlg` type switch over `ecdsa/rsa/ed25519` only → `"unsupported key type"`;
- `signature.GetDefaultAlgorithmDetails(pubKey)` — **no ML-DSA in the registry**.

So for `cosign sign-blob --key file:mldsa.key` to work end-to-end on the v3.0.6
binary, the fork also had to:
1. Add an ML-DSA branch in `internal/key/svkeypair.go` (`keyAlg = "ML-DSA"`,
   a non-x509 public-key hint, and a fixed `AlgorithmDetails`/hash mapping).
2. Add ML-DSA loader branches in `pkg/signature/keys.go`
   (`SignerVerifierFromKeyRef`/`loadKey` for the private PEM;
   `VerifierForKeyRef` for the public PEM) using `mldsa.IsPrivateKeyPEM` /
   `mldsa.LoadPrivateKeyPEM` etc.
3. Add `ml-dsa-65` to the `generate-key-pair --signing-algorithm` enum.

These were mechanical but touched sigstore-vendored expectations (the keypair
adapter assumes x509-marshalable keys) — see §3 for the resulting file list.

## 8. Remaining work — status

| Item | Status |
|---|---|
| ML-DSA-65 `SignerVerifier` (CIRCL) + tests | ✅ done |
| CLI wiring: `keys.go` loader branches (`VerifierForKeyRef`/`loadKey`/`PublicKeyPem`) + `svkeypair.go` ML-DSA adapter + `generate-key-pair` (`COSIGN_KEY_ALGORITHM=ml-dsa-65`) | ✅ done — `cosign sign-blob/verify-blob --key file:…` works on the binary |
| HSM path: `miekg/pkcs11` `CKM_ML_DSA` → softhsmv3 via the in-tree `mldsa-pkcs11:` `signature.SignerVerifier` | ✅ done — key generated non-extractable on the token; sign = `C_Sign` in the HSM |
| Rekor: tlog-disabled, tracked upstream | ✅ shipped disabled (honest), documented (§5) |
| Sandbox wiring: `Dockerfile.network` build-from-source (CGO=1) + `tests/34` rewrite | ✅ done; validated in-container (§10) |
| ML-DSA leaf **subject key from an externally-submitted CSR** | ⬜ blocked: Go can't parse an ML-DSA CSR SPKI (we self-generate keys; HSM keys live on the token) |
| ML-DSA-44/87 parameter sets via `mldsa-pkcs11:param-set=` | partial: HSM keygen honors the param set; the CIRCL file-key path is ML-DSA-65 only |

> Note: HSM-backing was implemented as an **in-tree** `mldsa-pkcs11:` SignerVerifier
> (cosign repo), not by patching the sigstore-vendored `pkcs11key` wrapper — it
> reuses cosign's `signature.SignerVerifier` seam and avoids a `replace` against
> `go.step.sm`/`sigstore`. The PKCS#11 ML-DSA codepoint is the **standard**
> `CKM_ML_DSA = 0x1D` (the earlier `0x4036` vendor codepoint was retired).

## 9. Provenance / reproducibility

- Only `cosign-pqc.patch` + this doc are committed in `pqctoday-hsm`.
- cosign's `.gitignore` has a bare `signature` entry that hides
  `pkg/signature/mldsa/`; `git apply` ignores `.gitignore`, so the patch lands
  the files correctly (verified from a pristine `v3.0.6` clone).

## 10. Status — validated in the production Linux image

Built the full `pqc-network` image (`docker compose build`, Debian/aarch64) with
the cosign block rebuilt from `v3.0.6` + this patch (`CGO_ENABLED=1`). In-container
`tests/34_test_supply_chain_signing.sh`:

- **PQC:** real forked `cosign v3.0.6` signs the OCI manifest **and** a real
  `syft` SPDX SBOM with an **HSM-resident ML-DSA-65 key** (softhsmv3 token
  `pqc-playground`, non-extractable, `C_Sign(CKM_ML_DSA)`); both `verify-blob`
  → OK. `hsm_backed:true`, `_simulated:false`, `quantum_safe:true`,
  transparency-log honestly disabled.
- **Classical:** real cosign ECDSA-P256 sign/verify of manifest + SBOM.

Also verified from a pristine `v3.0.6` clone (apply → cgo+nocgo build → slice
unit test → file-key and HSM sign/verify, 3309-byte FIPS 204 signatures,
tamper rejected). No push, no PR, no `pqctoday-org` repo.
