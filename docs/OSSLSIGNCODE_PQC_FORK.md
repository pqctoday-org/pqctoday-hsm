# osslsigncode PQC Fork — ML-DSA Authenticode Signing (Scenario 17)

strongSwan-style PQC fork of `osslsigncode` that adds **ML-DSA (FIPS 204)**
support to the Authenticode / PKCS#7 signing path, against **OpenSSL 3.6**
(which implements ML-DSA natively — no third-party PQC library needed).

- Patch: [`osslsigncode-pqc.patch`](../osslsigncode-pqc.patch)
- Master plan row: `pqctoday-sandbox/tasks/scenario-claims-fix-plan-06032026.md`
  §P2-OSSLSIGNCODE (Scenario 17), table rows 77 / 603.
- Status: **COMPLETE (sign + verify), validated in the production Linux image.**
  Patched `osslsigncode` signs a real PE32+ with an ML-DSA-44/65/87 key, embeds a
  cryptographically-valid ML-DSA signature in the Authenticode PKCS#7 (with the
  **messageDigest authenticated attribute binding the content** — see §2/§3.6),
  and `osslsigncode verify` returns **ok** for it (tampered content + wrong CA
  rejected). HSM/PKCS#11-resident keys via the OpenSSL pkcs11-provider remain the
  one finish item (§5/§7). The fundamental Windows-trust caveat (§4) is unchanged.

---

## 1. Pinned version + revision

| Field | Value |
|---|---|
| Upstream | `mtrojnar/osslsigncode` |
| Tag | **2.13** (spec calls for "2.13 stable") |
| Commit | `97a9ade6ec71c4dd41e199079643465af3ee6096` |
| Annotated tag object | `cb129129236e7d014b52ae3131f7387df9c53a6d` |
| Build backend | OpenSSL **3.6.2** (7 Apr 2026); minimum OpenSSL ≥ 3.5 for native ML-DSA |
| Build system | CMake (matches sandbox `Dockerfile.network`) |

### Dockerfile discrepancy to fix (noted, not changed here)

The sandbox `docker/Dockerfile.network` (line 135) currently does:

```dockerfile
RUN git clone --depth 1 https://github.com/mtrojnar/osslsigncode.git osslsigncode && ...
```

That clones the **moving `master` branch** (no pin), which contradicts the master
plan's "fork from … 2.13 stable" and makes builds non-reproducible. The finish
plan pins to tag `2.13` + applies this patch (see §6). This repo does **not** edit
the sandbox.

---

## 2. What the patch does

osslsigncode 2.13 builds its Authenticode signature through OpenSSL's **legacy
PKCS7 stack**, which has no ML-DSA support in two places:

1. **Sign-prep** — `pkcs7_create()` (helpers.c) calls
   `PKCS7_add_signature()` → `PKCS7_SIGNER_INFO_set()`, which has a hard-coded
   key-type whitelist (RSA/DSA/EC/EdDSA). For an ML-DSA key it fails immediately:

   ```
   PKCS7 routines:PKCS7_SIGNER_INFO_set:signing not supported for this key type
   ```

2. **Seal** — `pkcs7_sign_content()` → `PKCS7_dataFinal()` →
   `PKCS7_SIGNER_INFO_sign()` calls `EVP_DigestSignInit(ctx, NULL, md, …)` with a
   **non-NULL** message digest. ML-DSA is a *pure* signature scheme and requires
   `md == NULL`.

The sign-side patch (in `helpers.c`, 211 net new lines) adds a narrow ML-DSA
branch and leaves every classic RSA/EC/EdDSA path **byte-for-byte unchanged**
(the symmetric verify-side branch lives in `osslsigncode.c`, +123 lines — see
§3.6; the full patch is 2 files, +333/-1):

| Symbol | Role |
|---|---|
| `pkey_is_mldsa()` | `EVP_PKEY_is_a()` test for `ML-DSA-44/65/87`. |
| `pkcs7_signer_info_set_mldsa()` | Builds the `SignerInfo` by hand: `issuerAndSerialNumber` from the signer cert; `digestAlgorithm` = content hash (SHA-256, the Authenticode default); `digestEncryptionAlgorithm` = the ML-DSA key OID with absent parameters; then `PKCS7_add_signer()`. |
| `pkcs7_sign_content_mldsa()` | Re-encodes the `SET OF` authenticated attributes (`ASN1_item_i2d` + `PKCS7_ATTR_SIGN`) and signs them with the pure one-shot `EVP_DigestSign` (`md == NULL`), storing the signature in `enc_digest`. |

**OID note.** ML-DSA keys are provider-only, so `EVP_PKEY_get_id()` returns `-1`;
the patch resolves the OID from the key's type name
(`OBJ_txt2nid("ML-DSA-65")` → NID 1458 → `2.16.840.1.101.3.4.3.18`). OID values
were confirmed against the OpenSSL 3.6 object table:

| Algorithm | OID |
|---|---|
| ML-DSA-44 | `2.16.840.1.101.3.4.3.17` |
| **ML-DSA-65** | **`2.16.840.1.101.3.4.3.18`** |
| ML-DSA-87 | `2.16.840.1.101.3.4.3.19` |

No CLI change is required for the slice: osslsigncode 2.13 already loads the
private key via `-key <file|URI>` (file or PKCS#11 URI through providers) and the
key type is auto-detected. (The master plan's `-algorithm mldsa65` /
`-pkcs11engine` flags are optional ergonomics — see §5/§7.)

---

## 3. Validated-slice evidence (verbatim)

All commands run on macOS against Homebrew OpenSSL 3.6.2; binary built with
`cmake -DOPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3`. In the sandbox the
same applies against `/usr/local/ssl`.

### 3.1 Build

```
$ osslsigncode --version
osslsigncode 2.13, using:
	OpenSSL 3.6.2 7 Apr 2026 (Library: OpenSSL 3.6.2 7 Apr 2026)
```

### 3.2 Baseline (UNPATCHED) — the blocker the patch removes

```
$ osslsigncode sign -certs signer.pem -key signer.key -in test.exe -out signed.exe
Creating a new signature failed
Unable to prepare new signature
...:error:10800094:PKCS7 routines:PKCS7_SIGNER_INFO_set:signing not supported for this key type:crypto/pkcs7/pk7_lib.c:392:
Failed
(exit 255)
```

### 3.3 Patched — sign a real PE32+ with an ML-DSA-65 software key

```
$ openssl genpkey -algorithm ML-DSA-65 -out signer.key
$ openssl req -new -x509 -key signer.key -out signer.pem -days 3650 \
    -subj "/CN=PQCToday ML-DSA-65 CodeSign/O=pqctoday-org" \
    -addext "keyUsage=critical,digitalSignature" \
    -addext "extendedKeyUsage=codeSigning"
$ openssl x509 -in signer.pem -noout -text | grep -i "signature algorithm"
        Signature Algorithm: ML-DSA-65
    Signature Algorithm: ML-DSA-65

$ file test.exe
test.exe: PE32+ executable (console) x86-64, for MS Windows

$ osslsigncode sign -h sha256 -certs signer.pem -key signer.key -in test.exe -out signed.exe
Succeeded
(exit 0)

$ file signed.exe
signed.exe: PE32+ executable (console) x86-64, for MS Windows
```

### 3.4 The PKCS#7 structure carries the ML-DSA OID

```
$ osslsigncode extract-signature -in signed.exe -out sig.p7b   # Succeeded
$ openssl pkcs7 -inform DER -in sig.p7b -print | grep -i "algorithm"
        algorithm: sha256 (2.16.840.1.101.3.4.2.1)        # content digest
            algorithm: ML-DSA-65 (2.16.840.1.101.3.4.3.18)
          algorithm: ML-DSA-65 (2.16.840.1.101.3.4.3.18)  # cert sig
          algorithm: sha256 (2.16.840.1.101.3.4.2.1)      # SignerInfo digestAlgorithm
          algorithm: ML-DSA-65 (2.16.840.1.101.3.4.3.18)  # SignerInfo signatureAlgorithm
```

`openssl asn1parse` shows the SignerInfo signature is the expected FIPS 204
ML-DSA-65 size (3309 bytes):

```
 5971:d=6  hl=2 l=   9 prim: OBJECT       :ML-DSA-65
 5982:d=5  hl=4 l=3309 prim: OCTET STRING [HEX DUMP]:9FF9A1A4FF28518040FA05CAE7...
```

### 3.5 Independent cryptographic verification of the embedded signature

A standalone tool (`EVP_DigestVerify`, pure ML-DSA, `md == NULL`) re-encodes the
signed attributes and verifies the embedded signature against the cert's public
key:

```
signer public key type: ML-DSA-65
signatureAlgorithm OID (text): ML-DSA-65
signatureAlgorithm OID (dotted): 2.16.840.1.101.3.4.3.18
embedded signature length: 3309 bytes
EVP_DigestVerify (pure ML-DSA over signed attrs) => VALID
(exit 0)
```

This proves the signature is a **genuine, valid ML-DSA-65 signature** over the
Authenticode authenticated attributes — not a stub, not a fallback, not RSA/EC.

### 3.6 `osslsigncode verify` — now green (verify-side branch added)

```console
$ osslsigncode verify -in signed.exe -CAfile signer.pem
...
Calculated message digest : 2D2C7B38...A7A4          # content digest MATCHES
Signing certificate chain verified using: ...         # ML-DSA-65 chain VERIFIES
Signature verification: ok
Number of verified signatures: 1
(exit 0)

# tampered content or wrong CA -> exit 1 (rejected)
```

The patch adds an ML-DSA branch to `verify_pkcs7_data` (`verify_pkcs7_data_mldsa`):
the cert chain is verified via `PKCS7_verify(..., PKCS7_NOSIGS)`, the
**messageDigest authenticated attribute is checked against `digest(content)`**,
and the signature over the SET OF authenticated attributes is verified with the
pure one-shot `EVP_DigestVerify` (`md == NULL`). The classic `PKCS7_verify` path
is used for every non-ML-DSA SignerInfo.

> **Binding fix (found while building the verify side).** The sign-only slice did
> *not* add the `messageDigest` attribute (the bypassed `PKCS7_dataFinal()`
> normally does), so the signature was over attributes that did **not** bind the
> content. The patch now adds `messageDigest` during ML-DSA signing, so the
> signature genuinely binds the signed PE — and verify enforces it (a tampered
> PE is rejected).

---

## 4. Authenticode-PQC standardization caveat (read this)

**Microsoft has not defined a PQC Authenticode profile.** As of this writing:

- The Windows Authenticode signature format formally enumerates a small set of
  signature algorithms (RSA, and ECDSA in recent Windows); **ML-DSA / FIPS 204 is
  not in that set**, and the Windows code-integrity / `WinVerifyTrust` loader does
  **not** accept ML-DSA-signed PEs.
- The relevant standards work is still in draft: `draft-ietf-lamps-pqc-cms`
  (ML-DSA in CMS) and `draft-ietf-lamps-dilithium-certificates` (ML-DSA in X.509).
  CMS ≠ Authenticode; Microsoft would need to publish its own Authenticode profile
  and ship loader support before ML-DSA-signed binaries verify on Windows.

**Therefore this fork is forward-looking / educational.** It demonstrates that the
*tooling and crypto* (OpenSSL 3.6 ML-DSA + PKCS#7 wiring) are ready to emit a
well-formed PQC Authenticode envelope the moment a profile exists. It does **not**
produce binaries that today's Windows will trust. The signed PE verifies
end-to-end *within the PQC toolchain* (cert chain + content digest + independent
ML-DSA signature check, §3) — which is the appropriate scope for the sandbox.

This caveat matches the master plan's own risk note ("Authenticode spec only
formally supports a small algo set; some Windows clients may reject ML-DSA-signed
PEs. Acceptable for sandbox educational scope.").

---

## 5. HSM / PKCS#11 path (softhsmv3)

The HSM hook is the spec's preferred backend: the signing key stays resident in
`softhsmv3` and osslsigncode drives signing via `pkcs11-provider`.

**Why this is in reach, not in this slice:** osslsigncode 2.13 already accepts a
PKCS#11 **URI** in `-key` and loads it via `OSSL_STORE` / the configured provider.
The patched code path is key-agnostic — it calls `EVP_DigestSign` on whatever
`EVP_PKEY` was loaded, so a PKCS#11-backed ML-DSA `EVP_PKEY` flows through the
exact same `pkcs7_sign_content_mldsa()` branch with **no further C changes**. What
remains is environment wiring, not code:

1. Build/install `pkcs11-provider` against the same OpenSSL 3.6.
2. Point it at `softhsmv3` (`SOFTHSM2_CONF`, token in slot 0, ML-DSA-65 key object
   labelled e.g. `signer`).
3. Sign with:
   ```
   osslsigncode sign -h sha256 \
       -pkcs11module /usr/local/ssl/lib64/ossl-modules/pkcs11.so \
       -key 'pkcs11:object=signer;type=private;pin-value=1234' \
       -certs ca.pem -in input.exe -out signed.exe
   ```
4. Confirm key access stayed in the token (`pkcs11-tool -O`, or softhsmv3 audit
   log).

**Dependency:** `softhsmv3` must expose ML-DSA via PKCS#11 v3.2
(`CKM_ML_DSA`, `CKK_ML_DSA`, `CKA_PARAMETER_SET = CKP_ML_DSA_65`). That is exactly
the PQC surface this repo's `softhsmv3` fork is building (Phases 2–3). Until the
softhsmv3 ML-DSA mechanism + the OpenSSL `pkcs11-provider` ML-DSA mapping are both
live, the slice uses a software ML-DSA key (§3), which is the documented fallback.

---

## 6. Sandbox wiring (Dockerfile + tests/17)

Changes belong in `pqctoday-sandbox` (not edited here). Concretely:

### `docker/Dockerfile.network` (replaces the line-135 clone block)

```dockerfile
# osslsigncode: PQC (ML-DSA) Authenticode — pinned + patched against OpenSSL 3.6
WORKDIR /usr/src
COPY osslsigncode-pqc.patch /usr/src/osslsigncode-pqc.patch
RUN git clone --branch 2.13 --depth 1 https://github.com/mtrojnar/osslsigncode.git osslsigncode && \
    cd osslsigncode && \
    git apply /usr/src/osslsigncode-pqc.patch && \
    mkdir build && cd build && \
    OPENSSL_ROOT_DIR=/usr/local/ssl \
    cmake .. -DOPENSSL_ROOT_DIR=/usr/local/ssl \
             -DCMAKE_EXE_LINKER_FLAGS="-L/usr/local/ssl/lib64 -Wl,-rpath,/usr/local/ssl/lib64" && \
    make -j$(nproc) && make install && \
    cd /usr/src && rm -rf osslsigncode
```

(Or replace the upstream clone with a `pqctoday-org/osslsigncode` fork carrying
this patch, per the master plan. The patch is the source of truth either way.)

### `tests/17_test_osslsigncode.sh`

Current test (lines 113–125) **falls back** to `openssl pkeyutl -sign` (raw, no
Authenticode envelope) when ML-DSA PKCS#7 embedding fails. With this patch the
embed succeeds, so:

- Remove the `openssl pkeyutl` fallback branch.
- Keep the existing `osslsigncode sign … -certs … -key …` invocation (no flag
  changes needed for a software key); add the `-pkcs11module`/`-key pkcs11:` form
  once §5 is wired.
- Assert structure carries ML-DSA, e.g.:
  ```
  osslsigncode extract-signature -in signed.exe -out sig.p7b
  openssl pkcs7 -inform DER -in sig.p7b -print | grep -q "ML-DSA-65 (2.16.840.1.101.3.4.3.18)"
  ```
- Set `fallback_note=""` and keep `_simulated: false`.
- `artifact_signed` becomes a real Authenticode-embed result, not a raw-sign
  result.

---

## 7. Remaining work + status

| # | Item | Status |
|---|---|---|
| 1 | **PQC-aware `verify`** — ML-DSA branch in `verify_pkcs7_data` (§3.6) | ✅ done — `osslsigncode verify` returns ok; tampered/wrong-CA rejected |
| 2 | **messageDigest content binding** in the ML-DSA sign path | ✅ done (the binding fix, §3.6) |
| 3 | **ML-DSA-44/87 coverage** | ✅ done — `pkey_is_mldsa()` covers all three; ML-DSA-87 round-trip verified (OID .19) |
| 4 | **Dockerfile pin 2.13 + patch + valid PE fixture; de-fallback `tests/17`** | ✅ done in `pqctoday-sandbox`; validated in-container |
| 5 | **PKCS#11 / softhsmv3 backing** — `-key pkcs11:…` via the OpenSSL pkcs11-provider | ⬜ pending: the code path is key-agnostic (signs/verifies on the loaded `EVP_PKEY`), so it needs no C change — only the OpenSSL **pkcs11-provider's ML-DSA mapping** to softhsmv3 (external to this fork). step-ca/cosign already prove HSM-resident ML-DSA via direct PKCS#11. |
| 6 | **CLI ergonomics** — optional `-algorithm mldsa65` flag (auto-detect already works) | optional/cosmetic |

**Scenario 17 is real and complete for sign + verify with a software ML-DSA key.**
The only open item is HSM-resident keys, which is gated on the OpenSSL
pkcs11-provider exposing ML-DSA (a component outside osslsigncode). The Windows
PQC-Authenticode profile gap (§4) is a permanent ecosystem caveat, not a fork item.

---

## Appendix — reproduce the slice locally

```bash
# 1. clone + pin
git clone --branch 2.13 --depth 1 https://github.com/mtrojnar/osslsigncode.git
cd osslsigncode
git apply /path/to/pqctoday-hsm/osslsigncode-pqc.patch

# 2. build against OpenSSL 3.6 (macOS Homebrew shown; sandbox uses /usr/local/ssl)
mkdir build && cd build
OPENSSL_ROOT_DIR=$(brew --prefix openssl@3) \
  cmake .. -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3) -DCMAKE_BUILD_TYPE=Release
make -j

# 3. key + cert + PE, then sign
openssl genpkey -algorithm ML-DSA-65 -out signer.key
openssl req -new -x509 -key signer.key -out signer.pem -days 3650 \
  -subj "/CN=PQCToday ML-DSA-65 CodeSign/O=pqctoday-org" \
  -addext "extendedKeyUsage=codeSigning"
./osslsigncode sign -h sha256 -certs signer.pem -key signer.key \
  -in <any-PE32.exe> -out signed.exe        # -> "Succeeded"

# 4. prove ML-DSA is embedded
./osslsigncode extract-signature -in signed.exe -out sig.p7b
openssl pkcs7 -inform DER -in sig.p7b -print | grep "ML-DSA-65 (2.16.840.1.101.3.4.3.18)"
```
