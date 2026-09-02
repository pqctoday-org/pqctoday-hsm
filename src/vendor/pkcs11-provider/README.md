[![Build](https://github.com/latchset/pkcs11-provider/actions/workflows/build.yml/badge.svg)](https://github.com/latchset/pkcs11-provider/actions/workflows/build.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# pkcs11-provider

This is an OpenSSL 3.x provider to access Hardware and Software Tokens using
the PKCS#11 Cryptographic Token Interface. Access to tokens depends
on loading an appropriate PKCS#11 driver that knows how to talk to the specific
token. The PKCS#11 provider is a connector that allows OpenSSL to make proper
use of such drivers. This code targets PKCS#11 version 3.2 but is backwards
compatible to version 3.1, 3.0 and 2.40 as well.

To report Security Vulnerabilities, please use the "Report a Security
Vulnerability" template in the issues reporting page.

### Installation

See [BUILD](BUILD.md) for more details about building and installing the provider.

### Usage

Configuration directives for the provider are documented in [provider-pkcs11(7)](docs/provider-pkcs11.7.md)
man page. Example configurations and basic use cases can be found in [HOWTO](HOWTO.md).

### Post-Quantum Cryptography & SoftHSMv3 Support

This vendored provider has been inherently upgraded to support the `SoftHSMv3` implementation of the PKCS#11 v3.2 standard. A phase-3 through phase-8 remediation program (2026-08-25 through 2026-08-30; see `docs/README.md`'s "OpenSSL provider" historical-records list for the dated plans) closed most of the gap between what the two PKCS#11 engines can do and what this provider could actually reach:
- **ML-KEM / ML-DSA / SLH-DSA / HSS / XMSS / XMSS^MT**: Native `OSSL_OP_KEM` (`C_EncapsulateKey`/`C_DecapsulateKey`) and `OSSL_OP_SIGNATURE` dispatch for all FIPS 203/204/205 parameter sets, plus SP 800-208 HSS/LMS and RFC 8391 XMSS/XMSS^MT token-resident signing (`src/sig/{mldsa,slhdsa,hss,xmss}.c`).
- **ML-DSA external-µ** (`CKM_ML_DSA_EXTERNAL_MU`/`_GEN`, PKCS#11 v3.3 draft codepoints — still OASIS "proposed", adopted early): sign/verify against an independently-computed µ, cross-checked against OpenSSL's own native ML-DSA implementation (`src/sig/mldsa.c`).
- **HashML-DSA / HashSLH-DSA pre-hash routing**: the `CKM_HASH_ML_DSA*`/`CKM_HASH_SLH_DSA*` mechanism families (SHA-2/SHA-3/SHAKE-128/256 digests) reachable via `openssl dgst -sign`/`-verify` (`src/provider.c`).
- **Composite signatures**: all 8 draft-ietf-lamps-pq-composite-sigs profiles (ML-DSA-44/65/87 combined with RSA-PSS, ECDSA P-256/P-384, or Ed25519) as real `OSSL_OP_SIGNATURE` + keymgmt + encoder registrations (`src/composite.c`).
- **X25519/X448 key exchange + ML-KEM TLS 1.3 groups**: token-backed `OSSL_OP_KEYEXCH` for both Montgomery curves, plus pure ML-KEM-512/768/1024 TLS 1.3 groups (client role, and a fully token-backed server role for the certificate signature *and* the KEM) (`src/tls.c`, `src/exchange.c`).
- **EVP_MAC**: HMAC (SHA-1/256/384/512), CMAC, and KMAC-128/256, plus `OSSL_FUNC_MAC_INIT_SKEY` for all three (`src/mac.c` — see the Build note in `BUILD.md`: not yet wired into this fork's standalone `meson.build`).
- **KDFs**: HKDF (RFC 5869), PBKDF2 (`CKM_PKCS5_PBKD2`), and SP 800-108 Counter/Feedback/Double-Pipeline KBKDF (`src/kdf.c`).
- **Ciphers**: AES-GCM/CCM/CTR/OFB/CFB\*, AES-XTS, AES Key Wrap / Key Wrap with Padding (RFC 3394/5649), and ChaCha20/ChaCha20-Poly1305 (`src/cipher.c`, `src/chacha.c` — same standalone-`meson.build` caveat as EVP_MAC above).
- **PKCS#11 v3.x Asynchronous Integrations**: Supports the simulated `CKF_ASYNC_SESSION` mode to decouple blocking threads and unblock asynchronous API network gateways utilizing `C_AsyncComplete` routines natively via `CKR_OPERATION_NOT_INITIALIZED`.

#### Both PKCS#11 engines

This provider is engine-agnostic by construction: it `dlopen`s whatever PKCS#11 module `pkcs11-module-path` (or `PKCS11_PROVIDER_MODULE`) points at and drives it through the standard `C_*` API, so the same built `pkcs11.so`/`.dylib` works unmodified against either the C++ engine's `libsofthsmv3.so`/`.dylib` or the Rust engine's `libsofthsmrustv3.so`/`.dylib` cdylib — there is no compile-time or link-time coupling to either engine. Several of the mechanisms above needed real provider-side fixes to reach the Rust engine correctly (e.g. reading a key's *actual* parameter set instead of assuming the C++ engine's own default for HSS/LMS); once fixed, that routing code is shared and reaches both engines identically. `scripts/test-openssl-provider.sh` proves this directly with Rust-arm twin cases (suffixed `b`/`c`/`d`/`e`, e.g. `T28b` external-µ, `T29b`/`T30b` HashML-DSA/HashSLH-DSA, `T31b` SHAKE128/256, `T32c` XMSS, `T24d`/`T24e` HSS) run against `libsofthsmrustv3.so` alongside the primary C++-arm cases.

#### RSA-OAEP against a SoftHSMv3 token: pin the hash explicitly

`RSA_PKCS1_OAEP_PADDING`'s OpenSSL-wide default is SHA-1 for both the OAEP
digest and MGF1. The SoftHSMv3 C++ engine rejects that default outright —
`Invalid hashAlg/mgf combination for RSA-OAEP` — rather than silently
falling back to it. This is a deliberate FIPS posture on the engine side
(SHA-1 is not an approved OAEP digest under FIPS 186/140-3 guidance), not
a provider bug, so it is not "fixed" on either side. Every OAEP call
against a token key — encrypt or decrypt — must pin both hashes to an
approved digest, e.g.:

```
openssl pkeyutl -encrypt -pubin -inkey pub.pem \
  -pkeyopt rsa_padding_mode:oaep \
  -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 \
  -in plaintext -out ciphertext.bin

openssl pkeyutl -decrypt -inkey "pkcs11:token=...;type=private" \
  -pkeyopt rsa_padding_mode:oaep \
  -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 \
  -in ciphertext.bin -out plaintext.bin
```

Omitting either `-pkeyopt` on a token-backed key fails at the engine, not
at the provider or at OpenSSL's own padding check — see
`SoftHSM_keygen.cpp` for the rejection site and
`scripts/test-openssl-provider.sh`'s `T5` case for a working example
(software OAEP-encrypt with both hashes pinned to SHA-256, into a
token-backed RSA-3072 key).

### Testing

Coverage against the real (non-vendored) OpenSSL 3.6+ oracle, both PKCS#11
engines, and known gaps tracked as explicit XFAIL cases lives at
`scripts/test-openssl-provider.sh` at the repo root — see
`docs/openssl-provider-coverage-audit-2026-08-25.md` for the design record
and `docs/openssl-provider-remediation-plan-2026-08-25.md` (phases 2-8;
`docs/README.md` lists the later dated phase plans) for the gap backlog.
It is wired into `scripts/local-gate.sh` as the opt-in `--openssl-provider`
step. The harness defaults to the provider built by the repo's own root
CMake build (`build/src/vendor/pkcs11-provider/pkcs11-provider.so`, via
`src/CMakeLists.txt` → this directory's `CMakeLists.txt`), **not** the
standalone `meson.build` in this directory — see `BUILD.md` for why that
distinction currently matters.

The vendored `tests/` meson suite (upstream latchset's own tests, C-based
plus a handful of shell scripts) is intentionally left unwired in this
fork — no CMake/ctest/CI/gate target invokes it. It assumes upstream's
build layout and a `SoftHSM2`/NSS-softokn token backend, not this fork's
CMake native build or `softhsmv3` token semantics, so it would need real
adaptation work rather than a flag flip to make it meaningful here.

### Notes

 * [PKCS #11 Specification Version 3.2](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html)
