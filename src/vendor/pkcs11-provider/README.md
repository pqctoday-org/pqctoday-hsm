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

This vendored provider has been inherently upgraded to support the `SoftHSMv3` implementation of the PKCS#11 v3.2 standard.
- **ML-KEM**: Fully dispatches `OSSL_OP_KEM` encapsulations using FIPS 203 sizes (512, 768, 1024) natively through `C_EncapsulateKey`/`C_DecapsulateKey`.
- **ML-DSA**: Directly maps the FIPS 204 signatures (44, 65, 87) natively down to the HSM via `C_Sign`/`C_Verify`.
- **PKCS#11 v3.x Asynchronous Integrations**: Supports the simulated `CKF_ASYNC_SESSION` mode to decouple blocking threads and unblock asynchronous API network gateways utilizing `C_AsyncComplete` routines natively natively via `CKR_OPERATION_NOT_INITIALIZED`.

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
and `docs/openssl-provider-remediation-plan-2026-08-25.md` for the gap
backlog. It is wired into `scripts/local-gate.sh` as the opt-in
`--openssl-provider` step.

The vendored `tests/` meson suite (upstream latchset's own tests, C-based
plus a handful of shell scripts) is intentionally left unwired in this
fork — no CMake/ctest/CI/gate target invokes it. It assumes upstream's
build layout and a `SoftHSM2`/NSS-softokn token backend, not this fork's
CMake native build or `softhsmv3` token semantics, so it would need real
adaptation work rather than a flag flip to make it meaningful here.

### Notes

 * [PKCS #11 Specification Version 3.2](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html)
