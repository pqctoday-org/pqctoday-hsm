# softhsmv3 documentation index

Start here. This folder holds the current guides plus a set of historical
planning/audit records.

## Current guides

| I want to… | Read |
| --- | --- |
| **Build the token and write a client** (developer) | [`softhsmv3devguide.md`](softhsmv3devguide.md) |
| **Deploy / integrate the module** (ops, SRE) | [`softhsmv3opsguide.md`](softhsmv3opsguide.md) |
| **Build and test the token end to end** | [`howtotestsofthsmv3.md`](howtotestsofthsmv3.md) |
| Understand the Rust engine | [`rust-engine.md`](rust-engine.md) + [`../rust/README.md`](../rust/README.md) |
| Use the signing forks (cosign / osslsigncode / step-ca) | [`COSIGN_PQC_FORK.md`](COSIGN_PQC_FORK.md), [`OSSLSIGNCODE_PQC_FORK.md`](OSSLSIGNCODE_PQC_FORK.md), [`STEPCA_PQC_FORK.md`](STEPCA_PQC_FORK.md) |

## Testing the wrappers

The PKCS#11 dev/ops guides above cover the OpenSSL provider, strongSwan, and
JavaJCE. The other components have their own runbooks:

| Component | Runbook |
| --- | --- |
| **KMIP 3.0 server + CACP policy engine** | [`../kmip/README.md`](../kmip/README.md) |
| KMIP Python test client | [`../kmip/python-client/README.md`](../kmip/python-client/README.md) |
| OpenSSH over PKCS#11 | [`../openssh-pkcs11/README.md`](../openssh-pkcs11/README.md) |
| OpenPGP over PKCS#11 | [`../openpgp/README.md`](../openpgp/README.md) |
| MLS provider | [`../openmls-provider/README.md`](../openmls-provider/README.md) |
| strongSwan IKEv2 plugin | [`../strongswan-pkcs11/README.md`](../strongswan-pkcs11/README.md) |
| Java JCE provider | [`../JavaJCE/JavaJCESofthsmv3.md`](../JavaJCE/JavaJCESofthsmv3.md) |

## Historical records (not current guides)

These captured planning, gap analyses, and point-in-time audits. The work they
describe has largely shipped (see the root `CHANGELOG.md`, currently 0.8.0);
they are kept for provenance, not as a to-do list:

- `gap-analysis-pkcs11-v3.2.md`, `gap-analysis-rust-pkcs11-v3.2.md`
- `fix-plan-rust-pkcs11-v3.2-compliance.md`, `implementation-plan-rust-pkcs11-deferred.md`
- `compliance-audit-cpp-pkcs11-v3.2-2026-06-12.md`, `compliance-audit-kmip30-pkcs11v32-2026-06-10.md`
- `security_audit_03222026.md`, `security_audit_04132026.md`
- `softhsmv3gapanalysis.md`, `acvp-key-template-audit.md`, `wasm-charon-phase-3b-plus-roadmap.md`

For current conformance status use the checked-in reports instead:
[`../rust/RUST_P11_V32_CONFORMANCE_REPORT.md`](../rust/RUST_P11_V32_CONFORMANCE_REPORT.md),
[`../cpp_compliance_report.md`](../cpp_compliance_report.md), and
[`../kmip/docs/CONFORMANCE_REPORT.md`](../kmip/docs/CONFORMANCE_REPORT.md).
