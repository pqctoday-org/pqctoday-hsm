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
| Use the PKCS#11 remoting services (gRPC + REST) | [`PKCS11_REMOTING.md`](PKCS11_REMOTING.md) + [`../remoting/REMOTE_P11_V32_COVERAGE.md`](../remoting/REMOTE_P11_V32_COVERAGE.md) |
| Trace a PKCS#11 v3.2 profile claim to its proving test | [`PKCS11_PROFILE_TRACEABILITY.md`](PKCS11_PROFILE_TRACEABILITY.md) |
| Understand the JDK 27 JCA/JCE provider's FIPS 140-3 area mapping | [`jdk27-jca-provider-security-posture.md`](jdk27-jca-provider-security-posture.md) |

## Testing the wrappers

The PKCS#11 dev/ops guides above cover the OpenSSL provider, strongSwan, and
JavaJCE. The other components have their own runbooks:

| Component | Runbook |
| --- | --- |
| **KMIP 3.0 server + CACP policy engine** | [`../kmip/README.md`](../kmip/README.md) |
| KMIP Python test client | [`../kmip/python-client/README.md`](../kmip/python-client/README.md) |
| PKCS#11 remoting (gRPC + REST) | [`../remoting/REMOTE_P11_V32_COVERAGE.md`](../remoting/REMOTE_P11_V32_COVERAGE.md) |
| OpenSSH over PKCS#11 | [`../openssh-pkcs11/README.md`](../openssh-pkcs11/README.md) |
| OpenPGP over PKCS#11 | [`../openpgp/README.md`](../openpgp/README.md) |
| MLS provider | [`../openmls-provider/README.md`](../openmls-provider/README.md) |
| strongSwan IKEv2 plugin | [`../strongswan-pkcs11/README.md`](../strongswan-pkcs11/README.md) |
| Java JCA/JCE provider | [`../JavaJCE/README.md`](../JavaJCE/README.md) |
| Java JCA/JCE — gRPC-remote provider module | [`../JavaJCE-remote/README.md`](../JavaJCE-remote/README.md) |

## Historical records (not current guides)

These captured planning, gap analyses, and point-in-time audits. The work they
describe has largely shipped (see the root `CHANGELOG.md`, currently **0.27.0**,
plus unreleased work — always trust the CHANGELOG's top entry over any version
echoed here); they are kept for provenance, not as a to-do list:

**PKCS#11 v3.2 compliance (C++ / Rust engines):**
- `gap-analysis-pkcs11-v3.2.md`, `gap-analysis-rust-pkcs11-v3.2.md`
- `fix-plan-rust-pkcs11-v3.2-compliance.md`, `implementation-plan-rust-pkcs11-deferred.md`
- `compliance-audit-cpp-pkcs11-v3.2-2026-06-12.md`, `compliance-audit-kmip30-pkcs11v32-2026-06-10.md`
- `gap-analysis-cpp-rust-realignment-2026-07-25.md`, `remediation-plan-cpp-rust-pkcs11-parity-2026-07-25.md`
- `remediation-plan-pkcs11-v32-coverage-2026-08-29.md`, `remediation-plan-rust-pkcs11-v32-gaps-2026-08-30.md`
- `remediation-plan-pkcs11-engine-eddsa-keyderivation-gaps-2026-08-30.md`
- `remediation-plan-hashml-dsa-hashslh-dsa-prehash-2026-08-30.md`
- `remediation-plan-provider-layer-gaps-2026-08-30.md`, `remediation-plan-remaining-gaps-2026-08-31.md`

**OpenSSL provider:**
- `openssl-provider-coverage-audit-2026-08-25.md`
- `openssl-provider-remediation-plan-2026-08-25.md` (phases 2–8: `openssl-provider-remediation-plan-phase{2,3,4,5,6,7,8}-*.md`)
- `openssl-provider-ml-dsa-external-mu-vendor-ext-2026-08-26.md`
- `remediation-plan-provider-wrapper-coverage-gaps-2026-08-31.md`

**PKCS#11 remoting (gRPC/REST):**
- `remoting-pkcs11-v32-full-coverage-plan-2026-08-26.md`, `remoting-pkcs11-v32-gap-remediation-plan-2026-08-26.md`
- `remoting-pkcs11-v32-remaining-gaps-plan-2026-08-26.md`, `remoting-pkcs11-v32-residual-gaps-plan-2026-08-26.md`

**JDK 27 JCA/JCE provider:**
- `implementation-plan-jdk27-jca-provider-2026-08-24.md`, `implementation-plan-jca-remaining-gaps-2026-08-25.md`

**KMIP / CACP coverage:**
- `gap-analysis-kmip-cacp-pkcs11-coverage-2026-08-30.md`, `remediation-plan-kmip-cacp-pkcs11-coverage-2026-08-30.md`

**CKM_HPKE (RFC 9180, Rust engine):**
- `proposal-plan-ckm-hpke-mechanism-2026-08-31.md`, `remediation-plan-ckm-hpke-and-hpke-gaps-2026-08-31.md`
- `proposals/pkcs11-ckm-hpke-mechanism-proposal.md` — the mechanism spec itself; **still current**, not
  a point-in-time snapshot, referenced from the root `README.md`'s HPKE section

**Security audits:**
- `security_audit_03222026.md`, `security_audit_04132026.md`

**Superseded (self-marked in the file):**
- `wasm-charon-phase-3b-plus-roadmap.md` — targeted a `strongswan-wasm-v2-shims/` tree
  deleted 2026-08-31; real work landed in `strongswan-wasm-shims/` (v1) instead

**Other:**
- `softhsmv3gapanalysis.md`, `acvp-key-template-audit.md`

For current conformance status use the checked-in reports instead:
[`../rust/RUST_P11_V32_CONFORMANCE_REPORT.md`](../rust/RUST_P11_V32_CONFORMANCE_REPORT.md),
[`../cpp_compliance_report.md`](../cpp_compliance_report.md),
[`../remoting/REMOTE_P11_V32_COVERAGE.md`](../remoting/REMOTE_P11_V32_COVERAGE.md), and
[`../kmip/docs/CONFORMANCE_REPORT.md`](../kmip/docs/CONFORMANCE_REPORT.md).
