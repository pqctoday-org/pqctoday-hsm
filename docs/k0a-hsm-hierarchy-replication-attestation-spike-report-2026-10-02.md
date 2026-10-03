# K0A report: HSM hierarchy, replication and attestation spikes

Date: 2026-10-02
Repository: `pqctoday-hsm`
Engine: Rust (`softhsmrustv3`) only
Baseline: `b840293655a5f0f46be028b7ba8c5fc71ed72078`

## Executive result

The certificate, RATS evidence, release-profile and internal HPKE spikes pass. The original
existing-function replication ABI does not. The owner has since selected the separate named vendor
interface recorded in §6; that interface still requires K0B specification and review.

The key result is a protocol/API gate, not a crypto failure: PKCS#11 v3.2 requires
`C_WrapKey` and `C_WrapKeyAuthenticated` to wrap only keys whose `CKA_EXTRACTABLE` is true.
The feature is specifically intended to replicate keys whose `CKA_EXTRACTABLE` is false.
`C_DeriveKey` can return `CKO_DATA` for mechanisms such as `CKM_HKDF_DATA`, but describing a
protected-key export package as a derived key is not an honest mapping. Under D13 (no new
`C_*` entry points) and the non-extractability promise, secure package export therefore has no
clean existing-function mapping.

K0A is complete as an investigation and records the existing-function NO-GO. The owner selected
the `PQCTODAY_KEY_REPLICATION_1_0` alternative in §6. Production hierarchy work must not start
until K0B freezes that ABI and an independent review closes the protocol composition.

## 1. Normative pins and test-only identifiers

| Subject | Pin used by the spike | Result |
|---|---|---|
| ML-DSA certificates | [RFC 9881](https://www.rfc-editor.org/rfc/rfc9881.html) | ML-DSA-65 AlgorithmIdentifier parameters absent; signing chain passes |
| ML-KEM certificates | [RFC 9935](https://www.rfc-editor.org/rfc/rfc9935.html) | ML-KEM-768 parameters absent; leaf has only `keyEncipherment` in KeyUsage |
| HSM evidence | [draft-ietf-rats-pkix-key-attestation-07](https://datatracker.ietf.org/doc/html/draft-ietf-rats-pkix-key-attestation-07) | Exact `Evidence`, `TbsEvidence`, `ReportedElement`, `ReportedClaim`, `SignatureBlock` and `SignerIdentifier` container shape round-trips |
| Documentation OIDs | [RFC 5612](https://www.rfc-editor.org/rfc/rfc5612.html) PEN 32473; educational root `1.3.6.1.4.1.32473.20261002` | Fixed by private-authority commit `f2e5cfa`; used only by executable fixtures and an explicit local educational profile; rejected everywhere else |
| PKCS#11 semantics | local published `docs/refs/pkcs11-spec-v3.2-os.pdf`, dated 2026-06-03 | §5.18.2–§5.18.7 and §6.62.4 reviewed |
| HPKE PQ KEMs | `draft-ietf-hpke-pq-05`, upstream tag/commit `6433c8fce0b8b749dfc86c1095081a88698ccfab` | Local fixture is byte-identical to upstream; all in-scope vectors pass |

The RATS -07 module still contains `TBDMOD1`, `TBDMOD2` and `TBDMOD3`. No production OID was
invented or allocated. This alone prevents freezing a production evidence profile today.

## 2. Executable certificate and evidence results

The integration test is `rust/tests/hierarchy_attestation_spikes.rs` and requires the existing
`test-support` feature. It performs the following operations:

1. Generates a fresh host-side ML-DSA-65 test manufacturing root.
2. Generates an ML-DSA-65 device issuer inside the Rust engine.
3. Signs the device certificate with the manufacturing root.
4. Generates an ML-KEM-768 recovery-recipient key inside the Rust engine.
5. Signs its function certificate inside the engine with the device key.
6. DER round-trips all certificates and independently verifies all signatures.
7. Encodes draft -07 evidence, signs `TbsEvidence` inside the engine with ML-DSA-65, DER
   round-trips it, verifies it, and proves that changing the nonce invalidates the signature.

Measured DER sizes from the passing test:

| Object | Bytes |
|---|---:|
| Test manufacturing root certificate | 5,496 |
| Device issuer certificate | 5,486 |
| ML-KEM-768 recovery function certificate | 4,712 |
| `TbsEvidence` with transaction and key claims | 2,190 |
| Evidence with one ML-DSA-65 signature and signer SPKI | 7,510 |

The test uses provisional upper bounds of 8 KiB per certificate and 16 KiB per evidence object.
Those are spike guards, not final wire limits. K0B must define exact limits for subject names,
certificate chains, claims, signature blocks, package ciphertext and nesting depth before any
untrusted parser is exposed.

Command and result:

```text
cargo test -p softhsmrustv3 --test hierarchy_attestation_spikes \
  --no-default-features --features test-support -- --nocapture

2 passed; 0 failed
```

## 3. X.509/DER dependency and WASM cost

The spike adds test-only dependencies already present in the repository's resolved dependency
set. They are not normal dependencies and do not enter the shipped native or WASM artifact.

| Crate | Version | Cargo.lock checksum | Licence | Use |
|---|---:|---|---|---|
| `const-oid` | 0.9.6 | `c2459377285ad874054d797f3ccebf984978aa39129f6eafde5cdc8315b612f8` | Apache-2.0 OR MIT | Test OIDs |
| `der` | 0.7.10 | `e7c1832837b905bbfb5101e07cc24c8deddf52f93225eee6ead5f4d63d53ddcb` | Apache-2.0 OR MIT | RATS ASN.1 codec |
| `spki` | 0.7.3 | `d91ed6c858b01f942cd56b37a94b3e0a1798290327d1236e4d9cf4eaca44d29d` | Apache-2.0 OR MIT | RFC 9881/9935 SPKI |
| `x509-cert` | 0.2.5 | `1301e935010a701ae5f8655edc0ad17c44bad3ac5ce8c39185f75453b720ae94` | Apache-2.0 OR MIT | Test certificate construction/parsing |

The normal release WASM was rebuilt before and after these dev-dependency additions with the
same output size and hash, so their linked WASM cost is zero. The resulting candidate
shipped-shape artifact is 2,794,301 bytes with SHA-256
`82cee407f082b9731de75af9c21aa8413a7c6e4b39b49b24b5975641da9b2813`.
It remains only in the ignored `rust/pkg-release/` staging directory. Per release coordination,
the tracked `rust/pkg_bundler/` binary and manifest are not part of this change; the Hub re-pin
step will rebuild them once from final HSM main.

The repository-wide F6 licence gate is not closed: the root distribution is BSD-2-Clause while
`src/lib/vendor_mechanisms.h` says `SPDX-License-Identifier: GPL-3.0-only`. This pre-existing
conflict was not created or resolved by the spike and requires repository-owner/legal
clarification before a release claim can say the licence audit passed.

## 4. PKCS#11 v3.2 semantic review

The original §7 table is reviewed row by row below. “NO-GO” means the proposed function is a
misleading or contradictory use of its standard semantics, not merely that code is missing.

| Operation | Original candidate | Decision | Honest existing-function alternative |
|---|---|---|---|
| Issue function key and certificate | `C_DeriveKey` returning a key plus a certificate | **NO-GO.** §5.18.5 returns one derived key handle; it neither generates a key pair nor returns a certificate side effect | **Conditional GO as a sequence:** `C_GenerateKeyPair`; host constructs constrained TBSCertificate; `C_Sign` with an issuer-only vendor mechanism that validates all fields; `C_CreateObject` stores the certificate. This is not atomic and needs cleanup/idempotency rules |
| Key evidence | `C_DeriveKey` returning DER evidence | **NO-GO.** The evidence is a signed report, not a key derived from the attestation key | **GO as a constrained signing sequence:** host supplies canonical `TbsEvidence`; a vendor `C_Sign` mechanism recomputes and byte-compares every engine-owned claim and nonce before signing; host assembles `Evidence`. The attestation key allowlist contains only that mechanism |
| Seal clone or backup package | `C_DeriveKey` returning package data | **NO-GO / blocking.** The result is encrypted export of a second protected key, not derivation from the package-signing key. Standard wrap functions are the correct abstraction but §5.18.3 and §5.18.6 require the target to be extractable | No conforming existing-function mapping was found while retaining both D13 and `CKA_EXTRACTABLE=false` |
| Install from package | `C_UnwrapKey` | **GO for one private or secret key.** §5.18.4 is the correct import semantic and gives imported-history values | **NO-GO for the proposed paired-public-key side effect.** The function returns one new key handle. Either restore only the private/secret object and reconstruct public material separately, or define a separately reviewed transactional extension |
| Receipt | `C_DeriveKey` or install output attribute | **GO only as an install output attribute.** A read-only, engine-computed receipt bound to the installed key can be returned by `C_GetAttributeValue` | Do not create a receipt through `C_DeriveKey`; freeze retention, privacy and size rules in K0B |

The standard's `CKM_HKDF_DATA` precedent permits a specifically defined derivation mechanism to
produce `CKO_DATA`. It does not make every operation that returns data a derivation. In
particular, exporting another key's value under a transport protocol changes the security
meaning of `CKA_EXTRACTABLE` and must not be disguised as a KDF.

## 5. Snapshot and ledger cost result

The current `SHR3SNP2` format is a flat, uncompressed serialization of all token objects. Its
object cost is exactly:

```text
8 bytes object header + (8 bytes × attribute count) + sum(attribute value lengths)
```

The three measured certificate values alone add 15,694 bytes before their object attributes.
A full root + device + four ML-DSA function certificates (authentication, attestation, package and
receipt signing) + one ML-KEM function certificate is approximately 38 KiB of certificate DER
before keys, policy objects and metadata. This is an estimate extrapolated from the measured
ML-DSA certificate sizes, not a new measured fixture. The actual
production hierarchy will be larger because ML-DSA public/private objects and the ML-KEM
recipient key are also persisted.

The more important finding is unbounded growth: the snapshot parser currently accepts `u32`
token/object/attribute counts and lengths without a total snapshot cap, while a durable receipt
or consumption ledger grows with every transaction. K0B/F14 must therefore define:

- a maximum snapshot size and checked arithmetic before allocation/copy;
- maximum object, attribute, certificate, evidence and package sizes;
- a maximum ledger-entry count and a fail-closed “ledger full” result;
- a retention/rotation ceremony that never silently evicts transaction IDs and thereby permits
  replay;
- an atomic version bump/migration path and corrupt/truncated/oversized negative tests.

Silently using a ring buffer is rejected: eviction would eventually make an old package look
unused. A bounded ledger that refuses new replication when full is the safe baseline until a
cryptographically reviewed compaction/epoch protocol exists.

## 6. Owner/API disposition after K0A

This report preserves the K0A semantic result: no existing PKCS#11 v3.2 function honestly creates
or imports the proposed protected replication package while the source remains
`CKA_EXTRACTABLE=false`. After this report, the owner selected option 1 with a tighter ABI boundary:
the separately discoverable `PQCTODAY_KEY_REPLICATION_1_0` interface. Its normative primitives are
`C_PQCTODAY_CreateReplicationPackage` and `C_PQCTODAY_ImportReplicationPackage`;
`C_PQCTODAY_CloneKey` is a same-module convenience wrapper. The interface is discovered through
standard `C_GetInterfaceList` / `C_GetInterface` and does not modify `CK_FUNCTION_LIST_3_2`.
The HSM plan revision v3 governs the resulting K0B work.

The alternatives considered at K0A were:

1. **Add a vendor operation** dedicated to creating a replication package. **Selected**, through
   the separate named interface above; D13 was revised without changing the standard function list.
2. **Define a vendor mechanism on `C_WrapKeyAuthenticated` that may wrap only an immutable,
   policy-enrolled non-extractable key.** This preserves the function shape but intentionally
   extends the v3.2 `CKA_EXTRACTABLE` rule and must be labelled as a vendor conformance exception.
3. **Do not implement protected-key replication.** Keep attestation and hierarchy only.

Using `C_DeriveKey` as a hidden export channel is not recommended.

## 7. Engine prerequisites completed during K0A/K1 work

| Item | Result |
|---|---|
| F1, HPKE -05 | The fixture already matched the official -05 tag byte-for-byte. Stale -04 labels were corrected. The full in-scope vector test passes |
| F3, `CKA_DERIVE_TEMPLATE` | Enforced against final derived attributes before handle allocation; mismatch returns `CKR_TEMPLATE_INCONSISTENT`; regression test passes |
| F5, release/test RNG split | Normal native/WASM builds reject HPKE deterministic encapsulation seeds and non-null `C_Initialize.pReserved`; explicit `--acvp-test` builds use separate directories and never refresh the tracked bundle |
| F13, vendor mutability | Existing security-relevant BIP32/LMS/XMSS vendor attributes are explicitly immutable. The subsequently reserved hierarchy/policy/provenance attributes join that immutable set in the same K2/K4 change that introduces their constants, after the private-authority commit lands upstream |
| Internal HPKE reuse | Pure ML-KEM vectors pass; shipped deterministic randomness is off; output AEAD keys remain sensitive and non-extractable. Conditional GO, subject to the package-protocol review and the named-interface K0B specification |

The generic F8 hardening is complete: derivation from a sensitive base defaults to a sensitive,
non-extractable result and `CKA_DERIVE_TEMPLATE` is enforced. The replication-specific mechanism
allowlists and function-key templates remain K2/K4 work and use only authority-reserved values.

## 8. Gate status and next permitted work

| Gate | Status |
|---|---|
| K-1 inputs/pins | Partial: plan and pins are committed locally; dependency SBOM is recorded; pre-existing F6 licence conflict remains open |
| K0A spikes | Complete, with an existing-function package-export NO-GO and production-OID blocker recorded; the owner selected the named-interface resolution in §6 |
| K0B normative specification | Working ABI/wire specification present; PKCS #11 values reserved in local private-authority commit `36340f93`; educational OIDs fixed in local authority commit `f2e5cfa`; still blocked on upstream authority landing and independent protocol/suite review, while production use additionally requires real OIDs |
| K1 prerequisites | F1/F3/F5/F8/F13 implemented and focused tests pass; full local gate remains |
| K2–K5 production feature | Not started; starting before K0B closes would hard-code unresolved wire and security semantics |

K0A itself changed no external repository. Subsequent K0B work, explicitly authorized by the owner,
created local `pqctoday-priv` commits `36340f93` and `f2e5cfa` in an isolated worktree. No push
occurred. No Hub, KMIP/CACP, C++ engine, board or hardware changes were made.
