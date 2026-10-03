# Implementation plan: HSM key hierarchy, key replication and attestation (Rust engine)

Date: 2026-10-02 · Revision: **v2** (decision 9 recorded; HPKE fixture item corrected)
Status: **proposal; no implementation or runtime validation claimed.** Docs only. All nine owner decisions recorded in §11.
Owner request (relayed by the coordinator, 16:26 CDT, "proceed with default options"): extract the
key-hierarchy, cloning/backup-restore and attestation design from the FHE wrapper plan v6 into a
standalone `pqctoday-hsm` plan that is delivered first and that FHE then uses.

Code baseline: `pqctoday-hsm` `origin/main` **`b840293655a5f0f46be028b7ba8c5fc71ed72078`**. Every
`file:line` below was re-located at that commit with `git grep`/`git show`, not carried over from the
FHE plan's `ceddd554` references.

Source documents (same directory):
- FHE wrapper plan v6, `implementation-plan-fhe-wrapper-pkcs11-vendor-2026-10-02.md`: §0 D13–D16, §6.7, §6.8, §10 F1–F12, §10.1.
- Its reviews: `review-implementation-plan-fhe-wrapper-pkcs11-vendor-2026-10-02.md`, `final-challenge-fhe-wrapper-plan-v4-2026-10-02.md`.

## 0. Scope decisions (owner defaults 1a–4a, 2026-10-02)

| # | Decision | Consequence in this plan |
|---|---|---|
| K1 (1a) | **General HSM features for any protected key**, FHE seeds as the first consumer | Covers ML-DSA and ML-KEM private keys, AES and generic secret keys, and the FHE seed type once the FHE plan allocates it. **Excluded:** stateful hash-based signature keys (LMS/HSS, XMSS/XMSS^MT), threshold-FHE shares, and the device issuer/function keys themselves. Each needs a separate state-consistency design; duplicating them can cause one-time-key reuse or split protocol state |
| K2 (2a) | **Rust engine only** (`softhsmrustv3`), native and browser/WASM | Out of scope, recorded as such: the C++ engine, KMIP/CACP, the PKCS#11 remoting services, and the protocol wrappers (`JavaJCE*`, OpenSSL provider, `openssh-pkcs11`, `openpgp`, `openmls-provider`, `strongswan-pkcs11`) |
| K3 (3a) | **Software first**, with a clearly labelled **test manufacturing CA**; no hardware claims | A later, separately gated phase (K6) binds device identity to board hardware roots (i.MX 95, KV260). Until then every artefact says "software token / test hierarchy" |
| K4 (4a) | **Separate plan, delivered first**, with its own phases and exit gates | The FHE plan's P1 now depends on this plan's K4 exit (§9). The FHE plan keeps only FHE-specific work: the seed key type, its recovery descriptor and its policy |

Adopted unchanged from the FHE plan:
- **D13:** PKCS#11 v3.2 OS plus pqctoday vendor extensions only. No new `C_*` functions. Ordinary wrapping never bypasses non-extractability.
- **D14:** a manufacturing root signs each device certificate directly, and device keys sign function certificates. This applies to operational and backup HSMs alike.
- **D15:** pure PQC at Category 3: ML-DSA-65 signatures, ML-KEM-768 key establishment, AES-256-GCM payload protection. No classical-only or hybrid fallback.
- **D16:** reuse the RATS HSM-evidence draft and the LAMPS CSR-attestation and freshness drafts, with RFC 9881 and RFC 9935 certificate profiles. No invented evidence format.

D1 (educational emulator, no production claim) and D5 (KMIP out of scope) carry over as well.

## 1. Goal and claim boundaries

Give the Rust engine three generic capabilities, each with tests and evidence:

1. **Key hierarchy.** Manufacturing → device → function certificates, with enrolled trust anchors and domain policy.
2. **Controlled replication.** Live cloning to an authenticated peer token, and offline backup to an enrolled backup token, for non-extractable keys. Ordinary `C_WrapKey`/`C_WrapKeyAuthenticated` keeps refusing them.
3. **Key attestation.** RATS-format evidence about a key and its token, signed by a purpose-constrained attestation key.

Every artefact is labelled with its scope, following the FHE plan's §1.2:
- **Browser emulator:** no tamper resistance; the page can read WASM memory and its stored snapshot.
- **Native software token:** the host administrator can read or roll back token storage.
- **Hardware-rooted target:** designed here, proven only by K6 evidence.

A certificate chain from the test manufacturing CA proves which **software instance** signed something. It does not prove hardware isolation, certification or vendor provenance.

## 2. What exists at `b8402936` (inventory)

| Capability | State | Evidence |
|---|---|---|
| ML-DSA-65 sign/verify, ML-KEM-768 encap/decap, AES-GCM, SHA-384 | Present | `rust/src/constants.rs`; AWS-LC PQ path `rust/src/crypto/awslc_pq.rs` |
| HPKE in-token, pure ML-KEM KEMs `0x0040`–`0x0042`, HKDF-SHA384 and SHAKE256 KDFs | Present. The vector fixture comes from `hpkewg/hpke-pq@6433c8fc`, the official draft-ietf-hpke-pq-05 tag; the test file still labels it -04 | `CKM_HPKE` `0x80000014`; `rust/src/hpke_pq_vectors_tests.rs` |
| HPKE output key | Fixed template: sensitive, non-extractable, encrypt/decrypt only, no `CKA_WRAP` | `rust/src/native/hpke.rs:810` (`register_aead_key`) |
| HPKE deterministic-randomness hook | `pEphemeralSeed` reaches encapsulation with **no release guard** | `rust/src/ffi.rs:4831-4870`; `rust/src/native/hpke.rs:796,927,947` |
| ACVP RNG hook in shipped WASM | `build-wasm-bundle.sh` always builds `--features acvp`; the feature lets non-null `C_Initialize.pReserved` seed the RNG | `rust/build-wasm-bundle.sh:65-70`; hook at `rust/src/ffi.rs:298` |
| Wrap refusal of non-extractable keys | Enforced in plain and authenticated wrap | `rust/src/ffi.rs:13569`, `:14288` (`C_WrapKeyAuthenticated` at `:14214`) |
| Unwrap defaults | Unwrapped keys get `CKA_LOCAL=false`, `CKA_ALWAYS_SENSITIVE`/`CKA_NEVER_EXTRACTABLE=false`, and default `EXTRACTABLE=true`, `SENSITIVE=false` unless the template says otherwise | `rust/src/ffi.rs:14146-14152` and following |
| Derived-key defaults | Shared output block for all `C_DeriveKey` KDFs (HKDF, SP 800-108, SHA-n): secret keys default extractable and non-sensitive; `CKA_PRIVATE=true` since R7 | `rust/src/ffi.rs:12979` (`CKM_HKDF_DATA` split), `:12994-12995` |
| `CKA_DERIVE_TEMPLATE` | **Stored, flattened and copied, not enforced** | Constant `rust/src/constants.rs:391`; only other use is array-flattening in `rust/src/crypto/handlers.rs:453` |
| Vendor-attribute mutability | Every attribute `>= 0x8000_0000` is exempt from Cryptoki mutability rules; only the engine-private range `>= 0xFFFF_0000` is read-only | `rust/src/state.rs:1492-1497`; `ENGINE_PRIVATE_ATTR_BASE` `:1382` |
| `CKA_MODIFIABLE` / `CKA_COPYABLE` defaults | Both default true | `rust/src/state.rs:901,904`; `C_SetAttributeValue` honours `MODIFIABLE=false` at `rust/src/ffi.rs:16199` |
| `C_CopyObject` | Present; a non-SO copy cannot carry `CKA_TRUSTED` | `rust/src/ffi.rs:16096`; test `copy_trusted_requires_so_both_explicit_and_inherited` |
| `CKA_TRUSTED` SO-only | Enforced | `rust/src/ffi.rs:6848` |
| `CKA_WRAP_WITH_TRUSTED` | Enforced | `rust/src/ffi.rs:13072` (`wrap_with_trusted_violation`) |
| Roles | Private objects visible only to the logged-in user (`can_access_object`); `C_Logout` invalidates private handles. R7 (2026-10-02): `C_*` creation defaults `CKA_PRIVATE=TRUE` for data, private and secret keys; a private object outside a user session is `CKR_USER_NOT_LOGGED_IN` | `rust/src/state.rs:1187`; `rust/src/ffi.rs:1184,1216`; commit `3907cdaa` |
| Multiple tokens in one process | `SOFTHSMRUST_SLOTS=N` (1..256) brings slots 0..N-1 online at `C_Initialize` (R8) | `rust/src/cert_discovery_tests.rs:457-486` |
| Certificates | `CKO_CERTIFICATE` objects stored; the SPKI is extracted from an X.509 `CKA_VALUE` (R10); cross-slot discovery fixed (#314). **No X.509 building, path validation, revocation or attestation code.** The only crates are `spki 0.8.0-rc.4` and `pkcs8 0.11.0-rc.11` | `rust/src/ffi.rs:6798` (`x509_subject_public_key_info`), `:2221`; `rust/Cargo.toml:207,227` |
| Persistence | One flat snapshot of all token objects across slots; versioned magic; `CKR_PQCTODAY_SNAPSHOT_FORMAT_UNSUPPORTED` on mismatch | `rust/src/state_snapshot.rs:67,173`; `rust/src/constants.rs:56` |
| Audit | Operation-evidence log with the same record grammar as the C++ engine | `rust/src/oplog.rs` |
| Cancellation | `C_SessionCancel` does not cover key generation | `rust/src/ffi.rs:952` |
| Object read cache | Non-secret attributes cached per thread, epoch-validated; secret attributes are an explicit list | `rust/src/state.rs:207` (`is_secret_attr`) |

## 3. Key classes and replication eligibility

| Key class | Replicable in v1? | Notes |
|---|---|---|
| AES / generic secret keys | Yes | Value plus full attribute set |
| ML-KEM-768 private key (+ its public key object) | Yes | The package carries the stored private-key encoding (seed form or expanded, whichever the object holds; `CKA_SEED` if present) and the public key. P0B fixes which encodings are accepted |
| ML-DSA-65 private key (+ public key object) | Yes | As for ML-KEM. Category 3 sets are the tested baseline; other parameter sets follow the same path if P0B allows them |
| FHE seed (`CKK_PQCTODAY_FHE`, allocated by the FHE plan) | Yes, first consumer | Carries the FHE recovery descriptor as an opaque, authenticated, type-specific extension (FHE plan §5) |
| LMS/HSS, XMSS/XMSS^MT | **No** | State lives in engine-private attributes precisely to stop rewind; a copy is a rewind |
| Threshold-FHE shares | **No** | One-shot transcript state (FHE plan §6.4) |
| Device issuer, attestation, package-signing, recovery-recipient keys | **No** | Device identity is never copied; backup tokens get their own |
| Keys with `CKA_TRUSTED=true` | Value yes, trust no | Trust is a per-token SO decision; the destination SO re-marks it |
| Session objects (`CKA_TOKEN=false`) | No | Only token objects |
| Extractable keys | Not through this feature | They already have standard wrap paths; replication is for keys that cannot use them |

**Eligibility is opt-in and immutable.** A key is replicable only if, at creation or import, it is bound to an SO-enrolled replication policy, through an immutable vendor attribute, and `CKA_COPYABLE` / `CKA_MODIFIABLE` are false. Existing keys are not retroactively replicable. The policy names allowed domains, operations (live clone, offline backup, restore) and whether the destination may only equal or tighten restrictions.

## 4. Trust hierarchy and roles

```text
Test manufacturing CA (ML-DSA-65)    ← host-side tool, outside every token; labelled TEST
  └─ Device certificate (ML-DSA-65), issued directly by the manufacturing root
       ├─ Authentication function cert (ML-DSA-65)
       ├─ Attestation function cert (ML-DSA-65; attestation EKU per the RATS draft)
       ├─ Package-signing function cert (ML-DSA-65)
       └─ Recovery-recipient function cert (ML-KEM-768, keyEncipherment, RFC 9935)
          All function certs signed inside the token by the device key.
```

- **Manufacturing step (test tool).** The device key pair is generated inside the token. The test CA signs a device certificate from a CSR that carries attestation of that key (LAMPS CSR attestation). The CA's private key never enters a token. For fixtures, a published test root with a fixed key may be committed under an obviously test name. For runs, a fresh root is generated per run.
- **Function issuance.** An internal issuer operation creates the function key pairs and signs their certificates. Application `C_Sign` access to the device key is impossible: the device key's allowlist contains only the issuer mechanism.
- **SO enrollment.** The SO installs the manufacturing trust anchor as a `CKO_CERTIFICATE` with `CKA_TRUSTED=true`, using the existing SO-only rule. The SO also installs domain membership, allowed peers and replication policies as public, immutable objects, plus revocation and rotation data.
- **User authorization.** The user authorizes each replication of a private key under an enrolled policy. The SO never sees or uses private keys (R7 and `can_access_object`).
- **Isolation.** Function keys are non-extractable and non-copyable, and their usage attributes are immutable. They are not usable as general signing, decryption or derivation oracles through any application API. This is enforced on the native, FFI, copy, import and attribute-mutation paths.
- **Two-sided policy.** Device authenticity is not authorization: both sides check domain policy for every operation.

## 5. Replication protocol (generic form of FHE plan §6.7)

**Cryptographic profile.** RFC 9180 base mode with draft-ietf-hpke-pq-05, using KEM ML-KEM-768 (`0x0041`) and AES-256-GCM. The KDF is HKDF-SHA384 or SHAKE256; draft -05 allows either, and P0B picks one and records why. ML-DSA-65 signs the package statement. HPKE base mode does not authenticate the sender, so the signature is required. The composition needs an independent protocol review and exact test vectors; it is not a standardized interoperable cloning protocol.

**Bindings.** The canonical, signed package binds:
- protocol version and operation (clone, backup, restore);
- both device and function identities, the domain and the authorization;
- the peer challenges and the recipient KEM key;
- the source object's `CKA_UNIQUE_ID` and its full attribute set (class, type, usage, allowlists and templates);
- the replication-policy digest, the suite, and any type-specific extension (for example the FHE recovery descriptor).

The encapsulation and ciphertext are inside the signed object, and P0B specifies the exact bytes and parser limits.

**Randomness.** Encapsulation randomness is engine-generated. Shipped native and WASM builds reject `pEphemeralSeed` and non-null `pReserved` (F5). Test-only known-answer paths are separate builds and are labelled as such.

**State.** Transport secrets never get caller-visible handles. Each session has a sequence/nonce rule, and consumption is durable before any output leaves the token. A sizing call performs no cryptography and consumes nothing. Lost output can be recovered only as the identical cached result. Receipts are authenticated and bound to the package and the installed object. Duplicate installs are detected by transaction ID.

**Destination object.** It gets a new `CKA_UNIQUE_ID` and policy that is equal or stricter. History attributes are engine-assigned, never caller-asserted. Which values the standard history attributes take is open owner decision 1 (§11).

**Flows.**
1. **Live clone.** Both sides authenticate each other with certificates and fresh evidence bound to the recipient key and the challenges. The source seals the key to the destination's recipient key. The destination checks everything before decapsulating, stages the key, installs it atomically and returns a receipt. The source keeps its key; a move operation is out of scope.
2. **Offline backup.** The same checks as cloning, with a distinct operation label, sealed to an enrolled **backup token's** recovery-recipient key. The package file can be stored offline. A replacement token's new certificate cannot decrypt an old package; only the surviving backup token's recovery key can.
3. **Restore.** The backup token verifies provenance under the archival-validation policy, then either restores into itself or runs a protected clone to a newly authenticated replacement. The archival policy separates certificate expiry from revocation, defines its time evidence, and fails closed. Source evidence describes the source at backup time only.
4. **Redundancy and rotation.** Independent packages go to separately enrolled backup tokens. Recovery-key rotation needs a tested continuity ceremony. If every recovery key is lost, the backups cannot be restored, and that is stated.

**Rollback.** Snapshot rollback of a software token remains a disclosed limitation, as in FHE plan §1.2.

## 6. Attestation (generic form of FHE plan §6.8)

| Purpose | Pinned reference (checked 2026-10-02) | Status |
|---|---|---|
| HSM evidence and request model | draft-ietf-rats-pkix-key-attestation-07, "Evidence Encoding for Hardware Security Modules", 6 July 2026 | Active RATS WG draft; covers HSM migration and clustering use cases |
| Evidence in enrollment | draft-ietf-lamps-csr-attestation-29, 2 September 2026 | Past IETF Last Call ("Waiting for AD Go-Ahead", 16 September 2026); expect an RFC during this plan |
| Enrollment freshness | draft-ietf-lamps-attestation-freshness-08, 4 July 2026 | Active draft |
| ML-DSA in X.509 | RFC 9881 (October 2025) | Proposed Standard |
| ML-KEM in X.509 | RFC 9935 (March 2026) | Proposed Standard |

**Evidence for any key.**
- **Inputs:** a key handle and a verifier nonce.
- **Output:** a public `CKO_DATA` object. It must explicitly set `CKA_PRIVATE=false`, because R7 now defaults created data objects to private.
- **Content:** the RATS claims, filled from token state. They cover the key's PKCS#11 attributes, including `extractable`, `sensitive`, `never-extractable` and `local`, the platform and transaction claims, and an ML-DSA-65 signature by the attestation function key.
- **Exclusions:** no caller-supplied claims. The attestation key is never a generic message-signing oracle.

**Provenance.** A restored or cloned key reports its real creation path. It never claims to have been generated locally or to be the only copy. Source lineage and provenance are reported separately from current-device claims.

**Missing claims.** Where a claim the plan needs has no standard form, such as replication lineage or an FHE descriptor digest, record the gap. Profile the draft's existing extension mechanism rather than invent a format. Draft OIDs still marked TBD stay placeholders, and P0B freezes an interoperable test OID strategy.

**Verification.** Both peers verify evidence inside the engine before replication. A host-side verifier library is also provided for tests and the Hub. Unsigned, stale, misbound or wrong-purpose evidence is rejected, and so is any non-PQC chain.

## 7. ABI candidates (no numbers; P0B decides)

Existing functions only (D13). The candidate mapping is a design starting point, not a conformance claim. P0B runs a semantic review against the v3.2 OS text for each mapping and records GO or NO-GO.

| Operation | Candidate function | Base / unwrapping key | Mechanism parameter carries | Output |
|---|---|---|---|---|
| Issue function key + cert | `C_DeriveKey` | Device issuer key (allowlist: issuer mechanism only) | Purpose, subject, validity | Function key (non-extractable, non-copyable) + `CKO_CERTIFICATE` |
| Key evidence | `C_DeriveKey` | Attestation function key | Target key handle, nonce | Public `CKO_DATA` (DER evidence) |
| Seal for clone/backup | `C_DeriveKey` | Package-signing function key | Target key handle (precedent: `CKM_CONCATENATE_BASE_AND_KEY` passes a second handle), recipient certificate, peer evidence, challenges, transaction ID | Public `CKO_DATA` package |
| Install from package | `C_UnwrapKey` | Recovery-recipient function key | Package bytes are the wrapped data; policy reference | The restored key. `C_UnwrapKey` is the import side, so it does not touch the source's extractability rule. A paired public key is created from the authenticated public value in the package |
| Receipt | `C_DeriveKey` or output attribute of install | Authentication function key | Transaction ID | Public `CKO_DATA` receipt |

- **Why the target key is not the base key.** `C_DeriveKey` requires `CKA_DERIVE=true` on its base key. Making the replicated ML-DSA or AES key the base would force a derive permission onto it.
- **Gate on the target key.** The target handle in the parameter is access-checked. It must be eligible (§3), and the replication mechanism must be in its immutable allowlist.
- **What P0B fills in.** P0B specifies fixed-width parameter layouts, sizes, `C_GetMechanismInfo` values and error codes. It also specifies that a failure leaves no object behind and how the per-type extension slot works.
- **NO-GO path.** If an existing function cannot express an operation honestly, P0B records NO-GO and asks the owner rather than hiding a new API inside ordinary wrap.

## 8. Engine prerequisites (moved from FHE plan §10)

| ID | Item | Phase |
|---|---|---|
| F1 | Relabel the HPKE vectors as draft-ietf-hpke-pq-05 in `rust/src/hpke_pq_vectors_tests.rs` and the CHANGELOG; the fixture is already the -05 tag, so no re-pin is needed | K1 |
| F3 | Enforce `CKA_DERIVE_TEMPLATE` (today stored and flattened only). Record the C++ gap separately; this plan does not touch C++ | K1 |
| F4 | Bound certificate, evidence and package sizes; specify exact ML-DSA-65 signed bytes | K0B/K1 |
| F5 | Split shipped and test profiles: `wasm-playground` and native release builds without `acvp`. Reject `pReserved` and HPKE `pEphemeralSeed` in shipped artefacts. Ship a feature manifest, and have the Hub check the consumed artefact hash | K1 (exit blocker) |
| F6 | Licence: BSD-2 at the root vs `SPDX: GPL-3.0-only` in `src/lib/vendor_mechanisms.h`; SBOM for new X.509/DER crates | K-1 |
| F7 | Keep the stateful-key engine-private range as is; new attributes stay clear of it | — |
| F8 | Keep `CKM_SP800_108_*` and the other caller-visible KDFs off every replicable key's allowlist. Optional hardening: a key derived from a sensitive base defaults to sensitive and non-extractable | K1 |
| F9 | Internal replication state machine: nonces, durable consumption, receipts, duplicate handling, atomic install | K4 |
| F11 | Device/function issuance and verification, constrained evidence generation, SO policy enrollment, user operation gates | K2–K3 |
| F12 | Ordinary-wrap refusal, history/provenance rules, no import/copy/mutation bypass, recovery-key continuity tests | K4 |
| F13 (new) | Immutable vendor attributes. `attr_mutation_allowed` (`rust/src/state.rs:1492-1497`) exempts the whole public vendor range. Either add an explicit immutable set there, or keep engine-computed values (policy binding, lineage, history) in the engine-private range and expose read-only copies. Confirm first whether that range is visible to `C_GetAttributeValue` | K1 |
| F14 (new) | Snapshot format bump for device identity, enrolled policy, consumption ledger and receipts, with migration from the current magic and a refusal path (`CKR_PQCTODAY_SNAPSHOT_FORMAT_UNSUPPORTED`) | K2 |
| F15 (new) | Cache coherence: an installed or restored key must not be served from a stale entry in the per-thread object read cache or the AWS-LC/ML-DSA key caches. Test that writes bump the epoch | K4 |
| F16 (new) | Audit: clone, backup, restore, enrollment and evidence events emit `oplog` records. The grammar extension is reviewed for parity with the C++ parser, even though C++ will not emit them | K4 |

F2 and F10 are FHE-specific and stay in the FHE plan.

## 9. Phases and exit gates

| Phase | Work | Exit gate |
|---|---|---|
| **K-1 · Freeze inputs** | Commit this plan and the FHE docs (owner-gated). Pin `pqctoday-hsm` main and every draft/RFC revision. Choose the X.509/DER crates and pass the licence/SBOM gate (F6). Record the §11 owner decisions | Pins and decisions recorded; no speculative vendor allocation |
| **K0A · Spikes** | (a) Build and verify an ML-DSA-65 chain to RFC 9881, including the RFC 9935 ML-KEM leaf; measure the WASM size cost. (b) Encode and decode RATS -07 evidence with test OIDs. (c) Semantic review of the §7 mappings against v3.2. (d) Snapshot cost of device identity and ledger. (e) Reuse of the internal HPKE path with deterministic randomness off | Each spike has a written result; §7 rows marked GO or NO-GO |
| **K0B · Normative spec** | ABI (mechanisms, parameter layouts, attributes, errors). Object and role model. Certificate and evidence profiles. Replication protocol and package format. Receipts and ledger. Archival-validation policy. Threat model per scope (§1). History-attribute rule. Allocation batch in `pqctoday-priv/docs/platform/data/pkcs11-vendor-mech-allocation.md` | Independent review of the protocol and suite closed; allocation landed in the authority; no open wire, role or security semantics |
| **K1 · Engine prerequisites** | F1, F3, F5, F8, F13 | Conformance and the full local gate pass; shipped artefacts provably reject both RNG hooks |
| **K2 · Hierarchy (native)** | Test manufacturing CA tool; device enrollment with CSR attestation; function issuance; trust-anchor and policy enrollment; F14 | Two token instances (two slots via `SOFTHSMRUST_SLOTS`, and two processes) enroll under one test root; negative tests for wrong purpose, untrusted root, expired or revoked certificates, and SO/user role boundaries |
| **K3 · Attestation (native)** | Evidence for any key; in-engine and host-side verifiers | Evidence verifies against the chain; tests for stale nonce, misbound key, wrong function and downgrade pass; restored keys report true provenance |
| **K4 · Replication (native)** | Live clone and offline backup/restore for AES, ML-KEM-768 and ML-DSA-65 keys; F9, F12, F15, F16 | Every acceptance case in §10 passes for all three key classes; the exclusions in §3 are refused with the documented error |
| **K5 · Browser/WASM** | Same flows in the WASM build. Two token instances in workers; backup as a downloaded file, restore from an uploaded file. On-screen disclosure that this is an emulator with a test hierarchy | Desktop browser matrix passes; the page states the custody limits |
| **K6 · Hardware roots (after K5; decision 9)** | Bind the device identity key to a board root of trust, the i.MX 95 first, then the KV260. Separate scoping document first, using those board programs' own evidence | Only hardware-backed evidence earns hardware claims; nothing in K1–K5 depends on K6 |

**Critical path:** K-1 → K0A → K0B → K1 → K2 → K3 → K4. K5 follows K4. K6 is optional and later.

**FHE dependency:** FHE plan P1 starts only after K4 exits. The FHE seed is then added as one more replicable key class, carrying its recovery descriptor as the type-specific extension (§5).

### 9.1 Repository gates (from FHE plan §10.1, unchanged)

Every PR that adds a vendor constant, attribute, return code or fixture must satisfy all of these in the same PR:
- the vendor-constant manifest check (`kmip/pkcs11-mech-manifest.json` via `scripts/check_pkcs11_constants.py`; it checks constants even though KMIP is out of scope);
- the mechanism ledger, with an `excluded-by-scope:` reason on the C++ rows;
- the differential-exceptions rule `LEGAL-VENDOR-MECHANISMS`;
- Rust conformance-report freshness;
- vector reachability;
- the allocation authority, which lands before the constants;
- the full `scripts/local-gate.sh` before push.

## 10. Acceptance cases (K4/K5, per replicable key class)

**Positive flows:**
- live clone;
- offline backup, then restore with the source destroyed (a **test instance**, never real data);
- restore to a new authorized token via the backup token;
- backup-key rotation with continuity;
- restricted policy preserved or tightened;
- the key still works after restore (signature verifies, KEM decapsulates, AES decrypts).

**Negative cases (each must refuse):**
- ordinary or authenticated wrap of a replicable key;
- `CKA_VALUE` read;
- copy into a weaker object;
- mutation of the policy, allowlist or eligibility attributes;
- wrong recipient or domain;
- untrusted root;
- wrong certificate purpose;
- expired or revoked credentials under the defined policy;
- stale evidence;
- key substitution;
- tampered package or descriptor;
- weakened destination policy;
- deterministic randomness in shipped builds;
- nonce or session reuse;
- duplicate receipt or duplicate install;
- an excluded key class (LMS, XMSS, threshold share, device key);
- a crash before or after the durable commit;
- concurrent calls on the same transaction.

**Failure guarantees:**
- Failures expose no secret and leave no partial object.
- Restore uses only the package and the surviving backup token, with no dependence on the source token's storage.

## 11. Owner decisions

Recorded 2026-10-02. Decisions 1–8 come from the owner's "proceed" at 16:33 CDT; decision 9 from a later owner answer the same evening. The coordinator
session had asked "defaults for 1–8, choose 9" and relayed the answer; it is not a quote of each
decision.

| # | Question | Decision |
|---|---|---|
| 1 | What a cloned key reports about its own history | **Imported, plus provenance.** The clone follows the PKCS#11 v3.2 rule for keys from external material: `CKA_LOCAL`, `CKA_ALWAYS_SENSITIVE` and `CKA_NEVER_EXTRACTABLE` are false, and `CKA_KEY_GEN_MECHANISM` is unavailable. The engine's unwrap path already sets these unconditionally (`rust/src/ffi.rs:14154-14158` at `b8402936`). A read-only vendor provenance attribute and the attestation evidence record that the key is a protected clone of a key that was generated locally and never extractable |
| 2 | Which keys can be cloned | **Opt-in only.** A key must be bound at creation or import to an SO-enrolled replication policy, through an immutable attribute. Existing keys stay unclonable |
| 3 | Copy or move | **Copy.** The source keeps its key; there is no move operation in this plan |
| 4 | Test manufacturing CA | **A host-side test tool, never inside a token.** A fresh root per test run. One published, clearly labelled test root is allowed for fixtures. No production-looking root |
| 5 | Revocation in the first version | **A simple signed revocation list (CRL) from the test CA, checked fail-closed** |
| 6 | New dependencies for X.509 and DER | **RustCrypto crates allowed**, subject to the K-1 licence and SBOM gate |
| 7 | Time source | **Host clock** for certificate validity, with that limitation stated on screen |
| 8 | Commit and push | **A local commit now** of this file and the three FHE docs on `docs/fhe-wrapper-plan-1002`. The owner's direct instruction in this session to execute this plan satisfies the local-commit gate. **Push and a docs-only PR only after tonight's FHE release**; this instruction does not by itself establish that the release gate has lifted |
| 9 | Hardware phase: when, and which board first (i.MX 95 or KV260) | **After the software phases, i.MX 95 first.** K6 starts only once K-1 to K5 have passed their exit gates; the i.MX 95 is the first board for the hardware root of trust, the KV260 follows. Owner answer "After software, i.MX 95 (Recommended)", relayed by the coordinator session, 2026-10-02 |
