# Final challenge: FHE wrapper plan v4

Date: 2026-10-02.

Reviewed: implementation plan v4; the [same plan path now contains the consolidated v5 design, re-verified as v6](implementation-plan-fhe-wrapper-pkcs11-vendor-2026-10-02.md).

**Consolidation status (2026-10-02):** v5 incorporates the owner decisions and dispositions all
FC-1–FC-8 findings in §11.3. This document retains the historical v4 assessment and discussion
trail. Design corrections are not implementation/test evidence; the main plan's P0/P1/P2 gates
remain mandatory.

Baseline: HSM commit `ceddd554272a6cc434da96df0e30cb5efa8b46b1`; plan SHA-256 `f2f3a628deb63bf9086280ead171a7d3c7489a7a61c39a86b02827f35134139b`. Line references below refer to that exact file. The plan is untracked, so the content hash matters independently of the code commit.

## Assessment

Proceed with the proposed P-1/P0 investigation, with the corrections below included in its deliverables. **Do not treat v4 as ready to implement P1.** The direction is substantially improved: client-key-only recovery, the SO/user split, optional threshold lanes, a real Lattigo oracle, and keeping large public objects out of snapshots address concrete earlier defects.

Eight remaining findings are listed below: five high-priority design gaps and three medium-priority specification/test gaps. These are static review findings, not claims of an executed exploit or failed FHE integration. No builds, model downloads, browser runs, or hardware operations were performed. The proposed vendor mechanisms do not exist yet.

| ID | Priority | Remaining gap | Close by |
|---|---|---|---|
| FC-1 | High | Backup restrictions are bypassable unless mutation and copy rules are specified | P0B design; P1 tests |
| FC-2 | High | HPKE deterministic-randomness hook is outside the proposed release guard | P0B design; P1 tests |
| FC-3 | High | The seed's derive template conflicts with the public-object output | P0B ABI |
| FC-4 | High | SO-only decryption policy has no executable provisioning/recovery ceremony | P0B design; P1/P2 tests |
| FC-5 | High | Threshold retry protection needs protocol-specific public-input bindings | Threshold P0B; before P5 GO |
| FC-6 | Medium | Recovery metadata does not explicitly bind all key-generation and policy inputs | P0B recovery format |
| FC-7 | Medium | Statistical and rollback acceptance tests promise more than they can establish | P0B test specification |
| FC-8 | Medium | Phase dependencies and frozen-budget timing remain inconsistent | Before P-1 starts |

## FC-1 — Make backup-key restrictions immutable and enforce them across every API

**Plan:** lines 194–198, 209–223, 335–364; F9 at line 449.

The SO creates a public session AES key with `CKA_ENCRYPT=false`, a wrap template, a single-use flag and a bound nonce. The template omits `CKA_MODIFIABLE=false` and `CKA_COPYABLE=false`. These default to true in `rust/src/state.rs:735` and `:738`. `C_SetAttributeValue` checks modifiability at `rust/src/ffi.rs:15939`; `attr_mutation_allowed` explicitly permits vendor-attribute changes at `rust/src/state.rs:1330` and does not make `CKA_ENCRYPT`, mechanism allowlists or wrap templates immutable.

Consequently, the new flags alone would not establish the promised restriction. Under the existing generic rules, a caller could change the single-use flag or bound IV, loosen the wrap template, or enable ordinary AES-GCM encryption. F9 adds checks only to authenticated wrap/unwrap, so a changed usage permission could reach a different operation path. `C_CopyObject` is another route: the current code correctly removes trust on a non-SO copy, but a copy still contains the same AES material and could be given encryption permissions. Loss of trust prevents wrapping this seed; it does not prevent nonce reuse through ordinary encryption.

**Required correction:** define an engine-enforced backup-key profile: sensitive, non-extractable, non-copyable, non-modifiable, with immutable usage, recipient/suite binding, wrap/unwrap template and bound IV. Fix those values during creation, reject conflicting caller templates, and define the receiving key's consumption/cleanup rules too. Give FHE lineage, parameter identity, policy and transcript attributes explicit mutation rules rather than relying on the generic vendor range. The public object is accessible between role transitions, so enforcement cannot rely on caller discipline.

**Acceptance:** ordinary/public/user sessions cannot change these fields or copy the key into a usable alternative. Test encrypt, decrypt, derive, wrap and copy routes, two competing calls, errors and session closure. A sizing query should calculate length without invoking AES-GCM; a small-buffer result should not consume the key. Exactly one successful output is possible, and errors must not leave a reusable key after output release.

## FC-2 — Guard the HPKE randomness override separately from ACVP initialization

**Plan:** lines 331–341 and 371; F5 at line 445.

The release guard currently checks non-null `C_Initialize.pReserved`. HPKE has a separate deterministic hook: `C_EncapsulateKey` reads `pEphemeralSeed` at `rust/src/ffi.rs:4713–4752` and forwards it directly to encapsulation. That path has no test-profile check in the reviewed code. The HPKE proposal itself says this hook is for test contexts (`docs/proposals/pkcs11-ckm-hpke-mechanism-proposal.md`, §8).

**Design inference:** with base-mode ML-KEM HPKE, a caller that supplies known encapsulation randomness can reconstruct the shared secret and HPKE key schedule from that randomness and the public inputs. A non-extractable output handle does not make the resulting backup key unknown to that caller. Reusing the override can also recreate the same key/nonce under a new handle, bypassing a per-handle single-use rule. This is a release-profile gap, not an assertion that a normal user can independently create a trusted key.

**Required correction:** the backup profile must reject caller-supplied encapsulation randomness. Keep deterministic hooks in an explicitly marked test build/API and cover native as well as WASM entry points. Check output-template overrides cannot undo the fixed sensitive/non-extractable profile.

**Acceptance:** every supported shipped ABI rejects nonempty overrides before creating objects; test builds retain published-vector coverage; two normal ceremonies use fresh internal randomness. Cite the selected suite's key schedule and randomness requirements in the P0B construction. [RFC 9180, §§5.1, 9.7.5](https://www.rfc-editor.org/rfc/rfc9180.html#section-9.7.5), [ML-KEM HPKE draft -05](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-05).

## FC-3 — Remove the conflict between the seed template and public derivation

**Plan:** lines 176, 194–198 and 320.

The seed forces `CKA_DERIVE_TEMPLATE={CKA_SENSITIVE=true, CKA_EXTRACTABLE=false}` while its allowed derive operation produces a `CKO_PUBLIC_KEY` that must be exported. Those attributes describe private/secret keys, not the standard common-public-key object shape. Once F3 actually enforces the derive template, this cannot simply be ignored for `FHE_DERIVE_PUBLIC`.

The local PKCS#11 v3.2 OS PDF, §5.18.5, requires the base derive template to participate in output construction and requires conflicting templates to fail. Its common public/private/secret key tables distinguish their attributes. The engine already documents avoiding these attributes on public keys (`rust/src/ffi.rs:3869`). A permissive store accepting arbitrary attributes would not resolve the standards or export-policy ambiguity.

**Required correction:** define one coherent public-session-object path. For a seed that only derives public material, use output constraints appropriate to that class and enforce the secret-custody restrictions inside the vendor mechanism. Do not silently skip a standard derive template. Resolve the alternative “or as output bytes” in §6.6: `C_DeriveKey` normally returns an object handle, so a byte output needs an explicitly specified vendor parameter contract if retained.

**Acceptance:** with F3 enabled, derive/export succeeds for the documented public object, token persistence is refused for large material, a caller cannot change the output into an exportable secret object, and conflicting templates fail without orphan objects.

## FC-4 — Define who provisions the SO-owned decrypt policy

**Plan:** lines 194–198, 227–228 and 360–365.

The decryption policy is described as SO-set and immutable after creation, but the FHE seed is private and visible only to the normal user. The DR procedure expressly needs no SO. The two-step ceremony solves trusted wrapping-key creation; it does not explain how the SO supplies or authorizes a policy on the private seed or how that authorization survives recovery.

The role restriction is real: `rust/src/state.rs:1021`, `can_access_object`, permits private-object access only under the user login. Deferring “SO-set” to the attribute table leaves the same kind of unusable ceremony that v4 otherwise fixed.

**Required correction:** specify an SO-approved policy object/profile that the engine resolves and copies into user-created seeds, or another explicit authorization mechanism using the existing function surface. Define how a DR token obtains that policy authority. If DR must remain SO-free, state how the engine verifies the recovered policy against a pre-provisioned policy or authenticated backup authorization. The normal user must not be able to select a weaker arbitrary policy.

**Acceptance:** generate, backup and restore a seed with a non-default restrictive policy using only the documented roles. Policy replacement, missing policy authority and mismatched policy digests fail. The SO still cannot access seed bytes or perform seed decryption.

## FC-5 — Bind retry prevention to the actual cryptographic inputs

**Plan:** lines 250–255 and 273–283; T5 at line 310.

The plan binds transcript metadata and a CRP digest and says an abort can restart with a fresh epoch and common polynomial. That rule needs a separate definition for each protocol. Lattigo key switching, for example, takes a ciphertext and computes with its second polynomial; `GenShare` does not take an independently replaceable CRP. A fresh epoch or unrelated CRP digest does not change that input. [Pinned Lattigo v6.2.0 `KeySwitchProtocol.GenShare`](https://raw.githubusercontent.com/tuneinsight/lattigo/v6.2.0/multiparty/keyswitch_sk.go).

Lattigo's warning also covers changes to active party sets. Do not key the consumed-state ledger only by fresh transcript IDs, epochs, or temporary additive-share handles: those can change while the underlying long-lived secret and relevant public input remain the same. [Lattigo v6.2.0 security notice, “On the insecurity of retries”](https://github.com/tuneinsight/lattigo/blob/v6.2.0/SECURITY.md).

**Required correction:** P0B must define a retry/consumption key for each protocol, including the stable secret lineage and the actual relevant public polynomial, input ciphertext, recipient key and participant bindings. Specify canonicalization across equivalent ring encodings, protocol rounds and t-of-N combinations. State which failures require a genuinely new ciphertext/key setup and which permit only retransmission of the identical cached share. Commit consumed state before releasing a share. Do not promise that changing the epoch alone makes retries safe.

**Acceptance:** retries with a new transcript ID, changed party subset or temporary share handle still fail when they reuse the prohibited underlying inputs. Legitimate rounds pass. Crash injection cannot release two freshly randomized shares from the same forbidden state. Have the independent reviewer approve this exact rule before the threshold lane proceeds.

## FC-6 — Bind the complete recovery descriptor and define migration beyond rewrapping

**Plan:** lines 127–134, 334 and 365.

Client-key reproduction depends on KDF encoding, algorithm-version ID, backend/configuration and serialization semantics. The backup manifest explicitly lists a parameter hash and lineage, but does not expressly bind a complete recovery descriptor or decrypt-policy identity. These might be included in the parameter hash, but the plan does not say so. Current authenticated wrapping encrypts the key value, not the full attribute set (`rust/src/ffi.rs:14254`), so lost attributes cannot be assumed to reappear from unwrap.

Rewrapping the same seed cannot by itself compensate for a backend changing how that seed maps to a client key.

**Required correction:** define a canonical recovery descriptor containing, or cryptographically committing to, every KDF/key-generation input, backend algorithm/configuration version, policy digest and encoding version. Include it in the signed and authenticated backup construction. Either keep a version-dispatched old generator available or specify a real cryptographic migration of data/key material before removing it.

**Acceptance:** restore from the backup package into an empty compatible token and decrypt pre-backup ciphertext. Tampering with or omitting any required descriptor field fails. An unsupported old generator version fails explicitly rather than producing a different key. An upgrade test proves the chosen migration path.

## FC-7 — Separate observable tests from security claims

**Plan:** lines 231 and 306–311, read against lines 70 and 254.

T4 asks for a measured decryption-failure rate within the parameter bound. Finite testing cannot establish a probability of `2^-128`: with zero failures in N independent trials, the approximate one-sided 95% upper bound is `3/N`, still vastly larger for any practical N. Keep distribution/correctness tests, but use a cited analytical bound and its applicable assumptions for the cryptographic claim. TFHE-rs ties its IND-CPA-D statement to its parameters and algorithmic setting; it does not turn every arbitrary-ciphertext decryption API into a secure oracle. [TFHE-rs security documentation](https://docs.zama.org/tfhe-rs/get-started/security-and-cryptography).

T5 also promises rejection of “rolled-back round state,” whereas §1.2 correctly says whole-host snapshot rollback cannot be resisted.

**Required correction:** distinguish analytical security evidence, reproducibility tests and empirical sanity checks. Specify allowable input/computation assumptions for the decrypt API. Split stale messages presented to current state (must reject) from restoration of an older whole-token snapshot (known limitation, explicitly demonstrated and disclosed).

**Acceptance:** every statistical result records N and a confidence statement; no empirical test claims to prove negligible failure. The rollback suite reports the supported rejection case separately from the intentionally unprotected host-rollback case.

## FC-8 — Make the delivery dependencies match the stated scope

**Plan:** lines 77, 166, 183, 375 and 416–425.

Several inconsistencies remain:

- P-1 freezes a contract containing budgets, but §7 says budgets are set from P0A measurements. Freeze scenario semantics first; freeze numeric budgets in a versioned P0A exit update. Set acceptable user-experience limits before accepting measurements as “passing.”
- P0A still lists SP 800-108 “with the proposed FHE seed type,” although §6.2 explicitly removes that caller-visible requirement. Name the internal KDF compatibility test instead.
- P1 promises the D2 recovery and KDF-negative tests with no FHE backend. Define whether it uses a test-only opaque seed fixture/type; keep actual client-key regeneration in P2.
- The normative ABI is required “before any code,” but P0A explicitly needs executable feasibility spikes. Permit isolated spike code while keeping shipped mechanisms behind the later gates.
- P7 follows optional threshold and ARM phases, although those are declared nonblocking. State that TFHE Hub integration depends on P2/P3 evidence and its matching reference run; threshold and ARM results can be integrated later.
- Registry completeness at P0 exit must cover batch 1 and approved allocations only, because batch 2 is deliberately deferred to P5.

These are scheduling/specification defects, not reasons to reopen the selected libraries or owner decisions. Put the dependency graph and phase-specific acceptance artifacts into §9 before execution.

## Final disposition

The plan is suitable for a bounded feasibility/specification effort after these findings are added to the gates. P1 should remain blocked until FC-1 through FC-4 have an implementable ABI/role design and FC-6 has an unambiguous recovery format. FC-5 is a gate for the threshold lane and must not delay a correctly scoped TFHE delivery. FC-7 and FC-8 need explicit edits to the acceptance criteria and phase dependencies.

This pass checked v4 against the local engine, the local normative PKCS#11 v3.2 OS PDF, RFC 9180, the cited HPKE draft, and pinned Lattigo source/security guidance. It did not independently execute the Hub's uncommitted flows or revalidate every ISO publication-status entry. The existing P-1 pin/freshness gate remains necessary.

At the time of this review the implementation plan was left unchanged for comparison with the exact v4 baseline. It has since been consolidated as v5; see the status note above. The original review links here and is marked as historical.

## Follow-up: proposed pivot to non-extractable keys and controlled cloning

During this review the owner suggested non-extractable keys with secure HSM-to-HSM cloning, to tighten backup and the security model. This is a proposed replacement for D2/D10, pending the scope clarifications below; it is not yet a revised owner decision or implemented mechanism.

Recommendation: keep the FHE seed sensitive and non-extractable through the application-facing PKCS#11 surface, and give replication its own narrowly authorized vendor protocol. Ordinary wrap operations must continue to reject it. Cloning must authenticate the destination, check that destination's authorization, bind the complete recovery descriptor and restrictions, and install the key directly under an equal-or-stricter policy. The host may relay encrypted protocol messages but must not receive plaintext seed material or caller-controlled transport secrets. Do not temporarily flip `CKA_EXTRACTABLE` or bypass its standard meaning inside ordinary wrapping.

This has an established vendor precedent: Thales documents encrypted cloning between authorized domains and preservation of non-extractability across supported destinations. That is evidence for the architectural pattern, not a claim that our protocol would interoperate with Luna or inherit its security assurances. [Thales domain planning](https://www.thalesdocs.com/dpod/services/luna_cloud_hsm/extern/client_guides/Content/admin_partition/key_cloning/domains_planning.htm), [Thales partition administration guide](https://thalesdocs.com/gphsm/luna/7/docs/network/Content/PDF_Network/Partition%20Administration%20Guide.pdf).

The new design still needs explicit trust enrollment/revocation, source and destination authorization, fresh transport randomness, transcript binding, replay handling, atomic destination installation, acknowledgment semantics and audit. A source copy should remain intact unless a separately authorized move operation is specified. Cloning also creates two usable copies: it does not establish a globally shared rate limit or threshold-consumption ledger. Initially exclude active threshold shares and stateful signing keys from this FHE-seed cloning feature until their duplicated-state semantics have a separate reviewed design.

For this educational software token, peer identity authenticates an enrolled software instance; it does not prove hardware custody or resistance to a hostile host. Real-device attestation and vendor interoperability would be separate deliverables. Existing D1's emulator disclosures remain necessary.

Scope answer recorded: **both live cloning and offline backup are required in the first version**. Offline backup must therefore have an independently recoverable trust/key hierarchy; depending solely on the lost source token would defeat the recovery scenario. The detailed recovery authority and its custody remain to be chosen.

Remaining clarifications:

1. Two instances of our Rust token initially, or actual vendor HSM interoperability? Recommend the former with vendor designs used as references.
2. Offline restore to any newly authorized token in an enrolled recovery domain, or only to a predesignated surviving backup token? Recommend domain-authorized replacement with a separately specified surviving recovery authority. Enrollment alone cannot decrypt an old backup; the recovery authority must retain or recover the required secret under the selected custody policy.
3. Explicit authorization by administrators of both source and destination, or a broader M-of-N approval ceremony? Recommend explicit approval on both sides initially; offline backup creation and later recovery are separate authorizations.
4. Replace the planned wrap-export backup path entirely, or retain it as an explicitly weaker optional mode? Recommend replacement for this FHE feature.

If adopted, FC-1's current wrapping ceremony would be superseded rather than patched. The randomness, policy authority, recovery-descriptor and replay findings still apply to the new protocol. The plan must also reconcile the cloning ABI with D13's existing-functions-only constraint before selecting an API; standard PKCS#11 does not provide a generic interoperable secure-cloning operation.

### Owner clarification: hardware-key ceremony as the trust foundation

The owner clarified that cloning and backup/restore are based on an HSM hardware-key ceremony used for mutual HSM authentication and also intended to support issuing key-attestation certificates, then expressly clarified: **hardware key hierarchy**. The shared foundation is the hierarchy, not a requirement to reuse one operational private key for every purpose. A targeted search of this worktree's `docs`, `rust/src` and `kmip` found no existing ceremony/attestation specification; that is a limited search result, not evidence that none exists elsewhere.

Recommended design within that hierarchy: the ceremony enrolls each device under a trusted authority and provisions separately scoped device-authentication and attestation-signing keys. The cloning protocol authenticates both peers and checks explicit cloning-domain authorization and destination policy. An accepted device certificate alone does not authorize receipt of every key. Session encryption and offline recovery use separately specified encryption/KEM key material: authentication signatures do not themselves make an offline backup decryptable after source loss. Here, hierarchy means explicit certification, authorization and protection relationships; it does not imply that every operational key is deterministically derived from one device secret or that a device's private identity key is shared across HSMs.

Attestation must preserve provenance. A destination may attest that a key was securely cloned/restored and is currently subject to a stated policy; it must not describe it as freshly generated there or uniquely resident there. Device identity keys should remain device-specific rather than being copied with FHE keys. For FHE seeds, define a signed attestation statement bound to the public FHE artifact digest and recovery/policy descriptor; do not assume a conventional X.509 subject-public-key encoding exists for the FHE object itself. The certificate profile and its supported key types remain P0B work.

The hardware-rooted target and the software/browser implementation must remain distinct evidence scopes until the hardware binding is specified and tested. Remaining hierarchy clarifications are the existing hierarchy/ceremony document or intended hardware root, and which independent recovery secret survives loss of the source HSM. The meaning of reuse is now resolved at the hierarchy level.

Further owner clarification: the hierarchy has **manufacturing root keys shared by all HSMs**. The distinction between a shared public trust anchor and replicated private root material remains to be confirmed. Recommended construction: all devices trust the manufacturing root public certificate; the manufacturing root private signing key stays in the protected manufacturing CA infrastructure; each device holds its own unique non-exportable identity/attestation keys certified through that hierarchy. Do not interpret the owner's wording as authorization to replicate a manufacturing CA private key into every device. A cloning-domain/recovery secret, if selected, has a separate purpose and lifecycle from manufacturing identity. Manufacturer authenticity alone must not grant cloning rights across different owners or domains.

Confirmed additional requirements: **backup HSMs participate in the same manufacturing trust hierarchy, and the hierarchy is quantum-safe**. This covers the complete certificate/signature chain and protocol authentication, not just the cloning payload encryption. Candidate primitives for P0B selection are ML-DSA for CA/device/attestation signatures, ML-KEM for establishing cloning/recovery encryption secrets, and AES-256-GCM for authenticated payload protection. ML-KEM is not a signature algorithm. Exact security categories, profiles, key usages, certificate encodings, rotation and downgrade rejection must be pinned rather than inferred from these names. [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final).

An authorized backup HSM authenticates with its own device identity under that trust hierarchy. Its backup/restore permissions remain explicit domain policy. Offline backups must be protected for a surviving backup/recovery authority; manufacturing certificates authenticate that authority but are not themselves decryption secrets. Preserve source identity and key lineage on restore, and attest the destination's restored custody without replacing its unique hardware identity. The manufacturing CA private-key distribution question remains open; the additional backup-HSM scope does not resolve it.

### Confirmed hierarchy: manufacturing → device → functions

The owner specified the exact hierarchy as **manufacturing → device → functions**. Use these three levels for both operational and backup HSMs:

1. **Manufacturing:** common post-quantum manufacturing trust authority.
2. **Device:** a device-specific certificate signed directly by the manufacturing root key, as explicitly confirmed by the owner.
3. **Functions:** function certificates signed by the device key, as explicitly confirmed by the owner, for separately scoped peer authentication, key attestation, and cloning/backup/recovery protection. Signature and KEM keys retain their distinct cryptographic roles.

The proposed relationship is certification and authorization, not an assumption that function secrets are deterministically derived from the manufacturing private key. Each function credential must bind its device, permitted purpose and applicable policy; possession of a manufacturing-valid chain alone does not authorize cross-domain cloning. Fresh session keys are established within the authenticated protocol rather than shared as fleet-wide identity material.

For backup HSMs, the recovery function must retain access to the material needed to decrypt offline backups after the source is lost. Replacement of a backup HSM requires an explicit recovery-key continuity ceremony; a newly certified device identity alone cannot decrypt an existing package. The conventional recommended root custody remains a manufacturing CA private key held centrally and its public trust anchor distributed to devices; the three-level hierarchy does not by itself specify private-key distribution.

## Attestation standards selection — checked 2026-10-02

Owner instruction: **reuse the existing attestation model rather than invent a new one**. The selected design basis combines RATS evidence with LAMPS enrollment/freshness. This supersedes any earlier suggestion to start with a bespoke attestation statement. These references are a proposed implementation profile, not a claim of implemented conformance.

| Layer | Latest published revision checked | Role in our design |
|---|---|---|
| HSM evidence | [draft-ietf-rats-pkix-key-attestation-07](https://datatracker.ietf.org/doc/html/draft-ietf-rats-pkix-key-attestation-07), dated 6 July 2026; active draft | Reuse its ASN.1/DER evidence and request structures. It explicitly addresses key migration and HSM clustering (§2.2) |
| Certificate enrollment | [draft-ietf-lamps-csr-attestation-29](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-csr-attestation-29), 2 September 2026; active draft | Carry evidence in its `AttestationBundle` within PKCS#10/CRMF requests |
| Enrollment freshness | [draft-ietf-lamps-attestation-freshness-08](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-attestation-freshness-08), 4 July 2026; active draft | Reuse nonce acquisition via CMP/EST/CMC when using those enrollment protocols |
| Quantum-safe certificate encoding | [RFC 9881](https://www.rfc-editor.org/rfc/rfc9881.html), October 2025; published Proposed Standard | ML-DSA certificate/public-key/signature encodings for the manufacturing → device → function chain |

RATS §3.2 supports a manufacturer trust anchor leading to an attestation key. Its AK certificate requires `digitalSignature` and `id-kp-attestationKey`. Its evidence represents platform, key and transaction claims, including PKCS#11-aligned `extractable`, `sensitive`, `never-extractable` and `local`. Numeric OIDs still marked TBD must not be represented as final assignments. This draft supplies evidence semantics, not a cloning transport or authorization policy.

LAMPS supplies the enrollment container, not the underlying HSM evidence schema. Its §6.1 requires validation of the evidence/public-key binding; §6.3 discourages copying raw evidence into published certificates. A function certificate establishes the attestation signing key's authority; the signed evidence is a separate artifact. For freshness, bind the nonce inside the evidence. A newly supplied nonce does not automatically make every platform measurement current.

### Project-specific profile work and acceptance gates

The following are our implementation decisions/tests, not additional requirements claimed to be standardized by those drafts:

- Preserve the owner's direct manufacturing-root → device → function certificate signatures. Profile the device certificate as an issuer with appropriate CA constraints; limit function leaves to their permitted purposes. Use the attestation function key only for evidence. Establish its credential before using it to attest other keys, avoiding circular trust.
- Adopt the draft's existing claims first. Source values from token state. Do not allow a caller to request an invented `local=true` or non-extractability history. A restored object must report its actual creation path. Keep source lineage/provenance separately from current-device claims.
- Map an FHE seed using an existing key identifier and applicable claims. Do not expose secret bytes or invent an X.509 SPKI for a symmetric seed. Record any missing public-artifact/policy binding as a profile gap before allocating an extension; reuse the draft's extension mechanism only when the existing model is insufficient.
- Require signed evidence, an accepted PQ certificate chain, request/key binding, bounded freshness and successful local policy appraisal before cloning. Reject unsigned or unsupported alternatives in our profile even where an encoding permits them. Both sides independently check authorization for the requested domain and operation.
- A valid evidence signature is not an authorization to clone. An offline backup's historical evidence does not prove the destination's current state; restore needs fresh destination checks and explicit recovery authorization.
- Freeze the three draft revisions, an OID strategy and test fixtures in P0B. Test key substitution, stale evidence, incorrect function usage, untrusted roots, tampered attributes, cross-domain requests, restored-key provenance and quantum-unsafe algorithm downgrade. Test the attestation function through its own constrained API, not a generic caller-supplied-message signing oracle.
- Keep the browser/native emulator claim scope explicit. No manufacturer endorsement, certification level or hardware measurement is asserted merely because the implementation emits a well-formed evidence object.

This follow-up supplied the concrete attestation references and profile constraints subsequently consolidated into v5 §6.7–§6.8. No replacement attestation format or numeric OID was created, and no code was changed.

### Freshness and explicit PQC coverage check

Rechecked the unversioned IETF Datatracker records on 2026-10-02: CSR attestation **-29**, freshness **-08**, and RATS HSM evidence **-07** remain the latest submitted revisions shown. These are active drafts, not published RFCs. Use version-pinned documents for implementation and the unversioned records to detect subsequent changes.

The three attestation drafts do **not** explicitly name ML-DSA or provide a complete PQC deployment profile. A text search for “quantum” found no match in these revisions. The RATS evidence draft uses extensible signature-algorithm identifiers and has classical ECDSA examples; neither its examples nor a valid evidence encoding proves a quantum-safe implementation. Its reference to CNSA 2.0 is not an implemented PQ algorithm binding.

Use [RFC 9881](https://www.rfc-editor.org/rfc/rfc9881.html) as the explicit published ML-DSA certificate reference, alongside FIPS 204. RFC 9881 discusses NIST PQC security categories. Our evidence-signature profile must explicitly select and test the ML-DSA algorithm, parameters and signed-byte encoding; the attestation drafts alone do not mandate that selection. Require the selected PQ policy across every chain link and the evidence signature, and reject classical-only downgrade.

For the cloning/recovery function's ML-KEM public-key certificate, use the published [RFC 9935](https://www.rfc-editor.org/rfc/rfc9935.html), verified through its RFC Editor record. It explicitly defines quantum-resistant ML-KEM in X.509, including the key encodings and `keyEncipherment` usage. The device's ML-DSA key signs that certificate; its ML-KEM subject key does not sign certificates or evidence. This is a certificate profile, not a complete authenticated cloning or offline-backup protocol.

Owner answers recorded: **pure PQC throughout, ML-DSA signatures; Category 3, ML-DSA-65 and ML-KEM-768**. Apply ML-DSA-65 to manufacturing-root, device and signature-function certificates and to evidence signatures; use ML-KEM-768 for the cloning/recovery KEM function. The manufacturing root signs device certificates, and device keys sign function certificates. These are now explicit owner choices for the new hierarchy, not assumptions carried over from v4. AES-256-GCM remains the proposed payload-protection algorithm. Reject classical-only or hybrid substitution in this selected profile; the choice does not create a Category 3 assurance claim for the separate TFHE backend or the emulator's physical protection.
