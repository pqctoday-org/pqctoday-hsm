# Adversarial review: FHE wrapper + PKCS#11 vendor-extension implementation plan

**Review history:** the findings below assess the original plan. For the final challenge of **v4**, including blockers and acceptance criteria at that revision, see [the v4 final challenge](final-challenge-fhe-wrapper-plan-v4-2026-10-02.md). The [consolidated plan](implementation-plan-fhe-wrapper-pkcs11-vendor-2026-10-02.md) (v5 design, v6 verification pass of 2026-10-02) now records the owner decisions and all review dispositions (§11); its §0.1 lists which of this review's baseline facts have since drifted. Earlier owner questions and findings below are historical; design dispositions do not claim implemented fixes.

Date: 2026-10-02
Reviewed plan: `docs/implementation-plan-fhe-wrapper-pkcs11-vendor-2026-10-02.md`
Review posture: design, security, standards, implementation-baseline, browser, evidence, and delivery challenge
Verdict: **do not start P1–P8 from the plan as written**. Run a corrected preflight first.

## 1. Executive assessment

The plan has a good core direction:

- keep FHE evaluation outside the token;
- retain only compact secret material in the token;
- expose narrowly scoped PKCS#11 vendor mechanisms;
- validate Hub teaching flows with executable scenarios and measured evidence;
- separate native reference runs from the browser demonstration.

It is not yet implementation-ready. Four findings are immediate correctness blockers:

1. The proposed first FHE mechanism, `0x80000015`, is already allocated and implemented as `CKM_PQCTODAY_ECDSA_EXPLICIT_K`.
2. The seed is specified as `CKA_EXTRACTABLE=false` and is later wrapped for backup. PKCS#11 requires the wrapped key to have `CKA_EXTRACTABLE=true`; the current Rust implementation correctly returns `CKR_KEY_UNEXTRACTABLE` otherwise.
3. Finding F1 is stale: this exact HSM baseline already implements pure ML-KEM HPKE KEM IDs `0x0040`–`0x0042`, including ML-KEM-768 and tests. The current IETF work is draft `-05`, while the code vectors are pinned to `-04`.
4. The six Hub flows used as the requirements contract are untracked local files, absent from Hub `origin/main`. They cannot serve as a stable acceptance baseline.

The larger security concern is threshold FHE. The proposed Rust `fhe.rs` multiparty backend does exist, but its current source explicitly calls it incomplete and says common-reference-string generation and required key-switch noise flooding are not fully implemented. Lattigo also warns that retrying its current multiparty protocols can enable key recovery. A successful round-trip test would therefore demonstrate API wiring, not validate the security claims taught by the Hub.

Recommendation: narrow the first delivery to a version-pinned TFHE custody spike plus a corrected seed-backup construction. Treat OpenFHE, Lattigo, CKKS, and transciphering as separate reference-validation tracks until their security models, exact versions, and equivalence claims are specified.

## 2. Evidence baseline

This review used the following state, so later changes can be distinguished from review drift:

| Source | State reviewed | Important observation |
|---|---|---|
| `pqctoday-hsm` worktree | `ceddd554272a6cc434da96df0e30cb5efa8b46b1`, equal to `origin/main` | The plan itself is untracked; current code already contains pure ML-KEM HPKE and mechanism `0x80000015` |
| Vendor allocation authority | `pqctoday-priv` `origin/main`, `docs/platform/data/pkcs11-vendor-mech-allocation.md` | `0x80000015` is allocated to ECDSA explicit-k; the authority also explains the intentional C++/Rust stateful-attribute difference |
| Hub worktree | `83f97d3cf0019596f72e69acd59367fbc6685697`, equal to Hub `origin/main` | All FHE flow/cost/key-map files are untracked; none exists in `origin/main` |
| Sandbox checkout | `7d18b794a7f0f834a65ec675aa819789861b4a81` | Seven commits behind sandbox `origin/main` (`24e624487544e87ba9834f6ed157dd4467e7a0ec`) |
| `fhe.rs` | upstream `main` at `44ad194683f2c483d2ac3eee31eeaf67ed227037` | `experimental-mbfv` exists, but upstream labels it incomplete and unsuitable for sensitive data |

Primary external references checked:

- [PKCS #11 Specification v3.2 OS](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html)
- [IETF draft-ietf-hpke-pq-05](https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/)
- [ISO/IEC DIS 28033-2](https://www.iso.org/standard/87639.html)
- [ISO/IEC FDIS 28033-3](https://www.iso.org/standard/87640.html)
- [ISO/IEC FDIS 28033-4](https://www.iso.org/standard/87641.html)
- [NIST IR 8214C](https://csrc.nist.gov/pubs/ir/8214/c/final)
- [TFHE-rs upstream](https://github.com/zama-ai/tfhe-rs)
- [Poulpy upstream](https://github.com/poulpy-fhe/poulpy)
- [`fhe.rs` upstream](https://github.com/tlepoint/fhe.rs)
- [OpenFHE threshold example](https://github.com/openfheorg/openfhe-development/blob/main/src/pke/examples/threshold-fhe.cpp)
- [Lattigo upstream](https://github.com/tuneinsight/lattigo) and [its security notice](https://github.com/tuneinsight/lattigo/blob/main/SECURITY.md)

## 3. Blocking findings

### B1 — Vendor mechanism allocation collision

Plan references: §5.2 lines 123–138; P0 and P3.

The plan says the next free mechanism is `0x80000015` and assigns it to `CKM_PQCTODAY_FHE_KEY_GEN`. That value is already:

- registered in the private authority as `CKM_PQCTODAY_ECDSA_EXPLICIT_K`;
- defined in `src/lib/vendor_mechanisms.h`;
- defined in `rust/src/constants.rs`; and
- dispatched and tested in `rust/src/ffi.rs`.

Impact: the proposed mechanism block is unusable as written and could silently invoke the explicit-ECDSA-nonce teaching mechanism.

Required change: allocate the complete CKM/CKK/CKA/CKP surface in the private append-only authority before assigning any numbers in this plan. Generate the consumer manifest and make the registry-completeness gate part of P0. Do not describe an attribute block as free based only on a source search.

### B2 — The seed backup policy contradicts PKCS#11

Plan references: §5.1 line 116; §5.2 line 130; §5.3 lines 162 and 167–168.

The seed is created as sensitive and non-extractable, with `CKA_WRAP_WITH_TRUSTED`, and is then passed to `C_WrapKeyAuthenticated`. PKCS#11 v3.2 requires the key being wrapped to have `CKA_EXTRACTABLE=true`. The Rust engine enforces this in both ordinary and authenticated wrap paths.

Impact: the advertised backup and DR flow fails by design with `CKR_KEY_UNEXTRACTABLE`.

Required owner decision:

- **Wrapped-backup model:** seed is `CKA_SENSITIVE=true`, `CKA_EXTRACTABLE=true`, `CKA_WRAP_WITH_TRUSTED=true`; only a trusted, policy-constrained wrapping key may export it.
- **Strict non-extractable model:** remove wrapping entirely and create a separate approved backup/import or replicated-generation ceremony. Do not call that `C_WrapKey` backup.

Whichever model is selected needs role tests for the SO-only `CKA_TRUSTED` transition and negative tests for ordinary users.

### B3 — The implementation inventory is stale and internally misclassifies findings

Plan references: §5.1 line 111; §7 P2; §8 F1 and F7.

F1 is false on the reviewed baseline. `rust/src/constants.rs` defines pure ML-KEM HPKE IDs `0x0040`, `0x0041`, and `0x0042`; `rust/src/native/hpke.rs` implements them; and `rust/src/hpke_pq_vectors_tests.rs` exercises HPKE-12 with ML-KEM-768.

The code and vectors cite draft `-04`; the current IETF document is `draft-ietf-hpke-pq-05`. That is a version-refresh task, not a missing-feature task.

F7 is also misleading. The private allocation authority already records the difference:

- the C++ engine exposes `CKA_STATEFUL_KEY_STATE` and `CKA_LEAF_INDEX` in the vendor range;
- the Rust engine moved security-critical mutable state to engine-private `0xFFFF00xx` identifiers and permanently retired its old vendor values to prevent state rewind;
- the two engines intentionally do not share those state-storage identifiers.

Impact: P2 schedules already-completed work while missing real blockers. It also risks undoing a deliberate anti-rewind remediation.

Required change: regenerate §5.1 and §8 from the exact pinned commit. Replace F1 with “diff and repin HPKE PQ draft `-05` vectors.” Replace F7 with an engine-parity note that preserves the intentional divergence.

### B4 — The Hub is an unversioned, moving requirements source

Plan references: §1 lines 7–28; §7 P5/P8.

The referenced `fheHsmFlows.ts`, `fheHsmCosts.ts`, and `fheKeyMap.ts` do not exist on Hub `origin/main`. They are untracked files in the FHE Hub worktree. Consequently:

- no immutable Hub commit defines the six scenarios;
- the plan cannot prove that its trace “matches the Hub”;
- HSM and Hub work can drift without CI seeing either side;
- strong educational claims and estimates can change during implementation.

Required change: first commit and review the Hub content, or place a versioned scenario contract in a neutral repository. Pin its commit and schema in the HSM plan. Require both repositories to consume the same scenario IDs and evidence manifest.

### B5 — `fhe.rs` can demonstrate wiring, but cannot validate secure threshold FHE as claimed

Plan references: §3 lines 53 and 61–64; §4; §7 P4.

The current `fhe.rs` source does expose `experimental-mbfv`, but its own documentation states that the APIs are incomplete, have unresolved security requirements, and must not protect sensitive data. Its `mbfv` module specifically says common-reference-string generation and required key-switch noise flooding are not fully implemented; source TODOs note that the noise should be exponential in ciphertext noise.

Impact: a three-token decrypt-equals-plaintext test is insufficient evidence for protocol fidelity or security. The plan’s “experimental is acceptable” rationale conflates arithmetic/API correctness with protocol-security completeness.

Required change:

- classify the `fhe.rs` path as an **insecure research wiring demonstrator**, not validation of the OpenFHE threshold flow;
- do not expose it behind production-shaped PKCS#11 mechanisms until the missing security steps are implemented or explicitly impossible to invoke unsafely;
- validate the named OpenFHE flow with OpenFHE itself;
- define a separate, accurately named Rust MBFV flow if it remains useful.

### B6 — The WASM release path enables the ACVP-only RNG hook

Plan reference: §8 F5.

This is already documented in `docs/rust-engine.md`, but the plan treats it as a non-blocking “decide which is right.” `rust/Cargo.toml` says shipped artifacts must not enable `acvp`, because it accepts deterministic RNG seeding through non-null `C_Initialize.pReserved`. `rust/build-wasm-bundle.sh` always builds with `--features acvp` and copies that release into the tracked Hub bundle.

Impact: basing the FHE browser bundle on this script propagates a known release-conformance and security-provenance defect.

Required change: make this a pre-P1 release blocker. Split explicit `wasm-playground` and `wasm-acvp` build profiles; embed a machine-readable feature manifest; test that shipped WASM rejects non-null `pReserved`; and verify the consumed Hub artifact hash.

### B7 — `C_SessionCancel` cannot cancel the proposed long key-generation call

Plan references: §5.1 line 118; browser/user-experience assumptions.

The Rust implementation cancels active encrypt, decrypt, digest, sign, verify, find, and message-operation state. It has no key-generation flag, cancellation token, or cooperative checks inside synchronous `C_GenerateKey`/`C_DeriveKey`. PKCS#11's session-cancel flags do not create a general-purpose cancellation channel for an arbitrary synchronous key-generation implementation.

Impact: a multi-second server-key derivation can block the WASM worker and cannot be stopped as promised.

Required change: define a real async job interface or chunked vendor operation with progress, cancellation, resource accounting, and atomic cleanup. If no vendor async interface is approved, remove the cancellation claim and run the synchronous call in a disposable worker that can be terminated without leaving token objects behind.

### B8 — Top-level validation criteria contradict the Lattigo plan

Plan references: §1 condition 3 versus §5.3 line 173.

The definition of “validated” requires HSM-side steps for every scenario to run through PKCS#11. The Lattigo flow is explicitly planned as a Go sandbox flow with no PKCS#11 path unless an owner later expands scope.

Required change: define two validation levels:

- **reference-validated:** exact named library/protocol runs end to end outside PKCS#11;
- **token-validated:** specified secret-side operations run through the vendor PKCS#11 ABI.

Do not present reference-only Lattigo evidence as token validation.

## 4. High-severity design gaps

### H1 — The vendor ABI is underspecified

The plan lists structs and attributes but does not define a portable wire contract. It needs, before implementation:

- fixed-width fields and byte order rather than native pointer-bearing structures for protocol messages;
- a maximum length and canonical encoding for parameter-set identifiers;
- an allowlisted parameter registry, not caller-supplied arbitrary cryptographic parameters;
- serialization version, algorithm version, and parameter hash semantics;
- maximum input/output/object sizes and pre-allocation checks;
- mechanism/key-class/key-type compatibility tables;
- required, forbidden, default, mutable, sensitive, and SO-only attributes for every object class;
- `C_GetMechanismInfo` flags and meaningful min/max values;
- query-then-fill behavior, all error codes, and no-object-on-failure guarantees;
- transcript/session ID, protocol epoch, round, participant-set digest, CRP/CRS digest, and share type for multiparty messages.

Without these, a `CK_PQCTODAY_FHE_SHARE_PARAMS` carrying CRP data and a peer list is not stable across native, WASM, 32/64-bit, or language boundaries.

### H2 — Threshold replay, retry, mix-up, and malicious-share threats are absent

The Lattigo project warns that repeated shares for the same public polynomial and secret-key share can permit key recovery; its current countermeasures do not make protocol retries safe. The plan currently adds a rate limit only to decryption policy and does not bind shares to a unique transcript.

The design must specify:

- security model: honest-but-curious versus malicious participants and aggregator;
- one-time transcript state with durable anti-replay/anti-rollback counters;
- authenticated party and round binding for every share;
- behavior after timeout, crash, retry, party-set change, and partial completion;
- malformed-ciphertext and decryption-share validation;
- whether correctness proofs or commitments are required;
- what is persistently audited and what survives restart.

TLS transport alone does not prevent a coordinator from mixing valid shares from different rounds.

### H3 — “OpenFHE validated by fhe.rs” is not a valid equivalence claim

OpenFHE's current threshold example has specific chained key-generation, evaluation-key, lead/main partial-decryption, and fusion semantics. A Rust BFV multiparty implementation of a related paper does not validate OpenFHE's API, parameter selection, serialized artifacts, security options, or CKKS/BGV behavior.

Use three separately labelled lanes:

1. exact OpenFHE reference execution;
2. exact Lattigo reference execution;
3. a Rust MBFV vendor-mechanism prototype.

Only claim cross-implementation equivalence after defining and passing parameter, transcript, artifact, and result equivalence tests.

### H4 — Seed regeneration is not a durable backup specification

`keygen_from_seed(param_set, seed32)` needs more than deterministic output in one version. Reproducible DR requires:

- an algorithm-defined seed-expansion construction and domain separation per scheme/key kind/share;
- entropy-size justification per backend rather than assuming 32 bytes universally;
- exact dependency commit, compiler/features, parameter definition, and serialization version;
- known-answer hashes for every regenerated artifact;
- an upgrade/migration policy when a library changes generation behavior;
- an archived compatible implementation or explicit rewrap/migration ceremony before upgrade;
- a tested recovery run, not just a unit vector.

The envelope's library version is descriptive; it does not guarantee future reproducibility.

### H5 — The 30 MB attribute export assumption needs a spike, not analogy

Classic McEliece returning about 1.36 MB does not prove that a roughly 30 MB server key is safe. `C_GetAttributeValue` is non-streaming and can create multiple simultaneous copies across Rust, WASM linear memory, wasm-bindgen/JS, and application buffers.

P0 must measure:

- peak native and browser memory across the two-call query/fill pattern;
- copy count and time across the WASM boundary;
- browser memory growth and recovery;
- output caps, quotas, concurrent sessions, and low-memory failure behavior;
- atomic cleanup when `CKR_DEVICE_MEMORY`, timeout, worker termination, or cancellation occurs.

The CKKS counterexample must fail before allocating GB-scale output; it should estimate and return a documented error without destabilizing the process.

### H6 — HPKE backup needs a complete construction and precise compliance language

The current HPKE code returns an AEAD key and base nonce, but the AEAD key template cannot currently request `CKA_WRAP`/`CKA_UNWRAP`; F2 identifies only part of this work. The plan must also specify:

- the exact draft version and suite tuple;
- HPKE sequence-number/nonce handling (the first record uses sequence zero);
- canonical `info` and AAD;
- the authenticated wrapped-key encoding, including tag and version;
- canonical signed manifest framing rather than ambiguous `enc || wrapped || info` concatenation;
- suite IDs and downgrade protection;
- query/fill object-lifecycle tests and orphan-object cleanup;
- interoperation against published HPKE PQ vectors where applicable.

The alternative `ML-KEM → HKDF → AES-KWP` is a KEM/DEM wrapping construction, not HPKE. “Uses approved algorithms” must not be presented as “FIPS validated” without a validated module, approved mode, operational environment, and certificate scope.

### H7 — Decryption policy is not an enforcement design

An opaque `CKA_PQCTODAY_FHE_DECRYPT_POLICY` does not define:

- who may create or update it and whether it becomes immutable;
- which typed outputs are legal and how they are canonically decoded;
- maximum plaintext/result size and overflow behavior;
- noise-flooding floor and parameter derivation;
- rate-limit scope, persistence, multi-tenant behavior, and anti-rollback;
- ciphertext conformance/malformed-input validation;
- audit-event schema and failure privacy;
- resistance to adaptive decryption-oracle and failure attacks.

The threat model and policy specification must precede `CKM_PQCTODAY_FHE_DECRYPT`.

### H8 — Browser emulation is not an HSM security boundary

The live Hub flow uses a WASM SoftHSM emulator. It cannot provide hardware tamper resistance, protected seed custody, non-exportability against the page, or a hardware root of trust. The educational UI and evidence manifest must explicitly distinguish:

- browser emulator behavior;
- native software token behavior; and
- claims that require a real certified HSM/vendor implementation.

Otherwise the live demonstration teaches stronger custody guarantees than it provides.

### H9 — Browser support and delivery constraints are incomplete

The plan needs a supported-platform matrix and testable delivery budget:

- exact TFHE-rs feature set and pinned release/commit;
- single-thread and cross-origin-isolated thread modes;
- COOP/COEP, CSP, worker, and service-worker implications;
- compressed/downloaded/instantiated WASM sizes and cold-start time;
- memory on each supported browser, not only aggregate operation memory;
- progress, timeout, tab-backgrounding, worker termination, and recovery;
- integrity pinning of the lazy bundle;
- a clear definition of unsupported mobile behavior.

“Run it and allow failure” conflicts with a browser validation requirement unless mobile is explicitly unsupported and the UI is a non-live evidence view there.

### H10 — Licensing needs a gate, not an owner note

The HSM root and package metadata are BSD-2-Clause, while `src/lib/vendor_mechanisms.h` carries `GPL-3.0-only`. TFHE-rs uses BSD-3-Clause-Clear but its upstream README separately states that commercial use requires a patent licence. Poulpy currently describes itself as Apache-2.0; `fhe.rs` is MIT and unaudited.

Required P0 evidence:

- resolved licence for this repository and the anomalous header;
- copyright-licence and patent-licence analysis as separate questions;
- exact dependency commits, licence files, notices, and transitive SBOM;
- distribution decision for Hub WASM and sandbox images;
- approved-use statement for commercial versus educational/research deployment.

No dependency should be integrated before this gate closes.

## 5. Scenario-by-scenario challenge

| Scenario | Current plan can prove | It cannot yet prove | Required correction |
|---|---|---|---|
| CKKS single-HSM counterexample | Size/time for one pinned Poulpy parameter set on measured hardware | Universal inability of every HSM, PKCS#11, or KMIP implementation; OpenFHE-sized artifacts from Poulpy | Measure named library/version/parameters; describe product/API limits as scoped observations; run OpenFHE for OpenFHE claims |
| TFHE single-HSM custody | Software-token API path and browser-emulator behavior | Hardware-HSM feasibility, tamper resistance, durable deterministic recovery, or stated performance budgets | Start here, but label emulator/software evidence and pin seed expansion, TFHE version, parameters, hardware, and browser |
| OpenFHE 3-of-3 | Exact OpenFHE reference example in sandbox | OpenFHE validation via incomplete Rust MBFV or equivalence across BFV/BGV/CKKS | Keep exact OpenFHE reference lane; rename Rust lane; do not inherit OpenFHE claims |
| Lattigo 2-of-3 | Exact pinned Lattigo reference flow | PKCS#11 validation or retry-safe deployment | Label reference-only; incorporate upstream retry/key-recovery warning and one-shot transcript requirements |
| HSM compute limits | Measurements for tested software/hardware configurations | Absolute claim that HSMs cannot compute or export a size, or that all keygen/decrypt “belong” there | Replace absolutes with evidence-scoped limits and a decision model by key size, memory, timeout, and vendor API |
| TFHE/Kreyvium transciphering | Exact pinned TFHE-rs app execution if the API remains present | Stability, WASM viability, or HSM-side implementation merely from repository presence | Pin release/commit and test vectors; separate server-side app operation from token calls; measure bundle and runtime |

## 6. Freshness corrections

- ISO/IEC 28033-2 is currently a DIS for BGV/BFV, not a published International Standard.
- ISO/IEC 28033-3 is currently an FDIS for CKKS, not a published International Standard.
- ISO/IEC 28033-4 is currently an FDIS for look-up-table-based arithmetic, not a published International Standard.
- NIST IR 8214C is a final 2026 **call for submissions/reference material**, not an FHE or threshold-FHE standard and not validation of a submission.
- `draft-ietf-hpke-pq-05` is the current IETF draft reviewed here. Pure ML-KEM identifiers remain `0x0040`–`0x0042`, but the implementation must pin and diff the current draft rather than cite `-04` indefinitely.
- Lattigo v6 describes itself as fast-evolving with backward-incompatible changes possible within v6. “Lattigo v6 stable” is too strong; pin an exact tag and commit.
- Poulpy is evolving quickly and currently requires a pinned toolchain for parts of its CKKS stack. Pin exact commit, backend, features, target ISA, and toolchain.

## 7. Missing evidence and acceptance gates

The following gates should be added before implementation approval:

1. **Requirements provenance:** committed Hub scenario contract and exact commit pins for HSM, Hub, sandbox, and every cryptographic library.
2. **Registry:** collision-free allocations committed to the private authority and checked by generated manifests.
3. **ABI specification:** normative proposal with layouts, bounds, error behavior, state machine, object templates, and compatibility tables.
4. **Threat models:** single-party custody, browser emulator, threshold N-of-N, threshold t-of-N, backup/DR, and malicious coordinator.
5. **Dependency fitness:** build spike, deterministic-keygen spike, WASM spike, security-warning inventory, licence/patent approval, and SBOM.
6. **Backup proof:** successful backup/recovery under the selected extractability policy, negative role/policy cases, canonical signature manifest, and cross-version recovery test.
7. **Resource safety:** fail-fast size estimates, quotas, concurrent-load test, cancellation/worker termination, OOM cleanup, and orphan-object checks.
8. **Protocol safety:** transcript binding, no-retry enforcement, replay/mix-up negatives, malformed ciphertext/share negatives, crash recovery, and persistent anti-rollback state.
9. **Evidence schema:** library commit, parameters/hash, compiler and feature flags, hardware/OS/browser, warm-up, sample count, distribution, peak-memory method, artifact hashes, and measurement timestamp.
10. **Claim gate:** every Hub sentence must map either to a primary source or to a versioned measurement artifact. Estimates remain visibly estimates.

## 8. Recommended re-sequencing

### P-1 — Freeze and correct the inputs

- Commit or version the Hub scenarios.
- Pin all repository and dependency revisions.
- Regenerate the current-engine inventory.
- Correct F1/F7 and allocate non-conflicting vendor IDs.
- Decide the backup extractability model and licence/patent posture.

Exit: immutable requirements/evidence manifest and all blocking owner decisions recorded.

### P0 — Security and ABI specifications

- Write the vendor-mechanism proposal before code.
- Define threat models, object templates, wire formats, protocol state, quotas, cancellation model, and negative behavior.
- Separate emulator claims from hardware-HSM claims.

Exit: reviewable normative ABI and security design with no open semantics.

### P1 — Correct existing engine prerequisites

- Remove ACVP from shipped WASM and add artifact-feature attestation.
- Enforce `CKA_DERIVE_TEMPLATE` with a two-engine conformance matrix if both engines remain in scope.
- Refresh HPKE PQ vectors to the pinned current draft.
- Implement and test the selected backup construction, including AEAD-key usage attributes if HPKE sealing is retained.

Exit: existing engine passes conformance and backup recovery tests without FHE code.

### P2 — Minimal TFHE custody spike

- One pinned TFHE parameter set only.
- Native software-token flow first: seeded keygen, server/public derivation, signed manifest, encrypt, decrypt, backup, recovery.
- Measure output/memory/copy behavior before committing to the PKCS#11 ABI.

Exit: evidence shows the design fits stated native budgets and is recoverable.

### P3 — Browser emulator

- Separate lazy bundle with explicit non-ACVP feature manifest.
- Worker isolation, progress, termination, memory limits, integrity hash, and browser matrix.
- Clear educational disclosure that this is not hardware-protected custody.

Exit: supported desktop matrix passes; unsupported platforms display evidence rather than a broken live control.

### P4 — Reference validation tracks

- Exact OpenFHE reference flow.
- Exact Lattigo reference flow with retry limitations surfaced.
- Exact Poulpy CKKS measurements.
- Exact TFHE-rs Kreyvium flow.

Exit: each named scenario is validated by the library it names, with primary-source and measurement provenance.

### P5 — Optional Rust multiparty prototype

- Only after explicitly accepting the upstream security limitations.
- Name it Rust experimental MBFV, not OpenFHE validation.
- Do not ship production-shaped token claims until CRS, noise flooding, transcript/retry, and malicious-input defenses are resolved.

### P6 — Hub integration

- Import signed/versioned measurement JSON.
- Replace only estimates actually covered by equivalent parameters and platform evidence.
- Preserve estimate/measurement/source labels and deep links to evidence.

## 9. Owner decisions still required

1. Is the target a production-shaped PKCS#11 design, or an explicitly insecure educational emulator API? The current plan tries to serve both with one surface.
2. Should the seed be wrap-exportable under trusted wrapping policy, or truly non-extractable with a separate DR ceremony?
3. Are OpenFHE and Lattigo scenarios reference-only, or must every secret-side operation have a PKCS#11 path?
4. Is a Rust MBFV wiring demo valuable if it is clearly labelled incomplete and kept out of production claims?
5. Is TFHE-rs's separate commercial patent-licence requirement acceptable for the Hub/WASM distribution and intended use?
6. Is KMIP deliberately out of scope for the first release? If yes, remove ambiguous cross-protocol claims; if no, design the KMIP object/operation mappings in P0 rather than after PKCS#11 lands.

## 10. Approval recommendation

Approve only **P-1 and P0** after this review. Do not approve dependency integration, vendor-mechanism implementation, browser bundling, or Hub claim replacement until B1–B8 have explicit resolutions and tests.

The most efficient path to useful evidence is a narrow TFHE custody experiment. The least defensible path is implementing all four libraries behind one vendor ABI and treating successful plaintext recovery as proof of protocol security or HSM feasibility.
