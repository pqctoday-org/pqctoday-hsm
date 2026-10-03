# Implementation plan: FHE wrapper + PKCS#11 v3.2 vendor extensions (v7)

Date: 2026-10-02 · Revision: **v7** (2026-10-02, late): owner requirement for typed, policy-gated
decryption (§6.3), the custody TFHE configuration and measured sizes from the pqctoday-fhe spike
(§5, §6.6), and the Hub pin on main (§2). v6 summary follows. The v5 design (non-extractable seeds, live cloning and offline
backup/restore, manufacturing → device → function certificates, pure PQC Category 3, reuse of
RATS/LAMPS attestation) is unchanged. v6 re-verified every code, registry, Hub and upstream claim in
v5 on the evening of 2026-10-02 and corrects what had drifted (§0.1), adds the repository gates a
new vendor mechanism must pass (§10.1), and lists the v4 text still in the Hub worktree (§9, P7).
Reviews: `docs/review-implementation-plan-fhe-wrapper-pkcs11-vendor-2026-10-02.md` and
`docs/final-challenge-fhe-wrapper-plan-v4-2026-10-02.md`.
Status: **consolidated implementation proposal; no implementation or runtime validation claimed**.
**Dependency (owner, 2026-10-02 16:26 CDT, options 1a–4a):** the key hierarchy, live cloning,
offline backup/restore and attestation design in §6.7, §6.8 and F2/F4–F9/F11–F12 now lives in the
standalone HSM plan `implementation-plan-hsm-key-hierarchy-replication-attestation-2026-10-02.md`, generalized to any protected key and delivered **first**.
This plan only *uses* those features: FHE adds the seed key type, its recovery descriptor (§5) and
its decryption policy (§6.3). Where §6.7/§6.8 below and the HSM plan differ, the HSM plan governs.
That plan's code references are at `b8402936`; this plan's remain at `ceddd554`.
This file, its two companion reviews and the standalone HSM plan form the first K-1/P-1
documentation commit on branch `docs/fhe-wrapper-plan-1002`. The branch was fast-forwarded to the
standalone plan's `b8402936` code baseline before that commit; historical code references in this
FHE plan intentionally remain anchored at `ceddd554` until its own P-1 re-pin.

**PKCS#11 baseline (D13).** The reference is the PKCS#11 v3.2 OASIS Standard
(`docs/refs/pkcs11-spec-v3.2-os.pdf`), augmented only with pqctoday vendor mechanisms, key types and
attributes. Existing v3.2 functions remain the ABI constraint; the new vendor replication operations
must pass the P0B semantic mapping gate (§6.2). Ordinary wrapping never bypasses non-extractability.
The v3.3 draft only fills v3.2 gaps, per the repo's standing rule.

Approval scope requested: **P-1 and P0 only.** Nothing in P1 onward starts until the P0 exit gates
in §9 pass.

## 0. Revision history and owner decisions

| Rev | Change |
|---|---|
| v1 | Initial plan |
| v2 | All review findings dispositioned (§11). Mechanism numbers removed until they are allocated. Backup model fixed. Two validation levels defined. Threshold redesigned around a transcript-bound protocol spec. ARM-only acceleration added (§8). FPGA parked |
| v3 | Tightened the v2 design: made the scenario JSON the canonical contract; separated semantic conformance from wire interoperability; added threshold GO/NO-GO gates and independent cryptographic review; scoped rollback claims to a host-controlled software token; specified the trusted HPKE wrapping-key ceremony; removed CKKS and server-side Trivium from the token-linked crate; made browser and ARM support measurement-gated |
| v4 | Code-checked challenge of v3 (§11.2): closed a seed-custody bypass through the caller-visible KDF; replaced the SO-session backup with a two-step SO-then-user ceremony using a single-use AES-GCM key; limited recovery to the client key (TFHE-rs has no seeded server-key generation); switched the Lattigo scenario to BGV with a Rust port validated against Lattigo in Go; moved CKKS measurements from Poulpy to OpenFHE; kept large public material off the token; allocated vendor IDs in two batches; aligned the Hub flows with engine capabilities |
| v5 | Supersedes the v4 extractable-seed/SO-wrap ceremony. Consolidates hardware trust hierarchy, Category 3 PQC, dedicated replication of non-extractable seeds, live cloning plus offline backup/restore, RATS/LAMPS evidence reuse, recovery metadata, role provisioning and all FC-1–FC-8 dispositions (§11.3). Historical dispositions below are retained as history, not current requirements |
| v7 | §6.3 rewritten for the owner's typed-decrypt requirement: conformance-checked type gate, input-type rule with its reslicing limit, post-decrypt predicate with its one-bit limit, requester binding, recipient rule. Custody TFHE config fixed as `use_dedicated_oprf_key(false)` after the pqctoday-fhe spike measured the default server key at 57.4 MB (28.8 MB without the OPRF key). Hub scenario pin moved to Hub main `624115862`. `CompressedServerKey::new` signature corrected. HPKE fixture was already draft -05 |
| v6 | Verification pass, no design change. Corrected: TFHE-rs 1.8.1 release date, ISO/IEC 28033-3 stage, the RATS draft's name, the `0x80000005`–`0x8000000f` characterization, the LAMPS CSR-attestation status. Recorded: HSM `origin/main` moved past the `ceddd554` baseline; the Hub worktree still carries the v4 wrap ceremony; Lattigo's retry notice is stronger than v5 paraphrased it. Added: §0.1 verification record, §10.1 repository gates, immutable-attribute precedent in §6.2, fixture-reachability rule in §6.5.1. Same day, later: Hub text aligned to v5/v6 by session 0e (`81a2369b`, local); OpenFHE pinned to v1.6.0 |

Owner decisions recorded 2026-10-02:

| # | Question (review §9) | Decision |
|---|---|---|
| D1 | Production-shaped design, or educational emulator API? | **Educational emulator API.** Implemented in `softhsmrustv3` as a software token and browser emulator. Labelled everywhere as not hardware custody. Targets the pinned standards/drafts and source protocols, with conformance claimed only where §6.5 evidence exists; makes no production claims |
| D2 (revised in v5) | Seed backup model | **Non-extractable FHE seed with controlled cloning and backup/restore.** `CKA_SENSITIVE=true`, `CKA_EXTRACTABLE=false`; ordinary wrap APIs refuse it. A separate vendor replication policy authorizes protected transfers (§6.7), never temporary attribute relaxation |
| D3 | OpenFHE / Lattigo threshold: reference-only, or a PKCS#11 path for all? | **Target a PKCS#11 path for secret-side threshold steps, subject to a separate GO/NO-GO decision for N-of-N (fhe.rs BFV vs OpenFHE BFV) and t-of-N (Rust port vs Lattigo BGV, D7) in P0A.** Exact OpenFHE and Lattigo runs remain reference lanes. A failed feasibility or review gate downgrades that lane to reference-only rather than blocking TFHE delivery |
| D4 | TFHE-rs commercial patent-licence notice | **Owner intent: educational, non-commercial use** (Hub WASM, sandbox). Distribution remains blocked until the P-1 licence/patent review confirms that this use and redistribution are permitted. Commercial or appliance (CACP image) use is excluded until separately licensed |
| D5 | KMIP | **Out of scope** for this plan. No KMIP claims |
| D6 | Hardware acceleration | **ARM only** (§8). The FPGA track is parked |
| D7 | Lattigo t-of-N scenario | **Switch to BGV and port Lattigo's protocols to Rust:** Lattigo v6.2.0 `multiparty` + `mpbgv` over `schemes/bgv`, behind PKCS#11 vendor mechanisms in `softhsmrustv3` (§6.4) |
| D8 | Test strategy for the Rust port | **Go is the test oracle.** The real Lattigo, pinned, validates the port (§6.5.1). Go is never linked into the token or the Hub |
| D9 | TFHE recovery | **Client key only.** The seed regenerates the identical client key (`ClientKey::generate_with_seed`); server and public keys are generated fresh and re-signed |
| D10 (revised in v5) | Seed backup ceremony | **Hardware hierarchy and authenticated replication.** Operational and backup HSMs participate in manufacturing → device → function trust; live cloning and offline backup/restore are both required in the first delivered version. The v4 SO-created application-visible wrapping key is removed |
| D11 | Hub labelling | **Per-step engine badge** (in engine today / planned / refused by design / outside the HSM) plus a per-scenario validation target. v4 recorded initial badges in the Hub worktree; v5 hierarchy/cloning descriptions must be updated and verified in P7 |
| D12 (scope clarified) | Hybrid KEM naming | Existing engine inventory may name ML-KEM-768 + X25519 (`0x647a`); this hybrid is **not selected** for the v5 hierarchy or replication protocol. D15 requires pure PQC |
| D13 | PKCS#11 reference | **v3.2 OASIS Standard plus pqctoday vendor extensions only** (header note) |
| D14 | Certificate hierarchy | **Manufacturing root signs each device certificate directly; device keys sign function certificates.** Applies to operational and backup HSMs. Function purposes include authentication, attestation and cloning/recovery protection |
| D15 | Cryptographic profile | **Pure PQC, Category 3: ML-DSA-65 signatures and ML-KEM-768 key establishment.** No classical-only or hybrid fallback. AES-256-GCM is the proposed payload protection. This is not a Category 3 claim for the separate TFHE backend |
| D16 | Attestation model | **Reuse the existing RATS HSM-evidence draft (`draft-ietf-rats-pkix-key-attestation`, "Evidence Encoding for Hardware Security Modules") and the LAMPS CSR-attestation and freshness drafts**, with published PQ certificate profiles (RFC 9881, RFC 9935). Do not invent a replacement evidence format (§6.8). v5 called this draft "RATS HSM evidence" in some places and "RATS PKIX key attestation" in others; both meant this one document |

**Planning assumptions, not additional owner decisions:** first implementation uses isolated Rust-token
instances and a clearly labelled test manufacturing CA; actual hardware/vendor interoperability needs
separate evidence. The manufacturing private root stays in the manufacturing CA; all devices receive
its public trust anchor. Device/function private keys are device-specific. The default role model is
SO-approved enrollment/policy and explicit authorized user operations on both sides; M-of-N operator
approval is not assumed. Offline packages require a surviving authorized backup HSM (§6.7).
P0B must confirm these operational assumptions and the hardware-root integration before implementation;
they do not block writing or reviewing this consolidated plan.

### 0.1 v6 verification record (2026-10-02, evening)

What v6 checked, where, and what changed. Line numbers are at `ceddd554`.

| Claim in v5 | Checked against | Result |
|---|---|---|
| `0x80000015` = `CKM_PQCTODAY_ECDSA_EXPLICIT_K`; HPKE at `0x80000013`/`14`; pure ML-KEM KEM IDs `0x0040`–`0x0042`; hybrids `0x0050`, `0x0051`, `0x647a`; HKDF-SHA384 = `CKD_HPKE_HKDF_SHA384` | `rust/src/constants.rs`, `kmip/pkcs11-mech-manifest.json`, allocation authority (`pqctoday-priv` `0ccd9224`) | Holds |
| SP 800-108 derived keys default `CKA_EXTRACTABLE=TRUE, CKA_SENSITIVE=FALSE` | `rust/src/ffi.rs:12753-12756` | Holds |
| `CKA_DERIVE_TEMPLATE` declared but not enforced | only occurrence is `rust/src/constants.rs:386` | Holds |
| HPKE AEAD key fixed template, no `CKA_WRAP` | `rust/src/native/hpke.rs:810-830` | Holds |
| `C_WrapKeyAuthenticated` refuses `CKA_EXTRACTABLE=FALSE` | `rust/src/ffi.rs:14032-14041` | Holds |
| `pEphemeralSeed` reaches encapsulation with no release guard | `rust/src/ffi.rs:4713-4752`; `rust/src/native/hpke.rs:796,927,947` | Holds |
| Shipped WASM bundle built with `--features acvp` | `rust/build-wasm-bundle.sh:65-70`; `rust/Cargo.toml` `[features]`; `docs/rust-engine.md:126-145` | Holds |
| Vendor attributes (`>= 0x8000_0000`) exempt from mutability rules; engine-private range read-only | `rust/src/state.rs:1326-1332`, `ENGINE_PRIVATE_ATTR_BASE = 0xFFFF_0000` at `:1216` | Holds; precedent added to §6.2 |
| HPKE vectors labelled draft -04 | `rust/src/hpke_pq_vectors_tests.rs:10,122` | **Label was stale, fixture was already -05.** Its source, `hpkewg/hpke-pq@6433c8fc`, is the official `draft-ietf-hpke-pq-05` tag (6 July 2026); corrected in v7 |
| HSM baseline `ceddd554` = `origin/main` | `git fetch` | **Drifted**: `origin/main` is `b8402936` (PRs #312, #314, #313 merged after the review). All line references remain at `ceddd554`; P-1 re-pins (§2) |
| Hub FHE files untracked; badges per D11 | `pqctoday-hub-cc-fhe-section-1002`, branch `feat/cc-fhe-section-1002` | **Resolved later on 2026-10-02.** Session 0e owns that worktree; the owner chose v5/v6 and told 0e to make the edits. 0e committed all 13 files (9 new, 4 modified) **locally** as `81a2369b767da97387f087e9a0fbb701c4771de1` on top of `83f97d3cf`; it is not pushed. Verified at that commit: no step text calls `C_WrapKey*` on the seed, and `fheHsmCosts.test.ts:58` asserts that; the one-time-wrap, SO-ceremony and `0x647a` text is gone; the KMIP absolutes are scoped to estimates; OpenFHE links are pinned to `v1.6.0`. The remaining `X25519MLKEM768` mentions describe TLS key exchange, not the HSM hierarchy. Badge vocabulary (`engine`, `planned`, `refused`, `outside`) is unchanged |
| Sandbox 7 commits behind; no FHE material | `pqctoday-sandbox` at `7d18b794` | Holds; `git ls-files` has no OpenFHE/Lattigo/TFHE entries |
| TFHE-rs 1.8.1 (2026-09-14) | GitHub releases API | **Date wrong**: published 2026-09-17. `Seed(pub u128)`, `ClientKey::generate_with_seed`, unseeded `CompressedServerKey::new(&ClientKey)`, `apps/trivium` and the README patent notice confirmed at tag `tfhe-rs-1.8.1` |
| Lattigo v6.2.0 (2026-02-02, Apache-2.0) | GitHub releases API, `LICENSE`, `SECURITY.md` at `v6.2.0` | Holds; the retry notice is stronger than paraphrased (§4, §6.4) |
| fhe.rs `experimental-mbfv` incomplete | `crates/fhe/src/mbfv/mod.rs` at `main` `44ad194` (2026-09-08) and at tag `v0.1.1` | Holds verbatim on `main`; the warning and feature gate arrived in `bd05e2c0` (2026-08-15), after the last release v0.1.1 (2025-11-23), whose `mbfv` is ungated and unwarned. Pin by commit |
| draft-ietf-hpke-pq-05, 2026-07-06, IDs `0x0040`–`0x0042`; KDF/AEAD unrestricted for pure ML-KEM | Datatracker; draft text | Holds; SHA-3 KDFs are only called "convenient" (§6.7.2) |
| RATS -07 (6 July 2026); LAMPS CSR -29 (2 Sept 2026); freshness -08 (4 July 2026); RFC 9881; RFC 9935 | Datatracker, RFC Editor | Holds. CSR attestation -29 is past IETF Last Call ("Waiting for AD Go-Ahead", 16 Sept 2026) and may publish as an RFC during this plan. RFC 9881 October 2025; RFC 9935 March 2026 |
| ISO/IEC 28033-2 DIS, -3 FDIS, -4 FDIS | ISO catalogue listings (direct fetch returns 403; titles via search) | **-3 corrected to DIS** (listing title "ISO/IEC DIS 28033-3", stage 40.60). -2 DIS (ballot closed 2026-04-25). -4 FDIS (stage 50.20, ballot opened 2026-09-08). None published |
| NIST IR 8214C is a call for submissions | CSRC | Holds: "NIST First Call for Multi-Party Threshold Schemes", final January 2026 |
| `0x80000005`–`0x8000000f` "held for liboqs" | allocation authority log 2026-07-06 | **Overstated**: the log says a future C++/liboqs initiative "must re-allocate continuing from `0x80000005`"; nothing is formally reserved, and the Rust engine already occupies `0x80000010`–`0x80000015`. Treat the gap as not-free until the authority rules (§6.2) |

## 1. Goal

Validate, with running code and measured evidence, the FHE + HSM flows taught in the Hub's
Confidential Computing workshop. Each scenario carries explicit validation and conformance labels
(§1.1); no label is inferred from a successful round trip alone.

| Scenario | Scheme | Target level |
|---|---|---|
| TFHE single-HSM custody | TFHE/CGGI | Token-validated + reference-validated |
| Live cloning and offline restore of TFHE seed | ML-DSA-65 / ML-KEM-768 protecting TFHE seed | Both flows required; preserve client-key identity and policy; report software-emulator or hardware-backed evidence separately |
| Transciphering (TFHE-rs Kreyvium) | TFHE + Kreyvium | Token-validated (HSM steps) + reference-validated (server steps) |
| Threshold, OpenFHE-style N-of-N | BFV multiparty | Reference-validated with OpenFHE; provisional token-validation target through a reviewed Rust BFV protocol (§6.4–§6.5) |
| Threshold, Lattigo t-of-N | BGV: Lattigo `schemes/bgv` + `multiparty` + `mpbgv` | Reference-validated with Lattigo; token-validated through the Rust port (D7), conformance-mapped and, if T2/T3 pass, wire-interoperable with Lattigo (§6.5.1). Independent review required |
| CKKS single-HSM (counter-example) | CKKS | Reference-validated with **OpenFHE**, the library the Hub cites (measured sizes); token path fails fast by design (§6.6) |
| What can run in the HSM? | TFHE / CKKS | Evidence-scoped measurements, with no absolute claims |

### 1.1 Validation levels (fixes B8)

- **Reference-validated.** The exact named library and version runs the scenario end to end outside PKCS#11, with pinned commit, parameters and artifact hashes.
- **Token-validated.** Every secret-side operation of the scenario runs through the vendor PKCS#11 ABI on `softhsmrustv3`, natively and, where §7 allows, in the browser emulator.
- **Conformance-mapped.** A token-validated flow may claim to reproduce a reference protocol only after §6.5 maps its parameters, security assumptions, rounds, messages and results. **Wire-interoperable** is a separate, stronger label used only when native serialized artifacts are exchanged without a translation layer.

The Hub labels each scenario with the level it actually reached.

### 1.2 Custody claims (fixes H8)

The evidence manifest and the Hub distinguish three things:
1. **Browser emulator behaviour.** No tamper resistance; the page can read WASM memory.
2. **Native software-token behaviour.** The host administrator can inspect or roll back token storage; counters and one-shot transcript state prevent accidental reuse in the current state but are not hardware-backed anti-rollback.
3. **Hardware-rooted target architecture.** Manufacturing → device → function trust is designed here; actual hardware key isolation, attestation provenance and certification require separately identified hardware evidence. Software-generated certificates do not establish these properties.

## 2. Inputs frozen in P-1 (fixes B4, review §7 gate 1)

| Input | Pin |
|---|---|
| Requirements contract | `fhe-hsm-scenarios.v1.json`, **the canonical source**, committed in the Hub and referenced here by commit hash. P-1 freezes scenario/step IDs, fixtures, target labels, evidence slots, budget metrics and disclosures; numeric release budgets are frozen in a versioned P0A exit update. Hub TypeScript, HSM tests and sandbox fixtures consume or validate against it; it is not regenerated from mutable UI prose |
| `pqctoday-hsm` | Review baseline `ceddd554…`, to which every line reference in this plan and its reviews refers. `origin/main` had already moved to `b8402936` (PRs #312, #314, #313) by the v6 check; none of those touches the cited code, but P-1 re-pins to the then-current `origin/main`, re-checks every cited line, and re-pins again at P0 exit |
| `pqctoday-sandbox` | `origin/main` commit at P-1 (the local checkout `7d18b794` was 7 commits behind at review time and still is). The repo holds no OpenFHE, Lattigo or TFHE-rs material yet, so every P4 lane starts from nothing |
| `pqctoday-hub` scenario source | Hub `main` at **`624115862da17f1013f72bc54af0b9cbaed00add`** (release 4.144.0, PR #822, 2026-10-02), which contains the reviewed section commit `81a2369b767da97387f087e9a0fbb701c4771de1` and 0e's gated `759a628a`. This is the P-1 pin for the scenario text, now permanent on GitHub. The canonical `fhe-hsm-scenarios.v1.json` contract still has to be extracted from it and committed. Later Hub work on decrypt-step wording (`feat/fhe-flow-clarity-1002`, unreleased) follows §6.3 and is re-pinned when released |
| Libraries | Exact tag + commit + enabled features + toolchain for TFHE-rs (incl. `apps/trivium`), fhe.rs, OpenFHE and Lattigo, plus the Go toolchain and `go.sum` for the oracle. Candidates checked 2026-10-02: TFHE-rs **1.8.1** (tag `tfhe-rs-1.8.1`, published 2026-09-17), Lattigo **v6.2.0** (2026-02-02, Apache-2.0), fhe.rs **by commit** (no tagged release since v0.1.1 of 2025-11-23; `main` was `44ad194` on 2026-09-08), OpenFHE **v1.6.0** (published 2026-09-28, tag commit `6206d24f9eefefc620b524a4f2b9f308feb91e9f`, BSD-2-Clause; `threshold-fhe.cpp` at that tag still runs BGVrns-additive, BFVrns and CKKS, with `RunBFVrns` at line 210 as the reference). The Hub already links this tag. Poulpy is no longer used (v4) |
| Standards | PKCS#11 **v3.2 OS** + vendor extensions (D13). ISO/IEC 28033-2 **DIS** (ballot closed 2026-04-25), -3 **DIS** (stage 40.60; the earlier review said FDIS, the ISO listing says DIS), -4 **FDIS** (stage 50.20, ballot opened 2026-09-08); none published. draft-ietf-hpke-pq **-05** (2026-07-06; ML-KEM-512/768/1024 = `0x0040`/`0x0041`/`0x0042` confirmed; no KDF/AEAD restriction for pure ML-KEM). NIST IR 8214C ("First Call for Multi-Party Threshold Schemes", final January 2026) is a **call for submissions**, not a standard |
| Attestation / PQ certificates | `draft-ietf-rats-pkix-key-attestation` **-07**, LAMPS CSR attestation **-29** (past IETF Last Call, "Waiting for AD Go-Ahead" as of 2026-09-16, so it may become an RFC during this plan), LAMPS freshness **-08**, RFC **9881** (ML-DSA in X.509, October 2025) and RFC **9935** (ML-KEM in X.509, March 2026). Links, status and scope in §6.8. Recheck status/errata at P-1 and preserve exact snapshots |

Exit criterion: an immutable requirements contract exists; every claim has a source/evidence slot; every owner decision in §0 is recorded; and no document describes a future commit or allocation as if it already existed.

## 3. Where the work lives

| Piece | Repo |
|---|---|
| `pqc-fhe` wrapper crate + vendor mechanisms | `pqctoday-hsm/rust` (Rust engine only; C++ engine out of scope, recorded in the ledger) |
| Reference lanes (exact OpenFHE, Lattigo, TFHE-rs), the Lattigo **Go oracle** for the Rust port (§6.5.1), multi-token and mixed Rust/Go threshold runs, CKKS measurements with OpenFHE | `pqctoday-sandbox` (Docker) |
| Scenario contract, measured figures, live TFHE demo | `pqctoday-hub` |

## 4. Library choices and fitness (fixes B5, H3, H10)

| Library | Role | Known limitation (from its own source or docs) | Plan response |
|---|---|---|---|
| TFHE-rs + `tfhe-trivium` | TFHE custody and the separate Kreyvium server/reference lane | README at `tfhe-rs-1.8.1`: free under BSD-3-Clause-Clear "only for development, research, prototyping, and experimentation purposes"; "for any commercial use … companies must purchase Zama's commercial patent license". GitHub's licence detector reports the `LICENSE` file as `NOASSERTION`, so the gate must read the file itself | D4 plus written P-1 distribution approval |
| fhe.rs (`experimental-mbfv`) | Candidate Rust N-of-N BFV backend; its `fhe-math` ring crate is a candidate base for the Lattigo port | `mbfv/mod.rs` at `44ad194`: "This module is incomplete and has not been independently audited. In particular, common-reference-string generation and the noise flooding required by the key-switching protocols are not fully implemented. It must not be used in production or to protect sensitive data." MIT licence. That warning and the `experimental-mbfv` gate were added on 2026-08-15 (`bd05e2c0`) and are **not in any release**: in v0.1.1 (2025-11-23, the only tag the Hub library row cites) `mbfv` is ungated and its module doc carries no warning; only the README says the code is experimental and "never independently audited". Pin by commit, and do not cite v0.1.1 as the source of the incompleteness statement | P0A feasibility first, pinned by commit. A pinned fork may proceed only with an independent cryptographic review and an upstreaming/maintenance decision. Until all gates pass, threshold mechanisms are compiled out |
| OpenFHE | Exact reference and test oracle for the OpenFHE BFV scenario; source of the CKKS counter-example sizes | C++. `threshold-fhe.cpp` on `main` runs BGVrns (additive), BFVrns and CKKS; only the BFV run is the reference (C6) | Sandbox only, pinned by tag |
| Lattigo v6.2.0 (Go) | Exact reference for the Lattigo BGV scenario, the **source** of the Rust port (D7) and its **test oracle** (D8) | `SECURITY.md` at `v6.2.0`, "On the insecurity of retries": a party generating and transmitting its share more than once for the same public polynomial and secret-key share discloses enough for key recovery (Mouchet et al. 2024/194; Okada et al. 2025/409; Colin de Verdière et al. 2026/031). **None of the published countermeasures is implemented**, Colin de Verdière et al. show the 2024/194 countermeasure is insecure for threshold decryption and key switching, and "retrying any MHE protocol must be considered insecure (even when executed by different sets of parties in the t-out-of-N case)" | One-shot transcript rule adopted into §6.4; no countermeasure is ported by analogy. The port is a derivative of Apache-2.0 code: NOTICE and attribution go through the licence gate |
| Poulpy | Dropped in v4 | The Hub cites OpenFHE CKKS, so measuring with Poulpy could not reference-validate it (§1.1) | Not used |

**Licence gate (P-1, blocking).**
- Resolve the repo-licence anomaly: BSD-2-Clause at the root vs `SPDX: GPL-3.0-only` in `src/lib/vendor_mechanisms.h`.
- Treat copyright licence and patent licence as separate questions.
- Record per dependency: exact commit, licence files, notices, and a transitive SBOM.
- Decide distribution for the Hub WASM and sandbox images, consistent with D4.
- Record written approval or rejection for TFHE-rs source/binary redistribution under the intended public Hub deployment. A README interpretation is not the approval artifact.
- Record the Apache-2.0 obligations of the Lattigo port (NOTICE, attribution, change statement) and their compatibility with the repo licence once the anomaly above is resolved.

## 5. The `pqc-fhe` crate and token boundary

`pqc-fhe` owns common parameter IDs, envelopes, deterministic vectors and flow fixtures. The token
links only code that handles token-side custody operations:

- **Initially linked:** one pinned TFHE custody backend.
- **Conditionally linked after P0A/P5 gates:** the reviewed Rust N-of-N BFV backend and, separately,
  the reviewed Rust port of Lattigo's multiparty + `mpbgv` protocols (t-of-N, D7).
- **Never linked into the token:** any CKKS evaluation/bootstrapping (OpenFHE, sandbox only),
  TFHE-rs Trivium/Kreyvium server evaluation, and Go/Lattigo (test oracle only, §6.5.1).

The CKKS counterexample does not instantiate any CKKS library inside the token. The allowlisted registry
contains its measured size metadata, so the vendor request fails before allocation with a documented
unsupported/resource error.

**Additions required by the review (H4, reproducible recovery):**
- **Seed expansion is defined by the P0 ABI/recovery specification, not by the library default.** Per-purpose sub-seeds use SP 800-108 counter mode with a fixed PRF, counter width, output length, label and length-prefixed context containing the scheme, parameter hash, key kind, share index and algorithm-version ID. The backend's seeded CSPRNG consumes the derived sub-seed.
- **The KDF runs inside the FHE vendor mechanisms only (fixes C1).** They call the engine's existing SP 800-108 code internally. The caller-visible `CKM_SP800_108_*` mechanisms are never allowed on the seed: at `ceddd554` they create derived keys with `CKA_EXTRACTABLE=TRUE, CKA_SENSITIVE=FALSE` by default (`rust/src/ffi.rs:12752-12756`) and `CKA_DERIVE_TEMPLATE` is not enforced. Because the label and context are published in the ABI spec, allowing that mechanism would let any user-PIN holder derive and read a sub-seed, and so the FHE secret.
- **Entropy size is justified per backend.** 32 bytes is not assumed universally. TFHE-rs's seeded generation takes `Seed(pub u128)` (tfhe 1.8.1), so the TFHE client key carries the 128 bits the KDF supplies; P0A records that this matches the pinned parameters' 128-bit target.
- **No sub-seed object persists.** Derived sub-seeds and expanded secret material are zeroized after use and never exposed through `C_GetAttributeValue`.
- **Reproducibility is pinned to:** backend commit, features, parameter definition, serialization version, thread mode and deterministic RNG-consumption order.
- **Custody configuration (owner decision 2026-10-02).** `ConfigBuilder::default().use_dedicated_oprf_key(false)`. TFHE-rs 1.8.1's default config also generates a dedicated OPRF key (encrypted pseudo-random generation) and its server key, which the custody flow does not use and which doubles the export. The KDF context binds this configuration, so a changed configuration derives a different seed rather than silently a different key.
- **Measured, not assumed (pqctoday-fhe `reference-runs/tfhe-custody`).** Against the pinned TFHE-rs source: the same 32-byte test seed, through an SP 800-108 counter-mode KDF (HMAC-SHA-384) to `Seed(u128)`, regenerates a byte-identical client key; a different context gives a different key; two server keys from one client key differ; after deleting every key, the regenerated client key decrypts ciphertexts made before the "backup", and add/multiply under a fresh server key decrypt correctly. Parameters: n = 918, N = 2048, k = 1, KS level 4, log2 p_fail = −129.58. **Cross-platform:** with the custody configuration the derived seed and the client key are identical on macOS arm64, Linux arm64, Linux x86-64 and wasm32 in Node: client-key SHA-256 `9f5d847e4d1121eef9d75fcc473e89ee5306523f9cb140384eba5aa85a55b77b`, 24,087 B; pqctoday-fhe `ebda5c3d`, `reference-runs/tfhe-custody/results/matrix/`. That covers TFHE-rs's hardware and software AES-CTR paths. wasm32 needs a JavaScript host: TFHE-rs's wasm32 build imports wasm-bindgen glue, so a WASI runtime cannot load it. **Still open:** whether later TFHE-rs releases keep the same seed-to-key mapping (re-run the spike per tag; the upgrade policy below applies), and the desktop browser matrix (§7).
- **What is reproducible (D9, fixes C3).** Only the **client key**: `ClientKey::generate_with_seed(config, Seed)` regenerates it. TFHE-rs 1.8.1's `CompressedServerKey::new(&ClientKey)` takes no seed and draws fresh randomness, so server and public keys are **not** byte-reproducible through the public API; a byte-identical path would need `core_crypto` internals and is not used. The client key gets a known-answer hash on each supported architecture and on wasm32.
- **Recovery descriptor (FC-6).** Authenticated backups bind the exact KDF PRF/counter/labels/context/lengths, scheme and parameter hash, backend algorithm/version/configuration, serialization version, lineage and policy digest. Key bytes alone are not a complete backup. Unsupported descriptors fail before object installation.
- **Upgrade policy.** Retain a version-dispatched compatible generator or complete a specified data/key migration before removing it. Re-encrypting the same seed cannot repair changed key-generation semantics. Test old-package recovery across each supported upgrade.
- **Recovery run (acceptance test).** Restore the seed from backup → identical client-key hash → decrypt ciphertexts created before the backup → generate a fresh server key and compact public key, re-sign them, and evaluate with them.

## 6. PKCS#11 surface

### 6.1 Existing mechanisms reused (re-inventoried at `ceddd554`; fixes B3)

| Purpose | Mechanism / function | Status at baseline |
|---|---|---|
| Entropy | `C_GenerateRandom` | Present |
| Sub-seed derivation | SP 800-108 KBKDF code behind `CKM_SP800_108_COUNTER_KDF` | Present. Reused **internally** by FHE mechanisms only; the caller-visible mechanism is never on the seed's allowlist (§5, C1) |
| Recipient keys and signatures | `CKM_ML_KEM*` via `C_EncapsulateKey`/`C_DecapsulateKey` (FIPS 203); `CKM_ML_DSA*`, `CKM_HASH_ML_DSA_*` (FIPS 204) | Present. Sign bounded certificates, evidence and authenticated manifests; do not buffer large FHE exports as signature inputs |
| Manifest hashing | `CKM_SHA384` / `CKM_SHA3_384` | Present; proposed v5 security-binding digest is SHA-384, frozen and reviewed in P0B; no board-dependent format |
| HPKE | `CKM_HPKE_KEM_KEY_PAIR_GEN` (`0x80000013`), `CKM_HPKE` (`0x80000014`), **pure ML-KEM KEMs `0x0040`/`0x0041`/`0x0042` already implemented and tested**; hybrids `0x0050`, `0x0051`, `0x647a` (MLKEM768-X25519) | Pinned to draft **-04** vectors. Refresh to -05. The AEAD key is registered with a fixed template (sensitive, non-extractable, `CKA_ENCRYPT`/`CKA_DECRYPT`, **no** `CKA_WRAP`, no `CKA_PRIVATE`) at `rust/src/native/hpke.rs:810-828`; only the exporter key takes a caller template |
| Ordinary authenticated wrapping | `C_WrapKeyAuthenticated` / `C_UnwrapKeyAuthenticated` with `CKM_AES_GCM` | Present; **not the v5 FHE backup API**. Both wrapping APIs must reject the non-extractable seed. Current caller-IV handling does not supply replication state management |
| Protocol-share outputs | `C_DeriveKey` producing a `CKO_DATA` object | Precedent: `CKM_HKDF_DATA` (`rust/src/ffi.rs:12744`) |
| Multi-handle inputs | Extra key handles in the mechanism parameter | Precedent: `CKM_CONCATENATE_BASE_AND_KEY` |
| Roles | Private objects visible to the normal user only, never the SO (`rust/src/state.rs:1021`); `C_Logout` destroys private session objects (`rust/src/ffi.rs:1149`); one login state per token | Present; shapes the backup ceremony (§6.7) |
| Token persistence | One flat snapshot of all `CKA_TOKEN=TRUE` objects (`rust/src/state_snapshot.rs`) | Present; large public material stays off the token (§6.6) |
| Policy | `CKA_ALLOWED_MECHANISMS`, `CKA_WRAP_WITH_TRUSTED`, `CKA_TRUSTED` (SO-only), `CKA_UNWRAP_TEMPLATE` | Enforced |
| Derived-object templates | `CKA_DERIVE_TEMPLATE` | **Stored but not enforced.** Fix in P1 |

### 6.2 New vendor definitions (fixes B1, H1)

**No numbers are assigned in this plan.** Allocation happens in
`pqctoday-priv/docs/platform/data/pkcs11-vendor-mech-allocation.md`, the append-only authority, in
two batches so a NO-GO lane never leaves permanent unused entries (fixes C8):
- **Batch 1 (P0B, after ABI design):** custody definitions plus the approved attestation/replication mechanisms, policy attributes and session-state types. P-1 inventories/reserves design space only; it does not allocate speculative names. The v4 application-visible `SINGLE_USE`/`BOUND_IV` wrapping-key attributes are no longer required by this plan.
- **Batch 2 (start of P5, per GO lane):** `CKK_PQCTODAY_FHE_SHARE`, `CKM_PQCTODAY_FHE_MP_SHARE` and the threshold attributes.
Constraints:
- `0x80000015` is already `CKM_PQCTODAY_ECDSA_EXPLICIT_K`; the Rust engine occupies `0x80000010`–`0x80000015` and the authority's §1.4.2 block (`0x80000100`, `0x80000101`, `0x80001057`–`0x8000105c`).
- `0x80000005`–`0x8000000f` are **not formally reserved**, but the authority's 2026-07-06 log entry says the parked C++/liboqs initiative "must re-allocate continuing from `0x80000005`". Treat the gap as not-free until the authority rules; do not fill it from this plan.
- Mechanism, key-type and return-code namespaces already overlap numerically (`0x80000001` is a `CKM_`, a `CKK_` and a `CKR_`), which is why each namespace is checked independently below.

The registry-completeness gate and generated consumer manifest cover batch 1 at P0 exit; optional
batch 2 is checked at P5 entry, not prematurely required at P0.
Mechanism, key-type, attribute, parameter and return-code namespaces are allocated and checked
independently; equal numeric offsets in different namespaces are not treated as one allocation.

| Name (number TBA) | Kind | Function(s) |
|---|---|---|
| `CKK_PQCTODAY_FHE` | secret key | Seed-backed FHE secret (D2 template, below) |
| `CKK_PQCTODAY_FHE_SHARE` | secret key | One party's threshold share |
| `CKK_PQCTODAY_FHE_PUBLIC` | public key | Derived public material (versioned blob) |
| `CKM_PQCTODAY_FHE_KEY_GEN` | mechanism | `C_GenerateKey` |
| `CKM_PQCTODAY_FHE_DERIVE_PUBLIC` | mechanism | `C_DeriveKey` → bounded `CKO_PUBLIC_KEY` session object; export with `C_GetAttributeValue` |
| `CKM_PQCTODAY_FHE_DECRYPT` | mechanism | `C_Decrypt` under the policy of §6.3 |
| `CKM_PQCTODAY_FHE_ENCRYPT` | mechanism | `C_Encrypt` (test vectors) |
| `CKM_PQCTODAY_FHE_MP_SHARE` | mechanism | Multiparty protocol shares: public key, relinearization, Galois, refresh, key-switch, partial decryption. Bound to a transcript (§6.4) |
| `CKA_PQCTODAY_FHE_SCHEME`, `_PARAM_SET`, `_PARAM_HASH`, `_LIBRARY`, `_LINEAGE_ID`, `_PUBLIC_KIND`, `_DECRYPT_POLICY`, `_THRESHOLD`, `_SHARE_INDEX`, `_TRANSCRIPT_STATE` | attributes | See the P0 ABI spec |

**Replication/attestation ABI gate.** P0B specifies vendor operations for enrollment, evidence,
clone/export-to-peer and authenticated restore, with no assigned numbers here. Candidate mapping:
`C_DeriveKey` produces bounded public `CKO_DATA` protocol/evidence objects from the relevant base
key, or installs a protected seed from a recovery-function key and verified package. Source seed
and authorization handles must be bound and access-checked. Evidence bytes are read with
`C_GetAttributeValue`; host-provided bytes enter only as parsed mechanism parameters. Internal
transport keys never get caller-visible usable handles. A seed-based transfer operation, if selected,
must be explicitly in the immutable seed allowlist. P0B must settle exact function semantics,
object classes, imported/derived history attributes, capabilities and error behavior against v3.2;
the candidate mapping is not a conformance claim. If existing functions cannot express it honestly,
record NO-GO and resolve D13 before implementation, rather than hiding a new API inside ordinary wrap.

**The normative ABI spec** (`docs/proposals/pkcs11-ckm-pqctoday-fhe-proposal.md`) is a **P0
deliverable before production feature code**. Isolated P0A feasibility spikes are allowed. It covers:
- **Encoding:** fixed-width fields for the vendor ABI; standard ASN.1/DER for reused RATS/LAMPS/X.509 objects. No pointer-bearing network messages. Do not re-encode standard evidence into a proprietary format.
- **Parameters:** an allowlisted parameter registry (no caller-supplied cryptographic parameters), and canonical parameter-set IDs with maximum lengths.
- **Bounds and versions:** serialization and parameter-hash semantics; maximum input, output and object sizes, checked *before* allocation.
- **Object rules:** mechanism / key-class / key-type compatibility, and required / forbidden / default / sensitive / SO-only attributes per object class.
- **Behaviour:** `C_GetMechanismInfo` min/max values, query-then-fill behaviour, all error codes, and a guarantee that no object is left behind on failure.
- **Concurrency and transactions:** per-session operation rules, per-object locking, deterministic RNG-stream separation, quota accounting, atomic object/snapshot commit, panic/termination cleanup and zeroization.
- **Multiparty fields:** transcript ID, epoch, round, participant-set digest, common-random-polynomial digest and share type.

**Seed template under D2:**

`CKA_TOKEN=true, CKA_PRIVATE=true, CKA_SENSITIVE=true, CKA_EXTRACTABLE=false,
CKA_DERIVE=true, CKA_DECRYPT=true, CKA_COPYABLE=false, CKA_MODIFIABLE=false,
CKA_ALLOWED_MECHANISMS={CKM_PQCTODAY_FHE_DERIVE_PUBLIC, CKM_PQCTODAY_FHE_DECRYPT},
CKA_DERIVE_TEMPLATE={CKA_CLASS=CKO_PUBLIC_KEY, CKA_KEY_TYPE=CKK_PQCTODAY_FHE_PUBLIC,
CKA_TOKEN=false, CKA_PRIVATE=false}`.

This is the custody-only template. The replication-enabled variant is frozen in P0B with its
additional vendor allowlist entries and class-correct output constraints; it must not blindly use
the public-key derive template for a `CKO_DATA` transfer output. If one global derive template
cannot constrain all approved outputs, omit it on that variant and enforce each output class and
attribute set inside the corresponding vendor mechanism. F3 still enforces every supplied standard
template; no silent exception is permitted. Neither template forces secret-key sensitivity attributes
onto a public object (FC-3). History attributes are engine-computed, never caller assertions.

`CKA_PQCTODAY_FHE_LINEAGE_ID` is an immutable random identifier generated with the original seed.
It is the stable recovery identity. `CKA_UNIQUE_ID` remains token-generated and identifies only the
particular object instance; a restored DR object receives a new `CKA_UNIQUE_ID` and must never be
expected to reproduce the source token's value.

The vendor key type is never a base key for the caller-visible SP 800-108 mechanisms; the FHE
mechanisms call the KDF internally (§5). This removes v3's requirement to extend the SP 800-108
base-key rule to `CKK_PQCTODAY_FHE`.

The seed has **no application wrapping/export path**. Controlled replication is a separately
documented vendor capability for encrypted transfer to an authorized token; it does not mean that
the seed can never have a protected copy. Its sensitivity/extractability/permissions and lineage,
parameter, policy and transcript attributes are immutable to callers, including copy/import paths.
The generic vendor-attribute mutation allowance at the baseline must not apply to these attributes:
`attr_mutation_allowed` (`rust/src/state.rs:1326-1332`) returns `Ok` for every attribute at or above
`0x8000_0000` and refuses writes only at or above `ENGINE_PRIVATE_ATTR_BASE` (`0xFFFF_0000`,
`rust/src/state.rs:1216`), the range the engine already uses for XMSS/HSS state so that a client
cannot rewind it. P0B chooses one of two implementable rules and records it in the ABI spec:
(a) allocate the FHE attributes in the public vendor range and add an explicit immutable set to
`attr_mutation_allowed`, or (b) keep engine-computed values (lineage, policy digest, transcript
state, origin history) in the engine-private range and expose read-only copies. Before choosing
(b), confirm whether that range is stripped from client-visible templates, as
`tests/differential/exceptions.json` says it is for XMSS state; a recovery identity the caller
cannot read is useless.

Required tests:
- **Positive:** authorized live cloning and offline restore preserve key identity and restrictions; public-material derivation/export still works with F3 enabled.
- **Negative:**
  - ordinary or authenticated wrapping, even with trusted keys, and direct `CKA_VALUE` reads;
  - `C_DeriveKey(CKM_SP800_108_COUNTER_KDF)` with the seed as base key (mechanism not allowed);
  - changing sensitivity, extractability, allowlists, policy, lineage, input/output class or cloning authorization; copying into a weaker object; using internal transport material through an application crypto API;
  - caller-controlled KEM randomness, nonce reuse, stale evidence, key substitution and unauthorized peer/domain requests;
  - the SO cannot find or use the seed.

### 6.3 Decryption policy and typed ciphertexts (fixes H7, scoped to D1; owner requirement 2026-10-02)

Owner requirement, relayed by session 0e: "the hsm fhe decrypt somehow also need to manage the
concept of policy and typed encrypted block". `CKM_PQCTODAY_FHE_DECRYPT` therefore enforces five
rules, in this order, inside the token. Rules 1–3 limit **what** is released; rules 4–5 limit **to
whom**. None of them can establish **which computation** produced a submitted ciphertext.

**Policy provisioning (unchanged from v5).** The SO provisions a public, non-secret, immutable
policy object before user key creation. The user selects only an enrolled policy ID; the engine
validates authorization and stamps its digest/rules into the private seed. The SO never needs to
access that private seed. Updates create a new policy version through an explicit ceremony. Restore
compares the authenticated source policy to an already authorized destination policy, preserving or
tightening restrictions; a weaker, missing or unrecognized policy fails. No user-supplied template
can rewrite it (FC-4).

**Rule 1 — Pre-decrypt type gate.**
- The policy lists the **allowed output types**, each as an exact TFHE-rs high-level type and width (for example `FheBool`, `FheUint8`), the parameter-set ID and serialization version, and whether a compressed ciphertext list is accepted.
- The mechanism parses the submitted bytes with TFHE-rs's versioned, size-limited, **conformance-checked** deserialization (`tfhe::safe_serialization::safe_deserialize_conformant`). It is called with the conformance parameters of each allowed type in turn. Those parameters fix the block count, message and carry moduli, LWE dimension and atomic pattern, and the size limit is checked before allocation.
- Anything that does not conform to an allowed type is refused before decryption, with one uniform error.
- What the header can and cannot tell. TFHE-rs's serialization header carries the version and a type name, but every unsigned width is named `high_level_api::FheUint`. The width, block count, tag and degree are ordinary, unauthenticated bytes chosen by the submitter. The gate therefore enforces the **shape and maximum width** of what is released. It does not identify where the ciphertext came from.

**Rule 2 — Input types are never releasable, within the limit of rule 1.**
- The policy can mark the types the data owner encrypts inputs with (for example `FheUint64`) as never releasable. A raw input submitted whole as a "result" then fails rule 1.
- **Limitation, stated on screen.** This does not stop a submitter from **reslicing** an input. Taking 4 of the 32 blocks of an `FheUint64` input and presenting them as an `FheUint8` passes the gate and releases 8 bits of that input. Rule 2 bounds the bits released per call; the rate limit bounds the total.
- **What would establish provenance.** Only a verifiable-computation proof over the FHE evaluation could show which computation produced a ciphertext. That is research work and out of scope. Key separation does not help: a key-switching key from the input key to the output key would let the server switch raw inputs too.

**Rule 3 — Post-decrypt plaintext predicate.**
- The policy can attach range, shape or aggregate rules (for example "value ≤ 2¹⁶", "result is a count ≥ k"). They are evaluated inside the token after decryption and before release.
- A failure releases nothing. Every refusal uses one error code and the same response path, so the token does not say which rule failed.
- **Limitation, stated on screen.** Release-or-refuse is itself one bit of information about the plaintext. An adaptive requester can homomorphically compute f(input) and learn predicate(f(input)) one bit per call. Every call, released or refused, therefore counts against the rate limit, and the audit record logs refusals. The predicate limits what a single release discloses; the rate limit bounds the total.

**Rule 4 — Requester binding.**
- Only the data owner's authenticated PKCS#11 user session on the token holding the seed may call `CKM_PQCTODAY_FHE_DECRYPT`: the seed is `CKA_PRIVATE`, and the mechanism is in its allowlist only. The SO cannot call it.
- The third-party cloud never has a session. The flow is: cloud returns the encrypted result to the owner, and the owner asks its HSM to decrypt.
- **Limitation.** The token authenticates a role, not a person or an application. A compromised owner application, or an insider holding the user PIN, is still bounded by rules 1–3 and the rate limit, which is the reason those rules exist.

**Rule 5 — Recipient rule.**
- The policy names who may receive the plaintext. The default is **owner only**: plaintext is returned to the authenticated owner session.
- **Owner plus named third party** is an option. For a third-party recipient, the token seals the plaintext result to that recipient's enrolled ML-KEM-768 recipient certificate, using the in-token HPKE path and certificate profile from the HSM plan (RFC 9935, D15). The owner session only relays the sealed result.
- A recipient must be enrolled by the SO in the policy. The caller cannot name an arbitrary recipient public key. The policy can also be recipient-only, so that the owner session never sees that plaintext.

**Scheme-specific leakage control (unchanged from v5).**
- **Noise flooding** applies only where the selected protocol requires and defines it, not as a generic FHE knob. Multiparty BFV/BGV share generation follows the reviewed protocol's flooding rule: OpenFHE's for N-of-N, and the `noiseFlooding` distribution passed to Lattigo's protocol constructors for t-of-N.
- **TFHE (fixes C10, FC-7).** There is no generic noise-flooding knob. Pin an analytically justified failure probability ≤ 2⁻¹²⁸ and the applicable upstream assumptions. The default parameters measure log2 p_fail = −129.58 (pqctoday-fhe `reference-runs/tfhe-custody`). Finite runs do not prove that probability, and it does not establish CCA security for arbitrary submitted ciphertexts.

**Rate limiting, audit, and the threat model.**
- **Rate limit.** A per-object counter is persisted in token state, with atomic update and its scope stated. It counts every decrypt call, whether released or refused. It detects reuse within the current state but cannot resist rollback by the browser user or native host administrator, and the Hub discloses this.
- **Audit.** Each call records the policy ID, the type matched or "refused", the recipient, and the counter value. It never records the plaintext or the failing rule.
- **Threat model.** It names adaptive decryption-oracle attacks (IND-CPA^D, rule 3's one-bit leak, reslicing under rule 2), and states what an educational emulator does and does not resist.

**Tests (added to P1/P2):**
- **Type gate:**
  - each allowed type releases;
  - a disallowed width is refused before decryption;
  - an oversized input is refused before allocation;
  - a wrong parameter set is refused;
  - a malformed or truncated input is refused.
- **Input types:** a raw `FheUint64` input is refused; a resliced 4-block slice is **released**, as the documented limitation.
- **Predicate:** a failure releases nothing, and every failure looks identical to the caller; refusals consume the rate limit.
- **Requester:** SO, public session or another token's user is refused.
- **Recipient:** the default is owner only; third-party sealing opens only with the enrolled recipient key; an unenrolled recipient is refused; a recipient-only policy never returns plaintext to the owner session.

### 6.4 Threshold protocol feasibility and specification (fixes B5, H2; required by D3)

P0A first produces a separate feasibility result for (a) N-of-N BFV and (b) t-of-N. A lane proceeds
only if the selected backend implements the same scheme and security model as the reference lane,
all missing protocol steps are identified, and there is an owned maintenance path. A failure makes
that Hub lane reference-only; it does not block TFHE work. No threshold mechanism is compiled in
until the resulting protocol specification and implementation receive independent cryptographic
review.

- **Security model:** honest-but-curious parties, as in the source protocols. The malicious-participant and malicious-coordinator cases are documented as out of scope, which matches the educational scope.
- **One-shot transcripts.**
  - Each share is bound to (transcript ID, epoch, round, participant-set digest, common-random-polynomial digest, share type).
  - Token state commits consumption before releasing a share. The consumption key includes stable secret lineage and the protocol's actual relevant public inputs, not merely a transcript ID or temporary handle.
  - P0B defines the rule per protocol/round, including canonical ring encodings, input ciphertext/key bindings and active-set transformations. A second randomized share for a prohibited input combination is refused even with a changed epoch, participant set or derived-share handle. Legitimate required rounds must remain possible.
  - This prevents accidental retry in the current token state. It does **not** claim host-resistant anti-rollback in a browser or native software token; a restored snapshot can restore consumed state. Threshold live runs therefore assume an honest host and show this limitation.
  - Why the rule is absolute: Lattigo v6.2.0's `SECURITY.md` states that retrying any MHE protocol "must be considered insecure (even when executed by different sets of parties in the t-out-of-N case)", that none of the published countermeasures (Mouchet et al. ePrint 2024/194; Colin de Verdière et al. ePrint 2026/031) is implemented upstream, and that 2026/031 shows the 2024/194 countermeasure is insecure for threshold decryption and key switching. Okada et al. (ePrint 2025/409) extract secret-share bits by adaptively changing the active set and repeating. The port therefore adds **no** retry countermeasure of its own; a consumed state is final until the reviewed protocol says otherwise.
- **Abort semantics (FC-5):** timeout, crash or party-set change aborts the transaction. The reviewed protocol decides whether recovery needs new ciphertext/key setup or may retransmit an identical cached share. A fresh epoch, unrelated CRP or different active subset does not make retry safe: Lattigo key switching uses the input ciphertext's polynomial, and the t-of-N attack above works precisely by varying the party set. Review and test these exact rules before enabling the lane.
- **fhe.rs fork gaps to close:**
  - Common random polynomial generated from a transcript-bound XOF seed.
  - Key-switch and partial-decryption noise flooding with the parameter rule given in the source papers and OpenFHE's implementation.
  - Validation of malformed shares and ciphertexts.
  - Known-answer and negative tests for each.
- **N-of-N:** the Rust BFV fork is compared only with the pinned OpenFHE BFV configuration. It does not inherit OpenFHE BGV or CKKS claims.
- **t-of-N (D7): a Rust port of Lattigo v6.2.0, BGV.**
  - Ported: `multiparty` (`Thresholdizer`, `Combiner`, `PublicKeyGenProtocol`, `RelinearizationKeyGenProtocol`, `GaloisKeyGenProtocol`, `KeySwitchProtocol`, `PublicKeySwitchProtocol`) and `mpbgv.RefreshProtocol`, over Lattigo's `schemes/bgv` parameters (one implementation of BGV and BFV; the scale-invariant flag changes evaluation only, not keys or protocol shares).
  - Lattigo's key-generation, key-switching and threshold protocols are scheme-generic RLWE code; only refresh and encoding are BGV-specific. Shamir re-sharing is ported from Lattigo's `Thresholdizer`, never added to fhe.rs by analogy.
  - Ring layer: P0A evaluates fhe.rs's `fhe-math` against Lattigo's moduli, NTT, PRNG and samplers. Where they differ, the port follows Lattigo's ring package so §6.5.1 T1/T2 can pass.
  - The port is new cryptographic code. It needs the independent review below and the Go-oracle evidence of §6.5.1 before anything is compiled into the token.

**Party-side steps of the Lattigo BGV scenario through PKCS#11 v3.2 (vendor mechanisms only, no new
functions):**

| Lattigo step (one party) | PKCS#11 v3.2 call | Mechanism |
|---|---|---|
| Generate the party secret | `C_GenerateKey` | vendor `FHE_KEY_GEN` → `CKK_PQCTODAY_FHE_SHARE` |
| `Thresholdizer`: deal a Shamir share to each peer | `C_DeriveKey` returns a recipient-bound encrypted protocol message; ML-KEM/AES processing stays internal | vendor `MP_SHARE` (deal); authenticated transport profile reviewed in P5, not the TFHE seed-cloning operation |
| Receive and combine dealt shares | `C_DeriveKey` validates/decrypts each protocol message internally and combines protected share handles | vendor `MP_SHARE` (receive/aggregate); fail before exposing secret shares |
| Public-key, relinearization and Galois key shares | `C_DeriveKey` → `CKO_DATA` share | vendor `MP_SHARE` |
| Relinearization round 1 → round 2 | Round 1 keeps its ephemeral secret as a non-extractable session object; round 2 consumes and destroys it | vendor `MP_SHARE` |
| `Combiner`: t-of-N share → additive share for the active set | `C_DeriveKey` → non-extractable session key bound to the participant-set digest | vendor `MP_SHARE` |
| `mpbgv` refresh share; public-key-switch share to the data owner | `C_DeriveKey` → `CKO_DATA`, noise flooding per the protocol | vendor `MP_SHARE` |
| Sign each outgoing share | `C_Sign` ML-DSA-65 | standard |

Aggregation and finalisation run on the cloud side, outside any HSM. Every `MP_SHARE` call carries the
transcript fields above.
- **Review:** changed cryptographic protocol code requires named independent review, published review scope/findings, and a decision whether to upstream or maintain the fork. Passing unit tests alone is not the gate.

### 6.5 Conformance and interoperability tests (fixes H3)

Before a token-validated threshold flow may claim conformance with an OpenFHE or Lattigo scenario,
four checks must pass:
1. **Scheme and parameter mapping:** same scheme variant and security target; explicit mapping of ring degree, moduli, secret/error distributions, encodings and correctness bounds. “Both are RLWE” is insufficient.
2. **Protocol mapping:** the same security assumptions and a one-to-one account of rounds, public inputs and messages per party. Any extra or missing round prevents an “exact” label.
3. **Result and invariant tests:** shared plaintext/circuit fixtures, expected result, failure bounds, transcript bindings and negative cases.
4. **Wire interoperability, only if claimed:** native serialized keys, shares and ciphertexts exchange without translation. A translation layer is tested as a separate adapter and does not earn a wire-interoperable label.

Anything that fails a check is named honestly, e.g. "Rust experimental N-of-N BFV". No
equivalence claim crosses BFV, BGV and CKKS scheme boundaries: the N-of-N lane maps fhe.rs BFV to
OpenFHE BFV, and the t-of-N lane maps the Rust port to Lattigo BGV.

#### 6.5.1 Go oracle for the Rust port (D8)

The real Lattigo, in Go, is the test oracle. It runs only in `pqctoday-sandbox` (Docker, pinned Go
toolchain, Lattigo v6.2.0 with `go.sum`). It is never linked into the token or shipped to the Hub.

| Tier | Test | Pass condition |
|---|---|---|
| T1 | **Byte-exact fixtures.** A Go generator drives Lattigo with fixed `sampling.KeyedPRNG` keys and emits versioned, hash-pinned fixtures: parameters, CRP seeds, secret shares, every protocol share, aggregated keys, ciphertexts and outputs | The port reproduces every deterministic value byte for byte. P0A confirms that Lattigo's PRNG and samplers can be reproduced exactly; any value that cannot is moved to T4 and named |
| T2 | **Wire round trip.** Rust parses Lattigo `MarshalBinary` output and re-serializes it identically, and the reverse, including the ring-domain metadata Lattigo stores (NTT and Montgomery flags) | Identical bytes both ways |
| T3 | **Mixed-party sessions.** 2-of-3 runs with one party as the Rust token (through PKCS#11) and the rest as Lattigo processes, rotating which party is Rust, and with the aggregator in either language | The data owner decrypts the expected result. T2 + T3 earn the "wire-interoperable" label (§1.1) |
| T4 | **Statistical checks** for randomized outputs (error sampling, noise flooding) | Predefined distribution/correctness checks with sample count and confidence bounds; separate cited analytical security/failure bounds. Zero failures in N independent trials gives an approximate 95% upper bound of 3/N, not proof of a 2⁻¹²⁸ bound |
| T5 | **Negative cases generated in Go:** replay, wrong CRP/party set, malformed share, stale round message against current state, prohibited retry with renamed transcript/epoch/share handle | The token rejects each. Whole-token snapshot rollback is a separate demonstrated limitation under §1.2, not a promised rejection |
| T6 | **Lattigo's own test suite** at the pinned version, in the oracle container | Passes, so a Lattigo regression is never mistaken for a port bug |

HSM-repo CI consumes the checked-in, hash-pinned fixtures, so it needs no Go toolchain. Mixed-party
runs (T3) and fixture regeneration are sandbox jobs. The N-of-N lane uses OpenFHE (C++) as its oracle
the same way, for T1, T3 (without wire interoperability), T4 and T5.

Checked-in fixtures are subject to the repo's reachability gate (`scripts/check_vector_reachability.py`,
ruled 2026-09-26: fail, no allowlist): every vector-like file under one of its `VECTOR_ROOTS`
(`rust/kat/` is the natural home) must be named by a code line, not a comment, in a tracked source
file, or the local gate fails. Fixtures that are large (T1 can be tens of MB per protocol) need a
size decision at P4: commit, Git LFS, or regenerate in the sandbox and commit only hashes plus a
small subset. The plan does not pre-decide this; it records that an unreferenced fixture directory
is a gate failure, not coverage.

### 6.6 Resource safety and cancellation (fixes B7, H5)

- **Size checks before allocation.** Every derive or export computes its output size first and refuses before allocating if the size exceeds the per-object cap or the session quota. The CKKS bootstrapping set therefore fails fast with a documented error and never allocates GB.
- **Large public material stays off the token (fixes C7).** The token snapshot is one flat dump of every token object (`rust/src/state_snapshot.rs`), so a persisted 30 MB server key would make every snapshot, including each decrypt-counter update, at least 30 MB. `CKM_PQCTODAY_FHE_DERIVE_PUBLIC` returns public session objects for attribute export (§6.2); no alternative out-of-band byte-output ABI is assumed. Recovery re-generates them anyway (D9).
- **No cancellation claim.** `C_SessionCancel` does not cover key generation in this engine.
  - Native library calls remain synchronous and have no in-call timeout. Test/sandbox callers may isolate them in a child process and enforce an external deadline by terminating that process.
  - Browser calls run in a **disposable worker** that can be terminated.
  - Key generation publishes no partial object. Stateful operations (replication, threshold rounds and policy counters) must durably reserve/consume state before releasing protected output where their protocol requires it. Termination reopens the last complete snapshot: no partial object or corrupt snapshot survives, but a committed consumption record may survive without a delivered result. Recovery must not roll that record back to permit reuse (§6.7).
  - Terminating the browser worker ends that emulator instance and its sessions; it is not presented as cancellation of one PKCS#11 call.
  - A vendor asynchronous/chunked interface is not proposed.
- **Export size, measured.** The custody server key serializes to 28.8 MB (30,147,061 B) with `use_dedicated_oprf_key(false)`, and 57.4 MB with TFHE-rs's default config (pqctoday-fhe spike, M4 Pro, 2026-10-02). The compact public key is 33 KB and one `FheUint64` ciphertext 516 KB.
- **P0A spike measures the ~29 MB export:** peak memory across the query-then-fill pattern, the number of copies across the WASM/JS boundary, browser memory growth and recovery, concurrency, and the behaviour on low memory, timeout and termination.

### 6.7 Controlled cloning and offline backup/restore (D2, D10, FC-1–FC-6)

> **Moved.** The normative design is now §3–§5 of `implementation-plan-hsm-key-hierarchy-replication-attestation-2026-10-02.md`, generalized to any
> replicable key. The text below is kept as the FHE-specific statement of requirements. FHE
> contributes the seed key class and its recovery descriptor, carried as the HSM plan's type-specific
> package extension.

Both flows are required for the first TFHE delivery. They transfer the seed and complete recovery
descriptor, not device identities or large public evaluation keys. Standard wrapping always refuses
the seed. Only the enrolled vendor replication capability can produce a protected recipient-bound
package. Host code relays ciphertext, certificates and evidence; seed and transport secrets stay
inside the participating tokens' implementation boundaries. §1.2 still applies to software tokens.

#### 6.7.1 Trust hierarchy, roles and function isolation

```text
Manufacturing CA — ML-DSA-65
  └─ Device issuer certificate — ML-DSA-65, signed directly by manufacturing root
       ├─ Authentication signing certificate — ML-DSA-65
       ├─ Attestation signing certificate — ML-DSA-65
       ├─ Replication/package signing certificate — ML-DSA-65
       └─ Cloning/recovery recipient certificate — ML-KEM-768
          All function certificates are signed by that device's ML-DSA-65 key.
```

- This hierarchy covers operational and backup HSMs. Manufacturing/device certificates have issuer-appropriate constraints; function certificates are purpose-constrained leaves. The CA/root private key is not a fleet-shared device secret under the planning assumption in §0.
- The manufacturing ceremony enrolls device issuer keys. Device provisioning issues function certificates through a controlled internal issuer service, not arbitrary application `C_Sign` access to issuer keys. Bootstrap the attestation credential from that provisioning authority; do not use a credential to establish its own trust.
- Device authenticity is separate from tenant/cloning-domain authorization. SO enrollment installs trusted manufacturing anchors, allowed peers/functions, domain membership, policy profiles and revocation/rotation rules. Source and destination users authorize the permitted operation under that pre-established policy. No SO session needs to access the user's private FHE seed.
- Authentication/package-signing and attestation keys are separate. The attestation service signs measured engine-generated evidence only (§6.8). Internal recipient/transport keys cannot be copied, read, or used as general decrypt/derive or signing oracles. Restriction enforcement covers native, FFI, copy, import and attribute-mutation entry points.
- The source retains its key after a successful clone. A move/delete operation is outside this plan. Threshold shares, stateful signing keys and device issuer keys are excluded from this FHE-seed replication feature; duplicating them would require a separate state-consistency design. Ordinary TFHE clones also do not create a globally shared quota counter.

#### 6.7.2 Cryptographic and recovery profile

P0B freezes the replication protocol and package format, reusing the existing HPKE implementation
internally: RFC 9180 base mode plus pinned HPKE-PQ -05, ML-KEM-768 (`0x0041`), HKDF-SHA384,
AES-256-GCM. ML-DSA-65 authenticates the appropriate protocol/package statements. Base-mode HPKE
alone does not authenticate the sender. This composition needs protocol review and exact vectors;
it is not an existing standardized interoperable HSM-cloning protocol. HKDF-SHA384 and SHA-384
descriptor/transcript digests are engineering selections subject to the P0B full-suite security
review; native HPKE already lists HKDF-SHA384 (`CKD_HPKE_HKDF_SHA384`, `0x0002`) and, since PR #310,
the SHAKE256 one-stage KDF (`CKD_HPKE_SHAKE256`, `0x0011`). draft-ietf-hpke-pq-05 places no KDF or
AEAD restriction on the pure ML-KEM KEMs; it only calls an all-SHA-3 suite "convenient". P0B picks
one and records why. Do not infer the security of the entire composition solely from the names
ML-DSA-65 and ML-KEM-768.

- Bind protocol/version, operation (clone/backup/restore), both device and function identities, domain, authorization, peer challenges, recipient KEM key, lineage, source unique ID, the complete §5 recovery descriptor, policy digest and suite into a canonical authenticated transcript/package. Bind encapsulation and ciphertext into the signed package; distinguish pre-encryption AAD from the final signed object to avoid circular encodings. Specify exact bytes and parser limits in P0B.
- Use fresh engine-generated KEM randomness. Shipped native/WASM paths reject deterministic overrides, including HPKE `pEphemeralSeed`, independently of the ACVP `pReserved` guard (FC-2). Test-only known-answer paths are separate and labelled.
- Transport secrets remain internal; no application-visible trusted AES wrapping key is created. Fix sequence/nonce use in the internal session state. Sizing and small-buffer calls perform no cryptographic operation or consumption. Once a session is consumed it cannot be reused; if output delivery fails, recover only the identical cached result or start a newly authorized session. Bound concurrent calls and perform state changes atomically.
- Preserve stable FHE lineage but assign a new destination object `CKA_UNIQUE_ID`. Destination policy is equal or stricter and immutable. Origin and historical attributes are assigned by the engine according to the chosen vendor operation and v3.2 semantics; never accept caller-asserted local generation or sensitivity history.
- Current-state replay/duplicate-install prevention and persistent receipts are required. Snapshot rollback remains a disclosed software-token limitation. Durable consumption precedes externally visible output/acknowledgment; interrupted operations cannot silently install weaker or partial objects.

#### 6.7.3 Live cloning

1. Source and destination load enrolled policies and independently authenticate the peer, certificate purpose, fresh evidence and domain authorization. Bind evidence to the actual recipient key and transaction challenges, not merely a genuine device certificate.
2. The authorized source operation seals the seed/descriptor to the authenticated destination recipient key. It returns only the bounded encrypted package and signed provenance.
3. Destination checks the complete package, authorization and policy before internal decapsulation/decryption. It stages, validates and atomically installs the restricted seed; failure leaves no usable partial key.
4. Destination returns an authenticated receipt bound to the package and newly installed object. Lost acknowledgments are reconciled by transaction ID; they do not create duplicate keys or silently authorize a fresh transfer.

#### 6.7.4 Offline backup and restore

The proposed first-version recovery authority is an enrolled **backup HSM with a surviving recovery
private key**. The source creates a package for that backup HSM while its recipient credentials and
authorization are validated. The encrypted file can then be stored offline. A future replacement
HSM's newly issued certificate cannot by itself decrypt that file.

1. Create the backup package with the same immutable custody/descriptor checks as cloning, but a distinct operation/domain separator. Record backup-recipient key ID, source provenance, sequence and relevant validation records. The source can be removed after backup for the disaster-recovery test.
2. At restore, the surviving backup HSM verifies package provenance and applies the frozen archival-validation policy: distinguish ordinary certificate expiry from compromise/revocation, with defined time evidence and fail-closed behavior when required information is unavailable. Old source evidence describes backup-time state, not current destination health.
3. Recover internally into the authorized backup token, preserving the seed restrictions, or run its protected recovery-to-clone flow to a freshly authenticated authorized replacement. No plaintext package or recovery key crosses the host API.
4. Confirm the identical client key and decrypt pre-backup ciphertexts, then generate and sign fresh public/server keys. Test after destroying the source **test instance**, not real user data.

For redundancy, produce independent packages for separately enrolled backup HSMs; recovery-key
rotation/replacement requires a tested continuity ceremony before retiring old material. If all
authorized recovery private keys are lost, manufacturing certificates alone cannot recover the
backup. The exact backup-device topology and administrative quorum are P0B operational decisions;
no fleet-wide recovery secret or threshold recovery scheme is silently introduced.

#### 6.7.5 Required acceptance cases

Test both positive flows; source loss; backup-key rotation; restore to a new authorized device;
wrong recipient/domain; false firmware/custody claims; expired/revoked credentials under the defined
policy; stale evidence; key substitution; tampered descriptor/package; weakened policy; deterministic
randomness; nonce/session reuse; duplicate receipts; concurrent calls; crash before/after durable
commit; copy/mutation bypass; unsupported generator version; and ordinary wrap refusal. Failures
must not expose secrets or install partial objects. Test recovery from the package and surviving
backup authority alone, with no source database dependency.

### 6.8 Reused attestation model and PQ certificate profiles (D14–D16)

> **Moved.** Normative design is now §4 and §6 of `implementation-plan-hsm-key-hierarchy-replication-attestation-2026-10-02.md`. FHE-specific work here is
> only the lineage/descriptor binding of an FHE seed in the evidence.

| Purpose | Pinned reference, checked 2026-10-02 | Status |
|---|---|---|
| HSM evidence/request model | [draft-ietf-rats-pkix-key-attestation-07](https://datatracker.ietf.org/doc/html/draft-ietf-rats-pkix-key-attestation-07), "Evidence Encoding for Hardware Security Modules", 6 July 2026 | Active RATS WG draft; includes HSM migration/clustering use cases. This is the single document D16 and §2 mean by "RATS HSM evidence" |
| Evidence in enrollment | [LAMPS CSR attestation -29](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-csr-attestation-29), 2 September 2026 | Past IETF Last Call, "Waiting for AD Go-Ahead" (16 September 2026). Expect an RFC number during this plan; pin -29 and diff on publication |
| Enrollment freshness | [LAMPS attestation freshness -08](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-attestation-freshness-08), 4 July 2026 | Active draft; CMP/EST/CMC bindings |
| ML-DSA certificates | [RFC 9881](https://www.rfc-editor.org/rfc/rfc9881.html), October 2025 | Published Proposed Standard |
| ML-KEM recipient certificates | [RFC 9935](https://www.rfc-editor.org/rfc/rfc9935.html), March 2026 | Published Proposed Standard; `keyEncipherment` usage; not a signature algorithm |

Reuse the RATS ASN.1/DER evidence and claims; use LAMPS `AttestationBundle` when enrolling
certificates. Evidence remains separate from the function certificate. The attestation drafts are
algorithm-independent and do not supply an explicit complete PQC profile: D15 plus RFC 9881/9935
select the algorithms. Do not copy their classical examples into the selected PQ chain.

**Our profile and tests:**
- Require the attestation function's purpose-constrained certificate (`digitalSignature` and the draft's attestation EKU) and ML-DSA-65 evidence signatures chained through device to manufacturing root. Do not treat draft OID placeholders as final numbers; freeze an interoperable draft/test OID strategy before P1.
- Populate platform/key/transaction claims from measured state, not caller assertions. Bind the requested key, signer, nonce and transaction; accept only the authorized pure-PQC chain and suite. Fresh nonce evidence does not imply every historical platform measurement was newly collected.
- Represent FHE seeds by existing key identifiers and applicable claims. If a required FHE artifact/lineage binding lacks a standard claim, document the gap and profile the existing extension mechanism rather than inventing a replacement format or exposing secret material.
- Attest restored/cloned provenance honestly; do not claim the destination generated the original key or that only one copy exists. Standard PKCS#11 history claims retain their meanings.
- Certificate issuance uses the relevant LAMPS transport/freshness bindings where selected. Live cloning uses evidence under its own reviewed transaction protocol; these drafts do not standardize that transport or grant cloning authorization.
- Reject unsupported/unsigned evidence, stale nonces, misbound keys, invalid chains, wrong function purpose and algorithm downgrade. Keep sensitive raw evidence out of public certificates unless a separately reviewed disclosure policy requires it.
- Freeze source versions, mappings and fixture hashes in P0B; recheck live Datatracker/RFC Editor status and errata at P-1/release. Software fixtures use a test manufacturing hierarchy and cannot assert real hardware provenance or validation status.

## 7. Browser emulator (fixes B6, H8, H9)

- **Test-hook isolation (P1 exit blocker).** Split `wasm-playground` and `wasm-acvp` profiles and their native equivalents. The feature manifest and tests prove that shipped artifacts reject deterministic `pReserved` and HPKE `pEphemeralSeed` overrides. The Hub verifies the consumed artifact hash.
- **FHE bundle.** A separate lazy FHE bundle with a pinned TFHE-rs feature set and an integrity hash.
- **Threading.** Single-threaded and cross-origin-isolated threaded modes are both measured, including their COOP/COEP, CSP and worker implications.
- **Candidate platform matrix.** Desktop Chrome, Firefox and Safari are tested in P0A/P3. A browser becomes **supported** only after it meets the frozen memory, startup, operation and recovery budgets; failures receive an evidence-only view. **Mobile is explicitly unsupported for live runs** and always shows the measured evidence view.
- **Budgets.** P-1 defines acceptable user-experience ceilings and measurement methods. P0A measures bundle size, startup, memory, operations and worker recovery, then freezes release thresholds before P2/P3 testing. Do not choose a passing budget merely because it matches a slow implementation.
- **Token persistence.** Worker termination and restart tests cover snapshot atomicity, session loss and reinitialization. IndexedDB or another page-controlled store is never described as tamper-resistant or rollback-resistant.
- **Disclosure.** The Hub states on screen that the browser emulator is not hardware-protected custody.
- **t-of-N port.** The Rust port of Lattigo compiles to wasm32 and is a browser candidate under the same budgets. The Go oracle never ships to the Hub.

## 8. Hardware acceleration: ARM only (FPGA parked)

**Scope.**
- **HSM-side operations:** TFHE key generation and server-key derivation, decryption, manifest hashing, the HPKE and ML-DSA backup, and multiparty share generation and partial decryption.
- **Targets:** measured boards only. The i.MX 95 has Cortex-A55; the KV260 has Cortex-A53, used as a CPU only. The M4 Pro is for development, and its numbers are never quoted as board results.
- **Server-side FHE evaluation is out of scope.**

| Operation | Arithmetic (verified in TFHE-rs source) | ARM technique | Status |
|---|---|---|---|
| Seed → mask expansion (CSPRNG) | AES-CTR | TFHE-rs has an AArch64 AES path; confirm the selected build and runtime feature detection on each board rather than assuming the optional crypto extension is exposed | Profile first |
| TFHE server-key bodies (~1,800 GLWE + ~10,000 LWE encryptions, estimate to verify) | For the selected binary-secret parameter set, wrapping-u64 torus arithmetic includes polynomial products and LWE dot products | Profile CSPRNG, noise sampling, polynomial multiplication and serialization separately. Only then test a feature-gated NEON specialization against the upstream implementation and vectors | No optimization selected before profile evidence |
| Manifest hash over the measured export | Proposed canonical SHA-384 digest, frozen in P0B with the security profile | Measure runtime CPU features and throughput; optimize implementation, not the wire algorithm | Security profile precedes performance tuning |
| TFHE decrypt | Parameter-dependent LWE dot product with the selected binary key | Measure the exact dimension and latency; no optimization is assumed | Profile first |
| BFV / BGV multiparty shares, partial decrypt, refresh (§6.4) | Backend-specific RNS NTT and pointwise multiplication | Treat Montgomery, Barrett and Shoup as measured candidates only. The Lattigo port keeps Lattigo's ring representation so the Go-oracle tests (§6.5.1) stay byte-exact; a faster reduction must not change serialized values | Only after P0A GO and independent review |
| HPKE / ML-KEM / ML-DSA backup | Existing AWS-LC PQ native path in `rust/src/crypto/awslc_pq.rs` | Verify the exact feature set, runtime NEON selection and fallback on each board; cite a commit/evidence artifact rather than an issue number | No new optimization planned |

**Montgomery verdict (recorded so it isn't re-litigated).**
- It doesn't apply to the TFHE custody path, which has no modular reduction.
- It is one candidate among three for the BFV and BGV multiparty paths, where the Lattigo port must also preserve Lattigo's serialized representation.
- Acceleration does not change the CKKS counter-example, which is limited by output volume.

**Method.** `pqc-phase-profile` (workspace member `rust/pqc-phase-profile`, enabled through the
`phase-profile` Cargo feature, driven by `rust/tests/phase_profile.rs`) on the boards (performance
governor, pinned via `sched_setaffinity`).
Results go into the evidence schema (§9). Any code change is feature-gated with runtime detection
and is never compiled for wasm32.

ARM optimization is not on the correctness or Hub-delivery critical path. P6 starts only for an
operation that misses a frozen native budget and has a profile showing a dominant optimizable stage.

**FPGA: parked.** The candidate designs recorded on 2026-10-02 (TFHE key-generation engine,
streaming SHAKE engine, RNS NTT unit) are not part of this plan. Reconsider only if the ARM profile
shows TFHE key generation or hashing outside the native budgets.

## 9. Phases and gates (re-sequenced per review §8)

| Phase | Work | Exit gate |
|---|---|---|
| **P-1 · Freeze inputs** | Commit this plan and its two reviews on `docs/fhe-wrapper-plan-1002`; push the Hub FHE commit `81a2369b` (done locally by 0e; the push needs the owner's words and waits for the 4.143.0 freeze to lift) and commit the canonical scenario contract derived from it, and validate Hub consumers against it; pin repos/dependencies/standards (re-check every `ceddd554` line reference against the new pin), record the v5 decisions and budget metrics; inventory allocations; licence/patent/SBOM gate. Hub publishing/merge remains separately gated | Versioned scenario semantics including clone and offline restore; sources and distribution decision recorded; no speculative mechanism allocation; every document referenced by this plan has a commit hash |
| **P0A · Feasibility spikes** | TFHE client-key determinism and internal KDF compatibility; measure public export and candidate browsers; analytical failure-bound assumptions; PQ hierarchy/evidence parsing and existing-function replication ABI spikes. Separate N-of-N and t-of-N fitness/ring/Go-oracle studies; standards mapping; ARM baseline where available | Measured results, frozen numeric release budgets and explicit lane GO/NO-GO. Optional threshold/board work cannot delay the core lane |
| **P0B · Normative specs** | Core custody ABI, public/replication template variants, policy provisioning, hierarchy/ceremony/certificate profile, RATS/LAMPS mapping/OID strategy, live and offline recovery protocol, complete descriptor and archival policy; allocation batch 1. Separate reviewed threshold specs for GO lanes | No open core wire/role/security semantics; §0 operational assumptions resolved; full-suite/replication review closed; batch 1 gate passes. Optional lane approval remains separate |
| **P1 · FHE prerequisites on top of the HSM features** | **Depends on the HSM plan's K4 exit** (hierarchy, attestation and replication delivered and tested for AES, ML-KEM-768 and ML-DSA-65 keys). Then: allocate and register the FHE seed key type as a replicable class; FHE-specific immutable attributes (lineage, parameter hash, policy digest); the recovery-descriptor package extension; FHE decryption-policy enrollment (§6.3); F2 and F10. Use test-only opaque seed fixtures, not a TFHE backend | Both HSM-plan replication flows pass for an opaque FHE-seed fixture, including descriptor tamper and unsupported-version refusals. No FHE key-regeneration claim yet; fixture import hooks absent from shipped builds |
| **P2 · TFHE custody (native)** | Pinned TFHE backend: seeded generation, public export, decrypt policy, signed artifacts, live clone and offline recovery with source test instance absent; run exact TFHE reference fixtures alongside | Token-validated + reference-validated; both recovery flows preserve client-key identity and old ciphertext access; native budgets met |
| **P3 · Browser emulator** | Lazy bundle, worker isolation, candidate desktop matrix, snapshot recovery, disclosure | Browsers meeting frozen gates become supported; all others and mobile show the evidence view |
| **P4 · Reference lanes and oracles** | Exact OpenFHE (BFV threshold; CKKS sizes), Lattigo BGV (with its retry warning surfaced) as the Go-oracle harness of §6.5.1, TFHE-rs Kreyvium, all in the sandbox | Each named scenario reference-validated by its own library; T1 fixtures and T6 committed |
| **P5 · Threshold through PKCS#11 (optional per lane)** | Only P0A-GO lanes, after allocation **batch 2**: N-of-N fhe.rs gaps closed (§6.4); the Lattigo BGV Rust port; typed multiparty mechanism state machine; retry, mix-up, malformed-share and crash-recovery negatives; conformance tests (§6.5) and Go-oracle tiers T1–T5 (§6.5.1) | Independent review closed; token-validated and conformance-mapped (wire-interoperable only if T2 + T3 pass), or kept reference-only and named honestly |
| **P6 · ARM acceleration (optional)** | Profile-driven changes from §8 only for missed budgets | Measured gain on the target board, differential/vector tests pass, no regression, wasm32 untouched |
| **P7 · Hub integration, incremental** | Update teaching flows to v5 hierarchy, non-extractable custody, live/offline recovery and reused attestation; import hash-pinned measurements and link source evidence; update badges only to achieved levels. The v4 backup text listed in the first v6 pass (fheHsmFlows.ts lines 152, 180, 258-278, 424-444, 448, 460, 664; fheKeyMap.ts:60; fheHsmStepIO.ts:104-175; HomomorphicEncryptionSection.tsx:288-295) was **replaced by session 0e in `81a2369b`** on the owner's instruction, together with a compute-limits step that proposed releasing the seed to a confidential VM. P7 now covers only measurements, evidence links, badge promotion and later design changes | Every changed claim maps to evidence; none of the listed v4 sentences survives; core delivery needs P2/P3 and its own reference results, not P5/P6 |

**Dependencies:** the HSM plan's K-1 → K4 comes first. Core FHE path is then P-1 → core P0A/P0B → P1 → P2 → P3 → core P7. FHE P-1/P0A/P0B may run in parallel with the HSM plan, but P1 waits for its K4 exit.
P4 references may run after their input/licence gates and feed later scenario updates; the TFHE
reference is already required in P2. P5 needs its own P0 GO, P4 oracle evidence, batch 2 and independent
review. P6 is optional. Neither optional lane blocks core P7. These are planning phases, not evidence
that execution/merge/deployment has been authorized or performed.

**Evidence schema** (applies to every measurement):
This is benchmark/reproduction metadata, **not** the cryptographic RATS attestation format in §6.8.
- Provenance: library commit, parameters and parameter hash, compiler and features.
- Source basis: primary-source URL/document version and exact section, or the measurement/test artifact that supports the claim.
- Environment: hardware, OS and browser.
- Method: warm-up, sample count, distribution, peak-memory method.
- Outputs: artifact hashes and timestamp.
- Status: estimate, measured, reproduced, or independently reviewed.
- Claim scope: browser emulator, native software token, or external reference library.
- Signature: if evidence JSON is signed, the signing-key ID, public-key distribution, signature algorithm and verification step are defined; otherwise the Hub pins the artifact hash and does not call it signed.

## 10. Engine fixes carried into P1

> **Moved.** F1, F3–F9, F11 and F12 (and new F13–F16) are now owned by §8 of `implementation-plan-hsm-key-hierarchy-replication-attestation-2026-10-02.md` and land in its K1–K4 phases. F2 and F10 remain here. The table is kept for traceability.

| ID | Item |
|---|---|
| F1 (revised in v7) | Relabel only: the HPKE vector fixture already comes from the official draft-ietf-hpke-pq-05 tag (`hpkewg/hpke-pq@6433c8fc`); the test-file and CHANGELOG text still said -04. Pure ML-KEM HPKE already exists |
| F2 (replaced) | Internal-only replication transport and immutable function-key profiles; no caller-visible trusted wrapping-key template or special-case ordinary wrap bypass |
| F3 | Enforce `CKA_DERIVE_TEMPLATE` in the Rust engine. Record the pre-existing C++ gap separately; this plan does not silently expand to a C++ implementation |
| F4 | Bound certificate, evidence and signed-manifest sizes; keep large public FHE blobs outside signature buffering; specify exact ML-DSA-65 signed bytes |
| F5 (B6, FC-2) | Native/WASM test-profile isolation; reject `pReserved` and HPKE deterministic-randomness hooks in shipped artifacts; feature manifest and Hub hash checks |
| F6 | Licence anomaly resolved in the P-1 gate |
| F7 (revised) | **No change.** The C++/Rust stateful-attribute difference deliberately prevents client-driven state rewind within the current token state and is recorded in the authority. It is not host-storage anti-rollback. Keep it, and keep FHE attributes clear of those values |
| F8 | Keep `CKM_SP800_108_*` off the FHE seed's allowlist (C1). Optional hardening, recorded separately: a key derived from a sensitive base defaults to sensitive and non-extractable |
| F9 (replaced) | Internal replication state machine: nonces, consumption, immutable peer/descriptor bindings, atomic install, duplicate handling and authenticated receipts (§6.7) |
| F10 | `CKM_PQCTODAY_FHE_DERIVE_PUBLIC` never persists large public material as a token object (§6.6) |
| F11 | Manufacturing/device/function issuance and verification, constrained evidence generation, SO-approved policy enrollment and user-operation gates (§6.3, §6.7–§6.8) |
| F12 | Ordinary wrap refusal, protected clone/restore metadata/history, no import/copy/mutation bypass, recovery-key continuity and old-generator compatibility tests |

### 10.1 Repository gates every FHE change must pass (added v6)

These are existing `scripts/local-gate.sh` steps and registries, not new requirements. v5 did not
name them, and each one has already failed a PR in this repo when a mechanism, constant or fixture
arrived without its paper trail. Any P1–P5 PR that adds a vendor mechanism, key type, attribute,
return code or fixture must satisfy all of them in the same PR.

| Gate | What it requires of FHE work | Where |
|---|---|---|
| Vendor-constant manifest | `kmip/pkcs11-mech-manifest.json` `active` / `active_key_types` must list **exactly** the vendor-range `CKM_`/`CKK_` constants the engines define, with the hand-kept authority sha updated. This holds even though KMIP is out of scope (D5): the checker is about constants, not KMIP use | `scripts/check_pkcs11_constants.py` |
| Mechanism ledger | Every advertised mechanism needs a row; a row claiming `implemented` must be advertised; C++ rows for Rust-only FHE mechanisms must carry an `excluded-by-scope:` reason, as the HPKE and BIP32 rows do (ruling 2026-09-27, gap-closure 4.D). Regenerate with `gen_pkcs11_mechanism_ledger.py`; the checker never writes | `docs/pkcs11-mechanism-ledger.json`, `scripts/check_pkcs11_mechanism_ledger.py` |
| Differential exceptions | Rust-only vendor mechanisms are covered by `LEGAL-VENDOR-MECHANISMS` (rule-based, no mechanism names). Do not add FHE names to its justification; the ledger carries per-mechanism detail | `tests/differential/exceptions.json` |
| Conformance reports | The Rust report is regenerated by the conformance run and must match what is committed; the C++ report is regenerated when C++ changes (it should not, for this plan) | `rust/RUST_P11_V32_CONFORMANCE_REPORT.md`, `scripts/check_pkcs11_reports_fresh.py` |
| Vector reachability | Every fixture under a `VECTOR_ROOTS` directory must be loaded by a code line (§6.5.1) | `scripts/check_vector_reachability.py` |
| Shipped-artifact features | F5: the wasm bundle must stop carrying `acvp`; the FHE bundle gets its own feature manifest | `rust/build-wasm-bundle.sh`, `rust/Cargo.toml` |
| Allocation authority | Batch 1 and batch 2 land in the private authority **before** the constants land here; the manifest's authority sha is updated in the same PR | `pqctoday-priv/docs/platform/data/pkcs11-vendor-mech-allocation.md` |
| Remoting coverage ledger | Per `C_*` function, not per mechanism; no new row expected because the ABI gate (§6.2) forbids new functions. Confirm at P1 rather than assume | `remoting/REMOTE_P11_V32_COVERAGE.md`, `scripts/check_coverage_ledger.py` |
| Two-engine mechanism sets | CLAUDE.md: two engines advertising different mechanism sets is its own hazard, and Rust is a superset of C++ by design. FHE mechanisms widen that superset; the ledger reason is the record, and the Hub badge for the C++ engine is `refused by design`, never `planned` | `CLAUDE.md`, ledger |
| Full local gate before push | The gate runs in the container, takes the better part of an hour, and is the merge precondition; a subset is not a gate | `scripts/local-gate.sh` |

## 11. Review disposition

| Finding | Disposition |
|---|---|
| B1 allocation collision | Accepted. No numbers until allocated in the authority (§6.2) |
| B2 extractable contradiction | Replaced in v5. Non-extractable seed, ordinary-wrap refusal and controlled replication; role and bypass tests (§6.2, §6.7) |
| B3 stale inventory (F1, F7) | Accepted. Inventory regenerated at `ceddd554`; F1/F7 revised (§10) |
| B4 Hub not versioned | Accepted as a P-1 gate. The canonical scenario contract does not exist until it is committed and pinned (§2) |
| B5 fhe.rs incompleteness | Accepted. Threshold mechanisms are optional per lane and gated on feasibility, closing the fork gaps, and independent cryptographic review (§6.4) |
| B6 ACVP in shipped WASM | Accepted as a P1 exit blocker, including independent HPKE hooks in native and WASM builds (§7, §10) |
| B7 no cancellation for key generation | Accepted. Disposable worker + no-object-on-failure; no cancellation claim (§6.6) |
| B8 validation-level contradiction | Accepted. Explicit reference/token validation plus separate conformance and wire-interoperability labels (§1.1) |
| H1 ABI underspecified | Accepted. Normative spec in P0 |
| H2 threshold replay / mix-up | Accepted. One-shot transcripts prevent reuse in current state; host-resistant rollback protection is explicitly unavailable (§1.2, §6.4) |
| H3 equivalence claim | Accepted. Scheme/protocol conformance is separate from wire interoperability; cross-scheme equivalence is forbidden (§6.5) |
| H4 durable seed regeneration | Accepted. Defined KDF expansion, KATs, upgrade policy, recovery run (§5) |
| H5 30 MB export | Accepted. Measured in the P0A spike; size checks before allocation (§6.6) |
| H6 HPKE backup construction | Replaced in v5. Trust/profile and live/offline flows specified (§6.7); exact transcript, composition review and normative wire spec are P0B gates, not an already validated protocol |
| H7 decrypt policy | Accepted. Defined in P0, scoped to the educational emulator (§6.3) |
| H8 emulator ≠ HSM | Accepted. Three-way claim labelling (§1.2, §7) |
| H9 browser delivery | Accepted. Desktop matrix; mobile evidence-only (§7) |
| H10 licensing | Accepted. P-1 gate; D4 records owner intent but does not replace written distribution approval |
| Freshness corrections (review §6) | Accepted (§2) |

### 11.1 Gaps found in the v2 follow-up review and closed in v3

Historical design dispositions, not implementation evidence. V2-2's trusted-wrap design is
superseded by v5 §6.7; current requirements take precedence over this table.

| ID | v2 gap | v3 disposition |
|---|---|---|
| V2-1 | Scenario JSON was described as generated from mutable Hub TypeScript | JSON is the canonical contract; consumers validate against it (§2) |
| V2-2 | Trusted wrapping policy did not explain why plain wrap fails or how an HPKE output becomes trusted | SO-only HPKE AEAD-output template, AES-GCM allowlist and explicit ABI revision (§6.2, §6.7) |
| V2-3 | Software token claimed persistent anti-rollback | Claim narrowed to atomic current-state reuse prevention; hostile host rollback remains possible and disclosed (§1.2, §6.3–§6.4) |
| V2-4 | One Rust BFV fork was expected to validate both OpenFHE N-of-N and Lattigo t-of-N | Separate P0A GO/NO-GO decisions and exact scheme/protocol mapping; failed lanes remain reference-only (§6.4–§6.5, §9) |
| V2-5 | A translation layer could still earn “artifact equivalence” | Semantic conformance and wire interoperability are separate labels (§6.5) |
| V2-6 | CKKS and server-side Trivium remained in the token-linked crate | Token boundary narrowed to custody backends; reference/server evaluation stays outside (§5) |
| V2-7 | Native “timeouts” and worker termination were described as PKCS#11 cancellation | Calls remain synchronous; external process/worker termination and atomic snapshot recovery are tested (§6.6–§7) |
| V2-8 | Browser and ARM support/optimizations were declared before measurement | Candidate support and optimizations are gated by measurements; ARM work is optional and off the delivery critical path (§7–§9) |

### 11.2 Code-checked challenge of v3, closed in v4

Historical design dispositions, not implementation evidence. C2's wrap ceremony and C11's
two-step/hybrid Hub descriptions are superseded by v5. C10 requires the analytical justification
in §6.3, not an empirical claim of proving negligible failure probability.

Each finding was checked against `pqctoday-hsm` at `ceddd554`, TFHE-rs 1.8.1 docs, Lattigo v6.2.0
docs and draft-ietf-hpke-pq-05.

| ID | v3 gap (evidence) | v4 disposition |
|---|---|---|
| C1 | **Custody bypass.** The seed allowed `CKM_SP800_108_COUNTER_KDF`, whose outputs default to extractable and non-sensitive (`rust/src/ffi.rs:12752-12756`) while `CKA_DERIVE_TEMPLATE` is not enforced. A user-PIN holder could derive the published sub-seed and read it | KDF internal to FHE mechanisms only; mechanism off the allowlist; negative test (§5, §6.2, F8) |
| C2 | **Backup ceremony impossible as written.** The SO cannot see private objects (`rust/src/state.rs:1021`); logout destroys private session objects (`rust/src/ffi.rs:1149`); the HPKE AEAD key has no `CKA_WRAP` (`rust/src/native/hpke.rs:810-828`); `C_WrapKeyAuthenticated` does not track IV reuse (`rust/src/ffi.rs:13996-14004`) | Two-step SO-then-user ceremony with a single-use, IV-bound key (D10, §6.7, F9) |
| C3 | **Server key not reproducible.** `CompressedServerKey::new(&ClientKey)` takes no seed; only `ClientKey::generate_with_seed` is seeded | Recovery is client-key only (D9, §5) |
| C4 | **t-of-N lane could not match its reference.** The Hub's Lattigo scenario was CKKS (`mpckks`); the only Rust candidate (fhe.rs) is BFV-only | Scenario switched to BGV; Rust port of Lattigo validated by a Go oracle (D7, D8, §6.4, §6.5.1) |
| C5 | **CKKS counter-example mislabelled.** The Hub cites OpenFHE CKKS; v3 measured with Poulpy and called that reference-validated | Measured with OpenFHE; Poulpy dropped (§1, §4) |
| C6 | **OpenFHE scenario named no scheme.** The example runs BGV, BFV and CKKS | Pinned to BFV in the plan and the Hub |
| C7 | **Snapshot cost.** Whole-token flat snapshot (`rust/src/state_snapshot.rs`) would carry a 30 MB server key on every write | Large public material stays off the token (§6.6, F10) |
| C8 | **Premature allocation.** Threshold IDs were allocated at P-1 before any GO decision, in an append-only authority | Two allocation batches (§6.2) |
| C9 | **Seed template incomplete.** No `CKA_DECRYPT=true` | Added (§6.2) |
| C10 | **TFHE decrypt policy vague.** "Its own rules" named no defence | Pinned failure probability ≤ 2⁻¹²⁸, confirmed in P0A (§6.3) |
| C11 | **Hub drifted from the plan and the code:** "chunked" server-key export, "both keys regenerate from the seed", a non-extractable seed that is later wrapped, X-Wing (not in draft -05), CKKS-only size footnote, no engine-capability labels | Hub updated in the `feat/cc-fhe-section-1002` worktree: per-step engine badges and per-scenario validation targets (D11), two-step backup steps, client-key-only recovery, BFV/BGV naming, ML-KEM-768 + X25519 (`0x647a`) naming (D12), per-flow size basis. **v6 note:** those v4 two-step backup steps are now themselves stale against v5 and are still in the untracked worktree file; the exact lines are listed under P7 in §9 |

### 11.3 Final v4 challenge: v5 dispositions and remaining verification gates

All eight findings are addressed as **plan corrections** below. None is claimed to be an
implemented fix or a passed runtime/security test. P0 must close normative design questions;
P1/P2 and optional lane tests supply implementation evidence.

| ID | v5 correction | Required verification |
|---|---|---|
| FC-1 · Copy/mutation bypass | Remove caller-visible wrapping key; immutable non-extractable seeds and constrained internal replication functions (§6.2, §6.7) | P1 copy, mutation, ordinary-wrap, import and weaker-policy negatives |
| FC-2 · Independent HPKE randomness hook | Reject both `pEphemeralSeed` and `pReserved` in shipped native/WASM artifacts (F5) | P1 feature-matrix tests and exact consumed artifact hashes |
| FC-3 · Contradictory derive template | Public-output template specifies public/session object semantics; replication variants must satisfy their own templates, not silently ignore them (§6.2) | P0B existing-function semantic review; P1 allowed and conflicting template tests |
| FC-4 · SO cannot set private-user policy | SO enrolls immutable public policy before user-private key creation; engine binds its digest and enforces equal-or-stricter restore (§6.3, §6.7) | P1 login/role transitions, unauthorized policy changes and destination-policy tests |
| FC-5 · Retry binding | Protocol-specific actual public inputs and stable lineage; consumption before output; changed epoch/handle/active subset does not authorize unsafe reuse (§6.4) | Optional P5 protocol review and replay/retry/crash tests against pinned reference guidance |
| FC-6 · Incomplete recovery descriptor | Authenticate full KDF/backend/serialization/lineage/policy descriptor; retain old generator or prove real migration (§5, §6.7) | P2 source-loss live/offline recovery and old-ciphertext tests; no re-encryption-only migration claim |
| FC-7 · Unprovable statistical/rollback claims | Separate analytical bounds from sampling confidence; disclose host snapshot rollback (§1.2, §6.3, T4/T5) | P0A analytical basis; P2/P5 bounded empirical evidence and explicit rollback limitation |
| FC-8 · Phase/budget contradictions | Metrics at P-1, numeric budgets P0A, normative core specs P0B, engine fixes P1; optional threshold/ARM lanes do not block core delivery (§9) | Versioned gate evidence; no allocations or performance/support claims ahead of their gates |

## 12. References

- PKCS#11 v3.2 OS (`docs/refs/pkcs11-spec-v3.2-os.pdf`) + pqctoday vendor extensions (D13); the v3.3 draft snapshot has no HPKE mechanism
- RFC 9180 (§5.2 single-shot APIs, §6.1); draft-ietf-hpke-pq-05 (2026-07-06); FIPS 202/203/204; SP 800-38D; SP 800-38F; SP 800-108; RFC 5869
- Attestation and PQ certificate sources: version-pinned primary links and publication status in §6.8 (RATS key attestation -07; LAMPS CSR attestation -29 and freshness -08; RFC 9881 and RFC 9935). Drafts are not published standards; the selected pure-PQC composition remains our reviewed profile
- ISO/IEC DIS 28033-2, FDIS 28033-3, FDIS 28033-4; NIST IR 8214C (call for submissions)
- TFHE-rs 1.8.1, tag `tfhe-rs-1.8.1` (`tfhe/src/high_level_api/keys/client.rs` `generate_with_seed`; `tfhe-csprng/src/seeders/mod.rs` `Seed(pub u128)`; `CompressedServerKey::new(&[ClientKey])`; `tfhe-csprng` aarch64 AES generator; `core_crypto/algorithms/polynomial_algorithms.rs`; `apps/trivium`; README "Is Zama's library free to use?"), fhe.rs at `44ad194` (`crates/fhe/src/mbfv/mod.rs` security warning, `experimental-mbfv`, `fhe-math`), OpenFHE `threshold-fhe.cpp` (BFV run), Lattigo v6.2.0 `multiparty`, `multiparty/mpbgv`, `schemes/bgv` + `SECURITY.md` "On the insecurity of retries"
- Mouchet et al., PoPETs 2021 (ePrint 2020/304); Mouchet et al. 2022 (ePrint 2022/780, t-of-N); Mouchet et al. 2024 (ePrint 2024/194, retries); Okada et al. (ePrint 2025/409, adaptive active-set attack); Colin de Verdière et al. (ePrint 2026/031, concrete attack and synchronized-decryptor model); Balenbois, Orfila, Smart, WAHC 2023; Chillotti et al., J. Cryptology 2020
- ISO/IEC 28033 catalogue listings: [DIS 28033-2](https://www.iso.org/standard/87639.html), [DIS 28033-3](https://www.iso.org/standard/87640.html), [FDIS 28033-4](https://www.iso.org/standard/87641.html) (direct automated fetch returns HTTP 403; stages taken from the listing titles and the ISO Update supplement, to be re-read by hand at P-1); [NIST IR 8214C](https://csrc.nist.gov/pubs/ir/8214/c/final)
- Engine gates named in §10.1: `scripts/local-gate.sh`, `scripts/check_pkcs11_constants.py`, `scripts/check_pkcs11_mechanism_ledger.py`, `scripts/gen_pkcs11_mechanism_ledger.py`, `scripts/check_pkcs11_reports_fresh.py`, `scripts/check_vector_reachability.py`, `tests/differential/exceptions.json`
- Hub flows: Hub `main` `624115862` (release 4.144.0), `src/components/PKILearning/modules/ConfidentialComputing/data/fheHsmFlows.ts` and siblings
- Reference spike: private repo `pqctoday-org/pqctoday-fhe` at `ebda5c3d`, `reference-runs/tfhe-custody/` (TFHE-rs 1.8.1, custody config, four-platform client-key determinism)
- Review: `docs/review-implementation-plan-fhe-wrapper-pkcs11-vendor-2026-10-02.md`; HPKE proposal: `docs/proposals/pkcs11-ckm-hpke-mechanism-proposal.md`; allocation authority: `pqctoday-priv/docs/platform/data/pkcs11-vendor-mech-allocation.md`
- Final v4 challenge and owner-decision trail: [review and follow-ups](final-challenge-fhe-wrapper-plan-v4-2026-10-02.md); its findings are dispositioned in §11.3
