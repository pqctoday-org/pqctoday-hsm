# PKCS#11 v3.2 Coverage Remediation Plan — C++ and Rust engines

**Date:** 2026-08-29
**Baseline:** `origin/main` @ `dea9bfa18457aa2d55082f890d72823cefc1cdf7`
**Sources:** two independent mechanism-coverage audits (C++ `src/lib/`, Rust `rust/`) run 2026-08-29 against the relevant-mechanism set derived from `src/lib/pkcs11/pkcs11t.h` and the scope declared in `CLAUDE.md`.
**Status:** PLAN ONLY — nothing in this document has been executed.

### Decisions taken 2026-08-29 (binding on this plan)

| # | Question | Decision |
|---|---|---|
| **D1** | Sequencing vs. work already in flight | **Land the pending branches first** — `fix/acvp-hmac-general-aes-kwp`, then the 63-commit `feat/jdk27-jca-provider` blocked behind it — before starting any plan phase. See §12. |
| **D2** | SHA-384 HMAC ≥48-byte key floor (stricter than v3.2 §6.23.3's suggested 24) | **Investigate the history first.** Determine whether the floor was a deliberate security decision or an unexamined default, report, and do **not** change it until that is known. Tracked as **WS-1.4**. |
| **D3** | RSA-OAEP `hashAlg` fix rollout | **Hard fix + breaking-change note in `CHANGELOG.md`.** No transitional flag, no legacy escape hatch. Today's behaviour is already non-interoperable with any conforming module. |
| **D4** | WS-8 secondary-mechanism scope | **Implement every WS-8 variant that NIST ACVP publishes vectors for; everything else is out of scope.** ACVP availability is the sole inclusion test — see the rewritten §WS-8. |
| **D5** | Execution authority | **Execute the whole plan continuously, P-1 → P-7**, after D1's branches land. Surface decisions only when genuinely blocked. |
| **D6** | Handling the failures WS-2 exposes | **Fix everything WS-2 surfaces as part of WS-2.** Scope is open-ended by nature — the Rust engine has never been run against these ~16 ACVP suites — and is accepted as such. |
| **D7** | XMSS/XMSS-MT parameter-set breadth (65 total, ~80 s keygen each) | **Representative subset per hash family and tree height**, with the selection rationale written down. Not all 65; not the current 1+1. |
| **D8** | `tests/parity-wasm.mjs` (dead, exits green) | **Repair it**, don't delete. Fix the path, make failures exit non-zero, and treat whatever it then reports as real findings. |

---

## 0. Why this plan exists

Both engines advertise a large mechanism surface and both have substantial conformance reports. The audits found that the reports overwhelmingly prove **reachability** (the mechanism dispatches, returns `CKR_OK`, round-trips against itself) rather than **correctness** (the mechanism produces the byte-exact answer a standards body says it must).

Headline numbers from the two audits:

| | C++ | Rust |
|---|---|---|
| Relevant mechanisms considered | 185 | 165 |
| Advertised by `C_GetMechanismList` | 116 | 116 |
| Advertised **and** reaching real crypto (no stubs) | 116 / 116 | 116 / 116 |
| Advertised **and** backed by an external-oracle KAT | **28 / 116 (24%)** | **~34 / 116 (~29%)** |
| In-scope, not advertised, zero code references | 59 open | 66 |

Neither engine ships a stub behind an advertised mechanism — advertise == dispatch holds on both sides, which is genuinely good. The gap is evidence, plus a small number of real defects.

Two findings are **silent wrong answers**, not missing features, and are the reason this plan is P0-led rather than coverage-led.

---

## 1. Verification standard (normative for every item in this plan)

Per the 2026-08-29 direction: **validation is against NIST ACVP vectors; where ACVP does not cover a mechanism, another trusted vector source must be used.** The following ladder is binding. An item is not "done" until its evidence sits at Tier 1, 2, or 3 — Tier 4 alone never closes an item.

### Tier 1 — NIST ACVP (mandatory wherever it exists)

Source: `https://github.com/usnistgov/ACVP-Server`, path `gen-val/json-files/<ALGORITHM>/internalProjection.json`, **pinned by commit SHA**.

Known Tier-1 availability for this project's surface:

| Family | ACVP algorithm id |
|---|---|
| AES ECB/CBC/CTR/GCM/CCM/XTS/OFB/CFB1/CFB8/CFB128 | `ACVP-AES-<MODE>` |
| AES key wrap / wrap-with-pad | `ACVP-AES-KW`, `ACVP-AES-KWP` |
| AES CMAC, GMAC | `ACVP-AES-CMAC`, `ACVP-AES-GMAC` |
| SHA-1/2, SHA-3, SHAKE | `ACVP-SHA*`, `ACVP-SHA3-*`, `ACVP-SHAKE-*` |
| HMAC (all SHA-2/SHA-3 variants) | `ACVP-HMAC-SHA*` |
| KMAC-128/256 | `ACVP-KMAC-*` |
| RSA keygen / sigGen / sigVer | `ACVP-RSA-<mode>` |
| RSA-OAEP key transport | `KTS-IFC` |
| RSA raw primitive | `RSA-decryptionPrimitive`, `RSA-signaturePrimitive` |
| ECDSA keyGen / sigGen / sigVer | `ACVP-ECDSA-*` |
| EdDSA (Ed25519, Ed448) | `ACVP-EDDSA-*` |
| ECDH shared secret | `KAS-ECC-SSC` |
| HKDF | `KDA-HKDF` (SP 800-56Cr2) |
| SP 800-108 counter / feedback / double-pipeline | `KDF` |
| PBKDF2 | `PBKDF` (SP 800-132) |
| ML-DSA (FIPS 204) | `ML-DSA-keyGen`, `-sigGen`, `-sigVer` |
| ML-KEM (FIPS 203) | `ML-KEM-keyGen`, `ML-KEM-encapDecap` |
| SLH-DSA (FIPS 205) | `SLH-DSA-keyGen`, `-sigGen`, `-sigVer` |
| LMS/HSS (SP 800-208) | `LMS-keyGen`, `-sigGen`, `-sigVer` |

**WS-0.6 must confirm** whether ACVP currently publishes XMSS/XMSS^MT vectors (SP 800-208 covers XMSS, but ACVP-Server coverage has historically lagged LMS). If absent → Tier 3 RFC 8391.

### Tier 2 — NIST CAVP legacy response files

Only where ACVP has no equivalent. Same pinning and hashing requirements.

### Tier 3 — IETF RFC / standards-body published vectors

Permitted **only** for mechanisms Tier 1 and Tier 2 genuinely do not cover. Known Tier-3 needs on this surface:

| Mechanism | Source |
|---|---|
| `CKM_X25519`, `CKM_X448` | RFC 7748 §5.2 (single + iterated), §6.1/§6.2 |
| Ed25519ctx, Ed448 with context | RFC 8032 §7.2, §7.4 |
| ChaCha20 / ChaCha20-Poly1305 | RFC 8439 §2.8.2 (non-FIPS, no ACVP) |
| AES-KW / KWP (supplementary to ACVP) | RFC 3394 §4, RFC 5649 §6 |
| HKDF (if `KDA-HKDF` params don't map) | RFC 5869 Appendix A |
| PBKDF2 (supplementary) | RFC 6070 |
| XMSS / XMSS^MT (if no ACVP) | RFC 8391 |

### Tier 4 — Independent cross-implementation oracle

OpenSSL 3.6, Bouncy Castle, Node `crypto`. **Supplementary only.** Valuable for catching disagreement, but never sufficient to close an item — an oracle can share a bug with us (see WS-1.1, where the SHA-1 substitution is self-consistent and therefore invisible to every round-trip test).

### Never acceptable as sole evidence

1. **Self-generated vectors.** `tests/acvp/aescbc_test.json` on `main` literally declares `"source": "Generated via Node.js crypto (OpenSSL backend)"`. A vector generated by the same primitive family we are testing proves nothing. **All such vectors must be purged — see WS-0.5.**
2. **Engine-internal round-trip.** Sign→verify, wrap→unwrap, encap→decap *within one engine* is self-consistency, not correctness.
3. **Reachability probes.** `!= CKR_MECHANISM_INVALID` (the Rust report's G9 section, `RUST_P11_V32_CONFORMANCE_REPORT.md:170`, "193 passed") proves dispatch exists, nothing more. Do not count these toward coverage.
4. **Direct-library tests that bypass the PKCS#11 ABI.** `rust/src/native/prehash_kat.rs:56` and `prehash_kat_slh.rs:57` call `fips204`/`fips205` directly — they validate the patched crates, not our dispatch. Their own doc comments say so. Genuine evidence, wrong layer.

### Mandatory provenance block

Every vector file must carry the `_provenance` shape already established on branch `fix/acvp-hmac-general-aes-kwp` (`tests/acvp/aescbc_test.json`):

```json
"_provenance": {
  "source_url":     "https://raw.githubusercontent.com/usnistgov/ACVP-Server/<COMMIT>/gen-val/json-files/<ALG>/internalProjection.json",
  "source_release": "<COMMIT SHA>",
  "retrieved":      "YYYY-MM-DD",
  "producer":       "NIST ACVP-Server (reference/generator-validated sample vectors)",
  "source_sha256":  "<sha256 of the fetched source file>",
  "note":           "tgId <N>, tcId <M>, <what was selected and why>. <Independent re-verification performed.>"
}
```

For Tier 3, `producer` names the RFC and section; `source_url` points at the canonical `rfc-editor.org` text; `source_sha256` hashes the fetched document.

`source_sha256` must be **re-verifiable**: WS-0.4 adds a CI check that re-fetches and re-hashes.

---

## 2. Workstream map and sequencing

```
WS-0  Evidence integrity        ──┬──> everything else
                                  │    (harnesses that lie make all later
                                  │     "verified" claims worthless)
WS-1  Silent wrong answers      ──┤    P0 — ship independent of coverage work
WS-2  Cross-engine ACVP wiring  ──┴──> WS-3, WS-5 Rust halves
WS-3  Flagship PQC evidence
WS-4  Orphaned-vector activation      (highest evidence-per-hour)
WS-5  Advertised-but-untested classical
WS-6  Claimed-feature parity gaps
WS-7  Differential-harness depth
WS-8  Secondary mechanisms            (roadmap-gated)
```

**Merge `fix/acvp-hmac-general-aes-kwp` first** (see §12). It closes 10 of the C++ audit's 69 missing mechanisms and fixes a currently-*failing* AES-CBC KAT, and it establishes the provenance format this plan makes normative.

---

## WS-0 — Evidence integrity (P0, blocks all evidence claims)

Rationale: three harness defects currently allow a green result while testing nothing. Until these are fixed, no coverage claim in this repo can be trusted, including claims this plan's later workstreams would produce.

| Item | Finding | Evidence | Fix | Acceptance |
|---|---|---|---|---|
| **0.1** | `tests/parity-wasm.mjs` is dead and exits green. Its guard checks for `wasm/cpp/softhsm.js`, which does not exist (real path is `wasm/softhsm.js`, per `helpers.mjs:1359`), so it prints `SKIPPED` and `process.exit(0)`. Even if it ran, a verify failure is swallowed by a `try/catch` that prints `FAILED!` without a non-zero exit. | `tests/parity-wasm.mjs:17-21`, `:359-363` | **(D8) Repair, don't delete.** Fix the path, make failure exit non-zero. Run it once repaired and treat whatever it reports as a real finding to triage, not noise — it was written to compare engines and has never actually done so. | **RESOLVED 2026-08-30.** Repaired both real paths (also fixed the Rust-side path, which was equally wrong — `wasm/rust/softhsmrustv3.js` never existed; delegated loading to `helpers.mjs`'s already-proven `loadEngine()` instead of re-deriving paths a second time). Also fixed a real bug the first-ever run surfaced: the ML-KEM keygen call passed `0` for both attribute counts (templates built but never passed) with `CKA_VALUE` — an output-only attribute — as the template; replaced with the real keygen template matching `helpers.mjs`'s `generateMLKEMKeyPair`. **First real run: both cross-engine parity checks (ML-KEM encap/decap shared secret, ML-DSA sign-by-C++/verify-by-Rust) genuinely PASS** — real, previously-unavailable evidence that C++↔Rust interop works for these two mechanisms. Sabotage-verified: a deliberately mismatched byte now correctly exits 1. |
| **0.2** | `getMechanismSet` **fails open**: a broken engine runs every suite instead of skipping. | `tests/helpers.mjs:240-243` | Fail closed — an engine that cannot report its mechanism set is a hard error. | **RESOLVED 2026-08-30.** Now throws immediately with the real `CKR_*` code instead of returning an empty `Set`. Confirmed the only real caller (`tests/acvp-wasm.mjs:123`) always calls this right after loading a real engine, never expecting a graceful empty result. Verified fail-closed by monkey-patching `C_GetMechanismList` to return `CKR_DEVICE_ERROR` on a real loaded engine and confirming the throw fires. |
| **0.3** | `tests/smoke-wasm.mjs` header claims `C_GenerateKeyPair(ML-DSA-65) → C_Sign → C_Verify`; `CKM_ML_DSA*` is declared at `:59-60` and never used. | `tests/smoke-wasm.mjs:8`, `:59-60` | Either implement the advertised ML-DSA path or correct the header. Prefer implementing. | **RESOLVED 2026-08-30.** Implemented for real — generates an ML-DSA-65 key pair, signs, verifies, fails loudly on any non-OK return, matching every other `check()` call in the file. Verified: full smoke test run passes end-to-end including the new section. |
| **0.4** | No CI enforcement that vector files carry valid, re-verifiable provenance. | — | Add `scripts/check_acvp_provenance.py`: every file in `tests/acvp/` must have a `_provenance` block; `source_sha256` must match a re-fetch of `source_url`; `producer` must name a Tier 1/2/3 source. Wire into `local-gate.sh` as a **default** step. | **RESOLVED 2026-08-30.** Script written and wired in as the gate's first step (~6.5s including live re-fetch for all 29 files — negligible). One real design refinement the first run surfaced: the 4 LMS files' `source_sha256` is an honest, well-documented `null` (AFT test type — seeds are freshly randomized on every real ACVP pull, so there's no stable byte content to hash-match, only the schema is verifiable) — the checker requires a substantial `note` to accept a null rather than silently letting any missing hash through, distinguishing a deliberate documented exception from an oversight that happens to be null. |
| **0.5** | **Self-generated vectors are present and counted as evidence.** `tests/acvp/aescbc_test.json` on `main`: `"source": "Generated via Node.js crypto (OpenSSL backend), AES-256-CBC with PKCS#7 padding"`. | `tests/acvp/aescbc_test.json` | Audit **all 29** files in `tests/acvp/` for Tier-1/2/3 provenance. Replace every self-generated vector with a real NIST ACVP vector. (`fix/acvp-hmac-general-aes-kwp` already does this for 4 of them.) | **RESOLVED 2026-08-30 — 29/29.** All 9 files WS-0.4's gate found missing real provenance now have it, each independently live-hash-verified against the real NIST source and cross-checked against a second oracle (Python `cryptography`/`hashlib`/`pycryptodome`, never the vector source itself): AES-CTR/GCM/KW, ECDSA P-256/P-384/P-521, RSA-PSS, PBKDF2, KMAC. One prior commit's claim corrected in the process: RSA-PSS **does** have real Tier-1 coverage (`RSA-SigGen-FIPS186-5` tgId 9, plain SHA2-256/MGF1-SHA256) — the earlier "no ACVP match" finding had only checked `RSA-SigVer-FIPS186-5` (SHAKE/SHA3-256 only). Two new, real, previously-invisible gaps surfaced and documented rather than worked around: Rust has no SHA224 PRF arm for PBKDF2 (C++-only evidence), and C++'s `OSSLKMAC.cpp` never parses KMAC parameters at all, so its only valid evidence is a negative (`testPassed:false`) case. Running the full harness against the Rust engine for the first time also surfaced 15 real failures beyond the documented PBKDF2 gap (all 5 EdDSA variants, both RSA-OAEP unwrap KATs) — explicitly left for WS-2, not fixed here. |
| **0.6** | ACVP XMSS/XMSS^MT availability unknown. | — | Determine whether `ACVP-Server` publishes XMSS vectors at the pinned release. Record the answer in this plan. If absent, WS-3.4 uses Tier 3 (RFC 8391). | **RESOLVED 2026-08-30 — absent.** Queried the real ACVP-Server tree at the pinned commit directly (`gh api`/`curl` against `repos/usnistgov/ACVP-Server/contents/gen-val/json-files?ref=975de31eb83d87039ec88934fdc47d8c312b892d`, 177 algorithm folders total): only `LMS-keyGen-1.0`, `LMS-sigGen-1.0`, `LMS-sigGen-SP800-208`, `LMS-sigVer-1.0`, `LMS-sigVer-SP800-208` match `xmss\|lms\|hss\|stateful\|hash.based\|hbs` case-insensitively — zero XMSS/XMSS-MT folders under any naming. **WS-3.4 uses Tier 3 (RFC 8391) as the plan already anticipated.** |
| **0.7** | `src/lib/test/` (ctest) covers none of the PQC surface — 71 advertised mechanisms are never named there, including all ML-DSA/ML-KEM/SLH-DSA/HSS/XMSS, all SHA-3, KMAC, ChaCha20, SP800-108, `CONCATENATE_*`, X25519/X448, `EDDSA_PH`. It still references DES/DES3 mechanisms this fork removed. | `src/lib/test/` | Remove dead DES/DES3 references. Decide explicitly whether ctest is the right layer for PQC coverage or whether the ACVP harness owns it — and **write the decision down**, so the absence stops reading as an oversight. | **RESOLVED 2026-08-30.** Removed 69 dead DES/DES3 references (~730 lines) across `DeriveTests.{cpp,h}`, `SignVerifyTests.{cpp,h}`, `ObjectTests.cpp`, `SymmetricAlgorithmTests.{cpp,h}` — disabled test functions never in the live `CPPUNIT_TEST_SUITE` registration, their DES-only helpers, ~300 lines of now-unused RSA-under-DES KAT blobs, and dead DES case-labels inside two still-live shared functions. Two tests using `CKM_DES3_KEY_GEN` only incidentally (a NULL-template edge case, a `CKA_MODIFIABLE`-ordering regression test) were repointed at `CKM_AES_KEY_GEN` rather than deleted, preserving their real test value. Verified: full C++ build + `ctest`, 8/8 passing, unchanged from before. **Scope decision: ctest owns classical/structural PKCS#11 conformance (session lifecycle, object attributes, mechanism dispatch) inherited from upstream SoftHSM2's architecture; the ACVP harness (`tests/acvp-wasm.mjs`) owns algorithm-correctness KATs for every mechanism including all PQC.** The PQC-mechanism absence from ctest is intentional under this division, not an oversight — ctest's ~874 checks are appropriately about protocol/lifecycle behavior, not byte-exact cryptographic answers, which is what WS-0's own §0 finding (reachability vs. correctness) already established the ACVP harness is for. No new ctest PQC cases added under this item; WS-2/WS-3 already own closing PQC ACVP gaps in the correct layer. |

---

## WS-1 — Silent wrong answers (P0, security/correctness)

These produce incorrect results without any error. They are the highest-priority items in this plan.

### 1.1 — C++ RSA-OAEP wrap/unwrap ignores `hashAlg`, always uses SHA-1

**Severity: high.** A caller who correctly requests OAEP-SHA-256 gets OAEP-SHA-1 and is never told.

Chain:
- `MechParamCheckRSAPKCSOAEP` **accepts** `hashAlg=CKM_SHA256 / mgf=CKG_MGF1_SHA256` (and SHA-224/384/512, SHA3-224/256/384/512) and returns `CKR_OK` — `SoftHSM_keygen.cpp:8017-8075`
- `C_WrapKey` calls that check (`SoftHSM_keygen.cpp:1375`), then hands the mechanism to `WrapKeyAsym` (`:1636`)
- `WrapKeyAsym` hardcodes `mech = AsymMech::RSA_PKCS_OAEP` and **never reads `pParameter`** — `SoftHSM_keygen.cpp:1175-1181`. The adjacent comment still says `// SHA-1 is the only supported option`; the size bound is hardcoded `2 * 160 / 8`.
- `UnwrapKeyAsym` does the same — `:1779-1782`
- `OSSLRSA::encrypt` sets `RSA_PKCS1_OAEP_PADDING` and skips the `EVP_PKEY_CTX_set_rsa_oaep_md` block → OpenSSL default SHA-1 — `crypto/OSSLRSA.cpp:1370`, `:1396-1421`

**Why invisible today:** wrap and unwrap both substitute SHA-1, so the round trip self-consistently passes. Only a KAT or cross-engine differential catches it. Neither exists — `tests/acvp/rsa_oaep_test.json` sits on disk **loaded by nothing**.

**Blast radius:** any blob wrapped by this token under OAEP-SHA-256 is unwrappable only by another SHA-1 token — a real interop break with any conforming third-party module. `CKM_RSA_AES_KEY_WRAP` inherits the bug: it passes the caller's `pOAEPParams` through (`SoftHSM_keygen.cpp:1316`, `:1873`) into the same broken helpers, and `MechParamCheckRSAAESKEYWRAP` (`:8078-8123`) does not validate `hashAlg` at all, only `mgf ∈ 1..5`.

**Fix:** small. `C_EncryptInit`/`C_DecryptInit` already do this correctly — `SoftHSM_cipher.cpp:365-376` and `:1088-1099` map `hashAlg` → `AsymMech::RSA_PKCS_OAEP_SHA256` etc. The wrap path simply never adopted that switch. Port it into `WrapKeyAsym`/`UnwrapKeyAsym`, replace the hardcoded `2 * 160 / 8` bound with a hash-length-derived one, and tighten `MechParamCheckRSAAESKEYWRAP` to validate `hashAlg`.

**Evidence required (Tier 1):** `KTS-IFC` ACVP vectors for RSA-OAEP key transport, exercised through `C_WrapKey`/`C_UnwrapKey` — **not** through `C_Encrypt`/`C_Decrypt`, which already work. Plus a negative test: wrapping under SHA-256 and unwrapping under SHA-1 must **fail**.

**Acceptance:** OAEP-SHA-256 wrap output byte-matches the ACVP vector; the SHA-1/SHA-256 mismatch negative test fails as expected; `CKM_RSA_AES_KEY_WRAP` covered by the same pair.

**Rollout (D3):** hard fix. No transitional diagnostic, no opt-in legacy SHA-1 flag. Record as a **breaking fix** in `CHANGELOG.md`, stating plainly that blobs wrapped by an earlier build under a non-SHA-1 `hashAlg` were actually SHA-1 and must be re-wrapped. Rationale: the old behaviour cannot interoperate with any conforming PKCS#11 module, so preserving it would only prolong a silent defect — and a legacy flag would make the wrong behaviour permanently reachable.

### 1.2 — Rust exposes unwrapped EC private key material in the clear

**Severity: high (security).** An EC private key recovered through `C_UnwrapKey` has a **readable `CKA_VALUE`** in Rust, where C++ correctly answers `CKR_ATTRIBUTE_SENSITIVE`.

This is currently buried as a sub-claim inside `DEFECT-RUST-CKA_VALUE-ON-ASYMMETRIC-KEYS` (`tests/differential/exceptions.json:217-224`), an entry otherwise framed as an attribute-*presence* formatting difference and deferred behind plan item E5.

**Action:** split the sensitivity violation out of the E5 formatting bundle and treat it as its own security item. Whether or not Rust stores keys as an internal blob (the E5 root cause), `CKA_SENSITIVE`/`CKA_EXTRACTABLE` enforcement on read is independent of storage format and must not wait for E5.

**Evidence required:** a differential scenario asserting `CKR_ATTRIBUTE_SENSITIVE` on `CKA_VALUE` read for unwrapped and generated private keys, both engines, all key types.

**Acceptance:** Rust returns `CKR_ATTRIBUTE_SENSITIVE`; the exceptions entry is narrowed to the genuine formatting-only residue.

### 1.3 — C++ never reads `CK_EDDSA_PARAMS`

PKCS#11 v3.2 defines `CK_EDDSA_PARAMS { phFlag; ulContextDataLen; pContextData }` as the parameter to `CKM_EDDSA`. It is declared in this repo's own header (`src/lib/pkcs11/pkcs11t.h:2539-2545`, canonical copy `docs/refs/pkcs11t-canonical-v3.2.h:2491-2495`) and **never read** — `grep -rn "CK_EDDSA_PARAMS\|phFlag" src/lib/` outside the header returns nothing.

`AsymSignInit`'s `CKM_EDDSA` case leaves `param = NULL` (`SoftHSM_sign.cpp:880-884`), and the guard at `:1039-1043` then rejects any non-NULL `pParameter` with `CKR_MECHANISM_PARAM_INVALID`.

Consequences:
1. A conforming caller requesting Ed25519ph the standard way (`CKM_EDDSA` + `phFlag=CK_TRUE`) is **refused** — only the vendor-range `CKM_EDDSA_PH` (`0x80001057`, `pkcs11t.h:1268`) works.
2. **RFC 8032 context strings are unreachable entirely** — Ed25519ctx and any non-empty-context Ed448 signature can be neither produced nor verified.

**Evidence required (Tier 1 + Tier 3):** ACVP `ACVP-EDDSA-sigGen`/`sigVer` for the base cases; RFC 8032 §7.2 (Ed25519ctx) and §7.4 (Ed448 with context) for the context-string cases ACVP may not carry.

**Acceptance:** `CKM_EDDSA` + `phFlag=CK_TRUE` produces a signature byte-matching the Ed25519ph vector; a non-empty context produces the RFC 8032 §7.2 expected signature.

### 1.4 — Investigate the SHA-384 HMAC ≥48-byte key floor (D2 — investigate, do not change)

The engine rejects SHA-384 HMAC keys under 48 bytes. PKCS#11 v3.2 §6.23.3 points at FIPS-198's suggested floor of **24**. The stricter floor rejects roughly **a third of NIST's own SHA-384 HMAC test cases** — including `hmac_sha384` tcId 5 (26-byte key), which `fix/acvp-hmac-general-aes-kwp` had to route around by selecting tcId 25 instead.

**This item is investigation only.** Do not relax or raise the floor until the question below is answered.

Determine:
1. When and in which commit the 48-byte floor was introduced (`git log -S` on the constant / the key-length check in the MAC path, both engines).
2. Whether the commit message, an adjacent comment, or a plan doc records it as a **deliberate** hardening decision (e.g. "key at least as long as the digest", a defensible position) or whether it is an unexamined default — for instance a `getMinKeySize()` copied from the digest length without considering FIPS-198.
3. Whether C++ and Rust agree on the floor. A silent disagreement here would itself be a differential finding.
4. Whether any FIPS/CMVP-relevant claim in the repo depends on the stricter value.

**Deliverable:** a short written finding appended to this section, plus a recommendation. If it proves to be an unexamined default, relaxing to 24 becomes a normal WS-5.7 item and unblocks full Tier-1 SHA-384 HMAC vector coverage. If it was deliberate, record it as a documented, intentional deviation with its rationale, and the vector-selection workaround becomes permanent policy rather than an ad-hoc choice.

**Do not** treat "the tests pass with tcId 25" as closure — that is the workaround, not the answer.

**RESOLVED 2026-08-30.** Traced via `git log -S`/`git show`, not assumed:

1. **When introduced:** at this fork's very first commit, `db366c7` ("feat(phase-0): import SoftHSMv2 v2.7.0..."), 2026-03-02 — `ulMinKeySize = 48` and `minSize = 48` for `CKM_SHA384_HMAC` are already present in the imported upstream source, byte-identical to what exists today. Not introduced or altered by this PQC fork at any point; the later table-driven refactor (`858fc05`, "MAC lookup table") mechanically moved the same values from a switch statement into `kMacMechTable`, changing nothing.
2. **Deliberate or unexamined:** reads as upstream SoftHSMv2's own deliberate, **uniformly applied** convention — minimum key length equals the mechanism's own digest output length, for every single HMAC variant without exception (SHA-1→20, SHA-224→28, SHA-256→32, SHA-384→48, SHA-512→64, all four SHA-3 variants matching their own digest lengths) — not a SHA-384-specific anomaly, and every later addition to the table (the SHA-3 family, KMAC-128/256) follows the identical pattern. A copy-paste mistake would not be this consistent across 9+ independently-added rows spanning multiple commits and roughly five months.
3. **C++ vs Rust agreement: they disagree — a real, previously undocumented finding.** C++ enforces this floor symmetrically in both `MacSignInit` and `MacVerifyInit` (`SoftHSM_sign.cpp`, `kMacMechTable`). Rust's `sign_hmac` (`crypto/handlers.rs:1403-1437`) has **no minimum key-size check at all** — `Hmac::<Sha384>::new_from_slice(key_bytes)` from the RustCrypto `hmac` crate accepts any key length, since HMAC as a construction is defined for arbitrary-length keys per RFC 2104 and the crate imposes no floor itself. Rust silently accepts a 1-byte HMAC-SHA384 key that C++ would reject with `CKR_KEY_SIZE_RANGE`.
4. **FIPS/CMVP dependency:** none found. Grepped every `docs/*.md` for `FIPS 198`/`FIPS-198` and for any CMVP/FIPS-140 security-policy document referencing an HMAC key-size floor — no compliance claim anywhere in the repo depends on this specific value (this project is not undergoing CMVP certification; see standing policy against fact-checking certification status).

**Recommendation:** keep the C++ floor as-is — it is upstream's deliberate, internally consistent, five-month-stable convention, stricter than the spec's minimum but not wrong, and no evidence favors relaxing it. The real finding here is the **opposite** of D2's original hypothesis: it is not C++ that has an unexamined default, it is **Rust that has no floor at all**, silently accepting HMAC keys PKCS#11's own advertised `ulMinKeySize`/`ulMaxKeySize` range (which Rust would need to advertise consistently with C++ for this to be spec-honest) would reject on the C++ side. This is a genuine WS-6-class C++/Rust parity gap — Rust missing a validation C++ has, not C++ being overly strict — but fixing it is Rust-side work and out of scope under the current C++-only directive. Flagged here for whoever picks up WS-2/WS-6 on the Rust side; not fixed in this pass. The tcId-25 vector-selection workaround in `fix/acvp-hmac-general-aes-kwp` stands as permanent, correct policy — not a temporary one.

---

## WS-2 — Cross-engine ACVP enablement (P0, unlocks all Rust KAT evidence)

**The ACVP corpus has never run against the Rust engine.** `tests/acvp-wasm.mjs:74-75` defaults `engineMode` to `'cpp'`; `scripts/local-gate.sh:322-325` invokes `npm run test:acvp` with **no `--engine` flag** while labelling the step *"20 suites, cross-engine"*. No `--engine=rust` or `--engine=both` invocation exists anywhere in the repo.

Compounding: the artifact that path needs, `wasm/rust/softhsmrustv3_bg.wasm`, is **gitignored** (`.gitignore:95`), untracked, dated 2026-06-21, and **written by no script** — the gate builds to `rust/pkg/`. So `--engine=rust` would `ENOENT` on a clean checkout even if someone passed the flag.

| Item | Fix | Acceptance |
|---|---|---|
| **2.1** | Make the Rust wasm artifact reproducibly buildable at the path the harness expects. Either add a build step producing `wasm/rust/softhsmrustv3_bg.wasm`, or repoint the harness at `rust/pkg/`. Do **not** simply un-gitignore a stale binary. | A clean checkout + gate run produces the artifact; no manual step. |
| **2.2** | Flip `scripts/local-gate.sh:322-325` to `--engine=both`. | Both engines' results appear; a Rust-side failure fails the gate. |
| **2.3** | The step label becomes true, or is corrected. | Label matches behaviour. |
| **2.4** | **(D6) Triage and fix every failure this exposes, as part of WS-2 — not deferred to a later workstream.** The Rust engine has never been graded against these ~16 ACVP suites; expect real, previously-invisible defects, not just wiring noise. | Every suite that goes from zero-evidence to run-and-fail is driven to pass on real crypto grounds (a corrected implementation), not by loosening the suite or excluding the mechanism. Each fix gets its own commit citing the specific ACVP test that caught it. |

**Impact:** this single workstream converts ~16 ACVP suites from *zero* Rust evidence into real Tier-1 KATs — the highest-leverage item in the plan after WS-1. Depends on WS-0.2 (fail-closed), or a broken Rust engine will silently "pass" every suite.

**Scope note (D6):** 2.4 is deliberately open-ended — the size of what surfaces is unknown until the suites actually run. That is accepted, not a reason to scope it down after the fact. If a surfaced failure turns out to be large enough to be its own multi-day effort (e.g., it turns out to be the ML-KEM ABI gap already tracked as WS-3.1), fold it into that workstream by reference rather than duplicating the work — but do not leave it unfixed.

---

## WS-3 — Flagship PQC evidence (P0/P1)

### 3.1 — ML-KEM has no PKCS#11-ABI decapsulation evidence and no KAT (P0)

The project's headline FIPS 203 mechanism has **strictly weaker evidence than the FrodoKEM vendor mechanism sitting next to it.**

- The Rust conformance report's ML-KEM section is 4 checks: keygen, encapsulate size query, encapsulate, one negative. **No `C_DecapsulateKey` call.**
- `rust/test_p11_conformance.js` invokes `_C_DecapsulateKey` **exactly once** — line **2943**, for **FrodoKEM**. The only "encap → decap agree on the same shared secret" assertion in the entire 976-check report is FrodoKEM's.
- ML-KEM encap/decap agreement exists only on the typed `native::` surface (`rust/src/native/encrypt.rs:1810-1825`), not through the ABI. The `ffi.rs` encaps/decaps round-trip (`ffi.rs:18151-18231`) is **ECDH-as-KEM**, not ML-KEM.
- **No ML-KEM KAT anywhere.** `native/keygen.rs:3222`/`:3273` are `ml_dsa_keygen_from_seed_matches_acvp_kats` / `slh_dsa_..._matches_acvp_kats`; the ML-KEM twin at `:3324` is `ml_kem_keygen_from_seed_deterministic_and_round_trips` — determinism and self-consistency only.
- `tests/acvp/mlkem_test.json` exists but never runs against Rust (WS-2).

**Fix:** add a full `C_EncapsulateKey` → `C_DecapsulateKey` SEAM test through the PKCS#11 ABI for all three parameter sets, both engines, plus Tier-1 `ML-KEM-encapDecap` and `ML-KEM-keyGen` KATs.

**Acceptance:** encap→decap shared-secret agreement through the ABI for ML-KEM-512/768/1024 on both engines; decapsulation of an ACVP ciphertext yields the vector's expected shared secret; implicit-rejection (invalid ciphertext) behaviour matches FIPS 203.

### 3.2 — SLH-DSA sigVer covers 1 of 12 parameter sets

All 12 param sets map correctly (`crypto/OSSLSLHDSA.cpp:254-265`) and all 12 round-trip (`acvp-wasm.mjs:282-304`), but `tests/acvp/slhdsa_ctx_test.json` carries sigVer vectors for **all 12** and the harness reads only `SLH-DSA-SHA2-128f` (`acvp-wasm.mjs:606`).

**Fix:** iterate all 12. The vectors are already on disk. **Effort: very low; evidence gain: 11 parameter sets.**

### 3.3 — 22 `CKM_HASH_ML_DSA*` / `CKM_HASH_SLH_DSA*` variants have no FIPS 204/205 vectors

All 22 dispatch correctly (macro-expanded cases at `SoftHSM_sign.cpp:950-959`, `:1023-1032`, mirrored in verify) and are exercised — none against a standards vector. `tests/acvp/mldsa_extended_test.json`, which carries FIPS204-tr1 `context` and `preHash` sections, **is loaded by nothing.**

Note the layering trap: Rust's `prehash_kat.rs`/`prehash_kat_slh.rs` *do* check pre-hash against NIST ACVP, but call `fips204`/`fips205` directly, bypassing the PKCS#11 dispatch. That evidence does not cover this item.

**Fix:** wire `mldsa_extended_test.json` through the PKCS#11 ABI for all 22 variants.

### 3.4 — XMSS / XMSS^MT have no functional ABI evidence in the default gate

Zero occurrences of "XMSS" in the Rust conformance report. G9's XMSS keygen probes deliberately pass `CKA_PARAMETER_SET = 0xffffffff` (`rust/test_p11_conformance.js:3153`, `:3262-3264`) and return `0x209 CKR_PARAMETER_SET_NOT_SUPPORTED` — **no XMSS key is ever generated there.** The reason is documented honestly (`:2875-2915`): ~80 s keygen in the `--dev` wasm build.

Real coverage exists but is **opt-in only** — `rust/test_xmss_release.js:186-187` via `--release-xmss`/`--all` (`scripts/local-gate.sh:88,97,327-336`) — and covers **1 of 9** XMSS and **1 of 56** XMSS-MT parameter sets, round-trip, no RFC 8391 KAT. That opt-in tier has already earned its keep: it caught `CKM_XMSSMT` missing from `get_sig_len()` (512 vs 4963 bytes).

**Fix:** (a) resolve WS-0.6 (ACVP XMSS availability) and add Tier-1 or Tier-3 RFC 8391 KATs; (b) **(D7)** broaden parameter-set coverage to a **representative subset per hash family and tree height** — not all 65 (too slow at ~80s/keygen), not the current 1+1 (not meaningful). Concretely: one param set per {SHA2-256, SHA2-192, SHAKE256} hash family crossed with a low and a high tree height for both XMSS (9 sets → target ~4-6 covered) and XMSS-MT (56 sets → target ~6-8 covered, spanning both the 32 named `CKP_XMSSMT_*` constants and at least one of the 24 dispatched-but-unnamed OIDs from WS-6.5). Write the exact selection and the reason for each choice into the report next to the results — "representative" must be justified, not asserted; (c) decide and document whether the default gate should carry a fast XMSS case or remain opt-in.

### 3.5 — HSS/LMS evidence is round-trip only

`native/sign.rs:592-670` covers round-trip and key-exhaustion. `tests/acvp/lms_sigver_test.json` and `lms_keygen_test.json`/`lms_keygen_expected.json` are on disk and **never loaded** by the harness.

**Fix:** wire the orphaned LMS vectors (Tier 1, SP 800-208). Overlaps WS-4.

**Investigated 2026-08-30 — sigVer vectors wired (via WS-4), keygen vectors genuinely blocked, not deferred casually.** `lms_sigver_test.json` is real KAT evidence and already loaded. `lms_keygen_test.json`/`lms_keygen_expected.json` (80 real ACVP `seed`+`I` → `publicKey` cases) require the engine to generate an LMS/HSS key pair *deterministically from a given seed* to check against — the same pattern already implemented for ML-DSA/ML-KEM/SLH-DSA via `extractSeed()` (`SoftHSM_keygen.cpp:331-345`). That function's own doc comment enumerates exactly three families (`ML-DSA xi = 32, ML-KEM d||z = 64, SLH-DSA SK.seed||SK.prf||PK.seed = 3n`) and has exactly three call sites — none for `CKM_HSS_KEY_PAIR_GEN`. The underlying library (`src/lib/crypto/stateful/hash-sigs/`, Cisco's reference LMS/HSS implementation) generates keys through `hss_generate_private_key()`, which takes a caller-supplied `generate_random` **callback**, not a fixed seed buffer — reproducing a specific ACVP vector's exact public key would require either reverse-engineering the library's internal RNG-call sequence (how many bytes it pulls, in what order, for what purpose) to feed it deterministically, or bypassing the library's high-level API and reimplementing RFC 8554 §5.3's LM-OTS/LMS key derivation directly from `SEED`+`I`. Both are real, multi-hour undertakings with genuine crypto-correctness risk if rushed — comparable in scope to WS-3.4/XMSS, not a wiring task. Deferred alongside XMSS rather than attempted under time pressure; a dedicated follow-up should scope CKA_SEED support for `CKM_HSS_KEY_PAIR_GEN` as its own item before this can close.

### 3.6 — Classic McEliece has zero conformance evidence

1 of 5 parameter sets is supported (`mceliece6688128` hard-rejected otherwise, `ffi.rs:3417-3419`) — a documented scope decision, not a defect. But "MCELIECE" appears **0 times** in the conformance report; G8 covers only FrodoKEM/Keccak-256/KMAC/BIP32. Its sibling FrodoKEM has a full encap→decap SEAM test.

**Fix:** mirror the FrodoKEM G8 block for Classic McEliece. No Tier-1 source exists (not a NIST-standardised algorithm) → Tier 3/4: the round-3 NIST submission KAT files, or a cross-implementation oracle, explicitly recorded as such.

---

## WS-4 — Activate orphaned vectors (P1, highest evidence-per-hour)

**13 of 29 ACVP vector files are loaded by nothing.** Real vectors, already in the repo, producing zero evidence:

`ecdsa_p521_test.json`, `eddsa_test.json`, `eddsa_ed448_test.json`, `kmac_test.json`, `lms_keygen_test.json`, `lms_keygen_expected.json`, `mldsa_extended_test.json`, `pbkdf2_test.json`, `rsa_oaep_test.json`, `sha384_test.json`, `sha512_test.json`, `sha3_256_test.json`, `sha3_512_test.json`

Additional harness defects in the same area:
- Most suites read only `tests[0]` — use **all** `tests[]` entries.
- SLH-DSA reads 1 of 12 param sets (WS-3.2).

**This workstream writes almost no crypto.** It is wiring plus provenance verification (WS-0.4/0.5 must confirm each file is genuinely Tier-1 sourced before it is trusted — do not assume a file in `tests/acvp/` is a real ACVP vector; `aescbc_test.json` proves otherwise).

**Sequencing note:** WS-4 closes part of WS-1.1 (`rsa_oaep_test.json`), WS-1.3 (`eddsa_*`), WS-3.3 (`mldsa_extended`), WS-3.5 (`lms_*`) and WS-5.2 (`pbkdf2`). Do WS-4 *with* those items, not separately.

---

## WS-5 — Advertised, dispatched, never correctness-tested (P1)

### 5.1 — RSA signatures: 25 mechanisms advertised, 1 KAT

Exactly one RSA signature mechanism has a KAT — `CKM_SHA256_RSA_PKCS_PSS` (ACVP sigVer, `acvp-wasm.mjs:169-180`). The rest are covered as engine-internal round-trips (`cpp_compliance_report.md:475-485`) and the 8 SHA3×{PKCS,PSS} pairs as bare `RV=0` rows (`:1068-1073`). `CKM_RSA_X_509` has no operation at all — init + list only (`cpp_compliance_report.md:909-912`).

**Fix:** Tier-1 `ACVP-RSA-sigGen`/`sigVer` across the advertised SHA × {PKCS1v1.5, PSS} matrix; `RSA-signaturePrimitive`/`decryptionPrimitive` for `CKM_RSA_X_509`. Rust already has the primitive covered (`ffi.rs:17549+`) — port the pattern to C++.

### 5.2 — All four KDFs reach real `EVP_KDF` code with no vector comparison

`CKM_HKDF_DERIVE`, `CKM_PKCS5_PBKD2`, `CKM_SP800_108_COUNTER_KDF`, `CKM_SP800_108_FEEDBACK_KDF` — `SoftHSM_keygen.cpp:3302-3340`. The `### KCV` rows prove the check-value is a correct truncation of the derived key, **not** that the key is the right KDF output. The harness's HKDF check is `okm1 === okm2` (`acvp-wasm.mjs:497`) with no mechanism gate at all.

Rust is no better: `ffi.rs:14393` recomputes SP 800-108 inline with the *same* `hmac` crate — self-consistency, not a vector.

**Fix:** Tier-1 `KDA-HKDF`, `KDF` (counter + feedback), `PBKDF`. Tier-3 RFC 5869 / RFC 6070 as supplements where ACVP parameters don't map.

**Investigated 2026-08-30 — `PBKDF` partially resolved (via WS-0.5); `KDA-HKDF` and `KDF` genuinely blocked, not attempted from memory.**

- `CKM_PKCS5_PBKD2`: already has one real Tier-1 case (PBKDF2-HMAC-SHA224, `pbkdf2_test.json`, wired as `pbkdf2-224` — WS-0.5). SHA-512 still self-consistency only; not closed further this pass.
- `CKM_HKDF_DERIVE`: fetched the only Tier-1 source at the pinned commit, `KDA-HKDF-Sp800-56Cr2` — it is **not** a standalone HKDF vector set. NIST frames it inside SP 800-56C's key-agreement construction: the "info" input a test case expects is not raw bytes but the output of a separate `OtherInfo`/fixedInfo concatenation algorithm (`fixedInfoPartyU`/`fixedInfoPartyV`, each a `{partyId, ephemeralData}` structure, combined per a length-prefixing convention SP 800-56A Rev3 defines). Implementing that correctly requires the actual SP 800-56A text; this repo has no local copy, and guessing at the prefix widths/byte order rather than reading the real algorithm is exactly the kind of fabricated-crypto-detail this plan's own standards forbid — a wrong guess would just produce a plausible-looking mismatch, not a caught error, since there is no independent way to know the encoding is wrong versus something else being wrong. Checked for a Tier-3 shortcut (RFC 5869's own simpler Appendix A vectors, which map directly onto PKCS#11's raw-salt/raw-info `CK_HKDF_PARAMS`) the same way WS-5.3 found RFC 7748 vectors already vendored in `rust/src/native/encrypt.rs` — no RFC 5869 vectors exist anywhere in this repo. Deferred; needs either the real SP 800-56A text or a legitimately-sourced RFC 5869 vector set before this can close.
- `CKM_SP800_108_COUNTER_KDF`/`_FEEDBACK_KDF`: zero test coverage of any kind currently exists (not even self-consistency) — checked `tests/helpers.mjs` for a `CK_SP800_108_KDF_PARAMS`-building helper; none exists. Building one from scratch (the parameter shape has counter/DKM-length/context segments, `SoftHSM_keygen.cpp`'s own C_DeriveKey handling for it runs ~150 lines) plus sourcing real NIST `KDF` vectors is a real, multi-hour undertaking on the scale of WS-3.4/3.5, not attempted here.

### 5.3 — `CKM_X448` is advertised, dispatched, and never once executed

Dispatch is real (`SoftHSM_keygen.cpp:2745`, `:3181`). Its only appearance in 1144 lines of `cpp_compliance_report.md` is line 285 — `| Advertised_CKM_X448 | ✅ PASS | X448 derive |` — a **mechanism-list presence check**, not a derive. Sibling `CKM_X25519` has an oracle-checked KCV (`:893-896`).

**Fix:** Tier-3 RFC 7748 §6.2 (X448) and §6.1 (X25519), single and iterated. Rust already has these (`native/encrypt.rs:1961-2020`) — port to C++ and to the ABI layer.

### 5.4 — SHA-3 digests are weakly evidenced (C++)

`CKM_SHA3_224`/`SHA3_512` get only `len=NN deterministic, input-dependent` (`cpp_compliance_report.md:1061-1062`); `CKM_SHA3_384` is init-only; `CKM_SHA3_256` has a **hardcoded expected value in the harness** (`acvp-wasm.mjs:350`) while `sha3_256_test.json` and `sha3_512_test.json` sit orphaned. MD5 and RIPEMD-160 — the two *excluded* legacy digests — currently have better evidence than SHA3-256/384.

**Fix:** Tier-1 `ACVP-SHA3-*`, via WS-4.

### 5.5 — ECDSA sign has no KAT in Rust

Only `test_p521_kat_verify` (`handlers.rs:2650`) — verify-only, one curve.

**Fix:** Tier-1 `ACVP-ECDSA-sigGen` (deterministic-`k` or with the vector's `k`) across P-256/384/521.

### 5.6 — EdDSA has no KAT in either engine

No RFC 8032 vectors run anywhere; `eddsa_test.json` and `eddsa_ed448_test.json` are orphaned. Overlaps WS-1.3 and WS-4.

### 5.7 — Self-referential MAC/AEAD evidence

HMAC (`ffi.rs:15790`) matches against the same RustCrypto crate; KMAC and ChaCha20 have no vectors.

**Fix:** Tier-1 `ACVP-HMAC-*`, `ACVP-KMAC-*`; Tier-3 RFC 8439 for ChaCha20-Poly1305 (non-FIPS, no ACVP).

**Credit where due — these already have real Tier-1/Tier-3 evidence and need no work:** AES ECB/CBC/CTR/GCM (SP 800-38A/38D KATs, `rust/src/crypto/multipart.rs:695,732,819,836-889`), AES-KW (RFC 3394, `native/encrypt.rs:1385`), X25519/X448 in Rust (RFC 7748), ML-DSA/SLH-DSA keygen-from-seed vs ACVP, RSA PKCS1v15/PSS vs OpenSSL (`handlers.rs:2757,2769,2825`), `CKM_RSA_X_509` vs ACVP SignaturePrimitive. Plus transitive evidence: the differential harness byte-compares Rust against the ACVP-validated C++ engine for `CKM_SHA256`, `CKM_SHA3_256`, `CKM_SHA256_HMAC`, `AES_ECB/CBC/CTR/GCM`, `AES_KEY_WRAP` (`tests/differential/scenarios.inc:729-898`), and runs by default.

---

## WS-6 — Claimed-feature parity gaps (P2)

### 6.1 — Rust `CKM_AES_CMAC` / `CKM_AES_CMAC_GENERAL` missing (highest-value item here)

`CLAUDE.md:44` lists CMAC as a **retained** algorithm. The `cmac` crate is a dependency (`rust/Cargo.toml:85-86`, comment: *"retained MAC mechanism"*) and AES-CMAC crypto genuinely runs — **but only as an SP 800-108 KBKDF `prfType` parameter value** (`ffi.rs:7824`, `:8109-8114`, `:8145-8150`). There is no CMAC arm in the sign dispatch, no `mechanism_info` arm, and `C_GetMechanismInfo(CKM_AES_CMAC)` returns `CKR_MECHANISM_INVALID`. **The primitive is present; the mechanism is unwired.** C++ advertises it.

**Fix:** one dispatch arm + one `mechanism_info` arm. **Evidence:** Tier-1 `ACVP-AES-CMAC`.

### 6.2 — C++ missing 12 `CKM_SHA*_KEY_DERIVATION` mechanisms that Rust has and KATs

`rust/RUST_P11_V32_CONFORMANCE_REPORT.md:727-737` shows `CKM_SHA256/384/512_KEY_DERIVATION` and `CKM_SHA3_256/384/512_KEY_DERIVATION` each with *"derived value byte-equals independent Node digest of the base key"*. C++ has **none** of the 12 (SHA-1/224/256/384/512, SHA-512/224, SHA-512/256, SHA-512/t, SHA3 ×4).

Strongest single parity signal in the audit: the feature is proven buildable, proven correct, and one engine already has it.

### 6.3 — SHA-3 family is internally inconsistent (both engines)

**Rust (8 missing):** `CKM_SHA3_224`, `CKM_SHA3_384` (digests), `CKM_SHA3_224_HMAC`, `CKM_SHA3_384_HMAC`, `CKM_SHA3_224/256/512_RSA_PKCS` and their `_PSS` twins. The *inconsistency* is the finding:
- `CKM_SHA3_384_RSA_PKCS`, `_PSS`, `CKM_SHA3_384_KEY_DERIVATION` and `CKM_ECDSA_SHA3_384` **are** advertised — but the standalone `CKM_SHA3_384` digest is not.
- `CKM_ECDSA_SHA3_224` is advertised; `CKM_SHA3_224` is not.
- SHA3-384 is the **only** SHA-3 RSA composite present, while SHA3-256/512 (which do have digest + HMAC mechanisms) have none.
- Both hashers are compiled in and used: `sha3::Sha3_384` (`native/derive.rs:161`), `Sha3_224`/`Sha3_384` (`crypto/handlers.rs:1582,1584`). **Pure wiring omissions.**

**C++ (12 missing):** SHA-2 truncated variants — `CKM_SHA512_224`, `CKM_SHA512_256`, `CKM_SHA512_T` plus their `_HMAC`, `_HMAC_GENERAL`, `_KEY_GEN`, `_KEY_DERIVATION`. `C_DigestInit`'s switch ends at SHA3-512 (`SoftHSM_digest.cpp:67-119`). Advertise == dispatch is honoured, so this is honest absence, not a mismatch.

**RESOLVED 2026-08-30 (partial, deliberately) — `CKM_SHA512_224`/`CKM_SHA512_256` implemented; `CKM_SHA512_T` explicitly not.** Verified both mechanism names and every suffixed variant against the actual ratified spec text (`docs/refs/pkcs11-spec-v3.2-os.pdf` §6.25/§6.26), not just the local header — genuinely spec-defined, not invented. Implemented digest + `_HMAC` + `_HMAC_GENERAL` + `_KEY_DERIVATION` (8 mechanisms) using OpenSSL's built-in `EVP_sha512_224()`/`EVP_sha512_256()` (correct standardized initial hash values, not post-hoc truncation). `_KEY_GEN` deliberately excluded, consistent with this plan's own existing policy for every other `CKM_SHA*_KEY_GEN` (§WS-8, "Assessed OUT" table: no ACVP algorithm tests pure generic-secret-length key generation; `CKM_GENERIC_SECRET_KEY_GEN` already covers the use case) — confirmed C++ dispatches none of the existing SHA-2/SHA-3 `_KEY_GEN` mechanisms either before adding these two. `CKM_SHA512_T` (arbitrary caller-specified truncation) remains genuinely absent: the spec defines `CKM_SHA512_224` as literally "the same as `CKM_SHA512_T` with a parameter value of 224," but OpenSSL has no generic parameterized `EVP_MD` for arbitrary truncation lengths — implementing it would mean a from-scratch FIPS 180-4 §5.3.6 initial-hash-value computation (XOR the standard SHA-512 IV with a repeating `0xa5` pattern, then hash the ASCII string `"SHA-512/" + t` through one compression round to get the real IV), a materially different and riskier undertaking than reusing OpenSSL's audited fixed-IV support. Left out rather than rushed. Real Tier-1 ACVP evidence wired for everything implemented: `SHA2-512-224-1.0`/`SHA2-512-256-1.0` digest KATs (3 cases each), `HMAC-SHA2-512-224/256` verify KATs, and a derive-vs-digest cross-check (the same pattern WS-6.2 established) for both `_KEY_DERIVATION` mechanisms. CPP ACVP: 209 → 219 PASS, 0 FAIL, 0 SKIP.

### 6.4 — Remaining Rust mechanism gaps

`CKM_RSA_AES_KEY_WRAP`, `CKM_CONCATENATE_DATA_AND_BASE` (third of the concat triple — Rust has `BASE_AND_KEY` and `BASE_AND_DATA`), `CKM_AES_CBC_ENCRYPT_DATA`, `CKM_AES_ECB_ENCRYPT_DATA`.

**Note:** implement `CKM_RSA_AES_KEY_WRAP` only *after* WS-1.1, or Rust will faithfully reproduce the C++ OAEP bug.

### 6.5 — XMSS-MT constants (32) vs bridge dispatch (56)

`rust/src/crypto/xmss_bridge.rs:187-244` dispatches all **56** RFC 8391 OIDs; `rust/src/constants.rs:1025-1059` names only **32** (`CKP_XMSSMT_*` `0x01`–`0x20`). OIDs 33–56 (SHA2-192 and SHAKE256 sets) work if a caller passes the raw number but have no named constant — a latent naming/validation asymmetry.

### 6.6 — C++ `CKM_EXTRACT_KEY_FROM_KEY` asymmetry

All three `CKM_CONCATENATE_*` are advertised and dispatched (`SoftHSM_keygen.cpp:6798-6800`); the inverse operation does not exist in either engine. You can join key material but not split it.

---

## WS-7 — Differential-harness depth (P2)

The cross-engine harness is the repo's best structural defence — it byte-compares two independent implementations, and it runs by default. It is currently shallow:

- Only **21 distinct `CKM_*`** across all 49 scenarios.
- **`C_Sign` appears once** (HMAC). **`C_Verify` appears nowhere.**
- `CKM_ML_DSA`, `CKM_SLH_DSA`, `CKM_XMSS`, `CKM_ECDSA*`, `CKM_EDDSA`, `CKM_RSA_PKCS*` are covered at **keygen + attribute readback only**.

Three `"__never_matches__"` entries are acknowledged **blind spots**, not verified parity: `LEGAL-KDF-COVERAGE`, `LEGAL-MESSAGE-BASED-SIGNING-FLAGS`, `LEGAL-XMSS-STATE-REPRESENTATION`.

**Fix:** add sign/verify scenarios for every PQC and classical signature mechanism both engines advertise; add a KDF-output scenario to retire `LEGAL-KDF-COVERAGE`. This is the cheapest durable guard against the *next* WS-1.1-class silent divergence — note that a cross-engine byte comparison would have caught the OAEP bug immediately.

---

## WS-8 — Secondary mechanism coverage (P3) — scoped by ACVP availability (D4)

**Inclusion rule (D4): implement every mechanism in this section for which NIST ACVP publishes vectors. Everything else is out of scope and is recorded as such.**

This is a principled line, not a convenience one: a mechanism we can prove correct against NIST vectors earns its permanent conformance obligation; one we could only ever self-test does not. It also means no mechanism enters the codebase without Tier-1 evidence arriving alongside it — implementation and KAT land in the same change, never separately.

### WS-8.0 — Prerequisite: confirm ACVP availability per mechanism

The table below is this plan's **best current assessment and must be verified before any implementation starts.** Availability was inferred from NIST's published algorithm families, *not* confirmed against the ACVP-Server tree. Confirm each row against `usnistgov/ACVP-Server` `gen-val/json-files/` at the release pinned by WS-0.4, and correct this table in place with the findings.

Do not start an IN row until its `internalProjection.json` has been located; do not close an OUT row until its absence has been confirmed rather than assumed.

### Assessed IN — ACVP vectors expected

| Mechanism | Expected ACVP algorithm | Note |
|---|---|---|
| `CKM_AES_CCM` | `ACVP-AES-CCM` | Real demand (IoT, TLS) |
| `CKM_AES_XTS`, `CKM_AES_XTS_KEY_GEN` | `ACVP-AES-XTS` | Real demand (storage encryption). **Dependency researched 2026-08-29 — see below.** |
| `CKM_AES_OFB` | `ACVP-AES-OFB` | |
| `CKM_AES_CFB1`, `_CFB8`, `_CFB128` | `ACVP-AES-CFB1` / `-CFB8` / `-CFB128` | NIST defines exactly these three widths |
| `CKM_AES_GMAC` | `ACVP-AES-GMAC` | |
| `CKM_SP800_108_DOUBLE_PIPELINE_KDF` | `KDF` (double-pipeline mode) | Completes the SP 800-108 trio; counter + feedback already present |
| `CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS` | `ACVP-ECDSA-keyGen` (extra-bits secret-generation mode) | Verify the mode is actually published |
| `CKM_ECMQV_DERIVE` | `KAS-ECC` (MQV schemes) | Verify MQV schemes are published, not just ephemeralUnified |

### Assessed OUT — no NIST ACVP vectors expected

| Mechanism | Why no ACVP |
|---|---|
| `CKM_AES_CFB64` | Not a NIST-defined AES mode (NIST specifies CFB1/8/128 only) |
| `CKM_AES_CTS` | SP 800-38A **Addendum**; ACVP coverage doubtful — verify before excluding |
| `CKM_AES_MAC`, `CKM_AES_MAC_GENERAL` | CBC-MAC; superseded by CMAC, no ACVP algorithm |
| `CKM_AES_XCBC_MAC`, `_XCBC_MAC_96` | RFC 3566, not a NIST algorithm |
| `CKM_AES_KEY_WRAP_PKCS7` | Not a NIST-defined wrap variant (`KW`/`KWP` are). Note this leaves a v3.2 §6.16.3 mechanism unimplemented — see caveat below |
| `CKM_ECDH_AES_KEY_WRAP`, `_COF_`, `_X_` | Composite PKCS#11 mechanisms; ACVP covers the components (`KAS-ECC` + `ACVP-AES-KW`) but not the composite |
| `CKM_SHAKE_128_KEY_DERIVATION` | PKCS#11 packaging of SHAKE; `ACVP-SHAKE-128` covers the XOF, not this derivation mechanism |
| `CKM_HKDF_DATA`, `CKM_HKDF_KEY_GEN` | PKCS#11 packaging variants; `KDA-HKDF` covers the KDF itself |
| 12 × `CKM_SHA*_KEY_GEN` | Generic-secret generation, not an algorithm under test. Low impact anyway — `CKM_GENERIC_SECRET_KEY_GEN` covers the use case, and `kMacMechTable` sets `allowGenericSecret=true` for every HMAC row (`SoftHSM_sign.cpp:125-133`) |
| `CKM_EXTRACT_KEY_FROM_KEY` (WS-6.6) | Key-material slicing, no ACVP algorithm. **Reconsider separately** — its absence is a genuine asymmetry against the three implemented `CKM_CONCATENATE_*`, which is an argument independent of vector availability |

### C++ engine — investigated 2026-08-30 (WS-8, this session)

Confirmed real ACVP vectors exist for `CKM_AES_CCM`, `CKM_AES_OFB`,
`CKM_AES_CFB1/8/128`, `CKM_AES_GMAC`, `CKM_AES_XTS`
(`ACVP-AES-XTS-1.0`/`-2.0`), and `CKM_ECMQV_DERIVE` (`KAS-ECC-1.0` publishes
real `fullMqv`/`onePassMqv` scheme vectors — the earlier "verify MQV schemes
are published" open question above is now resolved: they are). C++ had
**zero** of these six/seven mechanisms implemented before this session (only
ECB/CBC/CTR/GCM existed on the cipher side, only HMAC/CMAC/KMAC on the MAC
side). CCM/OFB/CFB1/CFB8/CFB128/GMAC are done — real evidence, all passing
(see git history 2026-08-30). Two remain, assessed as follows:

- **`CKM_AES_XTS`**: being implemented now (double-length `CKK_AES_XTS` key
  type; every file that currently gates on `keyType == CKK_AES` — object
  attribute validation, check-value computation, cipher key-length
  validation — hard-assumes single-length 128/192/256-bit AES keys and needs
  a parallel path for XTS's 256/512-bit combined keys).
- **`CKM_ECMQV_DERIVE`**: **deliberately not implemented.** ACVP vectors
  exist, but OpenSSL's EVP API exposes no MQV primitive at all — PKCS#11
  full-MQV requires the raw private-key scalar (extractable via
  `EVP_PKEY_get_bn_param(..., OSSL_PKEY_PARAM_PRIV_KEY, ...)`, itself a
  lower-level escape hatch), the SP 800-56A "associate value function," and
  hand-driven `EC_POINT`/`BN_*` point addition and scalar multiplication to
  combine two key pairs (static + ephemeral) on each side. This is a
  different risk class from every other WS-8 mechanism: a subtly wrong MQV
  combiner can pass every KAT it's tested against while still being
  cryptographically unsound (e.g. missing the standard's required public-key
  validation / small-subgroup checks), in a way ACVP functional vectors
  alone won't necessarily surface. Explicit user decision 2026-08-30: skip,
  document as a real blocker rather than attempt it under this session's
  general evidence-first methodology, which is calibrated for functional
  correctness, not for auditing a hand-rolled cryptographic protocol.

### Rust dependency research (2026-08-29) — `CKM_AES_XTS`

Unlike CCM/OFB/CFB (all covered by well-known RustCrypto `block-modes`/`AEADs` crates already used elsewhere in this codebase's dependency family), **RustCrypto has no working XTS implementation**, despite appearances:

- RustCrypto reserved the crate name `xts` (owned by Artyom Pavlov / `newpavlov`, a core RustCrypto maintainer) — but it has sat at version **`0.0.0`, unstable, unreleased since 2019-10-14**. Not viable; do not depend on it.
- The only real, currently-maintained option is the **third-party `xts-mode` crate** (`github.com/pheki/xts-mode`): MIT licensed, actively maintained (**v0.6.0, released 2026-05-05** — current), genuinely built on the same RustCrypto `cipher` trait ecosystem already in this project's dependency tree (works directly with the existing `aes` crate, no new cipher implementation pulled in), and reasonably established (**#166 in the Cryptography category on crates.io, ~240,860 downloads/month**).
- Caveats to weigh, not silently accept: it states plainly that it **has never been independently audited**, and (like every XTS implementation, including OpenSSL's — this is a property of the *mode*, not this crate) it carries **no authentication tag**, so an adversary with write access to ciphertext can undetectably randomize whole blocks. This is expected and standard for disk-sector encryption (the addressable unit's integrity is normally handled at a layer above XTS), not a defect specific to this crate — but the "never audited" point is real and independent of that.

**Recommendation:** use `xts-mode` — it is the only currently viable option, not a compromise pick among several. Flag the "never independently audited" status explicitly in the implementation commit and in the catalog entry (below) rather than treating it as equivalent to the already-vetted RustCrypto PQC crates. If an audited, RustCrypto-native XTS ever ships, migrate to it — leave a tracking note in the code (not a TODO with no owner) pointing at this section.

### Caveat to record, not to silently accept

Two OUT rows are worth flagging to whoever reviews this scope rule, because vector availability and spec obligation diverge:

- **`CKM_AES_KEY_WRAP_PKCS7`** is named by v3.2 §6.16.3 *alongside* `KWP` as a replacement for the deprecated `_PAD`. Excluding it on ACVP grounds is defensible, but it means the engine implements only two of the three names the spec offers for padded key wrap.
- **`CKM_EXTRACT_KEY_FROM_KEY`** is the inverse of an operation we do implement three variants of.

Neither is a defect. Both are scope decisions that should be **written down in the conformance documentation** so their absence reads as intentional rather than overlooked — the same standard WS-0.7 applies to the ctest PQC gap.

---

## WS-9 — Already tracked / explicitly not gaps (do NOT re-investigate)

### Open, tracked defects (3)

All Rust-side, sharing root cause **plan item E5** (Rust stores asymmetric keys as an engine-internal blob under `CKA_VALUE`):

1. `DEFECT-RUST-WRAPPED-PRIVATE-KEY-NOT-PKCS8` — `exceptions.json:27-35`. 72 B vs C++'s correct 152 B. Plan item E6, blocked on E5.
2. `DEFECT-RUST-EC-PARAMS-ABSENT-ON-UNWRAPPED-PRIVATE` — `:100-108`. Blocked on #1.
3. `DEFECT-RUST-CKA_VALUE-ON-ASYMMETRIC-KEYS` — `:217-224`. **WS-1.2 splits the sensitivity violation out of this entry**; the attribute-presence residue stays here.

### Adjudicated `legal` — not gaps

The entire **SHA-1 and SHA-224 families** plus MD5 (`LEGAL-WEAK-PRIMITIVES-ABSENT-IN-RUST` — deliberate omission of weak primitives from a PQC engine); the 47-mechanism C++/Rust set difference wholesale (`LEGAL-MECHANISM-SET` — legal *only* because neither engine claims Profiles §5.2 Complete Provider); brainpool curves; `CKA_PUBLIC_KEY_INFO`; usage-flag defaults.

### Checked and cleared (each looked like a gap and is not — recorded so nobody re-chases them)

- `CKM_KECCAK_256` and `CKM_PQCTODAY_SPLIT_KEY` are Rust-only **by design** and correctly not advertised in C++ (`SoftHSM_slots.cpp:609-611`, `SoftHSM_digest.cpp:113-116`, `vendor_mechanisms.h:17-29`).
- `CKM_ECDH1_COFACTOR_DERIVE` genuinely enables cofactor mode (`crypto/OSSLECDH.cpp:273`), not a silent alias.
- `CKM_HASH_ML_DSA`/`CKM_HASH_SLH_DSA` rejecting SHAKE in `hctx->hash` (`SoftHSM_sign.cpp:928-931`, `:1000-1003`) is **correct** — PKCS#11 defines no SHAKE *digest* mechanism ID to name there.
- `CKM_KMAC_128/256` in the vendor range is honest: v3.2 defines no KMAC mechanism (confirmed against `docs/refs/pkcs11t-canonical-v3.2.h`).
- `CKM_RSA_X_509` Sign/VerifyRecover is real (`SoftHSM_sign.cpp:1911`); the `CKR_FUNCTION_NOT_SUPPORTED` at `:3976` is inside a commented-out block.
- `CKM_ECDSA_KEY_PAIR_GEN` is a deprecated **alias** sharing value `0x1040` with `CKM_EC_KEY_PAIR_GEN` (`pkcs11t.h:1048-1049`) — advertised.
- The three hybrid KEM groups (X25519MLKEM768 / SecP256r1MLKEM768 / SecP384r1MLKEM1024) have **no `CKM_*` codepoint at all** and live in `rust/src/native/hybrid.rs:29-33`, reached via KMIP/CACP — exactly as `CLAUDE.md:47-53` describes. Not a C++ gap.
- **No header drift:** `src/lib/pkcs11/pkcs11t.h` matches `docs/refs/pkcs11t-canonical-v3.2.h` on all 473 standard `CKM_*` values, adding only 7 vendor-range extensions.
- All ML-DSA (3), ML-KEM (3) and SLH-DSA (12) parameter sets map completely (`crypto/OSSLMLDSA.cpp:587-589`, `OSSLMLKEMPublicKey.cpp:47-49`, `OSSLSLHDSA.cpp:254-265`).
- `C_DigestKey` returning `CKR_FUNCTION_NOT_SUPPORTED` unconditionally (`ffi.rs:11575-11579`) is spec-legal.

---

## WS-10 — Provider-layer mechanism exposure (P-8, after engine-level gaps close)

**Directive (2026-08-30): close the engine-level gaps for both C++ and Rust, cross-check the two engines against each other, and only then update every downstream provider (Java, OpenSSL, others) to expose those changes.** This workstream is that last step — deliberately sequenced after WS-0 through WS-8, not alongside them, per that direction.

**Rationale:** a mechanism fixed or added at the PKCS#11 engine level is invisible to real callers until the layer they actually call into is updated to reach it. An investigation on 2026-08-30 checked all 6 provider/consumer components in this repo against the 4 mechanisms WS-1 and the merged `fix/acvp-hmac-general-aes-kwp` branch (§12) already fixed at the engine level: `CKM_*_HMAC_GENERAL`, `CKM_AES_KEY_WRAP_KWP`, RSA-OAEP caller-selectable hash, `CK_EDDSA_PARAMS` (context/prehash).

### 10.1 — JavaJCE: 3 of 4 mechanisms not registered

| Mechanism | Status | Fix |
|---|---|---|
| `CKM_*_HMAC_GENERAL` | Not registered. Only plain HMAC is wired (`SoftHSMv3Provider.java:801-808`); `P11Constants.java` has no `_HMAC_GENERAL` constants; `P11MacSpi.engineInit` (`P11MacSpi.java:44-47`) rejects any non-null param outright. | Reuse the parameterized-mechanism path already proven for RSA-PSS (`P11Library.java:481`) with a `CK_MAC_GENERAL_PARAMS`-shaped param object. Small-moderate. |
| `CKM_AES_KEY_WRAP_KWP` | Not registered — only the deprecated `CKM_AES_KEY_WRAP_PAD` name is wired (`SoftHSMv3Provider.java:786-787`). `P11AESWrapCipherSpi` is already generic on mechType. | Add the constant + one `registerAESWrap(...)` line. Trivial. |
| `CK_EDDSA_PARAMS` (context/prehash) | Not registered — only plain `CKM_EDDSA` is wired (`:631-632`); `P11PureSigSignatureSpi.engineSetParameter` (`P11PureSigSignatureSpi.java:111-116`) unconditionally throws on any non-null param. | New params class (JDK has no standard one to reuse), new signature-instance variants for Ed25519ph/ctx/Ed448ph, wire through the existing parameterized-mechanism path. The one genuine architectural item — bounded, not deep. |
| RSA-OAEP hash selection | **Already fully exposed** — one `Cipher` service per (digest, MGF) pair, including SHA-3, per a prior documented fix (`:751-756`). | Nothing to do. |

### 10.2 — OpenSSL provider (`src/vendor/pkcs11-provider`): mixed, one item already tracked, one new

**Not unmodified vendor code** — 18 commits of real PQC patches sit on top of upstream (`git log --oneline -- src/vendor/pkcs11-provider`). It also does not do fully dynamic mechanism discovery: `operations_init()` (`provider.c:904-923`) probes a fixed, compiled-in `checklist[]` (`:835-865`) — anything outside that list is invisible regardless of what the token advertises.

| Mechanism | Status | Fix |
|---|---|---|
| HMAC (plain or general) | **No implementation exists at all** — no `mac.c` anywhere in `src/vendor/pkcs11-provider/src/`; `p11prov_query_operation()`'s switch has no `case OSSL_OP_MAC:`. | Already scoped in `docs/openssl-provider-remediation-plan-2026-08-25.md:91`, item **R8**, effort M — unbuilt. No new tracking needed, just build it. |
| AES key wrap (any variant, incl. KWP) | **No implementation exists**, and unlike HMAC **not yet in that plan at all** (grepped every phase doc for "wrap"/"KWP" — zero hits). `checklist[]` omits it; `cipher.c` has zero mentions of "wrap". | **New item — add to the openssl-provider-remediation plan.** |
| RSA-OAEP hash selection | **Already fully dynamic** — `asymmetric_cipher.c:642-669` reads `OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST` straight into `CK_RSA_PKCS_OAEP_PARAMS.hashAlg`. Tracked DONE at `openssl-provider-remediation-plan-2026-08-25.md:69`, item R0.5 — was waiting only on the engine-side SHA-1 hardcode WS-1.1 just removed. | Nothing to do. |
| `CK_EDDSA_PARAMS` (context/prehash) | **Already fully implemented** — `sig/eddsa.c:255-339,540-560` builds `phFlag`/`pContextData`/`ulContextDataLen` from real OpenSSL params, dispatch tables for Ed25519/Ed25519ph/Ed25519ctx/Ed448/Ed448ph. Built anticipating the engine fix WS-1.3 just landed. | Nothing to do. |

### 10.3 — Consumers needing no change: openssh-pkcs11, openpgp, openmls-provider

Genuine PKCS#11 consumers (call into a token, don't define a new crypto-provider surface) whose actual use cases don't touch any of the 4 mechanisms:
- **`openssh-pkcs11/`** — sign-only SSH auth; its only mechanism-specific code is unrelated PQC key-type patches (`patches/apply_mldsa_patches.py`).
- **`openpgp/`** — uses the `cryptoki` crate's typed `Mechanism` enum directly; deliberately pure EdDSA (RFC 9580's Ed25519 legacy type doesn't need context/prehash), plain RSA PKCS#1v1.5 (not OAEP, matching OpenPGP's wire format), no HMAC/AES-wrap usage.
- **`openmls-provider/`** — needs full-length HMAC only (its HKDF construction, `crypto.rs:100-148`, needs the full digest, not truncated), pure EdDSA only (RFC 9420 doesn't need context/prehash). No AES-wrap or OAEP usage.

### 10.4 — strongswan-pkcs11: one small optional gap

`pkcs11_encryption_scheme_to_mech()` (`pkcs11_private_key.c:376-394`) hardcodes RSA-OAEP to SHA-1 with `NULL, 0` params — no `CK_RSA_PKCS_OAEP_PARAMS` is ever constructed, so this plugin cannot select a hash today even though the engine now supports it (upstream strongSwan's own scheme enum already has the SHA-224/256/384/512 OAEP variants — `strongswan-6.0.5-pqc.patch:179` — just not wired here). Small, well-scoped fix if desired. No HMAC/AES-wrap/EdDSA usage in this plugin at all.

### 10.5 — Ties into WS-1.4: openmls-provider CI failures explained

The `openmls-provider` GitHub Actions job ("Check / Test / Clippy") has been failing on `main` independent of today's changes — HKDF/HMAC integration tests panicking with `CryptoLibraryError`. Root cause: its test fixtures use RFC 4231 §4.2 / RFC 5869 §A.1's own canonical short keys (20 B / 13 B — `openmls-provider/lib/tests/integration.rs:147-172`, SHA-384 equivalents at `:757-849`), shorter than this engine's HMAC key-size floor (`kMacMechTable`'s `minKeyBytes`, `SoftHSM_sign.cpp:146-163` — 32/48/64 bytes by hash). `C_SignInit` returns `CKR_KEY_SIZE_RANGE`, surfaced by `cryptoki`'s Rust binding as the observed panic. Same floor already flagged as an open question in **WS-1.4** — this shows it's not just a test-vector-selection nuisance for this repo's own suite, it's **actively breaking a real downstream consumer's standard-RFC vectors today**. Raises WS-1.4's priority; does not change its "investigate before changing" instruction.

---

## 10. Recommended execution order

| Phase | Contents | Rationale |
|---|---|---|
| **P-0** (D1) | Merge `fix/acvp-hmac-general-aes-kwp` (§12), then unblock and land `feat/jdk27-jca-provider` (63 commits) behind it | Both are complete and verified. Closes 10 gaps, fixes a *failing* KAT, and establishes the provenance format this plan makes normative |
| **P-1** | WS-0 (all) | Nothing downstream is trustworthy until harnesses stop lying and self-generated vectors are purged |
| **P-2** | WS-1.1, WS-1.2, WS-1.3, WS-1.4 | Silent wrong answers and a key-material exposure. Ship independent of coverage work. WS-1.4 is investigation-only and can run in parallel |
| **P-3** | WS-2, including 2.4's full fixup scope (D6) | Unlocks ~16 ACVP suites for Rust — largest evidence gain per unit effort in the plan. Treat whatever 2.4 exposes as in-scope for this phase, not deferred |
| **P-4** | WS-4 + WS-3.1, WS-3.2, WS-3.3, WS-3.5 | Vectors already on disk; flagship PQC evidence |
| **P-5** | WS-5, WS-6.1, WS-6.2, WS-6.3 | Classical evidence, then the claimed-feature parity gaps |
| **P-6** | WS-7, WS-3.4, WS-3.6, WS-6.4, WS-6.5, WS-6.6 | Structural depth and remaining parity |
| **P-7** | WS-8 | Roadmap-gated; implement against demand only |
| **P-8** (2026-08-30 directive) | WS-10 — JavaJCE (3 items), OpenSSL provider (1 already-tracked build, 1 newly-added item), strongSwan (1 optional) | Runs **after** P-1 through P-7 close the engine-level gaps and both engines are cross-checked (WS-7) — a provider update built on an unfinished engine fix would need redoing |

---

## 11. Global acceptance criteria

This plan is complete when **all** hold:

1. Every mechanism either (a) carries Tier-1/2/3 KAT evidence exercised **through the PKCS#11 ABI**, or (b) is explicitly recorded as out of scope with a written reason.
2. `tests/acvp/` contains **zero** self-generated vectors; every file has a re-verifiable `_provenance` block; WS-0.4's gate enforces this on every run.
3. No harness can exit green while testing nothing (WS-0.1, WS-0.2), verified by deliberate sabotage.
4. The ACVP corpus runs against **both** engines by default.
5. The two silent-wrong-answer defects are fixed, each with a KAT **and** a negative test that fails when the bug is reintroduced.
6. Coverage numbers replacing §0's table are computed by a script, not asserted by hand.
7. Every remaining divergence between the engines is either fixed or has a **citation-backed** `exceptions.json` entry.

**Standing rule:** no item closes on a round-trip, a reachability probe, or a direct-library test that bypasses the PKCS#11 dispatch. Those are the exact three patterns that let this gap set accumulate.

---

## 12. Dependency: `fix/acvp-hmac-general-aes-kwp`

Local branch, 4 commits (`cbced0b`, `6764463`, `ad6009d`, `1dbe8b6`), **not** an ancestor of `dea9bfa`. It:

- Re-sources 4 vectors from real NIST ACVP at pinned commit `975de31`, each `source_sha256`-verified — **replacing self-generated ones** — and establishes the `_provenance` format §1 makes normative.
- Fixes the currently-**failing** AES-CBC decrypt KAT (`main` is red on this today: `pt`=64 B vs `ct`=80 B, arithmetically impossible under raw CBC).
- Implements the full `CKM_*_HMAC_GENERAL` family (SHA-1/224/256/384/512, SHA3 ×4, MD5, RIPEMD-160), fail-closed, with an independent OpenSSL oracle.
- Adds `CKM_AES_KEY_WRAP_KWP`, the current v3.2 §6.16.3 name for RFC 5649 (previously reachable only under the deprecated `_PAD` name).
- Moves `cpp_compliance_report` from 779P/0F/36S to **864P/0F/37S**; ACVP 129P/1F/4S → **134P/0F/0S**.

**One open judgment call it surfaced (now D2 → WS-1.4):** this engine requires ≥48-byte keys for SHA-384 HMAC — **stricter than the spec's own suggested FIPS-198 floor of 24** (v3.2 §6.23.3) — which rejects roughly a third of NIST's own SHA-384 HMAC test cases. The branch worked around it by selecting a compliant vector (tcId 25) rather than silently relaxing a key-size floor, which was the right call for a test fix. Per **D2 the floor is to be investigated, not changed** — see WS-1.4. The branch merges as-is; the workaround stands until that investigation reports.

---

## 13. Risks

| Risk | Mitigation |
|---|---|
| ACVP `internalProjection.json` files are large; wholesale vendoring bloats the repo | Extract only the selected `tgId`/`tcId` cases, as `fix/acvp-hmac-general-aes-kwp` does — but always record the **full source file's** `source_sha256` so the extraction stays auditable |
| ACVP-Server rewrites history / moves paths | Pin by commit SHA (never `main`); WS-0.4's re-fetch check surfaces breakage immediately |
| Adding mechanisms enlarges the conformance surface permanently | WS-8 is demand-gated; prefer evidence for what is already advertised over new mechanisms |
| WS-2 exposes many latent Rust failures at once | **(D6)** Land WS-2 on its own branch; fix everything it surfaces before merging rather than deferring — expect real defects, that is the point, and the scope is accepted as open-ended in advance |
| Continuous execution (D5) drifts scope or quality without a human checkpoint between phases | Every workstream still carries its own file:line citations and acceptance criteria; "continuous" means not pausing between phases for permission, not skipping verification within a phase. Genuine blockers (a WS-8.0 availability question, an ambiguous finding) still surface immediately rather than being guessed past |
| Fixing WS-1.1 breaks callers depending on today's SHA-1 behaviour | **D3: hard fix, no transitional flag.** Already non-interoperable with any conforming module. Document as a breaking fix in `CHANGELOG.md`, stating that blobs wrapped under a non-SHA-1 `hashAlg` by an earlier build were actually SHA-1 and need re-wrapping |
| WS-8's ACVP-availability rule (D4) silently drops a spec-named mechanism | `CKM_AES_KEY_WRAP_PKCS7` and `CKM_EXTRACT_KEY_FROM_KEY` are excluded on vector-availability grounds despite independent arguments for them. Both are flagged in §WS-8 and **must be written into the conformance documentation** as intentional scope decisions, not left as silent absences |
| WS-8.0's ACVP-availability table is an assessment, not a verified fact | Every IN/OUT row is explicitly marked as requiring confirmation against the pinned ACVP-Server tree before work starts. Do not implement from the table as written |
| A "gap" here is wrong and wastes effort | Every claim carries a `file:line`. Re-verify against source before starting an item — and treat §WS-9 as binding on what *not* to re-investigate |
