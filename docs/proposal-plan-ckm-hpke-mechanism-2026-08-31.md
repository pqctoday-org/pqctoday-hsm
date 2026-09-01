# Plan — CKM_HPKE mechanism specification proposal

**Date:** 2026-08-31
**Status:** Deliverable drafted — see
`docs/proposals/pkcs11-ckm-hpke-mechanism-proposal.md`. OQ1/OQ2/OQ3 (§6)
resolved by owner: pAdditionalDerivedKeys for the exporter key, an OPTIONAL
CKA_SEED-style seeding hook (owner overrode this plan's own "omit" leaning),
uniform CKK_HPKE_KEM for every suite. Phases 1-3 (§5) remain unexecuted,
gated on explicit approval.
**Decided inputs (owner, 2026-08-31):** deliverable = spec proposal document
only; engines (if/when implemented) = Rust first, C++ phase 2; API shape =
mechanism family under C_EncapsulateKey/C_DecapsulateKey (not one-shot, not a
stateful context object).

---

## 1. Problem statement

PKCS#11 v3.2 (ratified 2026-06) defines **no HPKE mechanism** — verified
against the canonical header (`docs/refs/pkcs11t-canonical-v3.2.h`: no HPKE
entry). The v3.3 working draft (snapshot:
`docs/refs/pkcs11-v3.3-draft-git-snapshot-20260828/`) adds `CKM_COMP_KEM`, but
that targets **draft-ietf-lamps-pq-composite-kem** (LAMPS WG, X.509-oriented,
KEM-only) — it covers neither RFC 9180's KeySchedule/AEAD/Export layers nor the
CFRG hybrid-KEM construction that **draft-ietf-hpke-pq** actually mandates.

The pqctoday-hub HPKE workshop
(`pqctoday-hub/src/components/PKILearning/modules/HybridCrypto/services/hpkeService.ts`)
proves HPKE **can** be composed from standard v3.2 primitives with full key
custody (no secret ever extractable): ~12 chained calls across
`CKM_ML_KEM`, `CKM_ECDH1_DERIVE`, `CKM_CONCATENATE_BASE_AND_KEY/_DATA`,
`CKM_SHA3_256_KEY_DERIVATION`, `CKM_HKDF_DERIVE` (incl. `CKF_HKDF_SALT_KEY`),
and the AEAD mechanisms — validated by 152 tests including a 54-case hybrid
cross-product with explicit non-extractability assertions. That composition is
the *evidence* for this proposal, and also its *motivation*: correctness
depends on the application getting a 12-step template-sensitive chain exactly
right. A native mechanism moves that responsibility inside the token boundary,
the same argument the v3.3 draft makes for `CKM_COMP_KEM`.

## 2. Goals

- G1: A mechanism-definition document, written in the **style and structure of
  the v3.3 working draft's own mechanism files** (model:
  `working/doc/spec/comp_kem.md` in the snapshot), defining a `CKM_HPKE`
  mechanism family for PKCS#11.
- G2: Fit for two audiences: (a) internal — the design contract a Phase-1 Rust
  implementation would build against; (b) external — submittable as public
  feedback to the OASIS PKCS#11 TC (github.com/oasis-tcs/pkcs11, OASIS
  Feedback License; see snapshot `CONTRIBUTING.md`).
- G3: Full key custody by construction: shared secrets, KeySchedule
  intermediates, and the AEAD key never exist outside the token; only
  `base_nonce` (public) and exporter output (RFC 9180's own external API) leave.
- G4: Cover RFC 9180 completely at the suite level: all registered
  KEMs (0x0010–0x0021), KDFs (0x0001–0x0003), AEADs (0x0001–0x0003,
  0xFFFF export-only), all four modes — plus draft-ietf-hpke-pq's PQ and PQ/T
  hybrid KEM IDs (0x0040–0x0051, 0x647a) with their documented mode
  restrictions (no Auth for ML-KEM-based KEMs).

## Non-goals

- No stateful HPKE context object (no `CKO_HPKE_CONTEXT`, no in-token `seq`
  tracking) — per-message nonce construction stays with the caller, as it does
  for every existing PKCS#11 AEAD mechanism. Documented as a security
  consideration, not solved by new object types.
- No one-shot single-message convenience form (can be added later as
  `CKM_HPKE_SEAL` if ever wanted; out of scope).
- No implementation in this deliverable (Phases 1–2 are separately gated).
- Not a replacement for `CKM_COMP_KEM` and not an X.509/LAMPS mechanism —
  complementary, different target spec.

## 3. Deliverable: the spec proposal document

**File:** `docs/proposals/pkcs11-ckm-hpke-mechanism-proposal.md` (new
`docs/proposals/` directory; this repo's `docs/` currently mixes plans and
audits — proposals get their own home).

**Required sections** (mirroring `comp_kem.md`'s skeleton, plus what HPKE
additionally needs):

1. **Overview & normative references** — RFC 9180; draft-ietf-hpke-pq;
   draft-irtf-cfrg-hybrid-kems + draft-irtf-cfrg-concrete-hybrid-kems (the CG
   combiner the hybrid KEM IDs delegate to); relationship to v3.3
   `CKM_COMP_KEM` stated explicitly (different WG, different combiner — not
   interchangeable).
2. **Mechanisms vs. Functions table** —
   - `CKM_HPKE` — valid for `C_EncapsulateKey` (sender) and
     `C_DecapsulateKey` (recipient). One call = KEM (+hybrid combiner where
     applicable) + full KeySchedule, in-token.
   - `CKM_HPKE_KEM_KEY_PAIR_GEN` — `C_GenerateKeyPair` for recipient keys,
     parameter-set driven (see key objects below).
3. **Key objects** — `CKK_HPKE_KEM` public/private key objects with
   `CKA_PARAMETER_SET` (`CK_HPKE_KEM_PARAMETER_SET_TYPE`, values = RFC 9180 §7.1
   + hpke-pq KEM IDs, e.g. `CKP_HPKE_KEM_MLKEM768_P256` = 0x0050). Rationale to
   state in the doc: classical DHKEM recipients *could* reuse bare
   `CKK_EC`/`CKK_EC_MONTGOMERY` keys, but the hybrid KEMs force a composite key
   object (decap needs dk_PQ **and** dk_T behind ONE handle —
   `C_DecapsulateKey` has a single `hKey` argument), and a uniform key type
   across all suites is simpler and matches `CKM_COMP_KEM`'s `CKK_COMP_KEM`
   precedent. `CKA_VALUE` encodings = the RFC 9180 / CFRG serializations
   already implemented and size-verified in `hpkeService.ts`'s `KEM_TABLE`
   (`ek_H = ek_PQ ‖ ek_T`, PQ-first).
4. **`CK_HPKE_PARAMS` structure** — the core design. Proposed fields:
   - `kemId`, `kdfId`, `aeadId`, `mode` (`CK_ULONG` each; ids verbatim from
     RFC 9180 §7 / hpke-pq — the spec doc must NOT invent a parallel registry).
   - `hPsk` (`CK_OBJECT_HANDLE`, PSK/AuthPSK modes; **handle, not bytes** — a
     PSK is keying material and deserves the same custody as everything else;
     `CKF_HKDF_SALT_KEY` in v3.2 §6.62.3 is the precedent for
     key-by-handle-in-params) + `pPskId`/`ulPskIdLen` (bytes; public).
   - `pInfo`/`ulInfoLen` (bytes; public).
   - Auth modes: `hSenderStaticKey` (`CK_OBJECT_HANDLE`, sender side) /
     `pSenderPk`/`ulSenderPkLen` (bytes, recipient side).
   - `pEnc`/`pulEncLen` — out-buffer on `C_EncapsulateKey`
     (that's the function's own ciphertext output — for HPKE the `enc` value);
     in-buffer on `C_DecapsulateKey`.
   - `pBaseNonce` (out-buffer, `Nn` bytes — public value, fine as bytes).
   - `pExporterKey` (`CK_DERIVED_KEY *`, optional) — second derived key object
     for the exporter_secret, using the **existing v3.2 precedent** of
     `CK_SP800_108_KDF_PARAMS.pAdditionalDerivedKeys` (§6.42) for
     multi-key-output derivation. Template decides its extractability; RFC 9180
     Export() calls then run as plain `CKM_HKDF_DERIVE` expand-only against it
     (already correct in this repo's Rust engine since the 2026-08-31
     `Hkdf::from_prk` fix), or the exporter key stays non-extractable and
     Export runs in-token the same way.
   - Returned `phKey` from the function = the AEAD key (type
     `CKK_AES`/`CKK_CHACHA20` per `aeadId`), template-controlled, intended
     non-extractable. For export-only suites (`aeadId = 0xFFFF`) `phKey`
     returns the exporter key instead and `pExporterKey` must be NULL.
5. **Mechanism semantics** — normative step lists for Encapsulate and
   Decapsulate mapping exactly onto RFC 9180 §5.1 KeySchedule, §4.1 DHKEM,
   and (for 0x0040+) the CG-framework combiner
   `SHA3-256(ss_PQ ‖ ss_T ‖ ct_T ‖ ek_T ‖ Label)` with the concrete labels
   from draft-irtf-cfrg-concrete-hybrid-kems (incl. the 6-byte
   `5c2e2f2f5e5c` label for MLKEM768-X25519, given in hex per LAMPS's own
   transcription-safety practice). Mode-validity matrix: Auth/AuthPSK
   rejected with `CKR_MECHANISM_PARAM_INVALID` for ML-KEM-based KEM IDs.
6. **Attribute rules** — contributed attributes on the derived keys
   (`CKA_ALWAYS_SENSITIVE`/`CKA_NEVER_EXTRACTABLE` handling copied from v3.2
   §5.18.8's encapsulated-key rules), `CKA_ALLOWED_MECHANISMS` interaction,
   sensitivity defaults.
7. **Security considerations** —
   - Key custody: which values never leave the token (all secrets), which
     leave by design (`enc`, `base_nonce`, exporter output when templated
     extractable) — reusing the analysis already written into
     `hpkeService.ts`'s "Non-extracting hybrid path" header note.
   - Nonce/seq misuse: caller owns `base_nonce ⊕ seq`; state the risk and the
     mitigation pattern (same posture as CKM_AES_GCM today).
   - FIPS mapping: SP 800-56Cr2 One-Step KDM / SP 800-227 hybrid-combiner
     allowance, mirroring LAMPS composite-kem §10.1's certification argument.
   - Deterministic Encaps: byte-exact RFC 9180 test vectors need forced
     ephemeral keys / seeded ML-KEM.Encaps; specify an OPTIONAL
     vendor-testing-only extension or point at `CKA_SEED` (v3.2) — decision
     recorded in the doc's open-questions annex.
8. **Informative appendix: test vectors & existing evidence** — RFC 9180
   Appendix A.3 (all four modes, byte-exact — already vendored in
   `pqctoday-hub .../data/hpkeTestVectors.ts`) and the 54-case hybrid
   round-trip matrix as implementer's evidence, with the caveat that CFRG
   Appendix-A hybrid vectors require seeded Encaps.
9. **Provisional numbering annex** — spec text written number-agnostic
   ("values to be assigned by the TC"); for any interim implementation, use
   this repo's vendor range per `rust/src/constants.rs`'s allocation ledger
   (`CKM_VENDOR_DEFINED | n`, next free slot after `CKM_PQCTODAY_SPLIT_KEY =
   0x8000_0012` — confirm against the ledger at write time). This annex is the
   ONLY place vendor numbering appears; the proposal proper stays clean OASIS
   style.

**Sourcing rule for the doc:** every normative claim cross-checked against the
locally cached primary sources only — RFC 9180 cache, the two CFRG drafts
(fetched this session), hpke-pq, `pkcs11t-canonical-v3.2.h`, the v3.2 spec
PDF, and the v3.3 snapshot — no memory, no web re-derivation. (Established
session rule: verify standards facts against the authoritative source.)

## 4. Validation plan (for the document itself)

- V1: Field-by-field re-derivation of every size/ID table from RFC 9180 §7 +
  hpke-pq's KEM table (the session already caught one transcription bug this
  way — MLKEM1024-P384 Nenc/Npk 1601/1697 → 1665/1665; assume nothing carries
  over unchecked).
- V2: Style conformance pass against `comp_kem.md` (headings, table format,
  template examples, footnote references) so it reads as a drop-in TC file.
- V3: Dry-run the mechanism semantics on paper against the existing
  `hpkeService.ts` call sequence — every step in the normative list must map
  1:1 onto an operation the 152-test suite already proves works in-token.
  Divergence = spec bug or service bug; investigate, don't paper over.
- V4: Adversarial read of `CK_HPKE_PARAMS` for PKCS#11 ABI hygiene: no
  variable-size middle fields, 32/64-bit layout stated, every out-buffer with
  a length-query convention (`pulEncLen` NULL-buffer sizing like
  `C_EncapsulateKey` itself).

## 5. Follow-on phases (gated — NOT part of this deliverable)

- **Phase 1 (on explicit approval): Rust engine implementation.**
  `rust/src/ffi.rs` dispatch arms in `C_EncapsulateKey_impl`/
  `C_DecapsulateKey_impl` + `ck_param` struct; internals reuse the audited
  building blocks (ML-KEM encap, ECDH, HKDF incl. the fixed `from_prk` path,
  SHA3 combiner already mirrored in `native/hybrid.rs`); vendor IDs from the
  annex; regression tests mirroring the hub's 54-case matrix in-engine; WASM
  rebuild via `rust/build-wasm-bundle.sh` + sync to the hub's four vendored
  copies; hub workshop gains a "native CKM_HPKE vs. composed primitives"
  toggle — which becomes the teaching moment: same result, 3 calls vs 12.
- **Phase 2 (after Phase 1): C++ engine parity.** `SoftHSM_kem.cpp` path,
  same spec doc as contract; parity test = cross-engine KAT like
  `softhsm.cross-engine.kat.test.ts`.
- **Phase 3 (owner's call, external action): TC feedback submission** under
  the OASIS Feedback License. Never initiated without explicit owner OK —
  this is an outward-facing publication.

## 6. Open questions to resolve during drafting (flagged in the doc, not blockers)

- OQ1: exporter output — `pAdditionalDerivedKeys`-style second key (current
  proposal) vs. a distinct `CKM_HPKE_EXPORT` derive mechanism. Leaning first;
  fewer new mechanisms, existing precedent.
- OQ2: deterministic/test-vector mode — omit entirely vs. OPTIONAL `CKA_SEED`
  hook. Leaning omit from the normative text with an informative note.
- OQ3: whether classical-DHKEM recipients may ALSO present bare
  `CKK_EC`/`CKK_EC_MONTGOMERY` keys (implementation convenience) or MUST use
  `CKK_HPKE_KEM` (uniformity). Leaning MUST, with an import path.

## 7. Estimate

Spec proposal document: one focused session (the research is done — all
primary sources cached and already cross-verified this session; the hardest
part, the params-struct design, is settled above at plan level). V1–V4
validation adds ~30% on top of drafting.
