# `softhsmv3-jce` security posture — FIPS 140-3 area mapping

Companion to
[`implementation-plan-jdk27-jca-provider-2026-08-24.md`](implementation-plan-jdk27-jca-provider-2026-08-24.md)
(the full build record — every decision's rationale and live-verification
result lives there; this document is the section-by-section summary the
plan's §6 called for). Written 2026-08-25, against the implementation as
of commit `233aa3e`.

## Scope and what this document is NOT

**This is not a CMVP submission, a security policy document in the
FIPS 140-3 Implementation Guidance sense, or a claim of validation.**
`softhsmv3-jce` has not been submitted for testing and no such submission
is planned as part of this work. This document exists to honestly map
what the plan's §6 operational-posture items actually do against the
eleven FIPS 140-3 requirement areas (per ISO/IEC 19790:2012 clause 7,
which FIPS 140-3 adopts), so a reader evaluating this module for a real
FIPS-adjacent use case can see exactly what's addressed, what's
partially addressed, and what's explicitly out of scope — rather than a
vague "FIPS 140-3 L3 posture" claim with no way to check it.

`softhsmv3-jce` is a **software** JCA provider bridging to a software
PKCS#11 token (`softhsmv3`, itself unvalidated). Several requirement
areas are inherently unaddressable by a software module at any
meaningful assurance level (physical tamper evidence, most of
non-invasive-attack mitigation) — those are marked N/A below, not
silently omitted.

## Area-by-area mapping

| # | FIPS 140-3 area | Status | This module |
|---|---|---|---|
| 1 | Cryptographic Module Specification | **Addressed** | The approved-algorithm boundary is real and enforced: plan §5's exclusion list (SHA-1/MD5/RIPEMD-160/Keccak-256, raw RSA as a cipher, ChaCha20, AES-ECB, X25519/X448, BIP32, standalone CONCATENATE/SHAKE-256-KDF, HSS/XMSS/XMSS-MT) is enforced by never registering a JCA `Service` for these names — verified by reading `SoftHSMv3Provider#registerServices()` end to end, not assumed (see the plan's §5 audit entry, which also disclosed that this is enforcement-by-omission, not a separate runtime allow/deny layer, correcting the plan's own earlier wording). `ExcludedMechanismsTest` is the regression guard. |
| 2 | Cryptographic Module Interfaces | **Addressed** | `P11Error` maps every `CK_RV` the module returns to a specific JCA exception with the CKR name preserved in the message — no return code is ever silently ignored (this repo's standing audit discipline, applied here from W1 onward). Input/output data paths are the standard JCA method surfaces (`Cipher`/`Signature`/`KeyPairGenerator`/etc.); there is no undocumented side channel. |
| 3 | Roles, Services, and Authentication | **Partially addressed** | `SoftHSMv3Provider extends AuthProvider` with real `login()`/`logout()`/`setCallbackHandler()` (identity-based, PIN via `CallbackHandler`/`PasswordCallback`, not hardcoded — plan's §6.1 entry). This is the `CKU_USER` role only: the engine's own SO role exists (`CKU_SO`), but this provider never authenticates as SO and has no code path that does — a real, disclosed scope boundary (see the certificate-management work's own finding on `CKA_TRUSTED` being SO-gated and therefore unreachable from this provider). No multi-factor authentication; PIN-only, matching Level 2/3's "role-based or identity-based operator authentication" rather than Level 4's multi-factor requirement. |
| 4 | Software/Firmware Security | **Not addressed** | No integrity check (signed jar, checksum verification, or equivalent) is performed on this module's own class files at load time. Out of scope for this plan; would need its own design (code signing key management, verification hook placement) before any claim here. |
| 5 | Operational Environment | **N/A / not addressed** | Runs inside a general-purpose JVM on a general-purpose OS — not a "limited" or "modifiable" operational environment in the FIPS 140-3 sense, and no role-based OS-level access control or audit mechanism is provided by this module. This area is inherently the deploying application's/OS's responsibility, not this provider's. |
| 6 | Physical Security | **N/A** | Software module — no physical enclosure, tamper evidence, or tamper response exists to evaluate. Genuinely unclaimable for software, stated plainly rather than hand-waved (this is exactly why the plan describes the target as the L3 *operational profile*, not L3 certification). |
| 7 | Non-Invasive Security | **Not addressed** | No mitigation against non-invasive attacks (power analysis, timing side channels, electromagnetic analysis per Annex F) has been designed or tested for in this module. A real, open gap for anyone using this in a threat model where such attacks are in scope — this module's timing characteristics have not been analyzed. |
| 8 | Sensitive Security Parameter (SSP) Management | **Substantially addressed, one disclosed gap remains** | Generated private/secret keys are opaque handles — `getEncoded()` returns `null` unconditionally, key material never crosses into the JVM by design (plan §6.2). `Destroyable` is implemented on every key type, `destroy()` genuinely issues `C_DestroyObject`. The two places genuine plaintext secret material *does* pass through the JVM (ML-KEM's decapsulated secret, ECDH's derived secret — both deliberate, necessary exceptions, since the whole point of a KEM/key-agreement output is to be usable off-token) now explicitly zero their intermediate `byte[]` copies once safely superseded by a defensively-cloned `SecretKeySpec`, verified live via a real heap-dump scan (`ZeroizationAuditTest`), not just code review. **Open gap, disclosed in the plan's zeroization-audit entry:** the native FFM layer (`P11Library`) currently allocates from one `Arena.ofShared()` for a session's entire lifetime rather than confined per-operation arenas with an explicit zero-fill pass before release — every native buffer that ever carried key material, mechanism parameters, or plaintext stays allocated (though not Java-heap-visible) until the whole session closes. Not fixed as part of this plan; needs its own scoped pass. |
| 9 | Self-Tests | **Addressed** | Full pre-operational POST battery runs before any service is exposed (plan §6.3): SHA-256, HMAC-SHA-256, and AES-GCM known-answer tests against real published vectors (FIPS 180-4; RFC 4231 Test Case 6; the original GCM specification's Appendix B Test Case 2, the paper NIST adopted as SP 800-38D's normative source); a DRBG sanity check; and a pairwise-consistency (generate → sign/encapsulate → verify/decapsulate) check for every asymmetric family (ML-DSA-65, SLH-DSA-SHA2-128S, ECDSA-P256, Ed25519, RSA-PSS, ML-KEM-768) — pairwise consistency rather than a fixed-vector KAT for these six specifically because a true fixed KAT would require importing a specific private key, which this provider refuses as policy (FIPS 140-3 IG 10.3.A's accepted substitute for exactly this situation). Any failure closes the session and throws out of the constructor — no caller can obtain a live reference to a provider whose POST failed, so it fails closed by construction, not by a checked flag. |
| 10 | Life-Cycle Assurance | **Partially addressed, informally** | No formal configuration management system, annotated source/design documentation set, or finite-state model exists for this module in the ISO/IEC 19790 sense. What *does* exist, informally: every design decision in this plan is documented with its rationale and live-verification evidence (the plan document itself functions as a lightweight, human-readable design record), and every change ships with a real, passing test suite (198/198 as of this document) run against the live engine, not mocked. This is real engineering discipline, not a substitute for the formal life-cycle assurance artifacts CMVP testing would require. |
| 11 | Mitigation of Other Attacks | **Not addressed** | No attacks outside the standard cryptographic threat model have been specifically identified, designed against, or documented as mitigated. |

## Bottom line

Areas 1, 2, 9 are genuinely, substantively addressed. Area 8 is
substantively addressed with one real, disclosed architectural gap
remaining (the Arena/zeroization item). Area 3 is addressed for the
`CKU_USER` role only. Areas 4, 5, 6, 7, 10, 11 are not addressed at a
level that would support any FIPS 140-3 area-specific claim — 5, 6, and
7 are largely inherent limitations of a software module rather than
things this plan chose to skip.

This adds up to a genuinely useful **operational security posture** for
a software PKCS#11-backed JCA provider — real fail-closed self-tests,
real opaque key handling, a real approved-algorithm boundary, real
`Destroyable`/zeroization work with one disclosed gap — but explicitly
**not** a certification-track security policy document, and this
document should not be represented as one.
