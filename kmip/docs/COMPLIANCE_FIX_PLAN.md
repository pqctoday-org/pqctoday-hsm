> **Historical record.** This fix plan is complete — see `CONFORMANCE_REPORT.md`
> and the root `CHANGELOG.md` for current standing. Kept for provenance.

# Compliance Fix Plan — pqctoday-kmip (KMIP 3.0 server + PKCS#11 bridge)

**Date**: 2026-06-10 · **Base branch**: `feat/kmip-conformance-round-2` (HEAD `7142333`)
**Source audit**: `docs/compliance-audit-kmip30-pkcs11v32-2026-06-10.md`
(findings `K-*` and `B-*`)
**Companion plan**: `docs/fix-plan-rust-pkcs11-v3.2-compliance.md` — engine
slices **S4** (CKR precision), **S6** (RSA hash variants), **S7** (PQC import)
are dependencies of K1, K6, K9 below.

Fourteen PR slices. Effort: S = ≤½ day, M = 1–2 days, L = multi-day.

## Standing acceptance gates (every slice)

1. `cargo test --test oasis_codec_roundtrip` — 124/124 pristine + 1234/1234 stubbed
2. Dispatcher replay harness — **92/92** (`conformance/REPLAY_REPORT.md`
   regenerated). Where a slice changes an emitted ResultReason, first check
   what the OASIS transcript actually expects: the corpus passed with the old
   codes, so per-transcript verification decides whether a change is safe or
   needs a harness-comparison note.
3. `manifest_consistency_test` (mech manifest sha256) when constants move
4. `kmip/docs/CONFORMANCE_REPORT.md` updated when posture changes

---

## K1 — Error model foundation (M) · findings B-3, K-3

Everything else builds on this; land first, together with engine slice S4.

1. **New `ResultReason` variants** (`src/error.rs:15-71`), values verified
   against `spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json`:
   `KeyFormatTypeNotSupported = 0x10`, `Sensitive = 0x16`,
   `NotExtractable = 0x17`, `InvalidDataType = 0x1c`,
   `UnsupportedCryptographicParameters = 0x3e`,
   `UnsupportedProtocolVersion = 0x3f`. Fix the `error.rs:36` comment
   misdescribing `ObjectArchived`.
2. **Full CKR→KmipError table** (`src/ops/helpers.rs:380-397`,
   `ck_rv_to_kmip_error`). Replace the 5-arm + catch-all with:

   | CK_RV | ResultReason |
   |---|---|
   | `CKR_KEY_FUNCTION_NOT_PERMITTED` | PermissionDenied (keep) |
   | `CKR_OBJECT_HANDLE_INVALID`, `CKR_KEY_HANDLE_INVALID`, `CKR_WRAPPING_KEY_HANDLE_INVALID`, `CKR_UNWRAPPING_KEY_HANDLE_INVALID` | ObjectNotFound |
   | `CKR_MECHANISM_INVALID` | OperationNotSupported (keep) |
   | `CKR_MECHANISM_PARAM_INVALID` | UnsupportedCryptographicParameters |
   | `CKR_ARGUMENTS_BAD`, `CKR_DATA_LEN_RANGE`, `CKR_KEY_SIZE_RANGE` | InvalidField |
   | `CKR_TEMPLATE_INCOMPLETE`, `CKR_TEMPLATE_INCONSISTENT`, `CKR_ATTRIBUTE_VALUE_INVALID` | InvalidAttributeValue |
   | `CKR_PIN_*`, `CKR_USER_NOT_LOGGED_IN` | AuthenticationNotSuccessful |
   | `CKR_KEY_TYPE_INCONSISTENT` | InvalidField |
   | `CKR_ENCRYPTED_DATA_INVALID`, `CKR_WRAPPED_KEY_INVALID`, `CKR_SIGNATURE_INVALID` | CryptographicFailure |
   | `CKR_ATTRIBUTE_SENSITIVE` | Sensitive |
   | `CKR_KEY_UNEXTRACTABLE`, `CKR_KEY_NOT_WRAPPABLE` | NotExtractable |
   | `CKR_DEVICE_*`, `CKR_HOST_MEMORY`, `CKR_GENERAL_ERROR`, default | GeneralFailure (0x100) — **not** CryptographicFailure |

3. **UnsupportedProtocolVersion**: map `WireError::UnsupportedVersion`
   (`src/kmip30/wire.rs:343-348`, `src/server/listener.rs:223-236`) to the new
   0x3f reason instead of `InvalidMessage`.
4. **Bridge module decision** (K-17): `src/pkcs11bridge/{session,error,mechs}.rs`
   is dead code; `src/attrmap/mod.rs` is an empty stub. Delete both (the
   `native::*` typed path is the architecture) and remove the
   `KmipError::Bridge` variant, or wire `BridgeError::classify` into
   `result_reason()`. **Recommendation: delete** — one error path, not two.

**Tests**: unit table test asserting every named CKR maps as above; replay run.

## K2 — ResultReason precision sweep (M) · findings K-6, K-7, K-8

1. Add `KmipError::object_not_found` calls at every **managed-object UID**
   lookup failure (~20 sites): `ops/activate.rs:39`, `ops/revoke.rs:44`,
   `ops/destroy.rs:38`, `ops/lifecycle_and_protocol.rs:40/86/122/136/154`,
   `ops/encrypt.rs:47`, `ops/decrypt.rs:48`, `ops/sign.rs:54`,
   `ops/signature_verify.rs:52`, `ops/mac_and_hash.rs:38/79`,
   `ops/attribute_mutate.rs` (5 sites), `ops/get_attributes.rs:47`,
   `ops/get_attribute_list.rs:31`. Reserve `ItemNotFound` for non-object items.
2. Activate wrong-state (`ops/activate.rs:42-52`) and Deactivate wrong-state
   (`ops/lifecycle_and_protocol.rs:47-53`): `PermissionDenied` →
   `WrongKeyLifecycleState` (0x43, already in the enum at `error.rs:37`).
   Delete the stale Deactivate comment claiming the variant doesn't exist.
3. Destroy on already-Destroyed (`ops/destroy.rs:58-65`): `object_archived` →
   `object_destroyed` (0x36).

**Gate**: this is the slice most likely to interact with replay expectations —
run the harness per-step, not per-PR; document any transcript that pins the
old reason (none is expected to: the corpus error-path tests use Get, which
already emits the correct codes).

## K3 — Operation decode & truthful Query (M) · findings K-4, K-11

1. **Decode all 64 op codepoints**: extend `Operation::from_wire_value`
   (`src/kmip30/ops.rs:117-178`) with DeriveKey 0x05, Certify 0x06, Cancel
   0x19, ReKeyKeyPair 0x1d, JoinSplitKey 0x29, DelegatedLogin 0x2f,
   ReProvision 0x35, SetDefaults 0x36 (values from the enums JSON).
2. **Split "malformed" from "unsupported"**: in `src/kmip30/wire.rs:583-606`,
   a recognized op without a handler must produce
   `OperationNotSupported (0x05)`, not `WireError::UnknownEnum` →
   `InvalidMessage`. Mechanism: decode the payload as an opaque "unsupported"
   marker and let the dispatcher (`src/dispatcher/mod.rs:323-384`) return the
   failure, so Batch Error Continuation applies normally.
3. **Truthful Query** (`src/ops/query.rs:110-208`): trim
   `supported_operations()` / `supported_object_types()` to the dispatcher's
   real surface. Then re-run replay: any corpus transcript that requires an
   advertised op forces a decision — implement it or keep it listed **and**
   implemented; never advertised-but-rejected.
4. **QueryProfiles / QueryCapabilities** (`query.rs:85-90` no-ops): return
   honest CapabilityInformation (streaming ✓, async ✗, attestation ✗,
   batch-undo ✓) and an empty/explicit profile list pending K13's decision.

## K4 — Message-layer SHALLs (S) · findings K-1, K-2

1. **Asynchronous Indicator** (`src/kmip30/wire.rs:423-425`): decode; if
   `Mandatory (0x01)` fail every batch item with `OperationNotSupported` +
   message "asynchronous processing not supported"; `Optional` → proceed
   synchronously.
2. **Critical Message Extension** (`wire.rs:437-455`): decode
   `MessageExtension`; `CriticalityIndicator=true` with unrecognized
   `VendorIdentification` → fail the batch item (`InvalidMessage` per §9.x
   reject-rule); non-critical → skip as today.

**Tests**: two new wire-level tests; corpus unaffected (no transcript sets
either field — verify with a grep over `oasis_corpus/`).

## K5 — Vendor mechanism codepoint migration (S) · finding B-1

The 0x4032–0x4037 block collides with standard `CKM_HSS_KEY_PAIR_GEN`…
`CKM_XMSSMT` (`pkcs11t.h:1218-1224`) and violates the ≥`CKM_VENDOR_DEFINED`
(0x80000000) rule.

1. Replace the six `CKM_PQCTODAY_*` constants (`src/kmip30/algos.rs:36-41`)
   with the **standard** v3.2 codepoints the engine already uses:
   keygen → `CKM_ML_KEM_KEY_PAIR_GEN (0x0f)` / `CKM_ML_DSA_KEY_PAIR_GEN (0x1c)`
   / `CKM_SLH_DSA_KEY_PAIR_GEN (0x2d)`; sign/verify → `CKM_ML_DSA (0x1d)` /
   `CKM_SLH_DSA (0x2e)`; encapsulate → `CKM_ML_KEM (0x17)`.
   Fix SLH-DSA keygen mislabeled as HSS (`algos.rs:263-273`).
2. Anything genuinely vendor-specific (none currently — all six have standard
   equivalents) moves to `0x8000_0000 | n`. Reserve and document the new range.
3. Sync `pkcs11-mech-manifest.json`, the manifest sha256 in
   `manifest_consistency_test`, and
   `pqctoday-priv/docs/platform/data/pkcs11-vendor-mech-allocation.md`
   (cross-repo: separate PR there, landed together).
4. Audit-log consumers: grep `pqctoday-hub`/`pqctoday-admin` for the 0x403x
   literals before merging (cross-layer constants have bitten before — see
   memory note on TS/JS sync).

## K6 — End silent algorithm substitution (M) · finding B-2

Step 1 (no engine dependency): **fail instead of substitute.**

- `aes_mechanism_for` (`src/ops/helpers.rs:182-191`) returns
  `Result<CkMechanismType, KmipError>`: CTR (6) → `CKM_AES_CTR` (engine path
  already exists — streaming matcher at `ops/encrypt.rs:220-223` becomes
  reachable); CBC/ECB/GCM as today; CFB/OFB/PCBC/CCM/XTS/NISTKeyWrap-in-Encrypt
  → `UnsupportedCryptographicParameters (0x3e)`. Delete the
  "fall through to GCM" comment.
- RSA padding (`src/kmip30/algos.rs:285`): `PKCS1v1.5 (0x08)` →
  `CKM_RSA_PKCS`; `OAEP (0x0b)` → `CKM_RSA_PKCS_OAEP`; absent → keep OAEP
  default (document); anything else → 0x3e.
- OAEP hash map (`helpers.rs:204-211`): supported → use; unsupported
  (SHA-1/SHA-224/SHA3-*) → **error**, never default to SHA-256.
- `effective_cp` consistency: `ops/encrypt.rs:457` and `ops/decrypt.rs:191`
  must build OAEP params from the same request-over-object CP used for mech
  selection three lines earlier.
- Sign/verify hash: error on `HashingAlgorithm` ∉ {SHA-256} for RSA/ECDSA
  (`helpers.rs:282-286`) instead of silently signing SHA-256.

Step 2 (after engine slice **S6**): map SHA-384/512 →
`CKM_SHA384/512_RSA_PKCS{,_PSS}` and `CKM_ECDSA_SHA384/512`; honor PSS salt
length from CP.

**Gate**: replay corpus exercises CBC/GCM/OAEP-SHA256 paths — expected
unaffected; add negative tests per rejected combination.

## K7 — Sensitive/Extractable enforcement on Get/Export (S) · finding B-4

- `ops/get.rs:107-111`: before returning material — `Sensitive=true` without
  `KeyWrappingSpecification` → fail `Sensitive (0x16)`; `Extractable=false` →
  fail `NotExtractable (0x17)`; engine-held private key (the current
  empty-OpaqueObject branch) → fail `Sensitive`/`PermissionDenied`, never a
  zero-length KeyValue.
- `ops/register_import_export.rs:394-398` (Export): same checks in addition
  to the existing Destroyed-state check.

**Gate**: AX-M wrapping transcripts supply KeyWrappingSpecification and must
still pass; QS/SKLC transcripts don't set Sensitive — verify with corpus grep.

## K8 — KeyFormatType correctness (M) · finding B-5

1. Enum fix (`src/kmip30/ops.rs:313-314`): `TransparentPrivateKey = 0x09` /
   `TransparentPublicKey = 0x0A` → `TransparentDSAPublicKey = 0x09` /
   `TransparentRSAPrivateKey = 0x0A` (per enums JSON; current variants are
   unreferenced, so zero blast radius).
2. Decoder (`src/kmip30/wire.rs:2174-2186`): unknown codepoint →
   `KeyFormatTypeNotSupported (0x10)`, not silent `Raw`.
3. Transparent RSA Private Key: either parse the sub-structure (P, Q, D, …)
   into PKCS#8 DER for the existing `register_rsa_private_key_pkcs8` path, or
   reject with 0x10. **Never store empty material** (`wire.rs:2141-2168`).
   Recommendation: parse — RSA import already exists, this is encoding glue.
4. Honor requested output format on Get/Export
   (`ExportRequest.key_format_type` decoded then ignored;
   `register_import_export.rs:416-420` maps everything to Raw): convertible
   pairs (Raw↔TransparentSymmetricKey, PKCS#1↔PKCS#8) convert; otherwise
   0x10; absent → preserve stored format.

## K9 — PQC Register usability (M) · finding B-6 — depends on engine slice S7

- Interim (can land now): PQC algorithms in Register
  (`ops/register_import_export.rs:147-196`) → explicit
  `OperationNotSupported` with message, so failure happens at Register, not
  first use (`sign.rs:198-201` ItemNotFound).
- Full (after S7): match arms for ML-DSA/ML-KEM/SLH-DSA calling
  `native::register_ml_dsa_private_key` etc.; derive the `CKP_*` param set
  from the KMIP CryptographicAlgorithm variant (e.g. `MLDsa65` →
  `CKP_ML_DSA_65`) + CryptographicLength cross-check; store the engine handle
  mapping exactly as Create does.

**Tests**: Register KAT keypair → Sign → SignatureVerify round-trip per PQC
family; wrong-length key material rejected at Register.

## K10 — Vendor tag for ML-KEM shared secret (S) · finding B-7

- Allocate `0x540001` (`PQCToday-SharedSecret`) in a new
  `src/kmip30/vendor_tags.rs`; emit the encapsulation shared secret there
  instead of `IVCounterNonce` (`src/kmip30/wire.rs:1087-1092`), removing the
  wire ambiguity with classical RandomIV responses (`ops/encrypt.rs:544`).
- Document in the mech manifest + `CONFORMANCE_REPORT.md` (vendor extension,
  KMIP 3.0 has no Encapsulate op).
- Coordinate with any client decoding the current stopgap (grep webrpc/,
  pqctoday-hub) — breaking wire change, version-gate if needed.
- Roadmap note (not this slice): model encapsulation output as a managed
  SymmetricKey object returning a UID, eliminating raw secrets on the wire.

## K11 — Attribute truthfulness (M) · findings K-13, K-14, K-15, K-16

1. **LastChangeDate**: set in the shared commit path of
   `ops/attribute_mutate.rs` so all five mutation ops update it (§11 SHALL).
2. **Digest**: compute at creation from real key material (public half via
   `native::get_attribute` at generate time), persist on the object record;
   where material is genuinely unavailable, **omit** the attribute — delete
   the SHA-256-of-UID fabrication (`ops/get_attributes.rs:210-221`).
3. **RandomNumberGenerator**: report the engine's actual DRBG or
   `Unspecified` — drop the hardcoded "ANSI X9.31 / AES-256"
   (`get_attributes.rs:227-231`).
4. **Links/UsageLimits**: emit all stored links by iterating the `links` map
   (`get_attributes.rs:183-194`) instead of cherry-picking four; emit the full
   UsageLimits structure (Total/Count/Unit) from stored data
   (`get_attributes.rs:199`).
5. **Document** synthesized defaults that remain (ObjectClass="User",
   LeaseTime=3600, ProtectionStorageMask=0x01) in `CONFORMANCE_REPORT.md`.

**Gate**: Digest change can break transcripts that pin the fabricated value —
check corpus first; OASIS transcripts use placeholder digests, expected safe.

## K12 — Enforcement & paging (M) · findings K-9, K-12

1. **CryptographicUsageMask enforcement**: before engine dispatch in
   Encrypt/Decrypt/Sign/SignatureVerify/MAC (`ops/encrypt.rs:45-115`,
   `ops/sign.rs:54-102`, …), test the required bit (Sign 0x01, Verify 0x02,
   Encrypt 0x04, Decrypt 0x08, WrapKey 0x40, UnwrapKey 0x80 — reuse `check`'s
   constants) → `IncompatibleCryptographicUsageMask (0x29)`. Corpus sets masks
   correctly; expected no regression.
2. **Locate paging** (`src/kmip30/ops.rs:321-327`): decode `Offset Items` and
   `Storage Status Mask` (§6.1.32); apply offset after the existing sort; mask
   against storage status (all objects On-line while Archive is a no-op).

## K13 — Conformance-claim decision + Baseline ops (L / doc-first) · finding K-10

1. **Doc-first (this week)**: state in `CONFORMANCE_REPORT.md` that the claim
   is "OASIS KMIP 3.0 conformance-corpus conformance", explicitly **not**
   Baseline Server profile conformance, and list the delta: client-to-server
   GetConstraints (0x38), GetUsageAllocation (0x11), SetDefaults (0x36),
   SetEndpointRole (0x32); server-to-client channel (DiscoverVersions, Notify,
   Put, Query, SetEndpointRole); Authentication (K14).
2. **If Baseline is the target** (separate decision): implement the four
   client-to-server ops (GetUsageAllocation over existing UsageLimits
   machinery; SetDefaults/GetConstraints over a config-backed static table;
   SetEndpointRole rejecting role changes with a spec-valid reason) — M; the
   server-to-client channel is L and architecturally new (`src/server/` is
   request-response only).

## K14 — Authentication (L, phased) · finding K-5

1. Decode the §8.1.2 `Authentication`/`Credential` structure
   (`src/kmip30/wire.rs:385-426` gains an arm); support
   UsernameAndPassword first.
2. Verifier trait + config-backed credential store; failure →
   `AuthenticationNotSuccessful (0x03)` (currently unreachable, `error.rs:18`).
3. Make `login` (`src/ops/session_and_auth.rs:132-140`) validate the
   credential before issuing a ticket.
4. Wire `tls_mtls` (`src/server/listener.rs:99-125`, currently
   `#[allow(dead_code)]`) behind config; map client-cert DN → KMIP username.

**Gate**: default config stays open-auth so the hermetic replay harness is
unaffected; auth enforced only when credentials are configured.

## K15 — Honesty & hygiene (S) · findings B-8, B-9, K-17, K-1 doc residue

1. **Truthful audit log**: move every `emit_pkcs11` after the call with the
   real rv (`ops/encrypt.rs:318,373`, `ops/decrypt.rs:134,178`,
   `ops/sign.rs:161-188`, `ops/create_key_pair.rs:180-193`); name the actual
   entry point (`native::encrypt`) or document the C-ABI alias mapping.
2. **HMAC through the engine**: route MAC/MACVerify via `native::sign` with
   `CKM_SHA{256,384,512}_HMAC` (`ops/mac_and_hash.rs:155-180`); keep the
   in-process `hmac` path only for KMIP-store-only keys, and log which path ran.
3. **Comment fixes**: OperationUndone is 0x03 not 0x02
   (`dispatcher/mod.rs:695`, `wire.rs:510`); delete the stale "Undo treated as
   Stop" comment (`dispatcher/mod.rs:60-62`); single-decode the request in
   `listener.rs:156-161`.

---

## Sequencing

```
K1 (error model, with engine S4) ──► K2 (reason sweep) ──► K3 (ops/Query)
K4, K5, K7, K10, K15 ─ independent, any order after K1
K6 step 1 after K1 · K6 step 2 after engine S6
K8 after K1 (needs 0x10 reason)
K9 interim after K1 · K9 full after engine S7
K11, K12 after K2
K13 doc-first now · K13 impl + K14 last (largest, least corpus-covered)
```

## Definition of done

- Replay harness 92/92 with zero new skips; codec round-trip unchanged.
- No silent substitution: every (algorithm, CP) combination either executes
  exactly as requested or fails with a spec-listed reason.
- Every CKR the engine can return maps to a deliberate ResultReason (no
  catch-all surprises) — pinned by the K1 table test.
- Query output ≡ dispatcher surface (pinned by a test that diffs
  `supported_operations()` against the dispatcher match arms).
- `CONFORMANCE_REPORT.md` scopes its claim explicitly (corpus vs profile) and
  lists remaining K13/K14 deltas.
