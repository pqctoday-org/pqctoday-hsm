# Compliance Audit — KMIP 3.0 → softhsmrustv3 (PKCS#11 v3.2)

**Date**: 2026-06-10 · **Branch**: `feat/kmip-conformance-round-2` (HEAD `7142333`)
**Scope**: `kmip/` crate (KMIP 3.0 server + PKCS#11 bridge) and `rust/` crate
(softhsmrustv3 engine), audited against:

- OASIS KMIP Specification v3.0 (`kmip/spec/oasis-kmip-3.0/kmip-spec-v3.0.html` + `kmip-spec-3.0-tags-enums.json`)
- OASIS KMIP Profiles v3.0 (`kmip-profiles-v3.0.pdf`, Baseline Server §5.1.2)
- OASIS PKCS#11 v3.2 CSD01 (`docs/refs/pkcs11-spec-v3.2-csd01.pdf` + normative `src/lib/pkcs11/pkcs11{t,f}.h`)

**Method**: four parallel code audits (KMIP server vs spec, KMIP→PKCS#11
bridge, Rust engine vs v3.2, documented-posture mining), with high-impact
findings spot-verified by hand against source and `pkcs11t.h`.

This report covers what the existing harnesses (OASIS replay 92/92, TTLV
round-trip 1234/1234) do **not** cover. Codec-level wire conformance is not
re-litigated here — it is byte-exact and stays that way.

---

## Executive summary

| Layer | Posture |
|---|---|
| TTLV codec | ✅ 100% byte-exact vs OASIS corpus — no findings |
| KMIP message layer | ⚠️ 4 violations (async indicator, critical extension, version-mismatch reason, unsupported-op reason), 1 gap (Authentication ignored) |
| KMIP operations / attributes | ⚠️ 6 violations (ResultReason precision, LastChangeDate, fabricated Digest), 5 gaps (Baseline ops, usage-mask enforcement, Locate paging) |
| KMIP→PKCS#11 bridge | 🔴 2 high-impact violation families: **vendor mech IDs squat on standard CKM_HSS/XMSS codepoints**, and **silent algorithm substitution** (AES mode→GCM, RSA pad→OAEP, hash→SHA-256); CKR→ResultReason catch-all loses semantics |
| Rust engine (PKCS#11 v3.2) | ⚠️ Most previously documented criticals (C-1…C-5, H-4/5/7/11/14) verified **FIXED** on this branch. 7 open violations (PQC key-size units, pre-init interface gate, wrap-family return codes, ALWAYS_SENSITIVE falsification…), 6 gaps (CKA_UNIQUE_ID absent, CKA_SEED readable, null-check sweep…) |
| Deliberate deviations | DES/3DES/DSA refusal, RNG policy variant — documented in `kmip/DEPRECATED.md`, no action |

**Finding IDs**: `K-*` KMIP server · `B-*` bridge · `P-*` Rust engine.
**Class**: VIOLATION = spec SHALL broken · GAP = required/expected feature missing · OBS = note, no spec breach.

---

## A. KMIP 3.0 server (`kmip/src`)

### A.1 Message layer

**K-1 · VIOLATION — Asynchronous Indicator silently ignored**
`kmip/src/kmip30/wire.rs:423-425` drops the header field in a `_ => {}` arm.
KMIP §8.1.2/§11: value `Mandatory (0x01)` ⇒ server SHALL process
asynchronously or fail the request; a synchronous server must reject it.
*Remediation*: decode the field; if `Mandatory`, fail each batch item with
`OperationFailed`/`OperationNotSupported` and a message stating async is
unsupported. If `Optional`, proceed synchronously (allowed). ~15 LOC + 1 test.

**K-2 · VIOLATION — Critical Message Extension not rejected**
`kmip/src/kmip30/wire.rs:437-455` swallows unknown batch-item children,
including `Message Extension` with `Criticality Indicator = true`. Spec §9.x:
receiver SHALL reject the entire message if it does not understand a critical
extension.
*Remediation*: decode `MessageExtension` (tag 0x420051); if
`CriticalityIndicator=true` and the vendor extension is unrecognized, fail the
batch item with `InvalidMessage` (and honor Batch Error Continuation).
Non-critical extensions remain skippable.

**K-3 · VIOLATION — Wrong ResultReason for unsupported protocol version**
`wire.rs:343-348` + `server/listener.rs:223-236`: a non-3.0 version yields
`InvalidMessage (0x04)`. The Result Reason enum defines
`Unsupported Protocol Version (0x3f)` for exactly this.
*Remediation*: map `WireError::UnsupportedVersion` to a dedicated
`ResultReason::UnsupportedProtocolVersion = 0x3f` variant (add to
`error.rs`). 1-line enum addition + mapping change.

**K-4 · VIOLATION — Recognized-but-unimplemented ops return InvalidMessage**
`wire.rs:583-606` rejects ReKey, Validate, Poll, SetEndpointRole, etc. at
payload decode via `WireError::UnknownEnum` → `InvalidMessage (0x04)`. The
message is well-formed; the spec-correct reason is
`Operation Not Supported (0x05)`.
*Remediation*: split decode-failure from op-unsupported: have
`Operation::from_wire_value` accept all 64 spec codepoints, and let the
dispatcher return `OperationNotSupported` for any op without a handler. This
also fixes the eight ops that currently aren't even decodable
(`kmip30/ops.rs:117-178`: DeriveKey 0x05, Certify 0x06, Cancel 0x19, ReKeyKeyPair
0x1d, JoinSplitKey 0x29, DelegatedLogin 0x2f, ReProvision 0x35, SetDefaults 0x36).

**K-5 · GAP — Authentication header ignored; Login unauthenticated; mTLS dead code**
`decode_request_header` (`wire.rs:385-426`) has no arm for the
`Authentication` structure; `AuthenticationNotSuccessful (0x03)` is defined in
`error.rs:18` but unreachable. `ops/session_and_auth.rs:132-140` issues login
tickets without validating any credential; `listener.rs:99-125` runs TLS
`with_no_client_auth` and `tls_mtls` is `#[allow(dead_code)]`. Baseline §5.1.2
item 12.a requires the Authentication message protocol.
*Remediation*: phased — (1) decode `Authentication`/`Credential`
(UsernameAndPassword at minimum), thread it to a verifier trait with a
config-backed store; fail with `AuthenticationNotSuccessful`; (2) wire
`tls_mtls` behind a config flag and map client-cert identity to the KMIP
username; (3) make `login` validate the credential before issuing a ticket.

### A.2 Operations & ResultReason precision

**K-6 · VIOLATION — `Item Not Found (0x01)` used where op error tables mandate `Object Not Found (0x37)`**
Only `get.rs:37` uses `object_not_found`. ~20 other UID-consuming handlers use
`KmipError::not_found` (ItemNotFound): `activate.rs:39`, `revoke.rs:44`,
`destroy.rs:38`, `lifecycle_and_protocol.rs:40/86/122/136/154`,
`encrypt.rs:47`, `decrypt.rs:48`, `sign.rs:54`, `signature_verify.rs:52`,
`mac_and_hash.rs:38/79`, `attribute_mutate.rs` (5 sites),
`get_attributes.rs:47`, `get_attribute_list.rs:31`. The per-op error tables
(Activate Tbl 251, Destroy Tbl 307, Revoke Tbl 397, …) list *Object Not
Found*, not Item Not Found.
*Remediation*: add `KmipError::object_not_found` everywhere a **managed
object UID** lookup fails; reserve `ItemNotFound` for non-object items
(e.g. attribute references). Mechanical change + replay-corpus re-run to
confirm the OASIS transcripts still match (the corpus passed with the current
codes, so re-verify each touched transcript expectation before merging).

**K-7 · VIOLATION — Activate/Deactivate wrong-state → `PermissionDenied` instead of `Wrong Key Lifecycle State (0x43)`**
`activate.rs:42-52`, `lifecycle_and_protocol.rs:47-53`. The sibling Destroy
handler already uses `WrongKeyLifecycleState` — internal inconsistency. The
Deactivate comment claiming the enum lacks the variant (and citing 0x12) is
stale and wrong: `error.rs:37` has `WrongKeyLifecycleState = 0x43`.
*Remediation*: switch both sites to `WrongKeyLifecycleState`; delete the
stale comment. 4 LOC.

**K-8 · VIOLATION — Destroy on already-Destroyed → `Object Archived (0x0d)` instead of `Object Destroyed (0x36)`**
`destroy.rs:58-65` (verified). Also contradicts `get.rs:43-56` which correctly
uses ObjectDestroyed, and the `error.rs:36` comment misdescribing
ObjectArchived.
*Remediation*: use `KmipError::object_destroyed`; fix the `error.rs` comment
(Object Archived = object resides in archival storage, per §6.1.4).

**K-9 · GAP — CryptographicUsageMask not enforced on crypto ops**
`encrypt.rs:45-115`, `sign.rs:54-102`: state and date windows are checked, but
the object's usage-mask bits (Encrypt/Decrypt/Sign/Verify) are never tested;
the policy engine defaults permissive. The Encrypt error table includes
*Incompatible Cryptographic Usage Mask (0x29)* — enforcement is expected, and
`check` already implements the comparison.
*Remediation*: before dispatching to the engine, test the required mask bit
(Encrypt=0x04, Decrypt=0x08, Sign=0x01, Verify=0x02, WrapKey=0x40 — reuse the
constants from `check`) and fail with `IncompatibleCryptographicUsageMask`.
Add per-op tests; confirm OASIS transcripts (they set masks correctly, so this
should not regress the 92/92).

**K-10 · GAP — Baseline-mandatory operations missing**
Profiles §5.1.2 item 9 requires Get Constraints (0x38), Get Usage Allocation
(0x11), Set Defaults (0x36), Set Endpoint Role (0x32); none has a handler
(`wire.rs:583-606` rejects them). Item 10 additionally requires
server-to-client Discover Versions / Notify / Put / Query / Set Endpoint Role —
no server-initiated channel exists.
*Remediation*: decide and document the conformance target. Option A (claim
Baseline Server): implement the four client-to-server ops (GetUsageAllocation
needs the existing UsageLimits machinery; SetDefaults/GetConstraints can carry
a static config-backed table; SetEndpointRole can reject role changes with a
spec-valid reason) and a minimal server-to-client Query/DiscoverVersions over
the existing connection. Option B (recommended short-term): state explicitly in
`CONFORMANCE_REPORT.md` that the target is "OASIS conformance-corpus
conformance, not Baseline Server profile conformance", and keep K-10 on the
roadmap. Either way, stop the report's ambiguity.

**K-11 · VIOLATION — Query advertises 14 unsupported operations and ~10 unsupported object types**
`ops/query.rs:110-208`: SetEndpointRole, ReKey, ReCertify, ObtainLease,
GetUsageAllocation, Validate, Poll, Notify, Put, CreateSplitKey,
SetConstraints, GetConstraints, QueryAsynchronousRequests, Process are
advertised but rejected on invocation; same for SplitKey/OpaqueObject/PgpKey
object types. §6.1.45 defines the Query response as what the server
*supports*. The Profiles §4.1.1 superset rule governs test comparison, not
server truthfulness.
*Remediation*: trim `supported_operations()`/`supported_object_types()` to
the dispatcher's real surface, then re-run the replay harness — if a corpus
transcript requires the longer list, keep only the ops that are then actually
implemented (ties into K-4/K-10). Also implement `QueryProfiles` /
`QueryCapabilities` responses (`query.rs:85-90` no-ops) with honest
CapabilityInformation (streaming yes, async no, attestation no).

**K-12 · GAP — Locate paging parameters not decoded**
`kmip30/ops.rs:321-327`: `Offset Items` and `Storage Status Mask` (§6.1.32)
are silently ignored — paging clients get wrong result windows.
*Remediation*: decode both; apply offset after sorting; mask against
on-line/archival status (with Archive being a no-op, all objects are
`On-line`). ~30 LOC.

### A.3 Attributes

**K-13 · VIOLATION — Last Change Date not updated by attribute mutation**
§11: Last Change Date SHALL be updated whenever any attribute changes.
`ops/attribute_mutate.rs` (Add/Modify/Delete/Set/AdjustAttribute) never
touches `last_change_date`; the stores don't auto-touch it.
*Remediation*: set `last_change_date = now()` in the shared
mutate-commit path of `attribute_mutate.rs` (single helper, all five ops flow
through `store.update`). 5 LOC + test.

**K-14 · VIOLATION — Digest attribute fabricated for engine-resident keys**
`get_attributes.rs:210-221`: when `key_material == None` (every
Create/CreateKeyPair object), DigestValue is SHA-256 of the **UID string**,
not of the key material — a client cross-checking Get output against Digest
will fail. §11 Digest SHALL be computed over the object's key material.
*Remediation*: compute the digest at creation time from real material:
for engine-held keys, digest the public key / key value retrieved once via
`native::get_attribute` at generate-time and persist it on the object record.
If material is genuinely unavailable (sensitive private halves), omit the
Digest attribute entirely rather than fabricate it — absence is conformant,
fabrication is not. Same treatment for the hardcoded `RandomNumberGenerator`
("ANSI X9.31 / AES-256", `get_attributes.rs:227-231`): report the real DRBG or
`Unspecified`.

**K-15 · GAP — Baseline item-8 attributes not surfaced**
Certificate attributes, Counter attributes, Cryptographic Domain Parameters,
Rotate Latest, full Link set (only PublicKey/PrivateKey/Next/Previous emitted,
`get_attributes.rs:183-194`), UsageLimits sub-structure (only
`UsageLimitsTotal`, `get_attributes.rs:199`).
*Remediation*: emit the full UsageLimits structure (Total/Count/Unit) from the
data already stored; emit all stored links generically (the `links` map
already holds them — iterate it instead of cherry-picking four). Certificate
and counter attributes follow whenever certificate objects/counters become
in-scope; track on roadmap.

**K-16 · OBS — Synthesized attribute values**
`ObjectClass="User"` on every object, `LeaseTime=3600`,
`ProtectionStorageMask=0x01` hardcoded (`get_attributes.rs:150-231`).
*Remediation*: none required for conformance (corpus-pinned), but document
them in `CONFORMANCE_REPORT.md` as synthesized defaults.

**K-17 · OBS — Doc/comment hygiene**
`OperationUndone` codepoint mis-documented as 0x02 in comments
(`dispatcher/mod.rs:695`, `wire.rs:510` — wire encoding is correct, 0x03);
stale "Undo treated as Stop" comment at `dispatcher/mod.rs:60-62` (Undo is
fully implemented); `attrmap/mod.rs` is an empty stub.
*Remediation*: fix comments; either implement `attrmap` as the single
KMIP↔CKA translation point (see B-5) or delete the stub.

---

## B. KMIP→PKCS#11 bridge (`kmip/src/ops` + `kmip/src/pkcs11bridge`)

> Architecture note: the nominal `pkcs11bridge/{session,error,mechs}.rs` is
> mostly dead code — handlers call `softhsmrustv3::native::*` typed wrappers
> directly via `Deps::engine_session`. Findings below apply to the live path.

**B-1 · VIOLATION — "Vendor" mechanism codepoints 0x4032–0x4037 collide with OASIS-assigned PKCS#11 v3.2 mechanisms**
`kmip30/algos.rs:36-41` + `pkcs11-mech-manifest.json` define
`CKM_PQCTODAY_{HSS_KEY_PAIR_GEN,SLH_DSA_SIGN_VERIFY,ML_KEM_KEY_PAIR_GEN,ML_DSA_KEY_PAIR_GEN,ML_DSA_SIGN_VERIFY,ML_KEM_ENCAPSULATE}` =
0x4032–0x4037. Verified against `pkcs11t.h:1218-1224`: these are the standard
`CKM_HSS_KEY_PAIR_GEN`, `CKM_HSS`, `CKM_XMSS_KEY_PAIR_GEN`,
`CKM_XMSSMT_KEY_PAIR_GEN`, `CKM_XMSS`, `CKM_XMSSMT`. PKCS#11 §3.5: vendor
mechanisms MUST be ≥ `CKM_VENDOR_DEFINED` (0x80000000). Today an "ML-DSA sign"
audit event carries the standard XMSS codepoint. The actual crypto calls use
correct standard codepoints, so this is a labeling/interop violation — but it
poisons audit logs and any PKCS#11-literate consumer of `to_pkcs11_mech()`.
*Remediation*: two changes — (1) for operations that have standard v3.2
codepoints, use them: `CKM_ML_KEM_KEY_PAIR_GEN=0x0f`, `CKM_ML_KEM=0x17`,
`CKM_ML_DSA_KEY_PAIR_GEN=0x1c`, `CKM_ML_DSA=0x1d`,
`CKM_SLH_DSA_KEY_PAIR_GEN=0x2d`, `CKM_SLH_DSA=0x2e` (the engine already
uses these; the vendor aliases are unnecessary); (2) anything genuinely
vendor-specific moves to `0x80000000 | n`. Update
`pkcs11-mech-manifest.json`, the manifest sha256 test, and
`pqctoday-priv/docs/platform/data/pkcs11-vendor-mech-allocation.md`. Also fix
SLH-DSA keygen mislabeled as HSS (`algos.rs:263-273`).

**B-2 · VIOLATION — Silent algorithm substitution (family)**
Verified in code:
- Unsupported AES block-cipher modes (CTR 6, CFB 4, OFB 5, PCBC 3, CCM 8,
  XTS 0x0b, NISTKeyWrap…) fall through to **CKM_AES_GCM**
  (`helpers.rs:182-191`, explicit `_ => CKM_AES_GCM` with an in-code comment
  acknowledging it). A client asking for AES-CTR gets GCM ciphertext, status
  Success. Note: the engine *has* a working CTR path and the streaming code
  matches `CKM_AES_CTR` (`encrypt.rs:220-223`) — currently unreachable.
- RSA Encrypt/Decrypt ignores `PaddingMethod` — always OAEP (`algos.rs:285`).
- OAEP hash whitelist silently downgrades SHA-1/SHA-224/SHA3-* to SHA-256
  (`helpers.rs:204-211`).
- RSA/ECDSA Sign hash hardwired to SHA-256 regardless of
  `HashingAlgorithm` (`helpers.rs:282-286`); PSS salt length never derived
  from KMIP CP.
- Request-level CryptographicParameters honored for mech selection but
  **ignored for OAEP params** — `encrypt.rs:457` / `decrypt.rs:191` read the
  *object's* stored CP, so a request-specified OAEP-SHA-384 silently encrypts
  with the object's SHA-256.

Silent substitution of a different algorithm than requested violates KMIP's
core contract (and is a real interop/security hazard: a CTR-expecting peer
cannot decrypt, and worse, signatures claimed as SHA-384 are SHA-256).
*Remediation*: make every selector **total or failing** —
(1) `aes_mechanism_for` returns `Result`, mapping CTR→`CKM_AES_CTR` (already
implemented downstream) and everything else unsupported →
`OperationNotSupported (0x05)` (add `Unsupported Cryptographic Parameters
(0x3e)` to the ResultReason enum and prefer it where the op error tables list
it); (2) RSA padding: PKCS1v1.5 (0x08) → `CKM_RSA_PKCS`, OAEP (0x0b) →
`CKM_RSA_PKCS_OAEP`, others → error; (3) OAEP hash map: support what the
engine supports, error on the rest — never default; (4) sign/verify: derive
the CKM from `HashingAlgorithm` (SHA-256/384/512 variants exist in
`pkcs11t.h`; add engine mechs as needed) and error on unsupported; honor PSS
salt-length CP; (5) use `effective_cp` (request-over-object) consistently for
OAEP params as is already done for mech selection. Re-run replay corpus after
each step.

**B-3 · VIOLATION — CKR→ResultReason catch-all loses spec semantics**
`helpers.rs:380-397` (verified): only five CKR codes are mapped; everything
else → `CryptographicFailure (0x0a)`, including
`CKR_KEY_HANDLE_INVALID` (should be ObjectNotFound),
`CKR_MECHANISM_PARAM_INVALID` (InvalidField/0x3e), `CKR_PIN_*` /
`CKR_USER_NOT_LOGGED_IN` (AuthenticationNotSuccessful/PermissionDenied),
`CKR_TEMPLATE_*` (InvalidAttribute), `CKR_KEY_SIZE_RANGE` /
`CKR_DATA_LEN_RANGE` (InvalidField), `CKR_DEVICE_*`/`CKR_HOST_MEMORY`
(GeneralFailure 0x100). Additionally `error.rs:176-183` maps **every**
`BridgeError` variant to GeneralFailure, discarding the careful
classification in `pkcs11bridge/error.rs:74-90`.
*Remediation*: extend `ck_rv_to_kmip_error` to a full table (the list above,
plus default GeneralFailure for device-class errors and CryptographicFailure
only for genuinely cryptographic codes). Add the missing ResultReason
variants: `KeyFormatTypeNotSupported (0x10)`, `Sensitive (0x16)`,
`NotExtractable (0x17)`, `InvalidDataType (0x1c)`,
`UnsupportedCryptographicParameters (0x3e)`, `UnsupportedProtocolVersion
(0x3f)` (also needed by K-3). Either wire `BridgeError`'s classification into
`KmipError::result_reason()` or delete the dead bridge module (K-17).

**B-4 · VIOLATION — Sensitive/Extractable never enforced on Get/Export; empty KeyBlock instead of failure**
`get.rs:107-111` returns `obj.key_material` unconditionally when present, and
for engine-held private keys returns `KeyFormatType::OpaqueObject` with a
**zero-length KeyValue** — KMIP has no "empty key" concept. Export
(`register_import_export.rs:394-398`) checks only Destroyed state. Clients can
set `Sensitive=true` (`attribute_mutate.rs:495-496`) and it is reported but
not enforced.
*Remediation*: in Get/Export — if `Sensitive=true` and no
KeyWrappingSpecification is supplied, fail with the new `Sensitive (0x16)`
reason; if `Extractable=false`, fail with `NotExtractable (0x17)`; for
engine-held private keys, fail with `PermissionDenied`/`Sensitive` instead of
returning an empty KeyBlock. Re-run replay corpus (the AX-M wrapping tests
supply KeyWrappingSpecification, so they should still pass).

**B-5 · VIOLATION — KeyFormatType handling: silent Raw coercion + mislabeled enum + unparsed Transparent structures**
- `kmip30/wire.rs:2174-2186`: unknown KeyFormatType decodes as `Raw`; KMIP
  defines `Key Format Type Not Supported (0x10)`.
- `kmip30/ops.rs:313-314`: `TransparentPrivateKey = 0x09`,
  `TransparentPublicKey = 0x0A` — per the OASIS enum JSON, 0x09 is
  *Transparent DSA Public Key* and 0x0A is *Transparent RSA Private Key*;
  the generic variants don't exist in KMIP 3.0. Latent (unreferenced) but a
  wire bug the moment they're used.
- Transparent key sub-structures (P/Q/D…) are never parsed
  (`wire.rs:2141-2168` unwraps only Raw ByteStrings and
  TransparentSymmetricKey `Key`), so a TransparentRSAPrivateKey Register
  stores an **empty** key.
- Export maps every stored format to Raw
  (`register_import_export.rs:416-420`); the request's `KeyFormatType`
  conversion parameter is decoded then ignored (§6.1.22/6.1.23).
*Remediation*: (1) make the decoder return an error for unknown formats →
`KeyFormatTypeNotSupported`; (2) rename/renumber the two enum variants to the
spec names; (3) either parse TransparentRSAPrivateKey into PKCS#8 for the
existing RSA import path, or reject it explicitly with
`KeyFormatTypeNotSupported` — never store empty material; (4) honor the
requested output format where convertible (Raw↔TransparentSymmetricKey,
PKCS#1↔PKCS#8 for RSA), error otherwise; preserve stored format on Export.

**B-6 · GAP — Registered PQC keys are unusable**
`register_import_export.rs:147-196` imports only RSA private/public and raw
HMAC secrets into the engine; ML-DSA/ML-KEM/SLH-DSA Register stores bytes in
the KMIP store only — a later Sign/Encrypt does `find_handle_for_object` →
no engine object → `ItemNotFound`. Register succeeds, use fails.
*Remediation*: add engine import paths via `native::create_object` with
`CKA_KEY_TYPE=CKK_ML_DSA/ML_KEM/SLH_DSA` + `CKA_PARAMETER_SET` derived from
the KMIP CryptographicAlgorithm variant + CryptographicLength; or, until
implemented, reject PQC Register with `OperationNotSupported` so failure is
at Register time, not use time. (Engine side already supports import via
`native::keygen.rs` import helpers for several types.)

**B-7 · VIOLATION — ML-KEM shared secret returned under the `IVCounterNonce` tag**
`kmip30/wire.rs:1087-1092` (acknowledged in-code as a stopgap). Abuses a
standard tag and is wire-indistinguishable from a classical RandomIV Encrypt
response (`encrypt.rs:544`). KMIP 3.0 has no Encapsulate operation, so the
Encrypt/Decrypt overload is a vendor design — fine — but the payload must use
a vendor extension tag (0x54xxxx), not a standard tag with different
semantics.
*Remediation*: allocate a vendor tag (e.g. `0x540001
PQCTODAY_SharedSecret`), emit the shared secret there, document it in the
manifest, and keep `IVCounterNonce` for IVs only. Longer-term: model
encapsulation output as a new managed SymmetricKey object (returns UID instead
of raw secret) — closer to both C_EncapsulateKey semantics and KMIP's managed
object philosophy, and stops shipping raw shared secrets over the wire.

**B-8 · OBS — Audit log fabricates PKCS#11 results**
`emit_pkcs11(..., 0, "CKR_OK")` is logged **before** the operation executes
and regardless of outcome (`encrypt.rs:318,373`, `decrypt.rs:134,178`,
`sign.rs:161-188`, `create_key_pair.rs:180-193`); function names reference the
C ABI (`C_EncryptInit`) though only `native::*` wrappers run.
*Remediation*: log after the call with the real rv; name the actual entry
point (`native::encrypt`) or keep the C-ABI alias but document the mapping.
For an HSM-audit-log product feature this is worth fixing early — a log that
asserts CKR_OK on failed operations is worse than no log.

**B-9 · OBS — HMAC bypasses the engine entirely**
KMIP MAC/MACVerify run on the in-process `hmac` crate
(`mac_and_hash.rs:155-180`), not PKCS#11 — key material never benefits from
engine custody.
*Remediation*: route through `native::sign` with `CKM_SHA256_HMAC` etc.
(mechs exist in the engine); keep the soft path only as a fallback for
KMIP-store-only keys.

---

## C. Rust engine — softhsmrustv3 (`rust/src`) vs PKCS#11 v3.2

Previously documented criticals verified **FIXED** on this branch: login/object
access gating (C-1), init gate (C-2), ChaCha20/KWP mech IDs (C-3), GCM zero-IV
fallback (C-4), AAD in authenticated wrap (C-5), two-call buffer convention
incl. stateful-sig leaf protection (H-4/H-5), session-handle validation on
init-stage calls (H-7), sensitive-attribute parity (H-11/H-12),
CKA_ENCAPSULATE/DECAPSULATE enforcement (H-14), R5 streaming fixes, F2
constants guard (329/329). `docs/gap-analysis-rust-pkcs11-v3.2.md` should be
updated to reflect this (it still reads as if C-1…C-5 are open).

### Open violations

**P-1 · VIOLATION — PQC mechanism-info key sizes use the wrong unit**
`ffi.rs:697-704` (verified): `CKM_ML_DSA` reports `(44, 87)`, `CKM_ML_KEM`
`(512, 1024)`, `CKM_SLH_DSA` `(128, 256)` — parameter-set numbers. Spec
§6.67–6.69: ulMin/MaxKeySize for these mechanisms are public-key sizes **in
bytes**: ML-DSA `(1312, 2592)`, ML-KEM `(800, 1568)`, SLH-DSA `(32, 64)`.
*Remediation*: pure table fix in `mechanism_info` + unit test asserting the
FIPS 203/204/205 public-key byte lengths.

**P-2 · VIOLATION — `C_GetInterfaceList`/`C_GetInterface` gated behind `require_init!`**
`ffi.rs:6264, 6295`. Spec §5.4: these are (with `C_GetFunctionList`) the only
functions callable **before** `C_Initialize`; `CKR_CRYPTOKI_NOT_INITIALIZED`
is not in their return-value list. Pre-init interface negotiation is
impossible.
*Remediation*: drop the gate from both. 2 LOC.

**P-3 · VIOLATION — Wrap/Unwrap/Derive conflate handle-invalid with not-permitted**
`ffi.rs:5334-5353` (`C_WrapKey`): nonexistent wrapping key →
`CKR_KEY_FUNCTION_NOT_PERMITTED` (spec: `CKR_WRAPPING_KEY_HANDLE_INVALID`);
nonexistent target → `CKR_KEY_UNEXTRACTABLE` (spec: `CKR_KEY_HANDLE_INVALID`).
Same pattern in `C_UnwrapKey` (`ffi.rs:5484-5493`,
`CKR_UNWRAPPING_KEY_HANDLE_INVALID`) and `C_DeriveKey` (`ffi.rs:4704-4713`).
These paths also skip the `can_access_object` login gate that Sign/Encrypt get
via `check_key_usage`.
*Remediation*: split the `.unwrap_or(false)` lookups into
exists-check → access-check → permission-check, returning the wrap-specific
CKR codes; route through `check_key_usage` (parameterized on the
handle-invalid code). Matters doubly since KMIP Get-with-wrapping
(`99ad235`) consumes these paths and B-3 maps their CKRs onward.

**P-4 · VIOLATION — AES-KW unwrap failures return generic codes**
`ffi.rs:5528-5566`: integrity failure → `CKR_FUNCTION_FAILED` (spec:
`CKR_WRAPPED_KEY_INVALID`); short input → `CKR_ARGUMENTS_BAD` (spec:
`CKR_WRAPPED_KEY_LEN_RANGE`).
*Remediation*: map the two paths to the wrap-specific codes (constants exist
in `pkcs11t.h`: 0x110, 0x112).

**P-5 · VIOLATION — Operate-stage calls return `CKR_OPERATION_NOT_INITIALIZED` for bogus session handles**
`C_Sign`/`C_Verify`/`C_Encrypt`/`C_Decrypt`/`C_Digest*`/`C_FindObjects` lack
`require_session!`, so a closed/invalid handle hits the per-session op map
miss first. §5.2 error priority: `CKR_SESSION_HANDLE_INVALID` outranks
operation-state errors. (H-7 was fixed for Init-stage only.)
*Remediation*: add `require_session!` at the top of the ~10 operate-stage
functions; the macro exists, this is mechanical.

**P-6 · VIOLATION — `C_CreateObject` falsifies `CKA_ALWAYS_SENSITIVE`/`CKA_NEVER_EXTRACTABLE`**
`ffi.rs:2369-2371` + `state.rs:645-650`: imported keys with
`CKA_SENSITIVE=TRUE` report `CKA_ALWAYS_SENSITIVE=TRUE`. §4.9/4.10: objects
created with `C_CreateObject` SHALL have both attributes `CK_FALSE` (the token
cannot vouch for the key's history). `C_UnwrapKey` already does this right
(`ffi.rs:5617-5621`).
*Remediation*: replace the conditional `finalize_private_key_attrs` call with
explicit `ALWAYS_SENSITIVE=FALSE`, `NEVER_EXTRACTABLE=FALSE` stores, mirroring
the unwrap path.

**P-7 · VIOLATION — `C_GetMechanismList` lacks init gate, null check, and slot validation**
`constants.rs:449-465`: callable pre-init/post-finalize (unlike its 100+
siblings), dereferences `pul_count` unchecked, ignores `slotID`.
*Remediation*: add `require_init!`, null check → `CKR_ARGUMENTS_BAD`, slot
check → `CKR_SLOT_ID_INVALID` (mirror `C_GetTokenInfo`).

### Open gaps

**P-8 · GAP — `CKA_UNIQUE_ID` entirely absent**
Zero references in the crate. §4.4.1 (v3.0+): every object SHALL have a
token-assigned, immutable, unique `CKA_UNIQUE_ID`. KMIP is unaffected (keys
off `CKA_ID`) but any v3.x client may rely on it.
*Remediation*: assign a UUID/monotonic string at object creation in
`state.rs`; expose read-only (reject in create templates with
`CKR_ATTRIBUTE_READ_ONLY`); add to `is_server_managed_attr`.

**P-9 · GAP — `CKA_SEED` absorbable and readable on sensitive keys**
`crypto/handlers.rs:121-141` skip-list lacks `CKA_SEED` (any template can
inject it), and both `ffi.rs:2181` and `native/object.rs:101` block only
`CKA_VALUE` — the v3.2 PQC key tables mark CKA_SEED with the same
sensitive-attribute footnotes as CKA_VALUE. M-6 remains open.
*Remediation*: add `CKA_SEED` to the sensitive-blocked set in
`state::value_is_blocked` and to the template skip-list; if/when
seed-deterministic keygen lands, store it engine-side only.

**P-10 · GAP — ML-KEM encapsulate/decapsulate: silent param-set default, no key-type check**
`ffi.rs:1983, 2079, 2133`: a key without `CKA_PARAMETER_SET` is treated as
ML-KEM-768; `CKA_KEY_TYPE` is never checked against `CKK_ML_KEM` (R3.5 second
half not executed; same default exists in `native/encrypt.rs:66,110`).
*Remediation*: missing param set → `CKR_TEMPLATE_INCOMPLETE` (or
`CKR_KEY_TYPE_INCONSISTENT` for wrong key type); remove the `| 0` fallback in
both ffi and native paths.

**P-11 · GAP — Null-check sweep incomplete**
`C_FindObjects` (`ffi.rs:4499-4504`), `C_Encrypt` `p_data` (`ffi.rs:3784`),
`C_UnwrapKey` (`ffi.rs:5499, 5639`), `C_GenerateKey` `p_mechanism`
(`ffi.rs:1868`) dereference unchecked — in wasm these read/write address 0.
*Remediation*: finish the PR-4 sweep; add a `nonnull!` macro and a grep-based
CI check for `*p_` derefs without a preceding null test.

**P-12 · GAP — ChaCha20-Poly1305 and ChaCha20 implemented but not advertised**
`C_EncryptInit` accepts them (`ffi.rs:3717`) and KMIP uses them, but neither
is in `SUPPORTED_MECHS`/`mechanism_info` → `C_GetMechanismInfo` returns
`CKR_MECHANISM_INVALID` for a working mechanism. Same for `CKM_BIP32_*`.
*Remediation*: add entries (ChaCha20 key 32 bytes → `(32,32)`,
flags CKF_ENCRYPT|CKF_DECRYPT; Poly1305 variant + CKF_MESSAGE_* if the
message-family supports it). The `supported_mechs_all_have_info` test pins
consistency once added.

**P-13 · GAP — `C_SessionCancel` ignores `CKF_MESSAGE_SIGN`/`CKF_MESSAGE_VERIFY`**
`ffi.rs:382-424`: doc comment lists them, body lacks the
`MESSAGE_SIGN_ACC`/`MESSAGE_VERIFY_ACC` arms (CloseSession clears them
correctly at `ffi.rs:349-351`).
*Remediation*: add the two arms, mirroring CloseSession.

**P-14 · GAP — `CKA_WRAP_WITH_TRUSTED`/`CKA_TRUSTED` policy unenforced**
M-8 open: `C_WrapKey` never checks the target's `CKA_WRAP_WITH_TRUSTED`
against the wrapping key's `CKA_TRUSTED`; and `CKA_TRUSTED` is settable by any
template without SO login (`crypto/handlers.rs:103-114` skip-list omission) —
§4.1.1 Table 12 requires SO.
*Remediation*: add `CKA_TRUSTED` to server-managed attrs (reject non-SO
sets with `CKR_ATTRIBUTE_READ_ONLY`); enforce the wrap-with-trusted check in
`C_WrapKey` → `CKR_KEY_NOT_WRAPPABLE`. Same sweep: reject caller-supplied
`CKA_KEY_GEN_MECHANISM` in `C_CreateObject` (`ffi.rs:2361-2367`).

**P-15 · OBS — Minor return-code precision**
Generic-secret keygen bad length → `CKR_ARGUMENTS_BAD` not
`CKR_ATTRIBUTE_VALUE_INVALID` (`ffi.rs:1910`); AES keygen defaults missing
`CKA_VALUE_LEN` to 16 instead of `CKR_TEMPLATE_INCOMPLETE` (`ffi.rs:1871`);
invalid `CKA_PARAMETER_SET` value → `CKR_ARGUMENTS_BAD` not
`CKR_ATTRIBUTE_VALUE_INVALID` (`ffi.rs:907`); ECDSA mech-info size
inconsistency (`(256,521)` vs `(256,384)`, engine supports P-521); `C_Digest`
after `C_DigestUpdate` appends instead of failing (M-2 residual); static
TokenInfo flags/label (H-15); message-encrypt O(n²) re-encryption design
(Appendix B, owner assigned).
*Remediation*: batch into the next return-code-precision PR; each is a
1-5 LOC fix except the message-encrypt rework (tracked separately).

---

## D. Deliberate deviations (documented, no action)

| Item | Where documented |
|---|---|
| DES / 3DES / DSA rejected at decode (`SKIP_DEPRECATED`, 5 OASIS tests) | `kmip/DEPRECATED.md` (NIST SP 800-131A / SP 800-186 rationale) |
| RNG-seed policy: full-consume only (3 `SKIP_POLICY_VARIANT` tests) | `kmip/conformance/REPLAY_REPORT.md` |
| 2 precondition tests requiring cross-transcript state | hermetic harness design, `REPLAY_REPORT.md` |
| C++ engine G7/G8/G9 omissions (async, recover/dual ops, session validation flags) | `docs/gap-analysis-pkcs11-v3.2.md` v16 |
| HSS/XMSS not exposed via KMIP | parked; consistent with engine support status |

---

## E. Prioritized remediation roadmap

### P0 — interop/security-relevant, small blast radius (1 PR each)

| # | Findings | Effort |
|---|---|---|
| 1 | **B-1** vendor mech codepoint collision (move to standard/≥0x80000000 IDs, manifest + docs sync) | S |
| 2 | **B-2** kill silent algorithm substitution (fail instead of substitute; wire CTR through) | M |
| 3 | **P-1** PQC mechanism-info byte units · **P-2** un-gate interface fns · **P-7** GetMechanismList hygiene | S |
| 4 | **B-4** enforce Sensitive/Extractable on Get/Export; no empty KeyBlocks | S |
| 5 | **P-6** stop falsifying ALWAYS_SENSITIVE/NEVER_EXTRACTABLE on C_CreateObject · **P-9** CKA_SEED blocking | S |

### P1 — spec-precision of error/response codes (mechanical, corpus-guarded)

| # | Findings | Effort |
|---|---|---|
| 6 | **K-3/K-4** UnsupportedProtocolVersion + OperationNotSupported reasons; decode all 64 op codepoints | S |
| 7 | **K-6/K-7/K-8** ObjectNotFound / WrongKeyLifecycleState / ObjectDestroyed precision (~25 sites) | M |
| 8 | **B-3** full CKR→ResultReason table + new ResultReason variants (0x10, 0x16, 0x17, 0x1c, 0x3e, 0x3f) | M |
| 9 | **P-3/P-4/P-5** wrap-family CKR codes, AES-KW unwrap codes, operate-stage session validation | M |
| 10 | **K-13** LastChangeDate on attribute mutation · **K-1/K-2** async indicator + critical extension | S |

### P2 — feature completeness & honesty

| # | Findings | Effort |
|---|---|---|
| 11 | **K-11** truthful Query (+ QueryProfiles/QueryCapabilities) · **K-14** real Digest or omit · **K-16** document synthesized attrs | M |
| 12 | **B-5** KeyFormatType correctness (enum fix, no Raw coercion, Transparent RSA parse-or-reject, honor requested format) | M |
| 13 | **B-6** PQC Register→engine import (or explicit reject) · **P-10** ML-KEM param-set/key-type strictness | M |
| 14 | **B-7** vendor tag for ML-KEM shared secret (stop abusing IVCounterNonce) | S |
| 15 | **K-5** Authentication: credential decode + verifier + mTLS wiring | L |
| 16 | **K-9** usage-mask enforcement · **K-12** Locate paging · **K-15** full Links/UsageLimits emission | M |
| 17 | **K-10** Baseline-profile decision (implement 4 ops + s2c channel, or scope the conformance claim explicitly) | L / doc |
| 18 | **B-8** truthful audit log (post-call rv) · **B-9** HMAC through engine · **P-8** CKA_UNIQUE_ID · **P-11** null sweep · **P-12** advertise ChaCha20 mechs · **P-13/P-14/P-15** residuals | M |

**Guard rails for all phases**: every PR re-runs (1) `cargo test --test
oasis_codec_roundtrip`, (2) the dispatcher replay harness (must stay 92/92 —
where a fix changes an emitted ResultReason, verify the corpus transcript
actually expects the old value before assuming regression), (3)
`scripts/check_pkcs11_constants.py` (329/329), (4) the engine test suite.
Update `docs/gap-analysis-rust-pkcs11-v3.2.md` to mark C-1…C-5/H-4/5/7/11/14
fixed, and `kmip/docs/CONFORMANCE_REPORT.md` to scope its claim ("OASIS
corpus conformance" ≠ "Baseline Server profile conformance") per K-10.
