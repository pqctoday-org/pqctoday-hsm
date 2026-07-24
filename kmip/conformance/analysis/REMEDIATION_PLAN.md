# OASIS KMIP 3.0 Conformance — Residual 91 FAILs — Deep Analysis + Remediation Plan

> **HISTORICAL (resolved).** This analysis dates from the PR #88 era
> (11/102 passing). All eight root-cause families below were remediated
> across PRs #88–#89; standing as of 2026-06-10 is **92 PASS / 0 FAIL
> / 10 deliberate skips** (AX-M-2's KMIP key wrapping was pulled
> forward from v0.2 and closed last).
> Kept for the audit trail; see `kmip/conformance/REPLAY_REPORT.md` for
> the live per-test table.

**Status snapshot:** PR #88 lands PASS 11/102. The 91 residual FAILs are
clustered into 8 root-cause families. Each family below cites the
specific KMIP 3.0 spec section it violates and proposes a contained
fix.

Severity legend: ⭐ = high-leverage (unlocks many tests), 🟨 = moderate,
🟦 = isolated.

---

## Family R1 ⭐ — Register / Create do not honour `ActivationDate`

**Tests impacted (~39 of bucket A):** every Encrypt/Decrypt/Sign/MAC
/SignatureVerify/MACVerify test that registers a key with
`<ActivationDate value="$NOW-3600"/>` then immediately calls the
cryptographic op. Includes the 19 CS-AC-M-OAEP tests, all 7 Decrypt
tests, both Sign tests (CS-AC-M-1, CS-AC-M-3), both MAC tests
(CS-AC-M-4, CS-AC-M-6), SignatureVerify (CS-AC-M-2), MACVerify
(CS-AC-M-5), plus BL-M-4 / SASED-M-2 (Register expects success but we
fail on a downstream op).

### Root cause

Both [`Register`](../../src/ops/register_import_export.rs#L108) and
[`Create`](../../src/ops/create.rs#L173) hard-code `state: State::PreActive,
activation_date: None`, dropping any `ActivationDate` /
`DeactivationDate` / `CompromiseDate` the request supplied. The
Encrypt handler then rejects the key with `ObjectArchived` in
[encrypt.rs:50-57](../../src/ops/encrypt.rs#L50-L57) because state ≠
Active.

### Normative reference

- KMIP 3.0 Spec §3.x **Cryptographic Object Life Cycle** — the
  Activation Date attribute drives the PreActive → Active transition.
  When the supplied date is in the past at Register time, the object
  is born Active.
- KMIP 3.0 Spec §6.1.48 (Register) — "The server SHALL assign
  attribute values when not specified by the client" — i.e. an
  attribute that IS specified must be honoured.
- KMIP Profiles v3.0 §5.1.2 Baseline Server item 5 — Activation Date
  is in the Baseline attribute set the profile requires the server to
  process.

### Remediation

In both `Register` and `Create` (and the symmetric +
`CreateKeyPair` paths), after attribute extraction, compute initial
state from the supplied dates:

```rust
fn initial_state(now: OffsetDateTime, attrs: &TemplateAttributes) -> State {
    if attrs.compromise_date.map_or(false, |d| d <= now) { State::Compromised }
    else if attrs.deactivation_date.map_or(false, |d| d <= now) { State::Deactivated }
    else if attrs.activation_date.map_or(false, |d| d <= now) { State::Active }
    else { State::PreActive }
}
```

Store the date attributes alongside the computed state. Wire the same
helper into `Create` and `CreateKeyPair` per-half (each half can have
its own activation date in `CommonAttributes` / `PrivateKeyAttributes`
/ `PublicKeyAttributes`).

### Risk

Low. The existing handlers ignore these inputs; honouring them
matches both the OASIS expectation and the FSM in
`docs/IMPLEMENTATION_PLAN.md` §3.4.

---

## Family R2 ⭐ — `CreateKeyPair` collapses per-half attributes

**Tests impacted (~6 of bucket C + bucket A):** AKLC-M-1, AKLC-M-2,
AKLC-M-3, SKLC-M-1, SKLC-M-2, SKLC-M-3, SKLC-O-1 — every CreateKeyPair
test that gives the private and public halves *different*
`CryptographicUsageMask` (e.g. private=Sign, public=Verify) and then
calls `GetAttributes` expecting per-half values.

### Root cause

[`extract_template` in create_key_pair.rs:247-…](../../src/ops/create_key_pair.rs#L247)
chains `common ∥ private ∥ public` into one iterator and overwrites a
single `usage: Option<UsageMask>` cell. The last attribute wins and
both halves receive the same mask. Same bug for any per-half
attribute (Name, ActivationDate, CryptographicParameters…).

### Normative reference

- KMIP 3.0 Spec §6.1.10 **CreateKeyPair** — the request body has
  three distinct attribute baskets (Common, Private Key, Public Key).
  Common is merged into BOTH halves; Private Key is applied to the
  private record only; Public Key to the public record only.
- KMIP Profiles v3.0 §4.1.1 item 20 — additional server-side
  attributes are tolerated, but *missing* spec-mandated attributes
  are non-conformant.

### Remediation

Refactor `extract_template` into three calls
(`extract_one(common)`, `extract_one(common + private)`,
`extract_one(common + public)`). Pass two `ObjectRecord` builders to
`deps.store.put` — one per half.

Same change unlocks per-half Name, Activation Date, Cryptographic
Parameters (CS-AC-M-OAEP-* OAEP params live in
PublicKeyAttributes), and per-half ID.

### Risk

Low. Mechanical refactor in a single file; existing unit tests
already exercise the merged path and can be updated.

---

## Family R3 ⭐ — `Get` does not return the registered KeyMaterial

**Tests impacted (4 of bucket E1):** BL-M-1, BL-M-3, BL-M-6, BL-M-14
— every Register-then-Get round-trip on a Raw or X.509-format key.

### Root cause

[`get.rs:75-105`](../../src/ops/get.rs#L75-L105) returns a zero buffer
when `deps.engine_session` is `None` (the production binary's default
case for the in-memory store). It never reads `obj.key_material` that
`Register` has already stored at
[`register_import_export.rs:117`](../../src/ops/register_import_export.rs#L117).

### Normative reference

- KMIP 3.0 Spec §6.1.21 **Get** — the response carries the managed
  object exactly as the server holds it. Returning a substituted
  buffer is non-conformant.
- KMIP Profiles v3.0 §4.1.1 item 7 carves out "key material returned
  for managed cryptographic objects which are generated by the
  server" — that exemption does **not** apply to Register, where the
  client supplied the material.

### Remediation

Three-tier lookup in `get.rs`:

```rust
let key_value = obj.key_material.clone()
    .or_else(|| read_from_engine_session(&deps, &obj))
    .unwrap_or_default(); // empty rather than zeros
```

For BL-M-3 (KeyMaterial child count 1 != 0 on the response), inspect:
test registers a DSA key with `<KeyMaterial><P/><Q/>…</KeyMaterial>`
structured form. Our encoder treats KeyMaterial as ByteString
unconditionally, emitting one ByteString child where expected has
zero (the structured P/Q/G/Y replaces KeyMaterial bytes entirely).
Either store the structured key material as-is or refuse to register
non-Raw key formats (returning a proper `KeyFormatTypeNotSupported`
result reason 0x10 per spec §11 Result Reason).

BL-M-12 / BL-M-13 / BL-M-5 (3 of bucket F) are the failure-side
manifestation of the same gap: TransparentDSAPublicKey isn't a
KeyFormatType our decoder recognises, so the whole RequestMessage
fails decode → wire_error_response emits a BatchItem with
`operation: None`, child-count goes 4 → 2 once ResultMessage drops.

### Risk

Medium. KeyMaterial round-trip for Raw is trivial. Structured
KeyMaterial (TransparentDSA/RSA Public/Private Key) requires
decoding nested BigIntegers per Spec §6.2 KeyValue / §6.2.1 Key
Material — non-trivial but scoped to the codec layer.

---

## Family R4 🟨 — Wrong `ResultReason` code

**Tests impacted (3 of bucket B + 2 of bucket A):** BL-M-8, CS-AC-M-8,
CS-BC-M-14 directly; plus CS-RNG-O-4 (RNGSeed fails with wrong
reason).

### Root cause + remediation

Three discrete code mappings to add:

| Scenario                                               | Currently returned                                   | Spec-mandated                                            | Where to fix                                                            |
| ------------------------------------------------------ | ---------------------------------------------------- | -------------------------------------------------------- | ----------------------------------------------------------------------- |
| Register with duplicate Name                           | `InvalidField` (0x07)                                | **`NonUniqueNameAttribute` (0x35)** per §11 Result Reason | `register_import_export.rs` duplicate-name detection                    |
| Crypto-op on `Deactivated` / `Compromised`             | `ObjectArchived` (0x0d)                              | **`WrongKeyLifecycleState` (0x43)** per §11              | `encrypt.rs`, `decrypt.rs`, `sign.rs`, `signature_verify.rs` state gate |
| RNGSeed without sufficient permission                  | (varies, currently `InvalidField`)                   | `OperationNotSupported` per Spec §6.1.55                 | `rng_and_pkcs11.rs::rng_seed`                                           |

**Normative reference:** OASIS extraction
`spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json` enum `Result
Reason` confirms both codepoints (0x35 = "Non Unique Name Attribute",
0x43 = "Wrong Key Lifecycle State"); they map 1-1 to the names the
tests expect.

### Risk

Trivial. New variants in `error::ResultReason` + new constructors
+ swap the call sites.

---

## Family R5 🟨 — `CreateCredential` rejects valid `CredentialType=Password`

**Tests impacted (5 of bucket A):** BL-M-15, BL-M-16, BL-M-17, plus 2
more in the BL-M-CreateCredential series.

### Root cause

[`session_and_auth.rs:55`](../../src/ops/session_and_auth.rs#L55) hard-
gates `req.credential_type != 0x01` → `OperationNotSupported`. The
OASIS test uses `CredentialType = Password = 0x07`.

### Normative reference

- KMIP 3.0 Spec §11 **Credential Type** enum (verified against
  `kmip-spec-3.0-tags-enums.json`): 0x01 UsernameAndPassword, 0x05
  HashedPassword, **0x07 Password**, 0x08 Certificate.
- §6.1.9 CreateCredential — server MUST support every CredentialType
  it advertises in Query (Baseline silently includes Password).

### Remediation

Replace the strict `== 0x01` gate with a list of accepted credential
types (0x01, 0x05, 0x07 at minimum). Persist credential material per
type; for `0x07 Password`, the payload is a `<PasswordCredential>`
containing only `<Password>` (no `<Username>`), as the test shows.

### Risk

Low.

---

## Family R6 🟨 — Per-attribute response gaps in `GetAttributes`

**Tests impacted (5 of bucket C):** SKFF-M-11, SKFF-M-12, AKLC-* extra
attributes, plus the `RandomNumberGenerator` cases.

### Root cause

`get_attributes.rs::attributes_from_record` doesn't emit
`RandomNumberGenerator` for any object, and emits
`CryptographicUsageMask` with the *merged* mask (Family R2 again).
SKFF-M-11 specifically expects `<RandomNumberGenerator>` as a
substructure with `RNGAlgorithm`, `CryptographicAlgorithm`,
`CryptographicLength`.

### Normative reference

- KMIP 3.0 Spec §6.2 **Random Number Generator** attribute — every
  managed cryptographic object may carry an RNG-source attribute
  describing how the server generated the material.
- KMIP Profiles v3.0 §4.1 Response Variations item 6 — "RNG …  the
  value returned may vary". So we may pick any valid RNG identifier.

### Remediation

1. Add `random_number_generator: Option<RandomNumberGenerator>` to
   `ObjectRecord` (the Baseline attribute set we already extended).
2. Default-populate it in `Create` / `CreateKeyPair` with the engine's
   advertised RNG (e.g. `RNGAlgorithm = ANSIX9_31`,
   `CryptographicAlgorithm = AES`, `CryptographicLength = 256`).
3. Surface in `attributes_from_record` + `attribute_name` +
   `attribute_present` (already wildcarded).

### Risk

Low.

---

## Family R7 🟨 — Multi-BatchItem dispatch swallowed by per-message decode error

**Tests impacted (4 of bucket G + parts of F):** AX-M-1, AX-M-2,
TL-M-2, TL-M-3 — the only multi-batch tests in the corpus.

### Root cause

[`wire.rs::decode_request_message`](../../src/kmip30/wire.rs#L223) is
"all-or-nothing": one BatchItem's payload failing to decode causes
the entire RequestMessage decode to error, and
[`listener.rs::wire_error_response`](../../src/server/listener.rs#L175)
emits exactly one BatchItem (no Operation echo). AX-M-1 has 4
BatchItems with legacy KMIP 1.x `<Attribute>` envelopes containing
VendorIdentification/AttributeName/AttributeValue triples — even
though our codec silently skips unknown envelopes, the
`Attributes` container ultimately has an Attribute child with an
unrecognised inner shape and decoding can fail at the BigInteger /
Sensitive boolean inner fields.

### Normative reference

- KMIP 3.0 Spec §8.1.3 / §8.2.3 — Batch Items are positionally
  correlated. The server SHALL return one response BatchItem per
  request BatchItem, in order, including failure responses.
- §9.5 / §9.5.1 Batch Error Continuation Option — `Stop` (default),
  `Undo`, `Continue` modes are all defined; the request header in
  AX-M-1 sets `<BatchErrorContinuationOption value="Undo"/>` but a
  decode error before reaching the per-item dispatch means the
  option never gets honoured.

### Remediation

Two-phase decode:

1. **Frame split** — split `RequestMessage` into header + a
   `Vec<TtlvFrame>` of BatchItem frames *without* parsing each
   payload yet. This must always succeed (only Structure/length
   parsing).
2. **Per-item decode + dispatch** — parse each BatchItem's payload
   inside the dispatcher loop. On payload-decode failure, emit a
   ResponseBatchItem with `operation: Some(echoed)`, ResultStatus =
   OperationFailed, ResultReason = InvalidMessage, ResultMessage =
   diagnostic. The other BatchItems keep flowing per the
   `BatchErrorContinuationOption` policy.

Step 1 alone fixes the multi-batch count; step 2 fixes the
"no Operation echo" tail.

### Risk

Medium. Touches the dispatcher/codec boundary. Worth a dedicated PR.

---

## Family R8 🟦 — `Query` non-list child shape (2 cases)

**Tests impacted:** SASED-M-1, TL-M-1 — Query with
`QueryServerInformation` + `QueryApplicationNamespaces`.

### Root cause

We currently emit only `ServerInformation` (no
`ApplicationNamespace`) when the request asks for both
`QueryServerInformation` + `QueryApplicationNamespaces`. The Query
response shape per Spec §6.1.39 includes `ApplicationNamespace`
TextString entries (zero or more) which we don't generate.

### Normative reference

- KMIP 3.0 Spec §6.1.39 **Query** response — `ApplicationNamespace`
  is part of the response payload alongside `VendorIdentification`
  and `ServerInformation`.
- KMIP Profiles v3.0 §4.1.1 item 14 — "Application Namespaces
  reported in Query for function Query Application Namespaces" are
  variable items. So content varies; presence depends on whether
  `QueryApplicationNamespaces` was requested.

### Remediation

Add `application_namespaces: Option<Vec<String>>` to `QueryResponse`;
emit a single TextString (e.g. `"pqctoday.io/baseline"`) when the
request asks for it.

### Risk

Trivial.

---

## Family R9 🟦 — `PKCS11-M-1` payload shape

**Tests impacted (1 of bucket E2):** PKCS11-M-1.

### Root cause

ResponsePayload child count 3 vs 2 — our encoder emits an extra
field (likely `PKCS_11OutputParameters` always-present, expected
case omits it when empty).

### Remediation

Emit `PKCS_11OutputParameters` only when non-empty, per Spec
§6.1.42 "Output Parameters: optional".

### Risk

Trivial.

---

## Family R10 🟦 — SASED-M-3 / SKFF-M-5/7/9 — Locate / Activate payload extras

**Tests impacted (4 of bucket E2):** SASED-M-3 (Locate), SKFF-M-5,
SKFF-M-7, SKFF-M-9 (Activate / Get sequences).

### Root cause

Suspected: Locate payload emits `LocatedItems` even when the request
didn't include an `OffsetItems` field (Response Variation item 7 says
this MAY be present, but the test apparently picks "no extras"). And
Activate emits `UniqueIdentifier` on success even though the test
expects an empty payload in some cases.

Need bench inspection per test before fixing.

### Risk

Low after one round of XML inspection.

---

## Family R11 🟦 — RSA-OAEP parameters not applied at Encrypt time

**Tests impacted (~19 of bucket A — overlap with R1):** all
CS-AC-M-OAEP-* tests. The RSA Encrypt handler ignores the OAEP
padding/MGF1/SHA-256 parameters stored on the key.

### Root cause

[`encrypt.rs::encrypt_classical`](../../src/ops/encrypt.rs#L154)
unconditionally calls `softhsmrustv3::native::encrypt(...)` with
`CKM_AES_GCM` — that's the only branch, even for RSA.

### Remediation

Branch on `obj.algorithm`:
- AES → CKM_AES_GCM (current path)
- RSA → look up the key's `CryptographicParameters` for
  `PaddingMethod` + `HashingAlgorithm` + `MaskGenerator{,HashingAlgorithm}`
  and select the OASIS-mandated mechanism
  (CKM_RSA_PKCS_OAEP with `CKM_SHA256`/`CKG_MGF1_SHA256` parameters
  for the SHA-256/MGF1 cases).

### Risk

Medium. Requires plumbing `CryptographicParameters` through the
ObjectRecord (already in Option B) and assembling the
`CK_RSA_PKCS_OAEP_PARAMS` C struct via the softhsmrustv3 bridge.

---

## Summary table

| Family | Test count | Difficulty | Suggested PR        |
| ------ | ---------- | ---------- | ------------------- |
| R1     | ~39        | Low        | PR #89 — date FSM   |
| R2     | ~6         | Low        | PR #89 — date FSM   |
| R3     | 4          | Medium     | PR #90 — KeyBlock   |
| R4     | 5          | Trivial    | PR #89 — date FSM   |
| R5     | 5          | Low        | PR #89              |
| R6     | 5          | Low        | PR #89              |
| R7     | 4          | Medium     | PR #91 — multibatch |
| R8     | 2          | Trivial    | PR #89              |
| R9     | 1          | Trivial    | PR #89              |
| R10    | 4          | Low        | PR #89              |
| R11    | ~19        | Medium     | PR #92 — RSA-OAEP   |

R1+R2+R4+R5+R6+R8+R9+R10 land together as a "single coherent dispatcher
fixes" PR (~67 tests). R3 (KeyBlock round-trip), R7 (multi-batch
isolation), R11 (RSA-OAEP) follow as separate PRs.

**Projected PASS:** 11 → ~78 / 102 after PR #89 + #90 + #91 + #92,
provided the test corpus has no further hidden interactions.

---

## Open clarifications for the reviewer

1. **Family R3 / structured key material.** The Baseline Server profile
   §5.1.2 doesn't enumerate the KeyFormatTypes a Baseline server must
   support. Spec §6.2 lists Raw, Opaque, X_509, PKCS_1, PKCS_8, and
   Transparent{RSA,DSA,EC,DH,ECDSA,Symmetric}{Public,Private}Key. **Question:**
   for v0.1, is the right call to support Raw + X_509 + PKCS_8 (the
   forms BL-M-* uses) and return
   `KeyFormatTypeNotSupported` (0x10) for the Transparent\* variants
   the rest of the corpus uses? Or do we need full TransparentDSA
   round-trip?

2. **Family R7 / Batch error continuation.** Spec §9.5.1 defines
   `Stop`, `Undo`, `Continue`. AX-M-* uses `Undo`. Implementing `Undo`
   requires journaling each BatchItem's side effects so we can roll
   them back when a later item fails. **Question:** is `Stop` (default)
   sufficient for the immediate compliance bar, with `Undo`/`Continue`
   deferred?

3. **Family R11 / RSA-OAEP encryption.** The OAEP parameters live on
   the **key**'s `CryptographicParameters` attribute, not on the
   `Encrypt` request. **Question:** confirm this design point — the
   test only sends `<UniqueIdentifier>` + `<Data>` in the Encrypt
   request, no `CryptographicParameters` override at op time. KMIP
   3.0 §6.1.21 allows both; we should implement key-attached params
   first.

4. **Family R10 / Activate response payload shape.** SKFF-M-5 expects
   an *empty* Activate ResponsePayload while we emit
   `<UniqueIdentifier>`. Spec §6.1.1 Table 252 lists UID as the only
   response field but doesn't mark it optional. **Question:** is
   OASIS treating this as a Response Variation, or is the test
   wrong?  (May need a web check against the OASIS errata.)

5. **Family R4 / `Bad Cryptographic Parameters` (0x24).** Several
   `Encrypt` failure cases not in the 51 might surface this code once
   R11 lands and we start rejecting unsupported parameter
   combinations. Should we audit those cases as a follow-up?

6. **Comparator scope.** We chose to add `VendorIdentification` to
   the variable-item set per §4.1 Response Variations item 5. Item 5
   says "value (if included) may vary" — i.e. the *value* varies but
   we already require presence (otherwise the Query non-list-child
   count mismatches). **Question:** any objection to keeping
   presence-required + value-variable for this tag?
