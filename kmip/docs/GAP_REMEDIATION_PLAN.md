# Post-"Honest Maximum" Gap Remediation Plan

> **Status:** PLAN (not yet executed) · **Authored:** 2026-07-08 · **Revised:** 2026-07-08 (v2)
> **Source:** an 8-agent parallel audit of `rust/` (PKCS#11 engine, 31.5k lines) and `kmip/`
> (KMIP 3.0 server, 44.8k lines), run immediately after `HONEST_MAXIMUM_PLAN.md` shipped
> (v0.12.0), specifically hunting for stub/fake/silently-dropped behavior that plan's own
> scope didn't cover.
> **Headline result:** `rust/` came back clean (0 functional findings, a few stale comments).
> `kmip/` has **9 real gaps** (2 of them security-relevant, not just honesty-relevant) and
> **4 medium-priority gaps**, concentrated in areas `HONEST_MAXIMUM_PLAN.md` didn't touch:
> attribute mutation, Register/Destroy, and wire-layer round-tripping.

**Anchor:** every finding below is cited to a real `file:line`. v1 of this plan was itself
audited before any code was touched — every phase's claims were independently re-verified
against source (and, for attribute-modifiability claims, against the actual KMIP 3.0 spec
attribute-rules tables, not assumption). **That pass found 5 concrete errors in v1**, all
corrected below and marked `[v2 correction]`. The remaining 8 findings held up under direct
re-verification with zero changes. Treat this document, not v1, as authoritative — the
correction history is kept inline rather than hidden so the *type* of error (a false
dependency claim, three spec-contradicting classifications, an unverified effort estimate, an
overstated risk level) stays visible for whoever executes this.

---

## 0. Scope and non-scope

**In scope:** the 13 numbered findings from the audit (9 high, 4 medium), all in `kmip/`.

**Out of scope for this plan** (tracked here for completeness, fixed opportunistically, not
phased): a handful of stale doc comments in `rust/` (`ck_abi.rs`, `constants.rs`, `sign.rs`
module doc, `lms.rs` dead code) and in `kmip/` (`ops/session_and_auth.rs`, `ops/mod.rs`,
`policy/rule.rs`'s `MaxKeyAgeDays` comment, `auditlog/mod.rs`'s status table) that describe
behavior which has since been fixed and were never updated. None of these change behavior —
see §9 for the full list and a one-pass cleanup task.

**Before starting any phase:** re-verify that phase's specific claims against current source
as T0, not a formality — this is the single practice that caught all 5 v1 errors. Findings
age; line numbers drift; a subagent's synthesis (or a plan author's own paraphrase of one) can
misstate a dependency or a spec rule with total confidence. Don't skip this because the
finding "already sounds verified" in this document.

---

## 1. Phase A — Security: Destroy must actually destroy (P0)

**Finding #1.** `kmip/src/ops/destroy.rs:85-112`. For objects imported via `Register` (not
engine-generated), the raw key bytes live in `ObjectRecord.key_material` in the KMIP store
itself (`store/traits.rs:94-99`). `Destroy` calls `native::destroy_object` on the engine
handle *if one exists*, flips `state`/`destroy_date`, and calls `store.update(obj)` — but
never clears `key_material`. `Export`'s own code filters `key_material` at *read* time
specifically because Destroy never clears it at the *source* — this is a load-bearing
workaround for a bug, not a design choice.

**Why this is P0, not just an honesty gap:** a "destroyed" key's plaintext bytes remain
fully recoverable (store dump, DB backup, memory inspection) indefinitely. This is the kind
of gap that fails an actual security review, not just a corpus-honesty review.

- **T1** In `destroy()`, after the engine-handle destroy (or when no engine handle exists),
  zero and clear `obj.key_material` (`Some(vec)` → `None`, zeroizing the vec's backing bytes
  first — this repo already depends on the `zeroize` crate elsewhere per `rust/Cargo.toml`,
  reuse that discipline here rather than a bare `drop`).
- **T2** Audit every other place `key_material` is read to confirm none of them need it
  post-Destroy for a legitimate reason (Export already correctly refuses to return it for a
  Destroyed object — after T1 that check becomes redundant-but-harmless defense in depth,
  leave it in place rather than removing it).
- **T3 `[v2 correction]`** T1 alone is necessary but **not sufficient** for the `SqliteStore`
  backend. Verified: `store/sqlite.rs`'s connection setup (`~line 76-84`) configures
  `journal_mode = WAL`, `synchronous = NORMAL`, `busy_timeout`, `foreign_keys` — **no
  `PRAGMA secure_delete`**. Without it, SQLite doesn't overwrite deleted content; it marks
  the page free for reuse, and the WAL file can retain the old plaintext until checkpointed.
  Clearing `key_material` in Rust and calling `store.update()` therefore does NOT guarantee
  the bytes are gone from disk — add `PRAGMA secure_delete = ON` (or `FAST`, which limits the
  overwrite to pages actually containing the deleted data — cheaper, still real) to the same
  connection-setup block. Confirm this doesn't have an unacceptable write-amplification cost
  given this store's actual write volume before picking `ON` vs `FAST`.
- **T4** New test: Register a `SecretData`/`SymmetricKey` with `key_material` set, Destroy it,
  assert `store.get(uid).unwrap().key_material.is_none()`. Also assert Export against the
  destroyed UID still correctly fails (regression-proofing the existing behavior, not just
  the new one). A disk-level "is the plaintext actually gone" test isn't practical in a unit
  test — T3's PRAGMA is the control for that; don't try to assert it via file inspection.
- *Exit:* no `ObjectRecord` in any store backend carries `key_material: Some(_)` once its
  `state == Destroyed`, **and** the SQLite backend is configured not to leave the old bytes
  recoverable in freed pages/WAL.

*(S / P0 — small, isolated, no dependency on other phases. T3 raised the scope slightly but
is still contained to one connection-setup block.)*

---

## 2. Phase B — Security/honesty: SetAttribute stops lying about success (P0)

**Finding #2.** `kmip/src/ops/attribute_mutate.rs:239-267,637`. `apply_attribute`'s final
match arm is a bare `_ => {}`, documented as "read-only or server-managed... a no-op" — but
it also silently swallows attribute types that are **neither** read-only **nor** explicitly
handled. `SetAttribute`/`ModifyAttribute` on any of these returns a genuine wire `Success`
while persisting nothing.

**`[v2 correction]`** v1 bucketed 5 attributes as "genuinely settable" by inference from
context, without checking the spec's own attribute-rules tables. Re-verified directly against
`kmip-spec-v3.0.pdf` (Tables 89, 93, and the Protection Storage Mask / Key Format Type
equivalents) — **3 of the 5 were wrong**, and implementing v1's plan as written would have
shipped a *new* spec violation in the same PR meant to fix one:

| Attribute | Spec: "Modifiable by client" | Correct bucket |
|---|---|---|
| `CryptographicParameters` | **Yes** | Genuinely settable (v1 was right) |
| `UsageLimits` | **Yes — but only while `Get Usage Allocation` has not yet been performed** | Genuinely settable, **with a guard condition v1 missed entirely** |
| `CryptographicDomainParameters` | **No** | Read-only rejection (v1 wrongly said settable) |
| `ProtectionStorageMask` | **No** | Read-only rejection (v1 wrongly said settable) |
| `KeyFormatType` | **No** | Read-only rejection (v1 wrongly said settable) |

- **T1** Split the catch-all into two real cases, using the corrected table above:
  - **Genuinely settable:** `CryptographicParameters` (unconditional) and `UsageLimits`
    (conditional — see T2). Add real `apply_attribute` arms that persist them onto the
    `ObjectRecord`, mirroring how `Create`/`Register` already populate these same fields.
  - **Genuinely server-managed, currently missing from `attribute_is_read_only`:**
    `CryptographicDomainParameters`, `ProtectionStorageMask`, `KeyFormatType`, the four `Link`
    variants, `DigitalSignatureAlgorithm`, `NistKeyType`, `ProtectionLevel`,
    `RevocationReasonCode`, `DeactivationReasonCode`, `CertificateType`, `CertificateValue`,
    the four `SplitKey*` attributes: add them to `attribute_is_read_only` so `SetAttribute`
    honestly rejects with `AttributeReadOnly` (§11, same code `BL-M-7` already pins for the
    existing read-only set) instead of silently no-op'ing.
- **T2** `UsageLimits`'s guard condition: `SetAttribute(UsageLimits)` must itself check
  whether `Get Usage Allocation` has already been called against this object (track via
  whatever state already distinguishes "budget set at creation, never allocated against" from
  "at least one allocation has been granted" — `usage_limits_remaining < usage_limits_total`
  is the obvious signal if nothing more explicit exists) and reject with the spec-appropriate
  error once it has, rather than silently allowing an unbounded re-budget after allocation has
  started.
- **T3 `[v2 correction]`** v1 claimed "sequence C before B... since AdjustAttribute/
  DeleteAttribute depend on [Finding #7's] table." **Verified false by reading the call
  graph directly**: `SetAttribute`/`ModifyAttribute` (this phase) decode an inline
  `Attribute` value and never call `tag_name_from_code` at all. `AdjustAttribute` (which
  *does* use it) has its own separate, already-honest 2-attribute-only handler
  (`attribute_mutate.rs:271-323` — `CryptographicUsageMask`/`CryptographicLength` only,
  everything else already correctly rejects `OperationNotSupported`) that never calls
  `apply_attribute`. `DeleteAttribute` uses a *third*, independent name-based removal path
  (`remove_attribute_by_name`/`attribute_name_present`) that this audit did not examine —
  **flag as an unaudited area**, not a known-clean one; check it for the same class of gap
  before considering attribute mutation fully closed. **B and C have no code dependency** —
  land in either order, or in parallel.
- **T4** New tests: for `CryptographicParameters` and (pre-allocation) `UsageLimits`, a
  `SetAttribute` → `GetAttributes` round-trip proving persistence; for post-allocation
  `UsageLimits`, a rejection test; for every attribute newly moved to "read-only," a
  `SetAttribute` → `AttributeReadOnly` rejection test.
- *Exit:* `apply_attribute`'s catch-all arm is unreachable in practice — every `Attribute`
  variant either persists for real (per its actual spec modifiability rule, not inference)
  or is honestly rejected as read-only.

*(M / P0 — no dependency on Phase C. The spec-verification step in T1's table is the one to
repeat for any attribute not already covered here before assuming it's safe to make settable.)*

---

## 3. Phase C — Wire-layer round-trip fidelity

Three independent wire-layer gaps, groupable into one phase since they're all in
`kmip30/wire.rs` and share the same "decodes fine, doesn't round-trip back out" shape. **No
longer a prerequisite for Phase B** (see Phase B/T3) — can land in either order.

**Finding #7.** `wire.rs:5004-5161` — `tag_code_from_name`/`tag_name_from_code` (used
*specifically* by `AdjustAttribute`'s and `DeleteAttribute`'s numeric `AttributeReference`
resolution — confirmed via direct read, not `SetAttribute`/`ModifyAttribute` per Phase B's
correction above) omit `CryptographicDomainParameters` and all five Split Key attributes,
even though `decode_attribute_v3` fully decodes them. A numeric reference to any of these
resolves to the literal string `"Unknown"` instead of the real name, so the mutation
silently targets nothing.
- **T1** Add the missing 6 entries to both directions of the table, verified against the same
  tag constants `decode_attribute_v3`/`encode_attribute_v3` already use (no new tag values
  needed — this is purely a lookup-table gap, not a missing wire encoding).
- **T2** Test: `AdjustAttribute`/`DeleteAttribute` referencing each of the 6 attributes by
  numeric `AttributeReference` code, not just by inline `Attribute` value. Note
  `AdjustAttribute` will still honestly reject 5 of these 6 as `OperationNotSupported` per
  its own narrow attribute list (Phase B/T3) — the fix here is that it resolves the *name*
  correctly before that rejection, not that it starts accepting them.

**Finding #6.** `wire.rs:3129-3158` `encode_cryptographic_parameters` drops 7 real struct
fields present in `decode_cryptographic_parameters`/`CryptographicParameters`
(`ops.rs:1349-1413`): `tag_length`, `random_iv`, `deterministic`, `context_string`,
`internal`, `external_mu`, `random`. A PQC signing object with `Deterministic`/
`ContextString` set, or an AEAD object with `TagLength` set, loses those fields on every
`GetAttributes`/`Export` response. **Re-verified line-for-line against both functions —
accurate exactly as stated, no correction.**
- **T1** Add the 7 missing fields to the encoder, mirroring the decoder's tag constants.
- **T2** Strengthen the existing round-trip test
  (`k18_cryptographic_parameters_salt_length_decodes_and_round_trips`) to cover all fields,
  not just `salt_length` — this is the test gap that let the original bug through CI.

**Finding #8.** `wire.rs:4013-4023` `decode_register_req`'s `SecretData` arm captures the
inner `KeyBlock` but explicitly (per its own comment) drops the sibling `SecretDataType`
enum. `RegisterRequest` (`ops.rs:1721-1739`) has no field to carry it. A later `Get` reports
the hardcoded default (`Password`) regardless of what was actually registered. **Re-verified
— confirmed, and the adjacent `OpaqueObject` arm two cases below handles its own analogous
type field correctly, confirming this is an inconsistency rather than a deliberate policy.**
- **T1** Add `secret_data_type: Option<u32>` to `RegisterRequest`, decode it alongside
  `KeyBlock` in the `SecretData` arm (mirroring the adjacent `OpaqueObject` arm), and persist
  it onto the `ObjectRecord` in `register_import_export.rs`.
- **T2** Test: Register a `SecretData` with `SecretDataType=Seed(0x02)`, `Get` it back,
  assert the type round-trips instead of silently becoming `Password`.

*(M / P1 — three independent, low-risk, additive fixes; no shared state, can land as one PR
or three small ones.)*

---

## 4. Phase D — Register import honesty (RSA public keys)

**Finding #3.** `register_import_export.rs:267-293`. `let _ = native::register_rsa_public_key_der(...)`
(and two sibling calls) discard the `Result`, contradicting the file's own stated invariant
two paragraphs later ("Register must NOT succeed-then-fail-at-use"). **Independently
re-verified on both sides of the crate boundary**: the KMIP-layer comment says "PKCS_1
RSAPublicKey or PKCS_8 SubjectPublicKeyInfo — store the DER as-is" with genuinely zero
`KeyFormatType` branching (confirmed by reading the full match arm — `material` passes
straight through); the engine's `register_rsa_public_key_der`
(`rust/src/native/keygen.rs:1020-1046`) calls `RsaPublicKey::from_pkcs1_der` only and maps
any parse failure (including well-formed PKCS#8 input) to `CKR_KEY_TYPE_INCONSISTENT`. A
PKCS#8-form Register call returns wire `Success` with a stored `ObjectRecord`, but no engine
object exists — a later `SignatureVerify` against it fails with an unrelated "not found"
error instead of `Register` honestly rejecting the malformed input.

- **T1** Replace all `let _ = native::register_*(...)` in this file with `.map_err(...)?`,
  matching the PQC/HSS import blocks in the same file that already do this correctly.
- **T2** Either (a) add real PKCS#8→PKCS#1 conversion before calling
  `register_rsa_public_key_der` so the doc comment's claimed PKCS#8 support becomes real, or
  (b) narrow the doc comment to "PKCS#1 only" and make the handler reject PKCS#8 input with a
  clear `InvalidField`/`KeyFormatTypeNotSupported` error instead of silently succeeding.
  **Recommend (a)** — PKCS#8 SPKI is the more common wire format for RSA public keys in
  practice, so silently narrowing support is a bigger behavioral regression for real clients
  than adding the conversion. `[v2 correction]` v1 estimated this conversion at "~10 lines" —
  **that was an unverified guess, not a checked estimate; nobody prototyped it.** The `rsa`
  crate's `pkcs8::DecodePublicKey` trait (the `pkcs8` crate is already a dependency per
  `rust/Cargo.toml`) likely makes `RsaPublicKey::from_public_key_der(der)` a drop-in fallback
  when `from_pkcs1_der` fails, which would keep this small — but confirm the trait impl and
  actual API before committing to (a)'s effort size; if it turns out to need manual ASN.1
  surgery instead, reconsider (b).
- **T3** Test: Register an RSA public key in both PKCS#1 and PKCS#8 form (via T2's chosen
  fix), confirm both produce a working engine object usable by a subsequent
  `SignatureVerify`; test that a genuinely malformed key now fails `Register` itself, not a
  later operation.
- *Exit:* no `register_*` call in this file has its `Result` discarded.

*(M / P1 — T1 is mechanical; T2's real effort is unknown until the `pkcs8` trait is checked
— do that check first, before estimating further.)*

---

## 5. Phase E — CryptographicParameters persistence gaps

Two related findings, both about a field not making it onto the stored `ObjectRecord` where
it should. **Both re-verified directly, no corrections — held up exactly as v1 described.**

**Finding #5.** `create_key_pair.rs` (~lines 331, 403). Re-verified: the shared
`extract_attrs` helper (`register_import_export.rs:807-850`) genuinely parses
`CryptographicParameters` into `priv_x.cryptographic_parameters`/
`pub_x.cryptographic_parameters` (confirmed at line 831) — `create_key_pair.rs` simply never
reads that field on either struct (zero matches on a direct grep for the field name in the
file). Unlike `create.rs`, `register_import_export.rs`, and `derive_key.rs`, which all
persist this field correctly. A key's declared default padding/hash (e.g. PSS/SHA-384) is
silently lost; later bare Sign/Verify falls back to the mechanism default.
- **T1** Add `cryptographic_parameters: Some(parsed)` to both `deps.store.put(...)` calls in
  `create_key_pair.rs`, mirroring `create.rs`'s existing pattern exactly.
- **T2** Test: CreateKeyPair with an explicit `CryptographicParameters` template (e.g. RSA +
  PSS + SHA-384), confirm `GetAttributes` reports it back and a bare `Sign` (no per-request
  override) actually uses PSS/SHA-384 rather than the mechanism default.

**Finding #13.** `create_key_pair.rs` never checks a client's `QuantumSafe=true` claim
against the resolved algorithm. Re-verified: `create.rs:137-151` performs this check
(citing the real OASIS `QS-M-2` corpus test), a direct grep for `QuantumSafe`/`quantum_safe`
in `create_key_pair.rs` returns zero hits.
- **T1** Port the same check from `create.rs` into `create_key_pair.rs`.
- **T2** Test: CreateKeyPair(RSA, QuantumSafe=true) → rejected, matching `create.rs`'s
  existing test for the same scenario.

*(S / P1 — both fixes are "copy the pattern that already exists two files over," low risk.)*

---

## 6. Phase F — Encrypt/Decrypt parameter fidelity for engine-resident keys

**Finding #4.** `encrypt.rs:631`, `decrypt.rs:296`. For `Create`/`CreateKeyPair`'d keys
(engine-resident, no `key_material` in the KMIP store), Encrypt/Decrypt call
`native::encrypt`/`decrypt(session, handle, mech, data, iv)` — confirmed by reading the
function directly (`rust/src/native/encrypt.rs:557-605`) to have **no AAD, tag-length, or
OAEP-hash parameters at all**; the `CKM_AES_GCM` arm hardcodes empty AAD with a comment
admitting it, and `CKM_RSA_PKCS_OAEP` hardcodes SHA-256 defaults with a similar comment.
Those client-supplied values are only wired through on the `Register`'d-key (raw-material)
path.

`[v2 correction]` v1 flagged this as the highest-risk phase ("M–L... higher risk than the
others because it changes a function signature multiple call sites depend on") and treated it
as needing new engine-layer design work. **That overstated the risk.** Directly reading the
target function revealed `native::encrypt_with_key_bytes`
(`rust/src/native/encrypt.rs:702-744`) **already contains the complete real logic** — it's
essentially the same match arms as `encrypt()`, with `aad`/`tag_len`/`oaep` genuinely threaded
through to `aes_gcm_encrypt`/`rsa_oaep_encrypt`. The engine code's own comment on the gap
(`encrypt.rs:572-574`) points at this exact function as the reference implementation. This is
a plumbing/refactor task — reuse the existing, already-correct match body for the
handle-based path — not new cryptography.

- **T1** Refactor the shared match logic out of `encrypt_with_key_bytes`/
  `decrypt_with_key_bytes` into a private helper both the raw-bytes path and a new/extended
  handle-based path call, then extend `native::encrypt`/`native::decrypt`'s signature to
  accept the same optional AAD/tag-length/OAEP-hash parameters, resolving the key bytes via
  the existing `get_object_value(key_handle)` call already present in `encrypt()` and handing
  them to the shared helper.
- **T2** Update every existing caller of `native::encrypt`/`decrypt` in `kmip/` (not just
  Encrypt/Decrypt's own handlers — check `helpers.rs` and any other call site) to pass the
  new parameters instead of silently omitting them.
- **T3** Test: Encrypt/Decrypt an engine-generated AES-GCM key with real AAD, confirm it's
  genuinely authenticated (tampering the AAD on decrypt fails); Encrypt with an engine-
  generated RSA key + explicit non-default OAEP hash (e.g. SHA-384 instead of SHA-256),
  confirm the real hash was used (cross-check against an independent OAEP implementation, not
  just "no error").
- *Exit:* AAD/tag-length/OAEP-hash behave identically regardless of whether the key came from
  `Create`/`CreateKeyPair` or `Register` — ideally because both paths now call the *same*
  underlying match body, not two parallel implementations that happen to agree.

*(M / P1 — downgraded from v1's M–L: the crypto logic already exists and is proven correct by
`encrypt_with_key_bytes`'s own callers; this is call-site plumbing + a signature extension,
not new engine design. Still the only phase touching `rust/`, still worth care on the
multi-call-site update in T2.)*

---

## 7. Phase G — Dispatcher Undo / IDPlaceholder completeness

**Finding #9.** `dispatcher/mod.rs`'s `newly_created_uids` doesn't match
`ResponsePayload::Encapsulate`/`Decapsulate`/`CreateSplitKey`/`JoinSplitKey` — every other
UID-producing op is handled, these four fall through the `_ => Vec::new()` catch-all.
**Re-verified by reading both functions in full — confirmed on both:**
`newly_created_uids` (`dispatcher/mod.rs:645-678`) has arms for Create, CreateKeyPair,
Register, Import, CreateCredential, CreateGroup, CreateUser, DeriveKey, ReKey, ReKeyKeyPair,
Certify, ReCertify, and Sign's `rekeyed` field — genuinely nothing for the four PQC/Split-Key
ops. `update_id_placeholder` (`dispatcher/mod.rs:760-790`) has the identical gap. Two
consequences: (a) a batch `Undo` after one of these ops succeeds leaks the newly-created
object instead of rolling it back; (b) a later batch item referencing `$IDPlaceholder` after
one of these fails with a spurious "ID Placeholder not set" error.

Note: `EncapsulateResponse.rekeyed: Option<EncapsulateRekeyInfo>` already carries a doc
comment stating it exists specifically so the dispatcher can find both new-key halves on
rollback — the field was built for this and never wired up.

- **T1** Add match arms for all four response types in `newly_created_uids`:
  `Encapsulate` → the new Secret Data object's UID (+ `rekeyed`'s two UIDs when present, same
  pattern `Sign`'s arm already uses for its own `rekeyed` field); `Decapsulate` → its new
  shared-secret UID; `CreateSplitKey` → all `uids`; `JoinSplitKey` → its `uid`.
- **T2** Add the same four arms to `update_id_placeholder`.
- **T3** Test: a 2-item batch with `BatchErrorContinuationOption::Undo` where item 1 is one
  of the four ops and item 2 deliberately fails — assert item 1's object is genuinely gone
  from the store after Undo (not just relabeled `OperationUndone` in the response). Separately,
  a 2-item batch where item 1 is one of the four ops and item 2 references
  `$IDPlaceholder` — assert it resolves to the real UID instead of failing.
- *Exit:* `newly_created_uids`/`update_id_placeholder` handle every `ResponsePayload` variant
  that mints a UID — cross-check against the full enum rather than eyeballing.

*(S / P1 — small, mechanical, no engine changes, but worth real tests since the bug is a
silent object leak, not a loud failure.)*

---

## 8. Phase H — Remaining medium-priority gaps

Three independent, low-effort items — batch together, no shared code. All three re-verified
directly; two carry a clarifying note that changes context but not the fix.

**Finding #10 — Locate filters most attributes silently.** `locate.rs:229-258`'s
`build_filters` recognizes exactly 7 attribute types (`CryptographicAlgorithm`, `ObjectType`,
`State`, `Name`, `ApplicationSpecificInformation`, `GroupLink`, `ObjectGroup` — confirmed by
reading the function); anything else hits `_ => {}` and is dropped, so filtering by e.g.
`CryptographicLength` is accepted as valid syntax and silently ignored (over-broad results,
not an error). `[v2 clarification]` checked `LocateRequest`
(`kmip30/ops.rs:553-566`) and confirmed `StorageStatusMask` is a **separate, dedicated
top-level field**, not routed through `build_filters`'s generic `Attribute` list at all — it
is genuinely implemented (3 existing tests) and **entirely unaffected by this gap**. Scope
this fix to the generic attribute-list filters only; don't touch `StorageStatusMask` handling.
- **T1** Either implement filters for the highest-value missing attributes
  (`CryptographicLength`, `CryptographicUsageMask`, `UniqueIdentifier` at minimum — check
  which ones the OASIS corpus's Locate tests actually exercise, since those already pass and
  shouldn't regress), or make the decoder reject a Locate template containing an
  unsupported filter attribute with a clear error instead of silently ignoring it. **Prefer
  implementing the filters** — a Locate that returns too much is less harmful than one that
  starts erroring on previously-silently-accepted templates, but confirm against whichever
  real clients/tests currently send these before deciding.
- **T2** Test: Locate with a `CryptographicLength` filter, confirm results are genuinely
  narrowed, not just "doesn't error."

**Finding #11 — AlternativeName Type is hardcoded/discarded.** `wire.rs:2788-2803` (decode)
keeps only the Value half of the `AlternativeName` Structure; `wire.rs:4881-4887` (encode)
always emits `Type=1` ("Uninterpreted Text String") regardless of what was set. Register with
`Type=URI` → GetAttributes always reports `Type=1`. `[v2 clarification]` the decode side's
own comment reveals this was a **known, deliberate trim from earlier this session**
("Honest-Maximum Phase 2.1... the Type enumeration isn't read back by anything downstream
yet"), found via the OASIS TL-M-2/TL-M-3 transcripts at the time — not a freshly-discovered
silent bug. This is a documented deferred item finally getting completed, not a new
regression. Doesn't change the fix.
- **T1** Add a `Type` field wherever `AlternativeName`'s value is currently stored, decode +
  persist + encode it for real.
- **T2** Test: Register with `AlternativeNameType=URI(2)`, confirm it round-trips.

**Finding #12 — SQLite store doesn't re-assert immutable dates on update.** Re-verified both
functions directly: `MemoryStore::update` (`store/memory.rs:59-75`) fetches the existing
record's `initial_date`/`original_creation_date` and overwrites the incoming record's fields
with them before persisting — genuine defense-in-depth. `SqliteStore::update`
(`store/sqlite.rs:196-250`) fetches only `state` (a targeted `SELECT state FROM objects`) for
the FSM check, then serializes and writes the full passed-in record with no re-assertion.
Confirmed as described, no correction.
- **T1** Port the same re-assertion `MemoryStore::update` does into `SqliteStore::update`, so
  both backends give the identical guarantee `store/lifecycle.rs`'s doc comment claims for
  "this layer."
- **T2** Test: call `update()` with a mutated `initial_date` against both backends, assert
  both silently correct it back to the original rather than only one of them doing so.

*(S / P2 — each is a small, contained fix; can be split across 3 tiny PRs or done together.)*

---

## 9. Phase I — Doc-only cleanup (no behavior change)

One pass fixing stale comments found incidentally during the audit — none affect behavior,
grouped here so they're tracked rather than silently forgotten:

| File | Stale claim | Reality |
|---|---|---|
| `kmip/src/ops/session_and_auth.rs:1-6` | "acknowledge-only... Phase 12" | Login/Logout ticket issuance/expiry/invalidation is real (Phase 1.4, shipped) |
| `kmip/src/ops/mod.rs:34` | "v0.1 uses placeholders so tests run without a token" | Extensive real PKCS#11 engine wiring exists now |
| `kmip/src/policy/rule.rs:136-138` | "`MaxKeyAgeDays` never fires" | `check_pass2` genuinely evaluates it; `object_activation_date` is populated by 5 op handlers |
| `kmip/src/auditlog/mod.rs:29-31` | P2/P3 events "⏳ Phase 5-6" pending | All emitted throughout `ops/*.rs` today |
| `kmip/src/kmip30/message.rs:34-35` | Correlation Value/Async Indicator/Authentication "omitted in v0.1" | All three genuinely implemented |
| `rust/src/ffi.rs:1201-1203` | "Stateful HBS keygen is not implemented" | HSS/XMSS/XMSS-MT keygen all call real tree generation |
| `rust/src/native/sign.rs` module doc | excludes "stateful HSS / XMSS / LMS paths" | HSS is fully implemented (only XMSS genuinely absent, and that correctly errors) |
| `rust/src/ck_abi.rs:39-49` | 64-bit pointer marshaling "returns `CKR_FUNCTION_FAILED`" | Marshals correctly at native width; the file's own test asserts `CKR_OK` |
| `rust/src/constants.rs:693` | "Multi-part operation stubs... only supports single-shot" | Real multi-part accumulator state + `C_*Update`/`C_*Final` flows exist |

Also: `kmip/src/auditlog/syslog.rs:62` swallows a UDP send failure with no log line, unlike
every sibling sink (`otlp.rs`/`ring.rs`/`jsonl.rs` all log+count losses) — add the same
`tracing::warn!` + drop-counter this repo's `AuditSink` trait doc says a sink "should" do on
failure. Small enough to fold into this phase rather than its own.

*(S / P3 — zero risk, do whenever convenient, e.g. bundled into whichever other phase's PR
touches the same file.)*

---

## 10. Sequencing & dependencies

```
A (Destroy)                — independent, do first (P0, security)
B (SetAttribute)            — independent of C (v1's claimed dependency was false — verified)
C (wire tables)              — independent of B
D (Register RSA)            — independent; check the pkcs8 trait before estimating T2 further
E (CryptoParams)            — independent
F (Encrypt/Decrypt)         — independent; lower risk than v1 stated, but still the only
                               phase touching rust/ — do after the pure-kmip/ phases so any
                               engine-side review bandwidth is used once, not interleaved
G (Dispatcher Undo)         — independent
H (medium-priority)         — independent, lowest priority of the numbered findings
I (doc cleanup)             — zero-risk, fold into whichever PR touches each file
```

**Recommended order:** A → B → C → D → E → G → F → H → I (opportunistic). B/C/D/E/G have no
inter-dependencies and can genuinely run in parallel if more than one person/session is
available — the linear order above is for a single-threaded execution, not a hard requirement.

## 11. Effort / risk

| Tier | Phases |
|---|---|
| S / low | A, E, G, H, I |
| M | B, C, D, F *(F downgraded from v1's M–L after reading the target function)* |

*(v1 also listed a standalone "M–L / higher risk" tier containing only F; folded into M above
per the Phase F correction — verify this still feels right once T1's refactor is scoped, since
"the logic already exists" and "the refactor is risk-free" aren't quite the same claim.)*

## 12. Definition of done

- No `ObjectRecord` with `state == Destroyed` retains `key_material`, and the SQLite backend
  has `secure_delete` configured (Phase A).
- Every non-custom `Attribute` variant either genuinely persists via `SetAttribute` (per its
  real spec modifiability rule) or is honestly rejected `AttributeReadOnly` — no silent
  no-op, and no attribute made settable that the spec says isn't (Phase B).
- `DeleteAttribute`'s independent name-based removal path has been checked for the same class
  of gap, not assumed clean by association with the other two ops (Phase B/T3 follow-up).
- `AdjustAttribute`/`DeleteAttribute` by numeric `AttributeReference` resolves every attribute
  that decodes to its real name (Phase C) — resolving correctly is distinct from
  `AdjustAttribute` *accepting* it, which stays narrowly scoped per its own spec-honest design.
- `CryptographicParameters` round-trips fully (all fields) through `GetAttributes`/`Export`,
  and is persisted by `CreateKeyPair` the same way `Create`/`Register`/`DeriveKey` already do
  (Phases C, E).
- `Register` never discards an engine-import failure (Phase D).
- AAD/tag-length/OAEP-hash behave identically for engine-generated and Register'd keys,
  ideally via one shared implementation rather than two that happen to agree (Phase F).
- Batch `Undo`/`$IDPlaceholder` handle all UID-producing response types, not a subset
  (Phase G).
- `Locate` either filters or honestly rejects every attribute template clients can send,
  without touching the already-working `StorageStatusMask` path (Phase H).
- Every doc comment flagged in Phase I matches the code it describes.
- `cargo test` green on both crates; new regression test per finding (not just "existing
  suite still passes" — each fix ships with a test that would have caught the original gap).
- Each phase's T0 (re-verify against current source before implementing) was actually done,
  not skipped because this document already sounds confident.
