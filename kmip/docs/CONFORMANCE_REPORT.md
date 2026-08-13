# KMIP 3.0 Conformance Report

> **Current as of v0.13.0.** The replay figures below are regenerated per run via
> `../conformance/harness/dispatcher_replay.py` (`cargo test` in CI also gates
> them); the dated stamps below are when the prose was last edited, not a ceiling
> on validity.

**Generated**: 2026-06-08 · **Updated**: 2026-07-09 (`GAP_REMEDIATION_PLAN.md` Phases A–I complete)
**Subsystem**: `pqctoday-kmip` (`kmip/` crate)
**Spec**: OASIS Key Management Interoperability Protocol v3.0 **Committee Specification Draft 01
(CSD01, 23 Aug 2024)** — a draft, not a ratified OASIS Standard. PQC extensions (Encapsulate /
Decapsulate, hybrid KEMs) are implemented per the later **Working Draft 19 (WD19, 14 Feb 2025)**,
also unpublished/unratified; the PQC surface has no OASIS test vectors (§4.1, §7 below). See
`../docs/HONEST_MAXIMUM_PLAN.md` for the roadmap this report reflects the completion of (Phases
0–4 and 6.1; Phase 5 — server-to-client — is deliberately parked, see §5), and
`GAP_REMEDIATION_PLAN.md` for a follow-up audit (13 findings, all fixed) that specifically
targeted silently-dropped errors and stub/placeholder behavior the dispatcher-conformance figures
below wouldn't have caught on their own (they test observable request/response shape, not every
internal error-propagation path — e.g. a discarded engine-import `Result` that still returns wire
`Success`).
**Test corpus**: `kmip-profiles-v3.0.zip` (`test-cases/kmip-v3.0/{mandatory,optional}/*.xml`) — CSD01-era, contains zero PQC test cases.

## TL;DR

| Layer | Status | Evidence |
|---|---|---|
| TTLV wire-format codec | ✅ **100% conformant** | 1234/1234 OASIS messages round-trip byte-identical |
| Dispatcher behaviour vs OASIS expectations | ✅ **97/97 actionable tests pass (100%)** | `conformance/REPLAY_REPORT.md` (regenerated per run) |
| Op coverage | ✅ all ops used by the OASIS corpus | 0 `SKIP_OP` in the replay report |
| Query honesty | ✅ **nothing advertised that isn't real** | both `ADVERTISED_UNIMPLEMENTED_*` lists in `ops/query.rs` are empty (Phase 6.1) |
| Asynchronous processing | ✅ **real** — job store + background executor | Poll/Cancel/Process/Query Asynchronous Requests all genuinely implemented (Phase 4) |
| Stateful hash-based signatures | ✅ **real** — HSS/LMS wired to the engine | KMIP `Sign` on an HSS/LMS key advances + persists the real leaf index (Phase 1.5) |
| Baseline Server profile (§5.1.2) | ⚠️ **all conditions met except item 10** (server-to-client) | §5 below — deliberately parked, not a gap discovered late |
| Third-party interop (PyKMIP / vendor) | ⏸️ never run | KMIP 3.0 has no compatible OSS client |

**Bottom line**: the wire bytes match the KMIP 3.0 CSD01 draft byte-for-byte AND the dispatcher
matches the OASIS conformance transcripts on **all 97 non-deprecated tests** in the corpus. The
remaining 5 transcripts are a deliberate, documented policy skip — DES / 3DES / classical DSA are
out of scope for the `softhsmrustv3` backend (`kmip/DEPRECATED.md`). There are, as of this
revision, **zero** other skip categories: no `SKIP_OP`, no `SKIP_PRECONDITION`, no
`SKIP_POLICY_VARIANT`, no `SKIP_PARSE` — every transcript the harness can meaningfully run,
it runs to a real PASS or FAIL.

## 0. Gap-remediation follow-up (v0.13.0, 2026-07-09)

The 97/97 corpus-replay figure above hasn't moved — but it was never designed to catch every gap
this class of bug produces. A dedicated audit of both the `rust/` (PKCS#11 engine) and `kmip/`
crates for stub/placeholder code and silently-dropped errors found 13 real gaps, none of which
changed an op's observable wire shape enough to fail a corpus transcript on its own (the corpus
mostly exercises the happy path with well-formed requests). All 13 are fixed, documented phase by
phase in `GAP_REMEDIATION_PLAN.md`, each with new regression tests:

- `Destroy` now genuinely scrubs key material instead of only flipping a lifecycle flag.
- `SetAttribute`/`ModifyAttribute`/`DeleteAttribute` no longer silently drop several attributes,
  and correctly reject others as Read-Only that previously fell through a permissive catch-all.
- Three wire-encoding round-trip gaps (attribute-name lookup table, `CryptographicParameters`
  field coverage, `SecretData` type persistence).
- `Register` no longer discards engine-import errors, and RSA public keys registered in PKCS#8 or
  Transparent form now genuinely produce a usable engine object (previously silent no-ops).
- `CreateKeyPair` persists `CryptographicParameters` and rejects false `QuantumSafe` claims.
- `Encrypt`/`Decrypt` pass real AAD and OAEP-hash choices through for engine-generated keys, not
  just `Register`'d ones.
- Batch `Undo`/`$IDPlaceholder` now cover `Encapsulate`/`Decapsulate`/`CreateSplitKey`/`JoinSplitKey`.
- `Locate` filters by cryptographic length, usage mask, and unique identifier instead of silently
  ignoring them.

One genuine regression was caught and fixed during this work itself: re-running the full
mandatory corpus replay while verifying the Locate fix turned up that the RSA-Register honesty fix
had exposed a pre-existing, separate bug (Transparent RSA Public Key registration never actually
worked) as a hard failure instead of a silent one. Both are fixed; the corpus is back to 97/0/5.

## 1. Test corpus inventory

The OASIS KMIP 3.0 profiles package contains the official conformance test
suite — 102 unique XML transcripts under `test-cases/kmip-v3.0/`:

| Subset | XML files | Total messages |
|---|---|---|
| `mandatory/` | 95 | ~1120 |
| `optional/` | 7 | ~114 |
| **Total** | **102** | **1234** |

Each transcript is alternating `RequestMessage` / `ResponseMessage` pairs
in OASIS XML notation (element name = tag name, `type=` attribute = TTLV
type, `value=` = typed value). Placeholders (`$NOW`, `$UNIQUE_IDENTIFIER_0`,
etc.) are bound dynamically when the conformance suite is replayed against
a server.

Corpus is checked in at `kmip/conformance/oasis_corpus/` and never regenerated.

## 2. TTLV codec compliance: ✅ 100%

Method: the harness at `conformance/harness/oasis_codec.py` parses each
OASIS XML transcript into a typed AST, encodes every element to TTLV bytes
per KMIP 3.0 §9.6, then feeds those bytes into our Rust codec
(`src/codec/`). The Rust codec must `decode → encode` and produce
byte-identical output.

Two vector tiers locked in `conformance/oasis_corpus_bytes/`:

| Tier | Vector count | Byte provenance |
|---|---|---|
| **pristine** | 124 | OASIS XML messages with no `$`-placeholders — every byte traces to the official corpus |
| **stubbed** | 1234 | Full corpus with `$NOW` / `$UID_n` replaced by neutral fillers — proves codec consistency across the full structural diversity of KMIP 3.0 |

**Result** (run `cargo test --test oasis_codec_roundtrip`):

```
test pristine_oasis_corpus_round_trips_byte_exact ... ok    (124/124)
test stubbed_oasis_corpus_round_trips_byte_exact  ... ok  (1234/1234)
test manifest_message_type_breakdown_matches_expectation ... ok
```

Every TTLV element shape — every primitive type (Integer, LongInteger,
BigInteger, Enumeration, Boolean, TextString, ByteString, DateTime,
Interval, DateTimeExtended), every nested Structure depth, every named
bit-flag mask, every enum lookup including the KMIP 3.0 `AttributeReference`
"enumerable Tag" special case — round-trips byte-identical. This tier is
unaffected by the Phase 0–4 work below: it exercises the corpus's actual
message shapes, none of which happen to invoke Split Key or the async ops
(those are proven end-to-end a different way — §4.3/§4.4).

### 2.1 What this proves

- Our `tag → 3-byte codepoint` table matches OASIS for every tag in the
  conformance corpus (~395 tags).
- Our `enum → 4-byte value` mappings are correct for every enum referenced
  in the corpus (62 enum tables).
- Our padding logic (zero-fill to 8-byte boundary per §9.6) matches OASIS
  for every variable-length type.
- Our nested-Structure length accounting is correct for the full structural
  diversity of KMIP 3.0 messages (max depth observed: 8 nested levels).

### 2.2 Limits of what this proves

Codec round-trip says **the bytes we speak are KMIP 3.0**. It does *not*
say "we respond correctly to a KMIP 3.0 request". That's §4 below.

## 3. Op coverage: closed

Every operation the OASIS corpus exercises as a live request is
implemented — the replay report shows **0 `SKIP_OP`**. Beyond corpus
coverage, this server's real (`HANDLED_OPERATIONS`) surface is
substantially broader than what the corpus itself exercises: the
asynchronous-subsystem ops (`Poll` / `Cancel` / `Process` / `Query
Asynchronous Requests`, Phase 4) and `Create Split Key` / `Join Split
Key` (Phase 3.3) are genuinely implemented but not invoked as live
requests by any CSD01-era transcript — see §4.3/§4.4 for how those are
proven instead.

## 4. Dispatcher conformance: ✅ measured continuously

The replay harness (`conformance/harness/dispatcher_replay.py`) drives
every OASIS transcript against a freshly started server per test
(hermetic; in-memory store), resolves `$NOW` / `$UNIQUE_IDENTIFIER_n` /
auto-bound tag placeholders, and compares responses tree-wise.

Current standing: **97 PASS / 0 FAIL / 5 SKIP_DEPRECATED** out of 102
transcripts (102/102 actionable-or-honestly-skipped; every
non-deprecated transcript passes). Per-test detail:
`conformance/REPLAY_REPORT.md`. The 5 skips are DES/3DES/classical-DSA
mechanisms declared out of scope for the `softhsmrustv3` backend
(`kmip/DEPRECATED.md`): `BL-M-12-30`, `BL-M-13-30` (DSA), `SKFF-M-4-30`,
`SKFF-M-8-30`, `SKFF-M-12-30` (3DES).

### 4.1 Vendor extension: ML-KEM shared secret (K10)

KMIP 3.0 WD19 adds native `Encapsulate`/`Decapsulate` ops (this server
implements them). For pre-WD19 clients the server ALSO overloads
Encrypt/Decrypt for ML-KEM encapsulation/decapsulation as a documented
vendor extension: the Encrypt response carries the encapsulation in
`Data` and the derived shared secret under the `PQCToday-SharedSecret`
vendor-extension tag **`0x540001`** (KMIP 3.0 §11.57 reserves
`0x540000–0x54FFFF` for Extensions). The standard `IVCounterNonce` tag
(`0x42003d`) is strictly an IV — the pre-K10 stopgap that reused it for
the shared secret was wire-ambiguous with classical RandomIV responses
(compliance-audit B-7) and has been removed. Allocation registry:
`kmip/src/kmip30/vendor_tags.rs` + `kmip/pkcs11-mech-manifest.json`
(`vendor_tags` section). No OASIS corpus transcript exercises this path,
so corpus conformance is unaffected.

### 4.2 Synthesized (corpus-pinned) attribute values (K11 / K-16)

After the K11 attribute-truthfulness pass, `Last Change Date` is
stamped by every attribute-mutation op (§11 SHALL), `Digest` is the
SHA-256 of the **actual** key material (persisted at creation; computed
inside the engine boundary for non-extractable private halves via
`native::get_value_digest_sha256`, and **omitted** when no material was
ever available instead of fabricated), all stored Link entries and the
full `UsageLimits` structure (Total / Count / Unit) are emitted, and
`Random Number Generator` reports `Unspecified` (0x01) — the engine
draws from the OS entropy pool (`rand::rngs::OsRng`), not a managed
DRBG. The harness treats Digest / RNG structure interiors as opaque
(Profiles v3.0 §4.1.1 item 10 / §4.1 RV item 6), so honest values are
corpus-safe.

The remaining values below are **synthesized defaults pinned by the
OASIS corpus shape**, not server-tracked state
(`ops/get_attributes.rs::attributes_from_record`):

| Attribute | Emitted value | Why |
|---|---|---|
| `Object Class` | `"User"` (unless explicitly set) | Baseline corpus expects `User` on every test-created object |
| `Lease Time` | `3600` s (unless explicitly set) | BL-M-14 / AKLC-O-1 / SKLC-O-1 pin 3600 on fresh keys; also the real cap `Obtain Lease` (§6.1.42, Phase 3.1) grants against |
| `Protection Storage Mask` | `0x01` (Software) | BL-M-14 / SKLC-O-1 / AKLC-O-1 step #3 pin Software |
| `Key Format Type` | `Raw` (0x01) when the record carries none | §6.2 default for Create/CreateKeyPair (no KeyBlock); SKLC-O-1 step #3 |

The OASIS fixtures display `RNGAlgorithm = ANSIX9_31 / AES / 256`, but
that is **not** comparator-pinned (opaque structure) — the server's
`Unspecified` report is the truthful one and replays clean.

### 4.3 Stateful hash-based signatures: HSS/LMS is real (Phase 1.5)

RFC 8554 HSS (and its single-tree LMS special case) are wired all the
way through: a `Sign` request against an HSS/LMS-keyed object advances
the real leaf index inside the engine and persists it onto the key
object (`CKA_LEAF_INDEX`), shared between the KMIP dispatch path
(`ops/sign.rs` → `native::sign`) and the PKCS#11 FFI path (`ffi.rs::C_Sign`)
via one common engine helper — there is exactly one place leaf-index
persistence can drift, and it's shared, not duplicated. A second Sign
against the same key consumes a fresh leaf; exhausting the tree fails
cleanly (`CKR_KEY_EXHAUSTED` → the matching KMIP `ResultReason`) rather
than reusing a leaf, which would be a real one-time-signature security
break. No OASIS CSD01 transcript exercises HSS/LMS (it predates the
draft's PQC additions), so this is proven by `rust/`'s own test suite
(a real 32/32-leaf exhaustion test, distinct leaf indices per sign,
FFI/native byte-identical output) rather than corpus replay.

### 4.4 Asynchronous processing: real, not a stub (Phase 4)

`Poll` / `Cancel` / `Process` / `Query Asynchronous Requests` (§6.1.45,
§6.1.5, §6.1.48, §6.1.48) are backed by a genuine job store and
executor, not a canned "always pending" or "always complete" response.
A `Mandatory`-async request against an eligible operation enqueues a
real job (keyed by a server-generated Asynchronous Correlation Value)
and responds `OperationPending` with no payload; the production server
(`bin/pqctoday-kmip.rs`) runs that job on a real detached OS thread,
concurrently with whatever the client does next, and `Asynchronous
Capability` in `Query` reports `true` only because this is actually
true. `Cancel` and `Process` handle the genuine race between a client
request and the background executor correctly (a single locked
check-and-set for Cancel-while-Submitted; Process blocks on a
`Condvar` rather than risking a double-executed side effect). No
OASIS CSD01 transcript exercises the async header, so this is proven
by `tests/async_ops_e2e.rs` (real dispatcher, real `Arc<Deps>` +
background thread, byte-exact match against a synchronous baseline)
and 7 deterministic unit tests in `ops::async_ops` pinning the exact
per-stage behavior.

### 4.5 Split Key: real secret-sharing math, not a placeholder (Phase 3.3)

`Create Split Key` / `Join Split Key` (§6.1.12, §6.1.33) implement all
four §11.54 methods from spec (XOR, Polynomial Sharing GF(2⁸)/GF(2¹⁶)/
Prime Field) in the engine layer, reachable only via opaque PKCS#11
object handles — the KMIP server never sees a raw secret byte, split or
whole. Building this surfaced and fixed a genuine bug in the KMIP 3.0
draft's own printed GF(2¹⁶) multiplication formula (re-derived from
first principles, cross-checked against the spec's own inverse
formula). No OASIS transcript exercises Split Key; proven by 18
crypto-layer unit tests plus an end-to-end test that splits a
freshly-generated key 5 ways, joins a 3-share subset back together, and
confirms the reconstructed bytes match exactly (and that fewer than
the threshold fails instead of silently reconstructing garbage).

## 5. Scope decision: resolved

### 5.1 Conformance claim — scope statement

**The claim this subsystem makes: *"OASIS KMIP 3.0 (CSD01 corpus) + WD19 PQC extensions —
Baseline Server profile conditions met, except that item 10's server-to-client operations are
implemented for `Notify` and `Put` only. Drafts, not a ratified Standard."*** Every actionable
transcript in the official `kmip-profiles-v3.0.zip` test suite passes (97/97 non-deprecated), and
the TTLV codec round-trips the full corpus byte-exactly.

Baseline Server profile conditions (kmip-profiles-v3.0 §5.1.2), checked against the spec's
own 13-item list rather than approximated:

| §5.1.2 item | Requirement | Status |
|---|---|---|
| 1 | KMIP Server Implementation Conformance clauses | Met — the dispatcher/codec/op-handler layers below are the evidence |
| 2–3 | System/User Objects: User, Group, Password Credential, Certificate | **Met** (Phase 6.1 correction — these were genuinely implemented all along via `CreateUser`/`CreateGroup`/`CreateCredential`; a stale Query-advertisement doc comment had mislabeled them "unimplemented" since before this server could actually create them) |
| 4–8, 11–12 | Attribute/Message/Object/Operation data structures, message protocols | Met — evidenced by §2 codec conformance + §4 dispatcher conformance |
| 9 | 32 named Client-to-Server Operations (Activate…Set Endpoint Role) | **Met** — every one of the 32 is a real, `HANDLED_OPERATIONS` handler. `Set Endpoint Role` accepts the identity request (role=Server) and, since 2026-08-13, also performs the real role switch (role=Client) for an authenticated caller — see §5.1.4 |
| 10 | 5 named Server-to-Client Operations (Discover Versions, Notify, Put, Query, Set Endpoint Role, all issued *by the server*) | **Partially met (2026-08-13).** `Notify` and `Put` are implemented and the server genuinely pushes them: a client hands over the server role via §6.1.61 and receives them on the same channel, proven end to end against a real client (§5.1.4). Server-issued `Discover Versions`, `Query` and `Set Endpoint Role` are NOT implemented — those are the server interrogating the client, for which nothing here has a use. So this is no longer "no outbound channel exists", but it is not the full five either |
| 13 | Optional non-contradicting extensions | N/A (optional) |

**Correction from the prior revision of this report:** that version speculated the async
operations (`Poll`/`Cancel`/`Process`/`Query Asynchronous Requests`) were entangled with item 10's
server-to-client gap ("the async plumbing item 9's Poll/Cancel/Process/Query-Async lean on"). That
was wrong — §5.1.2's own item 9/item 10 lists don't name the async ops at all (they're covered
separately, as message-layer plumbing, by item 11.a `Asynchronous Indicator`). Phase 4 built and
proved them as a fully independent piece of work with no dependency on the server-to-client
channel, and item 10 remains — as it always was — a pure client-to-server-only gap: the server can
answer `Poll` all day without ever being able to push a `Notify` to anyone.

### 5.1.4 Server-to-client push — what was built, and how it is proven

Implemented 2026-08-13. The channel is the one §6.1.61 specifies, not an invented
one: a client sends `Set Endpoint Role` with `Endpoint Role = Client`, and "the
server assumes the client role, and the client assumes the server role, but the
communication channel remains as established". The listener acts on that response
by reversing direction on the very connection the client opened — so no server
ever dials out, and the "which client, and where" question §6.2 leaves open never
has to be answered.

**Trigger.** Every attribute mutation (Add / Modify / Set / Adjust / Delete funnel
through one `commit_mutation`) queues a `Notify` for the object's owner, carrying
the Last Change Date §6.2.2 requires. Queued *after* the store update — a
notification for a change that then failed to commit would be a lie — and queued
rather than sent inline, because an attribute write must not block on, or fail
because of, whether anyone is listening.

**Scoping and authorisation.** Queues are per identity, exactly like
`object_defaults`, so one tenant is never told about another's objects. The role
switch is refused (`Permission Denied`) to an anonymous caller: notifications name
real managed objects, and an unauthenticated connection has no identity to scope
them to. Queues are capped per identity — an identity that never listens must not
become an unbounded memory sink.

**Delivery.** Each push waits for the client's empty-payload acknowledgement
(§6.2.2/§6.2.3: "The client SHALL send a response … containing no payload") before
the next is sent, so delivery is observable rather than assumed. A peer that closes
instead of answering stops the loop rather than failing the connection — that is
precisely the "prior knowledge that the client is not able to respond" case the
same clause allows for.

**Evidence.** `python-client/tests/test_server_to_client_push.py` runs against a
real server over TLS and asserts a real client receives a `Notify` naming the
object it changed, that a delivered notification is not delivered twice, that an
anonymous client cannot take the server role, and that listening with nothing
queued returns cleanly instead of hanging. Proven non-vacuous by disabling the
queue hook: the delivery test fails, and the rest still pass, so it is measuring
delivery specifically.

**Still missing for a full item 10**: server-issued `Discover Versions`, `Query`
and `Set Endpoint Role`. Those have the server interrogating the client, which
nothing in this system needs; they are listed here so the gap is explicit rather
than implied by silence.

## 6. How to re-run the codec compliance test

```bash
cd kmip
# Regenerate byte vectors from the OASIS XML corpus
python3 conformance/harness/generate_byte_vectors.py

# Run the Rust round-trip suite (pristine + stubbed tiers)
cargo test --test oasis_codec_roundtrip -- --nocapture
```

Expected output:

```
running 3 tests
test manifest_message_type_breakdown_matches_expectation ... ok
test pristine_oasis_corpus_round_trips_byte_exact ... ok    (124/124)
test stubbed_oasis_corpus_round_trips_byte_exact  ... ok  (1234/1234)
```

Any failure here is a real wire-format regression — investigate before
landing.

## 7. How to re-run the dispatcher replay

```bash
cd kmip
cargo build --release --bin pqctoday-kmip
python3 conformance/harness/dispatcher_replay.py
```

Expected: `conformance/REPLAY_REPORT.md` reports 97 PASS / 0 FAIL / 5 SKIP_DEPRECATED / 102 total,
with 0 in every other status category. Any `FAIL` or unexpected `SKIP_*` here is a real dispatcher
regression — investigate before landing.
