# KMIP 3.0 Conformance Report

**Generated**: 2026-06-08 · **Updated**: 2026-06-10 (dispatcher replay results)
**Subsystem**: `pqctoday-kmip` (`kmip/` crate)
**Spec**: OASIS Key Management Interoperability Protocol v3.0 CSD01
**Test corpus**: `kmip-profiles-v3.0.zip` (`test-cases/kmip-v3.0/{mandatory,optional}/*.xml`)

## TL;DR

| Layer | Status | Evidence |
|---|---|---|
| TTLV wire-format codec | ✅ **100% conformant** | 1234/1234 OASIS messages round-trip byte-identical |
| Dispatcher behaviour vs OASIS expectations | ✅ **92/92 actionable tests pass (100%)** | `conformance/REPLAY_REPORT.md` (regenerated per run) |
| Op coverage | ✅ all ops used by the OASIS corpus | 0 `SKIP_OP` in the replay report |
| Third-party interop (PyKMIP / vendor) | ⏸️ never run | KMIP 3.0 has no compatible OSS client |

**Bottom line**: the wire bytes are KMIP 3.0 standard AND the dispatcher
matches the OASIS conformance transcripts on **all 92 tests** that
exercise implemented, non-deprecated mechanisms (`Get` with
`KeyWrappingSpecification` — AES-KW key wrapping per AX-M-2 — was the
last gap, closed 2026-06-10). The remaining 10 transcripts are
deliberate skips: 5 deprecated mechanisms (DES / 3DES
/ DSA per `kmip/DEPRECATED.md`), 2 precondition tests requiring
prior-transcript state the hermetic harness wipes, 3 mutually-exclusive
RNG-seed policy variants.

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
"enumerable Tag" special case — round-trips byte-identical.

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

The 2026-06-08 revision of this report listed 35+ missing operations.
All ops exercised by the OASIS corpus have since been implemented
(`Register`, `GetAttributes`, `GetAttributeList`, attribute CRUD, `MAC` /
`MACVerify` / `Hash`, `DiscoverVersions`, RNG ops, session/auth ops,
`Check`, `Export` / `Import`, lifecycle ops, the PKCS#11 passthrough, and
multi-part streaming `Encrypt`). The replay report shows **0 `SKIP_OP`**.

## 4. Dispatcher conformance: ✅ measured continuously

The replay harness (`conformance/harness/dispatcher_replay.py`) drives
every OASIS transcript against a freshly started server per test
(hermetic; in-memory store), resolves `$NOW` / `$UNIQUE_IDENTIFIER_n` /
auto-bound tag placeholders, and compares responses tree-wise.

Current standing (2026-06-10): **92 PASS / 0 FAIL / 10 deliberate
skips** out of 102 transcripts. Per-test detail: `conformance/REPLAY_REPORT.md`.

### 4.1 Vendor extension: ML-KEM shared secret (K10)

KMIP 3.0 has **no Encapsulate operation**. This server overloads
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

## 5. Scope decision: resolved

The 2026-06-08 revision proposed Paths A/B/C. Events overtook it: the
implemented surface now exceeds Path A (Baseline-profile ops plus the
crypto-op family, streaming, KMIP-level key wrapping on `Get`, and the
PKCS#11 passthrough). No open scope lines remain against the corpus.

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
