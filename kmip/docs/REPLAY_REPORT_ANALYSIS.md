# OASIS KMIP 3.0 Dispatcher Replay — Baseline Analysis

**Generated**: 2026-06-09
**Harness**: `conformance/harness/dispatcher_replay.py`
**Raw report**: `conformance/REPLAY_REPORT.md` (Markdown) + `.json`

## TL;DR

| Metric | Value |
|---|---|
| Total OASIS test cases | 102 |
| Skipped (op not implemented) | 83 (81.4%) |
| Skipped (XML parse) | 0 |
| Errored (placeholder/encoding) | 3 |
| Failed (response mismatch) | 16 |
| **Passed (strict conformance)** | **0** |
| Candidates (use only our 12 ops) | 19 |

**Baseline: 0/19 tests pass strict OASIS comparison.** Not because our codec
is broken — the 1234-vector wire-format test in [`oasis_codec_roundtrip`](../tests/oasis_codec_roundtrip.rs)
passes 100%. The failures are at the **dispatcher / op-handler layer**:
our handlers respond with shapes that differ from OASIS expectations.

## Two distinct gap categories

### 1. Op-coverage gap (already documented)

83 of 102 tests skip because they require KMIP 3.0 operations we never
implemented (`Register`, `GetAttributes`, `DiscoverVersions`, etc.).
Closing this is straight implementation work — see PRs #81–#87 in the
follow-up plan.

### 2. **OASIS request/response-shape gap (NEW finding)**

Even the 19 tests we *should* be able to attempt all fail strict comparison
because our 12 existing op handlers don't match the OASIS-mandated message
shapes. Three root-cause patterns surfaced:

#### Pattern A: Request decoder doesn't unwrap `<Attributes>` Structure

OASIS Create requests wrap attributes in an `<Attributes>` element
(per KMIP 3.0 §6.1.6 — `Attributes` is a Required attribute on the
RequestPayload Structure):

```xml
<RequestPayload>
  <ObjectType type="Enumeration" value="SymmetricKey"/>
  <Attributes>
    <CryptographicAlgorithm type="Enumeration" value="AES"/>
    <CryptographicLength type="Integer" value="128"/>
    <CryptographicUsageMask type="Integer" value="Decrypt Encrypt"/>
  </Attributes>
</RequestPayload>
```

Our `src/kmip30/wire.rs` decoder treats the attributes as if they were
flat children of `RequestPayload` — so when the wrapped form arrives,
we don't see any CryptographicAlgorithm and return:

```
ResultStatus = Success
ResultReason = MissingData (0x06)
ResultMessage = "no CryptographicAlgorithm in template and policy supplied no default"
```

That's a real **wire-protocol conformance bug**. Affects all 8
`SKFF-M-*` tests. Same pattern likely affects `Activate`, `Revoke`,
`Encrypt`, `Decrypt`, `Sign`, `SignatureVerify` requests that carry
attributes.

#### Pattern B: Response BatchItem child count differs

Our BatchItem responses have an extra `ResultReason` + `ResultMessage`
child on failures, where OASIS expects only `Operation` + `ResultStatus`
+ `ResponsePayload` on success. On error, the spec wants
`Operation` + `ResultStatus` + `ResultReason` + `ResultMessage` (no
payload). We need to match the spec's branching exactly.

Affects all 3 `MSGENC-*` tests + all 8 `SKFF-M-*` tests
(which fail because our Create returns an error, see Pattern A).

#### Pattern C: ResultReason emitted as numeric, expected as enum-string

Our codec correctly emits the 4-byte enum value (0x06 = MissingData),
but the comparator's enum-name resolution surfaces the value as `6`
rather than `"MissingData"`. This is a comparator bug, not a server
bug. Easy fix: enhance `_values_equal` to carry tag context.

#### Pattern D: Time-relative placeholders not yet handled

3 `CS-BC-M-*` tests use `$NOW-3600` to mean "1 hour ago" for
`ActivationDate`. The placeholder resolver only handles `$NOW`.
Arithmetic placeholders should be:

```python
if value.startswith("$NOW") and value != "$NOW":
    # $NOW-3600, $NOW+86400 etc.
    offset = int(value[4:])
    return int(time.time()) + offset
```

Easy fix to bring 3 ERROR cases to FAIL/PASS classification.

## What this means for the plan

**Before adding new ops** (PRs #81+), we need to fix the existing 12 ops'
OASIS conformance. The work splits:

| Fix | Effort | Tests unblocked |
|---|---|---|
| Decoder: unwrap `<Attributes>` in Create / Activate / Get / Locate request paths | 0.5 PD | 8–12 |
| Dispatcher: BatchItem child sequencing (success vs error branches) | 0.5 PD | ~10 |
| Query response: lenient subset-OK comparator OR add unimplemented op markers | 0.25 PD | 1 |
| Harness: enum-name resolution + `$NOW±N` arithmetic | 0.25 PD | 3 |
| **Subtotal — bring existing 12 ops to strict-pass** | **~1.5 PD** | **~14–19** |

After that, the per-group implementation work (Groups A–G in the master
plan) lands strict-pass increases of roughly the unlock counts in
`docs/CONFORMANCE_REPORT.md`.

## Re-running the harness

```bash
# Build server (once)
cargo build --release --bin pqctoday-kmip

# Run all 102 tests (~30 sec)
python3 conformance/harness/dispatcher_replay.py

# Or single test for debugging
python3 conformance/harness/dispatcher_replay.py SKFF-M-1-30.xml
```

Results land in `conformance/REPLAY_REPORT.md` + `.json`. The Markdown
is human-friendly; the JSON is for downstream tooling (CI gates, badge
generation, etc.).
