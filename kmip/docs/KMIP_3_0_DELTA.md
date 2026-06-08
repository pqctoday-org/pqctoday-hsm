# KMIP 3.0 Delta — divergence between our pre-extraction draft and OASIS

This document records every place our pre-extraction working notes diverged
from the authoritative OASIS KMIP 3.0 spec, so future readers know which
numbers to trust. Generated 2026-06-07 as part of Phase 1 of the
[`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md).

| Authority | Path |
| --- | --- |
| OASIS KMIP 3.0 specification PDF | [`../spec/oasis-kmip-3.0/kmip-spec-v3.0.pdf`](../spec/oasis-kmip-3.0/kmip-spec-v3.0.pdf) |
| OASIS KMIP 3.0 specification HTML (extracted) | [`../spec/oasis-kmip-3.0/kmip-spec-v3.0.html`](../spec/oasis-kmip-3.0/kmip-spec-v3.0.html) |
| Extractor binary | [`../tools/extract_kmip_spec.rs`](../tools/extract_kmip_spec.rs) (`cargo run --bin extract-kmip-spec`) |
| Extracted authoritative JSON | [`../spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json`](../spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json) |

The extraction run on 2026-06-07 produced:

- **395** KMIP tags (codepoints `0x420000`–`0x42017b` and outliers).
- **62** enumeration types.
- **730** enum values across all enumerations.

## 1. PQC algorithm codepoints — pre-extraction draft was WRONG

### What our pre-extraction placeholder said (IMPLEMENTATION_PLAN §6.3, p0-kmip-pqc-22-impl.md §6.3)

```json
{
  "name": "Cryptographic Algorithm",
  "additions": [
    {"name": "ML-KEM-512",  "value": "0x00000040"},
    {"name": "ML-KEM-768",  "value": "0x00000041"},
    {"name": "ML-KEM-1024", "value": "0x00000042"},
    {"name": "ML-DSA-44",   "value": "0x00000050"},
    {"name": "ML-DSA-65",   "value": "0x00000051"},
    {"name": "ML-DSA-87",   "value": "0x00000052"}
  ]
}
```

### What OASIS actually published (extracted from kmip-spec-v3.0.html)

| Algorithm | OASIS codepoint | Our draft (wrong) | Delta |
| --- | --- | --- | --- |
| ML-KEM-512 | `0x00000039` | `0x00000040` | −7 |
| ML-KEM-768 | `0x0000003a` | `0x00000041` | −7 |
| ML-KEM-1024 | `0x0000003b` | `0x00000042` | −7 |
| ML-DSA-44 | `0x0000003c` | `0x00000050` | −20 |
| ML-DSA-65 | `0x0000003d` | `0x00000051` | −20 |
| ML-DSA-87 | `0x0000003e` | `0x00000052` | −20 |
| SLH-DSA-SHA2-128s | `0x0000003f` | (not in draft) | new |
| SLH-DSA-SHA2-128f | `0x00000040` | (collides with our draft ML-KEM-512!) | collision |
| SLH-DSA-SHA2-192s | `0x00000041` | (collides with our draft ML-KEM-768!) | collision |
| SLH-DSA-SHA2-192f | `0x00000042` | (collides with our draft ML-KEM-1024!) | collision |
| SLH-DSA-SHA2-256s | `0x00000043` | — | new |
| SLH-DSA-SHA2-256f | `0x00000044` | — | new |
| SLH-DSA-SHAKE-128s | `0x00000045` | — | new |
| SLH-DSA-SHAKE-128f | `0x00000046` | — | new |
| (continued in JSON; 12 SLH-DSA variants total) | … | … | … |

**Resolution:** the Phase 3 KMIP 3.0 extension layer (`src/kmip30/algos.rs`)
**MUST** use the OASIS codepoints exactly as extracted. The pre-extraction
draft codepoints in IMPLEMENTATION_PLAN §6.3 are documented here as a
discarded historical artifact. They were a guess made before the spec was in
hand; the extraction supersedes them. The original sandbox plan
([`p0-kmip-pqc-22-impl.md`](../../../pqctoday-sandbox/tasks/p0-kmip-pqc-22-impl.md))
inherited the same wrong numbers and is already marked superseded.

## 2. New-in-3.0 enumeration values

The OASIS KMIP 3.0 `Cryptographic Algorithm` enum carries **74 values** total
(74 from the extraction). The PQC additions are the contiguous block
`0x39`–`0x4a` (12 SLH-DSA variants + 3 ML-KEM + 3 ML-DSA + several others).
Pre-3.0 algorithms (DES, 3DES, AES, RSA, DSA, ECDSA, HMAC-*, …) keep their
KMIP 1.4 / 2.x codepoints unchanged.

See `enums["Cryptographic Algorithm"]` in
[`../spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json`](../spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json)
for the full list.

## 3. New-in-3.0 tags

Tags continue the established `0x42xxxx` numbering. The extraction picked up
**395 tags**; this is the union of KMIP 1.4 + 2.0 + 3.0 because the spec
includes all historical tags in a single normative table (Annex 9 in the
3.0 spec). Phase 3 (`src/kmip30/`) will subset to the tags actually used by
our v0.1 operation set; everything else stays available for future use.

## 4. Tag table format quirks

The Word-converted HTML uses ten-level-nested `<span>` elements per cell. The
extractor's strategy (find rows with a hex codepoint in column 2; classify by
codepoint pattern) sidesteps the styling noise and produces clean output. No
LLM in the loop — pure DOM walk.

## 5. Operation codepoints — not yet extracted

The `Operation` enumeration is in the extracted output under `enums.Operation`
— 50 values. KMIP 3.0 reuses the existing `Encrypt` / `Decrypt` ops for
ML-KEM encapsulation/decapsulation rather than introducing new
`Encapsulate` / `Decapsulate` ops (verified against the OASIS HTML
2026-06-04; see IMPLEMENTATION_PLAN.md §6 Phase 5 note). Phase 5 op handlers
branch on key algorithm inside the handlers, not on the op name.

## 6. Maintenance

Re-run `cargo run --bin extract-kmip-spec` whenever
`spec/oasis-kmip-3.0/kmip-spec-v3.0.html` is replaced (OASIS errata, future
3.x release). The `source_sha256` field in the output JSON is the gate — CI
should fail the build if the input file's sha256 changes without a
corresponding re-extraction.

## 7. KMIP 3.0 KAT cross-check (2026-06-07)

Walked the 102 KMIP 3.0 test cases (`kat/oasis-kmip-3.0/{mandatory,optional}/*.xml`)
and cross-referenced every symbolic name they reference against our
extraction:

| KAT vocabulary class | Used in 3.0 KAT | Covered by extraction | Notes |
| --- | --- | --- | --- |
| Tag names | 140 unique | 140 / 140 (100%) | All matched after acronym-aware comparison (CRT, IV, MAC, PKCS#11, RNG, CN are correctly extracted as written in the spec). |
| `Operation` enum values | 61 unique | 61 / 61 (100%) | All 61 KAT ops map cleanly to one of the 64 entries we extracted. |
| `CryptographicAlgorithm` enum values | 7 unique | 5 / 7 direct, 7 / 7 modulo notation | Notation differences only: KAT writes `DES3` vs spec text `3DES`; KAT writes `HMAC_SHA256` vs spec text `HMAC-SHA256`. Both refer to the same codepoints. |
| Any PQC algorithm | **0 unique** | n/a | **The published OASIS KMIP 3.0 KAT corpus contains zero test cases referencing any PQC algorithm** (`grep -rliE "ML.KEM\|ML.DSA\|SLH.DSA\|Kyber\|Dilithium" kat/oasis-kmip-3.0/` → 0 hits). Cross-check of PQC codepoints against KMIP 3.0 KAT is impossible: that ground truth does not exist yet. |

Conclusion: the extractor's correctness is validated against every concrete
symbolic name the KMIP 3.0 KAT actually uses. The PQC codepoint correctness
relies on the spec text alone (which is unambiguous about its
`Cryptographic Algorithm` enum table) and is also corroborated by the
KMIP 1.4 baseline codepoints round-tripping exactly (DES=0x01, 3DES=0x02,
…, RSA=0x04, ECDSA=0x06, ChaCha20=0x1c).

## 8. Upstream OASIS publication audit (2026-06-07)

Checked `docs.oasis-open.org/kmip/` via the `download_kmip_spec.py` tool
(template: `pqctoday-priv/patents/download_patents.py`) for any updated
KMIP 3.0 publication or KAT corpus carrying PQC test vectors.

| Resource | Local snapshot date | Upstream date | Content change? |
| --- | --- | --- | --- |
| `kmip-spec/v3.0/kmip-spec-v3.0.html` | 2023-11-30 | **2024-08-23** | **No.** Refreshed sha256 (`e593dad8…` → `4197ff90…`) but byte-identical length (19,055,347). Re-extraction emitted byte-equivalent JSON modulo the `source_sha256` + `extracted_at` fields — all 395 tags, 62 enums, 730 enum values match exactly. Verdict: Word-document metadata churn (save-state + bookmark IDs), no spec content changes. |
| `kmip-spec/v3.0/kmip-spec-v3.0.pdf` | 2023-11-30 | 2024-08-23 | No (byte-identical sha256 `e95f0ed9…`). |
| `kmip-profiles/v3.0/` (KMIP 3.0 KAT corpus) | 2023-11-30 | **2023-11-30** (unchanged) | n/a — directory has not been republished since first release. **No PQC test vectors have been added by OASIS.** |

The `from-2023-11-30.json` artifact in the same directory preserves the
prior extraction for byte-exact diff against the current run.

**Practical conclusion:** OASIS has neither corrected the spec nor added
PQC test cases between Nov-2023 and Aug-2024. Our extracted codepoints
remain authoritative for the current OASIS publication, and the
"no PQC KMIP 3.0 KAT" gap remains real.

## 9. Status

| Date | Note |
| --- | --- |
| 2026-06-07 | First extraction run against the 2023-11-30 spec HTML: 395 tags, 62 enums, 730 enum values. Documented the PQC algorithm codepoint correction (pre-extraction draft was off by 7–20 across ML-KEM and ML-DSA, with three direct collisions against SLH-DSA codepoints). Cross-checked extraction against all 102 KMIP 3.0 KAT XML cases — 100% tag-name coverage, 100% Operation enum coverage, every symbolic name accounted for. **Spec-refresh audit:** pulled the 2024-08-23 republished HTML via `tools/download_kmip_spec.py`; sha256 differs but byte length and re-extracted JSON are content-equivalent (Word metadata churn only). Test corpus (`kmip-profiles/v3.0/`) still dated 2023-11-30 — OASIS has not yet published PQC KAT vectors. Authoritative JSON at `spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json`; input to Phase 3 codegen for `src/kmip30/algos.rs`. |
