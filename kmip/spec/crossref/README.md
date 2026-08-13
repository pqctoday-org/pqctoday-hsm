# Spec cross-reference fact sheets

Hand-verified, topic-scoped YAML extracts from the KMIP 3.0 and PKCS#11 v3.2
specs. Purpose: stop re-running `pdftotext` + `grep` over the source PDFs
every time a design question needs a spec citation — read the YAML instead,
and treat the PDF as the thing to re-check only if the YAML looks stale or
disputed.

## Why this is not the same thing as `kmip-spec-3.0-tags-enums.json`

`../oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json` is a **mechanically
generated** artifact: `kmip/tools/extract_kmip_spec.rs` walks
`kmip-spec-v3.0-csd02.html` (the current baseline) and regex-extracts every
`(name, codepoint)` table row into JSON. It's consumed by an automated Rust
test (`kmip/tests/spec_crosscheck.rs`) that asserts the engine's own
tag/enum constants agree with it. It is exhaustive but **shallow** — numeric
codepoints only.

Since the 2026-07-25 CSD02 migration that artifact *does* cover the PQC
codepoints (they moved into the published spec), so the original reason this
directory existed — "PQC facts live only in WD19, which the extractor cannot
read" — no longer applies. What the extractor still cannot produce is
everything **non-numeric**: operation semantics, REQUIRED/OPTIONAL payload
shapes, error tables, normative SHALL language, and cross-spec PKCS#11
mechanism rows. That is what these files carry, and none of it is covered by
any automated check — facts here are verified **by hand** against the source
document and must be **re-verified by hand** when that document is
superseded, not just diffed.

Files in `crossref/` are **curated, prose-inclusive** fact sheets: they carry
the operation descriptions, error tables, and cross-spec mechanism notes an
automated tag extractor can't produce, with a citation (section/page/table)
next to every fact so it can be independently re-checked.

## Why YAML

- Comments and inline provenance notes sit right next to the fact — JSON
  can't do that, and a fact without "how do I know this / where do I
  re-check it" rots into an unverifiable claim within a few months.
- Block scalars (`>`, `|`) hold direct spec quotes cleanly without escaping.
- Matches this repo's dominant hand-authored structured-data convention
  (`kmip/policies/*.yaml`) — reviewable in a normal PR diff.
- Clearly distinct from the mechanically-generated JSON above, so nobody
  mistakes a hand-verified narrative fact sheet for an automated-parity
  artifact (or vice versa).

## Conventions

- One file per topic (e.g. `kem-encapsulate-decapsulate.yaml`), not one giant
  file — keeps diffs small and each file independently re-verifiable.
- Every file's `sources:` block records the exact local PDF path, a human
  label, the retrieval/edition date, and the file's own `sha256` — if the
  PDF is replaced, the checksum mismatch is the trigger to re-verify every
  fact in that file, the same discipline `../README.md`'s refresh policy
  already uses for the raw spec files.
- Every fact carries `section` + `page` (and `table`/`op_codepoint` where
  applicable) so a disagreement can be checked against the PDF in under a
  minute instead of re-deriving it from scratch.

## Index

| File | Topic | Verified against |
|---|---|---|
| [`kem-encapsulate-decapsulate.yaml`](kem-encapsulate-decapsulate.yaml) | KMIP 3.0 `Encapsulate`/`Decapsulate` ops + `KEM Algorithm` enum, PKCS#11 v3.2 `C_EncapsulateKey`/`C_DecapsulateKey` mechanism table rows (RSA, ECDH, DH, X9.42 DH) — the classical-vs-PQC-vs-hybrid KEM question. | KMIP 3.0 **CSD02** (2026-08-12) |

Add a row here whenever a new topic file is added, and update the "Verified against"
column — not just the file's own header — whenever a file is re-verified.
