# OASIS Specification Library — `pqctoday-hsm/kmip/spec/`

Local copies of the OASIS KMIP + PKCS#11 specification documents that the wrapper validates against. Stored offline so validation runs do not depend on `docs.oasis-open.org` availability.

**Current baseline: CSD02.** The `-csd02` files below are what the code implements and cites;
the CSD01 / WD19 files are retained only so a superseded citation can be traced.

| File | Bytes | Source | Date | Role |
|---|---|---|---|---|
| `oasis-kmip-3.0/kmip-spec-v3.0-csd02.pdf` | 2 962 732 | `https://docs.oasis-open.org/kmip/kmip-spec/v3.0/csd02/kmip-spec-v3.0-csd02.pdf` | 2026-05-07 | **BASELINE** |
| `oasis-kmip-3.0/kmip-spec-v3.0-csd02.html` | 19 266 598 | `https://docs.oasis-open.org/kmip/kmip-spec/v3.0/csd02/kmip-spec-v3.0-csd02.html` | 2026-05-07 | **BASELINE** — extractor input |
| `oasis-kmip-3.0/kmip-profiles-v3.0-csd02.pdf` | 1 278 197 | `https://docs.oasis-open.org/kmip/kmip-profiles/v3.0/csd02/kmip-profiles-v3.0-csd02.pdf` | 2026-05-21 | **BASELINE** — profiles (§3.3 Quantum Safe suite, §5.1.2 Baseline Server) |
| `oasis-kmip-3.0/kmip-profiles-v3.0-csd02.zip` | 1 429 398 | `https://docs.oasis-open.org/kmip/kmip-profiles/v3.0/csd02/kmip-profiles-v3.0-csd02.zip` | 2026-05-21 | **BASELINE** — conformance test cases |
| `oasis-kmip-3.0/kmip-ug-v3.0/` | — | KMIP Usage Guide v3.0 (`.pdf`/`.html`/`.docx`) | 2026-06-18 | companion |
| `oasis-kmip-3.0/kmip-spec-v3.0.pdf` / `.html` | 3 141 715 / 19 055 347 | `https://docs.oasis-open.org/kmip/kmip-spec/v3.0/kmip-spec-v3.0.{pdf,html}` | 2024-08-23 | superseded (CSD01) — retained for citation archaeology |
| `oasis-kmip-3.0/kmip-spec-v3.0-wd19-clean.pdf` | 3 142 670 | Working Draft 19 (pre-CSD, PQC ops added WD17+) | 2025-02-14 | superseded by CSD02 — retained for citation archaeology |
| `oasis-kmip-3.0/kmip-profiles-v3.0.pdf` / `.zip` | 1 142 181 / 8 389 246 | `https://docs.oasis-open.org/kmip/kmip-profiles/v3.0/kmip-profiles-v3.0.{pdf,zip}` | 2023-11-30 | superseded (CSD01 profiles) |
| `oasis-kmip-2.1/kmip-spec-v2.1-os.pdf` | 6 796 775 | `https://docs.oasis-open.org/kmip/kmip-spec/v2.1/os/kmip-spec-v2.1-os.pdf` | 2020-12-14 | fallback reference for legacy-mode clients |
| `../../docs/refs/pkcs11-spec-v3.2-os.pdf` | — | PKCS#11 v3.2 **OASIS Standard** | 2026-06-03 | ratified; content-identical to the CSD01 draft the engine implemented |
| `../../docs/refs/pkcs11-spec-v3.2-csd01.pdf` | 5 142 051 | `https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/csd01/pkcs11-spec-v3.2-csd01.pdf` | 2025-04-16 | superseded by the OS above |

All files have `.sha256` companions next to them; regenerate after any refresh. The PKCS#11 v3.2 PDFs live under `pqctoday-hsm/docs/refs/` (next to the canonical `pkcs11t.h`), not under a `oasis-pkcs11-3.2/` subdirectory here.

**Standardization status (checked 2026-08-12).** KMIP 3.0 CSD02 is a **committee draft, not a ratified OASIS Standard**. It completed a 30-day OASIS public review on **13 Aug 2026** (opened 14 Jul 2026) — the step preceding Committee Specification. PKCS#11 v3.2, by contrast, **is** ratified (OASIS Standard, 3 Jun 2026).

**The PQC surface is now in the published specification.** `Encapsulate` (§6.1.22) / `Decapsulate` (§6.1.15), the `KEM Algorithm` enumeration (§11.26, tag `0x4201c3`), and the ML-KEM/ML-DSA/SLH-DSA and hybrid-KEM codepoints are all in CSD02 — they are no longer WD19-only facts, and the automated tag/enum extractor (`kmip/tools/extract_kmip_spec.rs` → `kmip-spec-3.0-tags-enums.json`) now parses the **CSD02** `.html`, so it covers them. The [`crossref/`](crossref/) fact sheets remain useful for the prose an extractor cannot produce (operation semantics, error tables, cross-spec PKCS#11 mechanism rows) and were re-verified against CSD02 on 2026-08-12.

## Spec watch — what to do when OASIS publishes the next revision

CSD02's public review closed 2026-08-13, so a **CS01** (or a further CSD) is the expected next
artifact. There is no automation for this; it is a manual trigger. When it appears:

1. Download spec + profiles (+ UG if revised) into `oasis-kmip-3.0/`, regenerate `.sha256` sidecars.
2. Re-run the tag/enum extractor against the new `.html`; diff `kmip-spec-3.0-tags-enums.json`.
3. Add the new baseline's `§6.1.x` operation table to `kmip-spec-3.0-section61-headings.json`
   and re-run `kmip/tests/section61_citation_drift.rs` — it catches citations that never migrated.
4. Refresh the conformance corpus from the new profiles `.zip`; re-run the replay
   (`dispatcher_replay.py` → `assert_replay_report.py` → `check_report_fresh.py`).
5. **Re-verify `crossref/*.yaml` by hand** — a checksum change is the trigger, and these facts are
   not covered by any automated check (see [`crossref/README.md`](crossref/README.md)).
6. Re-check the §3.3 Quantum Safe Authentication Suite clause table and the
   `SecP384r1MLKEM1024` codepoint question in `../docs/CONFORMANCE_REPORT.md` §5.2 — the
   Specification assigned no Cryptographic Algorithm value for it in CSD02.
7. Update the baseline statements in `../docs/CONFORMANCE_REPORT.md`, `../docs/CACP_GUIDE.md` §4,
   and this file.

## Use

- **KMIP 3.0 spec (CSD02)** — authoritative source for tag/enum/operation codepoints. The derived tag/enum artifact is `oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json` (extracted from the CSD02 HTML; the prior extraction is kept as `kmip-spec-3.0-tags-enums-from-2023-11-30.json`). The `§6.1.x` operation tables for both baselines live in `kmip-spec-3.0-section61-headings.json` and drive the citation-drift guard.
- **KMIP 3.0 profiles ZIP (CSD02)** — bundles the OASIS-published conformance test cases (extracted into `../kat/oasis-kmip-3.0/`; the replay corpus is `../conformance/oasis_corpus/`).
- **KMIP 2.1 OS** — fallback reference for legacy-mode clients.
- **PKCS#11 v3.2** — referenced from `pqctoday-priv/docs/platform/data/pkcs11-vendor-mech-allocation.md` for vendor mech allocation rationale.

## Refresh policy

OASIS specs are versioned. Refresh quarterly, and whenever the TC announces a new revision
(see "Spec watch" above for the full post-download checklist):

```bash
cd pqctoday-hsm/kmip/spec/oasis-kmip-3.0
for url in \
  "https://docs.oasis-open.org/kmip/kmip-spec/v3.0/csd02/kmip-spec-v3.0-csd02.pdf" \
  "https://docs.oasis-open.org/kmip/kmip-spec/v3.0/csd02/kmip-spec-v3.0-csd02.html" \
  "https://docs.oasis-open.org/kmip/kmip-profiles/v3.0/csd02/kmip-profiles-v3.0-csd02.pdf" \
  "https://docs.oasis-open.org/kmip/kmip-profiles/v3.0/csd02/kmip-profiles-v3.0-csd02.zip"; do
  fname=$(basename "$url")
  curl -sSfL -o "$fname" "$url" && shasum -a 256 "$fname" > "$fname.sha256"
done
```

Substitute the new revision's directory (`cs01/`, `csd03/`, …) when one is published — the
`v3.0/` path without a revision segment still serves CSD01. Diff the `.sha256` sidecars against
what is committed; if any changed, regenerate `src/kmip30/spec_source.json`, re-run the extractor,
and work through the "Spec watch" checklist — a changed checksum invalidates every hand-verified
fact in `crossref/`.

## License (attribution)

OASIS documents are republished under the OASIS IPR Policy:

- KMIP Specification Version 3.0 — Committee Specification Draft 02, 2026-05-07.
- KMIP Profiles Version 3.0 — Committee Specification Draft 02, 2026-05-21.
- KMIP Usage Guide Version 3.0 — 2026-06-18.
- KMIP Specification Version 3.0 — Committee Specification Draft 01, 2024-08-23 (superseded).
- KMIP Profiles Version 3.0 — Committee Specification Draft 01, 2023-11-30 (superseded).
- KMIP Specification Version 2.1 — OASIS Standard, 2020-12-14.
- PKCS#11 Specification Version 3.2 — OASIS Standard, 2026-06-03.

OASIS materials are royalty-free under Limited Terms Mode. Full attribution and license terms: `https://www.oasis-open.org/policies-guidelines/ipr/`.
