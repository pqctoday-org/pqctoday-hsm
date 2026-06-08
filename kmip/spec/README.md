# OASIS Specification Library — `pqctoday-hsm/kmip/spec/`

Local copies of the OASIS KMIP + PKCS#11 specification documents that the wrapper validates against. Stored offline so validation runs do not depend on `docs.oasis-open.org` availability.

| File | Bytes | Source | Date |
|---|---|---|---|
| `oasis-kmip-3.0/kmip-spec-v3.0.pdf` | 3 141 715 | `https://docs.oasis-open.org/kmip/kmip-spec/v3.0/kmip-spec-v3.0.pdf` | 2024-08-23 |
| `oasis-kmip-3.0/kmip-spec-v3.0.html` | 19 055 347 | `https://docs.oasis-open.org/kmip/kmip-spec/v3.0/kmip-spec-v3.0.html` | 2024-08-23 |
| `oasis-kmip-3.0/kmip-profiles-v3.0.pdf` | 1 142 181 | `https://docs.oasis-open.org/kmip/kmip-profiles/v3.0/kmip-profiles-v3.0.pdf` | 2023-11-30 |
| `oasis-kmip-3.0/kmip-profiles-v3.0.zip` | 8 389 246 | `https://docs.oasis-open.org/kmip/kmip-profiles/v3.0/kmip-profiles-v3.0.zip` | 2023-11-30 |
| `oasis-kmip-2.1/kmip-spec-v2.1-os.pdf` | 6 796 775 | `https://docs.oasis-open.org/kmip/kmip-spec/v2.1/os/kmip-spec-v2.1-os.pdf` | 2020-12-14 |
| `oasis-pkcs11-3.2/` | TBD | `https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/` | TBD |

All files have `.sha256` companions next to them; regenerate after any refresh.

## Use

- **KMIP 3.0 spec** — authoritative source for tag/enum/operation codepoints. The `src/kmip30/spec_source.json` file is derived from this PDF (Phase 1 of the implementation plan: `caffeinate -i ollama run qwen3.6:27b` extraction).
- **KMIP 3.0 profiles ZIP** — bundles the OASIS-published conformance test cases (extracted into `../kat/oasis-kmip-3.0/`).
- **KMIP 2.1 OS** — fallback reference for legacy-mode clients.
- **PKCS#11 v3.2** — referenced from `pqctoday-priv/docs/platform/data/pkcs11-vendor-mech-allocation.md` for vendor mech allocation rationale.

## Refresh policy

OASIS specs are versioned. Refresh quarterly:

```bash
cd pqctoday-hsm/kmip/spec
for url in \
  "https://docs.oasis-open.org/kmip/kmip-spec/v3.0/kmip-spec-v3.0.pdf" \
  "https://docs.oasis-open.org/kmip/kmip-spec/v3.0/kmip-spec-v3.0.html" \
  "https://docs.oasis-open.org/kmip/kmip-profiles/v3.0/kmip-profiles-v3.0.pdf" \
  "https://docs.oasis-open.org/kmip/kmip-profiles/v3.0/kmip-profiles-v3.0.zip" \
  "https://docs.oasis-open.org/kmip/kmip-spec/v2.1/os/kmip-spec-v2.1-os.pdf"; do
  fname=$(basename "$url")
  curl -sSfL -o "oasis-kmip-*/${fname}" "$url"
done
find . -type f \( -name "*.pdf" -o -name "*.html" -o -name "*.zip" \) -exec shasum -a 256 {} \; > checksums.sha256
```

Diff `checksums.sha256` against committed; if changed, regenerate `src/kmip30/spec_source.json` and rerun the standalone validation gate.

## License (attribution)

OASIS documents are republished under the OASIS IPR Policy:

- KMIP Specification Version 3.0 — Committee Specification, 2024-08-23.
- KMIP Profiles Version 3.0 — Committee Specification 01, 2023-11-30.
- KMIP Specification Version 2.1 — OASIS Standard, 2020-12-14.

OASIS materials are royalty-free under Limited Terms Mode. Full attribution and license terms: `https://www.oasis-open.org/policies-guidelines/ipr/`.
