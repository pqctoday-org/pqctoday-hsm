# Deprecated mechanisms

This server runs on the `softhsmrustv3` PKCS#11 backend. That backend
**does not implement** the legacy cryptographic mechanisms listed
below, and we do not plan to add them. Any KMIP wire request that
names one of these mechanisms is rejected at decode time with
`WireError::UnknownEnum` → `ResultReason::InvalidMessage` (0x04).

This is a deliberate policy choice, not an implementation gap. The
OASIS conformance corpus contains tests that exercise these
mechanisms; the replay harness reports them as `SKIP_DEPRECATED`
rather than `FAIL` and removes them from the headline pass-rate
denominator.

## Out-of-scope mechanisms

| KMIP `CryptographicAlgorithm` codepoint | Name | Rationale |
|---|---|---|
| `0x01` | DES (single-DES, 56-bit) | NIST [SP 800-131A Rev 2 §1.2.1](https://csrc.nist.gov/pubs/sp/800/131/a/r2/final) — disallowed for federal use since 2005; effective key strength 56 bits is below the 2030 minimum (112 bits). |
| `0x02` | 3DES / DES3 (Triple-DES, 168-bit) | NIST [SP 800-131A Rev 2 §1.2.1](https://csrc.nist.gov/pubs/sp/800/131/a/r2/final) — disallowed for encryption after 2023, disallowed for decryption after 2024. ([NIST blog, 2024](https://csrc.nist.gov/news/2024/decision-to-revise-nist-sp-800-67-revision-2)) |
| `0x05` | DSA (classical discrete-log signatures) | NIST [SP 800-186 §5.4](https://csrc.nist.gov/pubs/sp/800/186/final) + FIPS 186-5 — DSA signing is removed from the federal cryptographic catalogue; new DSA signatures are non-conformant after 2023. |

The corresponding PKCS#11 v3.2 mechanism codepoints (`CKM_DES_*`,
`CKM_DES3_*`, `CKM_DSA*`) are intentionally absent from the KMIP algorithm
table in `src/kmip30/algos.rs` (the `KmipAlgorithm` enum) and have no shim path.

## Affected OASIS conformance tests

5 mandatory tests in `kat/oasis-kmip-3.0/mandatory/` exercise the
deprecated mechanisms. The harness reports them as `SKIP_DEPRECATED`:

| Test | Mechanism | What the test does |
|---|---|---|
| `BL-M-12-30.xml` | DSA | Register `PublicKey` with `KeyFormatType = TransparentDSAPublicKey` (P/Q/G/Y) |
| `BL-M-13-30.xml` | DSA | Register `PrivateKey` with `KeyFormatType = TransparentDSAPrivateKey` (P/Q/G/X) |
| `SKFF-M-4-30.xml` | 3DES | Register `SymmetricKey` with `CryptographicAlgorithm = DES3` (168-bit) |
| `SKFF-M-8-30.xml` | 3DES | Register `SymmetricKey` with `CryptographicAlgorithm = DES3` (168-bit) |
| `SKFF-M-12-30.xml` | 3DES | Create `SymmetricKey` with `CryptographicAlgorithm = DES3` (168-bit) |

No mandatory test in the v3.0 corpus exercises single-DES; the entry
in the skip-list is policy documentation, not a current test exclusion.

## How the harness handles these

- **`kmip/conformance/harness/dispatcher_replay.py`** has a
  `_DEPRECATED_ALGO_TESTS: dict[str, str]` keyed by XML basename.
  `run_test` consults that map first and returns
  `status="SKIP_DEPRECATED"` immediately on hit, before the server
  is contacted.
- **`conformance/REPLAY_REPORT.md`** carries a `SKIP_DEPRECATED` row
  in the aggregate table and lists each skipped test with its
  rationale. The "Of the N tests that exercise only implemented
  + non-deprecated ops" denominator excludes these.

## When (if) this policy changes

Re-enabling support for any of these mechanisms requires:

1. Adding the `KmipAlgorithm` enum variant to `src/kmip30/algos.rs`.
2. Adding a shim path for the mechanism (encrypt/sign/keygen).
3. Adding the wire codec coverage for the new algorithm.
4. Removing the corresponding entry from `_DEPRECATED_ALGO_TESTS`.
5. Documenting the rationale for the policy reversal here.

The most likely candidate for re-enablement would be 3DES (for
legacy decryption only — encrypt is permanently retired by NIST).
DSA + single-DES have no realistic re-enablement path.
