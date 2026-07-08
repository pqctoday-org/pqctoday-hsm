# FrodoKEM KAT vectors — provenance

Source: `microsoft/PQCrypto-LWEKE` (the reference implementation frodokem.org's
own spec cites as `[FrodoKEM_code]`), `FrodoKEM/KAT/*.rsp`, fetched from the
`master` branch. Confirmed via the repo's own commit history that these are
the **salted** (post-annex, current-spec) vectors: last touching commit
"Add salted variant of FrodoKEM" (2023-08-26). Matches `frodo-kem` v0.1.0's
implementation — see the FrodoKEM/Classic-McEliece/HQC implementation plan
Phase 0.4/root-cause research for why this distinction matters (liboqs
0.12.0/0.13.0 does *not* implement the salted variant, hence no dynamic
cross-check for FrodoKEM — these static KAT vectors are the primary
correctness evidence instead).

Each file has exactly 100 vectors (`count = 0` .. `count = 99`), NIST
`.rsp` format (`seed`/`pk`/`sk`/`ct`/`ss` hex fields). Checksums pinned in
`../manifest.sha256`. All 600 vectors (100 × 6 variants) are exercised by
`kmip/tests/frodokem_kat.rs`.

| File | Variant | sk bytes |
|---|---|---|
| `PQCkemKAT_19888.rsp` | FrodoKEM-640-AES | 19888 |
| `PQCkemKAT_19888_shake.rsp` | FrodoKEM-640-SHAKE | 19888 |
| `PQCkemKAT_31296.rsp` | FrodoKEM-976-AES | 31296 |
| `PQCkemKAT_31296_shake.rsp` | FrodoKEM-976-SHAKE | 31296 |
| `PQCkemKAT_43088.rsp` | FrodoKEM-1344-AES | 43088 |
| `PQCkemKAT_43088_shake.rsp` | FrodoKEM-1344-SHAKE | 43088 |
