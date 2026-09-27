# Classic McEliece KAT vectors — provenance

Source: the official Round 4 submission's own KAT package, split out separately
from the main submission archive —
`https://classic.mceliece.org/nist/mceliece-kat-20221023.tar.gz`
(sha256 `e63963668d05b78c37bf33994579a12e5792ca086d8d7f2a65df1abc3739dbc3`,
97,874,450 bytes), fetched 2026-09-09. The main submission package (spec text,
reference/optimized/additional C implementations) is the companion
`mceliece-20221023.tar.gz` (sha256
`0428f1c9aeb3472ab580f21693d7fa26ccc92f29beee40a78cc88dab79dfb7a3`) — not
staged here, since only the KAT vectors are needed for cross-implementation
verification; the reference C code itself is not vendored (this repo uses
`classic-mceliece-rust`/liboqs, not the submission's own C).

Each `kat_kem.rsp` is the standard NIST PQC `.rsp` KAT format
(`count`/`seed`/`pk`/`sk`/`ct`/`ss` hex fields), one file per parameter set,
extracted verbatim from `KAT/kem/<variant>/kat_kem.rsp` in the archive above —
nothing regenerated or reformatted locally. Unlike FrodoKEM's 100 vectors per
variant (`../frodokem/README.md`), Classic McEliece's official package ships
**10** vectors per variant (`count = 0`..`9`) — confirmed by count, not
assumed; the smaller count matches the far larger key sizes here (a single
`mceliece8192128` vector already carries a 1.36 MB public key).

Checksums pinned in `../manifest.sha256`. No corresponding `.req`/`.int` files
staged (the archive ships them alongside `.rsp`; they are redundant — every
field a correctness check needs is already in `.rsp` — and FrodoKEM's own
staging already established the convention of keeping only `.rsp`).

| File | Variant | Public key bytes | Secret key bytes | Ciphertext bytes | `.rsp` file bytes |
|---|---|---|---|---|---|
| `mceliece348864/kat_kem.rsp` | Classic-McEliece-348864 | 261,120 | 6,492 | 96 | 5,356,212 |
| `mceliece348864f/kat_kem.rsp` | Classic-McEliece-348864f | 261,120 | 6,492 | 96 | 5,356,213 |
| `mceliece460896/kat_kem.rsp` | Classic-McEliece-460896 | 524,160 | 13,608 | 156 | 10,760,532 |
| `mceliece460896f/kat_kem.rsp` | Classic-McEliece-460896f | 524,160 | 13,608 | 156 | 10,760,533 |
| `mceliece6688128/kat_kem.rsp` | Classic-McEliece-6688128 | 1,044,992 | 13,932 | 208 | 21,184,693 |
| `mceliece6688128f/kat_kem.rsp` | Classic-McEliece-6688128f | 1,044,992 | 13,932 | 208 | 21,184,694 |
| `mceliece6960119/kat_kem.rsp` | Classic-McEliece-6960119 | 1,047,319 | 13,948 | 194 | 21,231,273 |
| `mceliece6960119f/kat_kem.rsp` | Classic-McEliece-6960119f | 1,047,319 | 13,948 | 194 | 21,231,274 |
| `mceliece8192128/kat_kem.rsp` | Classic-McEliece-8192128 | 1,357,824 | 14,120 | 208 | 27,445,093 |
| `mceliece8192128f/kat_kem.rsp` | Classic-McEliece-8192128f | 1,357,824 | 14,120 | 208 | 27,445,094 |

Sizes cross-checked against `classic-mceliece-rust` 3.1.0's own
`CRYPTO_PUBLICKEYBYTES`/`CRYPTO_SECRETKEYBYTES`/`CRYPTO_CIPHERTEXTBYTES`
constants (`api.rs`) and liboqs's algorithm page — both agree byte for byte.

**Status: sourced, not yet consumed.** No test currently reads these files
(the implementation this plan describes — see
`../../../docs/implementation-plan-classic-mceliece-all-parameter-sets-2026-09-08.md`
§7 — hasn't started). Wiring a `classic_mceliece_kat.rs` analogous to
`kmip/tests/frodokem_kat.rs` is part of Phase 1/2's exit criteria, not this
sourcing step.
