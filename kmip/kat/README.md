# Known-Answer Test Vector Corpus — `pqctoday-hsm/kmip/kat/`

128 KAT files across 8 algorithm families + 102 OASIS KMIP 3.0 conformance test cases.

Used by:

- `tests/kat_replay.rs` — replays every TTLV byte pair in `ttlv-wire/` and OASIS XML test cases.
- `tests/acvp_roundtrip.rs` — drives NIST ACVP vectors through `Create` + crypto op; asserts byte-exact match.
- `compliance/profiles/*` — references vector files for profile-driven conformance runs.

The full sha256 manifest is `manifest.sha256` — regenerate after any addition with `find . -type f \( -name "*.json" -o -name "*.xml" \) | sort | xargs shasum -a 256 > manifest.sha256`.

## Provenance

| Directory | Source | Files | Purpose |
|---|---|---|---|
| `oasis-kmip-3.0/mandatory/` | OASIS KMIP Profiles v3.0 ZIP, extracted from `kmip-profiles-v3.0.zip` (2023-11-30) | 95 | OASIS-published mandatory conformance test cases for KMIP 3.0 protocol (classical-only) |
| `oasis-kmip-3.0/optional/` | Same source | 7 | Optional KMIP 3.0 conformance tests (AKLC, CS-RNG, OMOS, SKLC) |
| `oasis-kmip-2.1/` | Reserved | 0 | KMIP 2.1 fallback test cases (download as needed for legacy-mode validation) |
| `ttlv-wire/` | To be generated | 0 | KMIP 3.0 PQC-specific TTLV byte vectors (hand-crafted, codec round-trip) — populated during Phase 2 of the implementation plan |
| `ml-kem/` | Copy of `pqctoday-hub/src/data/acvp/mlkem_test.json` | 1 | NIST ACVP ML-KEM-512/768/1024 vectors |
| `ml-dsa/` | Copy of `pqctoday-hub/src/data/acvp/mldsa_test.json` + `composite-sigs-jose-kat.json` | 2 | NIST ACVP ML-DSA-44/65/87 + LAMPS draft-19 composite vectors |
| `slh-dsa/` | Copy of `pqctoday-hub/src/data/acvp/slhdsa_ctx_test.json` | 1 | NIST ACVP SLH-DSA SHA2 + SHAKE family with context vectors |
| `rsa/` | Copy of `pqctoday-hub/src/data/acvp/{rsapss,rsa_oaep}_test.json` | 2 | NIST ACVP RSA-PSS + RSA-OAEP vectors |
| `ecdsa/` | Copy of `pqctoday-hub/src/data/acvp/{ecdsa,ecdsa_p384,ecdsa_p521,eddsa,eddsa_ed448}_test.json` | 5 | NIST ACVP ECDSA P-256/384/521 + EdDSA Ed25519/Ed448 vectors |
| `aes/` | Copy of `pqctoday-hub/src/data/acvp/aes{gcm,cbc,cmac,ctr,kw}_test.json` | 5 | NIST CAVP AES vectors in 5 modes |
| `hmac/` | Copy of `pqctoday-hub/src/data/acvp/hmac{,_sha384,_sha512}_test.json` | 3 | NIST ACVP HMAC vectors |
| `sha/` | Copy of `pqctoday-hub/src/data/acvp/{sha256,sha384,sha512,sha3_256,sha3_512,kmac,hkdf}_test.json` | 7 | NIST ACVP digest + KDF vectors |

**Note on `oasis-kmip-2.1/`:** Empty by intent. The KMIP 3.0 mandatory profile already covers the classical surface; v2.1 fallback vectors are downloaded on demand from `https://docs.oasis-open.org/kmip/kmip-testcases/v2.1/`. See `spec/oasis-kmip-2.1/kmip-spec-v2.1-os.pdf` for the reference.

## What OASIS provides for KMIP 3.0 (and what it doesn't)

| Type | Available? | Where |
|---|---|---|
| OASIS specification PDF | ✅ yes | `../spec/oasis-kmip-3.0/kmip-spec-v3.0.pdf` |
| OASIS specification HTML | ✅ yes | `../spec/oasis-kmip-3.0/kmip-spec-v3.0.html` |
| OASIS profiles document | ✅ yes | `../spec/oasis-kmip-3.0/kmip-profiles-v3.0.pdf` |
| OASIS conformance test cases (classical) | ✅ yes (bundled inside the profiles ZIP, not the testcases directory) | `oasis-kmip-3.0/mandatory/` + `optional/` |
| OASIS PQC test cases | ❌ **not published** | gap — KMIP 3.0 spec adds PQC algorithm IDs but OASIS hasn't shipped corresponding test vectors |
| Conformance suite size | 102 tests | (1,452 in the 2025 OASIS interop event uses additional vendor-contributed vectors not in the public ZIP) |

**Implication for our KAT strategy:**

1. Use the 102 OASIS XML test cases as the **classical KMIP 3.0 baseline** — they cover all the inherited-from-2.1 operations.
2. For PQC operations (`Create` ML-KEM-768, `Encapsulate`, `Decapsulate`, `Sign` ML-DSA-65, `SignatureVerify`): **hand-craft TTLV byte vectors** during Phase 2 of the implementation plan (`tests/kat_replay.rs`). Each hand-crafted vector is documented in `ttlv-wire/manifest.json` with `provenance: codec-roundtrip-2026-MM-DD` so it's clear we generated it (not OASIS-published).
3. For PQC cryptographic correctness (the actual ML-KEM / ML-DSA output bytes), use the NIST ACVP vectors in `ml-kem/`, `ml-dsa/`, `slh-dsa/` — these ARE byte-exact authoritative sources.

This split is honest: OASIS validates our KMIP protocol surface, NIST validates our PQC cryptographic output.

## Test case naming convention (OASIS KMIP 3.0 mandatory)

| Prefix | Category | Count |
|---|---|---|
| `CS-*` | Cryptographic Services (AC = asymmetric, BC = block cipher, RNG) | 41 |
| `BL-*` | Basic Lifecycle | 21 |
| `SKFF-*` | Symmetric Key Foundry & Friends (derivation, wrapping) | 12 |
| `TL-*` | Transport Layer | 3 |
| `SKLC-*` | Symmetric Key Lifecycle | 3 |
| `SASED-*` | Server Attribute Setting / Get Attribute Discovery | 3 |
| `MSGENC-*` | Message Encoding (HTTPS, TTLV, JSON) | 3 |
| `AKLC-*` | Asymmetric Key Lifecycle | 3 |
| `QS-*` | Query Server | 2 |
| `AX-*` | Attribute Extensions | 2 |
| `PKCS11-M-1-30.xml` | PKCS#11 interop (1 test) | 1 |
| `OMOS-M-*` | Object Management Object Set | 1 |

The `-30` suffix marks KMIP 3.0; `-M-` denotes mandatory; `-O-` optional.

## Adding a new vector

1. Decide the algorithm family (or `oasis-kmip-3.0/` for protocol-level vectors).
2. Drop the file into the right directory.
3. Update this README's provenance table.
4. Regenerate `manifest.sha256`.
5. Add a test case in `tests/{kat_replay,acvp_roundtrip}.rs` that consumes the new vector.

## License

OASIS KMIP test cases are published under the OASIS IPR Policy with royalty-free terms (RF on Limited Terms Mode). NIST ACVP vectors are public-domain (US Government work, 17 USC §105). All files in this corpus are redistributable as part of `pqctoday-hsm/kmip/` (MIT license).
