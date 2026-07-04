# Known-Answer Test Vector Corpus — `pqctoday-hsm/kmip/kat/`

128 KAT files across 8 algorithm families + 102 OASIS KMIP 3.0 conformance test cases.

Used by:

- `tests/kat_replay.rs` — replays every TTLV byte pair in `ttlv-wire/` and OASIS XML test cases.
- `tests/acvp_roundtrip.rs` — drives the `softhsmrustv3` engine directly with the NIST/ACVP
  vector inputs and asserts byte-exact match (or expected pass/fail for sigVer KATs). See
  the coverage matrix below.
- `compliance/profiles/*` — references vector files for profile-driven conformance runs.

## `tests/acvp_roundtrip.rs` — what it actually covers

The KMIP crypto ops dispatch to `softhsmrustv3::{native,crypto}`. ACVP KATs need
deterministic inputs (fixed key/IV/seed/signature) that the KMIP op layer would otherwise
generate server-side, so the test drives the engine API directly — that's the level which
accepts explicit key material.

**Integrity gate:** `manifest_integrity_gate` recomputes the sha256 of every file listed in
`manifest.sha256` (all 128, JSON + XML) and fails loudly on any mismatch before KATs run.

**No silent orphans:** `no_orphan_vector_files` asserts every `*.json` under `kat/` (excluding
the `ttlv-wire/` provenance index) is either consumed by a test or listed in the test's
`KNOWN_UNCONSUMED` set with a reason — a newly-added vector cannot be silently ignored.

| Family (file) | Coverage | Engine entry point |
|---|---|---|
| `sha/sha256,sha384,sha512` | digest == md (byte-exact) | sha2 crate (engine's digest impl) |
| `sha/sha3-256,sha3-512` | digest == md (byte-exact) | sha3 crate (engine's digest impl) |
| `sha/kmac` | mac == expected (byte-exact) | `crypto::sign_kmac_ext` |
| `hmac/hmac-sha256,384,512` | mac == expected (byte-exact) | `crypto::sign_hmac` |
| `aes/aes-cbc` | enc/dec == ct/pt (PKCS#7-padded) | `native::encrypt/decrypt_with_key_bytes` (CKM_AES_CBC_PAD) |
| `aes/aes-ctr` | enc/dec == ct/pt | `native::encrypt/decrypt_with_key_bytes` |
| `aes/aes-gcm` | ct‖tag + tag-verified decrypt | `native::encrypt/decrypt_with_key_bytes` |
| `aes/aes-kw` | wrap/unwrap == wrapped/keyData | `native::aes_key_wrap/unwrap` |
| `rsa/rsa-pss` | sigVer == expected pass/fail | `crypto::verify_rsa` |
| `rsa/rsa-oaep` | decrypt == pt (byte-exact) | `native::decrypt_with_key_bytes` (PKCS#8 assembled from n/e/d/p/q) |
| `ecdsa/ecdsa-p256,p384,p521` | sigVer == expected | `crypto::verify_ecdsa` |
| `ecdsa/ed25519` | sigVer == expected | `crypto::verify_eddsa` |
| `ml-kem/ml-kem` (512/768/1024) | decap shared secret == ss (byte-exact) | `native::register_ml_kem_private_key` + `native::decapsulate` |
| `ml-dsa/ml-dsa` (44/65/87) | sigVer: published sig verifies | `crypto::verify_ml_dsa` |
| `slh-dsa/slh-dsa` (SHA2-128f) | sigVer byte-verified; sigGen determinism+validity | `crypto::verify_slh_dsa` / `crypto::sign_slh_dsa` |

ML-DSA vectors are sigGen-mode but ML-DSA's default signing is hedged (randomized), so we run
the deterministic verify side (each published signature must verify). ML-KEM decapsulation is
deterministic, so it's a genuine byte-exact KAT.

**Deferred (engine lacks a usable entry point — listed in `KNOWN_UNCONSUMED`, not faked):**

| File | Reason |
|---|---|
| `aes/aes-cmac-acvp.json` | engine exposes no AES-CMAC primitive |
| `sha/hkdf-acvp.json` | engine exposes no HKDF primitive |
| `ecdsa/ed448-acvp.json` | engine has no Ed448 implementation (only Ed25519) |
| `ml-dsa/composite-sigs-acvp.json` | self-pinned JOSE composite fixture (not ACVP `testGroups`); no engine composite-signature entry point |

**Known corpus defect:** the `sha/kmac-acvp.json` KMAC256 vector declares `macLen=512` but its
`mac` field is only 63 bytes (truncated one byte + zero-padded). KMAC output length is
determined by `macLen`, so it can never byte-match; that single case is skipped with an explicit
in-test assertion (the well-formed KMAC128 vector carries the byte-exact check). The SLH-DSA
`sigGen` `signature` does not byte-match the engine's deterministic output (generator-specific
`opt_rand`/addrnd wiring); the engine's determinism + signature validity are asserted instead,
and byte-exact sigGen against this fixture is deferred.

The full sha256 manifest is `manifest.sha256` — regenerate after any addition with `find . -type f \( -name "*.json" -o -name "*.xml" \) | sort | xargs shasum -a 256 > manifest.sha256`.

## Provenance

| Directory | Source | Files | Purpose |
|---|---|---|---|
| `oasis-kmip-3.0/mandatory/` | OASIS KMIP Profiles v3.0 ZIP, extracted from `kmip-profiles-v3.0.zip` (2023-11-30) | 95 | OASIS-published mandatory conformance test cases for KMIP 3.0 protocol (classical-only) |
| `oasis-kmip-3.0/optional/` | Same source | 7 | Optional KMIP 3.0 conformance tests (AKLC, CS-RNG, OMOS, SKLC) |
| `oasis-kmip-2.1/` | Download on demand | — (dir not present) | KMIP 2.1 fallback test cases (created only when downloaded for legacy-mode validation) |
| `ttlv-wire/` | Shipped | 6 `.bin` + `manifest.json` | KMIP 3.0 PQC-specific TTLV byte vectors (hand-crafted, codec round-trip) |
| `ml-kem/` | Copy of `pqctoday-hub/src/data/acvp/mlkem_test.json` | 1 | NIST ACVP ML-KEM-512/768/1024 vectors |
| `ml-dsa/` | Copy of `pqctoday-hub/src/data/acvp/mldsa_test.json` + `composite-sigs-jose-kat.json` | 2 | NIST ACVP ML-DSA-44/65/87 + LAMPS draft-19 composite vectors |
| `slh-dsa/` | Copy of `pqctoday-hub/src/data/acvp/slhdsa_ctx_test.json` | 1 | NIST ACVP SLH-DSA SHA2 + SHAKE family with context vectors |
| `rsa/` | Copy of `pqctoday-hub/src/data/acvp/{rsapss,rsa_oaep}_test.json` | 2 | NIST ACVP RSA-PSS + RSA-OAEP vectors |
| `ecdsa/` | Copy of `pqctoday-hub/src/data/acvp/{ecdsa,ecdsa_p384,ecdsa_p521,eddsa,eddsa_ed448}_test.json` | 5 | NIST ACVP ECDSA P-256/384/521 + EdDSA Ed25519/Ed448 vectors |
| `aes/` | Copy of `pqctoday-hub/src/data/acvp/aes{gcm,cbc,cmac,ctr,kw}_test.json` | 5 | NIST CAVP AES vectors in 5 modes |
| `hmac/` | Copy of `pqctoday-hub/src/data/acvp/hmac{,_sha384,_sha512}_test.json` | 3 | NIST ACVP HMAC vectors |
| `sha/` | Copy of `pqctoday-hub/src/data/acvp/{sha256,sha384,sha512,sha3_256,sha3_512,kmac,hkdf}_test.json` | 7 | NIST ACVP digest + KDF vectors |

**Note on `oasis-kmip-2.1/`:** Not present by intent (the directory is created only when needed). The KMIP 3.0 mandatory profile already covers the classical surface; v2.1 fallback vectors are downloaded on demand from `https://docs.oasis-open.org/kmip/kmip-testcases/v2.1/`. See `../spec/oasis-kmip-2.1/kmip-spec-v2.1-os.pdf` for the reference.

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
