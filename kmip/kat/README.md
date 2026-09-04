# Known-Answer Test Vector Corpus — `pqctoday-hsm/kmip/kat/`

143 files total: 41 non-OASIS vector files (28 NIST ACVP/CAVP JSON vectors across
8 crypto-primitive families, 6 FrodoKEM reference `.rsp` files, 6 hand-crafted TTLV
byte vectors + a provenance manifest, 1 external composite-signature fixture, and 1
OASIS PQC-interop engine-vector fixture) + 102 OASIS KMIP 3.0 conformance test cases
(XML). Counts verified against the actual tree — recompute with `find . -type f \(
-name "*.json" -o -name "*.xml" -o -name "*.rsp" -o -name "*.bin" \) | wc -l` if this
drifts.

Used by:

- `tests/kat_replay.rs` — replays every TTLV byte pair in `ttlv-wire/` and OASIS XML test cases.
- `tests/acvp_roundtrip.rs` — drives the `softhsmrustv3` engine directly with the NIST/ACVP
  vector inputs and asserts byte-exact match (or expected pass/fail for sigVer KATs). Also
  the single orphan-file registry for everything under `kat/` (its `no_orphan_vector_files`
  test walks the whole tree, not just its own `CONSUMED` list — see the coverage matrix below).
- `tests/pqc_interop_engine.rs` — drives the engine against `pqc-interop/`'s vectors,
  extracted from the OASIS 1452-transcript PQC interop set (see that row below).
- `src/ops/validate.rs` (`external_composite_vectors_verify`, a `#[cfg(test)]` unit test in
  the lib crate, not an integration test) — drives `composite-sigs/`'s vectors.
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
| `ml-kem/` | Copy of `pqctoday-hub/src/data/acvp/mlkem_test.json` — real NIST ACVP-Server sample data, byte-verified (2026-08-24 WS-6/K-3; see the file's own `_provenance` block) | 1 | NIST ACVP ML-KEM-512/768/1024 vectors |
| `ml-dsa/` | Copy of `pqctoday-hub/src/data/acvp/mldsa_test.json` + `composite-sigs-jose-kat.json` — real NIST ACVP-Server sample data, byte-verified (2026-08-24 WS-6/K-3) | 2 | NIST ACVP ML-DSA-44/65/87 + LAMPS draft-19 composite vectors |
| `slh-dsa/` | Copy of `pqctoday-hub/src/data/acvp/slhdsa_ctx_test.json` — real NIST ACVP-Server sample data, all 12 parameter sets (2026-08-24 WS-6/K-3/H-4; previously covered only SLH-DSA-SHA2-128f, itself unverified) | 1 | NIST ACVP SLH-DSA SHA2 + SHAKE family (all 12 param sets) with context vectors |
| `frodokem/raw/` | Microsoft `PQCrypto-LWEKE` reference implementation KATs (own README, already provenance-complete — see `frodokem/README.md`) | 6 | FrodoKEM-640/976/1344 × AES/SHAKE, 100 vectors each |
| `rsa/` | Copy of `pqctoday-hub/src/data/acvp/{rsapss,rsa_oaep}_test.json` | 2 | NIST ACVP RSA-PSS + RSA-OAEP vectors |
| `ecdsa/` | Copy of `pqctoday-hub/src/data/acvp/{ecdsa,ecdsa_p384,ecdsa_p521,eddsa,eddsa_ed448}_test.json` | 5 | NIST ACVP ECDSA P-256/384/521 + EdDSA Ed25519/Ed448 vectors |
| `aes/` | Copy of `pqctoday-hub/src/data/acvp/aes{gcm,cbc,cmac,ctr,kw}_test.json` | 5 | NIST CAVP AES vectors in 5 modes |
| `hmac/` | Copy of `pqctoday-hub/src/data/acvp/hmac{,_sha384,_sha512}_test.json` | 3 | NIST ACVP HMAC vectors |
| `sha/` | Copy of `pqctoday-hub/src/data/acvp/{sha256,sha384,sha512,sha3_256,sha3_512,kmac,hkdf}_test.json` | 7 | NIST ACVP digest + KDF vectors |
| `composite-sigs/external-composite-vectors.json` | Produced by **other** implementations, not this engine — deliberately, to catch cross-implementation interop bugs a self-generated vector structurally cannot (this file exists because a real one shipped 2026-08-17: the engine signed a composite certificate's classical half with SHA-512 instead of the draft-composite-sigs §6 "Traditional Signature Algorithm", and every self-round-trip test still passed because signer and verifier shared the same wrong table). 5 certificate vectors. **Never regenerate locally** — refresh only by pulling a newer upstream round | 1 | Cross-implementation composite-signature verification vectors |
| `pqc-interop/pqc_interop_engine_vectors.json` | Extracted by `scripts/extract_pqc_interop_vectors.py` from the OASIS KMIP 3.0 PQC interop test set (`kmip-3-0-pqc-tests-03.zip`, 2025-02-26, the same 1452-transcript set `../conformance/pqc_corpus/` vendors a subset of) — engine-level (input → expected-output) vectors for keygen/encapsulate/decapsulate (vendored in full: 270/30/75) and a representative siggen/sigver subset, for `tests/pqc_interop_engine.rs`'s byte-exact I0 checks at the `native`/`crypto` level (no KMIP, no dispatcher) | 1 | OASIS PQC interop engine-level vectors |

**Note on `oasis-kmip-2.1/`:** Not present by intent (the directory is created only when needed). The KMIP 3.0 mandatory profile already covers the classical surface; v2.1 fallback vectors are downloaded on demand from `https://docs.oasis-open.org/kmip/kmip-testcases/v2.1/`. See `../spec/oasis-kmip-2.1/kmip-spec-v2.1-os.pdf` for the reference.

### Classic McEliece — permanent gap, not an oversight (P-2, formalized 2026-08-24)

Classic McEliece has real functional coverage (`kmip/tests/frodokem_mceliece_e2e.rs`,
self-consistency round-trip) but **no external KAT vector of any kind** — not
NIST ACVP (never registered), not a submission-package static KAT, not even
the crate's own test harness. This was investigated during the 2026-07-25
FrodoKEM/McEliece C++/Rust parity work
(`docs/remediation-plan-cpp-rust-pkcs11-parity-2026-07-25.md` §4): the crate
in use, `classic-mceliece-rust` v3.1.0, ships no static KAT file, and neither
does PQClean's reference implementation the way FrodoKEM's `PQCrypto-LWEKE`
does. FrodoKEM's real, provenance-complete vectors above are a genuine
external check for that algorithm; nothing equivalent exists to pull for
McEliece with the crate this engine uses. Per the WS-6 remediation plan §6.5:
this is a legitimate bottom rung on the trust ladder, not a failure — but it
must be labeled honestly rather than left silently indistinguishable from the
vector-backed rows above. McEliece's only correctness evidence is the functional round-trip test —
**not even cross-engine differential comparison is available**: the C++
engine has no Classic McEliece implementation at all (`src/lib/` carries
no McEliece code; confirmed by grep, not assumed), so there is no second
engine to diff against, unlike FrodoKEM which the differential harness
does exercise. Never report McEliece as "ACVP-validated", "KAT-proven",
or "cross-validated" — self-consistency is the entire evidence base.

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
4. Regenerate `manifest.sha256` — `find . -type f \( -name "*.json" -o -name "*.xml" \) | sort | xargs shasum -a 256 > manifest.sha256`.
5. Add a test case in `tests/{kat_replay,acvp_roundtrip}.rs` (or the specific
   integration test / lib unit test that owns the family, e.g.
   `tests/pqc_interop_engine.rs` for `pqc-interop/`) that consumes the new vector.
6. **A new `*.json` under `kat/` will not build silently unconsumed.**
   `tests/acvp_roundtrip.rs::no_orphan_vector_files` walks the entire `kat/`
   tree (skipping only `ttlv-wire/` and `pqc-interop/`, which have their own
   guards) and fails if a file is neither in that test's `CONSUMED` list nor
   in `KNOWN_UNCONSUMED` with a reason — add the new file's path to whichever
   list actually applies, or the integration test suite fails to compile clean.

## License

OASIS KMIP test cases are published under the OASIS IPR Policy with royalty-free terms (RF on Limited Terms Mode). NIST ACVP vectors are public-domain (US Government work, 17 USC §105). All files in this corpus are redistributable as part of `pqctoday-hsm/kmip/` (MIT license).
