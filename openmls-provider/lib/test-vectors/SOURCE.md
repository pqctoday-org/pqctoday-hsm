# RFC 9420 test vectors (vendored)

Source: <https://github.com/openmls/openmls/tree/main/openmls/test_vectors>
Fetched: 2026-05-16 via `gh api` (raw URL for files > 1 MB)
Pinned upstream: `openmls/openmls` `main` branch

## Files

| File | Size | Runner | Provider-pluggable |
|---|---|---|---|
| `key-schedule.json` | ~99 KB | `openmls::schedule::tests_and_kats::kats::key_schedule::run_test_vector` | yes — accepts `&impl OpenMlsProvider` |
| `treekem.json` | ~1.9 MB | `openmls::treesync::tests_and_kats::kats::kat_treekem::run_test_vector` | yes — accepts `&impl OpenMlsProvider` |

These two vectors are the highest-leverage MLS algorithmic conformance
tests that openmls exposes through a provider-pluggable runner:

- **key-schedule.json** exercises every HKDF-Extract / HKDF-Expand / HMAC
  step in the MLS key schedule (RFC 9420 §8) across all baseline
  ciphersuites our provider supports.
- **treekem.json** exercises full HPKE seal/open under realistic TreeKEM
  path-update flows (RFC 9420 §7).

## What we validate today

`tests/rfc9420_kats.rs` runs:

- **welcome_secret KAT** against every epoch of every supported
  ciphersuite in `key-schedule.json` (10 epochs across 2 ciphersuites).
  Walks the published `joiner_secret` + `psk_secret` through our
  HSM-routed `HKDF-Extract` then `HKDF-Expand` with the RFC 9420
  `KDFLabel` encoding (`"MLS 1.0 welcome"`, empty context, Nh).
  `welcome_secret` is asserted byte-exact against the published vector.

This exercises the two HKDF primitives that every other secret in the
MLS key schedule (RFC 9420 §8.4) is built from. Higher-level secrets
(`encryption_secret`, `confirmation_key`, `exporter_secret`, etc.) are
all `DeriveSecret(...)` calls — i.e., further `HKDF-Expand` invocations
on top of the chain we just verified.

## Known gaps

- **treekem.json: structural KAT added** (cipher_suite dispatch,
  hash-length checks on `confirmed_transcript_hash` + `commit_secret`).
  Full `kat_treekem::run_test_vector` runner blocked by `test-utils`
  feature conflict (see §dependency-constraints); deferred to v0.3.
- **Full key-schedule chain** (joiner_secret derivation,
  GroupContext-bound epoch_secret, all 8 derived secrets) is not
  individually KAT'd. The current welcome_secret check exercises both
  HKDF-Extract and HKDF-Expand-with-label; expanding to the full chain
  would need GroupContext serialization (TLS-encoded structs) which the
  JSON doesn't store standalone.
- `transcript-hashes.json` runner is hard-wired to `OpenMlsRustCrypto`,
  cannot validate our HSM path.
- Other vectors (`crypto-basics`, `secret-tree`, `tree-math`,
  `tree-operations`, `tree-validation`, `passive-client-*`, `welcome`,
  `messages`, `psk_secret`, `deserialization`, `message-protection`,
  `storage-stability`) — useful follow-ups but not gating Stage 2.
