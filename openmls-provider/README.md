# `openmls_pqctoday_crypto`

OpenMLS crypto + RNG provider that routes the `OpenMlsCrypto` trait surface
through **PKCS#11 v3.2** against softhsmv3 (or any conformant module).

Sibling integration to:

- [`rust/`](../rust) — the softhsmrustv3 engine (the module this provider
  talks to by default)
- [`openpgp/`](../openpgp) — Sequoia-PGP integration

## What runs in the HSM (v0.1)

| OpenMlsCrypto fn | PKCS#11 path | HSM-resident |
| --- | --- | :---: |
| `hash` | `C_DigestInit` + `C_Digest` (SHA-256/384/512) | yes |
| `hmac` | `C_SignInit(CKM_*_HMAC)` + `C_Sign` | yes |
| `hkdf_extract` / `hkdf_expand` | RFC 5869 over `CKM_*_HMAC` (HSM-resident IKM/PRK) | yes |
| `aead_encrypt` / `aead_decrypt` (suites 1, 2) | `CKM_AES_GCM` | yes |
| `aead_encrypt` / `aead_decrypt` (suite 3, X-Wing) | `CKM_CHACHA20_POLY1305` via the `softhsmrustv3` Rust engine (`backend.rs`'s `PkcsOps::chacha20_poly1305`) | yes |
| `signature_key_gen` | `C_GenerateKeyPair(CKM_EC_EDWARDS_KEY_PAIR_GEN` / `CKM_EC_KEY_PAIR_GEN)` as **token object** | yes |
| `sign` / `verify_signature` | `CKM_EDDSA` / `CKM_ECDSA_SHA*` | yes |
| HPKE / `DhKem25519`+`HkdfSha256`+`AesGcm128` | `CKM_ECDH1_DERIVE` + `CKM_SHA256_HMAC` + `CKM_AES_GCM` (RFC 9180 in `hpke.rs`) | yes |
| HPKE / X-Wing (ML-KEM-768 + X25519) + ChaCha20-Poly1305 | ML-KEM-768 keygen/encapsulate/decapsulate + X25519 `CKM_ECDH1_DERIVE`, SHAKE-256 seed expansion and the SHA3-256 combiner via the Rust engine's `native::derive::{shake256_xof, run_combiner}`, `CKM_CHACHA20_POLY1305` for the AEAD (draft-connolly-cfrg-xwing-kem in `hpke.rs`) | yes |
| HPKE / other suites (`DhKemP256`/`P384`/`P521`/`448`) | `hpke-rs-rust-crypto` fallback in-process | **no — Phase 2.1** |

## Signature key custody

The big idea: **signature keys never leave the HSM**.

`signature_key_gen()` generates the key pair as **token objects** with
`CKA_SENSITIVE=TRUE` and `CKA_EXTRACTABLE=FALSE`. What we hand back to
OpenMLS as the `private_key: Vec<u8>` is **not** raw key material — it's an
opaque, versioned `HsmKeyHandle` blob that this provider knows how to
resolve back to a PKCS#11 object handle on the next `sign()` call.

```text
HsmKeyHandle wire format
┌────────┬─────────┬──────────┬──────────────┬────────────┐
│ "PQTH" │ ver (1) │ sig sch. │ cka_id_len   │  cka_id    │
│  4 B   │   1 B   │   2 B    │     2 B      │   N bytes  │
└────────┴─────────┴──────────┴──────────────┴────────────┘
```

OpenMLS just persists this blob in its `StorageProvider` like any other key.
We unpack it on every `sign()` and look up the matching token object via
`C_FindObjects({ CKA_CLASS=PRIVATE_KEY, CKA_ID=… })`. Real key bytes never
exist in process memory.

## Supported ciphersuites

- `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`
- `MLS_128_DHKEMP256_AES128GCM_SHA256_P256`
- `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` (suite 3 — added
  2026-08-10; the ChaCha20-Poly1305 record-layer AEAD was already
  implemented for HPKE's own inner AEAD, just not declared for the record
  layer; the WG interop rig had already exercised it under the union of
  both peers' advertised suites)
- `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519` (post-quantum — X-Wing
  (ML-KEM-768 + X25519) with Ed25519 signatures; the only PQ suite the
  released `openmls_traits` defines)

The first two are the MLS RFC 9420 baseline ciphersuites whose primitives
map cleanly onto mechanisms softhsmv3 already supports. Suite 3 and X-Wing
are `draft-ietf-mls-pq-ciphersuites`-adjacent constructions this provider
wires directly against `openmls_traits::types::Ciphersuite`'s existing
variants — see the "What runs in the HSM" table above for exactly which
primitives each one dispatches through the engine, and Phase 4 below for
what's still open.

## Usage

```rust
use openmls_pqctoday_crypto::{HsmConfig, PqcTodayProvider};

let cfg = HsmConfig::new("/usr/local/lib/softhsm/libsofthsm-pqctoday.so")
    .with_pin("1234");
let provider = PqcTodayProvider::new(&cfg)?;

// Pass `&provider` anywhere OpenMLS asks for an `&impl OpenMlsProvider`.
```

## Build

```bash
cd openmls-provider
cargo build --release
```

Targets the host triple. Browser/WASM target shares the same crate but uses
the in-process softhsmrustv3 backend — see Phase 5.

## Test

```bash
# Auto-resolves ../../build/src/lib/libsofthsmv3.{dylib,so}.
# Or set PKCS11_MODULE to point at another conformant module.
cargo test --release --test integration -- --test-threads=1
```

`--test-threads=1` is required: softhsmv3 doesn't support multiple
concurrent `C_Initialize` calls in the same process, and each test spins
up its own per-test token in a tmpdir. The integration suite (27 tests)
covers SHA-256/384/512, HMAC, HKDF (RFC 5869 §A.1 KATs, incl. cross-impl
checks for SHA-384/512), AES-128/256-GCM (with tamper detection and AAD
cross-impl checks), Ed25519 and ECDSA P-256 sign/verify (incl. RFC 8032/
RFC 6979 KATs), RNG, HPKE-X25519 (RFC 9180 §A.1.1), the X-Wing combiner,
and ciphersuite enumeration — all run end-to-end against a real softhsmv3
native module.

## Roadmap

### Phase 2 — HSM-resident HPKE (✅ done in v0.2 for `DhKem25519`)

The 5 HPKE entry points now run end-to-end through PKCS#11 primitives for
the suite used by `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`:
DH via `CKM_ECDH1_DERIVE`, HKDF stitched over `CKM_SHA256_HMAC`, AEAD via
`CKM_AES_GCM`. RFC 9180 implementation lives in
[`lib/src/hpke.rs`](lib/src/hpke.rs). Interop with `hpke-rs` is verified
in both directions by the `hpke_pkcs11_path_interops_with_hpke_rs` and
`hpke_pkcs11_exporter_secret_matches_hpke_rs` integration tests.

### Phase 2.1 — Remaining HPKE suites

Generalise `hpke.rs` to cover `DhKemP256`, `DhKemP384`, `DhKemP521`, and
`DhKem448` plus the SHA-384 / SHA-512 KDFs and ChaCha20-Poly1305 AEAD —
all of which softhsmv3 supports. Trait-level dispatch already routes
unmatched suites to `hpke-rs` as a safety net, so this is incremental.

### Phase 3 — Storage in the HSM (✅ v0.1 done)

Group state can now be **snapshotted to and restored from the HSM** as a
single `CKO_DATA` token object via [`crate::persistence`]
([`lib/src/persistence.rs`](lib/src/persistence.rs)):

```rust
// At launch — restores from CKO_DATA at `label`, or starts fresh.
let provider = PqcTodayProvider::with_persistence(&cfg, "alice-group-state")?;
// ... drive an MlsGroup through `&provider` ...
provider.persist()?;          // checkpoint to HSM at any save point
// process exits — `MemoryStorage` heap is gone, snapshot survives.
// Next launch with same `label` restores the full state.
```

**Wire format**: `"PQSM"` magic + version byte + length-prefixed KV
records, written as the `CKA_VALUE` of a `CKO_DATA` object with
`CKA_TOKEN=TRUE` + `CKA_PRIVATE=TRUE` (so it requires the user PIN to
read). Validated by [`tests/persistence_e2e.rs`](lib/tests/persistence_e2e.rs)
which builds a 2-member MLS group, persists, drops the provider, reopens
against the same token, and asserts the group reloads at the same epoch
with the same member list.

**Architecture choice**: we snapshot the entire
`MemoryStorage::values: HashMap<Vec<u8>, Vec<u8>>` map as one blob
rather than wrap all 57 `StorageProvider` trait methods to do per-key
PKCS#11 I/O. Trade-off: each `persist()` rewrites the whole blob (fine
for explicit checkpoint semantics; future Phase 3.1 can add
write-through caching if a use case demands it).

### Phase 4 — PQ ciphersuites (`draft-ietf-mls-pq-ciphersuites`)

**✅ KEM half done (2026-08-10).** `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519`
— the one PQ suite the released `openmls_traits` defines — is wired end to
end: X-Wing's ML-KEM-768 half runs through `CKM_ML_KEM_KEY_PAIR_GEN` /
`CKM_ML_KEM_ENCAPSULATE` / `CKM_ML_KEM_DECAPSULATE` (via the
`softhsmrustv3` Rust engine — `cryptoki` 0.10's mechanism allowlist and
function-list enum don't reach these v3.2 additions, so this path goes
through the engine's `native::*` typed API rather than `cryptoki`), and
its SHAKE-256/SHA3-256 combiner steps run through the same engine's
`native::derive` module. See the "What runs in the HSM" table above.

**Still open: PQ signatures.** This suite signs with Ed25519, not ML-DSA —
the released `openmls_traits::types::Ciphersuite` has no ML-KEM+ML-DSA
combination yet. When one lands, wire it through
`CKM_ML_DSA_KEY_PAIR_GEN` / `CKM_ML_DSA`, both already implemented by
softhsmv3 (FIPS 204).

### Phase 5 — WASM target

Replace the `cryptoki` backend with a thin Rust adapter that calls
softhsmrustv3's `_C_*` wasm-bindgen exports directly. Same crate, different
backend feature flag. Lets the OpenMLS playground in `pqctoday-hub` run
fully in-browser.

**Status (2026-05-17)**:

- ✅ **Cargo plumbing**: `cryptoki` is gated behind
  `cfg(not(target_arch = "wasm32"))` in `lib/Cargo.toml`; wasm32-only
  `getrandom = { features = ["js"] }` is wired for transitive deps.
- ✅ **Sibling-project blocker cleared**: `pqctoday-hsm/rust/`
  (softhsmrustv3) now compiles end-to-end on `wasm32-unknown-unknown`.
  Two fixes landed in the sibling tree:
  - `fips205-patched/src/hashers.rs`: 6 `hasher.update(message)` sites
    hit `E0034` (`Update::update` vs `Digest::update` ambiguity, only
    surfaced on wasm32) — disambiguated via UFCS
    `<ShaXXX as Digest>::update(&mut hasher, message)`.
  - `rust/src/ffi.rs::with_rng!`: the `if let Some(ref mut $rng)` branch
    bound `$rng` as `&mut T` but with an *immutable binding*, breaking
    15 `&mut rng` re-borrows on wasm32 (E0596). Rebound through
    `let mut $rng = _acvp` to make the binding mutable. Native untouched.
- ✅ **Architectural viability proven** ([`wasm-smoke/`](wasm-smoke/)):
  a workspace member compiles softhsmrustv3 into a wasm32 module and
  drives its `C_*` PKCS#11 entry points from another Rust crate. Grew from
  the original 2 `#[wasm_bindgen_test]`s to 8, covering SHA-256
  (`C_DigestInit`/`C_Digest`, FIPS 180-4 §B.1 KAT), HMAC-SHA256 (RFC 4231
  TC1), `C_GenerateRandom` non-triviality, Ed25519 sign/verify round-trip
  plus a negative (wrong-message-rejected) case, AES-128-GCM encrypt and
  decrypt (NIST GCM spec TC3), and `CKO_DATA` object create/find/read/
  destroy lifecycle — all in wasm32.
  Run with `wasm-pack test --node wasm-smoke` (requires Node 20+;
  softhsmrustv3 also gained an `#![allow(unsafe_op_in_unsafe_fn)]`
  to compile as a dependency under Rust 2024 edition).
- ✅ **In-crate architecture refactor complete**: `PkcsOps` trait in
  [`lib/src/backend.rs`](lib/src/backend.rs) abstracts the PKCS#11 (plus
  softhsmrustv3-native, for the operations `cryptoki` can't express)
  surface — `random`, `hash`, `hmac`, `aead_encrypt`/`aead_decrypt`,
  `shake256`, `xwing_combine`, `chacha20_poly1305`,
  `ml_kem_768_keygen_from_seed`/`ml_kem_decapsulate`/
  `ml_kem_encapsulate_to`, `ecdh_x25519`,
  `signature_key_gen`/`sign`/`verify_signature`, and
  `snapshot_write`/`snapshot_read` (17 methods — grew from the original 10
  when Phase 4's X-Wing work added the KEM/combiner/AEAD methods).
  `CryptokiBackend` wraps `HsmSession` for native targets;
  `WasmPkcs11Backend` drives softhsmrustv3 `C_*` calls directly on
  `wasm32-unknown-unknown`. All call sites in `crypto.rs`, `hpke.rs`,
  `signer.rs`, and `persistence.rs` migrated to `Arc<dyn PkcsOps>`.
  `cargo check --target wasm32-unknown-unknown` passes clean.

## Real-world validation

In addition to the spec-aligned KATs above, the provider is exercised
end-to-end against the canonical `openmls` library:

- **[`lib/examples/two_member_group.rs`](lib/examples/two_member_group.rs)**
  — runs a full 8-step `MlsGroup` lifecycle (KeyPackage → Add → Welcome
  → Commit → application message both directions) through two
  `PqcTodayProvider` instances sharing one softhsm token, with HSM-resident
  Ed25519 credential signers via
  [`PqcTodayHsmSigner`](lib/src/signer.rs).
- **[`lib/examples/two_member_group_rustcrypto.rs`](lib/examples/two_member_group_rustcrypto.rs)**
  — same scenario with stock `OpenMlsRustCrypto` + software
  `SignatureKeyPair`, used as the apples-to-apples reference.
- **[`lib/tests/openmls_contract.rs`](lib/tests/openmls_contract.rs)**
  — semantic-equivalence cross-validation: drives both flows, asserts
  identical epoch numbers, member counts, decrypted plaintexts. Test
  named `semantic_equivalence_vs_rustcrypto`.
- **[`lib/tests/rfc9420_kats.rs`](lib/tests/rfc9420_kats.rs)** — RFC
  9420 §8 key-schedule KAT against IETF-published vectors. Walks
  15 epochs across 3 ciphersuites (grew from 10/2 once suite 3 was
  declared) through our HSM-routed HKDF-Extract + HKDF-Expand under the
  MLS `KDFLabel` encoding; every `welcome_secret` matches byte-exactly.
- **[`interop/`](interop/)** — `tonic`-based gRPC server speaking the
  IETF `mls_client.MLSClient` contract from
  [`mlswg/mls-implementations`](https://github.com/mlswg/mls-implementations).
  21 of 34 RPCs are implemented (full parity with `openmls/interop_client`);
  the remaining 13 return `UNIMPLEMENTED`. Smoke test in
  `interop/tests/grpc_smoke.rs` proves the wire-level protobuf contract is
  correct end-to-end.

Run everything:

```bash
cargo test --release -- --test-threads=1   # all unit + integration + KAT tests
cargo run --release --example two_member_group
cargo run --release --example two_member_group_rustcrypto
cargo run --release --bin pqctoday-mls-grpc -- --port 50053
```

## How this compares to upstream providers

| Capability | `openmls_rust_crypto` (default) | `openmls_libcrux_crypto` | **`openmls_pqctoday_crypto`** |
| --- | :---: | :---: | :---: |
| Implementation | RustCrypto crates (`sha2`, `aes-gcm`, `hpke-rs`, `ed25519-dalek`, `p256`) | Cryspen libcrux (formally-verified primitives) | PKCS#11 v3.2 via `cryptoki` |
| Backing | pure-Rust software | pure-Rust software | softhsmv3 native module (any conformant module works) |
| Signature key custody | in-process `Vec<u8>` | in-process `Vec<u8>` | **HSM token object, `CKA_EXTRACTABLE=FALSE`** |
| HPKE execution | in-process (`hpke-rs-rust-crypto`) | in-process (`hpke-rs-libcrux`) | **HSM-resident for X25519+SHA256+AES128GCM (Phase 2) and X-Wing+SHA256+ChaCha20Poly1305 (Phase 4)** |
| Hash / HMAC / HKDF | in-process | in-process (verified) | **HSM-resident via `CKM_*`** |
| AEAD | in-process | in-process (verified) | **HSM-resident via `CKM_AES_GCM`** (suites 1, 2) **/ `CKM_CHACHA20_POLY1305`** (suite 3, X-Wing) |
| Randomness | OS `getrandom` | OS `getrandom` | **HSM DRBG via `C_GenerateRandom`** |
| PQ KEM / signature scheme support | none | ML-KEM available in `libcrux` but not wired to OpenMLS provider yet | **ML-KEM (X-Wing) wired and HSM-resident (Phase 4)**; ML-DSA signatures still open — no released `openmls_traits` ciphersuite combines them yet |
| FIPS validation path | n/a | n/a (libcrux is formally-verified, not FIPS-validated) | **inherited from the underlying HSM** — drop in a FIPS-validated module (Luna, nCipher, Entrust) without changing the provider |
| Browser / WASM | yes (via `openmls-wasm` wrapper) | yes | **Phase 5 complete** — `WasmPkcs11Backend` in `backend.rs` drives softhsmrustv3 `C_*` calls directly; `cargo check --target wasm32-unknown-unknown` passes clean |

The unique slot this crate fills: **HSM custody for OpenMLS signature
keys** plus an audit-traceable, FIPS-eligible execution path for every
crypto operation. That story is the centrepiece of the MLS learn module
in `pqctoday-hub`.

## Verification

### Tier A — RFC 9420 algorithmic KATs

Vendored test-vector files in [`lib/test-vectors/`](lib/test-vectors/) prove
the PKCS#11-routed primitives satisfy the MLS sub-protocol math:

| Vector file | What it exercises | Tests |
| --- | --- | --- |
| `key-schedule.json` | HKDF-Extract/Expand + HMAC over 15 epochs across 3 ciphersuites; `welcome_secret` asserted byte-exact | `rfc9420_key_schedule_hkdf_kat` |
| `treekem.json` | `confirmed_transcript_hash` + `commit_secret` length assertions across 33 vectors / 186 update-paths (of 77 total in the file — the rest cover DHKemP384/P521/448 suites still open per Phase 2.1) | `rfc9420_treekem_vectors_structural_kat` |

`transcript-hashes.json` was evaluated but its runner is hard-wired to
`OpenMlsRustCrypto` and cannot be plugged into our HSM provider — see
[`lib/test-vectors/SOURCE.md`](lib/test-vectors/SOURCE.md) §Known gaps.

Primitive-layer KATs in the integration suite:

| Layer | Spec source | Vector |
| --- | --- | --- |
| SHA-256 | FIPS 180-4 §B.1 | `"abc"` |
| HMAC-SHA256 | RFC 4231 §4.2 | Test Case 1 |
| HKDF-SHA256 | RFC 5869 §A.1 | Test Case 1 |
| AES-128-GCM | NIST GCM spec App. B | Test Case 3 |
| Ed25519 verify | RFC 8032 §7.1 | Test 2 |
| ECDSA P-256 verify | RFC 6979 §A.2.5 | message `"sample"` |
| HPKE (DhKem25519/SHA256/AES128GCM) full chain | RFC 9180 §A.1.1 | DeriveKeyPair determinism + decap of published ciphertext |

X-Wing itself is verified separately, through the Rust engine directly
(not via the integration suite above) in
[`lib/tests/xwing_rust_engine.rs`](lib/tests/xwing_rust_engine.rs): seed
expansion, encapsulate, and decapsulate against
`draft-connolly-cfrg-xwing-kem-10`'s own published test vectors, plus a
ChaCha20-Poly1305 known-answer test and an ML-KEM-768 round-trip check
(6 tests total).

### Tier B — in-process cross-validation examples

Two runnable examples prove the provider drives a real `openmls::MlsGroup`
end-to-end:

```bash
cargo run --release --example two_member_group
# ==> SUCCESS — both groups at epoch 1, 2 members, identical group_id
# ==> credential signing keys never left the HSM (25-byte HsmKeyHandle blobs)

cargo run --release --example two_member_group_rustcrypto
# ==> RUSTCRYPTO REFERENCE OK — epoch 1, 2 members
```

The cross-validation test in `lib/tests/openmls_contract.rs` runs both
provider flavours through the same 8-step MLS lifecycle and asserts semantic
equivalence (epoch number, member count, member identities, message
plaintexts) at each step:

```bash
cargo test --release --test openmls_contract -- --test-threads=1
```

### Tier C — gRPC interop harness

The [`interop/`](interop/) crate is a `tonic`-based gRPC server speaking the
IETF `mls_client.MLSClient` contract from
[`mlswg/mls-implementations`](https://github.com/mlswg/mls-implementations).
21 RPCs are implemented (full parity with `openmls/interop_client`); 13 RPCs
are stubbed matching openmls's own `todo!()`/`Status::unimplemented`.

```bash
# Run the full gRPC smoke suite (spins up in-process server + tonic client):
cargo test --release --test grpc_smoke -- --test-threads=1
# 6/6 passing: Name, SupportedCiphersuites, CreateKeyPackage, CreateGroup×2, Free,
# plus welcome_join / commit / external_join / external_psk / protect+unprotect e2e

# Run the two-process e2e test (two binary instances, shared gRPC handshake):
cargo test --release --test two_process_e2e -- --test-threads=1
```

Docker infrastructure for running all four implementations side-by-side lives
in [`interop/docker/`](interop/docker/). See the `docker-compose.yml` header
for the pairwise gate matrix and run commands.

**Cross-vendor interop (no Docker)**: [`interop/tests/cross_vendor_mls_rs.rs`](interop/tests/cross_vendor_mls_rs.rs)
drives `pqctoday-mls-grpc` against a real build of
[`awslabs/mls-rs`](https://github.com/awslabs/mls-rs)'s own gRPC harness
over the same IETF protobuf contract. The handshake (`Name` +
`SupportedCiphersuites` + ciphersuite negotiation) passes end-to-end;
`welcome_join` in either direction is currently blocked by two
spec-interpretation differences between openmls and mls-rs (KeyPackage
leaf-node lifetime range; default-extension-type advertisement) — neither
is a bug in this provider, and both are documented inline as `#[ignore]`d
tests with the finding. Skipped automatically unless `$MLS_RS_HARNESS`
points at a built `harness_client` binary (see the file's module docs for
the build steps); the rest of the workspace stays green without it.

### Running everything

```bash
cargo test --workspace --exclude pqctoday-mls-wasm-smoke -- --test-threads=1
cargo run --release --example two_member_group
cargo run --release --example two_member_group_rustcrypto
cargo run --release --bin pqctoday-mls-grpc -- --port 50053
```

### CI status

Wired as `.github/workflows/openmls-provider.yml` — triggers on push/PR to
`main` when any file under `openmls-provider/` changes. Steps: `cargo check
--workspace` → `cargo test --workspace --exclude pqctoday-mls-wasm-smoke --
--test-threads=1` → `cargo build --release -p pqctoday-mls-grpc` → `cargo
clippy -D warnings`.

The `--test-threads=1` requirement is intrinsic to softhsmv3 (its
`C_Initialize` is not safe under concurrent process-level invocation, and
each test mints a fresh per-test token in a tmpdir).
