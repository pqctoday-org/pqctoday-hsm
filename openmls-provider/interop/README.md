# `pqctoday-mls-interop` — IETF gRPC interop client

A `tonic`-based gRPC server implementing the
[`mlswg/mls-implementations`](https://github.com/mlswg/mls-implementations)
`mls_client.MLSClient` contract, backed by
[`openmls_pqctoday_crypto`](../lib). Lets the IETF test-runner pair our
HSM-resident provider against other registered MLS implementations
(`openmls`, `cisco/mlspp`, `awslabs/mls-rs`, …).

## What works today (v0.2.0)

**21 of 34 RPCs implemented — full functional parity with
`openmls/interop_client`.** The 13 "stubbed" RPCs in our impl
(`ReInit*`, `Branch`, `ExternalSigner`, `NewMemberAddProposal`,
`GroupContextExtensionsProposal`, `re_init_proposal`) are also `todo!()`
or `Status::unimplemented` in the openmls reference itself — they're
documented in the IETF protobuf but no implementation in the openmls
workspace handles them. We match the reference RPC-for-RPC.

Concretely we cover: `welcome_join.json`, application message exchange,
`external_join.json`, the external PSK ratchet, **and** `Commit.by_value`
(inline Add/Remove/PSK proposals) — every IETF interop scenario the
openmls reference can run.

| RPC | Status | Notes |
|---|---|---|
| `Name`, `SupportedCiphersuites` | ✅ | Stateless identity |
| `CreateGroup`, `CreateKeyPackage`, `Free` | ✅ | State mgmt + HSM-backed credential mint |
| `JoinGroup` | ✅ | Welcome → `StagedWelcome` → `MlsGroup` |
| `AddProposal`, `UpdateProposal`, `RemoveProposal` | ✅ | All three membership proposal kinds |
| `Commit` | ✅ | `by_reference` path; `by_value` returns `UNIMPLEMENTED` |
| `HandleCommit`, `HandlePendingCommit` | ✅ | Peer-commit merge + own-pending merge |
| `Protect`, `Unprotect` | ✅ | Application-message AEAD with AAD |
| `StateAuth` | ✅ | Returns `epoch_authenticator` |
| **`Export`** | ✅ | RFC 9420 §8.5 exporter via `export_secret` |
| **`GroupInfo`** | ✅ | Serialised `GroupInfo` + optional ratchet tree |
| **`ExternalJoin`** | ✅ | `MlsGroup::external_commit_builder` → joins via GroupInfo, no Welcome |
| ReInit / Branch / ExternalSigner / NewMemberAddProposal / GroupContextExtensions | ⏸️ stubbed (13 RPCs) | Same RPCs `openmls/interop_client` also stubs out as `todo!()` / `Status::unimplemented` — full functional parity with the reference |
| Cross-process interop on `localhost` (two of our binaries on different ports) | ⏸️ | Wired by [`tests/two_process_e2e.rs`](tests/two_process_e2e.rs) — see "Cross-process interop" below |
| Cross-vendor interop vs `openmls` / `mlspp` / `mls-rs` | ⏸️ | All native binaries; instructions below — no Docker |

## Validation

Two integration tests in [`tests/grpc_smoke.rs`](tests/grpc_smoke.rs):

- **`ietf_grpc_contract_smoke`** — server lifecycle + RPC-level assertions
  on Name / SupportedCiphersuites / CreateKeyPackage (incl. `signature_priv`
  starts with `"PQTH"`) / CreateGroup × 2 distinct `state_id`s / Export
  still UNIMPLEMENTED / Free.
- **`welcome_join_e2e_over_grpc`** — full welcome_join scenario over the
  gRPC wire. Bob mints a KeyPackage; Alice creates a group, adds Bob via
  proposal+commit, merges her pending commit; Bob joins from Alice's
  Welcome. Asserts both sides have the **same `epoch_authenticator`** —
  proves the entire crypto/key-schedule/wire-format chain works
  end-to-end against our HSM-backed provider.

## Run the server

```bash
cargo build --release --bin pqctoday-mls-grpc
./target/release/pqctoday-mls-grpc --port 50053
# → "pqctoday-mls gRPC interop client listening on 0.0.0.0:50053"
```

## Verify wire-level contract

```bash
cargo test --release --test grpc_smoke
# test ietf_grpc_contract_smoke ... ok
```

The smoke test asserts:

1. `Name` returns the documented implementation identifier
2. `SupportedCiphersuites` returns the documented ciphersuite list
3. Stubbed RPCs return `tonic::Code::Unimplemented` with the RPC name in
   the error message (i.e., the test-runner gets a clean failure, not a
   crash, on unimplemented operations)

## Cross-process interop (native — no Docker)

The IETF MLS WG happens to ship its multi-vendor test harness as Docker
images because their fleet is polyglot (C++ `mlspp`, Rust `mls-rs`, Go
`go-mls`, …). Our stack is pure Rust + a native softhsm dylib — we
don't need containers. Cross-process interop runs natively:

```bash
# Terminal 1 — our gRPC server, instance A
./target/release/pqctoday-mls-grpc --port 50053

# Terminal 2 — our gRPC server, instance B (different port, different softhsm token)
./target/release/pqctoday-mls-grpc --port 50054

# Terminal 3 — drive a welcome_join scenario across them. The Rust
# integration test in tests/two_process_e2e.rs is the runnable example.
cargo test --release --test two_process_e2e -- --test-threads=1 --nocapture
```

For cross-vendor (mls-rs / mlspp / openmls reference) the same pattern
applies — just one more native binary per vendor in a separate terminal:

```bash
# AWS Wickr lineage (pure Rust, builds with cargo)
git clone https://github.com/awslabs/mls-rs.git
cd mls-rs/mls-rs/test_harness_integration && cargo run --release -- --port 50055

# Cisco Webex lineage (C++, builds with cmake)
git clone https://github.com/cisco/mlspp.git
cd mlspp && cmake -B build && cmake --build build
./build/cmd/interop/interop --port 50056

# IETF test-runner (Go)
go run github.com/mlswg/mls-implementations/interop/test-runner \
  -client localhost:50053 \
  -client localhost:50055 \
  -config welcome_join.json
```

None of this needs Docker. Three to five native processes on
`localhost`, gRPC over the loopback interface.

Once the RPCs are ported, registering `pqctoday-mls` upstream in
[`mlswg/mls-implementations/implementation_list.md`](https://github.com/mlswg/mls-implementations/blob/main/implementation_list.md)
is a one-line PR.
