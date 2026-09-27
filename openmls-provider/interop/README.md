# `pqctoday-mls-interop` — IETF gRPC interop client

A `tonic`-based gRPC server implementing the
[`mlswg/mls-implementations`](https://github.com/mlswg/mls-implementations)
`mls_client.MLSClient` contract, backed by
[`openmls_pqctoday_crypto`](../lib). Lets the IETF test-runner pair our
HSM-resident provider against other registered MLS implementations
(`openmls`, `cisco/mlspp`, `awslabs/mls-rs`, …).

## What works today

**22 of 34 RPCs implemented.** The 12 remaining RPCs in our impl (the
`ReInit*`, `Branch`, `ExternalSigner`, and `NewMemberAddProposal` families)
are also `todo!()` or `Status::unimplemented` in the openmls reference
itself — they're documented in the IETF protobuf but no implementation in
the openmls workspace handles them.

Concretely we cover: `welcome_join.json`, application message exchange,
`external_join.json`, the external/resumption PSK ratchet, group-context
extension proposals, **and** `Commit.by_reference` (proposal-then-commit) —
every IETF interop scenario the openmls reference can run.
`Commit.by_value` (inline proposals folded directly into the commit) is
still `UNIMPLEMENTED` on our side.

| RPC | Status | Notes |
|---|---|---|
| `Name`, `SupportedCiphersuites` | ✅ | Stateless identity |
| `CreateGroup`, `CreateKeyPackage`, `Free` | ✅ | State mgmt + HSM-backed credential mint |
| `JoinGroup` | ✅ | Welcome → `StagedWelcome` → `MlsGroup` |
| `AddProposal`, `UpdateProposal`, `RemoveProposal` | ✅ | All three membership proposal kinds |
| `StorePSK`, `ExternalPSKProposal`, `ResumptionPSKProposal` | ✅ | PSK injection + both PSK proposal types |
| `GroupContextExtensionsProposal` | ✅ | Decodes proto extensions to their typed MLS form and auto-patches `RequiredCapabilities` so openmls's own commit validator accepts the result — see "Known asymmetry" below |
| `Commit` | ✅ | `by_reference` path; `by_value` returns `UNIMPLEMENTED` |
| `HandleCommit`, `HandlePendingCommit` | ✅ | Peer-commit merge + own-pending merge |
| `Protect`, `Unprotect` | ✅ | Application-message AEAD with AAD |
| `StateAuth` | ✅ | Returns `epoch_authenticator` |
| **`Export`** | ✅ | RFC 9420 §8.5 exporter via `export_secret` |
| **`GroupInfo`** | ✅ | Serialised `GroupInfo` + optional ratchet tree |
| **`ExternalJoin`** | ✅ | `MlsGroup::external_commit_builder` → joins via GroupInfo, no Welcome |
| ReInit family (6 RPCs), `Branch`/`HandleBranch`, `NewMemberAddProposal`, `ExternalSigner` family (3 RPCs) | ⏸️ stubbed (12 RPCs) | Same RPCs `openmls/interop_client` also stubs out as `todo!()` / `Status::unimplemented` |
| Cross-process interop on `localhost` (two of our binaries on different ports) | ⏸️ | Wired by [`tests/two_process_e2e.rs`](tests/two_process_e2e.rs) — see "Cross-process interop" below |
| Cross-vendor interop vs `openmls` / `mlspp` / `mls-rs` | ⏸️ | All native binaries; instructions below — no Docker |

### Known asymmetry: `GroupContextExtensionsProposal`

Our `propose_group_context_extensions_proposal` RPC works and produces a
spec-correct proposal. But the nightly gating job (below) shows most
`commit` scenarios that exercise it **fail on the openmls reference side**,
not ours: openmls 0.8.1's own commit-time validator has no implementation
for this extension type yet (`Group context extension is not implemented
yet`). So "22 of 34 implemented" is no longer full RPC-for-RPC parity with
`openmls/interop_client` — for this one RPC we're ahead of the reference,
which the gating numbers below make visible as reference-side failures
rather than ours.

## Nightly cross-implementation gating

`.github/workflows/openmls-interop.yml` runs nightly (04:30 UTC) plus on
`workflow_dispatch`: it builds Docker images for pqctoday and each peer
(`docker/Dockerfile.{pqctoday,openmls,mls-rs,test-runner}`), runs
[`run-gating-tests.sh`](run-gating-tests.sh) for `pqctoday vs {openmls,
mls-rs} × {welcome_join, commit, external_join}` across ciphersuites 1-3,
and uploads each JSON report (also kept in-repo under [`reports/`](reports/)
for audit trail, 90-day artifact retention). It's deliberately not run on
every PR (~30 min cold cache) — ordinary Rust-level regression coverage
stays in `openmls-provider.yml`.

```bash
./run-gating-tests.sh              # all known healthy peers
./run-gating-tests.sh openmls      # only pqctoday-vs-openmls
```

Only `welcome_join`, and only against `openmls` (not `mls-rs`), can fail the
build — set via the script's `GATING_SCENARIOS`/`GATING_PEERS` env vars.
`commit` and `external_join`, and the `mls-rs` peer, run and their reports
are kept, but don't gate: `mls-rs` disagrees with openmls (which backs our
client) on key-package lifetime limits, a policy RFC 9420 deliberately
leaves to each application, not a real defect on either side; most `commit`
failures against `openmls` are on the reference side (see "Known asymmetry"
above and the script's own header comment for the measured breakdown by
scenario). Ciphersuites 4-7 (the ones needing Ed448, P-384, or P-521
signatures) aren't exercised by this harness at all — this crate has no
Ed448/P-384/P-521 `signature_key_gen` support yet.

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
