# Remoting v3.2 mirror — residual-gaps remediation plan (2026-08-26, post-G5)

Execution-ready plan for the gaps left open after the gap-remediation
program (G1–G5, `docs/remoting-pkcs11-v32-gap-remediation-plan-
2026-08-26.md`) closed. Grounded 2026-08-26 against the ledger at
`43f4ed3`, the live test code, and the crate manifests — every claim
below was re-checked at write time, not carried forward from memory.

State at grounding: 99/104 `pkcs11f.h` functions + 2 vendor RPCs live;
ledger 64/64 categories, ratchet green; whole workspace 82 passed / 0
failed; 16 commits on `feat/remoting-v32-mirror`, unpushed; `main` has
not moved since the branch diverged (`git log HEAD..main` = 0).

Six residual items. Two are actionable here (H1, H2); three are
explicit no-action decisions that deserve to be written down so they
stop resurfacing as "gaps" in future audits (H3, H4); one is the
unchanged, environment-blocked pre-merge homework (H5). Push (H6)
stays user-gated.

## 1. H1 — Fork ledger row is stale against its own coverage (fix)

**The gap**: `coverage_ledger.json`'s `Fork` row still says the
cross-session RNG-divergence analogue "was not built as its own
dedicated case" and cites only the single-session
`core::random_and_seed_codes_are_the_engines_own`. That statement was
true when written (RW-T) and is false since G3:
`core::mechanism_sweep_kcv_profile_multipart_and_fork` (verbs_v32.rs,
"Fork analogue" block) opens TWO independent sessions and asserts their
`generate_random` draws differ — exactly the case the row says is
missing. It slipped because G3's ledger pass only targeted rows with
EMPTY `case_ids`, and Fork already had one; the row's prose was never
revisited. Real coverage exists; the ledger's self-description lies
about it.

**The fix** (XS, ledger + regenerated report only, no code):
- Append `core::mechanism_sweep_kcv_profile_multipart_and_fork` to the
  row's `case_ids` (keep the existing single-session case — it proves a
  related but distinct property).
- Rewrite the justification: disposition stays `N/A-local` (fork(2)
  itself cannot cross a network boundary — that part is still true),
  but the remote analogue is now CASED, dated G3 2026-08-26.
- Re-run `scripts/check_coverage_ledger.py` (check (b) will verify the
  new case_id resolves to a real fn) and regenerate
  `REMOTE_P11_V32_COVERAGE.md`.

Exit criterion: the ledger contains no sentence claiming a case is
missing that the test suite actually contains.

## 2. H2 — gRPC live binary: full RPC round-trip over real TLS (build)

**The gap, precisely scoped**: G5 proved the REST binary end-to-end
(real HTTPS session→keygen→sign→verify via `curl -k`) but for the gRPC
binary only proved the TLS handshake + h2 ALPN via `openssl s_client` —
no protobuf unary call ever crossed the real binary's real TLS
listener. `grpcurl`/`protoc` are not installed here, and the acceptance
harness's `spawn_grpc_v32` is plaintext-by-design, so neither can close
this.

**The fix — a pinned-cert smoke client, no new dependencies, no
verification-skipping** (S):

1. **Pre-generate a cert/key pair** (`openssl req -x509 -newkey` with
   `subjectAltName=DNS:localhost` — openssl is available at
   `/opt/homebrew/bin/openssl`) into the scratchpad. Start the real
   binary with `--tls-cert`/`--tls-key` pointing at it. **Bonus this
   buys for free**: G5 only ever exercised the no-args self-signed
   generation path; this exercises `load_or_generate_identity`'s
   file-loading arm and the `--tls-cert`+`--tls-key`
   must-come-together CLI validation — both currently untested on the
   live binary.
2. **Write `remoting/grpc/examples/smoke_client.rs`**: tonic is already
   in the grpc crate's `[dependencies]` AND `[dev-dependencies]` with
   `features = ["transport", "tls-aws-lc"]` (verified in
   `grpc/Cargo.toml`) — examples compile against dev-deps, so zero
   manifest changes. The client builds a `ClientTlsConfig` with the
   SAME PEM pinned as its CA root (`Certificate::from_pem`) — real
   certificate verification against a known root, not a
   `danger_accept_invalid` bypass — connects to
   `https://localhost:<port>`, and drives the same sequence REST got in
   G5: `C_OpenSession` → `C_GenerateKeyPair` (ML-DSA-65) → `C_SignInit`
   /`C_Sign` → `C_VerifyInit`/`C_Verify` → `C_CloseSession`, printing
   each `ck_rv` and exiting nonzero on any failure.
3. **Run it once** against the live binary
   (`cargo run -p pqc-grpc-pkcs11 --example smoke_client -- <port>
   <cert.pem>`), record the output in the execution log, shut the
   server down.

**Why an example, not a test**: this is G5's "run the app, not the test
suite" check — a one-off manual verification tool. `cargo test` never
builds/runs examples, so gate wall-time stays flat (plan §9's no-new-
gate-steps rule) and there is no port/cert fixture to keep alive in CI.
The example file itself is the durable artifact: next time anyone needs
to smoke the binary, the tool exists instead of being improvised.

**Ledger impact**: none (no new RPCs, no new categories). Execution-log
entry in the gap-remediation plan doc records the result and retires
the "honest scope limit" caveat G5 wrote down.

Exit criterion: a real `Pkcs11V32` unary call sequence completes with
`ck_rv=0` end-to-end over the real binary's real TLS listener, with the
server cert actually verified by the client.

## 3. H3 — the 4 empty ledger rows: explicit NO-ACTION (decide, document)

`FIPS`, `G4Retcodes`, `Init`, `Invariant` — all under the plan's own
"≤5 empty rows" exit bar, all design-level. The decision this section
records: **leave all four empty, permanently, and do not backfill them
with proxy case_ids.** Per row:

- **Init**: `C_Initialize`/`C_Finalize` are server-process bootstrap
  with no per-request network analogue. Also covered by the
  `pkcs11f_h_function_count.not_mirrored` block. Nothing to case.
- **FIPS**: the tempting fill is
  `v22_verify_signature_multipart_and_session_validation_flags_parity`
  (which proves the engine honestly reports an empty validation-flag
  set). Rejected: the compliance report's FIPS category is about
  self-test/POST surface, and v22 proves an adjacent honesty property,
  not that. Citing it would be measuring a proxy instead of the
  question — the exact failure mode the row-level-ratchet and
  measure-the-question lessons exist to prevent. Empty-with-reason is
  the honest state.
- **G4Retcodes / Invariant**: design-level restatements of the
  guarantee `ErrCodes`/`Negative` already carry (every negative case
  captures its CKR from an in-process control). Copying those rows'
  case_ids here would add bytes, not information, and would mean three
  rows silently drift apart on the next edit. The cross-reference in
  the justification IS the coverage claim.

Only change (XS, optional, fold into H1's ledger commit): one sentence
in each of the four justifications saying "deliberately empty —
decision recorded in the residual-gaps plan §3", so the next audit
finds the decision instead of re-litigating it.

## 4. H4 — V21b stays `#[ignore]`'d: NO-ACTION (reaffirm)

XMSS keygen is 326s at this engine's smallest single-tree parameter set
(height 10 — v3.2 §6.66.6 defines nothing smaller). That cost is
Merkle-tree construction, i.e. physics, not a fixable inefficiency. The
mitigation already shipped in G4: SLH-DSA runs routinely (V21a, ~11s
after the 128S→128F correction), XMSS/HSS runs on demand
(`cargo test -- --ignored v21b_xmss_hss_sign_verify_parity`), and the
cost is documented in the test's doc comment, `local-gate.sh`'s step
comment, and the ledger. Three synchronized warnings is enough;
anything further is churn.

## 5. H5 — environment-blocked items: pre-merge checklist (unchanged)

Neither is closable from this machine; both stay exactly where G5's §6
put them, restated here so this plan is self-contained:

1. **JavaJCE-remote stub regeneration**: run
   `bash scripts/local-gate.sh --javajce-remote` on a host with Maven +
   the sandbox up. This is a G6-checklist item, executed by whoever
   pushes, recorded in the PR body — never claimed as "ran" here.
2. **`spawn_blocking` vs REST benchmark**: fold into the existing
   transport-arms bench program (hsm PR #178 / sandbox v0.11.3) as one
   scenario — `C_Sign`(ML-DSA-87, large message) at high concurrency
   through the v32 gRPC path vs. the v32 REST path, p99 under a
   saturated worker pool. Until that program picks it up, the honest
   status line stays "unbenchmarked" in the PR body. Do NOT build a
   bespoke harness.

## 6. H6 — push/review: user-gated (unchanged)

The G6 checklist from the gap-remediation plan applies verbatim (full
`local-gate.sh` in the worktree with the `AG_CONTAINER_ROOT` override,
JavaJCE-remote on a Maven host, rebase-check against `main` — currently
a no-op, `main` unmoved — PR base `origin/main`, body listing H5's two
open items). Not executed without an explicit go-ahead.

## 7. Sequencing & effort

| Slice | Contents | Effort | Commit |
|---|---|---|---|
| H1+H3 | Fork row fix + four no-action markers, regenerated report | XS | 1 (ledger/docs) |
| H2 | Pinned-cert gRPC smoke client + live run, execution-log entry | S | 1 |
| H4 | Nothing — reaffirmed above | — | — |
| H5 | Nothing here — pre-merge checklist | — | — |
| H6 | Push/review | — | user-gated |

H1/H3 and H2 are independent; either order works. Both slices re-run
the full remoting suite + ratchet before committing, per the standing
per-commit discipline.

## 8. What this plan deliberately does NOT do

- No proxy case_ids on design-level rows (H3's whole point).
- No new gate steps, no `#[ignore]` removals, no bench harness.
- No engine-crate or wire-format changes of any kind — H2's client is
  a consumer of the existing proto, nothing more.
- No push, no CI, no deploy — H6 stays behind the user's explicit gate.
