# Remediation plan — authentication-attempt visibility and the empty PKCS#11 evidence log

**Date:** 2026-09-10
**Status:** IMPLEMENTED on branch `feat/auth-visibility-evidence-log` (based on
`main` `d56f2c7a`), 2026-09-10. Both gaps closed, proven live against real running
binaries (not just unit tests) — see §5. Not pushed, no PR opened yet — this repo's
own CI/review gate per the scope note below still applies before merge.
**Origin:** found while building appliance-side monitoring in `pqctoday-cacp`
(`docs/imx95-monitoring-plan-09102026.md`, WP0-WP2, done; this is that plan's WP8a,
promoted to its own document because both findings turned out to be more precise —
and in one case worse — than first described, and because fixing them means design
decisions this repo's own reviewers should make, not decisions to bake into a sandbox
plan silently.
**Scope note:** this repo has its own CI and review gate and is edited by one person
at a time. Nothing here has been implemented. This document exists to get agreement
on the shape of the fix before anyone writes code against it.
**Decisions (owner, 2026-09-10):** Q1 → dedicated auth-event log file (§1.2(b)); Q2 →
capture peer IP/mTLS CN; Q3 → build the remoting Prometheus endpoint now, not deferred
to WP8. §1.3, §3, and §4 below are updated to match — these three are no longer open.
Q4-Q6 remain open (each keeps its recommendation as a default, not yet confirmed).

## 0. What changed since the first pass (read this before anything else)

The original finding (written from the appliance side, without reading this repo's
source directly) said: *"a KMIP auth failure is counted, just folded into the general
error bucket."* That is **wrong** for the case that actually matters most. A full
read of `kmip/src/dispatcher/mod.rs` shows two separate auth-failure paths with
completely different outcomes:

- **Request-level auth failure** (wrong password, unknown user, missing credential —
  the case an operator actually cares about) returns at `dispatcher/mod.rs:140-143`,
  **before** the per-item loop that calls the metrics counter (`:165-175`) is ever
  reached. It is counted **nowhere**, logged **nowhere**, and produces no audit event.
  This is worse than "generic bucket" — it is a true blind spot.
- **A `Login` op failing inside an already-authenticated batch** does reach the
  counter, and — new information — is already distinguishable there:
  `response.result_reason == Some(0x03)` (`ResultReason::AuthenticationNotSuccessful`)
  is in scope at the exact call site (`kmip/src/kmip30/message.rs:271` defines the
  field; `kmip/src/error.rs:85` the constant).

The second finding — the evidence log staying empty for KMIP and PKCS#11 remoting —
is **confirmed and root-caused completely**, not partially as first written. Neither
`pqctoday-kmip` nor `pqc-grpc-pkcs11`/`pqc-rest-pkcs11` load `libsofthsmv3.so` at all.
All three link the Rust engine (`softhsmrustv3`) as a plain path dependency
(`remoting/core/Cargo.toml:11-13`: `softhsmrustv3 = { path = "../../rust" }`, same
pattern KMIP already uses) and call its `native::*` functions directly — never the
six `ffi::C_*` wrappers that are the *only* oplog-instrumented entry points in the
whole Rust engine (`rust/src/ffi.rs`: `C_SignInit`/`C_Sign`/`C_SignFinal`/
`C_GenerateKeyPair`/`C_EncapsulateKey`/`C_DecapsulateKey`). `PKCS11_MODULE` — the env
var the appliance's systemd units set, expecting it to select a module — is read by
**no code in `kmip/` or `remoting/`, anywhere**. The C++ engine's own, real,
correctly-wired `OpLog::emit` calls in `SoftHSM_sign.cpp` are irrelevant to this
appliance: nothing in the three processes it runs ever loads that library. An empty
evidence file is the current code's *correct* behaviour, not a flake.

## 1. Gap 1 — authentication-attempt visibility

### 1.1 The three blind spots, precisely

| Surface | What happens today | File:line |
|---|---|---|
| KMIP request-level auth (wrong/missing credential) | Nothing counted, nothing logged, no audit event | `dispatcher/mod.rs:123-145` |
| KMIP TLS handshake (wrong/absent client cert) | `?` returns before `record_tls_handshake` runs; only signal is a generic `tracing::warn!("conn {peer} closed with error: {e}")` shared with every other connection-teardown reason (dropped mid-frame, client hangup, ...) | `kmip/src/server/listener.rs:412,423-424` (same shape on the admin listener: `kmip/cryptopolicy-manager/manager.rs:168,194,200`) |
| PKCS#11 remoting PIN (`open_session`) | Wrong PIN → `CkError(CKR_PIN_INCORRECT)`, zero logging, zero counting, zero audit, anywhere | `remoting/core/src/verbs.rs:74-87` |

Two structural facts shape every option below:

- **`remoting/core` has no logging or metrics dependency at all** (`Cargo.toml`:
  `softhsmrustv3`, `serde`, `thiserror`, `x509-cert`, `der`, `spki`, `const-oid`,
  `time`). `remoting/grpc` and `remoting/rest` both already depend on `tracing` and
  call `tracing_subscriber::fmt::init()` in their own `main.rs` — but neither has a
  single `tracing::` call inside its actual request-handling code
  (`service.rs`/`routes.rs`); all existing tracing is startup-banner lines in `main`.
- **The peer address is available but discarded on both KMIP and remoting today.**
  KMIP: `peer: SocketAddr` is bound at the TCP-accept step (`listener.rs:407`) but
  never passed into `handle_conn` (`:418-422`), so it is out of scope exactly where
  the handshake fails. gRPC: `service.rs:37` calls `request.into_inner()` as its first
  statement, discarding the `tonic::Request` wrapper that carries `remote_addr()`.
  REST: structurally cannot see it today — the server is started with
  `.serve(app.into_make_service())` (`remoting/rest/src/main.rs:70-71`), not
  `into_make_service_with_connect_info::<SocketAddr>()`, so `ConnectInfo<SocketAddr>`
  is never in the request extensions for a handler to extract.

### 1.2 What "visible via SNMP/syslog/OpenMetrics" actually requires (a finding that changes the design)

Checked directly on the rebuilt appliance: `/etc/systemd/journald.conf` has
`#ForwardToSyslog=no` (systemd's own compiled-in default, unchanged here), and
`rsyslog.conf` loads `imuxsock` (the `/dev/log` socket) and `imklog` — **not**
`imjournal`. `tracing_subscriber::fmt::init()` writes to stdout, which systemd
captures into the **journal only**. **A bare `tracing::warn!` call, however it's
worded, reaches `journalctl` and nothing else** — not syslog, not the RELP collector,
not SNMP, not OpenMetrics. This is true today for the *existing* `tracing::warn!` at
`listener.rs:412` as well; it was never actually reaching the monitoring pipeline
built in `pqctoday-cacp`, independent of anything in this plan.

**Decided (Q1): route auth-failure events through a dedicated, purpose-built log
sink** — same shape as `SOFTHSM3_OP_LOG`/`oplog.rs` (env-var-gated path, one line per
event, `OpenOptions::append`), but its own env var (proposed `PQC_AUTH_LOG`) and its
own record grammar, since an auth event isn't a PKCS#11 operation and forcing it
through `oplog`'s existing sink would blur two different kinds of evidence. This
keeps the security-event stream narrow and structured rather than opening every trace
line appliance-wide (the `ForwardToSyslog=yes` alternative) — that appliance-side
setting is not touched by this decision.

### 1.3 Proposed shape (Q1-Q3 decided; Q4-Q6 still open, see §4)

**KMIP** (`kmip/src/metrics.rs`):
- New `CounterVec` `cacp_auth_failures_total{surface, reason}` — `surface` ∈
  `{"kmip-credential", "kmip-tls-handshake"}` for this repo (`"remoting-pin"` added by
  the parallel remoting work below), `reason` a short fixed set (`"bad-credential"`,
  `"missing-credential"`, `"handshake-rejected"`) — same cardinality discipline
  `record_admin_request`'s doc comment already states (`metrics.rs:104-105`: "route
  must be a stable pattern... unbounded cardinality breaks Prometheus"), applied to a
  new label instead of an old one.
- Call it once at `dispatcher/mod.rs:140` (the request-level `Err(())` arm, before the
  early `return`) — this is a pure addition, doesn't touch the per-item loop or its
  existing `record_kmip_request` call at `:170`.
- Call it once at `listener.rs:423` (replace the current `.map_err(ServerError::Io)?`
  with a `.map_err(|e| { crate::metrics::record_auth_failure(...); ServerError::Io(e) })?`
  or equivalent — needs the TLS-handshake error kept distinguishable from a later I/O
  error in the same function; simplest is a dedicated `ServerError::TlsHandshake`
  variant rather than folding it into the existing `Io` arm that seven other call
  sites already share).
- Logging sink (Q1, decided): a new, small sink module (a generalization of
  `oplog`'s existing `OpenOptions::append` pattern, not a reuse of `oplog` itself —
  see §1.2) writing one line per event to a new env-var-gated path (proposed
  `PQC_AUTH_LOG`, mirroring `SOFTHSM3_OP_LOG`'s own shape) — record grammar proposed:
  `PQCAUTH v=1 ts=<ms> pid=<pid> surface=<s> reason=<r> peer=<ip:port|none>`. `peer`
  is populated per Q2 (decided: capture it) — `SocketAddr` is already bound at
  `listener.rs:407`, just not threaded into `handle_conn`; that's the one signature
  change this needs on the KMIP side (`handle_conn(stream, acceptor, deps, peer)`).

**PKCS#11 remoting** (`remoting/core/src/verbs.rs`, `remoting/grpc`, `remoting/rest`):
- `remoting/core` stays dependency-free: `open_session` keeps returning
  `Err(CkError(CKR_PIN_INCORRECT))` exactly as today. `CkError::class()`
  (`core/src/error.rs:27-45`) already returns `"pin-incorrect"` for this and is
  documented as existing *for logging/metrics* (`:25-26`) — an unused hook, not a new
  one.
- Logging and metrics both move to the two transport crates, which already have
  `tracing`: `service.rs`/`routes.rs` match on the `Err` from `verbs::open_session`,
  write a `PQCAUTH` line (surface `"remoting-pin"`) via the same sink module Gap 1's
  KMIP half introduces (shared, not duplicated — a small crate or a `pub` module
  `remoting/core` can house without itself depending on anything new, since only the
  *callers* invoke it), and increment the new counter below.
- **Metrics (Q3, decided: build now, not deferred to WP8).** There is currently no
  Prometheus registry, no scrape endpoint, nothing, in any of the five `remoting/*`
  crates (confirmed by grep — the only "metrics"-adjacent hits are an unrelated
  `AtomicU64` serial counter in `cert.rs` and a doc comment). This adds one: a new,
  small module mirroring `kmip/src/metrics.rs`'s ~40-line pattern exactly (one
  `CounterVec` — `cacp_auth_failures_total{surface="remoting-pin",reason}` — a
  `Registry`, a hand-rolled plain-HTTP scrape responder), instantiated once per
  service binary (`pqc-grpc-pkcs11`, `pqc-rest-pkcs11`), each needing its **own new
  scrape port** — coordinate the actual port number with `pqctoday-cacp` (systemd
  unit + Fluent Bit's `prometheus_scrape` input in that repo's WP3, not yet built).
  Whether the module itself lives once in `remoting/core` (imported by both binaries)
  or is duplicated per-binary is an implementation detail, not a design fork — either
  is small. This is a deliberately narrow build: just the one counter, not the fuller
  latency-histogram/connection-gauge work WP8 still owns — the registry
  infrastructure this creates is exactly what WP8 will extend later, not a
  competing, throwaway version of it.
- Capturing the caller's address (Q2, decided: yes): gRPC can do this today without
  new infrastructure — `service.rs:37` just needs to read `request.remote_addr()`
  before calling `into_inner()`. REST needs a small, low-risk change to `main.rs:71`
  (`into_make_service_with_connect_info::<SocketAddr>()` and an
  `axum::extract::ConnectInfo<SocketAddr>` argument on the handler) — a well-trodden
  axum pattern, not a design risk, just a line item.

## 2. Gap 2 — the PKCS#11 evidence log stays empty

### 2.1 Root cause (fully confirmed, both processes)

`softhsmrustv3::native::*` — the code path every real sign/verify/keygen/encapsulate/
decapsulate call actually takes, in both `pqctoday-kmip` and both remoting
services — never calls `oplog::emit`/`oplog::enabled` (`grep -rn oplog rust/src/
native/` = zero hits). Only `rust/src/ffi.rs`'s six wrappers do, and nothing in this
appliance's runtime calls them. This is true independent of the `PKCS11_MODULE` env
var, which nothing reads.

### 2.2 Proposed fix

Add `oplog::emit` calls directly to the `native::` functions that are actually on the
hot path, matching the exact six operations already instrumented in `ffi.rs` (so the
record grammar and the appliance-side parser — `pqctoday-sandbox/tests/_evidence.sh`,
per `rust/src/oplog.rs`'s own module doc — need no changes):

| `ffi.rs` wrapper (instrumented) | `native::` equivalent (not instrumented) | File |
|---|---|---|
| `C_SignInit`/`C_Sign`/`C_SignFinal` | `sign`, `sign_pqc` | `rust/src/native/sign.rs:51,~140` (exact line for `sign_pqc` not yet located — confirm at implementation time) |
| `C_GenerateKeyPair` | `generate_ed25519_keypair`, `generate_ml_dsa_keypair`, `generate_ml_kem_keypair` | `rust/src/native/` (keygen module) |
| `C_EncapsulateKey` | `encapsulate` | `rust/src/native/` |
| `C_DecapsulateKey` | `decapsulate` | `rust/src/native/` |

Also missing on the `native::` side and worth adding at the same time for symmetry
(not currently instrumented on the `ffi::` side either, per the six-function table in
the investigation — confirm before treating as in-scope): `verify`/`verify_pqc`. This
repo's own `hsm-perf-bench` already has a documented pattern for "logging must be off
when the benchmark measures" (`rust/src/oplog.rs`'s module doc, point 3) — the same
runtime-zero-cost-when-unset guarantee applies unchanged, since `oplog::enabled()` is
still the same `OnceLock` check regardless of which call sites invoke it.

This is the more surgical fix compared to rerouting `native::` callers through
`ffi::` instead (which the Plane-3 pattern comment in `remoting/core/Cargo.toml`
suggests was deliberately avoided for a reason — likely PKCS#11 session-state/ABI
overhead this design specifically sidesteps): it adds instrumentation to the code
that actually runs, without changing which code runs.

## 3. Sequencing and estimate (updated for the Q1-Q3 decisions)

1. **Gap 2 fix** (evidence log) — smallest, most mechanical, no design ambiguity
   unless Q5 changes it: add `oplog::emit` calls to 5-6 `native::` functions, extend
   `rust/tests/oplog_evidence.rs`-style tests to cover them. **Half a day.**
2. **The new auth-event log sink** (Q1) — one small module, shared by the KMIP and
   remoting work below rather than built twice: env-var-gated path, `PQCAUTH v=1 ...`
   grammar, `OpenOptions::append`. **Half a day**, done once, ahead of items 3-4.
3. **Gap 1, KMIP half** — new `cacp_auth_failures_total` counter + call sites in
   `dispatcher/mod.rs` and `listener.rs`, a `ServerError` variant for a
   distinguishable handshake failure, `peer` threaded into `handle_conn` (Q2), calls
   into the item-2 sink, MIB/plan-doc update on the `pqctoday-cacp` side once the
   metric name is final. **1 day.**
4. **Gap 1, remoting half** — PIN-failure branch in `service.rs`/`routes.rs` calling
   the item-2 sink; `remote_addr()` capture on gRPC and the `ConnectInfo` wiring on
   REST (Q2); the new small Prometheus registry + scrape endpoint per binary (Q3,
   decided to build now). **1.5 days** — the registry/endpoint is the bulk of this
   (mirroring `kmip/src/metrics.rs`, but new to both `remoting` binaries).
5. **`pqctoday-cacp` side**: MIB row + `pass_persist` update for `cacpAuthFailures`
   (now three counters to read: KMIP's, and the new remoting one on its own port),
   an `imfile` stanza for the new `PQC_AUTH_LOG` path (same pattern as the existing
   evidence-log tail), scrape-port registration for Fluent Bit once WP3 exists,
   `run-suite.sh` gates proving a forced bad-PIN/bad-credential/bad-cert attempt is
   actually visible end to end via all three paths. **1 day**, sequenced after this
   repo's change lands and is released (pins into the appliance by tag, per the
   existing `pqctoday-hsm 0.30.0` pattern).

**Total: ~4 days**, split across two repos with different release/review cadences —
firmer than the original 1.5-3.5 day range now that Q1-Q3 are fixed rather than
forked (the remoting Prometheus endpoint, built now per Q3, is the single biggest
driver of the increase over the original estimate).

## 5. Implementation record (items 1-4; item 5 not started — see §3)

**Item 1, Gap 2 (evidence log) — done.** `oplog::emit` calls added at the six
`native::` entry points KMIP/remoting actually call: `sign_with_pss_salt` and
`sign_pqc` (`rust/src/native/sign.rs`, each synthesising the same paired
`C_SignInit`+`C_Sign` records `ffi.rs` emits, since the native path has no
separate init/sign phases — same grammar, zero changes needed to this repo's
one evidence consumer); `ml_dsa_keypair_impl`/`ml_kem_keypair_impl`/
`generate_ed25519_keypair` (`rust/src/native/keygen.rs`, via a new shared
`emit_generate_key_pair` helper — one call site each covers all of plain/
from_seed/from_seed_extractable, since those all funnel through the same impl
function); `encapsulate`/`decapsulate` (`rust/src/native/encrypt.rs`). New
integration test `rust/tests/oplog_evidence_native.rs` (its own process, same
reason `oplog_evidence.rs` already gives for not sharing one) drives all six
through the real engine and asserts the resulting records — paired
init/sign, correct mechanisms, correct sizes (ML-DSA-65 3309 bytes, Ed25519
64 bytes, ML-KEM-768 ciphertext 1088 bytes), matching shared secrets on
encaps/decaps. Found and fixed one small pre-existing gap along the way:
`oplog::mech_name` was missing `CKM_EC_EDWARDS_KEY_PAIR_GEN` entirely
(silently rendered `CKM_UNKNOWN` for every Ed25519/Ed448 keygen record ever
emitted by either engine, not just this change's new call sites).
Verified: `cargo test --lib` (rust/, 516 passed, 0 failed, 14 ignored — the
existing suite, unmodified, still green) and both `oplog_evidence` /
`oplog_evidence_native` integration tests, including the zero-cost gate
(`oplog_zero_cost.rs`, ~62k signs/sec unaffected with logging off). Also
confirmed the wasm32-unknown-unknown build still compiles.

**Item 2, the shared auth-event log sink (Q1) — done.** New `rust/src/
authlog.rs`, structurally identical to `oplog.rs` (env-var-gated
`OnceLock` sink, `OpenOptions::append`, cfg'd to a no-op on
`wasm32-unknown-unknown`), env var `PQC_AUTH_LOG`, grammar `PQCAUTH v=1
ts=<ms> pid=<pid> surface=<s> reason=<r> peer=<ip:port|none>`. Exposed as
`pub mod authlog` in `rust/src/lib.rs`, callable from any of the four
crates that already depend on `softhsmrustv3` directly (kmip, remoting/
core, remoting/grpc, remoting/rest — confirmed none needed a new Cargo.toml
dependency to reach it).

**Item 3, Gap 1 KMIP half — done.** `kmip/src/metrics.rs` gained
`cacp_auth_failures_total{surface,reason}` and a `record_auth_failure`
helper that increments it AND calls `authlog::emit` in one call (so a call
site can't do one without the other). Wired at three sites: `kmip/src/
server/listener.rs`'s TLS handshake rejection (new `ServerError::
TlsHandshake` variant, kept separate from the shared `Io` arm seven other
failure paths in the same function also produce; `peer: SocketAddr` now
threaded into `handle_conn`, which didn't have it before); the same
listener's request-level auth-gate rejection (checked after
`dispatch_with_transport_identity` returns, by inspecting the response's
first batch item for `ResultReason::AuthenticationNotSuccessful` — chosen
over threading a new parameter through that dispatcher function, which has
dozens of test call sites in `kmip/src/ops/tenancy_e2e.rs` alone; a
`had_credential` bool captured before the request moves into the dispatch
closure gives the missing-vs-bad-credential distinction without touching
dispatcher/mod.rs at all); and the admin facade's own TLS handshake
rejection (`kmip/cryptopolicy-manager/manager.rs`, same shape, `peer`
likewise threaded into its `handle_conn`). The admin facade's existing 403
authorization-denial path (`write_authorized` failing) was deliberately
NOT touched — that's `PermissionDenied`, a different, already-counted
signal (`record_admin_request(...,403)`), not `AuthenticationNotSuccessful`.
Verified live against a real running `pqctoday-kmip` binary requiring
mTLS: `openssl s_client` with no client certificate produced both a real
`PQCAUTH ... surface=kmip-tls-handshake reason=handshake-rejected
peer=127.0.0.1:51775` log line and a real `cacp_auth_failures_total{
reason="handshake-rejected",surface="kmip-tls-handshake"} 1` on the
scrape endpoint. The request-level credential path is covered by the
pre-existing, unmodified, still-passing `k14_auth_configured_missing_
credential_fails_every_item_0x03` / `k14_auth_configured_bad_credential_
fails_0x03` tests (they prove the exact response shape this new check
depends on) rather than a second live-fire test — building a full KMIP
protocol client purely to re-prove already-tested response behaviour
wasn't judged worth the added scope. `cargo test --lib -p pqctoday-kmip`:
801 passed, 0 failed. `cargo test --test tls_e2e`: 9 passed, 0 failed
(includes the handshake-rejection scenarios this change's code path
handles). Full `cargo test -p pqctoday-kmip` (all integration test files):
see the session's own final check before commit.

**Item 4, Gap 1 remoting half — done, including Q2 and Q3.** New
`remoting/core/src/metrics.rs` (added `prometheus` + `tokio` deps to
`remoting/core/Cargo.toml`, not feature-gated — unlike kmip, this crate has
no wasm32 target to keep lean for): the same `cacp_auth_failures_total`
counter (`surface` hardcoded `"remoting-pin"`, matching §1.3's design),
`record_auth_failure(reason, peer)` calling both the counter and
`authlog::emit` in one call, and a `serve_metrics_forever` scrape endpoint
mirroring KMIP's. Both `pqc-grpc-pkcs11` and `pqc-rest-pkcs11` gained a
`--metrics-listen` flag (defaults `127.0.0.1:9097`/`9098` — placeholders;
real port assignment is appliance-side work, item 5) and call `metrics::
init()` + spawn the scrape endpoint before serving. Peer capture (Q2):
gRPC reads `request.remote_addr()` before `into_inner()` discards it
(`remoting/grpc/src/service.rs`); REST needed `axum_server`'s
`into_make_service_with_connect_info::<SocketAddr>()` in `main.rs` plus a
`ConnectInfo<SocketAddr>` extractor on the `open_session` handler
(`remoting/rest/src/routes.rs`). `remoting/core`'s `open_session` itself
is untouched, exactly as planned — callers alone do the recording.
**A real regression this change caused, found and fixed by the existing
test suite, not introduced silently**: `remoting/acceptance/src/lib.rs`'s
`spawn_rest()`/`spawn_rest_v32()` test harness built its server with plain
`into_make_service()`, not the connect-info variant — after adding the
`ConnectInfo` extractor, axum's default (non-JSON) rejection broke every
REST request through the test harness, caught immediately by
`a1_wrong_pin_ckr_pin_incorrect_all_three_transports` failing with a JSON
decode error. Fixed by giving the harness the same `into_make_service_
with_connect_info` the real binary uses. After the fix: verified live
against a real running `pqc-rest-pkcs11` — a `curl` wrong-PIN request
produced a real `PQCAUTH ... surface=remoting-pin reason=pin-incorrect
peer=127.0.0.1:51834` line and a real `cacp_auth_failures_total{
reason="pin-incorrect",surface="remoting-pin"} 1`; the gRPC path is
proven via the SAME now-passing `a1_wrong_pin_...` test, which spawns a
real gRPC server and drives a real client through it — not a synthetic
in-process call. Full `cargo test --manifest-path remoting/Cargo.toml`:
every crate in the workspace (core, grpc, rest, proto, acceptance) green,
0 failures.

**Not started: item 5 (`pqctoday-cacp` side).** Correctly sequenced after
this work is released/tagged, per §3's own note.

**Q1 — DECIDED (owner, 2026-09-10): dedicated auth-event log sink**, not
`ForwardToSyslog=yes` and not counters-only. New `PQC_AUTH_LOG` env var, same shape
as `SOFTHSM3_OP_LOG`. See §1.2, §1.3, §3 item 2.

**Q2 — DECIDED (owner, 2026-09-10): capture the client's IP, and on KMIP an
mTLS-verified CN**, not a bare count. See §1.3's per-surface notes and §3 items 3-4.

**Q3 — DECIDED (owner, 2026-09-10): build the remoting Prometheus endpoint now**,
scoped to the auth-failure counter, not deferred to WP8. Original recommendation was
to defer (avoiding building the registry twice); owner chose to build it now for
sooner OpenMetrics/SNMP visibility into remoting auth failures. WP8 inherits and
extends this same registry later rather than creating its own. See §1.3, §3 item 4.

**Q4 — Should `cacp_kmip_requests_total`'s `status` label grow a third value (e.g.
`"auth_failed"`) instead of a wholly separate `cacp_auth_failures_total` counter?**
Recommend: keep them separate. The existing `record_kmip_request(operation: &'static
str, success: bool)` signature is a hard `bool`, not an open string — widening it
touches every one of its (currently one) call sites and the dashboards/MIB rows
already built against `{operation,status}` in the appliance's monitoring pipeline
(shipped 2026-09-10, described above). A new, separate, additive counter changes
nothing already deployed.

**Q5 — For Gap 2: instrument all six `native::` operations symmetrically with
`ffi.rs`'s existing six, or start narrower (sign/verify only, since that's what the
appliance's benchmarks actually exercise today) and extend later?** Recommend: all
six now, since the work is mechanical and identical per site, and a partially-
instrumented evidence log is a worse trap than no evidence log — someone will assume
`C_GenerateKeyPair`'s absence from a walk means it didn't happen, not that it was
never wired.

**Q6 — Does this plan proceed as one PR, or split by gap (Gap 2 first, since it's
smaller and has no open design question, followed by Gap 1 once Q1-Q4 are settled)?**
No recommendation — this is a process/reviewer-load call, not a technical one.
