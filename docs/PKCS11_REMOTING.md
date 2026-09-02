# PKCS#11 Remoting — gRPC + REST services

Two remote-access services in front of the `softhsmrustv3` engine, built
2026-08-24 per `sandbox-bench-transport-arms-plan-08242026.md` Step 1:

- **`pqc-grpc-pkcs11`** (`remoting/grpc`) — protobuf over gRPC (tonic),
  schema at `remoting/proto/proto/pkcs11_remote.proto`, package
  `pqctoday.pkcs11remote.v1`. Default port **5710**.
- **`pqc-rest-pkcs11`** (`remoting/rest`) — JSON+base64 over HTTP/1.1
  keep-alive (axum). **h2 is deliberately disabled** — ALPN offers only
  `http/1.1`, even to an h2-capable client — so a benchmark comparing this
  arm against gRPC compares framing style, not two accidentally-different
  HTTP/2 stacks. Default port **5720**.

Both wrap the same `pqctoday-pkcs11-remote-core` verb layer
(`remoting/core`), which calls `softhsmrustv3::native::*` directly — the
same functions the KMIP server's ops layer drives.

## Verb surface

Seven verbs, phase-1 scope (decision 6 of the plan): `Health`,
`OpenSession`, `CloseSession`, `GenerateKeyPair`, `Sign`, `Verify`,
`Encapsulate`, `Decapsulate`. Representative algorithm cells — the same
set the KMIP arm uses — plus the full ML-DSA/ML-KEM parameter-set family
for completeness: `Ed25519`, `ML-DSA-44/65/87`, `ML-KEM-512/768/1024`
(`remoting/core/src/algorithm.rs`). Widening the cell set is a match-arm
addition there, not new code in either service.

## Session model

**Single-tenant, one engine login per process.** `bootstrap()` runs once
at process startup (`init` + `init_token` + set the benchmark user PIN +
log the token in). Per-client `OpenSession` does **not** call the engine's
combined `open_session` (which performs its own `C_Login`) — real PKCS#11
login state is per-**token**, not per-session, so a second `C_Login` on an
already-logged-in token fails with `CKR_USER_ALREADY_LOGGED_IN`
(confirmed the hard way: this is exactly what the first version of this
service's own test suite hit). Instead `OpenSession` opens a bare session
via `C_OpenSession` directly and checks the caller's PIN at the
**application layer** against the well-known benchmark credential — not a
security boundary, matching the existing bench-harness/KMIP in-process
control arm's own convention (`kmip.rs`'s `bootstrap_default_token(0,
"so-pin", "1234", "bench-control")`).

**Inherited gap, stated rather than hidden**: `native::*` does not enforce
the token-scoping isolation `ffi::C_*` does (`rust/src/native/mod.rs`), so
a caller with a numeric session/key handle can in principle operate across
what would be separate tenants on the C ABI. These services are
single-tenant benchmark backends by design (plan §1.3), so this is an
inherited property to know about, not a defect being introduced here.

## TLS

Both services share `pqctoday-tls` (`tls/`), extracted verbatim from
`pqctoday-kmip`'s `server::secp384r1mlkem1024` / `server::listener` TLS-profile
code on 2026-08-24 (WP2) so a non-KMIP service can enforce the identical
KMIP 3.0 Profiles v3.0 §3.3 "Quantum Safe Authentication Suite" posture
without depending on the kmip crate.

Env `PKCS11_REMOTE_TLS_PROFILE` (also `--tls-profile`): `permissive`
(rustls defaults) | `quantum-safe` (TLS 1.3 only, the two §3.3.2 suites,
the three §3.3.3 hybrid ML-KEM groups only, mTLS via `--tls-client-ca`
required) | `classical-baseline` (identical to quantum-safe except
classical kx groups — measurement-only, never a deployment posture).

**Wording rule** (carried over unchanged from the KMIP server): every
description of a service built on `quantum_safe_provider()` says
**measured against** the Quantum Safe Authentication Suite, never
**conformant to** it.

**gRPC TLS mechanics — spike-verified, 2026-08-24.** tonic's
`ServerTlsConfig` builds its rustls `ServerConfig` via
`ServerConfig::builder()`, which resolves the **process-default**
`CryptoProvider` — there is no hook to inject an explicit provider into
tonic's built-in TLS path. `pqc-grpc-pkcs11` installs its one configured
posture as the process default at startup; this is safe specifically
because one process runs exactly one posture for its whole lifetime (the
same twin-container assumption the KMIP server already relies on). Proven
live: a real gRPC health call negotiated both `X25519MLKEM768` and the
locally-composed `SecP384r1MLKEM1024` (0x11ed) through this exact code
path, and a classical-only client was refused with `HandshakeFailure`.

**Client trap, found running the harness against a live server**: a
client that owns its TLS config must connect via
`Endpoint::connect_with_connector` using an **`http://` URI**, not
`https://` — an `https://` URI makes tonic wrap a SECOND TLS layer around
the already-TLS stream and fail with an opaque "transport error".

**REST TLS mechanics**: `axum-server`'s
`RustlsConfig::from_config(Arc<rustls::ServerConfig>)` takes the full
config `pqctoday_tls::server_config_builder` produces, with
`alpn_protocols` forced to `["http/1.1"]` regardless of profile — the h2
gate applies under every TLS posture.

## Connection models

Every benchmark row states its connection model (decision 7):

| Value | Arm | What it means |
|---|---|---|
| `persistent-channel` | gRPC | One tonic `Channel` opened once, reused (cloned cheaply) across every worker — the idiomatic gRPC pattern. |
| `per-request-channel` | gRPC | A fresh channel opened inside the timed loop for every single operation — the KMIP-comparable number: same framing, unamortized connection cost. |
| `keep-alive` | REST | One `ureq`/`reqwest` client with a pooled HTTP/1.1 connection, reused for the whole run. |
| `unix-socket-rpc` | p11-kit (Step 2) | Not built in Step 1 — see the plan's WP4c/§2.2. |

The bench-harness client arms live in `rust/bench-harness/src/transport.rs`
(subcommand `bench-harness transport --protocol grpc|grpc-per-request|rest`),
following the KMIP arm's own measurement discipline: fixed-duration
points via `measure::run_point`, `--repeats` + median + min/max spread,
and `--compare-tls` interleaving (A,B,A,B… within one session) for the
quantum-safe-premium measurement.

## v3.2-derived acceptance coverage (WP5a)

**This is NOT a claim of v3.2 conformance for the remoting services.**
Full PKCS#11 v3.2 conformance is, and remains, a property of the
**engine**, evidenced by `rust/RUST_P11_V32_CONFORMANCE_REPORT.md`
(`rust/test_p11_conformance.js`, 492 assertions, 40 named sections as of
the 2026-08-23 regeneration — see that report for the live count, which
this table intentionally does not restate as a fixed number since the
suite is actively evolving). These services expose 7 of the engine's many
verbs, so most of those 40 sections have no remote endpoint to test at
all. The claim here is narrower and precise: **of the sections that
genuinely touch the 7 exposed verbs, every applicable one is covered**,
asserted on the exact numeric `CKR_*` value, through all three surfaces
(in-process control, real gRPC, real REST) — `remoting/acceptance/tests/three_way_parity.rs`.

| # | Report section | Applicable? | Why / acceptance case |
|---|---|---|---|
| 1 | R1.2 — initialization gate (§5.4/§5.6) | N/A | Services always bootstrap the engine at startup; no client-facing "not yet initialized" state exists. |
| 2 | Token init (fixture) | N/A | Fixture, not a client-facing op. |
| 3 | T7 — TokenInfo flags before C_InitPIN | N/A | TokenInfo has no remote endpoint. |
| 4 | R2.2 — session flags (§5.6) | N/A | `CKF_SERIAL_SESSION`/`CKF_RW_SESSION` are transport-internal constants, not exposed on the wire. |
| 5 | Login fixture — SO/User login (§4.4) | **Applicable** | `OpenSession` is the login-equivalent verb. **Case A1** — wrong PIN → `CKR_PIN_INCORRECT` (0xA0), all 3 transports. |
| 6 | R2.1 — session-handle validation (§5.12 priority) | **Applicable** | **Case A2** — an unopened session handle on `Sign` → `CKR_SESSION_HANDLE_INVALID` (0xB3, empirically observed 2026-08-24), all 3 transports. |
| 7 | R2.4 — key-handle vs permission codes (§5.12.4) | Partially covered | The permission-check codepath (`CKA_SIGN`/`CKA_VERIFY`/`CKA_ENCAPSULATE`/`CKA_DECAPSULATE`) is exercised implicitly by every positive case (A3) using the correct half of each keypair; a dedicated wrong-key-role negative case is a good WS follow-up, not built in this pass. |
| 8 | R3.6 — CKA_PARAMETER_SET required (§6.67.2) | N/A | `GenerateKeyPair`'s `Algorithm` enum bakes the parameter set in — a client cannot construct an incomplete raw template. |
| 9 | R1.4 — GCM IV validation | N/A | No AES-GCM verb exposed. |
| 10 | H-4 — single-shot two-call convention (§5.2) | N/A | Buffer-sizing FFI convention; every RPC/REST verb is one-shot by construction. |
| 11 | Mixing guard — OPERATION_ACTIVE | N/A | No multi-part operation state machine exposed. |
| 12 | R2.5 — operation-active on re-init/find FSM | N/A | Same reason as #11. |
| 13 | H-5 — stateful sign/digest two-call | N/A | Buffer convention, not applicable. |
| 14 | R1.3 — private-object visibility (§4.4) | N/A — documented gap | Token-scoping isolation is not enforced by `native::*` at all (see Session model above); these services are single-tenant, so cross-session visibility is a known, stated limitation rather than a silently-skipped test. |
| 15 | H-11 — CKR_ATTRIBUTE_SENSITIVE (§5.7.5) | N/A | No `GetAttributeValue` verb exposed. |
| 16 | R1.5 — authenticated wrap AAD binding | N/A | No wrap/unwrap verb. |
| 17 | ML-KEM — encap/decap usage + provenance (§5.18.8/9) | **Applicable** | **Case A4** — `Decapsulate` with a wrong-length ciphertext → `CKR_ARGUMENTS_BAD` (0x7), grounded directly in `rust/src/native/encrypt.rs::decapsulate`'s explicit length check. Positive round-trip covered by A3's KEM analog (see note below the table). |
| 18 | E1 — ML-DSA context string + hedge variant | N/A | `Sign`'s wire schema always uses the external-hedged, empty-context default; the internal/external-µ/deterministic modes aren't exposed — a future widening, not a gap in what's exposed today. |
| 19 | E9 — CKR_SIGNATURE_LEN_RANGE (§5.12.6) | Covered by A3's shape | A3 covers "wrong content, same length" (`valid:false`, not an error). A dedicated wrong-*length* signature case is a good follow-up. |
| 20 | D4 — spec-mandated stubs | N/A | `C_GetOperationState` etc. have no remote equivalent. |
| 21 | F1 — mechanism table reconciliation | N/A | No `C_GetMechanismList` equivalent. |
| 22 | R3.1 — C_CreateObject template validation | N/A | No `CreateObject`/`Register` verb — only `GenerateKeyPair`. |
| 23 | E3 — GCM ulTagBits | N/A | No AES-GCM verb. |
| 24 | E4 — AES-CTR ulCounterBits | N/A | No AES-CTR verb. |
| 25 | E8 — HMAC general-length | N/A | No HMAC verb. |
| 26 | E2 — RSA-PSS params validated | N/A | RSA is outside the 7-cell representative set. |
| 27 | R3.7/D2 — session-object lifecycle + SessionCancel | **Applicable** | **Case A5** — `CloseSession` then reuse the handle → `CKR_SESSION_HANDLE_INVALID` (0xB3, empirically observed 2026-08-24, same code as A2), all 3 transports. |
| 28 | Round-2 — keygen template + RNG codes | N/A | No raw template/RNG-override verb. |
| 29 | Round-2 — wrap/unwrap role-specific handle codes | N/A | No wrap/unwrap verb. |
| 30 | Round-2 — operate-stage session-handle gate | Covered by A2 | Same codepath as #6. |
| 31 | Round-2 — T6 object management (Set/GetAttr, copy) | N/A | No attribute/object-management verb. |
| 32 | Round-2 — dynamic TokenInfo | N/A | No TokenInfo verb. |
| 33 | Round-2 — SignUpdate/Final ≡ one-shot | N/A | Multi-part not exposed. |
| 34 | Round-2 — mechanism table + FIPS ranges | N/A | No mechanism-table verb. |
| 35 | Round-2 — T5 message API ≡ one-shot GCM | N/A | No AES-GCM verb. |
| 36 | Round-2 — SP800-108 KBKDF PRF | N/A | No KDF verb. |
| 37 | Round-2 — SP800-108 CK_PRF_DATA_TYPE | N/A | No KDF verb. |
| 38 | WP4a — CKO_TRUST object lifecycle | N/A | No certificate/trust-object verb. |
| 39 | WP-A — CKA_ALLOWED_MECHANISMS enforcement (§4.8) | N/A | The enforcement exists in the engine, but the wire schema gives no way to construct a mechanism-restricted key, so it isn't independently testable through this surface. |
| 40 | WP-B — CKO_CERTIFICATE object lifecycle | N/A | No certificate verb. |

**A3** (ML-DSA-65 sign/verify positive round trip + tampered-signature
rejection) is the suite's positive-path backbone; its KEM analog
(GenerateKeyPair → Encapsulate → Decapsulate, shared-secret equality) was
proven live during Step 1's manual smoke testing (both gRPC and REST, both
`permissive` and real `quantum-safe` mTLS postures) and is a natural
addition to the automated suite in a follow-up pass — noted here rather
than silently counted as covered.

**Summary**: 5 applicable sections have a dedicated automated case
(5, 6, 17, 27, plus 30 sharing 6's case); 2 more are covered by an
existing case's shape without a dedicated one (19, and KEM's positive
path under 17); 1 is a documented, deliberate non-goal (14); the
remaining 32 are N/A because this service's 7-verb surface has no
corresponding endpoint. Nothing here is silently skipped — every N/A row
states why.

## The `Pkcs11V32` C_* mirror (2026-08-26 — a separate, additive service)

Everything above this section describes the **original 7-verb service**
(`Pkcs11Remote` in the proto — `Health`/`OpenSession`/`CloseSession`/
`GenerateKeyPair`/`Sign`/`Verify`/`Encapsulate`/`Decapsulate`, plus
`GetSelfSignedCertificate` added 2026-08-25), which stays **frozen
byte-for-byte** — the bench harness and JavaJCE-remote depend on it
unchanged. The "v3.2-derived acceptance coverage" table above is about
that service specifically and remains accurate for it; do not confuse it
with the coverage described here.

`docs/remoting-pkcs11-v32-full-coverage-plan-2026-08-26.md` and its
successor `docs/remoting-pkcs11-v32-remaining-gaps-plan-2026-08-26.md`
built a second, **additive** gRPC+REST service (`Pkcs11V32`, same proto
file, same two binaries) that mirrors the PKCS#11 v3.2 `C_*` API 1:1 —
one unary RPC per C function, `ck_rv` carried as a response FIELD (never
a transport error), raw `CKM_*`/`CKA_*`/`CKR_*` codepoints on the wire
(no enums). Where the original 7-verb service exposes a curated,
representative slice, this one exposes essentially the whole engine.

**Coverage is tracked as a live, checked artifact, not prose**:

- `remoting/coverage_ledger.json` — one row per category in
  `cpp_compliance_report.json`, plus vendor-only categories with no C++
  analogue (e.g. `SplitKey`) — 66 rows total as of 2026-09-01 (count
  corrected; this doc previously said 63, stale since the G2 Split Key
  workstream), each with a disposition
  (`RPC` / `N/A-local` / `N/A-engine` / `SUITE-GAP`), the test case(s)
  that exercise it, and why.
- `remoting/REMOTE_P11_V32_COVERAGE.md` — generated from the ledger via
  `python3 remoting/scripts/generate_coverage_report.py`; never hand-edit
  it.
- `remoting/scripts/check_coverage_ledger.py` — the ratchet: fails if a
  compliance category has no ledger row, a `case_ids` entry names a test
  that doesn't exist, or an RPC on `Pkcs11V32` has zero mention anywhere
  in the ledger. Wired into `scripts/local-gate.sh`'s existing
  "remoting gRPC+REST services + three-transport parity" step.

As of RW-T's coverage-ledger audit (2026-08-26, after RW5): **99 of 104
`pkcs11f.h` functions are live RPCs** (64 of 66 compliance categories
dispositioned `RPC` as of 2026-09-01 — count corrected, up from 63/61 after
later same-day ledger growth (G2's `SplitKey` vendor category, G3/G4); 2 are
`N/A-local` — Fork's RNG-divergence intent, and
`Init`'s `C_Initialize`/`C_Finalize` server lifecycle). The remaining 5
functions (`C_Initialize`, `C_Finalize`, `C_GetFunctionList`,
`C_GetInterface`, `C_GetInterfaceList`) are all deliberately N/A-local —
see the ledger's `pkcs11f_h_function_count` block for why. See the
generated report for the full per-category breakdown, and the
coverage-gap plan's "Execution log" for what shipped in each workstream
(RW0–RW6b, RW-T) and the real findings each one turned up — including
RW-T's own audit catching `C_VerifySignatureUpdate`/
`C_VerifySignatureFinal`/`C_GetSessionValidationFlags`, three real engine
capabilities RW6a's original sweep missed.

## Ports, certs, image (Step 2 — not built yet)

Suggested ports 5710 (gRPC) / 5720 (REST), both free on `pqc-mesh`. The
shared `admin-certs` mint (`kmip/src/cert_init.rs`) now includes SANs for
`pqc-grpc`, `pqc-rest`, `pqc-grpc-baseline`, `pqc-rest-baseline` alongside
`pqc-kmip` — one mint serves all services. Compose wiring, the job
runner, and the UI are Step 2 (`sandbox-bench-transport-arms-plan-08242026.md`
§5), gated on this step merging to hsm `main` with `HSM_REF` bumped.

## References

- PKCS#11 v3.2 OS (ratified 2026-06-03):
  <https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html>
- KMIP 3.0 Profiles v3.0 CSD02 §3.3 (Quantum Safe Authentication Suite) —
  vendored at `kmip/spec/oasis-kmip-3.0/`
- draft-ietf-tls-ecdhe-mlkem (hybrid group wire format)
- `sandbox-bench-transport-arms-plan-08242026.md` (workspace root of the
  Antigravity working directory) — the program plan this implements
