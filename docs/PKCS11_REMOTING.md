# PKCS#11 Remoting — gRPC + REST services

Two real, working, network-facing services in front of the `softhsmrustv3`
engine, first built 2026-08-24 per `sandbox-bench-transport-arms-plan-08242026.md`
Step 1 and substantially grown since (a 1:1 PKCS#11 v3.2 `C_*` mirror added
2026-08-26, FIPS 204 external-µ mode added 2026-08-31):

- **`pqc-grpc-pkcs11`** (`remoting/grpc`) — protobuf over gRPC (tonic),
  schema at `remoting/proto/proto/pkcs11_remote.proto`, package
  `pqctoday.pkcs11remote.v1`. Default listen address **`0.0.0.0:5710`**
  (`--listen` / env `PKCS11_REMOTE_LISTEN`).
- **`pqc-rest-pkcs11`** (`remoting/rest`) — JSON+base64 over HTTP/1.1
  keep-alive (axum). **h2 is deliberately disabled** — ALPN offers only
  `http/1.1`, even to an h2-capable client — so a benchmark comparing this
  arm against gRPC compares framing style, not two accidentally-different
  HTTP/2 stacks. Default listen address **`0.0.0.0:5720`** (`--listen` /
  env `PKCS11_REMOTE_LISTEN`).

Both wrap the same `pqctoday-pkcs11-remote-core` verb layer
(`remoting/core`), which calls `softhsmrustv3::native::*` directly — the
same functions the KMIP server's ops layer drives. Each binary actually
serves **two** independent proto services side by side: the original
hand-picked-verb service described in this section, and a much larger 1:1
`C_*` mirror (`Pkcs11V32`) described further down.

**Not the same thing as `webrpc/`**: `webrpc/README.md` describes an
unrelated, unbuilt roadmap item — a proposed extraction of a Flask+PyKCS11
prototype (`pqctoday-sandbox/api/kms_router.py`) into a standalone,
session-scoped-bearer-auth KMS. This `remoting/` service is real and
shipped, but it is **not** a replacement for that proposal: it has no
session-scoped bearer auth, no per-session key TTL/revocation, and no
orchestrator integration (see "Authentication and security posture"
below). Read `webrpc/README.md` before extending either one, so the two
don't duplicate the same wire-protocol work.

## Verb surface

**Nine RPCs on the `Pkcs11Remote` service**: a `Health` check, plus eight
PKCS#11-mapped verbs — `OpenSession`, `CloseSession`, `GenerateKeyPair`,
`Sign`, `Verify`, `Encapsulate`, `Decapsulate`, and `GetSelfSignedCertificate`
(the 8th verb, added 2026-08-25 — see `remoting/core/src/cert.rs`; the only
verb that returns a public key's real bytes at all, since
`GenerateKeyPairResponse` carries only two `uint32` handles). Representative
algorithm cells — the same set the KMIP arm uses — plus the full
ML-DSA/ML-KEM parameter-set family for completeness: `Ed25519`,
`ML-DSA-44/65/87`, `ML-KEM-512/768/1024` (`remoting/core/src/algorithm.rs`,
`Algorithm::ALL`, 7 cells). Widening the cell set is a match-arm addition
there, not new code in either service.

`Sign`/`Verify` also carry an `external_mu` flag (added 2026-08-31, ML-DSA
only): when `true`, the request's `data` is treated as an already-computed
64-byte FIPS 204 message representative µ rather than the raw message.
Setting it with `Ed25519` returns `CKR_MECHANISM_INVALID` (a real wire
condition, not a caller-bug panic — see `remoting/core/src/verbs.rs`).

This 9-RPC service is **frozen byte-for-byte** as a benchmark control arm
— the bench harness and `JavaJCE-remote` depend on it unchanged. It is
separate from, and much narrower than, the `Pkcs11V32` mirror described
under "The `Pkcs11V32` C_* mirror" below.

## Quick start — calling the service

**gRPC**, against the `Pkcs11V32` C_* mirror service (see below for what
that is): build and run the server, then drive a real sign/verify round
trip against it. This is exactly what `remoting/grpc/examples/smoke_client.rs`
does; it is a real example binary (not a `#[test]`), meant to be run by
hand against an already-started server:

```bash
# 1. Generate a dev TLS identity (subjectAltName must cover the domain
#    you connect to; CA:FALSE is required — see the file's own doc
#    comment for why):
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -days 1 -nodes -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment"

# 2. Start the real binary with that identity:
cargo run -p pqc-grpc-pkcs11 -- --listen 127.0.0.1:18710 \
  --tls-cert cert.pem --tls-key key.pem --enable-destructive

# 3. Run the smoke client against it — a full OpenSession →
#    GenerateKeyPair(ML-DSA-65) → SignInit/Sign → VerifyInit/Verify →
#    CloseSession sequence over a real TLS connection with a pinned CA:
cargo run -p pqc-grpc-pkcs11 --example smoke_client -- 127.0.0.1:18710 cert.pem
```

**REST**, using the original 9-RPC service's JSON+base64 shape
(`remoting/rest/src/routes.rs`/`dto.rs`). The REST server always serves
over TLS — there is no plaintext-HTTP mode — so a plain `cargo run -p
pqc-rest-pkcs11 -- --listen 0.0.0.0:5720` (default `permissive` profile,
no `--tls-cert`/`--tls-key`) auto-generates a self-signed dev identity at
startup; `curl -k` (skip cert verification) is what makes the example
below work against that self-signed cert:

```bash
# Open a session (the well-known benchmark PIN "1234" — see "Authentication
# and security posture" below for why this is not a real credential check):
curl -sk https://localhost:5720/v1/sessions \
  -H 'content-type: application/json' \
  -d '{"user_pin": "1234"}'
# → {"session_handle": 1}

# Generate an ML-DSA-65 keypair (cka_id is base64; algorithm names are
# kebab-case, e.g. "ml-dsa65", "ml-kem768", "ed25519" — see dto.rs):
curl -sk https://localhost:5720/v1/keys \
  -H 'content-type: application/json' \
  -d '{"session_handle": 1, "algorithm": "ml-dsa65", "cka_id": "AQ==", "label": "demo"}'
# → {"public_handle": 2, "private_handle": 3}

# Sign (data is base64; {id} in the path is the private-key handle):
curl -sk https://localhost:5720/v1/keys/3/sign \
  -H 'content-type: application/json' \
  -d '{"session_handle": 1, "algorithm": "ml-dsa65", "data": "aGVsbG8="}'
# → {"signature": "<base64>"}
```

The full REST route table (both the 9-RPC service's `/v1/*` routes and the
`Pkcs11V32` mirror's ~90 `/v32/*` routes) is in `remoting/rest/src/routes.rs`
and `routes_v32.rs`; the gRPC equivalent is the `service` definitions in
`remoting/proto/proto/pkcs11_remote.proto`.

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

## Authentication and security posture

**There is no application-level authentication in this service — no API
key, no bearer token, no per-caller identity.** This is stated plainly
because the doc previously risked implying otherwise; checked directly
against the code (`remoting/core/src/verbs.rs`, `remoting/grpc/src/main.rs`,
`remoting/rest/src/main.rs`, and a repo-wide grep for auth/bearer/api-key
patterns under `remoting/`), the only two access-control mechanisms that
exist today are:

1. **The `OpenSession` PIN check** — a string comparison against a single
   well-known, hardcoded benchmark constant (`"1234"`, `USER_PIN` in
   `verbs.rs`), the same for every caller and every process. The module
   doc for `verbs.rs` says this explicitly: "not a security boundary,
   matching the existing bench-harness/KMIP in-process control arm's own
   convention." Anyone who can reach the port and knows (or guesses) this
   constant can open a session.
2. **TLS, optionally with mutual TLS** — this is the one real control the
   service has, and it is genuinely enforced (see TLS below): under the
   `quantum-safe` profile, both binaries refuse to start at all without
   `--tls-client-ca`, and connections without a valid client certificate
   are rejected. Under `permissive` (the default) or `classical-baseline`,
   client certificates are accepted if presented but not required.

There is no session TTL, no key revocation, no per-caller scoping beyond
the single shared benchmark token, and no request-level authorization
(any caller who can open a session can drive any verb against any handle
that session can see — see the "Inherited gap" note above). This matches
exactly what `webrpc/README.md` says when distinguishing itself from this
service: "It is not a replacement for this proposal — it has no
session-scoped bearer auth, no per-session key TTL/revocation, and no
orchestrator integration." If a deployment needs real caller-level auth,
that is `webrpc/`'s (currently unbuilt) proposal, not something to assume
exists here.

## Building and running the services

Both binaries are real Cargo binaries (`pqc-grpc-pkcs11`, `pqc-rest-pkcs11`
— crate names `pqc-grpc-pkcs11`/`pqc-rest-pkcs11`, package names in
`remoting/grpc/Cargo.toml` and `remoting/rest/Cargo.toml`), built from the
standalone `remoting/` Cargo workspace (`remoting/Cargo.toml` — **not** a
member of `../rust`'s workspace, so it never enters the wasm build graph):

```bash
cd remoting
cargo build -p pqc-grpc-pkcs11 -p pqc-rest-pkcs11 --release

# gRPC, permissive TLS (self-signed dev cert auto-generated if
# --tls-cert/--tls-key are omitted):
cargo run -p pqc-grpc-pkcs11 -- --listen 0.0.0.0:5710

# REST, same defaults:
cargo run -p pqc-rest-pkcs11 -- --listen 0.0.0.0:5720
```

CLI flags (all also settable via environment variable — both binaries
share the same flag/env names):

| Flag | Env var | Default | Meaning |
|---|---|---|---|
| `--listen` | `PKCS11_REMOTE_LISTEN` | `0.0.0.0:5710` (gRPC) / `0.0.0.0:5720` (REST) | Listen address |
| `--tls-profile` | `PKCS11_REMOTE_TLS_PROFILE` | `permissive` | `permissive` \| `quantum-safe` \| `classical-baseline` — see TLS below |
| `--tls-cert` / `--tls-key` | `PKCS11_REMOTE_TLS_CERT` / `PKCS11_REMOTE_TLS_KEY` | unset | PEM server identity; if both are omitted, a self-signed identity is generated at startup (sandbox/dev only — logged as a warning) |
| `--tls-client-ca` | `PKCS11_REMOTE_TLS_CLIENT_CA` | unset | Client CA bundle for mTLS; **required** to start under `quantum-safe` (the binary refuses to start without it, mirroring the KMIP server's own rule) |
| `--enable-destructive` | `PKCS11_REMOTE_ENABLE_DESTRUCTIVE` | `false` | Enables destructive `Pkcs11V32` RPCs (`C_DestroyObject`, and the other RPCs marked "gated by `--enable-destructive`" in the proto) — OFF by default in any deployed container; the acceptance/gate environment turns it ON |

Both servers cap request/response size at **16 MiB** in both directions
(explicit — axum's/tonic's implicit defaults would silently reject
legitimate large payloads, e.g. big classical-cipher inputs). The default
ports (5710/5720) and the SAN list on the auto-generated self-signed dev
certs (`pqc-grpc`/`pqc-grpc-baseline`/`localhost` for gRPC,
`pqc-rest`/`pqc-rest-baseline`/`localhost` for REST) already match the
shared `admin-certs` mint's naming, so a real cert from that mint drops in
without renaming anything. What is **not** built yet — Docker Compose
wiring, a benchmark job runner, and a UI — is covered under "Ports, certs,
image" below; the servers themselves are real, buildable, runnable
binaries today, not a future step.

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
(`rust/test_p11_conformance.js`; **999 passed / 0 failed across 51
sections** as of the 2026-09-02 regeneration — see that report for the
live count, which this table intentionally does not restate as a fixed
number since the suite is actively evolving; the table below still
reflects the 40-section snapshot it was originally written against, so
the 11 sections added since are not yet individually mapped here). These
services expose 8 of the engine's many verbs, so most of those 40 sections
have no remote endpoint to test at all. The claim here is narrower and
precise: **of the sections that genuinely touch the 8 exposed verbs,
every applicable one is covered**, asserted on the exact numeric `CKR_*`
value, through all three surfaces (in-process control, real gRPC, real
REST) — `remoting/acceptance/tests/three_way_parity.rs`, which as of
2026-08-31 runs **8 cases (A1–A8)**, not the 5 this table's original
prose described.

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
| 18 | E1 — ML-DSA context string + hedge variant | Partially covered | `Sign`/`Verify` use the external-hedged, empty-context default, with one exposed variance: `external_mu` (FIPS 204 external-µ mode, added 2026-08-31 — **Case A8** proves a genuinely different code path, not a silently-ignored flag, three ways). The context-string and internal-µ/deterministic-signing modes remain unexposed — a future widening, not a gap in what's exposed today. |
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

**Summary**: 5 sections from the original 40-row table have a dedicated
automated case (5, 6, 17, 27, plus 30 sharing 6's case); 2 more are
covered by an existing case's shape without a dedicated one (18's
external-µ half via A8, 19, and KEM's positive path under 17); 1 is a
documented, deliberate non-goal (14); the remaining 31 are N/A because
this service's 8-verb surface has no corresponding endpoint. `GetSelfSignedCertificate`
(the 8th verb) doesn't map to any of these 40 rows at all — it isn't a
`C_*` function — but has its own dedicated coverage: **Case A6** (positive
round trip, all 3 transports, embedded signature re-verified not just
DER-parsed) and **Case A7** (rejects an ML-KEM key with `CKR_ARGUMENTS_BAD`).
Nothing here is silently skipped — every N/A row states why.

## The `Pkcs11V32` C_* mirror (2026-08-26 — a separate, additive service)

Everything above this section describes the **original 9-RPC service**
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
(no enums). Where the original 9-RPC service exposes a curated,
representative slice (8 verbs), this one exposes essentially the whole
engine — roughly 90 RPCs, one per `C_*` function plus two vendor-only
`SplitKey`/`JoinKey` RPCs (see `remoting/proto/proto/pkcs11_remote.proto`'s
`Pkcs11V32` service block for the exhaustive list; several destructive
RPCs — `C_DestroyObject`, `C_SetAttributeValue`, `C_InitToken`,
`C_InitPIN`, `C_SetPIN` — are gated behind `--enable-destructive`, off by
default).

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

## Ports, certs, image

**The servers, their default ports, and real certs already exist** — see
"Building and running the services" above. What's described in this
section as still outstanding is packaging/orchestration around them, not
the binaries themselves.

Ports 5710 (gRPC) / 5720 (REST) are the binaries' actual compiled-in
defaults (`--listen`, both free on `pqc-mesh`), not merely a suggestion.
The shared `admin-certs` mint (`kmip/src/cert_init.rs`) includes SANs for
`pqc-grpc`, `pqc-rest`, `pqc-grpc-baseline`, `pqc-rest-baseline` alongside
`pqc-kmip` — one mint serves all services, and those are exactly the same
names the binaries' own self-signed dev-cert fallback generates
(`rcgen_self_signed()` in `remoting/grpc/src/main.rs`, the equivalent in
`remoting/rest/src/main.rs`), so swapping in a real mint-issued cert via
`--tls-cert`/`--tls-key` needs no renaming.

**Still not built** (checked: no Dockerfile, `docker-compose*.yml`, or
job-runner references `pqc-grpc-pkcs11`/`pqc-rest-pkcs11`/port
5710/5720 anywhere in this repo outside `remoting/` itself as of this
writing): a container image, Compose wiring, a benchmark job runner, and
a UI. These remain Step 2 (`sandbox-bench-transport-arms-plan-08242026.md`
§5), gated on that step merging to hsm `main` with `HSM_REF` bumped.

## References

- PKCS#11 v3.2 OS (ratified 2026-06-03):
  <https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html>
- KMIP 3.0 Profiles v3.0 CSD02 §3.3 (Quantum Safe Authentication Suite) —
  vendored at `kmip/spec/oasis-kmip-3.0/`
- draft-ietf-tls-ecdhe-mlkem (hybrid group wire format)
- `sandbox-bench-transport-arms-plan-08242026.md` (workspace root of the
  Antigravity working directory) — the program plan this implements
- `webrpc/README.md` — a related but distinct, unbuilt roadmap proposal
  (session-scoped bearer auth, persistent keys, orchestrator integration);
  see "Not the same thing as `webrpc/`" above and "Authentication and
  security posture" for how the two differ today
- `remoting/REMOTE_P11_V32_COVERAGE.md` and `remoting/coverage_ledger.json`
  — the generated, checked source of truth for `Pkcs11V32` coverage
  claims; regenerate via `python3 remoting/scripts/generate_coverage_report.py`,
  verify via `python3 remoting/scripts/check_coverage_ledger.py`
