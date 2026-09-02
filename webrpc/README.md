# Web RPC — Language-Agnostic REST Signing Interface

> **Status: Roadmap item — not yet implemented as a standalone service.**
>
> A working prototype exists in
> [`pqctoday-sandbox/api/kms_router.py`](https://github.com/pqctoday/pqctoday-sandbox/blob/main/api/kms_router.py).
> This folder tracks the plan to graduate it into a proper softhsmv3 integration interface.
>
> **Related but distinct:** [`remoting/`](../remoting/REMOTE_P11_V32_COVERAGE.md) has
> since shipped a real gRPC + REST service (`pqc-grpc-pkcs11` / `pqc-rest-pkcs11`) that
> mirrors the full PKCS#11 surface (99/104 `pkcs11f.h` functions) over the network. It
> is not a replacement for this proposal — it has no session-scoped bearer auth, no
> per-session key TTL/revocation, and no orchestrator integration, all of which are this
> document's actual value proposition. Read `docs/PKCS11_REMOTING.md` before extracting
> this service, so the two don't duplicate the same wire-protocol work.

---

## What this would be

A fifth integration interface for softhsmv3, sitting alongside the four documented ones:

| Interface | Who can use it |
| --- | --- |
| Direct PKCS#11 (`libsofthsm3.so`) | Code that can `dlopen` a native library |
| OpenSSL Provider (`src/vendor/latchset/`) | Apps linked to or calling the OpenSSL CLI |
| StrongSwan Adapter (`strongswan-pkcs11/`) | IKEv2 VPN daemons |
| Java JCE Layer (`JavaJCE/`) | JVM applications (Besu, Spring Security) |
| **Web RPC** *(this folder)* | **Anything that can make an HTTP call** |

The value proposition is simple: every other interface requires native binding work.
A REST endpoint makes the full softhsmv3 PQC algorithm suite reachable from Go, Rust,
Ruby, bash, IoT devices, CI pipelines — without shipping softhsmv3 as a dependency or
knowing anything about PKCS#11.

---

## Current prototype (sandbox-only)

`pqctoday-sandbox/api/kms_router.py` is a Flask + PyKCS11 server running as the
`pqctoday-sandbox-kms` container (port 5000 internal, 9000 on host). It exposes:

```http
POST /api/v1/sign
Content-Type: application/json

{
  "algorithm": "ML-DSA-65",
  "key_label": "validator-node",
  "pin": "1234",
  "data_hex": "0xFFFC..."
}
→ { "status": "success", "algorithm_enforced": "ML-DSA-65", "signature": "0x..." }
```

Algorithms supported today: ML-DSA-44/65/87, all 12 SLH-DSA parameter sets.

It works. The sandbox uses it for ACVP vector validation (`tests/test_acvp_compliance.py`)
and as the signing backend for the Hyperledger Besu scenario (scenario 19).

---

## Why it has not been extracted yet

Three problems make the current prototype unsuitable as a published interface:

**1. Auth.** The PIN is in the request body (`"pin": "1234"`). That is fine inside a
Docker private network where the caller is a co-located container. Exposed externally it
is a credential in plaintext HTTP — a non-starter.

**2. Persistence.** The softhsmv3 token is initialised at image build time and lives in
the image layer. The container is reaped by the orchestrator after the session TTL expires,
taking all generated keys with it. A real KMS needs keys that survive restarts.

**3. Deployment coupling.** The kms-proxy is one of four containers spun up per sandbox
session (`ui + network + physics + kms-proxy`). It cannot be used without the full
sandbox stack. Most sandbox sessions today never call it — it is overhead that belongs
in a shared service, not a per-session sidecar.

These are solvable engineering problems, not fundamental objections to the approach.

---

## What the standalone service would look like

### Auth

Replace PIN-in-body with a bearer token:

```http
POST /api/v1/sign
Authorization: Bearer <session-api-key>
Content-Type: application/json

{ "algorithm": "ML-DSA-65", "key_label": "validator-node", "data_hex": "0x..." }
```

The orchestrator generates a UUID per sandbox session and passes it to the service
as a scoped key. When the session TTL expires the orchestrator revokes the key.
PIN stays as a server-side env var (`KMS_TOKEN_PIN`) — callers never supply credentials.

### Persistence

Mount a Docker volume at `/var/lib/softhsm/tokens`. Token init becomes idempotent:
run `softhsm2-util --init-token` only on first boot when the volume is empty.
Keys survive container restarts and redeployments.

### Deployment

A single always-on Fly.io machine (`kms.pqc.today`) shared across all sessions,
instead of one kms-proxy container per session. Reduces the orchestrator's per-session
container count from 4 to 3. At 20 concurrent sessions that eliminates ~20 ephemeral
machines, materially reducing the Fly.io bill.

### New endpoint

Add `POST /api/v1/keys/generate` to separate key provisioning from signing:

```http
POST /api/v1/keys/generate
Authorization: Bearer <key>

{ "algorithm": "ML-DSA-65", "label": "validator-node" }
→ { "label": "validator-node", "algorithm": "ML-DSA-65", "public_key_hex": "0x..." }
```

### Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `KMS_API_KEYS` | *(required)* | Comma-separated valid bearer tokens |
| `KMS_TOKEN_PIN` | `1234` | softhsmv3 user PIN (never in request body) |
| `KMS_SO_PIN` | `12345678` | softhsmv3 SO PIN |
| `KMS_TOKEN_LABEL` | `softhsm-kms` | Token label |
| `PKCS11_MODULE` | `/usr/local/lib/softhsm/libsofthsmv3.so` | Library path |
| `KMS_TLS_CERT` | *(unset)* | Optional TLS cert (Fly.io handles this automatically) |

---

## Benefits once extracted

**For pqctoday-sandbox:**
- Lean scenario containers — Go, Rust, Node scenarios get ML-DSA signing via two
  lines of curl, no softhsmv3 build in the container.
- Cross-scenario key continuity — scenario 17 (firmware signing) and scenario 34
  (supply chain) can share one signing key per session, enabling realistic end-to-end
  signing chains instead of isolated per-scenario ephemeral keys.
- Unblocks 8–10 scenarios that currently simulate signing because there is no clean
  way to reach ML-DSA from their runtime.

**For pqctoday-orchestrator:**
- One shared KMS replaces a per-session kms-proxy container.
- Session isolation via scoped API key revocation instead of container teardown.

**For pqc-timeline-app:**
- Foundation for persistent key workspaces in the paid tier — a user's ML-DSA
  identity key survives browser reloads and session TTL resets.

**For future pqctoday modules:**
- pqctoday-tpm gets a signing oracle without PKCS#11 plumbing.
- Any new module or partner integration reaches ML-DSA and SLH-DSA via REST.

---

## Why not now

The extraction is worth doing. The timing is not right yet.

- **The orchestrator is not deployed.** The Fly.io plan exists but milestones A–E are
  all unchecked. Building the KMS integration before the orchestrator is running in
  production means designing against a hypothetical session lifecycle, not a real one.

- **Usage is low.** Only `test_kms_proxy.py` and `test_acvp_compliance.py` call port
  9000 today. No scenario routes to it live. Extracting a service that almost nothing
  depends on is infrastructure work ahead of demonstrated need.

- **Cross-scenario key continuity requires scenario redesign.** The most compelling
  benefit needs 10+ scenarios to be updated to actually share a key. That is a
  separate project on top of the extraction project.

**Recommended sequence:**

1. Deploy the orchestrator on Fly.io (Milestones A–D).
2. Wire 3–4 sandbox scenarios to call the kms-proxy live (Besu is the natural first).
3. Observe real usage — which scenarios call it, how often, what key lifecycle looks like.
4. Extract to a standalone service once the usage pattern is clear.

Revisit in 4–6 weeks after the orchestrator is in production.

---

## Implementation estimate (when ready)

| Phase | Work | Duration |
| --- | --- | --- |
| 1 | Extract + harden `kms_router.py` → `softhsm-kms` repo | 3–4 days |
| 2 | Update sandbox: configurable `KMS_URL`, same image in compose | 1 day |
| 3 | Orchestrator: scoped API key issuance + revocation on reap | 1 day |
| 4 | Fly.io deployment as `kms.pqc.today` | 1 day |
| 5 | Add as 5th integration interface in softhsmv3 docs | 0.5 day |
| **Total** | | **~8 days** |

---

## References

- Prototype: [`pqctoday-sandbox/api/kms_router.py`](https://github.com/pqctoday/pqctoday-sandbox/blob/main/api/kms_router.py)
- Sandbox KMS Dockerfile: [`pqctoday-sandbox/docker/Dockerfile.kms`](https://github.com/pqctoday/pqctoday-sandbox/blob/main/docker/Dockerfile.kms)
- Orchestrator Fly.io plan: [`pqctoday-sandbox/docs/orchestrator-flyio-plan.md`](https://github.com/pqctoday/pqctoday-sandbox/blob/main/docs/orchestrator-flyio-plan.md)
- Other softhsmv3 integration interfaces: [`docs/softhsmv3devguide.md`](../docs/softhsmv3devguide.md)
