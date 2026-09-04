# cryptopolicy-manager — HTTP admin facade for the crypto-agility policy plane

> **Status: implemented.** The W4 *server-side HTTP admin facade* — a
> quantum-safe-mTLS JSON API over the `PolicyStore`, compiled into the
> `pqctoday-kmip` server and enabled with `--admin-listen`. It is **not** a
> KMIP surface — policy administration stays out-of-band from the enforcement
> protocol (separation of duties). See
> [`../docs/CRYPTO_AGILITY_CONFIGURATION.md`](../docs/CRYPTO_AGILITY_CONFIGURATION.md)
> for how policy works via file + CLI.
>
> Source: [`manager.rs`](manager.rs) (compiled into the crate via a `#[path]`
> module in `../src/lib.rs`).

## Purpose

Expose the existing Rust `PolicyStore` primitives over HTTP so a UI / ops
tooling can **read, author, validate, dry-run, and activate** crypto-agility
policies on a *running* server — without editing files on the box or
restarting it.

All routes below are versioned under `/api/v1/` except the three
infrastructure endpoints (`/healthz`, `/version`, `/openapi.yaml`), per the
module doc-comment in [`manager.rs`](manager.rs) and the routing match in its
`route()` function (the source of truth — verify against those, not this
table, if the two ever disagree). Errors are RFC 7807 `application/problem+json`.

| HTTP route | `PolicyStore` primitive | Effect |
|---|---|---|
| `GET /healthz` | — | `{"status":"ok"}` liveness check |
| `GET /version` | — | `{version, git_sha}` |
| `GET /openapi.yaml` | — | the OpenAPI 3.1 spec, embedded at compile time from [`openapi.yaml`](openapi.yaml) |
| `GET /api/v1/policies` | `list()` | enumerate policy names on disk |
| `POST /api/v1/policies` (body: YAML) | `validate_draft()` + `save()` | create a new policy file; name comes from the YAML's own `metadata.name` |
| `GET /api/v1/policies/{name}` | `load()` + raw YAML | read one (for an editor) |
| `PUT /api/v1/policies/{name}` (body: YAML) | `save(name, yaml)` | persist (atomic tempfile + rename) |
| `GET /api/v1/active` | `read_active()` | the active **legacy** (unscoped) policy, or `null` |
| `PUT /api/v1/active` (body: `{"name":"…"}`) | `activate_with_engine(name, engine)` | **swap the live legacy enforcement policy** — replaces the old `POST /policies/{name}/activate` route |
| `GET /api/v1/active-modules` | `read_active_modules()` | the active **modular** set: `{uncovered_ops, modules}` (schema v3 — see [`../policies/README.md`](../policies/README.md#modular-policies-schema-v3--scopes-and-multi-file-composition)) |
| `POST /api/v1/active-modules` (body: `{"name":"…"}`) | `activate_module_with_engine()` | push/upsert one scoped module onto the live set |
| `DELETE /api/v1/active-modules` | `clear_modules_with_engine()` | drop the entire modular set (fail-closed OFF) |
| `DELETE /api/v1/active-modules/{name}` | `deactivate_module_with_engine()` | deactivate one module by name |
| `PATCH /api/v1/active-modules/{name}` (body: `{"enabled":bool}`) | `set_module_enabled_with_engine()` | disable/re-enable a module without unloading it |
| `GET /api/v1/config/uncovered-ops` | `engine.uncovered_ops()` | current `deny`/`allow` policy for ops no active module claims |
| `PUT /api/v1/config/uncovered-ops` (body: `{"mode":"deny"\|"allow"}`) | `set_uncovered_ops_with_engine()` | change it live |
| `POST /api/v1/validate` (body: YAML) | `validate_draft(yaml)` | parse + validate, no disk (live lint) |
| `POST /api/v1/dry-run` (body: `{yaml,op,algorithm?}`) | `dry_run(yaml, {op,algorithm})` | evaluate a sample request, no side effects |
| `GET /api/v1/audit[?limit=N]` | `RingSink.snapshot()` | the three-plane audit trail (p1/p2/p3), newest last, capped at 2000 |
| `GET /api/v1/audit/stream` | `SseSink` | live `text/event-stream` of new audit events (heartbeat comments filtered by the client) |

**Legacy (`/api/v1/active`) and modular (`/api/v1/active-modules`) are
mutually exclusive slots** — whichever is non-empty governs; see
[`../policies/README.md`](../policies/README.md)'s "Modular policies" section
for `Engine::activate`/`replace_all`'s exact interaction.

The active-modules and `config/uncovered-ops` routes (added 2026-08-28 with
the modular-policy plan) are **not yet wrapped by the Python `AdminClient`**
in [`../python-client/`](../python-client/) — that client still only covers
the original twelve A1 endpoints. Reach them with a raw HTTPS request (or
extend `admin.py`) until a client method exists.

## Consumers

The primary consumer is a **crypto-agility policy-management section in the dev
sandbox** (`pqctoday-sandbox`): a UI panel that lists policies, shows/edits the
YAML, **lints live** (`POST /policies/validate` on edit), **tests** a draft
against a sample request (`POST /policies/dry-run` — the side-effect-free
"what would this policy decide?" button), persists (`PUT`), and **activates**
on the running server (`POST .../activate`). So the API is a stable JSON
contract: clean request/response shapes, explicit error bodies (carry the YAML
line/column from `validate_draft` where available), and CORS for the sandbox
origin. The sandbox section is a downstream piece (separate repo) that consumes
this API.

## The architectural constraint (why this is in-process)

`activate_with_engine` must mutate the **running KMIP server's** `Arc<Engine>`
to take effect without a restart. So the admin HTTP listener has to run **in
the same process** as the KMIP server, sharing that `Engine` handle, on a
**separate admin port** (never the KMIP port).

A fully separate process could only do *file-based* management (write the YAML
+ flip the `.active` marker) and would still need the server to reload — no
live hot-swap. So the design is: this folder holds the admin-facade code
(handlers + router + auth), and the `pqctoday-kmip` server binary opts into a
second listener (`--admin-listen <addr>`) that mounts it against the shared
`Engine` + `PolicyStore`.

## Security posture (non-negotiable)

- **Separate port**, bound to localhost by default; never multiplexed onto the
  KMIP listener.
- **Authentication required** for every mutating route (activate / save) — the
  facade can change the policy that governs all crypto, so it is the most
  security-sensitive surface in the system.
- Every mutation is **audited** — `activate_with_engine` already emits a
  Plane-1 `PolicyActivated` event; save/validate get their own.
- Read/dry-run vs write/activate may warrant different authz tiers.

## Resolved design

- **In-process** (live hot-swap): a `#[path]` module compiled into the
  `pqctoday-kmip` crate; the server spawns the admin listener sharing a clone of
  the live `Engine` (`Arc<RwLock>` inside), so an `activate` is enforced on the
  next KMIP request with no restart.
- **HTTP**: a minimal hand-rolled HTTP/1.1 handler (`Connection: close`, JSON)
  over the `tokio-rustls` stream — no new HTTP framework, matching the crate's
  hand-rolled-protocol style.
- **Transport / auth — quantum-safe mTLS**: `X25519MLKEM768`-only key exchange
  (ML-KEM-768 hybrid, TLS 1.3) via the rustls **aws-lc-rs** provider (the KMIP
  listener's `ring` default is untouched) + **required client certificates**.
  Client/server certs are **classical** (ECDSA/Ed25519): rustls 0.23 has no
  ML-DSA *certificate* support yet, so the quantum-safety is in the **session
  key exchange** (defeats harvest-now-decrypt-later), not the cert signatures.

## Running it

```bash
pqctoday-kmip \
  --listen 127.0.0.1:5696 --store-memory --policy-dir policies --policy aead-only \
  --admin-listen 127.0.0.1:5697 \
  --admin-tls-cert admin-server.crt --admin-tls-key admin-server.key \
  --admin-client-ca admin-client-ca.crt \
  --admin-write-cn policy-admin-alice
```

`--admin-write-cn` is required for anything beyond a read — with no CN
authorized, every mutating route (`POST`/`PUT policies`, `PUT active`, the
`active-modules` verbs, `PUT config/uncovered-ops`) returns 403 even over a
successfully-authenticated mTLS connection (S-1: mTLS authenticates, this
authorizes writes).

Client must offer `X25519MLKEM768` (OpenSSL ≥ 3.5 / aws-lc-rs / BoringSSL) and
present a client cert signed by `--admin-client-ca`, e.g.:

```bash
printf 'PUT /api/v1/active HTTP/1.1\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: 14\r\n\r\n{"name":"pqc"}' | \
  openssl s_client -connect 127.0.0.1:5697 -groups X25519MLKEM768 \
    -cert client.crt -key client.key -CAfile admin-client-ca.crt -quiet
```

(the client cert's subject CN must be one of the `--admin-write-cn` values,
e.g. `policy-admin-alice` above — otherwise this specific `PUT` gets 403; a
plain `GET /api/v1/active` needs no CN authorization, only a valid client cert)

## Verified (manual, OpenSSL 3.6.2 client)

- `Negotiated TLS1.3 group: X25519MLKEM768` ✓ (handshake fails on any other group).
- mTLS enforced — a certless client is rejected (`tlsv13 alert certificate required`).
- `GET /api/v1/policies`, `GET /api/v1/active`, `POST /api/v1/validate` (clean
  line/col error), `POST /api/v1/dry-run` (`{"decision":{"outcome":"allow"}}`),
  `PUT /api/v1/policies/{name}`, and **`PUT /api/v1/active`** all return
  correct JSON.
- **`GET /api/v1/audit`** returns the live three-plane trail — a pykmip-driven
  CreateKeyPair shows up as p1 PolicyDecided + p2 KmipRequestReceived/Sent +
  p3 Pkcs11Call, consumed via the same mTLS admin interface.
- Live activation flips the running engine (`GET /api/v1/active` reflects it
  immediately) and is audited with the client-cert CN:
  `admin: LIVE policy activated name="pqc" fp=… by cn="policy-admin-alice"`.

Unit tests in [`manager.rs`](manager.rs) cover the router + the PQC-mTLS config
build; the handshake/route behaviour above is the manual smoke.
