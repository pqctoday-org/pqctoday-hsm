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

| HTTP route | `PolicyStore` primitive | Effect |
|---|---|---|
| `GET /policies` | `list()` | enumerate policies |
| `GET /policies/{name}` | `load()` + raw YAML | read one (for an editor) |
| `GET /active` | `read_active()` | what's active now |
| `GET /audit?limit=N` | `RingSink.snapshot()` | the three-plane audit trail (p1/p2/p3), newest last — the "inspect logs" source |
| `POST /validate` | `validate_draft(yaml)` | parse + validate, no disk (live lint) |
| `POST /dry-run` | `dry_run(yaml, {op,algorithm})` | evaluate a sample request, no side effects |
| `PUT /policies/{name}` | `save(name, yaml)` | persist (atomic) |
| `POST /policies/{name}/activate` | `activate_with_engine(name, engine)` | **swap the live enforcement policy** |

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
  --admin-client-ca admin-client-ca.crt
```

Client must offer `X25519MLKEM768` (OpenSSL ≥ 3.5 / aws-lc-rs / BoringSSL) and
present a client cert signed by `--admin-client-ca`, e.g.:

```bash
printf 'POST /policies/pqc/activate HTTP/1.1\r\nConnection: close\r\n\r\n' | \
  openssl s_client -connect 127.0.0.1:5697 -groups X25519MLKEM768 \
    -cert client.crt -key client.key -CAfile admin-client-ca.crt -quiet
```

## Verified (manual, OpenSSL 3.6.2 client)

- `Negotiated TLS1.3 group: X25519MLKEM768` ✓ (handshake fails on any other group).
- mTLS enforced — a certless client is rejected (`tlsv13 alert certificate required`).
- `GET /policies`, `GET /active`, `POST /validate` (clean line/col error),
  `POST /dry-run` (`{"decision":{"outcome":"allow"}}`), `PUT /policies/{name}`,
  and **`POST /policies/{name}/activate`** all return correct JSON.
- **`GET /audit`** returns the live three-plane trail — a pykmip-driven
  CreateKeyPair shows up as p1 PolicyDecided + p2 KmipRequestReceived/Sent +
  p3 Pkcs11Call, consumed via the same mTLS admin interface.
- Live activation flips the running engine (`/active` reflects it immediately)
  and is audited with the client-cert CN:
  `admin: LIVE policy activated name="pqc" fp=… by cn="policy-admin-alice"`.

Unit tests in [`manager.rs`](manager.rs) cover the router + the PQC-mTLS config
build; the handshake/route behaviour above is the manual smoke.
