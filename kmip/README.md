# pqctoday-kmip — PQC KMIP 3.0 server + crypto-agility (CACP) policy engine

A post-quantum **KMIP 3.0** key-management server built on the `softhsmrustv3`
engine, with a three-plane architecture (policy / KMIP / PKCS#11), a durable or
in-memory key store, TLS + admin-mTLS transports, and the **CACP crypto-agility
policy engine**. This is the operator/developer runbook — build it, run it, and
exercise it end to end.

- **Data plane:** KMIP 3.0 TTLV over TLS (default `127.0.0.1:5696`).
- **Control plane:** optional REST policy-admin facade over mTLS.
- **Crypto:** ML-KEM, ML-DSA, SLH-DSA, AES/HMAC, and hybrid KEMs
  **X25519MLKEM768** / **SecP256r1MLKEM768**.

> New here? Run the one-command demo in §3, then read §5 (policies) and §6
> (conformance). For the algorithm deprecation policy see
> [`DEPRECATED.md`](DEPRECATED.md); for the policy engine see
> [`policies/README.md`](policies/README.md).

---

## 1. Prerequisites

- Rust stable with `cargo` (build uses the default `native` feature set: tokio +
  rustls TLS, bundled SQLite, rcgen PQC CA, Prometheus metrics).
- Python ≥ 3.10 for the stdlib-only test client (no pip dependencies).
- OpenSSL ≥ 3.5 is only needed if you cross-check certificates with the `openssl`
  CLI.

---

## 2. Build

```bash
cd kmip

# Server + client + compliance binaries (native feature set is the default)
cargo build --release

# Binaries land in target/release/:
#   pqctoday-kmip             — the KMIP server
#   pqctoday-kmip-client      — a Rust smoke client
#   pqctoday-kmip-compliance  — placeholder (the real conformance runner is the
#                               Rust test suite + the Python replay harness, §6)
```

To build the transport-free library core that the in-browser WASM bundle links
against (no TLS/SQLite/CA), use `cargo build --no-default-features`. The
in-browser control plane is built with `../scripts/build-kmip-wasm.sh` (Rust →
`wasm32-unknown-unknown` via wasm-bindgen; runs in an OrbStack `rust:1`
container if `cargo` is not on PATH).

---

## 3. Fastest path — the demo

The Python client ships an end-to-end demo (PQC happy path + an allow-vs-deny
policy check). It talks to a running server; the simplest server is the
sandbox profile: in-memory store + auto-generated self-signed TLS.

```bash
# Terminal 1 — start the sandbox server (memory store, self-signed TLS on :5696)
./target/release/pqctoday-kmip --store-memory

# Terminal 2 — run the demo against it
cd python-client
python -m pqctoday_kmip demo --host 127.0.0.1 --port 5696
```

With no `--tls-cert/--tls-key`, the server auto-generates a self-signed cert and
**prints its fingerprint** — the demo client uses `verify=False` for the sandbox.
For production, supply real certs (§4).

---

## 4. Running the server

```
pqctoday-kmip [OPTIONS]

  --listen <ADDR>            Data-plane TLS listener        [default 127.0.0.1:5696]
  --store <PATH>             Durable SQLite key store
  --store-memory             Volatile in-memory store (sandbox; default if --store omitted)
  --policy-dir <DIR>         Directory of policies/*.yaml   (empty = built-in permissive)
  --policy <NAME>            Activate this policy on startup (overrides the .active marker)
  --tls-cert <PEM>           Server cert (omit ⇒ self-signed sandbox cert)
  --tls-key  <PEM>           Server key (pairs with --tls-cert)
  --tls-client-ca <PEM>      Require + verify client certs (mutual TLS on the data plane)
  --tls-profile <NAME>       permissive | quantum-safe      [default permissive] (§4.1)
  --admin-listen <ADDR>      Enable the REST policy-admin facade (e.g. 127.0.0.1:5697)
  --admin-tls-cert/key <PEM> Admin facade server cert/key   (required with --admin-listen)
  --admin-client-ca <PEM>    Admin mTLS client-CA bundle    (required with --admin-listen)
  --admin-write-cn <CN>      Client-cert CN(s) allowed to MUTATE policy (repeatable)
  --init-certs <DIR>         Generate the admin mTLS CA+server+client certs on first boot
  --metrics-listen <ADDR>    Prometheus /metrics            [default 127.0.0.1:9095]
```

**Durable deployment example** (SQLite store, real TLS, admin control plane):

```bash
# One-time: generate admin mTLS material (CA + server + client certs) into ./admin-certs
./target/release/pqctoday-kmip --init-certs ./admin-certs --store-memory &  # boots, writes certs, then serve

./target/release/pqctoday-kmip \
  --listen 0.0.0.0:5696 \
  --store /var/lib/pqctoday-kmip/keys.db \
  --tls-cert server.crt --tls-key server.key \
  --policy-dir policies --policy cnsa-2.0 \
  --admin-listen 127.0.0.1:5697 \
  --admin-tls-cert admin-certs/server.crt --admin-tls-key admin-certs/server.key \
  --admin-client-ca admin-certs/ca.crt \
  --admin-write-cn kms-operator
```

### 4.1 Quantum-safe TLS profile (`--tls-profile quantum-safe`)

KMIP 3.0 **Profiles v3.0 §3.3, "Quantum Safe Authentication Suite"**, is a set
of SHALL / SHALL NOT clauses on the client channel — not a preference. Its
normative reference is `draft-ietf-tls-ecdhe-mlkem` (hybrid ECDHE-ML-KEM key
agreement for TLS 1.3).

`--tls-profile quantum-safe` enforces them. It is **opt-in**: the default stays
`permissive`, because §3.1.1 (the *Basic* suite) explicitly says servers SHOULD
support TLS 1.2, so tightening globally would put this server out of line with
the profile most deployments actually run.

| Clause | Enforced |
|---|---|
| §3.3.1 | TLS **1.3 only** — TLS 1.2 and below are refused, not merely deprioritised |
| §3.3.2 | exactly `TLS13_CHACHA20_POLY1305_SHA256` + `TLS13_AES_256_GCM_SHA384`. `TLS13_AES_128_GCM_SHA256` is **dropped**, as the clause forbids it |
| §3.3.3 | only hybrid ML-KEM groups — **classical groups are refused** (see the gap below) |
| §3.3.4 | refuses to **start** with neither `--auth-user` nor `--tls-client-ca`: the clause permits channel identity *or* credentials, not neither |
| §3.3.5 | port 5696 (unchanged) |

```bash
# Credentials as the identity source
./target/release/pqctoday-kmip --tls-profile quantum-safe --store-memory \
  --auth-user "alice:$(printf %s 'pw' | shasum -a 256 | cut -d' ' -f1)"

# …or mutual TLS, or both (§3.3.4 accepts either; a credential wins when both are sent)
./target/release/pqctoday-kmip --tls-profile quantum-safe --store-memory \
  --tls-cert admin-certs/server.crt --tls-key admin-certs/server.key \
  --tls-client-ca admin-certs/ca.crt
```

The startup log prints the groups and suites actually in force, so an operator
can see the posture without reading the source.

#### §3.3.3 — all three groups, as of 2026-08-12

§3.3.3 requires servers to support **all three** of `X25519MLKEM768`,
`SecP256r1MLKEM768` and `SecP384r1MLKEM1024`, and to offer nothing outside that
list. All three are now offered, and classical groups are absent entirely
rather than merely deprioritised.

`SecP384r1MLKEM1024` (IANA `0x11ed`) does not exist in rustls 0.23 — it has no
`NamedGroup` variant, no entry in `crypto::aws_lc_rs::kx_group`, and the generic
`Hybrid` combinator the other two are built from is private. It is therefore
composed here, in [`src/server/secp384r1mlkem1024.rs`](src/server/secp384r1mlkem1024.rs),
from the two halves rustls *does* export (`kx_group::SECP384R1`,
`kx_group::MLKEM1024`) through the public `hybrid_component()` seams. No new
cryptography — only the wiring rustls had not published.

**How it is proven.** A locally-composed hybrid that is self-consistent proves
nothing: reverse the combiner and both sides reverse it identically, agreeing
with each other and with no one else. So the gate is a handshake against an
implementation that did not come from this codebase — OpenSSL 3.6, which has
the group natively:

```bash
bash scripts/local-gate.sh --tls-interop
```

`tests/secp384r1mlkem1024_interop.rs` asserts the negotiated group **by name**
(so a fallback to the bare P-384 component cannot pass), requires application
data to actually flow, and includes a negative control proving a classical-only
client is refused. It was verified non-vacuous by deliberately reversing the
combiner: the interop test fails, as does the self round-trip.

> **Wording rule.** With all three groups offered and interop-proven, "§3.3
> conformant" is defensible for the server's TLS posture. Two caveats still
> attach to any broader claim: KMIP 3.0 itself is a **committee draft (CSD02)**,
> not a ratified standard, and no third-party KMIP client exists to interop the
> *protocol* against (see `docs/CONFORMANCE_REPORT.md` §5.3). Benchmarks
> comparing postures remain "measured against" language — that phrase was about
> measurement methodology, not this gap.

#### Proving a channel is quantum-safe from the client

The Python client cannot *pin* its key exchange group: `SSLContext.set_groups`
only exists from Python 3.13, and `set_ecdh_curve` rejects hybrid names. It
therefore proves the property by exclusion instead —
`KmipClient.assert_quantum_safe_channel()` opens a deliberately classical-only
TLS 1.3 connection and requires it to **fail**, so any connection that succeeds
must have used a hybrid group. It raises rather than certifying when the linked
OpenSSL is below 3.5 (no hybrid groups at all) or when the server accepts
classical key exchange.

---

## 5. Testing KMIP operations (Python client)

Install from source (no external deps):

```bash
cd python-client
pip install -e .        # or just: PYTHONPATH=src python -m pqctoday_kmip ...
```

### Data plane

```python
from pqctoday_kmip import KmipClient

c = KmipClient("127.0.0.1", 5696)          # sandbox: add verify=False / pin the fingerprint

# ML-DSA keygen + sign
kp   = c.create_key_pair("ML_DSA_44", "Sign Verify")
priv = kp.get("PrivateKeyUniqueIdentifier")
c.activate(priv)
sig  = c.sign(priv, b"hello", "ML_DSA_44")

# ML-KEM encapsulate / decapsulate
kem   = c.create_key_pair("ML_KEM_512", "KeyAgreement")
kpub  = kem.get("PublicKeyUniqueIdentifier")
kpriv = kem.get("PrivateKeyUniqueIdentifier")
c.activate(kpub); c.activate(kpriv)
enc = c.encapsulate(kpub)
ss  = c.decapsulate(kpriv, bytes.fromhex(enc.get("Data")))

# Symmetric + encrypt, then locate / inspect / revoke / destroy
aes = c.create_symmetric("AES", 256, name="demo-aes")
c.encrypt(aes.get("UniqueIdentifier"), b"plaintext", "AES")
c.locate(); c.get_attributes(priv); c.revoke(priv); c.destroy(priv)
```

Available `KmipClient` methods: `create_key_pair`, `create_symmetric`,
`activate`, `sign`, `encrypt`, `encapsulate`, `decapsulate`, `locate`,
`get_attributes`, `revoke`, `destroy`.

> **Register.** The server supports the KMIP `Register` operation, but the
> Python client does not expose a `register()` helper — generate keys server-side
> with `create_key_pair` / `create_symmetric`, or use the Rust
> `pqctoday-kmip-client` binary. (Tracked as a client gap.)

> **Hybrid KEM.** `X25519MLKEM768` / `SecP256r1MLKEM768` are exercised by the
> Rust end-to-end test `cargo test --test hybrid_kem_e2e` (they also back the
> admin-plane mTLS). A dedicated Python data-plane example is a known doc gap.

### Control plane (policy admin over mTLS)

```bash
# CLI form (needs the admin facade running, §4)
python -m pqctoday_kmip admin \
  --ca admin-certs/ca.crt --cert admin-certs/client.crt --key admin-certs/client.key \
  --host 127.0.0.1 --port 5697 list-policies
# admin subcommands: healthz, version, list-policies, get-policy NAME,
#                    create-policy, activate NAME, audit [--limit N], stream
```

### Three-plane audit trail

```bash
python -m pqctoday_kmip demo --audit-log /var/log/agile-audit.jsonl   # correlated p1/p2/p3 trail
python -m pqctoday_kmip audit /var/log/agile-audit.jsonl              # pretty-print an existing log
```

---

## 6. Conformance & interop testing

The `pqctoday-kmip-compliance` binary is a placeholder. Conformance is covered
by the Rust integration suite plus the OASIS replay harness:

```bash
# Full Rust integration suite (TLS e2e, hybrid KEM, OASIS codec, interop KATs,
# policy switch, store-backend parity, tri-plane audit, …)
cargo test --release

# Named highlights
cargo test --test oasis_codec_roundtrip -- --nocapture
cargo test --test hybrid_kem_e2e
cargo test --test tls_e2e

# OASIS KMIP 3.0 replay harness → conformance/REPLAY_REPORT.{json,md}
python conformance/harness/dispatcher_replay.py
python conformance/assert_replay_report.py     # gate the report
```

Reports and analysis live in [`docs/CONFORMANCE_REPORT.md`](docs/CONFORMANCE_REPORT.md)
and [`docs/PQC_INTEROP_TEST_PLAN.md`](docs/PQC_INTEROP_TEST_PLAN.md). The 10
intentionally-skipped OASIS tests (5 of them deprecated algorithms) are
explained in [`DEPRECATED.md`](DEPRECATED.md).

---

## 7. Map of this directory

| Path | What |
|---|---|
| `bin/pqctoday-kmip.rs` | The KMIP server |
| `bin/pqctoday-kmip-client.rs` | Rust smoke client |
| `src/kmip30/` | KMIP 3.0 wire codec + operations |
| `src/hybrid_kem.rs` | Hybrid KEM (X25519MLKEM768 / SecP256r1MLKEM768) |
| `src/policy/` | CACP policy engine (loader, evaluation) |
| `policies/*.yaml` | Shipped compliance policies — see [`policies/README.md`](policies/README.md) |
| `cryptopolicy-manager/` | REST admin facade — see [`cryptopolicy-manager/README.md`](cryptopolicy-manager/README.md) |
| `python-client/` | Stdlib-only test client + CLI — see [`python-client/README.md`](python-client/README.md) |
| `conformance/` | OASIS corpus + replay harness + reports |
| `kat/` | Known-answer-test vectors |
| `docs/` | Architecture, conformance, and interop plans |
| `DEPRECATED.md` | Deprecated-algorithm policy + OASIS skip rationale |
