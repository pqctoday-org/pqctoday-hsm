# pykmip — sandbox-dev integration client for the agile KMIP server

A small Python toolkit to **drive** the `pqctoday-kmip` server with real
crypto operations and **observe** how the crypto-agility layer governs them,
by reading the server's three-plane audit log.

It is the "format the KMIP calls + check the KMIP/PKCS#11 logs" layer for the
first sandbox-dev integration. It targets an **already-running** server and
is **policy-agnostic**: it issues operations and reports the results; *which*
policy is in force is configured on the server and observed in the audit log,
never managed from here (separation of duties).

## Pieces

| Module | What |
|--------|------|
| `pykmip.client.KmipClient` | Build + send KMIP calls over TLS (Create, CreateKeyPair, Encrypt, Sign, Encapsulate, Decapsulate, Get, Activate, Destroy). PQC-aware. Reuses the conformance harness's TTLV codec (knows the KMIP 3.0 WD19 PQC tags). |
| `pykmip.audit` | Correlate the server's `--audit-log` JSONL by `correlation_id` into per-request **p1 policy / p2 KMIP / p3 PKCS#11** trails. |
| `pykmip.demo` | Runs a PQC happy-path + an Encrypt allow-vs-deny contrast, then prints the correlated trail. |

## 1. Start the server (with audit log + a policy)

```bash
cd kmip
cargo build --release --bin pqctoday-kmip
./target/release/pqctoday-kmip \
    --listen 127.0.0.1:5696 --store-memory \
    --policy-dir policies --policy aead-only \
    --audit-log /tmp/agility-audit.jsonl
```

`--policy aead-only` makes the contrast visible: AES Encrypt must use an
authenticated mode. Swap in any policy from [`../policies/`](../policies/)
(`training-permissive`, `fips-hashing`, `pqc`, …) and re-run — the **same**
client code produces different p1 decisions. That is the agility story.

## 2. Drive it + read the trail

```bash
cd kmip
python3 -m pykmip.demo --audit-log /tmp/agility-audit.jsonl
```

Example output (under `aead-only`):

```
ALLOW  Sign            p1 policy : Allow
                       p2 kmip   : Success
                       p3 pkcs11 : native::sign [CKM_0x001D]

ALLOW  Encrypt         p1 policy : Allow
                       p2 kmip   : Success
                       p3 pkcs11 : native::encrypt [CKM_0x1087]      ← AES-GCM ran

DENY   Encrypt         p1 policy : Deny  AES must use an authenticated mode (GCM or CCM)
                       p2 kmip   : OperationFailed: PermissionDenied
                       p3 pkcs11 : (no engine call)                  ← AES-CBC stopped before the engine
```

The **absence** of a p3 line on the DENY proves the policy stopped the
request at Plane 1, before any key material was touched.

## 3. Use the client directly

```python
from pykmip import KmipClient, audit

c = KmipClient("127.0.0.1", 5696)
kp = c.create_key_pair("ML_DSA_44", "Sign Verify")
priv = kp.get("PrivateKeyUniqueIdentifier")
c.activate(priv)
sig = c.sign(priv, b"hello", "ML_DSA_44")
print(sig.ok, sig.get("SignatureData"))

# inspect the three-plane trail the server logged
print(audit.format_log("/tmp/agility-audit.jsonl"))
```

## Notes / known findings

- The client accepts the server's self-signed TLS cert without verification
  (`insecure=True`) — sandbox dev posture. Pass real CA trust for production.
- This integration surfaced two server-side findings in the WD19 ML-KEM ops
  (Encapsulate/Decapsulate): handle resolution is not PKCS#11-class-aware
  (breaks on `CreateKeyPair`-generated keys that share a CKA_ID), and the ops
  are not yet routed through the Plane-1 policy engine. Tracked separately.
