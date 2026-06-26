# pqctoday-kmip-client

Python client for the **pqctoday KMIP 3.0 PQC key management server** — data plane (TTLV over TLS) + control plane (REST over mTLS).

No external dependencies — uses Python stdlib only (`ssl`, `socket`, `http.client`).

## Install

```bash
pip install pqctoday-kmip-client
```

## Data plane — KMIP 3.0 operations

```python
from pqctoday_kmip import KmipClient

c = KmipClient("127.0.0.1", 5696)

# ML-DSA keygen + sign
kp = c.create_key_pair("ML_DSA_44", "Sign Verify")
priv = kp.get("PrivateKeyUniqueIdentifier")
c.activate(priv)
sig = c.sign(priv, b"hello", "ML_DSA_44")
print(sig.ok, sig.get("SignatureData"))

# ML-KEM encapsulate / decapsulate
kem = c.create_key_pair("ML_KEM_512", "KeyAgreement")
kpub = kem.get("PublicKeyUniqueIdentifier")
kpriv = kem.get("PrivateKeyUniqueIdentifier")
c.activate(kpub); c.activate(kpriv)
enc = c.encapsulate(kpub)
ct = enc.get("Data")
ss = c.decapsulate(kpriv, bytes.fromhex(ct))
```

## Control plane — policy management

```python
from pqctoday_kmip import AdminClient

a = AdminClient(
    host="127.0.0.1",
    port=5697,
    ca_cert="/admin-certs/ca.crt",
    client_cert="/admin-certs/client.crt",
    client_key="/admin-certs/client.key",
)

print(a.list_policies())        # ['aead-only', 'pqc', 'training-permissive', …]
print(a.get_active())           # {'name': 'training-permissive', 'fingerprint': '…'}
a.activate("pqc")               # live policy switch — zero downtime
a.validate(open("my.yaml").read())     # parse-check before activating
a.dry_run(open("my.yaml").read(), op="Sign", algorithm="AES")  # evaluate
```

## Audit trail

```python
from pqctoday_kmip import audit

# from the server's --audit-log file
print(audit.format_log("/var/log/agile-audit.jsonl"))
```

Output:
```
ALLOW  Sign            (a1b2c3d4)
    p1 policy : Allow
    p2 kmip   : Success
    p3 pkcs11 : native::sign [CKM_0x001D]

DENY   Encrypt         (e5f6a7b8)
    p1 policy : Deny  AES must use an authenticated mode (GCM or CCM)
    p2 kmip   : OperationFailed: PermissionDenied
    p3 pkcs11 : (no engine call)
```

## CLI

```bash
# Run the PQC demo against a running server
pqctoday-kmip demo --host 127.0.0.1 --port 5696 --audit-log /tmp/audit.jsonl

# Print a correlated audit trail
pqctoday-kmip audit /var/log/agile-audit.jsonl

# Admin commands (require mTLS certs)
pqctoday-kmip admin --ca ca.crt --cert client.crt --key client.key \
    --insecure list-policies
pqctoday-kmip admin --ca ca.crt --cert client.crt --key client.key \
    activate pqc
```

## Transport notes

- **Data plane** (port 5696): TLS 1.3, server's self-signed cert accepted by default (`insecure=True`).
- **Control plane** (port 5697): mTLS with ECDSA P-256 certs. Prefers X25519MLKEM768 KEM; falls back to X25519 for Python stdlib compatibility. Certs are minted at server first-boot via `--init-certs` and shared via Docker volume `/admin-certs/`.
