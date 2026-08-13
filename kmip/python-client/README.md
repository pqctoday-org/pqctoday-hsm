# pqctoday-kmip-client

Python client for the **pqctoday KMIP 3.0 PQC key management server** — data plane (TTLV over TLS) + control plane (REST over mTLS).

No external dependencies — uses Python stdlib only (`ssl`, `socket`, `http.client`).

## Install

Stdlib-only — no dependencies. Install from source (the package is not yet
published to PyPI):

```bash
cd kmip/python-client
pip install -e .
# or, without installing:
PYTHONPATH=src python -m pqctoday_kmip demo
```

## Data plane — KMIP 3.0 operations

```python
import os

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

# Hybrid KEM — one managed object, not two keys stapled together
#
# X25519MLKEM768 (0x5C) and SecP256r1MLKEM768 (0x5D) are first-class
# CryptographicAlgorithm values in KMIP 3.0 CSD02, so a hybrid is created
# and used through exactly the same three calls as ML-KEM above. The
# classical and post-quantum halves are combined inside the engine; the
# shared secret a peer recovers is the concatenation of both, so it stays
# secure if EITHER primitive survives.
hyb   = c.create_key_pair("X25519MLKEM768", "KeyAgreement")
hpub  = hyb.get("PublicKeyUniqueIdentifier")
hpriv = hyb.get("PrivateKeyUniqueIdentifier")
c.activate(hpub); c.activate(hpriv)

enc = c.encapsulate(hpub)                       # ct = ek_mlkem ‖ x25519 share
ss  = c.decapsulate(hpriv, bytes.fromhex(enc.get("Data")))
# Both sides now hold the same secret; enc.get("UniqueIdentifier") and
# ss.get("UniqueIdentifier") are managed SecretData objects, so the raw
# bytes never have to leave the HSM at all.

# Register — adopt a key you already hold, rather than minting a new one
#
# The import half of key management: use it to migrate material out of
# another KMS, or to pin a known test vector. The UID behaves like any
# other managed object afterwards.
imported = c.register(bytes(32), algorithm="AES", name="migrated-from-old-kms")
uid = imported.get("UniqueIdentifier")
c.activate(uid)
# The algorithm comes from the stored key, not the call. An IV is required —
# and must never repeat for a given key.
c.encrypt(uid, b"plaintext", block_cipher_mode="GCM", iv=os.urandom(12))
```

## Receiving server pushes (KMIP §6.2)

The server can push `Notify` (§6.2.2) messages describing attribute changes. It
never dials out: a client offers its own connection by handing over the server
role (§6.1.61 — "the server assumes the client role … but the communication
channel remains as established"), then reads what arrives on that same socket
and acknowledges each message.

```python
c = KmipClient("127.0.0.1", 5696, username="alice", password="pw")

# Blocks on one connection, returns what the server pushed.
for msg in c.serve_as_endpoint():
    print(msg["operation"], msg["uid"], msg["attributes"])
    # -> Notify urn:pqctoday:obj:… ['Last Change Date']

# …or react as each arrives, rather than collecting:
c.serve_as_endpoint(on_message=lambda m: print("changed:", m["uid"]))
```

Notes worth knowing before relying on it:

- **Credentials or mTLS are required.** An anonymous caller is refused the role
  switch — notifications name real managed objects, and there is no identity to
  scope them to otherwise.
- **Delivery consumes the queue.** A second call returns only what has changed
  since; nothing is re-delivered.
- **Notifications are per identity.** You are told about your own objects.
- **It returns promptly when nothing is queued**, so it is safe to poll.

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
