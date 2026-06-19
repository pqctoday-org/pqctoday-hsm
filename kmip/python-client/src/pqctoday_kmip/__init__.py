"""pqctoday-kmip-client — Python client for the pqctoday KMIP 3.0 PQC server.

Data plane (TTLV over TLS)::

    from pqctoday_kmip import KmipClient
    c = KmipClient("127.0.0.1", 5696)
    kp = c.create_key_pair("ML_DSA_44", "Sign Verify")
    priv = kp.get("PrivateKeyUniqueIdentifier")
    c.activate(priv)
    sig = c.sign(priv, b"hello", "ML_DSA_44")

Control plane (REST over mTLS)::

    from pqctoday_kmip import AdminClient
    a = AdminClient(
        host="127.0.0.1", port=5697,
        ca_cert="/admin-certs/ca.crt",
        client_cert="/admin-certs/client.crt",
        client_key="/admin-certs/client.key",
    )
    a.activate("pqc")

Audit log correlation::

    from pqctoday_kmip import audit
    print(audit.format_log("/var/log/agile-audit.jsonl"))
"""
from .kmip import KmipClient, KmipResult, RESULT_SUCCESS, RESULT_OP_FAILED
from .admin import AdminClient, AdminError
from . import audit

__all__ = [
    "KmipClient",
    "KmipResult",
    "RESULT_SUCCESS",
    "RESULT_OP_FAILED",
    "AdminClient",
    "AdminError",
    "audit",
]
