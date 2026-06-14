"""pykmip — a small Python KMIP 3.0 client for the agile pqctoday-kmip server.

Sandbox-dev integration toolkit:

  * `KmipClient` — format + send KMIP calls (Create / CreateKeyPair / Encrypt /
    Sign / Encapsulate / Decapsulate / Get / Activate / Destroy), PQC-aware.
  * `pykmip.audit` — correlate the server's `--audit-log` JSONL into per-request
    three-plane trails (p1 policy / p2 KMIP / p3 PKCS#11).

The client is policy-agnostic: it drives operations; *which* crypto policy is
in force is configured on the server (`--policy <name>`) and observed in the
audit log, never managed from here (separation of duties).
"""
from .client import KmipClient, KmipResult, RESULT_SUCCESS, RESULT_OP_FAILED
from . import audit

__all__ = ["KmipClient", "KmipResult", "RESULT_SUCCESS", "RESULT_OP_FAILED", "audit"]
