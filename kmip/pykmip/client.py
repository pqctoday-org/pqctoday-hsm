"""A small KMIP 3.0 client for driving the agile `pqctoday-kmip` server.

Builds TTLV `RequestMessage`s, sends one per TLS connection (the server
speaks one request/response per connection per KMIP 3.0 §6), and decodes
the response. PQC-aware: ML-DSA / SLH-DSA sign, ML-KEM encapsulate /
decapsulate, plus the classical Create / Encrypt / Sign path.

This is the "format the KMIP calls" layer for the sandbox-dev integration.
It is policy-agnostic: it issues operations and reports what came back; the
agile layer's allow / deny / rekey decision is observed out-of-band in the
server's audit log (see `pykmip.audit`), not here.

Targets an already-running server (host/port). Self-signed TLS is accepted
without verification by default (`insecure=True`) — sandbox dev posture.
"""
from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from typing import Optional

from . import codec
from .codec import find, find_all, leaf, struct

# ── KMIP ResultStatus enum (decoded as integers by the codec) ───────────────
RESULT_SUCCESS = 0
RESULT_OP_FAILED = 1
RESULT_OP_PENDING = 2
RESULT_OP_UNDONE = 3


def _proto() -> codec.TtlvNode:
    return struct(
        "ProtocolVersion",
        leaf("ProtocolVersionMajor", "Integer", 3),
        leaf("ProtocolVersionMinor", "Integer", 0),
    )


@dataclass
class KmipResult:
    """Decoded outcome of one KMIP batch item."""

    operation: str
    status: int
    reason: Optional[int] = None
    message: Optional[str] = None
    payload: Optional[codec.TtlvNode] = None
    raw: Optional[codec.TtlvNode] = None

    @property
    def ok(self) -> bool:
        return self.status == RESULT_SUCCESS

    def get(self, tag: str):
        """First value under the ResponsePayload matching `tag` (or None)."""
        if self.payload is None:
            return None
        n = find(self.payload, tag)
        return n.value if n is not None else None

    def __str__(self) -> str:
        if self.ok:
            return f"{self.operation}: SUCCESS"
        extra = self.message or (f"reason={self.reason}" if self.reason is not None else "")
        return f"{self.operation}: FAILED ({extra})"


class KmipClient:
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 5696,
        *,
        timeout: float = 5.0,
        insecure: bool = True,
    ):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._ctx = ssl.create_default_context()
        if insecure:
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE

    # ── transport ───────────────────────────────────────────────────────────
    def _send(self, request: codec.TtlvNode) -> codec.TtlvNode:
        req_bytes = codec.encode_node(request)
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        sock = self._ctx.wrap_socket(raw, server_hostname=self.host)
        try:
            sock.sendall(req_bytes)
            sock.settimeout(self.timeout)
            chunks: list[bytes] = []
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        finally:
            sock.close()
        resp_bytes = b"".join(chunks)
        if not resp_bytes:
            raise ConnectionError("server returned 0 bytes (request rejected at TLS/parse layer)")
        node, _ = codec.decode_one(resp_bytes)
        return node

    def request(self, operation: str, *payload: codec.TtlvNode) -> KmipResult:
        """Send a single-batch-item request for `operation` and decode it."""
        msg = struct(
            "RequestMessage",
            struct("RequestHeader", _proto()),
            struct(
                "BatchItem",
                leaf("Operation", "Enumeration", operation),
                struct("RequestPayload", *payload),
            ),
        )
        resp = self._send(msg)
        batch = find(resp, "BatchItem")
        status_node = find(batch, "ResultStatus") if batch else None
        reason_node = find(batch, "ResultReason") if batch else None
        msg_node = find(batch, "ResultMessage") if batch else None
        payload_node = find(batch, "ResponsePayload") if batch else None
        status = int(status_node.value) if status_node and status_node.value is not None else -1
        return KmipResult(
            operation=operation,
            status=status,
            reason=int(reason_node.value) if reason_node and reason_node.value is not None else None,
            message=str(msg_node.value) if msg_node and msg_node.value is not None else None,
            payload=payload_node,
            raw=resp,
        )

    # ── operations ────────────────────────────────────────────────────────────
    def create_symmetric(
        self,
        algorithm: str = "AES",
        length: int = 256,
        name: Optional[str] = None,
        usage: str = "Encrypt Decrypt",
    ) -> KmipResult:
        attrs = [
            leaf("CryptographicAlgorithm", "Enumeration", algorithm),
            leaf("CryptographicLength", "Integer", length),
            leaf("CryptographicUsageMask", "Integer", usage),
        ]
        if name:
            attrs.append(leaf("Name", "TextString", name))
        return self.request(
            "Create",
            leaf("ObjectType", "Enumeration", "SymmetricKey"),
            struct("Attributes", *attrs),
        )

    def create_key_pair(self, algorithm: str, usage: str) -> KmipResult:
        """ML-DSA / ML-KEM / SLH-DSA / RSA / ECDSA keypair. `usage` is a
        space-separated CryptographicUsageMask (e.g. "Sign Verify" or
        "KeyAgreement"). Returns priv/pub UIDs via .get("PrivateKeyUniqueIdentifier")."""
        return self.request(
            "CreateKeyPair",
            struct(
                "CommonAttributes",
                leaf("CryptographicAlgorithm", "Enumeration", algorithm),
                leaf("CryptographicUsageMask", "Integer", usage),
            ),
        )

    def activate(self, uid: str) -> KmipResult:
        return self.request("Activate", leaf("UniqueIdentifier", "TextString", uid))

    def get(self, uid: str, key_format_type: Optional[str] = None) -> KmipResult:
        payload = [leaf("UniqueIdentifier", "TextString", uid)]
        if key_format_type:
            payload.append(leaf("KeyFormatType", "Enumeration", key_format_type))
        return self.request("Get", *payload)

    def encrypt(
        self,
        uid: str,
        data: bytes,
        *,
        block_cipher_mode: Optional[str] = None,
        iv: Optional[bytes] = None,
    ) -> KmipResult:
        cp_children = []
        if block_cipher_mode:
            cp_children.append(leaf("BlockCipherMode", "Enumeration", block_cipher_mode))
        payload = [
            leaf("UniqueIdentifier", "TextString", uid),
            struct("CryptographicParameters", *cp_children),
            leaf("Data", "ByteString", data.hex()),
        ]
        if iv is not None:
            payload.append(leaf("IVCounterNonce", "ByteString", iv.hex()))
        return self.request("Encrypt", *payload)

    def sign(self, uid: str, data: bytes, algorithm: str) -> KmipResult:
        return self.request(
            "Sign",
            leaf("UniqueIdentifier", "TextString", uid),
            struct(
                "CryptographicParameters",
                leaf("CryptographicAlgorithm", "Enumeration", algorithm),
            ),
            leaf("Data", "ByteString", data.hex()),
        )

    def encapsulate(self, uid: str) -> KmipResult:
        """ML-KEM encapsulate against a public key UID. Returns the shared-secret
        object UID (.get("UniqueIdentifier")) and ciphertext (.get("Data"))."""
        return self.request("Encapsulate", leaf("UniqueIdentifier", "TextString", uid))

    def decapsulate(self, uid: str, ciphertext: bytes) -> KmipResult:
        """ML-KEM decapsulate `ciphertext` against a private key UID."""
        return self.request(
            "Decapsulate",
            leaf("UniqueIdentifier", "TextString", uid),
            leaf("Data", "ByteString", ciphertext.hex()),
        )

    def destroy(self, uid: str) -> KmipResult:
        return self.request("Destroy", leaf("UniqueIdentifier", "TextString", uid))
