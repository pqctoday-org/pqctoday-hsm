"""KMIP 3.0 data-plane client for the pqctoday-kmip server.

Builds TTLV RequestMessages, sends one per TLS connection (the server speaks
one request/response per connection per KMIP 3.0 §6), and decodes the response.
PQC-aware: ML-DSA / SLH-DSA sign, ML-KEM encapsulate / decapsulate, plus the
classical Create / Encrypt / Sign path.

Policy-agnostic: this layer drives operations and reports results.  The
crypto-agility layer's allow / deny / rekey decision is observed out-of-band
in the server's audit log (see `pqctoday_kmip.audit`), not here.
"""
from __future__ import annotations

import socket
import ssl
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from . import _ttlv

# ── KMIP ResultStatus enum (decoded as integers by the codec) ───────────────
RESULT_SUCCESS = 0
RESULT_OP_FAILED = 1
RESULT_OP_PENDING = 2
RESULT_OP_UNDONE = 3


# ── TTLV construction helpers ────────────────────────────────────────────────

def _struct(tag: str, *children: _ttlv.TtlvNode) -> _ttlv.TtlvNode:
    return _ttlv.TtlvNode(tag_name=tag, ttlv_type="Structure", children=list(children))


def _leaf(tag: str, ttlv_type: str, value) -> _ttlv.TtlvNode:
    return _ttlv.TtlvNode(tag_name=tag, ttlv_type=ttlv_type, value=value)


def _find(node: _ttlv.TtlvNode, tag: str) -> Optional[_ttlv.TtlvNode]:
    want = "".join(c for c in tag if c.isalnum())
    dq = deque([node])
    while dq:
        n = dq.popleft()
        if "".join(c for c in n.tag_name if c.isalnum()) == want:
            return n
        dq.extend(n.children)
    return None


def _proto() -> _ttlv.TtlvNode:
    return _struct(
        "ProtocolVersion",
        _leaf("ProtocolVersionMajor", "Integer", 3),
        _leaf("ProtocolVersionMinor", "Integer", 0),
    )


# ── result type ─────────────────────────────────────────────────────────────

@dataclass
class KmipResult:
    """Decoded outcome of one KMIP batch item."""
    operation: str
    status: int
    reason: Optional[int] = None
    message: Optional[str] = None
    payload: Optional[_ttlv.TtlvNode] = None
    raw: Optional[_ttlv.TtlvNode] = None

    @property
    def ok(self) -> bool:
        return self.status == RESULT_SUCCESS

    def get(self, tag: str):
        """First value under ResponsePayload matching ``tag`` (or None)."""
        if self.payload is None:
            return None
        n = _find(self.payload, tag)
        return n.value if n is not None else None

    def __str__(self) -> str:
        if self.ok:
            return f"{self.operation}: SUCCESS"
        extra = self.message or (f"reason={self.reason}" if self.reason is not None else "")
        return f"{self.operation}: FAILED ({extra})"


# ── client ───────────────────────────────────────────────────────────────────

class KmipClient:
    """KMIP 3.0 data-plane client over TLS.

    By default accepts the server's self-signed cert (``insecure=True``) —
    sandbox dev posture. Pass ``insecure=False`` + ``ca_cert`` for production.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 5696,
        *,
        timeout: float = 5.0,
        insecure: bool = True,
        ca_cert: Optional[str] = None,
    ):
        self.host = host
        self.port = port
        self.timeout = timeout
        if insecure:
            self._ctx = ssl.create_default_context()
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE
        else:
            self._ctx = ssl.create_default_context(
                ssl.Purpose.SERVER_AUTH,
                cafile=ca_cert,
            )

    # ── transport ───────────────────────────────────────────────────────────

    def _send(self, request: _ttlv.TtlvNode) -> _ttlv.TtlvNode:
        req_bytes = _ttlv.encode_node(request)
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
            raise ConnectionError("server returned 0 bytes")
        node, _ = _ttlv.decode_one(resp_bytes)
        return node

    def request(self, operation: str, *payload: _ttlv.TtlvNode) -> KmipResult:
        """Send a single-batch-item request for ``operation`` and decode it."""
        msg = _struct(
            "RequestMessage",
            _struct("RequestHeader", _proto()),
            _struct(
                "BatchItem",
                _leaf("Operation", "Enumeration", operation),
                _struct("RequestPayload", *payload),
            ),
        )
        resp = self._send(msg)
        batch = _find(resp, "BatchItem")
        status_node = _find(batch, "ResultStatus") if batch else None
        reason_node = _find(batch, "ResultReason") if batch else None
        msg_node = _find(batch, "ResultMessage") if batch else None
        payload_node = _find(batch, "ResponsePayload") if batch else None
        status = int(status_node.value) if status_node and status_node.value is not None else -1
        return KmipResult(
            operation=operation,
            status=status,
            reason=int(reason_node.value) if reason_node and reason_node.value is not None else None,
            message=str(msg_node.value) if msg_node and msg_node.value is not None else None,
            payload=payload_node,
            raw=resp,
        )

    # ── operations ───────────────────────────────────────────────────────────

    def create_symmetric(
        self,
        algorithm: str = "AES",
        length: int = 256,
        name: Optional[str] = None,
        usage: str = "Encrypt Decrypt",
    ) -> KmipResult:
        attrs = [
            _leaf("CryptographicAlgorithm", "Enumeration", algorithm),
            _leaf("CryptographicLength", "Integer", length),
            _leaf("CryptographicUsageMask", "Integer", usage),
        ]
        if name:
            attrs.append(_leaf("Name", "TextString", name))
        return self.request(
            "Create",
            _leaf("ObjectType", "Enumeration", "SymmetricKey"),
            _struct("Attributes", *attrs),
        )

    def create_key_pair(self, algorithm: str, usage: str) -> KmipResult:
        """ML-DSA / ML-KEM / SLH-DSA / RSA / ECDSA keypair.

        ``usage`` is space-separated CryptographicUsageMask flags,
        e.g. ``"Sign Verify"`` or ``"KeyAgreement"``.  Returns priv/pub UIDs
        via ``.get("PrivateKeyUniqueIdentifier")`` / ``.get("PublicKeyUniqueIdentifier")``.
        """
        return self.request(
            "CreateKeyPair",
            _struct(
                "CommonAttributes",
                _leaf("CryptographicAlgorithm", "Enumeration", algorithm),
                _leaf("CryptographicUsageMask", "Integer", usage),
            ),
        )

    def activate(self, uid: str) -> KmipResult:
        return self.request("Activate", _leaf("UniqueIdentifier", "TextString", uid))

    def get(self, uid: str, key_format_type: Optional[str] = None) -> KmipResult:
        payload = [_leaf("UniqueIdentifier", "TextString", uid)]
        if key_format_type:
            payload.append(_leaf("KeyFormatType", "Enumeration", key_format_type))
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
            cp_children.append(_leaf("BlockCipherMode", "Enumeration", block_cipher_mode))
        payload = [
            _leaf("UniqueIdentifier", "TextString", uid),
            _struct("CryptographicParameters", *cp_children),
            _leaf("Data", "ByteString", data.hex()),
        ]
        if iv is not None:
            payload.append(_leaf("IVCounterNonce", "ByteString", iv.hex()))
        return self.request("Encrypt", *payload)

    def sign(self, uid: str, data: bytes, algorithm: str) -> KmipResult:
        return self.request(
            "Sign",
            _leaf("UniqueIdentifier", "TextString", uid),
            _struct(
                "CryptographicParameters",
                _leaf("CryptographicAlgorithm", "Enumeration", algorithm),
            ),
            _leaf("Data", "ByteString", data.hex()),
        )

    def encapsulate(self, uid: str) -> KmipResult:
        """ML-KEM encapsulate against a public key UID."""
        return self.request("Encapsulate", _leaf("UniqueIdentifier", "TextString", uid))

    def decapsulate(self, uid: str, ciphertext: bytes) -> KmipResult:
        """ML-KEM decapsulate ``ciphertext`` against a private key UID."""
        return self.request(
            "Decapsulate",
            _leaf("UniqueIdentifier", "TextString", uid),
            _leaf("Data", "ByteString", ciphertext.hex()),
        )

    def destroy(self, uid: str) -> KmipResult:
        return self.request("Destroy", _leaf("UniqueIdentifier", "TextString", uid))

    def revoke(self, uid: str, reason: str = "Unspecified") -> KmipResult:
        return self.request(
            "Revoke",
            _leaf("UniqueIdentifier", "TextString", uid),
            _struct("RevocationReason",
                    _leaf("RevocationReasonCode", "Enumeration", reason)),
        )

    def locate(self) -> KmipResult:
        """KMIP Locate — returns all managed-object UIDs visible to this session."""
        return self.request("Locate")

    def get_attributes(self, uid: str) -> KmipResult:
        """KMIP GetAttributes for a single UID."""
        return self.request("GetAttributes", _leaf("UniqueIdentifier", "TextString", uid))
