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
        username: Optional[str] = None,
        password: Optional[str] = None,
    ):
        self.host = host
        self.port = port
        self.timeout = timeout
        # KMIP 3.0 §8.1.2 Authentication credentials. Without these the
        # client can only talk to a server in open-auth mode; any server
        # started with --auth-user answers every operation with
        # "authentication not successful". Send the password in the CLEAR
        # here (inside TLS) — the server hashes it and compares against the
        # SHA-256 it was configured with, so pre-hashing on this side would
        # authenticate the hash of a hash and always fail.
        self.username = username
        self.password = password
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

    def _auth_nodes(self) -> list[_ttlv.TtlvNode]:
        """The §8.1.2 `Authentication` structure, or nothing when no
        credentials are configured.

        Shape per §9.4 Table 504 / §9.9 Table 509-510, which is also exactly
        what the server's `decode_credential` walks:

            Authentication              (0x42000C, Structure)
              Credential                (0x420023, Structure)
                CredentialType          (0x420024, Enumeration = 1)
                CredentialValue         (0x420025, Structure)
                  Username              (0x420099, TextString)
                  Password              (0x4200A1, TextString)

        Omitted entirely when unset rather than sent empty: an empty
        Authentication is not the same as no Authentication, and a
        password-less credential is rejected by the verifier anyway.
        """
        if self.username is None or self.password is None:
            return []
        return [
            _struct(
                "Authentication",
                _struct(
                    "Credential",
                    _leaf("CredentialType", "Enumeration", "UsernameAndPassword"),
                    _struct(
                        "CredentialValue",
                        _leaf("Username", "TextString", self.username),
                        _leaf("Password", "TextString", self.password),
                    ),
                ),
            )
        ]

    def request(self, operation: str, *payload: _ttlv.TtlvNode) -> KmipResult:
        """Send a single-batch-item request for ``operation`` and decode it."""
        msg = _struct(
            "RequestMessage",
            _struct("RequestHeader", _proto(), *self._auth_nodes()),
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

    def get_usage_allocation(self, uid: str, usage_limits_count: Optional[int] = None) -> KmipResult:
        """KMIP GetUsageAllocation (§6.1.29) — grants a usage allocation by
        decrementing the object's tracked Usage Limits Count."""
        payload = [_leaf("UniqueIdentifier", "TextString", uid)]
        if usage_limits_count is not None:
            payload.append(_leaf("UsageLimitsCount", "LongInteger", usage_limits_count))
        return self.request("GetUsageAllocation", *payload)

    def get_constraints(self) -> KmipResult:
        """KMIP GetConstraints (§6.1.28) — the engine-backed cryptographic
        constraint table (minimum key lengths, allowed algorithms, …). Takes
        no request fields."""
        return self.request("GetConstraints")

    def set_endpoint_role(self, role: str = "Server") -> KmipResult:
        """KMIP SetEndpointRole (§6.1.61). Only ``role="Server"`` is
        acknowledged (the server keeps the role it already has);
        ``role="Client"`` is rejected with FeatureNotSupported."""
        return self.request("SetEndpointRole", _leaf("EndpointRole", "Enumeration", role))

    def set_defaults(self, object_type: str, name: Optional[str] = None) -> KmipResult:
        """KMIP SetDefaults (§6.1.60) — register a default Name new objects
        of ``object_type`` inherit at Create/CreateKeyPair time when the
        request doesn't supply its own. Matches the tested shape in
        ``op_coverage_e2e.rs``'s ``sd-set`` case (arbitrary attribute
        coverage beyond Name isn't exposed here yet)."""
        attrs = [_leaf("Name", "TextString", name)] if name else []
        return self.request(
            "SetDefaults",
            _struct(
                "DefaultsInformation",
                _struct(
                    "ObjectDefaults",
                    _leaf("ObjectType", "Enumeration", object_type),
                    _struct("Attributes", *attrs),
                ),
            ),
        )

    def derive_key(
        self,
        base_uid: str,
        *,
        derivation_data: bytes,
        object_type: str = "SymmetricKey",
        method: str = "NIST800-108-C",
        algorithm: str = "AES",
        length: int = 256,
        usage: str = "Encrypt Decrypt",
    ) -> KmipResult:
        """KMIP DeriveKey (§6.1.19) — derive a new key from ``base_uid``.
        Defaults match the tested NIST SP 800-108 Counter-Mode case in
        ``op_coverage_e2e.rs``'s ``dk-derive``. Returns the new object's UID
        via ``.get("UniqueIdentifier")``."""
        return self.request(
            "DeriveKey",
            _leaf("ObjectType", "Enumeration", object_type),
            _leaf("UniqueIdentifier", "TextString", base_uid),
            _leaf("DerivationMethod", "Enumeration", method),
            _struct(
                "DerivationParameters",
                _leaf("DerivationData", "ByteString", derivation_data.hex()),
            ),
            _struct(
                "Attributes",
                _leaf("CryptographicAlgorithm", "Enumeration", algorithm),
                _leaf("CryptographicLength", "Integer", length),
                _leaf("CryptographicUsageMask", "Integer", usage),
            ),
        )

    def rekey(self, uid: str, *, offset: Optional[int] = None) -> KmipResult:
        """KMIP Re-key (§6.1.53) — mint a replacement object for ``uid``,
        inheriting its algorithm; the original is linked via
        ``ReplacedObjectLink``. Returns the new UID via
        ``.get("UniqueIdentifier")``."""
        payload = [_leaf("UniqueIdentifier", "TextString", uid)]
        if offset is not None:
            payload.append(_leaf("Offset", "Interval", offset))
        return self.request("ReKey", *payload)

    def rekey_key_pair(self, uid: str, *, offset: Optional[int] = None) -> KmipResult:
        """KMIP Re-key Key Pair (§6.1.54) — mint a replacement key pair for
        the private key ``uid``. Returns the new private/public UIDs via
        ``.get("PrivateKeyUniqueIdentifier")`` / ``.get("PublicKeyUniqueIdentifier")``."""
        payload = [_leaf("UniqueIdentifier", "TextString", uid)]
        if offset is not None:
            payload.append(_leaf("Offset", "Interval", offset))
        return self.request("ReKeyKeyPair", *payload)
