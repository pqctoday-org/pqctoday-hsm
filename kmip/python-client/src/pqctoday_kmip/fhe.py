"""FHE key custody over KMIP: interface ``PQCTODAY_FHE_1_0`` (plan D02387, WP-C).

One KMIP function is one PKCS#11 call (``kmip/docs/FHE_CUSTODY_INTERFACE.md``). This module builds the version 1 DER
inputs with a small stdlib-only encoder and calls them through :meth:`KmipClient.pkcs11`.

Example (CKKS custody, owner release)::

    from pqctoday_kmip import KmipClient
    from pqctoday_kmip.fhe import FheCustody, CKA_VALUE

    fhe = FheCustody(KmipClient("board", 5696, ...))
    seed = fhe.generate_key(param_set=3, replication_policy_id=rp, decrypt_policy_id=dp, label=b"bank seed")
    descriptor = fhe.export_public(seed, version=2, kind=FheCustody.CKKS_DESCRIPTOR)   # derive, read, destroy
    plain = fhe.decrypt_owner(seed, ciphertext)      # C_DecryptInit, C_Decrypt size query, C_Decrypt

Roles follow PKCS#11: functions 1-6 run as the token's normal user, like any other key operation over KMIP. The
security-officer functions (``admin_issue_nonce``, ``admin_execute``) need the token's SO client certificate
(``replication-admin``); the signed request itself is built by the security officer's own tooling.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .kmip import KmipClient

IFACE = "PQCTODAY_FHE_1_0"

FN_GENERATE_KEY = 1
FN_DERIVE_KEY = 2
FN_GET_ATTRIBUTE_VALUE = 3
FN_DESTROY_OBJECT = 4
FN_DECRYPT_INIT = 5
FN_DECRYPT = 6
FN_ADMIN_ISSUE_NONCE = 7
FN_ADMIN_EXECUTE = 8

CKR_OK = 0x00
CKR_ATTRIBUTE_SENSITIVE = 0x11
CKR_ATTRIBUTE_TYPE_INVALID = 0x12
OWNER = bytes(48)

CKA_VALUE = 0x011
CKA_DESTROYABLE = 0x172
CKA_PQCTODAY_FHE_PARAM_SET = 0x8000010D
CKA_PQCTODAY_FHE_PARAM_HASH = 0x8000010E
CKA_PQCTODAY_FHE_LINEAGE_ID = 0x80000110
CKA_PQCTODAY_FHE_DECRYPT_POLICY = 0x80000112


class FheError(RuntimeError):
    """A PKCS#11 return code other than CKR_OK from the FHE interface."""

    def __init__(self, function: int, rv: int):
        super().__init__(f"{IFACE} function {function}: CK_RV 0x{rv:08x}")
        self.function = function
        self.rv = rv


# ── minimal DER (definite lengths, the subset the interface uses) ──────────

def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _len(len(value)) + value


def _int(v: int) -> bytes:
    if v < 0:
        raise ValueError("negative INTEGER not used by this interface")
    b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big")
    return _tlv(0x02, b)


def _octets(b: bytes) -> bytes:
    return _tlv(0x04, bytes(b))


def _utf8(s: bytes) -> bytes:
    return _tlv(0x0C, bytes(s))


def _seq(*items: bytes) -> bytes:
    return _tlv(0x30, b"".join(items))


def _read(b: bytes, off: int) -> tuple[int, bytes, int]:
    tag = b[off]
    first = b[off + 1]
    off += 2
    if first < 0x80:
        n = first
    else:
        k = first & 0x7F
        n = int.from_bytes(b[off:off + k], "big")
        off += k
    if off + n > len(b):
        raise ValueError("DER: truncated")
    return tag, b[off:off + n], off + n


def _children(body: bytes) -> list[tuple[int, bytes]]:
    out, off = [], 0
    while off < len(body):
        t, v, off = _read(body, off)
        out.append((t, v))
    return out


def _uid(uid: bytes | str) -> bytes:
    u = uid.encode() if isinstance(uid, str) else bytes(uid)
    if len(u) != 36:
        raise ValueError("a unique ID is 36 bytes")
    return u


def generate_key_v1(param_set: int, replication_policy_id: bytes, decrypt_policy_id: bytes, label: bytes = b"", id: bytes = b"") -> bytes:
    if len(replication_policy_id) != 48 or len(decrypt_policy_id) != 48:
        raise ValueError("policy IDs are 48 bytes")
    return _seq(_int(param_set), _octets(replication_policy_id), _octets(decrypt_policy_id), _octets(label), _octets(id))


def derive_key_v1(base_key: bytes | str, version: int, kind: int, key: int = 0, digit: int = 0, from_limb: int = 0, to_limb: int = 0) -> bytes:
    return _seq(_utf8(_uid(base_key)), _int(version), _int(kind), _int(key), _int(digit), _int(from_limb), _int(to_limb))


def get_attribute_value_v1(obj: bytes | str, types: list[int]) -> bytes:
    if not 1 <= len(types) <= 16:
        raise ValueError("1 to 16 attribute types")
    return _seq(_utf8(_uid(obj)), _seq(*(_int(t) for t in types)))


def decrypt_init_v1(key: bytes | str, recipient: bytes = OWNER) -> bytes:
    if len(recipient) != 48:
        raise ValueError("a recipient ID is 48 bytes (48 zero bytes = owner release)")
    return _seq(_utf8(_uid(key)), _octets(recipient))


def decrypt_v1(ciphertext: bytes, output_len: int) -> bytes:
    return _seq(_octets(ciphertext), _int(output_len))


def parse_attributes_v1(der: bytes) -> dict[int, Optional[bytes]]:
    """``AttributesV1``: SEQUENCE OF SEQUENCE { type INTEGER, value OCTET STRING OPTIONAL } → {type: value or None}."""
    tag, body, end = _read(der, 0)
    if tag != 0x30 or end != len(der):
        raise ValueError("AttributesV1: not one SEQUENCE")
    out: dict[int, Optional[bytes]] = {}
    for t, entry in _children(body):
        if t != 0x30:
            raise ValueError("AttributesV1: entry is not a SEQUENCE")
        f = _children(entry)
        if not f or f[0][0] != 0x02 or len(f) > 2 or (len(f) == 2 and f[1][0] != 0x04):
            raise ValueError("AttributesV1: unexpected fields")
        out[int.from_bytes(f[0][1], "big")] = f[1][1] if len(f) == 2 else None
    return out


def parse_der_integer(der: bytes) -> int:
    tag, body, end = _read(der, 0)
    if tag != 0x02 or end != len(der):
        raise ValueError("not one INTEGER")
    return int.from_bytes(body, "big")


class FheCustody:
    """The eight functions of ``PQCTODAY_FHE_1_0`` on one KMIP client, plus the two usual sequences."""

    # CKM_PQCTODAY_FHE_DERIVE_PUBLIC kinds
    TFHE_COMPRESSED_SERVER_KEY = 1
    TFHE_COMPACT_PUBLIC_KEY = 2
    CKKS_DESCRIPTOR = 3
    CKKS_PUBLIC_KEY = 4
    CKKS_EVK_CHUNK = 5
    CKKS_MANIFEST = 6

    def __init__(self, client: KmipClient):
        self.client = client

    def _call(self, function: int, data: bytes = b"", ok: tuple[int, ...] = (CKR_OK,)) -> tuple[int, bytes]:
        rv, out = self.client.pkcs11(IFACE, function, data)
        if rv not in ok:
            raise FheError(function, rv)
        return rv, out

    # one PKCS#11 call each
    def generate_key(self, param_set: int, replication_policy_id: bytes, decrypt_policy_id: bytes, label: bytes = b"", id: bytes = b"") -> str:
        return self._call(FN_GENERATE_KEY, generate_key_v1(param_set, replication_policy_id, decrypt_policy_id, label, id))[1].decode()

    def derive_key(self, base_key: bytes | str, version: int, kind: int, key: int = 0, digit: int = 0, from_limb: int = 0, to_limb: int = 0) -> str:
        return self._call(FN_DERIVE_KEY, derive_key_v1(base_key, version, kind, key, digit, from_limb, to_limb))[1].decode()

    def get_attribute_value(self, obj: bytes | str, types: list[int]) -> tuple[int, dict[int, Optional[bytes]]]:
        """Returns (CK_RV, {type: value}); as in PKCS#11, a sensitive or unknown attribute comes back as None with
        CKR_ATTRIBUTE_SENSITIVE or CKR_ATTRIBUTE_TYPE_INVALID while the rest of the template is filled."""
        rv, out = self._call(FN_GET_ATTRIBUTE_VALUE, get_attribute_value_v1(obj, types), ok=(CKR_OK, CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID))
        return rv, parse_attributes_v1(out)

    def destroy_object(self, obj: bytes | str) -> None:
        self._call(FN_DESTROY_OBJECT, _uid(obj))

    def decrypt_init(self, key: bytes | str, recipient: bytes = OWNER) -> None:
        self._call(FN_DECRYPT_INIT, decrypt_init_v1(key, recipient))

    def decrypt_size(self, ciphertext: bytes) -> int:
        """``C_Decrypt`` with ``pData == NULL``: the output length; the operation stays active."""
        return parse_der_integer(self._call(FN_DECRYPT, decrypt_v1(ciphertext, 0))[1])

    def decrypt(self, ciphertext: bytes, output_len: int) -> bytes:
        return self._call(FN_DECRYPT, decrypt_v1(ciphertext, output_len))[1]

    def admin_issue_nonce(self) -> bytes:
        return self._call(FN_ADMIN_ISSUE_NONCE)[1]

    def admin_execute(self, signed_request_der: bytes) -> bytes:
        return self._call(FN_ADMIN_EXECUTE, signed_request_der)[1]

    # the usual sequences
    def export_public(self, seed: bytes | str, version: int, kind: int, key: int = 0, digit: int = 0, from_limb: int = 0, to_limb: int = 0) -> bytes:
        """C_DeriveKey → C_GetAttributeValue(CKA_VALUE) → C_DestroyObject."""
        obj = self.derive_key(seed, version, kind, key, digit, from_limb, to_limb)
        try:
            _, attrs = self.get_attribute_value(obj, [CKA_VALUE])
            value = attrs.get(CKA_VALUE)
            if value is None:
                raise FheError(FN_GET_ATTRIBUTE_VALUE, CKR_ATTRIBUTE_SENSITIVE)
            return value
        finally:
            self.destroy_object(obj)

    def decrypt_owner(self, seed: bytes | str, ciphertext: bytes, recipient: bytes = OWNER) -> bytes:
        """C_DecryptInit → C_Decrypt (size query) → C_Decrypt, single part."""
        self.decrypt_init(seed, recipient)
        n = self.decrypt_size(ciphertext)
        return self.decrypt(ciphertext, n)
