"""KMIP 3.0 TTLV byte codec — packaged version.

Adapted from the conformance harness ``oasis_codec.py``. The tag/enum
table is loaded from bundled package data (``pqctoday_kmip/data/``)
instead of a source-tree path. The XML transcript helpers are included
but not needed for the client.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

# Named bit-flag tables for Integer-typed mask fields.
CRYPTOGRAPHIC_USAGE_MASK: dict[str, int] = {
    "Sign":              0x00000001,
    "Verify":            0x00000002,
    "Encrypt":           0x00000004,
    "Decrypt":           0x00000008,
    "WrapKey":           0x00000010,
    "UnwrapKey":         0x00000020,
    "Export":            0x00000040,
    "MACGenerate":       0x00000080,
    "MACVerify":         0x00000100,
    "DeriveKey":         0x00000200,
    "ContentCommitment": 0x00000400,
    "KeyAgreement":      0x00000800,
    "CertificateSign":   0x00001000,
    "CRLSign":           0x00002000,
    "Authenticate":      0x00004000,
    "Unrestricted":      0x00008000,
    "FPEEncrypt":        0x00010000,
    "FPEDecrypt":        0x00020000,
    "Encapsulate":       0x00040000,
    "Decapsulate":       0x00080000,
}

PROTECTION_STORAGE_MASK: dict[str, int] = {
    "Software":          0x00000001,
    "Hardware":          0x00000002,
    "OnProcessor":       0x00000004,
    "OnSystem":          0x00000008,
    "OffSystem":         0x00000010,
    "Hypervisor":        0x00000020,
    "OperatingSystem":   0x00000040,
    "Container":         0x00000080,
    "OnPremises":        0x00000100,
    "OffPremises":       0x00000200,
    "SelfManaged":       0x00000400,
    "Outsourced":        0x00000800,
    "Validated":         0x00001000,
    "SameJurisdiction":  0x00002000,
}

NAMED_INTEGER_MASKS: dict[str, dict[str, int]] = {
    "CryptographicUsageMask": CRYPTOGRAPHIC_USAGE_MASK,
    "ProtectionStorageMask":  PROTECTION_STORAGE_MASK,
}

# TTLV type codepoints — KMIP 3.0 §9.1.1.
TTLV_TYPE: dict[str, int] = {
    "Structure":        0x01,
    "Integer":          0x02,
    "LongInteger":      0x03,
    "BigInteger":       0x04,
    "Enumeration":      0x05,
    "Boolean":          0x06,
    "TextString":       0x07,
    "ByteString":       0x08,
    "DateTime":         0x09,
    "Interval":         0x0A,
    "DateTimeExtended": 0x0B,
}

XML_TYPE_ALIASES: dict[str, str] = {
    "Identifier":     "TextString",
    "Reference":      "TextString",
    "NameReference":  "TextString",
}


def _norm(name: str) -> str:
    return "".join(c for c in name if c.isalnum())


@dataclass
class CodepointTable:
    """Two-way maps for tag names ↔ 3-byte codepoints and enum value lookups."""
    tag_name_to_code: dict[str, int] = field(default_factory=dict)
    tag_code_to_name: dict[int, str] = field(default_factory=dict)
    enum_name_to_value: dict[str, dict[str, int]] = field(default_factory=dict)

    @classmethod
    def load(cls, path=None) -> "CodepointTable":
        if path is None:
            import importlib.resources as _ir
            _ref = _ir.files("pqctoday_kmip").joinpath("data/kmip-spec-3.0-tags-enums.json")
            raw = json.loads(_ref.read_text(encoding="utf-8"))
        else:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
        t = cls()
        for entry in raw["tags"]:
            code = int(entry["codepoint"], 16)
            key = _norm(entry["name"])
            t.tag_name_to_code[key] = code
            t.tag_code_to_name[code] = entry["name"]
        for enum_name, members in raw["enums"].items():
            key = _norm(enum_name)
            inner: dict[str, int] = {}
            for m in members:
                inner[_norm(m["name"])] = int(m["value"], 16)
            t.enum_name_to_value[key] = inner

        for tag, additions in _SPEC_EXTRACT_PATCHES.items():
            t.enum_name_to_value.setdefault(tag, {}).update(additions)
        for name, code in _SPEC_EXTRACT_TAG_PATCHES.items():
            t.tag_name_to_code[name] = code
            t.tag_code_to_name.setdefault(code, name)
        return t


# WD19 PQC tags absent from the published-3.0 spec JSON.
_SPEC_EXTRACT_TAG_PATCHES: dict[str, int] = {
    "KEMAlgorithm":     0x42_01C3,
    "Deterministic":    0x42_01C4,
    "ContextString":    0x42_01C5,
    "Seed":             0x42_01C6,
    "InputKeyMaterial": 0x42_01C7,
    "Internal":         0x42_01C8,
    "ExternalMu":       0x42_01C9,
    "Random":           0x42_01CA,
}

_SPEC_EXTRACT_PATCHES: dict[str, dict[str, int]] = {
    "MaskGenerator": {"MGF1": 0x00000001},
    "KeyFormatType": {"SeedPrivateKey": 0x00000018},
    "CredentialType": {
        "UsernameAndPassword": 0x00000001,
        "Device":              0x00000002,
        "Attestation":         0x00000003,
        "OneTimePassword":     0x00000004,
        "HashedPassword":      0x00000005,
        "Ticket":              0x00000006,
    },
    "CryptographicAlgorithm": {
        "DES":  0x00000001,
        "DES3": 0x00000002,
        "RC4":  0x00000005,
    },
    "Operation": {
        "ReKey":        0x00000004,
        "ReKeyKeyPair": 0x0000001E,
        "ReCertify":    0x00000007,
        "Encapsulate":  0x00000041,
        "Decapsulate":  0x00000042,
    },
    "OpaqueDataType": {},
    "PKCS11Function": {
        "CInitialize":      0x00000001,
        "CFinalize":        0x00000002,
        "CGetInfo":         0x00000003,
        "CGetSlotList":     0x00000004,
        "CGetSlotInfo":     0x00000005,
        "CGetTokenInfo":    0x00000006,
        "COpenSession":     0x00000007,
        "CCloseSession":    0x00000008,
        "CLogin":           0x00000009,
        "CLogout":          0x0000000A,
    },
    "MaskGeneratorHashingAlgorithm": {
        "SHA1":   0x00000004,
        "SHA224": 0x00000005,
        "SHA256": 0x00000006,
        "SHA384": 0x00000007,
        "SHA512": 0x00000008,
    },
    "PKCS11ReturnCode": {
        "OK":                   0x00000000,
        "Cancel":               0x00000001,
        "HostMemory":           0x00000002,
        "FunctionFailed":       0x00000006,
        "ArgumentsBad":         0x00000007,
        "AttributeReadOnly":    0x00000010,
        "AttributeTypeInvalid": 0x00000012,
        "AttributeValueInvalid": 0x00000013,
    },
}

_TABLE: CodepointTable | None = None


def table() -> CodepointTable:
    global _TABLE
    if _TABLE is None:
        _TABLE = CodepointTable.load()
    return _TABLE


@dataclass
class TtlvNode:
    """An in-memory TTLV element: tag name + type + value (or children)."""
    tag_name: str
    ttlv_type: str
    value: Any = None
    children: list["TtlvNode"] = field(default_factory=list)

    @property
    def is_placeholder(self) -> bool:
        return isinstance(self.value, str) and self.value.startswith("$")


def parse_xml_element(elem: ET.Element) -> TtlvNode:
    tag = elem.tag
    ttlv_type = elem.attrib.get("type")
    if ttlv_type is None or ttlv_type == "Structure":
        node = TtlvNode(tag_name=tag, ttlv_type="Structure")
        for child in elem:
            node.children.append(parse_xml_element(child))
        return node
    value = elem.attrib.get("value")
    ttlv_type = XML_TYPE_ALIASES.get(ttlv_type, ttlv_type)
    return TtlvNode(tag_name=tag, ttlv_type=ttlv_type, value=value)


def parse_transcript_xml(path: Path) -> list[TtlvNode]:
    text = path.read_text()
    if "#" in text:
        text = "\n".join(
            ln for ln in text.splitlines() if not ln.lstrip().startswith("#")
        )
    if "<KMIP>" not in text:
        text = f"<KMIP>{text}</KMIP>"
    root = ET.fromstring(text)
    return [parse_xml_element(child) for child in root]


class EncodeError(Exception):
    pass


def _pad8(n: int) -> int:
    return (n + 7) & ~7


def _encode_value(node: TtlvNode) -> bytes:
    t = node.ttlv_type
    v = node.value

    if node.is_placeholder:
        raise EncodeError(
            f"unresolved placeholder {v!r} on {node.tag_name} — bind before encoding"
        )

    if t == "Integer":
        sv = str(v)
        mask = NAMED_INTEGER_MASKS.get(node.tag_name)
        if mask is not None and not sv.lstrip("-").isdigit() and not sv.startswith("0x"):
            acc = 0
            for flag in sv.split():
                if flag not in mask:
                    raise EncodeError(
                        f"unknown {node.tag_name} flag {flag!r}; known: {sorted(mask)[:6]}…"
                    )
                acc |= mask[flag]
            return struct.pack(">i", acc)
        return struct.pack(">i", int(sv, 0))
    if t == "LongInteger":
        return struct.pack(">q", int(str(v), 0))
    if t == "Enumeration":
        tag_norm = _norm(node.tag_name)
        if tag_norm == "AttributeReference":
            tag_code = table().tag_name_to_code.get(_norm(str(v)))
            if tag_code is None:
                raise EncodeError(f"AttributeReference: unknown tag name {v!r}")
            return struct.pack(">I", tag_code)
        sv = str(v)
        if sv.startswith("0x") or sv.lstrip("-").isdigit():
            return struct.pack(">I", int(sv, 0))
        enum_map = table().enum_name_to_value.get(tag_norm)
        if enum_map is None:
            raise EncodeError(f"no enum definition for tag {node.tag_name!r} (value {v!r})")
        key = _norm(sv)
        code = enum_map.get(key)
        if code is None:
            raise EncodeError(
                f"unknown enum member {v!r} for {node.tag_name!r}; "
                f"known: {sorted(enum_map.keys())[:6]}…"
            )
        return struct.pack(">I", code)
    if t == "Boolean":
        return struct.pack(">Q", 1 if str(v).lower() in ("true", "1") else 0)
    if t == "TextString":
        return str(v).encode("utf-8")
    if t == "ByteString":
        return bytes.fromhex(str(v))
    if t == "DateTime":
        sv = str(v)
        if sv.lstrip("-").isdigit():
            return struct.pack(">q", int(sv, 0))
        from datetime import datetime
        dt = datetime.fromisoformat(sv)
        return struct.pack(">q", int(dt.timestamp()))
    if t == "Interval":
        return struct.pack(">I", int(str(v), 0))
    if t == "BigInteger":
        sv = str(v)
        if all(c in "0123456789abcdefABCDEF" for c in sv) and len(sv) % 2 == 0:
            return bytes.fromhex(sv)
        n = int(sv, 0)
        byte_len = max(1, (n.bit_length() + 8) // 8)
        return n.to_bytes(byte_len, "big", signed=True)
    if t == "DateTimeExtended":
        return struct.pack(">q", int(str(v), 0))

    raise EncodeError(f"unsupported TTLV type {t!r} on {node.tag_name!r}")


def encode_node(node: TtlvNode) -> bytes:
    """Encode one TTLV node (tag + type + length + value + padding)."""
    tag = table().tag_name_to_code.get(_norm(node.tag_name))
    if tag is None:
        raise EncodeError(f"unknown tag name {node.tag_name!r}")
    type_byte = TTLV_TYPE[node.ttlv_type]

    if node.ttlv_type == "Structure":
        body = b"".join(encode_node(c) for c in node.children)
        body_len = len(body)
    else:
        body = _encode_value(node)
        body_len = len(body)
        pad = _pad8(body_len) - body_len
        body = body + b"\x00" * pad

    tag_bytes = struct.pack(">I", tag)[1:]
    header = tag_bytes + bytes([type_byte]) + struct.pack(">I", body_len)
    return header + body


class DecodeError(Exception):
    pass


def _ttlv_type_name(code: int) -> str:
    for name, c in TTLV_TYPE.items():
        if c == code:
            return name
    raise DecodeError(f"unknown TTLV type byte 0x{code:02x}")


def decode_one(buf: bytes, offset: int = 0) -> tuple[TtlvNode, int]:
    """Decode one TTLV element; return (node, next_offset)."""
    if offset + 8 > len(buf):
        raise DecodeError(f"truncated header at offset {offset}")
    tag = int.from_bytes(b"\x00" + buf[offset : offset + 3], "big")
    type_byte = buf[offset + 3]
    body_len = struct.unpack(">I", buf[offset + 4 : offset + 8])[0]
    padded_len = _pad8(body_len)
    body = buf[offset + 8 : offset + 8 + body_len]
    if len(body) != body_len:
        raise DecodeError(
            f"truncated body for tag 0x{tag:06x} at offset {offset}: "
            f"want {body_len} got {len(body)}"
        )
    type_name = _ttlv_type_name(type_byte)
    tag_name = table().tag_code_to_name.get(tag, f"Unknown(0x{tag:06x})")
    next_off = offset + 8 + padded_len

    if type_name == "Structure":
        children: list[TtlvNode] = []
        inner = offset + 8
        end = offset + 8 + body_len
        while inner < end:
            child, inner = decode_one(buf, inner)
            children.append(child)
        return TtlvNode(tag_name=tag_name, ttlv_type="Structure", children=children), next_off

    if type_name == "Integer":
        value = struct.unpack(">i", body)[0]
    elif type_name == "LongInteger":
        value = struct.unpack(">q", body)[0]
    elif type_name == "Enumeration":
        value = struct.unpack(">I", body)[0]
    elif type_name == "Boolean":
        value = bool(struct.unpack(">Q", body)[0])
    elif type_name == "TextString":
        value = body.decode("utf-8")
    elif type_name == "ByteString":
        value = body.hex()
    elif type_name in ("DateTime", "DateTimeExtended"):
        value = struct.unpack(">q", body)[0]
    elif type_name == "Interval":
        value = struct.unpack(">I", body)[0]
    elif type_name == "BigInteger":
        value = int.from_bytes(body, "big", signed=True)
    else:
        value = body.hex()

    return TtlvNode(tag_name=tag_name, ttlv_type=type_name, value=value), next_off
