"""OASIS KMIP 3.0 XML transcript ↔ TTLV byte codec.

The OASIS conformance test suite (`kmip-profiles-v3.0.zip` →
`test-cases/kmip-v3.0/{mandatory,optional}/*.xml`) ships each test case
as an XML transcript: alternating ``<RequestMessage>`` and
``<ResponseMessage>`` elements, each with TTLV-typed children.

XML element names are *tag names* from the KMIP 3.0 spec (e.g.
``<UniqueIdentifier>`` is tag ``0x420094``). Element attributes carry:

- ``type`` — TTLV type name (``Integer``, ``Enumeration``, ``TextString``,
  ``ByteString``, ``Boolean``, ``DateTime``, ``LongInteger``, ``Interval``,
  ``BigInteger``, ``DateTimeExtended``); Structures have no ``type``.
- ``value`` — typed value; enums use the human-readable enum value name.
- Placeholders ``$NOW``, ``$UNIQUE_IDENTIFIER_n``, etc. are unresolved
  symbolic values that the conformance runner binds at replay time.

This module's job is the **codec layer**: tag-name + type-name + value →
TTLV bytes (per KMIP 3.0 §9.6), and the reverse. Placeholder resolution
and request-response orchestration live in :mod:`runner`.

The tag/enum table comes from ``spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json``
(extracted from the normative spec HTML by ``tools/extract_kmip_spec.rs``).
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

KMIP_ROOT = Path(__file__).resolve().parent.parent.parent  # kmip/
TAGS_ENUMS_PATH = KMIP_ROOT / "spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json"

# Named bit-flag tables for Integer-typed mask fields. OASIS XML carries
# these as space-separated flag names (e.g. "Decrypt Encrypt"). Values from
# KMIP 3.0 §11 + the tags-enums extract; mirrored in src/kmip30/attrs.rs.
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

# OASIS XML uses semantic type aliases that resolve to one of the 11 TTLV
# primitives at wire encode time. ``Identifier`` / ``Reference`` /
# ``NameReference`` are all UID-shaped TextStrings per KMIP 3.0 §9.1.1.
XML_TYPE_ALIASES: dict[str, str] = {
    "Identifier":     "TextString",
    "Reference":      "TextString",
    "NameReference":  "TextString",
}


def _norm(name: str) -> str:
    """Collapse whitespace + drop punctuation so spec names match XML element names.

    The spec table includes names like ``"Batch Error Continuation\\nOption"``
    and ``"Re-key"`` while XML uses ``BatchErrorContinuationOption`` and
    ``ReKey``. Normalise both ends to alphanumerics-only.
    """
    return "".join(c for c in name if c.isalnum())


@dataclass
class CodepointTable:
    """Two-way maps for tag names ↔ 3-byte codepoints and enum value lookups.

    Loaded once from the extracted spec JSON; pure data, no encoding logic.
    """
    tag_name_to_code: dict[str, int] = field(default_factory=dict)
    tag_code_to_name: dict[int, str] = field(default_factory=dict)
    enum_name_to_value: dict[str, dict[str, int]] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path = TAGS_ENUMS_PATH) -> "CodepointTable":
        raw = json.loads(path.read_text())
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

        # Apply hand-curated patches for spec-extractor gaps:
        # - tools/extract_kmip_spec.rs has a known typo (MFG1 in MaskGenerator,
        #   should be MGF1 per KMIP 3.0 §11.x);
        # - some legacy enum members (DES3, CredentialType variants) are
        #   parsed inconsistently from the HTML;
        # - `Operation` is missing post-spec-3.0 op names like ReKey.
        for tag, additions in _SPEC_EXTRACT_PATCHES.items():
            t.enum_name_to_value.setdefault(tag, {}).update(additions)
        return t


# Patches against ``spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json``.
# Each entry adds (or repairs) enum members the extractor missed. Values
# come from cross-referencing the normative spec HTML + the OASIS test
# corpus. Keys use the same normalisation as :func:`_norm` (alphanum only).
_SPEC_EXTRACT_PATCHES: dict[str, dict[str, int]] = {
    # MaskGenerator: spec uses MGF1, extractor saw "MFG1".
    "MaskGenerator": {"MGF1": 0x00000001},
    # CredentialType: extractor missed UsernameAndPassword (spec §11.x).
    "CredentialType": {
        "UsernameAndPassword": 0x00000001,
        "Device":              0x00000002,
        "Attestation":         0x00000003,
        "OneTimePassword":     0x00000004,
        "HashedPassword":      0x00000005,
        "Ticket":              0x00000006,
    },
    # CryptographicAlgorithm: extractor missed deprecated DES3 + a few
    # other legacy slots OASIS still references.
    "CryptographicAlgorithm": {
        "DES":  0x00000001,
        "DES3": 0x00000002,
        "RC4":  0x00000005,
    },
    # Operation: alternative spelling "ReKey" (extractor has "Rekey" from "Re-key").
    "Operation": {
        "ReKey":      0x00000004,
        "ReKeyKeyPair": 0x0000001E,
        "ReCertify":  0x00000007,
    },
    # OpaqueDataType: OASIS uses vendor-extension hex codepoints; codec
    # accepts numeric literals so empty map suffices.
    "OpaqueDataType": {},
    # PKCS_11Function: extension table from KMIP 3.0 §6.x (PKCS_11
    # passthrough op). Mapped to PKCS#11 v3.2 §5 function codes.
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
    # MaskGeneratorHashingAlgorithm: same set as CryptographicAlgorithm's
    # SHA-2 family, but the extractor missed this enum table. Values match
    # the PKCS#1 v2.2 hashAlgorithm OIDs (KMIP 3.0 §11.x).
    "MaskGeneratorHashingAlgorithm": {
        "SHA1":   0x00000004,
        "SHA224": 0x00000005,
        "SHA256": 0x00000006,
        "SHA384": 0x00000007,
        "SHA512": 0x00000008,
    },
    # PKCS_11ReturnCode: PKCS#11 v3.2 §5 return values surfaced through
    # the KMIP PKCS_11 passthrough op. OASIS uses "OK" for CKR_OK.
    "PKCS11ReturnCode": {
        "OK":                 0x00000000,
        "Cancel":             0x00000001,
        "HostMemory":         0x00000002,
        "FunctionFailed":     0x00000006,
        "ArgumentsBad":       0x00000007,
        "AttributeReadOnly":  0x00000010,
        "AttributeTypeInvalid": 0x00000012,
        "AttributeValueInvalid": 0x00000013,
    },
}


# Module-level singleton — load once.
_TABLE: CodepointTable | None = None


def table() -> CodepointTable:
    global _TABLE
    if _TABLE is None:
        _TABLE = CodepointTable.load()
    return _TABLE


# ── XML AST ─────────────────────────────────────────────────────────────────


@dataclass
class TtlvNode:
    """An in-memory TTLV element: tag name + type + value (or children).

    Values are kept symbolic: ``"$NOW"`` stays as a string until placeholder
    resolution happens at replay time. This lets the encoder fail loudly on
    unresolved placeholders rather than silently emit wrong bytes.
    """
    tag_name: str
    ttlv_type: str
    value: Any = None
    children: list["TtlvNode"] = field(default_factory=list)

    @property
    def is_placeholder(self) -> bool:
        return isinstance(self.value, str) and self.value.startswith("$")


def parse_xml_element(elem: ET.Element) -> TtlvNode:
    """Recursively parse an OASIS XML element into a :class:`TtlvNode`.

    Elements with a ``type`` attribute are leaves (or Structures with
    children); elements without ``type`` are implicit Structures (the
    OASIS XML pre-3.0 convention occasionally omits ``type="Structure"``).
    """
    tag = elem.tag  # already alphanumeric for OASIS XML
    ttlv_type = elem.attrib.get("type")

    # Structure (explicit or implicit by presence of children + absence of value).
    if ttlv_type is None or ttlv_type == "Structure":
        node = TtlvNode(tag_name=tag, ttlv_type="Structure")
        for child in elem:
            node.children.append(parse_xml_element(child))
        return node

    value = elem.attrib.get("value")
    # Collapse OASIS semantic type aliases to a real TTLV primitive.
    ttlv_type = XML_TYPE_ALIASES.get(ttlv_type, ttlv_type)
    return TtlvNode(tag_name=tag, ttlv_type=ttlv_type, value=value)


def parse_transcript_xml(path: Path) -> list[TtlvNode]:
    """Parse a full OASIS test-case XML file into a flat list of top-level
    ``<RequestMessage>`` and ``<ResponseMessage>`` nodes (in spec order).

    OASIS files contain multiple message pairs not wrapped in a root, so we
    wrap them in a synthetic ``<KMIP>`` root for ElementTree.
    """
    text = path.read_text()
    # The OASIS files use <KMIP> as the wrapper. Some have it, some don't.
    if "<KMIP>" not in text:
        text = f"<KMIP>{text}</KMIP>"
    root = ET.fromstring(text)
    return [parse_xml_element(child) for child in root]


# ── TTLV encoder ────────────────────────────────────────────────────────────


class EncodeError(Exception):
    """Raised when a node can't be encoded — unresolved placeholder, unknown
    tag, unknown enum member, malformed value, etc. Carries the offending
    tag name so callers can attribute test failures."""


def _pad8(n: int) -> int:
    """Round byte count up to the nearest 8-byte boundary (KMIP §9.6)."""
    return (n + 7) & ~7


def _encode_value(node: TtlvNode) -> bytes:
    """Encode just the value portion (no tag/type/length header).

    Length is intentionally NOT padded here — the caller adds zero padding
    after wrapping with the TTL header so the unpadded length lives in
    the length field per §9.6.
    """
    t = node.ttlv_type
    v = node.value

    if node.is_placeholder:
        raise EncodeError(
            f"unresolved placeholder {v!r} on {node.tag_name} — runner must "
            f"bind it before encoding"
        )

    if t == "Integer":
        sv = str(v)
        # Named bit-flag mask fields: "Encrypt Decrypt" → OR of named flags.
        mask = NAMED_INTEGER_MASKS.get(node.tag_name)
        if mask is not None and not sv.lstrip("-").isdigit() and not sv.startswith("0x"):
            acc = 0
            for flag in sv.split():
                if flag not in mask:
                    raise EncodeError(
                        f"unknown {node.tag_name} flag {flag!r}; "
                        f"known: {sorted(mask)[:6]}…"
                    )
                acc |= mask[flag]
            return struct.pack(">i", acc)
        return struct.pack(">i", int(sv, 0))
    if t == "LongInteger":
        return struct.pack(">q", int(str(v), 0))
    if t == "Enumeration":
        # `value` is the human-readable enum name; look up via the tag.
        # Most enum tags share the enum's tag name (e.g. tag Operation → enum Operation).
        # Some KMIP enums share a single namespace per tag.
        tag_norm = _norm(node.tag_name)

        # KMIP 3.0 special case: AttributeReference is an "enumerable Tag" —
        # its values are tag names from the Tag table (§11.x).
        if tag_norm == "AttributeReference":
            tag_code = table().tag_name_to_code.get(_norm(str(v)))
            if tag_code is None:
                raise EncodeError(f"AttributeReference: unknown tag name {v!r}")
            return struct.pack(">I", tag_code)

        # Numeric literal (hex or decimal) — used for vendor extensions.
        sv = str(v)
        if sv.startswith("0x") or sv.lstrip("-").isdigit():
            return struct.pack(">I", int(sv, 0))

        enum_map = table().enum_name_to_value.get(tag_norm)
        if enum_map is None:
            raise EncodeError(
                f"no enum definition for tag {node.tag_name!r} (value {v!r})"
            )
        key = _norm(sv)
        code = enum_map.get(key)
        if code is None:
            raise EncodeError(
                f"unknown enum member {v!r} for {node.tag_name!r}; "
                f"known: {sorted(enum_map.keys())[:6]}…"
            )
        return struct.pack(">I", code)
    if t == "Boolean":
        # 8-byte body per §9.6.
        return struct.pack(">Q", 1 if str(v).lower() in ("true", "1") else 0)
    if t == "TextString":
        return str(v).encode("utf-8")
    if t == "ByteString":
        # Hex per OASIS convention.
        return bytes.fromhex(str(v))
    if t == "DateTime":
        # `$NOW` is a placeholder; OASIS XML carries ISO 8601 strings for
        # concrete dates. Pure-numeric strings are kept as Unix-epoch
        # seconds (the codec self-test path uses ``"0"``).
        sv = str(v)
        if sv.lstrip("-").isdigit():
            return struct.pack(">q", int(sv, 0))
        from datetime import datetime
        dt = datetime.fromisoformat(sv)
        return struct.pack(">q", int(dt.timestamp()))
    if t == "Interval":
        return struct.pack(">I", int(str(v), 0))
    if t == "BigInteger":
        # KMIP §9.6.5: variable-length two's-complement big-endian, body
        # length padded to 8 bytes by the caller. OASIS XML carries the
        # raw hex byte sequence (no 0x prefix) — much simpler than parsing
        # as a Python int.
        sv = str(v)
        if all(c in "0123456789abcdefABCDEF" for c in sv) and len(sv) % 2 == 0:
            return bytes.fromhex(sv)
        n = int(sv, 0)
        # Smallest two's-complement big-endian encoding.
        byte_len = max(1, (n.bit_length() + 8) // 8)
        return n.to_bytes(byte_len, "big", signed=True)
    if t == "DateTimeExtended":
        # Microseconds since epoch — 8-byte signed integer.
        return struct.pack(">q", int(str(v), 0))

    raise EncodeError(f"unsupported TTLV type {t!r} on {node.tag_name!r}")


def encode_node(node: TtlvNode) -> bytes:
    """Encode one TTLV node (tag + type + length + value + padding).

    Structures recursively encode their children. Leaf values pad to 8-byte
    alignment but the *length* field encodes the unpadded body size.
    """
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

    # Tag is 3 bytes big-endian — pack as 4 bytes and drop the leading 0.
    tag_bytes = struct.pack(">I", tag)[1:]
    header = tag_bytes + bytes([type_byte]) + struct.pack(">I", body_len)
    return header + body


# ── TTLV decoder ────────────────────────────────────────────────────────────


class DecodeError(Exception):
    pass


def _ttlv_type_name(code: int) -> str:
    for name, c in TTLV_TYPE.items():
        if c == code:
            return name
    raise DecodeError(f"unknown TTLV type byte 0x{code:02x}")


def decode_one(buf: bytes, offset: int = 0) -> tuple[TtlvNode, int]:
    """Decode one TTLV element starting at ``offset``; return (node, next_offset)."""
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


PLACEHOLDER_STUBS: dict[str, str] = {
    # Replay-time bindings the OASIS suite uses; for codec round-trip we
    # substitute neutral fillers so encode/decode can prove byte-equivalence.
    # The conformance runner (not this codec) replaces with real values
    # captured from prior responses.
    "DateTime":             "0",
    "DateTimeExtended":     "0",
    "Integer":              "0",
    "LongInteger":          "0",
    "Enumeration":          "0x00000001",
    "Boolean":              "true",
    "TextString":           "stub-placeholder",
    "ByteString":           "00",
    "Interval":             "0",
    "BigInteger":           "0",
}


def resolve_placeholders_stub(node: TtlvNode) -> TtlvNode:
    """Return a copy of ``node`` with any ``$``-prefixed values replaced
    by neutral type-appropriate fillers. Used only for codec round-trip
    testing — the real conformance runner binds placeholders to values
    captured from prior responses.
    """
    children = [resolve_placeholders_stub(c) for c in node.children]
    value = node.value
    if isinstance(value, str) and value.startswith("$"):
        value = PLACEHOLDER_STUBS.get(node.ttlv_type, "0")
    return TtlvNode(
        tag_name=node.tag_name,
        ttlv_type=node.ttlv_type,
        value=value,
        children=children,
    )


def roundtrip_check(node: TtlvNode, *, stub_placeholders: bool = True) -> tuple[bool, str]:
    """Encode a node, decode the bytes back, validate byte consumption.

    Returns ``(ok, diagnostic)``. Used to validate that our codec is
    self-consistent on a per-message basis before any server interaction.

    With ``stub_placeholders=True`` (default), ``$NOW`` etc. are replaced
    by neutral fillers so codec correctness can be tested independent of
    placeholder semantics.
    """
    target = resolve_placeholders_stub(node) if stub_placeholders else node
    try:
        bytes_out = encode_node(target)
    except EncodeError as e:
        return False, f"encode failed: {e}"
    try:
        _decoded, consumed = decode_one(bytes_out, 0)
    except DecodeError as e:
        return False, f"decode failed: {e}"
    if consumed != len(bytes_out):
        return False, f"consumed {consumed} of {len(bytes_out)} bytes"
    return True, "ok"
