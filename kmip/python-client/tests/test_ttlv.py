"""Unit tests for pqctoday_kmip._ttlv — codec round-trips and helpers.

All tests are pure-Python, no network, no server.  Run with:
    cd kmip/python-client && python -m pytest tests/
"""
import pytest

from pqctoday_kmip._ttlv import (
    encode_node,
    decode_one,
    find,
    find_all,
    leaf,
    struct as ttlv_struct,
    table,
)


# ── CodepointTable ────────────────────────────────────────────────────────────

def test_table_loads():
    t = table()
    assert len(t.tag_name_to_code) >= 395
    assert len(t.enum_name_to_value) >= 50


def test_table_known_tags():
    t = table()
    assert "UniqueIdentifier" in t.tag_name_to_code
    assert "RequestMessage" in t.tag_name_to_code
    assert "BatchItem" in t.tag_name_to_code


def test_table_pqc_patches():
    t = table()
    # WD19 PQC tag patches
    assert "KEMAlgorithm" in t.tag_name_to_code
    assert t.tag_name_to_code["KEMAlgorithm"] == 0x4201C3
    # PQC enum patches
    assert "Encapsulate" in t.enum_name_to_value.get("Operation", {})
    assert "Decapsulate" in t.enum_name_to_value.get("Operation", {})


def test_table_certificate_services_tag_patches():
    # WP-py (cert-ops plan revision) — _SPEC_EXTRACT_TAG_PATCHES's
    # Sec6.1.62 Validate / Sec6.1.6 Certify / Sec6.1.50 Re-certify
    # additions, mirrored by hand from the hub's codepointTable.ts, had
    # never actually been exercised by this client's own test suite.
    # Values cross-checked against kmip/src/kmip30/wire.rs's tags::*
    # constants (the source of truth both TS and Python copy from).
    t = table()
    assert t.tag_name_to_code["CertificateValue"] == 0x42001E
    assert t.tag_name_to_code["CertificateRequestType"] == 0x420019
    assert t.tag_name_to_code["CertificateRequest"] == 0x420018
    assert t.tag_name_to_code["CertificateRequestValue"] == 0x420140
    assert t.tag_name_to_code["CertificateRequestUniqueIdentifier"] == 0x420139
    assert t.tag_name_to_code["ValidityDate"] == 0x42009A
    assert t.tag_name_to_code["ValidityIndicator"] == 0x42009B
    # Reverse mapping must resolve too — a decoded response's tag CODE has
    # to name back to something a caller can match on, not just encode.
    # `setdefault` means the patch's reverse entry only wins when the code
    # wasn't ALREADY present — 0x42009B already existed in the base spec
    # JSON under its canonical spaced form ("Validity Indicator"), so that
    # wins; _norm() is the codec's own stable comparison for exactly this
    # spaced-vs-PascalCase mismatch (see test_roundtrip_text_string).
    from pqctoday_kmip._ttlv import _norm
    assert _norm(t.tag_code_to_name[0x42009B]) == _norm("ValidityIndicator")


def test_table_certificate_services_enum_patches():
    # WP-py finding: `_SPEC_EXTRACT_PATCHES`'s comment claims
    # CertificateRequestType is "absent from the spec-extraction JSON" —
    # it isn't; the base JSON already defines it (as CRMF/PKCS10/PEM/
    # Reserved). `.update()` ADDS the patch's "Crmf" key alongside the
    # base's existing "CRMF" rather than replacing it (setdefault(tag, {})
    # .update(...) is additive, not a swap) — harmless for encoding
    # correctness (every name variant present resolves to the same wire
    # value) but means the patch's own comment is inaccurate, and a dict-
    # equality assertion against just the patch's three keys would be
    # wrong. Assert what actually has to be true: every name a real
    # caller (this client, or the hub's codepointTable.ts) uses resolves
    # to the correct wire value.
    t = table()
    req_type = t.enum_name_to_value.get("CertificateRequestType", {})
    assert req_type["PKCS10"] == 0x00000002
    assert req_type["PEM"] == 0x00000003
    assert req_type.get("Crmf") == 0x00000001 or req_type.get("CRMF") == 0x00000001
    validity = t.enum_name_to_value.get("ValidityIndicator", {})
    assert validity == {"Valid": 0x00000001, "Invalid": 0x00000002, "Unknown": 0x00000003}


def test_table_mldsa_algorithm():
    t = table()
    alg = t.enum_name_to_value.get("CryptographicAlgorithm", {})
    assert any("MLDSA" in k or "MLKSA" in k or "ML" in k for k in alg)


# ── Leaf constructors and traversal ─────────────────────────────────────────

def test_leaf_ctor():
    n = leaf("UniqueIdentifier", "TextString", "uid-001")
    assert n.tag_name == "UniqueIdentifier"
    assert n.ttlv_type == "TextString"
    assert n.value == "uid-001"
    assert n.children == []


def test_struct_ctor():
    n = ttlv_struct(
        "RequestMessage",
        leaf("UniqueIdentifier", "TextString", "x"),
    )
    assert n.ttlv_type == "Structure"
    assert len(n.children) == 1


def test_find_first():
    # BFS: shallower nodes are visited before deeper ones.
    # "b" is a direct child of Root (depth 1); "a" is inside Child (depth 2).
    tree = ttlv_struct(
        "Root",
        ttlv_struct("Child", leaf("UniqueIdentifier", "TextString", "a")),
        leaf("UniqueIdentifier", "TextString", "b"),
    )
    result = find(tree, "UniqueIdentifier")
    assert result is not None
    assert result.value == "b"


def test_find_missing():
    n = leaf("UniqueIdentifier", "TextString", "x")
    assert find(n, "NonExistentTag") is None


def test_find_all():
    tree = ttlv_struct(
        "Root",
        leaf("UniqueIdentifier", "TextString", "uid-1"),
        leaf("UniqueIdentifier", "TextString", "uid-2"),
        ttlv_struct("Nested", leaf("UniqueIdentifier", "TextString", "uid-3")),
    )
    results = find_all(tree, "UniqueIdentifier")
    assert len(results) == 3
    assert [r.value for r in results] == ["uid-1", "uid-2", "uid-3"]


def test_find_punctuation_insensitive():
    # _norm strips non-alphanumeric chars but preserves case.
    # Hyphens and dots are stripped; case must still match.
    n = ttlv_struct("RequestMessage", leaf("UniqueIdentifier", "TextString", "u"))
    assert find(n, "UniqueIdentifier") is not None
    assert find(n, "Unique-Identifier") is not None   # hyphen stripped → same
    assert find(n, "Unique.Identifier") is not None   # dot stripped → same


# ── Encode / decode round-trips ──────────────────────────────────────────────

def test_roundtrip_text_string():
    n = leaf("UniqueIdentifier", "TextString", "test-uid-42")
    encoded = encode_node(n)
    decoded, consumed = decode_one(encoded)
    # The codec stores canonical spec names (with spaces, e.g. "Unique Identifier").
    # _norm(decoded.tag_name) == _norm("UniqueIdentifier") is the stable comparison.
    from pqctoday_kmip._ttlv import _norm
    assert _norm(decoded.tag_name) == _norm("UniqueIdentifier")
    assert decoded.ttlv_type == "TextString"
    assert decoded.value == "test-uid-42"
    assert consumed == len(encoded)


def test_roundtrip_integer():
    n = leaf("ProtocolVersionMajor", "Integer", 3)
    encoded = encode_node(n)
    decoded, _ = decode_one(encoded)
    assert decoded.value == 3


def test_roundtrip_enumeration_by_name():
    n = leaf("Operation", "Enumeration", "Create")
    encoded = encode_node(n)
    decoded, _ = decode_one(encoded)
    assert decoded.ttlv_type == "Enumeration"
    assert isinstance(decoded.value, int)


def test_roundtrip_enumeration_pqc():
    n = leaf("Operation", "Enumeration", "Encapsulate")
    encoded = encode_node(n)
    decoded, _ = decode_one(encoded)
    assert decoded.ttlv_type == "Enumeration"
    assert decoded.value == 0x00000041


def test_roundtrip_byte_string():
    data = bytes.fromhex("deadbeef")
    n = leaf("Data", "ByteString", data.hex())
    encoded = encode_node(n)
    decoded, _ = decode_one(encoded)
    assert decoded.value == "deadbeef"


def test_roundtrip_boolean():
    n = leaf("Sensitive", "Boolean", "true")
    encoded = encode_node(n)
    decoded, _ = decode_one(encoded)
    assert decoded.value is True


def test_roundtrip_structure():
    tree = ttlv_struct(
        "ProtocolVersion",
        leaf("ProtocolVersionMajor", "Integer", 3),
        leaf("ProtocolVersionMinor", "Integer", 0),
    )
    encoded = encode_node(tree)
    decoded, _ = decode_one(encoded)
    assert decoded.ttlv_type == "Structure"
    assert len(decoded.children) == 2
    assert decoded.children[0].value == 3
    assert decoded.children[1].value == 0


def test_roundtrip_nested_request():
    msg = ttlv_struct(
        "RequestMessage",
        ttlv_struct(
            "RequestHeader",
            ttlv_struct(
                "ProtocolVersion",
                leaf("ProtocolVersionMajor", "Integer", 3),
                leaf("ProtocolVersionMinor", "Integer", 0),
            ),
        ),
        ttlv_struct(
            "BatchItem",
            leaf("Operation", "Enumeration", "Create"),
            ttlv_struct(
                "RequestPayload",
                leaf("ObjectType", "Enumeration", "SymmetricKey"),
            ),
        ),
    )
    encoded = encode_node(msg)
    decoded, consumed = decode_one(encoded)
    assert consumed == len(encoded)
    assert decoded.ttlv_type == "Structure"
    header = find(decoded, "RequestHeader")
    assert header is not None
    proto = find(header, "ProtocolVersion")
    assert proto is not None
    maj = find(proto, "ProtocolVersionMajor")
    assert maj is not None and maj.value == 3


def test_roundtrip_certify_request_with_csr():
    # WP-py (cert-ops plan revision) — a §6.1.6 Certify request built from
    # a PKCS#10 CSR, shaped like the hub's opTemplates.ts::certify()
    # builder, round-tripped through THIS client's own encode/decode using
    # its mirrored Certificate Services tag/enum patches end to end (not
    # just isolated dict membership checks).
    msg = ttlv_struct(
        "BatchItem",
        leaf("Operation", "Enumeration", "Certify"),
        ttlv_struct(
            "RequestPayload",
            leaf("CertificateRequestType", "Enumeration", "PKCS10"),
            leaf("CertificateRequest", "ByteString", "3082"),
        ),
    )
    encoded = encode_node(msg)
    decoded, consumed = decode_one(encoded)
    assert consumed == len(encoded)
    payload = find(decoded, "RequestPayload")
    assert payload is not None
    req_type = find(payload, "CertificateRequestType")
    assert req_type is not None
    assert req_type.value == 0x00000002  # PKCS10
    req = find(payload, "CertificateRequest")
    assert req is not None
    assert req.value == "3082"


def test_roundtrip_validate_response_validity_indicator():
    # §6.1.62 Validate's response — ValidityIndicator is the field the
    # hub's own test suite had to learn (this session) resolves to a raw
    # enum codepoint, not a name; confirm the Python client agrees.
    resp = ttlv_struct(
        "ResponsePayload",
        leaf("ValidityIndicator", "Enumeration", "Valid"),
    )
    encoded = encode_node(resp)
    decoded, _ = decode_one(encoded)
    indicator = find(decoded, "ValidityIndicator")
    assert indicator is not None
    assert indicator.value == 0x00000001


def test_usage_mask_flags():
    n = leaf("CryptographicUsageMask", "Integer", "Sign Verify")
    encoded = encode_node(n)
    decoded, _ = decode_one(encoded)
    assert decoded.value == (0x00000001 | 0x00000002)


def test_usage_mask_kem():
    n = leaf("CryptographicUsageMask", "Integer", "Encapsulate Decapsulate")
    encoded = encode_node(n)
    decoded, _ = decode_one(encoded)
    assert decoded.value == (0x00040000 | 0x00080000)


# ── Padding invariant ────────────────────────────────────────────────────────

def test_8byte_alignment():
    for text in ("a", "ab", "abc", "abcd", "abcde", "abcdef", "abcdefg", "abcdefgh"):
        encoded = encode_node(leaf("UniqueIdentifier", "TextString", text))
        assert len(encoded) % 8 == 0, f"misaligned for text={text!r}"


# ── Error paths ──────────────────────────────────────────────────────────────

def test_unknown_tag_raises():
    from pqctoday_kmip._ttlv import EncodeError
    with pytest.raises(EncodeError, match="unknown tag"):
        encode_node(leaf("NotARealTag", "TextString", "x"))


def test_unknown_enum_member_raises():
    from pqctoday_kmip._ttlv import EncodeError
    with pytest.raises(EncodeError, match="unknown enum member"):
        encode_node(leaf("Operation", "Enumeration", "NotAnOperation"))


def test_placeholder_raises():
    from pqctoday_kmip._ttlv import EncodeError
    with pytest.raises(EncodeError, match="unresolved placeholder"):
        encode_node(leaf("UniqueIdentifier", "TextString", "$placeholder"))
