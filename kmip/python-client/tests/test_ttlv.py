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
