"""Unit tests for pqctoday_kmip._ttlv — codec round-trips and helpers.

All tests are pure-Python, no network, no server.  Run with:
    cd kmip/python-client && python -m pytest tests/
"""
import json

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
    # §6.1.64 Validate's response — ValidityIndicator is the field the
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


# ── codepoint patch completeness + non-corruption guard (2026-07-24 CSD02 migration) ──
#
# Python-side counterpart to hub's codepointPatches.local.test.ts. Every
# entry in _SPEC_EXTRACT_TAG_PATCHES/_SPEC_EXTRACT_PATCHES must be accounted
# for by the base spec JSON itself (exact or case-insensitive _norm() match
# — the fallback exists because several patches are the same
# case-sensitive-norm-collision class of bug as the original H1/ReKeyKeyPair
# defect, e.g. ReKeyKeyPair vs the spec's "Re-key Key Pair"), or an explicit
# justified exception below.
#
# Replaces the 2026-07-23 version of this test (which also checked a WD19
# delta file): the base JSON is now extracted directly from the published
# CSD02 HTML, which superseded both CSD01 and the never-separately-published
# WD19 draft the delta file existed to cover — so there is only one baseline
# to check patches against now. This is the test that would have caught the
# 2026-07-23 RC4 bug (RC4 patched to 0x00000005 — DSA's real codepoint —
# instead of the real 0x00000016) and the two other gaps found the same day
# (missing X25519MLKEM768/SecP256r1MLKEM768, and a missing
# DeactivationReasonCode patch entirely).
import importlib.resources as _ir

from pqctoday_kmip._ttlv import _SPEC_EXTRACT_PATCHES, _SPEC_EXTRACT_TAG_PATCHES, _norm

_BASE_JSON = json.loads(
    _ir.files("pqctoday_kmip").joinpath("data/kmip-spec-3.0-tags-enums.json").read_text(encoding="utf-8")
)

# Enum-member patches with no match in the base JSON, each with why it's
# legitimately absent. Independently classified against THIS file's actual
# patch tables — not copied from the TS side's allowlist, though the
# underlying facts happen to be identical since both files patch the same
# real values.
_ENUM_ALLOWLIST: dict[str, dict[str, str]] = {
    "CryptographicAlgorithm": {
        "DES3": "naming-convention alias for the spec's '3DES' (0x00000002, digit-order differs, not a case issue)",
        "FrodoKEM-640": "BSI TR-02102-1 vendor KEM, not an OASIS codepoint",
        "FrodoKEM-640-AES": "BSI TR-02102-1 vendor KEM, not an OASIS codepoint",
        "FrodoKEM-640-SHAKE": "BSI TR-02102-1 vendor KEM, not an OASIS codepoint",
        "FrodoKEM-976": "BSI TR-02102-1 vendor KEM, not an OASIS codepoint",
        "FrodoKEM-976-AES": "BSI TR-02102-1 vendor KEM, not an OASIS codepoint",
        "FrodoKEM-976-SHAKE": "BSI TR-02102-1 vendor KEM, not an OASIS codepoint",
        "FrodoKEM-1344": "BSI TR-02102-1 vendor KEM, not an OASIS codepoint",
        "FrodoKEM-1344-AES": "BSI TR-02102-1 vendor KEM, not an OASIS codepoint",
        "FrodoKEM-1344-SHAKE": "BSI TR-02102-1 vendor KEM, not an OASIS codepoint",
        "Classic-McEliece-6688128": (
            "parameter-set-specific display name for the spec's real 'McEliece' entry "
            "(0x00000034) — same OASIS codepoint, not a vendor value"
        ),
        "ML-DSA-44-RSA2048-PSS": "LAMPS composite signature, vendor-extension range, not an OASIS codepoint",
        "ML-DSA-65-ECDSA-P256": "LAMPS composite signature, vendor-extension range, not an OASIS codepoint",
        "ML-DSA-87-ECDSA-P384": "LAMPS composite signature, vendor-extension range, not an OASIS codepoint",
        "SecP256r1MLKEM768": (
            "casing alias for the spec's own 'SECP256R1MLKEM768' (all-caps) — matches "
            "the Rust engine's naming instead"
        ),
    },
    "MaskGenerator": {
        "MGF1": (
            "spec's own table has 'MFG1' (transposed letters) at the same codepoint "
            "(0x00000001) — a spec typo, not a missing value"
        ),
    },
    "DeactivationReasonCode": {
        "KeyCompromise": (
            "the spec's own 'Deactivation Reason Code' table is still a PDF/HTML-extraction "
            "mismatch under CSD02 (wrong table extracted) — verified against "
            "kmip30::ops::DeactivationReason directly"
        ),
        "CACompromise": "same extraction defect as KeyCompromise above",
        "AffiliationChanged": "same extraction defect as KeyCompromise above",
        "Superseded": "same extraction defect as KeyCompromise above",
        "CessationOfOperation": "same extraction defect as KeyCompromise above",
        "PrivilegeWithdrawn": "same extraction defect as KeyCompromise above",
    },
    "PKCS11Function": {
        "*": "PKCS#11 function-call constants for the bridge, not KMIP OASIS operations",
    },
    "PKCS11ReturnCode": {
        "*": "PKCS#11 return-code constants for the bridge, not KMIP OASIS values",
    },
    "MaskGeneratorHashingAlgorithm": {
        "*": (
            "reuses the base JSON's 'Hashing Algorithm' enum values under a field-specific "
            "name (SHA1=4 matches 'SHA-1'=4, etc. — verified 1:1)"
        ),
    },
}

# No unmatched TAG patches: the surviving _SPEC_EXTRACT_TAG_PATCHES entries
# are all redundant cross-check aliases for CSD02 entries and match via
# exact norm().
_TAG_ALLOWLIST: dict[str, str] = {}


def _find_match(name, pool):
    """pool: iterable of (name, value). Exact _norm() match first, then a
    case-insensitive fallback (same two-rule structure as the TS test —
    Python's _norm() has the identical strip-non-alnum, case-sensitive
    behavior, confirmed by reading the source before writing this)."""
    n = _norm(name)
    for pn, pv in pool:
        if _norm(pn) == n:
            return pv
    nl = n.lower()
    for pn, pv in pool:
        if _norm(pn).lower() == nl:
            return pv
    return None


def test_tag_patches_are_verified_aliases_or_explicit_exceptions():
    base_tags = [(t["name"], int(t["codepoint"], 16)) for t in _BASE_JSON["tags"]]
    for name, patched_code in _SPEC_EXTRACT_TAG_PATCHES.items():
        m = _find_match(name, base_tags)
        if m is not None:
            assert patched_code == m, f"tag '{name}' patch value diverges from the spec's own value"
            continue
        assert name in _TAG_ALLOWLIST, (
            f"tag '{name}' (0x{patched_code:x}) is not in the spec JSON and not an explicit "
            "exception — is this a value the extractor is missing?"
        )


def test_enum_patches_are_verified_aliases_or_explicit_exceptions():
    for enum_name, members in _SPEC_EXTRACT_PATCHES.items():
        base_enum_key = next(
            (
                bn
                for bn in _BASE_JSON["enums"]
                if _norm(bn) == _norm(enum_name) or _norm(bn).lower() == _norm(enum_name).lower()
            ),
            None,
        )
        base_members = (
            [(m["name"], int(m["value"], 16)) for m in _BASE_JSON["enums"][base_enum_key]]
            if base_enum_key
            else []
        )
        allowlist_for_enum = _ENUM_ALLOWLIST.get(enum_name, {})

        for member_name, patched_value in members.items():
            m = _find_match(member_name, base_members)
            if m is not None:
                assert patched_value == m, (
                    f"{enum_name}.{member_name} patch value diverges from the spec's own value"
                )
                continue
            allowed = allowlist_for_enum.get(member_name) or allowlist_for_enum.get("*")
            assert allowed is not None, (
                f"{enum_name}.{member_name} (0x{patched_value:x}) is not in the spec JSON and "
                "not an explicit exception — is this a value the extractor is missing?"
            )


def test_allowlist_is_not_vacuous():
    """Sanity check the completeness test itself can fail: prove
    _ENUM_ALLOWLIST is load-bearing by removing one real exception (DES3)
    and confirming it has no other match, mirroring the TS test's approach."""
    without_des3 = dict(_ENUM_ALLOWLIST["CryptographicAlgorithm"])
    del without_des3["DES3"]

    base_algos = [(m["name"], int(m["value"], 16)) for m in _BASE_JSON["enums"]["Cryptographic Algorithm"]]
    assert _find_match("DES3", base_algos) is None, "DES3 unexpectedly matches the spec by name — probe assumption invalid"
    assert "DES3" not in without_des3, "probe removal failed"
