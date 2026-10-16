"""Unit tests for pqctoday_kmip.fhe — the PQCTODAY_FHE_1_0 input layouts and the PKCS_11 request.

The two DER vectors are also asserted, byte for byte, by the server's unit tests
(`kmip/src/ops/fhe_bridge.rs`, `wire_vectors_match_the_python_client`). No network, no server.
"""
import pytest

from pqctoday_kmip import fhe
from pqctoday_kmip._ttlv import decode_one, encode_node, find
from pqctoday_kmip.kmip import _leaf

DERIVE_VECTOR = (
    "30380c24" + "61" * 36 + "020102020105020103020100020100020104"
)
GENERATE_VECTOR = (
    "307102030080020430" + "01" * 48 + "0430" + "02" * 48 + "0404736565640400"
)


def test_derive_key_vector():
    assert fhe.derive_key_v1(b"a" * 36, 2, 5, 3, 0, 0, 4).hex() == DERIVE_VECTOR


def test_generate_key_vector():
    assert fhe.generate_key_v1(0x8002, b"\x01" * 48, b"\x02" * 48, b"seed", b"").hex() == GENERATE_VECTOR


def test_sizes_are_checked():
    with pytest.raises(ValueError):
        fhe.generate_key_v1(3, b"\x01" * 47, b"\x02" * 48)
    with pytest.raises(ValueError):
        fhe.decrypt_init_v1(b"a" * 35)
    with pytest.raises(ValueError):
        fhe.decrypt_init_v1(b"a" * 36, recipient=b"\x00" * 32)
    with pytest.raises(ValueError):
        fhe.get_attribute_value_v1(b"a" * 36, [])


def test_decrypt_layout_and_long_lengths():
    ct = bytes(300)
    der = fhe.decrypt_v1(ct, 0)
    assert der[:2] == b"\x30\x82"
    assert der == fhe._seq(b"\x04\x82\x01\x2c" + ct + b"\x02\x01\x00")


def test_attributes_parse_with_unavailable_entries():
    der = fhe._seq(
        fhe._seq(fhe._int(fhe.CKA_PQCTODAY_FHE_PARAM_SET), fhe._octets(b"\x02\x80\x00\x00")),
        fhe._seq(fhe._int(fhe.CKA_VALUE)),
    )
    assert fhe.parse_attributes_v1(der) == {fhe.CKA_PQCTODAY_FHE_PARAM_SET: b"\x02\x80\x00\x00", fhe.CKA_VALUE: None}
    with pytest.raises(ValueError):
        fhe.parse_attributes_v1(der + b"\x00")
    assert fhe.parse_der_integer(fhe._int(1048600)) == 1048600


def test_pkcs11_request_payload_encodes():
    for node, tag in [
        (_leaf("PKCS11Interface", "TextString", fhe.IFACE), 0x420159),
        (_leaf("PKCS11Function", "Enumeration", fhe.FN_DECRYPT), 0x42015A),
        (_leaf("PKCS11InputParameters", "ByteString", b"\x30\x00".hex()), 0x42015B),
    ]:
        raw = encode_node(node)
        assert int.from_bytes(raw[:3], "big") == tag
        back, _ = decode_one(raw, 0)
        assert find(back, node.tag_name) is not None


class _FakeClient:
    """Answers each call from a queue of (rv, output)."""

    def __init__(self, *answers):
        self.answers, self.calls = list(answers), []

    def pkcs11(self, interface, function, data=b""):
        self.calls.append((interface, function, data))
        return self.answers.pop(0)


def test_decrypt_owner_is_the_pkcs11_sequence():
    c = _FakeClient((0, b""), (0, fhe._int(5)), (0, b"plain"))
    assert fhe.FheCustody(c).decrypt_owner("a" * 36, b"ct") == b"plain"
    assert [f for _, f, _ in c.calls] == [fhe.FN_DECRYPT_INIT, fhe.FN_DECRYPT, fhe.FN_DECRYPT]
    assert c.calls[1][2] == fhe.decrypt_v1(b"ct", 0) and c.calls[2][2] == fhe.decrypt_v1(b"ct", 5)


def test_export_public_destroys_the_object_even_on_error():
    attrs = fhe._seq(fhe._seq(fhe._int(fhe.CKA_VALUE), fhe._octets(b"pk")))
    c = _FakeClient((0, b"o" * 36), (0, attrs), (0, b""))
    assert fhe.FheCustody(c).export_public("a" * 36, 2, fhe.FheCustody.CKKS_DESCRIPTOR) == b"pk"
    assert [f for _, f, _ in c.calls] == [fhe.FN_DERIVE_KEY, fhe.FN_GET_ATTRIBUTE_VALUE, fhe.FN_DESTROY_OBJECT]
    c = _FakeClient((0, b"o" * 36), (0x30, b""), (0, b""))
    with pytest.raises(fhe.FheError):
        fhe.FheCustody(c).export_public("a" * 36, 2, fhe.FheCustody.CKKS_DESCRIPTOR)
    assert c.calls[-1][1] == fhe.FN_DESTROY_OBJECT


def test_errors_carry_the_return_code():
    with pytest.raises(fhe.FheError) as e:
        fhe.FheCustody(_FakeClient((0x1B, b""))).destroy_object("a" * 36)
    assert e.value.rv == 0x1B and e.value.function == fhe.FN_DESTROY_OBJECT
