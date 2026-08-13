"""Wire-shape and guard tests for ``KmipClient.register`` (§6.1.56).

Mocked at the transport, so these run with no server. The live behaviour —
that a registered key really is usable afterwards — was verified separately
against a running server; what these pin is the request this client BUILDS,
which is the part a live test cannot isolate once the server has answered.
"""
import pytest

from pqctoday_kmip.kmip import KmipClient, _find


def _client_capturing(sent: list) -> KmipClient:
    """A client whose transport records the request instead of sending it."""
    c = KmipClient.__new__(KmipClient)  # no socket, no TLS context
    c.username = None
    c.password = None

    def _send(request):
        sent.append(request)
        # Minimal well-formed ResponseMessage the result parser accepts.
        from pqctoday_kmip import _ttlv

        return _ttlv.TtlvNode(
            "ResponseMessage",
            "Structure",
            [
                _ttlv.TtlvNode(
                    "BatchItem",
                    "Structure",
                    [
                        _ttlv.TtlvNode("ResultStatus", "Enumeration", "Success"),
                        _ttlv.TtlvNode(
                            "ResponsePayload",
                            "Structure",
                            [_ttlv.TtlvNode("UniqueIdentifier", "TextString", "uid-1")],
                        ),
                    ],
                )
            ],
        )

    c._send = _send  # type: ignore[method-assign]
    return c


def _payload(request):
    return _find(_find(request, "BatchItem"), "RequestPayload")


def test_register_builds_a_symmetric_key_block():
    sent: list = []
    c = _client_capturing(sent)
    c.register(bytes.fromhex("00" * 32), algorithm="AES", name="imported")

    p = _payload(sent[0])
    assert _find(p, "ObjectType").value == "SymmetricKey"

    block = _find(_find(p, "SymmetricKey"), "KeyBlock")
    assert block is not None, "Register must carry the managed object, not just attributes"
    assert _find(block, "KeyFormatType").value == "Raw"
    assert _find(_find(block, "KeyValue"), "KeyMaterial").value == "00" * 32
    # The KeyBlock carries its own algorithm/length as well as the Attributes
    # bag — the corpus transcripts (CS-BC-M-*) set both, and a server is
    # entitled to read either.
    assert _find(block, "CryptographicAlgorithm").value == "AES"
    assert int(_find(block, "CryptographicLength").value) == 256


def test_register_derives_length_from_the_material():
    sent: list = []
    c = _client_capturing(sent)
    c.register(bytes(16))  # 16 bytes => AES-128
    block = _find(_find(_payload(sent[0]), "SymmetricKey"), "KeyBlock")
    assert int(_find(block, "CryptographicLength").value) == 128


def test_register_refuses_a_length_that_contradicts_the_material():
    """A wrong length is caught here rather than stored.

    Forwarding it would leave the server holding an attribute that disagrees
    with its own key material, and the contradiction would only surface much
    later as an unexplained mechanism failure.
    """
    c = _client_capturing([])
    with pytest.raises(ValueError, match="contradicts key_material"):
        c.register(bytes(32), length=128)


def test_register_omits_name_when_not_given():
    sent: list = []
    c = _client_capturing(sent)
    c.register(bytes(32))
    attrs = _find(_payload(sent[0]), "Attributes")
    assert _find(attrs, "Name") is None


def test_register_sets_the_requested_usage_mask():
    sent: list = []
    c = _client_capturing(sent)
    c.register(bytes(32), usage="Encrypt")
    attrs = _find(_payload(sent[0]), "Attributes")
    assert _find(attrs, "CryptographicUsageMask").value == "Encrypt"
