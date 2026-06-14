"""TTLV codec shim.

`pykmip` reuses the single canonical TTLV codec that lives with the
conformance harness (`conformance/harness/oasis_codec.py`) rather than
carrying a second copy — that codec already knows every KMIP 3.0 tag/enum
codepoint *and* the KMIP 3.0 WD19 PQC extensions (ML-KEM Encapsulate /
Decapsulate, SeedPrivateKey, the PQC `CryptographicParameters` fields).

Importing it requires putting the harness directory on `sys.path`; we do
that here once so the rest of `pykmip` can just `from . import codec`.
"""
from __future__ import annotations

import pathlib
import sys

_HARNESS = pathlib.Path(__file__).resolve().parent.parent / "conformance" / "harness"
if str(_HARNESS) not in sys.path:
    sys.path.insert(0, str(_HARNESS))

import oasis_codec as _oc  # noqa: E402  (path injected above)

TtlvNode = _oc.TtlvNode
encode_node = _oc.encode_node
decode_one = _oc.decode_one
table = _oc.table
EncodeError = _oc.EncodeError
DecodeError = _oc.DecodeError


def norm(name: str) -> str:
    """Alphanumerics-only tag-name normaliser (matches the codec)."""
    return "".join(c for c in name if c.isalnum())


def struct(tag: str, *children: TtlvNode) -> TtlvNode:
    """Build a TTLV Structure node."""
    return TtlvNode(tag_name=tag, ttlv_type="Structure", children=list(children))


def leaf(tag: str, ttlv_type: str, value) -> TtlvNode:
    """Build a TTLV leaf node (Integer / Enumeration / ByteString / …)."""
    return TtlvNode(tag_name=tag, ttlv_type=ttlv_type, value=value)


def find(node: TtlvNode, tag: str):
    """Breadth-first search for the first descendant whose (normalised) tag
    matches `tag`. Returns the node or None. Tolerant of the decoder's
    space-separated tag names ("Result Status" ~ "ResultStatus")."""
    from collections import deque

    want = norm(tag)
    dq = deque([node])
    while dq:
        n = dq.popleft()
        if norm(n.tag_name) == want:
            return n
        dq.extend(n.children)
    return None


def find_all(node: TtlvNode, tag: str) -> list:
    """All descendants whose (normalised) tag matches `tag`, in BFS order."""
    from collections import deque

    want = norm(tag)
    out = []
    dq = deque([node])
    while dq:
        n = dq.popleft()
        if norm(n.tag_name) == want:
            out.append(n)
        dq.extend(n.children)
    return out
