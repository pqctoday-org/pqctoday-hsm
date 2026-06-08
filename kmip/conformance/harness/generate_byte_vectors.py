#!/usr/bin/env python3
"""Generate Rust-side KAT byte vectors from the OASIS KMIP 3.0 XML corpus.

Two output tiers:

* ``pristine/`` — only messages with NO ``$``-placeholder values. These are
  byte-exact OASIS-attested wire formats; any decode→encode regression in
  our Rust codec breaks compliance against the official test corpus.
* ``stubbed/`` — every message, with placeholders replaced by neutral
  fillers via :func:`oasis_codec.resolve_placeholders_stub`. Bigger corpus
  but mixes OASIS-attested bytes with our own conventions for the unknowns.

Each tier produces a ``manifest.json`` keyed by ``source_file`` +
``message_index`` so Rust integration tests can read it directly.

Run from ``kmip/``:

.. code-block:: shell

    python3 conformance/harness/generate_byte_vectors.py
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))  # let `from conformance...` work

from conformance.harness.oasis_codec import (  # noqa: E402
    encode_node,
    parse_transcript_xml,
    resolve_placeholders_stub,
    TtlvNode,
)

KMIP_ROOT = HERE.parent.parent  # kmip/
CORPUS_DIR = KMIP_ROOT / "conformance/oasis_corpus"
OUT_ROOT = KMIP_ROOT / "conformance/oasis_corpus_bytes"


def has_placeholder(n: TtlvNode) -> bool:
    if isinstance(n.value, str) and n.value.startswith("$"):
        return True
    return any(has_placeholder(c) for c in n.children)


def vector_filename(source_file: str, idx: int, message_type: str) -> str:
    """Stable filename: ``<test-id>__<idx>__<Request|Response>.bin``."""
    base = source_file.replace(".xml", "")
    short = "req" if message_type == "RequestMessage" else "rsp"
    return f"{base}__{idx:02d}__{short}.bin"


def write_tier(tier: str, vectors: list[dict]) -> None:
    out_dir = OUT_ROOT / tier
    out_dir.mkdir(parents=True, exist_ok=True)
    for entry in vectors:
        (out_dir / entry["filename"]).write_bytes(entry["bytes"])
    manifest = {
        "schema_version": 1,
        "tier": tier,
        "description": {
            "pristine": (
                "OASIS KMIP 3.0 messages with NO placeholders — byte-exact "
                "against the official conformance corpus. Any decode→encode "
                "regression here breaks compliance."
            ),
            "stubbed": (
                "Full OASIS corpus with $-placeholders replaced by neutral "
                "type-appropriate stubs. Proves codec consistency across "
                "the full structural diversity of KMIP 3.0 but mixes OASIS "
                "bytes with our own conventions."
            ),
        }[tier],
        "spec_reference": "OASIS kmip-profiles-v3.0 §test-cases/{mandatory,optional}",
        "vectors": [
            {
                "filename": e["filename"],
                "source_file": e["source_file"],
                "message_index": e["message_index"],
                "message_type": e["message_type"],
                "size_bytes": len(e["bytes"]),
                "sha256": hashlib.sha256(e["bytes"]).hexdigest(),
            }
            for e in vectors
        ],
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))


def main() -> int:
    pristine: list[dict] = []
    stubbed: list[dict] = []

    for sub in ("mandatory", "optional"):
        for path in sorted((CORPUS_DIR / sub).glob("*.xml")):
            try:
                nodes = parse_transcript_xml(path)
            except Exception as e:
                print(f"  [skip] {path.name}: XML parse {type(e).__name__}: {e}")
                continue
            for idx, n in enumerate(nodes):
                stub = resolve_placeholders_stub(n)
                try:
                    raw = encode_node(stub)
                except Exception as e:
                    print(f"  [skip] {path.name}#{idx} stubbed encode: {e}")
                    continue
                entry = {
                    "filename": vector_filename(path.name, idx, n.tag_name),
                    "source_file": f"{sub}/{path.name}",
                    "message_index": idx,
                    "message_type": n.tag_name,
                    "bytes": raw,
                }
                stubbed.append(entry)
                if not has_placeholder(n):
                    pristine.append(entry)

    write_tier("pristine", pristine)
    write_tier("stubbed", stubbed)

    print(f"  pristine: {len(pristine)} vectors")
    print(f"  stubbed:  {len(stubbed)} vectors")
    print(f"  output:   {OUT_ROOT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
