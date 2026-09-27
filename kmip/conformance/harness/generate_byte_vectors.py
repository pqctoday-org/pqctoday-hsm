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

    python3 conformance/harness/generate_byte_vectors.py            # regenerate
    python3 conformance/harness/generate_byte_vectors.py --check    # verify only

``--check`` re-derives every vector from the XML corpus in memory and compares
it against what is committed, exiting non-zero on any drift. It writes nothing.

This exists because nothing else could see that drift. The Rust suites
(``oasis_codec_roundtrip.rs`` and friends) round-trip the committed ``.bin``
files through our own codec, so a vector that no longer matches the XML it
came from still round-trips perfectly — the corpus is never consulted. Four
vectors were stale from the 2026-07 CSD02 refresh until 2026-09-06 and were
found only by accident, when an unrelated regeneration changed their size.
``verify_corpus_provenance.py`` answers the adjacent question (is the XML the
OASIS XML?); this answers "are the vectors what that XML actually produces?".
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


def build_tiers() -> tuple[list[dict], list[dict]]:
    """Derive both tiers from the XML corpus, writing nothing."""
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

    return pristine, stubbed


def check_tier(tier: str, vectors: list[dict]) -> list[str]:
    """Compare freshly-derived vectors against what is committed.

    Checks three things, because each catches a different way to drift:
      * the committed ``.bin`` equals the bytes the corpus produces today
        (a stale vector, which is the case that actually happened);
      * the manifest's ``sha256``/``size_bytes`` match those same bytes
        (a hand-edited or half-regenerated manifest);
      * neither side carries a vector the other does not (added/removed
        transcripts).
    """
    problems: list[str] = []
    out_dir = OUT_ROOT / tier
    manifest_path = out_dir / "manifest.json"

    if not manifest_path.is_file():
        return [f"{tier}: manifest.json missing — run without --check to generate"]
    try:
        manifest = json.loads(manifest_path.read_text())
    except json.JSONDecodeError as e:
        return [f"{tier}: manifest.json is not valid JSON: {e}"]

    committed = {e["filename"]: e for e in manifest.get("vectors", [])}
    fresh = {e["filename"]: e for e in vectors}

    for name in sorted(set(committed) - set(fresh)):
        problems.append(f"{tier}/{name}: committed but the corpus no longer produces it")
    for name in sorted(set(fresh) - set(committed)):
        problems.append(f"{tier}/{name}: the corpus produces it but it is not committed")

    for name in sorted(set(fresh) & set(committed)):
        raw = fresh[name]["bytes"]
        digest = hashlib.sha256(raw).hexdigest()
        entry = committed[name]

        if entry.get("sha256") != digest:
            problems.append(
                f"{tier}/{name}: manifest sha256 {entry.get('sha256')} "
                f"but the corpus now yields {digest}"
            )
        if entry.get("size_bytes") != len(raw):
            problems.append(
                f"{tier}/{name}: manifest size {entry.get('size_bytes')} "
                f"but the corpus now yields {len(raw)}"
            )

        blob = out_dir / name
        if not blob.is_file():
            problems.append(f"{tier}/{name}: listed in the manifest but the .bin is missing")
            continue
        on_disk = blob.read_bytes()
        if on_disk != raw:
            problems.append(
                f"{tier}/{name}: committed .bin is {len(on_disk)} bytes, "
                f"the corpus yields {len(raw)} — STALE, regenerate"
            )

    return problems


def main() -> int:
    check_only = "--check" in sys.argv[1:]
    pristine, stubbed = build_tiers()

    if check_only:
        problems = check_tier("pristine", pristine) + check_tier("stubbed", stubbed)
        if problems:
            print(f"VECTOR/CORPUS DRIFT — {len(problems)} problem(s):", file=sys.stderr)
            for p in problems:
                print(f"  {p}", file=sys.stderr)
            print(
                "\nRegenerate with:  python3 conformance/harness/generate_byte_vectors.py",
                file=sys.stderr,
            )
            return 1
        print(
            f"VECTOR/CORPUS CHECK OK — {len(pristine)} pristine + {len(stubbed)} stubbed "
            "vectors match the XML corpus byte-for-byte"
        )
        return 0

    write_tier("pristine", pristine)
    write_tier("stubbed", stubbed)

    print(f"  pristine: {len(pristine)} vectors")
    print(f"  stubbed:  {len(stubbed)} vectors")
    print(f"  output:   {OUT_ROOT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
