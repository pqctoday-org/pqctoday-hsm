#!/usr/bin/env python3
"""Generate byte-exact KMIP TTLV wire-format KAT vectors.

These are the golden references the Phase 2 codec (Rust `src/codec/`) will
proptest-decode and re-encode against. Vectors are hand-derived from the
OASIS KMIP 3.0 spec §9 TTLV encoding rules and §10 normative tag/type/enum
codepoints we extracted into `spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json`.

TTLV encoding (KMIP 3.0 §9.6):
  - Tag      : 3 bytes (big-endian, e.g. 0x420020)
  - Type     : 1 byte  (KMIP type enum, see §9.1.1)
  - Length   : 4 bytes (big-endian unsigned, count of value bytes BEFORE padding)
  - Value    : `length` bytes, then 0-byte padding to next 8-byte boundary
                (except Structure whose value is itself a sequence of TTLVs)

KMIP type codepoints (§9.1.1):
  0x01 Structure          0x07 TextString
  0x02 Integer            0x08 ByteString
  0x03 LongInteger        0x09 DateTime
  0x04 BigInteger         0x0A Interval
  0x05 Enumeration        0x0B DateTimeExtended
  0x06 Boolean

Usage:
  python3 tools/gen_ttlv_kats.py            # write vectors + manifest
  python3 tools/gen_ttlv_kats.py --check    # recompute manifest hashes; no writes

Output:
  kat/ttlv-wire/*.bin       — raw TTLV bytes
  kat/ttlv-wire/manifest.json — index with sha256 + description per vector
"""

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent  # kmip/
OUT_DIR = ROOT / "kat" / "ttlv-wire"


# ── TTLV primitives ──────────────────────────────────────────────────────────

def pad8(buf: bytes) -> bytes:
    """Zero-pad to next 8-byte boundary."""
    if len(buf) % 8 == 0:
        return buf
    return buf + b"\x00" * (8 - len(buf) % 8)


def ttlv_header(tag: int, type_byte: int, length: int) -> bytes:
    """3-byte tag + 1-byte type + 4-byte length (big-endian)."""
    if not (0 <= tag <= 0xFFFFFF):
        raise ValueError(f"tag out of range: {tag:#x}")
    tag_bytes = tag.to_bytes(3, "big")
    return tag_bytes + bytes([type_byte]) + struct.pack(">I", length)


def ttlv_integer(tag: int, value: int) -> bytes:
    """Integer is a signed 32-bit value, padded to 8 bytes total."""
    body = struct.pack(">i", value)
    return ttlv_header(tag, 0x02, 4) + pad8(body)


def ttlv_long_integer(tag: int, value: int) -> bytes:
    body = struct.pack(">q", value)
    return ttlv_header(tag, 0x03, 8) + body  # already 8 bytes


def ttlv_enumeration(tag: int, value: int) -> bytes:
    """Enumeration is a 32-bit unsigned, padded to 8 bytes total."""
    body = struct.pack(">I", value)
    return ttlv_header(tag, 0x05, 4) + pad8(body)


def ttlv_boolean(tag: int, value: bool) -> bytes:
    body = struct.pack(">Q", 1 if value else 0)
    return ttlv_header(tag, 0x06, 8) + body


def ttlv_text_string(tag: int, value: str) -> bytes:
    body = value.encode("utf-8")
    return ttlv_header(tag, 0x07, len(body)) + pad8(body)


def ttlv_structure(tag: int, *children: bytes) -> bytes:
    body = b"".join(children)
    return ttlv_header(tag, 0x01, len(body)) + body  # structure body is already TTLV-aligned


# ── KMIP 3.0 tag codepoints used in these vectors ────────────────────────────
# Source: spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json (extracted from
# the OASIS KMIP 3.0 HTML by tools/extract_kmip_spec.rs).

TAG_REQUEST_MESSAGE         = 0x420078
TAG_REQUEST_HEADER          = 0x420077
TAG_PROTOCOL_VERSION        = 0x420069
TAG_PROTOCOL_VERSION_MAJOR  = 0x42006a
TAG_PROTOCOL_VERSION_MINOR  = 0x42006b
TAG_BATCH_COUNT             = 0x42000d
TAG_BATCH_ITEM              = 0x42000f
TAG_OPERATION               = 0x42005c
TAG_REQUEST_PAYLOAD         = 0x420079
TAG_CRYPTOGRAPHIC_ALGORITHM = 0x420028
TAG_CRYPTOGRAPHIC_LENGTH    = 0x42002a
TAG_OBJECT_TYPE             = 0x420057
TAG_UNIQUE_IDENTIFIER       = 0x420094

# Enum values (from extracted JSON, OASIS KMIP 3.0 §10.2)
OP_CREATE        = 0x00000001
OP_LOCATE        = 0x00000008
OP_GET           = 0x0000000a
OP_DESTROY       = 0x00000014
OP_ENCRYPT       = 0x0000001f
OP_DECRYPT       = 0x00000020

ALGO_AES         = 0x00000003
ALGO_RSA         = 0x00000004
ALGO_ML_KEM_768  = 0x0000003a   # extracted from OASIS 3.0 spec — see KMIP_3_0_DELTA.md
ALGO_ML_DSA_65   = 0x0000003d


# ── Vectors ──────────────────────────────────────────────────────────────────
#
# Each `(filename, description, bytes)` triple becomes one .bin file plus one
# manifest entry. Keep this list small and surgical — the goal is "any future
# codec round-trips these byte-exact." Expand as Phase 2 needs.

def vectors() -> list[tuple[str, str, bytes]]:
    return [
        # 1 — minimal Integer: BatchCount = 1
        (
            "01-integer-batch-count-1.bin",
            "TTLV Integer: BatchCount tag (0x42000d) wrapping the value 1. "
            "Demonstrates 4-byte value + 4-byte zero-padding to 8-byte alignment.",
            ttlv_integer(TAG_BATCH_COUNT, 1),
        ),
        # 2 — minimal Enumeration: Operation = Create
        (
            "02-enum-operation-create.bin",
            "TTLV Enumeration: Operation tag (0x42005c) value Create (0x00000001).",
            ttlv_enumeration(TAG_OPERATION, OP_CREATE),
        ),
        # 3 — PQC enum: CryptographicAlgorithm = ML-KEM-768 (KMIP 3.0 NEW)
        (
            "03-enum-cryptographic-algorithm-ml-kem-768.bin",
            "TTLV Enumeration: CryptographicAlgorithm tag (0x420028) value "
            "ML-KEM-768 (0x0000003a). This is the first PQC algorithm "
            "enumerated by KMIP 3.0; codepoint extracted from OASIS spec. "
            "Round-tripping this vector validates the codec against the "
            "PQC additions in §10.2.6.",
            ttlv_enumeration(TAG_CRYPTOGRAPHIC_ALGORITHM, ALGO_ML_KEM_768),
        ),
        # 4 — Boolean true
        (
            "04-boolean-true.bin",
            "TTLV Boolean: arbitrary tag (0x420078, here used purely as a "
            "test fixture) wrapping the value true. Boolean is 8-byte body.",
            ttlv_boolean(TAG_REQUEST_MESSAGE, True),
        ),
        # 5 — TextString with non-aligned length (forces padding)
        (
            "05-text-string-padded.bin",
            "TTLV TextString: UniqueIdentifier tag (0x420094) wrapping the "
            "5-byte string 'pqc-1'. Value is 5 bytes → 3-byte zero-padding "
            "to 8-byte alignment.",
            ttlv_text_string(TAG_UNIQUE_IDENTIFIER, "pqc-1"),
        ),
        # 6 — Structure: minimal ProtocolVersion = (3, 0)
        (
            "06-structure-protocol-version-3-0.bin",
            "TTLV Structure: ProtocolVersion tag (0x420069) containing two "
            "child Integers — ProtocolVersionMajor=3 (0x42006a) and "
            "ProtocolVersionMinor=0 (0x42006b). Validates nested TTLV "
            "decoding + structure-length accounting.",
            ttlv_structure(
                TAG_PROTOCOL_VERSION,
                ttlv_integer(TAG_PROTOCOL_VERSION_MAJOR, 3),
                ttlv_integer(TAG_PROTOCOL_VERSION_MINOR, 0),
            ),
        ),
    ]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hex_preview(data: bytes, max_bytes: int = 32) -> str:
    """Space-separated hex string for the first N bytes."""
    head = data[:max_bytes]
    return " ".join(f"{b:02x}" for b in head)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="Verify on-disk vectors match the in-tool definitions; do not write.")
    args = ap.parse_args()

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    entries = []
    fail = 0
    for filename, description, data in vectors():
        path = OUT_DIR / filename
        digest = sha256(data)
        entry = {
            "filename": filename,
            "description": description,
            "size_bytes": len(data),
            "sha256": digest,
            "hex_preview": hex_preview(data),
        }
        entries.append(entry)

        if args.check:
            if not path.exists():
                print(f"MISSING  {filename}")
                fail += 1
                continue
            on_disk = path.read_bytes()
            if on_disk != data:
                print(f"DRIFT    {filename} — on-disk sha256={sha256(on_disk)[:16]} vs in-tool={digest[:16]}")
                fail += 1
            else:
                print(f"OK       {filename} ({len(data)} bytes, sha256={digest[:16]}...)")
        else:
            path.write_bytes(data)
            print(f"WRITE    {filename} ({len(data)} bytes, sha256={digest[:16]}...)")

    manifest = {
        "schema_version": 1,
        "description": (
            "Byte-exact KMIP TTLV wire-format KAT vectors. Generated by "
            "tools/gen_ttlv_kats.py from the OASIS KMIP 3.0 spec §9 "
            "encoding rules and the extracted §10 codepoints. Phase 2 "
            "codec (src/codec/) round-trips every entry below."
        ),
        "spec_reference": "OASIS KMIP 3.0 §9.6 (TTLV examples) + §10 (normative codepoints)",
        "codepoint_source": "spec/oasis-kmip-3.0/kmip-spec-3.0-tags-enums.json",
        "vectors": entries,
    }

    if not args.check:
        manifest_path = OUT_DIR / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
        print(f"\nWRITE    manifest.json ({len(entries)} vectors indexed)")

    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
