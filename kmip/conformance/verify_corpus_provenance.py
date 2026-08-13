#!/usr/bin/env python3
"""Prove the checked-in OASIS corpus is the one it claims to be.

The 102 transcripts under ``oasis_corpus/`` are the entire basis of the replay
figure in ``docs/CONFORMANCE_REPORT.md``. Until 2026-08-13 nothing in the tree
recorded which OASIS download they came from, so the only way to answer "are
these current?" was to fetch both editions and diff them by hand. That happened
once, cost an afternoon, and would have had to happen again at the next
revision.

This script makes it a second. It checks two things:

1. **Integrity** — every transcript still hashes to what ``corpus_provenance.json``
   recorded. Catches a corpus edited in place, which would silently move the
   replay figure.
2. **Provenance** — when the source zip is present (it is, under
   ``spec/oasis-kmip-3.0/``), extract it and confirm the corpus is byte-identical
   to what that zip contains. This is the part that actually ties our files to an
   OASIS artefact rather than to our own past self.

Step 2 is skipped, loudly, if the zip is absent — a shallow checkout still gets
the integrity check, but must not be able to *claim* provenance it did not verify.

Usage:
    python3 conformance/verify_corpus_provenance.py
    python3 conformance/verify_corpus_provenance.py --update   # re-record after a deliberate re-baseline
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path

KMIP_ROOT = Path(__file__).resolve().parent.parent
CORPUS_DIR = KMIP_ROOT / "conformance/oasis_corpus"
PROVENANCE = KMIP_ROOT / "conformance/corpus_provenance.json"
SPEC_DIR = KMIP_ROOT / "spec/oasis-kmip-3.0"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def corpus_files() -> list[Path]:
    return sorted(
        list((CORPUS_DIR / "mandatory").glob("*.xml"))
        + list((CORPUS_DIR / "optional").glob("*.xml"))
    )


def relative(path: Path) -> str:
    return str(path.relative_to(CORPUS_DIR))


def current_hashes() -> dict[str, str]:
    return {relative(p): sha256(p) for p in corpus_files()}


def check_integrity(record: dict) -> list[str]:
    """Every recorded transcript is present and unmodified, and no extras."""
    problems: list[str] = []
    recorded: dict[str, str] = record["transcripts"]
    actual = current_hashes()

    for name, want in sorted(recorded.items()):
        got = actual.get(name)
        if got is None:
            problems.append(f"missing transcript: {name}")
        elif got != want:
            problems.append(f"modified transcript: {name}\n    recorded {want}\n    actual   {got}")

    for name in sorted(set(actual) - set(recorded)):
        problems.append(f"unrecorded transcript present: {name}")

    return problems


def check_provenance(record: dict) -> tuple[list[str], bool]:
    """The corpus is byte-identical to the named zip's ``test-cases/`` tree.

    Returns (problems, ran) — ``ran`` is False when the zip is absent, so the
    caller can report "not verified" rather than "verified".
    """
    zip_path = SPEC_DIR / record["source_zip"]
    if not zip_path.exists():
        return [], False

    problems: list[str] = []
    zip_digest = sha256(zip_path)
    if zip_digest != record["source_zip_sha256"]:
        problems.append(
            f"source zip does not match the recorded digest:\n"
            f"    recorded {record['source_zip_sha256']}\n"
            f"    actual   {zip_digest}\n"
            f"    ({zip_path} was replaced — re-run with --update if that was deliberate)"
        )
        # A different zip makes the comparison below meaningless.
        return problems, True

    tmp = Path(tempfile.mkdtemp(prefix="kmip-corpus-provenance-"))
    try:
        with zipfile.ZipFile(zip_path) as zf:
            members = [m for m in zf.namelist() if m.startswith("test-cases/") and m.endswith(".xml")]
            zf.extractall(tmp, members=members)

        extracted = {
            # test-cases/kmip-v3.0/mandatory/FOO.xml -> mandatory/FOO.xml
            "/".join(Path(m).parts[-2:]): tmp / m
            for m in members
        }
        ours = {relative(p): p for p in corpus_files()}

        for name in sorted(set(ours) | set(extracted)):
            if name not in extracted:
                problems.append(f"{name}: in our corpus but not in {record['source_zip']}")
            elif name not in ours:
                problems.append(f"{name}: in {record['source_zip']} but not in our corpus")
            elif ours[name].read_bytes() != extracted[name].read_bytes():
                problems.append(f"{name}: differs from {record['source_zip']}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    return problems, True


def update() -> int:
    record = json.loads(PROVENANCE.read_text()) if PROVENANCE.exists() else {}
    zip_name = record.get("source_zip", "kmip-profiles-v3.0-csd02.zip")
    zip_path = SPEC_DIR / zip_name
    if not zip_path.exists():
        print(f"cannot update: source zip missing at {zip_path}", file=sys.stderr)
        return 1

    record["source_zip"] = zip_name
    record["source_zip_sha256"] = sha256(zip_path)
    record["transcripts"] = current_hashes()
    record["transcript_count"] = len(record["transcripts"])
    PROVENANCE.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(f"recorded {record['transcript_count']} transcripts from {zip_name}")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--update", action="store_true", help="re-record hashes after a deliberate re-baseline")
    args = ap.parse_args(argv[1:])

    if args.update:
        return update()

    if not PROVENANCE.exists():
        print(f"CORPUS PROVENANCE FAIL: no record at {PROVENANCE}", file=sys.stderr)
        return 1

    record = json.loads(PROVENANCE.read_text())
    problems = check_integrity(record)
    prov_problems, prov_ran = check_provenance(record)
    problems += prov_problems

    if problems:
        print("CORPUS PROVENANCE FAIL:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1

    n = record["transcript_count"]
    if prov_ran:
        print(
            f"CORPUS PROVENANCE OK: {n} transcripts, byte-identical to "
            f"{record['source_zip']} ({record['spec_revision']})"
        )
    else:
        print(
            f"CORPUS PROVENANCE PARTIAL: {n} transcripts unmodified, but "
            f"{record['source_zip']} is absent — provenance against the OASIS "
            f"download was NOT verified"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
