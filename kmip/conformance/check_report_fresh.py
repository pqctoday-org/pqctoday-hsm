#!/usr/bin/env python3
"""Report-staleness guard for the checked-in OASIS replay artifacts.

``REPLAY_REPORT.{md,json}`` are committed artifacts. They were once stale
at 1 test, which hid a 92->89 Locate regression. This guard fails CI if
the committed report differs from a fresh ``dispatcher_replay.py`` run,
forcing contributors to commit a current report.

The reports carry ONE volatile field each that legitimately changes every
run and would otherwise make the guard always-red:

  * ``REPLAY_REPORT.md``   — the ``Generated: <UTC timestamp>`` line.
  * ``REPLAY_REPORT.json`` — the ``"generated_at": <epoch>`` field.

This script normalizes ONLY those two fields to a fixed sentinel, then
compares the freshly-generated working-tree report against the version at
``HEAD``. Everything else (every PASS/FAIL/SKIP, every per-test row) must
match byte-for-byte. Run this AFTER ``dispatcher_replay.py`` has
regenerated the working-tree report.

Usage (from ``kmip/``):

    python3 conformance/check_report_fresh.py

Exit 0 = committed report matches the fresh run (modulo timestamp);
exit 1 = stale (a diff is printed to stderr).
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
KMIP_ROOT = HERE.parent
MD = HERE / "REPLAY_REPORT.md"
JSON = HERE / "REPLAY_REPORT.json"


def _git_root() -> Path:
    out = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=KMIP_ROOT, capture_output=True, text=True, check=True,
    ).stdout.strip()
    return Path(out)


_MD_TS = re.compile(r"^Generated: .*$", re.MULTILINE)


def normalize_md(text: str) -> str:
    return _MD_TS.sub("Generated: <NORMALIZED>", text)


def normalize_json(text: str) -> str:
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return text
    if isinstance(obj, dict):
        obj["generated_at"] = 0
    # Re-serialize with the same formatting the harness uses (indent=2)
    # so only semantic differences survive normalization.
    return json.dumps(obj, indent=2)


def head_blob(rel_path: Path) -> str | None:
    res = subprocess.run(
        ["git", "show", f"HEAD:{rel_path.as_posix()}"],
        cwd=KMIP_ROOT, capture_output=True, text=True,
    )
    if res.returncode != 0:
        return None
    return res.stdout


def check(path: Path, rel: Path, normalize) -> list[str]:
    problems: list[str] = []
    if not path.exists():
        return [f"{rel}: working-tree report missing — run dispatcher_replay.py"]
    committed = head_blob(rel)
    if committed is None:
        return [f"{rel}: not committed at HEAD (commit the fresh report)"]
    fresh_n = normalize(path.read_text())
    committed_n = normalize(committed)
    if fresh_n != committed_n:
        problems.append(
            f"{rel}: committed report is STALE — differs from a fresh "
            f"dispatcher_replay.py run (timestamp excluded). Re-run the "
            f"replay and commit the regenerated report."
        )
    return problems


def main() -> int:
    root = _git_root()
    md_rel = MD.relative_to(root)
    json_rel = JSON.relative_to(root)
    problems = check(MD, md_rel, normalize_md) + check(JSON, json_rel, normalize_json)
    if problems:
        print("REPORT STALENESS GUARD FAILED:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print("REPORT STALENESS GUARD OK: committed REPLAY_REPORT.{md,json} match a fresh run")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
