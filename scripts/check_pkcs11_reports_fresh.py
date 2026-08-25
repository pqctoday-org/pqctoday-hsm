#!/usr/bin/env python3
"""Report-staleness guard for the checked-in PKCS#11 v3.2 conformance
reports (cpp_compliance_report.{json,md}, rust/RUST_P11_V32_CONFORMANCE_REPORT.md).

Modeled directly on kmip/conformance/check_report_fresh.py's PROVEN
contract: the signal that matters is content drift (a fresh run producing
different PASS/FAIL/category rows than what's committed), not whether the
report's stamped commit hash equals literal `git rev-parse HEAD`. An
earlier version of this script required exact HEAD equality and false-
positived on every unrelated commit made after the report was generated
(a docs fix, a different subsystem) even though the report's content was
still perfectly accurate — the same trap the KMIP guard's own comments
warn about. Fixed before this script's first real use.

The PKCS#11 reports had no staleness guard at all before this: cpp_
compliance_report.* sat a month stale with an empty engine_commit field
and 15 missing categories; the Rust report's own header admitted a
"refresh" that never re-ran the harness, measuring an engine commit 45
source-commits behind HEAD. (2026-08-23)

This does NOT regenerate anything. Run it immediately after the report
generator (ctest / p11_v32_compliance_test, or node test_p11_conformance.js)
has already written a fresh copy into the working tree. Exit 0 means a
fresh run's content matches what's committed (commit hash and timestamp
excluded — those legitimately change every run) and the commit field is
at least present and well-formed; exit 1 means content drift, with the
diff printed to stderr.

Usage:
    python3 scripts/check_pkcs11_reports_fresh.py --cpp
    python3 scripts/check_pkcs11_reports_fresh.py --rust
    python3 scripts/check_pkcs11_reports_fresh.py --cpp --rust
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def git_root() -> Path:
    out = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout.strip()
    return Path(out)


def head_commit(short: bool = False) -> str:
    args = ["git", "rev-parse"] + (["--short"] if short else []) + ["HEAD"]
    return subprocess.run(args, cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()


def head_blob(root: Path, rel: Path) -> str | None:
    res = subprocess.run(["git", "show", f"HEAD:{rel.as_posix()}"], cwd=root, capture_output=True, text=True)
    return res.stdout if res.returncode == 0 else None


# ── C++ report (cpp_compliance_report.json / .md) ──────────────────────────

_MD_DATE = re.compile(r"^\*\*Date:\*\* .*$", re.MULTILINE)
_MD_ENGINE = re.compile(r"^\*\*Engine:\*\* .*$", re.MULTILINE)
_MD_COMMIT = re.compile(r"^\*\*Engine commit:\*\* `([0-9a-f]+)`", re.MULTILINE)


def normalize_cpp_md(text: str) -> str:
    text = _MD_DATE.sub("**Date:** <NORMALIZED>", text)
    text = _MD_ENGINE.sub("**Engine:** <NORMALIZED>", text)
    text = _MD_COMMIT.sub("**Engine commit:** `<NORMALIZED>`", text)
    return text


_HEX = re.compile(r"^[0-9a-f]{7,40}$")


def normalize_cpp_json(text: str) -> tuple[str, str | None]:
    """Returns (normalized_json_text, engine_commit_found)."""
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return text, None
    summary = obj.get("_summary", {})
    commit = summary.get("engine_commit")
    if isinstance(obj, dict) and "_summary" in obj:
        obj["_summary"]["engine"] = "<NORMALIZED>"
        obj["_summary"]["engine_commit"] = "<NORMALIZED>"
    return json.dumps(obj, indent=4, sort_keys=False), commit


def check_cpp(root: Path) -> list[str]:
    problems: list[str] = []
    json_path = root / "cpp_compliance_report.json"
    md_path = root / "cpp_compliance_report.md"

    if not json_path.exists() or not md_path.exists():
        return ["cpp_compliance_report.{json,md}: working-tree report missing — "
                "run p11_v32_compliance_test --report ./cpp_compliance_report first"]

    fresh_json_text = json_path.read_text()
    fresh_norm_json, fresh_commit = normalize_cpp_json(fresh_json_text)
    if not fresh_commit or not _HEX.match(fresh_commit):
        problems.append(
            f"cpp_compliance_report.json: _summary.engine_commit is "
            f"'{fresh_commit}' — empty or not a commit hash. Regenerate with "
            f"--engine-commit \"$(git rev-parse HEAD)\"."
        )

    committed_json = head_blob(root, Path("cpp_compliance_report.json"))
    if committed_json is None:
        problems.append("cpp_compliance_report.json: not committed at HEAD")
    else:
        committed_norm_json, _ = normalize_cpp_json(committed_json)
        if committed_norm_json != fresh_norm_json:
            problems.append(
                "cpp_compliance_report.json: committed report is STALE — "
                "differs from the working-tree run (engine path excluded). "
                "Re-run the suite and commit the regenerated report."
            )

    fresh_md = normalize_cpp_md(md_path.read_text())
    committed_md = head_blob(root, Path("cpp_compliance_report.md"))
    if committed_md is None:
        problems.append("cpp_compliance_report.md: not committed at HEAD")
    elif normalize_cpp_md(committed_md) != fresh_md:
        problems.append(
            "cpp_compliance_report.md: committed report is STALE — differs "
            "from the working-tree run (date/engine-path excluded)."
        )

    return problems


# ── Rust report (rust/RUST_P11_V32_CONFORMANCE_REPORT.md) ──────────────────

_RUST_HEADER = re.compile(
    r"\*\*Engine commit:\*\* `([0-9a-f]+)` · \*\*Generated:\*\* [^\s]+"
)


def normalize_rust_md(text: str) -> tuple[str, str | None]:
    m = _RUST_HEADER.search(text)
    commit = m.group(1) if m else None
    text = _RUST_HEADER.sub("**Engine commit:** `<NORMALIZED>` · **Generated:** <NORMALIZED>", text)
    return text, commit


def check_rust(root: Path) -> list[str]:
    problems: list[str] = []
    path = root / "rust" / "RUST_P11_V32_CONFORMANCE_REPORT.md"

    if not path.exists():
        return ["rust/RUST_P11_V32_CONFORMANCE_REPORT.md: working-tree report missing — "
                "run `scripts/local-gate.sh --rust-p11` (or node test_p11_conformance.js directly) first"]

    fresh_text = path.read_text()
    fresh_norm, fresh_commit = normalize_rust_md(fresh_text)
    if not fresh_commit or not _HEX.match(fresh_commit):
        problems.append(
            f"rust/RUST_P11_V32_CONFORMANCE_REPORT.md: header commit "
            f"'{fresh_commit}' — empty or not a commit hash. Regenerate via "
            f"scripts/local-gate.sh --rust-p11."
        )

    committed = head_blob(root, Path("rust/RUST_P11_V32_CONFORMANCE_REPORT.md"))
    if committed is None:
        problems.append("rust/RUST_P11_V32_CONFORMANCE_REPORT.md: not committed at HEAD")
    else:
        committed_norm, _ = normalize_rust_md(committed)
        if committed_norm != fresh_norm:
            problems.append(
                "rust/RUST_P11_V32_CONFORMANCE_REPORT.md: committed report is "
                "STALE — differs from the working-tree run (commit/timestamp "
                "excluded). Re-run and commit the regenerated report."
            )

    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cpp", action="store_true")
    ap.add_argument("--rust", action="store_true")
    args = ap.parse_args()
    if not args.cpp and not args.rust:
        ap.error("pass --cpp, --rust, or both")

    root = git_root()
    problems: list[str] = []
    if args.cpp:
        problems += check_cpp(root)
    if args.rust:
        problems += check_rust(root)

    if problems:
        print("PKCS#11 REPORT STALENESS GUARD FAILED:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print("PKCS#11 REPORT STALENESS GUARD OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
