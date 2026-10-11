#!/usr/bin/env python3
"""Public-boundary scan: block NEW private paths in this public repository.

Owner decision 2026-10-11: findings that already exist are accepted as they
are and frozen in a baseline; anything new fails. This is the same check, with
the same generic rules and the same baseline format, as the Hub's
`scripts/ci/leak-guard.ts --tree`.

What it does
  Scans every tracked text file (or every file under --tree DIR) with a small
  set of generic leak rules (references to the private companion
  repositories, local home-directory paths, temporary session paths, the
  evidence-cache folder, internal run identifiers and internal folders) and
  compares per-file, per-rule COUNTS with a committed baseline. A new file, a
  new rule or a higher count fails in --mode enforce. The baseline only ever
  shrinks: --update-baseline keeps the lower of the two counts and refuses to
  raise one unless --allow-increase is given (first creation, or a reviewed
  move). The baseline holds paths, rule ids and counts only, never text.

Output is redacted: a finding names the rule and the file, never the match.

Usage
  python3 scripts/check_public_boundary.py --tree . --tracked \
      --baseline scripts/public_boundary_baseline.json --mode enforce
  python3 scripts/check_public_boundary.py --tree . --tracked \
      --baseline scripts/public_boundary_baseline.json --update-baseline
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

RULES: list[tuple[str, re.Pattern[str]]] = [
    ("private-repo", re.compile(r"pqctoday-(priv|admin)\b", re.I)),
    ("evidence-cache", re.compile(r"local-evidence-cache", re.I)),
    ("home-path", re.compile(r"/Users/[^/\r\n]+/", re.I)),
    ("session-tmp-path", re.compile(r"/private/tmp/claude-", re.I)),
    ("run-id", re.compile(r"\bcx-20\d{6}T\d{6}Z", re.I)),
    ("internal-log", re.compile(r"\bcodex-log\b", re.I)),
    ("internal-folder", re.compile(r"(?<![\w-])maintenance/(lineage|runs|goldens|runbooks)\b", re.I)),
    ("agent-config-path", re.compile(r"\.claude/(skills|agents|projects)\b", re.I)),
]

# Files that necessarily contain the patterns themselves, and the baseline.
SELF = {
    "scripts/check_public_boundary.py",
    "tests/test_check_public_boundary.py",
    "scripts/public_boundary_baseline.json",
}
MAX_FILE = 256 * 1024 * 1024
SKIP_DIRS = {".git", "node_modules"}
BINARY_EXT = re.compile(
    r"\.(wasm|png|jpe?g|gif|webp|avif|ico|woff2?|ttf|otf|eot|gz|br|zip|pdf|mp4|webm|mp3|onnx|bin|so|a|o|dylib|rlib)$",
    re.I,
)

Counts = dict[str, dict[str, int]]


def baseline_key(path: str) -> str:
    """Bundler hashes and dated copies of a data file form one family."""
    path = re.sub(r"-[A-Za-z0-9_-]{8}(?=\.(?:js|mjs|css)$)", "-#", path, count=1)
    return re.sub(r"_\d{8}(?:_r\d+)?(?=(?:-#)?\.[A-Za-z0-9]+$)", "_#", path, count=1)


def count_text(text: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for line in re.split(r"\r?\n", text):
        for rule, pattern in RULES:
            if pattern.search(line):
                out[rule] = out.get(rule, 0) + 1
    return out


def list_tree(root: str) -> list[str]:
    found: list[str] = []
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not os.path.islink(os.path.join(base, d))]
        for name in files:
            full = os.path.join(base, name)
            if not os.path.islink(full):
                found.append(os.path.relpath(full, root).replace(os.sep, "/"))
    return found


def list_tracked(root: str) -> list[str]:
    raw = subprocess.run(
        ["git", "-C", root, "ls-files", "-z"], check=True, capture_output=True
    ).stdout.decode("utf-8", "surrogateescape")
    return [p for p in raw.split("\0") if p]


def scan_tree(root: str, tracked: bool = False) -> tuple[Counts, list[tuple[str, str]]]:
    counts: Counts = {}
    skipped: list[tuple[str, str]] = []
    for rel in list_tracked(root) if tracked else list_tree(root):
        if rel in SELF or BINARY_EXT.search(rel):
            continue
        full = os.path.join(root, rel)
        if os.path.islink(full) or not os.path.isfile(full):
            continue  # symlink, submodule entry or directory
        if os.path.getsize(full) > MAX_FILE:
            skipped.append((rel, "too large"))
            continue
        with open(full, "rb") as handle:
            data = handle.read()
        if b"\0" in data[:8192]:
            continue  # binary
        found = count_text(data.decode("utf-8", "replace"))
        key = baseline_key(rel)
        for rule, n in found.items():
            family = counts.setdefault(key, {})
            family[rule] = max(family.get(rule, 0), n)
    return counts, skipped


def compare(now: Counts, base: Counts) -> tuple[list[tuple[str, str, int, int]], list[tuple[str, str, int, int]]]:
    regressions, improved = [], []
    for file, rules in now.items():
        for rule, n in rules.items():
            was = base.get(file, {}).get(rule, 0)
            if n > was:
                regressions.append((file, rule, was, n))
    for file, rules in base.items():
        for rule, was in rules.items():
            n = now.get(file, {}).get(rule, 0)
            if n < was:
                improved.append((file, rule, was, n))
    return regressions, improved


def ratchet(now: Counts, base: Counts) -> Counts:
    out: Counts = {}
    for file, rules in base.items():
        for rule, was in rules.items():
            n = min(was, now.get(file, {}).get(rule, 0))
            if n > 0:
                out.setdefault(file, {})[rule] = n
    return out


def write_baseline(path: str, files: Counts) -> int:
    doc = {"version": 1, "rules": [r for r, _ in RULES], "files": files}
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(doc, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return sum(sum(r.values()) for r in files.values())


def read_baseline(path: str) -> Counts:
    with open(path, encoding="utf-8") as handle:
        doc = json.load(handle)
    if doc.get("version") != 1 or not isinstance(doc.get("files"), dict):
        raise SystemExit(f"{path}: not a version 1 baseline")
    return doc["files"]


def format_result(regressions, improved, skipped, mode: str) -> str:
    lines = []
    if not regressions:
        lines.append("public-boundary: no new findings against the baseline")
    else:
        note = " (report-only, not blocking)" if mode == "report" else ""
        lines.append(f"public-boundary: {len(regressions)} new or increased finding(s){note}")
        lines += [f"  {rule} @ {file}: {was} -> {n}" for file, rule, was, n in regressions]
    if improved:
        lines.append(f"{len(improved)} baseline entries fell; run with --update-baseline to ratchet down")
    if skipped:
        lines.append(f"not scanned ({len(skipped)}): " + ", ".join(f"{f} [{why}]" for f, why in skipped))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tree", required=True, help="directory to scan")
    ap.add_argument("--tracked", action="store_true", help="only git-tracked files of --tree")
    ap.add_argument("--baseline", required=True)
    ap.add_argument("--mode", choices=("report", "enforce"), default="report")
    ap.add_argument("--update-baseline", action="store_true")
    ap.add_argument("--allow-increase", action="store_true")
    args = ap.parse_args(argv)

    counts, skipped = scan_tree(args.tree, args.tracked)
    exists = os.path.exists(args.baseline)

    if args.update_baseline:
        if not exists and not args.allow_increase:
            print("public-boundary: no baseline yet; create the first one with --allow-increase", file=sys.stderr)
            return 2
        base = read_baseline(args.baseline) if exists else {}
        regressions, improved = compare(counts, base)
        if regressions and not args.allow_increase:
            print(format_result(regressions, improved, skipped, "enforce"))
            print("public-boundary: refusing to raise the baseline; fix the findings or use --allow-increase", file=sys.stderr)
            return 1
        total = write_baseline(args.baseline, counts if args.allow_increase else ratchet(counts, base))
        print(f"public-boundary: baseline written ({total} finding(s) frozen)")
        return 0

    if not exists:
        print(f"public-boundary: baseline {args.baseline} not found", file=sys.stderr)
        return 2
    regressions, improved = compare(counts, read_baseline(args.baseline))
    text = format_result(regressions, improved, skipped, args.mode)
    print(text)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(f"\n{text}\n")
    return 1 if args.mode == "enforce" and regressions else 0


if __name__ == "__main__":
    sys.exit(main())
