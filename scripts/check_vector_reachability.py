#!/usr/bin/env python3
"""Every committed test-vector file must be loaded by something.

Plan item 2.C (ruled 2026-09-26: fail, no allowlist). A vector file that no
runner loads is worse than no file: it looks like coverage. This repo had 20
NIST EdDSA pre-hash vectors whose only reference was a COMMENT in a checker
script (#276), and a 102-file XML corpus that the existing, narrower guard
(`kmip/tests/acvp_roundtrip.rs::no_orphan_vector_files`, `.json` under
`kmip/kat/` only) could not see.

Scope, stated because a guard's scope is load-bearing: every tracked file with
a vector-like extension under the VECTOR_ROOTS below. A file is REACHABLE when
a code line (not a comment) in a tracked source file outside the vector roots
names it — by file name, or by its directory for loaders that read a whole
directory. Mentions in docs, comments, provenance notes and this script do not
count. Out-of-scope vector-like files elsewhere are REPORTED, not skipped.

Exit 0: every in-scope vector file is reachable. Exit 1: the orphans, named.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VECTOR_ROOTS = (
    "tests/acvp/",
    "kmip/kat/",
    "rust/kat/",
    "openmls-provider/lib/test-vectors/",
    "kmip/conformance/oasis_corpus/",
    "kmip/conformance/pqc_corpus/",
)
VECTOR_EXT = (".json", ".rsp", ".req", ".bin", ".xml", ".txt")
SOURCE_EXT = (".rs", ".mjs", ".js", ".ts", ".py", ".sh", ".cpp", ".cc", ".h", ".c", ".cmake", ".toml", ".yml", ".yaml")
SOURCE_NAMES = ("CMakeLists.txt", "Makefile")
# Files whose mentions of vector names are not loads.
NOT_A_LOADER = {
    "scripts/check_vector_reachability.py",
    "scripts/check_acvp_provenance.py",
}
COMMENT = re.compile(r"^\s*(//|#|\*|/\*|--|;)")


def tracked() -> list[str]:
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True)
    return out.stdout.splitlines()


def main() -> int:
    files = tracked()
    in_scope = [f for f in files if f.startswith(VECTOR_ROOTS) and f.endswith(VECTOR_EXT)]
    # Vector-like files outside the roots: reported so the scope is visible.
    elsewhere = [
        f for f in files
        if f.endswith(VECTOR_EXT)
        and not f.startswith(VECTOR_ROOTS)
        and re.search(r"(acvp|kat|wycheproof|cavp|test[-_]?vectors?|nist_)", f, re.I)
    ]
    sources = [
        f for f in files
        if (f.endswith(SOURCE_EXT) or f.rsplit("/", 1)[-1] in SOURCE_NAMES)
        and not f.startswith(VECTOR_ROOTS)
        and f not in NOT_A_LOADER
    ]
    code_lines: list[str] = []
    for f in sources:
        try:
            text = (ROOT / f).read_text(errors="replace")
        except OSError:
            continue
        code_lines.extend(l for l in text.splitlines() if not COMMENT.match(l))
    blob = "\n".join(code_lines)

    orphans = []
    for f in in_scope:
        name = f.rsplit("/", 1)[-1]
        parent = f.rsplit("/", 1)[0]
        # Directory loaders name the directory relative to some base; accept
        # the last one or two path components (e.g. "kat/aes", "mandatory").
        parts = parent.split("/")
        dir_keys = {"/".join(parts[-2:]), "/".join(parts[-3:])}
        # A bare directory name counts only when it is distinctive (has "_",
        # "-" or a digit): "pqc_corpus" does, "mandatory" would match prose.
        if re.search(r"[_\-0-9]", parts[-1]):
            dir_keys.add(parts[-1])
        if name in blob or any(k and k in blob for k in dir_keys):
            continue
        orphans.append(f)

    print(f"vector reachability: {len(in_scope)} in-scope files under {', '.join(VECTOR_ROOTS)}; "
          f"{len(sources)} source files searched (code lines only)")
    if elsewhere:
        print(f"  out of scope, reported: {len(elsewhere)} vector-like files elsewhere "
              f"(e.g. {', '.join(elsewhere[:3])})")
    if orphans:
        print(f"FAIL — {len(orphans)} vector file(s) that nothing loads:", file=sys.stderr)
        for f in orphans:
            print(f"  {f}", file=sys.stderr)
        return 1
    print("OK — every in-scope vector file is loaded by code")
    return 0


if __name__ == "__main__":
    sys.exit(main())
