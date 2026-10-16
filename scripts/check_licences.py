#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""check_licences.py — the licence labels in this tree match COPYRIGHT.md.

Why (AGPL plan step 9, 2026-10-16): the code written here is AGPL-3.0-only, the
SoftHSM2 files stay BSD-2-Clause and third-party code keeps its own licence. A
label that drifts (a new own file copied with an MIT header, a crate whose
Cargo.toml still says MIT, a new file with no header) is caught here, in CI and
in the local gate, before it ships.

Rules, for tracked files:
  1. Own code files (outside the third-party paths in THIRD_PARTY, without a
     SoftHSM2 or other foreign copyright notice) that carry an
     SPDX-License-Identifier must say AGPL-3.0-only.
  2. Own code files without any SPDX line fail, except those frozen in the
     baseline (scripts/licence_header_baseline.txt), which only shrinks.
  3. Own crates' Cargo.toml (OWN_MANIFESTS) and package.json say AGPL-3.0-only.

Output names the rule and the file, never file contents.

Usage:
  python3 scripts/check_licences.py                   # check
  python3 scripts/check_licences.py --write-baseline  # freeze today's headerless files
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASELINE = ROOT / "scripts" / "licence_header_baseline.txt"

# Third-party code, each under its own licence (COPYRIGHT.md).
THIRD_PARTY = (
    "rust/vendor/", "rust/fips204-patched/", "rust/fips205-patched/", "rust/hbs-lms-patched/",
    "rust/ml-kem-patched/", "rust/xmss-patched/", "rust/classic-mceliece-multi/",
    "src/vendor/", "openpgp/", "openssh-pkcs11/", "strongswan-pkcs11/",
    "kmip/conformance/oasis_corpus/", "engines/notices/texts/", "docs/refs/",
)
THIRD_PARTY_FILES = {
    "src/lib/pkcs11/pkcs11.h", "src/lib/pkcs11/pkcs11f.h", "src/lib/pkcs11/pkcs11t.h",
    "src/bin/keyconv/base64.c", "src/bin/win32/getopt.cpp", "src/bin/win32/getopt.h",
    "tests/json.hpp", "cmake/modules/FindCppUnit.cmake", "cmake/modules/FindSQLite3.cmake",
}
OWN_MANIFESTS = (
    "kmip/Cargo.toml", "openmls-provider/interop/Cargo.toml", "openmls-provider/lib/Cargo.toml",
    "remoting/acceptance/Cargo.toml", "remoting/core/Cargo.toml", "remoting/grpc/Cargo.toml",
    "remoting/proto/Cargo.toml", "remoting/rest/Cargo.toml", "rust/Cargo.toml",
    "rust/pqc-hw/Cargo.toml", "tls/Cargo.toml", "wasm/Cargo.toml",
)
CODE = re.compile(r"\.(rs|c|cc|cpp|h|hpp|py|sh|js|mjs|ts|java|go|swift)$")
SPDX = re.compile(r"SPDX-License-Identifier:\s*([A-Za-z0-9.+-]+(?:\s+(?:AND|OR|WITH)\s+[A-Za-z0-9.+-]+)*)")
COPYRIGHT = re.compile(r"copyright\s*(\(c\)|©|\d{4})", re.I)
OWN_HOLDER = re.compile(r"pqc ?today|pqctoday-org", re.I)


def tracked() -> list[str]:
    out = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"], capture_output=True, check=True).stdout
    return [p for p in out.decode().split("\0") if p]


def third_party(path: str, head: str) -> bool:
    if path in THIRD_PARTY_FILES or path.startswith(THIRD_PARTY) or path.endswith(".patch"):
        return True
    holders = [line for line in head.splitlines() if COPYRIGHT.search(line)]
    return any(not OWN_HOLDER.search(line) for line in holders)


def scan(files: list[str], read) -> tuple[list[tuple[str, str]], list[str]]:
    """Returns (problems, own files without a header)."""
    problems: list[tuple[str, str]] = []
    headerless: list[str] = []
    for p in files:
        if not CODE.search(p):
            continue
        head = read(p)
        if head is None or third_party(p, head):
            continue
        m = SPDX.search(head)
        if not m:
            headerless.append(p)
        elif m.group(1) != "AGPL-3.0-only":
            problems.append(("own file not labelled AGPL-3.0-only", p))
    return problems, headerless


def manifest_problems(read) -> list[tuple[str, str]]:
    problems = []
    for p in OWN_MANIFESTS:
        text = read(p) or ""
        if not re.search(r'^license\s*=\s*"AGPL-3\.0-only"', text, re.M):
            problems.append(("own crate licence field is not AGPL-3.0-only", p))
    pkg = read("package.json") or ""
    if '"license": "AGPL-3.0-only AND BSD-2-Clause"' not in pkg:
        problems.append(("package.json licence is not AGPL-3.0-only AND BSD-2-Clause", "package.json"))
    return problems


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write-baseline", action="store_true")
    args = ap.parse_args(argv)

    def read(p: str) -> str | None:
        try:
            return (ROOT / p).read_bytes()[:8192].decode("utf-8", "replace")
        except OSError:
            return None

    problems, headerless = scan(tracked(), read)
    if args.write_baseline:
        BASELINE.write_text("".join(f"{p}\n" for p in sorted(headerless)))
        print(f"licences: baseline written ({len(headerless)} own files without a header)")
        return 0
    base = set(BASELINE.read_text().split()) if BASELINE.exists() else set()
    problems += [("new own code file without an SPDX header", p) for p in headerless if p not in base]
    problems += manifest_problems(read)
    stale = sorted(base - set(headerless))
    if stale:
        print(f"licences: {len(stale)} baseline entr{'y' if len(stale) == 1 else 'ies'} no longer needed; "
              "run with --write-baseline to shrink it")
    if problems:
        print(f"licences: {len(problems)} problem(s)")
        for rule, p in problems:
            print(f"  {p}: {rule}")
        return 1
    print(f"licences: OK ({len(headerless)} baselined files without a header)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
