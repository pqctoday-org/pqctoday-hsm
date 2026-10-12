#!/usr/bin/env python3
"""Package the browser engine bundles of this repository for a release.

Why: the Hub ships WebAssembly engines that are built here. Until now the build
scripts copied them into a sibling Hub checkout and a JSON file there claimed
which commit each came from. This tool turns that into a release a consumer can
pin and verify without any sibling: one tarball per bundle, a manifest with the
SHA-256 of every file, and a SHA256SUMS list. Owner decision 2026-10-12:
GitHub release assets, a separate numbered tag series (engines-N), an exact
version per engine.

What it does NOT do: it never uploads. `package` writes files into --out and
prints the exact `gh release create` command; running it is a separate,
deliberate act (a release is public). It does not rebuild anything: the files
are built where the toolchain lives, and the release attests which files were
published, not that they rebuild bit-for-bit from source.

Input layout: --from is any directory laid out the way the consumer expects
(paths in engines/bundles.json are consumer-relative, e.g. public/wasm/...).
Today that is the Hub checkout; the goal is a staging folder the build scripts
fill.

Usage
  python3 scripts/publish_engines.py package --from DIR --out DIR --tag engines-1 \
      [--provenance FILE | --commit NAME=SHA ... | --commit-head] [--only NAME ...]
  python3 scripts/publish_engines.py verify --manifest FILE (--tarballs DIR | --tree DIR)
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUNDLES_FILE = os.path.join(ROOT, "engines", "bundles.json")
TAG_RE = re.compile(r"^engines-[1-9][0-9]*$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class ToolError(Exception):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_bundles(path: str = BUNDLES_FILE) -> list[dict]:
    with open(path, encoding="utf-8") as handle:
        doc = json.load(handle)
    if doc.get("schema") != 1 or not isinstance(doc.get("bundles"), list):
        raise ToolError(f"{path}: not a schema 1 bundle declaration")
    return doc["bundles"]


def expand(root: str, entry: str) -> list[str]:
    """Consumer-relative files for one declared entry (a file, or a folder ending in /)."""
    if not entry.endswith("/"):
        if not os.path.isfile(os.path.join(root, entry)):
            raise ToolError(f"declared file not found under --from: {entry}")
        return [entry]
    base = os.path.join(root, entry)
    if not os.path.isdir(base):
        raise ToolError(f"declared folder not found under --from: {entry}")
    found = []
    for folder, _dirs, names in os.walk(base):
        for name in names:
            found.append(os.path.relpath(os.path.join(folder, name), root).replace(os.sep, "/"))
    if not found:
        raise ToolError(f"declared folder is empty: {entry}")
    return sorted(found)


def bundle_files(root: str, bundle: dict) -> list[str]:
    files: list[str] = []
    for entry in bundle["files"]:
        files.extend(expand(root, entry))
    return sorted(set(files))


def deterministic_tarball(root: str, files: list[str]) -> bytes:
    """Same input, same bytes: sorted names, zeroed owner and times, gzip without a timestamp."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as tar:
        for rel in files:
            full = os.path.join(root, rel)
            info = tarfile.TarInfo(rel)
            info.size = os.path.getsize(full)
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mode = 0o755 if os.access(full, os.X_OK) else 0o644
            with open(full, "rb") as handle:
                tar.addfile(info, handle)
    out = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=out, mtime=0, compresslevel=9) as gz:
        gz.write(raw.getvalue())
    return out.getvalue()


def resolve_commits(args, names: list[str]) -> dict[str, str]:
    commits: dict[str, str] = {}
    if args.provenance:
        with open(args.provenance, encoding="utf-8") as handle:
            for b in json.load(handle).get("bundles", []):
                if "name" in b and "hsmCommit" in b:
                    commits[b["name"]] = b["hsmCommit"]
    for pair in args.commit or []:
        name, _, sha = pair.partition("=")
        commits[name] = sha
    if args.commit_head:
        head = subprocess.run(
            ["git", "-C", ROOT, "rev-parse", "HEAD"], check=True, capture_output=True, text=True
        ).stdout.strip()
        for name in names:
            commits.setdefault(name, head)
    for name in names:
        sha = commits.get(name)
        if not sha or not SHA_RE.match(sha):
            raise ToolError(f"bundle {name}: no full 40-character commit given (use --provenance, --commit or --commit-head)")
        known = subprocess.run(
            ["git", "-C", ROOT, "cat-file", "-e", f"{sha}^{{commit}}"], capture_output=True
        ).returncode == 0
        if not known:
            raise ToolError(f"bundle {name}: commit {sha[:12]} is not in this repository")
    return {name: commits[name] for name in names}


def cmd_package(args) -> int:
    if not TAG_RE.match(args.tag):
        raise ToolError("--tag must look like engines-1, engines-2, ...")
    bundles = load_bundles()
    if args.only:
        unknown = set(args.only) - {b["name"] for b in bundles}
        if unknown:
            raise ToolError(f"unknown bundle(s): {', '.join(sorted(unknown))}")
        bundles = [b for b in bundles if b["name"] in args.only]
    commits = resolve_commits(args, [b["name"] for b in bundles])
    os.makedirs(args.out, exist_ok=True)
    manifest = {"schema": 1, "tag": args.tag, "producer": "pqctoday-org/pqctoday-hsm", "bundles": {}}
    sums = []
    for bundle in bundles:
        name = bundle["name"]
        script = bundle.get("buildScript", "")
        if script and not os.path.isfile(os.path.join(ROOT, script)):
            raise ToolError(f"bundle {name}: declared build script {script} does not exist")
        files = bundle_files(args.source, bundle)
        tarball = deterministic_tarball(args.source, files)
        tar_name = f"{name}-{commits[name][:8]}.tar.gz"
        with open(os.path.join(args.out, tar_name), "wb") as handle:
            handle.write(tarball)
        manifest["bundles"][name] = {
            "hsmCommit": commits[name],
            "buildScript": script,
            "tarball": tar_name,
            "tarballSha256": sha256_bytes(tarball),
            "files": {
                rel: {
                    "sha256": sha256_file(os.path.join(args.source, rel)),
                    "bytes": os.path.getsize(os.path.join(args.source, rel)),
                }
                for rel in files
            },
        }
        sums.append(f"{sha256_bytes(tarball)}  {tar_name}")
        print(f"  {name}: {len(files)} files, {len(tarball):,} bytes -> {tar_name}")
    manifest_text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    with open(os.path.join(args.out, "engines-manifest.json"), "w", encoding="utf-8") as handle:
        handle.write(manifest_text)
    sums.append(f"{sha256_bytes(manifest_text.encode())}  engines-manifest.json")
    with open(os.path.join(args.out, "SHA256SUMS"), "w", encoding="utf-8") as handle:
        handle.write("\n".join(sums) + "\n")
    assets = " ".join(
        [os.path.join(args.out, b["tarball"]) for b in manifest["bundles"].values()]
        + [os.path.join(args.out, "engines-manifest.json"), os.path.join(args.out, "SHA256SUMS")]
    )
    print("\nNothing was uploaded. To publish (a public act, run it yourself):")
    print(f"  gh release create {args.tag} --repo pqctoday-org/pqctoday-hsm --title '{args.tag}' \\")
    print(f"      --notes 'Engine files for the Hub; see engines-manifest.json.' {assets}")
    return 0


def cmd_verify(args) -> int:
    with open(args.manifest, encoding="utf-8") as handle:
        manifest = json.load(handle)
    problems: list[str] = []
    for name, b in manifest["bundles"].items():
        if args.tarballs:
            path = os.path.join(args.tarballs, b["tarball"])
            if not os.path.isfile(path):
                problems.append(f"{name}: tarball {b['tarball']} missing")
                continue
            if sha256_file(path) != b["tarballSha256"]:
                problems.append(f"{name}: tarball {b['tarball']} changed")
                continue
            with tarfile.open(path, "r:gz") as tar:
                members = {m.name: tar.extractfile(m).read() for m in tar.getmembers() if m.isfile()}
            for rel, meta in b["files"].items():
                if rel not in members:
                    problems.append(f"{name}: {rel} missing from tarball")
                elif sha256_bytes(members[rel]) != meta["sha256"]:
                    problems.append(f"{name}: {rel} changed inside tarball")
        if args.tree:
            for rel, meta in b["files"].items():
                full = os.path.join(args.tree, rel)
                if not os.path.isfile(full):
                    problems.append(f"{name}: {rel} missing")
                elif sha256_file(full) != meta["sha256"]:
                    problems.append(f"{name}: {rel} changed")
    if problems:
        print(f"engines verify: {len(problems)} problem(s)")
        for line in problems:
            print(f"  {line}")
        return 1
    print(f"engines verify: all {len(manifest['bundles'])} bundle(s) match the manifest")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("package", help="build release files (never uploads)")
    p.add_argument("--from", dest="source", required=True, help="directory laid out like the consumer")
    p.add_argument("--out", required=True)
    p.add_argument("--tag", required=True)
    p.add_argument("--provenance", help="JSON with bundles[].name/hsmCommit (bootstrap from the consumer's record)")
    p.add_argument("--commit", action="append", metavar="NAME=SHA")
    p.add_argument("--commit-head", action="store_true", help="use this repository's HEAD for bundles without a commit")
    p.add_argument("--only", action="append", metavar="NAME")
    v = sub.add_parser("verify", help="check release files or a tree against the manifest")
    v.add_argument("--manifest", required=True)
    v.add_argument("--tarballs")
    v.add_argument("--tree")
    args = ap.parse_args(argv)
    if args.cmd == "verify" and not (args.tarballs or args.tree):
        ap.error("verify needs --tarballs and/or --tree")
    try:
        return cmd_package(args) if args.cmd == "package" else cmd_verify(args)
    except ToolError as exc:
        print(f"engines: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
