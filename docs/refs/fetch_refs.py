#!/usr/bin/env python3
"""Restore local copies of the third-party documents this repository cites.

The repository is public and carries no third-party documents, only what was
extracted from them (owner rule 2026-10-15). Every document it used to carry
is listed, with its publisher URL and the SHA-256 of the exact copy the code
was audited against, in `docs/refs/third-party-documents.json`. This script
downloads them back to the paths the docs cite (all gitignored) and refuses
any download whose SHA-256 differs from the recorded one.

Nothing in the normal build, test or gate path calls this script or needs
the network. Only optional refresh work does: re-running the KMIP tag/enum
extractor (`kmip/tools/extract_kmip_spec.rs`), the full provenance check in
`kmip/conformance/verify_corpus_provenance.py`, or reading the PDFs by hand.

Usage (from anywhere):
  python3 docs/refs/fetch_refs.py --list           # what is recorded, what is present
  python3 docs/refs/fetch_refs.py --check          # verify local copies only (offline)
  python3 docs/refs/fetch_refs.py                  # download every missing document
  python3 docs/refs/fetch_refs.py --only kmip-spec-v3.0-csd02.zip
  python3 docs/refs/fetch_refs.py --v33            # also restore the PKCS #11 v3.3 TC snapshot
  python3 docs/refs/fetch_refs.py --force          # re-download even when present

HTML pages: the publisher's CDN rewrites e-mail links on every request, so a
fresh `.html` download does not reproduce the recorded SHA-256. Such a file is
refused like any other mismatch unless `--allow-html-drift` is given, in which
case it is saved and reported as UNVERIFIED. Byte-exact copies of the HTML are
kept in the maintainers' private archive.

Exit status: 0 when every requested document is present and verified
(or UNVERIFIED with --allow-html-drift); 1 otherwise.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

REPO = Path(__file__).resolve().parent.parent.parent
MANIFEST = Path(__file__).resolve().parent / "third-party-documents.json"
UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(url: str, timeout: int = 180) -> bytes:
    req = Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urlopen(req, timeout=timeout) as resp:
        return resp.read()


def load_manifest() -> dict:
    return json.loads(MANIFEST.read_text())


def status(doc: dict) -> str:
    dest = REPO / doc["path"]
    if not dest.exists():
        return "absent"
    return "ok" if sha256_file(dest) == doc["sha256"] else "MISMATCH"


def restore(doc: dict, force: bool, allow_html_drift: bool) -> tuple[bool, str]:
    dest = REPO / doc["path"]
    if dest.exists() and not force:
        st = status(doc)
        if st == "ok":
            return True, f"SKIP (present, verified)  {doc['path']}"
        return False, f"FAIL present but sha256 differs (use --force to replace)  {doc['path']}"
    try:
        data = fetch(doc["url"])
    except (HTTPError, URLError, TimeoutError, OSError) as e:
        return False, f"FAIL download {doc['url']}: {e}"
    digest = hashlib.sha256(data).hexdigest()
    if digest != doc["sha256"]:
        if doc.get("cdn_rewritten") and allow_html_drift:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            return True, (f"UNVERIFIED (publisher CDN rewrote the page; sha256 {digest[:16]}... "
                          f"!= recorded {doc['sha256'][:16]}...)  {doc['path']}")
        hint = " (HTML: retry with --allow-html-drift to accept a CDN-rewritten copy)" \
            if doc.get("cdn_rewritten") else " (the publisher changed or replaced the file)"
        return False, (f"FAIL sha256 mismatch for {doc['url']}: got {digest}, "
                       f"recorded {doc['sha256']}{hint}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    return True, f"OK   ({len(data):,} bytes, sha256 verified)  {doc['path']}"


def restore_snapshot(snap: dict, force: bool) -> tuple[bool, str]:
    dest = REPO / snap["path"]
    if dest.exists() and any(dest.iterdir()) and not force:
        return True, f"SKIP (present)  {snap['path']}"
    if shutil.which("git") is None:
        return False, "FAIL git is not installed"
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / "repo"
        cmds = [
            ["git", "init", "-q", str(work)],
            ["git", "-C", str(work), "fetch", "-q", "--depth", "1", snap["repo"], snap["commit"]],
            ["git", "-C", str(work), "checkout", "-q", "FETCH_HEAD"],
        ]
        for cmd in cmds:
            r = subprocess.run(cmd, capture_output=True, text=True)
            if r.returncode != 0:
                return False, f"FAIL {' '.join(cmd[3:])}: {r.stderr.strip()}"
        head = subprocess.run(["git", "-C", str(work), "rev-parse", "HEAD"],
                              capture_output=True, text=True).stdout.strip()
        if head != snap["commit"]:
            return False, f"FAIL fetched {head}, expected {snap['commit']}"
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(work, dest, ignore=shutil.ignore_patterns(".git"))
    return True, f"OK   {snap['repo']} @ {snap['commit'][:12]} -> {snap['path']}"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--list", action="store_true", help="list recorded documents and local status")
    ap.add_argument("--check", action="store_true", help="verify local copies only; never uses the network")
    ap.add_argument("--only", action="append", default=[], help="restrict to paths containing this text (repeatable)")
    ap.add_argument("--force", action="store_true", help="re-download even when a local copy exists")
    ap.add_argument("--allow-html-drift", action="store_true", help="accept CDN-rewritten .html downloads as UNVERIFIED")
    ap.add_argument("--v33", action="store_true", help="also restore the PKCS #11 v3.3 TC working-tree snapshot")
    args = ap.parse_args()

    manifest = load_manifest()
    docs = [d for d in manifest["documents"]
            if not args.only or any(o in d["path"] for o in args.only)]
    if not docs and not args.v33:
        print("no recorded document matches --only", file=sys.stderr)
        return 1

    if args.list or args.check:
        bad = 0
        for d in docs:
            st = status(d)
            if args.check and st == "MISMATCH":
                bad += 1
            print(f"{st:9} {d['path']}\n          {d['url']}")
        for s in manifest.get("git_snapshots", []):
            present = (REPO / s["path"]).exists()
            print(f"{'present' if present else 'absent':9} {s['path']}\n          {s['repo']} @ {s['commit']}")
        if args.check:
            print(f"\n{bad} local cop{'y' if bad == 1 else 'ies'} with a wrong sha256")
            return 1 if bad else 0
        return 0

    ok = fail = 0
    for i, d in enumerate(docs, 1):
        success, msg = restore(d, args.force, args.allow_html_drift)
        print(f"[{i}/{len(docs)}] {msg}")
        ok, fail = ok + success, fail + (not success)
        if "SKIP" not in msg:
            time.sleep(0.8)  # polite rate limit
    if args.v33:
        for s in manifest.get("git_snapshots", []):
            success, msg = restore_snapshot(s, args.force)
            print(f"[snapshot] {msg}")
            ok, fail = ok + success, fail + (not success)
    print(f"\nDone: {ok} ok, {fail} failed")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
