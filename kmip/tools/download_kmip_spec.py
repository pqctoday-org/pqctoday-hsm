#!/usr/bin/env python3
"""Download / refresh the OASIS KMIP 3.0 specification artifacts.

Pattern matches `pqctoday-priv/patents/download_patents.py`: urllib + Chrome
desktop UA + primary/fallback URL + magic-byte validation + on-disk skip
+ polite rate limiting. No third-party deps; runs under any Python 3.8+.

Targets (all from docs.oasis-open.org/kmip/kmip-spec/v3.0/):
  - kmip-spec-v3.0.html
  - kmip-spec-v3.0.pdf
  - kmip-spec-v3.0.docx
  - kmip-spec-v3.0.zip
  - csd01/* (optional — pre-supersede snapshot)

OASIS docs.oasis-open.org is not WAF-fronted; the lighter pattern is
sufficient. If a 403/Cloudflare layer ever appears, escalate to the
playwright-stealth pattern referenced in pqctoday-hub PR #305.

Usage:
  python3 download_kmip_spec.py                      # refresh all primary files
  python3 download_kmip_spec.py --include-csd01      # also pull csd01/
  python3 download_kmip_spec.py --force              # re-download even if local exists
  python3 download_kmip_spec.py --check              # report local vs remote sha256s only
"""

import argparse
import hashlib
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent.parent  # kmip/
OUT_DIR = ROOT / "spec" / "oasis-kmip-3.0"

BASE = "https://docs.oasis-open.org/kmip/kmip-spec/v3.0"

UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)

# (remote_path, local_filename, magic_bytes_prefix, min_bytes)
PRIMARY = [
    ("kmip-spec-v3.0.html", "kmip-spec-v3.0.html", b"<", 1_000_000),
    ("kmip-spec-v3.0.pdf",  "kmip-spec-v3.0.pdf",  b"%PDF", 100_000),
    ("kmip-spec-v3.0.docx", "kmip-spec-v3.0.docx", b"PK",   50_000),
    ("kmip-spec-v3.0.zip",  "kmip-spec-v3.0.zip",  b"PK",   100_000),
]

CSD01 = [
    ("csd01/kmip-spec-v3.0-csd01.html", "csd01-kmip-spec-v3.0-csd01.html", b"<", 1_000_000),
    ("csd01/kmip-spec-v3.0-csd01.pdf",  "csd01-kmip-spec-v3.0-csd01.pdf",  b"%PDF", 100_000),
]


def fetch(url: str, timeout: int = 120) -> bytes:
    req = Request(
        url,
        headers={
            "User-Agent": UA,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
        },
    )
    with urlopen(req, timeout=timeout) as resp:
        return resp.read()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def download_one(remote_path: str, local_filename: str, magic: bytes,
                 min_bytes: int, force: bool) -> tuple[bool, str]:
    url = f"{BASE}/{remote_path}"
    dest = OUT_DIR / local_filename

    if dest.exists() and not force:
        size = dest.stat().st_size
        if size >= min_bytes:
            return True, f"SKIP (exists, {size:,} bytes) {local_filename}"

    try:
        data = fetch(url)
    except (HTTPError, URLError) as e:
        return False, f"FAIL {local_filename} — {e}"
    except TimeoutError as e:
        return False, f"FAIL {local_filename} — timeout: {e}"

    if not data.startswith(magic):
        return False, (
            f"FAIL {local_filename} — magic-byte mismatch "
            f"(got {data[:8]!r}, expected prefix {magic!r})"
        )
    if len(data) < min_bytes:
        return False, (
            f"FAIL {local_filename} — too small "
            f"({len(data):,} bytes < {min_bytes:,})"
        )

    dest.write_bytes(data)
    digest = sha256(data)
    sha_file = dest.with_suffix(dest.suffix + ".sha256")
    sha_file.write_text(f"{digest}  {local_filename}\n")
    return True, f"OK   {local_filename} ({len(data):,} bytes, sha256={digest[:16]}...)"


def check_one(remote_path: str, local_filename: str) -> str:
    """Report local vs remote sha256 without writing anything."""
    url = f"{BASE}/{remote_path}"
    dest = OUT_DIR / local_filename

    local_sha = "(absent)"
    if dest.exists():
        local_sha = sha256(dest.read_bytes())

    try:
        remote_sha = sha256(fetch(url))
    except (HTTPError, URLError, TimeoutError) as e:
        return f"{local_filename}: local={local_sha[:16]} remote=ERROR ({e})"

    marker = "✓ match" if local_sha == remote_sha else "✗ DRIFT"
    return f"{local_filename}: local={local_sha[:16]} remote={remote_sha[:16]} {marker}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--include-csd01", action="store_true",
                    help="Also pull csd01/ pre-supersede snapshot")
    ap.add_argument("--force", action="store_true",
                    help="Re-download even if local file exists with valid size")
    ap.add_argument("--check", action="store_true",
                    help="Compare local vs remote sha256 only; do not modify any file")
    args = ap.parse_args()

    targets = list(PRIMARY)
    if args.include_csd01:
        targets.extend(CSD01)

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    if args.check:
        print(f"Comparing {len(targets)} files local vs remote ({BASE})")
        for remote_path, local_filename, _, _ in targets:
            print(f"  {check_one(remote_path, local_filename)}")
            time.sleep(0.8)
        return 0

    print(f"Source : {BASE}")
    print(f"Output : {OUT_DIR}")
    print(f"Targets: {len(targets)}{' (--force)' if args.force else ''}\n")

    ok = fail = 0
    for i, (remote_path, local_filename, magic, min_bytes) in enumerate(targets, 1):
        success, msg = download_one(remote_path, local_filename, magic, min_bytes, args.force)
        print(f"[{i}/{len(targets)}] {msg}")
        if success:
            ok += 1
        else:
            fail += 1
        time.sleep(0.8)  # polite rate limit

    print(f"\nDone: {ok} ok, {fail} failed, total {len(targets)}")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
