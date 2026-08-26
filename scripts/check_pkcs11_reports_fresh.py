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

A SECOND false-positive class, found live 2026-08-26 (v0.25.0 release
validation): a handful of the C++ suite's own tests deliberately report
freshly-generated, non-deterministic material in their `details` string —
child PIDs (fork tests), RNG divergence samples, and Key Check Values
computed from a freshly generated key each run (every `*_KCV_*` test).
These are not bugs — reporting a different KCV each run IS the test
passing (a repeated KCV across independent key generations would BE the
defect). But it means the naive committed-vs-fresh text comparison could
never converge: four consecutive full gate runs against an otherwise
byte-identical, fully isolated worktree all "failed" on this alone. Fixed
the same way as the commit-hash/date fields above: name-based allowlist
(_NONDETERMINISTIC_TESTS) of tests whose `details` legitimately vary,
normalized before comparing — everything else (status, and every other
test's details, including stable capability flags like
`CKM_RSA_PKCS_advertises_SIGN_RECOVER`'s `flags=0x424704`) still compares
byte-exact, so a real regression there still fails the guard.

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

# Tests whose own `details` string is BY DESIGN different every run — see
# the module docstring's second false-positive class. Exhaustively found by
# scanning a real report for every entry containing a hex run (>=6 chars)
# or "pid", then hand-verifying each hit: KCV-family entries all compute a
# check value over a freshly generated key/secret; the two RNG_diverge
# entries print raw divergence samples; the one fork-PID entry prints a
# live PID. Everything else that matched the raw scan (e.g.
# CKM_RSA_PKCS_advertises_SIGN_RECOVER's `flags=0x424704`,
# CKA_PROFILE_ID_absent_on_ordinary_object's sentinel value) is a STABLE
# capability/constant and is deliberately NOT in this set — it must keep
# comparing byte-exact.
_NONDETERMINISTIC_TESTS = frozenset({
    "Child_survived_and_reported",
    "Sibling_children_RNG_diverge",
    "Parent_and_child_RNG_diverge",
    "AES_Generate_KCV_Present",
    "AES_Generate_KCV_Equals_OracleEcbZeroBlock",
    "AES_Unwrap_KCV_Present",
    "AES_Unwrap_KCV_Equals_Original",
    "HKDF_Derive_KCV_Present",
    "HKDF_Derive_KCV_Equals_OracleSha1",
    "PBKD2_Derive_KCV_Present",
    "PBKD2_Derive_KCV_Equals_OracleSha1",
    "SP800_108_Counter_Derive_KCV_Present",
    "SP800_108_Counter_Derive_KCV_Equals_OracleSha1",
    "SP800_108_Feedback_Derive_KCV_Present",
    "SP800_108_Feedback_Derive_KCV_Equals_OracleSha1",
    "Encap_KCV_equals_SHA1_oracle",
    "Decap_KCV_equals_SHA1_oracle",
    "Encap_and_Decap_KCV_agree",
    "ECDH_Encap_KCV_equals_SHA1_oracle",
    "ECDH_Decap_KCV_equals_SHA1_oracle",
    "GenerateKey_AES_KCV_matches_oracle",
    "GenerateKey_Generic_KCV_matches_oracle",
    "UnwrapKey_AES_KCV_matches_oracle",
    "UnwrapKey_AES_correct_value_accepted",
    "DeriveKey_HKDF_KCV_matches_oracle",
    "DeriveKey_HKDF_correct_value_accepted",
    "DeriveKey_ECDH_KCV_matches_oracle",
    "DeriveKey_ECDH_correct_value_accepted",
    "DeriveKey_PBKD2_KCV_matches_oracle",
    "DeriveKey_PBKD2_correct_value_accepted",
    "DeriveKey_SP800108_KCV_matches_oracle",
    "DeriveKey_SP800108_correct_value_accepted",
    "DeriveKey_Concat_KCV_matches_oracle",
    "DeriveKey_Concat_correct_value_accepted",
    "DeriveKey_X25519_KCV_matches_oracle",
    "DeriveKey_X25519_correct_value_accepted",
    # Found via a direct empirical diff of two independent real runs
    # (2026-08-26), not the original hex-scan pass: these print the first
    # byte of a freshly generated key's raw CKA_VALUE, which varies with
    # the key just like the KCV entries above.
    "ML_DSA_44_CKA_VALUE_not_DER_wrapped",
    "ML_KEM_768_CKA_VALUE_not_DER_wrapped",
    "SLH_DSA_CKA_VALUE_not_DER_wrapped",
})

# Markdown table row: | TestName | Status | Details |
_MD_ROW = re.compile(r"^\| ([^\|]+) \| (.+?) \| (.+) \|$", re.MULTILINE)


def _normalize_md_row(m: "re.Match[str]") -> str:
    name = m.group(1).strip()
    if name in _NONDETERMINISTIC_TESTS:
        return f"| {name} | {m.group(2)} | <NORMALIZED> |"
    return m.group(0)


def normalize_cpp_md(text: str) -> str:
    text = _MD_DATE.sub("**Date:** <NORMALIZED>", text)
    text = _MD_ENGINE.sub("**Engine:** <NORMALIZED>", text)
    text = _MD_COMMIT.sub("**Engine commit:** `<NORMALIZED>`", text)
    text = _MD_ROW.sub(_normalize_md_row, text)
    return text


_HEX = re.compile(r"^[0-9a-f]{7,40}$")


def _normalize_json_entries(obj):
    """Recursively normalize `details` on any {"test": ..., "details": ...}
    entry whose test name is in _NONDETERMINISTIC_TESTS — same allowlist
    and rationale as the Markdown normalizer above."""
    if isinstance(obj, dict):
        if obj.get("test") in _NONDETERMINISTIC_TESTS and "details" in obj:
            obj["details"] = "<NORMALIZED>"
        for v in obj.values():
            _normalize_json_entries(v)
    elif isinstance(obj, list):
        for v in obj:
            _normalize_json_entries(v)


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
    _normalize_json_entries(obj)
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
