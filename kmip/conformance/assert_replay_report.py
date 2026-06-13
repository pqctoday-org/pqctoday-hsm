#!/usr/bin/env python3
"""CI gate assertion over ``conformance/REPLAY_REPORT.json``.

Belt-and-suspenders companion to ``dispatcher_replay.py``'s exit code.
Parses the JSON sidecar the replay emits and fails (exit 1) unless the
conformance posture is EXACTLY the documented baseline:

  * PASS  >= 92   (the headline candidate pass count)
  * FAIL  == 0
  * ERROR == 0
  * SKIP set == the documented 10:
        5 SKIP_DEPRECATED (DSA x2, 3DES x3 — out of scope by policy)
      + 2 SKIP_PRECONDITION (inter-transcript state our hermetic harness wipes)
      + 3 SKIP_POLICY_VARIANT (mutually-exclusive RNGSeed policy choices)
  * No SKIP_OP / SKIP_PARSE (an op regressing into "unsupported" or a
    transcript failing to parse is a coverage regression, not a skip).

A NEW skip silently appearing would otherwise shrink the pass-rate
denominator and hide a regression (the 92->89 Locate regression that
motivated this gate). Asserting the exact skip breakdown closes that.

Usage:

    python3 conformance/assert_replay_report.py [path/to/REPLAY_REPORT.json]

Exit 0 = baseline matched; exit 1 = drift (message on stderr).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Documented baseline. If these numbers legitimately change (e.g. a new
# op is implemented and a SKIP_OP becomes a PASS), update them here in the
# same PR that regenerates REPLAY_REPORT.json — that is the whole point of
# the gate.
MIN_PASS = 92
EXPECTED_SKIP = {
    "skip_deprecated": 5,
    "skip_precondition": 2,
    "skip_policy_variant": 3,
    "skip_op": 0,
    "skip_parse": 0,
}
EXPECTED_SKIP_TOTAL = sum(EXPECTED_SKIP.values())  # == 10


def main(argv: list[str]) -> int:
    here = Path(__file__).resolve().parent
    report_path = Path(argv[1]) if len(argv) > 1 else here / "REPLAY_REPORT.json"

    if not report_path.exists():
        print(f"ERROR: report not found: {report_path}", file=sys.stderr)
        return 1
    try:
        summary = json.loads(report_path.read_text())["summary"]
    except (json.JSONDecodeError, KeyError, OSError) as e:
        print(f"ERROR: cannot parse summary from {report_path}: {e}", file=sys.stderr)
        return 1

    errors: list[str] = []

    n_pass = summary.get("pass", -1)
    n_fail = summary.get("fail", -1)
    n_err = summary.get("error", -1)

    if n_pass < MIN_PASS:
        errors.append(f"PASS {n_pass} < required {MIN_PASS} (regression)")
    if n_fail != 0:
        errors.append(f"FAIL {n_fail} != 0 (conformance regression)")
    if n_err != 0:
        errors.append(f"ERROR {n_err} != 0 (harness/transport error)")

    # Exact skip-category breakdown — a new skip silently appearing is a
    # coverage regression even though it isn't a FAIL.
    for cat, want in EXPECTED_SKIP.items():
        got = summary.get(cat, -1)
        if got != want:
            errors.append(f"{cat} {got} != expected {want} (skip-set drift)")

    actual_skip_total = sum(summary.get(c, 0) for c in EXPECTED_SKIP)
    if actual_skip_total != EXPECTED_SKIP_TOTAL:
        errors.append(
            f"total skips {actual_skip_total} != documented {EXPECTED_SKIP_TOTAL} "
            f"(5 deprecated + 2 precondition + 3 policy-variant)"
        )

    if errors:
        print("REPLAY GATE FAILED:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        print(f"\nsummary was: {summary}", file=sys.stderr)
        return 1

    print(
        f"REPLAY GATE OK: {n_pass} PASS / {n_fail} FAIL / "
        f"{actual_skip_total} SKIP (5 deprecated + 2 precondition + 3 policy-variant)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
