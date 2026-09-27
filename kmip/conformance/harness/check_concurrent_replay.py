#!/usr/bin/env python3
"""Run two full OASIS replays AT THE SAME TIME and require both to pass.

Added 2026-09-27. The replay used to start each test's server on a fixed
port walk (10001, 10002, …) identical in every run, so two replays in one
container — two gates in different worktrees, or a server left over from
an aborted run — collided: an A5 gate failed its replay step with
"Address already in use". dispatcher_replay.py now takes an OS-assigned port
per server; this script is the proof, and the regression check.

Each replay writes its report to its own temporary directory
(REPLAY_REPORT_DIR), so the committed REPLAY_REPORT.* are not touched, and
each report is then held to the same assertion the gate uses
(assert_replay_report.py).

Usage (from kmip/, with target/release/pqctoday-kmip built):
    python3 conformance/harness/check_concurrent_replay.py
    python3 conformance/harness/check_concurrent_replay.py --harness OLD.py
The second form runs an alternate copy of dispatcher_replay.py — e.g. the
version before this fix, to show the check fails on it. The copy must sit
in conformance/harness/ so its relative paths resolve.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
KMIP_ROOT = HERE.parent.parent
ASSERT = KMIP_ROOT / "conformance" / "assert_replay_report.py"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--harness", default=str(HERE / "dispatcher_replay.py"))
    ap.add_argument("--runs", type=int, default=2)
    args = ap.parse_args()

    with tempfile.TemporaryDirectory(prefix="concurrent-replay-") as tmp:
        procs = []
        for n in range(args.runs):
            out = Path(tmp) / f"run{n}"
            out.mkdir()
            env = dict(os.environ, REPLAY_REPORT_DIR=str(out))
            log = open(out / "replay.log", "wb")
            procs.append((n, out, log, subprocess.Popen(
                [sys.executable, args.harness], cwd=KMIP_ROOT, env=env,
                stdout=log, stderr=subprocess.STDOUT)))
        failed = 0
        for n, out, log, p in procs:
            rc = p.wait()
            log.close()
            report = out / "REPLAY_REPORT.json"
            ok = rc == 0 and report.exists() and subprocess.run(
                [sys.executable, str(ASSERT), str(report)],
                cwd=KMIP_ROOT, capture_output=True).returncode == 0
            text = (out / "replay.log").read_text(errors="replace")
            in_use = text.count("Address already in use")
            print(f"replay {n}: exit {rc}, report {'OK' if ok else 'FAILED'}"
                  f"{f', {in_use} x Address already in use' if in_use else ''}")
            if not ok:
                failed += 1
                print("\n".join(text.splitlines()[-8:]))
        if failed:
            print(f"CONCURRENT REPLAY FAIL: {failed}/{args.runs} replay(s) failed when run together")
            return 1
        print(f"CONCURRENT REPLAY OK: {args.runs} replays ran at once, all passed")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
