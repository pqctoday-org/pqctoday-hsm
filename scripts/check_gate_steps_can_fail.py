#!/usr/bin/env python3
"""Assert every `local-gate.sh` step can actually fail, and measures its whole run.

A gate step that cannot fail is worse than no step: it is cited as evidence in
PR bodies, so it converts an unchecked area into a false claim of coverage.
This session found four instances of a guard protecting a defect rather than
catching it, two of them in this very script:

  * `wasm target still compiles` printed two E0063 compiler errors and then
    "wasm32 type-check clean ✓" in the same breath. `cmd | grep … && exit 1`
    CANNOT fail once `dexec` sets pipefail: when the real command errors the
    PIPELINE's status is that error rather than grep's 0, so `&&`
    short-circuits, `exit 1` never runs, and control reaches whatever follows
    the `;`. A broken wasm crate went unnoticed until a later step tried to
    use the bundle.
  * `kmip known-slow mechanisms` fell through to a bare `true`.
  * `kmip local-only suites (--include-ignored)` ran 1032 tests and took its
    verdict from `cargo test --test policy_op_layer` — **10** of them. The
    other 1022 ran with their result discarded.

Two checks, one per failure mode:

  UNFAILABLE  a step using `… && exit 1;` whose trailing command is `true` or
              an `echo` — nothing left that can carry a non-zero status.
  NARROWED    a step whose verdict command re-runs a STRICTLY SMALLER slice
              than the command it is meant to be checking (a `--test <name>`
              the first invocation did not have).

Exit 0 = every step can fail and measures what it runs. Exit 1 = offenders,
named, on stderr.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

GATE = Path(__file__).resolve().parent / "local-gate.sh"


def steps(text: str) -> list[tuple[str, str]]:
    """(step name, command string) for every run_step / run_step_host call."""
    out: list[tuple[str, str]] = []
    for m in re.finditer(r'run_step(?:_host)?\s+"([^"]+)"\s*\\?\s*\n', text):
        name = m.group(1)
        # the command is the next double-quoted string, which may span lines
        # via trailing backslashes
        rest = text[m.end():]
        q = rest.find('"')
        if q == -1:
            continue
        i, buf, esc = q + 1, [], False
        while i < len(rest):
            c = rest[i]
            if esc:
                buf.append(c)
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                break
            else:
                buf.append(c)
            i += 1
        out.append((name, "".join(buf)))
    return out


def verdict_tail(cmd: str) -> str:
    """Whatever decides the step's exit status: the last `;`-separated part."""
    return cmd.split(";")[-1].strip().strip("\\").strip()


def main() -> int:
    text = GATE.read_text(encoding="utf-8")
    found = steps(text)
    if len(found) < 5:
        print(f"parsed only {len(found)} steps — the parser is broken, not the gate",
              file=sys.stderr)
        return 1

    problems: list[str] = []
    for name, cmd in found:
        flat = " ".join(cmd.split())
        if "&& exit 1" not in flat:
            continue  # its own status decides; nothing to defeat
        if "PIPESTATUS" in flat:
            continue  # takes the real command's status explicitly

        tail = verdict_tail(flat)
        if tail in ("true", "") or tail.startswith("echo "):
            problems.append(
                f"UNFAILABLE  {name!r}\n"
                f"            `&& exit 1` cannot fire under pipefail and the trailing\n"
                f"            command is {tail!r} — this step can never fail."
            )
            continue

        # NARROWED: verdict re-runs a smaller slice than the thing under test
        lead = flat.split("&& exit 1")[0]
        lead_tests = set(re.findall(r"--test\s+(\S+)", lead))
        tail_tests = set(re.findall(r"--test\s+(\S+)", tail))
        if tail_tests and not tail_tests <= lead_tests:
            problems.append(
                f"NARROWED    {name!r}\n"
                f"            verdict re-runs only --test {', '.join(sorted(tail_tests))}\n"
                f"            while the step runs the whole suite. A failure outside\n"
                f"            that binary would pass silently."
            )

    if problems:
        print(f"GATE SELF-CHECK FAILED — {len(problems)} step(s):\n", file=sys.stderr)
        for p in problems:
            print(f"  {p}\n", file=sys.stderr)
        print("Take the verdict from the real command: ${PIPESTATUS[0]}, or an awk\n"
              "`exit (f>0)` over the WHOLE run. See the notes in local-gate.sh.",
              file=sys.stderr)
        return 1

    print(f"GATE SELF-CHECK OK — {len(found)} steps; every one can fail and "
          "measures what it runs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
