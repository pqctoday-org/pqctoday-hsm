#!/usr/bin/env python3
"""Generates remoting/REMOTE_P11_V32_COVERAGE.md from coverage_ledger.json.

The ledger is static, human-authored JSON (a disposition + case_ids +
justification per compliance category) — nothing in it varies run to run
(no KCVs, no RNG samples, no PIDs, no timestamps pulled from a live run),
so this generator's output is fully deterministic: the same ledger always
produces byte-identical markdown. That determinism is deliberate, not
incidental — the v0.25.0 freshness-checker bug (a generated report that
embedded live, randomly-varying values and then failed a "is this stale"
diff against itself) is exactly the failure mode a ledger-driven generator
is structurally immune to, as long as nothing here starts reading live
test output. Keep it that way: this script must never shell out to `cargo
test` or embed a timestamp/PID/random sample.

Run from the `remoting/` directory:

    python3 scripts/generate_coverage_report.py
"""

import json
from pathlib import Path

REMOTING_ROOT = Path(__file__).resolve().parent.parent
LEDGER_PATH = REMOTING_ROOT / "coverage_ledger.json"
OUT_PATH = REMOTING_ROOT / "REMOTE_P11_V32_COVERAGE.md"

DISPOSITION_LABEL = {
    "RPC": "RPC — remotely validatable",
    "N/A-local": "N/A-local — inherently in-process, no network analogue",
    "N/A-engine": "N/A-engine — a C++-engine-only capability the Rust engine doesn't advertise",
    "SUITE-GAP": "SUITE-GAP — untouched by either local compliance harness",
}


def main() -> None:
    with open(LEDGER_PATH) as f:
        ledger = json.load(f)

    rows = ledger["rows"]
    counts = {}
    for row in rows.values():
        counts[row["disposition"]] = counts.get(row["disposition"], 0) + 1

    lines = []
    lines.append("# PKCS#11 v3.2 remoting coverage — generated report")
    lines.append("")
    lines.append(
        "**Generated from `remoting/coverage_ledger.json` — do not hand-edit "
        "this file; edit the ledger and re-run "
        "`python3 scripts/generate_coverage_report.py` instead.** Ledger and "
        "generator are both deterministic (see the generator's own module "
        "doc for why); this file's content only changes when the ledger does."
    )
    lines.append("")
    lines.append(
        f"Reflects coverage through workstream **{ledger['generated_after_workstream']}** "
        f"of the remoting v3.2 coverage program (see `{ledger['generated_by']}`)."
    )
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"{len(rows)} compliance categories (from `cpp_compliance_report.json`), by disposition:")
    lines.append("")
    for disp in ["RPC", "N/A-local", "N/A-engine", "SUITE-GAP"]:
        if disp in counts:
            lines.append(f"- **{counts[disp]}** {DISPOSITION_LABEL[disp]}")
    lines.append("")
    lines.append(
        "Coverage is checked, not just described: "
        "`scripts/check_coverage_ledger.py` fails the gate if any compliance "
        "category has no ledger row, any `case_ids` entry names a test "
        "function that doesn't exist, or any RPC on the `Pkcs11V32` gRPC "
        "service has zero mention anywhere in the ledger."
    )
    lines.append("")
    fn_count = ledger.get("pkcs11f_h_function_count")
    if fn_count:
        lines.append(
            f"**{fn_count['live_rpcs']} of {fn_count['total']}** `pkcs11f.h` "
            f"functions are live RPCs. The remaining "
            f"{fn_count['total'] - fn_count['live_rpcs']} "
            f"(`{'`, `'.join(fn_count['not_mirrored'])}`) are deliberately "
            f"not mirrored: {fn_count['not_mirrored_justification']}"
        )
        lines.append("")
    lines.append("## Category → disposition")
    lines.append("")
    lines.append("| Category | Disposition | Case IDs | Justification |")
    lines.append("|---|---|---|---|")
    for category in sorted(rows.keys()):
        row = rows[category]
        case_ids = ", ".join(f"`{c}`" for c in row["case_ids"]) or "—"
        justification = row["justification"].replace("|", "\\|")
        lines.append(f"| {category} | {row['disposition']} | {case_ids} | {justification} |")
    lines.append("")

    OUT_PATH.write_text("\n".join(lines) + "\n")
    print(f"wrote {OUT_PATH} ({len(rows)} rows)")


if __name__ == "__main__":
    main()
