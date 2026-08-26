#!/usr/bin/env python3
"""Coverage ledger ratchet — the RW-T check from
docs/remoting-pkcs11-v32-remaining-gaps-plan-2026-08-26.md.

Fails the gate if the ledger has drifted from any of the three things it
claims to describe:

  (a) every category in cpp_compliance_report.json has a ledger row —
      the C++ compliance suite is the source of truth for "what a
      PKCS#11 v3.2 conformance sweep checks"; a category with no row
      would be a silent, undetectable coverage gap.
  (b) every case_id a row names actually exists as a test function in
      the file it claims to — a stale case_id (renamed/deleted test)
      would let the ledger claim coverage that no longer runs.
  (c) every RPC declared on the Pkcs11V32 service is mentioned SOMEWHERE
      in the ledger — an RPC with zero ledger presence means a
      workstream added it without ever accounting for it.

Run from the `remoting/` directory (matches every other gate-step
convention in this workspace):

    python3 scripts/check_coverage_ledger.py
"""

import json
import re
import sys
from pathlib import Path

REMOTING_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = REMOTING_ROOT.parent

LEDGER_PATH = REMOTING_ROOT / "coverage_ledger.json"
COMPLIANCE_REPORT_PATH = REPO_ROOT / "cpp_compliance_report.json"
PROTO_PATH = REMOTING_ROOT / "proto" / "proto" / "pkcs11_remote.proto"
V32_PARITY_PATH = REMOTING_ROOT / "acceptance" / "tests" / "v32_parity.rs"
VERBS_V32_PATH = REMOTING_ROOT / "core" / "src" / "verbs_v32.rs"


def fail(msg: str) -> None:
    print(f"COVERAGE LEDGER RATCHET FAILED: {msg}", file=sys.stderr)
    sys.exit(1)


def load_json(path: Path):
    if not path.exists():
        fail(f"missing required file: {path}")
    with open(path) as f:
        return json.load(f)


def rust_fn_names(path: Path) -> set:
    if not path.exists():
        fail(f"missing required file: {path}")
    text = path.read_text()
    # Matches both `fn name(` (acceptance test functions) and
    # `    fn name(` (core crate's nested `mod tests` functions) — this
    # intentionally also picks up non-test helper fns in verbs_v32.rs;
    # that's fine, a case_id naming a real fn (test or not) is still a
    # real, checkable claim, and helper fns are never what a case_id
    # would plausibly name.
    return set(re.findall(r"\bfn\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(", text))


def proto_rpc_names(path: Path) -> list:
    if not path.exists():
        fail(f"missing required file: {path}")
    text = path.read_text()
    m = re.search(r"service\s+Pkcs11V32\s*\{(.*?)\n\}", text, re.DOTALL)
    if not m:
        fail("could not find `service Pkcs11V32 { ... }` block in the proto file")
    body = m.group(1)
    return re.findall(r"\brpc\s+(C_[A-Za-z0-9_]+)\s*\(", body)


def main() -> None:
    ledger = load_json(LEDGER_PATH)
    report = load_json(COMPLIANCE_REPORT_PATH)

    rows = ledger.get("rows", {})
    errors = []

    # (a) every compliance-report category has a ledger row.
    report_categories = {k for k in report.keys() if k != "_summary"}
    missing_categories = sorted(report_categories - set(rows.keys()))
    if missing_categories:
        errors.append(
            "categories in cpp_compliance_report.json with NO ledger row: "
            + ", ".join(missing_categories)
        )

    # (b) every case_id resolves to a real function in the file it claims.
    parity_fns = rust_fn_names(V32_PARITY_PATH)
    core_fns = rust_fn_names(VERBS_V32_PATH)
    for category, row in sorted(rows.items()):
        for case_id in row.get("case_ids", []):
            if case_id.startswith("v32_parity::"):
                fn_name = case_id[len("v32_parity::") :]
                if fn_name not in parity_fns:
                    errors.append(
                        f"{category}: case_id '{case_id}' names a function not found in {V32_PARITY_PATH.relative_to(REPO_ROOT)}"
                    )
            elif case_id.startswith("core::"):
                fn_name = case_id[len("core::") :]
                if fn_name not in core_fns:
                    errors.append(
                        f"{category}: case_id '{case_id}' names a function not found in {VERBS_V32_PATH.relative_to(REPO_ROOT)}"
                    )
            else:
                errors.append(
                    f"{category}: case_id '{case_id}' has an unrecognised prefix (expected 'v32_parity::' or 'core::')"
                )

    # (c) every RPC on the Pkcs11V32 service is mentioned somewhere in the ledger.
    ledger_text = json.dumps(ledger)
    rpc_names = proto_rpc_names(PROTO_PATH)
    unmentioned_rpcs = sorted({rpc for rpc in rpc_names if rpc not in ledger_text})
    if unmentioned_rpcs:
        errors.append(
            "RPCs declared on Pkcs11V32 with ZERO mention anywhere in the ledger: "
            + ", ".join(unmentioned_rpcs)
        )

    if errors:
        fail("\n  - " + "\n  - ".join(errors))

    print(
        f"coverage ledger OK: {len(rows)} categories, "
        f"{len(rpc_names)} RPCs all accounted for."
    )


if __name__ == "__main__":
    main()
