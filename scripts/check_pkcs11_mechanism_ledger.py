#!/usr/bin/env python3
"""Mechanism-ledger ratchet — plan item X2' of
docs/remediation-plan-pkcs11-v32-phase2-09072026.md.

WHY THIS EXISTS. Nothing in this repo recorded, per CKM_*, whether each
engine implements it. scripts/check_pkcs11_constants.py validates CK*
VALUES only; tests/differential/exceptions.json adjudicates cross-engine
DIFFERENCES and excuses whole globs (LEGAL-MECHANISM-SET covers `mech*`,
which is how a wrong CK_MECHANISM_INFO key range for CKM_AES_CMAC sat
undetected until 2026-09-07); the docs held small hand-written tables that
went stale. That gap is why three separate audits each re-discovered
CKM_ECMQV_DERIVE as a finding, and why four mechanisms sat implemented
but unadvertised until plan item R2'a.

WHAT IT CHECKS, all statically — no engine is built or run:

  (a) every CKM_* in the canonical header has a ledger row. A new
      mechanism arriving in a header update cannot pass unnoticed.
  (b) each row's `value` matches the canonical header.
  (c) a row claiming `implemented` IS advertised by that engine, and a row
      claiming anything else is NOT. Both directions: the first catches a
      ledger that overstates, the second catches a mechanism that was
      quietly added to an engine without anyone recording a decision.
  (d) every `excluded-by-scope:<key>` names a key that exists in
      scope_reasons, and no row is left UNCLASSIFIED.
  (e) every advertised name has a row, including engine extensions
      outside the canonical header.

"Advertised" is read from the two places that BUILD those lists —
SoftHSM::prepareSupportedMechanisms() and SUPPORTED_MECHS — not from a
captured run, because a snapshot goes stale exactly when it matters.

Run from the repo root:

    python3 scripts/check_pkcs11_mechanism_ledger.py

Regenerate the ledger (never done by this script) with
scripts/gen_pkcs11_mechanism_ledger.py.
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CANON_HEADER = ROOT / "docs" / "refs" / "pkcs11t-canonical-v3.2.h"
CPP_SLOTS = ROOT / "src" / "lib" / "SoftHSM_slots.cpp"
RUST_CONSTS = ROOT / "rust" / "src" / "constants.rs"
LEDGER = ROOT / "docs" / "pkcs11-mechanism-ledger.json"

VALID_PREFIXES = ("implemented", "not-advertised", "excluded-by-scope:",
                  "deferred:", "tracked-todo:")

failures = []


def fail(msg: str) -> None:
    failures.append(msg)


def read(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="replace")


def canonical_mechanisms() -> dict:
    return {
        n: v
        for n, v in re.findall(
            r"^#define\s+(CKM_[A-Z0-9_]+)\s+(0x[0-9a-fA-F]+)UL", read(CANON_HEADER), re.M
        )
    }


def cpp_advertised() -> set:
    src = read(CPP_SLOTS)
    try:
        start = src.index("void SoftHSM::prepareSupportedMechanisms")
    except ValueError:
        fail(f"{CPP_SLOTS.name}: prepareSupportedMechanisms not found — this "
             f"checker reads the advertised set from it; the parse must be "
             f"repaired, not skipped")
        return set()
    body = src[start:]
    body = body[: body.index("\n}\n")]
    return set(re.findall(r'^\s*t\["(CKM_[A-Z0-9_]+)"\]', body, re.M))


def rust_advertised() -> set:
    src = read(RUST_CONSTS)
    try:
        start = src.index("pub const SUPPORTED_MECHS")
    except ValueError:
        fail(f"{RUST_CONSTS.name}: SUPPORTED_MECHS not found — see above")
        return set()
    body = src[start:]
    body = body[: body.index("\n];")]
    return set(re.findall(r"^\s*(CKM_[A-Z0-9_]+),", body, re.M))


def main() -> int:
    if not LEDGER.exists():
        print(f"FAIL: {LEDGER} is missing. Generate it with "
              f"scripts/gen_pkcs11_mechanism_ledger.py", file=sys.stderr)
        return 1

    ledger = json.loads(read(LEDGER))
    rows = ledger.get("rows", {})
    reasons = ledger.get("scope_reasons", {})
    canon = canonical_mechanisms()
    advertised = {"cpp": cpp_advertised(), "rust": rust_advertised()}

    if not rows:
        fail("ledger has no rows")

    # (a) every canonical mechanism has a row
    for name in sorted(canon):
        if name not in rows:
            fail(f"{name}: in the canonical header but has NO ledger row. A "
                 f"mechanism with no row is an undocumented decision — add one "
                 f"(regenerate, or write it by hand).")

    # (e) every advertised name has a row
    for engine, names in advertised.items():
        for name in sorted(names):
            if name not in rows:
                fail(f"{name}: advertised by the {engine} engine but has NO "
                     f"ledger row. Every mechanism a caller can see in "
                     f"C_GetMechanismList must be accounted for.")

    for name in sorted(rows):
        row = rows[name]

        # (b) value agrees with the canonical header
        if name in canon:
            declared = str(row.get("value", "")).lower()
            if declared != canon[name].lower():
                fail(f"{name}: ledger value {row.get('value')!r} disagrees with "
                     f"the canonical header's {canon[name]!r}. "
                     f"docs/refs/pkcs11t-canonical-v3.2.h wins.")
        elif row.get("value") != "engine-extension":
            fail(f"{name}: not in the canonical header, so its value must be "
                 f"the literal \"engine-extension\"; found {row.get('value')!r}.")

        for engine in ("cpp", "rust"):
            status = row.get(engine)
            if status is None:
                fail(f"{name}: no {engine!r} disposition.")
                continue
            if not any(status == p or status.startswith(p) for p in VALID_PREFIXES):
                fail(f"{name}: {engine} disposition {status!r} is not one of "
                     f"{VALID_PREFIXES}.")
                continue

            is_advertised = name in advertised[engine]

            # (c) the claim must match reality, in BOTH directions
            if status == "implemented" and not is_advertised:
                fail(f"{name}: ledger says the {engine} engine implements it, "
                     f"but it is not in that engine's advertised set. Either "
                     f"the engine lost it or the ledger overstates.")
            if status != "implemented" and is_advertised:
                fail(f"{name}: the {engine} engine ADVERTISES it, but the "
                     f"ledger records {status!r}. A mechanism was added without "
                     f"updating the ledger — that is exactly the drift this "
                     f"check exists to catch.")

            # (d) scope keys must resolve, and nothing may stay unclassified
            if status.startswith("excluded-by-scope:"):
                key = status.split(":", 1)[1]
                if key == "UNCLASSIFIED":
                    fail(f"{name}: {engine} is UNCLASSIFIED. Give it a rule in "
                         f"gen_pkcs11_mechanism_ledger.py or a hand-written "
                         f"disposition — an unexplained exclusion is the thing "
                         f"this ledger replaces.")
                elif key not in reasons:
                    fail(f"{name}: {engine} cites scope key {key!r}, which has "
                         f"no entry in scope_reasons.")

    if failures:
        print(f"FAIL — {len(failures)} mechanism-ledger problem(s):\n", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        print("\nLedger: docs/pkcs11-mechanism-ledger.json", file=sys.stderr)
        return 1

    n_cpp = len(advertised["cpp"])
    n_rust = len(advertised["rust"])
    cpp_only = sorted(advertised["cpp"] - advertised["rust"])
    print(f"OK — mechanism ledger consistent: {len(rows)} rows "
          f"({len(canon)} canonical + {len(rows) - len(canon)} engine extensions); "
          f"C++ advertises {n_cpp}, Rust {n_rust}; "
          f"C++-only: {len(cpp_only)}{' ' + str(cpp_only) if cpp_only else ''}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
