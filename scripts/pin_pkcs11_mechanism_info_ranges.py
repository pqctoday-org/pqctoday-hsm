#!/usr/bin/env python3
"""Pin each mechanism's CK_MECHANISM_INFO key-size range into the ledger.

Phase-5 §2 (docs/remediation-plan-pkcs11-phase5-09072026.md). Companion to
gen_pkcs11_mechanism_ledger.py, which records only whether each engine
IMPLEMENTS a mechanism. LEGAL-MECHANISM-INFO-KEY-SIZE-RANGES in
tests/differential/exceptions.json excuses 86 mechanisms' ulMinKeySize/
ulMaxKeySize differences by PATH, not value — its own text records the
consequence: a future change to either engine's range is excused too.
That is how CKM_AES_CMAC advertised a 64-byte maximum in Rust against
C++'s 32 for weeks before anything looked.

WHAT THIS DOES. Builds the C++/Rust engines and the differential harness
(reusing run-differential-harness.sh's own build step so the values come
from the SAME binaries the harness itself compares, never a hand-copied
table), runs ONLY env.mechanism_info_all with the harness's --dump-scenario
flag (added alongside this script) to get every mechanism's RAW min/max/
flags from BOTH engines -- not just the ones that already disagree, since
the normal report drops anything that matches -- then writes cpp_min/
cpp_max/rust_min/rust_max onto the matching row in
docs/pkcs11-mechanism-ledger.json. A row is touched only where that
engine's C_GetMechanismInfo returned CKR_OK; a mechanism neither engine
implements gets no range fields, matching the ledger's existing
implemented/not-advertised convention.

NAME RESOLUTION. The harness's own mech_name() table is small (54 of the
~166 mechanisms probed resolve to a symbolic name; the rest come back as
CKM_0x######## -- see p11_diff.cpp's own comment: "only the ones
scenarios actually reference"). So every mechanism is matched by NUMERIC
VALUE, not by name: this script parses BOTH engines' own value
definitions --
  * src/lib/pkcs11/pkcs11t.h, which is CLAUDE.md's declared source of
    truth for every CK* constant, including simple
    "(CKM_VENDOR_DEFINED | 0x...UL)" vendor-mechanism expressions
    (KMAC, ...); CKM_VENDOR_DEFINED itself is 0x80000000, defined in the
    same file;
  * rust/src/constants.rs, whose CKM_* items are already resolved plain
    hex literals -- for the (currently 6) mechanisms Rust advertises that
    C++'s header does not define at all.
Between the two, every mechanism either engine can return from
C_GetMechanismInfo has a known value, which is matched against the raw
hex embedded in the dump's own path segment.

Usage:  python3 scripts/pin_pkcs11_mechanism_info_ranges.py [--no-build]
"""

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LEDGER = ROOT / "docs" / "pkcs11-mechanism-ledger.json"
CPP_HEADER = ROOT / "src" / "lib" / "pkcs11" / "pkcs11t.h"
RUST_CONSTS = ROOT / "rust" / "src" / "constants.rs"
BUILD_DIR = ROOT / "build_union"
BIN = BUILD_DIR / "p11_diff"


def read(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="replace")


def parse_cpp_header_values() -> dict:
    """{name: int_value} for every #define CKM_* in the local header,
    including simple '(CKM_VENDOR_DEFINED | 0x...UL)' expressions."""
    src = read(CPP_HEADER)
    vendor_base = 0x80000000
    m = re.search(r"^#define\s+CKM_VENDOR_DEFINED\s+(0x[0-9a-fA-F]+)UL", src, re.M)
    if m:
        vendor_base = int(m.group(1), 16)

    values = {}
    for name, expr in re.findall(
        r"^#define\s+(CKM_[A-Z0-9_]+)\s+\(?\s*"
        r"(CKM_VENDOR_DEFINED\s*\|\s*0x[0-9a-fA-F]+|0x[0-9a-fA-F]+)(?:UL)?\s*\)?",
        src, re.M,
    ):
        if "CKM_VENDOR_DEFINED" in expr:
            offset_match = re.search(r"0x[0-9a-fA-F]+", expr.split("|", 1)[1])
            if not offset_match:
                continue
            values[name] = vendor_base | int(offset_match.group(0), 16)
        else:
            values[name] = int(expr, 16)
    return values


def parse_rust_const_values() -> dict:
    """{name: int_value} for plain 'pub const CKM_* : u32 = 0x...;' items."""
    src = read(RUST_CONSTS)
    values = {}
    for name, hexval in re.findall(
        r"^\s*pub const\s+(CKM_[A-Z0-9_]+)\s*:\s*u32\s*=\s*([0-9a-fA-Fx_]+)\s*;",
        src, re.M,
    ):
        try:
            values[name] = int(hexval.replace("_", ""), 16 if "x" in hexval else 10)
        except ValueError:
            continue
    return values


def build_value_to_name(cpp_vals: dict, rust_vals: dict) -> dict:
    """Merge both sources into {int_value: name}. C++'s header wins on a
    clash -- it is the declared source of truth -- but a clash would mean
    the two engines disagree about what a shared name means, which is
    worth knowing, so it is reported rather than silently overwritten."""
    value_to_name = {}
    clashes = []
    for name, v in cpp_vals.items():
        value_to_name[v] = name
    for name, v in rust_vals.items():
        if v in value_to_name and value_to_name[v] != name:
            clashes.append((v, value_to_name[v], name))
        value_to_name.setdefault(v, name)
    if clashes:
        print("WARNING: value clashes between C++ header and Rust constants:", file=sys.stderr)
        for v, cpp_name, rust_name in clashes:
            print(f"  0x{v:08x}: cpp={cpp_name} rust={rust_name}", file=sys.stderr)
    return value_to_name


MECH_KEY_RE = re.compile(r"^mi\.(.+)\.(rv|min|max|flags)$")


def parse_mech_value(key: str, value_to_name: dict) -> tuple:
    """Returns (numeric_value, resolved_name_or_None) for one dump path
    segment. mech_name() (p11_diff.cpp) emits three shapes: a resolved
    symbolic name; 'CKM_0x########' for an unresolved value with the
    vendor bit clear; 'CKM_VENDOR|0x########' for one with it set, WITH
    THE VENDOR BIT ALREADY STRIPPED from the printed offset -- it must be
    re-added before the value means anything."""
    if key.startswith("CKM_VENDOR|0x"):
        offset = int(key[len("CKM_VENDOR|0x"):], 16)
        v = 0x80000000 | offset
        return v, value_to_name.get(v)
    if key.startswith("CKM_0x"):
        v = int(key[len("CKM_0x"):], 16)
        return v, value_to_name.get(v)
    # A symbolic name the harness's own mech_name() resolved. Trust it
    # directly rather than re-deriving the value -- it already IS the name.
    return None, key


def run_dump(no_build: bool) -> dict:
    with tempfile.TemporaryDirectory() as td:
        dump_path = Path(td) / "mech_info_dump.json"
        cmd = ["bash", "scripts/run-differential-harness.sh",
               "--only", "env.mechanism_info_all"]
        if no_build:
            cmd.append("--no-build")
        # run-differential-harness.sh does not know --dump-scenario, so build
        # first via the normal script (for engine freshness), then invoke the
        # compiled binary a second time, directly, with the dump flags. The
        # binary is cheap to re-run -- a single scenario, in-memory token.
        print("==> building engines + harness via run-differential-harness.sh")
        subprocess.run(cmd, cwd=ROOT, check=True)

        cpp_engine = BUILD_DIR / "src" / "lib" / "libsofthsmv3.dylib"
        if not cpp_engine.exists():
            cpp_engine = BUILD_DIR / "src" / "lib" / "libsofthsmv3.so"
        rust_engine = ROOT / "rust" / "target" / "debug" / "libsofthsmrustv3.dylib"
        if not rust_engine.exists():
            rust_engine = ROOT / "rust" / "target" / "debug" / "libsofthsmrustv3.so"

        print("==> dumping raw per-engine CK_MECHANISM_INFO")
        subprocess.run([
            str(BIN),
            "--cpp-engine", str(cpp_engine),
            "--rust-engine", str(rust_engine),
            "--workdir", str(BUILD_DIR / "p11_diff_workdir"),
            "--report", str(BUILD_DIR / "p11_diff_report"),
            "--only", "env.mechanism_info_all",
            "--dump-scenario", "env.mechanism_info_all",
            "--dump-file", str(dump_path),
        ], cwd=ROOT, check=True)

        return json.loads(dump_path.read_text())


def main() -> int:
    no_build = "--no-build" in sys.argv[1:]

    cpp_vals = parse_cpp_header_values()
    rust_vals = parse_rust_const_values()
    value_to_name = build_value_to_name(cpp_vals, rust_vals)
    print(f"resolved {len(value_to_name)} mechanism name<->value pairs "
          f"({len(cpp_vals)} from pkcs11t.h, {len(rust_vals)} from constants.rs)")

    dump = run_dump(no_build)

    # {name: {"cpp": {min,max}, "rust": {min,max}}}
    per_mech = {}
    unresolved = set()
    for engine in ("cpp", "rust"):
        for key, val in dump[engine].items():
            m = MECH_KEY_RE.match(key)
            if not m:
                continue
            mech_key, field = m.group(1), m.group(2)
            _, name = parse_mech_value(mech_key, value_to_name)
            if name is None:
                unresolved.add(mech_key)
                continue
            slot = per_mech.setdefault(name, {}).setdefault(engine, {})
            slot[field] = val

    if unresolved:
        print(f"\n{len(unresolved)} dump entries could not be resolved to a "
              f"name (present in neither header) -- NOT pinned:", file=sys.stderr)
        for u in sorted(unresolved):
            print(f"  {u}", file=sys.stderr)

    ledger = json.loads(read(LEDGER))
    rows = ledger["rows"]

    touched = {"cpp": 0, "rust": 0}
    missing_row = set()
    for name, data in per_mech.items():
        row = rows.get(name)
        if row is None:
            missing_row.add(name)
            continue
        for engine in ("cpp", "rust"):
            e = data.get(engine)
            if not e or e.get("rv") != "CKR_OK":
                continue
            if "min" in e and "max" in e:
                row[f"{engine}_min"] = int(e["min"])
                row[f"{engine}_max"] = int(e["max"])
                touched[engine] += 1

    if missing_row:
        print(f"\n{len(missing_row)} resolved mechanism(s) have NO ledger row "
              f"at all -- regenerate the ledger first "
              f"(scripts/gen_pkcs11_mechanism_ledger.py):", file=sys.stderr)
        for n in sorted(missing_row):
            print(f"  {n}", file=sys.stderr)

    LEDGER.write_text(json.dumps(ledger, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"\nwrote {LEDGER.relative_to(ROOT)}: pinned cpp range on "
          f"{touched['cpp']} rows, rust range on {touched['rust']} rows")
    return 1 if (unresolved or missing_row) else 0


if __name__ == "__main__":
    sys.exit(main())
