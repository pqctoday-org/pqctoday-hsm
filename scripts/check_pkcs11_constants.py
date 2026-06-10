#!/usr/bin/env python3
"""CI guard: diff rust/src/constants.rs CK* values against the normative
src/lib/pkcs11/pkcs11t.h. Prevents the C-3 class of bug (wrong mechanism IDs
sourced from non-normative manifests) permanently.

Exit 0 = clean; exit 1 = any spec-name value mismatch.
Vendor/internal constants are allowed via WHITELIST below.
"""
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
RUST = REPO / "rust" / "src" / "constants.rs"
HEADER = REPO / "src" / "lib" / "pkcs11" / "pkcs11t.h"

# Intentional vendor / internal / IANA-sourced names that do NOT exist in
# pkcs11t.h (or intentionally differ). Each entry is a regex on the full name.
WHITELIST = [
    r"^CKA_PRIV_",                # engine-internal attrs (0xFFFF....)
    r"^CKA_STATEFUL_KEY_STATE$",  # vendor stateful-key attrs (0x800001xx)
    r"^CKA_LMS_PARAM_SET$", r"^CKA_LMOTS_PARAM_SET$",
    r"^CKA_XMSS_PARAM_SET$", r"^CKA_XMSSMT_PARAM_SET$",
    r"^CKA_LEAF_INDEX$", r"^CKA_XMSS_KEYS_REMAINING$",
    r"^CKM_KECCAK_256$",          # vendor digest (0x80000010)
    r"^CKM_EC_MONTGOMERY_KEY_DERIVE$",  # vendor alias (0x80000011)
    r"^CKM_AES_KEY_WRAP_PAD_LEGACY$",   # removed; keep tolerant if re-added
    r"^CKM_BIP32_",               # BIP32 vendor mechanisms
    r"^CKA_BIP32_",
    r"^CKF_BIP32_HARDENED$",
    r"^CKP_LMS_", r"^CKP_LMOTS_",  # IANA LMS registry values (RFC 8554)
    r"^CKP_XMSS_", r"^CKP_XMSSMT_",  # RFC 8391 OID values
    r"^CKP_PBKDF2_HMAC_",         # naming drift, values correct (spec: CKP_PKCS5_PBKD2_HMAC_*)
    r"^CKM_UNAVAILABLE_INFORMATION$",  # naming drift (spec: CK_UNAVAILABLE_INFORMATION)
    r"^CK_SP800_108_BYTE_ARRAY$",  # spec name without CKx_ prefix pattern
    r"^CKF_HKDF_SALT_DATA$",
    r"^CKD_SHA3_",                # present in spec; parser may miss CKD block
]
WHITELIST_RE = [re.compile(p) for p in WHITELIST]


def parse_rust(path: Path) -> dict[str, int]:
    out = {}
    pat = re.compile(
        r"pub const (CK[A-Z0-9_]*)\s*:\s*u32\s*=\s*(0x[0-9a-fA-F_]+|\d+)\s*;"
    )
    for m in pat.finditer(path.read_text()):
        name, raw = m.group(1), m.group(2).replace("_", "")
        out[name] = int(raw, 16) if raw.lower().startswith("0x") else int(raw)
    return out


def parse_header(path: Path) -> dict[str, int]:
    out = {}
    text = path.read_text(errors="replace")
    pat = re.compile(
        r"#define\s+(CK[A-Za-z0-9_]+)\s+\(?((?:0x[0-9a-fA-F]+|\d+)UL?L?"
        r"(?:\s*\|\s*0x[0-9a-fA-F]+UL?L?)?)\)?"
    )
    for m in pat.finditer(text):
        name, expr = m.group(1), m.group(2)
        expr = expr.replace("UL", "").replace("L", "")
        try:
            val = 0
            for part in expr.split("|"):
                part = part.strip()
                # resolve CKM_VENDOR_DEFINED-style symbol refs if present
                val |= int(part, 16) if part.lower().startswith("0x") else int(part)
            out[name] = val
        except ValueError:
            continue  # non-numeric defines (CK_PTR etc.)
    # second pass: resolve `#define X (CKM_VENDOR_DEFINED | 0x...)` forms
    pat2 = re.compile(
        r"#define\s+(CK[A-Za-z0-9_]+)\s+\(\s*(CK[A-Za-z0-9_]+)\s*\|\s*"
        r"(0x[0-9a-fA-F]+)UL?\s*\)"
    )
    for m in pat2.finditer(text):
        name, sym, lit = m.groups()
        if sym in out:
            out[name] = out[sym] | int(lit, 16)
    return out


def whitelisted(name: str) -> bool:
    return any(r.match(name) for r in WHITELIST_RE)


def main() -> int:
    rust = parse_rust(RUST)
    spec = parse_header(HEADER)
    mismatches, missing = [], []
    for name, val in sorted(rust.items()):
        if name in spec:
            if spec[name] != val:
                mismatches.append((name, val, spec[name]))
        elif not whitelisted(name):
            missing.append((name, val))

    for name, rv, sv in mismatches:
        print(f"MISMATCH  {name}: rust=0x{rv:08x} spec=0x{sv:08x}")
    for name, rv in missing:
        print(f"NOT-IN-SPEC (not whitelisted)  {name} = 0x{rv:08x}")

    total = len(rust)
    ok = total - len(mismatches) - len(missing)
    print(f"\nchecked {total} constants: {ok} ok, "
          f"{len(mismatches)} mismatched, {len(missing)} unlisted")
    return 1 if mismatches or missing else 0


if __name__ == "__main__":
    sys.exit(main())
