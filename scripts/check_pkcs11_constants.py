#!/usr/bin/env python3
"""CI guard for PKCS#11 constant integrity.

Validated sources (all diffed against the normative src/lib/pkcs11/pkcs11t.h):
  1. rust/src/constants.rs           — engine constants (u32)
  2. constants.js                    — published npm surface (@pqctoday/softhsm-wasm)
  3. kmip/pkcs11-mech-manifest.json  — `standard_pkcs11_v3_2` block
  4. src/lib/pkcs11/pkcs11t.h itself — diffed against the pinned canonical
     OASIS v3.2 include (docs/refs/pkcs11t-canonical-v3.2.h, sha256-pinned)
  5. src/lib/vendor_mechanisms.h     — C++ vendor constants (N9 remediation
     2026-08-13; previously a blind spot)
  6. src/lib/pkcs11/pkcs11f.h        — asserted byte-identical to the pinned
     canonical OASIS v3.2 function header
     (docs/refs/pkcs11f-canonical-v3.2.h, sha256-pinned); on divergence the
     CK_PKCS11_FUNCTION_INFO name sets are diff-reported

NOT validated here (known, deliberate): constants embedded in prose/docs,
per-protocol wrapper sources (openssh-pkcs11/, strongswan-pkcs11/, JavaJCE/,
openpgp/), and pkcs11.h itself (a thin include shim).

Rules:
  * Every CK* name in a source must either match the header value exactly or
    appear in PINNED below with the exact pinned value (no blanket regex
    whitelist — drift in formerly-whitelisted IANA/vendor constants FAILS).
  * PINNED entries of kind "vendor" must live in vendor space (>= 0x80000000).
  * Duplicate codepoints within a registry-style CK class (header AND each
    source) fail unless the colliding names form a known spec alias group.
  * The local header may only differ from the canonical OASIS header by
    vendor-space (>= 0x80000000) additions.

Exit 0 = clean; exit 1 = any failure. Per-source summary printed.
"""
import hashlib
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
RUST = REPO / "rust" / "src" / "constants.rs"
JS = REPO / "constants.js"
HEADER = REPO / "src" / "lib" / "pkcs11" / "pkcs11t.h"
VENDOR_HEADER = REPO / "src" / "lib" / "vendor_mechanisms.h"
CANONICAL = REPO / "docs" / "refs" / "pkcs11t-canonical-v3.2.h"
FUNC_HEADER = REPO / "src" / "lib" / "pkcs11" / "pkcs11f.h"
CANONICAL_F = REPO / "docs" / "refs" / "pkcs11f-canonical-v3.2.h"
MANIFEST = REPO / "kmip" / "pkcs11-mech-manifest.json"

# sha256 of the canonical OASIS PKCS#11 v3.2 pkcs11t.h pinned in F1.
# https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/include/pkcs11-v3.2/pkcs11t.h
CANONICAL_SHA256 = "95738fdcd9b5c9c73f55f9132aefa87354556cec1c46f681b8a2000b8b5dbccb"

# sha256 of the canonical OASIS PKCS#11 v3.2 pkcs11f.h (N9 remediation
# 2026-08-13; same pinning pattern as pkcs11t.h above).
# https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/include/pkcs11-v3.2/pkcs11f.h
CANONICAL_F_SHA256 = "3a205ff9a12247108193d124571fac88e38b59f1273e462baa1b5e00cd182fa0"

VENDOR_BASE = 0x80000000

# ── Pinned constants ─────────────────────────────────────────────────────────
# Names that intentionally do NOT exist in pkcs11t.h. Each is pinned to an
# exact value so any future drift fails. kind:
#   iana   — IANA-registered numeric IDs (RFC 8554 / RFC 8391 / SP 800-208);
#            values feed CKA_HSS_LMS_TYPE / vendor *_PARAM_SET attributes.
#   vendor — pqctoday vendor space; MUST be >= 0x80000000 (structural rule).
#   legacy — pre-vendor-migration compat codepoints kept for old tokens.
#   drift  — naming drift from a spec constant; value equals the spec one.
#   abi    — wasm32 ABI struct sizes exported on the JS surface only.
#   param-set — pqctoday's own small-integer CKA_PARAMETER_SET enumeration
#            for a vendor key type; not a codepoint, so exempt from the
#            vendor-space (>= 0x80000000) rule (same idea as CKP_ML_DSA_*/
#            CKP_ML_KEM_* in the OASIS header itself).
PINNED = {
    # LMS tree parameter sets (IANA "LMS" registry, RFC 8554 §5 + SP 800-208 §4)
    "CKP_LMS_SHA256_M32_H5": (0x05, "iana"),
    "CKP_LMS_SHA256_M32_H10": (0x06, "iana"),
    "CKP_LMS_SHA256_M32_H15": (0x07, "iana"),
    "CKP_LMS_SHA256_M32_H20": (0x08, "iana"),
    "CKP_LMS_SHA256_M32_H25": (0x09, "iana"),
    "CKP_LMS_SHA256_M24_H5": (0x0A, "iana"),
    "CKP_LMS_SHA256_M24_H10": (0x0B, "iana"),
    "CKP_LMS_SHA256_M24_H15": (0x0C, "iana"),
    "CKP_LMS_SHA256_M24_H20": (0x0D, "iana"),
    "CKP_LMS_SHA256_M24_H25": (0x0E, "iana"),
    "CKP_LMS_SHAKE_M32_H5": (0x0F, "iana"),
    "CKP_LMS_SHAKE_M32_H10": (0x10, "iana"),
    "CKP_LMS_SHAKE_M32_H15": (0x11, "iana"),
    "CKP_LMS_SHAKE_M32_H20": (0x12, "iana"),
    "CKP_LMS_SHAKE_M32_H25": (0x13, "iana"),
    "CKP_LMS_SHAKE_M24_H5": (0x14, "iana"),
    "CKP_LMS_SHAKE_M24_H10": (0x15, "iana"),
    "CKP_LMS_SHAKE_M24_H15": (0x16, "iana"),
    "CKP_LMS_SHAKE_M24_H20": (0x17, "iana"),
    "CKP_LMS_SHAKE_M24_H25": (0x18, "iana"),
    # LM-OTS parameter sets (IANA "LM-OTS" registry, RFC 8554 §4 + SP 800-208 §4)
    "CKP_LMOTS_SHA256_N32_W1": (0x01, "iana"),
    "CKP_LMOTS_SHA256_N32_W2": (0x02, "iana"),
    "CKP_LMOTS_SHA256_N32_W4": (0x03, "iana"),
    "CKP_LMOTS_SHA256_N32_W8": (0x04, "iana"),
    "CKP_LMOTS_SHA256_N24_W1": (0x05, "iana"),
    "CKP_LMOTS_SHA256_N24_W2": (0x06, "iana"),
    "CKP_LMOTS_SHA256_N24_W4": (0x07, "iana"),
    "CKP_LMOTS_SHA256_N24_W8": (0x08, "iana"),
    "CKP_LMOTS_SHAKE_N32_W1": (0x09, "iana"),
    "CKP_LMOTS_SHAKE_N32_W2": (0x0A, "iana"),
    "CKP_LMOTS_SHAKE_N32_W4": (0x0B, "iana"),
    "CKP_LMOTS_SHAKE_N32_W8": (0x0C, "iana"),
    "CKP_LMOTS_SHAKE_N24_W1": (0x0D, "iana"),
    "CKP_LMOTS_SHAKE_N24_W2": (0x0E, "iana"),
    "CKP_LMOTS_SHAKE_N24_W4": (0x0F, "iana"),
    "CKP_LMOTS_SHAKE_N24_W8": (0x10, "iana"),
    # XMSS parameter sets (RFC 8391 §8 / NIST SP 800-208 §5.3 IANA "XMSS
    # Signatures" registry ids — the same numbering the C++ engine's
    # xmss-reference params.c uses). N1 remediation 2026-08-13: the SHAKE
    # (SHAKE128) sets moved to their standard 0x07-0x09 ids; 0x11-0x13 are
    # the SHAKE256-based sets those ids actually denote in the registry
    # (previously mislabeled here as SHAKE128 under "historical numbering").
    "CKP_XMSS_SHA2_10_256": (0x01, "iana"),
    "CKP_XMSS_SHA2_16_256": (0x02, "iana"),
    "CKP_XMSS_SHA2_20_256": (0x03, "iana"),
    "CKP_XMSS_SHAKE_10_256": (0x07, "iana"),
    "CKP_XMSS_SHAKE_16_256": (0x08, "iana"),
    "CKP_XMSS_SHAKE_20_256": (0x09, "iana"),
    "CKP_XMSS_SHAKE256_16_256": (0x11, "iana"),
    "CKP_XMSS_SHAKE256_20_256": (0x12, "iana"),
    "CKP_XMSS_SHAKE256_10_192": (0x13, "iana"),
    # XMSS-MT parameter sets (RFC 8391 §8 numeric IDs, matching C++
    # xmssmt_parse_oid)
    "CKP_XMSSMT_SHA2_20_2_256": (0x01, "iana"),
    "CKP_XMSSMT_SHA2_20_4_256": (0x02, "iana"),
    "CKP_XMSSMT_SHA2_40_2_256": (0x03, "iana"),
    "CKP_XMSSMT_SHA2_40_4_256": (0x04, "iana"),
    "CKP_XMSSMT_SHA2_40_8_256": (0x05, "iana"),
    "CKP_XMSSMT_SHA2_60_3_256": (0x06, "iana"),
    "CKP_XMSSMT_SHA2_60_6_256": (0x07, "iana"),
    "CKP_XMSSMT_SHA2_60_12_256": (0x08, "iana"),
    "CKP_XMSSMT_SHA2_20_2_512": (0x09, "iana"),
    "CKP_XMSSMT_SHA2_20_4_512": (0x0A, "iana"),
    "CKP_XMSSMT_SHA2_40_2_512": (0x0B, "iana"),
    "CKP_XMSSMT_SHA2_40_4_512": (0x0C, "iana"),
    "CKP_XMSSMT_SHA2_40_8_512": (0x0D, "iana"),
    "CKP_XMSSMT_SHA2_60_3_512": (0x0E, "iana"),
    "CKP_XMSSMT_SHA2_60_6_512": (0x0F, "iana"),
    "CKP_XMSSMT_SHA2_60_12_512": (0x10, "iana"),
    "CKP_XMSSMT_SHAKE_20_2_256": (0x11, "iana"),
    "CKP_XMSSMT_SHAKE_20_4_256": (0x12, "iana"),
    "CKP_XMSSMT_SHAKE_40_2_256": (0x13, "iana"),
    "CKP_XMSSMT_SHAKE_40_4_256": (0x14, "iana"),
    "CKP_XMSSMT_SHAKE_40_8_256": (0x15, "iana"),
    "CKP_XMSSMT_SHAKE_60_3_256": (0x16, "iana"),
    "CKP_XMSSMT_SHAKE_60_6_256": (0x17, "iana"),
    "CKP_XMSSMT_SHAKE_60_12_256": (0x18, "iana"),
    "CKP_XMSSMT_SHAKE_20_2_512": (0x19, "iana"),
    "CKP_XMSSMT_SHAKE_20_4_512": (0x1A, "iana"),
    "CKP_XMSSMT_SHAKE_40_2_512": (0x1B, "iana"),
    "CKP_XMSSMT_SHAKE_40_4_512": (0x1C, "iana"),
    "CKP_XMSSMT_SHAKE_40_8_512": (0x1D, "iana"),
    "CKP_XMSSMT_SHAKE_60_3_512": (0x1E, "iana"),
    "CKP_XMSSMT_SHAKE_60_6_512": (0x1F, "iana"),
    "CKP_XMSSMT_SHAKE_60_12_512": (0x20, "iana"),
    # pqctoday vendor attributes / mechanisms (must sit in vendor space)
    "CKA_PRIV_PARAM_SET": (0xFFFF0001, "vendor"),
    "CKA_PRIV_ALGO_FAMILY": (0xFFFF0002, "vendor"),
    "CKA_PRIV_OWNER_SESSION": (0xFFFF0003, "vendor"),
    "CKA_PRIV_SLOT_ID": (0xFFFF0004, "vendor"),
    "CKA_STATEFUL_KEY_STATE": (0x80000101, "vendor"),
    "CKA_LMS_PARAM_SET": (0x80000102, "vendor"),
    "CKA_LMOTS_PARAM_SET": (0x80000103, "vendor"),
    "CKA_XMSS_PARAM_SET": (0x80000104, "vendor"),
    "CKA_LEAF_INDEX": (0x80000105, "vendor"),
    "CKA_XMSS_KEYS_REMAINING": (0x80000106, "vendor"),
    "CKA_XMSSMT_PARAM_SET": (0x80000107, "vendor"),
    "CKM_KECCAK_256": (0x80000010, "vendor"),
    "CKM_EC_MONTGOMERY_KEY_DERIVE": (0x80000011, "vendor"),
    # KMIP 3.0 §11.54 Create/Join Split Key (XOR + 3 Polynomial Sharing
    # variants) — no PKCS#11-standard mechanism for Shamir-style secret
    # splitting, so this is a pqctoday vendor mechanism reached only
    # through opaque object handles (v0.12.0 HONEST_MAXIMUM_PLAN). Next
    # sequential vendor-mechanism codepoint after CKM_EC_MONTGOMERY_KEY_DERIVE.
    "CKM_PQCTODAY_SPLIT_KEY": (0x80000012, "vendor"),
    # FrodoKEM / Classic McEliece (BSI TR-02102-1) — not OASIS-standardized,
    # so both the key types and mechanisms live in vendor space. Allocated in
    # pqctoday-priv's PKCS#11 authority file and mirrored into
    # kmip/pkcs11-mech-manifest.json.
    "CKK_PQCTODAY_FRODOKEM": (0x80000001, "vendor"),
    "CKK_PQCTODAY_CLASSIC_MCELIECE": (0x80000002, "vendor"),
    "CKM_PQCTODAY_FRODOKEM_KEY_PAIR_GEN": (0x80000001, "vendor"),
    "CKM_PQCTODAY_FRODOKEM_ENCAPSULATE": (0x80000002, "vendor"),
    "CKM_PQCTODAY_CLASSIC_MCELIECE_KEY_PAIR_GEN": (0x80000003, "vendor"),
    "CKM_PQCTODAY_CLASSIC_MCELIECE_ENCAPSULATE": (0x80000004, "vendor"),
    # FrodoKEM / Classic McEliece CKA_PARAMETER_SET enumeration (own small-
    # integer numbering, same convention as CKP_ML_DSA_*/CKP_ML_KEM_* above).
    "CKP_FRODOKEM_640_AES": (0x01, "param-set"),
    "CKP_FRODOKEM_640_SHAKE": (0x02, "param-set"),
    "CKP_FRODOKEM_976_AES": (0x03, "param-set"),
    "CKP_FRODOKEM_976_SHAKE": (0x04, "param-set"),
    "CKP_FRODOKEM_1344_AES": (0x05, "param-set"),
    "CKP_FRODOKEM_1344_SHAKE": (0x06, "param-set"),
    "CKP_CLASSIC_MCELIECE_6688128": (0x01, "param-set"),
    # legacy bare BIP32 codepoints (pre vendor-space migration, still accepted)
    "CKA_BIP32_CHAIN_CODE_LEGACY": (0x1021, "legacy"),
    "CKA_BIP32_CHILD_INDEX_LEGACY": (0x1022, "legacy"),
    "CKM_BIP32_MASTER_DERIVE_LEGACY": (0x105B, "legacy"),
    "CKM_BIP32_CHILD_DERIVE_LEGACY": (0x105C, "legacy"),
    # naming drift from spec constants (values equal the spec ones)
    "CKP_PBKDF2_HMAC_SHA256": (0x04, "drift"),  # = CKP_PKCS5_PBKD2_HMAC_SHA256
    "CKP_PBKDF2_HMAC_SHA384": (0x05, "drift"),  # = CKP_PKCS5_PBKD2_HMAC_SHA384
    "CKP_PBKDF2_HMAC_SHA512": (0x06, "drift"),  # = CKP_PKCS5_PBKD2_HMAC_SHA512
    "CKM_UNAVAILABLE_INFORMATION": (0xFFFFFFFF, "drift"),  # = CK_UNAVAILABLE_INFORMATION
    # spec defines CK_UNAVAILABLE_INFORMATION as (~0UL) — not a parseable
    # literal; 0xFFFFFFFF IS (~0UL) on the engine's 32-bit CK_ULONG ABI.
    "CK_UNAVAILABLE_INFORMATION": (0xFFFFFFFF, "drift"),
    # wasm32 ABI struct sizes published on the JS surface
    "CK_ATTRIBUTE_SIZE": (12, "abi"),
    "CK_MECHANISM_SIZE": (12, "abi"),
    "CK_SIGN_ADDITIONAL_CONTEXT_SIZE": (12, "abi"),
}

# Cross-check: drift pins must equal their spec counterpart in the header.
DRIFT_SPEC_TWIN = {
    "CKP_PBKDF2_HMAC_SHA256": "CKP_PKCS5_PBKD2_HMAC_SHA256",
    "CKP_PBKDF2_HMAC_SHA384": "CKP_PKCS5_PBKD2_HMAC_SHA384",
    "CKP_PBKDF2_HMAC_SHA512": "CKP_PKCS5_PBKD2_HMAC_SHA512",
}

# ── Duplicate-codepoint policy ───────────────────────────────────────────────
# Registry-style classes: one codepoint = one meaning, duplicates are bugs
# unless the names form a spec alias group below.
DUP_CHECK_CLASSES = ("CKM_", "CKA_", "CKR_", "CKK_", "CKO_", "CKU_",
                     "CKC_", "CKD_", "CKN_")
# CKF_/CKP_/CKH_/CKG_/CKS_/CKZ_ are context-scoped families where the spec
# itself reuses codepoints across unrelated domains (e.g. session flags vs
# token flags, profiles vs parameter sets, MGFs vs generators) — a global
# duplicate scan over those prefixes is meaningless and is skipped.

# Spec-legitimate aliases (same codepoint, both names normative).
ALIAS_GROUPS = [
    {"CKK_EC", "CKK_ECDSA"},
    {"CKK_CAST128", "CKK_CAST5"},
    {"CKA_EC_PARAMS", "CKA_ECDSA_PARAMS"},
    {"CKA_SUBPRIME_BITS", "CKA_SUB_PRIME_BITS"},
    {"CKM_EC_KEY_PAIR_GEN", "CKM_ECDSA_KEY_PAIR_GEN"},
    # original spec misspelling kept as a compat alias since v2.40
    {"CKM_DSA_PROBABILISTIC_PARAMETER_GEN", "CKM_DSA_PROBABLISTIC_PARAMETER_GEN"},
    {"CKM_CAST128_KEY_GEN", "CKM_CAST5_KEY_GEN"},
    {"CKM_CAST128_ECB", "CKM_CAST5_ECB"},
    {"CKM_CAST128_CBC", "CKM_CAST5_CBC"},
    {"CKM_CAST128_MAC", "CKM_CAST5_MAC"},
    {"CKM_CAST128_MAC_GENERAL", "CKM_CAST5_MAC_GENERAL"},
    {"CKM_CAST128_CBC_PAD", "CKM_CAST5_CBC_PAD"},
    {"CKM_PBE_MD5_CAST128_CBC", "CKM_PBE_MD5_CAST5_CBC"},
    {"CKM_PBE_SHA1_CAST128_CBC", "CKM_PBE_SHA1_CAST5_CBC"},
    {"CKM_SHA3_224_KEY_DERIVATION", "CKM_SHA3_224_KEY_DERIVE"},
    {"CKM_SHA3_256_KEY_DERIVATION", "CKM_SHA3_256_KEY_DERIVE"},
    {"CKM_SHA3_384_KEY_DERIVATION", "CKM_SHA3_384_KEY_DERIVE"},
    {"CKM_SHA3_512_KEY_DERIVATION", "CKM_SHA3_512_KEY_DERIVE"},
    {"CKM_SHAKE_128_KEY_DERIVATION", "CKM_SHAKE_128_KEY_DERIVE"},
    {"CKM_SHAKE_256_KEY_DERIVATION", "CKM_SHAKE_256_KEY_DERIVE"},
]


# ── Parsers ──────────────────────────────────────────────────────────────────
def parse_header(path: Path) -> dict:
    """Parse all numeric #define CK* entries, resolving (SYM | lit) and pure
    symbol aliases (#define A B) in extra passes."""
    out = {}
    text = path.read_text(errors="replace")
    pat = re.compile(
        r"^\s*#define\s+(CK[A-Za-z0-9_]+)\s+\(?\s*"
        r"((?:0x[0-9a-fA-F]+|\d+))(?:UL|U|L)?\s*\)?\s*(?:/\*.*)?$",
        re.M,
    )
    for m in pat.finditer(text):
        out[m.group(1)] = int(m.group(2), 0)
    # `#define X (CKM_VENDOR_DEFINED | 0x...)` forms
    pat2 = re.compile(
        r"^\s*#define\s+(CK[A-Za-z0-9_]+)\s+\(\s*(CK[A-Za-z0-9_]+)\s*\|\s*"
        r"(0x[0-9a-fA-F]+)(?:UL|U|L)?\s*\)",
        re.M,
    )
    # pure aliases: `#define CKA_SUB_PRIME_BITS CKA_SUBPRIME_BITS`
    pat3 = re.compile(
        r"^\s*#define\s+(CK[A-Za-z0-9_]+)\s+(CK[A-Za-z0-9_]+)\s*(?:/\*.*)?$",
        re.M,
    )
    for _ in range(3):  # fixed-point over chained aliases
        for m in pat2.finditer(text):
            name, sym, lit = m.groups()
            if sym in out:
                out[name] = out[sym] | int(lit, 16)
        for m in pat3.finditer(text):
            name, sym = m.groups()
            if sym in out:
                out[name] = out[sym]
    return out


def parse_rust(path: Path) -> dict:
    out = {}
    text = path.read_text()
    # RHS is captured as a raw expression (not just a bare literal) so a
    # constant may be composed from other already-declared constants, e.g.
    # `pub const CKA_ALLOWED_MECHANISMS: u32 = CKF_ARRAY_ATTRIBUTE | 0x0000_0600;`
    # (§4.8 Table 13) or a plain alias `pub const X: u32 = Y;`.
    pat = re.compile(
        r"^pub const (CK[A-Z0-9_]*)\s*:\s*u32\s*=\s*(.+?)\s*;",
        re.M,
    )
    exprs = {m.group(1): m.group(2) for m in pat.finditer(text)}

    def resolve(expr: str):
        """Evaluate a `LITERAL | LITERAL | NAME | ...` RHS against already-
        resolved names in `out`. Returns None if any term isn't yet
        resolvable (forward reference to a constant not yet in `out`)."""
        val = 0
        for term in expr.split("|"):
            term = term.strip()
            digits = term.replace("_", "")  # Rust digit separators, e.g. 0x0000_0600
            if re.fullmatch(r"0x[0-9a-fA-F]+", digits, re.I):
                val |= int(digits, 16)
            elif re.fullmatch(r"\d+", digits):
                val |= int(digits)
            elif term in out:
                val |= out[term]
            else:
                return None
        return val

    # Iterate to a fixed point: a term may reference a constant declared
    # later in the file (forward reference), so resolve whatever's ready
    # each pass until nothing new resolves.
    pending = dict(exprs)
    progress = True
    while pending and progress:
        progress = False
        for name, expr in list(pending.items()):
            resolved = resolve(expr)
            if resolved is not None:
                out[name] = resolved
                del pending[name]
                progress = True

    # parser hardening: every `pub const CK...` line must have been parsed
    declared = len(re.findall(r"^pub const CK", text, re.M))
    if declared != len(out):
        raise SystemExit(
            f"PARSER ERROR: {path.name} declares {declared} `pub const CK*` "
            f"lines but only {len(out)} were parsed as u32 constants "
            f"(unresolved: {', '.join(sorted(pending)) or '?'}) — "
            f"update parse_rust() to cover the new form."
        )
    return out


def parse_js(path: Path):
    """Returns (constants, errors). Duplicate object keys are errors — JS
    silently lets the last one win."""
    out, errors = {}, []
    text = path.read_text()
    pat = re.compile(r"^\s*(CK[A-Za-z0-9_]+)\s*:\s*(0x[0-9a-fA-F]+|\d+)\s*,", re.M)
    occurrences = 0
    for m in pat.finditer(text):
        name, raw = m.group(1), m.group(2)
        occurrences += 1
        val = int(raw, 0)
        if name in out:
            errors.append(
                f"DUPLICATE-KEY  {name}: defined twice "
                f"(0x{out[name]:x} then 0x{val:x}) — later key silently wins in JS"
            )
        out[name] = val
    # parser hardening: every `CKNAME:` line must have been parsed
    declared = len(re.findall(r"^\s*CK[A-Za-z0-9_]+\s*:", text, re.M))
    if declared != occurrences:
        raise SystemExit(
            f"PARSER ERROR: {path.name} has {declared} `CK*:` entries but "
            f"only {occurrences} were parsed as numeric constants — "
            f"update parse_js() to cover the new form."
        )
    return out, errors


# ── Checks ───────────────────────────────────────────────────────────────────
def check_source(label: str, consts: dict, spec: dict) -> list:
    errors = []
    for name, val in sorted(consts.items()):
        if name in spec:
            if spec[name] != val:
                errors.append(
                    f"MISMATCH  {name}: {label}=0x{val:08x} spec=0x{spec[name]:08x}"
                )
        elif name in PINNED:
            pinned_val, kind = PINNED[name]
            if val != pinned_val:
                errors.append(
                    f"PIN-DRIFT  {name}: {label}=0x{val:08x} "
                    f"pinned({kind})=0x{pinned_val:08x}"
                )
            if kind == "vendor" and val < VENDOR_BASE:
                errors.append(
                    f"VENDOR-SPACE  {name}=0x{val:08x} is kind=vendor but "
                    f"below CKx_VENDOR_DEFINED (0x{VENDOR_BASE:08x})"
                )
        else:
            errors.append(
                f"NOT-IN-SPEC (not pinned)  {name} = 0x{val:08x} — add to the "
                f"header or to PINNED with a justification"
            )
    return errors


def check_duplicates(label: str, consts: dict) -> list:
    errors = []
    for cls in DUP_CHECK_CLASSES:
        byval = {}
        for name, val in consts.items():
            if name.startswith(cls):
                byval.setdefault(val, []).append(name)
        for val, names in sorted(byval.items()):
            if len(names) < 2:
                continue
            names = sorted(names)
            if any(set(names) <= g for g in ALIAS_GROUPS):
                continue
            errors.append(
                f"DUPLICATE-CODEPOINT  {label} {cls.rstrip('_')} 0x{val:08x}: "
                f"{', '.join(names)} (add to ALIAS_GROUPS only if the spec "
                f"defines both)"
            )
    return errors


def check_pinned_hygiene(spec: dict) -> list:
    """PINNED must not shadow names the header now defines, and vendor pins
    must structurally sit in vendor space."""
    errors = []
    for name, (val, kind) in sorted(PINNED.items()):
        if name in spec:
            errors.append(
                f"PIN-SHADOWS-SPEC  {name} is now in pkcs11t.h "
                f"(0x{spec[name]:08x}) — remove it from PINNED"
            )
        if kind == "vendor" and val < VENDOR_BASE:
            errors.append(
                f"VENDOR-SPACE  PINNED {name}=0x{val:08x} is kind=vendor but "
                f"below 0x{VENDOR_BASE:08x}"
            )
    for drift, twin in DRIFT_SPEC_TWIN.items():
        if twin not in spec:
            errors.append(f"DRIFT-TWIN-MISSING  {twin} not found in header")
        elif spec[twin] != PINNED[drift][0]:
            errors.append(
                f"DRIFT-TWIN-MISMATCH  {drift}=0x{PINNED[drift][0]:08x} but "
                f"{twin}=0x{spec[twin]:08x}"
            )
    return errors


def check_canonical(spec: dict) -> list:
    errors = []
    if not CANONICAL.exists():
        return [f"CANONICAL-MISSING  {CANONICAL} not found"]
    digest = hashlib.sha256(CANONICAL.read_bytes()).hexdigest()
    if digest != CANONICAL_SHA256:
        return [
            f"CANONICAL-SHA256  {CANONICAL.name} hash {digest} != pinned "
            f"{CANONICAL_SHA256} — the canonical reference must never change "
            f"without re-pinning"
        ]
    canon = parse_header(CANONICAL)
    for name, val in sorted(canon.items()):
        if name not in spec:
            errors.append(f"CANONICAL-DELTA  {name} (0x{val:08x}) missing from local header")
        elif spec[name] != val:
            errors.append(
                f"CANONICAL-DELTA  {name}: local=0x{spec[name]:08x} "
                f"canonical=0x{val:08x}"
            )
    for name, val in sorted(spec.items()):
        if name not in canon and val < VENDOR_BASE:
            errors.append(
                f"CANONICAL-DELTA  local-only {name}=0x{val:08x} is outside "
                f"vendor space (only >= 0x{VENDOR_BASE:08x} additions allowed)"
            )
    return errors


def check_canonical_f() -> list:
    """N9 remediation 2026-08-13 — pkcs11f.h pin, following the pkcs11t.h
    pattern: the vendored canonical OASIS function header is sha256-pinned,
    and the in-tree header must match it byte-for-byte (it does today). If
    the two ever legitimately diverge, the CK_PKCS11_FUNCTION_INFO name sets
    are diff-reported so the delta is visible instead of silent."""
    errors = []
    if not CANONICAL_F.exists():
        return [f"CANONICAL-F-MISSING  {CANONICAL_F} not found"]
    digest = hashlib.sha256(CANONICAL_F.read_bytes()).hexdigest()
    if digest != CANONICAL_F_SHA256:
        return [
            f"CANONICAL-F-SHA256  {CANONICAL_F.name} hash {digest} != pinned "
            f"{CANONICAL_F_SHA256} — the canonical reference must never "
            f"change without re-pinning"
        ]
    if not FUNC_HEADER.exists():
        return [f"FUNC-HEADER-MISSING  {FUNC_HEADER} not found"]
    if FUNC_HEADER.read_bytes() == CANONICAL_F.read_bytes():
        return errors
    # Diverged: report the function-name delta (and flag the byte diff even
    # when the name sets agree — e.g. a changed prototype).
    fn_pat = re.compile(r"CK_PKCS11_FUNCTION_INFO\((C_\w+)\)")
    local_fns = set(fn_pat.findall(FUNC_HEADER.read_text(errors="replace")))
    canon_fns = set(fn_pat.findall(CANONICAL_F.read_text(errors="replace")))
    for name in sorted(canon_fns - local_fns):
        errors.append(f"CANONICAL-F-DELTA  {name} missing from local pkcs11f.h")
    for name in sorted(local_fns - canon_fns):
        errors.append(f"CANONICAL-F-DELTA  local-only function {name} (not in the OASIS header)")
    if not errors:
        errors.append(
            "CANONICAL-F-DELTA  pkcs11f.h differs from the canonical header "
            "in content (same function names) — inspect the diff manually"
        )
    return errors


def check_manifest(spec: dict) -> list:
    errors = []
    if not MANIFEST.exists():
        return [f"MANIFEST-MISSING  {MANIFEST} not found"]
    data = json.loads(MANIFEST.read_text())
    block = data.get("standard_pkcs11_v3_2", {})
    checked = 0
    for codepoint, entry in block.items():
        if codepoint.startswith("_"):
            continue
        symbol = entry.get("symbol")
        val = int(codepoint, 16)
        checked += 1
        if symbol not in spec:
            errors.append(f"MANIFEST  {symbol} ({codepoint}) not in pkcs11t.h")
        elif spec[symbol] != val:
            errors.append(
                f"MANIFEST  {symbol}: manifest={codepoint} "
                f"spec=0x{spec[symbol]:08x}"
            )
    if checked == 0:
        errors.append("MANIFEST  standard_pkcs11_v3_2 block is empty — "
                      "nothing validated (parser or manifest broken?)")
    return errors


def main() -> int:
    spec = parse_header(HEADER)
    if len(spec) < 900:
        print(f"PARSER ERROR: only {len(spec)} defines parsed from "
              f"{HEADER.name} — expected ~1050; parser or header is broken.")
        return 1

    rust = parse_rust(RUST)
    js, js_errors = parse_js(JS)
    # N9 — the C++ vendor header uses the same #define grammar as pkcs11t.h,
    # so the same parser applies (duplicate/vendor-range/pinned rules too).
    vend = parse_header(VENDOR_HEADER)

    sections = [
        ("pkcs11t.h vs canonical OASIS v3.2 (sha256-pinned)", check_canonical(spec)),
        ("pkcs11f.h vs canonical OASIS v3.2 (sha256-pinned)", check_canonical_f()),
        ("pkcs11t.h duplicate codepoints", check_duplicates("header", spec)),
        ("PINNED hygiene", check_pinned_hygiene(spec)),
        (f"rust/src/constants.rs ({len(rust)} constants)",
         check_source("rust", rust, spec) + check_duplicates("rust", rust)),
        (f"constants.js ({len(js)} constants)",
         js_errors + check_source("js", js, spec) + check_duplicates("js", js)),
        (f"src/lib/vendor_mechanisms.h ({len(vend)} constants)",
         check_source("vendor-hdr", vend, spec) + check_duplicates("vendor-hdr", vend)),
        ("kmip/pkcs11-mech-manifest.json (standard_pkcs11_v3_2)",
         check_manifest(spec)),
    ]

    total_errors = 0
    for title, errors in sections:
        status = "OK" if not errors else f"FAIL ({len(errors)})"
        print(f"[{status:>9}] {title}")
        for e in errors:
            print(f"    {e}")
        total_errors += len(errors)

    print(f"\nheader defines parsed: {len(spec)}; "
          f"rust: {len(rust)}; js: {len(js)}; vendor-hdr: {len(vend)}; "
          f"pinned: {len(PINNED)}; failures: {total_errors}")
    return 1 if total_errors else 0


if __name__ == "__main__":
    sys.exit(main())
