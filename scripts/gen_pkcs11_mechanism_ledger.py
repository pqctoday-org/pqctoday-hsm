#!/usr/bin/env python3
"""Regenerate docs/pkcs11-mechanism-ledger.json (plan item X2').

The LEDGER is the artefact; this script only rebuilds it. The gate runs
scripts/check_pkcs11_mechanism_ledger.py, which never calls this file —
so a hand-edited justification is never silently overwritten by a gate
run, only by someone deliberately regenerating.

What it does:
  * reads every CKM_* from docs/refs/pkcs11t-canonical-v3.2.h (the
    canonical OASIS header — the repo's source of truth for CK* values);
  * reads what each engine actually ADVERTISES, from the two places that
    build those lists: SoftHSM::prepareSupportedMechanisms() in
    src/lib/SoftHSM_slots.cpp, and SUPPORTED_MECHS in
    rust/src/constants.rs. Not from a captured run — a snapshot would go
    stale exactly when it matters;
  * classifies everything else against the SCOPE_RULES table below.

Existing justifications are PRESERVED: a row already in the ledger keeps
its note and scope key unless the engines' advertised sets changed. New
mechanisms (a header update) arrive classified by rule, or unclassified
if no rule matches — and an unclassified row fails the checker, which is
the point.

Usage:  python3 scripts/gen_pkcs11_mechanism_ledger.py
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

# Ordered; first match wins. Each entry is (regex, scope-key).
# The scope key's prose lives in SCOPE_REASONS and is what a reviewer
# reads — the regex only decides which prose applies.
SCOPE_RULES = [
    (r"^CKM_(DES|DES2|DES3|CDMF|IDEA|RC2|RC4|RC5|CAST|CAST3|CAST5|CAST128|"
     r"BLOWFISH|TWOFISH|SKIPJACK|BATON|JUNIPER|FORTEZZA|SEED|ARIA|CAMELLIA|"
     r"GOST28147)(_|$)", "legacy-block-ciphers"),
    (r"^CKM_(MD2|RIPEMD128|FASTHASH|GOSTR3411)(_|$)", "legacy-hashes"),
    (r"^CKM_(DSA|GOSTR3410|KEA)(_|$)", "legacy-signature-and-kex"),
    (r"^CKM_(RSA_9796|RSA_X9_31|SHA1_RSA_X9_31)", "legacy-rsa-signature"),
    (r"^CKM_RSA_PKCS(_OAEP)?_TPM_1_1$", "tpm-1x"),
    (r"^CKM_ECDSA_KEY_PAIR_GEN$", "deprecated-alias"),
    (r"^CKM_(DH_PKCS|X9_42)", "finite-field-dh"),
    (r"^CKM_(SSL3|TLS|TLS10|TLS12|WTLS)(_|$)", "protocol-kdfs-tls"),
    (r"^CKM_(PBE|PBA)_", "password-based"),
    (r"^CKM_(HOTP|ACTI|SECURID)(_|$)", "otp-tokens"),
    (r"^CKM_(XEDDSA|X3DH|X2RATCHET)(_|$)", "signal-protocol"),
    (r"^CKM_IKE\d?_", "protocol-kdfs-ike"),
    (r"^CKM_BLAKE2B", "blake2b"),
    (r"^CKM_(SALSA20|POLY1305)(_|$)", "salsa20-poly1305"),
    (r"^CKM_SHA512_T", "sha-512-t"),
    (r"^CKM_ECDH(_COF)?(_X)?_AES_KEY_WRAP$", "composite-ecdh-aes-wrap"),
    (r"^CKM_(AES_MAC|AES_XCBC_MAC|AES_CMAC_GENERAL)", "superseded-aes-macs"),
    (r"^CKM_(AES_CFB64|AES_CTS|AES_KEY_WRAP_PKCS7)$", "uncommon-aes-modes"),
    (r"_KEY_GEN$", "hash-keyed-key-gen"),
    (r"_KEY_DERIVATION$", "hash-key-derivation"),
    (r"^CKM_(KIP_DERIVE|KIP_MAC|KIP_WRAP)$", "kip"),
    (r"^CKM_ECMQV_DERIVE$", "ecmqv"),
    (r"^CKM_RIPEMD160_RSA_PKCS$", "ripemd160-rsa-composite"),
    (r"^CKM_(NULL|XOR_BASE_AND_DATA|EXTRACT_KEY_FROM_KEY|CMS_SIG|"
     r"KEY_WRAP_LYNKS|KEY_WRAP_SET_OAEP|PUB_KEY_FROM_PRIV_KEY)$", "misc-unadopted"),
    (r"^CKM_VENDOR_DEFINED$", "vendor-base"),
]

SCOPE_REASONS = {
    "legacy-block-ciphers":
        "Pre-AES or regional block ciphers (DES/3DES, RC2/RC4/RC5, CAST, IDEA, "
        "Blowfish/Twofish, SKIPJACK/BATON/JUNIPER/FORTEZZA, SEED, ARIA, Camellia, "
        "GOST 28147). This is a PQC engine with a deliberately narrow symmetric "
        "surface: AES and ChaCha20. Adding any of these would widen the attack "
        "surface to primitives no current caller should select.",
    "legacy-hashes":
        "Superseded hash functions (MD2, RIPEMD-128, FASTHASH, GOST R 34.11). "
        "MD5, SHA-1 and RIPEMD-160 ARE present — decision D2, 2026-09-07 — "
        "because callers must still verify existing artefacts signed with them; "
        "these have no comparable installed base to verify against.",
    "legacy-signature-and-kex":
        "DSA, GOST R 34.10 and KEA. Finite-field DSA is withdrawn from FIPS 186-5 "
        "for signature generation; GOST is a regional suite this engine does not "
        "target; KEA is a withdrawn NSA key-exchange algorithm.",
    "legacy-rsa-signature":
        "ISO 9796 and ANSI X9.31 RSA signature encodings. Both are superseded by "
        "PKCS#1 v1.5 and PSS, which the engine does implement.",
    "tpm-1x":
        "TPM 1.1 RSA blob formats. The repo's TPM work targets TPM 2.0 and does so "
        "through its own playground, not through PKCS#11 mechanisms.",
    "deprecated-alias":
        "CKM_ECDSA_KEY_PAIR_GEN is the v2.11-era name; PKCS#11 renamed it "
        "CKM_EC_KEY_PAIR_GEN and the engines implement it under that name. "
        "Advertising both would present one capability as two.",
    "finite-field-dh":
        "Finite-field Diffie-Hellman (PKCS#3 and X9.42, including their MQV and "
        "hybrid forms). The engine's key agreement is elliptic-curve and PQ/T "
        "hybrid; finite-field DH offers no migration path a PQC deployment wants.",
    "protocol-kdfs-tls":
        "SSL 3.0 / TLS 1.0-1.2 / WTLS key-block and master-secret derivations. "
        "These bind the token to a specific handshake's internals. TLS 1.3 "
        "defines no such mechanism, and the engine's TLS integration works through "
        "the OpenSSL provider with ordinary key agreement instead.",
    "password-based":
        "PKCS#5/PKCS#12 password-based encryption and authentication. "
        "CKM_PKCS5_PBKD2 IS implemented — deriving a key from a password is in "
        "scope; the PBE_* mechanisms bundle derivation with a legacy cipher "
        "(see legacy-block-ciphers) and cannot be adopted without it.",
    "otp-tokens":
        "One-time-password token mechanisms (HOTP, ACTI, SecurID). These describe "
        "an authentication token product, not a cryptographic service; nothing in "
        "this engine, its KMIP server or its policy layer models an OTP credential.",
    "signal-protocol":
        "Signal protocol primitives (XEdDSA, X3DH, Double Ratchet). A messaging "
        "protocol state machine, not a key-management primitive; the engine has no "
        "session-state model to hold a ratchet.",
    "protocol-kdfs-ike":
        "IKEv1/IKEv2 PRF and derivation mechanisms. Same reasoning as the TLS "
        "KDFs: they encode one protocol's key schedule. The repo's strongSwan "
        "integration (strongswan-pkcs11/) uses ordinary key agreement instead.",
    "blake2b":
        "The BLAKE2b family (digest, HMAC, key gen, key derivation, at four "
        "digest lengths). A well-regarded hash the engine simply does not "
        "implement — no standard this repo tracks (FIPS, NIST SP, LAMPS, KMIP "
        "3.0) requires it, and it has no PQC role.",
    "salsa20-poly1305":
        "Salsa20 and bare Poly1305. ChaCha20-Poly1305 IS implemented; Salsa20 is "
        "its predecessor and bare Poly1305 is the one-time authenticator used "
        "outside an AEAD construction, which no caller here needs.",
    "sha-512-t":
        "The parameterised SHA-512/t family. The two FIPS 180-4 named instances, "
        "SHA-512/224 and SHA-512/256, ARE implemented; CKM_SHA512_T takes an "
        "arbitrary truncation length as a parameter, which FIPS 180-4 does not "
        "define initial hash values for beyond those two.",
    "composite-ecdh-aes-wrap":
        "ECDH-then-AES-key-wrap composites. Both halves are implemented as "
        "separate mechanisms (CKM_ECDH1_DERIVE / CKM_ECDH1_COFACTOR_DERIVE and "
        "CKM_AES_KEY_WRAP), so a caller can build the composite; the fused "
        "mechanism is a convenience this engine does not offer.",
    "superseded-aes-macs":
        "CKM_AES_MAC / AES_MAC_GENERAL (CBC-MAC) and AES_XCBC_MAC. CBC-MAC is "
        "unsafe for variable-length messages and XCBC-MAC was superseded by "
        "CMAC, which IS implemented (CKM_AES_CMAC). CKM_AES_CMAC_GENERAL — the "
        "truncated-output form — is the one item in this group with no such "
        "objection; it is unimplemented rather than rejected.",
    "uncommon-aes-modes":
        "AES-CFB64, AES-CTS and AES_KEY_WRAP_PKCS7. The engine implements the "
        "modes its callers and KMIP 3.0 profiles use (ECB/CBC/CTR/GCM/CCM/XTS/"
        "OFB/CFB8/CFB128, KW and KWP).",
    "hash-keyed-key-gen":
        "CKM_<hash>_KEY_GEN mechanisms, which generate a generic secret key sized "
        "for one HMAC. CKM_GENERIC_SECRET_KEY_GEN IS implemented and generates a "
        "key of any requested length, which is the same capability without one "
        "mechanism per digest.",
    "hash-key-derivation":
        "CKM_<hash>_KEY_DERIVATION — single-pass 'hash the base key' derivation. "
        "The engine implements the KDFs standards actually specify (HKDF, "
        "SP 800-108 counter/feedback/double-pipeline, PBKDF2) plus "
        "CKM_SHAKE_256_KEY_DERIVATION for its XOF path.",
    "kip":
        "The Key Injection Protocol mechanisms. A vendor key-loading protocol "
        "with no published specification this repo can verify an implementation "
        "against.",
    "ecmqv":
        "CKM_ECMQV_DERIVE. Deliberately declined, and recorded here because THREE "
        "separate audits have each re-discovered it as an apparent gap. MQV's "
        "security depends on implicit key confirmation the PKCS#11 API cannot "
        "express, it is not in FIPS SP 800-56A rev3's approved schemes, and "
        "one-pass ECDH covers the deployed use. This row exists so the fourth "
        "audit reads a decision instead of filing it again.",
    "misc-unadopted":
        "Individually unadopted mechanisms: CKM_NULL (no-op wrap), "
        "CKM_XOR_BASE_AND_DATA (superseded by CKM_CONCATENATE_* plus a real KDF), "
        "CKM_EXTRACT_KEY_FROM_KEY (bit-slicing a key), CKM_CMS_SIG (embeds CMS "
        "structure knowledge in the token), CKM_KEY_WRAP_LYNKS and "
        "CKM_KEY_WRAP_SET_OAEP (obsolete wrap formats), and "
        "CKM_PUB_KEY_FROM_PRIV_KEY (recovering a public key from a private one, "
        "which the engine does internally but does not expose as a mechanism).",
    "ripemd160-rsa-composite":
        "CKM_RIPEMD160_RSA_PKCS, the fused RIPEMD-160-then-RSA-PKCS#1-v1.5 "
        "signature. Unlike the other exclusions here the underlying primitive IS "
        "in scope: both engines implement CKM_RIPEMD160 and its HMACs, for the "
        "same reason MD5 and SHA-1 are kept (decision D2) — callers have to "
        "verify existing artefacts. A caller who needs this signature can build "
        "it with CKM_RIPEMD160 plus CKM_RSA_PKCS, which takes a caller-supplied "
        "DigestInfo. The fused mechanism is simply not implemented, and no "
        "standard this repo tracks requires it.",
    "vendor-base":
        "CKM_VENDOR_DEFINED is the base of the vendor range, not a mechanism. "
        "Both engines define vendor mechanisms above it; those appear in this "
        "ledger as engine-extension rows.",
}


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
    """Names SoftHSM::prepareSupportedMechanisms() puts in the table."""
    src = read(CPP_SLOTS)
    start = src.index("void SoftHSM::prepareSupportedMechanisms")
    body = src[start:]
    body = body[: body.index("\n}\n")]
    return set(re.findall(r'^\s*t\["(CKM_[A-Z0-9_]+)"\]', body, re.M))


def rust_advertised() -> set:
    """Names listed in SUPPORTED_MECHS, which C_GetMechanismList returns."""
    src = read(RUST_CONSTS)
    start = src.index("pub const SUPPORTED_MECHS")
    body = src[start:]
    body = body[: body.index("\n];")]
    return set(re.findall(r"^\s*(CKM_[A-Z0-9_]+),", body, re.M))


def classify(name: str):
    for pattern, key in SCOPE_RULES:
        if re.search(pattern, name):
            return key
    return None


def main() -> int:
    canon = canonical_mechanisms()
    cpp = cpp_advertised()
    rust = rust_advertised()

    previous = {}
    if LEDGER.exists():
        previous = json.loads(read(LEDGER)).get("rows", {})

    rows = {}
    unclassified = []

    for name in sorted(canon):
        row = {"value": canon[name]}
        row["cpp"] = "implemented" if name in cpp else None
        row["rust"] = "implemented" if name in rust else None

        if row["cpp"] is None or row["rust"] is None:
            key = classify(name)
            if key is None:
                unclassified.append(name)
                key = "UNCLASSIFIED"
            for engine in ("cpp", "rust"):
                if row[engine] is None:
                    row[engine] = f"excluded-by-scope:{key}"

        prev = previous.get(name, {})
        if "note" in prev:
            row["note"] = prev["note"]
        rows[name] = row

    # Engine extensions: advertised names that are NOT in the canonical
    # header. These are real, reachable mechanisms — a caller sees them in
    # C_GetMechanismList — so they get rows too, or the ledger would
    # under-report what the engines expose.
    for name in sorted((cpp | rust) - set(canon)):
        prev = previous.get(name, {})
        rows[name] = {
            "value": prev.get("value", "engine-extension"),
            "cpp": "implemented" if name in cpp else "not-advertised",
            "rust": "implemented" if name in rust else "not-advertised",
            "note": prev.get(
                "note",
                "Engine extension: advertised by at least one engine but not "
                "defined in the canonical v3.2 header. Verify it sits in the "
                "CKM_VENDOR_DEFINED range or is a later-version mechanism.",
            ),
        }

    ledger = {
        "$schema_note": (
            "One row per CKM_* in docs/refs/pkcs11t-canonical-v3.2.h, plus one per "
            "engine extension advertised outside it. Per engine: 'implemented' "
            "(the engine advertises it), 'excluded-by-scope:<key>' (a deliberate "
            "product decision, prose in scope_reasons), 'deferred:<plan-ref>' or "
            "'tracked-todo:<id>' (a worklist item — set these BY HAND). "
            "scripts/check_pkcs11_mechanism_ledger.py fails the gate when a row "
            "disagrees with what the engines actually advertise, in either "
            "direction, and when a header mechanism has no row at all."
        ),
        "generated_by": "scripts/gen_pkcs11_mechanism_ledger.py (plan item X2')",
        "plan": "docs/remediation-plan-pkcs11-v32-phase2-09072026.md section 5",
        "sources_of_truth": {
            "values": "docs/refs/pkcs11t-canonical-v3.2.h",
            "cpp_advertised": "src/lib/SoftHSM_slots.cpp :: SoftHSM::prepareSupportedMechanisms",
            "rust_advertised": "rust/src/constants.rs :: SUPPORTED_MECHS",
        },
        "counts": {
            "canonical_header_mechanisms": len(canon),
            "cpp_advertised": len(cpp),
            "rust_advertised": len(rust),
            "cpp_only": sorted(cpp - rust),
            "rust_only_count": len(rust - cpp),
        },
        "scope_reasons": SCOPE_REASONS,
        "rows": rows,
    }

    LEDGER.write_text(json.dumps(ledger, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {LEDGER.relative_to(ROOT)}: {len(rows)} rows "
          f"({len(canon)} canonical + {len(rows) - len(canon)} engine extensions)")
    if unclassified:
        print(f"\n{len(unclassified)} mechanism(s) matched no SCOPE_RULE and are "
              f"marked UNCLASSIFIED — the checker will FAIL until each is given a "
              f"rule or a hand-written disposition:", file=sys.stderr)
        for n in unclassified:
            print(f"  {n}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
