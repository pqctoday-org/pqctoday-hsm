#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Build rust/kat/acvp-randomness/nist_optional_input.json.

The Rust engine's optional-test-input tests (ACVP explicit-randomness plan,
P4) need, for every NIST ACVP group the Hub skips today because PKCS#11 could
not carry a random value or the internal message encoding, at least one case
from the upstream NIST file. This script selects them; it never edits a value.

    python3 -I make_fixture.py <nist_dir> <hub_acvp_dir> <out.json>

<nist_dir> holds the five upstream internalProjection.json files of
usnistgov/ACVP-Server @ 975de31e, named as below; their sha256 must equal the
pins here (the same pins as the Hub's `_provenance.source_sha256`).
<hub_acvp_dir> is pqctoday-hub `src/data/acvp`: its `notExecuted` entries with
the five skip reasons name the in-scope groups (81 unique groups).

Selection (deterministic):
- ML-KEM encapsulation: every case of every in-scope group (cheap).
- sigGen: per group, the case with the shortest message (mu for external-mu
  groups), ties by lowest tcId; for preHash groups only hashAlg values with a
  PKCS#11 route (SHA2-224/256/384/512, SHA3-*, SHAKE-128/256, and — D5 —
  SHA2-512/224 and SHA2-512/256 through the generic mechanism), plus the
  shortest SHA2-512/224 or SHA2-512/256 case. The expected signature is stored as its SHA-256 and length
  (a byte-exact comparison; SLH-DSA signatures are up to 49,856 bytes).
- sigVer: per group, the shortest passing and the shortest failing case, with
  the full signature (needed as input).
Every retained field is byte-copied from upstream except `signature_sha256` /
`signature_len`, which are computed from the upstream signature.
"""
import hashlib
import json
import sys
import glob

COMMIT = "975de31eb83d87039ec88934fdc47d8c312b892d"
FILES = {
    "ML-KEM-encapDecap-FIPS203": "a556952ce869bb89c3a3196a701dad89647c193a34c86eafb61a9d710d5b810f",
    "ML-DSA-sigGen-FIPS204": "72dcaf5f69853ca267ccd16af9cb40949786aca0fcfbf05d1ebeba132b93af22",
    "ML-DSA-sigVer-FIPS204": "47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437",
    "SLH-DSA-sigGen-FIPS205": "62b42e7c27fda5de8a94aba2943ae413b59b6ea08141f3bc035b1eceae235dba",
    "SLH-DSA-sigVer-FIPS205": "a013fc2104f4ed4799d96d51141f65b965969b2cf10646626a021b6d456ce792",
}
REASONS = {
    "no-pkcs11-encapsulation-randomness-input",
    "hedged-rnd-not-injectable",
    "hedged-additional-randomness-not-injectable",
    "no-additional-randomness-injection",
    "no-pkcs11-internal-interface",
}
PREHASH_OK = {
    "SHA2-224", "SHA2-256", "SHA2-384", "SHA2-512",
    "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512",
    "SHAKE-128", "SHAKE-256",
    # Owner decision D5 (plan rev 10): through the generic CKM_HASH_ML_DSA /
    # CKM_HASH_SLH_DSA with hash = CKM_SHA512_224 / CKM_SHA512_256.
    "SHA2-512/224", "SHA2-512/256",
}
GROUP_KEYS = ("tgId", "testType", "parameterSet", "function", "deterministic",
              "signatureInterface", "preHash", "externalMu")


def main(nist_dir, hub_dir, out):
    want = {}
    for f in sorted(glob.glob(f"{hub_dir}/*.json")):
        try:
            d = json.load(open(f))
        except Exception:
            continue
        if not isinstance(d, dict) or "notExecuted" not in d:
            continue
        src = d["_provenance"]["source_path"].split("/")[2]
        for n in d["notExecuted"]:
            if n.get("why") in REASONS:
                want.setdefault(src, {}).setdefault(n["tgId"], set()).add(n["why"])

    files = []
    for src in sorted(want):
        raw = open(f"{nist_dir}/{src}.json", "rb").read()
        sha = hashlib.sha256(raw).hexdigest()
        if sha != FILES[src]:
            sys.exit(f"{src}: sha256 {sha} != pinned {FILES[src]}")
        data = json.loads(raw)
        groups = []
        for g in data["testGroups"]:
            if g["tgId"] not in want[src]:
                continue
            tests = g["tests"]
            if src.startswith("ML-KEM"):
                chosen = tests
            elif "sigGen" in src:
                cand = tests
                if g.get("preHash") == "preHash":
                    cand = [t for t in tests if t["hashAlg"] in PREHASH_OK]
                key = lambda t: (len(t.get("mu") or t.get("message") or ""), t["tcId"])
                chosen = [min(cand, key=key)]
                if g.get("preHash") == "preHash":
                    # Also the shortest SHA-512/224 or SHA-512/256 case (D5).
                    t512 = [t for t in tests if t["hashAlg"].startswith("SHA2-512/")]
                    if t512 and min(t512, key=key) not in chosen:
                        chosen.append(min(t512, key=key))
            else:
                key = lambda t: (len(t.get("message") or ""), t["tcId"])
                chosen = [min([t for t in tests if t["testPassed"]], key=key),
                          min([t for t in tests if not t["testPassed"]], key=key)]
            out_tests = []
            for t in chosen:
                t = {k: v for k, v in t.items() if k != "deferred"}
                if "sigGen" in src:
                    sig = bytes.fromhex(t.pop("signature"))
                    t["signature_sha256"] = hashlib.sha256(sig).hexdigest()
                    t["signature_len"] = len(sig)
                if src.startswith("ML-KEM"):
                    t.pop("dk", None)  # encapsulation needs ek only
                out_tests.append(t)
            grp = {k: g[k] for k in GROUP_KEYS if k in g}
            grp["skipReasons"] = sorted(want[src][g["tgId"]])
            grp["casesUpstream"] = len(tests)
            grp["tests"] = out_tests
            groups.append(grp)
        files.append({
            "source": src,
            "source_url": f"https://raw.githubusercontent.com/usnistgov/ACVP-Server/{COMMIT}/gen-val/json-files/{src}/internalProjection.json",
            "source_sha256": sha,
            "testGroups": groups,
        })
    doc = {
        "_provenance": {
            "producer": "NIST ACVP-Server (reference/generator-validated sample vectors)",
            "source_commit": COMMIT,
            "selection": __doc__.split("Selection (deterministic):")[1].strip(),
            "generator": "rust/kat/acvp-randomness/make_fixture.py",
            "scope": "the 81 unique NIST groups the Hub records as skipped for the five optional-input reasons",
        },
        "files": files,
    }
    with open(out, "w") as fh:
        json.dump(doc, fh, indent=0, sort_keys=False)
        fh.write("\n")
    n_g = sum(len(f["testGroups"]) for f in files)
    n_t = sum(len(g["tests"]) for f in files for g in f["testGroups"])
    print(f"groups={n_g} cases={n_t} -> {out}")


if __name__ == "__main__":
    main(*sys.argv[1:4])
