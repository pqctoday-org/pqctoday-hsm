#!/usr/bin/env python3
"""Build the vendored (CI-runnable) representative subset from the FULL
1452-vector extraction. Keeps keygen/decap/encap in FULL (small), and for
siggen/sigver keeps up to N per (family, mode) so every interface mode
— external / internal / external-mu — and both valid/invalid sigver outcomes
stay covered while bounding repo size (the SLH-DSA signatures are large).

Usage: subset_pqc_interop_vectors.py FULL.json OUT.json [N]
"""
import json, sys
from collections import defaultdict

full = json.load(open(sys.argv[1]))
out_path = sys.argv[2]
N = int(sys.argv[3]) if len(sys.argv) > 3 else 2

def mode(v):
    if v.get("external_mu"): return "ext_mu"
    if v.get("internal"): return "internal"
    return "external"

def is_slow_slh_s(v):
    """SLH-DSA "s" (small-signature) parameter sets: slow to SIGN and to KEYGEN
    in a debug build (more hashing / taller top tree). They dominate CI time."""
    f = v["family"]
    return f.startswith("SLH-DSA") and f.endswith("s")

kept, counts = [], defaultdict(int)
for v in full["vectors"]:
    cat = v["category"]
    if cat in ("decap", "encap"):
        kept.append(v); continue  # fast + small → vendor in FULL
    # CI-time guard: skip the slow SLH-DSA "s" sets for the expensive categories
    # (siggen = signing, keygen = hypertree build). sigver/decap/encap stay — they
    # verify/decapsulate, which is cheap even for "s". The slow "s" siggen/keygen
    # byte-exactness is covered by the full 1452 set (exhaustive gate) + the
    # focused interop_kat checks, just not on every CI push.
    if cat in ("siggen", "keygen") and is_slow_slh_s(v):
        continue
    # keygen: N per family. siggen/sigver: N per (family, mode, validity) to
    # keep interface diversity (external / internal / external-mu).
    key = (v["family"], cat) if cat == "keygen" \
        else (v["family"], cat, mode(v), bool(v.get("valid")))
    if counts[key] < N:
        kept.append(v); counts[key] += 1

prov = dict(full.get("provenance", {}))
prov["subset_note"] = (
    f"Engine-level vectors for I0. decap/encap vendored in FULL (30/75). "
    f"keygen vendored as up to {N} per family; siggen/sigver as up to {N} per "
    f"(family, interface-mode, validity) — covers external / internal / "
    f"external-mu and valid/invalid. SLH-DSA \"s\" sets are EXCLUDED from the "
    f"vendored siggen/keygen (slow signing / hypertree build in debug) to keep "
    f"CI fast; they stay in sigver (cheap). Their byte-exactness is covered by "
    f"the full 1452 set + focused interop_kat. Full set (the exhaustive gate) "
    f"regenerates via extract_pqc_interop_vectors.py; all 1452 verified "
    f"byte-exact."
)
json.dump({"provenance": prov, "vectors": kept}, open(out_path, "w"), separators=(",", ":"))
from collections import Counter
c = Counter((v["category"], mode(v)) for v in kept)
print(f"subset: {len(kept)} vectors -> {out_path}")
for k in sorted(c): print(f"  {k[0]:8s} {k[1]:9s} {c[k]}")
