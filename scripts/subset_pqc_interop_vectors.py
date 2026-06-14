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

kept, counts = [], defaultdict(int)
for v in full["vectors"]:
    cat = v["category"]
    if cat in ("decap", "encap"):
        kept.append(v); continue  # fast + small → vendor in FULL
    # keygen: N per family (SLH-DSA "s" keygen builds the hypertree root — slow
    # in debug — so don't vendor all 270). siggen/sigver: N per (family, mode,
    # validity) to keep interface diversity (external / internal / external-mu).
    key = (v["family"], cat) if cat == "keygen" \
        else (v["family"], cat, mode(v), bool(v.get("valid")))
    if counts[key] < N:
        kept.append(v); counts[key] += 1

prov = dict(full.get("provenance", {}))
prov["subset_note"] = (
    f"Engine-level vectors for I0. decap/encap vendored in FULL (30/75). "
    f"keygen vendored as up to {N} per family; siggen/sigver as up to {N} per "
    f"(family, interface-mode, validity) — covers external / internal / "
    f"external-mu and valid/invalid. Bounds repo size + CI time (large/slow "
    f"ML-DSA/SLH-DSA material). Full 1452-vector set (the exhaustive gate) "
    f"regenerates via extract_pqc_interop_vectors.py; all 1452 verified "
    f"byte-exact."
)
json.dump({"provenance": prov, "vectors": kept}, open(out_path, "w"), separators=(",", ":"))
from collections import Counter
c = Counter((v["category"], mode(v)) for v in kept)
print(f"subset: {len(kept)} vectors -> {out_path}")
for k in sorted(c): print(f"  {k[0]:8s} {k[1]:9s} {c[k]}")
