#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""
V4 (PKCS#11 v3.3 composite work, 2026-10-21): merge the outputs of ref_kem_check.py,
ref_sig_check.py and indep_check.py into one results.json, keyed by tcId:
  KEM:  {decaps_matches_k, pk_matches_sk, cert_spki_matches, ...}
  SIG:  {sig_verifies, sigWithContext_verifies, pk_matches_sk, cert_spki_matches, ...}
plus an "independent" block for the two entries re-checked from the draft text.
Values are true/false or "not-run: <reason>" / "error: <exception>".

Usage: python3 combine_results.py <out dir>
"""
import json
import os
import sys

d = sys.argv[1]
kem = json.load(open(os.path.join(d, "ref_kem_results.json")))
sig = json.load(open(os.path.join(d, "ref_sig_results.json")))
ind = json.load(open(os.path.join(d, "indep_results.json")))

KEM_KEYS = ["decaps_matches_k", "pk_matches_sk", "cert_spki_matches", "cert_sig_by_ca",
            "dk_pkcs8_wraps_dk", "ref_loadKeyPair_as_shipped", "loader_shim_used",
            "ref_validatePrivateKey"]
SIG_KEYS = ["sig_verifies", "sigWithContext_verifies", "pk_matches_sk", "cert_spki_matches",
            "cert_selfsig_verifies", "sk_pkcs8_wraps_sk", "neg_sWithContext_without_ctx_rejected"]

out = {"kem": {}, "sig": {}, "independent": ind["results"],
       "meta": {"kem_reference_VERSION_IMPLEMENTED": kem["reference_version_implemented"],
                "sig_reference_VERSION_IMPLEMENTED": sig["reference_version_implemented"],
                "independent_tooling": ind["openssl"] + "; Python " + ind["python"] + " stdlib"}}
for tc, r in kem["results"].items():
    out["kem"][tc] = {k: r.get(k, "not-run: not applicable") for k in KEM_KEYS}
for tc, r in sig["results"].items():
    out["sig"][tc] = {k: r.get(k, "not-run: not applicable") for k in SIG_KEYS}


def count(fam, key, prefix):
    rows = [v for t, v in out[fam].items() if t.startswith(prefix)]
    return f"{sum(1 for v in rows if v[key] is True)}/{len(rows)}"


out["summary"] = {
    "kem_composite_decaps": count("kem", "decaps_matches_k", "id-MLKEM"),
    "kem_composite_pk_rederived": count("kem", "pk_matches_sk", "id-MLKEM"),
    "kem_composite_cert_spki": count("kem", "cert_spki_matches", "id-MLKEM"),
    "kem_composite_cert_ca_sig": count("kem", "cert_sig_by_ca", "id-MLKEM"),
    "kem_composite_ref_loader_as_shipped": count("kem", "ref_loadKeyPair_as_shipped", "id-MLKEM"),
    "kem_plain_decaps": count("kem", "decaps_matches_k", "id-alg-ml-kem"),
    "sig_composite_s": count("sig", "sig_verifies", "id-MLDSA"),
    "sig_composite_sWithContext": count("sig", "sigWithContext_verifies", "id-MLDSA"),
    "sig_composite_pk_rederived": count("sig", "pk_matches_sk", "id-MLDSA"),
    "sig_composite_cert_spki": count("sig", "cert_spki_matches", "id-MLDSA"),
    "sig_composite_cert_selfsig": count("sig", "cert_selfsig_verifies", "id-MLDSA"),
    "sig_plain_s_and_ctx": count("sig", "sigWithContext_verifies", "id-ML-DSA"),
}
json.dump(out, open(os.path.join(d, "results.json"), "w"), indent=2)
print(json.dumps(out["summary"], indent=2))
