#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""
V5 (PKCS#11 v3.3 composite work, 2026-10-21): the draft authors' reference
implementation verifies signatures that the pqctoday-hsm Rust engine produced.

Upstream reference: https://github.com/lamps-wg/draft-composite-sigs
                    commit f0627ab34acfe1aee0abce4bee91ed2b577eab76
                    src/generate_test_vectors.py

Input (self-generated, NOT upstream vectors): JSON with top-level m and ctx
(the upstream vector file's own m and ctx) and "sig": [{tcId, pk, s,
sWithContext}] in hex — a fresh engine key pair per supported set and two
engine signatures over m, without and with ctx.

Per entry:
  ref_verifies_s              reference loadPK(pk); verify(s, m)        (empty ctx)
  ref_verifies_sWithContext   reference verify(sWithContext, m, ctx)
  neg_sWithContext_without_ctx_rejected   verify(sWithContext, m) is False
  neg_s_with_ctx_rejected                 verify(s, m, ctx) is False
  neg_other_message_rejected              verify(s, m + b"x") is False

Usage (inside a throwaway container only; the reference code is untrusted):
  python3 v5_sig_check.py <upstream src dir> <fixture.json> <out.json>
"""
import json
import sys

src_dir, fx_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, src_dir)
import generate_test_vectors as ref  # noqa: E402

from cryptography.exceptions import InvalidSignature  # noqa: E402

fx = json.load(open(fx_path))
m, ctx = bytes.fromhex(fx["m"]), bytes.fromhex(fx["ctx"])
results = {}


def run(fn):
    try:
        return bool(fn())
    except InvalidSignature:
        return False
    except Exception as e:
        return "error: " + repr(e)


def verify(pk, tc, sig, msg, c=None):
    a = ref.getNewInstanceByName(tc)
    a.loadPK(pk)
    if c is None:
        a.verify(sig, msg)
    else:
        a.verify(sig, msg, c)
    return True


for t in fx["sig"]:
    tc = t["tcId"]
    pk, s, sc = (bytes.fromhex(t[f]) for f in ("pk", "s", "sWithContext"))
    r = {}
    if ref.getNewInstanceByName(tc) is None:
        results[tc] = {"error": "reference has no class for this tcId"}
        continue
    r["ref_verifies_s"] = run(lambda: verify(pk, tc, s, m))
    r["ref_verifies_sWithContext"] = run(lambda: verify(pk, tc, sc, m, ctx))
    r["neg_sWithContext_without_ctx_rejected"] = run(lambda: verify(pk, tc, sc, m)) is False
    r["neg_s_with_ctx_rejected"] = run(lambda: verify(pk, tc, s, m, ctx)) is False
    r["neg_other_message_rejected"] = run(lambda: verify(pk, tc, s, m + b"x")) is False
    results[tc] = r
    print(tc, json.dumps(r), flush=True)

json.dump(
    {"reference_version_implemented": ref.VERSION_IMPLEMENTED, "results": results},
    open(out_path, "w"),
    indent=2,
)
