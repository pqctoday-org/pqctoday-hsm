#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""
V5 (PKCS#11 v3.3 composite work, 2026-10-21): the draft authors' reference
implementation decapsulates ciphertexts that the pqctoday-hsm Rust engine
produced, and must reach the shared secret the engine reported.

Upstream reference: https://github.com/lamps-wg/draft-composite-kem
                    commit d77e75420034d826e14cbef0b779986511f114e9
                    src/generate_test_vectors.py

Input (self-generated, NOT upstream vectors): JSON with "kem": [{tcId, ek, dk,
c, k}] in hex — a fresh engine key pair per supported set, one engine
encapsulation to ek (c) and the engine's own shared secret (k).

Per entry:
  ref_decaps_matches_engine_k  reference decap(c) with our dk == our k
  ref_pk_matches_engine_ek     reference public key re-derived from our dk == our ek
  ref_loadKeyPair_as_shipped   the reference's composite loader as shipped (it
                               raises at this commit; see the shim below)
  loader_shim_used             dk split with the reference's own
                               deserializePrivateKey, halves loaded with the
                               reference's own component loadKeyPair
  neg_tampered_trad_ct_differs one bit flipped in the last byte of c: the
                               reference must not return our k (it either
                               raises or returns another secret)

Usage (inside a throwaway container only; the reference code is untrusted):
  python3 v5_kem_check.py <upstream src dir> <fixture.json> <out.json>
"""
import json
import sys

src_dir, fx_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, src_dir)
import generate_test_vectors as ref  # noqa: E402

fx = json.load(open(fx_path))
results = {}


def run(fn):
    try:
        return bool(fn())
    except Exception as e:  # record, never hide
        return "error: " + repr(e)


for t in fx["kem"]:
    tc = t["tcId"]
    ek, dk, c, k = (bytes.fromhex(t[f]) for f in ("ek", "dk", "c", "k"))
    r = {}
    kem = ref.getNewInstanceByName(tc)
    if kem is None:
        results[tc] = {"error": "reference has no class for this tcId"}
        continue
    r["ref_loadKeyPair_as_shipped"] = run(lambda: (kem.loadKeyPair(dk), True)[1])
    if r["ref_loadKeyPair_as_shipped"] is not True:
        def shim():
            seed, trad = kem.deserializePrivateKey(dk)
            kem.mlkem.loadKeyPair(seed)
            kem.tradkem.loadKeyPair(trad)
            return True

        r["loader_shim_used"] = run(shim)
    r["ref_decaps_matches_engine_k"] = run(lambda: kem.decap(c) == k)
    r["ref_pk_matches_engine_ek"] = run(lambda: kem.public_key_bytes() == ek)

    def tampered():
        bad = bytearray(c)
        bad[-1] ^= 0x01
        try:
            return kem.decap(bytes(bad)) != k
        except Exception:
            return True  # explicit rejection is also "not our k"

    r["neg_tampered_trad_ct_differs"] = run(tampered)
    results[tc] = r
    print(tc, json.dumps(r), flush=True)

json.dump(
    {"reference_version_implemented": ref.VERSION_IMPLEMENTED, "results": results},
    open(out_path, "w"),
    indent=2,
)
