#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""
V4 (PKCS#11 v3.3 composite work, 2026-10-21): check the IETF LAMPS Composite ML-KEM
test vectors with the draft authors' OWN reference implementation.

Upstream: https://github.com/lamps-wg/draft-composite-kem
          commit d77e75420034d826e14cbef0b779986511f114e9
          src/generate_test_vectors.py (reference code) + src/testvectors.json

For every entry in testvectors.json (12 composites + 2 plain ML-KEM) this checks:
  decaps_matches_k   reference KEM.loadKeyPair(dk); KEM.decap(c) == k
                     (the shipped composite loadKeyPair is broken at this commit;
                     see the shim below, which only replaces the 3-line loader)
  pk_matches_sk      reference KEM.public_key_bytes() re-derived from dk == ek
  dk_pkcs8_wraps_dk  PKCS#8 privateKey OCTET STRING == dk (composites; plain ML-KEM
                     adds an [0] wrapper by design, checked as such)
  cert_spki_matches  x5c SPKI algorithm OID == reference OID_TABLE[tcId] and
                     SPKI subjectPublicKey == ek
  cert_sig_by_ca     x5c signature verifies under the top-level 'cacert'
                     (ML-DSA-65, via the reference's dilithium-py)
  ref_validatePrivateKey  the reference's own validatePrivateKey(dk_pkcs8, x5c, c, k)

Usage (inside a throwaway container only; the reference code is untrusted):
  python3 ref_kem_check.py <upstream src dir> <testvectors.json> <out.json>
"""
import base64
import json
import sys

src_dir, tv_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, src_dir)
import generate_test_vectors as ref  # noqa: E402  (runs createCA() at import; harmless)

from pyasn1.codec.der.decoder import decode as der_decode  # noqa: E402
from pyasn1_alt_modules import rfc5208, rfc5280  # noqa: E402
from dilithium_py.ml_dsa import ML_DSA_65  # noqa: E402

b64 = base64.b64decode
tv = json.load(open(tv_path))
results = {}


def run(fn):
    try:
        return bool(fn())
    except Exception as e:  # record, never hide
        return "error: " + repr(e)


ca_der = b64(tv["cacert"])
ca, _ = der_decode(ca_der, rfc5280.Certificate())
ca_pk = ca["tbsCertificate"]["subjectPublicKeyInfo"]["subjectPublicKey"].asOctets()

for t in tv["tests"]:
    tc = t["tcId"]
    ek, dk, dk8, c, k, x5c = (b64(t[f]) for f in ("ek", "dk", "dk_pkcs8", "c", "k", "x5c"))
    r = {}
    kem = ref.getNewInstanceByName(tc)
    if kem is None:
        results[tc] = {"error": "reference has no class for this tcId"}
        continue

    def load():
        kem.loadKeyPair(dk)

    # 1) the reference's own composite loader, exactly as shipped
    r["ref_loadKeyPair_as_shipped"] = run(lambda: (load(), True)[1])
    if r["ref_loadKeyPair_as_shipped"] is not True and tc.startswith("id-MLKEM"):
        # At d77e754 CompositeKEM.loadKeyPair does
        #   a, _, b = self.deserializePrivateKey(private_bytes)
        # but deserializePrivateKey returns 2 values (mlkemSeed, tradSK), so the
        # shipped loader always raises. Shim: split dk exactly as the reference's
        # own deserializePrivateKey does and load each half with the reference's
        # own component loaders. decap()/kemCombiner() below are untouched.
        def shim():
            seed, trad = kem.deserializePrivateKey(dk)
            kem.mlkem.loadKeyPair(seed)
            kem.tradkem.loadKeyPair(trad)
            return True

        r["loader_shim_used"] = run(shim)
    r["decaps_matches_k"] = run(lambda: kem.decap(c) == k)
    r["pk_matches_sk"] = run(lambda: kem.public_key_bytes() == ek)

    def pkcs8():
        pki, _ = der_decode(dk8, rfc5208.PrivateKeyInfo())
        inner = pki["privateKey"].asOctets()
        oid_ok = pki["privateKeyAlgorithm"]["algorithm"] == ref.OID_TABLE[tc]
        if tc.startswith("id-alg-ml-kem"):
            return oid_ok and inner == bytes([0x80, 0x40]) + dk
        return oid_ok and inner == dk

    r["dk_pkcs8_wraps_dk"] = run(pkcs8)

    cert, _ = der_decode(x5c, rfc5280.Certificate())
    spki = cert["tbsCertificate"]["subjectPublicKeyInfo"]
    r["cert_spki_oid"] = str(spki["algorithm"]["algorithm"])
    r["cert_spki_matches"] = run(
        lambda: spki["algorithm"]["algorithm"] == ref.OID_TABLE[tc]
        and spki["subjectPublicKey"].asOctets() == ek
    )

    def ca_sig():
        from pyasn1.codec.der.encoder import encode as der_encode
        tbs = der_encode(cert["tbsCertificate"])
        return ML_DSA_65.verify(ca_pk, tbs, cert["signature"].asOctets())

    r["cert_sig_by_ca"] = run(ca_sig)
    if tc.startswith("id-MLKEM"):
        r["ref_validatePrivateKey"] = run(
            lambda: ref.validatePrivateKey(dk8, x5c, c, k)
        )
    else:
        r["ref_validatePrivateKey"] = "not-run: reference validatePrivateKey expects a composite PKCS#8 (plain ML-KEM uses an [0] wrapper)"
    results[tc] = r
    print(tc, json.dumps(r), flush=True)

json.dump(
    {"reference_version_implemented": ref.VERSION_IMPLEMENTED, "results": results},
    open(out_path, "w"),
    indent=2,
)
