#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""
V4 (PKCS#11 v3.3 composite work, 2026-10-21): check the IETF LAMPS Composite ML-DSA
test vectors with the draft authors' OWN reference implementation.

Upstream: https://github.com/lamps-wg/draft-composite-sigs
          commit f0627ab34acfe1aee0abce4bee91ed2b577eab76
          src/generate_test_vectors.py (reference code) + src/testvectors.json

For every entry (18 composites + 3 plain ML-DSA), with m and ctx from the file:
  sig_verifies              reference CompositeSig.loadPK(pk); verify(s, m)  (ctx empty)
  sigWithContext_verifies   reference verify(sWithContext, m, ctx)
  pk_matches_sk             ML-DSA half: reference ML_DSA_x.key_derive(sk[:32]) public
                            key == pk[:len]; traditional half: sk[32:] loaded with
                            `cryptography` (RSAPrivateKey / ECPrivateKey DER, raw
                            Ed25519/Ed448) and serialised the way the reference
                            serialises public keys == pk[len:]. (The reference
                            has no private-key loader for signatures, so this
                            loader is ours; the public-key encodings are the
                            reference's own public_key_bytes() methods.)
  sk_pkcs8_wraps_sk         PKCS#8 OID == OID_TABLE[tcId] and privateKey == sk
                            (plain ML-DSA: [0]-wrapped seed by design)
  cert_spki_matches         x5c SPKI OID == OID_TABLE[tcId] and key bytes == pk
  cert_selfsig_verifies     the reference's own verifyCert(x5c) (self-signed with the
                            same composite key)

Usage (inside a throwaway container only; the reference code is untrusted):
  python3 ref_sig_check.py <upstream src dir> <testvectors.json> <out.json>
"""
import base64
import json
import sys

src_dir, tv_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, src_dir)
import generate_test_vectors as ref  # noqa: E402

from cryptography.hazmat.primitives.serialization import load_der_private_key  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519, ed448  # noqa: E402
from cryptography.exceptions import InvalidSignature  # noqa: E402
from pyasn1.codec.der.decoder import decode as der_decode  # noqa: E402
from pyasn1_alt_modules import rfc5208, rfc5280  # noqa: E402

b64 = base64.b64decode
tv = json.load(open(tv_path))
m, ctx = b64(tv["m"]), b64(tv["ctx"])
MLDSA_PK_LEN = {"MLDSA44": 1312, "MLDSA65": 1952, "MLDSA87": 2592}
results = {}


def run(fn):
    try:
        return bool(fn())
    except InvalidSignature:
        return False
    except Exception as e:
        return "error: " + repr(e)


def verify(alg, sig, msg, c=None):
    if c is None:
        alg.verify(sig, msg)  # plain ML-DSA & composite: ctx defaults to b''
    else:
        alg.verify(sig, msg, c)
    return True


for t in tv["tests"]:
    tc = t["tcId"]
    pk, sk, sk8, s, sc, x5c = (b64(t[f]) for f in ("pk", "sk", "sk_pkcs8", "s", "sWithContext", "x5c"))
    r = {}
    is_composite = tc.startswith("id-MLDSA")

    def fresh():
        a = ref.getNewInstanceByName(tc)
        a.loadPK(pk)
        return a

    r["sig_verifies"] = run(lambda: verify(fresh(), s, m))
    r["sigWithContext_verifies"] = run(lambda: verify(fresh(), sc, m, ctx))
    # negative control: the ctx signature must NOT verify without ctx
    r["neg_sWithContext_without_ctx_rejected"] = run(lambda: verify(fresh(), sc, m)) is False

    def rederive():
        a = ref.getNewInstanceByName(tc)
        if not is_composite:
            p, _ = a.ML_DSA_class.key_derive(sk)
            return p == pk
        n = MLDSA_PK_LEN[tc[3:10]]
        mpk, _ = a.mldsa.ML_DSA_class.key_derive(sk[:32])
        trad = a.tradsig
        rest = sk[32:]
        if isinstance(trad, ref.EdDSA):
            cls = ed25519.Ed25519PrivateKey if isinstance(trad, ref.Ed25519) else ed448.Ed448PrivateKey
            trad.sk = cls.from_private_bytes(rest)
        else:
            trad.sk = load_der_private_key(rest, password=None)
        trad.pk = trad.sk.public_key()
        return mpk == pk[:n] and trad.public_key_bytes() == pk[n:]

    r["pk_matches_sk"] = run(rederive)

    def pkcs8():
        pki, _ = der_decode(sk8, rfc5208.PrivateKeyInfo())
        inner = pki["privateKey"].asOctets()
        ok = pki["privateKeyAlgorithm"]["algorithm"] == ref.OID_TABLE[tc]
        return ok and (inner == (bytes([0x80, 0x20]) + sk if not is_composite else sk))

    r["sk_pkcs8_wraps_sk"] = run(pkcs8)

    cert, _ = der_decode(x5c, rfc5280.Certificate())
    spki = cert["tbsCertificate"]["subjectPublicKeyInfo"]
    r["cert_spki_oid"] = str(spki["algorithm"]["algorithm"])
    r["cert_spki_matches"] = run(
        lambda: spki["algorithm"]["algorithm"] == ref.OID_TABLE[tc]
        and spki["subjectPublicKey"].asOctets() == pk
    )
    r["cert_selfsig_verifies"] = run(lambda: ref.verifyCert(x5c))
    results[tc] = r
    print(tc, json.dumps(r), flush=True)

json.dump(
    {"reference_version_implemented": ref.VERSION_IMPLEMENTED, "results": results},
    open(out_path, "w"),
    indent=2,
)
