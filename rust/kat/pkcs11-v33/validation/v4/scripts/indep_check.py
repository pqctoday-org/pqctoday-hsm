#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""
V4 part 3 (PKCS#11 v3.3 composite work, 2026-10-21): check ONE composite signature
vector and ONE composite KEM vector WITHOUT the draft authors' code, following
the CURRENT drafts' text:

  * draft-ietf-lamps-pq-composite-sigs-19, sections 2.2 (Prefix/Label/M'),
    3.2/3.3 (Sign/Verify: ML-DSA.Verify(mldsaPK, M', mldsaSig, ctx=Label),
    Trad.Verify(tradPK, M', tradSig)), 4 (serialisation: pk = mldsaPK || tradPK,
    s = mldsaSig || tradSig, sk = mldsaSeed(32) || tradSK), 5 (ECDSA: X9.62
    uncompressed point, Ecdsa-Sig-Value), 6 (id-MLDSA65-ECDSA-P256-SHA512:
    label COMPSIG-MLDSA65-ECDSA-P256-SHA512, PH = SHA512, ecdsa-with-SHA256 on
    secp256r1).
  * draft-ietf-lamps-pq-composite-kem-23, sections 2.x (DHKEM: ss = DH(skR, pkE),
    ct = pkE; X25519 per RFC 7748), 3.3 (Decaps), 3.4/KemCombiner
    ss = SHA3-256(mlkemSS || tradSS || tradCT || tradPK || Label), 4 (sk =
    mlkemSeed(64) || tradSK, ct = mlkemCT(1088) || tradCT), 6
    (id-MLKEM768-X25519-SHA3-256, label hex 5c2e2f2f5e5c).

Tools: Python stdlib only (hashlib for SHA-512/SHA3-256, hand-built DER) and the
OpenSSL 3.5 command-line tool for every public-key operation (ML-DSA-65 verify
with context string, ECDSA P-256 verify, ML-KEM-768 decaps from the seed,
X25519 derive, public-key re-derivation). It does not import dilithium-py,
kyber-py, pyasn1 or `cryptography`, which the reference code uses.

Usage: python3 indep_check.py <kem testvectors.json> <sig testvectors.json> <out.json>
"""
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile

kem_tv, sig_tv, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
b64 = base64.b64decode
work = tempfile.mkdtemp()
log = []


def der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag, body):
    return bytes([tag]) + der_len(len(body)) + body


def oid(dotted):
    parts = [int(x) for x in dotted.split(".")]
    body = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        enc = [p & 0x7F]
        p >>= 7
        while p:
            enc.append(0x80 | (p & 0x7F))
            p >>= 7
        body += bytes(reversed(enc))
    return tlv(0x06, body)


def spki(alg_oid, key, param=None):
    algid = tlv(0x30, oid(alg_oid) + (oid(param) if param else b""))
    return tlv(0x30, algid + tlv(0x03, b"\x00" + key))


def pkcs8(alg_oid, private_key_octets):
    return tlv(0x30, tlv(0x02, b"\x00") + tlv(0x30, oid(alg_oid)) + tlv(0x04, private_key_octets))


def wf(name, data):
    p = os.path.join(work, name)
    open(p, "wb").write(data)
    return p


def ossl(*args, ok_rc=(0,)):
    p = subprocess.run(["openssl", *args], capture_output=True)
    log.append({"cmd": "openssl " + " ".join(args), "rc": p.returncode,
                "out": p.stdout.decode(errors="replace").strip()[-300:],
                "err": p.stderr.decode(errors="replace").strip()[-300:]})
    return p


def pub_raw_from_priv(keyfile, spki_hdr_len):
    out = os.path.join(work, "pub.der")
    p = ossl("pkey", "-in", keyfile, "-inform", "DER", "-pubout", "-outform", "DER", "-out", out)
    if p.returncode != 0:
        return None
    return open(out, "rb").read()[spki_hdr_len:]


results = {}

# ---------------- Signature: id-MLDSA65-ECDSA-P256-SHA512 (draft -19) ----------------
TC = "id-MLDSA65-ECDSA-P256-SHA512"
sv = json.load(open(sig_tv))
t = next(x for x in sv["tests"] if x["tcId"] == TC)
m, ctx = b64(sv["m"]), b64(sv["ctx"])
pk, sk = b64(t["pk"]), b64(t["sk"])
PREFIX = bytes.fromhex("436F6D706F73697465416C676F726974686D5369676E61747572657332303235")
LABEL = b"COMPSIG-MLDSA65-ECDSA-P256-SHA512"
assert PREFIX == b"CompositeAlgorithmSignatures2025"
mldsa_pk, ec_pk = pk[:1952], pk[1952:]
mldsa_spki = wf("mldsa_pub.der", spki("2.16.840.1.101.3.4.3.18", mldsa_pk))
ec_spki = wf("ec_pub.der", spki("1.2.840.10045.2.1", ec_pk, "1.2.840.10045.3.1.7"))
r = {"follows": "draft-ietf-lamps-pq-composite-sigs-19"}


def verify_composite(sig, c):
    mprime = PREFIX + LABEL + bytes([len(c)]) + c + hashlib.sha512(m).digest()
    msg = wf("mprime.bin", mprime)
    s1 = wf("mldsa.sig", sig[:3309])
    s2 = wf("ec.sig", sig[3309:])
    a = ossl("pkeyutl", "-verify", "-pubin", "-inkey", mldsa_spki, "-keyform", "DER",
             "-rawin", "-in", msg, "-sigfile", s1, "-pkeyopt", "context-string:" + LABEL.decode())
    b = ossl("dgst", "-sha256", "-verify", ec_spki, "-keyform", "DER", "-signature", s2, msg)
    return {"mldsa_half": a.returncode == 0 and b"Signature Verified Successfully" in a.stdout,
            "ecdsa_half": b.returncode == 0 and b"Verified OK" in b.stdout}


r["s_components"] = verify_composite(b64(t["s"]), b"")
r["sWithContext_components"] = verify_composite(b64(t["sWithContext"]), ctx)
r["sig_verifies"] = all(r["s_components"].values())
r["sigWithContext_verifies"] = all(r["sWithContext_components"].values())
# negative control: sWithContext checked with an empty ctx must fail in BOTH halves
neg = verify_composite(b64(t["sWithContext"]), b"")
r["neg_wrong_ctx_rejected"] = not any(neg.values())
# pk re-derivation from sk: ML-DSA seed via PKCS#8 seed-only form ([0] IMPLICIT OCTET STRING)
mk = wf("mldsa_seed.p8", pkcs8("2.16.840.1.101.3.4.3.18", tlv(0x80, sk[:32])))
# SPKI header length = SPKI of a 1952-byte key minus the key
hdr = len(spki("2.16.840.1.101.3.4.3.18", mldsa_pk)) - len(mldsa_pk)
ml_pub = pub_raw_from_priv(mk, hdr)
# ECPrivateKey (RFC 5915, no publicKey field) wrapped in PKCS#8 with id-ecPublicKey + curve
ec_p8 = wf("ec.p8", tlv(0x30, tlv(0x02, b"\x00") + tlv(0x30, oid("1.2.840.10045.2.1") + oid("1.2.840.10045.3.1.7")) + tlv(0x04, sk[32:])))
ec_hdr = len(spki("1.2.840.10045.2.1", ec_pk, "1.2.840.10045.3.1.7")) - len(ec_pk)
ec_pub = pub_raw_from_priv(ec_p8, ec_hdr)
r["pk_matches_sk"] = (ml_pub == mldsa_pk) and (ec_pub == ec_pk)
results[TC] = r

# ---------------- KEM: id-MLKEM768-X25519-SHA3-256 (draft -23) ----------------
TC = "id-MLKEM768-X25519-SHA3-256"
kv = json.load(open(kem_tv))
t = next(x for x in kv["tests"] if x["tcId"] == TC)
ek, dk, c, k = (b64(t[f]) for f in ("ek", "dk", "c", "k"))
KLABEL = bytes.fromhex("5c2e2f2f5e5c")
assert KLABEL == b"\\.//^\\"
seed, xsk = dk[:64], dk[64:]
mlkem_ct, x_ct = c[:1088], c[1088:]
r = {"follows": "draft-ietf-lamps-pq-composite-kem-23", "dk_len": len(dk), "c_len": len(c)}
mlkem_p8 = wf("mlkem_seed.p8", pkcs8("2.16.840.1.101.3.4.4.2", tlv(0x80, seed)))
ss_file = os.path.join(work, "mlkem.ss")
p = ossl("pkeyutl", "-decap", "-inkey", mlkem_p8, "-keyform", "DER", "-in", wf("mlkem.ct", mlkem_ct), "-secret", ss_file)
mlkem_ss = open(ss_file, "rb").read() if p.returncode == 0 else None
x_p8 = wf("x25519.p8", pkcs8("1.3.101.110", tlv(0x04, xsk)))
peer = wf("x25519_peer.der", spki("1.3.101.110", x_ct))
xss_file = os.path.join(work, "x.ss")
p = ossl("pkeyutl", "-derive", "-inkey", x_p8, "-keyform", "DER", "-peerkey", peer, "-peerform", "DER", "-out", xss_file)
x_ss = open(xss_file, "rb").read() if p.returncode == 0 else None
ml_hdr = len(spki("2.16.840.1.101.3.4.4.2", ek[:1184])) - 1184
mlkem_pub = pub_raw_from_priv(mlkem_p8, ml_hdr)
x_pub = pub_raw_from_priv(x_p8, len(spki("1.3.101.110", b"\x00" * 32)) - 32)
r["pk_matches_sk"] = mlkem_pub == ek[:1184] and x_pub == ek[1184:]
if mlkem_ss and x_ss and x_pub:
    ss = hashlib.sha3_256(mlkem_ss + x_ss + x_ct + x_pub + KLABEL).digest()
    r["decaps_matches_k"] = ss == k
else:
    r["decaps_matches_k"] = "not-run: an OpenSSL component step failed (see log)"
results[TC] = r

import shutil  # noqa: E402
shutil.rmtree(work, ignore_errors=True)
ver = subprocess.run(["openssl", "version"], capture_output=True).stdout.decode().strip()
json.dump({"openssl": ver, "python": sys.version.split()[0], "results": results, "log": log},
          open(out_path, "w"), indent=2)
print(json.dumps(results, indent=2))
